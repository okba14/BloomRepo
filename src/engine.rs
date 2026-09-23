use crate::config::AppConfig;
use crate::crawler::{CrawlerError, GithubCrawler};
use crate::db::Database;
use crate::filter::RepoFilter;
use crate::models::{GithubRepositoryRaw, RepoItem};
use crate::notifier::Notifier;
use crate::state::AppState;
use crate::tokens::{RateResource, TokenPool};
use chrono::{Duration as ChronoDuration, Utc};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("database: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("crawler: {0}")]
    Crawler(#[from] CrawlerError),
    #[error("state: {0}")]
    State(#[from] std::io::Error),
}

pub struct CycleResult {
    pub cycle: u64,
    pub items: Vec<RepoItem>,
    pub spam_count: usize,
    pub priority_count: usize,
    pub duration_ms: u128,
    pub db_total: usize,
    pub status: String,
}

pub struct Engine {
    pub config: AppConfig,
    pub db: Database,
    token_pool: TokenPool,
    crawler: GithubCrawler,
    filter: RepoFilter,
    notifier: Notifier,
    pub state: AppState,
    cycle: u64,
}

impl Engine {
    pub fn new(config: AppConfig, db: Database) -> Self {
        let token_pool = TokenPool::new(config.auth.tokens.clone(), config.auth.user_agent.clone());
        let mut state = AppState::load(&config.storage.state_path);
        if state.last_search_at == 0 {
            state.search_watermark =
                (Utc::now() - ChronoDuration::hours(config.general.lookback_hours)).to_rfc3339();
        }
        Self {
            filter: RepoFilter::new(config.filtering.clone()),
            crawler: GithubCrawler::new(token_pool.clone(), config.auth.timeout_seconds),
            notifier: Notifier::new(config.notifications.clone()),
            state,
            config,
            db,
            token_pool,
            cycle: 0,
        }
    }

    pub async fn run_cycle(&mut self) -> Result<CycleResult, EngineError> {
        let checkpoint = self.state.clone();
        let result = self.run_cycle_inner().await;
        if result.is_err() {
            self.state = checkpoint;
        }
        result
    }

    async fn run_cycle_inner(&mut self) -> Result<CycleResult, EngineError> {
        self.cycle += 1;
        let started = Instant::now();
        let mut raw_candidates = Vec::new();
        let mut event_candidates = Vec::new();
        let mut status = String::new();

        if self.state.sequential_since == 0 && self.config.streams.enable_sequential_stream {
            let db_max = self.db.get_max_id().unwrap_or(0);
            if db_max > 0 {
                self.state.sequential_since = db_max;
                info!(
                    anchor = db_max,
                    "initialized sequential cursor from local database"
                );
            } else {
                match self.crawler.fetch_latest_repo_id().await {
                    Ok(Some(latest_id)) => {
                        self.state.sequential_since = latest_id;
                        info!(
                            anchor = latest_id,
                            "initialized sequential cursor from GitHub"
                        );
                        status.push_str(&format!(" Initialized cursor at #{latest_id}."));
                    }
                    Ok(None) => warn!("could not determine latest repo id from GitHub"),
                    Err(err) => {
                        warn!(error = %err, "failed to initialize sequential cursor anchor")
                    }
                }
            }
        }

        if self.config.streams.enable_sequential_stream && self.state.sequential_since > 0 {
            if let Some(message) = self.collect_sequential(&mut raw_candidates).await? {
                status.push_str(&message);
            }
        }

        if self.config.streams.enable_events_stream {
            match self
                .crawler
                .fetch_events(self.state.events_etag.as_deref())
                .await
            {
                Ok(page) => {
                    self.state.events_etag = page.etag;
                    self.state.last_events_at = Utc::now().timestamp();
                    event_candidates.extend(page.items);
                    if let Some(poll) = page.poll_interval {
                        status.push_str(&format!(" Events poll={}s.", poll));
                    }
                }
                Err(CrawlerError::RateLimited(wait)) => warn!(wait, "events rate limited"),
                Err(err) => warn!(error=%err, "events stream failed; retaining state"),
            }
        }

        if self.config.streams.enable_search_stream && self.search_is_due() {
            let start = chrono::DateTime::parse_from_rfc3339(&self.state.search_watermark)
                .map(|v| v.with_timezone(&Utc))
                .unwrap_or_else(|_| {
                    Utc::now() - ChronoDuration::hours(self.config.general.lookback_hours)
                });
            let query = format!("created:>{}", start.format("%Y-%m-%dT%H:%M:%SZ"));
            match self.crawler.fetch_search_query(&query).await {
                Ok(page) => {
                    raw_candidates.extend(page.items);
                    self.state.search_watermark =
                        (Utc::now() - ChronoDuration::seconds(120)).to_rfc3339();
                    self.state.last_search_at = Utc::now().timestamp();
                }
                Err(CrawlerError::RateLimited(wait)) => {
                    status.push_str(&format!(" Search rate limited for {wait}s."))
                }
                Err(err) => warn!(error=%err, "search stream failed; watermark not advanced"),
            }
        }

        if self.state.sequential_since == 0 {
            if let Some(max_id) = raw_candidates.iter().map(|repo| repo.id).max() {
                self.state.sequential_since = max_id;
            } else if let Some(max_id) = event_candidates.iter().map(|repo| repo.id).max() {
                self.state.sequential_since = max_id;
            }
        }

        let mut seen_ids = HashSet::new();
        let mut candidates = Vec::with_capacity(raw_candidates.len() + event_candidates.len());
        for raw in raw_candidates {
            if seen_ids.insert(raw.id) {
                candidates.push(raw_to_item(raw));
            }
        }
        for item in event_candidates {
            if seen_ids.insert(item.id) {
                candidates.push(item);
            }
        }

        let mut accepted = Vec::new();
        let mut spam_count = 0;
        let mut priority_count = 0;
        for mut item in candidates {
            if self.filter.process(&mut item) {
                if item.is_priority {
                    priority_count += 1;
                }
                accepted.push(item);
            } else {
                spam_count += 1;
            }
        }
        accepted.sort_by_key(|repo| repo.id);

        // The cursor is persisted only after this transaction succeeds. Existing IDs are
        // enriched in SQLite but never produce duplicate files or notifications.
        let existing_ids = self.db.existing_ids(&accepted)?;
        self.db.insert_batch(&accepted)?;
        let new_items: Vec<RepoItem> = accepted
            .iter()
            .filter(|repo| !existing_ids.contains(&repo.id))
            .cloned()
            .collect();
        self.write_outputs(&new_items)?;
        for notify_error in self.notifier.notify(&new_items).await {
            error!(message=%notify_error, "notification failed");
        }
        self.state.checked = Utc::now().to_rfc3339();
        self.state.save_atomic(&self.config.storage.state_path)?;

        let (db_total, _, _) = self.db.get_stats()?;
        let duration_ms = started.elapsed().as_millis();
        Ok(CycleResult {
            cycle: self.cycle,
            items: new_items,
            spam_count,
            priority_count,
            duration_ms,
            db_total,
            status,
        })
    }

    async fn collect_sequential(
        &mut self,
        raw: &mut Vec<GithubRepositoryRaw>,
    ) -> Result<Option<String>, EngineError> {
        let mut url = self.state.sequential_next_url.clone().unwrap_or_else(|| {
            format!(
                "https://api.github.com/repositories?since={}&per_page=100",
                self.state.sequential_since
            )
        });
        let mut max_id = self.state.sequential_since;
        let mut pages = 0;
        let mut reached_end = false;
        while pages < self.config.general.max_pages_per_cycle {
            if let Some(wait) = self.wait_for_core().await {
                tokio::time::sleep(Duration::from_secs(wait.min(60))).await;
            }
            let page = match self.crawler.fetch_repositories_page(&url).await {
                Ok(page) => page,
                Err(CrawlerError::RateLimited(wait)) => {
                    return Ok(Some(format!(" Sequential rate limited for {wait}s.")));
                }
                Err(err) => {
                    warn!(error=%err, "sequential stream failed; cursor not advanced");
                    return Err(err.into());
                }
            };
            pages += 1;
            for repo in &page.items {
                max_id = max_id.max(repo.id);
            }
            raw.extend(page.items);
            match page.next_url {
                Some(next) => url = next,
                None => {
                    reached_end = true;
                    break;
                }
            }
        }
        if pages > 0 {
            if reached_end {
                self.state.sequential_since = max_id;
                self.state.sequential_next_url = None;
            } else {
                self.state.sequential_next_url = Some(url);
            }
        }
        Ok(None)
    }

    async fn wait_for_core(&self) -> Option<u64> {
        self.token_pool.wait_if_exhausted(RateResource::Core).await
    }

    fn search_is_due(&self) -> bool {
        Utc::now().timestamp() - self.state.last_search_at
            >= self.config.general.search_interval_seconds as i64
    }

    fn write_outputs(&self, repos: &[RepoItem]) -> Result<(), EngineError> {
        if repos.is_empty() {
            return Ok(());
        }
        let month = Utc::now().format("%Y-%m").to_string();
        if self.config.storage.enable_log_file {
            let path = format!("new_repos_{month}.log");
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            for repo in repos {
                writeln!(
                    file,
                    "{} | {}\n  {}",
                    repo.full_name,
                    repo.description.as_deref().unwrap_or("no description"),
                    repo.html_url
                )?;
            }
        }
        if self.config.storage.enable_jsonl_stream {
            let path = format!("repos_{month}.jsonl");
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            for repo in repos {
                serde_json::to_writer(&mut file, repo).map_err(std::io::Error::other)?;
                file.write_all(b"\n")?;
            }
        }
        Ok(())
    }
}

fn raw_to_item(raw: GithubRepositoryRaw) -> RepoItem {
    let (owner, name) = raw
        .full_name
        .split_once('/')
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .unwrap_or_else(|| ("unknown".into(), raw.name.clone()));
    let license = raw
        .license
        .and_then(|license| license.spdx_id.or(license.name));
    let owner_type = raw.owner.and_then(|owner| owner.owner_type);
    RepoItem {
        id: raw.id,
        name,
        full_name: raw.full_name,
        owner,
        owner_type,
        html_url: raw.html_url,
        description: raw.description,
        fork: raw.fork,
        stars: raw.stargazers_count,
        forks_count: raw.forks_count,
        language: raw.language,
        license,
        topics: raw.topics,
        created_at: raw.created_at,
        discovered_at: Utc::now().to_rfc3339(),
        is_priority: false,
    }
}
