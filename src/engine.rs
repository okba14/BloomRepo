use crate::config::AppConfig;
use crate::crawler::{raw_to_item, CrawlerError, GithubCrawler, Page};
use crate::db::{Database, OutboxMessage, SourceStatus};
use crate::filter::RepoFilter;
use crate::models::{GithubRepositoryRaw, RepoItem};
use crate::notifier::Notifier;
use crate::state::{AppState, SearchWindow};
use crate::tokens::{RateResource, TokenPool};
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Notify;
use tracing::{error, info, warn};

const MAX_SEARCH_WINDOWS: usize = 512;
const SEARCH_OVERLAP_SECONDS: i64 = 600;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("database operation failed: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("crawler: {0}")]
    Crawler(#[from] CrawlerError),
    #[error("local state or output operation failed: {0}")]
    State(#[from] std::io::Error),
    #[error("all due GitHub sources failed; inspect operational health")]
    SourcesUnavailable,
    #[error("invalid persisted monitoring state; no cursors were reset")]
    InvalidState,
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
    pub state: AppState,
    cycle: u64,
    outbox_wakeup: Arc<Notify>,
    dispatcher: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(task) = self.dispatcher.take() {
            task.abort();
        }
    }
}

impl Engine {
    pub fn new(config: AppConfig, db: Database) -> Result<Self, EngineError> {
        let persisted = db.load_state()?;
        let legacy = if persisted.is_none() {
            AppState::load_checked(&config.storage.state_path)?
        } else {
            None
        };
        let new_install = persisted.is_none() && legacy.is_none();
        let mut state = persisted.or(legacy).unwrap_or_default();
        if new_install {
            state.search_watermark =
                timestamp(Utc::now() - ChronoDuration::hours(config.general.lookback_hours));
            // Existing shipped data is a concrete migration anchor, not a search-sort guess.
            state.sequential_since = db.get_max_id()?;
        }
        validate_state(&state)?;
        state.schema_version = 3;
        let token_pool = TokenPool::new(config.auth.tokens.clone(), config.auth.user_agent.clone());
        let crawler = GithubCrawler::with_concurrency(
            token_pool.clone(),
            config.auth.timeout_seconds,
            config.general.max_concurrent_requests,
        );
        Ok(Self {
            filter: RepoFilter::new(config.filtering.clone()),
            config,
            db,
            crawler,
            token_pool,
            state,
            cycle: 0,
            outbox_wakeup: Arc::new(Notify::new()),
            dispatcher: None,
        })
    }

    pub fn start_dispatcher(&mut self) {
        if self.dispatcher.is_some() {
            return;
        }
        let db = self.db.clone();
        let config = self.config.clone();
        let wakeup = self.outbox_wakeup.clone();
        self.dispatcher = Some(tokio::spawn(async move {
            loop {
                if let Err(error) = dispatch_pending(&db, &config).await {
                    error!(error = %error, "outbox worker failed; deliveries remain durable");
                }
                tokio::select! {
                    _ = wakeup.notified() => {},
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {},
                }
            }
        }));
    }

    pub async fn dispatch_outbox(&self) -> Result<usize, EngineError> {
        dispatch_pending(&self.db, &self.config).await
    }

    pub async fn run_cycle(&mut self) -> Result<CycleResult, EngineError> {
        self.cycle += 1;
        let started = Instant::now();
        // Futures may be cancelled at any await: only this local checkpoint changes before COMMIT.
        let mut next = self.state.clone();
        let mut candidates = BTreeMap::new();
        let mut attempted = 0;
        let mut succeeded = 0;
        let now = Utc::now().timestamp();

        if self.config.streams.enable_events_stream
            && now >= next.events_next_at
            && source_due(&next, "events", now)
        {
            attempted += 1;
            match self.available(RateResource::Core).await {
                Ok(()) => match self.crawler.fetch_events(next.events_etag.as_deref()).await {
                    Ok(page) => {
                        next.events_etag = page.etag;
                        next.last_events_at = now;
                        next.events_next_at =
                            now.saturating_add(
                                page.poll_interval.unwrap_or(60).clamp(5, 86400) as i64
                            );
                        // Event descriptions are never persisted or notified before public visibility verification.
                        let mut pending: HashSet<_> =
                            next.pending_event_repositories.iter().cloned().collect();
                        for item in page.items {
                            if pending.len() < 1000 {
                                pending.insert(item.full_name);
                            }
                        }
                        next.pending_event_repositories = pending.into_iter().collect();
                        next.pending_event_repositories.sort();
                        let next_poll = next.events_next_at;
                        set_source(&mut next, "events", "healthy", "Public event references queued for visibility verification; GitHub's feed is bounded, not exhaustive.", now, next_poll);
                        succeeded += 1;
                    }
                    Err(error) => source_error(&mut next, "events", &error, now),
                },
                Err(error) => source_error(&mut next, "events", &error, now),
            }
        }

        if self.config.streams.enable_search_stream
            && source_due(&next, "search", now)
            && (!next.search_windows.is_empty()
                || now.saturating_sub(next.last_search_at)
                    >= self.config.general.search_interval_seconds as i64)
        {
            attempted += 1;
            match self.collect_search(&mut next, &mut candidates).await {
                Ok(pages) => {
                    let status = if next.search_windows.is_empty() {
                        "healthy"
                    } else {
                        "catching_up"
                    };
                    let message = format!("Fetched {pages} pages; {} bounded windows remain. Search is eventually indexed and reconciled with a ten-minute overlap, not an exhaustive GitHub archive.", next.search_windows.len());
                    set_source(
                        &mut next,
                        "search",
                        status,
                        &message,
                        now,
                        now + self.config.general.search_interval_seconds as i64,
                    );
                    succeeded += 1;
                }
                Err(error) => source_error(&mut next, "search", &error, now),
            }
        }

        if self.config.streams.enable_sequential_stream {
            if next.sequential_since == 0 {
                // Start at the lowest verified recent observation, not an unsupported "newest" sort.
                if let Some(id) = candidates.keys().next() {
                    next.sequential_since = *id;
                    info!(anchor = *id, "sequential source anchored to a recent observation; older history is outside this stream");
                }
            }
            if next.sequential_since > 0 && source_due(&next, "sequential", now) {
                attempted += 1;
                match self.collect_sequential(&mut next, &mut candidates).await {
                    Ok(pages) => {
                        set_source(&mut next, "sequential", "healthy", &format!("Fetched {pages} pages from the persisted ID anchor; pre-anchor history is not covered."), now, now + self.config.general.interval_seconds as i64);
                        succeeded += 1;
                    }
                    Err(error) => source_error(&mut next, "sequential", &error, now),
                }
            } else if next.sequential_since == 0 {
                set_source(&mut next, "sequential", "awaiting_anchor", "Waiting for a verified discovery anchor. Enable events or search on a new installation.", 0, 0);
            }
        }

        if self.config.monitoring.enabled
            && source_due(&next, "enrichment", now)
            && now >= next.enrichment_next_at
        {
            let mut pending = Vec::new();
            for name in next
                .pending_event_repositories
                .iter()
                .take(self.config.monitoring.enrich_per_cycle)
            {
                pending.push(name.clone());
            }
            for item in self
                .db
                .enrichment_candidates(self.config.monitoring.enrich_per_cycle)?
            {
                if !pending.contains(&item.full_name)
                    && pending.len() < self.config.monitoring.enrich_per_cycle
                {
                    pending.push(item.full_name);
                }
            }
            for item in candidates.values() {
                if !item.metadata_complete
                    && !pending.contains(&item.full_name)
                    && pending.len() < self.config.monitoring.enrich_per_cycle
                {
                    pending.push(item.full_name.clone());
                }
            }
            if !pending.is_empty() {
                attempted += 1;
                let mut completed = 0;
                let mut last_error = None;
                for name in pending {
                    if let Err(error) = self.available(RateResource::Core).await {
                        last_error = Some(error);
                        break;
                    }
                    match self.crawler.fetch_repository(&name).await {
                        Ok(mut item) => {
                            next.pending_event_repositories
                                .retain(|pending| pending != &name);
                            if !item.private {
                                item.source = "enrichment".into();
                                insert_candidate(&mut candidates, item);
                                completed += 1;
                            }
                        }
                        Err(error) => {
                            if matches!(error, CrawlerError::Api { status } if status == reqwest::StatusCode::NOT_FOUND)
                            {
                                next.pending_event_repositories
                                    .retain(|pending| pending != &name);
                            }
                            last_error = Some(error);
                            break;
                        }
                    }
                }
                next.enrichment_next_at = now + self.config.general.interval_seconds as i64;
                if let Some(error) = last_error {
                    source_error(&mut next, "enrichment", &error, now);
                } else {
                    let next_enrichment = next.enrichment_next_at;
                    set_source(&mut next, "enrichment", "healthy", &format!("Verified {completed} public metadata snapshots within the configured request budget."), now, next_enrichment);
                }
                if completed > 0 {
                    succeeded += 1;
                }
            }
        }

        if self.config.monitoring.enabled && source_due(&next, "watch", now) {
            let watched = self.db.due_watched(
                now,
                self.config.monitoring.watch_interval_seconds,
                self.config.monitoring.watch_per_cycle,
            )?;
            if !watched.is_empty() {
                attempted += 1;
                let mut completed = 0;
                let mut last_error = None;
                for previous in watched {
                    if let Err(error) = self.available(RateResource::Core).await {
                        last_error = Some(error);
                        break;
                    }
                    match self.crawler.fetch_repository(&previous.full_name).await {
                        Ok(mut item) if !item.private => {
                            if let Err(error) = self.available(RateResource::Core).await {
                                last_error = Some(error);
                                break;
                            }
                            match self.crawler.fetch_latest_release(&item.full_name).await {
                                Ok(release) => item.latest_release = release,
                                Err(error) => {
                                    last_error = Some(error);
                                    break;
                                }
                            }
                            item.source = "watch".into();
                            insert_candidate(&mut candidates, item);
                            completed += 1;
                        }
                        Ok(_) => {
                            self.db.quarantine_repository(previous.id)?;
                            last_error = Some(CrawlerError::Api {
                                status: reqwest::StatusCode::FORBIDDEN,
                            });
                        }
                        Err(error) => {
                            if matches!(error, CrawlerError::Api { status } if status == reqwest::StatusCode::NOT_FOUND)
                            {
                                self.db.quarantine_repository(previous.id)?;
                            }
                            last_error = Some(error);
                            break;
                        }
                    }
                }
                if let Some(error) = last_error {
                    source_error(&mut next, "watch", &error, now);
                } else {
                    set_source(&mut next, "watch", "healthy", &format!("Refreshed {completed} watched repositories, including latest release tags. No repository code was downloaded or executed."), now, now + self.config.general.interval_seconds as i64);
                }
                if completed > 0 {
                    succeeded += 1;
                }
            }
        }

        let mut items: Vec<_> = candidates
            .into_values()
            .filter(|repo| !repo.private)
            .collect();
        let mut assessments = Vec::with_capacity(items.len());
        for item in &mut items {
            // Rank sparse observations using stored verified metadata, without fabricating a new full snapshot.
            let mut evaluated = item.clone();
            if !item.metadata_complete {
                if let Some(previous) = self.db.get_repository(item.id)? {
                    if previous.metadata_complete {
                        evaluated = previous;
                        evaluated.source = item.source.clone();
                    }
                }
            }
            let assessment = self.filter.evaluate(&mut evaluated);
            item.is_priority = evaluated.is_priority;
            assessments.push(assessment);
        }
        let spam_count = assessments
            .iter()
            .filter(|a| a.decision == "rejected")
            .count();
        let mut channels = Notifier::new(self.config.notifications.clone()).channels();
        if self.config.storage.enable_log_file {
            channels.push("log".into());
        }
        if self.config.storage.enable_jsonl_stream {
            channels.push("jsonl".into());
        }
        next.checked = timestamp(Utc::now());
        let new_items = self.db.ingest(&items, &assessments, &next, &channels)?;
        self.state = next;
        self.outbox_wakeup.notify_one();
        if attempted > 0 && succeeded == 0 {
            return Err(EngineError::SourcesUnavailable);
        }
        let priority_count = new_items.iter().filter(|repo| repo.is_priority).count();
        let (db_total, _, _) = self.db.get_stats()?;
        let status = self
            .state
            .sources
            .iter()
            .map(|source| format!("{}: {}", source.name, source.status))
            .collect::<Vec<_>>()
            .join("; ");
        Ok(CycleResult {
            cycle: self.cycle,
            items: new_items,
            spam_count,
            priority_count,
            duration_ms: started.elapsed().as_millis(),
            db_total,
            status,
        })
    }

    async fn available(&self, resource: RateResource) -> Result<(), CrawlerError> {
        // Scheduling a retry is independent of other sources; never block a cycle for a full quota reset.
        match self.token_pool.wait_if_exhausted(resource).await {
            Some(wait) => Err(CrawlerError::RateLimited(wait)),
            None => Ok(()),
        }
    }

    async fn collect_sequential(
        &self,
        state: &mut AppState,
        candidates: &mut BTreeMap<i64, RepoItem>,
    ) -> Result<usize, CrawlerError> {
        let mut pages = 0;
        while pages < self.config.general.max_pages_per_cycle {
            self.available(RateResource::Core).await?;
            let url = state.sequential_next_url.clone().unwrap_or_else(|| {
                format!(
                    "https://api.github.com/repositories?since={}&per_page=100",
                    state.sequential_since
                )
            });
            let page = self.crawler.fetch_repositories_page(&url).await?;
            pages += 1;
            for raw in page.items {
                state.sequential_since = state.sequential_since.max(raw.id);
                let mut item = raw_to_item(raw);
                item.source = "sequential".into();
                insert_candidate(candidates, item);
            }
            state.sequential_next_url = page.next_url;
            if state.sequential_next_url.is_none() {
                break;
            }
        }
        Ok(pages)
    }

    async fn collect_search(
        &self,
        state: &mut AppState,
        candidates: &mut BTreeMap<i64, RepoItem>,
    ) -> Result<usize, CrawlerError> {
        if state.search_windows.is_empty() {
            let start =
                parse_timestamp(&state.search_watermark).map_err(|_| CrawlerError::InvalidQuery)?;
            let end = Utc::now() - ChronoDuration::seconds(120);
            if start >= end {
                return Ok(0);
            }
            let queries = if self.config.streams.search_queries.is_empty() {
                vec![String::new()]
            } else {
                self.config.streams.search_queries.clone()
            };
            state.search_target_end = timestamp(end);
            for (query_index, query) in queries.into_iter().enumerate() {
                state.search_windows.push(SearchWindow {
                    start: timestamp(start),
                    end: timestamp(end),
                    page: 1,
                    query_index,
                    expected_total: None,
                    query,
                });
            }
        }
        let mut pages = 0;
        while !state.search_windows.is_empty() && pages < self.config.general.max_pages_per_cycle {
            self.available(RateResource::Search).await?;
            let window = &state.search_windows[0];
            let query = format!("{} created:{}..{}", window.query, window.start, window.end);
            let page = self.crawler.fetch_search_page(&query, window.page).await?;
            pages += 1;
            apply_search_page(state, page, candidates)?;
        }
        if state.search_windows.is_empty() && !state.search_target_end.is_empty() {
            let end = parse_timestamp(&state.search_target_end)
                .map_err(|_| CrawlerError::InvalidQuery)?;
            state.search_watermark =
                timestamp(end - ChronoDuration::seconds(SEARCH_OVERLAP_SECONDS));
            state.search_target_end.clear();
            state.last_search_at = Utc::now().timestamp();
        }
        Ok(pages)
    }
}

fn apply_search_page(
    state: &mut AppState,
    page: Page<GithubRepositoryRaw>,
    candidates: &mut BTreeMap<i64, RepoItem>,
) -> Result<(), CrawlerError> {
    let window = state
        .search_windows
        .first()
        .cloned()
        .ok_or(CrawlerError::InvalidQuery)?;
    if page.incomplete_results || page.total_count.is_some_and(|total| total > 1000) {
        let start = parse_timestamp(&window.start).map_err(|_| CrawlerError::InvalidQuery)?;
        let end = parse_timestamp(&window.end).map_err(|_| CrawlerError::InvalidQuery)?;
        let seconds = (end - start).num_seconds();
        if seconds <= 1 || state.search_windows.len() >= MAX_SEARCH_WINDOWS {
            // Retain the blocking window: a coverage gap must not silently advance the watermark.
            return Err(CrawlerError::InvalidQuery);
        }
        let midpoint = timestamp(start + ChronoDuration::seconds(seconds / 2));
        let mut left = window.clone();
        left.end = midpoint.clone();
        left.page = 1;
        left.expected_total = None;
        let mut right = window;
        right.start = midpoint;
        right.page = 1;
        right.expected_total = None;
        state.search_windows.splice(0..1, [left, right]);
        return Ok(());
    }
    let total = page.total_count.ok_or(CrawlerError::Json)?;
    if window
        .expected_total
        .is_some_and(|previous| previous != total)
    {
        state.search_windows[0].page = 1;
        state.search_windows[0].expected_total = None;
        return Err(CrawlerError::InvalidQuery);
    }
    let count = page.items.len();
    for raw in page.items {
        let mut item = raw_to_item(raw);
        item.source = "search".into();
        insert_candidate(candidates, item);
    }
    let covered = window.page.saturating_mul(100);
    let expected_on_page = total
        .saturating_sub(window.page.saturating_sub(1).saturating_mul(100))
        .min(100);
    if count != expected_on_page {
        return Err(CrawlerError::InvalidQuery);
    }
    if covered < total {
        if count != 100 || window.page >= 10 || page.next_url.is_none() {
            return Err(CrawlerError::InvalidQuery);
        }
        state.search_windows[0].page += 1;
        state.search_windows[0].expected_total = Some(total);
    } else {
        state.search_windows.remove(0);
    }
    Ok(())
}

fn insert_candidate(candidates: &mut BTreeMap<i64, RepoItem>, item: RepoItem) {
    if item.private {
        return;
    }
    if candidates
        .get(&item.id)
        .is_some_and(|old| old.metadata_complete && !item.metadata_complete)
    {
        return;
    }
    candidates.insert(item.id, item);
}

fn source_due(state: &AppState, name: &str, now: i64) -> bool {
    state
        .sources
        .iter()
        .find(|source| source.name == name)
        .is_none_or(|source| now >= source.next_allowed_at)
}

fn set_source(
    state: &mut AppState,
    name: &str,
    status: &str,
    message: &str,
    success: i64,
    next: i64,
) {
    if let Some(source) = state.sources.iter_mut().find(|source| source.name == name) {
        source.status = status.into();
        source.message = message.into();
        source.last_success_at = source.last_success_at.max(success);
        source.next_allowed_at = next;
    } else {
        state.sources.push(SourceStatus {
            name: name.into(),
            status: status.into(),
            message: message.into(),
            last_success_at: success,
            next_allowed_at: next,
        });
    }
}

fn source_error(state: &mut AppState, name: &str, error: &CrawlerError, now: i64) {
    let wait = match error {
        CrawlerError::RateLimited(wait) => *wait,
        _ => 60,
    };
    let jitter = (now as u64 ^ name.bytes().map(u64::from).sum::<u64>()) % 11;
    let message = if matches!(error, CrawlerError::InvalidQuery) && name == "search" {
        "Search coverage is incomplete or the query is invalid; the blocking window and watermark were retained. Narrow the query or inspect the persisted state.".into()
    } else {
        error.to_string()
    };
    set_source(
        state,
        name,
        if matches!(error, CrawlerError::RateLimited(_)) {
            "rate_limited"
        } else {
            "degraded"
        },
        &message,
        0,
        now.saturating_add(wait.saturating_add(jitter).min(i64::MAX as u64) as i64),
    );
    warn!(source = name, error = %error, "source failed independently; completed pages will be committed with their data");
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, EngineError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| EngineError::InvalidState)
}

fn validate_state(state: &AppState) -> Result<(), EngineError> {
    if !(1..=3).contains(&state.schema_version)
        || state.sequential_since < 0
        || state.search_windows.len() > MAX_SEARCH_WINDOWS
        || state.pending_event_repositories.len() > 1000
    {
        return Err(EngineError::InvalidState);
    }
    parse_timestamp(&state.search_watermark)?;
    if !state.search_target_end.is_empty() {
        parse_timestamp(&state.search_target_end)?;
    }
    if !state.search_windows.is_empty() && state.search_target_end.is_empty() {
        return Err(EngineError::InvalidState);
    }
    for window in &state.search_windows {
        if !(1..=10).contains(&window.page)
            || parse_timestamp(&window.start)? >= parse_timestamp(&window.end)?
            || window.query.len() > 4096
        {
            return Err(EngineError::InvalidState);
        }
    }
    for name in &state.pending_event_repositories {
        crate::crawler::validate_repository_name(name)?;
    }
    Ok(())
}

async fn dispatch_pending(db: &Database, config: &AppConfig) -> Result<usize, EngineError> {
    let notifier = Notifier::new(config.notifications.clone());
    let started = Instant::now();
    let mut delivered = 0;
    for _ in 0..50 {
        if started.elapsed() >= Duration::from_secs(30) {
            break;
        }
        // Claim individually: a slow channel cannot expire leases of waiting rows.
        let Some(message) = db.claim_outbox(1)?.into_iter().next() else {
            break;
        };
        let result = if matches!(message.channel.as_str(), "log" | "jsonl") {
            let config = config.clone();
            let message = message.clone();
            tokio::task::spawn_blocking(move || write_event_output(&config, &message))
                .await
                .map_err(|_| "Local output worker failed.".to_string())
                .and_then(|result| result.map_err(|_| "Local output write failed.".to_string()))
        } else {
            notifier
                .deliver(
                    &message.channel,
                    std::slice::from_ref(&message.payload),
                    &message.event_key,
                )
                .await
                .map_err(|error| error.to_string())
        };
        match result {
            Ok(()) => {
                db.finish_outbox(message.id, None)?;
                delivered += 1;
            }
            Err(error) => {
                db.finish_outbox(message.id, Some(&error))?;
                warn!(channel = %message.channel, event = %message.event_key, error = %error, "delivery failed; durable retry scheduled");
            }
        }
    }
    Ok(delivered)
}

fn write_event_output(config: &AppConfig, message: &OutboxMessage) -> std::io::Result<()> {
    let parent = Path::new(&config.storage.database_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let month = DateTime::parse_from_rfc3339(&message.payload.discovered_at)
        .map_err(|_| std::io::Error::other("Invalid event timestamp"))?
        .format("%Y-%m")
        .to_string();
    let directory = parent.join("outputs").join(month);
    ensure_output_directory(&directory)?;
    let name = message.event_key.replace(':', "-");
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(std::io::Error::other("Invalid event key"));
    }
    let content = if message.channel == "jsonl" {
        let mut value = serde_json::to_value(&message.payload).map_err(std::io::Error::other)?;
        value["event_key"] = serde_json::Value::String(message.event_key.clone());
        format!(
            "{}\n",
            serde_json::to_string(&value).map_err(std::io::Error::other)?
        )
    } else {
        let description: String = message
            .payload
            .description
            .as_deref()
            .unwrap_or("No description")
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        format!(
            "{} | {} | {} | {}\n",
            message.event_key, message.payload.full_name, description, message.payload.html_url
        )
    };
    let path = directory.join(format!(
        "{name}.{}",
        if message.channel == "jsonl" {
            "jsonl"
        } else {
            "log"
        }
    ));
    if path.exists() {
        return verify_output(&path, content.as_bytes());
    }
    let temporary = directory.join(format!(
        ".{name}.{}-{}.tmp",
        std::process::id(),
        message.attempts
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        // A hard-link publishes without overwriting an existing event, then removes the temporary name.
        match fs::hard_link(&temporary, &path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_output(&path, content.as_bytes())
            }
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn ensure_output_directory(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.is_dir() || is_link(&metadata) {
                    return Err(std::io::Error::other("Unsafe output directory"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn verify_output(path: &Path, expected: &[u8]) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_link(&metadata) || metadata.len() != expected.len() as u64 {
        return Err(std::io::Error::other(
            "Existing output conflicts with the event",
        ));
    }
    let mut actual = Vec::new();
    fs::File::open(path)?
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut actual)?;
    if actual != expected {
        return Err(std::io::Error::other(
            "Existing output conflicts with the event",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> SearchWindow {
        SearchWindow {
            start: "2026-10-01T00:00:00Z".into(),
            end: "2026-10-01T01:00:00Z".into(),
            page: 1,
            query_index: 0,
            expected_total: None,
            query: String::new(),
        }
    }

    fn page(total: usize, incomplete: bool) -> Page<GithubRepositoryRaw> {
        Page {
            items: vec![],
            next_url: None,
            etag: None,
            poll_interval: None,
            total_count: Some(total),
            incomplete_results: incomplete,
        }
    }

    #[test]
    fn search_splits_saturated_or_incomplete_windows_without_advancing_watermark() {
        for response in [page(1001, false), page(1, true)] {
            let mut state = AppState {
                search_windows: vec![window()],
                ..Default::default()
            };
            let before = state.search_watermark.clone();
            apply_search_page(&mut state, response, &mut BTreeMap::new()).unwrap();
            assert_eq!(state.search_windows.len(), 2);
            assert_eq!(state.search_windows[0].end, state.search_windows[1].start);
            assert_eq!(state.search_watermark, before);
        }
    }

    #[test]
    fn incomplete_one_second_window_is_retained_as_a_gap() {
        let mut window = window();
        window.end = "2026-10-01T00:00:01Z".into();
        let mut state = AppState {
            search_windows: vec![window],
            ..Default::default()
        };
        assert!(apply_search_page(&mut state, page(2000, false), &mut BTreeMap::new()).is_err());
        assert_eq!(state.search_windows.len(), 1);
    }

    #[test]
    fn search_does_not_skip_short_pages_or_mutating_totals() {
        let mut state = AppState {
            search_windows: vec![window()],
            ..Default::default()
        };
        assert!(apply_search_page(&mut state, page(150, false), &mut BTreeMap::new()).is_err());
        assert_eq!(state.search_windows[0].page, 1);
        state.search_windows[0].page = 2;
        state.search_windows[0].expected_total = Some(150);
        assert!(apply_search_page(&mut state, page(160, false), &mut BTreeMap::new()).is_err());
        assert_eq!(state.search_windows[0].page, 1);
    }

    #[test]
    fn completed_empty_window_is_removed() {
        let mut state = AppState {
            search_windows: vec![window()],
            ..Default::default()
        };
        apply_search_page(&mut state, page(0, false), &mut BTreeMap::new()).unwrap();
        assert!(state.search_windows.is_empty());
    }

    #[test]
    fn source_failure_is_independent_and_scheduled() {
        let mut state = AppState::default();
        set_source(&mut state, "events", "healthy", "OK", 100, 200);
        source_error(&mut state, "search", &CrawlerError::RateLimited(1800), 100);
        assert_eq!(state.sources[0].status, "healthy");
        assert!(!source_due(&state, "search", 1899));
        assert_eq!(state.sources[1].last_success_at, 0);
    }

    #[tokio::test]
    async fn maintenance_cycle_commits_state_without_any_network() {
        let db = Database::new(":memory:", false).unwrap();
        let mut config = AppConfig::default();
        config.storage.state_path = "does-not-exist-bloomrepo-fixture.json".into();
        config.streams.enable_events_stream = false;
        config.streams.enable_search_stream = false;
        config.streams.enable_sequential_stream = false;
        config.monitoring.enabled = false;
        let mut engine = Engine::new(config, db.clone()).unwrap();
        let result = engine.run_cycle().await.unwrap();
        assert!(result.items.is_empty());
        assert_eq!(
            db.load_state().unwrap().unwrap().checked,
            engine.state.checked
        );
    }
}
