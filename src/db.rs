use crate::analysis::AnalysisReport;
use crate::filter::RepoFilter;
use crate::models::{Assessment, RepoItem};
use crate::state::AppState;
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Result, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const SCHEMA_VERSION: i64 = 2;
const MAX_PAGE: usize = 500;
const MAX_BATCH: usize = 10_000;
const MAX_JSON: usize = 256 * 1024;
const MAX_REPORT: usize = 2 * 1024 * 1024;
const LEASE_SECONDS: i64 = 600;
const MAX_ATTEMPTS: u32 = 12;

#[derive(Clone, Default)]
pub struct RepositoryQuery {
    pub text: String,
    pub priority_only: bool,
    pub hide_forks: bool,
    pub watch_only: bool,
    pub review_state: Option<String>,
    pub include_rejected: bool,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Clone)]
pub struct RepositoryRecord {
    pub repo: RepoItem,
    pub assessment: Assessment,
    pub review_state: String,
    pub watched: bool,
    pub last_observed_at: String,
}

#[derive(Clone)]
pub struct ChangeRecord {
    pub observed_at: String,
    pub field: String,
    pub before: String,
    pub after: String,
}

pub struct OperationalHealth {
    pub pending_notifications: usize,
    pub failed_notifications: usize,
    pub watched_repositories: usize,
    pub observations: usize,
    pub rejected_repositories: usize,
    pub sources: Vec<SourceStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SourceStatus {
    pub name: String,
    pub status: String,
    pub message: String,
    pub last_success_at: i64,
    pub next_allowed_at: i64,
}

#[derive(Clone)]
pub struct OutboxMessage {
    pub id: i64,
    pub event_key: String,
    pub channel: String,
    pub payload: RepoItem,
    pub attempts: u32,
}

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P, enable_wal: bool) -> Result<Self> {
        let path = path.as_ref();
        let memory = path == Path::new(":memory:");
        let checked_path = if memory {
            path.to_path_buf()
        } else {
            check_path(path, true)?
        };
        let path = checked_path.as_path();
        let existing = if memory {
            false
        } else {
            match fs::symlink_metadata(path) {
                Ok(meta) => {
                    if !meta.is_file() {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    meta.len() > 0
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(e) => return Err(io_error(e)),
            }
        };
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if version < SCHEMA_VERSION {
            // Online backup includes committed WAL pages. Never copy just the .db file.
            if existing {
                let filename = path.file_name().ok_or(rusqlite::Error::InvalidQuery)?;
                let mut backup_name = filename.to_os_string();
                backup_name.push(format!(
                    ".migration-v{version}-to-v{SCHEMA_VERSION}-{}-{}.bak",
                    chrono::Utc::now()
                        .timestamp_nanos_opt()
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    std::process::id()
                ));
                backup_connection(&conn, &path.with_file_name(backup_name))?;
            }
            migrate(&mut conn)?;
        }
        if enable_wal && !memory {
            let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        // FULL is also required when reopening a database already using WAL.
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| rusqlite::Error::InvalidQuery)
    }

    pub fn backup_to(&self, path: &Path) -> Result<()> {
        let conn = self.lock()?;
        backup_connection(&conn, path)
    }

    pub fn rebuild_index(&self) -> Result<()> {
        self.lock()?
            .execute("INSERT INTO repos_fts(repos_fts) VALUES ('rebuild')", [])?;
        Ok(())
    }

    pub fn get_max_id(&self) -> Result<i64> {
        self.lock()?
            .query_row("SELECT COALESCE(MAX(id),0) FROM repos", [], |r| r.get(0))
    }

    pub fn get_stats(&self) -> Result<(usize, usize, usize)> {
        self.lock()?.query_row(
            "SELECT COUNT(*), COALESCE(SUM(substr(discovered_at,1,10)=?1),0),
             COALESCE(SUM(is_priority=1),0) FROM repos WHERE private=0",
            [chrono::Utc::now().format("%Y-%m-%d").to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
    }

    #[allow(dead_code)]
    pub fn existing_ids(&self, items: &[RepoItem]) -> Result<HashSet<i64>> {
        if items.len() > MAX_BATCH {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let conn = self.lock()?;
        let mut existing = HashSet::new();
        for chunk in items.chunks(400) {
            let sql = format!(
                "SELECT id FROM repos WHERE id IN ({})",
                vec!["?"; chunk.len()].join(",")
            );
            let mut stmt = conn.prepare(&sql)?;
            for row in stmt.query_map(
                rusqlite::params_from_iter(chunk.iter().map(|r| r.id)),
                |r| r.get(0),
            )? {
                existing.insert(row?);
            }
        }
        Ok(existing)
    }

    pub fn get_repository(&self, id: i64) -> Result<Option<RepoItem>> {
        self.lock()?
            .query_row(
                "SELECT * FROM repos WHERE id=?1 AND private=0",
                [id],
                row_to_repo,
            )
            .optional()
    }

    pub fn list_repositories(&self, query: &RepositoryQuery) -> Result<Vec<RepositoryRecord>> {
        if query.text.len() > 4096
            || query.text.split_whitespace().count() > 64
            || query
                .text
                .chars()
                .any(|c| c.is_control() && !c.is_whitespace())
            || query.offset > i64::MAX as usize
            || query
                .review_state
                .as_deref()
                .is_some_and(|s| !valid_review(s))
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let conn = self.lock()?;
        let raw = query.text.trim();
        let fts = sanitize_fts5_query(raw);
        // Punctuation-only input cannot be tokenized by FTS; use literal LIKE instead.
        let use_fts = raw.chars().any(char::is_alphanumeric);
        let text_clause = if raw.is_empty() {
            "1"
        } else if use_fts {
            "r.id IN (SELECT rowid FROM repos_fts WHERE repos_fts MATCH ?1)"
        } else {
            "(r.name LIKE ?1 ESCAPE '!' OR r.full_name LIKE ?1 ESCAPE '!'
              OR r.description LIKE ?1 ESCAPE '!' OR r.topics LIKE ?1 ESCAPE '!')"
        };
        let sql = format!(
            "SELECT r.* FROM repos r WHERE r.private=0 AND ({text_clause})
             AND (?2=0 OR r.is_priority=1) AND (?3=0 OR r.fork=0)
             AND (?4=0 OR r.watched=1) AND (?5 IS NULL OR r.review_state=?5)
             AND (?6=1 OR r.decision<>'rejected') ORDER BY r.id DESC LIMIT ?7 OFFSET ?8"
        );
        let text = if use_fts { fts } else { like_pattern(raw) };
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![
                text,
                query.priority_only,
                query.hide_forks,
                query.watch_only,
                query.review_state,
                query.include_rejected,
                query.limit.min(MAX_PAGE) as i64,
                query.offset as i64
            ],
            row_to_record,
        )?;
        rows.collect()
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<RepoItem>> {
        Ok(self
            .list_repositories(&RepositoryQuery {
                text: query.to_owned(),
                limit,
                ..Default::default()
            })?
            .into_iter()
            .map(|r| r.repo)
            .collect())
    }

    pub fn set_watched(&self, id: i64, watched: bool) -> Result<()> {
        self.set_user_field(id, "watched", if watched { "1" } else { "0" })
    }

    pub fn quarantine_repository(&self, id: i64) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE repos SET private=1 WHERE id=?1", [id])?;
        tx.execute("UPDATE outbox SET status='cancelled',lease_until=0 WHERE repo_id=?1 AND status IN ('pending','processing','failed')", [id])?;
        tx.commit()
    }

    pub fn set_review_state(&self, id: i64, state: &str) -> Result<()> {
        if !valid_review(state) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        self.set_user_field(id, "review_state", state)
    }

    fn set_user_field(&self, id: i64, field: &str, value: &str) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let before: String = tx.query_row(
            &format!("SELECT CAST({field} AS TEXT) FROM repos WHERE id=?1 AND private=0"),
            [id],
            |r| r.get(0),
        )?;
        if before != value {
            tx.execute(
                &format!("UPDATE repos SET {field}=?1 WHERE id=?2"),
                params![value, id],
            )?;
            tx.execute(
                "INSERT INTO changes(repo_id,observed_at,field,before_value,after_value)
                        VALUES(?1,?2,?3,?4,?5)",
                params![id, timestamp(), field, before, value],
            )?;
            if field == "review_state" && value == "ignored" {
                tx.execute(
                    "UPDATE outbox SET status='cancelled',lease_until=0
                            WHERE repo_id=?1 AND status IN ('pending','processing','failed')",
                    [id],
                )?;
            }
        }
        tx.commit()
    }

    pub fn list_changes(&self, id: i64, limit: usize) -> Result<Vec<ChangeRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT observed_at,field,before_value,after_value FROM changes
                                    WHERE repo_id=?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![id, limit.min(MAX_PAGE) as i64], |r| {
            Ok(ChangeRecord {
                observed_at: r.get(0)?,
                field: r.get(1)?,
                before: r.get(2)?,
                after: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn load_state(&self) -> Result<Option<AppState>> {
        let text: Option<String> = self
            .lock()?
            .query_row("SELECT payload FROM app_state WHERE id=1", [], |r| r.get(0))
            .optional()?;
        text.map(|s| decode_json(&s, MAX_JSON)).transpose()
    }

    pub fn ingest(
        &self,
        items: &[RepoItem],
        assessments: &[Assessment],
        state: &AppState,
        channels: &[String],
    ) -> Result<Vec<RepoItem>> {
        self.ingest_inner(items, assessments, Some(state), channels)
    }

    fn ingest_inner(
        &self,
        items: &[RepoItem],
        assessments: &[Assessment],
        state: Option<&AppState>,
        channels: &[String],
    ) -> Result<Vec<RepoItem>> {
        if items.len() != assessments.len()
            || items.len() > MAX_BATCH
            || channels.len() > 6
            || channels.iter().any(|c| !valid_channel(c))
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let state_json = state.map(state_json).transpose()?;
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut accepted = Vec::new();
        for (item, assessment) in items.iter().zip(assessments) {
            // A private observation fails the whole batch, including cursor advancement.
            let incoming = safe_repo(item)?;
            let assessment = safe_assessment(assessment)?;
            let old = tx
                .query_row("SELECT * FROM repos WHERE id=?1", [item.id], row_to_record)
                .optional()?;
            let (announced, revision): (bool, i64) = if old.is_some() {
                tx.query_row(
                    "SELECT accepted_announced,metadata_revision FROM repos WHERE id=?1",
                    [item.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?
            } else {
                (false, 0)
            };
            let merged = merge_repo(old.as_ref().map(|r| &r.repo), &incoming);
            let changed = if let Some(old) = &old {
                metadata_changes(&old.repo, &merged)?
            } else {
                Vec::new()
            };
            let revision = if changed.is_empty() {
                revision
            } else {
                revision
                    .checked_add(1)
                    .ok_or(rusqlite::Error::InvalidQuery)?
            };
            let observed_at = timestamp();
            upsert_repo(&tx, &merged, &assessment, &observed_at, revision)?;
            tx.execute(
                "INSERT INTO observations(repo_id,observed_at,source,payload,assessment)
                        VALUES(?1,?2,?3,?4,?5)",
                params![
                    merged.id,
                    observed_at,
                    incoming.source,
                    encode_json(&incoming, MAX_JSON)?,
                    encode_json(&assessment, MAX_JSON)?
                ],
            )?;
            for (field, before, after) in &changed {
                tx.execute(
                    "INSERT INTO changes(repo_id,observed_at,field,before_value,after_value)
                            VALUES(?1,?2,?3,?4,?5)",
                    params![merged.id, observed_at, field, before, after],
                )?;
            }
            let ignored = old.as_ref().is_some_and(|r| r.review_state == "ignored");
            let eligible = assessment.decision == "accepted" && !ignored;
            if !eligible {
                tx.execute(
                    "UPDATE outbox SET status='cancelled',lease_until=0 WHERE repo_id=?1
                            AND status IN ('pending','processing','failed')",
                    [merged.id],
                )?;
            }
            if eligible && !announced {
                tx.execute(
                    "UPDATE repos SET accepted_announced=1 WHERE id=?1",
                    [merged.id],
                )?;
                enqueue(&tx, &merged, channels, "new")?;
                accepted.push(merged.clone());
            } else if eligible && !changed.is_empty() && old.as_ref().is_some_and(|r| r.watched) {
                enqueue(&tx, &merged, channels, &format!("change:{revision}"))?;
            }
            // Only successful persisted watch observations advance the watch clock.
            if matches!(incoming.source.as_str(), "watch" | "watched") {
                tx.execute(
                    "UPDATE repos SET last_watch_success=?1 WHERE id=?2",
                    params![chrono::Utc::now().timestamp(), merged.id],
                )?;
            }
        }
        if let Some(state_json) = state_json {
            tx.execute(
                "INSERT INTO app_state(id,payload) VALUES(1,?1)
                        ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                [state_json],
            )?;
        }
        if let Some(state) = state {
            for source in &state.sources {
                if source.name.len() > 64 || source.status.len() > 64 || source.message.len() > 4096 || source.last_success_at < 0 || source.next_allowed_at < 0 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                tx.execute("INSERT INTO source_status(name,status,message,last_success_at,next_allowed_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(name) DO UPDATE SET status=excluded.status,message=excluded.message,last_success_at=MAX(source_status.last_success_at,excluded.last_success_at),next_allowed_at=excluded.next_allowed_at", params![source.name,source.status,scrub(&source.message),source.last_success_at,source.next_allowed_at])?;
            }
        }
        tx.commit()?;
        Ok(accepted)
    }

    #[allow(dead_code)]
    pub fn insert_batch(&self, items: &[RepoItem]) -> Result<usize> {
        if items.len() > MAX_BATCH {
            return Err(rusqlite::Error::InvalidQuery);
        }
        // Legacy caller: preserve the durable cursor; never manufacture notification channels.
        let assessments: Vec<_> = items
            .iter()
            .map(|_| Assessment {
                decision: "accepted".into(),
                evaluated_at: timestamp(),
                ..Default::default()
            })
            .collect();
        self.ingest_inner(items, &assessments, None, &[])?;
        Ok(items.len())
    }

    pub fn enrichment_candidates(&self, limit: usize) -> Result<Vec<RepoItem>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM repos WHERE private=0 AND metadata_complete=0
                                    ORDER BY last_observed_at,id LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit.min(MAX_PAGE) as i64], row_to_repo)?;
        rows.collect()
    }

    pub fn due_watched(&self, now: i64, interval: u64, limit: usize) -> Result<Vec<RepoItem>> {
        if now < 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let cutoff = now.saturating_sub(interval.min(i64::MAX as u64) as i64);
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM repos WHERE private=0 AND watched=1
            AND (last_watch_success=0 OR last_watch_success<=?1)
            ORDER BY last_watch_success,id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![cutoff, limit.min(MAX_PAGE) as i64], row_to_repo)?;
        rows.collect()
    }

    #[allow(dead_code)]
    pub fn mark_watch_checked(&self, id: i64, now: i64) -> Result<()> {
        if now < 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if self.lock()?.execute(
            "UPDATE repos SET last_watch_success=MAX(last_watch_success,?1)
                                WHERE id=?2 AND private=0",
            params![now, id],
        )? != 1
        {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    pub fn re_evaluate(&self, filter: &RepoFilter) -> Result<usize> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut last_id = i64::MIN;
        let mut count = 0;
        loop {
            let batch: Vec<RepoItem> = {
                let mut stmt = tx.prepare(
                    "SELECT * FROM repos WHERE private=0 AND id>?1 ORDER BY id LIMIT 200",
                )?;
                let rows = stmt
                    .query_map([last_id], row_to_repo)?
                    .collect::<Result<Vec<_>>>()?;
                rows
            };
            if batch.is_empty() {
                break;
            }
            for mut repo in batch {
                last_id = repo.id;
                repo.is_priority = false;
                let assessment = safe_assessment(&filter.evaluate(&mut repo))?;
                tx.execute("UPDATE repos SET is_priority=?1,assessment_json=?2,decision=?3,
                            accepted_announced=CASE WHEN ?3='accepted' THEN 1 ELSE accepted_announced END
                            WHERE id=?4", params![repo.is_priority, encode_json(&assessment, MAX_JSON)?,
                            assessment.decision, repo.id])?;
                tx.execute(
                    "INSERT INTO assessment_history(repo_id,evaluated_at,assessment)
                            VALUES(?1,?2,?3)",
                    params![
                        repo.id,
                        assessment.evaluated_at,
                        encode_json(&assessment, MAX_JSON)?
                    ],
                )?;
                if assessment.decision != "accepted" {
                    tx.execute(
                        "UPDATE outbox SET status='cancelled',lease_until=0 WHERE repo_id=?1
                                AND status IN ('pending','processing','failed')",
                        [repo.id],
                    )?;
                }
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    #[allow(dead_code)]
    pub fn record_source_status(&self, source: &SourceStatus) -> Result<()> {
        if source.name.is_empty()
            || scrub(&source.name) != source.name
            || scrub(&source.status) != source.status
            || source.name.len() > 64
            || source.status.len() > 64
            || !source
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !source
                .status
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_- ".contains(&b))
            || source.last_success_at < 0
            || source.next_allowed_at < 0
            || source.message.len() > 4096
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        self.lock()?.execute("INSERT INTO source_status(name,status,message,last_success_at,next_allowed_at)
            VALUES(?1,?2,?3,?4,?5) ON CONFLICT(name) DO UPDATE SET status=excluded.status,
            message=excluded.message,last_success_at=MAX(source_status.last_success_at,excluded.last_success_at),
            next_allowed_at=excluded.next_allowed_at", params![source.name, scrub(&source.status),
            scrub(&source.message), source.last_success_at, source.next_allowed_at])?;
        Ok(())
    }

    pub fn operational_health(&self) -> Result<OperationalHealth> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let (pending_notifications, failed_notifications) = tx.query_row(
            "SELECT COALESCE(SUM(status IN ('pending','processing')),0),
             COALESCE(SUM(status='failed'),0) FROM outbox",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (watched_repositories, rejected_repositories) = tx.query_row(
            "SELECT COALESCE(SUM(watched=1),0),COALESCE(SUM(decision='rejected'),0)
             FROM repos WHERE private=0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let observations = tx.query_row("SELECT COUNT(*) FROM observations", [], |r| r.get(0))?;
        let sources = {
            let mut stmt = tx.prepare(
                "SELECT name,status,message,last_success_at,next_allowed_at
                                       FROM source_status ORDER BY name",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(SourceStatus {
                        name: r.get(0)?,
                        status: r.get(1)?,
                        message: r.get(2)?,
                        last_success_at: r.get(3)?,
                        next_allowed_at: r.get(4)?,
                    })
                })?
                .collect::<Result<Vec<_>>>()?;
            rows
        };
        tx.commit()?;
        Ok(OperationalHealth {
            pending_notifications,
            failed_notifications,
            watched_repositories,
            observations,
            rejected_repositories,
            sources,
        })
    }

    pub fn claim_outbox(&self, limit: usize) -> Result<Vec<OutboxMessage>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = chrono::Utc::now().timestamp();
        tx.execute(
            "UPDATE outbox SET status='failed',lease_until=0,
                    last_error='Delivery lease expired at retry limit.'
                    WHERE status='processing' AND lease_until<=?1 AND attempts>=?2",
            params![now, MAX_ATTEMPTS],
        )?;
        let mut messages = {
            let mut stmt = tx.prepare(
                "SELECT o.id,o.event_key,o.channel,o.payload,o.attempts
                FROM outbox o JOIN repos r ON r.id=o.repo_id
                WHERE r.private=0 AND r.review_state<>'ignored' AND r.decision='accepted'
                AND o.attempts<?1 AND ((o.status='pending' AND o.next_attempt_at<=?2)
                OR (o.status='processing' AND o.lease_until<=?2)) ORDER BY o.id LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(params![MAX_ATTEMPTS, now, limit.min(50) as i64], |r| {
                    let payload: String = r.get(3)?;
                    Ok(OutboxMessage {
                        id: r.get(0)?,
                        event_key: r.get(1)?,
                        channel: r.get(2)?,
                        payload: safe_repo(&decode_json(&payload, MAX_JSON)?)?,
                        attempts: r.get(4)?,
                    })
                })?
                .collect::<Result<Vec<_>>>()?;
            rows
        };
        for message in &mut messages {
            message.attempts += 1;
            tx.execute(
                "UPDATE outbox SET status='processing',attempts=?1,lease_until=?2
                        WHERE id=?3",
                params![message.attempts, now + LEASE_SECONDS, message.id],
            )?;
        }
        tx.commit()?;
        Ok(messages)
    }

    pub fn finish_outbox(&self, id: i64, error: Option<&str>) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = chrono::Utc::now().timestamp();
        let attempts: u32 = tx.query_row(
            "SELECT attempts FROM outbox WHERE id=?1
            AND status='processing' AND lease_until>?2",
            params![id, now],
            |r| r.get(0),
        )?;
        if let Some(error) = error {
            // Arbitrary errors can contain bot tokens, webhook URLs, or HTTP response bodies.
            // Store only known static diagnostics; never try to enumerate every secret format.
            let diagnostic = delivery_diagnostic(error);
            let delay = (5_i64 * (1_i64 << attempts.saturating_sub(1).min(10))).min(3600);
            let jitter: i64 = tx.query_row(
                "SELECT (random() & 2147483647) % ?1",
                [delay / 4 + 1],
                |r| r.get(0),
            )?;
            tx.execute(
                "UPDATE outbox SET status=?1,next_attempt_at=?2,lease_until=0,last_error=?3
                WHERE id=?4",
                params![
                    if attempts >= MAX_ATTEMPTS {
                        "failed"
                    } else {
                        "pending"
                    },
                    now + (delay + jitter).min(3600),
                    diagnostic,
                    id
                ],
            )?;
        } else {
            tx.execute(
                "UPDATE outbox SET status='delivered',delivered_at=?1,lease_until=0,
                        last_error=NULL WHERE id=?2",
                params![now, id],
            )?;
        }
        tx.commit()
    }

    pub fn retry_failed_notifications(&self) -> Result<usize> {
        self.lock()?.execute("UPDATE outbox SET status='pending',attempts=0,next_attempt_at=0,
            lease_until=0,last_error=NULL WHERE status='failed' AND repo_id IN
            (SELECT id FROM repos WHERE private=0 AND decision='accepted' AND review_state<>'ignored')", [])
    }

    pub fn save_analysis_report(&self, report: &AnalysisReport) -> Result<i64> {
        let mut value = serde_json::to_value(report).map_err(json_error)?;
        if report.findings.len() > 1000
            || report.dependencies.len() > 5000
            || report.limits.len() > 100
            || report.coverage_gaps.len() > 1000
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        // Secret findings must never persist caller-supplied source snippets.
        if let Some(findings) = value.get_mut("findings").and_then(Value::as_array_mut) {
            for finding in findings {
                if finding
                    .get("rule")
                    .and_then(Value::as_str)
                    .is_some_and(|r| r.starts_with("secret."))
                {
                    finding["evidence"] = Value::String(
                        "Credential-shaped material detected; value and source context omitted."
                            .into(),
                    );
                }
            }
        }
        scrub_json(&mut value, 0)?;
        let payload = encode_json(&value, MAX_REPORT)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO analysis_reports(generated_at,payload) VALUES(?1,?2)",
            params![scrub(&report.generated_at), payload],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn analysis_reports(&self, limit: usize) -> Result<Vec<AnalysisReport>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT payload FROM analysis_reports ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit.min(100) as i64], |r| {
            decode_json(&r.get::<_, String>(0)?, MAX_REPORT)
        })?;
        rows.collect()
    }
}

fn migrate(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if version < 1 {
        tx.execute_batch("CREATE TABLE IF NOT EXISTS repos(id INTEGER PRIMARY KEY);")?;
        let columns = {
            let mut stmt = tx.prepare("PRAGMA table_info(repos)")?;
            let columns = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<Result<HashSet<_>>>()?;
            columns
        };
        // Introspection permits both the shipped schema and earlier partial schemas.
        for (name, definition) in [
            ("name", "TEXT NOT NULL DEFAULT ''"),
            ("full_name", "TEXT NOT NULL DEFAULT ''"),
            ("owner", "TEXT NOT NULL DEFAULT ''"),
            ("owner_type", "TEXT"),
            ("html_url", "TEXT NOT NULL DEFAULT ''"),
            ("description", "TEXT"),
            ("fork", "INTEGER NOT NULL DEFAULT 0"),
            ("stars", "INTEGER NOT NULL DEFAULT 0"),
            ("forks_count", "INTEGER NOT NULL DEFAULT 0"),
            ("language", "TEXT"),
            ("license", "TEXT"),
            ("topics", "TEXT NOT NULL DEFAULT ''"),
            ("created_at", "TEXT"),
            ("discovered_at", "TEXT NOT NULL DEFAULT ''"),
            ("is_priority", "INTEGER NOT NULL DEFAULT 0"),
            ("metadata_complete", "INTEGER NOT NULL DEFAULT 0"),
            ("private", "INTEGER NOT NULL DEFAULT 0"),
            ("archived", "INTEGER NOT NULL DEFAULT 0"),
            ("pushed_at", "TEXT"),
            ("default_branch", "TEXT"),
            ("latest_release", "TEXT"),
            ("source", "TEXT NOT NULL DEFAULT 'legacy'"),
            ("topics_json", "TEXT"),
            ("assessment_json", "TEXT"),
            ("decision", "TEXT NOT NULL DEFAULT 'accepted'"),
            ("review_state", "TEXT NOT NULL DEFAULT 'new'"),
            ("watched", "INTEGER NOT NULL DEFAULT 0"),
            ("last_observed_at", "TEXT NOT NULL DEFAULT ''"),
            ("last_watch_success", "INTEGER NOT NULL DEFAULT 0"),
            ("accepted_announced", "INTEGER NOT NULL DEFAULT 0"),
            ("metadata_revision", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            if !columns.contains(name) {
                tx.execute_batch(&format!(
                    "ALTER TABLE repos ADD COLUMN {name} {definition};"
                ))?;
            }
        }
        tx.execute_batch("DROP TRIGGER IF EXISTS repos_ai;
            DROP TRIGGER IF EXISTS repos_ad;
            DROP TRIGGER IF EXISTS repos_au;
            UPDATE repos SET last_observed_at=discovered_at WHERE last_observed_at='';
            UPDATE repos SET accepted_announced=1 WHERE decision='accepted';
            CREATE INDEX IF NOT EXISTS idx_repos_discovered_at ON repos(discovered_at);
            CREATE INDEX IF NOT EXISTS idx_repos_language ON repos(language);
            CREATE INDEX IF NOT EXISTS idx_repos_priority ON repos(is_priority);
            CREATE INDEX IF NOT EXISTS idx_repos_enrichment ON repos(metadata_complete,last_observed_at,id);
            CREATE INDEX IF NOT EXISTS idx_repos_watch ON repos(watched,last_watch_success,id);
            CREATE TABLE IF NOT EXISTS observations(
                id INTEGER PRIMARY KEY,repo_id INTEGER NOT NULL REFERENCES repos(id),
                observed_at TEXT NOT NULL,source TEXT NOT NULL,payload TEXT NOT NULL,assessment TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_observations_repo ON observations(repo_id,id);
            CREATE TABLE IF NOT EXISTS changes(
                id INTEGER PRIMARY KEY,repo_id INTEGER NOT NULL REFERENCES repos(id),
                observed_at TEXT NOT NULL,field TEXT NOT NULL,before_value TEXT NOT NULL,after_value TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_changes_repo ON changes(repo_id,id);
            CREATE TABLE IF NOT EXISTS assessment_history(
                id INTEGER PRIMARY KEY,repo_id INTEGER NOT NULL REFERENCES repos(id),
                evaluated_at TEXT NOT NULL,assessment TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS app_state(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS source_status(name TEXT PRIMARY KEY,status TEXT NOT NULL,
                message TEXT NOT NULL,last_success_at INTEGER NOT NULL,next_allowed_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS analysis_reports(id INTEGER PRIMARY KEY,generated_at TEXT NOT NULL,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,event_key TEXT NOT NULL UNIQUE,
                repo_id INTEGER NOT NULL REFERENCES repos(id),channel TEXT NOT NULL,payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','delivered','failed','cancelled')),
                attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL DEFAULT 0,
                lease_until INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,delivered_at INTEGER,last_error TEXT);
            CREATE INDEX IF NOT EXISTS idx_outbox_due ON outbox(status,next_attempt_at,lease_until,id);
            CREATE INDEX IF NOT EXISTS idx_outbox_repo ON outbox(repo_id,status);")?;
        let mut last_id: Option<i64> = None;
        loop {
            let batch = {
                let mut stmt = tx.prepare("SELECT id,full_name FROM repos WHERE ?1 IS NULL OR id>?1 ORDER BY id LIMIT 200")?;
                let rows = stmt
                    .query_map([last_id], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>>>()?;
                rows
            };
            if batch.is_empty() {
                break;
            }
            for (id, full_name) in batch {
                if id <= 0 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                validate_name(&full_name)?;
                if scrub(&full_name) != full_name {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                tx.execute(
                    "UPDATE repos SET html_url=?1 WHERE id=?2",
                    params![format!("https://github.com/{full_name}"), id],
                )?;
                last_id = Some(id);
            }
        }
        tx.pragma_update(None, "user_version", 1)?;
    }
    if version < 2 {
        // Replace only derived-index triggers, never repository or observation data.
        tx.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS repos_fts USING fts5(
                name,full_name,description,topics,content='repos',content_rowid='id');
            DROP TRIGGER IF EXISTS repos_ai;
            DROP TRIGGER IF EXISTS repos_ad;
            DROP TRIGGER IF EXISTS repos_au;
            CREATE TRIGGER repos_ai AFTER INSERT ON repos BEGIN
                INSERT INTO repos_fts(rowid,name,full_name,description,topics)
                VALUES(new.id,new.name,new.full_name,new.description,new.topics); END;
            CREATE TRIGGER repos_ad AFTER DELETE ON repos BEGIN
                INSERT INTO repos_fts(repos_fts,rowid,name,full_name,description,topics)
                VALUES('delete',old.id,old.name,old.full_name,old.description,old.topics); END;
            CREATE TRIGGER repos_au AFTER UPDATE OF name,full_name,description,topics ON repos BEGIN
                INSERT INTO repos_fts(repos_fts,rowid,name,full_name,description,topics)
                VALUES('delete',old.id,old.name,old.full_name,old.description,old.topics);
                INSERT INTO repos_fts(rowid,name,full_name,description,topics)
                VALUES(new.id,new.name,new.full_name,new.description,new.topics); END;
            INSERT INTO repos_fts(repos_fts) VALUES('rebuild');",
        )?;
        tx.pragma_update(None, "user_version", 2)?;
    }
    tx.commit()
}

fn upsert_repo(
    conn: &Connection,
    r: &RepoItem,
    a: &Assessment,
    observed: &str,
    revision: i64,
) -> Result<()> {
    conn.execute("INSERT INTO repos(id,name,full_name,owner,owner_type,html_url,description,fork,
        stars,forks_count,language,license,topics,created_at,discovered_at,is_priority,metadata_complete,
        private,archived,pushed_at,default_branch,latest_release,source,topics_json,assessment_json,
        decision,last_observed_at,metadata_revision)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,
               0,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27)
        ON CONFLICT(id) DO UPDATE SET name=excluded.name,full_name=excluded.full_name,
        owner=excluded.owner,owner_type=excluded.owner_type,html_url=excluded.html_url,
        description=excluded.description,fork=excluded.fork,stars=excluded.stars,
        forks_count=excluded.forks_count,language=excluded.language,license=excluded.license,
        topics=excluded.topics,created_at=excluded.created_at,is_priority=excluded.is_priority,
        metadata_complete=excluded.metadata_complete,private=0,archived=excluded.archived,
        pushed_at=excluded.pushed_at,default_branch=excluded.default_branch,
        latest_release=excluded.latest_release,source=excluded.source,topics_json=excluded.topics_json,
        assessment_json=excluded.assessment_json,decision=excluded.decision,
        last_observed_at=excluded.last_observed_at,metadata_revision=excluded.metadata_revision",
        params![r.id,r.name,r.full_name,r.owner,r.owner_type,r.html_url,r.description,r.fork,
        r.stars,r.forks_count,r.language,r.license,r.topics.join(", "),r.created_at,r.discovered_at,
        r.is_priority,r.metadata_complete,r.archived,r.pushed_at,r.default_branch,r.latest_release,
        r.source,encode_json(&r.topics, MAX_JSON)?,encode_json(a, MAX_JSON)?,a.decision,observed,revision])?;
    Ok(())
}

fn row_to_repo(row: &rusqlite::Row<'_>) -> Result<RepoItem> {
    let topics_json: Option<String> = row.get("topics_json")?;
    let topics = if let Some(json) = topics_json {
        decode_json(&json, MAX_JSON)?
    } else {
        row.get::<_, String>("topics")?
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let mut repo = RepoItem {
        id: row.get("id")?,
        name: row.get("name")?,
        full_name: row.get("full_name")?,
        owner: row.get("owner")?,
        owner_type: row.get("owner_type")?,
        html_url: row.get("html_url")?,
        description: row.get("description")?,
        fork: row.get("fork")?,
        stars: row.get("stars")?,
        forks_count: row.get("forks_count")?,
        language: row.get("language")?,
        license: row.get("license")?,
        topics,
        created_at: row.get("created_at")?,
        discovered_at: row.get("discovered_at")?,
        is_priority: row.get("is_priority")?,
        metadata_complete: row.get("metadata_complete")?,
        private: row.get("private")?,
        archived: row.get("archived")?,
        pushed_at: row.get("pushed_at")?,
        default_branch: row.get("default_branch")?,
        latest_release: row.get("latest_release")?,
        source: row.get("source")?,
    };
    validate_name(&repo.full_name)?;
    // Legacy URL values are never trusted for navigation or notification delivery.
    repo.html_url = format!("https://github.com/{}", repo.full_name);
    safe_repo(&repo)
}

fn row_to_record(row: &rusqlite::Row<'_>) -> Result<RepositoryRecord> {
    let assessment: Option<String> = row.get("assessment_json")?;
    Ok(RepositoryRecord {
        repo: row_to_repo(row)?,
        assessment: if let Some(json) = assessment {
            decode_json(&json, MAX_JSON)?
        } else {
            Assessment {
                decision: row.get("decision")?,
                reasons: vec!["Migrated legacy repository; re-evaluation is available.".into()],
                ..Default::default()
            }
        },
        review_state: row.get("review_state")?,
        watched: row.get("watched")?,
        last_observed_at: row.get("last_observed_at")?,
    })
}

fn merge_repo(old: Option<&RepoItem>, incoming: &RepoItem) -> RepoItem {
    let mut merged = incoming.clone();
    if let Some(old) = old {
        merged.discovered_at = old.discovered_at.clone();
        if !incoming.metadata_complete {
            merged.metadata_complete = old.metadata_complete;
            merged.description = incoming
                .description
                .clone()
                .or_else(|| old.description.clone());
            merged.owner_type = incoming
                .owner_type
                .clone()
                .or_else(|| old.owner_type.clone());
            merged.language = incoming.language.clone().or_else(|| old.language.clone());
            merged.license = incoming.license.clone().or_else(|| old.license.clone());
            merged.created_at = incoming
                .created_at
                .clone()
                .or_else(|| old.created_at.clone());
            merged.pushed_at = incoming.pushed_at.clone().or_else(|| old.pushed_at.clone());
            merged.default_branch = incoming
                .default_branch
                .clone()
                .or_else(|| old.default_branch.clone());
            merged.latest_release = incoming
                .latest_release
                .clone()
                .or_else(|| old.latest_release.clone());
            merged.stars = old.stars.max(incoming.stars);
            merged.forks_count = old.forks_count.max(incoming.forks_count);
            merged.fork = old.fork || incoming.fork;
            merged.archived = old.archived || incoming.archived;
            if incoming.topics.is_empty() {
                merged.topics = old.topics.clone();
            }
        }
    }
    merged
}

fn metadata_changes(old: &RepoItem, new: &RepoItem) -> Result<Vec<(String, String, String)>> {
    let old = serde_json::to_value(old).map_err(json_error)?;
    let new = serde_json::to_value(new).map_err(json_error)?;
    let mut changes = Vec::new();
    for field in [
        "name",
        "full_name",
        "owner",
        "owner_type",
        "description",
        "fork",
        "stars",
        "forks_count",
        "language",
        "license",
        "topics",
        "created_at",
        "archived",
        "pushed_at",
        "default_branch",
        "latest_release",
    ] {
        if old[field] != new[field] {
            changes.push((
                field.to_owned(),
                change_value(&old[field])?,
                change_value(&new[field])?,
            ));
        }
    }
    Ok(changes)
}

fn change_value(value: &Value) -> Result<String> {
    if let Value::String(s) = value {
        Ok(scrub(s))
    } else {
        encode_json(value, MAX_JSON)
    }
}

fn enqueue(conn: &Connection, repo: &RepoItem, channels: &[String], event: &str) -> Result<()> {
    let payload = encode_json(repo, MAX_JSON)?;
    for channel in channels {
        conn.execute(
            "INSERT INTO outbox(event_key,repo_id,channel,payload,created_at)
            VALUES(?1,?2,?3,?4,?5) ON CONFLICT(event_key) DO NOTHING",
            params![
                format!("repo:{}:{event}:{channel}", repo.id),
                repo.id,
                channel,
                payload,
                chrono::Utc::now().timestamp()
            ],
        )?;
    }
    Ok(())
}

fn valid_review(s: &str) -> bool {
    matches!(
        s,
        "new" | "important" | "needs_review" | "ignored" | "resolved"
    )
}
fn valid_channel(s: &str) -> bool {
    matches!(
        s,
        "log" | "jsonl" | "toast" | "discord" | "telegram" | "webhook"
    )
}
fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn validate_name(full_name: &str) -> Result<()> {
    let (owner, name) = full_name
        .split_once('/')
        .ok_or(rusqlite::Error::InvalidQuery)?;
    if owner.is_empty()
        || owner.len() > 39
        || name.is_empty()
        || name.len() > 100
        || matches!(name, "." | "..")
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn safe_repo(repo: &RepoItem) -> Result<RepoItem> {
    if repo.private
        || repo.id <= 0
        || repo.stars < 0
        || repo.forks_count < 0
        || repo.topics.len() > 100
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    validate_name(&repo.full_name)?;
    let (owner, name) = repo
        .full_name
        .split_once('/')
        .ok_or(rusqlite::Error::InvalidQuery)?;
    if owner != repo.owner || name != repo.name {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if scrub(&repo.full_name) != repo.full_name {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut value = serde_json::to_value(repo).map_err(json_error)?;
    value["html_url"] = Value::String(format!("https://github.com/{}", repo.full_name));
    let url = value["html_url"].clone();
    value["html_url"] = Value::Null;
    // Source is a provenance label, not a URL, credential, or configuration snapshot.
    if repo.source.len() > 64
        || scrub(&repo.source) != repo.source
        || !repo
            .source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    scrub_json(&mut value, 0)?;
    value["html_url"] = url;
    decode_json(&encode_json(&value, MAX_JSON)?, MAX_JSON)
}

fn safe_assessment(assessment: &Assessment) -> Result<Assessment> {
    if !matches!(
        assessment.decision.as_str(),
        "accepted" | "rejected" | "deferred"
    ) || assessment.relevance > 100
        || assessment.confidence > 100
        || assessment.security_importance > 100
        || assessment.reasons.len() > 100
        || assessment.missing.len() > 100
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut value = serde_json::to_value(assessment).map_err(json_error)?;
    scrub_json(&mut value, 0)?;
    decode_json(&encode_json(&value, MAX_JSON)?, MAX_JSON)
}

fn state_json(state: &AppState) -> Result<String> {
    let mut value = serde_json::to_value(state).map_err(json_error)?;
    let next = value.get("sequential_next_url").cloned();
    if let Some(Value::String(url)) = &next {
        let parsed = reqwest::Url::parse(url).map_err(|_| rusqlite::Error::InvalidQuery)?;
        if url.len() > 4096
            || url
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
            || !url.starts_with("https://api.github.com/repositories?")
            || parsed.host_str() != Some("api.github.com")
            || parsed.path() != "/repositories"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.port_or_known_default() != Some(443)
            || parsed.query_pairs().any(|(k, v)| {
                !matches!(k.as_ref(), "since" | "per_page")
                    || v.is_empty()
                    || !v.bytes().all(|b| b.is_ascii_digit())
            })
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        value["sequential_next_url"] = Value::Null;
    }
    scrub_json(&mut value, 0)?;
    if let Some(next) = next {
        value["sequential_next_url"] = next;
    }
    encode_json(&value, MAX_JSON)
}

fn scrub_json(value: &mut Value, depth: usize) -> Result<()> {
    if depth > 16 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    match value {
        Value::String(s) => {
            if s.len() > 16 * 1024 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            *s = scrub(s);
        }
        Value::Array(a) => {
            if a.len() > 5000 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            for v in a {
                scrub_json(v, depth + 1)?;
            }
        }
        Value::Object(o) => {
            if o.len() > 100 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            for v in o.values_mut() {
                scrub_json(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn scrub(text: &str) -> String {
    static SECRETS: OnceLock<regex::Regex> = OnceLock::new();
    let regex = SECRETS.get_or_init(|| regex::Regex::new(concat!(
        r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
        r"|(?:gh[pousr]_[A-Za-z0-9]{8,255}|github_pat_[A-Za-z0-9_]{8,255}|(?:AKIA|ASIA)[A-Z0-9]{16})",
        r#"|https?://[^\s<>"']+"#,
        r"|\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=-]+",
        r"|\b(?:password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+",
        r"|\b[0-9]{5,20}:[A-Za-z0-9_-]{20,255}"
    )).expect("static database redaction expression"));
    regex
        .replace_all(text, "[REDACTED]")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn delivery_diagnostic(error: &str) -> &'static str {
    match error {
        "notification network request failed" => "Notification network request failed.",
        "notification service rejected delivery" => "Notification service rejected delivery.",
        "notification channel is unavailable" => "Notification channel is unavailable.",
        "Windows toast command failed" => "Windows toast command failed.",
        "Windows toast command timed out" => "Windows toast command timed out.",
        _ => "Notification delivery failed; untrusted details omitted.",
    }
}

pub fn sanitize_fts5_query(raw: &str) -> String {
    raw.split_whitespace()
        .take(64)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let token = s.replace('"', "\"\"");
            let suffix =
                if s.chars().count() >= 3 && s.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    "*"
                } else {
                    ""
                };
            format!("\"{token}\"{suffix}")
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

fn like_pattern(raw: &str) -> String {
    format!(
        "%{}%",
        raw.replace('!', "!!").replace('%', "!%").replace('_', "!_")
    )
}

fn encode_json<T: Serialize>(value: &T, max: usize) -> Result<String> {
    let encoded = serde_json::to_string(value).map_err(json_error)?;
    if encoded.len() > max {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(encoded)
}

fn decode_json<T: serde::de::DeserializeOwned>(text: &str, max: usize) -> Result<T> {
    if text.len() > max {
        return Err(rusqlite::Error::InvalidQuery);
    }
    serde_json::from_str(text).map_err(json_error)
}

fn json_error(_: serde_json::Error) -> rusqlite::Error {
    // JSON parser messages can quote credential-bearing input.
    rusqlite::Error::InvalidQuery
}

fn io_error(error: std::io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        error.kind(),
        "Database filesystem operation failed.",
    )))
}

fn is_link(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}

fn check_path(path: &Path, allow_missing_leaf: bool) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(io_error)?.join(path)
    };
    let mut current = PathBuf::new();
    let mut components = absolute.components().peekable();
    while let Some(component) = components.next() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        #[cfg(windows)]
        {
            use std::path::{Component, Prefix};
            if matches!(component, Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            if let Component::Normal(name) = component {
                let name = name.to_string_lossy();
                if name.contains(':') || name.ends_with(['.', ' ']) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
        }
        current.push(component.as_os_str());
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(meta) if is_link(&meta) => return Err(rusqlite::Error::InvalidQuery),
            Ok(meta) if components.peek().is_some() && !meta.is_dir() => {
                return Err(rusqlite::Error::InvalidQuery)
            }
            Ok(_) => {}
            Err(e)
                if allow_missing_leaf
                    && components.peek().is_none()
                    && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    Ok(absolute)
}

fn backup_connection(source: &Connection, path: &Path) -> Result<()> {
    let path = check_path(path, true)?;
    #[cfg(windows)]
    let _parents = {
        use std::os::windows::fs::OpenOptionsExt;
        let mut parents = Vec::new();
        // Pin ancestors root-first, without following reparse points. Denying DELETE
        // prevents another process from replacing a checked parent with a junction.
        let ancestors: Vec<_> = path
            .parent()
            .ok_or(rusqlite::Error::InvalidQuery)?
            .ancestors()
            .collect();
        for parent in ancestors.into_iter().rev() {
            let handle = OpenOptions::new()
                .read(true)
                .access_mode(0x80)
                .share_mode(0x1 | 0x2)
                .custom_flags(0x02000000 | 0x00200000)
                .open(parent)
                .map_err(io_error)?;
            let meta = handle.metadata().map_err(io_error)?;
            if !meta.is_dir() || is_link(&meta) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            parents.push(handle);
        }
        parents
    };
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Keep the reservation alive and deny deletion/rename while SQLite opens it.
        options.share_mode(0x1 | 0x2);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let reservation = options.open(&path).map_err(io_error)?;
    let mut destination = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    destination.busy_timeout(Duration::from_secs(2))?;
    destination.pragma_update(None, "synchronous", "FULL")?;
    {
        let backup = Backup::new(source, &mut destination)?;
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if Instant::now() >= deadline {
                return Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                    Some("Database backup exceeded its time budget.".into()),
                ));
            }
            match backup.step(256)? {
                StepResult::Done => break,
                StepResult::Busy | StepResult::Locked => {
                    std::thread::sleep(Duration::from_millis(25))
                }
                StepResult::More => {}
                _ => return Err(rusqlite::Error::InvalidQuery),
            }
        }
    }
    // A backup inherits the source WAL header; checkpoint and turn it into a standalone file.
    let (busy, _, _): (i64, i64, i64) =
        destination.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    if busy != 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mode: String = destination.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(rusqlite::Error::InvalidQuery);
    }
    destination.close().map_err(|(_, e)| e)?;
    reservation.sync_all().map_err(io_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let parent = std::env::temp_dir().join("bloomrepo-tests");
            fs::create_dir_all(&parent).unwrap();
            let path = parent.join(format!(
                "bloomrepo-db-{}-{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove isolated database fixtures");
        }
    }

    fn memory() -> Database {
        Database::new(":memory:", false).unwrap()
    }

    fn repo(id: i64) -> RepoItem {
        RepoItem {
            id,
            name: format!("repo{id}"),
            full_name: format!("owner/repo{id}"),
            owner: "owner".into(),
            owner_type: Some("User".into()),
            html_url: "https://user:secret@evil.invalid/?token=secret".into(),
            description: Some("A useful security parser".into()),
            fork: false,
            stars: 10,
            forks_count: 2,
            language: Some("Rust".into()),
            license: Some("MIT".into()),
            topics: vec!["security".into()],
            created_at: Some("2026-09-01T00:00:00Z".into()),
            discovered_at: timestamp(),
            is_priority: false,
            metadata_complete: true,
            private: false,
            archived: false,
            pushed_at: Some("2026-09-02T00:00:00Z".into()),
            default_branch: Some("main".into()),
            latest_release: Some("v1.0.0".into()),
            source: "github".into(),
        }
    }

    fn assessment(decision: &str) -> Assessment {
        Assessment {
            relevance: 75,
            confidence: 90,
            security_importance: 80,
            decision: decision.into(),
            reasons: vec!["Matches local rules".into()],
            missing: Vec::new(),
            evaluated_at: timestamp(),
        }
    }

    fn ingest(db: &Database, items: &[RepoItem], decision: &str) -> Vec<RepoItem> {
        db.ingest(
            items,
            &vec![assessment(decision); items.len()],
            &AppState::default(),
            &["log".into(), "webhook".into()],
        )
        .unwrap()
    }

    fn count(db: &Database, table: &str) -> usize {
        db.lock()
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn ingest_is_atomic_with_state_observations_and_outbox() {
        let db = memory();
        let state = AppState {
            sequential_since: 123,
            ..Default::default()
        };
        assert_eq!(
            db.ingest(
                &[repo(1)],
                &[assessment("accepted")],
                &state,
                &["log".into()]
            )
            .unwrap()
            .len(),
            1
        );
        assert_eq!(db.load_state().unwrap().unwrap().sequential_since, 123);
        assert_eq!(count(&db, "observations"), 1);
        assert_eq!(count(&db, "outbox"), 1);
        db.lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER force_failure BEFORE INSERT ON outbox
            BEGIN SELECT RAISE(ABORT,'forced transaction failure'); END;",
            )
            .unwrap();
        let later = AppState {
            sequential_since: 456,
            ..Default::default()
        };
        assert!(db
            .ingest(
                &[repo(2)],
                &[assessment("accepted")],
                &later,
                &["log".into()]
            )
            .is_err());
        assert!(db.get_repository(2).unwrap().is_none());
        assert_eq!(db.load_state().unwrap().unwrap().sequential_since, 123);
        assert_eq!(count(&db, "observations"), 1);
        assert_eq!(count(&db, "outbox"), 1);
        assert!(db.search("repo2", 10).unwrap().is_empty());
    }

    #[test]
    fn state_failure_rolls_back_existing_changes_and_watch_clock() {
        let db = memory();
        ingest(&db, &[repo(1)], "accepted");
        db.set_watched(1, true).unwrap();
        let before_state = serde_json::to_string(&db.load_state().unwrap()).unwrap();
        db.lock()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_state BEFORE UPDATE ON app_state
            BEGIN SELECT RAISE(ABORT,'forced cursor failure'); END;",
            )
            .unwrap();
        let mut changed = repo(1);
        changed.stars = 4;
        changed.source = "watch".into();
        assert!(db
            .ingest(
                &[changed],
                &[assessment("accepted")],
                &AppState {
                    sequential_since: 555,
                    ..Default::default()
                },
                &["log".into()]
            )
            .is_err());
        assert_eq!(db.get_repository(1).unwrap().unwrap().stars, 10);
        assert_eq!(count(&db, "observations"), 1);
        assert_eq!(count(&db, "outbox"), 2);
        assert_eq!(db.list_changes(1, 100).unwrap().len(), 1);
        assert_eq!(
            db.due_watched(chrono::Utc::now().timestamp(), 3600, 10)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            serde_json::to_string(&db.load_state().unwrap()).unwrap(),
            before_state
        );
        // Legacy inserts cannot overwrite or manufacture the engine's durable cursor.
        db.insert_batch(&[repo(2)]).unwrap();
        assert_eq!(
            serde_json::to_string(&db.load_state().unwrap()).unwrap(),
            before_state
        );
    }

    #[test]
    fn invalid_private_and_mismatched_batches_roll_back_everything() {
        let db = memory();
        let mut private = repo(2);
        private.private = true;
        assert!(db
            .ingest(
                &[repo(1), private],
                &vec![assessment("accepted"); 2],
                &AppState::default(),
                &["log".into()]
            )
            .is_err());
        assert_eq!(count(&db, "repos"), 0);
        assert_eq!(count(&db, "observations"), 0);
        assert_eq!(count(&db, "outbox"), 0);
        assert!(db.load_state().unwrap().is_none());
        assert!(db
            .ingest(&[repo(1)], &[], &AppState::default(), &[])
            .is_err());
        let mut invalid = repo(1);
        invalid.full_name = "owner/../escape".into();
        assert!(db.insert_batch(&[invalid]).is_err());
        assert!(db
            .ingest(
                &[repo(1)],
                &[assessment("accepted")],
                &AppState::default(),
                &["https://secret.invalid/hook".into()]
            )
            .is_err());
    }

    #[test]
    fn complete_decreases_nulls_and_priority_reset_but_sparse_metadata_survives() {
        let db = memory();
        let mut original = repo(1);
        original.is_priority = true;
        ingest(&db, &[original.clone()], "accepted");
        let mut sparse = original.clone();
        sparse.metadata_complete = false;
        sparse.description = None;
        sparse.language = None;
        sparse.license = None;
        sparse.latest_release = None;
        sparse.topics.clear();
        sparse.stars = 0;
        sparse.forks_count = 0;
        sparse.is_priority = false;
        sparse.source = "events".into();
        ingest(&db, &[sparse], "deferred");
        let merged = db.get_repository(1).unwrap().unwrap();
        assert!(merged.metadata_complete);
        assert_eq!(merged.description, original.description);
        assert_eq!(merged.language, original.language);
        assert_eq!(merged.latest_release, original.latest_release);
        assert_eq!(merged.topics, original.topics);
        assert_eq!(merged.stars, 10);
        assert_eq!(merged.forks_count, 2);
        assert!(!merged.is_priority);
        assert!(db.list_changes(1, 100).unwrap().is_empty());
        let mut complete = original;
        complete.stars = 3;
        complete.forks_count = 1;
        complete.description = None;
        complete.latest_release = None;
        complete.topics.clear();
        complete.is_priority = false;
        ingest(&db, &[complete], "accepted");
        let merged = db.get_repository(1).unwrap().unwrap();
        assert_eq!(merged.stars, 3);
        assert_eq!(merged.forks_count, 1);
        assert!(merged.description.is_none());
        assert!(merged.latest_release.is_none());
        assert!(merged.topics.is_empty());
        assert!(!merged.is_priority);
        assert!(db
            .list_changes(1, 100)
            .unwrap()
            .iter()
            .any(|r| r.field == "stars" && r.before == "10" && r.after == "3"));
    }

    #[test]
    fn transitions_notify_once_and_watch_changes_have_stable_unique_events() {
        let db = memory();
        let mut item = repo(1);
        assert!(ingest(&db, &[item.clone()], "rejected").is_empty());
        assert_eq!(count(&db, "repos"), 1);
        assert_eq!(count(&db, "outbox"), 0);
        assert_eq!(ingest(&db, &[item.clone()], "accepted").len(), 1);
        assert!(ingest(&db, &[item.clone()], "accepted").is_empty());
        assert_eq!(count(&db, "outbox"), 2);
        db.set_watched(1, true).unwrap();
        item.stars = 8;
        assert!(ingest(&db, &[item.clone()], "accepted").is_empty());
        assert_eq!(count(&db, "outbox"), 4);
        item.source = "watch".into();
        item.discovered_at = "2026-10-01T00:00:00Z".into();
        ingest(&db, &[item.clone()], "accepted");
        assert_eq!(count(&db, "outbox"), 4);
        assert!(db
            .due_watched(chrono::Utc::now().timestamp(), 3600, 10)
            .unwrap()
            .is_empty());
        assert!(ingest(&db, &[item.clone()], "deferred").is_empty());
        assert!(ingest(&db, &[item], "accepted").is_empty());
        assert_eq!(count(&db, "outbox"), 4);
    }

    #[test]
    fn ignored_repositories_do_not_notify_and_review_changes_are_audited() {
        let db = memory();
        ingest(&db, &[repo(1)], "rejected");
        db.set_review_state(1, "ignored").unwrap();
        assert!(ingest(&db, &[repo(1)], "accepted").is_empty());
        assert_eq!(count(&db, "outbox"), 0);
        db.set_review_state(1, "important").unwrap();
        db.set_review_state(1, "important").unwrap();
        assert!(db.set_review_state(1, "DROP TABLE repos").is_err());
        assert!(db.set_review_state(99, "new").is_err());
        let history = db.list_changes(1, 100).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].field, "review_state");
        assert_eq!(history[0].before, "ignored");
        assert_eq!(history[0].after, "important");
        assert_eq!(ingest(&db, &[repo(1)], "accepted").len(), 1);
        db.set_review_state(1, "ignored").unwrap();
        assert!(db.claim_outbox(10).unwrap().is_empty());
    }

    #[test]
    fn all_filters_apply_before_limit_and_search_uses_literals() {
        let db = memory();
        let mut first = repo(1);
        first.is_priority = true;
        ingest(&db, &[first, repo(2), repo(3)], "accepted");
        ingest(&db, &[repo(4)], "rejected");
        let mut fork = repo(5);
        fork.fork = true;
        fork.is_priority = true;
        ingest(&db, &[fork], "accepted");
        db.set_watched(1, true).unwrap();
        db.set_review_state(1, "important").unwrap();
        let query = RepositoryQuery {
            text: "parser".into(),
            priority_only: true,
            hide_forks: true,
            watch_only: true,
            review_state: Some("important".into()),
            limit: 1,
            ..Default::default()
        };
        let rows = db.list_repositories(&query).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].repo.id, 1);
        assert!(db
            .list_repositories(&RepositoryQuery { offset: 1, ..query })
            .unwrap()
            .is_empty());
        assert_eq!(
            db.list_repositories(&RepositoryQuery {
                limit: 100,
                ..Default::default()
            })
            .unwrap()
            .len(),
            4
        );
        assert_eq!(
            db.list_repositories(&RepositoryQuery {
                include_rejected: true,
                limit: 100,
                ..Default::default()
            })
            .unwrap()
            .len(),
            5
        );
        for query in [
            "AND OR NOT",
            "foo:bar",
            "\"broken quote",
            "*",
            "'%_",
            "NEAR(a b)",
            "\"",
            "a\" OR parser",
        ] {
            assert!(
                db.search(query, 10).unwrap().is_empty(),
                "unexpected literal match: {query}"
            );
        }
        let mut cpp = repo(6);
        cpp.description = Some("A C++ parser".into());
        ingest(&db, &[cpp], "accepted");
        assert_eq!(db.search("c++", 10).unwrap()[0].id, 6);
        assert_eq!(db.search("par", 10).unwrap().len(), 5);
        let mut punct = repo(7);
        punct.description = Some("literal %_ marker".into());
        ingest(&db, &[punct], "accepted");
        assert_eq!(db.search("%_", 10).unwrap()[0].id, 7);
    }

    #[test]
    fn legacy_populated_migration_backs_up_preserves_data_and_backfills_fts() {
        let fixture = Fixture::new();
        let path = fixture.path("legacy.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE repos(id INTEGER PRIMARY KEY,name TEXT NOT NULL,
                full_name TEXT NOT NULL,owner TEXT NOT NULL,owner_type TEXT,html_url TEXT NOT NULL,
                description TEXT,fork INTEGER NOT NULL,stars INTEGER NOT NULL DEFAULT 0,
                forks_count INTEGER NOT NULL DEFAULT 0,language TEXT,license TEXT,topics TEXT NOT NULL DEFAULT '',
                created_at TEXT,discovered_at TEXT NOT NULL,is_priority INTEGER NOT NULL DEFAULT 0);
                INSERT INTO repos(id,name,full_name,owner,html_url,description,fork,stars,topics,discovered_at)
                VALUES(42,'legacy','owner/legacy','owner','https://old.invalid/','migrationneedle',0,17,'rust, security','2026-09-01');
                CREATE VIRTUAL TABLE repos_fts USING fts5(name,full_name,description,topics,content='repos',content_rowid='id');
                CREATE TRIGGER repos_au AFTER UPDATE ON repos BEGIN
                    INSERT INTO repos_fts(repos_fts,rowid,name,full_name,description,topics)
                    VALUES('delete',old.id,old.name,old.full_name,old.description,old.topics); END;").unwrap();
        }
        let db = Database::new(&path, true).unwrap();
        assert_eq!(db.search("migrationneedle", 10).unwrap()[0].id, 42);
        let item = db.get_repository(42).unwrap().unwrap();
        assert_eq!(item.stars, 17);
        assert_eq!(item.topics, vec!["rust", "security"]);
        assert_eq!(item.html_url, "https://github.com/owner/legacy");
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row("SELECT html_url FROM repos WHERE id=42", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "https://github.com/owner/legacy"
        );
        assert!(ingest(&db, &[item.clone()], "accepted").is_empty());
        let backups: Vec<_> = fs::read_dir(&fixture.0)
            .unwrap()
            .map(|p| p.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "bak"))
            .collect();
        assert_eq!(backups.len(), 1);
        let backup = Connection::open(&backups[0]).unwrap();
        assert_eq!(
            backup
                .query_row("SELECT stars FROM repos WHERE id=42", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            17
        );
        assert_eq!(
            backup
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        let mut changed = item;
        changed.description = Some("updatedneedle".into());
        ingest(&db, &[changed], "accepted");
        assert!(db.search("migrationneedle", 10).unwrap().is_empty());
        assert_eq!(db.search("updatedneedle", 10).unwrap().len(), 1);
        db.lock()
            .unwrap()
            .execute("DELETE FROM repos WHERE id=42", [])
            .unwrap_err();
        drop(db);
        let reopened = Database::new(&path, false).unwrap();
        assert_eq!(reopened.get_max_id().unwrap(), 42);
        assert_eq!(
            fs::read_dir(&fixture.0)
                .unwrap()
                .filter(|p| p
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|e| e == "bak"))
                .count(),
            1
        );
    }

    #[test]
    fn failed_migration_rolls_back_schema_and_preserves_backup() {
        let fixture = Fixture::new();
        let path = fixture.path("broken.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE repos(id INTEGER PRIMARY KEY,full_name TEXT NOT NULL);
                INSERT INTO repos VALUES(123,'owner/repo'); CREATE TABLE repos_fts(incompatible TEXT);",
            )
            .unwrap();
        }
        assert!(Database::new(&path, false).is_err());
        let conn = Connection::open(&path).unwrap();
        assert_eq!(
            conn.query_row("SELECT id FROM repos", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            123
        );
        assert_eq!(
            conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pragma_table_info('repos')", [], |r| r
                .get::<_, usize>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            fs::read_dir(&fixture.0)
                .unwrap()
                .filter(|p| p
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|e| e == "bak"))
                .count(),
            1
        );
    }

    #[test]
    fn leases_retry_backoff_and_delivery_survive_reopen() {
        let fixture = Fixture::new();
        let path = fixture.path("outbox.db");
        let db = Database::new(&path, true).unwrap();
        db.ingest(
            &[repo(1)],
            &[assessment("accepted")],
            &AppState::default(),
            &["webhook".into()],
        )
        .unwrap();
        let message = db.claim_outbox(10).unwrap().remove(0);
        assert_eq!(message.attempts, 1);
        assert!(db.clone().claim_outbox(10).unwrap().is_empty());
        drop(db);
        let db = Database::new(&path, false).unwrap();
        assert!(db.claim_outbox(10).unwrap().is_empty());
        db.lock()
            .unwrap()
            .execute("UPDATE outbox SET lease_until=0 WHERE id=?1", [message.id])
            .unwrap();
        assert_eq!(db.claim_outbox(10).unwrap()[0].attempts, 2);
        db.finish_outbox(
            message.id,
            Some("Bearer top-secret https://user:password@evil.invalid/?token=secret"),
        )
        .unwrap();
        let (error, next): (String, i64) = db
            .lock()
            .unwrap()
            .query_row("SELECT last_error,next_attempt_at FROM outbox", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert!(!error.contains("top-secret"));
        assert!(!error.contains("password"));
        assert!(next > chrono::Utc::now().timestamp());
        assert!(db.claim_outbox(10).unwrap().is_empty());
        db.lock()
            .unwrap()
            .execute("UPDATE outbox SET next_attempt_at=0,attempts=11", [])
            .unwrap();
        assert_eq!(db.claim_outbox(10).unwrap()[0].attempts, 12);
        db.finish_outbox(message.id, Some("secret")).unwrap();
        assert_eq!(db.operational_health().unwrap().failed_notifications, 1);
        drop(db);
        let db = Database::new(&path, true).unwrap();
        assert_eq!(db.retry_failed_notifications().unwrap(), 1);
        let retry = db.claim_outbox(1).unwrap().remove(0);
        assert_eq!(retry.attempts, 1);
        assert_eq!(retry.event_key, message.event_key);
        db.finish_outbox(retry.id, None).unwrap();
        assert!(db.finish_outbox(retry.id, None).is_err());
        assert_eq!(db.operational_health().unwrap().pending_notifications, 0);
        drop(db);
        let db = Database::new(&path, true).unwrap();
        assert!(db.claim_outbox(100).unwrap().is_empty());
        assert_eq!(count(&db, "outbox"), 1);
    }

    #[test]
    fn expired_last_lease_fails_instead_of_retrying_forever() {
        let db = memory();
        ingest(&db, &[repo(1)], "accepted");
        db.claim_outbox(10).unwrap();
        db.lock()
            .unwrap()
            .execute("UPDATE outbox SET attempts=12,lease_until=0", [])
            .unwrap();
        assert!(db.claim_outbox(10).unwrap().is_empty());
        assert_eq!(db.operational_health().unwrap().failed_notifications, 2);
        assert_eq!(db.retry_failed_notifications().unwrap(), 2);
    }

    #[test]
    fn backup_is_standalone_no_overwrite_and_includes_uncheckpointed_wal() {
        let fixture = Fixture::new();
        let source = fixture.path("source.db");
        let backup = fixture.path("backup.db");
        let db = Database::new(&source, true).unwrap();
        db.lock()
            .unwrap()
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        let state = AppState {
            sequential_since: 999,
            ..Default::default()
        };
        db.ingest(
            &[repo(9)],
            &[assessment("accepted")],
            &state,
            &["log".into()],
        )
        .unwrap();
        let synchronous: i64 = db
            .lock()
            .unwrap()
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
        assert_eq!(synchronous, 2);
        assert!(fs::metadata(fixture.path("source.db-wal")).unwrap().len() > 0);
        db.backup_to(&backup).unwrap();
        assert!(db.backup_to(&backup).is_err());
        assert!(!fixture.path("backup.db-wal").exists());
        let reopened = Database::new(&backup, false).unwrap();
        assert_eq!(reopened.get_repository(9).unwrap().unwrap().stars, 10);
        assert_eq!(
            reopened.load_state().unwrap().unwrap().sequential_since,
            999
        );
        assert_eq!(
            reopened.operational_health().unwrap().pending_notifications,
            1
        );
        assert_eq!(reopened.search("parser", 10).unwrap().len(), 1);
        assert!(db.backup_to(&fixture.path("missing/backup.db")).is_err());
        assert!(db.backup_to(&fixture.path("../escape.db")).is_err());
    }

    #[test]
    fn observations_and_reports_do_not_persist_recognizable_credentials() {
        let db = memory();
        let secret = format!("ghp_{}", "A".repeat(36));
        let mut item = repo(1);
        item.description = Some(format!(
            "password=supersecret {secret} https://api.telegram.org/bot123:secret/sendMessage"
        ));
        let mut a = assessment("accepted");
        a.reasons.push(format!("Bearer supersecret {secret}"));
        db.ingest(&[item], &[a], &AppState::default(), &["webhook".into()])
            .unwrap();
        let report = AnalysisReport {
            generated_at: timestamp(),
            root: format!(r"C:\local\{secret}"),
            files_scanned: 1,
            skipped: 0,
            limits: vec![format!("secret=supersecret {secret}")],
            findings: vec![crate::analysis::Finding {
                severity: "high".into(),
                rule: "secret.github-token".into(),
                path: "config.rs".into(),
                line: Some(1),
                evidence: "an arbitrary unrecognized credential must not be stored here".into(),
                remediation: format!("Rotate {secret}"),
            }],
            dependencies: Vec::new(),
            coverage_gaps: Vec::new(),
            osv_requested: false,
            osv_queries: 0,
        };
        assert!(db.save_analysis_report(&report).unwrap() > 0);
        let persisted = db.analysis_reports(10).unwrap();
        assert_eq!(persisted.len(), 1);
        let json = serde_json::to_string(&persisted[0]).unwrap();
        assert!(!json.contains(&secret));
        assert!(!json.contains("supersecret"));
        assert!(!json.contains("unrecognized credential"));
        let conn = db.lock().unwrap();
        for sql in [
            "SELECT description FROM repos",
            "SELECT payload FROM observations",
            "SELECT assessment FROM observations",
            "SELECT payload FROM outbox",
            "SELECT payload FROM analysis_reports",
        ] {
            let mut stmt = conn.prepare(sql).unwrap();
            for row in stmt.query_map([], |r| r.get::<_, String>(0)).unwrap() {
                let text = row.unwrap();
                assert!(!text.contains(&secret));
                assert!(!text.contains("supersecret"));
                assert!(!text.contains("bot123"));
                assert!(!text.contains("evil.invalid"));
            }
        }
    }

    #[test]
    fn watch_due_order_enrichment_order_health_and_safe_source_status() {
        let db = memory();
        let mut incomplete = repo(1);
        incomplete.metadata_complete = false;
        ingest(&db, &[incomplete, repo(2)], "accepted");
        db.set_watched(1, true).unwrap();
        db.set_watched(2, true).unwrap();
        db.mark_watch_checked(1, 100).unwrap();
        db.mark_watch_checked(2, 200).unwrap();
        db.mark_watch_checked(1, 99).unwrap();
        assert_eq!(
            db.due_watched(150, 50, 10)
                .unwrap()
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(db.enrichment_candidates(10).unwrap()[0].id, 1);
        db.record_source_status(&SourceStatus {
            name: "search".into(),
            status: "rate_limited".into(),
            message: "https://user:secret@host.invalid/?token=secret".into(),
            last_success_at: 100,
            next_allowed_at: 500,
        })
        .unwrap();
        db.record_source_status(&SourceStatus {
            name: "search".into(),
            status: "ok".into(),
            message: "Bearer top-secret".into(),
            last_success_at: 50,
            next_allowed_at: 0,
        })
        .unwrap();
        let health = db.operational_health().unwrap();
        assert_eq!(health.watched_repositories, 2);
        assert_eq!(health.observations, 2);
        assert_eq!(health.pending_notifications, 4);
        assert_eq!(health.sources[0].last_success_at, 100);
        assert!(!health.sources[0].message.contains("top-secret"));
        assert!(db.mark_watch_checked(99, 100).is_err());
    }

    #[test]
    fn state_preserves_only_approved_cursor_urls() {
        let db = memory();
        let state = AppState {
            sequential_next_url: Some(
                "https://api.github.com/repositories?since=100&per_page=100".into(),
            ),
            ..Default::default()
        };
        db.ingest(&[], &[], &state, &[]).unwrap();
        assert_eq!(
            db.load_state().unwrap().unwrap().sequential_next_url,
            state.sequential_next_url
        );
        for url in [
            "https://user:secret@api.github.com/repositories?since=1",
            "https://evil.invalid/repositories?since=1",
            "https://api.github.com/repositories?token=secret",
            "https://api.github.com/repositories?since=1#secret",
        ] {
            let invalid = AppState {
                sequential_next_url: Some(url.into()),
                ..Default::default()
            };
            assert!(db.ingest(&[], &[], &invalid, &[]).is_err());
        }
    }
}
