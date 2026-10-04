use crate::analysis::{self, AnalysisReport};
use crate::config::AppConfig;
use crate::db::{ChangeRecord, Database, OperationalHealth, RepositoryQuery, RepositoryRecord};
use crate::engine::Engine;
use crate::filter::RepoFilter;
use eframe::egui::{self, Color32, RichText, Stroke};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc as async_mpsc, watch};

const ACCENT: Color32 = Color32::from_rgb(91, 192, 209);
const MUTED: Color32 = Color32::from_rgb(151, 165, 184);
const SURFACE: Color32 = Color32::from_rgb(26, 35, 48);
const BORDER: Color32 = Color32::from_rgb(48, 61, 79);
const ERROR: Color32 = Color32::from_rgb(240, 143, 136);
const PAGE_SIZE: usize = 40;
const WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const IO_SHUTDOWN_WARNING: &str =
    "Stalled filesystem I/O may outlive cancellation or GUI shutdown; it cannot be forcibly cancelled.";
const REVIEW_STATES: [&str; 5] = ["new", "important", "needs_review", "ignored", "resolved"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Workspace {
    Overview,
    Discover,
    Watchlist,
    Security,
    Health,
    Settings,
}

impl Workspace {
    const ALL: [Self; 6] = [
        Self::Overview,
        Self::Discover,
        Self::Watchlist,
        Self::Security,
        Self::Health,
        Self::Settings,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Discover => "Discover",
            Self::Watchlist => "Watchlist",
            Self::Security => "Security",
            Self::Health => "Health",
            Self::Settings => "Settings",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Self::Overview => "Discovery, review and monitoring at a glance.",
            Self::Discover => {
                "Search stored repositories and inspect the evidence behind each decision."
            }
            Self::Watchlist => "Repositories you follow, with observed changes and review history.",
            Self::Security => "Read-only static checks of authorized local source.",
            Self::Health => "Source availability, observations and notification delivery.",
            Self::Settings => "Safe configuration summary and explicit database maintenance.",
        }
    }
}

enum ScanCommand {
    Scan,
    Paused(bool),
}

enum ScanEvent {
    Ready,
    Started,
    Paused(bool),
    Finished {
        cycle: u64,
        new_count: usize,
        filtered: usize,
        duration_ms: u128,
    },
    Error(String),
}

#[derive(Clone)]
enum Mutation {
    Watch(bool),
    Review(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    Markdown,
    Json,
    CycloneDx,
}

impl ExportFormat {
    fn label(self) -> &'static str {
        match self {
            Self::Markdown => "Markdown",
            Self::Json => "Report JSON",
            Self::CycloneDx => "CycloneDX SBOM",
        }
    }
}

enum SqlCommand {
    Query(u64, RepositoryQuery),
    Snapshot,
    Changes(u64, i64),
    Mutate(i64, Mutation),
    RetryNotifications,
    ReEvaluate,
    Backup(PathBuf),
    Export(Arc<AnalysisReport>, ExportFormat, PathBuf),
    SaveReport(Arc<AnalysisReport>),
}

enum SqlEvent {
    Repositories(u64, Result<Vec<RepositoryRecord>, String>),
    Snapshot {
        stats: Result<(usize, usize, usize), String>,
        health: Result<OperationalHealth, String>,
        reports: Result<Vec<AnalysisReport>, String>,
    },
    Changes(u64, i64, Result<Vec<ChangeRecord>, String>),
    Mutated(i64, Mutation, Result<(), String>),
    Completed(Result<String, String>),
    ReportSaved(Arc<AnalysisReport>, Result<i64, String>),
}

struct AuditCommand {
    path: PathBuf,
    query_osv: bool,
    cancel_generation: u64,
}

enum AuditEvent {
    Finished(Arc<AnalysisReport>),
    Error(String),
    Cancelled,
}

enum ReportSaveState {
    Queued,
    Saving,
    Saved(i64),
    Failed(String),
}

struct ReportSave {
    report: Arc<AnalysisReport>,
    state: ReportSaveState,
}

impl ReportSave {
    fn pending(&self) -> bool {
        matches!(
            self.state,
            ReportSaveState::Queued | ReportSaveState::Saving
        )
    }

    fn finish(&mut self, report: &Arc<AnalysisReport>, result: Result<i64, String>) -> bool {
        if !Arc::ptr_eq(&self.report, report) || !matches!(self.state, ReportSaveState::Saving) {
            return false;
        }
        self.state = match result {
            Ok(id) => ReportSaveState::Saved(id),
            Err(error) => ReportSaveState::Failed(error),
        };
        true
    }

    fn message(&self) -> String {
        match &self.state {
            ReportSaveState::Queued => {
                "Analysis complete; report available. Waiting to queue local history save.".into()
            }
            ReportSaveState::Saving => {
                "Analysis complete; report available. Local history save pending.".into()
            }
            ReportSaveState::Saved(id) => {
                format!("Analysis report persisted in local history (report {id}).")
            }
            ReportSaveState::Failed(error) => {
                format!("Analysis report is available but was not persisted: {error}")
            }
        }
    }
}

// Every producer checks shutdown while waiting for a bounded result queue.
// A closed window cannot leave a worker blocked trying to report its last result.
fn deliver<T>(tx: &SyncSender<T>, mut event: T, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        match tx.try_send(event) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                event = returned;
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

struct Workers {
    stop: Arc<AtomicBool>,
    shutdown: watch::Sender<bool>,
    threads: Vec<JoinHandle<()>>,
}

impl Workers {
    fn cancel(&self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.shutdown.send(true);
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        self.cancel();
        let deadline = Instant::now() + WORKER_JOIN_TIMEOUT;
        while !self.threads.is_empty() {
            let mut index = 0;
            while index < self.threads.len() {
                if self.threads[index].is_finished() {
                    if self.threads.swap_remove(index).join().is_err() {
                        tracing::error!("GUI background worker panicked during shutdown");
                    }
                } else {
                    index += 1;
                }
            }
            if self.threads.is_empty() || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        for thread in self.threads.drain(..) {
            if thread.is_finished() {
                if thread.join().is_err() {
                    tracing::error!("GUI background worker panicked during shutdown");
                }
            } else {
                tracing::warn!(worker = thread.thread().name().unwrap_or("unnamed"),
                    "GUI shutdown deadline reached; detaching unfinished worker. Stalled filesystem/database I/O may continue; it has not been forcibly cancelled.");
            }
        }
    }
}

fn sql_worker(
    db: Database,
    config: AppConfig,
    rx: Receiver<SqlCommand>,
    tx: SyncSender<SqlEvent>,
    latest_query: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    let filter = RepoFilter::new(config.filtering);
    while !stop.load(Ordering::Acquire) {
        let command = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(command) => command,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        if stop.load(Ordering::Acquire) {
            break;
        }
        let event = match command {
            SqlCommand::Query(generation, query) => {
                if !is_current(generation, latest_query.load(Ordering::Acquire)) {
                    continue;
                }
                let result = db.list_repositories(&query).map_err(|e| e.to_string());
                if !is_current(generation, latest_query.load(Ordering::Acquire)) {
                    continue;
                }
                SqlEvent::Repositories(generation, result)
            }
            SqlCommand::Snapshot => {
                let stats = db.get_stats().map_err(|e| e.to_string());
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let health = db.operational_health().map_err(|e| e.to_string());
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let reports = db.analysis_reports(30).map_err(|e| e.to_string());
                SqlEvent::Snapshot {
                    stats,
                    health,
                    reports,
                }
            }
            SqlCommand::Changes(generation, id) => SqlEvent::Changes(
                generation,
                id,
                db.list_changes(id, 100).map_err(|e| e.to_string()),
            ),
            SqlCommand::Mutate(id, mutation) => {
                let result = match &mutation {
                    Mutation::Watch(watched) => db.set_watched(id, *watched),
                    Mutation::Review(state) => db.set_review_state(id, state),
                };
                SqlEvent::Mutated(id, mutation, result.map_err(|e| e.to_string()))
            }
            SqlCommand::RetryNotifications => SqlEvent::Completed(
                db.retry_failed_notifications()
                    .map(|count| format!("Queued {count} failed notifications for retry."))
                    .map_err(|e| e.to_string()),
            ),
            SqlCommand::ReEvaluate => SqlEvent::Completed(
                db.re_evaluate(&filter)
                    .map(|count| {
                        format!("Re-evaluated {count} stored repositories using current rules.")
                    })
                    .map_err(|e| e.to_string()),
            ),
            SqlCommand::Backup(path) => SqlEvent::Completed(
                db.backup_to(&path)
                    .map(|()| format!("Database backup created at {}.", path.display()))
                    .map_err(|e| e.to_string()),
            ),
            SqlCommand::Export(report, format, path) => {
                SqlEvent::Completed(export_report(&report, format, &path))
            }
            SqlCommand::SaveReport(report) => {
                let saved = db.save_analysis_report(&report).map_err(|e| e.to_string());
                SqlEvent::ReportSaved(report, saved)
            }
        };
        if !deliver(&tx, event, &stop) {
            break;
        }
    }
}

fn export_report(
    report: &AnalysisReport,
    format: ExportFormat,
    path: &Path,
) -> Result<String, String> {
    let content = match format {
        ExportFormat::Markdown => report.markdown(),
        ExportFormat::Json => serde_json::to_string_pretty(report).map_err(|e| e.to_string())?,
        ExportFormat::CycloneDx => {
            serde_json::to_string_pretty(&report.sbom_json()).map_err(|e| e.to_string())?
        }
    };
    write_new(path, content.as_bytes())?;
    Ok(format!(
        "{} exported to {}.",
        format.label(),
        path.display()
    ))
}

fn write_new(path: &Path, content: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            format!(
                "Cannot create {}: {e}. Choose a new file path.",
                path.display()
            )
        })?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("Export incomplete at {}: {e}", path.display()))
}

async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn scan_worker(
    config: AppConfig,
    db: Database,
    mut rx: async_mpsc::Receiver<ScanCommand>,
    tx: SyncSender<ScanEvent>,
    mut shutdown: watch::Receiver<bool>,
    stop: Arc<AtomicBool>,
) {
    if stop.load(Ordering::Acquire) {
        return;
    }
    let mut engine = match Engine::new(config.clone(), db) {
        Ok(engine) => engine,
        Err(error) => {
            deliver(
                &tx,
                ScanEvent::Error(format!("Engine initialization failed: {error}")),
                &stop,
            );
            return;
        }
    };
    engine.start_dispatcher();
    if !deliver(&tx, ScanEvent::Ready, &stop) {
        return;
    }
    let mut paused = !config.monitoring.enabled;
    let mut due = tokio::time::Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => break,
            command = rx.recv() => match command {
                Some(ScanCommand::Paused(value)) => {
                    paused = value;
                    due = tokio::time::Instant::now();
                    if !deliver(&tx, ScanEvent::Paused(paused), &stop) { break; }
                }
                Some(ScanCommand::Scan) => due = tokio::time::Instant::now(),
                None => break,
            },
            _ = tokio::time::sleep_until(due), if !paused => {
                if !deliver(&tx, ScanEvent::Started, &stop) { break; }
                if stop.load(Ordering::Acquire) { break; }
                // Keep the cycle future alive across pause commands. Shutdown drops it,
                // cancelling in-flight HTTP requests without spawning another scan.
                let cycle = engine.run_cycle();
                tokio::pin!(cycle);
                let result = loop {
                    tokio::select! {
                        biased;
                        _ = wait_for_shutdown(&mut shutdown) => return,
                        command = rx.recv() => match command {
                            Some(ScanCommand::Paused(value)) => {
                                paused = value;
                                if !deliver(&tx, ScanEvent::Paused(paused), &stop) { return; }
                            }
                            Some(ScanCommand::Scan) => {},
                            None => return,
                        },
                        result = &mut cycle => break result,
                    }
                };
                let event = match result {
                    Ok(result) => ScanEvent::Finished {
                        cycle: result.cycle,
                        new_count: result.items.len(),
                        filtered: result.spam_count,
                        duration_ms: result.duration_ms,
                    },
                    Err(error) => ScanEvent::Error(format!("Scan failed: {error}")),
                };
                if !deliver(&tx, event, &stop) { break; }
                due = tokio::time::Instant::now()
                    + Duration::from_secs(config.general.interval_seconds.max(1));
            }
        }
    }
}

async fn audit_worker(
    mut rx: async_mpsc::Receiver<AuditCommand>,
    tx: SyncSender<AuditEvent>,
    mut cancel: watch::Receiver<u64>,
    mut shutdown: watch::Receiver<bool>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        let command = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => return,
            command = rx.recv() => match command {
                Some(command) => command,
                None => return,
            },
        };
        if stop.load(Ordering::Acquire) {
            return;
        }
        if *cancel.borrow_and_update() != command.cancel_generation {
            if !deliver(&tx, AuditEvent::Cancelled, &stop) {
                return;
            }
            continue;
        }
        let result = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => return,
            _ = cancel.changed() => {
                if !deliver(&tx, AuditEvent::Cancelled, &stop) { return; }
                continue;
            },
            result = analysis::analyze_directory(&command.path, command.query_osv) => result,
        };
        let event = match result {
            Ok(report) => AuditEvent::Finished(Arc::new(report)),
            Err(error) => AuditEvent::Error(error),
        };
        if !deliver(&tx, event, &stop) {
            return;
        }
    }
}

fn is_current(received: u64, expected: u64) -> bool {
    received == expected
}

fn query_for(
    workspace: Workspace,
    text: &str,
    priority_only: bool,
    hide_forks: bool,
    review_state: &str,
    include_rejected: bool,
    page: usize,
) -> RepositoryQuery {
    RepositoryQuery {
        text: text.trim().to_owned(),
        priority_only,
        hide_forks,
        watch_only: workspace == Workspace::Watchlist,
        review_state: (!review_state.is_empty()).then(|| review_state.to_owned()),
        include_rejected,
        limit: PAGE_SIZE + 1,
        offset: page.saturating_mul(PAGE_SIZE),
    }
}

fn explicit_path(text: &str) -> Result<PathBuf, String> {
    let text = text.trim();
    if text.is_empty() {
        Err("Enter an explicit file or directory path first.".into())
    } else {
        Ok(PathBuf::from(text))
    }
}

fn severity_color(severity: &str) -> Color32 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" => ERROR,
        "medium" | "moderate" => Color32::from_rgb(222, 187, 120),
        _ => ACCENT,
    }
}

fn configured(value: bool) -> &'static str {
    if value {
        "Configured (redacted)"
    } else {
        "Not configured"
    }
}

fn redacted_message(config: &AppConfig, message: &str) -> String {
    let channels = &config.notifications;
    let destinations = [
        channels.discord_webhook_url.as_deref(),
        channels.telegram_bot_token.as_deref(),
        channels.telegram_chat_id.as_deref(),
        channels.webhook_url.as_deref(),
    ];
    let mut message = message.to_owned();
    for secret in config
        .auth
        .tokens
        .iter()
        .map(String::as_str)
        .chain(destinations.into_iter().flatten())
    {
        if !secret.is_empty() {
            message = message.replace(secret, "[redacted]");
        }
    }
    message
}

pub struct RepoWatcherApp {
    config: AppConfig,
    workspace: Workspace,
    monitoring: bool,
    engine_ready: bool,
    scanning: bool,
    pause_pending: bool,
    status: String,
    error: Option<String>,
    notice: Option<String>,
    stats: Option<(usize, usize, usize)>,
    stats_error: Option<String>,
    health: Option<OperationalHealth>,
    health_error: Option<String>,
    snapshot_loading: bool,
    snapshot_requested: bool,
    reports: Vec<Arc<AnalysisReport>>,
    reports_error: Option<String>,
    text: String,
    priority_only: bool,
    hide_forks: bool,
    include_rejected: bool,
    review_filter: String,
    page: usize,
    has_next: bool,
    repositories: Vec<RepositoryRecord>,
    query_generation: u64,
    latest_query: Arc<AtomicU64>,
    pending_query: Option<(u64, RepositoryQuery)>,
    query_after: Instant,
    query_loading: bool,
    query_error: Option<String>,
    selected: Option<RepositoryRecord>,
    detail_generation: u64,
    changes: Vec<ChangeRecord>,
    changes_loading: bool,
    changes_error: Option<String>,
    review_choice: String,
    sql_busy: bool,
    audit_path: String,
    authorized: bool,
    osv_consent: bool,
    auditing: bool,
    audit_error: Option<String>,
    active_report: Option<Arc<AnalysisReport>>,
    report_save: Option<ReportSave>,
    export_path: String,
    export_format: ExportFormat,
    backup_path: String,
    re_evaluate_confirmed: bool,
    show_about: bool,
    app_icon: Option<egui::TextureHandle>,
    sql_tx: SyncSender<SqlCommand>,
    sql_rx: Receiver<SqlEvent>,
    scan_tx: async_mpsc::Sender<ScanCommand>,
    scan_rx: Receiver<ScanEvent>,
    audit_tx: async_mpsc::Sender<AuditCommand>,
    audit_rx: Receiver<AuditEvent>,
    audit_cancel: watch::Sender<u64>,
    shutdown: watch::Sender<bool>,
    stop: Arc<AtomicBool>,
    last_refresh: Instant,
}

impl RepoWatcherApp {
    fn request_query(&mut self, debounce: bool) {
        self.query_generation = self.query_generation.wrapping_add(1);
        self.latest_query
            .store(self.query_generation, Ordering::Release);
        self.pending_query = Some((
            self.query_generation,
            query_for(
                self.workspace,
                &self.text,
                self.priority_only,
                self.hide_forks,
                &self.review_filter,
                self.include_rejected,
                self.page,
            ),
        ));
        self.query_after = Instant::now()
            + if debounce {
                Duration::from_millis(220)
            } else {
                Duration::ZERO
            };
        self.query_loading = true;
        self.query_error = None;
        self.repositories.clear();
        self.has_next = false;
    }

    fn flush_requests(&mut self) {
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        if let Some(save) = &mut self.report_save {
            if matches!(save.state, ReportSaveState::Queued) {
                match self
                    .sql_tx
                    .try_send(SqlCommand::SaveReport(save.report.clone()))
                {
                    Ok(()) => save.state = ReportSaveState::Saving,
                    Err(TrySendError::Full(_)) => {}
                    Err(TrySendError::Disconnected(_)) => {
                        save.state =
                            ReportSaveState::Failed("Database worker is unavailable.".into());
                    }
                }
            }
        }
        if Instant::now() >= self.query_after {
            if let Some((generation, query)) = self.pending_query.take() {
                match self.sql_tx.try_send(SqlCommand::Query(generation, query)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(SqlCommand::Query(generation, query))) => {
                        self.pending_query = Some((generation, query));
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        self.query_loading = false;
                        self.query_error = Some("Database worker is unavailable.".into());
                    }
                    Err(_) => unreachable!("only query commands are sent here"),
                }
            }
        }
        if self.snapshot_requested && !self.snapshot_loading {
            match self.sql_tx.try_send(SqlCommand::Snapshot) {
                Ok(()) => {
                    self.snapshot_requested = false;
                    self.snapshot_loading = true;
                }
                Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    self.snapshot_requested = false;
                    self.stats_error = Some("Database worker is unavailable.".into());
                    self.health_error = self.stats_error.clone();
                    self.reports_error = self.stats_error.clone();
                }
            }
        }
    }

    fn operation(&mut self, command: SqlCommand) {
        if self.sql_busy || self.stop.load(Ordering::Acquire) {
            return;
        }
        match self.sql_tx.try_send(command) {
            Ok(()) => {
                self.sql_busy = true;
                self.error = None;
                self.notice = None;
            }
            Err(TrySendError::Full(_)) => {
                self.error = Some("Database queue is busy. Please retry.".into())
            }
            Err(TrySendError::Disconnected(_)) => {
                self.error = Some("Database worker is unavailable.".into())
            }
        }
    }

    fn refresh(&mut self) {
        self.snapshot_requested = true;
        self.last_refresh = Instant::now();
        if matches!(self.workspace, Workspace::Discover | Workspace::Watchlist) {
            self.request_query(false);
        }
    }

    fn navigate(&mut self, workspace: Workspace) {
        if self.workspace == workspace {
            return;
        }
        self.workspace = workspace;
        self.page = 0;
        self.selected = None;
        if matches!(workspace, Workspace::Discover | Workspace::Watchlist) {
            self.request_query(false);
        }
    }

    fn open_detail(&mut self, record: RepositoryRecord) {
        self.detail_generation = self.detail_generation.wrapping_add(1);
        self.changes.clear();
        self.changes_error = None;
        self.review_choice = record.review_state.clone();
        match self
            .sql_tx
            .try_send(SqlCommand::Changes(self.detail_generation, record.repo.id))
        {
            Ok(()) => self.changes_loading = true,
            Err(error) => {
                self.changes_loading = false;
                self.changes_error = Some(format!("Cannot load change history: {error}"));
            }
        }
        self.selected = Some(record);
    }

    fn receive_results(&mut self) {
        // Bound work per frame even when several workers complete together.
        for _ in 0..32 {
            let event = match self.sql_rx.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if self.sql_busy
                        || self.snapshot_loading
                        || self.query_loading
                        || self.changes_loading
                        || self.report_save.as_ref().is_some_and(ReportSave::pending)
                    {
                        let error =
                            "Database worker stopped before completing the request.".to_owned();
                        self.error = Some(error.clone());
                        self.query_error = Some(error.clone());
                        self.stats_error = Some(error.clone());
                        self.health_error = Some(error.clone());
                        self.reports_error = Some(error.clone());
                        self.changes_error = Some(error);
                        self.sql_busy = false;
                        self.snapshot_loading = false;
                        self.query_loading = false;
                        self.changes_loading = false;
                        if let Some(save) = self.report_save.as_mut().filter(|save| save.pending())
                        {
                            save.state = ReportSaveState::Failed(
                                "Database worker stopped before saving the report.".into(),
                            );
                        }
                    }
                    break;
                }
            };
            match event {
                SqlEvent::Repositories(generation, result) => {
                    if !is_current(generation, self.query_generation) {
                        continue;
                    }
                    self.query_loading = false;
                    match result {
                        Ok(mut records) => {
                            self.has_next = records.len() > PAGE_SIZE;
                            records.truncate(PAGE_SIZE);
                            if let Some(selected) = &mut self.selected {
                                if let Some(current) =
                                    records.iter().find(|r| r.repo.id == selected.repo.id)
                                {
                                    *selected = current.clone();
                                }
                            }
                            self.repositories = records;
                            self.query_error = None;
                        }
                        Err(error) => self.query_error = Some(error),
                    }
                }
                SqlEvent::Snapshot {
                    stats,
                    health,
                    reports,
                } => {
                    self.snapshot_loading = false;
                    match stats {
                        Ok(stats) => {
                            self.stats = Some(stats);
                            self.stats_error = None;
                        }
                        Err(error) => self.stats_error = Some(error),
                    }
                    match health {
                        Ok(health) => {
                            self.health = Some(health);
                            self.health_error = None;
                        }
                        Err(error) => self.health_error = Some(error),
                    }
                    match reports {
                        Ok(reports) => {
                            self.reports = reports.into_iter().map(Arc::new).collect();
                            self.reports_error = None;
                        }
                        Err(error) => self.reports_error = Some(error),
                    }
                }
                SqlEvent::Changes(generation, id, result) => {
                    if !is_current(generation, self.detail_generation)
                        || self.selected.as_ref().map(|r| r.repo.id) != Some(id)
                    {
                        continue;
                    }
                    self.changes_loading = false;
                    match result {
                        Ok(changes) => self.changes = changes,
                        Err(error) => self.changes_error = Some(error),
                    }
                }
                SqlEvent::Mutated(id, mutation, result) => {
                    self.sql_busy = false;
                    match result {
                        Ok(()) => {
                            if let Some(record) = self.selected.as_mut().filter(|r| r.repo.id == id)
                            {
                                match mutation {
                                    Mutation::Watch(value) => record.watched = value,
                                    Mutation::Review(value) => record.review_state = value,
                                }
                            }
                            self.notice = Some("Repository review saved.".into());
                            self.refresh();
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
                SqlEvent::Completed(result) => {
                    self.sql_busy = false;
                    match result {
                        Ok(message) => {
                            self.notice = Some(message);
                            self.refresh();
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
                SqlEvent::ReportSaved(report, result) => {
                    let result = result.map_err(|error| redacted_message(&self.config, &error));
                    if let Some(save) = &mut self.report_save {
                        if save.finish(&report, result) {
                            let message = save.message();
                            if matches!(save.state, ReportSaveState::Saved(_)) {
                                self.notice = Some(message);
                                self.refresh();
                            } else {
                                self.error = Some(message);
                            }
                        }
                    }
                }
            }
        }
        for _ in 0..8 {
            let event = match self.scan_rx.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if self.engine_ready {
                        self.error
                            .get_or_insert_with(|| "Scan worker stopped unexpectedly.".into());
                    }
                    self.engine_ready = false;
                    self.scanning = false;
                    self.pause_pending = false;
                    break;
                }
            };
            match event {
                ScanEvent::Ready => {
                    self.engine_ready = true;
                    self.status = "Engine ready".into();
                }
                ScanEvent::Started => {
                    self.scanning = true;
                    self.status = "Discovery cycle running".into();
                }
                ScanEvent::Paused(paused) => {
                    self.pause_pending = false;
                    self.monitoring = !paused;
                    self.status = if paused && self.scanning {
                        "Pause scheduled; the current cycle will finish".into()
                    } else if paused {
                        "Automatic scanning paused".into()
                    } else {
                        "Automatic scanning resumed".into()
                    };
                }
                ScanEvent::Finished {
                    cycle,
                    new_count,
                    filtered,
                    duration_ms,
                } => {
                    self.scanning = false;
                    self.status = format!(
                        "Cycle {cycle}: {new_count} new, {filtered} filtered, {duration_ms} ms"
                    );
                    self.refresh();
                }
                ScanEvent::Error(error) => {
                    self.scanning = false;
                    self.status = "Engine needs attention".into();
                    self.error = Some(redacted_message(&self.config, &error));
                    self.refresh();
                }
            }
        }
        for _ in 0..4 {
            let event = match self.audit_rx.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if self.auditing {
                        self.audit_error =
                            Some("Analysis worker stopped before completing the request.".into());
                        self.auditing = false;
                    }
                    break;
                }
            };
            self.auditing = false;
            match event {
                AuditEvent::Finished(report) => {
                    self.active_report = Some(report.clone());
                    self.report_save = Some(ReportSave {
                        report,
                        state: ReportSaveState::Queued,
                    });
                    self.notice = Some(
                        "Analysis complete; report available. Local history save is pending."
                            .into(),
                    );
                }
                AuditEvent::Error(error) => self.audit_error = Some(error),
                AuditEvent::Cancelled => {
                    self.notice = Some("Analysis cancelled. No new report was stored.".into())
                }
            }
        }
    }

    fn scan_controls(&mut self, ui: &mut egui::Ui) {
        let enabled = self.engine_ready && !self.stop.load(Ordering::Acquire);
        if ui
            .add_enabled(
                enabled && !self.scanning && self.monitoring && !self.pause_pending,
                egui::Button::new("Scan now"),
            )
            .clicked()
        {
            match self.scan_tx.try_send(ScanCommand::Scan) {
                Ok(()) => {
                    self.scanning = true;
                    self.status = "Scan requested".into();
                }
                Err(error) => self.error = Some(format!("Cannot request scan: {error}")),
            }
        }
        let label = if self.monitoring {
            "Pause scans"
        } else {
            "Resume scans"
        };
        if ui
            .add_enabled(enabled && !self.pause_pending, egui::Button::new(label))
            .clicked()
        {
            match self.scan_tx.try_send(ScanCommand::Paused(self.monitoring)) {
                Ok(()) => self.pause_pending = true,
                Err(error) => self.error = Some(format!("Cannot change scanning state: {error}")),
            }
        }
        ui.label(
            RichText::new(if self.monitoring {
                "Monitoring on"
            } else {
                "Paused"
            })
            .color(MUTED),
        );
    }

    fn overview_ui(&mut self, ui: &mut egui::Ui) {
        if let Some(error) = &self.stats_error {
            error_text(ui, &format!("Statistics unavailable: {error}"));
        }
        ui.horizontal_wrapped(|ui| {
            let values = self
                .stats
                .map(|(total, today, priority)| [total, today, priority]);
            for (index, title) in [
                "Stored repositories",
                "Discovered today (UTC)",
                "Priority repositories",
            ]
            .iter()
            .enumerate()
            {
                metric(ui, title, values.map(|v| v[index]));
            }
            metric(
                ui,
                "Watched repositories",
                self.health.as_ref().map(|h| h.watched_repositories),
            );
        });
        ui.add_space(18.0);
        card(ui, |ui| {
            ui.heading("Discovery control");
            ui.label(&self.status);
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| self.scan_controls(ui));
            ui.label(
                RichText::new(
                    "Pausing prevents subsequent cycles; a running cycle finishes normally.",
                )
                .small()
                .color(MUTED),
            );
        });
        ui.add_space(12.0);
        card(ui, |ui| {
            ui.heading("Review workflow");
            ui.label("Discover repositories, inspect rule evidence, assign a review state, and watch relevant projects for changes.");
            ui.horizontal_wrapped(|ui| {
                if ui.button("Browse repositories").clicked() {
                    self.navigate(Workspace::Discover);
                }
                if ui.button("Open watchlist").clicked() {
                    self.navigate(Workspace::Watchlist);
                }
                if ui.button("Analyze local source").clicked() {
                    self.navigate(Workspace::Security);
                }
            });
        });
        ui.add_space(12.0);
        if let Some(health) = &self.health {
            card(ui, |ui| {
                ui.heading("Operational signals");
                ui.label(format!(
                    "{} observations recorded. {} notifications pending; {} failed.",
                    health.observations, health.pending_notifications, health.failed_notifications
                ));
                if health.sources.is_empty() {
                    ui.label(
                        RichText::new(
                            "No source observations yet. Run a discovery cycle to populate health.",
                        )
                        .color(MUTED),
                    );
                }
                for source in &health.sources {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(&source.name);
                        ui.label(&source.status);
                        ui.label(RichText::new(timestamp(source.last_success_at)).color(MUTED));
                    });
                }
            });
        } else if let Some(error) = &self.health_error {
            error_text(ui, &format!("Operational signals unavailable: {error}"));
        } else {
            loading(ui, "Loading operational signals...");
        }
    }

    fn repositories_ui(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        ui.horizontal_wrapped(|ui| {
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut self.text)
                        .hint_text("Search repository, description, topics...")
                        .desired_width(ui.available_width().min(350.0)),
                )
                .changed();
            changed |= ui.checkbox(&mut self.priority_only, "Priority").changed();
            changed |= ui.checkbox(&mut self.hide_forks, "Hide forks").changed();
            changed |= ui
                .checkbox(&mut self.include_rejected, "Include rejected")
                .changed();
            let before = self.review_filter.clone();
            egui::ComboBox::from_id_salt("review_filter")
                .selected_text(if self.review_filter.is_empty() {
                    "All review states"
                } else {
                    &self.review_filter
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.review_filter,
                        String::new(),
                        "All review states",
                    );
                    for state in REVIEW_STATES {
                        ui.selectable_value(&mut self.review_filter, state.to_owned(), state);
                    }
                });
            changed |= before != self.review_filter;
        });
        if changed {
            self.page = 0;
            self.request_query(true);
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.page > 0 && !self.query_loading,
                    egui::Button::new("Previous"),
                )
                .clicked()
            {
                self.page -= 1;
                self.request_query(false);
            }
            ui.label(format!("Page {}", self.page + 1));
            if ui
                .add_enabled(
                    self.has_next && !self.query_loading,
                    egui::Button::new("Next"),
                )
                .clicked()
            {
                self.page += 1;
                self.request_query(false);
            }
            if ui.button("Refresh results").clicked() {
                self.request_query(false);
            }
            ui.label(
                RichText::new("Filters apply before pagination.")
                    .small()
                    .color(MUTED),
            );
        });
        ui.separator();
        if self.query_loading {
            loading(ui, "Loading matching repositories...");
            return;
        }
        if let Some(error) = &self.query_error {
            error_text(ui, &format!("Repository query failed: {error}"));
            return;
        }
        if self.repositories.is_empty() {
            card(ui, |ui| {
                ui.strong(if self.workspace == Workspace::Watchlist {
                    "No watched repositories match these filters."
                } else {
                    "No matching repositories."
                });
                ui.label("Try changing the search or filters. New installations need a discovery cycle first.");
                if self.workspace == Workspace::Watchlist
                    && ui.button("Find repositories to watch").clicked()
                {
                    self.navigate(Workspace::Discover);
                }
            });
            return;
        }
        let mut selected = None;
        for record in &self.repositories {
            card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .button(RichText::new(&record.repo.full_name).strong().color(ACCENT))
                        .clicked()
                    {
                        selected = Some(record.clone());
                    }
                    ui.label(RichText::new(&record.review_state).small().color(MUTED));
                    if record.watched {
                        ui.label(RichText::new("Watched").small().color(ACCENT));
                    }
                    if record.repo.is_priority {
                        ui.label(RichText::new("Priority").small().color(ACCENT));
                    }
                    if record.repo.archived {
                        ui.label(RichText::new("Archived").small().color(MUTED));
                    }
                    if record.repo.fork {
                        ui.label(RichText::new("Fork").small().color(MUTED));
                    }
                });
                ui.label(
                    record
                        .repo
                        .description
                        .as_deref()
                        .filter(|d| !d.trim().is_empty())
                        .unwrap_or("No description observed."),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(
                            record
                                .repo
                                .language
                                .as_deref()
                                .unwrap_or("Language unknown"),
                        )
                        .small()
                        .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{} stars", record.repo.stars))
                            .small()
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!(
                            "Relevance {} / Confidence {} / Security {}",
                            record.assessment.relevance,
                            record.assessment.confidence,
                            record.assessment.security_importance
                        ))
                        .small()
                        .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!("Decision: {}", record.assessment.decision))
                            .small()
                            .color(MUTED),
                    );
                });
            });
            ui.add_space(6.0);
        }
        if let Some(record) = selected {
            self.open_detail(record);
        }
    }

    fn detail_ui(&mut self, ctx: &egui::Context) {
        let Some(record) = self.selected.clone() else {
            return;
        };
        let mut open = true;
        let size = ctx.screen_rect().size();
        egui::Window::new("Repository evidence")
            .id(egui::Id::new("repository_detail"))
            .open(&mut open)
            .default_width((size.x - 60.0).min(720.0))
            .max_width(size.x - 32.0)
            .max_height(size.y - 64.0)
            .resizable(true)
            .collapsible(false)
            .vscroll(true)
            .show(ctx, |ui| {
                ui.heading(&record.repo.full_name);
                ui.label(
                    record
                        .repo
                        .description
                        .as_deref()
                        .unwrap_or("No description observed."),
                );
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Open repository").clicked() {
                        if let Err(error) = open_repository(&record.repo.html_url) {
                            self.error = Some(error);
                        }
                    }
                    if ui
                        .add_enabled(
                            !self.sql_busy,
                            egui::Button::new(if record.watched {
                                "Remove from watchlist"
                            } else {
                                "Watch repository"
                            }),
                        )
                        .clicked()
                    {
                        self.operation(SqlCommand::Mutate(
                            record.repo.id,
                            Mutation::Watch(!record.watched),
                        ));
                    }
                    egui::ComboBox::from_id_salt("detail_review_state")
                        .selected_text(&self.review_choice)
                        .show_ui(ui, |ui| {
                            for state in REVIEW_STATES {
                                ui.selectable_value(
                                    &mut self.review_choice,
                                    state.to_owned(),
                                    state,
                                );
                            }
                        });
                    if ui
                        .add_enabled(
                            !self.sql_busy && self.review_choice != record.review_state,
                            egui::Button::new("Save review"),
                        )
                        .clicked()
                    {
                        self.operation(SqlCommand::Mutate(
                            record.repo.id,
                            Mutation::Review(self.review_choice.clone()),
                        ));
                    }
                });
                if self.sql_busy {
                    loading(ui, "Saving or running maintenance...");
                }
                if let Some(error) = &self.error {
                    error_text(ui, &redacted_message(&self.config, error));
                }
                ui.separator();
                ui.heading("Rule assessment");
                ui.label(format!(
                    "Decision: {} | relevance {} | confidence {} | security importance {}",
                    record.assessment.decision,
                    record.assessment.relevance,
                    record.assessment.confidence,
                    record.assessment.security_importance
                ));
                ui.label(
                    RichText::new("Rule-based scores are triage signals, not a security verdict.")
                        .small()
                        .color(MUTED),
                );
                ui.label(format!("Evaluated: {}", record.assessment.evaluated_at));
                ui.strong("Evidence and reasons");
                if record.assessment.reasons.is_empty() {
                    ui.label("No assessment reasons stored.");
                }
                for reason in &record.assessment.reasons {
                    ui.label(reason);
                }
                ui.add_space(6.0);
                ui.strong("Missing evidence");
                if record.assessment.missing.is_empty() {
                    ui.label("No missing fields reported by the assessment.");
                }
                for missing in &record.assessment.missing {
                    ui.label(RichText::new(missing).color(MUTED));
                }
                ui.separator();
                ui.heading("Observed metadata");
                ui.label(format!(
                    "Source: {} | metadata complete: {} | private: {} | archived: {}",
                    record.repo.source,
                    record.repo.metadata_complete,
                    record.repo.private,
                    record.repo.archived
                ));
                ui.label(format!(
                    "Language: {} | license: {} | stars: {} | forks: {}",
                    record.repo.language.as_deref().unwrap_or("Unknown"),
                    record.repo.license.as_deref().unwrap_or("Unknown"),
                    record.repo.stars,
                    record.repo.forks_count
                ));
                ui.label(format!(
                    "Default branch: {} | latest release: {}",
                    record.repo.default_branch.as_deref().unwrap_or("Unknown"),
                    record.repo.latest_release.as_deref().unwrap_or("Unknown")
                ));
                ui.label(format!(
                    "Created: {}",
                    record.repo.created_at.as_deref().unwrap_or("Unknown")
                ));
                ui.label(format!(
                    "Last push: {}",
                    record.repo.pushed_at.as_deref().unwrap_or("Unknown")
                ));
                ui.label(format!("Discovered: {}", record.repo.discovered_at));
                ui.label(format!("Last observed: {}", record.last_observed_at));
                if !record.repo.topics.is_empty() {
                    ui.label(format!("Topics: {}", record.repo.topics.join(", ")));
                }
                ui.separator();
                ui.heading("Historical changes");
                ui.label(
                    RichText::new(
                        "Most recent 100 stored changes. Unobserved changes are not inferred.",
                    )
                    .small()
                    .color(MUTED),
                );
                if self.changes_loading {
                    loading(ui, "Loading change history...");
                } else if let Some(error) = &self.changes_error {
                    error_text(ui, error);
                } else if self.changes.is_empty() {
                    ui.label("No changes recorded for this repository yet.");
                }
                for change in &self.changes {
                    card(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.strong(&change.field);
                            ui.label(RichText::new(&change.observed_at).small().color(MUTED));
                        });
                        ui.label(format!("Before: {}", change.before));
                        ui.label(format!("After: {}", change.after));
                    });
                }
            });
        if !open {
            self.selected = None;
        }
    }

    fn security_ui(&mut self, ui: &mut egui::Ui) {
        let save_pending = self.report_save.as_ref().is_some_and(ReportSave::pending);
        card(ui, |ui| {
            ui.strong("Analyze a local directory");
            let path_changed = ui
                .add_enabled(
                    !self.auditing,
                    egui::TextEdit::singleline(&mut self.audit_path)
                        .hint_text("Explicit local directory path")
                        .desired_width(ui.available_width()),
                )
                .changed();
            if path_changed {
                self.authorized = false;
            }
            ui.add_enabled(
                !self.auditing,
                egui::Checkbox::new(
                    &mut self.authorized,
                    "I own this source or have permission to analyze it.",
                ),
            );
            ui.add_enabled(
                !self.auditing,
                egui::Checkbox::new(
                    &mut self.osv_consent,
                    "Allow sending dependency names and versions to OSV for vulnerability lookup.",
                ),
            );
            ui.label(RichText::new("OSV is off by default. Source code stays local; dependency metadata leaves this machine only with the separate consent above.").small().color(MUTED));
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        self.authorized
                            && !self.auditing
                            && !save_pending
                            && !self.stop.load(Ordering::Acquire)
                            && !self.audit_path.trim().is_empty(),
                        egui::Button::new("Run authorized analysis"),
                    )
                    .clicked()
                {
                    match explicit_path(&self.audit_path) {
                        Ok(path) => match self.audit_tx.try_send(AuditCommand {
                            path,
                            query_osv: self.osv_consent,
                            cancel_generation: *self.audit_cancel.borrow(),
                        }) {
                            Ok(()) => {
                                self.auditing = true;
                                self.audit_error = None;
                                self.active_report = None;
                                self.report_save = None;
                                self.notice = None;
                            }
                            Err(error) => {
                                self.audit_error = Some(format!("Cannot start analysis: {error}"))
                            }
                        },
                        Err(error) => self.audit_error = Some(error),
                    }
                }
                if self.auditing {
                    loading(ui, "Analyzing source; discovery remains independent...");
                    if ui.button("Cancel analysis").clicked() {
                        self.audit_cancel
                            .send_modify(|value| *value = value.wrapping_add(1));
                    }
                }
            });
            if let Some(error) = &self.audit_error {
                error_text(ui, error);
            }
            if let Some(save) = &mut self.report_save {
                ui.separator();
                ui.label(RichText::new("Latest completed analysis").strong());
                ui.label(&save.report.root);
                let message = redacted_message(&self.config, &save.message());
                if save.pending() {
                    loading(ui, &message);
                    ui.label(RichText::new("View or export the completed report below. Finish saving before starting another analysis.").small().color(MUTED));
                } else if matches!(save.state, ReportSaveState::Failed(_)) {
                    error_text(ui, &message);
                    if ui
                        .add_enabled(
                            !self.stop.load(Ordering::Acquire),
                            egui::Button::new("Retry saving report"),
                        )
                        .clicked()
                    {
                        save.state = ReportSaveState::Queued;
                        self.error = None;
                    }
                } else {
                    ui.label(RichText::new(message).color(ACCENT));
                }
            }
        });
        ui.add_space(10.0);
        egui::CollapsingHeader::new("Stored analysis history (latest 30)")
            .default_open(self.active_report.is_none())
            .show(ui, |ui| {
                if let Some(error) = &self.reports_error {
                    error_text(ui, &format!("History unavailable: {error}"));
                } else if self.snapshot_loading && self.reports.is_empty() {
                    loading(ui, "Loading stored reports...");
                } else if self.reports.is_empty() {
                    ui.label("No stored reports. Run an authorized local analysis to begin.");
                }
                for report in &self.reports {
                    if ui
                        .selectable_label(
                            self.active_report.as_ref().is_some_and(|r| {
                                r.root == report.root && r.generated_at == report.generated_at
                            }),
                            format!(
                                "{} | {} | {} findings",
                                report.generated_at,
                                report.root,
                                report.findings.len()
                            ),
                        )
                        .clicked()
                    {
                        self.active_report = Some(report.clone());
                    }
                }
            });
        let Some(report) = self.active_report.clone() else {
            return;
        };
        ui.separator();
        ui.heading("Analysis report");
        ui.label(&report.root);
        ui.label(RichText::new(&report.generated_at).small().color(MUTED));
        ui.horizontal_wrapped(|ui| {
            metric(ui, "Files scanned", Some(report.files_scanned));
            metric(ui, "Skipped", Some(report.skipped));
            metric(ui, "Findings", Some(report.findings.len()));
            metric(ui, "Dependencies", Some(report.dependencies.len()));
        });
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.strong("Coverage and limitations");
            ui.label("This is bounded static analysis, not proof of safety. Skipped files, unsupported formats and unresolved dependencies may hide issues.");
            ui.label(if report.osv_requested {
                format!(
                    "OSV lookup enabled for this report: {} requests attempted.",
                    report.osv_queries
                )
            } else {
                "Offline report: no external vulnerability service was queried.".into()
            });
            if report.limits.is_empty() {
                ui.label("No additional coverage notes were recorded.");
            }
            for limit in &report.limits {
                ui.label(RichText::new(limit).color(MUTED));
            }
            ui.add_space(6.0);
            ui.strong("Recorded coverage gaps");
            if report.coverage_gaps.is_empty() {
                ui.label("No additional gaps recorded. Static rules and inventory remain incomplete by design.");
            }
            for gap in &report.coverage_gaps {
                ui.label(RichText::new(gap).color(MUTED));
            }
        });
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.strong("Export to a new file");
            ui.label(RichText::new(IO_SHUTDOWN_WARNING).small().color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.export_path)
                    .hint_text("Explicit output file path; existing files are never replaced")
                    .desired_width(ui.available_width()),
            );
            ui.horizontal_wrapped(|ui| {
                egui::ComboBox::from_id_salt("export_format")
                    .selected_text(self.export_format.label())
                    .show_ui(ui, |ui| {
                        for format in [
                            ExportFormat::Markdown,
                            ExportFormat::Json,
                            ExportFormat::CycloneDx,
                        ] {
                            ui.selectable_value(&mut self.export_format, format, format.label());
                        }
                    });
                if ui
                    .add_enabled(
                        !self.sql_busy && !self.export_path.trim().is_empty(),
                        egui::Button::new("Export report"),
                    )
                    .clicked()
                {
                    match explicit_path(&self.export_path) {
                        Ok(path) => self.operation(SqlCommand::Export(
                            report.clone(),
                            self.export_format,
                            path,
                        )),
                        Err(error) => self.error = Some(error),
                    }
                }
            });
        });
        ui.add_space(8.0);
        ui.heading("Findings");
        if report.findings.is_empty() {
            ui.label("No findings in the analyzed coverage. This does not establish that the project is secure.");
        }
        for (index, finding) in report.findings.iter().enumerate() {
            egui::CollapsingHeader::new(
                RichText::new(format!(
                    "{} | {} | {}{}",
                    finding.severity,
                    finding.rule,
                    finding.path,
                    finding
                        .line
                        .map(|line| format!(":{line}"))
                        .unwrap_or_default()
                ))
                .color(severity_color(&finding.severity)),
            )
            .id_salt(("finding", index))
            .default_open(index < 3)
            .show(ui, |ui| {
                ui.strong("Evidence");
                ui.add(egui::Label::new(RichText::new(&finding.evidence).monospace()).wrap());
                ui.strong("Remediation");
                ui.label(&finding.remediation);
            });
        }
        egui::CollapsingHeader::new("Dependency inventory").show(ui, |ui| {
            if report.dependencies.is_empty() {
                ui.label("No supported dependencies were identified. See coverage notes above.");
            }
            for dependency in &report.dependencies {
                ui.label(format!(
                    "{} | {} | {}",
                    dependency.ecosystem, dependency.name, dependency.version
                ));
            }
        });
    }

    fn health_ui(&mut self, ui: &mut egui::Ui) {
        if let Some(error) = &self.health_error {
            error_text(ui, &format!("Health unavailable: {error}"));
        }
        let Some(health) = &self.health else {
            if self.health_error.is_none() {
                loading(ui, "Loading operational health...");
            }
            return;
        };
        ui.horizontal_wrapped(|ui| {
            metric(
                ui,
                "Pending notifications",
                Some(health.pending_notifications),
            );
            metric(
                ui,
                "Failed notifications",
                Some(health.failed_notifications),
            );
            metric(ui, "Observations", Some(health.observations));
            metric(
                ui,
                "Rejected repositories",
                Some(health.rejected_repositories),
            );
        });
        let failed = health.failed_notifications;
        ui.add_space(8.0);
        ui.heading("Discovery sources");
        if health.sources.is_empty() {
            ui.label(
                "No source health recorded yet. A discovery cycle will record source outcomes.",
            );
        }
        for source in &health.sources {
            card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(&source.name);
                    ui.label(RichText::new(&source.status).color(ACCENT));
                });
                ui.label(redacted_message(&self.config, &source.message));
                ui.label(
                    RichText::new(format!(
                        "Last success: {} | Next allowed: {}",
                        timestamp(source.last_success_at),
                        timestamp(source.next_allowed_at)
                    ))
                    .small()
                    .color(MUTED),
                );
            });
            ui.add_space(6.0);
        }
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.strong("Notification recovery");
            ui.label("Retry queues failed deliveries for the engine. Delivery depends on the next active cycle and the configured channel.");
            if ui
                .add_enabled(
                    failed > 0 && !self.sql_busy,
                    egui::Button::new("Retry failed notifications"),
                )
                .clicked()
            {
                self.operation(SqlCommand::RetryNotifications);
            }
        });
    }

    fn settings_ui(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.heading("Monitoring");
            ui.horizontal_wrapped(|ui| self.scan_controls(ui));
            ui.label(format!(
                "Discovery interval: {} seconds | Concurrent requests: {}",
                self.config.general.interval_seconds, self.config.general.max_concurrent_requests
            ));
            ui.label(format!("Watch interval: {} seconds | Enrichment budget: {} / cycle | Watch budget: {} / cycle", self.config.monitoring.watch_interval_seconds, self.config.monitoring.enrich_per_cycle, self.config.monitoring.watch_per_cycle));
            ui.label(format!(
                "Sources: sequential {} | events {} | search {}",
                self.config.streams.enable_sequential_stream,
                self.config.streams.enable_events_stream,
                self.config.streams.enable_search_stream
            ));
            ui.label(RichText::new("Runtime pause does not rewrite configuration. Edit the configuration file and restart to change source or rule settings.").small().color(MUTED));
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            ui.heading("Credentials and channels");
            ui.label(format!(
                "GitHub credentials: {} configured; values hidden",
                self.config.auth.tokens.len()
            ));
            let channels = &self.config.notifications;
            ui.label(format!(
                "Desktop notifications: {}",
                if channels.enable_windows_toast {
                    "Enabled"
                } else {
                    "Disabled"
                }
            ));
            ui.label(format!(
                "Discord: {}",
                configured(channels.discord_webhook_url.is_some())
            ));
            ui.label(format!(
                "Telegram: {}",
                configured(
                    channels.telegram_bot_token.is_some() && channels.telegram_chat_id.is_some()
                )
            ));
            ui.label(format!(
                "Webhook: {}",
                configured(channels.webhook_url.is_some())
            ));
            ui.label(
                RichText::new(
                    "Tokens, destination URLs and chat identifiers are never displayed here.",
                )
                .small()
                .color(MUTED),
            );
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            ui.heading("Stored rule maintenance");
            ui.label("Apply the currently loaded filtering and assessment rules to stored repositories. This updates stored decisions; it does not fetch new metadata.");
            ui.checkbox(
                &mut self.re_evaluate_confirmed,
                "I understand stored assessments will be updated.",
            );
            if ui
                .add_enabled(
                    self.re_evaluate_confirmed && !self.sql_busy,
                    egui::Button::new("Re-evaluate stored rules"),
                )
                .clicked()
            {
                self.operation(SqlCommand::ReEvaluate);
                self.re_evaluate_confirmed = false;
            }
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            ui.heading("Database backup");
            ui.label(RichText::new(IO_SHUTDOWN_WARNING).small().color(MUTED));
            ui.label("Create a consistent database backup at an explicit new path. Choose a secure destination; the database includes reports and repository history.");
            ui.add(
                egui::TextEdit::singleline(&mut self.backup_path)
                    .hint_text("New backup file path")
                    .desired_width(ui.available_width()),
            );
            if ui
                .add_enabled(
                    !self.sql_busy && !self.backup_path.trim().is_empty(),
                    egui::Button::new("Create backup"),
                )
                .clicked()
            {
                match explicit_path(&self.backup_path) {
                    Ok(path) => self.operation(SqlCommand::Backup(path)),
                    Err(error) => self.error = Some(error),
                }
            }
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            ui.strong(format!("BloomRepo {}", env!("CARGO_PKG_VERSION")));
            ui.label("GUIAR OQBA | Systems Software Architect & Cyber Security Researcher");
            if ui.button("About BloomRepo").clicked() {
                self.show_about = true;
            }
        });
    }

    fn about_ui(&mut self, ctx: &egui::Context) {
        if !self.show_about {
            return;
        }
        let mut open = true;
        egui::Window::new("About BloomRepo")
            .open(&mut open)
            .collapsible(false)
            .default_width(380.0)
            .max_width(ctx.screen_rect().width() - 40.0)
            .show(ctx, |ui| {
                ui.heading(format!("BloomRepo {}", env!("CARGO_PKG_VERSION")));
                ui.label(
                    "GitHub discovery, repository monitoring and authorized local source analysis.",
                );
                ui.separator();
                ui.strong("GUIAR OQBA");
                ui.label("Systems Software Architect & Cyber Security Researcher");
                ui.horizontal_wrapped(|ui| {
                    for (label, url) in [
                        ("guiarx.com", "https://guiarx.com/"),
                        ("Business contact", "mailto:contact@guiarx.com"),
                        ("Direct contact", "mailto:hello@guiarx.com"),
                    ] {
                        if ui.link(label).clicked() {
                            if let Err(error) = webbrowser::open(url) {
                                self.error = Some(format!("Cannot open contact link: {error}"));
                            }
                        }
                    }
                });
            });
        self.show_about = open;
    }
}

impl eframe::App for RepoWatcherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|input| input.viewport().close_requested()) {
            self.stop.store(true, Ordering::Release);
            let _ = self.shutdown.send(true);
        }
        self.receive_results();
        if self.last_refresh.elapsed() > Duration::from_secs(20) && !self.snapshot_loading {
            self.snapshot_requested = true;
            self.last_refresh = Instant::now();
        }
        self.flush_requests();
        if self.stop.load(Ordering::Acquire) {
            self.status = format!("Shutting down. {IO_SHUTDOWN_WARNING}");
        }
        ctx.request_repaint_after(Duration::from_millis(100));
        let compact = ctx.screen_rect().width() < 900.0;
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                if self.scanning
                    || self.auditing
                    || self.sql_busy
                    || self.report_save.as_ref().is_some_and(ReportSave::pending)
                {
                    ui.spinner();
                }
                ui.label(RichText::new(&self.status).small().color(MUTED));
                if self.sql_busy {
                    ui.label(RichText::new(IO_SHUTDOWN_WARNING).small().color(MUTED));
                }
                if self.report_save.as_ref().is_some_and(ReportSave::pending) {
                    ui.label(
                        RichText::new("Analysis history save pending")
                            .small()
                            .color(MUTED),
                    );
                }
                if ui.small_button("About").clicked() {
                    self.show_about = true;
                }
            });
        });
        egui::SidePanel::left("navigation")
            .resizable(false)
            .exact_width(if compact { 108.0 } else { 188.0 })
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(18, 26, 38))
                    .inner_margin(if compact { 8.0 } else { 14.0 }),
            )
            .show(ctx, |ui| {
                ui.add_space(8.0);
                if let Some(icon) = &self.app_icon {
                    ui.add(egui::Image::new(icon).fit_to_exact_size(egui::vec2(24.0, 24.0)));
                }
                ui.label(
                    RichText::new("BloomRepo")
                        .strong()
                        .size(if compact { 14.0 } else { 20.0 })
                        .color(ACCENT),
                );
                if !compact {
                    ui.label(RichText::new("Repository operations").small().color(MUTED));
                }
                ui.add_space(24.0);
                ui.label(RichText::new("WORKSPACE").size(10.0).color(MUTED));
                ui.add_space(6.0);
                for workspace in Workspace::ALL {
                    if workspace == Workspace::Security || workspace == Workspace::Health {
                        ui.add_space(12.0);
                    }
                    let response = ui.add_sized(
                        [ui.available_width(), 32.0],
                        egui::SelectableLabel::new(self.workspace == workspace, workspace.title()),
                    );
                    if response.clicked() {
                        self.navigate(workspace);
                    }
                }
                ui.add_space(20.0);
                ui.separator();
                ui.label(RichText::new("GUIAR OQBA").size(10.0).color(MUTED));
                if !compact {
                    ui.label(
                        RichText::new("Architect & developer")
                            .size(10.0)
                            .color(MUTED),
                    );
                }
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_rgb(21, 29, 41))
                    .inner_margin(if compact { 12.0 } else { 24.0 }),
            )
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.heading(RichText::new(self.workspace.title()).size(26.0));
                    if ui
                        .add_enabled(!self.snapshot_loading, egui::Button::new("Refresh"))
                        .clicked()
                    {
                        self.refresh();
                    }
                });
                ui.label(RichText::new(self.workspace.subtitle()).color(MUTED));
                ui.add_space(12.0);
                egui::ScrollArea::vertical()
                    .id_salt("workspace_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if let Some(error) = self
                            .error
                            .as_ref()
                            .map(|error| redacted_message(&self.config, error))
                        {
                            card(ui, |ui| {
                                error_text(ui, &error);
                                if ui.small_button("Dismiss error").clicked() {
                                    self.error = None;
                                }
                            });
                            ui.add_space(8.0);
                        }
                        if let Some(notice) = self.notice.clone() {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new(notice).color(ACCENT));
                                if ui.small_button("Dismiss").clicked() {
                                    self.notice = None;
                                }
                            });
                            ui.add_space(8.0);
                        }
                        if self.sql_busy {
                            loading(ui, "Database operation in progress...");
                        }
                        match self.workspace {
                            Workspace::Overview => self.overview_ui(ui),
                            Workspace::Discover | Workspace::Watchlist => self.repositories_ui(ui),
                            Workspace::Security => self.security_ui(ui),
                            Workspace::Health => self.health_ui(ui),
                            Workspace::Settings => self.settings_ui(ui),
                        }
                    });
            });
        self.detail_ui(ctx);
        self.about_ui(ctx);
    }
}

fn card(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    let width = ui.available_width();
    egui::Frame::group(ui.style())
        .fill(SURFACE)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .inner_margin(12.0)
        .rounding(6.0)
        .show(ui, |ui| {
            ui.set_width((width - 26.0).max(1.0));
            contents(ui);
        });
}

fn metric(ui: &mut egui::Ui, title: &str, value: Option<usize>) {
    let remaining_on_line = ui.max_rect().right() - ui.cursor().left();
    let card_min_width = 175.0;
    if remaining_on_line < card_min_width && ui.cursor().left() > ui.max_rect().left() + 10.0 {
        ui.end_row();
    }
    egui::Frame::group(ui.style())
        .fill(SURFACE)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .inner_margin(12.0)
        .rounding(6.0)
        .show(ui, |ui| {
            ui.set_min_width(144.0);
            ui.label(RichText::new(title).small().color(MUTED));
            ui.label(
                RichText::new(
                    value
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "Pending".into()),
                )
                .size(25.0)
                .strong(),
            );
        });
}

fn loading(ui: &mut egui::Ui, message: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.spinner();
        ui.label(RichText::new(message).color(MUTED));
    });
}

fn error_text(ui: &mut egui::Ui, message: &str) {
    ui.label(RichText::new(message).color(ERROR));
}

fn timestamp(value: i64) -> String {
    if value <= 0 {
        return "Not recorded".into();
    }
    chrono::DateTime::from_timestamp(value, 0)
        .map(|date| date.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "Invalid recorded timestamp".into())
}

fn open_repository(url: &str) -> Result<(), String> {
    // Stored metadata must not launch local files or custom URL handlers.
    if !url.starts_with("https://github.com/") {
        return Err(
            "Only HTTPS GitHub repository links can be opened from stored metadata.".into(),
        );
    }
    webbrowser::open(url).map_err(|e| format!("Cannot open repository: {e}"))
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(Color32::from_rgb(220, 229, 240));
    visuals.panel_fill = Color32::from_rgb(21, 29, 41);
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = Color32::from_rgb(16, 24, 35);
    visuals.selection.bg_fill = Color32::from_rgb(35, 78, 91);
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.hyperlink_color = ACCENT;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    ctx.set_visuals(visuals);
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.wrap_mode = Some(egui::TextWrapMode::Wrap);
    ctx.set_style(style);
}

pub fn start_gui_mode(config: AppConfig, db: Database) -> Result<(), eframe::Error> {
    let (sql_tx, sql_commands) = mpsc::sync_channel(16);
    let (sql_events, sql_rx) = mpsc::sync_channel(16);
    let (scan_tx, scan_commands) = async_mpsc::channel(8);
    let (scan_events, scan_rx) = mpsc::sync_channel(8);
    let (audit_tx, audit_commands) = async_mpsc::channel(1);
    let (audit_events, audit_rx) = mpsc::sync_channel(2);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (audit_cancel, audit_cancel_rx) = watch::channel(0_u64);
    let stop = Arc::new(AtomicBool::new(false));
    let latest_query = Arc::new(AtomicU64::new(0));
    let mut workers = Workers {
        stop: stop.clone(),
        shutdown: shutdown.clone(),
        threads: Vec::new(),
    };

    let sql_db = db.clone();
    let sql_config = config.clone();
    let sql_stop = stop.clone();
    let sql_generation = latest_query.clone();
    workers.threads.push(
        std::thread::Builder::new()
            .name("bloomrepo-sql".into())
            .spawn(move || {
                sql_worker(
                    sql_db,
                    sql_config,
                    sql_commands,
                    sql_events,
                    sql_generation,
                    sql_stop,
                )
            })
            .map_err(|e| eframe::Error::AppCreation(Box::new(e)))?,
    );

    let scan_db = db;
    let scan_config = config.clone();
    let scan_stop = stop.clone();
    let scan_shutdown = shutdown_rx.clone();
    workers.threads.push(
        std::thread::Builder::new()
            .name("bloomrepo-scan".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .max_blocking_threads(2)
                    .build()
                {
                    Ok(runtime) => {
                        runtime.block_on(scan_worker(
                            scan_config,
                            scan_db,
                            scan_commands,
                            scan_events,
                            scan_shutdown,
                            scan_stop,
                        ));
                        runtime.shutdown_timeout(Duration::from_secs(2));
                    }
                    Err(error) => {
                        deliver(
                            &scan_events,
                            ScanEvent::Error(format!("Cannot start scan runtime: {error}")),
                            &scan_stop,
                        );
                    }
                }
            })
            .map_err(|e| eframe::Error::AppCreation(Box::new(e)))?,
    );

    let audit_stop = stop.clone();
    workers.threads.push(
        std::thread::Builder::new()
            .name("bloomrepo-audit".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .max_blocking_threads(2)
                    .build()
                {
                    Ok(runtime) => {
                        runtime.block_on(audit_worker(
                            audit_commands,
                            audit_events,
                            audit_cancel_rx,
                            shutdown_rx,
                            audit_stop,
                        ));
                        runtime.shutdown_timeout(Duration::from_secs(2));
                    }
                    Err(error) => {
                        deliver(
                            &audit_events,
                            AuditEvent::Error(format!("Cannot start analysis runtime: {error}")),
                            &audit_stop,
                        );
                    }
                }
            })
            .map_err(|e| eframe::Error::AppCreation(Box::new(e)))?,
    );

    let icon_data = eframe::icon_data::from_png_bytes(include_bytes!("../img/icon.png")).ok();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1180.0, 780.0])
        .with_min_inner_size([640.0, 480.0])
        .with_title("BloomRepo | Repository Operations");
    if let Some(icon) = &icon_data {
        viewport = viewport.with_icon(icon.clone());
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let result = eframe::run_native(
        "BloomRepo",
        options,
        Box::new(move |cc| {
            configure_style(&cc.egui_ctx);
            let app_icon = icon_data.map(|icon| {
                cc.egui_ctx.load_texture(
                    "bloomrepo_icon",
                    egui::ColorImage::from_rgba_unmultiplied(
                        [icon.width as usize, icon.height as usize],
                        &icon.rgba,
                    ),
                    egui::TextureOptions::LINEAR,
                )
            });
            let monitoring = config.monitoring.enabled;
            Ok(Box::new(RepoWatcherApp {
                config,
                workspace: Workspace::Overview,
                monitoring,
                engine_ready: false,
                scanning: false,
                pause_pending: false,
                status: "Starting background workers".into(),
                error: None,
                notice: None,
                stats: None,
                stats_error: None,
                health: None,
                health_error: None,
                snapshot_loading: false,
                snapshot_requested: true,
                reports: Vec::new(),
                reports_error: None,
                text: String::new(),
                priority_only: false,
                hide_forks: true,
                include_rejected: false,
                review_filter: String::new(),
                page: 0,
                has_next: false,
                repositories: Vec::new(),
                query_generation: 0,
                latest_query,
                pending_query: None,
                query_after: Instant::now(),
                query_loading: false,
                query_error: None,
                selected: None,
                detail_generation: 0,
                changes: Vec::new(),
                changes_loading: false,
                changes_error: None,
                review_choice: String::new(),
                sql_busy: false,
                audit_path: String::new(),
                authorized: false,
                osv_consent: false,
                auditing: false,
                audit_error: None,
                active_report: None,
                report_save: None,
                export_path: String::new(),
                export_format: ExportFormat::Markdown,
                backup_path: String::new(),
                re_evaluate_confirmed: false,
                show_about: false,
                app_icon,
                sql_tx,
                sql_rx,
                scan_tx,
                scan_rx,
                audit_tx,
                audit_rx,
                audit_cancel,
                shutdown,
                stop,
                last_refresh: Instant::now(),
            }))
        }),
    );
    // Also runs if native window creation fails, before any App is constructed.
    drop(workers);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Arc<AnalysisReport> {
        Arc::new(AnalysisReport {
            generated_at: "2026-10-01T00:00:00Z".into(),
            root: "authorized-test-directory".into(),
            files_scanned: 0,
            skipped: 0,
            limits: Vec::new(),
            findings: Vec::new(),
            dependencies: Vec::new(),
            coverage_gaps: Vec::new(),
            osv_requested: false,
            osv_queries: 0,
        })
    }

    #[test]
    fn shutdown_uses_one_deadline_and_does_not_forcibly_cancel_stalled_io() {
        let stop = Arc::new(AtomicBool::new(false));
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let mut releases = Vec::new();
        let mut threads = Vec::new();
        for index in 0..2 {
            let (release_tx, release_rx) = mpsc::channel::<()>();
            releases.push(release_tx);
            let started = started_tx.clone();
            let finished = finished_tx.clone();
            threads.push(
                std::thread::Builder::new()
                    .name(format!("test-stalled-io-{index}"))
                    .spawn(move || {
                        started.send(()).unwrap();
                        // A finite fallback keeps an unconditional-join regression from hanging the test suite.
                        let _ = release_rx.recv_timeout(Duration::from_secs(5));
                        finished.send(()).unwrap();
                    })
                    .unwrap(),
            );
        }
        threads.push(std::thread::spawn(|| {}));
        for _ in 0..2 {
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        let workers = Workers {
            stop: stop.clone(),
            shutdown,
            threads,
        };
        let start = Instant::now();
        drop(workers);
        let elapsed = start.elapsed();
        let completed_before_release = usize::from(finished_rx.try_recv().is_ok());
        for release in releases {
            let _ = release.send(());
        }
        for _ in completed_before_release..2 {
            finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        assert!(stop.load(Ordering::Acquire));
        assert!(*shutdown_rx.borrow());
        assert!(
            elapsed < WORKER_JOIN_TIMEOUT + Duration::from_secs(1),
            "shutdown took {elapsed:?}"
        );
        assert!(
            completed_before_release == 0,
            "stalled I/O was detached, not forcibly cancelled"
        );
    }

    #[test]
    fn report_save_status_requires_acknowledgement_and_ignores_stale_results() {
        let report = report();
        let unrelated = Arc::new((*report).clone());
        let mut save = ReportSave {
            report: report.clone(),
            state: ReportSaveState::Queued,
        };
        assert!(save.pending());
        assert!(!save.message().contains("persisted"));
        assert!(!save.finish(&report, Ok(1)));
        save.state = ReportSaveState::Saving;
        assert!(!save.finish(&unrelated, Ok(2)));
        assert!(save.pending());
        assert!(save.finish(&report, Err("database locked".into())));
        assert!(!save.pending());
        assert!(save.message().contains("not persisted: database locked"));
        save.state = ReportSaveState::Saving;
        assert!(save.finish(&report, Ok(42)));
        assert!(matches!(save.state, ReportSaveState::Saved(42)));
        assert!(!save.pending());
        assert!(save.message().contains("persisted in local history"));
        assert!(!save.finish(&report, Err("late failure".into())));
        assert!(matches!(save.state, ReportSaveState::Saved(42)));
    }

    #[test]
    fn sql_worker_reports_save_success_and_failure_with_report_identity() {
        let db = Database::new(":memory:", false).unwrap();
        let worker_db = db.clone();
        let (commands, rx) = mpsc::sync_channel(4);
        let (tx, events) = mpsc::sync_channel(4);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let report = report();
        let mut invalid = (*report).clone();
        invalid.limits = vec!["limit".into(); 101];
        let invalid = Arc::new(invalid);
        commands
            .send(SqlCommand::SaveReport(report.clone()))
            .unwrap();
        commands
            .send(SqlCommand::SaveReport(invalid.clone()))
            .unwrap();
        let thread = std::thread::spawn(move || {
            sql_worker(
                worker_db,
                AppConfig::default(),
                rx,
                tx,
                Arc::new(AtomicU64::new(0)),
                worker_stop,
            )
        });
        let saved = events.recv_timeout(Duration::from_secs(5));
        let failed = events.recv_timeout(Duration::from_secs(5));
        stop.store(true, Ordering::Release);
        drop(commands);
        thread.join().unwrap();
        assert!(
            matches!(saved, Ok(SqlEvent::ReportSaved(ref returned, Ok(id))) if Arc::ptr_eq(returned, &report) && id > 0)
        );
        assert!(
            matches!(failed, Ok(SqlEvent::ReportSaved(ref returned, Err(_))) if Arc::ptr_eq(returned, &invalid))
        );
        assert_eq!(db.analysis_reports(10).unwrap().len(), 1);
    }

    #[test]
    fn stopped_sql_worker_does_not_start_queued_report_save() {
        let db = Database::new(":memory:", false).unwrap();
        let (commands, rx) = mpsc::sync_channel(1);
        let (tx, _events) = mpsc::sync_channel(1);
        commands.send(SqlCommand::SaveReport(report())).unwrap();
        sql_worker(
            db.clone(),
            AppConfig::default(),
            rx,
            tx,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(true)),
        );
        assert!(db.analysis_reports(10).unwrap().is_empty());
    }

    #[test]
    fn stale_query_results_cannot_replace_latest_results() {
        assert!(is_current(8, 8));
        assert!(!is_current(7, 8));
        assert!(!is_current(9, 8));
        assert!(!is_current(u64::MAX, 0));
    }

    #[test]
    fn sql_worker_discards_superseded_queries() {
        let db = Database::new(":memory:", false).unwrap();
        let (commands, rx) = mpsc::sync_channel(4);
        let (tx, events) = mpsc::sync_channel(4);
        let latest = Arc::new(AtomicU64::new(2));
        let stop = Arc::new(AtomicBool::new(false));
        commands
            .send(SqlCommand::Query(
                1,
                query_for(Workspace::Discover, "", false, false, "", false, 0),
            ))
            .unwrap();
        commands
            .send(SqlCommand::Query(
                2,
                query_for(Workspace::Watchlist, "", false, false, "", false, 0),
            ))
            .unwrap();
        let worker_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            sql_worker(db, AppConfig::default(), rx, tx, latest, worker_stop)
        });
        let result = events.recv_timeout(Duration::from_secs(5));
        stop.store(true, Ordering::Release);
        drop(commands);
        thread.join().unwrap();
        assert!(matches!(result, Ok(SqlEvent::Repositories(2, Ok(_)))));
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn queued_audit_cancellation_is_not_lost() {
        let (commands, rx) = async_mpsc::channel(1);
        let (tx, events) = mpsc::sync_channel(2);
        let (_cancel, cancel_rx) = watch::channel(1_u64);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let stop = Arc::new(AtomicBool::new(false));
        commands
            .try_send(AuditCommand {
                path: PathBuf::from("must-not-be-analyzed"),
                query_osv: false,
                cancel_generation: 0,
            })
            .unwrap();
        let worker_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(audit_worker(rx, tx, cancel_rx, shutdown_rx, worker_stop));
            runtime.shutdown_timeout(Duration::from_secs(1));
        });
        let result = events.recv_timeout(Duration::from_secs(5));
        stop.store(true, Ordering::Release);
        shutdown.send(true).unwrap();
        drop(commands);
        thread.join().unwrap();
        assert!(matches!(result, Ok(AuditEvent::Cancelled)));
    }

    #[test]
    fn wrapped_stat_cards_fit_compact_and_desktop_content_widths() {
        for width in [640.0, 1180.0] {
            let ctx = egui::Context::default();
            configure_style(&ctx);
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 480.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::SidePanel::left("test_navigation").exact_width(if width < 900.0 { 108.0 } else { 188.0 }).show(ctx, |_| {});
                egui::CentralPanel::default().show(ctx, |ui| {
                    let right = ui.available_rect_before_wrap().right();
                    let metrics = ui.horizontal_wrapped(|ui| {
                        for title in ["Stored repositories", "Discovered today (UTC)", "Priority repositories", "Watched repositories"] {
                            metric(ui, title, None);
                        }
                    });
                    assert!(metrics.response.rect.right() <= right + 1.0);
                    card(ui, |ui| { ui.label("No repositories match these filters. Run a discovery cycle or adjust the query."); });
                    assert!(ui.min_rect().right() <= right + 1.0);
                });
            });
        }
    }

    #[test]
    fn configuration_errors_redact_credentials_and_destinations() {
        let mut config = AppConfig::default();
        config.auth.tokens = vec!["github-secret".into()];
        config.notifications.discord_webhook_url =
            Some("https://example.test/private-destination".into());
        config.notifications.telegram_bot_token = Some("bot-secret".into());
        config.notifications.telegram_chat_id = Some("private-chat".into());
        let message = redacted_message(
            &config,
            "github-secret bot-secret private-chat https://example.test/private-destination failed",
        );
        assert_eq!(
            message,
            "[redacted] [redacted] [redacted] [redacted] failed"
        );
    }

    #[test]
    fn query_contains_all_filters_before_pagination() {
        let query = query_for(
            Workspace::Watchlist,
            "  rust agent  ",
            true,
            true,
            "needs_review",
            true,
            3,
        );
        assert_eq!(query.text, "rust agent");
        assert!(
            query.priority_only && query.hide_forks && query.watch_only && query.include_rejected
        );
        assert_eq!(query.review_state.as_deref(), Some("needs_review"));
        assert_eq!(query.limit, PAGE_SIZE + 1);
        assert_eq!(query.offset, PAGE_SIZE * 3);
        let query = query_for(Workspace::Discover, "", false, false, "", false, usize::MAX);
        assert!(!query.watch_only);
        assert!(query.review_state.is_none());
        assert_eq!(query.offset, usize::MAX);
    }

    #[test]
    fn empty_paths_are_not_implicit_current_directory() {
        assert!(explicit_path(" \t ").is_err());
        assert_eq!(
            explicit_path(" report.md ").unwrap(),
            PathBuf::from("report.md")
        );
    }

    #[test]
    fn unknown_timestamps_do_not_imply_success() {
        assert_eq!(timestamp(0), "Not recorded");
        assert_eq!(timestamp(-1), "Not recorded");
        assert!(timestamp(1).contains("UTC"));
    }

    #[test]
    fn export_never_replaces_existing_files() {
        let path = std::env::temp_dir().join(format!(
            "bloomrepo-gui-export-{}-{}.txt",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        write_new(&path, b"original").unwrap();
        assert!(write_new(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn full_result_channel_does_not_block_shutdown() {
        let (tx, _rx) = mpsc::sync_channel(1);
        tx.send(1).unwrap();
        let stop = AtomicBool::new(true);
        assert!(!deliver(&tx, 2, &stop));
    }

    #[test]
    fn stored_links_cannot_launch_non_github_handlers() {
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://github.com.evil.test/x",
            "http://github.com/a/b",
        ] {
            assert!(open_repository(url).is_err());
        }
    }
}
