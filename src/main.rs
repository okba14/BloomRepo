mod analysis;
mod config;
mod crawler;
mod db;
mod engine;
mod filter;
mod gui;
mod models;
mod notifier;
mod state;
mod tokens;
mod ui;

use config::AppConfig;
use db::{Database, RepositoryQuery};
use engine::Engine;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{error, info, level_filters::LevelFilter};

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Gui,
    Cli,
    Once,
    Stats,
    Search(String),
    RebuildFts,
    ValidateConfig,
    Health,
    Watch(String, bool),
    Review(String, String),
    Reevaluate,
    RetryNotifications,
    Backup(PathBuf),
    Analyze {
        path: PathBuf,
        osv: bool,
        report: Option<PathBuf>,
        sbom: Option<PathBuf>,
    },
    Help,
}

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    config: PathBuf,
    action: Action,
}

fn parse_arguments(args: impl IntoIterator<Item = String>) -> Result<Arguments, String> {
    let mut args = args.into_iter();
    let mut config = None;
    let mut action = None;
    let mut interface = None;
    let mut authorized = false;
    let mut osv = false;
    let mut report = None;
    let mut sbom = None;
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .filter(|value| !value.trim().is_empty() && !value.starts_with('-'))
                .ok_or_else(|| "missing command argument".to_owned())
        };
        let next = match arg.as_str() {
            "--config" => {
                if config.replace(PathBuf::from(value()?)).is_some() {
                    return Err("--config may only be specified once".into());
                }
                None
            }
            "--cli" | "--console" | "--terminal" | "--gui" => {
                if interface.replace(arg == "--gui").is_some() {
                    return Err("only one CLI or GUI selector may be specified".into());
                }
                None
            }
            "--once" => Some(Action::Once),
            "--stats" => Some(Action::Stats),
            "--search" => Some(Action::Search(value()?)),
            "--rebuild-fts" => Some(Action::RebuildFts),
            "--validate-config" => Some(Action::ValidateConfig),
            "--health" => Some(Action::Health),
            "--watch" | "--unwatch" => Some(Action::Watch(value()?, arg == "--watch")),
            "--review" => {
                let name = value()?;
                let state = value()?;
                if !matches!(
                    state.as_str(),
                    "new" | "important" | "needs_review" | "ignored" | "resolved"
                ) {
                    return Err(
                        "review state must be new, important, needs_review, ignored, or resolved"
                            .into(),
                    );
                }
                Some(Action::Review(name, state))
            }
            "--reevaluate" => Some(Action::Reevaluate),
            "--retry-notifications" => Some(Action::RetryNotifications),
            "--backup" => Some(Action::Backup(PathBuf::from(value()?))),
            "--analyze" => Some(Action::Analyze {
                path: PathBuf::from(value()?),
                osv: false,
                report: None,
                sbom: None,
            }),
            "--authorized" => {
                if authorized {
                    return Err("duplicate --authorized".into());
                }
                authorized = true;
                None
            }
            "--osv" => {
                if osv {
                    return Err("duplicate --osv".into());
                }
                osv = true;
                None
            }
            "--report" => {
                if report.replace(PathBuf::from(value()?)).is_some() {
                    return Err("duplicate --report".into());
                }
                None
            }
            "--sbom" => {
                if sbom.replace(PathBuf::from(value()?)).is_some() {
                    return Err("duplicate --sbom".into());
                }
                None
            }
            "--help" | "-h" => Some(Action::Help),
            _ => return Err("unknown command argument; use --help".into()),
        };
        if let Some(next) = next {
            if action.replace(next).is_some() {
                return Err("command actions are mutually exclusive".into());
            }
        }
    }
    let mut action = action.unwrap_or(if interface == Some(false) {
        Action::Cli
    } else {
        Action::Gui
    });
    if interface == Some(true) && action != Action::Gui {
        return Err("--gui cannot be combined with a CLI action".into());
    }
    if let Action::Analyze {
        osv: query_osv,
        report: report_path,
        sbom: sbom_path,
        ..
    } = &mut action
    {
        if !authorized {
            return Err("local analysis requires explicit --authorized consent".into());
        }
        *query_osv = osv;
        *report_path = report;
        *sbom_path = sbom;
    } else if authorized || osv || report.is_some() || sbom.is_some() {
        return Err("--authorized, --osv, --report, and --sbom require --analyze".into());
    }
    if let Action::Watch(name, _) | Action::Review(name, _) = &action {
        crawler::validate_repository_name(name)
            .map_err(|_| "repository must be a valid owner/repo name".to_owned())?;
    }
    Ok(Arguments {
        config: config.unwrap_or_else(|| "config.toml".into()),
        action,
    })
}

fn print_help() {
    println!(
        "BloomRepo 3.0\n\
Usage: bloomrepo [--config PATH] [ACTION]\n\
  --gui                         Start the GUI (default)\n\
  --cli, --console, --terminal   Run discovery continuously\n\
  --once                        Run one cycle; errors exit nonzero\n\
  --validate-config             Offline validation; no database is opened\n\
  --stats | --health             Show local statistics or operational health\n\
  --search QUERY                Search stored repositories\n\
  --rebuild-fts                  Rebuild the local search index\n\
  --watch OWNER/REPO             Watch an existing stored repository\n\
  --unwatch OWNER/REPO           Stop watching a stored repository\n\
  --review OWNER/REPO STATE      Set new/important/needs_review/ignored/resolved\n\
  --reevaluate                  Apply current rules to stored repositories\n\
  --retry-notifications         Retry failed outbox deliveries\n\
  --backup PATH                 Create a new SQLite backup; never overwrite\n\
  --analyze PATH --authorized [--osv] [--report PATH] [--sbom PATH]\n\
                                Bounded read-only local static analysis\n\
  --help                        Show this help\n\n\
Analysis never executes repository code and requires authorization. It is offline\n\
unless --osv is explicitly supplied, which sends dependency names, versions, and\n\
ecosystems to https://api.osv.dev/v1/query. Report and SBOM exports never overwrite.\n\
Credentials may be read from the environment or .env beside the selected config.\n\
Do not commit inline credentials. Config serialization omits credentials and is\n\
not a lossless configuration-save format. No AI services are used."
    );
}

fn log_level(value: &str) -> LevelFilter {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => LevelFilter::OFF,
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "warn" | "warning" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    }
}

fn reject_links(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let linked = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let linked = {
            use std::os::windows::fs::MetadataExt;
            linked || metadata.file_attributes() & 0x400 != 0
        };
        if linked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "storage paths must not traverse symbolic links or reparse points",
            ));
        }
    }
    Ok(())
}

// Keep this handle alive until every GUI/CLI worker and SQLite connection is gone.
fn lock_database(path: &Path) -> io::Result<(PathBuf, File)> {
    if path == Path::new(":memory:") || path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a filesystem database path is required",
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    reject_links(&absolute)?;
    let canonical = match fs::canonicalize(&absolute) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = absolute.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "database has no parent directory",
                )
            })?;
            let parent = fs::canonicalize(parent)?;
            if !parent.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "database parent is not a directory",
                ));
            }
            parent.join(absolute.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid database filename")
            })?)
        }
        Err(error) => return Err(error),
    };
    let mut lock_name = canonical.as_os_str().to_os_string();
    lock_name.push(".lock");
    let lock_path = PathBuf::from(lock_name);
    reject_links(&lock_path)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    match lock.try_lock() {
        Ok(()) => Ok((canonical, lock)),
        Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "database is already in use by another BloomRepo instance",
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

fn create_export(path: &Path) -> io::Result<File> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    reject_links(&absolute)?;
    let parent = absolute.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "export has no parent directory",
        )
    })?;
    if !fs::metadata(parent)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "export parent is not a directory",
        ));
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(absolute)
}

fn redacted_status(config: &AppConfig, value: &str) -> String {
    let mut value = value.to_owned();
    for secret in config.auth.tokens.iter().map(String::as_str).chain(
        [
            config.notifications.discord_webhook_url.as_deref(),
            config.notifications.telegram_bot_token.as_deref(),
            config.notifications.telegram_chat_id.as_deref(),
            config.notifications.webhook_url.as_deref(),
        ]
        .into_iter()
        .flatten(),
    ) {
        if !secret.is_empty() {
            value = value.replace(secret, "[REDACTED]");
        }
    }
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn stored_repository_id(db: &Database, name: &str) -> AppResult<i64> {
    let mut query = RepositoryQuery {
        text: name.to_owned(),
        include_rejected: true,
        limit: 200,
        ..Default::default()
    };
    loop {
        let records = db.list_repositories(&query)?;
        if let Some(record) = records
            .iter()
            .find(|record| record.repo.full_name.eq_ignore_ascii_case(name))
        {
            return Ok(record.repo.id);
        }
        if records.len() < query.limit {
            break;
        }
        query.offset += records.len();
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "repository is not stored locally; no remote lookup was attempted",
    )
    .into())
}

fn main() -> AppResult<()> {
    let raw_args = env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command arguments must contain valid Unicode",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let args = parse_arguments(raw_args)
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    if args.action == Action::Help {
        print_help();
        return Ok(());
    }
    let mut config = AppConfig::load_from_file(&args.config)?;
    if args.action == Action::ValidateConfig {
        println!("Configuration is valid. Offline validation only; no database opened or destinations contacted.");
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_max_level(log_level(&config.general.log_level))
        .init();
    reject_links(&env::current_dir()?.join(&config.storage.state_path))?;
    let (database_path, _instance_lock) = lock_database(Path::new(&config.storage.database_path))?;
    config.storage.database_path = database_path
        .to_str()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "database path must contain valid Unicode",
            )
        })?
        .to_owned();
    let db = Database::new(&database_path, config.storage.enable_wal)?;
    match args.action {
        Action::RebuildFts => {
            db.rebuild_index()?;
            println!("FTS5 index rebuilt successfully.");
        }
        Action::Stats => {
            let (total, today, priority) = db.get_stats()?;
            ui::UI::print_stats(total, today, priority, &config.storage.database_path);
        }
        Action::Search(query) => {
            for repo in db.search(&query, 50)? {
                println!(
                    "{} - {}\n  {}",
                    redacted_status(&config, &repo.full_name),
                    redacted_status(
                        &config,
                        repo.description.as_deref().unwrap_or("No description")
                    ),
                    redacted_status(&config, &repo.html_url)
                );
            }
        }
        Action::Health => {
            let health = db.operational_health()?;
            println!("Repositories: {} watched, {} rejected; observations: {}\nNotifications: {} pending, {} failed",
                health.watched_repositories, health.rejected_repositories, health.observations,
                health.pending_notifications, health.failed_notifications);
            if health.sources.is_empty() {
                println!("No source health observations recorded yet.");
            }
            for source in health.sources {
                println!(
                    "{}: {} (last success: {}, next allowed: {})\n  {}",
                    redacted_status(&config, &source.name),
                    redacted_status(&config, &source.status),
                    source.last_success_at,
                    source.next_allowed_at,
                    redacted_status(&config, &source.message)
                );
            }
        }
        Action::Watch(name, watched) => {
            db.set_watched(stored_repository_id(&db, &name)?, watched)?;
            println!("{name}: watched={watched}");
        }
        Action::Review(name, state) => {
            db.set_review_state(stored_repository_id(&db, &name)?, &state)?;
            println!("{name}: review state={state}");
        }
        Action::Reevaluate => {
            let count = db.re_evaluate(&filter::RepoFilter::new(config.filtering.clone()))?;
            println!("Re-evaluated {count} stored repositories.");
        }
        Action::Backup(path) => {
            reject_links(&path)?;
            db.backup_to(&path)?;
            println!("Database backup created.");
        }
        Action::Gui => return gui::start_gui_mode(config, db).map_err(|error| error.into()),
        action @ (Action::Cli
        | Action::Once
        | Action::RetryNotifications
        | Action::Analyze { .. }) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                tokio::select! {
                    biased;
                    signal = tokio::signal::ctrl_c() => {
                        signal?;
                        println!("Shutdown received; cancelled pending work. Committed database transactions are retained.");
                        Err::<(), Box<dyn std::error::Error>>(io::Error::new(io::ErrorKind::Interrupted, "operation interrupted").into())
                    }
                    result = run_async_action(config, db, action) => result,
                }
            })?;
        }
        Action::ValidateConfig | Action::Help => unreachable!(),
    }
    Ok(())
}

async fn run_async_action(config: AppConfig, db: Database, action: Action) -> AppResult<()> {
    if let Action::Analyze {
        path,
        osv,
        report,
        sbom,
    } = action
    {
        // Reserve outputs before scanning or disclosure; create_new also rejects aliases.
        let mut report_file = report.as_deref().map(create_export).transpose()?;
        let mut sbom_file = sbom.as_deref().map(create_export).transpose()?;
        if osv {
            println!("OSV explicitly enabled: dependency names, versions, and ecosystems will be sent to https://api.osv.dev/v1/query. No source contents are sent.");
        } else {
            println!(
                "Authorized local static analysis; offline, without executing repository code."
            );
        }
        let analysis = analysis::analyze_directory(&path, osv)
            .await
            .map_err(io::Error::other)?;
        let id = db.save_analysis_report(&analysis)?;
        if let Some(file) = &mut report_file {
            file.write_all(analysis.markdown().as_bytes())?;
            file.sync_all()?;
        }
        if let Some(file) = &mut sbom_file {
            serde_json::to_writer_pretty(&mut *file, &analysis.sbom_json())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        println!("Saved analysis report #{id}: {} files, {} findings, {} dependencies. Static analysis is not proof of safety.",
            analysis.files_scanned, analysis.findings.len(), analysis.dependencies.len());
        return Ok(());
    }
    let interval = config.general.interval_seconds;
    let is_once = action == Action::Once;
    let mut engine = Engine::new(config, db)?;
    if action == Action::RetryNotifications {
        let queued = engine.db.retry_failed_notifications()?;
        let delivered = engine.dispatch_outbox().await?;
        println!("Queued {queued} failed notifications; delivered {delivered} outbox messages.");
        return Ok(());
    }
    if !is_once {
        engine.start_dispatcher();
    }
    loop {
        match engine.run_cycle().await {
            Ok(result) => {
                if is_once {
                    let delivered = engine.dispatch_outbox().await?;
                    info!(delivered, "one-shot outbox delivery pass completed; remaining events stay durable");
                }
                for repo in &result.items {
                    ui::UI::print_discovered_repo(repo);
                }
                ui::UI::print_cycle_summary(
                    result.cycle,
                    result.items.len(),
                    result.priority_count,
                    result.spam_count,
                    result.duration_ms,
                    result.db_total,
                );
                if !result.status.is_empty() {
                    info!(cycle = result.cycle, status = %redacted_status(&engine.config, &result.status), "cycle status");
                }
            }
            Err(err) if is_once => return Err(err.into()),
            Err(err) => {
                error!(error = %redacted_status(&engine.config, &err.to_string()), "cycle failed; consult persisted source health")
            }
        }
        if is_once {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn parse(args: &[&str]) -> Result<Arguments, String> {
        parse_arguments(args.iter().map(|arg| (*arg).to_owned()))
    }

    fn temp_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        env::temp_dir().join(format!(
            "bloomrepo-cli-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn parser_preserves_modes_aliases_and_config() {
        assert_eq!(parse(&[]).unwrap().action, Action::Gui);
        for alias in ["--cli", "--console", "--terminal"] {
            assert_eq!(parse(&[alias]).unwrap().action, Action::Cli);
            assert_eq!(parse(&[alias, "--once"]).unwrap().action, Action::Once);
        }
        assert_eq!(
            parse(&["--config", "other.toml", "--validate-config"]).unwrap(),
            Arguments {
                config: "other.toml".into(),
                action: Action::ValidateConfig
            }
        );
        assert_eq!(
            parse(&["--search", "rust tool"]).unwrap().action,
            Action::Search("rust tool".into())
        );
    }

    #[test]
    fn parser_rejects_unknown_missing_duplicate_and_conflicting_arguments() {
        for args in [
            vec!["--unknown"],
            vec!["unexpected"],
            vec!["--config"],
            vec!["--search"],
            vec!["--search", "--stats"],
            vec!["--once", "--stats"],
            vec!["--gui", "--once"],
            vec!["--gui", "--cli"],
            vec!["--once", "--once"],
            vec!["--review", "owner/repo"],
            vec!["--review", "owner/repo", "unsafe"],
            vec!["--watch", "../repo"],
            vec!["--config", "a", "--config", "b"],
            vec!["--authorized"],
            vec!["--osv"],
            vec!["--report", "out.md"],
            vec!["--analyze", "somewhere"],
        ] {
            assert!(parse(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn analysis_requires_consent_and_osv_is_opt_in() {
        let local = parse(&["--analyze", "somewhere", "--authorized"]).unwrap();
        assert!(matches!(local.action, Action::Analyze { osv: false, .. }));
        let online = parse(&[
            "--authorized",
            "--osv",
            "--analyze",
            "somewhere",
            "--report",
            "out.md",
            "--sbom",
            "out.json",
        ])
        .unwrap();
        assert_eq!(
            online.action,
            Action::Analyze {
                path: "somewhere".into(),
                osv: true,
                report: Some("out.md".into()),
                sbom: Some("out.json".into()),
            }
        );
    }

    #[test]
    fn database_lock_is_exclusive_released_and_path_normalized() {
        let path = temp_path("database");
        let (canonical, lock) = lock_database(&path).unwrap();
        assert_eq!(
            lock_database(&path).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            lock_database(&canonical).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let probe = |expected: &str| {
            std::process::Command::new(env::current_exe().unwrap())
                .args(["--exact", "tests::database_lock_process_probe", "--ignored"])
                .env("BLOOMREPO_LOCK_TEST_PATH", &path)
                .env("BLOOMREPO_LOCK_TEST_EXPECTED", expected)
                .status()
                .unwrap()
                .success()
        };
        assert!(probe("blocked"));
        drop(lock);
        assert!(probe("available"));
        let (_, lock) = lock_database(&path).unwrap();
        drop(lock);
        let mut name = canonical.into_os_string();
        name.push(".lock");
        fs::remove_file(PathBuf::from(name)).unwrap();
        assert!(lock_database(&temp_path("missing-parent").join("db.sqlite")).is_err());
    }

    #[test]
    #[ignore = "child-process probe invoked by the lock test"]
    fn database_lock_process_probe() {
        let path = env::var_os("BLOOMREPO_LOCK_TEST_PATH").expect("probe path");
        match env::var("BLOOMREPO_LOCK_TEST_EXPECTED").unwrap().as_str() {
            "blocked" => assert_eq!(
                lock_database(Path::new(&path)).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            ),
            "available" => {
                let _lock = lock_database(Path::new(&path)).unwrap();
            }
            _ => panic!("invalid probe expectation"),
        }
    }

    #[test]
    fn exports_are_new_only_and_synced() {
        let path = temp_path("export");
        let mut file = create_export(&path).unwrap();
        file.write_all(b"original").unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            create_export(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"original");
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn operational_messages_redact_credentials_and_terminal_controls() {
        let mut config = AppConfig::default();
        config.auth.tokens.push("private-token".into());
        config.notifications.webhook_url = Some("https://example.com/private-url".into());
        let message = redacted_status(
            &config,
            "private-token https://example.com/private-url\u{1b}[31m",
        );
        assert!(!message.contains("private-token"));
        assert!(!message.contains("private-url"));
        assert!(!message.contains('\u{1b}'));
    }
}
