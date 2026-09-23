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
use db::Database;
use engine::Engine;
use std::env;
use std::time::Duration;
use tracing::{error, info, level_filters::LevelFilter};

fn log_level(value: &str) -> LevelFilter {
    match value.trim().to_ascii_lowercase().as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "warn" | "warning" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_once = args.iter().any(|a| a == "--once");
    let is_stats = args.iter().any(|a| a == "--stats");
    let is_cli = args
        .iter()
        .any(|a| matches!(a.as_str(), "--cli" | "--console" | "--terminal"));
    let is_gui = args.iter().any(|a| a == "--gui");
    let config_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|idx| args.get(idx + 1))
        .map(String::as_str)
        .unwrap_or("config.toml");
    let config = AppConfig::load_from_file(config_path)?;
    tracing_subscriber::fmt()
        .with_max_level(log_level(&config.general.log_level))
        .init();
    let db = Database::new(&config.storage.database_path, config.storage.enable_wal)?;

    let is_rebuild_fts = args.iter().any(|a| a == "--rebuild-fts");

    if is_rebuild_fts {
        println!("Rebuilding FTS5 full-text index...");
        db.rebuild_index()?;
        println!("FTS5 index rebuilt successfully.");
        return Ok(());
    }

    if is_stats {
        let (total, today, priority) = db.get_stats()?;
        ui::UI::print_stats(total, today, priority, &config.storage.database_path);
        return Ok(());
    }
    if let Some(pos) = args.iter().position(|a| a == "--search") {
        if let Some(query) = args.get(pos + 1) {
            for repo in db.search(query, 50)? {
                println!(
                    "{} - {}\n  {}",
                    repo.full_name,
                    repo.description.as_deref().unwrap_or("No description"),
                    repo.html_url
                );
            }
        }
        return Ok(());
    }
    let should_run_gui = (is_gui || (!is_cli && !is_once)) && !is_stats;
    if should_run_gui {
        return gui::start_gui_mode(config, db).map_err(|e| e.into());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_cli(config, db, is_once))
}

async fn run_cli(
    config: AppConfig,
    db: Database,
    is_once: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let interval = config.general.interval_seconds;
    let mut engine = Engine::new(config, db);
    let mut cycle = 0u64;
    loop {
        cycle += 1;
        match engine.run_cycle().await {
            Ok(result) => {
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
                    info!(cycle, status=%result.status, "cycle status");
                }
            }
            Err(err) => error!(cycle, error=%err, "cycle failed; state was not committed"),
        }
        if is_once {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {},
            _ = tokio::signal::ctrl_c() => { println!("Graceful shutdown received."); break; }
        }
    }
    Ok(())
}
