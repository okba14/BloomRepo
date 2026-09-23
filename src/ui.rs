use crate::models::RepoItem;
use colored::*;

pub struct UI;

impl UI {
    pub fn print_discovered_repo(repo: &RepoItem) {
        let now = chrono::Local::now().format("%H:%M:%S");
        let prefix = if repo.is_priority {
            "🔥 [PRIORITY]".bold().bright_red()
        } else if repo.fork {
            "🍴 [FORK]    ".bright_yellow()
        } else {
            "✨ [NEW]     ".bright_green()
        };

        let lang = repo.language.as_deref().unwrap_or("General");
        let desc = repo.description.as_deref().unwrap_or("No description");
        let short_desc: String = desc.chars().take(80).collect();

        println!(
            "[{}] {} {} ({}) - {}\n            {}",
            now.to_string().bright_black(),
            prefix,
            repo.full_name.bold().bright_white(),
            lang.bright_cyan(),
            short_desc.dimmed(),
            repo.html_url.bright_blue().underline()
        );
    }

    pub fn print_cycle_summary(
        cycle: u64,
        new_count: usize,
        priority_count: usize,
        dropped_spam: usize,
        duration_ms: u128,
        db_total: usize,
    ) {
        println!(
            "{} Cycle #{} Finished | Discovered: {} new ({} priority) | Filtered: {} spam | Duration: {}ms | DB Total: {}",
            "✔".bold().bright_green(),
            cycle,
            new_count.to_string().bold().bright_green(),
            priority_count.to_string().bold().bright_red(),
            dropped_spam.to_string().bright_yellow(),
            duration_ms,
            db_total.to_string().bold().bright_white()
        );
    }

    pub fn print_stats(total: usize, today: usize, priority: usize, db_path: &str) {
        println!(
            "\n{}",
            "📊 BloomRepo - Database Statistics".bold().bright_cyan()
        );
        println!(
            "{}",
            "=================================================".bright_cyan()
        );
        println!("  Database File     : {}", db_path.bright_white());
        println!(
            "  Total Repositories: {}",
            total.to_string().bold().bright_green()
        );
        println!(
            "  Discovered Today  : {}",
            today.to_string().bold().bright_yellow()
        );
        println!(
            "  Priority Matches  : {}",
            priority.to_string().bold().bright_red()
        );
        println!(
            "{}\n",
            "=================================================".bright_cyan()
        );
    }
}
