use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub streams: StreamsConfig,
    #[serde(default)]
    pub filtering: FilteringConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_max_pages")]
    pub max_pages_per_cycle: usize,
    #[serde(default = "default_lookback")]
    pub lookback_hours: i64,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_requests: usize,
    #[serde(default = "default_search_interval")]
    pub search_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub tokens: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamsConfig {
    #[serde(default = "default_true")]
    pub enable_sequential_stream: bool,
    #[serde(default = "default_true")]
    pub enable_events_stream: bool,
    #[serde(default = "default_true")]
    pub enable_search_stream: bool,
    #[serde(default)]
    pub search_queries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteringConfig {
    #[serde(default = "default_true")]
    pub enable_spam_filter: bool,
    #[serde(default = "default_true")]
    pub ignore_forks: bool,
    #[serde(default)]
    pub min_description_length: usize,
    #[serde(default)]
    pub ignore_name_patterns: Vec<String>,
    #[serde(default)]
    pub priority_keywords: Vec<String>,
    #[serde(default)]
    pub allowed_languages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_db_path")]
    pub database_path: String,
    #[serde(default = "default_state_path")]
    pub state_path: String,
    #[serde(default = "default_true")]
    pub enable_wal: bool,
    #[serde(default = "default_true")]
    pub enable_log_file: bool,
    #[serde(default = "default_true")]
    pub enable_jsonl_stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    #[serde(default = "default_true")]
    pub enable_windows_toast: bool,
    #[serde(default)]
    pub toast_priority_only: bool,
    #[serde(default = "default_notification_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_max_notification_items")]
    pub max_items_per_message: usize,
    pub discord_webhook_url: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub webhook_url: Option<String>,
}

fn default_interval() -> u64 {
    30
}
fn default_max_pages() -> usize {
    5
}
fn default_lookback() -> i64 {
    3
}
fn default_log_level() -> String {
    "info".into()
}
fn default_max_concurrent() -> usize {
    4
}
fn default_search_interval() -> u64 {
    60
}
fn default_timeout() -> u64 {
    25
}
fn default_user_agent() -> String {
    "BloomRepo/2.1 (+https://github.com/)".into()
}
fn default_true() -> bool {
    true
}
fn default_db_path() -> String {
    "repos.db".into()
}
fn default_state_path() -> String {
    "_state.json".into()
}
fn default_notification_timeout() -> u64 {
    10
}
fn default_max_notification_items() -> usize {
    5
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            interval_seconds: default_interval(),
            max_pages_per_cycle: default_max_pages(),
            lookback_hours: default_lookback(),
            log_level: default_log_level(),
            max_concurrent_requests: default_max_concurrent(),
            search_interval_seconds: default_search_interval(),
        }
    }
}
impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            tokens: vec![],
            timeout_seconds: default_timeout(),
            user_agent: default_user_agent(),
        }
    }
}
impl Default for StreamsConfig {
    fn default() -> Self {
        Self {
            enable_sequential_stream: true,
            enable_events_stream: true,
            enable_search_stream: true,
            search_queries: vec![],
        }
    }
}
impl Default for FilteringConfig {
    fn default() -> Self {
        Self {
            enable_spam_filter: true,
            ignore_forks: true,
            min_description_length: 0,
            ignore_name_patterns: vec![
                r"^auto-repo-\d+".into(),
                r"^repo-\d+$".into(),
                r"^test-\d+$".into(),
                r"^homework-".into(),
            ],
            priority_keywords: vec![],
            allowed_languages: vec![],
        }
    }
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: default_db_path(),
            state_path: default_state_path(),
            enable_wal: true,
            enable_log_file: true,
            enable_jsonl_stream: true,
        }
    }
}
impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enable_windows_toast: true,
            toast_priority_only: false,
            timeout_seconds: default_notification_timeout(),
            max_items_per_message: default_max_notification_items(),
            discord_webhook_url: None,
            telegram_bot_token: None,
            telegram_chat_id: None,
            webhook_url: None,
        }
    }
}
impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        dotenvy::dotenv().ok();
        let content = fs::read_to_string(path_ref).map_err(|source| ConfigError::Read {
            path: path_ref.display().to_string(),
            source,
        })?;
        let mut config: AppConfig = toml::from_str(&content)?;
        config.apply_environment();
        config.validate()?;
        Ok(config)
    }

    fn apply_environment(&mut self) {
        if let Ok(value) = env::var("GITHUB_TOKENS") {
            self.auth.tokens = value
                .split([',', '\n'])
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned)
                .collect();
        } else if let Ok(value) = env::var("GITHUB_TOKEN") {
            if !value.trim().is_empty() {
                self.auth.tokens = vec![value];
            }
        }
        if let Ok(value) = env::var("GITHUB_USER_AGENT") {
            self.auth.user_agent = value;
        }
        if let Some(value) = env::var("GITHUB_TIMEOUT_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
        {
            self.auth.timeout_seconds = value;
        }
        if let Ok(value) = env::var("DISCORD_WEBHOOK_URL") {
            self.notifications.discord_webhook_url = Some(value);
        }
        if let Ok(value) = env::var("TELEGRAM_BOT_TOKEN") {
            self.notifications.telegram_bot_token = Some(value);
        }
        if let Ok(value) = env::var("TELEGRAM_CHAT_ID") {
            self.notifications.telegram_chat_id = Some(value);
        }
        if let Ok(value) = env::var("WEBHOOK_URL") {
            self.notifications.webhook_url = Some(value);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.general.interval_seconds < 5 {
            return Err(ConfigError::Invalid(
                "general.interval_seconds must be at least 5".into(),
            ));
        }
        if self.general.max_pages_per_cycle == 0 || self.general.max_pages_per_cycle > 1000 {
            return Err(ConfigError::Invalid(
                "general.max_pages_per_cycle must be between 1 and 1000".into(),
            ));
        }
        if self.general.lookback_hours <= 0 || self.general.lookback_hours > 24 * 30 {
            return Err(ConfigError::Invalid(
                "general.lookback_hours must be between 1 and 720".into(),
            ));
        }
        if self.general.max_concurrent_requests == 0 || self.general.max_concurrent_requests > 32 {
            return Err(ConfigError::Invalid(
                "general.max_concurrent_requests must be between 1 and 32".into(),
            ));
        }
        if self.auth.timeout_seconds == 0 || self.auth.timeout_seconds > 300 {
            return Err(ConfigError::Invalid(
                "auth.timeout_seconds must be between 1 and 300".into(),
            ));
        }
        if self.notifications.timeout_seconds == 0 || self.notifications.timeout_seconds > 120 {
            return Err(ConfigError::Invalid(
                "notifications.timeout_seconds must be between 1 and 120".into(),
            ));
        }
        if self.notifications.telegram_bot_token.is_some()
            != self.notifications.telegram_chat_id.is_some()
        {
            return Err(ConfigError::Invalid(
                "Telegram bot token and chat ID must be configured together".into(),
            ));
        }
        for pattern in &self.filtering.ignore_name_patterns {
            regex::Regex::new(pattern).map_err(|e| {
                ConfigError::Invalid(format!(
                    "invalid ignore_name_patterns regex '{pattern}': {e}"
                ))
            })?;
        }
        Ok(())
    }
}
