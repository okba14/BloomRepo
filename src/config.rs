use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fmt;
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
    // TOML errors contain source snippets, which may include credentials.
    #[error("invalid TOML configuration; check the file syntax and field types")]
    Parse,
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
    #[serde(default)]
    pub monitoring: MonitoringConfig,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default, skip_serializing)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    #[serde(default = "default_true")]
    pub enable_windows_toast: bool,
    #[serde(default)]
    pub toast_priority_only: bool,
    #[serde(default = "default_notification_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_max_notification_items")]
    pub max_items_per_message: usize,
    #[serde(default, skip_serializing)]
    pub discord_webhook_url: Option<String>,
    #[serde(default, skip_serializing)]
    pub telegram_bot_token: Option<String>,
    #[serde(default, skip_serializing)]
    pub telegram_chat_id: Option<String>,
    #[serde(default, skip_serializing)]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub watch_interval_seconds: u64,
    pub enrich_per_cycle: usize,
    pub watch_per_cycle: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_interval_seconds: 900,
            enrich_per_cycle: 10,
            watch_per_cycle: 10,
        }
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("tokens", &"[REDACTED]")
            .field("token_count", &self.tokens.len())
            .field("timeout_seconds", &self.timeout_seconds)
            .field("user_agent", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for NotificationsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationsConfig")
            .field("enable_windows_toast", &self.enable_windows_toast)
            .field("toast_priority_only", &self.toast_priority_only)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("max_items_per_message", &self.max_items_per_message)
            .field("discord_configured", &self.discord_webhook_url.is_some())
            .field("telegram_configured", &self.telegram_bot_token.is_some())
            .field("webhook_configured", &self.webhook_url.is_some())
            .finish()
    }
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
    "BloomRepo/3.0 (+https://github.com/)".into()
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
        let content = fs::read_to_string(path_ref).map_err(|source| ConfigError::Read {
            path: path_ref.display().to_string(),
            source,
        })?;
        let mut config: AppConfig = toml::from_str(&content).map_err(|_| ConfigError::Parse)?;
        let dotenv_path = path_ref.parent().unwrap_or(Path::new(".")).join(".env");
        let mut dotenv = HashMap::new();
        match dotenvy::from_path_iter(&dotenv_path) {
            Ok(values) => {
                for value in values {
                    let (key, value) = value.map_err(|_| {
                        ConfigError::Invalid("invalid .env file beside the configuration".into())
                    })?;
                    dotenv.entry(key).or_insert(value);
                }
            }
            Err(dotenvy::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(ConfigError::Invalid(
                    "cannot read .env file beside the configuration".into(),
                ));
            }
        }
        // Do not mutate the process environment or discover another project's .env.
        config.apply_environment(&dotenv, |key| match env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => Err(ConfigError::Invalid(format!(
                "environment variable {key} must contain valid Unicode"
            ))),
        })?;
        config.validate()?;
        Ok(config)
    }

    fn apply_environment(
        &mut self,
        dotenv: &HashMap<String, String>,
        mut environment: impl FnMut(&str) -> Result<Option<String>, ConfigError>,
    ) -> Result<(), ConfigError> {
        // The process wins as a layer, including singular vs plural token aliases.
        let plural = environment("GITHUB_TOKENS")?;
        let singular = if plural.is_none() {
            environment("GITHUB_TOKEN")?
        } else {
            None
        };
        let (plural, singular) = if plural.is_some() || singular.is_some() {
            (plural, singular)
        } else {
            (
                dotenv.get("GITHUB_TOKENS").cloned(),
                dotenv.get("GITHUB_TOKEN").cloned(),
            )
        };
        if let Some(value) = plural {
            if value
                .bytes()
                .any(|byte| byte.is_ascii_control() && byte != b'\n')
            {
                return Err(ConfigError::Invalid(
                    "GITHUB_TOKENS contains an invalid HTTP credential; use comma or newline separators"
                        .into(),
                ));
            }
            self.auth.tokens = value
                .split([',', '\n'])
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned)
                .collect();
        } else if let Some(value) = singular {
            self.auth.tokens = if value.trim().is_empty() {
                vec![]
            } else {
                vec![value]
            };
        }
        let mut value_for = |key: &str| -> Result<Option<String>, ConfigError> {
            Ok(environment(key)?.or_else(|| dotenv.get(key).cloned()))
        };
        if let Some(value) = value_for("GITHUB_USER_AGENT")? {
            self.auth.user_agent = value;
        }
        if let Some(value) = value_for("GITHUB_TIMEOUT_SECONDS")? {
            self.auth.timeout_seconds = value.parse().map_err(|_| {
                ConfigError::Invalid("GITHUB_TIMEOUT_SECONDS must be an integer".into())
            })?;
        }
        for (key, destination) in [
            (
                "DISCORD_WEBHOOK_URL",
                &mut self.notifications.discord_webhook_url,
            ),
            (
                "TELEGRAM_BOT_TOKEN",
                &mut self.notifications.telegram_bot_token,
            ),
            ("TELEGRAM_CHAT_ID", &mut self.notifications.telegram_chat_id),
            ("WEBHOOK_URL", &mut self.notifications.webhook_url),
        ] {
            if let Some(value) = value_for(key)? {
                *destination = (!value.trim().is_empty()).then_some(value);
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(5..=86_400).contains(&self.general.interval_seconds) {
            return Err(ConfigError::Invalid(
                "general.interval_seconds must be between 5 and 86400".into(),
            ));
        }
        if !(5..=86_400).contains(&self.general.search_interval_seconds) {
            return Err(ConfigError::Invalid(
                "general.search_interval_seconds must be between 5 and 86400".into(),
            ));
        }
        if !matches!(
            self.general.log_level.trim().to_ascii_lowercase().as_str(),
            "off" | "trace" | "debug" | "info" | "warn" | "warning" | "error"
        ) {
            return Err(ConfigError::Invalid(
                "general.log_level is not a supported level".into(),
            ));
        }
        if !(5..=86_400).contains(&self.monitoring.watch_interval_seconds) {
            return Err(ConfigError::Invalid(
                "monitoring.watch_interval_seconds must be between 5 and 86400".into(),
            ));
        }
        if !(1..=100).contains(&self.monitoring.enrich_per_cycle)
            || !(1..=100).contains(&self.monitoring.watch_per_cycle)
        {
            return Err(ConfigError::Invalid(
                "monitoring per-cycle limits must be between 1 and 100".into(),
            ));
        }
        if self.general.max_pages_per_cycle == 0 || self.general.max_pages_per_cycle > 40 {
            return Err(ConfigError::Invalid(
                "general.max_pages_per_cycle must be between 1 and 40".into(),
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
        if !(1..=10).contains(&self.notifications.max_items_per_message) {
            return Err(ConfigError::Invalid(
                "notifications.max_items_per_message must be between 1 and 10".into(),
            ));
        }
        for token in &self.auth.tokens {
            if token.is_empty()
                || !token.bytes().all(|byte| byte.is_ascii_graphic())
                || reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).is_err()
            {
                return Err(ConfigError::Invalid(
                    "auth.tokens contains an invalid HTTP credential".into(),
                ));
            }
        }
        if self.auth.user_agent.is_empty()
            || self
                .auth
                .user_agent
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || reqwest::header::HeaderValue::from_str(&self.auth.user_agent).is_err()
        {
            return Err(ConfigError::Invalid(
                "auth.user_agent is not a valid HTTP header".into(),
            ));
        }
        for destination in [
            self.notifications.discord_webhook_url.as_deref(),
            self.notifications.webhook_url.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            crate::notifier::validate_destination(destination).map_err(|_| {
                ConfigError::Invalid("notification destination must be a public HTTPS URL without credentials or a fragment".into())
            })?;
        }
        if let Some(token) = &self.notifications.telegram_bot_token {
            let valid = token.split_once(':').is_some_and(|(id, secret)| {
                !id.is_empty()
                    && id.bytes().all(|byte| byte.is_ascii_digit())
                    && !secret.is_empty()
                    && secret
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            });
            if token.len() > 256 || !valid {
                return Err(ConfigError::Invalid(
                    "invalid Telegram bot credential".into(),
                ));
            }
        }
        if let Some(chat) = &self.notifications.telegram_chat_id {
            if chat.is_empty()
                || chat.len() > 200
                || !chat.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(ConfigError::Invalid("invalid Telegram chat ID".into()));
            }
        }
        if self.notifications.telegram_bot_token.is_some()
            != self.notifications.telegram_chat_id.is_some()
        {
            return Err(ConfigError::Invalid(
                "Telegram bot token and chat ID must be configured together".into(),
            ));
        }
        for pattern in &self.filtering.ignore_name_patterns {
            regex::Regex::new(pattern).map_err(|_| {
                ConfigError::Invalid("invalid filtering.ignore_name_patterns regex".into())
            })?;
        }
        if self.storage.database_path.trim().is_empty() || self.storage.state_path.trim().is_empty()
        {
            return Err(ConfigError::Invalid(
                "storage paths must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(
        config: &mut AppConfig,
        dotenv: &[(&str, &str)],
        process: &[(&str, &str)],
    ) -> Result<(), ConfigError> {
        let dotenv = dotenv
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        config.apply_environment(&dotenv, |key| {
            Ok(process
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned()))
        })
    }

    #[test]
    fn monitoring_defaults_apply_to_missing_and_partial_sections() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert!(config.monitoring.enabled);
        assert_eq!(config.monitoring.watch_interval_seconds, 900);
        assert_eq!(config.monitoring.enrich_per_cycle, 10);
        assert_eq!(config.monitoring.watch_per_cycle, 10);
        let config: AppConfig = toml::from_str("[monitoring]\nenabled = false").unwrap();
        assert!(!config.monitoring.enabled);
        assert_eq!(config.monitoring.watch_interval_seconds, 900);
        config.validate().unwrap();
    }

    #[test]
    fn debug_and_serialization_do_not_expose_credentials() {
        let mut config = AppConfig::default();
        config.auth.tokens = vec!["github-private-value".into()];
        config.notifications.discord_webhook_url =
            Some("https://discord.com/api/webhooks/1/discord-private-value".into());
        config.notifications.telegram_bot_token = Some("123:telegram-private-value".into());
        config.notifications.telegram_chat_id = Some("chat-private-value".into());
        config.notifications.webhook_url =
            Some("https://example.com/hook?key=webhook-private-value".into());
        for output in [
            format!("{config:?}"),
            serde_json::to_string(&config).unwrap(),
            toml::to_string(&config).unwrap(),
        ] {
            for secret in [
                "github-private-value",
                "discord-private-value",
                "telegram-private-value",
                "chat-private-value",
                "webhook-private-value",
            ] {
                assert!(!output.contains(secret));
            }
        }
        let serialized = serde_json::to_value(&config).unwrap();
        assert!(serialized["auth"].get("tokens").is_none());
        assert!(serialized["notifications"].get("webhook_url").is_none());
    }

    #[test]
    fn process_environment_overrides_dotenv_and_inline_values() {
        let mut config = AppConfig::default();
        config.auth.tokens = vec!["inline".into()];
        apply(
            &mut config,
            &[("GITHUB_TOKENS", "dotenv-a,dotenv-b")],
            &[("GITHUB_TOKEN", "process")],
        )
        .unwrap();
        assert_eq!(config.auth.tokens, ["process"]);
        apply(
            &mut config,
            &[("GITHUB_TOKEN", "dotenv")],
            &[
                ("GITHUB_TOKENS", "first, second"),
                ("GITHUB_TOKEN", "ignored"),
            ],
        )
        .unwrap();
        assert_eq!(config.auth.tokens, ["first", "second"]);
        apply(
            &mut config,
            &[("GITHUB_TOKENS", "dotenv")],
            &[("GITHUB_TOKEN", "")],
        )
        .unwrap();
        assert!(config.auth.tokens.is_empty());
        apply(&mut config, &[("GITHUB_TOKEN", "dotenv")], &[]).unwrap();
        assert_eq!(config.auth.tokens, ["dotenv"]);
    }

    #[test]
    fn empty_environment_disables_inline_notification_destinations() {
        let mut config = AppConfig::default();
        config.notifications.discord_webhook_url = Some("https://example.com/inline".into());
        config.notifications.webhook_url = Some("https://example.com/inline".into());
        config.notifications.telegram_bot_token = Some("123:token".into());
        config.notifications.telegram_chat_id = Some("123".into());
        apply(
            &mut config,
            &[("WEBHOOK_URL", "https://example.com/dotenv")],
            &[
                ("DISCORD_WEBHOOK_URL", ""),
                ("WEBHOOK_URL", "  "),
                ("TELEGRAM_BOT_TOKEN", ""),
                ("TELEGRAM_CHAT_ID", ""),
            ],
        )
        .unwrap();
        assert!(config.notifications.discord_webhook_url.is_none());
        assert!(config.notifications.webhook_url.is_none());
        assert!(config.notifications.telegram_bot_token.is_none());
        assert!(config.notifications.telegram_chat_id.is_none());
        config.validate().unwrap();
    }

    #[test]
    fn header_and_destination_errors_are_redacted() {
        for token in [
            "secret\r\nInjected: true",
            "secret\0",
            "secret\tvalue",
            "",
            "non-ascii-\u{00e9}",
        ] {
            let mut config = AppConfig::default();
            config.auth.tokens = vec![token.into()];
            let error = config.validate().unwrap_err();
            assert!(!error.to_string().contains("secret"));
            assert!(!format!("{error:?}").contains("Injected"));
        }
        for destination in [
            "http://example.com/secret",
            "https://user:secret@example.com/",
            "https://127.0.0.1/secret",
            "https://localhost/secret",
            "https://example.com/secret#fragment",
        ] {
            let mut config = AppConfig::default();
            config.notifications.webhook_url = Some(destination.into());
            let error = config.validate().unwrap_err();
            assert!(!error.to_string().contains("secret"));
            assert!(!format!("{error:?}").contains(destination));
        }
        let mut config = AppConfig::default();
        config.auth.user_agent = "secret\r\nInjected: true".into();
        assert!(!config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("secret"));
        config.auth.user_agent = default_user_agent();
        config.notifications.webhook_url = Some("https://example.com/secret".into());
        config.validate().unwrap();
    }

    #[test]
    fn unsafe_bounds_and_invalid_environment_values_fail() {
        let mut config = AppConfig::default();
        config.general.interval_seconds = u64::MAX;
        assert!(config.validate().is_err());
        config.general.interval_seconds = 30;
        config.general.search_interval_seconds = 0;
        assert!(config.validate().is_err());
        config.general.search_interval_seconds = 60;
        config.general.log_level = "misspelled".into();
        assert!(config.validate().is_err());
        config.general.log_level = "info".into();
        config.monitoring.watch_interval_seconds = u64::MAX;
        assert!(config.validate().is_err());
        config.monitoring.watch_interval_seconds = 900;
        config.monitoring.enrich_per_cycle = 0;
        assert!(config.validate().is_err());
        config.monitoring.enrich_per_cycle = 10;
        config.monitoring.watch_per_cycle = 101;
        assert!(config.validate().is_err());
        config.monitoring.watch_per_cycle = 10;
        for count in [0, 11, usize::MAX] {
            config.notifications.max_items_per_message = count;
            assert!(config.validate().is_err());
        }
        config.notifications.max_items_per_message = 10;
        config.validate().unwrap();
        let error = apply(&mut config, &[], &[("GITHUB_TIMEOUT_SECONDS", "secret")]).unwrap_err();
        assert!(!format!("{error:?}").contains("secret"));
        assert!(apply(
            &mut config,
            &[],
            &[("GITHUB_TOKENS", "secret\r\nInjected: true")]
        )
        .is_err());
    }

    #[test]
    fn parse_error_never_retains_toml_source_snippets() {
        let path = env::temp_dir().join(format!(
            "bloomrepo-config-invalid-{}.toml",
            std::process::id()
        ));
        fs::write(&path, "[auth]\ntokens = [\"do-not-echo-secret\"").unwrap();
        let error = AppConfig::load_from_file(&path).unwrap_err();
        assert!(matches!(error, ConfigError::Parse));
        assert!(!format!("{error:?}").contains("do-not-echo-secret"));
        assert!(!error.to_string().contains("do-not-echo-secret"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn dotenv_is_only_read_beside_selected_config_without_environment_mutation() {
        let root = env::temp_dir().join(format!("bloomrepo-dotenv-{}", std::process::id()));
        let child = root.join("selected");
        fs::create_dir_all(&child).unwrap();
        fs::write(root.join(".env"), "not a valid dotenv assignment!").unwrap();
        let config_path = child.join("config.toml");
        fs::write(&config_path, "").unwrap();
        let key = format!("BLOOMREPO_DOTENV_TEST_{}", std::process::id());
        let before = env::var_os(&key);
        fs::write(child.join(".env"), format!("{key}=test-only-marker\n")).unwrap();
        AppConfig::load_from_file(&config_path).unwrap();
        assert_eq!(env::var_os(&key), before);
        fs::write(child.join(".env"), "not a valid dotenv assignment!").unwrap();
        let error = AppConfig::load_from_file(&config_path).unwrap_err();
        assert!(error.to_string().contains(".env"));
        assert!(!format!("{error:?}").contains("not a valid"));
        fs::remove_dir_all(root).unwrap();
    }
}
