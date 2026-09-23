use crate::config::NotificationsConfig;
use crate::models::RepoItem;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("notification request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("notification service returned {0}")]
    Status(reqwest::StatusCode),
}

pub struct Notifier {
    config: NotificationsConfig,
    http_client: Client,
}

impl Notifier {
    pub fn new(config: NotificationsConfig) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            config,
            http_client,
        }
    }

    pub async fn notify(&self, repos: &[RepoItem]) -> Vec<String> {
        if repos.is_empty() {
            return vec![];
        }
        let selected: Vec<&RepoItem> = if self.config.toast_priority_only {
            repos.iter().filter(|r| r.is_priority).collect()
        } else {
            repos.iter().collect()
        };
        if selected.is_empty() {
            return vec![];
        }
        let mut errors = Vec::new();
        #[cfg(windows)]
        if self.config.enable_windows_toast {
            show_windows_toast(&selected);
        }
        if let Some(url) = &self.config.discord_webhook_url {
            if let Err(err) = self.send_discord(url, &selected).await {
                errors.push(format!("discord: {err}"));
            }
        }
        if let (Some(token), Some(chat_id)) = (
            &self.config.telegram_bot_token,
            &self.config.telegram_chat_id,
        ) {
            if let Err(err) = self.send_telegram(token, chat_id, &selected).await {
                errors.push(format!("telegram: {err}"));
            }
        }
        if let Some(url) = &self.config.webhook_url {
            if let Err(err) = self.send_custom(url, &selected).await {
                errors.push(format!("webhook: {err}"));
            }
        }
        errors
    }

    async fn send_discord(&self, url: &str, repos: &[&RepoItem]) -> Result<(), NotifyError> {
        let embeds: Vec<_> = repos.iter().take(self.config.max_items_per_message).map(|repo| json!({
            "title": repo.full_name,
            "url": repo.html_url,
            "description": repo.description.as_deref().unwrap_or("No description provided"),
            "color": if repo.is_priority { 0xFF5722 } else { 0x2196F3 },
            "fields": [
                {"name":"Language","value":repo.language.as_deref().unwrap_or("Unknown"),"inline":true},
                {"name":"Stars","value":repo.stars.to_string(),"inline":true},
                {"name":"Discovered","value":repo.discovered_at,"inline":true}
            ]
        })).collect();
        let response = self.http_client.post(url).json(&json!({ "content": format!("Discovered {} new GitHub repositories", repos.len()), "embeds": embeds })).send().await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(NotifyError::Status(response.status()))
        }
    }

    async fn send_telegram(
        &self,
        token: &str,
        chat_id: &str,
        repos: &[&RepoItem],
    ) -> Result<(), NotifyError> {
        let mut message = format!("Discovered {} new GitHub repositories:\n\n", repos.len());
        for repo in repos.iter().take(self.config.max_items_per_message) {
            message.push_str(&format!(
                "- {}\n  {}\n  {}\n\n",
                repo.full_name,
                repo.description.as_deref().unwrap_or("No description"),
                repo.html_url
            ));
        }
        let response = self
            .http_client
            .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
            .json(
                &json!({ "chat_id": chat_id, "text": message, "disable_web_page_preview": false }),
            )
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(NotifyError::Status(response.status()))
        }
    }

    async fn send_custom(&self, url: &str, repos: &[&RepoItem]) -> Result<(), NotifyError> {
        let response = self.http_client.post(url).json(repos).send().await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(NotifyError::Status(response.status()))
        }
    }
}

#[cfg(windows)]
fn show_windows_toast(repos: &[&RepoItem]) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let title = if repos.len() == 1 {
        format!("GitHub: {}", repos[0].full_name)
    } else {
        format!("GitHub: {} new repositories", repos.len())
    };
    let body = if repos.len() == 1 {
        repos[0]
            .description
            .clone()
            .unwrap_or_else(|| "No description".into())
    } else {
        format!("{} + {} more", repos[0].full_name, repos.len() - 1)
    };
    let script = format!(
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; \
         $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
         $n = $t.GetElementsByTagName('text'); \
         $n[0].AppendChild($t.CreateTextNode('{}')) | Out-Null; \
         $n[1].AppendChild($t.CreateTextNode('{}')) | Out-Null; \
         $x = New-Object Windows.UI.Notifications.ToastNotification $t; \
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('BloomRepo').Show($x)",
        ps_quote(&title),
        ps_quote(&body)
    );
    let encoded = encode_powershell_script(&script);
    let _ = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            &encoded,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

#[cfg(windows)]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(windows)]
fn encode_powershell_script(script: &str) -> String {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    base64_encode(&utf16)
}

#[cfg(windows)]
fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        result.push(CHARSET[(b0 >> 2) as usize] as char);
        result.push(CHARSET[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARSET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARSET[(b2 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ps_quote() {
        assert_eq!(ps_quote("John's Repo"), "John''s Repo");
        assert_eq!(ps_quote("normal"), "normal");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"Hello World"), "SGVsbG8gV29ybGQ=");
    }
}
