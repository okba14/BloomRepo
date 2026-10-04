use crate::config::NotificationsConfig;
use crate::crawler::validate_repository_name;
use crate::models::RepoItem;
use reqwest::header::HeaderValue;
use reqwest::{Client, StatusCode, Url};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(any(windows, test))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Semaphore;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
static DNS_JOBS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(any(windows, test))]
static TOAST_JOBS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("notification network request failed")]
    Http,
    #[error("notification service returned HTTP {0}")]
    Status(StatusCode),
    #[error(
        "notification destination must be a public HTTPS endpoint without credentials or fragment"
    )]
    InvalidDestination,
    #[error("notification channel is unavailable")]
    InvalidChannel,
    #[error("invalid notification idempotency key")]
    InvalidIdempotencyKey,
    #[error("invalid Telegram bot credential")]
    InvalidTelegramCredential,
    #[error("notification service rejected delivery")]
    ServiceRejected,
    #[error("invalid notification service response")]
    InvalidResponse,
    #[error("notification service response exceeded the size limit")]
    ResponseTooLarge,
    #[error("notification contains a private repository or invalid repository path")]
    UnsafeRepository,
    #[error("secure notification HTTP client is unavailable")]
    ClientUnavailable,
    #[error("Windows toast command failed")]
    ToastFailed,
    #[error("Windows toast command timed out")]
    ToastTimeout,
    #[error("Windows toast delivery was cancelled")]
    ToastCancelled,
}

impl From<reqwest::Error> for NotifyError {
    fn from(_: reqwest::Error) -> Self {
        Self::Http
    }
}

#[derive(Debug)]
enum BlockingJobError {
    Timeout,
    Failed,
}

async fn admitted_blocking<T, F>(
    admission: Arc<Semaphore>,
    deadline: Instant,
    job: F,
) -> Result<T, BlockingJobError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async move {
        let permit = admission
            .acquire_owned()
            .await
            .map_err(|_| BlockingJobError::Failed)?;
        if Instant::now() >= deadline {
            return Err(BlockingJobError::Timeout);
        }
        let result = tokio::task::spawn_blocking(move || {
            // A timed-out/cancelled caller must not release admission for a live worker.
            let _permit = permit;
            if Instant::now() >= deadline {
                return Err(BlockingJobError::Timeout);
            }
            Ok(job())
        })
        .await
        .map_err(|_| BlockingJobError::Failed)?;
        if Instant::now() >= deadline {
            return Err(BlockingJobError::Timeout);
        }
        result
    })
    .await
    .map_err(|_| BlockingJobError::Timeout)?
}

#[cfg(any(windows, test))]
struct ToastCancellation(Arc<AtomicBool>);

#[cfg(any(windows, test))]
impl Drop for ToastCancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(any(windows, test))]
async fn run_toast_job<F>(deadline: Instant, job: F) -> Result<(), NotifyError>
where
    F: FnOnce(Arc<AtomicBool>) -> Result<(), NotifyError> + Send + 'static,
{
    let cancelled = Arc::new(AtomicBool::new(false));
    // This guard belongs to the awaiting future, not to the detached blocking closure.
    let _cancel_on_drop = ToastCancellation(cancelled.clone());
    admitted_blocking(
        TOAST_JOBS
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone(),
        deadline,
        move || job(cancelled),
    )
    .await
    .map_err(|error| match error {
        BlockingJobError::Timeout => NotifyError::ToastTimeout,
        BlockingJobError::Failed => NotifyError::ToastFailed,
    })?
}

#[cfg(any(windows, test))]
fn check_toast(cancelled: &AtomicBool, deadline: Instant) -> Result<(), NotifyError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(NotifyError::ToastCancelled);
    }
    if Instant::now() >= deadline {
        return Err(NotifyError::ToastTimeout);
    }
    Ok(())
}

/// Syntax validation for configuration; delivery also resolves and pins public IPs.
pub fn validate_destination(value: &str) -> Result<(), NotifyError> {
    destination_url(value).map(|_| ())
}

fn destination_url(value: &str) -> Result<Url, NotifyError> {
    if value
        .bytes()
        .any(|c| c.is_ascii_control() || c.is_ascii_whitespace() || c == b'\\')
    {
        return Err(NotifyError::InvalidDestination);
    }
    let url = Url::parse(value).map_err(|_| NotifyError::InvalidDestination)?;
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default());
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || authority.is_some_and(|v| v.contains('@'))
        || url.port_or_known_default() == Some(0)
    {
        return Err(NotifyError::InvalidDestination);
    }
    let host = url
        .host_str()
        .ok_or(NotifyError::InvalidDestination)?
        .trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !public_ip(ip) {
            return Err(NotifyError::InvalidDestination);
        }
    } else {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !host.contains('.')
            || host == "localhost"
            || host.ends_with(".localhost")
            || [
                ".local",
                ".internal",
                ".lan",
                ".home.arpa",
                ".test",
                ".invalid",
            ]
            .iter()
            .any(|suffix| host.ends_with(suffix))
            || host.split('.').any(|label| {
                label.is_empty()
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(NotifyError::InvalidDestination);
        }
    }
    Ok(url)
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    // Only global unicast; exclude mapped, translation, tunneling and special ranges.
    let segments = ip.segments();
    (segments[0] & 0xe000) == 0x2000
        && !(segments[0] == 0x2001 && (segments[1] < 0x0200 || segments[1] == 0x0db8))
        && segments[0] != 0x2002
        && !(segments[0] == 0x3fff && segments[1] < 0x1000)
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_ipv4(ip),
        IpAddr::V6(ip) => public_ipv6(ip),
    }
}

pub struct Notifier {
    config: NotificationsConfig,
}

impl Notifier {
    pub fn new(config: NotificationsConfig) -> Self {
        Self { config }
    }

    pub fn channels(&self) -> Vec<String> {
        let mut channels = Vec::new();
        #[cfg(windows)]
        if self.config.enable_windows_toast {
            channels.push("toast".into());
        }
        if self.config.discord_webhook_url.is_some() {
            channels.push("discord".into());
        }
        if self.config.telegram_bot_token.is_some() && self.config.telegram_chat_id.is_some() {
            channels.push("telegram".into());
        }
        if self.config.webhook_url.is_some() {
            channels.push("webhook".into());
        }
        channels
    }

    pub async fn deliver(
        &self,
        channel: &str,
        repos: &[RepoItem],
        idempotency_key: &str,
    ) -> Result<(), NotifyError> {
        if !self.channels().iter().any(|available| available == channel) {
            return Err(NotifyError::InvalidChannel);
        }
        if idempotency_key.is_empty()
            || idempotency_key.len() > 200
            || !idempotency_key.bytes().all(|c| c.is_ascii_graphic())
        {
            return Err(NotifyError::InvalidIdempotencyKey);
        }
        let selected: Vec<_> = repos
            .iter()
            .filter(|repo| {
                channel != "toast" || !self.config.toast_priority_only || repo.is_priority
            })
            .collect();
        if selected
            .iter()
            .any(|repo| repo.private || validate_repository_name(&repo.full_name).is_err())
        {
            return Err(NotifyError::UnsafeRepository);
        }
        if selected.is_empty() {
            return Ok(());
        }
        match channel {
            "discord" => {
                self.send_discord(
                    self.config
                        .discord_webhook_url
                        .as_deref()
                        .ok_or(NotifyError::InvalidChannel)?,
                    &selected,
                )
                .await
            }
            "telegram" => self.send_telegram(&selected).await,
            "webhook" => {
                self.send_custom(
                    self.config
                        .webhook_url
                        .as_deref()
                        .ok_or(NotifyError::InvalidChannel)?,
                    &selected,
                    idempotency_key,
                )
                .await
            }
            #[cfg(windows)]
            "toast" => {
                let deadline = Instant::now() + self.timeout();
                let messages: Vec<_> = selected.iter().map(|repo| toast_text(repo)).collect();
                run_toast_job(deadline, move |cancelled| {
                    show_windows_toasts(messages, deadline, cancelled)
                })
                .await
            }
            _ => Err(NotifyError::InvalidChannel),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_seconds.clamp(1, 120))
    }

    async fn secure_client(&self, url: &Url) -> Result<Client, NotifyError> {
        let host = url
            .host_str()
            .ok_or(NotifyError::InvalidDestination)?
            .trim_matches(['[', ']'])
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(NotifyError::InvalidDestination)?;
        let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            let lookup_host = host.clone();
            admitted_blocking(
                DNS_JOBS.get_or_init(|| Arc::new(Semaphore::new(2))).clone(),
                Instant::now() + self.timeout(),
                move || {
                    (lookup_host.as_str(), port)
                        .to_socket_addrs()
                        .map(|addresses| addresses.collect::<Vec<_>>())
                },
            )
            .await
            .map_err(|_| NotifyError::Http)?
            .map_err(|_| NotifyError::Http)?
        };
        // Reject mixed public/private answers too. Pin the checked answer to prevent rebinding.
        if addresses.is_empty() || addresses.iter().any(|address| !public_ip(address.ip())) {
            return Err(NotifyError::InvalidDestination);
        }
        Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(self.timeout())
            .resolve_to_addrs(&host, &addresses)
            .build()
            .map_err(|_| NotifyError::ClientUnavailable)
    }

    async fn post(
        &self,
        client: &Client,
        url: &Url,
        payload: &Value,
        idempotency_key: Option<&str>,
    ) -> Result<Vec<u8>, NotifyError> {
        validate_destination(url.as_str())?;
        let mut request = client.post(url.clone()).json(payload);
        if let Some(key) = idempotency_key {
            let mut value =
                HeaderValue::from_str(key).map_err(|_| NotifyError::InvalidIdempotencyKey)?;
            value.set_sensitive(true);
            request = request.header("idempotency-key", value);
        }
        let mut response = request.send().await?;
        if !response.status().is_success() {
            return Err(NotifyError::Status(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(NotifyError::ResponseTooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
                return Err(NotifyError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn send_discord(&self, value: &str, repos: &[&RepoItem]) -> Result<(), NotifyError> {
        let mut url = destination_url(value)?;
        // Discord's wait=true makes a successful response confirm message creation.
        let query: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "wait")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        url.set_query(None);
        url.query_pairs_mut()
            .extend_pairs(query)
            .append_pair("wait", "true");
        let client = self.secure_client(&url).await?;
        // Five bounded embeds stay below Discord's combined 6000 UTF-16-unit budget.
        for chunk in repos.chunks(self.config.max_items_per_message.clamp(1, 5)) {
            self.post(&client, &url, &discord_payload(chunk), None)
                .await?;
        }
        Ok(())
    }

    async fn send_telegram(&self, repos: &[&RepoItem]) -> Result<(), NotifyError> {
        let token = self
            .config
            .telegram_bot_token
            .as_deref()
            .ok_or(NotifyError::InvalidChannel)?;
        let (id, secret) = token
            .split_once(':')
            .ok_or(NotifyError::InvalidTelegramCredential)?;
        if id.is_empty()
            || !id.bytes().all(|c| c.is_ascii_digit())
            || secret.is_empty()
            || !secret
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err(NotifyError::InvalidTelegramCredential);
        }
        let chat = self
            .config
            .telegram_chat_id
            .as_deref()
            .ok_or(NotifyError::InvalidChannel)?;
        let url = destination_url(&format!("https://api.telegram.org/bot{token}/sendMessage"))?;
        let client = self.secure_client(&url).await?;
        for text in telegram_messages(repos, self.config.max_items_per_message) {
            let response = self
                .post(
                    &client,
                    &url,
                    &json!({
                        "chat_id": chat, "text": text, "disable_web_page_preview": true,
                        "disable_notification": false
                    }),
                    None,
                )
                .await?;
            telegram_result(&response)?;
        }
        Ok(())
    }

    async fn send_custom(
        &self,
        value: &str,
        repos: &[&RepoItem],
        key: &str,
    ) -> Result<(), NotifyError> {
        let url = destination_url(value)?;
        let client = self.secure_client(&url).await?;
        let size = self.config.max_items_per_message.clamp(1, 100);
        let count = repos.len().div_ceil(size);
        for (index, chunk) in repos.chunks(size).enumerate() {
            // Each chunk needs a stable distinct key; reusing one would drop later chunks.
            let chunk_key = if count == 1 {
                key.to_owned()
            } else {
                format!("{key}:{}", index + 1)
            };
            let payload = webhook_payload(chunk, key, &chunk_key, index, count);
            self.post(&client, &url, &payload, Some(&chunk_key)).await?;
        }
        Ok(())
    }
}

fn safe_text(value: &str, limit: usize) -> String {
    let text = value
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect::<String>()
        .replace('@', "(at)");
    if text.encode_utf16().count() <= limit {
        return text;
    }
    let budget = limit.saturating_sub(3);
    let mut result = String::new();
    let mut used = 0;
    for c in text.chars() {
        if used + c.len_utf16() > budget {
            break;
        }
        result.push(c);
        used += c.len_utf16();
    }
    result.push_str(&"..."[..limit.min(3)]);
    result
}

fn repo_url(repo: &RepoItem) -> String {
    format!("https://github.com/{}", repo.full_name)
}

fn discord_payload(repos: &[&RepoItem]) -> Value {
    let embeds: Vec<_> = repos.iter().map(|repo| json!({
        "title": safe_text(&repo.full_name, 256),
        "url": repo_url(repo),
        "description": safe_text(repo.description.as_deref().unwrap_or("No description provided"), 700),
        "color": if repo.is_priority { 0xFF5722 } else { 0x2196F3 },
        "fields": [
            {"name":"Language","value":safe_text(repo.language.as_deref().unwrap_or("Unknown"), 100),"inline":true},
            {"name":"Stars","value":repo.stars.to_string(),"inline":true},
            {"name":"Discovered","value":safe_text(&repo.discovered_at, 64),"inline":true}
        ]
    })).collect();
    json!({"content":format!("Discovered {} new GitHub repositories", repos.len()),
        "embeds":embeds,"allowed_mentions":{"parse":[],"users":[],"roles":[],"replied_user":false}})
}

fn telegram_messages(repos: &[&RepoItem], max_items: usize) -> Vec<String> {
    const HEADER: &str = "New GitHub repositories:\n\n";
    let mut messages = Vec::new();
    let mut message = HEADER.to_owned();
    let mut items = 0;
    for repo in repos {
        let row = format!(
            "- {}\n{}\n{}\n\n",
            safe_text(&repo.full_name, 256),
            safe_text(
                repo.description.as_deref().unwrap_or("No description"),
                1024
            ),
            repo_url(repo)
        );
        if items != 0
            && (items >= max_items.max(1)
                || message.encode_utf16().count() + row.encode_utf16().count() > 4096)
        {
            messages.push(message);
            message = HEADER.to_owned();
            items = 0;
        }
        message.push_str(&row);
        items += 1;
    }
    if items != 0 {
        messages.push(message);
    }
    messages
}

fn telegram_result(body: &[u8]) -> Result<(), NotifyError> {
    let result: Value = serde_json::from_slice(body).map_err(|_| NotifyError::InvalidResponse)?;
    match result.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(()),
        Some(false) => Err(NotifyError::ServiceRejected),
        None => Err(NotifyError::InvalidResponse),
    }
}

fn webhook_payload(
    repos: &[&RepoItem],
    delivery_key: &str,
    key: &str,
    index: usize,
    count: usize,
) -> Value {
    json!({"event":"repositories.discovered", "version":1, "idempotency_key":key,
        "delivery_id":delivery_key, "chunk_index":index, "chunk_count":count, "repositories":repos})
}

#[cfg(any(windows, test))]
fn toast_text(repo: &RepoItem) -> (String, String) {
    (
        safe_text(&format!("GitHub: {}", repo.full_name), 160),
        safe_text(repo.description.as_deref().unwrap_or("No description"), 512),
    )
}

#[cfg(any(windows, test))]
const TOAST_SCRIPT: &str = "$ErrorActionPreference = 'Stop'; try { \
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; \
    $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
    $n = $t.GetElementsByTagName('text'); \
    $n[0].AppendChild($t.CreateTextNode($env:BLOOM_TOAST_TITLE)) | Out-Null; \
    $n[1].AppendChild($t.CreateTextNode($env:BLOOM_TOAST_BODY)) | Out-Null; \
    $x = New-Object Windows.UI.Notifications.ToastNotification $t; \
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('BloomRepo').Show($x); \
    exit 0 } catch { exit 1 }";

#[cfg(windows)]
fn show_windows_toasts(
    messages: Vec<(String, String)>,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
) -> Result<(), NotifyError> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    check_toast(&cancelled, deadline)?;
    let root = std::env::var_os("SystemRoot").ok_or(NotifyError::ToastFailed)?;
    let executable =
        std::path::PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    for (title, body) in messages {
        check_toast(&cancelled, deadline)?;
        // Repository text is data in environment variables, never PowerShell source.
        let mut child = Command::new(&executable)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                TOAST_SCRIPT,
            ])
            .env("BLOOM_TOAST_TITLE", title)
            .env("BLOOM_TOAST_BODY", body)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|_| NotifyError::ToastFailed)?;
        loop {
            if let Err(error) = check_toast(&cancelled, deadline) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            match child.try_wait() {
                Ok(Some(status)) if status.success() => break,
                Ok(Some(_)) => return Err(NotifyError::ToastFailed),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(NotifyError::ToastFailed);
                }
                Ok(None) => {}
            }
            std::thread::sleep(
                Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    check_toast(&cancelled, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(id: usize) -> RepoItem {
        crate::crawler::raw_to_item(
            serde_json::from_value(json!({
                "id":id,"name":format!("repo{id}"),"full_name":format!("owner/repo{id}"),
                "html_url":"https://evil.invalid/", "private":false,"default_branch":"main",
                "description":"@everyone <@123> '); Write-Host hacked; #"
            }))
            .unwrap(),
        )
    }

    #[test]
    fn destinations_reject_local_private_credentials_and_unsafe_schemes() {
        for value in [
            "http://example.com",
            "https://localhost/a",
            "https://foo.localhost/a",
            "https://localhost./a",
            "https://127.0.0.1/a",
            "https://127.1/a",
            "https://2130706433/a",
            "https://10.0.0.1",
            "https://172.16.0.1",
            "https://192.168.1.1",
            "https://169.254.169.254",
            "https://100.64.0.1",
            "https://0.0.0.0",
            "https://[::1]",
            "https://[fc00::1]",
            "https://[::ffff:127.0.0.1]",
            "https://[2002:7f00:1::]",
            "https://example.com#secret",
            "https://user:secret@example.com",
            "https://@example.com",
            "https://example.com\\@localhost",
            "https://example.com\n",
        ] {
            assert!(validate_destination(value).is_err(), "accepted {value}");
        }
        for value in [
            "https://discord.com/api/webhooks/123/test",
            "https://api.telegram.org",
            "https://example.com/hook",
            "https://8.8.8.8/hook",
            "https://[2606:4700::1111]/hook",
        ] {
            assert!(validate_destination(value).is_ok(), "rejected {value}");
        }
    }

    #[test]
    fn unicode_truncation_is_bounded_and_mentions_are_neutralized() {
        let text = "\u{1f600}\u{00e9}@everyone".repeat(100);
        for limit in 0..40 {
            let result = safe_text(&text, limit);
            assert!(result.encode_utf16().count() <= limit);
            assert!(!result.contains('@'));
        }
    }

    #[test]
    fn platform_payloads_keep_every_row_and_stay_within_limits() {
        let mut repos: Vec<_> = (0..23).map(repo).collect();
        for repo in &mut repos {
            repo.description = Some("\u{1f600}@everyone".repeat(2000));
            repo.language = Some("x".repeat(200));
            repo.discovered_at = "y".repeat(200);
        }
        let refs: Vec<_> = repos.iter().collect();
        let mut count = 0;
        for chunk in refs.chunks(5) {
            let payload = discord_payload(chunk);
            let embeds = payload["embeds"].as_array().unwrap();
            count += embeds.len();
            let total: usize = embeds
                .iter()
                .map(|embed| {
                    let fields: usize = embed["fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|field| {
                            field["name"].as_str().unwrap().encode_utf16().count()
                                + field["value"].as_str().unwrap().encode_utf16().count()
                        })
                        .sum();
                    fields
                        + embed["title"].as_str().unwrap().encode_utf16().count()
                        + embed["description"]
                            .as_str()
                            .unwrap()
                            .encode_utf16()
                            .count()
                })
                .sum();
            assert!(total <= 6000);
            assert!(payload["allowed_mentions"]["parse"]
                .as_array()
                .unwrap()
                .is_empty());
        }
        assert_eq!(count, 23);
        let messages = telegram_messages(&refs, 100);
        assert!(messages
            .iter()
            .all(|message| message.encode_utf16().count() <= 4096));
        for repo in &repos {
            assert_eq!(
                messages
                    .iter()
                    .flat_map(|text| text.lines())
                    .filter(|line| *line == repo_url(repo))
                    .count(),
                1
            );
        }
        assert_eq!(telegram_messages(&refs, 0).len(), 23);
    }

    #[test]
    fn telegram_failure_and_all_error_strings_are_redacted() {
        assert!(matches!(
            telegram_result(br#"{"ok":false,"description":"token-secret"}"#),
            Err(NotifyError::ServiceRejected)
        ));
        assert!(telegram_result(br#"{"ok":true}"#).is_ok());
        assert!(telegram_result(br#"{"description":"token-secret"}"#).is_err());
        let error = validate_destination("https://user:token-secret@localhost").unwrap_err();
        assert!(!format!("{error} {error:?}").contains("token-secret"));
        assert!(!NotifyError::Http.to_string().contains("https://"));
        let transport = Client::new()
            .get("https://api.telegram.org/bot123:token-secret/sendMessage")
            .header("x-test", "\r\n")
            .build()
            .unwrap_err();
        let error = NotifyError::from(transport);
        assert!(!format!("{error} {error:?}").contains("token-secret"));
        assert!(!format!("{error} {error:?}").contains("https://"));
    }

    #[test]
    fn webhook_has_event_envelope_and_stable_chunk_identity() {
        let repo = repo(1);
        let payload = webhook_payload(&[&repo], "delivery", "delivery:2", 1, 3);
        assert_eq!(payload["event"], "repositories.discovered");
        assert_eq!(payload["idempotency_key"], "delivery:2");
        assert_eq!(payload["delivery_id"], "delivery");
        assert_eq!(payload["repositories"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn toast_priority_setting_does_not_drop_other_channels() {
        let config = NotificationsConfig {
            toast_priority_only: true,
            webhook_url: Some("https://localhost/hook".into()),
            ..Default::default()
        };
        let notifier = Notifier::new(config);
        assert!(matches!(
            notifier.deliver("webhook", &[repo(1)], "test").await,
            Err(NotifyError::InvalidDestination)
        ));
        #[cfg(not(windows))]
        assert!(!notifier.channels().contains(&"toast".into()));
    }

    #[tokio::test]
    async fn private_rows_and_header_injection_fail_before_network() {
        let config = NotificationsConfig {
            webhook_url: Some("https://localhost/hook".into()),
            ..Default::default()
        };
        let notifier = Notifier::new(config);
        let mut private = repo(1);
        private.private = true;
        assert!(matches!(
            notifier.deliver("webhook", &[private], "test").await,
            Err(NotifyError::UnsafeRepository)
        ));
        assert!(matches!(
            notifier
                .deliver("webhook", &[repo(1)], "test\r\nsecret")
                .await,
            Err(NotifyError::InvalidIdempotencyKey)
        ));
        assert!(matches!(
            notifier.deliver("unknown", &[repo(1)], "test").await,
            Err(NotifyError::InvalidChannel)
        ));
    }

    #[test]
    fn toast_data_is_not_interpolated_into_script() {
        let repo = repo(1);
        let (title, body) = toast_text(&repo);
        assert!(!TOAST_SCRIPT.contains(&title));
        assert!(!TOAST_SCRIPT.contains(&body));
        assert!(TOAST_SCRIPT.contains("$env:BLOOM_TOAST_TITLE"));
        assert!(TOAST_SCRIPT.contains("$ErrorActionPreference = 'Stop'"));
    }

    #[test]
    fn blocking_admission_is_global() {
        let first = DNS_JOBS.get_or_init(|| Arc::new(Semaphore::new(2))).clone();
        let second = DNS_JOBS.get_or_init(|| Arc::new(Semaphore::new(2))).clone();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.available_permits(), 2);
        let first = TOAST_JOBS
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone();
        let second = TOAST_JOBS
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn admission_wait_is_included_in_timeout_and_never_spawns() {
        let admission = Arc::new(Semaphore::new(1));
        let held = admission.clone().acquire_owned().await.unwrap();
        let started = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let result = admitted_blocking(
            admission.clone(),
            Instant::now() + Duration::from_millis(5),
            move || worker_started.store(true, Ordering::Release),
        )
        .await;
        assert!(matches!(result, Err(BlockingJobError::Timeout)));
        drop(held);
        assert_eq!(admission.available_permits(), 1);
        assert!(!started.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn cancelling_admission_wait_never_spawns() {
        let admission = Arc::new(Semaphore::new(1));
        let held = admission.clone().acquire_owned().await.unwrap();
        let started = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let mut waiting = Box::pin(admitted_blocking(
            admission.clone(),
            Instant::now() + Duration::from_secs(5),
            move || worker_started.store(true, Ordering::Release),
        ));
        assert!(tokio::time::timeout(Duration::from_millis(5), &mut waiting)
            .await
            .is_err());
        drop(waiting);
        drop(held);
        assert_eq!(admission.available_permits(), 1);
        assert!(!started.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn timed_out_blocking_worker_keeps_admission_until_completion() {
        let admission = Arc::new(Semaphore::new(1));
        let (release, worker_release) = std::sync::mpsc::channel();
        let (started, worker_started) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(admitted_blocking(
            admission.clone(),
            Instant::now() + Duration::from_secs(1),
            move || {
                let _ = started.send(());
                worker_release.recv_timeout(Duration::from_secs(5)).unwrap();
            },
        ));
        tokio::time::timeout(Duration::from_secs(2), worker_started)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            worker.await.unwrap(),
            Err(BlockingJobError::Timeout)
        ));
        assert_eq!(admission.available_permits(), 0);
        let retry_started = Arc::new(AtomicBool::new(false));
        let retry_flag = retry_started.clone();
        assert!(matches!(
            admitted_blocking(
                admission.clone(),
                Instant::now() + Duration::from_millis(5),
                move || retry_flag.store(true, Ordering::Release),
            )
            .await,
            Err(BlockingJobError::Timeout)
        ));
        assert!(!retry_started.load(Ordering::Acquire));
        release.send(()).unwrap();
        let permit =
            tokio::time::timeout(Duration::from_secs(2), admission.clone().acquire_owned())
                .await
                .unwrap()
                .unwrap();
        drop(permit);
        assert_eq!(admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelling_toast_future_signals_the_running_worker() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (started, worker_started) = tokio::sync::oneshot::channel();
        let (stopped, worker_stopped) = tokio::sync::oneshot::channel();
        let delivery = tokio::spawn(run_toast_job(deadline, move |cancelled| {
            let _ = started.send(());
            let result = loop {
                if let Err(error) = check_toast(&cancelled, deadline) {
                    break Err(error);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let _ = stopped.send(matches!(&result, Err(NotifyError::ToastCancelled)));
            result
        }));
        tokio::time::timeout(Duration::from_secs(2), worker_started)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(TOAST_JOBS.get().unwrap().available_permits(), 0);
        delivery.abort();
        assert!(delivery.await.unwrap_err().is_cancelled());
        assert!(tokio::time::timeout(Duration::from_secs(2), worker_stopped)
            .await
            .unwrap()
            .unwrap());
        let permit = tokio::time::timeout(
            Duration::from_secs(2),
            TOAST_JOBS.get().unwrap().clone().acquire_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(permit);
    }

    #[test]
    fn toast_cancel_and_deadline_checks_apply_to_the_whole_batch() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let future_deadline = Instant::now() + Duration::from_secs(5);
        assert!(check_toast(&cancelled, future_deadline).is_ok());
        let expired_deadline = Instant::now() - Duration::from_secs(1);
        for _ in 0..3 {
            assert!(matches!(
                check_toast(&cancelled, expired_deadline),
                Err(NotifyError::ToastTimeout)
            ));
        }
        let guard = ToastCancellation(cancelled.clone());
        drop(guard);
        assert!(matches!(
            check_toast(&cancelled, future_deadline),
            Err(NotifyError::ToastCancelled)
        ));
        assert_eq!(
            NotifyError::ToastCancelled.to_string(),
            "Windows toast delivery was cancelled"
        );
    }
}
