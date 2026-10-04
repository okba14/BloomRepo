use crate::models::{
    GithubEventRaw, GithubReleaseRaw, GithubRepositoryRaw, GithubSearchResponse, RepoItem,
};
use crate::tokens::{RateResource, TokenError, TokenPool};
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderName, ETAG, IF_NONE_MATCH, LINK};
use reqwest::{Client, StatusCode, Url};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;

const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum CrawlerError {
    #[error("GitHub network request failed")]
    Http,
    #[error("rate limited; retry in {0}s")]
    RateLimited(u64),
    #[error("invalid GitHub JSON response")]
    Json,
    #[error("GitHub returned HTTP {status}")]
    Api { status: StatusCode },
    #[error("GitHub credentials are invalid or unavailable")]
    InvalidCredentials,
    #[error("GitHub returned unusable rate-limit metadata")]
    InvalidRateLimit,
    #[error("unsafe GitHub URL or pagination link")]
    InvalidUrl,
    #[error("invalid GitHub repository name")]
    InvalidRepository,
    #[error("search must be public-only, without private qualifiers or OR operators")]
    InvalidQuery,
    #[error("GitHub response exceeded the size limit")]
    ResponseTooLarge,
    #[error("secure GitHub HTTP client is unavailable")]
    ClientUnavailable,
}

impl From<reqwest::Error> for CrawlerError {
    fn from(_: reqwest::Error) -> Self {
        Self::Http
    }
}

impl From<serde_json::Error> for CrawlerError {
    fn from(_: serde_json::Error) -> Self {
        Self::Json
    }
}

impl From<TokenError> for CrawlerError {
    fn from(error: TokenError) -> Self {
        match error {
            TokenError::InvalidCredentials => Self::InvalidCredentials,
            TokenError::InvalidRateLimit => Self::InvalidRateLimit,
        }
    }
}

pub struct GithubCrawler {
    client: Option<Client>,
    token_pool: TokenPool,
    concurrency: Semaphore,
}

pub struct Page<T> {
    pub items: Vec<T>,
    pub next_url: Option<String>,
    pub etag: Option<String>,
    pub poll_interval: Option<u64>,
    pub total_count: Option<usize>,
    pub incomplete_results: bool,
}

struct ApiResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl GithubCrawler {
    #[allow(dead_code)]
    pub fn new(token_pool: TokenPool, timeout_secs: u64) -> Self {
        Self::with_concurrency(token_pool, timeout_secs, 4)
    }

    pub fn with_concurrency(token_pool: TokenPool, timeout_secs: u64, max: usize) -> Self {
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(timeout_secs.clamp(1, 300)))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(max.clamp(1, 32))
            .build()
            .ok();
        Self {
            client,
            token_pool,
            concurrency: Semaphore::new(max.clamp(1, 32)),
        }
    }

    async fn request(
        &self,
        url: Url,
        resource: RateResource,
        etag: Option<&str>,
    ) -> Result<ApiResponse, CrawlerError> {
        // Validate again at the only point where Authorization is attached.
        validate_api_url(url.as_str())?;
        let _permit = self
            .concurrency
            .acquire()
            .await
            .map_err(|_| CrawlerError::ClientUnavailable)?;
        let client = self
            .client
            .as_ref()
            .ok_or(CrawlerError::ClientUnavailable)?;
        let (mut headers, token) = self.token_pool.get_headers(resource).await?;
        if let Some(etag) = etag {
            if let Ok(value) = etag.parse() {
                headers.insert(IF_NONE_MATCH, value);
            }
        }
        let mut response = client.get(url).headers(headers).send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        self.token_pool
            .observe_response(token.as_deref(), resource, status, &headers)
            .await;
        if status == StatusCode::UNAUTHORIZED {
            return Err(CrawlerError::InvalidCredentials);
        }
        if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
            if let Some(wait) = self.token_pool.wait_if_exhausted(resource).await {
                return Err(CrawlerError::RateLimited(wait));
            }
            return Err(CrawlerError::Api { status });
        }
        // Never read an error body: it can contain reflected secrets or attacker text.
        if !status.is_success()
            && status != StatusCode::NOT_MODIFIED
            && status != StatusCode::NOT_FOUND
        {
            return Err(CrawlerError::Api { status });
        }
        let mut body = Vec::new();
        if status.is_success() {
            if response
                .content_length()
                .is_some_and(|length| length > MAX_BODY_BYTES as u64)
            {
                return Err(CrawlerError::ResponseTooLarge);
            }
            while let Some(chunk) = response.chunk().await? {
                if chunk.len() > MAX_BODY_BYTES.saturating_sub(body.len()) {
                    return Err(CrawlerError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
        }
        Ok(ApiResponse {
            status,
            headers,
            body,
        })
    }

    pub async fn fetch_repositories_page(
        &self,
        url: &str,
    ) -> Result<Page<GithubRepositoryRaw>, CrawlerError> {
        let url = validate_pagination_url(url, "/repositories")?;
        let response = self.request(url, RateResource::Core, None).await?;
        require_success(response.status)?;
        let items: Vec<GithubRepositoryRaw> = serde_json::from_slice(&response.body)?;
        Ok(Page {
            items: items.into_iter().filter(is_public).collect(),
            next_url: parse_next_link(&response.headers, "/repositories")?,
            etag: header_string(&response.headers, ETAG),
            poll_interval: None,
            total_count: None,
            incomplete_results: false,
        })
    }

    pub async fn fetch_events(&self, etag: Option<&str>) -> Result<Page<RepoItem>, CrawlerError> {
        let response = self
            .request(
                validate_api_url("https://api.github.com/events?per_page=100")?,
                RateResource::Core,
                etag,
            )
            .await?;
        let items = if response.status == StatusCode::NOT_MODIFIED {
            Vec::new()
        } else {
            require_success(response.status)?;
            let events: Vec<GithubEventRaw> = serde_json::from_slice(&response.body)?;
            events.into_iter().filter_map(event_to_repo).collect()
        };
        Ok(Page {
            items,
            next_url: None,
            etag: header_string(&response.headers, ETAG).or_else(|| etag.map(ToOwned::to_owned)),
            poll_interval: parse_header_u64(&response.headers, "x-poll-interval"),
            total_count: None,
            incomplete_results: false,
        })
    }

    #[allow(dead_code)]
    pub async fn fetch_search_query(
        &self,
        query: &str,
    ) -> Result<Page<GithubRepositoryRaw>, CrawlerError> {
        self.fetch_search_page(query, 1).await
    }

    pub async fn fetch_search_page(
        &self,
        query: &str,
        page: usize,
    ) -> Result<Page<GithubRepositoryRaw>, CrawlerError> {
        let url = search_url(query, page)?;
        let response = self.request(url, RateResource::Search, None).await?;
        require_success(response.status)?;
        let result: GithubSearchResponse = serde_json::from_slice(&response.body)?;
        let next_url = parse_next_link(&response.headers, "/search/repositories")?;
        // Do not trust a server-provided query to preserve the public-only restriction.
        if let Some(next) = &next_url {
            let parsed = validate_pagination_url(next, "/search/repositories")?;
            let next_query = parsed
                .query_pairs()
                .find(|(key, _)| key == "q")
                .map(|(_, value)| value.into_owned())
                .ok_or(CrawlerError::InvalidUrl)?;
            public_query(&next_query)?;
        }
        Ok(Page {
            items: result.items.into_iter().filter(is_public).collect(),
            next_url,
            etag: header_string(&response.headers, ETAG),
            poll_interval: None,
            total_count: result.total_count,
            incomplete_results: result.incomplete_results,
        })
    }

    pub async fn fetch_repository(&self, full_name: &str) -> Result<RepoItem, CrawlerError> {
        validate_repository_name(full_name)?;
        let url = validate_api_url(&format!("https://api.github.com/repos/{full_name}"))?;
        let response = self.request(url, RateResource::Core, None).await?;
        require_success(response.status)?;
        let raw: GithubRepositoryRaw = serde_json::from_slice(&response.body)?;
        validate_repository_name(&raw.full_name)?;
        let mut item = raw_to_item(raw);
        item.source = "metadata".into();
        Ok(item)
    }

    pub async fn fetch_latest_release(
        &self,
        full_name: &str,
    ) -> Result<Option<String>, CrawlerError> {
        validate_repository_name(full_name)?;
        let url = validate_api_url(&format!(
            "https://api.github.com/repos/{full_name}/releases/latest"
        ))?;
        let response = self.request(url, RateResource::Core, None).await?;
        if response.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        require_success(response.status)?;
        let release: GithubReleaseRaw = serde_json::from_slice(&response.body)?;
        Ok((!release.draft && !release.tag_name.is_empty()).then_some(release.tag_name))
    }

    /// A sampled high ID, not a latest-ID guarantee or a safe sequential checkpoint.
    #[allow(dead_code)]
    pub async fn fetch_latest_repo_id(&self) -> Result<Option<i64>, CrawlerError> {
        let recent = (Utc::now() - chrono::Duration::days(1)).format("%Y-%m-%dT%H:%M:%SZ");
        let page = self
            .fetch_search_page(&format!("created:>={recent}"), 1)
            .await?;
        tracing::warn!(
            incomplete_results = page.incomplete_results,
            "Repository ID is a recent search sample only; it is not a latest-ID guarantee"
        );
        Ok(page.items.iter().map(|repo| repo.id).max())
    }
}

fn require_success(status: StatusCode) -> Result<(), CrawlerError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(CrawlerError::Api { status })
    }
}

fn is_public(raw: &GithubRepositoryRaw) -> bool {
    !raw.private
        && raw
            .visibility
            .as_deref()
            .is_none_or(|value| value == "public")
}

pub fn raw_to_item(raw: GithubRepositoryRaw) -> RepoItem {
    let valid_name = validate_repository_name(&raw.full_name).is_ok();
    let private = !is_public(&raw) || !valid_name;
    let metadata_complete =
        valid_name && raw.default_branch.as_deref().is_some_and(|s| !s.is_empty());
    let owner = raw
        .owner
        .as_ref()
        .map(|owner| owner.login.clone())
        .unwrap_or_else(|| raw.full_name.split('/').next().unwrap_or_default().into());
    RepoItem {
        id: raw.id,
        name: raw.name,
        html_url: if valid_name {
            format!("https://github.com/{}", raw.full_name)
        } else {
            "https://github.com/".into()
        },
        full_name: raw.full_name,
        owner,
        owner_type: raw.owner.and_then(|owner| owner.owner_type),
        description: raw.description,
        fork: raw.fork,
        stars: raw.stargazers_count,
        forks_count: raw.forks_count,
        language: raw.language,
        license: raw
            .license
            .and_then(|license| license.spdx_id.or(license.key).or(license.name)),
        topics: raw.topics,
        created_at: raw.created_at,
        discovered_at: Utc::now().to_rfc3339(),
        is_priority: false,
        metadata_complete,
        private,
        archived: raw.archived,
        pushed_at: raw.pushed_at,
        default_branch: raw.default_branch,
        latest_release: None,
        source: "github".into(),
    }
}

fn event_to_repo(event: GithubEventRaw) -> Option<RepoItem> {
    let payload = event.payload?;
    if event.event_type != "CreateEvent" || payload.ref_type.as_deref() != Some("repository") {
        return None;
    }
    validate_repository_name(&event.repo.name).ok()?;
    let (owner, name) = event.repo.name.split_once('/')?;
    Some(RepoItem {
        id: event.repo.id,
        name: name.into(),
        full_name: event.repo.name.clone(),
        owner: owner.into(),
        owner_type: None,
        html_url: format!("https://github.com/{}", event.repo.name),
        description: payload.description,
        fork: false,
        stars: 0,
        forks_count: 0,
        language: None,
        license: None,
        topics: vec![],
        created_at: event.created_at,
        discovered_at: Utc::now().to_rfc3339(),
        is_priority: false,
        metadata_complete: false,
        private: true,
        archived: false,
        pushed_at: None,
        default_branch: None,
        latest_release: None,
        source: "events".into(),
    })
}

pub(crate) fn validate_repository_name(full_name: &str) -> Result<(), CrawlerError> {
    let (owner, repo) = full_name
        .split_once('/')
        .ok_or(CrawlerError::InvalidRepository)?;
    if owner.is_empty()
        || owner.len() > 39
        || repo.is_empty()
        || repo.len() > 100
        || repo == "."
        || repo == ".."
        || !owner
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        || !repo
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    {
        return Err(CrawlerError::InvalidRepository);
    }
    Ok(())
}

fn validate_api_url(value: &str) -> Result<Url, CrawlerError> {
    if value
        .bytes()
        .any(|c| c.is_ascii_control() || c.is_ascii_whitespace() || c == b'\\')
    {
        return Err(CrawlerError::InvalidUrl);
    }
    let url = Url::parse(value).map_err(|_| CrawlerError::InvalidUrl)?;
    let authority = value
        .split_once("://")
        .map(|(_, v)| v.split(['/', '?', '#']).next().unwrap_or_default());
    let raw_path = value.split('?').next().unwrap_or(value);
    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || authority.is_some_and(|v| v.contains('@'))
        || url.path().contains('%')
        || raw_path.contains("/../")
        || raw_path.contains("/./")
        || raw_path.ends_with("/..")
        || raw_path.ends_with("/.")
    {
        return Err(CrawlerError::InvalidUrl);
    }
    let path = url.path();
    let allowed = matches!(path, "/repositories" | "/search/repositories" | "/events")
        || path.strip_prefix("/repos/").is_some_and(|repo| {
            let repo = repo.strip_suffix("/releases/latest").unwrap_or(repo);
            validate_repository_name(repo).is_ok()
        });
    if !allowed {
        return Err(CrawlerError::InvalidUrl);
    }
    Ok(url)
}

fn validate_pagination_url(value: &str, endpoint: &str) -> Result<Url, CrawlerError> {
    let url = validate_api_url(value)?;
    if !matches!(endpoint, "/repositories" | "/search/repositories") || url.path() != endpoint {
        return Err(CrawlerError::InvalidUrl);
    }
    Ok(url)
}

fn public_query(query: &str) -> Result<String, CrawlerError> {
    let normalized: String = query
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '\'' | '"'))
        .flat_map(char::to_lowercase)
        .collect();
    let has_or = query.split_whitespace().any(|part| {
        part.trim_matches(['(', ')', '"', '\''])
            .eq_ignore_ascii_case("OR")
    });
    if query.len() > 4096
        || query.chars().any(char::is_control)
        || has_or
        || [
            "is:private",
            "visibility:private",
            "is:internal",
            "visibility:internal",
        ]
        .iter()
        .any(|qualifier| normalized.contains(qualifier))
    {
        return Err(CrawlerError::InvalidQuery);
    }
    Ok(format!("{query} is:public"))
}

fn search_url(query: &str, page: usize) -> Result<Url, CrawlerError> {
    if !(1..=10).contains(&page) {
        return Err(CrawlerError::InvalidQuery);
    }
    let query = public_query(query)?;
    let mut url = validate_api_url("https://api.github.com/search/repositories")?;
    url.query_pairs_mut()
        .append_pair("q", &query)
        .append_pair("sort", "updated")
        .append_pair("order", "desc")
        .append_pair("per_page", "100")
        .append_pair("page", &page.to_string());
    Ok(url)
}

fn parse_next_link(headers: &HeaderMap, endpoint: &str) -> Result<Option<String>, CrawlerError> {
    let Some(link) = headers.get(LINK) else {
        return Ok(None);
    };
    let link = link.to_str().map_err(|_| CrawlerError::InvalidUrl)?;
    for part in link.split(',') {
        let mut pieces = part.trim().split(';');
        let target = pieces.next().unwrap_or_default().trim();
        let next = pieces.any(|p| {
            p.trim().strip_prefix("rel=").is_some_and(|rel| {
                rel.trim_matches('"')
                    .split_whitespace()
                    .any(|r| r == "next")
            })
        });
        if next {
            let value = target
                .strip_prefix('<')
                .and_then(|v| v.strip_suffix('>'))
                .ok_or(CrawlerError::InvalidUrl)?;
            return Ok(Some(validate_pagination_url(value, endpoint)?.into()));
        }
    }
    Ok(None)
}

fn header_string(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}

fn parse_header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;
    use serde_json::json;

    fn raw(extra: serde_json::Value) -> GithubRepositoryRaw {
        let mut value = json!({"id":1,"name":"repo","full_name":"owner/repo", "html_url":"https://github.com/owner/repo"});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn authenticated_urls_reject_malicious_destinations() {
        for url in [
            "http://api.github.com/repositories",
            "https://api.github.com.evil.test/repositories",
            "https://evil.test/repositories",
            "https://user:secret@api.github.com/repositories",
            "https://@api.github.com/repositories",
            "https://api.github.com:444/repositories",
            "https://api.github.com/repositories#secret",
            "https://api.github.com/repos/a/%2e%2e",
            "https://api.github.com/repos/a/../../repositories",
            "https://api.github.com/repos/a\\b",
            "https://api.github.com/user",
            "https://api.github.com/repositories\n",
        ] {
            assert!(validate_api_url(url).is_err(), "accepted {url}");
        }
        assert!(validate_api_url("https://api.github.com:443/repositories?since=1").is_ok());
    }

    #[test]
    fn pagination_is_origin_and_endpoint_bound() {
        let mut headers = HeaderMap::new();
        headers.insert(LINK, HeaderValue::from_static(
            r#"<https://api.github.com/repositories?since=100>; rel="next", <https://api.github.com/repositories{?since}>; rel="first""#));
        assert_eq!(
            parse_next_link(&headers, "/repositories")
                .unwrap()
                .as_deref(),
            Some("https://api.github.com/repositories?since=100")
        );
        for link in [
            r#"<https://evil.test/repositories>; rel="next""#,
            r#"<https://api.github.com/user>; rel="next""#,
            r#"<https://api.github.com/search/repositories>; rel="next""#,
        ] {
            headers.insert(LINK, HeaderValue::from_str(link).unwrap());
            assert!(parse_next_link(&headers, "/repositories").is_err());
        }
    }

    #[test]
    fn public_search_rejects_private_qualifiers_and_or_bypass() {
        for query in [
            "is:private",
            "visibility:PRIVATE",
            "rust OR is:private",
            "rust OR python",
            "is: \"private\"",
            "visibility:internal",
        ] {
            assert!(search_url(query, 1).is_err());
        }
        let url = search_url("rust stars:>1", 2).unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs["q"], "rust stars:>1 is:public");
        assert_eq!(pairs["sort"], "updated");
        assert_eq!(pairs["page"], "2");
        assert!(search_url("rust", 0).is_err());
        assert!(search_url("rust", 11).is_err());
    }

    #[test]
    fn privacy_is_fail_closed_and_metadata_requires_default_branch() {
        assert!(raw_to_item(raw(json!({}))).private);
        assert!(raw_to_item(raw(json!({"private":false,"visibility":"private"}))).private);
        assert!(raw_to_item(raw(json!({"private":false,"visibility":"internal"}))).private);
        let item = raw_to_item(raw(
            json!({"private":false,"visibility":"public","default_branch":"main",
            "archived":true,"pushed_at":"2026-10-01"}),
        ));
        assert!(!item.private);
        assert!(item.metadata_complete);
        assert!(item.archived);
        assert_eq!(item.pushed_at.as_deref(), Some("2026-10-01"));
        assert!(!raw_to_item(raw(json!({"private":false}))).metadata_complete);
    }

    #[test]
    fn repo_paths_and_errors_are_safe() {
        for name in [
            "a/..",
            "a/.",
            "a/b/c",
            "a/b?secret",
            "a/b#fragment",
            "a/%2f",
            "a/b\\c",
            "/b",
        ] {
            assert!(validate_repository_name(name).is_err());
        }
        assert!(validate_repository_name("octo-org/.github").is_ok());
        let json_error = serde_json::from_str::<u64>("\"secret\"").unwrap_err();
        let error = CrawlerError::from(json_error);
        assert!(!format!("{error} {error:?}").contains("secret"));
        assert_eq!(
            CrawlerError::Http.to_string(),
            "GitHub network request failed"
        );
        let transport = Client::new()
            .get("https://user:token-secret@api.github.com/repositories")
            .header("x-test", "\r\n")
            .build()
            .unwrap_err();
        let error = CrawlerError::from(transport);
        assert!(!format!("{error} {error:?}").contains("token-secret"));
        assert!(!format!("{error} {error:?}").contains("https://"));
    }

    #[test]
    fn search_totals_incompleteness_and_release_deserialize() {
        let result: GithubSearchResponse = serde_json::from_value(json!({
            "total_count":1234,"incomplete_results":true,"items":[]
        }))
        .unwrap();
        assert_eq!(result.total_count, Some(1234));
        assert!(result.incomplete_results);
        let release: GithubReleaseRaw = serde_json::from_value(json!({"tag_name":"v1"})).unwrap();
        assert!(release.draft);
    }

    #[tokio::test]
    async fn invalid_requests_fail_before_authentication_or_network() {
        let crawler = GithubCrawler::with_concurrency(
            TokenPool::new(vec!["test_token".into()], "test".into()),
            1,
            2,
        );
        assert_eq!(crawler.concurrency.available_permits(), 2);
        assert!(matches!(
            crawler
                .fetch_repositories_page("https://evil.test/repositories")
                .await,
            Err(CrawlerError::InvalidUrl)
        ));
        assert!(matches!(
            crawler.fetch_search_page("rust OR is:private", 1).await,
            Err(CrawlerError::InvalidQuery)
        ));
        assert!(matches!(
            crawler.fetch_repository("a/b/../../user").await,
            Err(CrawlerError::InvalidRepository)
        ));
        assert!(matches!(
            crawler.fetch_latest_release("a/b?secret").await,
            Err(CrawlerError::InvalidRepository)
        ));
    }
}
