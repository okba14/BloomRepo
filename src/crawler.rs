use crate::models::{GithubEventRaw, GithubRepositoryRaw, GithubSearchResponse, RepoItem};
use crate::tokens::{RateResource, TokenPool};
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderName, ETAG, IF_NONE_MATCH, LINK, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrawlerError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("rate limited; retry in {0}s")]
    RateLimited(u64),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("GitHub returned HTTP {status}: {body}")]
    Api { status: StatusCode, body: String },
}

pub struct GithubCrawler {
    client: Client,
    token_pool: TokenPool,
}

pub struct Page<T> {
    pub items: Vec<T>,
    pub next_url: Option<String>,
    pub etag: Option<String>,
    pub poll_interval: Option<u64>,
}

impl GithubCrawler {
    pub fn new(token_pool: TokenPool, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| Client::new());
        Self { client, token_pool }
    }

    pub async fn fetch_repositories_page(
        &self,
        url: &str,
    ) -> Result<Page<GithubRepositoryRaw>, CrawlerError> {
        let (headers, token) = self.token_pool.get_headers(RateResource::Core).await;
        let response = self.client.get(url).headers(headers).send().await?;
        let status = response.status();
        let response_headers = response.headers().clone();
        self.token_pool
            .update_limits(token.as_deref(), RateResource::Core, &response_headers)
            .await;
        if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
            return Err(CrawlerError::RateLimited(retry_seconds(
                &response_headers,
                60,
            )));
        }
        let body = response.text().await?;
        if !status.is_success() {
            return Err(CrawlerError::Api { status, body });
        }
        let items = serde_json::from_str(&body)?;
        Ok(Page {
            items,
            next_url: parse_next_link(&response_headers),
            etag: header_string(&response_headers, ETAG),
            poll_interval: None,
        })
    }

    pub async fn fetch_events(&self, etag: Option<&str>) -> Result<Page<RepoItem>, CrawlerError> {
        if let Some(wait) = self.token_pool.wait_if_exhausted(RateResource::Core).await {
            tokio::time::sleep(Duration::from_secs(wait.min(60))).await;
        }
        let (mut headers, token) = self.token_pool.get_headers(RateResource::Core).await;
        if let Some(etag) = etag {
            if let Ok(value) = etag.parse() {
                headers.insert(IF_NONE_MATCH, value);
            }
        }
        let response = self
            .client
            .get("https://api.github.com/events?per_page=100")
            .headers(headers)
            .send()
            .await?;
        let status = response.status();
        let response_headers = response.headers().clone();
        self.token_pool
            .update_limits(token.as_deref(), RateResource::Core, &response_headers)
            .await;
        if status == StatusCode::NOT_MODIFIED {
            return Ok(Page {
                items: vec![],
                next_url: None,
                etag: etag.map(ToOwned::to_owned),
                poll_interval: parse_header_u64(
                    &response_headers,
                    HeaderName::from_static("x-poll-interval"),
                ),
            });
        }
        if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
            return Err(CrawlerError::RateLimited(retry_seconds(
                &response_headers,
                60,
            )));
        }
        let body = response.text().await?;
        if !status.is_success() {
            return Err(CrawlerError::Api { status, body });
        }
        let events: Vec<GithubEventRaw> = serde_json::from_str(&body)?;
        let discovered = events.into_iter().filter_map(event_to_repo).collect();
        Ok(Page {
            items: discovered,
            next_url: None,
            etag: header_string(&response_headers, ETAG),
            poll_interval: parse_header_u64(
                &response_headers,
                HeaderName::from_static("x-poll-interval"),
            ),
        })
    }

    pub async fn fetch_search_query(
        &self,
        query: &str,
    ) -> Result<Page<GithubRepositoryRaw>, CrawlerError> {
        if let Some(wait) = self
            .token_pool
            .wait_if_exhausted(RateResource::Search)
            .await
        {
            tokio::time::sleep(Duration::from_secs(wait.min(60))).await;
        }
        let url = format!(
            "https://api.github.com/search/repositories?q={}&sort=created&order=desc&per_page=100",
            url_encode(query)
        );
        let (headers, token) = self.token_pool.get_headers(RateResource::Search).await;
        let response = self.client.get(url).headers(headers).send().await?;
        let status = response.status();
        let response_headers = response.headers().clone();
        self.token_pool
            .update_limits(token.as_deref(), RateResource::Search, &response_headers)
            .await;
        if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
            return Err(CrawlerError::RateLimited(retry_seconds(
                &response_headers,
                60,
            )));
        }
        let body = response.text().await?;
        if !status.is_success() {
            return Err(CrawlerError::Api { status, body });
        }
        let result: GithubSearchResponse = serde_json::from_str(&body)?;
        Ok(Page {
            items: result.items,
            next_url: None,
            etag: header_string(&response_headers, ETAG),
            poll_interval: None,
        })
    }

    pub async fn fetch_latest_repo_id(&self) -> Result<Option<i64>, CrawlerError> {
        if let Some(wait) = self
            .token_pool
            .wait_if_exhausted(RateResource::Search)
            .await
        {
            tokio::time::sleep(Duration::from_secs(wait.min(60))).await;
        }
        let url = "https://api.github.com/search/repositories?q=stars:%3E=0&sort=created&order=desc&per_page=1";
        let (headers, token) = self.token_pool.get_headers(RateResource::Search).await;
        let response = self.client.get(url).headers(headers).send().await?;
        let status = response.status();
        let response_headers = response.headers().clone();
        self.token_pool
            .update_limits(token.as_deref(), RateResource::Search, &response_headers)
            .await;
        if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
            return Err(CrawlerError::RateLimited(retry_seconds(
                &response_headers,
                60,
            )));
        }
        let body = response.text().await?;
        if !status.is_success() {
            return Err(CrawlerError::Api { status, body });
        }
        let result: GithubSearchResponse = serde_json::from_str(&body)?;
        Ok(result.items.first().map(|r| r.id))
    }
}

fn event_to_repo(event: GithubEventRaw) -> Option<RepoItem> {
    let payload = event.payload?;
    if event.event_type != "CreateEvent" || payload.ref_type.as_deref() != Some("repository") {
        return None;
    }
    let full_name = event.repo.name;
    let (owner, name) = full_name
        .split_once('/')
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .unwrap_or_else(|| ("unknown".into(), full_name.clone()));
    Some(RepoItem {
        id: event.repo.id,
        name,
        full_name: full_name.clone(),
        owner,
        owner_type: None,
        html_url: format!("https://github.com/{full_name}"),
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
    })
}

fn parse_next_link(headers: &HeaderMap) -> Option<String> {
    let link = headers.get(LINK)?.to_str().ok()?;
    link.split(',').find_map(|part| {
        let mut pieces = part.trim().split(';');
        let url = pieces
            .next()?
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>');
        let rel = pieces.any(|p| p.trim() == "rel=\"next\"");
        rel.then(|| url.to_string())
    })
}
fn header_string(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}
fn parse_header_u64(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<u64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}
fn retry_seconds(headers: &HeaderMap, fallback: u64) -> u64 {
    parse_header_u64(headers, RETRY_AFTER)
        .unwrap_or(fallback)
        .clamp(1, 900)
}
fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b':'
            | b'>'
            | b'<' => (b as char).to_string(),
            b' ' => "+".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, LINK};

    #[test]
    fn test_parse_next_link() {
        let mut headers = HeaderMap::new();
        headers.insert(
            LINK,
            HeaderValue::from_static(
                r#"<https://api.github.com/repositories?since=100&per_page=100>; rel="next", <https://api.github.com/repositories{?since}>; rel="first""#,
            ),
        );
        let next = parse_next_link(&headers);
        assert_eq!(
            next,
            Some("https://api.github.com/repositories?since=100&per_page=100".to_string())
        );
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("created:>2026-09-01"), "created:>2026-09-01");
        assert_eq!(url_encode("hello world"), "hello+world");
    }
}
