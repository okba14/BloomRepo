use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, RETRY_AFTER, USER_AGENT};
use reqwest::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateResource {
    Core,
    Search,
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("GitHub credentials are invalid or unavailable")]
    InvalidCredentials,
    #[error("GitHub returned unusable rate-limit metadata")]
    InvalidRateLimit,
}

struct Bucket {
    remaining: u64,
    reset: Instant,
}

struct PoolState {
    tokens: Vec<Option<HeaderValue>>,
    invalid: Vec<bool>,
    next: usize,
    buckets: HashMap<RateResource, Bucket>,
    secondary_until: Instant,
    invalid_rate_limit: bool,
}

#[derive(Clone)]
pub struct TokenPool {
    state: Arc<Mutex<PoolState>>,
    user_agent: HeaderValue,
}

impl TokenPool {
    pub fn new(tokens: Vec<String>, user_agent: String) -> Self {
        let anonymous = tokens.is_empty();
        let tokens: Vec<_> = if tokens.is_empty() {
            vec![None]
        } else {
            tokens
                .into_iter()
                .map(|token| {
                    if token.is_empty()
                        || !token
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"-._~+/=".contains(&c))
                    {
                        return None;
                    }
                    HeaderValue::from_str(&format!("Bearer {token}")).ok()
                })
                .collect()
        };
        // Only the single explicitly unauthenticated entry may have no Authorization.
        let invalid = tokens.iter().map(|t| t.is_none() && !anonymous).collect();
        Self {
            state: Arc::new(Mutex::new(PoolState {
                tokens,
                invalid,
                next: 0,
                buckets: HashMap::new(),
                secondary_until: Instant::now(),
                invalid_rate_limit: false,
            })),
            user_agent: HeaderValue::from_str(&user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static("BloomRepo/2.1")),
        }
    }

    pub async fn get_headers(
        &self,
        resource: RateResource,
    ) -> Result<(HeaderMap, Option<String>), TokenError> {
        loop {
            let mut state = self.state.lock().await;
            if state.invalid.iter().all(|invalid| *invalid) {
                return Err(TokenError::InvalidCredentials);
            }
            if state.invalid_rate_limit {
                return Err(TokenError::InvalidRateLimit);
            }
            let now = Instant::now();
            if let Some(wait) = pool_wait(&state, resource, now) {
                drop(state);
                tokio::time::sleep(wait).await;
                // Recheck: another response may have extended the pool-wide cooldown.
                continue;
            }
            if let Some(bucket) = state.buckets.get_mut(&resource) {
                if bucket.reset > now {
                    bucket.remaining = bucket.remaining.saturating_sub(1);
                }
            }
            let index = (0..state.tokens.len())
                .map(|offset| (state.next + offset) % state.tokens.len())
                .find(|index| !state.invalid[*index])
                .ok_or(TokenError::InvalidCredentials)?;
            state.next = (index + 1) % state.tokens.len();
            let mut headers = HeaderMap::new();
            headers.insert(
                ACCEPT,
                HeaderValue::from_static("application/vnd.github+json"),
            );
            headers.insert(USER_AGENT, self.user_agent.clone());
            headers.insert(
                "x-github-api-version",
                HeaderValue::from_static("2022-11-28"),
            );
            let token = if let Some(value) = &state.tokens[index] {
                let mut value = value.clone();
                value.set_sensitive(true);
                let token = value.to_str().ok().and_then(|v| v.strip_prefix("Bearer "));
                let token = token.map(ToOwned::to_owned);
                headers.insert(AUTHORIZATION, value);
                token
            } else {
                None
            };
            return Ok((headers, token));
        }
    }

    #[allow(dead_code)]
    pub async fn update_limits(
        &self,
        token: Option<&str>,
        resource: RateResource,
        headers: &HeaderMap,
    ) {
        self.observe_response(token, resource, StatusCode::OK, headers)
            .await;
    }

    pub async fn observe_response(
        &self,
        token: Option<&str>,
        requested_resource: RateResource,
        status: StatusCode,
        headers: &HeaderMap,
    ) {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        if status == StatusCode::UNAUTHORIZED {
            for index in 0..state.tokens.len() {
                let candidate = state.tokens[index]
                    .as_ref()
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "));
                if candidate == token {
                    state.invalid[index] = true;
                }
            }
        }
        let resource = match headers
            .get("x-ratelimit-resource")
            .and_then(|v| v.to_str().ok())
        {
            Some("core") => RateResource::Core,
            Some("search") => RateResource::Search,
            _ => requested_resource,
        };
        let remaining = header_u64(headers, "x-ratelimit-remaining");
        if headers.contains_key("x-ratelimit-remaining") && remaining.is_none()
            || headers.contains_key("x-ratelimit-reset") && reset_delay(headers).is_none()
            || headers.contains_key(RETRY_AFTER) && retry_after(headers).is_none()
        {
            state.invalid_rate_limit = true;
            return;
        }
        if let Some(remaining) = remaining {
            let delay = reset_delay(headers).unwrap_or(Duration::from_secs(60));
            let Some(reset) = now.checked_add(delay) else {
                state.invalid_rate_limit = true;
                return;
            };
            let bucket = state
                .buckets
                .entry(resource)
                .or_insert(Bucket { remaining, reset });
            if bucket.reset <= now {
                *bucket = Bucket { remaining, reset };
            } else {
                // Out-of-order responses and token rotation must not replenish a live bucket.
                bucket.remaining = bucket.remaining.min(remaining);
                bucket.reset = bucket.reset.max(reset);
            }
        }
        let retry = retry_after(headers);
        let secondary = status == StatusCode::TOO_MANY_REQUESTS
            || (status == StatusCode::FORBIDDEN && remaining != Some(0));
        if retry.is_some() || secondary {
            let delay = retry.unwrap_or(Duration::from_secs(60));
            let Some(deadline) = now.checked_add(delay) else {
                state.invalid_rate_limit = true;
                return;
            };
            state.secondary_until = state.secondary_until.max(deadline);
        }
    }

    pub async fn wait_if_exhausted(&self, resource: RateResource) -> Option<u64> {
        let state = self.state.lock().await;
        pool_wait(&state, resource, Instant::now()).map(ceil_seconds)
    }
}

fn pool_wait(state: &PoolState, resource: RateResource, now: Instant) -> Option<Duration> {
    let primary = state
        .buckets
        .get(&resource)
        .filter(|bucket| bucket.remaining == 0)
        .map(|bucket| bucket.reset)
        .unwrap_or(now);
    let deadline = state.secondary_until.max(primary);
    (deadline > now).then(|| deadline.duration_since(now))
}

fn ceil_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
}

fn header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse().ok()
}

fn reset_delay(headers: &HeaderMap) -> Option<Duration> {
    let reset = header_u64(headers, "x-ratelimit-reset")?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    Some(Duration::from_secs(reset.saturating_sub(now).max(1)))
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds.max(1)));
    }
    let date = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    Some(Duration::from_secs(
        date.timestamp()
            .saturating_sub(chrono::Utc::now().timestamp())
            .max(1) as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authorization_is_sensitive_and_versioned() {
        let pool = TokenPool::new(vec!["test_token".into()], "test".into());
        let (headers, _) = pool.get_headers(RateResource::Core).await.unwrap();
        assert!(headers[AUTHORIZATION].is_sensitive());
        assert_eq!(headers["x-github-api-version"], "2022-11-28");
        assert!(!format!("{headers:?}").contains("test_token"));
    }

    #[tokio::test]
    async fn waits_for_full_reset_and_honors_reported_resource() {
        let pool = TokenPool::new(vec!["one".into(), "two".into()], "test".into());
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        headers.insert("x-ratelimit-resource", HeaderValue::from_static("search"));
        headers.insert(
            "x-ratelimit-reset",
            HeaderValue::from_str(&(chrono::Utc::now().timestamp() + 600).to_string()).unwrap(),
        );
        pool.update_limits(Some("one"), RateResource::Core, &headers)
            .await;
        assert!(pool.wait_if_exhausted(RateResource::Search).await.unwrap() >= 599);
        assert_eq!(pool.wait_if_exhausted(RateResource::Core).await, None);
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            pool.get_headers(RateResource::Search)
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn secondary_limit_is_global_and_not_clamped() {
        let pool = TokenPool::new(vec!["one".into(), "two".into()], "test".into());
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("1800"));
        pool.observe_response(
            Some("one"),
            RateResource::Search,
            StatusCode::TOO_MANY_REQUESTS,
            &headers,
        )
        .await;
        assert!(pool.wait_if_exhausted(RateResource::Core).await.unwrap() >= 1799);
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            pool.get_headers(RateResource::Core)
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn reset_expiry_allows_requests_and_unauthorized_is_distinct() {
        let pool = TokenPool::new(vec!["one".into()], "test".into());
        pool.state.lock().await.buckets.insert(
            RateResource::Core,
            Bucket {
                remaining: 0,
                reset: Instant::now(),
            },
        );
        assert!(pool.get_headers(RateResource::Core).await.is_ok());
        pool.observe_response(
            Some("one"),
            RateResource::Core,
            StatusCode::UNAUTHORIZED,
            &HeaderMap::new(),
        )
        .await;
        assert!(matches!(
            pool.get_headers(RateResource::Core).await,
            Err(TokenError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn malformed_credentials_never_fall_back_to_anonymous() {
        let pool = TokenPool::new(vec!["bad\r\nsecret".into()], "test".into());
        assert!(matches!(
            pool.get_headers(RateResource::Core).await,
            Err(TokenError::InvalidCredentials)
        ));
        let anonymous = TokenPool::new(Vec::new(), "test".into());
        assert!(!anonymous
            .get_headers(RateResource::Core)
            .await
            .unwrap()
            .0
            .contains_key(AUTHORIZATION));
    }

    #[tokio::test]
    async fn invalid_or_overflowing_rate_limits_fail_closed() {
        for value in ["18446744073709551615", "not-a-date"] {
            let pool = TokenPool::new(vec!["one".into(), "two".into()], "test".into());
            let mut headers = HeaderMap::new();
            headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
            pool.observe_response(
                Some("one"),
                RateResource::Core,
                StatusCode::TOO_MANY_REQUESTS,
                &headers,
            )
            .await;
            assert!(matches!(
                pool.get_headers(RateResource::Search).await,
                Err(TokenError::InvalidRateLimit)
            ));
        }
    }

    #[tokio::test]
    async fn http_date_retry_after_and_reservations_are_honored() {
        let pool = TokenPool::new(Vec::new(), "test".into());
        let mut headers = HeaderMap::new();
        let date = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        headers.insert(RETRY_AFTER, HeaderValue::from_str(&date).unwrap());
        pool.observe_response(None, RateResource::Core, StatusCode::FORBIDDEN, &headers)
            .await;
        assert!(pool.wait_if_exhausted(RateResource::Search).await.unwrap() >= 599);
        pool.state.lock().await.secondary_until = Instant::now();
        pool.state.lock().await.buckets.insert(
            RateResource::Core,
            Bucket {
                remaining: 1,
                reset: Instant::now() + Duration::from_secs(600),
            },
        );
        pool.get_headers(RateResource::Core).await.unwrap();
        assert!(pool.wait_if_exhausted(RateResource::Core).await.unwrap() >= 599);
        assert_eq!(ceil_seconds(Duration::from_millis(60_001)), 61);
    }
}
