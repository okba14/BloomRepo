use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateResource {
    Core,
    Search,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    remaining: u32,
    reset_timestamp: i64,
    exhausted: bool,
}

#[derive(Debug, Clone)]
struct TokenStatus {
    token: Option<String>,
    buckets: HashMap<RateResource, Bucket>,
}

#[derive(Clone)]
pub struct TokenPool {
    tokens: Arc<RwLock<Vec<TokenStatus>>>,
    counter: Arc<AtomicUsize>,
    user_agent: String,
}

impl TokenPool {
    pub fn new(tokens: Vec<String>, user_agent: String) -> Self {
        let list = if tokens.is_empty() {
            vec![None]
        } else {
            tokens.into_iter().map(Some).collect()
        };
        let statuses = list
            .into_iter()
            .map(|token| {
                let mut buckets = HashMap::new();
                buckets.insert(
                    RateResource::Core,
                    Bucket {
                        remaining: 60,
                        reset_timestamp: 0,
                        exhausted: false,
                    },
                );
                buckets.insert(
                    RateResource::Search,
                    Bucket {
                        remaining: 10,
                        reset_timestamp: 0,
                        exhausted: false,
                    },
                );
                TokenStatus { token, buckets }
            })
            .collect();
        Self {
            tokens: Arc::new(RwLock::new(statuses)),
            counter: Arc::new(AtomicUsize::new(0)),
            user_agent,
        }
    }

    pub async fn get_headers(&self, resource: RateResource) -> (HeaderMap, Option<String>) {
        let now = chrono::Utc::now().timestamp();
        let statuses = self.tokens.read().await;
        let start = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut best = start % statuses.len().max(1);
        let mut best_remaining = 0;
        for (idx, status) in statuses.iter().enumerate() {
            let remaining = status
                .buckets
                .get(&resource)
                .map(|b| b.remaining)
                .unwrap_or(0);
            if status
                .buckets
                .get(&resource)
                .map(|b| !b.exhausted || b.reset_timestamp <= now)
                .unwrap_or(false)
                && remaining > best_remaining
            {
                best_remaining = remaining;
                best = idx;
            }
        }
        let selected = &statuses[best];
        let token = selected.token.clone();
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static("BloomRepo/2.1")),
        );
        if let Some(ref value) = token {
            if let Ok(auth) = HeaderValue::from_str(&format!("Bearer {value}")) {
                headers.insert(AUTHORIZATION, auth);
            }
        }
        (headers, token)
    }

    pub async fn update_limits(
        &self,
        token: Option<&str>,
        resource: RateResource,
        headers: &HeaderMap,
    ) {
        let remaining = headers
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let reset = headers
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        if let (Some(remaining), Some(reset)) = (remaining, reset) {
            let mut statuses = self.tokens.write().await;
            for status in statuses.iter_mut() {
                if status.token.as_deref() == token {
                    status.buckets.insert(
                        resource,
                        Bucket {
                            remaining,
                            reset_timestamp: reset,
                            exhausted: remaining <= 1,
                        },
                    );
                    break;
                }
            }
        }
    }

    pub async fn wait_if_exhausted(&self, resource: RateResource) -> Option<u64> {
        let now = chrono::Utc::now().timestamp();
        let statuses = self.tokens.read().await;
        let mut all = true;
        let mut wait = 60;
        for status in statuses.iter() {
            if let Some(bucket) = status.buckets.get(&resource) {
                if (!bucket.exhausted || bucket.reset_timestamp <= now) && bucket.remaining > 1 {
                    all = false;
                    break;
                }
                wait = wait.min(bucket.reset_timestamp.saturating_sub(now).max(1) as u64);
            }
        }
        if all {
            Some(wait)
        } else {
            None
        }
    }
}
