use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoItem {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    pub owner: String,
    pub owner_type: Option<String>,
    pub html_url: String,
    pub description: Option<String>,
    pub fork: bool,
    pub stars: i64,
    pub forks_count: i64,
    pub language: Option<String>,
    pub license: Option<String>,
    pub topics: Vec<String>,
    pub created_at: Option<String>,
    pub discovered_at: String,
    pub is_priority: bool,
}

// GitHub API: /repositories endpoint item
#[derive(Debug, Clone, Deserialize)]
pub struct GithubRepositoryRaw {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    pub owner: Option<GithubOwnerRaw>,
    pub html_url: String,
    pub description: Option<String>,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub stargazers_count: i64,
    #[serde(default)]
    pub forks_count: i64,
    pub language: Option<String>,
    pub license: Option<GithubLicenseRaw>,
    #[serde(default)]
    pub topics: Vec<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GithubOwnerRaw {
    pub login: String,
    #[serde(rename = "type")]
    pub owner_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GithubLicenseRaw {
    pub key: Option<String>,
    pub name: Option<String>,
    pub spdx_id: Option<String>,
}

// GitHub API: /search/repositories response
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GithubSearchResponse {
    pub total_count: Option<i64>,
    #[serde(default)]
    pub items: Vec<GithubRepositoryRaw>,
}

// GitHub API: /events response
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GithubEventRaw {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub repo: GithubEventRepo,
    pub payload: Option<GithubEventPayload>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GithubEventRepo {
    pub id: i64,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GithubEventPayload {
    pub ref_type: Option<String>,
    pub master_branch: Option<String>,
    pub description: Option<String>,
}
