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
    #[serde(default)]
    pub metadata_complete: bool,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub pushed_at: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub latest_release: Option<String>,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Assessment {
    pub relevance: u8,
    pub confidence: u8,
    pub security_importance: u8,
    pub decision: String,
    pub reasons: Vec<String>,
    pub missing: Vec<String>,
    pub evaluated_at: String,
}

// GitHub API: /repositories endpoint item
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
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
    #[serde(default = "github_private_default")]
    pub private: bool,
    pub visibility: Option<String>,
    #[serde(default)]
    pub archived: bool,
    pub pushed_at: Option<String>,
    pub default_branch: Option<String>,
}

fn github_private_default() -> bool {
    true
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
    pub total_count: Option<usize>,
    #[serde(default)]
    pub incomplete_results: bool,
    #[serde(default)]
    pub items: Vec<GithubRepositoryRaw>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubReleaseRaw {
    pub tag_name: String,
    #[serde(default = "github_private_default")]
    pub draft: bool,
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
