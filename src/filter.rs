use crate::config::FilteringConfig;
use crate::crawler::validate_repository_name;
use crate::models::{Assessment, RepoItem};
use regex::Regex;

pub struct RepoFilter {
    config: FilteringConfig,
    compiled_patterns: Vec<Regex>,
}

impl RepoFilter {
    pub fn new(config: FilteringConfig) -> Self {
        let compiled_patterns = config
            .ignore_name_patterns
            .iter()
            .filter_map(|pattern| Regex::new(pattern).ok())
            .collect();
        Self { config, compiled_patterns }
    }

    pub fn evaluate(&self, item: &mut RepoItem) -> Assessment {
        item.is_priority = false;
        let mut result = Assessment {
            relevance: 20,
            confidence: if item.metadata_complete { 70 } else { 20 },
            decision: "accepted".into(),
            evaluated_at: chrono::Utc::now().to_rfc3339(),
            ..Default::default()
        };
        if item.private || validate_repository_name(&item.full_name).is_err() {
            result.decision = "rejected".into();
            result.reasons.push("Public visibility and a valid repository identity are required.".into());
            return result;
        }
        result.reasons.push(format!("Public metadata observation from {}.", item.source));
        if !item.metadata_complete {
            result.decision = "deferred".into();
            result.missing.push("Detailed metadata has not been verified; enrich before notification.".into());
        }
        for (present, label) in [
            (item.language.is_some(), "Language is unavailable."),
            (item.license.is_some(), "License information is unavailable."),
            (item.description.as_ref().is_some_and(|s| !s.trim().is_empty()), "Description is unavailable."),
        ] {
            if present {
                result.confidence = result.confidence.saturating_add(10).min(100);
            } else {
                result.missing.push(label.into());
            }
        }
        result.missing.push("Security importance is unassessed (0), not a safety score. Run an authorized local security analysis.".into());

        let text = format!("{} {} {}", item.full_name, item.description.as_deref().unwrap_or(""), item.topics.join(" ")).to_lowercase();
        for keyword in &self.config.priority_keywords {
            let keyword = keyword.trim();
            if !keyword.is_empty() && text.contains(&keyword.to_lowercase()) {
                item.is_priority = true;
                result.relevance = result.relevance.saturating_add(20).min(100);
                result.reasons.push(format!("Interest rule matched keyword: {keyword}."));
            }
        }
        if !item.is_priority {
            result.reasons.push("No configured interest keyword matched; no security conclusion was inferred.".into());
        }
        if self.config.enable_spam_filter {
            if self.compiled_patterns.iter().any(|pattern| pattern.is_match(&item.name)) {
                result.decision = "rejected".into();
                result.reasons.push("Repository name matches an exclusion pattern.".into());
            }
            if self.config.ignore_forks && item.metadata_complete && item.fork {
                result.decision = "rejected".into();
                result.reasons.push("Fork excluded by the current rule.".into());
            }
            if item.metadata_complete && item.description.as_deref().unwrap_or("").trim().chars().count() < self.config.min_description_length {
                result.decision = "rejected".into();
                result.reasons.push("Description is shorter than the configured minimum.".into());
            }
            if !self.config.allowed_languages.is_empty() {
                match &item.language {
                    Some(language) if !self.config.allowed_languages.iter().any(|allowed| allowed.eq_ignore_ascii_case(language)) => {
                        result.decision = "rejected".into();
                        result.reasons.push("Known language is outside the configured allowlist.".into());
                    }
                    None if result.decision != "rejected" => {
                        result.decision = "deferred".into();
                        result.reasons.push("Language-dependent rule deferred; an unknown language is not a rejection.".into());
                    }
                    _ => {}
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> RepoItem {
        serde_json::from_value(serde_json::json!({
            "id":1,"name":"agent-tool","full_name":"alice/agent-tool","owner":"alice",
            "html_url":"https://github.com/alice/agent-tool","description":"A useful agent",
            "fork":false,"stars":0,"forks_count":0,"language":"Rust","license":null,
            "topics":["agent"],"created_at":null,"discovered_at":"now","is_priority":false,
            "metadata_complete":true,"source":"search"
        })).unwrap()
    }

    #[test]
    fn interest_is_explained_without_inventing_security_risk() {
        let filter = RepoFilter::new(FilteringConfig { enable_spam_filter:false, priority_keywords:vec!["agent".into()], ..Default::default() });
        let mut repo = item();
        let result = filter.evaluate(&mut repo);
        assert_eq!(result.decision, "accepted");
        assert!(repo.is_priority);
        assert!(result.reasons.iter().any(|s| s.contains("agent")));
        assert_eq!(result.security_importance, 0);
    }

    #[test]
    fn unknown_language_is_deferred_not_discarded() {
        let filter = RepoFilter::new(FilteringConfig { allowed_languages:vec!["Rust".into()], ..Default::default() });
        let mut repo = item();
        repo.language = None;
        assert_eq!(filter.evaluate(&mut repo).decision, "deferred");
        repo.language = Some("Python".into());
        assert_eq!(filter.evaluate(&mut repo).decision, "rejected");
    }

    #[test]
    fn priority_resets_and_empty_keywords_match_nothing() {
        let mut repo = item();
        repo.is_priority = true;
        let filter = RepoFilter::new(FilteringConfig { priority_keywords:vec![" ".into()], ..Default::default() });
        filter.evaluate(&mut repo);
        assert!(!repo.is_priority);
    }

    #[test]
    fn visibility_and_sparse_metadata_fail_closed() {
        let filter = RepoFilter::new(FilteringConfig::default());
        let mut repo = item();
        repo.metadata_complete = false;
        assert_eq!(filter.evaluate(&mut repo).decision, "deferred");
        repo.private = true;
        assert_eq!(filter.evaluate(&mut repo).decision, "rejected");
    }

    #[test]
    fn known_exclusion_still_rejects_sparse_observation() {
        let filter = RepoFilter::new(FilteringConfig::default());
        let mut repo = item();
        repo.metadata_complete = false;
        repo.name = "test-42".into();
        assert_eq!(filter.evaluate(&mut repo).decision, "rejected");
    }
}
