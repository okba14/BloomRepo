use crate::config::FilteringConfig;
use crate::models::RepoItem;
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
            .filter_map(|p| Regex::new(p).ok())
            .collect();
        Self {
            config,
            compiled_patterns,
        }
    }

    pub fn process(&self, item: &mut RepoItem) -> bool {
        if self.config.enable_spam_filter {
            if self.config.ignore_forks && item.fork {
                return false;
            }
            if self
                .compiled_patterns
                .iter()
                .any(|pattern| pattern.is_match(&item.name))
            {
                return false;
            }
            let description_length = item
                .description
                .as_deref()
                .map(str::trim)
                .map(str::len)
                .unwrap_or(0);
            if description_length < self.config.min_description_length {
                return false;
            }
            if !self.config.allowed_languages.is_empty()
                && !item.language.as_ref().is_some_and(|lang| {
                    self.config
                        .allowed_languages
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(lang))
                })
            {
                return false;
            }
        }
        if !self.config.priority_keywords.is_empty() {
            let name = item.name.to_lowercase();
            let description = item.description.as_deref().unwrap_or("").to_lowercase();
            item.is_priority = self.config.priority_keywords.iter().any(|keyword| {
                let keyword = keyword.to_lowercase();
                name.contains(&keyword)
                    || description.contains(&keyword)
                    || item
                        .topics
                        .iter()
                        .any(|topic| topic.to_lowercase().contains(&keyword))
            });
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> RepoItem {
        RepoItem {
            id: 1,
            name: "agent-tool".into(),
            full_name: "alice/agent-tool".into(),
            owner: "alice".into(),
            owner_type: None,
            html_url: "https://github.com/alice/agent-tool".into(),
            description: Some("A useful agent".into()),
            fork: false,
            stars: 0,
            forks_count: 0,
            language: Some("Rust".into()),
            license: None,
            topics: vec!["agent".into()],
            created_at: None,
            discovered_at: "now".into(),
            is_priority: false,
        }
    }

    #[test]
    fn disabled_spam_filter_still_marks_priority() {
        let config = FilteringConfig {
            enable_spam_filter: false,
            priority_keywords: vec!["agent".into()],
            ..Default::default()
        };
        let filter = RepoFilter::new(config);
        let mut repo = item();
        assert!(filter.process(&mut repo));
        assert!(repo.is_priority);
    }
}
