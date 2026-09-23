use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppState {
    pub schema_version: u32,
    #[serde(alias = "last_id")]
    pub sequential_since: i64,
    pub sequential_next_url: Option<String>,
    pub search_watermark: String,
    pub last_search_at: i64,
    pub last_events_at: i64,
    pub events_etag: Option<String>,
    pub search_etag: Option<String>,
    pub checked: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            schema_version: 2,
            sequential_since: 0,
            sequential_next_url: None,
            search_watermark: chrono::Utc::now().to_rfc3339(),
            last_search_at: 0,
            last_events_at: 0,
            events_etag: None,
            search_etag: None,
            checked: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl AppState {
    pub fn load<P: AsRef<Path>>(path: P) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|data| serde_json::from_str(&data).ok())
            .unwrap_or_default()
    }

    pub fn save_atomic<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let path = path.as_ref();
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        fs::write(&tmp, json)?;
        fs::rename(tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_state_round_trip_preserves_independent_cursors() {
        let path =
            std::env::temp_dir().join(format!("bloomrepo-state-{}.json", std::process::id()));
        let state = AppState {
            sequential_since: 123,
            search_watermark: "2026-09-22T18:00:00Z".into(),
            ..Default::default()
        };
        state.save_atomic(&path).unwrap();
        let loaded = AppState::load(&path);
        assert_eq!(loaded.sequential_since, 123);
        assert_eq!(loaded.search_watermark, "2026-09-22T18:00:00Z");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_state_file_is_backward_compatible() {
        let legacy_json = r#"{
  "last_id": 1382156998,
  "checked": "2026-09-22T18:42:31.542756400+00:00"
}"#;
        let loaded: AppState = serde_json::from_str(legacy_json).expect("deserialize legacy json");
        assert_eq!(loaded.sequential_since, 1382156998);
        assert_eq!(loaded.schema_version, 2);
        assert_eq!(loaded.last_events_at, 0);
    }
}
