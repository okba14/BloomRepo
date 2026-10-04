use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchWindow {
    pub start: String,
    pub end: String,
    pub page: usize,
    pub query_index: usize,
    pub expected_total: Option<usize>,
    #[serde(default)]
    pub query: String,
}

#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub search_windows: Vec<SearchWindow>,
    #[serde(default)]
    pub events_next_at: i64,
    #[serde(default)]
    pub enrichment_next_at: i64,
    #[serde(default)]
    pub sources: Vec<crate::db::SourceStatus>,
    #[serde(default)]
    pub search_target_end: String,
    #[serde(default)]
    pub pending_event_repositories: Vec<String>,
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("schema_version", &self.schema_version)
            .field("sequential_since", &self.sequential_since)
            .field("search_watermark", &self.search_watermark)
            .field("search_windows", &self.search_windows)
            .field("source_count", &self.sources.len())
            .finish_non_exhaustive()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            schema_version: 3,
            sequential_since: 0,
            sequential_next_url: None,
            search_watermark: chrono::Utc::now().to_rfc3339(),
            last_search_at: 0,
            last_events_at: 0,
            events_etag: None,
            search_etag: None,
            checked: chrono::Utc::now().to_rfc3339(),
            search_windows: Vec::new(),
            events_next_at: 0,
            enrichment_next_at: 0,
            sources: Vec::new(),
            search_target_end: String::new(),
            pending_event_repositories: Vec::new(),
        }
    }
}

impl AppState {
    pub fn load_checked<P: AsRef<Path>>(path: P) -> io::Result<Option<Self>> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut data = String::new();
        file.take(256 * 1024 + 1).read_to_string(&mut data)?;
        if data.len() > 256 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted state exceeds the size limit",
            ));
        }
        let mut state: Self = serde_json::from_str(&data).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid persisted state JSON")
        })?;
        if !(1..=3).contains(&state.schema_version) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported persisted state schema version",
            ));
        }
        state.schema_version = 3;
        Ok(Some(state))
    }

    #[deprecated(note = "Persist authoritative state in the database cycle transaction")]
    #[allow(dead_code)]
    pub fn save_atomic<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let path = path.as_ref();
        let tmp = path.with_extension(format!(
            "json.{}.{}.tmp",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        let result = (|| {
            file.write_all(&json)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn atomic_state_round_trip_preserves_independent_cursors() {
        let path =
            std::env::temp_dir().join(format!("bloomrepo-state-{}.json", std::process::id()));
        let state = AppState {
            sequential_since: 123,
            search_watermark: "2026-09-22T18:00:00Z".into(),
            search_windows: vec![SearchWindow {
                start: "2026-09-22T18:00:00Z".into(),
                end: "2026-09-22T19:00:00Z".into(),
                page: 2,
                query_index: 1,
                expected_total: Some(150),
                query: String::new(),
            }],
            events_next_at: 1234,
            enrichment_next_at: 2345,
            sources: vec![crate::db::SourceStatus {
                name: "search".into(),
                status: "healthy".into(),
                message: "OK".into(),
                last_success_at: 100,
                next_allowed_at: 200,
            }],
            ..Default::default()
        };
        state.save_atomic(&path).unwrap();
        let loaded = AppState::load_checked(&path).unwrap().unwrap();
        assert_eq!(loaded.sequential_since, 123);
        assert_eq!(loaded.search_watermark, "2026-09-22T18:00:00Z");
        assert_eq!(loaded.search_windows[0].page, 2);
        assert_eq!(loaded.search_windows[0].query_index, 1);
        assert_eq!(loaded.search_windows[0].expected_total, Some(150));
        assert_eq!(loaded.events_next_at, 1234);
        assert_eq!(loaded.enrichment_next_at, 2345);
        assert_eq!(loaded.sources[0].name, "search");
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
        assert_eq!(loaded.schema_version, 3);
        assert_eq!(loaded.last_events_at, 0);
    }

    #[test]
    fn checked_load_distinguishes_missing_corrupt_and_future_state() {
        let path = std::env::temp_dir().join(format!(
            "bloomrepo-state-invalid-{}.json",
            std::process::id()
        ));
        assert!(AppState::load_checked(&path).unwrap().is_none());
        fs::write(&path, r#"{"token": "do-not-echo-me", "#).unwrap();
        let error = AppState::load_checked(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!error.to_string().contains("do-not-echo-me"));
        for version in [0, 4, u32::MAX] {
            fs::write(&path, format!(r#"{{"schema_version":{version}}}"#)).unwrap();
            assert_eq!(
                AppState::load_checked(&path).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn checked_load_migrates_legacy_versions_without_losing_cursors() {
        let path = std::env::temp_dir().join(format!(
            "bloomrepo-state-migrate-{}.json",
            std::process::id()
        ));
        for version in [1, 2] {
            fs::write(&path, format!(r#"{{"schema_version":{version},"last_id":42,"last_search_at":100,"events_etag":"etag","search_watermark":"2026-01-01T00:00:00Z"}}"#)).unwrap();
            let loaded = AppState::load_checked(&path).unwrap().unwrap();
            assert_eq!(loaded.schema_version, 3);
            assert_eq!(loaded.sequential_since, 42);
            assert_eq!(loaded.last_search_at, 100);
            assert_eq!(loaded.events_etag.as_deref(), Some("etag"));
            assert_eq!(loaded.search_watermark, "2026-01-01T00:00:00Z");
            assert!(loaded.search_windows.is_empty());
        }
        fs::remove_file(path).unwrap();
    }
}
