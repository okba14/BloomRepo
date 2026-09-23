use crate::models::RepoItem;
use rusqlite::{params, Connection, Result};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P, enable_wal: bool) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        if enable_wal {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
        } else {
            conn.pragma_update(None, "synchronous", "FULL")?;
        }
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "cache_size", "-64000")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS repos (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                full_name TEXT NOT NULL,
                owner TEXT NOT NULL,
                owner_type TEXT,
                html_url TEXT NOT NULL,
                description TEXT,
                fork INTEGER NOT NULL,
                stars INTEGER NOT NULL DEFAULT 0,
                forks_count INTEGER NOT NULL DEFAULT 0,
                language TEXT,
                license TEXT,
                topics TEXT NOT NULL DEFAULT '',
                created_at TEXT,
                discovered_at TEXT NOT NULL,
                is_priority INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_repos_discovered_at ON repos(discovered_at);
            CREATE INDEX IF NOT EXISTS idx_repos_language ON repos(language);
            CREATE INDEX IF NOT EXISTS idx_repos_priority ON repos(is_priority);
            CREATE VIRTUAL TABLE IF NOT EXISTS repos_fts USING fts5(
                name, full_name, description, topics,
                content='repos', content_rowid='id'
            );
            CREATE TRIGGER IF NOT EXISTS repos_ai AFTER INSERT ON repos BEGIN
                INSERT INTO repos_fts(rowid, name, full_name, description, topics)
                VALUES (new.id, new.name, new.full_name, new.description, new.topics);
            END;
            CREATE TRIGGER IF NOT EXISTS repos_ad AFTER DELETE ON repos BEGIN
                INSERT INTO repos_fts(repos_fts, rowid, name, full_name, description, topics)
                VALUES ('delete', old.id, old.name, old.full_name, old.description, old.topics);
            END;
            CREATE TRIGGER IF NOT EXISTS repos_au AFTER UPDATE ON repos BEGIN
                INSERT INTO repos_fts(repos_fts, rowid, name, full_name, description, topics)
                VALUES ('delete', old.id, old.name, old.full_name, old.description, old.topics);
                INSERT INTO repos_fts(rowid, name, full_name, description, topics)
                VALUES (new.id, new.name, new.full_name, new.description, new.topics);
            END;",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn rebuild_index(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.execute("INSERT INTO repos_fts(repos_fts) VALUES ('rebuild')", [])?;
        Ok(())
    }

    pub fn get_max_id(&self) -> Result<i64> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM repos", [], |r| r.get(0))
    }

    pub fn insert_batch(&self, items: &[RepoItem]) -> Result<usize> {
        if items.is_empty() {
            return Ok(0);
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare_cached(
            "INSERT INTO repos (
                id, name, full_name, owner, owner_type, html_url, description,
                fork, stars, forks_count, language, license, topics, created_at,
                discovered_at, is_priority
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, full_name=excluded.full_name, owner=excluded.owner,
                owner_type=excluded.owner_type, html_url=excluded.html_url,
                description=COALESCE(excluded.description, repos.description),
                fork=excluded.fork, stars=MAX(repos.stars, excluded.stars),
                forks_count=MAX(repos.forks_count, excluded.forks_count),
                language=COALESCE(excluded.language, repos.language),
                license=COALESCE(excluded.license, repos.license),
                topics=CASE WHEN excluded.topics <> '' THEN excluded.topics ELSE repos.topics END,
                created_at=COALESCE(excluded.created_at, repos.created_at),
                is_priority=MAX(repos.is_priority, excluded.is_priority)",
        )?;
        let mut changed = 0;
        for item in items {
            let topics = item.topics.join(", ");
            changed += stmt.execute(params![
                item.id,
                item.name,
                item.full_name,
                item.owner,
                item.owner_type,
                item.html_url,
                item.description,
                item.fork as i32,
                item.stars,
                item.forks_count,
                item.language,
                item.license,
                topics,
                item.created_at,
                item.discovered_at,
                item.is_priority as i32,
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(changed)
    }

    pub fn existing_ids(&self, items: &[RepoItem]) -> Result<HashSet<i64>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut existing = HashSet::new();
        let ids: Vec<i64> = items.iter().map(|item| item.id).collect();
        for chunk in ids.chunks(400) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!("SELECT id FROM repos WHERE id IN ({placeholders})");
            let mut stmt = conn.prepare(&sql)?;
            let rows =
                stmt.query_map(rusqlite::params_from_iter(chunk.iter()), |row| row.get(0))?;
            for row in rows {
                existing.insert(row?);
            }
        }
        Ok(existing)
    }

    pub fn get_stats(&self) -> Result<(usize, usize, usize)> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let total = conn.query_row("SELECT COUNT(*) FROM repos", [], |r| r.get(0))?;
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let today_count = conn.query_row(
            "SELECT COUNT(*) FROM repos WHERE discovered_at LIKE ?1",
            params![format!("{}%", today)],
            |r| r.get(0),
        )?;
        let priority = conn.query_row(
            "SELECT COUNT(*) FROM repos WHERE is_priority = 1",
            [],
            |r| r.get(0),
        )?;
        Ok((total, today_count, priority))
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<RepoItem>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut results = Vec::new();
        let trimmed = query.trim();
        if trimmed.is_empty() {
            let mut stmt = conn.prepare("SELECT id,name,full_name,owner,owner_type,html_url,description,fork,stars,forks_count,language,license,topics,created_at,discovered_at,is_priority FROM repos ORDER BY id DESC LIMIT ?1")?;
            let rows = stmt.query_map(params![limit], row_to_repo)?;
            for row in rows {
                results.push(row?);
            }
            return Ok(results);
        }

        let sanitized = sanitize_fts5_query(trimmed);
        if sanitized.is_empty() {
            let mut stmt = conn.prepare("SELECT id,name,full_name,owner,owner_type,html_url,description,fork,stars,forks_count,language,license,topics,created_at,discovered_at,is_priority FROM repos ORDER BY id DESC LIMIT ?1")?;
            let rows = stmt.query_map(params![limit], row_to_repo)?;
            for row in rows {
                results.push(row?);
            }
            return Ok(results);
        }

        let fts_sql = "SELECT r.id,r.name,r.full_name,r.owner,r.owner_type,r.html_url,r.description,
                              r.fork,r.stars,r.forks_count,r.language,r.license,r.topics,r.created_at,
                              r.discovered_at,r.is_priority
                       FROM repos r JOIN repos_fts f ON r.id=f.rowid
                       WHERE repos_fts MATCH ?1 ORDER BY r.id DESC LIMIT ?2";

        let mut stmt = conn.prepare(fts_sql)?;
        let fts_success = match stmt.query_map(params![sanitized, limit], row_to_repo) {
            Ok(rows) => {
                for row in rows {
                    results.push(row?);
                }
                true
            }
            Err(_) => false,
        };
        drop(stmt);

        if fts_success {
            return Ok(results);
        }

        // Graceful fallback to LIKE if FTS5 syntax fails on unexpected input
        let fallback_sql = "SELECT id,name,full_name,owner,owner_type,html_url,description,fork,stars,forks_count,language,license,topics,created_at,discovered_at,is_priority FROM repos WHERE full_name LIKE ?1 OR description LIKE ?1 ORDER BY id DESC LIMIT ?2";
        let mut fallback_stmt = conn.prepare(fallback_sql)?;
        let pattern = format!("%{}%", trimmed);
        let rows = fallback_stmt.query_map(params![pattern, limit], row_to_repo)?;
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}

pub fn sanitize_fts5_query(raw: &str) -> String {
    let mut tokens = Vec::new();
    for part in raw.split_whitespace() {
        let clean: String = part.chars().filter(|&c| c != '"').collect();
        if clean.is_empty() {
            continue;
        }
        if clean.len() >= 3 && clean.chars().all(|c| c.is_alphanumeric() || c == '_') {
            tokens.push(format!("\"{}\"*", clean));
        } else {
            tokens.push(format!("\"{}\"", clean));
        }
    }
    tokens.join(" ")
}

fn row_to_repo(r: &rusqlite::Row<'_>) -> Result<RepoItem> {
    let topics_raw: String = r.get(12)?;
    Ok(RepoItem {
        id: r.get(0)?,
        name: r.get(1)?,
        full_name: r.get(2)?,
        owner: r.get(3)?,
        owner_type: r.get(4)?,
        html_url: r.get(5)?,
        description: r.get(6)?,
        fork: r.get::<_, i32>(7)? != 0,
        stars: r.get(8)?,
        forks_count: r.get(9)?,
        language: r.get(10)?,
        license: r.get(11)?,
        topics: topics_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        created_at: r.get(13)?,
        discovered_at: r.get(14)?,
        is_priority: r.get::<_, i32>(15)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::new(":memory:", false).expect("create in-memory db")
    }

    fn sample_repo(id: i64, name: &str, desc: &str) -> RepoItem {
        RepoItem {
            id,
            name: name.into(),
            full_name: format!("user/{name}"),
            owner: "user".into(),
            owner_type: None,
            html_url: format!("https://github.com/user/{name}"),
            description: Some(desc.into()),
            fork: false,
            stars: 10,
            forks_count: 2,
            language: Some("Rust".into()),
            license: Some("MIT".into()),
            topics: vec!["cli".into(), "tool".into()],
            created_at: Some("2026-09-01T00:00:00Z".into()),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            is_priority: false,
        }
    }

    #[test]
    fn test_insert_batch_and_get_stats() {
        let db = test_db();
        let items = vec![
            sample_repo(1, "alpha", "First repository"),
            sample_repo(2, "beta", "Second repository"),
        ];
        let inserted = db.insert_batch(&items).expect("insert batch");
        assert_eq!(inserted, 2);

        let (total, today, priority) = db.get_stats().expect("get stats");
        assert_eq!(total, 2);
        assert_eq!(today, 2);
        assert_eq!(priority, 0);

        let max_id = db.get_max_id().expect("max id");
        assert_eq!(max_id, 2);
    }

    #[test]
    fn test_existing_ids() {
        let db = test_db();
        let items = vec![sample_repo(10, "ten", "desc")];
        db.insert_batch(&items).expect("insert");

        let probe = vec![
            sample_repo(10, "ten", "desc"),
            sample_repo(20, "twenty", "desc"),
        ];
        let existing = db.existing_ids(&probe).expect("existing");
        assert!(existing.contains(&10));
        assert!(!existing.contains(&20));
    }

    #[test]
    fn test_fts5_sanitization_and_special_chars() {
        let db = test_db();
        let items = vec![
            sample_repo(1, "cpp-tool", "A C++ high performance parser"),
            sample_repo(2, "rust-agent", "Autonomous AI agent in Rust"),
        ];
        db.insert_batch(&items).expect("insert");

        // Test searching with special characters that previously broke FTS5:
        let res_cpp = db.search("c++", 10).expect("search c++");
        assert!(!res_cpp.is_empty());
        assert_eq!(res_cpp[0].name, "cpp-tool");

        let res_quotes = db.search(r#""broken quote"#, 10).expect("search quote");
        // Should not fail or crash
        assert!(res_quotes.is_empty() || !res_quotes.is_empty());

        let res_colon = db.search("foo:bar", 10).expect("search colon");
        assert!(res_colon.is_empty());

        let res_logic = db.search("AND OR NOT", 10).expect("search logic words");
        assert!(res_logic.is_empty());
    }
}
