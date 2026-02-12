//! SQLite database wrapper using rusqlite.

use crate::error::AppResult;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use tracing::warn;

/// A thread-safe SQLite database handle.
///
/// rusqlite's `Connection` is `!Send`, so we wrap it in a `std::sync::Mutex`
/// and expose a closure-based API. All DB work runs on `spawn_blocking`
/// threads to avoid blocking the async runtime.
#[derive(Clone)]
pub struct Db {
    pub(crate) conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Open a local SQLite database (or `:memory:`) with WAL mode enabled.
    pub fn open(path: &str) -> AppResult<Self> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Try to open a database with retries and exponential backoff.
    pub async fn open_with_retry(
        path: &str,
        max_retries: u32,
        base_delay: std::time::Duration,
    ) -> AppResult<Self> {
        let mut last_err = None;
        for attempt in 0..=max_retries {
            match Self::open(path) {
                Ok(db) => return Ok(db),
                Err(e) => {
                    if attempt < max_retries {
                        let delay = base_delay * 2u32.pow(attempt);
                        warn!(
                            attempt = attempt + 1,
                            max_retries,
                            delay_ms = delay.as_millis() as u64,
                            error = %e,
                            "Failed to open database, retrying..."
                        );
                        tokio::time::sleep(delay).await;
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| anyhow::anyhow!("Database open failed without an error").into()))
    }

    /// Execute a read-only closure with a shared reference to the connection.
    pub async fn call<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&Connection) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().unwrap();
            f(&guard)
        })
        .await?
    }

    /// Execute a mutating closure with a mutable reference to the connection.
    pub async fn call_mut<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap();
            f(&mut guard)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_with_retry_succeeds_immediately() {
        let db = Db::open_with_retry(":memory:", 3, std::time::Duration::from_millis(10)).await;
        assert!(db.is_ok());
    }

    #[tokio::test]
    async fn open_with_retry_fails_after_exhausting_retries() {
        let invalid_path =
            std::env::temp_dir().join(format!("cratedex-open-with-retry-{}", std::process::id()));
        std::fs::create_dir_all(&invalid_path).expect("create temp directory");
        let result = Db::open_with_retry(
            &invalid_path.to_string_lossy(),
            1,
            std::time::Duration::from_millis(1),
        )
        .await;
        let _ = std::fs::remove_dir_all(&invalid_path);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn call_executes_read_closure() {
        let db = Db::open(":memory:").unwrap();
        let version: String = db
            .call(|conn| {
                let v: String = conn.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
                Ok(v)
            })
            .await
            .unwrap();
        assert!(!version.is_empty());
    }

    #[tokio::test]
    async fn call_mut_executes_write_closure() {
        let db = Db::open(":memory:").unwrap();
        db.call_mut(|conn| {
            conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)", [])?;
            conn.execute("INSERT INTO t (id) VALUES (42)", [])?;
            Ok(())
        })
        .await
        .unwrap();

        let id: i64 = db
            .call(|conn| {
                let v: i64 = conn.query_row("SELECT id FROM t", [], |row| row.get(0))?;
                Ok(v)
            })
            .await
            .unwrap();
        assert_eq!(id, 42);
    }
}
