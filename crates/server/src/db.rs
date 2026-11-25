//! Read access to the detections edr-locald stores in workbench.db.
//!
//! edr-locald owns the tables and writes them. The server creates them if
//! they are missing, so it can start before edr-locald has run, and
//! otherwise only reads.

use rusqlite::{params, Connection, OpenFlags};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// One detection, as stored by edr-locald.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredSignal {
    pub signal_id: String,
    pub signal_type: String,
    pub severity: String,
    pub host: String,
    pub ts: i64,
    pub ts_start: i64,
    pub ts_end: i64,
    pub proc_key: Option<String>,
    pub file_key: Option<String>,
    pub identity_key: Option<String>,
    pub metadata: serde_json::Value,
    pub evidence_ptrs: Vec<serde_json::Value>,
    pub dropped_evidence_count: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalStats {
    pub total: i64,
    pub by_severity: HashMap<String, i64>,
    pub by_host: HashMap<String, i64>,
    pub by_type: HashMap<String, i64>,
}

pub struct Database {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS signals (
        signal_id TEXT PRIMARY KEY,
        signal_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        host TEXT NOT NULL,
        ts INTEGER NOT NULL,
        ts_start INTEGER NOT NULL,
        ts_end INTEGER NOT NULL,
        proc_key TEXT,
        file_key TEXT,
        identity_key TEXT,
        metadata TEXT NOT NULL,
        evidence_ptrs TEXT NOT NULL,
        dropped_evidence_count INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS signal_explanations (
        signal_id TEXT PRIMARY KEY,
        explanation_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );";

const SIGNAL_COLUMNS: &str = "signal_id, signal_type, severity, host, ts, ts_start, ts_end, \
     proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count";

impl Database {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        // edr-locald writes while the server reads. Wait for its lock
        // instead of failing the request.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Database { conn: Mutex::new(conn) })
    }

    pub fn health_check(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT 1", [], |_| Ok(()))
    }

    pub fn get_signal(&self, signal_id: &str) -> rusqlite::Result<Option<StoredSignal>> {
        let conn = self.conn.lock().unwrap();
        let sql = format!("SELECT {} FROM signals WHERE signal_id = ?1", SIGNAL_COLUMNS);
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params![signal_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_signal(row)?)),
            None => Ok(None),
        }
    }

    /// Newest first, with optional exact match filters.
    pub fn list_signals(
        &self,
        host: Option<&str>,
        signal_type: Option<&str>,
        severity: Option<&str>,
        limit: usize,
    ) -> rusqlite::Result<Vec<StoredSignal>> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {} FROM signals
             WHERE (?1 IS NULL OR host = ?1) AND (?2 IS NULL OR signal_type = ?2) AND (?3 IS NULL OR severity = ?3)
             ORDER BY ts DESC LIMIT ?4",
            SIGNAL_COLUMNS
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params![host, signal_type, severity, limit as i64])?;
        let mut signals = Vec::new();
        while let Some(row) = rows.next()? {
            signals.push(row_to_signal(row)?);
        }
        Ok(signals)
    }

    pub fn get_signal_explanation(&self, signal_id: &str) -> rusqlite::Result<Option<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT explanation_json FROM signal_explanations WHERE signal_id = ?1")?;
        let mut rows = stmt.query(params![signal_id])?;
        match rows.next()? {
            Some(row) => {
                let text: String = row.get(0)?;
                Ok(Some(serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)))
            }
            None => Ok(None),
        }
    }

    pub fn signal_stats(&self) -> rusqlite::Result<SignalStats> {
        let conn = self.conn.lock().unwrap();
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0))?;
        let mut counts = Vec::new();
        for column in ["severity", "host", "signal_type"] {
            let mut map = HashMap::new();
            let sql = format!("SELECT {}, COUNT(*) FROM signals GROUP BY {}", column, column);
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                map.insert(row.get::<_, String>(0)?, row.get::<_, i64>(1)?);
            }
            counts.push(map);
        }
        let by_type = counts.pop().unwrap_or_default();
        let by_host = counts.pop().unwrap_or_default();
        let by_severity = counts.pop().unwrap_or_default();
        Ok(SignalStats {
            total,
            by_severity,
            by_host,
            by_type,
        })
    }
}

fn row_to_signal(row: &rusqlite::Row) -> rusqlite::Result<StoredSignal> {
    let metadata: String = row.get(10)?;
    let evidence: String = row.get(11)?;
    Ok(StoredSignal {
        signal_id: row.get(0)?,
        signal_type: row.get(1)?,
        severity: row.get(2)?,
        host: row.get(3)?,
        ts: row.get(4)?,
        ts_start: row.get(5)?,
        ts_end: row.get(6)?,
        proc_key: row.get(7)?,
        file_key: row.get(8)?,
        identity_key: row.get(9)?,
        metadata: serde_json::from_str(&metadata).unwrap_or_default(),
        evidence_ptrs: serde_json::from_str(&evidence).unwrap_or_default(),
        dropped_evidence_count: row.get(12)?,
    })
}
