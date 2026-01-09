//! EDR Locald entry point - macOS signal detection daemon
//!
//! Pipeline: segments/*.jsonl -> MacOSSignalEngine -> signals table -> edr-server
//!
//! This daemon continuously watches telemetry segments produced by
//! capture_macos_rotating and runs detection logic via MacOSSignalEngine.
//! It also runs the hypothesis/incident compiler for explainability.

use chrono::Utc;
use edr_core::{Event, EvidencePtr};
use edr_locald::hypothesis_controller::HypothesisController;
use edr_locald::os::macos::{extract_facts, macos_playbooks};
use edr_locald::scoring::ScoringEngine;
use edr_locald::MacOSSignalEngine;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Get telemetry root from env or default
fn get_telemetry_root() -> PathBuf {
    std::env::var("EDR_TELEMETRY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/edr"))
}

/// Index file structure
#[derive(Debug, Deserialize)]
struct SegmentIndex {
    #[allow(dead_code)]
    schema_version: u32,
    segments: Vec<SegmentEntry>,
}

#[derive(Debug, Deserialize)]
struct SegmentEntry {
    #[serde(alias = "path", alias = "rel_path")]
    path: Option<String>,
    #[allow(dead_code)]
    stream_id: Option<String>,
}

impl SegmentEntry {
    fn get_path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

/// Parse a segment JSONL record into edr_core::Event
fn parse_segment_record(line: &str, segment_id: u64, record_index: u32) -> Option<Event> {
    let parsed: serde_json::Value = serde_json::from_str(line).ok()?;

    let ts_ms = parsed.get("ts_ms")?.as_i64()?;
    let host = parsed.get("host")?.as_str()?.to_string();

    let tags: Vec<String> = parsed
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Extract fields from the "fields" object
    let fields: BTreeMap<String, serde_json::Value> = parsed
        .get("fields")
        .and_then(|v| v.as_object())
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    // Build evidence pointer from segment record or construct one
    let evidence_ptr = parsed.get("evidence_ptr").and_then(|ep| {
        let stream_id = ep.get("stream_id")?.as_str()?.to_string();
        let seg_id = ep.get("segment_id")?.as_u64()?;
        let rec_idx = ep.get("record_index")?.as_u64()? as u32;
        Some(EvidencePtr {
            stream_id,
            segment_id: seg_id,
            record_index: rec_idx,
        })
    }).or_else(|| {
        // Construct evidence pointer from our position
        Some(EvidencePtr {
            stream_id: "openbsm".to_string(),
            segment_id,
            record_index,
        })
    });

    Some(Event {
        ts_ms,
        host,
        tags,
        proc_key: parsed
            .get("proc_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        file_key: parsed
            .get("file_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        identity_key: parsed
            .get("identity_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        evidence_ptr,
        fields,
    })
}

fn main() {
    let telemetry_root = get_telemetry_root();

    eprintln!("edr-locald starting (macOS)");
    eprintln!("TELEMETRY_ROOT: {}", telemetry_root.display());

    // Ensure directories exist
    let segments_dir = telemetry_root.join("segments");
    if let Err(e) = fs::create_dir_all(&segments_dir) {
        eprintln!("ERROR: Failed to create segments dir: {}", e);
        return;
    }

    // Initialize SQLite database
    let db_path = telemetry_root.join("workbench.db");
    let db = match Connection::open(&db_path) {
        Ok(conn) => {
            // Create signals table (same schema as edr-server)
            let _ = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS signals (
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
                CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_signals_type ON signals(signal_type);
                CREATE INDEX IF NOT EXISTS idx_signals_host ON signals(host);
                CREATE INDEX IF NOT EXISTS idx_signals_severity ON signals(severity);

                CREATE TABLE IF NOT EXISTS signal_explanations (
                    signal_id TEXT PRIMARY KEY,
                    explanation_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (signal_id) REFERENCES signals(signal_id)
                );
                CREATE INDEX IF NOT EXISTS idx_explanations_signal ON signal_explanations(signal_id);

                CREATE TABLE IF NOT EXISTS locald_checkpoint (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );",
            );
            eprintln!("Database: {}", db_path.display());
            conn
        }
        Err(e) => {
            eprintln!("FATAL: Failed to open database: {}", e);
            return;
        }
    };

    // Get hostname
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });
    eprintln!("Host: {}", hostname);

    // Initialize MacOS signal engine
    let mut signal_engine = MacOSSignalEngine::new(hostname.clone());
    eprintln!("MacOSSignalEngine: ready");

    // Initialize scoring engine
    let scoring_engine = ScoringEngine::new(false);

    // Initialize hypothesis controller with macOS playbooks
    let playbooks = macos_playbooks();
    let mut hypothesis_controller = HypothesisController::new(&hostname);
    for playbook in &playbooks {
        hypothesis_controller.register_playbook(playbook.clone());
    }
    eprintln!("HypothesisController: loaded {} macOS playbooks", playbooks.len());

    // Track processed segments
    let mut seen_segments: HashSet<String> = HashSet::new();

    // Load checkpoint
    if let Ok(checkpoint) = db.query_row::<String, _, _>(
        "SELECT value FROM locald_checkpoint WHERE key = 'seen_segments'",
        [],
        |row| row.get(0),
    ) {
        for seg in checkpoint.split(',') {
            if !seg.is_empty() {
                seen_segments.insert(seg.to_string());
            }
        }
        eprintln!(
            "Resumed from checkpoint with {} segments",
            seen_segments.len()
        );
    }

    // Setup graceful shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        eprintln!("\n[locald] Shutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .ok();

    let index_path = telemetry_root.join("index.json");
    eprintln!("Watching: {}", index_path.display());
    eprintln!("(Press Ctrl+C to stop)");

    let mut total_events = 0u64;
    let mut total_signals = 0u64;

    // Main loop
    while !shutdown.load(Ordering::Relaxed) {
        // Read index.json
        if let Ok(index_content) = fs::read_to_string(&index_path) {
            if let Ok(index) = serde_json::from_str::<SegmentIndex>(&index_content) {
                for entry in &index.segments {
                    let entry_path = match entry.get_path() {
                        Some(p) => p.to_string(),
                        None => continue,
                    };

                    if seen_segments.contains(&entry_path) {
                        continue;
                    }

                    let segment_path = telemetry_root.join(&entry_path);
                    if !segment_path.exists() {
                        continue;
                    }

                    // Extract segment_id from filename (UUID or numeric)
                    let segment_id: u64 = segment_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .and_then(|s| {
                            // Try parsing as number first
                            s.parse::<u64>().ok().or_else(|| {
                                // Use hash of UUID string as segment_id
                                use std::hash::{Hash, Hasher};
                                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                                s.hash(&mut hasher);
                                Some(hasher.finish())
                            })
                        })
                        .unwrap_or(0);

                    eprintln!("[ingest] Processing: {}", entry_path);

                    if let Ok(content) = fs::read_to_string(&segment_path) {
                        let mut segment_events = 0u32;
                        let mut segment_signals = 0u32;

                        for (record_index, line) in content.lines().enumerate() {
                            if line.trim().is_empty() {
                                continue;
                            }

                            if let Some(event) =
                                parse_segment_record(line, segment_id, record_index as u32)
                            {
                                segment_events += 1;

                                // Extract facts for hypothesis controller
                                let facts = extract_facts(&event);
                                for fact in facts {
                                    // Feed to hypothesis controller (returns affected hypothesis IDs)
                                    match hypothesis_controller.ingest_fact(fact.clone()) {
                                        Ok(hypothesis_ids) => {
                                            for hyp_id in hypothesis_ids {
                                                // Check if hypothesis was promoted to incident
                                                // The incident ID is derived from hypothesis ID
                                                if let Some(hypothesis) = hypothesis_controller.get_hypothesis(&hyp_id) {
                                                    if let Some(incident_id) = &hypothesis.absorbed_into_incident_id {
                                                        // Generate explanation using built-in API
                                                        if let Some(explanation) = hypothesis_controller.explain_incident(incident_id) {
                                                            let explanation_json = serde_json::to_string(&explanation)
                                                                .unwrap_or_else(|_| "{}".to_string());
                                                            let created_at = Utc::now().to_rfc3339();
                                                            let _ = db.execute(
                                                                "INSERT OR REPLACE INTO signal_explanations (signal_id, explanation_json, created_at) VALUES (?1, ?2, ?3)",
                                                                params![incident_id, explanation_json, created_at],
                                                            );
                                                            eprintln!(
                                                                "  [incident] {} (explanation stored)",
                                                                incident_id
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("  [hypothesis error] {}", e);
                                        }
                                    }
                                }

                                // Process event through MacOSSignalEngine
                                let signals = signal_engine.process_event(&event);
                                for signal in signals {
                                    segment_signals += 1;
                                    
                                    // Score the signal
                                    let scored = scoring_engine.score(signal.clone());
                                    
                                    // Persist to database
                                    persist_signal(&db, &scored.signal);

                                    eprintln!(
                                        "  [signal] {} severity={} risk={:.2}",
                                        scored.signal.signal_type,
                                        scored.signal.severity,
                                        scored.risk_score
                                    );
                                }
                            }
                        }

                        total_events += segment_events as u64;
                        total_signals += segment_signals as u64;

                        eprintln!(
                            "  [done] {} events, {} signals (total: {} events, {} signals)",
                            segment_events, segment_signals, total_events, total_signals
                        );
                    }

                    seen_segments.insert(entry_path.clone());

                    // Save checkpoint
                    let checkpoint = seen_segments.iter().cloned().collect::<Vec<_>>().join(",");
                    let _ = db.execute(
                        "INSERT OR REPLACE INTO locald_checkpoint (key, value) VALUES ('seen_segments', ?1)",
                        params![checkpoint],
                    );
                }
            }
        }

        // Poll every 2 seconds
        std::thread::sleep(Duration::from_secs(2));
    }

    eprintln!(
        "edr-locald stopped. Total: {} events, {} signals",
        total_events, total_signals
    );
}

/// Persist a signal to the database
fn persist_signal(db: &Connection, signal: &edr_locald::SignalResult) {
    let evidence_json =
        serde_json::to_string(&signal.evidence_ptrs).unwrap_or_else(|_| "[]".to_string());
    let metadata_json = signal.metadata.to_string();
    let created_at = Utc::now().to_rfc3339();

    let _ = db.execute(
        "INSERT OR REPLACE INTO signals
         (signal_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            signal.signal_id,
            signal.signal_type,
            signal.severity,
            signal.host,
            signal.ts,
            signal.ts_start,
            signal.ts_end,
            signal.proc_key,
            signal.file_key,
            signal.identity_key,
            metadata_json,
            evidence_json,
            signal.dropped_evidence_count,
            created_at
        ],
    );
}
