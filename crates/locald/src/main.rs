//! edr-locald: macOS detection daemon.
//!
//! segments/*.jsonl (from capture_macos_rotating)
//!   -> facts (os::macos::fact_extractor)
//!   -> playbook slots (HypothesisController with the YAML playbooks)
//!   -> incidents, stored as rows in workbench.db for edr-server
//!
//! Each playbook that fires is stored as one row in the `signals` table
//! (signal_id is the hypothesis id), and a full explanation is stored in
//! `signal_explanations`. The hypothesis controller also groups detections
//! of the same family and login session into one incident. That incident id
//! is kept in the signal metadata so related detections can be listed
//! together. The explanation lists every slot of the
//! playbook, the evidence pointer that filled it, and the event line read
//! back from the segment file with its SHA-256 checked, so an analyst can
//! see exactly which audit records produced the incident.
//!
//! After every segment, the list of finished segments and the controller's
//! open hypotheses are saved in one SQLite transaction. On start both are
//! read back, so a restart in the middle of a multi step playbook loses
//! nothing. If edr-locald dies in the middle of a segment, that segment is
//! processed again from the last saved state. Signal ids are deterministic
//! and rows are written with INSERT OR REPLACE, so that is safe.

use chrono::{DateTime, Utc};
use edr_core::Event;
use edr_locald::hypothesis::canonical_event::EvidencePtr;
use edr_locald::hypothesis_controller::{ControllerSnapshot, HypothesisController};
use edr_locald::os::macos::{extract_facts_with_hash, load_playbooks_from_dir, macos_playbooks};
use edr_locald::slot_matcher::PlaybookDef;
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "\
edr-locald: run the macOS playbooks over capture segments

USAGE:
  edr-locald [--telemetry-root DIR] [--playbooks DIR] [--once]

OPTIONS:
  --telemetry-root DIR  folder with index.json and segments/ (default: $EDR_TELEMETRY_ROOT, else ./telemetry_output)
  --playbooks DIR       load YAML playbooks from DIR (default: $EDR_PLAYBOOK_DIR, else the built in set)
  --once                process the segments that exist now, then exit
  -h, --help            show this help
";

#[derive(Debug, Deserialize)]
struct SegmentIndex {
    segments: Vec<SegmentEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct SegmentEntry {
    seq: u64,
    rel_path: String,
    #[serde(default)]
    sha256_segment: Option<String>,
}

struct Args {
    telemetry_root: PathBuf,
    playbook_dir: Option<PathBuf>,
    once: bool,
}

fn parse_args() -> Result<Option<Args>, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut telemetry_root = std::env::var("EDR_TELEMETRY_ROOT").ok().map(PathBuf::from);
    let mut playbook_dir = std::env::var("EDR_PLAYBOOK_DIR").ok().map(PathBuf::from);
    let mut once = false;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--telemetry-root" | "--playbooks" => {
                let value = raw.get(i + 1).ok_or_else(|| format!("{} needs a value", raw[i]))?;
                if raw[i] == "--telemetry-root" {
                    telemetry_root = Some(PathBuf::from(value));
                } else {
                    playbook_dir = Some(PathBuf::from(value));
                }
                i += 1;
            }
            "--once" => once = true,
            "-h" | "--help" => return Ok(None),
            other => return Err(format!("unknown argument '{}'", other)),
        }
        i += 1;
    }
    Ok(Some(Args {
        telemetry_root: telemetry_root.unwrap_or_else(|| PathBuf::from("telemetry_output")),
        playbook_dir,
        once,
    }))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn open_db(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
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
        CREATE TABLE IF NOT EXISTS signal_explanations (
            signal_id TEXT PRIMARY KEY,
            explanation_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS locald_checkpoint (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )?;
    Ok(conn)
}

/// Reads segment lines back by (segment seq, line number) for explanations.
struct EvidenceReader {
    root: PathBuf,
    paths: HashMap<u64, String>,
    cache: HashMap<u64, Vec<String>>,
}

impl EvidenceReader {
    fn line(&mut self, seq: u64, index: u64) -> Option<String> {
        if !self.cache.contains_key(&seq) {
            let rel = self.paths.get(&seq)?;
            let text = fs::read_to_string(self.root.join(rel)).ok()?;
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            // Keep the cache small. Explanations usually point at recent segments.
            if self.cache.len() > 16 {
                self.cache.clear();
            }
            self.cache.insert(seq, lines);
        }
        self.cache.get(&seq)?.get(index as usize).cloned()
    }

    /// The evidence entry for one pointer: the pointer, the event line read
    /// back from disk, and whether its hash still matches.
    fn excerpt(&mut self, ptr: &EvidencePtr) -> Value {
        let seq = ptr.segment_id.parse::<u64>().ok();
        let line = seq.and_then(|s| self.line(s, ptr.record_index));
        let (event, verified) = match &line {
            Some(text) => {
                let ok = ptr
                    .record_sha256
                    .as_ref()
                    .map(|h| *h == sha256_hex(text.as_bytes()))
                    .unwrap_or(false);
                (serde_json::from_str::<Value>(text).unwrap_or(Value::Null), ok)
            }
            None => (Value::Null, false),
        };
        json!({
            "stream_id": ptr.stream_id,
            "segment_seq": seq,
            "record_index": ptr.record_index,
            "record_sha256": ptr.record_sha256,
            "ts": ptr.ts,
            "verified": verified,
            "event": event,
        })
    }
}

fn ms(ts: DateTime<Utc>) -> i64 {
    ts.timestamp_millis()
}

/// Store one fired playbook as a signal plus its explanation.
fn persist_incident(
    db: &Connection,
    controller: &HypothesisController,
    playbooks: &HashMap<String, PlaybookDef>,
    hypothesis_id: &str,
    incident_id: &str,
    evidence: &mut EvidenceReader,
) -> Result<String, String> {
    let hypothesis = controller
        .get_hypothesis(hypothesis_id)
        .ok_or_else(|| format!("hypothesis {} not found", hypothesis_id))?;
    let playbook = playbooks
        .get(&hypothesis.template_id)
        .ok_or_else(|| format!("playbook {} not loaded", hypothesis.template_id))?;
    let incident = controller.get_incident(incident_id);

    let mut slots = Vec::new();
    let mut all_ptrs = Vec::new();
    let mut first_ts: Option<DateTime<Utc>> = None;
    let mut last_ts: Option<DateTime<Utc>> = None;
    for slot in &playbook.slots {
        let fill = hypothesis.slot_fills.get(&slot.slot_id);
        let mut excerpts = Vec::new();
        if let Some(fill) = fill {
            for ptr in &fill.evidence_ptrs {
                excerpts.push(evidence.excerpt(ptr));
                all_ptrs.push(json!({
                    "stream_id": ptr.stream_id,
                    "segment_id": ptr.segment_id.parse::<u64>().unwrap_or(0),
                    "record_index": ptr.record_index,
                    "record_sha256": ptr.record_sha256,
                }));
            }
            first_ts = Some(first_ts.map_or(fill.first_ts, |t| t.min(fill.first_ts)));
            last_ts = Some(last_ts.map_or(fill.last_ts, |t| t.max(fill.last_ts)));
        }
        slots.push(json!({
            "slot_id": slot.slot_id,
            "name": slot.name,
            "required": slot.required,
            "fact_type": slot.predicate.fact_type,
            "filled": fill.map(|f| f.satisfied).unwrap_or(false),
            "evidence": excerpts,
        }));
    }
    let first_ts = first_ts.unwrap_or_else(Utc::now);
    let last_ts = last_ts.unwrap_or(first_ts);
    let mitre: Vec<&String> = playbook.tags.iter().filter(|t| t.starts_with('T')).collect();
    let all_verified = slots
        .iter()
        .flat_map(|s| s["evidence"].as_array().cloned().unwrap_or_default())
        .all(|e| e["verified"] == true);

    let explanation = json!({
        "signal_id": hypothesis_id,
        "incident_id": incident_id,
        "playbook_id": playbook.playbook_id,
        "title": playbook.title,
        "family": playbook.family,
        "severity": playbook.severity,
        "mitre_techniques": mitre,
        "narrative": playbook.narrative,
        "scope": hypothesis.scope_key.to_string(),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "slots": slots,
        "evidence_verified": all_verified,
        "engine": controller.explain(hypothesis_id),
    });

    // Host name as the capture agent recorded it on the first evidence event.
    let host = slots
        .iter()
        .flat_map(|s| s["evidence"].as_array().cloned().unwrap_or_default())
        .find_map(|e| e["event"]["host"].as_str().map(|h| h.to_string()))
        .or_else(|| incident.map(|i| i.host_id.clone()))
        .unwrap_or_default();
    let metadata = json!({
        "incident_id": incident_id,
        "title": playbook.title,
        "family": playbook.family,
        "playbook_id": playbook.playbook_id,
        "mitre_techniques": mitre,
        "scope": hypothesis.scope_key.to_string(),
        "narrative": playbook.narrative,
    });
    let created_at = Utc::now().to_rfc3339();
    db.execute(
        "INSERT OR REPLACE INTO signals
         (signal_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key,
          metadata, evidence_ptrs, dropped_evidence_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, ?8, ?9, 0, ?10)",
        params![
            hypothesis_id,
            playbook.playbook_id,
            playbook.severity,
            host,
            ms(last_ts),
            ms(first_ts),
            ms(last_ts),
            metadata.to_string(),
            Value::Array(all_ptrs).to_string(),
            created_at
        ],
    )
    .map_err(|e| e.to_string())?;
    db.execute(
        "INSERT OR REPLACE INTO signal_explanations (signal_id, explanation_json, created_at) VALUES (?1, ?2, ?3)",
        params![hypothesis_id, explanation.to_string(), created_at],
    )
    .map_err(|e| e.to_string())?;
    Ok(playbook.playbook_id.clone())
}

fn load_checkpoint(db: &Connection) -> BTreeSet<u64> {
    let mut done = BTreeSet::new();
    if let Ok(text) = db.query_row::<String, _, _>(
        "SELECT value FROM locald_checkpoint WHERE key = 'segments_done'",
        [],
        |row| row.get(0),
    ) {
        for part in text.split(',') {
            if let Ok(seq) = part.parse::<u64>() {
                done.insert(seq);
            }
        }
    }
    done
}

/// Save the finished segments and the open hypotheses together, so the two
/// can never disagree after a crash.
fn save_checkpoint(db: &Connection, done: &BTreeSet<u64>, controller: &HypothesisController) -> Result<(), String> {
    let text: Vec<String> = done.iter().map(|s| s.to_string()).collect();
    let snapshot = serde_json::to_string(&controller.snapshot()).map_err(|e| e.to_string())?;
    let tx = db.unchecked_transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT OR REPLACE INTO locald_checkpoint (key, value) VALUES ('segments_done', ?1)",
        params![text.join(",")],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT OR REPLACE INTO locald_checkpoint (key, value) VALUES ('controller_state', ?1)",
        params![snapshot],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

fn load_controller_state(db: &Connection) -> Option<ControllerSnapshot> {
    let text: String = db
        .query_row(
            "SELECT value FROM locald_checkpoint WHERE key = 'controller_state'",
            [],
            |row| row.get(0),
        )
        .ok()?;
    match serde_json::from_str(&text) {
        Ok(snapshot) => Some(snapshot),
        Err(e) => {
            eprintln!("[locald] saved state does not parse, starting empty: {}", e);
            None
        }
    }
}

/// Signals already in the database, so a restored hypothesis is not stored twice.
fn stored_signal_ids(db: &Connection) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    if let Ok(mut stmt) = db.prepare("SELECT signal_id FROM signals") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
            for id in rows.flatten() {
                ids.insert(id);
            }
        }
    }
    ids
}

fn main() {
    let args = match parse_args() {
        Ok(Some(a)) => a,
        Ok(None) => {
            print!("{}", USAGE);
            return;
        }
        Err(e) => {
            eprintln!("error: {}\n\n{}", e, USAGE);
            std::process::exit(2);
        }
    };
    let root = args.telemetry_root.clone();
    if let Err(e) = fs::create_dir_all(root.join("segments")) {
        eprintln!("[locald] error: cannot create {}: {}", root.display(), e);
        std::process::exit(1);
    }

    let playbook_list = match &args.playbook_dir {
        Some(dir) => match load_playbooks_from_dir(dir) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[locald] error: {}", e);
                std::process::exit(1);
            }
        },
        None => macos_playbooks(),
    };
    let db_path = root.join("workbench.db");
    let db = match open_db(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("[locald] error: cannot open {}: {}", db_path.display(), e);
            std::process::exit(1);
        }
    };

    eprintln!("[locald] telemetry root: {}", root.display());
    eprintln!(
        "[locald] {} playbooks loaded from {}",
        playbook_list.len(),
        args.playbook_dir
            .as_ref()
            .map(|d| d.display().to_string())
            .unwrap_or_else(|| "the built in set".to_string())
    );

    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let mut controller = HypothesisController::new(&host);
    let mut playbooks = HashMap::new();
    for playbook in playbook_list {
        controller.register_playbook(playbook.clone());
        playbooks.insert(playbook.playbook_id.clone(), playbook);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    let _ = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst));

    let mut done = load_checkpoint(&db);
    let mut persisted: BTreeSet<String> = stored_signal_ids(&db);
    if let Some(snapshot) = load_controller_state(&db) {
        let restored = controller.restore(snapshot);
        eprintln!(
            "[locald] restored {} open hypotheses, {} segments already done",
            restored,
            done.len()
        );
    }
    let mut total_events = 0u64;
    let mut total_incidents = 0u64;
    let index_path = root.join("index.json");

    while !shutdown.load(Ordering::SeqCst) {
        let index: Option<SegmentIndex> = fs::read_to_string(&index_path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        if let Some(index) = index {
            let mut segments = index.segments.clone();
            segments.sort_by_key(|s| s.seq);
            let mut evidence = EvidenceReader {
                root: root.clone(),
                paths: segments.iter().map(|s| (s.seq, s.rel_path.clone())).collect(),
                cache: HashMap::new(),
            };
            for seg in segments {
                if done.contains(&seg.seq) {
                    continue;
                }
                let path = root.join(&seg.rel_path);
                let bytes = match fs::read(&path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                // The index records a SHA-256 per segment. A mismatch means
                // the file changed after capture wrote it.
                if let Some(expected) = &seg.sha256_segment {
                    let actual = sha256_hex(&bytes);
                    if &actual != expected {
                        eprintln!(
                            "[locald] segment {} hash mismatch (index {}, file {}), skipped",
                            seg.rel_path, expected, actual
                        );
                        done.insert(seg.seq);
                        continue;
                    }
                }
                let text = String::from_utf8_lossy(&bytes);
                let mut segment_events = 0u64;
                let mut segment_incidents = 0u64;
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let event: Event = match serde_json::from_str(line) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    segment_events += 1;
                    let line_hash = sha256_hex(line.as_bytes());
                    for fact in extract_facts_with_hash(&event, Some(line_hash)) {
                        let affected = match controller.ingest_fact(fact) {
                            Ok(ids) => ids,
                            Err(e) => {
                                eprintln!("[locald] fact rejected: {}", e);
                                continue;
                            }
                        };
                        for hypothesis_id in affected {
                            let incident_id = controller
                                .get_hypothesis(&hypothesis_id)
                                .and_then(|h| h.absorbed_into_incident_id.clone());
                            let incident_id = match incident_id {
                                Some(id) => id,
                                None => continue,
                            };
                            if persisted.contains(&hypothesis_id) {
                                continue;
                            }
                            match persist_incident(&db, &controller, &playbooks, &hypothesis_id, &incident_id, &mut evidence) {
                                Ok(playbook_id) => {
                                    eprintln!("[locald] {} fired: signal {} in incident {}", playbook_id, hypothesis_id, incident_id);
                                    persisted.insert(hypothesis_id.clone());
                                    segment_incidents += 1;
                                }
                                Err(e) => eprintln!("[locald] could not store signal {}: {}", hypothesis_id, e),
                            }
                        }
                    }
                }
                total_events += segment_events;
                total_incidents += segment_incidents;
                eprintln!(
                    "[locald] {}: {} events, {} detections",
                    seg.rel_path, segment_events, segment_incidents
                );
                done.insert(seg.seq);
                if let Err(e) = save_checkpoint(&db, &done, &controller) {
                    eprintln!("[locald] could not save checkpoint: {}", e);
                }
            }
        }
        if args.once {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    eprintln!(
        "[locald] stopped: {} events, {} detections this run",
        total_events, total_incidents
    );
}
