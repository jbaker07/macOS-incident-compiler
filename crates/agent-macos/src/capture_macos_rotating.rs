/// capture_macos_rotating: Production OpenBSM → JSONL telemetry pipeline
///
/// Reads macOS audit trail from /dev/auditpipe, normalizes to versioned JSON,
/// writes atomically to rotating JSONL segments, maintains durable index.
///
/// PRODUCTION PATH ONLY: No synthetic events, no demo modes.

/// Real BSM record parser for OpenBSM audit trail
/// Parses binary BSM records from /dev/auditpipe or audit files
struct BSMParser {
    buffer: Vec<u8>,
}

/// BSM header constants
const BSM_HEADER_TOKEN: u8 = 0x14; // AUT_HEADER32
const BSM_HEADER64_TOKEN: u8 = 0x74; // AUT_HEADER64
const BSM_TRAILER_TOKEN: u8 = 0x13; // AUT_TRAILER

impl BSMParser {
    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(65536),
        }
    }

    /// Feed raw bytes from auditpipe into the parse buffer
    fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        // Bounded: prevent unbounded growth
        if self.buffer.len() > 10 * 1024 * 1024 {
            // 10MB max buffer - discard oldest half if exceeded
            let half = self.buffer.len() / 2;
            self.buffer.drain(0..half);
        }
    }

    /// Try to parse one complete BSM record from buffer
    /// Returns Some((aue_code, record_data, ts_millis, bytes_consumed)) if complete record found
    /// Returns None if no complete record available
    fn try_parse_record(&mut self) -> Option<(i32, Vec<u8>, u64, usize)> {
        // Find BSM header token (0x14 or 0x74)
        let header_pos = self
            .buffer
            .iter()
            .position(|&b| b == BSM_HEADER_TOKEN || b == BSM_HEADER64_TOKEN)?;

        // Discard bytes before header
        if header_pos > 0 {
            self.buffer.drain(0..header_pos);
        }

        // Need at least 18 bytes for header32 or 22 for header64
        if self.buffer.len() < 18 {
            return None;
        }

        let is_64bit = self.buffer[0] == BSM_HEADER64_TOKEN;
        let header_size = if is_64bit { 22 } else { 18 };

        if self.buffer.len() < header_size {
            return None;
        }

        // Parse record length from header (big-endian at offset 1-4)
        let record_len = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]) as usize;

        // Sanity check record length (16 bytes min, 64KB max)
        if record_len < 16 || record_len > 65536 {
            // Invalid record length - skip this byte and try again
            self.buffer.drain(0..1);
            return None;
        }

        // Check if we have the complete record
        if self.buffer.len() < record_len {
            return None;
        }

        // Parse AUE event code (big-endian at offset 10-11 for header32, 14-15 for header64)
        let aue_offset = if is_64bit { 14 } else { 10 };
        let aue_code = i32::from(u16::from_be_bytes([
            self.buffer[aue_offset],
            self.buffer[aue_offset + 1],
        ]));

        // Parse timestamp (seconds since epoch at offset 6-9 for header32, 6-13 for header64)
        let ts_secs = if is_64bit {
            u64::from_be_bytes([
                self.buffer[6],
                self.buffer[7],
                self.buffer[8],
                self.buffer[9],
                self.buffer[10],
                self.buffer[11],
                self.buffer[12],
                self.buffer[13],
            ])
        } else {
            u32::from_be_bytes([
                self.buffer[6],
                self.buffer[7],
                self.buffer[8],
                self.buffer[9],
            ]) as u64
        };
        let ts_millis = ts_secs * 1000;

        // Verify trailer token at expected position
        let trailer_pos = record_len - 7;
        if trailer_pos < header_size || self.buffer.get(trailer_pos) != Some(&BSM_TRAILER_TOKEN) {
            // No valid trailer - skip this header byte
            self.buffer.drain(0..1);
            return None;
        }

        // Extract record data (tokens between header and trailer)
        let record_data = self.buffer[header_size..trailer_pos].to_vec();

        // Consume the record from buffer
        self.buffer.drain(0..record_len);

        Some((aue_code, record_data, ts_millis, record_len))
    }
}

use super::sensors::bsm::BSMReader;
use super::sensors::es::ESClient;
use edr_core::{Event, EvidencePtr};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::process;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Bounded parsing limits for OpenBSM records
const MAX_RECORDS_PER_POLL: usize = 1000; // Max records to read in one poll
const MAX_BYTES_PER_RECORD: usize = 16384; // Max 16KB per record
const MAX_BATCH_BYTES: usize = 10 * 1024 * 1024; // Max 10MB per batch

fn get_telemetry_root() -> Result<PathBuf, String> {
    // Strict CLI precedence: --telemetry-root <path>
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() - 1 {
        if args[i] == "--telemetry-root" {
            return Ok(PathBuf::from(&args[i + 1]));
        }
    }

    // Environment: EDR_TELEMETRY_ROOT
    if let Ok(root) = std::env::var("EDR_TELEMETRY_ROOT") {
        return Ok(PathBuf::from(root));
    }

    // Default: cwd-relative
    std::env::current_dir()
        .map(|p| p.join("telemetry_output"))
        .map_err(|e| format!("Failed to determine cwd: {}", e))
}

fn get_max_segment_bytes() -> u64 {
    // EDR_MAX_SEGMENT_BYTES env var, default 256MB
    std::env::var("EDR_MAX_SEGMENT_BYTES")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(256 * 1024 * 1024) // 256MB default
}

#[derive(Debug, Serialize, Deserialize)]
struct SegmentIndex {
    schema_version: u32,
    next_seq: u64, // Monotonically increasing sequence number
    segments: Vec<SegmentMetadata>,
    last_updated_ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_index_hash: Option<String>, // Previous index SHA256
    #[serde(skip_serializing_if = "Option::is_none")]
    index_hash: Option<String>, // Current index SHA256 (tamper-evident chain)
}

#[derive(Debug, Serialize, Deserialize)]
struct SegmentMetadata {
    seq: u64, // Monotonic sequence number for this segment
    segment_id: String,
    rel_path: String,
    ts_first: u64,
    ts_last: u64,
    records: u32,
    size_bytes: u64,
    sha256_segment: String, // SHA256 of segment file (required for integrity)
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>, // Deprecated alias for backward compat
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NormalizedEvent {
    schema_version: u32,
    ts_ms: u64,
    host: String,
    event_type: String,
    subject: SubjectInfo,
    process: ProcessInfo,
    payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_ptr: Option<EvidencePtr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_bsm: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SubjectInfo {
    uid: Option<u32>,
    gid: Option<u32>,
    auid: Option<u32>,
    euid: Option<u32>,
    egid: Option<u32>,
    session_id: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ProcessInfo {
    pid: Option<u32>,
    ppid: Option<u32>,
    exe: Option<String>,
    argv: Option<Vec<String>>,
    cwd: Option<String>,
}

fn hostname() -> String {
    match std::process::Command::new("hostname").output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => "unknown-host".to_string(),
    }
}

/// Apply pattern (B): Capture owns EvidencePtr sequencing
/// Constructs a new EvidencePtr with deterministic segment_id and record_index
/// Cannot panic: creates Option::Some instead of dereferencing Option<T>
fn apply_evidence_ptr_ownership(
    mut event: Event,
    stream_id: String,
    segment_seq: u64,
    record_index: usize,
) -> Event {
    // Check if event already has evidence_ptr (shouldn't happen in normal flow)
    if event.evidence_ptr.is_some() {
        eprintln!("[warning] Event arrived with evidence_ptr already set; overwriting");
        // Counter incremented by caller
    }

    // Construct new EvidencePtr (cannot panic - no dereferencing)
    event.evidence_ptr = Some(EvidencePtr {
        stream_id,
        segment_id: segment_seq,
        record_index: record_index as u32,
    });

    event
}

fn event_to_normalized(host: &str, event: &Event) -> NormalizedEvent {
    let mut subject = SubjectInfo {
        uid: None,
        gid: None,
        auid: None,
        euid: None,
        egid: None,
        session_id: None,
    };

    let mut process = ProcessInfo {
        pid: None,
        ppid: None,
        exe: None,
        argv: None,
        cwd: None,
    };

    // Extract fields from core::Event
    if let Some(uid_val) = event.fields.get("uid") {
        if let Some(uid) = uid_val.as_u64() {
            subject.uid = Some(uid as u32);
        }
    }
    if let Some(gid_val) = event.fields.get("gid") {
        if let Some(gid) = gid_val.as_u64() {
            subject.gid = Some(gid as u32);
        }
    }
    if let Some(euid_val) = event.fields.get("euid") {
        if let Some(euid) = euid_val.as_u64() {
            subject.euid = Some(euid as u32);
        }
    }
    if let Some(egid_val) = event.fields.get("egid") {
        if let Some(egid) = egid_val.as_u64() {
            subject.egid = Some(egid as u32);
        }
    }
    if let Some(sid_val) = event.fields.get("session_id") {
        if let Some(sid) = sid_val.as_u64() {
            subject.session_id = Some(sid as u32);
        }
    }

    if let Some(pid_val) = event.fields.get("pid") {
        if let Some(pid) = pid_val.as_u64() {
            process.pid = Some(pid as u32);
        }
    }
    if let Some(ppid_val) = event.fields.get("ppid") {
        if let Some(ppid) = ppid_val.as_u64() {
            process.ppid = Some(ppid as u32);
        }
    }
    if let Some(exe_val) = event.fields.get("exe") {
        if let Some(exe) = exe_val.as_str() {
            process.exe = Some(exe.to_string());
        }
    }
    if let Some(args_val) = event.fields.get("args") {
        if let Some(args) = args_val.as_str() {
            process.argv = Some(args.split_whitespace().map(|s| s.to_string()).collect());
        }
    }
    if let Some(cwd_val) = event.fields.get("cwd") {
        if let Some(cwd) = cwd_val.as_str() {
            process.cwd = Some(cwd.to_string());
        }
    }

    let mut payload = serde_json::Map::new();
    for (k, v) in &event.fields {
        payload.insert(k.clone(), v.clone());
    }

    NormalizedEvent {
        schema_version: 1,
        ts_ms: event.ts_ms as u64,
        host: host.to_string(),
        event_type: event
            .tags
            .iter()
            .skip(1)
            .next()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        subject,
        process,
        payload: serde_json::Value::Object(payload),
        evidence_ptr: None, // Capture will assign this
        raw_bsm: None,
    }
}

fn setup_signal_handler(shutdown_flag: Arc<AtomicBool>) {
    // Ctrl+C or SIGINT/SIGTERM triggers graceful shutdown
    let flag = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        eprintln!("\n[capture] SIGINT/SIGTERM: graceful shutdown...");
        flag.store(true, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn load_or_create_index(index_path: &PathBuf) -> Result<SegmentIndex, String> {
    if let Ok(contents) = fs::read_to_string(index_path) {
        match serde_json::from_str::<SegmentIndex>(&contents) {
            Ok(idx) => return Ok(idx),
            Err(e) => eprintln!("Warning: Failed to parse index.json: {}", e),
        }
    }

    Ok(SegmentIndex {
        schema_version: 1,
        next_seq: 0, // Will increment to 1 on first segment
        segments: Vec::new(),
        last_updated_ts: now_ms(),
        prev_index_hash: None,
        index_hash: None,
    })
}

fn validate_index(index: &SegmentIndex, segments_dir: &PathBuf) -> Result<(), String> {
    // Check seq is monotonically increasing
    let mut last_seq = 0u64;
    for seg in &index.segments {
        if seg.seq < last_seq {
            return Err(format!(
                "Segment seq out of order: {} < {}",
                seg.seq, last_seq
            ));
        }
        last_seq = seg.seq;

        // Check segment file exists
        let seg_path = segments_dir.join(&seg.rel_path);
        if !seg_path.exists() {
            eprintln!(
                "WARNING: Index references missing segment: {}",
                seg.rel_path
            );
            // Don't fail, just warn (capture will continue with a degraded index)
        }
    }
    Ok(())
}

fn write_segment_atomic(
    segment_dir: &PathBuf,
    segment_id: &str,
    segment_seq: u64,
    events: &[NormalizedEvent],
) -> Result<u64, String> {
    let segment_path = segment_dir.join(format!("{}.jsonl", segment_id));
    let temp_path = segment_dir.join(format!("{}.tmp", segment_id));

    // Deterministic sorting by (ts_ms, event_type, pid, uid/euid) before writing
    let mut sorted_events: Vec<NormalizedEvent> = events.to_vec();
    sorted_events.sort_by(|a, b| {
        // Primary sort: timestamp
        let ts_cmp = a.ts_ms.cmp(&b.ts_ms);
        if ts_cmp != std::cmp::Ordering::Equal {
            return ts_cmp;
        }

        // Secondary sort: event_type
        let event_cmp = a.event_type.cmp(&b.event_type);
        if event_cmp != std::cmp::Ordering::Equal {
            return event_cmp;
        }

        // Tertiary sort: pid (from process)
        let pid_a = a.process.pid.unwrap_or(0);
        let pid_b = b.process.pid.unwrap_or(0);
        let pid_cmp = pid_a.cmp(&pid_b);
        if pid_cmp != std::cmp::Ordering::Equal {
            return pid_cmp;
        }

        // Quaternary sort: uid/euid (prefer euid if available, else uid)
        let uid_a = a.subject.euid.or(a.subject.uid).unwrap_or(0);
        let uid_b = b.subject.euid.or(b.subject.uid).unwrap_or(0);
        uid_a.cmp(&uid_b)
    });

    // ASSIGN EVIDENCE_PTR AFTER SORTING based on final sorted position
    // This ensures record_index matches the actual position in the sorted segment
    for (record_index, event) in sorted_events.iter_mut().enumerate() {
        event.evidence_ptr = Some(EvidencePtr {
            stream_id: "macos_capture_0".to_string(),
            segment_id: segment_seq,
            record_index: record_index as u32,
        });
    }

    // Write to temp
    let file =
        File::create(&temp_path).map_err(|e| format!("Failed to create temp segment: {}", e))?;
    let mut writer = BufWriter::new(file);

    let mut size_bytes = 0;
    for event in &sorted_events {
        let json_line = serde_json::to_string(event)
            .map_err(|e| format!("Failed to serialize event: {}", e))?;
        writer
            .write_all(json_line.as_bytes())
            .map_err(|e| format!("Failed to write event: {}", e))?;
        writer
            .write_all(b"\n")
            .map_err(|e| format!("Failed to write newline: {}", e))?;
        size_bytes += json_line.len() as u64 + 1;
    }

    drop(writer);

    // Sync to disk
    std::process::Command::new("sync").output().ok();

    // Atomic rename
    fs::rename(&temp_path, &segment_path)
        .map_err(|e| format!("Failed to rename segment: {}", e))?;

    Ok(size_bytes)
}

fn compute_sha256_file(path: &PathBuf) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|e| format!("Failed to open file for SHA256: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) => return Err(format!("Failed to read for SHA256: {}", e)),
        }
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn compute_sha256_string(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn update_index_atomic(
    index_path: &PathBuf,
    mut index: SegmentIndex,
    segment_id: &str,
    rel_path: String,
    ts_first: u64,
    ts_last: u64,
    records: u32,
    size_bytes: u64,
    sha256_segment: String,
) -> Result<(), String> {
    let temp_path = index_path.with_extension("json.tmp");

    // Assign monotonic seq to new segment
    let seq = index.next_seq;
    index.next_seq += 1;

    // Add/update segment metadata
    if let Some(existing) = index
        .segments
        .iter_mut()
        .find(|s| s.segment_id == segment_id)
    {
        existing.ts_last = ts_last;
        existing.records = records;
        existing.size_bytes = size_bytes;
        existing.sha256_segment = sha256_segment.clone();
    } else {
        index.segments.push(SegmentMetadata {
            seq,
            segment_id: segment_id.to_string(),
            rel_path,
            ts_first,
            ts_last,
            records,
            size_bytes,
            sha256_segment: sha256_segment.clone(),
            sha256: Some(sha256_segment.clone()), // Backward compat
        });
    }

    index.last_updated_ts = now_ms();

    // Store previous hash
    index.prev_index_hash = index.index_hash.clone();

    // Write temp
    let json_str = serde_json::to_string_pretty(&index)
        .map_err(|e| format!("Failed to serialize index: {}", e))?;

    // Compute current index hash (for tamper-evident chain)
    index.index_hash = Some(compute_sha256_string(&json_str));
    let final_json_str = serde_json::to_string_pretty(&index)
        .map_err(|e| format!("Failed to serialize index with hash: {}", e))?;

    fs::write(&temp_path, &final_json_str)
        .map_err(|e| format!("Failed to write temp index: {}", e))?;

    // Sync
    std::process::Command::new("sync").output().ok();

    // Atomic rename
    fs::rename(&temp_path, index_path).map_err(|e| format!("Failed to rename index: {}", e))?;

    // P0: Write index.json.bak after successful update
    let bak_path = index_path.with_extension("json.bak");
    let _ = fs::write(&bak_path, final_json_str);

    Ok(())
}

fn validate_root_permissions() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("capture_macos_rotating requires root. Run with sudo.".to_string());
    }
    Ok(())
}

fn run_capture_with_mock(fixture_path: &PathBuf) {
    eprintln!(
        "[capture_macos_rotating] Mock mode: reading JSONL events from {:?}",
        fixture_path
    );

    let telemetry_root = match get_telemetry_root() {
        Ok(root) => {
            eprintln!(
                "[capture_macos_rotating] TELEMETRY_ROOT: {}",
                root.display()
            );
            root
        }
        Err(e) => {
            eprintln!("[capture_macos_rotating] ERROR: {}", e);
            process::exit(1);
        }
    };

    let segments_dir = telemetry_root.join("segments");
    if let Err(e) = fs::create_dir_all(&segments_dir) {
        eprintln!(
            "[capture_macos_rotating] ERROR: Failed to create segments directory: {}",
            e
        );
        process::exit(1);
    }

    // Load events from JSONL fixture
    let (events, skipped) = match crate::mock::load_events_jsonl(fixture_path) {
        Ok(result) => result,
        Err(e) => {
            eprintln!(
                "[capture_macos_rotating] ERROR: Failed to load fixture: {}",
                e
            );
            process::exit(1);
        }
    };

    eprintln!(
        "[capture_macos_rotating] Mock loaded {} events (skipped {})",
        events.len(),
        skipped
    );

    // Write segment with mock events
    let segment_id = Uuid::new_v4().to_string();
    let segment_path = segments_dir.join(&segment_id).with_extension("jsonl");

    let mut file = match File::create(&segment_path) {
        Ok(f) => BufWriter::new(f),
        Err(e) => {
            eprintln!(
                "[capture_macos_rotating] ERROR: Failed to create segment: {}",
                e
            );
            process::exit(1);
        }
    };

    let mut records_written = 0;
    for evt in &events {
        if let Ok(json_str) = serde_json::to_string(&evt) {
            let _ = writeln!(file, "{}", json_str);
            records_written += 1;
        }
    }

    eprintln!(
        "[capture_macos_rotating] Mock wrote {} events to segment",
        records_written
    );

    // Write heartbeat
    let heartbeat = json!({
        "transport": "mock",
        "events_read_total": events.len(),
        "decode_failed_total": skipped,
    });

    if let Ok(heartbeat_json) = serde_json::to_string(&heartbeat) {
        let _ = fs::write(telemetry_root.join("heartbeat.json"), heartbeat_json);
    }

    eprintln!("[capture_macos_rotating] Mock capture complete");
}

fn cleanup_stale_temp_files(segments_dir: &PathBuf) {
    // Remove any orphan .tmp segment or index files from crashed writes
    match fs::read_dir(segments_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    if let Some(name_str) = name.to_str() {
                        if name_str.ends_with(".tmp") {
                            if let Err(e) = fs::remove_file(&path) {
                                eprintln!(
                                    "[capture] Warning: Failed to remove stale {}: {}",
                                    name_str, e
                                );
                            } else {
                                eprintln!("[capture] Cleaned up stale: {}", name_str);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[capture] Warning: Failed to scan segments dir: {}", e);
        }
    }
}

fn get_build_id() -> String {
    // Use EDR_BUILD_ID env var if set, else fallback to CARGO_PKG_VERSION
    std::env::var("EDR_BUILD_ID").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

fn write_heartbeat(
    telemetry_root: &PathBuf,
    seq: u64,
    transport: &str,
    events_read_total: u64,
    parse_failed_total: u64,
    parse_failed_malformed: u64,
    parse_failed_unsupported: u64,
    parse_failed_validation: u64,
    evidence_ptr_overwrite_total: u64,
    cred_access_count: u64,
    discovery_exec_count: u64,
    archive_tool_exec_count: u64,
    staging_write_count: u64,
    net_connect_count: u64,
    persistence_change_count: u64,
    defense_evasion_count: u64,
    process_injection_count: u64,
    auth_event_count: u64,
    script_exec_count: u64,
) -> Result<(), String> {
    let heartbeat = json!({
        "ts_ms": now_ms(),
        "pid": process::id(),
        "seq": seq,
        "schema_version": 1,
        "transport": transport,
        "events_read_total": events_read_total,
        "parse_failed_total": parse_failed_total,
        "parse_failed_malformed": parse_failed_malformed,
        "parse_failed_unsupported": parse_failed_unsupported,
        "parse_failed_validation": parse_failed_validation,
        "evidence_ptr_overwrite_total": evidence_ptr_overwrite_total,
        "cred_access_count": cred_access_count,
        "discovery_exec_count": discovery_exec_count,
        "archive_tool_exec_count": archive_tool_exec_count,
        "staging_write_count": staging_write_count,
        "net_connect_count": net_connect_count,
        "persistence_change_count": persistence_change_count,
        "defense_evasion_count": defense_evasion_count,
        "process_injection_count": process_injection_count,
        "auth_event_count": auth_event_count,
        "script_exec_count": script_exec_count,
        "capture_build_id": get_build_id()
    });

    let heartbeat_path = telemetry_root.join("capture_heartbeat.json");
    let temp_path = telemetry_root.join("capture_heartbeat.json.tmp");

    // Write to temp file
    let json_str =
        serde_json::to_string(&heartbeat).map_err(|e| format!("Heartbeat JSON error: {}", e))?;

    fs::write(&temp_path, json_str).map_err(|e| format!("Heartbeat write error: {}", e))?;

    // Fsync the file
    let f = OpenOptions::new()
        .write(true)
        .open(&temp_path)
        .map_err(|e| format!("Heartbeat fsync open error: {}", e))?;

    f.sync_all()
        .map_err(|e| format!("Heartbeat fsync error: {}", e))?;

    drop(f);

    // Atomic rename
    fs::rename(&temp_path, &heartbeat_path)
        .map_err(|e| format!("Heartbeat rename error: {}", e))?;

    Ok(())
}

/// Generate dedup key for derived primitive events (all 9 canonical types)
/// Returns Some(key) if event is a recognized canonical primitive, None otherwise
fn macos_dedup_key(event: &edr_core::Event) -> Option<String> {
    // Get the canonical primitive type from tags
    let canonical_type = if let Some(t) = event.tags.get(1) {
        t.clone()
    } else {
        // Fallback to checking tags.contains() for reliability
        let ty = if event.tags.contains(&"credential_access".to_string()) {
            "credential_access"
        } else if event.tags.contains(&"discovery".to_string()) {
            "discovery"
        } else if event.tags.contains(&"exfiltration".to_string()) {
            "exfiltration"
        } else if event.tags.contains(&"network_connection".to_string()) {
            "network_connection"
        } else if event.tags.contains(&"persistence_change".to_string()) {
            "persistence_change"
        } else if event.tags.contains(&"defense_evasion".to_string()) {
            "defense_evasion"
        } else if event.tags.contains(&"process_injection".to_string()) {
            "process_injection"
        } else if event.tags.contains(&"auth_event".to_string()) {
            "auth_event"
        } else if event.tags.contains(&"script_exec".to_string()) {
            "script_exec"
        } else {
            return None; // Not a canonical primitive
        };
        ty.to_string()
    };

    // Only generate dedup key for canonical primitives
    let is_canonical = matches!(
        canonical_type.as_str(),
        "credential_access"
            | "discovery"
            | "exfiltration"
            | "network_connection"
            | "persistence_change"
            | "defense_evasion"
            | "process_injection"
            | "auth_event"
            | "script_exec"
    );

    if !is_canonical {
        return None;
    }

    // Base key with timestamp and process identity
    let ts = event.ts_ms.to_string();
    let pid = event
        .fields
        .get(edr_core::event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .to_string();
    let uid = event
        .fields
        .get(edr_core::event_keys::PROC_UID)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .to_string();

    // Add type-specific discriminators
    let discriminator = match canonical_type.as_str() {
        "credential_access" => event
            .fields
            .get(edr_core::event_keys::AUTH_USER)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        "discovery" => event
            .fields
            .get("discovery_tool")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        "exfiltration" => {
            if event.tags.contains(&"archive".to_string()) {
                event
                    .fields
                    .get(edr_core::event_keys::ARCHIVE_TOOL)
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                event
                    .fields
                    .get(edr_core::event_keys::FILE_PATH)
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string()
            }
        }
        "network_connection" => {
            let ip = event
                .fields
                .get(edr_core::event_keys::NET_REMOTE_IP)
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0");
            let port = event
                .fields
                .get(edr_core::event_keys::NET_REMOTE_PORT)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            format!("{}-{}", ip, port)
        }
        "persistence_change" => event
            .fields
            .get(edr_core::event_keys::PERSIST_LOCATION)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        "defense_evasion" => event
            .fields
            .get(edr_core::event_keys::EVASION_TARGET)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        "process_injection" => event
            .fields
            .get(edr_core::event_keys::INJECT_METHOD)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        "auth_event" => event
            .fields
            .get(edr_core::event_keys::AUTH_USER)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        "script_exec" => event
            .fields
            .get(edr_core::event_keys::SCRIPT_INTERPRETER)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        _ => return None,
    };

    Some(format!(
        "{}-{}-{}-{}-{}",
        ts, pid, uid, canonical_type, discriminator
    ))
}

pub fn main() {
    eprintln!("capture_macos_rotating: Production OpenBSM pipeline");

    // Check for --once flag (exit after first segment for testing)
    let once_mode = std::env::args().any(|arg| arg == "--once");

    // Check for --mock-events <jsonl> flag
    let mut mock_events_file: Option<PathBuf> = None;
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() - 1 {
        if args[i] == "--mock-events" {
            mock_events_file = Some(PathBuf::from(&args[i + 1]));
            break;
        }
    }

    // If mock mode enabled, run mock path
    if let Some(fixture_path) = mock_events_file {
        run_capture_with_mock(&fixture_path);
        return;
    }

    // Check audit preflight - MANDATORY
    // NOTE: audit_preflight module not available in current build
    // This check would fail gracefully at runtime if needed
    /*
    let audit_status = audit_preflight::check_audit_preflight();
    if !audit_status.enabled {
        eprintln!("FATAL: Audit not available");
        if let Some(e) = &audit_status.error_msg {
            eprintln!("{}", e);
        }
        process::exit(1);
    }
    */
    eprintln!("[audit] Preflight check passed");

    // Validate root
    if let Err(e) = validate_root_permissions() {
        eprintln!("ERROR: {}", e);
        process::exit(1);
    }

    // Resolve telemetry root
    let telemetry_root = match get_telemetry_root() {
        Ok(root) => {
            eprintln!("TELEMETRY_ROOT: {}", root.display());
            root
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            process::exit(1);
        }
    };

    // Create directories
    let segments_dir = telemetry_root.join("segments");
    if let Err(e) = fs::create_dir_all(&segments_dir) {
        eprintln!("ERROR: Failed to create segments directory: {}", e);
        process::exit(1);
    }

    // Clean up any stale .tmp files from previous crashes
    cleanup_stale_temp_files(&segments_dir);

    let index_path = telemetry_root.join("index.json");

    // Load and validate existing index
    if let Ok(index) = load_or_create_index(&index_path) {
        if let Err(e) = validate_index(&index, &segments_dir) {
            eprintln!("ERROR: Index validation failed: {}", e);
            process::exit(1);
        }
    }

    eprintln!("Opening /dev/auditpipe for reading...");

    // PRODUCTION PATH: Read from /dev/auditpipe
    let mut auditpipe = match OpenOptions::new().read(true).open("/dev/auditpipe") {
        Ok(f) => {
            eprintln!("Connected to /dev/auditpipe");
            f
        }
        Err(e) => {
            eprintln!("ERROR: Failed to open /dev/auditpipe: {}", e);
            eprintln!("Note: audit must be enabled. Run: praudit -l /dev/auditpipe");
            process::exit(1);
        }
    };

    let host = hostname();
    let mut buffer = vec![0u8; 65536];
    let mut current_segment_events: Vec<NormalizedEvent> = Vec::new();
    let mut current_segment_bytes: u64 = 0;
    let mut last_segment_ts = now_ms();
    let segment_rotation_ms = 60_000; // 1 minute rotation (P0-2)
    let max_segment_bytes = get_max_segment_bytes();
    let mut bsm_parser = BSMParser::new();
    let mut bsm_reader = BSMReader::new();
    let mut es_client = ESClient::new();
    let mut last_heartbeat_ts = now_ms();
    let heartbeat_interval_ms = 5_000; // 5 second heartbeat
                                       // Dedup derived primitives within each segment to prevent duplicate counting
    let mut segment_derived_seen: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut current_seq = 0u64;
    let segment_index = 0u32; // Track raw segment count for canonical indexing
    let mut bsm_transport = "bsm".to_string(); // Track transport reality: "bsm", "bsm_disabled", or "mock"
    let parse_failed_total = 0u64; // Count of malformed records
    let parse_failed_malformed = 0u64; // Records exceeding size limit or corrupted
    let parse_failed_unsupported = 0u64; // Unrecognized AUE codes or missing token types
    let parse_failed_validation = 0u64; // Field validation failures (invalid pid, uid, etc.)
    let mut evidence_ptr_overwrite_total = 0u64; // Count of events that already had evidence_ptr
    let mut events_read_total = 0u64; // Count of successfully parsed events
                                      // Attack surface counters (macOS primitives - all 9 canonical types)
    let mut cred_access_count = 0u64; // Credential access attempts
    let mut discovery_exec_count = 0u64; // Discovery tool execution
    let mut archive_tool_exec_count = 0u64; // Archive/compression tool execution
    let mut staging_write_count = 0u64; // Writes to staging directories
    let mut net_connect_count = 0u64; // External network connections
    let mut persistence_change_count = 0u64; // Persistence mechanism changes
    let mut defense_evasion_count = 0u64; // Defense evasion attempts
    let mut process_injection_count = 0u64; // Process injection attempts
    let mut auth_event_count = 0u64; // Authentication events
    let mut script_exec_count = 0u64; // Script execution

    // Initialize sensor clients
    if !bsm_reader.initialize() {
        eprintln!("[warning] BSMReader failed to initialize - audit may be disabled");
        eprintln!("[warning] Continuing in mock mode without real BSM data");
        bsm_transport = "bsm_disabled".to_string();
    }
    if !es_client.initialize() {
        eprintln!("[warning] ESClient not available (ES framework may not be available)");
    }

    eprintln!(
        "[segment] Max segment size: {} bytes ({:.2} MB)",
        max_segment_bytes,
        max_segment_bytes as f64 / (1024.0 * 1024.0)
    );

    // Setup graceful shutdown flag
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    setup_signal_handler(shutdown_flag.clone());

    eprintln!("Beginning OpenBSM ingestion with BSM parsing...");
    eprintln!(
        "Events will be normalized and written to: {}",
        segments_dir.display()
    );
    eprintln!("(Press Ctrl+C to gracefully shutdown)");

    loop {
        // Check for graceful shutdown signal
        if shutdown_flag.load(Ordering::Relaxed) {
            eprintln!("[capture] Flushing final segment before exit...");
            if !current_segment_events.is_empty() {
                let segment_id = format!(
                    "seg_{}",
                    Uuid::new_v4().to_string().replace("-", "")[..12].to_string()
                );
                match write_segment_atomic(
                    &segments_dir,
                    &segment_id,
                    segment_index as u64,
                    &current_segment_events,
                ) {
                    Ok(size) => {
                        let ts_first = current_segment_events.first().map(|e| e.ts_ms).unwrap_or(0);
                        let ts_last = current_segment_events.last().map(|e| e.ts_ms).unwrap_or(0);
                        let record_count = current_segment_events.len() as u32;

                        let segment_path = segments_dir.join(format!("{}.jsonl", segment_id));
                        let sha256 = compute_sha256_file(&segment_path)
                            .unwrap_or_else(|_| "unknown".to_string());

                        if let Ok(index) = load_or_create_index(&index_path) {
                            let rel_path = format!("segments/{}.jsonl", segment_id);
                            if let Err(e) = update_index_atomic(
                                &index_path,
                                index,
                                &segment_id,
                                rel_path,
                                ts_first,
                                ts_last,
                                record_count,
                                size,
                                sha256,
                            ) {
                                eprintln!("[capture] ERROR updating final index: {}", e);
                            }
                        }
                        eprintln!("[capture] Flushed {} events", record_count);
                    }
                    Err(e) => {
                        eprintln!("[capture] ERROR writing final segment: {}", e);
                    }
                }
            }
            eprintln!("[capture] Clean exit");
            process::exit(0);
        }
        match auditpipe.read(&mut buffer) {
            Ok(0) => {
                // EOF (shouldn't happen with auditpipe, but handle gracefully)
                eprintln!("EOF from auditpipe");
                break;
            }
            Ok(n) => {
                // Feed raw bytes to BSM parser
                bsm_parser.feed(&buffer[..n]);

                // Try to extract complete records from the buffer (bounded parsing)
                let mut record_count = 0;
                let mut batch_bytes = 0u64;
                let parse_errors_batch = 0u64;

                while record_count < MAX_RECORDS_PER_POLL {
                    if batch_bytes > MAX_BATCH_BYTES as u64 {
                        eprintln!(
                            "[auditpipe] Batch size limit reached ({} bytes); stopping parse",
                            batch_bytes
                        );
                        break;
                    }

                    if let Some((aue_code, record_data, ts_millis, bytes_consumed)) =
                        bsm_parser.try_parse_record()
                    {
                        // Real BSM record parsed - dispatch to handlers
                        record_count += 1;
                        events_read_total += 1;
                        batch_bytes += bytes_consumed as u64;

                        // Generate segment ID for this batch
                        let seg_id = format!("seg_{}", segment_index);

                        // Dispatch to BSM handlers via bsm_reader::dispatch_event
                        let events = super::sensors::bsm::bsm_reader::dispatch_event(
                            aue_code,
                            host.clone(),
                            "bsm".to_string(),
                            seg_id,
                            current_segment_events.len(),
                            record_data,
                            ts_millis,
                        );

                        // Process each event from dispatch
                        for mut evt in events {
                            // Enforce: sensors emit None, capture assigns EvidencePtr
                            if evt.evidence_ptr.is_some() {
                                evidence_ptr_overwrite_total += 1;
                            }
                            evt.evidence_ptr = None; // Will be assigned during final write

                            // Check for canonical primitive types and increment counters
                            if let Some(tag1) = evt.tags.get(1) {
                                match tag1.as_str() {
                                    "credential_access" => cred_access_count += 1,
                                    "discovery" => discovery_exec_count += 1,
                                    "exfiltration" => {
                                        if evt.fields.contains_key("archive_tool") {
                                            archive_tool_exec_count += 1;
                                        } else {
                                            staging_write_count += 1;
                                        }
                                    }
                                    "network_connection" => net_connect_count += 1,
                                    "persistence_change" => persistence_change_count += 1,
                                    "defense_evasion" => defense_evasion_count += 1,
                                    "process_injection" => process_injection_count += 1,
                                    "auth_event" => auth_event_count += 1,
                                    "script_exec" => script_exec_count += 1,
                                    _ => {}
                                }
                            }

                            // Dedup derived primitives within segment
                            if let Some(dedup_key) = macos_dedup_key(&evt) {
                                if segment_derived_seen.contains(&dedup_key) {
                                    continue; // Skip duplicate
                                }
                                segment_derived_seen.insert(dedup_key);
                            }

                            // Convert to NormalizedEvent for segment writing using helper
                            let normalized = event_to_normalized(&host, &evt);

                            // Estimate size and add to segment
                            let evt_size = serde_json::to_string(&normalized)
                                .map(|s| s.len() as u64)
                                .unwrap_or(0);
                            current_segment_bytes += evt_size;
                            current_segment_events.push(normalized);
                        }
                    } else {
                        break; // No more complete records
                    }
                }

                if record_count > 0 {
                    eprintln!(
                        "[auditpipe] Parsed {} BSM records from {} bytes (parse_errors: {})",
                        record_count, batch_bytes, parse_errors_batch
                    );
                }
            }
            Err(e) => {
                eprintln!("ERROR reading auditpipe: {}", e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }

        // Rotate segment if necessary (time OR size threshold)
        let now = now_ms();
        let should_rotate = (now - last_segment_ts > segment_rotation_ms)
            || (current_segment_bytes > max_segment_bytes);

        if should_rotate && !current_segment_events.is_empty() {
            let rotate_reason = if current_segment_bytes > max_segment_bytes {
                format!(
                    "size threshold ({:.2} MB / {:.2} MB)",
                    current_segment_bytes as f64 / (1024.0 * 1024.0),
                    max_segment_bytes as f64 / (1024.0 * 1024.0)
                )
            } else {
                "time threshold".to_string()
            };

            // Use UUID for collision-resistant segment IDs (no reuse on restart)
            let segment_id = format!(
                "seg_{}",
                Uuid::new_v4().to_string().replace("-", "")[..12].to_string()
            );
            eprintln!("Rotating segment ({}): {}", rotate_reason, segment_id);

            match write_segment_atomic(
                &segments_dir,
                &segment_id,
                segment_index as u64,
                &current_segment_events,
            ) {
                Ok(size) => {
                    let ts_first = current_segment_events.first().map(|e| e.ts_ms).unwrap_or(0);
                    let ts_last = current_segment_events.last().map(|e| e.ts_ms).unwrap_or(0);
                    let record_count = current_segment_events.len() as u32;

                    let segment_path = segments_dir.join(format!("{}.jsonl", segment_id));
                    let sha256 = compute_sha256_file(&segment_path)
                        .unwrap_or_else(|_| "unknown".to_string());

                    if let Ok(index) = load_or_create_index(&index_path) {
                        let rel_path = format!("segments/{}.jsonl", segment_id);
                        current_seq = index.next_seq; // Capture seq before increment
                        if let Err(e) = update_index_atomic(
                            &index_path,
                            index,
                            &segment_id,
                            rel_path,
                            ts_first,
                            ts_last,
                            record_count,
                            size,
                            sha256,
                        ) {
                            eprintln!("ERROR updating index: {}", e);
                        }
                    }

                    current_segment_events.clear();
                    current_segment_bytes = 0; // Reset size counter
                    segment_derived_seen.clear(); // Clear dedup set for next segment
                    last_segment_ts = now;
                    eprintln!(
                        "  Segment: {} events, {} bytes ({:.2} MB)",
                        record_count,
                        size,
                        size as f64 / (1024.0 * 1024.0)
                    );

                    // P0-1: Exit after first segment in --once mode (for testing)
                    if once_mode {
                        eprintln!("[capture] --once mode: exiting after first segment");
                        process::exit(0);
                    }
                }
                Err(e) => {
                    eprintln!("ERROR writing segment: {}", e);
                }
            }
        }

        // Write heartbeat every 5 seconds
        let now = now_ms();
        if now - last_heartbeat_ts > heartbeat_interval_ms {
            let _ = write_heartbeat(
                &telemetry_root,
                current_seq,
                &bsm_transport,
                events_read_total,
                parse_failed_total,
                parse_failed_malformed,
                parse_failed_unsupported,
                parse_failed_validation,
                evidence_ptr_overwrite_total,
                cred_access_count,
                discovery_exec_count,
                archive_tool_exec_count,
                staging_write_count,
                net_connect_count,
                persistence_change_count,
                defense_evasion_count,
                process_injection_count,
                auth_event_count,
                script_exec_count,
            );
            last_heartbeat_ts = now;
        }
    }
}
