//! capture_macos_rotating: BSM audit records to JSONL segments.
//!
//! Three input modes:
//!
//! - live: read /dev/auditpipe (needs root and auditing enabled in the kernel)
//! - replay: `--bsm-file <trail>` reads audit trail files, no root needed
//! - mock: `--mock-events <file.jsonl>` writes `edr_core::Event` lines as is
//!
//! Output, under the telemetry root:
//!
//! - `segments/seg_<seq>_<id>.jsonl`, one `edr_core::Event` per line. Each
//!   event's evidence pointer is (stream "bsm", segment seq, line number).
//! - `index.json`, the list of segments with a SHA-256 of each file and a
//!   hash chain over successive versions of the index.
//! - `capture_heartbeat.json`, counters that show what the agent is doing.

use crate::auditpipe;
use crate::sensors::bsm::{parse_record, Normalizer, RecordSplitter};
use edr_core::{Event, EvidencePtr};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STREAM_ID: &str = "bsm";
const ROTATE_AFTER_MS: u64 = 60_000;
const HEARTBEAT_EVERY_MS: u64 = 5_000;

const USAGE: &str = "\
capture_macos_rotating: decode OpenBSM audit records into JSONL segments

USAGE:
  sudo capture_macos_rotating [--telemetry-root DIR] [--classes LIST] [--once]
  capture_macos_rotating --bsm-file TRAIL [--bsm-file TRAIL ...] [--telemetry-root DIR] [--host NAME]
  capture_macos_rotating --mock-events FILE.jsonl [--telemetry-root DIR]

OPTIONS:
  --telemetry-root DIR  output folder (default: $EDR_TELEMETRY_ROOT, else ./telemetry_output)
  --bsm-file TRAIL      replay a binary audit trail instead of reading /dev/auditpipe
  --classes LIST        audit classes for the live pipe (default: ex,pc,fr,fw,fc,fd,fm,nt,ad)
  --host NAME           host name to stamp on events (default: this machine's host name)
  --once                live mode: exit after the first segment is written
  --duration SECONDS    live mode: capture for this long, write what was captured, exit
  --mock-events FILE    write edr_core::Event JSON lines from FILE as one segment
  -h, --help            show this help
";

#[derive(Debug, Default)]
pub struct CaptureArgs {
    pub telemetry_root: Option<PathBuf>,
    pub bsm_files: Vec<PathBuf>,
    pub mock_events: Option<PathBuf>,
    pub classes: Option<String>,
    pub host: Option<String>,
    pub once: bool,
    pub duration_secs: Option<u64>,
    pub help: bool,
}

pub fn parse_args(args: &[String]) -> Result<CaptureArgs, String> {
    let mut parsed = CaptureArgs::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let needs_value = matches!(
            arg,
            "--telemetry-root" | "--bsm-file" | "--mock-events" | "--classes" | "--host" | "--duration"
        );
        let value = if needs_value {
            if i + 1 >= args.len() {
                return Err(format!("{} needs a value", arg));
            }
            i += 1;
            Some(args[i].clone())
        } else {
            None
        };
        match arg {
            "--telemetry-root" => parsed.telemetry_root = value.map(PathBuf::from),
            "--bsm-file" => parsed.bsm_files.push(PathBuf::from(value.unwrap())),
            "--mock-events" => parsed.mock_events = value.map(PathBuf::from),
            "--classes" => parsed.classes = value,
            "--host" => parsed.host = value,
            "--once" => parsed.once = true,
            "--duration" => {
                let text = value.unwrap();
                parsed.duration_secs = Some(text.parse().map_err(|_| format!("--duration needs a number of seconds, got '{}'", text))?);
            }
            "-h" | "--help" => parsed.help = true,
            other => return Err(format!("unknown argument '{}'", other)),
        }
        i += 1;
    }
    Ok(parsed)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..end]).to_string();
        if !name.is_empty() {
            return name;
        }
    }
    "unknown-host".to_string()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Write `data` to `path` through a temp file, fsync and rename, so a reader
/// never sees half a file.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp).map_err(|e| format!("create {}: {}", tmp.display(), e))?;
        file.write_all(data).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {}", tmp.display(), e))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SegmentMetadata {
    pub seq: u64,
    pub segment_id: String,
    pub rel_path: String,
    pub stream_id: String,
    pub ts_first: u64,
    pub ts_last: u64,
    pub records: u32,
    pub size_bytes: u64,
    pub sha256_segment: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SegmentIndex {
    pub schema_version: u32,
    pub next_seq: u64,
    pub segments: Vec<SegmentMetadata>,
    pub last_updated_ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_index_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_hash: Option<String>,
}

impl SegmentIndex {
    fn empty() -> Self {
        SegmentIndex {
            schema_version: 1,
            next_seq: 0,
            segments: Vec::new(),
            last_updated_ts: now_ms(),
            prev_index_hash: None,
            index_hash: None,
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("index.json is not valid: {}", e)),
            Err(_) => Ok(SegmentIndex::empty()),
        }
    }

    /// Hash of the index with index_hash left out. Each new index stores the
    /// previous index_hash, so editing an old entry breaks the chain.
    pub fn compute_hash(&self) -> String {
        let mut copy = serde_json::to_value(self).unwrap_or(json!({}));
        if let Some(obj) = copy.as_object_mut() {
            obj.remove("index_hash");
        }
        sha256_hex(serde_json::to_string_pretty(&copy).unwrap_or_default().as_bytes())
    }
}

/// Collects events and writes them out as segments.
pub struct SegmentWriter {
    telemetry_root: PathBuf,
    segments_dir: PathBuf,
    index_path: PathBuf,
    events: Vec<Event>,
    bytes: u64,
    pub segments_written: u64,
    pub events_written: u64,
}

impl SegmentWriter {
    pub fn new(telemetry_root: &Path) -> Result<Self, String> {
        let segments_dir = telemetry_root.join("segments");
        fs::create_dir_all(&segments_dir).map_err(|e| format!("create {}: {}", segments_dir.display(), e))?;
        // Remove temp files left by a crash in the middle of a write.
        if let Ok(entries) = fs::read_dir(&segments_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().map(|e| e == "tmp").unwrap_or(false) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        let index_path = telemetry_root.join("index.json");
        // Refuse to append to an index that does not parse.
        SegmentIndex::load(&index_path)?;
        Ok(SegmentWriter {
            telemetry_root: telemetry_root.to_path_buf(),
            segments_dir,
            index_path,
            events: Vec::new(),
            bytes: 0,
            segments_written: 0,
            events_written: 0,
        })
    }

    pub fn push(&mut self, event: Event) {
        self.bytes += 256 + event.fields.len() as u64 * 32;
        self.events.push(event);
    }

    pub fn pending(&self) -> usize {
        self.events.len()
    }

    pub fn pending_bytes(&self) -> u64 {
        self.bytes
    }

    /// Write the buffered events as one segment and add it to index.json.
    pub fn flush(&mut self) -> Result<Option<SegmentMetadata>, String> {
        if self.events.is_empty() {
            return Ok(None);
        }
        let mut index = SegmentIndex::load(&self.index_path)?;
        let seq = index.next_seq;
        let short_id: String = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        let segment_id = format!("seg_{:06}_{}", seq, short_id);
        let rel_path = format!("segments/{}.jsonl", segment_id);

        let mut body = Vec::new();
        for (line_number, event) in self.events.iter_mut().enumerate() {
            event.evidence_ptr = Some(EvidencePtr {
                stream_id: STREAM_ID.to_string(),
                segment_id: seq,
                record_index: line_number as u32,
            });
            let line = serde_json::to_string(event).map_err(|e| e.to_string())?;
            body.extend_from_slice(line.as_bytes());
            body.push(b'\n');
        }
        let segment_path = self.segments_dir.join(format!("{}.jsonl", segment_id));
        write_atomic(&segment_path, &body)?;
        let sha = sha256_file(&segment_path)?;

        let ts_first = self.events.iter().map(|e| e.ts_ms).min().unwrap_or(0) as u64;
        let ts_last = self.events.iter().map(|e| e.ts_ms).max().unwrap_or(0) as u64;
        let meta = SegmentMetadata {
            seq,
            segment_id,
            rel_path,
            stream_id: STREAM_ID.to_string(),
            ts_first,
            ts_last,
            records: self.events.len() as u32,
            size_bytes: body.len() as u64,
            sha256_segment: sha,
        };

        index.next_seq = seq + 1;
        index.segments.push(meta.clone());
        index.last_updated_ts = now_ms();
        index.prev_index_hash = index.index_hash.take();
        index.index_hash = Some(index.compute_hash());
        let text = serde_json::to_string_pretty(&index).map_err(|e| e.to_string())?;
        write_atomic(&self.index_path, text.as_bytes())?;

        self.events_written += self.events.len() as u64;
        self.segments_written += 1;
        self.events.clear();
        self.bytes = 0;
        Ok(Some(meta))
    }

    pub fn telemetry_root(&self) -> &Path {
        &self.telemetry_root
    }
}

/// Counters written to capture_heartbeat.json.
#[derive(Debug, Default, Serialize)]
pub struct CaptureStats {
    pub transport: String,
    pub records_read: u64,
    pub records_decoded: u64,
    pub decode_errors: u64,
    pub records_with_unknown_token: u64,
    pub events_emitted: u64,
    pub records_not_handled: u64,
    pub skipped_bytes: u64,
    pub pipe_drops: Option<u64>,
    pub by_category: BTreeMap<String, u64>,
    pub last_decode_error: Option<String>,
}

/// Decode one record and hand the event to the writer.
pub fn process_record(
    bytes: &[u8],
    normalizer: &mut Normalizer,
    writer: &mut SegmentWriter,
    stats: &mut CaptureStats,
) {
    stats.records_read += 1;
    let record = match parse_record(bytes) {
        Ok(r) => r,
        Err(e) => {
            stats.decode_errors += 1;
            stats.last_decode_error = Some(e.to_string());
            return;
        }
    };
    stats.records_decoded += 1;
    if record.unknown_token.is_some() {
        stats.records_with_unknown_token += 1;
    }
    match normalizer.normalize(&record) {
        Some(event) => {
            let key = format!("{}.{}", event.tags[1], event.tags[2]);
            *stats.by_category.entry(key).or_insert(0) += 1;
            stats.events_emitted += 1;
            writer.push(event);
        }
        None => stats.records_not_handled += 1,
    }
}

fn write_heartbeat(root: &Path, stats: &CaptureStats, writer: &SegmentWriter) {
    let heartbeat = json!({
        "ts_ms": now_ms(),
        "pid": process::id(),
        "build": env!("CARGO_PKG_VERSION"),
        "segments_written": writer.segments_written,
        "events_written": writer.events_written,
        "stats": stats,
    });
    let text = serde_json::to_string_pretty(&heartbeat).unwrap_or_default();
    let _ = write_atomic(&root.join("capture_heartbeat.json"), text.as_bytes());
}

/// Replay audit trail files. No root needed.
pub fn run_replay(files: &[PathBuf], root: &Path, host: &str) -> Result<CaptureStats, String> {
    let mut writer = SegmentWriter::new(root)?;
    let mut normalizer = Normalizer::new(host, STREAM_ID);
    let mut stats = CaptureStats {
        transport: "bsm_file".to_string(),
        ..Default::default()
    };
    for file in files {
        let data = fs::read(file).map_err(|e| format!("read {}: {}", file.display(), e))?;
        let mut splitter = RecordSplitter::new();
        splitter.feed(&data);
        while let Some(record) = splitter.next_record() {
            process_record(&record, &mut normalizer, &mut writer, &mut stats);
        }
        stats.skipped_bytes += splitter.skipped_bytes + splitter.buffered() as u64;
        if let Some(meta) = writer.flush()? {
            eprintln!(
                "[capture] {} -> {} ({} events)",
                file.display(),
                meta.rel_path,
                meta.records
            );
        }
    }
    write_heartbeat(root, &stats, &writer);
    Ok(stats)
}

/// Write edr_core::Event JSON lines as one segment.
pub fn run_mock(fixture: &Path, root: &Path) -> Result<usize, String> {
    let (events, skipped) = crate::mock::load_events_jsonl(fixture)?;
    let mut writer = SegmentWriter::new(root)?;
    let count = events.len();
    for mut event in events {
        event.evidence_ptr = None;
        writer.push(event);
    }
    writer.flush()?;
    eprintln!("[capture] mock: wrote {} events, skipped {} lines", count, skipped);
    Ok(count)
}

/// Chunks the pipe reader may hold before it waits for the parser (each chunk is
/// one read, at most 256 KiB).
#[cfg(target_os = "macos")]
const READ_CHUNKS_QUEUED: usize = 4096;

#[cfg(target_os = "macos")]
fn run_live(root: &Path, host: &str, classes: &str, once: bool, duration_secs: Option<u64>) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("live capture reads /dev/auditpipe, which is root only. Run with sudo, or use --bsm-file to replay a trail.".to_string());
    }
    // audit -c exits 0 only when auditing is on in the kernel. It has been
    // off by default since macOS 14, and the pipe stays silent until it is on.
    match process::Command::new("/usr/sbin/audit").arg("-c").output() {
        Ok(out) if out.status.success() => eprintln!("[capture] audit -c: auditing is enabled in the kernel"),
        Ok(_) => eprintln!(
            "[capture] warning: audit -c says auditing is not enabled. Expect no records until it is. See the README section on enabling audit."
        ),
        Err(e) => eprintln!("[capture] warning: could not run /usr/sbin/audit -c: {}", e),
    }
    let class_mask = auditpipe::parse_classes(classes)?;
    let pipe = auditpipe::AuditPipe::open(class_mask)
        .map_err(|e| format!("could not open and configure /dev/auditpipe: {}", e))?;
    eprintln!(
        "[capture] /dev/auditpipe open, classes {} ({:#010x}), queue limit {}",
        classes, class_mask, pipe.queue_limit
    );
    eprintln!("[capture] if no records arrive, auditing is off in the kernel. See the README section on enabling audit.");

    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
        .map_err(|e| format!("signal handler: {}", e))?;

    let max_segment_bytes: u64 = std::env::var("EDR_MAX_SEGMENT_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(256 * 1024 * 1024);

    let mut writer = SegmentWriter::new(root)?;
    let mut normalizer = Normalizer::new(host, STREAM_ID);
    let mut splitter = RecordSplitter::new();
    let mut stats = CaptureStats {
        transport: "auditpipe".to_string(),
        ..Default::default()
    };
    // A reader thread only moves bytes from the pipe into a channel, and this loop
    // parses, normalizes and writes them. The kernel's queue for one pipe holds at most
    // queue_limit records (1,024 on GitHub's macOS runner). With all of the work in one
    // loop the queue filled during bursts and the kernel dropped 10,709 of about 142,000
    // records in one CI run. The reader now keeps draining while records are processed.
    let pipe = Arc::new(pipe);
    let (chunk_tx, chunk_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(READ_CHUNKS_QUEUED);
    let reader_pipe = pipe.clone();
    let reader_stop = shutdown.clone();
    let read_size = pipe.max_record_bytes.max(256 * 1024);
    let reader = std::thread::Builder::new()
        .name("auditpipe-reader".to_string())
        .spawn(move || -> Result<(), String> {
            let mut buffer = vec![0u8; read_size];
            let mut file = &reader_pipe.file;
            while !reader_stop.load(Ordering::SeqCst) {
                if !reader_pipe.wait_readable(200).map_err(|e| format!("poll: {}", e))? {
                    continue;
                }
                match file.read(&mut buffer) {
                    Ok(0) => {}
                    Ok(n) => {
                        if chunk_tx.send(buffer[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(format!("read /dev/auditpipe: {}", e)),
                }
            }
            Ok(())
        })
        .map_err(|e| format!("could not start the pipe reader: {}", e))?;

    let mut segment_started = now_ms();
    let started = segment_started;
    let mut last_heartbeat = 0u64;
    let mut feed = |chunk: &[u8], normalizer: &mut Normalizer, writer: &mut SegmentWriter, stats: &mut CaptureStats| {
        splitter.feed(chunk);
        while let Some(record) = splitter.next_record() {
            process_record(&record, normalizer, writer, stats);
        }
        splitter.skipped_bytes
    };
    let mut skipped_bytes = 0u64;

    while !shutdown.load(Ordering::SeqCst) {
        match chunk_rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(chunk) => {
                skipped_bytes = feed(&chunk, &mut normalizer, &mut writer, &mut stats);
                while let Ok(more) = chunk_rx.try_recv() {
                    skipped_bytes = feed(&more, &mut normalizer, &mut writer, &mut stats);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            // The reader stopped on its own: its error is reported after the loop.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        let now = now_ms();
        let rotate = now.saturating_sub(segment_started) >= ROTATE_AFTER_MS || writer.pending_bytes() >= max_segment_bytes;
        if rotate {
            if let Some(meta) = writer.flush()? {
                eprintln!("[capture] wrote {} ({} events)", meta.rel_path, meta.records);
                if once {
                    break;
                }
            }
            segment_started = now;
        }
        if let Some(seconds) = duration_secs {
            if now.saturating_sub(started) >= seconds * 1000 {
                eprintln!("[capture] --duration: {} seconds done", seconds);
                break;
            }
        }
        if once && now.saturating_sub(started) >= ROTATE_AFTER_MS && writer.segments_written == 0 {
            eprintln!("[capture] --once: no audit records in {} seconds. Auditing is probably off in the kernel.", ROTATE_AFTER_MS / 1000);
            break;
        }
        if now.saturating_sub(last_heartbeat) >= HEARTBEAT_EVERY_MS {
            stats.pipe_drops = pipe.drops();
            stats.skipped_bytes = skipped_bytes;
            write_heartbeat(root, &stats, &writer);
            last_heartbeat = now;
        }
    }

    // Stop the reader, then process what it had already read.
    shutdown.store(true, Ordering::SeqCst);
    let reader_result = reader.join().unwrap_or_else(|_| Err("the pipe reader panicked".to_string()));
    while let Ok(chunk) = chunk_rx.try_recv() {
        skipped_bytes = feed(&chunk, &mut normalizer, &mut writer, &mut stats);
    }
    stats.skipped_bytes = skipped_bytes;
    reader_result?;

    if let Some(meta) = writer.flush()? {
        eprintln!("[capture] wrote {} ({} events)", meta.rel_path, meta.records);
    }
    stats.pipe_drops = pipe.drops();
    write_heartbeat(root, &stats, &writer);
    eprintln!(
        "[capture] stopped: {} records read, {} events written, {} decode errors",
        stats.records_read, writer.events_written, stats.decode_errors
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run_live(_root: &Path, _host: &str, _classes: &str, _once: bool, _duration_secs: Option<u64>) -> Result<(), String> {
    Err("live capture is only available on macOS".to_string())
}

pub fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}\n\n{}", e, USAGE);
            process::exit(2);
        }
    };
    if args.help {
        print!("{}", USAGE);
        return;
    }

    let root = args
        .telemetry_root
        .clone()
        .or_else(|| std::env::var("EDR_TELEMETRY_ROOT").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("telemetry_output"));
    let host = args.host.clone().unwrap_or_else(hostname);
    eprintln!("[capture] telemetry root: {}", root.display());

    let result = if let Some(fixture) = &args.mock_events {
        run_mock(fixture, &root).map(|_| ())
    } else if !args.bsm_files.is_empty() {
        run_replay(&args.bsm_files, &root, &host).map(|stats| {
            eprintln!(
                "[capture] replay done: {} records, {} events, {} decode errors, {} not handled",
                stats.records_read, stats.events_emitted, stats.decode_errors, stats.records_not_handled
            );
        })
    } else {
        let classes = args.classes.clone().unwrap_or_else(|| auditpipe::DEFAULT_CLASSES.to_string());
        run_live(&root, &host, &classes, args.once, args.duration_secs)
    };

    if let Err(e) = result {
        eprintln!("[capture] error: {}", e);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_arguments() {
        let args: Vec<String> = ["--bsm-file", "a.bsm", "--bsm-file", "b.bsm", "--host", "h", "--once", "--duration", "40"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let parsed = parse_args(&args).unwrap();
        assert_eq!(parsed.bsm_files.len(), 2);
        assert_eq!(parsed.host.as_deref(), Some("h"));
        assert!(parsed.once);
        assert_eq!(parsed.duration_secs, Some(40));
        assert!(parse_args(&["--duration".to_string(), "soon".to_string()]).is_err());
        assert!(parse_args(&["--bogus".to_string()]).is_err());
        assert!(parse_args(&["--bsm-file".to_string()]).is_err());
    }

    #[test]
    fn index_chain_links_versions() {
        let dir = std::env::temp_dir().join(format!("edr-capture-test-{}", uuid::Uuid::new_v4()));
        let mut writer = SegmentWriter::new(&dir).unwrap();
        for seq in 0..2 {
            let mut fields = BTreeMap::new();
            fields.insert("pid".to_string(), json!(1));
            writer.push(Event {
                ts_ms: 1000 + seq,
                host: "h".into(),
                tags: vec!["macos".into(), "process".into(), "exec".into()],
                proc_key: None,
                file_key: None,
                identity_key: None,
                evidence_ptr: None,
                fields,
            });
            writer.flush().unwrap();
        }
        let index = SegmentIndex::load(&dir.join("index.json")).unwrap();
        assert_eq!(index.next_seq, 2);
        assert_eq!(index.segments.len(), 2);
        assert_eq!(index.index_hash.as_deref(), Some(index.compute_hash().as_str()));
        assert!(index.prev_index_hash.is_some());
        for seg in &index.segments {
            let path = dir.join(&seg.rel_path);
            assert_eq!(sha256_file(&path).unwrap(), seg.sha256_segment);
            let line = fs::read_to_string(&path).unwrap();
            let event: Event = serde_json::from_str(line.lines().next().unwrap()).unwrap();
            assert_eq!(event.evidence_ptr.unwrap().segment_id, seg.seq);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
