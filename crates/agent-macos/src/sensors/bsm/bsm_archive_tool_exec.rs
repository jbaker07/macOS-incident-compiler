// macos/sensors/bsm/bsm_archive_tool_exec.rs
// Detects archive/compression tool execution
// Triggers on bounded set of 8 archive tools (tar, zip, unzip, gzip, bzip2, xz, ditto, 7z)

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect archive tool execution (exfiltration, staging indicators)
/// Triggers on bounded list of archive/compression tools:
/// - tar (TAR archival)
/// - zip, unzip (ZIP archive)
/// - gzip (GZIP compression)
/// - bzip2 (BZIP2 compression)
/// - xz (XZ compression)
/// - ditto (macOS built-in archival)
/// - 7z (7-Zip)
pub fn detect_archive_tool_exec(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    exe_path: &str,
    argv: &[String],
    pid: u32,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    let archive_tools = ["tar", "zip", "unzip", "gzip", "bzip2", "xz", "ditto", "7z"];

    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    // Check if exe matches bounded archive tool list
    let matched_tool = archive_tools
        .iter()
        .find(|tool| exe_base.contains(**tool))?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(
        event_keys::ARCHIVE_TOOL.to_string(),
        json!(matched_tool.to_string()),
    );
    fields.insert(
        event_keys::PRIMITIVE_SUBTYPE.to_string(),
        json!("archive_tool_exec"),
    ); // Distinguish from staging_write

    if !argv.is_empty() {
        // Limit to first 50 args to avoid excessive logging
        let limited_argv: Vec<String> = argv.iter().take(50).cloned().collect();
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(limited_argv));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "exfiltration".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}
