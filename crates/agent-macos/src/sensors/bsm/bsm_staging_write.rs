// macos/sensors/bsm/bsm_staging_write.rs
// Detects file writes to staging directories (/tmp, ~/Downloads, ~/Desktop)
// Indicates potential exfiltration staging or temporary artifact placement

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect writes to staging directories
/// Triggers on:
/// - /tmp/, /var/tmp/, /private/tmp/ (temporary staging)
/// - ~/Downloads/ (download staging)
/// - ~/Desktop/ (user desktop staging)
pub fn detect_staging_write(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    file_path: &str,
    exe_path: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    op: &str, // "write", "create", etc.
    ts_millis: u64,
) -> Option<Event> {
    let staging_prefixes = [
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
        "/Users/", // Will check for Downloads/ or Desktop/ suffix
    ];

    // Check if path matches staging directories
    let mut is_staging = false;
    for prefix in &staging_prefixes {
        if file_path.starts_with(prefix) {
            if *prefix == "/Users/" {
                // Check if it contains Downloads or Desktop
                if file_path.contains("/Downloads/") || file_path.contains("/Desktop/") {
                    is_staging = true;
                }
            } else {
                is_staging = true;
            }
            if is_staging {
                break;
            }
        }
    }

    if !is_staging {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::FILE_PATH.to_string(), json!(file_path));
    fields.insert(event_keys::FILE_OP.to_string(), json!(op));
    fields.insert(
        event_keys::PRIMITIVE_SUBTYPE.to_string(),
        json!("staging_write"),
    ); // Distinguish from archive_tool_exec

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "exfiltration".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, file_path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}
