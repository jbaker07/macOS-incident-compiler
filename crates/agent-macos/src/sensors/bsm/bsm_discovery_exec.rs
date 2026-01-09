// macos/sensors/bsm/bsm_discovery_exec.rs
// Detects discovery tool execution (whoami, id, uname, ps, lsof, netstat, etc.)
// Triggers on bounded set of 13 reconnaissance tools

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect discovery/reconnaissance tool execution
/// Triggers on bounded list of discovery tools:
/// - whoami, id, uname (user/system info)
/// - ps, lsof (process enumeration)
/// - netstat, ifconfig (network enumeration)
/// - scutil, system_profiler (system discovery)
/// - dscl, dscacheutil (directory discovery)
/// - csrutil (system integrity check)
/// - launchctl (service enumeration)
pub fn detect_discovery_exec(
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
    let discovery_tools = [
        "whoami",
        "id",
        "uname",
        "ps",
        "lsof",
        "netstat",
        "ifconfig",
        "scutil",
        "system_profiler",
        "dscl",
        "dscacheutil",
        "csrutil",
        "launchctl",
    ];

    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    // Check if exe matches bounded discovery tool list
    let matched_tool = discovery_tools
        .iter()
        .find(|tool| exe_base.contains(**tool))?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(
        event_keys::DISCOVERY_TOOL.to_string(),
        json!(matched_tool.to_string()),
    );

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "discovery".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}
