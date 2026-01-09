// macos/sensors/bsm/bsm_cred_access.rs
// Detects credential access attempts (keychain, ssh-agent, password managers)
// Triggers on bounded set of credential tools + python/perl with keyword detection

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect credential access via bounded tools or keyword matching
/// Triggers on:
/// - security (keychain command)
/// - ssh-add (add SSH key to agent)
/// - ssh-keygen (generate SSH key)
/// - dscl (directory service CLI)
/// - dscacheutil (directory service cache utility)
/// - profiles (macOS configuration)
/// - sqlite3 (direct keychain DB access)
/// - osascript (AppleScript password dialogs)
/// - python/perl with keychain/password/credential keywords
pub fn detect_cred_access_from_exec(
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
    let cred_tools = [
        "security",
        "ssh-add",
        "ssh-keygen",
        "dscl",
        "dscacheutil",
        "profiles",
        "sqlite3",
        "osascript",
    ];

    // Check if exe matches bounded list
    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    let mut is_cred_tool = false;
    let mut matched_tool = None;

    for tool in &cred_tools {
        if exe_base.contains(tool) {
            is_cred_tool = true;
            matched_tool = Some(tool.to_string());
            break;
        }
    }

    // Check python/perl with keyword matching (bounded to 100 args)
    if !is_cred_tool {
        if exe_base.contains("python") || exe_base.contains("perl") {
            let cred_keywords = [
                "keychain",
                "password",
                "credential",
                "secret",
                "api_key",
                "token",
                "oauth",
            ];

            let first_100_args = &argv[..std::cmp::min(100, argv.len())];
            let arg_str = first_100_args.join(" ");

            for keyword in &cred_keywords {
                if arg_str.to_lowercase().contains(keyword) {
                    is_cred_tool = true;
                    matched_tool = Some(format!("{}_with_{}", exe_base, keyword));
                    break;
                }
            }
        }
    }

    if !is_cred_tool {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    if let Some(tool) = matched_tool {
        fields.insert(event_keys::CRED_TOOL.to_string(), json!(tool));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "credential_access".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}
