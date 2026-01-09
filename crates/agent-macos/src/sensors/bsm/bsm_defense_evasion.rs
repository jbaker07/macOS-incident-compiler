// macos/sensors/bsm/bsm_defense_evasion.rs
// Detects defense evasion attempts on macOS
// Triggers on: log clearing, history deletion, audit tampering, SIP bypass, xattr removal

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Security-related log files that shouldn't be tampered with
const SECURITY_LOGS: &[&str] = &[
    "/var/log/system.log",
    "/var/log/install.log",
    "/var/log/wifi.log",
    "/var/log/secure.log",
    "/var/audit/",
    "/private/var/log/",
    "/Library/Logs/",
];

/// Shell history files
const HISTORY_FILES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".history",
    ".sh_history",
    ".python_history",
];

/// Audit-related paths
const AUDIT_PATHS: &[&str] = &[
    "/var/audit/",
    "/etc/security/audit_control",
    "/etc/security/audit_class",
    "/etc/security/audit_event",
];

/// Security tools/configs
const SECURITY_TOOLS: &[&str] = &[
    "com.apple.security",
    "com.apple.alf", // Application Layer Firewall
    "com.apple.xprotect",
    "com.apple.MRT", // Malware Removal Tool
    "Gatekeeper",
];

/// Detect defense evasion from file operations
pub fn detect_defense_evasion_from_file_op(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    file_path: &str,
    file_op: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    exe_path: &str,
    ts_millis: u64,
) -> Option<Event> {
    let (evasion_target, evasion_action) = classify_evasion_file_op(file_path, file_op)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::FILE_PATH.to_string(), json!(file_path));
    fields.insert(
        event_keys::EVASION_TARGET.to_string(),
        json!(evasion_target),
    );
    fields.insert(
        event_keys::EVASION_ACTION.to_string(),
        json!(evasion_action),
    );

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "defense_evasion".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, file_path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Detect defense evasion from exec commands
pub fn detect_defense_evasion_from_exec(
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
    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    let arg_str = argv.iter().take(50).cloned().collect::<Vec<_>>().join(" ");

    let (evasion_target, evasion_action) = classify_evasion_exec(exe_base, &arg_str)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert(
        event_keys::EVASION_TARGET.to_string(),
        json!(evasion_target),
    );
    fields.insert(
        event_keys::EVASION_ACTION.to_string(),
        json!(evasion_action),
    );

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "defense_evasion".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Classify file operation as evasion attempt
fn classify_evasion_file_op(path: &str, op: &str) -> Option<(&'static str, &'static str)> {
    let is_destructive = matches!(op, "unlink" | "truncate" | "rmdir");

    // Log tampering
    for log_path in SECURITY_LOGS {
        if path.starts_with(log_path) || path.contains(log_path) {
            if is_destructive {
                return Some((
                    "log",
                    if op == "truncate" {
                        "truncate"
                    } else {
                        "delete"
                    },
                ));
            }
        }
    }

    // History deletion
    for hist in HISTORY_FILES {
        if path.ends_with(hist) && is_destructive {
            return Some(("history", "delete"));
        }
    }

    // Audit tampering
    for audit_path in AUDIT_PATHS {
        if path.starts_with(audit_path) {
            if is_destructive {
                return Some(("audit", "delete"));
            }
        }
    }

    None
}

/// Classify exec command as evasion attempt
fn classify_evasion_exec(exe_base: &str, arg_str: &str) -> Option<(&'static str, &'static str)> {
    // csrutil - SIP manipulation
    if exe_base == "csrutil" {
        if arg_str.contains("disable") {
            return Some(("security_tool", "disable"));
        }
    }

    // spctl - Gatekeeper manipulation
    if exe_base == "spctl" {
        if arg_str.contains("--master-disable") || arg_str.contains("disable") {
            return Some(("security_tool", "disable"));
        }
    }

    // Log clearing commands
    if exe_base == "log" && arg_str.contains("erase") {
        return Some(("log", "clear"));
    }

    // rm/shred on logs or history
    if exe_base == "rm" || exe_base == "shred" || exe_base == "srm" {
        for hist in HISTORY_FILES {
            if arg_str.contains(hist) {
                return Some(("history", "delete"));
            }
        }
        for log_path in SECURITY_LOGS {
            if arg_str.contains(log_path) {
                return Some(("log", "delete"));
            }
        }
    }

    // History clearing
    if exe_base == "history" && arg_str.contains("-c") {
        return Some(("history", "clear"));
    }

    // xattr - quarantine removal
    if exe_base == "xattr" {
        if arg_str.contains("-d") && arg_str.contains("com.apple.quarantine") {
            return Some(("security_tool", "disable"));
        }
        if arg_str.contains("-c") {
            // clear all
            return Some(("security_tool", "disable"));
        }
    }

    // Audit control manipulation
    if exe_base == "audit" && arg_str.contains("-s") {
        return Some(("audit", "disable"));
    }

    // launchctl unloading security services
    if exe_base == "launchctl" && arg_str.contains("unload") {
        for tool in SECURITY_TOOLS {
            if arg_str.contains(tool) {
                return Some(("security_tool", "disable"));
            }
        }
    }

    // Firewall manipulation
    if exe_base == "pfctl" && arg_str.contains("-d") {
        return Some(("security_tool", "disable"));
    }

    // defaults write to disable security
    if exe_base == "defaults" && arg_str.contains("write") {
        if arg_str.contains("com.apple.LaunchServices") && arg_str.contains("LSQuarantine") {
            return Some(("security_tool", "disable"));
        }
    }

    // Touch to modify timestamps (timestomping)
    if exe_base == "touch" && (arg_str.contains("-t") || arg_str.contains("-d")) {
        // Only flag if touching security-relevant files
        for log_path in SECURITY_LOGS {
            if arg_str.contains(log_path) {
                return Some(("log", "modify"));
            }
        }
    }

    // dd to overwrite logs
    if exe_base == "dd" {
        for log_path in SECURITY_LOGS {
            if arg_str.contains(log_path) {
                return Some(("log", "truncate"));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_log_deletion() {
        let event = detect_defense_evasion_from_file_op(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/var/log/system.log",
            "unlink",
            1234,
            501,
            501,
            "/bin/rm",
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"defense_evasion".to_string()));
        assert_eq!(e.fields.get("evasion_target").unwrap(), "log");
        assert_eq!(e.fields.get("evasion_action").unwrap(), "delete");
    }

    #[test]
    fn test_detect_history_deletion() {
        let event = detect_defense_evasion_from_file_op(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/Users/user/.bash_history",
            "unlink",
            1234,
            501,
            501,
            "/bin/rm",
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("evasion_target").unwrap(), "history");
    }

    #[test]
    fn test_detect_spctl_disable() {
        let event = detect_defense_evasion_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/sbin/spctl",
            &["spctl".to_string(), "--master-disable".to_string()],
            1234,
            0,
            0,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("evasion_target").unwrap(), "security_tool");
        assert_eq!(e.fields.get("evasion_action").unwrap(), "disable");
    }

    #[test]
    fn test_detect_xattr_quarantine_removal() {
        let event = detect_defense_evasion_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/xattr",
            &[
                "xattr".to_string(),
                "-d".to_string(),
                "com.apple.quarantine".to_string(),
                "/tmp/malware".to_string(),
            ],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("evasion_target").unwrap(), "security_tool");
    }

    #[test]
    fn test_detect_history_clear_cmd() {
        let event = detect_defense_evasion_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/history",
            &["history".to_string(), "-c".to_string()],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("evasion_target").unwrap(), "history");
        assert_eq!(e.fields.get("evasion_action").unwrap(), "clear");
    }

    #[test]
    fn test_no_detection_normal_file() {
        let event = detect_defense_evasion_from_file_op(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/tmp/normal_file.txt",
            "unlink",
            1234,
            501,
            501,
            "/bin/rm",
            1000000,
        );
        assert!(event.is_none());
    }
}
