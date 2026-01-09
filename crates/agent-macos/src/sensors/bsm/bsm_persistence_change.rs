// macos/sensors/bsm/bsm_persistence_change.rs
// Detects persistence mechanism modifications on macOS
// Triggers on: LaunchAgent/LaunchDaemon, cron, periodic, login items

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Persistence locations on macOS (bounded set)
const LAUNCHAGENT_PATHS: &[&str] = &["/Library/LaunchAgents/", "/System/Library/LaunchAgents/"];

const LAUNCHDAEMON_PATHS: &[&str] = &["/Library/LaunchDaemons/", "/System/Library/LaunchDaemons/"];

const CRON_PATHS: &[&str] = &["/var/at/tabs/", "/usr/lib/cron/tabs/"];

const PERIODIC_PATHS: &[&str] = &[
    "/etc/periodic/daily/",
    "/etc/periodic/weekly/",
    "/etc/periodic/monthly/",
    "/usr/local/etc/periodic/",
];

const PROFILE_PATHS: &[&str] = &[
    ".bash_profile",
    ".bashrc",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".login",
];

/// Detect persistence changes from file operations
pub fn detect_persistence_change_from_file_op(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    file_path: &str,
    file_op: &str, // "create", "write", "unlink"
    pid: u32,
    uid: u32,
    euid: u32,
    exe_path: &str,
    ts_millis: u64,
) -> Option<Event> {
    // Determine persistence type based on path
    let (persist_type, is_match) = classify_persistence_path(file_path);

    if !is_match {
        return None;
    }

    // Map file operation to persistence action
    let persist_action = match file_op {
        "create" | "open_rw" => "create",
        "write" | "truncate" => "modify",
        "unlink" | "rmdir" => "delete",
        _ => "modify",
    };

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::PERSIST_LOCATION.to_string(), json!(file_path));
    fields.insert(event_keys::PERSIST_TYPE.to_string(), json!(persist_type));
    fields.insert(
        event_keys::PERSIST_ACTION.to_string(),
        json!(persist_action),
    );

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "persistence_change".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, file_path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}

/// Detect persistence changes from launchctl commands
pub fn detect_persistence_change_from_exec(
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

    // Detect launchctl load/unload
    if exe_base == "launchctl" {
        let arg_str = argv
            .get(0..std::cmp::min(10, argv.len()))
            .map(|a| a.join(" "))
            .unwrap_or_default();

        let persist_action = if arg_str.contains("load") || arg_str.contains("bootstrap") {
            "create"
        } else if arg_str.contains("unload") || arg_str.contains("bootout") {
            "delete"
        } else if arg_str.contains("enable") || arg_str.contains("disable") {
            "modify"
        } else {
            return None;
        };

        // Try to extract plist path from args
        let plist_path = argv
            .iter()
            .skip(1)
            .find(|a| {
                a.ends_with(".plist") || a.contains("LaunchAgent") || a.contains("LaunchDaemon")
            })
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let persist_type = if plist_path.contains("LaunchDaemon") {
            "launchdaemon"
        } else {
            "launchagent"
        };

        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
        fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
        fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
        fields.insert(event_keys::PERSIST_LOCATION.to_string(), json!(plist_path));
        fields.insert(event_keys::PERSIST_TYPE.to_string(), json!(persist_type));
        fields.insert(
            event_keys::PERSIST_ACTION.to_string(),
            json!(persist_action),
        );
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));

        return Some(Event {
            ts_ms: ts_millis as i64,
            host: host.to_string(),
            tags: vec![
                "macos".to_string(),
                "persistence_change".to_string(),
                "bsm".to_string(),
            ],
            proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
            file_key: None,
            identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
            evidence_ptr: None,
            fields,
        });
    }

    // Detect crontab command
    if exe_base == "crontab" {
        let arg_str = argv
            .get(0..std::cmp::min(10, argv.len()))
            .map(|a| a.join(" "))
            .unwrap_or_default();

        let persist_action = if arg_str.contains("-r") {
            "delete"
        } else if arg_str.contains("-e") || arg_str.contains("-l") {
            "modify"
        } else {
            "create"
        };

        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
        fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
        fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
        fields.insert(
            event_keys::PERSIST_LOCATION.to_string(),
            json!(format!("/var/at/tabs/{}", uid)),
        );
        fields.insert(event_keys::PERSIST_TYPE.to_string(), json!("cron"));
        fields.insert(
            event_keys::PERSIST_ACTION.to_string(),
            json!(persist_action),
        );
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));

        return Some(Event {
            ts_ms: ts_millis as i64,
            host: host.to_string(),
            tags: vec![
                "macos".to_string(),
                "persistence_change".to_string(),
                "bsm".to_string(),
            ],
            proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
            file_key: None,
            identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
            evidence_ptr: None,
            fields,
        });
    }

    None
}

/// Classify a file path into persistence type
fn classify_persistence_path(path: &str) -> (&'static str, bool) {
    // LaunchAgents
    for prefix in LAUNCHAGENT_PATHS {
        if path.starts_with(prefix) && path.ends_with(".plist") {
            return ("launchagent", true);
        }
    }
    // Also check user-level LaunchAgents
    if path.contains("/LaunchAgents/") && path.ends_with(".plist") {
        return ("launchagent", true);
    }

    // LaunchDaemons
    for prefix in LAUNCHDAEMON_PATHS {
        if path.starts_with(prefix) && path.ends_with(".plist") {
            return ("launchdaemon", true);
        }
    }

    // Cron
    for prefix in CRON_PATHS {
        if path.starts_with(prefix) {
            return ("cron", true);
        }
    }

    // Periodic
    for prefix in PERIODIC_PATHS {
        if path.starts_with(prefix) {
            return ("periodic", true);
        }
    }

    // Profile/RC files
    for suffix in PROFILE_PATHS {
        if path.ends_with(suffix) {
            return ("profile", true);
        }
    }

    ("", false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_launchagent() {
        let (t, m) = classify_persistence_path("/Library/LaunchAgents/com.evil.plist");
        assert!(m);
        assert_eq!(t, "launchagent");
    }

    #[test]
    fn test_classify_launchdaemon() {
        let (t, m) = classify_persistence_path("/Library/LaunchDaemons/com.evil.plist");
        assert!(m);
        assert_eq!(t, "launchdaemon");
    }

    #[test]
    fn test_classify_cron() {
        let (t, m) = classify_persistence_path("/var/at/tabs/root");
        assert!(m);
        assert_eq!(t, "cron");
    }

    #[test]
    fn test_classify_profile() {
        let (t, m) = classify_persistence_path("/Users/user/.zshrc");
        assert!(m);
        assert_eq!(t, "profile");
    }

    #[test]
    fn test_classify_no_match() {
        let (_, m) = classify_persistence_path("/tmp/random_file.txt");
        assert!(!m);
    }

    #[test]
    fn test_detect_persistence_launchagent_create() {
        let event = detect_persistence_change_from_file_op(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/Library/LaunchAgents/com.evil.plist",
            "create",
            1234,
            501,
            501,
            "/usr/bin/cp",
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"persistence_change".to_string()));
        assert_eq!(e.fields.get("persist_type").unwrap(), "launchagent");
        assert_eq!(e.fields.get("persist_action").unwrap(), "create");
    }

    #[test]
    fn test_detect_launchctl_load() {
        let event = detect_persistence_change_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/bin/launchctl",
            &[
                "load".to_string(),
                "/Library/LaunchAgents/com.evil.plist".to_string(),
            ],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("persist_action").unwrap(), "create");
    }
}
