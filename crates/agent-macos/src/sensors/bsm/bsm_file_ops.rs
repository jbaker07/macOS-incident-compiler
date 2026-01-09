// macos/sensors/bsm/bsm_file_ops.rs
// File operation handlers for OpenBSM audit records
// Handles: open, read, write, create, unlink, chmod, chown, rename
// Emits canonical events with proper evidence_ptr + derived exfiltration/staging events

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// AUE codes for file operations
pub mod aue {
    pub const AUE_OPEN_R: i32 = 3; // open() with O_RDONLY
    pub const AUE_OPEN_W: i32 = 4; // open() with O_WRONLY or O_RDWR
    pub const AUE_OPEN_RW: i32 = 5; // open() with O_RDWR
    pub const AUE_CREAT: i32 = 300; // creat() / open() with O_CREAT
    pub const AUE_UNLINK: i32 = 7; // unlink()
    pub const AUE_CHMOD: i32 = 17; // chmod()
    pub const AUE_CHOWN: i32 = 18; // chown()
    pub const AUE_RENAME: i32 = 6; // rename()
    pub const AUE_FCHMOD: i32 = 39; // fchmod()
    pub const AUE_FCHOWN: i32 = 40; // fchown()
    pub const AUE_TRUNCATE: i32 = 310; // truncate()
    pub const AUE_FTRUNCATE: i32 = 311; // ftruncate()
}

/// Sensitive paths for exfiltration detection
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/",
    "/.ssh/",
    "/id_rsa",
    "/id_ed25519",
    "/authorized_keys",
    "/known_hosts",
    ".aws/credentials",
    ".kube/config",
    "/etc/krb5.keytab",
    ".gnupg/",
    "Keychain",
    "/var/db/dslocal/",
    "/Library/Keychains/",
];

/// Staging directories for exfiltration staging detection
const STAGING_DIRS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "/dev/shm/",
    "/Users/Shared/",
];

/// Handle AUE_OPEN (read/write/readwrite) - file open events
pub fn handle_open(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    aue_code: i32,
    path: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    mode: Option<&str>, // "r", "w", "rw"
    ts_millis: u64,
) -> Option<Event> {
    if path.is_empty() {
        return None;
    }

    let access_mode = mode.unwrap_or(match aue_code {
        aue::AUE_OPEN_R => "r",
        aue::AUE_OPEN_W => "w",
        aue::AUE_OPEN_RW | _ => "rw",
    });

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
    fields.insert(event_keys::FILE_OP.to_string(), json!("open"));
    fields.insert("access_mode".to_string(), json!(access_mode));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));

    // Mark sensitive file access
    let is_sensitive = is_sensitive_path(path);
    if is_sensitive {
        fields.insert("sensitive_file".to_string(), json!(true));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "open".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None, // Assigned after sort
        fields,
    })
}

/// Handle AUE_CREAT - file create events
pub fn handle_create(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    path: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    mode: Option<u32>, // file mode bits
    ts_millis: u64,
) -> Option<Event> {
    if path.is_empty() {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
    fields.insert(event_keys::FILE_OP.to_string(), json!("create"));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));

    if let Some(m) = mode {
        fields.insert("file_mode".to_string(), json!(format!("{:o}", m)));
    }

    // Check for staging directory
    let is_staging = is_staging_path(path);
    if is_staging {
        fields.insert("staging_dir".to_string(), json!(true));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "create".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_UNLINK - file delete events
pub fn handle_unlink(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    path: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    if path.is_empty() {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
    fields.insert(event_keys::FILE_OP.to_string(), json!("unlink"));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));

    // Mark log file deletion for defense evasion detection
    let is_log = is_log_file(path);
    if is_log {
        fields.insert("log_deletion".to_string(), json!(true));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "unlink".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_CHMOD/AUE_FCHMOD - file permission change events
pub fn handle_chmod(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    path: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    new_mode: Option<u32>,
    ts_millis: u64,
) -> Option<Event> {
    if path.is_empty() {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
    fields.insert(event_keys::FILE_OP.to_string(), json!("chmod"));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));

    if let Some(mode) = new_mode {
        fields.insert("new_mode".to_string(), json!(format!("{:o}", mode)));
        // Check for suspicious mode changes (making files executable, world-writable, etc.)
        if mode & 0o111 != 0 {
            fields.insert("made_executable".to_string(), json!(true));
        }
        if mode & 0o002 != 0 {
            fields.insert("world_writable".to_string(), json!(true));
        }
        if mode & 0o4000 != 0 {
            fields.insert("setuid".to_string(), json!(true));
        }
        if mode & 0o2000 != 0 {
            fields.insert("setgid".to_string(), json!(true));
        }
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "chmod".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_CHOWN/AUE_FCHOWN - file ownership change events
pub fn handle_chown(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    path: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    new_owner: Option<u32>,
    new_group: Option<u32>,
    ts_millis: u64,
) -> Option<Event> {
    if path.is_empty() {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
    fields.insert(event_keys::FILE_OP.to_string(), json!("chown"));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));

    if let Some(owner) = new_owner {
        fields.insert("new_owner".to_string(), json!(owner));
        // Changing ownership to root is suspicious
        if owner == 0 {
            fields.insert("chown_to_root".to_string(), json!(true));
        }
    }
    if let Some(group) = new_group {
        fields.insert("new_group".to_string(), json!(group));
        if group == 0 {
            fields.insert("chgrp_to_wheel".to_string(), json!(true));
        }
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "chown".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_RENAME - file rename events
pub fn handle_rename(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    old_path: &str,
    new_path: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    if old_path.is_empty() || new_path.is_empty() {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::FILE_PATH.to_string(), json!(new_path));
    fields.insert("old_path".to_string(), json!(old_path));
    fields.insert(event_keys::FILE_OP.to_string(), json!("rename"));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));

    // Detect moving files to staging directories
    if is_staging_path(new_path) && !is_staging_path(old_path) {
        fields.insert("move_to_staging".to_string(), json!(true));
    }

    // Detect hiding files (moving to dot-prefix)
    let new_name = std::path::Path::new(new_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let old_name = std::path::Path::new(old_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if new_name.starts_with('.') && !old_name.starts_with('.') {
        fields.insert("hiding_file".to_string(), json!(true));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "rename".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, new_path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_TRUNCATE - file truncate events (can indicate log wiping)
pub fn handle_truncate(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    path: &str,
    pid: u32,
    uid: u32,
    euid: u32,
    new_size: Option<u64>,
    ts_millis: u64,
) -> Option<Event> {
    if path.is_empty() {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
    fields.insert(event_keys::FILE_OP.to_string(), json!("truncate"));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));

    if let Some(size) = new_size {
        fields.insert("new_size".to_string(), json!(size));
        // Truncating to 0 is suspicious (log wiping)
        if size == 0 && is_log_file(path) {
            fields.insert("log_truncated".to_string(), json!(true));
        }
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "truncate".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Check if path is sensitive (credentials, keys, etc.)
fn is_sensitive_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    SENSITIVE_PATHS
        .iter()
        .any(|p| path_lower.contains(&p.to_lowercase()))
}

/// Check if path is in a staging directory
fn is_staging_path(path: &str) -> bool {
    STAGING_DIRS.iter().any(|d| path.starts_with(d))
}

/// Check if path is a log file
fn is_log_file(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    path_lower.contains("/var/log/")
        || path_lower.contains("/library/logs/")
        || path_lower.ends_with(".log")
        || path_lower.contains(".bash_history")
        || path_lower.contains(".zsh_history")
        || path_lower.contains(".history")
        || path_lower.contains("audit")
}

/// Generic dispatcher for file operation AUE codes
/// Routes to appropriate handler based on AUE code
#[allow(clippy::too_many_arguments)]
pub fn handle_file_operation_event(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    aue_code: i32,
    pid: u32,
    uid: u32,
    euid: u32,
    path: Option<&str>,
    dest_path: Option<&str>,
    mode: Option<u32>,
    target_uid: Option<u32>,
    target_gid: Option<u32>,
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    let path = path.unwrap_or("");
    if path.is_empty() && aue_code != aue::AUE_RENAME {
        return None;
    }

    match aue_code {
        aue::AUE_OPEN_R | aue::AUE_OPEN_W | aue::AUE_OPEN_RW => handle_open(
            host,
            stream_id,
            segment_id,
            record_index,
            aue_code,
            path,
            pid,
            uid,
            euid,
            None,
            ts_millis,
        ),
        aue::AUE_CREAT => handle_create(
            host,
            stream_id,
            segment_id,
            record_index,
            path,
            pid,
            uid,
            euid,
            mode,
            ts_millis,
        ),
        aue::AUE_UNLINK => handle_unlink(
            host,
            stream_id,
            segment_id,
            record_index,
            path,
            pid,
            uid,
            euid,
            ts_millis,
        ),
        aue::AUE_CHMOD | aue::AUE_FCHMOD => handle_chmod(
            host,
            stream_id,
            segment_id,
            record_index,
            path,
            pid,
            uid,
            euid,
            mode,
            ts_millis,
        ),
        aue::AUE_CHOWN | aue::AUE_FCHOWN => handle_chown(
            host,
            stream_id,
            segment_id,
            record_index,
            path,
            pid,
            uid,
            euid,
            target_uid,
            target_gid,
            ts_millis,
        ),
        aue::AUE_RENAME => {
            let dest = dest_path.unwrap_or("");
            handle_rename(
                host,
                stream_id,
                segment_id,
                record_index,
                path,
                dest,
                pid,
                uid,
                euid,
                ts_millis,
            )
        }
        aue::AUE_TRUNCATE | aue::AUE_FTRUNCATE => handle_truncate(
            host,
            stream_id,
            segment_id,
            record_index,
            path,
            pid,
            uid,
            euid,
            mode.map(|m| m as u64),
            ts_millis,
        ),
        _ => None,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use edr_core::event_keys;

    #[test]
    fn test_handle_open_sensitive_file() {
        let event = handle_open(
            "testhost",
            "stream1",
            "seg1",
            0,
            aue::AUE_OPEN_R,
            "/Users/admin/.ssh/id_rsa",
            1234,
            501,
            501,
            Some("r"),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"file".to_string()));
        assert!(e.tags.contains(&"open".to_string()));
        assert_eq!(
            e.fields.get(event_keys::FILE_PATH).unwrap(),
            "/Users/admin/.ssh/id_rsa"
        );
        assert_eq!(e.fields.get("sensitive_file").unwrap(), true);
    }

    #[test]
    fn test_handle_create_staging_dir() {
        let event = handle_create(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/tmp/exfil_data.tar.gz",
            1234,
            501,
            501,
            Some(0o644),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"create".to_string()));
        assert_eq!(e.fields.get("staging_dir").unwrap(), true);
    }

    #[test]
    fn test_handle_unlink_log_file() {
        let event = handle_unlink(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/var/log/system.log",
            1234,
            0,
            0,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"unlink".to_string()));
        assert_eq!(e.fields.get("log_deletion").unwrap(), true);
    }

    #[test]
    fn test_handle_chmod_setuid() {
        let event = handle_chmod(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/tmp/backdoor",
            1234,
            501,
            0,
            Some(0o4755), // setuid + executable
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"chmod".to_string()));
        assert_eq!(e.fields.get("setuid").unwrap(), true);
        assert_eq!(e.fields.get("made_executable").unwrap(), true);
    }

    #[test]
    fn test_handle_chown_to_root() {
        let event = handle_chown(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/tmp/rootkit",
            1234,
            501,
            0,
            Some(0), // root
            Some(0), // wheel
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"chown".to_string()));
        assert_eq!(e.fields.get("chown_to_root").unwrap(), true);
        assert_eq!(e.fields.get("chgrp_to_wheel").unwrap(), true);
    }

    #[test]
    fn test_handle_rename_to_staging() {
        let event = handle_rename(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/Users/admin/Documents/secrets.docx",
            "/tmp/secrets.docx",
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"rename".to_string()));
        assert_eq!(e.fields.get("move_to_staging").unwrap(), true);
    }

    #[test]
    fn test_handle_rename_hiding_file() {
        let event = handle_rename(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/tmp/malware",
            "/tmp/.malware",
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("hiding_file").unwrap(), true);
    }

    #[test]
    fn test_handle_truncate_log_wipe() {
        let event = handle_truncate(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/var/log/auth.log",
            1234,
            0,
            0,
            Some(0), // truncate to 0
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"truncate".to_string()));
        assert_eq!(e.fields.get("log_truncated").unwrap(), true);
    }

    #[test]
    fn test_rejects_empty_path() {
        assert!(handle_open("h", "s", "seg", 0, aue::AUE_OPEN_R, "", 1, 1, 1, None, 0).is_none());
        assert!(handle_create("h", "s", "seg", 0, "", 1, 1, 1, None, 0).is_none());
        assert!(handle_unlink("h", "s", "seg", 0, "", 1, 1, 1, 0).is_none());
    }
}
