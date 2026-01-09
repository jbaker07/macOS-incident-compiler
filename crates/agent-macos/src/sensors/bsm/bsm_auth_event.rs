// macos/sensors/bsm/bsm_auth_event.rs
// Detects authentication events on macOS
// Triggers on: login, sudo, su, ssh, authorization framework events

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// BSM audit event types for authentication (AUE codes)
/// These come from /etc/security/audit_event
pub const AUE_USER_CHANGE: u32 = 6152; // User identity changed
pub const AUE_LOGIN: u32 = 6155; // Login
pub const AUE_LOGOUT: u32 = 6156; // Logout
pub const AUE_AUTH_USER: u32 = 6162; // User authenticated
pub const AUE_AUTH_FAILURE: u32 = 6163; // Authentication failure
pub const AUE_SUDO: u32 = 6164; // sudo command
pub const AUE_SU: u32 = 6165; // su command
pub const AUE_SSH: u32 = 6166; // SSH connection
pub const AUE_AUTHORIZATION: u32 = 6167; // Authorization framework

/// Detect auth event from BSM record
pub fn detect_auth_event_from_bsm(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    aue_code: u32,
    user: &str,
    src_ip: Option<&str>,
    auth_method: &str,
    auth_result: &str, // "success" or "failure"
    pid: Option<u32>,
    uid: Option<u32>,
    euid: Option<u32>,
    ts_millis: u64,
) -> Option<Event> {
    // Validate AUE code is auth-related
    let valid_aue_codes = [
        AUE_USER_CHANGE,
        AUE_LOGIN,
        AUE_LOGOUT,
        AUE_AUTH_USER,
        AUE_AUTH_FAILURE,
        AUE_SUDO,
        AUE_SU,
        AUE_SSH,
        AUE_AUTHORIZATION,
    ];

    if !valid_aue_codes.contains(&aue_code) {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::AUTH_USER.to_string(), json!(user));
    fields.insert(event_keys::AUTH_METHOD.to_string(), json!(auth_method));
    fields.insert(event_keys::AUTH_RESULT.to_string(), json!(auth_result));

    if let Some(ip) = src_ip {
        fields.insert(event_keys::AUTH_SRC_IP.to_string(), json!(ip));
    }

    if let Some(p) = pid {
        fields.insert(event_keys::PROC_PID.to_string(), json!(p));
    }
    if let Some(u) = uid {
        fields.insert(event_keys::PROC_UID.to_string(), json!(u));
    }
    if let Some(e) = euid {
        fields.insert(event_keys::PROC_EUID.to_string(), json!(e));
    }

    let identity_key = uid.map(|u| hash_keys::identity_key(host, u, stream_id));
    let proc_key = pid.map(|p| hash_keys::proc_key(host, p, stream_id));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "auth_event".to_string(),
            "bsm".to_string(),
        ],
        proc_key,
        file_key: None,
        identity_key,
        evidence_ptr: None,
        fields,
    })
}

/// Detect auth event from exec of auth-related commands
pub fn detect_auth_event_from_exec(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    exe_path: &str,
    argv: &[String],
    pid: u32,
    uid: u32,
    euid: u32,
    exit_code: Option<i32>,
    ts_millis: u64,
) -> Option<Event> {
    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    let (auth_method, target_user) = match exe_base {
        "sudo" => {
            let target = extract_sudo_target_user(argv);
            ("sudo", target)
        }
        "su" => {
            let target = extract_su_target_user(argv);
            ("su", target)
        }
        "login" => {
            let target = argv
                .get(1)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            ("login", target)
        }
        "ssh" => {
            let target = extract_ssh_target(argv);
            ("ssh", target)
        }
        "kinit" => {
            let target = argv
                .get(1)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            ("kerberos", target)
        }
        "security" => {
            // Check for authorization commands
            let arg_str = argv.join(" ");
            if arg_str.contains("unlock-keychain") || arg_str.contains("authorizationdb") {
                ("authorization_framework", "system".to_string())
            } else {
                return None;
            }
        }
        "dscl" | "dscacheutil" => {
            let arg_str = argv.join(" ");
            if arg_str.contains("-authonly") || arg_str.contains("passwd") {
                ("directory_service", "system".to_string())
            } else {
                return None;
            }
        }
        _ => return None,
    };

    // Determine auth result from exit code if available
    let auth_result = match exit_code {
        Some(0) => "success",
        Some(_) => "failure",
        None => "unknown",
    };

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::AUTH_USER.to_string(), json!(target_user));
    fields.insert(event_keys::AUTH_METHOD.to_string(), json!(auth_method));
    fields.insert(event_keys::AUTH_RESULT.to_string(), json!(auth_result));

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "auth_event".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Extract target user from sudo command
fn extract_sudo_target_user(argv: &[String]) -> String {
    // Look for -u <user> flag
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        if arg == "-u" {
            if let Some(user) = iter.next() {
                return user.clone();
            }
        }
    }
    // Default to root
    "root".to_string()
}

/// Extract target user from su command
fn extract_su_target_user(argv: &[String]) -> String {
    // su [options] [user]
    // Look for non-flag argument
    for arg in argv.iter().skip(1) {
        if !arg.starts_with('-') {
            return arg.clone();
        }
    }
    // Default to root
    "root".to_string()
}

/// Extract target from ssh command
fn extract_ssh_target(argv: &[String]) -> String {
    // ssh [options] [user@]host
    // Options that take an argument: -p, -l, -i, -F, -o, -b, -c, -D, -e, -J, -L, -m, -O, -Q, -R, -S, -W, -w
    const OPTS_WITH_ARG: &[&str] = &[
        "-p", "-l", "-i", "-F", "-o", "-b", "-c", "-D", "-e", "-J", "-L", "-m", "-O", "-Q", "-R",
        "-S", "-W", "-w",
    ];

    let mut skip_next = false;
    for arg in argv.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with('-') {
            // Check if this option takes an argument
            if OPTS_WITH_ARG.contains(&arg.as_str()) {
                skip_next = true;
            }
            continue;
        }
        // This is a positional argument - should be the host
        return arg.clone();
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use edr_core::event_keys;

    #[test]
    fn test_detect_sudo_exec() {
        let event = detect_auth_event_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/sudo",
            &[
                "sudo".to_string(),
                "-u".to_string(),
                "admin".to_string(),
                "ls".to_string(),
            ],
            1234,
            501,
            501,
            Some(0),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"auth_event".to_string()));
        assert_eq!(e.fields.get(event_keys::AUTH_METHOD).unwrap(), "sudo");
        assert_eq!(e.fields.get(event_keys::AUTH_USER).unwrap(), "admin");
        assert_eq!(e.fields.get(event_keys::AUTH_RESULT).unwrap(), "success");
    }

    #[test]
    fn test_detect_sudo_default_root() {
        let event = detect_auth_event_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/sudo",
            &["sudo".to_string(), "whoami".to_string()],
            1234,
            501,
            501,
            Some(0),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get(event_keys::AUTH_USER).unwrap(), "root");
    }

    #[test]
    fn test_detect_su_exec() {
        let event = detect_auth_event_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/su",
            &["su".to_string(), "-".to_string(), "admin".to_string()],
            1234,
            501,
            501,
            Some(1),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get(event_keys::AUTH_METHOD).unwrap(), "su");
        assert_eq!(e.fields.get(event_keys::AUTH_USER).unwrap(), "admin");
        assert_eq!(e.fields.get(event_keys::AUTH_RESULT).unwrap(), "failure");
    }

    #[test]
    fn test_detect_ssh_exec() {
        let event = detect_auth_event_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/ssh",
            &["ssh".to_string(), "user@remotehost".to_string()],
            1234,
            501,
            501,
            None,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get(event_keys::AUTH_METHOD).unwrap(), "ssh");
        assert_eq!(
            e.fields.get(event_keys::AUTH_USER).unwrap(),
            "user@remotehost"
        );
    }

    #[test]
    fn test_detect_bsm_auth_success() {
        let event = detect_auth_event_from_bsm(
            "testhost",
            "stream1",
            "seg1",
            0,
            AUE_AUTH_USER,
            "admin",
            Some("192.168.1.100"),
            "password",
            "success",
            Some(1234),
            Some(501),
            Some(501),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get(event_keys::AUTH_RESULT).unwrap(), "success");
        assert_eq!(
            e.fields.get(event_keys::AUTH_SRC_IP).unwrap(),
            "192.168.1.100"
        );
    }

    #[test]
    fn test_detect_bsm_auth_failure() {
        let event = detect_auth_event_from_bsm(
            "testhost",
            "stream1",
            "seg1",
            0,
            AUE_AUTH_FAILURE,
            "user",
            None,
            "password",
            "failure",
            Some(1234),
            Some(501),
            Some(501),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get(event_keys::AUTH_RESULT).unwrap(), "failure");
    }

    #[test]
    fn test_no_detection_non_auth_cmd() {
        let event = detect_auth_event_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/bin/ls",
            &["ls".to_string(), "-la".to_string()],
            1234,
            501,
            501,
            Some(0),
            1000000,
        );
        assert!(event.is_none());
    }

    #[test]
    fn test_extract_sudo_target() {
        assert_eq!(
            extract_sudo_target_user(&["-u".to_string(), "admin".to_string()]),
            "admin"
        );
        assert_eq!(extract_sudo_target_user(&["whoami".to_string()]), "root");
    }

    #[test]
    fn test_extract_ssh_target() {
        assert_eq!(
            extract_ssh_target(&["ssh".to_string(), "user@host".to_string()]),
            "user@host"
        );
        assert_eq!(
            extract_ssh_target(&[
                "ssh".to_string(),
                "-p".to_string(),
                "22".to_string(),
                "host".to_string()
            ]),
            "host"
        );
    }
}
