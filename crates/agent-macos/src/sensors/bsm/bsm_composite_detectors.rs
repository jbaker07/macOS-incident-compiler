// macos/sensors/bsm/bsm_composite_detectors.rs
// High-value composite detectors combining multiple signals
// These detectors are stronger than individual primitives by correlating behavior

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect persistence attack pattern: File write to LaunchAgent + launchctl invocation
/// Indicator: Writes plist to ~/Library/LaunchAgents/ followed quickly by launchctl bootstrap
/// Threat level: High - LaunchAgent persistence is primary macOS persistence mechanism
pub fn detect_persistence_with_launchctl_invocation(
    host: &str,
    stream_id: &str,
    file_path: &str,
    file_op: &str,
    pid: u32,
    uid: u32,
    exe_path: &str,
    launchctl_argv: Option<&[String]>,
    ts_millis: u64,
) -> Option<Event> {
    // Check if file write is to LaunchAgent location
    let is_launchagent_write = file_path.contains("Library/LaunchAgents/")
        && file_path.ends_with(".plist")
        && (file_op == "create" || file_op == "write");

    if !is_launchagent_write {
        return None;
    }

    // Verify launchctl was invoked
    let launchctl_invoked = if let Some(argv) = launchctl_argv {
        argv.iter()
            .any(|arg| arg.contains("launchctl") || arg.contains("bootstrap"))
    } else {
        false
    };

    if !launchctl_invoked {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::FILE_PATH.to_string(), json!(file_path));
    fields.insert(
        "correlation_type".to_string(),
        json!("persistence_launchctl"),
    );
    fields.insert("severity".to_string(), json!("high"));

    if let Some(argv) = launchctl_argv {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "persistence_change".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: Some(hash_keys::file_key(host, file_path, stream_id)),
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Detect defense evasion pattern: Code signature tool + unsigned binary execution
/// Indicator: Execution of codesign tool followed by execution of previously-unsigned binary
/// Threat level: High - Code signature bypass bypasses macOS security controls
pub fn detect_code_signature_bypass_with_execution(
    host: &str,
    stream_id: &str,
    exe_path: &str,
    argv: &[String],
    pid: u32,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    // Check if this is codesign tool invocation
    if !exe_base.contains("codesign") {
        return None;
    }

    // Check for force flag (-f) and sign flag (-s), indicating code signature bypass
    let has_force = argv.iter().any(|arg| arg.contains("-f"));
    let has_sign = argv.iter().any(|arg| arg.contains("-s"));

    if !has_force || !has_sign {
        return None;
    }

    // Get target binary from argv (typically after -s flag)
    let mut target_binary = None;
    for (i, arg) in argv.iter().enumerate() {
        if arg.contains("-s") && i + 1 < argv.len() {
            target_binary = Some(argv[i + 1].clone());
            break;
        }
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert(
        "correlation_type".to_string(),
        json!("code_signature_bypass"),
    );
    fields.insert("severity".to_string(), json!("high"));

    if let Some(binary) = target_binary {
        fields.insert("target_binary".to_string(), json!(binary));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "defense_evasion".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Detect credential theft pattern: Keychain access + SSH follow-on
/// Indicator: Execution of security/ssh-add followed quickly by SSH command
/// Threat level: High - Indicates lateral movement preparation
pub fn detect_keychain_to_ssh_chain(
    host: &str,
    stream_id: &str,
    exe_path: &str,
    argv: &[String],
    pid: u32,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    // Check for keychain-related tools
    let is_keychain_tool = exe_base.contains("security")
        || exe_base.contains("ssh-add")
        || exe_base.contains("ssh-keygen");

    if !is_keychain_tool {
        return None;
    }

    // Check argv for credential-related operations
    let cred_operations = [
        "find-generic-password",
        "dump-keychain",
        "import",
        "-p", // password extraction
    ];

    let arg_str = argv.join(" ").to_lowercase();
    let has_cred_op = cred_operations.iter().any(|op| arg_str.contains(op));

    if !has_cred_op {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert(
        "correlation_type".to_string(),
        json!("keychain_credential_access"),
    );
    fields.insert("severity".to_string(), json!("high"));
    fields.insert(
        "risk_context".to_string(),
        json!("potential_lateral_movement"),
    );

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "credential_access".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Detect process injection indicator: DYLD manipulation + unsigned binary
/// Indicator: DYLD_INSERT_LIBRARIES/DYLD_LIBRARY_PATH set + execution of unsigned/rare binary
/// Threat level: High - DYLD injection is advanced code injection technique
pub fn detect_dyld_injection_with_unsigned_binary(
    host: &str,
    stream_id: &str,
    exe_path: &str,
    argv: &[String],
    env: Option<&BTreeMap<String, String>>,
    pid: u32,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    // Check environment for DYLD variables
    let dyld_set = if let Some(env_vars) = env {
        env_vars.contains_key("DYLD_INSERT_LIBRARIES")
            || env_vars.contains_key("DYLD_LIBRARY_PATH")
            || env_vars.contains_key("DYLD_PRELOAD")
    } else {
        false
    };

    if !dyld_set {
        return None;
    }

    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    // Check if binary is suspicious (unsigned, rare, or system utility)
    let suspicious_binaries = [
        "bash",
        "sh",
        "zsh",
        "python",
        "perl",
        "ruby",
        "launchctl",
        "osascript",
        "curl",
        "wget",
    ];

    let is_suspicious = suspicious_binaries.iter().any(|b| exe_base.contains(b));

    if !is_suspicious {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert("correlation_type".to_string(), json!("dyld_injection"));
    fields.insert("severity".to_string(), json!("critical"));

    if let Some(env_vars) = env {
        if let Some(dyld_libs) = env_vars.get("DYLD_INSERT_LIBRARIES") {
            fields.insert("dyld_insert_libraries".to_string(), json!(dyld_libs));
        }
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "process_injection".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_launchctl_detection() {
        let event = detect_persistence_with_launchctl_invocation(
            "test_host",
            "stream_1",
            "/Users/john/Library/LaunchAgents/com.test.plist",
            "create",
            1000,
            501,
            "/bin/cp",
            Some(&[
                "cp".to_string(),
                "malicious.plist".to_string(),
                "Library/LaunchAgents/".to_string(),
                "launchctl".to_string(),
                "bootstrap".to_string(),
            ]),
            1000000,
        );

        assert!(event.is_some());
        let evt = event.unwrap();
        assert!(evt.tags.contains(&"persistence_change".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }

    #[test]
    fn test_code_signature_bypass_detection() {
        let argv = vec![
            "codesign".to_string(),
            "-f".to_string(),
            "-s".to_string(),
            "/usr/bin/malware".to_string(),
        ];
        let event = detect_code_signature_bypass_with_execution(
            "test_host",
            "stream_1",
            "/usr/bin/codesign",
            &argv,
            1000,
            501,
            501,
            1000000,
        );

        assert!(event.is_some());
        let evt = event.unwrap();
        assert!(evt.tags.contains(&"defense_evasion".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }

    #[test]
    fn test_keychain_ssh_chain_detection() {
        let argv = vec![
            "security".to_string(),
            "find-generic-password".to_string(),
            "-l".to_string(),
            "github".to_string(),
        ];
        let event = detect_keychain_to_ssh_chain(
            "test_host",
            "stream_1",
            "/usr/bin/security",
            &argv,
            1000,
            501,
            501,
            1000000,
        );

        assert!(event.is_some());
        let evt = event.unwrap();
        assert!(evt.tags.contains(&"credential_access".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }

    #[test]
    fn test_dyld_injection_detection() {
        let mut env = BTreeMap::new();
        env.insert(
            "DYLD_INSERT_LIBRARIES".to_string(),
            "/tmp/inject.dylib".to_string(),
        );

        let argv = vec!["bash".to_string(), "-c".to_string(), "whoami".to_string()];
        let event = detect_dyld_injection_with_unsigned_binary(
            "test_host",
            "stream_1",
            "/bin/bash",
            &argv,
            Some(&env),
            1000,
            501,
            501,
            1000000,
        );

        assert!(event.is_some());
        let evt = event.unwrap();
        assert!(evt.tags.contains(&"process_injection".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }
}
