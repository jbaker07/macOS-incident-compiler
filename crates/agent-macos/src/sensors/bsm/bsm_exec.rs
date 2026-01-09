// macos/sensors/bsm/bsm_exec.rs
// AUE_EXECVE event handler for OpenBSM
// Detects privilege escalation, remote tools, process injection

use super::{bsm_archive_tool_exec, bsm_cred_access, bsm_discovery_exec, bsm_helpers, bsm_tokens};
use crate::sensors::hash_keys;
use serde_json::json;
use std::collections::BTreeMap;
// bsm_priv_escalation: NOT YET IMPLEMENTED - currently unused

/// Handle AUE_EXECVE audit record (AUE code 59)
/// Parses real BSM tokens to extract exe, argv, uid/euid
/// Returns Vec<Event> including primary exec event + derived primitive events
pub fn handle_exec(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    aue_code: i32,
    tokens: Vec<u8>,
    ts_millis: u64,
) -> Result<Vec<edr_core::Event>, String> {
    // Real parsing: extract subject token
    let subject_token = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::SUBJECT_TOKEN_32)
        .ok()
        .and_then(|mut v| v.pop())
        .and_then(|t| bsm_tokens::parse_subject_token(&t))
        .ok_or_else(|| "missing subject token".to_string())?;

    let pid = subject_token.pid.ok_or_else(|| "missing pid".to_string())?;
    let uid = subject_token.uid.ok_or_else(|| "missing uid".to_string())?;
    let euid = subject_token
        .euid
        .or(subject_token.uid)
        .ok_or_else(|| "missing euid".to_string())?;

    // Sanity check: reject absurd values
    if pid == 0 || pid > 100_000_000 {
        return Err("invalid pid".to_string());
    }
    if uid > 100_000_000 || euid > 100_000_000 {
        return Err("invalid uid/euid".to_string());
    }

    // Extract path tokens (exe and args are represented as path/text tokens)
    let exe_path = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::PATH_TOKEN)
        .ok()
        .and_then(|mut v| v.pop())
        .and_then(|t| bsm_tokens::parse_path_token(&t))
        .unwrap_or_else(|| "/unknown".to_string());

    // Extract cwd from text token if present
    let cwd = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::TEXT_TOKEN)
        .ok()
        .and_then(|mut v| v.pop())
        .and_then(|t| bsm_tokens::parse_text_token(&t));

    // Extract argv from arg tokens (bounded to 100 args per record)
    let mut argv = Vec::new();
    if let Ok(tokens) = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::ARG_TOKEN) {
        for token in tokens.into_iter().take(100) {
            if let Some((_arg_num, arg)) = bsm_tokens::parse_arg_token(&token) {
                argv.push(arg);
            }
        }
    }

    let mut events = Vec::new();
    let mut fields = BTreeMap::new();
    fields.insert("aue_code".to_string(), json!(aue_code));
    fields.insert("pid".to_string(), json!(pid));
    fields.insert("uid".to_string(), json!(uid));
    fields.insert("euid".to_string(), json!(euid));
    fields.insert("exe".to_string(), json!(exe_path.clone()));

    if !argv.is_empty() {
        fields.insert("argv".to_string(), json!(argv.clone()));
    }
    if let Some(ref cwd_str) = cwd {
        fields.insert("cwd".to_string(), json!(cwd_str));
    }

    // Detect euid mismatch (privilege boundary cross: user → setuid binary)
    if uid != euid {
        fields.insert("euid_mismatch".to_string(), json!(true));
        if euid == 0 {
            fields.insert("privilege_escalation".to_string(), json!(true));
            fields.insert("attack_class".to_string(), json!("privilege_escalation"));
        }
    }

    // Detect sudo/su execution (privilege escalation via wrapper)
    if exe_path.contains("sudo") || exe_path.contains("su") {
        fields.insert("sudo_or_su".to_string(), json!(true));
        fields.insert("attack_class".to_string(), json!("privilege_escalation"));
    }

    // Detect remote access tools (SSH, SCP, etc.) - lateral movement
    if let Some(remote_tool) = detect_remote_tool(&exe_path) {
        fields.insert("remote_tool".to_string(), json!(remote_tool));
        fields.insert("attack_class".to_string(), json!("lateral_movement"));
    }

    // Detect dylib injection env variables (DYLD_INSERT_LIBRARIES, etc.)
    if let Some(injection_var) = bsm_helpers::detect_dylib_injection_env(&argv) {
        fields.insert("dylib_injection_env".to_string(), json!(injection_var));
        fields.insert("attack_class".to_string(), json!("process_injection"));
    }

    // Detect setuid bit execution
    if is_likely_setuid_binary(&exe_path) {
        fields.insert("likely_setuid".to_string(), json!(true));
        if uid != euid {
            fields.insert("attack_class".to_string(), json!("privilege_escalation"));
        }
    }

    // Primary exec event
    events.push(edr_core::Event {
        ts_ms: ts_millis as i64,
        host: host.clone(),
        tags: vec![
            "macos".to_string(),
            "process".to_string(),
            "exec".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(&host, pid, &stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(&host, uid, &stream_id)),
        evidence_ptr: None, // Capture will assign this
        fields,
    });

    // Wire derived primitive events from exec
    if let Some(cred_evt) = bsm_cred_access::detect_cred_access_from_exec(
        &host,
        &stream_id,
        &segment_id,
        record_index,
        &exe_path,
        &argv,
        pid,
        uid,
        euid,
        ts_millis,
    ) {
        events.push(cred_evt);
    }

    if let Some(disc_evt) = bsm_discovery_exec::detect_discovery_exec(
        &host,
        &stream_id,
        &segment_id,
        record_index,
        &exe_path,
        &argv,
        pid,
        uid,
        euid,
        ts_millis,
    ) {
        events.push(disc_evt);
    }

    if let Some(arch_evt) = bsm_archive_tool_exec::detect_archive_tool_exec(
        &host,
        &stream_id,
        &segment_id,
        record_index,
        &exe_path,
        &argv,
        pid,
        uid,
        euid,
        ts_millis,
    ) {
        events.push(arch_evt);
    }

    Ok(events)
}

/// Detect remote access tools in exec path
/// Returns tool name if found (ssh, sshd, scp, sftp, rsync, screen, tmux)
fn detect_remote_tool(exe_path: &str) -> Option<String> {
    let remote_tools = [
        ("ssh", "ssh"),
        ("sshd", "sshd"),
        ("scp", "scp"),
        ("sftp", "sftp"),
        ("rsync", "rsync"),
        ("screen", "screen"),
        ("tmux", "tmux"),
    ];

    for (name, label) in &remote_tools {
        if exe_path.contains(name) {
            return Some(label.to_string());
        }
    }

    None
}

/// Detect likely setuid binary paths
/// Common setuid binaries: sudo, passwd, chsh, chfn, su, ping, at, mount, etc.
fn is_likely_setuid_binary(exe_path: &str) -> bool {
    let setuid_patterns = [
        "/usr/bin/sudo",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/bin/su",
        "/sbin/ping",
        "/usr/bin/at",
        "/sbin/mount",
        "/sbin/umount",
        "/usr/bin/newgrp",
        "/usr/libexec/", // Many Apple system tools
    ];

    setuid_patterns.iter().any(|pat| exe_path.contains(pat))
}
