// macos/sensors/bsm/bsm_helpers.rs
// Shared utilities for bounded parsing, path classification, canonical event building

use serde_json::json;
use std::collections::BTreeMap;

/// Classify file path into attack categories for enhanced detection
pub fn classify_path(path: &str) -> Vec<&'static str> {
    let mut tags = Vec::new();

    if is_persistence_path(path) {
        tags.push("persistence");
    }
    if is_ssh_path(path) {
        tags.push("ssh");
    }
    if is_cron_path(path) {
        tags.push("cron");
    }
    if is_shell_init_path(path) {
        tags.push("shell_init");
    }
    if is_log_tamper_path(path) {
        tags.push("log_tamper");
    }
    if is_audit_path(path) {
        tags.push("audit_tamper");
    }
    if is_user_writable_path(path) {
        tags.push("user_writable");
    }

    tags
}

/// Check if path is a persistence target (LaunchAgents/Daemons/cron/ssh/init)
fn is_persistence_path(path: &str) -> bool {
    let persistence_patterns = [
        "LaunchAgents/",
        "LaunchDaemons/",
        "crontab",
        "/etc/cron.d/",
        "/usr/lib/cron/tabs/",
        ".ssh/",
        ".zshrc",
        ".bashrc",
        ".profile",
        "/etc/zshrc",
        "/etc/profile",
    ];

    persistence_patterns.iter().any(|pat| path.contains(pat))
}

/// Check if path is SSH-related
fn is_ssh_path(path: &str) -> bool {
    path.contains(".ssh/") || path.contains("authorized_keys") || path.contains("ssh/config")
}

/// Check if path is cron-related
fn is_cron_path(path: &str) -> bool {
    path.contains("crontab") || path.contains("/etc/cron") || path.contains("/usr/lib/cron")
}

/// Check if path is shell init
fn is_shell_init_path(path: &str) -> bool {
    path.contains(".zshrc")
        || path.contains(".bashrc")
        || path.contains(".profile")
        || path.contains("/etc/zshrc")
        || path.contains("/etc/profile")
}

/// Check if path is in audit/log directories
fn is_log_tamper_path(path: &str) -> bool {
    path.starts_with("/var/log/") || path.starts_with("/var/audit/")
}

/// Check if path is audit config
fn is_audit_path(path: &str) -> bool {
    path.contains("/etc/security/audit") || path.contains("/etc/audit")
}

/// Check if path is user-writable location used for staging
fn is_user_writable_path(path: &str) -> bool {
    path.contains("/tmp/")
        || path.contains("/var/tmp/")
        || path.contains("Downloads/")
        || path.contains("/Library/")
}

/// Bounded argv parsing: cap items + string lengths
pub fn parse_argv_bounded(argv_str: &str, max_items: usize, max_len: usize) -> Vec<String> {
    argv_str
        .split_whitespace()
        .take(max_items)
        .map(|s| {
            if s.len() > max_len {
                format!("{}...", &s[..max_len])
            } else {
                s.to_string()
            }
        })
        .collect()
}

/// Extract special flags from argv (bounded): -i, -s, -u, etc.
pub fn extract_argv_flags(argv: &[String]) -> BTreeMap<String, String> {
    let mut flags = BTreeMap::new();
    let mut i = 0;

    while i < argv.len() && i < 50 {
        // Bounded iteration
        match argv[i].as_str() {
            "-i" | "--login" => {
                flags.insert("flag_interactive".to_string(), "true".to_string());
            }
            "-s" | "--shell" => {
                flags.insert("flag_shell".to_string(), "true".to_string());
            }
            "-u" if i + 1 < argv.len() && i < 49 => {
                flags.insert("sudo_target_user".to_string(), argv[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    flags
}

/// Bounded env parsing: cap entries + string sizes
pub fn parse_env_bounded(env_str: &str, max_entries: usize, max_len: usize) -> Vec<String> {
    env_str
        .split_whitespace()
        .take(max_entries)
        .filter(|entry| entry.len() <= max_len)
        .map(|s| s.to_string())
        .collect()
}

/// Detect dylib injection env variables (DYLD_INSERT_LIBRARIES, etc.)
/// Bounded parsing to avoid large argv strings
pub fn detect_dylib_injection_env(env_vars: &[String]) -> Option<String> {
    let injection_patterns = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
    ];

    for var in env_vars.iter().take(100) {
        // Bounded to first 100 env vars
        for pattern in &injection_patterns {
            if var.contains(pattern) {
                // Return truncated version if too long
                if var.len() > 256 {
                    return Some(format!("{}...", &var[..256]));
                }
                return Some(var.clone());
            }
        }
    }

    None
}

/// Detect ptrace/debugging env variables and flags
/// macOS uses ptrace(PT_DENY_ATTACH) to prevent debugging
pub fn detect_ptrace_activity(path: &str, argv: &[String]) -> Option<String> {
    // Detect debuggers/ptrace tools
    let ptrace_tools = [
        "lldb",         // LLVM debugger
        "gdb",          // GNU debugger
        "dtrace",       // Dynamic tracing
        "strace",       // System call tracing
        "DebugService", // macOS debug service
    ];

    for tool in &ptrace_tools {
        if path.contains(tool) {
            return Some(tool.to_string());
        }
    }

    // Detect ptrace-related flags in argv
    for arg in argv.iter().take(50) {
        if arg.contains("--pid") || arg.contains("-p") {
            // Likely attaching to process
            return Some("ptrace_attach".to_string());
        }
    }

    None
}

/// Canonical event builder for macOS BSM events
/// Note: This helper is deprecated - use direct Event construction in handlers
/// to maintain proper proc_key/file_key/identity_key assignments
#[deprecated(note = "Use direct Event construction in handlers instead")]
pub fn build_bsm_event(
    host: String,
    event_type: &str,
    pid: u32,
    uid: u32,
    ts_millis: u64,
    mut fields: BTreeMap<String, serde_json::Value>,
) -> edr_core::Event {
    // Ensure core fields are set
    fields
        .entry("event_type".to_string())
        .or_insert(json!(event_type));
    fields.entry("pid".to_string()).or_insert(json!(pid));
    fields.entry("uid".to_string()).or_insert(json!(uid));

    edr_core::Event {
        ts_ms: ts_millis as i64,
        host,
        tags: vec!["macos".to_string(), event_type.to_string()],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None, // Capture will assign this
        fields,
    }
}
