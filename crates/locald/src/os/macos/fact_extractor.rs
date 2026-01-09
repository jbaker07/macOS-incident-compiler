//! macOS Fact Extractor
//!
//! Converts macOS BSM/OpenBSM telemetry events to canonical Facts for playbook matching.
//! Maps BSM event types and tags to the FactType enum variants.

use crate::hypothesis::canonical_fact::{Fact, FactType, PersistenceType, AuthType};
use crate::hypothesis::{EvidencePtr, ScopeKey};
use chrono::{DateTime, TimeZone, Utc};
use edr_core::Event;

/// Extract canonical facts from a macOS BSM event
///
/// This is the primary entry point for the fact extraction pipeline.
/// Maps macOS event tags/fields to canonical FactType variants.
pub fn extract_facts(event: &Event) -> Vec<Fact> {
    let mut facts = Vec::new();
    let ts = timestamp_from_ms(event.ts_ms);
    let host_id = event.host.clone();

    // Build evidence pointer with timestamp
    let evidence = match &event.evidence_ptr {
        Some(ptr) => EvidencePtr::new(
            ptr.stream_id.clone(),
            format!("{}", ptr.segment_id),
            ptr.record_index as u64,
        )
        .with_timestamp(ts),
        None => EvidencePtr::new("unknown", "0", 0).with_timestamp(ts),
    };

    // Route by tags to appropriate extractors
    for tag in &event.tags {
        match tag.as_str() {
            // Process execution events (AUE_EXECVE, AUE_EXEC, etc.)
            "process" | "exec" | "execve" | "fork" | "posix_spawn" => {
                if let Some(fact) = extract_process_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // File operations (AUE_OPEN_*, AUE_CREATE, etc.)
            "file" | "open" | "create" | "unlink" | "rename" | "write" | "read" => {
                if let Some(fact) = extract_file_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Credential/auth events (AUE_auth_*, AUE_sudo, etc.)
            "auth" | "sudo" | "su" | "login" | "logout" => {
                if let Some(fact) = extract_auth_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Keychain access
            "keychain" | "security" => {
                if let Some(fact) = extract_keychain_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Persistence mechanisms
            "launchd" | "launchagent" | "launchdaemon" | "cron" | "at" => {
                if let Some(fact) = extract_persistence_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Privilege escalation
            "setuid" | "setgid" | "privilege" | "priv_escalation" => {
                if let Some(fact) = extract_privesc_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Defense evasion
            "xattr" | "quarantine" | "gatekeeper" | "tcc" | "sip" => {
                if let Some(fact) = extract_evasion_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Network events
            "network" | "socket" | "connect" | "bind" | "listen" => {
                if let Some(fact) = extract_network_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Shell command execution
            "shell" | "bash" | "zsh" | "sh" => {
                if let Some(fact) = extract_shell_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Script execution (osascript, python, etc.)
            "script" | "osascript" | "python" | "ruby" | "perl" => {
                if let Some(fact) = extract_script_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            _ => {}
        }
    }

    // Also check fields for BSM event types
    if let Some(aue_code) = event.fields.get("aue_code").and_then(|v| v.as_i64()) {
        if let Some(fact) = extract_from_aue_code(event, aue_code as i32, &host_id, &evidence) {
            // Deduplicate - only add if not already present
            let dominated = facts.iter().any(|f| {
                std::mem::discriminant(&f.fact_type) == std::mem::discriminant(&fact.fact_type)
            });
            if !dominated {
                facts.push(fact);
            }
        }
    }

    facts
}

/// Convert milliseconds timestamp to DateTime
fn timestamp_from_ms(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap_or_else(Utc::now)
}

/// Build scope key from host and event
fn build_scope_key(host_id: &str, event: &Event) -> ScopeKey {
    // Use ProcScopeKeyBuilder if we have process info
    if let Some(proc_key) = &event.proc_key {
        // Parse pid if available
        let pid = event
            .fields
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        
        let start_time_ns = event.ts_ms as u64 * 1_000_000; // Convert ms to ns
        
        let mut builder = crate::hypothesis::scope_keys::ProcScopeKeyBuilder::new(
            host_id,
            start_time_ns,
            pid,
        );
        
        // Add exe hash if available
        if let Some(hash) = event.fields.get("hash").and_then(|v| v.as_str()) {
            builder = builder.exe_hash(hash);
        }
        
        return builder.build();
    }
    
    // Fall back to user scope key if we have user info
    if let Some(user) = event.fields.get("user").or_else(|| event.fields.get("uid")) {
        if let Some(user_str) = user.as_str() {
            return ScopeKey::User { key: format!("{}:{}", host_id, user_str) };
        }
    }
    
    // Default to process scope with just host info
    ScopeKey::Process { key: format!("{}:unknown", host_id) }
}

/// Extract process execution fact (maps to Exec)
fn extract_process_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("exec_path"))
        .and_then(|v| v.as_str())?;

    let cmdline = event
        .fields
        .get("cmdline")
        .or_else(|| event.fields.get("args"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let fact_type = FactType::Exec {
        path: path.to_string(),
        exe_hash: event.fields.get("hash").and_then(|v| v.as_str()).map(|s| s.to_string()),
        signer: event.fields.get("signer").and_then(|v| v.as_str()).map(|s| s.to_string()),
        cmdline,
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract file access/modification fact
fn extract_file_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("file_path"))
        .and_then(|v| v.as_str())?;

    let operation = event
        .fields
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("read");

    // Map operation to appropriate fact type
    let fact_type = match operation {
        "write" | "modify" => FactType::WritePath {
            path: path.to_string(),
            inode: event.fields.get("inode").and_then(|v| v.as_u64()),
            bytes: event.fields.get("bytes").and_then(|v| v.as_u64()),
            entropy: None,
        },
        "create" => FactType::CreatePath {
            path: path.to_string(),
            inode: event.fields.get("inode").and_then(|v| v.as_u64()),
        },
        "delete" | "unlink" => FactType::DeletePath {
            path: path.to_string(),
            inode: event.fields.get("inode").and_then(|v| v.as_u64()),
        },
        "rename" => FactType::RenamePath {
            old_path: path.to_string(),
            new_path: event.fields.get("new_path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        },
        _ => FactType::ReadPath {
            path: path.to_string(),
            inode: event.fields.get("inode").and_then(|v| v.as_u64()),
            bytes: event.fields.get("bytes").and_then(|v| v.as_u64()),
        },
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract authentication fact
fn extract_auth_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let user = event
        .fields
        .get("user")
        .or_else(|| event.fields.get("target_user"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let success = event
        .fields
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let is_sudo = event.tags.iter().any(|t| t == "sudo");
    let is_su = event.tags.iter().any(|t| t == "su");
    let is_ssh = event.tags.iter().any(|t| t == "ssh");

    let auth_type = if is_sudo {
        AuthType::Sudo
    } else if is_su {
        AuthType::Su
    } else if is_ssh {
        AuthType::Ssh
    } else {
        AuthType::Interactive  // Local login on macOS
    };

    let fact_type = FactType::AuthEvent {
        user: user.to_string(),
        auth_type,
        source: event.fields.get("source_ip").and_then(|v| v.as_str()).map(|s| s.to_string()),
        success,
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract keychain access fact (credential access - maps to ReadPath on keychain)
fn extract_keychain_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let keychain_path = event
        .fields
        .get("keychain")
        .or_else(|| event.fields.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("~/Library/Keychains/login.keychain-db");

    let fact_type = FactType::ReadPath {
        path: keychain_path.to_string(),
        inode: None,
        bytes: None,
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract persistence installation fact
fn extract_persistence_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("plist_path"))
        .and_then(|v| v.as_str())?;

    let artifact_type = if path.contains("LaunchAgents") {
        PersistenceType::LaunchAgent
    } else if path.contains("LaunchDaemons") {
        PersistenceType::LaunchDaemon
    } else if path.contains("cron") || path.contains("/var/at/") {
        PersistenceType::CronJob
    } else {
        PersistenceType::Other("macos_other".to_string())
    };

    let fact_type = FactType::PersistArtifact {
        artifact_type,
        path_or_key: path.to_string(),
        enable_action: true,
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract privilege escalation fact
fn extract_privesc_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let uid_before = event
        .fields
        .get("uid")
        .or_else(|| event.fields.get("ruid"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(1000);

    let uid_after = event
        .fields
        .get("euid")
        .or_else(|| event.fields.get("target_uid"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    let fact_type = FactType::PrivilegeBoundary {
        uid_before,
        uid_after,
        caps_before: None,
        caps_after: None,
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract defense evasion fact (maps to SecurityToolDisable or LogTamper)
fn extract_evasion_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let is_gatekeeper = event.tags.iter().any(|t| t == "gatekeeper" || t == "quarantine" || t == "xattr");
    let is_tcc = event.tags.iter().any(|t| t == "tcc");
    let is_sip = event.tags.iter().any(|t| t == "sip");

    let fact_type = if is_gatekeeper {
        FactType::SecurityToolDisable {
            tool_name: "Gatekeeper".to_string(),
            method: "xattr_removal".to_string(),
        }
    } else if is_tcc {
        FactType::SecurityToolDisable {
            tool_name: "TCC".to_string(),
            method: "database_manipulation".to_string(),
        }
    } else if is_sip {
        FactType::SecurityToolDisable {
            tool_name: "SIP".to_string(),
            method: "csrutil".to_string(),
        }
    } else {
        FactType::SecurityToolDisable {
            tool_name: "unknown".to_string(),
            method: "unknown".to_string(),
        }
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract network connection fact
fn extract_network_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let dest_ip = event
        .fields
        .get("dest_ip")
        .or_else(|| event.fields.get("remote_addr"))
        .and_then(|v| v.as_str())?;

    let dest_port = event
        .fields
        .get("dest_port")
        .or_else(|| event.fields.get("remote_port"))
        .and_then(|v| v.as_i64())
        .map(|v| v as u16)
        .unwrap_or(0);

    let protocol = event
        .fields
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");

    let fact_type = FactType::OutboundConnect {
        dst_ip: dest_ip.to_string(),
        dst_port: dest_port,
        proto: protocol.to_string(),
        sock_id: None,
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract shell command execution fact
fn extract_shell_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let shell = event
        .fields
        .get("shell")
        .or_else(|| event.fields.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("/bin/sh");

    let command = event
        .fields
        .get("cmdline")
        .or_else(|| event.fields.get("command"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let fact_type = FactType::ShellCommand {
        shell: shell.to_string(),
        command: command.to_string(),
        is_encoded: command.contains("-enc") || command.contains("base64"),
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract script execution fact
fn extract_script_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let interpreter = event
        .fields
        .get("interpreter")
        .or_else(|| event.fields.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("osascript");

    let script_path = event
        .fields
        .get("script_path")
        .or_else(|| event.fields.get("script"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let fact_type = FactType::ScriptExec {
        interpreter: interpreter.to_string(),
        script_path,
        script_content_hash: None,
    };

    Some(Fact::new(
        host_id,
        build_scope_key(host_id, event),
        fact_type,
        vec![evidence.clone()],
    ))
}

/// Extract fact based on BSM AUE code
fn extract_from_aue_code(event: &Event, aue_code: i32, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // Map common BSM AUE codes to fact types
    match aue_code {
        // Process execution (AUE_EXECVE = 23, AUE_EXEC = 7)
        7 | 23 | 190 | 191 => extract_process_fact(event, host_id, evidence),
        
        // File operations (AUE_OPEN* = 72-77, AUE_CREATE = 4)
        4 | 72..=77 | 42 | 43 => extract_file_fact(event, host_id, evidence),
        
        // Auth events (AUE_auth_user = 45000+)
        45001..=45100 => extract_auth_fact(event, host_id, evidence),
        
        // Socket operations (AUE_SOCKET = 183, AUE_CONNECT = 62)
        62 | 183 | 184 | 185 => extract_network_fact(event, host_id, evidence),
        
        // Setuid/setgid (AUE_SETUID = 200, AUE_SETGID = 201)
        200 | 201 | 202 | 203 => extract_privesc_fact(event, host_id, evidence),
        
        _ => None,
    }
}
