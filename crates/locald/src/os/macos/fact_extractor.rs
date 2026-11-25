//! macOS fact extractor.
//!
//! Turns the events that `capture_macos_rotating` writes into canonical
//! facts for playbook matching. The event schema is documented in
//! `crates/agent-macos/src/sensors/bsm/bsm_reader.rs`: three tags
//! `["macos", category, operation]` and flat fields (`pid`, `exe`, `path`,
//! `cmdline`, `remote_ip` and so on).
//!
//! Scope: every fact is keyed to the audit session of the process that made
//! the call (`auid` plus `asid`). The audit user id is set at login and is
//! kept across sudo and su, and every process started from one login shares
//! the session id. That lets a playbook join a file write by `cp`, a
//! `launchctl load` and a later root action into one hypothesis, because they
//! all came from the same login.

use crate::hypothesis::canonical_fact::{Fact, FactType, InjectionType, PersistenceType};
use crate::hypothesis::{EvidencePtr, ScopeKey};
use chrono::{DateTime, TimeZone, Utc};
use edr_core::Event;

fn timestamp_from_ms(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap_or_else(Utc::now)
}

fn str_field<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event.fields.get(key).and_then(|v| v.as_str())
}

fn u64_field(event: &Event, key: &str) -> Option<u64> {
    event.fields.get(key).and_then(|v| v.as_u64())
}

fn succeeded(event: &Event) -> bool {
    event.fields.get("success").and_then(|v| v.as_bool()).unwrap_or(true)
}

/// Session scope when the process has a login (auid), otherwise user scope.
pub fn scope_for(event: &Event) -> ScopeKey {
    if let Some(auid) = u64_field(event, "auid") {
        let asid = u64_field(event, "asid").unwrap_or(0);
        return ScopeKey::Session {
            key: format!("{}:auid={}:asid={}", event.host, auid, asid),
        };
    }
    let uid = u64_field(event, "uid").unwrap_or(0);
    ScopeKey::User {
        key: format!("{}:uid={}", event.host, uid),
    }
}

/// What kind of persistence a path is, if it is one.
pub fn persistence_type(path: &str) -> Option<PersistenceType> {
    if path.ends_with(".plist") && path.contains("/Library/LaunchAgents/") {
        return Some(PersistenceType::LaunchAgent);
    }
    if path.ends_with(".plist") && path.contains("/Library/LaunchDaemons/") {
        return Some(PersistenceType::LaunchDaemon);
    }
    if path.starts_with("/usr/lib/cron/tabs/")
        || path.starts_with("/private/var/at/tabs/")
        || path.starts_with("/var/at/tabs/")
        || path == "/etc/crontab"
        || path == "/private/etc/crontab"
    {
        return Some(PersistenceType::CronJob);
    }
    if path.ends_with("/.ssh/authorized_keys") {
        return Some(PersistenceType::SshAuthorizedKey);
    }
    let profiles = ["/.zshrc", "/.zprofile", "/.zshenv", "/.bash_profile", "/.bashrc", "/.profile"];
    for profile in profiles.iter() {
        if path.ends_with(profile) {
            return Some(PersistenceType::ShellProfile);
        }
    }
    if path.starts_with("/Library/StartupItems/") || path.starts_with("/private/etc/periodic/") {
        return Some(PersistenceType::Other("macos_startup".to_string()));
    }
    None
}

/// Extract facts from one capture event.
pub fn extract_facts(event: &Event) -> Vec<Fact> {
    extract_facts_with_hash(event, None)
}

/// Same as `extract_facts`, with the SHA-256 of the segment line that held
/// the event, so each evidence pointer can be checked against the file.
pub fn extract_facts_with_hash(event: &Event, record_sha256: Option<String>) -> Vec<Fact> {
    let mut facts = Vec::new();
    if event.tags.len() < 3 || event.tags[0] != "macos" {
        return facts;
    }
    let category = event.tags[1].as_str();
    let op = event.tags[2].as_str();
    let ts = timestamp_from_ms(event.ts_ms);
    let host = event.host.clone();
    let scope = scope_for(event);

    let mut evidence = match &event.evidence_ptr {
        Some(ptr) => EvidencePtr::new(ptr.stream_id.clone(), ptr.segment_id.to_string(), ptr.record_index as u64),
        None => EvidencePtr::new("unknown", "0", 0),
    }
    .with_timestamp(ts);
    evidence.record_sha256 = record_sha256;

    // Who did it. Playbooks can match on the actor with actor_exe_regex and
    // leave out known good tools with actor_exe_not_regex.
    let mut actor = std::collections::HashMap::new();
    for key in ["exe", "pid", "ppid", "parent_exe", "auid", "uid", "euid", "success"] {
        if let Some(value) = event.fields.get(key) {
            let name = match key {
                "exe" => "actor_exe".to_string(),
                "pid" => "actor_pid".to_string(),
                other => other.to_string(),
            };
            actor.insert(name, value.clone());
        }
    }

    let mut push = |fact_type: FactType| {
        let mut fact = Fact::new(host.clone(), scope.clone(), fact_type, vec![evidence.clone()]);
        fact.extra_fields = actor.clone();
        facts.push(fact);
    };

    let pid = u64_field(event, "pid").unwrap_or(0);

    match (category, op) {
        ("process", "exec") => {
            if !succeeded(event) {
                return facts;
            }
            let path = str_field(event, "exe").unwrap_or("").to_string();
            if path.is_empty() {
                return facts;
            }
            let signer = str_field(event, "signing_id").filter(|s| !s.is_empty()).map(|s| {
                match str_field(event, "team_id").filter(|t| !t.is_empty()) {
                    Some(team) => format!("{} ({})", s, team),
                    None => s.to_string(),
                }
            });
            push(FactType::Exec {
                exe_hash: str_field(event, "cdhash").map(|s| s.to_string()),
                path,
                signer,
                cmdline: str_field(event, "cmdline").map(|s| s.to_string()),
            });
            if let Some(ppid) = u64_field(event, "ppid") {
                push(FactType::ProcSpawn {
                    parent_proc_key: format!("pid:{}", ppid),
                    child_proc_key: format!("pid:{}", pid),
                });
            }
        }
        ("process", "task_for_pid") | ("process", "ptrace") => {
            if !succeeded(event) {
                return facts;
            }
            if let Some(target) = u64_field(event, "target_pid") {
                let injection_type = if op == "ptrace" {
                    InjectionType::PtraceAttach
                } else {
                    InjectionType::Other("task_for_pid".to_string())
                };
                push(FactType::Injection {
                    source_proc_key: format!("pid:{}", pid),
                    target_proc_key: format!("pid:{}", target),
                    injection_type,
                });
            }
        }
        ("file", _) => {
            let path = match str_field(event, "path") {
                Some(p) => p.to_string(),
                None => return facts,
            };
            match op {
                "read" => push(FactType::ReadPath {
                    path: path.clone(),
                    inode: u64_field(event, "inode"),
                    bytes: None,
                }),
                "write" | "truncate" => push(FactType::WritePath {
                    path: path.clone(),
                    inode: u64_field(event, "inode"),
                    bytes: None,
                    entropy: None,
                }),
                "create" => push(FactType::CreatePath {
                    path: path.clone(),
                    inode: u64_field(event, "inode"),
                }),
                "delete" => push(FactType::DeletePath {
                    path: path.clone(),
                    inode: u64_field(event, "inode"),
                }),
                "rename" => push(FactType::RenamePath {
                    old_path: path.clone(),
                    new_path: str_field(event, "new_path").unwrap_or("").to_string(),
                }),
                _ => {}
            }

            if succeeded(event) {
                // A plist, crontab or profile written or moved into place
                let target = if op == "rename" {
                    str_field(event, "new_path").map(|s| s.to_string())
                } else if op == "create" || op == "write" {
                    Some(path.clone())
                } else {
                    None
                };
                if let Some(target) = target {
                    if let Some(kind) = persistence_type(&target) {
                        push(FactType::PersistArtifact {
                            artifact_type: kind,
                            path_or_key: target,
                            enable_action: false,
                        });
                    }
                }
            }
        }
        ("privilege", "setuid") | ("privilege", "seteuid") | ("privilege", "setreuid") | ("privilege", "setresuid") => {
            if !succeeded(event) {
                return facts;
            }
            let before = u64_field(event, "uid").unwrap_or(0) as u32;
            if let Some(after) = u64_field(event, "target_uid") {
                if after as u32 != before {
                    push(FactType::PrivilegeBoundary {
                        uid_before: before,
                        uid_after: after as u32,
                        caps_before: None,
                        caps_after: None,
                    });
                }
            }
        }
        ("network", "connect") => {
            if let (Some(ip), Some(port)) = (str_field(event, "remote_ip"), u64_field(event, "remote_port")) {
                push(FactType::OutboundConnect {
                    dst_ip: ip.to_string(),
                    dst_port: port as u16,
                    proto: str_field(event, "family").unwrap_or("inet").to_string(),
                    sock_id: u64_field(event, "fd").map(|fd| format!("pid:{}:fd:{}", pid, fd)),
                });
            }
        }
        ("network", "accept") => {
            if let (Some(ip), Some(port)) = (str_field(event, "remote_ip"), u64_field(event, "remote_port")) {
                push(FactType::InboundConnect {
                    src_ip: ip.to_string(),
                    src_port: port as u16,
                    proto: str_field(event, "family").unwrap_or("inet").to_string(),
                    sock_id: None,
                });
            }
        }
        _ => {}
    }

    facts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn event(tags: [&str; 3], fields: serde_json::Value) -> Event {
        let mut map = BTreeMap::new();
        for (k, v) in fields.as_object().unwrap() {
            map.insert(k.clone(), v.clone());
        }
        Event {
            ts_ms: 1_795_446_000_000,
            host: "test-mac".into(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: Some(edr_core::EvidencePtr {
                stream_id: "bsm".into(),
                segment_id: 3,
                record_index: 7,
            }),
            fields: map,
        }
    }

    #[test]
    fn exec_becomes_exec_and_spawn_facts() {
        let e = event(
            ["macos", "process", "exec"],
            json!({"pid": 10, "ppid": 9, "exe": "/bin/launchctl", "cmdline": "launchctl load x.plist",
                   "signing_id": "com.apple.xpc.launchctl", "team_id": "", "auid": 501, "asid": 7, "uid": 501, "success": true}),
        );
        let facts = extract_facts(&e);
        assert_eq!(facts.len(), 2);
        match &facts[0].fact_type {
            FactType::Exec { path, cmdline, signer, .. } => {
                assert_eq!(path, "/bin/launchctl");
                assert_eq!(cmdline.as_deref(), Some("launchctl load x.plist"));
                assert_eq!(signer.as_deref(), Some("com.apple.xpc.launchctl"));
            }
            other => panic!("unexpected {:?}", other),
        }
        assert_eq!(facts[0].scope_key.to_string(), "session:test-mac:auid=501:asid=7");
        assert_eq!(facts[0].evidence_ptrs[0].segment_id, "3");
        assert_eq!(facts[0].evidence_ptrs[0].record_index, 7);
        assert_eq!(facts[0].extra_fields["actor_exe"], "/bin/launchctl");
    }

    #[test]
    fn launch_agent_create_adds_persistence() {
        let e = event(
            ["macos", "file", "create"],
            json!({"pid": 10, "path": "/Users/alice/Library/LaunchAgents/com.x.plist", "auid": 501, "asid": 7, "success": true}),
        );
        let facts = extract_facts(&e);
        assert!(facts.iter().any(|f| matches!(f.fact_type, FactType::CreatePath { .. })));
        assert!(facts.iter().any(|f| matches!(
            &f.fact_type,
            FactType::PersistArtifact { artifact_type: PersistenceType::LaunchAgent, .. }
        )));
    }

    #[test]
    fn delete_is_a_delete_fact_and_failed_exec_adds_nothing() {
        let e = event(
            ["macos", "file", "delete"],
            json!({"pid": 10, "path": "/private/var/log/system.log", "auid": 501, "asid": 7, "success": true}),
        );
        let facts = extract_facts(&e);
        assert!(matches!(facts[0].fact_type, FactType::DeletePath { .. }));

        let failed = event(["macos", "process", "exec"], json!({"pid": 10, "exe": "/bin/ls", "success": false}));
        assert!(extract_facts(&failed).is_empty());
    }

    #[test]
    fn setuid_to_a_new_uid_is_a_privilege_boundary() {
        let e = event(
            ["macos", "privilege", "setuid"],
            json!({"pid": 10, "uid": 501, "euid": 0, "target_uid": 0, "auid": 501, "asid": 7, "success": true}),
        );
        let facts = extract_facts(&e);
        assert!(matches!(
            facts[0].fact_type,
            FactType::PrivilegeBoundary { uid_before: 501, uid_after: 0, .. }
        ));
    }
}
