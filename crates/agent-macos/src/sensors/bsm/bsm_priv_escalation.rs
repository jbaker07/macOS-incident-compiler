// macos/sensors/bsm/bsm_priv_escalation.rs
// Privilege escalation handlers for OpenBSM audit records
// Handles: setuid, setgid, seteuid, setegid, setgroups, setreuid, setregid
// Emits canonical events for credential manipulation and priv escalation detection

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// AUE codes for privilege escalation operations
pub mod aue {
    pub const AUE_SETUID: i32 = 24; // setuid()
    pub const AUE_SETGID: i32 = 25; // setgid()
    pub const AUE_SETEUID: i32 = 126; // seteuid()
    pub const AUE_SETEGID: i32 = 127; // setegid()
    pub const AUE_SETGROUPS: i32 = 128; // setgroups()
    pub const AUE_SETREUID: i32 = 130; // setreuid()
    pub const AUE_SETREGID: i32 = 131; // setregid()
    pub const AUE_SETAUID: i32 = 177; // setauid() - audit user ID
    pub const AUE_SETPRIORITY: i32 = 41; // setpriority() - nice value
}

/// Privileged UIDs that indicate escalation
const PRIVILEGED_UIDS: &[u32] = &[
    0, // root
    1, // daemon
];

/// System groups that indicate privileged access
const PRIVILEGED_GIDS: &[u32] = &[
    0,  // wheel
    1,  // daemon
    80, // admin
    20, // staff (less privileged but notable)
];

/// Handle AUE_SETUID - setuid() system call
/// Detects attempts to change real user ID
pub fn handle_setuid(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    pid: u32,
    original_uid: u32,
    original_euid: u32,
    target_uid: u32,
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(original_uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(original_euid));
    fields.insert("target_uid".to_string(), json!(target_uid));
    fields.insert("operation".to_string(), json!("setuid"));
    fields.insert("success".to_string(), json!(success));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    // Classify the privilege transition
    let escalation_type = classify_uid_transition(original_uid, original_euid, target_uid);
    fields.insert("escalation_type".to_string(), json!(escalation_type));

    // Mark if this is escalation to root
    let to_root = target_uid == 0;
    let from_unprivileged = original_uid != 0 && original_euid != 0;

    if to_root {
        fields.insert("to_root".to_string(), json!(true));
    }
    if from_unprivileged && to_root {
        fields.insert("priv_escalation".to_string(), json!(true));
    }

    // If escalating to root from unprivileged, emit as defense_evasion canonical type
    let tags = if to_root && from_unprivileged {
        // Add canonical defense_evasion fields
        fields.insert(event_keys::EVASION_TARGET.to_string(), json!("uid_control"));
        fields.insert(
            event_keys::EVASION_ACTION.to_string(),
            json!("setuid_to_root"),
        );
        vec![
            "macos".to_string(),
            "defense_evasion".to_string(), // CANONICAL TYPE at tags[1]
            "priv_escalation".to_string(),
            "setuid".to_string(),
            "bsm".to_string(),
            "high_value".to_string(),
        ]
    } else {
        // Base signal - not canonical, won't be counted/validated
        vec![
            "macos".to_string(),
            "priv_base".to_string(), // Non-canonical base signal
            "priv_escalation".to_string(),
            "setuid".to_string(),
            "bsm".to_string(),
        ]
    };

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, target_uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_SETGID - setgid() system call
pub fn handle_setgid(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    pid: u32,
    uid: u32,
    euid: u32,
    original_gid: u32,
    target_gid: u32,
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert("original_gid".to_string(), json!(original_gid));
    fields.insert("target_gid".to_string(), json!(target_gid));
    fields.insert("operation".to_string(), json!("setgid"));
    fields.insert("success".to_string(), json!(success));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    // Check for privileged group transition
    let to_privileged = PRIVILEGED_GIDS.contains(&target_gid);
    let from_unprivileged = !PRIVILEGED_GIDS.contains(&original_gid);

    if to_privileged {
        fields.insert("to_privileged_group".to_string(), json!(true));
    }
    if from_unprivileged && to_privileged {
        fields.insert("group_escalation".to_string(), json!(true));
    }

    // If escalating to wheel (gid 0) from unprivileged, emit as defense_evasion
    let tags = if target_gid == 0 && from_unprivileged {
        fields.insert(event_keys::EVASION_TARGET.to_string(), json!("gid_control"));
        fields.insert(
            event_keys::EVASION_ACTION.to_string(),
            json!("setgid_to_wheel"),
        );
        vec![
            "macos".to_string(),
            "defense_evasion".to_string(), // CANONICAL TYPE at tags[1]
            "priv_escalation".to_string(),
            "setgid".to_string(),
            "wheel".to_string(),
            "bsm".to_string(),
        ]
    } else {
        // Base signal - not canonical
        let mut t = vec![
            "macos".to_string(),
            "priv_base".to_string(),
            "priv_escalation".to_string(),
            "setgid".to_string(),
            "bsm".to_string(),
        ];
        if target_gid == 0 {
            t.push("wheel".to_string());
        }
        t
    };

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_SETEUID - set effective user ID
pub fn handle_seteuid(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    pid: u32,
    uid: u32,
    original_euid: u32,
    target_euid: u32,
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert("original_euid".to_string(), json!(original_euid));
    fields.insert("target_euid".to_string(), json!(target_euid));
    fields.insert("operation".to_string(), json!("seteuid"));
    fields.insert("success".to_string(), json!(success));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    let escalation_type = classify_euid_transition(original_euid, target_euid);
    fields.insert("escalation_type".to_string(), json!(escalation_type));

    let to_root = target_euid == 0;
    let from_unprivileged = original_euid != 0;

    if to_root {
        fields.insert("to_root".to_string(), json!(true));
    }
    if from_unprivileged && to_root {
        fields.insert("priv_escalation".to_string(), json!(true));
    }

    // If escalating to root from unprivileged, emit as defense_evasion canonical type
    let tags = if to_root && from_unprivileged {
        fields.insert(
            event_keys::EVASION_TARGET.to_string(),
            json!("euid_control"),
        );
        fields.insert(
            event_keys::EVASION_ACTION.to_string(),
            json!("seteuid_to_root"),
        );
        vec![
            "macos".to_string(),
            "defense_evasion".to_string(), // CANONICAL TYPE at tags[1]
            "priv_escalation".to_string(),
            "seteuid".to_string(),
            "bsm".to_string(),
            "high_value".to_string(),
        ]
    } else {
        // Base signal - not canonical
        vec![
            "macos".to_string(),
            "priv_base".to_string(),
            "priv_escalation".to_string(),
            "seteuid".to_string(),
            "bsm".to_string(),
        ]
    };

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, target_euid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_SETEGID - set effective group ID
pub fn handle_setegid(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    pid: u32,
    uid: u32,
    euid: u32,
    original_egid: u32,
    target_egid: u32,
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert("original_egid".to_string(), json!(original_egid));
    fields.insert("target_egid".to_string(), json!(target_egid));
    fields.insert("operation".to_string(), json!("setegid"));
    fields.insert("success".to_string(), json!(success));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    let to_privileged = PRIVILEGED_GIDS.contains(&target_egid);
    let from_unprivileged = !PRIVILEGED_GIDS.contains(&original_egid);
    if to_privileged {
        fields.insert("to_privileged_group".to_string(), json!(true));
    }

    // If escalating to wheel (egid 0) from unprivileged, emit as defense_evasion
    let tags = if target_egid == 0 && from_unprivileged {
        fields.insert(
            event_keys::EVASION_TARGET.to_string(),
            json!("egid_control"),
        );
        fields.insert(
            event_keys::EVASION_ACTION.to_string(),
            json!("setegid_to_wheel"),
        );
        vec![
            "macos".to_string(),
            "defense_evasion".to_string(),
            "priv_escalation".to_string(),
            "setegid".to_string(),
            "bsm".to_string(),
        ]
    } else {
        vec![
            "macos".to_string(),
            "priv_base".to_string(),
            "priv_escalation".to_string(),
            "setegid".to_string(),
            "bsm".to_string(),
        ]
    };

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_SETGROUPS - set supplementary group IDs
pub fn handle_setgroups(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    pid: u32,
    uid: u32,
    euid: u32,
    groups: &[u32],
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert("groups".to_string(), json!(groups));
    fields.insert("group_count".to_string(), json!(groups.len()));
    fields.insert("operation".to_string(), json!("setgroups"));
    fields.insert("success".to_string(), json!(success));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    // Check if gaining privileged groups
    let privileged_gained: Vec<u32> = groups
        .iter()
        .filter(|g| PRIVILEGED_GIDS.contains(g))
        .cloned()
        .collect();

    if !privileged_gained.is_empty() {
        fields.insert(
            "privileged_groups_gained".to_string(),
            json!(privileged_gained),
        );
    }

    let has_wheel = groups.contains(&0);
    let has_admin = groups.contains(&80);

    if has_wheel {
        fields.insert("has_wheel".to_string(), json!(true));
    }
    if has_admin {
        fields.insert("has_admin".to_string(), json!(true));
    }

    // If gaining wheel group, emit as defense_evasion
    let tags = if has_wheel {
        fields.insert(
            event_keys::EVASION_TARGET.to_string(),
            json!("groups_control"),
        );
        fields.insert(
            event_keys::EVASION_ACTION.to_string(),
            json!("setgroups_with_wheel"),
        );
        vec![
            "macos".to_string(),
            "defense_evasion".to_string(),
            "priv_escalation".to_string(),
            "setgroups".to_string(),
            "bsm".to_string(),
        ]
    } else {
        vec![
            "macos".to_string(),
            "priv_base".to_string(),
            "priv_escalation".to_string(),
            "setgroups".to_string(),
            "bsm".to_string(),
        ]
    };

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_SETREUID - set real and effective user IDs
pub fn handle_setreuid(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    pid: u32,
    original_uid: u32,
    original_euid: u32,
    target_ruid: u32,
    target_euid: u32,
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert("original_uid".to_string(), json!(original_uid));
    fields.insert("original_euid".to_string(), json!(original_euid));
    fields.insert("target_ruid".to_string(), json!(target_ruid));
    fields.insert("target_euid".to_string(), json!(target_euid));
    fields.insert("operation".to_string(), json!("setreuid"));
    fields.insert("success".to_string(), json!(success));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    // Detect privilege escalation patterns
    let to_root = target_ruid == 0 || target_euid == 0;
    let from_unprivileged = original_uid != 0 && original_euid != 0;

    if to_root {
        fields.insert("to_root".to_string(), json!(true));
    }
    if from_unprivileged && to_root {
        fields.insert("priv_escalation".to_string(), json!(true));
    }

    // Detect setreuid(-1, 0) pattern (drop privileges then re-escalate)
    let reescalation = original_euid != 0 && target_euid == 0;
    if reescalation {
        fields.insert("reescalation".to_string(), json!(true));
    }

    // If escalating to root from unprivileged, emit as defense_evasion
    let tags = if to_root && from_unprivileged {
        fields.insert(event_keys::EVASION_TARGET.to_string(), json!("uid_control"));
        fields.insert(
            event_keys::EVASION_ACTION.to_string(),
            json!("setreuid_to_root"),
        );
        vec![
            "macos".to_string(),
            "defense_evasion".to_string(),
            "priv_escalation".to_string(),
            "setreuid".to_string(),
            "bsm".to_string(),
            "high_value".to_string(),
        ]
    } else {
        vec![
            "macos".to_string(),
            "priv_base".to_string(),
            "priv_escalation".to_string(),
            "setreuid".to_string(),
            "bsm".to_string(),
        ]
    };

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, target_euid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_SETREGID - set real and effective group IDs
pub fn handle_setregid(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    pid: u32,
    uid: u32,
    euid: u32,
    original_gid: u32,
    original_egid: u32,
    target_rgid: u32,
    target_egid: u32,
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert("original_gid".to_string(), json!(original_gid));
    fields.insert("original_egid".to_string(), json!(original_egid));
    fields.insert("target_rgid".to_string(), json!(target_rgid));
    fields.insert("target_egid".to_string(), json!(target_egid));
    fields.insert("operation".to_string(), json!("setregid"));
    fields.insert("success".to_string(), json!(success));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    let to_wheel = target_rgid == 0 || target_egid == 0;
    let from_unprivileged = original_gid != 0 && original_egid != 0;
    if to_wheel {
        fields.insert("to_wheel".to_string(), json!(true));
    }

    // If escalating to wheel from unprivileged, emit as defense_evasion
    let tags = if to_wheel && from_unprivileged {
        fields.insert(event_keys::EVASION_TARGET.to_string(), json!("gid_control"));
        fields.insert(
            event_keys::EVASION_ACTION.to_string(),
            json!("setregid_to_wheel"),
        );
        vec![
            "macos".to_string(),
            "defense_evasion".to_string(),
            "priv_escalation".to_string(),
            "setregid".to_string(),
            "bsm".to_string(),
        ]
    } else {
        vec![
            "macos".to_string(),
            "priv_base".to_string(),
            "priv_escalation".to_string(),
            "setregid".to_string(),
            "bsm".to_string(),
        ]
    };

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Generic dispatcher for privilege escalation AUE codes
pub fn handle_priv_escalation_event(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    aue_code: i32,
    pid: u32,
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    target_value: u32,          // target UID/GID depending on AUE code
    target_value2: Option<u32>, // second target for setreuid/setregid
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    match aue_code {
        aue::AUE_SETUID => handle_setuid(
            host,
            stream_id,
            segment_id,
            record_index,
            pid,
            uid,
            euid,
            target_value,
            exe_path,
            success,
            ts_millis,
        ),
        aue::AUE_SETGID => handle_setgid(
            host,
            stream_id,
            segment_id,
            record_index,
            pid,
            uid,
            euid,
            gid,
            target_value,
            exe_path,
            success,
            ts_millis,
        ),
        aue::AUE_SETEUID => handle_seteuid(
            host,
            stream_id,
            segment_id,
            record_index,
            pid,
            uid,
            euid,
            target_value,
            exe_path,
            success,
            ts_millis,
        ),
        aue::AUE_SETEGID => handle_setegid(
            host,
            stream_id,
            segment_id,
            record_index,
            pid,
            uid,
            euid,
            egid,
            target_value,
            exe_path,
            success,
            ts_millis,
        ),
        aue::AUE_SETREUID => {
            if let Some(target_euid) = target_value2 {
                handle_setreuid(
                    host,
                    stream_id,
                    segment_id,
                    record_index,
                    pid,
                    uid,
                    euid,
                    target_value,
                    target_euid,
                    exe_path,
                    success,
                    ts_millis,
                )
            } else {
                None
            }
        }
        aue::AUE_SETREGID => {
            if let Some(target_egid) = target_value2 {
                handle_setregid(
                    host,
                    stream_id,
                    segment_id,
                    record_index,
                    pid,
                    uid,
                    euid,
                    gid,
                    egid,
                    target_value,
                    target_egid,
                    exe_path,
                    success,
                    ts_millis,
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Classify UID transition type
fn classify_uid_transition(original_uid: u32, original_euid: u32, target_uid: u32) -> &'static str {
    if target_uid == 0 && original_uid != 0 && original_euid != 0 {
        "escalation_to_root"
    } else if target_uid == 0 && (original_uid == 0 || original_euid == 0) {
        "maintaining_root"
    } else if target_uid != 0 && (original_uid == 0 || original_euid == 0) {
        "privilege_drop"
    } else {
        "lateral_transition"
    }
}

/// Classify EUID transition type
fn classify_euid_transition(original_euid: u32, target_euid: u32) -> &'static str {
    if target_euid == 0 && original_euid != 0 {
        "escalation_to_root"
    } else if target_euid == 0 && original_euid == 0 {
        "maintaining_root"
    } else if target_euid != 0 && original_euid == 0 {
        "privilege_drop"
    } else {
        "lateral_transition"
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
    fn test_handle_setuid_escalation_to_root() {
        let event = handle_setuid(
            "testhost",
            "stream1",
            "seg1",
            0,
            1234, // pid
            501,  // original uid (normal user)
            501,  // original euid
            0,    // target uid (root)
            Some("/usr/bin/sudo"),
            true,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"priv_escalation".to_string()));
        assert!(e.tags.contains(&"high_value".to_string()));
        assert_eq!(e.fields.get("to_root").unwrap(), true);
        assert_eq!(e.fields.get("priv_escalation").unwrap(), true);
        assert_eq!(
            e.fields.get("escalation_type").unwrap(),
            "escalation_to_root"
        );
    }

    #[test]
    fn test_handle_setuid_privilege_drop() {
        let event = handle_setuid(
            "testhost",
            "stream1",
            "seg1",
            0,
            1234,
            0,     // original uid (root)
            0,     // original euid (root)
            65534, // target uid (nobody)
            Some("/usr/sbin/httpd"),
            true,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("escalation_type").unwrap(), "privilege_drop");
        assert!(e.fields.get("to_root").is_none());
    }

    #[test]
    fn test_handle_setgid_to_wheel() {
        let event = handle_setgid(
            "testhost", "stream1", "seg1", 0, 1234, 501, 501,
            500, // original gid (user's group)
            0,   // target gid (wheel)
            None, true, 1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"wheel".to_string()));
        assert_eq!(e.fields.get("to_privileged_group").unwrap(), true);
        assert_eq!(e.fields.get("group_escalation").unwrap(), true);
    }

    #[test]
    fn test_handle_seteuid_escalation() {
        let event = handle_seteuid(
            "testhost",
            "stream1",
            "seg1",
            0,
            1234,
            501, // uid
            501, // original euid
            0,   // target euid (root)
            Some("/tmp/exploit"),
            true,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"high_value".to_string()));
        assert_eq!(e.fields.get("priv_escalation").unwrap(), true);
    }

    #[test]
    fn test_handle_setgroups_with_privileged() {
        let event = handle_setgroups(
            "testhost",
            "stream1",
            "seg1",
            0,
            1234,
            501,
            501,
            &[0, 20, 80], // wheel, staff, admin
            Some("/usr/bin/login"),
            true,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("has_wheel").unwrap(), true);
        assert_eq!(e.fields.get("has_admin").unwrap(), true);
        assert_eq!(e.fields.get("group_count").unwrap(), 3);
    }

    #[test]
    fn test_handle_setreuid_reescalation() {
        let event = handle_setreuid(
            "testhost",
            "stream1",
            "seg1",
            0,
            1234,
            501, // original uid
            501, // original euid (dropped)
            501, // target ruid (keep)
            0,   // target euid (re-escalate to root)
            Some("/usr/bin/sudo"),
            true,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("reescalation").unwrap(), true);
        assert_eq!(e.fields.get("to_root").unwrap(), true);
    }

    #[test]
    fn test_handle_setregid_to_wheel() {
        let event = handle_setregid(
            "testhost", "stream1", "seg1", 0, 1234, 501, 501, 20, // original gid
            20, // original egid
            0,  // target rgid (wheel)
            0,  // target egid (wheel)
            None, true, 1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("to_wheel").unwrap(), true);
    }

    #[test]
    fn test_classify_uid_transition() {
        assert_eq!(classify_uid_transition(501, 501, 0), "escalation_to_root");
        assert_eq!(classify_uid_transition(0, 0, 0), "maintaining_root");
        assert_eq!(classify_uid_transition(0, 0, 65534), "privilege_drop");
        assert_eq!(classify_uid_transition(501, 501, 502), "lateral_transition");
    }

    #[test]
    fn test_failed_escalation() {
        let event = handle_setuid(
            "testhost",
            "stream1",
            "seg1",
            0,
            1234,
            501,
            501,
            0,
            Some("/tmp/exploit"),
            false, // Failed attempt
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("success").unwrap(), false);
        // Still marks as high_value because it's an attempt
        assert!(e.tags.contains(&"high_value".to_string()));
    }
}
