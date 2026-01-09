// macos/sensors/bsm/bsm_fs_ops.rs
// Filesystem mount/unmount handlers for OpenBSM

use super::super::hash_keys;
use super::bsm_tokens;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Handle AUE_MOUNT
pub fn handle_mount(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    tokens: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // Parse subject token → pid, uid
    let subject = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::SUBJECT_TOKEN_32)
        .ok()
        .and_then(|mut v| v.pop())
        .and_then(|t| bsm_tokens::parse_subject_token(&t));

    let (pid, uid) = match &subject {
        Some(s) => (s.pid.unwrap_or(0), s.uid.unwrap_or(0)),
        None => (0, 0),
    };

    // Skip if no valid subject
    if pid == 0 {
        return None;
    }

    // Parse path token → mountpoint
    let mountpoint = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::PATH_TOKEN)
        .ok()
        .and_then(|mut v| v.pop())
        .and_then(|t| bsm_tokens::parse_path_token(&t))
        .unwrap_or_else(|| "/unknown".to_string());

    let mut fields = BTreeMap::new();
    fields.insert("mountpoint".to_string(), json!(mountpoint.clone()));
    fields.insert("pid".to_string(), json!(pid));
    fields.insert("uid".to_string(), json!(uid));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.clone(),
        tags: vec!["macos".to_string(), "fs".to_string(), "mount".to_string()],
        proc_key: Some(hash_keys::proc_key(&host, pid, &stream_id)),
        file_key: Some(hash_keys::file_key(&host, &mountpoint, &stream_id)),
        identity_key: Some(hash_keys::identity_key(&host, uid, &stream_id)),
        evidence_ptr: None, // Capture assigns EvidencePtr
        fields,
    })
}

/// Handle AUE_UNMOUNT
pub fn handle_unmount(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    tokens: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // Parse subject token → pid, uid
    let subject = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::SUBJECT_TOKEN_32)
        .ok()
        .and_then(|mut v| v.pop())
        .and_then(|t| bsm_tokens::parse_subject_token(&t));

    let (pid, uid) = match &subject {
        Some(s) => (s.pid.unwrap_or(0), s.uid.unwrap_or(0)),
        None => (0, 0),
    };

    // Skip if no valid subject
    if pid == 0 {
        return None;
    }

    // Parse path token → mountpoint
    let mountpoint = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::PATH_TOKEN)
        .ok()
        .and_then(|mut v| v.pop())
        .and_then(|t| bsm_tokens::parse_path_token(&t))
        .unwrap_or_else(|| "/unknown".to_string());

    let mut fields = BTreeMap::new();
    fields.insert("mountpoint".to_string(), json!(mountpoint.clone()));
    fields.insert("pid".to_string(), json!(pid));
    fields.insert("uid".to_string(), json!(uid));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.clone(),
        tags: vec!["macos".to_string(), "fs".to_string(), "unmount".to_string()],
        proc_key: Some(hash_keys::proc_key(&host, pid, &stream_id)),
        file_key: Some(hash_keys::file_key(&host, &mountpoint, &stream_id)),
        identity_key: Some(hash_keys::identity_key(&host, uid, &stream_id)),
        evidence_ptr: None, // Capture assigns EvidencePtr
        fields,
    })
}

/// Handle AUE_CONNECT
pub fn handle_connect(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    tokens: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // Parse subject token → pid, uid
    let subject = bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::SUBJECT_TOKEN_32)
        .ok()
        .and_then(|mut v| v.pop())
        .and_then(|t| bsm_tokens::parse_subject_token(&t));

    let (pid, uid) = match &subject {
        Some(s) => (s.pid.unwrap_or(0), s.uid.unwrap_or(0)),
        None => (0, 0),
    };

    // Skip if no valid subject
    if pid == 0 {
        return None;
    }

    // Parse socket token → IP, port
    let (remote_ip, remote_port) =
        bsm_tokens::scan_tokens(&tokens, bsm_tokens::token_type::SOCKADDR_IN_TOKEN)
            .ok()
            .and_then(|mut v| v.pop())
            .and_then(|t| bsm_tokens::parse_sockaddr_ipv4(&t))
            .unwrap_or(("0.0.0.0".to_string(), 0));

    let mut fields = BTreeMap::new();
    fields.insert("pid".to_string(), json!(pid));
    fields.insert("uid".to_string(), json!(uid));
    fields.insert("remote_ip".to_string(), json!(remote_ip));
    fields.insert("remote_port".to_string(), json!(remote_port));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.clone(),
        tags: vec![
            "macos".to_string(),
            "network".to_string(),
            "connect".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(&host, pid, &stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(&host, uid, &stream_id)),
        evidence_ptr: None, // Capture assigns EvidencePtr
        fields,
    })
}
