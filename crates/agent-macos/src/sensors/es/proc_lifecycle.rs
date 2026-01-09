// macos/sensors/es/proc_lifecycle.rs
// ES_EVENT_TYPE_FORK, ES_EVENT_TYPE_EXIT → lifecycle events

use super::identity::{extract_process_identity, identity_tags};
use edr_core::{Event, EvidencePtr};
use serde_json::json;
use std::collections::BTreeMap;

pub fn handle_fork(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // TODO: Parse ES fork_event_t for child process
    let identity =
        extract_process_identity(host.clone(), &event_data, stream_id.clone(), ts_millis)?;

    let mut fields = BTreeMap::new();
    fields.insert("host".to_string(), json!(host.clone()));
    fields.insert("pid".to_string(), json!(identity.pid));
    fields.insert("ppid".to_string(), json!(identity.ppid));
    fields.insert("uid".to_string(), json!(identity.uid));
    fields.insert("event".to_string(), json!("fork"));

    let mut tags = vec![
        "macos".to_string(),
        "process".to_string(),
        "lifecycle".to_string(),
    ];
    tags.extend(identity_tags(&identity));

    Some(Event {
        ts_ms: ts_millis as i64,
        host,
        tags,
        proc_key: Some(identity.proc_key(&stream_id)),
        file_key: None,
        identity_key: Some(identity.identity_key(&stream_id)),
        evidence_ptr: Some(EvidencePtr {
            stream_id,
            segment_id: segment_id.parse::<u64>().unwrap_or(0),
            record_index: record_index as u32,
        }),
        fields,
    })
}

pub fn handle_exit(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // TODO: Parse ES exit_event_t
    let identity =
        extract_process_identity(host.clone(), &event_data, stream_id.clone(), ts_millis)?;

    let mut fields = BTreeMap::new();
    fields.insert("host".to_string(), json!(host.clone()));
    fields.insert("pid".to_string(), json!(identity.pid));
    fields.insert("ppid".to_string(), json!(identity.ppid));
    fields.insert("uid".to_string(), json!(identity.uid));
    fields.insert("event".to_string(), json!("exit"));

    let mut tags = vec![
        "macos".to_string(),
        "process".to_string(),
        "lifecycle".to_string(),
    ];
    tags.extend(identity_tags(&identity));

    Some(Event {
        ts_ms: ts_millis as i64,
        host,
        tags,
        proc_key: Some(identity.proc_key(&stream_id)),
        file_key: None,
        identity_key: Some(identity.identity_key(&stream_id)),
        evidence_ptr: Some(EvidencePtr {
            stream_id,
            segment_id: segment_id.parse::<u64>().unwrap_or(0),
            record_index: record_index as u32,
        }),
        fields,
    })
}
