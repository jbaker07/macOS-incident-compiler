// macos/sensors/es/file_open.rs
// ES_EVENT_TYPE_OPEN → file open events

use crate::sensors::hash_keys;
use edr_core::{Event, EvidencePtr};
use serde_json::json;
use std::collections::BTreeMap;

pub fn handle_open(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // TODO: Parse ES open_event_t
    // Extract: path, flags, pid, uid
    // Placeholder path extraction
    let path = String::from("/tmp/placeholder");

    let mut fields = BTreeMap::new();
    fields.insert("host".to_string(), json!(host.clone()));
    fields.insert("path".to_string(), json!(path.clone()));
    fields.insert("event".to_string(), json!("open"));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.clone(),
        tags: vec!["macos".to_string(), "file".to_string(), "open".to_string()],
        proc_key: None,
        file_key: Some(hash_keys::file_key(&host, &path, &stream_id)),
        identity_key: None,
        evidence_ptr: Some(EvidencePtr {
            stream_id,
            segment_id: segment_id.parse::<u64>().unwrap_or(0),
            record_index: record_index as u32,
        }),
        fields,
    })
}
