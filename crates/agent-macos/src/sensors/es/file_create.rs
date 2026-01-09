// macos/sensors/es/file_create.rs
// ES_EVENT_TYPE_CREATE → file create events

use crate::sensors::hash_keys;
use edr_core::{Event, EvidencePtr};
use serde_json::json;
use std::collections::BTreeMap;

pub fn handle_create(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // TODO: Parse ES create_event_t
    // Extract: path, mode, pid, uid
    let path = String::from("/tmp/placeholder");
    let mut fields = BTreeMap::new();
    fields.insert("host".to_string(), json!(host.clone()));
    fields.insert("path".to_string(), json!(path.clone()));
    fields.insert("event".to_string(), json!("create"));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.clone(),
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "create".to_string(),
        ],
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
