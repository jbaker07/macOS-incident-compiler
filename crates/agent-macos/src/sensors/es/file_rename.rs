// macos/sensors/es/file_rename.rs
// ES_EVENT_TYPE_RENAME → file rename events

use edr_core::{Event, EvidencePtr};
use serde_json::json;
use std::collections::BTreeMap;

pub fn handle_rename(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // TODO: Parse ES rename_event_t
    // Extract: old_path, new_path, pid, uid
    let mut fields = BTreeMap::new();
    fields.insert("host".to_string(), json!(host.clone()));
    fields.insert("event".to_string(), json!("rename"));

    Some(Event {
        ts_ms: ts_millis as i64,
        host,
        tags: vec![
            "macos".to_string(),
            "file".to_string(),
            "rename".to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: Some(EvidencePtr {
            stream_id,
            segment_id: segment_id.parse::<u64>().unwrap_or(0),
            record_index: record_index as u32,
        }),
        fields,
    })
}
