// macos/sensors/es/mounts.rs
// ES_EVENT_TYPE_MOUNT, ES_EVENT_TYPE_UNMOUNT → mount/unmount events

use super::identity::{extract_process_identity, identity_tags};
use crate::sensors::hash_keys;
use edr_core::{Event, EvidencePtr};
use serde_json::json;
use std::collections::BTreeMap;

pub fn handle_mount(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // TODO: Parse ES mount_event_t
    // Extract: mountpoint, device, flags, pid, uid
    let identity =
        extract_process_identity(host.clone(), &event_data, stream_id.clone(), ts_millis)?;
    let mountpoint = String::from("/mnt/placeholder");

    let mut fields = BTreeMap::new();
    fields.insert("host".to_string(), json!(host.clone()));
    fields.insert("mountpoint".to_string(), json!(mountpoint.clone()));
    fields.insert("pid".to_string(), json!(identity.pid));
    fields.insert("uid".to_string(), json!(identity.uid));
    fields.insert("event".to_string(), json!("mount"));

    let mut tags = vec!["macos".to_string(), "fs".to_string(), "mount".to_string()];
    tags.extend(identity_tags(&identity));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.clone(),
        tags,
        proc_key: Some(identity.proc_key(&stream_id)),
        file_key: Some(hash_keys::file_key(&host, &mountpoint, &stream_id)),
        identity_key: Some(identity.identity_key(&stream_id)),
        evidence_ptr: Some(EvidencePtr {
            stream_id,
            segment_id: segment_id.parse::<u64>().unwrap_or(0),
            record_index: record_index as u32,
        }),
        fields,
    })
}

pub fn handle_unmount(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // TODO: Parse ES unmount_event_t
    // Extract: mountpoint, flags, pid, uid
    let identity =
        extract_process_identity(host.clone(), &event_data, stream_id.clone(), ts_millis)?;
    let mountpoint = String::from("/mnt/placeholder");

    let mut fields = BTreeMap::new();
    fields.insert("host".to_string(), json!(host.clone()));
    fields.insert("mountpoint".to_string(), json!(mountpoint.clone()));
    fields.insert("pid".to_string(), json!(identity.pid));
    fields.insert("uid".to_string(), json!(identity.uid));
    fields.insert("event".to_string(), json!("unmount"));

    let mut tags = vec!["macos".to_string(), "fs".to_string(), "unmount".to_string()];
    tags.extend(identity_tags(&identity));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.clone(),
        tags,
        proc_key: Some(identity.proc_key(&stream_id)),
        file_key: Some(hash_keys::file_key(&host, &mountpoint, &stream_id)),
        identity_key: Some(identity.identity_key(&stream_id)),
        evidence_ptr: Some(EvidencePtr {
            stream_id,
            segment_id: segment_id.parse::<u64>().unwrap_or(0),
            record_index: record_index as u32,
        }),
        fields,
    })
}
