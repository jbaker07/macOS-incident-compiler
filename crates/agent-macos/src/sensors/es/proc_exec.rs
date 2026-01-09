// macos/sensors/es/proc_exec.rs
// ES_EVENT_TYPE_EXEC → ProcExec event

use super::identity::{extract_process_identity, identity_tags};
use edr_core::{Event, EvidencePtr};
use serde_json::json;
use std::collections::BTreeMap;

/// Handle ES exec event
pub fn handle_exec(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Option<Event> {
    // TODO: Parse ES exec_event_t
    // - original_ppid (u32)
    // - executable (es_file_t)
    // - arguments (es_string_t array)
    // - return_value (i32)

    let identity =
        extract_process_identity(host.clone(), &event_data, stream_id.clone(), ts_millis)?;

    let mut fields = BTreeMap::new();
    fields.insert("host".to_string(), json!(host.clone()));
    fields.insert("pid".to_string(), json!(identity.pid));
    fields.insert("ppid".to_string(), json!(identity.ppid));
    fields.insert("uid".to_string(), json!(identity.uid));
    fields.insert("exe".to_string(), json!(identity.exe_path.clone()));
    fields.insert("args".to_string(), json!(identity.args.join(" ")));
    fields.insert("cwd".to_string(), json!(identity.cwd.clone()));

    if let Some(sid) = &identity.signing_id {
        fields.insert("signing_id".to_string(), json!(sid));
    }
    if let Some(tid) = &identity.team_id {
        fields.insert("team_id".to_string(), json!(tid));
    }

    let mut tags = vec![
        "macos".to_string(),
        "process".to_string(),
        "exec".to_string(),
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
