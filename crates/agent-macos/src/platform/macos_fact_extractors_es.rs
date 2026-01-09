//! Endpoint Security framework fact extractor (macOS)
//! Parses ES-derived records and emits same Fact enum as BSM for unified processing

use super::evidence::EvidencePtr;
use super::macos_fact_extractors::Fact;
use serde_json::Value;

pub fn extract_facts_from_es_record(
    record: &Value,
    segment_id: String,
    record_index: usize,
    ts: u64,
) -> Vec<Fact> {
    let mut facts = Vec::new();

    let event_type = record
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let uid = record.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let pid = record.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as u32;

    let evidence = EvidencePtr {
        segment_id: segment_id.clone(),
        record_index,
        ts,
        event_type: format!("es_{}", event_type),
    };

    match event_type {
        "file_open" => {
            if let Some(path) = record.get("path").and_then(|v| v.as_str()) {
                let flags = record
                    .get("flags")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                facts.push(Fact::FileOpen {
                    path: path.to_string(),
                    flags,
                    uid,
                    pid,
                    evidence: evidence.clone(),
                });
            }
        }
        "file_read" => {
            if let Some(path) = record.get("path").and_then(|v| v.as_str()) {
                facts.push(Fact::FileRead {
                    path: path.to_string(),
                    uid,
                    pid,
                    evidence: evidence.clone(),
                });
            }
        }
        "file_setattr" => {
            if let Some(path) = record.get("path").and_then(|v| v.as_str()) {
                let attr_type = record
                    .get("attr_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                facts.push(Fact::FileSetAttr {
                    path: path.to_string(),
                    attr_type,
                    uid,
                    pid,
                    evidence: evidence.clone(),
                });
            }
        }
        "file_truncate" => {
            if let Some(path) = record.get("path").and_then(|v| v.as_str()) {
                let new_size = record.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                facts.push(Fact::FileTruncate {
                    path: path.to_string(),
                    new_size,
                    uid,
                    pid,
                    evidence: evidence.clone(),
                });
            }
        }
        "mmap" => {
            let address = record.get("address").and_then(|v| v.as_u64()).unwrap_or(0);
            let size = record.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let flags = record
                .get("flags")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let file_path = record
                .get("file_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            facts.push(Fact::MmapEvent {
                address,
                size,
                flags,
                file_path,
                uid,
                pid,
                evidence: evidence.clone(),
            });
        }
        "mount" => {
            if let Some(mount_point) = record.get("mount_point").and_then(|v| v.as_str()) {
                let fstype = record
                    .get("fstype")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let operation = record
                    .get("operation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("mount")
                    .to_string();
                facts.push(Fact::MountOp {
                    mount_point: mount_point.to_string(),
                    fstype,
                    operation,
                    uid,
                    evidence: evidence.clone(),
                });
            }
        }
        _ => {}
    }

    facts
}
