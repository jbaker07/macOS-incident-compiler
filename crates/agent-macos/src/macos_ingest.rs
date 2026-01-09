//! macOS segment parsing: convert OpenBSM JSON segments to TelemetryRecords
//!
//! This is the bridge between capture_macos_rotating (which writes segments)
//! and the enrichment pipeline (which consumes TelemetryRecords).

use crate::telemetry::TelemetryRecord;

#[derive(Debug, Clone)]
pub struct SegmentData {
    pub host: String,
    pub segment_id: String,
    pub ts: u64,
    pub events: Vec<RawEvent>,
}

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub event_type: String,
    pub data: serde_json::Value,
}

/// Parse a raw OpenBSM JSON segment into normalized TelemetryRecords
pub fn parse_segment(segment_data: &SegmentData) -> Vec<TelemetryRecord> {
    let mut records = Vec::new();

    for (idx, raw_event) in segment_data.events.iter().enumerate() {
        if let Some(record) = parse_raw_event(raw_event, segment_data.ts, idx) {
            records.push(record);
        }
    }

    records
}

/// Parse a single OpenBSM event into a TelemetryRecord
fn parse_raw_event(raw_event: &RawEvent, base_ts: u64, idx: usize) -> Option<TelemetryRecord> {
    let data = &raw_event.data;

    // Extract common fields from OpenBSM event
    let pid = data
        .get("pid")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(0);

    let ppid = data
        .get("ppid")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(0);

    let uid = data
        .get("uid")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    let binary_path = data
        .get("exe")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let command_line = data
        .get("comm")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let cwd = data
        .get("cwd")
        .and_then(|v| v.as_str())
        .unwrap_or("/")
        .to_string();

    let timestamp = base_ts + idx as u64;

    let record = TelemetryRecord {
        timestamp,
        pid,
        ppid,
        uid,
        binary_path,
        command_line,
        cwd,
        env_vars: None,
        tags: vec![raw_event.event_type.clone()],
        risk_score: None,
    };

    Some(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_exec_event() {
        let raw_event = RawEvent {
            event_type: "exec".to_string(),
            data: json!({
                "pid": 1234,
                "ppid": 1000,
                "uid": 501,
                "exe": "/bin/bash",
                "comm": "bash",
                "cwd": "/tmp"
            }),
        };

        let record = parse_raw_event(&raw_event, 1000000, 0).unwrap();
        assert_eq!(record.pid, 1234);
        assert_eq!(record.ppid, 1000);
        assert_eq!(record.uid, 501);
        assert_eq!(record.binary_path, "/bin/bash");
    }

    #[test]
    fn test_parse_segment() {
        let segment = SegmentData {
            host: "test-host".to_string(),
            segment_id: "seg-001".to_string(),
            ts: 1700000000000,
            events: vec![
                RawEvent {
                    event_type: "exec".to_string(),
                    data: json!({"pid": 100, "ppid": 1, "uid": 0, "exe": "/bin/ls"}),
                },
                RawEvent {
                    event_type: "open".to_string(),
                    data: json!({"pid": 100, "ppid": 1, "uid": 0, "exe": "/bin/ls"}),
                },
            ],
        };

        let records = parse_segment(&segment);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].tags, vec!["exec"]);
        assert_eq!(records[1].tags, vec!["open"]);
    }
}
