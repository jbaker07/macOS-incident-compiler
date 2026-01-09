//! Evidence Pointers: Immutable references to facts for incident traceability
//!
//! Every incident must be tied to immutable evidence pointers that allow
//! complete reconstruction of detection reasoning.

use serde::{Deserialize, Serialize};

/// Canonical evidence pointer: locates a fact in the telemetry database
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EvidencePtr {
    /// Segment ID where fact originated
    pub segment_id: String,
    /// Record index/line within segment (0-based)
    pub record_index: usize,
    /// Timestamp (unix seconds)
    pub ts: u64,
    /// Event type (e.g., "process_exec", "file_write")
    pub event_type: String,
}

impl EvidencePtr {
    /// Create new evidence pointer
    pub fn new(segment_id: String, record_index: usize, ts: u64, event_type: String) -> Self {
        EvidencePtr {
            segment_id,
            record_index,
            ts,
            event_type,
        }
    }

    /// Generate unique key for deduplication
    pub fn dedup_key(&self) -> String {
        format!("{}:{}:{}", self.segment_id, self.record_index, self.ts)
    }
}

/// Trait: types that carry evidence pointers
pub trait HasEvidence {
    fn evidence(&self) -> &EvidencePtr;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_ptr_creation() {
        let ep = EvidencePtr::new(
            "seg-001".to_string(),
            42,
            1703000000,
            "process_exec".to_string(),
        );
        assert_eq!(ep.segment_id, "seg-001");
        assert_eq!(ep.record_index, 42);
        assert_eq!(ep.ts, 1703000000);
    }

    #[test]
    fn test_evidence_ptr_dedup() {
        let ep1 = EvidencePtr::new("seg-001".to_string(), 42, 1703000000, "exec".to_string());
        let ep2 = EvidencePtr::new("seg-001".to_string(), 42, 1703000000, "exec".to_string());
        assert_eq!(ep1.dedup_key(), ep2.dedup_key());
    }
}
