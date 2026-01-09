// macos/sensors/es/extract.rs
// ES event → Fact extraction logic
// Parses Endpoint Security framework events and emits canonical Facts
//
// IMPORTANT: This module is a STUB. ES parsing is not implemented.
// Use BSM pipeline (platform/bsm_parser.rs) as the primary macOS telemetry source.

use crate::platform::facts::Fact;
use crate::telemetry::TelemetryRecord;
use super::{should_emit_es_facts, es_capability_status};

/// Extract Facts from an ES framework event
/// Returns all Facts found in this event (typically 1 per event)
///
/// NOTE: Currently returns empty Vec because ES parsing is not implemented.
/// This is intentional - we don't want stub data polluting the fact pipeline.
/// Use BSM pipeline for macOS telemetry until ES parsing is implemented.
pub fn extract_facts_from_es_event(record: &TelemetryRecord) -> Vec<Fact> {
    // CAPABILITY GATE: Don't emit facts if ES is not properly implemented
    if !should_emit_es_facts() {
        // Log once per session that ES facts are being skipped
        static LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!(
                "[es_extract] ES capability status: {:?} - skipping ES fact extraction. Use BSM pipeline.",
                es_capability_status()
            );
        }
        return Vec::new();
    }

    let facts = Vec::new();

    // TODO: Implement ES event parsing when ES framework bindings are available
    // Pattern:
    // 1. Parse record.data (ES binary format)
    // 2. Identify event type (ES_EVENT_TYPE_EXEC, ES_EVENT_TYPE_OPEN, etc.)
    // 3. Extract relevant fields from es_message_t structure
    // 4. Construct EvidencePtr from segment_id, record_index, ts
    // 5. Emit corresponding Fact

    facts
}
