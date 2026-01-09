// macos/sensors/bsm/mod.rs
// BSM (OpenBSM) audit log extractor
// Emits canonical core::Event from OpenBSM audit records

pub mod bsm_archive_tool_exec;
pub mod bsm_auth_event;
pub mod bsm_composite_detectors;
pub mod bsm_cred_access;
pub mod bsm_defense_evasion;
pub mod bsm_discovery_exec;
pub mod bsm_exec;
pub mod bsm_file_ops;
pub mod bsm_fs_ops;
pub mod bsm_helpers;
pub mod bsm_net_connect;
pub mod bsm_network;
pub mod bsm_persistence_change;
pub mod bsm_priv_escalation;
pub mod bsm_process_injection;
pub mod bsm_reader;
pub mod bsm_script_exec;
pub mod bsm_staging_write;
pub mod bsm_tokens;

pub use bsm_reader::BSMReader;

/// Extract facts from BSM record using BSMReader
/// Takes raw audit record tokens and emits canonical Events
pub fn extract_facts_from_record(
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    record_data: Vec<u8>,
    ts_millis: u64,
) -> Vec<edr_core::Event> {
    // TODO: Parse BSM record header to get AUE code
    // TODO: Parse tokens from record_data
    // TODO: Route to dispatcher based on AUE code
    // TODO: Return Vec<Event>
    vec![]
}
