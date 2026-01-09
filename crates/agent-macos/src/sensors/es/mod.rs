// macos/sensors/es/mod.rs
// Endpoint Security (ES) event extractor
// Converts ES events to canonical core::Event
//
// CAPABILITY STATUS: UNAVAILABLE (stub implementation)
// The ES parsers in this module are not yet implemented.
// They return placeholder/stub data and should NOT be used in production.
// Use BSM pipeline (platform/bsm_parser.rs) as the primary macOS telemetry source.

pub mod es_client;
pub mod extract;
pub mod file_create;
pub mod file_metadata;
pub mod file_open;
pub mod file_rename;
pub mod file_unlink;
pub mod file_write;
pub mod identity;
pub mod mounts;
pub mod parsers;
pub mod proc_exec;
pub mod proc_lifecycle;

pub use es_client::ESClient;

/// ES capability status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ESCapabilityStatus {
    /// ES framework is available and working
    Available,
    /// ES framework is not implemented (stubs only)
    Unimplemented,
    /// ES framework is not available on this system
    Unavailable,
    /// ES framework is offline/disconnected
    Offline,
}

/// Check ES capability status
/// Returns the current capability status of the ES framework
pub fn es_capability_status() -> ESCapabilityStatus {
    // IMPORTANT: ES parsers are currently stubs and return placeholder data.
    // Until the parsing is implemented, we mark this as Unimplemented.
    // This prevents facts from being emitted from the ES pipeline.
    ESCapabilityStatus::Unimplemented
}

/// Check if ES facts should be emitted
/// Returns false if ES is unimplemented/unavailable, preventing stub data
/// from polluting the fact pipeline
pub fn should_emit_es_facts() -> bool {
    match es_capability_status() {
        ESCapabilityStatus::Available => true,
        ESCapabilityStatus::Unimplemented => false,
        ESCapabilityStatus::Unavailable => false,
        ESCapabilityStatus::Offline => false,
    }
}

/// Get ES capability description for health reporting
pub fn es_capability_description() -> &'static str {
    match es_capability_status() {
        ESCapabilityStatus::Available => "ES framework available and working",
        ESCapabilityStatus::Unimplemented => "ES parsers not implemented (stubs only) - use BSM pipeline",
        ESCapabilityStatus::Unavailable => "ES framework not available on this system",
        ESCapabilityStatus::Offline => "ES framework offline or disconnected",
    }
}
