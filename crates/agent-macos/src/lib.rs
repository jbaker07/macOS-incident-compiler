// agent-macos lib.rs
// macOS capture agent library - BSM/EndpointSecurity

// Core telemetry types
pub mod telemetry;
pub mod telemetry_types;

// Sensor modules
pub mod capture_macos_rotating;
pub mod mock;
pub mod platform;
pub mod sensors;

// Detection and processing
pub mod macos_ingest;
pub mod macos_stubs;

// Re-export key types
pub use platform::slot_engine;
pub use sensors::bsm;
pub use sensors::es;
pub use sensors::hash_keys;
pub use telemetry::TelemetryRecord;
pub use telemetry_types::TelemetryOutput;
