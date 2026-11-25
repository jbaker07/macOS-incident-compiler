//! macOS capture agent.
//!
//! Reads OpenBSM audit records from /dev/auditpipe (live, needs root) or from
//! audit trail files (replay, no root), turns each record into an
//! `edr_core::Event` and writes JSONL segments with an index for edr-locald.

pub mod auditpipe;
pub mod capture_macos_rotating;
pub mod mock;
pub mod sensors;

pub use sensors::bsm;
pub use sensors::hash_keys;
