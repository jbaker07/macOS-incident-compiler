//! Sensor code for the macOS capture agent.
//!
//! - `bsm`: OpenBSM audit records from /dev/auditpipe or a trail file
//! - `hash_keys`: stable process, file and identity keys
pub mod bsm;
pub mod hash_keys;
