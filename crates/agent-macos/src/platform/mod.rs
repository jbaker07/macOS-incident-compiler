//! macOS Detection System: unified evidence-first incident compiler
//!
//! This is the production threat detection layer for macOS.
//! It implements:
//! - Evidence-first design (all incidents tied to immutable EvidencePtr)
//! - Dual playbooks: slot-based (ground truth) + heuristics (signals)
//! - Deterministic incident compilation with step traces
//! - API handlers for REST exposure

pub mod bsm_parser;
pub mod evidence;
pub mod facts;
pub mod macos_fact_extractors;
pub mod macos_fact_extractors_es;
pub mod slot_engine;

// TODO: Re-enable when all dependencies are ported
// #[cfg(test)]
// mod integration_tests;
// #[cfg(test)]
// mod synthetic_pipeline_tests;

// Re-export key types from existing modules
pub use evidence::{EvidencePtr as PlatformEvidence, HasEvidence};
pub use facts::{Fact, FactType};
pub use slot_engine::{Incident as SlotIncident, PlaybookSpec, Slot, SlotEngine};
