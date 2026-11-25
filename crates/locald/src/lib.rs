//! edr-locald library.
//!
//! The `edr-locald` binary (src/main.rs) uses three parts of this crate:
//!
//! - `os::macos::fact_extractor` turns capture events into canonical facts
//! - `os::macos::playbooks` loads the YAML playbooks in playbooks/macos
//! - `hypothesis_controller` fills playbook slots with facts and promotes a
//!   hypothesis to an incident when every required slot is filled

pub mod os;

// Slot matcher: playbook slot matching engine
pub mod slot_matcher;
#[cfg(test)]
mod slot_matcher_tests;

// Evidence system with path safety (Ship Hardening)
pub mod evidence;

// Evidence deref convenience functions
pub mod evidence_deref;

// Credibility locks: path safety, namespace isolation, ZIP safety
pub mod safety;

// Hypothesis/Incident detection system (incident compiler)
pub mod hypothesis;

// HypothesisController: Runtime wiring for the incident compiler
pub mod hypothesis_controller;

// Explanation builder for signal explanations
pub mod explanation_builder;

// Integration layer: export incidents + ingest third-party alerts
pub mod integrations;

// Re-export hypothesis controller
pub use hypothesis_controller::{ControllerSnapshot, HypothesisController};

// Re-export slot matcher types
pub use slot_matcher::{
    CapabilityLevel, CapabilityRegistry, PlaybookDef, PlaybookIndex, PlaybookSlot, 
    SlotMatcher, SlotPredicate,
};

// Re-export hypothesis types for incident compiler
pub use hypothesis::{
    // Arbitration and explanation
    ArbitrationEngine,
    ArbitrationResponse,
    // Core types
    CanonicalEvent,
    Claim,
    ClaimCertainty,
    // Visibility (production robustness)
    CollectorHealth,
    CollectorStatus,
    CriticalGap,
    DeterminismChecker,
    EvidencePtr,
    ExplanationBuilder,
    ExplanationResponse,
    Fact,
    FactDomain,
    FactStore,
    FactType,
    // Determinism
    GlobalOrderKey,
    GlobalWatermark,
    HypothesisState,
    HypothesisStatus,
    // Storage
    HypothesisStorage,
    InMemoryStorage,
    Incident,
    IncidentStatus,
    IncidentStore,
    LateArrivalAction,
    // Late arrival (Fix D)
    LateArrivalPolicy,
    RankedHypothesis,
    ScopeKey,
    Slot,
    SlotRequirement,
    SuppressedHypothesis,
    SuppressionReason,
    TimelineEntry,
    TimelineEntryKind,
    WindowVisibility,
};
