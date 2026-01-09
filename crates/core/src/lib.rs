pub mod error;
pub mod event;
pub mod event_keys;
pub mod evidence_ptr;
pub mod explain;
pub mod severity;
pub mod signal_result;

#[cfg(test)]
mod event_validation_test;

pub use error::{ErrorCode, ErrorReport};
pub use event::Event;
pub use evidence_ptr::EvidencePtr;
pub use explain::{
    EntityBundle, EvidenceExcerpt, ExplanationBundle, ExplanationCounters,
    FactEntityKeys, MatchedFact, SlotExplanation, SlotStatus,
};
pub use severity::Severity;
pub use signal_result::SignalResult;
