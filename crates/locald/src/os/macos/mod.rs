//! macOS-specific signal detection

pub mod signal_engine;
pub mod playbooks;
pub mod fact_extractor;

pub use signal_engine::MacOSSignalEngine;
pub use playbooks::macos_playbooks;
pub use fact_extractor::extract_facts;
