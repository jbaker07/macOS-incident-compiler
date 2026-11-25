//! macOS detection: fact extraction from capture events and the YAML playbooks.

pub mod fact_extractor;
pub mod playbooks;

pub use fact_extractor::{extract_facts, extract_facts_with_hash};
pub use playbooks::{load_playbooks_from_dir, macos_playbooks, parse_playbook};
