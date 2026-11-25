//! OpenBSM audit record decoding.
//!
//! - `aue`: audit event numbers from `<bsm/audit_kevents.h>`
//! - `record`: record framing and token parsing from `<bsm/audit_record.h>`
//! - `bsm_reader`: turns a decoded record into an `edr_core::Event`

pub mod aue;
pub mod bsm_reader;
pub mod record;

pub use bsm_reader::{classify, Normalizer};
pub use record::{parse_record, BsmRecord, ParseError, RecordSplitter};
