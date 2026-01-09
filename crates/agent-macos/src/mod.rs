// macos/mod.rs
// macOS sensor module
// Emits core::Event from BSM/Endpoint Security sources

pub mod capture_macos_rotating;
pub mod sensors;

pub use sensors::*;
