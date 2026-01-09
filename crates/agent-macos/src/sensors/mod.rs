/// macOS sensor modules
///
/// Contains sensor extraction implementations that convert platform events to canonical Events:
/// - bsm/: OpenBSM audit log → Events
/// - es/: Endpoint Security events → Events
pub mod bsm;
pub mod es;
pub mod hash_keys;

#[cfg(test)]
mod wiring_tests;
