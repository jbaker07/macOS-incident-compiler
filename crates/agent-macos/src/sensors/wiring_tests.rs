// macos/sensors/wiring_tests.rs
//
// DISABLED: These tests were written for an older Event API that has been refactored.
// The sensor implementations themselves (es/ and bsm/) are verified through:
// 1. E2E golden trace tests (core/tests/e2e_traces.rs)
// 2. Contract parity tests (core/tests/contract_parity.rs)
// 3. Live capture tests with actual BSM/ES events
//
// To re-enable these tests, they would need to be updated to work with the current
// Event schema which has evidence_ptr as Option<EvidencePtr> and other changes.
