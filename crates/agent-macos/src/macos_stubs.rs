//! Stub module implementations for macOS Model A
//! These are minimal no-op implementations that allow telemetry.rs to compile.
//! For production, these would call actual detection modules.

use crate::telemetry_types::TelemetryOutput;
use std::sync::{Arc, Mutex};

// ============================================================
// Process Monitor Stubs
// ============================================================

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub exe: String,
    pub command_line: String,
}

pub fn gather_processes() -> Vec<ProcessInfo> {
    // Stub: In production, would gather actual processes from system
    vec![]
}

pub fn scan_processes() -> Vec<TelemetryOutput> {
    // Stub: In production, would scan for suspicious processes
    vec![]
}

// ============================================================
// Auth Monitor Stubs
// ============================================================

pub fn start_auth_monitor() {
    // Stub: In production, would start background auth monitoring
}

pub fn scan_auth_activity() -> Vec<TelemetryOutput> {
    // Stub: In production, would detect suspicious authentication
    vec![]
}

// ============================================================
// Other Monitor Stubs
// ============================================================

pub fn scan_container_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn scan_dll_injection_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn scan_encrypted_payload_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_entropy_exec_monitor() {}
pub fn scan_file_hash_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_file_hash_monitor<T>(_: Arc<Mutex<T>>) {}
pub fn scan_file_tamper_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn scan_geo_ip_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn scan_job_sched_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_job_sched_monitors<T>(_: Arc<Mutex<T>>) {}
pub fn scan_logon_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_logon_tracker<T>(_: Arc<Mutex<T>>) {}
pub fn scan_memory_health() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn scan_mfa_bypass_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_mfa_bypass_monitor() {}
pub fn scan_network_anomalies() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_network_monitor() {}
pub fn log_open_connections() {}
pub fn scan_password_sprays() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn scan_persistence_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_persistence_watch() {}
pub fn scan_privilege_activity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_privilege_monitor() {}
pub fn scan_injection_fallback() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_process_injection_monitor() {}
pub fn scan_signal_integrity() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_integrity_monitor() {}
pub fn scan_script_monitor() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_script_monitor() {}
pub fn scan_ipc_passive() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn scan_usb_state() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn start_usb_monitor() {}
pub fn get_logged_in_users() -> Vec<String> {
    vec![]
}
pub fn scan_user_sessions() -> Vec<TelemetryOutput> {
    vec![]
}
pub fn store_replay_event(_: serde_json::Value) {}
