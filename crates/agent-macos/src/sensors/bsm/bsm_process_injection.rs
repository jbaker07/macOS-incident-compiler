// macos/sensors/bsm/bsm_process_injection.rs
// Detects process injection attempts on macOS
// Triggers on: DYLD_INSERT_LIBRARIES, task_for_pid, mach_inject patterns

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Environment variables used for injection
const INJECTION_ENV_VARS: &[&str] = &[
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
];

/// Tools commonly used for injection
const INJECTION_TOOLS: &[&str] = &[
    "inject",      // generic inject tools
    "osxinj",      // macOS inject
    "mach_inject", // mach inject framework
    "substrate",   // mobile substrate
    "frida",       // dynamic instrumentation
    "cycript",     // runtime manipulation
    "lldb",        // debugger can inject
    "dtrace",      // can attach/trace
];

/// Detect process injection from exec with DYLD_* env vars
pub fn detect_process_injection_from_exec(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    exe_path: &str,
    argv: &[String],
    env_vars: Option<&[String]>,
    pid: u32,
    uid: u32,
    euid: u32,
    target_pid: Option<u32>,
    ts_millis: u64,
) -> Option<Event> {
    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    let mut inject_method: Option<&str> = None;
    let mut detected_target_pid: Option<u32> = target_pid;

    // Check for DYLD_* injection via environment
    if let Some(env) = env_vars {
        let env_strs: Vec<&str> = env
            .iter()
            .take(100) // Bounded
            .map(|s| s.as_str())
            .collect();
        let env_str = env_strs.join(" ");

        for env_var in INJECTION_ENV_VARS {
            if env_str.contains(env_var) {
                inject_method = Some("dyld_insert");
                break;
            }
        }
    }

    // Check for gdb/lldb attaching to process FIRST (before generic injection tools)
    // This ensures we get the more specific "debugger_attach" classification
    if inject_method.is_none() && (exe_base == "lldb" || exe_base == "gdb") {
        let arg_str = argv.join(" ");
        if arg_str.contains("-p") || arg_str.contains("--attach") || arg_str.contains("attach") {
            inject_method = Some("debugger_attach");
            detected_target_pid = extract_target_pid_from_args(argv);
        }
    }

    // Check for injection tool execution
    if inject_method.is_none() {
        for tool in INJECTION_TOOLS {
            if exe_base.contains(tool) {
                inject_method = Some("injection_tool");

                // Try to extract target PID from args
                if detected_target_pid.is_none() {
                    detected_target_pid = extract_target_pid_from_args(argv);
                }
                break;
            }
        }
    }

    // Check for task_for_pid/mach_task patterns in argv
    if inject_method.is_none() {
        let arg_strs: Vec<&str> = argv.iter().take(50).map(|s| s.as_str()).collect();
        let arg_str = arg_strs.join(" ");

        if arg_str.contains("task_for_pid") || arg_str.contains("mach_task") {
            inject_method = Some("task_for_pid");
        } else if arg_str.contains("ptrace") || arg_str.contains("PT_ATTACH") {
            inject_method = Some("ptrace");
        }
    }

    let method = inject_method?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(event_keys::INJECT_METHOD.to_string(), json!(method));

    // Target PID is required, but use 0 if we couldn't extract it
    let target = detected_target_pid.unwrap_or(0);
    fields.insert(event_keys::INJECT_TARGET_PID.to_string(), json!(target));

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "process_injection".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}

/// Detect process injection from task_for_pid syscall
pub fn detect_process_injection_from_task_for_pid(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    caller_pid: u32,
    target_pid: u32,
    caller_exe: &str,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    // Skip if process is accessing itself
    if caller_pid == target_pid {
        return None;
    }

    // Skip legitimate system debuggers accessing themselves
    let exe_base = std::path::Path::new(caller_exe)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Allow system processes that legitimately use task_for_pid
    let legitimate_callers = [
        "activity_monitor",
        "launchd",
        "kernel_task",
        "ReportCrash",
        "spindump",
        "sample",
    ];

    for legit in &legitimate_callers {
        if exe_base.contains(legit) {
            return None;
        }
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(caller_pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(caller_exe));
    fields.insert(event_keys::INJECT_METHOD.to_string(), json!("task_for_pid"));
    fields.insert(event_keys::INJECT_TARGET_PID.to_string(), json!(target_pid));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "process_injection".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, caller_pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Extract target PID from argument list
fn extract_target_pid_from_args(argv: &[String]) -> Option<u32> {
    // Look for -p <pid> or --pid <pid> patterns
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        if arg == "-p" || arg == "--pid" || arg == "--attach" {
            if let Some(pid_str) = iter.next() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Some(pid);
                }
            }
        }
        // Also check for -p123 pattern
        if arg.starts_with("-p") {
            if let Ok(pid) = arg[2..].parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_dyld_insert() {
        let env = vec!["DYLD_INSERT_LIBRARIES=/tmp/evil.dylib".to_string()];
        let event = detect_process_injection_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/some_app",
            &["some_app".to_string()],
            Some(&env),
            1234,
            501,
            501,
            None,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"process_injection".to_string()));
        assert_eq!(e.fields.get("inject_method").unwrap(), "dyld_insert");
    }

    #[test]
    fn test_detect_frida() {
        let event = detect_process_injection_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/local/bin/frida",
            &["frida".to_string(), "-p".to_string(), "1234".to_string()],
            None,
            5678,
            501,
            501,
            None,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("inject_method").unwrap(), "injection_tool");
        assert_eq!(e.fields.get("inject_target_pid").unwrap(), 1234);
    }

    #[test]
    fn test_detect_lldb_attach() {
        let event = detect_process_injection_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/lldb",
            &["lldb".to_string(), "-p".to_string(), "999".to_string()],
            None,
            5678,
            501,
            501,
            None,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("inject_method").unwrap(), "debugger_attach");
        assert_eq!(e.fields.get("inject_target_pid").unwrap(), 999);
    }

    #[test]
    fn test_detect_task_for_pid() {
        let event = detect_process_injection_from_task_for_pid(
            "testhost",
            "stream1",
            "seg1",
            0,
            1234,
            5678,
            "/tmp/evil_app",
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("inject_method").unwrap(), "task_for_pid");
        assert_eq!(e.fields.get("inject_target_pid").unwrap(), 5678);
    }

    #[test]
    fn test_skip_self_access() {
        let event = detect_process_injection_from_task_for_pid(
            "testhost", "stream1", "seg1", 0, 1234, 1234, // same PID
            "/tmp/app", 501, 501, 1000000,
        );
        assert!(event.is_none());
    }

    #[test]
    fn test_skip_legitimate_caller() {
        let event = detect_process_injection_from_task_for_pid(
            "testhost",
            "stream1",
            "seg1",
            0,
            100,
            5678,
            "/usr/bin/activity_monitor",
            0,
            0,
            1000000,
        );
        assert!(event.is_none());
    }

    #[test]
    fn test_extract_pid_from_args() {
        assert_eq!(
            extract_target_pid_from_args(&["-p".to_string(), "1234".to_string()]),
            Some(1234)
        );
        assert_eq!(
            extract_target_pid_from_args(&["--pid".to_string(), "5678".to_string()]),
            Some(5678)
        );
        assert_eq!(
            extract_target_pid_from_args(&["-p999".to_string()]),
            Some(999)
        );
        assert_eq!(extract_target_pid_from_args(&["--help".to_string()]), None);
    }
}
