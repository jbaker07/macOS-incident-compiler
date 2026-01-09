// macos/sensors/bsm/bsm_reader.rs
// OpenBSM audit log record reader and dispatcher

use edr_core::Event;

/// BSM record reader: parses OpenBSM binary format and dispatches to handlers
pub struct BSMReader {
    /// Whether reader is initialized
    pub enabled: bool,
}

impl BSMReader {
    /// Create new BSM reader
    pub fn new() -> Self {
        BSMReader { enabled: false }
    }

    /// Initialize BSM reader: open /dev/auditpipe or /var/audit/*
    /// Returns true if successful
    pub fn initialize(&mut self) -> bool {
        // TODO: Open /dev/auditpipe (real-time) or /var/audit (on-demand)
        // Handle permission errors gracefully
        self.enabled = true;
        true
    }

    /// Dispatch BSM event to appropriate handler (public for testing and direct use)
    pub fn read_record(
        &self,
        host: &str,
        stream_id: &str,
        segment_id: &str,
        record_index: usize,
    ) -> Option<Event> {
        // TODO: Read from auditpipe
        // 1. Read BSM header (length + event code)
        // 2. Read token stream
        // 3. Dispatch to handler based on AUE code
        None
    }
}

/// Public dispatcher for BSM events (for testing and direct use)
/// Routes AUE codes to appropriate handler modules
/// Returns Vec<Event> to support multiple derived events from a single AUE code
pub fn dispatch_event(
    aue_code: i32,
    host: String,
    stream_id: String,
    segment_id: String,
    record_index: usize,
    event_data: Vec<u8>,
    ts_millis: u64,
) -> Vec<Event> {
    let mut events = Vec::new();

    match aue_code {
        // Process execution (AUE_EXECVE = 59)
        59 => {
            let mut evts = crate::sensors::bsm::bsm_exec::handle_exec(
                host,
                stream_id,
                segment_id,
                record_index,
                aue_code,
                event_data,
                ts_millis,
            )
            .unwrap_or_else(|_| Vec::new());
            events.append(&mut evts);
        }

        // File operations - route to bsm_file_ops module
        // AUE_OPEN_R(3), AUE_OPEN_W(4), AUE_OPEN_RW(5), AUE_CREAT(300), AUE_UNLINK(7), AUE_CHMOD(17)
        3 | 4 | 5 | 6 | 7 | 17 | 18 | 39 | 40 | 300 | 310 | 311 => {
            // Parse BSM tokens from event_data to extract path, mode, pid, uid
            use crate::sensors::bsm::{bsm_file_ops, bsm_tokens};

            // Extract subject token for pid/uid/euid
            let subject =
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::SUBJECT_TOKEN_32)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_subject_token(&t));

            let (pid, uid, euid) = match &subject {
                Some(s) => (
                    s.pid.unwrap_or(0),
                    s.uid.unwrap_or(0),
                    s.euid.or(s.uid).unwrap_or(0),
                ),
                None => (0, 0, 0),
            };

            // Skip events with invalid pid (validation)
            if pid == 0 {
                return events; // No valid subject token
            }

            // Extract path token
            let path = bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::PATH_TOKEN)
                .ok()
                .and_then(|mut v| v.pop())
                .and_then(|t| bsm_tokens::parse_path_token(&t));

            // Extract second path for rename (if applicable)
            let dest_path = if aue_code == 6 {
                // AUE_RENAME
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::PATH_TOKEN)
                    .ok()
                    .and_then(|v| if v.len() >= 2 { Some(v) } else { None })
                    .and_then(|mut v| {
                        v.pop(); // skip first
                        v.pop().and_then(|t| bsm_tokens::parse_path_token(&t))
                    })
            } else {
                None
            };

            // Extract return token for success/failure
            let success =
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::RETURN_TOKEN)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_return_token(&t))
                    .map(|(err, _ret)| err == 0)
                    .unwrap_or(true);

            // Extract exe path from text token if available
            let exe_path = bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::TEXT_TOKEN)
                .ok()
                .and_then(|mut v| v.pop())
                .and_then(|t| bsm_tokens::parse_text_token(&t));

            if let Some(evt) = bsm_file_ops::handle_file_operation_event(
                &host,
                &stream_id,
                &segment_id,
                record_index,
                aue_code,
                pid,
                uid,
                euid,
                path.as_deref(),
                dest_path.as_deref(),
                None, // mode - not critical for canonical events
                None, // target_uid - for chown, extracted separately if needed
                None, // target_gid - for chown
                exe_path.as_deref(),
                success,
                ts_millis,
            ) {
                events.push(evt);
            }
        }

        // Privilege escalation - route to bsm_priv_escalation module
        // AUE_SETUID(24), AUE_SETGID(25), AUE_SETEUID(126), AUE_SETEGID(127),
        // AUE_SETGROUPS(128), AUE_SETREUID(130), AUE_SETREGID(131)
        24 | 25 | 126 | 127 | 128 | 130 | 131 => {
            // Parse BSM tokens from event_data to extract uid/gid transitions
            use crate::sensors::bsm::{bsm_priv_escalation, bsm_tokens};

            // Extract subject token for pid/uid/euid/gid/egid
            let subject =
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::SUBJECT_TOKEN_32)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_subject_token(&t));

            let (pid, uid, euid, gid, egid) = match &subject {
                Some(s) => (
                    s.pid.unwrap_or(0),
                    s.uid.unwrap_or(0),
                    s.euid.or(s.uid).unwrap_or(0),
                    s.gid.unwrap_or(0),
                    s.egid.or(s.gid).unwrap_or(0),
                ),
                None => (0, 0, 0, 0, 0),
            };

            // Skip events with invalid pid (validation)
            if pid == 0 {
                return events;
            }

            // Extract arg token for target uid/gid value
            let target_value =
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::ARG_TOKEN)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_arg_token(&t))
                    .map(|(_num, val)| val.parse::<u32>().unwrap_or(0))
                    .unwrap_or(0);

            // Extract second arg for setreuid/setregid
            let target_value2 = if aue_code == 130 || aue_code == 131 {
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::ARG_TOKEN)
                    .ok()
                    .and_then(|v| if v.len() >= 2 { Some(v) } else { None })
                    .and_then(|mut v| {
                        v.pop();
                        v.pop().and_then(|t| bsm_tokens::parse_arg_token(&t))
                    })
                    .map(|(_num, val)| val.parse::<u32>().unwrap_or(0))
            } else {
                None
            };

            // Extract return token for success/failure
            let success =
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::RETURN_TOKEN)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_return_token(&t))
                    .map(|(err, _ret)| err == 0)
                    .unwrap_or(true);

            // Extract exe path from text token
            let exe_path = bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::TEXT_TOKEN)
                .ok()
                .and_then(|mut v| v.pop())
                .and_then(|t| bsm_tokens::parse_text_token(&t));

            if let Some(evt) = bsm_priv_escalation::handle_priv_escalation_event(
                &host,
                &stream_id,
                &segment_id,
                record_index,
                aue_code,
                pid,
                uid,
                euid,
                gid,
                egid,
                target_value,
                target_value2,
                exe_path.as_deref(),
                success,
                ts_millis,
            ) {
                events.push(evt);
            }
        }

        // Mount operations
        21 => {
            if let Some(evt) = crate::sensors::bsm::bsm_fs_ops::handle_mount(
                host,
                stream_id,
                segment_id,
                record_index,
                event_data,
                ts_millis,
            ) {
                events.push(evt);
            }
        }
        22 => {
            if let Some(evt) = crate::sensors::bsm::bsm_fs_ops::handle_unmount(
                host,
                stream_id,
                segment_id,
                record_index,
                event_data,
                ts_millis,
            ) {
                events.push(evt);
            }
        }

        // Socket/network - route to bsm_network module
        // AUE_SOCKET(40), AUE_BIND(42), AUE_CONNECT(43), AUE_ACCEPT(44), AUE_LISTEN(45)
        42 | 43 | 44 | 45 => {
            // Parse BSM tokens from event_data to extract network info
            use crate::sensors::bsm::{bsm_network, bsm_tokens};

            // Extract subject token for pid/uid/euid
            let subject =
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::SUBJECT_TOKEN_32)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_subject_token(&t));

            let (pid, uid, euid) = match &subject {
                Some(s) => (
                    s.pid.unwrap_or(0),
                    s.uid.unwrap_or(0),
                    s.euid.or(s.uid).unwrap_or(0),
                ),
                None => (0, 0, 0),
            };

            // Skip events with invalid pid
            if pid == 0 {
                return events;
            }

            // Extract sockaddr token for IP/port (IPv4)
            let (remote_ip, remote_port) =
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::SOCKADDR_IN_TOKEN)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_sockaddr_ipv4(&t))
                    .map(|(ip, port)| (Some(ip), Some(port)))
                    .unwrap_or((None, None));

            // Try IPv6 if no IPv4 found
            let (remote_ip, remote_port) = if remote_ip.is_none() {
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::SOCKADDR_IN6_TOKEN)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_sockaddr_ipv6(&t))
                    .map(|(ip, port)| (Some(ip), Some(port)))
                    .unwrap_or((None, None))
            } else {
                (remote_ip, remote_port)
            };

            // Extract return token for success/failure
            let success =
                bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::RETURN_TOKEN)
                    .ok()
                    .and_then(|mut v| v.pop())
                    .and_then(|t| bsm_tokens::parse_return_token(&t))
                    .map(|(err, _ret)| err == 0)
                    .unwrap_or(true);

            // Extract exe path from text token
            let exe_path = bsm_tokens::scan_tokens(&event_data, bsm_tokens::token_type::TEXT_TOKEN)
                .ok()
                .and_then(|mut v| v.pop())
                .and_then(|t| bsm_tokens::parse_text_token(&t));

            if let Some(evt) = bsm_network::handle_network_event(
                &host,
                &stream_id,
                &segment_id,
                record_index,
                aue_code,
                pid,
                uid,
                euid,
                remote_ip.as_deref(),
                remote_port,
                None, // local_ip - not always available
                None, // local_port - not always available
                exe_path.as_deref(),
                success,
                ts_millis,
            ) {
                events.push(evt);
            }
        }

        _ => {}
    }

    events
}

/// Helper function to derive primitive events from a base event's fields
/// Emits cred_access, discovery, archive, staging, and net_connect events
/// when applicable based on the primary event's content
pub fn derive_primitive_events(base_event: &Event, host: &str, stream_id: &str) -> Vec<Event> {
    let mut derived = Vec::new();

    // Check event tags to determine what primitive detections to run
    if base_event.tag_contains("exec") {
        // Extract fields we need for exec-based detectors
        if let (Some(exe_val), Some(pid_val), Some(uid_val)) = (
            base_event.fields.get("exe"),
            base_event.fields.get("pid"),
            base_event.fields.get("uid"),
        ) {
            if let (Some(exe), Some(pid), Some(uid)) =
                (exe_val.as_str(), pid_val.as_u64(), uid_val.as_u64())
            {
                let pid = pid as u32;
                let uid = uid as u32;
                let euid = base_event
                    .fields
                    .get("euid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
                    .unwrap_or(uid);

                let argv: Vec<String> = base_event
                    .fields
                    .get("argv")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                // Try cred access detection
                if let Some(evt) =
                    crate::sensors::bsm::bsm_cred_access::detect_cred_access_from_exec(
                        host,
                        stream_id,
                        "",
                        0,
                        exe,
                        &argv,
                        pid,
                        uid,
                        euid,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }

                // Try discovery exec detection
                if let Some(evt) = crate::sensors::bsm::bsm_discovery_exec::detect_discovery_exec(
                    host,
                    stream_id,
                    "",
                    0,
                    exe,
                    &argv,
                    pid,
                    uid,
                    euid,
                    base_event.ts_ms as u64,
                ) {
                    derived.push(evt);
                }

                // Try archive tool detection
                if let Some(evt) =
                    crate::sensors::bsm::bsm_archive_tool_exec::detect_archive_tool_exec(
                        host,
                        stream_id,
                        "",
                        0,
                        exe,
                        &argv,
                        pid,
                        uid,
                        euid,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }

                // === NEW DETECTORS ===

                // Try process injection detection from exec
                if let Some(evt) =
                    crate::sensors::bsm::bsm_process_injection::detect_process_injection_from_exec(
                        host,
                        stream_id,
                        "",
                        0,
                        exe,
                        &argv,
                        None,
                        pid,
                        uid,
                        euid,
                        None,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }

                // Try defense evasion detection from exec
                if let Some(evt) =
                    crate::sensors::bsm::bsm_defense_evasion::detect_defense_evasion_from_exec(
                        host,
                        stream_id,
                        "",
                        0,
                        exe,
                        &argv,
                        pid,
                        uid,
                        euid,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }

                // Try auth event detection from exec
                if let Some(evt) = crate::sensors::bsm::bsm_auth_event::detect_auth_event_from_exec(
                    host,
                    stream_id,
                    "",
                    0,
                    exe,
                    &argv,
                    pid,
                    uid,
                    euid,
                    None,
                    base_event.ts_ms as u64,
                ) {
                    derived.push(evt);
                }

                // Try script exec detection
                if let Some(evt) =
                    crate::sensors::bsm::bsm_script_exec::detect_script_exec_from_exec(
                        host,
                        stream_id,
                        "",
                        0,
                        exe,
                        &argv,
                        pid,
                        uid,
                        euid,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }

                // Try LOLBin detection
                if let Some(evt) = crate::sensors::bsm::bsm_script_exec::detect_lolbin_exec(
                    host,
                    stream_id,
                    "",
                    0,
                    exe,
                    &argv,
                    pid,
                    uid,
                    euid,
                    base_event.ts_ms as u64,
                ) {
                    derived.push(evt);
                }

                // Try persistence change from exec (launchctl, crontab, etc.)
                if let Some(evt) =
                    crate::sensors::bsm::bsm_persistence_change::detect_persistence_change_from_exec(
                        host,
                        stream_id,
                        "",
                        0,
                        exe,
                        &argv,
                        pid,
                        uid,
                        euid,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }

                // === HIGH-VALUE COMPOSITE DETECTORS ===

                // Detect code signature bypass pattern (codesign tool + unsigned execution)
                if let Some(evt) = crate::sensors::bsm::bsm_composite_detectors::detect_code_signature_bypass_with_execution(
                    host, stream_id, exe, &argv, pid, uid, euid, base_event.ts_ms as u64
                ) {
                    derived.push(evt);
                }

                // Detect keychain credential access chain (security + ssh context)
                if let Some(evt) =
                    crate::sensors::bsm::bsm_composite_detectors::detect_keychain_to_ssh_chain(
                        host,
                        stream_id,
                        exe,
                        &argv,
                        pid,
                        uid,
                        euid,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }

                // Detect DYLD injection with unsigned binary execution
                let env_vars = base_event
                    .fields
                    .get("env")
                    .and_then(|v| v.as_object())
                    .map(|obj| {
                        let mut map = std::collections::BTreeMap::new();
                        for (k, v) in obj {
                            if let Some(val) = v.as_str() {
                                map.insert(k.clone(), val.to_string());
                            }
                        }
                        map
                    });

                if let Some(evt) = crate::sensors::bsm::bsm_composite_detectors::detect_dyld_injection_with_unsigned_binary(
                    host, stream_id, exe, &argv, env_vars.as_ref(), pid, uid, euid, base_event.ts_ms as u64
                ) {
                    derived.push(evt);
                }
            }
        }
    }

    // Check for file operations to derive staging write events
    if base_event.tag_contains("file")
        && (base_event.tag_contains("write") || base_event.tag_contains("create"))
    {
        if let (Some(path_val), Some(pid_val), Some(uid_val)) = (
            base_event.fields.get("path"),
            base_event.fields.get("pid"),
            base_event.fields.get("uid"),
        ) {
            if let (Some(path), Some(pid), Some(uid)) =
                (path_val.as_str(), pid_val.as_u64(), uid_val.as_u64())
            {
                let pid = pid as u32;
                let uid = uid as u32;
                let euid = base_event
                    .fields
                    .get("euid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
                    .unwrap_or(uid);

                let op = if base_event.tag_contains("write") {
                    "write"
                } else {
                    "create"
                };
                let exe_path = base_event
                    .fields
                    .get("exe")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                if let Some(evt) = crate::sensors::bsm::bsm_staging_write::detect_staging_write(
                    host,
                    stream_id,
                    "",
                    0,
                    path,
                    "",
                    pid,
                    uid,
                    euid,
                    op,
                    base_event.ts_ms as u64,
                ) {
                    derived.push(evt);
                }

                // === NEW FILE-BASED DETECTORS ===

                // Try persistence change detection from file ops
                if let Some(evt) = crate::sensors::bsm::bsm_persistence_change::detect_persistence_change_from_file_op(
                    host, stream_id, "", 0, path, op, pid, uid, euid, exe_path, base_event.ts_ms as u64
                ) {
                    derived.push(evt);
                }

                // Try defense evasion detection from file ops
                if let Some(evt) =
                    crate::sensors::bsm::bsm_defense_evasion::detect_defense_evasion_from_file_op(
                        host,
                        stream_id,
                        "",
                        0,
                        path,
                        op,
                        pid,
                        uid,
                        euid,
                        exe_path,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }

                // === HIGH-VALUE COMPOSITE: Persistence with LaunchAgent + launchctl ===
                let exe_base = std::path::Path::new(exe_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                // Note: argv not available in dispatch_event context; would need BSM exec event augmentation
                if exe_base.contains("launchctl") {
                    if let Some(evt) = crate::sensors::bsm::bsm_composite_detectors::detect_persistence_with_launchctl_invocation(
                        host, stream_id, path, op, pid, uid, exe_path, None, base_event.ts_ms as u64
                    ) {
                        derived.push(evt);
                    }
                }
            }
        }
    }

    // Check for file delete/unlink operations
    if base_event.tag_contains("file")
        && (base_event.tag_contains("unlink") || base_event.tag_contains("delete"))
    {
        if let (Some(path_val), Some(pid_val), Some(uid_val)) = (
            base_event.fields.get("path"),
            base_event.fields.get("pid"),
            base_event.fields.get("uid"),
        ) {
            if let (Some(path), Some(pid), Some(uid)) =
                (path_val.as_str(), pid_val.as_u64(), uid_val.as_u64())
            {
                let pid = pid as u32;
                let uid = uid as u32;
                let euid = base_event
                    .fields
                    .get("euid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
                    .unwrap_or(uid);

                let exe_path = base_event
                    .fields
                    .get("exe")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                // Try persistence change detection from delete
                if let Some(evt) = crate::sensors::bsm::bsm_persistence_change::detect_persistence_change_from_file_op(
                    host, stream_id, "", 0, path, "unlink", pid, uid, euid, exe_path, base_event.ts_ms as u64
                ) {
                    derived.push(evt);
                }

                // Try defense evasion detection from delete (log/history deletion)
                if let Some(evt) =
                    crate::sensors::bsm::bsm_defense_evasion::detect_defense_evasion_from_file_op(
                        host,
                        stream_id,
                        "",
                        0,
                        path,
                        "unlink",
                        pid,
                        uid,
                        euid,
                        exe_path,
                        base_event.ts_ms as u64,
                    )
                {
                    derived.push(evt);
                }
            }
        }
    }

    // Check for network connections to derive net_connect events
    if base_event.tag_contains("network") && base_event.tag_contains("connect") {
        if let (Some(ip_val), Some(port_val), Some(pid_val), Some(uid_val)) = (
            base_event.fields.get("remote_ip"),
            base_event.fields.get("remote_port"),
            base_event.fields.get("pid"),
            base_event.fields.get("uid"),
        ) {
            if let (Some(ip), Some(port), Some(pid), Some(uid)) = (
                ip_val.as_str(),
                port_val.as_u64(),
                pid_val.as_u64(),
                uid_val.as_u64(),
            ) {
                let pid = pid as u32;
                let uid = uid as u32;
                let euid = base_event
                    .fields
                    .get("euid")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
                    .unwrap_or(uid);

                if let Some(evt) = crate::sensors::bsm::bsm_net_connect::detect_net_connect(
                    host,
                    stream_id,
                    "",
                    0,
                    pid,
                    uid,
                    euid,
                    ip,
                    port as u16,
                    base_event.ts_ms as u64,
                ) {
                    derived.push(evt);
                }
            }
        }
    }

    derived
}

impl Default for BSMReader {
    fn default() -> Self {
        Self::new()
    }
}
