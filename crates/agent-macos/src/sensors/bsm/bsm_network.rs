// macos/sensors/bsm/bsm_network.rs
// Network operation handlers for OpenBSM audit records
// Handles: connect, bind, accept, socket operations
// Emits canonical network_connection events with suspicious port detection

use crate::sensors::hash_keys;
use edr_core::event_keys;
use edr_core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// AUE codes for network operations
pub mod aue {
    pub const AUE_SOCKET: i32 = 40; // socket()
    pub const AUE_BIND: i32 = 42; // bind()
    pub const AUE_CONNECT: i32 = 43; // connect()
    pub const AUE_ACCEPT: i32 = 44; // accept()
    pub const AUE_LISTEN: i32 = 45; // listen()
    pub const AUE_SENDTO: i32 = 46; // sendto()
    pub const AUE_RECVFROM: i32 = 47; // recvfrom()
    pub const AUE_SHUTDOWN: i32 = 48; // shutdown()
    pub const AUE_SOCKETPAIR: i32 = 49; // socketpair()
}

/// Suspicious ports commonly used by malware/C2
const SUSPICIOUS_PORTS: &[u16] = &[
    4444,  // Metasploit default
    5555,  // Android ADB / common backdoor
    6666,  // IRC / common backdoor
    6667,  // IRC
    7777,  // Common backdoor
    8080,  // HTTP proxy (can be suspicious if not expected)
    8443,  // HTTPS alt
    9999,  // Common backdoor
    1337,  // Leet port / common backdoor
    31337, // Elite port / Back Orifice
    12345, // NetBus
    27374, // SubSeven
    1234,  // Common backdoor
    5900,  // VNC (suspicious outbound)
    3389,  // RDP (suspicious outbound from macOS)
];

/// High-value external ports (data exfiltration indicators when unusual)
const EXFIL_PORTS: &[u16] = &[
    20,  // FTP data
    21,  // FTP control
    22,  // SSH/SCP/SFTP
    23,  // Telnet
    25,  // SMTP
    53,  // DNS (tunneling)
    69,  // TFTP
    110, // POP3
    143, // IMAP
    443, // HTTPS (common for C2)
    465, // SMTPS
    587, // SMTP submission
    993, // IMAPS
    995, // POP3S
];

/// Internal/private IP ranges
const PRIVATE_RANGES: &[(&str, &str)] = &[
    ("10.", "10.255.255.255"),
    ("172.16.", "172.31.255.255"),
    ("192.168.", "192.168.255.255"),
    ("127.", "127.255.255.255"),
    ("169.254.", "169.254.255.255"), // Link-local
];

/// Handle AUE_CONNECT - outbound connection events
pub fn handle_connect(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    remote_ip: &str,
    remote_port: u16,
    local_ip: Option<&str>,
    local_port: Option<u16>,
    pid: u32,
    uid: u32,
    euid: u32,
    exe_path: Option<&str>,
    ts_millis: u64,
) -> Option<Event> {
    if remote_ip.is_empty() {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(remote_ip));
    fields.insert(event_keys::NET_REMOTE_PORT.to_string(), json!(remote_port));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert("direction".to_string(), json!("outbound"));

    if let Some(lip) = local_ip {
        fields.insert(event_keys::NET_LOCAL_IP.to_string(), json!(lip));
    }
    if let Some(lport) = local_port {
        fields.insert(event_keys::NET_LOCAL_PORT.to_string(), json!(lport));
    }
    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    // Classify connection
    let is_external = !is_private_ip(remote_ip);
    let is_suspicious_port = SUSPICIOUS_PORTS.contains(&remote_port);
    let is_exfil_port = EXFIL_PORTS.contains(&remote_port);

    fields.insert("external".to_string(), json!(is_external));

    if is_suspicious_port {
        fields.insert("suspicious_port".to_string(), json!(true));
    }
    if is_exfil_port && is_external {
        fields.insert("exfil_indicator".to_string(), json!(true));
    }

    // High-value classification
    let mut tags = vec![
        "macos".to_string(),
        "network".to_string(),
        "connect".to_string(),
        "bsm".to_string(),
    ];

    // Add network_connection tag for canonical type
    tags.push("network_connection".to_string());

    if is_external {
        tags.push("external".to_string());
    }
    if is_suspicious_port {
        tags.push("suspicious".to_string());
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_BIND - socket bind events (server/listener setup)
pub fn handle_bind(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    bind_ip: &str,
    bind_port: u16,
    pid: u32,
    uid: u32,
    euid: u32,
    exe_path: Option<&str>,
    ts_millis: u64,
) -> Option<Event> {
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::NET_LOCAL_IP.to_string(), json!(bind_ip));
    fields.insert(event_keys::NET_LOCAL_PORT.to_string(), json!(bind_port));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert("direction".to_string(), json!("listen"));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    // Check for suspicious bind port
    let is_suspicious = SUSPICIOUS_PORTS.contains(&bind_port);
    let is_privileged = bind_port < 1024;
    let is_any_interface = bind_ip == "0.0.0.0" || bind_ip == "::";

    if is_suspicious {
        fields.insert("suspicious_port".to_string(), json!(true));
    }
    if is_privileged {
        fields.insert("privileged_port".to_string(), json!(true));
    }
    if is_any_interface {
        fields.insert("bind_any".to_string(), json!(true));
    }

    let mut tags = vec![
        "macos".to_string(),
        "network".to_string(),
        "bind".to_string(),
        "bsm".to_string(),
    ];

    if is_suspicious {
        tags.push("suspicious".to_string());
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle AUE_ACCEPT - inbound connection acceptance
pub fn handle_accept(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    remote_ip: &str,
    remote_port: u16,
    local_port: u16,
    pid: u32,
    uid: u32,
    euid: u32,
    exe_path: Option<&str>,
    ts_millis: u64,
) -> Option<Event> {
    if remote_ip.is_empty() {
        return None;
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(remote_ip));
    fields.insert(event_keys::NET_REMOTE_PORT.to_string(), json!(remote_port));
    fields.insert(event_keys::NET_LOCAL_PORT.to_string(), json!(local_port));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert("direction".to_string(), json!("inbound"));

    if let Some(exe) = exe_path {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }

    let is_external = !is_private_ip(remote_ip);
    fields.insert("external".to_string(), json!(is_external));

    let mut tags = vec![
        "macos".to_string(),
        "network".to_string(),
        "accept".to_string(),
        "bsm".to_string(),
        "network_connection".to_string(),
    ];

    if is_external {
        tags.push("external".to_string());
    }

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags,
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None,
        fields,
    })
}

/// Handle generic socket event with IP/port from BSM tokens
pub fn handle_socket_event(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    aue_code: i32,
    remote_ip: Option<&str>,
    remote_port: Option<u16>,
    local_ip: Option<&str>,
    local_port: Option<u16>,
    pid: u32,
    uid: u32,
    euid: u32,
    exe_path: Option<&str>,
    ts_millis: u64,
) -> Option<Event> {
    match aue_code {
        aue::AUE_CONNECT => {
            if let (Some(rip), Some(rport)) = (remote_ip, remote_port) {
                return handle_connect(
                    host,
                    stream_id,
                    segment_id,
                    record_index,
                    rip,
                    rport,
                    local_ip,
                    local_port,
                    pid,
                    uid,
                    euid,
                    exe_path,
                    ts_millis,
                );
            }
        }
        aue::AUE_BIND => {
            if let (Some(lip), Some(lport)) = (local_ip, local_port) {
                return handle_bind(
                    host,
                    stream_id,
                    segment_id,
                    record_index,
                    lip,
                    lport,
                    pid,
                    uid,
                    euid,
                    exe_path,
                    ts_millis,
                );
            }
        }
        aue::AUE_ACCEPT => {
            if let (Some(rip), Some(rport), Some(lport)) = (remote_ip, remote_port, local_port) {
                return handle_accept(
                    host,
                    stream_id,
                    segment_id,
                    record_index,
                    rip,
                    rport,
                    lport,
                    pid,
                    uid,
                    euid,
                    exe_path,
                    ts_millis,
                );
            }
        }
        _ => {}
    }
    None
}

/// Check if IP is in private/internal range
fn is_private_ip(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }

    // IPv6 localhost
    if ip == "::1" || ip == "::ffff:127.0.0.1" {
        return true;
    }

    // Check IPv4 private ranges
    for (prefix, _) in PRIVATE_RANGES {
        if ip.starts_with(prefix) {
            return true;
        }
    }

    // IPv6 private ranges
    if ip.starts_with("fc") || ip.starts_with("fd") || ip.starts_with("fe80") {
        return true;
    }

    false
}

/// Get port classification for reporting
pub fn classify_port(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 465 | 587 => "smtp",
        53 => "dns",
        80 => "http",
        110 | 995 => "pop3",
        143 | 993 => "imap",
        443 => "https",
        3306 => "mysql",
        5432 => "postgresql",
        3389 => "rdp",
        5900 => "vnc",
        8080 => "http-proxy",
        p if SUSPICIOUS_PORTS.contains(&p) => "suspicious",
        p if p < 1024 => "privileged",
        _ => "ephemeral",
    }
}

/// Generic dispatcher for network AUE codes
/// Routes to appropriate handler based on AUE code
#[allow(clippy::too_many_arguments)]
pub fn handle_network_event(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    aue_code: i32,
    pid: u32,
    uid: u32,
    euid: u32,
    remote_ip: Option<&str>,
    remote_port: Option<u16>,
    local_ip: Option<&str>,
    local_port: Option<u16>,
    exe_path: Option<&str>,
    success: bool,
    ts_millis: u64,
) -> Option<Event> {
    handle_socket_event(
        host,
        stream_id,
        segment_id,
        record_index,
        aue_code,
        remote_ip,
        remote_port,
        local_ip,
        local_port,
        pid,
        uid,
        euid,
        exe_path,
        ts_millis,
    )
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use edr_core::event_keys;

    #[test]
    fn test_handle_connect_external_suspicious() {
        let event = handle_connect(
            "testhost",
            "stream1",
            "seg1",
            0,
            "203.0.113.50", // External IP
            4444,           // Suspicious port (Metasploit)
            Some("192.168.1.100"),
            Some(54321),
            1234,
            501,
            501,
            Some("/usr/bin/nc"),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"network_connection".to_string()));
        assert!(e.tags.contains(&"external".to_string()));
        assert!(e.tags.contains(&"suspicious".to_string()));
        assert_eq!(e.fields.get("suspicious_port").unwrap(), true);
        assert_eq!(e.fields.get("external").unwrap(), true);
    }

    #[test]
    fn test_handle_connect_internal() {
        let event = handle_connect(
            "testhost",
            "stream1",
            "seg1",
            0,
            "192.168.1.50", // Internal IP
            8080,
            None,
            None,
            1234,
            501,
            501,
            None,
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(!e.tags.contains(&"external".to_string()));
        assert_eq!(e.fields.get("external").unwrap(), false);
    }

    #[test]
    fn test_handle_connect_exfil_indicator() {
        let event = handle_connect(
            "testhost", "stream1", "seg1", 0, "8.8.8.8",
            443, // HTTPS to external = exfil indicator
            None, None, 1234, 501, 501, None, 1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("exfil_indicator").unwrap(), true);
    }

    #[test]
    fn test_handle_bind_suspicious_port() {
        let event = handle_bind(
            "testhost",
            "stream1",
            "seg1",
            0,
            "0.0.0.0",
            4444, // Suspicious
            1234,
            501,
            501,
            Some("/tmp/backdoor"),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"bind".to_string()));
        assert!(e.tags.contains(&"suspicious".to_string()));
        assert_eq!(e.fields.get("suspicious_port").unwrap(), true);
        assert_eq!(e.fields.get("bind_any").unwrap(), true);
    }

    #[test]
    fn test_handle_bind_privileged_port() {
        let event = handle_bind(
            "testhost",
            "stream1",
            "seg1",
            0,
            "127.0.0.1",
            80, // Privileged
            1234,
            0,
            0,
            Some("/usr/sbin/httpd"),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert_eq!(e.fields.get("privileged_port").unwrap(), true);
    }

    #[test]
    fn test_handle_accept_external() {
        let event = handle_accept(
            "testhost",
            "stream1",
            "seg1",
            0,
            "203.0.113.100", // External attacker
            12345,
            22, // SSH
            1234,
            0,
            0,
            Some("/usr/sbin/sshd"),
            1000000,
        );
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.tags.contains(&"accept".to_string()));
        assert!(e.tags.contains(&"external".to_string()));
        assert_eq!(e.fields.get("direction").unwrap(), "inbound");
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("203.0.113.1"));
    }

    #[test]
    fn test_classify_port() {
        assert_eq!(classify_port(22), "ssh");
        assert_eq!(classify_port(443), "https");
        assert_eq!(classify_port(4444), "suspicious");
        assert_eq!(classify_port(80), "http");
        assert_eq!(classify_port(50000), "ephemeral");
    }

    #[test]
    fn test_rejects_empty_ip() {
        assert!(handle_connect("h", "s", "seg", 0, "", 80, None, None, 1, 1, 1, None, 0).is_none());
        assert!(handle_accept("h", "s", "seg", 0, "", 80, 22, 1, 1, 1, None, 0).is_none());
    }
}
