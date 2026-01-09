// macos/sensors/bsm/bsm_net_connect.rs
// Network connection detection via OpenBSM with EndpointSecurity enhancements
// Uses existing bsm_network.rs handlers, plus optional ES framework for completeness

use crate::sensors::hash_keys;
use edr_core::{event_keys, Event};
use serde_json::json;
use std::collections::BTreeMap;

/// Unified net_connect detection from OpenBSM (primary)
/// Returns events for outbound connections with filtering for private IPs
/// Tags as ["macos", "network_connection", "bsm"]
pub fn detect_net_connect(
    host: &str,
    stream_id: &str,
    segment_id: &str,
    record_index: usize,
    pid: u32,
    uid: u32,
    euid: u32,
    remote_ip: &str,
    remote_port: u16,
    ts_millis: u64,
) -> Option<Event> {
    // Filter out private/link-local connections (reduce noise)
    // Only emit external connections by default
    if is_rfc1918(remote_ip) || is_link_local(remote_ip) {
        return None; // Skip private connections
    }

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(remote_ip));
    fields.insert(event_keys::NET_REMOTE_PORT.to_string(), json!(remote_port));
    fields.insert(event_keys::NET_FAMILY.to_string(), json!("ipv4")); // Simplified: assume v4 for this event type
    fields.insert(event_keys::NET_IS_PRIVATE.to_string(), json!(false));
    fields.insert(event_keys::NET_IS_LINK_LOCAL.to_string(), json!(false));

    Some(Event {
        ts_ms: ts_millis as i64,
        host: host.to_string(),
        tags: vec![
            "macos".to_string(),
            "network_connection".to_string(),
            "bsm".to_string(),
        ],
        proc_key: Some(hash_keys::proc_key(host, pid, stream_id)),
        file_key: None,
        identity_key: Some(hash_keys::identity_key(host, uid, stream_id)),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}

/// Check if IP is RFC 1918 (private)
fn is_rfc1918(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("172.16.")
        || ip.starts_with("172.17.")
        || ip.starts_with("172.18.")
        || ip.starts_with("172.19.")
        || ip.starts_with("172.20.")
        || ip.starts_with("172.21.")
        || ip.starts_with("172.22.")
        || ip.starts_with("172.23.")
        || ip.starts_with("172.24.")
        || ip.starts_with("172.25.")
        || ip.starts_with("172.26.")
        || ip.starts_with("172.27.")
        || ip.starts_with("172.28.")
        || ip.starts_with("172.29.")
        || ip.starts_with("172.30.")
        || ip.starts_with("172.31.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.") // Loopback
}

/// Check if IP is link-local (169.254.x.x)
fn is_link_local(ip: &str) -> bool {
    ip.starts_with("169.254.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_net_connect_uses_canonical_field_keys() {
        // Verify that detect_net_connect emits canonical field keys, not hardcoded strings
        let event = detect_net_connect(
            "test-host",
            "stream1",
            "segment1",
            0,
            1234, // pid
            501,  // uid
            501,  // euid
            "8.8.8.8",
            443,
            1234567890,
        );

        let ev = event.expect("Should emit external IP connection");

        // CRITICAL: Fields must use canonical event_keys constants, not hardcoded strings
        assert!(
            ev.fields.contains_key(event_keys::NET_REMOTE_IP),
            "Event must contain key '{}' (canonical NET_REMOTE_IP constant)",
            event_keys::NET_REMOTE_IP
        );
        assert!(
            ev.fields.contains_key(event_keys::NET_REMOTE_PORT),
            "Event must contain key '{}' (canonical NET_REMOTE_PORT constant)",
            event_keys::NET_REMOTE_PORT
        );

        // Verify values are correct
        assert_eq!(
            ev.fields
                .get(event_keys::NET_REMOTE_IP)
                .and_then(|v| v.as_str()),
            Some("8.8.8.8")
        );
        assert_eq!(
            ev.fields
                .get(event_keys::NET_REMOTE_PORT)
                .and_then(|v| v.as_u64()),
            Some(443)
        );
    }

    #[test]
    fn test_net_connect_filters_private_ips() {
        // Verify RFC1918 IPs are filtered out
        let event = detect_net_connect(
            "test-host",
            "stream1",
            "segment1",
            0,
            1234,
            501,
            501,
            "192.168.1.1", // Private IP
            22,
            1234567890,
        );

        assert!(event.is_none(), "Private IP should not emit event");
    }
}
