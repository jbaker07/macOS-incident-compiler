// macos/sensors/es/identity.rs
// Unified process identity extraction from ES events

use crate::sensors::hash_keys;

/// Shared process identity information extracted from ES events
/// Used as key for process-level correlation across all ES event types
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProcessIdentity {
    /// Host identifier
    pub host: String,
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Effective user ID
    pub euid: u32,
    /// Effective group ID
    pub egid: u32,
    /// Executable path
    pub exe_path: String,
    /// Command line arguments
    pub args: Vec<String>,
    /// Current working directory
    pub cwd: String,
    /// Signing identifier (codesign -d output)
    pub signing_id: Option<String>,
    /// Team ID (from code signing)
    pub team_id: Option<String>,
    /// Code Directory hash (sha256 of __LINKEDIT)
    pub cdhash: Option<String>,
    /// Whether this is a platform binary (Apple-signed)
    pub is_platform_binary: bool,
    /// Session ID
    pub sid: u32,
    /// Timestamp when process started (unix millis)
    pub start_ts: u64,
}

impl ProcessIdentity {
    /// Generate deterministic process key using hash_keys
    /// Format: "proc_{16hex_chars}"
    pub fn proc_key(&self, stream_id: &str) -> String {
        hash_keys::proc_key(&self.host, self.pid, stream_id)
    }

    /// Generate deterministic identity key using hash_keys
    /// Format: "id_{16hex_chars}"
    pub fn identity_key(&self, stream_id: &str) -> String {
        hash_keys::identity_key(&self.host, self.uid, stream_id)
    }
}

/// Extract process identity from ES process_t structure
/// Called for every ES event to enrich with process context
pub fn extract_process_identity(
    host: String,
    es_event_data: &[u8],
    stream_id: String,
    start_ts: u64,
) -> Option<ProcessIdentity> {
    // TODO: Parse ES process_t structure
    // Structure layout (from EndpointSecurity headers):
    // - audit_token_t
    // - pid (u32)
    // - ppid (u32)
    // - original_ppid (u32)
    // - uid (uid_t = u32)
    // - gid (gid_t = u32)
    // - ruid (uid_t)
    // - rgid (gid_t)
    // - euid (uid_t)
    // - egid (gid_t)
    // - refcount (u32)
    // - uuid[16]
    // - signing_id (es_string_t)
    // - team_id (es_string_t)
    // - cdhash[20]
    // - is_platform_binary (bool)
    // - executable (es_file_t)
    // - session_id (u32)

    Some(ProcessIdentity {
        host,
        pid: 0,                    // TODO: parse from es_event_data
        ppid: 0,                   // TODO
        uid: 0,                    // TODO
        gid: 0,                    // TODO
        euid: 0,                   // TODO
        egid: 0,                   // TODO
        exe_path: String::new(),   // TODO
        args: Vec::new(),          // TODO
        cwd: String::new(),        // TODO
        signing_id: None,          // TODO
        team_id: None,             // TODO
        cdhash: None,              // TODO
        is_platform_binary: false, // TODO
        sid: 0,                    // TODO
        start_ts,
    })
}

/// Build tags for a process based on identity characteristics
pub fn identity_tags(identity: &ProcessIdentity) -> Vec<String> {
    let mut tags = Vec::new();

    tags.push("macos".to_string());
    tags.push("process".to_string());

    if identity.is_platform_binary {
        tags.push("platform_binary".to_string());
    } else if identity.signing_id.is_some() {
        tags.push("signed".to_string());
    } else {
        tags.push("unsigned".to_string());
    }

    if identity.uid == 0 {
        tags.push("root".to_string());
    } else if identity.euid == 0 {
        tags.push("setuid".to_string());
    }

    tags
}
