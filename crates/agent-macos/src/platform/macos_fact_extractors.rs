use super::evidence::EvidencePtr;
use crate::telemetry::TelemetryRecord;
use serde::{Deserialize, Serialize};

/// macOS sensor capability model
#[derive(Clone, Debug, PartialEq)]
pub enum MacOSSensorMode {
    BSM,
    ES,
    None,
}

/// Sensor capabilities: which fact types can be extracted
#[derive(Clone, Debug)]
pub struct SensorCapabilities {
    pub mode: MacOSSensorMode,
    pub has_proc_exec: bool,
    pub has_file_ops: bool,
    pub has_mmap: bool,
    pub has_mount: bool,
    pub has_netconnect: bool,
}

impl SensorCapabilities {
    pub fn new(mode: MacOSSensorMode) -> Self {
        match mode {
            MacOSSensorMode::BSM => Self {
                mode: MacOSSensorMode::BSM,
                has_proc_exec: true,
                has_file_ops: true,
                has_mmap: false,
                has_mount: false,
                has_netconnect: true,
            },
            MacOSSensorMode::ES => Self {
                mode: MacOSSensorMode::ES,
                has_proc_exec: true,
                has_file_ops: true,
                has_mmap: true,
                has_mount: true,
                has_netconnect: false,
            },
            MacOSSensorMode::None => Self {
                mode: MacOSSensorMode::None,
                has_proc_exec: false,
                has_file_ops: false,
                has_mmap: false,
                has_mount: false,
                has_netconnect: false,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub enum Fact {
    /// Process execution: exe path, cmdline, parent info, uid, cwd
    ProcExec {
        exe: String,
        cmdline: String,
        ppid: u32,
        pid: u32,
        uid: u32,
        cwd: String,
        tags: Vec<String>,
        risk_score: u8,
        evidence: EvidencePtr,
    },
    /// File write event: path, size written, timestamp
    FileWrite {
        path: String,
        size: u64,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// File creation event: path, timestamp
    FileCreate {
        path: String,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// File rename event: old_path → new_path
    FileRename {
        old_path: String,
        new_path: String,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// File deletion event: path, timestamp
    FileUnlink {
        path: String,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// File open event: path, flags (read/write/append)
    FileOpen {
        path: String,
        flags: String,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// File read event: path
    FileRead {
        path: String,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// File metadata change: chmod/chown/settime
    FileSetAttr {
        path: String,
        attr_type: String,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// File truncate event: path, new_size
    FileTruncate {
        path: String,
        new_size: u64,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// Memory mapping event: address, size, flags, file_path
    MmapEvent {
        address: u64,
        size: u64,
        flags: String,
        file_path: Option<String>,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// Mount/unmount event: mount_point, fstype, operation
    MountOp {
        mount_point: String,
        fstype: String,
        operation: String,
        uid: u32,
        evidence: EvidencePtr,
    },
    /// Authentication event: uid, auth_type, success
    AuthEvent {
        uid: u32,
        auth_type: String,
        success: bool,
        evidence: EvidencePtr,
    },
    /// LaunchCtl activity: action (bootstrap/load/unload/start/stop), plist_path
    LaunchCtlActivity {
        action: String,
        plist_path: String,
        uid: u32,
        evidence: EvidencePtr,
    },
    /// Network connection: dest_ip, dest_port, protocol, uid, pid
    NetConnect {
        dest_ip: String,
        dest_port: u16,
        protocol: String,
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
    /// Keychain access: security tool usage detected
    KeychainAccess {
        action: String, // find-generic-password, dump-keychain, etc.
        uid: u32,
        pid: u32,
        evidence: EvidencePtr,
    },
}

impl Fact {
    /// Extract evidence pointer from any fact
    pub fn evidence(&self) -> &EvidencePtr {
        match self {
            Fact::ProcExec { evidence, .. } => evidence,
            Fact::FileWrite { evidence, .. } => evidence,
            Fact::FileCreate { evidence, .. } => evidence,
            Fact::FileRename { evidence, .. } => evidence,
            Fact::FileUnlink { evidence, .. } => evidence,
            Fact::FileOpen { evidence, .. } => evidence,
            Fact::FileRead { evidence, .. } => evidence,
            Fact::FileSetAttr { evidence, .. } => evidence,
            Fact::FileTruncate { evidence, .. } => evidence,
            Fact::MmapEvent { evidence, .. } => evidence,
            Fact::MountOp { evidence, .. } => evidence,
            Fact::AuthEvent { evidence, .. } => evidence,
            Fact::LaunchCtlActivity { evidence, .. } => evidence,
            Fact::NetConnect { evidence, .. } => evidence,
            Fact::KeychainAccess { evidence, .. } => evidence,
        }
    }

    /// Get fact type name
    pub fn fact_type(&self) -> &'static str {
        match self {
            Fact::ProcExec { .. } => "ProcExec",
            Fact::FileWrite { .. } => "FileWrite",
            Fact::FileCreate { .. } => "FileCreate",
            Fact::FileRename { .. } => "FileRename",
            Fact::FileUnlink { .. } => "FileUnlink",
            Fact::FileOpen { .. } => "FileOpen",
            Fact::FileRead { .. } => "FileRead",
            Fact::FileSetAttr { .. } => "FileSetAttr",
            Fact::FileTruncate { .. } => "FileTruncate",
            Fact::MmapEvent { .. } => "MmapEvent",
            Fact::MountOp { .. } => "MountOp",
            Fact::AuthEvent { .. } => "AuthEvent",
            Fact::LaunchCtlActivity { .. } => "LaunchCtlActivity",
            Fact::NetConnect { .. } => "NetConnect",
            Fact::KeychainAccess { .. } => "KeychainAccess",
        }
    }
}

/// Derived signal from correlated facts with evidence pointers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignalFact {
    pub signal_type: String, // "UserWritableExecThenEgress", "SuspiciousKeychainAccess", etc.
    pub severity: String,    // "high", "medium", "low"
    pub host: String,
    pub user: String,
    pub exe: Option<String>,
    pub entity_key: String,
    pub ts_start: u64,
    pub ts_end: u64,
    pub evidence_ptrs: Vec<EvidencePtr>, // Direct references to Facts that triggered this
    pub metadata: serde_json::Value,     // Additional context
}

impl SignalFact {
    pub fn new(signal_type: &str, severity: &str) -> Self {
        Self {
            signal_type: signal_type.to_string(),
            severity: severity.to_string(),
            host: String::new(),
            user: String::new(),
            exe: None,
            entity_key: String::new(),
            ts_start: 0,
            ts_end: 0,
            evidence_ptrs: Vec::new(),
            metadata: serde_json::json!({}),
        }
    }
}

/// Extract facts from a TelemetryRecord based on binary path and cmdline patterns
pub fn extract_facts_from_record(
    record: &TelemetryRecord,
    segment_id: String,
    record_index: usize,
) -> Vec<Fact> {
    let mut facts = Vec::new();

    // Create base evidence pointer
    let evidence = EvidencePtr {
        segment_id: segment_id.clone(),
        record_index,
        ts: record.timestamp,
        event_type: "process".to_string(),
    };

    // All TelemetryRecords are process exec events (from OpenBSM BSM_EXECVE)
    // Extract ProcExec fact from the record
    if !record.binary_path.is_empty() {
        let exe = record.binary_path.clone();
        let cmdline = record.command_line.clone();
        let cwd = record.cwd.clone();
        let ppid = record.ppid as u32;
        let pid = record.pid as u32;
        let uid = record.uid;

        // Compute risk_score and tags based on exe, cmdline patterns
        let (risk_score, tags) = compute_proc_risk(&exe, &cmdline, uid);

        facts.push(Fact::ProcExec {
            exe,
            cmdline,
            ppid,
            pid,
            uid,
            cwd,
            tags: tags.iter().map(|s| s.to_string()).collect(),
            risk_score,
            evidence: evidence.clone(),
        });
    }

    facts
}

/// Compute risk score for process execution based on exe/cmdline patterns
fn compute_proc_risk(exe: &str, cmdline: &str, uid: u32) -> (u8, Vec<&'static str>) {
    let mut score = 0u8;
    let mut tags = Vec::new();

    // Root/system execution increases risk
    if uid == 0 {
        score += 20;
        tags.push("root_execution");
    }

    // Suspicious interpreters
    if exe.contains("python") || exe.contains("ruby") || exe.contains("perl") {
        score += 15;
        tags.push("interpreter");

        // Inline script execution even more suspicious
        if cmdline.contains("-c") || cmdline.contains("-e") {
            score += 25;
            tags.push("inline_script");
        }
    }

    // Shell execution
    if exe.contains("bash") || exe.contains("sh") || exe.contains("zsh") {
        score += 10;
        tags.push("shell");

        if cmdline.contains("curl") || cmdline.contains("wget") {
            score += 20;
            tags.push("curl_chain");
        }
    }

    // Suspicious binaries
    if exe.contains("nc") || exe.contains("ncat") || exe.contains("netcat") {
        score += 20;
        tags.push("network_tool");
    }

    if exe.contains("base64") || exe.contains("openssl") {
        score += 15;
        tags.push("encoding_tool");
    }

    // Temporary directory execution
    if exe.starts_with("/tmp") || exe.starts_with("/var/tmp") || exe.starts_with("/dev/shm") {
        score += 25;
        tags.push("tmp_execution");
    }

    // Unusual parent processes (detected by cmdline patterns, would need parent context)
    if cmdline.contains("cron") || cmdline.contains("systemd") {
        score += 20;
        tags.push("suspicious_parent");
    }

    // Cap score at 100
    score = score.min(100);

    (score, tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_proc_risk() {
        let (score, tags) = compute_proc_risk("/usr/bin/python3", "python3 -c 'import os'", 501);
        assert!(score > 0);
        assert!(tags.contains(&"interpreter"));
        assert!(tags.contains(&"inline_script"));
    }

    #[test]
    fn test_proc_exec_fact_evidence() {
        let evidence = EvidencePtr {
            segment_id: "seg123".to_string(),
            record_index: 42,
            ts: 1234567890,
            event_type: "process".to_string(),
        };
        let fact = Fact::ProcExec {
            exe: "/bin/bash".to_string(),
            cmdline: "bash -c test".to_string(),
            ppid: 1,
            pid: 100,
            uid: 501,
            cwd: "/tmp".to_string(),
            tags: vec![],
            risk_score: 30,
            evidence: evidence.clone(),
        };
        assert_eq!(fact.evidence().segment_id, "seg123");
        assert_eq!(fact.fact_type(), "ProcExec");
    }
}
