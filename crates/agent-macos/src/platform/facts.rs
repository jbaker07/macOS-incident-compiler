
/// Core fact types from OpenBSM
#[derive(Clone, Debug, PartialEq)]
pub enum FactType {
    /// Process execution
    ProcExec { exe_path: String, cmdline: String },
    /// File write operation
    FileWrite { path: String, size: usize },
    /// Network connection
    NetConnect { dest_ip: String, dest_port: u16 },
    /// Environment variable set
    EnvVar { key: String, value: String },
    /// Keychain access
    KeychainAccess { keychain_path: String },
}

/// Primary fact from OpenBSM segment
#[derive(Clone, Debug)]
pub struct Fact {
    /// Unique segment identifier
    pub segment_id: String,
    /// Fact ID within segment
    pub fact_id: String,
    /// Timestamp (unix seconds)
    pub ts: i64,
    /// Hostname
    pub host: String,
    /// Username (if applicable)
    pub user: Option<String>,
    /// User ID
    pub uid: Option<u32>,
    /// Group ID
    pub gid: Option<u32>,
    /// Fact type with details
    pub fact_type: FactType,
}

impl Fact {
    /// Get the path from fact if applicable
    pub fn get_fact_path(&self) -> Option<String> {
        match &self.fact_type {
            FactType::ProcExec { exe_path, .. } => Some(exe_path.clone()),
            FactType::FileWrite { path, .. } => Some(path.clone()),
            FactType::KeychainAccess { keychain_path } => Some(keychain_path.clone()),
            _ => None,
        }
    }

    /// Get the executable path if this is a ProcExec
    pub fn get_exe_path(&self) -> Option<&str> {
        match &self.fact_type {
            FactType::ProcExec { exe_path, .. } => Some(exe_path),
            _ => None,
        }
    }

    /// Get command line if this is a ProcExec
    pub fn get_cmdline(&self) -> Option<&str> {
        match &self.fact_type {
            FactType::ProcExec { cmdline, .. } => Some(cmdline),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fact_creation() {
        let fact = Fact {
            segment_id: "seg-001".to_string(),
            fact_id: "fact-001".to_string(),
            ts: 1234567890,
            host: "test-mac".to_string(),
            user: Some("user".to_string()),
            uid: Some(501),
            gid: Some(20),
            fact_type: FactType::ProcExec {
                exe_path: "/usr/bin/test".to_string(),
                cmdline: "test".to_string(),
            },
        };

        assert_eq!(fact.segment_id, "seg-001");
        assert_eq!(fact.get_exe_path(), Some("/usr/bin/test"));
    }

    #[test]
    fn test_fact_path_extraction() {
        let exec_fact = Fact {
            segment_id: "seg-001".to_string(),
            fact_id: "fact-001".to_string(),
            ts: 1234567890,
            host: "test".to_string(),
            user: None,
            uid: None,
            gid: None,
            fact_type: FactType::ProcExec {
                exe_path: "/tmp/test".to_string(),
                cmdline: "test".to_string(),
            },
        };

        assert_eq!(exec_fact.get_fact_path(), Some("/tmp/test".to_string()));
    }
}
