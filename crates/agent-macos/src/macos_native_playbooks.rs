//! macOS-Native Playbook Definitions (Not converted from Linux)
//!
//! These playbooks represent detection strategies specific to macOS threat actors,
//! exploiting platform-specific persistence and execution mechanisms.
//!
//! PLAYBOOK FAMILIES:
//! - Launchd Persistence: Writing to LaunchAgents/LaunchDaemons + launchctl bootstrap
//! - DYLD Injection: Environment variable manipulation for library injection
//! - Keychain Manipulation: security command usage for credential access
//! - LOLBIN Staging: curl|osascript|python chains
//! - Quarantine/First-Seen Unsigned: Code signature evasion + rapid follow-on
//! - Code Signature Bypass: Modifying/removing code signatures before execution

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MacOSNativePlaybook {
    pub id: String,
    pub name: String,
    pub technique_ids: Vec<String>, // MITRE ATT&CK technique IDs
    pub required_slots: Vec<String>,
    pub optional_slots: Vec<String>,
    pub window_sec: u64,
    pub description: String,
}

pub fn get_native_playbooks() -> Vec<MacOSNativePlaybook> {
    vec![
        MacOSNativePlaybook {
            id: "pb_macos_launchd_persistence".to_string(),
            name: "macOS LaunchD Persistence".to_string(),
            technique_ids: vec![
                "T1547.013".to_string(), // Plist Modification
                "T1547.001".to_string(), // Launchd
            ],
            required_slots: vec![
                "plist_write_to_launch_dir".to_string(),
                "launchctl_bootstrap_within_ttl".to_string(),
            ],
            optional_slots: vec![
                "binary_exec_from_launch_path".to_string(),
                "network_connection_post_exec".to_string(),
            ],
            window_sec: 300, // 5 minute window for launchctl bootstrap after plist write
            description: "Writes plist to ~/Library/LaunchAgents or /Library/LaunchDaemons, \
                          followed by launchctl bootstrap within TTL. Indicates persistence setup.".to_string(),
        },
        MacOSNativePlaybook {
            id: "pb_macos_dyld_injection".to_string(),
            name: "macOS DYLD Library Injection".to_string(),
            technique_ids: vec![
                "T1547.006".to_string(), // Dyld Environment Variables
            ],
            required_slots: vec![
                "dyld_env_var_set".to_string(), // DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH, etc.
                "unsigned_or_suspicious_binary_exec".to_string(),
            ],
            optional_slots: vec![
                "network_connection_post_exec".to_string(),
                "keychain_access_post_exec".to_string(),
            ],
            window_sec: 60, // Tight window: env var → exec
            description: "Sets DYLD_* environment variables (DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH) \
                          followed by execution of unsigned or rarely-seen binary. Indicates library injection attack.".to_string(),
        },
        MacOSNativePlaybook {
            id: "pb_macos_keychain_access".to_string(),
            name: "macOS Keychain Credential Access".to_string(),
            technique_ids: vec![
                "T1555".to_string(), // Credentials from Password Stores
                "T1555.001".to_string(), // Keychain
            ],
            required_slots: vec![
                "security_cmd_invoked".to_string(), // security find-generic-password, security dump-keychain
            ],
            optional_slots: vec![
                "suspicious_ancestry".to_string(),
                "output_redirect_to_file".to_string(),
                "follow_on_ssh_or_cloud_cli".to_string(),
            ],
            window_sec: 600, // 10 minute window for follow-on activity
            description: "Execution of macOS 'security' command for keychain access (find-generic-password, \
                          dump-keychain, etc.). Often followed by SSH or cloud CLI execution.".to_string(),
        },
        MacOSNativePlaybook {
            id: "pb_macos_lolbin_stager".to_string(),
            name: "macOS LOLBIN Staging Chain".to_string(),
            technique_ids: vec![
                "T1059".to_string(), // Command and Scripting Interpreter
                "T1059.004".to_string(), // Unix Shell
            ],
            required_slots: vec![
                "curl_or_wget_exec".to_string(),
                "sh_or_python_piping".to_string(),
            ],
            optional_slots: vec![
                "suspicious_cwd".to_string(), // /tmp, /var/tmp, /dev/shm
                "network_connection_pre_exec".to_string(),
            ],
            window_sec: 30, // Very tight: download → pipe → exec
            description: "Classic 'curl | sh' or 'python -c' chain. Stage 1 fetch data, Stage 2 exec interpreted.".to_string(),
        },
        MacOSNativePlaybook {
            id: "pb_macos_quarantine_unsigned_first".to_string(),
            name: "macOS Quarantine-Unsigned-First Execution".to_string(),
            technique_ids: vec![
                "T1202".to_string(), // Indirect Command Execution
                "T1204.002".to_string(), // User Execution: Malicious File
            ],
            required_slots: vec![
                "quarantine_xattr_present".to_string(), // com.apple.quarantine xattr
                "unsigned_code_signature".to_string(),
                "first_seen_binary".to_string(),
                "execution_occurs".to_string(),
            ],
            optional_slots: vec![
                "network_connection_post_exec".to_string(),
                "file_write_post_exec".to_string(),
            ],
            window_sec: 120, // 2 minute window from exec to follow-on
            description: "Binary with quarantine xattr + unsigned code signature + never-seen-before \
                          + rapid follow-on behavior. Strong indicator of downloaded malware execution.".to_string(),
        },
        MacOSNativePlaybook {
            id: "pb_macos_code_signature_bypass".to_string(),
            name: "macOS Code Signature Bypass/Modification".to_string(),
            technique_ids: vec![
                "T1036.001".to_string(), // Masquerading: Invalid Code Signature
                "T1578.004".to_string(), // Modify Cloud Compute Infrastructure
            ],
            required_slots: vec![
                "codesign_tool_invoked".to_string(), // codesign -f -s command
                "unsigned_binary_exec_post".to_string(),
            ],
            optional_slots: vec![
                "network_connection_post_exec".to_string(),
            ],
            window_sec: 300, // 5 minute window
            description: "Execution of 'codesign' tool to remove/forge code signatures, \
                          followed by execution of previously-unsigned binary. Evasion technique.".to_string(),
        },
        MacOSNativePlaybook {
            id: "pb_macos_mdm_evasion".to_string(),
            name: "macOS MDM Evasion/Tamper".to_string(),
            technique_ids: vec![
                "T1562.001".to_string(), // Disable or Modify Tools: Disable or Modify macOS Logs
                "T1078.001".to_string(), // Valid Accounts: Default Accounts
            ],
            required_slots: vec![
                "mdm_profile_removal_attempt".to_string(), // Remove MDM/jamf profiles
            ],
            optional_slots: vec![
                "log_deletion_attempt".to_string(),
                "sudo_usage".to_string(),
                "network_connection_to_external".to_string(),
            ],
            window_sec: 600,
            description: "Attempts to remove MDM profiles or disable logging mechanisms. \
                          Indicates post-compromise persistence/evasion activity.".to_string(),
        },
        MacOSNativePlaybook {
            id: "pb_macos_ransomware_filewrite_burst".to_string(),
            name: "macOS Ransomware: File Write Burst".to_string(),
            technique_ids: vec![
                "T1486".to_string(), // Data Encrypted for Impact
            ],
            required_slots: vec![
                "suspicious_process_or_unsigned".to_string(),
                "file_write_burst".to_string(), // Many writes, low rename ratio
            ],
            optional_slots: vec![
                "entropy_analysis".to_string(),
                "extension_change_pattern".to_string(),
            ],
            window_sec: 1800, // 30 minute window for aggregation
            description: "Process with suspicious origins (unsigned, rare, suspicious parent) \
                          performing high-volume file writes with low rename ratio. \
                          Typical of encryption/ransomware activity.".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_playbooks_populated() {
        let playbooks = get_native_playbooks();
        assert!(!playbooks.is_empty());
        assert!(playbooks.len() >= 7);
        assert!(playbooks.iter().all(|p| !p.id.is_empty()));
        assert!(playbooks.iter().all(|p| !p.required_slots.is_empty()));
    }

    #[test]
    fn test_playbook_window_times() {
        let playbooks = get_native_playbooks();
        for pb in playbooks {
            assert!(pb.window_sec > 0 && pb.window_sec <= 3600, 
                    "Playbook {} has unreasonable window_sec: {}", pb.id, pb.window_sec);
        }
    }
}
