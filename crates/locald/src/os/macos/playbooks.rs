//! macOS Playbook Definitions
//!
//! This module provides programmatic playbook definitions for macOS detection.
//! Maps OpenBSM audit events to hypothesis-based incident detection.
//!
//! Coverage Map:
//! - Credential Access: 2 playbooks
//! - Persistence: 3 playbooks
//! - Defense Evasion: 3 playbooks
//! - Execution: 3 playbooks
//! - Privilege Escalation: 2 playbooks
//!
//! Total: 13 playbooks

use crate::slot_matcher::{PlaybookDef, PlaybookSlot, SlotPredicate};

/// Build all macOS playbook definitions
pub fn macos_playbooks() -> Vec<PlaybookDef> {
    vec![
        // === CREDENTIAL ACCESS ===
        credential_keychain_access(),
        credential_password_file_access(),
        // === PERSISTENCE ===
        persistence_launch_agent(),
        persistence_launch_daemon(),
        persistence_cron_job(),
        // === DEFENSE EVASION ===
        defense_evasion_gatekeeper_bypass(),
        defense_evasion_sip_modification(),
        defense_evasion_tcc_manipulation(),
        // === EXECUTION ===
        execution_shell_spawn(),
        execution_osascript(),
        execution_installer_abuse(),
        // === PRIVILEGE ESCALATION ===
        privesc_sudo_abuse(),
        privesc_setuid_execution(),
    ]
}

// ============================================================================
// CREDENTIAL ACCESS
// ============================================================================

/// Keychain Access - Suspicious access to keychain items
fn credential_keychain_access() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_credential_keychain".to_string(),
        title: "Keychain Access Detected".to_string(),
        family: "credential_access".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec!["credential_access".to_string(), "keychain".to_string(), "T1555.001".to_string()],
        slots: vec![PlaybookSlot::required(
            "keychain_access",
            "Keychain item access event",
            SlotPredicate::for_fact_type("CredentialAccess"),
        )
        .with_ttl(300)],
        narrative: Some("Detected access to macOS Keychain - potential credential theft".to_string()),
        playbook_hash: String::new(),
    }
}

/// Password File Access - Direct access to /etc/passwd, /etc/shadow equivalents
fn credential_password_file_access() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_credential_passwd".to_string(),
        title: "Password File Access".to_string(),
        family: "credential_access".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 60,
        tags: vec!["credential_access".to_string(), "password_file".to_string()],
        slots: vec![PlaybookSlot::required(
            "passwd_access",
            "Password file read event",
            SlotPredicate::for_fact_type("FileAccess"),
        )
        .with_ttl(300)],
        narrative: Some("Detected access to password-related files".to_string()),
        playbook_hash: String::new(),
    }
}

// ============================================================================
// PERSISTENCE
// ============================================================================

/// LaunchAgent Persistence - User-level persistence via LaunchAgents
fn persistence_launch_agent() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_persist_launchagent".to_string(),
        title: "LaunchAgent Persistence".to_string(),
        family: "persistence".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 600,
        cooldown_seconds: 300,
        tags: vec!["persistence".to_string(), "launch_agent".to_string(), "T1543.001".to_string()],
        slots: vec![PlaybookSlot::required(
            "plist_write",
            "LaunchAgent plist creation/modification",
            SlotPredicate::for_fact_type("PersistenceInstall"),
        )
        .with_ttl(600)],
        narrative: Some("Detected LaunchAgent plist modification - persistence mechanism".to_string()),
        playbook_hash: String::new(),
    }
}

/// LaunchDaemon Persistence - System-level persistence via LaunchDaemons
fn persistence_launch_daemon() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_persist_launchdaemon".to_string(),
        title: "LaunchDaemon Persistence".to_string(),
        family: "persistence".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host".to_string(),
        ttl_seconds: 600,
        cooldown_seconds: 300,
        tags: vec!["persistence".to_string(), "launch_daemon".to_string(), "T1543.004".to_string()],
        slots: vec![PlaybookSlot::required(
            "daemon_plist",
            "LaunchDaemon plist creation",
            SlotPredicate::for_fact_type("PersistenceInstall"),
        )
        .with_ttl(600)],
        narrative: Some("Detected LaunchDaemon creation - system-level persistence".to_string()),
        playbook_hash: String::new(),
    }
}

/// Cron Job Persistence
fn persistence_cron_job() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_persist_cron".to_string(),
        title: "Cron Job Persistence".to_string(),
        family: "persistence".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec!["persistence".to_string(), "cron".to_string(), "T1053.003".to_string()],
        slots: vec![PlaybookSlot::required(
            "cron_modify",
            "Crontab modification event",
            SlotPredicate::for_fact_type("PersistenceInstall"),
        )
        .with_ttl(300)],
        narrative: Some("Detected crontab modification - scheduled persistence".to_string()),
        playbook_hash: String::new(),
    }
}

// ============================================================================
// DEFENSE EVASION
// ============================================================================

/// Gatekeeper Bypass - Attempts to bypass Gatekeeper
fn defense_evasion_gatekeeper_bypass() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_evasion_gatekeeper".to_string(),
        title: "Gatekeeper Bypass Attempt".to_string(),
        family: "defense_evasion".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec!["defense_evasion".to_string(), "gatekeeper".to_string(), "T1553.001".to_string()],
        slots: vec![PlaybookSlot::required(
            "xattr_remove",
            "Quarantine xattr removal",
            SlotPredicate::for_fact_type("DefenseEvasion"),
        )
        .with_ttl(300)],
        narrative: Some("Detected quarantine attribute removal - Gatekeeper bypass".to_string()),
        playbook_hash: String::new(),
    }
}

/// SIP Modification Attempt - System Integrity Protection tampering
fn defense_evasion_sip_modification() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_evasion_sip".to_string(),
        title: "SIP Modification Attempt".to_string(),
        family: "defense_evasion".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host".to_string(),
        ttl_seconds: 600,
        cooldown_seconds: 300,
        tags: vec!["defense_evasion".to_string(), "sip".to_string(), "T1562.001".to_string()],
        slots: vec![PlaybookSlot::required(
            "sip_modify",
            "SIP-protected path modification attempt",
            SlotPredicate::for_fact_type("DefenseEvasion"),
        )
        .with_ttl(600)],
        narrative: Some("Detected attempt to modify SIP-protected system files".to_string()),
        playbook_hash: String::new(),
    }
}

/// TCC Database Manipulation - Transparency, Consent, Control bypass
fn defense_evasion_tcc_manipulation() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_evasion_tcc".to_string(),
        title: "TCC Database Manipulation".to_string(),
        family: "defense_evasion".to_string(),
        severity: "CRITICAL".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec!["defense_evasion".to_string(), "tcc".to_string(), "T1562".to_string()],
        slots: vec![PlaybookSlot::required(
            "tcc_access",
            "TCC database access event",
            SlotPredicate::for_fact_type("DefenseEvasion"),
        )
        .with_ttl(300)],
        narrative: Some("Detected TCC database manipulation - permission bypass attempt".to_string()),
        playbook_hash: String::new(),
    }
}

// ============================================================================
// EXECUTION
// ============================================================================

/// Shell Spawn from Unexpected Parent
fn execution_shell_spawn() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_exec_shell".to_string(),
        title: "Suspicious Shell Spawn".to_string(),
        family: "execution".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user|process".to_string(),
        ttl_seconds: 60,
        cooldown_seconds: 30,
        tags: vec!["execution".to_string(), "shell".to_string(), "T1059.004".to_string()],
        slots: vec![PlaybookSlot::required(
            "shell_exec",
            "Shell execution event",
            SlotPredicate::for_fact_type("ProcessExec"),
        )
        .with_ttl(60)],
        narrative: Some("Detected shell spawn from potentially suspicious parent process".to_string()),
        playbook_hash: String::new(),
    }
}

/// osascript Execution - AppleScript/JXA execution
fn execution_osascript() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_exec_osascript".to_string(),
        title: "osascript Execution".to_string(),
        family: "execution".to_string(),
        severity: "MEDIUM".to_string(),
        entity_scope: "host|user|process".to_string(),
        ttl_seconds: 120,
        cooldown_seconds: 60,
        tags: vec!["execution".to_string(), "osascript".to_string(), "T1059.002".to_string()],
        slots: vec![PlaybookSlot::required(
            "osascript_exec",
            "osascript execution event",
            SlotPredicate::for_fact_type("ProcessExec"),
        )
        .with_ttl(120)],
        narrative: Some("Detected osascript execution - AppleScript/JavaScript for Automation".to_string()),
        playbook_hash: String::new(),
    }
}

/// Installer Package Abuse
fn execution_installer_abuse() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_exec_installer".to_string(),
        title: "Installer Package Abuse".to_string(),
        family: "execution".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 120,
        tags: vec!["execution".to_string(), "installer".to_string(), "T1059".to_string()],
        slots: vec![PlaybookSlot::required(
            "installer_exec",
            "Installer execution with scripts",
            SlotPredicate::for_fact_type("ProcessExec"),
        )
        .with_ttl(300)],
        narrative: Some("Detected installer package execution with embedded scripts".to_string()),
        playbook_hash: String::new(),
    }
}

// ============================================================================
// PRIVILEGE ESCALATION
// ============================================================================

/// Sudo Abuse - Suspicious sudo usage
fn privesc_sudo_abuse() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_privesc_sudo".to_string(),
        title: "Suspicious Sudo Usage".to_string(),
        family: "privilege_escalation".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user".to_string(),
        ttl_seconds: 300,
        cooldown_seconds: 60,
        tags: vec!["privilege_escalation".to_string(), "sudo".to_string(), "T1548.003".to_string()],
        slots: vec![PlaybookSlot::required(
            "sudo_exec",
            "Sudo execution event",
            SlotPredicate::for_fact_type("PrivilegeEscalation"),
        )
        .with_ttl(300)],
        narrative: Some("Detected suspicious sudo command execution".to_string()),
        playbook_hash: String::new(),
    }
}

/// Setuid Binary Execution
fn privesc_setuid_execution() -> PlaybookDef {
    PlaybookDef {
        playbook_id: "macos_privesc_setuid".to_string(),
        title: "Setuid Binary Execution".to_string(),
        family: "privilege_escalation".to_string(),
        severity: "HIGH".to_string(),
        entity_scope: "host|user|process".to_string(),
        ttl_seconds: 120,
        cooldown_seconds: 60,
        tags: vec!["privilege_escalation".to_string(), "setuid".to_string(), "T1548.001".to_string()],
        slots: vec![PlaybookSlot::required(
            "setuid_exec",
            "Setuid binary execution",
            SlotPredicate::for_fact_type("PrivilegeEscalation"),
        )
        .with_ttl(120)],
        narrative: Some("Detected execution of setuid binary for privilege escalation".to_string()),
        playbook_hash: String::new(),
    }
}
