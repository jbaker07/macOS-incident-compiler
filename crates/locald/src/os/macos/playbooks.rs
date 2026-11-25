//! macOS playbooks.
//!
//! The playbooks are YAML files in `playbooks/macos/`, one detection per
//! file, in the `PlaybookDef` schema from `slot_matcher.rs`. The files are
//! compiled into the binary with `include_str!` so `edr-locald` works from
//! any folder. Set `EDR_PLAYBOOK_DIR` to load a folder of YAML files at
//! startup instead, for example to try a new detection without rebuilding.
//!
//! Every playbook is checked when it loads: the fact types must be ones the
//! slot matcher knows, every regex must compile and at least one slot must be
//! required. A playbook that fails the check is an error, not a warning, so a
//! typo cannot silently turn a detection off.

use crate::slot_matcher::PlaybookDef;
use std::path::Path;

/// The YAML files under playbooks/macos, embedded at build time.
pub const EMBEDDED_PLAYBOOKS: &[(&str, &str)] = &[
    ("audit_disabled.yaml", include_str!("../../../../../playbooks/macos/audit_disabled.yaml")),
    ("browser_credential_read.yaml", include_str!("../../../../../playbooks/macos/browser_credential_read.yaml")),
    ("cron_persistence.yaml", include_str!("../../../../../playbooks/macos/cron_persistence.yaml")),
    ("exec_from_writable_dir.yaml", include_str!("../../../../../playbooks/macos/exec_from_writable_dir.yaml")),
    ("gatekeeper_disabled.yaml", include_str!("../../../../../playbooks/macos/gatekeeper_disabled.yaml")),
    ("keychain_dump.yaml", include_str!("../../../../../playbooks/macos/keychain_dump.yaml")),
    ("launch_agent_persistence.yaml", include_str!("../../../../../playbooks/macos/launch_agent_persistence.yaml")),
    ("launch_daemon_persistence.yaml", include_str!("../../../../../playbooks/macos/launch_daemon_persistence.yaml")),
    ("launchd_plist_loaded.yaml", include_str!("../../../../../playbooks/macos/launchd_plist_loaded.yaml")),
    ("osascript_shell.yaml", include_str!("../../../../../playbooks/macos/osascript_shell.yaml")),
    ("quarantine_attribute_removed.yaml", include_str!("../../../../../playbooks/macos/quarantine_attribute_removed.yaml")),
    ("shell_history_deletion.yaml", include_str!("../../../../../playbooks/macos/shell_history_deletion.yaml")),
    ("shell_profile_persistence.yaml", include_str!("../../../../../playbooks/macos/shell_profile_persistence.yaml")),
    ("ssh_private_key_read.yaml", include_str!("../../../../../playbooks/macos/ssh_private_key_read.yaml")),
    ("sudo_root_shell.yaml", include_str!("../../../../../playbooks/macos/sudo_root_shell.yaml")),
    ("system_log_deletion.yaml", include_str!("../../../../../playbooks/macos/system_log_deletion.yaml")),
    ("task_port_access.yaml", include_str!("../../../../../playbooks/macos/task_port_access.yaml")),
    ("tcc_database_access.yaml", include_str!("../../../../../playbooks/macos/tcc_database_access.yaml")),
    ("writable_exec_then_egress.yaml", include_str!("../../../../../playbooks/macos/writable_exec_then_egress.yaml")),
];

/// Fact types the extractor and slot matcher understand.
pub const KNOWN_FACT_TYPES: &[&str] = &[
    "Exec",
    "ProcSpawn",
    "ReadPath",
    "WritePath",
    "CreatePath",
    "DeletePath",
    "RenamePath",
    "PersistArtifact",
    "PrivilegeBoundary",
    "OutboundConnect",
    "InboundConnect",
    "Injection",
];

/// Parse and check one playbook.
pub fn parse_playbook(name: &str, text: &str) -> Result<PlaybookDef, String> {
    let playbook: PlaybookDef =
        serde_yaml::from_str(text).map_err(|e| format!("{}: {}", name, e))?;
    validate(name, &playbook)?;
    Ok(playbook)
}

fn validate(name: &str, playbook: &PlaybookDef) -> Result<(), String> {
    if playbook.slots.is_empty() {
        return Err(format!("{}: no slots", name));
    }
    if !playbook.slots.iter().any(|s| s.required) {
        return Err(format!("{}: no required slot", name));
    }
    for slot in &playbook.slots {
        let fact_type = slot.predicate.fact_type.as_str();
        if !KNOWN_FACT_TYPES.contains(&fact_type) {
            return Err(format!("{}: slot {} uses unknown fact type {}", name, slot.slot_id, fact_type));
        }
        let patterns = [
            &slot.predicate.path_regex,
            &slot.predicate.cmdline_regex,
            &slot.predicate.actor_exe_regex,
            &slot.predicate.actor_exe_not_regex,
        ];
        for pattern in patterns.iter() {
            if let Some(p) = pattern {
                regex::Regex::new(p)
                    .map_err(|e| format!("{}: slot {} regex does not compile: {}", name, slot.slot_id, e))?;
            }
        }
    }
    Ok(())
}

/// The built in playbooks.
pub fn macos_playbooks() -> Vec<PlaybookDef> {
    let mut playbooks = Vec::new();
    for (name, text) in EMBEDDED_PLAYBOOKS {
        // The tests parse every embedded file, so this cannot fail in a
        // build that passed its tests.
        playbooks.push(parse_playbook(name, text).expect("embedded playbook is valid"));
    }
    playbooks
}

/// Load every .yaml and .yml file in a folder, sorted by file name.
pub fn load_playbooks_from_dir(dir: &Path) -> Result<Vec<PlaybookDef>, String> {
    let mut names = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false);
        if path.is_file() && is_yaml {
            names.push(path);
        }
    }
    names.sort();
    let mut playbooks = Vec::new();
    for path in names {
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {}", path.display(), e))?;
        playbooks.push(parse_playbook(&path.display().to_string(), &text)?);
    }
    if playbooks.is_empty() {
        return Err(format!("no playbooks found in {}", dir.display()));
    }
    Ok(playbooks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn playbook_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../playbooks/macos")
    }

    #[test]
    fn every_embedded_playbook_parses() {
        let playbooks = macos_playbooks();
        assert_eq!(playbooks.len(), EMBEDDED_PLAYBOOKS.len());
        let ids: HashSet<&str> = playbooks.iter().map(|p| p.playbook_id.as_str()).collect();
        assert_eq!(ids.len(), playbooks.len(), "duplicate playbook ids");
    }

    #[test]
    fn embedded_list_matches_the_folder() {
        let mut on_disk: Vec<String> = std::fs::read_dir(playbook_dir())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".yaml"))
            .collect();
        on_disk.sort();
        let embedded: Vec<String> = EMBEDDED_PLAYBOOKS.iter().map(|(n, _)| n.to_string()).collect();
        assert_eq!(on_disk, embedded, "add new playbook files to EMBEDDED_PLAYBOOKS");
        assert_eq!(load_playbooks_from_dir(&playbook_dir()).unwrap().len(), embedded.len());
    }

    #[test]
    fn bad_playbooks_are_rejected() {
        let unknown_type = "playbook_id: x\ntitle: x\nfamily: x\nseverity: LOW\nttl_seconds: 1\nslots:\n  - {slot_id: a, name: a, required: true, ttl_seconds: 1, predicate: {fact_type: Nope}}\n";
        assert!(parse_playbook("t", unknown_type).unwrap_err().contains("unknown fact type"));
        let bad_regex = "playbook_id: x\ntitle: x\nfamily: x\nseverity: LOW\nttl_seconds: 1\nslots:\n  - {slot_id: a, name: a, required: true, ttl_seconds: 1, predicate: {fact_type: Exec, path_regex: '('}}\n";
        assert!(parse_playbook("t", bad_regex).unwrap_err().contains("regex"));
        let no_required = "playbook_id: x\ntitle: x\nfamily: x\nseverity: LOW\nttl_seconds: 1\nslots:\n  - {slot_id: a, name: a, required: false, ttl_seconds: 1, predicate: {fact_type: Exec}}\n";
        assert!(parse_playbook("t", no_required).unwrap_err().contains("required"));
    }
}
