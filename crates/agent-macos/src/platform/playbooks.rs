/// Six macOS detection playbooks: A-F
/// Spec §3A-F: Persistence, unsigned+net, entropy drop, DYLD, keychain, LOLBins

use crate::macos_detect::*;
use crate::macos_detect::state_machine::IncidentFactory;
use std::collections::HashMap;

pub trait Playbook {
    fn process_fact(&mut self, fact: &EnrichedFact) -> Vec<Incident>;
    fn playbook_id(&self) -> &str;
}

// ==================== A: LaunchD Persistence ====================

pub struct PlaybookA {
    state: HashMap<String, PlaybookState>, // keyed by dedupe
    config: PlaybookAConfig,
}

#[derive(Debug, Clone)]
pub struct PlaybookAConfig {
    pub launchd_ttl_ms: u64,
    pub launchd_activation_window_ms: u64,
    pub require_activation: bool,
}

impl Default for PlaybookAConfig {
    fn default() -> Self {
        Self {
            launchd_ttl_ms: 600_000,         // 10 min
            launchd_activation_window_ms: 600_000,
            require_activation: false,
        }
    }
}

impl PlaybookA {
    pub fn new(config: PlaybookAConfig) -> Self {
        Self {
            state: HashMap::new(),
            config,
        }
    }

    fn check_plist_write(&self, fact: &EnrichedFact) -> Option<String> {
        if let FactType::FileWrite(write_fact) = &fact.fact.fact_type {
            if write_fact.path.ends_with(".plist") && is_launchd_path(&write_fact.path) {
                return Some(write_fact.path.clone());
            }
        }
        None
    }

    fn check_launchctl_activation(&self, fact: &EnrichedFact) -> bool {
        if let FactType::ProcExec(exec_fact) = &fact.fact.fact_type {
            if exec_fact.exe_path.contains("launchctl") {
                let argv_lower: Vec<String> = exec_fact
                    .argv
                    .iter()
                    .map(|a| a.to_lowercase())
                    .collect();
                return argv_lower.iter().any(|a| {
                    a.contains("bootstrap")
                        || a.contains("load")
                        || a.contains("enable")
                        || a.contains("kickstart")
                        || a.contains("submit")
                });
            }
        }
        false
    }
}

impl Playbook for PlaybookA {
    fn process_fact(&mut self, fact: &EnrichedFact) -> Vec<Incident> {
        let mut incidents = Vec::new();

        // Step 1: FileWrite to plist
        if let Some(plist_path) = self.check_plist_write(fact) {
            let dedupe_key = format!(
                "PERSIST_LAUNCHD:{}:{}:{}:{}",
                fact.fact.host,
                fact.fact.uid.unwrap_or(0),
                plist_path,
                hour_bucket(fact.fact.ts)
            );

            let mut confidence = 0.80_f64;
            let mut severity = Severity::MEDIUM;

            // Check if writer is unsigned
            if let Some(ref codesign) = fact.enrichments.codesign {
                if codesign.signed == Some(false) {
                    confidence += 0.10;
                    severity = Severity::HIGH;
                }
            }

            // Check if writer path is user-writable
            if let Some(ref exe) = fact.fact.exe_path {
                if is_user_writable_dir(exe) {
                    confidence += 0.10;
                }
            }

            let evidence_ptr = EvidencePtr {
                segment_id: fact.fact.segment_id.clone(),
                fact_id: fact.fact.fact_id.clone(),
                fact_type: "FileWrite".to_string(),
                ts: fact.fact.ts,
            };

            let incident = IncidentFactory::create(
                "A",
                severity,
                (confidence as f64).min(1.0),
                &fact.fact.host,
                fact.fact.uid,
                &fact.fact.subject_key(),
                fact.fact.exe_path.clone(),
                vec!["T1543.001".to_string(), "T1547".to_string()],
                format!("LaunchD plist modification: {}", plist_path),
                vec![evidence_ptr],
                (fact.fact.ts, fact.fact.ts),
            );

            incidents.push(incident);
        }

        // Step 2: Check for launchctl activation (upgrade confidence)
        if self.check_launchctl_activation(fact) {
            // Find matching plist state and upgrade
            for (_, incident) in self.state.iter_mut() {
                incident.matched_steps.insert("activation".to_string());
            }
        }

        incidents
    }

    fn playbook_id(&self) -> &str {
        "A"
    }
}

// ==================== B: Unsigned Exec + Net ====================

pub struct PlaybookB {
    state: HashMap<String, PlaybookState>,
    config: PlaybookBConfig,
}

#[derive(Debug, Clone)]
pub struct PlaybookBConfig {
    pub unsigned_exec_net_ttl_ms: u64,
    pub suspicious_ports: Vec<u16>,
}

impl Default for PlaybookBConfig {
    fn default() -> Self {
        Self {
            unsigned_exec_net_ttl_ms: 120_000, // 2 min
            suspicious_ports: vec![4444, 5555, 6666, 8888, 9999],
        }
    }
}

impl PlaybookB {
    pub fn new(config: PlaybookBConfig) -> Self {
        Self {
            state: HashMap::new(),
            config,
        }
    }
}

impl Playbook for PlaybookB {
    fn process_fact(&mut self, fact: &EnrichedFact) -> Vec<Incident> {
        let mut incidents = Vec::new();

        // Step 1: Unsigned exec from user-writable dir
        if let FactType::ProcExec(exec_fact) = &fact.fact.fact_type {
            if is_user_writable_dir(&exec_fact.exe_path) {
                let is_unsigned = fact.enrichments.codesign.as_ref().map_or(true, |c| {
                    c.signed == Some(false) || c.signed.is_none()
                });

                if is_unsigned {
                    let dedupe_key = format!(
                        "UNSIGNED_EXEC_NET:{}:{}:{}:{}",
                        fact.fact.host,
                        fact.fact.uid.unwrap_or(0),
                        exec_fact.exe_path,
                        hour_bucket(fact.fact.ts)
                    );

                    let mut confidence: f64 = 0.85;
                    let mut severity = Severity::HIGH;

                    if let Some(ref rarity) = fact.enrichments.rarity {
                        if rarity.first_seen_host || rarity.first_seen_user {
                            confidence += 0.05;
                        }
                    }

                    let evidence_ptr = EvidencePtr {
                        segment_id: fact.fact.segment_id.clone(),
                        fact_id: fact.fact.fact_id.clone(),
                        fact_type: "ProcExec".to_string(),
                        ts: fact.fact.ts,
                    };

                    let incident = IncidentFactory::create(
                        "B",
                        severity,
                        confidence.min(1.0),
                        &fact.fact.host,
                        fact.fact.uid,
                        &fact.fact.subject_key(),
                        Some(exec_fact.exe_path.clone()),
                        vec!["T1204".to_string(), "T1071".to_string()],
                        format!("Unsigned execution from user-writable: {}", exec_fact.exe_path),
                        vec![evidence_ptr],
                        (fact.fact.ts, fact.fact.ts),
                    );

                    incidents.push(incident);
                }
            }
        }

        // Step 2: NetConnect from same process
        if let FactType::NetConnect(net_fact) = &fact.fact.fact_type {
            let mut confidence_boost: f64 = 0.0;
            if self.config.suspicious_ports.contains(&net_fact.dest_port) {
                confidence_boost += 0.05;
            }
            if let Some(ref rarity) = fact.enrichments.rarity {
                if rarity.first_seen_tuple {
                    confidence_boost += 0.05;
                }
            }

            let _dedupe_key = format!(
                "UNSIGNED_EXEC_NET:{}:{}:{}:{}:{}",
                fact.fact.host,
                fact.fact.uid.unwrap_or(0),
                fact.fact.exe_path.as_deref().unwrap_or("unknown"),
                net_fact.dest_ip,
                net_fact.dest_port,
            );

            let evidence_ptr = EvidencePtr {
                segment_id: fact.fact.segment_id.clone(),
                fact_id: fact.fact.fact_id.clone(),
                fact_type: "NetConnect".to_string(),
                ts: fact.fact.ts,
            };

            let incident = IncidentFactory::create(
                "B",
                Severity::HIGH,
                (0.85 + confidence_boost).min(1.0),
                &fact.fact.host,
                fact.fact.uid,
                &fact.fact.subject_key(),
                fact.fact.exe_path.clone(),
                vec!["T1204".to_string(), "T1071".to_string()],
                format!(
                    "Outbound connection from unsigned process: {} -> {}:{}",
                    fact.fact.exe_path.as_deref().unwrap_or("unknown"),
                    net_fact.dest_ip,
                    net_fact.dest_port
                ),
                vec![evidence_ptr],
                (fact.fact.ts, fact.fact.ts),
            );

            incidents.push(incident);
        }

        incidents
    }

    fn playbook_id(&self) -> &str {
        "B"
    }
}

// ==================== C: Entropy Drop + Exec ====================

pub struct PlaybookC {
    state: HashMap<String, PlaybookState>,
    config: PlaybookCConfig,
}

#[derive(Debug, Clone)]
pub struct PlaybookCConfig {
    pub entropy_threshold: f64,
    pub entropy_drop_exec_ttl_ms: u64,
    pub exec_net_ttl_ms: u64,
}

impl Default for PlaybookCConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 7.2,
            entropy_drop_exec_ttl_ms: 300_000,  // 5 min
            exec_net_ttl_ms: 120_000,           // 2 min
        }
    }
}

impl PlaybookC {
    pub fn new(config: PlaybookCConfig) -> Self {
        Self {
            state: HashMap::new(),
            config,
        }
    }
}

impl Playbook for PlaybookC {
    fn process_fact(&mut self, fact: &EnrichedFact) -> Vec<Incident> {
        let mut incidents = Vec::new();

        // Step 1: High-entropy file write
        if let FactType::FileWrite(write_fact) = &fact.fact.fact_type {
            if let Some(ref content) = fact.enrichments.content {
                if let Some(entropy) = content.entropy {
                    if entropy >= self.config.entropy_threshold {
                        let dedupe_key = format!(
                            "ENTROPY_DROP_EXEC:{}:{}:{}:{}",
                            fact.fact.host,
                            fact.fact.uid.unwrap_or(0),
                            write_fact.path,
                            hour_bucket(fact.fact.ts)
                        );

                        let evidence_ptr = EvidencePtr {
                            segment_id: fact.fact.segment_id.clone(),
                            fact_id: fact.fact.fact_id.clone(),
                            fact_type: "FileWrite".to_string(),
                            ts: fact.fact.ts,
                        };

                        let incident = IncidentFactory::create(
                            "C",
                            Severity::MEDIUM,
                            0.70,
                            &fact.fact.host,
                            fact.fact.uid,
                            &fact.fact.subject_key(),
                            fact.fact.exe_path.clone(),
                            vec!["T1027".to_string(), "T1059".to_string()],
                            format!(
                                "High-entropy file drop: {} (entropy: {:.2})",
                                write_fact.path, entropy
                            ),
                            vec![evidence_ptr],
                            (fact.fact.ts, fact.fact.ts),
                        );

                        incidents.push(incident);
                    }
                }
            }
        }

        // Step 2: Exec of dropped file (or interpreter)
        if let FactType::ProcExec(exec_fact) = &fact.fact.fact_type {
            // Simplified: if exe_path matches a previously seen high-entropy drop
            // In real impl, would correlate via file_key
            let dedupe_key = format!(
                "ENTROPY_DROP_EXEC:{}:{}:{}:{}",
                fact.fact.host,
                fact.fact.uid.unwrap_or(0),
                exec_fact.exe_path,
                hour_bucket(fact.fact.ts)
            );

            // Check if this looks like interpreter of suspicious script
            let is_interpreter = ["bash", "sh", "zsh", "python", "node", "osascript"]
                .iter()
                .any(|interp| exec_fact.exe_path.contains(interp));

            if is_interpreter && is_user_writable_dir(&exec_fact.exe_path) {
                let evidence_ptr = EvidencePtr {
                    segment_id: fact.fact.segment_id.clone(),
                    fact_id: fact.fact.fact_id.clone(),
                    fact_type: "ProcExec".to_string(),
                    ts: fact.fact.ts,
                };

                let incident = IncidentFactory::create(
                    "C",
                    Severity::HIGH,
                    0.85,
                    &fact.fact.host,
                    fact.fact.uid,
                    &fact.fact.subject_key(),
                    Some(exec_fact.exe_path.clone()),
                    vec!["T1027".to_string(), "T1059".to_string()],
                    format!(
                        "Suspicious interpreter execution: {}",
                        exec_fact.exe_path
                    ),
                    vec![evidence_ptr],
                    (fact.fact.ts, fact.fact.ts),
                );

                incidents.push(incident);
            }
        }

        incidents
    }

    fn playbook_id(&self) -> &str {
        "C"
    }
}

// ==================== D: DYLD Injection ====================

pub struct PlaybookD;

impl Playbook for PlaybookD {
    fn process_fact(&mut self, fact: &EnrichedFact) -> Vec<Incident> {
        let mut incidents = Vec::new();

        if let FactType::ProcExec(exec_fact) = &fact.fact.fact_type {
            if let Some(ref env) = exec_fact.env {
                let dyld_keys: Vec<&str> = vec![
                    "DYLD_INSERT_LIBRARIES",
                    "DYLD_LIBRARY_PATH",
                    "DYLD_FRAMEWORK_PATH",
                ];

                for key in dyld_keys {
                    if env.contains_key(key) {
                        let mut confidence: f64 = match key {
                            "DYLD_INSERT_LIBRARIES" => 0.92,
                            _ => 0.80,
                        };

                        // Boost if target is Apple-signed
                        if let Some(ref codesign) = fact.enrichments.codesign {
                            if codesign.apple_signed == Some(true) {
                                confidence += 0.05;
                            }
                        }

                        let evidence_ptr = EvidencePtr {
                            segment_id: fact.fact.segment_id.clone(),
                            fact_id: fact.fact.fact_id.clone(),
                            fact_type: "ProcExec".to_string(),
                            ts: fact.fact.ts,
                        };

                        let incident = IncidentFactory::create(
                            "D",
                            Severity::HIGH,
                            confidence.min(1.0),
                            &fact.fact.host,
                            fact.fact.uid,
                            &fact.fact.subject_key(),
                            Some(exec_fact.exe_path.clone()),
                            vec!["T1574.006".to_string(), "T1055".to_string()],
                            format!("DYLD environment injection detected: {}", key),
                            vec![evidence_ptr],
                            (fact.fact.ts, fact.fact.ts),
                        );

                        incidents.push(incident);
                    }
                }
            }
        }

        incidents
    }

    fn playbook_id(&self) -> &str {
        "D"
    }
}

// ==================== E: Keychain Access ====================

pub struct PlaybookE;

impl Playbook for PlaybookE {
    fn process_fact(&mut self, fact: &EnrichedFact) -> Vec<Incident> {
        let mut incidents = Vec::new();

        if let FactType::ProcExec(exec_fact) = &fact.fact.fact_type {
            if exec_fact.exe_path.ends_with("/security") {
                let argv_lower: Vec<String> =
                    exec_fact.argv.iter().map(|a| a.to_lowercase()).collect();

                let keychain_ops = vec![
                    "dump-keychain",
                    "export",
                    "find-generic-password",
                    "find-internet-password",
                    "import",
                ];

                for op in keychain_ops {
                    if argv_lower.iter().any(|a| a.contains(op)) {
                        let evidence_ptr = EvidencePtr {
                            segment_id: fact.fact.segment_id.clone(),
                            fact_id: fact.fact.fact_id.clone(),
                            fact_type: "ProcExec".to_string(),
                            ts: fact.fact.ts,
                        };

                        let incident = IncidentFactory::create(
                            "E",
                            Severity::HIGH,
                            0.85,
                            &fact.fact.host,
                            fact.fact.uid,
                            &fact.fact.subject_key(),
                            Some(exec_fact.exe_path.clone()),
                            vec!["T1555.001".to_string()],
                            format!("Keychain credential access: {}", op),
                            vec![evidence_ptr],
                            (fact.fact.ts, fact.fact.ts),
                        );

                        incidents.push(incident);
                    }
                }
            }
        }

        incidents
    }

    fn playbook_id(&self) -> &str {
        "E"
    }
}

// ==================== F: LOLBins / Stagers ====================

pub struct PlaybookF {
    config: PlaybookFConfig,
}

#[derive(Debug, Clone)]
pub struct PlaybookFConfig {
    pub suspicious_patterns: Vec<String>,
}

impl Default for PlaybookFConfig {
    fn default() -> Self {
        Self {
            suspicious_patterns: vec![
                "curl.*\\|.*sh".to_string(),
                "curl.*-o.*&&.*chmod.*\\+x".to_string(),
                "osascript.*-e".to_string(),
                "python.*-c".to_string(),
                "bash.*-c.*base64".to_string(),
            ],
        }
    }
}

impl PlaybookF {
    pub fn new(config: PlaybookFConfig) -> Self {
        Self { config }
    }
}

impl Playbook for PlaybookF {
    fn process_fact(&mut self, fact: &EnrichedFact) -> Vec<Incident> {
        let mut incidents = Vec::new();

        if let FactType::ProcExec(exec_fact) = &fact.fact.fact_type {
            let argv_str = exec_fact.argv.join(" ");

            for pattern in &self.config.suspicious_patterns {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    if regex.is_match(&argv_str) {
                        let mut confidence: f64 = match pattern.as_str() {
                            p if p.contains("curl") && p.contains("sh") => 0.90,
                            p if p.contains("curl") && p.contains("chmod") => 0.85,
                            p if p.contains("osascript") => 0.80,
                            _ => 0.65,
                        };

                        // Boost if from user-writable
                        if is_user_writable_dir(&exec_fact.exe_path) {
                            confidence += 0.10;
                        }

                        let evidence_ptr = EvidencePtr {
                            segment_id: fact.fact.segment_id.clone(),
                            fact_id: fact.fact.fact_id.clone(),
                            fact_type: "ProcExec".to_string(),
                            ts: fact.fact.ts,
                        };

                        let incident = IncidentFactory::create(
                            "F",
                            Severity::MEDIUM,
                            confidence.min(1.0),
                            &fact.fact.host,
                            fact.fact.uid,
                            &fact.fact.subject_key(),
                            Some(exec_fact.exe_path.clone()),
                            vec!["T1059".to_string(), "T1105".to_string()],
                            format!("Suspicious LOLBin chain: {} ", exec_fact.exe_path),
                            vec![evidence_ptr],
                            (fact.fact.ts, fact.fact.ts),
                        );

                        incidents.push(incident);
                        break; // One incident per exec
                    }
                }
            }
        }

        incidents
    }

    fn playbook_id(&self) -> &str {
        "F"
    }
}
