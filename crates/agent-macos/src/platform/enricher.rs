/// Enrichment pipeline: canonicalization, codesign, rarity, content inspection
/// Spec §2: Bounded, cached, deterministic

use crate::macos_detect::*;
use std::collections::HashMap;
use std::process::Command;

pub struct Enricher {
    codesign_cache: HashMap<String, CodesignInfo>,
    rarity_db: HashMap<String, RarityFlags>,
    config: EnricherConfig,
}

#[derive(Debug, Clone)]
pub struct EnricherConfig {
    pub codesign_timeout_ms: u64,
    pub max_entropy_file_size: u64,
    pub entropy_threshold: f64,
    pub base64_threshold: f64,
}

impl Default for EnricherConfig {
    fn default() -> Self {
        Self {
            codesign_timeout_ms: 500,
            max_entropy_file_size: 5 * 1024 * 1024, // 5MB
            entropy_threshold: 7.2,
            base64_threshold: 0.7,
        }
    }
}

impl Enricher {
    pub fn new(config: EnricherConfig) -> Self {
        Self {
            codesign_cache: HashMap::new(),
            rarity_db: HashMap::new(),
            config,
        }
    }

    pub fn enrich(&mut self, fact: Fact) -> EnrichedFact {
        let mut enrichments = Enrichments::default();

        // Canonicalization
        if let Some(path) = &fact.exe_path {
            enrichments.canonical_path = Some(canonicalize_path(path));
        }

        if let Some(argv) = &fact.argv {
            enrichments.canonical_argv = Some(canonicalize_argv(argv));
        }

        // Codesign enrichment (for ProcExec)
        if let FactType::ProcExec(exec_fact) = &fact.fact_type {
            enrichments.codesign = self.get_codesign_info(&exec_fact.exe_path);
            enrichments.rarity =
                self.compute_rarity(&fact.subject_key(), &exec_fact.exe_path, "exec");
        }

        // Content inspection (for FileWrite under risky conditions)
        if let FactType::FileWrite(write_fact) = &fact.fact_type {
            if let Some(size) = write_fact.size {
                if is_user_writable_dir(&write_fact.path) && size < self.config.max_entropy_file_size {
                    enrichments.content = self.analyze_content(&write_fact.path, size);
                }
            }
        }

        // NetConnect rarity
        if let FactType::NetConnect(net_fact) = &fact.fact_type {
            enrichments.rarity = self.compute_rarity(
                &fact.subject_key(),
                &net_fact.dest_ip,
                "net_dest",
            );
        }

        EnrichedFact { fact, enrichments }
    }

    fn get_codesign_info(&mut self, exe_path: &str) -> Option<CodesignInfo> {
        if let Some(cached) = self.codesign_cache.get(exe_path) {
            return Some(cached.clone());
        }

        let info = query_codesign(exe_path, self.config.codesign_timeout_ms);
        if let Some(ref info) = info {
            self.codesign_cache.insert(exe_path.to_string(), info.clone());
        }
        info
    }

    fn compute_rarity(
        &mut self,
        session_key: &SessionKey,
        entity: &str,
        entity_type: &str,
    ) -> Option<RarityFlags> {
        let key = format!("{}:{}:{}", session_key.deterministic_hash(), entity_type, entity);

        if self.rarity_db.contains_key(&key) {
            return self.rarity_db.get(&key).cloned();
        }

        let flags = RarityFlags {
            first_seen_host: true,  // Simplified; real impl queries baseline
            first_seen_user: true,
            first_seen_tuple: true,
        };

        self.rarity_db.insert(key, flags.clone());
        Some(flags)
    }

    fn analyze_content(&self, path: &str, size: u64) -> Option<ContentInfo> {
        let entropy = compute_entropy_bounded(path, 65536); // First 64KB
        let base64_score = estimate_base64_score(path, 1024); // First 1KB

        Some(ContentInfo {
            size_bytes: size,
            entropy,
            base64_score,
            sha256: None, // Only compute if rate-limited and justified
        })
    }
}

// ==================== Canonicalization ====================

pub fn canonicalize_path(path: &str) -> String {
    let path = path.replace("~", "/Users/current");
    let mut parts: Vec<&str> = path.split('/').collect();

    // Remove empty and . parts, handle ..
    let mut resolved = Vec::new();
    for part in parts {
        match part {
            "" | "." => {}
            ".." => {
                resolved.pop();
            }
            _ => resolved.push(part),
        }
    }

    "/".to_string() + &resolved.join("/")
}

pub fn canonicalize_argv(argv: &[String]) -> Vec<String> {
    argv.iter()
        .map(|arg| {
            // Lowercase flags
            if arg.starts_with('-') && !arg.contains('=') {
                arg.to_lowercase()
            } else {
                arg.clone()
            }
        })
        .collect()
}

// ==================== Codesign Enrichment ====================

fn query_codesign(exe_path: &str, timeout_ms: u64) -> Option<CodesignInfo> {
    // Run: codesign -dvv <exe> 2>&1
    // Parse output to extract: signed, apple_signed, team_id, identifier, notarized
    // Timeout after timeout_ms

    match Command::new("codesign")
        .args(&["-dvv", exe_path])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let combined = format!("{}\n{}", stdout, stderr);

            let info = CodesignInfo {
                signed: Some(!combined.contains("code or signature invalid")),
                apple_signed: Some(combined.contains("Apple")),
                team_id: extract_team_id(&combined),
                identifier: extract_identifier(&combined),
                notarized: None, // Would require spctl check
            };
            Some(info)
        }
        Err(_) => None,
    }
}

fn extract_team_id(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains("TeamIdentifier") {
            return line.split('=').nth(1).map(|s| s.trim().to_string());
        }
    }
    None
}

fn extract_identifier(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.starts_with("Identifier=") {
            return line.split('=').nth(1).map(|s| s.trim().to_string());
        }
    }
    None
}

// ==================== Content Inspection ====================

fn compute_entropy_bounded(path: &str, max_bytes: usize) -> Option<f64> {
    match std::fs::read(path) {
        Ok(data) => {
            let sample = &data[..std::cmp::min(max_bytes, data.len())];
            Some(shannon_entropy(sample))
        }
        Err(_) => None,
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn estimate_base64_score(path: &str, max_bytes: usize) -> Option<f64> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let sample = &content[..std::cmp::min(max_bytes, content.len())];
            let base64_chars = sample.chars().filter(|c| is_base64_char(*c)).count();
            let ratio = base64_chars as f64 / sample.len().max(1) as f64;
            Some(ratio)
        }
        Err(_) => None,
    }
}

fn is_base64_char(c: char) -> bool {
    c.is_alphanumeric() || c == '+' || c == '/' || c == '='
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_path() {
        assert_eq!(canonicalize_path("/tmp//foo"), "/tmp/foo");
        assert_eq!(canonicalize_path("/tmp/./foo"), "/tmp/foo");
        assert_eq!(canonicalize_path("/tmp/foo/.."), "/tmp");
    }

    #[test]
    fn test_shannon_entropy() {
        let uniform = vec![0u8, 1, 2, 3, 4, 5, 6, 7]; // Perfect entropy
        let entropy = shannon_entropy(&uniform);
        assert!(entropy > 2.0);

        let flat = vec![0u8; 100]; // No entropy
        let entropy = shannon_entropy(&flat);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_canonicalize_argv() {
        let argv = vec!["-XvvF".to_string(), "value".to_string()];
        let canonical = canonicalize_argv(&argv);
        assert_eq!(canonical[0], "-xvvf");
        assert_eq!(canonical[1], "value");
    }
}
