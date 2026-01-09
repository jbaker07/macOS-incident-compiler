/// ExplanationBundle: Canonical model for evidence-backed explanations
/// Every incident, entity, and fact gets a deterministic explanation tied to evidence.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Evidence pointer: immutable reference to a raw fact
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvidencePointer {
    pub segment_id: String,
    pub fact_id: String,
    pub ts: u64,
    pub fact_type: String, // ProcExec, FileWrite, NetConnect, etc
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl EvidencePointer {
    pub fn key(&self) -> (String, String) {
        (self.segment_id.clone(), self.fact_id.clone())
    }
}

/// TimelineEntry: ordered event with evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub ts: u64,
    pub annotation: String, // "unsigned binary exec", "first network connection", etc
    pub evidence_ptr: EvidencePointer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// CausalLink: A → B causality with evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalLink {
    pub from: String,          // description of event A
    pub to: String,            // description of event B
    pub reason: String,        // "temporal proximity", "same process", etc
    pub evidence_ptrs: Vec<EvidencePointer>,
    pub time_delta_secs: Option<u64>,
}

/// PlaybookScoreComponent: breakdown of playbook scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookScoreComponent {
    pub playbook_id: String,
    pub playbook_name: String,
    pub base_confidence: f64,
    pub matched_steps: Vec<PlaybookStep>,
    pub missed_steps: Vec<PlaybookStep>,
    pub boosts_applied: Vec<ScoreBoost>,
    pub final_confidence: f64,
    pub ttl_window_secs: u64,
    pub dedupe_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub step_id: String,
    pub description: String,
    pub matched: bool,
    pub weight: f64,
    pub reason: String,
    pub evidence_ptrs: Vec<EvidencePointer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBoost {
    pub reason: String,        // "first_seen_host", "unsigned_binary", etc
    pub delta: f64,
    pub evidence_ptrs: Vec<EvidencePointer>,
}

/// AnomalyScoreComponent: statistical anomaly explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScoreComponent {
    pub feature_name: String,
    pub observed_value: serde_json::Value,
    pub baseline_mean: Option<f64>,
    pub baseline_std: Option<f64>,
    pub z_score: Option<f64>,
    pub rarity_pct: f64, // 0.1 = appears in 0.1% of baseline
    pub explanation: String,
    pub evidence_ptrs: Vec<EvidencePointer>,
}

/// TrustScoreComponent: trust dimension breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScoreComponent {
    pub dimension: String, // "persistence", "execution", "network", etc
    pub delta: f64,        // positive = risky
    pub reason: String,
    pub decay_applied: bool,
    pub propagation_edges: Vec<String>, // process IDs inherited from
    pub evidence_ptrs: Vec<EvidencePointer>,
}

/// GraphComponent: subgraph explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphComponent {
    pub node_ids: Vec<String>, // process_id, file_path, etc
    pub edge_descriptions: Vec<String>, // "proc123 spawn proc456", etc
    pub evidence_ptrs: Vec<EvidencePointer>,
    pub is_minimal_subgraph: bool,
}

/// ModelExplainability: GNN/ML model attribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelExplainability {
    pub model_name: String,
    pub model_version: String,
    pub subgraph_ids: Vec<String>,
    pub top_contributing_nodes: Vec<(String, f64)>, // (node_id, contribution_score)
    pub top_contributing_edges: Vec<(String, String, f64)>, // (from, to, score)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unexplained_components: Option<String>, // if attribution not available
    pub fallback_rationale: String, // backup explanation if black box
}

/// Counterfactual: what would have prevented the incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counterfactual {
    pub condition: String,  // "If binary was signed…", "If entropy was normal…"
    pub impact: String,     // "Would not have fired"
    pub priority: String,   // "essential", "helpful", "nice_to_have"
}

/// Recommendation: action item grounded in evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub action: String,
    pub rationale: String, // tied to evidence
    pub priority: String,  // "critical", "high", "medium", "low"
    pub evidence_ptrs: Vec<EvidencePointer>,
}

/// DebugInfo: reproducibility and versioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugInfo {
    pub correlation_key: String,
    pub dedupe_key: String,
    pub ttl_window_secs: u64,
    pub playbook_config_hash: String,
    pub threshold_config_hash: String,
    pub allowlist_hash: String,
    pub generated_at_unix_ms: u64,
}

/// Main ExplanationBundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationBundle {
    pub subject_type: String, // "Incident", "Entity", "Fact"
    pub subject_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_hash: String, // sha256 of content for dedup/versioning
    
    // One-liner
    pub summary_one_liner: String, // max 140 chars
    
    // Narrative
    pub narrative: String, // short paragraph, deterministic
    
    // Evidence
    pub evidence_ptrs: Vec<EvidencePointer>, // deduplicated, sorted
    
    // Timeline
    pub timeline: Vec<TimelineEntry>, // sorted by ts
    
    // Causality
    pub causal_chain: Vec<CausalLink>,
    
    // Scoring
    pub scoring_breakdown: ScoringBreakdown,
    
    // Counterfactuals
    pub counterfactuals: Vec<Counterfactual>,
    
    // Recommendations
    pub recommendations: Vec<Recommendation>,
    
    // Debug
    pub debug: DebugInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringBreakdown {
    pub playbook_components: Vec<PlaybookScoreComponent>,
    pub anomaly_components: Vec<AnomalyScoreComponent>,
    pub trust_components: Vec<TrustScoreComponent>,
    pub graph_component: Option<GraphComponent>,
    pub model_component: Option<ModelExplainability>,
    pub final_confidence: f64,
    pub final_severity: String,
}

impl ExplanationBundle {
    /// Normalize: deduplicate and sort evidence pointers
    pub fn normalize(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.evidence_ptrs.retain(|ep| seen.insert(ep.key()));
        self.evidence_ptrs.sort();
    }

    /// For reproducibility: hash the content
    pub fn compute_hash(&self) -> String {
        use sha2::{Sha256, Digest};
        let json = serde_json::to_string(&self)
            .unwrap_or_else(|_| "serialization_error".to_string());
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

// ==================== Explanation Traces (emitted during processing) ====================

/// EnrichmentTrace: what enrichment happened and what baselines were queried
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentTrace {
    pub fact_id: String,
    pub enrichments_applied: Vec<String>, // ["codesign_lookup", "rarity_check", "entropy_calc"]
    pub baseline_queries: Vec<BaselineQuery>,
    pub normalized_fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineQuery {
    pub baseline_key: String,
    pub result: String, // "first_seen_host", "rarity_5pct", etc
    pub values: HashMap<String, serde_json::Value>,
}

/// PlaybookStepTrace: per-step decision record from a playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStepTrace {
    pub playbook_id: String,
    pub step_id: String,
    pub description: String,
    pub matched: bool,
    pub match_reason: String,
    pub evidence_ptrs: Vec<EvidencePointer>,
    pub weight: f64,
    pub state_transitions: Vec<String>, // for state machine tracking
}

/// AnomalyExplain: statistical anomaly with full provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyExplain {
    pub feature_vector_name: String,
    pub features: Vec<(String, serde_json::Value)>, // feature name and value
    pub baseline_summary: BaselineSummary,
    pub computed_distance: f64,
    pub is_outlier: bool,
    pub explanation_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub mean: Option<f64>,
    pub cov: Option<Vec<Vec<f64>>>,
    pub robust_median: Option<f64>,
    pub sample_count: u32,
}

/// TrustExplain: trust dimension deltas and propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustExplain {
    pub dimension: String,
    pub delta: f64,
    pub reason: String,
    pub decay_inputs: HashMap<String, f64>,
    pub propagation_edges: Vec<(String, String)>, // (from_entity, to_entity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_pointer_ordering() {
        let mut eps = vec![
            EvidencePointer {
                segment_id: "seg2".to_string(),
                fact_id: "f2".to_string(),
                ts: 100,
                fact_type: "ProcExec".to_string(),
                summary: None,
            },
            EvidencePointer {
                segment_id: "seg1".to_string(),
                fact_id: "f1".to_string(),
                ts: 50,
                fact_type: "FileWrite".to_string(),
                summary: None,
            },
        ];
        eps.sort();
        assert_eq!(eps[0].segment_id, "seg1");
    }

    #[test]
    fn test_explanation_bundle_hash_deterministic() {
        let mut b1 = ExplanationBundle {
            subject_type: "Incident".to_string(),
            subject_id: "inc1".to_string(),
            generated_at_unix_ms: 1000,
            bundle_hash: "".to_string(),
            summary_one_liner: "test".to_string(),
            narrative: "test narrative".to_string(),
            evidence_ptrs: vec![],
            timeline: vec![],
            causal_chain: vec![],
            scoring_breakdown: ScoringBreakdown {
                playbook_components: vec![],
                anomaly_components: vec![],
                trust_components: vec![],
                graph_component: None,
                model_component: None,
                final_confidence: 0.9,
                final_severity: "HIGH".to_string(),
            },
            counterfactuals: vec![],
            recommendations: vec![],
            debug: DebugInfo {
                correlation_key: "key".to_string(),
                dedupe_key: "dedupe".to_string(),
                ttl_window_secs: 3600,
                playbook_config_hash: "hash1".to_string(),
                threshold_config_hash: "hash2".to_string(),
                allowlist_hash: "hash3".to_string(),
                generated_at_unix_ms: 1000,
            },
        };

        let hash1 = b1.compute_hash();
        let hash2 = b1.compute_hash();
        assert_eq!(hash1, hash2); // deterministic
    }
}
