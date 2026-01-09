/// API endpoints for explanation queries
/// GET /api/incidents/{id}/explain
/// GET /api/entities/{id}/explain  
/// GET /api/facts/{id}/explain
/// GET /api/incidents/{id}/graph
/// GET /api/incidents/{id}/timeline

use crate::macos_detect::explain::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ExplainResponse {
    pub success: bool,
    pub bundle: Option<ExplanationBundle>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimelineResponse {
    pub timeline: Vec<TimelineEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GraphResponse {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub evidence_map: std::collections::HashMap<String, EvidencePointer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String, // process, file, user, ip
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation_type: String, // spawn, write, connect, etc
    pub evidence_key: Option<String>,
}

/// Incident explain endpoint
pub fn explain_incident(incident_id: &str, db: &dyn ExplanationStore) -> ExplainResponse {
    match db.get_incident_explanation(incident_id) {
        Ok(Some(bundle)) => ExplainResponse {
            success: true,
            bundle: Some(bundle),
            error: None,
        },
        Ok(None) => ExplainResponse {
            success: false,
            bundle: None,
            error: Some(format!("Incident {} not found", incident_id)),
        },
        Err(e) => ExplainResponse {
            success: false,
            bundle: None,
            error: Some(format!("Database error: {}", e)),
        },
    }
}

/// Entity explain endpoint
pub fn explain_entity(entity_id: &str, db: &dyn ExplanationStore) -> ExplainResponse {
    match db.get_entity_explanation(entity_id) {
        Ok(Some(bundle)) => ExplainResponse {
            success: true,
            bundle: Some(bundle),
            error: None,
        },
        Ok(None) => ExplainResponse {
            success: false,
            bundle: None,
            error: Some(format!("Entity {} not found", entity_id)),
        },
        Err(e) => ExplainResponse {
            success: false,
            bundle: None,
            error: Some(format!("Database error: {}", e)),
        },
    }
}

/// Fact explain endpoint
pub fn explain_fact(fact_id: &str, db: &dyn ExplanationStore) -> ExplainResponse {
    match db.get_fact_explanation(fact_id) {
        Ok(Some(bundle)) => ExplainResponse {
            success: true,
            bundle: Some(bundle),
            error: None,
        },
        Ok(None) => ExplainResponse {
            success: false,
            bundle: None,
            error: Some(format!("Fact {} not found", fact_id)),
        },
        Err(e) => ExplainResponse {
            success: false,
            bundle: None,
            error: Some(format!("Database error: {}", e)),
        },
    }
}

/// Timeline endpoint
pub fn get_timeline(incident_id: &str, db: &dyn ExplanationStore) -> Result<TimelineResponse, String> {
    match db.get_incident_explanation(incident_id) {
        Ok(Some(bundle)) => Ok(TimelineResponse {
            timeline: bundle.timeline,
        }),
        Ok(None) => Err(format!("Incident {} not found", incident_id)),
        Err(e) => Err(format!("Database error: {}", e)),
    }
}

/// Minimal causal graph endpoint
pub fn get_incident_graph(incident_id: &str, db: &dyn ExplanationStore) -> Result<GraphResponse, String> {
    match db.get_incident_explanation(incident_id) {
        Ok(Some(bundle)) => {
            let mut nodes = Vec::new();
            let mut edges = Vec::new();
            let mut evidence_map = std::collections::HashMap::new();

            // Extract nodes from causal chain
            let mut node_ids = std::collections::HashSet::new();
            for link in &bundle.causal_chain {
                node_ids.insert(link.from.clone());
                node_ids.insert(link.to.clone());

                edges.push(GraphEdge {
                    from: link.from.clone(),
                    to: link.to.clone(),
                    relation_type: link.reason.clone(),
                    evidence_key: link.evidence_ptrs.first().map(|ep| ep.key().0),
                });

                // Add evidence pointers to map
                for ep in &link.evidence_ptrs {
                    evidence_map.insert(format!("{}-{}", ep.segment_id, ep.fact_id), ep.clone());
                }
            }

            // Create nodes
            for id in node_ids {
                nodes.push(GraphNode {
                    id: id.clone(),
                    label: id.clone(),
                    node_type: "event".to_string(),
                });
            }

            Ok(GraphResponse {
                nodes,
                edges,
                evidence_map,
            })
        }
        Ok(None) => Err(format!("Incident {} not found", incident_id)),
        Err(e) => Err(format!("Database error: {}", e)),
    }
}

/// Trait for explanation storage backend
pub trait ExplanationStore: Send + Sync {
    fn get_incident_explanation(&self, id: &str) -> Result<Option<ExplanationBundle>, String>;
    fn get_entity_explanation(&self, id: &str) -> Result<Option<ExplanationBundle>, String>;
    fn get_fact_explanation(&self, id: &str) -> Result<Option<ExplanationBundle>, String>;
    fn store_explanation(&self, bundle: &ExplanationBundle) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockStore {
        bundles: std::collections::HashMap<String, ExplanationBundle>,
    }

    impl ExplanationStore for MockStore {
        fn get_incident_explanation(
            &self,
            id: &str,
        ) -> Result<Option<ExplanationBundle>, String> {
            Ok(self.bundles.get(id).cloned())
        }

        fn get_entity_explanation(&self, _id: &str) -> Result<Option<ExplanationBundle>, String> {
            Ok(None)
        }

        fn get_fact_explanation(&self, _id: &str) -> Result<Option<ExplanationBundle>, String> {
            Ok(None)
        }

        fn store_explanation(&self, _bundle: &ExplanationBundle) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn test_explain_incident() {
        let bundle = ExplanationBundle {
            subject_type: "Incident".to_string(),
            subject_id: "inc123".to_string(),
            generated_at_unix_ms: 1000,
            bundle_hash: "hash".to_string(),
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

        let mut store = MockStore {
            bundles: std::collections::HashMap::new(),
        };
        store.bundles.insert("inc123".to_string(), bundle);

        let resp = explain_incident("inc123", &store);
        assert!(resp.success);
        assert!(resp.bundle.is_some());
    }

    #[test]
    fn test_explain_incident_not_found() {
        let store = MockStore {
            bundles: std::collections::HashMap::new(),
        };

        let resp = explain_incident("nonexistent", &store);
        assert!(!resp.success);
        assert!(resp.error.is_some());
    }
}
