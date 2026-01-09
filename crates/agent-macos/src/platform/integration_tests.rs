/// Integration test: End-to-end explanation workflow
/// Facts → Enrichment → Playbook → Explanation Bundle → API

#[cfg(test)]
mod integration_tests {
    use crate::macos_detect::explain::*;
    use crate::macos_detect::explainer::{ExplainerBuilder, ConfigHashes};
    use crate::macos_detect::api::*;
    use std::collections::HashMap;

    /// Mock explanation store for testing
    struct TestStore {
        bundles: HashMap<String, ExplanationBundle>,
    }

    impl ExplanationStore for TestStore {
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
    fn test_end_to_end_incident_explanation() {
        // Step 1: Create evidence pointers (facts)
        let evidence_pstr = vec![
            EvidencePointer {
                segment_id: "seg_20251219_001".to_string(),
                fact_id: "fact_launchd_write_001".to_string(),
                ts: 1702984800000,
                fact_type: "FileWrite".to_string(),
                summary: Some("LaunchAgent plist written".to_string()),
            },
            EvidencePointer {
                segment_id: "seg_20251219_001".to_string(),
                fact_id: "fact_launchctl_exec_001".to_string(),
                ts: 1702984860000,
                fact_type: "ProcExec".to_string(),
                summary: Some("launchctl bootstrap executed".to_string()),
            },
        ];

        // Step 2: Create playbook step traces
        let step1 = PlaybookStepTrace {
            playbook_id: "A".to_string(),
            step_id: "persist_step_1".to_string(),
            description: "LaunchDaemon/LaunchAgent plist created".to_string(),
            matched: true,
            match_reason: "File path matches LaunchAgents directory".to_string(),
            evidence_ptrs: vec![evidence_pstr[0].clone()],
            weight: 0.5,
            state_transitions: vec!["init -> seen_write".to_string()],
        };

        let step2 = PlaybookStepTrace {
            playbook_id: "A".to_string(),
            step_id: "persist_step_2".to_string(),
            description: "Launch service bootstrap within 10 minutes".to_string(),
            matched: true,
            match_reason: "launchctl bootstrap called 60s after plist write".to_string(),
            evidence_ptrs: vec![evidence_pstr[1].clone()],
            weight: 0.5,
            state_transitions: vec!["seen_write -> seen_bootstrap".to_string()],
        };

        // Step 3: Create explanation bundle using ExplainerBuilder
        let builder = ExplainerBuilder::new("Incident", "inc_persist_001");

        let boost1 = ScoreBoost {
            reason: "Binary unsigned".to_string(),
            delta: 0.05,
            evidence_ptrs: vec![evidence_pstr[0].clone()],
        };

        let boost2 = ScoreBoost {
            reason: "First-seen host".to_string(),
            delta: 0.05,
            evidence_ptrs: vec![evidence_pstr[1].clone()],
        };

        let bundle = builder.build_incident_explanation(
            "A",
            "LaunchD Persistence Detection",
            vec![step1, step2],
            vec![boost1, boost2],
            0.85,
            "HIGH",
            "PERSIST_LAUNCHD:testhost:501:/Library/LaunchAgents/com.evil.plist",
            ConfigHashes::default(),
        );

        // Step 4: Verify bundle completeness
        assert_eq!(bundle.subject_id, "inc_persist_001");
        assert!(!bundle.evidence_ptrs.is_empty());
        assert!(!bundle.timeline.is_empty());
        assert!(!bundle.narrative.is_empty());
        assert!(!bundle.summary_one_liner.is_empty());
        assert_eq!(bundle.scoring_breakdown.final_confidence, 0.85);
        assert!(!bundle.counterfactuals.is_empty());
        assert!(!bundle.recommendations.is_empty());

        // Step 5: Store in mock DB
        let mut store = TestStore {
            bundles: HashMap::new(),
        };
        store
            .bundles
            .insert("inc_persist_001".to_string(), bundle.clone());

        // Step 6: Test API endpoints
        let resp = explain_incident("inc_persist_001", &store);
        assert!(resp.success);
        assert!(resp.bundle.is_some());

        let bundle_retrieved = resp.bundle.unwrap();
        assert_eq!(bundle_retrieved.subject_id, "inc_persist_001");
        assert_eq!(
            bundle_retrieved.scoring_breakdown.final_confidence,
            0.85
        );

        // Step 7: Test timeline endpoint
        let timeline_resp = get_timeline("inc_persist_001", &store);
        assert!(timeline_resp.is_ok());
        let timeline = timeline_resp.unwrap();
        assert!(!timeline.timeline.is_empty());

        // Step 8: Test graph endpoint
        let graph_resp = get_incident_graph("inc_persist_001", &store);
        assert!(graph_resp.is_ok());
        let graph = graph_resp.unwrap();
        assert!(!graph.edges.is_empty());
        assert!(!graph.nodes.is_empty());
    }

    #[test]
    fn test_narrative_generation_deterministic() {
        let builder = ExplainerBuilder::new("Incident", "inc_test_002");

        let step = PlaybookStepTrace {
            playbook_id: "B".to_string(),
            step_id: "step1".to_string(),
            description: "Unsigned binary network connection".to_string(),
            matched: true,
            match_reason: "unsigned + port 4444".to_string(),
            evidence_ptrs: vec![EvidencePointer {
                segment_id: "seg_002".to_string(),
                fact_id: "fact_003".to_string(),
                ts: 1702985000000,
                fact_type: "NetConnect".to_string(),
                summary: None,
            }],
            weight: 0.7,
            state_transitions: vec![],
        };

        let bundle1 = builder.build_incident_explanation(
            "B",
            "Unsigned Exec + Network",
            vec![step.clone()],
            vec![],
            0.90,
            "HIGH",
            "UNSIGNED_NET:testhost:501:curl:192.168.1.1:4444",
            ConfigHashes::default(),
        );

        let bundle2 = builder.build_incident_explanation(
            "B",
            "Unsigned Exec + Network",
            vec![step],
            vec![],
            0.90,
            "HIGH",
            "UNSIGNED_NET:testhost:501:curl:192.168.1.1:4444",
            ConfigHashes::default(),
        );

        // Same inputs → deterministic narrative
        assert_eq!(bundle1.narrative, bundle2.narrative);
        assert_eq!(bundle1.summary_one_liner, bundle2.summary_one_liner);
        assert_eq!(bundle1.evidence_ptrs, bundle2.evidence_ptrs);
    }

    #[test]
    fn test_counterfactuals_and_recommendations() {
        let bundle = ExplainerBuilder::new("Incident", "inc_cf_001")
            .build_incident_explanation(
                "D",
                "DYLD Injection",
                vec![PlaybookStepTrace {
                    playbook_id: "D".to_string(),
                    step_id: "dyld_inject".to_string(),
                    description: "DYLD_INSERT_LIBRARIES environment variable set".to_string(),
                    matched: true,
                    match_reason: "env var present".to_string(),
                    evidence_ptrs: vec![],
                    weight: 0.8,
                    state_transitions: vec![],
                }],
                vec![ScoreBoost {
                    reason: "Library from /tmp".to_string(),
                    delta: 0.05,
                    evidence_ptrs: vec![],
                }],
                0.95,
                "CRITICAL",
                "DYLD:testhost:0:/usr/bin/curl",
                ConfigHashes::default(),
            );

        // Verify counterfactuals present
        assert!(!bundle.counterfactuals.is_empty());
        let cf = bundle.counterfactuals[0].clone();
        assert!(cf.condition.contains("Apple-signed"));
        assert!(cf.impact.contains("Would not have fired"));

        // Verify recommendations present
        assert!(!bundle.recommendations.is_empty());
        let rec = bundle.recommendations[0].clone();
        assert!(!rec.action.is_empty());
        assert!(!rec.rationale.is_empty());
        assert!(["critical", "high", "medium", "low"].contains(&rec.priority.as_str()));
    }

    #[test]
    fn test_evidence_deduplication_in_bundle() {
        let ep1 = EvidencePointer {
            segment_id: "seg_001".to_string(),
            fact_id: "fact_001".to_string(),
            ts: 1000,
            fact_type: "ProcExec".to_string(),
            summary: None,
        };

        let ep1_dup = ep1.clone(); // Duplicate

        let ep2 = EvidencePointer {
            segment_id: "seg_002".to_string(),
            fact_id: "fact_002".to_string(),
            ts: 2000,
            fact_type: "FileWrite".to_string(),
            summary: None,
        };

        let builder = ExplainerBuilder::new("Incident", "inc_dedup_001");

        let step = PlaybookStepTrace {
            playbook_id: "A".to_string(),
            step_id: "step1".to_string(),
            description: "test".to_string(),
            matched: true,
            match_reason: "test".to_string(),
            evidence_ptrs: vec![ep1, ep1_dup, ep2],
            weight: 1.0,
            state_transitions: vec![],
        };

        let bundle = builder.build_incident_explanation(
            "A",
            "Test",
            vec![step],
            vec![],
            0.8,
            "MEDIUM",
            "TEST_KEY",
            ConfigHashes::default(),
        );

        // Should have deduplicated: only 2 unique evidence pointers
        assert_eq!(bundle.evidence_ptrs.len(), 2);
    }
}
