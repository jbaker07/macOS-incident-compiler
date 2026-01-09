/// ExplainerBuilder: Constructs ExplanationBundle from traces
/// Integrates facts, enrichment, playbooks, scoring, and graph data

use crate::macos_detect::explain::*;
use crate::macos_detect::narrative::NarrativeCompiler;
use std::collections::{BTreeMap, HashMap, HashSet};

pub struct ExplainerBuilder {
    subject_type: String,
    subject_id: String,
    generated_at_unix_ms: u64,
}

impl ExplainerBuilder {
    pub fn new(subject_type: &str, subject_id: &str) -> Self {
        Self {
            subject_type: subject_type.to_string(),
            subject_id: subject_id.to_string(),
            generated_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        }
    }

    /// Build incident explanation from playbook traces
    pub fn build_incident_explanation(
        &self,
        playbook_id: &str,
        playbook_name: &str,
        step_traces: Vec<PlaybookStepTrace>,
        boosts_applied: Vec<ScoreBoost>,
        final_confidence: f64,
        severity: &str,
        dedupe_key: &str,
        config_hashes: ConfigHashes,
    ) -> ExplanationBundle {
        // Collect all evidence pointers
        let mut all_evidence_ptrs = Vec::new();
        for step in &step_traces {
            all_evidence_ptrs.extend(step.evidence_ptrs.clone());
        }
        for boost in &boosts_applied {
            all_evidence_ptrs.extend(boost.evidence_ptrs.clone());
        }

        // Deduplicate and sort evidence
        let mut evidence_set = HashSet::new();
        let mut evidence_ptrs: Vec<_> = all_evidence_ptrs
            .into_iter()
            .filter(|ep| evidence_set.insert(ep.key()))
            .collect();
        evidence_ptrs.sort();

        // Build timeline from evidence
        let mut timeline = Vec::new();
        for ep in &evidence_ptrs {
            timeline.push(TimelineEntry {
                ts: ep.ts,
                annotation: ep.fact_type.clone(),
                evidence_ptr: ep.clone(),
                detail: ep.summary.clone(),
            });
        }
        timeline.sort_by_key(|t| t.ts);

        // Convert step traces to PlaybookStep
        let playbook_steps: Vec<_> = step_traces
            .iter()
            .map(|st| PlaybookStep {
                step_id: st.step_id.clone(),
                description: st.description.clone(),
                matched: st.matched,
                weight: st.weight,
                reason: st.match_reason.clone(),
                evidence_ptrs: st.evidence_ptrs.clone(),
            })
            .collect();

        // Build causal chain from step order
        let mut causal_chain = Vec::new();
        for window in playbook_steps.windows(2) {
            if window[0].matched && window[1].matched {
                let time_delta = if !timeline.is_empty() {
                    timeline
                        .last()
                        .zip(timeline.first())
                        .map(|(last, first)| last.ts.saturating_sub(first.ts))
                } else {
                    None
                };

                causal_chain.push(CausalLink {
                    from: window[0].description.clone(),
                    to: window[1].description.clone(),
                    reason: "sequential match".to_string(),
                    evidence_ptrs: vec![],
                    time_delta_secs: time_delta.map(|d| d / 1000),
                });
            }
        }

        // Scoring breakdown
        let scoring_breakdown = ScoringBreakdown {
            playbook_components: vec![PlaybookScoreComponent {
                playbook_id: playbook_id.to_string(),
                playbook_name: playbook_name.to_string(),
                base_confidence: final_confidence - boosts_applied.iter().map(|b| b.delta).sum::<f64>(),
                matched_steps: playbook_steps
                    .iter()
                    .filter(|s| s.matched)
                    .cloned()
                    .collect(),
                missed_steps: playbook_steps
                    .iter()
                    .filter(|s| !s.matched)
                    .cloned()
                    .collect(),
                boosts_applied: boosts_applied.clone(),
                final_confidence,
                ttl_window_secs: 3600, // TODO: config-driven
                dedupe_key: dedupe_key.to_string(),
            }],
            anomaly_components: vec![],
            trust_components: vec![],
            graph_component: None,
            model_component: None,
            final_confidence,
            final_severity: severity.to_string(),
        };

        // Counterfactuals: what would have prevented it
        let mut counterfactuals = vec![
            Counterfactual {
                condition: "If binary was Apple-signed".to_string(),
                impact: "Would not have fired (unsigned detection depends on signature)".to_string(),
                priority: "essential".to_string(),
            },
        ];

        // Add per-boost counterfactuals
        for boost in &boosts_applied {
            counterfactuals.push(Counterfactual {
                condition: format!("If {} was false", boost.reason),
                impact: "Confidence would be lower".to_string(),
                priority: "helpful".to_string(),
            });
        }

        // Recommendations
        let recommendations = vec![
            Recommendation {
                action: "Investigate process pedigree and code signing".to_string(),
                rationale: "Unsigned processes matching detection criteria warrant review".to_string(),
                priority: "high".to_string(),
                evidence_ptrs: evidence_ptrs.iter().take(1).cloned().collect(),
            },
            Recommendation {
                action: "Check for persistence mechanisms".to_string(),
                rationale: "Correlate with file system and launch services monitoring".to_string(),
                priority: "medium".to_string(),
                evidence_ptrs: vec![],
            },
        ];

        // Narrative
        let narrative = NarrativeCompiler::compile(
            playbook_id,
            playbook_name,
            &playbook_steps,
            &boosts_applied,
            final_confidence,
            evidence_ptrs.first(),
        );

        // One-liner
        let summary_one_liner = NarrativeCompiler::one_liner(
            playbook_name,
            playbook_steps
                .first()
                .map(|s| s.description.as_str())
                .unwrap_or("detected"),
            final_confidence,
        );

        // Debug info
        let debug = DebugInfo {
            correlation_key: self.subject_id.clone(),
            dedupe_key: dedupe_key.to_string(),
            ttl_window_secs: 3600,
            playbook_config_hash: config_hashes.playbook_hash,
            threshold_config_hash: config_hashes.threshold_hash,
            allowlist_hash: config_hashes.allowlist_hash,
            generated_at_unix_ms: self.generated_at_unix_ms,
        };

        let mut bundle = ExplanationBundle {
            subject_type: self.subject_type.clone(),
            subject_id: self.subject_id.clone(),
            generated_at_unix_ms: self.generated_at_unix_ms,
            bundle_hash: "".to_string(),
            summary_one_liner,
            narrative,
            evidence_ptrs,
            timeline,
            causal_chain,
            scoring_breakdown,
            counterfactuals,
            recommendations,
            debug,
        };

        bundle.normalize();
        bundle.bundle_hash = bundle.compute_hash();
        bundle
    }
}

pub struct ConfigHashes {
    pub playbook_hash: String,
    pub threshold_hash: String,
    pub allowlist_hash: String,
}

impl Default for ConfigHashes {
    fn default() -> Self {
        Self {
            playbook_hash: "v1_default".to_string(),
            threshold_hash: "v1_default".to_string(),
            allowlist_hash: "v1_default".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explainer_builder_creates_bundle() {
        let builder = ExplainerBuilder::new("Incident", "inc123");

        let step = PlaybookStepTrace {
            playbook_id: "A".to_string(),
            step_id: "step1".to_string(),
            description: "LaunchD plist written".to_string(),
            matched: true,
            match_reason: "matched path".to_string(),
            evidence_ptrs: vec![EvidencePointer {
                segment_id: "seg1".to_string(),
                fact_id: "fact1".to_string(),
                ts: 1000,
                fact_type: "FileWrite".to_string(),
                summary: Some("plist written".to_string()),
            }],
            weight: 0.8,
            state_transitions: vec![],
        };

        let bundle = builder.build_incident_explanation(
            "A",
            "LaunchD Persistence",
            vec![step],
            vec![],
            0.85,
            "HIGH",
            "LAUNCHD:host:uid:/path",
            ConfigHashes::default(),
        );

        assert_eq!(bundle.subject_id, "inc123");
        assert!(!bundle.evidence_ptrs.is_empty());
        assert!(!bundle.narrative.is_empty());
        assert!(bundle.bundle_hash.len() > 0);
    }

    #[test]
    fn test_bundle_determinism() {
        let builder = ExplainerBuilder::new("Incident", "inc123");

        let step = PlaybookStepTrace {
            playbook_id: "B".to_string(),
            step_id: "step1".to_string(),
            description: "test".to_string(),
            matched: true,
            match_reason: "reason".to_string(),
            evidence_ptrs: vec![],
            weight: 0.5,
            state_transitions: vec![],
        };

        let bundle1 = builder.build_incident_explanation(
            "B",
            "Test",
            vec![step.clone()],
            vec![],
            0.9,
            "MEDIUM",
            "key",
            ConfigHashes::default(),
        );

        let bundle2 = builder.build_incident_explanation(
            "B",
            "Test",
            vec![step],
            vec![],
            0.9,
            "MEDIUM",
            "key",
            ConfigHashes::default(),
        );

        // Same inputs → same content (allowing for timestamp drift in generated_at)
        assert_eq!(bundle1.narrative, bundle2.narrative);
        assert_eq!(bundle1.evidence_ptrs.len(), bundle2.evidence_ptrs.len());
    }
}
