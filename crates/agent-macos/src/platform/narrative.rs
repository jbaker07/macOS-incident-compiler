/// Deterministic narrative generator
/// Produces evidence-backed, multi-sentence explanations with citations

use crate::macos_detect::explain::*;

pub struct NarrativeCompiler;

impl NarrativeCompiler {
    /// Generate deterministic narrative from traces
    pub fn compile(
        playbook_id: &str,
        playbook_name: &str,
        matched_steps: &[PlaybookStep],
        boosts: &[ScoreBoost],
        final_confidence: f64,
        first_evidence: Option<&EvidencePointer>,
    ) -> String {
        let mut sentences = Vec::new();

        // Sentence 1: What happened (playbook + trigger)
        if let Some(trigger_step) = matched_steps.first() {
            let s1 = format!(
                "{} (playbook {}): {}. Evidence: {}",
                playbook_name,
                playbook_id,
                trigger_step.description,
                first_evidence
                    .map(|ep| format!("fact_{}", ep.fact_id))
                    .unwrap_or_else(|| "unknown".to_string())
            );
            sentences.push(s1);
        }

        // Sentence 2: Why it's suspicious (boosts)
        let boost_reasons: Vec<_> = boosts
            .iter()
            .take(2)
            .map(|b| b.reason.clone())
            .collect();
        if !boost_reasons.is_empty() {
            let reason_str = boost_reasons.join(", ");
            let s2 = format!("Suspicious because: {}.", reason_str);
            sentences.push(s2);
        }

        // Sentence 3: How it progressed (step chain)
        if matched_steps.len() > 1 {
            let step_chain: Vec<_> = matched_steps
                .iter()
                .take(3)
                .map(|s| s.description.clone())
                .collect();
            let s3 = format!("Chain: {}.", step_chain.join(" → "));
            sentences.push(s3);
        }

        // Sentence 4: Confidence + corroboration
        let s4 = format!(
            "Confidence: {:.0}% ({} matched steps).",
            final_confidence * 100.0,
            matched_steps.iter().filter(|s| s.matched).count()
        );
        sentences.push(s4);

        sentences.join(" ")
    }

    /// One-liner (max 140 chars)
    pub fn one_liner(
        playbook_name: &str,
        trigger: &str,
        confidence: f64,
    ) -> String {
        let text = format!(
            "{}: {} ({}% confidence)",
            playbook_name,
            trigger,
            (confidence * 100.0) as i32
        );

        if text.len() > 140 {
            format!("{}…", &text[..137])
        } else {
            text
        }
    }

    /// Convert confidence to plain English
    pub fn confidence_text(conf: f64) -> &'static str {
        match (conf * 100.0) as i32 {
            90..=100 => "very high",
            75..=89 => "high",
            50..=74 => "moderate",
            25..=49 => "low",
            _ => "very low",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_narrative_compile() {
        let step = PlaybookStep {
            step_id: "step1".to_string(),
            description: "unsigned binary execution".to_string(),
            matched: true,
            weight: 0.5,
            reason: "unsigned check failed".to_string(),
            evidence_ptrs: vec![],
        };

        let boost = ScoreBoost {
            reason: "first_seen_host".to_string(),
            delta: 0.1,
            evidence_ptrs: vec![],
        };

        let narrative = NarrativeCompiler::compile(
            "B",
            "Unsigned Exec + Network",
            &[step],
            &[boost],
            0.95,
            None,
        );

        assert!(narrative.contains("Unsigned Exec + Network"));
        assert!(narrative.contains("95%"));
    }

    #[test]
    fn test_one_liner_truncation() {
        let liner = NarrativeCompiler::one_liner(
            "Very Long Playbook Name",
            "This is a very long trigger description that should be truncated",
            0.85,
        );

        assert!(liner.len() <= 140);
        assert!(liner.contains("85%"));
    }

    #[test]
    fn test_confidence_text() {
        assert_eq!(NarrativeCompiler::confidence_text(0.95), "very high");
        assert_eq!(NarrativeCompiler::confidence_text(0.80), "high");
        assert_eq!(NarrativeCompiler::confidence_text(0.60), "moderate");
    }
}
