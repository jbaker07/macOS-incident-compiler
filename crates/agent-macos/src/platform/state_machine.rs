/// Playbook state machine: TTL management, step matching, incident generation
/// Spec §4: Deterministic scoring, negative conditions, idempotent upsert

use crate::macos_detect::*;
use std::collections::HashMap;

pub struct PlaybookStateMachine {
    states: HashMap<String, PlaybookState>, // keyed by dedupe_key
    ttl_ms: u64,
}

impl PlaybookStateMachine {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            states: HashMap::new(),
            ttl_ms,
        }
    }

    /// Record a matched step in a playbook. Returns incident if all steps matched and ready.
    pub fn record_step(
        &mut self,
        dedupe_key: &str,
        step: &str,
        evidence_ptr: EvidencePtr,
        ts: u64,
    ) -> Option<PlaybookState> {
        let state = self.states.entry(dedupe_key.to_string()).or_insert_with(|| {
            PlaybookState {
                session_key_hash: "".to_string(),
                matched_steps: Default::default(),
                evidence_ptrs: vec![],
                first_event_ts: ts,
                last_event_ts: ts,
                created_ts: current_unix_ms(),
                updated_ts: current_unix_ms(),
                expires_ts: current_unix_ms() + self.ttl_ms,
                step_data: Default::default(),
            }
        });

        state.matched_steps.insert(step.to_string());
        state.evidence_ptrs.push(evidence_ptr);
        state.last_event_ts = ts;
        state.updated_ts = current_unix_ms();

        // Check if state is expired
        if current_unix_ms() > state.expires_ts {
            self.states.remove(dedupe_key);
            return None;
        }

        Some(state.clone())
    }

    /// Evict expired states
    pub fn evict_expired(&mut self, now_ms: u64) {
        self.states.retain(|_, state| now_ms <= state.expires_ts);
    }

    /// Upsert playbook state: if dedupe_key exists, update; else create
    pub fn upsert_state(
        &mut self,
        dedupe_key: String,
        mut state: PlaybookState,
    ) -> (PlaybookState, bool) {
        // Check if state exists for this key
        if let Some(existing_state) = self.states.get(&dedupe_key) {
            // Merge evidence pointers
            let mut merged_evidence = existing_state.evidence_ptrs.clone();
            merged_evidence.extend(state.evidence_ptrs.clone());

            // De-dup evidence
            let unique_evidence: Vec<_> = {
                let mut seen = std::collections::HashSet::new();
                merged_evidence
                    .into_iter()
                    .filter(|e| seen.insert((e.segment_id.clone(), e.fact_id.clone())))
                    .collect()
            };

            state.evidence_ptrs = unique_evidence;
            state.updated_ts = current_unix_ms();

            // Store back the merged state
            self.states.insert(dedupe_key, state.clone());

            (state, false) // false = updated, not new
        } else {
            // Store new state
            self.states.insert(dedupe_key, state.clone());
            (state, true) // true = new
        }
    }
}

// ==================== Incident Factory ====================

pub struct IncidentFactory;

impl IncidentFactory {
    pub fn create(
        playbook_id: &str,
        severity: Severity,
        confidence: f64,
        host: &str,
        uid: Option<u32>,
        session_key: &SessionKey,
        exe_path: Option<String>,
        mitre_tags: Vec<String>,
        summary: String,
        evidence_ptrs: Vec<EvidencePtr>,
        ts_window: (u64, u64),
    ) -> Incident {
        let dedupe_key = Self::generate_dedupe_key(
            playbook_id,
            host,
            uid,
            &exe_path,
            ts_window.0,
        );

        let id = format!("{}:{}", playbook_id, sha2_hash(&dedupe_key));

        Incident {
            id,
            dedupe_key,
            playbook_id: playbook_id.to_string(),
            severity,
            confidence,
            host: host.to_string(),
            uid,
            session_key_hash: session_key.deterministic_hash(),
            exe_path,
            mitre_tags,
            summary,
            first_seen_ts: ts_window.0,
            last_seen_ts: ts_window.1,
            window_start_ts: ts_window.0,
            window_end_ts: ts_window.1,
            evidence_ptrs,
            tags: vec![],
            explanation: None,
        }
    }

    fn generate_dedupe_key(
        playbook_id: &str,
        host: &str,
        uid: Option<u32>,
        exe_path: &Option<String>,
        ts: u64,
    ) -> String {
        let hour_bucket = hour_bucket(ts);
        let exe_part = exe_path.as_deref().unwrap_or("unknown");
        let uid_part = uid.unwrap_or(0);

        format!(
            "{}:{}:{}:{}:{}",
            playbook_id, host, uid_part, exe_part, hour_bucket
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_machine_record_step() {
        let mut sm = PlaybookStateMachine::new(60_000);
        let ts = current_unix_ms();

        let evidence = EvidencePtr {
            segment_id: "seg1".to_string(),
            fact_id: "fact1".to_string(),
            fact_type: "ProcExec".to_string(),
            ts,
        };

        let state = sm.record_step("key1", "step1", evidence, ts);
        assert!(state.is_some());
        assert!(state.unwrap().matched_steps.contains("step1"));
    }

    #[test]
    fn test_incident_upsert_idempotency() {
        let mut sm = PlaybookStateMachine::new(60_000);
        let dedupe = "test_key".to_string();
        let ts = current_unix_ms();

        let state1 = PlaybookState {
            session_key_hash: "hash".to_string(),
            matched_steps: {
                let mut s = std::collections::HashSet::new();
                s.insert("step1".to_string());
                s
            },
            evidence_ptrs: vec![],
            first_event_ts: ts,
            last_event_ts: ts,
            created_ts: ts,
            updated_ts: ts,
            expires_ts: ts + 60_000,
            step_data: std::collections::HashMap::new(),
        };

        let (result1, is_new1) = sm.upsert_state(dedupe.clone(), state1.clone());
        assert!(is_new1);

        let (result2, is_new2) = sm.upsert_state(dedupe, state1);
        assert!(!is_new2); // Second upsert = update
    }
}
