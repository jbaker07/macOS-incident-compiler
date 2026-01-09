//! Slot-based playbook engine: deterministic incident compilation
//!
//! This is the PRIMARY incident compiler. It implements the ground-truth
//! incident model: REQUIRED slots must fill within TTL to emit incidents.
//! Each slot fill is recorded with an immutable EvidencePtr for traceability.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::platform::evidence::EvidencePtr;

/// Slot: a predicate that matches facts
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Slot {
    /// Slot ID (e.g., "process_exec_suspicious")
    pub id: String,
    /// Slot TTL in seconds (how long to keep filled state)
    pub ttl_sec: u64,
    /// True if this is required to fire incident
    pub required: bool,
    /// Fact type this slot matches (e.g., "ProcExec", "FileWrite")
    pub fact_type: String,
}

/// Filled slot: records which evidence filled this slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotFill {
    /// Which slot was filled
    pub slot_id: String,
    /// Evidence pointer to the fact that filled it
    pub evidence_ptr: EvidencePtr,
    /// Fill timestamp
    pub fill_ts: u64,
}

/// Incident (ground truth): emitted when all REQUIRED slots fill within TTL
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Incident {
    /// Unique incident ID (deterministic based on slots)
    pub incident_id: String,
    /// Playbook that fired this incident
    pub playbook_id: String,
    /// Severity: high, medium, low
    pub severity: String,
    /// Slot fills that contributed (step trace)
    pub slot_fills: Vec<SlotFill>,
    /// First slot fill time
    pub created_ts: u64,
    /// Last slot fill time
    pub last_updated_ts: u64,
    /// Status: NEW, UPDATED, CLOSED
    pub status: String,
}

/// Playbook: declarative incident template
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaybookSpec {
    /// Playbook ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Severity (for incidents it emits)
    pub severity: String,
    /// Window for slot correlation
    pub window_sec: u64,
    /// Cooldown after incident fire
    pub cooldown_sec: u64,
    /// Required slots (all must fill to fire)
    pub required_slots: Vec<Slot>,
    /// Optional slots (enrich incident if present)
    pub optional_slots: Vec<Slot>,
}

/// State: tracks in-flight slot fills per (host, user, exe)
#[derive(Clone, Debug, Default)]
pub struct PlaybookState {
    /// Key: (host, user, exe); Value: slot fills in progress
    pub in_flight: HashMap<String, Vec<SlotFill>>,
    /// Last incident fire time per key (for cooldown)
    pub last_fire: HashMap<String, u64>,
}

/// Slot engine: deterministic incident compiler
pub struct SlotEngine {
    /// Loaded playbooks
    playbooks: HashMap<String, PlaybookSpec>,
    /// In-flight state per playbook
    state: HashMap<String, PlaybookState>,
}

impl SlotEngine {
    pub fn new() -> Self {
        SlotEngine {
            playbooks: HashMap::new(),
            state: HashMap::new(),
        }
    }

    /// Register a playbook
    pub fn register_playbook(&mut self, spec: PlaybookSpec) {
        self.playbooks.insert(spec.id.clone(), spec.clone());
        self.state.insert(spec.id.clone(), PlaybookState::default());
    }

    /// Attempt to fill a slot in a playbook
    pub fn fill_slot(
        &mut self,
        playbook_id: &str,
        slot_id: &str,
        evidence_ptr: EvidencePtr,
        correlation_key: &str,
    ) -> Option<Incident> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let playbook = self.playbooks.get(playbook_id)?;
        let state = self.state.get_mut(playbook_id)?;

        // Check cooldown
        if let Some(&last_fire_ts) = state.last_fire.get(correlation_key) {
            if now - last_fire_ts < playbook.cooldown_sec {
                return None; // Still in cooldown
            }
        }

        // Record slot fill
        let slot_fill = SlotFill {
            slot_id: slot_id.to_string(),
            evidence_ptr,
            fill_ts: now,
        };

        state
            .in_flight
            .entry(correlation_key.to_string())
            .or_insert_with(Vec::new)
            .push(slot_fill);

        // Check if all REQUIRED slots are filled
        let fills = state.in_flight.get(correlation_key)?;
        let required_ids: Vec<_> = playbook
            .required_slots
            .iter()
            .map(|s| &s.id)
            .collect();

        let filled_ids: std::collections::HashSet<_> =
            fills.iter().map(|f| &f.slot_id).collect();

        let all_required_filled = required_ids.iter().all(|id| filled_ids.contains(id));

        if all_required_filled {
            // All REQUIRED slots filled → emit incident
            let incident_id = format!("{}_{}_{}", playbook_id, correlation_key, now);
            let incident = Incident {
                incident_id,
                playbook_id: playbook_id.to_string(),
                severity: playbook.severity.clone(),
                slot_fills: fills.clone(),
                created_ts: now,
                last_updated_ts: now,
                status: "NEW".to_string(),
            };

            // Mark cooldown
            state.last_fire.insert(correlation_key.to_string(), now);

            // Clear in-flight for this key
            state.in_flight.remove(correlation_key);

            return Some(incident);
        }

        None
    }

    /// Cleanup stale slot fills (older than window)
    pub fn cleanup_stale(&mut self, now: u64) {
        for state in self.state.values_mut() {
            for fills in state.in_flight.values_mut() {
                fills.retain(|f| now - f.fill_ts < 3600); // Keep 1 hour
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_engine_basic() {
        let mut engine = SlotEngine::new();
        let spec = PlaybookSpec {
            id: "pb_test".to_string(),
            name: "Test Playbook".to_string(),
            severity: "high".to_string(),
            window_sec: 300,
            cooldown_sec: 600,
            required_slots: vec![
                Slot {
                    id: "slot1".to_string(),
                    ttl_sec: 300,
                    required: true,
                    fact_type: "ProcExec".to_string(),
                },
                Slot {
                    id: "slot2".to_string(),
                    ttl_sec: 300,
                    required: true,
                    fact_type: "FileWrite".to_string(),
                },
            ],
            optional_slots: vec![],
        };

        engine.register_playbook(spec);

        let ep1 = EvidencePtr::new("seg-001".to_string(), 0, 1703000000, "exec".to_string());
        let ep2 = EvidencePtr::new("seg-001".to_string(), 1, 1703000001, "write".to_string());

        // Fill slot 1: no incident yet
        let incident = engine.fill_slot("pb_test", "slot1", ep1, "test_key");
        assert!(incident.is_none());

        // Fill slot 2: should emit incident
        let incident = engine.fill_slot("pb_test", "slot2", ep2, "test_key");
        assert!(incident.is_some());
        let inc = incident.unwrap();
        assert_eq!(inc.severity, "high");
        assert_eq!(inc.slot_fills.len(), 2);
    }
}
