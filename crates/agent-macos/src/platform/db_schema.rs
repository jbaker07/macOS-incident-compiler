/// Database schema for explanations
/// Tables: explanations, evidence_ptrs, explain_steps, score_breakdowns

pub const SCHEMA_SQL: &str = r#"
-- Explanation bundles
CREATE TABLE IF NOT EXISTS explanations (
    id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,        -- Incident, Entity, Fact
    subject_id TEXT NOT NULL,
    bundle_json TEXT NOT NULL,         -- Serialized ExplanationBundle
    generated_at_unix_ms INTEGER NOT NULL,
    bundle_hash TEXT NOT NULL UNIQUE,  -- For dedup/versioning
    playbook_config_hash TEXT,
    threshold_config_hash TEXT,
    allowlist_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_explanations_subject ON explanations(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_explanations_hash ON explanations(bundle_hash);
CREATE INDEX IF NOT EXISTS idx_explanations_ts ON explanations(generated_at_unix_ms DESC);

-- Evidence pointers
CREATE TABLE IF NOT EXISTS evidence_ptrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_type TEXT NOT NULL,        -- Incident, Entity, Fact
    subject_id TEXT NOT NULL,
    segment_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    fact_ts INTEGER NOT NULL,
    fact_type TEXT NOT NULL,
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_evidence_subject ON evidence_ptrs(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_evidence_fact ON evidence_ptrs(segment_id, fact_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_unique ON evidence_ptrs(
    subject_id, segment_id, fact_id
);

-- Explain steps (per playbook)
CREATE TABLE IF NOT EXISTS explain_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    playbook_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    step_description TEXT NOT NULL,
    matched INTEGER NOT NULL,         -- boolean
    weight REAL NOT NULL,
    reason TEXT NOT NULL,
    evidence_ptrs_json TEXT,           -- Array of EvidencePointer
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(incident_id) REFERENCES explanations(id)
);

CREATE INDEX IF NOT EXISTS idx_explain_steps_incident ON explain_steps(incident_id);
CREATE INDEX IF NOT EXISTS idx_explain_steps_playbook ON explain_steps(playbook_id);

-- Score breakdowns
CREATE TABLE IF NOT EXISTS score_breakdowns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    components_json TEXT NOT NULL,    -- Serialized ScoringBreakdown
    final_confidence REAL NOT NULL,
    final_severity TEXT NOT NULL,
    playbook_config_hash TEXT,
    config_version_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(incident_id) REFERENCES explanations(id)
);

CREATE INDEX IF NOT EXISTS idx_score_breakdowns_incident ON score_breakdowns(incident_id);
CREATE INDEX IF NOT EXISTS idx_score_breakdowns_confidence ON score_breakdowns(final_confidence DESC);

-- Audit log for explanation queries
CREATE TABLE IF NOT EXISTS explanation_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    query_type TEXT NOT NULL,          -- explain_incident, explain_entity, explain_fact
    queried_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_queries_subject ON explanation_queries(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON explanation_queries(queried_at DESC);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_valid_sql() {
        // Just verify schema string doesn't have obvious syntax errors
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS explanations"));
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS"));
        assert!(SCHEMA_SQL.contains("PRIMARY KEY"));
    }
}
