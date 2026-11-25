//! Route tests for edr-server against a workbench.db laid out the way edr-locald writes it.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use edr_server::db::Database;
use http_body_util::BodyExt;
use rusqlite::{params, Connection};
use std::sync::Arc;
use tower::ServiceExt;

fn seeded_db(dir: &std::path::Path) -> Arc<Database> {
    let path = dir.join("workbench.db");
    let db = Database::open(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    let rows = [
        ("hyp_a", "macos_keychain_dump", "HIGH", "mac-1", 2000),
        ("hyp_b", "macos_osascript_shell", "MEDIUM", "mac-1", 3000),
        ("hyp_c", "macos_keychain_dump", "HIGH", "mac-2", 1000),
    ];
    for (id, kind, severity, host, ts) in rows {
        conn.execute(
            "INSERT INTO signals (signal_id, signal_type, severity, host, ts, ts_start, ts_end, metadata,
             evidence_ptrs, dropped_evidence_count, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, ?6, ?7, 0, 'now')",
            params![
                id,
                kind,
                severity,
                host,
                ts,
                r#"{"title":"t"}"#,
                r#"[{"stream_id":"bsm","segment_id":0,"record_index":12}]"#
            ],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO signal_explanations (signal_id, explanation_json, created_at) VALUES ('hyp_a', ?1, 'now')",
        params![r#"{"playbook_id":"macos_keychain_dump","evidence_verified":true}"#],
    )
    .unwrap();
    Arc::new(db)
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let response = app.oneshot(Request::get(uri).body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn health_and_pages() {
    let dir = tempfile::tempdir().unwrap();
    let app = edr_server::router(seeded_db(dir.path()));
    let (status, body) = get(app.clone(), "/api/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["database"], "ok");

    let (status, _) = get(app.clone(), "/").await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let (status, body) = get(app.clone(), "/ui/index.html").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<title>Incident Compiler</title>"));
    let (status, body) = get(app.clone(), "/api").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("/api/signals/:id/explain"));
    // Routes from the old workbench are gone.
    let (status, _) = get(app, "/api/documents").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_filter_and_stats() {
    let dir = tempfile::tempdir().unwrap();
    let app = edr_server::router(seeded_db(dir.path()));
    let (_, body) = get(app.clone(), "/api/signals").await;
    let all = json(&body)["data"].as_array().unwrap().clone();
    let ids: Vec<&str> = all.iter().map(|s| s["signal_id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["hyp_b", "hyp_a", "hyp_c"], "newest first");
    assert_eq!(all[0]["evidence_ptrs"][0]["record_index"], 12);

    let (_, body) = get(app.clone(), "/api/signals?host=mac-1&severity=HIGH").await;
    let filtered = json(&body)["data"].as_array().unwrap().clone();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["signal_id"], "hyp_a");

    let (_, body) = get(app.clone(), "/api/signals?limit=1").await;
    assert_eq!(json(&body)["data"].as_array().unwrap().len(), 1);

    let (_, body) = get(app, "/api/signals/stats").await;
    let stats = json(&body)["data"].clone();
    assert_eq!(stats["total"], 3);
    assert_eq!(stats["by_severity"]["HIGH"], 2);
    assert_eq!(stats["by_type"]["macos_keychain_dump"], 2);
    assert_eq!(stats["by_host"]["mac-1"], 2);
}

#[tokio::test]
async fn one_signal_and_its_explanation() {
    let dir = tempfile::tempdir().unwrap();
    let app = edr_server::router(seeded_db(dir.path()));
    let (status, body) = get(app.clone(), "/api/signals/hyp_a").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["data"]["signal_type"], "macos_keychain_dump");

    let (status, body) = get(app.clone(), "/api/signals/hyp_a/explain").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["data"]["evidence_verified"], true);

    let (status, body) = get(app.clone(), "/api/signals/hyp_b/explain").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(json(&body)["error"].as_str().unwrap().contains("no explanation"));

    let (status, _) = get(app, "/api/signals/missing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
