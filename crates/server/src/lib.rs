//! edr-server: a small read only HTTP API over the detections in workbench.db,
//! plus the detections page.
//!
//! Routes:
//!
//! - `GET /` redirects to `/ui/index.html`
//! - `GET /ui/index.html` the detections page (compiled into the binary)
//! - `GET /api` a short list of these endpoints
//! - `GET /health`, `GET /api/health`
//! - `GET /api/signals?host=&signal_type=&severity=&limit=`
//! - `GET /api/signals/stats`
//! - `GET /api/signals/:id`
//! - `GET /api/signals/:id/explain`

pub mod db;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use db::Database;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The detections page, compiled in so the binary works from any folder.
pub const INDEX_HTML: &str = include_str!("../../../ui/index.html");

const API_PAGE: &str = r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Incident Compiler API</title>
<style>body{font-family:-apple-system,sans-serif;max-width:800px;margin:40px auto;padding:0 16px}code{background:#eee;padding:2px 6px;border-radius:3px}li{margin:6px 0}</style>
</head>
<body>
<h1>Incident Compiler API</h1>
<p><a href="/ui/index.html">Open the detections page</a></p>
<ul>
<li>GET <code>/api/health</code> service status and version</li>
<li>GET <code>/api/signals</code> detections stored by edr-locald (query: host, signal_type, severity, limit)</li>
<li>GET <code>/api/signals/stats</code> counts by severity, host and playbook</li>
<li>GET <code>/api/signals/:id</code> one detection</li>
<li>GET <code>/api/signals/:id/explain</code> playbook slots, evidence pointers and the audit events behind them</li>
</ul>
</body>
</html>"#;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn ok<T: Serialize>(data: T) -> Response {
    Json(ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    })
    .into_response()
}

fn err(status: StatusCode, message: String) -> Response {
    (
        status,
        Json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some(message),
        }),
    )
        .into_response()
}

fn db_error(e: rusqlite::Error) -> Response {
    err(StatusCode::INTERNAL_SERVER_ERROR, format!("database error: {}", e))
}

#[derive(Deserialize)]
struct SignalQuery {
    host: Option<String>,
    signal_type: Option<String>,
    severity: Option<String>,
    limit: Option<usize>,
}

async fn health(State(db): State<Arc<Database>>) -> Response {
    let database = if db.health_check().is_ok() { "ok" } else { "error" };
    Json(serde_json::json!({
        "status": "ok",
        "service": "edr-server",
        "version": env!("CARGO_PKG_VERSION"),
        "database": database,
    }))
    .into_response()
}

async fn list_signals(State(db): State<Arc<Database>>, Query(q): Query<SignalQuery>) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    match db.list_signals(q.host.as_deref(), q.signal_type.as_deref(), q.severity.as_deref(), limit) {
        Ok(signals) => ok(signals),
        Err(e) => db_error(e),
    }
}

async fn signal_stats(State(db): State<Arc<Database>>) -> Response {
    match db.signal_stats() {
        Ok(stats) => ok(stats),
        Err(e) => db_error(e),
    }
}

async fn get_signal(State(db): State<Arc<Database>>, Path(id): Path<String>) -> Response {
    match db.get_signal(&id) {
        Ok(Some(signal)) => ok(signal),
        Ok(None) => err(StatusCode::NOT_FOUND, format!("signal '{}' not found", id)),
        Err(e) => db_error(e),
    }
}

async fn explain_signal(State(db): State<Arc<Database>>, Path(id): Path<String>) -> Response {
    match db.get_signal(&id) {
        Ok(Some(_)) => {}
        Ok(None) => return err(StatusCode::NOT_FOUND, format!("signal '{}' not found", id)),
        Err(e) => return db_error(e),
    }
    match db.get_signal_explanation(&id) {
        Ok(Some(explanation)) => ok(explanation),
        Ok(None) => err(StatusCode::NOT_FOUND, format!("no explanation stored for '{}'", id)),
        Err(e) => db_error(e),
    }
}

async fn index_page() -> impl IntoResponse {
    Html(INDEX_HTML)
}

/// Build the router. Used by main.rs and by the tests.
pub fn router(db: Arc<Database>) -> Router {
    // No CORS layer: the page is served from this origin, and without CORS
    // headers a browser will not let any other site read these responses.
    Router::new()
        .route("/", get(|| async { Redirect::temporary("/ui/index.html") }))
        .route("/ui", get(|| async { Redirect::temporary("/ui/index.html") }))
        .route("/ui/index.html", get(index_page))
        .route("/api", get(|| async { Html(API_PAGE) }))
        .route("/health", get(health))
        .route("/api/health", get(health))
        .route("/api/signals", get(list_signals))
        .route("/api/signals/stats", get(signal_stats))
        .route("/api/signals/:id", get(get_signal))
        .route("/api/signals/:id/explain", get(explain_signal))
        .with_state(db)
}
