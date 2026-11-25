//! edr-server entry point.
//!
//! USAGE: edr-server [--port N] [--telemetry-root DIR]
//!
//! Serves the detections in DIR/workbench.db on 127.0.0.1. The API has no
//! authentication, so it stays on loopback unless EDR_SERVER_BIND says
//! otherwise.

use edr_server::db::Database;
use std::path::PathBuf;
use std::sync::Arc;

fn arg_value(args: &[String], names: &[&str]) -> Option<String> {
    let position = args.iter().position(|a| names.contains(&a.as_str()))?;
    args.get(position + 1).cloned()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "edr_server=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("edr-server: HTTP API and detections page for edr-locald's workbench.db\n");
        println!("USAGE:\n  edr-server [--port N] [--telemetry-root DIR]\n");
        println!("  --port N              port on 127.0.0.1 (default: $EDR_SERVER_PORT, else 3000)");
        println!("  --telemetry-root DIR  folder holding workbench.db (default: $EDR_TELEMETRY_ROOT, else ./telemetry_output)");
        return;
    }
    let port: u16 = arg_value(&args, &["--port", "-p"])
        .or_else(|| std::env::var("EDR_SERVER_PORT").ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    let root = arg_value(&args, &["--telemetry-root", "-t"])
        .or_else(|| std::env::var("EDR_TELEMETRY_ROOT").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("telemetry_output"));

    if let Err(e) = std::fs::create_dir_all(&root) {
        eprintln!("edr-server: cannot create {}: {}", root.display(), e);
        std::process::exit(1);
    }
    let db_path = root.join("workbench.db");
    let db = match Database::open(&db_path) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("edr-server: cannot open {}: {}", db_path.display(), e);
            std::process::exit(1);
        }
    };

    let bind = std::env::var("EDR_SERVER_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{}:{}", bind, port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("edr-server: cannot listen on {}: {}", addr, e);
            std::process::exit(1);
        }
    };
    tracing::info!("database {}", db_path.display());
    tracing::info!("listening on http://{}", addr);
    axum::serve(listener, edr_server::router(db))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap();
}
