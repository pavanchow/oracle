//! A small HTTP API over the Oracle engine, so a UI or an agent can run OQL
//! against a loaded graph.
//!
//!   GET  /health          -> "ok"
//!   GET  /graph           -> the loaded graph JSON (for visualization)
//!   POST /query {"oql":..} -> structured query result, or 400 with {"error":..}

use crate::Graph;
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

struct AppState {
    graph: Graph,
    graph_json: Value,
}

#[derive(Deserialize)]
struct QueryReq {
    oql: String,
}

pub fn serve(graph_path: &str, port: u16) -> Result<()> {
    let raw = std::fs::read_to_string(graph_path)?;
    let graph = Graph::from_json(&raw)?;
    let graph_json: Value = serde_json::from_str(&raw)?;
    let state = Arc::new(AppState { graph, graph_json });

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(|| async { "ok" }))
        .route("/graph", get(get_graph))
        .route("/query", post(post_query))
        .with_state(state);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
        eprintln!("oracle console on http://127.0.0.1:{port}  (UI at /, POST /query, GET /graph)");
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

async fn get_graph(State(s): State<Arc<AppState>>) -> Json<Value> {
    Json(s.graph_json.clone())
}

async fn post_query(State(s): State<Arc<AppState>>, Json(req): Json<QueryReq>) -> impl IntoResponse {
    match s.graph.run_oql(&req.oql) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}
