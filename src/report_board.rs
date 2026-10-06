//! Anonymous report publication; only explicitly published document versions are exposed.
use crate::runtime::Office;
use authority::authority::Authority;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Html,
    routing::get,
};
use serde::Deserialize;
use std::net::SocketAddr;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub key: std::path::PathBuf,
}
#[derive(Clone)]
struct Board {
    authority: Authority<Office>,
    identity: identity::PeerId,
}
#[derive(Deserialize)]
struct Page {
    after: Option<String>,
}
const PAGE_SIZE: usize = 50;
pub async fn serve(authority: Authority<Office>, config: Config) -> anyhow::Result<()> {
    let identity = identity::Identity::load(&config.key)?.peer_id();
    let app = Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("report_board.html")) }),
        )
        .route("/reports.json", get(list))
        .route("/reports/{id}", get(document))
        .with_state(Board {
            authority,
            identity,
        });
    axum::serve(tokio::net::TcpListener::bind(config.bind).await?, app).await?;
    Ok(())
}
async fn list(
    State(board): State<Board>,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let state = board
        .authority
        .state(board.identity)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut selected = state
        .domain
        .inner
        .office
        .publications
        .iter()
        .filter(|(id, _)| page.after.as_ref().is_none_or(|a| *id > a))
        .take(PAGE_SIZE + 1)
        .collect::<Vec<_>>();
    let more = selected.len() > PAGE_SIZE;
    selected.truncate(PAGE_SIZE);
    let next = if more {
        selected.last().map(|(id, _)| (*id).clone())
    } else {
        None
    };
    let reports = selected
        .into_iter()
        .map(|(id, report)| serde_json::json!({"id":id,"report":report}))
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({"reports":reports,"next":next})))
}
async fn document(
    State(board): State<Board>,
    Path(id): Path<String>,
) -> Result<([(axum::http::header::HeaderName, &'static str); 2], Vec<u8>), StatusCode> {
    let state = board
        .authority
        .state(board.identity)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let report = state
        .domain
        .inner
        .office
        .publications
        .get(&id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let bytes = state
        .domain
        .inner
        .files
        .read(&report.output)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            ),
            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    ))
}
