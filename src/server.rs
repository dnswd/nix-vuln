use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rust_embed::RustEmbed;
use std::sync::Arc;
use crate::graph_builder::GraphData;

#[derive(RustEmbed)]
#[folder = "frontend/dist"]
struct Assets;

pub fn app(graph: Arc<GraphData>) -> Router {
    Router::new()
        .route("/api/graph", get(api_graph))
        .fallback(static_handler)
        .with_state(graph)
}

pub async fn start_server(port: u16, graph_data: GraphData) -> anyhow::Result<()> {
    let app = app(Arc::new(graph_data));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    println!("Server running on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}
async fn api_graph(State(graph): State<Arc<GraphData>>) -> impl IntoResponse {
    Json(graph.as_ref().clone())
}

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        path = "index.html";
    }

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(content.data))
                .unwrap()
        }
        None => {
            if path == "index.html" {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from("404 Not Found"))
                    .unwrap()
            } else {
                // SPA fallback for react router if needed
                match Assets::get("index.html") {
                    Some(content) => {
                        let mime = mime_guess::from_path("index.html").first_or_octet_stream();
                        Response::builder()
                            .header(header::CONTENT_TYPE, mime.as_ref())
                            .body(Body::from(content.data))
                            .unwrap()
                    }
                    None => {
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Body::from("404 Not Found"))
                            .unwrap()
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;
    use crate::graph_builder::{GraphData, Node, Link};
    use axum::body::to_bytes;

    #[tokio::test]
    async fn test_api_graph() {
        let graph_data = GraphData {
            nodes: vec![Node {
                id: "node1".to_string(),
                label: "node1".to_string(),
                color: "green".to_string(),
                cves: vec![],
            }],
            links: vec![],
        };
        let app = app(Arc::new(graph_data.clone()));
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/graph")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        let returned_data: GraphData = serde_json::from_str(&body_str).unwrap();

        assert_eq!(returned_data.nodes.len(), 1);
        assert_eq!(returned_data.nodes[0].id, "node1");
    }
}
