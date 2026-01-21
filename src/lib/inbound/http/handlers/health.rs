use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::inbound::http::AppState;

pub async fn health_check(State(state): State<AppState>) -> Json<Value> {
    match state.health_service.health_check().await {
        Ok(_) => Json(json!({
            "status": "ok",
            "database": "connected"
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Json(json!({
                "status": "error",
                "database": "disconnected",
                "error": e.to_string()
            }))
        }
    }
}
