use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{AppState, auth_helpers::extract_token};

// ─── GET /amps ────────────────────────────────────────────────────────────────
// Returns the caller's available Amp count and the list of servers they've boosted.

pub async fn get_amps(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match extract_token(&state.signing_key, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT amps_available FROM user_amps WHERE user_id = $1",
    )
    .bind(&claims.uid)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let amps_available = row.map(|(n,)| n).unwrap_or(0);

    let applied: Vec<(String, i64)> = sqlx::query_as(
        "SELECT server_url, applied_at FROM server_amps WHERE user_id = $1 ORDER BY applied_at DESC",
    )
    .bind(&claims.uid)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let applied_json: Vec<serde_json::Value> = applied
        .into_iter()
        .map(|(url, at)| json!({ "server_url": url, "applied_at": at }))
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "amps_available": amps_available,
            "applied": applied_json,
        })),
    )
        .into_response()
}

// ─── POST /amps/apply ─────────────────────────────────────────────────────────
// Applies one of the caller's Amps to a server, enabling server perks.

#[derive(Deserialize)]
pub struct ApplyAmpRequest {
    pub server_url: String,
}

pub async fn apply_amp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ApplyAmpRequest>,
) -> impl IntoResponse {
    let claims = match extract_token(&state.signing_key, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    if !claims.premium {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Radiant subscription required to use Amps"})),
        )
            .into_response();
    }

    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT amps_available FROM user_amps WHERE user_id = $1",
    )
    .bind(&claims.uid)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let amps_available = match row {
        Some((n,)) => n,
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "No Amps allocation found"})),
            )
                .into_response()
        }
    };

    if amps_available <= 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No Amps available — all 5 have been applied"})),
        )
            .into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let insert_result = sqlx::query(
        "INSERT INTO server_amps (user_id, server_url, applied_at) VALUES ($1, $2, $3)",
    )
    .bind(&claims.uid)
    .bind(&body.server_url)
    .bind(now)
    .execute(&state.db)
    .await;

    if let Err(e) = insert_result {
        let msg = e.to_string();
        if msg.contains("unique") || msg.contains("duplicate") {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "Already applied an Amp to this server"})),
            )
                .into_response();
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to apply Amp"})),
        )
            .into_response();
    }

    let _ = sqlx::query(
        "UPDATE user_amps SET amps_available = amps_available - 1 WHERE user_id = $1",
    )
    .bind(&claims.uid)
    .execute(&state.db)
    .await;

    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

// ─── POST /amps/remove ────────────────────────────────────────────────────────
// Removes the caller's Amp from a server, returning it to their available count.

#[derive(Deserialize)]
pub struct RemoveAmpRequest {
    pub server_url: String,
}

pub async fn remove_amp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RemoveAmpRequest>,
) -> impl IntoResponse {
    let claims = match extract_token(&state.signing_key, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let result = sqlx::query(
        "DELETE FROM server_amps WHERE user_id = $1 AND server_url = $2",
    )
    .bind(&claims.uid)
    .bind(&body.server_url)
    .execute(&state.db)
    .await;

    let rows_affected = match result {
        Ok(r) => r.rows_affected(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to remove Amp"})),
            )
                .into_response()
        }
    };

    if rows_affected == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No Amp applied to this server"})),
        )
            .into_response();
    }

    let _ = sqlx::query(
        "UPDATE user_amps SET amps_available = amps_available + 1 WHERE user_id = $1",
    )
    .bind(&claims.uid)
    .execute(&state.db)
    .await;

    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

// ─── GET /amps/server?server_url=... ──────────────────────────────────────────
// Public endpoint: returns the total Amp count for a server and which perks are active.
// Perks: discoverable (>= 2 Amps), emoji_packs (>= 1 Amp).

#[derive(Deserialize)]
pub struct ServerUrlQuery {
    pub server_url: String,
}

pub async fn server_amp_info(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ServerUrlQuery>,
) -> impl IntoResponse {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*) FROM server_amps WHERE server_url = $1",
    )
    .bind(&params.server_url)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let total_amps = row.map(|(n,)| n).unwrap_or(0);

    (
        StatusCode::OK,
        Json(json!({
            "server_url": params.server_url,
            "total_amps": total_amps,
            "perks": {
                "discoverable": total_amps >= 2,
                "emoji_packs": total_amps >= 1,
            },
        })),
    )
        .into_response()
}

// ─── Helpers (called from stripe.rs and shop.rs) ──────────────────────────────

/// Grants 5 Amps to a newly subscribed user. No-ops if they already have a row
/// (e.g. subscription renewal) so existing Amp counts are preserved.
pub async fn grant_amps(db: &sqlx::PgPool, user_id: &str) {
    let _ = sqlx::query(
        "INSERT INTO user_amps (user_id, amps_available) VALUES ($1, 5) ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .execute(db)
    .await;
}

/// Revokes all Amps when a subscription is cancelled — removes server boosts too.
pub async fn revoke_amps(db: &sqlx::PgPool, user_id: &str) {
    let _ = sqlx::query("DELETE FROM server_amps WHERE user_id = $1")
        .bind(user_id)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM user_amps WHERE user_id = $1")
        .bind(user_id)
        .execute(db)
        .await;
}
