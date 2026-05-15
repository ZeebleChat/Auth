use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use sqlx::Row;

use crate::AppState;
use crate::auth_helpers::extract_token;
use crate::beam::make_beam_identity;
use crate::models::{
    AddServerRequest, CreateCloudServerRequest, ErrorResponse, FriendIdPath, FriendRequestSummary,
    FriendSummary, ParentalControls, RegisterServerRequest, SendFriendRequest, ServerSummary, UrlPath,
};

// ── Servers ───────────────────────────────────────────────────────────────────

// POST /servers/register — server-to-server: a zeeble-chat server registers itself
pub async fn register_server(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterServerRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let server_url = req.server_url.trim();
    if server_url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "server_url is required".into(),
            }),
        ));
    }

    let token_header = headers
        .get("x-register-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(ref secret) = req.jwt_secret {
        if token_header != secret.as_str() {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid registration token".into(),
                }),
            ));
        }
    }

    sqlx::query(
        "INSERT INTO server_registry (server_url, owner_beam_identity, jwt_secret)
         VALUES ($1, $2, $3)
         ON CONFLICT(server_url) DO UPDATE SET
             owner_beam_identity = EXCLUDED.owner_beam_identity,
             jwt_secret = EXCLUDED.jwt_secret",
    )
    .bind(server_url)
    .bind(&req.owner_beam_identity)
    .bind(&req.jwt_secret)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to register server".into(),
            }),
        )
    })?;

    Ok(StatusCode::OK)
}

// GET /servers
pub async fn list_servers(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ServerSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    let rows = sqlx::query(
        "SELECT server_url, server_name, joined_at, is_owner
         FROM user_servers WHERE user_id = $1 ORDER BY joined_at DESC",
    )
    .bind(&claims.uid)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".into(),
            }),
        )
    })?;

    let servers: Vec<ServerSummary> = rows
        .into_iter()
        .map(|r| ServerSummary {
            server_url: r.try_get("server_url").unwrap_or_default(),
            server_name: r
                .try_get::<Option<String>, _>("server_name")
                .unwrap_or(None)
                .filter(|s| !s.is_empty()),
            joined_at: r.try_get("joined_at").unwrap_or_default(),
            is_owner: r.try_get("is_owner").unwrap_or(false),
        })
        .collect();

    Ok(Json(servers))
}

// POST /servers
pub async fn add_server(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddServerRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    if claims.account_type == "child" {
        let pc_val: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT parental_controls FROM users WHERE id = $1",
        )
        .bind(&claims.uid)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
        let pc: ParentalControls = pc_val.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        if !pc.can_join_servers {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse { error: "Joining servers is disabled by parental controls".into() }),
            ));
        }
    }

    let server_url = req.server_url.trim().to_string();
    if server_url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "server_url is required".into(),
            }),
        ));
    }

    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_servers WHERE user_id = $1 AND server_url = $2",
    )
    .bind(&claims.uid)
    .bind(&server_url)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if exists > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Server already added".into(),
            }),
        ));
    }

    // Enforce per-user server limit: 10 for free accounts, 200 for premium
    let server_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_servers WHERE user_id = $1",
    )
    .bind(&claims.uid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let limit: i64 = if claims.premium { 200 } else { 10 };
    if server_count >= limit {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: format!(
                    "Server limit reached ({limit}). {}",
                    if claims.premium { "You have reached the maximum of 200 servers." }
                    else { "Upgrade to premium to join up to 200 servers." }
                ),
            }),
        ));
    }

    let registry_row = sqlx::query(
        "SELECT owner_beam_identity FROM server_registry WHERE server_url = $1",
    )
    .bind(&server_url)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".into(),
            }),
        )
    })?;

    let is_owner = match registry_row {
        Some(row) => {
            let owner: Option<String> = row.try_get("owner_beam_identity").unwrap_or(None);
            owner.map_or(false, |o| o == claims.sub)
        }
        None => {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM user_servers WHERE server_url = $1",
            )
            .bind(&server_url)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
            count == 0
        }
    };

    sqlx::query(
        "INSERT INTO user_servers (user_id, server_url, server_name, is_owner) VALUES ($1, $2, $3, $4)",
    )
    .bind(&claims.uid)
    .bind(&server_url)
    .bind(req.server_name.as_deref())
    .bind(is_owner)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to add server".into(),
            }),
        )
    })?;

    Ok(StatusCode::CREATED)
}

// DELETE /servers/:url
pub async fn remove_server(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(UrlPath { url }): Path<UrlPath>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    if claims.account_type == "child" {
        let pc_val: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT parental_controls FROM users WHERE id = $1",
        )
        .bind(&claims.uid)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
        let pc: ParentalControls = pc_val.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        if !pc.can_leave_servers {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse { error: "Leaving servers is disabled by parental controls".into() }),
            ));
        }
    }

    let result = sqlx::query(
        "DELETE FROM user_servers WHERE user_id = $1 AND server_url = $2",
    )
    .bind(&claims.uid)
    .bind(&url)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to remove server".into(),
            }),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Server not found".into(),
            }),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Cloud server creation ─────────────────────────────────────────────────────

// POST /servers/cloud — create a managed cloud server via zcloud.
//
// 1. Authenticate the calling user.
// 2. Forward the creation request to zcloud.
// 3. Register the resulting server in server_registry (type = 'cloud').
// 4. Add it to the user's server list as owner.
// 5. Return the full server info.
pub async fn create_cloud_server(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCloudServerRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), (axum::http::StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    // Enforce cloud server quota: 10 for free accounts, 30 for premium
    let cloud_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM server_registry WHERE owner_beam_identity = $1 AND server_type = 'cloud'",
    )
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let cloud_limit: i64 = if claims.premium { 30 } else { 10 };
    if cloud_count >= cloud_limit {
        return Err((
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: format!(
                    "Cloud server limit reached ({cloud_limit}). {}",
                    if claims.premium { "You have reached the maximum of 30 cloud servers." }
                    else { "Upgrade to premium to create up to 30 cloud servers." }
                ),
            }),
        ));
    }

    // Enforce total server limit: 10 for free accounts, 200 for premium
    let server_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_servers WHERE user_id = $1",
    )
    .bind(&claims.uid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let limit: i64 = if claims.premium { 200 } else { 10 };
    if server_count >= limit {
        return Err((
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: format!(
                    "Server limit reached ({limit}). {}",
                    if claims.premium { "You have reached the maximum of 200 servers." }
                    else { "Upgrade to premium to create up to 200 servers." }
                ),
            }),
        ));
    }

    let zcloud_url = std::env::var("ZCLOUD_URL")
        .unwrap_or_else(|_| "http://zcloud:3003".to_string());

    // Call zcloud to provision the server.
    let client = reqwest::Client::new();
    let zcloud_resp = client
        .post(format!("{}/servers", zcloud_url.trim_end_matches('/')))
        .header("Authorization", headers.get("Authorization").and_then(|v| v.to_str().ok()).unwrap_or(""))
        .json(&serde_json::json!({
            "name":     req.name,
            "about":    req.about,
            "owner_id": claims.sub,
        }))
        .send()
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(ErrorResponse { error: format!("Could not reach zcloud: {e}") }),
            )
        })?;

    if !zcloud_resp.status().is_success() {
        let status = zcloud_resp.status();
        let body: serde_json::Value = zcloud_resp.json().await.unwrap_or_default();
        let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("zcloud error").to_string();
        return Err((
            axum::http::StatusCode::BAD_GATEWAY,
            Json(ErrorResponse { error: format!("zcloud {status}: {msg}") }),
        ));
    }

    let server_data: serde_json::Value = zcloud_resp.json().await.map_err(|e| {
        (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(ErrorResponse { error: format!("Bad zcloud response: {e}") }),
        )
    })?;

    let server_id = server_data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let server_url = server_data.get("server_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let server_name = server_data.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Register in server_registry.
    let _ = sqlx::query(
        "INSERT INTO server_registry (server_url, owner_beam_identity, server_type, cloud_server_id)
         VALUES ($1, $2, 'cloud', $3)
         ON CONFLICT (server_url) DO UPDATE SET
             owner_beam_identity = EXCLUDED.owner_beam_identity,
             server_type = 'cloud',
             cloud_server_id = EXCLUDED.cloud_server_id",
    )
    .bind(&server_url)
    .bind(&claims.sub)
    .bind(&server_id)
    .execute(&state.db)
    .await;

    // Add to user's server list as owner.
    let _ = sqlx::query(
        "INSERT INTO user_servers (user_id, server_url, server_name, is_owner)
         VALUES ($1, $2, $3, true)
         ON CONFLICT DO NOTHING",
    )
    .bind(&claims.uid)
    .bind(&server_url)
    .bind(&server_name)
    .execute(&state.db)
    .await;

    Ok((axum::http::StatusCode::CREATED, Json(server_data)))
}

// ── Friends ───────────────────────────────────────────────────────────────────

// GET /friends
pub async fn list_friends(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<FriendSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    let rows = sqlx::query(
        "SELECT u.id, u.display_name, u.beam_tag, u.account_type, u.avatar_attachment_id, f.status, f.created_at
         FROM friendships f
         JOIN users u ON f.friend_user_id = u.id
         WHERE f.user_id = $1 AND f.status = 'accepted'
         ORDER BY LOWER(u.display_name)",
    )
    .bind(&claims.uid)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".into(),
            }),
        )
    })?;

    let friends: Vec<FriendSummary> = rows
        .into_iter()
        .map(|r| {
            let dn: String = r.try_get("display_name").unwrap_or_default();
            let bt: String = r.try_get("beam_tag").unwrap_or_default();
            let at: String = r.try_get("account_type").unwrap_or_default();
            let av: Option<i64> = r.try_get("avatar_attachment_id").unwrap_or(None);
            FriendSummary {
                id: r.try_get("id").unwrap_or_default(),
                beam_identity: make_beam_identity(&dn, &bt, &at),
                display_name: dn,
                status: r.try_get("status").unwrap_or_default(),
                created_at: r.try_get("created_at").unwrap_or_default(),
                avatar_attachment_id: av,
            }
        })
        .collect();

    Ok(Json(friends))
}

// POST /friends
pub async fn send_friend_request(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendFriendRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    let (friend_display, friend_tag) = crate::beam::split_beam(&req.friend_beam_identity);
    if friend_tag.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid beam identity format".into(),
            }),
        ));
    }

    let friend_row = sqlx::query(
        "SELECT id FROM users WHERE display_name = $1 AND beam_tag = $2",
    )
    .bind(&friend_display)
    .bind(&friend_tag)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".into(),
            }),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User not found".into(),
            }),
        )
    })?;

    let friend_id: String = friend_row.try_get("id")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    if friend_id == claims.uid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot friend yourself".into(),
            }),
        ));
    }

    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM friendships
         WHERE (user_id = $1 AND friend_user_id = $2)
            OR (user_id = $2 AND friend_user_id = $1)",
    )
    .bind(&claims.uid)
    .bind(&friend_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if exists > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Friendship already exists or pending".into(),
            }),
        ));
    }

    sqlx::query(
        "INSERT INTO friendships (user_id, friend_user_id, status) VALUES ($1, $2, 'pending')",
    )
    .bind(&claims.uid)
    .bind(&friend_id)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to send friend request".into(),
            }),
        )
    })?;

    Ok(StatusCode::CREATED)
}

// PUT /friends/:id/accept
pub async fn accept_friend_request(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(FriendIdPath { id: friend_id }): Path<FriendIdPath>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    if friend_id == claims.uid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot accept self".into(),
            }),
        ));
    }

    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM friendships
         WHERE user_id = $1 AND friend_user_id = $2 AND status = 'pending'",
    )
    .bind(&friend_id)
    .bind(&claims.uid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if pending == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Friend request not found".into(),
            }),
        ));
    }

    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Transaction failed".into(),
            }),
        )
    })?;

    sqlx::query(
        "UPDATE friendships SET status = 'accepted' WHERE user_id = $1 AND friend_user_id = $2",
    )
    .bind(&friend_id)
    .bind(&claims.uid)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update request".into(),
            }),
        )
    })?;

    sqlx::query(
        "INSERT INTO friendships (user_id, friend_user_id, status) VALUES ($1, $2, 'accepted')
         ON CONFLICT DO NOTHING",
    )
    .bind(&claims.uid)
    .bind(&friend_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create friendship".into(),
            }),
        )
    })?;

    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Transaction failed".into(),
            }),
        )
    })?;

    Ok(StatusCode::OK)
}

// GET /friend-requests
pub async fn list_incoming_requests(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<FriendRequestSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    let rows = sqlx::query(
        "SELECT u.id, u.display_name, u.beam_tag, u.account_type, u.avatar_attachment_id, f.created_at
         FROM friendships f
         JOIN users u ON f.user_id = u.id
         WHERE f.friend_user_id = $1 AND f.status = 'pending'
         ORDER BY f.created_at DESC",
    )
    .bind(&claims.uid)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".into(),
            }),
        )
    })?;

    let reqs: Vec<FriendRequestSummary> = rows
        .into_iter()
        .map(|r| {
            let dn: String = r.try_get("display_name").unwrap_or_default();
            let bt: String = r.try_get("beam_tag").unwrap_or_default();
            let at: String = r.try_get("account_type").unwrap_or_default();
            let av: Option<i64> = r.try_get("avatar_attachment_id").unwrap_or(None);
            FriendRequestSummary {
                id: r.try_get("id").unwrap_or_default(),
                beam_identity: make_beam_identity(&dn, &bt, &at),
                display_name: dn,
                created_at: r.try_get("created_at").unwrap_or_default(),
                avatar_attachment_id: av,
            }
        })
        .collect();

    Ok(Json(reqs))
}
