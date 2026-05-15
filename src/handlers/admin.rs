use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    AppState,
    auth_helpers::extract_token,
    models::ErrorResponse,
};

// ─── Hard-coded owner ─────────────────────────────────────────────────────────
// This is the ONLY place the owner identity is defined. It is checked against
// the `sub` field of the cryptographically-verified JWT — never against anything
// the caller sends in the request body.
const HARDCODED_OWNER: &str = "creeper7»l0na6";

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminRole {
    Owner,
    Staff,
}

struct AdminAccess {
    role: AdminRole,
    uid: String,
    identity: String,
}

// ─── Auth helpers ──────────────────────────────────────────────────────────────

/// Verify the JWT and check that the caller is either the hard-coded owner
/// or a user with `is_staff = TRUE` in the DB.
/// Identity is ONLY taken from the signed JWT `sub` claim — never from the request body.
async fn require_admin(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<AdminAccess, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, headers).await?;

    if claims.sub == HARDCODED_OWNER {
        return Ok(AdminAccess {
            role: AdminRole::Owner,
            uid: claims.uid,
            identity: claims.sub,
        });
    }

    let is_staff: bool = sqlx::query_scalar(
        "SELECT COALESCE(is_staff, FALSE) FROM users WHERE id = $1",
    )
    .bind(&claims.uid)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false);

    if is_staff {
        Ok(AdminAccess {
            role: AdminRole::Staff,
            uid: claims.uid,
            identity: claims.sub,
        })
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse { error: "Not authorized".into() }),
        ))
    }
}

/// Stronger check — only the hard-coded owner can perform this action.
async fn require_owner(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<AdminAccess, (StatusCode, Json<ErrorResponse>)> {
    let acc = require_admin(state, headers).await?;
    if acc.role == AdminRole::Owner {
        Ok(acc)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse { error: "Owner only".into() }),
        ))
    }
}

// ─── GET /admin/me ─────────────────────────────────────────────────────────────

pub async fn admin_me(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match require_admin(&state, &headers).await {
        Ok(acc) => {
            let role_str = if acc.role == AdminRole::Owner { "owner" } else { "staff" };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "identity": acc.identity,
                    "uid": acc.uid,
                    "role": role_str,
                    "is_owner": acc.role == AdminRole::Owner,
                })),
            ).into_response()
        }
        Err((code, body)) => (code, body).into_response(),
    }
}

// ─── GET /admin/stats ──────────────────────────────────────────────────────────

pub async fn admin_stats(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    let total_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE account_type = 'primary'")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let premium_users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE premium = TRUE AND account_type = 'primary'")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let total_servers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM server_registry")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let open_flags: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM platform_bans WHERE (expires_at IS NULL OR expires_at > EXTRACT(EPOCH FROM NOW())::BIGINT)"
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let staff_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_staff = TRUE")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    (StatusCode::OK, Json(serde_json::json!({
        "total_users": total_users,
        "premium_users": premium_users,
        "total_servers": total_servers,
        "active_bans": open_flags,
        "staff_count": staff_count,
    }))).into_response()
}

// ─── GET /admin/users ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UserListQuery {
    pub page: Option<i64>,
    pub search: Option<String>,
}

pub async fn admin_list_users(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Query(q): Query<UserListQuery>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    let page = q.page.unwrap_or(0).max(0);
    let limit: i64 = 50;
    let offset = page * limit;

    use sqlx::Row;

    let rows = if let Some(search) = &q.search {
        let pattern = format!("%{}%", search.to_lowercase());
        sqlx::query(
            "SELECT id, display_name, beam_tag, account_type, premium, verified, locked, is_staff, staff_role, created_at
             FROM users
             WHERE account_type = 'primary'
               AND (LOWER(display_name) LIKE $1 OR LOWER(beam_tag) LIKE $1)
             ORDER BY created_at DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(&pattern)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            "SELECT id, display_name, beam_tag, account_type, premium, verified, locked, is_staff, staff_role, created_at
             FROM users
             WHERE account_type = 'primary'
             ORDER BY created_at DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await
    };

    let rows = match rows {
        Ok(r) => r,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let users: Vec<serde_json::Value> = rows.iter().map(|row| {
        let beam_tag: String = row.try_get("beam_tag").unwrap_or_default();
        let display_name: String = row.try_get("display_name").unwrap_or_default();
        let beam_identity = format!("{}»{}", display_name, beam_tag);
        serde_json::json!({
            "id": row.try_get::<String, _>("id").unwrap_or_default(),
            "beam_identity": beam_identity,
            "display_name": display_name,
            "beam_tag": beam_tag,
            "account_type": row.try_get::<String, _>("account_type").unwrap_or_default(),
            "premium": row.try_get::<bool, _>("premium").unwrap_or(false),
            "verified": row.try_get::<bool, _>("verified").unwrap_or(false),
            "locked": row.try_get::<bool, _>("locked").unwrap_or(false),
            "is_staff": row.try_get::<bool, _>("is_staff").unwrap_or(false),
            "staff_role": row.try_get::<Option<String>, _>("staff_role").unwrap_or(None),
            "created_at": row.try_get::<String, _>("created_at").unwrap_or_default(),
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({ "users": users, "page": page }))).into_response()
}

// ─── POST /admin/users/:id/lock ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BanBody {
    pub reason: Option<String>,
    pub expires_at: Option<i64>,
}

pub async fn admin_lock_user(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(uid): Path<String>,
    Json(body): Json<BanBody>,
) -> impl IntoResponse {
    let acc = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    // Cannot ban the owner
    let target_identity: Option<String> = sqlx::query_scalar(
        "SELECT display_name || '»' || beam_tag FROM users WHERE id = $1"
    )
    .bind(&uid)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    if target_identity.as_deref() == Some(HARDCODED_OWNER) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Cannot ban the owner"}))).into_response();
    }

    sqlx::query("UPDATE users SET locked = TRUE WHERE id = $1")
        .bind(&uid)
        .execute(&state.db)
        .await
        .ok();

    let reason = body.reason.unwrap_or_else(|| "No reason given".into());
    sqlx::query(
        "INSERT INTO platform_bans (user_id, reason, banned_by, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&uid)
    .bind(&reason)
    .bind(&acc.identity)  // always from JWT, never from request body
    .bind(body.expires_at)
    .execute(&state.db)
    .await
    .ok();

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

// ─── POST /admin/users/:id/unlock ─────────────────────────────────────────────

pub async fn admin_unlock_user(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(uid): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    sqlx::query("UPDATE users SET locked = FALSE WHERE id = $1")
        .bind(&uid)
        .execute(&state.db)
        .await
        .ok();

    sqlx::query("DELETE FROM platform_bans WHERE user_id = $1")
        .bind(&uid)
        .execute(&state.db)
        .await
        .ok();

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

// ─── GET /admin/staff ─────────────────────────────────────────────────────────

pub async fn admin_list_staff(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, display_name, beam_tag, staff_role, staff_note, staff_added_at, avatar_attachment_id
         FROM users
         WHERE is_staff = TRUE
         ORDER BY staff_added_at ASC NULLS LAST",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut members: Vec<serde_json::Value> = rows.iter().map(|row| {
        let display_name: String = row.try_get("display_name").unwrap_or_default();
        let beam_tag: String = row.try_get("beam_tag").unwrap_or_default();
        serde_json::json!({
            "id": row.try_get::<String, _>("id").unwrap_or_default(),
            "beam_identity": format!("{}»{}", display_name, beam_tag),
            "display_name": display_name,
            "staff_role": row.try_get::<Option<String>, _>("staff_role").unwrap_or(None).unwrap_or_else(|| "staff".into()),
            "staff_note": row.try_get::<Option<String>, _>("staff_note").unwrap_or(None),
            "staff_added_at": row.try_get::<Option<String>, _>("staff_added_at").unwrap_or(None),
            "avatar_attachment_id": row.try_get::<Option<i64>, _>("avatar_attachment_id").unwrap_or(None),
        })
    }).collect();

    // Prepend the hard-coded owner (always at top, not in DB's is_staff column)
    members.insert(0, serde_json::json!({
        "id": "owner",
        "beam_identity": HARDCODED_OWNER,
        "display_name": HARDCODED_OWNER.split('»').next().unwrap_or(HARDCODED_OWNER),
        "staff_role": "owner",
        "staff_note": null,
        "staff_added_at": null,
        "avatar_attachment_id": null,
    }));

    (StatusCode::OK, Json(serde_json::json!({ "staff": members }))).into_response()
}

// ─── POST /admin/staff ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddStaffBody {
    pub uid: String,
    pub staff_role: Option<String>,
    pub staff_note: Option<String>,
}

pub async fn admin_add_staff(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddStaffBody>,
) -> impl IntoResponse {
    // Only the owner can add staff
    if let Err(e) = require_owner(&state, &headers).await {
        return e.into_response();
    }

    let role = body.staff_role.unwrap_or_else(|| "staff".into());
    let now = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}", secs)
    };

    let result = sqlx::query(
        "UPDATE users SET is_staff = TRUE, staff_role = $1, staff_note = $2, staff_added_at = $3 WHERE id = $4",
    )
    .bind(&role)
    .bind(&body.staff_note)
    .bind(&now)
    .bind(&body.uid)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "User not found"}))).into_response(),
    }
}

// ─── DELETE /admin/staff/:uid ─────────────────────────────────────────────────

pub async fn admin_remove_staff(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(uid): Path<String>,
) -> impl IntoResponse {
    // Only the owner can remove staff
    if let Err(e) = require_owner(&state, &headers).await {
        return e.into_response();
    }

    sqlx::query(
        "UPDATE users SET is_staff = FALSE, staff_role = NULL, staff_note = NULL, staff_added_at = NULL WHERE id = $1",
    )
    .bind(&uid)
    .execute(&state.db)
    .await
    .ok();

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

// ─── GET /admin/promos ────────────────────────────────────────────────────────

pub async fn admin_list_promos(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT code, uses_max, uses_count, expires_at, grants_premium, created_by_server_url
         FROM promo_codes ORDER BY code ASC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let promos: Vec<serde_json::Value> = rows.iter().map(|row| {
        serde_json::json!({
            "code": row.try_get::<String, _>("code").unwrap_or_default(),
            "uses_max": row.try_get::<Option<i64>, _>("uses_max").unwrap_or(None),
            "uses_count": row.try_get::<i64, _>("uses_count").unwrap_or(0),
            "expires_at": row.try_get::<Option<i64>, _>("expires_at").unwrap_or(None),
            "grants_premium": row.try_get::<bool, _>("grants_premium").unwrap_or(false),
            "created_by": row.try_get::<Option<String>, _>("created_by_server_url").unwrap_or(None),
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({ "promos": promos }))).into_response()
}

// ─── POST /admin/promos ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreatePromoBody {
    pub code: String,
    pub uses_max: Option<i64>,
    pub expires_at: Option<i64>,
    pub grants_premium: Option<bool>,
}

pub async fn admin_create_promo(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreatePromoBody>,
) -> impl IntoResponse {
    let acc = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let code = body.code.trim().to_uppercase();
    if code.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Code cannot be empty"}))).into_response();
    }

    let result = sqlx::query(
        "INSERT INTO promo_codes (code, uses_max, expires_at, grants_premium, created_by_server_url)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&code)
    .bind(body.uses_max)
    .bind(body.expires_at)
    .bind(body.grants_premium.unwrap_or(false))
    .bind(&acc.identity)  // store who created it
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"ok": true, "code": code}))).into_response(),
        Err(e) if e.to_string().contains("duplicate") || e.to_string().contains("unique") => {
            (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Code already exists"}))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    }
}

// ─── DELETE /admin/promos/:code ───────────────────────────────────────────────

pub async fn admin_delete_promo(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    sqlx::query("DELETE FROM promo_codes WHERE code = $1")
        .bind(&code)
        .execute(&state.db)
        .await
        .ok();

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

// ─── GET /admin/bans ──────────────────────────────────────────────────────────

pub async fn admin_list_bans(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT pb.id, pb.user_id, pb.reason, pb.banned_by, pb.expires_at, pb.created_at,
                u.display_name, u.beam_tag
         FROM platform_bans pb
         JOIN users u ON u.id = pb.user_id
         ORDER BY pb.created_at DESC
         LIMIT 200",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let bans: Vec<serde_json::Value> = rows.iter().map(|row| {
        let display_name: String = row.try_get("display_name").unwrap_or_default();
        let beam_tag: String = row.try_get("beam_tag").unwrap_or_default();
        serde_json::json!({
            "id": row.try_get::<i64, _>("id").unwrap_or(0),
            "user_id": row.try_get::<String, _>("user_id").unwrap_or_default(),
            "beam_identity": format!("{}»{}", display_name, beam_tag),
            "reason": row.try_get::<String, _>("reason").unwrap_or_default(),
            "banned_by": row.try_get::<String, _>("banned_by").unwrap_or_default(),
            "expires_at": row.try_get::<Option<i64>, _>("expires_at").unwrap_or(None),
            "created_at": row.try_get::<String, _>("created_at").unwrap_or_default(),
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({ "bans": bans }))).into_response()
}

// ─── GET /admin/broadcasts ────────────────────────────────────────────────────

pub async fn admin_list_broadcasts(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, message, sent_by, sent_at, target FROM platform_broadcasts ORDER BY sent_at DESC LIMIT 100",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let broadcasts: Vec<serde_json::Value> = rows.iter().map(|row| {
        serde_json::json!({
            "id": row.try_get::<i64, _>("id").unwrap_or(0),
            "message": row.try_get::<String, _>("message").unwrap_or_default(),
            "sent_by": row.try_get::<String, _>("sent_by").unwrap_or_default(),
            "sent_at": row.try_get::<String, _>("sent_at").unwrap_or_default(),
            "target": row.try_get::<String, _>("target").unwrap_or_default(),
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({ "broadcasts": broadcasts }))).into_response()
}

// ─── POST /admin/broadcasts ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendBroadcastBody {
    pub message: String,
    pub target: Option<String>,
}

pub async fn admin_send_broadcast(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<SendBroadcastBody>,
) -> impl IntoResponse {
    let acc = match require_admin(&state, &headers).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    if body.message.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Message cannot be empty"}))).into_response();
    }

    sqlx::query(
        "INSERT INTO platform_broadcasts (message, sent_by, target) VALUES ($1, $2, $3)",
    )
    .bind(&body.message)
    .bind(&acc.identity)  // always from JWT
    .bind(body.target.unwrap_or_else(|| "all".into()))
    .execute(&state.db)
    .await
    .ok();

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

// ─── DELETE /admin/servers ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteServerBody {
    pub server_url: String,
}

pub async fn admin_delete_server(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeleteServerBody>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    sqlx::query("DELETE FROM user_servers WHERE server_url = $1")
        .bind(&body.server_url)
        .execute(&state.db)
        .await
        .ok();

    sqlx::query("DELETE FROM server_registry WHERE server_url = $1")
        .bind(&body.server_url)
        .execute(&state.db)
        .await
        .ok();

    // If it's a zcloud-managed server, also delete the data from zcloud.
    let zcloud_public = std::env::var("ZCLOUD_PUBLIC_URL")
        .unwrap_or_else(|_| "https://cloud.zeeble.xyz".to_string());
    let zcloud_internal = std::env::var("ZCLOUD_URL")
        .unwrap_or_else(|_| "http://zcloud:3003".to_string());

    if body.server_url.starts_with(zcloud_public.trim_end_matches('/')) {
        if let Some(uuid) = body.server_url.split("/servers/").nth(1) {
            let uuid = uuid.trim_end_matches('/');
            let delete_url = format!("{}/servers/{}", zcloud_internal.trim_end_matches('/'), uuid);
            reqwest::Client::new().delete(&delete_url).send().await.ok();
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

// ─── GET /admin/servers ───────────────────────────────────────────────────────

pub async fn admin_list_servers(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&state, &headers).await {
        return e.into_response();
    }

    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT sr.server_url, sr.owner_beam_identity,
                COUNT(us.user_id) AS member_count
         FROM server_registry sr
         LEFT JOIN user_servers us ON us.server_url = sr.server_url
         GROUP BY sr.server_url, sr.owner_beam_identity
         ORDER BY member_count DESC
         LIMIT 200",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let servers: Vec<serde_json::Value> = rows.iter().map(|row| {
        serde_json::json!({
            "server_url": row.try_get::<String, _>("server_url").unwrap_or_default(),
            "owner": row.try_get::<String, _>("owner_beam_identity").unwrap_or_default(),
            "member_count": row.try_get::<i64, _>("member_count").unwrap_or(0),
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({ "servers": servers }))).into_response()
}
