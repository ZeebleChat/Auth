use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use rand::RngExt;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::AppState;
use crate::auth_helpers::{
    decode_access_token, generate_refresh_token, hash_refresh_token, make_access_token, now_secs,
};
use crate::beam::{assign_beam_tag, make_beam_identity};
use crate::models::{AccountType, ErrorResponse};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn random_state() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn oauth_done_html(provider: &str, success: bool) -> Html<String> {
    let (title, msg) = if success {
        (
            format!("{provider} Connected"),
            format!("Your {provider} account has been connected. You can close this window and return to Zeeble."),
        )
    } else {
        (
            format!("{provider} Connection Failed"),
            "Something went wrong. Please close this window and try again.".to_string(),
        )
    };
    Html(format!(
        r#"<!DOCTYPE html><html><head><title>{title}</title>
<style>
  body{{font-family:system-ui,sans-serif;background:#1a1a2e;color:#eee;
       display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
  .box{{text-align:center;padding:2rem;background:#16213e;border-radius:12px;max-width:400px}}
  h2{{margin:0 0 .75rem}}p{{margin:0;color:rgba(255,255,255,.6);font-size:14px}}
</style></head>
<body><div class="box"><h2>{title}</h2><p>{msg}</p></div></body></html>"#
    ))
}

async fn extract_optional_uid(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let bearer = headers.get("Authorization")?.to_str().ok()?;
    let token = bearer.strip_prefix("Bearer ")?;
    decode_access_token(token, &state.signing_key).ok().map(|c| c.uid)
}

async fn mark_error(db: &sqlx::PgPool, state_key: &str, error: &str) {
    sqlx::query("UPDATE oauth_states SET error = $1 WHERE state = $2")
        .bind(error)
        .bind(state_key)
        .execute(db)
        .await
        .ok();
}

/// Find user by provider column or create a new primary account.
/// Returns (access_token, refresh_token, uid, beam_identity).
async fn create_or_login_oauth(
    state: &AppState,
    provider_id: &str,
    provider_col: &str,
    display_name_hint: &str,
) -> Result<(String, String, String, String), ()> {
    let q = format!(
        "SELECT id, display_name, beam_tag, premium, verified, age_verified FROM users WHERE {provider_col} = $1"
    );
    let row = sqlx::query(&q)
        .bind(provider_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| ())?;

    let (uid, display_name, beam_tag, premium, verified, age_verified) = if let Some(r) = row {
        (
            r.try_get::<String, _>("id").map_err(|_| ())?,
            r.try_get::<String, _>("display_name").map_err(|_| ())?,
            r.try_get::<String, _>("beam_tag").map_err(|_| ())?,
            r.try_get::<bool, _>("premium").unwrap_or(false),
            r.try_get::<bool, _>("verified").unwrap_or(false),
            r.try_get::<bool, _>("age_verified").unwrap_or(false),
        )
    } else {
        let new_uid = Uuid::new_v4().to_string();
        let dn = sanitize_display_name(display_name_hint);
        let bt = assign_beam_tag(&state.db, &dn).await.ok_or(())?;
        let q = format!(
            "INSERT INTO users (id, display_name, beam_tag, account_type, auth_methods, created_at, {provider_col})
             VALUES ($1, $2, $3, 'primary', 0, NOW()::text, $4)"
        );
        sqlx::query(&q)
            .bind(&new_uid)
            .bind(&dn)
            .bind(&bt)
            .bind(provider_id)
            .execute(&state.db)
            .await
            .map_err(|_| ())?;
        (new_uid, dn, bt, false, false, false)
    };

    let refresh_tok = generate_refresh_token();
    sqlx::query("UPDATE users SET refresh_token_hash = $1 WHERE id = $2")
        .bind(hash_refresh_token(&refresh_tok))
        .bind(&uid)
        .execute(&state.db)
        .await
        .map_err(|_| ())?;

    let beam_id = make_beam_identity(&display_name, &beam_tag, "primary");
    let access_tok = make_access_token(
        &state.signing_key,
        &beam_id,
        &uid,
        None,
        &AccountType::Primary,
        premium,
        verified,
        age_verified,
        None,
        Some(display_name),
    )
    .map_err(|_| ())?;

    Ok((access_tok, refresh_tok, uid, beam_id))
}

fn sanitize_display_name(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(12)
        .collect();
    if s.is_empty() { "user".to_string() } else { s }
}

// ── Discord ───────────────────────────────────────────────────────────────────

// POST /oauth/discord/start
pub async fn discord_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let uid = extract_optional_uid(&state, &headers).await;
    let mode = if uid.is_some() { "link" } else { "login" };

    let oauth_state = random_state();
    let now = now_secs() as i64;

    sqlx::query(
        "INSERT INTO oauth_states (state, provider, mode, uid, expires_at, created_at)
         VALUES ($1, 'discord', $2, $3, $4, $5)",
    )
    .bind(&oauth_state)
    .bind(mode)
    .bind(&uid)
    .bind(now + 600)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "db_error".into() }))
    })?;

    let url = format!(
        "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=identify&state={}",
        state.discord_client_id,
        url_encode(&state.discord_redirect_uri),
        oauth_state,
    );

    Ok(Json(json!({ "state": oauth_state, "url": url })))
}

// GET /oauth/discord/callback
pub async fn discord_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(oauth_state) = params.get("state").cloned() else {
        return oauth_done_html("Discord", false).into_response();
    };

    if params.contains_key("error") {
        mark_error(&state.db, &oauth_state, "user_denied").await;
        return oauth_done_html("Discord", false).into_response();
    }

    let Some(code) = params.get("code").cloned() else {
        return oauth_done_html("Discord", false).into_response();
    };

    let now = now_secs() as i64;
    let row = sqlx::query(
        "SELECT mode, uid FROM oauth_states
         WHERE state = $1 AND provider = 'discord' AND expires_at > $2
           AND session_token IS NULL AND error IS NULL",
    )
    .bind(&oauth_state)
    .bind(now)
    .fetch_optional(&state.db)
    .await;

    let Ok(Some(row)) = row else {
        return oauth_done_html("Discord", false).into_response();
    };

    let mode: String = row.try_get("mode").unwrap_or_default();
    let uid: Option<String> = row.try_get("uid").unwrap_or(None);

    // Exchange code for access token
    let http = reqwest::Client::new();
    let token_res = http
        .post("https://discord.com/api/oauth2/token")
        .form(&[
            ("client_id", state.discord_client_id.as_str()),
            ("client_secret", state.discord_client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", state.discord_redirect_uri.as_str()),
        ])
        .send()
        .await;

    let Ok(token_res) = token_res else {
        mark_error(&state.db, &oauth_state, "token_exchange_failed").await;
        return oauth_done_html("Discord", false).into_response();
    };

    let Ok(token_json) = token_res.json::<serde_json::Value>().await else {
        mark_error(&state.db, &oauth_state, "token_parse_failed").await;
        return oauth_done_html("Discord", false).into_response();
    };

    let Some(access_token) = token_json["access_token"].as_str() else {
        mark_error(&state.db, &oauth_state, "no_access_token").await;
        return oauth_done_html("Discord", false).into_response();
    };

    // Fetch Discord user
    let user_res = http
        .get("https://discord.com/api/users/@me")
        .bearer_auth(access_token)
        .send()
        .await;

    let Ok(user_res) = user_res else {
        mark_error(&state.db, &oauth_state, "user_fetch_failed").await;
        return oauth_done_html("Discord", false).into_response();
    };

    let Ok(user_json) = user_res.json::<serde_json::Value>().await else {
        mark_error(&state.db, &oauth_state, "user_parse_failed").await;
        return oauth_done_html("Discord", false).into_response();
    };

    let Some(discord_id) = user_json["id"].as_str() else {
        mark_error(&state.db, &oauth_state, "no_discord_id").await;
        return oauth_done_html("Discord", false).into_response();
    };

    if mode == "link" {
        let Some(uid) = uid else {
            mark_error(&state.db, &oauth_state, "missing_uid").await;
            return oauth_done_html("Discord", false).into_response();
        };
        if sqlx::query("UPDATE users SET discord_id = $1 WHERE id = $2")
            .bind(discord_id)
            .bind(&uid)
            .execute(&state.db)
            .await
            .is_err()
        {
            mark_error(&state.db, &oauth_state, "link_failed").await;
            return oauth_done_html("Discord", false).into_response();
        }
        sqlx::query("UPDATE oauth_states SET session_token = 'linked' WHERE state = $1")
            .bind(&oauth_state)
            .execute(&state.db)
            .await
            .ok();
        return oauth_done_html("Discord", true).into_response();
    }

    // Login mode
    let display_name_hint = user_json["global_name"]
        .as_str()
        .or_else(|| user_json["username"].as_str())
        .unwrap_or("user");

    match create_or_login_oauth(&state, discord_id, "discord_id", display_name_hint).await {
        Ok((tok, ref_tok, uid_out, beam_id)) => {
            sqlx::query(
                "UPDATE oauth_states SET session_token=$1, refresh_token=$2, uid=$3, beam_identity=$4
                 WHERE state=$5",
            )
            .bind(&tok)
            .bind(&ref_tok)
            .bind(&uid_out)
            .bind(&beam_id)
            .bind(&oauth_state)
            .execute(&state.db)
            .await
            .ok();
            oauth_done_html("Discord", true).into_response()
        }
        Err(_) => {
            mark_error(&state.db, &oauth_state, "session_create_failed").await;
            oauth_done_html("Discord", false).into_response()
        }
    }
}

// ── Steam ─────────────────────────────────────────────────────────────────────

// POST /oauth/steam/start
pub async fn steam_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let uid = extract_optional_uid(&state, &headers).await;
    let mode = if uid.is_some() { "link" } else { "login" };

    let oauth_state = random_state();
    let now = now_secs() as i64;

    sqlx::query(
        "INSERT INTO oauth_states (state, provider, mode, uid, expires_at, created_at)
         VALUES ($1, 'steam', $2, $3, $4, $5)",
    )
    .bind(&oauth_state)
    .bind(mode)
    .bind(&uid)
    .bind(now + 600)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "db_error".into() }))
    })?;

    // State is embedded in return_to so Steam passes it back
    let return_to = format!("{}?state={}", state.steam_redirect_uri, oauth_state);
    let ns = url_encode("http://specs.openid.net/auth/2.0");
    let id_select = url_encode("http://specs.openid.net/auth/2.0/identifier_select");
    let url = format!(
        "https://steamcommunity.com/openid/login\
         ?openid.ns={ns}\
         &openid.mode=checkid_setup\
         &openid.return_to={}\
         &openid.realm={}\
         &openid.identity={id_select}\
         &openid.claimed_id={id_select}",
        url_encode(&return_to),
        url_encode(&state.steam_realm),
    );

    Ok(Json(json!({ "state": oauth_state, "url": url })))
}

// GET /oauth/steam/callback
pub async fn steam_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(oauth_state) = params.get("state").cloned() else {
        return oauth_done_html("Steam", false).into_response();
    };

    if params.get("openid.mode").map(|s| s.as_str()) != Some("id_res") {
        mark_error(&state.db, &oauth_state, "user_denied").await;
        return oauth_done_html("Steam", false).into_response();
    }

    let Some(claimed_id) = params.get("openid.claimed_id").cloned() else {
        return oauth_done_html("Steam", false).into_response();
    };

    let Some(steam64_id) = claimed_id.rsplit('/').next().filter(|s| !s.is_empty()).map(|s| s.to_string()) else {
        mark_error(&state.db, &oauth_state, "invalid_claimed_id").await;
        return oauth_done_html("Steam", false).into_response();
    };

    // Verify with Steam
    let http = reqwest::Client::new();
    let mut verify: Vec<(String, String)> = params
        .iter()
        .filter(|(k, _)| k.starts_with("openid."))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Override mode for verification
    if let Some(entry) = verify.iter_mut().find(|(k, _)| k == "openid.mode") {
        entry.1 = "check_authentication".to_string();
    } else {
        verify.push(("openid.mode".to_string(), "check_authentication".to_string()));
    }

    let verify_res = http
        .post("https://steamcommunity.com/openid/login")
        .form(&verify)
        .send()
        .await;

    let Ok(verify_res) = verify_res else {
        mark_error(&state.db, &oauth_state, "steam_verify_failed").await;
        return oauth_done_html("Steam", false).into_response();
    };

    let Ok(body) = verify_res.text().await else {
        mark_error(&state.db, &oauth_state, "steam_verify_parse_failed").await;
        return oauth_done_html("Steam", false).into_response();
    };

    if !body.contains("is_valid:true") {
        mark_error(&state.db, &oauth_state, "steam_invalid").await;
        return oauth_done_html("Steam", false).into_response();
    }

    let now = now_secs() as i64;
    let row = sqlx::query(
        "SELECT mode, uid FROM oauth_states
         WHERE state = $1 AND provider = 'steam' AND expires_at > $2
           AND session_token IS NULL AND error IS NULL",
    )
    .bind(&oauth_state)
    .bind(now)
    .fetch_optional(&state.db)
    .await;

    let Ok(Some(row)) = row else {
        return oauth_done_html("Steam", false).into_response();
    };

    let mode: String = row.try_get("mode").unwrap_or_default();
    let uid: Option<String> = row.try_get("uid").unwrap_or(None);

    if mode == "link" {
        let Some(uid) = uid else {
            mark_error(&state.db, &oauth_state, "missing_uid").await;
            return oauth_done_html("Steam", false).into_response();
        };
        if sqlx::query("UPDATE users SET steam_id = $1 WHERE id = $2")
            .bind(&steam64_id)
            .bind(&uid)
            .execute(&state.db)
            .await
            .is_err()
        {
            mark_error(&state.db, &oauth_state, "link_failed").await;
            return oauth_done_html("Steam", false).into_response();
        }
        sqlx::query("UPDATE oauth_states SET session_token = 'linked' WHERE state = $1")
            .bind(&oauth_state)
            .execute(&state.db)
            .await
            .ok();
        return oauth_done_html("Steam", true).into_response();
    }

    // Login mode — fetch display name from Steam API
    let display_name_hint = get_steam_persona(&http, &state.steam_api_key, &steam64_id)
        .await
        .unwrap_or_else(|| format!("user{}", &steam64_id[..8.min(steam64_id.len())]));

    match create_or_login_oauth(&state, &steam64_id, "steam_id", &display_name_hint).await {
        Ok((tok, ref_tok, uid_out, beam_id)) => {
            sqlx::query(
                "UPDATE oauth_states SET session_token=$1, refresh_token=$2, uid=$3, beam_identity=$4
                 WHERE state=$5",
            )
            .bind(&tok)
            .bind(&ref_tok)
            .bind(&uid_out)
            .bind(&beam_id)
            .bind(&oauth_state)
            .execute(&state.db)
            .await
            .ok();
            oauth_done_html("Steam", true).into_response()
        }
        Err(_) => {
            mark_error(&state.db, &oauth_state, "session_create_failed").await;
            oauth_done_html("Steam", false).into_response()
        }
    }
}

async fn get_steam_persona(http: &reqwest::Client, api_key: &str, steam64_id: &str) -> Option<String> {
    if api_key.is_empty() {
        return None;
    }
    let url = format!(
        "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={api_key}&steamids={steam64_id}"
    );
    let data: serde_json::Value = http.get(&url).send().await.ok()?.json().await.ok()?;
    data["response"]["players"][0]["personaname"]
        .as_str()
        .map(|s| s.to_string())
}

// ── Poll ──────────────────────────────────────────────────────────────────────

// GET /oauth/poll?state=
pub async fn oauth_poll(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(state_key) = params.get("state") else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "missing_state" }))).into_response();
    };

    let now = now_secs() as i64;
    let row = sqlx::query(
        "SELECT session_token, refresh_token, uid, beam_identity, error
         FROM oauth_states WHERE state = $1 AND expires_at > $2",
    )
    .bind(state_key)
    .bind(now)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some(r)) => {
            let error: Option<String> = r.try_get("error").unwrap_or(None);
            if let Some(err) = error {
                sqlx::query("DELETE FROM oauth_states WHERE state = $1")
                    .bind(state_key).execute(&state.db).await.ok();
                return (StatusCode::OK, Json(json!({ "ready": false, "error": err }))).into_response();
            }
            let session_token: Option<String> = r.try_get("session_token").unwrap_or(None);
            if let Some(tok) = session_token {
                if tok == "linked" {
                    sqlx::query("DELETE FROM oauth_states WHERE state = $1")
                        .bind(state_key).execute(&state.db).await.ok();
                    return (StatusCode::OK, Json(json!({ "ready": true, "linked": true }))).into_response();
                }
                let ref_tok: Option<String> = r.try_get("refresh_token").unwrap_or(None);
                let uid: Option<String> = r.try_get("uid").unwrap_or(None);
                let beam_id: Option<String> = r.try_get("beam_identity").unwrap_or(None);
                sqlx::query("DELETE FROM oauth_states WHERE state = $1")
                    .bind(state_key).execute(&state.db).await.ok();
                return (StatusCode::OK, Json(json!({
                    "ready": true,
                    "token": tok,
                    "refresh_token": ref_tok,
                    "uid": uid,
                    "beam_identity": beam_id,
                }))).into_response();
            }
            (StatusCode::OK, Json(json!({ "ready": false }))).into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({ "error": "state_not_found" }))).into_response(),
    }
}

// ── Unlink ────────────────────────────────────────────────────────────────────

// DELETE /oauth/discord
pub async fn discord_unlink(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let Some(uid) = extract_optional_uid(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
    };
    sqlx::query("UPDATE users SET discord_id = NULL WHERE id = $1")
        .bind(&uid)
        .execute(&state.db)
        .await
        .ok();
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

// DELETE /oauth/steam
pub async fn steam_unlink(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let Some(uid) = extract_optional_uid(&state, &headers).await else {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
    };
    sqlx::query("UPDATE users SET steam_id = NULL WHERE id = $1")
        .bind(&uid)
        .execute(&state.db)
        .await
        .ok();
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}
