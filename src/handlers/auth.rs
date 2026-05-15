use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use bcrypt::{DEFAULT_COST, hash, verify};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::AppState;
use crate::auth_helpers::{
    ACCESS_TOKEN_EXPIRY, decode_access_token, decode_bot_token, generate_refresh_token,
    hash_refresh_token, make_access_token, now_secs, signing_key_to_pkcs8_v2_der,
    verify_refresh_token, verify_totp,
};
use crate::beam::{assign_beam_tag, make_beam_identity, normalize, validate_display_name};
use crate::models::{
    AUTH_PASSWORD, AUTH_TOTP, AccessClaims, AccessTokenResponse, AccountType, ErrorResponse,
    ExchangeRequest, LoginRequest, LoginResponse, RefreshRequest, RegisterRequest, ValidateRequest,
};
use crate::auth_helpers::hash_recovery_code;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

// POST /register
pub async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.auth_rate_limiter.check(&addr.ip().to_string()) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "Too many requests — please wait before trying again".into(),
            }),
        ));
    }

    let password = req.password.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Password required (passkey coming soon)".into(),
            }),
        )
    })?;

    let display_name = normalize(&req.display_name);
    if !validate_display_name(&display_name) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Display name must be 1-12 visible characters".into(),
            }),
        ));
    }

    let email = req.email.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_lowercase);
    if let Some(ref e) = email {
        let parts: Vec<&str> = e.splitn(2, '@').collect();
        let valid = parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.');
        if !valid {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "Invalid email address".into() }),
            ));
        }
    }

    let password_hash = hash(&password, DEFAULT_COST).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Password hashing failed".into(),
            }),
        )
    })?;
    let id = Uuid::new_v4().to_string();

    let beam_tag = assign_beam_tag(&state.db, &display_name).await.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Could not assign beam tag, try again".into(),
            }),
        )
    })?;

    let raw_refresh = generate_refresh_token();
    let refresh_hash = hash_refresh_token(&raw_refresh);

    sqlx::query(
        "INSERT INTO users
            (id, display_name, beam_tag, password_hash, auth_methods, account_type, refresh_token_hash, email)
         VALUES ($1, $2, $3, $4, $5, 'primary', $6, $7)",
    )
    .bind(&id)
    .bind(&display_name)
    .bind(&beam_tag)
    .bind(&password_hash)
    .bind(AUTH_PASSWORD)
    .bind(&refresh_hash)
    .bind(&email)
    .execute(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        let error = if msg.contains("unique") || msg.contains("duplicate") {
            "An account with that email already exists".into()
        } else {
            "Registration failed".into()
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error }))
    })?;

    let beam_identity = make_beam_identity(&display_name, &beam_tag, "primary");

    let token = make_access_token(
        &*state.signing_key,
        &beam_identity,
        &id,
        None,
        &AccountType::Primary,
        false,
        false,
        false,
        None,
        Some(display_name.clone()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Token generation failed".into(),
            }),
        )
    })?;

    Ok(Json(LoginResponse {
        token,
        refresh_token: raw_refresh,
        uid: id,
        beam_identity,
        account_type: "primary".into(),
    }))
}

// POST /login
pub async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.auth_rate_limiter.check(&addr.ip().to_string()) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "Too many requests — please wait before trying again".into(),
            }),
        ));
    }

    let invalid_creds = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid credentials".into(),
            }),
        )
    };

    let row = if let Some(ref email) = req.email {
        let email = email.trim().to_lowercase();
        sqlx::query(
            "SELECT id, display_name, beam_tag, password_hash, auth_methods, totp_secret,
                    totp_backup_codes, account_type, premium, verified, age_verified,
                    parent_id, locked, avatar_attachment_id
             FROM users WHERE email = $1",
        )
        .bind(&email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Database error".into() }),
            )
        })?
        .ok_or_else(invalid_creds)?
    } else if let Some(ref bi) = req.beam_identity {
        let (dn, bt) = crate::beam::split_beam(bi);
        if bt.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Use name»tag format (e.g. sarah»k4mx9)".into(),
                }),
            ));
        }
        sqlx::query(
            "SELECT id, display_name, beam_tag, password_hash, auth_methods, totp_secret,
                    totp_backup_codes, account_type, premium, verified, age_verified,
                    parent_id, locked, avatar_attachment_id
             FROM users WHERE display_name = $1 AND beam_tag = $2",
        )
        .bind(&dn)
        .bind(&bt)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Database error".into() }),
            )
        })?
        .ok_or_else(invalid_creds)?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Provide either email or beam identity".into(),
            }),
        ));
    };

    let db_err = || {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Database error".into() }),
        )
    };
    let id: String = row.try_get("id").map_err(|_| db_err())?;
    let display_name: String = row.try_get("display_name").map_err(|_| db_err())?;
    let beam_tag: String = row.try_get("beam_tag").map_err(|_| db_err())?;
    let password_hash: Option<String> = row.try_get("password_hash").unwrap_or(None);
    let auth_methods: Option<i64> = row.try_get("auth_methods").unwrap_or(None);
    let totp_secret: Option<String> = row.try_get("totp_secret").unwrap_or(None);
    let totp_backup_codes: Option<String> = row.try_get("totp_backup_codes").unwrap_or(None);
    let account_type_str: String = row.try_get("account_type").map_err(|_| db_err())?;
    let premium: bool = row.try_get("premium").unwrap_or(false);
    let verified: bool = row.try_get("verified").unwrap_or(false);
    let age_verified: bool = row.try_get("age_verified").unwrap_or(false);
    let parent_id: Option<String> = row.try_get("parent_id").unwrap_or(None);
    let locked: bool = row.try_get("locked").unwrap_or(false);
    let avatar_attachment_id: Option<i64> = row.try_get("avatar_attachment_id").unwrap_or(None);

    if account_type_str == "bot" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Bot accounts cannot log in — use the bot token".into(),
            }),
        ));
    }

    if locked {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "This account has been locked".into(),
            }),
        ));
    }

    let auth = auth_methods.unwrap_or(0);

    if auth & AUTH_PASSWORD != 0 {
        let hash_str = password_hash.ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Auth config error".into(),
                }),
            )
        })?;
        if !verify(req.password.as_deref().unwrap_or(""), &hash_str).unwrap_or(false) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid beam identity or password".into(),
                }),
            ));
        }
    }

    if auth & AUTH_TOTP != 0 {
        let secret = totp_secret.ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "TOTP config error".into(),
                }),
            )
        })?;
        let provided_code = req.totp_code.as_deref().unwrap_or("");
        let totp_ok = verify_totp(&secret, provided_code);

        if !totp_ok {
            // Check if the provided code matches a recovery code.
            let recovery_accepted = if let Some(ref codes_json) = totp_backup_codes {
                let mut codes: Vec<String> = serde_json::from_str(codes_json).unwrap_or_default();
                let hashed_input = hash_recovery_code(provided_code);
                if let Some(pos) = codes.iter().position(|c| *c == hashed_input) {
                    // Remove the used code and persist
                    codes.remove(pos);
                    let updated = serde_json::to_string(&codes).unwrap_or_default();
                    sqlx::query("UPDATE users SET totp_backup_codes = $1 WHERE id = $2")
                        .bind(&updated)
                        .bind(&id)
                        .execute(&state.db)
                        .await
                        .ok();
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !recovery_accepted {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Invalid or missing 2FA code".into(),
                    }),
                ));
            }
        }
    }

    let raw_refresh = generate_refresh_token();
    let refresh_hash = hash_refresh_token(&raw_refresh);
    sqlx::query("UPDATE users SET refresh_token_hash = $1 WHERE id = $2")
        .bind(&refresh_hash)
        .bind(&id)
        .execute(&state.db)
        .await
        .ok();

    let account_type = AccountType::from_str(&account_type_str).unwrap_or(AccountType::Primary);
    let beam_identity = make_beam_identity(&display_name, &beam_tag, &account_type_str);

    let token = make_access_token(
        &*state.signing_key,
        &beam_identity,
        &id,
        parent_id.as_deref(),
        &account_type,
        premium,
        verified,
        age_verified,
        avatar_attachment_id,
        Some(display_name.clone()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Token generation failed".into(),
            }),
        )
    })?;

    Ok(Json(LoginResponse {
        token,
        refresh_token: raw_refresh,
        uid: id,
        beam_identity,
        account_type: account_type_str,
    }))
}

// POST /refresh — exchange refresh token for a new short-lived access token
pub async fn refresh(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<AccessTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.auth_rate_limiter.check(&addr.ip().to_string()) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "Too many requests — please wait before trying again".into(),
            }),
        ));
    }
    let row = sqlx::query(
        "SELECT display_name, beam_tag, refresh_token_hash, account_type, parent_id,
                premium, verified, age_verified, avatar_attachment_id
         FROM users WHERE id = $1",
    )
    .bind(&req.uid)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid refresh token".into(),
            }),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid refresh token".into(),
            }),
        )
    })?;

    let db_err = || {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "Database error".into() }),
        )
    };
    let display_name: String = row.try_get("display_name").map_err(|_| db_err())?;
    let beam_tag: String = row.try_get("beam_tag").map_err(|_| db_err())?;
    let refresh_hash: Option<String> = row.try_get("refresh_token_hash").unwrap_or(None);
    let account_type_str: String = row.try_get("account_type").map_err(|_| db_err())?;
    let parent_id: Option<String> = row.try_get("parent_id").unwrap_or(None);
    let premium: bool = row.try_get("premium").unwrap_or(false);
    let verified: bool = row.try_get("verified").unwrap_or(false);
    let age_verified: bool = row.try_get("age_verified").unwrap_or(false);
    let avatar_attachment_id: Option<i64> = row.try_get("avatar_attachment_id").unwrap_or(None);

    let stored_hash = refresh_hash.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "No active session".into(),
            }),
        )
    })?;

    if !verify_refresh_token(&req.refresh_token, &stored_hash) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid refresh token".into(),
            }),
        ));
    }

    let account_type = AccountType::from_str(&account_type_str).unwrap_or(AccountType::Primary);
    let beam_identity = make_beam_identity(&display_name, &beam_tag, &account_type_str);

    let token = make_access_token(
        &*state.signing_key,
        &beam_identity,
        &req.uid,
        parent_id.as_deref(),
        &account_type,
        premium,
        verified,
        age_verified,
        avatar_attachment_id,
        Some(display_name.clone()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Token generation failed".into(),
            }),
        )
    })?;

    Ok(Json(AccessTokenResponse {
        token,
        beam_identity,
    }))
}

// POST /logout — invalidate session by clearing the refresh token
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    sqlx::query("UPDATE users SET refresh_token_hash = NULL WHERE id = $1")
        .bind(&req.uid)
        .execute(&state.db)
        .await
        .ok();
    Ok(StatusCode::OK)
}

// POST /validate — validate JWT token (for client-side token checks)
pub async fn validate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ValidateRequest>,
) -> impl IntoResponse {
    match decode_access_token(&req.token, &*state.signing_key) {
        Ok(claims) => Json(json!({ "valid": true, "beam_identity": claims.sub })),
        Err(_) => Json(json!({ "valid": false })),
    }
}

// POST /exchange — trade auth server token for a specific zeeble-chat server's JWT
pub async fn exchange(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ExchangeRequest>,
) -> impl IntoResponse {
    let auth_header = match headers.get("Authorization") {
        Some(h) => h,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Missing Authorization header" })),
            )
                .into_response();
        }
    };
    let bearer = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid Authorization header" })),
            )
                .into_response();
        }
    };
    if !bearer.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid Authorization format" })),
        )
            .into_response();
    }
    let token = &bearer[7..];

    enum ExchangedClaims {
        User(AccessClaims),
        Bot(crate::models::BotClaims),
    }

    let exchanged = match decode_access_token(token, &*state.signing_key) {
        Ok(claims) => ExchangedClaims::User(claims),
        Err(_) => match decode_bot_token(token, &*state.signing_key) {
            Ok(bot) => ExchangedClaims::Bot(bot),
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Invalid or expired token" })),
                )
                    .into_response();
            }
        },
    };

    let exp = now_secs() + ACCESS_TOKEN_EXPIRY as usize;
    let new_claims = match exchanged {
        ExchangedClaims::User(claims) => AccessClaims {
            sub: claims.sub,
            uid: claims.uid,
            parent_uid: claims.parent_uid,
            account_type: claims.account_type,
            premium: claims.premium,
            verified: claims.verified,
            age_verified: claims.age_verified,
            exp,
            aud: Some(body.server_url.clone()),
            avatar_attachment_id: claims.avatar_attachment_id,
            display_name: claims.display_name,
        },
        ExchangedClaims::Bot(bot) => {
            let stored_version: Option<i64> = sqlx::query_scalar(
                "SELECT bot_token_version FROM users WHERE id = $1",
            )
            .bind(&bot.uid)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

            match stored_version {
                Some(v) if v == bot.token_version => {}
                _ => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({ "error": "Bot token has been rotated" })),
                    )
                        .into_response();
                }
            }

            AccessClaims {
                sub: bot.sub,
                uid: bot.uid,
                parent_uid: Some(bot.parent_uid),
                account_type: bot.account_type,
                premium: false,
                verified: false,
                age_verified: false,
                exp,
                aud: Some(body.server_url.clone()),
                avatar_attachment_id: None,
                display_name: None,
            }
        }
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("auth-1".to_string());
    let der = signing_key_to_pkcs8_v2_der(&state.signing_key);
    let enc_key = EncodingKey::from_ed_der(&der);
    let new_token = match encode(&header, &new_claims, &enc_key) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to generate token" })),
            )
                .into_response();
        }
    };

    Json(json!({ "token": new_token })).into_response()
}

// GET /health
pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "server_name": "Zeeble Auth",
        "version": env!("CARGO_PKG_VERSION")
    }))
}
