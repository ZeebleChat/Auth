use std::sync::Arc;

use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::collections::HashMap;
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use bcrypt::{DEFAULT_COST, hash, verify};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::AppState;
use crate::auth_helpers::{decode_access_token, extract_token, make_access_token, make_bot_token};
use crate::beam::{
    assign_beam_tag, make_beam_identity, normalize, validate_display_name, validate_premium_tag,
};
use crate::models::{
    AUTH_PASSKEY, AUTH_PASSWORD, AUTH_TOTP, AccessTokenResponse, AccountInfoResponse, AccountType,
    BotSummary, SubAction, SubActionRequest, CreateSubAccountRequest, ErrorResponse,
    FriendSummary, RecoveryCodesRequest, RecoveryCodesResponse, RecoveryCodesStatusResponse,
    RotateBotTokenRequest, ServerSummary, SubAccountIdPath, SubAccountSummary,
    SwitchAltRequest, TotpDisableRequest, TotpEnableRequest, TotpSetupRequest, TotpSetupResponse,
    UpdateBeamTagRequest, UpdateDisplayNameRequest, UpdatePasswordRequest,
    SendEmailPinRequest, VerifyEmailPinRequest,
    SendPasswordResetPinRequest, ResetPasswordWithPinRequest,
};

// POST /account/switch_alt — instant alt switch, primary proves ownership
pub async fn switch_alt(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SwitchAltRequest>,
) -> Result<Json<AccessTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let primary_claims =
        decode_access_token(&req.primary_token, &*state.signing_key).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".into(),
                }),
            )
        })?;

    if primary_claims.account_type != "primary" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only primary accounts can switch to alts".into(),
            }),
        ));
    }

    let row = sqlx::query(
        "SELECT display_name, beam_tag, premium, verified, avatar_attachment_id
         FROM users WHERE id = $1 AND parent_id = $2 AND account_type = 'alt'",
    )
    .bind(&req.alt_id)
    .bind(&primary_claims.uid)
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
                error: "Alt not found or does not belong to you".into(),
            }),
        )
    })?;

    let db_err = || (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }));
    let display_name: String = row.try_get("display_name").map_err(|_| db_err())?;
    let beam_tag: String = row.try_get("beam_tag").map_err(|_| db_err())?;
    let premium: bool = row.try_get("premium").unwrap_or(false);
    let verified: bool = row.try_get("verified").unwrap_or(false);
    let avatar_attachment_id: Option<i64> = row.try_get("avatar_attachment_id").unwrap_or(None);

    let beam_identity = make_beam_identity(&display_name, &beam_tag, "alt");

    let token = make_access_token(
        &*state.signing_key,
        &beam_identity,
        &req.alt_id,
        Some(primary_claims.uid.as_str()),
        &AccountType::Alt,
        premium,
        verified,
        avatar_attachment_id,
        Some(display_name.clone()),
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Token generation failed".into() })))?;

    Ok(Json(AccessTokenResponse { token, beam_identity }))
}

// POST /account/sub — create alt, child, or bot sub-account
pub async fn create_sub_account(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSubAccountRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let parent_claims =
        decode_access_token(&req.parent_token, &*state.signing_key).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".into(),
                }),
            )
        })?;

    if parent_claims.account_type != "primary" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only primary accounts can create sub-accounts".into(),
            }),
        ));
    }

    let sub_type = AccountType::from_str(&req.account_type).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "account_type must be alt, child, bot, or streamer".into(),
            }),
        )
    })?;

    if sub_type == AccountType::Primary {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot create a primary as a sub-account".into(),
            }),
        ));
    }

    let display_name = normalize(&req.display_name);
    if !validate_display_name(&display_name) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Display name must be 1-12 visible characters".into(),
            }),
        ));
    }

    let counts_row = sqlx::query(
        "SELECT alt_count, bot_count, child_count, streamer_count FROM users WHERE id = $1",
    )
    .bind(&parent_claims.uid)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Could not fetch parent account".into(),
            }),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Could not fetch parent account".into(),
            }),
        )
    })?;

    let alt_count: i64 = counts_row.try_get("alt_count").unwrap_or(0);
    let bot_count: i64 = counts_row.try_get("bot_count").unwrap_or(0);
    let child_count: i64 = counts_row.try_get("child_count").unwrap_or(0);
    let streamer_count: i64 = counts_row.try_get("streamer_count").unwrap_or(0);

    // Enforce total sub-account limit: 10 for free, 20 for premium
    let total_sub_count = alt_count + bot_count + child_count + streamer_count;
    let sub_limit: i64 = if parent_claims.premium { 20 } else { 10 };
    if total_sub_count >= sub_limit {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Sub-account limit reached ({sub_limit}). {}",
                    if parent_claims.premium { "You have reached the maximum of 20 sub-accounts." }
                    else { "Upgrade to premium for up to 20 sub-accounts." }
                ),
            }),
        ));
    }

    match sub_type {
        AccountType::Alt if alt_count >= 5 => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Max 5 alts allowed".into(),
                }),
            ));
        }
        AccountType::Bot if bot_count >= 5 => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Max 5 bots allowed".into(),
                }),
            ));
        }
        AccountType::Child if child_count >= 5 => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Max 5 child accounts allowed".into(),
                }),
            ));
        }
        AccountType::Streamer if streamer_count >= 5 => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Max 5 streamer accounts allowed".into(),
                }),
            ));
        }
        _ => {}
    }

    let beam_tag = assign_beam_tag(&state.db, &display_name).await.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Could not assign beam tag, try again".into(),
            }),
        )
    })?;

    let new_id = Uuid::new_v4().to_string();
    let beam_identity = make_beam_identity(&display_name, &beam_tag, sub_type.as_str());

    match sub_type {
        AccountType::Alt => {
            let password = req.password.as_deref().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Alt accounts require a password".into(),
                    }),
                )
            })?;
            let password_hash = hash(password, DEFAULT_COST).map_err(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Password hashing failed".into() }))
            })?;

            sqlx::query(
                "INSERT INTO users (id, display_name, beam_tag, password_hash, auth_methods, account_type, parent_id)
                 VALUES ($1, $2, $3, $4, $5, 'alt', $6)",
            )
            .bind(&new_id)
            .bind(&display_name)
            .bind(&beam_tag)
            .bind(&password_hash)
            .bind(AUTH_PASSWORD)
            .bind(&parent_claims.uid)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to create alt account".into(),
                    }),
                )
            })?;

            sqlx::query("UPDATE users SET alt_count = alt_count + 1 WHERE id = $1")
                .bind(&parent_claims.uid)
                .execute(&state.db)
                .await
                .ok();

            Ok(Json(
                json!({ "id": new_id, "beam_identity": beam_identity, "account_type": "alt" }),
            ))
        }

        AccountType::Child => {
            let password = req.password.as_deref().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Child accounts require a password".into(),
                    }),
                )
            })?;
            let password_hash = hash(password, DEFAULT_COST).map_err(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Password hashing failed".into() }))
            })?;

            sqlx::query(
                "INSERT INTO users (id, display_name, beam_tag, password_hash, auth_methods, account_type, parent_id)
                 VALUES ($1, $2, $3, $4, $5, 'child', $6)",
            )
            .bind(&new_id)
            .bind(&display_name)
            .bind(&beam_tag)
            .bind(&password_hash)
            .bind(AUTH_PASSWORD)
            .bind(&parent_claims.uid)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to create child account".into(),
                    }),
                )
            })?;

            sqlx::query("UPDATE users SET child_count = child_count + 1 WHERE id = $1")
                .bind(&parent_claims.uid)
                .execute(&state.db)
                .await
                .ok();

            Ok(Json(
                json!({ "id": new_id, "beam_identity": beam_identity, "account_type": "child" }),
            ))
        }

        AccountType::Bot => {
            let bot_token = make_bot_token(
                &*state.signing_key,
                &beam_identity,
                &new_id,
                &parent_claims.uid,
                1,
            )
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Token generation failed".into() })))?;

            sqlx::query(
                "INSERT INTO users (id, display_name, beam_tag, account_type, parent_id, bot_token_version)
                 VALUES ($1, $2, $3, 'bot', $4, 1)",
            )
            .bind(&new_id)
            .bind(&display_name)
            .bind(&beam_tag)
            .bind(&parent_claims.uid)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to create bot".into(),
                    }),
                )
            })?;

            sqlx::query("UPDATE users SET bot_count = bot_count + 1 WHERE id = $1")
                .bind(&parent_claims.uid)
                .execute(&state.db)
                .await
                .ok();

            Ok(Json(
                json!({ "bot_token": bot_token, "beam_identity": beam_identity, "account_type": "bot" }),
            ))
        }

        AccountType::Streamer => {
            let password = req.password.as_deref().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Streamer accounts require a password".into(),
                    }),
                )
            })?;
            let password_hash = hash(password, DEFAULT_COST).map_err(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Password hashing failed".into() }))
            })?;

            sqlx::query(
                "INSERT INTO users (id, display_name, beam_tag, password_hash, auth_methods, account_type, parent_id)
                 VALUES ($1, $2, $3, $4, $5, 'streamer', $6)",
            )
            .bind(&new_id)
            .bind(&display_name)
            .bind(&beam_tag)
            .bind(&password_hash)
            .bind(AUTH_PASSWORD)
            .bind(&parent_claims.uid)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to create streamer account".into(),
                    }),
                )
            })?;

            sqlx::query("UPDATE users SET streamer_count = streamer_count + 1 WHERE id = $1")
                .bind(&parent_claims.uid)
                .execute(&state.db)
                .await
                .ok();

            Ok(Json(
                json!({ "id": new_id, "beam_identity": beam_identity, "account_type": "streamer" }),
            ))
        }

        AccountType::Primary => unreachable!(),
    }
}

// POST /account/child/action — parent manages a child account
pub async fn sub_action(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubActionRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let parent_claims =
        decode_access_token(&req.parent_token, &*state.signing_key).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".into(),
                }),
            )
        })?;

    if parent_claims.account_type != "primary" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only primary accounts can manage sub-accounts".into(),
            }),
        ));
    }

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE id = $1 AND parent_id = $2 AND account_type != 'primary'",
    )
    .bind(&req.sub_id)
    .bind(&parent_claims.uid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if count == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Sub-account not found or does not belong to you".into(),
            }),
        ));
    }

    match req.action {
        SubAction::Lock => {
            sqlx::query("UPDATE users SET locked = TRUE WHERE id = $1")
                .bind(&req.sub_id)
                .execute(&state.db)
                .await
                .ok();
        }
        SubAction::Unlock => {
            sqlx::query("UPDATE users SET locked = FALSE WHERE id = $1")
                .bind(&req.sub_id)
                .execute(&state.db)
                .await
                .ok();
        }
        SubAction::ResetPassword { new_password } => {
            let is_bot: bool = sqlx::query_scalar(
                "SELECT account_type = 'bot' FROM users WHERE id = $1",
            )
            .bind(&req.sub_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(false);

            if is_bot {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Bot accounts do not have passwords".into(),
                    }),
                ));
            }

            let new_hash = match hash(&new_password, DEFAULT_COST) {
                Ok(h) => h,
                Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Password hashing failed".into() }))),
            };
            sqlx::query(
                "UPDATE users SET password_hash = $1, auth_methods = $2 WHERE id = $3",
            )
            .bind(&new_hash)
            .bind(AUTH_PASSWORD)
            .bind(&req.sub_id)
            .execute(&state.db)
            .await
            .ok();
        }
    }

    Ok(StatusCode::OK)
}

// POST /account/bot/rotate — rotate bot token (increments token_version)
pub async fn rotate_bot_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RotateBotTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let parent_claims =
        decode_access_token(&req.parent_token, &*state.signing_key).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".into(),
                }),
            )
        })?;

    let row = sqlx::query(
        "SELECT display_name, beam_tag, bot_token_version
         FROM users WHERE id = $1 AND parent_id = $2 AND account_type = 'bot'",
    )
    .bind(&req.bot_id)
    .bind(&parent_claims.uid)
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
                error: "Bot not found or does not belong to you".into(),
            }),
        )
    })?;

    let db_err = || (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }));
    let display_name: String = row.try_get("display_name").map_err(|_| db_err())?;
    let beam_tag: String = row.try_get("beam_tag").map_err(|_| db_err())?;
    let current_version: i64 = row.try_get("bot_token_version").unwrap_or(1);

    let new_version = current_version + 1;
    sqlx::query("UPDATE users SET bot_token_version = $1 WHERE id = $2")
        .bind(new_version)
        .bind(&req.bot_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to rotate bot token".into(),
                }),
            )
        })?;

    let beam_identity = make_beam_identity(&display_name, &beam_tag, "bot");
    let new_token = make_bot_token(
        &*state.signing_key,
        &beam_identity,
        &req.bot_id,
        &parent_claims.uid,
        new_version,
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Token generation failed".into() })))?;

    Ok(Json(
        json!({ "bot_token": new_token, "beam_identity": beam_identity, "token_version": new_version }),
    ))
}

// DELETE /account/sub/:id — delete a subaccount (alt/child/bot)
pub async fn delete_sub_account(
    State(state): State<Arc<AppState>>,
    Path(SubAccountIdPath { id }): Path<SubAccountIdPath>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(auth.token(), &*state.signing_key).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
            }),
        )
    })?;

    if claims.account_type != "primary" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only primary accounts can delete subaccounts".into(),
            }),
        ));
    }

    let row = sqlx::query(
        "SELECT account_type FROM users WHERE id = $1 AND parent_id = $2",
    )
    .bind(&id)
    .bind(&claims.uid)
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
                error: "Subaccount not found or does not belong to you".into(),
            }),
        )
    })?;

    let account_type: String = row.try_get("account_type")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    sqlx::query("DELETE FROM users WHERE id = $1 AND parent_id = $2")
        .bind(&id)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to delete subaccount".into(),
                }),
            )
        })?;

    match account_type.as_str() {
        "alt" => {
            sqlx::query("UPDATE users SET alt_count = alt_count - 1 WHERE id = $1")
                .bind(&claims.uid)
                .execute(&state.db)
                .await
                .ok();
        }
        "child" => {
            sqlx::query("UPDATE users SET child_count = child_count - 1 WHERE id = $1")
                .bind(&claims.uid)
                .execute(&state.db)
                .await
                .ok();
        }
        "bot" => {
            sqlx::query("UPDATE users SET bot_count = bot_count - 1 WHERE id = $1")
                .bind(&claims.uid)
                .execute(&state.db)
                .await
                .ok();
        }
        _ => {}
    }

    Ok(StatusCode::NO_CONTENT)
}

// POST /account/name — change display name
pub async fn update_display_name(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateDisplayNameRequest>,
) -> Result<Json<AccessTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
            }),
        )
    })?;

    let new_name = normalize(&req.new_display_name);
    if !validate_display_name(&new_name) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Display name must be 1-12 visible characters".into(),
            }),
        ));
    }

    let row = sqlx::query(
        "SELECT beam_tag, premium, verified, account_type, avatar_attachment_id FROM users WHERE id = $1",
    )
    .bind(&claims.uid)
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
                error: "Account not found".into(),
            }),
        )
    })?;

    let db_err = || (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }));
    let beam_tag: String = row.try_get("beam_tag").map_err(|_| db_err())?;
    let premium: bool = row.try_get("premium").unwrap_or(false);
    let verified: bool = row.try_get("verified").unwrap_or(false);
    let account_type_str: String = row.try_get("account_type").map_err(|_| db_err())?;
    let avatar_attachment_id: Option<i64> = row.try_get("avatar_attachment_id").unwrap_or(None);

    let taken: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE display_name = $1 AND beam_tag = $2 AND id != $3",
    )
    .bind(&new_name)
    .bind(&beam_tag)
    .bind(&claims.uid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if taken > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "That display name with your beam tag is already taken".into(),
            }),
        ));
    }

    sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
        .bind(&new_name)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to update display name".into(),
                }),
            )
        })?;

    let beam_identity = make_beam_identity(&new_name, &beam_tag, &account_type_str);
    let account_type = AccountType::from_str(&account_type_str).unwrap_or(AccountType::Primary);

    let token = make_access_token(
        &*state.signing_key,
        &beam_identity,
        &claims.uid,
        claims.parent_uid.as_deref(),
        &account_type,
        premium,
        verified,
        avatar_attachment_id,
        Some(new_name.clone()),
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Token generation failed".into() })))?;

    Ok(Json(AccessTokenResponse { token, beam_identity }))
}

// POST /account/password — change password (requires current password)
pub async fn update_password(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdatePasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
            }),
        )
    })?;

    if req.new_password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "New password must be at least 8 characters".into(),
            }),
        ));
    }

    let row = sqlx::query(
        "SELECT auth_methods, password_hash FROM users WHERE id = $1",
    )
    .bind(&claims.uid)
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
                error: "Account not found".into(),
            }),
        )
    })?;

    let auth_methods: Option<i64> = row.try_get("auth_methods").unwrap_or(None);
    let password_hash: Option<String> = row.try_get("password_hash").unwrap_or(None);

    let auth = auth_methods.unwrap_or(0);
    if (auth & AUTH_PASSWORD) == 0 {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Password authentication not enabled for this account".into(),
            }),
        ));
    }

    let current_hash = password_hash.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Auth configuration error".into(),
            }),
        )
    })?;

    if !verify(req.current_password.as_str(), &current_hash).unwrap_or(false) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Current password is incorrect".into(),
            }),
        ));
    }

    let new_hash = hash(&req.new_password, DEFAULT_COST).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to hash new password".into(),
            }),
        )
    })?;

    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to update password".into(),
                }),
            )
        })?;

    Ok(Json(json!({ "ok": true })))
}

// POST /account/beam — premium only: set a custom beam tag
pub async fn update_beam_tag(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateBeamTagRequest>,
) -> Result<Json<AccessTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
            }),
        )
    })?;

    if !claims.premium {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Custom beam tags are a premium feature".into(),
            }),
        ));
    }

    let new_tag = normalize(&req.new_tag);
    if !validate_premium_tag(&new_tag) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid beam tag — max 5 visible characters".into(),
            }),
        ));
    }

    let row = sqlx::query(
        "SELECT display_name, premium, verified, account_type, avatar_attachment_id FROM users WHERE id = $1",
    )
    .bind(&claims.uid)
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
                error: "Account not found".into(),
            }),
        )
    })?;

    let db_err = || (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }));
    let display_name: String = row.try_get("display_name").map_err(|_| db_err())?;
    let premium: bool = row.try_get("premium").unwrap_or(false);
    let verified: bool = row.try_get("verified").unwrap_or(false);
    let account_type_str: String = row.try_get("account_type").map_err(|_| db_err())?;
    let avatar_attachment_id: Option<i64> = row.try_get("avatar_attachment_id").unwrap_or(None);

    let taken: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE display_name = $1 AND beam_tag = $2",
    )
    .bind(&display_name)
    .bind(&new_tag)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if taken > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "That beam tag is already taken for this name".into(),
            }),
        ));
    }

    sqlx::query("UPDATE users SET beam_tag = $1 WHERE id = $2")
        .bind(&new_tag)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to update beam tag".into(),
                }),
            )
        })?;

    let beam_identity = make_beam_identity(&display_name, &new_tag, &account_type_str);
    let account_type = AccountType::from_str(&account_type_str).unwrap_or(AccountType::Primary);

    let token = make_access_token(
        &*state.signing_key,
        &beam_identity,
        &claims.uid,
        claims.parent_uid.as_deref(),
        &account_type,
        premium,
        verified,
        avatar_attachment_id,
        Some(display_name.clone()),
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Token generation failed".into() })))?;

    Ok(Json(AccessTokenResponse { token, beam_identity }))
}

// GET /account/info — full account info
pub async fn account_info(
    State(state): State<Arc<AppState>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<AccountInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(auth.token(), &*state.signing_key).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
            }),
        )
    })?;

    let row = sqlx::query(
        "SELECT display_name, beam_tag, premium, verified, discord_id, auth_methods, avatar_attachment_id, banner_attachment_id, email
         FROM users WHERE id = $1",
    )
    .bind(&claims.uid)
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
                error: "Account not found".into(),
            }),
        )
    })?;

    let db_err = || (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() }));
    let display_name: String = row.try_get("display_name").map_err(|_| db_err())?;
    let beam_tag: String = row.try_get("beam_tag").map_err(|_| db_err())?;
    let premium: bool = row.try_get("premium").unwrap_or(false);
    let verified: bool = row.try_get("verified").unwrap_or(false);
    let discord_id: Option<String> = row.try_get("discord_id").unwrap_or(None);
    let auth_methods: Option<i64> = row.try_get("auth_methods").unwrap_or(None);
    let avatar_attachment_id: Option<i64> = row.try_get("avatar_attachment_id").unwrap_or(None);
    let banner_attachment_id: Option<i64> = row.try_get("banner_attachment_id").unwrap_or(None);
    let email: Option<String> = row.try_get("email").unwrap_or(None);

    let mut alts: Vec<SubAccountSummary> = vec![];
    let mut children: Vec<SubAccountSummary> = vec![];
    let mut bots: Vec<BotSummary> = vec![];
    let mut streamers: Vec<SubAccountSummary> = vec![];

    if claims.account_type == "primary" {
        let sub_rows = sqlx::query(
            "SELECT id, display_name, beam_tag, account_type, locked, bot_token_version
             FROM users WHERE parent_id = $1",
        )
        .bind(&claims.uid)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        for sub_row in sub_rows {
            let id: String = sub_row.try_get("id").unwrap_or_default();
            let dn: String = sub_row.try_get("display_name").unwrap_or_default();
            let bt: String = sub_row.try_get("beam_tag").unwrap_or_default();
            let atype: String = sub_row.try_get("account_type").unwrap_or_default();
            let locked: bool = sub_row.try_get("locked").unwrap_or(false);
            let bot_version: Option<i64> = sub_row.try_get("bot_token_version").unwrap_or(None);
            let beam_identity = make_beam_identity(&dn, &bt, &atype);

            match atype.as_str() {
                "alt" => alts.push(SubAccountSummary {
                    id,
                    beam_identity,
                    display_name: dn,
                    account_type: atype,
                    locked,
                }),
                "child" => children.push(SubAccountSummary {
                    id,
                    beam_identity,
                    display_name: dn,
                    account_type: atype,
                    locked,
                }),
                "bot" => {
                    let token = match make_bot_token(
                        &*state.signing_key,
                        &beam_identity,
                        &id,
                        &claims.uid,
                        bot_version.unwrap_or(0),
                    ) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    bots.push(BotSummary {
                        id,
                        beam_identity,
                        display_name: dn,
                        account_type: "bot".to_string(),
                        token_version: bot_version.unwrap_or(0),
                        bot_token: token,
                    });
                }
                "streamer" => streamers.push(SubAccountSummary {
                    id,
                    beam_identity,
                    display_name: dn,
                    account_type: atype,
                    locked,
                }),
                _ => {}
            }
        }
    }

    let server_rows = sqlx::query(
        "SELECT server_url, server_name, joined_at, is_owner
         FROM user_servers WHERE user_id = $1 ORDER BY joined_at DESC",
    )
    .bind(&claims.uid)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let servers: Vec<ServerSummary> = server_rows
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

    let friend_rows = sqlx::query(
        "SELECT u.id, u.display_name, u.beam_tag, u.account_type, u.avatar_attachment_id, f.status, f.created_at
         FROM friendships f
         JOIN users u ON f.friend_user_id = u.id
         WHERE f.user_id = $1 AND f.status = 'accepted'
         ORDER BY LOWER(u.display_name)",
    )
    .bind(&claims.uid)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let friends: Vec<FriendSummary> = friend_rows
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

    let auth = auth_methods.unwrap_or(0);
    let mut methods = vec![];
    if auth & AUTH_PASSWORD != 0 {
        methods.push("password".into());
    }
    if auth & AUTH_PASSKEY != 0 {
        methods.push("passkey".into());
    }
    if auth & AUTH_TOTP != 0 {
        methods.push("totp".into());
    }

    Ok(Json(AccountInfoResponse {
        beam_identity: make_beam_identity(&display_name, &beam_tag, &claims.account_type),
        display_name,
        beam_tag,
        account_type: claims.account_type,
        premium,
        verified,
        discord_linked: discord_id.is_some(),
        auth_methods: methods,
        alts,
        children,
        bots,
        streamers,
        servers,
        friends,
        avatar_attachment_id,
        banner_attachment_id,
        email,
    }))
}

// POST /account/email — update email address
pub async fn update_email(
    State(state): State<Arc<AppState>>,
    Json(req): Json<crate::models::UpdateEmailRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: "Invalid or expired token".into() }),
        )
    })?;

    let new_email = req.new_email.trim().to_lowercase();
    let parts: Vec<&str> = new_email.splitn(2, '@').collect();
    let valid = parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.');
    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "Invalid email address".into() }),
        ));
    }

    sqlx::query("UPDATE users SET email = $1 WHERE id = $2")
        .bind(&new_email)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            let error = if msg.contains("unique") || msg.contains("duplicate") {
                "That email is already in use".into()
            } else {
                "Failed to update email".into()
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error }))
        })?;

    Ok(Json(json!({ "ok": true })))
}

// POST /account/email/send-pin — generate a 6-digit PIN and email it to the given address
pub async fn send_email_pin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendEmailPinRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid or expired token".into() }))
    })?;

    let email = req.email.trim().to_lowercase();
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    let valid = parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.');
    if !valid {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid email address".into() })));
    }

    // Generate a random 6-digit PIN
    use rand::RngExt;
    let pin: u32 = rand::rng().random_range(0..1_000_000);
    let pin_str = format!("{:06}", pin);
    let pin_hash = crate::email::hash_pin(&pin_str);

    // Expire in 15 minutes
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0) + 900;

    // Delete any previous pending verifications for this user
    sqlx::query("DELETE FROM email_verifications WHERE user_id = $1")
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .ok();

    // Store the new verification
    sqlx::query(
        "INSERT INTO email_verifications (user_id, email, pin_hash, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&claims.uid)
    .bind(&email)
    .bind(&pin_hash)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to store verification".into() })))?;

    // Look up display name for the email body
    let display_name: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1")
        .bind(&claims.uid)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "there".to_string());

    // Send the email (or log to console in dev mode)
    crate::email::send_pin_email(&email, &pin_str, &display_name).await;

    Ok(Json(json!({ "ok": true })))
}

// POST /account/email/verify-pin — verify the PIN and mark email as verified
pub async fn verify_email_pin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyEmailPinRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid or expired token".into() }))
    })?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Fetch the latest pending verification for this user
    let row = sqlx::query(
        "SELECT id, email, pin_hash, expires_at FROM email_verifications WHERE user_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(&claims.uid)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    let row = row.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "No pending verification found — please request a new code".into() }))
    })?;

    let row_id: i64 = row.try_get("id").unwrap_or(0);
    let stored_email: String = row.try_get("email").unwrap_or_default();
    let stored_hash: String = row.try_get("pin_hash").unwrap_or_default();
    let expires_at: i64 = row.try_get("expires_at").unwrap_or(0);

    if now > expires_at {
        sqlx::query("DELETE FROM email_verifications WHERE id = $1").bind(row_id).execute(&state.db).await.ok();
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Verification code has expired — please request a new one".into() })));
    }

    let input_hash = crate::email::hash_pin(req.pin.trim());
    if input_hash != stored_hash {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Incorrect code — please try again".into() })));
    }

    // PIN is correct — update the user's email and mark as verified
    sqlx::query("UPDATE users SET email = $1, email_verified = TRUE WHERE id = $2")
        .bind(&stored_email)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            let error = if msg.contains("unique") || msg.contains("duplicate") {
                "That email is already in use by another account".into()
            } else {
                "Failed to update email".into()
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error }))
        })?;

    // Clean up the verification record
    sqlx::query("DELETE FROM email_verifications WHERE id = $1").bind(row_id).execute(&state.db).await.ok();

    Ok(Json(json!({ "ok": true })))
}

// POST /account/avatar — upload profile picture
pub async fn upload_avatar(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = match extract_token(&*state.signing_key, &headers).await {
        Ok(claims) => claims,
        Err(e) => return Err(e),
    };

    let mut file_info = None;

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let filename = match field.file_name() {
            Some(name) => sanitize_filename(name).to_string(),
            None => continue,
        };
        let mime_type = match field.content_type() {
            Some(mime) => mime.to_string(),
            None => continue,
        };
        if !mime_type.starts_with("image/") {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Only image files are allowed for avatars".into(),
                }),
            ));
        }
        let mut bytes = Vec::new();
        while let Ok(Some(chunk)) = field.chunk().await {
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Empty file".into(),
                }),
            ));
        }
        file_info = Some((filename, mime_type, bytes));
        break;
    }

    let (filename, mime_type, bytes) = file_info.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No file provided".into(),
            }),
        )
    })?;

    let file_size = bytes.len() as i64;
    const MAX_AVATAR_SIZE: i64 = 5 * 1024 * 1024;
    if file_size > MAX_AVATAR_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: "Avatar file size exceeds 5MB limit".into(),
            }),
        ));
    }

    // Get old avatar id before inserting new one
    let old_avatar_id: Option<i64> = sqlx::query_scalar(
        "SELECT avatar_attachment_id FROM users WHERE id = $1",
    )
    .bind(&claims.uid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(None);

    let attachment_id: i64 = sqlx::query_scalar(
        "INSERT INTO attachments (filename, mime_type, file_size, file_data, uploaded_by)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&filename)
    .bind(&mime_type)
    .bind(file_size)
    .bind(&bytes)
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to store avatar: {e}"),
            }),
        )
    })?;

    sqlx::query("UPDATE users SET avatar_attachment_id = $1 WHERE id = $2")
        .bind(attachment_id)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to update avatar: {e}"),
                }),
            )
        })?;

    if let Some(old_id) = old_avatar_id {
        if old_id != attachment_id {
            sqlx::query("DELETE FROM attachments WHERE id = $1")
                .bind(old_id)
                .execute(&state.db)
                .await
                .ok();
        }
    }

    Ok(Json(
        json!({ "ok": true, "avatar_attachment_id": attachment_id }),
    ))
}

// GET /attachments/:id — serve an avatar attachment stored in the auth DB
pub async fn get_attachment(
    headers: HeaderMap,
    Path(attachment_id): Path<i64>,
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let claims = if let Ok(c) = extract_token(&*state.signing_key, &headers).await {
        Ok(c)
    } else if let Some(token) = params.get("token") {
        decode_access_token(token, &*state.signing_key).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".into(),
                }),
            )
        })
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing Authorization header".into(),
            }),
        ))
    };

    if let Err(e) = claims {
        return e.into_response();
    }

    let row = sqlx::query(
        "SELECT filename, mime_type, file_data FROM attachments WHERE id = $1",
    )
    .bind(attachment_id)
    .fetch_optional(&state.db)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Attachment not found" })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Database error" })),
            )
                .into_response();
        }
    };

    let filename: String = row.try_get("filename").unwrap_or_default();
    let mime_type: String = row.try_get("mime_type").unwrap_or_default();
    let data: Vec<u8> = row.try_get("file_data").unwrap_or_default();

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        axum::http::header::CONTENT_TYPE,
        mime_type
            .parse()
            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    let disposition = format!("inline; filename=\"{}\"", filename);
    response_headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        disposition
            .parse()
            .unwrap_or_else(|_| "inline".parse().unwrap()),
    );
    response_headers.insert(
        axum::http::header::CACHE_CONTROL,
        "public, max-age=31536000, immutable".parse().unwrap(),
    );

    (StatusCode::OK, response_headers, data).into_response()
}

// POST /account/banner — upload profile banner (premium only)
pub async fn upload_banner(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = match extract_token(&*state.signing_key, &headers).await {
        Ok(claims) => claims,
        Err(e) => return Err(e),
    };

    if !claims.premium {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Profile banners are a premium feature".into(),
            }),
        ));
    }

    let mut file_info = None;

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let filename = match field.file_name() {
            Some(name) => sanitize_filename(name).to_string(),
            None => continue,
        };
        let mime_type = match field.content_type() {
            Some(mime) => mime.to_string(),
            None => continue,
        };
        if !mime_type.starts_with("image/") {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Only image files are allowed for banners".into(),
                }),
            ));
        }
        let mut bytes = Vec::new();
        while let Ok(Some(chunk)) = field.chunk().await {
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "Empty file".into() }),
            ));
        }
        file_info = Some((filename, mime_type, bytes));
        break;
    }

    let (filename, mime_type, bytes) = file_info.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "No file provided".into() }),
        )
    })?;

    let file_size = bytes.len() as i64;
    const MAX_BANNER_SIZE: i64 = 8 * 1024 * 1024;
    if file_size > MAX_BANNER_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: "Banner file size exceeds 8MB limit".into(),
            }),
        ));
    }

    let old_banner_id: Option<i64> = sqlx::query_scalar(
        "SELECT banner_attachment_id FROM users WHERE id = $1",
    )
    .bind(&claims.uid)
    .fetch_one(&state.db)
    .await
    .unwrap_or(None);

    let attachment_id: i64 = sqlx::query_scalar(
        "INSERT INTO attachments (filename, mime_type, file_size, file_data, uploaded_by)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&filename)
    .bind(&mime_type)
    .bind(file_size)
    .bind(&bytes)
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to store banner: {e}"),
            }),
        )
    })?;

    sqlx::query("UPDATE users SET banner_attachment_id = $1 WHERE id = $2")
        .bind(attachment_id)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to update banner: {e}"),
                }),
            )
        })?;

    if let Some(old_id) = old_banner_id {
        if old_id != attachment_id {
            sqlx::query("DELETE FROM attachments WHERE id = $1")
                .bind(old_id)
                .execute(&state.db)
                .await
                .ok();
        }
    }

    Ok(Json(json!({ "ok": true, "banner_attachment_id": attachment_id })))
}

// GET /users/:beam_identity — public profile (premium, avatar, banner)
pub async fn get_public_profile(
    headers: HeaderMap,
    Path(beam_identity): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::models::PublicProfileResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Require auth (token in header or query param)
    let _claims = if let Ok(c) = extract_token(&*state.signing_key, &headers).await {
        c
    } else if let Some(token) = params.get("token") {
        decode_access_token(token, &*state.signing_key).map_err(|_| {
            (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid token".into() }))
        })?
    } else {
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Missing token".into() })));
    };

    let row = sqlx::query(
        "SELECT display_name, beam_tag, account_type, premium, verified, avatar_attachment_id, banner_attachment_id
         FROM users WHERE display_name || '»' || beam_tag || '#' || account_type = $1
            OR display_name || '»' || beam_tag = $1",
    )
    .bind(&beam_identity)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "User not found".into() })))?;

    use crate::beam::make_beam_identity;
    let display_name: String = row.try_get("display_name").unwrap_or_default();
    let beam_tag: String = row.try_get("beam_tag").unwrap_or_default();
    let account_type: String = row.try_get("account_type").unwrap_or_default();
    let premium: bool = row.try_get("premium").unwrap_or(false);
    let verified: bool = row.try_get("verified").unwrap_or(false);
    let avatar_attachment_id: Option<i64> = row.try_get("avatar_attachment_id").unwrap_or(None);
    let banner_attachment_id: Option<i64> = row.try_get("banner_attachment_id").unwrap_or(None);

    Ok(Json(crate::models::PublicProfileResponse {
        beam_identity: make_beam_identity(&display_name, &beam_tag, &account_type),
        display_name,
        premium,
        verified,
        avatar_attachment_id,
        banner_attachment_id,
    }))
}

fn sanitize_filename(filename: &str) -> String {
    let sanitized = filename.replace("..", "").replace(['/', '\\'], "_");
    if sanitized.len() > 255 {
        if let Some(ext_pos) = sanitized.rfind('.') {
            let ext = &sanitized[ext_pos..];
            let max_name_len = 255 - ext.len();
            if max_name_len > 0 {
                format!("{}{}", &sanitized[..max_name_len], ext)
            } else {
                sanitized[..255].to_string()
            }
        } else {
            sanitized[..255].to_string()
        }
    } else {
        sanitized
    }
}

// ─── TOTP / 2FA handlers ──────────────────────────────────────────────────────

// POST /account/totp/setup — generate a new TOTP secret (not enabled yet)
pub async fn totp_setup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TotpSetupRequest>,
) -> Result<Json<TotpSetupResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid token".into() }))
    })?;

    let (secret, otpauth_url) = crate::auth_helpers::generate_totp_secret(&claims.sub);

    sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
        .bind(&secret)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    Ok(Json(TotpSetupResponse { secret, otpauth_url }))
}

// POST /account/totp/enable — verify the TOTP code and enable 2FA
pub async fn totp_enable(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TotpEnableRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid token".into() }))
    })?;

    let row = sqlx::query("SELECT totp_secret, auth_methods FROM users WHERE id = $1")
        .bind(&claims.uid)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "User not found".into() })))?;

    let secret: Option<String> = row.try_get("totp_secret").unwrap_or(None);
    let auth_methods: Option<i64> = row.try_get("auth_methods").unwrap_or(None);

    let secret = secret.ok_or_else(|| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Run setup first".into() })))?;

    if !crate::auth_helpers::verify_totp(&secret, &req.code) {
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid TOTP code".into() })));
    }

    let new_methods = auth_methods.unwrap_or(1) | AUTH_TOTP;
    sqlx::query("UPDATE users SET auth_methods = $1 WHERE id = $2")
        .bind(new_methods)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// DELETE /account/totp — disable 2FA (requires password confirmation)
pub async fn totp_disable(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TotpDisableRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid token".into() }))
    })?;

    let row = sqlx::query("SELECT password_hash, auth_methods FROM users WHERE id = $1")
        .bind(&claims.uid)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "User not found".into() })))?;

    let password_hash: Option<String> = row.try_get("password_hash").unwrap_or(None);
    let auth_methods: Option<i64> = row.try_get("auth_methods").unwrap_or(None);

    let stored_hash = password_hash.ok_or_else(|| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "No password set".into() })))?;
    if !verify(&req.password, &stored_hash).unwrap_or(false) {
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Incorrect password".into() })));
    }

    let new_methods = auth_methods.unwrap_or(1) & !AUTH_TOTP;
    sqlx::query("UPDATE users SET auth_methods = $1, totp_secret = NULL, totp_backup_codes = NULL WHERE id = $2")
        .bind(new_methods)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

// ─── Recovery Code handlers ───────────────────────────────────────────────────

// POST /account/recovery-codes — generate 8 new backup codes (requires password)
pub async fn generate_recovery_codes_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecoveryCodesRequest>,
) -> Result<Json<RecoveryCodesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = decode_access_token(&req.token, &*state.signing_key).map_err(|_| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid token".into() }))
    })?;

    let row = sqlx::query("SELECT password_hash FROM users WHERE id = $1")
        .bind(&claims.uid)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "User not found".into() })))?;

    let password_hash: Option<String> = row.try_get("password_hash").unwrap_or(None);
    let stored_hash = password_hash.ok_or_else(|| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "No password set".into() })))?;
    if !verify(&req.password, &stored_hash).unwrap_or(false) {
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Incorrect password".into() })));
    }

    let codes = crate::auth_helpers::generate_recovery_codes();
    let hashed: Vec<String> = codes.iter().map(|c| crate::auth_helpers::hash_recovery_code(c)).collect();
    let stored = serde_json::to_string(&hashed).unwrap_or_default();

    sqlx::query("UPDATE users SET totp_backup_codes = $1 WHERE id = $2")
        .bind(&stored)
        .bind(&claims.uid)
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    let count = codes.len();
    Ok(Json(RecoveryCodesResponse { codes, count }))
}

// GET /account/recovery-codes/status — how many codes remain
pub async fn recovery_codes_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RecoveryCodesStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let claims = extract_token(&*state.signing_key, &headers).await?;

    let row = sqlx::query("SELECT totp_backup_codes FROM users WHERE id = $1")
        .bind(&claims.uid)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "User not found".into() })))?;

    let codes_json: Option<String> = row.try_get("totp_backup_codes").unwrap_or(None);
    let (enabled, remaining) = if let Some(json_str) = codes_json {
        let codes: Vec<String> = serde_json::from_str(&json_str).unwrap_or_default();
        (!codes.is_empty(), codes.len())
    } else {
        (false, 0)
    };

    Ok(Json(RecoveryCodesStatusResponse { enabled, remaining }))
}

// POST /account/password/reset-pin
// Unauthenticated — accepts an email, sends a 6-digit reset PIN if the account exists.
// Always returns ok:true to avoid leaking whether an email is registered.
pub async fn send_password_reset_pin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendPasswordResetPinRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let email = req.email.trim().to_lowercase();
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    let valid = parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.');
    if !valid {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Invalid email address".into() })));
    }

    // Look up the user — if not found, return ok silently (don't leak existence)
    let row = sqlx::query("SELECT id, display_name, beam_tag FROM users WHERE email = $1 LIMIT 1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    if let Some(row) = row {
        let user_id: String = row.try_get("id").unwrap_or_default();
        let display_name: String = row.try_get("display_name").unwrap_or_else(|_| "there".to_string());
        let beam_tag: String = row.try_get("beam_tag").unwrap_or_default();
        let beam_identity = format!("{}»{}", display_name, beam_tag);

        use rand::RngExt;
        let pin: u32 = rand::rng().random_range(0..1_000_000);
        let pin_str = format!("{:06}", pin);
        let pin_hash = crate::email::hash_pin(&pin_str);

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0) + 900;

        // Remove any previous reset entries for this email
        sqlx::query("DELETE FROM password_reset_verifications WHERE email = $1")
            .bind(&email)
            .execute(&state.db)
            .await
            .ok();

        sqlx::query(
            "INSERT INTO password_reset_verifications (email, pin_hash, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&email)
        .bind(&pin_hash)
        .bind(expires_at)
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to store reset token".into() })))?;

        let _ = user_id; // kept for future use (e.g. rate limiting per user)
        crate::email::send_password_reset_email(&email, &pin_str, &display_name, &beam_identity).await;
    }

    Ok(Json(json!({ "ok": true })))
}

// POST /account/password/reset
// Unauthenticated — verifies the PIN sent to the email and sets a new password.
pub async fn reset_password_with_pin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ResetPasswordWithPinRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let email = req.email.trim().to_lowercase();

    if req.new_password.len() < 8 {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Password must be at least 8 characters".into() })));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let row = sqlx::query(
        "SELECT id, pin_hash, expires_at FROM password_reset_verifications WHERE email = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })))?;

    let row = row.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "No reset code found — please request a new one".into() }))
    })?;

    let row_id: i64 = row.try_get("id").unwrap_or(0);
    let stored_hash: String = row.try_get("pin_hash").unwrap_or_default();
    let expires_at: i64 = row.try_get("expires_at").unwrap_or(0);

    if now > expires_at {
        sqlx::query("DELETE FROM password_reset_verifications WHERE id = $1").bind(row_id).execute(&state.db).await.ok();
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Reset code has expired — please request a new one".into() })));
    }

    let input_hash = crate::email::hash_pin(req.pin.trim());
    if input_hash != stored_hash {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Incorrect code — please try again".into() })));
    }

    let new_hash = hash(&req.new_password, DEFAULT_COST).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to hash password".into() }))
    })?;

    sqlx::query("UPDATE users SET password_hash = $1 WHERE email = $2")
        .bind(&new_hash)
        .bind(&email)
        .execute(&state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to update password".into() })))?;

    sqlx::query("DELETE FROM password_reset_verifications WHERE id = $1").bind(row_id).execute(&state.db).await.ok();

    Ok(Json(json!({ "ok": true })))
}
