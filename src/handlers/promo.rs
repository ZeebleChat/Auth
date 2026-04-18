use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use std::sync::Arc;

use crate::{
    AppState,
    auth_helpers::extract_token,
    models::{
        PromoRedeemResponse, PromoValidateResponse, RedeemPromoRequest, ValidatePromoRequest,
    },
};

// POST /promo/validate — check if a promo code is valid (auth required)
pub async fn validate_promo(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ValidatePromoRequest>,
) -> impl IntoResponse {
    let _claims = match extract_token(&*state.signing_key, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let code = req.code.trim().to_string();
    if code.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PromoValidateResponse {
                valid: false,
                code: None,
                uses_remaining: None,
                expires_at: None,
                description: None,
                error: Some("Promo code cannot be empty".into()),
            }),
        )
            .into_response();
    }

    let row = sqlx::query(
        "SELECT uses_max, uses_count, expires_at, created_by_server_url FROM promo_codes WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let row = match row {
        Some(r) => r,
        None => {
            return (
                StatusCode::OK,
                Json(PromoValidateResponse {
                    valid: false,
                    code: Some(code),
                    uses_remaining: None,
                    expires_at: None,
                    description: None,
                    error: Some("Promo code not found".into()),
                }),
            )
                .into_response();
        }
    };

    use sqlx::Row;
    let uses_max: Option<i64> = row.try_get("uses_max").unwrap_or(None);
    let uses_count: i64 = row.try_get("uses_count").unwrap_or(0);
    let expires_at: Option<i64> = row.try_get("expires_at").unwrap_or(None);
    let created_by_server_url: Option<String> = row.try_get("created_by_server_url").unwrap_or(None);

    if let Some(exp) = expires_at {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if now > exp {
            return (
                StatusCode::OK,
                Json(PromoValidateResponse {
                    valid: false,
                    code: Some(code),
                    uses_remaining: None,
                    expires_at: Some(exp),
                    description: None,
                    error: Some("Promo code has expired".into()),
                }),
            )
                .into_response();
        }
    }

    if let Some(max) = uses_max {
        if uses_count >= max {
            return (
                StatusCode::OK,
                Json(PromoValidateResponse {
                    valid: false,
                    code: Some(code),
                    uses_remaining: Some(0),
                    expires_at,
                    description: None,
                    error: Some("Promo code has exhausted all uses".into()),
                }),
            )
                .into_response();
        }
        let remaining = max - uses_count;
        return (
            StatusCode::OK,
            Json(PromoValidateResponse {
                valid: true,
                code: Some(code),
                uses_remaining: Some(remaining),
                expires_at,
                description: created_by_server_url,
                error: None,
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(PromoValidateResponse {
            valid: true,
            code: Some(code),
            uses_remaining: None,
            expires_at,
            description: created_by_server_url,
            error: None,
        }),
    )
        .into_response()
}

// POST /promo/redeem — redeem a promo code for the authenticated user
pub async fn redeem_promo(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<RedeemPromoRequest>,
) -> impl IntoResponse {
    let claims = match extract_token(&*state.signing_key, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let user_uid = claims.uid;

    let code = req.code.trim().to_string();
    if code.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PromoRedeemResponse {
                ok: false,
                code: None,
                error: Some("Promo code cannot be empty".into()),
            }),
        )
            .into_response();
    }

    let row = sqlx::query(
        "SELECT uses_max, uses_count, expires_at, grants_premium FROM promo_codes WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let row = match row {
        Some(r) => r,
        None => {
            return (
                StatusCode::OK,
                Json(PromoRedeemResponse {
                    ok: false,
                    code: Some(code),
                    error: Some("Invalid promo code".into()),
                }),
            )
                .into_response();
        }
    };

    use sqlx::Row;
    let uses_max: Option<i64> = row.try_get("uses_max").unwrap_or(None);
    let uses_count: i64 = row.try_get("uses_count").unwrap_or(0);
    let expires_at: Option<i64> = row.try_get("expires_at").unwrap_or(None);
    let grants_premium: bool = row.try_get("grants_premium").unwrap_or(false);

    if let Some(exp) = expires_at {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if now > exp {
            return (
                StatusCode::OK,
                Json(PromoRedeemResponse {
                    ok: false,
                    code: Some(code),
                    error: Some("Promo code has expired".into()),
                }),
            )
                .into_response();
        }
    }

    if let Some(max) = uses_max {
        if uses_count >= max {
            return (
                StatusCode::OK,
                Json(PromoRedeemResponse {
                    ok: false,
                    code: Some(code),
                    error: Some("Promo code has no remaining uses".into()),
                }),
            )
                .into_response();
        }
    }

    let already: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_promos WHERE user_id = $1 AND promo_code = $2",
    )
    .bind(&user_uid)
    .bind(&code)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    if already > 0 {
        return (
            StatusCode::OK,
            Json(PromoRedeemResponse {
                ok: false,
                code: Some(code),
                error: Some("You have already redeemed this promo code".into()),
            }),
        )
            .into_response();
    }

    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PromoRedeemResponse {
                    ok: false,
                    code: Some(code),
                    error: Some("Transaction failed".into()),
                }),
            )
                .into_response();
        }
    };

    sqlx::query("INSERT INTO user_promos (user_id, promo_code) VALUES ($1, $2)")
        .bind(&user_uid)
        .bind(&code)
        .execute(&mut *tx)
        .await
        .ok();

    sqlx::query("UPDATE promo_codes SET uses_count = uses_count + 1 WHERE code = $1")
        .bind(&code)
        .execute(&mut *tx)
        .await
        .ok();

    if grants_premium {
        sqlx::query("UPDATE users SET premium = TRUE WHERE id = $1")
            .bind(&user_uid)
            .execute(&mut *tx)
            .await
            .ok();
    }

    tx.commit().await.ok();

    (
        StatusCode::OK,
        Json(PromoRedeemResponse {
            ok: true,
            code: Some(code),
            error: None,
        }),
    )
        .into_response()
}
