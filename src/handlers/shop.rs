use std::sync::Arc;

use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Json};
use serde_json::json;

use crate::{AppState, auth_helpers::extract_token, handlers::amps::grant_amps};

const ICHOR_PRICE_CENTS: u64 = 500; // $5.00
const ICHOR_PACK_AMOUNT: i64 = 500;
const ICHOR_PREMIUM_COST: i64 = 500;

// ─── POST /shop/buy-ichor ─────────────────────────────────────────────────────
// Creates a Stripe Checkout Session for a one-time $5 → 500 ichor purchase.
// Webhook (checkout.session.completed) credits the balance on completion.
pub async fn buy_ichor_checkout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match extract_token(&state.signing_key, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let secret_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) => k,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Stripe not configured"})),
        ).into_response(),
    };

    let success_url = std::env::var("STRIPE_SUCCESS_URL")
        .unwrap_or_else(|_| "https://zeeble.xyz/success".to_string());
    let cancel_url = std::env::var("STRIPE_CANCEL_URL")
        .unwrap_or_else(|_| "https://zeeble.xyz".to_string());

    let client = reqwest::Client::new();
    let amount_str = ICHOR_PRICE_CENTS.to_string();
    let ichor_str = ICHOR_PACK_AMOUNT.to_string();

    let params = [
        ("mode",                                                        "payment"),
        ("line_items[0][price_data][currency]",                         "usd"),
        ("line_items[0][price_data][unit_amount]",                      amount_str.as_str()),
        ("line_items[0][price_data][product_data][name]",               "500 Ichor"),
        ("line_items[0][price_data][product_data][description]",        "500 Ichor to spend in Zeeble"),
        ("line_items[0][quantity]",                                     "1"),
        ("success_url",                                                 success_url.as_str()),
        ("cancel_url",                                                  cancel_url.as_str()),
        ("metadata[user_id]",                                           claims.uid.as_str()),
        ("metadata[purchase_type]",                                     "ichor"),
        ("metadata[ichor_amount]",                                      ichor_str.as_str()),
    ];

    let res = match client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(&secret_key, Some(""))
        .form(&params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to contact Stripe"})),
        ).into_response(),
    };

    let data: serde_json::Value = match res.json().await {
        Ok(d) => d,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Invalid Stripe response"})),
        ).into_response(),
    };

    match data.get("url").and_then(|v| v.as_str()) {
        Some(url) => (StatusCode::OK, Json(json!({"ok": true, "url": url}))).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("No checkout URL in Stripe response: {data}")})),
        ).into_response(),
    }
}

// ─── POST /shop/premium-with-ichor ───────────────────────────────────────────
// Atomically deducts 500 ichor and activates Premium for the caller.
pub async fn premium_with_ichor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match extract_token(&state.signing_key, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    if claims.premium {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Already a Premium member"})),
        ).into_response();
    }

    let result = sqlx::query(
        "UPDATE users SET ichor_balance = ichor_balance - $1, premium = TRUE
         WHERE id = $2 AND ichor_balance >= $1",
    )
    .bind(ICHOR_PREMIUM_COST)
    .bind(&claims.uid)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 1 => {
            grant_amps(&state.db, &claims.uid).await;
            (StatusCode::OK, Json(json!({"ok": true}))).into_response()
        }
        Ok(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Not enough ichor — you need 500 ◈"})),
        ).into_response(),
        Err(e) => {
            tracing::error!("premium_with_ichor: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response()
        }
    }
}
