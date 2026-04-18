use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;

use crate::{AppState, auth_helpers::extract_token};

type HmacSha256 = Hmac<Sha256>;

// ─── POST /stripe/subscribe ───────────────────────────────────────────────────
// Creates (or retrieves) a Stripe Customer, creates a subscription in
// default_incomplete mode, then creates a SetupIntent so the frontend can
// collect card details without charging immediately.
// Returns { client_secret, subscription_id, invoice_id }

pub async fn create_subscription(
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
            Json(json!({"error": "Already subscribed to Premium"})),
        )
            .into_response();
    }

    let secret_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Stripe not configured"})),
            )
                .into_response()
        }
    };

    let price_id = match std::env::var("STRIPE_PRICE_ID") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "STRIPE_PRICE_ID not configured"})),
            )
                .into_response()
        }
    };

    let client = reqwest::Client::new();

    // ── 1. Get or create Stripe Customer ─────────────────────────────────────
    let stripe_customer_id = match get_or_create_customer(
        &client,
        &secret_key,
        &claims.uid,
        &claims.sub,
        &state.db,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e})),
            )
                .into_response()
        }
    };

    // ── 2. Create Subscription (default_incomplete) ───────────────────────────
    let sub_params = [
        ("customer", stripe_customer_id.as_str()),
        ("items[0][price]", price_id.as_str()),
        ("payment_behavior", "default_incomplete"),
        ("payment_settings[save_default_payment_method]", "on_subscription"),
        ("metadata[user_id]", claims.uid.as_str()),
    ];

    let sub_res = match client
        .post("https://api.stripe.com/v1/subscriptions")
        .basic_auth(&secret_key, Some(""))
        .form(&sub_params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to contact Stripe"})),
            )
                .into_response()
        }
    };

    let sub_data: serde_json::Value = match sub_res.json().await {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Invalid Stripe subscription response"})),
            )
                .into_response()
        }
    };

    let subscription_id = match sub_data.get("id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("No subscription id: {sub_data}")})),
            )
                .into_response()
        }
    };

    let invoice_id = match sub_data.pointer("/latest_invoice/id").and_then(|v| v.as_str())
        .or_else(|| sub_data.get("latest_invoice").and_then(|v| v.as_str()))
    {
        Some(id) => id.to_string(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "No invoice id in subscription response"})),
            )
                .into_response()
        }
    };

    // ── 3. Create SetupIntent — collect card details without charging yet ─────
    // Stripe flexible billing doesn't auto-create PaymentIntents, so we use a
    // SetupIntent to securely collect the card, then pay the invoice explicitly.
    let si_params = [
        ("customer", stripe_customer_id.as_str()),
        ("usage", "off_session"),
        ("payment_method_types[]", "card"),
        ("metadata[invoice_id]", invoice_id.as_str()),
        ("metadata[subscription_id]", subscription_id.as_str()),
        ("metadata[user_id]", claims.uid.as_str()),
    ];

    let si_res = match client
        .post("https://api.stripe.com/v1/setup_intents")
        .basic_auth(&secret_key, Some(""))
        .form(&si_params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create SetupIntent"})),
            )
                .into_response()
        }
    };

    let si_data: serde_json::Value = match si_res.json().await {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Invalid SetupIntent response"})),
            )
                .into_response()
        }
    };

    let client_secret = match si_data.get("client_secret").and_then(|v| v.as_str()) {
        Some(cs) => cs.to_string(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("No client_secret in SetupIntent: {si_data}")})),
            )
                .into_response()
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "client_secret": client_secret,
            "subscription_id": subscription_id,
            "invoice_id": invoice_id,
        })),
    )
        .into_response()
}

// ─── POST /stripe/confirm ─────────────────────────────────────────────────────
// After the frontend confirms the SetupIntent (card saved), this endpoint pays
// the subscription's first invoice using that payment method.

#[derive(Deserialize)]
pub struct ConfirmPaymentRequest {
    pub invoice_id: String,
    pub payment_method_id: String,
}

pub async fn confirm_payment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ConfirmPaymentRequest>,
) -> impl IntoResponse {
    let _claims = match extract_token(&state.signing_key, &headers).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let secret_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Stripe not configured"})),
            )
                .into_response()
        }
    };

    let client = reqwest::Client::new();

    // Pay the invoice with the collected payment method
    let pay_params = [
        ("payment_method", body.payment_method_id.as_str()),
    ];

    let pay_res = match client
        .post(format!(
            "https://api.stripe.com/v1/invoices/{}/pay",
            body.invoice_id
        ))
        .basic_auth(&secret_key, Some(""))
        .form(&pay_params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to pay invoice"})),
            )
                .into_response()
        }
    };

    let pay_data: serde_json::Value = match pay_res.json().await {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Invalid invoice pay response"})),
            )
                .into_response()
        }
    };

    let status = pay_data.get("status").and_then(|v| v.as_str()).unwrap_or("");

    // Check if payment requires further action (3DS)
    if let Some(pi) = pay_data.get("payment_intent") {
        if let Some(cs) = pi.get("client_secret").and_then(|v| v.as_str()) {
            return (
                StatusCode::OK,
                Json(json!({
                    "requires_action": true,
                    "client_secret": cs,
                })),
            )
                .into_response();
        }
    }

    if status == "paid" {
        (StatusCode::OK, Json(json!({"status": "paid"}))).into_response()
    } else {
        (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"error": format!("Invoice payment failed: {pay_data}")})),
        )
            .into_response()
    }
}

// ─── POST /stripe/checkout ────────────────────────────────────────────────────
// Creates a Stripe Checkout Session (hosted payment page) and returns the URL.
// The desktop app opens this URL in the user's real browser — no card details
// ever touch the app, and no Stripe.js is needed in the frontend.

pub async fn create_checkout_session(
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
            Json(json!({"error": "Already subscribed to Premium"})),
        )
            .into_response();
    }

    let secret_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) => k,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Stripe not configured"})),
        ).into_response(),
    };

    let price_id = match std::env::var("STRIPE_PRICE_ID") {
        Ok(p) if !p.is_empty() => p,
        _ => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "STRIPE_PRICE_ID not configured"})),
        ).into_response(),
    };

    let success_url = std::env::var("STRIPE_SUCCESS_URL")
        .unwrap_or_else(|_| "https://zeeble.xyz/success".to_string());
    let cancel_url = std::env::var("STRIPE_CANCEL_URL")
        .unwrap_or_else(|_| "https://zeeble.xyz".to_string());

    let client = reqwest::Client::new();

    let stripe_customer_id = match get_or_create_customer(
        &client, &secret_key, &claims.uid, &claims.sub, &state.db,
    ).await {
        Ok(id) => id,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        ).into_response(),
    };

    let params = [
        ("customer",                                    stripe_customer_id.as_str()),
        ("mode",                                        "subscription"),
        ("line_items[0][price]",                        price_id.as_str()),
        ("line_items[0][quantity]",                     "1"),
        ("success_url",                                 success_url.as_str()),
        ("cancel_url",                                  cancel_url.as_str()),
        ("subscription_data[metadata][user_id]",        claims.uid.as_str()),
        ("metadata[user_id]",                           claims.uid.as_str()),
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
        Some(url) => (StatusCode::OK, Json(json!({"url": url}))).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("No checkout URL in Stripe response: {data}")})),
        ).into_response(),
    }
}

// ─── POST /stripe/webhook ─────────────────────────────────────────────────────

pub async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let webhook_secret = match std::env::var("STRIPE_WEBHOOK_SECRET") {
        Ok(s) if !s.is_empty() && s != "whsec_" => s,
        _ => return StatusCode::OK.into_response(), // webhook not configured yet, ignore
    };

    let sig_header = match headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Parse t= and v1= from the Stripe-Signature header
    let mut timestamp = "";
    let mut v1_sig = "";
    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("t=") {
            timestamp = v;
        }
        if let Some(v) = part.strip_prefix("v1=") {
            v1_sig = v;
        }
    }

    if timestamp.is_empty() || v1_sig.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Verify HMAC-SHA256
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(&body));
    let mut mac = match HmacSha256::new_from_slice(webhook_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    if expected != v1_sig {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match event.get("type").and_then(|t| t.as_str()) {
        // Payment succeeded — activate premium
        Some("invoice.payment_succeeded") => {
            if let Some(user_id) = event
                .pointer("/data/object/subscription_details/metadata/user_id")
                .or_else(|| event.pointer("/data/object/metadata/user_id"))
                .and_then(|v| v.as_str())
            {
                let _ = sqlx::query(
                    "UPDATE users SET premium = TRUE WHERE id = $1",
                )
                .bind(user_id)
                .execute(&state.db)
                .await;
            }
        }
        // Subscription cancelled or payment failed — revoke premium
        Some("customer.subscription.deleted") | Some("invoice.payment_failed") => {
            if let Some(user_id) = event
                .pointer("/data/object/metadata/user_id")
                .and_then(|v| v.as_str())
            {
                let _ = sqlx::query(
                    "UPDATE users SET premium = FALSE WHERE id = $1",
                )
                .bind(user_id)
                .execute(&state.db)
                .await;
            }
        }
        _ => {}
    }

    StatusCode::OK.into_response()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async fn get_or_create_customer(
    client: &reqwest::Client,
    secret_key: &str,
    user_id: &str,
    beam_identity: &str,
    db: &sqlx::PgPool,
) -> Result<String, String> {
    // Check if we already stored a Stripe customer ID
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT stripe_customer_id FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e: sqlx::Error| e.to_string())?;

    if let Some((Some(cid),)) = row {
        if !cid.is_empty() {
            return Ok(cid);
        }
    }

    // Create a new Stripe customer
    let params = [
        ("metadata[user_id]", user_id),
        ("metadata[beam]", beam_identity),
    ];

    let res = client
        .post("https://api.stripe.com/v1/customers")
        .basic_auth(secret_key, Some(""))
        .form(&params)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let data: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;

    let cid = data
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("No customer id in Stripe response: {data}"))?
        .to_string();

    // Persist the customer ID
    sqlx::query(
        "UPDATE users SET stripe_customer_id = $1 WHERE id = $2",
    )
    .bind(&cid)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e: sqlx::Error| e.to_string())?;

    Ok(cid)
}
