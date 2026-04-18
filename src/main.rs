mod auth_helpers;
mod beam;
mod db;
mod email;
mod handlers;
mod models;
mod rate_limit;

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rate_limit::RateLimiter;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    Json, Router,
    routing::{delete, get, post, put},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dotenvy::dotenv;
use ed25519_dalek::{
    SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use pkcs8::LineEnding;
use rand_core::OsRng;
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use axum::http::{Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};

use axum::extract::State;
use handlers::{
    account::{
        account_info, get_attachment, get_public_profile, sub_action, create_sub_account,
        delete_sub_account, generate_recovery_codes_handler, recovery_codes_status,
        rotate_bot_token, switch_alt, totp_disable, totp_enable, totp_setup, update_beam_tag,
        update_display_name, update_email, update_password, upload_avatar, upload_banner,
        send_email_pin, verify_email_pin,
        send_password_reset_pin, reset_password_with_pin,
    },
    auth::{exchange, health, login, logout, refresh, register, validate},
    promo::{redeem_promo, validate_promo},
    stripe::{confirm_payment, create_checkout_session, create_subscription, stripe_webhook},
    social::{
        accept_friend_request, add_server, create_cloud_server, list_friends,
        list_incoming_requests, list_servers, register_server, remove_server, send_friend_request,
    },
};

// ─── CORS ─────────────────────────────────────────────────────────────────────

fn build_cors_layer() -> CorsLayer {
    let allow_origin = if let Ok(origins_str) = std::env::var("ALLOWED_ORIGINS") {
        // Production: explicit allowlist from env var
        let origins: Vec<axum::http::HeaderValue> = origins_str
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        AllowOrigin::list(origins)
    } else {
        // Default: allow all localhost variants (any scheme/port) for local dev
        AllowOrigin::predicate(|origin: &axum::http::HeaderValue, _| {
            let s = origin.to_str().unwrap_or("");
            s == "tauri://localhost"
                || s.starts_with("http://localhost")
                || s.starts_with("https://localhost")
                || s.starts_with("http://tauri.localhost")
                || s.starts_with("https://tauri.localhost")
        })
    };
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}

// ─── JWKS Handler ─────────────────────────────────────────────────────────────

async fn jwks_handler(state: State<Arc<AppState>>) -> impl IntoResponse {
    let verifying_key = state.signing_key.verifying_key();
    let x = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());

    let jwks = json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
                "alg": "EdDSA",
                "kid": "auth-1"
            }
        ]
    });

    (StatusCode::OK, Json(jwks))
}

// ─── App State ────────────────────────────────────────────────────────────────

pub struct AppState {
    pub db: PgPool,
    pub signing_key: Arc<SigningKey>,
    /// Rate limiter shared across auth endpoints (login/register/refresh).
    /// 10 requests per 60 seconds per client IP by default; override with
    /// AUTH_RATE_LIMIT_REQUESTS and AUTH_RATE_LIMIT_WINDOW_SECS env vars.
    pub auth_rate_limiter: Arc<RateLimiter>,
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async fn connect_with_retry(database_url: &str) -> PgPool {
    let mut delay = std::time::Duration::from_secs(1);
    loop {
        match PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await
        {
            Ok(pool) => return pool,
            Err(e) => {
                eprintln!("PostgreSQL not ready, retrying in {}s: {}", delay.as_secs(), e);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(16));
            }
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = connect_with_retry(&database_url).await;

    db::run_migrations(&pool).await;

    // ─── Ed25519 Key Management ─────────────────────────────────────────────────
    let key_path = std::env::var("JWT_PRIVATE_KEY_PATH")
        .unwrap_or_else(|_| "keys/auth-private.pem".to_string());
    let signing_key: Arc<SigningKey> = if Path::new(&key_path).exists() {
        let pem_str = fs::read_to_string(&key_path).expect("Failed to read Ed25519 private key");
        let key = SigningKey::from_pkcs8_pem(&pem_str)
            .expect("Failed to parse Ed25519 private key from PEM");
        Arc::new(key)
    } else {
        println!("Generating new Ed25519 keypair at {}", key_path);
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        if let Some(parent) = Path::new(&key_path).parent() {
            fs::create_dir_all(parent).expect("Failed to create keys directory");
        }
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("Failed to encode key to PEM");
        fs::write(&key_path, pem).expect("Failed to write Ed25519 private key to file");
        Arc::new(key)
    };
    // ─────────────────────────────────────────────────────────────────────────────

    let rate_limit_requests: u32 = std::env::var("AUTH_RATE_LIMIT_REQUESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let rate_limit_window: u64 = std::env::var("AUTH_RATE_LIMIT_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let state = Arc::new(AppState {
        db: pool,
        signing_key,
        auth_rate_limiter: Arc::new(RateLimiter::new(rate_limit_requests, rate_limit_window)),
    });

    let app = Router::new()
        // JWKS
        .route("/.well-known/jwks.json", get(jwks_handler))
        // Auth
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/validate", post(validate))
        .route("/exchange", post(exchange))
        .route("/health", get(health))
        // Account
        .route("/account/switch_alt", post(switch_alt))
        .route("/account/sub", post(create_sub_account))
        .route("/account/info", get(account_info))
        .route("/account/name", post(update_display_name))
        .route("/account/beam", post(update_beam_tag))
        .route("/account/password", post(update_password))
        .route("/account/password/reset-pin", post(send_password_reset_pin))
        .route("/account/password/reset", post(reset_password_with_pin))
        .route("/account/email", post(update_email))
        .route("/account/email/send-pin", post(send_email_pin))
        .route("/account/email/verify-pin", post(verify_email_pin))
        .route("/account/sub/action", post(sub_action))
        .route("/account/child/action", post(sub_action)) // backward compat alias
        .route("/account/sub/:id", delete(delete_sub_account))
        .route("/account/bot/rotate", post(rotate_bot_token))
        .route("/account/avatar", post(upload_avatar))
        .route("/account/banner", post(upload_banner))
        .route("/users/:beam_identity", get(get_public_profile))
        .route("/account/totp/setup",   post(totp_setup))
        .route("/account/totp/enable",  post(totp_enable))
        .route("/account/totp",         delete(totp_disable))
        .route("/account/recovery-codes",        post(generate_recovery_codes_handler))
        .route("/account/recovery-codes/status", get(recovery_codes_status))
        .route("/attachments/:id", get(get_attachment))
        // Social & multi-server
        .route("/servers/register", post(register_server))
        .route("/servers/cloud", post(create_cloud_server))
        .route("/servers", get(list_servers))
        .route("/servers", post(add_server))
        .route("/servers/:url", delete(remove_server))
        .route("/friends", get(list_friends))
        .route("/friends", post(send_friend_request))
        .route("/friends/:id/accept", put(accept_friend_request))
        .route("/friend-requests", get(list_incoming_requests))
        // Promo codes
        .route("/promo/validate", post(validate_promo))
        .route("/promo/redeem", post(redeem_promo))
        // Stripe
        .route("/stripe/checkout", post(create_checkout_session))
        .route("/stripe/subscribe", post(create_subscription))
        .route("/stripe/confirm", post(confirm_payment))
        .route("/stripe/webhook", post(stripe_webhook))
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(50 * 1024 * 1024))
        .layer(build_cors_layer());

    println!("Zeeble auth server running on http://localhost:8001");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8001")
        .await
        .expect("Failed to bind port 3001");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("Server error");
}
