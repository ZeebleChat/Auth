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
    admin::{
        admin_me, admin_stats, admin_list_users, admin_lock_user, admin_unlock_user,
        admin_list_staff, admin_add_staff, admin_remove_staff,
        admin_list_promos, admin_create_promo, admin_delete_promo,
        admin_list_bans, admin_list_broadcasts, admin_send_broadcast, admin_list_servers,
        admin_delete_server,
    },
    amps::{apply_amp, get_amps, remove_amp, server_amp_info},
    auth::{exchange, health, login, logout, refresh, register, validate},
    oauth::{discord_callback, discord_start, discord_unlink, oauth_poll, steam_callback, steam_start, steam_unlink},
    promo::{redeem_promo, validate_promo},
    shop::{buy_ichor_checkout, premium_with_ichor},
    stripe::{confirm_payment, create_checkout_session, create_subscription, stripe_webhook, start_identity_verification, identity_status},
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
    pub auth_rate_limiter: Arc<RateLimiter>,
    // Discord OAuth2
    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub discord_redirect_uri: String,
    // Steam OpenID
    pub steam_api_key: String,
    pub steam_redirect_uri: String,
    pub steam_realm: String,
}

// ─── Status heartbeat ─────────────────────────────────────────────────────────

fn spawn_heartbeat(key: &'static str) {
    let url = std::env::var("ZSTATUS_URL")
        .unwrap_or_else(|_| "http://zstatus:8004".to_string());
    let secret = std::env::var("ZSTATUS_SECRET").unwrap_or_default();

    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("heartbeat client");
        let endpoint = format!("{}/heartbeat", url);
        loop {
            let body = serde_json::json!({ "key": key, "ok": true });
            let mut req = client.post(&endpoint).json(&body);
            if !secret.is_empty() {
                req = req.header("Authorization", format!("Bearer {}", secret));
            }
            if let Err(e) = req.send().await {
                eprintln!("[heartbeat] zstatus unreachable: {e}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
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
        discord_client_id:     std::env::var("DISCORD_CLIENT_ID").unwrap_or_default(),
        discord_client_secret: std::env::var("DISCORD_CLIENT_SECRET").unwrap_or_default(),
        discord_redirect_uri:  std::env::var("DISCORD_REDIRECT_URI").unwrap_or_default(),
        steam_api_key:         std::env::var("STEAM_API_KEY").unwrap_or_default(),
        steam_redirect_uri:    std::env::var("STEAM_REDIRECT_URI").unwrap_or_default(),
        steam_realm:           std::env::var("STEAM_REALM").unwrap_or_default(),
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
        // OAuth
        .route("/oauth/discord/start",    post(discord_start))
        .route("/oauth/discord/callback", get(discord_callback))
        .route("/oauth/discord",          delete(discord_unlink))
        .route("/oauth/steam/start",      post(steam_start))
        .route("/oauth/steam/callback",   get(steam_callback))
        .route("/oauth/steam",            delete(steam_unlink))
        .route("/oauth/poll",             get(oauth_poll))
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
        // Amps (server boosts for Radiant subscribers)
        .route("/amps", get(get_amps))
        .route("/amps/apply", post(apply_amp))
        .route("/amps/remove", post(remove_amp))
        .route("/amps/server", get(server_amp_info))
        // Promo codes
        .route("/promo/validate", post(validate_promo))
        .route("/promo/redeem", post(redeem_promo))
        .route("/shop/buy-ichor", post(buy_ichor_checkout))
        .route("/shop/premium-with-ichor", post(premium_with_ichor))
        // Stripe
        .route("/stripe/checkout", post(create_checkout_session))
        .route("/stripe/subscribe", post(create_subscription))
        .route("/stripe/confirm", post(confirm_payment))
        .route("/stripe/webhook", post(stripe_webhook))
        .route("/stripe/identity/start", post(start_identity_verification))
        .route("/stripe/identity/status", get(identity_status))
        // Admin — all routes require valid JWT; identity is taken from JWT claims only
        .route("/admin/me",                   get(admin_me))
        .route("/admin/stats",                get(admin_stats))
        .route("/admin/users",                get(admin_list_users))
        .route("/admin/users/:id/lock",       post(admin_lock_user))
        .route("/admin/users/:id/unlock",     post(admin_unlock_user))
        .route("/admin/staff",                get(admin_list_staff))
        .route("/admin/staff",                post(admin_add_staff))
        .route("/admin/staff/:uid",           delete(admin_remove_staff))
        .route("/admin/promos",               get(admin_list_promos))
        .route("/admin/promos",               post(admin_create_promo))
        .route("/admin/promos/:code",         delete(admin_delete_promo))
        .route("/admin/bans",                 get(admin_list_bans))
        .route("/admin/broadcasts",           get(admin_list_broadcasts))
        .route("/admin/broadcasts",           post(admin_send_broadcast))
        .route("/admin/servers",              get(admin_list_servers))
        .route("/admin/servers",              delete(admin_delete_server))
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(50 * 1024 * 1024))
        .layer(build_cors_layer());

    spawn_heartbeat("api");

    println!("Zeeble auth server running on http://localhost:8001");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8001")
        .await
        .expect("Failed to bind port 3001");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("Server error");
}
