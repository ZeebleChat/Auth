use serde::{Deserialize, Serialize};

// ─── Account Types ────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AccountType {
    Primary,
    Alt,
    Child,
    Bot,
    Streamer,
}

impl AccountType {
    pub fn as_str(&self) -> &str {
        match self {
            AccountType::Primary => "primary",
            AccountType::Alt => "alt",
            AccountType::Child => "child",
            AccountType::Bot => "bot",
            AccountType::Streamer => "streamer",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "primary" => Some(AccountType::Primary),
            "alt" => Some(AccountType::Alt),
            "child" => Some(AccountType::Child),
            "bot" => Some(AccountType::Bot),
            "streamer" => Some(AccountType::Streamer),
            _ => None,
        }
    }
}

// ─── Auth Method Flags ────────────────────────────────────────────────────────

pub const AUTH_PASSWORD: i64 = 1;
pub const AUTH_PASSKEY: i64 = 2;
pub const AUTH_TOTP: i64 = 4;

// ─── JWT Claims ───────────────────────────────────────────────────────────────

// Access token — short lived, never stored
#[derive(Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String, // beam identity e.g. "sarah»k4mx9"
    pub uid: String, // account UUID
    pub parent_uid: Option<String>,
    pub account_type: String,
    pub premium: bool,
    pub verified: bool,
    pub exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>, // audience — set to target server URL when exchanging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_attachment_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>, // human-readable name separate from beam tag
}

// Bot token claims — carries token_version for rotation invalidation
#[derive(Serialize, Deserialize)]
pub struct BotClaims {
    pub sub: String,          // beam identity
    pub uid: String,          // bot UUID
    pub parent_uid: String,   // owner UUID
    pub account_type: String, // always "bot"
    pub token_version: i64,   // incremented on rotate, old tokens fail
    pub exp: usize,           // set to year 2100 — effectively permanent
}

// ─── Request Types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub display_name: String,
    pub password: Option<String>,
    pub email: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub beam_identity: String,
    pub password: Option<String>,
    pub totp_code: Option<String>,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String, // raw refresh token from client
    pub uid: String,           // which account to refresh
}

#[derive(Deserialize)]
pub struct ExchangeRequest {
    pub server_url: String,
}

#[derive(Deserialize)]
pub struct ValidateRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct SwitchAltRequest {
    pub primary_token: String, // access token of the primary account
    pub alt_id: String,
}

#[derive(Deserialize)]
pub struct CreateSubAccountRequest {
    pub parent_token: String,
    pub display_name: String,
    pub account_type: String,
    pub password: Option<String>, // required for child, ignored for alt and bot
}

#[derive(Deserialize)]
pub struct UpdateDisplayNameRequest {
    pub token: String,
    pub new_display_name: String,
}

#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    pub token: String,
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct UpdateBeamTagRequest {
    pub token: String,
    pub new_tag: String,
}

#[derive(Deserialize)]
pub struct UpdateEmailRequest {
    pub token: String,
    pub new_email: String,
}

#[derive(Deserialize)]
pub struct SendEmailPinRequest {
    pub token: String,
    pub email: String,
}

#[derive(Deserialize)]
pub struct VerifyEmailPinRequest {
    pub token: String,
    pub pin: String,
}

#[derive(Deserialize)]
pub struct SendPasswordResetPinRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordWithPinRequest {
    pub email: String,
    pub pin: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct SubActionRequest {
    pub parent_token: String,
    pub sub_id: String,
    pub action: SubAction,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubAction {
    Lock,
    Unlock,
    ResetPassword { new_password: String },
}

#[derive(Deserialize)]
pub struct RotateBotTokenRequest {
    pub parent_token: String,
    pub bot_id: String,
}

#[derive(Deserialize)]
pub struct UrlPath {
    pub url: String,
}

#[derive(Deserialize)]
pub struct FriendIdPath {
    pub id: String,
}

#[derive(Deserialize)]
pub struct SubAccountIdPath {
    pub id: String,
}

#[derive(Deserialize)]
pub struct AddServerRequest {
    pub server_url: String,
    pub server_name: Option<String>,
}

#[derive(Deserialize)]
pub struct RegisterServerRequest {
    pub server_url: String,
    pub owner_beam_identity: String,
    pub jwt_secret: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateCloudServerRequest {
    pub name: String,
    pub about: Option<String>,
}

#[derive(Deserialize)]
pub struct SendFriendRequest {
    pub friend_beam_identity: String,
}

#[derive(Deserialize)]
pub struct ValidatePromoRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct RedeemPromoRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct PromoValidateResponse {
    pub valid: bool,
    pub code: Option<String>,
    pub uses_remaining: Option<i64>,
    pub expires_at: Option<i64>,
    pub description: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct PromoRedeemResponse {
    pub ok: bool,
    pub code: Option<String>,
    pub error: Option<String>,
}

// ─── Response Types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,         // short lived, use for API calls
    pub refresh_token: String, // long lived, use to get new access tokens
    pub uid: String,           // user id
    pub beam_identity: String,
    pub account_type: String,
}

#[derive(Serialize)]
pub struct AccessTokenResponse {
    pub token: String,
    pub beam_identity: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Serialize)]
pub struct AccountInfoResponse {
    pub beam_identity: String,
    pub display_name: String,
    pub beam_tag: String,
    pub account_type: String,
    pub premium: bool,
    pub verified: bool,
    pub discord_linked: bool,
    pub auth_methods: Vec<String>,
    pub alts: Vec<SubAccountSummary>,
    pub children: Vec<SubAccountSummary>,
    pub bots: Vec<BotSummary>,
    pub streamers: Vec<SubAccountSummary>,
    pub servers: Vec<ServerSummary>,
    pub friends: Vec<FriendSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_attachment_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_attachment_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Serialize)]
pub struct PublicProfileResponse {
    pub beam_identity: String,
    pub display_name: String,
    pub premium: bool,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_attachment_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_attachment_id: Option<i64>,
}

#[derive(Serialize)]
pub struct SubAccountSummary {
    pub id: String,
    pub beam_identity: String,
    pub display_name: String,
    pub account_type: String,
    pub locked: bool,
}

#[derive(Serialize)]
pub struct BotSummary {
    pub id: String,
    pub beam_identity: String,
    pub display_name: String,
    pub account_type: String,
    pub token_version: i64,
    pub bot_token: String,
}

#[derive(Serialize)]
pub struct ServerSummary {
    pub server_url: String,
    pub server_name: Option<String>,
    pub joined_at: String,
    pub is_owner: bool,
}

#[derive(Serialize)]
pub struct FriendSummary {
    pub id: String,
    pub beam_identity: String,
    pub display_name: String,
    pub status: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_attachment_id: Option<i64>,
}

#[derive(Serialize)]
pub struct FriendRequestSummary {
    pub id: String,
    pub beam_identity: String,
    pub display_name: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_attachment_id: Option<i64>,
}

// ─── TOTP / 2FA ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TotpSetupRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub otpauth_url: String,
}

#[derive(Deserialize)]
pub struct TotpEnableRequest {
    pub token: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct TotpDisableRequest {
    pub token: String,
    pub password: String,
}

// ─── Recovery Codes ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RecoveryCodesRequest {
    pub token: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
    pub count: usize,
}

#[derive(Serialize)]
pub struct RecoveryCodesStatusResponse {
    pub enabled: bool,
    pub remaining: usize,
}

