use axum::{
    Json,
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::{DEFAULT_COST, hash, verify};
use ed25519_dalek::SigningKey;
use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngExt;

use crate::models::{AccessClaims, AccountType, BotClaims, ErrorResponse};

pub const ACCESS_TOKEN_EXPIRY: u64 = 86400; // 24 hours

// ─── PKCS8 v2 DER ─────────────────────────────────────────────────────────────
// ed25519-dalek 2.x produces PKCS8 v1 (no public key), but ring 0.16.x (used
// by jsonwebtoken 8.x) requires PKCS8 v2 (OneAsymmetricKey with public key).
// We construct the 85-byte v2 DER manually from the raw key bytes.
pub fn signing_key_to_pkcs8_v2_der(signing_key: &SigningKey) -> [u8; 85] {
    let private_bytes = signing_key.to_bytes();
    let public_bytes = signing_key.verifying_key().to_bytes();
    let mut der = [0u8; 85];
    // SEQUENCE (83 bytes)
    der[0] = 0x30;
    der[1] = 0x53;
    // version = 1  (v2 uses version INTEGER = 1)
    der[2] = 0x02;
    der[3] = 0x01;
    der[4] = 0x01;
    // algorithm SEQUENCE { OID 1.3.101.112 }
    der[5] = 0x30;
    der[6] = 0x05;
    der[7] = 0x06;
    der[8] = 0x03;
    der[9] = 0x2b;
    der[10] = 0x65;
    der[11] = 0x70;
    // privateKey OCTET STRING (34 bytes) wrapping CurvePrivateKey OCTET STRING (32 bytes)
    der[12] = 0x04;
    der[13] = 0x22;
    der[14] = 0x04;
    der[15] = 0x20;
    der[16..48].copy_from_slice(&private_bytes);
    // [1] EXPLICIT (35 bytes) — publicKey BIT STRING
    der[48] = 0xa1;
    der[49] = 0x23;
    der[50] = 0x03;
    der[51] = 0x21;
    der[52] = 0x00; // 0 unused bits
    der[53..85].copy_from_slice(&public_bytes);
    der
}

// ─── Token Creation ───────────────────────────────────────────────────────────

pub fn make_access_token(
    signing_key: &SigningKey,
    beam_identity: &str,
    id: &str,
    parent_uid: Option<&str>,
    account_type: &AccountType,
    premium: bool,
    verified: bool,
    avatar_attachment_id: Option<i64>,
    display_name: Option<String>,
) -> Result<String, Error> {
    let exp = now_secs() + ACCESS_TOKEN_EXPIRY as usize;
    let claims = AccessClaims {
        sub: beam_identity.to_string(),
        uid: id.to_string(),
        parent_uid: parent_uid.map(|s| s.to_string()),
        account_type: account_type.as_str().to_string(),
        premium,
        verified,
        exp,
        aud: None,
        avatar_attachment_id,
        display_name,
    };
    let der = signing_key_to_pkcs8_v2_der(signing_key);
    let enc_key = EncodingKey::from_ed_der(&der);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("auth-1".to_string());
    encode(&header, &claims, &enc_key)
}

pub fn make_bot_token(
    signing_key: &SigningKey,
    beam_identity: &str,
    id: &str,
    parent_uid: &str,
    version: i64,
) -> Result<String, Error> {
    let claims = BotClaims {
        sub: beam_identity.to_string(),
        uid: id.to_string(),
        parent_uid: parent_uid.to_string(),
        account_type: "bot".to_string(),
        token_version: version,
        exp: 4102444800, // 2100-01-01
    };
    let der = signing_key_to_pkcs8_v2_der(signing_key);
    let enc_key = EncodingKey::from_ed_der(&der);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("auth-1".to_string());
    encode(&header, &claims, &enc_key)
}

pub fn decode_access_token(token: &str, signing_key: &SigningKey) -> Result<AccessClaims, Error> {
    let verifying_key = signing_key.verifying_key();
    let x_bytes = verifying_key.to_bytes();
    // from_ed_components expects the JWK "x" field: base64url without padding
    let x_b64 = URL_SAFE_NO_PAD.encode(x_bytes);
    let decoding_key = DecodingKey::from_ed_components(&x_b64)
        .map_err(|_| Error::from(ErrorKind::InvalidAlgorithm))?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = true;
    let data = decode::<AccessClaims>(token, &decoding_key, &validation)?;
    Ok(data.claims)
}

pub fn decode_bot_token(token: &str, signing_key: &SigningKey) -> Result<BotClaims, Error> {
    let verifying_key = signing_key.verifying_key();
    let x_b64 = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    let decoding_key = DecodingKey::from_ed_components(&x_b64)
        .map_err(|_| Error::from(ErrorKind::InvalidAlgorithm))?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = true;
    let data = decode::<BotClaims>(token, &decoding_key, &validation)?;
    Ok(data.claims)
}

pub fn now_secs() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as usize
}

// ─── Refresh Token Helpers ────────────────────────────────────────────────────

/// Generate a random opaque refresh token string
/// rand 0.10: rand::rng() returns ThreadRng, Rng::random::<T>() replaces old gen::<T>()
pub fn generate_refresh_token() -> String {
    let mut rng = rand::rng();
    (0..64)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

/// Hash the refresh token before storing — so a DB leak doesn't expose sessions
pub fn hash_refresh_token(token: &str) -> String {
    hash(token, DEFAULT_COST).expect("bcrypt hash failed")
}

pub fn verify_refresh_token(raw: &str, stored_hash: &str) -> bool {
    verify(raw, stored_hash).unwrap_or(false)
}

// ─── TOTP ─────────────────────────────────────────────────────────────────────

/// Verify a TOTP code against a base32-encoded secret.
pub fn verify_totp(secret_b32: &str, code: &str) -> bool {
    use totp_rs::{Algorithm, Secret, TOTP};
    let secret = Secret::Encoded(secret_b32.to_string());
    let bytes = match secret.to_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes) {
        Ok(t) => t,
        Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}

/// Generate a new TOTP secret. Returns (base32_secret, otpauth_url).
pub fn generate_totp_secret(beam_identity: &str) -> (String, String) {
    use totp_rs::Secret;
    let secret = Secret::generate_secret();
    let encoded = secret.to_encoded().to_string();
    let label = beam_identity.replace('@', "%40").replace(' ', "%20");
    let issuer = "Zeeble";
    let url = format!(
        "otpauth://totp/{issuer}:{label}?secret={encoded}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    );
    (encoded, url)
}

/// Generate 8 plaintext recovery codes.
pub fn generate_recovery_codes() -> Vec<String> {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..8).map(|_| {
        let a: u32 = rng.random_range(0..=9999);
        let b: u32 = rng.random_range(0..=9999);
        let c: u32 = rng.random_range(0..=9999);
        format!("{:04}-{:04}-{:04}", a, b, c)
    }).collect()
}

/// Hash a recovery code for storage (SHA-256, hex-encoded).
pub fn hash_recovery_code(code: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(code.trim().to_lowercase().as_bytes());
    hex::encode(hasher.finalize())
}

// ─── Request Auth Extraction ──────────────────────────────────────────────────

/// Helper to extract and decode token from Authorization header
pub async fn extract_token(
    signing_key: &SigningKey,
    headers: &HeaderMap,
) -> Result<AccessClaims, (StatusCode, Json<ErrorResponse>)> {
    let auth = headers.get("Authorization").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing Authorization header".into(),
            }),
        )
    })?;
    let bearer = auth.to_str().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid Authorization header".into(),
            }),
        )
    })?;
    if !bearer.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid Authorization format".into(),
            }),
        ));
    }
    let token = &bearer[7..];
    match decode_access_token(token, signing_key) {
        Ok(claims) => Ok(claims),
        Err(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
            }),
        )),
    }
}
