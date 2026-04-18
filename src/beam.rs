use rand::RngExt;
use sqlx::PgPool;

// ─── Beam Identity Constants ──────────────────────────────────────────────────

const FREE_BEAM_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
pub const BEAM_TAG_LEN: usize = 5;
pub const BEAM_TAG_MAX: usize = 5;
pub const DISPLAY_NAME_MAX: usize = 12;

// Beam identity separators by account type
const SEPARATOR_PRIMARY: char = '»';
const SEPARATOR_ALT: char = '§';
const SEPARATOR_CHILD: char = '‡';
const SEPARATOR_BOT: char = 'λ';
const SEPARATOR_STREAMER: char = '@';

pub fn get_separator_for_account_type(account_type: &str) -> char {
    match account_type {
        "primary" => SEPARATOR_PRIMARY,
        "alt" => SEPARATOR_ALT,
        "child" => SEPARATOR_CHILD,
        "bot" => SEPARATOR_BOT,
        "streamer" => SEPARATOR_STREAMER,
        _ => SEPARATOR_PRIMARY,
    }
}

// ─── Beam Helpers ─────────────────────────────────────────────────────────────

pub fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

pub fn split_beam(input: &str) -> (String, String) {
    let n = normalize(input);
    let separators = [
        SEPARATOR_PRIMARY,
        SEPARATOR_ALT,
        SEPARATOR_CHILD,
        SEPARATOR_BOT,
        SEPARATOR_STREAMER,
    ];
    for &sep in separators.iter() {
        if let Some(pos) = n.rfind(sep) {
            return (n[..pos].to_string(), n[pos + sep.len_utf8()..].to_string());
        }
    }
    // No separator found — return whole string as name, empty tag
    (n, String::new())
}

pub fn make_beam_identity(display_name: &str, beam_tag: &str, account_type: &str) -> String {
    let separator = get_separator_for_account_type(account_type);
    format!("{}{}{}", display_name, separator, beam_tag)
}

// rand 0.10: rand::rng() replaces thread_rng(), random_range(a..b) replaces gen_range(a, b)
pub fn random_beam_tag() -> String {
    let mut rng = rand::rng();
    (0..BEAM_TAG_LEN)
        .map(|_| FREE_BEAM_CHARS[rng.random_range(0..FREE_BEAM_CHARS.len())] as char)
        .collect()
}

pub fn validate_premium_tag(tag: &str) -> bool {
    let t = tag.trim();
    !t.is_empty() && t.chars().count() <= BEAM_TAG_MAX && !t.chars().any(|c| c.is_control())
}

pub fn validate_display_name(name: &str) -> bool {
    let t = name.trim();
    !t.is_empty() && t.chars().count() <= DISPLAY_NAME_MAX && !t.chars().any(|c| c.is_control())
}

/// Assigns a unique beam tag for a display name.
///
/// Attempts up to 100 random tags to find an unused combination.
/// Returns None if no unique tag is found after 100 attempts.
pub async fn assign_beam_tag(pool: &PgPool, display_name: &str) -> Option<String> {
    for _ in 0..100 {
        let tag = random_beam_tag();
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE display_name = $1 AND beam_tag = $2",
        )
        .bind(display_name)
        .bind(&tag)
        .fetch_one(pool)
        .await
        .unwrap_or(0);
        if count == 0 {
            return Some(tag);
        }
    }
    None
}
