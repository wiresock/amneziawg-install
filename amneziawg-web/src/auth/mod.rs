//! Authentication primitives for the web panel.
//!
//! # Design
//!
//! The panel uses **session cookie auth** for both HTML pages and JSON API
//! calls, with an optional **bearer token** for headless API access.
//!
//! Sessions are kept in an in-memory `HashMap<session_id, created_at>`.  On
//! restart all sessions are invalidated (acceptable for a single-admin MVP).
//!
//! ## Password storage
//!
//! Passwords are stored as Argon2id PHC strings; plaintext passwords are never
//! stored or logged.  Use `AuthConfig::hash_password` (or any Argon2id tool)
//! to generate the hash.
//!
//! ## CSRF
//!
//! Session cookies are set with `SameSite=Lax`.  All HTML-form write routes
//! (POST) are not reachable cross-origin via simple-form CSRF because:
//! - `SameSite=Lax` blocks cross-origin POST form submissions.
//! - The JSON PATCH endpoint requires `Content-Type: application/json` which
//!   is not a "simple" request and is blocked by CORS preflight.
//!
//! For enhanced hardening a reverse proxy should restrict to same-origin, and
//! `SameSite=Strict` or explicit CSRF tokens can be added in a future PR.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rand::rngs::OsRng;
use rand::RngCore;

/// Name of the HTTP cookie that carries the session token.
pub const SESSION_COOKIE: &str = "awg_session";

/// How long a session is valid after creation.
pub const SESSION_LIFETIME: Duration = Duration::from_secs(86_400); // 24 h

// ── AuthConfig ───────────────────────────────────────────────────────────────

/// Runtime authentication configuration derived from environment variables.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// When `false` every request is let through without any credential check.
    /// Useful for local development or trusted-network deployments.
    pub enabled: bool,

    /// Expected username for the single admin account.
    pub username: String,

    /// Argon2id PHC string of the admin password.
    ///
    /// Generate with:
    /// ```text
    /// python3 -c "import argon2; print(argon2.PasswordHasher().hash('yourpassword'))"
    /// ```
    /// or any Argon2id-compatible tool.
    pub password_hash: String,

    /// Optional static bearer token accepted on the `Authorization: Bearer <token>`
    /// header for headless API access.  When absent, only session cookies are
    /// accepted for the API.
    pub api_token: Option<String>,

    /// Emit the `Secure` flag on the session cookie.
    ///
    /// Set to `true` when the panel is accessed over HTTPS.
    pub secure_cookie: bool,
}

impl AuthConfig {
    /// Create a disabled (pass-through) auth config.  Used when
    /// `AUTH_ENABLED=false` and in tests.
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            username: String::new(),
            password_hash: String::new(),
            api_token: None,
            secure_cookie: false,
        }
    }

    /// Hash a plaintext password using Argon2id with production-strength
    /// parameters.  The resulting PHC string should be stored in
    /// `AUTH_PASSWORD_HASH`.
    #[allow(dead_code)]
    pub fn hash_password(password: &str) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("argon2 hash failed")
            .to_string()
    }

    /// Same as `hash_password` but uses minimal Argon2 parameters so that
    /// test suites complete quickly.  **Never use in production.**
    #[cfg(test)]
    pub fn hash_password_fast(password: &str) -> String {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        // m=1024, t=1, p=1 – intentionally weak, for tests only.
        let params = argon2::Params::new(1024, 1, 1, None).expect("argon2 params");
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("argon2 test hash failed")
            .to_string()
    }
}

// ── Session store ─────────────────────────────────────────────────────────────

/// Thread-safe in-memory session store: `session_id → created_at`.
pub type SessionStore = Arc<RwLock<HashMap<String, Instant>>>;

/// Create a new, empty session store.
pub fn new_session_store() -> SessionStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Generate a cryptographically random 32-byte session ID, hex-encoded.
pub fn generate_session_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Return `true` if the given session token exists and has not expired.
///
/// Also removes expired sessions lazily on every call (amortised cleanup).
pub fn is_session_valid(store: &SessionStore, token: &str) -> bool {
    let mut map = store.write().expect("session store poisoned");
    // Lazy cleanup of expired sessions.
    map.retain(|_, created_at| created_at.elapsed() < SESSION_LIFETIME);
    map.contains_key(token)
}

/// Insert a new session token into the store.
pub fn add_session(store: &SessionStore, token: String) {
    store
        .write()
        .expect("session store poisoned")
        .insert(token, Instant::now());
}

/// Remove a session token from the store (logout).
pub fn remove_session(store: &SessionStore, token: &str) {
    store.write().expect("session store poisoned").remove(token);
}

// ── Password verification ─────────────────────────────────────────────────────

/// Verify `password` against an Argon2id PHC `hash` string.
///
/// Returns `false` on any parsing or verification failure (wrong password, bad
/// hash format, etc.) without revealing which failure occurred.  Uses
/// constant-time comparison provided by the `argon2` crate.
pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

/// Build the `Set-Cookie` header value for a new session.
pub fn make_session_cookie(token: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{name}={token}; HttpOnly; SameSite=Lax; Max-Age={max_age}; Path=/{secure_flag}",
        name = SESSION_COOKIE,
        max_age = SESSION_LIFETIME.as_secs(),
    )
}

/// Build the `Set-Cookie` header value that clears the session cookie.
pub fn clear_session_cookie() -> String {
    format!(
        "{name}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/",
        name = SESSION_COOKIE,
    )
}

/// Extract the session token from the raw `Cookie` header value, or `None`.
pub fn extract_session_token(cookie_header: &str) -> Option<String> {
    let prefix = format!("{SESSION_COOKIE}=");
    cookie_header
        .split(';')
        .find(|part| part.trim().starts_with(&prefix))
        .map(|part| part.trim()[prefix.len()..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── verify_password ────────────────────────────────────────────────────

    #[test]
    fn verify_password_correct() {
        let hash = AuthConfig::hash_password_fast("hunter2");
        assert!(verify_password(&hash, "hunter2"));
    }

    #[test]
    fn verify_password_wrong_password() {
        let hash = AuthConfig::hash_password_fast("hunter2");
        assert!(!verify_password(&hash, "wrong"));
    }

    #[test]
    fn verify_password_bad_hash_returns_false() {
        assert!(!verify_password("not-a-valid-hash", "any"));
    }

    // ── session store ──────────────────────────────────────────────────────

    #[test]
    fn add_and_validate_session() {
        let store = new_session_store();
        let id = generate_session_id();
        add_session(&store, id.clone());
        assert!(is_session_valid(&store, &id));
    }

    #[test]
    fn remove_session_invalidates() {
        let store = new_session_store();
        let id = generate_session_id();
        add_session(&store, id.clone());
        remove_session(&store, &id);
        assert!(!is_session_valid(&store, &id));
    }

    #[test]
    fn unknown_session_invalid() {
        let store = new_session_store();
        assert!(!is_session_valid(&store, "does-not-exist"));
    }

    #[test]
    fn generate_session_id_is_64_hex_chars() {
        let id = generate_session_id();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── cookie helpers ─────────────────────────────────────────────────────

    #[test]
    fn extract_session_token_found() {
        let header = "other=x; awg_session=abc123; foo=bar";
        assert_eq!(extract_session_token(header), Some("abc123".to_string()));
    }

    #[test]
    fn extract_session_token_not_found() {
        assert_eq!(extract_session_token("other=x; foo=bar"), None);
    }

    #[test]
    fn extract_session_token_first_in_list() {
        let header = "awg_session=tok1";
        assert_eq!(extract_session_token(header), Some("tok1".to_string()));
    }

    #[test]
    fn make_session_cookie_contains_required_attrs() {
        let c = make_session_cookie("mytoken", false);
        assert!(c.contains("awg_session=mytoken"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Lax"));
        assert!(c.contains("Max-Age="));
    }

    #[test]
    fn make_session_cookie_secure_flag() {
        let c = make_session_cookie("tok", true);
        assert!(c.contains("Secure"));
        let c_no = make_session_cookie("tok", false);
        assert!(!c_no.contains("Secure"));
    }

    #[test]
    fn clear_session_cookie_has_max_age_zero() {
        let c = clear_session_cookie();
        assert!(c.contains("Max-Age=0"));
        assert!(c.contains("awg_session=;"));
    }
}
