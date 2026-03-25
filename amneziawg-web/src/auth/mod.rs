//! Authentication, session management, CSRF protection and login rate-limiting.
//!
//! # Session cookie auth
//!
//! Sessions are kept in an in-memory `HashMap<session_id, SessionEntry>`.
//! Each entry stores the creation time and a per-session CSRF token.
//! Session TTL is configurable via `AUTH_SESSION_TTL_SECS` (default 24 h).
//! On restart all sessions are invalidated (acceptable for a single-admin MVP).
//!
//! # CSRF protection
//!
//! Every authenticated session gets a random 16-byte CSRF token stored in the
//! session entry.  HTML forms include a hidden `csrf_token` field.  POST
//! handlers call `validate_form_csrf` to compare the submitted token against
//! the stored one using a constant-time comparison.
//!
//! The login form (before a session exists) uses a separate short-lived
//! pre-login CSRF token stored in `LoginCsrfStore` (10-minute TTL, single-use).
//!
//! When `AUTH_ENABLED=false` all CSRF checks are bypassed (dev/trusted-network).
//!
//! # Login rate limiting
//!
//! Sliding-window rate limiter keyed by client IP: max 5 attempts per 5-minute
//! window.  IP is extracted from `X-Forwarded-For` / `X-Real-IP` headers (set
//! by a reverse proxy).  Without a reverse proxy the key falls back to
//! `"unknown"` (global limit) — document this deployment assumption.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rand::rngs::OsRng;
use rand::RngCore;

/// Name of the HTTP cookie that carries the session token.
pub const SESSION_COOKIE: &str = "awg_session";

/// Default session lifetime (24 h).
pub const DEFAULT_SESSION_TTL_SECS: u64 = 86_400;

/// Maximum login attempts per rate-limit window.
pub const RATE_LIMIT_MAX_ATTEMPTS: u32 = 5;

/// Rate-limit sliding window.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(300); // 5 min

/// How long a pre-login CSRF token stays valid.
const LOGIN_CSRF_TTL: Duration = Duration::from_secs(600); // 10 min

// ── AuthConfig ───────────────────────────────────────────────────────────────

/// Runtime authentication configuration derived from environment variables.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// When `false` every request is let through without any credential check.
    pub enabled: bool,

    /// Expected username for the single admin account.
    pub username: String,

    /// Argon2id PHC string of the admin password.
    pub password_hash: String,

    /// Optional static bearer token for headless API access.
    pub api_token: Option<String>,

    /// Emit the `Secure` flag on the session cookie.
    pub secure_cookie: bool,

    /// How long a session is valid after creation.
    pub session_ttl: Duration,
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
            session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
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
        let params = argon2::Params::new(1024, 1, 1, None).expect("argon2 params");
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("argon2 test hash failed")
            .to_string()
    }
}

// ── Session store ─────────────────────────────────────────────────────────────

/// Data stored for each active session.
#[derive(Clone, Debug)]
pub struct SessionEntry {
    /// When the session was created.
    pub created_at: Instant,
    /// Per-session CSRF token embedded in HTML forms.
    pub csrf_token: String,
}

/// Thread-safe in-memory session store: `session_id → SessionEntry`.
pub type SessionStore = Arc<RwLock<HashMap<String, SessionEntry>>>;

/// Create a new, empty session store.
pub fn new_session_store() -> SessionStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Generate a cryptographically random 32-byte session ID, hex-encoded (64 chars).
pub fn generate_session_id() -> String {
    generate_hex_token(32)
}

/// Insert a new session into the store and return its CSRF token.
///
/// The CSRF token is a 16-byte random value (32-char hex string).
pub fn add_session(store: &SessionStore, session_id: String) -> String {
    let csrf_token = generate_hex_token(16);
    store.write().expect("session store poisoned").insert(
        session_id,
        SessionEntry {
            created_at: Instant::now(),
            csrf_token: csrf_token.clone(),
        },
    );
    csrf_token
}

/// Return `true` if the session token exists and has not expired.
///
/// Also removes expired sessions lazily on every call (amortised cleanup).
pub fn is_session_valid(store: &SessionStore, token: &str, ttl: Duration) -> bool {
    let mut map = store.write().expect("session store poisoned");
    map.retain(|_, e| e.created_at.elapsed() < ttl);
    map.contains_key(token)
}

/// Look up the CSRF token for a session.  Returns `None` if the session does
/// not exist or has expired.  Also runs lazy expiry cleanup.
pub fn get_session_csrf(store: &SessionStore, session_id: &str, ttl: Duration) -> Option<String> {
    let mut map = store.write().expect("session store poisoned");
    map.retain(|_, e| e.created_at.elapsed() < ttl);
    map.get(session_id).map(|e| e.csrf_token.clone())
}

/// Remove a session token from the store (logout).
pub fn remove_session(store: &SessionStore, token: &str) {
    store.write().expect("session store poisoned").remove(token);
}

// ── Pre-login CSRF store ───────────────────────────────────────────────────────

/// Short-lived CSRF tokens used on the login form (before a session exists).
pub type LoginCsrfStore = Arc<RwLock<HashMap<String, Instant>>>;

/// Create a new, empty login-CSRF store.
pub fn new_login_csrf_store() -> LoginCsrfStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Generate a pre-login CSRF token, store it, and return it.
pub fn generate_login_csrf(store: &LoginCsrfStore) -> String {
    let token = generate_hex_token(16);
    store
        .write()
        .expect("login csrf store poisoned")
        .insert(token.clone(), Instant::now());
    token
}

/// Validate and consume a pre-login CSRF token (single-use).
///
/// Returns `true` if the token was present and has not expired.
/// Expired tokens are removed lazily on every call.
pub fn consume_login_csrf(store: &LoginCsrfStore, token: &str) -> bool {
    let mut map = store.write().expect("login csrf store poisoned");
    map.retain(|_, created_at| created_at.elapsed() < LOGIN_CSRF_TTL);
    map.remove(token).is_some()
}

// ── Login rate limiter ────────────────────────────────────────────────────────

/// Sliding-window login attempt counters keyed by client identifier (IP).
pub type LoginRateLimiter = Arc<RwLock<HashMap<String, VecDeque<Instant>>>>;

/// Create a new, empty rate limiter.
pub fn new_login_rate_limiter() -> LoginRateLimiter {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Check whether a login attempt from `key` is allowed and record it.
///
/// Returns `true` (allowed) if the attempt count within `window` is below
/// `max_attempts`.  Returns `false` (blocked) otherwise.
///
/// The `key` is typically the client IP address extracted from
/// `X-Forwarded-For` / `X-Real-IP` headers.
pub fn check_and_record_login_attempt(
    limiter: &LoginRateLimiter,
    key: &str,
    max_attempts: u32,
    window: Duration,
) -> bool {
    let mut map = limiter.write().expect("rate limiter poisoned");
    let attempts = map.entry(key.to_string()).or_default();
    // Prune entries outside the current window.
    while attempts
        .front()
        .map(|t| t.elapsed() >= window)
        .unwrap_or(false)
    {
        attempts.pop_front();
    }
    if attempts.len() >= max_attempts as usize {
        return false;
    }
    attempts.push_back(Instant::now());
    true
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

// ── CSRF helpers ──────────────────────────────────────────────────────────────

/// Constant-time equality check for CSRF tokens.
///
/// Returns `false` immediately for unequal lengths (length is not secret for
/// random tokens of fixed size).  For equal-length strings uses a folded XOR
/// to avoid early-exit timing leaks.
pub fn csrf_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

/// Build the `Set-Cookie` header value for a new session.
pub fn make_session_cookie(token: &str, secure: bool, ttl: Duration) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{name}={token}; HttpOnly; SameSite=Lax; Max-Age={max_age}; Path=/{secure_flag}",
        name = SESSION_COOKIE,
        max_age = ttl.as_secs(),
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

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Generate a random token of `n` bytes, returned as a lowercase hex string.
fn generate_hex_token(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ttl() -> Duration {
        Duration::from_secs(DEFAULT_SESSION_TTL_SECS)
    }

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
        let _csrf = add_session(&store, id.clone());
        assert!(is_session_valid(&store, &id, test_ttl()));
    }

    #[test]
    fn add_session_returns_csrf_token() {
        let store = new_session_store();
        let id = generate_session_id();
        let csrf = add_session(&store, id.clone());
        assert_eq!(csrf.len(), 32); // 16 bytes → 32 hex chars
        assert!(csrf.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn get_session_csrf_returns_stored_token() {
        let store = new_session_store();
        let id = generate_session_id();
        let csrf = add_session(&store, id.clone());
        assert_eq!(get_session_csrf(&store, &id, test_ttl()), Some(csrf));
    }

    #[test]
    fn remove_session_invalidates() {
        let store = new_session_store();
        let id = generate_session_id();
        let _ = add_session(&store, id.clone());
        remove_session(&store, &id);
        assert!(!is_session_valid(&store, &id, test_ttl()));
    }

    #[test]
    fn unknown_session_invalid() {
        let store = new_session_store();
        assert!(!is_session_valid(&store, "does-not-exist", test_ttl()));
    }

    #[test]
    fn generate_session_id_is_64_hex_chars() {
        let id = generate_session_id();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn expired_session_is_invalid() {
        let store = new_session_store();
        let id = generate_session_id();
        let _ = add_session(&store, id.clone());
        // Use a TTL of 0 – session is immediately expired.
        assert!(!is_session_valid(&store, &id, Duration::from_secs(0)));
    }

    #[test]
    fn expired_session_csrf_returns_none() {
        let store = new_session_store();
        let id = generate_session_id();
        let _ = add_session(&store, id.clone());
        assert!(get_session_csrf(&store, &id, Duration::from_secs(0)).is_none());
    }

    // ── pre-login CSRF ─────────────────────────────────────────────────────

    #[test]
    fn login_csrf_valid_token_consumed() {
        let store = new_login_csrf_store();
        let token = generate_login_csrf(&store);
        assert!(consume_login_csrf(&store, &token));
    }

    #[test]
    fn login_csrf_token_single_use() {
        let store = new_login_csrf_store();
        let token = generate_login_csrf(&store);
        consume_login_csrf(&store, &token);
        // Second attempt with the same token must fail.
        assert!(!consume_login_csrf(&store, &token));
    }

    #[test]
    fn login_csrf_unknown_token_rejected() {
        let store = new_login_csrf_store();
        assert!(!consume_login_csrf(&store, "bogus-token"));
    }

    // ── csrf_eq ────────────────────────────────────────────────────────────

    #[test]
    fn csrf_eq_matching_tokens() {
        assert!(csrf_eq("abc123", "abc123"));
    }

    #[test]
    fn csrf_eq_different_tokens() {
        assert!(!csrf_eq("abc123", "xyz789"));
    }

    #[test]
    fn csrf_eq_different_lengths() {
        assert!(!csrf_eq("short", "longer_token"));
    }

    // ── rate limiter ───────────────────────────────────────────────────────

    #[test]
    fn rate_limit_allows_within_budget() {
        let limiter = new_login_rate_limiter();
        for _ in 0..5 {
            assert!(check_and_record_login_attempt(
                &limiter,
                "10.0.0.1",
                5,
                RATE_LIMIT_WINDOW
            ));
        }
    }

    #[test]
    fn rate_limit_blocks_on_sixth_attempt() {
        let limiter = new_login_rate_limiter();
        for _ in 0..5 {
            check_and_record_login_attempt(&limiter, "10.0.0.1", 5, RATE_LIMIT_WINDOW);
        }
        assert!(!check_and_record_login_attempt(
            &limiter,
            "10.0.0.1",
            5,
            RATE_LIMIT_WINDOW
        ));
    }

    #[test]
    fn rate_limit_different_ips_independent() {
        let limiter = new_login_rate_limiter();
        for _ in 0..5 {
            check_and_record_login_attempt(&limiter, "10.0.0.1", 5, RATE_LIMIT_WINDOW);
        }
        // A different IP is not blocked.
        assert!(check_and_record_login_attempt(
            &limiter,
            "10.0.0.2",
            5,
            RATE_LIMIT_WINDOW
        ));
    }

    #[test]
    fn rate_limit_clears_after_window() {
        let limiter = new_login_rate_limiter();
        // Use a zero-duration window so all previous entries are immediately expired.
        for _ in 0..5 {
            check_and_record_login_attempt(&limiter, "10.0.0.1", 5, Duration::from_secs(0));
        }
        // With zero window, all old entries expire; the next attempt is allowed.
        assert!(check_and_record_login_attempt(
            &limiter,
            "10.0.0.1",
            5,
            Duration::from_secs(0)
        ));
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
        let ttl = Duration::from_secs(86400);
        let c = make_session_cookie("mytoken", false, ttl);
        assert!(c.contains("awg_session=mytoken"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Lax"));
        assert!(c.contains("Max-Age=86400"));
    }

    #[test]
    fn make_session_cookie_secure_flag() {
        let ttl = Duration::from_secs(3600);
        let c = make_session_cookie("tok", true, ttl);
        assert!(c.contains("Secure"));
        let c_no = make_session_cookie("tok", false, ttl);
        assert!(!c_no.contains("Secure"));
    }

    #[test]
    fn make_session_cookie_uses_ttl() {
        let c = make_session_cookie("tok", false, Duration::from_secs(7200));
        assert!(c.contains("Max-Age=7200"));
    }

    #[test]
    fn clear_session_cookie_has_max_age_zero() {
        let c = clear_session_cookie();
        assert!(c.contains("Max-Age=0"));
        assert!(c.contains("awg_session=;"));
    }
}
