//! Direct client creation without the external install script.
//!
//! Implements client creation using individual AWG commands and file
//! operations, mirroring the logic from `nonInteractiveAddClient()` in
//! `amneziawg-install.sh` but executed natively in Rust.
//!
//! ## Privilege model
//!
//! The web service runs as a non-root user (`awg-web`).  Privileged
//! operations are delegated through a root-owned helper that validates every
//! subcommand and argument before executing fixed absolute binaries:
//!
//! | Operation | Command |
//! |-----------|---------|
//! | Read safe params | `…-privileged read-params` |
//! | Read sanitized server state | `…-privileged read-server-state <iface>` |
//! | Append peer to server config | `…-privileged append-peer <iface> <name>` |
//! | Remove managed peer block | `…-privileged remove-client[-if-key] …` |
//! | Reconcile live interface | `…-privileged reconcile-interface <iface>` |
//!
//! Key generation (`awg genkey`, `awg pubkey`, `awg genpsk`) does **not**
//! require root privileges.
//!
//! The clients directory (`config_dir`) must be writable by the service user
//! so that client config files can be created directly.

use std::collections::HashSet;
use std::net::Ipv6Addr;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use thiserror::Error;
#[cfg(unix)]
use tracing::{debug, info};

use crate::admin::script_bridge;
use crate::awg;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CreateClientError {
    #[error("invalid client name: {0}")]
    InvalidName(String),

    #[error("client '{0}' already exists")]
    DuplicateName(String),

    #[error("no free IP address available (max 253 clients)")]
    NoFreeIp,

    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    #[error("IP address already in use: {0}")]
    IpInUse(String),

    #[error("failed to read server parameters: {0}")]
    ParamsRead(String),

    #[error("failed to load data from database: {0}")]
    DbRead(String),

    #[error("failed to generate keys: {0}")]
    KeyGen(String),

    #[error("failed to write config file: {0}")]
    FileWrite(String),

    #[error("failed to parse config: {0}")]
    ConfigParse(String),

    #[error("AWG command failed: {0}")]
    Awg(#[from] crate::awg::AwgError),

    #[error("another add/remove operation is already in progress")]
    LockBusy,

    #[error("internal error during client creation: {0}")]
    Internal(String),
}

/// Optional IP address overrides for client creation.
///
/// When both fields are `None`, the first available IP pair is allocated
/// automatically (existing behaviour).  When set, each field contains the
/// **full** client IP address (e.g. `"10.66.66.100"` or
/// `"fd42:42:42::ff"`), which is validated against the server subnet.
#[derive(Debug, Clone, Default)]
pub struct IpOverride {
    /// Full IPv4 address for the client (e.g. `"10.66.66.100"`).
    pub ipv4_address: Option<String>,
    /// Full IPv6 address for the client (e.g. `"fd42:42:42::ff"`).
    pub ipv6_address: Option<String>,
}

/// Suggested IP addresses for a new client.
#[derive(Debug, Clone)]
pub struct SuggestedIps {
    /// The next available full IPv4 address (e.g. `"10.66.66.3"`).
    pub ipv4: String,
    /// The next available full IPv6 address (e.g. `"fd42:42:42::3"`), if the
    /// server interface has IPv6 enabled.
    pub ipv6: Option<String>,
}

#[derive(Debug, Error)]
pub enum RemoveClientError {
    #[error("invalid client name: {0}")]
    InvalidName(String),

    #[error("client '{0}' not found in server config")]
    ClientNotFound(String),

    #[error("client '{0}' does not match the expected peer identity")]
    IdentityMismatch(String),

    #[error("failed to read server parameters: {0}")]
    ParamsRead(String),

    #[error("failed to load data from database: {0}")]
    DbRead(String),

    #[error("invalid client config directory: {0}")]
    InvalidConfigDir(String),

    #[error("failed to write config file: {0}")]
    FileWrite(String),

    #[error("AWG command failed: {0}")]
    Awg(#[from] crate::awg::AwgError),

    #[error("another add/remove operation is already in progress")]
    LockBusy,

    #[error("internal error during client removal: {0}")]
    Internal(String),
}

/// Return a short, sanitized error category for use in audit event detail.
///
/// This is stored in `events.detail` which is exposed via `/api/events`,
/// so it must not contain raw stderr, OS errors, or filesystem paths.
pub fn sanitized_create_error_category(error: &CreateClientError) -> &'static str {
    match error {
        CreateClientError::InvalidName(_) => "invalid_name",
        CreateClientError::DuplicateName(_) => "duplicate_name",
        CreateClientError::NoFreeIp => "no_free_ip",
        CreateClientError::InvalidIp(_) => "invalid_ip",
        CreateClientError::IpInUse(_) => "ip_in_use",
        CreateClientError::ParamsRead(_) => "params_read_failed",
        CreateClientError::DbRead(_) => "db_read_failed",
        CreateClientError::KeyGen(_) => "key_generation_failed",
        CreateClientError::FileWrite(_) => "file_write_failed",
        CreateClientError::ConfigParse(_) => "config_parse_failed",
        CreateClientError::Awg(_) => "awg_command_failed",
        CreateClientError::LockBusy => "lock_busy",
        CreateClientError::Internal(_) => "internal_error",
    }
}

#[cfg(unix)]
pub(crate) fn acquire_lifecycle_lock(lock_dir: &Path) -> Result<std::fs::File, std::io::Error> {
    // Lock the already-existing persistent state directory itself. Keeping
    // lifecycle serialization on this descriptor avoids creating or mutating
    // a lock pathname and remains available when the client directory is gone.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(lock_dir)?;

    use std::os::unix::io::AsRawFd;
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(f)
}

#[cfg(not(unix))]
pub(crate) fn acquire_lifecycle_lock(_lock_path: &Path) -> Result<std::fs::File, std::io::Error> {
    Err(std::io::Error::other(
        "file locking for add/remove lifecycle is supported only on unix targets",
    ))
}

pub fn sanitized_remove_error_category(error: &RemoveClientError) -> &'static str {
    match error {
        RemoveClientError::InvalidName(_) => "invalid_name",
        RemoveClientError::ClientNotFound(_) => "client_not_found",
        RemoveClientError::IdentityMismatch(_) => "identity_mismatch",
        RemoveClientError::ParamsRead(_) => "params_read_failed",
        RemoveClientError::DbRead(_) => "db_read_failed",
        RemoveClientError::InvalidConfigDir(_) => "invalid_config_dir",
        RemoveClientError::FileWrite(_) => "file_write_failed",
        RemoveClientError::Awg(_) => "awg_command_failed",
        RemoveClientError::LockBusy => "lock_busy",
        RemoveClientError::Internal(_) => "internal_error",
    }
}

impl From<script_bridge::ScriptError> for CreateClientError {
    fn from(e: script_bridge::ScriptError) -> Self {
        match e {
            script_bridge::ScriptError::InvalidName(msg) => CreateClientError::InvalidName(msg),
            other => CreateClientError::Internal(other.to_string()),
        }
    }
}

impl From<script_bridge::ScriptError> for RemoveClientError {
    fn from(e: script_bridge::ScriptError) -> Self {
        match e {
            script_bridge::ScriptError::InvalidName(msg) => RemoveClientError::InvalidName(msg),
            other => RemoveClientError::Internal(other.to_string()),
        }
    }
}

// ── Server parameters ───────────────────────────────────────────────────────

/// Server parameters parsed from the params file.
///
/// The params file (`/etc/amnezia/amneziawg/params`) is a shell-sourceable
/// KEY='VALUE' file written by the install script.  It contains all the
/// settings needed to generate new client configs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwgProtocolVersion {
    V2,
    V3,
    V31,
}

#[derive(Debug, Clone)]
pub struct ServerParams {
    pub server_pub_ip: String,
    pub server_awg_nic: String,
    pub server_awg_ipv4: String,
    pub server_awg_ipv6: String,
    pub server_port: String,
    pub server_pub_key: String,
    pub client_dns_1: String,
    pub client_dns_2: String,
    pub allowed_ips: String,
    pub jc: String,
    pub jmin: String,
    pub jmax: String,
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub s4: String,
    pub h1: String,
    pub h2: String,
    pub h3: String,
    pub h4: String,
    pub protocol_version: AwgProtocolVersion,
    pub header_protection_key: String,
    pub content_padding_addition: String,
    pub rekey_after_time: String,
    pub rekey_timeout: String,
    pub reject_after_time: String,
    pub keepalive_timeout: String,
    pub random_trailers: String,
    pub disable_cookies: String,
}

fn validate_awg3_range(name: &str, value: &str) -> Result<(), CreateClientError> {
    if value.is_empty() {
        return Ok(());
    }
    let (low, high) = match value.split_once('-') {
        Some((low, high)) if !high.contains('-') => (low, high),
        Some(_) => {
            return Err(CreateClientError::ParamsRead(format!(
                "{name} must be an integer or inclusive range"
            )))
        }
        None => (value, value),
    };
    let parse_bound = |bound: &str| -> Result<u16, CreateClientError> {
        if bound.is_empty() || bound.len() > 5 || !bound.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CreateClientError::ParamsRead(format!(
                "{name} must contain uint16 values"
            )));
        }
        bound.parse::<u16>().map_err(|_| {
            CreateClientError::ParamsRead(format!("{name} must contain uint16 values"))
        })
    };
    let low = parse_bound(low)?;
    let high = parse_bound(high)?;
    if low > high {
        return Err(CreateClientError::ParamsRead(format!(
            "{name} range must be ordered"
        )));
    }
    Ok(())
}

fn validate_awg3_params(params: &ServerParams) -> Result<(), CreateClientError> {
    let key = params.header_protection_key.as_bytes();
    if key.len() != 44
        || key[43] != b'='
        || !matches!(
            key[42],
            b'A' | b'E'
                | b'I'
                | b'M'
                | b'Q'
                | b'U'
                | b'Y'
                | b'c'
                | b'g'
                | b'k'
                | b'o'
                | b's'
                | b'w'
                | b'0'
                | b'4'
                | b'8'
        )
        || !key[..43]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
    {
        return Err(CreateClientError::ParamsRead(
            "invalid AWG 3.0 HeaderProtectionKey".to_string(),
        ));
    }
    for (name, value) in [
        ("SERVER_AWG_S1", &params.s1),
        ("SERVER_AWG_S2", &params.s2),
        ("SERVER_AWG_S3", &params.s3),
        ("SERVER_AWG_S4", &params.s4),
    ] {
        let padding = value
            .parse::<u16>()
            .map_err(|_| CreateClientError::ParamsRead(format!("{name} must be a uint16 value")))?;
        if padding < 12 {
            return Err(CreateClientError::ParamsRead(format!(
                "{name} must be at least 12 for AWG 3.0"
            )));
        }
    }
    for (name, value) in [
        ("ContentPaddingAddition", &params.content_padding_addition),
        ("RekeyAfterTime", &params.rekey_after_time),
        ("RekeyTimeout", &params.rekey_timeout),
        ("RejectAfterTime", &params.reject_after_time),
        ("KeepaliveTimeout", &params.keepalive_timeout),
    ] {
        validate_awg3_range(name, value)?;
    }
    Ok(())
}

fn normalize_awg_on_off(name: &str, value: &str) -> Result<String, CreateClientError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok("on".to_string()),
        "off" | "false" | "no" | "0" => Ok("off".to_string()),
        _ => Err(CreateClientError::ParamsRead(format!(
            "{name} must be on or off"
        ))),
    }
}

fn validate_awg31_params(params: &ServerParams) -> Result<(String, String), CreateClientError> {
    validate_awg3_params(params)?;
    Ok((
        normalize_awg_on_off("RandomTrailers", &params.random_trailers)?,
        normalize_awg_on_off("DisableCookies", &params.disable_cookies)?,
    ))
}

/// AWG 3.0 params must not retain 3.1-only keys. The installer treats that as
/// inconsistent protocol state and repairs it; generating clients from it would
/// disagree with CLI fail-closed checks.
fn reject_dormant_awg31_params(params: &ServerParams) -> Result<(), CreateClientError> {
    if params.random_trailers.is_empty() && params.disable_cookies.is_empty() {
        return Ok(());
    }
    Err(CreateClientError::ParamsRead(
        "AWG 3.0 params must not contain AWG_RANDOM_TRAILERS or AWG_DISABLE_COOKIES".to_string(),
    ))
}

/// Parse params file content (KEY='VALUE' format) into [`ServerParams`].
///
/// The format is produced by `serializeParams()` in the install script,
/// which uses `safeQuoteParam()` to single-quote each value.  Embedded
/// single quotes are escaped as `'"'"'` (end-quote, double-quoted literal
/// quote, start-quote).
pub fn parse_params(content: &str) -> Result<ServerParams, CreateClientError> {
    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            // Remove surrounding single or double quotes and decode
            // safeQuoteParam() encoding for embedded single quotes.
            let was_single_quoted =
                value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'');
            let is_double_quoted =
                value.len() >= 2 && value.starts_with('"') && value.ends_with('"');
            let unquoted = if was_single_quoted || is_double_quoted {
                &value[1..value.len() - 1]
            } else {
                value
            };
            // Decode safeQuoteParam() encoding: embedded single quotes are
            // serialized as '"'"' (end-quote, literal quote via double-quoting,
            // start-quote).  After stripping the outer quotes above, the
            // remaining pattern is '"'"' which we collapse back to a single '.
            let final_value = if was_single_quoted {
                unquoted.replace("'\"'\"'", "'")
            } else {
                unquoted.to_string()
            };
            map.insert(key.to_string(), final_value);
        }
    }

    let get = |key: &str| -> Result<String, CreateClientError> {
        map.get(key)
            .cloned()
            .ok_or_else(|| CreateClientError::ParamsRead(format!("missing key: {key}")))
    };

    let get_opt = |key: &str| -> String { map.get(key).cloned().unwrap_or_default() };

    let protocol_version = match get_opt("AWG_PROTOCOL_VERSION").as_str() {
        "" | "2" | "2.0" => AwgProtocolVersion::V2,
        "3" | "3.0" => AwgProtocolVersion::V3,
        "3.1" => AwgProtocolVersion::V31,
        value => {
            return Err(CreateClientError::ParamsRead(format!(
                "unsupported AWG protocol version: {value}"
            )))
        }
    };

    let mut params = ServerParams {
        server_pub_ip: get("SERVER_PUB_IP")?,
        server_awg_nic: get("SERVER_AWG_NIC")?,
        server_awg_ipv4: get("SERVER_AWG_IPV4")?,
        server_awg_ipv6: get("SERVER_AWG_IPV6")?,
        server_port: get("SERVER_PORT")?,
        server_pub_key: get("SERVER_PUB_KEY")?,
        client_dns_1: get("CLIENT_DNS_1")?,
        client_dns_2: get_opt("CLIENT_DNS_2"),
        allowed_ips: get("ALLOWED_IPS")?,
        jc: get("SERVER_AWG_JC")?,
        jmin: get("SERVER_AWG_JMIN")?,
        jmax: get("SERVER_AWG_JMAX")?,
        s1: get("SERVER_AWG_S1")?,
        s2: get("SERVER_AWG_S2")?,
        s3: get("SERVER_AWG_S3")?,
        s4: get("SERVER_AWG_S4")?,
        h1: get("SERVER_AWG_H1")?,
        h2: get("SERVER_AWG_H2")?,
        h3: get("SERVER_AWG_H3")?,
        h4: get("SERVER_AWG_H4")?,
        protocol_version,
        header_protection_key: get_opt("AWG_HEADER_PROTECTION_KEY"),
        content_padding_addition: get_opt("AWG_CONTENT_PADDING_ADDITION"),
        rekey_after_time: get_opt("AWG_REKEY_AFTER_TIME"),
        rekey_timeout: get_opt("AWG_REKEY_TIMEOUT"),
        reject_after_time: get_opt("AWG_REJECT_AFTER_TIME"),
        keepalive_timeout: get_opt("AWG_KEEPALIVE_TIMEOUT"),
        random_trailers: get_opt("AWG_RANDOM_TRAILERS"),
        disable_cookies: get_opt("AWG_DISABLE_COOKIES"),
    };

    // Validate server_awg_nic: must be a safe interface name (alphanumeric,
    // underscore, dot, hyphen; no path separators or leading dashes; < 16 chars).
    // This prevents path-traversal when constructing filesystem paths and
    // option-injection when the name is passed as a command argument.
    validate_interface_name(&params.server_awg_nic)?;
    match params.protocol_version {
        AwgProtocolVersion::V2 => {}
        AwgProtocolVersion::V3 => {
            validate_awg3_params(&params)?;
            reject_dormant_awg31_params(&params)?;
        }
        AwgProtocolVersion::V31 => {
            let (random_trailers, disable_cookies) = validate_awg31_params(&params)?;
            params.random_trailers = random_trailers;
            params.disable_cookies = disable_cookies;
        }
    }

    Ok(params)
}

/// Validate that a string is a safe AWG interface name.
///
/// Rules (matching the install script's validation):
/// - Non-empty
/// - Only `[a-zA-Z0-9_.-]`
/// - Must not start with `-` (prevents option injection)
/// - Less than 16 characters (Linux IFNAMSIZ)
/// - Must not contain `..` (prevents path traversal)
fn validate_interface_name(name: &str) -> Result<(), CreateClientError> {
    if name.is_empty() {
        return Err(CreateClientError::ConfigParse(
            "SERVER_AWG_NIC must not be empty".into(),
        ));
    }
    if name.len() >= 16 {
        return Err(CreateClientError::ConfigParse(
            "SERVER_AWG_NIC must be less than 16 characters".into(),
        ));
    }
    if name.starts_with('-') {
        return Err(CreateClientError::ConfigParse(
            "SERVER_AWG_NIC must not start with '-'".into(),
        ));
    }
    if name.contains("..") {
        return Err(CreateClientError::ConfigParse(
            "SERVER_AWG_NIC must not contain '..'".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(CreateClientError::ConfigParse(
            "SERVER_AWG_NIC contains invalid characters (only alphanumeric, _, ., - allowed)"
                .into(),
        ));
    }
    Ok(())
}

// ── IPv6 helpers ────────────────────────────────────────────────────────────

/// Normalize an IPv6 address to its fully expanded form (8 groups of 4 hex
/// digits), matching the behaviour of `normalizeIPv6()` in the install script.
///
/// This form is used in the server config's AllowedIPs to ensure consistent
/// comparison across different representations.
fn normalize_ipv6(addr_str: &str) -> Result<String, CreateClientError> {
    let addr: Ipv6Addr = addr_str
        .parse()
        .map_err(|e| CreateClientError::ConfigParse(format!("invalid IPv6 '{addr_str}': {e}")))?;
    let segs = addr.segments();
    Ok(format!(
        "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
        segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7]
    ))
}

/// Compress an IPv6 address to its canonical RFC 5952 form, matching the
/// behaviour of `compressIPv6()` in the install script.
///
/// This form is used in client configs for human-readable display.
fn compress_ipv6(addr_str: &str) -> Result<String, CreateClientError> {
    let addr: Ipv6Addr = addr_str
        .parse()
        .map_err(|e| CreateClientError::ConfigParse(format!("invalid IPv6 '{addr_str}': {e}")))?;
    Ok(addr.to_string())
}

/// Extract the first 4 groups (the /64 prefix) from a normalized IPv6 address.
fn ipv6_prefix(normalized: &str) -> &str {
    // A normalized IPv6 always has the form xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx.
    // The first 4 groups end at the 4th colon.
    let mut colons = 0;
    for (i, c) in normalized.char_indices() {
        if c == ':' {
            colons += 1;
            if colons == 4 {
                return &normalized[..i];
            }
        }
    }
    normalized
}

// ── IP allocation ───────────────────────────────────────────────────────────

/// Extract the base IPv4 prefix (first 3 octets) from a server IPv4 address.
///
/// E.g., `"10.66.66.1"` → `"10.66.66"`.
fn ipv4_base(server_ipv4: &str) -> &str {
    match server_ipv4.rfind('.') {
        Some(pos) => &server_ipv4[..pos],
        None => server_ipv4,
    }
}

/// Find all host numbers (.2–.254) currently used in the server config
/// based on IPv4 AllowedIPs entries.
///
/// Scans AllowedIPs in `[Peer]` sections for IPv4 addresses matching the
/// given base prefix (e.g., `10.66.66.X/32`).  Returns a set of used host
/// numbers.
///
/// IPv6 collision detection is handled separately via
/// `find_existing_ipv6_normalized()` to avoid a mismatch between the hex
/// representation of IPv6 host numbers and the decimal DOT_IP used by the
/// allocator.
fn find_used_ipv4_dots(server_config: &str, base_ipv4: &str) -> HashSet<u16> {
    let mut used = HashSet::new();
    let prefix_with_dot = format!("{base_ipv4}.");

    for line in server_config.lines() {
        let trimmed = line.trim();
        if let Some(val) = parse_kv(trimmed, "AllowedIPs") {
            for cidr in val.split(',') {
                let cidr = cidr.trim();
                // Check IPv4: "10.66.66.X/32"
                if let Some(rest) = cidr.strip_prefix(&prefix_with_dot) {
                    if let Some(host) = rest.strip_suffix("/32") {
                        if let Ok(dot) = host.parse::<u16>() {
                            used.insert(dot);
                        }
                    }
                }
            }
        }
    }

    used
}

/// Collect all normalized `/128` IPv6 addresses present in the server config.
///
/// Used for candidate-based collision detection: for each DOT_IP candidate,
/// the caller generates `normalize_ipv6("{base_ipv6}::{dot_ip}")` and checks
/// membership in this set.  This mirrors the installer's
/// `nonInteractiveAddClient()` logic and avoids the hex/decimal mismatch
/// that would occur if we tried to extract DOT_IP directly from the IPv6
/// numeric value.
fn find_existing_ipv6_normalized(server_config: &str) -> HashSet<String> {
    let mut set = HashSet::new();

    for line in server_config.lines() {
        let trimmed = line.trim();
        if let Some(val) = parse_kv(trimmed, "AllowedIPs") {
            for cidr in val.split(',') {
                let cidr = cidr.trim();
                if let Some(ip) = cidr.strip_suffix("/128") {
                    if let Ok(normalized) = normalize_ipv6(ip) {
                        set.insert(normalized);
                    }
                }
            }
        }
    }

    set
}

/// Find the first available host number in the .2–.254 range.
///
/// A DOT_IP is available when it is not in the `used_ipv4` set (from IPv4
/// AllowedIPs) AND the candidate IPv6 address `{base_ipv6}::{dot}` does
/// not appear in `existing_ipv6s` (the set of normalized /128 addresses
/// already in the config).
fn find_available_dot(
    used_ipv4: &HashSet<u16>,
    existing_ipv6s: &HashSet<String>,
    base_ipv6: &str,
) -> Option<u16> {
    (2..=254).find(|&dot| {
        if used_ipv4.contains(&dot) {
            return false;
        }
        // Generate the candidate IPv6 and check for collisions.
        if let Ok(candidate) = normalize_ipv6(&format!("{base_ipv6}::{dot}")) {
            if existing_ipv6s.contains(&candidate) {
                return false;
            }
        }
        true
    })
}

/// Simple INI key-value parser for a single line.
fn parse_kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut parts = line.splitn(2, '=');
    let k = parts.next()?.trim();
    if k.eq_ignore_ascii_case(key) {
        Some(parts.next()?.trim())
    } else {
        None
    }
}

fn server_interface_has_ipv6_address(server_config: &str) -> bool {
    let mut in_interface = false;

    for line in server_config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_interface = trimmed.eq_ignore_ascii_case("[Interface]");
            continue;
        }
        if !in_interface {
            continue;
        }
        if let Some(value) = parse_kv(trimmed, "Address") {
            let uncommented = value.split(['#', ';']).next().unwrap_or_default().trim();
            if uncommented.split(',').map(str::trim).any(|cidr| {
                cidr.split('/')
                    .next()
                    .is_some_and(|addr| addr.contains(':'))
            }) {
                return true;
            }
        }
    }

    false
}

fn find_available_ipv4_dot(used_ipv4: &HashSet<u16>) -> Option<u16> {
    (2..=254).find(|dot| !used_ipv4.contains(dot))
}

/// Resolve the IPv4/optional IPv6 addresses for a new client.
///
/// If `ip_override` contains user-specified full addresses, they are
/// validated (subnet membership + range + collision) against the server
/// config.  Otherwise the first available address pair is allocated
/// automatically.
///
/// Returns `(client_ipv4, client_ipv6_full)`, e.g.
/// `("10.66.66.5", Some("fd42:0042:0042:0000::5"))`.
fn resolve_client_ips(
    server_config: &str,
    base_ipv4: &str,
    base_ipv6: Option<&str>,
    ip_override: &IpOverride,
) -> Result<(String, Option<String>), CreateClientError> {
    let used_ipv4 = find_used_ipv4_dots(server_config, base_ipv4);

    let ipv4_host = match &ip_override.ipv4_address {
        Some(addr) => Some(parse_ipv4_address(addr, base_ipv4)?),
        None => None,
    };

    let Some(base_ipv6) = base_ipv6 else {
        if let Some(addr) = &ip_override.ipv6_address {
            return Err(CreateClientError::InvalidIp(format!(
                "IPv6 is disabled on the server, cannot assign {addr}"
            )));
        }
        let host = match ipv4_host {
            Some(host) => {
                if used_ipv4.contains(&host) {
                    return Err(CreateClientError::IpInUse(format!("{base_ipv4}.{host}")));
                }
                host
            }
            None => find_available_ipv4_dot(&used_ipv4).ok_or(CreateClientError::NoFreeIp)?,
        };
        return Ok((format!("{base_ipv4}.{host}"), None));
    };

    let existing_ipv6s = find_existing_ipv6_normalized(server_config);
    let ipv6_full = match &ip_override.ipv6_address {
        Some(addr) => Some(parse_ipv6_address(addr, base_ipv6)?),
        None => None,
    };

    match (ipv4_host, &ipv6_full) {
        // No overrides – auto-allocate.
        (None, None) => {
            let dot_ip = find_available_dot(&used_ipv4, &existing_ipv6s, base_ipv6)
                .ok_or(CreateClientError::NoFreeIp)?;
            Ok((
                format!("{base_ipv4}.{dot_ip}"),
                Some(format!("{base_ipv6}::{dot_ip}")),
            ))
        }
        // Both overrides specified.
        (Some(host), Some(ipv6)) => {
            if used_ipv4.contains(&host) {
                return Err(CreateClientError::IpInUse(format!("{base_ipv4}.{host}")));
            }
            let ipv6_norm = normalize_ipv6(ipv6)?;
            if existing_ipv6s.contains(&ipv6_norm) {
                return Err(CreateClientError::IpInUse(ipv6.to_string()));
            }
            Ok((format!("{base_ipv4}.{host}"), Some(ipv6.to_string())))
        }
        // Only IPv4 override – derive IPv6 host segment by reusing the same host value as a string.
        (Some(host), None) => {
            if used_ipv4.contains(&host) {
                return Err(CreateClientError::IpInUse(format!("{base_ipv4}.{host}")));
            }
            let ipv6_derived = format!("{base_ipv6}::{host}");
            let ipv6_norm = normalize_ipv6(&ipv6_derived)?;
            if existing_ipv6s.contains(&ipv6_norm) {
                return Err(CreateClientError::IpInUse(ipv6_derived));
            }
            Ok((format!("{base_ipv4}.{host}"), Some(ipv6_derived)))
        }
        // Only IPv6 override – auto-allocate IPv4 with collision check for the
        // user-specified IPv6.
        (None, Some(ipv6)) => {
            let ipv6_norm = normalize_ipv6(ipv6)?;
            if existing_ipv6s.contains(&ipv6_norm) {
                return Err(CreateClientError::IpInUse(ipv6.to_string()));
            }
            let dot_ip = find_available_ipv4_dot(&used_ipv4).ok_or(CreateClientError::NoFreeIp)?;
            Ok((format!("{base_ipv4}.{dot_ip}"), Some(ipv6.to_string())))
        }
    }
}

/// Compute the next available full IP addresses for a new client.
///
/// This is a non-blocking, read-only function used to pre-fill the
/// "Add user" form with suggested addresses.
///
/// Returns `Err` if the server params/config cannot be read, or if no
/// free IP addresses are available.
#[cfg(unix)]
pub fn suggest_next_ips() -> Result<SuggestedIps, CreateClientError> {
    let params_content = awg::read_params_via_sudo()
        .map_err(|e| CreateClientError::ParamsRead(format!("failed to read params file: {e}")))?;
    let params = parse_params(&params_content)?;

    let server_config = awg::read_server_state_via_sudo(&params.server_awg_nic)
        .map_err(|e| CreateClientError::ParamsRead(format!("failed to read server config: {e}")))?;

    let base_ipv4 = ipv4_base(&params.server_awg_ipv4);

    let used_ipv4 = find_used_ipv4_dots(&server_config, base_ipv4);
    let server_ipv6_normalized = if server_interface_has_ipv6_address(&server_config) {
        Some(normalize_ipv6(&params.server_awg_ipv6)?)
    } else {
        None
    };
    let base_ipv6 = server_ipv6_normalized.as_deref().map(ipv6_prefix);
    let dot_ip = if let Some(base_ipv6) = base_ipv6 {
        let existing_ipv6s = find_existing_ipv6_normalized(&server_config);
        find_available_dot(&used_ipv4, &existing_ipv6s, base_ipv6)
            .ok_or(CreateClientError::NoFreeIp)?
    } else {
        find_available_ipv4_dot(&used_ipv4).ok_or(CreateClientError::NoFreeIp)?
    };

    let ipv4 = format!("{base_ipv4}.{dot_ip}");
    let ipv6 = base_ipv6
        .map(|base_ipv6| compress_ipv6(&format!("{base_ipv6}::{dot_ip}")))
        .transpose()?;

    Ok(SuggestedIps { ipv4, ipv6 })
}

/// Non-Unix stub: IP suggestion requires reading AWG config files.
#[cfg(not(unix))]
pub fn suggest_next_ips() -> Result<SuggestedIps, CreateClientError> {
    Err(CreateClientError::Internal(
        "IP suggestion is only supported on Unix targets".to_string(),
    ))
}

/// Length of a normalised IPv6 /64 prefix in "xxxx:xxxx:xxxx:xxxx" form.
const IPV6_NORMALIZED_PREFIX_LEN: usize = 19;

/// Parse and validate a full IPv4 address, returning the host (last octet).
///
/// The address must belong to the expected subnet (`base_ipv4`, e.g.
/// `"10.66.66"`) and have a host number in the 2–254 range.
fn parse_ipv4_address(addr: &str, base_ipv4: &str) -> Result<u16, CreateClientError> {
    let prefix_with_dot = format!("{base_ipv4}.");
    let host_str = addr.strip_prefix(&prefix_with_dot).ok_or_else(|| {
        CreateClientError::InvalidIp(format!(
            "IPv4 address must be in the {base_ipv4}.x subnet, got: {addr}"
        ))
    })?;
    let host: u16 = host_str.parse().map_err(|_| {
        CreateClientError::InvalidIp(format!("IPv4 host part must be a number, got: {host_str}"))
    })?;
    validate_ipv4_host(host)?;
    Ok(host)
}

/// Parse and validate a full IPv6 address, returning a canonical form under the given /64 prefix.
///
/// The address must belong to the expected /64 prefix (`base_ipv6`, e.g.
/// `"fd42:0042:0042:0000"`) and have a non-empty host part.  The input
/// may use compressed notation (e.g. `"fd42:42:42::ff"`), but the returned
/// value is reconstructed as `<base_ipv6>::<host>` to match the server config format.
fn parse_ipv6_address(addr: &str, base_ipv6: &str) -> Result<String, CreateClientError> {
    // Parse to get the normalised full form, then check the prefix.
    let normalized = normalize_ipv6(addr)
        .map_err(|_| CreateClientError::InvalidIp(format!("invalid IPv6 address: {addr}")))?;
    let base_normalized = normalize_ipv6(&format!("{base_ipv6}::0")).map_err(|_| {
        CreateClientError::ConfigParse(format!("cannot normalise base IPv6: {base_ipv6}"))
    })?;
    // Compare /64 prefixes (first 4 groups of normalised form).
    if normalized[..IPV6_NORMALIZED_PREFIX_LEN] != base_normalized[..IPV6_NORMALIZED_PREFIX_LEN] {
        return Err(CreateClientError::InvalidIp(format!(
            "IPv6 address must be in the {base_ipv6}:: subnet, got: {addr}"
        )));
    }
    // Check that the host part is not all zeros (that's the network address).
    let host_part = &normalized[IPV6_NORMALIZED_PREFIX_LEN..];
    if host_part.chars().all(|c| c == ':' || c == '0') {
        return Err(CreateClientError::InvalidIp(
            "IPv6 host part must be non-zero".to_string(),
        ));
    }
    // Return the user-supplied form after normalisation for consistent storage.
    // Use the expanded notation that matches the server config format.
    Ok(format!(
        "{base_ipv6}::{}",
        extract_ipv6_host_segment(addr, base_ipv6)?
    ))
}

/// Extract the host segment from a full IPv6 address relative to a /64 prefix.
///
/// For example, given `"fd42:42:42::ff"` and prefix `"fd42:0042:0042:0000"`,
/// returns `"ff"`.
fn extract_ipv6_host_segment(addr: &str, base_ipv6: &str) -> Result<String, CreateClientError> {
    let normalized = normalize_ipv6(addr)?;
    let base_norm = normalize_ipv6(&format!("{base_ipv6}::0"))?;

    // The normalised form is xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx.
    // The last 4 groups (after group 4) form the interface identifier.
    let segments: Vec<&str> = normalized.split(':').collect();
    let base_segments: Vec<&str> = base_norm.split(':').collect();

    // Verify prefix match (groups 0–3).
    if segments[..4] != base_segments[..4] {
        return Err(CreateClientError::InvalidIp(format!(
            "IPv6 address does not match server subnet: {addr}"
        )));
    }

    // Build the host portion, stripping leading-zero groups.
    // Re-assemble groups 4–7, skipping all-zero leading groups.
    let host_groups = &segments[4..];
    let mut found_nonzero = false;
    let mut result_parts = Vec::new();
    for &g in host_groups {
        let trimmed = g.trim_start_matches('0');
        let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
        if trimmed != "0" || found_nonzero {
            found_nonzero = true;
            result_parts.push(trimmed);
        }
    }
    if result_parts.is_empty() {
        result_parts.push("0");
    }
    Ok(result_parts.join(":"))
}

/// Validate the IPv4 host number (last octet).
fn validate_ipv4_host(host: u16) -> Result<(), CreateClientError> {
    if !(2..=254).contains(&host) {
        return Err(CreateClientError::InvalidIp(
            "IPv4 host number must be between 2 and 254".to_string(),
        ));
    }
    Ok(())
}

// ── Config generation ───────────────────────────────────────────────────────

/// Build the endpoint string, bracketing IPv6 addresses.
fn build_endpoint(server_pub_ip: &str, server_port: &str) -> String {
    if server_pub_ip.contains(':') {
        // IPv6 – ensure brackets
        let ip = server_pub_ip.trim_start_matches('[').trim_end_matches(']');
        format!("[{ip}]:{server_port}")
    } else {
        format!("{server_pub_ip}:{server_port}")
    }
}

/// Build the DNS line for the client config.
fn build_dns(dns1: &str, dns2: &str) -> String {
    if dns2.is_empty() {
        dns1.to_string()
    } else {
        format!("{dns1},{dns2}")
    }
}

fn format_client_allowed_ips(allowed_ips: &str) -> String {
    allowed_ips
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

fn prepare_client_allowed_ips(
    allowed_ips: &str,
    ipv6_enabled: bool,
) -> Result<String, CreateClientError> {
    let filtered = allowed_ips
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .filter(|entry| ipv6_enabled || !entry.contains(':'))
        .collect::<Vec<_>>()
        .join(",");
    let formatted = format_client_allowed_ips(&filtered);

    if formatted.is_empty() {
        return Err(CreateClientError::ConfigParse(
            "ALLOWED_IPS has no usable routes for this client's address family".to_string(),
        ));
    }

    Ok(formatted)
}

/// Build the client configuration file content.
fn build_client_config(
    params: &ServerParams,
    client_priv_key: &str,
    client_ipv4: &str,
    client_ipv6_display: Option<&str>,
    client_psk: &str,
    dns: &str,
    endpoint: &str,
) -> Result<String, CreateClientError> {
    let address = match client_ipv6_display {
        Some(ipv6) => format!("{client_ipv4}/32,{ipv6}/128"),
        None => format!("{client_ipv4}/32"),
    };
    let allowed_ips =
        prepare_client_allowed_ips(&params.allowed_ips, client_ipv6_display.is_some())?;
    let protocol_fields = match params.protocol_version {
        AwgProtocolVersion::V2 => String::new(),
        AwgProtocolVersion::V3 | AwgProtocolVersion::V31 => {
            let extra_31 = if params.protocol_version == AwgProtocolVersion::V31 {
                let (random_trailers, disable_cookies) = validate_awg31_params(params)?;
                vec![
                    format!("RandomTrailers = {random_trailers}"),
                    format!("DisableCookies = {disable_cookies}"),
                ]
            } else {
                validate_awg3_params(params)?;
                Vec::new()
            };
            let mut fields = [
                Some(format!(
                    "HeaderProtectionKey = {}",
                    params.header_protection_key
                )),
                (!params.content_padding_addition.is_empty()).then(|| {
                    format!(
                        "ContentPaddingAddition = {}",
                        params.content_padding_addition
                    )
                }),
                (!params.rekey_after_time.is_empty())
                    .then(|| format!("RekeyAfterTime = {}", params.rekey_after_time)),
                (!params.rekey_timeout.is_empty())
                    .then(|| format!("RekeyTimeout = {}", params.rekey_timeout)),
                (!params.reject_after_time.is_empty())
                    .then(|| format!("RejectAfterTime = {}", params.reject_after_time)),
                (!params.keepalive_timeout.is_empty())
                    .then(|| format!("KeepaliveTimeout = {}", params.keepalive_timeout)),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            fields.extend(extra_31);
            fields.join("\n")
        }
    };

    Ok(format!(
        "\
[Interface]
PrivateKey = {client_priv_key}
Address = {address}
DNS = {dns}
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
S3 = {s3}
S4 = {s4}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}
{protocol_fields}

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {client_psk}
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}",
        jc = params.jc,
        jmin = params.jmin,
        jmax = params.jmax,
        s1 = params.s1,
        s2 = params.s2,
        s3 = params.s3,
        s4 = params.s4,
        h1 = params.h1,
        h2 = params.h2,
        h3 = params.h3,
        h4 = params.h4,
        server_pub_key = params.server_pub_key,
        allowed_ips = allowed_ips,
    ))
}

fn remove_client_block(server_config: &str, name: &str) -> Option<String> {
    let marker = format!("### Client {name}");
    let lines: Vec<&str> = server_config.lines().collect();
    let marker_index = lines.iter().position(|line| line.trim() == marker)?;

    let mut start = marker_index;
    while start > 0 && lines[start - 1].trim().is_empty() {
        start -= 1;
    }

    let mut end = marker_index + 1;
    while end < lines.len() && !lines[end].trim_start().starts_with("### Client ") {
        end += 1;
    }

    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i >= start && i < end {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    Some(out)
}

fn server_config_contains_public_key(server_config: &str, expected_public_key: &str) -> bool {
    server_config.lines().any(|line| {
        line.split_once('=')
            .filter(|(key, _)| key.trim().eq_ignore_ascii_case("PublicKey"))
            .is_some_and(|(_, value)| value.trim() == expected_public_key)
    })
}

fn live_interfaces_contain_public_key(
    interfaces: &[awg::AwgInterface],
    expected_public_key: &str,
) -> bool {
    interfaces.iter().any(|interface| {
        interface
            .peers
            .iter()
            .any(|peer| peer.public_key.0 == expected_public_key)
    })
}

// ── Client creation ─────────────────────────────────────────────────────────

/// Result of a successful client creation.
#[derive(Debug)]
pub struct CreateClientResult {
    /// Absolute path to the generated client config file.
    pub config_path: String,
    /// Stem of the generated client config filename.
    pub config_name: String,
    /// The client name that was created.
    pub client_name: String,
    /// Human-readable peer name derived from the generated config filename.
    pub friendly_name: String,
    /// Public key generated for the new peer.
    pub public_key: String,
    /// Comma-separated client CIDRs as written to the server config.
    pub allowed_ips: String,
    /// Whether the on-disk configs were written but the live interface sync failed.
    pub sync_required: bool,
}

#[cfg(unix)]
fn prepare_client_config_dir(config_dir: &Path) -> Result<(), CreateClientError> {
    // Reject a symlinked AWG_CONFIG_DIR to prevent redirection attacks.
    match std::fs::symlink_metadata(config_dir) {
        Ok(sym_meta) => {
            if sym_meta.file_type().is_symlink() {
                return Err(CreateClientError::FileWrite(format!(
                    "AWG_CONFIG_DIR {} is a symbolic link; refusing to use it for client configs",
                    config_dir.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(CreateClientError::FileWrite(format!(
                "cannot lstat {}: {e}",
                config_dir.display()
            )));
        }
    }

    std::fs::create_dir_all(config_dir).map_err(|e| {
        CreateClientError::FileWrite(format!("mkdir {}: {e}", config_dir.display()))
    })?;

    let cfg_meta = std::fs::symlink_metadata(config_dir).map_err(|e| {
        CreateClientError::FileWrite(format!("cannot lstat {}: {e}", config_dir.display()))
    })?;
    let cfg_ftype = cfg_meta.file_type();
    if cfg_ftype.is_symlink() {
        return Err(CreateClientError::FileWrite(format!(
            "AWG_CONFIG_DIR {} is a symbolic link; refusing to use it for client configs",
            config_dir.display()
        )));
    }
    if !cfg_ftype.is_dir() {
        return Err(CreateClientError::FileWrite(format!(
            "config path exists but is not a directory: {}",
            config_dir.display()
        )));
    }

    if let Err(e) = std::fs::set_permissions(config_dir, std::fs::Permissions::from_mode(0o700)) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            let meta = std::fs::metadata(config_dir).map_err(|me| {
                CreateClientError::FileWrite(format!("cannot stat {}: {me}", config_dir.display()))
            })?;
            let uid = unsafe { libc::getuid() };
            let dir_uid = std::os::unix::fs::MetadataExt::uid(&meta);
            let dir_mode = meta.permissions().mode();
            const UNSAFE_WRITE_BITS: u32 = 0o022;
            if dir_uid != uid {
                return Err(CreateClientError::FileWrite(format!(
                    "AWG_CONFIG_DIR {} is owned by uid {dir_uid}, not the service user (uid {uid}); \
                     run: sudo chown awg-web:awg-web {}",
                    config_dir.display(), config_dir.display(),
                )));
            }
            if dir_mode & UNSAFE_WRITE_BITS != 0 {
                return Err(CreateClientError::FileWrite(format!(
                    "AWG_CONFIG_DIR {} has unsafe permissions {dir_mode:#o} (group/world writable); \
                     run: sudo chmod 0700 {}",
                    config_dir.display(), config_dir.display(),
                )));
            }
            tracing::warn!(
                dir = %config_dir.display(),
                error = %e,
                "chmod on config dir failed; verified directory is owned by service user \
                 and not group/world-writable, proceeding",
            );
        } else {
            return Err(CreateClientError::FileWrite(format!(
                "chmod {}: {e}",
                config_dir.display()
            )));
        }
    }
    Ok(())
}

/// Prepare the client directory and acquire the lifecycle lock before native
/// creation. Callers may retain the returned file across database persistence.
#[cfg(unix)]
fn acquire_creation_lock(lock_dir: &Path) -> Result<std::fs::File, CreateClientError> {
    acquire_lifecycle_lock(lock_dir).map_err(|err| match err.raw_os_error() {
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
            CreateClientError::LockBusy
        }
        _ => CreateClientError::FileWrite(format!(
            "failed to acquire lock for client creation: {err}"
        )),
    })
}

#[cfg(unix)]
fn acquire_standalone_creation_lock(config_dir: &Path) -> Result<std::fs::File, CreateClientError> {
    prepare_client_config_dir(config_dir)?;
    acquire_creation_lock(config_dir)
}

#[cfg(unix)]
pub(crate) fn acquire_creation_lifecycle_lock(
    config_dir: &Path,
    lifecycle_lock_dir: &Path,
) -> Result<std::fs::File, CreateClientError> {
    let lock = acquire_creation_lock(lifecycle_lock_dir)?;
    prepare_client_config_dir(config_dir)?;
    Ok(lock)
}

#[cfg(not(unix))]
pub(crate) fn acquire_creation_lifecycle_lock(
    _config_dir: &Path,
    _lifecycle_lock_dir: &Path,
) -> Result<std::fs::File, CreateClientError> {
    Err(CreateClientError::Internal(
        "create_client is supported only on unix targets".to_string(),
    ))
}

/// Create a new AmneziaWG client directly, without the external install script.
///
/// This function is **blocking** (it calls AWG commands and performs file I/O)
/// and should be run inside `tokio::task::spawn_blocking`.
///
/// # Steps
///
/// 1. Validate the client name.
/// 2. Read server parameters from the params file.
/// 3. Read the server config to check for duplicate names and find used IPs.
/// 4. Find the first available IP address pair (IPv4 + IPv6), or use the
///    user-specified overrides from `ip_override`.
/// 5. Generate cryptographic keys (private, public, pre-shared).
/// 6. Write the client config file to `config_dir`.
/// 7. Append the peer block to the server config.
/// 8. Sync the running AWG interface.
#[cfg(unix)]
pub fn create_client(
    config_dir: &Path,
    name: &str,
    disabled_keys: &HashSet<String>,
    ip_override: &IpOverride,
) -> Result<CreateClientResult, CreateClientError> {
    script_bridge::validate_client_name(name)?;
    // Standalone callers use the client directory itself as their lock inode,
    // so restore the documented create-on-first-use behavior before opening it.
    // The web path uses acquire_creation_lifecycle_lock with an independent,
    // already-existing persistent state directory and therefore locks first.
    let _lock_file = acquire_standalone_creation_lock(config_dir)?;
    create_client_with_lifecycle_lock(config_dir, name, disabled_keys, ip_override)
}

/// Native creation variant for a caller that already holds the lifecycle lock.
#[cfg(unix)]
pub(crate) fn create_client_with_lifecycle_lock(
    config_dir: &Path,
    name: &str,
    disabled_keys: &HashSet<String>,
    ip_override: &IpOverride,
) -> Result<CreateClientResult, CreateClientError> {
    // Step 1: Validate the client name.
    script_bridge::validate_client_name(name)?;

    // Step 3: Read server parameters.
    let params_content = awg::read_params_via_sudo()
        .map_err(|e| CreateClientError::ParamsRead(format!("failed to read params file: {e}")))?;
    let params = parse_params(&params_content)?;

    debug!(nic = %params.server_awg_nic, "server params loaded");

    // Step 4: Read server config to check for duplicates and find used IPs.
    let server_config = awg::read_server_state_via_sudo(&params.server_awg_nic)
        .map_err(|e| CreateClientError::ParamsRead(format!("failed to read server config: {e}")))?;

    // Check for duplicate name (look for ### Client <name> marker).
    let marker = format!("### Client {name}");
    for line in server_config.lines() {
        if line.trim() == marker {
            return Err(CreateClientError::DuplicateName(name.to_string()));
        }
    }

    // Also check if a client config file already exists.
    let config_name = format!("{}-client-{name}", params.server_awg_nic);
    let client_conf_path = config_dir.join(format!("{config_name}.conf"));
    if client_conf_path.exists() {
        return Err(CreateClientError::DuplicateName(name.to_string()));
    }

    // Step 5: Find an available IP address pair (or use overrides).
    let base_ipv4 = ipv4_base(&params.server_awg_ipv4);
    let ipv6_enabled = server_interface_has_ipv6_address(&server_config);
    let server_ipv6_normalized = if ipv6_enabled {
        Some(normalize_ipv6(&params.server_awg_ipv6)?)
    } else {
        None
    };
    let base_ipv6 = server_ipv6_normalized.as_deref().map(ipv6_prefix);

    let (client_ipv4, client_ipv6_full) =
        resolve_client_ips(&server_config, base_ipv4, base_ipv6, ip_override)?;
    let client_ipv6_normalized = match &client_ipv6_full {
        Some(ipv6) => {
            let normalized = normalize_ipv6(ipv6)?;
            if Some(normalized.as_str()) == server_ipv6_normalized.as_deref() {
                return Err(CreateClientError::IpInUse(ipv6.to_string()));
            }
            Some(normalized)
        }
        None => None,
    };
    let client_ipv6_display = client_ipv6_full.as_deref().map(compress_ipv6).transpose()?;

    let user_specified = ip_override.ipv4_address.is_some() || ip_override.ipv6_address.is_some();
    debug!(
        ipv4 = %client_ipv4,
        ipv6 = ?client_ipv6_display,
        user_specified = user_specified,
        "resolved client IP addresses"
    );

    // Step 6: Generate cryptographic keys.
    let priv_key = awg::genkey().map_err(|e| CreateClientError::KeyGen(e.to_string()))?;
    let pub_key = awg::pubkey(&priv_key).map_err(|e| CreateClientError::KeyGen(e.to_string()))?;
    let psk = awg::genpsk().map_err(|e| CreateClientError::KeyGen(e.to_string()))?;

    debug!("client keys generated");

    // Step 7: Build and write the client config file.
    let endpoint = build_endpoint(&params.server_pub_ip, &params.server_port);
    let dns = build_dns(&params.client_dns_1, &params.client_dns_2);
    let client_config = build_client_config(
        &params,
        &priv_key,
        &client_ipv4,
        client_ipv6_display.as_deref(),
        &psk,
        &dns,
        &endpoint,
    )?;

    // Write with restrictive permissions (mode 600).
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&client_conf_path)
            .map_err(|e| {
                CreateClientError::FileWrite(format!("open {}: {e}", client_conf_path.display()))
            })?;
        std::io::Write::write_all(&mut f, client_config.as_bytes()).map_err(|e| {
            CreateClientError::FileWrite(format!("write {}: {e}", client_conf_path.display()))
        })?;
        std::io::Write::flush(&mut f).map_err(|e| {
            CreateClientError::FileWrite(format!("flush {}: {e}", client_conf_path.display()))
        })?;
    }

    info!(path = %client_conf_path.display(), "client config written");

    // Step 8: Append the peer block to the server config.
    let allowed_ips = match client_ipv6_normalized.as_deref() {
        Some(ipv6) => format!("{client_ipv4}/32,{ipv6}/128"),
        None => format!("{client_ipv4}/32"),
    };
    if let Err(e) =
        awg::append_peer_via_sudo(&params.server_awg_nic, name, &pub_key, &psk, &allowed_ips)
    {
        // Clean up the client config on failure.
        let _ = std::fs::remove_file(&client_conf_path);
        return Err(CreateClientError::FileWrite(format!(
            "append to server config: {e}"
        )));
    }

    info!(client = name, "peer block appended to server config");

    // Step 9: Sync the running AWG interface.
    // Keep the lock held through strip+syncconf to prevent a concurrent
    // remove/add from modifying on-disk config between the two steps.
    let sync_required = match awg::sync_interface(&params.server_awg_nic, disabled_keys) {
        Ok(()) => false,
        Err(e) => {
            // The peer is in the config file but not yet on the running interface.
            // Return the creation metadata so the caller can durably persist the
            // peer and its comment even though a later interface sync is required.
            tracing::warn!(
                error = %e,
                "interface sync failed after adding peer – peer will become active after an explicit AWG sync or restart"
            );
            true
        }
    };

    Ok(CreateClientResult {
        config_path: client_conf_path.to_string_lossy().to_string(),
        config_name,
        client_name: name.to_string(),
        friendly_name: name.to_string(),
        public_key: pub_key,
        allowed_ips,
        sync_required,
    })
}

#[cfg(not(unix))]
pub fn create_client(
    _config_dir: &Path,
    _name: &str,
    _disabled_keys: &HashSet<String>,
    _ip_override: &IpOverride,
) -> Result<CreateClientResult, CreateClientError> {
    Err(CreateClientError::Internal(
        "create_client is supported only on unix targets".to_string(),
    ))
}

#[cfg(unix)]
pub fn remove_client(
    config_dir: &Path,
    name: &str,
    disabled_keys: &HashSet<String>,
) -> Result<(), RemoveClientError> {
    remove_client_inner(config_dir, name, None, disabled_keys, false)
}

#[cfg(not(unix))]
pub(crate) fn create_client_with_lifecycle_lock(
    config_dir: &Path,
    name: &str,
    disabled_keys: &HashSet<String>,
    ip_override: &IpOverride,
) -> Result<CreateClientResult, CreateClientError> {
    create_client(config_dir, name, disabled_keys, ip_override)
}

/// Remove or resume removal of a database-linked managed client.
///
/// The named server block must contain `expected_public_key`. If the block is
/// already absent, cleanup can resume only when that key is also absent from
/// the server config. This makes partial retries safe without treating a
/// renamed or mismatched live peer as successfully removed.
#[cfg(unix)]
pub fn remove_client_resumable(
    config_dir: &Path,
    name: &str,
    expected_public_key: &str,
    disabled_keys: &HashSet<String>,
) -> Result<(), RemoveClientError> {
    remove_client_inner(
        config_dir,
        name,
        Some(expected_public_key),
        disabled_keys,
        true,
    )
}

fn remove_client_inner(
    config_dir: &Path,
    name: &str,
    expected_public_key: Option<&str>,
    disabled_keys: &HashSet<String>,
    allow_missing_server_block: bool,
) -> Result<(), RemoveClientError> {
    script_bridge::validate_client_name(name)?;

    // Validate the unprivileged client-config directory before changing the
    // root-owned server config.  Otherwise a redirected directory could make
    // the request fail only after the peer block had already been removed.
    match std::fs::symlink_metadata(config_dir) {
        Ok(sym_meta) => {
            let file_type = sym_meta.file_type();
            if file_type.is_symlink() {
                return Err(RemoveClientError::InvalidConfigDir(format!(
                    "AWG_CONFIG_DIR {} is a symbolic link; refusing to remove client configs from it",
                    config_dir.display()
                )));
            }
            if !file_type.is_dir() {
                return Err(RemoveClientError::InvalidConfigDir(format!(
                    "AWG_CONFIG_DIR path exists but is not a directory: {}",
                    config_dir.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // If the directory does not exist, there are no config files to remove.
        }
        Err(e) => {
            return Err(RemoveClientError::FileWrite(format!(
                "cannot lstat {}: {e}",
                config_dir.display()
            )));
        }
    }

    let params_content = awg::read_params_via_sudo()
        .map_err(|e| RemoveClientError::ParamsRead(format!("failed to read params file: {e}")))?;
    let params =
        parse_params(&params_content).map_err(|e| RemoveClientError::ParamsRead(e.to_string()))?;

    let server_config = awg::read_server_state_via_sudo(&params.server_awg_nic)
        .map_err(|e| RemoveClientError::ParamsRead(format!("failed to read server config: {e}")))?;

    if remove_client_block(&server_config, name).is_some() {
        match expected_public_key {
            Some(public_key) => {
                // The helper revalidates this identity while holding the
                // server-config lock, closing the read/delete TOCTOU window.
                awg::remove_client_if_key_via_sudo(&params.server_awg_nic, name, public_key)
            }
            None => awg::remove_client_via_sudo(&params.server_awg_nic, name),
        }
        .map_err(|e| RemoveClientError::FileWrite(format!("remove from server config: {e}")))?;
    } else if !allow_missing_server_block {
        return Err(RemoveClientError::ClientNotFound(name.to_string()));
    } else if expected_public_key
        .is_some_and(|public_key| server_config_contains_public_key(&server_config, public_key))
    {
        return Err(RemoveClientError::IdentityMismatch(name.to_string()));
    }

    // Always sync after the persistent server config has been removed (or was
    // already absent). This is the step that makes retries repair a previous
    // remove-then-sync failure and evicts the peer from the live interface.
    awg::sync_interface(&params.server_awg_nic, disabled_keys)?;

    // A missing named block alone cannot prove that removal is complete: the
    // database may be linked to a different interface or an out-of-band edit
    // may have renamed the marker. Fail closed until the expected peer key is
    // absent from every live interface. Client files and database state remain
    // available for a later retry or manual diagnosis when this check fails.
    if let Some(expected_public_key) = expected_public_key {
        let interfaces = awg::show_all_dump()?;
        if live_interfaces_contain_public_key(&interfaces, expected_public_key) {
            return Err(RemoveClientError::IdentityMismatch(name.to_string()));
        }
    }

    let mut config_cleanup_error = None;
    match std::fs::read_dir(config_dir) {
        Ok(entries) => {
            let suffix = format!("-client-{name}.conf");
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let file_name = entry.file_name();
                        if file_name
                            .to_str()
                            .is_some_and(|file_name| file_name.ends_with(&suffix))
                        {
                            if let Err(e) = std::fs::remove_file(entry.path()) {
                                tracing::warn!(
                                    path = %entry.path().display(),
                                    error = %e,
                                    "failed to remove client config from config_dir"
                                );
                                config_cleanup_error.get_or_insert_with(|| {
                                    RemoveClientError::FileWrite(format!(
                                        "remove client config {}: {e}",
                                        entry.path().display()
                                    ))
                                });
                            }
                        }
                    }
                    Err(e) => {
                        config_cleanup_error.get_or_insert_with(|| {
                            RemoveClientError::FileWrite(format!(
                                "read entry in {}: {e}",
                                config_dir.display()
                            ))
                        });
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            config_cleanup_error = Some(RemoveClientError::FileWrite(format!(
                "read client config directory {}: {e}",
                config_dir.display()
            )));
        }
    }

    if let Some(error) = config_cleanup_error {
        return Err(error);
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn remove_client(
    _config_dir: &Path,
    _name: &str,
    _disabled_keys: &HashSet<String>,
) -> Result<(), RemoveClientError> {
    Err(RemoveClientError::Internal(
        "remove_client is supported only on unix targets".to_string(),
    ))
}

#[cfg(not(unix))]
pub fn remove_client_resumable(
    _config_dir: &Path,
    _name: &str,
    _expected_public_key: &str,
    _disabled_keys: &HashSet<String>,
) -> Result<(), RemoveClientError> {
    Err(RemoveClientError::Internal(
        "remove_client is supported only on unix targets".to_string(),
    ))
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_uses_state_directory_descriptor_and_rejects_symlinks() {
        let parent = tempfile::tempdir().expect("temp parent");
        let state_dir = parent.path().join("state");
        std::fs::create_dir(&state_dir).expect("create state dir");

        let first = acquire_lifecycle_lock(&state_dir).expect("first lifecycle lock");
        let second = acquire_lifecycle_lock(&state_dir).expect_err("lock must contend");
        assert!(matches!(
            second.raw_os_error(),
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
        ));
        assert!(std::fs::read_dir(&state_dir)
            .expect("read state dir")
            .next()
            .is_none());
        drop(first);

        let symlink = parent.path().join("state-link");
        std::os::unix::fs::symlink(&state_dir, &symlink).expect("create symlink");
        assert!(acquire_lifecycle_lock(&symlink).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_does_not_require_client_directory() {
        let state_dir = tempfile::tempdir().expect("state tempdir");
        let missing_config_dir = state_dir.path().join("missing-clients");

        let _lock = acquire_lifecycle_lock(state_dir.path()).expect("lifecycle lock");

        assert!(!missing_config_dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn standalone_creation_lock_prepares_missing_client_directory() {
        let parent = tempfile::tempdir().expect("temp parent");
        let missing_config_dir = parent.path().join("missing-clients");

        let _lock = acquire_standalone_creation_lock(&missing_config_dir)
            .expect("standalone creation lock");

        assert!(missing_config_dir.is_dir());
    }

    #[test]
    fn remove_client_block_removes_only_target_client_section() {
        let server = "[Interface]\nPrivateKey = S\n\n### Client alice\n[Peer]\nPublicKey = A\nAllowedIPs = 10.66.66.2/32,fd42::2/128\n\n### Client bob\n[Peer]\nPublicKey = B\nAllowedIPs = 10.66.66.3/32,fd42::3/128\n";
        let updated = remove_client_block(server, "alice").expect("alice block should exist");

        assert!(!updated.contains("### Client alice"));
        assert!(updated.contains("### Client bob"));
        assert!(updated.contains("[Interface]"));
    }

    #[test]
    fn remove_client_block_returns_none_for_unknown_client() {
        let server = "[Interface]\nPrivateKey = S\n\n### Client alice\n[Peer]\nPublicKey = A\n";
        assert!(remove_client_block(server, "missing").is_none());
    }

    #[test]
    fn resumable_removal_identity_helpers_detect_keys_across_config_and_live_state() {
        let server = "[Interface]\nPrivateKey = S\n\n### Client renamed\n[Peer]\nPublicKey = ALICE_KEY=\n\n### Client bob\n[Peer]\nPublicKey = BOB_KEY=\n";

        assert!(server_config_contains_public_key(server, "ALICE_KEY="));
        assert!(!server_config_contains_public_key(server, "MISSING_KEY="));

        let interfaces = vec![awg::AwgInterface {
            name: "awg0".to_string(),
            public_key: crate::domain::PublicKey("SERVER_KEY=".to_string()),
            listen_port: Some(51820),
            peers: vec![awg::AwgPeer {
                public_key: crate::domain::PublicKey("ALICE_KEY=".to_string()),
                endpoint: None,
                allowed_ips: vec!["10.66.66.2/32".to_string()],
                last_handshake: None,
                rx_bytes: 0,
                tx_bytes: 0,
            }],
        }];
        assert!(live_interfaces_contain_public_key(
            &interfaces,
            "ALICE_KEY="
        ));
        assert!(!live_interfaces_contain_public_key(
            &interfaces,
            "MISSING_KEY="
        ));
    }

    #[cfg(unix)]
    #[test]
    fn remove_client_rejects_non_directory_config_path() {
        let config_file = tempfile::NamedTempFile::new().expect("temporary config file");

        let error = remove_client(config_file.path(), "alice", &HashSet::new())
            .expect_err("a non-directory config path must be rejected");

        assert!(matches!(
            &error,
            RemoveClientError::InvalidConfigDir(message)
                if message.contains("AWG_CONFIG_DIR path exists but is not a directory")
        ));
        assert_eq!(
            sanitized_remove_error_category(&error),
            "invalid_config_dir"
        );
    }

    // ── parse_params ────────────────────────────────────────────────────

    #[test]
    fn parse_params_basic() {
        let content = "\
SERVER_PUB_IP='203.0.113.42'
SERVER_PUB_NIC='eth0'
SERVER_AWG_NIC='awg0'
SERVER_AWG_IPV4='10.66.66.1'
SERVER_AWG_IPV6='fd42:42:42::1'
SERVER_PORT='51820'
SERVER_PRIV_KEY='PRIVATE_KEY='
SERVER_PUB_KEY='PUBLIC_KEY='
CLIENT_DNS_1='1.1.1.1'
CLIENT_DNS_2='1.0.0.1'
ALLOWED_IPS='0.0.0.0/0, ::/0'
SERVER_AWG_JC='8'
SERVER_AWG_JMIN='50'
SERVER_AWG_JMAX='1000'
SERVER_AWG_S1='107'
SERVER_AWG_S2='105'
SERVER_AWG_S3='62'
SERVER_AWG_S4='95'
SERVER_AWG_H1='321941292'
SERVER_AWG_H2='774489227'
SERVER_AWG_H3='1084244185'
SERVER_AWG_H4='1837068650'
";
        let params = parse_params(content).unwrap();
        assert_eq!(params.server_pub_ip, "203.0.113.42");
        assert_eq!(params.server_awg_nic, "awg0");
        assert_eq!(params.server_awg_ipv4, "10.66.66.1");
        assert_eq!(params.server_awg_ipv6, "fd42:42:42::1");
        assert_eq!(params.server_port, "51820");
        assert_eq!(params.server_pub_key, "PUBLIC_KEY=");
        assert_eq!(params.client_dns_1, "1.1.1.1");
        assert_eq!(params.client_dns_2, "1.0.0.1");
        assert_eq!(params.allowed_ips, "0.0.0.0/0, ::/0");
        assert_eq!(params.jc, "8");
        assert_eq!(params.h4, "1837068650");
        assert_eq!(params.protocol_version, AwgProtocolVersion::V2);
    }

    #[test]
    fn parse_params_accepts_and_validates_awg3_state() {
        let legacy = "\
SERVER_PUB_IP='203.0.113.42'
SERVER_AWG_NIC='awg0'
SERVER_AWG_IPV4='10.66.66.1'
SERVER_AWG_IPV6='fd42:42:42::1'
SERVER_PORT='51820'
SERVER_PUB_KEY='PUBLIC_KEY='
CLIENT_DNS_1='1.1.1.1'
ALLOWED_IPS='0.0.0.0/0'
SERVER_AWG_JC='8'
SERVER_AWG_JMIN='50'
SERVER_AWG_JMAX='1000'
SERVER_AWG_S1='107'
SERVER_AWG_S2='105'
SERVER_AWG_S3='62'
SERVER_AWG_S4='95'
SERVER_AWG_H1='1'
SERVER_AWG_H2='2'
SERVER_AWG_H3='3'
SERVER_AWG_H4='4'
";
        let content = format!(
            "{legacy}AWG_PROTOCOL_VERSION='3'\n\
             AWG_HEADER_PROTECTION_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='\n\
             AWG_CONTENT_PADDING_ADDITION='10-100'\n\
             AWG_REKEY_AFTER_TIME='100-120'\n\
             AWG_REKEY_TIMEOUT='3-7'\n\
             AWG_REJECT_AFTER_TIME='150-180'\n\
             AWG_KEEPALIVE_TIMEOUT='5-15'\n"
        );
        let params = parse_params(&content).unwrap();
        assert_eq!(params.protocol_version, AwgProtocolVersion::V3);
        assert_eq!(params.rekey_timeout, "3-7");

        let awg31 = format!("{content}AWG_RANDOM_TRAILERS='on'\nAWG_DISABLE_COOKIES='off'\n")
            .replace("AWG_PROTOCOL_VERSION='3'", "AWG_PROTOCOL_VERSION='3.1'");
        let params31 = parse_params(&awg31).unwrap();
        assert_eq!(params31.protocol_version, AwgProtocolVersion::V31);
        assert_eq!(params31.random_trailers, "on");
        assert_eq!(params31.disable_cookies, "off");
        assert!(parse_params(
            &content.replace("AWG_PROTOCOL_VERSION='3'", "AWG_PROTOCOL_VERSION='3.1'")
        )
        .is_err());
        assert!(
            parse_params(&format!(
                "{content}AWG_RANDOM_TRAILERS='on'\nAWG_DISABLE_COOKIES='off'\n"
            ))
            .is_err(),
            "AWG 3.0 params must reject dormant AWG 3.1 keys"
        );
        assert!(
            parse_params(&format!(
                "{content}AWG_RANDOM_TRAILERS=''\nAWG_DISABLE_COOKIES=''\n"
            ))
            .is_ok(),
            "empty serialized AWG 3.1 keys remain valid in AWG 3.0"
        );
    }

    #[test]
    fn parse_params_normalizes_awg31_boolean_aliases() {
        let base = "\
SERVER_PUB_IP='203.0.113.42'
SERVER_AWG_NIC='awg0'
SERVER_AWG_IPV4='10.66.66.1'
SERVER_AWG_IPV6='fd42:42:42::1'
SERVER_PORT='51820'
SERVER_PUB_KEY='PUBLIC_KEY='
CLIENT_DNS_1='1.1.1.1'
ALLOWED_IPS='0.0.0.0/0'
SERVER_AWG_JC='8'
SERVER_AWG_JMIN='50'
SERVER_AWG_JMAX='1000'
SERVER_AWG_S1='107'
SERVER_AWG_S2='105'
SERVER_AWG_S3='62'
SERVER_AWG_S4='95'
SERVER_AWG_H1='1'
SERVER_AWG_H2='2'
SERVER_AWG_H3='3'
SERVER_AWG_H4='4'
AWG_PROTOCOL_VERSION='3.1'
AWG_HEADER_PROTECTION_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
AWG_CONTENT_PADDING_ADDITION='10-100'
AWG_REKEY_AFTER_TIME='100-120'
AWG_REKEY_TIMEOUT='3-7'
AWG_REJECT_AFTER_TIME='150-180'
AWG_KEEPALIVE_TIMEOUT='5-15'
";
        let parse = |trailers: &str, cookies: &str| {
            parse_params(&format!(
                "{base}AWG_RANDOM_TRAILERS='{trailers}'\nAWG_DISABLE_COOKIES='{cookies}'\n"
            ))
        };
        let params = parse("1", "true").unwrap();
        assert_eq!(params.random_trailers, "on");
        assert_eq!(params.disable_cookies, "on");
        let params = parse("yes", "TRUE").unwrap();
        assert_eq!(params.random_trailers, "on");
        assert_eq!(params.disable_cookies, "on");
        let params = parse(" ON ", " False ").unwrap();
        assert_eq!(params.random_trailers, "on");
        assert_eq!(params.disable_cookies, "off");
        let params = parse(" 1 ", " 0 ").unwrap();
        assert_eq!(params.random_trailers, "on");
        assert_eq!(params.disable_cookies, "off");
        let params = parse("YES", "no").unwrap();
        assert_eq!(params.random_trailers, "on");
        assert_eq!(params.disable_cookies, "off");
        assert!(
            parse("maybe", "off").is_err(),
            "invalid RandomTrailers aliases remain rejected"
        );
        assert!(
            parse("on", "perhaps").is_err(),
            "invalid DisableCookies aliases remain rejected"
        );
        assert!(
            parse("on extra", "off").is_err(),
            "internal whitespace in RandomTrailers remains rejected"
        );
    }

    #[test]
    fn parse_params_rejects_incomplete_awg3_but_ignores_awg3_fields_in_v2() {
        let base = "\
SERVER_PUB_IP='203.0.113.42'
SERVER_AWG_NIC='awg0'
SERVER_AWG_IPV4='10.66.66.1'
SERVER_AWG_IPV6='fd42:42:42::1'
SERVER_PORT='51820'
SERVER_PUB_KEY='PUBLIC_KEY='
CLIENT_DNS_1='1.1.1.1'
ALLOWED_IPS='0.0.0.0/0'
SERVER_AWG_JC='8'
SERVER_AWG_JMIN='50'
SERVER_AWG_JMAX='1000'
SERVER_AWG_S1='107'
SERVER_AWG_S2='105'
SERVER_AWG_S3='62'
SERVER_AWG_S4='95'
SERVER_AWG_H1='1'
SERVER_AWG_H2='2'
SERVER_AWG_H3='3'
SERVER_AWG_H4='4'
AWG_HEADER_PROTECTION_KEY='invalid'
";
        assert!(parse_params(&format!("{base}AWG_PROTOCOL_VERSION='3'\n")).is_err());
        assert!(parse_params(&format!("{base}AWG_PROTOCOL_VERSION='2'\n")).is_ok());
    }

    #[test]
    fn parse_params_missing_key_returns_error() {
        let content = "SERVER_PUB_IP='1.2.3.4'\n";
        assert!(parse_params(content).is_err());
    }

    #[test]
    fn parse_params_double_quotes() {
        let content = "\
SERVER_PUB_IP=\"1.2.3.4\"
SERVER_AWG_NIC=\"awg0\"
SERVER_AWG_IPV4=\"10.0.0.1\"
SERVER_AWG_IPV6=\"fd00::1\"
SERVER_PORT=\"51820\"
SERVER_PUB_KEY=\"KEY=\"
CLIENT_DNS_1=\"8.8.8.8\"
ALLOWED_IPS=\"0.0.0.0/0\"
SERVER_AWG_JC=\"1\"
SERVER_AWG_JMIN=\"2\"
SERVER_AWG_JMAX=\"3\"
SERVER_AWG_S1=\"4\"
SERVER_AWG_S2=\"5\"
SERVER_AWG_S3=\"6\"
SERVER_AWG_S4=\"7\"
SERVER_AWG_H1=\"8\"
SERVER_AWG_H2=\"9\"
SERVER_AWG_H3=\"10\"
SERVER_AWG_H4=\"11\"
";
        let params = parse_params(content).unwrap();
        assert_eq!(params.server_pub_ip, "1.2.3.4");
    }

    #[test]
    fn parse_params_no_quotes() {
        let content = "\
SERVER_PUB_IP=1.2.3.4
SERVER_AWG_NIC=awg0
SERVER_AWG_IPV4=10.0.0.1
SERVER_AWG_IPV6=fd00::1
SERVER_PORT=51820
SERVER_PUB_KEY=KEY=
CLIENT_DNS_1=8.8.8.8
ALLOWED_IPS=0.0.0.0/0
SERVER_AWG_JC=1
SERVER_AWG_JMIN=2
SERVER_AWG_JMAX=3
SERVER_AWG_S1=4
SERVER_AWG_S2=5
SERVER_AWG_S3=6
SERVER_AWG_S4=7
SERVER_AWG_H1=8
SERVER_AWG_H2=9
SERVER_AWG_H3=10
SERVER_AWG_H4=11
";
        let params = parse_params(content).unwrap();
        assert_eq!(params.server_pub_ip, "1.2.3.4");
    }

    #[test]
    fn parse_params_safe_quote_param_embedded_single_quote() {
        // safeQuoteParam("O'Reilly") produces: 'O'"'"'Reilly'
        // After the outer single quotes are stripped, the remainder is:
        // O'"'"'Reilly — which should decode back to O'Reilly.
        let content = "\
SERVER_PUB_IP='O'\"'\"'Reilly'
SERVER_AWG_NIC='awg0'
SERVER_AWG_IPV4='10.0.0.1'
SERVER_AWG_IPV6='fd00::1'
SERVER_PORT='51820'
SERVER_PUB_KEY='KEY='
CLIENT_DNS_1='8.8.8.8'
ALLOWED_IPS='0.0.0.0/0'
SERVER_AWG_JC='1'
SERVER_AWG_JMIN='2'
SERVER_AWG_JMAX='3'
SERVER_AWG_S1='4'
SERVER_AWG_S2='5'
SERVER_AWG_S3='6'
SERVER_AWG_S4='7'
SERVER_AWG_H1='8'
SERVER_AWG_H2='9'
SERVER_AWG_H3='10'
SERVER_AWG_H4='11'
";
        let params = parse_params(content).unwrap();
        assert_eq!(params.server_pub_ip, "O'Reilly");
    }

    // ── validate_interface_name ──────────────────────────────────────────

    #[test]
    fn validate_interface_name_valid() {
        assert!(validate_interface_name("awg0").is_ok());
        assert!(validate_interface_name("wg0").is_ok());
        assert!(validate_interface_name("eth0.1").is_ok());
        assert!(validate_interface_name("my_iface").is_ok());
    }

    #[test]
    fn validate_interface_name_rejects_empty() {
        assert!(validate_interface_name("").is_err());
    }

    #[test]
    fn validate_interface_name_rejects_leading_dash() {
        assert!(validate_interface_name("-awg0").is_err());
    }

    #[test]
    fn validate_interface_name_rejects_path_traversal() {
        assert!(validate_interface_name("../etc").is_err());
        assert!(validate_interface_name("awg0/..").is_err());
    }

    #[test]
    fn validate_interface_name_rejects_slashes() {
        assert!(validate_interface_name("awg0/conf").is_err());
    }

    #[test]
    fn validate_interface_name_rejects_too_long() {
        assert!(validate_interface_name("1234567890123456").is_err());
    }

    #[test]
    fn validate_interface_name_rejects_spaces() {
        assert!(validate_interface_name("awg 0").is_err());
    }

    #[test]
    fn parse_params_rejects_invalid_nic() {
        let content = "\
SERVER_PUB_IP='1.2.3.4'
SERVER_AWG_NIC='../etc'
SERVER_AWG_IPV4='10.0.0.1'
SERVER_AWG_IPV6='fd00::1'
SERVER_PORT='51820'
SERVER_PUB_KEY='KEY='
CLIENT_DNS_1='8.8.8.8'
ALLOWED_IPS='0.0.0.0/0'
SERVER_AWG_JC='1'
SERVER_AWG_JMIN='2'
SERVER_AWG_JMAX='3'
SERVER_AWG_S1='4'
SERVER_AWG_S2='5'
SERVER_AWG_S3='6'
SERVER_AWG_S4='7'
SERVER_AWG_H1='8'
SERVER_AWG_H2='9'
SERVER_AWG_H3='10'
SERVER_AWG_H4='11'
";
        assert!(parse_params(content).is_err());
    }

    #[test]
    fn parse_params_single_char_quote_no_panic() {
        // A malformed value consisting of just a single quote character
        // should not panic (it should be treated as a literal value).
        let content = "\
SERVER_PUB_IP='1.2.3.4'
SERVER_AWG_NIC='awg0'
SERVER_AWG_IPV4='10.0.0.1'
SERVER_AWG_IPV6='fd00::1'
SERVER_PORT='51820'
SERVER_PUB_KEY='
CLIENT_DNS_1='8.8.8.8'
ALLOWED_IPS='0.0.0.0/0'
SERVER_AWG_JC='1'
SERVER_AWG_JMIN='2'
SERVER_AWG_JMAX='3'
SERVER_AWG_S1='4'
SERVER_AWG_S2='5'
SERVER_AWG_S3='6'
SERVER_AWG_S4='7'
SERVER_AWG_H1='8'
SERVER_AWG_H2='9'
SERVER_AWG_H3='10'
SERVER_AWG_H4='11'
";
        // Should not panic — the single-char ' is treated as an unquoted value
        let result = parse_params(content);
        // Parsing may fail (missing required keys) but must not panic
        let _ = result;
    }

    // ── IPv6 helpers ────────────────────────────────────────────────────

    #[test]
    fn normalize_ipv6_compressed() {
        let result = normalize_ipv6("fd42:42:42::1").unwrap();
        assert_eq!(result, "fd42:0042:0042:0000:0000:0000:0000:0001");
    }

    #[test]
    fn normalize_ipv6_already_expanded() {
        let result = normalize_ipv6("fd42:0042:0042:0000:0000:0000:0000:0002").unwrap();
        assert_eq!(result, "fd42:0042:0042:0000:0000:0000:0000:0002");
    }

    #[test]
    fn compress_ipv6_expanded() {
        let result = compress_ipv6("fd42:0042:0042:0000:0000:0000:0000:0002").unwrap();
        assert_eq!(result, "fd42:42:42::2");
    }

    #[test]
    fn ipv6_prefix_extraction() {
        let normalized = "fd42:0042:0042:0000:0000:0000:0000:0001";
        assert_eq!(ipv6_prefix(normalized), "fd42:0042:0042:0000");
    }

    // ── IP allocation ───────────────────────────────────────────────────

    #[test]
    fn ipv4_base_extracts_prefix() {
        assert_eq!(ipv4_base("10.66.66.1"), "10.66.66");
        assert_eq!(ipv4_base("192.168.1.1"), "192.168.1");
    }

    #[test]
    fn find_used_ipv4_dots_parses_server_config() {
        let config = "\
[Interface]
PrivateKey = KEY=

### Client alice
[Peer]
PublicKey = ALICE_KEY=
PresharedKey = ALICE_PSK=
AllowedIPs = 10.66.66.2/32,fd42:0042:0042:0000:0000:0000:0000:0002/128

### Client bob
[Peer]
PublicKey = BOB_KEY=
PresharedKey = BOB_PSK=
AllowedIPs = 10.66.66.3/32,fd42:0042:0042:0000:0000:0000:0000:0003/128
";
        let used = find_used_ipv4_dots(config, "10.66.66");
        assert!(used.contains(&2));
        assert!(used.contains(&3));
        assert!(!used.contains(&4));
    }

    #[test]
    fn find_existing_ipv6_normalized_collects_normalized() {
        let config = "\
[Peer]
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128

[Peer]
AllowedIPs = 10.66.66.3/32,fd42:0042:0042:0000:0000:0000:0000:0003/128
";
        let ipv6s = find_existing_ipv6_normalized(config);
        // Both compressed and expanded forms should normalize to the same thing
        assert!(ipv6s.contains("fd42:0042:0042:0000:0000:0000:0000:0002"));
        assert!(ipv6s.contains("fd42:0042:0042:0000:0000:0000:0000:0003"));
        assert_eq!(ipv6s.len(), 2);
    }

    #[test]
    fn find_available_dot_returns_first_free() {
        let mut used = HashSet::new();
        used.insert(2);
        used.insert(3);
        let empty_ipv6s = HashSet::new();
        assert_eq!(
            find_available_dot(&used, &empty_ipv6s, "fd42:0042:0042:0000"),
            Some(4)
        );
    }

    #[test]
    fn find_available_dot_returns_2_when_empty() {
        let used = HashSet::new();
        let empty_ipv6s = HashSet::new();
        assert_eq!(
            find_available_dot(&used, &empty_ipv6s, "fd42:0042:0042:0000"),
            Some(2)
        );
    }

    #[test]
    fn find_available_dot_none_when_full() {
        let used: HashSet<u16> = (2..=254).collect();
        let empty_ipv6s = HashSet::new();
        assert_eq!(
            find_available_dot(&used, &empty_ipv6s, "fd42:0042:0042:0000"),
            None
        );
    }

    #[test]
    fn find_available_dot_ipv6_collision_blocks_candidate() {
        // DOT_IP 2 is free in IPv4, but its IPv6 form is already used
        let used_ipv4 = HashSet::new();
        let mut existing_ipv6s = HashSet::new();
        existing_ipv6s.insert("fd42:0042:0042:0000:0000:0000:0000:0002".to_string());
        assert_eq!(
            find_available_dot(&used_ipv4, &existing_ipv6s, "fd42:0042:0042:0000"),
            Some(3)
        );
    }

    #[test]
    fn server_interface_has_ipv6_address_detects_interface_only() {
        let enabled = "\
[Interface]
Address = 10.66.66.1/24,fd42:42:42::1/64

[Peer]
AllowedIPs = 10.66.66.2/32
";
        let disabled = "\
[Interface]
Address = 10.66.66.1/24

[Peer]
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128
";
        let commented_after_comma = "\
[Interface]
Address = 10.66.66.1/24, #fd42:42:42::1/64

[Peer]
AllowedIPs = 10.66.66.2/32
";

        assert!(server_interface_has_ipv6_address(enabled));
        assert!(!server_interface_has_ipv6_address(disabled));
        assert!(!server_interface_has_ipv6_address(commented_after_comma));
    }

    // ── Config generation ───────────────────────────────────────────────

    #[test]
    fn build_endpoint_ipv4() {
        assert_eq!(build_endpoint("1.2.3.4", "51820"), "1.2.3.4:51820");
    }

    #[test]
    fn build_endpoint_ipv6() {
        assert_eq!(
            build_endpoint("2001:db8::1", "51820"),
            "[2001:db8::1]:51820"
        );
    }

    #[test]
    fn build_endpoint_ipv6_already_bracketed() {
        assert_eq!(
            build_endpoint("[2001:db8::1]", "51820"),
            "[2001:db8::1]:51820"
        );
    }

    #[test]
    fn build_dns_single() {
        assert_eq!(build_dns("1.1.1.1", ""), "1.1.1.1");
    }

    #[test]
    fn build_dns_dual() {
        assert_eq!(build_dns("1.1.1.1", "1.0.0.1"), "1.1.1.1,1.0.0.1");
    }

    #[test]
    fn format_client_allowed_ips_adds_space_after_comma() {
        assert_eq!(
            format_client_allowed_ips("0.0.0.0/0,::/0"),
            "0.0.0.0/0, ::/0"
        );
    }

    #[test]
    fn format_client_allowed_ips_trims_and_drops_empty_entries() {
        assert_eq!(
            format_client_allowed_ips(" 0.0.0.0/0,, ::/0, "),
            "0.0.0.0/0, ::/0"
        );
        assert_eq!(format_client_allowed_ips(" , , "), "");
    }

    #[test]
    fn build_client_config_contains_all_fields() {
        let params = ServerParams {
            server_pub_ip: "1.2.3.4".into(),
            server_awg_nic: "awg0".into(),
            server_awg_ipv4: "10.66.66.1".into(),
            server_awg_ipv6: "fd42:42:42::1".into(),
            server_port: "51820".into(),
            server_pub_key: "SVR_PUB=".into(),
            client_dns_1: "1.1.1.1".into(),
            client_dns_2: "1.0.0.1".into(),
            allowed_ips: "0.0.0.0/0, ::/0".into(),
            jc: "8".into(),
            jmin: "50".into(),
            jmax: "1000".into(),
            s1: "107".into(),
            s2: "105".into(),
            s3: "62".into(),
            s4: "95".into(),
            h1: "321941292".into(),
            h2: "774489227".into(),
            h3: "1084244185".into(),
            h4: "1837068650".into(),
            protocol_version: AwgProtocolVersion::V2,
            header_protection_key: String::new(),
            content_padding_addition: String::new(),
            rekey_after_time: String::new(),
            rekey_timeout: String::new(),
            reject_after_time: String::new(),
            keepalive_timeout: String::new(),
            random_trailers: String::new(),
            disable_cookies: String::new(),
        };
        let config = build_client_config(
            &params,
            "PRIV_KEY=",
            "10.66.66.2",
            Some("fd42:42:42::2"),
            "PSK_KEY=",
            "1.1.1.1,1.0.0.1",
            "1.2.3.4:51820",
        )
        .unwrap();
        assert!(config.contains("PrivateKey = PRIV_KEY="));
        assert!(config.contains("Address = 10.66.66.2/32,fd42:42:42::2/128"));
        assert!(config.contains("DNS = 1.1.1.1,1.0.0.1"));
        assert!(config.contains("Jc = 8"));
        assert!(config.contains("H4 = 1837068650"));
        assert!(config.contains("PublicKey = SVR_PUB="));
        assert!(config.contains("PresharedKey = PSK_KEY="));
        assert!(config.contains("Endpoint = 1.2.3.4:51820"));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(!config.contains("HeaderProtectionKey"));

        let mut awg3_params = params.clone();
        awg3_params.protocol_version = AwgProtocolVersion::V3;
        awg3_params.header_protection_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        awg3_params.content_padding_addition = "10-100".into();
        awg3_params.rekey_after_time = "100-120".into();
        awg3_params.rekey_timeout = "3-7".into();
        awg3_params.reject_after_time = "150-180".into();
        awg3_params.keepalive_timeout = "5-15".into();
        let awg3_config = build_client_config(
            &awg3_params,
            "PRIV_KEY=",
            "10.66.66.2",
            Some("fd42:42:42::2"),
            "PSK_KEY=",
            "1.1.1.1,1.0.0.1",
            "1.2.3.4:51820",
        )
        .unwrap();
        assert!(awg3_config
            .contains("HeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(awg3_config.contains("ContentPaddingAddition = 10-100"));
        assert!(awg3_config.contains("KeepaliveTimeout = 5-15"));
        assert!(!awg3_config.contains("RandomTrailers"));
        assert!(!awg3_config.contains("DisableCookies"));

        let mut awg31_params = awg3_params.clone();
        awg31_params.protocol_version = AwgProtocolVersion::V31;
        awg31_params.random_trailers = "ON".into();
        awg31_params.disable_cookies = "0".into();
        let awg31_config = build_client_config(
            &awg31_params,
            "PRIV_KEY=",
            "10.66.66.2",
            Some("fd42:42:42::2"),
            "PSK_KEY=",
            "1.1.1.1,1.0.0.1",
            "1.2.3.4:51820",
        )
        .unwrap();
        assert!(awg31_config.contains("RandomTrailers = on"));
        assert!(awg31_config.contains("DisableCookies = off"));
        assert!(awg31_config
            .contains("HeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));

        awg31_params.random_trailers = "off".into();
        awg31_params.disable_cookies = "on".into();
        let mixed = build_client_config(
            &awg31_params,
            "PRIV_KEY=",
            "10.66.66.2",
            Some("fd42:42:42::2"),
            "PSK_KEY=",
            "1.1.1.1,1.0.0.1",
            "1.2.3.4:51820",
        )
        .unwrap();
        assert!(mixed.contains("RandomTrailers = off"));
        assert!(mixed.contains("DisableCookies = on"));
        assert_eq!(mixed.matches("RandomTrailers =").count(), 1);
        assert_eq!(mixed.matches("DisableCookies =").count(), 1);
    }

    #[test]
    fn build_client_config_omits_ipv6_when_disabled() {
        let params = ServerParams {
            server_pub_ip: "1.2.3.4".into(),
            server_awg_nic: "awg0".into(),
            server_awg_ipv4: "10.66.66.1".into(),
            server_awg_ipv6: "fd42:42:42::1".into(),
            server_port: "51820".into(),
            server_pub_key: "SVR_PUB=".into(),
            client_dns_1: "1.1.1.1".into(),
            client_dns_2: "".into(),
            allowed_ips: "0.0.0.0/0, ::/0".into(),
            jc: "8".into(),
            jmin: "50".into(),
            jmax: "1000".into(),
            s1: "107".into(),
            s2: "105".into(),
            s3: "62".into(),
            s4: "95".into(),
            h1: "321941292".into(),
            h2: "774489227".into(),
            h3: "1084244185".into(),
            h4: "1837068650".into(),
            protocol_version: AwgProtocolVersion::V2,
            header_protection_key: String::new(),
            content_padding_addition: String::new(),
            rekey_after_time: String::new(),
            rekey_timeout: String::new(),
            reject_after_time: String::new(),
            keepalive_timeout: String::new(),
            random_trailers: String::new(),
            disable_cookies: String::new(),
        };
        let config = build_client_config(
            &params,
            "PRIV_KEY=",
            "10.66.66.2",
            None,
            "PSK_KEY=",
            "1.1.1.1",
            "1.2.3.4:51820",
        )
        .unwrap();

        assert!(config.contains("Address = 10.66.66.2/32\n"));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(!config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(!config.contains("/128"));
    }

    #[test]
    fn build_client_config_rejects_empty_allowed_ips() {
        let params = ServerParams {
            server_pub_ip: "1.2.3.4".into(),
            server_awg_nic: "awg0".into(),
            server_awg_ipv4: "10.66.66.1".into(),
            server_awg_ipv6: "fd42:42:42::1".into(),
            server_port: "51820".into(),
            server_pub_key: "SVR_PUB=".into(),
            client_dns_1: "1.1.1.1".into(),
            client_dns_2: "".into(),
            allowed_ips: "fd00::/8, ::/0".into(),
            jc: "8".into(),
            jmin: "50".into(),
            jmax: "1000".into(),
            s1: "107".into(),
            s2: "105".into(),
            s3: "62".into(),
            s4: "95".into(),
            h1: "321941292".into(),
            h2: "774489227".into(),
            h3: "1084244185".into(),
            h4: "1837068650".into(),
            protocol_version: AwgProtocolVersion::V2,
            header_protection_key: String::new(),
            content_padding_addition: String::new(),
            rekey_after_time: String::new(),
            rekey_timeout: String::new(),
            reject_after_time: String::new(),
            keepalive_timeout: String::new(),
            random_trailers: String::new(),
            disable_cookies: String::new(),
        };

        let err = build_client_config(
            &params,
            "PRIV_KEY=",
            "10.66.66.2",
            None,
            "PSK_KEY=",
            "1.1.1.1",
            "1.2.3.4:51820",
        )
        .unwrap_err();

        assert!(matches!(err, CreateClientError::ConfigParse(_)));
    }

    // ── IP override / resolve_client_ips tests ─────────────────────────

    #[test]
    fn resolve_client_ips_auto_allocates_when_no_override() {
        let config = "\
[Peer]
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128
";
        let ovr = IpOverride::default();
        let (ipv4, ipv6) =
            resolve_client_ips(config, "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap();
        assert_eq!(ipv4, "10.66.66.3");
        assert_eq!(ipv6.as_deref(), Some("fd42:0042:0042:0000::3"));
    }

    #[test]
    fn resolve_client_ips_uses_ipv4_override() {
        let config = "\
[Peer]
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128
";
        let ovr = IpOverride {
            ipv4_address: Some("10.66.66.100".to_string()),
            ipv6_address: None,
        };
        let (ipv4, ipv6) =
            resolve_client_ips(config, "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap();
        assert_eq!(ipv4, "10.66.66.100");
        // When only IPv4 is specified, the IPv6 host segment reuses the same host value as a string.
        assert_eq!(ipv6.as_deref(), Some("fd42:0042:0042:0000::100"));
    }

    #[test]
    fn resolve_client_ips_uses_ipv6_override() {
        let config = "\
[Peer]
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128
";
        let ovr = IpOverride {
            ipv4_address: None,
            ipv6_address: Some("fd42:42:42::ff".to_string()),
        };
        let (ipv4, ipv6) =
            resolve_client_ips(config, "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap();
        // IPv4 auto-allocated to first free (3, since 2 is used).
        assert_eq!(ipv4, "10.66.66.3");
        assert_eq!(ipv6.as_deref(), Some("fd42:0042:0042:0000::ff"));
    }

    #[test]
    fn resolve_client_ips_uses_both_overrides() {
        let config = "\
[Peer]
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128
";
        let ovr = IpOverride {
            ipv4_address: Some("10.66.66.50".to_string()),
            ipv6_address: Some("fd42:42:42::ab".to_string()),
        };
        let (ipv4, ipv6) =
            resolve_client_ips(config, "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap();
        assert_eq!(ipv4, "10.66.66.50");
        assert_eq!(ipv6.as_deref(), Some("fd42:0042:0042:0000::ab"));
    }

    #[test]
    fn resolve_client_ips_ipv4_only_auto_allocates() {
        let config = "\
[Peer]
AllowedIPs = 10.66.66.2/32
";
        let ovr = IpOverride::default();
        let (ipv4, ipv6) = resolve_client_ips(config, "10.66.66", None, &ovr).unwrap();
        assert_eq!(ipv4, "10.66.66.3");
        assert_eq!(ipv6, None);
    }

    #[test]
    fn resolve_client_ips_ipv4_only_rejects_ipv6_override() {
        let ovr = IpOverride {
            ipv4_address: None,
            ipv6_address: Some("fd42:42:42::2".to_string()),
        };
        let err = resolve_client_ips("", "10.66.66", None, &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::InvalidIp(_)));
    }

    #[test]
    fn resolve_client_ips_rejects_ipv4_in_use() {
        let config = "\
[Peer]
AllowedIPs = 10.66.66.5/32,fd42:42:42::5/128
";
        let ovr = IpOverride {
            ipv4_address: Some("10.66.66.5".to_string()),
            ipv6_address: None,
        };
        let err =
            resolve_client_ips(config, "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::IpInUse(_)));
    }

    #[test]
    fn resolve_client_ips_rejects_ipv6_in_use() {
        let config = "\
[Peer]
AllowedIPs = 10.66.66.2/32,fd42:42:42::ff/128
";
        let ovr = IpOverride {
            ipv4_address: Some("10.66.66.100".to_string()),
            ipv6_address: Some("fd42:42:42::ff".to_string()),
        };
        let err =
            resolve_client_ips(config, "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::IpInUse(_)));
    }

    #[test]
    fn resolve_client_ips_rejects_invalid_ipv4_host() {
        // Host 0 is network address, host 1 is server.
        let ovr = IpOverride {
            ipv4_address: Some("10.66.66.0".to_string()),
            ipv6_address: None,
        };
        let err =
            resolve_client_ips("", "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::InvalidIp(_)));

        let ovr = IpOverride {
            ipv4_address: Some("10.66.66.1".to_string()),
            ipv6_address: None,
        };
        let err =
            resolve_client_ips("", "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::InvalidIp(_)));

        let ovr = IpOverride {
            ipv4_address: Some("10.66.66.255".to_string()),
            ipv6_address: None,
        };
        let err =
            resolve_client_ips("", "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::InvalidIp(_)));
    }

    #[test]
    fn resolve_client_ips_rejects_wrong_ipv4_subnet() {
        let ovr = IpOverride {
            ipv4_address: Some("192.168.1.5".to_string()),
            ipv6_address: None,
        };
        let err =
            resolve_client_ips("", "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::InvalidIp(_)));
    }

    #[test]
    fn resolve_client_ips_rejects_invalid_ipv6_address() {
        let ovr = IpOverride {
            ipv4_address: None,
            ipv6_address: Some("not-an-ipv6".to_string()),
        };
        let err =
            resolve_client_ips("", "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::InvalidIp(_)));
    }

    #[test]
    fn resolve_client_ips_rejects_wrong_ipv6_subnet() {
        let ovr = IpOverride {
            ipv4_address: None,
            ipv6_address: Some("fe80::1".to_string()),
        };
        let err =
            resolve_client_ips("", "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::InvalidIp(_)));
    }

    #[test]
    fn resolve_client_ips_rejects_zero_ipv6_host() {
        let ovr = IpOverride {
            ipv4_address: None,
            ipv6_address: Some("fd42:42:42::0".to_string()),
        };
        let err =
            resolve_client_ips("", "10.66.66", Some("fd42:0042:0042:0000"), &ovr).unwrap_err();
        assert!(matches!(err, CreateClientError::InvalidIp(_)));
    }

    #[test]
    fn validate_ipv4_host_boundary_values() {
        assert!(validate_ipv4_host(2).is_ok());
        assert!(validate_ipv4_host(254).is_ok());
        assert!(validate_ipv4_host(128).is_ok());
        assert!(validate_ipv4_host(0).is_err());
        assert!(validate_ipv4_host(1).is_err());
        assert!(validate_ipv4_host(255).is_err());
    }

    #[test]
    fn parse_ipv4_address_valid() {
        assert_eq!(parse_ipv4_address("10.66.66.5", "10.66.66").unwrap(), 5);
        assert_eq!(parse_ipv4_address("10.66.66.254", "10.66.66").unwrap(), 254);
    }

    #[test]
    fn parse_ipv4_address_wrong_subnet() {
        assert!(parse_ipv4_address("192.168.1.5", "10.66.66").is_err());
    }

    #[test]
    fn parse_ipv6_address_valid() {
        let result = parse_ipv6_address("fd42:42:42::ff", "fd42:0042:0042:0000").unwrap();
        assert_eq!(result, "fd42:0042:0042:0000::ff");
    }

    #[test]
    fn parse_ipv6_address_wrong_subnet() {
        assert!(parse_ipv6_address("fe80::1", "fd42:0042:0042:0000").is_err());
    }

    #[test]
    fn parse_ipv6_address_zero_host() {
        assert!(parse_ipv6_address("fd42:42:42::", "fd42:0042:0042:0000").is_err());
    }
}
