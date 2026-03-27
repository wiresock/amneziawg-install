use serde::Deserialize;
use std::path::Path;

use crate::errors::ProxyError;

// ---------------------------------------------------------------------------
// AmneziaWG obfuscation parameters
// ---------------------------------------------------------------------------

/// A min–max range for an H header parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HRange {
    pub min: u32,
    pub max: u32,
}

impl HRange {
    /// Returns `true` if `value` falls within this range (inclusive).
    pub fn contains(&self, value: u32) -> bool {
        value >= self.min && value <= self.max
    }
}

/// AmneziaWG obfuscation parameters parsed from an AWG config file.
///
/// AmneziaWG extends WireGuard by replacing the standard 4-byte message type
/// header with a random value drawn from a per-type H range and appending
/// S bytes of random padding after the packet payload.
///
/// | Packet type          | Header range | Padding |
/// |----------------------|-------------|---------|
/// | Handshake Initiation | H1          | S1      |
/// | Handshake Response   | H2          | S2      |
/// | Cookie Reply         | H3          | S3      |
/// | Transport Data       | H4          | S4      |
#[derive(Debug, Clone)]
pub struct AwgParams {
    /// Junk packet count per handshake.
    pub jc: u32,
    /// Minimum junk packet size in bytes.
    pub jmin: u32,
    /// Maximum junk packet size in bytes.
    pub jmax: u32,
    /// Padding bytes appended to Handshake Initiation packets.
    pub s1: u32,
    /// Padding bytes appended to Handshake Response packets.
    pub s2: u32,
    /// Padding bytes appended to Cookie Reply packets.
    pub s3: u32,
    /// Padding bytes appended to Transport Data packets.
    pub s4: u32,
    /// Header value range for Handshake Initiation.
    pub h1: HRange,
    /// Header value range for Handshake Response.
    pub h2: HRange,
    /// Header value range for Cookie Reply.
    pub h3: HRange,
    /// Header value range for Transport Data.
    pub h4: HRange,
}

/// Parse an AWG config file (INI-style) and extract the obfuscation parameters
/// from the `[Interface]` section.
///
/// Expected format (keys are case-insensitive):
/// ```ini
/// [Interface]
/// Jc = 5
/// Jmin = 50
/// Jmax = 1000
/// S1 = 42
/// S2 = 88
/// S3 = 33
/// S4 = 120
/// H1 = 123456-223455
/// H2 = 300000-400000
/// H3 = 500000-600000
/// H4 = 700000-800000
/// ```
pub fn parse_awg_config(text: &str) -> Result<AwgParams, ProxyError> {
    let mut jc: Option<u32> = None;
    let mut jmin: Option<u32> = None;
    let mut jmax: Option<u32> = None;
    let mut s1: Option<u32> = None;
    let mut s2: Option<u32> = None;
    let mut s3: Option<u32> = None;
    let mut s4: Option<u32> = None;
    let mut h1: Option<HRange> = None;
    let mut h2: Option<HRange> = None;
    let mut h3: Option<HRange> = None;
    let mut h4: Option<HRange> = None;

    let mut in_interface = false;

    for line in text.lines() {
        let trimmed = line.trim();

        // Detect section headers
        if trimmed.starts_with('[') {
            in_interface = trimmed.eq_ignore_ascii_case("[interface]");
            continue;
        }

        if !in_interface {
            continue;
        }

        // Skip comments and blank lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        // Parse key = value
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim();

            match key.to_ascii_lowercase().as_str() {
                "jc" => jc = Some(parse_u32(key, value)?),
                "jmin" => jmin = Some(parse_u32(key, value)?),
                "jmax" => jmax = Some(parse_u32(key, value)?),
                "s1" => s1 = Some(parse_u32(key, value)?),
                "s2" => s2 = Some(parse_u32(key, value)?),
                "s3" => s3 = Some(parse_u32(key, value)?),
                "s4" => s4 = Some(parse_u32(key, value)?),
                "h1" => h1 = Some(parse_h_range(key, value)?),
                "h2" => h2 = Some(parse_h_range(key, value)?),
                "h3" => h3 = Some(parse_h_range(key, value)?),
                "h4" => h4 = Some(parse_h_range(key, value)?),
                _ => {} // ignore unknown keys (Address, PrivateKey, etc.)
            }
        }
    }

    let params = AwgParams {
        jc: jc.ok_or_else(|| ProxyError::Config("missing AWG parameter: Jc".into()))?,
        jmin: jmin.ok_or_else(|| ProxyError::Config("missing AWG parameter: Jmin".into()))?,
        jmax: jmax.ok_or_else(|| ProxyError::Config("missing AWG parameter: Jmax".into()))?,
        s1: s1.ok_or_else(|| ProxyError::Config("missing AWG parameter: S1".into()))?,
        s2: s2.ok_or_else(|| ProxyError::Config("missing AWG parameter: S2".into()))?,
        s3: s3.ok_or_else(|| ProxyError::Config("missing AWG parameter: S3".into()))?,
        s4: s4.ok_or_else(|| ProxyError::Config("missing AWG parameter: S4".into()))?,
        h1: h1.ok_or_else(|| ProxyError::Config("missing AWG parameter: H1".into()))?,
        h2: h2.ok_or_else(|| ProxyError::Config("missing AWG parameter: H2".into()))?,
        h3: h3.ok_or_else(|| ProxyError::Config("missing AWG parameter: H3".into()))?,
        h4: h4.ok_or_else(|| ProxyError::Config("missing AWG parameter: H4".into()))?,
    };

    validate_awg_params(&params)?;
    Ok(params)
}

/// Load AWG parameters from a config file on disk.
pub fn load_awg_config(path: &Path) -> Result<AwgParams, ProxyError> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        ProxyError::Config(format!("failed to read AWG config {}: {}", path.display(), e))
    })?;
    parse_awg_config(&contents)
}

fn parse_u32(key: &str, value: &str) -> Result<u32, ProxyError> {
    value
        .parse::<u32>()
        .map_err(|e| ProxyError::Config(format!("invalid value for {key}: '{value}' ({e})")))
}

/// Parse an H-range value in `"min-max"` or single-value format.
fn parse_h_range(key: &str, value: &str) -> Result<HRange, ProxyError> {
    if let Some((min_s, max_s)) = value.split_once('-') {
        let min = min_s
            .trim()
            .parse::<u32>()
            .map_err(|e| ProxyError::Config(format!("invalid {key} min: '{min_s}' ({e})")))?;
        let max = max_s
            .trim()
            .parse::<u32>()
            .map_err(|e| ProxyError::Config(format!("invalid {key} max: '{max_s}' ({e})")))?;
        if min > max {
            return Err(ProxyError::Config(format!(
                "{key} range min ({min}) > max ({max})"
            )));
        }
        Ok(HRange { min, max })
    } else {
        // Single value → point range
        let v = value
            .parse::<u32>()
            .map_err(|e| ProxyError::Config(format!("invalid {key} value: '{value}' ({e})")))?;
        Ok(HRange { min: v, max: v })
    }
}

fn validate_awg_params(p: &AwgParams) -> Result<(), ProxyError> {
    // Jmin <= Jmax
    if p.jmin > p.jmax {
        return Err(ProxyError::Config(format!(
            "Jmin ({}) > Jmax ({})",
            p.jmin, p.jmax
        )));
    }

    // H ranges must not overlap
    let ranges = [
        ("H1", p.h1),
        ("H2", p.h2),
        ("H3", p.h3),
        ("H4", p.h4),
    ];
    for i in 0..ranges.len() {
        for j in (i + 1)..ranges.len() {
            let (name_a, a) = ranges[i];
            let (name_b, b) = ranges[j];
            if a.min <= b.max && b.min <= a.max {
                return Err(ProxyError::Config(format!(
                    "{name_a} ({}-{}) overlaps {name_b} ({}-{})",
                    a.min, a.max, b.min, b.max
                )));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Proxy TOML configuration
// ---------------------------------------------------------------------------

/// Top-level configuration loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// Address the proxy listens on, e.g. `"0.0.0.0:51820"`.
    pub listen: String,

    /// Backend (real AmneziaWG) address, e.g. `"127.0.0.1:51821"`.
    pub backend: String,

    /// Session time-to-live in seconds. Idle sessions are reaped after this.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,

    /// Interval in seconds between session cleanup sweeps.
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,

    /// Maximum probe responses per client per second.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_sec: u32,

    /// Which protocol to imitate: `"quic"`, `"dns"`, or `"sip"`.
    #[serde(default = "default_imitate_protocol")]
    pub imitate_protocol: String,

    /// Buffer size for UDP recv in bytes.
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Maximum number of concurrent sessions (prevents resource exhaustion).
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Optional path to the AmneziaWG config file (e.g. `/etc/awg/awg0.conf`).
    /// When set, AWG obfuscation parameters (S1-S4, H1-H4) are loaded and used
    /// for packet classification and per-type padding transformation.
    #[serde(default)]
    pub awg_config: Option<String>,
}

fn default_session_ttl() -> u64 {
    300
}
fn default_cleanup_interval() -> u64 {
    60
}
fn default_rate_limit() -> u32 {
    5
}
fn default_imitate_protocol() -> String {
    "quic".into()
}
fn default_buffer_size() -> usize {
    65535
}
fn default_max_sessions() -> usize {
    10000
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:51820".into(),
            backend: "127.0.0.1:51821".into(),
            session_ttl_secs: default_session_ttl(),
            cleanup_interval_secs: default_cleanup_interval(),
            rate_limit_per_sec: default_rate_limit(),
            imitate_protocol: default_imitate_protocol(),
            buffer_size: default_buffer_size(),
            max_sessions: default_max_sessions(),
            awg_config: None,
        }
    }
}

/// Load configuration from a TOML file at the given path.
pub fn load_config(path: &Path) -> Result<ProxyConfig, ProxyError> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        ProxyError::Config(format!("failed to read {}: {}", path.display(), e))
    })?;
    let config: ProxyConfig = toml::from_str(&contents)
        .map_err(|e| ProxyError::Config(format!("invalid TOML: {e}")))?;
    validate(&config)?;
    Ok(config)
}

/// Parse configuration from a TOML string.
pub fn parse_config(toml_str: &str) -> Result<ProxyConfig, ProxyError> {
    let config: ProxyConfig =
        toml::from_str(toml_str).map_err(|e| ProxyError::Config(format!("invalid TOML: {e}")))?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &ProxyConfig) -> Result<(), ProxyError> {
    config
        .listen
        .parse::<std::net::SocketAddr>()
        .map_err(|e| ProxyError::Config(format!("bad listen address '{}': {e}", config.listen)))?;
    config.backend.parse::<std::net::SocketAddr>().map_err(|e| {
        ProxyError::Config(format!("bad backend address '{}': {e}", config.backend))
    })?;
    let valid_protos = ["quic", "dns", "sip"];
    if !valid_protos.contains(&config.imitate_protocol.as_str()) {
        return Err(ProxyError::Config(format!(
            "unsupported imitate_protocol '{}'; expected one of: {}",
            config.imitate_protocol,
            valid_protos.join(", ")
        )));
    }
    if config.buffer_size == 0 {
        return Err(ProxyError::Config("buffer_size must be > 0".into()));
    }
    if config.cleanup_interval_secs == 0 {
        return Err(ProxyError::Config(
            "cleanup_interval_secs must be > 0".into(),
        ));
    }
    if config.session_ttl_secs == 0 {
        return Err(ProxyError::Config(
            "session_ttl_secs must be > 0".into(),
        ));
    }
    if config.max_sessions == 0 {
        return Err(ProxyError::Config(
            "max_sessions must be > 0".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Proxy TOML config tests --

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
"#;
        let cfg = parse_config(toml).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:51820");
        assert_eq!(cfg.backend, "127.0.0.1:51821");
        assert_eq!(cfg.session_ttl_secs, 300);
        assert_eq!(cfg.cleanup_interval_secs, 60);
        assert_eq!(cfg.rate_limit_per_sec, 5);
        assert_eq!(cfg.imitate_protocol, "quic");
        assert_eq!(cfg.buffer_size, 65535);
        assert!(cfg.awg_config.is_none());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
listen = "0.0.0.0:9999"
backend = "10.0.0.1:51821"
session_ttl_secs = 600
cleanup_interval_secs = 30
rate_limit_per_sec = 10
imitate_protocol = "dns"
buffer_size = 4096
awg_config = "/etc/awg/awg0.conf"
"#;
        let cfg = parse_config(toml).unwrap();
        assert_eq!(cfg.session_ttl_secs, 600);
        assert_eq!(cfg.cleanup_interval_secs, 30);
        assert_eq!(cfg.rate_limit_per_sec, 10);
        assert_eq!(cfg.imitate_protocol, "dns");
        assert_eq!(cfg.buffer_size, 4096);
        assert_eq!(cfg.awg_config.as_deref(), Some("/etc/awg/awg0.conf"));
    }

    #[test]
    fn reject_bad_listen() {
        let toml = r#"
listen = "not-an-addr"
backend = "127.0.0.1:51821"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("bad listen address"));
    }

    #[test]
    fn reject_bad_protocol() {
        let toml = r#"
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
imitate_protocol = "http"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("unsupported imitate_protocol"));
    }

    #[test]
    fn reject_zero_buffer_size() {
        let toml = r#"
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
buffer_size = 0
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("buffer_size must be > 0"));
    }

    #[test]
    fn reject_zero_cleanup_interval() {
        let toml = r#"
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
cleanup_interval_secs = 0
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("cleanup_interval_secs must be > 0"));
    }

    #[test]
    fn reject_zero_session_ttl() {
        let toml = r#"
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
session_ttl_secs = 0
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("session_ttl_secs must be > 0"));
    }

    #[test]
    fn reject_zero_max_sessions() {
        let toml = r#"
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
max_sessions = 0
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.to_string().contains("max_sessions must be > 0"));
    }

    #[test]
    fn load_config_missing_file() {
        let err = load_config(Path::new("/nonexistent/config.toml")).unwrap_err();
        assert!(err.to_string().contains("failed to read"));
    }

    #[test]
    fn load_config_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.toml");
        std::fs::write(
            &path,
            r#"
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
"#,
        )
        .unwrap();
        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:51820");
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = ProxyConfig::default();
        validate(&cfg).unwrap();
    }

    // -- AWG config parsing tests --

    fn sample_awg_conf() -> &'static str {
        r#"[Interface]
Address = 10.66.66.1/24,fd42:42:42::1/64
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 42
S2 = 88
S3 = 33
S4 = 120
H1 = 100-200
H2 = 300-400
H3 = 500-600
H4 = 700-800

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.66.66.2/32
"#
    }

    #[test]
    fn parse_awg_config_full() {
        let p = parse_awg_config(sample_awg_conf()).unwrap();
        assert_eq!(p.jc, 5);
        assert_eq!(p.jmin, 50);
        assert_eq!(p.jmax, 1000);
        assert_eq!(p.s1, 42);
        assert_eq!(p.s2, 88);
        assert_eq!(p.s3, 33);
        assert_eq!(p.s4, 120);
        assert_eq!(p.h1, HRange { min: 100, max: 200 });
        assert_eq!(p.h2, HRange { min: 300, max: 400 });
        assert_eq!(p.h3, HRange { min: 500, max: 600 });
        assert_eq!(p.h4, HRange { min: 700, max: 800 });
    }

    #[test]
    fn parse_awg_config_single_h_value() {
        let conf = r#"[Interface]
Jc = 1
Jmin = 10
Jmax = 100
S1 = 20
S2 = 30
S3 = 40
S4 = 50
H1 = 999
H2 = 2000-3000
H3 = 5000-6000
H4 = 8000-9000
"#;
        let p = parse_awg_config(conf).unwrap();
        assert_eq!(p.h1, HRange { min: 999, max: 999 });
    }

    #[test]
    fn parse_awg_config_missing_param() {
        let conf = r#"[Interface]
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 42
"#;
        let err = parse_awg_config(conf).unwrap_err();
        assert!(err.to_string().contains("missing AWG parameter"));
    }

    #[test]
    fn parse_awg_config_jmin_gt_jmax() {
        let conf = r#"[Interface]
Jc = 5
Jmin = 500
Jmax = 100
S1 = 20
S2 = 30
S3 = 40
S4 = 50
H1 = 100-200
H2 = 300-400
H3 = 500-600
H4 = 700-800
"#;
        let err = parse_awg_config(conf).unwrap_err();
        assert!(err.to_string().contains("Jmin"));
    }

    #[test]
    fn parse_awg_config_overlapping_h_ranges() {
        let conf = r#"[Interface]
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
S3 = 40
S4 = 50
H1 = 100-300
H2 = 250-400
H3 = 500-600
H4 = 700-800
"#;
        let err = parse_awg_config(conf).unwrap_err();
        assert!(err.to_string().contains("overlaps"));
    }

    #[test]
    fn parse_awg_config_h_range_inverted() {
        let conf = r#"[Interface]
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
S3 = 40
S4 = 50
H1 = 300-100
H2 = 400-500
H3 = 600-700
H4 = 800-900
"#;
        let err = parse_awg_config(conf).unwrap_err();
        assert!(err.to_string().contains("min"));
    }

    #[test]
    fn parse_awg_config_ignores_peer_section() {
        // Ensure keys in [Peer] don't interfere
        let conf = r#"[Interface]
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
S3 = 40
S4 = 50
H1 = 100-200
H2 = 300-400
H3 = 500-600
H4 = 700-800

[Peer]
PublicKey = XXXX
AllowedIPs = 10.0.0.0/8
"#;
        let p = parse_awg_config(conf).unwrap();
        assert_eq!(p.jc, 5);
    }

    #[test]
    fn parse_awg_config_case_insensitive_section() {
        let conf = r#"[interface]
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
S3 = 40
S4 = 50
H1 = 100-200
H2 = 300-400
H3 = 500-600
H4 = 700-800
"#;
        let p = parse_awg_config(conf).unwrap();
        assert_eq!(p.s1, 20);
    }

    #[test]
    fn h_range_contains() {
        let r = HRange { min: 100, max: 200 };
        assert!(r.contains(100));
        assert!(r.contains(150));
        assert!(r.contains(200));
        assert!(!r.contains(99));
        assert!(!r.contains(201));
    }

    #[test]
    fn load_awg_config_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("awg0.conf");
        std::fs::write(&path, sample_awg_conf()).unwrap();
        let p = load_awg_config(&path).unwrap();
        assert_eq!(p.s1, 42);
    }

    #[test]
    fn load_awg_config_missing_file() {
        let err = load_awg_config(Path::new("/nonexistent/awg0.conf")).unwrap_err();
        assert!(err.to_string().contains("failed to read"));
    }

    #[test]
    fn parse_awg_config_invalid_h_value() {
        let conf = r#"[Interface]
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
S3 = 40
S4 = 50
H1 = abc
H2 = 300-400
H3 = 500-600
H4 = 700-800
"#;
        let err = parse_awg_config(conf).unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn parse_awg_config_large_h_ranges() {
        // Realistic ranges as generated by the install script
        let conf = r#"[Interface]
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 42
S2 = 88
S3 = 33
S4 = 120
H1 = 5-100000004
H2 = 100000005-200000004
H3 = 200000005-300000004
H4 = 300000005-400000004
"#;
        let p = parse_awg_config(conf).unwrap();
        assert_eq!(p.h1.min, 5);
        assert_eq!(p.h1.max, 100_000_004);
        assert!(p.h4.contains(350_000_000));
    }
}
