use serde::Deserialize;
use std::path::Path;

use crate::errors::ProxyError;

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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
"#;
        let cfg = parse_config(toml).unwrap();
        assert_eq!(cfg.session_ttl_secs, 600);
        assert_eq!(cfg.cleanup_interval_secs, 30);
        assert_eq!(cfg.rate_limit_per_sec, 10);
        assert_eq!(cfg.imitate_protocol, "dns");
        assert_eq!(cfg.buffer_size, 4096);
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
}
