//! BoringTun's native packet imitation settings. No proxy is involved.
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Settings {
    pub protocol: String,
    pub domain: String,
}

impl Settings {
    /// Match the installer's strict ASCII LDH hostname rules at the HTTP edge.
    pub fn parse(protocol: &str, domain: &str) -> Result<Self, &'static str> {
        if !matches!(protocol, "none" | "dns" | "quic" | "sip" | "stun") {
            return Err("Choose Off, DNS, QUIC, SIP or STUN.");
        }
        if !domain.is_empty() {
            if !matches!(protocol, "dns" | "quic" | "sip") {
                return Err("This imitation mode does not use a hostname.");
            }
            if domain.len() > 253
                || !domain.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label.as_bytes()[0].is_ascii_alphanumeric()
                        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
            {
                return Err("Enter an ASCII hostname (up to 253 characters), without a URL or trailing dot.");
            }
        }
        Ok(Self {
            protocol: protocol.into(),
            domain: domain.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_settings_match_installer_hostname_rules() {
        for protocol in ["none", "dns", "quic", "sip", "stun"] {
            assert!(Settings::parse(protocol, "").is_ok());
            assert_eq!(
                Settings::parse(protocol, "Example-1.com").is_ok(),
                matches!(protocol, "dns" | "quic" | "sip")
            );
        }
        for invalid in [
            "-a",
            "a-",
            "a..b",
            "a.",
            "a_b",
            "a b",
            "é.com",
            "https://example.com",
            "a\nb",
        ] {
            assert!(Settings::parse("quic", invalid).is_err(), "{invalid}");
        }
        assert!(Settings::parse("quic", &"a".repeat(63)).is_ok());
        assert!(Settings::parse("quic", &"a".repeat(64)).is_err());
        let maximum = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(Settings::parse("dns", &maximum).is_ok());
        assert!(Settings::parse("dns", &(maximum + "d")).is_err());
        assert!(Settings::parse("--help", "").is_err());
    }
}
