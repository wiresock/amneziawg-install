use thiserror::Error;

/// Top-level errors for the proxy application.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("session not found for {0}")]
    SessionNotFound(std::net::SocketAddr),

    #[error("rate limited: {0}")]
    RateLimited(std::net::SocketAddr),

    #[error("backend unreachable: {0}")]
    BackendUnreachable(String),

    #[error("shutdown signal received")]
    Shutdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_config() {
        let e = ProxyError::Config("bad toml".into());
        assert_eq!(e.to_string(), "configuration error: bad toml");
    }

    #[test]
    fn error_display_io() {
        let io = std::io::Error::new(std::io::ErrorKind::AddrInUse, "port taken");
        let e = ProxyError::Io(io);
        assert!(e.to_string().contains("port taken"));
    }

    #[test]
    fn error_display_rate_limited() {
        let addr: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let e = ProxyError::RateLimited(addr);
        assert!(e.to_string().contains("127.0.0.1:1234"));
    }

    #[test]
    fn error_display_session_not_found() {
        let addr: std::net::SocketAddr = "10.0.0.1:5555".parse().unwrap();
        let e = ProxyError::SessionNotFound(addr);
        assert!(e.to_string().contains("10.0.0.1:5555"));
    }

    #[test]
    fn error_display_backend_unreachable() {
        let e = ProxyError::BackendUnreachable("timeout".into());
        assert_eq!(e.to_string(), "backend unreachable: timeout");
    }

    #[test]
    fn error_display_shutdown() {
        let e = ProxyError::Shutdown;
        assert_eq!(e.to_string(), "shutdown signal received");
    }
}
