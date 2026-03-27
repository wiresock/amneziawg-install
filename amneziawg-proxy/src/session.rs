use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tracing::{debug, info};

/// A single client session: maps a client address to a dedicated backend socket.
pub struct Session {
    /// Dedicated UDP socket bound to an ephemeral port for talking to the backend.
    pub backend_sock: Arc<UdpSocket>,
    /// Last time this session saw activity.
    pub last_active: Instant,
    /// The client address that owns this session.
    pub client_addr: SocketAddr,
}

/// Concurrent session table keyed by client SocketAddr.
pub struct SessionTable {
    sessions: DashMap<SocketAddr, Session>,
    backend_addr: SocketAddr,
    ttl: Duration,
    max_sessions: usize,
}

impl SessionTable {
    pub fn new(backend_addr: SocketAddr, ttl: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            backend_addr,
            ttl,
            max_sessions,
        }
    }

    /// Get the backend socket for a client, creating a new session if needed.
    ///
    /// Returns `(socket, is_new)` where `is_new` is `true` when a fresh session
    /// was just created (so the caller can spawn a relay task for it).
    pub async fn get_or_create(
        &self,
        client_addr: SocketAddr,
    ) -> anyhow::Result<(Arc<UdpSocket>, bool)> {
        // Fast path: session exists
        if let Some(mut entry) = self.sessions.get_mut(&client_addr) {
            entry.last_active = Instant::now();
            return Ok((Arc::clone(&entry.backend_sock), false));
        }

        // Check session limit before creating a new one
        if self.sessions.len() >= self.max_sessions {
            anyhow::bail!(
                "session limit reached ({}/{}), rejecting {}",
                self.sessions.len(),
                self.max_sessions,
                client_addr,
            );
        }

        // Slow path: create a new session.
        // Bind to the correct address family so connect() works for both
        // IPv4 and IPv6 backend addresses.
        let bind_addr = if self.backend_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind_addr).await?;
        sock.connect(self.backend_addr).await?;
        let sock = Arc::new(sock);

        let session = Session {
            backend_sock: Arc::clone(&sock),
            last_active: Instant::now(),
            client_addr,
        };

        self.sessions.insert(client_addr, session);
        debug!(%client_addr, "new session created");
        Ok((sock, true))
    }

    /// Touch a session (update last_active).
    pub fn touch(&self, client_addr: &SocketAddr) {
        if let Some(mut entry) = self.sessions.get_mut(client_addr) {
            entry.last_active = Instant::now();
        }
    }

    /// Remove expired sessions and return removed client addresses.
    pub fn cleanup_expired(&self) -> Vec<SocketAddr> {
        let now = Instant::now();
        let mut expired = Vec::new();

        self.sessions.retain(|addr, session| {
            if now.duration_since(session.last_active) > self.ttl {
                info!(%addr, "session expired");
                expired.push(*addr);
                false
            } else {
                true
            }
        });

        expired
    }

    /// Look up a client address by the local address of its backend socket.
    pub fn find_client_by_backend_local_addr(
        &self,
        local_addr: SocketAddr,
    ) -> Option<SocketAddr> {
        for entry in self.sessions.iter() {
            if let Ok(addr) = entry.backend_sock.local_addr() {
                if addr == local_addr {
                    return Some(entry.client_addr);
                }
            }
        }
        None
    }

    /// Get all backend sockets for the currently active sessions.
    pub fn all_backend_sockets(&self) -> Vec<(SocketAddr, Arc<UdpSocket>)> {
        self.sessions
            .iter()
            .map(|entry| (entry.client_addr, Arc::clone(&entry.backend_sock)))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Remove a specific session.
    pub fn remove(&self, addr: &SocketAddr) {
        self.sessions.remove(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_retrieve_session() {
        let backend: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let table = SessionTable::new(backend, Duration::from_secs(60), 1000);
        let client: SocketAddr = "10.0.0.1:5555".parse().unwrap();

        let (sock1, is_new1) = table.get_or_create(client).await.unwrap();
        assert!(is_new1, "first call should create a new session");

        let (sock2, is_new2) = table.get_or_create(client).await.unwrap();
        assert!(!is_new2, "second call should return existing session");

        // Should return the same socket
        assert_eq!(
            sock1.local_addr().unwrap(),
            sock2.local_addr().unwrap()
        );
        assert_eq!(table.len(), 1);
    }

    #[tokio::test]
    async fn cleanup_expired_sessions() {
        let backend: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        // TTL of 0 means everything expires immediately
        let table = SessionTable::new(backend, Duration::from_millis(0), 1000);
        let client: SocketAddr = "10.0.0.1:5555".parse().unwrap();

        table.get_or_create(client).await.unwrap();
        assert_eq!(table.len(), 1);

        // Wait a tiny bit so the session is expired
        tokio::time::sleep(Duration::from_millis(10)).await;

        let expired = table.cleanup_expired();
        assert_eq!(expired, vec![client]);
        assert!(table.is_empty());
    }

    #[tokio::test]
    async fn touch_refreshes_session() {
        let backend: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let table = SessionTable::new(backend, Duration::from_secs(60), 1000);
        let client: SocketAddr = "10.0.0.1:5555".parse().unwrap();

        table.get_or_create(client).await.unwrap();
        table.touch(&client);

        assert_eq!(table.len(), 1);
    }

    #[tokio::test]
    async fn remove_session() {
        let backend: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let table = SessionTable::new(backend, Duration::from_secs(60), 1000);
        let client: SocketAddr = "10.0.0.1:5555".parse().unwrap();

        table.get_or_create(client).await.unwrap();
        table.remove(&client);
        assert!(table.is_empty());
    }

    #[tokio::test]
    async fn all_backend_sockets_returns_entries() {
        let backend: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let table = SessionTable::new(backend, Duration::from_secs(60), 1000);
        let c1: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        let c2: SocketAddr = "10.0.0.2:2222".parse().unwrap();

        table.get_or_create(c1).await.unwrap();
        table.get_or_create(c2).await.unwrap();

        let socks = table.all_backend_sockets();
        assert_eq!(socks.len(), 2);
    }

    #[tokio::test]
    async fn session_limit_enforced() {
        let backend: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let table = SessionTable::new(backend, Duration::from_secs(60), 2);

        let c1: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        let c2: SocketAddr = "10.0.0.2:2222".parse().unwrap();
        let c3: SocketAddr = "10.0.0.3:3333".parse().unwrap();

        assert!(table.get_or_create(c1).await.is_ok());
        assert!(table.get_or_create(c2).await.is_ok());
        // Third session should be rejected
        assert!(table.get_or_create(c3).await.is_err());
        assert_eq!(table.len(), 2);
    }
}
