use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tracing::{debug, info};

/// RAII guard that decrements `session_count` on drop unless committed.
///
/// This ensures that if the future holding the guard is cancelled between
/// the counter reservation and the final insert/rollback, the slot is always
/// released — preventing permanent capacity loss.
struct SlotReservation<'a> {
    counter: &'a AtomicUsize,
    committed: bool,
}

impl<'a> SlotReservation<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        Self {
            counter,
            committed: false,
        }
    }

    /// Mark the reservation as consumed so `Drop` won't release the slot.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for SlotReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

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
    /// Atomic counter kept in sync with `sessions.len()` so the capacity
    /// check + insert are race-free (same pattern as MetricsStore).
    session_count: AtomicUsize,
}

impl SessionTable {
    pub fn new(backend_addr: SocketAddr, ttl: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            backend_addr,
            ttl,
            max_sessions,
            session_count: AtomicUsize::new(0),
        }
    }

    /// Get the backend socket for a client, creating a new session if needed.
    ///
    /// Returns `(socket, is_new)` where `is_new` is `true` when a fresh session
    /// was just created (so the caller can spawn a relay task for it).
    ///
    /// Session creation is single-flight per client address: we pre-create the
    /// socket outside the lock, then use `DashMap::entry` to atomically insert
    /// only if the key is still vacant. This prevents two concurrent calls for
    /// the same `client_addr` from both inserting separate sessions.
    pub async fn get_or_create(
        &self,
        client_addr: SocketAddr,
    ) -> anyhow::Result<(Arc<UdpSocket>, bool)> {
        // Fast path: session exists
        if let Some(mut entry) = self.sessions.get_mut(&client_addr) {
            entry.last_active = Instant::now();
            return Ok((Arc::clone(&entry.backend_sock), false));
        }

        // Atomically reserve a slot before creating the session.
        // This prevents concurrent callers from all observing len() < max
        // and exceeding the limit.
        loop {
            let current = self.session_count.load(Ordering::Acquire);
            if current >= self.max_sessions {
                // Before rejecting, re-check whether this client already has
                // a session — concurrent callers for the same client_addr
                // should still succeed when the limit is reached.
                if let Some(mut entry) = self.sessions.get_mut(&client_addr) {
                    entry.last_active = Instant::now();
                    return Ok((Arc::clone(&entry.backend_sock), false));
                }
                anyhow::bail!(
                    "session limit reached ({}/{}), rejecting {}",
                    current,
                    self.max_sessions,
                    client_addr,
                );
            }
            if self.session_count.compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                break;
            }
        }

        // RAII guard: if the future is cancelled between the reservation
        // above and the final insert/rollback below, this automatically
        // decrements session_count so the slot is never leaked.
        let reservation = SlotReservation::new(&self.session_count);

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

        // Use entry API so concurrent calls for the same client_addr
        // don't create duplicate sessions / orphaned sockets.
        let entry = self.sessions.entry(client_addr);
        match entry {
            dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                // Another task raced us — reuse the existing session.
                // Drop reservation (which decrements the counter).
                occ.get_mut().last_active = Instant::now();
                Ok((Arc::clone(&occ.get().backend_sock), false))
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                let session = Session {
                    backend_sock: Arc::clone(&sock),
                    last_active: Instant::now(),
                    client_addr,
                };
                vac.insert(session);
                // Commit the reservation so Drop doesn't decrement.
                reservation.commit();
                debug!(%client_addr, "new session created");
                Ok((sock, true))
            }
        }
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
                self.session_count.fetch_sub(1, Ordering::AcqRel);
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
        if self.sessions.remove(addr).is_some() {
            self.session_count.fetch_sub(1, Ordering::AcqRel);
        }
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

    #[tokio::test]
    async fn existing_client_allowed_at_capacity() {
        let backend: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let table = SessionTable::new(backend, Duration::from_secs(60), 2);

        let c1: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        let c2: SocketAddr = "10.0.0.2:2222".parse().unwrap();

        assert!(table.get_or_create(c1).await.is_ok());
        assert!(table.get_or_create(c2).await.is_ok());
        // Existing client should still succeed at capacity
        let (_, is_new) = table.get_or_create(c1).await.unwrap();
        assert!(!is_new, "existing client should reuse session at capacity");
        assert_eq!(table.len(), 2);
    }
}
