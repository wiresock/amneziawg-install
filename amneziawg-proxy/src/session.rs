use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tracing::{debug, info};

/// Process-wide monotonic epoch used to express session activity timestamps
/// as a plain `u64` (milliseconds), so they can live in an atomic and be
/// updated under a DashMap *read* guard on the per-packet hot path instead
/// of requiring an exclusive shard lock.
fn process_epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Milliseconds elapsed since the process epoch.
fn now_millis() -> u64 {
    process_epoch().elapsed().as_millis() as u64
}

/// Lookup-free handle to a single session's activity timestamp.
///
/// The per-session relay task captures one of these at spawn time and refreshes
/// it on every outbound packet, so keeping a download-heavy session alive costs
/// a cached atomic store instead of a `DashMap` read guard + hash + lookup.
#[derive(Clone)]
pub struct ActivityHandle(Arc<AtomicU64>);

impl ActivityHandle {
    /// Refresh the activity timestamp (see [`Session::touch`] for ordering).
    pub fn touch(&self) {
        self.0.store(now_millis(), Ordering::Relaxed);
    }
}

/// A single client session: maps a client address to a dedicated backend socket.
pub struct Session {
    /// Dedicated UDP socket bound to an ephemeral port for talking to the backend.
    pub backend_sock: Arc<UdpSocket>,
    /// Last activity time, as milliseconds since [`process_epoch`]. Stored
    /// atomically (behind an `Arc` so the relay can hold an [`ActivityHandle`]
    /// to it) so both data paths refresh it without write-lock contention
    /// between the inbound receive loop and the per-session relay task.
    pub last_active: Arc<AtomicU64>,
    /// The client address that owns this session.
    pub client_addr: SocketAddr,
}

impl Session {
    /// Refresh the activity timestamp. Relaxed ordering is sufficient: the
    /// value is only compared against the cleanup sweep's notion of "now",
    /// and a stale read there merely delays expiry by one sweep interval.
    fn touch(&self) {
        self.last_active.store(now_millis(), Ordering::Relaxed);
    }
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
    /// Requested kernel socket buffer size (SO_RCVBUF/SO_SNDBUF) for backend
    /// session sockets, in bytes. `0` leaves the OS defaults untouched.
    socket_buffer_bytes: usize,
}

impl SessionTable {
    pub fn new(backend_addr: SocketAddr, ttl: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            backend_addr,
            ttl,
            max_sessions,
            session_count: AtomicUsize::new(0),
            socket_buffer_bytes: 0,
        }
    }

    /// Set the kernel socket buffer size applied to newly created backend
    /// session sockets. `0` (the default) leaves the OS defaults untouched.
    pub fn with_socket_buffer_bytes(mut self, bytes: usize) -> Self {
        self.socket_buffer_bytes = bytes;
        self
    }

    /// Get the backend socket for a client, creating a new session if needed.
    ///
    /// Returns `(socket, is_new)` where `is_new` is `true` when a fresh session
    /// was just created (so the caller can spawn a relay task for it).
    ///
    /// Session creation is single-flight per client address: we pre-create the
    /// socket outside the lock, then use `DashMap::entry` to atomically check
    /// vacancy *and* enforce capacity in the same critical section. This
    /// prevents two concurrent calls for the same `client_addr` from both
    /// consuming a capacity slot when only one insert actually succeeds.
    pub async fn get_or_create(
        &self,
        client_addr: SocketAddr,
    ) -> anyhow::Result<(Arc<UdpSocket>, bool)> {
        // Fast path: session exists. Uses a shared (read) guard — the
        // activity timestamp is atomic, so no exclusive shard lock is taken
        // on the per-packet path.
        if let Some(entry) = self.sessions.get(&client_addr) {
            entry.touch();
            return Ok((Arc::clone(&entry.backend_sock), false));
        }

        // Slow path: create a new session.
        // Cheap capacity pre-check: reject new clients early when the table
        // is full, avoiding the expensive UdpSocket::bind()/connect() work
        // that would be discarded in the Vacant arm below.
        // Re-check the map when at capacity because a concurrent task may
        // have inserted the session between the fast-path `get` above and
        // this point.
        let current = self.session_count.load(Ordering::Acquire);
        if current >= self.max_sessions {
            if let Some(entry) = self.sessions.get(&client_addr) {
                entry.touch();
                return Ok((Arc::clone(&entry.backend_sock), false));
            }
            anyhow::bail!(
                "session limit reached ({}/{}), rejecting {}",
                current,
                self.max_sessions,
                client_addr,
            );
        }

        // Pre-create the backend socket before acquiring the entry lock so
        // no .await points are held under the DashMap shard guard.
        let bind_addr = if self.backend_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind_addr).await?;
        sock.connect(self.backend_addr).await?;
        crate::backend::configure_socket_buffers(&sock, self.socket_buffer_bytes);
        let sock = Arc::new(sock);

        // Use entry API so concurrent calls for the same client_addr
        // don't create duplicate sessions / orphaned sockets.
        // Capacity is checked only when the entry is truly vacant,
        // eliminating the race where two callers for the same client
        // both consume a slot while only one insert succeeds.
        let entry = self.sessions.entry(client_addr);
        match entry {
            dashmap::mapref::entry::Entry::Occupied(occ) => {
                // Another task raced us — reuse the existing session.
                occ.get().touch();
                Ok((Arc::clone(&occ.get().backend_sock), false))
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                // Atomically reserve a slot only after confirming the key
                // is vacant. No .await points between reservation and
                // insert, so cancellation cannot leak the slot.
                loop {
                    let current = self.session_count.load(Ordering::Acquire);
                    if current >= self.max_sessions {
                        anyhow::bail!(
                            "session limit reached ({}/{}), rejecting {}",
                            current,
                            self.max_sessions,
                            client_addr,
                        );
                    }
                    if self
                        .session_count
                        .compare_exchange(
                            current,
                            current + 1,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }

                let session = Session {
                    backend_sock: Arc::clone(&sock),
                    last_active: Arc::new(AtomicU64::new(now_millis())),
                    client_addr,
                };
                vac.insert(session);
                debug!(%client_addr, "new session created");
                Ok((sock, true))
            }
        }
    }

    /// Touch a session (update last_active). Takes only a shared (read)
    /// DashMap guard — safe to call per packet from the relay task without
    /// contending with the inbound receive loop.
    pub fn touch(&self, client_addr: &SocketAddr) {
        if let Some(entry) = self.sessions.get(client_addr) {
            entry.touch();
        }
    }

    /// Return a lookup-free [`ActivityHandle`] for `client_addr`, or `None` if
    /// the session does not exist. The relay task fetches this once at spawn so
    /// its per-packet keep-alive is a cached atomic store rather than a table
    /// lookup.
    pub fn activity_handle(&self, client_addr: &SocketAddr) -> Option<ActivityHandle> {
        self.sessions
            .get(client_addr)
            .map(|entry| ActivityHandle(Arc::clone(&entry.last_active)))
    }

    /// Remove expired sessions and return removed client addresses.
    pub fn cleanup_expired(&self) -> Vec<SocketAddr> {
        let now = now_millis();
        let ttl_ms = self.ttl.as_millis().min(u64::MAX as u128) as u64;
        let mut expired = Vec::new();

        self.sessions.retain(|addr, session| {
            let last = session.last_active.load(Ordering::Relaxed);
            if now.saturating_sub(last) > ttl_ms {
                expired.push(*addr);
                self.session_count.fetch_sub(1, Ordering::AcqRel);
                false
            } else {
                true
            }
        });

        // Log outside the retain closure to avoid holding DashMap shard locks
        // during formatting/IO under contention.
        for addr in &expired {
            info!(%addr, "session expired");
        }

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
