use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;

/// Per-client metrics: packet counts and rate-limit state.
pub struct ClientMetrics {
    /// Total packets received from this client.
    pub packets_in: AtomicU64,
    /// Total packets sent to this client.
    pub packets_out: AtomicU64,
    /// Total probe responses sent to this client.
    pub probes_sent: AtomicU64,
    /// Rate-limit token bucket state.
    rate_tokens: std::sync::Mutex<RateBucket>,
}

struct RateBucket {
    tokens: f64,
    last_refill: Instant,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl ClientMetrics {
    pub fn new(rate_limit_per_sec: u32) -> Self {
        let max = rate_limit_per_sec as f64;
        Self {
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            probes_sent: AtomicU64::new(0),
            rate_tokens: std::sync::Mutex::new(RateBucket {
                tokens: max,
                last_refill: Instant::now(),
                max_tokens: max,
                refill_rate: max,
            }),
        }
    }

    /// Try to consume one rate-limit token. Returns `true` if allowed.
    pub fn try_acquire_probe(&self) -> bool {
        let mut bucket = self.rate_tokens.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn record_in(&self) {
        self.packets_in.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_out(&self) {
        self.packets_out.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_probe(&self) {
        self.probes_sent.fetch_add(1, Ordering::Relaxed);
    }
}

/// Global metrics store keyed by client address.
pub struct MetricsStore {
    clients: DashMap<SocketAddr, ClientMetrics>,
    rate_limit_per_sec: u32,
    max_clients: usize,
}

impl MetricsStore {
    pub fn new(rate_limit_per_sec: u32) -> Self {
        Self {
            clients: DashMap::new(),
            rate_limit_per_sec,
            max_clients: 10000,
        }
    }

    /// Get or create metrics for a client.
    /// Returns `None` if the client limit has been reached and this is a new client.
    pub fn get_or_create(&self, addr: SocketAddr) -> Option<dashmap::mapref::one::Ref<'_, SocketAddr, ClientMetrics>> {
        // Fast path: already exists
        if let Some(r) = self.clients.get(&addr) {
            return Some(r);
        }
        // Check limit before inserting
        if self.clients.len() >= self.max_clients {
            return None;
        }
        self.clients
            .entry(addr)
            .or_insert_with(|| ClientMetrics::new(self.rate_limit_per_sec));
        self.clients.get(&addr)
    }

    /// Remove metrics for a client (called on session expiry).
    pub fn remove(&self, addr: &SocketAddr) {
        self.clients.remove(addr);
    }

    /// Number of tracked clients.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_allows_burst() {
        let m = ClientMetrics::new(3);
        assert!(m.try_acquire_probe());
        assert!(m.try_acquire_probe());
        assert!(m.try_acquire_probe());
        // 4th should be denied
        assert!(!m.try_acquire_probe());
    }

    #[test]
    fn rate_limit_refills_over_time() {
        let m = ClientMetrics::new(10);
        // Drain all tokens
        for _ in 0..10 {
            assert!(m.try_acquire_probe());
        }
        assert!(!m.try_acquire_probe());
        // Manually adjust the bucket time to simulate 1 second passing
        {
            let mut bucket = m.rate_tokens.lock().unwrap();
            bucket.last_refill = Instant::now() - std::time::Duration::from_secs(1);
        }
        // Now should have refilled
        assert!(m.try_acquire_probe());
    }

    #[test]
    fn packet_counters() {
        let m = ClientMetrics::new(5);
        m.record_in();
        m.record_in();
        m.record_out();
        m.record_probe();
        assert_eq!(m.packets_in.load(Ordering::Relaxed), 2);
        assert_eq!(m.packets_out.load(Ordering::Relaxed), 1);
        assert_eq!(m.probes_sent.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn metrics_store_get_or_create() {
        let store = MetricsStore::new(5);
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert!(store.is_empty());

        let m = store.get_or_create(addr).unwrap();
        m.record_in();
        drop(m);

        assert_eq!(store.len(), 1);
        let m = store.get_or_create(addr).unwrap();
        assert_eq!(m.packets_in.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn metrics_store_remove() {
        let store = MetricsStore::new(5);
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        store.get_or_create(addr);
        assert_eq!(store.len(), 1);
        store.remove(&addr);
        assert!(store.is_empty());
    }

    #[test]
    fn metrics_store_max_clients() {
        let mut store = MetricsStore::new(5);
        store.max_clients = 2;

        let a1: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let a2: SocketAddr = "127.0.0.1:1002".parse().unwrap();
        let a3: SocketAddr = "127.0.0.1:1003".parse().unwrap();

        assert!(store.get_or_create(a1).is_some());
        assert!(store.get_or_create(a2).is_some());
        // Third client should be rejected
        assert!(store.get_or_create(a3).is_none());
        assert_eq!(store.len(), 2);
    }
}
