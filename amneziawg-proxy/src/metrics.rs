use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use dashmap::DashMap;

/// Per-client metrics: packet counts and rate-limit state.
///
/// The token bucket uses lock-free atomics so it never blocks a Tokio
/// worker thread. Tokens and the last-refill timestamp are packed into a
/// single `AtomicU64` and updated via `compare_exchange`.
pub struct ClientMetrics {
    /// Total packets received from this client.
    pub packets_in: AtomicU64,
    /// Total packets sent to this client.
    pub packets_out: AtomicU64,
    /// Total probe responses sent to this client.
    pub probes_sent: AtomicU64,
    /// Packed token bucket state: high 32 bits = tokens × 1000 (fixed-point
    /// millitoken representation), low 32 bits = last-refill timestamp as
    /// seconds since an unspecified epoch obtained from `coarse_now_secs()`.
    rate_state: AtomicU64,
    max_tokens: u32,
    refill_rate: u32,
}

/// Cheap monotonic seconds counter.  Uses `Instant` under the hood but only
/// returns whole seconds, which is sufficient for the token-bucket granularity.
fn coarse_now_secs() -> u32 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_secs() as u32
}

/// Pack millitoken count and timestamp into a single u64.
fn pack(millitokens: u32, ts: u32) -> u64 {
    ((millitokens as u64) << 32) | (ts as u64)
}

/// Unpack millitoken count and timestamp from a u64.
fn unpack(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v as u32)
}

impl ClientMetrics {
    pub fn new(rate_limit_per_sec: u32) -> Self {
        let now = coarse_now_secs();
        let millitokens = rate_limit_per_sec.saturating_mul(1000);
        Self {
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            probes_sent: AtomicU64::new(0),
            rate_state: AtomicU64::new(pack(millitokens, now)),
            max_tokens: rate_limit_per_sec,
            refill_rate: rate_limit_per_sec,
        }
    }

    /// Try to consume one rate-limit token. Returns `true` if allowed.
    ///
    /// This is entirely lock-free: we CAS-loop on the packed atomic state
    /// so no `Mutex` is held across `.await` boundaries.
    pub fn try_acquire_probe(&self) -> bool {
        self.try_acquire_at(coarse_now_secs())
    }

    /// Core token-bucket CAS loop parameterised by `now` so that tests
    /// can simulate elapsed time without real sleeps.
    fn try_acquire_at(&self, now: u32) -> bool {
        loop {
            let old = self.rate_state.load(Ordering::Acquire);
            let (old_mt, old_ts) = unpack(old);

            // Refill: elapsed seconds × refill_rate × 1000 (millitoken)
            let elapsed = now.saturating_sub(old_ts);
            let refill = (elapsed as u64)
                .saturating_mul(self.refill_rate as u64)
                .saturating_mul(1000);
            let max_mt = self.max_tokens.saturating_mul(1000);
            let current_mt = std::cmp::min(
                (old_mt as u64).saturating_add(refill),
                max_mt as u64,
            ) as u32;

            if current_mt < 1000 {
                // Not enough for one full token — store refilled state and reject.
                let new = pack(current_mt, now);
                // Best-effort update; if another thread won the race we'll
                // recalculate on the next call.
                let _ = self.rate_state.compare_exchange(
                    old, new, Ordering::AcqRel, Ordering::Acquire,
                );
                return false;
            }

            let new_mt = current_mt - 1000;
            let new = pack(new_mt, now);
            if self.rate_state.compare_exchange(
                old, new, Ordering::AcqRel, Ordering::Acquire,
            ).is_ok() {
                return true;
            }
            // CAS failed — another thread modified state, retry.
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
    /// Atomic counter for the number of tracked clients, kept in sync with
    /// `clients.len()` so the capacity check in `get_or_create` is race-free.
    client_count: AtomicUsize,
}

impl MetricsStore {
    pub fn new(rate_limit_per_sec: u32) -> Self {
        Self {
            clients: DashMap::new(),
            rate_limit_per_sec,
            max_clients: 10000,
            client_count: AtomicUsize::new(0),
        }
    }

    /// Get or create metrics for a client.
    /// Returns `None` if the client limit has been reached and this is a new client.
    pub fn get_or_create(&self, addr: SocketAddr) -> Option<dashmap::mapref::one::Ref<'_, SocketAddr, ClientMetrics>> {
        // Fast path: already exists
        if let Some(r) = self.clients.get(&addr) {
            return Some(r);
        }
        // Atomically reserve a slot before inserting. If the counter is at or
        // above the limit, reject the new client without inserting.
        loop {
            let current = self.client_count.load(Ordering::Acquire);
            if current >= self.max_clients {
                return None;
            }
            // Try to increment; if another thread won the race, retry.
            if self.client_count.compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                break;
            }
        }
        // We've reserved a slot — insert if still absent, or undo if another
        // call already inserted the same addr concurrently.
        {
            let entry = self.clients.entry(addr);
            match entry {
                dashmap::mapref::entry::Entry::Occupied(_) => {
                    // Another task beat us to it; undo the counter bump.
                    self.client_count.fetch_sub(1, Ordering::AcqRel);
                }
                dashmap::mapref::entry::Entry::Vacant(v) => {
                    v.insert(ClientMetrics::new(self.rate_limit_per_sec));
                }
            }
        }
        self.clients.get(&addr)
    }

    /// Remove metrics for a client (called on session expiry).
    pub fn remove(&self, addr: &SocketAddr) {
        if self.clients.remove(addr).is_some() {
            self.client_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Number of tracked clients.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Override the maximum client count (for testing).
    #[cfg(test)]
    pub fn set_max_clients(&mut self, max: usize) {
        self.max_clients = max;
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

        // Simulate 2 seconds passing by calling try_acquire_at() with a
        // synthetic timestamp instead of sleeping for real wall-clock time.
        // This exercises the same CAS refill logic without the 1+ second
        // wall-clock delay.
        let future = coarse_now_secs() + 2;
        assert!(m.try_acquire_at(future));
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
        store.set_max_clients(2);

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
