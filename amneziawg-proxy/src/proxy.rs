use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::backend;
use crate::config::{AwgParams, ProxyConfig};
use crate::metrics::MetricsStore;
use crate::quic_handshake::{QuicHandshakeResponder, QuicResponse};
use crate::responder::{self, Protocol};
use crate::session::SessionTable;
use crate::transform;

/// A relay task handle paired with its generation, so stale tasks can't
/// accidentally remove a newer handle from the map.
struct RelayEntry {
    handle: tokio::task::JoinHandle<()>,
    generation: u64,
}

/// The main proxy runtime state.
pub struct Proxy {
    config: ProxyConfig,
    frontend: Arc<UdpSocket>,
    sessions: Arc<SessionTable>,
    metrics: Arc<MetricsStore>,
    fixed_protocol: Option<Protocol>,
    client_protocols: Arc<DashMap<SocketAddr, Protocol>>,
    awg_params: Option<Arc<AwgParams>>,
    dns_forward_enabled: bool,
    dns_upstream: Option<SocketAddr>,
    dns_upstream_timeout: Duration,
    quic_handshake: Option<Arc<Mutex<QuicHandshakeResponder>>>,
    shutdown: Arc<Notify>,
    /// Per-session relay task handles, keyed by client address.
    /// Each task awaits data from the session's backend socket and relays it
    /// back to the client — fully event-driven, no polling.
    relay_handles: Arc<DashMap<SocketAddr, RelayEntry>>,
    /// Monotonically increasing generation counter for relay tasks.
    relay_generation: AtomicU64,
}

impl Proxy {
    /// Create and bind a new proxy instance.
    pub async fn bind(config: ProxyConfig, awg_params: Option<AwgParams>) -> anyhow::Result<Self> {
        let listen_addr: SocketAddr = config.listen.parse()?;
        let backend_addr: SocketAddr = config.backend.parse()?;
        let frontend = Arc::new(UdpSocket::bind(listen_addr).await?);

        let fixed_protocol = match config.imitate_protocol.as_str() {
            "quic" => Some(Protocol::Quic),
            "dns" => Some(Protocol::Dns),
            "sip" => Some(Protocol::Sip),
            "auto" => None,
            _ => anyhow::bail!("unsupported protocol: {}", config.imitate_protocol),
        };

        let sessions = Arc::new(SessionTable::new(
            backend_addr,
            Duration::from_secs(config.session_ttl_secs),
            config.max_sessions,
        ));
        let metrics = Arc::new(MetricsStore::new(config.rate_limit_per_sec));
        let dns_upstream = if config.dns_forward_enabled {
            Some(config.dns_upstream.parse::<SocketAddr>()?)
        } else {
            None
        };
        let dns_forward_enabled = config.dns_forward_enabled;
        let dns_upstream_timeout = Duration::from_millis(config.dns_upstream_timeout_ms);
        let quic_handshake = if config.quic_handshake_enabled {
            Some(Arc::new(Mutex::new(QuicHandshakeResponder::new(
                &config.quic_certificate_domain,
            )?)))
        } else {
            None
        };

        info!(
            listen = %listen_addr,
            backend = %backend_addr,
            protocol = %config.imitate_protocol,
            session_ttl = config.session_ttl_secs,
            awg_params = awg_params.is_some(),
            "proxy initialized"
        );

        Ok(Self {
            config,
            frontend,
            sessions,
            metrics,
            fixed_protocol,
            client_protocols: Arc::new(DashMap::new()),
            awg_params: awg_params.map(Arc::new),
            dns_forward_enabled,
            dns_upstream,
            dns_upstream_timeout,
            quic_handshake,
            shutdown: Arc::new(Notify::new()),
            relay_handles: Arc::new(DashMap::new()),
            relay_generation: AtomicU64::new(0),
        })
    }

    /// Create from pre-existing components (useful for testing).
    pub fn from_parts(
        config: ProxyConfig,
        frontend: Arc<UdpSocket>,
        sessions: Arc<SessionTable>,
        metrics: Arc<MetricsStore>,
        protocol: Protocol,
        awg_params: Option<AwgParams>,
    ) -> Self {
        Self {
            config,
            frontend,
            sessions,
            metrics,
            fixed_protocol: Some(protocol),
            client_protocols: Arc::new(DashMap::new()),
            awg_params: awg_params.map(Arc::new),
            dns_forward_enabled: false,
            dns_upstream: None,
            dns_upstream_timeout: Duration::from_millis(1500),
            quic_handshake: None,
            shutdown: Arc::new(Notify::new()),
            relay_handles: Arc::new(DashMap::new()),
            relay_generation: AtomicU64::new(0),
        }
    }

    async fn send_quic_responses(&self, responses: Vec<QuicResponse>) {
        for response in responses {
            if let Err(e) = self.frontend.send_to(&response.payload, response.destination).await {
                warn!(
                    destination = %response.destination,
                    error = %e,
                    "failed to send QUIC handshake response"
                );
            } else if let Some(metrics) = self.metrics.get(&response.destination) {
                metrics.record_probe();
            }
        }
    }

    /// Get a handle to signal shutdown.
    pub fn shutdown_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown)
    }

    /// Returns the actual listen address (useful when bound to port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.frontend.local_addr()
    }

    /// Run the proxy until shutdown is signaled.
    pub async fn run(&self) -> anyhow::Result<()> {
        let cleanup_handle = self.spawn_cleanup_task();
        let mut quic_tick = self
            .quic_handshake
            .as_ref()
            .map(|_| time::interval(Duration::from_millis(50)));

        info!("proxy running");

        // Main receive loop.
        // Packets are processed inline to preserve ordering guarantees for
        // per-client session state. For the expected workload (single
        // backend on localhost), session creation and backend send are fast
        // enough that pipelining provides no measurable benefit while adding
        // complexity. If throughput becomes a concern under extreme load,
        // this can be changed to spawn per-packet tasks.
        let buffer_size = self.config.buffer_size.min(65_535);
        let mut buf = vec![0u8; buffer_size];

        loop {
            tokio::select! {
                result = self.frontend.recv_from(&mut buf) => {
                    match result {
                        Ok((n, client_addr)) => {
                            self.handle_client_packet(&buf[..n], client_addr).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "frontend recv error");
                        }
                    }
                }
                _ = self.shutdown.notified() => {
                    info!("shutdown signal received, stopping proxy");
                    break;
                }
                _ = async {
                    if let Some(interval) = quic_tick.as_mut() {
                        interval.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if self.quic_handshake.is_some() => {
                    if let Some(quic) = &self.quic_handshake {
                        let responses = {
                            let mut responder = quic.lock().await;
                            responder.handle_timeouts()
                        };
                        self.send_quic_responses(responses).await;
                    }
                }
            }
        }

        cleanup_handle.abort();
        // Abort all per-session relay tasks
        self.relay_handles.iter().for_each(|entry| {
            entry.value().handle.abort();
        });
        self.relay_handles.clear();
        info!("proxy stopped");
        Ok(())
    }

    /// Handle a packet received from a client.
    async fn handle_client_packet(&self, data: &[u8], client_addr: SocketAddr) {
        // Perform a single metrics lookup per client packet and reuse the
        // owned metrics handle for both accounting and probe-related rate
        // limiting across async boundaries.
        let metrics_ref = self.metrics.get_or_create(client_addr);

        if let Some(ref metrics) = metrics_ref {
            metrics.record_in();
        }

        // Check if this is a probe packet and respond if rate allows.
        // Only respond to probes that match the configured protocol so the
        // proxy does not appear to host multiple services on the same port.
        let mut probe_response: Option<bytes::Bytes> = None;
        if let Some(proto) = responder::detect_protocol(data) {
            let selected_proto = match self.fixed_protocol {
                Some(fixed) if proto == fixed => Some(fixed),
                Some(_) => None,
                None => Some(proto),
            };
            if let Some(proto) = selected_proto {
                self.client_protocols.insert(client_addr, proto);
                if let Some(ref metrics) = metrics_ref {
                    if proto == Protocol::Quic {
                        if let Some(quic) = &self.quic_handshake {
                            let (is_continuation, responses, probe_allowed) = {
                                let mut responder = quic.lock().await;
                                let continuation = responder.has_active_connection(client_addr);
                                let allowed = continuation || metrics.try_acquire_probe();
                                if !allowed {
                                    (continuation, Vec::new(), false)
                                } else {
                                    (
                                        continuation,
                                        responder.handle_datagram(client_addr, data),
                                        true,
                                    )
                                }
                            };

                            if is_continuation || !responses.is_empty() {
                                self.send_quic_responses(responses).await;
                            } else if !probe_allowed {
                                debug!(%client_addr, "probe rate limited");
                            } else {
                                debug!(%client_addr, "probe allowed but no QUIC response generated");
                            }

                            if probe_allowed && !is_continuation {
                                let fallback_needed = {
                                    let responder = quic.lock().await;
                                    !responder.has_active_connection(client_addr)
                                };
                                if fallback_needed {
                                    probe_response = Some(responder::generate_response(proto, data));
                                }
                            }
                        } else {
                            if metrics.try_acquire_probe() {
                                probe_response = Some(responder::generate_response(proto, data));
                            } else {
                                debug!(%client_addr, "probe rate limited");
                            }
                        }
                    } else if metrics.try_acquire_probe() {
                        if proto == Protocol::Dns && self.dns_forward_enabled {
                            probe_response = self.forward_dns_probe(data).await.or_else(|| {
                                Some(responder::generate_response(proto, data))
                            });
                        } else {
                            probe_response = Some(responder::generate_response(proto, data));
                        }
                    } else {
                        debug!(%client_addr, "probe rate limited");
                    }
                }
            }
        }

        // Send probe response (if any).
        if let Some(response) = probe_response {
            if let Err(e) = self.frontend.send_to(&response, client_addr).await {
                warn!(%client_addr, error = %e, "failed to send probe response");
            } else if let Some(ref metrics) = metrics_ref {
                metrics.record_probe();
            }
            debug!(%client_addr, "probe response sent");
        }

        // Forward to backend (and spawn relay task for new sessions)
        match self.sessions.get_or_create(client_addr).await {
            Ok((backend_sock, is_new)) => {
                if is_new {
                    self.spawn_session_relay(client_addr, Arc::clone(&backend_sock));
                }
                if let Err(e) = backend::forward_to_backend(&backend_sock, data).await {
                    warn!(%client_addr, error = %e, "failed to forward to backend");
                }
            }
            Err(e) => {
                error!(%client_addr, error = %e, "failed to create session");
                // Remove orphaned metrics entry — without a session, the
                // cleanup task will never expire this client's metrics.
                self.metrics.remove(&client_addr);
                self.client_protocols.remove(&client_addr);
            }
        }
    }

    async fn forward_dns_probe(&self, query: &[u8]) -> Option<bytes::Bytes> {
        let upstream = self.dns_upstream?;
        let bind_addr = if upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let sock = tokio::net::UdpSocket::bind(bind_addr).await.ok()?;
        if sock.send_to(query, upstream).await.is_err() {
            return None;
        }

        let mut buf = vec![0u8; 4096];
        let recv = tokio::time::timeout(self.dns_upstream_timeout, sock.recv_from(&mut buf)).await;
        let Ok(Ok((n, from))) = recv else {
            return None;
        };
        if from != upstream || n == 0 {
            return None;
        }

        Some(bytes::Bytes::copy_from_slice(&buf[..n]))
    }

    /// Spawn an event-driven relay task for a single session.
    ///
    /// The task awaits data from the backend socket and relays responses back to
    /// the client via the frontend socket. This is fully event-driven — no
    /// polling or per-tick allocation.
    fn spawn_session_relay(&self, client_addr: SocketAddr, backend_sock: Arc<UdpSocket>) {
        let frontend = Arc::clone(&self.frontend);
        let metrics = Arc::clone(&self.metrics);
        let sessions = Arc::clone(&self.sessions);
        let fixed_protocol = self.fixed_protocol;
        let client_protocols = Arc::clone(&self.client_protocols);
        let awg_params = self.awg_params.clone();
        // Size the per-session relay buffer from configured `buffer_size` so
        // backend datagrams are not silently truncated by `recv()`.
        const MAX_UDP_PAYLOAD_SIZE: usize = 65_535;
        let relay_buf_size = std::cmp::min(self.config.buffer_size, MAX_UDP_PAYLOAD_SIZE);
        let relay_handles = Arc::clone(&self.relay_handles);
        let generation = self.relay_generation.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; relay_buf_size];
            loop {
                match backend_sock.recv(&mut buf).await {
                    Ok(n) => {
                        // Apply padding transformation to outgoing packets.
                        // When AWG params are available, use per-type S-value
                        // padding based on H-range classification.
                        if let Some(ref params) = awg_params {
                            let protocol = client_protocols
                                .get(&client_addr)
                                .map(|p| *p)
                                .or(fixed_protocol)
                                .unwrap_or(Protocol::Quic);
                            transform::apply_awg_transform(
                                &mut buf[..n],
                                params,
                                protocol,
                            );
                        }

                        if let Some(m) = metrics.get_or_create(client_addr) {
                            m.record_out();
                        }

                        sessions.touch(&client_addr);

                        if let Err(e) =
                            backend::send_to_client(&frontend, client_addr, &buf[..n]).await
                        {
                            warn!(%client_addr, error = %e, "failed to relay to client");
                        }
                    }
                    Err(e) => {
                        warn!(%client_addr, error = %e, "relay recv error, removing session");
                        // Remove the session so the next client packet recreates it
                        // (and spawns a fresh relay).  Without this the session stays
                        // in the table (is_new=false), no new relay is spawned, and
                        // backend responses are silently black-holed until TTL cleanup.
                        sessions.remove(&client_addr);
                        client_protocols.remove(&client_addr);
                        metrics.remove(&client_addr);
                        break;
                    }
                }
            }
            // Only remove our own entry — if a newer relay was spawned for
            // the same client, its generation will differ and we must not
            // remove it.  This handles the case where this task exits after
            // a replacement relay has already been inserted: `remove_if`'s
            // predicate fails for the newer generation, preserving it.
            relay_handles.remove_if(&client_addr, |_, entry| entry.generation == generation);
        });

        // Abort any previously running relay task for this client before
        // inserting the new handle, so we don't leak orphaned tasks.
        if let Some((_, old_entry)) = self.relay_handles.remove(&client_addr) {
            old_entry.handle.abort();
        }
        self.relay_handles.insert(client_addr, RelayEntry { handle, generation });

        // If the task has already completed (e.g., due to an immediate recv error)
        // by the time we insert its handle, remove the stale entry to avoid
        // leaving a finished JoinHandle in the map.
        if let Some(entry_ref) = self.relay_handles.get(&client_addr) {
            if entry_ref.handle.is_finished() {
                drop(entry_ref);
                self.relay_handles.remove_if(&client_addr, |_, entry| entry.generation == generation);
            }
        }
    }

    /// Spawn a task that periodically cleans up expired sessions.
    fn spawn_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let sessions = Arc::clone(&self.sessions);
        let metrics = Arc::clone(&self.metrics);
        let client_protocols = Arc::clone(&self.client_protocols);
        let relay_handles = Arc::clone(&self.relay_handles);
        let interval = Duration::from_secs(self.config.cleanup_interval_secs);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // first tick is immediate, skip it
            loop {
                ticker.tick().await;
                let expired = sessions.cleanup_expired();
                for addr in &expired {
                    metrics.remove(addr);
                    client_protocols.remove(addr);
                    // Abort the relay task for the expired session
                    if let Some((_, entry)) = relay_handles.remove(addr) {
                        entry.handle.abort();
                    }
                }
                if !expired.is_empty() {
                    info!(count = expired.len(), "cleaned up expired sessions");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_bind_and_shutdown() {
        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: "127.0.0.1:19999".into(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec: 5,
            imitate_protocol: "quic".into(),
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            max_sessions: 1000,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, None).await.unwrap();
        let addr = proxy.local_addr().unwrap();
        assert_ne!(addr.port(), 0);

        let shutdown = proxy.shutdown_handle();

        let handle = tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Notify::notify_one() stores the permit, so the proxy will pick it
        // up on its first select! iteration even if the recv loop hasn't
        // started yet. No readiness probe needed for a pure bind+shutdown test.
        // Signal shutdown
        shutdown.notify_one();

        // Should complete
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("proxy did not shut down in time")
            .unwrap();
    }

    #[tokio::test]
    async fn proxy_handles_probe_and_forward() {
        // Set up a mock backend (echo server)
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec: 10,
            imitate_protocol: "quic".into(),
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            max_sessions: 1000,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, None).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let shutdown = proxy.shutdown_handle();

        let proxy_handle = tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Wait for proxy to become ready by using the actual QUIC probe as the
        // readiness signal — the proxy responds to QUIC probes directly, so we
        // retry until we get a version-negotiation response.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Minimal QUIC Initial-like probe:
        // - long header first byte + version (1)
        // - DCID length (4) + DCID bytes
        // - SCID length (0)
        let mut quic_pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01];
        quic_pkt.push(4);
        quic_pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        quic_pkt.push(0);

        let mut buf = [0u8; 4096];
        let mut got_probe_response = false;
        const MAX_RETRIES: u32 = 10;
        for attempt in 0..MAX_RETRIES {
            let _ = client.send_to(&quic_pkt, proxy_addr).await;
            match tokio::time::timeout(
                Duration::from_millis(200),
                client.recv_from(&mut buf),
            ).await {
                Ok(Ok((_n, from))) => {
                    assert_eq!(from, proxy_addr);
                    // Version negotiation starts with 0xC3 (preserving incoming type bits)
                    assert_eq!(buf[0], 0xC3);
                    got_probe_response = true;
                    break;
                }
                _ => {
                    if attempt + 1 == MAX_RETRIES {
                        panic!("proxy did not become ready after {MAX_RETRIES} retries");
                    }
                }
            }
        }
        assert!(got_probe_response, "should receive probe response");

        // Backend should also have received the forwarded packet
        // (may have received multiple copies from readiness retries — drain the
        // first one which matches our probe).
        let mut backend_buf = [0u8; 4096];
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            backend.recv_from(&mut backend_buf),
        )
        .await;
        assert!(result.is_ok(), "backend should receive the forwarded packet");
        let (n, _) = result.unwrap().unwrap();
        assert_eq!(&backend_buf[..n], &quic_pkt);

        shutdown.notify_one();
        // Await the proxy task to prevent leaked tasks / flaky CI.
        tokio::time::timeout(Duration::from_secs(5), proxy_handle)
            .await
            .expect("proxy should shut down within 5s")
            .unwrap();
    }

    #[tokio::test]
    async fn quic_fallback_probe_respects_rate_limit() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec: 1,
            imitate_protocol: "quic".into(),
            quic_handshake_enabled: true,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            max_sessions: 1000,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, None).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let mut quic_pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01];
        quic_pkt.push(4);
        quic_pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        quic_pkt.push(0);

        let mut buf = [0u8; 4096];

        proxy.handle_client_packet(&quic_pkt, client_addr).await;
        let (n, from) = tokio::time::timeout(
            Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await
        .expect("first probe should receive a response")
        .unwrap();
        assert!(n > 0);
        assert_eq!(from, proxy_addr);

        loop {
            match tokio::time::timeout(Duration::from_millis(20), client.recv_from(&mut buf)).await {
                Ok(Ok((extra_n, extra_from))) => {
                    assert!(extra_n > 0);
                    assert_eq!(extra_from, proxy_addr);
                }
                Ok(Err(e)) => panic!("unexpected recv_from error while draining responses: {e}"),
                Err(_) => break,
            }
        }

        proxy.handle_client_packet(&quic_pkt, client_addr).await;
        let second = tokio::time::timeout(
            Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(second.is_err(), "second probe should be rate limited");
    }
}
