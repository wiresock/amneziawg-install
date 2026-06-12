use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::Serialize;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex, Semaphore};
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::backend;
use crate::config::{AwgParams, ProxyConfig};
use crate::metrics::MetricsStore;
use crate::quic_handshake::{QuicHandshakeResponder, QuicResponse};
use crate::responder::{self, DnsEcho, Protocol, SipDialog, SipDialogStage};
use crate::session::SessionTable;
use crate::transform;

/// A relay task handle paired with its generation, so stale tasks can't
/// accidentally remove a newer handle from the map.
struct RelayEntry {
    handle: tokio::task::JoinHandle<()>,
    generation: u64,
}

struct SipDeferredEntry {
    handle: tokio::task::JoinHandle<()>,
    generation: u64,
}

fn sip_stage_after_immediate_response(
    current: SipDialogStage,
    stage_before_response: Option<SipDialogStage>,
    method: &str,
    responses_len: usize,
    sent_response_count: usize,
    sent_any_response: bool,
    sent_ringing: bool,
) -> SipDialogStage {
    if method == "INVITE" {
        match (stage_before_response.unwrap_or(current), current) {
            (
                SipDialogStage::Idle | SipDialogStage::Terminated,
                SipDialogStage::Idle | SipDialogStage::Terminated,
            ) if sent_any_response => SipDialogStage::Invited,
            (SipDialogStage::Invited, SipDialogStage::Invited) if sent_ringing => {
                SipDialogStage::Ringing
            }
            _ => current,
        }
    } else if method == "CANCEL" {
        responder::sip_next_stage(current, method)
    } else {
        let sent_all_responses = responses_len != 0 && sent_response_count == responses_len;
        if sent_all_responses || method == "ACK" {
            responder::sip_next_stage(current, method)
        } else {
            current
        }
    }
}

/// Handle for signalling proxy shutdown. Cloneable; [`shutdown`](Self::shutdown)
/// is idempotent and reliably wakes the run loop and every detached task,
/// because the underlying `watch` channel is level-triggered and broadcast.
#[derive(Clone)]
pub struct ShutdownHandle(watch::Sender<bool>);

impl ShutdownHandle {
    /// Signal all proxy tasks to shut down.
    pub fn shutdown(&self) {
        // `send_replace` (not `send`) so the value is stored even when there
        // are currently no receivers — e.g. shutdown signalled after `bind`
        // but before `run` has subscribed. The channel is level-triggered, so
        // a task that subscribes afterwards still observes the signal.
        let _ = self.0.send_replace(true);
    }

    /// Resolve once shutdown has been signalled (now or earlier), so a consumer
    /// can await shutdown via the same handle it uses to trigger it without
    /// reaching into `Proxy` internals. Level-triggered: returns immediately if
    /// shutdown was already signalled.
    pub async fn wait(&self) {
        let mut rx = self.0.subscribe();
        wait_for_shutdown(&mut rx).await;
    }
}

/// Resolve once shutdown has been signalled. `wait_for` inspects the current
/// value first, so a shutdown signalled before this receiver existed is still
/// observed; a dropped sender (all handles gone) is likewise treated as
/// shutdown.
async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|&signalled| signalled).await;
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
    /// Per-client SIP dialog state, maintained across INVITE/ACK/BYE.
    sip_dialogs: Arc<DashMap<SocketAddr, SipDialog>>,
    /// Most recent DNS query (TXID + QNAME + QTYPE) observed per client, so
    /// DNS cover-traffic responses can echo the request (see `transform`).
    dns_query_echo: Arc<DashMap<SocketAddr, DnsEcho>>,
    /// Broadcast shutdown signal. `watch` is level-triggered (a task that
    /// checks after the signal still observes it) and wakes *all* receivers,
    /// unlike the single-waiter `Notify` it replaced — which meant one
    /// `notify_one()` could be consumed by a detached task instead of the run
    /// loop, leaving shutdown unobserved by the rest.
    shutdown_tx: watch::Sender<bool>,
    /// Per-session relay task handles, keyed by client address.
    /// Each task awaits data from the session's backend socket and relays it
    /// back to the client — fully event-driven, no polling.
    relay_handles: Arc<DashMap<SocketAddr, RelayEntry>>,
    /// Deferred SIP dialog response tasks, keyed by client address.
    sip_deferred_handles: Arc<DashMap<SocketAddr, SipDeferredEntry>>,
    /// Monotonically increasing generation counter for relay tasks.
    relay_generation: AtomicU64,
    /// Monotonically increasing generation counter for deferred SIP tasks.
    sip_deferred_generation: AtomicU64,
    /// Bounds the number of concurrent in-flight DNS upstream forwards so a
    /// burst of DNS probes cannot amplify into an unbounded pile of detached
    /// tasks each holding an ephemeral socket open for up to
    /// `dns_upstream_timeout`. Probes that cannot get a permit fall back to the
    /// synthetic response instead of querying upstream.
    dns_forward_semaphore: Arc<Semaphore>,
}

/// Maximum concurrent in-flight DNS upstream forwards (see
/// [`Proxy::dns_forward_semaphore`]).
const MAX_INFLIGHT_DNS_FORWARDS: usize = 256;

#[derive(Debug, Serialize)]
struct ProxyStatusFile {
    schema_version: u32,
    generated_at_unix_ms: u64,
    proxy_listen_addr: String,
    proxy_listen_port: u16,
    target_addr: String,
    target_port: u16,
    imitate_protocol: String,
    session_ttl_secs: u64,
    sessions: Vec<ProxySessionStatus>,
}

#[derive(Debug, Serialize)]
struct ProxySessionStatus {
    remote_addr: String,
    remote_ip: String,
    remote_port: u16,
    local_proxy_addr: String,
    local_proxy_port: u16,
    target_addr: String,
    target_port: u16,
    backend_socket_addr: Option<String>,
    obfuscation_protocol: String,
    last_activity_unix_ms: u64,
    last_activity_ms_ago: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    probe_packets: u64,
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn build_proxy_status_snapshot(
    sessions: &SessionTable,
    metrics: &MetricsStore,
    protocols: &DashMap<SocketAddr, Protocol>,
    fixed_protocol: Option<Protocol>,
    listen_addr: SocketAddr,
    target_addr: &str,
    target_port: u16,
    imitate_protocol: &str,
    session_ttl_secs: u64,
) -> ProxyStatusFile {
    let generated_at_unix_ms = current_unix_millis();
    let session_now_ms = crate::session::now_millis();
    let mut active_sessions: Vec<ProxySessionStatus> = sessions
        .snapshots()
        .into_iter()
        .map(|session| {
            let last_activity_ms_ago = session_now_ms.saturating_sub(session.last_active_ms);
            let metric = metrics.get(&session.client_addr).map(|m| m.snapshot());
            // In auto mode a client with no detected cover protocol is plain
            // AWG pass-through (the relay applies no outbound transform), so
            // report "none" rather than echoing the configured mode string.
            let protocol = fixed_protocol
                .or_else(|| protocols.get(&session.client_addr).map(|p| *p))
                .map(|protocol| protocol.to_string())
                .unwrap_or_else(|| "none".to_string());
            let backend_socket_addr = session.backend_local_addr.map(|addr| addr.to_string());

            ProxySessionStatus {
                remote_addr: session.client_addr.to_string(),
                remote_ip: session.client_addr.ip().to_string(),
                remote_port: session.client_addr.port(),
                local_proxy_addr: listen_addr.to_string(),
                local_proxy_port: listen_addr.port(),
                target_addr: target_addr.to_string(),
                target_port,
                backend_socket_addr,
                obfuscation_protocol: protocol,
                last_activity_unix_ms: generated_at_unix_ms.saturating_sub(last_activity_ms_ago),
                last_activity_ms_ago,
                rx_packets: metric.map(|m| m.packets_in).unwrap_or(0),
                tx_packets: metric.map(|m| m.packets_out).unwrap_or(0),
                rx_bytes: metric.map(|m| m.bytes_in).unwrap_or(0),
                tx_bytes: metric.map(|m| m.bytes_out).unwrap_or(0),
                probe_packets: metric.map(|m| m.probes_sent).unwrap_or(0),
            }
        })
        .collect();

    active_sessions.sort_by(|a, b| a.remote_addr.cmp(&b.remote_addr));

    ProxyStatusFile {
        schema_version: 1,
        generated_at_unix_ms,
        proxy_listen_addr: listen_addr.to_string(),
        proxy_listen_port: listen_addr.port(),
        target_addr: target_addr.to_string(),
        target_port,
        imitate_protocol: imitate_protocol.to_string(),
        session_ttl_secs,
        sessions: active_sessions,
    }
}

async fn write_proxy_status_file(path: &Path, status: &ProxyStatusFile) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let json = serde_json::to_vec_pretty(status)?;
    let tmp_path = status_tmp_path(path);
    tokio::fs::write(&tmp_path, json).await?;
    rename_status_file(&tmp_path, path).await?;
    Ok(())
}

fn status_tmp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sessions.json");
    path.with_file_name(format!(
        ".{filename}.{}.{}.tmp",
        std::process::id(),
        counter
    ))
}

#[cfg(unix)]
async fn rename_status_file(tmp_path: &Path, path: &Path) -> anyhow::Result<()> {
    match tokio::fs::rename(tmp_path, path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = tokio::fs::remove_file(tmp_path).await;
            Err(e.into())
        }
    }
}

#[cfg(not(unix))]
async fn rename_status_file(tmp_path: &Path, path: &Path) -> anyhow::Result<()> {
    match tokio::fs::rename(tmp_path, path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = tokio::fs::remove_file(path).await;
            match tokio::fs::rename(tmp_path, path).await {
                Ok(()) => Ok(()),
                Err(e) => {
                    let _ = tokio::fs::remove_file(tmp_path).await;
                    Err(e.into())
                }
            }
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(tmp_path).await;
            Err(e.into())
        }
    }
}

impl Proxy {
    /// Create and bind a new proxy instance.
    pub async fn bind(config: ProxyConfig, awg_params: Option<AwgParams>) -> anyhow::Result<Self> {
        let listen_addr: SocketAddr = config.listen.parse()?;
        let backend_addr: SocketAddr = config.backend.parse()?;
        let frontend = UdpSocket::bind(listen_addr).await?;
        // Enlarge the frontend kernel buffers so bursts are absorbed instead of
        // dropped (in-proxy UDP loss looks like path loss and collapses TCP
        // throughput through the tunnel).
        backend::configure_socket_buffers(&frontend, config.socket_buffer_bytes);
        let frontend = Arc::new(frontend);

        let fixed_protocol = match config.imitate_protocol.as_str() {
            "quic" => Some(Protocol::Quic),
            "dns" => Some(Protocol::Dns),
            "stun" => Some(Protocol::Stun),
            "sip" => Some(Protocol::Sip),
            "auto" => None,
            _ => anyhow::bail!("unsupported protocol: {}", config.imitate_protocol),
        };

        let sessions = Arc::new(
            SessionTable::new(
                backend_addr,
                Duration::from_secs(config.session_ttl_secs),
                config.max_sessions,
            )
            .with_socket_buffer_bytes(config.socket_buffer_bytes),
        );
        let metrics = Arc::new(MetricsStore::new(
            config.rate_limit_per_sec,
            config.max_sessions,
        ));
        let dns_upstream = if config.dns_forward_enabled {
            Some(config.dns_upstream.parse::<SocketAddr>()?)
        } else {
            None
        };
        let dns_forward_enabled = config.dns_forward_enabled;
        let dns_upstream_timeout = Duration::from_millis(config.dns_upstream_timeout_ms);
        // Only build the (expensive, certificate-generating) QUIC handshake
        // responder when QUIC is actually a possible imitation target. In DNS,
        // STUN, or SIP fixed modes the responder is never consulted, and
        // constructing it would also schedule a 50 ms timer tick for nothing.
        let quic_possible = matches!(fixed_protocol, None | Some(Protocol::Quic));
        let quic_handshake = if config.quic_handshake_enabled && quic_possible {
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
            sip_dialogs: Arc::new(DashMap::new()),
            dns_query_echo: Arc::new(DashMap::new()),
            shutdown_tx: watch::channel(false).0,
            relay_handles: Arc::new(DashMap::new()),
            sip_deferred_handles: Arc::new(DashMap::new()),
            relay_generation: AtomicU64::new(0),
            sip_deferred_generation: AtomicU64::new(0),
            dns_forward_semaphore: Arc::new(Semaphore::new(MAX_INFLIGHT_DNS_FORWARDS)),
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
            sip_dialogs: Arc::new(DashMap::new()),
            dns_query_echo: Arc::new(DashMap::new()),
            shutdown_tx: watch::channel(false).0,
            relay_handles: Arc::new(DashMap::new()),
            sip_deferred_handles: Arc::new(DashMap::new()),
            relay_generation: AtomicU64::new(0),
            sip_deferred_generation: AtomicU64::new(0),
            dns_forward_semaphore: Arc::new(Semaphore::new(MAX_INFLIGHT_DNS_FORWARDS)),
        }
    }

    async fn send_quic_responses(&self, responses: Vec<QuicResponse>) {
        for response in responses {
            if let Err(e) = self
                .frontend
                .send_to(&response.payload, response.destination)
                .await
            {
                warn!(
                    destination = %response.destination,
                    error = %e,
                    "failed to send QUIC handshake response"
                );
            } else if let Some(metrics) = self.metrics.get(&response.destination) {
                metrics.record_probe_bytes(response.payload.len());
            }
        }
    }

    /// Get a handle to signal shutdown.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(self.shutdown_tx.clone())
    }

    /// Returns the actual listen address (useful when bound to port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.frontend.local_addr()
    }

    /// Run the proxy until shutdown is signaled.
    pub async fn run(&self) -> anyhow::Result<()> {
        let cleanup_handle = self.spawn_cleanup_task();
        let status_handle = self.spawn_status_writer();
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
        let mut shutdown_rx = self.shutdown_tx.subscribe();

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
                _ = wait_for_shutdown(&mut shutdown_rx) => {
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
        if let Some(handle) = status_handle {
            handle.abort();
        }
        // Abort all per-session relay tasks
        self.relay_handles.iter().for_each(|entry| {
            entry.value().handle.abort();
        });
        self.relay_handles.clear();
        self.sip_deferred_handles.iter().for_each(|entry| {
            entry.value().handle.abort();
        });
        self.sip_deferred_handles.clear();
        info!("proxy stopped");
        Ok(())
    }

    fn spawn_status_writer(&self) -> Option<tokio::task::JoinHandle<()>> {
        let path = PathBuf::from(self.config.status_file.clone());
        let interval = Duration::from_secs(self.config.status_interval_secs);
        let sessions = Arc::clone(&self.sessions);
        let metrics = Arc::clone(&self.metrics);
        let protocols = Arc::clone(&self.client_protocols);
        let fixed_protocol = self.fixed_protocol;
        let listen_addr = match self.frontend.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                warn!(error = %e, "failed to read proxy listener address for status file");
                match self.config.listen.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        warn!(error = %e, "failed to parse configured listen address for status file");
                        return None;
                    }
                }
            }
        };
        let target_addr = self.config.backend.clone();
        let target_port = self
            .config
            .backend
            .parse::<SocketAddr>()
            .map(|addr| addr.port())
            .unwrap_or(0);
        let imitate_protocol = self.config.imitate_protocol.clone();
        let session_ttl_secs = self.config.session_ttl_secs;
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        Some(tokio::spawn(async move {
            let mut ticker = time::interval(interval);
            ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let status = build_proxy_status_snapshot(
                            &sessions,
                            &metrics,
                            &protocols,
                            fixed_protocol,
                            listen_addr,
                            &target_addr,
                            target_port,
                            &imitate_protocol,
                            session_ttl_secs,
                        );
                        if let Err(e) = write_proxy_status_file(&path, &status).await {
                            warn!(path = %path.display(), error = %e, "failed to write proxy session status");
                        }
                    }
                    _ = wait_for_shutdown(&mut shutdown_rx) => {
                        break;
                    }
                }
            }
        }))
    }

    /// Handle a packet received from a client.
    async fn handle_client_packet(&self, data: &[u8], client_addr: SocketAddr) {
        // Perform a single metrics lookup per client packet and reuse the
        // owned metrics handle for both accounting and probe-related rate
        // limiting across async boundaries.
        let metrics_ref = self.metrics.get_or_create(client_addr);

        if let Some(ref metrics) = metrics_ref {
            metrics.record_in_bytes(data.len());
        }

        // When AWG params are available, check whether the incoming packet is
        // actually AWG data whose S-padding prefix happens to look like the
        // imitated protocol (e.g. WireSock `Ip=quic` rewrites the leading
        // S-bytes with a QUIC long-header prologue).  Such packets must be
        // forwarded as-is and never treated as external probes, otherwise the
        // QUIC handshake responder fires and sends back real QUIC frames that
        // the client tries — and fails — to decrypt as AWG.
        let is_awg_packet = self
            .awg_params
            .as_deref()
            .is_some_and(|p| responder::classify_awg_packet(data, p).is_some());

        if !is_awg_packet {
            self.handle_probe(data, client_addr, &metrics_ref).await;
        }

        // Remember this client's latest DNS query so the relay can echo its
        // QNAME/QTYPE/transaction ID in the cover-traffic responses. The client's
        // real traffic is AWG (the query lives in the S-padding prefix) and skips
        // `handle_probe`, so the capture must happen here on the data path, using
        // the same effective-protocol resolution the relay uses. `parse_dns_query_echo`
        // returns `None` for anything that is not a well-formed DNS query, so a
        // non-DNS prefix simply leaves the previous echo (if any) in place.
        // The DNS query echo is only consulted when DNS is the effective
        // protocol. In any fixed mode `client_protocols` is never populated
        // (it is written only in the auto-mode branch of `handle_probe`), so a
        // fixed non-DNS mode answers this statically without a per-packet
        // DashMap lookup; only auto mode pays for the lookup.
        let dns_active = match self.fixed_protocol {
            Some(p) => p == Protocol::Dns,
            None => self.client_protocols.get(&client_addr).map(|p| *p) == Some(Protocol::Dns),
        };
        if dns_active {
            if let Some(echo_ref) = responder::parse_dns_query_echo_ref(data) {
                // WireSock typically repeats the same imitated query, so the
                // echo is usually unchanged. Compare against the stored value
                // under a shared (read) guard first and only take the
                // write-lock + heap allocation when it actually differs.
                let unchanged = self
                    .dns_query_echo
                    .get(&client_addr)
                    .is_some_and(|e| e.matches(&echo_ref));
                if !unchanged {
                    self.dns_query_echo.insert(client_addr, echo_ref.into());
                }
            }
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
                self.sip_dialogs.remove(&client_addr);
                self.dns_query_echo.remove(&client_addr);
                if let Some((_, entry)) = self.sip_deferred_handles.remove(&client_addr) {
                    entry.handle.abort();
                }
            }
        }
    }

    /// Check whether `data` is an external probe and send an appropriate
    /// response if rate limits allow.
    ///
    /// Only responds to probes that match the configured protocol so the
    /// proxy does not appear to host multiple services on the same port.
    async fn handle_probe(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        metrics_ref: &Option<Arc<crate::metrics::ClientMetrics>>,
    ) {
        let mut probe_response: Option<bytes::Bytes> = None;

        if let Some(proto) = responder::detect_protocol(data) {
            // Whether this is the first detection for an auto-mode client and we
            // therefore need to record (write-lock) its protocol.  Avoided on
            // the hot path: established clients only take a shared read lock via
            // `get`, and fixed-protocol mode never writes the map at all (the
            // relay falls back to `fixed_protocol`).
            let mut insert_needed = false;
            let selected_proto = match self.fixed_protocol {
                Some(fixed) if proto == fixed => Some(fixed),
                Some(_) => None,
                // Auto mode: lock each client to the first protocol detected for
                // it.  Once a client's protocol is established, ignore probes
                // that detect as a *different* protocol so a single mis-detected
                // packet cannot switch an established session (e.g. answer a DNS
                // client with QUIC).  This is defense-in-depth alongside the
                // version validation in `detect_protocol`.
                None => match self.client_protocols.get(&client_addr).map(|p| *p) {
                    Some(locked) if locked != proto => None,
                    Some(_) => Some(proto),
                    None => {
                        insert_needed = true;
                        Some(proto)
                    }
                },
            };
            if let Some(proto) = selected_proto {
                if insert_needed {
                    self.client_protocols.insert(client_addr, proto);
                }
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
                                    probe_response = Some(responder::generate_response_for_client(
                                        proto,
                                        data,
                                        client_addr,
                                    ));
                                }
                            }
                        } else if metrics.try_acquire_probe() {
                            probe_response = Some(responder::generate_response_for_client(
                                proto,
                                data,
                                client_addr,
                            ));
                        } else {
                            debug!(%client_addr, "probe rate limited");
                        }
                    } else if proto == Protocol::Sip {
                        self.handle_sip_probe(data, client_addr, metrics_ref, false)
                            .await;
                    } else if metrics.try_acquire_probe() {
                        // Forward DNS probes to the upstream resolver off the
                        // hot path. Awaiting it here would stall the single
                        // receive loop for up to `dns_upstream_timeout` (default
                        // 1.5 s), blocking *all* clients' data forwarding on one
                        // probe. `try_spawn_dns_forward` returns `false` when no
                        // task was started (forwarding disabled, no upstream, or
                        // the in-flight cap is reached); in that case — and for
                        // non-DNS protocols — reply inline with the synthetic
                        // response so a probe burst never amplifies into
                        // unbounded task spawns.
                        let forwarded = proto == Protocol::Dns
                            && self.dns_forward_enabled
                            && self.try_spawn_dns_forward(data, client_addr, metrics);
                        if !forwarded {
                            probe_response = Some(responder::generate_response_for_client(
                                proto,
                                data,
                                client_addr,
                            ));
                        }
                    } else {
                        debug!(%client_addr, "probe rate limited");
                    }
                }
            }
        }

        if let Some(response) = probe_response {
            if let Err(e) = self.frontend.send_to(&response, client_addr).await {
                warn!(%client_addr, error = %e, "failed to send probe response");
            } else if let Some(ref metrics) = metrics_ref {
                metrics.record_probe_bytes(response.len());
            }
            debug!(%client_addr, "probe response sent");
        }
    }

    /// Handle a SIP probe using a per-client stateful dialog.
    ///
    /// Sequence for a well-behaved client:
    /// 1. `INVITE`  → `100 Trying` immediately; `180 Ringing` after ~200 ms;
    ///    `200 OK` after ~1 s (simulates answer).
    /// 2. `ACK`     → no response (call established).
    /// 3. `BYE`     → `200 OK` only once the dialog is established.
    /// 4. `CANCEL`  → `200 OK` immediately; plus `487 Request Terminated` when an INVITE is still in progress.
    /// REGISTER / OPTIONS / NOTIFY / SUBSCRIBE / MESSAGE / INFO each get a
    /// plain `200 OK` using whatever dialog state is available, or a bounded
    /// lightweight parse if no INVITE has been seen yet.
    async fn handle_sip_probe(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        metrics_ref: &Option<Arc<crate::metrics::ClientMetrics>>,
        mut pre_acquired_probe_token: bool,
    ) {
        let method = match responder::sip_method(data) {
            Some(m) => m.to_ascii_uppercase(),
            None => {
                let allowed = if pre_acquired_probe_token {
                    true
                } else {
                    metrics_ref
                        .as_ref()
                        .map_or(true, |metrics| metrics.try_acquire_probe())
                };
                if !allowed {
                    debug!(%client_addr, "SIP fallback response rate limited");
                    return;
                }

                let response =
                    responder::generate_response_for_client(Protocol::Sip, data, client_addr);
                match self.frontend.send_to(&response, client_addr).await {
                    Ok(_) => {
                        if let Some(metrics) = metrics_ref {
                            metrics.record_probe_bytes(response.len());
                        }
                    }
                    Err(e) => {
                        warn!(%client_addr, error = %e, "failed to send SIP fallback response")
                    }
                }
                return;
            }
        };

        let mut is_fresh_invite = false;
        let mut fresh_call_id: Option<String> = None;
        let mut stage_before_response: Option<SipDialogStage> = None;
        let mut use_stored_dialog = true;
        let mut request_dialog: Option<SipDialog> = None;

        // For a fresh INVITE, create (or reset) the dialog from the request.
        if method == "INVITE" {
            if let Some(dialog) = SipDialog::from_invite(data) {
                let existing = self
                    .sip_dialogs
                    .get(&client_addr)
                    .map(|d| (d.stage, d.call_id_value.clone()));
                let is_new_dialog = existing
                    .as_ref()
                    .map(|(stage, call_id_value)| {
                        matches!(stage, SipDialogStage::Terminated | SipDialogStage::Idle)
                            || call_id_value != &dialog.call_id_value
                    })
                    .unwrap_or(true);

                if is_new_dialog {
                    fresh_call_id = Some(dialog.call_id_value.clone());
                    self.sip_dialogs.insert(client_addr, dialog);
                    is_fresh_invite = true;
                } else {
                    // Retransmit for the active dialog — update transaction headers.
                    if let Some(mut d) = self.sip_dialogs.get_mut(&client_addr) {
                        d.update_request_headers(data);
                    }
                }
            } else {
                self.sip_dialogs.remove(&client_addr);
                use_stored_dialog = false;
            }
        } else {
            // For non-INVITE methods, only reuse the active dialog if the
            // incoming request belongs to the same Call-ID. Otherwise build a
            // bounded response from the request itself without mutating the
            // active dialog for a different call.
            let parsed_request = SipDialog::from_request(data);
            if let Some(mut d) = self.sip_dialogs.get_mut(&client_addr) {
                match parsed_request {
                    Some(dialog) if dialog.call_id_value == d.call_id_value => {
                        d.update_request_headers(data);
                    }
                    Some(dialog) => {
                        request_dialog = Some(dialog);
                        use_stored_dialog = false;
                    }
                    None => {
                        use_stored_dialog = false;
                    }
                }
            } else {
                request_dialog = parsed_request;
                use_stored_dialog = false;
            }
        }

        // Build and send immediate response(s)
        let responses: Vec<bytes::Bytes> = {
            if use_stored_dialog {
                if let Some(d) = self.sip_dialogs.get(&client_addr) {
                    stage_before_response = Some(d.stage);
                    responder::generate_sip_responses(&d, &method)
                } else {
                    Vec::new()
                }
            } else if let Some(dialog) = request_dialog.as_ref() {
                responder::generate_sip_responses(dialog, &method)
            } else {
                // No dialog state yet (e.g. OPTIONS before any INVITE). Try a
                // bounded header parse for standalone SIP methods that can receive
                // a 200 OK without dialog state. Malformed ACK/BYE/CANCEL have no
                // valid transaction headers to reflect, so stay silent instead of
                // falling back to the legacy INVITE-like 100 Trying path.
                match method.as_str() {
                    "ACK" | "BYE" | "CANCEL" => Vec::new(),
                    "REGISTER" | "OPTIONS" | "NOTIFY" | "SUBSCRIBE" | "MESSAGE" | "INFO" => {
                        SipDialog::from_request(data)
                            .map(|dialog| responder::generate_sip_responses(&dialog, &method))
                            .unwrap_or_default()
                    }
                    _ => vec![responder::generate_response_for_client(
                        Protocol::Sip,
                        data,
                        client_addr,
                    )],
                }
            }
        };

        let mut sent_any_response = false;
        let mut sent_response_count = 0usize;
        let mut sent_ringing = false;
        for pkt in &responses {
            let allowed = if pre_acquired_probe_token {
                pre_acquired_probe_token = false;
                true
            } else {
                metrics_ref
                    .as_ref()
                    .map_or(true, |metrics| metrics.try_acquire_probe())
            };
            if !allowed {
                debug!(%client_addr, method = %method, "SIP response rate limited");
                continue;
            }
            match self.frontend.send_to(pkt, client_addr).await {
                Ok(_) => {
                    if let Some(metrics) = metrics_ref {
                        metrics.record_probe_bytes(pkt.len());
                    }
                    sent_any_response = true;
                    sent_response_count += 1;
                    if pkt.starts_with(b"SIP/2.0 180 Ringing") {
                        sent_ringing = true;
                    }
                }
                Err(e) => warn!(%client_addr, error = %e, "failed to send SIP response"),
            }
        }

        // Advance the dialog stage
        if use_stored_dialog {
            if let Some(mut d) = self.sip_dialogs.get_mut(&client_addr) {
                d.stage = sip_stage_after_immediate_response(
                    d.stage,
                    stage_before_response,
                    &method,
                    responses.len(),
                    sent_response_count,
                    sent_any_response,
                    sent_ringing,
                );
            }
        }

        if is_fresh_invite && sent_any_response {
            let frontend = Arc::clone(&self.frontend);
            let dialogs = Arc::clone(&self.sip_dialogs);
            let metrics = metrics_ref.as_ref().map(Arc::clone);
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            let sip_deferred_handles = Arc::clone(&self.sip_deferred_handles);
            let generation = self.sip_deferred_generation.fetch_add(1, Ordering::Relaxed);
            let expected_call_id = match fresh_call_id {
                Some(call_id) => call_id,
                None => return,
            };

            let handle = tokio::spawn(async move {
                // 180 Ringing after 200 ms. Check the current stage at send
                // time so retransmits that already emitted 180 suppress this.
                tokio::select! {
                    _ = time::sleep(Duration::from_millis(200)) => {}
                    _ = wait_for_shutdown(&mut shutdown_rx) => {
                        sip_deferred_handles.remove_if(&client_addr, |_, entry| {
                            entry.generation == generation
                        });
                        return;
                    }
                }
                let ringing_allowed = metrics
                    .as_ref()
                    .map_or(true, |metrics| metrics.try_acquire_probe());
                if ringing_allowed {
                    let sent_len = dialogs.get_mut(&client_addr).and_then(|mut d| {
                        if d.stage != SipDialogStage::Invited || d.call_id_value != expected_call_id
                        {
                            return None;
                        }
                        let pkt = responder::generate_sip_ringing(&d);
                        let len = pkt.len();
                        match frontend.try_send_to(&pkt, client_addr) {
                            Ok(_) => {
                                d.stage = SipDialogStage::Ringing;
                                Some(len)
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                debug!(%client_addr, error = %e, "deferred SIP 180 Ringing send would block");
                                None
                            }
                            Err(e) => {
                                warn!(%client_addr, error = %e, "failed to send deferred SIP 180 Ringing");
                                None
                            }
                        }
                    });
                    if let Some(bytes) = sent_len {
                        if let Some(metrics) = metrics.as_ref() {
                            metrics.record_probe_bytes(bytes);
                        }
                    }
                } else {
                    debug!(%client_addr, "deferred SIP 180 Ringing rate limited");
                }

                // 200 OK after another 800 ms (total ~1 s). Use try_send_to
                // while holding the dialog guard so the final state check,
                // send, and Established transition happen without an await gap
                // where a CANCEL/BYE could terminate the dialog.
                tokio::select! {
                    _ = time::sleep(Duration::from_millis(800)) => {}
                    _ = wait_for_shutdown(&mut shutdown_rx) => {
                        sip_deferred_handles.remove_if(&client_addr, |_, entry| {
                            entry.generation == generation
                        });
                        return;
                    }
                }
                let ok_allowed = metrics
                    .as_ref()
                    .map_or(true, |metrics| metrics.try_acquire_probe());
                if ok_allowed {
                    let sent_len = dialogs.get_mut(&client_addr).and_then(|mut d| {
                        if !matches!(d.stage, SipDialogStage::Invited | SipDialogStage::Ringing)
                            || d.call_id_value != expected_call_id
                        {
                            return None;
                        }
                        let pkt = responder::generate_sip_ok(&d);
                        let len = pkt.len();
                        match frontend.try_send_to(&pkt, client_addr) {
                            Ok(_) => {
                                d.stage = SipDialogStage::Established;
                                Some(len)
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                debug!(%client_addr, error = %e, "deferred SIP 200 OK send would block");
                                None
                            }
                            Err(e) => {
                                warn!(%client_addr, error = %e, "failed to send deferred SIP 200 OK");
                                None
                            }
                        }
                    });
                    if let Some(bytes) = sent_len {
                        if let Some(metrics) = metrics.as_ref() {
                            metrics.record_probe_bytes(bytes);
                        }
                    }
                } else {
                    debug!(%client_addr, "deferred SIP 200 OK rate limited");
                }
                sip_deferred_handles
                    .remove_if(&client_addr, |_, entry| entry.generation == generation);
            });
            if let Some((_, old_entry)) = self.sip_deferred_handles.remove(&client_addr) {
                old_entry.handle.abort();
            }
            self.sip_deferred_handles
                .insert(client_addr, SipDeferredEntry { handle, generation });
            if let Some(entry) = self.sip_deferred_handles.get(&client_addr) {
                if entry.handle.is_finished() {
                    drop(entry);
                    self.sip_deferred_handles.remove_if(&client_addr, |_, e| {
                        e.generation == generation && e.handle.is_finished()
                    });
                }
            }
        }
    }

    /// Try to forward a DNS probe to the upstream resolver off the receive
    /// loop. Returns `true` when a detached forward task was started (it will
    /// deliver the upstream reply, or a synthetic fallback on timeout/error,
    /// and record the probe). Returns `false` when nothing was spawned — no
    /// upstream configured, or the in-flight forward cap is reached — so the
    /// caller replies inline with the synthetic response instead. Acquiring the
    /// concurrency permit *before* spawning bounds the number of detached tasks
    /// to the permit count, so a probe burst can't amplify into unbounded task
    /// spawns (only the upstream round-trips were bounded before).
    ///
    /// The probe rate-limit token is acquired by the caller; the spawned task
    /// only records the probe once a response is sent.
    fn try_spawn_dns_forward(
        &self,
        query: &[u8],
        client_addr: SocketAddr,
        metrics: &Arc<crate::metrics::ClientMetrics>,
    ) -> bool {
        let Some(upstream) = self.dns_upstream else {
            return false;
        };
        let Ok(permit) = Arc::clone(&self.dns_forward_semaphore).try_acquire_owned() else {
            return false;
        };
        let query = query.to_vec();
        let metrics = Arc::clone(metrics);
        let frontend = Arc::clone(&self.frontend);
        let timeout = self.dns_upstream_timeout;
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            // Hold the permit for the task's lifetime so the in-flight count
            // reflects active upstream round-trips.
            let _permit = permit;
            let response = tokio::select! {
                // Abandon the upstream round trip if the proxy is shutting
                // down, so a slow resolver cannot keep this detached task
                // (and a stray client send) alive past shutdown.
                r = forward_dns_query(upstream, &query, timeout) => {
                    r.unwrap_or_else(|| {
                        responder::generate_response_for_client(Protocol::Dns, &query, client_addr)
                    })
                }
                _ = wait_for_shutdown(&mut shutdown_rx) => return,
            };
            match frontend.send_to(&response, client_addr).await {
                Ok(_) => {
                    metrics.record_probe_bytes(response.len());
                    debug!(%client_addr, "DNS probe response sent");
                }
                Err(e) => warn!(%client_addr, error = %e, "failed to send DNS probe response"),
            }
        });
        true
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
        let sip_dialogs = Arc::clone(&self.sip_dialogs);
        let dns_query_echo = Arc::clone(&self.dns_query_echo);
        let sip_deferred_handles = Arc::clone(&self.sip_deferred_handles);
        let awg_params = self.awg_params.clone();
        // The relay buffer is resident memory per session, so it is sized
        // from `relay_buffer_size` (default 8 KiB — ample for any
        // internet-path tunnel MTU plus S-padding) rather than the 64 KiB
        // `buffer_size`; datagrams larger than this are truncated, and the
        // config documents when to raise it.
        const MAX_UDP_PAYLOAD_SIZE: usize = 65_535;
        let relay_buf_size = std::cmp::min(self.config.relay_buffer_size, MAX_UDP_PAYLOAD_SIZE);
        let relay_handles = Arc::clone(&self.relay_handles);
        let generation = self.relay_generation.fetch_add(1, Ordering::Relaxed);
        // Register this relay's generation on the session: expiry reports it,
        // and the cleanup sweep aborts only a generation-matched relay, so a
        // relay spawned for a re-created session can never be torn down by a
        // sweep that expired the *previous* session for this address.
        self.sessions.set_relay_generation(&client_addr, generation);
        // Cache this client's metrics handle once. The entry is created in
        // `handle_client_packet` before this relay is spawned and is removed
        // together with this task, so the `Arc` is stable for the session's
        // lifetime — caching it avoids a DashMap lookup + `Arc` clone on every
        // outbound packet.
        let client_metrics = self.metrics.get(&client_addr);

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; relay_buf_size];
            // Auto-mode protocol lock, cached once observed. The lock is
            // insert-once per client (`handle_probe` never overwrites an
            // existing entry, and removal only happens together with this
            // relay's teardown), so after the first hit the per-packet
            // DashMap lookup disappears from the outbound hot path.
            let mut locked_protocol: Option<Protocol> = None;
            loop {
                match backend_sock.recv(&mut buf).await {
                    Ok(n) => {
                        // Apply padding transformation to outgoing packets.
                        // When AWG params are available, use per-type S-value
                        // padding based on H-range classification.
                        // In "auto" mode (fixed_protocol is None) only transform
                        // when the client's protocol has actually been detected;
                        // without a detected protocol there is no basis for choosing
                        // a padding strategy, so the packet is forwarded as-is.
                        if let Some(ref params) = awg_params {
                            // In fixed mode the protocol is known statically and
                            // `client_protocols` is always empty, so skip the
                            // lookup entirely; in auto mode (late binding) look
                            // it up only until the lock is first observed.
                            let protocol = match (fixed_protocol, locked_protocol) {
                                (Some(p), _) => Some(p),
                                (None, Some(p)) => Some(p),
                                (None, None) => {
                                    locked_protocol =
                                        client_protocols.get(&client_addr).map(|p| *p);
                                    locked_protocol
                                }
                            };
                            if let Some(protocol) = protocol {
                                // The query echo only feeds DNS cover responses
                                // (other protocols ignore it), so skip the
                                // DashMap lookup entirely off the DNS path.
                                let echo = if protocol == Protocol::Dns {
                                    dns_query_echo.get(&client_addr)
                                } else {
                                    None
                                };
                                transform::apply_awg_transform(
                                    &mut buf[..n],
                                    params,
                                    protocol,
                                    echo.as_deref(),
                                );
                            }
                        }

                        if let Some(m) = &client_metrics {
                            m.record_out_bytes(n);
                        }

                        // Deliberately no session keep-alive here: only packets
                        // *from the client* refresh the TTL (in `get_or_create`).
                        // Backend→client traffic alone — e.g. AWG retrying
                        // handshakes toward a client that vanished while return
                        // traffic for its old flows still arrives — must not
                        // keep the session alive forever.
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
                        sip_dialogs.remove(&client_addr);
                        dns_query_echo.remove(&client_addr);
                        if let Some((_, entry)) = sip_deferred_handles.remove(&client_addr) {
                            entry.handle.abort();
                        }
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
        self.relay_handles
            .insert(client_addr, RelayEntry { handle, generation });
        // If the spawned task already finished before we inserted (e.g. the
        // backend socket immediately errored with ECONNREFUSED), its
        // `remove_if` cleanup ran before our insert, leaving a finished
        // handle in the map. Clean it up here so we don't leak the entry.
        if let Some(entry) = self.relay_handles.get(&client_addr) {
            if entry.handle.is_finished() {
                drop(entry);
                self.relay_handles.remove_if(&client_addr, |_, e| {
                    e.generation == generation && e.handle.is_finished()
                });
            }
        }
    }

    /// Spawn a task that periodically cleans up expired sessions.
    fn spawn_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let sessions = Arc::clone(&self.sessions);
        let metrics = Arc::clone(&self.metrics);
        let client_protocols = Arc::clone(&self.client_protocols);
        let sip_dialogs = Arc::clone(&self.sip_dialogs);
        let dns_query_echo = Arc::clone(&self.dns_query_echo);
        let relay_handles = Arc::clone(&self.relay_handles);
        let sip_deferred_handles = Arc::clone(&self.sip_deferred_handles);
        let interval = Duration::from_secs(self.config.cleanup_interval_secs);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // first tick is immediate, skip it
            let ctx = ClientTeardown {
                sessions: &sessions,
                metrics: &metrics,
                client_protocols: &client_protocols,
                sip_dialogs: &sip_dialogs,
                dns_query_echo: &dns_query_echo,
                relay_handles: &relay_handles,
                sip_deferred_handles: &sip_deferred_handles,
            };
            loop {
                ticker.tick().await;
                let expired = sessions.cleanup_expired();
                for (addr, relay_generation) in &expired {
                    teardown_expired_client(&ctx, addr, *relay_generation);
                }
                if !expired.is_empty() {
                    info!(count = expired.len(), "cleaned up expired sessions");
                }
            }
        })
    }
}

/// Borrowed handles to the per-client state maps, grouping what
/// [`teardown_expired_client`] needs so the teardown is a single testable
/// function rather than an inline body in the cleanup task.
struct ClientTeardown<'a> {
    sessions: &'a SessionTable,
    metrics: &'a MetricsStore,
    client_protocols: &'a DashMap<SocketAddr, Protocol>,
    sip_dialogs: &'a DashMap<SocketAddr, SipDialog>,
    dns_query_echo: &'a DashMap<SocketAddr, DnsEcho>,
    relay_handles: &'a DashMap<SocketAddr, RelayEntry>,
    sip_deferred_handles: &'a DashMap<SocketAddr, SipDeferredEntry>,
}

/// Tear down the state of `addr`'s expired session, whose relay generation
/// the expiry sweep reported as `relay_generation`.
///
/// The client may have come back between the sweep and this teardown,
/// re-creating a session for the same address; that session must come through
/// unharmed. Two guards ensure it:
/// - the relay is aborted only when its generation matches the expired
///   session's — a re-created session's relay carries a newer generation, and
///   aborting it would leave the new session permanently relay-less;
/// - the per-client auxiliary state (metrics, protocol lock, SIP dialog, DNS
///   echo, deferred SIP responses) is wiped only while no session exists for
///   the address, so a re-created session keeps its counters and protocol
///   lock consistent with the relay's cached handles. A re-creation racing
///   the wipe itself inherits (or transiently loses) per-address auxiliary
///   state — cosmetic at worst, and gone for good when that session in turn
///   expires — but it can never lose its relay.
fn teardown_expired_client(ctx: &ClientTeardown<'_>, addr: &SocketAddr, relay_generation: u64) {
    if let Some((_, entry)) = ctx
        .relay_handles
        .remove_if(addr, |_, e| e.generation == relay_generation)
    {
        entry.handle.abort();
    }
    if ctx.sessions.contains(addr) {
        return;
    }
    ctx.metrics.remove(addr);
    ctx.client_protocols.remove(addr);
    ctx.sip_dialogs.remove(addr);
    ctx.dns_query_echo.remove(addr);
    if let Some((_, entry)) = ctx.sip_deferred_handles.remove(addr) {
        entry.handle.abort();
    }
}

/// Send a DNS query to `upstream` on an ephemeral socket and return the reply,
/// or `None` on bind/send failure, timeout, or a response from an unexpected
/// source. Pure helper (no `self`) so it can run inside a detached task.
async fn forward_dns_query(
    upstream: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Option<bytes::Bytes> {
    let bind_addr = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let sock = tokio::net::UdpSocket::bind(bind_addr).await.ok()?;
    if sock.send_to(query, upstream).await.is_err() {
        return None;
    }

    let mut buf = [0u8; 4096];
    let recv = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await;
    let Ok(Ok((n, from))) = recv else {
        return None;
    };
    if from != upstream || n == 0 {
        return None;
    }

    Some(bytes::Bytes::copy_from_slice(&buf[..n]))
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.relay_handles.iter().for_each(|entry| {
            entry.value().handle.abort();
        });
        self.sip_deferred_handles.iter().for_each(|entry| {
            entry.value().handle.abort();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_invite_stage_update_does_not_regress_live_stage() {
        assert_eq!(
            sip_stage_after_immediate_response(
                SipDialogStage::Idle,
                Some(SipDialogStage::Idle),
                "INVITE",
                1,
                1,
                true,
                false,
            ),
            SipDialogStage::Invited
        );
        assert_eq!(
            sip_stage_after_immediate_response(
                SipDialogStage::Invited,
                Some(SipDialogStage::Invited),
                "INVITE",
                2,
                2,
                true,
                true,
            ),
            SipDialogStage::Ringing
        );
        assert_eq!(
            sip_stage_after_immediate_response(
                SipDialogStage::Ringing,
                Some(SipDialogStage::Idle),
                "INVITE",
                1,
                1,
                true,
                false,
            ),
            SipDialogStage::Ringing
        );
        assert_eq!(
            sip_stage_after_immediate_response(
                SipDialogStage::Established,
                Some(SipDialogStage::Invited),
                "INVITE",
                2,
                2,
                true,
                true,
            ),
            SipDialogStage::Established
        );
    }

    #[test]
    fn sip_cancel_stage_update_advances_on_cancel_receipt() {
        assert_eq!(
            sip_stage_after_immediate_response(
                SipDialogStage::Invited,
                Some(SipDialogStage::Invited),
                "CANCEL",
                2,
                1,
                true,
                false,
            ),
            SipDialogStage::Terminated
        );
        assert_eq!(
            sip_stage_after_immediate_response(
                SipDialogStage::Ringing,
                Some(SipDialogStage::Ringing),
                "CANCEL",
                2,
                1,
                true,
                false,
            ),
            SipDialogStage::Terminated
        );
        assert_eq!(
            sip_stage_after_immediate_response(
                SipDialogStage::Invited,
                Some(SipDialogStage::Invited),
                "CANCEL",
                2,
                0,
                false,
                false,
            ),
            SipDialogStage::Terminated
        );
    }

    #[tokio::test]
    async fn status_snapshot_reports_active_session() {
        let backend: SocketAddr = "127.0.0.1:51821".parse().unwrap();
        let sessions = SessionTable::new(backend, Duration::from_secs(300), 1000);
        let metrics = MetricsStore::new(16, 1000);
        let protocols = DashMap::new();
        let client: SocketAddr = "203.0.113.10:45678".parse().unwrap();

        sessions.get_or_create(client).await.unwrap();
        let client_metrics = metrics.get_or_create(client).unwrap();
        client_metrics.record_in_bytes(1200);
        client_metrics.record_out_bytes(800);
        client_metrics.record_probe();
        protocols.insert(client, Protocol::Dns);

        let status = build_proxy_status_snapshot(
            &sessions,
            &metrics,
            &protocols,
            None,
            "0.0.0.0:51820".parse().unwrap(),
            "127.0.0.1:51821",
            51821,
            "auto",
            300,
        );

        assert_eq!(status.schema_version, 1);
        assert_eq!(status.sessions.len(), 1);
        let session = &status.sessions[0];
        assert_eq!(session.remote_addr, "203.0.113.10:45678");
        assert_eq!(session.remote_ip, "203.0.113.10");
        assert_eq!(session.local_proxy_port, 51820);
        assert_eq!(session.target_port, 51821);
        assert_eq!(session.obfuscation_protocol, "dns");
        assert_eq!(session.rx_packets, 1);
        assert_eq!(session.tx_packets, 1);
        assert_eq!(session.rx_bytes, 1200);
        assert_eq!(session.tx_bytes, 800);
        assert_eq!(session.probe_packets, 1);
        assert!(session.backend_socket_addr.is_some());
    }

    #[tokio::test]
    async fn status_snapshot_reports_none_when_no_protocol_detected() {
        // Auto mode, client never sent recognisable cover traffic: the session
        // is plain AWG pass-through and must be reported as "none", not as the
        // configured mode string (and never as a junk-misdetected protocol).
        let backend: SocketAddr = "127.0.0.1:51821".parse().unwrap();
        let sessions = SessionTable::new(backend, Duration::from_secs(300), 1000);
        let metrics = MetricsStore::new(16, 1000);
        let protocols = DashMap::new();
        let client: SocketAddr = "203.0.113.10:45678".parse().unwrap();

        sessions.get_or_create(client).await.unwrap();
        metrics.get_or_create(client).unwrap();

        let status = build_proxy_status_snapshot(
            &sessions,
            &metrics,
            &protocols,
            None,
            "0.0.0.0:51820".parse().unwrap(),
            "127.0.0.1:51821",
            51821,
            "auto",
            300,
        );

        assert_eq!(status.imitate_protocol, "auto");
        assert_eq!(status.sessions.len(), 1);
        assert_eq!(status.sessions[0].obfuscation_protocol, "none");
    }

    #[tokio::test]
    async fn backend_traffic_does_not_keep_session_alive() {
        // Regression: a client vanished, but the backend (AWG) kept sending
        // toward its last endpoint — handshake initiations triggered by stale
        // return traffic for the client's old flows. The relayed backend→client
        // packets used to refresh the session TTL, so the session (and its
        // "active" row in the status file) lived forever. Only client packets
        // may keep a session alive.
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 1,
            cleanup_interval_secs: 3600, // swept manually below
            rate_limit_per_sec: 16,
            imitate_protocol: "auto".into(),
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, None).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // A single client packet creates the session and spawns the relay.
        proxy
            .handle_client_packet(b"hello backend", client_addr)
            .await;
        assert_eq!(proxy.sessions.len(), 1);

        // Learn the proxy's per-session backend socket from the forwarded packet.
        let mut buf = [0u8; 64];
        let (_, session_backend_addr) =
            tokio::time::timeout(Duration::from_millis(500), backend.recv_from(&mut buf))
                .await
                .expect("client packet must be forwarded to the backend")
                .unwrap();

        // The client stays silent while the backend keeps sending past the
        // 1 s TTL; each packet is relayed to the client.
        for _ in 0..6 {
            backend
                .send_to(b"backend says hi", session_backend_addr)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // Prove the relay actually delivered backend packets to the client —
        // without this the test would also pass with a dead relay, which is
        // not the scenario under test.
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
                .await
                .expect("relay must deliver backend packets to the client")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert_eq!(&buf[..n], b"backend says hi");

        // Despite the ongoing backend→client relay traffic, the client has
        // been silent for > TTL: the session must expire.
        let expired = proxy.sessions.cleanup_expired();
        let expired_addrs: Vec<SocketAddr> = expired.iter().map(|(addr, _)| *addr).collect();
        assert_eq!(
            expired_addrs,
            vec![client_addr],
            "session must expire after TTL of client silence"
        );
        assert!(proxy.sessions.is_empty());
    }

    #[tokio::test]
    async fn cleanup_spares_relay_of_recreated_session() {
        // Race regression (flagged in review): the client returns between the
        // expiry sweep (`cleanup_expired`) and the relay teardown that follows
        // it in `spawn_cleanup_task`. The teardown must abort only the relay
        // whose generation was reported by the sweep — aborting the re-created
        // session's fresh relay would leave that session permanently
        // relay-less, black-holing all backend responses for the client.
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 1,
            cleanup_interval_secs: 3600, // swept manually below
            rate_limit_per_sec: 16,
            imitate_protocol: "auto".into(),
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, None).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // First life: session + relay.
        proxy.handle_client_packet(b"first life", client_addr).await;
        let mut buf = [0u8; 2048];
        tokio::time::timeout(Duration::from_millis(500), backend.recv_from(&mut buf))
            .await
            .expect("first-life packet must be forwarded")
            .unwrap();

        // Client silent past the TTL: the sweep expires the session and
        // reports the generation of the relay that served it.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let expired = proxy.sessions.cleanup_expired();
        assert_eq!(expired.len(), 1);
        let (expired_addr, expired_generation) = expired[0];
        assert_eq!(expired_addr, client_addr);

        // Before the teardown step runs, the client comes back: same address,
        // new session, new relay with a newer generation.
        proxy
            .handle_client_packet(b"second life", client_addr)
            .await;
        let (_, session_backend_addr) =
            tokio::time::timeout(Duration::from_millis(500), backend.recv_from(&mut buf))
                .await
                .expect("second-life packet must be forwarded")
                .unwrap();
        // Give the re-created session some per-client state the teardown
        // must not destroy.
        proxy
            .client_protocols
            .insert(client_addr, responder::Protocol::Sip);

        // The teardown exactly as `spawn_cleanup_task` performs it, with the
        // stale generation from the sweep: it must spare the new relay and
        // the new session's per-client state.
        let ctx = ClientTeardown {
            sessions: &proxy.sessions,
            metrics: &proxy.metrics,
            client_protocols: &proxy.client_protocols,
            sip_dialogs: &proxy.sip_dialogs,
            dns_query_echo: &proxy.dns_query_echo,
            relay_handles: &proxy.relay_handles,
            sip_deferred_handles: &proxy.sip_deferred_handles,
        };
        teardown_expired_client(&ctx, &client_addr, expired_generation);

        assert!(
            proxy.sessions.contains(&client_addr),
            "re-created session must survive the stale teardown"
        );
        assert!(
            proxy.metrics.get(&client_addr).is_some(),
            "re-created session's metrics must survive (the relay caches this handle)"
        );
        assert_eq!(
            proxy.client_protocols.get(&client_addr).map(|p| *p),
            Some(responder::Protocol::Sip),
            "re-created session's protocol lock must survive"
        );

        // The re-created session's relay is alive: backend traffic still
        // reaches the client.
        backend
            .send_to(b"hello again", session_backend_addr)
            .await
            .unwrap();
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
                .await
                .expect("relay of the re-created session must still deliver")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert_eq!(&buf[..n], b"hello again");
    }

    #[tokio::test]
    async fn teardown_wipes_state_when_session_not_recreated() {
        // The normal expiry path: the client did not come back, so the
        // teardown must remove the relay and all per-client state.
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 1,
            cleanup_interval_secs: 3600, // swept manually below
            rate_limit_per_sec: 16,
            imitate_protocol: "auto".into(),
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, None).await.unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        proxy.handle_client_packet(b"only life", client_addr).await;
        proxy
            .client_protocols
            .insert(client_addr, responder::Protocol::Dns);

        tokio::time::sleep(Duration::from_millis(1100)).await;
        let expired = proxy.sessions.cleanup_expired();
        assert_eq!(expired.len(), 1);
        let (expired_addr, expired_generation) = expired[0];
        assert_eq!(expired_addr, client_addr);

        let ctx = ClientTeardown {
            sessions: &proxy.sessions,
            metrics: &proxy.metrics,
            client_protocols: &proxy.client_protocols,
            sip_dialogs: &proxy.sip_dialogs,
            dns_query_echo: &proxy.dns_query_echo,
            relay_handles: &proxy.relay_handles,
            sip_deferred_handles: &proxy.sip_deferred_handles,
        };
        teardown_expired_client(&ctx, &client_addr, expired_generation);

        assert!(proxy.sessions.is_empty());
        assert!(proxy.metrics.get(&client_addr).is_none(), "metrics wiped");
        assert!(
            proxy.client_protocols.get(&client_addr).is_none(),
            "protocol lock wiped"
        );
        assert!(
            !proxy.relay_handles.contains_key(&client_addr),
            "relay handle removed"
        );
    }

    #[tokio::test]
    async fn proxy_bind_and_shutdown() {
        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: "127.0.0.1:19999".into(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec: 16,
            imitate_protocol: "quic".into(),
            quic_handshake_enabled: true,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, None).await.unwrap();
        let addr = proxy.local_addr().unwrap();
        assert_ne!(addr.port(), 0);

        let shutdown = proxy.shutdown_handle();

        let handle = tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // The shutdown `watch` is level-triggered, so the proxy observes the
        // signal on its first select! iteration even if the recv loop hasn't
        // started yet (or had already started). No readiness probe needed for
        // a pure bind+shutdown test.
        shutdown.shutdown();

        // Should complete
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("proxy did not shut down in time")
            .unwrap();
    }

    /// Regression: with the previous single-waiter `Notify` + `notify_one()`,
    /// one `shutdown()` woke only one waiter — which could be a detached task
    /// rather than the run loop, leaving the proxy running. The broadcast
    /// `watch` must wake the run loop *and* every parked task from a single
    /// signal.
    #[tokio::test]
    async fn shutdown_wakes_run_loop_even_with_other_waiters_parked() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let upstream: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = dns_forward_config(backend_addr, upstream, 60_000);
        let proxy = Proxy::bind(config, None).await.unwrap();

        let shutdown = proxy.shutdown_handle();

        // Park several waiters on the shutdown signal, mimicking in-flight
        // detached DNS-forward / SIP-deferred tasks competing for the wake-up.
        let parked: Vec<_> = (0..8)
            .map(|_| {
                let h = shutdown.clone();
                tokio::spawn(async move { h.wait().await })
            })
            .collect();

        let run = tokio::spawn(async move { proxy.run().await.unwrap() });

        // Let the run loop and parked tasks register as waiters first.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.shutdown();

        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("run loop must observe shutdown despite other parked waiters")
            .unwrap();
        for p in parked {
            tokio::time::timeout(Duration::from_secs(1), p)
                .await
                .expect("each parked waiter must be woken by the broadcast")
                .unwrap();
        }
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
            rate_limit_per_sec: 16,
            imitate_protocol: "quic".into(),
            quic_handshake_enabled: false, // exercises the VN fallback path explicitly
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
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
            match tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await
            {
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
        let result =
            tokio::time::timeout(Duration::from_secs(2), backend.recv_from(&mut backend_buf)).await;
        assert!(
            result.is_ok(),
            "backend should receive the forwarded packet"
        );
        let (n, _) = result.unwrap().unwrap();
        assert_eq!(&backend_buf[..n], &quic_pkt);

        shutdown.shutdown();
        // Await the proxy task to prevent leaked tasks / flaky CI.
        tokio::time::timeout(Duration::from_secs(5), proxy_handle)
            .await
            .expect("proxy should shut down within 5s")
            .unwrap();
    }

    /// Build an AWG transport-data packet whose S4-padding prefix looks like a
    /// QUIC long-header Initial (mirroring what WireSock emits with `Ip=quic`).
    ///
    /// Layout: [S4 bytes of QUIC-like padding] ++ [H4 header LE u32] ++ [body]
    fn awg_quic_masked_transport_packet(params: &crate::config::AwgParams) -> Vec<u8> {
        let s4 = params.s4 as usize;
        let h4_value = params.h4.min;

        // S4 padding that passes detect_protocol's QUIC heuristic:
        //   byte 0: 0xC0 (long-header form + fixed bit, Initial type, PN len 0)
        //   bytes 1-4: 0x00000001 (QUIC v1)
        //   byte 5: DCID length = 8 (valid: 4..=20)
        //   bytes 6..14: DCID bytes
        //   byte 14: SCID length = 0
        //   bytes 15..: fill to reach s4
        let mut pkt = vec![0u8; s4];
        if s4 >= 1 {
            pkt[0] = 0xC0;
        }
        if s4 >= 5 {
            pkt[1] = 0x00;
            pkt[2] = 0x00;
            pkt[3] = 0x00;
            pkt[4] = 0x01;
        }
        if s4 >= 6 {
            pkt[5] = 8;
        }
        // bytes 6..14: DCID (arbitrary non-zero)
        for i in 6..std::cmp::min(14, s4) {
            pkt[i] = 0xAB;
        }
        if s4 > 14 {
            pkt[14] = 0;
        }
        // Append H4 header (LE u32) then body to meet TransportData minimum size.
        pkt.extend_from_slice(&h4_value.to_le_bytes());
        // Body: needs at least WG_TRANSPORT_DATA_MIN_SIZE (32) bytes after s4.
        pkt.extend(std::iter::repeat(0xBBu8).take(32));
        pkt
    }

    /// Build an AWG transport-data packet whose S4-padding prefix is a DNS query
    /// (mirroring what WireSock emits with `Ip=dns`): header + QNAME + QTYPE +
    /// QCLASS, zero-filled to S4, then the H4 header and body.
    fn awg_dns_masked_transport_packet(
        params: &crate::config::AwgParams,
        qname_wire: &[u8],
        qtype: [u8; 2],
        txid: [u8; 2],
    ) -> Vec<u8> {
        let s4 = params.s4 as usize;
        assert!(
            s4 >= 12 + qname_wire.len() + 4,
            "S4 too small for the query"
        );
        let mut pkt = vec![0u8; s4];
        pkt[0] = txid[0];
        pkt[1] = txid[1];
        pkt[2] = 0x01; // RD=1
        pkt[3] = 0x20; // AD=1
        pkt[4] = 0x00;
        pkt[5] = 0x01; // QDCOUNT=1
        let mut pos = 12;
        pkt[pos..pos + qname_wire.len()].copy_from_slice(qname_wire);
        pos += qname_wire.len();
        pkt[pos..pos + 2].copy_from_slice(&qtype);
        pos += 2;
        pkt[pos..pos + 2].copy_from_slice(&[0x00, 0x01]); // QCLASS IN
        pkt.extend_from_slice(&params.h4.min.to_le_bytes());
        pkt.extend(std::iter::repeat(0xBBu8).take(32));
        pkt
    }

    /// Regression test for the echo-capture path: the client's DNS query lives in
    /// the S-padding prefix of an AWG packet, which is classified as AWG and so
    /// skips `handle_probe`. The capture must therefore happen on the data path,
    /// otherwise responses never echo the query (root-label fallback only).
    #[tokio::test]
    async fn dns_echo_captured_from_awg_data_packet() {
        use crate::config::HRange;

        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let awg_params = crate::config::AwgParams {
            jc: 8,
            jmin: 50,
            jmax: 1000,
            s1: 72,
            s2: 142,
            s3: 59,
            s4: 40,
            h1: HRange {
                min: 102_875_432,
                max: 202_875_431,
            },
            h2: HRange {
                min: 728_639_326,
                max: 828_639_325,
            },
            h3: HRange {
                min: 1_469_276_895,
                max: 1_569_276_894,
            },
            h4: HRange {
                min: 2_037_058_179,
                max: 2_137_058_178,
            },
        };

        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec: 16,
            imitate_protocol: "dns".into(),
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, Some(awg_params.clone())).await.unwrap();
        let client_addr: SocketAddr = "127.0.0.1:55555".parse().unwrap();

        // QNAME wire bytes for "test.example".
        let qname = b"\x04test\x07example\x00";
        let pkt = awg_dns_masked_transport_packet(&awg_params, qname, [0x00, 0x01], [0x12, 0x34]);

        // Precondition: classified as AWG, so `handle_probe` is skipped.
        assert!(
            responder::classify_awg_packet(&pkt, &awg_params).is_some(),
            "packet must classify as AWG"
        );

        proxy.handle_client_packet(&pkt, client_addr).await;

        let echo = proxy
            .dns_query_echo
            .get(&client_addr)
            .map(|e| e.clone())
            .expect("echo must be captured from the AWG data packet");
        assert_eq!(echo.txid, [0x12, 0x34], "TXID captured");
        assert_eq!(echo.qname, qname.to_vec(), "QNAME captured");
        assert_eq!(echo.qtype, [0x00, 0x01], "QTYPE captured");
    }

    /// Minimal well-formed DNS query: 12-byte header (given TXID, RD=1,
    /// QDCOUNT=1) plus a single `example.com` IN A question. Accepted by
    /// `detect_protocol` as `Protocol::Dns`.
    fn dns_query(txid: [u8; 2]) -> Vec<u8> {
        let mut q = vec![
            txid[0], txid[1], // transaction ID
            0x01, 0x00, // flags: RD=1, QR=0
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        q.extend_from_slice(b"\x07example\x03com\x00"); // QNAME
        q.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        q
    }

    fn dns_forward_config(
        backend_addr: SocketAddr,
        upstream: SocketAddr,
        timeout_ms: u64,
    ) -> ProxyConfig {
        ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec: 16,
            imitate_protocol: "dns".into(),
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: true,
            dns_upstream: upstream.to_string(),
            dns_upstream_timeout_ms: timeout_ms,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        }
    }

    /// With `dns_forward_enabled`, an allowed DNS probe is forwarded to the
    /// upstream resolver and the resolver's reply is relayed back to the client
    /// verbatim (off the receive loop, via the detached `try_spawn_dns_forward`
    /// task).
    #[tokio::test]
    async fn dns_forward_relays_upstream_reply_to_client() {
        let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = resolver.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let config = dns_forward_config(backend_addr, upstream_addr, 1500);
        let proxy = Proxy::bind(config, None).await.unwrap();

        // Stand-in resolver: echo the query TXID with a distinctive payload so
        // the assertion can tell an upstream reply from the synthetic fallback.
        let upstream_reply = b"\x12\x34\x81\x80UPSTREAM-REPLY".to_vec();
        let reply = upstream_reply.clone();
        let resolver_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = resolver.recv_from(&mut buf).await.unwrap();
            assert!(n >= 12, "resolver received a DNS-sized query");
            resolver.send_to(&reply, from).await.unwrap();
        });

        let query = dns_query([0x12, 0x34]);
        let metrics = proxy.metrics.get_or_create(client_addr);
        proxy.handle_probe(&query, client_addr, &metrics).await;

        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("client should receive the forwarded upstream reply")
            .unwrap();
        assert_eq!(
            &buf[..n],
            upstream_reply.as_slice(),
            "client receives the upstream reply verbatim"
        );
        resolver_task.await.unwrap();
    }

    /// When the upstream resolver does not answer within the timeout, the
    /// detached task still delivers the synthetic fallback (SERVFAIL echoing
    /// the query TXID) so the probe is never left unanswered.
    #[tokio::test]
    async fn dns_forward_falls_back_to_synthetic_on_timeout() {
        // A bound-but-silent upstream: sends succeed, no reply ever arrives.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = silent.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let config = dns_forward_config(backend_addr, upstream_addr, 100);
        let proxy = Proxy::bind(config, None).await.unwrap();

        let query = dns_query([0xAB, 0xCD]);
        let metrics = proxy.metrics.get_or_create(client_addr);
        proxy.handle_probe(&query, client_addr, &metrics).await;

        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("client should receive the synthetic fallback after upstream timeout")
            .unwrap();
        assert!(n >= 12, "fallback is a DNS-sized message");
        assert_eq!(&buf[..2], &[0xAB, 0xCD], "fallback echoes the query TXID");
        assert_eq!(buf[2] & 0x80, 0x80, "fallback has QR=1 (a response)");
    }

    fn sip_test_config(backend_addr: SocketAddr) -> ProxyConfig {
        sip_test_config_with_rate(backend_addr, 16)
    }

    fn sip_test_config_with_rate(backend_addr: SocketAddr, rate_limit_per_sec: u32) -> ProxyConfig {
        ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec,
            imitate_protocol: "sip".into(),
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        }
    }

    #[tokio::test]
    async fn awg_packet_not_treated_as_probe() {
        use crate::config::HRange;

        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        // AWG params matching the user's config: S4=40, H4 range such that the
        // H4 header at offset 40 is unmistakably classified as TransportData.
        let awg_params = crate::config::AwgParams {
            jc: 8,
            jmin: 50,
            jmax: 1000,
            s1: 72,
            s2: 142,
            s3: 59,
            s4: 40,
            h1: HRange {
                min: 102_875_432,
                max: 202_875_431,
            },
            h2: HRange {
                min: 728_639_326,
                max: 828_639_325,
            },
            h3: HRange {
                min: 1_469_276_895,
                max: 1_569_276_894,
            },
            h4: HRange {
                min: 2_037_058_179,
                max: 2_137_058_178,
            },
        };

        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec: 16,
            imitate_protocol: "auto".into(),
            quic_handshake_enabled: true,
            quic_certificate_domain: "cloudflare.com".into(),
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, Some(awg_params.clone())).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Build a transport-data packet whose S4 prefix looks like QUIC.
        let pkt = awg_quic_masked_transport_packet(&awg_params);

        // Verify the packet is classified as AWG (precondition for the test).
        assert!(
            responder::classify_awg_packet(&pkt, &awg_params).is_some(),
            "test packet must be classified as AWG"
        );
        // And that it would fool detect_protocol into thinking it's QUIC
        // (this is exactly the bug scenario).
        assert_eq!(
            responder::detect_protocol(&pkt),
            Some(responder::Protocol::Quic),
            "test packet S4-prefix must look like QUIC to detect_protocol"
        );

        // Send the packet through handle_client_packet.
        proxy.handle_client_packet(&pkt, client_addr).await;

        // No probe response should arrive at the client socket.
        let mut buf = [0u8; 4096];
        let probe_response =
            tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut buf)).await;
        assert!(
            probe_response.is_err(),
            "AWG-classified packet must not produce a probe response (got one from {proxy_addr})"
        );

        // The packet must still be forwarded to the backend.
        let backend_recv =
            tokio::time::timeout(Duration::from_millis(500), backend.recv_from(&mut buf)).await;
        assert!(
            backend_recv.is_ok(),
            "AWG-classified packet must be forwarded to the backend"
        );
        let (n, _) = backend_recv.unwrap().unwrap();
        assert_eq!(&buf[..n], &pkt, "forwarded packet must be byte-identical");
    }

    #[tokio::test]
    async fn auto_mode_locks_client_to_first_detected_protocol() {
        // Regression: in auto mode the proxy must lock a client to the first
        // protocol detected for it.  A later packet that detects as a different
        // protocol must neither switch the stored protocol nor elicit a
        // mismatched probe response (e.g. a DNS client being answered with a
        // QUIC Version Negotiation packet).
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let config = ProxyConfig {
            listen: "127.0.0.1:0".into(),
            backend: backend_addr.to_string(),
            session_ttl_secs: 60,
            cleanup_interval_secs: 60,
            rate_limit_per_sec: 16,
            imitate_protocol: "auto".into(),
            // QUIC would use the easily-identifiable VN fallback if it fired.
            quic_handshake_enabled: false,
            quic_certificate_domain: "localhost".into(),
            // DNS probes get a locally-generated SERVFAIL response.
            dns_forward_enabled: false,
            dns_upstream: "127.0.0.1:53".into(),
            dns_upstream_timeout_ms: 1500,
            buffer_size: 4096,
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
            awg_config: None,
        };

        let proxy = Proxy::bind(config, None).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // (1) DNS probe locks the client to DNS and yields a SERVFAIL response.
        let dns_query = vec![
            0xAB, 0xCD, // transaction ID
            0x01, 0x00, // flags: standard query, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x00, // root-label QNAME
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];
        assert_eq!(
            responder::detect_protocol(&dns_query),
            Some(responder::Protocol::Dns),
            "precondition: first probe is detected as DNS"
        );
        proxy.handle_client_packet(&dns_query, client_addr).await;

        let mut buf = [0u8; 4096];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("DNS probe should receive a response")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(n >= 12, "DNS response must contain a header");
        assert_eq!(&buf[..2], &dns_query[..2], "must echo DNS transaction ID");
        assert_eq!(buf[2] & 0x80, 0x80, "DNS response must have QR=1");

        // The client is now locked to DNS.
        assert_eq!(
            proxy.client_protocols.get(&client_addr).map(|p| *p),
            Some(responder::Protocol::Dns),
            "client must be locked to DNS after the first probe"
        );

        // Drain the forwarded DNS probe from the backend.
        let _ = tokio::time::timeout(Duration::from_millis(200), backend.recv_from(&mut buf)).await;

        // (2) A QUIC-like probe from the SAME client must be ignored by the
        // probe responder and must not switch the stored protocol.
        let mut quic_pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01];
        quic_pkt.push(4);
        quic_pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        quic_pkt.push(0);
        assert_eq!(
            responder::detect_protocol(&quic_pkt),
            Some(responder::Protocol::Quic),
            "precondition: second probe is detected as QUIC"
        );
        proxy.handle_client_packet(&quic_pkt, client_addr).await;

        let mismatched =
            tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut buf)).await;
        assert!(
            mismatched.is_err(),
            "a DNS-locked client must not receive a QUIC probe response"
        );
        assert_eq!(
            proxy.client_protocols.get(&client_addr).map(|p| *p),
            Some(responder::Protocol::Dns),
            "mis-detected QUIC probe must not switch the locked protocol"
        );
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
            relay_buffer_size: 4096,
            max_sessions: 1000,
            socket_buffer_bytes: 0,
            status_file: "/tmp/amneziawg-proxy-sessions.json".into(),
            status_interval_secs: 5,
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
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("first probe should receive a response")
                .unwrap();
        assert!(n > 0);
        assert_eq!(from, proxy_addr);

        loop {
            match tokio::time::timeout(Duration::from_millis(20), client.recv_from(&mut buf)).await
            {
                Ok(Ok((extra_n, extra_from))) => {
                    assert!(extra_n > 0);
                    assert_eq!(extra_from, proxy_addr);
                }
                Ok(Err(e)) => panic!("unexpected recv_from error while draining responses: {e}"),
                Err(_) => break,
            }
        }

        proxy.handle_client_packet(&quic_pkt, client_addr).await;
        let second =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
        assert!(second.is_err(), "second probe should be rate limited");
    }

    #[tokio::test]
    async fn sip_options_without_dialog_returns_200_ok() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let options = b"OPTIONS sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: options-call@192.168.224.194\r\n\
CSeq: 95930 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(options, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("OPTIONS should receive a SIP response")
                .unwrap();
        assert_eq!(from, proxy_addr);
        let text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(text.contains("CSeq: 95930 OPTIONS"));
        assert_eq!(
            metrics_ref
                .unwrap()
                .probes_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn sip_response_line_probe_gets_stateless_response() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let response_probe = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKresponse;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>;tag=remote\r\n\
Call-ID: response-line-probe@192.168.224.194\r\n\
CSeq: 95930 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_probe(
                response_probe,
                client_addr,
                &proxy.metrics.get_or_create(client_addr),
            )
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("SIP response-line probe should receive stateless fallback")
                .unwrap();
        assert_eq!(from, proxy_addr);
        let text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.starts_with("SIP/2.0 100 Trying\r\n"));
        assert!(text.contains("Call-ID: response-line-probe@192.168.224.194"));
        assert!(text.contains("CSeq: 95930 INVITE"));
    }

    #[tokio::test]
    async fn sip_invite_retransmit_suppresses_deferred_duplicate_ringing() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: retransmit-call@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("fresh INVITE should receive 100 Trying")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 100 Trying\r\n"));

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut statuses = Vec::new();
        for _ in 0..2 {
            let (n, from) =
                tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                    .await
                    .expect("retransmitted INVITE should receive immediate responses")
                    .unwrap();
            assert_eq!(from, proxy_addr);
            statuses.push(
                std::str::from_utf8(&buf[..n])
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap()
                    .to_string(),
            );
        }
        assert!(statuses.iter().any(|s| s == "SIP/2.0 100 Trying"));
        assert!(statuses.iter().any(|s| s == "SIP/2.0 180 Ringing"));

        let duplicate =
            tokio::time::timeout(Duration::from_millis(350), client.recv_from(&mut buf)).await;
        assert!(
            duplicate.is_err(),
            "deferred timer must not emit a second 180 after retransmit"
        );
    }

    #[tokio::test]
    async fn sip_invite_with_new_call_id_replaces_active_dialog() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let old_invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKold;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=old\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: old-active-call@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let new_invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKnew;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=new\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: new-active-call@192.168.224.194\r\n\
CSeq: 95930 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(old_invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("old INVITE should receive 100 Trying")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("Call-ID: old-active-call@192.168.224.194"));

        proxy
            .handle_sip_probe(new_invite, client_addr, &metrics_ref, true)
            .await;

        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("new INVITE should receive response from new dialog")
                .unwrap();
        assert_eq!(from, proxy_addr);
        let text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.contains("Call-ID: new-active-call@192.168.224.194"));
        assert!(!text.contains("old-active-call@192.168.224.194"));
        assert_eq!(
            proxy
                .sip_dialogs
                .get(&client_addr)
                .map(|d| d.call_id.clone())
                .as_deref(),
            Some("Call-ID: new-active-call@192.168.224.194")
        );
    }

    #[tokio::test]
    async fn sip_invite_same_call_id_value_is_retransmit() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKfirst;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=first\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: same-active-call@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let retransmit = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKretransmit;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=first\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
CALL-ID:    same-active-call@192.168.224.194   \r\n\
CSeq: 95930 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("fresh INVITE should receive response")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 100 Trying\r\n"));

        proxy
            .handle_sip_probe(retransmit, client_addr, &metrics_ref, true)
            .await;

        let mut statuses = Vec::new();
        let mut saw_retransmit_via = false;
        for _ in 0..2 {
            let (n, from) =
                tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                    .await
                    .expect("same Call-ID value should be treated as retransmit")
                    .unwrap();
            assert_eq!(from, proxy_addr);
            let text = std::str::from_utf8(&buf[..n]).unwrap();
            statuses.push(text.lines().next().unwrap().to_string());
            saw_retransmit_via |= text.contains("branch=z9hG4bKretransmit");
            assert!(text.contains("Call-ID: same-active-call@192.168.224.194"));
            assert!(!text.contains("CALL-ID:"));
        }

        assert!(statuses.iter().any(|s| s == "SIP/2.0 100 Trying"));
        assert!(statuses.iter().any(|s| s == "SIP/2.0 180 Ringing"));
        assert!(saw_retransmit_via);
        assert_eq!(
            proxy
                .sip_dialogs
                .get(&client_addr)
                .map(|d| d.call_id_value.clone())
                .as_deref(),
            Some("same-active-call@192.168.224.194")
        );
    }

    #[tokio::test]
    async fn sip_non_invite_different_call_id_does_not_reuse_active_dialog() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKactive;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=active\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: active-call@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let options = b"OPTIONS sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKother;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=other\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: other-call@192.168.224.194\r\n\
CSeq: 95930 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
        let mut active_dialog = SipDialog::from_invite(invite).unwrap();
        active_dialog.stage = SipDialogStage::Established;
        proxy.sip_dialogs.insert(client_addr, active_dialog);

        proxy
            .handle_sip_probe(options, client_addr, &metrics_ref, false)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("mismatched OPTIONS should receive request-scoped response")
                .unwrap();
        assert_eq!(from, proxy_addr);
        let text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(text.contains("Call-ID: other-call@192.168.224.194"));
        assert!(!text.contains("active-call@192.168.224.194"));
        assert_eq!(
            proxy
                .sip_dialogs
                .get(&client_addr)
                .map(|d| (d.call_id_value.clone(), d.stage)),
            Some((
                "active-call@192.168.224.194".to_string(),
                SipDialogStage::Established
            ))
        );
    }

    #[tokio::test]
    async fn sip_immediate_responses_consume_rate_limit_per_packet() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config_with_rate(backend_addr, 1), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let metrics = metrics_ref.as_ref().unwrap();
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: rate-limited-retransmit@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let mut dialog = SipDialog::from_invite(invite).unwrap();
        dialog.stage = SipDialogStage::Invited;
        proxy.sip_dialogs.insert(client_addr, dialog);
        assert!(
            metrics.try_acquire_probe(),
            "pre-acquire inbound probe token"
        );

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("pre-acquired token should allow first response")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 100 Trying\r\n"));
        let second =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
        assert!(
            second.is_err(),
            "second immediate SIP response must require another rate token"
        );
    }

    #[tokio::test]
    async fn sip_ack_without_response_does_not_consume_probe_token() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config_with_rate(backend_addr, 1), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let ack = b"ACK sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKack;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: ack-no-response@192.168.224.194\r\n\
CSeq: 95929 ACK\r\n\
Content-Length: 0\r\n\r\n";
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKinvite;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: ack-no-response@192.168.224.194\r\n\
CSeq: 95930 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_probe(ack, client_addr, &proxy.metrics.get_or_create(client_addr))
            .await;

        let mut buf = [0u8; 1024];
        let ack_response =
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf)).await;
        assert!(
            ack_response.is_err(),
            "ACK without dialog should not emit a response"
        );

        proxy
            .handle_probe(
                invite,
                client_addr,
                &proxy.metrics.get_or_create(client_addr),
            )
            .await;

        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("INVITE should still have the only rate token available")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 100 Trying\r\n"));
    }

    #[tokio::test]
    async fn malformed_bye_cancel_without_dialog_do_not_fallback_to_trying() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config_with_rate(backend_addr, 2), None)
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let mut buf = [0u8; 1024];

        for request in [
            b"BYE sip:olivia@profi.ru SIP/2.0\r\nCall-ID: missing-headers\r\n\r\n".as_slice(),
            b"CANCEL sip:olivia@profi.ru SIP/2.0\r\nCall-ID: missing-headers\r\n\r\n".as_slice(),
        ] {
            proxy.handle_probe(request, client_addr, &metrics_ref).await;
            let response =
                tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf)).await;
            assert!(
                response.is_err(),
                "malformed standalone BYE/CANCEL must not receive stateless 100 Trying"
            );
        }
    }

    #[tokio::test]
    async fn malformed_standalone_methods_do_not_fallback_to_trying() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config_with_rate(backend_addr, 2), None)
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let mut buf = [0u8; 1024];

        for request in [
            b"OPTIONS sip:olivia@profi.ru SIP/2.0\r\nCall-ID: missing-headers\r\n\r\n".as_slice(),
            b"REGISTER sip:olivia@profi.ru SIP/2.0\r\nCall-ID: missing-headers\r\n\r\n".as_slice(),
        ] {
            proxy.handle_probe(request, client_addr, &metrics_ref).await;
            let response =
                tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf)).await;
            assert!(
                response.is_err(),
                "malformed standalone requests must not receive stateless 100 Trying"
            );
        }
    }

    #[tokio::test]
    async fn sip_non_invite_does_not_advance_when_response_suppressed() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config_with_rate(backend_addr, 0), None)
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKinvite;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: rate-limited-bye@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let bye = b"BYE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKbye;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: rate-limited-bye@192.168.224.194\r\n\
CSeq: 95930 BYE\r\n\
Content-Length: 0\r\n\r\n";
        let mut dialog = SipDialog::from_invite(invite).unwrap();
        dialog.stage = SipDialogStage::Established;
        proxy.sip_dialogs.insert(client_addr, dialog);

        proxy
            .handle_sip_probe(bye, client_addr, &metrics_ref, false)
            .await;

        let mut buf = [0u8; 1024];
        let response =
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf)).await;
        assert!(response.is_err(), "rate-limited BYE should not emit 200 OK");
        assert_eq!(
            proxy.sip_dialogs.get(&client_addr).map(|d| d.stage),
            Some(SipDialogStage::Established)
        );
    }

    #[tokio::test]
    async fn sip_cancel_advances_when_487_is_rate_limited() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config_with_rate(backend_addr, 1), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKinvite;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: rate-limited-cancel@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let cancel = b"CANCEL sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKcancel;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: rate-limited-cancel@192.168.224.194\r\n\
CSeq: 95930 CANCEL\r\n\
Content-Length: 0\r\n\r\n";
        let mut dialog = SipDialog::from_invite(invite).unwrap();
        dialog.stage = SipDialogStage::Invited;
        proxy.sip_dialogs.insert(client_addr, dialog);

        proxy
            .handle_sip_probe(cancel, client_addr, &metrics_ref, false)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("first CANCEL response should use the only available token")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 200 OK\r\n"));

        let second =
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf)).await;
        assert!(second.is_err(), "487 should be suppressed by rate limit");
        assert_eq!(
            proxy.sip_dialogs.get(&client_addr).map(|d| d.stage),
            Some(SipDialogStage::Terminated)
        );
    }

    #[tokio::test]
    async fn sip_cancel_before_answer_suppresses_deferred_invite_ok() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKinvite;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: cancel-before-answer@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let cancel = b"CANCEL sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKcancel;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: cancel-before-answer@192.168.224.194\r\n\
CSeq: 95930 CANCEL\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("INVITE should receive immediate 100 Trying")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 100 Trying\r\n"));

        let (n, from) =
            tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
                .await
                .expect("INVITE should receive deferred 180 Ringing")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 180 Ringing\r\n"));

        proxy
            .handle_sip_probe(cancel, client_addr, &metrics_ref, false)
            .await;

        let mut cancel_responses = Vec::new();
        for _ in 0..2 {
            let (n, from) =
                tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                    .await
                    .expect("CANCEL should receive both immediate responses")
                    .unwrap();
            assert_eq!(from, proxy_addr);
            cancel_responses.push(std::str::from_utf8(&buf[..n]).unwrap().to_string());
        }
        assert!(cancel_responses
            .iter()
            .any(|s| s.starts_with("SIP/2.0 200 OK\r\n") && s.contains("CSeq: 95930 CANCEL")));
        assert!(cancel_responses
            .iter()
            .any(|s| s.starts_with("SIP/2.0 487 Request Terminated\r\n")));

        let late =
            tokio::time::timeout(Duration::from_millis(900), client.recv_from(&mut buf)).await;
        assert!(
            late.is_err(),
            "deferred INVITE 200 OK must not be sent after CANCEL"
        );
        assert_eq!(
            proxy.sip_dialogs.get(&client_addr).map(|d| d.stage),
            Some(SipDialogStage::Terminated)
        );
    }

    #[tokio::test]
    async fn sip_cancel_before_ringing_suppresses_deferred_ringing() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKinvite;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: cancel-before-ringing@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let cancel = b"CANCEL sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKcancel;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: cancel-before-ringing@192.168.224.194\r\n\
CSeq: 95930 CANCEL\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("INVITE should receive immediate 100 Trying")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 100 Trying\r\n"));

        proxy
            .handle_sip_probe(cancel, client_addr, &metrics_ref, false)
            .await;

        let mut cancel_responses = Vec::new();
        for _ in 0..2 {
            let (n, from) =
                tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                    .await
                    .expect("CANCEL should receive both immediate responses")
                    .unwrap();
            assert_eq!(from, proxy_addr);
            cancel_responses.push(std::str::from_utf8(&buf[..n]).unwrap().to_string());
        }
        assert!(cancel_responses
            .iter()
            .all(|s| !s.starts_with("SIP/2.0 180 Ringing\r\n")));

        let late =
            tokio::time::timeout(Duration::from_millis(350), client.recv_from(&mut buf)).await;
        assert!(
            late.is_err(),
            "deferred 180/200 must not be sent after early CANCEL"
        );
    }

    #[tokio::test]
    async fn sip_deferred_task_removes_finished_handle() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKcleanup;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: cleanup-deferred@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        for expected in [
            "SIP/2.0 100 Trying\r\n",
            "SIP/2.0 180 Ringing\r\n",
            "SIP/2.0 200 OK\r\n",
        ] {
            let (n, _) =
                tokio::time::timeout(Duration::from_millis(1200), client.recv_from(&mut buf))
                    .await
                    .expect("expected SIP response")
                    .unwrap();
            assert!(std::str::from_utf8(&buf[..n])
                .unwrap()
                .starts_with(expected));
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !proxy.sip_deferred_handles.contains_key(&client_addr),
            "finished deferred SIP task should remove its handle"
        );
    }

    #[tokio::test]
    async fn sip_deferred_task_stops_on_shutdown() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKshutdown;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: shutdown-deferred@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("INVITE should receive immediate 100 Trying")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 100 Trying\r\n"));

        proxy.shutdown_handle().shutdown();

        let deferred =
            tokio::time::timeout(Duration::from_millis(350), client.recv_from(&mut buf)).await;
        assert!(
            deferred.is_err(),
            "shutdown should suppress deferred SIP 180/200 responses"
        );
        assert!(
            !proxy.sip_deferred_handles.contains_key(&client_addr),
            "shutdown before 180 should remove the deferred SIP task handle"
        );
    }

    #[tokio::test]
    async fn sip_deferred_task_removes_handle_on_shutdown_after_ringing() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKshutdown-after-ringing;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: shutdown-after-ringing@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        for expected in ["SIP/2.0 100 Trying\r\n", "SIP/2.0 180 Ringing\r\n"] {
            let (n, from) =
                tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
                    .await
                    .expect("expected SIP response before shutdown")
                    .unwrap();
            assert_eq!(from, proxy_addr);
            assert!(std::str::from_utf8(&buf[..n])
                .unwrap()
                .starts_with(expected));
        }

        proxy.shutdown_handle().shutdown();

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !proxy.sip_deferred_handles.contains_key(&client_addr),
            "shutdown before 200 should remove the deferred SIP task handle"
        );
        let final_ok =
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buf)).await;
        assert!(
            final_ok.is_err(),
            "shutdown should suppress deferred SIP 200 OK"
        );
    }

    #[tokio::test]
    async fn sip_deferred_responses_consume_rate_limit_tokens() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config_with_rate(backend_addr, 0), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: deferred-rate-limit@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("pre-acquired token should allow initial 100 Trying")
                .unwrap();
        assert_eq!(from, proxy_addr);
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("SIP/2.0 100 Trying\r\n"));

        let extra =
            tokio::time::timeout(Duration::from_millis(1200), client.recv_from(&mut buf)).await;
        assert!(
            extra.is_err(),
            "deferred SIP responses must require their own rate tokens"
        );
        assert_eq!(
            metrics_ref
                .unwrap()
                .probes_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn malformed_fresh_invite_drops_stale_dialog_state() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let proxy = Proxy::bind(sip_test_config(backend_addr), None)
            .await
            .unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let metrics_ref = proxy.metrics.get_or_create(client_addr);
        let old_invite = b"INVITE sip:old@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKold;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=old\r\n\
To: Olivia <sip:old@profi.ru>\r\n\
Call-ID: old-call@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let mut old_dialog = SipDialog::from_invite(old_invite).unwrap();
        old_dialog.stage = SipDialogStage::Terminated;
        proxy.sip_dialogs.insert(client_addr, old_dialog);

        let malformed_invite = b"INVITE sip:new@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKnew;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=new\r\n\
Call-ID: new-call@192.168.224.194\r\n\
CSeq: 95930 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        proxy
            .handle_sip_probe(malformed_invite, client_addr, &metrics_ref, true)
            .await;

        let mut buf = [0u8; 1024];
        let (n, from) =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .expect("malformed INVITE should receive stateless SIP response")
                .unwrap();
        assert_eq!(from, proxy_addr);
        let text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.starts_with("SIP/2.0 100 Trying\r\n"));
        assert!(text.contains("Call-ID: new-call@192.168.224.194"));
        assert!(!text.contains("old-call@192.168.224.194"));
        assert!(!proxy.sip_dialogs.contains_key(&client_addr));
    }
}
