use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use quinn_proto::crypto::rustls::QuicServerConfig;
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig,
    EndpointEvent, ServerConfig,
};
use rcgen::generate_simple_self_signed;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

struct DynamicSniResolver {
    default_domain: String,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl DynamicSniResolver {
    fn new(default_domain: &str) -> anyhow::Result<Self> {
        let default_domain = default_domain.to_ascii_lowercase();
        let mut cache = HashMap::new();
        let default_key = generate_certified_key(&default_domain)?;
        cache.insert(default_domain.clone(), default_key);
        Ok(Self {
            default_domain,
            cache: Mutex::new(cache),
        })
    }

    fn is_valid_sni_hostname(name: &str) -> bool {
        if name.is_empty() || name.len() > 253 {
            return false;
        }
        if name.starts_with('.') || name.ends_with('.') {
            return false;
        }
        name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
    }

    fn cache_get(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        // Recover from a poisoned mutex instead of permanently disabling the
        // cache. Losing the cache would force regenerating self-signed certs
        // on every handshake, which is exactly the CPU-spike behavior we want
        // to avoid under adversarial traffic.
        let cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.get(name).cloned()
    }
}

impl fmt::Debug for DynamicSniResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicSniResolver")
            .field("default_domain", &self.default_domain)
            .finish()
    }
}

impl ResolvesServerCert for DynamicSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let requested = client_hello
            .server_name()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("")
            .to_ascii_lowercase();

        if requested == self.default_domain {
            return self
                .cache_get(&self.default_domain)
                .or_else(|| generate_certified_key(&self.default_domain).ok());
        }

        if Self::is_valid_sni_hostname(&requested) {
            if let Some(ck) = self.cache_get(&requested) {
                return Some(ck);
            }
            // Intentionally do not generate per-SNI certificates for cache misses.
            // Falling back to the default cert bounds CPU/memory work under
            // adversarial traffic with many unique SNI values.
        }

        self.cache_get(&self.default_domain)
            .or_else(|| generate_certified_key(&self.default_domain).ok())
    }
}

fn generate_certified_key(domain: &str) -> anyhow::Result<Arc<CertifiedKey>> {
    let rcgen::CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![domain.to_string()])
            .with_context(|| format!("failed to generate self-signed certificate for '{domain}'"))?;

    let cert_chain: Vec<CertificateDer<'static>> = vec![cert.der().clone()];
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let private_key: PrivateKeyDer<'static> = key_der.into();
    let signing_key = any_supported_type(&private_key)
        .context("failed to create signing key from generated private key")?;

    Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
}

/// Minimum byte total that distinguishes a server Certificate flight from a
/// bare `CONNECTION_CLOSE`-only response.  A successful TLS 1.3 Handshake
/// flight (Certificate + CertificateVerify + Finished) always exceeds this
/// threshold; a `CONNECTION_CLOSE` with a TLS alert is typically < 200 bytes.
///
/// Used both in `drive()` to guard flush-and-forget eviction and in the test
/// suite to assert a full flight was produced.
const MIN_CERT_FLIGHT_BYTES: usize = 500;

/// Minimal stateful QUIC handshake responder.
///
/// This responder uses `quinn-proto` as the QUIC/TLS state machine, which handles
/// Initial key derivation, Initial packet decryption, TLS ClientHello parsing,
/// and generation of server Initial/Handshake flight packets.
pub struct QuicHandshakeResponder {
    endpoint: Endpoint,
    connections: HashMap<ConnectionHandle, Connection>,
    conn_events: HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
    active_remotes: HashMap<SocketAddr, usize>,
    /// Connections that should be silently dropped after their first transmit
    /// burst is collected.  Prevents quinn-proto loss-recovery timers from
    /// retransmitting the Handshake flight mid-session — the proxy only needs
    /// to emit the server Certificate flight; it never completes the handshake.
    flush_and_forget: HashSet<ConnectionHandle>,
}

pub struct QuicResponse {
    pub destination: SocketAddr,
    pub payload: Bytes,
}

impl QuicHandshakeResponder {
    const MAX_TRACKED_CONNECTIONS: usize = 2_048;

    pub fn new(certificate_domain: &str) -> anyhow::Result<Self> {
        let resolver = Arc::new(DynamicSniResolver::new(certificate_domain)?);
        let mut rustls_server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        rustls_server_cfg.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];
        rustls_server_cfg.max_early_data_size = 0;

        let quic_crypto = QuicServerConfig::try_from(rustls_server_cfg)
            .context("failed to create QUIC rustls server config")?;
        let server_cfg = ServerConfig::with_crypto(Arc::new(quic_crypto));

        let endpoint = Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(Arc::new(server_cfg)),
            false,
            None,
        );

        Ok(Self {
            endpoint,
            connections: HashMap::new(),
            conn_events: HashMap::new(),
            active_remotes: HashMap::new(),
            flush_and_forget: HashSet::new(),
        })
    }

    pub fn has_active_connection(&self, remote: SocketAddr) -> bool {
        self.active_remotes.contains_key(&remote)
    }

    pub fn handle_datagram(&mut self, remote: SocketAddr, packet: &[u8]) -> Vec<QuicResponse> {
        let now = Instant::now();
        let mut out = Vec::new();
        let mut buf = Vec::new();

        if let Some(event) = self.endpoint.handle(
            now,
            remote,
            None,
            None,
            BytesMut::from(packet),
            &mut buf,
        ) {
            self.handle_endpoint_datagram_event(event, now, &mut buf, &mut out);
        }

        self.drive(now, &mut buf, &mut out);
        out
    }

    pub fn handle_timeouts(&mut self) -> Vec<QuicResponse> {
        let now = Instant::now();
        let mut out = Vec::new();
        let mut buf = Vec::new();
        self.drive(now, &mut buf, &mut out);
        out
    }

    fn handle_endpoint_datagram_event(
        &mut self,
        event: DatagramEvent,
        now: Instant,
        buf: &mut Vec<u8>,
        out: &mut Vec<QuicResponse>,
    ) {
        match event {
            DatagramEvent::Response(transmit) => {
                out.push(QuicResponse {
                    destination: transmit.destination,
                    payload: Bytes::copy_from_slice(&buf[..transmit.size]),
                });
                buf.clear();
            }
            DatagramEvent::NewConnection(incoming) => {
                let remote = incoming.remote_address();
                if self.connections.len() < Self::MAX_TRACKED_CONNECTIONS {
                    if let Ok((ch, conn)) = self.endpoint.accept(incoming, now, buf, None) {
                        // Flush any immediate post-accept datagram (e.g. stateless
                        // reset or early server Initial ACK) produced by accept().
                        if !buf.is_empty() {
                            out.push(QuicResponse {
                                destination: remote,
                                payload: Bytes::copy_from_slice(buf),
                            });
                            buf.clear();
                        }
                        self.connections.insert(ch, conn);
                        *self.active_remotes.entry(remote).or_insert(0) += 1;
                        // Mark for silent eviction after the first transmit burst.
                        // The proxy only needs to emit the Certificate flight; it
                        // never receives a client Finished, so leaving the connection
                        // alive would cause quinn-proto to retransmit the Handshake
                        // epoch at ~1s/2s/5s intervals — visible as spurious
                        // mid-session Initial/Handshake packets on the wire.
                        self.flush_and_forget.insert(ch);
                    }
                } else if !buf.is_empty() {
                    out.push(QuicResponse {
                        destination: remote,
                        payload: Bytes::copy_from_slice(buf),
                    });
                    buf.clear();
                }
            }
            DatagramEvent::ConnectionEvent(ch, event) => {
                self.conn_events.entry(ch).or_default().push_back(event);
            }
        }
    }

    /// Decrement the active-remote refcount for `remote`, removing the entry
    /// when it reaches zero.
    fn release_remote(&mut self, remote: SocketAddr) {
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.active_remotes.entry(remote)
        {
            *entry.get_mut() -= 1;
            if *entry.get() == 0 {
                entry.remove();
            }
        }
    }

    /// Remove a naturally-drained connection (conn.is_drained() == true).
    ///
    /// For naturally drained connections quinn-proto has already emitted
    /// `EndpointEvent::drained()` via `poll_endpoint_events()` and the endpoint
    /// has already processed it.  We must NOT send it a second time.
    fn drain_connection(&mut self, ch: ConnectionHandle) {
        if let Some(conn) = self.connections.remove(&ch) {
            self.release_remote(conn.remote_address());
        }
        self.conn_events.remove(&ch);
        self.flush_and_forget.remove(&ch);
    }

    /// Forcibly evict a flush-and-forget connection that has not gone through
    /// the normal quinn-proto drain sequence.
    ///
    /// Because the connection was never closed or drained normally, the endpoint
    /// still holds internal CID / routing state for it.  Sending
    /// `EndpointEvent::drained()` here is the correct way to release that state
    /// without emitting a CONNECTION_CLOSE datagram on the wire.
    ///
    /// Note: after eviction a replayed Initial from the same peer will be treated
    /// as a brand-new connection by the endpoint and will regenerate the
    /// Certificate flight.  This is bounded by the existing `active_remotes` cap
    /// and the probe rate-limiter in the outer `Proxy`.
    fn force_evict_connection(&mut self, ch: ConnectionHandle) {
        if let Some(conn) = self.connections.remove(&ch) {
            self.release_remote(conn.remote_address());
            // Notify the endpoint so it releases CID/routing state without
            // sending CONNECTION_CLOSE on the wire.
            self.endpoint.handle_event(ch, EndpointEvent::drained());
        }
        self.conn_events.remove(&ch);
        self.flush_and_forget.remove(&ch);
    }

    fn drive(&mut self, now: Instant, buf: &mut Vec<u8>, out: &mut Vec<QuicResponse>) {
        loop {
            let mut endpoint_events: Vec<(ConnectionHandle, EndpointEvent)> = Vec::new();
            let mut drained_connections: Vec<ConnectionHandle> = Vec::new();
            let mut made_progress = false;
            // Track flush-and-forget handles that produced transmits in this
            // iteration.  We record (ch, out_start, out_end) — the slice of `out`
            // that belongs exclusively to this connection — so the burst-size
            // check sums only this connection's bytes, not those of later
            // connections processed in the same drive() iteration.
            let mut transmitted_this_iter: Vec<(ConnectionHandle, usize, usize)> = Vec::new();

            let handles: Vec<ConnectionHandle> = self.connections.keys().copied().collect();
            for ch in handles {
                let Some(conn) = self.connections.get_mut(&ch) else {
                    continue;
                };

                if let Some(events) = self.conn_events.get_mut(&ch) {
                    while let Some(event) = events.pop_front() {
                        conn.handle_event(event);
                        made_progress = true;
                    }
                }

                while let Some(event) = conn.poll_endpoint_events() {
                    endpoint_events.push((ch, event));
                    made_progress = true;
                }

                let out_start = out.len();
                while let Some(transmit) = conn.poll_transmit(now, 1, buf) {
                    out.push(QuicResponse {
                        destination: transmit.destination,
                        payload: Bytes::copy_from_slice(&buf[..transmit.size]),
                    });
                    buf.clear();
                    made_progress = true;
                }
                let out_end = out.len();
                if out_end > out_start && self.flush_and_forget.contains(&ch) {
                    transmitted_this_iter.push((ch, out_start, out_end));
                }

                if let Some(timeout) = conn.poll_timeout() {
                    if timeout <= now {
                        conn.handle_timeout(now);
                        made_progress = true;
                    }
                }

                if conn.is_drained() {
                    drained_connections.push(ch);
                }
            }

            for (ch, event) in endpoint_events {
                if let Some(conn_event) = self.endpoint.handle_event(ch, event) {
                    self.conn_events.entry(ch).or_default().push_back(conn_event);
                    made_progress = true;
                }
            }

            for ch in drained_connections {
                self.drain_connection(ch);
                made_progress = true;
            }

            // Evict flush-and-forget connections whose burst in this iteration
            // was large enough to contain a Certificate flight.  The threshold
            // guards against premature eviction if a future quinn-proto version
            // splits the server flight (e.g. bare Initial ACK first, then
            // Certificate) across separate drive() iterations.
            // The quinn-proto dependency is pinned in Cargo.lock; the regression
            // test also asserts the full flight is present before eviction.
            for (ch, out_start, out_end) in transmitted_this_iter {
                let burst_bytes: usize = out[out_start..out_end]
                    .iter()
                    .map(|r| r.payload.len())
                    .sum();
                if burst_bytes >= MIN_CERT_FLIGHT_BYTES {
                    self.force_evict_connection(ch);
                }
            }

            if !made_progress {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::crypto::rustls::QuicClientConfig;
    use quinn_proto::{ClientConfig, Endpoint as ClientEndpoint, EndpointConfig, TransportConfig};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as TlsError,
                 SignatureScheme};

    /// A no-op TLS certificate verifier that accepts any server certificate.
    /// Used only in tests so we can connect to a self-signed test cert without
    /// needing a trust store.
    #[derive(Debug)]
    struct AcceptAnyCert;

    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    /// Build a quinn-proto client endpoint and return the raw bytes of the
    /// first QUIC Initial packet it produces, ready to feed into the responder.
    fn make_h3_initial(alpn: &[&str]) -> Vec<u8> {
        let mut tls = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        tls.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        let quic_tls = QuicClientConfig::try_from(tls)
            .expect("QuicClientConfig from h3 ClientConfig must succeed");

        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(
            std::time::Duration::from_secs(5).try_into().unwrap(),
        ));
        let mut client_cfg = ClientConfig::new(Arc::new(quic_tls));
        client_cfg.transport_config(Arc::new(transport));

        let mut endpoint = ClientEndpoint::new(
            Arc::new(EndpointConfig::default()),
            None,
            false,
            None,
        );
        let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let (_handle, mut conn) = endpoint
            .connect(
                Instant::now(),
                client_cfg,
                server_addr,
                "example.com",
            )
            .expect("client connect must succeed");

        let mut buf = Vec::new();
        let tx = conn
            .poll_transmit(Instant::now(), 16, &mut buf)
            .expect("client must produce an Initial packet");
        buf[..tx.size].to_vec()
    }

    /// Sum the payload bytes across all responses in a server flight.
    fn total_response_bytes(responses: &[QuicResponse]) -> usize {
        responses.iter().map(|r| r.payload.len()).sum()
    }

    /// Regression test: the responder must produce a large server flight
    /// (containing the Certificate) when the client offers h3.
    ///
    /// Before the fix, `alpn_protocols` was empty → rustls sent `CONNECTION_CLOSE`
    /// with `no_application_protocol` (TLS alert 120). That flight is tiny
    /// (< 200 bytes). With the fix the server proceeds through the full TLS 1.3
    /// Handshake flight (Certificate + CertificateVerify + Finished) which
    /// always exceeds MIN_CERT_FLIGHT_BYTES.
    #[test]
    fn h3_clienthello_produces_certificate_flight() {
        let mut responder = QuicHandshakeResponder::new("example.com").unwrap();
        let client_addr: SocketAddr = "127.0.0.1:11111".parse().unwrap();

        let initial = make_h3_initial(&["h3"]);
        let responses = responder.handle_datagram(client_addr, &initial);

        assert!(
            !responses.is_empty(),
            "responder must reply to a valid h3 ClientHello Initial"
        );
        let total = total_response_bytes(&responses);
        assert!(
            total >= MIN_CERT_FLIGHT_BYTES,
            "server flight must be >= {MIN_CERT_FLIGHT_BYTES} bytes to contain \
             a Certificate (got {total} bytes across {} datagram(s)); \
             a tiny response indicates a CONNECTION_CLOSE abort (missing ALPN)",
            responses.len(),
        );
    }

    /// Verify h3-29 (draft-29 ALPN) is also accepted — a DPI probe using an
    /// older QUIC stack must receive a full Certificate flight, not a close.
    #[test]
    fn h3_29_clienthello_produces_certificate_flight() {
        let mut responder = QuicHandshakeResponder::new("example.com").unwrap();
        let client_addr: SocketAddr = "127.0.0.1:11112".parse().unwrap();

        let initial = make_h3_initial(&["h3-29"]);
        let responses = responder.handle_datagram(client_addr, &initial);

        assert!(
            !responses.is_empty(),
            "responder must reply to a valid h3-29 ClientHello Initial"
        );
        let total = total_response_bytes(&responses);
        assert!(
            total >= MIN_CERT_FLIGHT_BYTES,
            "server flight must be >= {MIN_CERT_FLIGHT_BYTES} bytes to contain \
             a Certificate for h3-29 (got {total} bytes across {} datagram(s)); \
             a tiny response indicates a CONNECTION_CLOSE abort (missing ALPN)",
            responses.len(),
        );
    }

    #[test]
    fn empty_datagram_produces_no_response() {
        let mut r = QuicHandshakeResponder::new("example.com").unwrap();
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let responses = r.handle_datagram(addr, &[]);
        assert!(responses.is_empty(), "empty datagram must produce no response");
    }

    /// Regression: after the Certificate flight is emitted the connection must
    /// be silently evicted so that quinn-proto's retransmit timers never fire.
    ///
    /// Failure mode before the fix: connections stayed alive → poll_transmit
    /// would re-emit the Handshake epoch at ~1s/2s/5s intervals.
    #[test]
    fn flush_and_forget_evicts_after_certificate_flight() {
        let mut responder = QuicHandshakeResponder::new("example.com").unwrap();
        let client_addr: SocketAddr = "127.0.0.1:22222".parse().unwrap();

        // Feed a real h3 ClientHello — this triggers NewConnection + Certificate flight.
        let initial = make_h3_initial(&["h3"]);
        let first_responses = responder.handle_datagram(client_addr, &initial);
        assert!(
            !first_responses.is_empty(),
            "must produce Certificate flight on first datagram"
        );
        assert!(
            total_response_bytes(&first_responses) >= MIN_CERT_FLIGHT_BYTES,
            "first response must be a Certificate flight, not a CONNECTION_CLOSE"
        );

        // After the burst the connection must have been evicted.
        assert!(
            responder.connections.is_empty(),
            "connection must be evicted after Certificate flight"
        );
        assert!(
            responder.flush_and_forget.is_empty(),
            "flush_and_forget set must be empty after eviction"
        );
        assert!(
            responder.active_remotes.is_empty(),
            "active_remotes refcount must be zero after eviction"
        );

        // Call handle_timeouts — since the connection was evicted there are no
        // quinn-proto retransmit timers left to fire, so no packets should be
        // emitted regardless of wall-clock time.
        let retransmit_responses = responder.handle_timeouts();
        assert!(
            retransmit_responses.is_empty(),
            "no retransmissions must be emitted after eviction (got {} packets)",
            retransmit_responses.len()
        );
    }
}
