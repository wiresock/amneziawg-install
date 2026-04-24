use std::collections::{HashMap, VecDeque};
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
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(name).cloned())
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
                        self.connections.insert(ch, conn);
                        *self.active_remotes.entry(remote).or_insert(0) += 1;
                    }
                }
                if !buf.is_empty() {
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

    fn drive(&mut self, now: Instant, buf: &mut Vec<u8>, out: &mut Vec<QuicResponse>) {
        loop {
            let mut endpoint_events: Vec<(ConnectionHandle, EndpointEvent)> = Vec::new();
            let mut drained_connections: Vec<ConnectionHandle> = Vec::new();
            let mut made_progress = false;

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

                while let Some(transmit) = conn.poll_transmit(now, 1, buf) {
                    out.push(QuicResponse {
                        destination: transmit.destination,
                        payload: Bytes::copy_from_slice(&buf[..transmit.size]),
                    });
                    buf.clear();
                    made_progress = true;
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
                if let Some(conn) = self.connections.remove(&ch) {
                    let remote = conn.remote_address();
                    if let std::collections::hash_map::Entry::Occupied(mut entry) =
                        self.active_remotes.entry(remote)
                    {
                        *entry.get_mut() -= 1;
                        if *entry.get() == 0 {
                            entry.remove();
                        }
                    }
                    made_progress = true;
                }
                self.conn_events.remove(&ch);
            }

            if !made_progress {
                break;
            }
        }
    }
}
