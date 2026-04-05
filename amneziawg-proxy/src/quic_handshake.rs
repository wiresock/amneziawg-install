use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig,
    EndpointEvent, ServerConfig,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Minimal stateful QUIC handshake responder.
///
/// This responder uses `quinn-proto` as the QUIC/TLS state machine, which handles
/// Initial key derivation, Initial packet decryption, TLS ClientHello parsing,
/// and generation of server Initial/Handshake flight packets.
pub struct QuicHandshakeResponder {
    endpoint: Endpoint,
    connections: HashMap<ConnectionHandle, Connection>,
    conn_events: HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
}

pub struct QuicResponse {
    pub destination: SocketAddr,
    pub payload: Bytes,
}

impl QuicHandshakeResponder {
    pub fn new(certificate_domain: &str) -> anyhow::Result<Self> {
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![
            certificate_domain.to_string(),
        ])
        .context("failed to generate self-signed certificate")?;

        let cert_chain: Vec<CertificateDer<'static>> = vec![cert.der().clone()];
        let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let private_key: PrivateKeyDer<'static> = key_der.into();

        let server_cfg = ServerConfig::with_single_cert(cert_chain, private_key)
            .context("failed to create QUIC server config")?;

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
        })
    }

    pub fn has_active_connection(&self, remote: SocketAddr) -> bool {
        self.connections
            .values()
            .any(|conn| conn.remote_address() == remote)
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
                if let Ok((ch, conn)) = self.endpoint.accept(incoming, now, buf, None) {
                    self.connections.insert(ch, conn);
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
            }

            for (ch, event) in endpoint_events {
                if let Some(conn_event) = self.endpoint.handle_event(ch, event) {
                    self.conn_events.entry(ch).or_default().push_back(conn_event);
                    made_progress = true;
                }
            }

            if !made_progress {
                break;
            }
        }
    }
}
