use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

use crate::backend;
use crate::config::ProxyConfig;
use crate::metrics::MetricsStore;
use crate::responder::{self, Protocol};
use crate::session::SessionTable;
use crate::transform;

/// The main proxy runtime state.
pub struct Proxy {
    config: ProxyConfig,
    frontend: Arc<UdpSocket>,
    sessions: Arc<SessionTable>,
    metrics: Arc<MetricsStore>,
    protocol: Protocol,
    shutdown: Arc<Notify>,
}

impl Proxy {
    /// Create and bind a new proxy instance.
    pub async fn bind(config: ProxyConfig) -> anyhow::Result<Self> {
        let listen_addr: SocketAddr = config.listen.parse()?;
        let backend_addr: SocketAddr = config.backend.parse()?;
        let frontend = Arc::new(UdpSocket::bind(listen_addr).await?);

        let protocol = match config.imitate_protocol.as_str() {
            "quic" => Protocol::Quic,
            "dns" => Protocol::Dns,
            "sip" => Protocol::Sip,
            _ => anyhow::bail!("unsupported protocol: {}", config.imitate_protocol),
        };

        let sessions = Arc::new(SessionTable::new(
            backend_addr,
            Duration::from_secs(config.session_ttl_secs),
        ));
        let metrics = Arc::new(MetricsStore::new(config.rate_limit_per_sec));

        info!(
            listen = %listen_addr,
            backend = %backend_addr,
            protocol = %config.imitate_protocol,
            session_ttl = config.session_ttl_secs,
            "proxy initialized"
        );

        Ok(Self {
            config,
            frontend,
            sessions,
            metrics,
            protocol,
            shutdown: Arc::new(Notify::new()),
        })
    }

    /// Create from pre-existing components (useful for testing).
    pub fn from_parts(
        config: ProxyConfig,
        frontend: Arc<UdpSocket>,
        sessions: Arc<SessionTable>,
        metrics: Arc<MetricsStore>,
        protocol: Protocol,
    ) -> Self {
        Self {
            config,
            frontend,
            sessions,
            metrics,
            protocol,
            shutdown: Arc::new(Notify::new()),
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
        let relay_handle = self.spawn_relay_tasks();

        info!("proxy running");

        // Main receive loop
        let mut buf = vec![0u8; self.config.buffer_size];

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
            }
        }

        cleanup_handle.abort();
        relay_handle.abort();
        info!("proxy stopped");
        Ok(())
    }

    /// Handle a packet received from a client.
    async fn handle_client_packet(&self, data: &[u8], client_addr: SocketAddr) {
        let metrics = self.metrics.get_or_create(client_addr);
        metrics.record_in();
        drop(metrics);

        // Check if this is a probe packet and respond if rate allows
        if let Some(proto) = responder::detect_protocol(data) {
            let metrics = self.metrics.get_or_create(client_addr);
            if metrics.try_acquire_probe() {
                metrics.record_probe();
                drop(metrics);

                let response = responder::generate_response(proto, data);
                if let Err(e) = self.frontend.send_to(&response, client_addr).await {
                    warn!(%client_addr, error = %e, "failed to send probe response");
                }
                debug!(%client_addr, protocol = ?proto, "probe response sent");
            } else {
                debug!(%client_addr, "probe rate limited");
                drop(metrics);
            }
        }

        // Forward to backend
        match self.sessions.get_or_create(client_addr).await {
            Ok(backend_sock) => {
                if let Err(e) = backend::forward_to_backend(&backend_sock, data).await {
                    warn!(%client_addr, error = %e, "failed to forward to backend");
                }
            }
            Err(e) => {
                error!(%client_addr, error = %e, "failed to create session");
            }
        }
    }

    /// Spawn a task that periodically cleans up expired sessions.
    fn spawn_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let sessions = Arc::clone(&self.sessions);
        let metrics = Arc::clone(&self.metrics);
        let interval = Duration::from_secs(self.config.cleanup_interval_secs);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // first tick is immediate, skip it
            loop {
                ticker.tick().await;
                let expired = sessions.cleanup_expired();
                for addr in &expired {
                    metrics.remove(addr);
                }
                if !expired.is_empty() {
                    info!(count = expired.len(), "cleaned up expired sessions");
                }
            }
        })
    }

    /// Spawn tasks that relay responses from backend sockets back to clients.
    fn spawn_relay_tasks(&self) -> tokio::task::JoinHandle<()> {
        let sessions = Arc::clone(&self.sessions);
        let frontend = Arc::clone(&self.frontend);
        let metrics = Arc::clone(&self.metrics);
        let protocol = self.protocol;
        let buffer_size = self.config.buffer_size;
        let _shutdown = Arc::clone(&self.shutdown);

        tokio::spawn(async move {
            // Poll all backend sockets for responses
            let mut interval = tokio::time::interval(Duration::from_millis(1));

            loop {
                interval.tick().await;

                let sockets = sessions.all_backend_sockets();
                for (client_addr, backend_sock) in sockets {
                    let mut buf = vec![0u8; buffer_size];
                    match backend::try_recv_from_backend(
                        &backend_sock,
                        &mut buf,
                        Duration::from_millis(0),
                    )
                    .await
                    {
                        Ok(Some(n)) => {
                            // Apply S4 padding transformation
                            // For simplicity, we treat the entire packet as payload
                            // and apply the transform in-place
                            transform::apply_s4_padding(&mut buf[..n], n, protocol);

                            let m = metrics.get_or_create(client_addr);
                            m.record_out();
                            drop(m);

                            sessions.touch(&client_addr);

                            if let Err(e) =
                                backend::send_to_client(&frontend, client_addr, &buf[..n]).await
                            {
                                warn!(%client_addr, error = %e, "failed to relay to client");
                            }
                        }
                        Ok(None) => {} // no data
                        Err(e) => {
                            debug!(%client_addr, error = %e, "backend recv error in relay");
                        }
                    }
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
            buffer_size: 4096,
        };

        let proxy = Proxy::bind(config).await.unwrap();
        let addr = proxy.local_addr().unwrap();
        assert_ne!(addr.port(), 0);

        let shutdown = proxy.shutdown_handle();

        let handle = tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Give it a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

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
            buffer_size: 4096,
        };

        let proxy = Proxy::bind(config).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let shutdown = proxy.shutdown_handle();

        tokio::spawn(async move {
            proxy.run().await.unwrap();
        });

        // Give proxy time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send a QUIC-like probe packet
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut quic_pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01];
        quic_pkt.push(4);
        quic_pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        quic_pkt.push(0);

        client.send_to(&quic_pkt, proxy_addr).await.unwrap();

        // Should get a probe response (QUIC version negotiation)
        let mut buf = [0u8; 4096];
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await;

        assert!(result.is_ok(), "should receive probe response");
        let (_n, from) = result.unwrap().unwrap();
        assert_eq!(from, proxy_addr);
        // Version negotiation starts with 0x80
        assert_eq!(buf[0], 0x80);

        // Backend should also have received the forwarded packet
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
    }
}
