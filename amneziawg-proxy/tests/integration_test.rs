//! Integration test: full proxy round-trip with a mock echo backend.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

/// Spawn a mock backend that echoes every packet back with a 2-byte prefix `[0xEC, 0x00]`.
async fn spawn_echo_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let mut response = vec![0xEC, 0x00];
                    response.extend_from_slice(&buf[..n]);
                    let _ = sock.send_to(&response, from).await;
                }
                Err(_) => break,
            }
        }
    });

    (addr, handle)
}

/// Send a single byte probe and wait for any response to confirm the proxy
/// is ready.  Retries up to `max_retries` times with `interval` between
/// attempts, which is more robust under CI load than a fixed sleep.
async fn wait_for_proxy_ready(proxy_addr: SocketAddr, max_retries: u32, interval: Duration) {
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..max_retries {
        // Send a unique non-protocol payload so we can distinguish readiness
        // probes from any stale queued echoes.
        let probe_payload = [0xA5, 0x5A, (i & 0xFF) as u8, ((i >> 8) & 0xFF) as u8];
        let _ = probe.send_to(&probe_payload, proxy_addr).await;
        let mut buf = [0u8; 64];
        let deadline = tokio::time::Instant::now() + interval;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            match tokio::time::timeout(deadline - now, probe.recv_from(&mut buf)).await {
                Ok(Ok((n, _)))
                    if n == probe_payload.len() + 2
                        && buf[..2] == [0xEC, 0x00]
                        && buf[2..n] == probe_payload =>
                {
                    // Drain any additional queued echoes so later assertions
                    // read only responses from the packets they send.
                    loop {
                        match tokio::time::timeout(
                            Duration::from_millis(10),
                            probe.recv_from(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok(_)) => continue,
                            _ => break,
                        }
                    }
                    return;
                }
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }
        if i + 1 == max_retries {
            panic!("proxy did not become ready after {max_retries} retries");
        }
    }
}

/// Build a minimal in-memory TOML config and exercise the proxy via the library (no subprocess).
#[tokio::test]
async fn full_round_trip_with_echo_backend() {
    // 1. Start the echo backend
    let (backend_addr, backend_handle) = spawn_echo_backend().await;

    // 2. Start the proxy
    //    We test via the proxy module directly (white-box integration test).
    //    We need to build the proxy from config.
    let config_toml = format!(
        r#"
listen = "127.0.0.1:0"
backend = "{}"
session_ttl_secs = 60
cleanup_interval_secs = 60
rate_limit_per_sec = 10
imitate_protocol = "quic"
buffer_size = 4096
"#,
        backend_addr
    );

    // Parse config to get a ProxyConfig using the same validation as production
    let cfg = amneziawg_proxy::config::parse_config(&config_toml).unwrap();

    let proxy = amneziawg_proxy::proxy::Proxy::bind(cfg, None).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let shutdown = proxy.shutdown_handle();

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.unwrap();
    });

    // Wait for the proxy to become ready (retry-based, no fixed sleep)
    wait_for_proxy_ready(proxy_addr, 20, Duration::from_millis(100)).await;

    // 3. Create a "client" and send a packet
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"hello from client";
    client.send_to(payload, proxy_addr).await.unwrap();

    // 4. We should receive the echo from backend (with 0xEC 0x00 prefix)
    let mut buf = [0u8; 4096];
    let result = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf)).await;
    assert!(result.is_ok(), "should receive echoed response from backend");
    let (n, from) = result.unwrap().unwrap();
    assert_eq!(from, proxy_addr);

    // The echo backend prepends [0xEC, 0x00]
    assert!(n >= 2);
    assert_eq!(buf[0], 0xEC);
    assert_eq!(buf[1], 0x00);
    assert_eq!(&buf[2..n], payload);

    // 5. Test probe detection: send a QUIC Initial-like packet
    let mut quic_pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01]; // QUIC Initial header
    quic_pkt.push(4); // DCID len
    quic_pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // DCID
    quic_pkt.push(0); // SCID len

    client.send_to(&quic_pkt, proxy_addr).await.unwrap();

    // We should get TWO responses: a probe response (QUIC Version
    // Negotiation) and a backend echo (prefixed with [0xEC, 0x00]).
    let mut responses = Vec::new();
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => responses.push(buf[..n].to_vec()),
            _ => break,
        }
    }

    assert_eq!(
        responses.len(),
        2,
        "expected both probe response and backend echo, got {}",
        responses.len()
    );

    // One response must be the QUIC Version Negotiation (first byte 0xC3).
    let has_version_neg = responses.iter().any(|r| !r.is_empty() && r[0] == 0xC3);
    assert!(has_version_neg, "should have a QUIC version negotiation response");

    // The other must be the backend echo (prefixed with [0xEC, 0x00]) and
    // must contain the exact QUIC payload we just sent.
    let backend_echo = responses
        .iter()
        .find(|r| r.len() >= 2 && r[0] == 0xEC && r[1] == 0x00)
        .expect("should have a backend echo response");
    assert_eq!(
        backend_echo.len(),
        quic_pkt.len() + 2,
        "backend echo should contain prefix plus the original QUIC packet"
    );
    assert_eq!(
        &backend_echo[2..],
        quic_pkt.as_slice(),
        "backend echo payload should match the QUIC packet that was sent"
    );

    // 6. Shutdown
    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(2), proxy_handle)
        .await
        .expect("proxy did not shut down in time")
        .unwrap();
    backend_handle.abort();
}

/// Test that multiple clients get independent sessions.
#[tokio::test]
async fn multiple_clients_independent_sessions() {
    let (backend_addr, backend_handle) = spawn_echo_backend().await;

    let config_toml = format!(
        r#"
listen = "127.0.0.1:0"
backend = "{}"
session_ttl_secs = 60
cleanup_interval_secs = 60
rate_limit_per_sec = 10
imitate_protocol = "dns"
buffer_size = 4096
"#,
        backend_addr
    );

    // Parse config using the same validation as production
    let cfg = amneziawg_proxy::config::parse_config(&config_toml).unwrap();

    let proxy = amneziawg_proxy::proxy::Proxy::bind(cfg, None).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let shutdown = proxy.shutdown_handle();

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.unwrap();
    });

    // Wait for the proxy to become ready (retry-based, no fixed sleep)
    wait_for_proxy_ready(proxy_addr, 20, Duration::from_millis(100)).await;

    // Two independent clients
    let client_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    client_a.send_to(b"msg-from-a", proxy_addr).await.unwrap();
    client_b.send_to(b"msg-from-b", proxy_addr).await.unwrap();

    let mut buf_a = [0u8; 4096];
    let mut buf_b = [0u8; 4096];

    // Receive from both clients in parallel using separate buffers
    let (res_a, res_b) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(3), client_a.recv_from(&mut buf_a)),
        tokio::time::timeout(Duration::from_secs(3), client_b.recv_from(&mut buf_b)),
    );

    // Validate client A response
    let (n_a, src_a) = res_a
        .expect("client A timed out")
        .expect("client A recv error");
    assert_eq!(src_a, proxy_addr, "client A response must come from proxy");
    assert!(n_a >= 2, "client A response too short: {} bytes", n_a);
    assert_eq!(
        &buf_a[..2],
        &[0xEC, 0x00],
        "client A response missing [0xEC, 0x00] prefix"
    );
    assert_eq!(
        &buf_a[2..n_a],
        b"msg-from-a",
        "client A payload mismatch"
    );

    // Validate client B response
    let (n_b, src_b) = res_b
        .expect("client B timed out")
        .expect("client B recv error");
    assert_eq!(src_b, proxy_addr, "client B response must come from proxy");
    assert!(n_b >= 2, "client B response too short: {} bytes", n_b);
    assert_eq!(
        &buf_b[..2],
        &[0xEC, 0x00],
        "client B response missing [0xEC, 0x00] prefix"
    );
    assert_eq!(
        &buf_b[2..n_b],
        b"msg-from-b",
        "client B payload mismatch"
    );

    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(2), proxy_handle)
        .await
        .expect("proxy did not shut down in time")
        .unwrap();
    backend_handle.abort();
}
