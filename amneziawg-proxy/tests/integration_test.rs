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

    // Give the proxy a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

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

    // We should get TWO responses: probe response + backend echo
    // Collect responses
    let mut responses = Vec::new();
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => responses.push(buf[..n].to_vec()),
            _ => break,
        }
    }

    // At least the probe response should be present
    assert!(
        !responses.is_empty(),
        "should receive at least the probe response"
    );

    // Check that we got a QUIC version negotiation (starts with 0xC3, preserving incoming type bits)
    let has_version_neg = responses.iter().any(|r| !r.is_empty() && r[0] == 0xC3);
    assert!(has_version_neg, "should have a QUIC version negotiation response");

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

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Two independent clients
    let client_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    client_a.send_to(b"msg-from-a", proxy_addr).await.unwrap();
    client_b.send_to(b"msg-from-b", proxy_addr).await.unwrap();

    let mut buf_a = [0u8; 4096];
    let mut buf_b = [0u8; 4096];

    // Collect responses (order may vary)
    let mut payloads = Vec::new();

    // Receive from both clients in parallel using separate buffers
    let (res_a, res_b) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(3), client_a.recv_from(&mut buf_a)),
        tokio::time::timeout(Duration::from_secs(3), client_b.recv_from(&mut buf_b)),
    );

    if let Ok(Ok((n, _))) = res_a {
        if n >= 2 {
            payloads.push(("a".to_string(), buf_a[2..n].to_vec()));
        }
    }
    if let Ok(Ok((n, _))) = res_b {
        if n >= 2 {
            payloads.push(("b".to_string(), buf_b[2..n].to_vec()));
        }
    }

    // Each client should get its own echo back
    assert_eq!(payloads.len(), 2, "both clients should get responses");

    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(2), proxy_handle)
        .await
        .expect("proxy did not shut down in time")
        .unwrap();
    backend_handle.abort();
}
