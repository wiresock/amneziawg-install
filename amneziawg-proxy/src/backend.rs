use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// Apply the requested kernel receive/send buffer sizes (`SO_RCVBUF`/`SO_SNDBUF`)
/// to a UDP socket. A `bytes` value of `0` is a no-op, leaving the OS defaults
/// in place.
///
/// Larger socket buffers absorb bursts while a worker is briefly busy, which is
/// the main defense against in-proxy UDP drops that the tunnel would otherwise
/// see as path loss (collapsing TCP throughput). Best-effort: failures are
/// logged at debug and never abort session setup. The kernel may also clamp the
/// request to `net.core.rmem_max` / `wmem_max`, so the effective size can be
/// smaller than requested.
pub fn configure_socket_buffers(sock: &UdpSocket, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let sock_ref = socket2::SockRef::from(sock);
    if let Err(e) = sock_ref.set_recv_buffer_size(bytes) {
        debug!(error = %e, requested = bytes, "failed to set SO_RCVBUF");
    }
    if let Err(e) = sock_ref.set_send_buffer_size(bytes) {
        debug!(error = %e, requested = bytes, "failed to set SO_SNDBUF");
    }
}

/// Forward a packet from the client to the backend via the session's dedicated socket.
pub async fn forward_to_backend(
    backend_sock: &UdpSocket,
    data: &[u8],
) -> std::io::Result<usize> {
    let sent = backend_sock.send(data).await?;
    debug!(bytes = sent, "forwarded to backend");
    Ok(sent)
}

/// Receive a response from the backend on the session's dedicated socket.
/// Awaits until data is available and returns the number of bytes read.
///
/// Note: the proxy runtime drives relay tasks via `backend_sock.recv()` directly;
/// this helper is provided for external callers and tests.
pub async fn recv_from_backend(
    backend_sock: &UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let n = backend_sock.recv(buf).await?;
    debug!(bytes = n, "received from backend");
    Ok(n)
}

/// Send a response packet back to the client via the frontend socket.
pub async fn send_to_client(
    frontend_sock: &Arc<UdpSocket>,
    client_addr: std::net::SocketAddr,
    data: &[u8],
) -> std::io::Result<usize> {
    let sent = frontend_sock.send_to(data, client_addr).await?;
    debug!(bytes = sent, %client_addr, "sent to client");
    Ok(sent)
}

/// Try to receive from the backend with a timeout.
/// Returns `Ok(Some(n))` if data was received, `Ok(None)` on timeout.
///
/// Note: the proxy runtime drives relay tasks via `backend_sock.recv()` directly;
/// this helper is provided for external callers and tests.
pub async fn try_recv_from_backend(
    backend_sock: &UdpSocket,
    buf: &mut [u8],
    timeout: std::time::Duration,
) -> std::io::Result<Option<usize>> {
    match tokio::time::timeout(timeout, backend_sock.recv(buf)).await {
        Ok(Ok(n)) => Ok(Some(n)),
        Ok(Err(e)) => {
            warn!(error = %e, "backend recv error");
            Err(e)
        }
        Err(_) => Ok(None), // timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forward_and_receive() {
        // Set up a mock "backend" that echoes packets
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        // Session socket
        let session_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        session_sock.connect(backend_addr).await.unwrap();

        let payload = b"hello backend";
        let sent = forward_to_backend(&session_sock, payload).await.unwrap();
        assert_eq!(sent, payload.len());

        // Backend receives and echoes back
        let mut buf = [0u8; 1024];
        let (n, from) = backend.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload);
        backend.send_to(&buf[..n], from).await.unwrap();

        // Session receives the echo
        let n = recv_from_backend(&session_sock, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[tokio::test]
    async fn send_to_client_works() {
        let frontend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let frontend_addr = frontend.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let data = b"response";
        send_to_client(&frontend, client_addr, data).await.unwrap();

        let mut buf = [0u8; 1024];
        let (n, from) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], data);
        assert_eq!(from, frontend_addr);
    }

    #[tokio::test]
    async fn try_recv_timeout() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect("127.0.0.1:19876").await.unwrap();

        let mut buf = [0u8; 64];
        let result = try_recv_from_backend(
            &sock,
            &mut buf,
            std::time::Duration::from_millis(10),
        )
        .await
        .unwrap();

        assert!(result.is_none());
    }
}
