use bytes::{BytesMut, BufMut};

use crate::responder::Protocol;

/// Apply S4 padding transformation to an outgoing packet.
///
/// AmneziaWG appends random padding bytes to WireGuard packets. When imitating
/// a specific protocol, we overwrite the padding region (bytes after the
/// WireGuard payload) with protocol-conformant filler so that DPI sees
/// plausible traffic.
///
/// The `payload_len` parameter indicates where the real WireGuard payload ends
/// within `data`. Everything from `payload_len..data.len()` is treated as
/// padding that gets overwritten.
///
/// If `payload_len >= data.len()`, no transformation is applied (no padding
/// region exists).
pub fn apply_s4_padding(data: &mut [u8], payload_len: usize, proto: Protocol) {
    if payload_len >= data.len() {
        return;
    }

    let padding = &mut data[payload_len..];

    match proto {
        Protocol::Quic => apply_quic_padding(padding),
        Protocol::Dns => apply_dns_padding(padding),
        Protocol::Sip => apply_sip_padding(padding),
    }
}

/// Build a complete packet with S4 padding appended.
///
/// Takes the original payload and appends `pad_len` bytes of
/// protocol-conformant padding.
pub fn build_padded_packet(payload: &[u8], pad_len: usize, proto: Protocol) -> BytesMut {
    let mut buf = BytesMut::with_capacity(payload.len() + pad_len);
    buf.put_slice(payload);

    if pad_len == 0 {
        return buf;
    }

    // Append padding bytes (initially zeros)
    buf.put_bytes(0, pad_len);

    let payload_end = payload.len();
    apply_s4_padding(&mut buf[..], payload_end, proto);

    buf
}

/// QUIC-style padding: PADDING frames (type 0x00).
/// RFC 9000 §19.1: A PADDING frame has no content; just 0x00 bytes.
fn apply_quic_padding(padding: &mut [u8]) {
    // QUIC PADDING frames are literally zero bytes
    for byte in padding.iter_mut() {
        *byte = 0x00;
    }
}

/// DNS-style padding: EDNS(0) padding option (RFC 7830).
/// We write a plausible OPT RR padding structure.
/// Format: zeros (since the padding option content SHOULD be zeros).
fn apply_dns_padding(padding: &mut [u8]) {
    // DNS EDNS padding is zero-filled
    for byte in padding.iter_mut() {
        *byte = 0x00;
    }
}

/// SIP-style padding: pad with spaces and CRLF to look like SIP header
/// continuation or body padding.
/// SIP messages are text-based, so we use spaces (0x20) as filler,
/// terminated by CRLF.
fn apply_sip_padding(padding: &mut [u8]) {
    if padding.is_empty() {
        return;
    }

    let len = padding.len();
    // Fill with spaces
    for byte in padding.iter_mut() {
        *byte = 0x20; // space
    }

    // End with \r\n if we have room
    if len >= 2 {
        padding[len - 2] = b'\r';
        padding[len - 1] = b'\n';
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_padding_zeroes() {
        let mut data = vec![0xAA; 20];
        let payload_len = 10;
        apply_s4_padding(&mut data, payload_len, Protocol::Quic);

        // First 10 bytes untouched
        assert!(data[..10].iter().all(|&b| b == 0xAA));
        // Padding region is all zeros
        assert!(data[10..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn dns_padding_zeroes() {
        let mut data = vec![0xBB; 16];
        let payload_len = 8;
        apply_s4_padding(&mut data, payload_len, Protocol::Dns);

        assert!(data[..8].iter().all(|&b| b == 0xBB));
        assert!(data[8..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn sip_padding_spaces_crlf() {
        let mut data = vec![0xCC; 20];
        let payload_len = 10;
        apply_s4_padding(&mut data, payload_len, Protocol::Sip);

        assert!(data[..10].iter().all(|&b| b == 0xCC));
        // Padding should be spaces ending with \r\n
        assert!(data[10..18].iter().all(|&b| b == 0x20));
        assert_eq!(data[18], b'\r');
        assert_eq!(data[19], b'\n');
    }

    #[test]
    fn no_padding_when_payload_equals_len() {
        let mut data = vec![0xDD; 10];
        apply_s4_padding(&mut data, 10, Protocol::Quic);
        assert!(data.iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn no_padding_when_payload_exceeds_len() {
        let mut data = vec![0xEE; 10];
        apply_s4_padding(&mut data, 15, Protocol::Dns);
        assert!(data.iter().all(|&b| b == 0xEE));
    }

    #[test]
    fn build_padded_packet_quic() {
        let payload = vec![0x01, 0x02, 0x03];
        let result = build_padded_packet(&payload, 5, Protocol::Quic);
        assert_eq!(result.len(), 8);
        assert_eq!(&result[..3], &[0x01, 0x02, 0x03]);
        assert!(result[3..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn build_padded_packet_zero_pad() {
        let payload = vec![0x01, 0x02];
        let result = build_padded_packet(&payload, 0, Protocol::Quic);
        assert_eq!(result.len(), 2);
        assert_eq!(&result[..], &[0x01, 0x02]);
    }

    #[test]
    fn build_padded_packet_sip() {
        let payload = vec![0xFF];
        let result = build_padded_packet(&payload, 4, Protocol::Sip);
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], 0xFF);
        assert_eq!(result[1], 0x20);
        assert_eq!(result[2], 0x20);
        assert_eq!(result[3], b'\r');
        assert_eq!(result[4], b'\n');
    }

    #[test]
    fn sip_padding_single_byte() {
        let mut data = [0u8; 1];
        apply_sip_padding(&mut data);
        assert_eq!(data[0], 0x20);
    }

    #[test]
    fn sip_padding_two_bytes() {
        let mut data = [0u8; 2];
        apply_sip_padding(&mut data);
        assert_eq!(data[0], b'\r');
        assert_eq!(data[1], b'\n');
    }
}
