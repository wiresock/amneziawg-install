#[cfg(test)]
use bytes::{BufMut, BytesMut};

use crate::config::AwgParams;
use crate::responder::{classify_awg_packet, Protocol};

/// Apply protocol-conformant padding transformation to an outgoing packet.
///
/// AmneziaWG prepends random padding bytes (S1–S4) before the obfuscated
/// header. When imitating a specific protocol, we overwrite this leading
/// padding region (`data[0..pad_size]`) with protocol-conformant filler so
/// that DPI sees plausible traffic.
///
/// The `pad_size` parameter indicates how many leading bytes are padding.
/// Everything from `data[pad_size..]` is the real WireGuard payload (header +
/// body) and is used for PRNG seeding but never modified.
///
/// If `pad_size == 0` or `pad_size >= data.len()`, no transformation is
/// applied.
///
/// Protocol-specific padding strategies:
/// - **QUIC**: Pseudo-random bytes resembling encrypted QUIC payload (high
///   entropy), with a QUIC short-header form byte at the start.
/// - **DNS**: DNS response header structure (transaction ID, flags, section
///   counts) followed by zero-fill for EDNS OPT padding (RFC 7830).
/// - **STUN**: STUN Binding Indication header with the RFC 5389 magic cookie
///   and a deterministic transaction ID derived from the payload.
/// - **SIP**: SIP header continuation text (`Via:`, `Content-Length:`)
///   ending with CRLF.
pub fn apply_padding(data: &mut [u8], pad_size: usize, proto: Protocol) {
    if pad_size == 0 || pad_size >= data.len() {
        return;
    }

    match proto {
        Protocol::Quic => apply_quic_padding(data, pad_size),
        Protocol::Dns => apply_dns_padding(data, pad_size),
        Protocol::Stun => apply_stun_padding(data, pad_size),
        Protocol::Sip => apply_sip_padding(data, pad_size),
    }
}

/// Apply AWG-aware padding transformation to an outgoing packet.
///
/// Classifies the packet using the S-offset / H-range pairs to determine its
/// type, then overwrites the leading S-padding prefix with protocol-conformant
/// filler.
///
/// Returns `true` if the packet was classified and transformed, `false` if the
/// packet type could not be identified (e.g. junk packet) and was left
/// unchanged.
pub fn apply_awg_transform(data: &mut [u8], params: &AwgParams, proto: Protocol) -> bool {
    let pkt_type = match classify_awg_packet(data, params) {
        Some(t) => t,
        None => return false,
    };

    let pad_size = pkt_type.padding_size(params);
    let total = data.len();

    if pad_size == 0 || pad_size >= total {
        return false;
    }

    apply_padding(data, pad_size, proto);
    true
}

/// Build a complete packet with protocol-conformant padding prepended.
///
/// Takes the original payload and prepends `pad_len` bytes of
/// protocol-conformant padding.  `pad_len` is silently clamped to
/// `MAX_PAD_LEN` (1024) to prevent excessive allocation — AmneziaWG
/// S-values are typically well below this limit.
#[cfg(test)]
const MAX_PAD_LEN: usize = 1_024;

#[cfg(test)]
pub(crate) fn build_padded_packet(payload: &[u8], pad_len: usize, proto: Protocol) -> BytesMut {
    let pad_len = pad_len.min(MAX_PAD_LEN);
    let mut buf = BytesMut::with_capacity(pad_len + payload.len());

    // Prepend padding bytes (initially zeros) before the payload
    buf.put_bytes(0, pad_len);
    buf.put_slice(payload);

    if pad_len == 0 {
        return buf;
    }

    apply_padding(&mut buf[..], pad_len, proto);

    buf
}

// ---------------------------------------------------------------------------
// Protocol-specific padding implementations
// ---------------------------------------------------------------------------

/// QUIC-style padding: long-header Initial bytes followed by pseudo-random
/// "encrypted" payload.
///
/// The padding region is overwritten with a QUIC v1 long-header Initial
/// prologue (RFC 9000 §17.2.2):
///   - byte 0:    `0xC0 | PN_len` — long-header form, fixed bit, Initial type,
///                  reserved bits cleared, random 2-bit Packet Number length.
///   - bytes 1-4: `0x00000001`     — QUIC v1 (Draft 29 and earlier are obsolete
///                  and would be a detectable fingerprint).
///   - byte 5:    DCID length in `4..=20` (RFC 9000 §17.2 caps at 20; real
///                  client Initials always carry a non-empty DCID).
///   - bytes 6+:  pseudo-random, seeded from the encrypted WG payload that
///                  follows the padding — high-entropy bytes resembling
///                  encrypted QUIC CRYPTO/PADDING frames.
///
/// This aligns the proxy with the WireSock client's `protocol_aware_padding_generator`
/// (`amnezia.h`), which also emits a long-header Initial prologue. A short-header
/// 1-RTT form would be more realistic for `S4` transport-phase padding, but
/// emitting *different* QUIC header forms on the two ends of the same conversation
/// is itself a stronger fingerprint than picking one form and using it consistently.
fn apply_quic_padding(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    // Seed PRNG from payload bytes (after the padding) using FNV-1a hash
    let mut state: u32 = 0x811c_9dc5;
    for &b in payload.iter().take(64) {
        state ^= b as u32;
        state = state.wrapping_mul(0x0100_0193);
    }

    // QUIC long-header Initial first byte: 1-1-0-0-0-0-PN-PN
    let pn_len_bits = (state as u8) & 0x03;
    state = lcg_step(state);
    // DCID length in [4, 20] — typical client Initial range. Real clients
    // never send DCID length 0 in their first Initial.
    let dcid_len = ((state as u8) % 17) + 4;
    state = lcg_step(state);

    let header: [u8; 6] = [
        0xC0 | pn_len_bits,
        0x00,
        0x00,
        0x00,
        0x01, // QUIC v1
        dcid_len,
    ];

    let copy_len = std::cmp::min(padding.len(), header.len());
    padding[..copy_len].copy_from_slice(&header[..copy_len]);

    // Remaining bytes: pseudo-random, simulating encrypted QUIC payload
    for byte in padding[copy_len..].iter_mut() {
        *byte = (state >> 16) as u8;
        state = lcg_step(state);
    }
}

/// DNS-style padding: minimal DNS response header followed by zero padding.
///
/// Creates a plausible DNS response structure:
/// - Transaction ID derived from the packet payload (which follows the padding)
/// - Standard response flags (QR=1, RA=1, RCODE=NOERROR); RD is left clear
///   because this is padding filler, not an echo of a real client query.
/// - Remaining bytes are zero-filled for generic padding
fn apply_dns_padding(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    // Derive transaction ID from first two payload bytes (H header)
    let tx_hi = payload.first().copied().unwrap_or(0);
    let tx_lo = payload.get(1).copied().unwrap_or(0);

    // DNS response header (12 bytes)
    let header: [u8; 12] = [
        tx_hi, tx_lo, // Transaction ID
        0x80, 0x80, // Flags: QR=1, RA=1, RCODE=NOERROR (RD not set — no query to echo)
        0x00, 0x00, // QDCOUNT = 0 (no question section emitted)
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0 (no additional records emitted)
    ];

    let copy_len = std::cmp::min(padding.len(), header.len());
    padding[..copy_len].copy_from_slice(&header[..copy_len]);

    // Rest: zero-fill (generic padding content)
    for byte in padding[copy_len..].iter_mut() {
        *byte = 0x00;
    }
}

/// STUN-style padding: Binding Indication header with deterministic transaction ID.
///
/// A strict STUN parser validates the whole UDP datagram length, while the proxy
/// can only rewrite the AWG padding prefix and must leave the encrypted payload
/// untouched. The leading bytes therefore mimic the STUN header shape that DPI
/// heuristics look for: message type, zero length, magic cookie, and 96-bit
/// transaction ID.
fn apply_stun_padding(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    let mut state: u32 = 0x811c_9dc5;
    for &b in payload.iter().take(64) {
        state ^= b as u32;
        state = state.wrapping_mul(0x0100_0193);
    }

    let mut header = [0u8; 20];
    header[0..2].copy_from_slice(&0x0011u16.to_be_bytes()); // Binding Indication
    header[2..4].copy_from_slice(&0u16.to_be_bytes()); // no attributes in the header
    header[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
    for chunk in header[8..20].chunks_mut(4) {
        chunk.copy_from_slice(&state.to_be_bytes());
        state = lcg_step(state);
    }

    let copy_len = std::cmp::min(padding.len(), header.len());
    padding[..copy_len].copy_from_slice(&header[..copy_len]);

    for byte in padding[copy_len..].iter_mut() {
        *byte = 0x00;
    }
}

/// SIP-style padding: SIP response status line + header continuation text.
///
/// The padded packet is being emitted by the proxy *toward the client*, so it
/// is the server side of the conversation. Real SIP responses start with a
/// `SIP/2.0 <status>` line (RFC 3261 §7.2), not with a request method or bare
/// header. Filling the padding with a `SIP/2.0 100 Trying` status line plus a
/// generic Via/Content-Length tail therefore matches the directionality of the
/// flow: client-side AmneziaWG padding (WireSock `protocol_aware_padding_generator`)
/// emits a `METHOD sip:...` request line, and proxy-side padding emits a
/// `SIP/2.0 ...` response line.
///
/// The padding always ends with CRLF when at least two bytes are available.
fn apply_sip_padding(data: &mut [u8], pad_size: usize) {
    let padding = &mut data[..pad_size];
    if padding.is_empty() {
        return;
    }

    let len = padding.len();

    // SIP 100 Trying response with generic Via and Content-Length headers.
    // Starts with the response status line so the directionality (server →
    // client) matches what a DPI engine expects for traffic emitted by the
    // proxy. `100 Trying` is the most common provisional response, never
    // contains a body, and elicits no client retransmission.
    static SIP_FILL: &[u8] = b"SIP/2.0 100 Trying\r\nVia: SIP/2.0/UDP proxy\r\nContent-Length: 0\r\n";

    // Fill padding by cycling through the SIP text
    let fill_len = SIP_FILL.len();
    let mut pos = 0;
    while pos < len {
        let remaining = len - pos;
        let chunk = std::cmp::min(remaining, fill_len);
        padding[pos..pos + chunk].copy_from_slice(&SIP_FILL[..chunk]);
        pos += chunk;
    }

    // Ensure the padding ends with \r\n if at least 2 bytes
    if len >= 2 {
        padding[len - 2] = b'\r';
        padding[len - 1] = b'\n';
    }
}

/// Linear congruential generator step (glibc constants).
fn lcg_step(state: u32) -> u32 {
    state.wrapping_mul(1_103_515_245).wrapping_add(12345)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HRange;

    // -- QUIC padding tests --

    #[test]
    fn quic_padding_has_header_and_entropy() {
        // 10 bytes padding prefix + 10 bytes payload
        let mut data = vec![0xAA; 20];
        let pad_size = 10;
        apply_padding(&mut data, pad_size, Protocol::Quic);

        // First padding byte has QUIC long-header form bit (0x80) + fixed bit (0x40)
        assert_eq!(
            data[0] & 0xC0,
            0xC0,
            "QUIC padding first byte should have long-header form + fixed bit"
        );
        // Packet type bits (0x30) must indicate Initial (00)
        assert_eq!(
            data[0] & 0x30,
            0x00,
            "QUIC padding first byte should encode the Initial packet type"
        );
        // Reserved bits (0x0C) must be cleared per RFC 9000 §17.2
        assert_eq!(
            data[0] & 0x0C,
            0x00,
            "QUIC padding first byte must have reserved bits cleared"
        );
        // Bytes 1..5 must be QUIC v1 version field (0x00000001)
        assert_eq!(&data[1..5], &[0x00, 0x00, 0x00, 0x01]);
        // Byte 5 is DCID length, expected to be in the realistic 4..=20 range
        assert!((4..=20).contains(&data[5]));
        // Payload (last 10 bytes) untouched
        assert!(data[10..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn quic_padding_varies_with_payload() {
        // Two different payloads should produce different padding
        let mut data_a = [0u8; 20];
        let mut data_b = [0u8; 20];
        // Set different payload content (bytes 10..20)
        data_a[10..].fill(0xAA);
        data_b[10..].fill(0xBB);
        apply_padding(&mut data_a, 10, Protocol::Quic);
        apply_padding(&mut data_b, 10, Protocol::Quic);
        // Padding regions (first 10 bytes) should differ (different seeds)
        assert_ne!(&data_a[..10], &data_b[..10]);
    }

    // -- DNS padding tests --

    #[test]
    fn dns_padding_has_response_header() {
        // 20 bytes padding prefix + 4 bytes payload
        let mut data = vec![0x00; 24];
        data[20..24].copy_from_slice(&[0xBB, 0xBB, 0xBB, 0xBB]);
        let pad_size = 20;
        apply_padding(&mut data, pad_size, Protocol::Dns);

        // DNS response header: TX ID derived from payload bytes
        assert_eq!(data[0], 0xBB); // tx_hi from payload[0]
        assert_eq!(data[1], 0xBB); // tx_lo from payload[1]
                                   // Flags: QR=1 (high bit of flags byte)
        assert_eq!(data[2] & 0x80, 0x80, "DNS QR bit should be set");
        assert_eq!(data[2], 0x80); // QR=1, RD=0 (no query to echo)
        assert_eq!(data[3], 0x80); // RA=1
                                   // QDCOUNT = 0
        assert_eq!(data[4], 0x00);
        assert_eq!(data[5], 0x00);
        // After header (12 bytes), rest of padding should be zeros
        assert!(data[12..20].iter().all(|&b| b == 0x00));
        // Payload untouched
        assert!(data[20..24].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn dns_padding_short_fills_partial_header() {
        // Only 5 bytes of padding prefix — should fill what fits from DNS header
        let mut data = vec![0x00; 10];
        data[5..10].copy_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC, 0xCC]);
        let pad_size = 5;
        apply_padding(&mut data, pad_size, Protocol::Dns);

        assert_eq!(data[0], 0xCC); // tx_hi from payload[0]
        assert_eq!(data[1], 0xCC); // tx_lo from payload[1]
        assert_eq!(data[2], 0x80); // flags high: QR=1, RD=0
        assert_eq!(data[3], 0x80); // flags low: RA=1
        assert_eq!(data[4], 0x00); // QDCOUNT high
                                   // Payload untouched
        assert!(data[5..10].iter().all(|&b| b == 0xCC));
    }

    // -- STUN padding tests --

    #[test]
    fn stun_padding_has_binding_indication_header() {
        let mut data = vec![0x00; 28];
        data[20..28].copy_from_slice(&[0xAB; 8]);
        apply_padding(&mut data, 20, Protocol::Stun);

        assert_eq!(&data[0..2], &0x0011u16.to_be_bytes());
        assert_eq!(&data[2..4], &0u16.to_be_bytes());
        assert_eq!(&data[4..8], &0x2112_A442u32.to_be_bytes());
        assert!(data[8..20].iter().any(|&b| b != 0x00));
        assert!(data[20..28].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn stun_padding_short_fills_partial_header() {
        let mut data = vec![0x00; 10];
        data[7..10].fill(0xCC);
        apply_padding(&mut data, 7, Protocol::Stun);

        assert_eq!(&data[0..2], &0x0011u16.to_be_bytes());
        assert_eq!(&data[2..4], &0u16.to_be_bytes());
        assert_eq!(&data[4..7], &0x2112_A442u32.to_be_bytes()[..3]);
        assert!(data[7..10].iter().all(|&b| b == 0xCC));
    }

    // -- SIP padding tests --

    #[test]
    fn sip_padding_has_sip_headers() {
        // 50 bytes padding prefix + 10 bytes payload
        let mut data = vec![0x00; 60];
        data[50..60].fill(0xCC);
        let pad_size = 50;
        apply_padding(&mut data, pad_size, Protocol::Sip);

        // Padding starts with the SIP/2.0 response status line
        let padding = &data[..50];
        assert!(padding.starts_with(b"SIP/2.0 100 Trying"));
        // Padding ends with \r\n
        assert_eq!(data[48], b'\r');
        assert_eq!(data[49], b'\n');
        // Payload untouched
        assert!(data[50..60].iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn sip_padding_single_byte() {
        let mut data = [0x00, 0xAA]; // 1 byte padding + 1 byte payload
        apply_padding(&mut data, 1, Protocol::Sip);
        assert_eq!(data[0], b'S'); // first byte of "SIP/2.0 100 Trying\r\n..."
        assert_eq!(data[1], 0xAA); // payload untouched
    }

    #[test]
    fn sip_padding_two_bytes() {
        let mut data = [0x00, 0x00, 0xAA]; // 2 bytes padding + 1 byte payload
        apply_padding(&mut data, 2, Protocol::Sip);
        // Two bytes: ends with \r\n
        assert_eq!(data[0], b'\r');
        assert_eq!(data[1], b'\n');
        assert_eq!(data[2], 0xAA); // payload untouched
    }

    // -- General padding tests --

    #[test]
    fn no_padding_when_pad_size_zero() {
        let mut data = vec![0xDD; 10];
        apply_padding(&mut data, 0, Protocol::Quic);
        assert!(data.iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn no_padding_when_pad_size_equals_len() {
        let mut data = vec![0xDD; 10];
        apply_padding(&mut data, 10, Protocol::Quic);
        assert!(data.iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn no_padding_when_pad_size_exceeds_len() {
        let mut data = vec![0xEE; 10];
        apply_padding(&mut data, 15, Protocol::Dns);
        assert!(data.iter().all(|&b| b == 0xEE));
    }

    // -- Build padded packet tests --

    #[test]
    fn build_padded_packet_quic() {
        let payload = vec![0x01, 0x02, 0x03];
        let result = build_padded_packet(&payload, 5, Protocol::Quic);
        assert_eq!(result.len(), 8);
        // Last 3 bytes are payload (prepended padding)
        assert_eq!(&result[5..8], &[0x01, 0x02, 0x03]);
        // First padding byte is QUIC long-header Initial form
        assert_eq!(result[0] & 0xC0, 0xC0);
        assert_eq!(result[0] & 0x30, 0x00);
        // Reserved bits must be cleared
        assert_eq!(result[0] & 0x0C, 0x00);
        // Version field starts inside the 5-byte padding (bytes 1..5)
        assert_eq!(&result[1..5], &[0x00, 0x00, 0x00, 0x01]);
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
        // Last byte is payload
        assert_eq!(result[4], 0xFF);
        // SIP response status-line fill, last 2 bytes of padding overridden with \r\n
        assert_eq!(result[0], b'S');
        assert_eq!(result[1], b'I');
        assert_eq!(result[2], b'\r');
        assert_eq!(result[3], b'\n');
    }

    #[test]
    fn build_padded_packet_dns() {
        let payload = vec![0x42, 0x43, 0x44];
        let result = build_padded_packet(&payload, 12, Protocol::Dns);
        assert_eq!(result.len(), 15);
        // Last 3 bytes are payload
        assert_eq!(&result[12..15], &[0x42, 0x43, 0x44]);
        // DNS header: TX ID from payload bytes 0-1
        assert_eq!(result[0], 0x42); // tx_hi
        assert_eq!(result[1], 0x43); // tx_lo
                                     // Flags: QR=1, RD=0
        assert_eq!(result[2] & 0x80, 0x80);
        assert_eq!(
            result[2] & 0x01,
            0x00,
            "RD must not be set in padding filler"
        );
    }

    #[test]
    fn build_padded_packet_stun() {
        let payload = vec![0x42, 0x43, 0x44, 0x45];
        let result = build_padded_packet(&payload, 20, Protocol::Stun);
        assert_eq!(result.len(), 24);
        assert_eq!(&result[20..24], &[0x42, 0x43, 0x44, 0x45]);
        assert_eq!(&result[0..2], &0x0011u16.to_be_bytes());
        assert_eq!(&result[4..8], &0x2112_A442u32.to_be_bytes());
    }

    // -- AWG-aware transform tests --

    fn test_awg_params() -> AwgParams {
        AwgParams {
            jc: 5,
            jmin: 50,
            jmax: 1000,
            s1: 10,
            s2: 8,
            s3: 6,
            s4: 20,
            h1: HRange { min: 100, max: 200 },
            h2: HRange { min: 300, max: 400 },
            h3: HRange { min: 500, max: 600 },
            h4: HRange { min: 700, max: 800 },
        }
    }

    #[test]
    fn awg_transform_handshake_init_quic() {
        let params = test_awg_params();
        // Build a packet: S1 prefix padding + H1-range header + 148-byte WG message
        let padding_original = [0xFF; 10]; // S1 = 10 bytes of random prefix padding
        let header = 150u32.to_le_bytes();
        let body = [0xAA; 148 - 4]; // 148 total message size includes 4-byte header
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&padding_original);
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&body);
        assert_eq!(pkt.len(), 10 + 148); // S1 + WG message size

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic);
        assert!(result);

        // Prefix padding (first 10 bytes): long-header Initial first byte
        assert_eq!(pkt[0] & 0xC0, 0xC0);
        assert_eq!(pkt[0] & 0x30, 0x00);
        // Reserved bits must be cleared
        assert_eq!(pkt[0] & 0x0C, 0x00);
        // Bytes 1..5 must be QUIC v1
        assert_eq!(&pkt[1..5], &[0x00, 0x00, 0x00, 0x01]);
        // Byte 5 carries DCID length in the realistic range
        assert!((4..=20).contains(&pkt[5]));
        // Header should be untouched
        assert_eq!(&pkt[10..14], &150u32.to_le_bytes());
        // Body should be untouched
        assert!(pkt[14..10 + 148].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn awg_transform_transport_data_sip() {
        let params = test_awg_params();
        // S4 = 20 bytes prefix + H4-range header + body
        let padding_original = [0xFF; 20]; // S4 = 20
        let header = 750u32.to_le_bytes();
        let body = [0xBB; 100];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&padding_original);
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&body);

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Sip);
        assert!(result);

        // Prefix padding should start with the SIP response status line
        assert!(pkt[..20].starts_with(b"SIP/2.0 100 Trying"));
        // Padding ends with \r\n
        assert_eq!(pkt[18], b'\r');
        assert_eq!(pkt[19], b'\n');
        // Header + body should be untouched
        assert_eq!(&pkt[20..24], &750u32.to_le_bytes());
        assert!(pkt[24..124].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn awg_transform_handshake_response_dns() {
        let params = test_awg_params();
        // Build a packet: S2 prefix padding + H2-range header + 92-byte WG message
        let padding_original = [0xFF; 8]; // S2 = 8 bytes of random prefix padding
        let header = 350u32.to_le_bytes();
        let body = [0xDD; 92 - 4]; // 92 total message size includes 4-byte header
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&padding_original);
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&body);
        assert_eq!(pkt.len(), 8 + 92); // S2 + WG message size

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Dns);
        assert!(result);

        // Prefix padding (first 8 bytes): DNS header structure
        // Flags byte at offset 2 should have QR=1
        assert_eq!(pkt[2] & 0x80, 0x80);
        // Header should be untouched
        assert_eq!(&pkt[8..12], &350u32.to_le_bytes());
        // Body should be untouched
        assert!(pkt[12..8 + 92].iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn awg_transform_transport_data_stun() {
        let params = test_awg_params();
        let padding_original = [0xFF; 20];
        let header = 750u32.to_le_bytes();
        let body = [0xBB; 100];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&padding_original);
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&body);

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Stun);
        assert!(result);

        assert_eq!(&pkt[0..2], &0x0011u16.to_be_bytes());
        assert_eq!(&pkt[4..8], &0x2112_A442u32.to_be_bytes());
        assert_eq!(&pkt[20..24], &750u32.to_le_bytes());
        assert!(pkt[24..124].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn awg_transform_unknown_packet() {
        let params = test_awg_params();
        let mut pkt = vec![0xFF; 50]; // No valid H-range header at any S offset
        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic);
        assert!(!result);
        // Packet should be unchanged
        assert!(pkt.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn awg_transform_padding_larger_than_packet() {
        let params = AwgParams {
            s1: 100, // padding larger than packet
            ..test_awg_params()
        };
        // Packet too short for S1(100) + 4 header bytes → can't classify
        let header = 150u32.to_le_bytes();
        let mut pkt = Vec::from(header); // only 4 bytes
        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic);
        assert!(!result); // can't classify (too short for S1 offset)
    }
}
