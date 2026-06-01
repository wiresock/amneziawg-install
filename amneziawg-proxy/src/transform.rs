#[cfg(test)]
use bytes::{BufMut, BytesMut};

use crate::config::AwgParams;
use crate::responder::{classify_awg_packet, AwgPacketType, Protocol};

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
/// - **QUIC**: Packet-type-aware header form (see `apply_quic_padding_typed`).
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
        Protocol::Quic => apply_quic_padding_initial(data, pad_size),
        Protocol::Dns => apply_dns_padding(data, pad_size),
        Protocol::Stun => apply_stun_padding(data, pad_size),
        Protocol::Sip => apply_sip_padding(data, pad_size),
    }
}

/// Apply QUIC-style padding with the header form appropriate for the given
/// AWG packet type.
///
/// Real QUIC uses different header forms at each phase of the connection:
/// - **Handshake** (S2/S3, Handshake Response / Cookie Reply): long-header
///   Handshake (`0xE0..`)
/// - **1-RTT** (S1 HandshakeInit, S4 TransportData): short-header 1-RTT (`0x40..0x7F`)
///
/// S1 uses 1-RTT rather than Initial because QUIC Initial datagrams carry a
/// mandatory >=1200-byte minimum (RFC 9000 §14.1) that cannot be met within
/// the fixed `S1+148` AWG wire size without changing the shared framing
/// contract.  1-RTT short headers have no size minimum and are the dominant
/// packet type in any established QUIC session, so they are indistinguishable
/// from normal data traffic.
pub fn apply_quic_padding_typed(
    data: &mut [u8],
    pad_size: usize,
    pkt_type: AwgPacketType,
) {
    if pad_size == 0 || pad_size >= data.len() {
        return;
    }
    match pkt_type {
        // S1 (HandshakeInit) uses 1-RTT short header, not Initial long-header.
        // QUIC Initial requires >=1200-byte datagrams (RFC 9000 §14.1) which
        // cannot be satisfied within the fixed S1+148 AWG wire size.  1-RTT
        // short headers carry no size minimum and dominate real QUIC sessions.
        AwgPacketType::HandshakeInit | AwgPacketType::TransportData => {
            apply_quic_padding_short(data, pad_size)
        }
        AwgPacketType::HandshakeResponse | AwgPacketType::CookieReply => {
            apply_quic_padding_handshake(data, pad_size)
        }
    }
}

/// Apply AWG-aware padding transformation to an outgoing packet.
///
/// Classifies the packet using the S-offset / H-range pairs to determine its
/// type, then overwrites the leading S-padding prefix with protocol-conformant
/// filler. For QUIC, uses the packet-type-aware header form so that the
/// correct QUIC epoch (Initial / Handshake / 1-RTT) is emitted for each AWG
/// message type.
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

    if proto == Protocol::Quic {
        apply_quic_padding_typed(data, pad_size, pkt_type);
    } else {
        apply_padding(data, pad_size, proto);
    }
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

/// QUIC long-header Initial padding (S1 — Handshake Initiation).
///
/// Emits a QUIC v1 long-header Initial prologue (RFC 9000 §17.2.2):
///   - byte 0:    `0xC0 | PN_len` — form=1, fixed=1, type=00 (Initial),
///                  reserved bits cleared, random 2-bit Packet Number length.
///   - bytes 1-4: `0x00000001` — QUIC v1.
///   - byte 5:    DCID length in `4..=20`.
///   - bytes 6+:  pseudo-random high-entropy fill.
fn apply_quic_padding_initial(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    let mut state = fnv1a_seed(payload);

    let pn_len_bits = (state as u8) & 0x03;
    state = lcg_step(state);
    let dcid_len = ((state as u8) % 17) + 4; // 4..=20
    state = lcg_step(state);

    let header: [u8; 6] = [
        0xC0 | pn_len_bits, // long-header, fixed, Initial, pn_len
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        dcid_len,
    ];

    let copy_len = padding.len().min(header.len());
    padding[..copy_len].copy_from_slice(&header[..copy_len]);
    for byte in padding[copy_len..].iter_mut() {
        *byte = (state >> 16) as u8;
        state = lcg_step(state);
    }
}

/// QUIC long-header Handshake padding (S2/S3 — Handshake Response / Cookie Reply).
///
/// Emits a QUIC v1 long-header Handshake prologue (RFC 9000 §17.2.4):
///   - byte 0:    `0xE0 | PN_len` — form=1, fixed=1, type=10 (Handshake),
///                  reserved bits cleared, random PN length.
///   - bytes 1-4: `0x00000001` — QUIC v1.
///   - byte 5:    DCID length in `0..=20` (server may use 0-length DCID).
///   - bytes 6+:  pseudo-random high-entropy fill.
fn apply_quic_padding_handshake(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    let mut state = fnv1a_seed(payload);

    let pn_len_bits = (state as u8) & 0x03;
    state = lcg_step(state);
    let dcid_len = (state as u8) % 21; // 0..=20
    state = lcg_step(state);

    let header: [u8; 6] = [
        0xE0 | pn_len_bits, // long-header, fixed, Handshake, pn_len
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        dcid_len,
    ];

    let copy_len = padding.len().min(header.len());
    padding[..copy_len].copy_from_slice(&header[..copy_len]);
    for byte in padding[copy_len..].iter_mut() {
        *byte = (state >> 16) as u8;
        state = lcg_step(state);
    }
}

/// QUIC short-header 1-RTT padding (S4 — Transport Data).
///
/// Emits a QUIC 1-RTT short-header byte (RFC 9000 §17.3.1) followed by
/// pseudo-random bytes simulating an encrypted QUIC 1-RTT payload:
///   - byte 0: `0x40 | (spin<<5) | (reserved=00) | (key_phase<<2) | pn_len`
///     — form=0, fixed=1, random spin bit, random key-phase bit, random PN len.
///   - bytes 1+: pseudo-random (simulating DCID + encrypted payload).
///
/// Note: the short header has no version field or length field — the
/// remaining bytes after byte 0 are indistinguishable from random data,
/// which is the correct appearance for 1-RTT QUIC ciphertext.
fn apply_quic_padding_short(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    let mut state = fnv1a_seed(payload);

    // Short header first byte: 0 1 S R R K P P
    //   form=0, fixed=1, spin=random, reserved=00, key_phase=random, pn_len=random
    let spin = ((state >> 8) as u8) & 0x01;
    state = lcg_step(state);
    let key_phase = ((state >> 8) as u8) & 0x01;
    state = lcg_step(state);
    let pn_len_bits = (state as u8) & 0x03;
    state = lcg_step(state);

    padding[0] = 0x40 | (spin << 5) | (key_phase << 2) | pn_len_bits;

    for byte in padding[1..].iter_mut() {
        *byte = (state >> 16) as u8;
        state = lcg_step(state);
    }
}

/// FNV-1a seed from first 64 bytes of payload for PRNG initialisation.
fn fnv1a_seed(payload: &[u8]) -> u32 {
    let mut state: u32 = 0x811c_9dc5;
    for &b in payload.iter().take(64) {
        state ^= b as u32;
        state = state.wrapping_mul(0x0100_0193);
    }
    state
}

/// DNS-style padding: a realistic DNS response that consumes the entire padding
/// prefix with no bytes left outside the DNS message structure.
///
/// Layout (total = `pad_size` bytes):
///
/// ```text
/// [ Header 12 B ][ Question 5 B ][ Answer fixed 11 B ][ RDATA (pad_size-28) B ]
/// ```
///
/// - **Header** (12 B): `QR=1, RA=1, RCODE=NOERROR, QDCOUNT=1, ANCOUNT=1`.
///   Transaction ID derived from the first two payload bytes.
/// - **Question** (5 B): root-label QNAME `0x00` + `QTYPE A (1)` + `QCLASS IN (1)`.
/// - **Answer fixed prefix** (11 B): root-label NAME + `TYPE NULL (10)` +
///   `CLASS IN` + `TTL 60` + `RDLENGTH` = `pad_size - 28` (big-endian u16).
///   `TYPE NULL` (RFC 1035 §3.3.10) carries opaque RDATA of any length, so
///   the remaining `pad_size - 28` zero bytes are fully accounted for as RDATA.
///
/// Only sections that physically fit within `pad_size` are advertised:
/// - `QDCOUNT=1` only when `pad_size >= 17` (header 12 B + question 5 B)
/// - `ANCOUNT=1` only when `pad_size >= 28` (+ answer prefix 11 B)
///
/// This prevents parsers from being told about a section whose bytes are
/// absent, which would cause them to interpret AWG payload as DNS data.
/// Returns immediately when `pad_size == 0`.
fn apply_dns_padding(data: &mut [u8], pad_size: usize) {
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    // Transaction ID derived from first two payload bytes.
    let tx_hi = payload.first().copied().unwrap_or(0);
    let tx_lo = payload.get(1).copied().unwrap_or(0);

    // Only advertise sections that actually fit within pad_size.
    let qdcount: u8 = if pad_size >= 17 { 1 } else { 0 };
    let ancount: u8 = if pad_size >= 28 { 1 } else { 0 };

    // RDLENGTH = bytes remaining after the 28-byte fixed prefix.
    // Saturates to 0 when pad_size < 28 (ANCOUNT is 0 in that case).
    let rdlength: u16 = pad_size.saturating_sub(28).min(u16::MAX as usize) as u16;
    let [rl_hi, rl_lo] = rdlength.to_be_bytes();

    // Fixed DNS structure: 28 bytes (header 12 + question 5 + answer-prefix 11).
    // Any byte beyond index 27 is RDATA (zero-filled below) and is consumed by
    // the parser as part of the NULL RR — no trailing extraneous bytes.
    #[rustfmt::skip]
    let fixed: [u8; 28] = [
        // Header (12 bytes)
        tx_hi, tx_lo,           // Transaction ID
        0x80, 0x80,             // Flags: QR=1, opcode=0, RA=1, RCODE=NOERROR
        0x00, qdcount,          // QDCOUNT: 1 iff pad_size >= 17
        0x00, ancount,          // ANCOUNT: 1 iff pad_size >= 28
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
        // Question section (5 bytes; present only when pad_size >= 17)
        0x00,                   // QNAME: root label (empty = ".")
        0x00, 0x01,             // QTYPE  = A (1)
        0x00, 0x01,             // QCLASS = IN (1)
        // Answer fixed prefix (11 bytes; present only when pad_size >= 28)
        0x00,                   // NAME: root label
        0x00, 0x0a,             // TYPE  = NULL (10) — opaque RDATA, any length
        0x00, 0x01,             // CLASS = IN
        0x00, 0x00, 0x00, 0x3c, // TTL = 60 seconds
        rl_hi, rl_lo,           // RDLENGTH = pad_size - 28 (consumes rest of padding)
    ];

    let copy_len = std::cmp::min(padding.len(), fixed.len());
    padding[..copy_len].copy_from_slice(&fixed[..copy_len]);

    // RDATA: zero-fill the rest of the padding (bytes 28..pad_size).
    // These bytes are inside the NULL RR's RDATA field — not extraneous.
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
        // apply_padding with QUIC routes to the Initial variant
        let mut data = vec![0xAA; 20];
        let pad_size = 10;
        apply_padding(&mut data, pad_size, Protocol::Quic);

        // form=1, fixed=1 (0xC0)
        assert_eq!(data[0] & 0xC0, 0xC0, "Initial: long-header + fixed bit");
        // type=00 (Initial)
        assert_eq!(data[0] & 0x30, 0x00, "Initial: type bits must be 00");
        // reserved bits cleared
        assert_eq!(data[0] & 0x0C, 0x00, "Initial: reserved bits cleared");
        assert_eq!(&data[1..5], &[0x00, 0x00, 0x00, 0x01], "QUIC v1");
        assert!((4..=20).contains(&data[5]), "DCID len 4..=20");
        assert!(data[10..].iter().all(|&b| b == 0xAA), "payload untouched");
    }

    #[test]
    fn quic_padding_handshake_has_correct_header() {
        let mut data = vec![0xAA; 20];
        apply_quic_padding_handshake(&mut data, 10);

        // form=1, fixed=1, type=10 (Handshake) => byte & 0xF0 == 0xE0
        assert_eq!(data[0] & 0xF0, 0xE0, "Handshake: type bits must be E0..EF");
        // reserved bits cleared
        assert_eq!(data[0] & 0x0C, 0x00, "Handshake: reserved bits cleared");
        assert_eq!(&data[1..5], &[0x00, 0x00, 0x00, 0x01], "QUIC v1");
        assert!((0..=20).contains(&data[5]), "DCID len 0..=20");
        assert!(data[10..].iter().all(|&b| b == 0xAA), "payload untouched");
    }

    #[test]
    fn quic_padding_short_has_correct_header() {
        let mut data = vec![0xAA; 20];
        apply_quic_padding_short(&mut data, 10);

        // form=0, fixed=1 => byte & 0xC0 == 0x40
        assert_eq!(data[0] & 0xC0, 0x40, "1-RTT: form=0, fixed=1");
        // reserved bits (0x18) must be cleared per RFC 9000 §17.3
        assert_eq!(data[0] & 0x18, 0x00, "1-RTT: reserved bits cleared");
        assert!(data[10..].iter().all(|&b| b == 0xAA), "payload untouched");
    }

    #[test]
    fn quic_padding_varies_with_payload() {
        let mut data_a = [0u8; 20];
        let mut data_b = [0u8; 20];
        data_a[10..].fill(0xAA);
        data_b[10..].fill(0xBB);
        apply_padding(&mut data_a, 10, Protocol::Quic);
        apply_padding(&mut data_b, 10, Protocol::Quic);
        assert_ne!(&data_a[..10], &data_b[..10]);
    }

    // -- DNS padding tests --

    #[test]
    fn dns_padding_has_response_header() {
        // pad_size=40: RDLENGTH = 40-28 = 12, so entire padding is consumed as RDATA.
        let mut data = vec![0x00; 46];
        data[40..46].copy_from_slice(&[0xBB, 0xCC, 0x01, 0x02, 0x03, 0x04]);
        let pad_size = 40;
        apply_padding(&mut data, pad_size, Protocol::Dns);

        // Header: TX ID derived from payload bytes 0-1
        assert_eq!(data[0], 0xBB, "tx_hi from payload[0]");
        assert_eq!(data[1], 0xCC, "tx_lo from payload[1]");
        // Flags: QR=1, RA=1, RCODE=NOERROR
        assert_eq!(data[2] & 0x80, 0x80, "DNS QR bit should be set");
        assert_eq!(data[2], 0x80);
        assert_eq!(data[3], 0x80, "RA=1");
        // QDCOUNT=1, ANCOUNT=1
        assert_eq!(&data[4..6], &[0x00, 0x01], "QDCOUNT should be 1");
        assert_eq!(&data[6..8], &[0x00, 0x01], "ANCOUNT should be 1");
        // Question section: root label + QTYPE A + QCLASS IN
        assert_eq!(data[12], 0x00, "QNAME root label");
        assert_eq!(&data[13..15], &[0x00, 0x01], "QTYPE A");
        assert_eq!(&data[15..17], &[0x00, 0x01], "QCLASS IN");
        // Answer fixed prefix: root label + TYPE NULL(10) + CLASS IN + TTL 60
        assert_eq!(data[17], 0x00, "answer NAME root label");
        assert_eq!(&data[18..20], &[0x00, 0x0a], "answer TYPE NULL(10)");
        assert_eq!(&data[20..22], &[0x00, 0x01], "answer CLASS IN");
        assert_eq!(&data[22..26], &[0x00, 0x00, 0x00, 0x3c], "TTL 60s");
        // RDLENGTH = pad_size - 28 = 12, consuming remaining padding as RDATA
        assert_eq!(&data[26..28], &[0x00, 0x0c], "RDLENGTH = 12");
        // RDATA (bytes 28..40): zero-filled — inside NULL RR, not extraneous
        assert!(data[28..40].iter().all(|&b| b == 0x00), "RDATA zero-filled");
        // Payload untouched
        assert_eq!(&data[40..46], &[0xBB, 0xCC, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn dns_padding_short_fills_partial_header() {
        // Only 5 bytes of padding prefix — partial DNS header (header is 12 bytes).
        // RDLENGTH saturates to 0 (pad_size 5 < 28).
        let mut data = vec![0x00; 10];
        data[5..10].copy_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC, 0xCC]);
        let pad_size = 5;
        apply_padding(&mut data, pad_size, Protocol::Dns);

        assert_eq!(data[0], 0xCC, "tx_hi from payload[0]");
        assert_eq!(data[1], 0xCC, "tx_lo from payload[1]");
        assert_eq!(data[2], 0x80, "flags high: QR=1");
        assert_eq!(data[3], 0x80, "flags low: RA=1");
        assert_eq!(data[4], 0x00, "QDCOUNT high byte (partial — only 5 bytes fit)");
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

        // Prefix padding (first 10 bytes): 1-RTT short header (form=0, fixed=1)
        assert_eq!(pkt[0] & 0xC0, 0x40, "HandshakeInit must use 1-RTT short header");
        // Reserved bits must be cleared (RFC 9000 §17.3)
        assert_eq!(pkt[0] & 0x18, 0x00, "reserved bits cleared");
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
        // Use S2=40 (>= 28) so the full DNS structure fits without overlapping
        // the AWG header that starts at offset 40.
        let params = AwgParams { s2: 40, ..test_awg_params() };
        let padding_original = [0xFF; 40]; // S2 = 40
        let header = 350u32.to_le_bytes();
        let body = [0xDD; 92 - 4];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&padding_original);
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&body);
        assert_eq!(pkt.len(), 40 + 92);

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Dns);
        assert!(result);

        // DNS header
        assert_eq!(pkt[2] & 0x80, 0x80, "DNS QR=1");
        assert_eq!(&pkt[4..6], &[0x00, 0x01], "DNS QDCOUNT=1");
        assert_eq!(&pkt[6..8], &[0x00, 0x01], "DNS ANCOUNT=1");
        // Answer TYPE=NULL(10) and RDLENGTH=12 (40-28)
        assert_eq!(&pkt[18..20], &[0x00, 0x0a], "DNS TYPE=NULL");
        assert_eq!(&pkt[26..28], &[0x00, 0x0c], "DNS RDLENGTH=12");
        // AWG header and body start at offset 40, untouched
        assert_eq!(&pkt[40..44], &350u32.to_le_bytes());
        assert!(pkt[44..40 + 92].iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn awg_transform_handshake_response_quic_uses_handshake_header() {
        let params = test_awg_params();
        // S2 = 8 bytes padding + H2-range header (350) + 92-byte WG Handshake Response
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xFF; 8]);
        pkt.extend_from_slice(&350u32.to_le_bytes());
        pkt.extend_from_slice(&[0xDD; 88]);
        assert_eq!(pkt.len(), 8 + 92);

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic);
        assert!(result);

        // S2 padding must use Handshake long-header (0xE0..), NOT Initial (0xC0..)
        assert_eq!(pkt[0] & 0xF0, 0xE0, "HandshakeResponse must use QUIC Handshake header (0xE0..)");
        assert_eq!(pkt[0] & 0x0C, 0x00, "reserved bits cleared");
        assert_eq!(&pkt[1..5], &[0x00, 0x00, 0x00, 0x01], "QUIC v1");
        assert_eq!(&pkt[8..12], &350u32.to_le_bytes(), "AWG header untouched");
    }

    #[test]
    fn awg_transform_transport_data_quic_uses_short_header() {
        let params = test_awg_params();
        // S4 = 20 bytes padding + H4-range header (750) + 100-byte body
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xFF; 20]);
        pkt.extend_from_slice(&750u32.to_le_bytes());
        pkt.extend_from_slice(&[0xBB; 100]);

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic);
        assert!(result);

        // S4 padding must use 1-RTT short-header (form=0, fixed=1 => 0x40..0x7F)
        assert_eq!(pkt[0] & 0xC0, 0x40, "TransportData must use QUIC 1-RTT short-header (0x40..)");
        assert_eq!(pkt[0] & 0x18, 0x00, "reserved bits cleared");
        assert_eq!(&pkt[20..24], &750u32.to_le_bytes(), "AWG header untouched");
        assert!(pkt[24..124].iter().all(|&b| b == 0xBB), "body untouched");
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
