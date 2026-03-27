use bytes::{Bytes, BytesMut, BufMut};

use crate::config::AwgParams;

/// Detected imitation protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Quic,
    Dns,
    Sip,
}

/// AmneziaWG packet type, identified by matching the first 4 bytes (header)
/// against the H1–H4 ranges from the AWG configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwgPacketType {
    /// Handshake Initiation (WG type 1), padded with S1 bytes.
    HandshakeInit,
    /// Handshake Response (WG type 2), padded with S2 bytes.
    HandshakeResponse,
    /// Cookie Reply (WG type 3), padded with S3 bytes.
    CookieReply,
    /// Transport Data (WG type 4), padded with S4 bytes.
    TransportData,
}

impl AwgPacketType {
    /// Return the number of padding bytes (S-value) for this packet type.
    pub fn padding_size(&self, params: &AwgParams) -> usize {
        match self {
            AwgPacketType::HandshakeInit => params.s1 as usize,
            AwgPacketType::HandshakeResponse => params.s2 as usize,
            AwgPacketType::CookieReply => params.s3 as usize,
            AwgPacketType::TransportData => params.s4 as usize,
        }
    }
}

/// Classify an AmneziaWG packet by reading the first 4 bytes as a little-endian
/// u32 and checking which H range it falls into.
///
/// Returns `None` if the packet is too short or the header value doesn't match
/// any configured H range (e.g. junk packet or non-AWG traffic).
pub fn classify_awg_packet(data: &[u8], params: &AwgParams) -> Option<AwgPacketType> {
    if data.len() < 4 {
        return None;
    }

    let header = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    if params.h1.contains(header) {
        Some(AwgPacketType::HandshakeInit)
    } else if params.h2.contains(header) {
        Some(AwgPacketType::HandshakeResponse)
    } else if params.h3.contains(header) {
        Some(AwgPacketType::CookieReply)
    } else if params.h4.contains(header) {
        Some(AwgPacketType::TransportData)
    } else {
        None
    }
}

/// Detect whether an incoming packet looks like a QUIC, DNS, or SIP initiation.
///
/// Heuristics:
/// - **QUIC**: First byte has the long-header form bit set (0x80) and the
///   fixed bit set (0x40), i.e. `(byte & 0xC0) == 0xC0`, which matches
///   QUIC Initial packets (RFC 9000 §17.2).
/// - **DNS**: At least 12 bytes, bytes 2-3 encode flags with QR=0 (query)
///   and a standard query opcode, i.e. `(flags & 0xF800) == 0x0000`, plus
///   QDCOUNT >= 1 in bytes 4-5 (RFC 1035 §4.1.1).
/// - **SIP**: Starts with ASCII `SIP/` or a SIP method keyword followed by a
///   space (RFC 3261 §7). We check for `REGISTER `, `INVITE `, `OPTIONS `,
///   and `SIP/` prefixes.
pub fn detect_protocol(data: &[u8]) -> Option<Protocol> {
    if data.is_empty() {
        return None;
    }

    // QUIC long header: form bit (0x80) + fixed bit (0x40) must both be set,
    // plus additional invariants to avoid false positives on AWG packets
    // whose random H-range headers happen to have those bits set.
    //   - Minimum 7 bytes (1 header + 4 version + 1 DCID len + 1 SCID len)
    //   - DCID length ≤ 20 (RFC 9000 §17.2)
    //   - Packet contains SCID length field
    //   - SCID length ≤ 20
    if data.len() >= 7 && data[0] & 0xC0 == 0xC0 {
        let dcid_len = data[5] as usize;
        if dcid_len <= 20 {
            let scid_len_offset = 6 + dcid_len;
            if data.len() > scid_len_offset {
                let scid_len = data[scid_len_offset] as usize;
                if scid_len <= 20 {
                    return Some(Protocol::Quic);
                }
            }
        }
    }

    // DNS query: >= 12 bytes, QR=0, standard opcode, QDCOUNT >= 1
    if data.len() >= 12 {
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if flags & 0xF800 == 0x0000 && qdcount >= 1 {
            return Some(Protocol::Dns);
        }
    }

    // SIP: starts with known SIP method or version prefix
    if data.len() >= 4 {
        let prefix = &data[..std::cmp::min(data.len(), 10)];
        if let Ok(text) = std::str::from_utf8(prefix) {
            let upper = text.to_uppercase();
            if upper.starts_with("SIP/")
                || upper.starts_with("REGISTER ")
                || upper.starts_with("INVITE ")
                || upper.starts_with("OPTIONS ")
            {
                return Some(Protocol::Sip);
            }
        }
    }

    None
}

/// Generate a response packet that matches the detected protocol.
///
/// - **QUIC**: Builds a minimal QUIC Version Negotiation packet
///   (long header, zero version, echoes the incoming DCID/SCID).
/// - **DNS**: Builds a standard SERVFAIL response echoing the query ID.
/// - **SIP**: Builds a `SIP/2.0 100 Trying` response.
pub fn generate_response(proto: Protocol, incoming: &[u8]) -> Bytes {
    match proto {
        Protocol::Quic => generate_quic_version_negotiation(incoming),
        Protocol::Dns => generate_dns_servfail(incoming),
        Protocol::Sip => generate_sip_trying(incoming),
    }
}

/// QUIC Version Negotiation (RFC 9000 §17.2.1):
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+
///  |1|  Unused (7) |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         Version (32) = 0                       |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | DCID Len (8)  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |               Destination Connection ID (0..2040)              |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | SCID Len (8)  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                 Source Connection ID (0..2040)                  |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          Supported Version 1 (32)                              |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
fn generate_quic_version_negotiation(incoming: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(64);

    // First byte: long header indicator + fixed bit, preserving incoming type bits
    let first_byte = if let Some(&b0) = incoming.first() {
        b0 | 0xC0
    } else {
        0xC0
    };
    buf.put_u8(first_byte);
    // Version = 0 (version negotiation)
    buf.put_u32(0);

    // Parse incoming DCID and SCID
    if incoming.len() >= 6 {
        let dcid_len = incoming[5] as usize;
        let dcid_end = 6 + dcid_len;

        if incoming.len() > dcid_end {
            let scid_len = incoming[dcid_end] as usize;
            let scid_end = dcid_end + 1 + scid_len;

            // In version negotiation, swap DCID and SCID from the incoming packet
            // Response DCID = incoming SCID, Response SCID = incoming DCID
            if incoming.len() >= scid_end {
                let incoming_dcid = &incoming[6..dcid_end];
                let incoming_scid = &incoming[dcid_end + 1..scid_end];

                buf.put_u8(scid_len as u8);
                buf.put_slice(incoming_scid);
                buf.put_u8(dcid_len as u8);
                buf.put_slice(incoming_dcid);
            } else {
                buf.put_u8(0);
                buf.put_u8(0);
            }
        } else {
            buf.put_u8(0);
            buf.put_u8(0);
        }
    } else {
        buf.put_u8(0);
        buf.put_u8(0);
    }

    // Supported version: QUIC v1 (0x00000001)
    buf.put_u32(0x00000001);

    buf.freeze()
}

/// DNS SERVFAIL response (RFC 1035 §4.1):
/// Echoes the transaction ID and question section, sets QR=1, RCODE=2
/// (SERVFAIL).
///
/// Echoing the question section back is required by RFC 1035 §4.1.1 and makes
/// the response indistinguishable from a real recursive resolver failure.
fn generate_dns_servfail(incoming: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(512);

    // Transaction ID (echo from query)
    if incoming.len() >= 2 {
        buf.put_slice(&incoming[..2]);
    } else {
        buf.put_u16(0);
    }

    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=2 (SERVFAIL)
    buf.put_u16(0x8182);
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    buf.put_u16(1);
    buf.put_u16(0);
    buf.put_u16(0);
    buf.put_u16(0);

    // Echo the question section from the incoming query if available.
    // The question section starts at byte 12 in a DNS message and consists
    // of: QNAME (sequence of labels ending with 0) + QTYPE (2) + QCLASS (2).
    if incoming.len() > 12 {
        let mut pos = 12;
        // Walk QNAME labels until root label (0) or end of packet
        while pos < incoming.len() {
            let label_len = incoming[pos] as usize;
            if label_len == 0 {
                // Include root label (0) + QTYPE (2) + QCLASS (2) = 5 bytes
                let end = std::cmp::min(pos + 5, incoming.len());
                buf.put_slice(&incoming[12..end]);
                break;
            }
            pos += 1 + label_len;
            if pos > incoming.len() {
                break;
            }
        }
    }

    buf.freeze()
}

/// SIP 100 Trying response (RFC 3261 §8.2.6).
///
/// A proper 100 Trying MUST echo the Via, From, To, Call-ID, and CSeq headers
/// from the incoming request. We parse and echo these when available; this
/// makes the response indistinguishable from a real SIP proxy.
fn generate_sip_trying(incoming: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(512);
    buf.put_slice(b"SIP/2.0 100 Trying\r\n");

    // Echo key SIP headers from the incoming request for realism.
    if let Ok(text) = std::str::from_utf8(incoming) {
        let echo_prefixes = ["via:", "from:", "to:", "call-id:", "cseq:"];
        for line in text.lines() {
            let trimmed = line.trim();
            let lower = trimmed.to_lowercase();
            for &prefix in &echo_prefixes {
                if lower.starts_with(prefix) {
                    buf.put_slice(trimmed.as_bytes());
                    buf.put_slice(b"\r\n");
                    break;
                }
            }
        }
    }

    buf.put_slice(b"Content-Length: 0\r\n\r\n");
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HRange;

    // -- imitation protocol detection tests --

    #[test]
    fn detect_quic_initial() {
        // QUIC long header: first byte = 0xC3 (Initial packet)
        let mut pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01]; // version 1
        pkt.push(8); // DCID len
        pkt.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // DCID
        pkt.push(0); // SCID len
        assert_eq!(detect_protocol(&pkt), Some(Protocol::Quic));
    }

    #[test]
    fn detect_dns_query() {
        // Standard DNS query
        let mut pkt = vec![0x00u8; 12];
        pkt[0] = 0xAB; // TX ID high
        pkt[1] = 0xCD; // TX ID low
        pkt[2] = 0x01; // flags: RD=1, QR=0
        pkt[3] = 0x00;
        pkt[4] = 0x00; // QDCOUNT = 1
        pkt[5] = 0x01;
        assert_eq!(detect_protocol(&pkt), Some(Protocol::Dns));
    }

    #[test]
    fn detect_sip_invite() {
        let pkt = b"INVITE sip:user@example.com SIP/2.0\r\n";
        assert_eq!(detect_protocol(pkt), Some(Protocol::Sip));
    }

    #[test]
    fn detect_sip_response() {
        let pkt = b"SIP/2.0 200 OK\r\n";
        assert_eq!(detect_protocol(pkt), Some(Protocol::Sip));
    }

    #[test]
    fn detect_unknown() {
        let pkt = [0x01, 0x02, 0x03];
        assert_eq!(detect_protocol(&pkt), None);
    }

    #[test]
    fn detect_empty() {
        assert_eq!(detect_protocol(&[]), None);
    }

    #[test]
    fn detect_quic_rejects_short_packet() {
        // Too short for valid QUIC long header (< 7 bytes)
        let pkt = [0xC3, 0x00, 0x00, 0x00, 0x01, 0x04];
        assert_eq!(detect_protocol(&pkt), None);
    }

    #[test]
    fn detect_quic_rejects_oversized_dcid() {
        // DCID length > 20 is invalid per RFC 9000 §17.2.
        // Byte 2 is set to 0x80 so that the DNS detection heuristic
        // (flags & 0xF800 == 0x0000) fails, preventing a false DNS match.
        let mut pkt = vec![0xC3u8, 0x00, 0x80, 0x00, 0x01];
        pkt.push(21); // DCID len > 20
        pkt.extend(std::iter::repeat(0xAA).take(21)); // DCID
        pkt.push(0); // SCID len
        assert_eq!(detect_protocol(&pkt), None);
    }

    #[test]
    fn detect_quic_rejects_oversized_scid() {
        // SCID length > 20 is invalid per RFC 9000 §17.2.
        // Same byte-2 trick as above to avoid DNS false positive.
        let mut pkt = vec![0xC3u8, 0x00, 0x80, 0x00, 0x01];
        pkt.push(4); // DCID len
        pkt.extend_from_slice(&[1, 2, 3, 4]); // DCID
        pkt.push(21); // SCID len > 20
        pkt.extend(std::iter::repeat(0xBB).take(21)); // SCID
        assert_eq!(detect_protocol(&pkt), None);
    }

    #[test]
    fn detect_quic_rejects_truncated_before_scid_len() {
        // Packet has DCID but no SCID length byte
        let mut pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01];
        pkt.push(4); // DCID len
        pkt.extend_from_slice(&[1, 2, 3, 4]); // DCID (but no SCID len byte)
        assert_eq!(detect_protocol(&pkt), None);
    }

    #[test]
    fn generate_quic_response() {
        let mut pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01]; // version 1
        pkt.push(4); // DCID len
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // DCID
        pkt.push(2); // SCID len
        pkt.extend_from_slice(&[0x11, 0x22]); // SCID

        let resp = generate_response(Protocol::Quic, &pkt);
        // Should start with 0xC3 (version negotiation, preserving incoming type bits)
        assert_eq!(resp[0], 0xC3);
        // Version = 0
        assert_eq!(&resp[1..5], &[0, 0, 0, 0]);
    }

    #[test]
    fn generate_dns_response() {
        let mut query = vec![0x00u8; 12];
        query[0] = 0xAB;
        query[1] = 0xCD;

        let resp = generate_response(Protocol::Dns, &query);
        // TX ID echoed
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);
        // QR=1
        assert!(resp[2] & 0x80 != 0);
    }

    #[test]
    fn generate_sip_response() {
        let resp = generate_response(Protocol::Sip, b"INVITE sip:user@example.com SIP/2.0\r\n");
        let text = std::str::from_utf8(&resp).unwrap();
        assert!(text.starts_with("SIP/2.0 100 Trying"));
    }

    #[test]
    fn generate_sip_response_echoes_headers() {
        let incoming = b"INVITE sip:user@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776\r\nFrom: <sip:caller@example.com>;tag=1234\r\nTo: <sip:user@example.com>\r\nCall-ID: a84b4c76e66710@pc33.example.com\r\nCSeq: 314159 INVITE\r\nContent-Length: 0\r\n\r\n";
        let resp = generate_response(Protocol::Sip, incoming);
        let text = std::str::from_utf8(&resp).unwrap();
        assert!(text.starts_with("SIP/2.0 100 Trying"));
        assert!(text.contains("Via:"));
        assert!(text.contains("From:"));
        assert!(text.contains("To:"));
        assert!(text.contains("Call-ID:"));
        assert!(text.contains("CSeq:"));
    }

    #[test]
    fn generate_dns_response_echoes_question() {
        // Build a DNS query for "example.com" A record
        let mut query = Vec::new();
        query.extend_from_slice(&[0xAB, 0xCD]); // TX ID
        query.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        // QNAME: 7example3com0
        query.push(7);
        query.extend_from_slice(b"example");
        query.push(3);
        query.extend_from_slice(b"com");
        query.push(0); // root label
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let resp = generate_response(Protocol::Dns, &query);
        // TX ID echoed
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);
        // QR=1
        assert!(resp[2] & 0x80 != 0);
        // Response should include the question section
        assert!(resp.len() > 12, "DNS response should include question section");
        // QNAME echoed: starts at byte 12 with label length 7 ("example")
        assert_eq!(resp[12], 7);
    }

    // -- AWG packet classification tests --

    fn test_awg_params() -> AwgParams {
        AwgParams {
            jc: 5,
            jmin: 50,
            jmax: 1000,
            s1: 42,
            s2: 88,
            s3: 33,
            s4: 120,
            h1: HRange { min: 100, max: 200 },
            h2: HRange { min: 300, max: 400 },
            h3: HRange { min: 500, max: 600 },
            h4: HRange { min: 700, max: 800 },
        }
    }

    #[test]
    fn classify_handshake_init() {
        let params = test_awg_params();
        let header = 150u32.to_le_bytes();
        let mut pkt = Vec::from(header);
        pkt.extend_from_slice(&[0u8; 200]); // body
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeInit)
        );
    }

    #[test]
    fn classify_handshake_response() {
        let params = test_awg_params();
        let header = 350u32.to_le_bytes();
        let mut pkt = Vec::from(header);
        pkt.extend_from_slice(&[0u8; 100]);
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeResponse)
        );
    }

    #[test]
    fn classify_cookie_reply() {
        let params = test_awg_params();
        let header = 550u32.to_le_bytes();
        let mut pkt = Vec::from(header);
        pkt.extend_from_slice(&[0u8; 70]);
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::CookieReply)
        );
    }

    #[test]
    fn classify_transport_data() {
        let params = test_awg_params();
        let header = 750u32.to_le_bytes();
        let mut pkt = Vec::from(header);
        pkt.extend_from_slice(&[0u8; 500]);
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::TransportData)
        );
    }

    #[test]
    fn classify_unknown_header() {
        let params = test_awg_params();
        // Header value 50 is below H1 range (100-200)
        let header = 50u32.to_le_bytes();
        let pkt = Vec::from(header);
        assert_eq!(classify_awg_packet(&pkt, &params), None);
    }

    #[test]
    fn classify_too_short() {
        let params = test_awg_params();
        assert_eq!(classify_awg_packet(&[0x01, 0x02], &params), None);
    }

    #[test]
    fn classify_boundary_values() {
        let params = test_awg_params();
        // H1 min boundary
        let pkt = Vec::from(100u32.to_le_bytes());
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeInit)
        );
        // H1 max boundary
        let pkt = Vec::from(200u32.to_le_bytes());
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeInit)
        );
        // Just outside H1
        let pkt = Vec::from(201u32.to_le_bytes());
        assert_eq!(classify_awg_packet(&pkt, &params), None);
    }

    #[test]
    fn padding_size_per_type() {
        let params = test_awg_params();
        assert_eq!(AwgPacketType::HandshakeInit.padding_size(&params), 42);
        assert_eq!(AwgPacketType::HandshakeResponse.padding_size(&params), 88);
        assert_eq!(AwgPacketType::CookieReply.padding_size(&params), 33);
        assert_eq!(AwgPacketType::TransportData.padding_size(&params), 120);
    }
}
