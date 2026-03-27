use bytes::{Bytes, BytesMut, BufMut};

/// Detected imitation protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Quic,
    Dns,
    Sip,
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

    // QUIC Initial: long header form bit (0x80) + fixed bit (0x40) set
    if data[0] & 0xC0 == 0xC0 {
        return Some(Protocol::Quic);
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

    // First byte: long header indicator
    buf.put_u8(0x80);
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
/// Echoes the transaction ID, sets QR=1, RCODE=2 (SERVFAIL).
fn generate_dns_servfail(incoming: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(12);

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

    buf.freeze()
}

/// SIP 100 Trying response.
fn generate_sip_trying(_incoming: &[u8]) -> Bytes {
    Bytes::from_static(b"SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn generate_quic_response() {
        let mut pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01]; // version 1
        pkt.push(4); // DCID len
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // DCID
        pkt.push(2); // SCID len
        pkt.extend_from_slice(&[0x11, 0x22]); // SCID

        let resp = generate_response(Protocol::Quic, &pkt);
        // Should start with 0x80 (version negotiation)
        assert_eq!(resp[0], 0x80);
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
}
