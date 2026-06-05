use std::fmt;
use std::net::{IpAddr, SocketAddr};

use bytes::{BufMut, Bytes, BytesMut};

use crate::config::AwgParams;

/// WireGuard message sizes (excluding padding)
/// These are the standard WireGuard message sizes as defined in the WireGuard specification
const WG_HANDSHAKE_INIT_SIZE: usize = 148;
const WG_HANDSHAKE_RESPONSE_SIZE: usize = 92;
const WG_COOKIE_REPLY_SIZE: usize = 64;
/// Transport data messages have variable size, so we only validate minimum size
const WG_TRANSPORT_DATA_MIN_SIZE: usize = 32;

/// Detected imitation protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Quic,
    Dns,
    Stun,
    Sip,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Quic => write!(f, "quic"),
            Protocol::Dns => write!(f, "dns"),
            Protocol::Stun => write!(f, "stun"),
            Protocol::Sip => write!(f, "sip"),
        }
    }
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

    /// Return the expected WireGuard message size (excluding padding) for this packet type.
    /// Returns None for TransportData since it has variable size.
    pub fn expected_message_size(&self) -> Option<usize> {
        match self {
            AwgPacketType::HandshakeInit => Some(WG_HANDSHAKE_INIT_SIZE),
            AwgPacketType::HandshakeResponse => Some(WG_HANDSHAKE_RESPONSE_SIZE),
            AwgPacketType::CookieReply => Some(WG_COOKIE_REPLY_SIZE),
            AwgPacketType::TransportData => None, // Variable size
        }
    }

    /// Return the minimum total packet size (padding + message) for this packet type.
    pub fn min_total_size(&self, params: &AwgParams) -> usize {
        let padding = self.padding_size(params);
        match self {
            AwgPacketType::TransportData => padding + WG_TRANSPORT_DATA_MIN_SIZE,
            _ => padding + self.expected_message_size().unwrap_or(0),
        }
    }
}

/// Classify an AmneziaWG packet by checking the H-range header that follows
/// the S-padding prefix and validating expected packet sizes.
///
/// AmneziaWG prepends S1–S4 random bytes before the obfuscated header, so the
/// header starts at byte offset S for each packet type.  This function tries
/// each (S-offset, H-range) pair and validates the total packet size matches
/// expected WireGuard message sizes.
///
/// Returns `None` if the packet is too short, the header value doesn't match
/// any configured H range, or the total size doesn't match expected message
/// sizes (reduces false positives from random data).
pub fn classify_awg_packet(data: &[u8], params: &AwgParams) -> Option<AwgPacketType> {
    let candidates = [
        (params.s1 as usize, params.h1, AwgPacketType::HandshakeInit),
        (
            params.s2 as usize,
            params.h2,
            AwgPacketType::HandshakeResponse,
        ),
        (params.s3 as usize, params.h3, AwgPacketType::CookieReply),
        (params.s4 as usize, params.h4, AwgPacketType::TransportData),
    ];

    for (offset, range, pkt_type) in candidates {
        // Check if we have enough bytes to read the header
        if data.len() < offset + 4 {
            continue;
        }

        // Check if total size matches expected message size
        if let Some(expected_msg_size) = pkt_type.expected_message_size() {
            let total_expected_size = offset + expected_msg_size;
            if data.len() != total_expected_size {
                continue; // Size mismatch, skip this candidate
            }
        } else {
            // For TransportData (variable size), check minimum size
            let min_total_size = pkt_type.min_total_size(params);
            if data.len() < min_total_size {
                continue;
            }
        }

        // Check if header matches the H-range
        let header = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        if range.contains(header) {
            return Some(pkt_type);
        }
    }
    None
}

const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Returns `true` if `version` is a QUIC version a client would put in a real
/// long-header (Initial) packet.
///
/// Validating the version field is what distinguishes a genuine QUIC long
/// header from other protocols whose leading byte happens to have the
/// long-header form bits (`0xC0`) set — most notably DNS queries whose
/// transaction-ID high byte falls in `0xC0..=0xFF`.  A well-formed DNS query's
/// bytes 1..5 (flags + counts) do not correspond to a recognised QUIC version
/// in practice, so this check rejects them.  Note this is a heuristic, not a
/// guarantee: a crafted or malformed datagram could still place a matching
/// version here — the per-client protocol lock in `handle_probe` is the
/// defense-in-depth backstop for that case.
///
/// Accepted versions:
/// - `0x0000_0001` — QUIC v1 (RFC 9000)
/// - `0x6b33_43cf` — QUIC v2 (RFC 9369)
/// - `0xff00_00xx` — IETF draft versions (draft-ietf-quic-transport)
/// - `0x?a?a_?a?a` — GREASE / forced-version-negotiation values (RFC 9000 §15)
fn is_quic_version(version: u32) -> bool {
    match version {
        0x0000_0001 => true,
        0x6b33_43cf => true,
        v if v & 0xffff_ff00 == 0xff00_0000 => true,
        v if v & 0x0f0f_0f0f == 0x0a0a_0a0a => true,
        _ => false,
    }
}

/// Detect whether an incoming packet looks like a QUIC, DNS, STUN, or SIP initiation.
///
/// Heuristics:
/// - **QUIC**: First byte has the long-header form bit set (0x80) and the
///   fixed bit set (0x40), i.e. `(byte & 0xC0) == 0xC0`, AND the 32-bit
///   version field (bytes 1..5) is a recognised QUIC version
///   (see `is_quic_version`).  The version check prevents DNS queries with a
///   high transaction-ID byte from being misclassified as QUIC.
/// - **STUN**: RFC 5389/8489 header with the top two message-type bits clear,
///   4-byte-aligned length, magic cookie `0x2112A442`, exact datagram length,
///   and Binding Request type.
/// - **DNS**: At least 12 bytes, bytes 2-3 encode flags with QR=0 (query)
///   and a standard query opcode, i.e. `(flags & 0xF800) == 0x0000`, plus
///   QDCOUNT >= 1 in bytes 4-5 (RFC 1035 §4.1.1).
/// - **SIP**: Starts with ASCII `SIP/` or a SIP method keyword followed by a
///   space (RFC 3261 §7). We check for `INVITE `, `CANCEL `, `NOTIFY `,
///   `OPTIONS `, `REGISTER `, `SUBSCRIBE `, and `SIP/` prefixes — covering
///   every method the WireSock client may emit as junk traffic.
pub fn detect_protocol(data: &[u8]) -> Option<Protocol> {
    if data.is_empty() {
        return None;
    }

    // QUIC long header: form bit (0x80) + fixed bit (0x40) must both be set,
    // plus additional invariants to avoid false positives on AWG packets
    // whose random H-range headers happen to have those bits set.
    //   - Minimum 7 bytes (1 header + 4 version + 1 DCID len + 1 SCID len)
    //   - Version field (bytes 1..5) is a recognised QUIC version — this is
    //     what rejects DNS queries whose transaction-ID high byte is 0xC0..=0xFF
    //   - DCID length ≤ 20 (RFC 9000 §17.2)
    //   - Packet contains SCID length field
    //   - SCID length ≤ 20
    if data.len() >= 7 && data[0] & 0xC0 == 0xC0 {
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let dcid_len = data[5] as usize;
        if is_quic_version(version) && dcid_len <= 20 {
            let scid_len_offset = 6 + dcid_len;
            if data.len() > scid_len_offset {
                let scid_len = data[scid_len_offset] as usize;
                if scid_len <= 20 && data.len() >= scid_len_offset + 1 + scid_len {
                    return Some(Protocol::Quic);
                }
            }
        }
    }

    // STUN Binding Request (RFC 5389 / RFC 8489): 20-byte header, first two
    // message-type bits clear, length aligned to 32 bits, magic cookie at
    // bytes 4..8, and a 96-bit transaction ID at bytes 8..20.
    let has_stun_cookie = data.len() >= 8
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == STUN_MAGIC_COOKIE;
    if data.len() >= 20 && has_stun_cookie {
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if msg_type & 0xC000 == 0
            && msg_type == STUN_BINDING_REQUEST
            && msg_len % 4 == 0
            && data.len() == 20 + msg_len
        {
            return Some(Protocol::Stun);
        }
    }

    // DNS query: >= 12 bytes, QR=0, standard opcode, QDCOUNT >= 1
    if data.len() >= 12 && !has_stun_cookie {
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if flags & 0xF800 == 0x0000 && qdcount >= 1 {
            return Some(Protocol::Dns);
        }
    }

    // SIP: starts with known SIP method or version prefix.
    // Allocation-free ASCII case-insensitive prefix checks.
    //
    // The method list mirrors what the WireSock client may emit:
    //   - INVITE, CANCEL: simulate_sip_request (INVITE + matching CANCEL burst)
    //   - REGISTER, OPTIONS, SUBSCRIBE, NOTIFY: generate_protocol_packet
    //     (pre-handshake junk packets in `send_random_packets`)
    // SIP/ matches a response line, kept for symmetry though clients do not
    // normally emit responses.
    if data.len() >= 4 {
        let prefix = &data[..std::cmp::min(data.len(), 10)];
        if let Ok(text) = std::str::from_utf8(prefix) {
            let is_sip = text
                .get(..4)
                .is_some_and(|s| s.eq_ignore_ascii_case("SIP/"))
                || text
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("INVITE "))
                || text
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("CANCEL "))
                || text
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("NOTIFY "))
                || text
                    .get(..8)
                    .is_some_and(|s| s.eq_ignore_ascii_case("OPTIONS "))
                || text
                    .get(..9)
                    .is_some_and(|s| s.eq_ignore_ascii_case("REGISTER "))
                || text
                    .get(..10)
                    .is_some_and(|s| s.eq_ignore_ascii_case("SUBSCRIBE "));
            if is_sip {
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
/// - **STUN**: Builds a Binding Success response. Without a client address,
///   the XOR-MAPPED-ADDRESS falls back to `0.0.0.0:0`.
/// - **SIP**: Builds a `SIP/2.0 100 Trying` response.
pub fn generate_response(proto: Protocol, incoming: &[u8]) -> Bytes {
    let fallback_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    generate_response_for_client(proto, incoming, fallback_addr)
}

/// Generate a response packet that can include client-address-specific fields.
///
/// STUN uses the client address for `XOR-MAPPED-ADDRESS`; other protocols
/// ignore it and preserve the legacy response behavior.
pub fn generate_response_for_client(
    proto: Protocol,
    incoming: &[u8],
    client_addr: SocketAddr,
) -> Bytes {
    match proto {
        Protocol::Quic => generate_quic_version_negotiation(incoming),
        Protocol::Dns => generate_dns_servfail(incoming),
        Protocol::Stun => generate_stun_binding_success(incoming, client_addr),
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

    // Parse incoming DCID and SCID.
    // Enforce RFC 9000 §17.2 length limits (≤ 20) even though detect_protocol()
    // already validates these — this function is a public library API and may be
    // called with arbitrary inputs.
    const MAX_CID: usize = 20;
    if incoming.len() >= 6 {
        let dcid_len = incoming[5] as usize;
        let dcid_end = 6 + dcid_len;

        if dcid_len <= MAX_CID && incoming.len() > dcid_end {
            let scid_len = incoming[dcid_end] as usize;
            let scid_end = dcid_end + 1 + scid_len;

            // In version negotiation, swap DCID and SCID from the incoming packet
            // Response DCID = incoming SCID, Response SCID = incoming DCID
            if scid_len <= MAX_CID && incoming.len() >= scid_end {
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

    // Supported version: GREASE value (RFC 9000 §Appendix A).
    // We must NOT list 0x00000001 here: per RFC 9000 §6.2, a server MUST NOT
    // send a Version Negotiation packet when the client already sent the same
    // version the server supports. Listing v1 in the VN response for a v1
    // client is therefore both an RFC violation and a detectable fingerprint.
    // A GREASE value signals "no version in common" without claiming v1 support.
    buf.put_u32(0x0a0a_0a0a);

    buf.freeze()
}

/// STUN Binding Success response (RFC 5389 / RFC 8489).
///
/// The response echoes the 96-bit transaction ID from the request and includes
/// a single XOR-MAPPED-ADDRESS attribute for the observed client address.
fn generate_stun_binding_success(incoming: &[u8], client_addr: SocketAddr) -> Bytes {
    let attr_value_len = match client_addr.ip() {
        IpAddr::V4(_) => 8,
        IpAddr::V6(_) => 20,
    };
    let attr_total_len = 4 + attr_value_len;
    let mut buf = BytesMut::with_capacity(20 + attr_total_len);

    buf.put_u16(STUN_BINDING_SUCCESS_RESPONSE);
    buf.put_u16(attr_total_len as u16);
    buf.put_u32(STUN_MAGIC_COOKIE);

    let mut transaction_id = [0u8; 12];
    if incoming.len() >= 20 {
        transaction_id.copy_from_slice(&incoming[8..20]);
    }
    buf.put_slice(&transaction_id);

    buf.put_u16(STUN_ATTR_XOR_MAPPED_ADDRESS);
    buf.put_u16(attr_value_len as u16);
    buf.put_u8(0); // reserved

    let xor_port = client_addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    match client_addr.ip() {
        IpAddr::V4(ip) => {
            buf.put_u8(0x01);
            buf.put_u16(xor_port);
            let xor_addr = u32::from(ip) ^ STUN_MAGIC_COOKIE;
            buf.put_u32(xor_addr);
        }
        IpAddr::V6(ip) => {
            buf.put_u8(0x02);
            buf.put_u16(xor_port);
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key[4..].copy_from_slice(&transaction_id);
            let octets = ip.octets();
            for (addr_byte, key_byte) in octets.iter().zip(xor_key.iter()) {
                buf.put_u8(*addr_byte ^ *key_byte);
            }
        }
    }

    buf.freeze()
}

/// DNS SERVFAIL response (RFC 1035 §4.1):
/// Echoes the transaction ID and question section, sets QR=1, RCODE=2
/// (SERVFAIL).
///
/// Echoing the question section back is required by RFC 1035 §4.1.1 and makes
/// the response indistinguishable from a real recursive resolver failure.
fn generate_dns_servfail(incoming: &[u8]) -> Bytes {
    // Hard cap: standard DNS message size (RFC 1035 §2.3.4).
    const MAX_RESPONSE: usize = 512;
    const MAX_LABEL: usize = 63;
    const MAX_QNAME: usize = 255;

    let mut buf = BytesMut::with_capacity(MAX_RESPONSE);

    // Transaction ID (echo from query)
    if incoming.len() >= 2 {
        buf.put_slice(&incoming[..2]);
    } else {
        buf.put_u16(0);
    }

    // Flags: QR=1, Opcode=0, AA=0, TC=0, RA=1, RCODE=2 (SERVFAIL).
    // Per RFC 1035, the RD bit must be copied from the query.
    let mut flags: u16 = 0x8082; // QR=1, RA=1, RCODE=2 (RD cleared)
    if incoming.len() >= 4 {
        let query_flags = u16::from_be_bytes([incoming[2], incoming[3]]);
        if (query_flags & 0x0100) != 0 {
            flags |= 0x0100; // copy RD from query
        }
    }
    buf.put_u16(flags);
    // QDCOUNT (placeholder — will be patched to 1 if we echo the question),
    // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    let qdcount_offset = buf.len();
    buf.put_u16(0); // QDCOUNT placeholder
    buf.put_u16(0);
    buf.put_u16(0);
    buf.put_u16(0);

    // Echo the question section from the incoming query if available.
    // The question section starts at byte 12 in a DNS message and consists
    // of: QNAME (sequence of labels ending with 0) + QTYPE (2) + QCLASS (2).
    // We intentionally do not support compression pointers here; if we
    // encounter them, we refrain from echoing the question.
    //
    // We validate RFC 1035 §2.3.4 label/QNAME limits (label ≤ 63, total
    // name ≤ 255) and enforce a hard 512-byte response cap. Invalid or
    // oversized names are silently dropped (header-only response).
    if incoming.len() > 12 {
        let mut pos = 12;
        let mut qname_len: usize = 0;
        // Walk QNAME labels until root label (0) or end of packet
        while pos < incoming.len() {
            let label_len = incoming[pos] as usize;
            // Compression pointer (two high bits set) is not supported here.
            if label_len & 0xC0 == 0xC0 {
                break;
            }
            if label_len == 0 {
                // Ensure we have root label (0) + QTYPE (2) + QCLASS (2) = 5 bytes
                let question_end = pos + 5;
                if question_end <= incoming.len() && buf.len() + (question_end - 12) <= MAX_RESPONSE
                {
                    buf.put_slice(&incoming[12..question_end]);
                    // Patch QDCOUNT to 1 since we successfully echoed the question
                    buf[qdcount_offset] = 0x00;
                    buf[qdcount_offset + 1] = 0x01;
                }
                break;
            }
            // Validate label length (RFC 1035 §2.3.4: label ≤ 63 octets)
            if label_len > MAX_LABEL {
                break;
            }
            qname_len += 1 + label_len;
            // Validate total QNAME length (RFC 1035 §2.3.4: ≤ 255 octets,
            // including the terminating root label which adds 1 octet)
            if qname_len + 1 > MAX_QNAME {
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
    // Cap the response size to prevent memory/CPU DoS from oversized SIP probes.
    // 512 bytes is generous for a 100 Trying with the five echoed headers.
    const MAX_RESPONSE_SIZE: usize = 512;

    let mut buf = BytesMut::with_capacity(MAX_RESPONSE_SIZE);
    buf.put_slice(b"SIP/2.0 100 Trying\r\n");

    // Echo key SIP headers from the incoming request for realism.
    // Allocation-free ASCII case-insensitive prefix checks.
    // Only scan up to a bounded prefix (2 KiB) of the request to limit CPU
    // work on spoofed/oversized UDP payloads.
    let suffix = b"Content-Length: 0\r\n\r\n";
    let scan_limit = std::cmp::min(incoming.len(), 2048);
    if let Ok(text) = std::str::from_utf8(&incoming[..scan_limit]) {
        let echo_prefixes = ["via:", "from:", "to:", "call-id:", "cseq:"];
        for line in text.lines() {
            let trimmed = line.trim();
            for &prefix in &echo_prefixes {
                if trimmed
                    .get(..prefix.len())
                    .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
                {
                    // Stop echoing if adding this line would exceed the cap
                    let line_len = trimmed.len() + 2; // +2 for \r\n
                    if buf.len() + line_len + suffix.len() > MAX_RESPONSE_SIZE {
                        // No more room — finish the response now
                        buf.put_slice(suffix);
                        return buf.freeze();
                    }
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

    // -- Protocol Display tests --

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Quic.to_string(), "quic");
        assert_eq!(Protocol::Dns.to_string(), "dns");
        assert_eq!(Protocol::Stun.to_string(), "stun");
        assert_eq!(Protocol::Sip.to_string(), "sip");
    }

    // -- imitation protocol detection tests --

    fn stun_binding_request() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        pkt
    }

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
    fn detect_dns_query_with_high_txid_not_quic() {
        // Regression: a DNS query whose transaction-ID high byte is in
        // 0xC0..=0xFF sets the QUIC long-header form bits (data[0] & 0xC0 ==
        // 0xC0).  Without version validation this was misclassified as QUIC,
        // causing the proxy to emit QUIC Version Negotiation / handshake
        // packets into a DNS session (observed as non-DNS server frames).
        // It must now be detected as DNS.
        let pkt = vec![
            0xe1, 0x6b, // TX ID 0xe16b (high byte trips the 0xC0 form bits)
            0x01, 0x00, // flags: standard query, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x00, // root-label QNAME
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];
        assert_eq!(detect_protocol(&pkt), Some(Protocol::Dns));
    }

    #[test]
    fn detect_quic_rejects_invalid_version() {
        // Long-header form bits set but the version field is not a recognised
        // QUIC version -> must NOT be classified as QUIC.
        let mut pkt = vec![0xC3u8, 0x12, 0x34, 0x56, 0x78]; // bogus version
        pkt.push(4); // DCID len
        pkt.extend_from_slice(&[1, 2, 3, 4]);
        pkt.push(0); // SCID len
        assert_eq!(detect_protocol(&pkt), None);
    }

    #[test]
    fn detect_quic_accepts_v2_and_grease() {
        for version in [0x6b33_43cfu32, 0x0a0a_0a0a, 0xff00_001d] {
            let mut pkt = vec![0xC3u8];
            pkt.extend_from_slice(&version.to_be_bytes());
            pkt.push(4); // DCID len
            pkt.extend_from_slice(&[1, 2, 3, 4]);
            pkt.push(0); // SCID len
            assert_eq!(
                detect_protocol(&pkt),
                Some(Protocol::Quic),
                "version {version:#010x} should be accepted as QUIC"
            );
        }
    }

    #[test]
    fn quic_version_predicate() {
        assert!(is_quic_version(0x0000_0001)); // v1
        assert!(is_quic_version(0x6b33_43cf)); // v2
        assert!(is_quic_version(0xff00_001d)); // draft-29
        assert!(is_quic_version(0x1a2a_3a4a)); // GREASE pattern
        assert!(!is_quic_version(0x0000_0000)); // VN sentinel, not a client version
        assert!(!is_quic_version(0x6b01_0000)); // DNS-query-shaped bytes
    }

    #[test]
    fn detect_stun_binding_request() {
        let pkt = stun_binding_request();
        assert_eq!(detect_protocol(&pkt), Some(Protocol::Stun));
    }

    #[test]
    fn detect_stun_rejects_bad_magic_cookie() {
        let mut pkt = stun_binding_request();
        pkt[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(detect_protocol(&pkt), None);
    }

    #[test]
    fn detect_stun_rejects_bad_length() {
        let mut pkt = stun_binding_request();
        pkt[2..4].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(detect_protocol(&pkt), None);
    }

    #[test]
    fn detect_stun_rejects_response_as_probe() {
        let mut pkt = stun_binding_request();
        pkt[0..2].copy_from_slice(&STUN_BINDING_SUCCESS_RESPONSE.to_be_bytes());
        assert_eq!(detect_protocol(&pkt), None);
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
    fn detect_sip_cancel_register_options_notify_subscribe() {
        // All SIP methods the WireSock client may emit must be classified as SIP
        // so the proxy produces a matching response and primes its protocol
        // state for the client.
        for line in [
            "CANCEL sip:bob@example.com SIP/2.0\r\n".as_bytes(),
            "REGISTER sip:registrar.example.com SIP/2.0\r\n".as_bytes(),
            "OPTIONS sip:bob@example.com SIP/2.0\r\n".as_bytes(),
            "NOTIFY sip:bob@example.com SIP/2.0\r\n".as_bytes(),
            "SUBSCRIBE sip:bob@example.com SIP/2.0\r\n".as_bytes(),
        ] {
            assert_eq!(
                detect_protocol(line),
                Some(Protocol::Sip),
                "method should be classified as SIP: {:?}",
                std::str::from_utf8(line).unwrap_or("?")
            );
        }
    }

    #[test]
    fn detect_sip_methods_are_case_insensitive() {
        // RFC 3261 §7.1 method names are case-sensitive at the parser level,
        // but our heuristic uses case-insensitive matching to be robust to
        // junk/probing traffic that may not normalize casing.
        let pkt = b"invite sip:bob@example.com SIP/2.0\r\n";
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
    fn detect_quic_rejects_truncated_scid_body() {
        // Packet has SCID length but not enough SCID bytes.
        // Byte 2 is set to 0x80 so that the DNS detection heuristic
        // (flags & 0xF800 == 0x0000) fails, preventing a false DNS match.
        let mut pkt = vec![0xC3u8, 0x00, 0x80, 0x00, 0x01];
        pkt.push(4); // DCID len
        pkt.extend_from_slice(&[1, 2, 3, 4]); // DCID
        pkt.push(8); // SCID len = 8
        pkt.extend_from_slice(&[0xAA, 0xBB]); // only 2 bytes of SCID (truncated)
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
        // Version field = 0 (Version Negotiation indicator per RFC 9000 §17.2.1)
        assert_eq!(&resp[1..5], &[0, 0, 0, 0]);
        // Supported-version field must be a GREASE value, not 0x00000001.
        // Advertising v1 as "supported" in a VN response to a v1 client violates
        // RFC 9000 §6.2 and is a detectable fingerprint.
        let supported_version =
            u32::from_be_bytes([resp[resp.len() - 4], resp[resp.len() - 3], resp[resp.len() - 2], resp[resp.len() - 1]]);
        assert_ne!(supported_version, 0x00000001, "must not advertise QUIC v1 in VN response to a v1 client");
        assert_eq!(supported_version, 0x0a0a_0a0a, "should use GREASE version");
    }

    #[test]
    fn generate_quic_response_rejects_oversized_dcid() {
        // DCID len = 21, exceeds RFC 9000 §17.2 max of 20
        let mut pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01];
        pkt.push(21); // DCID len
        pkt.extend_from_slice(&[0xAA; 21]); // DCID body
        pkt.push(2); // SCID len
        pkt.extend_from_slice(&[0x11, 0x22]);

        let resp = generate_response(Protocol::Quic, &pkt);
        // Should fall back to zero-length CIDs
        assert_eq!(resp[5], 0); // DCID len = 0
        assert_eq!(resp[6], 0); // SCID len = 0
    }

    #[test]
    fn generate_quic_response_rejects_oversized_scid() {
        // DCID len = 4 (valid), SCID len = 21 (exceeds max)
        let mut pkt = vec![0xC3u8, 0x00, 0x00, 0x00, 0x01];
        pkt.push(4);
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        pkt.push(21); // SCID len
        pkt.extend_from_slice(&[0x11; 21]);

        let resp = generate_response(Protocol::Quic, &pkt);
        // Should fall back to zero-length CIDs
        assert_eq!(resp[5], 0);
        assert_eq!(resp[6], 0);
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
    fn generate_stun_response_ipv4_echoes_transaction_and_xor_address() {
        let req = stun_binding_request();
        let client_addr = SocketAddr::from(([192, 0, 2, 1], 3478));
        let resp = generate_response_for_client(Protocol::Stun, &req, client_addr);

        assert_eq!(resp.len(), 32);
        assert_eq!(
            u16::from_be_bytes([resp[0], resp[1]]),
            STUN_BINDING_SUCCESS_RESPONSE
        );
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 12);
        assert_eq!(
            u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&resp[8..20], &req[8..20]);
        assert_eq!(
            u16::from_be_bytes([resp[20], resp[21]]),
            STUN_ATTR_XOR_MAPPED_ADDRESS
        );
        assert_eq!(u16::from_be_bytes([resp[22], resp[23]]), 8);
        assert_eq!(resp[24], 0);
        assert_eq!(resp[25], 0x01);
        assert_eq!(
            u16::from_be_bytes([resp[26], resp[27]]),
            3478 ^ ((STUN_MAGIC_COOKIE >> 16) as u16)
        );
        assert_eq!(
            u32::from_be_bytes([resp[28], resp[29], resp[30], resp[31]]),
            u32::from_be_bytes([192, 0, 2, 1]) ^ STUN_MAGIC_COOKIE
        );
    }

    #[test]
    fn generate_stun_response_ipv6_uses_transaction_id_xor_key() {
        let req = stun_binding_request();
        let client_addr: SocketAddr = "[2001:db8::1]:5349".parse().unwrap();
        let resp = generate_response_for_client(Protocol::Stun, &req, client_addr);

        assert_eq!(resp.len(), 44);
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 24);
        assert_eq!(u16::from_be_bytes([resp[22], resp[23]]), 20);
        assert_eq!(resp[25], 0x02);
        assert_eq!(
            u16::from_be_bytes([resp[26], resp[27]]),
            5349 ^ ((STUN_MAGIC_COOKIE >> 16) as u16)
        );

        let mut xor_key = [0u8; 16];
        xor_key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        xor_key[4..].copy_from_slice(&req[8..20]);
        let ip = match client_addr.ip() {
            IpAddr::V6(ip) => ip.octets(),
            _ => unreachable!(),
        };
        let expected: Vec<u8> = ip
            .iter()
            .zip(xor_key.iter())
            .map(|(addr_byte, key_byte)| *addr_byte ^ *key_byte)
            .collect();
        assert_eq!(&resp[28..44], expected.as_slice());
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
        // RD=1 should be copied from the query
        assert!(resp[2] & 0x01 != 0, "RD bit should be copied from query");
        // Response should include the question section
        assert!(
            resp.len() > 12,
            "DNS response should include question section"
        );
        // QNAME echoed: starts at byte 12 with label length 7 ("example")
        assert_eq!(resp[12], 7);
        // QDCOUNT should be 1 since the question was echoed
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
    }

    #[test]
    fn generate_dns_response_rd_zero_query_rd_zero_response() {
        // DNS query with RD=0 — response must also have RD=0 (RFC 1035).
        let mut query = Vec::new();
        query.extend_from_slice(&[0x11, 0x22]); // TX ID
        query.extend_from_slice(&[0x00, 0x00]); // Flags: RD=0
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
                                                // QNAME: 3foo0
        query.push(3);
        query.extend_from_slice(b"foo");
        query.push(0); // root label
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let resp = generate_response(Protocol::Dns, &query);
        // QR=1
        assert!(resp[2] & 0x80 != 0);
        // RD=0 should be preserved from query
        assert_eq!(resp[2] & 0x01, 0, "RD bit should be 0 when query has RD=0");
        // RA=1 and RCODE=2 (SERVFAIL) should still be set
        assert_eq!(resp[3], 0x82);
    }

    #[test]
    fn generate_dns_response_truncated_question_qdcount_zero() {
        // DNS query with truncated question section (missing QTYPE/QCLASS)
        let mut query = vec![0x00u8; 12];
        query[0] = 0x12; // TX ID
        query[1] = 0x34;
        query[4] = 0x00;
        query[5] = 0x01; // QDCOUNT=1
                         // QNAME: 3foo0 but missing QTYPE/QCLASS
        query.push(3);
        query.extend_from_slice(b"foo");
        query.push(0); // root label — but no QTYPE/QCLASS follows

        let resp = generate_response(Protocol::Dns, &query);
        // TX ID echoed
        assert_eq!(resp[0], 0x12);
        assert_eq!(resp[1], 0x34);
        // QDCOUNT should be 0 since question section is incomplete
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 0);
        // Response should be header only (12 bytes)
        assert_eq!(resp.len(), 12);
    }

    #[test]
    fn generate_dns_response_compression_pointer_qdcount_zero() {
        // DNS query with a compression pointer in QNAME — we don't support these
        let mut query = vec![0x00u8; 12];
        query[0] = 0x56; // TX ID
        query[1] = 0x78;
        query[4] = 0x00;
        query[5] = 0x01; // QDCOUNT=1
                         // QNAME starting with a compression pointer (0xC0 0x00)
        query.push(0xC0);
        query.push(0x00);

        let resp = generate_response(Protocol::Dns, &query);
        // QDCOUNT should be 0 since we refused to parse compression pointer
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 0);
        // Response should be header only (12 bytes)
        assert_eq!(resp.len(), 12);
    }

    #[test]
    fn generate_dns_response_label_too_long_qdcount_zero() {
        // DNS query with a label > 63 octets — violates RFC 1035 §2.3.4
        let mut query = vec![0x00u8; 12];
        query[0] = 0xAA;
        query[1] = 0xBB;
        query[4] = 0x00;
        query[5] = 0x01; // QDCOUNT=1
                         // Label length = 64 (exceeds the 63-octet limit)
        query.push(64);
        query.extend_from_slice(&[b'x'; 64]);
        query.push(0); // root label
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let resp = generate_response(Protocol::Dns, &query);
        // QDCOUNT should be 0 since label length exceeds RFC 1035 limit
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 0);
        assert_eq!(resp.len(), 12);
    }

    #[test]
    fn generate_dns_response_qname_too_long_qdcount_zero() {
        // DNS query with total QNAME > 255 octets — violates RFC 1035 §2.3.4
        let mut query = vec![0x00u8; 12];
        query[0] = 0xCC;
        query[1] = 0xDD;
        query[4] = 0x00;
        query[5] = 0x01; // QDCOUNT=1
                         // Build a QNAME with many 63-byte labels to exceed 255 total
                         // 4 labels of 63 bytes = 4*(1+63) = 256 > 255
        for _ in 0..4 {
            query.push(63);
            query.extend_from_slice(&[b'a'; 63]);
        }
        query.push(0); // root label
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let resp = generate_response(Protocol::Dns, &query);
        // QDCOUNT should be 0 since QNAME exceeds 255-octet limit
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 0);
        assert_eq!(resp.len(), 12);
    }

    #[test]
    fn generate_dns_response_qname_boundary_255_accepted() {
        // Build a QNAME whose total encoded length is exactly 255 octets
        // (including root label). This is the maximum allowed by RFC 1035.
        // 3 labels of 63 bytes = 3*(1+63) = 192 octets
        // + 1 label of 61 bytes = 1+61 = 62 octets → subtotal = 254
        // + root label (1 octet) = 255 total → valid
        let mut query = vec![0x00u8; 12];
        query[0] = 0xEE;
        query[1] = 0xFF;
        query[4] = 0x00;
        query[5] = 0x01; // QDCOUNT=1
        for _ in 0..3 {
            query.push(63);
            query.extend_from_slice(&[b'b'; 63]);
        }
        query.push(61);
        query.extend_from_slice(&[b'c'; 61]);
        query.push(0); // root label
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let resp = generate_response(Protocol::Dns, &query);
        // QDCOUNT should be 1 — the name is exactly at the boundary
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        assert!(
            resp.len() > 12,
            "response should include the echoed question"
        );
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
        // S1(42) prefix padding + 148-byte WG message total
        let mut pkt = vec![0x00; 42]; // S1 padding
        pkt.extend_from_slice(&150u32.to_le_bytes()); // H1 header (replaces message type)
        pkt.extend_from_slice(&[0u8; 148 - 4]); // Rest of WG message (148 total includes 4-byte header)
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeInit)
        );
    }

    #[test]
    fn classify_handshake_response() {
        let params = test_awg_params();
        // S2(88) prefix padding + 92-byte WG message total
        let mut pkt = vec![0x00; 88]; // S2 padding
        pkt.extend_from_slice(&350u32.to_le_bytes()); // H2 header (replaces message type)
        pkt.extend_from_slice(&[0u8; 92 - 4]); // Rest of WG message (92 total includes 4-byte header)
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeResponse)
        );
    }

    #[test]
    fn classify_cookie_reply() {
        let params = test_awg_params();
        // S3(33) prefix padding + 64-byte WG message total
        let mut pkt = vec![0x00; 33]; // S3 padding
        pkt.extend_from_slice(&550u32.to_le_bytes()); // H3 header (replaces message type)
        pkt.extend_from_slice(&[0u8; 64 - 4]); // Rest of WG message (64 total includes 4-byte header)
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::CookieReply)
        );
    }

    #[test]
    fn classify_transport_data() {
        let params = test_awg_params();
        // S4(120) prefix padding + H4-range header at offset 120 + body
        let mut pkt = vec![0x00; 120];
        pkt.extend_from_slice(&750u32.to_le_bytes());
        pkt.extend_from_slice(&[0u8; 500]);
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::TransportData)
        );
    }

    #[test]
    fn classify_unknown_header() {
        let params = test_awg_params();
        // Packet with all zeros → header=0 at every S offset, no H range match
        let pkt = vec![0x00; 200];
        assert_eq!(classify_awg_packet(&pkt, &params), None);
    }

    #[test]
    fn classify_too_short() {
        let params = test_awg_params();
        // Packet too short for any S offset + 4 header bytes
        assert_eq!(classify_awg_packet(&[0x01, 0x02], &params), None);
    }

    #[test]
    fn classify_size_mismatch_rejects_false_positive() {
        let params = test_awg_params();
        // Handshake Init with correct header but wrong size (should be S1+148=190 bytes)
        let mut pkt = vec![0x00; 42]; // S1 padding
        pkt.extend_from_slice(&150u32.to_le_bytes()); // H1 header (within range 100-200)
        pkt.extend_from_slice(&[0u8; 100]); // Only 100 bytes payload, total 146 < 190
        assert_eq!(classify_awg_packet(&pkt, &params), None);
    }

    #[test]
    fn classify_exact_size_accepted() {
        let params = test_awg_params();
        // Handshake Init with exact correct size: S1(42) + 148 = 190 bytes total
        let mut pkt = vec![0x00; 42]; // S1 padding
        pkt.extend_from_slice(&150u32.to_le_bytes()); // H1 header (within range 100-200)
        pkt.extend_from_slice(&[0u8; 148 - 4]); // Rest of WG message
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeInit)
        );
    }

    #[test]
    fn classify_transport_data_variable_size() {
        let params = test_awg_params();
        // Transport Data with variable size, should accept any size >= minimum
        let mut pkt = vec![0x00; 120]; // S4 padding
        pkt.extend_from_slice(&750u32.to_le_bytes()); // H4 header
        pkt.extend_from_slice(&[0u8; 200]); // 200 bytes payload (>= min 32)
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::TransportData)
        );
    }

    #[test]
    fn classify_transport_data_too_small() {
        let params = test_awg_params();
        // Transport Data below minimum size: S4(120) + min payload(32) = 152 bytes
        let mut pkt = vec![0x00; 120]; // S4 padding
        pkt.extend_from_slice(&750u32.to_le_bytes()); // H4 header
        pkt.extend_from_slice(&[0u8; 20]); // Only 20 bytes payload < min 32
        assert_eq!(classify_awg_packet(&pkt, &params), None);
    }

    #[test]
    fn classify_boundary_values() {
        let params = test_awg_params();
        // H1 min boundary at offset S1(42) with exact size
        let mut pkt = vec![0x00; 42]; // S1 padding
        pkt.extend_from_slice(&100u32.to_le_bytes()); // H1 min value
        pkt.extend_from_slice(&[0u8; 148 - 4]); // Rest of WG message
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeInit)
        );
        // H1 max boundary at offset S1(42) with exact size
        let mut pkt = vec![0x00; 42]; // S1 padding
        pkt.extend_from_slice(&200u32.to_le_bytes()); // H1 max value
        pkt.extend_from_slice(&[0u8; 148 - 4]); // Rest of WG message
        assert_eq!(
            classify_awg_packet(&pkt, &params),
            Some(AwgPacketType::HandshakeInit)
        );
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
