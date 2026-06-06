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

/// Detect whether an incoming packet looks like a QUIC, DNS, STUN, or SIP initiation.
///
/// Heuristics:
/// - **QUIC**: First byte has the long-header form bit set (0x80) and the
///   fixed bit set (0x40), i.e. `(byte & 0xC0) == 0xC0`, which matches
///   QUIC Initial packets (RFC 9000 §17.2).
/// - **STUN**: RFC 5389/8489 header with the top two message-type bits clear,
///   4-byte-aligned length, magic cookie `0x2112A442`, exact datagram length,
///   and Binding Request type.
/// - **DNS**: At least 12 bytes, bytes 2-3 encode flags with QR=0 (query)
///   and a standard query opcode, i.e. `(flags & 0xF800) == 0x0000`, plus
///   QDCOUNT >= 1 in bytes 4-5 (RFC 1035 §4.1.1).
/// - **SIP**: Starts with ASCII `SIP/` or a SIP method keyword followed by a
///   space (RFC 3261 §7). We check for `INVITE `, `ACK `, `BYE `, `CANCEL `,
///   `INFO `, `MESSAGE `, `NOTIFY `, `OPTIONS `, `REGISTER `, `SUBSCRIBE `,
///   and `SIP/` prefixes — covering every method the WireSock client may emit
///   as junk traffic.
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
                    .is_some_and(|s| s.eq_ignore_ascii_case("SUBSCRIBE "))
                || text
                    .get(..4)
                    .is_some_and(|s| s.eq_ignore_ascii_case("ACK "))
                || text
                    .get(..4)
                    .is_some_and(|s| s.eq_ignore_ascii_case("BYE "))
                || text
                    .get(..5)
                    .is_some_and(|s| s.eq_ignore_ascii_case("INFO "))
                || text
                    .get(..8)
                    .is_some_and(|s| s.eq_ignore_ascii_case("MESSAGE "));
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

// ---------------------------------------------------------------------------
// SIP dialog state machine
// ---------------------------------------------------------------------------

/// Stage of a per-client SIP dialog.
///
/// The proxy advances through these stages as methods arrive:
/// `Idle` → (INVITE) → `Invited` → (180 sent) → `Ringing` → (200 OK sent) → `Established` → (BYE) → `Terminated`
///
/// Once `Terminated` the dialog may be reused for a new INVITE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SipDialogStage {
    /// No dialog in progress; proxy will respond to INVITE to start one.
    Idle,
    /// INVITE received; initial response sent, awaiting provisional/final answer.
    Invited,
    /// `180 Ringing` sent; final `200 OK` is still pending.
    Ringing,
    /// `200 OK` sent; awaiting ACK or BYE.
    Established,
    /// BYE (or CANCEL) received; `200 OK` sent.  Next INVITE starts fresh.
    Terminated,
}

/// Per-client SIP dialog state extracted from the first INVITE.
///
/// Headers are stored verbatim from the incoming request so the proxy's
/// responses are byte-for-byte consistent with what the real SIP client sent.
#[derive(Debug, Clone)]
pub(crate) struct SipDialog {
    pub(crate) stage: SipDialogStage,
    /// Current transaction `Via:` header lines (one per hop).
    pub(crate) via: Vec<String>,
    /// Original INVITE `Via:` header lines, used for final responses to the
    /// INVITE transaction (for example `487 Request Terminated` after CANCEL).
    pub(crate) invite_via: Vec<String>,
    /// `From:` header line, echoed from the original INVITE.
    pub(crate) from: String,
    /// `To:` header line from the INVITE (no tag yet — added on 200 OK).
    pub(crate) to: String,
    /// `To:` tag generated by the proxy for the `200 OK` and `BYE 200 OK`.
    pub(crate) to_tag: String,
    /// `Call-ID:` header line, echoed from the original INVITE.
    pub(crate) call_id: String,
    /// Normalized Call-ID value, used for dialog identity comparisons.
    pub(crate) call_id_value: String,
    /// Original INVITE `CSeq:` header, used for final responses to the INVITE
    /// transaction (for example `487 Request Terminated` after CANCEL).
    pub(crate) invite_cseq: String,
    /// `CSeq:` header line — updated for each successive request.
    pub(crate) cseq: String,
}

const SIP_SCAN_LIMIT: usize = 2048;
const SIP_MAX_RESPONSE_SIZE: usize = 512;

impl SipDialog {
    /// Create a new dialog by parsing a SIP request.  Returns `None` if the
    /// packet is not a parseable UTF-8 SIP message or required headers are
    /// missing/too large to reflect safely.
    pub(crate) fn from_request(incoming: &[u8]) -> Option<Self> {
        let scan_limit = std::cmp::min(incoming.len(), SIP_SCAN_LIMIT);
        let text = std::str::from_utf8(&incoming[..scan_limit]).ok()?;

        let mut via: Vec<String> = Vec::new();
        let mut from = String::new();
        let mut to = String::new();
        let mut call_id = String::new();
        let mut cseq = String::new();

        for line in text.lines() {
            let t = sip_header_line(line);
            if t.is_empty() {
                break;
            }
            if t.get(..4).is_some_and(|s| s.eq_ignore_ascii_case("via:")) {
                via.push(t.to_string());
            } else if from.is_empty() && t.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("from:"))
            {
                from = t.to_string();
            } else if to.is_empty() && t.get(..3).is_some_and(|s| s.eq_ignore_ascii_case("to:")) {
                to = t.to_string();
            } else if call_id.is_empty()
                && t.get(..8)
                    .is_some_and(|s| s.eq_ignore_ascii_case("call-id:"))
            {
                call_id = t.to_string();
            } else if cseq.is_empty() && t.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("cseq:"))
            {
                cseq = t.to_string();
            }
        }

        // Require the request headers we must reflect to build well-formed
        // responses. Fall back to the stateless path if any are absent.
        if via.is_empty()
            || from.is_empty()
            || to.is_empty()
            || call_id.is_empty()
            || cseq.is_empty()
            || via.iter().any(|line| sip_header_value(line).is_empty())
            || sip_header_value(&from).is_empty()
            || sip_header_value(&to).is_empty()
            || sip_header_value(&call_id).is_empty()
            || sip_header_value(&cseq).is_empty()
        {
            return None;
        }

        // Derive a stable To-tag from the Call-ID so it is deterministic across
        // retransmits but distinct per dialog.
        let call_id_value = sip_header_value(&call_id).to_string();
        let to_tag = sip_dialog_tag(&call_id_value);

        let dialog = SipDialog {
            stage: SipDialogStage::Idle,
            invite_via: via.clone(),
            via,
            from,
            to,
            to_tag,
            call_id,
            call_id_value,
            invite_cseq: cseq.clone(),
            cseq,
        };

        if !sip_reflected_responses_fit(&dialog) {
            return None;
        }

        Some(dialog)
    }

    /// Create a new dialog by parsing the INVITE.  Returns `None` if the
    /// packet is not a parseable UTF-8 SIP message.
    pub(crate) fn from_invite(incoming: &[u8]) -> Option<Self> {
        if !sip_method(incoming)?.eq_ignore_ascii_case("INVITE") {
            return None;
        }
        Self::from_request(incoming)
    }

    /// Update transaction-specific reflected headers from the latest request.
    pub(crate) fn update_request_headers(&mut self, incoming: &[u8]) {
        let scan_limit = std::cmp::min(incoming.len(), SIP_SCAN_LIMIT);
        if let Ok(text) = std::str::from_utf8(&incoming[..scan_limit]) {
            let mut via: Vec<String> = Vec::new();
            let mut cseq: Option<String> = None;

            for line in text.lines() {
                let t = sip_header_line(line);
                if t.is_empty() {
                    break;
                }
                if t.get(..4).is_some_and(|s| s.eq_ignore_ascii_case("via:")) {
                    via.push(t.to_string());
                } else if cseq.is_none()
                    && t.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("cseq:"))
                {
                    cseq = Some(t.to_string());
                }
            }

            if via.is_empty() && cseq.is_none() {
                return;
            }

            let mut candidate = self.clone();
            if !via.is_empty() {
                candidate.via = via;
            }
            if let Some(cseq) = cseq {
                candidate.cseq = cseq;
            }

            if sip_reflected_responses_fit(&candidate) {
                self.via = candidate.via;
                self.cseq = candidate.cseq;
            }
        }
    }
}

fn sip_header_line(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

fn sip_header_value(line: &str) -> &str {
    line.split_once(':')
        .map(|(_, value)| value.trim())
        .unwrap_or_else(|| line.trim())
}

fn sip_cseq_method(line: &str) -> Option<&str> {
    let value = sip_header_value(line);
    let mut parts = value.split_ascii_whitespace();
    parts.next()?;
    parts.next()
}

/// Derive a short deterministic tag string from a Call-ID.
fn sip_dialog_tag(call_id: &str) -> String {
    // Simple non-cryptographic hash; just needs to be stable and look hex-like.
    let mut h: u32 = 0x811c_9dc5;
    for b in call_id.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("{h:08x}")
}

// ---------------------------------------------------------------------------
// SIP response builders
// ---------------------------------------------------------------------------

/// Build a well-formed SIP response from a dialog and a numeric status.
///
/// `status_line` is the full first line, e.g. `"SIP/2.0 100 Trying"`.
/// `add_to_tag` controls whether the proxy's To-tag is appended to the To
/// header (required for 180 Ringing and 200 OK, forbidden for 100 Trying).
fn build_sip_response(dialog: &SipDialog, status_line: &str, add_to_tag: bool) -> Bytes {
    let mut buf = BytesMut::with_capacity(SIP_MAX_RESPONSE_SIZE);
    buf.put_slice(status_line.as_bytes());
    buf.put_slice(b"\r\n");

    for v in &dialog.via {
        buf.put_slice(v.as_bytes());
        buf.put_slice(b"\r\n");
    }
    if !dialog.from.is_empty() {
        buf.put_slice(dialog.from.as_bytes());
        buf.put_slice(b"\r\n");
    }
    if !dialog.to.is_empty() {
        if add_to_tag && !sip_to_has_tag(&dialog.to) {
            buf.put_slice(dialog.to.as_bytes());
            buf.put_slice(b";tag=");
            buf.put_slice(dialog.to_tag.as_bytes());
            buf.put_slice(b"\r\n");
        } else {
            buf.put_slice(dialog.to.as_bytes());
            buf.put_slice(b"\r\n");
        }
    }
    if !dialog.call_id.is_empty() {
        buf.put_slice(dialog.call_id.as_bytes());
        buf.put_slice(b"\r\n");
    }
    if !dialog.cseq.is_empty() {
        buf.put_slice(dialog.cseq.as_bytes());
        buf.put_slice(b"\r\n");
    }
    buf.put_slice(b"Content-Length: 0\r\n\r\n");
    buf.freeze()
}

fn sip_to_has_tag(to: &str) -> bool {
    let bytes = to.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b';' {
            i += 1;
            continue;
        }

        i += 1;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
            i += 1;
        }

        if i + 3 <= bytes.len() && bytes[i..i + 3].eq_ignore_ascii_case(b"tag") {
            let mut j = i + 3;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                return true;
            }
        }

        while i < bytes.len() && bytes[i] != b';' {
            i += 1;
        }
    }
    false
}

fn sip_response_fits(dialog: &SipDialog, status_line: &str, add_to_tag: bool) -> bool {
    sip_response_len(dialog, status_line, add_to_tag) <= SIP_MAX_RESPONSE_SIZE
}

fn sip_reflected_responses_fit(dialog: &SipDialog) -> bool {
    [
        ("SIP/2.0 100 Trying", false),
        ("SIP/2.0 180 Ringing", true),
        ("SIP/2.0 200 OK", true),
        ("SIP/2.0 487 Request Terminated", true),
    ]
    .into_iter()
    .all(|(status, add_to_tag)| sip_response_fits(dialog, status, add_to_tag))
}

fn sip_response_len(dialog: &SipDialog, status_line: &str, add_to_tag: bool) -> usize {
    let mut len = status_line.len() + 2;
    len += dialog.via.iter().map(|v| v.len() + 2).sum::<usize>();
    if !dialog.from.is_empty() {
        len += dialog.from.len() + 2;
    }
    if !dialog.to.is_empty() {
        len += dialog.to.len();
        if add_to_tag && !sip_to_has_tag(&dialog.to) {
            len += b";tag=".len() + dialog.to_tag.len();
        }
        len += 2;
    }
    if !dialog.call_id.is_empty() {
        len += dialog.call_id.len() + 2;
    }
    if !dialog.cseq.is_empty() {
        len += dialog.cseq.len() + 2;
    }
    len + b"Content-Length: 0\r\n\r\n".len()
}

/// Parse the SIP method from the first line of a SIP request.
///
/// Returns e.g. `Some("INVITE")`, `Some("ACK")`, `Some("BYE")`, etc.
pub(crate) fn sip_method(data: &[u8]) -> Option<&str> {
    let limit = std::cmp::min(data.len(), 32);
    let text = std::str::from_utf8(&data[..limit]).ok()?;
    let method = text.split_ascii_whitespace().next()?;
    if method.bytes().all(|b| b.is_ascii_alphabetic()) {
        Some(method)
    } else {
        None
    }
}

/// Generate the appropriate SIP response(s) for a given dialog stage + method.
///
/// Returns a list because an INVITE retransmit may need to replay the latest
/// provisional response, or a CANCEL needs
/// both `200 OK` (for CANCEL itself) and `487 Request Terminated` (for the
/// original INVITE transaction).
///
/// The caller is responsible for advancing `dialog.stage` after calling this
/// (use the `SipDialogStage` variant returned by [`sip_next_stage`]).
pub(crate) fn generate_sip_responses(dialog: &SipDialog, method: &str) -> Vec<Bytes> {
    match method.to_ascii_uppercase().as_str() {
        "INVITE" => match dialog.stage {
            SipDialogStage::Idle | SipDialogStage::Terminated => {
                // Fresh call: 100 Trying immediately; 180 Ringing follows
                vec![build_sip_response(dialog, "SIP/2.0 100 Trying", false)]
            }
            SipDialogStage::Invited => {
                // First retransmit before the timer: send the first 180 now.
                vec![
                    build_sip_response(dialog, "SIP/2.0 100 Trying", false),
                    build_sip_response(dialog, "SIP/2.0 180 Ringing", true),
                ]
            }
            SipDialogStage::Ringing => {
                // Later retransmits replay the latest provisional response.
                vec![build_sip_response(dialog, "SIP/2.0 180 Ringing", true)]
            }
            SipDialogStage::Established => {
                // Retransmit after 200 OK sent — re-send 200 OK until ACK arrives.
                vec![build_sip_response(dialog, "SIP/2.0 200 OK", true)]
            }
        },
        "ACK" => vec![],
        "BYE" => {
            vec![build_sip_response(dialog, "SIP/2.0 200 OK", true)]
        }
        "CANCEL" => {
            let mut invite_dialog = dialog.clone();
            invite_dialog.via = invite_dialog.invite_via.clone();
            invite_dialog.cseq = invite_dialog.invite_cseq.clone();
            let mut responses = vec![build_sip_response(dialog, "SIP/2.0 200 OK", false)];
            if sip_cseq_method(&invite_dialog.cseq)
                .is_some_and(|method| method.eq_ignore_ascii_case("INVITE"))
            {
                responses.push(build_sip_response(
                    &invite_dialog,
                    "SIP/2.0 487 Request Terminated",
                    true,
                ));
            }
            responses
        }
        _ => {
            // REGISTER / OPTIONS / NOTIFY / SUBSCRIBE / MESSAGE / INFO — 200 OK
            let in_dialog = matches!(
                dialog.stage,
                SipDialogStage::Invited | SipDialogStage::Ringing | SipDialogStage::Established
            );
            vec![build_sip_response(dialog, "SIP/2.0 200 OK", in_dialog)]
        }
    }
}

/// Return the next `SipDialogStage` after handling `method` in the current dialog.
pub(crate) fn sip_next_stage(current: SipDialogStage, method: &str) -> SipDialogStage {
    match method.to_ascii_uppercase().as_str() {
        "INVITE" => match current {
            SipDialogStage::Idle | SipDialogStage::Terminated => SipDialogStage::Invited,
            SipDialogStage::Invited => SipDialogStage::Ringing,
            SipDialogStage::Ringing | SipDialogStage::Established => current,
        },
        "ACK" => match current {
            SipDialogStage::Established => SipDialogStage::Established,
            SipDialogStage::Idle
            | SipDialogStage::Invited
            | SipDialogStage::Ringing
            | SipDialogStage::Terminated => current,
        },
        "BYE" => match current {
            SipDialogStage::Idle => SipDialogStage::Idle,
            SipDialogStage::Invited
            | SipDialogStage::Ringing
            | SipDialogStage::Established
            | SipDialogStage::Terminated => SipDialogStage::Terminated,
        },
        "CANCEL" => match current {
            SipDialogStage::Invited | SipDialogStage::Ringing => SipDialogStage::Terminated,
            SipDialogStage::Idle | SipDialogStage::Established | SipDialogStage::Terminated => {
                current
            }
        },
        _ => current,
    }
}

/// Generate a `180 Ringing` response to be sent after a short delay following
/// the initial `100 Trying` for a fresh INVITE.
pub(crate) fn generate_sip_ringing(dialog: &SipDialog) -> Bytes {
    build_sip_response(dialog, "SIP/2.0 180 Ringing", true)
}

/// Generate a `200 OK` response for the INVITE (sent after ACK-timeout or
/// after a separate trigger — kept for explicit use by the proxy).
pub(crate) fn generate_sip_ok(dialog: &SipDialog) -> Bytes {
    build_sip_response(dialog, "SIP/2.0 200 OK", true)
}

/// Fallback: generate a stateless `100 Trying` by echoing headers from the raw
/// incoming bytes.  Used when no dialog state is available yet.
fn generate_sip_trying(incoming: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(SIP_MAX_RESPONSE_SIZE);
    buf.put_slice(b"SIP/2.0 100 Trying\r\n");

    let suffix = b"Content-Length: 0\r\n\r\n";
    let scan_limit = std::cmp::min(incoming.len(), SIP_SCAN_LIMIT);
    if let Ok(text) = std::str::from_utf8(&incoming[..scan_limit]) {
        let echo_prefixes = ["via:", "from:", "to:", "call-id:", "cseq:"];
        for line in text.lines() {
            let trimmed = line.trim();
            for &prefix in &echo_prefixes {
                if trimmed
                    .get(..prefix.len())
                    .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
                {
                    let line_len = trimmed.len() + 2;
                    if buf.len() + line_len + suffix.len() > SIP_MAX_RESPONSE_SIZE {
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
        let supported_version = u32::from_be_bytes([
            resp[resp.len() - 4],
            resp[resp.len() - 3],
            resp[resp.len() - 2],
            resp[resp.len() - 1],
        ]);
        assert_ne!(
            supported_version, 0x00000001,
            "must not advertise QUIC v1 in VN response to a v1 client"
        );
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

    // -----------------------------------------------------------------------
    // SIP dialog state machine tests
    // -----------------------------------------------------------------------

    /// A realistic INVITE packet similar to what the pcap shows.
    fn sample_invite() -> Vec<u8> {
        b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
Max-Forwards: 70\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: 66ad04dd4dfefac9@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    fn sample_options() -> Vec<u8> {
        b"OPTIONS sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: options-call@192.168.224.194\r\n\
CSeq: 95930 OPTIONS\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    #[test]
    fn detect_sip_ack_bye_info_message() {
        for method in ["ACK ", "BYE ", "INFO ", "MESSAGE "] {
            let pkt = format!("{method}sip:bob@example.com SIP/2.0\r\n");
            assert_eq!(
                detect_protocol(pkt.as_bytes()),
                Some(Protocol::Sip),
                "{method} should be detected as SIP"
            );
        }
    }

    #[test]
    fn sip_method_parse() {
        assert_eq!(sip_method(b"INVITE sip:x SIP/2.0\r\n"), Some("INVITE"));
        assert_eq!(sip_method(b"BYE sip:x SIP/2.0\r\n"), Some("BYE"));
        assert_eq!(sip_method(b"ACK sip:x SIP/2.0\r\n"), Some("ACK"));
        assert_eq!(sip_method(b"CANCEL sip:x SIP/2.0\r\n"), Some("CANCEL"));
        assert_eq!(sip_method(b"SIP/2.0 100 Trying\r\n"), None); // responses have no valid method
        assert_eq!(sip_method(b""), None);
    }

    #[test]
    fn sip_dialog_from_invite_parses_headers() {
        let invite = sample_invite();
        let dialog = SipDialog::from_invite(&invite).expect("should parse");
        assert_eq!(dialog.stage, SipDialogStage::Idle);
        assert!(!dialog.via.is_empty());
        assert!(dialog.via[0].starts_with("Via:"));
        assert!(dialog.from.starts_with("From:"));
        assert!(dialog.to.starts_with("To:"));
        assert!(dialog.call_id.starts_with("Call-ID:"));
        assert!(dialog.cseq.starts_with("CSeq:"));
        assert!(!dialog.to_tag.is_empty());
    }

    #[test]
    fn sip_dialog_rejects_missing_required_headers() {
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bK\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
Call-ID: missing-to@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        assert!(SipDialog::from_invite(invite).is_none());
    }

    #[test]
    fn sip_dialog_rejects_empty_required_header_values() {
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bK\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID:     \r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        assert!(SipDialog::from_invite(invite).is_none());

        let options = b"OPTIONS sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bK\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: options-call@192.168.224.194\r\n\
CSeq:   \r\n\
Content-Length: 0\r\n\r\n";
        assert!(SipDialog::from_request(options).is_none());
    }

    #[test]
    fn sip_dialog_ignores_body_lines_after_header_terminator() {
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: body-via@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 52\r\n\r\n\
Via: SIP/2.0/UDP body.example.com:5060;branch=body\r\n";

        assert!(SipDialog::from_invite(invite).is_none());
    }

    #[test]
    fn sip_dialog_rejects_oversized_reflected_headers() {
        let oversized_from = "a".repeat(700);
        let invite = format!(
            "INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bK\r\n\
From: <sip:{oversized_from}@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: too-large@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n"
        );
        assert!(SipDialog::from_invite(invite.as_bytes()).is_none());
    }

    #[test]
    fn sip_dialog_echoes_multiple_via_headers_in_order() {
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP proxy1.example.com:5060;branch=z9hG4bK111\r\n\
Via: SIP/2.0/UDP proxy2.example.com:5060;branch=z9hG4bK222\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: multi-via@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let dialog = SipDialog::from_invite(invite).unwrap();
        assert_eq!(dialog.via.len(), 2);

        let responses = generate_sip_responses(&dialog, "INVITE");
        let text = std::str::from_utf8(&responses[0]).unwrap();
        let via_lines: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("Via:"))
            .collect();
        assert_eq!(
            via_lines,
            vec![
                "Via: SIP/2.0/UDP proxy1.example.com:5060;branch=z9hG4bK111",
                "Via: SIP/2.0/UDP proxy2.example.com:5060;branch=z9hG4bK222",
            ]
        );
    }

    #[test]
    fn sip_dialog_preserves_header_whitespace_when_echoing() {
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP proxy1.example.com:5060;branch=z9hG4bK111   \r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4  \r\n\
To: Olivia <sip:olivia@profi.ru> \r\n\
Call-ID: whitespace@192.168.224.194 \r\n\
CSeq: 95929 INVITE  \r\n\
Content-Length: 0\r\n\r\n";
        let dialog = SipDialog::from_invite(invite).unwrap();
        let response = generate_sip_responses(&dialog, "INVITE");
        let text = std::str::from_utf8(&response[0]).unwrap();

        assert!(text.contains("Via: SIP/2.0/UDP proxy1.example.com:5060;branch=z9hG4bK111   \r\n"));
        assert!(text.contains("From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4  \r\n"));
        assert!(text.contains("To: Olivia <sip:olivia@profi.ru> \r\n"));
        assert!(text.contains("Call-ID: whitespace@192.168.224.194 \r\n"));
        assert!(text.contains("CSeq: 95929 INVITE  \r\n"));
    }

    #[test]
    fn sip_response_len_matches_built_response_len() {
        let invite = sample_invite();
        let dialog = SipDialog::from_invite(&invite).unwrap();
        let response = generate_sip_ok(&dialog);

        assert_eq!(
            sip_response_len(&dialog, "SIP/2.0 200 OK", true),
            response.len()
        );
    }

    #[test]
    fn sip_dialog_tag_is_deterministic() {
        let id = "66ad04dd4dfefac9@192.168.224.194";
        assert_eq!(sip_dialog_tag(id), sip_dialog_tag(id));
        assert_ne!(sip_dialog_tag(id), sip_dialog_tag("other-call-id"));
    }

    #[test]
    fn sip_dialog_tag_uses_call_id_value() {
        let invite_a = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bK\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: same-value@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let invite_b = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bK\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
CALL-ID:    same-value@192.168.224.194   \r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";

        let dialog_a = SipDialog::from_invite(invite_a).unwrap();
        let dialog_b = SipDialog::from_invite(invite_b).unwrap();

        assert_eq!(dialog_a.to_tag, dialog_b.to_tag);
    }

    #[test]
    fn sip_dialog_invite_returns_100_trying_no_to_tag() {
        let invite = sample_invite();
        let dialog = SipDialog::from_invite(&invite).unwrap();
        let responses = generate_sip_responses(&dialog, "INVITE");
        assert_eq!(responses.len(), 1);
        let text = std::str::from_utf8(&responses[0]).unwrap();
        assert!(text.starts_with("SIP/2.0 100 Trying\r\n"));
        // RFC 3261 §8.2.6.1: 100 Trying MUST NOT add a proxy-assigned To tag.
        // Check the To: line specifically — the From: line has its own client tag.
        let to_line = text.lines().find(|l| l.starts_with("To:")).unwrap_or("");
        assert!(
            !to_line.contains(";tag="),
            "100 Trying To: must not carry a tag"
        );
    }

    #[test]
    fn sip_dialog_invited_retransmit_returns_100_and_180() {
        let invite = sample_invite();
        let mut dialog = SipDialog::from_invite(&invite).unwrap();
        // Advance to Invited manually to simulate a retransmit
        dialog.stage = SipDialogStage::Invited;
        assert_eq!(dialog.stage, SipDialogStage::Invited);
        let responses = generate_sip_responses(&dialog, "INVITE");
        assert_eq!(responses.len(), 2);
        let t0 = std::str::from_utf8(&responses[0]).unwrap();
        let t1 = std::str::from_utf8(&responses[1]).unwrap();
        assert!(t0.starts_with("SIP/2.0 100 Trying\r\n"));
        assert!(t1.starts_with("SIP/2.0 180 Ringing\r\n"));
        // 180 Ringing MUST add a To tag (RFC 3261 §12.1.1)
        assert!(t1.contains(";tag="));
        // Advance stage
        dialog.stage = sip_next_stage(dialog.stage, "INVITE");
        assert_eq!(dialog.stage, SipDialogStage::Ringing);
        let responses = generate_sip_responses(&dialog, "INVITE");
        assert_eq!(responses.len(), 1);
        assert!(std::str::from_utf8(&responses[0])
            .unwrap()
            .starts_with("SIP/2.0 180 Ringing\r\n"));
    }

    #[test]
    fn sip_dialog_ack_returns_no_response() {
        let invite = sample_invite();
        let mut dialog = SipDialog::from_invite(&invite).unwrap();
        dialog.stage = SipDialogStage::Established;
        let responses = generate_sip_responses(&dialog, "ACK");
        assert!(responses.is_empty());
        dialog.stage = sip_next_stage(dialog.stage, "ACK");
        assert_eq!(dialog.stage, SipDialogStage::Established);
    }

    #[test]
    fn sip_dialog_bye_returns_200_ok_with_to_tag() {
        let invite = sample_invite();
        let mut dialog = SipDialog::from_invite(&invite).unwrap();
        dialog.stage = SipDialogStage::Established;
        dialog.update_request_headers(
            b"BYE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKbye;rport\r\n\
CSeq: 95930 BYE\r\n\r\n",
        );
        let responses = generate_sip_responses(&dialog, "BYE");
        assert_eq!(responses.len(), 1);
        let text = std::str::from_utf8(&responses[0]).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(text.contains(
            "Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKbye;rport"
        ));
        assert!(text.contains("CSeq: 95930 BYE"));
        assert!(text.contains(";tag="), "200 OK for BYE must carry To tag");
        dialog.stage = sip_next_stage(dialog.stage, "BYE");
        assert_eq!(dialog.stage, SipDialogStage::Terminated);
    }

    #[test]
    fn sip_dialog_cancel_returns_200_and_487() {
        let invite = sample_invite();
        let mut dialog = SipDialog::from_invite(&invite).unwrap();
        dialog.update_request_headers(
            b"CANCEL sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKcancel;rport\r\n\
CSeq: 95931 CANCEL\r\n\r\n",
        );
        let responses = generate_sip_responses(&dialog, "CANCEL");
        assert_eq!(responses.len(), 2);
        let t0 = std::str::from_utf8(&responses[0]).unwrap();
        let t1 = std::str::from_utf8(&responses[1]).unwrap();
        assert!(t0.starts_with("SIP/2.0 200 OK\r\n"), "CANCEL → 200 OK");
        assert!(t0.contains("CSeq: 95931 CANCEL"));
        assert!(
            t1.starts_with("SIP/2.0 487 Request Terminated\r\n"),
            "CANCEL → 487"
        );
        assert!(t1.contains("CSeq: 95929 INVITE"));
        assert!(t0.contains("branch=z9hG4bKcancel"));
        assert!(t1.contains("branch=z9hG4bKee43689b8812e305"));
        assert!(!t1.contains("branch=z9hG4bKcancel"));
        // 200 for CANCEL: To header must not carry the proxy-assigned to_tag
        // (the From header legitimately contains the client's own tag).
        let to_tag = &dialog.to_tag;
        assert!(
            !t0.contains(to_tag.as_str()),
            "200 OK for CANCEL must not add To tag"
        );
    }

    #[test]
    fn sip_dialog_request_scoped_cancel_returns_only_200_ok() {
        let cancel = b"CANCEL sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKcancel;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>\r\n\
Call-ID: request-scoped-cancel@192.168.224.194\r\n\
CSeq: 95931 CANCEL\r\n\
Content-Length: 0\r\n\r\n";

        let dialog = SipDialog::from_request(cancel).unwrap();
        let responses = generate_sip_responses(&dialog, "CANCEL");
        assert_eq!(responses.len(), 1);
        let text = std::str::from_utf8(&responses[0]).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(text.contains("CSeq: 95931 CANCEL"));
        assert!(!text.contains("487 Request Terminated"));
    }

    #[test]
    fn sip_dialog_options_returns_200_ok() {
        let invite = sample_invite();
        let dialog = SipDialog::from_invite(&invite).unwrap();
        let responses = generate_sip_responses(&dialog, "OPTIONS");
        assert_eq!(responses.len(), 1);
        assert!(std::str::from_utf8(&responses[0])
            .unwrap()
            .starts_with("SIP/2.0 200 OK\r\n"));
    }

    #[test]
    fn sip_dialog_options_without_existing_dialog_returns_200_ok() {
        let options = sample_options();
        let dialog = SipDialog::from_request(&options).unwrap();
        let responses = generate_sip_responses(&dialog, "OPTIONS");
        assert_eq!(responses.len(), 1);
        let text = std::str::from_utf8(&responses[0]).unwrap();
        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(text.contains("CSeq: 95930 OPTIONS"));
    }

    #[test]
    fn sip_dialog_in_dialog_generic_request_returns_200_ok_with_to_tag() {
        let invite = sample_invite();
        let mut dialog = SipDialog::from_invite(&invite).unwrap();
        dialog.stage = SipDialogStage::Established;
        dialog.update_request_headers(
            b"INFO sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKinfo;rport\r\n\
CSeq: 95930 INFO\r\n\r\n",
        );

        let responses = generate_sip_responses(&dialog, "INFO");
        assert_eq!(responses.len(), 1);
        let text = std::str::from_utf8(&responses[0]).unwrap();
        let to_line = text.lines().find(|line| line.starts_with("To:")).unwrap();
        assert!(to_line.contains(dialog.to_tag.as_str()));
        assert!(text.contains("CSeq: 95930 INFO"));
    }

    #[test]
    fn sip_dialog_response_does_not_duplicate_existing_to_tag() {
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>;tag=remote-tag\r\n\
Call-ID: tagged-to@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let dialog = SipDialog::from_invite(invite).unwrap();
        let ok = generate_sip_ok(&dialog);
        let text = std::str::from_utf8(&ok).unwrap();
        let to_line = text.lines().find(|line| line.starts_with("To:")).unwrap();
        assert_eq!(to_line.matches(";tag=").count(), 1);
        assert!(to_line.contains(";tag=remote-tag"));
    }

    #[test]
    fn sip_dialog_response_detects_spaced_to_tag() {
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>; tag = remote-tag\r\n\
Call-ID: spaced-tagged-to@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let dialog = SipDialog::from_invite(invite).unwrap();
        let ok = generate_sip_ok(&dialog);
        let text = std::str::from_utf8(&ok).unwrap();
        let to_line = text.lines().find(|line| line.starts_with("To:")).unwrap();
        assert!(to_line.contains("; tag = remote-tag"));
        assert!(!to_line.contains(dialog.to_tag.as_str()));
    }

    #[test]
    fn sip_dialog_response_skips_non_tag_to_parameters() {
        let invite = b"INVITE sip:olivia@profi.ru SIP/2.0\r\n\
Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bKee43689b8812e305;rport\r\n\
From: Frank545 <sip:frank545@profi.ru>;tag=a3c46b4581b775e4\r\n\
To: Olivia <sip:olivia@profi.ru>;foo=bar; tag = remote-tag\r\n\
Call-ID: param-tagged-to@192.168.224.194\r\n\
CSeq: 95929 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let dialog = SipDialog::from_invite(invite).unwrap();
        let ok = generate_sip_ok(&dialog);
        let text = std::str::from_utf8(&ok).unwrap();
        let to_line = text.lines().find(|line| line.starts_with("To:")).unwrap();
        assert!(to_line.contains(";foo=bar; tag = remote-tag"));
        assert!(!to_line.contains(dialog.to_tag.as_str()));
    }

    #[test]
    fn sip_dialog_oversized_cseq_update_is_ignored() {
        let invite = sample_invite();
        let mut dialog = SipDialog::from_invite(&invite).unwrap();
        let original_cseq = dialog.cseq.clone();
        let oversized = format!(
            "BYE sip:olivia@profi.ru SIP/2.0\r\nCSeq: 1 {}\r\n",
            "A".repeat(700)
        );

        dialog.update_request_headers(oversized.as_bytes());

        assert_eq!(dialog.cseq, original_cseq);
    }

    #[test]
    fn sip_dialog_update_rejects_headers_that_make_ringing_too_large() {
        let invite = sample_invite();
        let mut dialog = SipDialog::from_invite(&invite).unwrap();
        let original_via = dialog.via.clone();
        let original_cseq = dialog.cseq.clone();

        let (via, cseq) = (0..700)
            .find_map(|n| {
                let via = format!(
                    "Via: SIP/2.0/UDP 172.23.4.143:59672;branch=z9hG4bK{};rport",
                    "A".repeat(n)
                );
                let cseq = "CSeq: 95930 INVITE".to_string();
                let mut candidate = dialog.clone();
                candidate.via = vec![via.clone()];
                candidate.cseq = cseq.clone();
                if sip_response_fits(&candidate, "SIP/2.0 200 OK", true)
                    && !sip_response_fits(&candidate, "SIP/2.0 180 Ringing", true)
                {
                    Some((via, cseq))
                } else {
                    None
                }
            })
            .expect("test should find a Via length where 200 fits but 180 does not");
        let update = format!("INVITE sip:olivia@profi.ru SIP/2.0\r\n{via}\r\n{cseq}\r\n\r\n");

        dialog.update_request_headers(update.as_bytes());

        assert_eq!(dialog.via, original_via);
        assert_eq!(dialog.cseq, original_cseq);
    }

    #[test]
    fn sip_dialog_responses_echo_call_id_and_cseq() {
        let invite = sample_invite();
        let dialog = SipDialog::from_invite(&invite).unwrap();
        let responses = generate_sip_responses(&dialog, "INVITE");
        let text = std::str::from_utf8(&responses[0]).unwrap();
        assert!(text.contains("Call-ID: 66ad04dd4dfefac9@192.168.224.194"));
        assert!(text.contains("CSeq: 95929 INVITE"));
    }

    #[test]
    fn sip_ringing_and_ok_helpers() {
        let invite = sample_invite();
        let dialog = SipDialog::from_invite(&invite).unwrap();
        let ringing = generate_sip_ringing(&dialog);
        let ok = generate_sip_ok(&dialog);
        assert!(std::str::from_utf8(&ringing)
            .unwrap()
            .starts_with("SIP/2.0 180 Ringing\r\n"));
        assert!(std::str::from_utf8(&ok)
            .unwrap()
            .starts_with("SIP/2.0 200 OK\r\n"));
    }

    #[test]
    fn sip_next_stage_transitions() {
        assert_eq!(
            sip_next_stage(SipDialogStage::Idle, "INVITE"),
            SipDialogStage::Invited
        );
        assert_eq!(
            sip_next_stage(SipDialogStage::Invited, "ACK"),
            SipDialogStage::Invited
        );
        assert_eq!(
            sip_next_stage(SipDialogStage::Ringing, "ACK"),
            SipDialogStage::Ringing
        );
        assert_eq!(
            sip_next_stage(SipDialogStage::Invited, "INVITE"),
            SipDialogStage::Ringing
        );
        assert_eq!(
            sip_next_stage(SipDialogStage::Ringing, "INVITE"),
            SipDialogStage::Ringing
        );
        assert_eq!(
            sip_next_stage(SipDialogStage::Established, "INVITE"),
            SipDialogStage::Established
        );
        assert_eq!(
            sip_next_stage(SipDialogStage::Established, "BYE"),
            SipDialogStage::Terminated
        );
        assert_eq!(
            sip_next_stage(SipDialogStage::Invited, "CANCEL"),
            SipDialogStage::Terminated
        );
        assert_eq!(
            sip_next_stage(SipDialogStage::Established, "CANCEL"),
            SipDialogStage::Established
        );
        // Unknown methods leave stage unchanged
        assert_eq!(
            sip_next_stage(SipDialogStage::Established, "OPTIONS"),
            SipDialogStage::Established
        );
    }
}
