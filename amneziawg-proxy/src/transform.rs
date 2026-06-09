#[cfg(test)]
use bytes::{BufMut, BytesMut};

use crate::config::AwgParams;
use crate::responder::{classify_awg_packet, AwgPacketType, DnsEcho, Protocol};

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
/// - **QUIC**: 1-RTT short header for every phase (see `apply_quic_padding_typed`).
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
        Protocol::Quic => apply_quic_padding_short(data, pad_size),
        Protocol::Dns => apply_dns_padding(data, pad_size, None),
        Protocol::Stun => apply_stun_padding(data, pad_size),
        Protocol::Sip => apply_sip_padding(data, pad_size),
    }
}

/// Apply QUIC-style padding for the given AWG packet type.
///
/// All phases are imitated as **1-RTT short-header** packets (`0x40..0x7F`).
/// Short headers have no version or length field, so the bytes after the first
/// are indistinguishable from encrypted 1-RTT ciphertext — the dominant and
/// least-conspicuous QUIC packet type — and there is no length field that could
/// fail to frame the immutable WG payload (which is what made the previous
/// long-header Handshake imitation parse as malformed).
///
/// Long-header forms are deliberately avoided here: Initial requires a datagram
/// of at least 1200 bytes (RFC 9000 §14.1) that the fixed `S1+148` size cannot
/// meet, and a lone Handshake packet would have no preceding Initial (S1 is
/// 1-RTT, not Initial) — incoherent QUIC state. `pkt_type` is retained for API
/// symmetry and future per-phase tuning.
pub fn apply_quic_padding_typed(
    data: &mut [u8],
    pad_size: usize,
    pkt_type: AwgPacketType,
) {
    if pad_size == 0 || pad_size >= data.len() {
        return;
    }
    // Every AWG phase is imitated as a 1-RTT short-header packet.
    //
    // S1/S4 always were: QUIC Initial requires >=1200-byte datagrams (RFC 9000
    // §14.1) which the fixed S1+148 wire size cannot meet, and 1-RTT short
    // headers carry no size minimum and dominate real QUIC sessions.
    //
    // S2/S3 (Handshake Response / Cookie Reply) now join them. A QUIC long-header
    // Handshake packet carries a mandatory Length field that must frame the
    // Packet Number + payload; the imitation cannot make it span the immutable
    // WG ciphertext without writing a full DCID/SCID/Length structure, and even
    // then it would be a lone Handshake with no preceding Initial (S1 is 1-RTT,
    // not Initial) — semantically incoherent and, as emitted before, malformed.
    // A uniform 1-RTT flow is coherent and never malformed.
    match pkt_type {
        AwgPacketType::HandshakeInit
        | AwgPacketType::TransportData
        | AwgPacketType::HandshakeResponse
        | AwgPacketType::CookieReply => apply_quic_padding_short(data, pad_size),
    }
}

/// Apply AWG-aware padding transformation to an outgoing packet.
///
/// Classifies the packet using the S-offset / H-range pairs to determine its
/// type, then overwrites the leading S-padding prefix with protocol-conformant
/// filler. For QUIC every phase is emitted as a 1-RTT short header (see
/// `apply_quic_padding_typed`).
///
/// Returns `true` if the packet was classified and transformed, `false` if the
/// packet type could not be identified (e.g. junk packet) and was left
/// unchanged.
/// `dns_echo`, when present, is the most recent DNS query observed from this
/// client; for `Protocol::Dns` it lets the response echo the query's QNAME,
/// QTYPE, and transaction ID (ignored for other protocols).
pub(crate) fn apply_awg_transform(
    data: &mut [u8],
    params: &AwgParams,
    proto: Protocol,
    dns_echo: Option<&DnsEcho>,
) -> bool {
    let pkt_type = match classify_awg_packet(data, params) {
        Some(t) => t,
        None => return false,
    };

    let pad_size = pkt_type.padding_size(params);
    let total = data.len();

    if pad_size == 0 || pad_size >= total {
        return false;
    }

    match proto {
        Protocol::Quic => apply_quic_padding_typed(data, pad_size, pkt_type),
        Protocol::Dns => apply_dns_padding(data, pad_size, dns_echo),
        _ => apply_padding(data, pad_size, proto),
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

/// QUIC short-header 1-RTT padding (all AWG phases — see `apply_quic_padding_typed`).
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

/// DNS message header length (RFC 1035 §4.1.1).
const DNS_HEADER_LEN: usize = 12;
/// Root-label question length: QNAME `0x00` + QTYPE(2) + QCLASS(2).
const DNS_ROOT_QUESTION_LEN: usize = 5;
/// EDNS0 OPT RR fixed prefix: root NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
const DNS_OPT_FIXED_LEN: usize = 11;
/// EDNS0 option header: OPTION-CODE(2) + OPTION-LENGTH(2).
const DNS_OPT_OPTION_HDR_LEN: usize = 4;
/// Smallest pad prefix that fits the full OPT framing with a root-label question.
const DNS_OPT_MIN: usize =
    DNS_HEADER_LEN + DNS_ROOT_QUESTION_LEN + DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN; // 32
/// EDNS0 OPT advertised UDP payload size (modern resolver default, RFC 6891).
const DNS_OPT_UDP_SIZE: u16 = 1232;
/// EDNS0 option code for the opaque cover payload. 65001 (0xFDE9) is in the
/// IANA "local/experimental" range (RFC 6891 §6.1.2): resolvers must ignore
/// unknown options regardless of length, so this carries the ciphertext without
/// the zero-content expectation that option code 12 (Padding, RFC 7830) implies.
const DNS_OPT_COVER_CODE: u16 = 0xFDE9;

/// DNS-style padding: a realistic EDNS *response* whose Additional-section
/// `OPT (41)` record (RFC 6891) accounts for every byte of the UDP datagram
/// after the fixed prefix. The encrypted AWG payload becomes the opaque
/// option-data of a single unknown EDNS option, so the whole datagram parses as
/// one well-formed DNS message with no trailing bytes — while looking like the
/// ordinary EDNS traffic that dominates the modern internet, rather than the
/// `TYPE NULL` answer used previously (which is essentially never seen in the
/// wild and is a strong fingerprint).
///
/// Layout (root-label question; `question_len` grows when a real QNAME is echoed):
///
/// ```text
/// Bytes 0..pad_size (rewritten):
///   [ Header 12 B ][ Question 5 B ][ OPT fixed 11 B ][ option hdr 4 B ][ zero-fill ]
/// Bytes pad_size..total (intact):
///   [ encrypted AWG payload ]
///   ^--- zero-fill + payload are the OPT option-data (OPTION-LENGTH covers them);
///        the OPT RDLENGTH covers the option header + option-data, so every byte
///        is inside the OPT RR and nothing is left dangling.
/// ```
///
/// - **Header** (12 B): TXID from payload bytes 0-1; flags `0x8180`
///   (QR=1, RD=1, RA=1, NOERROR) — RD is echoed so the response matches the
///   client's `RD=1` queries. `QDCOUNT=1`, `ANCOUNT=0`, `ARCOUNT=1`.
/// - **Question** (5 B): root-label QNAME + `QTYPE A` + `QCLASS IN`.
/// - **OPT RR** (11 B fixed + 4 B option header): root NAME, `TYPE OPT (41)`,
///   CLASS = advertised UDP size 1232, TTL field 0 (ext-rcode/version/flags),
///   `RDLENGTH = total_len - (12 + question_len + 11)`, then one option
///   `{code = 0xFDE9 (unknown), length = total_len - (12 + question_len + 15)}`.
///
/// For `pad_size < DNS_OPT_MIN` the OPT framing does not fit; the function falls
/// back to [`apply_dns_padding_null`], which keeps the previous `TYPE NULL`
/// behaviour for those rare small pads (response S-values are normally far
/// larger). Returns immediately when `pad_size == 0`.
fn apply_dns_padding(data: &mut [u8], pad_size: usize, echo: Option<&DnsEcho>) {
    if pad_size == 0 {
        return;
    }
    if pad_size < DNS_OPT_MIN {
        apply_dns_padding_null(data, pad_size);
        return;
    }

    let total_len = data.len();
    let (padding, payload) = data.split_at_mut(pad_size);

    // Build the question section. When the client's most recent query fits the
    // pad prefix, echo its QNAME/QTYPE and reuse its transaction ID so the
    // response mirrors the request (RFC 1035 §4.1.1). Otherwise fall back to a
    // root-label question with a payload-derived ID.
    let mut qbuf = [0u8; 259]; // max QNAME 255 (incl. root) + QTYPE 2 + QCLASS 2
    let (question, txid): (&[u8], [u8; 2]) = match echo {
        Some(e)
            if e.qname.len() + 4 <= qbuf.len()
                && DNS_HEADER_LEN + e.qname.len() + 4 + DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN
                    <= pad_size =>
        {
            let qn = e.qname.len();
            qbuf[..qn].copy_from_slice(&e.qname);
            qbuf[qn..qn + 2].copy_from_slice(&e.qtype);
            qbuf[qn + 2..qn + 4].copy_from_slice(&[0x00, 0x01]); // QCLASS IN
            (&qbuf[..qn + 4], e.txid)
        }
        _ => {
            qbuf[..5].copy_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // root QNAME + A + IN
            let txid = [
                payload.first().copied().unwrap_or(0),
                payload.get(1).copied().unwrap_or(0),
            ];
            (&qbuf[..5], txid)
        }
    };

    write_dns_opt_response(padding, total_len, txid, question);
}

/// Write an EDNS OPT-framed DNS response header into `padding` (the `pad_size`
/// prefix), with `question` already encoded (QNAME wire bytes + QTYPE + QCLASS).
///
/// Caller guarantees `padding.len() >= DNS_HEADER_LEN + question.len()
/// + DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN`, so every field below is in
/// range. The OPT option-data spans the rest of the datagram (the zero-filled
/// tail of `padding` plus the untouched payload after it).
fn write_dns_opt_response(padding: &mut [u8], total_len: usize, txid: [u8; 2], question: &[u8]) {
    let opt_off = DNS_HEADER_LEN + question.len();
    // RDLENGTH covers the option header + option-data = everything after the
    // RDLENGTH field. OPTION-LENGTH covers just the option-data.
    let rdlength = total_len
        .saturating_sub(opt_off + DNS_OPT_FIXED_LEN)
        .min(u16::MAX as usize) as u16;
    let opt_len = total_len
        .saturating_sub(opt_off + DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN)
        .min(u16::MAX as usize) as u16;

    // Header (12 B).
    padding[0] = txid[0];
    padding[1] = txid[1];
    padding[2] = 0x81; // QR=1, opcode=0, AA=0, TC=0, RD=1
    padding[3] = 0x80; // RA=1, Z=0, RCODE=NOERROR
    padding[4] = 0x00;
    padding[5] = 0x01; // QDCOUNT = 1
    padding[6] = 0x00;
    padding[7] = 0x00; // ANCOUNT = 0 (NODATA)
    padding[8] = 0x00;
    padding[9] = 0x00; // NSCOUNT = 0
    padding[10] = 0x00;
    padding[11] = 0x01; // ARCOUNT = 1 (the OPT RR)

    // Question.
    padding[DNS_HEADER_LEN..opt_off].copy_from_slice(question);

    // OPT RR fixed prefix (11 B) + option header (4 B).
    let [rl_hi, rl_lo] = rdlength.to_be_bytes();
    let [oc_hi, oc_lo] = DNS_OPT_COVER_CODE.to_be_bytes();
    let [ol_hi, ol_lo] = opt_len.to_be_bytes();
    let [us_hi, us_lo] = DNS_OPT_UDP_SIZE.to_be_bytes();
    #[rustfmt::skip]
    let opt: [u8; DNS_OPT_FIXED_LEN + DNS_OPT_OPTION_HDR_LEN] = [
        0x00,           // NAME: root label (OPT must use the root name)
        0x00, 0x29,     // TYPE  = OPT (41)
        us_hi, us_lo,   // CLASS = requestor's UDP payload size (1232)
        0x00, 0x00, 0x00, 0x00, // TTL: ext-RCODE 0, EDNS version 0, flags 0 (DO=0)
        rl_hi, rl_lo,   // RDLENGTH = option header + option-data
        oc_hi, oc_lo,   // OPTION-CODE = 0xFDE9 (unknown / local-use)
        ol_hi, ol_lo,   // OPTION-LENGTH = option-data bytes (zero-fill tail + payload)
    ];
    padding[opt_off..opt_off + opt.len()].copy_from_slice(&opt);

    // Zero-fill the remaining padding bytes; they are the leading part of the
    // OPT option-data (the rest is the untouched payload after `pad_size`).
    for byte in padding[opt_off + opt.len()..].iter_mut() {
        *byte = 0x00;
    }
}

/// Legacy `TYPE NULL` DNS padding, retained only for `pad_size < DNS_OPT_MIN`
/// (too small for the OPT framing). A NULL RR (RFC 1035 §3.3.10) carries opaque
/// RDATA of any length, so for `pad_size >= 28` it still covers the whole
/// datagram; smaller pads degrade to header(+question) only, with the count
/// fields advertising just the sections that physically fit.
fn apply_dns_padding_null(data: &mut [u8], pad_size: usize) {
    let total_len = data.len();
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }

    let tx_hi = payload.first().copied().unwrap_or(0);
    let tx_lo = payload.get(1).copied().unwrap_or(0);

    let qdcount: u8 = if pad_size >= 17 { 1 } else { 0 };
    let ancount: u8 = if pad_size >= 28 { 1 } else { 0 };

    let rdlength: u16 = total_len.saturating_sub(28).min(u16::MAX as usize) as u16;
    let [rl_hi, rl_lo] = rdlength.to_be_bytes();

    #[rustfmt::skip]
    let fixed: [u8; 28] = [
        tx_hi, tx_lo,
        0x81, 0x80,             // Flags: QR=1, RD=1, RA=1, RCODE=NOERROR
        0x00, qdcount,
        0x00, ancount,
        0x00, 0x00,
        0x00, 0x00,
        0x00,                   // QNAME: root label
        0x00, 0x01,             // QTYPE  = A
        0x00, 0x01,             // QCLASS = IN
        0x00,                   // answer NAME: root label
        0x00, 0x0a,             // TYPE  = NULL (10)
        0x00, 0x01,             // CLASS = IN
        0x00, 0x00, 0x00, 0x3c, // TTL = 60
        rl_hi, rl_lo,           // RDLENGTH = total_len - 28
    ];

    let advertised_len: usize = if pad_size >= 28 {
        28
    } else if pad_size >= 17 {
        17
    } else {
        12
    };
    let copy_len = std::cmp::min(padding.len(), advertised_len);
    padding[..copy_len].copy_from_slice(&fixed[..copy_len]);

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
/// transaction ID. Padding shorter than the 20-byte STUN header copies the
/// longest available header prefix; 15-byte install-script padding still carries
/// the type, length, magic cookie, and partial transaction ID.
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

fn decimal_digits(mut value: usize) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// `core::fmt::Write` adapter that formats into a fixed stack buffer, so SIP
/// header lines can be built with `write!` without per-packet heap allocation.
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl core::fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let end = self.len.checked_add(bytes.len()).ok_or(core::fmt::Error)?;
        if end > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

/// SIP-style padding: a SIP *response* header block packed into the padding.
///
/// The padded packet is emitted by the proxy *toward the client*, so it is the
/// server side of the conversation — real SIP responses start with a
/// `SIP/2.0 <status>` line (RFC 3261 §7.2). Mirroring the client's request-side
/// padding, the response greedily packs the status line plus as many mandatory
/// headers as fit — `Via` (with a per-packet `branch`), `From`, `To`, `Call-ID`,
/// `CSeq` — in canonical order, so a DPI that inspects only the leading bytes of
/// the datagram sees a realistic SIP response header block rather than a bare
/// status line. The WireGuard payload (the message body) begins at byte
/// `pad_size`.
///
/// Because the proxy sees the whole datagram, it can append a `Content-Length`
/// that covers the *entire* body (the space-fill remainder of the padding plus
/// the untouched WG payload), so the datagram is a single framed SIP message
/// with no trailing/"extraneous" bytes — but only when the full mandatory header
/// set already fit, so headers are never displaced by `Content-Length`.
///
/// A complete header block cannot fit a small S value (a minimal realistic
/// response is ~150–200 B), so below that the message is intentionally
/// incomplete: whole-message parsers note missing headers, but the inspected
/// prefix stays SIP-shaped. Padding too small for even the status line falls back
/// to a status-line fragment with a CRLF suffix.
fn apply_sip_padding(data: &mut [u8], pad_size: usize) {
    use core::fmt::Write as _;

    let total_len = data.len();
    let (padding, payload) = data.split_at_mut(pad_size);
    if padding.is_empty() {
        return;
    }
    let len = padding.len();

    // Per-packet deterministic values derived from the payload (no global RNG,
    // no per-packet allocation).
    let mut st = fnv1a_seed(payload);
    macro_rules! next {
        () => {{
            let v = st;
            st = lcg_step(st);
            v
        }};
    }
    const STATUS: [&str; 3] = ["100 Trying", "180 Ringing", "200 OK"];
    const HOSTS: [&str; 3] = ["sip.example.com", "pbx.example.net", "voip.example.org"];
    const METHODS: [&str; 3] = ["INVITE", "OPTIONS", "REGISTER"];
    let status = STATUS[next!() as usize % STATUS.len()];
    let host = HOSTS[next!() as usize % HOSTS.len()];
    let method = METHODS[next!() as usize % METHODS.len()];
    let branch = next!();
    let from_tag = next!();
    let to_tag = next!();
    let call_id = next!();
    // Last value reads the state directly (no further `next!`), so the final draw
    // leaves no dead write to `st`.
    let cseq = 1 + (st % 100_000);

    let mut pos = 0usize;
    let mut scratch = [0u8; 128];
    // Append a CRLF-terminated header line if it — plus the 2-byte closing blank
    // line — still fits in the padding region. Returns whether it was written.
    macro_rules! put_line {
        ($($arg:tt)*) => {{
            let written = {
                let mut w = SliceWriter { buf: &mut scratch, len: 0 };
                if write!(w, $($arg)*).is_ok() { Some(w.len) } else { None }
            };
            match written {
                Some(n) if pos + n + 2 <= len => {
                    padding[pos..pos + n].copy_from_slice(&scratch[..n]);
                    pos += n;
                    true
                }
                _ => false,
            }
        }};
    }

    // The status line is mandatory. If even it does not fit, emit a status-line
    // fragment with a CRLF suffix so the bytes still look like the start of a SIP
    // response rather than a broken header block.
    if !put_line!("SIP/2.0 {status}\r\n") {
        const FRAG: &[u8] = b"SIP/2.0 100 Trying\r\n";
        let take = FRAG.len().min(len);
        padding[..take].copy_from_slice(&FRAG[..take]);
        for b in padding[take..].iter_mut() {
            *b = b' ';
        }
        if len >= 2 {
            padding[len - 2] = b'\r';
            padding[len - 1] = b'\n';
        }
        return;
    }

    // Mandatory response headers in canonical order; stop at the first that does
    // not fit so the emitted set stays a contiguous, in-order prefix. (A response
    // echoes Via/From/To/Call-ID/CSeq; Max-Forwards is request-only.)
    let all_mandatory =
        put_line!("Via: SIP/2.0/UDP {host}:5060;branch=z9hG4bK{branch:08x};rport\r\n")
            && put_line!("From: <sip:caller@{host}>;tag={from_tag:08x}\r\n")
            && put_line!("To: <sip:callee@{host}>;tag={to_tag:08x}\r\n")
            && put_line!("Call-ID: {call_id:08x}@{host}\r\n")
            && put_line!("CSeq: {cseq} {method}\r\n");

    // Only when every mandatory header fit, append a Content-Length covering the
    // entire body — the space-fill remainder of the padding plus the WG payload —
    // so the datagram frames as one SIP message with no extraneous bytes. The
    // body length equals total_len - header_end; solve for the digit count.
    if all_mandatory {
        for digits in 1..=decimal_digits(total_len) {
            let header_end = pos + b"Content-Length: ".len() + digits + b"\r\n\r\n".len();
            if header_end > len {
                break;
            }
            if decimal_digits(total_len - header_end) == digits {
                let _ = put_line!("Content-Length: {}\r\n", total_len - header_end);
                break;
            }
        }
    }

    // Closing blank line, then space-fill the rest of the padding region. The
    // message body is these spaces followed by the WG payload at byte `pad_size`.
    if pos + 2 <= len {
        padding[pos] = b'\r';
        padding[pos + 1] = b'\n';
        pos += 2;
    }
    for b in padding[pos..].iter_mut() {
        *b = b' ';
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

    // Validate that the SIP response padding looks like a SIP response to a DPI
    // inspecting the leading bytes: it starts with a `SIP/2.0` status line, every
    // header line up to the blank line contains ':', and the padding body (after
    // the header block) is space-filled.
    fn assert_sip_response_padding(padding: &[u8]) {
        assert!(
            padding.starts_with(b"SIP/2.0 "),
            "SIP response padding must start with a status line"
        );
        let text = std::str::from_utf8(padding).expect("SIP padding must be ASCII text");
        if let Some(header_end) = text.find("\r\n\r\n") {
            let block = &text[..header_end];
            let mut lines = block.split("\r\n");
            assert!(
                lines.next().unwrap().starts_with("SIP/2.0 "),
                "first line must be the status line"
            );
            for line in lines {
                assert!(
                    line.contains(':'),
                    "every SIP header line must contain ':' : [{line}]"
                );
            }
            assert!(
                padding[header_end + 4..].iter().all(|&b| b == b' '),
                "SIP padding body must be space-filled"
            );
        }
    }

    // -- QUIC padding tests --

    #[test]
    fn quic_padding_has_header_and_entropy() {
        // apply_padding with QUIC emits a 1-RTT short header (uniform 1-RTT).
        let mut data = vec![0xAA; 20];
        let pad_size = 10;
        apply_padding(&mut data, pad_size, Protocol::Quic);

        // form=0, fixed=1 => byte & 0xC0 == 0x40
        assert_eq!(data[0] & 0xC0, 0x40, "1-RTT: form=0, fixed=1");
        // reserved bits (0x18) cleared per RFC 9000 §17.3
        assert_eq!(data[0] & 0x18, 0x00, "1-RTT: reserved bits cleared");
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

    #[test]
    fn protocol_padding_generates_boundaries_15_64_150() {
        for proto in [Protocol::Quic, Protocol::Dns, Protocol::Stun, Protocol::Sip] {
            for pad_size in [15usize, 64, 150] {
                let mut data = vec![0x00; pad_size + 32];
                data[pad_size..].fill(0xCC);

                apply_padding(&mut data, pad_size, proto);

                assert!(
                    data[..pad_size].iter().any(|&b| b != 0x00),
                    "{proto:?} padding should write a protocol-shaped prefix at {pad_size} bytes"
                );
                assert!(
                    data[pad_size..].iter().all(|&b| b == 0xCC),
                    "{proto:?} padding must not touch payload at {pad_size} bytes"
                );

                match proto {
                    Protocol::Quic => {
                        assert_ne!(
                            data[0] & 0x40,
                            0,
                            "QUIC fixed bit should be set at {pad_size} bytes"
                        );
                    }
                    Protocol::Dns => {
                        assert_eq!(data[2], 0x81, "DNS QR+RD flags at {pad_size} bytes");
                        assert_eq!(data[3], 0x80, "DNS RA flag at {pad_size} bytes");
                    }
                    Protocol::Stun => {
                        assert_eq!(&data[0..2], &0x0011u16.to_be_bytes());
                        if pad_size >= 8 {
                            assert_eq!(&data[4..8], &0x2112_A442u32.to_be_bytes());
                        }
                    }
                    Protocol::Sip => {
                        assert!(data[..pad_size].starts_with(b"SIP/2.0"));
                        if pad_size >= 16 {
                            assert!(data[..pad_size].windows(4).any(|w| w == b"\r\n\r\n"));
                        } else {
                            assert_eq!(&data[pad_size - 2..pad_size], b"\r\n");
                        }
                    }
                }
            }
        }
    }

    // -- DNS padding tests --

    #[test]
    fn dns_padding_has_response_header() {
        // pad_size=40 (>= DNS_OPT_MIN=32): full EDNS OPT framing with a root
        // question. data.len()=46. OPT starts at byte 17 (12 header + 5 question).
        // RDLENGTH covers everything after it: 46 - (17 + 11) = 18.
        // OPTION-LENGTH covers the option-data: 46 - (17 + 15) = 14.
        let mut data = vec![0x00; 46];
        data[40..46].copy_from_slice(&[0xBB, 0xCC, 0x01, 0x02, 0x03, 0x04]);
        let pad_size = 40;
        apply_padding(&mut data, pad_size, Protocol::Dns);

        // Header: TXID from payload bytes 0-1.
        assert_eq!(data[0], 0xBB, "tx_hi from payload[0]");
        assert_eq!(data[1], 0xCC, "tx_lo from payload[1]");
        // Flags 0x8180: QR=1, RD=1 (echoed), RA=1, NOERROR.
        assert_eq!(data[2], 0x81, "QR=1, RD=1");
        assert_eq!(data[3], 0x80, "RA=1, RCODE=NOERROR");
        // QDCOUNT=1, ANCOUNT=0 (NODATA), NSCOUNT=0, ARCOUNT=1 (OPT).
        assert_eq!(&data[4..6], &[0x00, 0x01], "QDCOUNT=1");
        assert_eq!(&data[6..8], &[0x00, 0x00], "ANCOUNT=0");
        assert_eq!(&data[8..10], &[0x00, 0x00], "NSCOUNT=0");
        assert_eq!(&data[10..12], &[0x00, 0x01], "ARCOUNT=1");
        // Question: root QNAME + QTYPE A + QCLASS IN.
        assert_eq!(data[12], 0x00, "QNAME root label");
        assert_eq!(&data[13..15], &[0x00, 0x01], "QTYPE A");
        assert_eq!(&data[15..17], &[0x00, 0x01], "QCLASS IN");
        // OPT RR: root NAME + TYPE OPT(41) + CLASS udp-size(1232) + TTL 0.
        assert_eq!(data[17], 0x00, "OPT NAME root label");
        assert_eq!(&data[18..20], &[0x00, 0x29], "TYPE OPT(41)");
        assert_eq!(&data[20..22], &1232u16.to_be_bytes(), "CLASS = UDP size 1232");
        assert_eq!(&data[22..26], &[0x00, 0x00, 0x00, 0x00], "TTL field 0");
        // RDLENGTH = 46 - 28 = 18 (option header 4 + option-data 14).
        assert_eq!(&data[26..28], &[0x00, 18], "RDLENGTH");
        // Option: CODE 0xFDE9 (unknown) + LENGTH 14.
        assert_eq!(&data[28..30], &0xFDE9u16.to_be_bytes(), "OPTION-CODE");
        assert_eq!(&data[30..32], &[0x00, 14], "OPTION-LENGTH");
        // Option-data prefix in padding (bytes 32..40) is zero-filled.
        assert!(data[32..40].iter().all(|&b| b == 0x00), "option-data zero-fill");
        // Payload untouched (it is the tail of the OPT option-data).
        assert_eq!(&data[40..46], &[0xBB, 0xCC, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn dns_padding_opt_covers_entire_datagram() {
        // Every byte from the OPT RDATA start must be accounted for: RDLENGTH
        // must reach exactly the end of the datagram, leaving no trailing bytes
        // for a dissector to flag as extraneous.
        for total in [DNS_OPT_MIN + 1, 64, 200, 1472] {
            let pad_size = DNS_OPT_MIN; // root question
            let mut data = vec![0x07u8; total];
            apply_padding(&mut data, pad_size, Protocol::Dns);
            // OPT at byte 17 (12 + 5). RDATA begins after RDLENGTH (byte 28).
            let rdlength = u16::from_be_bytes([data[26], data[27]]) as usize;
            assert_eq!(28 + rdlength, total, "RDLENGTH must cover to end (total={total})");
            let opt_len = u16::from_be_bytes([data[30], data[31]]) as usize;
            assert_eq!(32 + opt_len, total, "OPTION-LENGTH must cover to end (total={total})");
            // Payload after pad_size is untouched.
            assert!(data[pad_size..].iter().all(|&b| b == 0x07), "payload untouched");
        }
    }

    #[test]
    fn dns_padding_echoes_query_question_and_txid() {
        // Echo www.profi.ru / type A with TXID 0x1234. The question section in
        // the response must be byte-identical to the query's, and the TXID must
        // match (not be payload-derived).
        let echo = DnsEcho {
            txid: [0x12, 0x34],
            qname: b"\x03www\x05profi\x02ru\x00".to_vec(),
            qtype: [0x00, 0x01],
        };
        let qn = echo.qname.len(); // 15
        // total comfortably fits header(12) + question(qn+4) + OPT(15) + payload.
        let pad_size = 12 + qn + 4 + 15 + 8;
        let total = pad_size + 40;
        let mut data = vec![0x5Au8; total];
        apply_dns_padding(&mut data, pad_size, Some(&echo));

        // TXID echoed (not derived from the 0x5A payload).
        assert_eq!(&data[0..2], &[0x12, 0x34], "TXID echoed from query");
        assert_eq!(data[2], 0x81, "QR=1, RD=1");
        assert_eq!(&data[10..12], &[0x00, 0x01], "ARCOUNT=1 (OPT)");
        // Question section is byte-identical to the query's QNAME + QTYPE + QCLASS.
        let q_end = 12 + qn + 4;
        assert_eq!(&data[12..12 + qn], echo.qname.as_slice(), "QNAME echoed");
        assert_eq!(&data[12 + qn..12 + qn + 2], &echo.qtype, "QTYPE echoed");
        assert_eq!(&data[12 + qn + 2..q_end], &[0x00, 0x01], "QCLASS IN");
        // OPT RR immediately follows the question.
        assert_eq!(&data[q_end + 1..q_end + 3], &[0x00, 0x29], "TYPE OPT(41)");
        // Payload untouched.
        assert!(data[pad_size..].iter().all(|&b| b == 0x5A), "payload untouched");
    }

    #[test]
    fn dns_padding_falls_back_to_root_when_qname_too_large_for_pad() {
        // Echo present but pad_size too small for the echoed QNAME: fall back to
        // the root-label question with a payload-derived TXID.
        let echo = DnsEcho {
            txid: [0x12, 0x34],
            qname: b"\x03www\x05profi\x02ru\x00".to_vec(),
            qtype: [0x00, 0x01],
        };
        let pad_size = DNS_OPT_MIN; // 32: only fits a root-label question
        let total = pad_size + 20;
        let mut data = vec![0u8; total];
        data[pad_size] = 0xDE; // payload[0] -> tx_hi
        data[pad_size + 1] = 0xAD; // payload[1] -> tx_lo
        apply_dns_padding(&mut data, pad_size, Some(&echo));

        assert_eq!(&data[0..2], &[0xDE, 0xAD], "payload-derived TXID on fallback");
        assert_eq!(data[12], 0x00, "root-label QNAME");
        assert_eq!(&data[13..15], &[0x00, 0x01], "QTYPE A");
        assert_eq!(&data[18..20], &[0x00, 0x29], "TYPE OPT(41)");
    }

    #[test]
    fn dns_padding_null_fallback_below_opt_min() {
        // pad_size in [28, 32) is too small for OPT framing: the legacy NULL
        // record still covers the whole datagram (RDLENGTH = total - 28).
        let pad_size = 30;
        let mut data = vec![0x00; 40];
        data[30..40].copy_from_slice(&[0xAB; 10]);
        apply_padding(&mut data, pad_size, Protocol::Dns);

        assert_eq!(data[2], 0x81, "QR=1, RD=1 (echoed even in fallback)");
        assert_eq!(data[3], 0x80, "RA=1");
        assert_eq!(&data[6..8], &[0x00, 0x01], "ANCOUNT=1 (NULL answer)");
        assert_eq!(&data[18..20], &[0x00, 0x0a], "answer TYPE NULL(10)");
        let rdlength = u16::from_be_bytes([data[26], data[27]]) as usize;
        assert_eq!(28 + rdlength, 40, "NULL RDLENGTH covers to end");
        assert!(data[30..40].iter().all(|&b| b == 0xAB), "payload untouched");
    }

    #[test]
    fn dns_padding_short_fills_partial_header() {
        // Only 5 bytes of padding prefix — partial DNS header (header is 12 bytes).
        // data.len()=10 so total_len < 28; RDLENGTH saturates to 0.
        let mut data = vec![0x00; 10];
        data[5..10].copy_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC, 0xCC]);
        let pad_size = 5;
        apply_padding(&mut data, pad_size, Protocol::Dns);

        assert_eq!(data[0], 0xCC, "tx_hi from payload[0]");
        assert_eq!(data[1], 0xCC, "tx_lo from payload[1]");
        assert_eq!(data[2], 0x81, "flags high: QR=1, RD=1");
        assert_eq!(data[3], 0x80, "flags low: RA=1");
        assert_eq!(data[4], 0x00, "QDCOUNT high byte (partial — only 5 bytes fit)");
        // Payload untouched
        assert!(data[5..10].iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn dns_padding_question_only_no_answer() {
        // pad_size=20: fits header (12 B) + question (5 B) = 17 B, but not the
        // full answer prefix (28 B). Expect QDCOUNT=1, ANCOUNT=0, bytes 17..20
        // zero-filled (no partial answer bytes), payload untouched.
        let mut data = vec![0x00; 26]; // pad_size=20, payload=6 bytes
        data[20..26].copy_from_slice(&[0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04]);
        let pad_size = 20;
        apply_padding(&mut data, pad_size, Protocol::Dns);

        // TXID from payload
        assert_eq!(data[0], 0xAA, "tx_hi");
        assert_eq!(data[1], 0xBB, "tx_lo");
        // Flags
        assert_eq!(data[2], 0x81, "QR=1, RD=1");
        assert_eq!(data[3], 0x80, "RA=1");
        // QDCOUNT=1 (question fits), ANCOUNT=0 (answer prefix does not fit)
        assert_eq!(&data[4..6], &[0x00, 0x01], "QDCOUNT=1");
        assert_eq!(&data[6..8], &[0x00, 0x00], "ANCOUNT=0");
        // Question section present
        assert_eq!(data[12], 0x00, "QNAME root label");
        assert_eq!(&data[13..15], &[0x00, 0x01], "QTYPE A");
        assert_eq!(&data[15..17], &[0x00, 0x01], "QCLASS IN");
        // Bytes 17..20: zero-filled (no partial answer bytes written)
        assert!(data[17..20].iter().all(|&b| b == 0x00), "no partial answer bytes");
        // Payload untouched
        assert_eq!(&data[20..26], &[0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04]);
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
        assert_sip_response_padding(padding);
        assert!(!padding.windows(4).any(|w| w == b"\r\nVi"));
        // Payload untouched
        assert!(data[50..60].iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn sip_padding_variant_depends_on_payload() {
        // Same size, different payloads -> the per-packet status/host/branch/tags
        // differ, so the emitted SIP response padding differs.
        let mut a = vec![0x00; 140];
        let mut b = vec![0x00; 140];
        a[120..140].fill(0x11);
        b[120..140].fill(0x22);
        apply_padding(&mut a, 120, Protocol::Sip);
        apply_padding(&mut b, 120, Protocol::Sip);

        assert_sip_response_padding(&a[..120]);
        assert_sip_response_padding(&b[..120]);
        assert_ne!(
            &a[..120],
            &b[..120],
            "same-size SIP padding should vary across different payloads"
        );
    }

    #[test]
    fn sip_padding_full_header_block_when_it_fits() {
        // 280 B padding fits the whole mandatory header set plus Content-Length.
        let mut data = vec![0x00; 300];
        data[280..300].fill(0xCC);
        apply_padding(&mut data, 280, Protocol::Sip);

        let padding = &data[..280];
        let text = std::str::from_utf8(padding).unwrap();
        assert_sip_response_padding(padding);
        assert!(text.starts_with("SIP/2.0 "));
        for header in [
            "\r\nVia: SIP/2.0/UDP ",
            "\r\nFrom: <sip:",
            "\r\nTo: <sip:",
            "\r\nCall-ID: ",
            "\r\nCSeq: ",
            "\r\nContent-Length: ",
        ] {
            assert!(text.contains(header), "missing header: {header}");
        }
        // The branch parameter carries a per-packet token (not the empty cookie).
        assert!(text.contains(";branch=z9hG4bK") && !text.contains(";branch=z9hG4bK\r\n"));

        // Content-Length covers the full body: the space-fill remainder of the
        // padding plus the untouched WG payload.
        let header_end = text.find("\r\n\r\n").unwrap() + 4;
        let content_length: usize = text
            .split("\r\n")
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            content_length,
            data.len() - header_end,
            "Content-Length must cover the padding body and the WG payload"
        );
        assert!(data[280..300].iter().all(|&b| b == 0xCC));
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

    #[test]
    fn sip_padding_four_bytes() {
        let mut data = [0x00, 0x00, 0x00, 0x00, 0xAA]; // 4 bytes padding + payload
        apply_padding(&mut data, 4, Protocol::Sip);
        assert_eq!(&data[..4], b"SI\r\n");
        assert_eq!(data[4], 0xAA); // payload untouched
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
        // First padding byte is a QUIC 1-RTT short header (form=0, fixed=1).
        assert_eq!(result[0] & 0xC0, 0x40);
        // Reserved bits (0x18) cleared per RFC 9000 §17.3.
        assert_eq!(result[0] & 0x18, 0x00);
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
        // Too short for a complete SIP header block; keep a recognizable prefix
        // and the legacy CRLF suffix.
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
                                     // Flags: QR=1, RD=1 (echoed to match the client's RD=1 queries)
        assert_eq!(result[2] & 0x80, 0x80, "QR=1");
        assert_eq!(
            result[2] & 0x01,
            0x01,
            "RD echoed so the response matches the client's recursive query"
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

    fn awg_params_with_s(s: u32) -> AwgParams {
        AwgParams {
            s1: s,
            s2: s,
            s3: s,
            s4: s,
            ..test_awg_params()
        }
    }

    fn build_awg_packet(pkt_type: AwgPacketType, params: &AwgParams) -> (Vec<u8>, usize, u32) {
        let (pad_size, header, body_len) = match pkt_type {
            AwgPacketType::HandshakeInit => (params.s1 as usize, 150u32, 148 - 4),
            AwgPacketType::HandshakeResponse => (params.s2 as usize, 350u32, 92 - 4),
            AwgPacketType::CookieReply => (params.s3 as usize, 550u32, 64 - 4),
            AwgPacketType::TransportData => (params.s4 as usize, 750u32, 32 - 4),
        };

        let mut pkt = vec![0xFF; pad_size];
        pkt.extend_from_slice(&header.to_le_bytes());
        pkt.extend(std::iter::repeat(0xAB).take(body_len));
        (pkt, pad_size, header)
    }

    fn assert_protocol_prefix(proto: Protocol, pkt_type: AwgPacketType, data: &[u8], pad_size: usize) {
        match proto {
            Protocol::Quic => {
                // All AWG phases use a 1-RTT short header (form=0, fixed=1).
                let _ = pkt_type;
                assert_eq!(data[0] & 0xC0, 0x40, "QUIC must use 1-RTT short header");
                assert_eq!(data[0] & 0x18, 0x00, "QUIC short reserved bits cleared");
            }
            Protocol::Dns => {
                assert_eq!(data[2], 0x81, "DNS QR+RD flags");
                assert_eq!(data[3], 0x80, "DNS RA flag");
            }
            Protocol::Stun => {
                assert_eq!(&data[0..2], &0x0011u16.to_be_bytes());
                assert_eq!(&data[4..8], &0x2112_A442u32.to_be_bytes());
            }
            Protocol::Sip => {
                assert!(data[..pad_size].starts_with(b"SIP/2.0"));
                if pad_size >= 16 {
                    assert!(data[..pad_size].windows(4).any(|w| w == b"\r\n\r\n"));
                } else {
                    assert_eq!(&data[pad_size - 2..pad_size], b"\r\n");
                }
            }
        }
    }

    #[test]
    fn awg_transform_supports_s1_s2_s3_s4_boundaries_for_all_protocols() {
        for s in [15u32, 64, 150] {
            let params = awg_params_with_s(s);
            for pkt_type in [
                AwgPacketType::HandshakeInit,
                AwgPacketType::HandshakeResponse,
                AwgPacketType::CookieReply,
                AwgPacketType::TransportData,
            ] {
                for proto in [Protocol::Quic, Protocol::Dns, Protocol::Stun, Protocol::Sip] {
                    let (mut pkt, pad_size, header) = build_awg_packet(pkt_type, &params);

                    assert_eq!(classify_awg_packet(&pkt, &params), Some(pkt_type));
                    assert!(apply_awg_transform(&mut pkt, &params, proto, None));

                    assert_protocol_prefix(proto, pkt_type, &pkt, pad_size);
                    assert_eq!(
                        &pkt[pad_size..pad_size + 4],
                        &header.to_le_bytes(),
                        "AWG header must stay untouched for {pkt_type:?} {proto:?} S={s}"
                    );
                    assert!(
                        pkt[pad_size + 4..].iter().all(|&b| b == 0xAB),
                        "AWG payload must stay untouched for {pkt_type:?} {proto:?} S={s}"
                    );
                }
            }
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

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic, None);
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

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Sip, None);
        assert!(result);

        // Prefix padding should contain a complete minimal SIP response.
        assert_sip_response_padding(&pkt[..20]);
        // Header + body should be untouched
        assert_eq!(&pkt[20..24], &750u32.to_le_bytes());
        assert!(pkt[24..124].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn awg_transform_handshake_response_dns() {
        // Use S2=40 (>= DNS_OPT_MIN=32) so the full EDNS OPT framing fits without
        // overlapping the AWG header that starts at offset 40.
        let params = AwgParams { s2: 40, ..test_awg_params() };
        let padding_original = [0xFF; 40]; // S2 = 40
        let header = 350u32.to_le_bytes();
        let body = [0xDD; 92 - 4];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&padding_original);
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&body);
        assert_eq!(pkt.len(), 40 + 92); // total_len = 132

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Dns, None);
        assert!(result);

        // DNS header: QR=1, RD=1, RA=1, NODATA + OPT.
        assert_eq!(pkt[2], 0x81, "DNS QR=1, RD=1");
        assert_eq!(pkt[3], 0x80, "DNS RA=1");
        assert_eq!(&pkt[4..6], &[0x00, 0x01], "DNS QDCOUNT=1");
        assert_eq!(&pkt[6..8], &[0x00, 0x00], "DNS ANCOUNT=0");
        assert_eq!(&pkt[10..12], &[0x00, 0x01], "DNS ARCOUNT=1 (OPT)");
        // OPT RR at byte 17. RDLENGTH = 132 - 28 = 104; OPTION-LENGTH = 132 - 32 = 100.
        assert_eq!(&pkt[18..20], &[0x00, 0x29], "DNS TYPE=OPT(41)");
        assert_eq!(&pkt[26..28], &104u16.to_be_bytes(), "OPT RDLENGTH=104");
        assert_eq!(&pkt[28..30], &0xFDE9u16.to_be_bytes(), "OPTION-CODE");
        assert_eq!(&pkt[30..32], &100u16.to_be_bytes(), "OPTION-LENGTH=100");
        // AWG header and body start at offset 40, untouched.
        assert_eq!(&pkt[40..44], &350u32.to_le_bytes());
        assert!(pkt[44..40 + 92].iter().all(|&b| b == 0xDD));
    }

    #[test]
    fn awg_transform_handshake_response_quic_uses_short_header() {
        let params = test_awg_params();
        // S2 = 8 bytes padding + H2-range header (350) + 92-byte WG Handshake Response
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xFF; 8]);
        pkt.extend_from_slice(&350u32.to_le_bytes());
        pkt.extend_from_slice(&[0xDD; 88]);
        assert_eq!(pkt.len(), 8 + 92);

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic, None);
        assert!(result);

        // S2/S3 now use a 1-RTT short header (form=0, fixed=1) like S1/S4 — a long
        // Handshake header has a Length field that cannot frame the WG payload and
        // would parse as malformed.
        assert_eq!(pkt[0] & 0xC0, 0x40, "HandshakeResponse must use QUIC 1-RTT short header");
        assert_eq!(pkt[0] & 0x18, 0x00, "1-RTT reserved bits cleared");
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

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic, None);
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

        let result = apply_awg_transform(&mut pkt, &params, Protocol::Stun, None);
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
        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic, None);
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
        let result = apply_awg_transform(&mut pkt, &params, Protocol::Quic, None);
        assert!(!result); // can't classify (too short for S1 offset)
    }
}
