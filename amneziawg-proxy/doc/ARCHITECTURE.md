# amneziawg-proxy — Architecture & Packet Flows

## Overview

`amneziawg-proxy` is an async UDP proxy that sits in front of an AmneziaWG
server and makes the traffic look like a legitimate application protocol
(QUIC, DNS, STUN, or SIP) to defeat Deep Packet Inspection (DPI).

It performs two complementary functions:

1. **Probe response** — when a DPI system sends a protocol probe (e.g. a QUIC
   Initial or a DNS query), the proxy generates a valid protocol response so
   the port appears to host the imitated service.
2. **Padding transformation** — outgoing AmneziaWG packets have their S1–S4
   padding prefix (the random bytes prepended before the obfuscated header)
   overwritten with protocol-conformant filler bytes, so the statistical byte
   distribution matches the imitated protocol.

```
                                  ┌──────────────────────────────┐
                                  │       amneziawg-proxy        │
                                  │                              │
    Internet                      │  ┌────────────┐              │
   ───────────────────────────────┤  │  frontend   │◄── listen   │
   clients / DPI probes           │  │  UdpSocket  │    :51820   │
                                  │  └─────┬──────┘              │
                                  │        │                     │
                                  │  ┌─────▼──────┐              │
                                  │  │ Proxy::run  │              │
                                  │  │  main loop  │              │
                                  │  └──┬──────┬──┘              │
                                  │     │      │                 │
                           probe? │     │      │ forward         │
                                  │  ┌──▼──┐ ┌─▼──────────────┐  │
                                  │  │resp-│ │  SessionTable   │  │
                                  │  │onder│ │  (per-client    │  │
                                  │  └──┬──┘ │   backend sock) │  │
                                  │     │    └──────┬──────────┘  │
                                  │     │           │             │
                                  │     │    ┌──────▼──────────┐  │
                                  │     │    │   relay tasks    │  │
                                  │     │    │  (per-session    │  │
                                  │     │    │   async recv,    │  │
                                  │     │    │   apply padding  │  │
                                  │     │    │   transform)     │  │
                                  │     │    └──────┬──────────┘  │
                                  │     │           │             │
                                  └─────┼───────────┼─────────────┘
                                        │           │
                                        │   ┌───────▼───────┐
                                        │   │  AmneziaWG    │
                                        │   │  backend      │
                                        │   │  :51821       │
                                        │   └───────────────┘
                                        │
                    probe response ◄────┘
                    sent back to client
```

---

## Deployment Topology

```
                            ┌───────────────────────────────┐
  VPN client ──── UDP ────► │  0.0.0.0:51820  awg-proxy     │
                            │          │                    │
                            │          ▼                    │
                            │  127.0.0.1:51821  awg0 (AWG)  │
                            └───────────────────────────────┘
```

The installer configures AmneziaWG to listen on `127.0.0.1:51821` (loopback
only) and the proxy binds the public-facing port `:51820`. All client traffic
passes through the proxy, which adds the imitation layer.

---

## Module Map

| Module             | Responsibility |
|--------------------|----------------|
| `main.rs`          | CLI entry point: loads TOML config, optionally loads AWG config, sets up logging and signal handling, runs the proxy. |
| `config.rs`        | Parses `proxy.toml` (TOML) and AWG INI-style config files. Validates addresses, protocol names, H-range non-overlap, Jmin≤Jmax. |
| `proxy.rs`         | Core runtime: binds frontend socket, runs the main `recv_from` loop, spawns per-session relay tasks and cleanup task, orchestrates all other modules. |
| `responder.rs`     | Probe detection (`detect_protocol`) and response generation (`generate_response`). Also contains AWG packet classification (`classify_awg_packet`). |
| `transform.rs`     | Padding transformation: overwrites the S1–S4 padding prefix with protocol-conformant filler (QUIC PRNG, DNS header, STUN header, SIP text). |
| `session.rs`       | Per-client session table backed by `DashMap`. Each session owns a dedicated ephemeral UDP socket connected to the backend. TTL-based expiry. |
| `backend.rs`       | Low-level backend I/O: `forward_to_backend`, `recv_from_backend`, `send_to_client`, `try_recv_from_backend` (with timeout). |
| `metrics.rs`       | Per-client counters (packets in/out, probes) and token-bucket rate limiter for probe responses. |
| `errors.rs`        | `ProxyError` enum with `thiserror` derives: Config, Io, SessionNotFound, RateLimited, BackendUnreachable, Shutdown. |
| `quic_handshake.rs`| Stateful QUIC handshake responder backed by `quinn-proto`. Handles TLS ClientHello and generates server Initial/Handshake flight packets. |

---

## Packet Flow: Normal Traffic

A normal (non-probe) packet from an AmneziaWG client:

```
Client                      Proxy                           Backend (AWG)
  │                           │                                │
  │── UDP packet ────────────►│                                │
  │                           │  1. metrics.record_in()        │
  │                           │  2. detect_protocol() → None   │
  │                           │  3. get_or_create session      │
  │                           │  4. forward_to_backend() ─────►│
  │                           │                                │
  │                           │◄── backend response ───────────│
  │                           │  5. classify packet (H1-H4)    │
  │                           │  6. apply_awg_transform()      │
  │                           │     (overwrite S-padding)      │
  │                           │  7. metrics.record_out()       │
  │◄── transformed packet ────│                                │
  │                           │                                │
```

**Step 5–6 detail (padding transform):**

The per-session relay task classifies the backend response by trying each
(S-offset, H-range) pair: it reads the 4 bytes at offset S as a
little-endian `u32` and checks whether the value falls into the
corresponding H range. This determines the AWG packet type (Handshake Init /
Response / Cookie Reply / Transport Data). The S-value tells it how many
leading bytes are the padding prefix. Those bytes are then overwritten with
protocol-conformant filler (see "Padding Strategies" below).

---

## Packet Flow: Probe Detection & Response

When DPI or a network scanner sends a protocol-specific probe:

```
DPI Probe                   Proxy                           Backend (AWG)
  │                           │                                │
  │── QUIC Initial ──────────►│                                │
  │                           │  1. metrics.record_in()        │
  │                           │  2. detect_protocol()          │
  │                           │     → Some(Protocol::Quic)     │
  │                           │  3. try_acquire_probe()        │
  │                           │     → true (rate limiter OK)   │
  │                           │  4. generate_response(Quic)    │
  │◄── Version Negotiation ───│                                │
  │                           │  5. Also forwards to backend   │
  │                           │     (AWG will drop it as       │
  │                           │      invalid handshake)        │
  │                           │                                │
```

Both the probe response **and** the forwarding happen — this is intentional.
The backend (real AWG server) simply drops the packet since it's not a valid
AWG handshake. The client/DPI probe gets a realistic protocol response.

If `try_acquire_probe()` returns `false` (rate limit exceeded), the probe
response is silently skipped, but the packet is still forwarded to the
backend.

---

## Protocol Imitation Details

### QUIC Imitation

**Probe detection** (`detect_protocol`):
```
1. Packet length ≥ 7
2. First byte: (byte & 0xC0) == 0xC0
3. DCID length (byte 5) ≤ 20
4. Packet long enough to contain SCID length byte
5. SCID length ≤ 20
```
This matches QUIC long-header packets (RFC 9000 §17.2), including Initial,
0-RTT, Handshake, and Retry packets. The two high bits being `11` indicate
the long header form bit (0x80) and the fixed bit (0x40). The additional
connection ID length checks (≤ 20, per RFC 9000 §17.2) reduce false positives
from AWG packets whose random H-range headers happen to have those bits set.

**Probe response** (`generate_quic_version_negotiation`):
A valid QUIC Version Negotiation packet (RFC 9000 §17.2.1):
```
Byte  Field
────  ─────
 0    0xC3                    Long header form + fixed bit (incoming type bits preserved)
 1-4  0x00000000              Version = 0 (version negotiation)
 5    SCID_len                Response DCID = incoming SCID (swapped)
 6+   incoming_SCID bytes     (the swap makes it RFC-compliant)
 ...  DCID_len                Response SCID = incoming DCID
 ...  incoming_DCID bytes
 ...  0x00000001              Supported Version: QUIC v1
```
The DCID/SCID swap is per RFC 9000 §17.2.1: "the server includes the value
from the Source Connection ID field of the packet it receives in the
Destination Connection ID field."

**Padding fill** (`apply_quic_padding`):
- First byte: QUIC short-header byte with fixed bit set, header form = 0,
  reserved bits (0x18) cleared and spin/key-phase/PN-length bits derived
  from the PRNG
- Remaining bytes: pseudo-random from an FNV-1a-seeded LCG PRNG
- Seed is derived from the first 64 bytes of the WG payload (which follows
  the padding prefix), so each packet produces different padding
- Result: high-entropy byte distribution matching encrypted QUIC 1-RTT data

```
AWG packet (backend → client):
┌────────────────────────┬──────────┬──────────────────────┐
│   S padding (random)   │ H header │   WG payload         │
│   (S1-S4 bytes)        │ (4 bytes)│   (variable)         │
└────────────────────────┴──────────┴──────────────────────┘
 ▲
 │ overwritten with:
 ▼
┌────────────────────────┐
│ 0x4X │ PRNG bytes ...  │
│ short│ (high entropy)  │
│ hdr  │                 │
└────────────────────────┘
```

### DNS Imitation

**Probe detection** (`detect_protocol` → `is_plausible_dns_query`):
```
data.len() >= 12
  AND (flags & 0xF800) == 0x0000   (QR=0, standard opcode)
  AND QDCOUNT == 1
  AND QNAME walk valid             (uncompressed labels, terminated in-bounds)
  AND QTYPE + QCLASS present
  AND QCLASS in {IN, CH, HS, ANY}
```
Flags are bytes 2-3 (big-endian), QDCOUNT is bytes 4-5 (big-endian), per
RFC 1035 §4.1.1. The mask `0xF800` checks QR bit (must be 0 = query) and
opcode (must be 0 = standard query). Bytes after the question section are
allowed (EDNS OPT records).

The question section is validated end-to-end because the header flags alone
are far too weak a signal: AmneziaWG junk packets are uniformly random and
~3% of them pass the flags/QDCOUNT check, so in `auto` mode a non-masking
client would sooner or later be mislabeled (and answered) as DNS. A random
packet essentially never survives the QNAME label walk *and* lands one of
the four accepted QCLASS values.

**Probe response** (`generate_dns_servfail`):
A valid DNS SERVFAIL response (RFC 1035 §4.1):
```
Byte  Field
────  ─────
 0-1  Transaction ID      Echoed from incoming query
 2-3  Flags               QR=1, RA=1, RCODE=2 (SERVFAIL); RD copied from query
 4-5  QDCOUNT             1 when question echoed, 0 otherwise
 6-7  0x0000              ANCOUNT = 0
 8-9  0x0000              NSCOUNT = 0
10-11 0x0000              ARCOUNT = 0
12+   Question section    Echoed when fully parsed (optional)
```
The RD (Recursion Desired) bit is copied from the incoming query per
RFC 1035 §4.1.1. The question section is parsed by walking the QNAME labels
(each prefixed with a length byte, terminated by a zero root label; individual
labels ≤ 63, total QNAME ≤ 255 including root) then appending 4 bytes for
QTYPE and QCLASS. If the question section cannot be fully parsed (truncated
query, compression pointers, or RFC 1035 label/name length violations), the
response is returned header-only with QDCOUNT = 0. The total echoed response
is capped at 512 bytes per RFC 1035 §2.3.4.

**Padding fill** (`apply_dns_padding`):

The fill rewrites the S-padding prefix as a complete DNS **response** whose
EDNS0 OPT record frames the *entire datagram* — the WireGuard payload that
follows the prefix becomes the OPT option-data, so a DNS dissector consumes the
whole packet with no trailing "extraneous data" (the fingerprint a naïve
header-only fill would leave). Layout, when the prefix is at least
`DNS_OPT_MIN` (32 bytes):

- Bytes 0-1: Transaction ID. Echoed from the client's most recent DNS query
  when its question fits the prefix, otherwise derived from the first two
  payload bytes. Only the transaction ID and the question bytes (below) are
  reused from the query — the response flags are fixed, not mirrored.
- Bytes 2-3: `0x81 0x80` (QR=1, RD=1, RA=1, RCODE=NOERROR) — fixed regardless
  of the echoed query.
- Bytes 4-11: Section counts — QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, **ARCOUNT=1**
  (the OPT pseudo-RR).
- Question section: the echoed query's QNAME/QTYPE (+ QCLASS=IN) when it fits,
  else a root-label `A`/`IN` question.
- OPT RR: root NAME, TYPE=OPT(41), CLASS = UDP payload size (1232), TTL=0
  (EDNS version 0, DO=0), RDLENGTH covering the option header + option-data,
  OPTION-CODE = `0xFDE9` (an unknown / local-use code, so the opaque WG bytes
  aren't held to a known option's format), OPTION-LENGTH spanning the
  zero-filled tail of the prefix **plus the untouched WG payload**.

When the prefix is smaller than `DNS_OPT_MIN` (too small for OPT framing), the
fill falls back to a legacy `TYPE NULL` RR (`apply_dns_padding_null`): a NULL
RR (RFC 1035 §3.3.10) carries opaque RDATA of any length, so for prefixes ≥ 28
bytes it still covers the whole datagram; smaller pads degrade to
header(+question) only.

```
AWG packet (backend → client):
┌──────────────────────────┬──────────┬──────────────────────┐
│   S padding (random)     │ H header │   WG payload         │
│   (S1-S4 bytes)          │ (4 bytes)│   (variable)         │
└──────────────────────────┴──────────┴──────────────────────┘
 ▲                                     ▲
 │ overwritten with DNS response       │ becomes OPT option-data
 ▼ header + question + OPT header       (untouched, covered by OPTION-LENGTH)
┌────────────────────────────────────┐┌──────────────────────┐
│ ID │ 81 80 │ QD=1 AN=0 NS=0 AR=1   ││  WG payload          │
│ question (echoed or root-label)    ││  (opaque option-data)│
│ OPT RR: 00 29 04d0 … FDE9 OPT_LEN ─┼┼─► spans payload      │
└────────────────────────────────────┘└──────────────────────┘
```

### STUN Imitation

**Probe detection** (`detect_protocol`):
```
data.len() >= 20
  AND (message_type & 0xC000) == 0
  AND message_type == 0x0001       (Binding Request)
  AND message_length % 4 == 0
  AND data.len() == 20 + message_length
  AND magic_cookie == 0x2112A442
```
The STUN magic cookie is bytes 4-7, and the 96-bit transaction ID is bytes
8-19. STUN detection runs before DNS detection because a Binding Request with
zero attributes can otherwise look like a DNS query to the simpler DNS
heuristic.

**Probe response** (`generate_stun_binding_success`):
A valid STUN Binding Success response (RFC 5389/RFC 8489):
```
Byte  Field
----  -----
 0-1  0x0101                  Binding Success Response
 2-3  Attribute length        12 for IPv4, 24 for IPv6
 4-7  0x2112A442              Magic cookie
 8-19 Transaction ID          Echoed from incoming request
20+   XOR-MAPPED-ADDRESS      Encoded from the observed client address
```
For IPv4 clients the attribute value contains the reserved byte, family
`0x01`, the client port XORed with the high 16 bits of the magic cookie, and
the IPv4 address XORed with the magic cookie. IPv6 uses the magic cookie plus
transaction ID as the 128-bit XOR key.

**Padding fill** (`apply_stun_padding`):

The fill rewrites the S-padding prefix as a **Binding Success Response** — the
natural reply to the client's Binding Request cover traffic — carrying
well-formed attributes rather than a bare header:

- Bytes 0-1: `0x0101` (Binding Success Response).
- Bytes 2-3: Advertised message length = **exactly the attribute bytes written**
  (not the whole prefix), so a strict parser stops on the attribute boundary.
- Bytes 4-7: `0x2112A442` magic cookie.
- Bytes 8-19: 96-bit transaction ID derived from the WG payload (FNV-1a seed +
  LCG), consumed before any attribute randomness so it is **stable across pad
  sizes** for a given payload.
- Bytes 20+ (when the prefix has room): an `XOR-MAPPED-ADDRESS` (0x0020, IPv4,
  12-byte TLV) — the attribute that makes the message read as a genuine
  response — followed by a `SOFTWARE` (0x8022) attribute that fills the rest of
  the advertised body. The SOFTWARE value is printable ASCII and clamped to 124
  bytes (RFC 5389 §15.10 requires a value below 128; 124 is the largest
  4-aligned length under that).
- Any prefix bytes past the advertised attributes are zero-filled.

The advertised length covers exactly the TLVs written, so a strict STUN parser
stops before the WireGuard payload — which trails undissected, as a short STUN
message does inside an oversized datagram — instead of reading it as an
attribute whose bogus length overruns the buffer (the "Malformed Packet"
fingerprint a header-only fill would leave). Prefixes shorter than the 20-byte
header copy the longest available header prefix; the 15-byte install-script
minimum still carries the type, length, magic cookie, and partial transaction
ID.

```
AWG packet (backend → client):
┌──────────────────────────┬──────────┬──────────────────────┐
│   S padding (random)     │ H header │   WG payload         │
│   (S1-S4 bytes)          │ (4 bytes)│   (variable)         │
└──────────────────────────┴──────────┴──────────────────────┘
 ▲                                     ▲
 │ overwritten with STUN response      │ trails the advertised
 ▼ header + attributes                 length (undissected)
┌────────────────────────────────────┐┌──────────────────────┐
│ 0101 │ msg_len │ 2112A442 │ txn(12) ││  WG payload          │
│ 0020 0008 XOR-MAPPED-ADDRESS        ││  (opaque ciphertext) │
│ 8022 vlen   SOFTWARE (≤124) │ 00 …  ││                      │
└────────────────────────────────────┘└──────────────────────┘
```

### SIP Imitation

**Probe detection** (`detect_protocol`):
```
ASCII prefix matches (case-insensitive):
  "SIP/"  | "REGISTER " | "INVITE " | "OPTIONS "
```
These are the most common SIP request methods and the SIP version string
(RFC 3261 §7). Up to 10 bytes are checked.

**Probe response** (`generate_sip_trying`):
A valid SIP `100 Trying` response (RFC 3261 §8.2.6):
```
SIP/2.0 100 Trying\r\n
Via: <echoed from request>\r\n
From: <echoed from request>\r\n
To: <echoed from request>\r\n
Call-ID: <echoed from request>\r\n
CSeq: <echoed from request>\r\n
Content-Length: 0\r\n
\r\n
```
RFC 3261 requires echoing Via, From, To, Call-ID, and CSeq headers. The
proxy parses the incoming request line-by-line and echoes any header whose
name (case-insensitive) matches one of these five. This makes the response
indistinguishable from a real SIP proxy.

**Padding fill** (`apply_sip_padding`):
- Filled by cycling through: `Via: SIP/2.0/UDP proxy\r\nContent-Length: 0\r\n`
- The last 2 bytes of the padding prefix are always overwritten with `\r\n`
- This makes the padding look like legitimate SIP header continuation

```
AWG packet (backend → client):
┌──────────────────────────────┬──────────┬──────────────────────┐
│   S padding (random)         │ H header │   WG payload         │
│   (S1-S4 bytes)              │ (4 bytes)│   (variable)         │
└──────────────────────────────┴──────────┴──────────────────────┘
 ▲
 │ overwritten with:
 ▼
┌──────────────────────────────┐
│ Via: SIP/2.0/UDP proxy\r\n   │
│ Content-Length: 0\r\n         │
│ Via: SIP/2.0/UDP pr...\r\n   │
└──────────────────────────────┘
```

---

## AWG Packet Classification

AmneziaWG modifies standard WireGuard by replacing the 4-byte message type
header with a random value from a per-type range and prepending random
padding before the obfuscated header.

| WireGuard Type        | AWG Header Range | Padding Prefix |
|-----------------------|------------------|----------------|
| Handshake Initiation  | H1 (min–max)     | S1 bytes       |
| Handshake Response    | H2 (min–max)     | S2 bytes       |
| Cookie Reply          | H3 (min–max)     | S3 bytes       |
| Transport Data        | H4 (min–max)     | S4 bytes       |

Classification algorithm (`classify_awg_packet`):
```
for each (S, H-range, packet_type) in [(S1,H1), (S2,H2), (S3,H3), (S4,H4)]:
    if data.len() >= S + 4:
        header = u32::from_le_bytes(data[S..S+4])
        if H.min ≤ header ≤ H.max → return packet_type

otherwise → unclassified (no transform applied)
```

The S-padding precedes the H header, so the classifier tries each S offset
to find the header. The H ranges are validated to be non-overlapping during
config parsing so classification is unambiguous.

---

## Worked Examples

### Example 1: QUIC Initial Probe

A DPI system sends a QUIC Initial to test if the port runs a QUIC server.

**Incoming packet** (11 bytes):
```
Byte  Value   Meaning
────  ─────   ───────
  0   0xC3    Long header: form=1, fixed=1, type=00 (Initial), reserved=00, pn_length=11
  1   0x00    ┐
  2   0x00    │ Version = 0x00000001 (QUIC v1)
  3   0x00    │
  4   0x01    ┘
  5   0x04    DCID length = 4
  6   0xAA    ┐
  7   0xBB    │ DCID = AA BB CC DD
  8   0xCC    │
  9   0xDD    ┘
 10   0x00    SCID length = 0 (no source connection ID)
```

**Proxy processing:**
1. `detect_protocol()` → `len ≥ 7`, `data[0] & 0xC0 = 0xC0`, `DCID_len = 4 ≤ 20`,
   `SCID_len = 0 ≤ 20` → `Protocol::Quic`
2. `try_acquire_probe()` → `true` (rate limiter has tokens)
3. `generate_response(Quic, &data)` → Version Negotiation packet
4. Packet is also forwarded to backend (AWG ignores it)

**Outgoing probe response** (15 bytes):
```
Byte  Value       Meaning
────  ─────       ───────
  0   0xC3        Long header form + fixed bit (incoming type bits preserved)
  1   0x00 00     ┐
  3   0x00 00     ┘ Version = 0 (version negotiation marker)
  5   0x00        Response DCID len = 0 (incoming SCID was empty)
  6   0x04        Response SCID len = 4 (incoming DCID length)
  7   0xAA        ┐
  8   0xBB        │ Response SCID = incoming DCID (swapped per RFC)
  9   0xCC        │
 10   0xDD        ┘
 11   0x00        ┐
 12   0x00        │ Supported Version = 0x00000001 (QUIC v1)
 13   0x00        │
 14   0x01        ┘
```

### Example 2: DNS Query Probe

A DPI system sends a DNS A-record query for `example.com`.

**Incoming packet** (29 bytes):
```
Byte  Value   Meaning
────  ─────   ───────
  0   0xAB    ┐ Transaction ID = 0xABCD
  1   0xCD    ┘
  2   0x01    ┐ Flags: QR=0, Opcode=0, RD=1
  3   0x00    ┘
  4   0x00    ┐ QDCOUNT = 1
  5   0x01    ┘
  6   0x00    ┐ ANCOUNT = 0
  7   0x00    ┘
  8   0x00    ┐ NSCOUNT = 0
  9   0x00    ┘
 10   0x00    ┐ ARCOUNT = 0
 11   0x00    ┘
 12   0x07    Label length = 7
 13   'e'     ┐
 14   'x'     │
 15   'a'     │ "example"
 16   'm'     │
 17   'p'     │
 18   'l'     │
 19   'e'     ┘
 20   0x03    Label length = 3
 21   'c'     ┐
 22   'o'     │ "com"
 23   'm'     ┘
 24   0x00    Root label (end of QNAME)
 25   0x00    ┐ QTYPE = 1 (A record)
 26   0x01    ┘
 27   0x00    ┐ QCLASS = 1 (IN)
 28   0x01    ┘
```

**Proxy processing:**
1. `detect_protocol()` → `len ≥ 12`, `flags & 0xF800 = 0x0000`, `QDCOUNT = 1`,
   QNAME `example.com` walks cleanly to the root label, QCLASS = IN
   → `Protocol::Dns`
2. `try_acquire_probe()` → `true`
3. `generate_response(Dns, &data)` → SERVFAIL with echoed question section

**Outgoing probe response** (29 bytes):
```
Byte  Value   Meaning
────  ─────   ───────
  0   0xAB    ┐ Transaction ID = 0xABCD (echoed)
  1   0xCD    ┘
  2   0x81    ┐ Flags: QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
  3   0x82    ┘
  4   0x00    ┐ QDCOUNT = 1
  5   0x01    ┘
  6   0x00    ┐ ANCOUNT = 0
  7   0x00    ┘
  8   0x00    ┐ NSCOUNT = 0
  9   0x00    ┘
 10   0x00    ┐ ARCOUNT = 0
 11   0x00    ┘
 12   0x07    ┐
 13   'e'     │
  …          │ Question section echoed verbatim
 24   0x00    │
 25   0x00    │ QTYPE = 1
 26   0x01    │
 27   0x00    │ QCLASS = 1
 28   0x01    ┘
```

### Example 3: SIP INVITE Probe

A DPI system sends a SIP INVITE request.

**Incoming packet:**
```
INVITE sip:user@example.com SIP/2.0\r\n
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776\r\n
From: <sip:caller@example.com>;tag=1234\r\n
To: <sip:user@example.com>\r\n
Call-ID: a84b4c76e66710@pc33.example.com\r\n
CSeq: 314159 INVITE\r\n
Content-Length: 0\r\n
\r\n
```

**Proxy processing:**
1. `detect_protocol()` → ASCII prefix starts with `INVITE ` → `Protocol::Sip`
2. `try_acquire_probe()` → `true`
3. `generate_response(Sip, &data)` → `100 Trying` with echoed headers

**Outgoing probe response:**
```
SIP/2.0 100 Trying\r\n
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776\r\n
From: <sip:caller@example.com>;tag=1234\r\n
To: <sip:user@example.com>\r\n
Call-ID: a84b4c76e66710@pc33.example.com\r\n
CSeq: 314159 INVITE\r\n
Content-Length: 0\r\n
\r\n
```

### Example 4: AWG Transport Data with QUIC Padding

Backend sends a Transport Data packet back to the client. AWG config has
`S4 = 20` and `H4 = 700-800`.

**Backend response** (124 bytes):
```
┌──────────────────┬──────────────────┬─────────────────────────┐
│  Random padding  │ Header: 750 (LE) │  WG encrypted payload   │
│  (20 bytes)      │ [0xEE,0x02,0,0]  │  (100 bytes)            │
└──────────────────┴──────────────────┴─────────────────────────┘
 bytes 0-19          bytes 20-23        bytes 24-123
```

**Relay task processing:**
1. `classify_awg_packet()` → tries S4 offset (20), reads header `750` at
   bytes 20-23, matches H4 range `[700,800]` → `TransportData`
2. `padding_size()` → `S4 = 20`
3. `apply_quic_padding(data, 20)`:
   - FNV-1a hash of `data[20..84]` (payload after padding) → seed
   - `data[0]` = QUIC short-header byte with fixed bit set, reserved bits
     (0x18) cleared, and spin/key-phase/PN-length bits derived from seed
   - `data[1..20]` = LCG PRNG pseudo-random bytes

**Transformed packet** (124 bytes, same length):
```
┌──────────────────┬──────────────────┬─────────────────────────┐
│ QUIC-like padding│ Header: 750 (LE) │  WG encrypted payload   │
│ [0x4X, PRN...]   │ [0xEE,0x02,0,0]  │  (100 bytes, untouched) │
└──────────────────┴──────────────────┴─────────────────────────┘
```

To DPI, the leading bytes now look like encrypted QUIC 1-RTT data rather
than random padding.

---

## Session Management

Each client `SocketAddr` gets a dedicated **Session** consisting of an
ephemeral UDP socket `connect()`ed to the backend. This provides:

- **NAT-like isolation** — each client's traffic uses a distinct source port
  to the backend, so the backend (and any intermediate NAT) can distinguish
  clients.
- **Efficient relay** — each session gets a dedicated async recv task that
  awaits data from the backend socket event-driven (no polling or per-tick
  allocation), keeping CPU usage proportional to actual traffic.
- **Automatic cleanup** — a periodic task (default: every 60 s) reaps
  sessions idle longer than `session_ttl_secs` (default: 300 s) and removes
  associated metrics.
- **Resource limits** — `max_sessions` (default: 10,000) prevents resource
  exhaustion. Both the session table and the metrics store enforce this limit.
  Excess clients receive an error log and their packets are dropped.

```
SessionTable (DashMap<SocketAddr, Session>)
  │
  ├── 203.0.113.1:4500  ──► Session { backend_sock: 0.0.0.0:49152 → backend, ... }
  ├── 198.51.100.5:6789 ──► Session { backend_sock: 0.0.0.0:49153 → backend, ... }
  └── 192.0.2.10:3333   ──► Session { backend_sock: 0.0.0.0:49154 → backend, ... }
```

---

## Rate Limiting

Probe responses are rate-limited per client using a **token bucket**
algorithm:

- Each client gets `rate_limit_per_sec` tokens (default: 5)
- Tokens refill continuously at `rate_limit_per_sec` tokens/second
- Each probe response costs 1 token
- If no tokens available, the probe response is silently skipped (the
  packet is still forwarded to the backend)
- The `MetricsStore` enforces the same `max_sessions` cap as the session table

This prevents a DPI system from using the probe response mechanism to amplify
traffic or exhaust proxy resources.

---

## Testing

```bash
cd amneziawg-proxy
cargo test
```

The test suite includes:

- A comprehensive suite of unit tests covering config parsing/validation,
  protocol detection, response generation, padding transformation, AWG
  classification, session management, backend I/O, metrics/rate limiting,
  and error types.
- Integration tests that spin up a mock echo backend, start the proxy,
  send real UDP packets, and verify end-to-end behavior including probe
  detection, version negotiation responses, and multi-client session
  isolation.
