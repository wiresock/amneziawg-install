# amneziawg-proxy — Architecture & Packet Flows

## Overview

`amneziawg-proxy` is an async UDP proxy that sits in front of an AmneziaWG
server and makes the traffic look like a legitimate application protocol
(QUIC, DNS, or SIP) to defeat Deep Packet Inspection (DPI).

It performs two complementary functions:

1. **Probe response** — when a DPI system sends a protocol probe (e.g. a QUIC
   Initial or a DNS query), the proxy generates a valid protocol response so
   the port appears to host the imitated service.
2. **Padding transformation** — outgoing AmneziaWG packets have their S1–S4
   padding regions overwritten with protocol-conformant filler bytes, so the
   statistical byte distribution matches the imitated protocol.

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
                                  │     │    │   relay task     │  │
                                  │     │    │  (poll backends, │  │
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

| Module         | Responsibility |
|----------------|----------------|
| `main.rs`      | CLI entry point: loads TOML config, optionally loads AWG config, sets up logging and signal handling, runs the proxy. |
| `config.rs`    | Parses `proxy.toml` (TOML) and AWG INI-style config files. Validates addresses, protocol names, H-range non-overlap, Jmin≤Jmax. |
| `proxy.rs`     | Core runtime: binds frontend socket, runs the main `recv_from` loop, spawns cleanup and relay tasks, orchestrates all other modules. |
| `responder.rs` | Probe detection (`detect_protocol`) and response generation (`generate_response`). Also contains AWG packet classification (`classify_awg_packet`). |
| `transform.rs` | Padding transformation: overwrites the S1–S4 padding region with protocol-conformant filler (QUIC PRNG, DNS header, SIP text). |
| `session.rs`   | Per-client session table backed by `DashMap`. Each session owns a dedicated ephemeral UDP socket connected to the backend. TTL-based expiry. |
| `backend.rs`   | Low-level backend I/O: `forward_to_backend`, `recv_from_backend`, `send_to_client`, `try_recv_from_backend` (with timeout). |
| `metrics.rs`   | Per-client counters (packets in/out, probes) and token-bucket rate limiter for probe responses. |
| `errors.rs`    | `ProxyError` enum with `thiserror` derives: Config, Io, SessionNotFound, RateLimited, BackendUnreachable, Shutdown. |

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

The relay task reads the first 4 bytes of the backend response as a
little-endian `u32` header value. It checks which H range the value falls
into, determining the AWG packet type (Handshake Init / Response / Cookie
Reply / Transport Data). The corresponding S-value tells it how many trailing
bytes are the padding region. Those bytes are then overwritten with
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
First byte: (byte & 0xC0) == 0xC0
```
This matches QUIC long-header packets (RFC 9000 §17.2), including Initial,
0-RTT, Handshake, and Retry packets. The two high bits being `11` indicate
the long header form bit (0x80) and the fixed bit (0x40).

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
- First byte: `0x40 | (prng & 0x3F)` — QUIC short-header form (fixed bit
  set, header form = 0)
- Remaining bytes: pseudo-random from an FNV-1a-seeded LCG PRNG
- Seed is derived from the first 64 bytes of the WG payload, so each packet
  produces different padding
- Result: high-entropy byte distribution matching encrypted QUIC 1-RTT data

```
AWG packet (backend → client):
┌──────────┬──────────────────────┬────────────────────────┐
│ H header │   WG payload         │   S padding (random)   │
│ (4 bytes)│   (variable)         │   (S1-S4 bytes)        │
└──────────┴──────────────────────┴────────────────────────┘
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

**Probe detection** (`detect_protocol`):
```
data.len() >= 12
  AND (flags & 0xF800) == 0x0000   (QR=0, standard opcode)
  AND QDCOUNT >= 1
```
Flags are bytes 2-3 (big-endian), QDCOUNT is bytes 4-5 (big-endian), per
RFC 1035 §4.1.1. The mask `0xF800` checks QR bit (must be 0 = query) and
opcode (must be 0 = standard query).

**Probe response** (`generate_dns_servfail`):
A valid DNS SERVFAIL response (RFC 1035 §4.1):
```
Byte  Field
────  ─────
 0-1  Transaction ID      Echoed from incoming query
 2-3  0x8182              Flags: QR=1, RD=1, RA=1, RCODE=2 (SERVFAIL)
 4-5  0x0001              QDCOUNT = 1
 6-7  0x0000              ANCOUNT = 0
 8-9  0x0000              NSCOUNT = 0
10-11 0x0000              ARCOUNT = 0
12+   Question section    Echoed from incoming query (QNAME + QTYPE + QCLASS)
```
The question section is parsed by walking the QNAME labels (each prefixed
with a length byte, terminated by a zero root label) then appending 4 bytes
for QTYPE and QCLASS. Echoing the question section is required by RFC 1035
and makes the response indistinguishable from a real recursive resolver
failure.

**Padding fill** (`apply_dns_padding`):
- Bytes 0-1: Transaction ID derived from payload bytes 0-1
- Bytes 2-3: `0x81 0x80` (QR=1, RD=1, RA=1, RCODE=NOERROR)
- Bytes 4-11: Section counts (QDCOUNT=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0)
- Bytes 12+: Zero-filled (EDNS OPT padding per RFC 7830)

```
AWG packet (backend → client):
┌──────────┬──────────────────────┬──────────────────────────┐
│ H header │   WG payload         │   S padding (random)     │
│ (4 bytes)│   (variable)         │   (S1-S4 bytes)          │
└──────────┴──────────────────────┴──────────────────────────┘
                                   ▲
                                   │ overwritten with:
                                   ▼
                               ┌──────────────────────────┐
                               │ TX_ID │ flags │ counts   │
                               │ (2B)  │ (2B)  │ (8B)     │
                               │ 0x81 0x80     │          │
                               ├──────────────────────────┤
                               │ 0x00 ... (EDNS padding)  │
                               └──────────────────────────┘
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
- The last 2 bytes are always overwritten with `\r\n`
- This makes the padding look like legitimate SIP header continuation

```
AWG packet (backend → client):
┌──────────┬──────────────────────┬──────────────────────────────┐
│ H header │   WG payload         │   S padding (random)         │
│ (4 bytes)│   (variable)         │   (S1-S4 bytes)              │
└──────────┴──────────────────────┴──────────────────────────────┘
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
header with a random value from a per-type range and appending random padding.

| WireGuard Type        | AWG Header Range | Padding Size |
|-----------------------|------------------|-------------|
| Handshake Initiation  | H1 (min–max)     | S1 bytes    |
| Handshake Response    | H2 (min–max)     | S2 bytes    |
| Cookie Reply          | H3 (min–max)     | S3 bytes    |
| Transport Data        | H4 (min–max)     | S4 bytes    |

Classification algorithm (`classify_awg_packet`):
```
header = u32::from_le_bytes(data[0..4])

if H1.min ≤ header ≤ H1.max → HandshakeInit   → padding = S1
if H2.min ≤ header ≤ H2.max → HandshakeResponse → padding = S2
if H3.min ≤ header ≤ H3.max → CookieReply      → padding = S3
if H4.min ≤ header ≤ H4.max → TransportData    → padding = S4
otherwise                    → unclassified (no transform applied)
```

The H ranges are validated to be non-overlapping during config parsing so
classification is unambiguous.

---

## Worked Examples

### Example 1: QUIC Initial Probe

A DPI system sends a QUIC Initial to test if the port runs a QUIC server.

**Incoming packet** (11 bytes):
```
Byte  Value   Meaning
────  ─────   ───────
  0   0xC3    Long header: form=1, fixed=1, type=00 (Initial), reserved=11
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
1. `detect_protocol()` → `data[0] & 0xC0 = 0xC0` → `Protocol::Quic`
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
1. `detect_protocol()` → `len ≥ 12`, `flags & 0xF800 = 0x0000`, `QDCOUNT = 1`
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
┌──────────────────┬─────────────────────────┬──────────────────┐
│ Header: 750 (LE) │  WG encrypted payload   │  Random padding  │
│ [0xEE,0x02,0,0]  │  (100 bytes)            │  (20 bytes)      │
└──────────────────┴─────────────────────────┴──────────────────┘
 bytes 0-3           bytes 4-103               bytes 104-123
```

**Relay task processing:**
1. `classify_awg_packet()` → header `750` is in H4 range `[700,800]`
   → `TransportData`
2. `padding_size()` → `S4 = 20`
3. `payload_end = 124 - 20 = 104`
4. `apply_quic_padding(data, 104)`:
   - FNV-1a hash of `data[0..64]` → seed
   - `data[104]` = `0x40 | (seed & 0x3F)` (QUIC short header)
   - `data[105..124]` = LCG PRNG pseudo-random bytes

**Transformed packet** (124 bytes, same length):
```
┌──────────────────┬─────────────────────────┬──────────────────┐
│ Header: 750 (LE) │  WG encrypted payload   │ QUIC-like padding│
│ [0xEE,0x02,0,0]  │  (100 bytes, untouched) │ [0x4X, PRN...]   │
└──────────────────┴─────────────────────────┴──────────────────┘
```

To DPI, the trailing bytes now look like encrypted QUIC 1-RTT data rather
than random padding.

---

## Session Management

Each client `SocketAddr` gets a dedicated **Session** consisting of an
ephemeral UDP socket `connect()`ed to the backend. This provides:

- **NAT-like isolation** — each client's traffic uses a distinct source port
  to the backend, so the backend (and any intermediate NAT) can distinguish
  clients.
- **Efficient relay** — the relay task polls all backend sockets every 1 ms
  using `try_recv_from_backend` with a zero timeout (non-blocking).
- **Automatic cleanup** — a periodic task (default: every 60 s) reaps
  sessions idle longer than `session_ttl_secs` (default: 300 s) and removes
  associated metrics.
- **Resource limits** — `max_sessions` (default: 10,000) prevents resource
  exhaustion. Excess clients receive an error log and their packets are
  dropped.

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
- The `MetricsStore` also enforces a maximum of 10,000 tracked clients

This prevents a DPI system from using the probe response mechanism to amplify
traffic or exhaust proxy resources.

---

## Configuration Reference

### proxy.toml

```toml
# Address the proxy listens on (required)
listen = "0.0.0.0:51820"

# Backend AmneziaWG address (required)
backend = "127.0.0.1:51821"

# Which protocol to imitate: "quic", "dns", or "sip" (default: "quic")
imitate_protocol = "quic"

# Session TTL in seconds (default: 300)
session_ttl_secs = 300

# Cleanup sweep interval in seconds (default: 60)
cleanup_interval_secs = 60

# Max probe responses per client per second (default: 5)
rate_limit_per_sec = 5

# UDP recv buffer size in bytes (default: 65535)
buffer_size = 65535

# Max concurrent sessions (default: 10000)
max_sessions = 10000

# Optional: path to AWG config file for packet classification
# When set, the proxy reads S1-S4 and H1-H4 for per-type padding.
# Without this, no padding transformation is applied.
awg_config = "/etc/amnezia/amneziawg/awg0.conf"
```

### AWG Config (INI-style, `[Interface]` section)

```ini
[Interface]
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 42
S2 = 88
S3 = 33
S4 = 120
H1 = 5-100000004
H2 = 100000005-200000004
H3 = 200000005-300000004
H4 = 300000005-400000004
```

Only the `[Interface]` section is parsed; `[Peer]` sections and unknown keys
(Address, PrivateKey, etc.) are ignored.

---

## Testing

```bash
cd amneziawg-proxy
cargo test
```

The test suite includes:

- **81 unit tests** covering config parsing/validation, protocol detection,
  response generation, padding transformation, AWG classification, session
  management, backend I/O, metrics/rate limiting, and error types.
- **2 integration tests** that spin up a mock echo backend, start the proxy,
  send real UDP packets, and verify end-to-end behavior including probe
  detection, version negotiation responses, and multi-client session
  isolation.
