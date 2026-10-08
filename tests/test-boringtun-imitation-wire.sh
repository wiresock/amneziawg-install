#!/usr/bin/env bash

# Unit tests for the imitation wire checks: the framing, fragment
# bookkeeping, packet-kind classification, record parsers and per-kind SIP
# oracle of tests/helpers/boringtun-imitation-wire.py, the owned-child tracker,
# process contracts and result checks of tests/helpers/boringtun-wire-checks.sh,
# and the two consumers that use them, wire_prefixes in
# tests/test-boringtun-host-live.sh and run_scenario/expect_scenario in
# tests/test-boringtun-sip-wire-live.sh. Nothing here needs root or the
# network: synthetic frames, datagrams and capture files stand in for the
# wire, and a fake capture/replay child stands in for the packet sockets. The
# consumers are extracted verbatim from their files; only their external
# processes are replaced.
#
# A consumer fixture counts as rejecting bad evidence only if it completed,
# made assertions, exited 1 and failed the intended assertion: an empty result
# or a fixture that crashed is a failure of this test, never a detection.
#
# The oracle replaces a pooled check that demanded at least one SIP-shaped
# server datagram whenever any of S2-S4 was 31 bytes or more. That check failed
# on a correct server with S2=26 S3=81 S4=22 (0/2054 shaped): S3 prefixes only
# cookie replies, and none was sent.
#
# A complete datagram that fits more than one kind is resolved by MAC1
# consistency under the receiving client's public key and receiver-index
# correlation, in a fixed precedence; neither verifies a Noise handshake or
# an AEAD. Without that, the host check failed on a correct server whose one
# handshake response, at S2=54, presumably also fit the transport rule at
# S4=52 (follow-up D; that datagram's bytes were not retained, and genuine
# reproductions show the mechanism). Genuine datagrams of the pinned binary
# at those sizes anchor the mac1 computation to the real wire.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WIRE_REAL="${SCRIPT_DIR}/helpers/boringtun-imitation-wire.py"
HOST_LIVE="${SCRIPT_DIR}/test-boringtun-host-live.sh"
SIP_LIVE="${SCRIPT_DIR}/test-boringtun-sip-wire-live.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-imitation-wire.XXXXXX")"
trap 'rm -rf -- "${T}"' EXIT
export PYTHONDONTWRITEBYTECODE=1

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required" >&2; exit 1; }
REAL_PYTHON="$(command -v python3)"

PASS=0
FAIL=0
ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}
not_ok() {
	printf '  FAIL: %s\n' "$1" >&2
	FAIL=$((FAIL + 1))
}
assert_eq() {
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected:\n%s\n    actual:\n%s\n' "$(sed 's/^/      /' <<<"$1")" "$(sed 's/^/      /' <<<"$2")" >&2
	fi
}
assert_true() {
	local NAME="$1"
	shift
	if "$@"; then ok "${NAME}"; else not_ok "${NAME}"; fi
}

H="100000001-100000100,200000001-200000100,300000001-300000100,400000001-400000100"
# The receiving client's public key the consumers pass to the capture.
FIXTURE_KEY="QZhn3Fgt6SXW24z7epWkvKtUNLJFyqiVehDDDRwUf2g="
# Python against the real helper, imported from its file: datagrams, frames
# and capture files built exactly.
py() {
	"${REAL_PYTHON}" - "${WIRE_REAL}" "$@" <<'PY'
import base64, hashlib, importlib.util, os, struct, sys
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
SIZES = {"init": 148, "response": 92, "cookie": 64, "transport": 32}
TAGS = {"init": 100000050, "response": 200000050, "cookie": 300000050, "transport": 400000050}
SERVER = bytes([192, 0, 2, 1])
# Genuine datagrams of the pinned BoringTun (71d88784) SIP server at follow-up
# D's sizes, S1=99 S2=54 S3=92 S4=52, with REPORTED's H ranges, recorded on the
# client's side: the handshake response, which also fits the transport rule
# (its four bytes at 52 are 0x6f602020, inside H4), and the first ping reply
# after it, which carries that response's receiver index. Public bytes only:
# SIP text, a handshake response, ciphertext. GENUINE_KEY is the receiving
# client's static public key.
REPORTED = "99,54,92,52,123456789-223456788,708538112-708538367,1234567890-1334567889,1862270976-1962270975"
GENUINE_KEY = "QZhn3Fgt6SXW24z7epWkvKtUNLJFyqiVehDDDRwUf2g="
GENUINE_RESPONSE = bytes.fromhex(
    "4f5054494f4e53207369703a6d40766f69702e7062782e6578616d706c65205349502f322e300d0a0d0a2020202020202020"
    "20202020606f3b2a011c8b2e0101e34c374fba8079d1bacc51b0947e24d74c92a465e5d603f523753b4165f1ced5722cc62e"
    "b4f555167df1634f163785c19ba131fa9b44e3a99d34a93a4795ce0337f300000000000000000000000000000000")
GENUINE_TRANSPORT = bytes.fromhex(
    "4d455353414745207369703a6e6f63406c616e2e7062782e6578616d706c65205349502f322e300d0a0d0a20202020202020"
    "2020056408710101e34c0000000000000000258805a040114b24f95603e3ef7b44be86423f6a7bad454aafa50a3c4f0d1a2e"
    "9b8b427519d770af0000ba323ed92213d4c960d30a817e8039c994c0ceca793e31e48a3654594bce6fed4c3f62f78a41431c"
    "f8193ae14f59c5bb1617e9fc108e918246619f8594636a8e167f04b09dd7")
# Constructed datagrams fitting more than one kind: S1=64 S2=81 S3=109 S4=45
# with wide H2 and H3 (a transport of 96 plaintext bytes is 173 bytes, the
# length of a response and of a cookie reply), and a receiving key of this
# test's own. mac1 is computed here as the WireGuard protocol defines it,
# independently of the helper; the genuine response above holds it too.
# Their Noise fields and ciphertext are random bytes: they isolate the MAC1
# and receiver-index rules and are no handshake or transport a peer accepts.
CROSSED = "64,81,109,45,5-104,65536-1073741823,1073741824-2130706431,2130706432-2147483647"
TEST_KEY = bytes(range(32))

def with_mac1(body, public, valid=True):
    """BODY (a handshake message up to mac1) with its mac1 and a zero mac2."""
    mac = hashlib.blake2s(body, digest_size=16, key=hashlib.blake2s(b"mac1----" + public).digest()).digest()
    return body + (mac if valid else bytes(b ^ 0xFF for b in mac)) + bytes(16)

def response_message(receiver, valid=True, at28=0, public=TEST_KEY, tag=500000000):
    """A response to RECEIVER whose ephemeral key holds AT28 at offset 28."""
    body = bytearray(struct.pack("<III", tag, 0x11223344, receiver) + os.urandom(48))
    body[28:32] = struct.pack("<I", at28)
    return with_mac1(bytes(body), public, valid)

def init_message(valid=True, at56=0, public=TEST_KEY, tag=50):
    """An initiation whose encrypted static key holds AT56 at offset 56."""
    body = bytearray(struct.pack("<II", tag, 0x55667788) + os.urandom(108))
    body[56:60] = struct.pack("<I", at56)
    return with_mac1(bytes(body), public, valid)

def transport(receiver, s4=45, plaintext=96, tag=2140000000):
    return os.urandom(s4) + struct.pack("<IIQ", tag, receiver, 7) + os.urandom(plaintext + 16)

def put(datagram, offset, value):
    return datagram[:offset] + struct.pack("<I", value) + datagram[offset + 4:]

def datagram(kind, s, prefix="random", tag=None, extra=0):
    if prefix == "sip":
        head = b"OPTIONS sip:u@x SIP/2.0\r\n\r\n"
        body = (head + b" " * s)[:s] if s >= len(head) else os.urandom(s)
    else:
        body = os.urandom(s)
    value = TAGS[kind] if tag is None else tag
    return body + struct.pack("<I", value) + os.urandom(SIZES[kind] - 4 + extra)

def ipv4(payload, src="192.0.2.1", dst="192.0.2.2", sport=51820, dport=40000, proto=17, ident=7,
         fragment=0, udp_length=None, total=None, version=4, ihl=5, pad=b""):
    udp = struct.pack(">HHHH", sport, dport, len(payload) + 8 if udp_length is None else udp_length, 0) + payload
    body = udp if proto == 17 else payload
    length = ihl * 4 + len(body) if total is None else total
    header = struct.pack(">BBHHHBBH4s4s", (version << 4) | ihl, 0, length, ident, fragment, 64, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return header + b"\0" * (ihl * 4 - 20) + body + pad

def raw(body, ident=7, fragment=0, dst="192.0.2.2"):
    """An IPv4 frame around BODY as it is: a later fragment carries no UDP header."""
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, fragment, 64, 17, 0,
                       SERVER, bytes(map(int, dst.split(".")))) + body

cmd = sys.argv[2]
if cmd == "kind":
    # kind <layout> <kind> <s> <prefix> [tag] [extra]
    sizes, ranges = wire.parse_layout(sys.argv[3])
    kind, s, prefix = sys.argv[4], int(sys.argv[5]), sys.argv[6]
    tag = int(sys.argv[7]) if len(sys.argv) > 7 and sys.argv[7] != "-" else None
    extra = int(sys.argv[8]) if len(sys.argv) > 8 else 0
    print(wire.kind_of(datagram(kind, s, prefix, tag, extra), sizes, ranges))
elif cmd == "ambiguous":
    # A response at S2=10 that is also a transport at S4=70: both tags fit.
    sizes, ranges = wire.parse_layout("64,10,64,70," + sys.argv[3])
    d = bytearray(os.urandom(102))
    d[10:14] = struct.pack("<I", 200000050)
    d[70:74] = struct.pack("<I", 400000050)
    print(wire.kind_of(bytes(d), sizes, ranges))
elif cmd == "evidence":
    # One "<case> <result>" per line: datagrams that fit more than one kind,
    # with and without the helper's MAC1 and receiver-index evidence
    # (wire.Evidence).
    key = wire.parse_public_key(GENUINE_KEY)
    sizes, ranges = wire.parse_layout(REPORTED)
    print("genuine-response-without-evidence", wire.kind_of(GENUINE_RESPONSE, sizes, ranges))
    ev = wire.Evidence(key)
    print("genuine-response", wire.kind_of(GENUINE_RESPONSE, sizes, ranges, ev))
    print("genuine-ping-reply", wire.kind_of(GENUINE_TRANSPORT, sizes, ranges, ev))
    print("genuine-response-other-key", wire.kind_of(GENUINE_RESPONSE, sizes, ranges, wire.Evidence(TEST_KEY)))
    status, length, data, _ = wire.frame_payload(ipv4(GENUINE_RESPONSE), SERVER, 51820, fragments=wire.Fragments())
    print("genuine-record", wire.record_line(sizes, ranges, status, length, data, wire.Evidence(key)).replace(" ", "_"))
    # Its first 136 bytes as a first fragment: both tags and mac1 are inside
    # it, but a fragment is never resolved by evidence.
    udp = struct.pack(">HHHH", 51820, 40000, 8 + len(GENUINE_RESPONSE), 0) + GENUINE_RESPONSE
    status, length, data, _ = wire.frame_payload(raw(udp[:144], fragment=0x2000), SERVER, 51820, fragments=wire.Fragments())
    print("genuine-first-fragment", wire.record_line(sizes, ranges, status, length, data, wire.Evidence(key)).split(" ")[0])

    sizes, ranges = wire.parse_layout(CROSSED)
    def kind(datagram, evidence):
        return wire.kind_of(datagram, sizes, ranges, evidence)
    def response(receiver, valid=True, at109=0):
        """A 173-byte response at S2=81 whose bytes at 45 (the transport
        reading) fit no range and at 109 (the cookie reading) are AT109."""
        return put(os.urandom(81) + response_message(receiver, valid, at28=at109), 45, 0)
    def ping_reply(receiver, at81=0, at109=0):
        """A 173-byte transport whose bytes at 81 and 109 are AT81, AT109."""
        return put(put(transport(receiver), 81, at81), 109, at109)
    # A transport that also fits the response rule: the response reading's
    # mac1 is invalid, so it is a transport, with or without a recorded
    # receiver index.
    mirror = ping_reply(0xA1A1A1A1, at81=300000000)
    print("transport-also-response-without-evidence", kind(mirror, None))
    print("transport-also-response", kind(mirror, wire.Evidence(TEST_KEY)))
    # A transport that also fits the cookie rule: resolved only by a receiver
    # index recorded from a MAC1-valid response.
    tie = ping_reply(0xB2B2B2B2, at109=1500000000)
    ev = wire.Evidence(TEST_KEY)
    print("session-response", kind(response(0xB2B2B2B2), ev))
    print("transport-also-cookie-in-session", kind(tie, ev))
    print("transport-also-cookie-other-session", kind(ping_reply(0xC3C3C3C3, at109=1500000000), ev))
    print("transport-also-cookie-no-session", kind(tie, wire.Evidence(TEST_KEY)))
    forged = wire.Evidence(TEST_KEY)
    print("forged-response", kind(response(0xB2B2B2B2, valid=False), forged))
    print("transport-also-cookie-after-forged-response", kind(tie, forged))
    print("transport-also-response-and-cookie-in-session", kind(ping_reply(0xB2B2B2B2, 300000000, 1500000000), ev))
    print("transport-also-response-and-cookie-no-session",
          kind(ping_reply(0xB2B2B2B2, 300000000, 1500000000), wire.Evidence(TEST_KEY)))
    # A response that also fits the cookie rule (its ephemeral key at 109).
    print("response-also-cookie", kind(response(0xD4D4D4D4, at109=1500000000), wire.Evidence(TEST_KEY)))
    print("forged-response-also-cookie", kind(response(0xD4D4D4D4, valid=False, at109=1500000000), wire.Evidence(TEST_KEY)))
    # A server initiation (212 bytes) that also fits the transport rule.
    init = put(os.urandom(64) + init_message(), 45, 2140000000)
    print("init-also-transport", kind(init, wire.Evidence(TEST_KEY)))
    print("forged-init-also-transport", kind(put(os.urandom(64) + init_message(valid=False), 45, 2140000000),
                                              wire.Evidence(TEST_KEY)))
    # An initiation and a response in one datagram (S2 = S1 + 56, which the
    # installer never draws): one mac1 field serves both readings.
    sizes, ranges = wire.parse_layout("10,66,31,130,5-104,65536-1073741823,1073741824-2130706431,2130706432-2147483647")
    both = os.urandom(10) + init_message(at56=300000000)
    print("init-also-response", wire.kind_of(both, sizes, ranges, wire.Evidence(TEST_KEY)))
    neither = os.urandom(10) + init_message(valid=False, at56=300000000)
    print("forged-init-also-response", wire.kind_of(neither, sizes, ranges, wire.Evidence(TEST_KEY)))
    # Both MAC1 results mocked valid: this checks that two MAC1-valid
    # readings stay ambiguous, not two genuine handshakes.
    class Credulous(wire.Evidence):
        def authentic(self, message):
            return True
    print("two-authentic-readings", wire.kind_of(both, sizes, ranges, Credulous(TEST_KEY)))
elif cmd == "key":
    try:
        print("accepted %d" % len(wire.parse_public_key(sys.argv[3])))
    except wire.InputError:
        print("refused")
elif cmd == "record-genuine":
    # record-genuine <out> <with-evidence|without-evidence> <cookies>: the
    # genuine response and three copies of the genuine ping reply, then
    # COOKIES shaped cookie replies, recorded as capture() records them.
    sizes, ranges = wire.parse_layout(REPORTED)
    ev = wire.Evidence(wire.parse_public_key(GENUINE_KEY)) if sys.argv[4] == "with-evidence" else None
    datagrams = [GENUINE_RESPONSE] + [GENUINE_TRANSPORT] * 3
    datagrams += [datagram("cookie", 92, "sip", tag=1300000000) for _ in range(int(sys.argv[5]))]
    with open(sys.argv[3], "w") as out:
        for d in datagrams:
            status, length, data, _ = wire.frame_payload(ipv4(d), SERVER, 51820, fragments=wire.Fragments())
            out.write(wire.record_line(sizes, ranges, status, length, data, ev) + "\n")
elif cmd == "record":
    # record <layout> <out> (<kind>:<count>:<sip|random>)...: a capture file
    # written exactly as capture() writes it, through frame_payload.
    sizes, ranges = wire.parse_layout(sys.argv[3])
    with open(sys.argv[4], "w") as out:
        for spec in sys.argv[5:]:
            kind, count, prefix = spec.split(":")
            s = sizes[wire.KIND_NAMES.index(kind)]
            for _ in range(int(count)):
                d = datagram(kind, s, prefix, extra=16 if kind == "transport" else 0)
                status, length, data, _ = wire.frame_payload(ipv4(d), SERVER, 51820, fragments=wire.Fragments())
                out.write(wire.record_line(sizes, ranges, status, length, data) + "\n")
elif cmd == "frame":
    # frame <case>: "<status> <length> <payload bytes kept> <whole|fragmented>"
    payload = os.urandom(77)
    cases = {
        "valid": dict(),
        "padded": dict(pad=b"\0" * 6),
        "udp-length-8": dict(udp_length=8),
        "udp-length-long": dict(udp_length=200),
        "ip-total-28": dict(total=28),
        "ip-total-long": dict(total=500),
        "ipv6-version": dict(version=6),
        "ihl-4": dict(ihl=4),
        "ihl-6": dict(ihl=6),
        "orphan-fragment": dict(fragment=10),
        "first-fragment-short": dict(fragment=0x2000, udp_length=40),
        "other-source": dict(src="192.0.2.9"),
        "other-port": dict(sport=53),
        "icmp": dict(proto=1),
    }
    name = sys.argv[3]
    if name == "first-fragment":
        frame = ipv4(payload[:72], fragment=0x2000, udp_length=1000)
    elif name == "first-fragment-odd":
        frame = ipv4(payload[:73], fragment=0x2000, udp_length=1000)
    elif name == "short-header":
        frame = ipv4(payload)[:18]
    else:
        frame = ipv4(payload, **cases[name])
    status, length, data, fragmented = wire.frame_payload(frame, SERVER, 51820, fragments=wire.Fragments())
    print(status, length, len(data), "fragmented" if fragmented else "whole")
elif cmd == "fragments":
    # One "<case> <result>" per line: the re-review's 241-byte datagram, with
    # S=(64,149,31,55), a transport tag at offset 55 and a response tag at 149,
    # fragmented after 64 payload bytes, and the bookkeeping around it. The
    # clock is injected, so expiry is exact.
    sizes, ranges = wire.parse_layout("64,149,31,55," + sys.argv[3])
    payload = bytearray(b" " * 241)
    payload[:16] = b"OPTIONS sip:u@x "
    payload[55:59] = struct.pack("<I", 400000050)
    payload[149:153] = struct.pack("<I", 200000050)
    whole = struct.pack(">HHHH", 51820, 40000, 249, 0) + bytes(payload)
    now = [0.0]
    frags = wire.Fragments(clock=lambda: now[0])
    def fp(frame):
        return wire.frame_payload(frame, SERVER, 51820, fragments=frags)
    print("complete-datagram", wire.kind_of(bytes(payload), sizes, ranges))
    status, length, data, _ = fp(raw(whole[:72], fragment=0x2000))
    print("first-fragment-record", wire.record_line(sizes, ranges, status, length, data).replace(" ", "_"))
    print("genuine-continuation", fp(raw(whole[72:], fragment=9))[0])
    print("after-completion-same-id", fp(raw(whole[72:], fragment=9))[0])
    fp(raw(whole[:72], ident=8, fragment=0x2000))
    print("same-id-other-destination", fp(raw(whole[72:], ident=8, fragment=9, dst="192.0.2.99"))[0])
    print("in-order-rest", fp(raw(whole[72:], ident=8, fragment=9))[0])
    # Each further case follows a first fragment of its own, so no case's
    # outcome rests on the state another case left behind.
    adverse = (("same-id-offset-8191", b"12345678", 8191), ("overlapping", whole[8:72], 0x2000 | 1),
               ("not-last-odd-length", whole[72:77], 0x2000 | 9), ("last-short", whole[72:200], 9),
               ("duplicate-first", whole[:72], 0x2000))
    for ident, (case, body, fragment) in enumerate(adverse, 12):
        fp(raw(whole[:72], ident=ident, fragment=0x2000))
        print(case, fp(raw(body, ident=ident, fragment=fragment))[0])
    fp(raw(whole[:72], ident=9, fragment=0x2000))
    now[0] = 29.0
    print("within-30s", fp(raw(whole[72:], ident=9, fragment=9))[0])
    fp(raw(whole[:72], ident=10, fragment=0x2000))
    now[0] = 59.5
    print("stale-after-30s", fp(raw(whole[72:], ident=10, fragment=9))[0])
    # A first fragment that carries every eligible tag classifies as usual.
    big = struct.pack(">HHHH", 51820, 40000, 1008, 0) + bytes(payload[:16]) + bytes(39) + struct.pack("<I", 400000050) + bytes(941)
    status, length, data, _ = fp(raw(big[:80], ident=11, fragment=0x2000))
    print("first-fragment-tags-seen", wire.record_line(sizes, ranges, status, length, data).split(" ")[0])
    # The second review's boundary: a 104-byte UDP datagram (96 payload bytes,
    # a shaped transport for S4=45) whose first fragment carries 64 bytes.
    # Each case is "offset:length:more" pieces of it, one status per piece.
    sizes45, ranges45 = wire.parse_layout("64,31,31,45," + sys.argv[3])
    body = bytearray((b"OPTIONS sip:u@x SIP/2.0\r\n" + b" " * 96)[:96])
    body[45:49] = struct.pack("<I", 400000050)
    udp = struct.pack(">HHHH", 51820, 40000, 104, 0) + bytes(body)
    def piece(ident, offset, length, more):
        return fp(raw(udp[offset:offset + length], ident=ident, fragment=(0x2000 if more else 0) | offset // 8))
    def pieces(ident, *specs):
        return ",".join(piece(ident, *spec)[0] for spec in specs)
    print("boundary-nonfinal-at-end", pieces(20, (0, 64, 1), (64, 40, 1)))
    print("boundary-then-last", pieces(20, (64, 40, 0)))
    print("boundary-exact-end", pieces(21, (0, 64, 1), (64, 40, 0)))
    print("boundary-exact-end-again", pieces(21, (64, 40, 0)))
    print("boundary-shorter-nonfinal", pieces(22, (0, 64, 1), (64, 32, 1), (96, 8, 0)))
    print("boundary-out-of-order", pieces(23, (0, 64, 1), (96, 8, 0), (64, 32, 1)))
    print("boundary-out-of-order-again", pieces(23, (64, 32, 1)))
    print("boundary-empty", pieces(25, (0, 64, 1), (64, 0, 1)))
    lines = [wire.record_line(sizes45, ranges45, *piece(24, *spec)[:3]) for spec in ((0, 64, 1), (64, 40, 1))]
    print("boundary-records", "|".join(line.replace(" ", "_") for line in lines if line is not None))
elif cmd == "layout":
    try:
        wire.parse_layout(sys.argv[3])
        print("accepted")
    except wire.InputError:
        print("refused")
elif cmd == "chacha20":
    print(wire.chacha20_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000")).hex())
elif cmd == "recorder":
    # recorder <case>: the record's core (Recorder) on a scripted packet
    # source and scripted clocks, its lines printed with bytes abbreviated.
    import io
    case = sys.argv[3]
    SECOND = 10 ** 9

    class Clocks:
        def __init__(self):
            self.boot_ns, self.real_offset, self.mono_offset = 100 * SECOND, 1_700_000_000 * SECOND, 5 * SECOND

        def sample(self):
            self.boot_ns += 1000
            return wire.ClockSample(self.boot_ns, self.real_offset, 0, self.mono_offset)

        def boot(self):
            self.boot_ns += 1000
            return self.boot_ns

        def sleep(self, nanoseconds):
            self.boot_ns += nanoseconds

    class Source:
        """Frames queued with their kernel stamps; DROPPED counts like
        PACKET_STATISTICS and resets on reading; ENDLESS keeps the queue full."""

        def __init__(self):
            self.queue, self.dropped, self.endless = [], 0, False

        def read(self):
            if self.endless:
                clocks.sleep(10 ** 7)
                return (ipv4(b"x" * 8), None)
            return self.queue.pop(0) if self.queue else None

        def drops(self):
            dropped, self.dropped = self.dropped, 0
            return dropped

    clocks, source, out = Clocks(), Source(), io.StringIO()
    source.dropped = 7  # before the record exists: not its business
    recorder = wire.Recorder(source, clocks, out, {SERVER}, None, 40000, clocks.sample())
    def stamped(payload, before_ns):
        return (ipv4(payload), clocks.boot_ns - before_ns + clocks.real_offset)
    ready = recorder.begin()
    if case == "delayed-ready":
        # Drops after readiness, before the first poll, are reported.
        source.dropped = 993
        clocks.sleep(SECOND)
        recorder.batch(256)
        recorder.poll()
        recorder.finish(clocks.boot())
    elif case == "queued-at-stop":
        # Everything queued when the stop came is read before the end marker.
        source.queue = [stamped(b"p%02d" % i, 2 * SECOND) for i in range(50)]
        recorder.finish(clocks.boot())
    elif case == "dequeue-delay":
        # A frame read 2.2 s after it arrived is recorded at its arrival.
        clocks.sleep(3 * SECOND)
        arrived = clocks.boot_ns - 22 * SECOND // 10
        source.queue = [(ipv4(b"late"), arrived + clocks.real_offset)]
        recorder.batch(256)
        print("arrival-error-cs %d" % (int(out.getvalue().split()[0]) - arrived // 10 ** 7))
        recorder.finish(clocks.boot())
    elif case == "no-stamp":
        clocks.sleep(SECOND)
        source.queue = [(ipv4(b"none"), None)]
        recorder.batch(256)
        recorder.finish(clocks.boot())
    elif case == "clock-step":
        # The realtime clock steps while the frame waits: its stamp no longer
        # converts, so its arrival is the interval it must lie in.
        clocks.sleep(SECOND)
        source.queue = [stamped(b"step", SECOND // 2)]
        clocks.real_offset += 3 * SECOND
        recorder.batch(256)
        recorder.poll()
        recorder.finish(clocks.boot())
    elif case == "suspend":
        clocks.sleep(SECOND)
        clocks.mono_offset += 40 * SECOND
        recorder.poll()
        recorder.finish(clocks.boot())
    elif case == "endless":
        # Traffic that never lets the queue empty: the drain gives up in time.
        source.endless = True
        recorder.finish(clocks.boot())
    print("ready %d" % wire.centiseconds_down(ready.boot))
    for line in out.getvalue().splitlines():
        fields = line.split(" ")
        if len(fields) == 5 and fields[1] != "-":
            fields[4] = "<%d bytes>" % (len(fields[4]) // 2)
        print(" ".join(fields))
PY
}
kinds() { # <capture> <S1,S2,S3,S4>
	"${REAL_PYTHON}" "${WIRE_REAL}" kinds sip "$1" "$2"
}
kinds_rc() { # <capture> <S1,S2,S3,S4>: "<rc> <stdout lines>"
	local OUT RC
	OUT="$(kinds "$1" "$2" 2>/dev/null)"
	RC=$?
	echo "${RC} $(grep -c . <<<"${OUT}")"
}

echo "=== Packet kind from length and type tag ==="
L="29,26,81,22,${H}"
INDEX=0
for KIND in init response cookie transport; do
	INDEX=$((INDEX + 1))
	S="$(cut -d, -f"${INDEX}" <<<"${L}")"
	assert_eq "${KIND}" "$(py kind "${L}" "${KIND}" "${S}" random)" "a ${KIND} with a random S prefix is a ${KIND}"
	assert_eq "${KIND}" "$(py kind "${L}" "${KIND}" "${S}" sip)" "  and with any prefix content: the SIP text is never consulted"
done
assert_eq "transport" "$(py kind "${L}" transport 22 random - 1396)" "a large transport datagram is a transport"
assert_eq "unknown" "$(py kind "${L}" response 26 random 100000050)" "a response-sized datagram with an H1 tag is no kind"
assert_eq "unknown" "$(py kind "${L}" cookie 81 random 999)" "a cookie-sized datagram with a tag in no range is no kind"
assert_eq "unknown" "$(py kind "${L}" response 26 random - 1)" "a response one byte too long is no response"
assert_eq "unknown" "$(py kind "${L}" transport 21 random)" "a datagram shorter than the smallest transport is no kind"
assert_eq "transport" "$(py kind "31,31,31,31,1-4,5-8,9-12,13-16" transport 31 random 14)" "a single-tag or narrow range layout parses"
assert_eq "cookie" "$(py kind "40,40,40,40,${H}" cookie 40 random)" "with equal S sizes a cookie reply is still a cookie"
assert_eq "transport" "$(py kind "40,40,40,40,${H}" transport 40 random - 32)" "  and a transport of the cookie's length is still a transport"
assert_eq "ambiguous" "$(py ambiguous "${H}")" "a datagram that is a response at S2 and a transport at S4 is ambiguous, not dropped"

echo "=== Layout validation ==="
for LAYOUT in "29,26,81,22" "29,26,81,22,${H},5" "x,26,81,22,${H}" "29,26,81,65536,${H}" "29,26,81,-1,${H}" \
	"29,26,81,22,1-10,5-20,30-40,50-60" "29,26,81,22,10-1,20-30,40-50,60-70" "29,26,81,22,1-2,3-4,5-6,4294967296" \
	"029,26,81,22,${H}"; do
	assert_eq "refused" "$(py layout "${LAYOUT}")" "the layout '${LAYOUT}' is refused"
done
assert_eq "accepted" "$(py layout "29,26,81,22,${H}")" "a valid layout is accepted"

echo "=== More than one kind: MAC1 consistency and receiver-index correlation ==="
# Follow-up D: main 2ff94d0's host SIP check failed on a correct server
# (BoringTun Host run 37276248795, Debian 12, S1=99 S2=54 S3=92 S4=52). Its
# one handshake response presumably also fit the transport rule at S4=52,
# two filler bytes and half its tag, and was recorded ambiguous; that
# datagram was not retained, and genuine reproductions show the mechanism.
# A complete datagram that fits more than one kind is resolved in a fixed
# precedence: MAC1-valid handshake readings first; with none, handshake
# readings are removed, and a transport whose receiver index was recorded
# from a MAC1-valid response comes before an unchecked cookie reading; what
# remains otherwise stands. No reading wins by kind order, and none of this
# authenticates a handshake, a session or a transport.
EVIDENCE="$(py evidence)"
evidence_is() { # <case> <expected> <message>
	assert_eq "$2" "$(awk -v c="$1" '$1 == c { print $2 }' <<<"${EVIDENCE}")" "$3"
}
evidence_is genuine-response-without-evidence ambiguous \
	"follow-up D's genuine response fits the response and the transport rule: alone, ambiguous"
evidence_is genuine-response response "  its mac1 holds under the client's key: a response"
evidence_is genuine-ping-reply transport "  and the genuine ping reply after it is a transport"
evidence_is genuine-response-other-key transport \
	"  under another key its mac1 fails and only its transport reading remains: no response is claimed"
evidence_is genuine-record response_146_4f5054494f4e53207369703a6d40766f \
	"  the capture's record path records it as a response, with its prefix"
evidence_is genuine-first-fragment ambiguous "  a first fragment of it is not resolved by evidence, though its tags and mac1 are inside"
evidence_is transport-also-response-without-evidence ambiguous "a transport that also fits the response rule: alone, ambiguous"
evidence_is transport-also-response transport "  the response reading's mac1 is invalid: a transport, with or without a recorded index"
evidence_is session-response response "a MAC1-valid response records the receiver index it names"
evidence_is transport-also-cookie-in-session transport "a transport naming that recorded index that also fits the cookie rule is a transport"
evidence_is transport-also-cookie-other-session ambiguous "  one naming another index stays ambiguous: a cookie reading is never checked"
evidence_is transport-also-cookie-no-session ambiguous "  as does one before any response"
evidence_is forged-response response "a response whose mac1 fails is still a response where it fits no other kind"
evidence_is transport-also-cookie-after-forged-response ambiguous "  but it records no index: a transport naming it stays ambiguous"
evidence_is transport-also-response-and-cookie-in-session transport \
	"a transport naming a recorded index that also fits the response and the cookie rule is a transport"
evidence_is transport-also-response-and-cookie-no-session ambiguous "  without a recorded index it stays ambiguous"
evidence_is response-also-cookie response "a response that also fits the cookie rule is decided by its mac1"
evidence_is forged-response-also-cookie cookie "  if that fails, the cookie reading is all that remains"
evidence_is init-also-transport init "a server initiation that also fits the transport rule is decided by its mac1"
evidence_is forged-init-also-transport transport "  if that fails, the transport reading is all that remains"
evidence_is init-also-response init "an initiation that also fits the response rule: only the initiation's mac1 holds"
evidence_is forged-init-also-response unknown "  when neither mac1 holds it is no kind"
evidence_is two-authentic-readings ambiguous "two MAC1-valid readings (mocked) stay ambiguous: no kind wins by its order"
for KEY in "QZhn3Fgt6SXW24z7epWkvKtUNLJFyqiVehDDDRwUf2g" "QZhn3Fgt6SXW24z7epWkvKtUNLJFyqiVehDDDRwUf2g==" "" "not-a-key" \
	"QZhn3Fgt6SXW24z7epWkvKtUNLJFyqiVehDDDRwUf2g=x" "QZhn3Fgt6SXW24z7epWkvKtUNLJFyqiVehDDDRwUf2-="; do
	assert_eq refused "$(py key "${KEY}")" "the receiver key '${KEY}' is refused"
done
assert_eq "accepted 32" "$(py key "${FIXTURE_KEY}")" "a base64 public key of 32 bytes is accepted"
CAPTURE_ARGS=(capture lo 127.0.0.1 51820 1 "${T}/args.capture" "29,26,81,22,${H}")
"${REAL_PYTHON}" "${WIRE_REAL}" "${CAPTURE_ARGS[@]}" >/dev/null 2>&1
assert_eq 2 "$?" "a capture given a layout without the receiver key is refused (usage)"
"${REAL_PYTHON}" "${WIRE_REAL}" "${CAPTURE_ARGS[@]}" not-a-key >/dev/null 2>&1
assert_eq "1 absent" "$? $(test -e "${T}/args.capture.state" && echo present || echo absent)" \
	"  as is one given a key that is not 32 base64 bytes, before it writes anything"
"${REAL_PYTHON}" "${WIRE_REAL}" capture-to 40001 lo 127.0.0.1 51820 1 "${T}/to.capture" "29,26,81,22,${H}" >/dev/null 2>&1
assert_eq 2 "$?" "capture-to given a layout without the receiver key is refused (usage)"
for PORT in x 0x10 65536 -1 ""; do
	"${REAL_PYTHON}" "${WIRE_REAL}" capture-to "${PORT}" lo 127.0.0.1 51820 1 "${T}/to.capture" >/dev/null 2>&1
	assert_eq "1 absent" "$? $(test -e "${T}/to.capture.state" && echo present || echo absent)" \
		"capture-to refuses the destination port '${PORT}' before it writes anything"
done

echo "=== One client's stream among several behind one address (capture-to) ==="
# Datagrams from the server 192.0.2.1:51820 to two clients behind 192.0.2.2,
# ports 40001 and 40002, through frame_payload as capture-to uses it.
CAPTURE_TO="$("${REAL_PYTHON}" - "${WIRE_REAL}" <<'PY'
import importlib.util, struct, sys
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
SERVER, CLIENT = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])

def frame(dport, payload, ident=1, offset=0, more=False, udp_length=None, body=None):
    if body is None:
        body = struct.pack(">HHHH", 51820, dport, udp_length or 8 + len(payload), 0) + payload
    flags = (0x2000 if more else 0) | (offset // 8)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, flags, 64, 17, 0, SERVER, CLIENT) + body

def status(result):
    return {wire.DATAGRAM: "datagram", wire.IGNORE: "ignore", wire.MALFORMED: "malformed",
            wire.CONTINUATION: "continuation"}[result[0]]

out = []
frags = wire.Fragments()
for dport in (40001, 40002):
    out.append(status(wire.frame_payload(frame(dport, b"x" * 40), SERVER, 51820, destination_port=40001, fragments=frags)))
# A datagram of 1600 bytes to the other client, in two fragments.
first = struct.pack(">HHHH", 51820, 40002, 1608, 0) + b"y" * 1472
out.append(status(wire.frame_payload(frame(0, b"", ident=7, more=True, body=first), SERVER, 51820, destination_port=40001, fragments=frags)))
out.append(status(wire.frame_payload(frame(0, b"", ident=7, offset=1480, body=b"y" * 128), SERVER, 51820, destination_port=40001, fragments=frags)))
# The same later fragment with no first fragment seen is malformed, as before.
out.append(status(wire.frame_payload(frame(0, b"", ident=8, offset=1480, body=b"y" * 128), SERVER, 51820, destination_port=40001, fragments=frags)))
# Without a destination port every client's datagram is relevant, as capture records it.
out.append(status(wire.frame_payload(frame(40002, b"x" * 40), SERVER, 51820, fragments=wire.Fragments())))
print(" ".join(out))
PY
)"
assert_eq "datagram ignore ignore continuation malformed datagram" "${CAPTURE_TO}" \
	"capture-to records its client's datagram, skips the other client's and that one's later fragment, and still flags an orphan fragment"

echo "=== Auto: shaped prefixes, probe replies and the rest (classify-auto) ==="
# Prefixes as a capture without layout records them: a dns-shaped S prefix
# (flags 0x0120, one question), a DNS SERVFAIL reply, a stun-shaped prefix
# (Binding Request, magic cookie), a Binding Success, a QUIC short header, a
# Version Negotiation, a SIP request line, and random bytes.
DNS_S="12340120000100000000000107657861"
DNS_REPLY="12348182000100000000000007657861"
STUN_S="000100002112a442aabbccddeeff0011"
STUN_REPLY="010100302112a442aabbccddeeff0011"
QUIC_S="4f0011223344556677889900aabbccdd"
QUIC_REPLY="80000000000811223344556677880811"
SIP_S="$(printf 'OPTIONS sip:a@b ' | od -An -tx1 | tr -d ' \n')"
RANDOM_S="9c3e5f17a20b44d1e8c0f7a6b5d4c3b2"
printf '%s\n' "${DNS_S}" "${DNS_S}" "${DNS_REPLY}" >"${T}/auto-dns"
printf '%s\n' "${STUN_S}" "${STUN_REPLY}" "${STUN_REPLY}" "${RANDOM_S}" >"${T}/auto-stun"
printf '%s\n' "${QUIC_S}" "${QUIC_REPLY}" >"${T}/auto-quic"
printf '%s\n' "${SIP_S}" "${RANDOM_S}" >"${T}/auto-sip"
printf '%s\n' "${RANDOM_S}" "${RANDOM_S}" "${QUIC_S}" >"${T}/auto-none"
printf '%s\n' "${RANDOM_S}" "${DNS_S}" "${STUN_S}" "${SIP_S}" >"${T}/auto-none-shaped"
for CASE in "dns auto-dns 3 2 1 0" "stun auto-stun 4 1 2 1" "quic auto-quic 2 1 1 0" "sip auto-sip 2 1 0 1" \
	"none auto-none 3 0 0 3" "none auto-none-shaped 4 3 0 1" "dns auto-stun 4 0 0 4"; do
	read -r PROTOCOL FILE WANT <<<"${CASE}"
	assert_eq "${WANT}" "$("${REAL_PYTHON}" "${WIRE_REAL}" classify-auto "${PROTOCOL}" "${T}/${FILE}" 2>&1)" \
		"classify-auto ${PROTOCOL} on ${FILE}: datagrams, shaped, probe replies, other"
done
printf '%s\n' "${DNS_S}" "response 124 -" >"${T}/auto-mixed"
"${REAL_PYTHON}" "${WIRE_REAL}" classify-auto dns "${T}/auto-mixed" >/dev/null 2>&1
assert_eq 1 "$?" "classify-auto refuses a per-kind record, as classify does"
"${REAL_PYTHON}" "${WIRE_REAL}" classify-auto auto "${T}/auto-dns" >/dev/null 2>&1
assert_eq 1 "$?" "classify-auto has no classification for auto itself"
"${REAL_PYTHON}" "${WIRE_REAL}" send sip 127.0.0.1 9 70000 >/dev/null 2>&1
assert_eq 1 "$?" "send refuses a source port beyond 65535"
SEND_PORT=$((30000 + RANDOM % 20000))
SENT="$("${REAL_PYTHON}" - "${WIRE_REAL}" "${SEND_PORT}" <<'PY'
import socket, subprocess, sys
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(("127.0.0.1", 0))
listener.settimeout(5)
out = subprocess.run([sys.executable, sys.argv[1], "send", "sip", "127.0.0.1", str(listener.getsockname()[1]), sys.argv[2]],
                     capture_output=True, text=True)
data, source = listener.recvfrom(65535)
print(out.returncode, out.stdout.strip(), source[1] == int(sys.argv[2]), data == b"OPTIONS sip:a@b SIP/2.0\r\n\r\n")
PY
)"
assert_eq "0 sent 27 True True" "${SENT}" \
	"send sends the 27-byte SIP request line from the given source port, shorter than any AmneziaWG datagram, and says so"
"${REAL_PYTHON}" "${WIRE_REAL}" send dns 127.0.0.1 9 40000 >/dev/null 2>&1
assert_eq 2 "$?" "send plants only the hints it knows to be no AmneziaWG datagram (usage)"

echo "=== Which planted datagram the server can take for AmneziaWG (candidates) ==="
# The S sizes of the BoringTun Host job whose planted 247-byte SIP probe was
# not learned (run 37615364152), with an H4 that holds the probe's bytes at
# S4 = 37, and with one that does not.
H_LOW="100000001-100000100,200000001-200000100,300000001-300000100"
COLLIDING="27,113,125,37,${H_LOW},1767000000-1866999999"
CLEAR="27,113,125,37,${H_LOW},1900000000-1999999999"
# Every u32 in some H range, every S at 0, and H4 holding the probe's first
# four bytes ("OPTI", 1230262351): the widest a layout can be.
EVERYTHING="0,0,0,0,0-1073741823,2147483648-3221225471,3221225472-4294967295,1073741824-2147483647"
for CASE in "probe ${COLLIDING} 247 transport" "probe ${CLEAR} 247 none" "send ${COLLIDING} 27 none" "send ${CLEAR} 27 none" \
	"send ${EVERYTHING} 27 none" "probe ${EVERYTHING} 247 transport"; do
	read -r SOURCE LAYOUT WANT_LENGTH WANT_KINDS <<<"${CASE}"
	assert_eq "${WANT_LENGTH} ${WANT_KINDS}" "$("${REAL_PYTHON}" "${WIRE_REAL}" candidates "${SOURCE}" sip "${LAYOUT}" 2>&1)" \
		"candidates: the ${SOURCE} sip datagram under ${LAYOUT%%,1*}… fits: ${WANT_KINDS}"
done
"${REAL_PYTHON}" "${WIRE_REAL}" candidates send dns "${CLEAR}" >/dev/null 2>&1
assert_eq 2 "$?" "candidates knows only the datagrams send and probe send (usage)"

echo "=== Auto: what the server can learn, from what reached it (detect, inbound_candidates, auto-expect) ==="
# The pre-initiation datagrams of real BoringTun clients (the published
# b94943906b11 binary, --imitate-protocol dns, quic, sip and stun), recorded
# whole on the server's side under S1-S4 40 and narrow H ranges: imitation
# datagrams and Jc junk, public bytes only.
PRELUDES="${SCRIPT_DIR}/fixtures/boringtun-auto-preludes"
# Upstream's own detection vectors (noise/imitation/detect.rs tests), and the
# recorded preludes: what each is detected as.
DETECTED="$("${REAL_PYTHON}" - "${WIRE_REAL}" "${PRELUDES}" <<'PY'
import importlib.util, struct, sys
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
def dns_query(txid):
    return bytes([txid[0], txid[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]) + b"\x07example\x03com\x00" + bytes([0, 1, 0, 1])
stun = b"\x00\x01\x00\x00" + bytes.fromhex("2112a442") + b"\xab" * 12
quic = bytes([0xC3]) + struct.pack(">I", 1) + bytes([4, 1, 2, 3, 4, 0]) + bytes(16)
def version(value):
    return quic[:1] + struct.pack(">I", value) + quic[5:]
bad_stun = bytearray(stun); bad_stun[3] = 4
q0 = bytearray(dns_query(b"\x01\x02")); q0[5] = 0
q1 = bytearray(dns_query(b"\x01\x02")); q1[12] = 0xC0
q2 = bytearray(dns_query(b"\x01\x02")); q2[-1] = 9
cases = [("dns query", dns_query(b"\x12\x34")), ("dns query, txid c0", dns_query(b"\xc0\x34")),
         ("dns query, txid ff", dns_query(b"\xff\x34")), ("stun binding request", stun), ("quic v1 initial", quic),
         ("INVITE", b"INVITE sip:a@b SIP/2.0\r\n\r\n"), ("OPTIONS", b"OPTIONS sip:a@b SIP/2.0\r\n\r\n"),
         ("sip/2.0 response", b"sip/2.0 100 Trying\r\n\r\n"), ("BYE with a multibyte name", b"BYE sip:x\xc3\xa4@b SIP/2.0\r\n\r\n"),
         ("SUBSCRIBE", b"SUBSCRIBE \xc3\xa4 SIP/2.0\r\n\r\n"), ("empty", b""), ("one byte", b"\x00"), ("six c0", b"\xc0" * 6),
         ("quic draft 0", version(0xFF000000)), ("quic draft 1", version(0xFF000001)), ("quic grease", version(0x1A2A3A4A)),
         ("quic version 2 (unassigned)", version(2)), ("stun with a wrong length", bytes(bad_stun)),
         ("dns, no question", bytes(q0)), ("dns, compressed name", bytes(q1)), ("dns, bad qclass", bytes(q2)),
         ("dns, cut short", dns_query(b"\x01\x02")[:14])]
for name, data in cases:
    print("%s: %s" % (name, wire.detect(data)))
for protocol in ("dns", "quic", "sip", "stun"):
    found = [wire.detect(bytes.fromhex(line)) for line in open("%s/%s.hex" % (sys.argv[2], protocol)).read().split()]
    print("recorded %s prelude: %s" % (protocol, " ".join(str(item) for item in found)))
PY
)"
assert_eq "dns query: dns
dns query, txid c0: dns
dns query, txid ff: dns
stun binding request: stun
quic v1 initial: quic
INVITE: sip
OPTIONS: sip
sip/2.0 response: sip
BYE with a multibyte name: sip
SUBSCRIBE: sip
empty: None
one byte: None
six c0: None
quic draft 0: None
quic draft 1: quic
quic grease: quic
quic version 2 (unassigned): None
stun with a wrong length: None
dns, no question: None
dns, compressed name: None
dns, bad qclass: None
dns, cut short: None
recorded dns prelude: dns dns dns dns dns dns
recorded quic prelude: quic quic None None
recorded sip prelude: sip sip sip sip sip
recorded stun prelude: stun stun None None None" "${DETECTED}" \
	"detect: upstream's own vectors, and what real clients send before their initiation (Jc junk aside, two QUIC datagrams carry a v1 connection ID over 20 bytes, which upstream does not take for QUIC)"

assert_eq "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e" \
	"$(py chacha20 2>&1)" "the header-protection keystream's ChaCha20 block is RFC 8439's (section 2.3.2 test vector)"

# auto-expect over synthetic records: the datagrams that reached the server
# (initiations carry a mac1 computed here, as WireGuard defines it, under the
# server's public key), each with its arrival clock, and the scenario's
# evidence: when each client process started and when it first pinged
# through the tunnel (an establishment), and, where a case says so, when a
# connected socket to the client was seen. CASE names what it builds; the
# helper's verdict is compared with what upstream's rules give for every
# history that evidence allows, worked out in the comment of each case.
STUN_CLEAR="110,57,133,36,66166068-166166067,862271148-962271147,1349667297-1449667296,2030000000-2129999999"
auto_case() { # <case> [<epoch> <window start> <window end>]
	"${REAL_PYTHON}" - "${WIRE_REAL}" "${PRELUDES}" "${T}/auto-record" "$@" <<'PY'
import base64, contextlib, hashlib, importlib.util, io, os, struct, sys
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
preludes, path, case = sys.argv[2], sys.argv[3], sys.argv[4]
SERVER = bytes(range(32, 64))
HP = bytes(range(64, 96))
with open(path + ".hp", "w") as key:
    key.write(base64.b64encode(HP).decode() + "\n")
COLLIDING = "110,57,133,36,66166068-166166067,862271148-962271147,1349667297-1449667296,1917290954-2017290953"
CLEAR = "110,57,133,36,66166068-166166067,862271148-962271147,1349667297-1449667296,2030000000-2129999999"
NARROW = "40,40,40,40,100000001-100000100,200000001-200000100,300000001-300000100,400000001-400000100"
SHORT = "20,24,28,30,100000001-100000100,200000001-200000100,300000001-300000100,400000001-400000100"
def recorded(protocol):
    return [bytes.fromhex(line) for line in open("%s/%s.hex" % (preludes, protocol)).read().split()]
def mask(datagram, offset, length, hp):
    if not hp:
        return datagram
    stream = wire.hp_keystream(HP, datagram, length)
    return datagram[:offset] + bytes(a ^ b for a, b in zip(datagram[offset:offset + length], stream)) + datagram[offset + length:]
def initiation(prefix=None, valid=True):
    """An init candidate whose mac1 is consistent with the server's key (or
    not): what a client sends, and what anyone who knows the key can forge."""
    sizes, ranges = wire.parse_layout(layout)
    body = struct.pack("<II", ranges[0][0] + 7, 0x01020304) + os.urandom(108)
    mac = hashlib.blake2s(body, digest_size=16, key=hashlib.blake2s(b"mac1----" + SERVER).digest()).digest()
    if not valid:
        mac = bytes(b ^ 1 for b in mac)
    head = (prefix or b"")[:sizes[0]] + os.urandom(max(0, sizes[0] - len(prefix or b"")))
    return mask(head + body + mac + bytes(16), sizes[0], 148, hp)
def transport(counter=0):
    sizes, ranges = wire.parse_layout(layout)
    datagram = os.urandom(sizes[3]) + struct.pack("<IIQ", ranges[3][0] + 9, 0x0A0B0C0D, counter) + os.urandom(48)
    return mask(datagram, sizes[3], 16, hp)
SIP_HINT = b"OPTIONS sip:a@b SIP/2.0\r\n\r\n"
A, OTHER = "192.0.2.2", "192.0.2.9"
lines = []
def add(clock, data, address=A, port=41006):
    lines.append("%s %s %d %d %s" % (clock, address, port, len(data), data.hex() or "-"))
def sequence(start, datagrams, address=A, port=41006):
    for index, data in enumerate(datagrams):
        add(start + index, data, address, port)
ready, epoch, window = 1000, 1500, (1900, 20000)
layout, hp, connected = CLEAR, False, "-"
# A client process started at 1995 and pinged through the tunnel at 2040,
# unless a case says otherwise.
est = [(1995, 2040)]
if case == "stun-colliding":
    # Both STUN requests are transport candidates under H4 (their bytes at 36
    # are in it), the junk is detected as nothing: no hint; the initiation's
    # random S1 prefix is no protocol either. Unresolved: random.
    layout = COLLIDING
    sequence(2000, recorded("stun") + [initiation(), transport()])
elif case == "stun-clear":
    # Only H4 differs: the first STUN request is the hint, at most 0.41 s old
    # when the initiation the client's ping proves was processed: stun.
    sequence(2000, recorded("stun") + [initiation(), transport()])
elif case == "other-port":
    # The same sequence from another port of the same address leaves a hint
    # for that port only.
    sequence(2000, recorded("stun"), port=41007)
    sequence(2010, [initiation(), transport()])
elif case == "other-address":
    sequence(2000, recorded("stun"), address=OTHER)
    sequence(2010, [initiation(), transport()])
elif case in ("age-28", "age-32", "age-30"):
    # A hint planted at 2000, the client 28, 30.2 or 32 s later. At most 28.31
    # s old when the initiation was processed (by its ping): live, sip. Older,
    # nothing bounds when the server processed the hint, which may have come
    # to it as late as the initiation: undecided, never random by arrival
    # times alone.
    add(2000, SIP_HINT)
    at = 2000 + {"age-28": 2800, "age-30": 3020, "age-32": 3200}[case]
    est = [(at - 10, at + 30)]
    sequence(at, [initiation(), transport()])
elif case == "first-hint-wins":
    # The first detected protocol per source stays while it lives.
    sequence(2000, [recorded("quic")[0], SIP_HINT, initiation(), transport()])
elif case == "from-initiation":
    # No hint: detect over the initiation datagram, whose S1 prefix is a DNS
    # query here, selects dns.
    layout = NARROW
    query = bytes([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]) + b"\x16" + b"a" * 22 + b"\x00\x00\x01\x00\x01"
    sequence(2000, [initiation(prefix=query), transport()])
elif case == "hp-sip-large":
    # Header protection with an S of 31 bytes or more refuses sip.
    layout, hp = NARROW, True
    sequence(2000, [SIP_HINT, initiation(), transport()])
elif case == "hp-sip-small":
    # With every S of 12 to 30 bytes, sip is kept.
    layout, hp = SHORT, True
    sequence(2000, [SIP_HINT, initiation(), transport()])
elif case == "hp-unmasked-initiation":
    # Under header protection an unmasked initiation fits no kind.
    layout, hp = NARROW, True
    hp = False
    datagrams = [SIP_HINT, initiation()]
    hp = True
    sequence(2000, datagrams + [transport()])
elif case == "no-initiation":
    sequence(2000, [SIP_HINT, initiation(valid=False), transport()])
elif case in ("policy-retry", "policy-retry-connected"):
    # Finding 1 (the review's counterexample): AWG 3.0, S 40. A SIP hint, a
    # client without imitation whose initiation the server accepts and whose
    # sip the policy refuses; the client restarts on the same port with DNS
    # imitation. Its DNS queries reach either the listener, where the refused
    # SIP hint still holds the slot (random), or the connected socket the
    # first session opened, whose tunnel takes the first query as its hint
    # (dns): undecided. With the connected socket seen at 2300, before the
    # second client, every later datagram reached it: dns.
    layout, hp = NARROW, True
    add(2000, SIP_HINT)
    sequence(2050, [initiation(), transport(), transport(1)])
    sequence(2381, recorded("dns") + [initiation(), transport(), transport(1)])
    est = [(1990, 2080), (2380, 2470)]
    window = (2480, 3000)
    if case == "policy-retry-connected":
        connected = "2300"
elif case == "forgery":
    # Finding 2 (the review's counterexample): a STUN hint, an initiation
    # whose mac1 is consistent with the server's key but that no Noise
    # handshake accepts, and a transport candidate with a low counter; 32 s
    # later a SIP hint and the real client. Syntax proves neither acceptance:
    # if the forgery was accepted, stun; if not, the STUN hint may or may not
    # have expired when the SIP hint came (stun or sip): undecided.
    layout = NARROW
    sequence(2000, [recorded("stun")[0], initiation(), transport(1)])
    add(5250, SIP_HINT)
    sequence(5300, [initiation(), transport()])
    est = [(5260, 5340)]
    window = (5250, 6000)
elif case in ("gap-full", "gap-hidden", "gap-before-epoch", "gap-after-pin"):
    # Finding 3 (the review's counterexample): a real STUN session, then 32 s
    # later the same peer reconnects with a SIP hint; the server keeps the
    # stun it learned. With the first session recorded: stun. With it
    # replaced by the record's drop interval: undecided, since the hidden
    # frames may hold a session that pinned the peer. A drop interval before
    # the epoch, or one that came after the selection was certainly pinned,
    # cannot change it: stun.
    layout = NARROW
    first = recorded("stun") + [initiation(), transport(), transport(1)]
    if case == "gap-hidden":
        lines.append("2060 - drops %d 1996" % len(first))
    else:
        sequence(2000, first)
    if case == "gap-before-epoch":
        lines.insert(0, "1450 - drops 30 1400")
    if case == "gap-after-pin":
        lines.append("3100 - drops 12 3000")
    add(5210, SIP_HINT)
    sequence(5250, [initiation(), transport()])
    est = [(1995, 2050), (5200, 5290)]
    window = (5300, 6000)
elif case in ("timing-fresh", "timing-paused", "timing-untimed", "timing-untimed-fresh", "timing-step"):
    # Finding 4: a SIP hint, then the client. Fresh (the client 3 s later):
    # sip. The review's pause, recorded at the arrival times it really had
    # (32 s apart): undecided, since nothing bounds when the server processed
    # the hint. A hint the record bounds only by an interval: sip while even
    # its earliest arrival is under 30 s before the initiation was processed,
    # undecided when it reaches further back. A clock step: undecided.
    layout = NARROW
    at = 5300 if case in ("timing-paused", "timing-untimed") else 2300
    if case in ("timing-untimed", "timing-untimed-fresh"):
        lines.append("1990~%d %s 41006 %d %s" % (at - 1, A, len(SIP_HINT), SIP_HINT.hex()))
    else:
        add(2000, SIP_HINT)
    sequence(at, [initiation(), transport()])
    if case == "timing-step":
        lines.append("2310 - clock-step 2250")
    est = [(at - 10, at + 40)]
    window = (at - 20, at + 1000)
elif case == "malformed":
    # A frame whose datagram is unknown, while it could have been the hint.
    sequence(2000, [SIP_HINT, initiation(), transport()])
    lines.insert(1, "2000 %s - malformed 28 4500001c" % A)
elif case == "malformed-other-address":
    sequence(2000, [SIP_HINT, initiation(), transport()])
    lines.insert(1, "2000 %s - malformed 28 4500001c" % OTHER)
elif case == "malformed-early":
    # Long before the client: its port, and so whether it holds a session of
    # this peer or a hint, is unknown: undecided.
    lines.append("1600 %s - malformed 28 4500001c" % A)
    sequence(4800, [SIP_HINT, initiation(), transport()])
    est = [(4790, 4840)]
elif case == "malformed-after-pin":
    sequence(2000, [SIP_HINT, initiation(), transport()])
    lines.append("2500 %s - malformed 28 4500001c" % A)
elif case == "drops-during":
    sequence(2000, [SIP_HINT, initiation(), transport()])
    lines.insert(1, "2000 - drops 3 1990")
elif case == "fragment":
    sequence(2000, [SIP_HINT, initiation(), transport()])
    lines.insert(1, "2000 %s 41006 fragment 1400" % A)
elif case == "fragment-other-port":
    sequence(2000, [SIP_HINT, initiation(), transport()])
    lines.insert(1, "2000 %s 41007 fragment 1400" % A)
elif case == "late-record":
    ready = 2500
    sequence(3000, [SIP_HINT, initiation(), transport()])
    est = [(2995, 3040)]
elif case == "straddles-epoch":
    lines.append("1400~1600 %s 41006 %d %s" % (A, len(SIP_HINT), SIP_HINT.hex()))
    sequence(2000, [initiation(), transport()])
elif case in ("retry", "retry-window-after"):
    # An initiation without a hint, then a SIP hint and a second initiation,
    # then the client's ping. Either may be the one the server answered: if
    # only the first, random; if the second, sip: undecided, also over a
    # window after the ping.
    sequence(2000, [initiation()])
    sequence(2600, [SIP_HINT, initiation(), transport()])
    est = [(1995, 2640)]
    if case == "retry-window-after":
        window = (2700, 20000)
elif case == "no-establishment":
    # Without the client's evidence nothing bounds when anything was
    # processed, or whether the initiation was accepted.
    sequence(2000, [SIP_HINT, initiation(), transport()])
    est = []
else:
    raise SystemExit("no case " + case)
# Complete through a cutoff after every window these cases use.
lines.append("99999 - complete 99998")
with open(path, "w") as out:
    out.write("".join(line + "\n" for line in lines))
with open(path + ".state", "w") as state:
    state.write("ready 1 1 %d\nstopped %d %s\n" % (ready, len(lines), "0" * 32))
args = sys.argv[5:]
if args:
    epoch, window = int(args[0]), (int(args[1]), int(args[2]))
argv = ["auto-expect", path, A, "41006", layout, base64.b64encode(SERVER).decode(), path + ".hp" if hp else "-", "off",
        str(epoch), str(window[0]), str(window[1]), ",".join("%d:%d" % pair for pair in est) or "-", connected]
buffer = io.StringIO()
with contextlib.redirect_stdout(buffer):
    status = wire.main(argv)
print("%d %s" % (status, buffer.getvalue().splitlines()[-1] if buffer.getvalue() else "-"))
PY
}
for CASE in "stun-colliding|0 expect random" "stun-clear|0 expect stun" "other-port|0 expect random" \
	"other-address|0 expect random" "age-28|0 expect sip" "first-hint-wins|0 expect quic" "from-initiation|0 expect dns" \
	"hp-sip-large|0 expect random" "hp-sip-small|0 expect sip" "policy-retry-connected|0 expect dns" \
	"gap-full|0 expect stun" "gap-before-epoch|0 expect stun" "gap-after-pin|0 expect stun" "timing-fresh|0 expect sip" "timing-untimed-fresh|0 expect sip" \
	"malformed-other-address|0 expect sip" "malformed-after-pin|0 expect sip" "fragment-other-port|0 expect sip"; do
	assert_eq "${CASE#*|}" "$(auto_case "${CASE%%|*}" 2>&1)" "auto-expect, ${CASE%%|*}: ${CASE#*|}"
done
for CASE in age-30 age-32 hp-unmasked-initiation no-initiation policy-retry forgery gap-hidden timing-paused timing-untimed \
	timing-step malformed malformed-early drops-during fragment late-record straddles-epoch retry retry-window-after \
	no-establishment; do
	GOT="$(auto_case "${CASE}" 2>&1)"
	assert_true "auto-expect, ${CASE}: undecided, exit 1, never a guess (${GOT})" bash -c '[[ "$1" == "1 undecided "* ]]' _ "${GOT}"
done
GOT="$(auto_case stun-clear 1500 1900 1950 2>&1)"
assert_true "auto-expect, a window that ends before any initiation: undecided (${GOT})" \
	bash -c '[[ "$1" == "1 undecided no initiation"* ]]' _ "${GOT}"
printf '1000 192.0.2.2 41006 3 abcd\n' >"${T}/bad-record"
printf 'ready 1 1 900\nstopped 1 %s\n' "$(printf '0%.0s' {1..32})" >"${T}/bad-record.state"
"${REAL_PYTHON}" "${WIRE_REAL}" auto-expect "${T}/bad-record" 192.0.2.2 41006 "${STUN_CLEAR}" "${FIXTURE_KEY}" - off 1000 1000 2000 >/dev/null 2>&1
assert_eq 1 "$?" "auto-expect refuses a record whose length is not that of its bytes"
printf '1000 192.0.2.2 41006 2 abcd\n3000 - complete 2999\n1001 192.0.2.2 41006 2 abcd\n' >"${T}/bad-record"
printf 'ready 1 1 900\nstopped 3 %s\n' "$(printf '0%.0s' {1..32})" >"${T}/bad-record.state"
"${REAL_PYTHON}" "${WIRE_REAL}" auto-expect "${T}/bad-record" 192.0.2.2 41006 "${STUN_CLEAR}" "${FIXTURE_KEY}" - off 1000 1000 2000 >/dev/null 2>&1
assert_eq 1 "$?" "auto-expect refuses a record with a line after its end marker"
for END in "" "3000 - incomplete 2999" "1900 - complete 1899"; do
	{ printf '1000 192.0.2.2 41006 2 abcd\n'; [[ -z "${END}" ]] || printf '%s\n' "${END}"; } >"${T}/bad-record"
	printf 'ready 1 1 900\nstopped %d %s\n' "$((${END:+1} + 1))" "$(printf '0%.0s' {1..32})" >"${T}/bad-record.state"
	GOT="$("${REAL_PYTHON}" "${WIRE_REAL}" auto-expect "${T}/bad-record" 192.0.2.2 41006 "${STUN_CLEAR}" "${FIXTURE_KEY}" - off 1000 1000 2000 2>&1)"
	assert_true "auto-expect: a record ${END:+ending '${END}'}${END:-without an end marker} is not complete through the window: undecided (${GOT##*$'\n'})" \
		bash -c '[[ "$1" == "undecided the record is not complete through"* ]]' _ "${GOT##*$'\n'}"
done
printf '1000 192.0.2.2 41006 2 abcd\n' >"${T}/bad-record"
printf 'ready 1 1 900\nstopped 2 %s\n' "$(printf '0%.0s' {1..32})" >"${T}/bad-record.state"
"${REAL_PYTHON}" "${WIRE_REAL}" auto-expect "${T}/bad-record" 192.0.2.2 41006 "${STUN_CLEAR}" "${FIXTURE_KEY}" - off 1000 1000 2000 >/dev/null 2>&1
assert_eq 1 "$?" "auto-expect refuses a record whose transcript does not count its records"
printf 'ready 1 1 900\n' >"${T}/bad-record.state"
"${REAL_PYTHON}" "${WIRE_REAL}" auto-expect "${T}/bad-record" 192.0.2.2 41006 "${STUN_CLEAR}" "${FIXTURE_KEY}" - off 1000 1000 2000 >/dev/null 2>&1
assert_eq 1 "$?" "auto-expect refuses a record that has not ended"
echo "=== The record's completeness and arrival times (Recorder, on a scripted socket and clocks) ==="
# The packet socket and the clocks are scripted (py recorder); the record's
# core is the helper's own. The socket's clock is 100 s after boot when it is
# created; frames come from 192.0.2.1 to port 40000.
for CASE in delayed-ready queued-at-stop dequeue-delay no-stamp clock-step suspend endless; do
	py recorder "${CASE}" >"${T}/recorder-${CASE}" 2>&1
done
assert_true "the drop counters' baseline comes before readiness: 993 drops after it, before the first poll, are reported, the 7 before the record existed are not ($(grep -c ' drops ' "${T}/recorder-delayed-ready"))" \
	bash -c 'grep -qE "^[0-9]+ - drops 993 [0-9]+$" "$1" && ! grep -q " drops 7 " "$1" && [[ "$(tail -n 1 "$1")" =~ \ -\ complete\ [0-9]+$ ]]' _ "${T}/recorder-delayed-ready"
assert_true "a stop drains the queue: all 50 queued frames are recorded before the complete marker ($(grep -c '<3 bytes>' "${T}/recorder-queued-at-stop"))" \
	bash -c '[[ "$(grep -c "<3 bytes>" "$1")" == 50 && "$(tail -n 1 "$1")" =~ \ -\ complete\ [0-9]+$ ]]' _ "${T}/recorder-queued-at-stop"
assert_true "a frame read 2.2 s after it arrived is recorded at its kernel arrival time, not when it was read ($(grep arrival-error "${T}/recorder-dequeue-delay"))" \
	bash -c 'grep -qx "arrival-error-cs 0" "$1"' _ "${T}/recorder-dequeue-delay"
assert_true "a frame without a kernel stamp is recorded with the interval it must have arrived in ($(grep '<4 bytes>' "${T}/recorder-no-stamp"))" \
	bash -c 'grep -qE "^[0-9]+~[0-9]+ 192\.0\.2\.1 51820 4 <4 bytes>$" "$1"' _ "${T}/recorder-no-stamp"
assert_true "a realtime step while a frame waits: its stamp is not converted, it gets its interval, and the step is marked ($(grep -c clock-step "${T}/recorder-clock-step"))" \
	bash -c 'grep -qE "^[0-9]+~[0-9]+ 192\.0\.2\.1 51820 4 <4 bytes>$" "$1" && grep -qE "^[0-9]+ - clock-step [0-9]+$" "$1"' _ "${T}/recorder-clock-step"
assert_true "a suspend (boottime moving against monotonic, the server's clock) is marked as a clock step" \
	bash -c 'grep -qE "^[0-9]+ - clock-step [0-9]+$" "$1"' _ "${T}/recorder-suspend"
assert_true "traffic that never lets the queue empty: the drain gives up within its budget and the record ends incomplete ($(tail -n 1 "${T}/recorder-endless"))" \
	bash -c '[[ "$(tail -n 1 "$1")" =~ \ -\ incomplete\ [0-9]+$ ]]' _ "${T}/recorder-endless"

echo "=== IPv4/UDP framing before payload ==="
assert_eq "datagram 77 77 whole" "$(py frame valid)" "a valid frame yields its UDP payload"
assert_eq "datagram 77 77 whole" "$(py frame padded)" "  bounded by the IPv4 total length, not the frame"
for CASE in udp-length-8 udp-length-long ip-total-28 ip-total-long ipv6-version ihl-4 orphan-fragment first-fragment-short \
	first-fragment-odd short-header; do
	assert_eq "malformed" "$(py frame "${CASE}" | cut -d' ' -f1)" "a relevant frame with ${CASE} is malformed, never payload"
done
assert_eq "datagram 77 77 whole" "$(py frame ihl-6)" "IPv4 options are skipped by the header length"
assert_eq "datagram 992 72 fragmented" "$(py frame first-fragment)" "a first fragment yields the declared length and the bytes it carries"
for CASE in other-source other-port icmp; do
	assert_eq "ignore" "$(py frame "${CASE}" | cut -d' ' -f1)" "a frame from ${CASE} is not relevant (addressing alone)"
done

echo "=== Fragments: no unique kind from unseen bytes, continuations only where they fit ==="
FRAGMENTS="$(py fragments "${H}")"
fragment_case() { # <case>
	sed -n "s/^$1 //p" <<<"${FRAGMENTS}"
}
assert_eq "ambiguous" "$(fragment_case complete-datagram)" "the complete 241-byte datagram is ambiguous (transport at 55, response at 149)"
assert_eq "unresolved_241_-" "$(fragment_case first-fragment-record)" \
	"its 64-byte first fragment, which hides the response tag, is recorded unresolved, not transport"
assert_eq "continuation" "$(fragment_case genuine-continuation)" "its genuine later fragment is a continuation"
assert_eq "malformed" "$(fragment_case after-completion-same-id)" "after the datagram is complete, the same IP ID names nothing"
assert_eq "malformed" "$(fragment_case same-id-other-destination)" "a fragment with the same IP ID to another destination is malformed"
assert_eq "continuation" "$(fragment_case in-order-rest)" "  while the right later fragment still continues it"
assert_eq "malformed" "$(fragment_case same-id-offset-8191)" "a fragment with the same IP ID at offset 8191, outside the datagram, is malformed"
assert_eq "malformed" "$(fragment_case overlapping)" "a fragment overlapping bytes already seen is malformed"
assert_eq "malformed" "$(fragment_case not-last-odd-length)" "a fragment that is not the last but carries no multiple of 8 bytes is malformed"
assert_eq "malformed" "$(fragment_case last-short)" "a last fragment that does not end the datagram is malformed"
assert_eq "malformed" "$(fragment_case duplicate-first)" "a second first fragment while one is in progress is malformed"
assert_eq "continuation" "$(fragment_case within-30s)" "a later fragment 29 s after its first fragment continues it"
assert_eq "malformed" "$(fragment_case stale-after-30s)" "one 30.5 s after its first fragment finds that state expired and is malformed"
assert_eq "transport" "$(fragment_case first-fragment-tags-seen)" "a first fragment that carries every eligible tag is classified as usual"
printf '%s\n' "$(fragment_case first-fragment-record | tr '_' ' ')" >"${T}/fragment-record"
# A fragment that says more follow must leave room for them: under the
# declared length, one that reaches the end with More Fragments set
# contradicts itself. Only the last fragment can end the payload, so an entry
# is retired with it, in whatever order the fragments come.
assert_eq "datagram,malformed" "$(fragment_case boundary-nonfinal-at-end)" \
	"a non-final fragment that reaches the declared end (64 of 104 bytes, then 40 with More Fragments) is malformed"
assert_eq "continuation" "$(fragment_case boundary-then-last)" "  while the right last fragment still ends that datagram"
assert_eq "datagram,continuation" "$(fragment_case boundary-exact-end)" "a last fragment that ends the declared payload exactly continues it"
assert_eq "malformed" "$(fragment_case boundary-exact-end-again)" "  and completes it: the same IP ID then names nothing"
assert_eq "datagram,continuation,continuation" "$(fragment_case boundary-shorter-nonfinal)" \
	"a shorter non-final fragment, then the last one, continue it"
assert_eq "datagram,continuation,continuation" "$(fragment_case boundary-out-of-order)" \
	"the last fragment before the middle one continues it as well"
assert_eq "malformed" "$(fragment_case boundary-out-of-order-again)" "  and the middle one completes it out of order"
assert_eq "datagram,malformed" "$(fragment_case boundary-empty)" "a later fragment that carries nothing is malformed"
fragment_case boundary-records | tr '|_' '\n ' >"${T}/boundary-records"
assert_eq "transport 96 malformed 60" "$(cut -d' ' -f1,2 "${T}/boundary-records" | tr '\n' ' ' | sed 's/ $//')" \
	"the real helper records that contradictory observation: the transport's first fragment, and a malformed frame"

echo "=== The recorded follow-up C failure ==="
# S2=26 S3=81 S4=22: handshake responses and transport, no cookie reply, 0/2054 shaped.
py record "${L}" "${T}/recorded" response:2:random transport:2052:random
POOLED_DEMAND=no
for S in 26 81 22; do ((S >= 31)) && POOLED_DEMAND=yes; done
assert_eq "init 0 0 random unobserved
response 2 0 random ok
cookie 0 0 shaped unobserved
transport 2052 0 random ok
unknown 0
ambiguous 0
unresolved 0
malformed 0" "$(kinds "${T}/recorded" 29,26,81,22)" \
	"the per-kind oracle passes it: responses and transport random as S2 and S4 say, no cookie reply seen"
assert_eq "yes 0" "${POOLED_DEMAND} $(kinds "${T}/recorded" 29,26,81,22 | awk 'NF == 5 { s += $3 } END { print s + 0 }')" \
	"the pooled oracle demands a request line (max S2-S4 is 81) and finds none: its expectation is false"
py record "${L}" "${T}/recorded-cookies" response:2:random cookie:150:sip transport:300:random
assert_eq "cookie 150 150 shaped ok" "$(kinds "${T}/recorded-cookies" 29,26,81,22 | grep '^cookie ')" \
	"with cookie replies, S3=81 must shape every one"

echo "=== The 30/31 boundary ==="
for KIND in response cookie transport; do
	py record "30,30,30,30,${H}" "${T}/b" "${KIND}:5:random"
	assert_eq "random" "$(kinds "${T}/b" 30,30,30,30 | awk -v k="${KIND}" '$1 == k { print $4 }')" "S=30: ${KIND}s are expected random"
	py record "31,31,31,31,${H}" "${T}/b" "${KIND}:5:sip"
	assert_eq "shaped" "$(kinds "${T}/b" 31,31,31,31 | awk -v k="${KIND}" '$1 == k { print $4 }')" "S=31: ${KIND}s are expected shaped"
done

echo "=== Signature accounting after classification: one kind wrong, the others right ==="
LAYOUT31="64,31,31,45,${H}"
for KIND in response cookie transport; do
	SPECS=()
	EXPECTED=""
	for OTHER in response cookie transport; do
		if [[ "${OTHER}" == "${KIND}" ]]; then
			SPECS+=("${OTHER}:4:random")
			EXPECTED+="${OTHER}=FAIL "
		else
			SPECS+=("${OTHER}:4:sip")
			EXPECTED+="${OTHER}=ok "
		fi
	done
	py record "${LAYOUT31}" "${T}/neg" "${SPECS[@]}"
	assert_eq "${EXPECTED}" "$(kinds "${T}/neg" 64,31,31,45 | awk 'NF == 5 && $1 != "init" { printf "%s=%s ", $1, $5 }')" \
		"${KIND}s without request lines fail only the ${KIND} verdict"
done
py record "${LAYOUT31}" "${T}/neg" response:3:sip cookie:3:sip transport:3:sip transport:1:random
assert_eq "transport 4 3 shaped FAIL" "$(kinds "${T}/neg" 64,31,31,45 | grep '^transport ')" \
	"a single transport datagram without a request line fails the transport verdict"

echo "=== Strict per-kind records ==="
SIG="4f5054494f4e53207369703a75407820"
py record "${LAYOUT31}" "${T}/good" response:2:sip cookie:2:sip transport:2:sip
assert_eq "0 8" "$(kinds_rc "${T}/good" 64,31,31,45)" "a valid capture gives eight rows"
: >"${T}/empty"
assert_eq "0 8" "$(kinds_rc "${T}/empty" 64,31,31,45)" "an empty capture is valid, every kind unobserved"
for RECORD in "transport 77" "transport 77 ${SIG} extra" "transport  77 ${SIG}" "transport NOT_A_LENGTH ${SIG}" \
	"transport 077 ${SIG}" "transport -77 ${SIG}" "transport 76 ${SIG}" "response 136 ${SIG}" "cookie 96 ${SIG}" \
	"transport 77 ${SIG}00" "transport 77 ${SIG:2}" "transport 77 ${SIG^^}" "transport 77 ${SIG:1}" "transport 77 -" \
	"unknown 77 ${SIG}" "unresolved 77 ${SIG}" "unknown x -" "probe 77 -" "${SIG}" "malformed" ""; do
	{ cat "${T}/good"; printf '%s\n' "${RECORD}"; } >"${T}/bad"
	assert_eq "1 0" "$(kinds_rc "${T}/bad" 64,31,31,45)" "valid records followed by '${RECORD}' are refused, nothing printed"
done
{ cat "${T}/good"; printf 'transport 77 %s' "${SIG}"; } >"${T}/bad"
assert_eq "1 0" "$(kinds_rc "${T}/bad" 64,31,31,45)" "an unterminated last record is refused"
{ cat "${T}/good"; printf 'transport 77 \xff\n'; } >"${T}/bad"
assert_eq "1 0" "$(kinds_rc "${T}/bad" 64,31,31,45)" "a non-ASCII record is refused"
for SIZES in 64,31,31 64,31,31,45,1 64,31,31,x 64,31,31,065; do
	assert_eq "1 0" "$(kinds_rc "${T}/good" "${SIZES}")" "the sizes '${SIZES}' are refused"
done
{ cat "${T}/good"; printf 'unknown 77 -\nambiguous 102 -\nunresolved 241 -\nmalformed 41 -\n'; } >"${T}/summaries"
assert_eq "unknown 1
ambiguous 1
unresolved 1
malformed 1" "$(kinds "${T}/summaries" 64,31,31,45 | tail -n 4)" "unknown, ambiguous, unresolved and malformed records are counted, each on its own row"

echo "=== Strict legacy prefixes (dns, stun, quic) ==="
printf '%s\n' "${SIG}" "" "0001000021120a" >"${T}/legacy"
assert_eq "2 1" "$("${REAL_PYTHON}" "${WIRE_REAL}" classify sip "${T}/legacy")" "classify reads legacy prefixes, an empty payload line uncounted"
for RECORD in "transport 77 ${SIG}" "malformed 41 -" "${SIG}00" "${SIG^^}" "abc" "zz"; do
	{ cat "${T}/legacy"; printf '%s\n' "${RECORD}"; } >"${T}/legacy-bad"
	"${REAL_PYTHON}" "${WIRE_REAL}" classify dns "${T}/legacy-bad" >/dev/null 2>&1
	assert_eq "1" "$?" "a legacy capture with '${RECORD}' is refused, not reinterpreted"
done

echo "=== The shared result check (tests/helpers/boringtun-wire-checks.sh) ==="
# shellcheck source=helpers/boringtun-wire-checks.sh
source "${SCRIPT_DIR}/helpers/boringtun-wire-checks.sh"
VALID_ROWS="$(kinds "${T}/good" 64,31,31,45)"
assert_true "the helper's own output validates" bt_wire_validate_kinds "${VALID_ROWS}" 64,31,31,45
refused() { # <label> <output>
	if bt_wire_validate_kinds "$2" 64,31,31,45; then not_ok "$1 is refused"; else ok "$1 is refused (${BT_WIRE_REASON})"; fi
}
refused "empty output" ""
refused "garbage output" "THIS IS NOT AN ORACLE RESULT"
refused "output without its last row" "$(head -n 7 <<<"${VALID_ROWS}")"
refused "output in the earlier seven-row form" "$(grep -v '^unresolved ' <<<"${VALID_ROWS}")"
refused "output with a repeated row" "$(head -n 2 <<<"${VALID_ROWS}"; tail -n 7 <<<"${VALID_ROWS}")"
refused "output with an extra row" "${VALID_ROWS}"$'\nunknown 0'
refused "output with two rows swapped" "$(sed -n '2p' <<<"${VALID_ROWS}"; sed -n '1p' <<<"${VALID_ROWS}"; tail -n 6 <<<"${VALID_ROWS}")"
refused "a row with a missing field" "$(sed '3s/ ok$//' <<<"${VALID_ROWS}")"
refused "a row with an extra field" "$(sed '3s/$/ extra/' <<<"${VALID_ROWS}")"
refused "a negative count" "$(sed '2s/^response 2 2/response -2 2/' <<<"${VALID_ROWS}")"
refused "a non-numeric count" "$(sed '2s/^response 2 2/response two 2/' <<<"${VALID_ROWS}")"
refused "more shaped than seen" "$(sed '2s/^response 2 2/response 2 3/' <<<"${VALID_ROWS}")"
refused "an expectation S does not give" "$(sed '2s/ shaped / random /' <<<"${VALID_ROWS}")"
refused "a verdict the counts do not give" "$(sed '2s/ ok$/ FAIL/' <<<"${VALID_ROWS}")"
refused "an unobserved verdict for seen datagrams" "$(sed '2s/ ok$/ unobserved/' <<<"${VALID_ROWS}")"
refused "a summary with a non-numeric count" "$(sed '7s/^unresolved 0$/unresolved none/' <<<"${VALID_ROWS}")"

echo "=== Owned children: identity, not number ==="
WIRE="${WIRE_REAL}"
assert_true "this Python offers pidfds (os.pidfd_open, signal.pidfd_send_signal)" \
	"${REAL_PYTHON}" -c 'import os, signal; os.pidfd_open; signal.pidfd_send_signal'
# This test's own checks and its own ending of processes go by identity too
# (PID and start time), never by a number alone, independently of the
# tracker under test: if the tracker ends or reaps a process it should not,
# that number may already belong to another process.
start_of() { # <pid>: its start time, if it exists
	local LINE FIELDS=()
	read -r LINE 2>/dev/null <"/proc/$1/stat" || return 1
	read -r -a FIELDS <<<"${LINE##*) }"
	echo "${FIELDS[19]}"
}
runs_as() { # <pid> <start>: that very process still runs (not a zombie)
	local LINE FIELDS=()
	read -r LINE 2>/dev/null <"/proc/$1/stat" || return 1
	read -r -a FIELDS <<<"${LINE##*) }"
	[[ "${FIELDS[19]}" == "$2" && "${FIELDS[0]}" != Z ]]
}
gone_as() { # <pid> <start>: that very process is no more, not even a zombie
	[[ "$(start_of "$1")" != "$2" ]]
}
end_as() { # <pid> <start>: SIGTERM to that very process through a pidfd, if it is still there
	"${REAL_PYTHON}" -c '
import os, signal, sys
pid, start = int(sys.argv[1]), sys.argv[2]
try:
    fd = os.pidfd_open(pid)
except ProcessLookupError:
    sys.exit(1)
try:
    with open("/proc/%d/stat" % pid) as stat:
        if stat.read().rsplit(")", 1)[1].split()[19] != start:
            sys.exit(1)
    signal.pidfd_send_signal(fd, signal.SIGTERM)
finally:
    os.close(fd)' "$1" "$2"
}
bt_wire_spawn RUNNING /dev/null - sleep 30
read -r RUN_PID RUN_START _ <<<"${RUNNING}"
assert_eq "${RUN_PID} $(start_of "${RUN_PID}") ${BASHPID}" "${RUNNING}" "a spawned child's handle is its own PID, start time and parent"
# Released once tracked, the child becomes its command within its 10 ms poll.
for ((I = 0; I < 100; I++)); do
	[[ "$(tr '\0' ' ' <"/proc/${RUN_PID}/cmdline" | cut -d' ' -f1)" == sleep ]] && break
	sleep 0.01
done
assert_eq "sleep" "$(tr '\0' ' ' <"/proc/${RUN_PID}/cmdline" | cut -d' ' -f1)" "  and once released, the PID runs the command itself"
# Processes that have a tracked number but not its start time, as a PID given
# to another process after the tracked child was reaped. Each check has one of
# its own, so no check's outcome rests on what another did to its process.
stranger() { # sets STRANGER and STRANGER_START: a new child of this shell
	sleep 30 &
	STRANGER=$!
	STRANGER_START="$(start_of "${STRANGER}")"
}
still_ours() { # <label>: neither ended nor reaped by the tracker
	end_as "${STRANGER}" "${STRANGER_START}"
	wait "${STRANGER}"
	assert_eq "143" "$?" "$1"
}
stranger
bt_wire_signal "${STRANGER} 1 ${BASHPID}" TERM
assert_eq "1" "$?" "a handle whose start time is not the process's sends no signal"
assert_true "  the process with that PID still runs after the signal" runs_as "${STRANGER}" "${STRANGER_START}"
still_ours "  and is still this shell's to end and reap (143)"
stranger
bt_wire_collect "${STRANGER} 1 ${BASHPID}"
assert_eq "unknown" "${BT_WIRE_STATUS}" \
	"a handle whose start time is not the process's is not waited for while another child of this shell has its PID (status unknown)"
assert_true "  the process with that PID still runs after the collection" runs_as "${STRANGER}" "${STRANGER_START}"
still_ours "  and was not reaped by it: this shell ends and reaps it now (143)"
stranger
bt_wire_track "${STRANGER} 1 ${BASHPID}"
bt_wire_cleanup
assert_true "bt_wire_cleanup leaves the process that has a tracked number but another identity alone" \
	runs_as "${STRANGER}" "${STRANGER_START}"
assert_true "  and ends the tracked child that runs" gone_as "${RUN_PID}" "${RUN_START}"
still_ours "  the untracked process was neither signalled nor reaped by it (this shell reaps it now: 143)"
# A tracked child that this shell reaps by itself before any wait.
bt_wire_spawn EXITED /dev/null - bash -c 'exit 42'
read -r OLD_PID OLD_START _ <<<"${EXITED}"
for ((I = 0; I < 50; I++)); do
	gone_as "${OLD_PID}" "${OLD_START}" && break
	sleep 0.1
done
assert_true "the shell reaped the exited child by itself, with no wait" gone_as "${OLD_PID}" "${OLD_START}"
assert_eq "unknown" "$(bt_wire_collect "${EXITED}"; echo "${BT_WIRE_STATUS}")" \
	"  a shell that is not its parent cannot collect it: status unknown, never a number"
bt_wire_collect "${EXITED}"
assert_eq "42" "${BT_WIRE_STATUS}" "  its parent's status still comes from the shell's own record"
# A child that ignores SIGTERM: killed at the limit, and collected.
bt_wire_spawn IGNORING /dev/null - bash -c 'trap "" TERM; : >"$1"; exec sleep 30' _ "${T}/ignoring"
for ((I = 0; I < 100; I++)); do
	[[ -e "${T}/ignoring" ]] && break
	sleep 0.1
done
bt_wire_stop "${IGNORING}" 1
assert_eq "137" "${BT_WIRE_STATUS}" "a child that ignores SIGTERM is killed after the limit and collected (137)"
assert_eq "0" "${#BT_WIRE_CHILDREN[@]}" "collected children are no longer tracked"

echo "=== Owned children: tracked before they run ==="
# A child records its identity and waits; the parent tracks the handle and
# only then releases it. Each phase is interrupted on purpose, in a shell
# whose SIGTERM trap is the callers' (end and collect what is tracked, then
# exit 143). The child's command would create RAN; afterwards the child must
# be gone, and with the trap run, the identity records too.
handoff() { # <phase>: "<status> <ran|not-run> <child running|gone> <identity records left|cleaned>"
	local PHASE="$1" RAN="${T}/handoff-$1" CHILD="" START="" DIR STATUS
	rm -f -- "${RAN}" "${RAN}.handle" "${RAN}.dir"
	(
		trap 'bt_wire_cleanup; exit 143' TERM
		eval "original_$(declare -f bt_wire_track)"
		note() { echo "$1" >"${RAN}.handle"; echo "${BT_WIRE_DIR}" >"${RAN}.dir"; }
		case "${PHASE}" in
			before-tracking) bt_wire_track() { note "$1"; kill -TERM "${BASHPID}"; original_bt_wire_track "$1"; } ;;
			before-release) bt_wire_track() { note "$1"; original_bt_wire_track "$1"; kill -TERM "${BASHPID}"; } ;;
			parent-killed) bt_wire_track() { note "$1"; original_bt_wire_track "$1"; kill -KILL "${BASHPID}"; } ;;
			released) bt_wire_track() { note "$1"; original_bt_wire_track "$1"; } ;;
		esac
		bt_wire_spawn HANDLE /dev/null - bash -c ': >"$1"; exec sleep 30' _ "${RAN}"
		for ((I = 0; I < 100; I++)); do
			[[ -e "${RAN}" ]] && break
			sleep 0.05
		done
		kill -TERM "${BASHPID}"
		exit 0
	)
	STATUS=$?
	# A withdrawn child notices within 10 ms that its parent let go.
	sleep 0.3
	read -r CHILD START _ 2>/dev/null <"${RAN}.handle"
	DIR="$(cat "${RAN}.dir" 2>/dev/null)"
	echo "${STATUS} $([[ -e "${RAN}" ]] && echo ran || echo not-run)" \
		"$(runs_as "${CHILD}" "${START}" && echo running || echo gone)" "$([[ -n "${DIR}" && -e "${DIR}" ]] && echo left || echo cleaned)"
	end_as "${CHILD}" "${START}" 2>/dev/null
	[[ -n "${DIR}" ]] && rm -rf -- "${DIR}"
}
assert_eq "143 not-run gone cleaned" "$(handoff before-tracking)" \
	"interrupted before its child is tracked, the caller exits 143 and the child never runs its command"
assert_eq "143 not-run gone cleaned" "$(handoff before-release)" \
	"interrupted after tracking and before the release, the waiting child is ended and never runs its command"
assert_eq "143 ran gone cleaned" "$(handoff released)" "interrupted once its command runs, the tracked child is ended"
assert_eq "137 not-run gone left" "$(handoff parent-killed)" \
	"a caller killed outright before the release leaves no child running its command (no trap could clean up)"
# A failed registration releases nothing.
registration() { # <case>: "<spawn status> '<handle>' <ran|not-run> <tracked>"
	local RAN="${T}/registration-$1"
	rm -f -- "${RAN}"
	(
		case "$1" in
			unwritable) bt_wire_self_identity() { return 1; } ;;
			foreign)
				bt_wire_self_identity() {
					local LINE FIELDS=()
					read -r LINE </proc/self/stat
					read -r -a FIELDS <<<"${LINE##*) }"
					printf '1 1 %s\n' "${FIELDS[1]}"
				}
				;;
		esac
		HANDLE=""
		bt_wire_spawn HANDLE /dev/null - bash -c ': >"$1"; exec sleep 30' _ "${RAN}" >/dev/null
		RC=$?
		sleep 0.5
		echo "${RC} '${HANDLE}' $([[ -e "${RAN}" ]] && echo ran || echo not-run) ${#BT_WIRE_CHILDREN[@]}"
		bt_wire_cleanup
	)
}
assert_eq "1 '' not-run 0" "$(registration unwritable)" \
	"a child that cannot record its identity is never released: spawn fails, nothing is tracked, its command never runs"
assert_eq "1 '' not-run 0" "$(registration foreign)" \
	"a child whose recorded identity is not its own is withdrawn: spawn fails, nothing is tracked, its command never runs"

# ── The consumers, with a fake capture/replay child ─────────────────────────
# The fake follows the helper's protocol unless a mode breaks it: it copies a
# given capture, puts its SIGTERM handler in place, waits FAKE_START_DELAY
# seconds (a slow start), and only then writes "ready <pid> <start time>
# <ready clock>" (its own, the clock from /proc/uptime). On SIGTERM it ends
# "stopped <n> <token>" when the stop file holds a token, else "interrupted
# <n>" (status 3); with FAKE_END=complete it sleeps FAKE_RUN seconds (the
# capture interval by default) and ends "complete <n> <end clock>".
# FAKE_CAPTURE_RC replaces status 0. Modes: noready, crash (status 42 after
# ready), premature (complete at once), stale (a stale transcript, then
# exit), stale-running (a stale transcript, still running), selfterm (a
# SIGTERM to itself before the caller's stop), wrongready (a ready line of
# another process), wrongcount (an end with one record too many), extra (an
# extra line after its end), noclock and endnoclock (a ready or complete
# line without its clock), readyearly (a ready clock before its start),
# readylate (a ready clock after the caller saw it), endlate (an end clock
# after the caller saw it end). With FAKE_EXPECT_KEY it starts only when given
# a layout and that receiver key: an expected-key guard that checks the
# consumers forward the right key. The real helper checks only the key's
# format; it cannot tell a well-formed wrong key at startup. The
# replay prints its ready line and "replayed <n>" and exits FAKE_REPLAY_RC;
# modes noready and noinit. `kinds` runs the real helper unless FAKE_KINDS
# asks for empty or garbage output with exit 0; "owned" always runs the real
# helper.
FAKEWIRE="${T}/fakewire"
cat >"${FAKEWIRE}" <<'EOF'
#!/bin/bash
read -r LINE </proc/self/stat
read -r -a FIELDS <<<"${LINE##*) }"
ME="$$ ${FIELDS[19]}"
# The capture's clock: CLOCK_BOOTTIME in centiseconds, as /proc/uptime has it.
clock() {
	local UPTIME REST
	read -r UPTIME REST </proc/uptime
	UPTIME="${UPTIME/./}"
	CLOCK=$((10#${UPTIME}))
}
case "$1" in
	capture)
		# With FAKE_EXPECT_KEY, only a layout capture given that receiver key
		# starts: the expected-key guard (the real helper needs a layout and
		# a well-formed key, and checks only the format).
		if [[ -n "${FAKE_EXPECT_KEY:-}" ]] && [[ $# -ne 8 || -z "$7" || "$8" != "${FAKE_EXPECT_KEY}" ]]; then
			echo "fake capture: no layout with the receiver key ${FAKE_EXPECT_KEY}: $*" >&2
			exit 1
		fi
		OUT="$6"
		STATE="${OUT}.state"
		cp -- "${FAKE_CAPTURE}" "${OUT}"
		N="$(wc -l <"${OUT}")"
		[[ "${FAKE_CAPTURE_MODE:-}" == noready ]] && exit 1
		on_term() {
			local TOKEN=""
			read -r TOKEN 2>/dev/null <"${OUT}.stop"
			if [[ "${TOKEN}" =~ ^[0-9a-f]{32}$ ]]; then
				[[ "${FAKE_CAPTURE_MODE:-}" == wrongcount ]] && N=$((N + 1))
				echo "stopped ${N} ${TOKEN}" >>"${STATE}"
				[[ "${FAKE_CAPTURE_MODE:-}" == extra ]] && echo "junk" >>"${STATE}"
				exit "${FAKE_CAPTURE_RC:-0}"
			fi
			echo "interrupted ${N}" >>"${STATE}"
			exit 3
		}
		trap on_term TERM
		# Its readiness delayed, as a slow start would.
		sleep "${FAKE_START_DELAY:-0}"
		clock
		READY="${CLOCK}"
		case "${FAKE_CAPTURE_MODE:-}" in
			wrongready) echo "ready 1 1 ${READY}" >>"${STATE}" ;;
			noclock) echo "ready ${ME}" >>"${STATE}" ;;
			readyearly) echo "ready ${ME} 0" >>"${STATE}" ;;
			readylate) echo "ready ${ME} $((READY + 100000))" >>"${STATE}" ;;
			*) echo "ready ${ME} ${READY}" >>"${STATE}" ;;
		esac
		case "${FAKE_CAPTURE_MODE:-}" in
			crash) exit 42 ;;
			premature) clock; echo "complete ${N} ${CLOCK}" >>"${STATE}"; exit 0 ;;
			stale) printf 'stopped %s\njunk\nstopped %s\n' "${N}" "${N}" >>"${STATE}"; exit 0 ;;
			stale-running) printf 'stopped %s\njunk\n' "${N}" >>"${STATE}" ;;
			selfterm) kill -TERM "$$" ;;
		esac
		if [[ "${FAKE_END}" == stop ]]; then
			while :; do sleep 0.05; done
		fi
		# It completes after FAKE_RUN seconds, its interval by default.
		sleep "${FAKE_RUN:-$5}"
		[[ "${FAKE_CAPTURE_MODE:-}" == wrongcount ]] && N=$((N + 1))
		clock
		case "${FAKE_CAPTURE_MODE:-}" in
			endlate) echo "complete ${N} $((READY + 100000))" >>"${STATE}" ;;
			endnoclock) echo "complete ${N}" >>"${STATE}" ;;
			*) echo "complete ${N} ${CLOCK}" >>"${STATE}" ;;
		esac
		[[ "${FAKE_CAPTURE_MODE:-}" == extra ]] && echo "junk" >>"${STATE}"
		exit "${FAKE_CAPTURE_RC:-0}"
		;;
	replay)
		[[ "${FAKE_REPLAY_MODE:-}" == noready ]] && exit 1
		echo "ready ${ME}"
		if [[ "${FAKE_REPLAY_MODE:-}" == noinit ]]; then
			echo "no initiation seen" >&2
			exit 1
		fi
		echo "replayed $7"
		exit "${FAKE_REPLAY_RC:-0}"
		;;
	kinds)
		case "${FAKE_KINDS:-real}" in
			empty) exit 0 ;;
			garbage) echo "THIS IS NOT AN ORACLE RESULT"; exit 0 ;;
		esac
		;;
esac
exec "${REAL_PYTHON}" "${WIRE_REAL}" "$@"
EOF
chmod 0755 "${FAKEWIRE}"
export REAL_PYTHON WIRE_REAL
extract() { # <file> <function>: its definition, verbatim
	awk -v f="$2" '$0 ~ "^"f"\\(\\) \\{" {on=1} on {print} on && /^}/ {exit}' "$1"
}
for FUNCTION in "${HOST_LIVE}:wire_prefixes" "${SIP_LIVE}:run_scenario" "${SIP_LIVE}:expect_scenario" "${SIP_LIVE}:peer_modes"; do
	assert_true "${FUNCTION##*/} is extracted from its file" test -n "$(extract "${FUNCTION%:*}" "${FUNCTION##*:}")"
done
# Records for S1=64 S2=31 S3=31 S4=45 (and S2=S3=S4=31 for the harness).
py record "64,31,31,45,${H}" "${T}/host-valid" response:1:sip transport:3:sip
py record "64,31,31,31,${H}" "${T}/live-valid" response:1:sip cookie:3:sip transport:3:sip
with_record() { # <capture> <record> <out>
	{ cat "$1"; printf '%s\n' "$2"; } >"$3"
}
for SUMMARY in unknown ambiguous unresolved malformed; do
	with_record "${T}/host-valid" "${SUMMARY} 41 -" "${T}/host-${SUMMARY}"
	with_record "${T}/live-valid" "${SUMMARY} 41 -" "${T}/live-${SUMMARY}"
done
with_record "${T}/host-valid" "transport 77" "${T}/host-truncated"
with_record "${T}/host-valid" "transport NOT_A_LENGTH ${SIG}" "${T}/host-badlength"
with_record "${T}/live-valid" "transport 77" "${T}/live-truncated"
# The real helper's record of the fragmented ambiguous datagram, mixed with
# valid records of its layout (S=64,149,31,55: a response is 241 bytes).
py record "64,149,31,55,${H}" "${T}/fragment-valid-host" response:1:sip transport:2:sip
cat "${T}/fragment-valid-host" "${T}/fragment-record" >"${T}/host-fragment"
py record "64,149,31,55,${H}" "${T}/fragment-valid-live" response:1:sip cookie:2:sip transport:2:sip
cat "${T}/fragment-valid-live" "${T}/fragment-record" >"${T}/live-fragment"
# The real helper's records of the contradictory continuation, mixed with
# valid records (the transport's 96 bytes fit S4=45 and S4=31 alike).
cat "${T}/host-valid" "${T}/boundary-records" >"${T}/host-boundary"
cat "${T}/live-valid" "${T}/boundary-records" >"${T}/live-boundary"
# Follow-up D's genuine response and ping replies, plus shaped cookie replies
# for the harness consumer's rules, as the real helper records them with the
# client's key and without it.
py record-genuine "${T}/genuine-with" with-evidence 2
py record-genuine "${T}/genuine-without" without-evidence 2
OTHER_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# The host consumer: wire_prefixes sip, its capture stopped after the traffic.
# Prints the consumer's assertions and a last line "complete assertions=<n>
# failures=<m>"; exits 1 when an assertion failed.
host_case() { # <capture> [VAR=value...]
	local CAPTURE="$1"
	shift
	# shellcheck disable=SC2034 # the fixture settings are read by the extracted wire_prefixes
	(
		# shellcheck disable=SC2163 # the arguments are VAR=value assignments
		export FAKE_CAPTURE="${CAPTURE}" FAKE_END=stop FAKE_EXPECT_KEY="${FIXTURE_KEY}" "$@"
		WORK="${T}/host-work"
		rm -rf "${WORK}" && mkdir -p "${WORK}"
		WIRE=fake NS=fixture VETH_CLIENT=fixture HOST_ADDR=192.0.2.1 PORT=51820
		SIZES="${FIXTURE_SIZES:-64,31,31,45}"
		PASSED=0 FAILED=0
		# The fixture shell itself; deeper shells are the spawned children and
		# command substitutions, where the stand-in for python3 becomes the fake.
		LEVEL="${BASH_SUBSHELL}"
		ok() { echo "  OK: $1"; PASSED=$((PASSED + 1)); }
		bad() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
		check() { local M="$1"; shift; if "$@"; then ok "${M}"; else bad "${M}"; fi; }
		params_s() { cut -d, -f"${1#S}" <<<"${SIZES}"; }
		params_layout() { echo "${SIZES},${H}"; }
		client_public_key() { echo "${FIXTURE_CONSUMER_KEY:-${FIXTURE_KEY}}"; }
		datapath() { :; }
		python3() { if ((BASH_SUBSHELL > LEVEL)); then exec "${FAKEWIRE}" "${@:2}"; else "${FAKEWIRE}" "${@:2}"; fi; }
		ip() { if [[ "$1 $2" == "netns exec" ]]; then shift 3; "$@"; else return 97; fi; }
		eval "$(extract "${HOST_LIVE}" wire_prefixes)"
		wire_prefixes sip
		bt_wire_cleanup
		echo "complete assertions=$((PASSED + FAILED)) failures=${FAILED}"
		((FAILED == 0))
	)
}
# The harness consumer: run_scenario and expect_scenario, with cookies.
live_case() { # <capture> [VAR=value...]
	local CAPTURE="$1"
	shift
	# shellcheck disable=SC2034 # the fixture settings are read by the extracted run_scenario
	(
		# shellcheck disable=SC2163 # the arguments are VAR=value assignments
		export FAKE_CAPTURE="${CAPTURE}" FAKE_END=complete FAKE_EXPECT_KEY="${FIXTURE_KEY}" "$@"
		WORK="${T}/live-work"
		rm -rf "${WORK}" && mkdir -p "${WORK}"
		WIRE=fake NS_C=fixture VETH_C=fixture ADDR_C=192.0.2.2 ADDR_S=192.0.2.1 PORT=51999 DOMAIN=pbx.example
		REPLAYS=400 TUN_S=10.77.0.1 H_RANGES="${H}" CAPTURE_SECONDS=3
		CLIENT_PUB="${FIXTURE_CONSUMER_KEY:-${FIXTURE_KEY}}"
		IFS=, read -r S1 S2 S3 S4 <<<"${FIXTURE_SIZES:-64,31,31,31}"
		declare -A SIZES_OF=()
		PASSED=0 FAILED=0
		# The fixture shell itself; deeper shells are the spawned children and
		# command substitutions, where the stand-in for python3 becomes the fake.
		LEVEL="${BASH_SUBSHELL}"
		ok() { echo "  OK: $1"; PASSED=$((PASSED + 1)); }
		bad() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
		# With FIXTURE_COLLECT_DELAY, the first poll inside the capture's
		# finish sleeps that long, as a caller slow to collect a status would.
		DELAY_POLL=no
		check() {
			local M="$1"
			shift
			[[ "${M}" == *"capture outlived the traffic"* && "${FIXTURE_COLLECT_DELAY:-0}" != 0 ]] && DELAY_POLL=yes
			if "$@"; then ok "${M}"; else bad "${M}"; fi
		}
		sleep() {
			if [[ "${DELAY_POLL}" == yes ]]; then
				DELAY_POLL=no
				command sleep "${FIXTURE_COLLECT_DELAY}"
			else
				command sleep "$@"
			fi
		}
		# Stand-in peers whose /proc cmdlines carry what peer_modes reads.
		bash -c 'while :; do sleep 0.2; done' server --imitate-protocol sip --imitate-domain pbx.example fixture0 &
		SERVER_PID=$!
		bash -c 'while :; do sleep 0.2; done' client fixture1 &
		CLIENT_PID=$!
		setup_pair() { :; }
		python3() { if ((BASH_SUBSHELL > LEVEL)); then exec "${FAKEWIRE}" "${@:2}"; else "${FAKEWIRE}" "${@:2}"; fi; }
		ip() {
			[[ "$1 $2" == "netns exec" ]] || return 97
			shift 3
			[[ "$1" == ping ]] && return 0
			"$@"
		}
		for FUNCTION in run_scenario expect_scenario peer_modes; do
			eval "$(extract "${SIP_LIVE}" "${FUNCTION}")"
		done
		run_scenario fixture "${S1}" "${S2}" "${S3}" "${S4}" cookies
		expect_scenario fixture init:absent response:required cookie:required transport:required
		bt_wire_cleanup
		kill "${SERVER_PID}" "${CLIENT_PID}" 2>/dev/null
		wait "${SERVER_PID}" "${CLIENT_PID}" 2>/dev/null
		echo "complete assertions=$((PASSED + FAILED)) failures=${FAILED}"
		((FAILED == 0))
	)
}
# Run a consumer fixture and judge it. It must complete (its last line) with
# a positive assertion count. "pass": exit 0 and no failure. "reject": exit 1
# and at least one failed assertion whose message contains TEXT.
expect_fixture() { # <label> <pass|reject> <text|-> <fixture command...>
	local LABEL="$1" WANT="$2" TEXT="$3" OUTPUT RC LAST N M FAILED_LINES
	shift 3
	OUTPUT="$("$@" 2>&1)"
	RC=$?
	LAST="$(tail -n 1 <<<"${OUTPUT}")"
	if [[ ! "${LAST}" =~ ^complete\ assertions=([0-9]+)\ failures=([0-9]+)$ ]]; then
		not_ok "${LABEL}: the fixture did not complete (exit ${RC}, last line '${LAST}')"
		return
	fi
	N="${BASH_REMATCH[1]}"
	M="${BASH_REMATCH[2]}"
	FAILED_LINES="$(grep '^  FAIL: ' <<<"${OUTPUT}")"
	if ((N == 0)); then
		not_ok "${LABEL}: the fixture made no assertion"
	elif [[ "${WANT}" == pass ]]; then
		if ((RC == 0 && M == 0)); then
			ok "${LABEL} (${N} assertions)"
		else
			not_ok "${LABEL}: exit ${RC}, ${M} of ${N} failed: ${FAILED_LINES}"
		fi
	elif ((RC == 1 && M >= 1)) && grep -qF -- "${TEXT}" <<<"${FAILED_LINES}"; then
		ok "${LABEL} (exit 1; ${M} of ${N} failed, including '${TEXT}')"
	else
		not_ok "${LABEL}: expected exit 1 and a failure containing '${TEXT}'; exit ${RC}, ${M} of ${N} failed: ${FAILED_LINES:-none}"
	fi
}

echo "=== The capture contract, directly ==="
# The interval is the capture's own, from its ready clock to its end clock:
# neither a slow start nor a slow collection of its status may stand in for
# it. DIRECT_COLLECT_DELAY delays the caller's first poll inside the finish.
capture_direct() { # <seconds> [VAR=value...]: the finish's status and message
	local SECONDS_ARG="$1"
	shift
	(
		# shellcheck disable=SC2163 # the arguments are VAR=value assignments
		export FAKE_CAPTURE="${T}/host-valid" FAKE_END=complete "$@"
		LEVEL="${BASH_SUBSHELL}"
		python3() { if ((BASH_SUBSHELL > LEVEL)); then exec "${FAKEWIRE}" "${@:2}"; else "${FAKEWIRE}" "${@:2}"; fi; }
		ip() { if [[ "$1 $2" == "netns exec" ]]; then shift 3; "$@"; else return 97; fi; }
		DELAY_POLL=no
		sleep() {
			if [[ "${DELAY_POLL}" == yes ]]; then
				DELAY_POLL=no
				command sleep "${DIRECT_COLLECT_DELAY}"
			else
				command sleep "$@"
			fi
		}
		# shellcheck disable=SC2034 # read by the sourced boringtun-wire-checks.sh
		WIRE=fake
		if ! bt_wire_capture_start fixture fixture 192.0.2.1 51820 "${SECONDS_ARG}" "${T}/direct.capture" "64,31,31,45,${H}" \
			>"${T}/direct.message"; then
			bt_wire_cleanup
			echo "1 $(cat "${T}/direct.message")"
			exit 0
		fi
		[[ -n "${DIRECT_COLLECT_DELAY:-}" ]] && DELAY_POLL=yes
		# In this shell, the capture's parent, as the real callers do.
		bt_wire_capture_finish "${T}/direct.capture" complete 10 >"${T}/direct.message"
		RC=$?
		bt_wire_cleanup
		echo "${RC} $(cat "${T}/direct.message")"
	)
}
assert_eq "0 " "$(capture_direct 1)" "a capture that runs its whole 1 s interval and completes passes"
direct_rejects() { # <label> <message start> <seconds> [VAR=value...]
	local LABEL="$1" WANT="$2" RESULT
	shift 2
	RESULT="$(capture_direct "$@")"
	assert_true "${LABEL} (${RESULT%%$'\n'*})" bash -c '[[ "$1" == "1     $2"* ]]' _ "${RESULT}" "${WANT}"
}
direct_rejects "a capture still running when asked, that completes after 1 s of a 3 s interval, is rejected" \
	"the capture was ready at " 3 FAKE_RUN=1
direct_rejects "  as is one that became ready 2.4 s late and then ran 1 s" "the capture was ready at " 3 FAKE_START_DELAY=2.4 FAKE_RUN=1
direct_rejects "  and one that ran 1 s while the caller was 3.5 s late to collect its status" \
	"the capture was ready at " 3 FAKE_RUN=1 DIRECT_COLLECT_DELAY=3.5
assert_eq "0 " "$(capture_direct 3 FAKE_START_DELAY=2.4)" "one that became ready 2.4 s late and then ran its whole 3 s passes"
assert_eq "0 " "$(capture_direct 3 DIRECT_COLLECT_DELAY=3.5)" "  as does one that ran its whole 3 s while the caller was 3.5 s late to collect it"
direct_rejects "a ready line without its clock is refused" "the capture did not become ready" 1 FAKE_CAPTURE_MODE=noclock
direct_rejects "a ready clock before the capture was started is refused" "the capture's ready clock " 1 FAKE_CAPTURE_MODE=readyearly
direct_rejects "a ready clock after the caller saw the ready line is refused" "the capture's ready clock " 1 FAKE_CAPTURE_MODE=readylate
direct_rejects "a complete line without its clock is refused" "the capture's transcript is not exactly" 1 FAKE_CAPTURE_MODE=endnoclock
direct_rejects "an end clock after the caller saw the capture end is refused" "the capture's end clock " 1 FAKE_CAPTURE_MODE=endlate

echo "=== The host consumer (wire_prefixes) ==="
CAPTURE_TEXT="the client-side capture ran from before the traffic until its authorized stop"
expect_fixture "valid response and transport records pass" pass - host_case "${T}/host-valid"
expect_fixture "follow-up D's genuine datagrams, recorded with the client's key, pass" pass - \
	host_case "${T}/genuine-with" FIXTURE_SIZES=99,54,92,52
expect_fixture "  recorded without it, the ambiguous response is rejected" reject "no recorded server datagram is ambiguous (1)" \
	host_case "${T}/genuine-without" FIXTURE_SIZES=99,54,92,52
expect_fixture "  as is the missing response" reject "response datagrams were recorded (0)" \
	host_case "${T}/genuine-without" FIXTURE_SIZES=99,54,92,52
expect_fixture "a consumer that forwards another receiver key fails the fake capture's expected-key guard" reject "the client-side capture started" \
	host_case "${T}/host-valid" FIXTURE_CONSUMER_KEY="${OTHER_KEY}"
for SUMMARY in unknown ambiguous unresolved malformed; do
	expect_fixture "valid records plus a ${SUMMARY} record are rejected" reject "no recorded server datagram is ${SUMMARY}" \
		host_case "${T}/host-${SUMMARY}"
done
expect_fixture "the real helper's record of a fragment that hides a tag is rejected among valid records" reject \
	"no recorded server datagram is unresolved" host_case "${T}/host-fragment" FIXTURE_SIZES=64,149,31,55
expect_fixture "the real helper's records of a non-final fragment that reaches the declared end are rejected" reject \
	"no recorded server datagram is malformed" host_case "${T}/host-boundary"
for CASE in truncated badlength; do
	expect_fixture "valid records plus a ${CASE} record are rejected" reject "the capture has a complete, valid per-kind result" \
		host_case "${T}/host-${CASE}"
done
for KINDS_MODE in empty garbage; do
	expect_fixture "a helper that exits 0 with ${KINDS_MODE} output is rejected" reject \
		"the capture has a complete, valid per-kind result" host_case "${T}/host-valid" FAKE_KINDS="${KINDS_MODE}"
done
for MODE in FAKE_CAPTURE_RC=42 FAKE_CAPTURE_MODE=crash FAKE_CAPTURE_MODE=premature FAKE_CAPTURE_MODE=stale \
	FAKE_CAPTURE_MODE=stale-running FAKE_CAPTURE_MODE=selfterm FAKE_CAPTURE_MODE=wrongcount FAKE_CAPTURE_MODE=extra; do
	expect_fixture "a capture with ${MODE} after valid records is rejected" reject "${CAPTURE_TEXT}" \
		host_case "${T}/host-valid" "${MODE}"
done
for MODE in FAKE_CAPTURE_MODE=noready FAKE_CAPTURE_MODE=wrongready FAKE_CAPTURE_MODE=noclock FAKE_CAPTURE_MODE=readyearly \
	FAKE_CAPTURE_MODE=readylate; do
	expect_fixture "a capture with ${MODE} is rejected" reject "the client-side capture started" host_case "${T}/host-valid" "${MODE}"
done

echo "=== The harness consumer (run_scenario, expect_scenario) ==="
LIVE_CAPTURE_TEXT="the capture outlived the traffic, ran its whole 3 s and completed with all its records"
expect_fixture "a valid scenario passes" pass - live_case "${T}/live-valid"
expect_fixture "follow-up D's genuine datagrams, recorded with the client's key, pass" pass - \
	live_case "${T}/genuine-with" FIXTURE_SIZES=99,54,92,52
expect_fixture "  recorded without it, the ambiguous response is rejected" reject "no recorded server datagram is ambiguous (1)" \
	live_case "${T}/genuine-without" FIXTURE_SIZES=99,54,92,52
expect_fixture "  as is the missing response" reject "response datagrams were recorded (0)" \
	live_case "${T}/genuine-without" FIXTURE_SIZES=99,54,92,52
expect_fixture "a scenario that forwards another receiver key fails the fake capture's expected-key guard" reject "the capture started" \
	live_case "${T}/live-valid" FIXTURE_CONSUMER_KEY="${OTHER_KEY}"
# The interval is the capture's own: a late start, or a caller late to
# collect the status, neither shortens a whole interval nor lengthens a
# short one.
expect_fixture "a scenario whose capture ran only 1 s of its 3 s is rejected" reject "${LIVE_CAPTURE_TEXT}" \
	live_case "${T}/live-valid" FAKE_RUN=1
expect_fixture "a scenario whose capture became ready 2.4 s late and ran its whole 3 s passes" pass - \
	live_case "${T}/live-valid" FAKE_START_DELAY=2.4
expect_fixture "a scenario whose capture became ready 2.4 s late and ran only 1 s is rejected" reject "${LIVE_CAPTURE_TEXT}" \
	live_case "${T}/live-valid" FAKE_START_DELAY=2.4 FAKE_RUN=1
expect_fixture "a scenario whose capture ran its whole 3 s while the caller was 3.5 s late to collect it passes" pass - \
	live_case "${T}/live-valid" FIXTURE_COLLECT_DELAY=3.5
expect_fixture "a scenario whose capture ran only 1 s while the caller was 3.5 s late to collect it is rejected" reject \
	"${LIVE_CAPTURE_TEXT}" live_case "${T}/live-valid" FAKE_RUN=1 FIXTURE_COLLECT_DELAY=3.5
for SUMMARY in unknown ambiguous unresolved malformed; do
	expect_fixture "valid records plus a ${SUMMARY} record are rejected" reject "no recorded server datagram is ${SUMMARY}" \
		live_case "${T}/live-${SUMMARY}"
done
expect_fixture "the real helper's record of a fragment that hides a tag is rejected among valid records" reject \
	"no recorded server datagram is unresolved" live_case "${T}/live-fragment" FIXTURE_SIZES=64,149,31,55
expect_fixture "the real helper's records of a non-final fragment that reaches the declared end are rejected" reject \
	"no recorded server datagram is malformed" live_case "${T}/live-boundary"
expect_fixture "valid records plus a truncated record are rejected" reject "the capture has a complete, valid per-kind result" \
	live_case "${T}/live-truncated"
for MODE in FAKE_CAPTURE_RC=42 FAKE_CAPTURE_MODE=crash FAKE_CAPTURE_MODE=premature FAKE_CAPTURE_MODE=stale \
	FAKE_CAPTURE_MODE=selfterm FAKE_CAPTURE_MODE=wrongcount FAKE_CAPTURE_MODE=extra FAKE_CAPTURE_MODE=endnoclock \
	FAKE_CAPTURE_MODE=endlate; do
	expect_fixture "a scenario whose capture has ${MODE} is rejected" reject "${LIVE_CAPTURE_TEXT}" live_case "${T}/live-valid" "${MODE}"
done
expect_fixture "a scenario whose capture never gets ready is rejected" reject "the capture started" \
	live_case "${T}/live-valid" FAKE_CAPTURE_MODE=noready
for MODE in FAKE_REPLAY_RC=42 FAKE_REPLAY_MODE=noinit; do
	expect_fixture "a scenario whose replay has ${MODE} is rejected" reject "one genuine initiation was replayed 400 times" \
		live_case "${T}/live-valid" "${MODE}"
done
expect_fixture "a scenario whose replay never gets ready is rejected" reject "the replay listens for the client's initiation" \
	live_case "${T}/live-valid" FAKE_REPLAY_MODE=noready
for KINDS_MODE in empty garbage; do
	expect_fixture "a scenario whose helper exits 0 with ${KINDS_MODE} output is rejected" reject \
		"the capture has a complete, valid per-kind result" live_case "${T}/live-valid" FAKE_KINDS="${KINDS_MODE}"
done

echo "=== The auto hint test's scenarios: planting and stale evidence (tests/test-boringtun-auto-hint-live.sh) ==="
# Its scenario runner, extracted verbatim, with every external step stubbed
# to succeed except the one a case breaks. Planting counts only with exit
# status 0 and exactly the report its kind gives; a scenario that did not run
# to the end is never judged, so no earlier scenario's files can stand in for
# its evidence.
HINT_LIVE="${SCRIPT_DIR}/test-boringtun-auto-hint-live.sh"
for FUNCTION in run_scenario scenario plant_ok plant_expected capture_format; do
	assert_true "${FUNCTION} is extracted from test-boringtun-auto-hint-live.sh" test -n "$(extract "${HINT_LIVE}" "${FUNCTION}")"
done
hint_case() { # [VAR=value...]: FIX_SENT, FIX_RC, FIX_SETUP, FIX_ORACLE, FIX_STALE
	# shellcheck disable=SC2034 # the fixture settings are read by the extracted functions
	(
		# shellcheck disable=SC2163 # the arguments are VAR=value assignments
		export FIX_SENT="sent 27" FIX_RC=0 FIX_SETUP=0 FIX_ORACLE="expect sip" FIX_STALE="" "$@"
		WORK="${T}/hint-work"
		rm -rf "${WORK}" && mkdir -p "${WORK}"
		NS_S=fixture NS_C=fixture VETH_S=fixture VETH_C=fixture IF_C=fixture ADDR_S=203.0.113.1 ADDR_C=203.0.113.2
		PORT=51998 CLIENT_PORT=41006 TUN_S=10.78.0.1 TUN_C=10.78.0.2 CAPTURE_SECONDS=12 S_SIZES=27,113,125,37 H_RANGES="${H}"
		SERVER_PUB="${FIXTURE_KEY}" CLIENT_PUB="${FIXTURE_KEY}" STUN_PRELUDE="${PRELUDES}/stun.hex" EXPECT=""
		PASSED=0 FAILED=0
		ok() { echo "  OK: $1"; PASSED=$((PASSED + 1)); }
		bad() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }
		check() { local M="$1"; shift; if "$@"; then ok "${M}"; else bad "${M}"; fi; }
		setup() { return "${FIX_SETUP}"; }
		start_server() { EPOCH=101; }
		sleep() { :; }
		wait_for() { shift; "$@"; }
		tunnel_ping() { :; }
		start_peer() { :; }
		ip() { :; }
		tunnel_up() { :; }
		bt_wire_capture_start() { BT_WIRE_CAPTURE_READY_CLOCK=100; echo fresh >"$6"; }
		bt_wire_capture_park() { :; }
		bt_wire_capture_resume() { :; }
		bt_wire_capture_finish() { :; }
		bt_wire_now() { BT_WIRE_NOW=200; }
		plant() { printf '%s\n' "${FIX_SENT}"; return "${FIX_RC}"; }
		python3() { if [[ "$2" == auto-expect ]]; then echo "${FIX_ORACLE}"; else command python3 "$@"; fi; }
		judge() { echo "  JUDGED $1 from: $(cat "${WORK}/$1.capture")"; ok "the stand-in judge ran"; }
		for FUNCTION in run_scenario scenario plant_ok plant_expected capture_format; do
			eval "$(extract "${HINT_LIVE}" "${FUNCTION}")"
		done
		[[ -z "${FIX_STALE}" ]] || printf 'STALE\n' | tee "${WORK}/hint.capture" "${WORK}/hint.expect" "${WORK}/hint.format" >/dev/null
		if declare -F scenario >/dev/null; then
			scenario hint hint 0 none sip
		else
			run_scenario hint hint 0
		fi
		echo "complete assertions=$((PASSED + FAILED)) failures=${FAILED}"
		((FAILED == 0))
	)
}
expect_fixture "a planted hint sent with exit 0 and the report 'sent 27' counts, and the scenario is judged" pass - hint_case
expect_fixture "planting that reports 'sent 27' but exits 1 fails the scenario" reject "sent from 203.0.113.2:41006 (exit 1, 'sent 27'" \
	hint_case FIX_RC=1
for REPORT in "sent 28" "sent 27 more" "sent 27:" ""; do
	expect_fixture "planting that exits 0 but reports '${REPORT}' fails the scenario" reject "sent from 203.0.113.2:41006 (exit 0, '${REPORT}'" \
		hint_case FIX_SENT="${REPORT}"
done
expect_fixture "a record that decides nothing fails the scenario" reject "decides what it selected for the client (undecided" \
	hint_case FIX_ORACLE="undecided no initiation from this client was recorded by the end of the window"
for CASE in "FIX_RC=1|planting failed" "FIX_SETUP=1|the setup failed" "FIX_ORACLE=undecided x|the record decided nothing"; do
	OUTPUT="$(hint_case FIX_STALE=1 "${CASE%%|*}" 2>&1)"
	assert_true "when ${CASE#*|}, an earlier scenario's files are removed and nothing is judged" \
		bash -c '[[ "$1" != *JUDGED* && "$1" == *"none of its evidence is judged"* ]] && ! grep -qs STALE "$2"/hint.expect "$2"/hint.format "$2"/hint.capture' \
		_ "${OUTPUT}" "${T}/hint-work"
done
assert_eq "sent 5: 104 108 95 57 95" "$(
	# shellcheck disable=SC2034 # read by the extracted plant_expected
	STUN_PRELUDE="${PRELUDES}/stun.hex"
	eval "$(extract "${HINT_LIVE}" plant_expected)"
	plant_expected stun-sequence
)" "the recorded STUN sequence is planted only with the report of all five datagrams, in order"

echo "=== The fixture judge itself ==="
crashing_fixture() {
	(exit 3)
}
empty_fixture() {
	echo "complete assertions=0 failures=0"
	return 1
}
JUDGE="$( (
	PASS=0 FAIL=0
	ok() { PASS=$((PASS + 1)); }
	not_ok() { FAIL=$((FAIL + 1)); }
	expect_fixture "crash" reject "anything" crashing_fixture
	expect_fixture "empty" reject "anything" empty_fixture
	echo "${PASS} ${FAIL}"
) )"
assert_eq "0 2" "${JUDGE}" "a fixture that crashed or made no assertion is never counted as a rejection"

echo
echo "${PASS} tests, ${FAIL} failures"
((FAIL == 0))
