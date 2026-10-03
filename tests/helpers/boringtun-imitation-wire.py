#!/usr/bin/env python3
"""Wire checks of BoringTun protocol imitation for the live tests.

  probe <kind> <host> <port>
      Send one probe of KIND (dns, stun, quic, quic-v1 or sip) to HOST:PORT
      over UDP and print what came back: servfail, binding-success,
      version-negotiation, silent, or unexpected:<length>. Each reply is
      matched to its own probe (transaction ID, connection IDs).

  capture <interface> <source address> <source port> <seconds> <file> [<layout>]
      Record every UDP datagram that arrives on INTERFACE from SOURCE
      ADDRESS:SOURCE PORT, one line each, until SECONDS have passed or a
      SIGTERM asks it to stop. Needs root (a packet socket). Relevance is
      decided by addresses, protocol and ports only, and every IPv4 and UDP
      length is validated before any byte is payload (frame_payload); a
      relevant frame that is not valid IPv4/UDP is recorded as malformed.
      Without LAYOUT a line is the payload's first 16 bytes (hex). With
      LAYOUT ("S1,S2,S3,S4,H1,H2,H3,H4", each H a number or MIN-MAX, the H
      ranges disjoint) a line is "<kind> <length> <prefix>": the packet kind
      is decided in memory from the length and the AmneziaWG type tag that
      follows the kind's S prefix, never from the prefix's content, and only
      the first 16 bytes of that S prefix are kept; "unknown", "ambiguous"
      and "malformed" keep none ("-"). The rest of each datagram is
      ciphertext and is never recorded. FILE.state gets "ready" once the
      socket listens, then "complete <records>" at the deadline or "stopped
      <records>" after a SIGTERM; both exit 0. Any other end leaves no final
      line and exits nonzero.

  classify <protocol> <file>
      For a capture without layout, print "<datagrams> <matching>": how many
      recorded prefixes have the shape PROTOCOL's imitation gives an S
      prefix (dns: header flags 0x0120 and QDCOUNT 1; stun: Binding Request
      type and magic cookie; quic: a 1-RTT short header; sip: a request
      line). Any line that is not a prefix -- a malformed frame, a per-kind
      record -- is refused (exit 1).

  kinds sip <file> <S1,S2,S3,S4>
      For a LAYOUT capture, after validating every record against the sizes
      (kind_records), print seven rows in this order:
      "<kind> <datagrams> <shaped> <expected> <verdict>" for init,
      response, cookie and transport, then "unknown <n>", "ambiguous <n>"
      and "malformed <n>". A SIP request line fits an S prefix of 31 bytes or
      more (SIP_REQUEST_LINE_MIN in the pinned BoringTun), so a kind whose S
      is at least 31 is expected "shaped" (every datagram), a shorter one
      "random" (none); the verdict is "ok", "FAIL", or "unobserved" when no
      datagram of the kind was seen, which proves nothing either way. A
      malformed record or argument prints nothing and exits 1.

  replay <interface> <client address> <server address> <server port> <layout> <count> <seconds>
      Print "ready" once listening, then wait up to SECONDS for one
      complete, unfragmented handshake initiation (kind "init") from CLIENT
      ADDRESS to SERVER ADDRESS:SERVER PORT on INTERFACE, send that datagram
      COUNT times to the server from a new UDP socket and print "replayed
      <count>"; any other end exits nonzero. A genuine initiation carries a
      valid mac1, so past the server's handshake rate limit each copy
      without a cookie MAC draws a cookie reply. The datagram is held in
      memory only.

The probe formats are those the pinned BoringTun classifies
(boringtun/src/noise/imitation/detect.rs at the pinned commit).
"""

import os
import re
import select
import signal
import socket
import struct
import sys
import time

STUN_COOKIE = bytes.fromhex("2112a442")
REPLY_TIMEOUT = 2.0


def dns_probe():
    txid = os.urandom(2)
    query = txid + bytes([0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    query += b"\x07example\x03com\x00" + bytes([0x00, 0x01, 0x00, 0x01])

    def check(reply):
        if len(reply) >= 12 and reply[:2] == txid and reply[2] & 0x80 and reply[3] & 0x0F == 2:
            return "servfail"
        return None

    return query, check


def stun_probe():
    txid = os.urandom(12)
    request = bytes([0x00, 0x01, 0x00, 0x00]) + STUN_COOKIE + txid

    def check(reply):
        if len(reply) >= 20 and reply[:2] == b"\x01\x01" and reply[4:8] == STUN_COOKIE and reply[8:20] == txid:
            return "binding-success"
        return None

    return request, check


def quic_probe(version):
    dcid, scid = os.urandom(8), os.urandom(8)
    initial = bytes([0xC3]) + struct.pack(">I", version) + bytes([8]) + dcid + bytes([8]) + scid
    initial += bytes(1200 - len(initial))

    def check(reply):
        # Version Negotiation: a long header, version 0, the probe's
        # connection IDs swapped.
        if (len(reply) >= 7 + 16 and reply[0] & 0x80 and reply[1:5] == b"\x00\x00\x00\x00"
                and reply[5] == 8 and reply[6:14] == scid and reply[14] == 8 and reply[15:23] == dcid):
            return "version-negotiation"
        return None

    return initial, check


def sip_probe():
    request = (b"OPTIONS sip:probe@example.com SIP/2.0\r\n"
               b"Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK0123456789\r\n"
               b"Max-Forwards: 70\r\nFrom: <sip:probe@example.com>;tag=1\r\n"
               b"To: <sip:probe@example.com>\r\nCall-ID: 0123456789@example.com\r\n"
               b"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
    return request, lambda reply: None


PROBES = {
    "dns": dns_probe,
    "stun": stun_probe,
    "quic": lambda: quic_probe(0x0A0A0A0A),  # a reserved (greasing) version
    "quic-v1": lambda: quic_probe(0x00000001),
    "sip": sip_probe,
}


def probe(kind, host, port):
    request, check = PROBES[kind]()
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.connect((host, int(port)))
        sock.send(request)
        deadline = time.monotonic() + REPLY_TIMEOUT
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([sock], [], [], left)[0]:
                return "silent"
            try:
                reply = sock.recv(65535)
            except ConnectionRefusedError:
                return "silent"
            verdict = check(reply)
            return verdict if verdict else "unexpected:%d" % len(reply)


# The AmneziaWG packet kinds: their S index and the size of the WireGuard
# message that follows the S prefix (boringtun/src/noise/mod.rs:
# HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ, COOKIE_REPLY_SZ and DATA_OVERHEAD_SZ,
# the smallest transport message).
KINDS = (("init", 0, 148), ("response", 1, 92), ("cookie", 2, 64), ("transport", 3, 32))
KIND_NAMES = tuple(name for name, _, _ in KINDS)
# Datagrams that are counted but have no packet kind: no kind's length and tag
# fit ("unknown"), more than one does ("ambiguous"), or the frame carrying a
# relevant datagram is not valid IPv4/UDP ("malformed").
SUMMARY_NAMES = ("unknown", "ambiguous", "malformed")
SIP_REQUEST_LINE_MIN = 31
# The S prefix bytes a record keeps, at most.
PREFIX_KEPT = 16
NUMBER = re.compile(r"0|[1-9][0-9]{0,9}")
STRICT_HEX = re.compile(r"(?:[0-9a-f]{2})*")


class InputError(ValueError):
    """A layout, capture or argument that is not what it must be."""


def parse_number(text, what, maximum):
    if not NUMBER.fullmatch(text) or int(text) > maximum:
        raise InputError("%s %r is not a number from 0 to %d" % (what, text, maximum))
    return int(text)


def parse_sizes(text):
    """"S1,S2,S3,S4" -> four S sizes (BoringTun keeps each in a u16)."""
    fields = text.split(",")
    if len(fields) != 4:
        raise InputError("sizes are S1,S2,S3,S4, not %r" % text)
    return [parse_number(field, "S%d" % (index + 1), 65535) for index, field in enumerate(fields)]


def parse_layout(text):
    """"S1,S2,S3,S4,H1,H2,H3,H4" -> ([S1..S4], [(min, max) for H1..H4]).
    Each H is a u32 or MIN-MAX with MIN <= MAX, and no two H ranges overlap,
    as BoringTun requires (ObfuscationRanges::new)."""
    fields = text.split(",")
    if len(fields) != 8:
        raise InputError("a layout is S1,S2,S3,S4,H1,H2,H3,H4, not %r" % text)
    sizes = parse_sizes(",".join(fields[:4]))
    ranges = []
    for index, field in enumerate(fields[4:]):
        low_text, dash, high_text = field.partition("-")
        low = parse_number(low_text, "H%d" % (index + 1), 0xFFFFFFFF)
        high = parse_number(high_text, "H%d" % (index + 1), 0xFFFFFFFF) if dash else low
        if low > high:
            raise InputError("H%d %r is an empty range" % (index + 1, field))
        ranges.append((low, high))
    for first in range(4):
        for second in range(first + 1, 4):
            if ranges[first][0] <= ranges[second][1] and ranges[second][0] <= ranges[first][1]:
                raise InputError("H%d and H%d overlap" % (first + 1, second + 1))
    return sizes, ranges


def classify_datagram(length, head, sizes, ranges):
    """The packet kind of a datagram of LENGTH bytes whose first bytes are
    HEAD (all of it, or the part a first IPv4 fragment carries): the kind
    whose length rule LENGTH meets and whose type tag, read little-endian
    after the kind's S prefix as the pinned BoringTun reads it, is in the
    kind's H range. "ambiguous" when more than one kind fits, "unknown" when
    none does. The prefix's content is never consulted."""
    found = []
    for name, index, size in KINDS:
        offset = sizes[index]
        if (length < offset + size) if name == "transport" else (length != offset + size):
            continue
        if len(head) < offset + 4:
            continue
        tag = struct.unpack("<I", head[offset:offset + 4])[0]
        low, high = ranges[index]
        if low <= tag <= high:
            found.append(name)
    if len(found) > 1:
        return "ambiguous"
    return found[0] if found else "unknown"


def kind_of(payload, sizes, ranges):
    """The packet kind of a complete datagram."""
    return classify_datagram(len(payload), payload, sizes, ranges)


# What the IPv4/UDP framing of one captured frame yields.
IGNORE = "ignore"            # not from the wanted source address and port
MALFORMED = "malformed"      # from the wanted source, but not valid IPv4/UDP
CONTINUATION = "continuation"  # a later fragment of a datagram already counted
DATAGRAM = "datagram"


def frame_payload(frame, source, source_port, destination=None, destination_port=None, first_fragments=None):
    """(status, datagram length, datagram bytes, fragmented) for one IPv4 frame.

    Relevance is decided by addressing alone: the IPv4 source address (and
    destination, when given), the IPv4 protocol, and the UDP ports. Every
    length is validated before any byte counts as payload: the IPv4 header
    length and total length within the frame, the UDP header within the IPv4
    payload, and the UDP length equal to the IPv4 payload -- or, for a first
    fragment, larger than it. A first fragment yields the datagram's declared
    length and only the bytes it carries, and its IP ID is remembered in
    FIRST_FRAGMENTS; a later fragment is a continuation of such a datagram, or
    malformed. Frames that cannot be validated from a relevant source are
    malformed, never skipped."""
    if len(frame) < 20:
        relevant = len(frame) >= 16 and frame[12:16] == source
        return (MALFORMED if relevant else IGNORE), len(frame), b"", False
    if frame[12:16] != source or (destination is not None and frame[16:20] != destination):
        return IGNORE, len(frame), b"", False
    header = (frame[0] & 0x0F) * 4
    total = struct.unpack(">H", frame[2:4])[0]
    if frame[0] >> 4 != 4 or header < 20 or total < header or total > len(frame):
        return MALFORMED, len(frame), b"", False
    if frame[9] != 17:
        return IGNORE, len(frame), b"", False
    fragment = struct.unpack(">H", frame[6:8])[0]
    offset, more = fragment & 0x1FFF, bool(fragment & 0x2000)
    body = frame[header:total]
    ident = bytes(frame[4:6])
    if offset:
        if first_fragments is not None and ident in first_fragments:
            return CONTINUATION, len(frame), b"", True
        return MALFORMED, len(frame), b"", True
    if len(body) < 8:
        return MALFORMED, len(frame), b"", more
    sport, dport, udp_length = struct.unpack(">HHH", body[:6])
    if sport != source_port or (destination_port is not None and dport != destination_port):
        return IGNORE, len(frame), b"", more
    if udp_length < 8:
        return MALFORMED, len(frame), b"", more
    if more:
        if udp_length <= len(body):
            return MALFORMED, len(frame), b"", True
        if first_fragments is not None:
            first_fragments.add(ident)
        return DATAGRAM, udp_length - 8, body[8:], True
    if udp_length != len(body):
        return MALFORMED, len(frame), b"", False
    return DATAGRAM, udp_length - 8, body[8:], False


def record_line(sizes, ranges, status, length, data):
    """The capture record of one relevant frame, or None for a continuation."""
    if status == CONTINUATION:
        return None
    if status == MALFORMED:
        return "malformed %d -" % length
    if sizes is None:
        return data[:PREFIX_KEPT].hex()
    kind = classify_datagram(length, data, sizes, ranges)
    if kind in SUMMARY_NAMES:
        return "%s %d -" % (kind, length)
    prefix = data[:min(PREFIX_KEPT, sizes[KIND_NAMES.index(kind)])]
    return "%s %d %s" % (kind, length, prefix.hex() or "-")


def write_state(path, line):
    with open(path, "a") as state:
        state.write(line + "\n")
        state.flush()
        os.fsync(state.fileno())


def capture(interface, source, source_port, seconds, path, layout=None):
    """Record the relevant datagrams, then write "complete <records>" to
    PATH.state at the deadline, or "stopped <records>" after a SIGTERM, the
    caller's controlled stop. "ready" is written once the socket is bound.
    Anything else -- an exception, another signal -- leaves no final line and
    a nonzero exit status. A record is always written whole: the stop request
    is only acted on between records."""
    sizes, ranges = parse_layout(layout) if layout else (None, None)
    wanted_source = socket.inet_aton(source)
    wanted_port = parse_number(source_port, "port", 65535)
    duration = float(seconds)
    state_path = path + ".state"
    stop = []
    wake_read, wake_write = os.pipe()
    os.set_blocking(wake_write, False)
    signal.set_wakeup_fd(wake_write)
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.append(signum))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    sock.bind((interface, 0))
    first_fragments = set()
    records = 0
    with open(path, "w") as out:
        write_state(state_path, "ready")
        deadline = time.monotonic() + duration
        while not stop:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            readable = select.select([sock, wake_read], [], [], left)[0]
            if wake_read in readable:
                os.read(wake_read, 64)
            if sock not in readable:
                continue
            status, length, data, _ = frame_payload(sock.recv(65535), wanted_source, wanted_port,
                                                    first_fragments=first_fragments)
            if status == IGNORE:
                continue
            line = record_line(sizes, ranges, status, length, data)
            if line is not None:
                out.write(line + "\n")
                out.flush()
                records += 1
    write_state(state_path, ("stopped %d" if stop else "complete %d") % records)


def replay(interface, client, server, server_port, layout, count, seconds):
    """Print "ready" once listening, then wait up to SECONDS for one complete,
    unfragmented handshake initiation from CLIENT to SERVER:SERVER_PORT, send
    it COUNT times and print "replayed <count>"; anything else exits nonzero."""
    sizes, ranges = parse_layout(layout)
    port = parse_number(server_port, "port", 65535)
    copies = parse_number(count, "count", 100000)
    # ETH_P_ALL: a packet socket bound to one protocol sees only incoming
    # frames, and the initiation leaves this interface.
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    sniffer.bind((interface, 0))
    wanted_client, wanted_server = socket.inet_aton(client), socket.inet_aton(server)
    print("ready", flush=True)
    deadline = time.monotonic() + float(seconds)
    initiation = None
    while initiation is None:
        left = deadline - time.monotonic()
        if left <= 0:
            print("no initiation seen", file=sys.stderr)
            return 1
        if not select.select([sniffer], [], [], left)[0]:
            continue
        frame, address = sniffer.recvfrom(65535)
        if address[1] != 0x0800 or len(frame) < 24 or frame[12:16] != wanted_client:
            continue
        header = (frame[0] & 0x0F) * 4
        if len(frame) < header + 2:
            continue
        own_port = struct.unpack(">H", frame[header:header + 2])[0]
        status, length, data, fragmented = frame_payload(frame, wanted_client, own_port, wanted_server, port)
        if status == DATAGRAM and not fragmented and kind_of(data, sizes, ranges) == "init":
            initiation = data
    sniffer.close()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((server, port))
        for _ in range(copies):
            sock.send(initiation)
    print("replayed %d" % copies, flush=True)
    return 0


def shaped(protocol, prefix):
    if protocol == "dns":
        return prefix[2:4] == b"\x01\x20" and prefix[4:6] == b"\x00\x01"
    if protocol == "stun":
        return prefix[:2] == b"\x00\x01" and prefix[4:8] == STUN_COOKIE
    if protocol == "quic":
        return len(prefix) > 0 and prefix[0] & 0xC0 == 0x40
    if protocol == "sip":
        return prefix[:12] in (b"OPTIONS sip:", b"REGISTER sip", b"MESSAGE sip:")
    return False


def capture_lines(path):
    """(line number, line) of a capture file, each ended by a newline; a
    file that is not ASCII or whose last line is unterminated is refused."""
    with open(path, "rb") as source:
        data = source.read()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise InputError("%s is not ASCII" % path) from None
    if text and not text.endswith("\n"):
        raise InputError("%s ends in an unterminated record" % path)
    return enumerate(text.splitlines(), 1)


def legacy_prefixes(path):
    """The prefixes of a capture without layout: one line of lowercase hex
    (at most 16 bytes) per datagram; an empty line is a datagram whose
    payload was empty, as capture writes it, and is not counted. A malformed
    frame, a per-kind record or anything else is refused."""
    for number, line in capture_lines(path):
        if line == "":
            continue
        if " " in line or not STRICT_HEX.fullmatch(line) or len(line) > 2 * PREFIX_KEPT:
            raise InputError("%s:%d is not a legacy prefix record: %r" % (path, number, line[:80]))
        yield bytes.fromhex(line)


def kind_records(path, sizes):
    """(kind, prefix bytes) of a capture with layout, every record checked
    against the layout's sizes: "<kind> <length> <prefix>" with single spaces,
    a known kind, a decimal length, and for a packet kind a length its rule
    allows and exactly min(16, S) prefix bytes of lowercase hex ("-" for
    none); a summary kind has "-". Anything else is refused, never skipped."""
    for number, line in capture_lines(path):
        fields = line.split(" ")
        where = "%s:%d" % (path, number)
        if len(fields) != 3:
            raise InputError("%s is not a per-kind record: %r" % (where, line[:80]))
        kind, length_text, prefix_text = fields
        if kind not in KIND_NAMES and kind not in SUMMARY_NAMES:
            raise InputError("%s has an unknown record kind %r" % (where, kind))
        length = parse_number(length_text, where + " length", 65535)
        if kind in SUMMARY_NAMES:
            if prefix_text != "-":
                raise InputError("%s: a %s record keeps no prefix" % (where, kind))
            yield kind, b""
            continue
        index = KIND_NAMES.index(kind)
        size = KINDS[index][2]
        rule_ok = length >= sizes[index] + size if kind == "transport" else length == sizes[index] + size
        if not rule_ok:
            raise InputError("%s: %d bytes is no %s for S%d=%d" % (where, length, kind, index + 1, sizes[index]))
        kept = min(PREFIX_KEPT, sizes[index])
        if kept == 0:
            if prefix_text != "-":
                raise InputError("%s: S%d=0 leaves no prefix" % (where, index + 1))
            yield kind, b""
            continue
        if not STRICT_HEX.fullmatch(prefix_text) or len(prefix_text) != 2 * kept:
            raise InputError("%s: the prefix must be %d bytes of lowercase hex" % (where, kept))
        yield kind, bytes.fromhex(prefix_text)


def classify(protocol, path):
    total = matching = 0
    for prefix in legacy_prefixes(path):
        total += 1
        matching += shaped(protocol, prefix)
    print(total, matching)


def kinds(protocol, path, sizes_text):
    """Every row at once, after the whole capture is validated: four packet
    kinds, then the three summaries, in this order."""
    if protocol != "sip":
        raise InputError("per-kind expectations are defined for sip only")
    sizes = parse_sizes(sizes_text)
    counts = {name: [0, 0] for name in KIND_NAMES}
    summary = {name: 0 for name in SUMMARY_NAMES}
    for kind, prefix in kind_records(path, sizes):
        if kind in summary:
            summary[kind] += 1
        else:
            counts[kind][0] += 1
            counts[kind][1] += shaped(protocol, prefix)
    rows = []
    for name, index, _ in KINDS:
        total, matching = counts[name]
        expected = "shaped" if sizes[index] >= SIP_REQUEST_LINE_MIN else "random"
        if total == 0:
            verdict = "unobserved"
        elif expected == "shaped":
            verdict = "ok" if matching == total else "FAIL"
        else:
            verdict = "ok" if matching == 0 else "FAIL"
        rows.append("%s %d %d %s %s" % (name, total, matching, expected, verdict))
    rows.extend("%s %d" % (name, summary[name]) for name in SUMMARY_NAMES)
    print("\n".join(rows))


def main(argv):
    try:
        if len(argv) == 4 and argv[0] == "probe" and argv[1] in PROBES:
            print(probe(argv[1], argv[2], argv[3]))
        elif len(argv) in (6, 7) and argv[0] == "capture":
            capture(*argv[1:])
        elif len(argv) == 3 and argv[0] == "classify":
            classify(argv[1], argv[2])
        elif len(argv) == 4 and argv[0] == "kinds":
            kinds(argv[1], argv[2], argv[3])
        elif len(argv) == 8 and argv[0] == "replay":
            return replay(*argv[1:])
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except InputError as error:
        print("ERROR: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
