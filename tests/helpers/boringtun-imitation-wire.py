#!/usr/bin/env python3
"""Wire checks of BoringTun protocol imitation for the live tests.

  probe <kind> <host> <port>
      Send one probe of KIND (dns, stun, quic, quic-v1 or sip) to HOST:PORT
      over UDP and print what came back: servfail, binding-success,
      version-negotiation, silent, or unexpected:<length>. Each reply is
      matched to its own probe (transaction ID, connection IDs).

  capture <interface> <source address> <source port> <seconds> <file> [<layout>]
      Record, for SECONDS, every UDP payload that arrives on INTERFACE from
      SOURCE ADDRESS:SOURCE PORT, one line each. Needs root (a packet
      socket). Without LAYOUT a line is the payload's first 16 bytes (hex).
      With LAYOUT ("S1,S2,S3,S4,H1,H2,H3,H4", each H a number or MIN-MAX) a
      line is "<kind> <length> <prefix>": the packet kind is decided in
      memory from the length and the AmneziaWG type tag that follows the
      kind's S prefix, never from the prefix's content, and only the first
      16 bytes of that S prefix are kept (kind "unknown" keeps none). The
      rest of each datagram is ciphertext and is never recorded.

  classify <protocol> <file>
      Print "<datagrams> <matching>": how many recorded prefixes have the
      shape PROTOCOL's imitation gives an S prefix (dns: header flags 0x0120
      and QDCOUNT 1; stun: Binding Request type and magic cookie; quic: a
      1-RTT short header; sip: a request line).

  kinds sip <file> <S1,S2,S3,S4>
      For a LAYOUT capture, one line per packet kind:
      "<kind> <datagrams> <shaped> <expected> <verdict>". A SIP request line
      fits an S prefix of 31 bytes or more (SIP_REQUEST_LINE_MIN in the
      pinned BoringTun), so a kind whose S is at least 31 is expected
      "shaped" (every datagram), a shorter one "random" (none); the verdict
      is "ok", "FAIL", or "unobserved" when no datagram of the kind was
      seen, which proves nothing either way. A last line "unknown <n>"
      counts datagrams of no kind.

  replay <interface> <client address> <server address> <server port> <layout> <count> <seconds>
      Wait up to SECONDS for one handshake initiation (kind "init") from
      CLIENT ADDRESS to SERVER ADDRESS:SERVER PORT on INTERFACE, then send
      that datagram COUNT times to the server from a new UDP socket and
      print "replayed <count>". A genuine initiation carries a valid mac1,
      so past the server's handshake rate limit each copy without a cookie
      MAC draws a cookie reply. The datagram is held in memory only.

The probe formats are those the pinned BoringTun classifies
(boringtun/src/noise/imitation/detect.rs at the pinned commit).
"""

import os
import select
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
SIP_REQUEST_LINE_MIN = 31


def parse_layout(text):
    """"S1,S2,S3,S4,H1,H2,H3,H4" -> ([S1..S4], [(min, max) for H1..H4])."""
    fields = text.split(",")
    if len(fields) != 8:
        raise ValueError("a layout is S1,S2,S3,S4,H1,H2,H3,H4")
    sizes = [int(field) for field in fields[:4]]
    ranges = []
    for field in fields[4:]:
        low, _, high = field.partition("-")
        ranges.append((int(low), int(high or low)))
    return sizes, ranges


def kind_of(payload, sizes, ranges):
    """The packet kind of a datagram, from its length and the type tag after
    the kind's S prefix (little-endian, as the pinned BoringTun reads it), or
    "unknown". The prefix's content is never consulted."""
    found = []
    for name, index, size in KINDS:
        offset = sizes[index]
        exact = name != "transport"
        if (len(payload) != offset + size) if exact else (len(payload) < offset + size):
            continue
        tag = struct.unpack("<I", payload[offset:offset + 4])[0]
        low, high = ranges[index]
        if low <= tag <= high:
            found.append(name)
    return found[0] if len(found) == 1 else "unknown"


def udp_from(packet, wanted_source, wanted_port, wanted_destination=None, wanted_destination_port=None):
    """The UDP payload of an IPv4 packet from SOURCE:PORT (and to
    DESTINATION:PORT when given), or None."""
    if len(packet) < 28 or packet[9] != 17 or packet[12:16] != wanted_source:
        return None
    if wanted_destination is not None and packet[16:20] != wanted_destination:
        return None
    header = (packet[0] & 0x0F) * 4
    udp = packet[header:header + 8]
    if len(udp) < 8 or struct.unpack(">H", udp[:2])[0] != wanted_port:
        return None
    if wanted_destination_port is not None and struct.unpack(">H", udp[2:4])[0] != wanted_destination_port:
        return None
    return packet[header + 8:]


def capture(interface, source, source_port, seconds, path, layout=None):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    sock.bind((interface, 0))
    wanted_source = socket.inet_aton(source)
    wanted_port = int(source_port)
    sizes, ranges = parse_layout(layout) if layout else (None, None)
    deadline = time.monotonic() + float(seconds)
    with open(path, "w") as out:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            if not select.select([sock], [], [], left)[0]:
                continue
            payload = udp_from(sock.recv(65535), wanted_source, wanted_port)
            if payload is None:
                continue
            if sizes is None:
                out.write(payload[:16].hex() + "\n")
            else:
                kind = kind_of(payload, sizes, ranges)
                if kind == "unknown":
                    out.write("unknown %d -\n" % len(payload))
                else:
                    prefix = payload[:min(16, sizes[[k[0] for k in KINDS].index(kind)])]
                    out.write("%s %d %s\n" % (kind, len(payload), prefix.hex() or "-"))
            out.flush()


def replay(interface, client, server, server_port, layout, count, seconds):
    sizes, ranges = parse_layout(layout)
    # ETH_P_ALL: a packet socket bound to one protocol sees only incoming
    # frames, and the initiation leaves this interface.
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    sniffer.bind((interface, 0))
    wanted_client, wanted_server = socket.inet_aton(client), socket.inet_aton(server)
    deadline = time.monotonic() + float(seconds)
    initiation = None
    while initiation is None:
        left = deadline - time.monotonic()
        if left <= 0:
            print("no initiation seen", file=sys.stderr)
            return 1
        if not select.select([sniffer], [], [], left)[0]:
            continue
        packet, address = sniffer.recvfrom(65535)
        if address[1] != 0x0800 or len(packet) < 28 or packet[12:16] != wanted_client:
            continue
        header = (packet[0] & 0x0F) * 4
        payload = udp_from(packet, wanted_client, struct.unpack(">H", packet[header:header + 2])[0],
                           wanted_server, int(server_port))
        if payload is not None and kind_of(payload, sizes, ranges) == "init":
            initiation = payload
    sniffer.close()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((server, int(server_port)))
        for _ in range(int(count)):
            sock.send(initiation)
    print("replayed %d" % int(count))
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


def records(path):
    """(kind, prefix bytes) per recorded datagram, of either capture format."""
    with open(path) as lines:
        for line in lines:
            fields = line.split()
            if len(fields) == 1:
                yield None, bytes.fromhex(fields[0])
            elif len(fields) == 3:
                yield fields[0], b"" if fields[2] == "-" else bytes.fromhex(fields[2])


def classify(protocol, path):
    total = matching = 0
    for _, prefix in records(path):
        total += 1
        matching += shaped(protocol, prefix)
    print(total, matching)


def kinds(protocol, path, sizes_text):
    if protocol != "sip":
        raise ValueError("per-kind expectations are defined for sip only")
    sizes = [int(size) for size in sizes_text.split(",")]
    if len(sizes) != 4:
        raise ValueError("sizes are S1,S2,S3,S4")
    counts = {name: [0, 0] for name, _, _ in KINDS}
    unknown = 0
    for kind, prefix in records(path):
        if kind in counts:
            counts[kind][0] += 1
            counts[kind][1] += shaped(protocol, prefix)
        else:
            unknown += 1
    for name, index, _ in KINDS:
        total, matching = counts[name]
        expected = "shaped" if sizes[index] >= SIP_REQUEST_LINE_MIN else "random"
        if total == 0:
            verdict = "unobserved"
        elif expected == "shaped":
            verdict = "ok" if matching == total else "FAIL"
        else:
            verdict = "ok" if matching == 0 else "FAIL"
        print(name, total, matching, expected, verdict)
    print("unknown", unknown)


def main(argv):
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
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
