#!/usr/bin/env python3
"""Wire checks of BoringTun protocol imitation for the live tests.

  probe <kind> <host> <port>
      Send one probe of KIND (dns, stun, quic, quic-v1 or sip) to HOST:PORT
      over UDP and print what came back: servfail, binding-success,
      version-negotiation, silent, or unexpected:<length>. Each reply is
      matched to its own probe (transaction ID, connection IDs).

  capture <interface> <source address> <source port> <seconds> <file> [<layout> <receiver key>]
      Record every UDP datagram that arrives on INTERFACE from SOURCE
      ADDRESS:SOURCE PORT, one line each, until SECONDS have passed or a
      SIGTERM asks it to stop. Needs root (a packet socket). Relevance is
      decided by addresses, protocol and ports only, and every IPv4 and UDP
      length is validated before any byte is payload (frame_payload); a
      relevant frame that is not valid IPv4/UDP, and a later fragment that
      fits no recorded first fragment (Fragments), is recorded as malformed.
      Without LAYOUT a line is the payload's first 16 bytes (hex). With
      LAYOUT ("S1,S2,S3,S4,H1,H2,H3,H4", each H a number or MIN-MAX, the H
      ranges disjoint) a line is "<kind> <length> <prefix>": the packet kind
      is decided in memory from the length and the AmneziaWG type tag that
      follows the kind's S prefix, never from the prefix's content, and only
      the first 16 bytes of that S prefix are kept; "unknown", "ambiguous",
      "unresolved" and "malformed" keep none ("-"). RECEIVER KEY is the
      static public key (base64) of the peer the datagrams are sent to. A
      complete datagram that fits more than one kind is resolved by MAC1
      consistency under that key and receiver-index correlation, in a fixed
      precedence (Evidence), and is ambiguous when that leaves more than one
      kind; neither check verifies a Noise handshake or any AEAD. The rest
      of each datagram is ciphertext and is never recorded. FILE.state is
      the transcript:
      "ready <pid> <start time> <ready clock>" once the socket listens, then
      exactly one end -- "complete <records> <end clock>" once SECONDS have
      passed since the ready clock, "stopped <records> <token>" after a
      SIGTERM that FILE.stop authorized (both exit 0), or "interrupted
      <records>" after one it did not (exit 3). The clocks are CLOCK_BOOTTIME
      in centiseconds, the clock of /proc/uptime. Any other end leaves no end
      line and exits nonzero.

  capture-to <destination port> <interface> <source address> <source port> <seconds> <file> [<layout> <receiver key>]
      capture, of the datagrams to DESTINATION PORT only: the stream to one
      client where several share an address. A first fragment of a datagram
      to another port is remembered (Fragments), so that its later
      fragments are skipped as that datagram's, never recorded as malformed
      ones of this stream; records, transcript and exit statuses are those
      of capture.

  classify <protocol> <file>
      For a capture without layout, print "<datagrams> <matching>": how many
      recorded prefixes have the shape PROTOCOL's imitation gives an S
      prefix (dns: header flags 0x0120 and QDCOUNT 1; stun: Binding Request
      type and magic cookie; quic: a 1-RTT short header; sip: a request
      line). Any line that is not a prefix -- a malformed frame, a per-kind
      record -- is refused (exit 1).

  classify-auto <dns|quic|sip|stun|none> <file>
      For a capture without layout of the datagrams to one client of an
      imitation auto server, print "<datagrams> <shaped> <replies> <other>":
      prefixes with the shape of that protocol's imitation (as classify),
      replies of its probe responder (servfail, binding-success,
      version-negotiation), and the rest. For none, an unresolved peer,
      shaped counts the prefixes with any dns, stun or sip shape. Refuses
      what classify refuses.

  send <kind> <host> <port> <source port>
      Send one probe of KIND (as probe) to HOST:PORT from SOURCE PORT and
      print "sent <length>", without waiting for a reply: under imitation
      auto, the first datagram a client's imitation sends, which leaves a
      hint for that source.

  kinds sip <file> <S1,S2,S3,S4>
      For a LAYOUT capture, after validating every record against the sizes
      (kind_records), print eight rows in this order:
      "<kind> <datagrams> <shaped> <expected> <verdict>" for init,
      response, cookie and transport, then "unknown <n>", "ambiguous <n>",
      "unresolved <n>" and "malformed <n>". A SIP request line fits an S prefix of 31 bytes or
      more (SIP_REQUEST_LINE_MIN in the pinned BoringTun), so a kind whose S
      is at least 31 is expected "shaped" (every datagram), a shorter one
      "random" (none); the verdict is "ok", "FAIL", or "unobserved" when no
      datagram of the kind was seen, which proves nothing either way. A
      malformed record or argument prints nothing and exits 1.

  replay <interface> <client address> <server address> <server port> <layout> <count> <seconds>
      Print "ready <pid> <start time>" once listening, then wait up to
      SECONDS for one complete, unfragmented handshake initiation (kind
      "init") from CLIENT ADDRESS to SERVER ADDRESS:SERVER PORT on INTERFACE,
      send that datagram COUNT times to the server from a new UDP socket and
      print "replayed <count>"; any other end exits nonzero. A genuine
      initiation carries a valid mac1, so past the server's handshake rate
      limit each copy without a cookie MAC draws a cookie reply. The datagram
      is held in memory only.

  owned <pid> <start time> <check|TERM|KILL|STOP>
      Probe or signal the process with that PID only if it is still the one
      that recorded that start time, through a pidfd (owned): never a process
      that was given the PID later. STOP returns once every thread of it is
      stopped.

The probe formats are those the pinned BoringTun classifies
(boringtun/src/noise/imitation/detect.rs at the pinned commit).
"""

import base64
import hashlib
import hmac
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


def send(kind, host, port, source_port):
    """Send one probe of KIND to HOST:PORT from SOURCE PORT, without waiting
    for a reply: under imitation auto, the datagram a client's own imitation
    sends first, which leaves a hint for that source address and port."""
    request, _ = PROBES[kind]()
    sport = parse_number(source_port, "source port", 65535)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", sport))
        sock.sendto(request, (host, int(port)))
    return "sent %d" % len(request)


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
# fit ("unknown"); more than one does ("ambiguous"); a kind whose length rule
# fits has its type tag beyond the bytes observed, as in a short first IPv4
# fragment, so no unique kind can be claimed ("unresolved"); or the frame
# carrying a relevant datagram is not valid IPv4/UDP ("malformed").
SUMMARY_NAMES = ("unknown", "ambiguous", "unresolved", "malformed")
SIP_REQUEST_LINE_MIN = 31
# The S prefix bytes a record keeps, at most.
PREFIX_KEPT = 16
NUMBER = re.compile(r"0|[1-9][0-9]{0,9}")
WIDE_NUMBER = re.compile(r"0|[1-9][0-9]{0,18}")
STRICT_HEX = re.compile(r"(?:[0-9a-f]{2})*")
# A stop authorization: one line of 32 lowercase hex digits.
STOP_TOKEN = re.compile(r"[0-9a-f]{32}")
# A WireGuard public key: 32 bytes in base64, 44 characters.
PUBLIC_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")
# The handshake kinds, whose messages end in mac1 and mac2 (16 bytes each),
# and the label of mac1's key (boringtun/src/noise/handshake.rs: LABEL_MAC1).
HANDSHAKES = ("init", "response")
MAC1_LABEL = b"mac1----"


class InputError(ValueError):
    """A layout, capture or argument that is not what it must be."""


def parse_number(text, what, maximum, pattern=NUMBER):
    if not pattern.fullmatch(text) or int(text) > maximum:
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


def parse_public_key(text):
    """A base64 WireGuard public key -> its 32 bytes."""
    if not PUBLIC_KEY.fullmatch(text):
        raise InputError("%r is not a base64 public key of 32 bytes" % text[:60])
    return base64.b64decode(text)


def message_of(datagram, sizes, kind):
    """The WireGuard message that reading DATAGRAM as KIND finds after the
    kind's S prefix: its fixed size, or for transport its 16-byte header."""
    index = KIND_NAMES.index(kind)
    size = 16 if kind == "transport" else KINDS[index][2]
    return datagram[sizes[index]:sizes[index] + size]


class Evidence:
    """MAC1 consistency and receiver-index correlation, used to resolve a
    complete datagram that fits more than one kind. Its purpose is to
    resolve accidental classification collisions in controlled AWG 2.0
    captures between correctly configured peers; it authenticates nothing.

    A handshake reading (init, response) is MAC1-valid (authentic()) when
    its mac1 field equals keyed BLAKE2s-128 over the message from its type
    tag up to mac1, keyed by BLAKE2s-256("mac1----" || the receiving peer's
    static public key), as BoringTun computes it after writing the tag
    (handshake.rs: append_mac1_and_mac2). It covers neither the S prefix nor
    the bytes after the message, so the SIP text under test plays no part.
    A valid mac1 shows only that the reading is consistent with a handshake
    message under a key derived from that public key: anyone who knows the
    key can compute one, so it does not authenticate the sender, verify a
    Noise handshake or establish an accepted session. Under a model of
    random bytes, an accidental reading of unrelated bytes matches with
    probability 2**-128; that bounds nothing a sender constructs.

    A response's receiver index (bytes 8-12) is recorded (learn) when a
    complete datagram is classified a response and its mac1 is valid. A
    transport reading whose receiver index (bytes 4-8) was recorded is
    correlated with that response (confirmed): server transport on a session
    the client initiated carries the index the response returned. The
    correlation is evidence for the reading, not a check of the transport's
    AEAD, replay counter or session membership; that unrelated bytes match a
    recorded index by accident is unlikely only under a byte-distribution
    assumption such as random bytes (about n/2**32 for n indices).

    Cookie readings are never checked: their AEAD is keyed by the server's
    static key and bound to the mac1 of the client's handshake that drew
    them, which this capture does not record.

    The precedence for a complete datagram with more than one reading
    (decide):
      1. MAC1-valid handshake readings take precedence over every other
         reading, a correlated transport included; more than one of them
         stays ambiguous.
      2. If no handshake reading is MAC1-valid, the handshake readings are
         removed.
      3. A remaining transport reading with a recorded receiver index takes
         precedence over an unchecked cookie reading.
      4. Otherwise the remaining readings stand: a sole one resolves by
         elimination, more than one stays ambiguous, and none is no kind.
    The pinned BoringTun receiver gates each reading on mac1 and then runs a
    Noise or AEAD trial (boringtun/src/noise/inbound.rs: receive); this
    helper runs neither trial, so it does not decide as that receiver does.
    A datagram that fits a single kind is classified syntactically and is
    not checked here."""

    def __init__(self, public_key):
        self.mac1_key = hashlib.blake2s(MAC1_LABEL + public_key).digest()
        self.sessions = set()

    def authentic(self, message):
        """Whether the mac1 of a complete handshake MESSAGE is valid under
        the receiving peer's key: consistency, not authentication."""
        mac1 = hashlib.blake2s(message[:-32], digest_size=16, key=self.mac1_key).digest()
        return hmac.compare_digest(mac1, message[-32:-16])

    def decide(self, datagram, sizes, readings):
        """The READINGS of a complete DATAGRAM that remain under the
        precedence above: the MAC1-valid handshake readings, if any;
        otherwise the readings that are not handshakes, narrowed to the
        transport reading when its receiver index was recorded, the rest
        being cookie readings."""
        authentic = [kind for kind in readings
                     if kind in HANDSHAKES and self.authentic(message_of(datagram, sizes, kind))]
        if authentic:
            return authentic
        rest = [kind for kind in readings if kind not in HANDSHAKES]
        if "transport" in rest and self.confirmed(datagram, sizes):
            return ["transport"]
        return rest

    def confirmed(self, datagram, sizes):
        """Whether reading DATAGRAM as transport gives a receiver index
        recorded from a MAC1-valid response: correlation only."""
        receiver = struct.unpack("<I", message_of(datagram, sizes, "transport")[4:8])[0]
        return receiver in self.sessions

    def learn(self, datagram, sizes):
        """Record the receiver index of a complete DATAGRAM classified a
        response, if its mac1 is valid."""
        response = message_of(datagram, sizes, "response")
        if self.authentic(response):
            self.sessions.add(struct.unpack("<I", response[8:12])[0])


def classify_datagram(length, head, sizes, ranges, evidence=None):
    """The packet kind of a datagram of LENGTH bytes whose first bytes are
    HEAD (all of it, or the part a first IPv4 fragment carries): the kind
    whose length rule LENGTH meets and whose type tag, read little-endian
    after the kind's S prefix as the pinned BoringTun reads it, is in the
    kind's H range. "ambiguous" when more than one kind fits; "unresolved"
    when a kind whose length rule LENGTH meets has its tag beyond HEAD, so
    that a unique kind cannot be claimed; "unknown" when no kind fits. The
    prefix's content is never consulted. With EVIDENCE (an Evidence) and
    the whole datagram in HEAD, more than one fitting kind is first
    resolved by the precedence of Evidence.decide (MAC1 consistency, then
    receiver-index correlation), and is ambiguous only if that leaves more
    than one; a fragment is never resolved that way. A complete datagram
    classified a response has its receiver index recorded in EVIDENCE if
    its mac1 is valid (Evidence.learn)."""
    found = []
    unseen = False
    for name, index, size in KINDS:
        offset = sizes[index]
        if (length < offset + size) if name == "transport" else (length != offset + size):
            continue
        if len(head) < offset + 4:
            unseen = True
            continue
        tag = struct.unpack("<I", head[offset:offset + 4])[0]
        low, high = ranges[index]
        if low <= tag <= high:
            found.append(name)
    complete = evidence is not None and len(head) == length
    if complete and len(found) > 1:
        found = evidence.decide(head, sizes, found)
    if len(found) > 1:
        return "ambiguous"
    if unseen:
        return "unresolved"
    if not found:
        return "unknown"
    if complete and found[0] == "response":
        evidence.learn(head, sizes)
    return found[0]


def kind_of(payload, sizes, ranges, evidence=None):
    """The packet kind of a complete datagram."""
    return classify_datagram(len(payload), payload, sizes, ranges, evidence)


# What the IPv4/UDP framing of one captured frame yields.
IGNORE = "ignore"            # not from the wanted source address and port
MALFORMED = "malformed"      # from the wanted source, but not valid IPv4/UDP
CONTINUATION = "continuation"  # a later fragment that fits a recorded first fragment
DATAGRAM = "datagram"


class Fragments:
    """The first fragments of relevant datagrams whose later fragments are
    still due, so that a later fragment counts as the continuation only of a
    datagram whose first fragment was recorded, and only where it fits.

    An entry is keyed by the IPv4 source, destination and identification --
    the IP ID alone names no datagram -- and keeps the datagram's IP payload
    length (its declared UDP length) and the byte ranges seen. A later
    fragment is a continuation only if it lies inside that payload and
    overlaps nothing seen; the last fragment (More Fragments clear) must end
    the payload exactly, and any other must carry a multiple of 8 bytes and
    end before the payload does, since the fragments it says will follow need
    room. So only the last fragment can account for the payload's final
    byte, in whatever order the fragments come, and an entry is retired once
    every byte is accounted for, the last fragment included; after that the
    same key names no datagram. An entry also expires TIMEOUT seconds after
    its first fragment (the Linux default ipfrag_time). This is bookkeeping,
    not reassembly: the bytes of later fragments are never inspected, and a
    datagram whose later fragments never arrive is not reported."""

    TIMEOUT = 30.0

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.entries = {}

    def _expire(self):
        now = self.clock()
        for key in [key for key, entry in self.entries.items() if now - entry[2] > self.TIMEOUT]:
            del self.entries[key]
        return now

    def first(self, key, total, carried):
        """A first fragment carrying CARRIED of the datagram's TOTAL IP payload
        bytes. False if a datagram with this key is already in progress."""
        now = self._expire()
        if key in self.entries:
            return False
        self.entries[key] = [total, [(0, carried)], now]
        return True

    def later(self, key, offset, length, last):
        """A later fragment carrying LENGTH bytes at byte OFFSET; LAST when its
        More Fragments flag is clear. False unless it fits as described."""
        self._expire()
        entry = self.entries.get(key)
        if entry is None:
            return False
        total, seen, _ = entry
        end = offset + length
        if length == 0:
            return False
        if (end != total) if last else (length % 8 or end >= total):
            return False
        if any(start < end and offset < stop for start, stop in seen):
            return False
        seen.append((offset, end))
        if sum(stop - start for start, stop in seen) == total:
            del self.entries[key]
        return True


def frame_payload(frame, source, source_port, destination=None, destination_port=None, fragments=None):
    """(status, datagram length, datagram bytes, fragmented) for one IPv4 frame.

    Relevance is decided by addressing alone: the IPv4 source address (and
    destination, when given), the IPv4 protocol, and the UDP ports. Every
    length is validated before any byte counts as payload: the IPv4 header
    length and total length within the frame, the UDP header within the IPv4
    payload, and the UDP length equal to the IPv4 payload -- or, for a first
    fragment, larger than it and a multiple of 8 bytes carried. A first
    fragment yields the datagram's declared length and only the bytes it
    carries; with FRAGMENTS (a Fragments) it is recorded there, and a later
    fragment is a continuation only if FRAGMENTS accepts it. Frames that cannot
    be validated from a relevant source are malformed, never skipped."""
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
    key = (bytes(frame[12:16]), bytes(frame[16:20]), bytes(frame[4:6]))
    if offset:
        if fragments is not None and fragments.later(key, offset * 8, len(body), not more):
            return CONTINUATION, len(frame), b"", True
        return MALFORMED, len(frame), b"", True
    if len(body) < 8:
        return MALFORMED, len(frame), b"", more
    sport, dport, udp_length = struct.unpack(">HHH", body[:6])
    if sport != source_port or (destination_port is not None and dport != destination_port):
        if (more and fragments is not None and destination_port is not None and sport == source_port
                and udp_length > len(body) and not len(body) % 8):
            # The first fragment of a datagram to another port: its later
            # fragments, which carry no ports, are then continuations.
            fragments.first(key, udp_length, len(body))
        return IGNORE, len(frame), b"", more
    if udp_length < 8:
        return MALFORMED, len(frame), b"", more
    if more:
        if udp_length <= len(body) or len(body) % 8:
            return MALFORMED, len(frame), b"", True
        if fragments is not None and not fragments.first(key, udp_length, len(body)):
            return MALFORMED, len(frame), b"", True
        return DATAGRAM, udp_length - 8, body[8:], True
    if udp_length != len(body):
        return MALFORMED, len(frame), b"", False
    return DATAGRAM, udp_length - 8, body[8:], False


def record_line(sizes, ranges, status, length, data, evidence=None):
    """The capture record of one relevant frame, or None for a continuation."""
    if status == CONTINUATION:
        return None
    if status == MALFORMED:
        return "malformed %d -" % length
    if sizes is None:
        return data[:PREFIX_KEPT].hex()
    kind = classify_datagram(length, data, sizes, ranges, evidence)
    if kind in SUMMARY_NAMES:
        return "%s %d -" % (kind, length)
    prefix = data[:min(PREFIX_KEPT, sizes[KIND_NAMES.index(kind)])]
    return "%s %d %s" % (kind, length, prefix.hex() or "-")


def write_state(path, line):
    with open(path, "a") as state:
        state.write(line + "\n")
        state.flush()
        os.fsync(state.fileno())


def stat_fields(path):
    """The fields of a /proc/<pid>/stat file after the command name: [0] is
    the state (field 3), [1] the parent PID (field 4), [19] the start time in
    clock ticks after boot (field 22)."""
    with open(path) as stat:
        return stat.read().rsplit(")", 1)[1].split()


def own_identity():
    """This process's PID and start time, as the shell tracker records them."""
    return os.getpid(), int(stat_fields("/proc/self/stat")[19])


def stop_token(path):
    """The stop authorization in PATH, or None."""
    try:
        with open(path) as authorization:
            text = authorization.read(100)
    except FileNotFoundError:
        return None
    token = text[:-1] if text.endswith("\n") else text
    return token if STOP_TOKEN.fullmatch(token) else None


def boot_centiseconds(nanoseconds):
    """A CLOCK_BOOTTIME reading in whole centiseconds, as /proc/uptime gives
    the same clock to the shell."""
    return nanoseconds // 10 ** 7


def capture(interface, source, source_port, seconds, path, layout=None, receiver=None, destination_port=None):
    """Record the relevant datagrams; return the exit status. With
    DESTINATION_PORT, only those sent to that port are relevant. With LAYOUT,
    RECEIVER is the base64 static public key of the peer they are sent to:
    the key under which Evidence checks mac1 when a datagram fits more than
    one kind, its receiver indices recorded in the order the datagrams
    arrive. Its format is checked; whether it is the intended peer's key is
    not.

    PATH.state is the transcript: "ready <pid> <start time> <ready clock>"
    once the socket is bound, then exactly one end. The clock is CLOCK_BOOTTIME
    in centiseconds, the clock of /proc/uptime, read when the capture is ready;
    its deadline is SECONDS after that reading. At the deadline, "complete
    <records> <end clock>" (status 0), the end clock read once the deadline
    has passed: the end clock is at least SECONDS later than the ready clock.
    On SIGTERM, "stopped <records> <token>" (status 0) when PATH.stop holds
    the caller's stop authorization, else "interrupted <records>" (status 3):
    a TERM nobody authorized is not a controlled stop. A PATH.stop that exists
    before the start is refused. Anything else -- an exception, another
    signal -- leaves no end line and a nonzero status. A record is always
    written whole: a stop is only acted on between records."""
    sizes, ranges = parse_layout(layout) if layout else (None, None)
    evidence = Evidence(parse_public_key(receiver)) if layout else None
    wanted_source = socket.inet_aton(source)
    wanted_port = parse_number(source_port, "port", 65535)
    wanted_destination = None if destination_port is None else parse_number(destination_port, "destination port", 65535)
    duration = parse_number(seconds, "capture seconds", 86400) * 10 ** 9
    state_path, stop_path = path + ".state", path + ".stop"
    if os.path.lexists(stop_path):
        raise InputError("%s exists before the capture started" % stop_path)
    stop = []
    wake_read, wake_write = os.pipe()
    os.set_blocking(wake_write, False)
    signal.set_wakeup_fd(wake_write)
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.append(signum))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    sock.bind((interface, 0))
    fragments = Fragments()
    records = 0
    with open(path, "w") as out:
        ready = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        write_state(state_path, "ready %d %d %d" % (own_identity() + (boot_centiseconds(ready),)))
        deadline = ready + duration
        while not stop:
            left = deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            if left <= 0:
                break
            readable = select.select([sock, wake_read], [], [], left / 10 ** 9)[0]
            if wake_read in readable:
                os.read(wake_read, 64)
            if sock not in readable:
                continue
            status, length, data, _ = frame_payload(sock.recv(65535), wanted_source, wanted_port,
                                                    destination_port=wanted_destination, fragments=fragments)
            if status == IGNORE:
                continue
            line = record_line(sizes, ranges, status, length, data, evidence)
            if line is not None:
                out.write(line + "\n")
                out.flush()
                records += 1
    if not stop:
        end = boot_centiseconds(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        write_state(state_path, "complete %d %d" % (records, end))
        return 0
    token = stop_token(stop_path)
    if token is None:
        write_state(state_path, "interrupted %d" % records)
        return 3
    write_state(state_path, "stopped %d %s" % (records, token))
    return 0


def replay(interface, client, server, server_port, layout, count, seconds):
    """Print "ready <pid> <start time>" once listening, then wait up to
    SECONDS for one complete, unfragmented handshake initiation from CLIENT to
    SERVER:SERVER_PORT, send it COUNT times and print "replayed <count>";
    anything else exits nonzero."""
    sizes, ranges = parse_layout(layout)
    port = parse_number(server_port, "port", 65535)
    copies = parse_number(count, "count", 100000)
    # ETH_P_ALL: a packet socket bound to one protocol sees only incoming
    # frames, and the initiation leaves this interface.
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    sniffer.bind((interface, 0))
    wanted_client, wanted_server = socket.inet_aton(client), socket.inet_aton(server)
    print("ready %d %d" % own_identity(), flush=True)
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


OWNED_ACTIONS = {"check": None, "TERM": signal.SIGTERM, "KILL": signal.SIGKILL, "STOP": signal.SIGSTOP}


def all_stopped(fd, pid, start):
    """Whether every thread of the process behind the pidfd FD is stopped;
    None once it has exited (the pidfd turns readable) or its PID names
    another process."""
    if select.select([fd], [], [], 0)[0]:
        return None
    try:
        states = [stat_fields("/proc/%d/task/%s/stat" % (pid, task))[0] for task in os.listdir("/proc/%d/task" % pid)]
        if int(stat_fields("/proc/%d/stat" % pid)[19]) != start:
            return None
    except (FileNotFoundError, ProcessLookupError):
        return None
    return bool(states) and all(state in ("T", "t") for state in states)


def owned(pid_text, start_text, action):
    """Probe or signal one process the caller started, named by its PID and
    the start time it recorded itself (field 22 of /proc/PID/stat), never a
    process that was given the same PID later. A pidfd is opened first and the
    identity checked through /proc afterwards: an open pidfd refers to one
    process, so a signal sent through it reaches that process or nothing.
    STOP also waits, up to 2 s, until every thread of it is stopped: it can
    then change nothing until it is continued or killed. Prints "running",
    "signalled" or "stopped" (exit 0), or "gone", "replaced", "exited" or,
    for a STOP not seen to take hold, "running" (exit 1)."""
    pid = parse_number(pid_text, "PID", 4194304)
    start = parse_number(start_text, "start time", 2 ** 62, WIDE_NUMBER)
    if action not in OWNED_ACTIONS:
        raise InputError("the action is check, TERM, KILL or STOP, not %r" % action)
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        print("gone")
        return 1
    try:
        try:
            fields = stat_fields("/proc/%d/stat" % pid)
        except FileNotFoundError:
            print("gone")
            return 1
        if int(fields[19]) != start:
            print("replaced")
            return 1
        if fields[0] in ("Z", "X"):
            print("exited")
            return 1
        if OWNED_ACTIONS[action] is None:
            print("running")
            return 0
        try:
            signal.pidfd_send_signal(fd, OWNED_ACTIONS[action])
        except ProcessLookupError:
            print("exited")
            return 1
        if action != "STOP":
            print("signalled")
            return 0
        deadline = time.monotonic() + 2
        while True:
            stopped = all_stopped(fd, pid, start)
            if stopped is None:
                print("exited")
                return 1
            if stopped:
                print("stopped")
                return 0
            if time.monotonic() > deadline:
                print("running")
                return 1
            time.sleep(0.005)
    finally:
        os.close(fd)


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


def probe_reply(protocol, prefix):
    """Whether PREFIX starts a reply of PROTOCOL's probe responder (a DNS
    response with one question, a STUN Binding Success, a QUIC Version
    Negotiation), which never has the shape of that imitation's S prefix."""
    if protocol == "dns":
        return len(prefix) >= 6 and bool(prefix[2] & 0x80) and prefix[4:6] == b"\x00\x01"
    if protocol == "stun":
        return prefix[:2] == b"\x01\x01" and prefix[4:8] == STUN_COOKIE
    if protocol == "quic":
        return len(prefix) >= 5 and bool(prefix[0] & 0x80) and prefix[1:5] == b"\x00\x00\x00\x00"
    return False


# What an unresolved peer's random S padding must not look like. QUIC's short
# header is a single bit pattern that a quarter of random first bytes have.
UNRESOLVED_SHAPES = ("dns", "stun", "sip")


def classify_auto(protocol, path):
    """For a capture without layout of the datagrams to one client of an auto
    server, print "<datagrams> <shaped> <replies> <other>": prefixes with the
    shape of PROTOCOL's imitation, replies of its probe responder (to the
    client's own imitation datagrams), and the rest. For "none", an
    unresolved peer, shaped counts the prefixes that have any of the dns,
    stun or sip shapes."""
    if protocol not in ("dns", "quic", "sip", "stun", "none"):
        raise InputError("no auto classification for %r" % protocol)
    total = matching = replies = 0
    for prefix in legacy_prefixes(path):
        total += 1
        if protocol == "none":
            matching += any(shaped(name, prefix) for name in UNRESOLVED_SHAPES)
        elif shaped(protocol, prefix):
            matching += 1
        elif probe_reply(protocol, prefix):
            replies += 1
    print(total, matching, replies, total - matching - replies)


def kinds(protocol, path, sizes_text):
    """Every row at once, after the whole capture is validated: four packet
    kinds, then the four summaries, in this order."""
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
        elif len(argv) in (6, 8) and argv[0] == "capture":
            return capture(*argv[1:])
        elif len(argv) in (7, 9) and argv[0] == "capture-to":
            return capture(*argv[2:], destination_port=argv[1])
        elif len(argv) == 3 and argv[0] == "classify":
            classify(argv[1], argv[2])
        elif len(argv) == 3 and argv[0] == "classify-auto":
            classify_auto(argv[1], argv[2])
        elif len(argv) == 5 and argv[0] == "send" and argv[1] in PROBES:
            print(send(*argv[1:]))
        elif len(argv) == 4 and argv[0] == "kinds":
            kinds(argv[1], argv[2], argv[3])
        elif len(argv) == 8 and argv[0] == "replay":
            return replay(*argv[1:])
        elif len(argv) == 4 and argv[0] == "owned":
            return owned(*argv[1:])
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except InputError as error:
        print("ERROR: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
