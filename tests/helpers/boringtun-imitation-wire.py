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

  record <destination port> <interface|any> <source address[,address...]> <source port|any> <seconds> <file>
      capture-to, but every datagram is recorded whole, with the clock it
      was received at: "<clock> <source address> <source port> <length>
      <hex>"; the first fragment of a fragmented datagram as "<clock>
      <address> <port> fragment <length>", a frame that is not valid
      IPv4/UDP as "<clock> <address> - malformed <length> <its first 40
      bytes>", and frames its packet socket dropped (PACKET_STATISTICS,
      polled after every wakeup, into a 32 MiB receive buffer) as "<clock> -
      drops <count> <clock of the poll before>". Several source
      addresses, any source port, and with "any" every interface of the
      namespace, also one created later: what reached the server from its
      clients, in arrival order. Transcript and exit statuses are capture's.

  auto-expect <record> <address> <port> <layout> <server public key> <hp key file|-> <on|off> <epoch> <start> <end> [<establishments|-> [<connected|->]]
      From a finished record (its transcript checked) and the scenario's
      evidence, derive what an imitation auto server selects for the client
      at ADDRESS:PORT, by the pinned BoringTun's own rules restated here (see
      "Imitation auto" below): which of its datagrams fit an AmneziaWG packet
      kind under LAYOUT (through the header-protection mask when HP KEY FILE
      holds the base64 key; "on" for RandomTrailers), which protocol each of
      the others is detected as, the listener's hints and a connected
      socket's own, the selection at an accepted initiation, and the
      header-protection policy. Nothing the server sent is consulted, and no
      datagram's syntax counts as proof that it was accepted: every
      initiation candidate may or may not have been, as ESTABLISHMENTS allow
      ("<client start>:<first ping>,...": some initiation that client process
      sent was accepted and answered by its first ping). CONNECTED is when a
      socket connected to the client's endpoint was seen; without it, where
      the endpoint's datagrams moved to that socket is open. Each history the
      evidence allows is replayed, with every hint-lifetime comparison the
      arrival and processing bounds leave open taken both ways; prints one
      history's trace, then "expect <dns|quic|sip|stun|random>" for the
      server's datagrams to that client between the clocks START and END
      (centiseconds of CLOCK_BOOTTIME) if every history gives it. EPOCH is
      when the server's state was last empty; the record must have been ready
      before it and be complete through END. Otherwise "undecided <reason>"
      (exit 1): histories that disagree, a clock step, frames the record
      dropped or could not read from the epoch until the selection was
      certainly pinned, no initiation, or a history the model does not
      support (see auto_expect).

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

  send sip <host> <port> <source port>
      Send the SIP hint (a 27-byte request line, shorter than any AmneziaWG
      datagram, so never taken for one) to HOST:PORT from SOURCE PORT and
      print "sent <length>", without waiting for a reply: under imitation
      auto, what a client's imitation sends before a handshake, which leaves
      a hint for that source.

  candidates <send|probe> <kind> <layout>
      Print "<length> <kinds>": the length of the datagram that send (or
      probe) sends for KIND, and the AmneziaWG packet kinds it fits under
      LAYOUT without header protection ("none" if it fits none). A datagram
      that fits a kind is AmneziaWG traffic to the server, never a hint.

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

  owned <pid> <start time> <check|TERM|KILL|STOP|CONT>
      Probe or signal the process with that PID only if it is still the one
      that recorded that start time, through a pidfd (owned): never a process
      that was given the PID later. STOP returns once every thread of it is
      stopped; CONT continues it.

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


# The smallest AmneziaWG datagram: a transport message (32 bytes) behind an S4
# of 0. Anything shorter fits no packet kind's length rule under any S sizes,
# H ranges or header-protection key (inbound_candidates in the pinned
# BoringTun tests the length first), so the server always hands it to probe
# classification, the only door that records an auto hint. A longer datagram
# can be an AmneziaWG candidate under some layouts: the SIP probe below is a
# transport candidate whenever its four bytes at S4 fall in H4, and then it is
# never a hint.
AWG_MIN_DATAGRAM = 32
# The hints `send` plants: upstream's own SIP detection vector, a request
# line and an empty header section.
HINTS = {
    "sip": b"OPTIONS sip:a@b SIP/2.0\r\n\r\n",
}
assert all(len(hint) < AWG_MIN_DATAGRAM for hint in HINTS.values())


def send(kind, host, port, source_port):
    """Send the hint of KIND to HOST:PORT from SOURCE PORT, without waiting
    for a reply: under imitation auto, the datagram a client's own imitation
    sends before its handshake, which leaves a hint for that source address
    and port. It is shorter than any AmneziaWG datagram, so it is never taken
    for one."""
    request = HINTS[kind]
    sport = parse_number(source_port, "source port", 65535)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", sport))
        sock.sendto(request, (host, int(port)))
    return "sent %d" % len(request)


def candidates(source, kind, layout):
    """The AmneziaWG packet kinds the datagram that `send` (SOURCE "send") or
    `probe` (SOURCE "probe") would send for KIND fits under LAYOUT, without
    header protection: each kind whose length rule and H range its bytes meet
    (classify_datagram's rule, which is inbound_candidates' in the pinned
    BoringTun without a header-protection key or RandomTrailers), or "none".
    A datagram with any candidate is AmneziaWG traffic to the server and never
    an auto hint."""
    sizes, ranges = parse_layout(layout)
    if source == "send":
        datagram = HINTS[kind]
    else:
        datagram, _ = PROBES[kind]()
    found = []
    for name, index, size in KINDS:
        offset = sizes[index]
        length = len(datagram)
        if (length < offset + size) if name == "transport" else (length != offset + size):
            continue
        tag = struct.unpack("<I", datagram[offset:offset + 4])[0]
        if ranges[index][0] <= tag <= ranges[index][1]:
            found.append(name)
    return "%d %s" % (len(datagram), " ".join(found) or "none")


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
    destination, when given), the IPv4 protocol, and the UDP ports (a
    SOURCE_PORT of None admits any source port). Every length is validated before any byte counts as payload: the IPv4 header
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
    port_ok = source_port is None or sport == source_port
    if not port_ok or (destination_port is not None and dport != destination_port):
        if (more and fragments is not None and destination_port is not None and port_ok
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


MALFORMED_KEPT = 40
# A record's receive buffer: a bulk transfer through the tunnel must not
# overflow it while the record writes. Drops are reported regardless.
# BT_WIRE_RECORD_BUFFER (bytes) overrides it, for the overflow regression.
RECORD_BUFFER = 32 * 1024 * 1024
SOL_PACKET = 263
PACKET_STATISTICS = 6
SO_TIMESTAMPNS = getattr(socket, "SO_TIMESTAMPNS", 35)
# Frames read per wakeup before drops and clocks are polled again.
RECORD_BATCH = 256
# How long the shutdown drain may take before the record ends incomplete,
# and how long past the cutoff the queue must still be found empty: a frame
# stamped just before the cutoff may be queued a moment later.
RECORD_DRAIN_NS = 5 * 10 ** 9
RECORD_SETTLE_NS = 10 ** 8
# The longest a wait lasts, so that drops and clocks are polled while idle.
RECORD_IDLE_NS = 5 * 10 ** 8
# How far two readings of a clock offset may differ without counting as a
# step of the realtime clock or a suspend (boottime against monotonic).
CLOCK_TOLERANCE_NS = 2 * 10 ** 6


class ClockSample:
    """One reading of the clocks: CLOCK_BOOTTIME (BOOT), the offset of
    CLOCK_REALTIME from it (REAL_OFFSET, bracketed by two realtime readings,
    whose spread is REAL_ERROR) and the offset of CLOCK_MONOTONIC from it
    (MONO_OFFSET). Kernel receive timestamps are realtime; the shell's clock
    is boottime (/proc/uptime); the server measures hint ages on monotonic."""

    def __init__(self, boot, real_offset, real_error, mono_offset):
        self.boot, self.real_offset, self.real_error, self.mono_offset = boot, real_offset, real_error, mono_offset

    def steady_since(self, earlier):
        """Whether neither offset moved between EARLIER and this reading."""
        return (abs(self.real_offset - earlier.real_offset) <= CLOCK_TOLERANCE_NS + self.real_error + earlier.real_error
                and abs(self.mono_offset - earlier.mono_offset) <= CLOCK_TOLERANCE_NS)


class SystemClocks:
    def sample(self):
        real_before = time.clock_gettime_ns(time.CLOCK_REALTIME)
        boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        mono = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        real_after = time.clock_gettime_ns(time.CLOCK_REALTIME)
        return ClockSample(boot, (real_before + real_after) // 2 - boot, real_after - real_before, boot - mono)

    def boot(self):
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)

    def sleep(self, nanoseconds):
        time.sleep(nanoseconds / 10 ** 9)


class PacketSource:
    """The record's packet socket: every IPv4 frame the namespace receives
    (or one interface's), each with the kernel's receive timestamp."""

    def __init__(self, interface, buffer):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
        for option in (getattr(socket, "SO_RCVBUFFORCE", 33), socket.SO_RCVBUF):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, option, buffer)
                break
            except OSError:
                continue
        self.sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        if interface != "any":
            self.sock.bind((interface, 0))
        self.sock.setblocking(False)

    def fileno(self):
        return self.sock.fileno()

    def read(self):
        """(frame, kernel receive time in realtime nanoseconds or None), or
        None once the queue is empty."""
        try:
            frame, ancillary, _, _ = self.sock.recvmsg(65535, socket.CMSG_SPACE(16))
        except BlockingIOError:
            return None
        stamp = None
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS and len(data) >= 16:
                seconds, nanoseconds = struct.unpack("qq", data[:16])
                stamp = seconds * 10 ** 9 + nanoseconds or None
        return frame, stamp

    def drops(self):
        """Frames dropped since the last call (PACKET_STATISTICS, which
        resets on reading)."""
        return struct.unpack("II", self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))[1]


def centiseconds_down(nanoseconds):
    return nanoseconds // 10 ** 7


def centiseconds_up(nanoseconds):
    return -(-nanoseconds // 10 ** 7)


class Recorder:
    """What the `record` command writes, one line per relevant frame, in the
    order the packet socket delivered them (its queue order):

      "<arrival> <address> <port> <length> <hex>"      a whole datagram
      "<arrival> <address> <port> fragment <length>"   a first fragment
      "<arrival> <address> - malformed <length> <hex>" not valid IPv4/UDP,
                                                       its first 40 bytes

    ARRIVAL is the kernel's receive time in centiseconds of CLOCK_BOOTTIME,
    converted from the realtime timestamp with the offset read at the time it
    was read, when the offsets did not move since the queue was last seen
    empty; otherwise, or without a timestamp, "<from>~<to>": the frame arrived
    after the queue was last seen empty and before it was read. Markers:

      "<clock> - drops <count> <since>"   frames the socket dropped since the
                                          poll at SINCE (polled after every
                                          batch, from a baseline taken before
                                          the record was ready)
      "<clock> - clock-step <since>"      the realtime or the boottime clock
                                          stepped (or the system suspended)
                                          since the reading at SINCE
      "<clock> - complete <cutoff>"       the last line: every frame that
                                          arrived by CUTOFF is recorded or
                                          counted in a drops line
      "<clock> - incomplete <cutoff>"     the last line when the queue could
                                          not be drained to CUTOFF in time
    """

    def __init__(self, source, clocks, out, wanted_sources, wanted_port, destination_port, created):
        self.source, self.clocks, self.out = source, clocks, out
        self.wanted_sources, self.wanted_port, self.destination_port = wanted_sources, wanted_port, destination_port
        self.fragments = Fragments()
        self.records = 0
        # Every queued frame arrived after this reading: the socket's
        # creation, then each time the queue was found empty.
        self.empty = created
        self.last = created
        self.polled = created.boot

    def write(self, line):
        self.out.write(line + "\n")
        self.records += 1

    def begin(self):
        """Take the drop counters' baseline, then the reading at which the
        record counts as ready: every drop after it is reported."""
        before = self.clocks.sample()
        self.source.drops()
        ready = self.clocks.sample()
        self.polled = before.boot
        return ready

    def arrival(self, stamp, now):
        """The arrival field of a frame read at reading NOW."""
        low, high = self.empty.boot, self.clocks.boot()
        if stamp is not None and now.steady_since(self.empty):
            boot = stamp - now.real_offset
            slack = CLOCK_TOLERANCE_NS + now.real_error
            if low - slack <= boot <= high + slack:
                return "%d" % centiseconds_down(min(max(boot, low), high))
        return "%d~%d" % (centiseconds_down(low), centiseconds_up(high))

    def frame(self, frame, stamp, now):
        if len(frame) < 16 or frame[12:16] not in self.wanted_sources:
            return
        status, length, data, fragmented = frame_payload(frame, frame[12:16], self.wanted_port,
                                                         destination_port=self.destination_port, fragments=self.fragments)
        if status in (IGNORE, CONTINUATION):
            return
        at = self.arrival(stamp, now)
        address = socket.inet_ntoa(frame[12:16])
        if status == MALFORMED:
            self.write("%s %s - malformed %d %s" % (at, address, length, frame[:MALFORMED_KEPT].hex()))
            return
        header = (frame[0] & 0x0F) * 4
        sport = struct.unpack(">H", frame[header:header + 2])[0]
        if fragmented:
            self.write("%s %s %d fragment %d" % (at, address, sport, length))
        else:
            self.write("%s %s %d %d %s" % (at, address, sport, length, data.hex() or "-"))

    def batch(self, limit):
        """Read up to LIMIT frames; True if the queue was found empty."""
        now = self.clocks.sample()
        for _ in range(limit):
            item = self.source.read()
            if item is None:
                self.empty = self.clocks.sample()
                return True
            self.frame(item[0], item[1], now)
        return False

    def poll(self):
        """Report drops and clock steps since the last poll."""
        dropped = self.source.drops()
        now = self.clocks.sample()
        if dropped:
            self.write("%d - drops %d %d" % (centiseconds_up(now.boot), dropped, centiseconds_down(self.polled)))
        if not now.steady_since(self.last):
            self.write("%d - clock-step %d" % (centiseconds_up(now.boot), centiseconds_down(self.last.boot)))
        self.polled, self.last = now.boot, now

    def finish(self, cutoff):
        """Drain the queue through CUTOFF (a boottime reading), within
        RECORD_DRAIN_NS, report the drops and write the end marker. True if
        the record is complete through CUTOFF."""
        give_up = self.clocks.boot() + RECORD_DRAIN_NS
        complete = False
        while self.clocks.boot() < give_up:
            if self.batch(RECORD_BATCH):
                if self.empty.boot >= cutoff + RECORD_SETTLE_NS:
                    complete = True
                    break
                self.clocks.sleep(RECORD_SETTLE_NS // 4)
        self.poll()
        self.write("%d - %s %d" % (centiseconds_up(self.clocks.boot()), "complete" if complete else "incomplete",
                                   centiseconds_down(cutoff)))
        self.out.flush()
        return complete


def record(destination_port, interface, sources_text, source_port, seconds, path, source=None, clocks=None):
    """The `record` command: every frame from SOURCES to DESTINATION_PORT
    (Recorder), through a cutoff at the deadline or at an authorized stop.
    PATH.state is capture's transcript ("ready ..."; "complete <records> <end
    clock>" at the deadline, "stopped <records> <token>" after an authorized
    SIGTERM, both status 0; "interrupted <records>", status 3). The records
    count every line, markers included; whether the record is complete is its
    last line's to say, and a reader must check it."""
    sources = sources_text.split(",")
    wanted_sources = set()
    for address in sources:
        try:
            wanted_sources.add(socket.inet_aton(address))
        except OSError:
            raise InputError("%r is not an IPv4 address" % address) from None
    if len(wanted_sources) != len(sources):
        raise InputError("the source addresses %r are not distinct" % sources_text)
    wanted_port = None if source_port == "any" else parse_number(source_port, "port", 65535)
    wanted_destination = parse_number(destination_port, "destination port", 65535)
    duration = parse_number(seconds, "record seconds", 86400) * 10 ** 9
    buffer = parse_number(os.environ.get("BT_WIRE_RECORD_BUFFER", str(RECORD_BUFFER)), "record buffer", 2 ** 31 - 1)
    state_path, stop_path = path + ".state", path + ".stop"
    if os.path.lexists(stop_path):
        raise InputError("%s exists before the record started" % stop_path)
    stop = []
    wake_read, wake_write = os.pipe()
    os.set_blocking(wake_read, False)
    os.set_blocking(wake_write, False)
    signal.set_wakeup_fd(wake_write)
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.append(signum))
    clocks = clocks or SystemClocks()
    created = clocks.sample()
    source = source or PacketSource(interface, buffer)
    with open(path, "w") as out:
        recorder = Recorder(source, clocks, out, wanted_sources, wanted_port, wanted_destination, created)
        ready = recorder.begin()
        write_state(state_path, "ready %d %d %d" % (own_identity() + (centiseconds_down(ready.boot),)))
        deadline = ready.boot + duration
        while not stop:
            left = deadline - clocks.boot()
            if left <= 0:
                break
            select.select([source, wake_read], [], [], min(left, RECORD_IDLE_NS) / 10 ** 9)
            try:
                os.read(wake_read, 64)
            except BlockingIOError:
                pass
            if recorder.batch(RECORD_BATCH):
                out.flush()
            recorder.poll()
        cutoff = clocks.boot()
        if not stop or stop_token(stop_path) is not None:
            recorder.finish(cutoff)
    if not stop:
        write_state(state_path, "complete %d %d" % (recorder.records, centiseconds_up(clocks.boot())))
        return 0
    token = stop_token(stop_path)
    if token is None:
        write_state(state_path, "interrupted %d" % recorder.records)
        return 3
    write_state(state_path, "stopped %d %s" % (recorder.records, token))
    return 0


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


OWNED_ACTIONS = {"check": None, "TERM": signal.SIGTERM, "KILL": signal.SIGKILL, "STOP": signal.SIGSTOP,
                 "CONT": signal.SIGCONT}


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
        raise InputError("the action is check, TERM, KILL, STOP or CONT, not %r" % action)
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


# ── Imitation auto: what the server can learn, from what reached it ─────────
# A restatement of the pinned BoringTun's rules (b94943906b11), so that the
# protocol an auto server must select for a peer is derived from the
# datagrams that reached it, never from what it sent:
#   - inbound_candidates: amnezia.rs candidates_under_mask, header protection
#     included (header_protection.rs type_mask);
#   - detect: noise/imitation/detect.rs with quic/version_negotiation.rs
#     parse_long_header, stun.rs binding_request_len and dns.rs question_end;
#   - the hint cache: device/imitation_auto.rs ImitationHints (only a
#     datagram with no AmneziaWG candidate is observed; the first detected
#     protocol per source address and port; HINT_LIFETIME 30 s, not extended
#     by repeats), on the listener; a connected socket's tunnel keeps its own
#     pending hint (noise/imitation/auto.rs), a separate state (History);
#   - selection: noise/mod.rs commit_with_imitation (at an accepted handshake
#     initiation while nothing is learned: the live hint, else detect over
#     the initiation datagram itself; then pinned) and amnezia.rs
#     resolve_imitation / check_header_protection_nonce (with header
#     protection, sip is refused while any S is 31 bytes or more, and every
#     protocol while any S is below 12).
QUIC_REAL_VERSIONS = (0x00000001, 0x6B3343CF)
QUIC_MAX_CID = 20
STUN_MAX_REQUEST = 1024
SIP_DETECT_PREFIXES = (b"SUBSCRIBE ", b"REGISTER ", b"OPTIONS ", b"MESSAGE ", b"INVITE ", b"CANCEL ",
                       b"NOTIFY ", b"INFO ", b"ACK ", b"BYE ", b"SIP/")
HINT_LIFETIME_CS = 3000
HP_NONCE_SIZE = 12


def chacha20_block(key, counter, nonce):
    """One 64-byte ChaCha20 block (RFC 8439 section 2.3): 32-byte KEY, 32-bit
    block COUNTER, 12-byte NONCE."""
    def rotl(value, count):
        return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))

    def quarter(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotl(x[b] ^ x[c], 7)

    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    work = list(state)
    for _ in range(10):
        quarter(work, 0, 4, 8, 12)
        quarter(work, 1, 5, 9, 13)
        quarter(work, 2, 6, 10, 14)
        quarter(work, 3, 7, 11, 15)
        quarter(work, 0, 5, 10, 15)
        quarter(work, 1, 6, 11, 12)
        quarter(work, 2, 7, 8, 13)
        quarter(work, 3, 4, 9, 14)
    return struct.pack("<16I", *((work[i] + state[i]) & 0xFFFFFFFF for i in range(16)))


def hp_keystream(key, datagram, length):
    """The header-protection keystream of DATAGRAM: ChaCha20 under KEY with
    the datagram's first 12 bytes as nonce, from block 0."""
    nonce = bytes(datagram[:HP_NONCE_SIZE])
    stream = b"".join(chacha20_block(key, block, nonce) for block in range((length + 63) // 64))
    return stream[:length]


def quic_long_header(data):
    if len(data) < 7 or data[0] & 0xC0 != 0xC0:
        return False
    version = struct.unpack(">I", data[1:5])[0]
    capped = version in QUIC_REAL_VERSIONS
    known = (capped or (version & 0xFFFFFF00 == 0xFF000000 and version & 0xFF != 0)
             or version & 0x0F0F0F0F == 0x0A0A0A0A)
    if not known:
        return False
    dcid = data[5]
    if capped and dcid > QUIC_MAX_CID:
        return False
    dcid_end = 6 + dcid
    if dcid_end >= len(data):
        return False
    scid = data[dcid_end]
    if capped and scid > QUIC_MAX_CID:
        return False
    return len(data) >= dcid_end + 1 + scid


def stun_binding_request(data):
    if not 20 <= len(data) <= STUN_MAX_REQUEST or data[:2] != b"\x00\x01" or data[4:8] != STUN_COOKIE:
        return False
    length = struct.unpack(">H", data[2:4])[0]
    return length % 4 == 0 and len(data) == 20 + length


def dns_qname_end(data, start):
    position, total = start, 0
    while True:
        if position >= len(data):
            return None
        label = data[position]
        if label & 0xC0:
            return None
        if label == 0:
            return position + 1
        if label > 63:
            return None
        total += 1 + label
        if total + 1 > 255:
            return None
        position += 1 + label


def dns_query(data):
    if len(data) < 12 or data[2] & 0xF8 or data[3] & 0xCF:
        return False
    if struct.unpack(">HHH", data[4:10]) != (1, 0, 0):
        return False
    end = dns_qname_end(data, 12)
    if end is None or len(data) < end + 4:
        return False
    return struct.unpack(">H", data[end + 2:end + 4])[0] in (1, 3, 4, 255)


def detect(data):
    """The protocol upstream's detect() recognizes in DATA, or None."""
    if not data:
        return None
    if quic_long_header(data):
        return "quic"
    has_cookie = len(data) >= 8 and data[4:8] == STUN_COOKIE
    if stun_binding_request(data):
        return "stun"
    if not has_cookie and dns_query(data):
        return "dns"
    head = bytes(data[:10])
    if any(len(head) >= len(prefix) and head[:len(prefix)].lower() == prefix.lower()
           for prefix in SIP_DETECT_PREFIXES):
        return "sip"
    return None


def inbound_candidates(datagram, sizes, ranges, hp_key=None, trailers=False):
    """The AmneziaWG packet kinds DATAGRAM fits on arrival (upstream's
    inbound_candidates): a handshake kind of exactly S + its size (at least,
    with RandomTrailers), transport of at least S4 + 32, and the type tag
    after the S prefix -- read through the header-protection mask when a key
    is set -- in the kind's H range. With a key, a datagram shorter than the
    nonce fits nothing, and a kind whose S is below 12 is never read."""
    mask = b"\x00" * 4
    if hp_key is not None:
        if len(datagram) < HP_NONCE_SIZE:
            return []
        mask = hp_keystream(hp_key, datagram, 4)
    found = []
    for name, index, size in KINDS:
        offset = sizes[index]
        if name == "transport" or trailers:
            fits = len(datagram) >= offset + size
        else:
            fits = len(datagram) == offset + size
        if not fits or (hp_key is not None and offset < HP_NONCE_SIZE):
            continue
        tag = struct.unpack("<I", bytes(a ^ b for a, b in zip(datagram[offset:offset + 4], mask)))[0]
        if ranges[index][0] <= tag <= ranges[index][1]:
            found.append(name)
    return found


def genuine_initiation(datagram, candidates, sizes, mac1_key, hp_key=None):
    """Whether DATAGRAM is a handshake initiation to the server: an init
    candidate whose 148-byte message (unmasked with the header-protection
    keystream when a key is set) carries a mac1 valid under the server's
    public key. That is what the server checks before its Noise trial; a
    sender that knows the public key can compute it, so it identifies the
    initiation of a correctly configured client and authenticates no one."""
    if "init" not in candidates:
        return False
    message = bytes(datagram[sizes[0]:sizes[0] + 148])
    if hp_key is not None:
        message = bytes(a ^ b for a, b in zip(message, hp_keystream(hp_key, datagram, 148)))
    mac1 = hashlib.blake2s(message[:-32], digest_size=16, key=mac1_key).digest()
    return hmac.compare_digest(mac1, message[-32:-16])


def policy_allows(protocol, sizes, hp_key):
    """Whether resolve_imitation keeps PROTOCOL: without header protection
    always; with it, never while an S is below the nonce, and sip only while
    every S is below SIP_REQUEST_LINE_MIN."""
    if hp_key is None:
        return True
    if min(sizes) < HP_NONCE_SIZE:
        return False
    return not (protocol == "sip" and max(sizes) >= SIP_REQUEST_LINE_MIN)


ARRIVAL = r"((?:0|[1-9][0-9]{0,17})(?:~(?:0|[1-9][0-9]{0,17}))?)"
CLOCK = r"(0|[1-9][0-9]{0,17})"
RECORD_DATAGRAM = re.compile(ARRIVAL + r" ([0-9.]{7,15}) (0|[1-9][0-9]{0,4}) (0|[1-9][0-9]{0,4}) (-|(?:[0-9a-f]{2})+)")
RECORD_FRAGMENT = re.compile(ARRIVAL + r" ([0-9.]{7,15}) (0|[1-9][0-9]{0,4}) fragment (0|[1-9][0-9]{0,4})")
RECORD_MALFORMED = re.compile(ARRIVAL + r" ([0-9.]{7,15}) - malformed (0|[1-9][0-9]{0,4}) ((?:[0-9a-f]{2}){0,40})")
RECORD_DROPS = re.compile(CLOCK + r" - drops ([1-9][0-9]{0,9}) " + CLOCK)
RECORD_STEP = re.compile(CLOCK + r" - clock-step " + CLOCK)
RECORD_END = re.compile(CLOCK + r" - (complete|incomplete) " + CLOCK)


class Frame:
    """One recorded frame: its arrival between LOW and HIGH (centiseconds of
    CLOCK_BOOTTIME; an exact stamp is the centisecond it fell in, so HIGH is
    LOW + 1), its source, KIND "datagram", "fragment" (no data) or
    "malformed" (port None, data its first bytes), and INDEX, its position in
    the socket's queue order."""

    def __init__(self, index, arrival, address, port, kind, data):
        if "~" in arrival:
            low, high = (int(part) for part in arrival.split("~"))
        else:
            low = int(arrival)
            high = low + 1
        self.index, self.low, self.high = index, low, high
        self.address, self.port, self.kind, self.data = address, port, kind, data


class Record:
    """A finished `record`: READY, its ready clock; FRAMES in queue order;
    DROPS (since, clock, count) and STEPS (since, clock) intervals; END
    ("complete" or "incomplete", cutoff), from its last line."""

    def __init__(self, ready, frames, drops, steps, end):
        self.ready, self.frames, self.drops, self.steps, self.end = ready, frames, drops, steps, end


def read_record(path):
    """Parse a finished `record`. Its transcript must be a ready line and a
    stopped or complete end that counts every line; every line must be well
    formed; an end marker must be the last line and only there. Arrival
    stamps may go back (frames from different interfaces or CPUs), queue
    order is the line order."""
    with open(path + ".state") as state:
        transcript = state.read().splitlines()
    ready = re.fullmatch(r"ready [0-9]+ [0-9]+ (0|[1-9][0-9]{0,17})", transcript[0]) if transcript else None
    if len(transcript) != 2 or not ready:
        raise InputError("%s.state is not a ready line and one end" % path)
    frames, drops, steps, end = [], [], [], None
    lines = 0
    for number, line in capture_lines(path):
        lines += 1
        where = "%s:%d" % (path, number)
        if end is not None:
            raise InputError("%s follows the record's end marker" % where)
        marker = RECORD_END.fullmatch(line)
        if marker:
            end = (marker.group(2), int(marker.group(3)))
            continue
        marker = RECORD_DROPS.fullmatch(line)
        if marker:
            if int(marker.group(3)) > int(marker.group(1)):
                raise InputError("%s: its interval goes back" % where)
            drops.append((int(marker.group(3)), int(marker.group(1)), int(marker.group(2))))
            continue
        marker = RECORD_STEP.fullmatch(line)
        if marker:
            if int(marker.group(2)) > int(marker.group(1)):
                raise InputError("%s: its interval goes back" % where)
            steps.append((int(marker.group(2)), int(marker.group(1))))
            continue
        for kind, pattern in (("datagram", RECORD_DATAGRAM), ("fragment", RECORD_FRAGMENT), ("malformed", RECORD_MALFORMED)):
            match = pattern.fullmatch(line)
            if match:
                break
        else:
            raise InputError("%s is not a record line: %r" % (where, line[:80]))
        if "~" in match.group(1) and int(match.group(1).split("~")[0]) > int(match.group(1).split("~")[1]):
            raise InputError("%s: its arrival interval goes back" % where)
        try:
            socket.inet_aton(match.group(2))
        except OSError:
            raise InputError("%s has no IPv4 source address" % where) from None
        if kind == "datagram":
            data = b"" if match.group(5) == "-" else bytes.fromhex(match.group(5))
            if len(data) != int(match.group(4)):
                raise InputError("%s: its length is not that of its bytes" % where)
            frames.append(Frame(len(frames), match.group(1), match.group(2), int(match.group(3)), kind, data))
        elif kind == "fragment":
            frames.append(Frame(len(frames), match.group(1), match.group(2), int(match.group(3)), kind, b""))
        else:
            frames.append(Frame(len(frames), match.group(1), match.group(2), None, kind, bytes.fromhex(match.group(4))))
    count = re.fullmatch(r"(?:stopped ([0-9]+) [0-9a-f]{32}|complete ([0-9]+) [0-9]+)", transcript[1])
    if not count or int(count.group(1) or count.group(2)) != lines:
        raise InputError("%s.state does not end with a stop or completion that counts its %d lines" % (path, lines))
    return Record(int(ready.group(1)), frames, drops, steps, end)


class Undecided(Exception):
    """The record and the evidence do not decide what the server selected."""


# What the model supports, from the pinned BoringTun's code:
#   - one listener socket per family, each drained by one worker at a time
#     (EPOLLONESHOT), so datagrams on it are processed in queue order, no
#     earlier than they arrived; the same holds for each connected socket;
#   - the listener keeps the device's hints (ImitationHints: the first
#     detected protocol per source address and port, for HINT_LIFETIME from
#     its processing; never extended; discarded when a selection there
#     learns a protocol); its acceptance selects the live hint, else what the
#     initiation datagram itself is detected as;
#   - after a peer's first accepted initiation the device connects a socket
#     to its endpoint; from some point on, the endpoint's datagrams reach that
#     socket, whose tunnel keeps a hint of its own (AutoImitation: replaced
#     once expired, cleared when something is learned and on a new path); a
#     connected socket closes only on a roam, the peer's removal or
#     ConnectionExpired (3 * REJECT_AFTER_TIME after the session, 540 s);
#   - a learned protocol is pinned; a refused one (the header-protection
#     policy) changes nothing.
# What it takes as given, from the scenario: the client keeps one endpoint;
# the server is not reconfigured during the history (a peer removal or a
# framing change clears the device's hints); fewer than MAX_HINT_SOURCES
# sources leave hints.
MAX_HINT_SOURCES = 1024
MAX_INITIATIONS = 10
MAX_HISTORIES = 20000
CONNECTION_EXPIRY_CS = 54000
INFINITY = float("inf")


class Datagram:
    """One of the client's datagrams in queue order: arrival bounds LOW and
    HIGH, KIND "hint" (fits no AmneziaWG kind; PROTOCOL the one detected),
    "initiation" (an init candidate with a mac1 consistent with the server's
    key: a valid initiation or a forgery, which syntax cannot tell; DETECTED
    what the datagram itself is detected as) or "other"."""

    def __init__(self, frame, sizes, ranges, mac1_key, hp_key, trailers):
        self.low, self.high, self.size = frame.low, frame.high, len(frame.data)
        candidates = inbound_candidates(frame.data, sizes, ranges, hp_key, trailers)
        self.protocol = self.detected = None
        if not candidates:
            self.protocol = detect(frame.data)
            self.kind = "hint" if self.protocol else "other"
        elif genuine_initiation(frame.data, candidates, sizes, mac1_key, hp_key):
            self.kind = "initiation"
            self.detected = detect(frame.data)
        else:
            self.kind = "other"


class Branch(Exception):
    """A timing comparison the evidence does not decide: explore both."""


class History:
    """One history of what the server did with the client's datagrams: which
    initiations it accepted (ACCEPTED, indices), from which datagram on its
    endpoint's datagrams reached the connected socket (SWITCH, or None), and
    the outcomes of the timing comparisons the evidence leaves open
    (CHOICES, consumed in order)."""

    def __init__(self, datagrams, accepted, switch, choices, establishments, steps):
        self.datagrams, self.accepted, self.switch, self.choices = datagrams, accepted, switch, choices
        self.first = min(accepted) if accepted else None
        self.used = 0
        self.steps = steps
        self.bound = [INFINITY] * len(datagrams)
        for start, up in establishments:
            # Some initiation the client process started at START sent, and
            # the server accepted and answered, was processed by UP: the
            # earliest of those it may have been, and everything queued
            # before it on the same socket.
            possible = [k for k in accepted if datagrams[k].low <= up and datagrams[k].high >= start]
            paths = {self.path(k) for k in possible}
            if len(paths) != 1:
                continue
            earliest, path = min(possible), paths.pop()
            for index in range(earliest + 1):
                if self.path(index) == path:
                    self.bound[index] = min(self.bound[index], up + 1)

    def path(self, index):
        if self.first is not None and index > self.first and self.switch is not None and index >= self.switch:
            return "connected"
        return "listener"

    def choose(self):
        if self.used == len(self.choices):
            raise Branch()
        self.used += 1
        return self.choices[self.used - 1]

    def live(self, inserted, at):
        """Whether the hint the datagram at INSERTED left is still live when
        the datagram at AT is processed: certain from the bounds, else a
        choice."""
        oldest = self.bound[at] - self.datagrams[inserted].low
        youngest = self.datagrams[at].low - self.bound[inserted]
        if not self.steps:
            if oldest < HINT_LIFETIME_CS:
                return True
            if youngest > HINT_LIFETIME_CS:
                return False
        return self.choose()

    def run(self):
        """(learned protocol or None, index it was learned at, notes)."""
        listener = tunnel = None
        learned = learned_at = None
        notes = []
        for index, datagram in enumerate(self.datagrams):
            path = self.path(index)
            where = "#%d %s, %d B, %s" % (index + 1, path, datagram.size, datagram.kind)
            if datagram.kind == "hint":
                if path == "listener":
                    if listener is not None and not self.live(listener[1], index):
                        listener = None
                    if listener is None:
                        listener = (datagram.protocol, index)
                        notes.append("%s %s: the listener's hint" % (where, datagram.protocol))
                elif learned is None:
                    if tunnel is None or not self.live(tunnel[1], index):
                        tunnel = (datagram.protocol, index)
                        notes.append("%s %s: the tunnel's hint" % (where, datagram.protocol))
                continue
            if datagram.kind != "initiation":
                continue
            if index not in self.accepted:
                notes.append("%s: not accepted" % where)
                continue
            if learned is None:
                cache = listener if path == "listener" else tunnel
                hint = cache[0] if cache is not None and self.live(cache[1], index) else None
                selected = hint or datagram.detected
                if selected is None:
                    notes.append("%s: accepted; no live hint, nothing detected in it: unresolved" % where)
                elif policy_allows_auto(selected, self):
                    learned, learned_at, tunnel = selected, index, None
                    if path == "listener":
                        listener = None
                    notes.append("%s: accepted; %s from %s: learned" % (where, selected, "the hint" if hint else "itself"))
                else:
                    notes.append("%s: accepted; %s refused by the header-protection policy: unresolved" % (where, selected))
            if index == self.first:
                tunnel = None
        return learned, learned_at, notes


def policy_allows_auto(protocol, history):
    return policy_allows(protocol, history.sizes, history.hp_key)


def history_expectation(history, learned, learned_at, window_start, window_end):
    """What the server's datagrams to the client between the window's clocks
    are under HISTORY."""
    datagrams = history.datagrams
    sessions = [k for k in history.accepted if datagrams[k].low <= window_end]
    if learned is not None and history.bound[learned_at] <= window_start:
        return learned
    if learned is not None and datagrams[learned_at].low <= window_end:
        if any(k < learned_at for k in history.accepted):
            raise Undecided("the peer may have learned %s inside the window, after a session without it" % learned)
        return learned
    if not sessions:
        raise Undecided("no initiation accepted by the window's end")
    return "random"


def parse_establishments(text):
    """"START:UP,..." -> [(start, up)]: a client process started at START
    completed a handshake by UP (its first successful ping), so the server
    accepted and answered an initiation that arrived between them."""
    if text == "-":
        return []
    pairs = []
    for item in text.split(","):
        start, colon, up = item.partition(":")
        if not colon:
            raise InputError("an establishment is START:UP, not %r" % item)
        start = parse_number(start, "establishment start", 2 ** 62, WIDE_NUMBER)
        up = parse_number(up, "establishment", 2 ** 62, WIDE_NUMBER)
        if start > up:
            raise InputError("an establishment %r ends before it starts" % item)
        pairs.append((start, up))
    return pairs


def auto_expect(path, address, port_text, layout, server_key, hp_key_path, trailers_text, epoch_text, start_text, end_text,
                establishments_text="-", connected_text="-"):
    """Print how an auto server treats the client at ADDRESS:PORT, from the
    finished `record` at PATH and the scenario's evidence, then "expect
    <dns|quic|sip|stun|random>" for the server's datagrams to the client
    between the clocks START and END, or "undecided <reason>" (exit 1).

    EPOCH is when the server's state was last empty (its process start); the
    record must have been ready before it and complete through END.
    ESTABLISHMENTS ("START:UP,...", or "-") are the client-side evidence of
    acceptance: a client process started at START pinged through the tunnel
    by UP. Nothing in a datagram proves that the server accepted it, so every
    initiation candidate (mac1 consistent with the server's key) may or may
    not have been accepted, subject to that evidence. CONNECTED (a clock, or
    "-") is when a socket connected to the client's endpoint was seen in the
    server's socket table; without it, the point from which the endpoint's
    datagrams reached that socket is open.

    Every history the evidence allows is replayed (History): which
    initiations were accepted, where the endpoint moved to the connected
    socket, and each hint-lifetime comparison the arrival and processing
    bounds leave open (the server processes a datagram no earlier than its
    arrival; the only upper bound is an establishment's UP). The outcome is
    decided only if every history gives the same one. Undecided also: an
    incomplete record, a clock step, frames the record dropped or could not
    read (a malformed frame from the address, a fragment from the port) at a
    time they could have changed the outcome (from the epoch until the
    selection was pinned, or the window's end), more than MAX_HINT_SOURCES
    hint sources, more initiations than MAX_INITIATIONS, or a window ending
    more than CONNECTION_EXPIRY_CS after the first possible acceptance."""
    sizes, ranges = parse_layout(layout)
    port = parse_number(port_text, "port", 65535)
    mac1_key = hashlib.blake2s(MAC1_LABEL + parse_public_key(server_key)).digest()
    hp_key = None
    if hp_key_path != "-":
        with open(hp_key_path) as source:
            hp_key = parse_public_key(source.read().strip())
    if trailers_text not in ("on", "off"):
        raise InputError("RandomTrailers is on or off, not %r" % trailers_text)
    trailers = trailers_text == "on"
    epoch = parse_number(epoch_text, "epoch", 2 ** 62, WIDE_NUMBER)
    window_start = parse_number(start_text, "window start", 2 ** 62, WIDE_NUMBER)
    window_end = parse_number(end_text, "window end", 2 ** 62, WIDE_NUMBER)
    establishments = parse_establishments(establishments_text)
    connected = None if connected_text == "-" else parse_number(connected_text, "connected", 2 ** 62, WIDE_NUMBER)
    try:
        socket.inet_aton(address)
    except OSError:
        raise InputError("%r is not an IPv4 address" % address) from None
    record = read_record(path)
    try:
        outcome, notes = decide(record, address, port, sizes, ranges, mac1_key, hp_key, trailers, epoch,
                                window_start, window_end, establishments, connected)
    except Undecided as reason:
        print("undecided %s" % reason)
        return 1
    print("\n".join(notes))
    print("expect %s" % outcome)
    return 0


def decide(record, address, port, sizes, ranges, mac1_key, hp_key, trailers, epoch, window_start, window_end,
           establishments, connected):
    """(outcome, notes of one history) or Undecided."""
    if record.ready + 1 > epoch:
        raise Undecided("the record was ready at %d, not before the server's state was last empty at %d" % (record.ready, epoch))
    if record.end is None or record.end[0] != "complete" or record.end[1] < window_end:
        raise Undecided("the record is not complete through the window's end at %d (%s)"
                        % (window_end, "no end marker" if record.end is None else "%s %d" % record.end))
    steps = [step for step in record.steps if step[1] >= epoch and step[0] <= window_end]
    # What the record cannot tell: frames it dropped (any source), a
    # malformed frame from the address (its port unknown), a fragment from
    # the client's port.
    gaps = [(since, clock, "%d frames the record dropped between %d and %d" % (count, since, clock))
            for since, clock, count in record.drops if clock >= epoch and since <= window_end]
    frames, sources = [], set()
    for frame in record.frames:
        if frame.high < epoch or frame.low > window_end:
            continue
        if frame.kind == "datagram" and frame.port is not None:
            if not inbound_candidates(frame.data, sizes, ranges, hp_key, trailers) and detect(frame.data):
                sources.add((frame.address, frame.port))
        if frame.address != address:
            continue
        if frame.low < epoch:
            gaps.append((frame.low, frame.high, "a frame from %s that may have arrived before the epoch (%d~%d)"
                         % (address, frame.low, frame.high)))
        elif frame.kind == "malformed" or (frame.kind == "fragment" and frame.port == port):
            gaps.append((frame.low, frame.high, "a %s frame from %s at %d~%d (%s)"
                         % (frame.kind, address, frame.low, frame.high, frame.data.hex() or "-")))
        elif frame.kind == "datagram" and frame.port == port:
            frames.append(frame)
    if len(sources) >= MAX_HINT_SOURCES:
        raise Undecided("%d sources left hints, as many as the device keeps" % len(sources))
    datagrams = [Datagram(frame, sizes, ranges, mac1_key, hp_key, trailers) for frame in frames]
    initiations = [index for index, datagram in enumerate(datagrams) if datagram.kind == "initiation"]
    if not initiations:
        raise Undecided("no initiation from this client reached the server by the window's end")
    if len(initiations) > MAX_INITIATIONS:
        raise Undecided("%d initiations are more histories than this model enumerates" % len(initiations))
    if window_end - datagrams[initiations[0]].low > CONNECTION_EXPIRY_CS:
        raise Undecided("the window ends so long after the first initiation that a connected socket may have expired")
    relevant = [index for index, datagram in enumerate(datagrams) if datagram.kind in ("hint", "initiation")]
    outcomes = {}
    shown = None
    histories = 0
    for mask in range(1, 1 << len(initiations)):
        accepted = {initiations[bit] for bit in range(len(initiations)) if mask >> bit & 1}
        if not all(any(datagrams[k].low <= up and datagrams[k].high >= start for k in accepted)
                   for start, up in establishments):
            continue
        first = min(accepted)
        switches = [None] + [index for index in relevant if index > first]
        if connected is not None:
            # Datagrams that arrived after the connected socket was seen
            # reached it.
            later = [index for index in relevant if index > first and datagrams[index].low > connected]
            if later:
                switches = [switch for switch in switches if switch is not None and switch <= later[0]]
        for switch in switches:
            pending = [[]]
            while pending:
                choices = pending.pop()
                histories += 1
                if histories > MAX_HISTORIES:
                    raise Undecided("more than %d histories" % MAX_HISTORIES)
                history = History(datagrams, accepted, switch, choices, establishments, steps)
                history.sizes, history.hp_key = sizes, hp_key
                try:
                    learned, learned_at, notes = history.run()
                except Branch:
                    pending.append(choices + [False])
                    pending.append(choices + [True])
                    continue
                pinned = history.bound[learned_at] if learned is not None else INFINITY
                for low, high, what in gaps:
                    if high >= epoch and low <= min(pinned, window_end):
                        raise Undecided("%s, before the selection was certainly pinned" % what)
                outcome = history_expectation(history, learned, learned_at, window_start, window_end)
                outcomes.setdefault(outcome, describe(history, initiations))
                if shown is None:
                    shown = notes
    if not outcomes:
        raise Undecided("no history agrees with the establishments %s%s" % (
            establishments or "given", "; the record has a gap: %s" % gaps[0][2] if gaps else ""))
    if len(outcomes) > 1:
        raise Undecided("the outcome depends on the history: " +
                        "; ".join("%s if %s" % (outcome, how) for outcome, how in sorted(outcomes.items())))
    for low, high, what in gaps:
        shown.append("%s: after the selection was pinned or before the epoch, it cannot change it" % what)
    shown.append("%d histories of %d initiations considered" % (histories, len(initiations)))
    return next(iter(outcomes)), shown


def describe(history, initiations):
    accepted = ",".join("#%d" % (k + 1) for k in sorted(history.accepted))
    switch = "never" if history.switch is None else "from #%d" % (history.switch + 1)
    return "accepted %s, connected socket %s, timing choices %s" % (accepted, switch, history.choices or "none")


def main(argv):
    try:
        if len(argv) == 4 and argv[0] == "probe" and argv[1] in PROBES:
            print(probe(argv[1], argv[2], argv[3]))
        elif len(argv) in (6, 8) and argv[0] == "capture":
            return capture(*argv[1:])
        elif len(argv) in (7, 9) and argv[0] == "capture-to":
            return capture(*argv[2:], destination_port=argv[1])
        elif len(argv) == 7 and argv[0] == "record":
            return record(*argv[1:])
        elif len(argv) in (11, 12, 13) and argv[0] == "auto-expect":
            return auto_expect(*argv[1:])
        elif len(argv) == 3 and argv[0] == "classify":
            classify(argv[1], argv[2])
        elif len(argv) == 3 and argv[0] == "classify-auto":
            classify_auto(argv[1], argv[2])
        elif len(argv) == 5 and argv[0] == "send" and argv[1] in HINTS:
            print(send(*argv[1:]))
        elif (len(argv) == 4 and argv[0] == "candidates" and
              ((argv[1] == "send" and argv[2] in HINTS) or (argv[1] == "probe" and argv[2] in PROBES))):
            print(candidates(*argv[1:]))
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
