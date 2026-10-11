#!/bin/bash
# Live test of the wire helper's `record` (tests/helpers/boringtun-imitation-
# wire.py), the server-side record that the imitation auto checks derive
# their expectations from, with a real packet socket in a fresh network
# namespace: UDP datagrams from 127.0.0.1:41006 to 127.0.0.1:51998 over its
# loopback, while the record is paused (SIGSTOP) where a scheduler delay
# would pause it.
#   delayed-read:   two datagrams wait 2.2 s in the queue; each is recorded at
#                   its kernel arrival time, not when it was read.
#   queued-at-stop: 50 datagrams are queued when the authorized stop comes;
#                   all 50 are recorded before the end marker "complete".
#   overflow:       a 4 KiB receive buffer (BT_WIRE_RECORD_BUFFER) and 1000
#                   datagrams sent while the record, just ready, is paused:
#                   every datagram is either recorded or counted in a drops
#                   line, and some are dropped.
#   flood-at-stop:  datagrams keep coming while it stops: it still ends within
#                   its drain budget, with an end marker.
#   interrupted:    a SIGTERM nobody authorized ends it "interrupted" (status 3).
#   poll-preempted: the record stopped right after its drop counters reset
#                   while 1000 datagrams overflow it: the drops line's interval
#                   begins before the reset (third review, finding 4).
#   clock-preempted-1, -2: a clock reading stopped 3 s between its realtime
#                   reads; each arrival still holds its send (finding 3).
#   delivery:       the UDP sockets on the record's port: a listener's and a
#                   connected socket's drops, sockets closed after a reading
#                   saw them, one no reading could see (finding 2).
#   capture:        the client side's capture, stopped after 20 STUN-shaped
#                   datagrams while 2 more and 1 unshaped arrive, ends at its
#                   deadline or an authorized stop with all 23, and the STUN
#                   verdict fails; a clean control passes; an overflowed
#                   capture ends incomplete and is never judged (finding 1).
#
# Requirements: root, ip (iproute2) with network namespaces, python3 and
# AWG_DISPOSABLE_HOST_TEST=1.
#
# Usage: AWG_DISPOSABLE_HOST_TEST=1 bash tests/test-boringtun-record-live.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIRE="${SCRIPT_DIR}/helpers/boringtun-imitation-wire.py"
NETNS="awgrec-$(printf '%04x' $((RANDOM % 65536)))"
WORK=""

die() {
	echo "ERROR: $*" >&2
	exit 2
}
[[ "${AWG_DISPOSABLE_HOST_TEST:-}" == 1 ]] || die "this test creates a network namespace; set AWG_DISPOSABLE_HOST_TEST=1 on a disposable host"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
if ip netns list 2>/dev/null | grep -qE "^${NETNS}( |$)"; then
	die "namespace ${NETNS} already exists; it is not this run's"
fi
cleanup() {
	local RC=$?
	trap - EXIT
	ip netns delete "${NETNS}" 2>/dev/null
	[[ -n "${WORK}" ]] && rm -rf "${WORK}"
	exit "${RC}"
}
trap cleanup EXIT
WORK="$(mktemp -d /var/tmp/awg-record-live.XXXXXX)"
ip netns add "${NETNS}" && ip -n "${NETNS}" link set lo up || die "cannot set up namespace ${NETNS}"

ip netns exec "${NETNS}" python3 - "${WIRE}" "${WORK}" <<'PY'
import base64, errno, hashlib, importlib.util, io, os, pathlib, signal, socket, struct, subprocess, sys, threading, time
WIRE, WORK = sys.argv[1], pathlib.Path(sys.argv[2])
PASSED = FAILED = 0
LOADED = []


def load_wire():
    """The helper as a module, for the parts run in this process."""
    if not LOADED:
        spec = importlib.util.spec_from_file_location("wire", WIRE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        LOADED.append(module)
    return LOADED[0]


def check(message, condition):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print("  OK: " + message, flush=True)
    else:
        FAILED += 1
        print("  FAIL: " + message, flush=True)


def boot_cs():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 10 ** 7


def start(name, buffer=None, port="51998", source_port="41006"):
    path = WORK / (name + ".record")
    env = dict(os.environ)
    if buffer:
        env["BT_WIRE_RECORD_BUFFER"] = str(buffer)
    process = subprocess.Popen([sys.executable, "-B", WIRE, "record", port, "any", "127.0.0.1", source_port, "120", str(path)],
                               env=env)
    state = pathlib.Path(str(path) + ".state")
    for _ in range(500):
        if state.exists() and state.read_text().startswith("ready "):
            return process, path
        time.sleep(0.01)
    process.kill()
    raise SystemExit("the record did not become ready")


def pause(process):
    process.send_signal(signal.SIGSTOP)
    for _ in range(200):
        if pathlib.Path("/proc/%d/stat" % process.pid).read_text().rsplit(")", 1)[1].split()[0] == "T":
            return
        time.sleep(0.005)
    raise SystemExit("the record did not stop")


def stop(process, path, authorized=True):
    if authorized:
        pathlib.Path(str(path) + ".stop").write_text("a" * 32 + "\n")
    process.send_signal(signal.SIGTERM)
    process.send_signal(signal.SIGCONT)
    return process.wait(timeout=30)


def lines(path):
    return path.read_text().splitlines()


def datagrams(rows):
    return [row for row in rows if " 127.0.0.1 41006 " in row]


receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(("127.0.0.1", 51998))
receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.bind(("127.0.0.1", 41006))


def send(count, size=8):
    for i in range(count):
        sender.sendto(b"%08d" % i + bytes(max(0, size - 8)), ("127.0.0.1", 51998))


print("--- delayed-read")
process, path = start("delayed-read")
pause(process)
sent = boot_cs()
send(2)
time.sleep(2.2)
rc = stop(process, path)
rows = lines(path)
stamps = [int(row.split()[0]) for row in datagrams(rows) if "~" not in row.split()[0]]
check("it exits 0 after its authorized stop (%d)" % rc, rc == 0)
check("both datagrams are recorded with a kernel arrival stamp (%d of 2)" % len(stamps), len(stamps) == 2)
check("each at its arrival, within 0.05 s of the send, not 2.2 s later when it was read (%s, sent at %d)" % (stamps, sent),
      len(stamps) == 2 and all(sent - 1 <= stamp <= sent + 5 for stamp in stamps))
check("the record ends complete (%s)" % rows[-1:], bool(rows) and " - complete " in rows[-1])

print("--- queued-at-stop")
process, path = start("queued-at-stop")
pause(process)
send(50)
rc = stop(process, path)
rows = lines(path)
check("it exits 0 after its authorized stop (%d)" % rc, rc == 0)
check("all 50 datagrams queued at the stop are recorded (%d)" % len(datagrams(rows)), len(datagrams(rows)) == 50)
check("before the end marker, which says complete (%s)" % rows[-1:], bool(rows) and " - complete " in rows[-1])

print("--- overflow")
process, path = start("overflow", buffer=4096)
pause(process)
send(1000, 512)
rc = stop(process, path)
rows = lines(path)
recorded = len(datagrams(rows))
dropped = sum(int(row.split()[3]) for row in rows if " - drops " in row)
check("it exits 0 after its authorized stop (%d)" % rc, rc == 0)
check("the 4 KiB buffer overflowed while it was paused just after ready, and the drops are reported (%d)" % dropped, dropped > 0)
check("every datagram is recorded or counted as dropped: %d + %d of 1000" % (recorded, dropped), recorded + dropped == 1000)

print("--- flood-at-stop")
process, path = start("flood-at-stop")
flooding = [True]


def flood():
    while flooding[0]:
        send(200, 64)


thread = threading.Thread(target=flood)
thread.start()
time.sleep(0.5)
began = time.monotonic()
rc = stop(process, path)
took = time.monotonic() - began
flooding[0] = False
thread.join()
rows = lines(path)
check("under continuing traffic it still ends within its drain budget (%.1f s, status %d)" % (took, rc), rc == 0 and took < 10)
check("with an end marker that says whether it is complete (%s)" % rows[-1][:60:], bool(rows) and (" - complete " in rows[-1] or " - incomplete " in rows[-1]))

print("--- interrupted")
process, path = start("interrupted")
rc = stop(process, path, authorized=False)
transcript = pathlib.Path(str(path) + ".state").read_text().splitlines()
check("a SIGTERM nobody authorized ends it with status 3 (%d)" % rc, rc == 3)
check("and the transcript says interrupted (%s)" % transcript[-1:], len(transcript) == 2 and transcript[1].startswith("interrupted "))

# The helper's record with one function patched to stop the process where a
# scheduler would preempt it: PATCH names the function, ARM a file whose
# presence arms it, PAUSED the file it writes (with the clock) when it stops.
PATCHED = r'''
import importlib.util, os, pathlib, signal, sys, time
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
patch, arm, paused = sys.argv[2], pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
def pause():
    paused.write_text("%d\n" % (time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 10 ** 7))
    os.kill(os.getpid(), signal.SIGSTOP)
if patch.startswith("sample-"):
    # The Nth clock reading a batch takes after arming stops between its
    # first realtime read and its boottime read.
    which, calls = int(patch.split("-")[1]), [0]
    def sample(self):
        real_before = time.clock_gettime_ns(time.CLOCK_REALTIME)
        if sys._getframe(1).f_code.co_name == "batch" and arm.exists():
            calls[0] += 1
            if calls[0] == which:
                arm.unlink()
                pause()
        boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        mono = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        real_after = time.clock_gettime_ns(time.CLOCK_REALTIME)
        return wire.ClockSample(boot, (real_before + real_after) // 2 - boot, abs(real_after - real_before), boot - mono)
    wire.SystemClocks.sample = sample
elif patch == "drops":
    # The first poll after arming stops right after the counters reset.
    original = wire.PacketSource.drops
    def drops(self):
        count = original(self)
        if arm.exists() and sys._getframe(1).f_code.co_name == "poll":
            arm.unlink()
            pause()
        return count
    wire.PacketSource.drops = drops
sys.exit(wire.record(*sys.argv[5:]))
'''


def start_patched(name, patch, buffer=None):
    path = WORK / (name + ".record")
    arm, paused = WORK / (name + ".arm"), WORK / (name + ".paused")
    env = dict(os.environ)
    if buffer:
        env["BT_WIRE_RECORD_BUFFER"] = str(buffer)
    process = subprocess.Popen([sys.executable, "-B", "-c", PATCHED, WIRE, patch, str(arm), str(paused),
                                "51998", "any", "127.0.0.1", "41006", "120", str(path)], env=env)
    state = pathlib.Path(str(path) + ".state")
    for _ in range(500):
        if state.exists() and state.read_text().startswith("ready "):
            return process, path, arm, paused
        time.sleep(0.01)
    process.kill()
    raise SystemExit("the record did not become ready")


def stopped(process, paused):
    """The clock at which the armed record stopped itself."""
    for _ in range(500):
        if paused.exists() and pathlib.Path("/proc/%d/stat" % process.pid).read_text().rsplit(")", 1)[1].split()[0] == "T":
            return int(paused.read_text())
        time.sleep(0.01)
    raise SystemExit("the record did not stop where it was armed to")


def arrival(row):
    """(low, high) centiseconds of a record line's arrival field."""
    low, _, high = row.split()[0].partition("~")
    return int(low), int(high) if high else int(low) + 1


print("--- poll-preempted")
process, path, arm, paused = start_patched("poll-preempted", "drops", buffer=4096)
arm.touch()
reset = stopped(process, paused)
sent = boot_cs()
send(1000, 512)
sent_end = boot_cs()
time.sleep(0.5)
process.send_signal(signal.SIGCONT)
rc = stop(process, path)
markers = [row.split() for row in lines(path) if " - drops " in row]
check("it exits 0 after its authorized stop (%d)" % rc, rc == 0)
check("the datagrams sent while it was stopped after the reset (%d to %d) were dropped and reported (%s)"
      % (sent, sent_end, [" ".join(marker) for marker in markers]), bool(markers))
check("their interval begins no later than the reset (%d) and ends after the last send" % reset,
      bool(markers) and int(markers[0][4]) <= reset <= sent and int(markers[0][0]) >= sent_end)

for which, label in ((1, "the reading before the queue was found empty"), (2, "the reading after the batch")):
    print("--- clock-preempted-%d" % which)
    # The datagram is queued while the record is stopped, so that the batch
    # that reads it takes the armed reading; the second comes right after
    # the preempted reading, before an idle wakeup could replace it.
    process, path, arm, paused = start_patched("clock-preempted-%d" % which, "sample-%d" % which)
    pause(process)
    first = boot_cs()
    send(1)
    arm.touch()
    process.send_signal(signal.SIGCONT)
    stopped(process, paused)
    time.sleep(3)
    process.send_signal(signal.SIGCONT)
    second = boot_cs()
    send(1)
    time.sleep(0.3)
    rc = stop(process, path)
    rows = datagrams(lines(path))
    bounds = [arrival(row) for row in rows]
    check("it exits 0, both datagrams recorded (%d, %s)" % (rc, [row.split()[0] for row in rows]), rc == 0 and len(rows) == 2)
    check("preempting %s: each arrival holds its send (%d, %d) and is at most 4 s wide (%s)" % (label, first, second, bounds),
          len(bounds) == 2 and all(low - 1 <= at <= high and high - low <= 400 for (low, high), at in zip(bounds, (first, second))))

print("--- delivery")
DELIVERY_PORT = 51999


def overflow(sock, sender_port, count=200):
    """Send COUNT datagrams to SOCK's full queue from SENDER_PORT, then
    drain it: how many the socket dropped."""
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", sender_port))
    for i in range(count):
        peer.sendto(b"%08d" % i + bytes(504), ("127.0.0.1", DELIVERY_PORT))
    peer.close()
    sock.setblocking(False)
    queued = 0
    while True:
        try:
            sock.recv(2048)
        except BlockingIOError:
            return count - queued
        queued += 1


process, path = start("delivery", port=str(DELIVERY_PORT), source_port="any")
time.sleep(0.6)
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
listener.bind(("127.0.0.1", DELIVERY_PORT))
time.sleep(0.6)
lost = overflow(listener, 41011)
time.sleep(0.6)
listener.close()
time.sleep(0.6)
connected = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
connected.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
connected.bind(("127.0.0.1", DELIVERY_PORT))
connected.connect(("127.0.0.1", 41007))
time.sleep(0.6)
lost_connected = overflow(connected, 41007)
time.sleep(0.6)
connected.close()
time.sleep(0.6)
pause(process)
brief = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
brief.bind(("127.0.0.1", DELIVERY_PORT))
brief.connect(("127.0.0.1", 41012))
brief.close()
time.sleep(0.3)
process.send_signal(signal.SIGCONT)
time.sleep(0.6)
rc = stop(process, path)
rows = lines(path)
found = [row.split() for row in rows if " - delivery " in row]
watch = rows[0].split() if rows else ["0"]
check("it exits 0, its first line the delivery watch of port %d (%s)" % (DELIVERY_PORT, " ".join(watch)),
      rc == 0 and watch[1:] == ["-", "delivery-watch", str(DELIVERY_PORT)])


def counted(peer):
    return sum(int(row[3]) for row in found if row[5] == peer and row[3] != "unknown")


def unknown(peer):
    return [row for row in found if row[5] == peer and row[3] == "unknown"]


check("the listener's %d drops are reported for any endpoint (%s)" % (lost, [" ".join(row[3:]) for row in found]),
      lost > 0 and counted("any") == lost)
check("the connected socket's %d drops for its endpoint, 127.0.0.1:41007 (%d)" % (lost_connected, counted("127.0.0.1:41007")),
      lost_connected > 0 and counted("127.0.0.1:41007") == lost_connected)
since_watch = [row for row in unknown("any") if int(row[4]) <= int(watch[0])]
check("each socket closed after a reading saw it leaves what it lost after that reading unknown, once",
      len(unknown("any")) - len(since_watch) == 1 and len(unknown("127.0.0.1:41007")) == 1)
check("a socket created and closed while no reading could see it (connected to 127.0.0.1:41012 when closed): unknown "
      "since the watch began, for any endpoint", len(since_watch) == 1)
check("and nothing for anyone else", all(row[5] in ("any", "127.0.0.1:41007") for row in found))
check("the watch ends after the cutoff, before the end marker (%s)" % rows[-2:-1],
      len(rows) >= 2 and " - delivery-end " in rows[-2])

print("--- unseen-connect")
# The fourth review's socket: bound to the watched port with a 4 KiB buffer,
# it drops datagrams from 127.0.0.1:41006, is then connected to
# 127.0.0.1:41007 and closed before any reading sees it. Its destruction
# names 41007, but its losses were 41006's: the watch must not narrow them.
UNSEEN_PORT = 52127
watcher = load_wire().DeliveryWatch(UNSEEN_PORT)
check("the watch begins on port %d" % UNSEEN_PORT, watcher.begin())
unseen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
unseen.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
unseen.bind(("127.0.0.1", UNSEEN_PORT))
for _ in range(200):
    sender.sendto(bytes(80), ("127.0.0.1", UNSEEN_PORT))
dropped = load_wire().udp_sockets(UNSEEN_PORT)
unseen.connect(("127.0.0.1", 41007))
unseen.close()
time.sleep(0.05)
losses = watcher.read()
check("the socket dropped 41006's datagrams before it was connected (%s)" % dropped,
      any(drops > 0 for _, drops in dropped.values()))
check("its unseen lifetime is unknown for any endpoint, not only 41007 (%s)" % losses, losses == [(None, "any", True)])
watcher.events.close()

print("--- capture")
CAPTURE_PORT = 41010
capture_receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
capture_receiver.bind(("127.0.0.1", CAPTURE_PORT))
capture_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
capture_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
capture_sender.bind(("127.0.0.1", 52000))
GOOD = bytes.fromhex("000100002112a442") + bytes(92)
BAD = bytes(100)


def start_capture(name, seconds, buffer=None):
    path = WORK / (name + ".capture")
    env = dict(os.environ)
    if buffer:
        env["BT_WIRE_RECORD_BUFFER"] = str(buffer)
    process = subprocess.Popen([sys.executable, "-B", WIRE, "capture", "lo", "127.0.0.1", "52000", str(seconds), str(path)],
                               env=env)
    state = pathlib.Path(str(path) + ".state")
    for _ in range(500):
        if state.exists() and state.read_text().startswith("ready "):
            return process, path
        time.sleep(0.01)
    process.kill()
    raise SystemExit("the capture did not become ready")


def verdict(path):
    """bt_wire_auto_verdict stun on the capture: (status, reason)."""
    checks = os.path.join(os.path.dirname(WIRE), "boringtun-wire-checks.sh")
    result = subprocess.run(["bash", "-c", 'WIRE="$1"; source "$2"; bt_wire_auto_verdict stun "$3" prefixes; echo "$? ${BT_WIRE_REASON}"',
                             "_", WIRE, checks, str(path)], capture_output=True, text=True)
    status, _, reason = result.stdout.strip().rpartition("\n")[2].partition(" ")
    return int(status) if status.isdigit() else 9, reason


for mode in ("deadline", "authorized-stop", "clean"):
    process, path = start_capture("capture-" + mode, 3)
    for _ in range(20):
        capture_sender.sendto(GOOD, ("127.0.0.1", CAPTURE_PORT))
    for _ in range(500):
        if path.exists() and len(lines(path)) == 20:
            break
        time.sleep(0.01)
    pause(process)
    for datagram in (GOOD, GOOD, GOOD if mode == "clean" else BAD):
        capture_sender.sendto(datagram, ("127.0.0.1", CAPTURE_PORT))
    if mode == "authorized-stop":
        rc = stop(process, path)
    else:
        time.sleep(3.1)
        process.send_signal(signal.SIGCONT)
        rc = process.wait(timeout=30)
    transcript = pathlib.Path(str(path) + ".state").read_text().splitlines()
    status, reason = verdict(path)
    check("%s: it exits 0 and its end counts all 23 datagrams, the 3 that arrived while it was stopped too (%d, %s)"
          % (mode, rc, transcript[-1:]), rc == 0 and len(lines(path)) == 23 and transcript[-1].split()[1] == "23")
    if mode == "clean":
        check("clean: 23 STUN-shaped datagrams pass the STUN verdict (%s)" % reason, status == 0)
    else:
        check("%s: the unshaped datagram fails the STUN verdict (%s)" % (mode, reason), status == 1 and " 1 other" in reason)

process, path = start_capture("capture-overflow", 3, buffer=4096)
pause(process)
for _ in range(1000):
    capture_sender.sendto(GOOD, ("127.0.0.1", CAPTURE_PORT))
process.send_signal(signal.SIGCONT)
rc = process.wait(timeout=30)
transcript = pathlib.Path(str(path) + ".state").read_text().splitlines()
status, reason = verdict(path)
check("a capture whose socket dropped frames ends incomplete with status 4, its drops counted (%d, %s)" % (rc, transcript[-1:]),
      rc == 4 and transcript[-1].startswith("incomplete ") and int(transcript[-1].split()[2]) > 0)
check("and no verdict judges it, however many good datagrams it holds (%s)" % reason, status == 1 and "not whole" in reason)

print("--- final-collection")
# The fourth review's race, in this process with real sockets: a socket on
# the watched port, first created after the watch's baseline, is closed
# while the final collection's first dump runs, so that no dump sees it.
# A SIP hint and a mac1-consistent initiation reach it from 41006 before the
# cutoff. Its unknown lifetime must reach the record, and auto-expect must
# not decide; the clean control (the socket stays open) decides sip. The
# review's own variant adds 200 datagrams into a 4 KiB buffer first.
wire = load_wire()
KEY = bytes(range(32, 64))
NARROW = "40,40,40,40,100000001-100000100,200000001-200000100,300000001-300000100,400000001-400000100"
SIP_HINT = b"OPTIONS sip:a@b SIP/2.0\r\n\r\n"
BODY = struct.pack("<II", 100000007, 0x01020304) + bytes(108)
INITIATION = bytes(40) + BODY + hashlib.blake2s(BODY, digest_size=16, key=hashlib.blake2s(b"mac1----" + KEY).digest()).digest() \
    + bytes(16)


class Gate:
    """The watch's notification socket, held shut until UNTIL (monotonic):
    real notifications, delivered late."""

    def __init__(self, sock):
        self.sock, self.until = sock, 0.0

    def recv(self, size):
        if time.monotonic() < self.until:
            raise BlockingIOError()
        return self.sock.recv(size)

    def close(self):
        self.sock.close()


PORT_RANGE = "/proc/sys/net/ipv4/ip_local_port_range"


def final_collection(name, port, close, flood, delay=0.0, fail_last=False, lock_port=False, block=False):
    """CLOSE: the socket is closed during the final collection's first dump
    (its notifications then held DELAY s); FAIL_LAST: the last dump fails
    (an injected OSError); LOCK_PORT: this namespace's ephemeral range is
    the watched port alone during the final collection, so the canary's
    bind(port 0) gets that port once the socket is gone; BLOCK: every
    notification is held past the final collection's wait."""
    clocks = wire.SystemClocks()
    created = clocks.sample()
    packets = wire.PacketSource("lo", 32 * 1024 * 1024)
    watch, out = wire.DeliveryWatch(port), io.StringIO()
    recorder = wire.Recorder(packets, clocks, out, {socket.inet_aton("127.0.0.1")}, None, port, created, watch)
    ready = recorder.begin()
    gate = watch.events = Gate(watch.events)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if flood:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    server.bind(("127.0.0.1", port))
    client = sender  # 127.0.0.1:41006
    time.sleep(0.1)
    for _ in range(200 if flood else 0):
        client.sendto(bytes(80), ("127.0.0.1", port))
    client.sendto(SIP_HINT, ("127.0.0.1", port))
    time.sleep(0.02)
    born = boot_cs()
    client.sendto(INITIATION, ("127.0.0.1", port))
    up = boot_cs() + 1
    time.sleep(0.2)
    cutoff = clocks.boot()
    real_dump, real_socket, dumps, bound = wire.udp_sockets, socket.socket, [0], []

    def final_dump(watched):
        dumps[0] += 1
        if dumps[0] == 1 and close:
            server.close()
            gate.until = time.monotonic() + delay
            time.sleep(0.05 if not delay else 0.02)
        if dumps[0] == 2 and fail_last:
            raise OSError(errno.EINTR, "injected: the last dump failed")
        return real_dump(watched)

    class Recording(real_socket):
        def bind(self, address):
            real_socket.bind(self, address)
            if self.family == socket.AF_INET and address[1] == 0:
                bound.append(self.getsockname()[1])

    with open(PORT_RANGE) as current:
        saved_range = current.read().strip()
    wire.udp_sockets = final_dump
    wire.socket.socket = Recording
    if block:
        gate.until = time.monotonic() + 1.0
    if lock_port:
        with open(PORT_RANGE, "w") as locked:
            locked.write("%d %d\n" % (port, port))
    try:
        recorder.finish(cutoff)
    finally:
        wire.udp_sockets, wire.socket.socket = real_dump, real_socket
        with open(PORT_RANGE, "w") as restored:
            restored.write(saved_range.replace("\t", " ") + "\n")
        server.close()
        packets.sock.close()
        watch.events.close()
    if bound:
        print("    (%s: the canary was bound to port %d)" % (name, bound[-1]))
    path = WORK / (name + ".record")
    path.write_text(out.getvalue())
    pathlib.Path(str(path) + ".state").write_text("ready 1 1 %d\nstopped %d %s\n" % (wire.centiseconds_down(ready.boot),
                                                                                     recorder.records, "a" * 32))
    verdict = subprocess.run([sys.executable, "-B", WIRE, "auto-expect", str(path), "127.0.0.1", "41006", NARROW,
                              base64.b64encode(KEY).decode(), "-", "off", str(wire.centiseconds_down(ready.boot) + 1),
                              str(up + 2), str(wire.centiseconds_down(cutoff)), "%d:%d" % (born, up), "-"],
                             capture_output=True, text=True).stdout.strip().splitlines()
    markers = [line for line in out.getvalue().splitlines() if " - " in line]
    return markers, verdict[-1] if verdict else "-", bound


markers, verdict, _ = final_collection("final-clean", 52130, close=False, flood=False)
check("clean control: the socket stays open; no loss is reported and the record decides sip (%s; %s)" % (markers, verdict),
      verdict == "expect sip" and not any(" - delivery unknown " in marker for marker in markers))
for name, port, flood in (("final-closed", 52131, False), ("final-closed-flooded", 52129, True)):
    markers, verdict, _ = final_collection(name, port, close=True, flood=flood)
    check("%s: closed during the final dump, its unknown lifetime reaches the record (%s)" % (name, markers),
          any(marker.endswith(" any") and " - delivery unknown " in marker for marker in markers))
    check("%s: and auto-expect does not decide (%s)" % (name, verdict), verdict.startswith("undecided the hint #"))

print("--- final-pending")
# The fifth review's cases, real drops and real notifications: the socket
# (200 datagrams into 4 KiB, a SIP hint, an initiation) closes during the
# final collection's first dump and its notifications are held 90 ms, so
# that they arrive while the watch waits. Then the last dump fails (an
# injected OSError): the notifications already received must still reach
# the record. Control: the same with a last dump that succeeds.
for name, port, fail in (("final-failed-last-dump", 52132, True), ("final-pending-control", 52133, False)):
    markers, verdict, _ = final_collection(name, port, close=True, flood=True, delay=0.09, fail_last=fail)
    check("%s: the socket's unknown lifetime, since the watch began, reaches the record (%s)" % (name, markers),
          any(" - delivery unknown " in marker and marker.endswith(" any") and int(marker.split()[4]) <= int(markers[0].split()[0])
              for marker in markers))
    check("%s: and auto-expect does not decide (%s)" % (name, verdict), verdict.startswith("undecided the hint #"))

print("--- canary-identity")
# The watched port becomes free when the socket closes; with this
# namespace's ephemeral range locked to it, the canary's bind(port 0) is
# given that very port. Only the canary's own notification (its cookie) may
# be set aside: the socket's must still reach the record. Controls: a canary
# on an ordinary port with the socket left open decides sip (final-clean
# above); with every notification held past the wait, nothing since the
# watch began is covered.
markers, verdict, bound = final_collection("canary-port-reuse", 52134, close=True, flood=True, delay=0.09, lock_port=True)
check("canary-port-reuse: the canary was given the watched port (%s)" % bound, bound[-1:] == [52134])
check("canary-port-reuse: the socket's unknown lifetime still reaches the record (%s)" % markers,
      any(" - delivery unknown " in marker and marker.endswith(" any") and int(marker.split()[4]) <= int(markers[0].split()[0])
          for marker in markers))
check("canary-port-reuse: and auto-expect does not decide (%s)" % verdict, verdict.startswith("undecided the hint #"))
markers, verdict, _ = final_collection("canary-missing", 52135, close=False, flood=False, block=True)
check("canary-missing: no notification in time, so nothing since the watch began is covered (%s)" % markers,
      any(" - delivery unknown " in marker and marker.endswith(" any") and int(marker.split()[4]) <= int(markers[0].split()[0])
          for marker in markers))
check("canary-missing: and auto-expect does not decide (%s)" % verdict, verdict.startswith("undecided the hint #"))
with open(PORT_RANGE) as current:
    restored = current.read().split()
check("the namespace's ephemeral port range is restored (%s)" % restored, restored != ["52134", "52134"])

print()
print("BoringTun record live test: %d passed, %d failed" % (PASSED, FAILED))
sys.exit(1 if FAILED else 0)
PY
