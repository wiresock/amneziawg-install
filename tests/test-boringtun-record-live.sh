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
import os, pathlib, signal, socket, subprocess, sys, threading, time
WIRE, WORK = sys.argv[1], pathlib.Path(sys.argv[2])
PASSED = FAILED = 0


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


def start(name, buffer=None):
    path = WORK / (name + ".record")
    env = dict(os.environ)
    if buffer:
        env["BT_WIRE_RECORD_BUFFER"] = str(buffer)
    process = subprocess.Popen([sys.executable, "-B", WIRE, "record", "51998", "any", "127.0.0.1", "41006", "120", str(path)],
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

print()
print("BoringTun record live test: %d passed, %d failed" % (PASSED, FAILED))
sys.exit(1 if FAILED else 0)
PY
