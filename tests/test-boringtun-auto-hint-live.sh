#!/bin/bash
# Live, deterministic test of the planted SIP hint that the imitation auto
# checks of tests/test-boringtun-host-live.sh rely on, on the given
# boringtun-cli (the verified binary of the release under test). A server with
# --imitate-protocol auto (at --verbosity info, so that its warnings are
# visible) and a stock client (--imitate-protocol none, listen port 41006) run
# in fresh network namespaces with fixed S1-S4 and H1-H4. Before the client
# starts, a datagram is sent to the server from the client's address and
# port; the client's side then records the server's datagrams while the
# client pings through the tunnel.
#
# The layout is S1=27 S2=113 S3=125 S4=37 with H4 1767000000-1866999999, the S
# sizes of the BoringTun Host job that failed (run 37615364152) and an H4 that
# holds the four bytes the 247-byte SIP probe of
# tests/helpers/boringtun-imitation-wire.py has at offset 37. Under it:
#   collision: that probe, the hint the live test planted before, is an
#     AmneziaWG transport candidate (at least S4 + 32 bytes, its tag at S4 in
#     H4), so the server takes it for AmneziaWG traffic and never for a hint:
#     no response or transport to that client carries a SIP request line.
#     This is the failure the host test saw whenever its random layout made
#     the probe a candidate.
#   hint: the 27-byte request line that `send sip` plants, shorter than any
#     AmneziaWG datagram, is learned: with S2 and S4 of 31 bytes or more,
#     every response and transport carries a request line.
#   AWG 3.0, hint: with a header-protection key the same hint draws
#     BoringTun's warning that the header-protection policy refused the
#     learned sip, and no datagram to the client carries a SIP shape.
#   AWG 3.0, no hint: no such warning, and no SIP shape either; so the
#     warning above is the hint's.
# Every capture must be ready before its traffic, run its whole interval and
# complete (tests/helpers/boringtun-wire-checks.sh).
# A scenario's evidence is judged only if every step of it succeeded: the
# setup, the capture, the planted datagram (its sender's exit status and its
# exact report), the client, the tunnel and the capture's completion. Its
# capture is removed before it starts, so nothing of an earlier scenario can
# stand in for its own.
#
# Requirements: root, ip (iproute2) with network namespaces, /dev/net/tun, awg
# (amneziawg-tools), ping, python3 and AWG_DISPOSABLE_HOST_TEST=1. With
# AWG_LIVE_SECRET_SCAN set, the keys generated here join that output scan.
#
# Usage: AWG_DISPOSABLE_HOST_TEST=1 bash tests/test-boringtun-auto-hint-live.sh <boringtun-cli>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034 # read by the sourced boringtun-wire-checks.sh
WIRE="${SCRIPT_DIR}/helpers/boringtun-imitation-wire.py"
BIN="${1:-}"
RUN_ID="$(printf '%04x' $((RANDOM % 65536)))"
NS_S="awgah-s-${RUN_ID}"
NS_C="awgah-c-${RUN_ID}"
VETH_S="awgahv${RUN_ID}s"
VETH_C="awgahv${RUN_ID}c"
IF_S="awgahs${RUN_ID}"
IF_C="awgahc${RUN_ID}"
ADDR_S="203.0.113.1"
ADDR_C="203.0.113.2"
TUN_S="10.78.0.1"
TUN_C="10.78.0.2"
PORT=51998
CLIENT_PORT=41006
S_SIZES="27,113,125,37"
H_RANGES="100000001-100000100,200000001-200000100,300000001-300000100,1767000000-1866999999"
CAPTURE_SECONDS=12
REFUSAL='auto imitation refused by header-protection policy; retaining random prefixes'
WORK=""
PEERS=()
CREATED_NETNS=()
PASSED=0
FAILED=0

die() {
	echo "ERROR: $*" >&2
	exit 2
}
ok() {
	echo "  OK: $1"
	PASSED=$((PASSED + 1))
}
bad() {
	echo "  FAIL: $1"
	FAILED=$((FAILED + 1))
}
check() { # <message> <command...>
	local MESSAGE="$1"
	shift
	if "$@"; then ok "${MESSAGE}"; else bad "${MESSAGE}"; fi
}
wait_for() { # <seconds> <command...>
	local LIMIT="$1" I
	shift
	for ((I = 0; I < LIMIT * 5; I++)); do
		"$@" && return 0
		sleep 0.2
	done
	return 1
}
# shellcheck source=helpers/boringtun-wire-checks.sh
source "${SCRIPT_DIR}/helpers/boringtun-wire-checks.sh"

[[ "${AWG_DISPOSABLE_HOST_TEST:-}" == 1 ]] || die "this test creates network namespaces and interfaces; set AWG_DISPOSABLE_HOST_TEST=1 on a disposable host"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -n "${BIN}" && -x "${BIN}" ]] || die "usage: $0 <boringtun-cli>"
for TOOL in ip awg ping python3; do
	command -v "${TOOL}" >/dev/null 2>&1 || die "${TOOL} is required"
done
[[ -c /dev/net/tun ]] || die "/dev/net/tun is required"

# Stop this run's peers (owned children), then remove the namespaces it made
# and the UAPI nodes of its own interface names.
teardown() {
	local HANDLE NETNS IF
	for HANDLE in "${PEERS[@]}"; do
		bt_wire_signal "${HANDLE}" TERM
		bt_wire_await "${HANDLE}" 5 || bt_wire_signal "${HANDLE}" KILL
		bt_wire_collect "${HANDLE}" >/dev/null 2>&1
	done
	PEERS=()
	bt_wire_cleanup
	for NETNS in "${CREATED_NETNS[@]}"; do
		ip netns delete "${NETNS}" 2>/dev/null
	done
	CREATED_NETNS=()
	for IF in "${IF_S}" "${IF_C}"; do
		rm -f -- "/var/run/wireguard/${IF}.sock" "/var/run/amneziawg/${IF}.sock"
	done
}
cleanup() {
	local RC=$?
	trap - EXIT
	teardown
	[[ -n "${WORK}" ]] && rm -rf "${WORK}"
	exit "${RC}"
}
trap cleanup EXIT
WORK="$(mktemp -d /var/tmp/awg-auto-hint.XXXXXX)"
chmod 0700 "${WORK}"
SERVER_KEY="$(awg genkey)"
CLIENT_KEY="$(awg genkey)"
HP_KEY="$(awg genkey)"
if [[ -n "${AWG_LIVE_SECRET_SCAN:-}" ]]; then
	printf '%s\n' "${SERVER_KEY}" "${CLIENT_KEY}" "${HP_KEY}" >>"${AWG_LIVE_SECRET_SCAN}" ||
		die "cannot add this run's keys to ${AWG_LIVE_SECRET_SCAN}"
fi
SERVER_PUB="$(awg pubkey <<<"${SERVER_KEY}")"
CLIENT_PUB="$(awg pubkey <<<"${CLIENT_KEY}")"

shared_lines() { # <hp 0|1>
	local S1 S2 S3 S4 H1 H2 H3 H4
	IFS=, read -r S1 S2 S3 S4 <<<"${S_SIZES}"
	IFS=, read -r H1 H2 H3 H4 <<<"${H_RANGES}"
	printf 'Jc = 3\nJmin = 10\nJmax = 50\nS1 = %s\nS2 = %s\nS3 = %s\nS4 = %s\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n' \
		"${S1}" "${S2}" "${S3}" "${S4}" "${H1}" "${H2}" "${H3}" "${H4}"
	(($1 == 0)) || printf 'HeaderProtectionKey = %s\n' "${HP_KEY}"
}
# Start one peer in its namespace as an owned child, configured through its
# UAPI socket once it appears.
start_peer() { # <namespace> <interface> <log> <config> <address> <peer address> <imitation> <verbosity>
	local HANDLE SOCKET
	for SOCKET in "/var/run/wireguard/$2.sock" "/var/run/amneziawg/$2.sock"; do
		if [[ -e "${SOCKET}" || -L "${SOCKET}" ]]; then
			echo "    ${SOCKET} already exists; it is not this run's and is left alone"
			return 1
		fi
	done
	bt_wire_spawn HANDLE "$3" - ip netns exec "$1" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "${BIN}" \
		--foreground --disable-drop-privileges --verbosity "$8" --imitate-protocol "$7" "$2" || return 1
	PEERS+=("${HANDLE}")
	if ! wait_for 10 test -S "/var/run/wireguard/$2.sock"; then
		sed 's/^/    | /' "$3"
		return 1
	fi
	awg setconf "$2" "$4" &&
		ip -n "$1" addr add "$5/32" dev "$2" &&
		ip -n "$1" link set "$2" up &&
		ip -n "$1" route add "$6/32" dev "$2"
}
make_netns() { # <name>
	if ip netns list 2>/dev/null | grep -qE "^$1( |$)"; then
		echo "    namespace $1 already exists; it is not this run's and is left alone"
		return 1
	fi
	ip netns add "$1" || return 1
	CREATED_NETNS+=("$1")
}
# Fresh namespaces and a server; the client is only configured.
setup() { # <hp 0|1>
	teardown
	make_netns "${NS_S}" && make_netns "${NS_C}" || return 1
	ip link add "${VETH_S}" netns "${NS_S}" type veth peer name "${VETH_C}" netns "${NS_C}" || return 1
	ip -n "${NS_S}" addr add "${ADDR_S}/24" dev "${VETH_S}" && ip -n "${NS_S}" link set "${VETH_S}" up &&
		ip -n "${NS_S}" link set lo up || return 1
	ip -n "${NS_C}" addr add "${ADDR_C}/24" dev "${VETH_C}" && ip -n "${NS_C}" link set "${VETH_C}" up &&
		ip -n "${NS_C}" link set lo up || return 1
	{
		printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' "${SERVER_KEY}" "${PORT}"
		shared_lines "$1"
		printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' "${CLIENT_PUB}" "${TUN_C}"
	} >"${WORK}/server.conf"
	{
		printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' "${CLIENT_KEY}" "${CLIENT_PORT}"
		shared_lines "$1"
		printf '\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = %s/32\n' "${SERVER_PUB}" "${ADDR_S}" "${PORT}" "${TUN_S}"
	} >"${WORK}/client.conf"
	chmod 0600 "${WORK}/server.conf" "${WORK}/client.conf"
	: >"${WORK}/server.log"
	start_peer "${NS_S}" "${IF_S}" "${WORK}/server.log" "${WORK}/server.conf" "${TUN_S}" "${TUN_C}" auto info
}
# The datagram a scenario plants from the client's port, by name: the
# helper's 27-byte SIP hint, the 247-byte SIP probe, or nothing. Each sender
# reports exactly what it sent (plant_expected) and exits 0 only if it sent it.
plant() { # <hint|probe|none>
	case "$1" in
		hint)
			ip netns exec "${NS_C}" python3 "${WIRE}" send sip "${ADDR_S}" "${PORT}" "${CLIENT_PORT}"
			;;
		probe)
			ip netns exec "${NS_C}" python3 - "${WIRE}" "${ADDR_S}" "${PORT}" "${CLIENT_PORT}" <<'PY'
import importlib.util, socket, sys
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
request, _ = wire.sip_probe()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("0.0.0.0", int(sys.argv[4])))
    if sock.sendto(request, (sys.argv[2], int(sys.argv[3]))) != len(request):
        sys.exit("short send")
print("sent %d" % len(request))
PY
			;;
		none) echo "sent nothing" ;;
		*) return 2 ;;
	esac
}
plant_expected() { # <hint|probe|none>
	case "$1" in
		hint) echo "sent 27" ;;
		probe) echo "sent 247" ;;
		none) echo "sent nothing" ;;
	esac
}
# Planting succeeded only with exit status 0 and exactly the report its kind
# gives: a sender that failed, or reported anything else, sent nothing that
# can count.
plant_ok() { # <exit status> <report> <kind>
	[[ "$1" == 0 && -n "$2" && "$2" == "$(plant_expected "$3")" ]]
}
tunnel_up() {
	ip netns exec "${NS_C}" ping -c 15 -i 0.2 -W 2 -q "${TUN_S}" >/dev/null
}
# One scenario: plant, then start the client and ping inside a capture of the
# server's datagrams. Returns 0 only if every step succeeded; its capture is
# removed first and written anew.
run_scenario() { # <name> <hint|probe|none> <hp 0|1>
	local NAME="$1" CAPTURE="${WORK}/$1.capture" SENT RC FAILED_BEFORE="${FAILED}"
	local -a LAYOUT=()
	rm -f -- "${CAPTURE}" "${CAPTURE}".*
	echo "--- ${NAME}: S1-S4 ${S_SIZES}, H4 ${H_RANGES##*,}, planted: $2$( (($3)) && echo ', header protection')"
	if ! setup "$3"; then
		bad "${NAME}: the server could not be set up"
		return 1
	fi
	(($3)) || LAYOUT=("${S_SIZES},${H_RANGES}" "${CLIENT_PUB}")
	if ! bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" "${CAPTURE_SECONDS}" "${CAPTURE}" "${LAYOUT[@]}"; then
		bad "${NAME}: the capture started"
		return 1
	fi
	SENT="$(plant "$2" 2>&1)"
	RC=$?
	if ! plant_ok "${RC}" "${SENT}" "$2"; then
		bad "${NAME}: the planted datagram was sent from ${ADDR_C}:${CLIENT_PORT} (exit ${RC}, '${SENT}'; wanted exit 0 and '$(plant_expected "$2")')"
		return 1
	fi
	ok "${NAME}: the planted datagram was sent from ${ADDR_C}:${CLIENT_PORT} before the client started (${SENT})"
	if ! start_peer "${NS_C}" "${IF_C}" "${WORK}/client.log" "${WORK}/client.conf" "${TUN_C}" "${TUN_S}" none error; then
		bad "${NAME}: the client could not be set up"
		return 1
	fi
	check "${NAME}: the client reaches the server through the tunnel (15 pings)" tunnel_up
	check "${NAME}: the capture outlived the traffic, ran its whole ${CAPTURE_SECONDS} s and completed with all its records" \
		bt_wire_capture_finish "${CAPTURE}" complete "$((CAPTURE_SECONDS + 10))"
	((FAILED == FAILED_BEFORE))
}
# Run a scenario and, only if it ran to the end, its JUDGE <name>: no
# earlier scenario's capture or server log can stand in for its evidence.
scenario() { # <name> <hint|probe|none> <hp 0|1> <judge>
	if ! run_scenario "$1" "$2" "$3"; then
		bad "$1: the scenario did not run to the end, so none of its evidence is judged"
		return 1
	fi
	"$4" "$1"
}
refusals() {
	sed 's/\x1b\[[0-9;]*m//g' "${WORK}/server.log" | grep -cF "${REFUSAL}"
}
judge_collision() {
	bt_wire_kinds "${WORK}/$1.capture" "${S_SIZES}" ||
		bad "$1: the capture has a complete, valid per-kind result (${BT_WIRE_REASON})"
	check "$1: responses were recorded (${BT_WIRE_SEEN[response]:-0}), none with a SIP request line (${BT_WIRE_SHAPED[response]:-?})" \
		test "${BT_WIRE_SEEN[response]:-0}" -ge 1 -a "${BT_WIRE_SHAPED[response]:-1}" -eq 0
	check "$1: transports were recorded (${BT_WIRE_SEEN[transport]:-0}), none with a SIP request line (${BT_WIRE_SHAPED[transport]:-?}): the probe was taken for AmneziaWG, never for a hint" \
		test "${BT_WIRE_SEEN[transport]:-0}" -ge 10 -a "${BT_WIRE_SHAPED[transport]:-1}" -eq 0
}
judge_hint() {
	bt_wire_assert_sip "$1" "${WORK}/$1.capture" "${S_SIZES}" init:optional response:required:shaped cookie:optional transport:required:shaped
}
judge_unshaped() { # <name>: no dns, stun or sip shape
	local COUNTS
	COUNTS="$(python3 "${WIRE}" classify-auto none "${WORK}/$1.capture" 2>&1)"
	check "$1: the server sent datagrams, none with a dns, stun or sip shape (${COUNTS})" \
		bash -c '[[ "$1" =~ ^([0-9]+)\ 0\ 0\ ([0-9]+)$ ]] && ((BASH_REMATCH[1] >= 10))' _ "${COUNTS}"
}
judge_hp_hint() {
	check "AWG 3.0, hint: BoringTun warns that the header-protection policy refused the learned sip" \
		bash -c 'sed "s/\x1b\[[0-9;]*m//g" "$1" | grep -F "$2" | grep -q "\"sip\""' _ "${WORK}/server.log" "${REFUSAL}"
	judge_unshaped "$1"
}
judge_hp_none() {
	check "AWG 3.0, no hint: no refusal warning ($(refusals))" test "$(refusals)" -eq 0
	judge_unshaped "$1"
}

echo "=== Auto hints on $("${BIN}" --version 2>/dev/null) ($(sha256sum "${BIN}" | cut -d' ' -f1))"
LAYOUT_TEXT="${S_SIZES},${H_RANGES}"
check "the 247-byte SIP probe is an AmneziaWG transport candidate under this layout" \
	test "$(python3 "${WIRE}" candidates probe sip "${LAYOUT_TEXT}")" = "247 transport"
check "the 27-byte SIP hint fits no AmneziaWG packet kind under it" \
	test "$(python3 "${WIRE}" candidates send sip "${LAYOUT_TEXT}")" = "27 none"

scenario collision probe 0 judge_collision
scenario hint hint 0 judge_hint
scenario hp-hint hint 1 judge_hp_hint
scenario hp-none none 1 judge_hp_none

echo
echo "BoringTun auto hint test: ${PASSED} passed, ${FAILED} failed"
((FAILED == 0))
