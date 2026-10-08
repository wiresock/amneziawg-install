#!/bin/bash
# Live test of what an imitation auto server learns, on the given
# boringtun-cli (the verified binary of the release under test), with layouts
# fixed so that the outcome is known. A server with --imitate-protocol auto
# (at --verbosity info, so that its warnings are visible) and one client
# (listen port 41006) run in fresh network namespaces. Before the client
# starts, a scenario may send datagrams to the server from the client's
# address and port; the client's side then records the server's datagrams
# while the client pings through the tunnel.
#
# What the server must have selected is never read from what it sent. The
# server's side records everything that reaches it from the client's address
# (the helper's record, ready before the server starts), and the helper's
# auto-expect derives the selection from that record and the client side's
# evidence of acceptance (the client's start and its first ping) by the
# pinned BoringTun's own rules, over every history that evidence allows:
# which datagrams fit an AmneziaWG packet kind (never a hint), which protocol
# each other one is detected as, the 30 s hints of the listener and of a
# connected socket, which initiations were accepted and the
# header-protection policy. The server's datagrams to the client are then
# held to that expectation. Each scenario whose layout and traffic were
# chosen to give a known outcome also checks that the record gives it.
#
#   collision (S 27,113,125,37, H4 1767000000-1866999999): the 247-byte SIP
#     probe of tests/helpers/boringtun-imitation-wire.py, which the live test
#     once planted, is an AmneziaWG transport candidate here (its four bytes
#     at 37 fall in H4), so it is never a hint: random.
#   hint: the 27-byte request line `send sip` plants, shorter than any
#     AmneziaWG datagram, is learned: sip.
#   hp-hint, hp-none: with header protection that hint draws BoringTun's
#     warning that the policy refused sip (an S is 31 bytes or more) and the
#     peer stays random; without a hint there is no warning, so the warning
#     is the hint's.
#   stun-replay-colliding, stun-replay-clear (S 110,57,133,36, the review's
#     H1-H3): the five datagrams a real STUN client sent before its
#     initiation, recorded whole, are sent again unchanged, then a client
#     without imitation connects. Under H4 1917290954-2017290953 both STUN
#     requests are transport candidates (bytes 36-39 of each fall in H4) and
#     the junk is detected as nothing: random. With only H4 changed to
#     2030000000-2129999999 the first request is a hint: stun.
#   genuine-dns, -quic, -sip, -stun (S 40, H ranges 100 wide): real clients of
#     each imitation, under a layout their datagrams practically never fit;
#     each must be learned, and the record must show eligible evidence.
#   reviewed-stun-1..3 (S 110,57,133,25, H4 1740000000-1839999999, the
#     review's case): real STUN clients, whose STUN requests are transport
#     candidates there in some runs and not in others. No outcome is
#     assumed: the record decides each run, and the server must match it.
# Cross-controls then hold captures to the expectation of the opposite
# scenario (collision against hint, colliding against clear STUN replay):
# a server that learned without eligible evidence, or did not learn with it,
# fails.
#
# A scenario's evidence is judged only if every step of it succeeded: the
# setup, the server-side record, the client-side capture, the planted
# traffic (its sender's exit status and its exact report), the tunnel, and a
# decision from the record. Its files are removed before it starts, so
# nothing of an earlier scenario can stand in for its own.
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
STUN_PRELUDE="${SCRIPT_DIR}/fixtures/boringtun-auto-preludes/stun.hex"
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
NARROW_H123="100000001-100000100,200000001-200000100,300000001-300000100"
REVIEW_H123="66166068-166166067,862271148-962271147,1349667297-1449667296"
LAYOUT_SIP="27,113,125,37|${NARROW_H123},1767000000-1866999999"
LAYOUT_STUN_COLLIDING="110,57,133,36|${REVIEW_H123},1917290954-2017290953"
LAYOUT_STUN_CLEAR="110,57,133,36|${REVIEW_H123},2030000000-2129999999"
LAYOUT_POSITIVE="40,40,40,40|${NARROW_H123},400000001-400000100"
LAYOUT_REVIEWED="110,57,133,25|${REVIEW_H123},1740000000-1839999999"
S_SIZES=""
H_RANGES=""
CAPTURE_SECONDS=12
REFUSAL='auto imitation refused by header-protection policy; retaining random prefixes'
WORK=""
PEERS=()
CREATED_NETNS=()
EXPECT=""
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
[[ -s "${STUN_PRELUDE}" ]] || die "${STUN_PRELUDE} is required"

# Stop this run's peers and captures (owned children), then remove the
# namespaces it made and the UAPI nodes of its own interface names.
teardown() {
	local HANDLE NETNS IF
	for HANDLE in "${PEERS[@]}"; do
		bt_wire_signal "${HANDLE}" TERM
		bt_wire_await "${HANDLE}" 5 || bt_wire_signal "${HANDLE}" KILL
		bt_wire_collect "${HANDLE}" >/dev/null 2>&1
	done
	PEERS=()
	bt_wire_cleanup
	# shellcheck disable=SC2034 # the sourced boringtun-wire-checks.sh's capture state
	BT_WIRE_CAPTURE=""
	# shellcheck disable=SC2034 # the sourced boringtun-wire-checks.sh's capture state
	BT_WIRE_PARKED=()
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
# For auto-expect, which unmasks with it; never printed.
(umask 077 && printf '%s\n' "${HP_KEY}" >"${WORK}/hp.key")

use_layout() { # <S1,S2,S3,S4|H1,H2,H3,H4>
	S_SIZES="${1%%|*}"
	H_RANGES="${1#*|}"
}
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
# Fresh namespaces and both peers' configs; nothing runs yet.
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
}
# Start the server and set EPOCH to its process's start (centiseconds of
# CLOCK_BOOTTIME, from the start time its owned handle recorded, rounded
# down): its state, hints included, is empty then.
start_server() {
	local START
	start_peer "${NS_S}" "${IF_S}" "${WORK}/server.log" "${WORK}/server.conf" "${TUN_S}" "${TUN_C}" auto info || return 1
	read -r _ START _ <<<"${PEERS[-1]}"
	EPOCH="$((START * 100 / $(getconf CLK_TCK)))"
}
# The datagrams a scenario plants from the client's port, by name: the
# helper's 27-byte SIP hint, the 247-byte SIP probe, the recorded STUN
# client's pre-initiation datagrams in order, or nothing. Each sender reports
# exactly what it sent (plant_expected) and exits 0 only if it sent it.
plant() { # <hint|probe|stun-sequence|none>
	case "$1" in
		hint)
			ip netns exec "${NS_C}" python3 "${WIRE}" send sip "${ADDR_S}" "${PORT}" "${CLIENT_PORT}"
			;;
		probe | stun-sequence)
			ip netns exec "${NS_C}" python3 - "${WIRE}" "${ADDR_S}" "${PORT}" "${CLIENT_PORT}" "$1" "${STUN_PRELUDE}" <<'PY'
import importlib.util, socket, sys, time
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
if sys.argv[5] == "probe":
    datagrams = [wire.sip_probe()[0]]
else:
    datagrams = [bytes.fromhex(line) for line in open(sys.argv[6]).read().split()]
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("0.0.0.0", int(sys.argv[4])))
    for datagram in datagrams:
        if sock.sendto(datagram, (sys.argv[2], int(sys.argv[3]))) != len(datagram):
            sys.exit("short send")
        time.sleep(0.015)
if sys.argv[5] == "probe":
    print("sent %d" % len(datagrams[0]))
else:
    print("sent %d: %s" % (len(datagrams), " ".join(str(len(d)) for d in datagrams)))
PY
			;;
		forgery)
			# A real STUN client's first request, then an initiation whose mac1
			# is consistent with the server's public key but which is no Noise
			# handshake, and a transport candidate with counter 1: what anyone
			# who knows the public key can send.
			ip netns exec "${NS_C}" python3 - "${WIRE}" "${ADDR_S}" "${PORT}" "${CLIENT_PORT}" "${STUN_PRELUDE}" \
				"${S_SIZES},${H_RANGES}" "${SERVER_PUB}" <<'PY'
import base64, hashlib, importlib.util, os, socket, struct, sys, time
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
sizes, ranges = wire.parse_layout(sys.argv[6])
key = hashlib.blake2s(b"mac1----" + base64.b64decode(sys.argv[7])).digest()
body = struct.pack("<II", ranges[0][0], 0x0BADF00D) + os.urandom(108)
initiation = os.urandom(sizes[0]) + body + hashlib.blake2s(body, digest_size=16, key=key).digest() + bytes(16)
transport = os.urandom(sizes[3]) + struct.pack("<IIQ", ranges[3][0], 0x0BADF00D, 1) + os.urandom(16)
datagrams = [bytes.fromhex(open(sys.argv[5]).read().split()[0]), initiation, transport]
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("0.0.0.0", int(sys.argv[4])))
    for datagram in datagrams:
        if sock.sendto(datagram, (sys.argv[2], int(sys.argv[3]))) != len(datagram):
            sys.exit("short send")
        time.sleep(0.015)
print("sent %d: %s" % (len(datagrams), " ".join(str(len(d)) for d in datagrams)))
PY
			;;
		none) echo "sent nothing" ;;
		*) return 2 ;;
	esac
}
plant_expected() { # <hint|probe|stun-sequence|none>
	case "$1" in
		hint) echo "sent 27" ;;
		probe) echo "sent 247" ;;
		stun-sequence) printf 'sent %s: %s\n' "$(grep -c . "${STUN_PRELUDE}")" "$(awk '{ printf "%s%d", (NR == 1 ? "" : " "), length($0) / 2 }' "${STUN_PRELUDE}")" ;;
		forgery) printf 'sent 3: %d %d %d\n' "$(($(head -n 1 "${STUN_PRELUDE}" | tr -d '\n' | wc -c) / 2))" \
			"$((${S_SIZES%%,*} + 148))" "$((${S_SIZES##*,} + 32))" ;;
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
tunnel_ping() {
	ip netns exec "${NS_C}" ping -c 1 -W 1 -q "${TUN_S}" >/dev/null
}
# The client-side capture's form: per packet kind where a learned sip is
# possible and the tags can be read (no header protection), else prefixes.
capture_format() { # <plant> <hp> <client imitation>
	if (($2 == 0)) && [[ "$1" =~ ^(hint|probe)$ || "$3" == sip ]]; then echo kinds; else echo prefixes; fi
}
# One scenario: the server, its record of what reaches it, the client-side
# capture, the planted traffic, the client, then the decision from the
# record (EXPECT). Returns 0 only if every step succeeded; its files are
# removed first and written anew.
run_scenario() { # <name> <hint|probe|stun-sequence|none> <hp 0|1> [client imitation]
	local NAME="$1" PLANT="$2" HP="$3" IMITATION="${4:-none}" CAPTURE="${WORK}/$1.capture" RECORD="${WORK}/$1.record"
	local SENT RC FAILED_BEFORE="${FAILED}" EPOCH START END BORN UP ORACLE FORMAT HP_FILE=-
	local -a LAYOUT=()
	EXPECT=""
	rm -f -- "${CAPTURE}" "${CAPTURE}".* "${RECORD}" "${RECORD}".* "${WORK}/${NAME}".{expect,format,sizes}
	FORMAT="$(capture_format "${PLANT}" "${HP}" "${IMITATION}")"
	echo "--- ${NAME}: S1-S4 ${S_SIZES}, H4 ${H_RANGES##*,}, client ${IMITATION}, planted: ${PLANT}$( ((HP)) && echo ', header protection')"
	if ! setup "${HP}"; then
		bad "${NAME}: the namespaces could not be set up"
		return 1
	fi
	# The record is ready before the server exists, so it holds everything
	# that reaches the server from the client's address.
	if ! BT_WIRE_CAPTURE_RECORD=1 BT_WIRE_CAPTURE_TO_PORT="${PORT}" bt_wire_capture_start "${NS_S}" "${VETH_S}" "${ADDR_C}" any 600 "${RECORD}"; then
		bad "${NAME}: the server-side record of what reaches the server started"
		return 1
	fi
	if ! bt_wire_capture_park record; then
		bad "${NAME}: the server-side record runs alongside the client-side capture"
		return 1
	fi
	EPOCH=""
	# A clock tick apart, so that the server's start cannot fall in the
	# centisecond the record became ready in.
	sleep 0.05
	if ! start_server || [[ ! "${EPOCH}" =~ ^[0-9]+$ ]]; then
		bad "${NAME}: the server could not be set up"
		return 1
	fi
	[[ "${FORMAT}" != kinds ]] || LAYOUT=("${S_SIZES},${H_RANGES}" "${CLIENT_PUB}")
	if ! bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" "${CAPTURE_SECONDS}" "${CAPTURE}" "${LAYOUT[@]}"; then
		bad "${NAME}: the client-side capture started"
		return 1
	fi
	START="${BT_WIRE_CAPTURE_READY_CLOCK}"
	SENT="$(plant "${PLANT}" 2>&1)"
	RC=$?
	if ! plant_ok "${RC}" "${SENT}" "${PLANT}"; then
		bad "${NAME}: the planted datagrams were sent from ${ADDR_C}:${CLIENT_PORT} (exit ${RC}, '${SENT}'; wanted exit 0 and '$(plant_expected "${PLANT}")')"
		return 1
	fi
	ok "${NAME}: the planted datagrams were sent from ${ADDR_C}:${CLIENT_PORT} before the client started (${SENT})"
	# The client side's evidence that the server accepted one of this
	# client's initiations: the client process started at BORN and pinged
	# through the tunnel at UP.
	bt_wire_now
	BORN="${BT_WIRE_NOW}"
	if ! start_peer "${NS_C}" "${IF_C}" "${WORK}/client.log" "${WORK}/client.conf" "${TUN_C}" "${TUN_S}" "${IMITATION}" error; then
		bad "${NAME}: the client could not be set up"
		return 1
	fi
	if ! wait_for 20 tunnel_ping; then
		bad "${NAME}: the client's first ping through the tunnel succeeded"
		return 1
	fi
	bt_wire_now
	UP="${BT_WIRE_NOW}"
	check "${NAME}: the client reaches the server through the tunnel (a first ping after $(((UP - BORN) * 10)) ms, then 15)" tunnel_up
	check "${NAME}: the client-side capture outlived the traffic, ran its whole ${CAPTURE_SECONDS} s and completed with all its records" \
		bt_wire_capture_finish "${CAPTURE}" complete "$((CAPTURE_SECONDS + 10))"
	bt_wire_now
	END="${BT_WIRE_NOW}"
	if bt_wire_capture_resume record && bt_wire_capture_finish "${RECORD}" stop 10; then
		ok "${NAME}: the server-side record ran from before the planted traffic until its authorized stop ($(wc -l <"${RECORD}") datagrams)"
	else
		bad "${NAME}: the server-side record ran from before the planted traffic until its authorized stop"
		return 1
	fi
	((HP == 0)) || HP_FILE="${WORK}/hp.key"
	ORACLE="$(python3 "${WIRE}" auto-expect "${RECORD}" "${ADDR_C}" "${CLIENT_PORT}" "${S_SIZES},${H_RANGES}" "${SERVER_PUB}" \
		"${HP_FILE}" off "${EPOCH}" "${START}" "${END}" "${BORN}:${UP}" - 2>&1)"
	sed 's/^/    record | /' <<<"${ORACLE}"
	if [[ "${ORACLE##*$'\n'}" =~ ^expect\ (dns|quic|sip|stun|random)$ ]]; then
		EXPECT="${BASH_REMATCH[1]}"
		ok "${NAME}: what reached the server decides what it selected for the client: ${EXPECT}"
	else
		bad "${NAME}: what reached the server decides what it selected for the client (${ORACLE##*$'\n'})"
		return 1
	fi
	((FAILED == FAILED_BEFORE)) || return 1
	printf '%s\n' "${EXPECT}" >"${WORK}/${NAME}.expect"
	printf '%s\n' "${FORMAT}" >"${WORK}/${NAME}.format"
	printf '%s\n' "${S_SIZES}" >"${WORK}/${NAME}.sizes"
}
# Hold a scenario's capture to its expectation.
judge() { # <name>
	local EXPECT_OF FORMAT
	EXPECT_OF="$(cat "${WORK}/$1.expect")"
	FORMAT="$(cat "${WORK}/$1.format")"
	if [[ "${EXPECT_OF}" == sip && "${FORMAT}" == kinds ]]; then
		bt_wire_assert_sip "$1" "${WORK}/$1.capture" "$(cat "${WORK}/$1.sizes")" \
			init:optional response:required cookie:optional transport:required
		return
	fi
	if bt_wire_auto_verdict "${EXPECT_OF}" "${WORK}/$1.capture" "${FORMAT}" "$(cat "${WORK}/$1.sizes")"; then
		ok "$1: the server's datagrams to the client are ${EXPECT_OF}, as the record decided (${BT_WIRE_REASON})"
	else
		bad "$1: the server's datagrams to the client are ${EXPECT_OF}, as the record decided (${BT_WIRE_REASON})"
	fi
}
# Run a scenario and, only if it ran to the end, judge it; with KNOWN, the
# record must also give that outcome.
scenario() { # <name> <plant> <hp 0|1> <client imitation> <known outcome|->
	if ! run_scenario "$1" "$2" "$3" "$4"; then
		bad "$1: the scenario did not run to the end, so none of its evidence is judged"
		return 1
	fi
	[[ "$5" == - ]] || check "$1: the record gives ${5}, the outcome this layout and traffic were chosen for (${EXPECT})" test "${EXPECT}" = "$5"
	judge "$1"
}
# Hold one scenario's capture to another's expectation, which it must fail.
cross_control() { # <scenario whose capture> <scenario whose expectation>
	local OTHER
	if [[ ! -s "${WORK}/$1.expect" || ! -s "${WORK}/$2.expect" ]]; then
		bad "cross-control $1 against $2: both scenarios ran to the end"
		return
	fi
	OTHER="$(cat "${WORK}/$2.expect")"
	if [[ "${OTHER}" == "$(cat "${WORK}/$1.expect")" ]]; then
		bad "cross-control $1 against $2: their records decide different outcomes (both ${OTHER})"
	elif bt_wire_auto_verdict "${OTHER}" "${WORK}/$1.capture" "$(cat "${WORK}/$1.format")" "$(cat "${WORK}/$1.sizes")"; then
		bad "cross-control: $1's capture passes as ${OTHER}, $2's outcome (${BT_WIRE_REASON})"
	else
		ok "cross-control: $1's capture fails as ${OTHER}, $2's outcome (${BT_WIRE_REASON})"
	fi
}
refusals() {
	sed 's/\x1b\[[0-9;]*m//g' "${WORK}/server.log" | grep -cF "${REFUSAL}"
}

echo "=== Auto hints on $("${BIN}" --version 2>/dev/null) ($(sha256sum "${BIN}" | cut -d' ' -f1))"
use_layout "${LAYOUT_SIP}"
check "the 247-byte SIP probe is an AmneziaWG transport candidate under S ${S_SIZES}, H4 ${H_RANGES##*,}" \
	test "$(python3 "${WIRE}" candidates probe sip "${S_SIZES},${H_RANGES}")" = "247 transport"
check "the 27-byte SIP hint fits no AmneziaWG packet kind under it" \
	test "$(python3 "${WIRE}" candidates send sip "${S_SIZES},${H_RANGES}")" = "27 none"

scenario collision probe 0 none random
scenario hint hint 0 none sip
if scenario hp-hint hint 1 none random; then
	check "hp-hint: BoringTun warns that the header-protection policy refused the learned sip" \
		bash -c 'sed "s/\x1b\[[0-9;]*m//g" "$1" | grep -F "$2" | grep -q "\"sip\""' _ "${WORK}/server.log" "${REFUSAL}"
fi
if scenario hp-none none 1 none random; then
	check "hp-none: no refusal warning ($(refusals))" test "$(refusals)" -eq 0
fi
cross_control collision hint
cross_control hint collision

use_layout "${LAYOUT_STUN_COLLIDING}"
scenario stun-replay-colliding stun-sequence 0 none random
use_layout "${LAYOUT_STUN_CLEAR}"
scenario stun-replay-clear stun-sequence 0 none stun
cross_control stun-replay-colliding stun-replay-clear
cross_control stun-replay-clear stun-replay-colliding

use_layout "${LAYOUT_POSITIVE}"
for PROTOCOL in dns quic sip stun; do
	scenario "genuine-${PROTOCOL}" none 0 "${PROTOCOL}" "${PROTOCOL}"
done

use_layout "${LAYOUT_REVIEWED}"
OUTCOMES=""
for RUN in 1 2 3; do
	scenario "reviewed-stun-${RUN}" none 0 stun - && OUTCOMES+=" ${EXPECT}"
done
echo "    (real STUN clients under the reviewed layout; the record decided:${OUTCOMES:- nothing})"

# ── Histories an earlier model got wrong, on the binary ─────────────────────
# Each was a counterexample to an earlier version of auto-expect (review of
# 3ad670b): it must now give the outcome the evidence establishes, or be
# undecided, never the wrong one. Layout: S 40, H ranges 100 wide.
#   policy-retry: AWG 3.0. A SIP hint, a client without imitation (the
#     policy refuses sip), then the same port's client restarted with DNS
#     imitation. Its queries reach the connected socket the first session
#     opened, whose tunnel takes them as its own hint: the binary learns dns.
#     With the socket seen in the server's socket table before the restart
#     and the same socket (its cookie) after the observed window, the record
#     decides dns; without that evidence it is undecided, since the queries
#     could have reached the listener, where the refused SIP hint holds the
#     slot.
#   forgery: a STUN request, a forged initiation and transport candidate,
#     32 s later a SIP hint and a client without imitation: undecided (which
#     initiations were accepted, and whether the STUN hint had expired, is
#     not in the evidence). The binary's output is shown.
#   early-gap: a STUN client's session, 32 s later a SIP hint and the same
#     port's client without imitation: the peer stays stun, which the full
#     record decides; with the first session replaced by a drop interval,
#     undecided.
#   paused-record: a SIP hint reaches the server while the record is paused;
#     32 s later, resumed, a client without imitation. The record stamps the
#     hint at its arrival, and the outcome is undecided (whether the server
#     processed it more than 30 s before the initiation is not in the
#     evidence). The binary's output is shown.
CX_NAME="" CX_HP=0 CX_RECORD="" CX_EPOCH="" CX_EST="" CX_START="" CX_END="" CX_CAPTURE=""
cx_begin() { # <name> <hp 0|1>
	CX_NAME="$1" CX_HP="$2" CX_RECORD="${WORK}/$1.record" CX_EST=""
	rm -f -- "${WORK}/$1".* "${WORK}/$1"-*
	echo "--- $1: S1-S4 ${S_SIZES}, H4 ${H_RANGES##*,}$( (($2)) && echo ', header protection')"
	if ! setup "$2"; then
		bad "$1: the namespaces could not be set up"
		return 1
	fi
	if ! BT_WIRE_CAPTURE_RECORD=1 BT_WIRE_CAPTURE_TO_PORT="${PORT}" bt_wire_capture_start "${NS_S}" "${VETH_S}" "${ADDR_C}" any 900 "${CX_RECORD}" ||
		! bt_wire_capture_park record; then
		bad "$1: the server-side record started before the server"
		return 1
	fi
	sleep 0.05
	EPOCH=""
	if ! start_server || [[ ! "${EPOCH}" =~ ^[0-9]+$ ]]; then
		bad "$1: the server could not be set up"
		return 1
	fi
	CX_EPOCH="${EPOCH}"
}
cx_plant() { # <plant>
	local SENT RC
	SENT="$(plant "$1" 2>&1)"
	RC=$?
	if ! plant_ok "${RC}" "${SENT}" "$1"; then
		bad "${CX_NAME}: the planted datagrams were sent (exit ${RC}, '${SENT}')"
		return 1
	fi
	ok "${CX_NAME}: the planted datagrams were sent from ${ADDR_C}:${CLIENT_PORT} (${SENT})"
}
# Start the client and wait for its first ping: an establishment.
cx_client() { # <imitation>
	local BORN
	bt_wire_now
	BORN="${BT_WIRE_NOW}"
	if ! start_peer "${NS_C}" "${IF_C}" "${WORK}/client.log" "${WORK}/client.conf" "${TUN_C}" "${TUN_S}" "$1" error ||
		! wait_for 20 tunnel_ping; then
		bad "${CX_NAME}: a client with imitation $1 reaches the server"
		return 1
	fi
	bt_wire_now
	CX_EST+="${CX_EST:+,}${BORN}:${BT_WIRE_NOW}"
	ok "${CX_NAME}: a client with imitation $1 reaches the server (started at ${BORN}, first ping at ${BT_WIRE_NOW})"
}
cx_client_stop() {
	local HANDLE="${PEERS[-1]}"
	bt_wire_signal "${HANDLE}" TERM
	bt_wire_await "${HANDLE}" 5 || bt_wire_signal "${HANDLE}" KILL
	bt_wire_collect "${HANDLE}" >/dev/null 2>&1
	unset 'PEERS[-1]'
	rm -f -- "/var/run/wireguard/${IF_C}.sock" "/var/run/amneziawg/${IF_C}.sock"
	wait_for 5 bash -c '! ip -n "$1" link show "$2" >/dev/null 2>&1' _ "${NS_C}" "${IF_C}"
}
# The observed window: the server's datagrams to the client over 15 pings.
cx_window() { # <prefixes|kinds>
	local -a LAYOUT=()
	CX_CAPTURE="${WORK}/${CX_NAME}.capture"
	[[ "$1" != kinds ]] || LAYOUT=("${S_SIZES},${H_RANGES}" "${CLIENT_PUB}")
	if ! bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" 6 "${CX_CAPTURE}" "${LAYOUT[@]}"; then
		bad "${CX_NAME}: the client-side capture started"
		return 1
	fi
	CX_START="${BT_WIRE_CAPTURE_READY_CLOCK}"
	check "${CX_NAME}: the client reaches the server through the tunnel (15 pings)" tunnel_up
	if ! bt_wire_capture_finish "${CX_CAPTURE}" complete 20; then
		bad "${CX_NAME}: the client-side capture completed"
		return 1
	fi
	bt_wire_now
	CX_END="${BT_WIRE_NOW}"
}
cx_end() {
	if bt_wire_capture_resume record && bt_wire_capture_finish "${CX_RECORD}" stop 10; then
		ok "${CX_NAME}: the server-side record ran until its authorized stop ($(wc -l <"${CX_RECORD}") lines)"
	else
		bad "${CX_NAME}: the server-side record ran until its authorized stop"
		return 1
	fi
}
cx_oracle() { # <record> <connected|->: prints the oracle's output
	local HP_FILE=-
	((CX_HP == 0)) || HP_FILE="${WORK}/hp.key"
	python3 "${WIRE}" auto-expect "$1" "${ADDR_C}" "${CLIENT_PORT}" "${S_SIZES},${H_RANGES}" "${SERVER_PUB}" "${HP_FILE}" off \
		"${CX_EPOCH}" "${CX_START}" "${CX_END}" "${CX_EST}" "$2" 2>&1
}
cx_expect() { # <label> <record> <connected|-> <expected protocol|undecided>
	local ORACLE
	ORACLE="$(cx_oracle "$2" "$3")"
	sed 's/^/    record | /' <<<"${ORACLE}"
	if [[ "$4" == undecided ]]; then
		check "${CX_NAME}: $1: the record does not decide, and says so (${ORACLE##*$'\n'})" \
			bash -c '[[ "$1" == "undecided "* ]]' _ "${ORACLE##*$'\n'}"
	else
		check "${CX_NAME}: $1: the record decides $4 (${ORACLE##*$'\n'})" test "${ORACLE##*$'\n'}" = "expect $4"
	fi
}
# The binary's output, against the outcomes in question, for the record.
cx_show() { # <format> <outcome...>
	local OUTCOME
	for OUTCOME in "${@:2}"; do
		if bt_wire_auto_verdict "${OUTCOME}" "${CX_CAPTURE}" "$1" "${S_SIZES}"; then
			echo "    (${CX_NAME}: the server's datagrams are ${OUTCOME}: ${BT_WIRE_REASON})"
		else
			echo "    (${CX_NAME}: the server's datagrams are not ${OUTCOME}: ${BT_WIRE_REASON})"
		fi
	done
}
# The server's socket connected to the client's endpoint: its cookie (unique
# for as long as the system runs), if the server process owns it.
connected_socket() {
	local PID
	read -r PID _ <<<"${PEERS[0]}"
	ip netns exec "${NS_S}" ss -Huanpe dst "${ADDR_C}:${CLIENT_PORT}" 2>/dev/null |
		awk -v owner="pid=${PID}," 'index($0, owner) { for (i = 1; i <= NF; i++) if ($i ~ /^sk:/) print substr($i, 4) }'
}
# Pause or resume the parked record (owned STOP/CONT).
record_signal() { # <STOP|CONT>
	local HANDLE PID START
	HANDLE="${BT_WIRE_PARKED[record]%%|*}"
	read -r PID START _ <<<"${HANDLE}"
	python3 "${WIRE}" owned "${PID}" "${START}" "$1" >/dev/null
}

use_layout "${LAYOUT_POSITIVE}"
policy_retry() {
	local BEFORE AFTER SEEN
	cx_begin policy-retry 1 && cx_plant hint && cx_client none || return
	check "policy-retry: BoringTun warns that the header-protection policy refused the learned sip" \
		bash -c 'sed "s/\x1b\[[0-9;]*m//g" "$1" | grep -F "$2" | grep -q "\"sip\""' _ "${WORK}/server.log" "${REFUSAL}"
	BEFORE="$(connected_socket)"
	bt_wire_now
	SEEN="${BT_WIRE_NOW}"
	check "policy-retry: after the first session the server has a socket connected to ${ADDR_C}:${CLIENT_PORT} (sk:${BEFORE:-none})" test -n "${BEFORE}"
	cx_client_stop
	cx_client dns && cx_window prefixes || return
	AFTER="$(connected_socket)"
	check "policy-retry: the same connected socket after the observed window (sk:${AFTER:-none}), so it existed throughout" \
		test -n "${AFTER}" -a "${AFTER}" = "${BEFORE}"
	cx_end || return
	cx_expect "with the connected socket seen at ${SEEN}" "${CX_RECORD}" "${SEEN}" dns
	if bt_wire_auto_verdict dns "${CX_CAPTURE}" prefixes; then
		ok "policy-retry: the server's datagrams to the restarted client are dns, as the record decided (${BT_WIRE_REASON})"
	else
		bad "policy-retry: the server's datagrams to the restarted client are dns, as the record decided (${BT_WIRE_REASON})"
	fi
	cx_expect "without the socket evidence" "${CX_RECORD}" - undecided
}
forgery() {
	cx_begin forgery 0 && cx_plant forgery || return
	echo "    (forgery: waiting 32 s, past the STUN hint's lifetime)"
	sleep 32
	cx_plant hint && cx_client none && cx_window kinds && cx_end || return
	cx_expect "a forged initiation and transport" "${CX_RECORD}" - undecided
	cx_show kinds sip random
}
early_gap() {
	local SPLIT GAP="${WORK}/early-gap-hidden.record" FIRST LAST COUNT
	cx_begin early-gap 0 && cx_client stun || return
	sleep 1
	cx_client_stop
	bt_wire_now
	SPLIT="${BT_WIRE_NOW}"
	echo "    (early-gap: waiting 32 s, past the STUN hint's lifetime)"
	sleep 32
	cx_plant hint && cx_client none && cx_window prefixes && cx_end || return
	cx_expect "the whole record" "${CX_RECORD}" - stun
	if bt_wire_auto_verdict stun "${CX_CAPTURE}" prefixes; then
		ok "early-gap: the server's datagrams to the reconnected client are stun, as the record decided (${BT_WIRE_REASON})"
	else
		bad "early-gap: the server's datagrams to the reconnected client are stun, as the record decided (${BT_WIRE_REASON})"
	fi
	# The same record with the first session's lines replaced by a drop
	# interval spanning them, as if the record had lost them.
	read -r FIRST LAST COUNT < <(awk -v cut="${SPLIT}" '$2 != "-" { a = $1; sub(/~.*/, "", a); if (a + 0 < cut) { n++; if (!f) f = a; l = a } } END { print f, l + 1, n }' "${CX_RECORD}")
	awk -v cut="${SPLIT}" -v first="${FIRST}" -v last="${LAST}" -v count="${COUNT}" '
		$2 != "-" { a = $1; sub(/~.*/, "", a); if (a + 0 < cut) { if (!done) { print last " - drops " count " " first; done = 1 } next } }
		{ print }' "${CX_RECORD}" >"${GAP}"
	sed "s/^\(stopped\|complete\) [0-9]*/\1 $(wc -l <"${GAP}")/" "${CX_RECORD}.state" >"${GAP}.state"
	echo "    (early-gap: ${COUNT} lines of the first session, ${FIRST} to ${LAST}, replaced by a drop interval)"
	cx_expect "the first session hidden by a drop interval" "${GAP}" - undecided
}
paused_record() {
	local PLANTED STAMP
	cx_begin paused-record 0 || return
	check "paused-record: the record is paused" record_signal STOP
	bt_wire_now
	PLANTED="${BT_WIRE_NOW}"
	cx_plant hint || return
	echo "    (paused-record: waiting 32 s while the record is paused)"
	sleep 32
	check "paused-record: the record resumes" record_signal CONT
	cx_client none && cx_window kinds && cx_end || return
	STAMP="$(awk -v hint="$(printf 'OPTIONS sip:a@b SIP/2.0\r\n\r\n' | od -An -tx1 | tr -d ' \n')" '$5 == hint { print $1; exit }' "${CX_RECORD}")"
	check "paused-record: the hint is stamped at its arrival (${STAMP:-none}), not when the resumed record read it (planted at ${PLANTED})" \
		bash -c '[[ "$1" =~ ^[0-9]+$ ]] && (($1 >= $2 && $1 <= $2 + 100))' _ "${STAMP}" "${PLANTED}"
	cx_expect "a hint 32 s older than the initiation" "${CX_RECORD}" - undecided
	cx_show kinds sip random
}
policy_retry
forgery
early_gap
paused_record

echo
echo "BoringTun auto hint test: ${PASSED} passed, ${FAILED} failed"
((FAILED == 0))
