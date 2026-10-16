#!/bin/bash
# Live check of what an imitation auto server of boringtun-cli e94c04f3f4fd
# learns in a few fixed, reproducible scenarios, and of the difference from
# b94943906b11 where it changed: a recognizable prelude that also fits an
# AmneziaWG packet kind. Each scenario is a fresh server (--verbosity info,
# so that its warnings are visible) and one controlled client (listen port
# 41006) in fresh network namespaces, with fixed S1-S4 and H1-H4. Before the
# client starts, a scenario may send datagrams to the server from the
# client's address and port; the client's side then records the server's
# datagrams while the client pings through the tunnel, and the server's side
# records whole everything that reaches the server from the client's address.
#
# Every outcome below is the one these binaries give in that scenario; none
# is derived from a model of either release's hint rules. Each scenario
# checks, from its server-side record and the helper's `detected`, the
# premise its outcome rests on (which protocols the client's datagrams are
# detected as, and whether those datagrams also fit an AmneziaWG kind), then
# holds the server's datagrams to the client to the outcome, with
# cross-controls that the capture fails as the other outcome:
#
#   sip-collision (S 27,113,125,37, H4 1767000000-1866999999): the 247-byte
#     SIP probe of tests/helpers/boringtun-imitation-wire.py, an AmneziaWG
#     transport candidate there, then a client without imitation.
#     e94c04f3f4fd: sip (its readings are refused, then it is a hint);
#     b94943906b11: random.
#   stun-collision (S 110,57,133,36, the review's H1-H3, H4
#     1917290954-2017290953): the five datagrams a real STUN client sent
#     before its initiation (tests/fixtures/boringtun-auto-preludes/stun.hex),
#     both STUN requests transport candidates there, then a client without
#     imitation. e94c04f3f4fd: stun; b94943906b11: random.
#   stun-clear (b94943906b11 only, H4 2030000000-2129999999): the same
#     datagrams, the first request fitting no kind: stun. It shows that the
#     earlier binary's random in stun-collision is the collision's.
#   genuine-dns, -quic, -sip, -stun (S 40, H ranges 100 wide): a real client
#     of each imitation, whose datagrams fit no kind there: that protocol.
#   no-hint (the same layout): a client without imitation and nothing
#     planted: random, and the record shows that nothing the client sent is
#     detected as any protocol, so the test traffic left no hint of its own.
#   hp-hint, hp-none (the same layout with header protection, every S 40):
#     the 27-byte SIP hint draws BoringTun's warning that the
#     header-protection policy refused sip, and the peer stays random;
#     without a hint there is no warning.
#   fixed-stun (the sip-collision layout and probe): a server with
#     --imitate-protocol stun, the fixed mode, stays stun.
#
# Fixed imitation modes are further exercised by
# tests/test-boringtun-host-live.sh (each mode on the installed daemon) and
# tests/test-boringtun-sip-wire-live.sh. These scenarios establish behaviour
# for these histories only, not for every history a server can have.
#
# A scenario's evidence is judged only if every step of it succeeded: the
# setup, the server-side record, the client-side capture, the planted
# traffic (its sender's exit status and its exact report), the tunnel and the
# record's completeness. A scenario that did not run to the end fails; it is
# never skipped or counted as passed.
#
# The binaries are named by their SHA-256 (RELEASE_OF below), never by their
# version, which both releases report as 0.7.1.
#
# Requirements: root, ip (iproute2) with network namespaces, /dev/net/tun, awg
# (amneziawg-tools), ping, python3 and AWG_DISPOSABLE_HOST_TEST=1. With
# AWG_LIVE_SECRET_SCAN set, the keys generated here join that output scan.
#
# Usage: AWG_DISPOSABLE_HOST_TEST=1 bash tests/test-boringtun-auto-collision-live.sh <e94c04f3f4fd boringtun-cli> [<b94943906b11 boringtun-cli>]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034 # read by the sourced boringtun-wire-checks.sh
WIRE="${SCRIPT_DIR}/helpers/boringtun-imitation-wire.py"
STUN_PRELUDE="${SCRIPT_DIR}/fixtures/boringtun-auto-preludes/stun.hex"
NEW_BIN="${1:-}"
OLD_BIN="${2:-}"
BIN=""
# The published binaries these expectations belong to, by SHA-256 (x86_64
# and aarch64 of each release).
declare -A RELEASE_OF=(
	[7c717357554a4d8022154fbdb1c40c92de8174ee064e81878fdf5f610651fb79]=e94c04f3f4fd
	[cc1cdf215bb3d75f8a7006f8d424d698e9574dadb3e08becd8ace17a3c44cb08]=e94c04f3f4fd
	[1210a3c6780948ea07f301c4fa022c0b4ab634da71db0053f65757c8683470d5]=b94943906b11
	[c6752410b3994007a9ace5f2d93c30c009b2d7478ebed27b01aacc6168a08629]=b94943906b11
)
RUN_ID="$(printf '%04x' $((RANDOM % 65536)))"
NS_S="awgac-s-${RUN_ID}"
NS_C="awgac-c-${RUN_ID}"
VETH_S="awgacv${RUN_ID}s"
VETH_C="awgacv${RUN_ID}c"
IF_S="awgacs${RUN_ID}"
IF_C="awgacc${RUN_ID}"
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
S_SIZES=""
H_RANGES=""
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
[[ -n "${NEW_BIN}" && -x "${NEW_BIN}" ]] || die "usage: $0 <e94c04f3f4fd boringtun-cli> [<b94943906b11 boringtun-cli>]"
[[ -z "${OLD_BIN}" || -x "${OLD_BIN}" ]] || die "${OLD_BIN} is not executable"
for TOOL in ip awg ping python3 sha256sum; do
	command -v "${TOOL}" >/dev/null 2>&1 || die "${TOOL} is required"
done
[[ -c /dev/net/tun ]] || die "/dev/net/tun is required"
[[ -s "${STUN_PRELUDE}" ]] || die "${STUN_PRELUDE} is required"
release_of() { # <binary>
	local SUM
	SUM="$(sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1)"
	echo "${RELEASE_OF[${SUM:-none}]:-unknown}"
}
[[ "$(release_of "${NEW_BIN}")" == e94c04f3f4fd ]] ||
	die "${NEW_BIN} is not a published e94c04f3f4fd boringtun-cli ($(sha256sum -- "${NEW_BIN}" | cut -d' ' -f1)); these expectations are that release's"
[[ -z "${OLD_BIN}" || "$(release_of "${OLD_BIN}")" == b94943906b11 ]] ||
	die "${OLD_BIN} is not a published b94943906b11 boringtun-cli ($(sha256sum -- "${OLD_BIN}" | cut -d' ' -f1)); the comparison needs that release"

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
WORK="$(mktemp -d /var/tmp/awg-auto-collision.XXXXXX)" || die "cannot create a work directory"
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
# For `detected`, which unmasks with it; never printed.
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
# Start one peer of BIN in its namespace as an owned child, configured
# through its UAPI socket once it appears.
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
		none) echo "sent nothing" ;;
		*) return 2 ;;
	esac
}
plant_expected() { # <hint|probe|stun-sequence|none>
	case "$1" in
		hint) echo "sent 27" ;;
		probe) echo "sent 247" ;;
		stun-sequence) printf 'sent %s: %s\n' "$(grep -c . "${STUN_PRELUDE}")" "$(awk '{ printf "%s%d", (NR == 1 ? "" : " "), length($0) / 2 }' "${STUN_PRELUDE}")" ;;
		none) echo "sent nothing" ;;
	esac
}
tunnel_up() {
	ip netns exec "${NS_C}" ping -c 15 -i 0.2 -W 2 -q "${TUN_S}" >/dev/null
}
tunnel_ping() {
	ip netns exec "${NS_C}" ping -c 1 -W 1 -q "${TUN_S}" >/dev/null
}
refusals() {
	sed 's/\x1b\[[0-9;]*m//g' "${WORK}/server.log" | grep -cF "${REFUSAL}"
}

# One scenario on BIN: the server-side record, the server, the client-side
# capture, the planted traffic, the client, then the record's premise
# (`detected`, whose last line must be PREMISE, a pattern). Returns 0 only if
# every step succeeded, and only then is the capture judged (scenario); its
# files are removed first and written anew.
run_scenario() { # <name> <plant> <hp 0|1> <client imitation> <server imitation> <expected> <premise pattern>
	local NAME="$1" PLANT="$2" HP="$3" IMITATION="$4" SERVER_IMITATION="$5" PREMISE="$7"
	local CAPTURE="${WORK}/$1.capture" RECORD="${WORK}/$1.record" SENT RC FAILED_BEFORE="${FAILED}" FORMAT=prefixes DETECTED HP_FILE=-
	local -a LAYOUT=()
	rm -f -- "${CAPTURE}" "${CAPTURE}".* "${RECORD}" "${RECORD}".* "${WORK}/${NAME}".{format,sizes}
	# Per packet kind where sip is possible and the tags can be read.
	if ((HP == 0)) && [[ "${PLANT}" =~ ^(hint|probe)$ || "${IMITATION}" == sip ]] && [[ "${SERVER_IMITATION}" == auto ]]; then
		FORMAT=kinds
		LAYOUT=("${S_SIZES},${H_RANGES}" "${CLIENT_PUB}")
	fi
	echo "--- ${NAME} on $(release_of "${BIN}"): S1-S4 ${S_SIZES}, H4 ${H_RANGES##*,}, server ${SERVER_IMITATION}, client ${IMITATION}, planted: ${PLANT}$( ((HP)) && echo ', header protection')"
	if ! setup "${HP}"; then
		bad "${NAME}: the namespaces could not be set up"
		return 1
	fi
	# The record is ready before the server exists, so it holds everything
	# that reaches the server from the client's address.
	if ! BT_WIRE_CAPTURE_RECORD=1 BT_WIRE_CAPTURE_TO_PORT="${PORT}" bt_wire_capture_start "${NS_S}" "${VETH_S}" "${ADDR_C}" any 600 "${RECORD}" ||
		! bt_wire_capture_park record; then
		bad "${NAME}: the server-side record started before the server"
		return 1
	fi
	sleep 0.05
	if ! start_peer "${NS_S}" "${IF_S}" "${WORK}/server.log" "${WORK}/server.conf" "${TUN_S}" "${TUN_C}" "${SERVER_IMITATION}" info; then
		bad "${NAME}: the server could not be set up"
		return 1
	fi
	if ! bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" "${CAPTURE_SECONDS}" "${CAPTURE}" "${LAYOUT[@]}"; then
		bad "${NAME}: the client-side capture started"
		return 1
	fi
	SENT="$(plant "${PLANT}" 2>&1)"
	RC=$?
	if [[ "${RC}" != 0 || "${SENT}" != "$(plant_expected "${PLANT}")" ]]; then
		bad "${NAME}: the planted datagrams were sent from ${ADDR_C}:${CLIENT_PORT} (exit ${RC}, '${SENT}'; wanted exit 0 and '$(plant_expected "${PLANT}")')"
		return 1
	fi
	ok "${NAME}: the planted datagrams were sent from ${ADDR_C}:${CLIENT_PORT} before the client started (${SENT})"
	if ! start_peer "${NS_C}" "${IF_C}" "${WORK}/client.log" "${WORK}/client.conf" "${TUN_C}" "${TUN_S}" "${IMITATION}" error; then
		bad "${NAME}: the client could not be set up"
		return 1
	fi
	if ! wait_for 20 tunnel_ping; then
		bad "${NAME}: the client's first ping through the tunnel succeeded"
		return 1
	fi
	check "${NAME}: the client reaches the server through the tunnel (15 pings)" tunnel_up
	check "${NAME}: the client-side capture outlived the traffic, ran its whole ${CAPTURE_SECONDS} s and completed with all its records" \
		bt_wire_capture_finish "${CAPTURE}" complete "$((CAPTURE_SECONDS + 10))"
	if bt_wire_capture_resume record && bt_wire_capture_finish "${RECORD}" stop 10; then
		ok "${NAME}: the server-side record ran from before the server until its authorized stop ($(wc -l <"${RECORD}") lines)"
	else
		bad "${NAME}: the server-side record ran from before the server until its authorized stop"
		return 1
	fi
	((HP == 0)) || HP_FILE="${WORK}/hp.key"
	DETECTED="$(python3 "${WIRE}" detected "${RECORD}" "${ADDR_C}" "${CLIENT_PORT}" "${S_SIZES},${H_RANGES}" "${HP_FILE}" off 2>&1)"
	sed 's/^/    record | /' <<<"${DETECTED}"
	if [[ "${DETECTED##*$'\n'}" =~ ^${PREMISE}$ ]]; then
		ok "${NAME}: what the client's address and port sent is the scenario's premise (${DETECTED##*$'\n'})"
	else
		bad "${NAME}: what the client's address and port sent is the scenario's premise '${PREMISE}' (${DETECTED##*$'\n'})"
		return 1
	fi
	((FAILED == FAILED_BEFORE)) || return 1
	printf '%s\n' "${FORMAT}" >"${WORK}/${NAME}.format"
	printf '%s\n' "${S_SIZES}" >"${WORK}/${NAME}.sizes"
}
# Hold a scenario's capture to OUTCOME; returns whether it passes, and sets
# BT_WIRE_REASON. A sip capture per kind is held by bt_wire_assert_sip.
holds() { # <name> <outcome>
	bt_wire_auto_verdict "$2" "${WORK}/$1.capture" "$(cat "${WORK}/$1.format")" "$(cat "${WORK}/$1.sizes")"
}
judge() { # <name> <outcome>
	local OTHER
	if [[ "$2" == sip && "$(cat "${WORK}/$1.format")" == kinds ]]; then
		bt_wire_assert_sip "$1" "${WORK}/$1.capture" "$(cat "${WORK}/$1.sizes")" init:optional response:required cookie:optional transport:required
	elif holds "$1" "$2"; then
		ok "$1: the server's datagrams to the client are $2 (${BT_WIRE_REASON})"
	else
		bad "$1: the server's datagrams to the client are $2 (${BT_WIRE_REASON})"
	fi
	# Cross-controls: the same capture must fail as the outcomes it is not.
	if [[ "$2" == random ]]; then
		for OTHER in dns quic stun sip; do
			[[ "${OTHER}" == sip && "$(cat "${WORK}/$1.format")" != kinds ]] && continue
			[[ "${OTHER}" != sip && "$(cat "${WORK}/$1.format")" == kinds ]] && continue
			if holds "$1" "${OTHER}"; then
				bad "cross-control: $1's capture also passes as ${OTHER} (${BT_WIRE_REASON})"
			else
				ok "cross-control: $1's capture fails as ${OTHER} (${BT_WIRE_REASON})"
			fi
		done
	elif [[ "$2" == quic ]]; then
		echo "    ($1: no random cross-control: QUIC's short header looks like random padding)"
	elif holds "$1" random; then
		bad "cross-control: $1's capture also passes as random (${BT_WIRE_REASON})"
	else
		ok "cross-control: $1's capture fails as random (${BT_WIRE_REASON})"
	fi
}
# Run a scenario and, only if it ran to the end, judge it.
scenario() { # <name> <plant> <hp 0|1> <client imitation> <server imitation> <expected> <premise pattern>
	if ! run_scenario "$@"; then
		bad "$1: the scenario did not run to the end, so none of its evidence is judged"
		return 1
	fi
	judge "$1" "$6"
}

echo "=== Auto collisions on $("${NEW_BIN}" --version 2>/dev/null) ($(sha256sum "${NEW_BIN}" | cut -d' ' -f1), e94c04f3f4fd)"
use_layout "${LAYOUT_SIP}"
check "the 247-byte SIP probe is an AmneziaWG transport candidate under S ${S_SIZES}, H4 ${H_RANGES##*,}" \
	test "$(python3 "${WIRE}" candidates probe sip "${S_SIZES},${H_RANGES}")" = "247 transport"
check "the 27-byte SIP hint fits no AmneziaWG packet kind under it" \
	test "$(python3 "${WIRE}" candidates send sip "${S_SIZES},${H_RANGES}")" = "27 none"

BIN="${NEW_BIN}"
use_layout "${LAYOUT_SIP}"
scenario sip-collision probe 0 none auto sip 'detected sip clear none'
scenario fixed-stun probe 0 none stun stun 'detected sip clear none'
use_layout "${LAYOUT_STUN_COLLIDING}"
scenario stun-collision stun-sequence 0 none auto stun 'detected stun clear none'
use_layout "${LAYOUT_POSITIVE}"
for PROTOCOL in dns quic sip stun; do
	scenario "genuine-${PROTOCOL}" none 0 "${PROTOCOL}" auto "${PROTOCOL}" "detected ([a-z]+,)*${PROTOCOL}(,[a-z]+)* clear ([a-z]+,)*${PROTOCOL}(,[a-z]+)*"
done
scenario no-hint none 0 none auto random 'detected none clear none'
if scenario hp-hint hint 1 none auto random 'detected sip clear sip'; then
	check "hp-hint: BoringTun warns that the header-protection policy refused the learned sip" \
		bash -c 'sed "s/\x1b\[[0-9;]*m//g" "$1" | grep -F "$2" | grep -q "\"sip\""' _ "${WORK}/server.log" "${REFUSAL}"
fi
if scenario hp-none none 1 none auto random 'detected none clear none'; then
	check "hp-none: no refusal warning ($(refusals))" test "$(refusals)" -eq 0
fi

if [[ -n "${OLD_BIN}" ]]; then
	echo "=== The same collisions on $("${OLD_BIN}" --version 2>/dev/null) ($(sha256sum "${OLD_BIN}" | cut -d' ' -f1), b94943906b11)"
	BIN="${OLD_BIN}"
	use_layout "${LAYOUT_SIP}"
	scenario sip-collision-b94943906b11 probe 0 none auto random 'detected sip clear none'
	use_layout "${LAYOUT_STUN_COLLIDING}"
	scenario stun-collision-b94943906b11 stun-sequence 0 none auto random 'detected stun clear none'
	use_layout "${LAYOUT_STUN_CLEAR}"
	scenario stun-clear-b94943906b11 stun-sequence 0 none auto stun 'detected stun clear stun'
	# The difference, on the same scenarios: each binary's capture fails as
	# the other's outcome.
	for PAIR in "sip-collision|sip-collision-b94943906b11|sip|random" "stun-collision|stun-collision-b94943906b11|stun|random"; do
		IFS='|' read -r NEW_CASE OLD_CASE NEW_OUTCOME OLD_OUTCOME <<<"${PAIR}"
		if [[ ! -s "${WORK}/${NEW_CASE}.format" || ! -s "${WORK}/${OLD_CASE}.format" ]]; then
			bad "difference ${NEW_CASE}: both binaries ran the scenario to the end"
			continue
		fi
		if holds "${NEW_CASE}" "${OLD_OUTCOME}"; then
			bad "difference ${NEW_CASE}: e94c04f3f4fd's capture also passes as ${OLD_OUTCOME}, b94943906b11's outcome (${BT_WIRE_REASON})"
		else
			ok "difference ${NEW_CASE}: e94c04f3f4fd's capture fails as ${OLD_OUTCOME}, b94943906b11's outcome (${BT_WIRE_REASON})"
		fi
		if holds "${OLD_CASE}" "${NEW_OUTCOME}"; then
			bad "difference ${NEW_CASE}: b94943906b11's capture also passes as ${NEW_OUTCOME}, e94c04f3f4fd's outcome (${BT_WIRE_REASON})"
		else
			ok "difference ${NEW_CASE}: b94943906b11's capture fails as ${NEW_OUTCOME}, e94c04f3f4fd's outcome (${BT_WIRE_REASON})"
		fi
	done
else
	echo "    (no b94943906b11 binary given: the comparison with the earlier release is not part of this run)"
fi

echo
echo "BoringTun auto collision test: ${PASSED} passed, ${FAILED} failed"
((FAILED == 0))
