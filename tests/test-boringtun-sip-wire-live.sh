#!/bin/bash
# Live, deterministic wire test of BoringTun's SIP protocol imitation, packet
# kind by packet kind. Two copies of the given boringtun-cli run in fresh
# network namespaces: a server with --imitate-protocol sip and a stock client,
# both configured with the same fixed S1-S4 and H1-H4. The client's side
# records the server's datagrams; each one's kind (handshake response, cookie
# reply, transport) is decided from its length and the AmneziaWG type tag after
# that kind's S prefix, never from the SIP text under test
# (tests/helpers/boringtun-imitation-wire.py).
#
# The pinned BoringTun writes a SIP request line into every S prefix of 31
# bytes or more (SIP_REQUEST_LINE_MIN) and leaves a shorter one random, for
# each packet kind on its own S: S2 for handshake responses, S3 for cookie
# replies, S4 for transport. A kind is "shaped" when every datagram of it
# carries a request line, "random" when none does; the check measures the
# three request-line signatures, not randomness.
#
# Cookie replies are produced on purpose: one genuine initiation from the
# client, replayed a few hundred times within a second, passes mac1 and takes
# the server past its handshake rate limit (100 per second), so each copy
# without a cookie MAC draws a cookie reply, as long as the reply is not
# larger than the initiation (S3 + 64 <= S1 + 148). A cookie reply counts as
# seen only when a datagram of that kind is on the wire, never because the
# traffic was heavy.
#
# The scenarios: the S sizes of the recorded follow-up C failure (S1=29 S2=26
# S3=81 S4=22) without and with cookie replies, every server S at 31, every
# server S at 30, and a mixed layout with an ordinary S4 of 45. Each capture
# and replay child must exit 0 with its completion marker
# (tests/helpers/boringtun-wire-checks.sh), and each capture must hold only
# classified datagrams. Controls on the real captures then show that an
# unknown, ambiguous or malformed record fails the check, and that removing
# the request lines of one kind, or giving a random kind request lines, fails
# that kind's verdict and only that one. The signature controls change records
# that are already classified: they prove the per-kind accounting, not that a
# capture is complete.
#
# Requirements: root, ip (iproute2) with network namespaces, /dev/net/tun,
# awg (amneziawg-tools), ping, python3, and AWG_DISPOSABLE_HOST_TEST=1. With
# AWG_LIVE_SECRET_SCAN set (tests/test-boringtun-host-live.sh does), the two
# private keys generated here are added to that output scan's secret list.
#
# Usage: AWG_DISPOSABLE_HOST_TEST=1 bash tests/test-boringtun-sip-wire-live.sh <boringtun-cli>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034 # read by the sourced boringtun-wire-checks.sh
WIRE="${SCRIPT_DIR}/helpers/boringtun-imitation-wire.py"
BIN="${1:-}"
# Names of this run only, so that a concurrent run or an existing namespace
# or link is never touched: what this run did not create, it does not remove.
RUN_ID="$(printf '%04x' $((RANDOM % 65536)))"
NS_S="awgsip-s-${RUN_ID}"
NS_C="awgsip-c-${RUN_ID}"
VETH_S="awgsv${RUN_ID}s"
VETH_C="awgsv${RUN_ID}c"
IF_S="awgss${RUN_ID}"
IF_C="awgsc${RUN_ID}"
ADDR_S="198.51.100.1"
ADDR_C="198.51.100.2"
TUN_S="10.77.0.1"
TUN_C="10.77.0.2"
PORT=51999
DOMAIN="pbx.example"
JUNK="Jc = 2
Jmin = 40
Jmax = 80"
H_RANGES="100000001-100000100,200000001-200000100,300000001-300000100,400000001-400000100"
REPLAYS=400
CAPTURE_SECONDS=14
WORK=""
SERVER_PID=""
CLIENT_PID=""
STARTED_PID=""
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

# Stop every child this run started (peers, capture, replay), each within a
# bounded time, then remove the namespaces it created (their veth and TUN
# links go with them) and the peers' UAPI sockets.
teardown() {
	local NETNS
	bt_wire_cleanup
	SERVER_PID=""
	CLIENT_PID=""
	for NETNS in "${CREATED_NETNS[@]}"; do
		ip netns delete "${NETNS}" 2>/dev/null
	done
	CREATED_NETNS=()
	rm -f "/var/run/wireguard/${IF_S}.sock" "/var/run/wireguard/${IF_C}.sock" \
		"/var/run/amneziawg/${IF_S}.sock" "/var/run/amneziawg/${IF_C}.sock"
}
cleanup() {
	local RC=$?
	trap - EXIT
	teardown
	[[ -n "${WORK}" ]] && rm -rf "${WORK}"
	exit "${RC}"
}
trap cleanup EXIT
WORK="$(mktemp -d /var/tmp/awg-sip-wire.XXXXXX)"
chmod 0700 "${WORK}"
SERVER_KEY="$(awg genkey)"
CLIENT_KEY="$(awg genkey)"
# Both private keys join the caller's output scan before anything else runs;
# they are never printed.
if [[ -n "${AWG_LIVE_SECRET_SCAN:-}" ]]; then
	printf '%s\n' "${SERVER_KEY}" "${CLIENT_KEY}" >>"${AWG_LIVE_SECRET_SCAN}" ||
		die "cannot add this run's private keys to ${AWG_LIVE_SECRET_SCAN}"
fi
SERVER_PUB="$(awg pubkey <<<"${SERVER_KEY}")"
CLIENT_PUB="$(awg pubkey <<<"${CLIENT_KEY}")"

# The [Interface] lines both peers share: the junk settings, S1-S4, H1-H4.
shared_lines() { # <S1> <S2> <S3> <S4>
	local H1 H2 H3 H4
	IFS=, read -r H1 H2 H3 H4 <<<"${H_RANGES}"
	printf '%s\nS1 = %s\nS2 = %s\nS3 = %s\nS4 = %s\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n' \
		"${JUNK}" "$1" "$2" "$3" "$4" "${H1}" "${H2}" "${H3}" "${H4}"
}
# Start one peer in its namespace, as a tracked child of this shell
# (STARTED_PID), and configure it through its UAPI socket.
start_peer() { # <namespace> <interface> <log> <config file> <tunnel address> <peer tunnel address> [imitation args...]
	local NETNS="$1" IF="$2" LOG="$3" CONF="$4" ADDR="$5" PEER_ADDR="$6"
	shift 6
	ip netns exec "${NETNS}" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "${BIN}" --foreground --disable-drop-privileges \
		--verbosity error "$@" "${IF}" >"${LOG}" 2>&1 </dev/null &
	STARTED_PID=$!
	bt_wire_track "${STARTED_PID}"
	if ! wait_for 10 test -S "/var/run/wireguard/${IF}.sock"; then
		sed 's/^/    | /' "${LOG}"
		return 1
	fi
	awg setconf "${IF}" "${CONF}" &&
		ip -n "${NETNS}" addr add "${ADDR}/32" dev "${IF}" &&
		ip -n "${NETNS}" link set "${IF}" up &&
		ip -n "${NETNS}" route add "${PEER_ADDR}/32" dev "${IF}"
}
# A namespace of this run: refused if the name is taken, recorded once made.
create_netns() { # <name>
	if ip netns list 2>/dev/null | grep -qE "^$1( |$)"; then
		echo "    namespace $1 already exists; it is not this run's and is left alone"
		return 1
	fi
	ip netns add "$1" || return 1
	CREATED_NETNS+=("$1")
}
# A fresh pair of peers with the given S sizes.
setup_pair() { # <S1> <S2> <S3> <S4>
	teardown
	if ip link show "${VETH_S}" >/dev/null 2>&1 || ip link show "${VETH_C}" >/dev/null 2>&1; then
		echo "    a link named ${VETH_S} or ${VETH_C} already exists; it is not this run's and is left alone"
		return 1
	fi
	create_netns "${NS_S}" && create_netns "${NS_C}" || return 1
	ip link add "${VETH_S}" netns "${NS_S}" type veth peer name "${VETH_C}" netns "${NS_C}" || return 1
	ip -n "${NS_S}" addr add "${ADDR_S}/24" dev "${VETH_S}" && ip -n "${NS_S}" link set "${VETH_S}" up &&
		ip -n "${NS_S}" link set lo up || return 1
	ip -n "${NS_C}" addr add "${ADDR_C}/24" dev "${VETH_C}" && ip -n "${NS_C}" link set "${VETH_C}" up &&
		ip -n "${NS_C}" link set lo up || return 1
	{
		printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' "${SERVER_KEY}" "${PORT}"
		shared_lines "$@"
		printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' "${CLIENT_PUB}" "${TUN_C}"
	} >"${WORK}/server.conf"
	{
		printf '[Interface]\nPrivateKey = %s\n' "${CLIENT_KEY}"
		shared_lines "$@"
		printf '\n[Peer]\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = %s/32\n' "${SERVER_PUB}" "${ADDR_S}" "${PORT}" "${TUN_S}"
	} >"${WORK}/client.conf"
	chmod 0600 "${WORK}/server.conf" "${WORK}/client.conf"
	start_peer "${NS_S}" "${IF_S}" "${WORK}/server.log" "${WORK}/server.conf" "${TUN_S}" "${TUN_C}" \
		--imitate-protocol sip --imitate-domain "${DOMAIN}"
	local RC=$?
	SERVER_PID="${STARTED_PID}"
	((RC == 0)) || return 1
	start_peer "${NS_C}" "${IF_C}" "${WORK}/client.log" "${WORK}/client.conf" "${TUN_C}" "${TUN_S}"
	RC=$?
	CLIENT_PID="${STARTED_PID}"
	return "${RC}"
}
# The server imitates SIP for the domain, the client imitates nothing.
peer_modes() {
	[[ "$(tr '\0' ' ' <"/proc/${SERVER_PID}/cmdline")" == *"--imitate-protocol sip --imitate-domain ${DOMAIN} "* &&
		"$(tr '\0' ' ' <"/proc/${CLIENT_PID}/cmdline")" != *imitate* ]]
}

declare -A SIZES_OF=()
# One scenario: fresh peers, the client's side recording the server's
# datagrams for CAPTURE_SECONDS while the client pings through the tunnel
# (handshake response and transport), and, with "cookies", a replayed
# initiation (cookie replies). The capture must run to its deadline and the
# replay must finish, both with status 0 and their completion markers.
run_scenario() { # <name> <S1> <S2> <S3> <S4> <cookies|no-cookies>
	local NAME="$1" S1="$2" S2="$3" S3="$4" S4="$5" COOKIES="$6" LAYOUT CAPTURE="${WORK}/$1.capture"
	LAYOUT="${S1},${S2},${S3},${S4},${H_RANGES}"
	SIZES_OF[${NAME}]="${S1},${S2},${S3},${S4}"
	echo "--- ${NAME}: S1=${S1} S2=${S2} S3=${S3} S4=${S4}, ${COOKIES}"
	if ! setup_pair "${S1}" "${S2}" "${S3}" "${S4}"; then
		bad "${NAME}: the peers could not be set up"
		return 1
	fi
	check "${NAME}: the server runs --imitate-protocol sip, the client no imitation" peer_modes
	if ! bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" "${CAPTURE_SECONDS}" "${CAPTURE}" "${LAYOUT}"; then
		bad "${NAME}: the capture started"
		return 1
	fi
	if [[ "${COOKIES}" == cookies ]]; then
		check "${NAME}: the replay listens for the client's initiation" \
			bt_wire_replay_start "${NS_C}" "${WORK}/${NAME}.replay" "${VETH_C}" "${ADDR_C}" "${ADDR_S}" "${PORT}" "${LAYOUT}" "${REPLAYS}" 10
	fi
	check "${NAME}: the client reaches the server through the tunnel" \
		ip netns exec "${NS_C}" ping -c 20 -i 0.2 -W 2 -q "${TUN_S}" >/dev/null
	if [[ "${COOKIES}" == cookies ]]; then
		check "${NAME}: one genuine initiation was replayed ${REPLAYS} times, and the replay exited 0" \
			bt_wire_replay_finish "${WORK}/${NAME}.replay" "${REPLAYS}" 15
	fi
	check "${NAME}: the capture ran its ${CAPTURE_SECONDS} s to completion and exited 0 with all its records" \
		bt_wire_capture_finish "${CAPTURE}" complete "$((CAPTURE_SECONDS + 10))"
}
# The per-kind check of a scenario's capture.
expect_scenario() { # <name> <kind:rule[:shaped|random]>...
	local NAME="$1"
	shift
	bt_wire_assert_sip "${NAME}" "${WORK}/${NAME}.capture" "${SIZES_OF[${NAME}]}" "$@"
}
# Whether the per-kind check of CAPTURE fails, run apart from this test's
# counters: for controls that must make it fail.
check_fails() { # <capture> <S1,S2,S3,S4> <kind:rule>...
	(
		PASSED=0 FAILED=0
		ok() { PASSED=$((PASSED + 1)); }
		bad() { FAILED=$((FAILED + 1)); }
		bt_wire_assert_sip control "$@" >/dev/null
		((FAILED > 0))
	)
}
check_passes() { # <capture> <S1,S2,S3,S4> <kind:rule>...
	! check_fails "$@"
}

echo "=== BoringTun SIP imitation on the wire, per packet kind"
echo "binary: ${BIN} ($(sha256sum "${BIN}" | cut -d' ' -f1))"
COOKIE_RULES=(init:absent response:required cookie:required transport:required)

# 1. The S sizes of the recorded failure, ordinary traffic only.
run_scenario recorded 29 26 81 22 no-cookies
expect_scenario recorded init:absent response:required:random cookie:absent transport:required:random
# The pooled check this replaces: any of S2-S4 at 31 or more demanded at least
# one SIP-shaped server datagram, whatever its kind.
if bt_wire_kinds "${WORK}/recorded.capture" "${SIZES_OF[recorded]}"; then
	POOLED_SHAPED="$(bt_wire_pooled_shaped)"
	check "recorded: the pooled check's expectation is false here: max(S2,S3,S4)=81 demands a request line, ${POOLED_SHAPED} datagrams carry one, and no cookie reply was sent" \
		test "${POOLED_SHAPED}" = 0 -a "${BT_WIRE_SEEN[cookie]}" = 0
else
	bad "recorded: the pooled check can be evaluated (${BT_WIRE_REASON})"
fi

# 2. The same sizes with cookie replies: S3=81 shapes them, the other kinds
# stay random.
run_scenario recorded-cookies 29 26 81 22 cookies
expect_scenario recorded-cookies init:absent response:required:random cookie:required:shaped transport:required:random

# 3. The boundary: every server S at exactly 31.
run_scenario at-31 64 31 31 31 cookies
expect_scenario at-31 init:absent response:required:shaped cookie:required:shaped transport:required:shaped

# 4. One byte below it: every server S at 30.
run_scenario at-30 64 30 30 30 cookies
expect_scenario at-30 init:absent response:required:random cookie:required:random transport:required:random

# 5. Mixed, with an ordinary S4: each kind follows its own S.
run_scenario mixed 64 30 31 45 cookies
expect_scenario mixed init:absent response:required:random cookie:required:shaped transport:required:shaped
teardown

echo "--- controls on the real captures"
# Evidence that is not a complete, classified capture fails the check: a
# record of no kind, of two kinds, from a malformed frame, a truncated or
# non-numeric record, or one in the legacy prefix format.
for CONTROL in "unknown 77 -" "ambiguous 95 -" "malformed 41 -" "transport 77" \
	"transport NOT_A_LENGTH 4f5054494f4e53207369703a75407820" "4f5054494f4e53207369703a75407820"; do
	{ cat "${WORK}/at-31.capture"; printf '%s\n' "${CONTROL}"; } >"${WORK}/control.capture"
	check "at-31 with the record '${CONTROL}' appended fails the per-kind check" \
		check_fails "${WORK}/control.capture" 64,31,31,31 "${COOKIE_RULES[@]}"
done
check "at-31 as recorded passes the same check (the controls' baseline)" \
	check_passes "${WORK}/at-31.capture" 64,31,31,31 "${COOKIE_RULES[@]}"
# Signature accounting after classification: rewrite the recorded prefixes of
# one kind; "strip" replaces them with zero bytes (a request line missing),
# "sip" with the start of one (a request line where none belongs). Only that
# kind's verdict may change.
tamper() { # <capture> <kind> <strip|sip> <output>
	awk -v kind="$2" -v how="$3" '
		$1 == kind && $3 != "-" {
			n = length($3)
			if (how == "strip") { s = ""; for (i = 0; i < n; i += 2) s = s "00"; $3 = s }
			else { $3 = substr("4f5054494f4e53207369703a" "000000000000000000000000000000000000", 1, n) }
		}
		{ print }' "$1" >"$4"
}
verdicts() { # <capture> <S1,S2,S3,S4>: "response=<v> cookie=<v> transport=<v>"
	bt_wire_kinds "$1" "$2" || { echo "invalid: ${BT_WIRE_REASON}"; return; }
	printf 'response=%s cookie=%s transport=%s' "${BT_WIRE_VERDICT[response]}" "${BT_WIRE_VERDICT[cookie]}" "${BT_WIRE_VERDICT[transport]}"
}
for KIND in response cookie transport; do
	tamper "${WORK}/at-31.capture" "${KIND}" strip "${WORK}/neg.capture"
	EXPECTED=""
	for OTHER in response cookie transport; do
		if [[ "${OTHER}" == "${KIND}" ]]; then EXPECTED+="${OTHER}=FAIL "; else EXPECTED+="${OTHER}=ok "; fi
	done
	EXPECTED="${EXPECTED% }"
	check "at-31 without request lines in ${KIND}s: only the ${KIND} verdict fails (${EXPECTED})" \
		test "$(verdicts "${WORK}/neg.capture" 64,31,31,31)" = "${EXPECTED}"
	tamper "${WORK}/at-30.capture" "${KIND}" sip "${WORK}/neg.capture"
	check "at-30 with request lines in ${KIND}s: only the ${KIND} verdict fails (${EXPECTED})" \
		test "$(verdicts "${WORK}/neg.capture" 64,30,30,30)" = "${EXPECTED}"
done
tamper "${WORK}/mixed.capture" transport strip "${WORK}/neg.capture"
check "mixed without request lines in transports: transport fails while the shaped cookies and random responses pass" \
	test "$(verdicts "${WORK}/neg.capture" 64,30,31,45)" = "response=ok cookie=ok transport=FAIL"
tamper "${WORK}/mixed.capture" cookie strip "${WORK}/neg.capture"
check "mixed without request lines in cookie replies: cookie fails while the shaped transports pass" \
	test "$(verdicts "${WORK}/neg.capture" 64,30,31,45)" = "response=ok cookie=FAIL transport=ok"

echo "BoringTun SIP wire test: ${PASSED} passed, ${FAILED} failed"
((FAILED == 0))
