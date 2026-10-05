#!/bin/bash
# Live, deterministic wire test of BoringTun's SIP protocol imitation, packet
# kind by packet kind. Two copies of the given boringtun-cli run in fresh
# network namespaces: a server with --imitate-protocol sip and a stock client,
# both configured with the same fixed S1-S4 and H1-H4. The client's side
# records the server's datagrams; each one's kind (handshake response, cookie
# reply, transport) is decided from its length and the AmneziaWG type tag after
# that kind's S prefix, never from the SIP text under test
# (tests/helpers/boringtun-imitation-wire.py). A datagram that fits more than
# one kind is decided by what the client can verify of each reading: a
# handshake message's mac1 under the client's public key, a transport's
# receiver index against the session an authenticated response opened.
# Nothing decides a cookie reading, so a transport that also fits the cookie
# rule outside a seen session stays ambiguous.
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
# server S at 30, a mixed layout with an ordinary S4 of 45, the S sizes of
# the recorded follow-up D failure (S1=99 S2=54 S3=92 S4=52) with H ranges
# that make every response fit the transport rule too, and a crossed layout
# whose ping replies also fit the response and cookie rules; that crossed
# layout with its handshake before the capture must stay ambiguous. Each capture
# must be ready before its traffic, outlive it, run its whole interval (by
# its own boot-time clock, from ready to complete) and complete, and each
# replay must finish; both must exit 0 with their exact transcripts
# (tests/helpers/boringtun-wire-checks.sh). Every recorded
# relevant datagram must then be classified and follow its kind's rule; that
# holds what the packet socket delivered, which is not proof that nothing
# escaped it. Controls on the real captures then show that an unknown,
# ambiguous, unresolved or malformed record fails the check, and that
# removing the request lines of one kind, or giving a random kind request
# lines, fails that kind's verdict and only that one. The signature controls
# change records that are already classified: they prove the per-kind
# accounting, not that a capture is complete. Further controls use real
# processes: a SIGTERM that reaches the real capture before its authorized
# stop fails the capture check; a SIGTERM while a namespace is being made
# ends the run only once that namespace is recorded; in a PID namespace of
# its own (unshare), a tracked child's PID, reaped by the shell and given to
# another process, leads the tracker neither to signal nor to wait for that
# process; a UAPI socket this run did not create, or one replaced since, is
# left alone; and one that a child of this run holds but this run had not
# yet recorded is removed with that child.
#
# Requirements: root, ip and ss (iproute2) with network namespaces,
# /dev/net/tun, awg (amneziawg-tools), ping, python3, unshare and nsenter
# (util-linux), and AWG_DISPOSABLE_HOST_TEST=1. With
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
PEER_HANDLE=""
CREATED_NETNS=()
# The UAPI sockets this run's peers created: path -> "device inode ctime".
declare -A OWNED_SOCKETS=()
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
for TOOL in ip ss awg ping python3 unshare nsenter; do
	command -v "${TOOL}" >/dev/null 2>&1 || die "${TOOL} is required"
done
[[ -c /dev/net/tun ]] || die "/dev/net/tun is required"

# The identity of a filesystem object: device, inode and ctime in ns.
socket_identity() { # <path>
	stat -c '%d %i %.9Z' -- "$1" 2>/dev/null
}
# The identity of the UNIX socket node at PATH when the live process
# PID/START holds it: one of the socket inodes among its fds is, by ss's
# socket diagnostics in its network namespace, bound to exactly this file
# (its inode and device), the proof the installer uses for its daemon's
# sockets. A node that another process bound, or one that changed during
# the check, is not that process's: nothing is printed.
socket_held_by() { # <path> <pid> <start time>
	local NODE="$1" PID="$2" START="$3" ID DEV INO MAJOR MINOR FD LINK HELD=" "
	[[ -S "${NODE}" && ! -L "${NODE}" ]] || return 1
	ID="$(socket_identity "${NODE}")" || return 1
	read -r DEV INO _ <<<"${ID}"
	MAJOR=$(((DEV >> 8) & 0xfff))
	MINOR=$(((DEV & 0xff) | ((DEV >> 12) & 0xfff00)))
	for FD in "/proc/${PID}/fd/"*; do
		LINK="$(readlink -- "${FD}" 2>/dev/null)" || continue
		[[ "${LINK}" =~ ^socket:\[([0-9]+)\]$ ]] && HELD+="${BASH_REMATCH[1]} "
	done
	[[ "${HELD}" != " " ]] || return 1
	nsenter --net="/proc/${PID}/ns/net" ss -xlHe 2>/dev/null | awk -v ino="${INO}" -v dev="${DEV}" \
		-v major="${MAJOR}" -v minor="${MINOR}" -v held="${HELD}" '
		{
			vino = ""; vmaj = ""; vmin = ""
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^ino:[0-9]+$/) vino = substr($i, 5)
				if ($i ~ /^dev:[0-9]+\/[0-9]+$/) { split(substr($i, 5), d, "/"); vmaj = d[1]; vmin = d[2] }
			}
			if (vino == ino && ((vmaj == 0 && vmin == dev) || (vmaj == major && vmin == minor)) && index(held, " " $6 " ")) found = 1
		}
		END { exit !found }' || return 1
	# Still that process, so the fds read were its own; still that node.
	python3 "${WIRE}" owned "${PID}" "${START}" check >/dev/null 2>&1 || return 1
	[[ "$(socket_identity "${NODE}")" == "${ID}" ]] || return 1
	printf '%s\n' "${ID}"
}
# BoringTun's AmneziaWG UAPI path is a symlink to its WireGuard socket: it
# counts as the peer's while it resolves to that very node. Prints the
# symlink's own identity.
symlink_to_node() { # <link> <node path> <node identity>
	local ID
	[[ -L "$1" ]] || return 1
	ID="$(socket_identity "$1")" || return 1
	[[ "$(readlink -f -- "$1" 2>/dev/null)" == "$(readlink -f -- "$2" 2>/dev/null)" ]] || return 1
	[[ "$(socket_identity "$2")" == "$3" && "$(socket_identity "$1")" == "${ID}" ]] || return 1
	printf '%s\n' "${ID}"
}
# Record as this run's the UAPI nodes of interface IF that the owned child
# HANDLE holds: its WireGuard socket, and the AmneziaWG symlink once that
# points at it. 1 if the child holds no socket at that path.
own_held_sockets() { # <handle> <interface>
	local PID START NODE="/var/run/wireguard/$2.sock" LINK="/var/run/amneziawg/$2.sock" ID
	read -r PID START _ <<<"$1"
	ID="$(socket_held_by "${NODE}" "${PID}" "${START}")" || return 1
	OWNED_SOCKETS[${NODE}]="${ID}"
	ID="$(symlink_to_node "${LINK}" "${NODE}" "${ID}")" && OWNED_SOCKETS[${LINK}]="${ID}"
	return 0
}
# Stop every child this run started (peers, capture, replay), then remove
# the namespaces it created (their veth and TUN links go with them) and the
# UAPI nodes its peers created -- each only while it is still that node.
# Each child is first frozen (SIGSTOP through its pidfd, every thread
# stopped) and the nodes it holds are recorded before it is killed: a frozen
# child creates nothing more, so a node that a peer made at its start, before
# this run recorded it, cannot be left behind. Nothing this run did not
# create is removed, also when it runs before anything was created.
teardown() {
	local NETNS SOCKET HANDLE IF
	for HANDLE in "${BT_WIRE_CHILDREN[@]}"; do
		bt_wire_signal "${HANDLE}" STOP
		for IF in "${IF_S}" "${IF_C}"; do
			own_held_sockets "${HANDLE}" "${IF}"
		done
		bt_wire_signal "${HANDLE}" KILL
	done
	bt_wire_cleanup
	SERVER_PID=""
	CLIENT_PID=""
	for NETNS in "${CREATED_NETNS[@]}"; do
		ip netns delete "${NETNS}" 2>/dev/null
	done
	CREATED_NETNS=()
	for SOCKET in "${!OWNED_SOCKETS[@]}"; do
		[[ "$(socket_identity "${SOCKET}")" == "${OWNED_SOCKETS[${SOCKET}]}" ]] && rm -f -- "${SOCKET}"
	done
	OWNED_SOCKETS=()
}
cleanup() {
	local RC=$?
	trap - EXIT
	teardown
	[[ -n "${WORK}" ]] && rm -rf "${WORK}"
	exit "${RC}"
}
trap cleanup EXIT
# An interrupted run still cleans up: its exit runs the EXIT trap. While
# something is being made and recorded (recording), the interruption waits
# until the record is written, so nothing made is ever left unrecorded.
INTERRUPTED=""
RECORDING=0
interrupted() { # <exit status>
	if ((RECORDING)); then
		INTERRUPTED="$1"
	else
		exit "$1"
	fi
}
recording() { # <command...>
	local RC
	RECORDING=1
	"$@"
	RC=$?
	RECORDING=0
	[[ -z "${INTERRUPTED}" ]] || exit "${INTERRUPTED}"
	return "${RC}"
}
trap 'interrupted 143' TERM
trap 'interrupted 130' INT
trap 'interrupted 129' HUP
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

# The [Interface] lines both peers share: the junk settings, S1-S4, H1-H4
# (H_RANGES unless given).
shared_lines() { # <S1> <S2> <S3> <S4> [<H1,H2,H3,H4>]
	local H1 H2 H3 H4
	IFS=, read -r H1 H2 H3 H4 <<<"${5:-${H_RANGES}}"
	printf '%s\nS1 = %s\nS2 = %s\nS3 = %s\nS4 = %s\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n' \
		"${JUNK}" "$1" "$2" "$3" "$4" "${H1}" "${H2}" "${H3}" "${H4}"
}
# Start one peer in its namespace as an owned child (PEER_HANDLE, its PID in
# STARTED_PID), record the UAPI socket it creates as this run's once it is
# proven to hold it, and configure it through that socket. A socket path
# that already exists is not this run's: the peer is not started and the
# path is left alone.
start_peer() { # <namespace> <interface> <log> <config file> <tunnel address> <peer tunnel address> [imitation args...]
	local NETNS="$1" IF="$2" LOG="$3" CONF="$4" ADDR="$5" PEER_ADDR="$6" SOCKET
	shift 6
	STARTED_PID=""
	for SOCKET in "/var/run/wireguard/${IF}.sock" "/var/run/amneziawg/${IF}.sock"; do
		if [[ -e "${SOCKET}" || -L "${SOCKET}" ]]; then
			echo "    ${SOCKET} already exists; it is not this run's and is left alone"
			return 1
		fi
	done
	bt_wire_spawn PEER_HANDLE "${LOG}" - ip netns exec "${NETNS}" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "${BIN}" \
		--foreground --disable-drop-privileges --verbosity error "$@" "${IF}" || return 1
	STARTED_PID="${PEER_HANDLE%% *}"
	if ! wait_for 10 own_held_sockets "${PEER_HANDLE}" "${IF}"; then
		sed 's/^/    | /' "${LOG}"
		echo "    no UAPI socket that peer ${STARTED_PID} holds appeared at /var/run/wireguard/${IF}.sock"
		return 1
	fi
	awg setconf "${IF}" "${CONF}" &&
		ip -n "${NETNS}" addr add "${ADDR}/32" dev "${IF}" &&
		ip -n "${NETNS}" link set "${IF}" up &&
		ip -n "${NETNS}" route add "${PEER_ADDR}/32" dev "${IF}"
}
# A namespace of this run: refused if the name is taken, recorded as it is
# made (an interruption meanwhile waits for the record).
create_netns() { # <name>
	if ip netns list 2>/dev/null | grep -qE "^$1( |$)"; then
		echo "    namespace $1 already exists; it is not this run's and is left alone"
		return 1
	fi
	recording add_netns "$1"
}
add_netns() { # <name>
	ip netns add "$1" || return 1
	CREATED_NETNS+=("$1")
}
# A fresh pair of peers with the given S sizes (and H ranges, H_RANGES unless
# given).
setup_pair() { # <S1> <S2> <S3> <S4> [<H1,H2,H3,H4>]
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
# initiation (cookie replies). The capture must be ready before the traffic,
# still running after it, and run its whole interval to completion; the
# replay must finish. Both must exit 0 with their exact transcripts
# (tests/helpers/boringtun-wire-checks.sh). The capture is given the client's
# public key: a datagram that fits more than one kind is decided by what the
# client can verify of each reading.
run_scenario() { # <name> <S1> <S2> <S3> <S4> <cookies|no-cookies> [<H1,H2,H3,H4>]
	local NAME="$1" S1="$2" S2="$3" S3="$4" S4="$5" COOKIES="$6" H="${7:-${H_RANGES}}" LAYOUT CAPTURE="${WORK}/$1.capture"
	LAYOUT="${S1},${S2},${S3},${S4},${H}"
	SIZES_OF[${NAME}]="${S1},${S2},${S3},${S4}"
	echo "--- ${NAME}: S1=${S1} S2=${S2} S3=${S3} S4=${S4}, ${COOKIES}${7:+, H=${H}}"
	if ! setup_pair "${S1}" "${S2}" "${S3}" "${S4}" "${H}"; then
		bad "${NAME}: the peers could not be set up"
		return 1
	fi
	check "${NAME}: the server runs --imitate-protocol sip, the client no imitation" peer_modes
	if ! bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" "${CAPTURE_SECONDS}" "${CAPTURE}" "${LAYOUT}" "${CLIENT_PUB}"; then
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
	check "${NAME}: the capture outlived the traffic, ran its whole ${CAPTURE_SECONDS} s and completed with all its records" \
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

# 6. Follow-up D's layout (S1=99 S2=54 S3=92 S4=52, an installer draw), with
# H ranges in the installer's segments that make every response fit two
# kinds: a response's S2 prefix ends in two filler spaces before its tag, so
# the four bytes at S4=52 read 0x2020 | (tag & 0xffff) << 16, and with H2 =
# 0x2a3b6f00-0x2a3b6fff that is 0x6fXX2020, inside H4. Its mac1, under the
# client's key, decides it a response.
REPORTED_H="123456789-223456788,708538112-708538367,1234567890-1334567889,1862270976-1962270975"
run_scenario reported 99 54 92 52 no-cookies "${REPORTED_H}"
expect_scenario reported init:absent response:required:shaped cookie:absent transport:required:shaped

# 7. Crossed: a ping reply (96 bytes of plaintext) is S4 + 32 + 96 = 173 bytes,
# the length of a response at S2=81 and of a cookie reply at S3=109, and its
# ciphertext at 81 and 109 falls in the wide H2 and H3 about one time in four
# each; so does the response's ephemeral key at 109. H4's top byte 0x7f is
# never SIP text. A reading whose mac1 fails is not the client's; a
# transport whose receiver index is the session an authenticated response
# opened is decided against an unconfirmable cookie reading.
CROSSED_H="5-104,65536-1073741823,1073741824-2130706431,2130706432-2147483647"
run_scenario crossed 64 81 109 45 no-cookies "${CROSSED_H}"
expect_scenario crossed init:absent response:required:shaped cookie:absent transport:required:shaped
# The same layout with the handshake made before the capture: no response
# names the session, so a ping reply that also fits the cookie rule cannot
# be decided and stays ambiguous, which fails the check.
echo "--- crossed, handshake before the capture"
if setup_pair 64 81 109 45 "${CROSSED_H}" &&
	ip netns exec "${NS_C}" ping -c 1 -W 2 -q "${TUN_S}" >/dev/null &&
	bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" 60 "${WORK}/unseen.capture" "64,81,109,45,${CROSSED_H}" "${CLIENT_PUB}"; then
	ip netns exec "${NS_C}" ping -c 60 -i 0.05 -W 2 -q "${TUN_S}" >/dev/null
	check "crossed, handshake before the capture: the capture ran until its authorized stop" \
		bt_wire_capture_finish "${WORK}/unseen.capture" stop 10
	if bt_wire_kinds "${WORK}/unseen.capture" 64,81,109,45; then
		check "  ping replies that also fit the cookie rule stay ambiguous without their session's response (${BT_WIRE_SUMMARY[ambiguous]} ambiguous, ${BT_WIRE_SEEN[transport]} transport, ${BT_WIRE_SEEN[response]} response)" \
			test "${BT_WIRE_SUMMARY[ambiguous]}" -ge 1 -a "${BT_WIRE_SEEN[response]}" = 0
	else
		bad "crossed, handshake before the capture: the capture has a valid per-kind result (${BT_WIRE_REASON})"
	fi
	check "  and the per-kind check fails" \
		check_fails "${WORK}/unseen.capture" 64,81,109,45 init:absent response:optional cookie:absent transport:required
else
	bad "crossed, handshake before the capture: the peers, the handshake and the capture started"
fi
teardown

echo "--- controls on the real captures"
# Evidence that is not a complete, classified capture fails the check: a
# record of no kind, of two kinds, from a malformed frame, a truncated or
# non-numeric record, or one in the legacy prefix format.
for CONTROL in "unknown 77 -" "ambiguous 95 -" "unresolved 95 -" "malformed 41 -" "transport 77" \
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

echo "--- controls on the capture contract (the real capture helper)"
fails() { # <command...>
	! "$@"
}
# The authorized stop of a real capture passes. A SIGTERM that reaches it
# before that -- from anyone -- fails the same check, and the capture itself
# ends as interrupted, with status 3.
CONTROL_LAYOUT="64,31,31,31,${H_RANGES}"
if setup_pair 64 31 31 31; then
	if bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" 60 "${WORK}/authorized.capture" "${CONTROL_LAYOUT}" "${CLIENT_PUB}"; then
		check "the authorized stop of a running real capture passes the capture check (the controls' baseline)" \
			bt_wire_capture_finish "${WORK}/authorized.capture" stop 10
	else
		bad "the real capture started for the authorized-stop baseline"
	fi
	if bt_wire_capture_start "${NS_C}" "${VETH_C}" "${ADDR_S}" "${PORT}" 60 "${WORK}/oob.capture" "${CONTROL_LAYOUT}" "${CLIENT_PUB}"; then
		bt_wire_signal "${BT_WIRE_CAPTURE}" TERM
		bt_wire_await "${BT_WIRE_CAPTURE}" 10
		check "a SIGTERM before the authorized stop fails the capture check" \
			fails bt_wire_capture_finish "${WORK}/oob.capture" stop 10
		check "  and the capture ended as interrupted, with status 3 ($(tail -n 1 "${WORK}/oob.capture.state"), ${BT_WIRE_STATUS})" \
			bash -c '[[ "$1" =~ ^interrupted\ (0|[1-9][0-9]*)$ && "$2" == 3 ]]' _ "$(tail -n 1 "${WORK}/oob.capture.state")" "${BT_WIRE_STATUS}"
	else
		bad "the real capture started for the out-of-band stop control"
	fi
else
	bad "the peers could not be set up for the capture controls"
fi
teardown

echo "--- an interruption while a namespace is made"
# This run's create_netns, with ip wrapped so that this shell gets SIGTERM
# just after "ip netns add" has made the namespace: the run must end (143)
# only once the namespace is recorded, so that its cleanup finds it.
PROBE_NS="awgsip-p-${RUN_ID}"
PROBE_FILE="${WORK}/netns-probe"
(
	CREATED_NETNS=()
	trap 'interrupted 143' TERM
	trap 'printf "%s\n" "${CREATED_NETNS[@]}" >"${PROBE_FILE}"' EXIT
	ip() {
		command ip "$@"
		local RC=$?
		[[ "$1 $2" == "netns add" ]] && kill -TERM "${BASHPID}"
		return "${RC}"
	}
	create_netns "${PROBE_NS}"
	echo reached >"${PROBE_FILE}.after"
)
PROBE_RC=$?
check "a SIGTERM while a namespace is being made ends the run (${PROBE_RC}) only once that namespace is recorded" \
	test "${PROBE_RC}" = 143 -a "$(cat "${PROBE_FILE}" 2>/dev/null)" = "${PROBE_NS}" -a ! -e "${PROBE_FILE}.after"
[[ "$(cat "${PROBE_FILE}" 2>/dev/null)" == "${PROBE_NS}" ]] && ip netns delete "${PROBE_NS}"

echo "--- the owned-child tracker, in a PID namespace of its own (unshare)"
# Bash reaps a background child by itself, and the kernel may then give its
# PID to another process. That is forced here, and only inside a fresh PID
# namespace: bt_wire_cleanup must neither signal nor wait for the process
# that was given the tracked child's number, and must still end a tracked
# child that runs.
cat >"${WORK}/pid-reuse.sh" <<'EOF'
set -uo pipefail
WIRE="$1/helpers/boringtun-imitation-wire.py"
source "$1/helpers/boringtun-wire-checks.sh"
echo "namespace-shell-pid $$"
bt_wire_spawn RUNNING /dev/null - sleep 30 || exit 3
bt_wire_spawn EXITED /dev/null - bash -c 'exit 42' || exit 3
OLD="${EXITED%% *}"
for ((I = 0; I < 50; I++)); do
	[[ -e "/proc/${OLD}" ]] || break
	sleep 0.1
done
if [[ -e "/proc/${OLD}" ]]; then
	echo "inconclusive: ${OLD} was not reaped by the shell"
	exit 4
fi
echo "reaped-without-wait ${OLD}"
printf '%s' "$((OLD - 1))" >/proc/sys/kernel/ns_last_pid || exit 5
sleep 30 &
STRANGER=$!
if [[ "${STRANGER}" != "${OLD}" ]]; then
	kill "${STRANGER}"
	echo "inconclusive: the new process got PID ${STRANGER}, not ${OLD}"
	exit 4
fi
echo "reused ${OLD}"
bt_wire_cleanup
if kill -0 "${STRANGER}" 2>/dev/null; then echo "replacement-alive"; else echo "replacement-gone"; fi
if [[ -e "/proc/${RUNNING%% *}" ]]; then echo "tracked-running-survived"; else echo "tracked-running-ended"; fi
kill -TERM "${STRANGER}" 2>/dev/null
wait "${STRANGER}"
echo "replacement-status $?"
EOF
if command -v unshare >/dev/null 2>&1; then
	REUSE="$(unshare --pid --fork --mount-proc bash "${WORK}/pid-reuse.sh" "${SCRIPT_DIR}" 2>&1)"
	sed 's/^/    | /' <<<"${REUSE}"
	check "a tracked child that the shell reaped by itself had its PID given to an untracked process (forced, private PID namespace)" \
		grep -q '^reused ' <<<"${REUSE}"
	check "  bt_wire_cleanup neither signalled nor reaped that process" \
		bash -c 'grep -qx replacement-alive <<<"$1" && grep -qx "replacement-status 143" <<<"$1"' _ "${REUSE}"
	check "  and still ended the tracked child that ran" grep -qx tracked-running-ended <<<"${REUSE}"
else
	bad "unshare is available for the PID-reuse control"
fi

echo "--- UAPI sockets: only this run's are removed"
mkdir -p /var/run/wireguard
FOREIGN="/var/run/wireguard/${IF_S}.sock"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${FOREIGN}"
FOREIGN_ID="$(socket_identity "${FOREIGN}")"
teardown
check "a teardown while this run owns no socket leaves an existing one alone" \
	test -n "${FOREIGN_ID}" -a "$(socket_identity "${FOREIGN}")" = "${FOREIGN_ID}"
check "a peer is not started on a socket path that already exists" fails setup_pair 64 31 31 31
teardown
check "  and the teardown after it leaves that socket alone" test "$(socket_identity "${FOREIGN}")" = "${FOREIGN_ID}"
rm -f -- "${FOREIGN}"
REPLACED="/var/run/wireguard/${IF_C}.sock"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${REPLACED}"
OWNED_SOCKETS[${REPLACED}]="$(socket_identity "${REPLACED}")"
rm -f -- "${REPLACED}"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${REPLACED}"
REPLACED_ID="$(socket_identity "${REPLACED}")"
teardown
check "a socket this run recorded, then replaced at the same path by another, is left alone" \
	test "$(socket_identity "${REPLACED}")" = "${REPLACED_ID}"
rm -f -- "${REPLACED}"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${REPLACED}"
OWNED_SOCKETS[${REPLACED}]="$(socket_identity "${REPLACED}")"
teardown
check "while one this run recorded and still the same is removed" test ! -e "${REPLACED}"
# A peer interrupted after it made its UAPI nodes and before this run
# recorded them: a tracked stand-in binds and holds the WireGuard socket and
# makes the AmneziaWG symlink, as BoringTun does, and nothing records them.
mkdir -p /var/run/amneziawg
HOLDER='import os, socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen()
if len(sys.argv) > 2:
    os.symlink(sys.argv[1], sys.argv[2])
time.sleep(600)'
NODE="/var/run/wireguard/${IF_S}.sock"
NODE_LINK="/var/run/amneziawg/${IF_S}.sock"
HOLDER_HANDLE=""
if bt_wire_spawn HOLDER_HANDLE /dev/null - python3 -c "${HOLDER}" "${NODE}" "${NODE_LINK}" &&
	wait_for 10 test -S "${NODE}" -a -L "${NODE_LINK}"; then
	read -r HOLDER_PID HOLDER_START _ <<<"${HOLDER_HANDLE}"
	teardown
	check "a node that a tracked child holds, not yet recorded by this run, is removed with that child" \
		test ! -e "${NODE}" -a ! -L "${NODE_LINK}"
	check "  and the child was ended" \
		bash -c '! python3 "$1" owned "$2" "$3" check >/dev/null' _ "${WIRE}" "${HOLDER_PID}" "${HOLDER_START}"
else
	bad "a tracked stand-in holds the node of ${IF_S}"
fi
# The same node held by a process this run does not track, and a tracked
# child's socket whose node another process replaced at the same path.
if bt_wire_spawn HOLDER_HANDLE /dev/null - python3 -c "${HOLDER}" "${NODE}" && wait_for 10 test -S "${NODE}"; then
	read -r HOLDER_PID HOLDER_START _ <<<"${HOLDER_HANDLE}"
	bt_wire_untrack "${HOLDER_HANDLE}"
	FOREIGN_ID="$(socket_identity "${NODE}")"
	teardown
	check "a node that a process this run does not track holds is left alone" \
		test "$(socket_identity "${NODE}")" = "${FOREIGN_ID}"
	check "  as is that process" \
		bash -c 'python3 "$1" owned "$2" "$3" check >/dev/null' _ "${WIRE}" "${HOLDER_PID}" "${HOLDER_START}"
	bt_wire_stop "${HOLDER_HANDLE}" 5
	rm -f -- "${NODE}"
else
	bad "an untracked stand-in holds the node of ${IF_S}"
fi
if bt_wire_spawn HOLDER_HANDLE /dev/null - python3 -c "${HOLDER}" "${NODE}" && wait_for 10 test -S "${NODE}"; then
	rm -f -- "${NODE}"
	python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${NODE}"
	REPLACED_ID="$(socket_identity "${NODE}")"
	teardown
	check "a node that replaced a tracked child's socket at its path is left alone" \
		test "$(socket_identity "${NODE}")" = "${REPLACED_ID}"
	rm -f -- "${NODE}"
else
	bad "a tracked stand-in holds the node of ${IF_S} for the replacement control"
fi

echo "BoringTun SIP wire test: ${PASSED} passed, ${FAILED} failed"
((FAILED == 0))
