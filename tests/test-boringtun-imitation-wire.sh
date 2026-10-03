#!/usr/bin/env bash

# Unit tests for the imitation wire checks: the framing, packet-kind
# classification, record parsers and per-kind SIP oracle of
# tests/helpers/boringtun-imitation-wire.py, the process contracts and result
# checks of tests/helpers/boringtun-wire-checks.sh, and the two consumers that
# use them, wire_prefixes in tests/test-boringtun-host-live.sh and
# run_scenario/expect_scenario in tests/test-boringtun-sip-wire-live.sh. Nothing
# here needs root or the network: synthetic frames, datagrams and capture
# files stand in for the wire, and a fake capture/replay child stands in for
# the packet sockets. The consumers are extracted verbatim from their files;
# only their external processes are replaced.
#
# The oracle replaces a pooled check that demanded at least one SIP-shaped
# server datagram whenever any of S2-S4 was 31 bytes or more. That check failed
# on a correct server with S2=26 S3=81 S4=22 (0/2054 shaped): S3 prefixes only
# cookie replies, and none was sent.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WIRE_REAL="${SCRIPT_DIR}/helpers/boringtun-imitation-wire.py"
HOST_LIVE="${SCRIPT_DIR}/test-boringtun-host-live.sh"
SIP_LIVE="${SCRIPT_DIR}/test-boringtun-sip-wire-live.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-imitation-wire.XXXXXX")"
trap 'rm -rf -- "${T}"' EXIT
export PYTHONDONTWRITEBYTECODE=1

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required" >&2; exit 1; }
REAL_PYTHON="$(command -v python3)"

PASS=0
FAIL=0
ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}
not_ok() {
	printf '  FAIL: %s\n' "$1" >&2
	FAIL=$((FAIL + 1))
}
assert_eq() {
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected:\n%s\n    actual:\n%s\n' "$(sed 's/^/      /' <<<"$1")" "$(sed 's/^/      /' <<<"$2")" >&2
	fi
}
assert_true() {
	local NAME="$1"
	shift
	if "$@"; then ok "${NAME}"; else not_ok "${NAME}"; fi
}

H="100000001-100000100,200000001-200000100,300000001-300000100,400000001-400000100"
# Python against the real helper, imported from its file: datagrams, frames
# and capture files built exactly.
py() {
	"${REAL_PYTHON}" - "${WIRE_REAL}" "$@" <<'PY'
import importlib.util, os, struct, sys
spec = importlib.util.spec_from_file_location("wire", sys.argv[1])
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
SIZES = {"init": 148, "response": 92, "cookie": 64, "transport": 32}
TAGS = {"init": 100000050, "response": 200000050, "cookie": 300000050, "transport": 400000050}

def datagram(kind, s, prefix="random", tag=None, extra=0):
    if prefix == "sip":
        head = b"OPTIONS sip:u@x SIP/2.0\r\n\r\n"
        body = (head + b" " * s)[:s] if s >= len(head) else os.urandom(s)
    else:
        body = os.urandom(s)
    value = TAGS[kind] if tag is None else tag
    return body + struct.pack("<I", value) + os.urandom(SIZES[kind] - 4 + extra)

def ipv4(payload, src="192.0.2.1", dst="192.0.2.2", sport=51820, dport=40000, proto=17, ident=7,
         fragment=0, udp_length=None, total=None, version=4, ihl=5, pad=b""):
    udp = struct.pack(">HHHH", sport, dport, len(payload) + 8 if udp_length is None else udp_length, 0) + payload
    body = udp if proto == 17 else payload
    length = ihl * 4 + len(body) if total is None else total
    header = struct.pack(">BBHHHBBH4s4s", (version << 4) | ihl, 0, length, ident, fragment, 64, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return header + b"\0" * (ihl * 4 - 20) + body + pad

cmd = sys.argv[2]
if cmd == "kind":
    # kind <layout> <kind> <s> <prefix> [tag] [extra]
    sizes, ranges = wire.parse_layout(sys.argv[3])
    kind, s, prefix = sys.argv[4], int(sys.argv[5]), sys.argv[6]
    tag = int(sys.argv[7]) if len(sys.argv) > 7 and sys.argv[7] != "-" else None
    extra = int(sys.argv[8]) if len(sys.argv) > 8 else 0
    print(wire.kind_of(datagram(kind, s, prefix, tag, extra), sizes, ranges))
elif cmd == "ambiguous":
    # A response at S2=10 that is also a transport at S4=70: both tags fit.
    sizes, ranges = wire.parse_layout("64,10,64,70," + sys.argv[3])
    d = bytearray(os.urandom(102))
    d[10:14] = struct.pack("<I", 200000050)
    d[70:74] = struct.pack("<I", 400000050)
    print(wire.kind_of(bytes(d), sizes, ranges))
elif cmd == "record":
    # record <layout> <out> (<kind>:<count>:<sip|random>)...: a capture file
    # written exactly as capture() writes it, through frame_payload.
    sizes, ranges = wire.parse_layout(sys.argv[3])
    with open(sys.argv[4], "w") as out:
        for spec in sys.argv[5:]:
            kind, count, prefix = spec.split(":")
            s = sizes[wire.KIND_NAMES.index(kind)]
            for _ in range(int(count)):
                d = datagram(kind, s, prefix, extra=16 if kind == "transport" else 0)
                status, length, data, _ = wire.frame_payload(ipv4(d), bytes([192, 0, 2, 1]), 51820)
                out.write(wire.record_line(sizes, ranges, status, length, data) + "\n")
elif cmd == "frame":
    # frame <case>: "<status> <length> <payload bytes kept>" of frame_payload
    payload = os.urandom(77)
    first = set()
    cases = {
        "valid": dict(),
        "padded": dict(pad=b"\0" * 6),
        "udp-length-8": dict(udp_length=8),
        "udp-length-long": dict(udp_length=200),
        "ip-total-28": dict(total=28),
        "ip-total-long": dict(total=500),
        "ipv6-version": dict(version=6),
        "ihl-4": dict(ihl=4),
        "ihl-6": dict(ihl=6),
        "orphan-fragment": dict(fragment=10),
        "first-fragment": dict(fragment=0x2000, udp_length=1000),
        "first-fragment-short": dict(fragment=0x2000, udp_length=40),
        "other-source": dict(src="192.0.2.9"),
        "other-port": dict(sport=53),
        "icmp": dict(proto=1),
    }
    name = sys.argv[3]
    if name == "continuation":
        wire.frame_payload(ipv4(payload, fragment=0x2000, udp_length=1000), bytes([192, 0, 2, 1]), 51820,
                           first_fragments=first)
        frame = ipv4(payload, fragment=10)
    elif name == "short-header":
        frame = ipv4(payload)[:18]
    else:
        frame = ipv4(payload, **cases[name])
    status, length, data, fragmented = wire.frame_payload(frame, bytes([192, 0, 2, 1]), 51820, first_fragments=first)
    print(status, length, len(data), "fragmented" if fragmented else "whole")
elif cmd == "layout":
    try:
        wire.parse_layout(sys.argv[3])
        print("accepted")
    except wire.InputError as error:
        print("refused")
PY
}
kinds() { # <capture> <S1,S2,S3,S4>
	"${REAL_PYTHON}" "${WIRE_REAL}" kinds sip "$1" "$2"
}
kinds_rc() { # <capture> <S1,S2,S3,S4>: "<rc> <stdout lines>"
	local OUT RC
	OUT="$(kinds "$1" "$2" 2>/dev/null)"
	RC=$?
	echo "${RC} $(grep -c . <<<"${OUT}")"
}

echo "=== Packet kind from length and type tag ==="
L="29,26,81,22,${H}"
INDEX=0
for KIND in init response cookie transport; do
	INDEX=$((INDEX + 1))
	S="$(cut -d, -f"${INDEX}" <<<"${L}")"
	assert_eq "${KIND}" "$(py kind "${L}" "${KIND}" "${S}" random)" "a ${KIND} with a random S prefix is a ${KIND}"
	assert_eq "${KIND}" "$(py kind "${L}" "${KIND}" "${S}" sip)" "  and with any prefix content: the SIP text is never consulted"
done
assert_eq "transport" "$(py kind "${L}" transport 22 random - 1396)" "a large transport datagram is a transport"
assert_eq "unknown" "$(py kind "${L}" response 26 random 100000050)" "a response-sized datagram with an H1 tag is no kind"
assert_eq "unknown" "$(py kind "${L}" cookie 81 random 999)" "a cookie-sized datagram with a tag in no range is no kind"
assert_eq "unknown" "$(py kind "${L}" response 26 random - 1)" "a response one byte too long is no response"
assert_eq "unknown" "$(py kind "${L}" transport 21 random)" "a datagram shorter than the smallest transport is no kind"
assert_eq "transport" "$(py kind "31,31,31,31,1-4,5-8,9-12,13-16" transport 31 random 14)" "a single-tag or narrow range layout parses"
assert_eq "cookie" "$(py kind "40,40,40,40,${H}" cookie 40 random)" "with equal S sizes a cookie reply is still a cookie"
assert_eq "transport" "$(py kind "40,40,40,40,${H}" transport 40 random - 32)" "  and a transport of the cookie's length is still a transport"
assert_eq "ambiguous" "$(py ambiguous "${H}")" "a datagram that is a response at S2 and a transport at S4 is ambiguous, not dropped"

echo "=== Layout validation ==="
for LAYOUT in "29,26,81,22" "29,26,81,22,${H},5" "x,26,81,22,${H}" "29,26,81,65536,${H}" "29,26,81,-1,${H}" \
	"29,26,81,22,1-10,5-20,30-40,50-60" "29,26,81,22,10-1,20-30,40-50,60-70" "29,26,81,22,1-2,3-4,5-6,4294967296" \
	"029,26,81,22,${H}"; do
	assert_eq "refused" "$(py layout "${LAYOUT}")" "the layout '${LAYOUT}' is refused"
done
assert_eq "accepted" "$(py layout "29,26,81,22,${H}")" "a valid layout is accepted"

echo "=== IPv4/UDP framing before payload ==="
assert_eq "datagram 77 77 whole" "$(py frame valid)" "a valid frame yields its UDP payload"
assert_eq "datagram 77 77 whole" "$(py frame padded)" "  bounded by the IPv4 total length, not the frame"
for CASE in udp-length-8 udp-length-long ip-total-28 ip-total-long ipv6-version ihl-4 orphan-fragment first-fragment-short short-header; do
	assert_eq "malformed" "$(py frame "${CASE}" | cut -d' ' -f1)" "a relevant frame with ${CASE} is malformed, never payload"
done
assert_eq "datagram 77 77 whole" "$(py frame ihl-6)" "IPv4 options are skipped by the header length"
assert_eq "datagram 992 77 fragmented" "$(py frame first-fragment)" "a first fragment yields the declared length and the bytes it carries"
assert_eq "continuation" "$(py frame continuation | cut -d' ' -f1)" "a later fragment of a counted datagram is its continuation"
for CASE in other-source other-port icmp; do
	assert_eq "ignore" "$(py frame "${CASE}" | cut -d' ' -f1)" "a frame from ${CASE} is not relevant (addressing alone)"
done

echo "=== The recorded follow-up C failure ==="
# S2=26 S3=81 S4=22: handshake responses and transport, no cookie reply, 0/2054 shaped.
py record "${L}" "${T}/recorded" response:2:random transport:2052:random
POOLED_DEMAND=no
for S in 26 81 22; do ((S >= 31)) && POOLED_DEMAND=yes; done
assert_eq "init 0 0 random unobserved
response 2 0 random ok
cookie 0 0 shaped unobserved
transport 2052 0 random ok
unknown 0
ambiguous 0
malformed 0" "$(kinds "${T}/recorded" 29,26,81,22)" \
	"the per-kind oracle passes it: responses and transport random as S2 and S4 say, no cookie reply seen"
assert_eq "yes 0" "${POOLED_DEMAND} $(kinds "${T}/recorded" 29,26,81,22 | awk 'NF == 5 { s += $3 } END { print s + 0 }')" \
	"the pooled oracle demands a request line (max S2-S4 is 81) and finds none: its expectation is false"
py record "${L}" "${T}/recorded-cookies" response:2:random cookie:150:sip transport:300:random
assert_eq "cookie 150 150 shaped ok" "$(kinds "${T}/recorded-cookies" 29,26,81,22 | grep '^cookie ')" \
	"with cookie replies, S3=81 must shape every one"

echo "=== The 30/31 boundary ==="
for KIND in response cookie transport; do
	py record "30,30,30,30,${H}" "${T}/b" "${KIND}:5:random"
	assert_eq "random" "$(kinds "${T}/b" 30,30,30,30 | awk -v k="${KIND}" '$1 == k { print $4 }')" "S=30: ${KIND}s are expected random"
	py record "31,31,31,31,${H}" "${T}/b" "${KIND}:5:sip"
	assert_eq "shaped" "$(kinds "${T}/b" 31,31,31,31 | awk -v k="${KIND}" '$1 == k { print $4 }')" "S=31: ${KIND}s are expected shaped"
done

echo "=== Signature accounting after classification: one kind wrong, the others right ==="
LAYOUT31="64,31,31,45,${H}"
for KIND in response cookie transport; do
	SPECS=()
	EXPECTED=""
	for OTHER in response cookie transport; do
		if [[ "${OTHER}" == "${KIND}" ]]; then
			SPECS+=("${OTHER}:4:random")
			EXPECTED+="${OTHER}=FAIL "
		else
			SPECS+=("${OTHER}:4:sip")
			EXPECTED+="${OTHER}=ok "
		fi
	done
	py record "${LAYOUT31}" "${T}/neg" "${SPECS[@]}"
	assert_eq "${EXPECTED}" "$(kinds "${T}/neg" 64,31,31,45 | awk 'NF == 5 && $1 != "init" { printf "%s=%s ", $1, $5 }')" \
		"${KIND}s without request lines fail only the ${KIND} verdict"
done
py record "${LAYOUT31}" "${T}/neg" response:3:sip cookie:3:sip transport:3:sip transport:1:random
assert_eq "transport 4 3 shaped FAIL" "$(kinds "${T}/neg" 64,31,31,45 | grep '^transport ')" \
	"a single transport datagram without a request line fails the transport verdict"

echo "=== Strict per-kind records ==="
SIG="4f5054494f4e53207369703a75407820"
py record "${LAYOUT31}" "${T}/good" response:2:sip cookie:2:sip transport:2:sip
assert_eq "0 7" "$(kinds_rc "${T}/good" 64,31,31,45)" "a valid capture gives seven rows"
: >"${T}/empty"
assert_eq "0 7" "$(kinds_rc "${T}/empty" 64,31,31,45)" "an empty capture is valid, every kind unobserved"
for RECORD in "transport 77" "transport 77 ${SIG} extra" "transport  77 ${SIG}" "transport NOT_A_LENGTH ${SIG}" \
	"transport 077 ${SIG}" "transport -77 ${SIG}" "transport 76 ${SIG}" "response 136 ${SIG}" "cookie 96 ${SIG}" \
	"transport 77 ${SIG}00" "transport 77 ${SIG:2}" "transport 77 ${SIG^^}" "transport 77 ${SIG:1}" "transport 77 -" \
	"unknown 77 ${SIG}" "unknown x -" "probe 77 -" "${SIG}" "malformed" ""; do
	{ cat "${T}/good"; printf '%s\n' "${RECORD}"; } >"${T}/bad"
	assert_eq "1 0" "$(kinds_rc "${T}/bad" 64,31,31,45)" "valid records followed by '${RECORD}' are refused, nothing printed"
done
{ cat "${T}/good"; printf 'transport 77 %s' "${SIG}"; } >"${T}/bad"
assert_eq "1 0" "$(kinds_rc "${T}/bad" 64,31,31,45)" "an unterminated last record is refused"
{ cat "${T}/good"; printf 'transport 77 \xff\n'; } >"${T}/bad"
assert_eq "1 0" "$(kinds_rc "${T}/bad" 64,31,31,45)" "a non-ASCII record is refused"
for SIZES in 64,31,31 64,31,31,45,1 64,31,31,x 64,31,31,065; do
	assert_eq "1 0" "$(kinds_rc "${T}/good" "${SIZES}")" "the sizes '${SIZES}' are refused"
done
{ cat "${T}/good"; printf 'unknown 77 -\nambiguous 102 -\nmalformed 41 -\n'; } >"${T}/summaries"
assert_eq "unknown 1
ambiguous 1
malformed 1" "$(kinds "${T}/summaries" 64,31,31,45 | tail -n 3)" "unknown, ambiguous and malformed records are counted, each on its own row"

echo "=== Strict legacy prefixes (dns, stun, quic) ==="
printf '%s\n' "${SIG}" "" "0001000021120a" >"${T}/legacy"
assert_eq "2 1" "$("${REAL_PYTHON}" "${WIRE_REAL}" classify sip "${T}/legacy")" "classify reads legacy prefixes, an empty payload line uncounted"
for RECORD in "transport 77 ${SIG}" "malformed 41 -" "${SIG}00" "${SIG^^}" "abc" "zz"; do
	{ cat "${T}/legacy"; printf '%s\n' "${RECORD}"; } >"${T}/legacy-bad"
	"${REAL_PYTHON}" "${WIRE_REAL}" classify dns "${T}/legacy-bad" >/dev/null 2>&1
	assert_eq "1" "$?" "a legacy capture with '${RECORD}' is refused, not reinterpreted"
done

echo "=== The shared result check (tests/helpers/boringtun-wire-checks.sh) ==="
# shellcheck source=helpers/boringtun-wire-checks.sh
source "${SCRIPT_DIR}/helpers/boringtun-wire-checks.sh"
VALID_ROWS="$(kinds "${T}/good" 64,31,31,45)"
assert_true "the helper's own output validates" bt_wire_validate_kinds "${VALID_ROWS}" 64,31,31,45
refused() { # <label> <output>
	if bt_wire_validate_kinds "$2" 64,31,31,45; then not_ok "$1 is refused"; else ok "$1 is refused (${BT_WIRE_REASON})"; fi
}
refused "empty output" ""
refused "garbage output" "THIS IS NOT AN ORACLE RESULT"
refused "output without its last row" "$(head -n 6 <<<"${VALID_ROWS}")"
refused "output with a repeated row" "$(head -n 2 <<<"${VALID_ROWS}"; tail -n 6 <<<"${VALID_ROWS}")"
refused "output with an extra row" "${VALID_ROWS}"$'\nunknown 0'
refused "output with two rows swapped" "$(sed -n '2p' <<<"${VALID_ROWS}"; sed -n '1p' <<<"${VALID_ROWS}"; tail -n 5 <<<"${VALID_ROWS}")"
refused "a row with a missing field" "$(sed '3s/ ok$//' <<<"${VALID_ROWS}")"
refused "a row with an extra field" "$(sed '3s/$/ extra/' <<<"${VALID_ROWS}")"
refused "a negative count" "$(sed '2s/^response 2 2/response -2 2/' <<<"${VALID_ROWS}")"
refused "a non-numeric count" "$(sed '2s/^response 2 2/response two 2/' <<<"${VALID_ROWS}")"
refused "more shaped than seen" "$(sed '2s/^response 2 2/response 2 3/' <<<"${VALID_ROWS}")"
refused "an expectation S does not give" "$(sed '2s/ shaped / random /' <<<"${VALID_ROWS}")"
refused "a verdict the counts do not give" "$(sed '2s/ ok$/ FAIL/' <<<"${VALID_ROWS}")"
refused "an unobserved verdict for seen datagrams" "$(sed '2s/ ok$/ unobserved/' <<<"${VALID_ROWS}")"
refused "a summary with a non-numeric count" "$(sed '5s/^unknown 0$/unknown none/' <<<"${VALID_ROWS}")"

echo "=== Child processes: bounded reaping and owned-only cleanup ==="
sleep 30 &
CHILD=$!
bt_wire_track "${CHILD}"
sleep 30 &
STRANGER=$!
bt_wire_cleanup
assert_true "cleanup terminates and reaps a tracked child" bash -c '! kill -0 "$1" 2>/dev/null' _ "${CHILD}"
assert_true "  and leaves an untracked one alone" kill -0 "${STRANGER}"
kill "${STRANGER}" 2>/dev/null
wait "${STRANGER}" 2>/dev/null
# The child ignores SIGTERM before it says so, so the signal cannot arrive first.
bash -c 'trap "" TERM; : >"$1"; sleep 30' _ "${T}/ignoring" &
CHILD=$!
bt_wire_track "${CHILD}"
for ((I = 0; I < 100; I++)); do
	[[ -e "${T}/ignoring" ]] && break
	sleep 0.1
done
kill -TERM "${CHILD}"
bt_wire_reap "${CHILD}" 1
assert_eq "1 timeout" "$? ${BT_WIRE_STATUS}" "a child that ignores SIGTERM is killed at the time limit and reaped"
(exit 42) &
CHILD=$!
bt_wire_track "${CHILD}"
bt_wire_reap "${CHILD}" 5
assert_eq "0 42" "$? ${BT_WIRE_STATUS}" "an exited child's status is kept"
assert_eq "0" "${#BT_WIRE_CHILDREN[@]}" "reaped children are no longer tracked"

# ── The consumers, with a fake capture/replay child ─────────────────────────
# The fake follows the helper's contract unless a mode breaks it: it copies a
# given capture, writes "ready", then ends with "stopped <n>" on SIGTERM
# (FAKE_END=stop) or "complete <n>" (FAKE_END=complete), exiting
# FAKE_CAPTURE_RC. Other modes: "noready", "early" (complete before any stop),
# "crash" (exit 42 after the records, no final line). The replay prints
# "ready" and "replayed <n>" and exits FAKE_REPLAY_RC, or ("noready") prints
# nothing. `kinds` runs the real helper unless FAKE_KINDS asks for empty or
# garbage output with exit 0.
FAKEWIRE="${T}/fakewire"
cat >"${FAKEWIRE}" <<'EOF'
#!/bin/bash
case "$1" in
	capture)
		OUT="$6"
		cp -- "${FAKE_CAPTURE}" "${OUT}"
		N="$(wc -l <"${OUT}")"
		[[ "${FAKE_CAPTURE_MODE:-}" == noready ]] && exit 1
		echo ready >>"${OUT}.state"
		case "${FAKE_CAPTURE_MODE:-}" in
			early) echo "complete ${N}" >>"${OUT}.state"; exit 0 ;;
			crash) exit 42 ;;
		esac
		if [[ "${FAKE_END}" == stop ]]; then
			trap 'echo "stopped ${N}" >>"${OUT}.state"; exit "${FAKE_CAPTURE_RC:-0}"' TERM
			while :; do sleep 0.05; done
		fi
		echo "complete ${N}" >>"${OUT}.state"
		exit "${FAKE_CAPTURE_RC:-0}"
		;;
	replay)
		[[ "${FAKE_REPLAY_MODE:-}" == noready ]] && exit 1
		echo ready
		echo "replayed $7"
		exit "${FAKE_REPLAY_RC:-0}"
		;;
	kinds)
		case "${FAKE_KINDS:-real}" in
			empty) exit 0 ;;
			garbage) echo "THIS IS NOT AN ORACLE RESULT"; exit 0 ;;
		esac
		;;
esac
exec "${REAL_PYTHON}" "${WIRE_REAL}" "$@"
EOF
chmod 0755 "${FAKEWIRE}"
export REAL_PYTHON WIRE_REAL
extract() { # <file> <function>: its definition, verbatim
	awk -v f="$2" '$0 ~ "^"f"\\(\\) \\{" {on=1} on {print} on && /^}/ {exit}' "$1"
}
for FUNCTION in "${HOST_LIVE}:wire_prefixes" "${SIP_LIVE}:run_scenario" "${SIP_LIVE}:expect_scenario" "${SIP_LIVE}:peer_modes"; do
	assert_true "${FUNCTION##*/} is extracted from its file" test -n "$(extract "${FUNCTION%:*}" "${FUNCTION##*:}")"
done
# Records for S1=64 S2=31 S3=31 S4=45 (and S2=S3=S4=31 for the harness).
py record "64,31,31,45,${H}" "${T}/host-valid" response:1:sip transport:3:sip
py record "64,31,31,31,${H}" "${T}/live-valid" response:1:sip cookie:3:sip transport:3:sip
with_record() { # <capture> <record> <out>
	{ cat "$1"; printf '%s\n' "$2"; } >"$3"
}
with_record "${T}/host-valid" "unknown 77 -" "${T}/host-unknown"
with_record "${T}/host-valid" "ambiguous 102 -" "${T}/host-ambiguous"
with_record "${T}/host-valid" "malformed 41 -" "${T}/host-malformed-frame"
with_record "${T}/host-valid" "transport 77" "${T}/host-truncated"
with_record "${T}/host-valid" "transport NOT_A_LENGTH ${SIG}" "${T}/host-badlength"
with_record "${T}/live-valid" "transport 77" "${T}/live-truncated"
with_record "${T}/live-valid" "unknown 77 -" "${T}/live-unknown"

# The host consumer: wire_prefixes sip, its capture stopped after the traffic.
host_case() { # <capture> [VAR=value...]: "assertions=<n> failures=<n>"
	local CAPTURE="$1"
	shift
	# shellcheck disable=SC2034 # the fixture settings are read by the extracted wire_prefixes
	(
		# shellcheck disable=SC2163 # the arguments are VAR=value assignments
		export FAKE_CAPTURE="${CAPTURE}" FAKE_END=stop "$@"
		WORK="${T}/host-work"
		rm -rf "${WORK}" && mkdir -p "${WORK}"
		WIRE=fake NS=fixture VETH_CLIENT=fixture HOST_ADDR=192.0.2.1 PORT=51820
		PASSED=0 FAILED=0
		ok() { PASSED=$((PASSED + 1)); }
		bad() { FAILED=$((FAILED + 1)); }
		check() { local M="$1"; shift; if "$@"; then ok "${M}"; else bad "${M}"; fi; }
		params_s() { case "$1" in S1) echo 64 ;; S2 | S3) echo 31 ;; S4) echo 45 ;; esac; }
		params_layout() { echo "64,31,31,45,${H}"; }
		datapath() { :; }
		python3() { if ((BASH_SUBSHELL > 0)); then exec "${FAKEWIRE}" "${@:2}"; else "${FAKEWIRE}" "${@:2}"; fi; }
		ip() { if [[ "$1 $2" == "netns exec" ]]; then shift 3; "$@"; else return 97; fi; }
		eval "$(extract "${HOST_LIVE}" wire_prefixes)"
		wire_prefixes sip >/dev/null 2>&1
		echo "assertions=$((PASSED + FAILED)) failures=${FAILED}"
	)
}
echo "=== The host consumer (wire_prefixes) ==="
assert_eq "assertions=8 failures=0" "$(host_case "${T}/host-valid")" "valid response and transport records pass"
for CASE in unknown ambiguous malformed-frame truncated badlength; do
	RESULT="$(host_case "${T}/host-${CASE}")"
	assert_true "valid records plus a ${CASE} record fail (${RESULT})" bash -c '[[ "$1" != *"failures=0" ]]' _ "${RESULT}"
done
for KINDS_MODE in empty garbage; do
	RESULT="$(host_case "${T}/host-valid" FAKE_KINDS="${KINDS_MODE}")"
	assert_true "a helper that exits 0 with ${KINDS_MODE} output fails, never zero assertions (${RESULT})" \
		bash -c '[[ "$1" != *"failures=0" && "$1" != "assertions=0 "* ]]' _ "${RESULT}"
done
for CAPTURE_MODE in "FAKE_CAPTURE_RC=42" "FAKE_CAPTURE_MODE=crash" "FAKE_CAPTURE_MODE=early" "FAKE_CAPTURE_MODE=noready"; do
	RESULT="$(host_case "${T}/host-valid" "${CAPTURE_MODE}")"
	assert_true "a capture with ${CAPTURE_MODE} after valid records fails (${RESULT})" bash -c '[[ "$1" != *"failures=0" ]]' _ "${RESULT}"
done

# The harness consumer: run_scenario and expect_scenario with cookies.
live_case() { # <capture> [VAR=value...]: "assertions=<n> failures=<n>"
	local CAPTURE="$1"
	shift
	# shellcheck disable=SC2034 # the fixture settings are read by the extracted run_scenario
	(
		# shellcheck disable=SC2163 # the arguments are VAR=value assignments
		export FAKE_CAPTURE="${CAPTURE}" FAKE_END=complete "$@"
		WORK="${T}/live-work"
		rm -rf "${WORK}" && mkdir -p "${WORK}"
		WIRE=fake NS_C=fixture VETH_C=fixture ADDR_C=192.0.2.2 ADDR_S=192.0.2.1 PORT=51999 DOMAIN=pbx.example
		REPLAYS=400 TUN_S=10.77.0.1 H_RANGES="${H}" CAPTURE_SECONDS=1
		declare -A SIZES_OF=()
		PASSED=0 FAILED=0
		ok() { PASSED=$((PASSED + 1)); }
		bad() { FAILED=$((FAILED + 1)); }
		check() { local M="$1"; shift; if "$@"; then ok "${M}"; else bad "${M}"; fi; }
		# Stand-in peers whose /proc cmdlines carry what peer_modes reads.
		bash -c 'while :; do sleep 0.2; done' server --imitate-protocol sip --imitate-domain pbx.example fixture0 &
		SERVER_PID=$!
		bash -c 'while :; do sleep 0.2; done' client fixture1 &
		CLIENT_PID=$!
		setup_pair() { :; }
		python3() { if ((BASH_SUBSHELL > 0)); then exec "${FAKEWIRE}" "${@:2}"; else "${FAKEWIRE}" "${@:2}"; fi; }
		ip() {
			[[ "$1 $2" == "netns exec" ]] || return 97
			shift 3
			[[ "$1" == ping ]] && return 0
			"$@"
		}
		for FUNCTION in run_scenario expect_scenario peer_modes; do
			eval "$(extract "${SIP_LIVE}" "${FUNCTION}")"
		done
		{
			run_scenario fixture 64 31 31 31 cookies
			expect_scenario fixture init:absent response:required:shaped cookie:required:shaped transport:required:shaped
		} >/dev/null 2>&1
		kill "${SERVER_PID}" "${CLIENT_PID}" 2>/dev/null
		wait "${SERVER_PID}" "${CLIENT_PID}" 2>/dev/null
		echo "assertions=$((PASSED + FAILED)) failures=${FAILED}"
	)
}
echo "=== The harness consumer (run_scenario, expect_scenario) ==="
assert_eq "assertions=18 failures=0" "$(live_case "${T}/live-valid")" "a valid scenario passes"
for CASE in truncated unknown; do
	RESULT="$(live_case "${T}/live-${CASE}")"
	assert_true "valid records plus a ${CASE} record fail (${RESULT})" bash -c '[[ "$1" != *"failures=0" ]]' _ "${RESULT}"
done
for MODE in "FAKE_CAPTURE_RC=42" "FAKE_CAPTURE_MODE=crash" "FAKE_CAPTURE_MODE=noready" "FAKE_REPLAY_RC=42" \
	"FAKE_REPLAY_MODE=noready" "FAKE_KINDS=garbage" "FAKE_KINDS=empty"; do
	RESULT="$(live_case "${T}/live-valid" "${MODE}")"
	assert_true "a scenario with ${MODE} fails (${RESULT})" bash -c '[[ "$1" != *"failures=0" ]]' _ "${RESULT}"
done

echo
echo "${PASS} tests, ${FAIL} failures"
((FAIL == 0))
