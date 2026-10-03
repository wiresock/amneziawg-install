#!/usr/bin/env bash

# Unit tests for the packet-kind classification and the per-kind SIP oracle of
# tests/helpers/boringtun-imitation-wire.py. Nothing here needs root or the
# network: synthetic datagrams and capture files stand in for the wire.
#
# The oracle replaces a pooled check that demanded at least one SIP-shaped
# server datagram whenever any of S2-S4 was 31 bytes or more. That check failed
# on a correct server with S2=26 S3=81 S4=22 (0/2054 shaped): S3 prefixes only
# cookie replies, and none was sent. Here each packet kind is held to its own
# S, and the kind of a datagram comes from its length and type tag, never from
# the SIP text.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WIRE="${SCRIPT_DIR}/helpers/boringtun-imitation-wire.py"
T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-imitation-wire.XXXXXX")"
trap 'rm -rf -- "${T}"' EXIT

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required" >&2; exit 1; }

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

H="100000001-100000100,200000001-200000100,300000001-300000100,400000001-400000100"
# A datagram of a kind with an S prefix (a SIP request line or random bytes),
# its type tag and filler, as hex; "tag" may name a value outside the kind.
# Python, so the bytes are built exactly; the helper is imported from its file.
py() {
	python3 - "${WIRE}" "$@" <<'PY'
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
    rest = os.urandom(SIZES[kind] - 4 + extra)
    return body + struct.pack("<I", value) + rest

cmd = sys.argv[2]
sizes, ranges = wire.parse_layout(sys.argv[3])
if cmd == "kind":
    # kind <layout> <kind> <s> <prefix> [tag] [extra]
    kind, s, prefix = sys.argv[4], int(sys.argv[5]), sys.argv[6]
    tag = int(sys.argv[7]) if len(sys.argv) > 7 and sys.argv[7] != "-" else None
    extra = int(sys.argv[8]) if len(sys.argv) > 8 else 0
    print(wire.kind_of(datagram(kind, s, prefix, tag, extra), sizes, ranges))
elif cmd == "record":
    # record <layout> <out> (<kind>:<count>:<sip|random>)...: a capture file
    # written exactly as capture() writes it.
    with open(sys.argv[4], "w") as out:
        for spec in sys.argv[5:]:
            kind, count, prefix = spec.split(":")
            s = sizes[[k[0] for k in wire.KINDS].index(kind)]
            for _ in range(int(count)):
                d = datagram(kind, s, prefix, extra=16 if kind == "transport" else 0)
                k = wire.kind_of(d, sizes, ranges)
                out.write("%s %d %s\n" % (k, len(d), d[:min(16, s)].hex() or "-"))
PY
}
kinds() { # <capture> <S1,S2,S3,S4>
	python3 "${WIRE}" kinds sip "$1" "$2"
}

echo "=== Packet kind from length and type tag ==="
L="29,26,81,22,${H}"
for KIND in init response cookie transport; do
	S="$(cut -d, -f"$(( $(printf 'init\nresponse\ncookie\ntransport\n' | grep -nx "${KIND}" | cut -d: -f1) ))" <<<"${L}")"
	assert_eq "${KIND}" "$(py kind "${L}" "${KIND}" "${S}" random)" "a ${KIND} with a random S prefix is a ${KIND}"
	assert_eq "${KIND}" "$(py kind "${L}" "${KIND}" "${S}" sip)" "  and with any prefix content: the SIP text is never consulted"
done
assert_eq "transport" "$(py kind "${L}" transport 22 random - 1396)" "a large transport datagram is a transport"
assert_eq "unknown" "$(py kind "${L}" response 26 random 100000050)" "a response-sized datagram with an H1 tag is no kind"
assert_eq "unknown" "$(py kind "${L}" cookie 81 random 999)" "a cookie-sized datagram with a tag in no range is no kind"
assert_eq "unknown" "$(py kind "${L}" response 26 random - 1)" "a response one byte too long is no response"
assert_eq "unknown" "$(py kind "${L}" transport 21 random)" "a datagram shorter than the smallest transport is no kind"
assert_eq "transport" "$(py kind "31,31,31,31,1-4,5-8,9-12,13-16" transport 31 random 14)" "a single-tag or narrow range layout parses"
# Equal S and a length that fits two kinds: the tag decides.
assert_eq "cookie" "$(py kind "40,40,40,40,${H}" cookie 40 random)" "with equal S sizes a cookie reply is still a cookie"
assert_eq "transport" "$(py kind "40,40,40,40,${H}" transport 40 random - 32)" "  and a transport of the cookie's length is still a transport"

echo "=== The recorded follow-up C failure ==="
# S2=26 S3=81 S4=22: handshake responses and transport, no cookie reply, 0/2054 shaped.
py record "${L}" "${T}/recorded" response:2:random transport:2052:random
assert_eq "2054 0" "$(python3 "${WIRE}" classify sip "${T}/recorded")" "the recorded capture: 2054 datagrams, none with a request line"
POOLED_DEMAND=no
for S in 26 81 22; do ((S >= 31)) && POOLED_DEMAND=yes; done
assert_eq "yes 0" "${POOLED_DEMAND} $(python3 "${WIRE}" classify sip "${T}/recorded" | cut -d' ' -f2)" \
	"the pooled oracle demands a request line (max S2-S4 is 81) and finds none: its expectation is false"
assert_eq "init 0 0 random unobserved
response 2 0 random ok
cookie 0 0 shaped unobserved
transport 2052 0 random ok
unknown 0" "$(kinds "${T}/recorded" 29,26,81,22)" \
	"the per-kind oracle passes it: responses and transport random as S2 and S4 say, no cookie reply seen"
py record "${L}" "${T}/recorded-cookies" response:2:random cookie:150:sip transport:300:random
assert_eq "cookie 150 150 shaped ok" "$(kinds "${T}/recorded-cookies" 29,26,81,22 | grep '^cookie ')" \
	"with cookie replies, S3=81 must shape every one"

echo "=== The 30/31 boundary ==="
for KIND in response cookie transport; do
	assert_eq "random" "$(py record "30,30,30,30,${H}" "${T}/b" "${KIND}:5:random" && kinds "${T}/b" 30,30,30,30 | awk -v k="${KIND}" '$1 == k { print $4 }')" \
		"S=30: ${KIND}s are expected random"
	assert_eq "shaped" "$(py record "31,31,31,31,${H}" "${T}/b" "${KIND}:5:sip" && kinds "${T}/b" 31,31,31,31 | awk -v k="${KIND}" '$1 == k { print $4 }')" \
		"S=31: ${KIND}s are expected shaped"
done

echo "=== Negative controls: one kind wrong, the others right ==="
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
	assert_eq "${EXPECTED}" "$(kinds "${T}/neg" 64,31,31,45 | awk '$1 != "unknown" && $1 != "init" { printf "%s=%s ", $1, $5 }')" \
		"${KIND}s without request lines fail only the ${KIND} verdict"
done
py record "${LAYOUT31}" "${T}/neg" response:3:sip cookie:3:sip transport:3:sip transport:1:random
assert_eq "transport 4 3 shaped FAIL" "$(kinds "${T}/neg" 64,31,31,45 | grep '^transport ')" \
	"a single transport datagram without a request line fails the transport verdict"
py record "30,30,30,30,${H}" "${T}/neg" response:3:sip cookie:3:random transport:3:random
assert_eq "response=FAIL cookie=ok transport=ok " "$(kinds "${T}/neg" 30,30,30,30 | awk '$1 != "unknown" && $1 != "init" { printf "%s=%s ", $1, $5 }')" \
	"request lines where S=30 leaves the prefix random fail that kind"
printf 'unknown 999 -\n' >>"${T}/neg"
assert_eq "unknown 1" "$(kinds "${T}/neg" 30,30,30,30 | tail -n 1)" "datagrams of no kind are counted, not given a verdict"

echo "=== Formats and refusals ==="
printf '%s\n' "$(printf 'OPTIONS sip:u@x' | od -An -tx1 | tr -d ' \n')00" >"${T}/legacy"
assert_eq "1 1" "$(python3 "${WIRE}" classify sip "${T}/legacy")" "classify still reads the 16-byte capture format"
python3 "${WIRE}" kinds dns "${T}/neg" 30,30,30,30 >/dev/null 2>&1
assert_eq "1" "$?" "per-kind expectations are refused for other protocols"
python3 "${WIRE}" kinds sip "${T}/neg" 30,30,30 >/dev/null 2>&1
assert_eq "1" "$?" "a layout without four S sizes is refused"

echo
echo "${PASS} tests, ${FAIL} failures"
((FAIL == 0))
