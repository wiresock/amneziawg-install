#!/bin/bash
# Unit tests for amneziawg-install.sh pure functions
#
# Usage: bash tests/test-functions.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source the install script to load function definitions
# The main execution block is guarded by BASH_SOURCE check, so only functions are loaded
source "${PROJECT_ROOT}/amneziawg-install.sh"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

function assert_eq() {
	local EXPECTED="$1"
	local ACTUAL="$2"
	local MSG="${3:-assertion}"
	TESTS_RUN=$((TESTS_RUN + 1))
	if [[ "${EXPECTED}" == "${ACTUAL}" ]]; then
		TESTS_PASSED=$((TESTS_PASSED + 1))
	else
		TESTS_FAILED=$((TESTS_FAILED + 1))
		echo "  FAIL: ${MSG} (expected '${EXPECTED}', got '${ACTUAL}')"
	fi
}

function assert_rc() {
	local EXPECTED_RC="$1"
	shift
	local ACTUAL_RC=0
	"$@" || ACTUAL_RC=$?
	local MSG="$*"
	TESTS_RUN=$((TESTS_RUN + 1))
	if [[ "${EXPECTED_RC}" == "${ACTUAL_RC}" ]]; then
		TESTS_PASSED=$((TESTS_PASSED + 1))
	else
		TESTS_FAILED=$((TESTS_FAILED + 1))
		echo "  FAIL: ${MSG} -> exit code (expected ${EXPECTED_RC}, got ${ACTUAL_RC})"
	fi
}

echo "=== isPrivateIPv4 ==="
# Private/non-routable ranges
assert_rc 0 isPrivateIPv4 "10.0.0.1"
assert_rc 0 isPrivateIPv4 "10.255.255.255"
assert_rc 0 isPrivateIPv4 "172.16.0.1"
assert_rc 0 isPrivateIPv4 "172.31.0.1"        # AWS default VPC range
assert_rc 0 isPrivateIPv4 "172.31.255.254"
assert_rc 0 isPrivateIPv4 "192.168.1.1"
assert_rc 0 isPrivateIPv4 "127.0.0.1"
assert_rc 0 isPrivateIPv4 "169.254.169.254"   # AWS metadata / link-local
assert_rc 0 isPrivateIPv4 "100.64.0.1"        # CGNAT lower bound
assert_rc 0 isPrivateIPv4 "100.127.255.255"   # CGNAT upper bound
assert_rc 0 isPrivateIPv4 "0.0.0.0"
# Public addresses
assert_rc 1 isPrivateIPv4 "8.8.8.8"
assert_rc 1 isPrivateIPv4 "1.1.1.1"
assert_rc 1 isPrivateIPv4 "172.15.0.1"        # just outside 172.16/12
assert_rc 1 isPrivateIPv4 "172.32.0.1"        # just outside 172.16/12
assert_rc 1 isPrivateIPv4 "192.169.0.1"       # just outside 192.168/16
assert_rc 1 isPrivateIPv4 "100.63.255.255"    # just outside CGNAT
assert_rc 1 isPrivateIPv4 "100.128.0.0"       # just outside CGNAT
assert_rc 1 isPrivateIPv4 "169.253.0.1"       # just outside link-local
# Non-IPv4 inputs
assert_rc 1 isPrivateIPv4 ""
assert_rc 1 isPrivateIPv4 "not-an-ip"
assert_rc 1 isPrivateIPv4 "::1"
assert_rc 1 isPrivateIPv4 "256.0.0.1"
# Leading-zero inputs must not trigger bash octal parsing or arithmetic errors.
# These are accepted by the IPv4 regex; they should be classified consistently
# without producing stderr noise.
assert_rc 0 isPrivateIPv4 "010.0.0.1"       # 10.0.0.1 — private, octal-looking
assert_rc 1 isPrivateIPv4 "08.0.0.1"        # 8.0.0.1 — public, invalid octal
assert_rc 1 isPrivateIPv4 "09.0.0.1"        # 9.0.0.1 — public, invalid octal
assert_rc 0 isPrivateIPv4 "172.016.0.1"    # 172.16.0.1 — private (boundary)

echo "=== detectPublicIPv4 ==="
# Helper: run detectPublicIPv4 with stubbed `ip`, `curl`, and `wget`
# binaries on PATH. This exercises every branch (local public IP, local
# private IP + curl success/failure, wget fallback, opt-out) without making
# real network requests.
DPI_TMP="$(mktemp -d)"
trap 'rm -rf "${DPI_TMP}"' EXIT
mkdir -p "${DPI_TMP}/bin" "${DPI_TMP}/realbin"
# Build an isolated PATH containing only the coreutils detectPublicIPv4 needs
# plus our stubs. Any tool not symlinked here (notably curl/wget) will be
# absent unless we stub it explicitly, which is exactly what we want to
# exercise branches like "curl missing -> use wget".
for _cmd in head sed tr awk cat bash printf; do
	if _real="$(command -v "${_cmd}" 2>/dev/null)"; then
		ln -sf "${_real}" "${DPI_TMP}/realbin/${_cmd}"
	fi
done
unset _cmd _real

# stub creates an executable shell stub at "${DPI_TMP}/bin/<name>" that
# prints $2 to stdout and exits with $3 (default 0).
function _stub() {
	local NAME="$1"
	local OUT="${2:-}"
	local RC="${3:-0}"
	# Write OUT to a sibling data file so arbitrary bytes (newlines, quotes,
	# shell metacharacters) cannot break the generated stub script.
	local OUT_FILE="${DPI_TMP}/bin/${NAME}.out"
	printf '%s\n' "${OUT}" > "${OUT_FILE}"
	cat > "${DPI_TMP}/bin/${NAME}" <<EOF
#!/usr/bin/env bash
cat "${OUT_FILE}"
exit ${RC}
EOF
	chmod +x "${DPI_TMP}/bin/${NAME}"
}

# Run detectPublicIPv4 with only our stubs and the symlinked coreutils on PATH.
function _run_detect() {
	(
		PATH="${DPI_TMP}/bin:${DPI_TMP}/realbin"
		export PATH
		unset AWG_SKIP_PUBLIC_IP_LOOKUP
		detectPublicIPv4
	)
}

# Case 1: local interface has a public IPv4 -> return it, no external lookup.
_stub ip "5: eth0    inet 203.0.113.10/24 scope global eth0"
_stub curl "SHOULD_NOT_BE_CALLED" 0
_stub wget "SHOULD_NOT_BE_CALLED" 0
assert_eq "203.0.113.10" "$(_run_detect)" "detectPublicIPv4 returns local public IPv4"

# Case 2: local interface is private, curl returns a public IPv4.
_stub ip "5: eth0    inet 172.31.4.10/20 scope global eth0"
_stub curl "203.0.113.42" 0
_stub wget "SHOULD_NOT_BE_CALLED" 0
assert_eq "203.0.113.42" "$(_run_detect)" "detectPublicIPv4 falls back to curl on private local IP"

# Case 3: local interface empty, curl returns a public IPv4 (with whitespace).
_stub ip ""
_stub curl $'  198.51.100.7  \n' 0
assert_eq "198.51.100.7" "$(_run_detect)" "detectPublicIPv4 trims whitespace from external response"

# Case 4: local is private, curl returns a private IP -> rejected, fall back to local.
_stub ip "5: eth0    inet 10.0.0.5/24 scope global eth0"
_stub curl "10.1.2.3" 0
assert_eq "10.0.0.5" "$(_run_detect)" "detectPublicIPv4 rejects private IP from external service"

# Case 5: curl absent, wget present and returns a public IPv4.
rm -f "${DPI_TMP}/bin/curl"
_stub ip "5: eth0    inet 192.168.1.5/24 scope global eth0"
_stub wget "203.0.113.99" 0
assert_eq "203.0.113.99" "$(_run_detect)" "detectPublicIPv4 uses wget when curl is absent"

# Case 6: curl absent, wget returns garbage -> fall back to local private IP.
_stub ip "5: eth0    inet 192.168.1.5/24 scope global eth0"
_stub wget "not-an-ip" 0
assert_eq "192.168.1.5" "$(_run_detect)" "detectPublicIPv4 falls back when wget returns invalid"

# Case 6b: multi-homed host with a private interface listed first and a
# public one listed second -> pick the public one, no external lookup.
# (Re-stub curl since Case 5 removed it.)
_stub curl "SHOULD_NOT_BE_CALLED" 0
_stub wget "SHOULD_NOT_BE_CALLED" 0
_stub ip "$(printf '%s\n' \
	"3: ens5    inet 172.31.4.10/20 scope global ens5" \
	"4: eth1    inet 198.51.100.25/24 scope global eth1")"
assert_eq "198.51.100.25" "$(_run_detect)" "detectPublicIPv4 prefers public over private on multi-homed host"

# Case 6c: multi-homed host where all global IPv4s are private -> external
# lookup runs, but local fallback is the *first* private address listed.
_stub ip "$(printf '%s\n' \
	"3: ens5    inet 10.0.0.5/24 scope global ens5" \
	"4: eth1    inet 192.168.1.20/24 scope global eth1")"
_stub curl "" 1   # external lookup fails
assert_eq "10.0.0.5" "$(_run_detect)" "detectPublicIPv4 falls back to first private IP when all are private"

# Case 7: opt-out via AWG_SKIP_PUBLIC_IP_LOOKUP=y suppresses external lookups.
_stub ip "5: eth0    inet 172.31.4.10/20 scope global eth0"
_stub curl "203.0.113.42" 0   # would be used if not opted out
_stub wget "203.0.113.99" 0
assert_eq "172.31.4.10" "$(
	PATH="${DPI_TMP}/bin:${DPI_TMP}/realbin" AWG_SKIP_PUBLIC_IP_LOOKUP=y \
		bash -c "$(declare -f detectPublicIPv4 isPrivateIPv4); detectPublicIPv4"
)" "detectPublicIPv4 honours AWG_SKIP_PUBLIC_IP_LOOKUP=y"

# Case 8: opt-out via AWG_SKIP_PUBLIC_IP_LOOKUP=1 also accepted.
assert_eq "172.31.4.10" "$(
	PATH="${DPI_TMP}/bin:${DPI_TMP}/realbin" AWG_SKIP_PUBLIC_IP_LOOKUP=1 \
		bash -c "$(declare -f detectPublicIPv4 isPrivateIPv4); detectPublicIPv4"
)" "detectPublicIPv4 honours AWG_SKIP_PUBLIC_IP_LOOKUP=1"

trap - EXIT
rm -rf "${DPI_TMP}"
unset DPI_TMP

echo "=== isValidIPv6 ==="
assert_rc 0 isValidIPv6 "::1"
assert_rc 0 isValidIPv6 "fd42:42:42::1"
assert_rc 0 isValidIPv6 "2001:db8::1"
assert_rc 0 isValidIPv6 "fe80::1"
assert_rc 0 isValidIPv6 "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
assert_rc 0 isValidIPv6 "::"
assert_rc 1 isValidIPv6 ""
assert_rc 1 isValidIPv6 "not-an-ipv6"
assert_rc 1 isValidIPv6 "192.168.1.1"
assert_rc 1 isValidIPv6 ":::"
assert_rc 1 isValidIPv6 "2001:db8::1::2"
assert_rc 1 isValidIPv6 "gggg::1"
assert_rc 1 isValidIPv6 "12345::1"

echo "=== normalizeIPv6 ==="
assert_eq "fd42:42:42:0:0:0:0:1" "$(normalizeIPv6 "fd42:42:42::1")" "normalizeIPv6 fd42:42:42::1"
assert_eq "0:0:0:0:0:0:0:1" "$(normalizeIPv6 "::1")" "normalizeIPv6 ::1"
assert_eq "0:0:0:0:0:0:0:0" "$(normalizeIPv6 "::")" "normalizeIPv6 ::"
assert_eq "2001:db8:85a3:0:0:8a2e:370:7334" "$(normalizeIPv6 "2001:0db8:85a3:0000:0000:8a2e:0370:7334")" "normalizeIPv6 full form"
assert_eq "fe80:0:0:0:0:0:0:1" "$(normalizeIPv6 "fe80::1")" "normalizeIPv6 fe80::1"
assert_eq "2001:db8:0:0:0:0:0:0" "$(normalizeIPv6 "2001:db8::")" "normalizeIPv6 trailing ::"

echo "=== compressIPv6 ==="
# Addresses that should NOT compress (no run of >= 2 consecutive zero groups)
assert_eq "2001:db8:0:1:2:3:4:5" "$(compressIPv6 "2001:db8:0:1:2:3:4:5")" "compressIPv6 single zero no compress"
assert_eq "2001:db8:0:1:2:3:4:0" "$(compressIPv6 "2001:db8:0:1:2:3:4:0")" "compressIPv6 trailing single zero no compress"

# Simple middle run (>= 2 consecutive zeros)
assert_eq "2001:db8::1:0:0:1" "$(compressIPv6 "2001:db8:0:0:1:0:0:1")" "compressIPv6 middle run"

# Leading zero run
assert_eq "::1:2:3:4:5" "$(compressIPv6 "0:0:0:1:2:3:4:5")" "compressIPv6 leading run"

# Trailing zero run
assert_eq "2001:db8:1:2:3:4::" "$(compressIPv6 "2001:db8:1:2:3:4:0:0")" "compressIPv6 trailing run"

echo "=== compressIPv6 (via installer helper) ==="
assert_rc 0 run_compressIPv6_tests

echo "=== parseRange ==="
TEMP_MIN="" ; TEMP_MAX=""
assert_rc 0 parseRange "100-200" TEMP_MIN TEMP_MAX
assert_eq "100" "${TEMP_MIN}" "parseRange 100-200 min"
assert_eq "200" "${TEMP_MAX}" "parseRange 100-200 max"

TEMP_MIN="" ; TEMP_MAX=""
assert_rc 0 parseRange "42" TEMP_MIN TEMP_MAX
assert_eq "42" "${TEMP_MIN}" "parseRange single value min"
assert_eq "42" "${TEMP_MAX}" "parseRange single value max"

TEMP_MIN="" ; TEMP_MAX=""
assert_rc 0 parseRange "5-5" TEMP_MIN TEMP_MAX
assert_eq "5" "${TEMP_MIN}" "parseRange same value min"
assert_eq "5" "${TEMP_MAX}" "parseRange same value max"

assert_rc 1 parseRange "" TEMP_MIN TEMP_MAX
assert_rc 1 parseRange "abc" TEMP_MIN TEMP_MAX
assert_rc 1 parseRange "200-100" TEMP_MIN TEMP_MAX

# Octal handling: leading zeros should be treated as decimal
TEMP_MIN="" ; TEMP_MAX=""
assert_rc 0 parseRange "010" TEMP_MIN TEMP_MAX
assert_eq "10" "${TEMP_MIN}" "parseRange octal-like value treated as decimal"

echo "=== rangesOverlap ==="
assert_rc 0 rangesOverlap 1 10 5 15
assert_rc 0 rangesOverlap 1 10 10 20
assert_rc 0 rangesOverlap 5 5 5 5
assert_rc 0 rangesOverlap 1 100 50 60
assert_rc 1 rangesOverlap 1 10 11 20
assert_rc 1 rangesOverlap 11 20 1 10
assert_rc 1 rangesOverlap 1 5 100 200

echo "=== validateRange ==="
assert_rc 0 validateRange 5 100 1 200
assert_rc 0 validateRange 1 200 1 200
assert_rc 0 validateRange 5 5 1 200
assert_rc 1 validateRange 200 100 1 200
assert_rc 1 validateRange 0 100 1 200
assert_rc 1 validateRange 5 300 1 200

echo "=== safeQuoteParam ==="
assert_eq "'simple'" "$(safeQuoteParam "simple")" "safeQuoteParam simple"
assert_eq "'O'\"'\"'Reilly'" "$(safeQuoteParam "O'Reilly")" "safeQuoteParam with quotes"
assert_eq "''" "$(safeQuoteParam "")" "safeQuoteParam empty"
assert_eq "'hello world'" "$(safeQuoteParam "hello world")" "safeQuoteParam with space"

echo "=== convertHToRangeIfNeeded ==="
TEST_H=""
convertHToRangeIfNeeded "TEST_H" ; RC=$?
assert_eq "1" "${RC}" "empty -> NO_CHANGE"

TEST_H="100-200"
convertHToRangeIfNeeded "TEST_H" ; RC=$?
assert_eq "1" "${RC}" "valid range -> NO_CHANGE"
assert_eq "100-200" "${TEST_H}" "valid range preserved"

TEST_H="42"
convertHToRangeIfNeeded "TEST_H" ; RC=$?
assert_eq "0" "${RC}" "single value -> CONVERTED"
assert_eq "42-42" "${TEST_H}" "single value -> range"

TEST_H="5"
convertHToRangeIfNeeded "TEST_H" ; RC=$?
assert_eq "0" "${RC}" "min boundary value -> CONVERTED"
assert_eq "5-5" "${TEST_H}" "min boundary -> range"

TEST_H="2147483647"
convertHToRangeIfNeeded "TEST_H" ; RC=$?
assert_eq "0" "${RC}" "max boundary value -> CONVERTED"
assert_eq "2147483647-2147483647" "${TEST_H}" "max boundary -> range"

TEST_H="3"
convertHToRangeIfNeeded "TEST_H" ; RC=$?
assert_eq "2" "${RC}" "below min -> INVALID"

TEST_H="notanumber"
convertHToRangeIfNeeded "TEST_H" ; RC=$?
assert_eq "2" "${RC}" "non-numeric -> INVALID"

TEST_H="200-100"
convertHToRangeIfNeeded "TEST_H" ; RC=$?
assert_eq "2" "${RC}" "reversed range -> INVALID"

echo "=== generateH1AndH2AndH3AndH4Ranges ==="
for ITER in {1..5}; do
	generateH1AndH2AndH3AndH4Ranges

	# Check all ranges are set and within valid bounds
	for H in H1 H2 H3 H4; do
		MIN_VAR="RANDOM_AWG_${H}_MIN"
		MAX_VAR="RANDOM_AWG_${H}_MAX"
		TESTS_RUN=$((TESTS_RUN + 1))
		if [[ -z "${!MIN_VAR}" ]] || [[ -z "${!MAX_VAR}" ]]; then
			TESTS_FAILED=$((TESTS_FAILED + 1))
			echo "  FAIL: ${MIN_VAR} or ${MAX_VAR} not set (iter ${ITER})"
		elif (( ${!MIN_VAR} < 5 )) || (( ${!MAX_VAR} > 2147483647 )) || (( ${!MIN_VAR} > ${!MAX_VAR} )); then
			TESTS_FAILED=$((TESTS_FAILED + 1))
			echo "  FAIL: ${H} range invalid: ${!MIN_VAR}-${!MAX_VAR} (iter ${ITER})"
		else
			TESTS_PASSED=$((TESTS_PASSED + 1))
		fi
	done

	# Check no overlaps between any pair
	PAIRS=("H1 H2" "H1 H3" "H1 H4" "H2 H3" "H2 H4" "H3 H4")
	for PAIR in "${PAIRS[@]}"; do
		read -r A B <<< "${PAIR}"
		A_MIN="RANDOM_AWG_${A}_MIN"
		A_MAX="RANDOM_AWG_${A}_MAX"
		B_MIN="RANDOM_AWG_${B}_MIN"
		B_MAX="RANDOM_AWG_${B}_MAX"
		TESTS_RUN=$((TESTS_RUN + 1))
		if rangesOverlap "${!A_MIN}" "${!A_MAX}" "${!B_MIN}" "${!B_MAX}"; then
			TESTS_FAILED=$((TESTS_FAILED + 1))
			echo "  FAIL: ${A} [${!A_MIN}-${!A_MAX}] overlaps ${B} [${!B_MIN}-${!B_MAX}] (iter ${ITER})"
		else
			TESTS_PASSED=$((TESTS_PASSED + 1))
		fi
	done
done

echo "=== S1/S2 generation constraint ==="
for ITER in {1..20}; do
	generateS1AndS2
	while (( RANDOM_AWG_S1 + 56 == RANDOM_AWG_S2 )) || (( RANDOM_AWG_S2 + 56 == RANDOM_AWG_S1 )); do
		generateS1AndS2
	done
	TESTS_RUN=$((TESTS_RUN + 1))
	if (( RANDOM_AWG_S1 + 56 == RANDOM_AWG_S2 )) || (( RANDOM_AWG_S2 + 56 == RANDOM_AWG_S1 )); then
		TESTS_FAILED=$((TESTS_FAILED + 1))
		echo "  FAIL: S1/S2 constraint violated (S1=${RANDOM_AWG_S1}, S2=${RANDOM_AWG_S2})"
	else
		TESTS_PASSED=$((TESTS_PASSED + 1))
	fi
done

echo "=== S3/S4 generation constraint ==="
for ITER in {1..20}; do
	generateS3AndS4
	while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); do
		generateS3AndS4
	done
	TESTS_RUN=$((TESTS_RUN + 1))
	if (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); then
		TESTS_FAILED=$((TESTS_FAILED + 1))
		echo "  FAIL: S3/S4 constraint violated (S3=${RANDOM_AWG_S3}, S4=${RANDOM_AWG_S4})"
	else
		TESTS_PASSED=$((TESTS_PASSED + 1))
	fi
done

echo "=== serializeParams ==="
# Set all required variables for serialization
SERVER_PUB_IP="198.51.100.1"
SERVER_PUB_NIC="eth0"
SERVER_AWG_NIC="awg0"
SERVER_AWG_IPV4="10.66.66.1"
SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"
SERVER_PORT="51820"
SERVER_PRIV_KEY="test_priv_key"
SERVER_PUB_KEY="test_pub_key"
CLIENT_DNS_1="1.1.1.1"
CLIENT_DNS_2="1.0.0.1"
ALLOWED_IPS="0.0.0.0/0, ::/0"
SERVER_AWG_JC="5"
SERVER_AWG_JMIN="50"
SERVER_AWG_JMAX="1000"
SERVER_AWG_S1="30"
SERVER_AWG_S2="100"
SERVER_AWG_S3="45"
SERVER_AWG_S4="120"
SERVER_AWG_H1="5-100000004"
SERVER_AWG_H2="100000006-200000010"
SERVER_AWG_H3="200000012-300000016"
SERVER_AWG_H4="300000018-400000022"

SERIALIZE_TMP=$(mktemp)
serializeParams "${SERIALIZE_TMP}"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ -s "${SERIALIZE_TMP}" ]]; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: serializeParams produced empty file"
fi

# Verify the serialized file can be sourced and values round-trip
(
	# Source in subshell to avoid polluting current env
	source "${SERIALIZE_TMP}"
	if [[ "${SERVER_PUB_IP}" != "198.51.100.1" ]] || [[ "${SERVER_PORT}" != "51820" ]] || \
	   [[ "${SERVER_AWG_S3}" != "45" ]] || [[ "${SERVER_AWG_H1}" != "5-100000004" ]]; then
		echo "  FAIL: serializeParams round-trip values don't match"
		exit 1
	fi
) && {
	TESTS_RUN=$((TESTS_RUN + 1))
	TESTS_PASSED=$((TESTS_PASSED + 1))
} || {
	TESTS_RUN=$((TESTS_RUN + 1))
	TESTS_FAILED=$((TESTS_FAILED + 1))
}
rm -f "${SERIALIZE_TMP}"

echo "=== formatClientAllowedIPs ==="
assert_eq "0.0.0.0/0, ::/0" "$(formatClientAllowedIPs "0.0.0.0/0,::/0")" "formatClientAllowedIPs adds space after comma"
assert_eq "0.0.0.0/0, ::/0" "$(formatClientAllowedIPs " 0.0.0.0/0, ::/0 ")" "formatClientAllowedIPs trims entries"
assert_eq "0.0.0.0/0, ::/0" "$(formatClientAllowedIPs "0.0.0.0/0,, ::/0,")" "formatClientAllowedIPs drops empty entries"
assert_eq "" "$(formatClientAllowedIPs " , , ")" "formatClientAllowedIPs returns empty for no entries"
assert_eq "0.0.0.0/0" "$(prepareClientAllowedIPs "0.0.0.0/0, ::/0" n)" "prepareClientAllowedIPs strips ipv6 in v4-only mode"
PREP_OUT=""
PREP_RC=0
PREP_OUT="$(prepareClientAllowedIPs "fd00::/8, ::/0" n)" || PREP_RC=$?
assert_eq "1" "${PREP_RC}" "prepareClientAllowedIPs rejects empty v4-only route list"
assert_eq "" "${PREP_OUT}" "prepareClientAllowedIPs emits nothing on empty result"
unset PREP_OUT PREP_RC

# ============================================================
# checkOS tests (Linux Mint support)
# ============================================================
echo "=== checkOS ==="

# Helper: run checkOS with a fake /etc/os-release in a subshell.
# The source builtin is overridden so checkOS reads our fake file
# instead of the real /etc/os-release.
FAKE_OS_DIR=$(mktemp -d)
trap 'rm -rf "${FAKE_OS_DIR}"' EXIT

run_checkOS_with() {
	local FAKE_CONTENT="$1"
	echo "${FAKE_CONTENT}" > "${FAKE_OS_DIR}/os-release"
	(
		# The install script does not use set -u, so disable it in the
		# subshell to match production behaviour (VERSION_ID may be unset).
		set +u
		# Override source builtin to redirect /etc/os-release reads
		source() {
			if [[ "$1" == "/etc/os-release" ]]; then
				builtin source "${FAKE_OS_DIR}/os-release"
			else
				builtin source "$@"
			fi
		}
		checkOS
		# On success, print the normalised OS value so the caller can verify it
		echo "OS=${OS}"
	) 2>&1
}

# Linux Mint 21.1 (Vera) — should succeed and normalise to ubuntu
OUTPUT=$(run_checkOS_with 'ID="linuxmint"
VERSION_ID="21.1"')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "OS=ubuntu"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: checkOS Mint 21.1 should succeed and set OS=ubuntu (rc=${RC}, output: ${OUTPUT})"
fi

# Linux Mint 21 — should succeed
OUTPUT=$(run_checkOS_with 'ID="linuxmint"
VERSION_ID="21"')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "OS=ubuntu"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: checkOS Mint 21 should succeed and set OS=ubuntu (rc=${RC}, output: ${OUTPUT})"
fi

# Linux Mint 22 — should succeed (future version)
OUTPUT=$(run_checkOS_with 'ID="linuxmint"
VERSION_ID="22"')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "OS=ubuntu"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: checkOS Mint 22 should succeed (rc=${RC}, output: ${OUTPUT})"
fi

# Linux Mint 20.3 — too old, should fail
OUTPUT=$(run_checkOS_with 'ID="linuxmint"
VERSION_ID="20.3"')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -ne 0 ]] && echo "${OUTPUT}" | grep -q "not supported"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: checkOS Mint 20.3 should fail (rc=${RC}, output: ${OUTPUT})"
fi

# Linux Mint with missing VERSION_ID — should fail
OUTPUT=$(run_checkOS_with 'ID="linuxmint"')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -ne 0 ]] && echo "${OUTPUT}" | grep -q "VERSION_ID is missing"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: checkOS Mint with missing VERSION_ID should fail (rc=${RC}, output: ${OUTPUT})"
fi

# Ubuntu 24.04 — should still work
OUTPUT=$(run_checkOS_with 'ID="ubuntu"
VERSION_ID="24.04"')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "OS=ubuntu"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: checkOS Ubuntu 24.04 should succeed (rc=${RC}, output: ${OUTPUT})"
fi

# Unsupported distro — should fail
OUTPUT=$(run_checkOS_with 'ID="archlinux"
VERSION_ID="2024.01"')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -ne 0 ]] && echo "${OUTPUT}" | grep -q "aren't running"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: checkOS unsupported distro should fail (rc=${RC}, output: ${OUTPUT})"
fi

echo "=== ensureSupportedInstallDistro ==="

assert_temp_disable_message() {
	local OUTPUT="$1"
	echo "${OUTPUT}" | grep -Eq "temporarily disabled.*RPM-based distributions"
}

OUTPUT=$(OS="fedora"; ensureSupportedInstallDistro 2>&1)
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -ne 0 ]] && assert_temp_disable_message "${OUTPUT}"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureSupportedInstallDistro should block fedora with temporary disable message (rc=${RC}, output: ${OUTPUT})"
fi

OUTPUT=$(OS="almalinux"; ensureSupportedInstallDistro 2>&1)
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -ne 0 ]] && assert_temp_disable_message "${OUTPUT}"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureSupportedInstallDistro should block almalinux with temporary disable message (rc=${RC}, output: ${OUTPUT})"
fi

OUTPUT=$(OS="rocky"; ensureSupportedInstallDistro 2>&1)
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -ne 0 ]] && assert_temp_disable_message "${OUTPUT}"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureSupportedInstallDistro should block rocky with temporary disable message (rc=${RC}, output: ${OUTPUT})"
fi

OUTPUT=$(OS="centos"; ensureSupportedInstallDistro 2>&1)
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && [[ -z "${OUTPUT}" ]]; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureSupportedInstallDistro should not block centos (rc=${RC}, output: ${OUTPUT})"
fi

echo "=== gai_conf_has_active_ipv4_rule ==="
GAI_TEST_FILE="$(mktemp)"
ORIG_GAI_CONF="${GAI_CONF}"
GAI_CONF="${GAI_TEST_FILE}"

printf '%s\n' "# default config" "#precedence ::ffff:0:0/96  100" > "${GAI_TEST_FILE}"
TESTS_RUN=$((TESTS_RUN + 1))
if gai_conf_has_active_ipv4_rule; then
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: commented gai.conf rule should not be treated as active"
else
	TESTS_PASSED=$((TESTS_PASSED + 1))
fi

printf '%s\n' "precedence ::ffff:0:0/96 100" > "${GAI_TEST_FILE}"
TESTS_RUN=$((TESTS_RUN + 1))
if gai_conf_has_active_ipv4_rule; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: active gai.conf rule with single space should be detected"
fi

printf '%s\n' "  precedence   ::ffff:0:0/96  100   # keep" > "${GAI_TEST_FILE}"
TESTS_RUN=$((TESTS_RUN + 1))
if gai_conf_has_active_ipv4_rule; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: active gai.conf rule with variable spacing/comment should be detected"
fi

rm -f "${GAI_TEST_FILE}"
GAI_CONF="${ORIG_GAI_CONF}"

# ============================================================
# ensureAmneziawgKernelModule tests
# ============================================================
echo "=== ensureAmneziawgKernelModule ==="

# Create a temporary mock bin directory for ensureAmneziawgKernelModule tests.
# Each test overrides PATH in a subshell so the function sees mock commands.
MOCK_BIN_DIR=$(mktemp -d)

_make_mock() {
	local CMD="$1"
	local BODY="$2"
	printf '%s\n' '#!/bin/bash' "${BODY}" > "${MOCK_BIN_DIR}/${CMD}"
	chmod +x "${MOCK_BIN_DIR}/${CMD}"
}

# Base mocks shared by all tests
_make_mock "systemctl" 'exit 0'
_make_mock "dkms" 'exit 0'
_make_mock "depmod" 'exit 0'
_make_mock "apt-get" 'exit 0'
_make_mock "dpkg-query" 'echo "unknown ok not-installed"'
_make_mock "dpkg" 'echo "amd64"'
_make_mock "dnf" 'exit 0'
_make_mock "rpm" 'exit 1'
_make_mock "sed" 'exit 0'
_make_mock "tail" 'exit 0'

# Helper: run ensureAmneziawgKernelModule in a subshell with mocked commands.
# $1 = lsmod body, $2 = modprobe body, $3 = find body (optional)
# $4 = OS value (default: ubuntu), $5 = SERVER_AWG_NIC (default: awg0)
run_ensureModule() {
	local LSMOD_BODY="$1"
	local MODPROBE_BODY="$2"
	local FIND_BODY="${3:-exit 0}"
	local TEST_OS="${4:-ubuntu}"
	local TEST_NIC="${5:-awg0}"

	_make_mock "lsmod" "${LSMOD_BODY}"
	_make_mock "modprobe" "${MODPROBE_BODY}"
	_make_mock "find" "${FIND_BODY}"
	# uname mock returns a fixed kernel version
	_make_mock "uname" 'echo "6.8.0-110-generic"'

	(
		set +u +o pipefail
		export PATH="${MOCK_BIN_DIR}:${PATH}"
		OS="${TEST_OS}"
		SERVER_AWG_NIC="${TEST_NIC}"
		# Stub enable_apt_ipv4/disable_apt_ipv4 to avoid touching real system files
		enable_apt_ipv4() { :; }
		disable_apt_ipv4() { :; }
		ensureAmneziawgKernelModule
	) 2>&1
}

# Test 1: module already loaded → fast-path returns immediately
OUTPUT=$(run_ensureModule \
	'echo "amneziawg 12345 0"' \
	'exit 1' \
	'exit 0')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && ! echo "${OUTPUT}" | grep -q "not built"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureAmneziawgKernelModule should fast-path when module loaded (rc=${RC}, output: ${OUTPUT})"
fi

# Test 2: .ko exists but module not loaded → modprobe succeeds → returns success
# Uses a flag file to simulate lsmod seeing the module only after modprobe runs.
# Avoids inline functions with hyphens in names (e.g., apt-get) which is fragile.
MOCK_MODPROBE_FLAG="$(mktemp)"
rm -f "${MOCK_MODPROBE_FLAG}"
# lsmod reports the module only after modprobe has run (flag file exists)
cat > "${MOCK_BIN_DIR}/lsmod" << EOF
#!/bin/bash
if [[ -f "${MOCK_MODPROBE_FLAG}" ]]; then
	echo "amneziawg 12345 0"
else
	echo ""
fi
EOF
chmod +x "${MOCK_BIN_DIR}/lsmod"
# modprobe creates the flag file to signal success, then exits 0
cat > "${MOCK_BIN_DIR}/modprobe" << EOF
#!/bin/bash
touch "${MOCK_MODPROBE_FLAG}"
exit 0
EOF
chmod +x "${MOCK_BIN_DIR}/modprobe"
_make_mock "find" 'echo "/lib/modules/6.8.0-110-generic/amneziawg.ko"'
_make_mock "uname" 'echo "6.8.0-110-generic"'
OUTPUT=$(
	(
		set +u +o pipefail
		export PATH="${MOCK_BIN_DIR}:${PATH}"
		OS="ubuntu"
		SERVER_AWG_NIC="awg0"
		enable_apt_ipv4() { :; }
		disable_apt_ipv4() { :; }
		ensureAmneziawgKernelModule
	) 2>&1)
RC=$?
rm -f "${MOCK_MODPROBE_FLAG}"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && ! echo "${OUTPUT}" | grep -q "Attempting automatic repair"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureAmneziawgKernelModule should load via modprobe when .ko exists (rc=${RC}, output: ${OUTPUT})"
fi

# Test 3: module not loaded, no .ko → full repair path → modprobe succeeds → returns success
OUTPUT=$(run_ensureModule \
	'echo ""' \
	'exit 0' \
	'exit 0')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "Attempting automatic repair"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureAmneziawgKernelModule should attempt repair when module missing (rc=${RC}, output: ${OUTPUT})"
fi

# Test 4: full repair path → modprobe fails → exits with error
OUTPUT=$(run_ensureModule \
	'echo ""' \
	'exit 1' \
	'exit 0')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -ne 0 ]] && echo "${OUTPUT}" | grep -q "could not be loaded"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureAmneziawgKernelModule should exit with error when modprobe fails (rc=${RC}, output: ${OUTPUT})"
fi

# Test 5: repair path on ubuntu shows apt-based manual recovery
OUTPUT=$(run_ensureModule \
	'echo ""' \
	'exit 1' \
	'exit 0' \
	'ubuntu')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if echo "${OUTPUT}" | grep -q 'apt install'; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureAmneziawgKernelModule should show apt recovery on ubuntu (output: ${OUTPUT})"
fi

# Test 6: repair path on fedora shows dnf-based manual recovery
OUTPUT=$(run_ensureModule \
	'echo ""' \
	'exit 1' \
	'exit 0' \
	'fedora')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if echo "${OUTPUT}" | grep -q 'dnf install'; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureAmneziawgKernelModule should show dnf recovery on fedora (output: ${OUTPUT})"
fi

# Test 7: repair path attempts to start awg-quick when not running
_make_mock "systemctl" '
case "$1" in
	is-active) exit 1;;
	start)     exit 0;;
	*)         exit 0;;
esac
'
OUTPUT=$(run_ensureModule \
	'echo ""' \
	'exit 0' \
	'exit 0' \
	'ubuntu' \
	'awg0')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "Starting awg-quick@awg0"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureAmneziawgKernelModule should start awg-quick when not running (rc=${RC}, output: ${OUTPUT})"
fi

# Reset systemctl mock to default
_make_mock "systemctl" 'exit 0'

# Test 8: module already loaded but service inactive → fast-path starts service
_make_mock "systemctl" '
case "$1" in
	is-active) exit 1;;
	start)     exit 0;;
	*)         exit 0;;
esac
'
OUTPUT=$(run_ensureModule \
	'echo "amneziawg 12345 0"' \
	'exit 1' \
	'exit 0' \
	'ubuntu' \
	'awg0')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && echo "${OUTPUT}" | grep -q "Starting awg-quick@awg0"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ensureAmneziawgKernelModule should start awg-quick when module loaded but service inactive (rc=${RC}, output: ${OUTPUT})"
fi

# Reset systemctl mock to default
_make_mock "systemctl" 'exit 0'

rm -rf "${MOCK_BIN_DIR}"

# ============================================================
# writeFirewallRules tests (issue #79: nftables vs iptables)
# ============================================================
echo "=== writeFirewallRules ==="

assert_contains() {  # haystack needle msg
	TESTS_RUN=$((TESTS_RUN + 1))
	if [[ "$1" == *"$2"* ]]; then
		TESTS_PASSED=$((TESTS_PASSED + 1))
	else
		TESTS_FAILED=$((TESTS_FAILED + 1))
		echo "  FAIL: ${3:-assertion} (missing: '$2')"
	fi
}
assert_not_contains() {  # haystack needle msg
	TESTS_RUN=$((TESTS_RUN + 1))
	if [[ "$1" != *"$2"* ]]; then
		TESTS_PASSED=$((TESTS_PASSED + 1))
	else
		TESTS_FAILED=$((TESTS_FAILED + 1))
		echo "  FAIL: ${3:-assertion} (unexpected: '$2')"
	fi
}

# Isolated PATH so `command -v nft`/`iptables` only sees our stubs (the CI runner
# itself ships a real nft, which would otherwise leak into the fallback case).
FW_TMP="$(mktemp -d)"
mkdir -p "${FW_TMP}/bin" "${FW_TMP}/realbin"
for _cmd in grep cut cat bash sed; do
	if _real="$(command -v "${_cmd}" 2>/dev/null)"; then
		ln -sf "${_real}" "${FW_TMP}/realbin/${_cmd}"
	fi
done
unset _cmd _real

SERVER_PORT="51820"
SERVER_PUB_NIC="eth0"
SERVER_AWG_NIC="awg0"
SERVER_AWG_IPV4="10.66.66.1"
SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"

_fw_stub() {  # name body
	printf '%s\n%s\n' '#!/usr/bin/env bash' "$2" > "${FW_TMP}/bin/$1"
	chmod +x "${FW_TMP}/bin/$1"
}
_run_fw() { ( PATH="${FW_TMP}/bin:${FW_TMP}/realbin"; UFW_CONF_PATH="${FW_TMP}/ufw.conf"; export PATH UFW_CONF_PATH; writeFirewallRules ); }

# Backend 1: firewalld active -> firewall-cmd rules.
_fw_stub systemctl '[[ "$*" == "is-active --quiet firewalld" ]] && exit 0; exit 1'
rm -f "${FW_TMP}/bin/nft" "${FW_TMP}/bin/iptables"
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "PostUp = firewall-cmd --add-port 51820/udp" "firewalld: adds port"
assert_contains "${FW_OUT}" "family=ipv4 source address=10.66.66.0/24 masquerade" "firewalld: ipv4 masquerade"
assert_contains "${FW_OUT}" "firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i awg0 -j ACCEPT" "firewalld: allows tunnel-originated forwarding"
assert_contains "${FW_OUT}" "firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i eth0 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "firewalld: allows established return traffic only"
assert_contains "${FW_OUT}" "firewall-cmd --direct --add-rule ipv4 filter FORWARD 1 -i eth0 -o awg0 -j DROP" "firewalld: drops new internet-to-tunnel traffic"
assert_contains "${FW_OUT}" "firewall-cmd --direct --add-rule ipv4 mangle FORWARD 0 -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" "firewalld: clamps MSS on tunnel egress"
assert_contains "${FW_OUT}" "firewall-cmd --direct --remove-rule ipv4 filter FORWARD 1 -i eth0 -o awg0 -j DROP" "firewalld: removes internet-to-tunnel drop"
assert_not_contains "${FW_OUT}" "nft add table" "firewalld: no nft rules"

# Backend 2: firewalld inactive, nft present, iptables nf_tables-backed -> nft rules.
_fw_stub systemctl 'exit 1'
_fw_stub nft 'exit 0'
_fw_stub iptables 'case "$1" in --version) echo "iptables v1.8.10 (nf_tables)";; esac; exit 0'
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "PostUp = nft add table inet awg-awg0" "nft: creates inet table"
assert_contains "${FW_OUT}" "input udp dport 51820 accept" "nft: accepts vpn port"
assert_contains "${FW_OUT}" "postrouting oifname eth0 masquerade" "nft: masquerades via pub nic"
assert_contains "${FW_OUT}" "hook postrouting priority 100" "nft: nat chain at srcnat priority"
assert_contains "${FW_OUT}" "forward oifname awg0 tcp flags '&' '(syn|rst)' == syn tcp option maxseg size set rt mtu" "nft: clamps MSS on tunnel egress"
assert_contains "${FW_OUT}" "forward iifname eth0 oifname awg0 ct state related,established accept" "nft: allows established return traffic only"
assert_contains "${FW_OUT}" "forward iifname eth0 oifname awg0 drop" "nft: drops new internet-to-tunnel traffic"
assert_contains "${FW_OUT}" "PostDown = nft delete table inet awg-awg0" "nft: tears down table"
assert_not_contains "${FW_OUT}" "forward iifname eth0 oifname awg0 accept" "nft: no internet-to-tunnel forward accept"
assert_not_contains "${FW_OUT}" "iptables -" "nft: no legacy iptables rules"
# The MSS clamp carries no verdict, so it must appear before the accept rules
# that would otherwise terminate the forward chain first.
NFT_MSS_LINE="$(printf '%s\n' "${FW_OUT}" | grep -n 'maxseg size set' | head -1 | cut -d: -f1)"
NFT_ACCEPT_LINE="$(printf '%s\n' "${FW_OUT}" | grep -n 'forward iifname awg0 accept' | head -1 | cut -d: -f1)"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ -n "${NFT_MSS_LINE}" && -n "${NFT_ACCEPT_LINE}" && "${NFT_MSS_LINE}" -lt "${NFT_ACCEPT_LINE}" ]]; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: nft MSS clamp must precede forward accept (mss=${NFT_MSS_LINE}, accept=${NFT_ACCEPT_LINE})"
fi

# Backend 3: ufw.service active but UFW disabled -> stay on nft.
_fw_stub systemctl '[[ "$*" == "is-active --quiet ufw" ]] && exit 0; exit 1'
_fw_stub nft 'exit 0'
_fw_stub iptables 'case "$1" in --version) echo "iptables v1.8.10 (nf_tables)";; esac; exit 0'
_fw_stub ufw '[[ "$*" == "status" ]] && echo "Status: inactive"; exit 0'
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "PostUp = nft add table inet awg-awg0" "ufw disabled: uses nft backend"
assert_not_contains "${FW_OUT}" "iptables -I INPUT" "ufw disabled: does not use ufw iptables branch"

# Backend 4: firewalld inactive, UFW enabled by config without an active systemd unit -> UFW-compatible iptables rules.
_fw_stub systemctl 'exit 1'
rm -f "${FW_TMP}/bin/ufw"
printf '%s\n' 'ENABLED=yes' > "${FW_TMP}/ufw.conf"
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "iptables -I INPUT -p udp --dport 51820 -j ACCEPT" "ufw config: uses ufw iptables branch"
assert_not_contains "${FW_OUT}" "nft add table" "ufw config: no native nft table"
rm -f "${FW_TMP}/ufw.conf"

# Backend 5: firewalld inactive, UFW active without an active systemd unit -> UFW-compatible iptables rules.
_fw_stub ufw '[[ "$*" == "status" ]] && echo "Status: active"; exit 0'
_fw_stub ip6tables 'exit 0'
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "iptables -I INPUT -p udp --dport 51820 -j ACCEPT" "ufw: inserts udp accept through iptables"
assert_contains "${FW_OUT}" "iptables -I FORWARD -i awg0 -j ACCEPT" "ufw: allows tunnel-originated forwarding"
assert_contains "${FW_OUT}" "iptables -I FORWARD -i eth0 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "ufw: allows established return traffic only"
assert_contains "${FW_OUT}" "iptables -I FORWARD 2 -i eth0 -o awg0 -j DROP" "ufw: drops new internet-to-tunnel traffic"
assert_contains "${FW_OUT}" "PostDown = iptables -D FORWARD -i eth0 -o awg0 -j DROP" "ufw: removes internet-to-tunnel drop"
assert_contains "${FW_OUT}" "ip6tables -I FORWARD -i eth0 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "ufw: allows established return traffic only (ipv6)"
assert_contains "${FW_OUT}" "ip6tables -I FORWARD 2 -i eth0 -o awg0 -j DROP" "ufw: drops new internet-to-tunnel traffic (ipv6)"
assert_contains "${FW_OUT}" "PostDown = ip6tables -D FORWARD -i eth0 -o awg0 -j DROP" "ufw: removes internet-to-tunnel drop (ipv6)"
assert_contains "${FW_OUT}" "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" "ufw: masquerade rule"
assert_not_contains "${FW_OUT}" "nft add table" "ufw: no native nft table"
assert_not_contains "${FW_OUT}" "-i eth0 -o awg0 -j ACCEPT" "ufw: no internet-to-tunnel forward accept"
rm -f "${FW_TMP}/bin/ip6tables"
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "iptables -I FORWARD 2 -i eth0 -o awg0 -j DROP" "ufw: keeps ipv4 internet-to-tunnel drop without ip6tables"
assert_not_contains "${FW_OUT}" "ip6tables" "ufw: skips ipv6 rules when ip6tables is unavailable"

# Backend 6: firewalld inactive, nft absent -> iptables fallback.
rm -f "${FW_TMP}/bin/ufw" "${FW_TMP}/ufw.conf"
_fw_stub systemctl 'exit 1'
rm -f "${FW_TMP}/bin/nft"
_fw_stub iptables 'case "$1" in --version) echo "iptables v1.8.7 (legacy)";; esac; exit 0'
_fw_stub ip6tables 'exit 0'
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" "iptables: masquerade rule"
assert_contains "${FW_OUT}" "ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" "iptables: ipv6 masquerade rule"
assert_contains "${FW_OUT}" "iptables -I FORWARD -i eth0 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "iptables: allows established return traffic only"
assert_contains "${FW_OUT}" "iptables -I FORWARD 2 -i eth0 -o awg0 -j DROP" "iptables: drops new internet-to-tunnel traffic"
assert_contains "${FW_OUT}" "PostDown = iptables -D FORWARD -i eth0 -o awg0 -j DROP" "iptables: removes internet-to-tunnel drop"
assert_contains "${FW_OUT}" "ip6tables -I FORWARD -i eth0 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "iptables: allows established return traffic only (ipv6)"
assert_contains "${FW_OUT}" "ip6tables -I FORWARD 2 -i eth0 -o awg0 -j DROP" "iptables: drops new internet-to-tunnel traffic (ipv6)"
assert_contains "${FW_OUT}" "PostDown = ip6tables -D FORWARD -i eth0 -o awg0 -j DROP" "iptables: removes internet-to-tunnel drop (ipv6)"
assert_contains "${FW_OUT}" "iptables -t mangle -A FORWARD -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" "iptables: clamps MSS on tunnel egress"
assert_contains "${FW_OUT}" "ip6tables -t mangle -A FORWARD -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" "iptables: clamps MSS on tunnel egress (ipv6)"
assert_contains "${FW_OUT}" "PostDown = iptables -t mangle -D FORWARD -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" "iptables: removes MSS clamp (matches PostUp)"
assert_not_contains "${FW_OUT}" "-i eth0 -o awg0 -j ACCEPT" "iptables: no internet-to-tunnel forward accept"
assert_not_contains "${FW_OUT}" "nft add table" "iptables: no nft rules"
rm -f "${FW_TMP}/bin/ip6tables"
FW_OUT="$(_run_fw)"
assert_not_contains "${FW_OUT}" "ip6tables" "iptables: skips ipv6 rules when ip6tables is unavailable"

# Backend gate: nft present but iptables is legacy-backed -> stay on iptables so we
# don't disturb a host that deliberately uses the legacy backend.
_fw_stub systemctl 'exit 1'
_fw_stub nft 'exit 0'
_fw_stub iptables 'case "$1" in --version) echo "iptables v1.8.7 (legacy)";; esac; exit 0'
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "iptables -t nat -A POSTROUTING" "legacy gate: keeps iptables when backend is legacy"
assert_not_contains "${FW_OUT}" "nft add table" "legacy gate: no nft rules on legacy backend"

# IPv4-only mode (issue #51): no IPv6 firewall rules in any backend.
ENABLE_IPV6=n
# firewalld
_fw_stub systemctl '[[ "$*" == "is-active --quiet firewalld" ]] && exit 0; exit 1'
rm -f "${FW_TMP}/bin/nft" "${FW_TMP}/bin/iptables"
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "family=ipv4 source address=10.66.66.0/24 masquerade" "firewalld v4-only: ipv4 masquerade present"
assert_not_contains "${FW_OUT}" "family=ipv6" "firewalld v4-only: no ipv6 rich rule"
# iptables fallback
_fw_stub systemctl 'exit 1'
rm -f "${FW_TMP}/bin/nft"
_fw_stub iptables 'case "$1" in --version) echo "iptables v1.8.7 (legacy)";; esac; exit 0'
_fw_stub ip6tables 'exit 0'
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" "iptables v4-only: ipv4 masquerade present"
assert_not_contains "${FW_OUT}" "ip6tables" "iptables v4-only: no ip6tables rules"
# UFW path should also avoid ip6tables in IPv4-only mode.
_fw_stub systemctl '[[ "$*" == "is-active --quiet ufw" ]] && exit 0; exit 1'
_fw_stub nft 'exit 0'
_fw_stub iptables 'case "$1" in --version) echo "iptables v1.8.10 (nf_tables)";; esac; exit 0'
_fw_stub ufw '[[ "$*" == "status" ]] && echo "Status: active"; exit 0'
_fw_stub ip6tables 'exit 0'
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" "ufw v4-only: ipv4 masquerade present"
assert_not_contains "${FW_OUT}" "ip6tables" "ufw v4-only: no ip6tables rules"
# nft uses an IPv4-only table when IPv6 is disabled.
rm -f "${FW_TMP}/bin/ufw" "${FW_TMP}/ufw.conf"
_fw_stub systemctl 'exit 1'
_fw_stub nft 'exit 0'
_fw_stub iptables 'case "$1" in --version) echo "iptables v1.8.10 (nf_tables)";; esac; exit 0'
FW_OUT="$(_run_fw)"
assert_contains "${FW_OUT}" "PostUp = nft add table ip awg-awg0" "nft v4-only: emits ipv4-only table"
assert_not_contains "${FW_OUT}" "nft add table inet" "nft v4-only: no dual-family inet table"
assert_contains "${FW_OUT}" "postrouting oifname eth0 masquerade" "nft v4-only: masquerade present"
unset ENABLE_IPV6

rm -rf "${FW_TMP}"
unset FW_TMP FW_OUT

echo "=== stripIPv6FromList ==="
assert_eq "0.0.0.0/0" "$(stripIPv6FromList "0.0.0.0/0,::/0")" "stripIPv6FromList drops ::/0"
assert_eq "10.0.0.0/8,192.168.0.0/16" "$(stripIPv6FromList "10.0.0.0/8,fd00::/8,192.168.0.0/16")" "stripIPv6FromList keeps v4 order, drops v6"
assert_eq "0.0.0.0/0" "$(stripIPv6FromList "0.0.0.0/0")" "stripIPv6FromList no-op on v4-only"
assert_eq "" "$(stripIPv6FromList "::/0")" "stripIPv6FromList empties an all-IPv6 list"
assert_eq "0.0.0.0/0" "$(stripIPv6FromList " 0.0.0.0/0 , ::/0 ")" "stripIPv6FromList trims surrounding whitespace"

echo "=== serverConfigHasIPv6Address ==="
SC_IPV6_TMP="$(mktemp -d)"
cat > "${SC_IPV6_TMP}/dual.conf" <<'EOF'
[Interface]
Address=10.66.66.1/24, fd42:42:42::1/64
EOF
cat > "${SC_IPV6_TMP}/comment.conf" <<'EOF'
[Interface]
Address = 10.66.66.1/24 # converted from fd42:42:42::1/64
EOF
assert_rc 0 serverConfigHasIPv6Address "${SC_IPV6_TMP}/dual.conf"
assert_rc 1 serverConfigHasIPv6Address "${SC_IPV6_TMP}/comment.conf"
rm -rf "${SC_IPV6_TMP}"
unset SC_IPV6_TMP

echo "=== ipv6Available ==="
# Environment-dependent, but it must always exit cleanly with 0 (available) or 1.
ipv6Available; IPV6_AVAIL_RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "${IPV6_AVAIL_RC}" == "0" || "${IPV6_AVAIL_RC}" == "1" ]]; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ipv6Available returned unexpected code ${IPV6_AVAIL_RC}"
fi
unset IPV6_AVAIL_RC

echo "=== nonInteractiveAddClient (IPv4-only vs dual-stack) ==="
# Drive the real client generator with mocked externals and assert that an
# IPv4-only client carries no IPv6 anywhere, while dual-stack still does (#51).
NIAC_BIN="$(mktemp -d)"
cat > "${NIAC_BIN}/awg" <<'EOF'
#!/usr/bin/env bash
case "$1" in
	genkey) echo "PRIVKEY";;
	pubkey) read -r _ 2>/dev/null; echo "PUBKEY";;
	genpsk) echo "PSK";;
	*) exit 0;;
esac
EOF
cat > "${NIAC_BIN}/awg-quick" <<'EOF'
#!/usr/bin/env bash
echo "[Interface]"
EOF
chmod +x "${NIAC_BIN}/awg" "${NIAC_BIN}/awg-quick"

# Run nonInteractiveAddClient in a subshell; echo "<clientconf>|||<serverconf>".
_run_niac() {  # $1=ENABLE_IPV6 (y/n) $2=client name
	local dir; dir="$(mktemp -d)"
	mkdir -p "${dir}/amneziawg"
	printf '%s\n' "[Interface]" "Address = 10.66.66.1/24" "ListenPort = 51820" \
		> "${dir}/amneziawg/awg0.conf"
	(
		PATH="${NIAC_BIN}:${PATH}"; export PATH
		AMNEZIAWG_DIR="${dir}/amneziawg"
		WEB_PANEL_CONFIG_DIR="${dir}/amneziawg/clients"
		SERVER_AWG_NIC="awg0"; SERVER_AWG_IPV4="10.66.66.1"
		SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"; SERVER_PORT="51820"
		SERVER_PUB_IP="198.51.100.1"; SERVER_PUB_KEY="SRVPUB"
		CLIENT_DNS_1="1.1.1.1"; CLIENT_DNS_2=""
		SERVER_AWG_JC=4; SERVER_AWG_JMIN=50; SERVER_AWG_JMAX=1000
		SERVER_AWG_S1=30; SERVER_AWG_S2=100; SERVER_AWG_S3=45; SERVER_AWG_S4=120
		SERVER_AWG_H1="5-10"; SERVER_AWG_H2="11-20"; SERVER_AWG_H3="21-30"; SERVER_AWG_H4="31-40"
		ALLOWED_IPS="0.0.0.0/0,::/0"; ENABLE_IPV6="$1"
		# Neutralize side-effecting helpers for the unit test.
		ensureAmneziawgKernelModule() { :; }
		copyToWebPanelDir() { :; }
		nonInteractiveAddClient "$2" >/dev/null 2>&1
	)
	echo "${dir}/amneziawg/clients/awg0-client-$2.conf|||${dir}/amneziawg/awg0.conf"
}

# Dual-stack: client and server peer keep IPv6.
NIAC_PATHS="$(_run_niac y dsclient)"
NIAC_CC="$(cat "${NIAC_PATHS%%|||*}" 2>/dev/null)"
NIAC_SC_PEER="$(grep '^AllowedIPs' "${NIAC_PATHS##*|||}" 2>/dev/null | tail -1)"
assert_contains "${NIAC_CC}" "/128" "niac dual-stack: client Address keeps IPv6"
assert_contains "${NIAC_SC_PEER}" "/128" "niac dual-stack: server peer keeps IPv6"

# IPv4-only: no IPv6 in the client config or the server peer entry.
NIAC_PATHS="$(_run_niac n v4client)"
NIAC_CC="$(cat "${NIAC_PATHS%%|||*}" 2>/dev/null)"
NIAC_SC_PEER="$(grep '^AllowedIPs' "${NIAC_PATHS##*|||}" 2>/dev/null | tail -1)"
assert_contains "${NIAC_CC}" "Address = 10.66.66.2/32" "niac v4-only: client has IPv4 address"
assert_not_contains "${NIAC_CC}" "::" "niac v4-only: client config has no IPv6"
assert_not_contains "${NIAC_CC}" "/128" "niac v4-only: client config has no /128"
assert_not_contains "${NIAC_SC_PEER}" "/128" "niac v4-only: server peer has no /128"
assert_not_contains "${NIAC_SC_PEER}" "::" "niac v4-only: server peer has no IPv6"
rm -rf "${NIAC_BIN}"
unset NIAC_BIN NIAC_PATHS NIAC_CC NIAC_SC_PEER

echo "=== installKernelHeaders future-upgrade coverage ==="
KERNEL_HEADER_TMP="$(mktemp -d)"
KERNEL_HEADER_LOG="${KERNEL_HEADER_TMP}/apt-get.log"
KERNEL_HEADER_ERR="${KERNEL_HEADER_TMP}/stderr.log"

_mock_debian_kernel_image_source() {
	local EXPECTED_IMAGE="linux-image-${DEB_TEST_KERNEL_VER}${DEB_TEST_IMAGE_SUFFIX:-}"
	local QUERY_PACKAGE="${!#}"

	if [[ -n "${DEB_TEST_META_PACKAGE:-}" ]] && \
			[[ "${QUERY_PACKAGE}" == "${DEB_TEST_META_PACKAGE}" ]] && \
			[[ "$*" == *'${Version}|${db:Status-Want}|${db:Status-Status}|${db:Status-Eflag}'* ]] && \
			[[ -n "${DEB_TEST_INSTALLED_META_VERSION:-}" ]]; then
		printf '%s|%s|installed|ok\n' "${DEB_TEST_INSTALLED_META_VERSION}" \
			"${DEB_TEST_META_WANT:-install}"
		return 0
	fi

	[[ "${QUERY_PACKAGE}" == "${EXPECTED_IMAGE}" ]] || return 1
	if [[ "$*" == *'${source:Package}|${db:Status-Status}|${db:Status-Eflag}'* ]]; then
		[[ -n "${DEB_TEST_SOURCE:-}" ]] || return 1
		printf '%s|%s|%s\n' "${DEB_TEST_SOURCE}" \
			"${DEB_TEST_STATUS:-installed}" "${DEB_TEST_ERROR_FLAG:-ok}"
	elif [[ "$*" == *'${Version}|${db:Status-Status}|${db:Status-Eflag}'* ]]; then
		printf '%s|%s|%s\n' "${DEB_TEST_IMAGE_VERSION:-1.0}" \
			"${DEB_TEST_STATUS:-installed}" "${DEB_TEST_ERROR_FLAG:-ok}"
	else
		return 1
	fi
}

# A successful version-specific install must not short-circuit the Debian
# architecture meta-package needed by the next kernel upgrade (#98).
(
	OS=debian
	DEB_TEST_KERNEL_VER='6.12.38+deb13-amd64'
	DEB_TEST_SOURCE='linux-signed-amd64'
	dpkg() { printf '%s\n' amd64; }
	apt-cache() { return 1; }
	dpkg-query() { _mock_debian_kernel_image_source "$@"; }
	apt-get() { printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"; return 0; }
	installKernelHeaders "${DEB_TEST_KERNEL_VER}"
) >/dev/null
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" "install -y linux-headers-6.12.38+deb13-amd64" "kernel headers: installs the running Debian kernel package"
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" "install -y linux-headers-amd64" "kernel headers: installs the Debian architecture meta-package"
assert_eq "2" "$(wc -l < "${KERNEL_HEADER_LOG}" | tr -d ' ')" "kernel headers: successful Debian path needs exactly current and meta packages"

# Debian backports shares rolling meta-package names with stable, but its lower
# APT priority means the suite must be preserved with an explicit version.
: > "${KERNEL_HEADER_LOG}"
DEBIAN_BACKPORT_RDEPENDS_OUTPUT="$(
	(
		OS=debian
		DEB_TEST_KERNEL_VER='6.12.27+bpo-amd64'
		DEB_TEST_SOURCE='linux-signed-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.27-1~bpo12+1'
		dpkg() { printf '%s\n' amd64; }
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		apt-cache() {
			case "$1" in
				rdepends)
					printf '%s\n' \
						'linux-headers-6.12.27+bpo-amd64' \
						'Reverse Depends:' \
						'  linux-headers-amd64'
					;;
				madison)
					case "$2" in
						linux-image-6.12.27+bpo-amd64)
							printf '%s\n' ' linux-image-6.12.27+bpo-amd64 | 6.12.27-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
							;;
						linux-headers-amd64)
							printf '%s\n' \
								' linux-headers-amd64 | 6.1.153-1 | http://deb.debian.org/debian bookworm/main amd64 Packages' \
								' linux-headers-amd64 | 6.12.95-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
							;;
						*) return 1 ;;
					esac
					;;
				*) return 1 ;;
			esac
		}
		apt-get() { printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"; return 0; }
		installKernelHeaders "${DEB_TEST_KERNEL_VER}"
	) 2>&1
)"
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" 'install -y linux-headers-6.12.27+bpo-amd64' "kernel headers: backports path installs the running ABI headers"
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" 'install -y linux-headers-amd64=6.12.95-1~bpo12+1' "kernel headers: reverse dependencies retain the explicit backports meta version"
assert_eq '0' "$(grep -Fxc 'install -y linux-headers-amd64' "${KERNEL_HEADER_LOG}")" "kernel headers: reverse dependencies never install the unqualified shared Debian meta"
assert_not_contains "${DEBIAN_BACKPORT_RDEPENDS_OUTPUT}" 'Could not determine a safe rolling kernel header meta-package' "kernel headers: resolved backports version emits no rolling-header warning"

# The provenance fallback must apply the same version qualification when the
# running ABI has aged out of APT reverse dependencies. Modern backports ABIs
# use +debN names, so detection comes from the installed binary version.
: > "${KERNEL_HEADER_LOG}"
DEBIAN_BACKPORT_FALLBACK_OUTPUT="$(
	(
		OS=debian
		DEB_TEST_KERNEL_VER='6.12.90+deb12-cloud-arm64'
		DEB_TEST_SOURCE='linux'
		DEB_TEST_IMAGE_SUFFIX='-unsigned'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12+1'
		dpkg() { printf '%s\n' arm64; }
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		apt-cache() {
			case "$1" in
				rdepends) return 1 ;;
				madison)
					case "$2" in
						linux-image-6.12.90+deb12-cloud-arm64-unsigned)
							printf '%s\n' ' linux-image-6.12.90+deb12-cloud-arm64-unsigned | 6.12.90-2~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main arm64 Packages'
							;;
						linux-headers-cloud-arm64)
							printf '%s\n' \
								' linux-headers-cloud-arm64 | 6.1.153-1 | http://deb.debian.org/debian bookworm/main arm64 Packages' \
								' linux-headers-cloud-arm64 | 6.12.95-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main arm64 Packages'
							;;
						*) return 1 ;;
					esac
					;;
				*) return 1 ;;
			esac
		}
		apt-get() { printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"; return 0; }
		installKernelHeaders "${DEB_TEST_KERNEL_VER}"
	) 2>&1
)"
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" 'install -y linux-headers-cloud-arm64=6.12.95-1~bpo12+1' "kernel headers: stale unsigned backports ABI retains its current rolling version"
assert_eq '0' "$(grep -Fxc 'install -y linux-headers-cloud-arm64' "${KERNEL_HEADER_LOG}")" "kernel headers: fallback never installs an unqualified backports cloud meta"
assert_not_contains "${DEBIAN_BACKPORT_FALLBACK_OUTPUT}" 'Could not determine a safe rolling kernel header meta-package' "kernel headers: provenance fallback resolves the backports version"

# Without one safe backports candidate, install only exact running-ABI headers
# and keep the existing future-upgrade warning instead of guessing stable.
: > "${KERNEL_HEADER_LOG}"
DEBIAN_BACKPORT_UNRESOLVED_OUTPUT="$(
	(
		OS=debian
		DEB_TEST_KERNEL_VER='6.12.90+deb12-amd64'
		DEB_TEST_SOURCE='linux-signed-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12+1'
		dpkg() { printf '%s\n' amd64; }
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		apt-cache() {
			case "$1" in
				rdepends) return 1 ;;
				madison)
					case "$2" in
						linux-image-6.12.90+deb12-amd64)
							printf '%s\n' ' linux-image-6.12.90+deb12-amd64 | 6.12.90-2~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
							;;
						linux-headers-amd64)
							printf '%s\n' ' linux-headers-amd64 | 6.1.153-1 | http://deb.debian.org/debian bookworm/main amd64 Packages'
							;;
						*) return 1 ;;
					esac
					;;
				*) return 1 ;;
			esac
		}
		apt-get() { printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"; return 0; }
		installKernelHeaders "${DEB_TEST_KERNEL_VER}"
	) 2>&1
)"
assert_contains "${DEBIAN_BACKPORT_UNRESOLVED_OUTPUT}" "Could not determine a safe rolling kernel header meta-package for '6.12.90+deb12-amd64'" "kernel headers: unavailable backports metadata warns about rolling coverage"
assert_eq 'install -y linux-headers-6.12.90+deb12-amd64' "$(cat "${KERNEL_HEADER_LOG}")" "kernel headers: unresolved backports metadata installs only exact headers"

_debian_ambiguous_backport_meta_spec() {
	(
		DEB_TEST_KERNEL_VER='6.12.90+deb12-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12+1'
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		apt-cache() {
			case "$2" in
				linux-image-6.12.90+deb12-amd64)
					printf '%s\n' ' linux-image-6.12.90+deb12-amd64 | 6.12.90-2~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				linux-headers-amd64)
					printf '%s\n' \
						' linux-headers-amd64 | 6.12.95-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages' \
						' linux-headers-amd64 | 6.12.95-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports-sloppy/main amd64 Packages'
					;;
				*) return 1 ;;
			esac
		}
		getDebianKernelHeaderMetaInstallSpec "${DEB_TEST_KERNEL_VER}" 'linux-headers-amd64'
	)
}
assert_rc 1 _debian_ambiguous_backport_meta_spec

_debian_missing_image_version_meta_spec() {
	(
		dpkg-query() { return 1; }
		apt-cache() { return 1; }
		getDebianKernelHeaderMetaInstallSpec '6.5.0-0.deb12.4-amd64' 'linux-headers-amd64'
	)
}
assert_rc 1 _debian_missing_image_version_meta_spec

_debian_installed_backport_meta_spec() {
	(
		DEB_TEST_KERNEL_VER='6.12.90+deb12-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12+1'
		DEB_TEST_META_PACKAGE='linux-headers-amd64'
		DEB_TEST_INSTALLED_META_VERSION='6.12.95-1~bpo12+1'
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		dpkg() { return 1; }
		apt-cache() {
			case "$2" in
				linux-image-6.12.90+deb12-amd64)
					printf '%s\n' ' linux-image-6.12.90+deb12-amd64 | 6.12.90-2~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				linux-headers-amd64)
					printf '%s\n' ' linux-headers-amd64 | 6.12.95-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				*) return 1 ;;
			esac
		}
		getDebianKernelHeaderMetaInstallSpec "${DEB_TEST_KERNEL_VER}" "${DEB_TEST_META_PACKAGE}"
	)
}
assert_eq 'linux-headers-amd64=6.12.95-1~bpo12+1' "$(_debian_installed_backport_meta_spec)" "kernel headers: an installed backports meta keeps an explicit indexed version"

_debian_held_backport_meta_is_not_claimed_as_rolling() {
	(
		DEB_TEST_KERNEL_VER='6.12.90+deb12-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12+1'
		DEB_TEST_META_PACKAGE='linux-headers-amd64'
		DEB_TEST_INSTALLED_META_VERSION='6.12.95-1~bpo12+1'
		DEB_TEST_META_WANT='hold'
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		dpkg() { return 1; }
		apt-cache() {
			case "$2" in
				linux-image-6.12.90+deb12-amd64)
					printf '%s\n' ' linux-image-6.12.90+deb12-amd64 | 6.12.90-2~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				linux-headers-amd64)
					printf '%s\n' ' linux-headers-amd64 | 6.12.95-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				*) return 1 ;;
			esac
		}
		getDebianKernelHeaderMetaInstallSpec "${DEB_TEST_KERNEL_VER}" "${DEB_TEST_META_PACKAGE}"
	)
}
assert_rc 1 _debian_held_backport_meta_is_not_claimed_as_rolling

_debian_regular_backport_rejects_sloppy_meta() {
	(
		DEB_TEST_KERNEL_VER='6.12.90+deb12-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12+1'
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		apt-cache() {
			case "$2" in
				linux-image-6.12.90+deb12-amd64)
					printf '%s\n' ' linux-image-6.12.90+deb12-amd64 | 6.12.90-2~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				linux-headers-amd64)
					printf '%s\n' ' linux-headers-amd64 | 7.0.9-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports-sloppy/main amd64 Packages'
					;;
				*) return 1 ;;
			esac
		}
		getDebianKernelHeaderMetaInstallSpec "${DEB_TEST_KERNEL_VER}" 'linux-headers-amd64'
	)
}
assert_rc 1 _debian_regular_backport_rejects_sloppy_meta

_debian_newer_installed_meta_is_not_downgraded() {
	(
		DEB_TEST_KERNEL_VER='6.12.90+deb12-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12+1'
		DEB_TEST_META_PACKAGE='linux-headers-amd64'
		DEB_TEST_INSTALLED_META_VERSION='6.12.95-1'
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		dpkg() {
			[[ "$1" == '--compare-versions' ]] && \
				[[ "$2" == '6.12.95-1' ]] && [[ "$3" == 'gt' ]] && \
				[[ "$4" == '6.12.95-1~bpo12+1' ]]
		}
		apt-cache() {
			case "$2" in
				linux-image-6.12.90+deb12-amd64)
					printf '%s\n' ' linux-image-6.12.90+deb12-amd64 | 6.12.90-2~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				linux-headers-amd64)
					printf '%s\n' ' linux-headers-amd64 | 6.12.95-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				*) return 1 ;;
			esac
		}
		getDebianKernelHeaderMetaInstallSpec "${DEB_TEST_KERNEL_VER}" "${DEB_TEST_META_PACKAGE}"
	)
}
assert_rc 1 _debian_newer_installed_meta_is_not_downgraded

_debian_older_stable_meta_upgrades_to_backport() {
	(
		DEB_TEST_KERNEL_VER='6.12.90+deb12-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12+1'
		DEB_TEST_META_PACKAGE='linux-headers-amd64'
		DEB_TEST_INSTALLED_META_VERSION='6.1.153-1'
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		dpkg() { return 1; }
		apt-cache() {
			case "$2" in
				linux-image-6.12.90+deb12-amd64)
					printf '%s\n' ' linux-image-6.12.90+deb12-amd64 | 6.12.90-2~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				linux-headers-amd64)
					printf '%s\n' ' linux-headers-amd64 | 6.12.95-1~bpo12+1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				*) return 1 ;;
			esac
		}
		getDebianKernelHeaderMetaInstallSpec "${DEB_TEST_KERNEL_VER}" "${DEB_TEST_META_PACKAGE}"
	)
}
assert_eq 'linux-headers-amd64=6.12.95-1~bpo12+1' "$(_debian_older_stable_meta_upgrades_to_backport)" "kernel headers: an older stable meta upgrades to the explicit backports track"

_debian_policy_backport_update_meta_spec() {
	(
		DEB_TEST_KERNEL_VER='6.12.90+deb12-amd64'
		DEB_TEST_IMAGE_VERSION='6.12.90-2~bpo12u1'
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		apt-cache() {
			case "$2" in
				linux-image-6.12.90+deb12-amd64)
					printf '%s\n' ' linux-image-6.12.90+deb12-amd64 | 6.12.90-2~bpo12u1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				linux-headers-amd64)
					printf '%s\n' ' linux-headers-amd64 | 6.12.95-1~bpo12u1 | http://deb.debian.org/debian bookworm-backports/main amd64 Packages'
					;;
				*) return 1 ;;
			esac
		}
		getDebianKernelHeaderMetaInstallSpec "${DEB_TEST_KERNEL_VER}" 'linux-headers-amd64'
	)
}
assert_eq 'linux-headers-amd64=6.12.95-1~bpo12u1' "$(_debian_policy_backport_update_meta_spec)" "kernel headers: Debian policy backport update suffix stays on its suite"

# Ubuntu cloud meta-packages should follow the installed kernel track instead
# of installing unrelated generic or differently-versioned headers.
: > "${KERNEL_HEADER_LOG}"
(
	OS=ubuntu
	apt-cache() { return 1; }
	dpkg-query() {
		printf '%s\t%s\n' \
			'linux-image-aws' \
			'install ok installed'
	}
	apt-get() { printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"; return 0; }
	installKernelHeaders "6.8.0-1030-aws"
) >/dev/null 2> "${KERNEL_HEADER_ERR}"
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" "install -y linux-headers-6.8.0-1030-aws" "kernel headers: installs the running Ubuntu AWS kernel package"
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" "install -y linux-headers-aws" "kernel headers: installs the matching Ubuntu AWS meta-package"
assert_not_contains "$(cat "${KERNEL_HEADER_ERR}")" "Could not determine a safe rolling kernel header meta-package" "kernel headers: resolved Ubuntu track emits no rolling-header warning"

# Ambiguous installed tracks must not be guessed, but a successful exact-header
# install must still warn that future kernel upgrades are not covered.
: > "${KERNEL_HEADER_LOG}"
(
	OS=ubuntu
	apt-cache() { return 1; }
	dpkg-query() {
		printf '%s\t%s\n' \
			'linux-image-aws' 'install ok installed' \
			'linux-image-aws-6.8' 'install ok installed'
	}
	apt-get() { printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"; return 0; }
	installKernelHeaders "6.8.0-1051-aws"
) >/dev/null 2> "${KERNEL_HEADER_ERR}"
assert_contains "$(cat "${KERNEL_HEADER_ERR}")" "Could not determine a safe rolling kernel header meta-package for '6.8.0-1051-aws'" "kernel headers: unresolved rolling track warns even when exact headers install"
assert_contains "$(cat "${KERNEL_HEADER_ERR}")" "future kernel upgrades may require installing matching headers manually" "kernel headers: unresolved rolling track explains the future-upgrade risk"
assert_eq "1" "$(grep -Fc "Could not determine a safe rolling kernel header meta-package" "${KERNEL_HEADER_ERR}")" "kernel headers: unresolved rolling track warns exactly once"
assert_eq "install -y linux-headers-6.8.0-1051-aws" "$(cat "${KERNEL_HEADER_LOG}")" "kernel headers: ambiguous Ubuntu tracks install only the exact package"

# Installing a rolling meta-package for a newer ABI must not masquerade as
# usable headers for the older running kernel.
: > "${KERNEL_HEADER_LOG}"
KERNEL_HEADER_OUTPUT="$(
	(
		OS=ubuntu
		getKernelHeaderMetaPackage() { printf '%s\n' 'linux-headers-generic'; }
		kernelHeadersAreAvailableForVersion() { return 1; }
		apt-get() {
			printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"
			[[ "${!#}" == 'linux-headers-generic' ]]
		}
		installKernelHeaders '6.8.0-79-generic'
	) 2>&1
)"
assert_contains "${KERNEL_HEADER_OUTPUT}" "A rolling kernel header meta-package was installed, but headers for the running kernel (6.8.0-79-generic) remain unavailable" "kernel headers: rolling success does not hide missing running-ABI headers"
assert_eq "2" "$(wc -l < "${KERNEL_HEADER_LOG}" | tr -d ' ')" "kernel headers: stale ABI attempts only exact and selected rolling packages"
assert_not_contains "$(cat "${KERNEL_HEADER_LOG}")" "raspberrypi-kernel-headers" "kernel headers: non-Raspberry stale ABI skips the Raspberry fallback"

_raspberry_rolling_header_install() {
	local BUILD_READY="$1"
	(
		OS=debian
		dpkg() { printf '%s\n' arm64; }
		apt-cache() { return 1; }
		kernelHeadersAreAvailableForVersion() { [[ "${BUILD_READY}" == 'yes' ]]; }
		apt-get() { [[ "${!#}" == 'raspberrypi-kernel-headers' ]]; }
		installKernelHeaders '6.1.21-v8+'
	) 2>&1
}
assert_contains "$(_raspberry_rolling_header_install no)" "headers for the running kernel (6.1.21-v8+) remain unavailable" "kernel headers: Raspberry rolling success does not hide missing running-ABI headers"
assert_not_contains "$(_raspberry_rolling_header_install yes)" "remain unavailable" "kernel headers: verified Raspberry build tree avoids a false current-header warning"

_debian_modern_rpi_header_meta() {
	local KERNEL_VER="$1"
	local ARCH="$2"
	(
		OS=debian
		dpkg() { printf '%s\n' "${ARCH}"; }
		apt-cache() { return 1; }
		getKernelHeaderMetaPackage "${KERNEL_VER}"
	)
}
assert_eq 'linux-headers-rpi-v6' "$(_debian_modern_rpi_header_meta '6.6.51+rpt-rpi-v6' armhf)" "kernel headers: modern Raspberry Pi v6 suffix selects its rolling headers"
assert_eq 'linux-headers-rpi-v7' "$(_debian_modern_rpi_header_meta '6.6.51+rpt-rpi-v7' armhf)" "kernel headers: modern Raspberry Pi v7 suffix selects its rolling headers"
assert_eq 'linux-headers-rpi-v7l' "$(_debian_modern_rpi_header_meta '6.6.51+rpt-rpi-v7l' armhf)" "kernel headers: modern Raspberry Pi v7l suffix selects its rolling headers"
assert_eq 'linux-headers-rpi-v8' "$(_debian_modern_rpi_header_meta '6.6.51+rpt-rpi-v8' arm64)" "kernel headers: modern Raspberry Pi v8 suffix selects its rolling headers"
assert_eq 'linux-headers-rpi-2712' "$(_debian_modern_rpi_header_meta '6.1.0-rpi8-rpi-2712' arm64)" "kernel headers: early Bookworm Raspberry Pi 2712 suffix selects its rolling headers"
assert_eq 'linux-headers-rpi-v8-rt' "$(_debian_modern_rpi_header_meta '6.12.34+rpt-rpi-v8-rt' arm64)" "kernel headers: modern Raspberry Pi RT suffix selects its rolling headers"

_debian_unknown_modern_rpi_header_meta() {
	_debian_modern_rpi_header_meta '6.6.51+rpt-rpi-arm64' arm64
}
assert_rc 1 _debian_unknown_modern_rpi_header_meta

_debian_incomplete_modern_rpi_header_meta() {
	_debian_modern_rpi_header_meta '6.6.51+rpt-rpi' arm64
}
assert_rc 1 _debian_incomplete_modern_rpi_header_meta

_debian_incomplete_early_rpi_header_meta() {
	_debian_modern_rpi_header_meta '6.1.0-rpi8-rpi' arm64
}
assert_rc 1 _debian_incomplete_early_rpi_header_meta

_debian_impostor_rpi_header_meta() {
	_debian_modern_rpi_header_meta '6.6.51-acme-rpi-v8' arm64
}
assert_rc 1 _debian_impostor_rpi_header_meta

_debian_legacy_rpi_header_meta() {
	(
		OS=debian
		dpkg() { printf '%s\n' armhf; }
		apt-cache() { return 1; }
		getKernelHeaderMetaPackage '5.15.84-v7l+'
	)
}
assert_eq 'raspberrypi-kernel-headers' "$(_debian_legacy_rpi_header_meta)" "kernel headers: legacy Raspberry Pi suffix selects its rolling headers"

# Modern Raspberry Pi OS tracks must install their matching linux-headers-rpi-*
# meta-package instead of the frozen legacy raspberrypi-kernel-headers package.
: > "${KERNEL_HEADER_LOG}"
MODERN_RPI_HEADER_OUTPUT="$(
	(
		OS=debian
		dpkg() { printf '%s\n' arm64; }
		apt-cache() { return 1; }
		kernelHeadersAreAvailableForVersion() { return 1; }
		apt-get() {
			printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"
			[[ "${!#}" == 'linux-headers-rpi-v8' ]]
		}
		installKernelHeaders '6.6.51+rpt-rpi-v8'
	) 2>&1
)"
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" 'install -y linux-headers-6.6.51+rpt-rpi-v8' "kernel headers: modern Raspberry Pi path attempts the running ABI package"
assert_contains "$(cat "${KERNEL_HEADER_LOG}")" 'install -y linux-headers-rpi-v8' "kernel headers: modern Raspberry Pi path installs its rolling meta-package"
assert_not_contains "$(cat "${KERNEL_HEADER_LOG}")" 'raspberrypi-kernel-headers' "kernel headers: modern Raspberry Pi path skips the legacy header package"
assert_eq '2' "$(wc -l < "${KERNEL_HEADER_LOG}" | tr -d ' ')" "kernel headers: modern Raspberry Pi path attempts only current and rolling packages"
assert_not_contains "${MODERN_RPI_HEADER_OUTPUT}" 'Could not determine a safe rolling kernel header meta-package' "kernel headers: modern Raspberry Pi track resolves without an ambiguity warning"
assert_contains "${MODERN_RPI_HEADER_OUTPUT}" 'headers for the running kernel (6.6.51+rpt-rpi-v8) remain unavailable' "kernel headers: modern Raspberry Pi rolling success still verifies running-ABI headers"

_debian_header_meta_with_source() {
	local KERNEL_VER="$1"
	local ARCH="$2"
	local SOURCE="$3"
	local IMAGE_SUFFIX="${4:-}"
	local STATUS="${5:-installed}"
	local ERROR_FLAG="${6:-ok}"
	(
		OS=debian
		DEB_TEST_KERNEL_VER="${KERNEL_VER}"
		DEB_TEST_SOURCE="${SOURCE}"
		DEB_TEST_IMAGE_SUFFIX="${IMAGE_SUFFIX}"
		DEB_TEST_STATUS="${STATUS}"
		DEB_TEST_ERROR_FLAG="${ERROR_FLAG}"
		dpkg() { printf '%s\n' "${ARCH}"; }
		apt-cache() { return 1; }
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		getKernelHeaderMetaPackage "${KERNEL_VER}"
	)
}

assert_eq 'linux-headers-amd64' "$(_debian_header_meta_with_source '5.10.0-45-amd64' amd64 linux-signed-amd64)" "kernel headers: Debian 11 signed image selects the stock rolling headers"
assert_eq 'linux-headers-6.1-amd64' "$(_debian_header_meta_with_source '6.1.0-0.deb11.48-amd64' amd64 linux-signed-6.1-amd64)" "kernel headers: Debian 11 parallel source preserves its versioned track"
assert_eq 'linux-headers-6.1-rt-armmp' "$(_debian_header_meta_with_source '6.1.0-0.deb11.48-rt-armmp' armhf linux-6.1)" "kernel headers: Debian versioned unsigned source preserves its RT ARM track"
assert_eq 'linux-headers-cloud-arm64' "$(_debian_header_meta_with_source '6.1.0-50-cloud-arm64' arm64 linux -unsigned)" "kernel headers: Debian unsigned image selects its cloud rolling headers"
assert_eq 'linux-headers-amd64' "$(_debian_header_meta_with_source '6.12.27+bpo-amd64' amd64 linux-signed-amd64)" "kernel headers: Debian transitional backport ABI is validated by image provenance"
assert_eq 'linux-headers-arm64-16k' "$(_debian_header_meta_with_source '6.12.90+deb13+1-arm64-16k' arm64 linux -unsigned)" "kernel headers: Debian revision ABI retains the 16K flavor"
assert_eq 'linux-headers-rpi' "$(_debian_header_meta_with_source '6.1.0-50-rpi' armel linux)" "kernel headers: stock Debian RPi image selects its armel rolling headers"
assert_eq 'linux-headers-powerpc64le-64k' "$(_debian_header_meta_with_source '6.12.90+deb13-powerpc64le-64k' ppc64el linux)" "kernel headers: Debian ppc64el 64K image retains its flavor"

_debian_liquorix_header_meta() {
	_debian_header_meta_with_source '6.12.13-1-liquorix-amd64' amd64 linux-liquorix
}
assert_rc 1 _debian_liquorix_header_meta

_debian_liquorix_rt_header_meta() {
	_debian_header_meta_with_source '6.12.13-1-liquorix-rt-amd64' amd64 linux-liquorix
}
assert_rc 1 _debian_liquorix_rt_header_meta

_debian_missing_image_header_meta() {
	_debian_header_meta_with_source '6.1.0-50-amd64' amd64 ''
}
assert_rc 1 _debian_missing_image_header_meta

_debian_removed_image_header_meta() {
	_debian_header_meta_with_source '6.1.0-50-amd64' amd64 linux-signed-amd64 '' config-files
}
assert_rc 1 _debian_removed_image_header_meta

# A third-party exact package may install successfully, but it must never make
# an unrelated stock Debian rolling meta-package look safe.
: > "${KERNEL_HEADER_LOG}"
LIQUORIX_HEADER_OUTPUT="$(
	(
		OS=debian
		DEB_TEST_KERNEL_VER='6.12.13-1-liquorix-amd64'
		DEB_TEST_SOURCE='linux-liquorix'
		dpkg() { printf '%s\n' amd64; }
		apt-cache() { return 1; }
		dpkg-query() { _mock_debian_kernel_image_source "$@"; }
		apt-get() { printf '%s\n' "$*" >> "${KERNEL_HEADER_LOG}"; return 0; }
		installKernelHeaders "${DEB_TEST_KERNEL_VER}"
	) 2>&1
)"
assert_contains "${LIQUORIX_HEADER_OUTPUT}" "Could not determine a safe rolling kernel header meta-package for '6.12.13-1-liquorix-amd64'" "kernel headers: Liquorix install warns that rolling tracking is unresolved"
assert_eq 'install -y linux-headers-6.12.13-1-liquorix-amd64' "$(cat "${KERNEL_HEADER_LOG}")" "kernel headers: Liquorix install attempts only the exact header package"

_debian_cloud_header_meta() {
	_debian_header_meta_with_source '6.12.38+deb13-cloud-amd64' amd64 linux-signed-amd64
}
assert_eq "linux-headers-cloud-amd64" "$(_debian_cloud_header_meta)" "kernel headers: Debian cloud kernels retain their flavor"

_debian_arm64_header_meta() {
	_debian_header_meta_with_source '6.12.38+deb13-arm64' arm64 linux-signed-arm64
}
assert_eq "linux-headers-arm64" "$(_debian_arm64_header_meta)" "kernel headers: Debian arm64 selects its architecture meta-package"

_debian_pve_header_meta() {
	(
		OS=debian
		dpkg() { printf '%s\n' amd64; }
		apt-cache() { return 1; }
		getKernelHeaderMetaPackage '6.8.12-11-pve'
	)
}
assert_rc 1 _debian_pve_header_meta

_debian_rt_i386_header_meta() {
	_debian_header_meta_with_source '6.1.0-49-rt-686-pae' i386 linux-signed-i386
}
assert_eq 'linux-headers-rt-686-pae' "$(_debian_rt_i386_header_meta)" "kernel headers: Debian i386 RT kernels retain the RT flavor"

_ubuntu_hwe_rdepends() {
	printf '%s\n' \
		"linux-headers-6.8.0-90-generic" \
		"Reverse Depends:" \
		"  linux-headers-generic-hwe-22.04-edge" \
		"  linux-headers-generic-hwe-22.04"
}

_ubuntu_edge_hwe_header_meta() {
	(
		OS=ubuntu
		apt-cache() { _ubuntu_hwe_rdepends; }
		# The edge image meta-package may be installed before its matching
		# headers. Preserve that selected track instead of switching to stable.
		dpkg-query() {
			if [[ "${!#}" == 'linux-image-generic-hwe-22.04-edge' ]]; then
				printf '%s\n' 'install ok installed'
			else
				return 1
			fi
		}
		getKernelHeaderMetaPackage "6.8.0-90-generic"
	)
}
assert_eq "linux-headers-generic-hwe-22.04-edge" "$(_ubuntu_edge_hwe_header_meta)" "kernel headers: installed Ubuntu image meta preserves the edge HWE track"

_ubuntu_virtual_edge_hwe_header_meta() {
	(
		OS=ubuntu
		apt-cache() { _ubuntu_hwe_rdepends; }
		dpkg-query() {
			if [[ "${!#}" == 'linux-image-virtual-hwe-22.04-edge' ]]; then
				printf '%s\n' 'install ok installed'
			else
				return 1
			fi
		}
		getKernelHeaderMetaPackage "6.8.0-90-generic"
	)
}
assert_eq "linux-headers-generic-hwe-22.04-edge" "$(_ubuntu_virtual_edge_hwe_header_meta)" "kernel headers: installed Ubuntu virtual image meta preserves the compatible edge HWE track"

_ubuntu_stable_hwe_header_meta() {
	(
		OS=ubuntu
		apt-cache() { _ubuntu_hwe_rdepends; }
		dpkg-query() { return 1; }
		getKernelHeaderMetaPackage "6.8.0-90-generic"
	)
}
assert_eq "linux-headers-generic-hwe-22.04" "$(_ubuntu_stable_hwe_header_meta)" "kernel headers: APT metadata defaults to the stable Ubuntu HWE track"

_ubuntu_ga_hwe_rdepends() {
	local ORDER="$1"
	printf '%s\n' \
		'linux-headers-5.15.0-25-generic' \
		'Reverse Depends:'
	if [[ "${ORDER}" == 'ga-first' ]]; then
		printf '%s\n' \
			'  linux-headers-generic' \
			'  linux-headers-generic-hwe-22.04'
	else
		printf '%s\n' \
			'  linux-headers-generic-hwe-22.04' \
			'  linux-headers-generic'
	fi
}

_ubuntu_ga_hwe_header_meta() {
	local ORDER="$1"
	local INSTALLED_TRACK="$2"
	(
		OS=ubuntu
		apt-cache() { _ubuntu_ga_hwe_rdepends "${ORDER}"; }
		dpkg-query() {
			case "${INSTALLED_TRACK}:${!#}" in
				ga:linux-image-generic|both:linux-image-generic|hwe:linux-image-generic-hwe-22.04|both:linux-image-generic-hwe-22.04)
					printf '%s\n' 'install ok installed'
					;;
				*) return 1 ;;
			esac
		}
		getAptKernelHeaderMetaPackage '5.15.0-25-generic'
	)
}
assert_rc 1 _ubuntu_ga_hwe_header_meta ga-first none
assert_rc 1 _ubuntu_ga_hwe_header_meta hwe-first none
assert_eq 'linux-headers-generic-hwe-22.04' "$(_ubuntu_ga_hwe_header_meta ga-first hwe)" "kernel headers: installed HWE evidence resolves a shared GA/HWE ABI"
assert_rc 1 _ubuntu_ga_hwe_header_meta ga-first both

_ubuntu_duplicate_hwe_header_meta() {
	(
		OS=ubuntu
		apt-cache() {
			printf '%s\n' \
				'linux-headers-6.8.0-90-generic' \
				'Reverse Depends:' \
				'  linux-headers-generic-hwe-22.04' \
				'  linux-headers-generic-hwe-22.04' \
				'  linux-headers-generic-hwe-22.04-edge'
		}
		dpkg-query() { return 1; }
		getAptKernelHeaderMetaPackage '6.8.0-90-generic'
	)
}
assert_eq 'linux-headers-generic-hwe-22.04' "$(_ubuntu_duplicate_hwe_header_meta)" "kernel headers: duplicate APT output does not create false ambiguity"

_ubuntu_unrelated_edge_header_meta() {
	(
		OS=ubuntu
		apt-cache() {
			printf '%s\n' \
				'linux-headers-6.8.0-90-generic' \
				'Reverse Depends:' \
				'  linux-headers-generic' \
				'  linux-headers-generic-hwe-22.04-edge'
		}
		dpkg-query() { return 1; }
		getAptKernelHeaderMetaPackage '6.8.0-90-generic'
	)
}
assert_rc 1 _ubuntu_unrelated_edge_header_meta

_ubuntu_edge_chain_header_meta() {
	(
		OS=ubuntu
		apt-cache() {
			printf '%s\n' \
				'linux-headers-6.8.0-90-generic' \
				'Reverse Depends:' \
				'  linux-headers-generic-hwe-22.04-edge' \
				'  linux-headers-generic-hwe-22.04-edge-edge'
		}
		dpkg-query() { return 1; }
		getAptKernelHeaderMetaPackage '6.8.0-90-generic'
	)
}
assert_rc 1 _ubuntu_edge_chain_header_meta

_ubuntu_installed_hwe_header_meta() {
	(
		OS=ubuntu
		# Model a successful apt-cache lookup after the older ABI has disappeared
		# from current repository reverse dependencies.
		apt-cache() {
			printf '%s\n' \
				'linux-headers-6.8.0-79-generic' \
				'Reverse Depends:'
		}
		dpkg-query() {
			local ARG
			local SAW_IMAGE_GLOB=0
			local SAW_VIRTUAL_GLOB=0
			for ARG in "$@"; do
				[[ "${ARG}" == 'linux-image-generic*' ]] && SAW_IMAGE_GLOB=1
				[[ "${ARG}" == 'linux-image-virtual*' ]] && SAW_VIRTUAL_GLOB=1
				[[ "${ARG}" == 'linux-generic*' ]] && return 1
			done
			if [[ "${SAW_IMAGE_GLOB}" -ne 1 ]] || [[ "${SAW_VIRTUAL_GLOB}" -ne 1 ]]; then
				return 1
			fi
			printf '%s\t%s\n' \
				'linux-image-generic-hwe-22.04' \
				'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-79-generic"
	)
}
assert_eq "linux-headers-generic-hwe-22.04" "$(_ubuntu_installed_hwe_header_meta)" "kernel headers: installed Ubuntu image meta recovers an older HWE track"

_ubuntu_installed_virtual_hwe_header_meta() {
	(
		OS=ubuntu
		apt-cache() {
			printf '%s\n' \
				'linux-headers-6.8.0-79-generic' \
				'Reverse Depends:'
		}
		dpkg-query() {
			local ARG
			local SAW_VIRTUAL_GLOB=0
			for ARG in "$@"; do
				[[ "${ARG}" == 'linux-image-virtual*' ]] && SAW_VIRTUAL_GLOB=1
				[[ "${ARG}" == 'linux-virtual*' ]] && return 1
			done
			[[ "${SAW_VIRTUAL_GLOB}" -eq 1 ]] || return 1
			printf '%s\t%s\n' \
				'linux-image-virtual-hwe-22.04' \
				'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-79-generic"
	)
}
assert_eq "linux-headers-virtual-hwe-22.04" "$(_ubuntu_installed_virtual_hwe_header_meta)" "kernel headers: installed Ubuntu virtual image meta recovers an older HWE track"

_ubuntu_ambiguous_header_meta() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			printf '%s\t%s\n' \
				'linux-image-generic' 'install ok installed' \
				'linux-image-generic-hwe-22.04' 'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-79-generic"
	)
}
assert_rc 1 _ubuntu_ambiguous_header_meta

_ubuntu_ambiguous_virtual_header_meta() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			printf '%s\t%s\n' \
				'linux-image-generic-hwe-22.04' 'install ok installed' \
				'linux-image-virtual-hwe-22.04' 'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-79-generic"
	)
}
assert_rc 1 _ubuntu_ambiguous_virtual_header_meta

_ubuntu_generic_64k_mismatch() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			printf '%s\t%s\n' \
				'linux-image-generic-64k' \
				'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-79-generic"
	)
}
assert_rc 1 _ubuntu_generic_64k_mismatch

_ubuntu_versioned_azure_header_meta() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			local ARG
			local SAW_AZURE_GLOB=0
			for ARG in "$@"; do
				[[ "${ARG}" == 'linux-image-azure*' ]] && SAW_AZURE_GLOB=1
				[[ "${ARG}" == 'linux-azure*' ]] && return 1
			done
			[[ "${SAW_AZURE_GLOB}" -eq 1 ]] || return 1
			printf '%s\t%s\n' \
				'linux-image-azure-6.8' \
				'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-1062-azure"
	)
}
assert_eq "linux-headers-azure-6.8" "$(_ubuntu_versioned_azure_header_meta)" "kernel headers: installed Ubuntu Azure image meta preserves its versioned track"

_ubuntu_edge_gcp_header_meta() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			printf '%s\t%s\n' \
				'linux-image-gcp-edge' \
				'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-1060-gcp"
	)
}
assert_eq "linux-headers-gcp-edge" "$(_ubuntu_edge_gcp_header_meta)" "kernel headers: installed Ubuntu GCP image meta preserves its edge track"

_ubuntu_ibm_classic_header_meta() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			printf '%s\t%s\n' \
				'linux-image-ibm-classic' \
				'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-1057-ibm"
	)
}
assert_eq "linux-headers-ibm-classic" "$(_ubuntu_ibm_classic_header_meta)" "kernel headers: installed Ubuntu IBM Classic image meta preserves its selected track"

_ubuntu_ambiguous_aws_header_meta() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			printf '%s\t%s\n' \
				'linux-image-aws' 'install ok installed' \
				'linux-image-aws-6.8' 'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-1051-aws"
	)
}
assert_rc 1 _ubuntu_ambiguous_aws_header_meta

_ubuntu_gcp_64k_sibling_not_meta() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			printf '%s\t%s\n' \
				'linux-image-gcp-64k-6.8' \
				'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-1060-gcp"
	)
}
assert_rc 1 _ubuntu_gcp_64k_sibling_not_meta

_ubuntu_aws_support_package_not_meta() {
	(
		OS=ubuntu
		apt-cache() { return 1; }
		dpkg-query() {
			printf '%s\t%s\n' \
				'linux-aws-6.8-headers-6.8.0-1051' \
				'install ok installed'
		}
		getKernelHeaderMetaPackage "6.8.0-1051-aws"
	)
}
assert_rc 1 _ubuntu_aws_support_package_not_meta

_debian_ppc64el_header_meta() {
	_debian_header_meta_with_source '6.12.38+deb13-powerpc64le' ppc64el linux
}
assert_eq "linux-headers-powerpc64le" "$(_debian_ppc64el_header_meta)" "kernel headers: Debian ppc64el maps to its kernel flavor"

_debian_arm64_16k_header_meta() {
	_debian_header_meta_with_source '6.12.38+deb13-arm64-16k' arm64 linux -unsigned
}
assert_eq "linux-headers-arm64-16k" "$(_debian_arm64_16k_header_meta)" "kernel headers: Debian arm64-16k retains its flavor"

rm -rf "${KERNEL_HEADER_TMP}"
unset KERNEL_HEADER_TMP KERNEL_HEADER_LOG KERNEL_HEADER_ERR

echo ""
echo "=========================================="
echo "Results: ${TESTS_PASSED}/${TESTS_RUN} passed, ${TESTS_FAILED} failed"
echo "=========================================="

if (( TESTS_FAILED > 0 )); then
	exit 1
fi
