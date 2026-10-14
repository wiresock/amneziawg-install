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

echo "=== optional client MTU persistence ==="
MTU_PARAMS_DIR="$(mktemp -d)"
MTU_PARAMS="${MTU_PARAMS_DIR}/params"
for MTU_VALUE in '' 1280 1380 65535; do
	CLIENT_MTU="${MTU_VALUE}" serializeParams "${MTU_PARAMS}"
	assert_eq "${MTU_VALUE}" "$(unset CLIENT_MTU; source "${MTU_PARAMS}"; printf '%s' "${CLIENT_MTU-missing}")" "MTU round-trip: '${MTU_VALUE}'"
done
# Exercise the real privileged allow-list, with only its params path redirected.
MTU_SAFE_PARAMS="$(
	# Load all helper functions without dispatching main (which requires root).
	# Only the fixed config root changes; real filtering and file checks run.
	source <(sed -e '$d' -e "s|^readonly AWG_CONFIG_ROOT=.*|readonly AWG_CONFIG_ROOT='${MTU_PARAMS_DIR}'|" \
		"${PROJECT_ROOT}/amneziawg-web/scripts/amneziawg-web-privileged")
	emit_safe_params
)"
assert_eq "CLIENT_MTU='65535'" "$(printf '%s\n' "${MTU_SAFE_PARAMS}" | grep '^CLIENT_MTU=')" "web helper exposes client MTU"
assert_eq 0 "$(printf '%s\n' "${MTU_SAFE_PARAMS}" | grep -c '^SERVER_PRIV_KEY=' || true)" "web helper keeps server private key hidden"

# Legacy params must not inherit CLIENT_MTU from the process environment.
_check_loaded_mtu() (
	local dir; dir="$(mktemp -d)"
	trap 'rm -rf "${dir}"' EXIT
	AMNEZIAWG_DIR="${dir}"
	CLIENT_MTU=1380 serializeParams "${dir}/params" || exit 1
	case "$1" in
		legacy|legacy-state) sed -i '/^CLIENT_MTU=/d' "${dir}/params";;
		invalid) printf "CLIENT_MTU='1279'\n" >>"${dir}/params";;
	esac
	printf '[Interface]\nAddress = 10.66.66.1/24\n' >"${dir}/awg0.conf"
	# This suite is unprivileged; fake ownership only, retaining real mode checks.
	stat() { if [[ "$1" == -c && "$2" == %u ]]; then echo 0; else command stat "$@"; fi; }
	CLIENT_MTU=1420
	validateParamsFile >/dev/null || exit 1
	if [[ "$1" == legacy-state ]]; then
		local before; before="$(awgParamsStateDigest)"
		serializeParams "${dir}/params" || exit 1
		validateParamsFile >/dev/null || exit 1
		[[ "$(awgParamsStateDigest)" == "${before}" ]] || exit 1
		printf stable
		return
	fi
	printf '%s' "${CLIENT_MTU:-}"
)
for MTU_LOAD_CASE in valid legacy legacy-state; do
	MTU_RC=0
	MTU_LOADED="$(_check_loaded_mtu "${MTU_LOAD_CASE}")" || MTU_RC=$?
	assert_eq 0 "${MTU_RC}" "${MTU_LOAD_CASE}: MTU loading fixture succeeds"
	case "${MTU_LOAD_CASE}" in
		valid) assert_eq 1380 "${MTU_LOADED}" "load persisted client MTU";;
		legacy) assert_eq '' "${MTU_LOADED}" "legacy params clear environment MTU";;
		legacy-state) assert_eq stable "${MTU_LOADED}" "legacy params keep transaction state after serialization";;
	esac
done
unset MTU_LOAD_CASE MTU_LOADED
MTU_RC=0
_check_loaded_mtu invalid >/dev/null 2>&1 || MTU_RC=$?
assert_eq 1 "${MTU_RC}" "load rejects invalid persisted client MTU"
MTU_RC=0
( CLIENT_MTU=1279 AUTO_INSTALL=y installQuestions ) >/dev/null 2>&1 || MTU_RC=$?
assert_eq 1 "${MTU_RC}" "automatic install rejects invalid MTU"
_check_install_mtu() (
	local mode="$1" value="$2" dir answers
	dir="$(mktemp -d)"
	trap 'rm -rf "${dir}"' EXIT
	# Only host discovery is mocked; all prompts, validation and persistence run.
	detectPublicIPv4() { echo 198.51.100.1; }
	ip() { echo 'default via 198.51.100.254 dev eth0'; }
	ipv6Available() { return 1; }
	AUTO_INSTALL="${mode}"
	CLIENT_MTU=""
	if [[ "${mode}" == y ]]; then CLIENT_MTU="${value}"; fi
	answers=$'198.51.100.1\neth0\nawg0\n10.66.66.1\nn\n51820\n1.1.1.1\n\n'
	answers+="${value}"$'\n0.0.0.0/0\n4\n50\n1000\n30\n100\n45\n120\n5-10\n11-20\n21-30\n31-40\ny\n'
	installQuestions >"${dir}/stdout" 2>"${dir}/stderr" <<<"${answers}" || exit 1
	serializeParams "${dir}/params" || exit 1
	unset CLIENT_MTU
	source "${dir}/params"
	printf '%s|%s' "${CLIENT_MTU:-}" "$(grep -c 'CLIENT_MTU must' "${dir}/stderr" || true)"
)
assert_eq '1380|0' "$(_check_install_mtu y 1380)" "automatic install persists requested MTU"
assert_eq '1380|0' "$(_check_install_mtu n 1380)" "interactive install accepts valid MTU on first attempt"
assert_eq '|0' "$(_check_install_mtu n '')" "interactive install accepts omitted MTU"
assert_eq '1380|1' "$(_check_install_mtu n $'1279\n1380')" "interactive install retries invalid MTU and persists correction"
for MTU_WHITESPACE in ' 1380' '1380 ' '   ' $'\t1380\t' $'\t'; do
	MTU_RC=0
	MTU_PROMPT_RESULT="$(_check_install_mtu n "${MTU_WHITESPACE}"$'\n1380')" || MTU_RC=$?
	assert_eq 0 "${MTU_RC}" "interactive MTU whitespace fixture succeeds"
	assert_eq '1380|1' "${MTU_PROMPT_RESULT}" "interactive install rejects MTU whitespace before accepting correction"
done
unset MTU_WHITESPACE MTU_PROMPT_RESULT
printf 'unchanged\n' >"${MTU_PARAMS}"
MTU_RC=0
CLIENT_MTU=1279 serializeParams "${MTU_PARAMS}" 2>/dev/null || MTU_RC=$?
assert_eq 1 "${MTU_RC}" "invalid MTU refuses serialization"
assert_eq unchanged "$(cat "${MTU_PARAMS}")" "invalid MTU does not truncate params"
rm -f "${MTU_PARAMS}"
rmdir "${MTU_PARAMS_DIR}"
unset MTU_PARAMS MTU_PARAMS_DIR MTU_VALUE MTU_RC MTU_SAFE_PARAMS

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
# $6 = service-start mode (default: 1)
run_ensureModule() {
	local LSMOD_BODY="$1"
	local MODPROBE_BODY="$2"
	local FIND_BODY="${3:-exit 0}"
	local TEST_OS="${4:-ubuntu}"
	local TEST_NIC="${5:-awg0}"
	local START_AWG_QUICK="${6:-1}"

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
		# The compiler regression exercises the real patch in a temporary tree.
		patchAwgDkmsUdpTunnelCompat() { echo 0; }
		ensureAmneziawgKernelModule "${START_AWG_QUICK}"
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
		patchAwgDkmsUdpTunnelCompat() { echo 0; }
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

# Test 9: module-only preparation preserves an inactive service
_make_mock "systemctl" '
case "$1" in
	is-active) exit 1;;
	start)     echo "unexpected service start"; exit 1;;
	*)         exit 0;;
esac
'
OUTPUT=$(run_ensureModule \
	'echo "amneziawg 12345 0"' \
	'exit 1' \
	'exit 0' \
	'ubuntu' \
	'awg0' \
	'0')
RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ ${RC} -eq 0 ]] && \
	! echo "${OUTPUT}" | grep -q "Starting awg-quick@awg0" && \
	! echo "${OUTPUT}" | grep -q "unexpected service start"; then
	TESTS_PASSED=$((TESTS_PASSED + 1))
else
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: module-only preparation must preserve an inactive service (rc=${RC}, output: ${OUTPUT})"
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

# Without an installed panel, the CLI uses the client directory as its lock so a
# same-name recreate cannot land between server removal and config cleanup.
NIAC_LOCK_DIR="$(mktemp -d)"
NIAC_ORIGINAL_WEB_PANEL_CONFIG_DIR="${WEB_PANEL_CONFIG_DIR}"
NIAC_ORIGINAL_WEB_PANEL_ENV_FILE="${WEB_PANEL_ENV_FILE}"
NIAC_ORIGINAL_WEB_PANEL_SYSTEMD_UNIT="${WEB_PANEL_SYSTEMD_UNIT}"
NIAC_WEB_ROOT="$(mktemp -d)"
WEB_PANEL_CONFIG_DIR="${NIAC_LOCK_DIR}"
WEB_PANEL_ENV_FILE="${NIAC_WEB_ROOT}/missing-env.conf"
WEB_PANEL_SYSTEMD_UNIT="${NIAC_WEB_ROOT}/missing.service"
exec {NIAC_HELD_LOCK_FD}< "${NIAC_LOCK_DIR}"
flock -xn "${NIAC_HELD_LOCK_FD}"
_client_lock_must_be_busy() {
	acquireClientLifecycleLock >/dev/null 2>&1
}
assert_rc 1 _client_lock_must_be_busy
exec {NIAC_HELD_LOCK_FD}>&-
assert_rc 0 acquireClientLifecycleLock
assert_eq "" "$(find "${NIAC_LOCK_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" \
	"client lifecycle locking creates no service-writable lock file"
if [[ -n "${CLIENT_LIFECYCLE_LOCK_FD:-}" ]]; then
	exec {CLIENT_LIFECYCLE_LOCK_FD}>&-
fi
NIAC_LOCK_LINK="${NIAC_LOCK_DIR}-link"
ln -s "${NIAC_LOCK_DIR}" "${NIAC_LOCK_LINK}"
WEB_PANEL_CONFIG_DIR="${NIAC_LOCK_LINK}"
assert_rc 1 acquireClientLifecycleLock
rm -f "${NIAC_LOCK_LINK}"

# Custom web installer paths must resolve through the service unit and env file.
# The database directory is the stable lifecycle inode even when the configured
# client directory does not exist yet.
NIAC_CUSTOM_CONFIG_DIR="${NIAC_WEB_ROOT}/custom-clients"
NIAC_CUSTOM_STATE_DIR="${NIAC_WEB_ROOT}/custom-state"
mkdir -p "${NIAC_CUSTOM_STATE_DIR}"
cat > "${NIAC_WEB_ROOT}/custom.env" <<EOF
AWG_WEB_DB=sqlite://${NIAC_CUSTOM_STATE_DIR}/awg-web.db
AWG_CONFIG_DIR=${NIAC_CUSTOM_CONFIG_DIR}
EOF
cat > "${NIAC_WEB_ROOT}/amneziawg-web.service" <<EOF
[Service]
Environment=AWG_WEB_DB=${NIAC_LOCK_DIR}/ignored.db
Environment=AWG_CONFIG_DIR=${NIAC_LOCK_DIR}/ignored-clients
EnvironmentFile=${NIAC_WEB_ROOT}/custom.env
EOF
WEB_PANEL_CONFIG_DIR="${NIAC_LOCK_DIR}"
WEB_PANEL_SYSTEMD_UNIT="${NIAC_WEB_ROOT}/amneziawg-web.service"
assert_eq "${NIAC_CUSTOM_CONFIG_DIR}" "$(resolveWebPanelConfigDir)" \
	"client config directory follows the web service EnvironmentFile"
assert_eq "${NIAC_CUSTOM_STATE_DIR}" "$(resolveClientLifecycleLockDir)" \
	"client lifecycle directory follows the configured database"
exec {NIAC_HELD_LOCK_FD}< "${NIAC_CUSTOM_STATE_DIR}"
flock -xn "${NIAC_HELD_LOCK_FD}"
assert_rc 1 _client_lock_must_be_busy
exec {NIAC_HELD_LOCK_FD}>&-
assert_eq "false" "$([[ -e "${NIAC_CUSTOM_CONFIG_DIR}" ]] && echo true || echo false)" \
	"lifecycle locking does not create a missing client directory"

rm -rf "${NIAC_CUSTOM_STATE_DIR}"
assert_rc 1 acquireClientLifecycleLock
assert_eq "false" "$([[ -e "${NIAC_CUSTOM_STATE_DIR}" ]] && echo true || echo false)" \
	"root CLI does not recreate a missing panel state directory"

# Inline unit settings are supported too. Relative database paths resolve from
# WorkingDirectory, and an unreferenced environment file is ignored.
NIAC_INLINE_WORK_DIR="${NIAC_WEB_ROOT}/inline-work"
NIAC_INLINE_STATE_DIR="${NIAC_INLINE_WORK_DIR}/relative-state"
NIAC_INLINE_CONFIG_DIR="${NIAC_WEB_ROOT}/inline-clients"
mkdir -p "${NIAC_INLINE_STATE_DIR}"
WEB_PANEL_ENV_FILE="${NIAC_WEB_ROOT}/custom.env"
cat > "${NIAC_WEB_ROOT}/amneziawg-web.service" <<EOF
[Service]
WorkingDirectory=${NIAC_INLINE_WORK_DIR}
Environment="AWG_WEB_DB=sqlite:relative-state/awg-web.db"
Environment=AWG_CONFIG_DIR=${NIAC_INLINE_CONFIG_DIR}
EOF
assert_eq "${NIAC_INLINE_STATE_DIR}" "$(resolveClientLifecycleLockDir)" \
	"inline relative database path resolves from WorkingDirectory"
assert_eq "${NIAC_INLINE_CONFIG_DIR}" "$(resolveWebPanelConfigDir)" \
	"inline client config directory is discovered"
exec {NIAC_HELD_LOCK_FD}< "${NIAC_INLINE_STATE_DIR}"
flock -xn "${NIAC_HELD_LOCK_FD}"
assert_rc 1 _client_lock_must_be_busy
exec {NIAC_HELD_LOCK_FD}>&-

# PID 1's normalized properties must win over the base fragment. This models a
# drop-in that resets Environment=/EnvironmentFile= before replacing the web
# paths; systemd has already applied those reset and filename-ordering rules.
NIAC_EFFECTIVE_WORK_DIR="${NIAC_WEB_ROOT}/effective-work"
NIAC_EFFECTIVE_STATE_DIR="${NIAC_EFFECTIVE_WORK_DIR}/effective-state"
NIAC_EFFECTIVE_CONFIG_DIR="${NIAC_WEB_ROOT}/effective-clients"
NIAC_EXEC_STATE_DIR="${NIAC_EFFECTIVE_WORK_DIR}/exec-state"
NIAC_EXEC_CONFIG_DIR="${NIAC_WEB_ROOT}/exec-clients"
NIAC_EFFECTIVE_EXEC_START="{ path=/usr/local/bin/amneziawg-web ; argv[]=/usr/local/bin/amneziawg-web --auth-enabled --database-url=sqlite:exec-state/awg-web.db --auth-secure-cookie --config-dir ${NIAC_EXEC_CONFIG_DIR} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
NIAC_EFFECTIVE_ENV_FIRST="${NIAC_WEB_ROOT}/effective-first.env"
NIAC_EFFECTIVE_ENV_LAST="${NIAC_WEB_ROOT}/effective-last.env"
mkdir -p "${NIAC_EFFECTIVE_STATE_DIR}" "${NIAC_EXEC_STATE_DIR}" \
	"${NIAC_WEB_ROOT}/amneziawg-web.service.d"
cat > "${NIAC_EFFECTIVE_ENV_FIRST}" <<EOF
AWG_WEB_DB=sqlite:ignored-state/awg-web.db
AWG_CONFIG_DIR=${NIAC_LOCK_DIR}/ignored-from-first-file
EOF
cat > "${NIAC_EFFECTIVE_ENV_LAST}" <<EOF
AWG_WEB_DB=sqlite:effective-state/awg-web.db
AWG_CONFIG_DIR=${NIAC_EFFECTIVE_CONFIG_DIR}
EOF
cat > "${NIAC_WEB_ROOT}/amneziawg-web.service" <<EOF
[Service]
WorkingDirectory=${NIAC_INLINE_WORK_DIR}
Environment=AWG_WEB_DB=${NIAC_LOCK_DIR}/ignored-from-fragment.db
EnvironmentFile=${NIAC_WEB_ROOT}/custom.env
EOF
cat > "${NIAC_WEB_ROOT}/amneziawg-web.service.d/90-paths.conf" <<EOF
[Service]
WorkingDirectory=${NIAC_EFFECTIVE_WORK_DIR}
Environment=
Environment=AWG_WEB_DB=${NIAC_LOCK_DIR}/ignored-from-drop-in.db
EnvironmentFile=
EnvironmentFile=${NIAC_EFFECTIVE_ENV_FIRST}
EnvironmentFile=${NIAC_EFFECTIVE_ENV_LAST}
EOF
systemctl() {
	local argument property=""
	for argument in "$@"; do
		case "${argument}" in
			--property=*) property="${argument#--property=}" ;;
		esac
	done
	case "${property}" in
		LoadState) printf '%s\n' "loaded" ;;
		FragmentPath) printf '%s\n' "${WEB_PANEL_SYSTEMD_UNIT}" ;;
		EnvironmentFiles)
			printf '%s (ignore_errors=no) %s (ignore_errors=no)\n' \
				"${NIAC_EFFECTIVE_ENV_FIRST}" "${NIAC_EFFECTIVE_ENV_LAST}"
			;;
		Environment) printf 'AWG_WEB_DB=%s/ignored-effective.db\n' "${NIAC_LOCK_DIR}" ;;
		WorkingDirectory) printf '%s\n' "${NIAC_EFFECTIVE_WORK_DIR}" ;;
		ExecStart) printf '%s\n' "${NIAC_EFFECTIVE_EXEC_START}" ;;
		*) return 1 ;;
	esac
}
assert_eq "$(printf '0\t%s\n0\t%s' "${NIAC_EFFECTIVE_ENV_FIRST}" "${NIAC_EFFECTIVE_ENV_LAST}")" \
	"$(resolveWebPanelEnvFiles)" \
	"single-line systemd EnvironmentFiles output preserves every ordered tuple"
assert_eq "${NIAC_EFFECTIVE_CONFIG_DIR}" "$(readWebPanelSetting AWG_CONFIG_DIR)" \
	"later effective EnvironmentFile values take precedence before CLI overrides"
assert_eq "${NIAC_EXEC_STATE_DIR}" "$(resolveClientLifecycleLockDir)" \
	"effective ExecStart database override wins over environment and base unit values"
assert_eq "${NIAC_EXEC_CONFIG_DIR}" "$(resolveWebPanelConfigDir)" \
	"effective ExecStart handles boolean flags and overrides ordered EnvironmentFile values"
exec {NIAC_HELD_LOCK_FD}< "${NIAC_EXEC_STATE_DIR}"
flock -xn "${NIAC_HELD_LOCK_FD}"
assert_rc 1 _client_lock_must_be_busy
exec {NIAC_HELD_LOCK_FD}>&-
NIAC_EFFECTIVE_EXEC_START="{ path=/usr/local/bin/amneziawg-web ; argv[]=/usr/local/bin/amneziawg-web --config-dir ${NIAC_EXEC_CONFIG_DIR} unexpected ; ignore_errors=no }"
assert_rc 2 resolveWebPanelConfigDir
unset -f systemctl

WEB_PANEL_CONFIG_DIR="${NIAC_ORIGINAL_WEB_PANEL_CONFIG_DIR}"
WEB_PANEL_ENV_FILE="${NIAC_ORIGINAL_WEB_PANEL_ENV_FILE}"
WEB_PANEL_SYSTEMD_UNIT="${NIAC_ORIGINAL_WEB_PANEL_SYSTEMD_UNIT}"
rm -rf "${NIAC_LOCK_DIR}"
rm -rf "${NIAC_WEB_ROOT}"
unset NIAC_LOCK_DIR NIAC_LOCK_LINK NIAC_CUSTOM_CONFIG_DIR NIAC_CUSTOM_STATE_DIR NIAC_WEB_ROOT
unset NIAC_INLINE_WORK_DIR NIAC_INLINE_STATE_DIR NIAC_INLINE_CONFIG_DIR
unset NIAC_EFFECTIVE_WORK_DIR NIAC_EFFECTIVE_STATE_DIR NIAC_EFFECTIVE_CONFIG_DIR
unset NIAC_EXEC_STATE_DIR NIAC_EXEC_CONFIG_DIR
unset NIAC_EFFECTIVE_EXEC_START
unset NIAC_EFFECTIVE_ENV_FIRST NIAC_EFFECTIVE_ENV_LAST
unset NIAC_ORIGINAL_WEB_PANEL_CONFIG_DIR NIAC_ORIGINAL_WEB_PANEL_ENV_FILE
unset NIAC_ORIGINAL_WEB_PANEL_SYSTEMD_UNIT NIAC_HELD_LOCK_FD
unset -f _client_lock_must_be_busy

# Load the actual backend dispatch and install completion blocks, omitting
# package installation, host configuration writes and backend startup. This
# keeps return propagation under test without installing anything on the host.
_initial_client_install_functions() {
	awk '
		/^function installBoringtunHost\(\)/ {
			bt_start++
			mode = "boringtun"
			print
			print "\tlocal ACTIVE=1"
			next
		}
		/^function installAmneziaWG\(\)/ { kernel_start++; mode = "kernel"; copying = 1 }
		mode == "kernel" && /^\t# Run setup questions first$/ { kernel_gap++; copying = 0 }
		mode == "kernel" && /^\tlocal MODULE_READY=0$/ { kernel_tail++; copying = 1 }
		mode == "boringtun" && /^\tif \(\(ACTIVE\)\); then$/ { bt_tail++; copying = 1 }
		mode != "" {
			if (copying) print
			if ($0 == "}") { ends++; mode = ""; copying = 0 }
		}
		END {
			if (bt_start != 1 || bt_tail != 1 || kernel_start != 1 || kernel_gap != 1 || kernel_tail != 1 || ends != 2)
				exit 1
		}
	' "${PROJECT_ROOT}/amneziawg-install.sh"
}

# Run allocation in a subshell; echo "<clientconf>|||<serverconf>".
_run_niac() {  # $1=ENABLE_IPV6 $2=name $3=params IPv4 $4=extra config $5=mode $6=input $7=interface IPv4 $8=MTU
	local dir rc=0; dir="$(mktemp -d)"
	mkdir -p "${dir}/amneziawg"
	printf '%s\n' "[Interface]" "Address = ${7:-${3:-10.66.66.1}}/24" "ListenPort = 51820" "${4:-}" \
		> "${dir}/amneziawg/awg0.conf"
	cp "${dir}/amneziawg/awg0.conf" "${dir}/server-before.conf"
	(
		PATH="${NIAC_BIN}:${PATH}"; export PATH
		AMNEZIAWG_DIR="${dir}/amneziawg"
		WEB_PANEL_CONFIG_DIR="${dir}/amneziawg/clients"
		WEB_PANEL_ENV_FILE="${dir}/missing-env.conf"
		WEB_PANEL_SYSTEMD_UNIT="${dir}/missing.service"
		SERVER_AWG_NIC="awg0"; SERVER_AWG_IPV4="${3:-10.66.66.1}"
		SERVER_AWG_CONF="${AMNEZIAWG_DIR}/awg0.conf"
		SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"; SERVER_PORT="51820"
		SERVER_PUB_IP="198.51.100.1"; SERVER_PUB_KEY="SRVPUB"
		CLIENT_DNS_1="1.1.1.1"; CLIENT_DNS_2=""
		CLIENT_MTU="${8:-}"
		SERVER_AWG_JC=4; SERVER_AWG_JMIN=50; SERVER_AWG_JMAX=1000
		SERVER_AWG_S1=30; SERVER_AWG_S2=100; SERVER_AWG_S3=45; SERVER_AWG_S4=120
		SERVER_AWG_H1="5-10"; SERVER_AWG_H2="11-20"; SERVER_AWG_H3="21-30"; SERVER_AWG_H4="31-40"
		ALLOWED_IPS="0.0.0.0/0,::/0"; ENABLE_IPV6="$1"
		# Neutralize side-effecting helpers for the unit test.
		loadParams() { :; }
		ensureAwgBackendReady() { :; }
		copyToWebPanelDir() { :; }
		case "${5:-noninteractive}" in
			noninteractive) nonInteractiveAddClient "$2" >"${dir}/stdout" 2>"${dir}/stderr";;
			*)
				mkdir -p "${AMNEZIAWG_DIR}/clients"
				getHomeDirForClient() { echo "${AMNEZIAWG_DIR}/clients"; }
				CLIENT_AWG_IPV6=""
				AUTO_INSTALL=y
				[[ "$5" == interactive ]] && AUTO_INSTALL=n
				case "$5" in
					initial-*)
						local install_functions
						install_functions="$(_initial_client_install_functions)" || exit 1
						unset -f installAmneziaWG installBoringtunHost
						eval "${install_functions}" || exit 1
						ensureSupportedInstallDistro() { :; }
						selectFreshInstallBackend() { :; }
						selectFreshInstallImitation() { :; }
						modprobe() { :; }
						systemctl() { :; }
						AWG_BACKEND="${5#initial-}"
						CREATE_INITIAL_CLIENT=y
						installAmneziaWG >"${dir}/stdout" 2>"${dir}/stderr"
						;;
					*) newClient >"${dir}/stdout" 2>"${dir}/stderr" <<< "${6:-}" ;;
				esac
				;;
		esac
	) || rc=$?
	printf '%s\n' "${rc}" > "${dir}/rc"
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

echo "=== client allocation reserves server IPv4 (#150) ==="
# Exercise both CLI entry points using real allocation and config generation.
# Only key generation/backend operations are mocked; all writes stay in mktemp.
for ALLOC_MODE in noninteractive auto; do
	for ALLOC_IPV6 in n y; do
		NIAC_PATHS="$(_run_niac "${ALLOC_IPV6}" client 10.66.66.2 $'[Peer]\nAllowedIPs = 0.0.0.0/0,::/0' "${ALLOC_MODE}")"
		NIAC_CC="$(cat "${NIAC_PATHS%%|||*}" 2>/dev/null)"
		NIAC_SC_PEER="$(grep '^AllowedIPs' "${NIAC_PATHS##*|||}" | tail -1)"
		assert_contains "${NIAC_CC}" "Address = 10.66.66.3/32" "${ALLOC_MODE} IPv6=${ALLOC_IPV6}: skip server .2"
		assert_contains "${NIAC_SC_PEER}" "AllowedIPs = 10.66.66.3/32" "${ALLOC_MODE} IPv6=${ALLOC_IPV6}: peer uses free .3"
	done
	NIAC_PATHS="$(_run_niac n client 10.66.66.42 $'[Peer]\nAllowedIPs = 10.66.66.2/32' "${ALLOC_MODE}")"
	assert_contains "$(cat "${NIAC_PATHS%%|||*}")" "Address = 10.66.66.3/32" "${ALLOC_MODE}: keep unmarked peer reservation"
	NIAC_PATHS="$(_run_niac n client 10.66.66.2 $'Address = fd42:42:42::1/64, 10.66.66.3/24\nAddress = 10.66.66.4\n[Peer]\nAllowedIPs = 0.0.0.0/0' "${ALLOC_MODE}")"
	assert_contains "$(cat "${NIAC_PATHS%%|||*}")" "Address = 10.66.66.5/32" "${ALLOC_MODE}: reserve every interface address"
done
NIAC_PATHS="$(_run_niac n client 10.66.66.42 '' interactive $'client\n42\n3')"
assert_contains "$(cat "${NIAC_PATHS%%|||*}")" "Address = 10.66.66.3/32" "interactive: reject explicitly selected server .42"
NIAC_PATHS="$(_run_niac n client 10.66.66.2 '' interactive $'client\n02\n3')"
assert_contains "$(cat "${NIAC_PATHS%%|||*}")" "Address = 10.66.66.3/32" "interactive: leading zero cannot bypass server reservation"
for ALLOC_ADDRESSES in '10.66.66.2/24 10.66.66.3/24' $'10.66.66.2\t10.66.66.3'; do
	for ALLOC_MODE in noninteractive auto interactive; do
		NIAC_PATHS="$(_run_niac n client 10.66.66.1 "Address = ${ALLOC_ADDRESSES}" "${ALLOC_MODE}" $'client\n2\n3\n4')"
		assert_contains "$(cat "${NIAC_PATHS%%|||*}")" "Address = 10.66.66.4/32" "${ALLOC_MODE}: reserve whitespace-separated addresses (${ALLOC_ADDRESSES})"
	done
done
unset ALLOC_ADDRESSES
# Initial installation must report failed client creation to its caller and
# suppress the success guidance, for both backends. Also exercise success so
# extraction/setup failures cannot make the negative assertions pass alone.
for ALLOC_MODE in initial-kernel initial-boringtun; do
	NIAC_PATHS="$(_run_niac n client 10.66.66.02 '' "${ALLOC_MODE}")"
	ALLOC_DIR="$(dirname "$(dirname "${NIAC_PATHS##*|||}")")"
	assert_eq 1 "$(cat "${ALLOC_DIR}/rc")" "${ALLOC_MODE}: propagate initial allocation failure"
	assert_contains "$(cat "${ALLOC_DIR}/stderr")" "canonical dotted-decimal" "${ALLOC_MODE}: preserve allocation diagnostic"
	assert_not_contains "$(cat "${ALLOC_DIR}/stdout")" "If you want to add more clients" "${ALLOC_MODE}: suppress client success message on failure"
	assert_rc 1 test -e "${NIAC_PATHS%%|||*}"
	assert_rc 0 cmp -s "${ALLOC_DIR}/server-before.conf" "${NIAC_PATHS##*|||}"
	NIAC_PATHS="$(_run_niac n client 10.66.66.2 '' "${ALLOC_MODE}")"
	ALLOC_DIR="$(dirname "$(dirname "${NIAC_PATHS##*|||}")")"
	assert_eq 0 "$(cat "${ALLOC_DIR}/rc")" "${ALLOC_MODE}: successful initial allocation"
	assert_contains "$(cat "${ALLOC_DIR}/stdout")" "If you want to add more clients" "${ALLOC_MODE}: retain success guidance"
	assert_contains "$(cat "${NIAC_PATHS%%|||*}")" "Address = 10.66.66.3/32" "${ALLOC_MODE}: initial client reserves server IPv4"
done
# Linux interprets leading-zero octets as octal. Refuse ambiguous server
# configuration rather than allocating an address it may already own.
ALLOC_PEERS=""
for ALLOC_HOST in {2..7}; do
	ALLOC_PEERS+=$'[Peer]\nAllowedIPs = 10.66.66.'"${ALLOC_HOST}"$'/32\n'
done
for ALLOC_SERVER_IP in 10.66.66.02 10.66.66.010 010.66.66.2; do
	for ALLOC_MODE in noninteractive auto interactive; do
		NIAC_PATHS="$(_run_niac n client "${ALLOC_SERVER_IP}" "${ALLOC_PEERS}" "${ALLOC_MODE}" $'client\n08')"
		ALLOC_DIR="$(dirname "$(dirname "${NIAC_PATHS##*|||}")")"
		assert_eq 1 "$(cat "${ALLOC_DIR}/rc")" "${ALLOC_MODE}: reject ambiguous server ${ALLOC_SERVER_IP}"
		assert_contains "$(cat "${ALLOC_DIR}/stderr")" "canonical dotted-decimal" "${ALLOC_MODE}: explain invalid server ${ALLOC_SERVER_IP}"
		assert_rc 1 test -e "${NIAC_PATHS%%|||*}"
		assert_rc 0 cmp -s "${ALLOC_DIR}/server-before.conf" "${NIAC_PATHS##*|||}"
	done
done
# The canonical interface address must not mask missing parameter-prefix
# validation: Linux interprets 010.66.66.2 as the server-owned 8.66.66.2.
for ALLOC_MODE in noninteractive auto interactive; do
	NIAC_PATHS="$(_run_niac n client 010.66.66.1 '' "${ALLOC_MODE}" $'client\n2' 8.66.66.2)"
	ALLOC_DIR="$(dirname "$(dirname "${NIAC_PATHS##*|||}")")"
	assert_eq 1 "$(cat "${ALLOC_DIR}/rc")" "${ALLOC_MODE}: independently reject ambiguous pool prefix"
	assert_contains "$(cat "${ALLOC_DIR}/stderr")" "canonical dotted-decimal" "${ALLOC_MODE}: explain ambiguous pool prefix"
	assert_rc 1 test -e "${NIAC_PATHS%%|||*}"
	assert_rc 0 cmp -s "${ALLOC_DIR}/server-before.conf" "${NIAC_PATHS##*|||}"
done
# Validation must inspect every Address entry, even after finding a reservation.
NIAC_PATHS="$(_run_niac n client 10.66.66.2 'Address = 10.66.66.010/24' auto)"
ALLOC_DIR="$(dirname "$(dirname "${NIAC_PATHS##*|||}")")"
assert_contains "$(cat "${ALLOC_DIR}/stderr")" "canonical dotted-decimal" "auto: reject ambiguous secondary server address"
assert_rc 1 test -e "${NIAC_PATHS%%|||*}"
assert_rc 0 cmp -s "${ALLOC_DIR}/server-before.conf" "${NIAC_PATHS##*|||}"
unset ALLOC_DIR ALLOC_HOST ALLOC_PEERS ALLOC_SERVER_IP
unset ALLOC_MODE ALLOC_IPV6
echo "=== optional client MTU generation ==="
for MTU_MODE in noninteractive auto interactive initial-kernel initial-boringtun; do
	for MTU_VALUE in '' 1280 1380 65535; do
		NIAC_PATHS="$(_run_niac y client '' '' "${MTU_MODE}" $'client\n2\n2' '' "${MTU_VALUE}")"
		MTU_DIR="$(dirname "$(dirname "${NIAC_PATHS##*|||}")")"
		assert_eq 0 "$(cat "${MTU_DIR}/rc")" "${MTU_MODE}: valid MTU '${MTU_VALUE}'"
		MTU_EXPECTED=""; [[ -z "${MTU_VALUE}" ]] || MTU_EXPECTED="MTU = ${MTU_VALUE}"
		assert_eq "${MTU_EXPECTED}" "$(grep '^MTU' "${NIAC_PATHS%%|||*}" || true)" "${MTU_MODE}: generated MTU '${MTU_VALUE}'"
	done
	for MTU_VALUE in 0 1279 65536 01380 +1380 -1380 1380.5 '1380 ' '1+1380' 999999999999999999999 $'1380\nPostUp = false'; do
		NIAC_PATHS="$(_run_niac n client '' '' "${MTU_MODE}" $'client\n2' '' "${MTU_VALUE}")"
		MTU_DIR="$(dirname "$(dirname "${NIAC_PATHS##*|||}")")"
		assert_eq 1 "$(cat "${MTU_DIR}/rc")" "${MTU_MODE}: reject invalid MTU"
		assert_contains "$(cat "${MTU_DIR}/stderr")" 'CLIENT_MTU' "${MTU_MODE}: explain invalid MTU"
		assert_rc 1 test -e "${NIAC_PATHS%%|||*}"
		assert_rc 0 cmp -s "${MTU_DIR}/server-before.conf" "${NIAC_PATHS##*|||}"
	done
done
unset MTU_MODE MTU_VALUE MTU_DIR MTU_EXPECTED
rm -rf "${NIAC_BIN}"
unset NIAC_BIN NIAC_PATHS NIAC_CC NIAC_SC_PEER

echo "=== nonInteractiveAddClient syncconf error file ==="
# The add path captures `awg syncconf` stderr in a private temporary file. The
# awg mock records which file its stderr went to and that file's mode, and can
# wait at a barrier so two concurrent adds provably hold their files at once.
SYNCERR_ROOT="$(readlink -f "$(mktemp -d)")"
SYNCERR_BIN="${SYNCERR_ROOT}/bin"
mkdir -p "${SYNCERR_BIN}"
cat > "${SYNCERR_BIN}/awg" <<'EOF'
#!/usr/bin/env bash
case "$1" in
	genkey) echo "PRIVKEY";;
	pubkey) read -r _ 2>/dev/null; echo "PUBKEY";;
	genpsk) echo "PSK";;
	syncconf)
		cat -- "$3" >/dev/null
		err_path="$(readlink -f "/proc/$$/fd/2")"
		met=no
		if [[ -n "${SYNCERR_BARRIER:-}" ]]; then
			: >"${SYNCERR_BARRIER}/${SYNCERR_MARKER}"
			for _ in $(seq 1 200); do
				arrived=("${SYNCERR_BARRIER}"/*)
				if (( ${#arrived[@]} >= 2 )); then met=yes; break; fi
				sleep 0.05
			done
		fi
		printf '%s %s %s\n' "${err_path}" "$(stat -c '%a' -- "${err_path}")" "${met}" \
			>"${SYNCERR_RECORD}"
		echo "syncconf stdout ${SYNCERR_MARKER}"
		echo "syncconf failed: ${SYNCERR_MARKER}" >&2
		if [[ "${SYNCERR_KILL_CALLER:-0}" == "1" ]]; then
			kill -TERM "${PPID}"
		fi
		exit "${SYNCERR_RC:-0}"
		;;
	*) exit 0;;
esac
EOF
cat > "${SYNCERR_BIN}/awg-quick" <<'EOF'
#!/usr/bin/env bash
echo "strip warning ${SYNCERR_MARKER}" >&2
printf '[Interface]\nListenPort = 51820\n'
EOF
chmod +x "${SYNCERR_BIN}/awg" "${SYNCERR_BIN}/awg-quick"

# Add client $2 to a fresh server state in directory $1, with TMPDIR set to $3.
# Stdout, stderr, the exit status and the awg mock's record land in $1. The
# lifecycle lock is disabled so concurrent runs overlap, as they did in the
# parallel test runs that exposed the former fixed error-file path.
_run_syncerr_add() {
	local dir="$1" client="$2" tmp_dir="$3"
	mkdir -p "${dir}/amneziawg"
	printf '%s\n' "[Interface]" "Address = 10.66.66.1/24" "ListenPort = 51820" \
		> "${dir}/amneziawg/awg0.conf"
	(
		PATH="${SYNCERR_BIN}:${PATH}"; export PATH
		export TMPDIR="${tmp_dir}" SYNCERR_MARKER="${client}" SYNCERR_RECORD="${dir}/record"
		AMNEZIAWG_DIR="${dir}/amneziawg"
		WEB_PANEL_CONFIG_DIR="${dir}/amneziawg/clients"
		WEB_PANEL_ENV_FILE="${dir}/missing-env.conf"
		WEB_PANEL_SYSTEMD_UNIT="${dir}/missing.service"
		SERVER_AWG_NIC="awg0"; SERVER_AWG_IPV4="10.66.66.1"
		SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"; SERVER_PORT="51820"
		SERVER_PUB_IP="198.51.100.1"; SERVER_PUB_KEY="SRVPUB"
		CLIENT_DNS_1="1.1.1.1"; CLIENT_DNS_2=""
		SERVER_AWG_JC=4; SERVER_AWG_JMIN=50; SERVER_AWG_JMAX=1000
		SERVER_AWG_S1=30; SERVER_AWG_S2=100; SERVER_AWG_S3=45; SERVER_AWG_S4=120
		SERVER_AWG_H1="5-10"; SERVER_AWG_H2="11-20"; SERVER_AWG_H3="21-30"; SERVER_AWG_H4="31-40"
		ALLOWED_IPS="0.0.0.0/0"; ENABLE_IPV6="n"
		acquireClientLifecycleLock() { :; }
		loadParams() { :; }
		ensureAmneziawgKernelModule() { :; }
		copyToWebPanelDir() { :; }
		nonInteractiveAddClient "${client}" >"${dir}/stdout" 2>"${dir}/stderr"
		echo "$?" >"${dir}/rc"
	)
}

# Print "<error file> <mode> <barrier met>" as recorded by the awg mock.
_syncerr_record() {
	cat "$1/record" 2>/dev/null || echo "missing missing missing"
}

# Print every file left in a temporary directory.
_syncerr_leftovers() {
	find "$1" -mindepth 1 -print 2>/dev/null
}

# Print "unique" when a recorded error file is a mktemp name inside $2.
_syncerr_is_private_name() {
	if [[ "$1" == "$2"/amneziawg-syncconf.?????? ]]; then echo "unique"; else echo "$1"; fi
}

# Success: a unique mode-0600 file under TMPDIR receives syncconf stderr and is
# removed. syncconf stderr stays off stderr; awg-quick strip diagnostics stay on it.
SYNCERR_TMP="${SYNCERR_ROOT}/tmp-success"
mkdir -p "${SYNCERR_TMP}"
_run_syncerr_add "${SYNCERR_ROOT}/success" okclient "${SYNCERR_TMP}"
read -r SYNCERR_FILE SYNCERR_MODE _ <<<"$(_syncerr_record "${SYNCERR_ROOT}/success")"
assert_eq "0" "$(cat "${SYNCERR_ROOT}/success/rc")" "syncconf error file: successful add exits 0"
assert_eq "${SYNCERR_ROOT}/success/amneziawg/clients/awg0-client-okclient.conf" \
	"$(tail -n 1 "${SYNCERR_ROOT}/success/stdout")" \
	"syncconf error file: successful add still prints the client config path last"
assert_eq "strip warning okclient" "$(cat "${SYNCERR_ROOT}/success/stderr")" \
	"syncconf error file: success keeps strip diagnostics on stderr and syncconf stderr off it"
assert_eq "unique" "$(_syncerr_is_private_name "${SYNCERR_FILE}" "${SYNCERR_TMP}")" \
	"syncconf error file: stderr goes to a unique mktemp file under TMPDIR, not a fixed path"
assert_eq "600" "${SYNCERR_MODE}" "syncconf error file: the file is private (mode 600)"
assert_eq "" "$(_syncerr_leftovers "${SYNCERR_TMP}")" "syncconf error file: removed after success"

# Failure: the same diagnostics as before, the captured detail holds only
# syncconf stderr (strip diagnostics come first, uncaptured), and the file is removed.
SYNCERR_TMP="${SYNCERR_ROOT}/tmp-failure"
mkdir -p "${SYNCERR_TMP}"
SYNCERR_RC=1 _run_syncerr_add "${SYNCERR_ROOT}/failure" failclient "${SYNCERR_TMP}"
assert_eq "1" "$(cat "${SYNCERR_ROOT}/failure/rc")" "syncconf error file: failed sync exits 1"
assert_eq "strip warning failclient
ERROR: failed to sync AmneziaWG interface 'awg0' after adding client 'failclient'
syncconf failed: failclient" "$(cat "${SYNCERR_ROOT}/failure/stderr")" \
	"syncconf error file: failed sync prints the same error and only the syncconf stderr as detail"
assert_eq "syncconf stdout failclient" "$(cat "${SYNCERR_ROOT}/failure/stdout")" \
	"syncconf error file: failed sync passes syncconf stdout through and prints no config path"
assert_eq "" "$(_syncerr_leftovers "${SYNCERR_TMP}")" "syncconf error file: removed after a failed sync"

# Concurrency: two failing adds share one TMPDIR and wait for each other inside
# syncconf, so both error files exist at once. Each must report only its own
# stderr, and neither may remove the other's file.
SYNCERR_TMP="${SYNCERR_ROOT}/tmp-parallel"
mkdir -p "${SYNCERR_TMP}" "${SYNCERR_ROOT}/barrier"
(
	export SYNCERR_RC=1 SYNCERR_BARRIER="${SYNCERR_ROOT}/barrier"
	_run_syncerr_add "${SYNCERR_ROOT}/alpha" alpha "${SYNCERR_TMP}" &
	_run_syncerr_add "${SYNCERR_ROOT}/beta" beta "${SYNCERR_TMP}" &
	wait
)
read -r SYNCERR_ALPHA_FILE _ SYNCERR_ALPHA_MET <<<"$(_syncerr_record "${SYNCERR_ROOT}/alpha")"
read -r SYNCERR_BETA_FILE _ SYNCERR_BETA_MET <<<"$(_syncerr_record "${SYNCERR_ROOT}/beta")"
assert_eq "yes yes" "${SYNCERR_ALPHA_MET} ${SYNCERR_BETA_MET}" \
	"syncconf error file: concurrent adds held their error files at the same time"
assert_eq "unique unique" \
	"$(_syncerr_is_private_name "${SYNCERR_ALPHA_FILE}" "${SYNCERR_TMP}") $(_syncerr_is_private_name "${SYNCERR_BETA_FILE}" "${SYNCERR_TMP}")" \
	"syncconf error file: concurrent adds use mktemp files under TMPDIR"
if [[ "${SYNCERR_ALPHA_FILE}" != "${SYNCERR_BETA_FILE}" ]]; then SYNCERR_DISTINCT="distinct"; else SYNCERR_DISTINCT="shared"; fi
assert_eq "distinct" "${SYNCERR_DISTINCT}" "syncconf error file: concurrent adds use distinct files"
for SYNCERR_CLIENT in alpha beta; do
	assert_eq "1" "$(cat "${SYNCERR_ROOT}/${SYNCERR_CLIENT}/rc")" \
		"syncconf error file: concurrent failed sync for ${SYNCERR_CLIENT} exits 1"
	assert_eq "strip warning ${SYNCERR_CLIENT}
ERROR: failed to sync AmneziaWG interface 'awg0' after adding client '${SYNCERR_CLIENT}'
syncconf failed: ${SYNCERR_CLIENT}" "$(cat "${SYNCERR_ROOT}/${SYNCERR_CLIENT}/stderr")" \
		"syncconf error file: concurrent add ${SYNCERR_CLIENT} reports only its own syncconf stderr"
done
assert_eq "" "$(_syncerr_leftovers "${SYNCERR_TMP}")" "syncconf error file: concurrent adds leave no files behind"

# No fallback: when no private file can be created, the add fails before syncing.
_run_syncerr_add "${SYNCERR_ROOT}/no-tmp" notmp "${SYNCERR_ROOT}/missing-tmp-dir"
assert_eq "1" "$(cat "${SYNCERR_ROOT}/no-tmp/rc")" "syncconf error file: add fails when the file cannot be created"
assert_contains "$(cat "${SYNCERR_ROOT}/no-tmp/stderr")" \
	"ERROR: could not create a temporary file for AmneziaWG sync errors" \
	"syncconf error file: the creation failure is reported"
assert_eq "missing missing missing" "$(_syncerr_record "${SYNCERR_ROOT}/no-tmp")" \
	"syncconf error file: no sync runs without a private error file"

# A terminating signal during the sync still removes the file.
SYNCERR_TMP="${SYNCERR_ROOT}/tmp-signal"
mkdir -p "${SYNCERR_TMP}"
SYNCERR_KILL_CALLER=1 _run_syncerr_add "${SYNCERR_ROOT}/signal" sigclient "${SYNCERR_TMP}"
assert_eq "unique" "$(_syncerr_is_private_name "$(_syncerr_record "${SYNCERR_ROOT}/signal" | cut -d' ' -f1)" "${SYNCERR_TMP}")" \
	"syncconf error file: the interrupted sync had its private file"
assert_eq "143" "$(cat "${SYNCERR_ROOT}/signal/rc")" "syncconf error file: an interrupted sync exits 143, as before"
assert_eq "" "$(_syncerr_leftovers "${SYNCERR_TMP}")" "syncconf error file: removed after a terminating signal"

rm -rf "${SYNCERR_ROOT}"
unset SYNCERR_ROOT SYNCERR_BIN SYNCERR_TMP SYNCERR_FILE SYNCERR_MODE SYNCERR_DISTINCT SYNCERR_CLIENT
unset SYNCERR_ALPHA_FILE SYNCERR_ALPHA_MET SYNCERR_BETA_FILE SYNCERR_BETA_MET
unset -f _run_syncerr_add _syncerr_record _syncerr_leftovers _syncerr_is_private_name

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

echo "=== isWebPanelInstalled ==="
TMP_IWPI="$(mktemp -d)"

_case1_isWebPanelInstalled() {
	(
		WEB_PANEL_ENV_FILE="${TMP_IWPI}/missing.env"
		WEB_PANEL_SYSTEMD_UNIT="${TMP_IWPI}/missing.service"
		resolveWebPanelEnvFiles() { printf '0\t%s\n' "${WEB_PANEL_ENV_FILE}"; }
		readWebPanelEffectiveProperty() { return 1; }
		isWebPanelInstalled
	)
}
assert_rc 1 _case1_isWebPanelInstalled "isWebPanelInstalled: false when missing env, unit, and service"

_case2_isWebPanelInstalled() {
	(
		local env_file="${TMP_IWPI}/exists.env"
		touch "${env_file}"
		WEB_PANEL_ENV_FILE="${env_file}"
		WEB_PANEL_SYSTEMD_UNIT="${TMP_IWPI}/missing.service"
		resolveWebPanelEnvFiles() { printf '0\t%s\n' "${env_file}"; }
		readWebPanelEffectiveProperty() { return 1; }
		isWebPanelInstalled
	)
}
assert_rc 0 _case2_isWebPanelInstalled "isWebPanelInstalled: true when env file exists"

_case3_isWebPanelInstalled() {
	(
		local unit_file="${TMP_IWPI}/exists.service"
		touch "${unit_file}"
		WEB_PANEL_ENV_FILE="${TMP_IWPI}/missing.env"
		WEB_PANEL_SYSTEMD_UNIT="${unit_file}"
		resolveWebPanelEnvFiles() { printf '0\t%s\n' "${WEB_PANEL_ENV_FILE}"; }
		readWebPanelEffectiveProperty() { return 1; }
		isWebPanelInstalled
	)
}
assert_rc 0 _case3_isWebPanelInstalled "isWebPanelInstalled: true when systemd unit exists"

_case4_isWebPanelInstalled() {
	(
		WEB_PANEL_ENV_FILE="${TMP_IWPI}/missing.env"
		WEB_PANEL_SYSTEMD_UNIT="${TMP_IWPI}/missing.service"
		resolveWebPanelEnvFiles() { printf '0\t%s\n' "${WEB_PANEL_ENV_FILE}"; }
		readWebPanelEffectiveProperty() {
			[[ "$1" == "LoadState" ]] && return 0
			return 1
		}
		isWebPanelInstalled
	)
}
assert_rc 0 _case4_isWebPanelInstalled "isWebPanelInstalled: true when LoadState succeeds"

rm -rf "${TMP_IWPI}"
unset TMP_IWPI

echo "=== copyToWebPanelDir self-copy ==="
_run_copy_self_test() {
	(
		local TMP; TMP="$(mktemp -d)"
		local PANEL_DIR="${TMP}/clients"
		mkdir -p "${PANEL_DIR}"
		resolveWebPanelConfigDir() { printf '%s\n' "${PANEL_DIR}"; }

		local TEST_FILE="${PANEL_DIR}/test.conf"
		printf '%s\n' "[Interface]" > "${TEST_FILE}"
		copyToWebPanelDir "${TEST_FILE}" || { rm -rf "${TMP}"; return 1; }
		local content
		content="$(cat "${TEST_FILE}")"
		rm -rf "${TMP}"
		[[ "${content}" == "[Interface]" ]] || return 1
		return 0
	)
}
assert_rc 0 _run_copy_self_test "copyToWebPanelDir self-copy preserves content without error"

echo "=== regenerateClients candidate discovery and web-panel protection ==="
REGEN_TEST_TMP="$(mktemp -d)"
trap 'rm -rf "${REGEN_TEST_TMP}"' EXIT

mkdir -p "${REGEN_TEST_TMP}/bin"
cat > "${REGEN_TEST_TMP}/bin/awg" <<'EOF'
#!/usr/bin/env bash
case "$1" in
	genkey) echo "NEW_PRIVKEY";;
	pubkey)
		key="$(cat -)"
		case "${key}" in
			*PRIV_ALICE*) echo "PUB_ALICE";;
			*PRIV_BOB*) echo "PUB_BOB";;
			*NEW_PRIVKEY*) echo "NEW_PUBKEY";;
			*) echo "PUB_${key}";;
		esac
		;;
	syncconf) exit 0;;
	*) exit 0;;
esac
EOF
cat > "${REGEN_TEST_TMP}/bin/awg-quick" <<'EOF'
#!/usr/bin/env bash
echo "[Interface]"
EOF
chmod +x "${REGEN_TEST_TMP}/bin/awg" "${REGEN_TEST_TMP}/bin/awg-quick"

_run_regen_test() {
	(
		PATH="${REGEN_TEST_TMP}/bin:${PATH}"; export PATH
		local dir; dir="$(mktemp -d)"
		local PANEL_DIR="${dir}/web-clients"
		mkdir -p "${dir}/amneziawg" "${PANEL_DIR}"
		SERVER_AWG_NIC="awg0"
		SERVER_AWG_CONF="${dir}/amneziawg/awg0.conf"
		SERVER_AWG_IPV4="10.66.66.1"
		SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"
		SERVER_PORT="51820"
		SERVER_PUB_IP="198.51.100.1"
		SERVER_PUB_KEY="SRVPUB"
		CLIENT_DNS_1="1.1.1.1"
		CLIENT_DNS_2=""
		CLIENT_MTU="${2:-}"
		SERVER_AWG_JC=4; SERVER_AWG_JMIN=50; SERVER_AWG_JMAX=1000
		SERVER_AWG_S1=30; SERVER_AWG_S2=100; SERVER_AWG_S3=45; SERVER_AWG_S4=120
		SERVER_AWG_H1="5-10"; SERVER_AWG_H2="11-20"; SERVER_AWG_H3="21-30"; SERVER_AWG_H4="31-40"
		ALLOWED_IPS="0.0.0.0/0,::/0"; ENABLE_IPV6="y"
		loadParams() { :; }
		ensureAmneziawgKernelModule() { :; }
		getHomeDirForClient() { echo "${dir}/nonexistent-home/$1"; }
		resolveWebPanelConfigDir() { echo "${PANEL_DIR}"; }

		"$1" "${dir}" "${PANEL_DIR}"
	)
}

# Test 1: Client config exists ONLY in web panel config directory -> key is preserved
_setup_panel_only() {
	local dir="$1" PANEL_DIR="$2"
	cat > "${SERVER_AWG_CONF}" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = SRVPRIV

### Client alice
[Peer]
PublicKey = PUB_ALICE
PresharedKey = PSK_ALICE
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128
EOF
	cat > "${PANEL_DIR}/awg0-client-alice.conf" <<EOF
[Interface]
PrivateKey = PRIV_ALICE
Address = 10.66.66.2/32,fd42:42:42::2/128
DNS = 1.1.1.1
H1 = 1-2

[Peer]
PublicKey = SRVPUB
PresharedKey = PSK_ALICE
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0,::/0
EOF
	local out
	out="$(regenerateClients 2>&1)"
	local cur_pub
	cur_pub="$(grep -m1 -E '^PublicKey = ' "${SERVER_AWG_CONF}" | sed 's/^PublicKey = //')"
	local cur_priv
	cur_priv="$(grep -m1 -E '^PrivateKey = ' "${PANEL_DIR}/awg0-client-alice.conf" | sed 's/^PrivateKey = //')"
	local cur_h1
	cur_h1="$(grep -m1 -E '^H1 = ' "${PANEL_DIR}/awg0-client-alice.conf" | sed 's/^H1 = //')"

	if [[ "${cur_pub}" != "PUB_ALICE" ]]; then
		echo "FAIL: expected PublicKey PUB_ALICE, got ${cur_pub}" >&2
		return 1
	fi
	if [[ "${cur_priv}" != "PRIV_ALICE" ]]; then
		echo "FAIL: expected PrivateKey PRIV_ALICE, got ${cur_priv}" >&2
		return 1
	fi
	if [[ "${cur_h1}" != "5-10" ]]; then
		echo "FAIL: expected H1 5-10, got ${cur_h1}" >&2
		return 1
	fi
	local expected_mtu=""
	[[ -z "${CLIENT_MTU}" ]] || expected_mtu="MTU = ${CLIENT_MTU}"
	if [[ "$(grep '^MTU' "${PANEL_DIR}/awg0-client-alice.conf" || true)" != "${expected_mtu}" ]]; then
		echo "FAIL: regenerated config has incorrect MTU" >&2
		return 1
	fi
	if ! echo "${out}" | grep -q "1 succeeded, 0 failed"; then
		echo "FAIL: expected summary '1 succeeded, 0 failed', got: ${out}" >&2
		return 1
	fi
	if echo "${out}" | grep -q "no existing private key found"; then
		echo "FAIL: unexpected key regeneration triggered: ${out}" >&2
		return 1
	fi
	echo "OK"
}
assert_eq "OK" "$(_run_regen_test _setup_panel_only)" "regenerateClients: preserves key when config exists only in web panel config dir"
assert_eq "OK" "$(_run_regen_test _setup_panel_only 1380)" "regenerateClients: applies persisted client MTU"

_setup_invalid_mtu_regen() {
	local dir="$1" PANEL_DIR="$2" rc=0 diagnostic=no before after unchanged=no
	cat >"${SERVER_AWG_CONF}" <<'EOF'
[Interface]
Address = 10.66.66.1/24
PrivateKey = SRVPRIV

### Client alice
[Peer]
PublicKey = PUB_ALICE
PresharedKey = PSK_ALICE
AllowedIPs = 10.66.66.2/32
EOF
	cat >"${PANEL_DIR}/awg0-client-alice.conf" <<'EOF'
[Interface]
PrivateKey = PRIV_ALICE
Address = 10.66.66.2/32
MTU = 1420

[Peer]
PublicKey = SRVPUB
PresharedKey = PSK_ALICE
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
EOF
	printf 'CLIENT_MTU=%s\n' "$(safeQuoteParam "${CLIENT_MTU}")" >"${dir}/amneziawg/params"
	before="$(find "${dir}/amneziawg" "${PANEL_DIR}" -type f -exec sha256sum {} + | sort)"
	: >"${dir}/awg-calls"
	# Keep the existing key tool mock, but record every command across subshells.
	awg() { printf '%s\n' "$*" >>"${dir}/awg-calls"; command awg "$@"; }
	regenerateClients >"${dir}/stdout" 2>"${dir}/stderr" </dev/null || rc=$?
	grep -q 'CLIENT_MTU must' "${dir}/stderr" && diagnostic=yes
	after="$(find "${dir}/amneziawg" "${PANEL_DIR}" -type f -exec sha256sum {} + | sort)"
	[[ "${before}" != "${after}" ]] || unchanged=yes
	printf '%s|%s|%s|%s\n' "${rc}" "${diagnostic}" "$(wc -l <"${dir}/awg-calls")" "${unchanged}"
}
for MTU_INVALID in 1279 65536 '1380 ' $'1380\nPostUp = false'; do
	MTU_RC=0
	MTU_REGEN_RESULT="$(_run_regen_test _setup_invalid_mtu_regen "${MTU_INVALID}")" || MTU_RC=$?
	assert_eq 0 "${MTU_RC}" "invalid-MTU regeneration fixture succeeds"
	IFS='|' read -r MTU_REGEN_RC MTU_DIAGNOSTIC MTU_KEY_CALLS MTU_UNCHANGED <<<"${MTU_REGEN_RESULT}"
	assert_eq 1 "${MTU_REGEN_RC}" "regeneration rejects invalid MTU"
	assert_eq yes "${MTU_DIAGNOSTIC}" "regeneration explains invalid MTU"
	assert_eq 0 "${MTU_KEY_CALLS}" "invalid MTU prevents key and interface commands"
	assert_eq yes "${MTU_UNCHANGED}" "invalid MTU preserves all params, server and client files"
done
unset MTU_INVALID MTU_RC MTU_REGEN_RESULT MTU_REGEN_RC MTU_DIAGNOSTIC MTU_KEY_CALLS MTU_UNCHANGED

# Test 2: Web panel installed, client config MISSING, non-interactive -> refuses to rotate key
_setup_panel_missing_noninteractive() {
	local dir="$1" PANEL_DIR="$2"
	cat > "${SERVER_AWG_CONF}" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = SRVPRIV

### Client bob
[Peer]
PublicKey = PUB_BOB
PresharedKey = PSK_BOB
AllowedIPs = 10.66.66.3/32,fd42:42:42::3/128
EOF
	isWebPanelInstalled() { return 0; }
	local out
	out="$(regenerateClients </dev/null 2>&1)"
	local cur_pub
	cur_pub="$(grep -m1 -E '^PublicKey = ' "${SERVER_AWG_CONF}" | sed 's/^PublicKey = //')"
	if [[ "${cur_pub}" != "PUB_BOB" ]]; then
		echo "FAIL: PublicKey was modified when key rotation should be refused: ${cur_pub}" >&2
		return 1
	fi
	if ! echo "${out}" | grep -q "skipped to avoid rotating web-managed client identity"; then
		echo "FAIL: missing refusal warning in output: ${out}" >&2
		return 1
	fi
	if ! echo "${out}" | grep -q "0 succeeded, 1 failed"; then
		echo "FAIL: expected summary '0 succeeded, 1 failed', got: ${out}" >&2
		return 1
	fi
	echo "OK"
}
assert_eq "OK" "$(_run_regen_test _setup_panel_missing_noninteractive)" "regenerateClients: refuses silent key rotation when panel installed and config missing"

# Test 3: Web panel NOT installed, client config MISSING -> generates new key (standalone behavior)
_setup_standalone_missing() {
	local dir="$1" PANEL_DIR="$2"
	cat > "${SERVER_AWG_CONF}" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = SRVPRIV

### Client charlie
[Peer]
PublicKey = PUB_OLD_CHARLIE
PresharedKey = PSK_CHARLIE
AllowedIPs = 10.66.66.4/32,fd42:42:42::4/128
EOF
	isWebPanelInstalled() { return 1; }
	local out
	out="$(regenerateClients </dev/null 2>&1)"
	local cur_pub
	cur_pub="$(grep -m1 -E '^PublicKey = ' "${SERVER_AWG_CONF}" | sed 's/^PublicKey = //')"
	if [[ "${cur_pub}" != "NEW_PUBKEY" ]]; then
		echo "FAIL: expected PublicKey to rotate to NEW_PUBKEY, got: ${cur_pub}" >&2
		return 1
	fi
	if ! echo "${out}" | grep -q "1 succeeded, 0 failed"; then
		echo "FAIL: expected summary '1 succeeded, 0 failed', got: ${out}" >&2
		return 1
	fi
	if ! echo "${out}" | grep -q "1 client(s) had new key pairs generated"; then
		echo "FAIL: expected '1 client(s) had new key pairs generated', got: ${out}" >&2
		return 1
	fi
	echo "OK"
}
assert_eq "OK" "$(_run_regen_test _setup_standalone_missing)" "regenerateClients: generates new key in standalone mode when config missing"

echo ""
echo "=========================================="
echo "Results: ${TESTS_PASSED}/${TESTS_RUN} passed, ${TESTS_FAILED} failed"
echo "=========================================="

if (( TESTS_FAILED > 0 )); then
	exit 1
fi
