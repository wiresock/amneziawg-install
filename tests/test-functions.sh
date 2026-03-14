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
ALLOWED_IPS="0.0.0.0/0,::/0"
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

echo ""
echo "=========================================="
echo "Results: ${TESTS_PASSED}/${TESTS_RUN} passed, ${TESTS_FAILED} failed"
echo "=========================================="

if (( TESTS_FAILED > 0 )); then
	exit 1
fi
