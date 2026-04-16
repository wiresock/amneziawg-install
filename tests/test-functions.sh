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
		set +u
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
	set +u
	export PATH="${MOCK_BIN_DIR}:${PATH}"
	OS="ubuntu"
	SERVER_AWG_NIC="awg0"
	enable_apt_ipv4() { :; }
	disable_apt_ipv4() { :; }
	ensureAmneziawgKernelModule
) 2>&1
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

echo ""
echo "=========================================="
echo "Results: ${TESTS_PASSED}/${TESTS_RUN} passed, ${TESTS_FAILED} failed"
echo "=========================================="

if (( TESTS_FAILED > 0 )); then
	exit 1
fi
