#!/bin/bash

# AmneziaWG server installer
# https://github.com/wiresock/amneziawg-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"

# Ensure sbin directories are in PATH for depmod, modprobe, sysctl, etc.
# Some minimal or non-login root shells may not include these by default.
# Only adjust PATH when the script is executed directly, not when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	if [ -n "${PATH:-}" ]; then
		export PATH="/sbin:/usr/sbin:${PATH:-}"
	else
		export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	fi
fi

# For sensitive files (private keys, params, configs), a restrictive umask (077)
# is applied locally around their creation to avoid them being briefly world-readable.
# This avoids affecting subprocesses (apt/dnf, dkms, etc.) that expect the default umask.

# Safely quote a value for inclusion in a sourced params file
# Escapes single quotes and wraps in single quotes to prevent shell injection
function safeQuoteParam() {
	local VALUE="$1"
	# Replace each single quote with '"'"' (end quote, literal quote, start quote)
	local ESCAPED
	ESCAPED="$(printf '%s' "${VALUE}" | sed "s/'/'\"'\"'/g")"
	printf "'%s'\n" "${ESCAPED}"
}

# Optional self-test for safeQuoteParam; run by setting SAFE_QUOTE_PARAM_SELFTEST=1
if [[ "${SAFE_QUOTE_PARAM_SELFTEST:-0}" == "1" ]]; then
	TEST_VALUE="O'Reilly"
	QUOTED="$(safeQuoteParam "${TEST_VALUE}")"
	# Verify the quoted form matches the known-good shell-safe literal; no eval needed
	EXPECTED="'O'\"'\"'Reilly'"
	if [[ "${QUOTED}" != "${EXPECTED}" ]]; then
		echo "ERROR: safeQuoteParam self-test failed: expected '${EXPECTED}', got '${QUOTED}'" >&2
		exit 1
	fi
fi

# Serialize all server parameters to a params file
# Uses safe quoting for string values to prevent shell injection when sourced
# Arguments:
#   $1 - Output file path to write the serialized params to
function serializeParams() {
	local OUTPUT_FILE="$1"
	if [[ -z "${OUTPUT_FILE}" ]]; then
		echo "ERROR: serializeParams() requires an output file path" >&2
		return 1
	fi
	# Apply a restrictive umask only while writing the params file to disk,
	# so that subprocesses (apt/dnf, dkms, etc.) are not affected.
	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077
	cat >"${OUTPUT_FILE}" <<EOF
SERVER_PUB_IP=$(safeQuoteParam "${SERVER_PUB_IP}")
SERVER_PUB_NIC=$(safeQuoteParam "${SERVER_PUB_NIC}")
SERVER_AWG_NIC=$(safeQuoteParam "${SERVER_AWG_NIC}")
SERVER_AWG_IPV4=$(safeQuoteParam "${SERVER_AWG_IPV4}")
SERVER_AWG_IPV6=$(safeQuoteParam "${SERVER_AWG_IPV6}")
SERVER_PORT=$(safeQuoteParam "${SERVER_PORT}")
SERVER_PRIV_KEY=$(safeQuoteParam "${SERVER_PRIV_KEY}")
SERVER_PUB_KEY=$(safeQuoteParam "${SERVER_PUB_KEY}")
CLIENT_DNS_1=$(safeQuoteParam "${CLIENT_DNS_1}")
CLIENT_DNS_2=$(safeQuoteParam "${CLIENT_DNS_2}")
ALLOWED_IPS=$(safeQuoteParam "${ALLOWED_IPS}")
SERVER_AWG_JC=$(safeQuoteParam "${SERVER_AWG_JC}")
SERVER_AWG_JMIN=$(safeQuoteParam "${SERVER_AWG_JMIN}")
SERVER_AWG_JMAX=$(safeQuoteParam "${SERVER_AWG_JMAX}")
SERVER_AWG_S1=$(safeQuoteParam "${SERVER_AWG_S1}")
SERVER_AWG_S2=$(safeQuoteParam "${SERVER_AWG_S2}")
SERVER_AWG_S3=$(safeQuoteParam "${SERVER_AWG_S3}")
SERVER_AWG_S4=$(safeQuoteParam "${SERVER_AWG_S4}")
SERVER_AWG_H1=$(safeQuoteParam "${SERVER_AWG_H1}")
SERVER_AWG_H2=$(safeQuoteParam "${SERVER_AWG_H2}")
SERVER_AWG_H3=$(safeQuoteParam "${SERVER_AWG_H3}")
SERVER_AWG_H4=$(safeQuoteParam "${SERVER_AWG_H4}")
EOF
	umask "${OLD_UMASK}"
}

# Validate an IPv6 address string
# Handles full form (8 hextets), compressed form (with ::), and mixed forms
# Returns 0 if valid, 1 if invalid
# Note: Does not support IPv4-mapped addresses (e.g., ::ffff:192.0.2.1)
function isValidIPv6() {
	local ADDR="$1"

	if [[ -z "${ADDR}" ]]; then
		return 1
	fi

	# Must only contain hex digits and colons
	if ! [[ "${ADDR}" =~ ^[a-fA-F0-9:]+$ ]]; then
		return 1
	fi

	# Must not start or end with a single colon (:: at boundaries is OK)
	if [[ "${ADDR}" =~ ^:[^:] ]] || [[ "${ADDR}" =~ [^:]:$ ]]; then
		return 1
	fi

	# Count :: occurrences (at most one allowed)
	local WITHOUT_DC="${ADDR//::}"
	local DC_COUNT=$(( (${#ADDR} - ${#WITHOUT_DC}) / 2 ))

	if (( DC_COUNT > 1 )); then
		return 1
	fi

	local -a PARTS=() LEFT_PARTS=() RIGHT_PARTS=()
	local PART LEFT RIGHT LEFT_COUNT RIGHT_COUNT

	if (( DC_COUNT == 1 )); then
		LEFT="${ADDR%%::*}"
		RIGHT="${ADDR#*::}"
		LEFT_COUNT=0
		RIGHT_COUNT=0

		if [[ -n "${LEFT}" ]]; then
			IFS=':' read -ra LEFT_PARTS <<< "${LEFT}"
			LEFT_COUNT=${#LEFT_PARTS[@]}
			for PART in "${LEFT_PARTS[@]}"; do
				if [[ -z "${PART}" ]] || (( ${#PART} > 4 )); then
					return 1
				fi
			done
		fi

		if [[ -n "${RIGHT}" ]]; then
			IFS=':' read -ra RIGHT_PARTS <<< "${RIGHT}"
			RIGHT_COUNT=${#RIGHT_PARTS[@]}
			for PART in "${RIGHT_PARTS[@]}"; do
				if [[ -z "${PART}" ]] || (( ${#PART} > 4 )); then
					return 1
				fi
			done
		fi

		# With :: present, total groups must be fewer than 8
		if (( LEFT_COUNT + RIGHT_COUNT >= 8 )); then
			return 1
		fi
	else
		# No :: compression - must have exactly 8 colon-separated groups
		IFS=':' read -ra PARTS <<< "${ADDR}"
		if (( ${#PARTS[@]} != 8 )); then
			return 1
		fi
		for PART in "${PARTS[@]}"; do
			if [[ -z "${PART}" ]] || (( ${#PART} > 4 )); then
				return 1
			fi
		done
	fi

	return 0
}

# Expand an IPv6 address to its full 8-group form without :: compression
# Each group is lowercase with leading zeros stripped
# e.g., fd42:42:42::1 -> fd42:42:42:0:0:0:0:1
# Used for semantic comparison and reliable prefix extraction
function normalizeIPv6() {
	local ADDR="$1"
	local -a HEXTETS=() LEFT_PARTS=() RIGHT_PARTS=()
	local LEFT RIGHT FILL_COUNT i RESULT NORMALIZED

	if [[ "${ADDR}" == *"::"* ]]; then
		LEFT="${ADDR%%::*}"
		RIGHT="${ADDR#*::}"

		if [[ -n "${LEFT}" ]]; then
			IFS=':' read -ra LEFT_PARTS <<< "${LEFT}"
		fi
		if [[ -n "${RIGHT}" ]]; then
			IFS=':' read -ra RIGHT_PARTS <<< "${RIGHT}"
		fi

		FILL_COUNT=$((8 - ${#LEFT_PARTS[@]} - ${#RIGHT_PARTS[@]}))

		HEXTETS=("${LEFT_PARTS[@]}")
		for (( i = 0; i < FILL_COUNT; i++ )); do
			HEXTETS+=("0")
		done
		HEXTETS+=("${RIGHT_PARTS[@]}")
	else
		IFS=':' read -ra HEXTETS <<< "${ADDR}"
	fi

	RESULT=""
	for (( i = 0; i < 8; i++ )); do
		if (( i > 0 )); then
			RESULT+=":"
		fi
		printf -v NORMALIZED '%x' "0x${HEXTETS[$i]:-0}"
		RESULT+="${NORMALIZED}"
	done

	echo "${RESULT}"
}

function isRoot() {
	if [[ "${EUID}" -ne 0 ]]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if ! command -v systemd-detect-virt &>/dev/null; then
		return
	fi

	if [[ "$(systemd-detect-virt)" == "openvz" ]]; then
		echo "OpenVZ is not supported"
		exit 1
	fi

	if [[ "$(systemd-detect-virt)" == "lxc" ]]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	if [[ ! -f /etc/os-release ]] || [[ ! -r /etc/os-release ]]; then
		echo "Cannot detect OS: /etc/os-release is missing or not readable"
		exit 1
	fi
	# shellcheck source=/etc/os-release
	source /etc/os-release
	OS="${ID}"
	if [[ -z "${OS}" ]]; then
		echo "Cannot detect OS: /etc/os-release is missing the ID field"
		exit 1
	fi
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Debian version: VERSION_ID is missing from /etc/os-release"
			exit 1
		fi
		# Extract major version to handle point-release formats (e.g., "11.7")
		local DEBIAN_MAJOR
		DEBIAN_MAJOR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${DEBIAN_MAJOR} =~ ^[0-9]+$ ]] || [[ ${DEBIAN_MAJOR} -lt 11 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Ubuntu version: VERSION_ID is missing from /etc/os-release"
			exit 1
		fi
		local RELEASE_YEAR
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${RELEASE_YEAR} =~ ^[0-9]+$ ]] || [[ ${RELEASE_YEAR} -lt 22 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 22.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Fedora version: VERSION_ID is missing from /etc/os-release"
			exit 1
		fi
		# Extract major version to handle potential future format changes
		local FEDORA_MAJOR
		FEDORA_MAJOR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${FEDORA_MAJOR} =~ ^[0-9]+$ ]] || [[ ${FEDORA_MAJOR} -lt 39 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 39 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect CentOS/AlmaLinux/Rocky version: VERSION_ID is missing from /etc/os-release"
			exit 1
		fi
		if [[ ${VERSION_ID} == 7* ]] || [[ ${VERSION_ID} == 8* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 9 or later"
			exit 1
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux or Rocky Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [[ -z "${CLIENT_NAME}" ]]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written.
	# Use getent passwd for reliable lookup (supports LDAP, custom home paths, etc.),
	# but gracefully handle systems where getent is unavailable or misconfigured.
	local PASSWD_HOME=""
	local RESULT_DIR
	local HAVE_GETENT=false
	if command -v getent &>/dev/null; then
		HAVE_GETENT=true
	fi
	if [[ "${HAVE_GETENT}" == true ]]; then
		PASSWD_HOME=$(getent passwd "${CLIENT_NAME}" 2>/dev/null | cut -d: -f6)
	fi
	if [[ -n "${PASSWD_HOME}" ]] && [[ -d "${PASSWD_HOME}" ]]; then
		RESULT_DIR="${PASSWD_HOME}"
	elif [[ -d "/home/${CLIENT_NAME}" ]]; then
		# Fallback to traditional /home path for the client when getent is unavailable or misconfigured
		RESULT_DIR="/home/${CLIENT_NAME}"
	elif [[ "${CLIENT_NAME}" == "root" ]]; then
		# Explicitly handle root client
		RESULT_DIR="/root"
	elif [[ "${SUDO_USER:-}" ]]; then
		# if not a system user, use SUDO_USER
		local SUDO_HOME=""
		if [[ "${HAVE_GETENT}" == true ]]; then
			SUDO_HOME=$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6)
		fi
		if [[ -n "${SUDO_HOME}" ]] && [[ -d "${SUDO_HOME}" ]]; then
			RESULT_DIR="${SUDO_HOME}"
		elif [[ -d "/home/${SUDO_USER}" ]]; then
			# Fallback to traditional /home path when getent is unavailable or misconfigured
			RESULT_DIR="/home/${SUDO_USER}"
		else
			RESULT_DIR="/root"
		fi
	else
		# if not SUDO_USER, use /root
		RESULT_DIR="/root"
	fi

	echo "${RESULT_DIR}"
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function readJminAndJmax() {
	SERVER_AWG_JMIN=0
	SERVER_AWG_JMAX=0
	until [[ ${SERVER_AWG_JMIN} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMIN} >= 1 )) && (( ${SERVER_AWG_JMIN} <= 1280 )); do
		read -rp "Server AmneziaWG Jmin [1-1280]: " -e -i 50 SERVER_AWG_JMIN
	done
	until [[ ${SERVER_AWG_JMAX} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMAX} >= 1 )) && (( ${SERVER_AWG_JMAX} <= 1280 )); do
		read -rp "Server AmneziaWG Jmax [1-1280]: " -e -i 1000 SERVER_AWG_JMAX
	done
}

function generateS1AndS2() {
	RANDOM_AWG_S1=$(shuf -i15-150 -n1)
	RANDOM_AWG_S2=$(shuf -i15-150 -n1)
}

function readS1AndS2() {
	SERVER_AWG_S1=0
	SERVER_AWG_S2=0
	until [[ ${SERVER_AWG_S1} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S1} >= 15 )) && (( ${SERVER_AWG_S1} <= 150 )); do
		read -rp "Server AmneziaWG S1 [15-150]: " -e -i "${RANDOM_AWG_S1}" SERVER_AWG_S1
	done
	until [[ ${SERVER_AWG_S2} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S2} >= 15 )) && (( ${SERVER_AWG_S2} <= 150 )); do
		read -rp "Server AmneziaWG S2 [15-150]: " -e -i "${RANDOM_AWG_S2}" SERVER_AWG_S2
	done
}

function generateS3AndS4() {
	RANDOM_AWG_S3=$(shuf -i15-150 -n1)
	RANDOM_AWG_S4=$(shuf -i15-150 -n1)
}

function readS3AndS4() {
	SERVER_AWG_S3=0
	SERVER_AWG_S4=0
	until [[ ${SERVER_AWG_S3} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S3} >= 15 )) && (( ${SERVER_AWG_S3} <= 150 )); do
		read -rp "Server AmneziaWG S3 [15-150]: " -e -i "${RANDOM_AWG_S3}" SERVER_AWG_S3
	done
	until [[ ${SERVER_AWG_S4} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S4} >= 15 )) && (( ${SERVER_AWG_S4} <= 150 )); do
		read -rp "Server AmneziaWG S4 [15-150]: " -e -i "${RANDOM_AWG_S4}" SERVER_AWG_S4
	done
}

# Parse a range string "min-max" or single value into MIN and MAX variables
# Uses indirect variable assignment via printf -v to set caller's variables by name
#
# NOTE: This function only validates format and that min <= max. It does NOT
# validate bounds - callers must use validateRange() to check domain-specific
# bounds (e.g., [5-2147483647] for H parameters, [15-150] for S parameters).
function parseRange() {
	local INPUT="$1"  # SECURITY: Must quote to prevent shell injection
	local MIN_VAR_NAME="$2"  # Name of variable to store min value (indirect assignment)
	local MAX_VAR_NAME="$3"  # Name of variable to store max value (indirect assignment)
	
	# Validate input is not empty
	if [[ -z "${INPUT}" ]]; then
		return 1
	fi
	
	if [[ ${INPUT} =~ ^([0-9]+)-([0-9]+)$ ]]; then
		# Force base-10 interpretation to avoid octal issues with leading zeros
		# e.g., "010" would be interpreted as 8 (octal) without 10# prefix
		local MIN=$((10#${BASH_REMATCH[1]}))
		local MAX=$((10#${BASH_REMATCH[2]}))
		
		# Validate that min <= max
		if (( MIN > MAX )); then
			return 1
		fi
		
		# Indirect assignment: sets the variable named by $MIN_VAR_NAME to $MIN
		printf -v "$MIN_VAR_NAME" '%s' "${MIN}"
		printf -v "$MAX_VAR_NAME" '%s' "${MAX}"
	elif [[ ${INPUT} =~ ^[0-9]+$ ]]; then
		# Single value: use as both min and max
		# Force base-10 interpretation here as well
		local VAL=$((10#${INPUT}))
		printf -v "$MIN_VAR_NAME" '%s' "${VAL}"
		printf -v "$MAX_VAR_NAME" '%s' "${VAL}"
	else
		return 1
	fi
	return 0
}

# Check if two ranges overlap
# Returns 0 (true) if ranges overlap, 1 (false) if they don't
#
# Note: This uses STRICT non-overlap detection where ranges must be fully separated.
# Ranges that share a boundary point (e.g., [5-100] and [100-200]) ARE considered
# overlapping because the value 100 could be selected from either range.
# For AmneziaWG header randomization, this ensures each H parameter produces
# values from completely distinct ranges, maximizing entropy and preventing
# any single value from appearing in multiple parameters.
#
# To create non-overlapping ranges, ensure: range1_max < range2_min
# Example: [5-99] and [100-200] do NOT overlap (99 < 100)
function rangesOverlap() {
	local MIN1=$1
	local MAX1=$2
	local MIN2=$3
	local MAX2=$4
	
	# Ranges do NOT overlap if: max1 < min2 OR max2 < min1 (strict inequality)
	# This means [5-100] and [100-200] DO overlap (100 is not < 100)
	if (( MAX1 < MIN2 )) || (( MAX2 < MIN1 )); then
		return 1  # No overlap
	fi
	return 0  # Overlap exists
}

# Validate that a range is valid (min <= max) and within bounds
function validateRange() {
	local MIN=$1
	local MAX=$2
	local LOWER_BOUND=$3
	local UPPER_BOUND=$4
	
	if (( MIN > MAX )); then
		return 1
	fi
	if (( MIN < LOWER_BOUND )) || (( MAX > UPPER_BOUND )); then
		return 1
	fi
	return 0
}

# Generate non-overlapping random ranges for H1-H4
function generateH1AndH2AndH3AndH4Ranges() {
	# Size of each H1-H4 range (1e8). Chosen to provide a large randomization space
	# while staying well below the 32-bit signed int max (2,147,483,647) so that
	# four ranges plus minimum 1-unit gaps between them all fit within [MIN_VAL, MAX_VAL]
	local RANGE_SIZE=100000000
	local MIN_VAL=5
	local MAX_VAL=2147483647
	local GAP=1  # Minimum gap between segments to prevent boundary overlap
	
	# Calculate available range, rounding down to a multiple of 4 to ensure even distribution among 4 segments
	local RAW_AVAILABLE=$((MAX_VAL - MIN_VAL - GAP * 3))
	local AVAILABLE_RANGE=$((RAW_AVAILABLE - RAW_AVAILABLE % 4))
	
	# Generate 4 non-overlapping ranges by dividing the available space into 4 segments
	local SEGMENT_SIZE=$((AVAILABLE_RANGE / 4))
	
	# Validate that segment size is larger than range size
	if (( SEGMENT_SIZE <= RANGE_SIZE )); then
		# Fallback to deterministic fixed non-overlapping ranges when the calculated segment
		# size is too small to randomize positions for all four ranges. This ensures each
		# range has size RANGE_SIZE and is separated by at least GAP units.
		#
		# Note: With current constants (RANGE_SIZE=100M, MAX_VAL=2.1B), four ranges plus gaps
		# total ~400M which fits comfortably. This fallback exists for future-proofing if
		# constants are changed to values that reduce available randomization space.
		#
		# IMPORTANT: Constants must satisfy: MIN_VAL + 4*(RANGE_SIZE - 1) + 3*GAP <= MAX_VAL
		# With current values: 5 + 4*99999999 + 3*1 = 400,000,004 <= 2,147,483,647 (OK)
		RANDOM_AWG_H1_MIN=${MIN_VAL}
		RANDOM_AWG_H1_MAX=$((MIN_VAL + RANGE_SIZE - 1))
		RANDOM_AWG_H2_MIN=$((RANDOM_AWG_H1_MAX + GAP))
		RANDOM_AWG_H2_MAX=$((RANDOM_AWG_H2_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H3_MIN=$((RANDOM_AWG_H2_MAX + GAP))
		RANDOM_AWG_H3_MAX=$((RANDOM_AWG_H3_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H4_MIN=$((RANDOM_AWG_H3_MAX + GAP))
		RANDOM_AWG_H4_MAX=$((RANDOM_AWG_H4_MIN + RANGE_SIZE - 1))
		return
	fi
	
	local RANDOM_OFFSET_MAX=$((SEGMENT_SIZE - RANGE_SIZE))
	
	# H1 range (segment 0)
	local H1_START=$((MIN_VAL + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H1_MIN=${H1_START}
	RANDOM_AWG_H1_MAX=$((H1_START + RANGE_SIZE - 1))
	
	# H2 range (segment 1, with gap after H1's segment)
	local H2_START=$((MIN_VAL + SEGMENT_SIZE + GAP + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H2_MIN=${H2_START}
	RANDOM_AWG_H2_MAX=$((H2_START + RANGE_SIZE - 1))
	
	# H3 range (segment 2, with gap after H2's segment)
	local H3_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 2 + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H3_MIN=${H3_START}
	RANDOM_AWG_H3_MAX=$((H3_START + RANGE_SIZE - 1))
	
	# H4 range (segment 3, with gap after H3's segment)
	local H4_SEGMENT_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 3))
	
	# Adjust H4 segment start if necessary so that a full RANGE_SIZE fits before MAX_VAL
	# This prevents the edge case where randomization could produce a truncated range
	local H4_SEGMENT_MAX_START=$((MAX_VAL - RANGE_SIZE + 1))
	if (( H4_SEGMENT_START > H4_SEGMENT_MAX_START )); then
		H4_SEGMENT_START=${H4_SEGMENT_MAX_START}
	fi

	# Recalculate RANDOM_OFFSET_MAX for H4 based on potentially adjusted segment
	local H4_RANDOM_OFFSET_MAX=$((MAX_VAL - H4_SEGMENT_START - RANGE_SIZE + 1))
	if (( H4_RANDOM_OFFSET_MAX < 0 )); then
		H4_RANDOM_OFFSET_MAX=0
	fi
	
	local H4_START=$((H4_SEGMENT_START + $(shuf -i0-${H4_RANDOM_OFFSET_MAX} -n1)))
	
	# H4 range is guaranteed to fit within bounds due to pre-adjusted segment start
	local H4_END=$((H4_START + RANGE_SIZE - 1))
	
	RANDOM_AWG_H4_MIN=${H4_START}
	RANDOM_AWG_H4_MAX=${H4_END}
	
	# Final validation: ensure all four ranges are non-overlapping
	# The segment-based generation above should prevent overlaps, but this serves
	# as a safety net for any edge cases (e.g., arithmetic boundary conditions)
	local HAS_OVERLAP=0
	if rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}" "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}"; then
		HAS_OVERLAP=1
	fi
	
	# If overlaps remain, fall back to deterministic non-overlapping layout
	if (( HAS_OVERLAP )); then
		RANDOM_AWG_H1_MIN=${MIN_VAL}
		RANDOM_AWG_H1_MAX=$((RANDOM_AWG_H1_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H2_MIN=$((RANDOM_AWG_H1_MAX + GAP))
		RANDOM_AWG_H2_MAX=$((RANDOM_AWG_H2_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H3_MIN=$((RANDOM_AWG_H2_MAX + GAP))
		RANDOM_AWG_H3_MAX=$((RANDOM_AWG_H3_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H4_MIN=$((RANDOM_AWG_H3_MAX + GAP))
		RANDOM_AWG_H4_MAX=$((RANDOM_AWG_H4_MIN + RANGE_SIZE - 1))
	fi
}

# Read an H parameter range from user input with validation
# Uses indirect variable assignment to set SERVER_AWG_${H_NAME}_MIN and _MAX
function readHRange() {
	local H_NAME=$1
	local DEFAULT_MIN=$2
	local DEFAULT_MAX=$3
	# Variable names for indirect assignment via printf -v
	local RESULT_VAR_MIN="SERVER_AWG_${H_NAME}_MIN"
	local RESULT_VAR_MAX="SERVER_AWG_${H_NAME}_MAX"
	
	local INPUT=""
	local VALID=0
	
	until [[ ${VALID} == 1 ]]; do
		read -rp "Server AmneziaWG ${H_NAME} [5-2147483647] (format: min-max or single value): " -e -i "${DEFAULT_MIN}-${DEFAULT_MAX}" INPUT
		
		if parseRange "${INPUT}" "TEMP_MIN" "TEMP_MAX"; then
			if validateRange "${TEMP_MIN}" "${TEMP_MAX}" 5 2147483647; then
				# Indirect assignment: sets global variables by name
				printf -v "$RESULT_VAR_MIN" '%s' "${TEMP_MIN}"
				printf -v "$RESULT_VAR_MAX" '%s' "${TEMP_MAX}"
				VALID=1
			else
				echo -e "${ORANGE}Invalid range. Min must be <= Max and both must be between 5 and 2147483647.${NC}"
			fi
		else
			echo -e "${ORANGE}Invalid format. Use 'min-max' for a range or a single number.${NC}"
		fi
	done
}

function readH1AndH2AndH3AndH4Ranges() {
	# Validate that generateH1AndH2AndH3AndH4Ranges was called first
	# These variables must be set before using them as defaults
	if [[ -z "${RANDOM_AWG_H1_MIN}" ]] || [[ -z "${RANDOM_AWG_H1_MAX}" ]] || \
	   [[ -z "${RANDOM_AWG_H2_MIN}" ]] || [[ -z "${RANDOM_AWG_H2_MAX}" ]] || \
	   [[ -z "${RANDOM_AWG_H3_MIN}" ]] || [[ -z "${RANDOM_AWG_H3_MAX}" ]] || \
	   [[ -z "${RANDOM_AWG_H4_MIN}" ]] || [[ -z "${RANDOM_AWG_H4_MAX}" ]]; then
		echo -e "${RED}ERROR: H1-H4 random ranges not initialized. Call generateH1AndH2AndH3AndH4Ranges first.${NC}"
		exit 1
	fi
	
	local H_NAMES=("H1" "H2" "H3" "H4")
	local RANDOM_MINS=("${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H4_MIN}")
	local RANDOM_MAXS=("${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H2_MAX}" "${RANDOM_AWG_H3_MAX}" "${RANDOM_AWG_H4_MAX}")
	
	for i in "${!H_NAMES[@]}"; do
		local H_NAME="${H_NAMES[$i]}"
		local VALID=0
		
		until [[ ${VALID} == 1 ]]; do
			readHRange "${H_NAME}" "${RANDOM_MINS[$i]}" "${RANDOM_MAXS[$i]}"
			VALID=1
			
			# Check for overlap with all previously defined ranges (skip for first range)
			if (( i > 0 )); then
				for (( j = 0; j < i; j++ )); do
					local PREV_H="${H_NAMES[$j]}"
					local PREV_MIN_VAR="SERVER_AWG_${PREV_H}_MIN"
					local PREV_MAX_VAR="SERVER_AWG_${PREV_H}_MAX"
					local CURR_MIN_VAR="SERVER_AWG_${H_NAME}_MIN"
					local CURR_MAX_VAR="SERVER_AWG_${H_NAME}_MAX"
					
					if rangesOverlap "${!PREV_MIN_VAR}" "${!PREV_MAX_VAR}" "${!CURR_MIN_VAR}" "${!CURR_MAX_VAR}"; then
						echo -e "${ORANGE}${H_NAME} range overlaps with ${PREV_H}. Please enter a non-overlapping range.${NC}"
						VALID=0
						break
					fi
				done
			fi
		done
	done
	
	# Set the final SERVER_AWG_H* variables (combined min-max format for config files)
	SERVER_AWG_H1="${SERVER_AWG_H1_MIN}-${SERVER_AWG_H1_MAX}"
	SERVER_AWG_H2="${SERVER_AWG_H2_MIN}-${SERVER_AWG_H2_MAX}"
	SERVER_AWG_H3="${SERVER_AWG_H3_MIN}-${SERVER_AWG_H3_MAX}"
	SERVER_AWG_H4="${SERVER_AWG_H4_MIN}-${SERVER_AWG_H4_MAX}"
}

# Helper function to convert a single H value to range format if needed
# Validates that the value is numeric and within bounds [5-2147483647]
#
# Return codes (non-standard to convey conversion status):
#   0 = CONVERTED:    Conversion was needed and successful
#   1 = NO_CHANGE:    No conversion needed (empty or already valid range format)
#   2 = INVALID:      Validation failed (caller should regenerate the value)
function convertHToRangeIfNeeded() {
	local VAR_NAME=$1
	local VALUE=${!VAR_NAME}
	
	# No conversion needed if empty
	if [[ -z "${VALUE}" ]]; then
		return 1  # NO_CHANGE
	fi
	
	if [[ "${VALUE}" =~ ^[0-9]+-[0-9]+$ ]]; then
		# Already in range format - validate the range
		local RANGE_MIN RANGE_MAX
		if parseRange "${VALUE}" "RANGE_MIN" "RANGE_MAX"; then
			if validateRange "${RANGE_MIN}" "${RANGE_MAX}" 5 2147483647; then
				return 1  # NO_CHANGE (valid range format)
			fi
		fi
		return 2  # INVALID (malformed range)
	fi
	
	# Single value - validate it's numeric and within bounds
	if [[ "${VALUE}" =~ ^[0-9]+$ ]]; then
		# Force base-10 interpretation to avoid octal issues
		local NUM_VALUE=$((10#${VALUE}))
		if (( NUM_VALUE >= 5 )) && (( NUM_VALUE <= 2147483647 )); then
			# Valid single value - convert to range format
			printf -v "$VAR_NAME" '%s' "${NUM_VALUE}-${NUM_VALUE}"
			return 0  # CONVERTED
		fi
	fi
	
	return 2  # INVALID (non-numeric or out of bounds)
}

function installQuestions() {
	# Non-interactive mode: use environment variable overrides or sensible defaults
	# Set AUTO_INSTALL=y to skip all prompts
	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		SERVER_PUB_IP=${SERVER_PUB_IP:-$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)}
		if [[ -z "${SERVER_PUB_IP}" ]]; then
			SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
		fi
		if [[ -z "${SERVER_PUB_IP}" ]]; then
			echo -e "${RED}ERROR: Could not detect public IP address. Set SERVER_PUB_IP and rerun.${NC}"
			exit 1
		fi

		SERVER_PUB_NIC=${SERVER_PUB_NIC:-$(ip -4 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}' | head -1)}
		if [[ -z "${SERVER_PUB_NIC}" ]]; then
			SERVER_PUB_NIC=$(ip -6 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}' | head -1)
		fi
		if [[ -z "${SERVER_PUB_NIC}" ]]; then
			echo -e "${RED}ERROR: Could not detect public interface. Set SERVER_PUB_NIC and rerun.${NC}"
			exit 1
		fi

		SERVER_AWG_NIC=${SERVER_AWG_NIC:-awg0}
		SERVER_AWG_IPV4=${SERVER_AWG_IPV4:-10.66.66.1}
		SERVER_AWG_IPV6=${SERVER_AWG_IPV6:-fd42:42:42::1}
		SERVER_PORT=${SERVER_PORT:-$(shuf -i49152-65535 -n1)}
		CLIENT_DNS_1=${CLIENT_DNS_1:-1.1.1.1}
		# Use ${var-default} (not ${var:-default}) so an explicitly empty CLIENT_DNS_2
		# is honored (skip second resolver), matching the interactive flow.
		CLIENT_DNS_2=${CLIENT_DNS_2-1.0.0.1}
		ALLOWED_IPS=${ALLOWED_IPS:-0.0.0.0/0,::/0}

		# Validate all overrides with the same checks used in the interactive flow.
		# These values end up in iptables rules, systemd unit paths, and config files,
		# so unsafe characters (shell metacharacters, path separators, whitespace)
		# could enable command injection or path traversal.
		if ! [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_.-]+$ ]]; then
			echo -e "${RED}ERROR: SERVER_PUB_NIC contains invalid characters: ${SERVER_PUB_NIC}${NC}"
			exit 1
		fi
		if ! [[ ${SERVER_AWG_NIC} =~ ^[a-zA-Z0-9_.-]+$ ]] || [[ ${#SERVER_AWG_NIC} -ge 16 ]]; then
			echo -e "${RED}ERROR: SERVER_AWG_NIC is invalid (must be alphanumeric/._- and < 16 chars): ${SERVER_AWG_NIC}${NC}"
			exit 1
		fi
		if ! [[ ${SERVER_AWG_IPV4} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			echo -e "${RED}ERROR: SERVER_AWG_IPV4 is not a valid IPv4 address: ${SERVER_AWG_IPV4}${NC}"
			exit 1
		fi
		if ! isValidIPv6 "${SERVER_AWG_IPV6}"; then
			echo -e "${RED}ERROR: Invalid IPv6 address specified in SERVER_AWG_IPV6: ${SERVER_AWG_IPV6}.${NC}"
			exit 1
		fi
		if ! [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] || (( SERVER_PORT < 1 )) || (( SERVER_PORT > 65535 )); then
			echo -e "${RED}ERROR: SERVER_PORT must be a number between 1 and 65535: ${SERVER_PORT}${NC}"
			exit 1
		fi
		if ! [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			echo -e "${RED}ERROR: CLIENT_DNS_1 is not a valid IPv4 address: ${CLIENT_DNS_1}${NC}"
			exit 1
		fi
		if [[ -n "${CLIENT_DNS_2}" ]] && ! [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			echo -e "${RED}ERROR: CLIENT_DNS_2 is not a valid IPv4 address: ${CLIENT_DNS_2}${NC}"
			exit 1
		fi

		SERVER_AWG_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")

		SERVER_AWG_JC=$(shuf -i3-10 -n1)
		SERVER_AWG_JMIN=50
		SERVER_AWG_JMAX=1000

		generateS1AndS2
		while (( RANDOM_AWG_S1 + 56 == RANDOM_AWG_S2 )) || (( RANDOM_AWG_S2 + 56 == RANDOM_AWG_S1 )); do
			generateS1AndS2
		done
		SERVER_AWG_S1=${RANDOM_AWG_S1}
		SERVER_AWG_S2=${RANDOM_AWG_S2}

		generateS3AndS4
		while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); do
			generateS3AndS4
		done
		SERVER_AWG_S3=${RANDOM_AWG_S3}
		SERVER_AWG_S4=${RANDOM_AWG_S4}

		generateH1AndH2AndH3AndH4Ranges
		SERVER_AWG_H1="${RANDOM_AWG_H1_MIN}-${RANDOM_AWG_H1_MAX}"
		SERVER_AWG_H2="${RANDOM_AWG_H2_MIN}-${RANDOM_AWG_H2_MAX}"
		SERVER_AWG_H3="${RANDOM_AWG_H3_MIN}-${RANDOM_AWG_H3_MAX}"
		SERVER_AWG_H4="${RANDOM_AWG_H4_MIN}-${RANDOM_AWG_H4_MAX}"

		return
	fi

	# Reset all interactive variables to prevent pre-set environment variables
	# from bypassing prompt validation loops
	SERVER_PUB_IP=""
	SERVER_PUB_NIC=""
	SERVER_AWG_NIC=""
	SERVER_AWG_IPV4=""
	SERVER_AWG_IPV6=""
	SERVER_PORT=""
	CLIENT_DNS_1=""
	CLIENT_DNS_2=""
	ALLOWED_IPS=""
	SERVER_AWG_JC=""
	SERVER_AWG_JMIN=""
	SERVER_AWG_JMAX=""
	SERVER_AWG_S1=""
	SERVER_AWG_S2=""
	SERVER_AWG_S3=""
	SERVER_AWG_S4=""

	echo "AmneziaWG server installer (https://github.com/wiresock/amneziawg-install)"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z "${SERVER_PUB_IP}" ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "Public IPv4 or IPv6 address or domain: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	# Extract the token after 'dev' to handle both 'default via ... dev <if>'
	# and 'default dev <if>' (no gateway) route formats
	SERVER_NIC="$(ip -4 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}' | head -1)"
	if [[ -z "${SERVER_NIC}" ]]; then
		# Fallback to IPv6 default route for IPv6-only servers
		SERVER_NIC="$(ip -6 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}' | head -1)"
	fi
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_.-]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_AWG_NIC} =~ ^[a-zA-Z0-9_.-]+$ && ${#SERVER_AWG_NIC} -lt 16 ]]; do
		read -rp "AmneziaWG interface name: " -e -i awg0 SERVER_AWG_NIC
	done

	until [[ ${SERVER_AWG_IPV4} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Server AmneziaWG IPv4: " -e -i 10.66.66.1 SERVER_AWG_IPV4
	done

	until isValidIPv6 "${SERVER_AWG_IPV6}"; do
		read -rp "Server AmneziaWG IPv6: " -e -i fd42:42:42::1 SERVER_AWG_IPV6
	done
	# Normalize to expanded form for consistent storage and comparison
	SERVER_AWG_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [[ "${SERVER_PORT}" -ge 1 ]] && [[ "${SERVER_PORT}" -le 65535 ]]; do
		read -rp "Server AmneziaWG port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Adguard DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	while true; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		# Accept empty input (skip second DNS) or a valid IPv4 address
		if [[ -z "${CLIENT_DNS_2}" ]] || [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			break
		fi
		echo -e "${ORANGE}Invalid IPv4 address. Enter a valid address or leave empty to skip.${NC}"
	done

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nAmneziaWG uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="0.0.0.0/0,::/0"
		fi
	done

	# Jc
	RANDOM_AWG_JC=$(shuf -i3-10 -n1)
	until [[ ${SERVER_AWG_JC} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JC} >= 1 )) && (( ${SERVER_AWG_JC} <= 128 )); do
		read -rp "Server AmneziaWG Jc [1-128]: " -e -i "${RANDOM_AWG_JC}" SERVER_AWG_JC
	done

	# Jmin && Jmax
	# Note: Jmin == Jmax is valid - it results in fixed-size junk packets rather than
	# randomized sizes within a range. The protocol accepts Jmin <= Jmax.
	readJminAndJmax
	until [[ "${SERVER_AWG_JMIN}" -le "${SERVER_AWG_JMAX}" ]]; do
		echo "Jmin must be less than or equal to Jmax"
		readJminAndJmax
	done

	# S1 && S2
	# Note: The constraints S1 + 56 != S2 and S2 + 56 != S1 are required by the AmneziaWG
	# protocol to ensure proper packet obfuscation. The value 56 is the WireGuard handshake
	# initiation message size, and this offset must be avoided in both directions.
	generateS1AndS2
	while (( ${RANDOM_AWG_S1} + 56 == ${RANDOM_AWG_S2} )) || (( ${RANDOM_AWG_S2} + 56 == ${RANDOM_AWG_S1} )); do
		generateS1AndS2
	done
	readS1AndS2
	while (( ${SERVER_AWG_S1} + 56 == ${SERVER_AWG_S2} )) || (( ${SERVER_AWG_S2} + 56 == ${SERVER_AWG_S1} )); do
		echo "AmneziaWG requires S1 + 56 != S2 and S2 + 56 != S1"
		readS1AndS2
	done

	# S3 && S4 (AmneziaWG 2.0)
	# Note: Same constraint as S1/S2 - the 56-byte offset must be avoided in both directions
	echo -e "\n${GREEN}AmneziaWG 2.0 Features:${NC}"
	generateS3AndS4
	while (( ${RANDOM_AWG_S3} + 56 == ${RANDOM_AWG_S4} )) || (( ${RANDOM_AWG_S4} + 56 == ${RANDOM_AWG_S3} )); do
		generateS3AndS4
	done
	readS3AndS4
	while (( ${SERVER_AWG_S3} + 56 == ${SERVER_AWG_S4} )) || (( ${SERVER_AWG_S4} + 56 == ${SERVER_AWG_S3} )); do
		echo "AmneziaWG requires S3 + 56 != S4 and S4 + 56 != S3"
		readS3AndS4
	done

	# H1-H4 Ranged Headers (AmneziaWG 2.0)
	echo -e "\n${GREEN}H1-H4 Ranged Headers (ranges must not overlap):${NC}"
	generateH1AndH2AndH3AndH4Ranges
	readH1AndH2AndH3AndH4Ranges

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your AmneziaWG server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

function installAmneziaWG() {
	# Run setup questions first
	installQuestions

	# Install AmneziaWG tools and module
	if [[ ${OS} == 'ubuntu' ]]; then
		if [[ -e /etc/apt/sources.list.d/ubuntu.sources ]]; then
			# Check whether any Types: line lacks deb-src. A single stanza with
			# deb-src shouldn't suppress source entries for other binary-only stanzas.
			if grep -q '^Types:' /etc/apt/sources.list.d/ubuntu.sources && \
			   grep '^Types:' /etc/apt/sources.list.d/ubuntu.sources | grep -qv 'deb-src'; then
				# Tag managed file with sentinel so uninstall can verify ownership
				echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources
				cat /etc/apt/sources.list.d/ubuntu.sources >> /etc/apt/sources.list.d/amneziawg.sources
				# Rewrite every Types field in the DEB822 copy to deb-src.
				# The guard above ensures at least one stanza is binary-only,
				# and transforming all stanzas to deb-src is harmless (apt deduplicates).
				sed -i 's/^Types: .*/Types: deb-src/' /etc/apt/sources.list.d/amneziawg.sources
				chmod 644 /etc/apt/sources.list.d/amneziawg.sources
			elif ! grep -q '^Types:' /etc/apt/sources.list.d/ubuntu.sources; then
				echo -e "${ORANGE}NOTE: /etc/apt/sources.list.d/ubuntu.sources has no Types: lines (unexpected format).${NC}"
				echo -e "${ORANGE}Skipping deb-src source generation. DKMS builds may fail if source repos are unavailable.${NC}"
			fi
		else
			if ! grep -q "^deb-src" /etc/apt/sources.list; then
				# Tag managed file with sentinel so uninstall can verify ownership
				echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources.list
				cat /etc/apt/sources.list >> /etc/apt/sources.list.d/amneziawg.sources.list
				# Anchor to line-start 'deb' followed by whitespace to avoid matching deb-src lines
				sed -i 's/^deb[[:space:]]\+/deb-src /' /etc/apt/sources.list.d/amneziawg.sources.list
				chmod 644 /etc/apt/sources.list.d/amneziawg.sources.list
			fi
		fi
		apt-get update || { echo -e "${RED}ERROR: Failed to refresh APT package index.${NC}"; exit 1; }
		apt install -y software-properties-common || { echo -e "${RED}ERROR: Failed to install software-properties-common.${NC}"; exit 1; }
		add-apt-repository -y ppa:amnezia/ppa || { echo -e "${RED}ERROR: Failed to add Amnezia PPA.${NC}"; exit 1; }
		apt-get update || { echo -e "${RED}ERROR: Failed to update APT package index after adding Amnezia PPA.${NC}"; exit 1; }
		# Install kernel headers for the running kernel so DKMS can compile the module.
		# This is critical on Raspberry Pi / ARM where the default headers package
		# (linux-headers-generic) may not match the actual raspi kernel flavour.
		# Try several candidates in order: exact versioned headers, Raspberry Pi headers,
		# then the generic meta package as a last resort.
		HEADER_INSTALLED=0
		HEADER_CANDIDATES=("linux-headers-$(uname -r)" "raspberrypi-kernel-headers" "linux-headers-generic")
		for HEADER_PKG in "${HEADER_CANDIDATES[@]}"; do
			if apt install -y "${HEADER_PKG}"; then
				HEADER_INSTALLED=1
				break
			else
				echo -e "${ORANGE}WARNING: Failed to install kernel headers package '${HEADER_PKG}'. Trying next candidate...${NC}"
			fi
		done
		if [[ "${HEADER_INSTALLED}" -ne 1 ]]; then
			echo -e "${ORANGE}WARNING: Failed to install any suitable kernel headers package. DKMS module build may fail; continuing installation, but the amneziawg kernel module might not be available until headers are installed and the module is rebuilt.${NC}"
		fi
		apt install -y dkms iptables amneziawg amneziawg-tools qrencode || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -q "^deb-src" /etc/apt/sources.list; then
			# Tag managed file with sentinel so uninstall can verify ownership
			echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources.list
			cat /etc/apt/sources.list >> /etc/apt/sources.list.d/amneziawg.sources.list
			# Convert deb lines to deb-src, tolerating any whitespace while skipping existing deb-src lines
			sed -i -E '/^[[:space:]]*deb-src[[:space:]]/!s/^[[:space:]]*deb[[:space:]]+/deb-src /' /etc/apt/sources.list.d/amneziawg.sources.list
			chmod 644 /etc/apt/sources.list.d/amneziawg.sources.list
		fi
		# Ensure required tools are available for key download/dearmor on minimal systems
		if ! command -v gpg &>/dev/null; then
			apt-get update
			apt-get install -y gnupg || { echo -e "${RED}ERROR: Failed to install gnupg required for key import.${NC}"; exit 1; }
		fi
		if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
			apt-get update
			apt-get install -y curl || { echo -e "${RED}ERROR: Failed to install curl required for key download.${NC}"; exit 1; }
		fi
		mkdir -p /etc/apt/keyrings
		chmod 755 /etc/apt/keyrings
		# Full 40-character fingerprint of the AmneziaWG APT signing key.
		# Short key IDs (e.g., 0x57290828) are collision-prone; always fetch and
		# verify by full fingerprint to prevent keyserver substitution attacks.
		local AMNEZIAWG_APT_FPR="75C9DD72C799870E310542E24166F2C257290828"
		local KEY_URL="https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${AMNEZIAWG_APT_FPR}"
		local TMP_KEY_ASC
		TMP_KEY_ASC=$(mktemp /tmp/amneziawg-apt-key.XXXXXX) || { echo -e "${RED}ERROR: Failed to create temporary file for APT signing key.${NC}"; exit 1; }
		local KEY_FETCH_OK=0
		if command -v curl &>/dev/null; then
			curl -fsSL "${KEY_URL}" -o "${TMP_KEY_ASC}" && KEY_FETCH_OK=1
		elif command -v wget &>/dev/null; then
			wget -qO "${TMP_KEY_ASC}" "${KEY_URL}" && KEY_FETCH_OK=1
		fi
		if [[ ${KEY_FETCH_OK} -ne 1 ]] || [[ ! -s "${TMP_KEY_ASC}" ]]; then
			rm -f "${TMP_KEY_ASC}"
			echo -e "${RED}ERROR: Failed to download the AmneziaWG APT signing key.${NC}"
			echo -e "${ORANGE}Verify network connectivity and that curl/wget and gnupg are installed.${NC}"
			exit 1
		fi
		# Verify the downloaded key's fingerprint matches before importing.
		# This prevents importing a substituted key from a compromised keyserver.
		local DOWNLOADED_FPR
		DOWNLOADED_FPR=$(gpg --show-keys --with-colons "${TMP_KEY_ASC}" 2>/dev/null | awk -F: '/^fpr:/ { print $10; exit }')
		if [[ -z "${DOWNLOADED_FPR}" ]]; then
			rm -f "${TMP_KEY_ASC}"
			echo -e "${RED}ERROR: Unable to read fingerprint from downloaded AmneziaWG APT signing key.${NC}"
			exit 1
		fi
		if [[ "${DOWNLOADED_FPR^^}" != "${AMNEZIAWG_APT_FPR^^}" ]]; then
			rm -f "${TMP_KEY_ASC}"
			echo -e "${RED}ERROR: Downloaded key fingerprint (${DOWNLOADED_FPR}) does not match expected (${AMNEZIAWG_APT_FPR}).${NC}"
			echo -e "${ORANGE}The key may have been tampered with. Aborting.${NC}"
			exit 1
		fi
		# Fingerprint verified — import the key into the dedicated keyring
		local TMP_KEYRING
		TMP_KEYRING=$(mktemp /etc/apt/keyrings/amneziawg.gpg.tmp.XXXXXX) || {
			rm -f "${TMP_KEY_ASC}"
			echo -e "${RED}ERROR: Failed to create temporary file for AmneziaWG APT signing keyring.${NC}"
			exit 1
		}
		if ! gpg --dearmor < "${TMP_KEY_ASC}" > "${TMP_KEYRING}" 2>/dev/null; then
			rm -f "${TMP_KEY_ASC}" "${TMP_KEYRING}"
			echo -e "${RED}ERROR: Failed to import the AmneziaWG APT signing key into keyring.${NC}"
			exit 1
		fi
		rm -f "${TMP_KEY_ASC}"
		if [[ ! -s "${TMP_KEYRING}" ]]; then
			rm -f "${TMP_KEYRING}"
			echo -e "${RED}ERROR: AmneziaWG APT keyring file is empty after import.${NC}"
			exit 1
		fi
		chmod 644 "${TMP_KEYRING}"
		mv "${TMP_KEYRING}" /etc/apt/keyrings/amneziawg.gpg
		if [[ ! -s /etc/apt/keyrings/amneziawg.gpg ]]; then
			echo -e "${RED}ERROR: AmneziaWG APT keyring file is empty after import.${NC}"
			exit 1
		fi
		# Ensure the managed file exists with sentinel before appending PPA lines.
		# When /etc/apt/sources.list already has deb-src, the copy block above is
		# skipped and the file doesn't exist yet — without this guard the >> below
		# would create it without the sentinel, causing uninstall to leave it behind.
		if [[ ! -f /etc/apt/sources.list.d/amneziawg.sources.list ]]; then
			echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources.list
			chmod 644 /etc/apt/sources.list.d/amneziawg.sources.list
		fi
		# Append PPA repo lines only if not already present (idempotent on re-run)
		if ! grep -q 'ppa.launchpadcontent.net/amnezia/ppa' /etc/apt/sources.list.d/amneziawg.sources.list; then
			echo "deb [signed-by=/etc/apt/keyrings/amneziawg.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
			echo "deb-src [signed-by=/etc/apt/keyrings/amneziawg.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		fi
		apt update
		# Try to install appropriate kernel headers, but don't hard-fail if the
		# exact versioned package is unavailable (e.g., on some Raspberry Pi kernels).
		HEADER_PKG=""
		if apt-cache show "linux-headers-$(uname -r)" >/dev/null 2>&1; then
			HEADER_PKG="linux-headers-$(uname -r)"
		elif apt-cache show raspberrypi-kernel-headers >/dev/null 2>&1; then
			HEADER_PKG="raspberrypi-kernel-headers"
		fi

		if [[ -n "${HEADER_PKG}" ]]; then
			apt install -y "${HEADER_PKG}" dkms amneziawg amneziawg-tools qrencode iptables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
		else
			echo -e "${ORANGE}WARNING: No suitable kernel headers package found. Continuing without installing headers; DKMS module builds may fail.${NC}"
			apt install -y dkms amneziawg amneziawg-tools qrencode iptables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
		fi
	elif [[ ${OS} == 'fedora' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		if ! dnf install -y "kernel-devel-$(uname -r)"; then
			echo -e "${ORANGE}WARNING: Failed to install kernel-devel for the running kernel ($(uname -r)). Attempting to install the latest kernel-devel instead.${NC}"
			if ! dnf install -y kernel-devel; then
				echo -e "${ORANGE}WARNING: Failed to install any kernel-devel package. Continuing without kernel headers; DKMS module builds may fail until headers are installed and the system is rebooted.${NC}"
			fi
		fi
		dnf install -y dkms amneziawg-dkms amneziawg-tools qrencode iptables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		if ! dnf install -y "kernel-devel-$(uname -r)"; then
			echo -e "${ORANGE}WARNING: Failed to install kernel-devel for the running kernel ($(uname -r)). Attempting to install the latest kernel-devel instead.${NC}"
			if ! dnf install -y kernel-devel; then
				echo -e "${ORANGE}WARNING: Failed to install any kernel-devel package. Continuing without kernel headers; DKMS module builds may fail until headers are installed and the system is rebooted.${NC}"
			fi
		fi
		dnf install -y dkms amneziawg-dkms amneziawg-tools qrencode iptables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	fi

	# Force DKMS to build the module
	# The package post-install hook may not trigger if headers were installed in the
	# same apt transaction, so an explicit autoinstall guarantees the .ko is present.
	if command -v dkms &>/dev/null; then
		dkms autoinstall || true
	fi

	# Rebuild module dependency cache (required for DKMS + compressed modules, especially on ARM/Ubuntu)
	if command -v depmod &>/dev/null; then
		if ! depmod -a; then
			echo -e "${ORANGE}WARNING: depmod -a failed. The kernel module may not load correctly.${NC}"
			echo -e "${ORANGE}You may need to reboot after installation.${NC}"
		fi
	else
		echo -e "${ORANGE}WARNING: depmod not found. Skipping module dependency cache rebuild.${NC}"
	fi

	# Ensure AmneziaWG kernel module is loaded at boot (before awg-quick service starts)
	mkdir -p /etc/modules-load.d
	chmod 755 /etc/modules-load.d
	if ! grep -qx "amneziawg" /etc/modules-load.d/amneziawg.conf 2>/dev/null; then
		echo "amneziawg" >> /etc/modules-load.d/amneziawg.conf
	fi
	chmod 644 /etc/modules-load.d/amneziawg.conf

	# Ensure configuration directory exists
	mkdir -p "${AMNEZIAWG_DIR}"
	chmod 700 "${AMNEZIAWG_DIR}"

	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	SERVER_PRIV_KEY=$(awg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)

	# Restrict umask for sensitive file creation (private keys, server config)
	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077

	# Save WireGuard settings atomically: write to temp file then move into place
	PARAMS_TMP_FILE="$(mktemp "${AMNEZIAWG_DIR}/params.XXXXXX")" || { echo -e "${RED}ERROR: Failed to create temporary params file.${NC}"; exit 1; }
	serializeParams "${PARAMS_TMP_FILE}" || { echo -e "${RED}ERROR: Failed to write params file.${NC}"; rm -f "${PARAMS_TMP_FILE}"; exit 1; }
	if ! mv -f "${PARAMS_TMP_FILE}" "${AMNEZIAWG_DIR}/params"; then
		echo -e "${RED}ERROR: Failed to move params file into place.${NC}"
		rm -f "${PARAMS_TMP_FILE}"
		exit 1
	fi
	chmod 600 "${AMNEZIAWG_DIR}/params"

	# Add server interface
	echo "[Interface]
Address = ${SERVER_AWG_IPV4}/24,${SERVER_AWG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}" >"${SERVER_AWG_CONF}"
	chmod 600 "${SERVER_AWG_CONF}"

	# Restore default umask before creating system files and running services
	umask "${OLD_UMASK}"

	if systemctl is-active --quiet firewalld 2>/dev/null; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_AWG_IPV4}" | cut -d"." -f1-3)".0"
		# Derive /64 network address from the normalized IPv6 (first 4 groups + :0:0:0:0)
		FIREWALLD_IPV6_ADDRESS="$(echo "${SERVER_AWG_IPV6}" | cut -d':' -f1-4):0:0:0:0"
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'" >>"${SERVER_AWG_CONF}"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"${SERVER_AWG_CONF}"
	fi

	# Enable routing on the server
	mkdir -p /etc/sysctl.d
	chmod 755 /etc/sysctl.d
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/awg.conf
	chmod 644 /etc/sysctl.d/awg.conf

	sysctl -p /etc/sysctl.d/awg.conf

	# Add a systemd drop-in override that:
	#  - Ensures the amneziawg module is loaded before awg-quick starts (ExecStartPre)
	#  - Waits for network-online so the interface is available for routing
	# This survives reboots and kernel upgrades without manual intervention.
	mkdir -p "/etc/systemd/system/awg-quick@${SERVER_AWG_NIC}.service.d"
	chmod 755 "/etc/systemd/system/awg-quick@${SERVER_AWG_NIC}.service.d"
	cat > "/etc/systemd/system/awg-quick@${SERVER_AWG_NIC}.service.d/override.conf" <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=modprobe amneziawg
EOF
	chmod 644 "/etc/systemd/system/awg-quick@${SERVER_AWG_NIC}.service.d/override.conf"
	systemctl daemon-reload

	# Gate the service start on the kernel module actually being loadable.
	# If modprobe fails here, the module wasn't built for this kernel — starting
	# the service would just produce a confusing "Unknown device type" error.
	local MODULE_READY=0

	# Always enable the service so it starts on next boot. Even if modprobe fails
	# now (e.g., missing kernel headers), a reboot after installing headers or
	# running dkms autoinstall will load the module via the ExecStartPre override.
	systemctl enable "awg-quick@${SERVER_AWG_NIC}"

	if modprobe amneziawg; then
		systemctl start "awg-quick@${SERVER_AWG_NIC}"
		MODULE_READY=1
	else
		local HEADERS_HINT="matching kernel headers"
		local INSTALL_HINT="Install matching kernel headers"
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			HEADERS_HINT="linux-headers-$(uname -r)"
			INSTALL_HINT="apt install -y \"linux-headers-$(uname -r)\""
		elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			HEADERS_HINT="kernel-devel-$(uname -r)"
			INSTALL_HINT="dnf install -y \"kernel-devel-$(uname -r)\""
		fi

		echo -e "${RED}ERROR: amneziawg kernel module could not be loaded for kernel $(uname -r).${NC}"
		echo -e "${ORANGE}The service was NOT started but is enabled for next boot.${NC}"
		echo -e "${ORANGE}To fix:${NC}"
		echo -e "${ORANGE}  1. Ensure ${HEADERS_HINT} is installed${NC}"
		echo -e "${ORANGE}     ${INSTALL_HINT}${NC}"
		echo -e "${ORANGE}  2. Run: dkms autoinstall && depmod -a${NC}"
		echo -e "${ORANGE}  3. Run: modprobe amneziawg${NC}"
		echo -e "${ORANGE}  4. Run: systemctl start awg-quick@${SERVER_AWG_NIC}${NC}"
		echo -e "${ORANGE}  Or simply reboot the server.${NC}"
	fi

	if [[ ${MODULE_READY} -eq 1 ]]; then
		newClient
		echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"
	else
		echo -e "${ORANGE}Skipping client generation because the server interface is not active.${NC}"
	fi

	# Check if AmneziaWG is running
	systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
	AWG_RUNNING=$?

	# AmneziaWG might not work if we updated the kernel. Tell the user to reboot
	if [[ ${AWG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: AmneziaWG does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if AmneziaWG is running with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
		if ! lsmod | grep -q amneziawg; then
			local HEADERS_HINT="matching kernel headers"
			local INSTALL_HINT="Install matching kernel headers"
			if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
				HEADERS_HINT="linux-headers-$(uname -r)"
				INSTALL_HINT="apt install -y \"linux-headers-$(uname -r)\""
			elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
				HEADERS_HINT="kernel-devel-$(uname -r)"
				INSTALL_HINT="dnf install -y \"kernel-devel-$(uname -r)\""
			fi

			echo -e "${ORANGE}The amneziawg kernel module is NOT loaded.${NC}"
			echo -e "${ORANGE}This usually means the module was not built for kernel $(uname -r).${NC}"
			echo -e "${ORANGE}Install ${HEADERS_HINT} and rebuild: ${INSTALL_HINT} && dkms autoinstall && depmod -a${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_AWG_NIC}\", please reboot!${NC}"
	else # AmneziaWG is running
		echo -e "\n${GREEN}AmneziaWG is running.${NC}"
		echo -e "${GREEN}You can check the status of AmneziaWG with: systemctl status awg-quick@${SERVER_AWG_NIC}\n\n${NC}"
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	# Reset variables to ensure clean state for each new client
	local CLIENT_NAME=""
	local CLIENT_EXISTS=""
	local IPV4_EXISTS=""
	local IPV6_EXISTS=""
	local DOT_IP=""
	local DOT_EXISTS=""
	local BASE_IP=""

	# If SERVER_PUB_IP is IPv6, normalize brackets
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		SERVER_PUB_IP="${SERVER_PUB_IP#\[}"
		SERVER_PUB_IP="${SERVER_PUB_IP%\]}"
		SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	BASE_IP=$(echo "$SERVER_AWG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')

	# Precompute normalized server IPv6 and base prefix once, since SERVER_AWG_IPV6 is constant here.
	local NORMALIZED_SERVER_IPV6 BASE_IPV6
	NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
	BASE_IPV6=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)

	local FREE_DOT_IP_FOUND=0
	for DOT_IP in {2..254}; do
		# Check IPv4 address "${BASE_IP}.${DOT_IP}/32" is not already in use
		DOT_EXISTS=$(grep -cF "${BASE_IP}.${DOT_IP}/32" "${SERVER_AWG_CONF}")

		# Derive the would-be IPv6 client address in the same way as in AUTO_INSTALL
		# and ensure the corresponding /128 is also not already present.
		local CLIENT_IPV6_CANDIDATE
		CLIENT_IPV6_CANDIDATE=$(normalizeIPv6 "${BASE_IPV6}::${DOT_IP}")

		# Perform a semantic duplicate check: normalize existing /128 IPv6 addresses
		# before comparing, so compressed vs expanded forms are treated as equal.
		IPV6_EXISTS=0
		while IFS= read -r _existing_ip_cidr; do
			# Strip the /128 suffix to get the raw IPv6 address
			local _existing_ip="${_existing_ip_cidr%/*}"
			local _normalized_existing
			_normalized_existing=$(normalizeIPv6 "${_existing_ip}")
			if [[ "${_normalized_existing}" == "${CLIENT_IPV6_CANDIDATE}" ]]; then
				IPV6_EXISTS=1
				break
			fi
		done < <(grep -oE '([0-9a-fA-F:]+)/128' "${SERVER_AWG_CONF}")

		if [[ ${DOT_EXISTS} == '0' && ${IPV6_EXISTS} == '0' ]]; then
			FREE_DOT_IP_FOUND=1
			break
		fi
	done

	if [[ ${FREE_DOT_IP_FOUND} -eq 0 ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		# Auto mode: use default client name and first available IPs
		CLIENT_NAME="client"
		local CLIENT_NUM=2
		while [[ $(grep -c -xF "### Client ${CLIENT_NAME}" "${SERVER_AWG_CONF}") != 0 ]]; do
			CLIENT_NAME="client${CLIENT_NUM}"
			CLIENT_NUM=$((CLIENT_NUM + 1))
		done

		CLIENT_AWG_IPV4="${BASE_IP}.${DOT_IP}"

		local NORMALIZED_SERVER_IPV6 BASE_IPV6_PREFIX
		NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
		BASE_IPV6_PREFIX=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)
		CLIENT_AWG_IPV6=$(normalizeIPv6 "${BASE_IPV6_PREFIX}::${DOT_IP}")
	else
		echo ""
		echo "Client configuration"
		echo ""
		echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

		until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
			read -rp "Client name: " -e CLIENT_NAME
			CLIENT_EXISTS=$(grep -c -xF "### Client ${CLIENT_NAME}" "${SERVER_AWG_CONF}")

			if [[ ${CLIENT_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
				echo ""
			fi
		done

		until [[ ${IPV4_EXISTS} == '0' ]]; do
			read -rp "Client AmneziaWG IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP

			# Validate host number is between 2 and 254
			if ! [[ ${DOT_IP} =~ ^[0-9]+$ ]] || (( DOT_IP < 2 )) || (( DOT_IP > 254 )); then
				echo ""
				echo -e "${ORANGE}Invalid host number. Must be between 2 and 254.${NC}"
				echo ""
				IPV4_EXISTS='1'
				continue
			fi

			CLIENT_AWG_IPV4="${BASE_IP}.${DOT_IP}"
			IPV4_EXISTS=$(grep -cF "$CLIENT_AWG_IPV4/32" "${SERVER_AWG_CONF}")

			if [[ ${IPV4_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
				echo ""
			fi
		done

		# Normalize server IPv6 and extract /64 prefix (first 4 groups)
		local NORMALIZED_SERVER_IPV6
		NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
		BASE_IP=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)

		until [[ ${IPV6_EXISTS} == '0' ]]; do
			read -rp "Client AmneziaWG IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP

			# Validate IPv6 host part is a valid hex segment (1-4 hex characters)
			if ! [[ ${DOT_IP} =~ ^[a-fA-F0-9]{1,4}$ ]]; then
				echo ""
				echo -e "${ORANGE}Invalid IPv6 host part. Must be 1-4 hexadecimal characters.${NC}"
				echo ""
				IPV6_EXISTS='1'
				continue
			fi

			CLIENT_AWG_IPV6=$(normalizeIPv6 "${BASE_IP}::${DOT_IP}")
			# Semantic duplicate check: normalize all existing IPv6 in config for comparison
			IPV6_EXISTS=0
			local EXISTING_IPV6_RAW
			while IFS= read -r EXISTING_IPV6_RAW; do
				if [[ "$(normalizeIPv6 "${EXISTING_IPV6_RAW%/128}")" == "${CLIENT_AWG_IPV6}" ]]; then
					IPV6_EXISTS=1
					break
				fi
			done < <(grep -oE '[a-fA-F0-9:]+/128' "${SERVER_AWG_CONF}")

			if [[ ${IPV6_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
				echo ""
			fi
		done
	fi

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(awg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
	CLIENT_PRE_SHARED_KEY=$(awg genpsk)

	local HOME_DIR
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Build DNS line: include second resolver only if provided
	local CLIENT_DNS="${CLIENT_DNS_1}"
	if [[ -n "${CLIENT_DNS_2}" ]]; then
		CLIENT_DNS="${CLIENT_DNS_1},${CLIENT_DNS_2}"
	fi

	# Restrict umask for client config file creation (contains private key)
	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_AWG_IPV4}/32,${CLIENT_AWG_IPV6}/128
DNS = ${CLIENT_DNS}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# Restore default umask
	umask "${OLD_UMASK}"

	local client_conf owner_group sudo_home client_chown_ok client_chown_target client_primary_group sudo_chown_target sudo_primary_group
	client_conf="${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
	if ! chmod 600 "${client_conf}"; then
		echo "Warning: failed to set permissions on ${client_conf}" >&2
	fi

	# Ensure the generated client config is readable by the intended non-root user,
	# without unintentionally granting access to the sudo-invoking user.
	# Prefer:
	#   1. CLIENT_NAME, if it is a real system user.
	#   2. The owner of HOME_DIR.
	#   3. SUDO_USER, but only if HOME_DIR is SUDO_USER's home directory.

	# Try to determine the ownership of HOME_DIR, if stat is available.
	if command -v stat >/dev/null 2>&1; then
		owner_group="$(stat -c '%U:%G' "${HOME_DIR}" 2>/dev/null || true)"
	fi

	# 1. If CLIENT_NAME corresponds to an existing user, chown to that user.
	client_chown_ok=1
	if [ -n "${CLIENT_NAME:-}" ] && id -u "${CLIENT_NAME}" >/dev/null 2>&1; then
		client_chown_target="${CLIENT_NAME}"
		if command -v id >/dev/null 2>&1; then
			client_primary_group="$(id -gn "${CLIENT_NAME}" 2>/dev/null || true)"
			if [ -n "${client_primary_group}" ]; then
				client_chown_target="${CLIENT_NAME}:${client_primary_group}"
			fi
		fi
		if chown "${client_chown_target}" "${client_conf}" 2>/dev/null; then
			client_chown_ok=0
		fi
	fi

	# 2. If CLIENT_NAME chown did not succeed and we know the owner of HOME_DIR, match that ownership.
	if [ ${client_chown_ok} -ne 0 ] && [ -n "${owner_group:-}" ]; then
		if chown "${owner_group}" "${client_conf}" 2>/dev/null; then
			client_chown_ok=0
		fi
	fi

	# 3. As a last resort, fall back to SUDO_USER only when HOME_DIR is the sudo user's home.
	if [ ${client_chown_ok} -ne 0 ] && [ -n "${SUDO_USER:-}" ] && id -u "${SUDO_USER}" >/dev/null 2>&1; then
		if command -v getent >/dev/null 2>&1; then
			sudo_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
		fi
		if [ -n "${sudo_home:-}" ] && [ "${sudo_home}" = "${HOME_DIR}" ]; then
			sudo_chown_target="${SUDO_USER}"
			if command -v id >/dev/null 2>&1; then
				sudo_primary_group="$(id -gn "${SUDO_USER}" 2>/dev/null || true)"
				if [ -n "${sudo_primary_group}" ]; then
					sudo_chown_target="${SUDO_USER}:${sudo_primary_group}"
				fi
			fi
			chown "${sudo_chown_target}" "${client_conf}" || true
		fi
	fi

	# Add the client as a peer to the server
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_AWG_IPV4}/32,${CLIENT_AWG_IPV6}/128" >>"${SERVER_AWG_CONF}"

	awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
	local CLIENT_NUMBER=""
	until [[ ${CLIENT_NUMBER} =~ ^[0-9]+$ ]] && [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${NUMBER_OF_CLIENTS} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# Validate client name contains only characters safe for sed regex patterns.
	# Names created by this script are always [a-zA-Z0-9_-], but a manually
	# edited config could introduce regex metacharacters (e.g., '.', '*').
	if ! [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
		echo -e "${RED}ERROR: Client name '${CLIENT_NAME}' contains unsafe characters. Please fix the config manually.${NC}"
		exit 1
	fi

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

	# remove generated client file
	local HOME_DIR
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# restart AmneziaWG to apply changes
	awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
}

function regenerateClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	# If SERVER_PUB_IP is IPv6, normalize brackets
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		SERVER_PUB_IP="${SERVER_PUB_IP#\[}"
		SERVER_PUB_IP="${SERVER_PUB_IP%\]}"
		SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Regenerating all client configurations with current server parameters..."
	echo ""

	local REGENERATED=0
	local FAILED=0
	local NEWKEYS=0

	# Iterate over each client peer block in the server config
	while IFS= read -r CLIENT_NAME; do
		# Validate client name contains only characters safe for sed regex patterns.
		# Names created by this script are always [a-zA-Z0-9_-], but a manually
		# edited config could introduce regex metacharacters (e.g., '.', '*').
		if ! [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
			echo -e "${RED}  SKIP: '${CLIENT_NAME}' - name contains unsafe characters${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		# Extract peer details from the server config for this client
		# The block starts with "### Client <name>" and ends at the next empty line
		local PEER_BLOCK
		PEER_BLOCK=$(sed -n "/^### Client ${CLIENT_NAME}\$/,/^$/p" "${SERVER_AWG_CONF}")

		local CLIENT_PUB_KEY
		CLIENT_PUB_KEY=$(echo "${PEER_BLOCK}" | grep -E "^PublicKey = " | sed 's/^PublicKey = //')
		local CLIENT_PRE_SHARED_KEY
		CLIENT_PRE_SHARED_KEY=$(echo "${PEER_BLOCK}" | grep -E "^PresharedKey = " | sed 's/^PresharedKey = //')
		local CLIENT_ALLOWED_IPS
		CLIENT_ALLOWED_IPS=$(echo "${PEER_BLOCK}" | grep -E "^AllowedIPs = " | sed 's/^AllowedIPs = //')

		if [[ -z "${CLIENT_PUB_KEY}" ]] || [[ -z "${CLIENT_PRE_SHARED_KEY}" ]] || [[ -z "${CLIENT_ALLOWED_IPS}" ]]; then
			echo -e "${RED}  SKIP: ${CLIENT_NAME} - could not parse peer block from server config${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		# Parse IPv4 and IPv6 addresses from AllowedIPs (e.g., "10.66.66.2/32,fd42:42:42::2/128").
		# There may be multiple routes; select a single "client address" per family to avoid
		# multi-line values corrupting the generated Address = ... line.
		local CLIENT_AWG_IPV4
		local CLIENT_AWG_IPV4_CANDIDATES
		CLIENT_AWG_IPV4_CANDIDATES=$(echo "${CLIENT_ALLOWED_IPS}" \
			| tr ',' '\n' \
			| sed 's/^[[:space:]]*//' \
			| grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32([[:space:]]*$)' \
			| sed 's|/32[[:space:]]*$||')

		local CLIENT_AWG_IPV6
		local CLIENT_AWG_IPV6_CANDIDATES
		CLIENT_AWG_IPV6_CANDIDATES=$(echo "${CLIENT_ALLOWED_IPS}" \
			| tr ',' '\n' \
			| sed 's/^[[:space:]]*//' \
			| grep -E ':' \
			| grep -E '/128([[:space:]]*$)' \
			| sed 's|/128[[:space:]]*$||')

		if [[ -z "${CLIENT_AWG_IPV4_CANDIDATES}" ]]; then
			echo -e "${RED}  SKIP: ${CLIENT_NAME} - could not parse IPv4 from AllowedIPs${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		# Use the first IPv4/IPv6 candidate as the client address; warn if multiple exist.
		if [[ "$(echo "${CLIENT_AWG_IPV4_CANDIDATES}" | wc -l | tr -d ' ')" -gt 1 ]]; then
			echo -e "${ORANGE}  WARN: ${CLIENT_NAME} - multiple IPv4 entries in AllowedIPs; using first one${NC}"
		fi
		CLIENT_AWG_IPV4=$(echo "${CLIENT_AWG_IPV4_CANDIDATES}" | head -n 1)

		if [[ -n "${CLIENT_AWG_IPV6_CANDIDATES}" ]]; then
			if [[ "$(echo "${CLIENT_AWG_IPV6_CANDIDATES}" | wc -l | tr -d ' ')" -gt 1 ]]; then
				echo -e "${ORANGE}  WARN: ${CLIENT_NAME} - multiple IPv6 entries in AllowedIPs; using first one${NC}"
			fi
			CLIENT_AWG_IPV6=$(echo "${CLIENT_AWG_IPV6_CANDIDATES}" | head -n 1)
		else
			CLIENT_AWG_IPV6=""
		fi

		# Build address string, including IPv6 only if present in AllowedIPs
		local CLIENT_ADDRESS="${CLIENT_AWG_IPV4}/32"
		if [[ -n "${CLIENT_AWG_IPV6}" ]]; then
			CLIENT_ADDRESS="${CLIENT_ADDRESS},${CLIENT_AWG_IPV6}/128"
		fi

		# Determine home directory and locate existing client config file
		local HOME_DIR
		HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
		# CLIENT_CONF is the canonical "home-based" path for this client's config.
		local CLIENT_CONF
		# CLIENT_CONF_OUTPUT is the path we will ultimately write the regenerated
		# config to. By default it matches CLIENT_CONF, but if we discover an
		# existing config in another location (one of the candidates below),
		# later code should update CLIENT_CONF_OUTPUT to that path so that the
		# regenerated config overwrites/updates the file we actually used to
		# recover the client's private key.
		local CLIENT_CONF_OUTPUT=""
		if [[ -n "${HOME_DIR}" ]]; then
			CLIENT_CONF="${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
			CLIENT_CONF_OUTPUT="${CLIENT_CONF}"
		else
			# If HOME_DIR could not be determined, leave CLIENT_CONF empty and let
			# later logic choose an appropriate output path based on where an
			# existing config is actually found (if any).
			CLIENT_CONF=""
		fi
		local CLIENT_PRIV_KEY=""

		# Try to recover the client's private key from an existing config file.
		# Search multiple common locations to avoid regenerating keys just because
		# getHomeDirForClient guessed a different home than where the config was created.
		local -a CLIENT_CONF_CANDIDATES=()

		# 1) Config under the resolved HOME_DIR (if any)
		if [[ -n "${CLIENT_CONF}" ]]; then
			CLIENT_CONF_CANDIDATES+=("${CLIENT_CONF}" "${CLIENT_CONF}.old")
		fi

		# 2) Root's home (common when run as root or via sudo)
		if [[ -d "/root" ]]; then
			CLIENT_CONF_CANDIDATES+=("/root/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf" \
									 "/root/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf.old")
		fi

		# 3) All user homes under /home
		for SEARCH_DIR in /home/*; do
			if [[ -d "${SEARCH_DIR}" ]]; then
				CLIENT_CONF_CANDIDATES+=("${SEARCH_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf" \
										 "${SEARCH_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf.old")
			fi
		done

		# Scan candidate config files (including .conf.old, renamed during migration)
		local MATCHED_CONF=""
		for CANDIDATE in "${CLIENT_CONF_CANDIDATES[@]}"; do
			if [[ -f "${CANDIDATE}" ]]; then
				CLIENT_PRIV_KEY=$(grep -E "^PrivateKey = " "${CANDIDATE}" | sed 's/^PrivateKey = //')
				if [[ -n "${CLIENT_PRIV_KEY}" ]]; then
					MATCHED_CONF="${CANDIDATE}"
					break
				fi
			fi
		done

		# If we recovered an existing private key, align CLIENT_CONF_OUTPUT
		# with the location where that key/config was found. If the matched
		# config is a ".conf.old", strip the suffix so we regenerate the
		# non-.old config in the same directory.
		if [[ -n "${CLIENT_PRIV_KEY}" && -n "${MATCHED_CONF}" ]]; then
			if [[ "${MATCHED_CONF}" == *.old ]]; then
				CLIENT_CONF_OUTPUT="${MATCHED_CONF%.old}"
			else
				CLIENT_CONF_OUTPUT="${MATCHED_CONF}"
			fi
		fi

		if [[ -z "${CLIENT_PRIV_KEY}" ]]; then
			# No existing private key found - generate a new key pair
			# This means the client will need the new config to reconnect
			echo -e "${ORANGE}  ${CLIENT_NAME}: no existing private key found, generating new key pair${NC}"
			CLIENT_PRIV_KEY=$(awg genkey)
			local NEW_CLIENT_PUB_KEY
			NEW_CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)

			# Update the server config with the new public key
			sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/ s|^PublicKey = .*|PublicKey = ${NEW_CLIENT_PUB_KEY}|" "${SERVER_AWG_CONF}"
			CLIENT_PUB_KEY="${NEW_CLIENT_PUB_KEY}"
			NEWKEYS=$((NEWKEYS + 1))
		fi

		# Build DNS line: include second resolver only if provided
		local CLIENT_DNS="${CLIENT_DNS_1}"
		if [[ -n "${CLIENT_DNS_2}" ]]; then
			CLIENT_DNS="${CLIENT_DNS_1},${CLIENT_DNS_2}"
		fi

		# Write the new client config file with current server parameters
		local OUTPUT_CONF="${CLIENT_CONF_OUTPUT:-$CLIENT_CONF}"
		local TMP_CONF

		# Ensure parent directory for the output config exists
		if ! mkdir -p "$(dirname "${OUTPUT_CONF}")"; then
			echo -e "${RED}  ${CLIENT_NAME}: failed to create directory for client config (${OUTPUT_CONF})${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		TMP_CONF="$(mktemp "$(dirname "${OUTPUT_CONF}")/.$(basename "${OUTPUT_CONF}").tmp.XXXXXX")" || {
			echo -e "${RED}  ${CLIENT_NAME}: failed to create temporary file for client config (${OUTPUT_CONF})${NC}"
			FAILED=$((FAILED + 1))
			continue
		}

		if cat <<EOF >"${TMP_CONF}" && chmod 600 "${TMP_CONF}" && mv "${TMP_CONF}" "${OUTPUT_CONF}"; then
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_ADDRESS}
DNS = ${CLIENT_DNS}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}
EOF

		# If running as root and the output directory is owned by a non-root user,
		# ensure the regenerated client config is owned by that user so they can
		# actually read it (while keeping permissions at 600).
		if [ "$(id -u)" -eq 0 ]; then
			local OUTPUT_OWNER_GROUP OUTPUT_OWNER
			OUTPUT_OWNER_GROUP="$(stat -c '%U:%G' "$(dirname "${OUTPUT_CONF}")" 2>/dev/null || echo "")"
			OUTPUT_OWNER="${OUTPUT_OWNER_GROUP%%:*}"
			if [ -n "${OUTPUT_OWNER_GROUP}" ] && [ -n "${OUTPUT_OWNER}" ] && [ "${OUTPUT_OWNER}" != "root" ]; then
				chown "${OUTPUT_OWNER_GROUP}" "${OUTPUT_CONF}" 2>/dev/null || :
			fi
		fi

		# Regeneration succeeded; existing client config has been updated.

		# Generate QR code if qrencode is installed
		if command -v qrencode &>/dev/null; then
			echo -e "${GREEN}  ${CLIENT_NAME}: regenerated (QR code below)${NC}"
			qrencode -t ansiutf8 -l L <"${OUTPUT_CONF}"
		else
			echo -e "${GREEN}  ${CLIENT_NAME}: regenerated -> ${OUTPUT_CONF}${NC}"
		fi

		REGENERATED=$((REGENERATED + 1))
	else
		# Cleanup temporary file on failure to avoid leaking sensitive data
		rm -f "${TMP_CONF}"
		echo -e "${RED}  ${CLIENT_NAME}: failed to regenerate client config, existing config left unchanged.${NC}"
		FAILED=$((FAILED + 1))
	fi
	done < <(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3)

	# If any server-side peer keys were updated, sync the running config
	if (( NEWKEYS > 0 )); then
		awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
	fi

	echo ""
	echo -e "${GREEN}Regeneration complete: ${REGENERATED} succeeded, ${FAILED} failed.${NC}"
	if (( NEWKEYS > 0 )); then
		echo -e "${ORANGE}${NEWKEYS} client(s) had new key pairs generated (old private key was not found).${NC}"
	fi
	echo -e "${ORANGE}Distribute the new .conf files to your clients.${NC}"
}

function uninstallAmneziaWG() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/amnezia/amneziawg directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == [yY] ]]; then
		checkOS

		systemctl stop "awg-quick@${SERVER_AWG_NIC}"
		systemctl disable "awg-quick@${SERVER_AWG_NIC}"

		# Remove systemd drop-in override created during install
		DROPIN_DIR="/etc/systemd/system/awg-quick@${SERVER_AWG_NIC:?}.service.d"
		OVERRIDE_FILE="${DROPIN_DIR}/override.conf"
		if [[ -f "${OVERRIDE_FILE}" ]]; then
			rm -f "${OVERRIDE_FILE}"
		fi
		# Remove drop-in directory only if empty to avoid deleting user-managed files
		if [[ -d "${DROPIN_DIR}" ]] && [[ -z "$(ls -A "${DROPIN_DIR}")" ]]; then
			rmdir "${DROPIN_DIR}"
		fi
		systemctl daemon-reload

		# Remove module auto-load entry
		rm -f /etc/modules-load.d/amneziawg.conf

		# Disable routing
		# Only remove our conf file; do NOT force ip_forward=0 at runtime because
		# other services (Docker, libvirt, other VPNs) may depend on forwarding.
		# The setting will revert to the system default on next reboot.
		rm -f /etc/sysctl.d/awg.conf

		# Remove config files
		rm -rf "${AMNEZIAWG_DIR:?}"

		if [[ ${OS} == 'ubuntu' ]]; then
			apt remove -y amneziawg amneziawg-tools
			add-apt-repository -ry ppa:amnezia/ppa
			# Only remove source files that we created (identified by sentinel comment)
			if [[ -e /etc/apt/sources.list.d/ubuntu.sources ]]; then
				if [[ -f /etc/apt/sources.list.d/amneziawg.sources ]] && head -1 /etc/apt/sources.list.d/amneziawg.sources | grep -q '# Managed by amneziawg-install'; then
					rm -f /etc/apt/sources.list.d/amneziawg.sources
				elif [[ -f /etc/apt/sources.list.d/amneziawg.sources ]]; then
					echo -e "${ORANGE}NOTE: /etc/apt/sources.list.d/amneziawg.sources was not created by this installer (missing sentinel). Leaving it in place.${NC}"
				fi
			else
				if [[ -f /etc/apt/sources.list.d/amneziawg.sources.list ]] && head -1 /etc/apt/sources.list.d/amneziawg.sources.list | grep -q '# Managed by amneziawg-install'; then
					rm -f /etc/apt/sources.list.d/amneziawg.sources.list
				elif [[ -f /etc/apt/sources.list.d/amneziawg.sources.list ]]; then
					echo -e "${ORANGE}NOTE: /etc/apt/sources.list.d/amneziawg.sources.list was not created by this installer (missing sentinel). Leaving it in place.${NC}"
				fi
			fi
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y amneziawg amneziawg-tools
			# Only remove source file and keyring if the source file has our sentinel on line 1
			if [[ -f /etc/apt/sources.list.d/amneziawg.sources.list ]] && head -1 /etc/apt/sources.list.d/amneziawg.sources.list | grep -q '# Managed by amneziawg-install'; then
				rm -f /etc/apt/sources.list.d/amneziawg.sources.list
				rm -f /etc/apt/keyrings/amneziawg.gpg
			elif [[ -f /etc/apt/sources.list.d/amneziawg.sources.list ]]; then
				echo -e "${ORANGE}NOTE: /etc/apt/sources.list.d/amneziawg.sources.list was not created by this installer (missing sentinel). Leaving it and keyring in place.${NC}"
			elif [[ -f /etc/apt/keyrings/amneziawg.gpg ]]; then
				# Source file is gone (manually deleted) but orphaned keyring remains
				echo -e "${ORANGE}NOTE: Managed source file not found but orphaned keyring detected. Removing keyring.${NC}"
				rm -f /etc/apt/keyrings/amneziawg.gpg
			fi
			apt update
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		fi

		# Check if AmneziaWG is running
		systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
		AWG_RUNNING=$?

		if [[ ${AWG_RUNNING} -eq 0 ]]; then
			echo "AmneziaWG failed to uninstall properly."
			exit 1
		else
			echo "AmneziaWG uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function validateParamsFile() {
	# Security: verify params file is safe to source (owned by root, not readable/writable by others)
	# This mitigates the risk of arbitrary code execution or private key exposure
	# Reject symlinks explicitly so we don't accidentally source an unexpected file via a link.
	if [[ -L "${AMNEZIAWG_DIR}/params" ]] || [[ -h "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file must not be a symbolic link: ${AMNEZIAWG_DIR}/params${NC}"
		echo -e "${ORANGE}Remove the symlink and create a regular file owned by root with mode 600 or 400.${NC}"
		return 1
	fi
	if [[ ! -f "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file not found or is not a regular file: ${AMNEZIAWG_DIR}/params${NC}"
		echo -e "${ORANGE}The installer cannot continue without a valid params file.${NC}"
		return 1
	fi
	if [[ ! -r "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file is not readable: ${AMNEZIAWG_DIR}/params${NC}"
		echo -e "${ORANGE}Ensure the file is readable by root and try again.${NC}"
		return 1
	fi
	local PARAMS_OWNER PARAMS_PERMS
	PARAMS_OWNER=$(stat -c '%u' "${AMNEZIAWG_DIR}/params" 2>/dev/null)
	PARAMS_PERMS=$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null)
	if [[ -z "${PARAMS_OWNER}" ]] || [[ -z "${PARAMS_PERMS}" ]]; then
		echo -e "${RED}ERROR: Failed to read file metadata for ${AMNEZIAWG_DIR}/params.${NC}"
		echo -e "${ORANGE}Ensure the file exists and is accessible, then retry.${NC}"
		return 1
	fi
	if [[ "${PARAMS_OWNER}" != "0" ]]; then
		echo -e "${RED}ERROR: ${AMNEZIAWG_DIR}/params is not owned by root (owner UID: ${PARAMS_OWNER}).${NC}"
		echo -e "${ORANGE}This is a security risk. Fix with: chown root:root ${AMNEZIAWG_DIR}/params${NC}"
		return 1
	fi
	# Require mode 600 or 400: the file contains SERVER_PRIV_KEY and must not be
	# readable or writable by group/other. Modes like 644 would leak the private key.
	if [[ "${PARAMS_PERMS}" != "600" ]] && [[ "${PARAMS_PERMS}" != "400" ]]; then
		echo -e "${RED}WARNING: ${AMNEZIAWG_DIR}/params has insecure permissions (${PARAMS_PERMS}).${NC}"
		echo -e "${RED}This file contains the server private key and must not be accessible by non-root users.${NC}"
		# For legacy installs created before strict umask/chmod logic, try to auto-remediate
		# when running as root and the file is owned by root, to avoid locking out management actions.
		if [[ "${EUID}" -eq 0 ]] && [[ "${PARAMS_OWNER}" == "0" ]]; then
			echo -e "${ORANGE}Attempting to fix permissions by setting mode 600 on ${AMNEZIAWG_DIR}/params...${NC}"
			if chmod 600 "${AMNEZIAWG_DIR}/params"; then
				echo -e "${GREEN}Permissions on ${AMNEZIAWG_DIR}/params updated to 600. Continuing.${NC}"
			else
				echo -e "${RED}ERROR: Failed to automatically fix permissions on ${AMNEZIAWG_DIR}/params.${NC}"
				echo -e "${ORANGE}Fix manually with: chmod 600 ${AMNEZIAWG_DIR}/params${NC}"
				return 1
			fi
		else
			echo -e "${ORANGE}Fix with: chmod 600 ${AMNEZIAWG_DIR}/params${NC}"
			return 1
		fi
	fi

	# shellcheck source=/etc/amnezia/amneziawg/params
	if ! source "${AMNEZIAWG_DIR}/params"; then
		echo -e "${RED}ERROR: Failed to load params from ${AMNEZIAWG_DIR}/params.${NC}"
		echo -e "${ORANGE}The file may be corrupted or contain a syntax error. Fix or regenerate it and rerun the installer.${NC}"
		return 1
	fi
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	# Verify server config file exists before attempting migration
	if [[ ! -f "${SERVER_AWG_CONF}" ]]; then
		echo -e "${RED}ERROR: Server configuration file not found: ${SERVER_AWG_CONF}${NC}"
		echo -e "${ORANGE}The params file exists but the config file is missing.${NC}"
		return 1
	fi

	# Validate and normalize SERVER_AWG_IPV6 from params file
	# Older installations may have stored non-normalized or oddly formatted IPv6
	if ! isValidIPv6 "${SERVER_AWG_IPV6}"; then
		echo -e "${RED}ERROR: Invalid IPv6 address in params file: ${SERVER_AWG_IPV6}${NC}"
		echo -e "${ORANGE}Fix the SERVER_AWG_IPV6 value in ${AMNEZIAWG_DIR}/params${NC}"
		return 1
	fi
	# Global used by loadParams to detect IPv6 normalization changes;
	# prefixed with _ to denote script-internal cross-function state
	_MIGRATE_ORIG_IPV6="${SERVER_AWG_IPV6}"
	SERVER_AWG_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
}

# Migration for pre-2.0 installations: check for missing or invalid S3/S4 parameters
# Sets SERVER_AWG_S3 and SERVER_AWG_S4 if they are missing or invalid
# Returns 0 if migration was needed, 1 if no change
function migrateS3S4() {
	# If both S3/S4 are present, validate them before skipping migration.
	# This catches invalid values from manual edits or partial writes.
	if [[ -n "${SERVER_AWG_S3}" ]] && [[ -n "${SERVER_AWG_S4}" ]]; then
		if [[ "${SERVER_AWG_S3}" =~ ^[0-9]+$ ]] && [[ "${SERVER_AWG_S4}" =~ ^[0-9]+$ ]] && \
		   (( SERVER_AWG_S3 >= 15 )) && (( SERVER_AWG_S3 <= 150 )) && \
		   (( SERVER_AWG_S4 >= 15 )) && (( SERVER_AWG_S4 <= 150 )) && \
		   (( SERVER_AWG_S3 + 56 != SERVER_AWG_S4 )) && (( SERVER_AWG_S4 + 56 != SERVER_AWG_S3 )); then
			return 1
		fi
		# Values are present but invalid — clear them so the logic below regenerates
		SERVER_AWG_S3=""
		SERVER_AWG_S4=""
	fi

	# Try to read existing S3/S4 from config file before using defaults
	# This handles cases where params file is missing values but config file has them
	local CONF_S3 CONF_S4
	CONF_S3=$(grep -E "^S3 = " "${SERVER_AWG_CONF}" 2>/dev/null | sed 's/^S3 = //')
	CONF_S4=$(grep -E "^S4 = " "${SERVER_AWG_CONF}" 2>/dev/null | sed 's/^S4 = //')

	if [[ -n "${CONF_S3}" ]] && [[ -n "${CONF_S4}" ]]; then
		# Validate that loaded values are numeric, within valid range [15-150],
		# and satisfy the bidirectional constraint S3 + 56 != S4 and S4 + 56 != S3
		if [[ "${CONF_S3}" =~ ^[0-9]+$ ]] && [[ "${CONF_S4}" =~ ^[0-9]+$ ]] && \
		   (( CONF_S3 >= 15 )) && (( CONF_S3 <= 150 )) && \
		   (( CONF_S4 >= 15 )) && (( CONF_S4 <= 150 )) && \
		   (( CONF_S3 + 56 != CONF_S4 )) && (( CONF_S4 + 56 != CONF_S3 )); then
			SERVER_AWG_S3="${CONF_S3}"
			SERVER_AWG_S4="${CONF_S4}"
		else
			# Fallback: regenerate S3/S4 if config values are invalid
			generateS3AndS4
			while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); do
				generateS3AndS4
			done
			SERVER_AWG_S3=${RANDOM_AWG_S3}
			SERVER_AWG_S4=${RANDOM_AWG_S4}
		fi
	else
		# Generate random S3/S4 values within the valid range [15-150]
		# ensuring they satisfy the bidirectional constraint S3 + 56 != S4 and S4 + 56 != S3
		# (56 is the WireGuard handshake initiation message size)
		generateS3AndS4
		while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); do
			generateS3AndS4
		done
		SERVER_AWG_S3=${RANDOM_AWG_S3}
		SERVER_AWG_S4=${RANDOM_AWG_S4}
	fi

	return 0
}

# Migration for pre-2.0 installations: convert/validate H1-H4 range parameters
# Returns 0 if migration was needed, 1 if no change
function migrateH1H4() {
	# Check each H1-H4 independently for conversion
	# Return codes: 0=converted, 1=no change needed, 2=invalid (needs regeneration)
	local H_CONVERTED=0
	local H_INVALID=0
	local H_RC

	convertHToRangeIfNeeded "SERVER_AWG_H1"
	H_RC=$?
	if [[ ${H_RC} -eq 0 ]]; then
		H_CONVERTED=1
	elif [[ ${H_RC} -eq 2 ]]; then
		H_INVALID=1
	fi

	convertHToRangeIfNeeded "SERVER_AWG_H2"
	H_RC=$?
	if [[ ${H_RC} -eq 0 ]]; then
		H_CONVERTED=1
	elif [[ ${H_RC} -eq 2 ]]; then
		H_INVALID=1
	fi

	convertHToRangeIfNeeded "SERVER_AWG_H3"
	H_RC=$?
	if [[ ${H_RC} -eq 0 ]]; then
		H_CONVERTED=1
	elif [[ ${H_RC} -eq 2 ]]; then
		H_INVALID=1
	fi

	convertHToRangeIfNeeded "SERVER_AWG_H4"
	H_RC=$?
	if [[ ${H_RC} -eq 0 ]]; then
		H_CONVERTED=1
	elif [[ ${H_RC} -eq 2 ]]; then
		H_INVALID=1
	fi

	# If any H value is still empty after conversion attempts, force regeneration
	# This handles pre-2.0 installations where H1-H4 were never set
	if [[ -z "${SERVER_AWG_H1}" ]] || [[ -z "${SERVER_AWG_H2}" ]] || \
	   [[ -z "${SERVER_AWG_H3}" ]] || [[ -z "${SERVER_AWG_H4}" ]]; then
		H_INVALID=1
	fi

	# Check for overlapping ranges after conversion (even if all values were valid)
	# This catches cases like H1=100, H2=100 which both convert to "100-100"
	if [[ ${H_INVALID} == 0 ]] && [[ ${H_CONVERTED} == 1 || -n "${SERVER_AWG_H1}" ]]; then
		# Parse all H ranges to check for overlaps
		local H1_MIN H1_MAX H2_MIN H2_MAX H3_MIN H3_MAX H4_MIN H4_MAX
		if parseRange "${SERVER_AWG_H1}" "H1_MIN" "H1_MAX" && \
		   parseRange "${SERVER_AWG_H2}" "H2_MIN" "H2_MAX" && \
		   parseRange "${SERVER_AWG_H3}" "H3_MIN" "H3_MAX" && \
		   parseRange "${SERVER_AWG_H4}" "H4_MIN" "H4_MAX"; then
			# Check all pairwise combinations for overlap
			if rangesOverlap "${H1_MIN}" "${H1_MAX}" "${H2_MIN}" "${H2_MAX}" || \
			   rangesOverlap "${H1_MIN}" "${H1_MAX}" "${H3_MIN}" "${H3_MAX}" || \
			   rangesOverlap "${H1_MIN}" "${H1_MAX}" "${H4_MIN}" "${H4_MAX}" || \
			   rangesOverlap "${H2_MIN}" "${H2_MAX}" "${H3_MIN}" "${H3_MAX}" || \
			   rangesOverlap "${H2_MIN}" "${H2_MAX}" "${H4_MIN}" "${H4_MAX}" || \
			   rangesOverlap "${H3_MIN}" "${H3_MAX}" "${H4_MIN}" "${H4_MAX}"; then
				H_INVALID=1
			fi
		else
			# Failed to parse one or more ranges - regenerate all
			H_INVALID=1
		fi
	fi

	# If any H value failed validation or ranges overlap, regenerate all H1-H4 ranges
	# We regenerate all to ensure non-overlapping ranges
	if [[ ${H_INVALID} == 1 ]]; then
		generateH1AndH2AndH3AndH4Ranges
		SERVER_AWG_H1="${RANDOM_AWG_H1_MIN}-${RANDOM_AWG_H1_MAX}"
		SERVER_AWG_H2="${RANDOM_AWG_H2_MIN}-${RANDOM_AWG_H2_MAX}"
		SERVER_AWG_H3="${RANDOM_AWG_H3_MIN}-${RANDOM_AWG_H3_MAX}"
		SERVER_AWG_H4="${RANDOM_AWG_H4_MIN}-${RANDOM_AWG_H4_MAX}"
		H_CONVERTED=1
	fi

	if [[ ${H_CONVERTED} == 1 ]]; then
		return 0
	fi
	return 1
}

# Restore migration backups and exit on failure
# Must only be called from persistMigration after backups have been created
# Provides detailed error context and allows investigation before exiting
function _migrationRestoreAndExit() {
	local ERROR_MSG=$1
	echo ""
	echo -e "${RED}================================================================================${NC}"
	echo -e "${RED}  MIGRATION FAILED${NC}"
	echo -e "${RED}================================================================================${NC}"
	echo -e "${RED}  Error: ${ERROR_MSG}${NC}"
	echo -e "${RED}================================================================================${NC}"
	echo ""
	echo -e "${GREEN}Restoring configuration from backups...${NC}"

	local RESTORE_FAILED=0
	if ! cp "${SERVER_AWG_CONF}.bak" "${SERVER_AWG_CONF}" 2>/dev/null; then
		echo -e "${RED}  WARNING: Failed to restore ${SERVER_AWG_CONF}${NC}"
		RESTORE_FAILED=1
	else
		echo -e "${GREEN}  Restored: ${SERVER_AWG_CONF}${NC}"
	fi

	if ! cp "${AMNEZIAWG_DIR}/params.bak" "${AMNEZIAWG_DIR}/params" 2>/dev/null; then
		echo -e "${RED}  WARNING: Failed to restore ${AMNEZIAWG_DIR}/params${NC}"
		RESTORE_FAILED=1
	else
		echo -e "${GREEN}  Restored: ${AMNEZIAWG_DIR}/params${NC}"
	fi

	if (( RESTORE_FAILED )); then
		echo ""
		echo -e "${RED}Some backups could not be restored automatically.${NC}"
		echo -e "${ORANGE}Backup files remain at:${NC}"
		echo -e "${ORANGE}  ${SERVER_AWG_CONF}.bak${NC}"
		echo -e "${ORANGE}  ${AMNEZIAWG_DIR}/params.bak${NC}"
	else
		rm -f "${SERVER_AWG_CONF}.bak" "${AMNEZIAWG_DIR}/params.bak"
		echo -e "${GREEN}Backup restoration complete. Original configuration preserved.${NC}"
	fi

	echo ""
	echo -e "${ORANGE}You can investigate the issue and re-run the script to retry migration.${NC}"
	echo -e "${ORANGE}The VPN service should still be operational with the original configuration.${NC}"
	exit 1
}

# Persist migrated values to params and server config files
# Handles backup, atomic writes, config file updates, and client config renaming
# Arguments:
#   $1 - ORIG_IPV6: Original IPv6 before normalization (for Address line update)
#   $2 - IPV6_CHANGED: 1 if IPv6 was normalized, 0 otherwise
function persistMigration() {
	local ORIG_IPV6="$1"
	local IPV6_CHANGED="$2"

	# Show prominent warning BEFORE migration begins
	echo ""
	echo -e "${RED}================================================================================${NC}"
	echo -e "${RED}  IMPORTANT: Migration to AmneziaWG 2.0 format required${NC}"
	echo -e "${RED}================================================================================${NC}"
	echo -e "${RED}  After this migration, existing client configurations will be INCOMPATIBLE.${NC}"
	echo -e "${RED}  You MUST regenerate all client configurations for them to connect.${NC}"
	echo -e "${RED}================================================================================${NC}"
	echo ""

	# Require explicit user confirmation before proceeding with migration
	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		echo -e "${GREEN}AUTO_INSTALL: Auto-confirming migration to AmneziaWG 2.0${NC}"
	else
		while true; do
			read -rp "Do you want to proceed with migration to AmneziaWG 2.0? [y/N]: " RESP
			case "${RESP}" in
				[Yy])
					break
					;;
				[Nn]|"")
					echo -e "${ORANGE}Migration cancelled. The script cannot continue without migration.${NC}"
					echo -e "${ORANGE}Your existing configuration remains unchanged.${NC}"
					exit 0
					;;
				*)
					echo "Please answer y or n."
					;;
			esac
		done
	fi

	echo -e "${GREEN}Updating configuration with migrated values...${NC}"

	# Create backups of both files before migration
	# Note: If the script is interrupted, the .bak files will remain for manual recovery
	if ! cp "${SERVER_AWG_CONF}" "${SERVER_AWG_CONF}.bak"; then
		echo -e "${RED}ERROR: Failed to create backup of configuration file.${NC}"
		exit 1
	fi

	# Capture original params file permissions so we can preserve secure read-only (400)
	# vs read-write (600) settings chosen by the admin. If detection fails or an
	# unexpected mode is found, default to 600 to preserve existing behavior.
	local original_params_mode
	if original_params_mode="$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null)"; then
		if [ "${original_params_mode}" != "400" ]; then
			original_params_mode="600"
		fi
	else
		original_params_mode="600"
	fi

	if ! cp "${AMNEZIAWG_DIR}/params" "${AMNEZIAWG_DIR}/params.bak"; then
		echo -e "${RED}ERROR: Failed to create backup of params file.${NC}"
		rm -f "${SERVER_AWG_CONF}.bak"
		exit 1
	fi

	# Write to a temporary file first, then atomically rename to prevent partial writes
	local PARAMS_TMP
	if ! PARAMS_TMP="$(mktemp "${AMNEZIAWG_DIR}/params.tmp.XXXXXX")"; then
		_migrationRestoreAndExit "Failed to create temporary params file."
	fi
	if ! serializeParams "${PARAMS_TMP}"; then
		rm -f "${PARAMS_TMP}"
		_migrationRestoreAndExit "Failed to write temporary params file."
	fi

	# Atomically replace the params file to avoid partial writes on interruption
	if ! mv -f "${PARAMS_TMP}" "${AMNEZIAWG_DIR}/params"; then
		rm -f "${PARAMS_TMP}"
		_migrationRestoreAndExit "Failed to atomically replace params file."
	fi

	# Explicitly enforce secure permissions on the new params file, preserving any
	# intentional read-only (400) setting; otherwise default to 600.
	if ! chmod "${original_params_mode}" "${AMNEZIAWG_DIR}/params"; then
		_migrationRestoreAndExit "Failed to set secure permissions on params file."
	fi

	# Update server configuration file with migrated values
	echo -e "${GREEN}Updating server configuration file...${NC}"

	# Insert or update S3 (try update first, then insert after S2)
	if grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
		if ! sed -i "s|^S3 = .*|S3 = ${SERVER_AWG_S3}|" "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "Failed to update S3 in server configuration file."
		fi
	else
		# Verify S2 exists before attempting insertion
		if ! grep -q "^S2 = " "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "Cannot insert S3: S2 parameter not found in configuration file."
		fi
		if ! sed -i "/^S2 = .*/a S3 = ${SERVER_AWG_S3}" "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "Failed to insert S3 into server configuration file."
		fi
		# Verify insertion succeeded
		if ! grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "S3 insertion appeared to succeed but S3 not found in configuration file."
		fi
	fi

	# Insert or update S4 (try update first, then insert after S3, fallback to after S2)
	# Note: Backups were created at the start of migration, so any failure will restore
	# the original files via _migrationRestoreAndExit(). GNU sed -i is atomic (writes to
	# temp file then renames), so partial modifications within a single sed call are unlikely.
	if grep -q "^S4 = " "${SERVER_AWG_CONF}"; then
		if ! sed -i "s|^S4 = .*|S4 = ${SERVER_AWG_S4}|" "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "Failed to update S4 in server configuration file."
		fi
	else
		local S4_INSERTED=0
		local S4_ANCHOR=""

		# Determine anchor point for insertion (prefer S3, fallback to S2)
		if grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
			S4_ANCHOR="S3"
		elif grep -q "^S2 = " "${SERVER_AWG_CONF}"; then
			S4_ANCHOR="S2"
		else
			_migrationRestoreAndExit "Failed to insert S4: neither S3 nor S2 found in configuration file."
		fi

		# Perform single insertion after determined anchor
		if sed -i "/^${S4_ANCHOR} = .*/a S4 = ${SERVER_AWG_S4}" "${SERVER_AWG_CONF}"; then
			S4_INSERTED=1
		fi

		if [[ ${S4_INSERTED} == 0 ]]; then
			_migrationRestoreAndExit "Failed to insert S4 after ${S4_ANCHOR} in server configuration file."
		fi

		# Verify insertion succeeded
		if ! grep -q "^S4 = " "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "S4 insertion appeared to succeed but S4 not found in configuration file."
		fi
	fi

	# Update H1-H4 values (verify existence first, insert if missing)
	# Process in reverse order (H4, H3, H2, H1) so that when inserting after
	# the same anchor point, the final order is correct (H1, H2, H3, H4)
	for H_PARAM in H4 H3 H2 H1; do
		local H_VAR="SERVER_AWG_${H_PARAM}"
		local H_VALUE="${!H_VAR}"

		if grep -q "^${H_PARAM} = " "${SERVER_AWG_CONF}"; then
			if ! sed -i "s|^${H_PARAM} = .*|${H_PARAM} = ${H_VALUE}|" "${SERVER_AWG_CONF}"; then
				_migrationRestoreAndExit "Failed to update ${H_PARAM} in server configuration file."
			fi
		else
			# Parameter doesn't exist, insert after S4 (or S3, S2 as fallback)
			local INSERTED=0
			for AFTER_PARAM in S4 S3 S2; do
				if grep -q "^${AFTER_PARAM} = " "${SERVER_AWG_CONF}"; then
					if sed -i "/^${AFTER_PARAM} = .*/a ${H_PARAM} = ${H_VALUE}" "${SERVER_AWG_CONF}"; then
						INSERTED=1
						break
					fi
				fi
			done
			if [[ ${INSERTED} == 0 ]]; then
				_migrationRestoreAndExit "Failed to insert ${H_PARAM} into server configuration file."
			fi
		fi
	done

	# Normalize the Address line IPv6 if it changed (cosmetic, covered by backup)
	# Scoped to ^Address to avoid touching PostUp/PostDown firewalld rules
	if [[ ${IPV6_CHANGED} == 1 ]]; then
		if sed -i "/^Address = /s|${ORIG_IPV6}/64|${SERVER_AWG_IPV6}/64|" "${SERVER_AWG_CONF}" 2>/dev/null; then
			echo -e "${GREEN}Normalized Address IPv6: ${ORIG_IPV6} -> ${SERVER_AWG_IPV6}${NC}"
		fi
	fi

	# Migration successful, remove backups
	rm -f "${SERVER_AWG_CONF}.bak" "${AMNEZIAWG_DIR}/params.bak"

	# Rename existing client config files that don't have the new parameters
	# This prevents confusion when users try to use old configs after migration
	# Only rename configs that are actually outdated (missing S3/S4 parameters)
	#
	# Iterates over clients listed in the server config and uses getHomeDirForClient
	# to locate each config file. If the expected path does not exist (e.g., because
	# the installer is being re-run under a different context than when configs were
	# created), fall back to a bounded search under /home and /root.
	echo -e "${GREEN}Marking old client configurations as outdated...${NC}"
	local CLIENT_CONFIGS_RENAMED=0
	while IFS= read -r MIGRATE_CLIENT_NAME; do
		if ! [[ ${MIGRATE_CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
			continue
		fi
		local MIGRATE_HOME_DIR
		MIGRATE_HOME_DIR=$(getHomeDirForClient "${MIGRATE_CLIENT_NAME}")
		local MIGRATE_CLIENT_CONF_BASE="${SERVER_AWG_NIC}-client-${MIGRATE_CLIENT_NAME}.conf"
		local MIGRATE_CLIENT_CONF="${MIGRATE_HOME_DIR}/${MIGRATE_CLIENT_CONF_BASE}"

		# If the config is not found at the expected home directory, search common
		# locations (/home and /root) for a matching filename. This helps when the
		# installer is re-run under a different user/root context.
		if [[ ! -f "${MIGRATE_CLIENT_CONF}" ]]; then
			local FOUND_MIGRATE_CONF
			FOUND_MIGRATE_CONF=$(find /home /root -xdev -maxdepth 5 -type f -name "${MIGRATE_CLIENT_CONF_BASE}" 2>/dev/null | head -n 1)
			if [[ -n "${FOUND_MIGRATE_CONF}" ]]; then
				MIGRATE_CLIENT_CONF="${FOUND_MIGRATE_CONF}"
			fi
		fi

		if [[ -f "${MIGRATE_CLIENT_CONF}" ]]; then
			# Only rename if the config doesn't already have S3 parameter
			# (indicating it's a pre-2.0 config that needs regeneration)
			if ! grep -q "^S3 = " "${MIGRATE_CLIENT_CONF}"; then
				if mv "${MIGRATE_CLIENT_CONF}" "${MIGRATE_CLIENT_CONF}.old"; then
					echo -e "${ORANGE}  Renamed: ${MIGRATE_CLIENT_CONF} -> ${MIGRATE_CLIENT_CONF}.old${NC}"
					CLIENT_CONFIGS_RENAMED=$((CLIENT_CONFIGS_RENAMED + 1))
				else
					echo -e "${RED}  WARNING: Failed to rename ${MIGRATE_CLIENT_CONF}${NC}"
				fi
			fi
		fi
	done < <(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3)

	if (( CLIENT_CONFIGS_RENAMED > 0 )); then
		echo -e "${ORANGE}  ${CLIENT_CONFIGS_RENAMED} client config(s) renamed with .old suffix${NC}"
	fi

	# Reload AmneziaWG configuration
	if systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
		echo -e "${GREEN}Reloading AmneziaWG configuration...${NC}"

		# Validate configuration before reloading to prevent VPN disconnection
		if awg-quick strip "${SERVER_AWG_NIC}" >/dev/null 2>&1; then
			awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
		else
			echo -e "${ORANGE}WARNING: Configuration validation failed. Skipping live reload.${NC}"
			echo -e "${ORANGE}The configuration file has been updated successfully, but the running${NC}"
			echo -e "${ORANGE}VPN service could not be reloaded and is still using the previous settings.${NC}"
			echo -e "${ORANGE}To apply the new configuration, manually restart the service:${NC}"
			echo -e "${ORANGE}  systemctl restart awg-quick@${SERVER_AWG_NIC}${NC}"
		fi
	fi

	echo -e "${GREEN}Migration completed successfully.${NC}"
	echo ""
	if (( CLIENT_CONFIGS_RENAMED > 0 )); then
		echo -e "${ORANGE}NOTE: ${CLIENT_CONFIGS_RENAMED} old client config(s) were renamed with .old suffix.${NC}"
		echo -e "${ORANGE}You can delete them after regenerating new configs, or keep them for reference.${NC}"
	fi
	echo -e "${ORANGE}REMINDER: All existing client configurations must be regenerated.${NC}"
	echo -e "${ORANGE}Use option 4 (Regenerate all client configs) to update them automatically.${NC}"
	echo ""
}

# Quiet params rewrite when only IPv6 normalization changed (no protocol migration)
# This keeps the params file in canonical form without alarming the user
# Arguments:
#   $1 - ORIG_IPV6: Original IPv6 before normalization
function quietIPv6Rewrite() {
	local ORIG_IPV6="$1"

	local PARAMS_TMP
	PARAMS_TMP="$(mktemp "${AMNEZIAWG_DIR}/params.tmp.XXXXXX")" || {
		echo -e "${ORANGE}WARNING: Unable to create temporary file for IPv6 normalization. Non-critical.${NC}"
		return 1
	}

	# Preserve existing params file mode (e.g., 400 vs 600) across the rewrite.
	local PARAMS_MODE="600"
	if [ -e "${AMNEZIAWG_DIR}/params" ]; then
		PARAMS_MODE="$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null || echo "600")"
	fi

	if serializeParams "${PARAMS_TMP}" && 
	   mv -f "${PARAMS_TMP}" "${AMNEZIAWG_DIR}/params"; then
		chmod "${PARAMS_MODE}" "${AMNEZIAWG_DIR}/params"
	else
		rm -f "${PARAMS_TMP}"
		echo -e "${ORANGE}WARNING: Failed to rewrite params with normalized IPv6. Non-critical.${NC}"
	fi

	# Also normalize the Address line in the server config for full consistency.
	# Scoped to ^Address to avoid touching PostUp/PostDown firewalld rules,
	# which must keep the original form so removal matches on shutdown.
	if sed -i "/^Address = /s|${ORIG_IPV6}/64|${SERVER_AWG_IPV6}/64|" "${SERVER_AWG_CONF}" 2>/dev/null; then
		echo -e "${GREEN}Normalized Address IPv6: ${ORIG_IPV6} -> ${SERVER_AWG_IPV6}${NC}"
	fi
}

function loadParams() {
	if ! validateParamsFile; then
		echo -e "${RED}Failed to validate params file. Aborting parameter loading.${NC}"
		exit 1
	fi

	local NEEDS_UPDATE=0
	# Track IPv6 normalization separately from protocol migration;
	# a cosmetic rewrite should not trigger the migration warning
	local IPV6_CHANGED=0
	if [[ "${_MIGRATE_ORIG_IPV6}" != "${SERVER_AWG_IPV6}" ]]; then
		IPV6_CHANGED=1
	fi

	if migrateS3S4; then
		NEEDS_UPDATE=1
	fi

	if migrateH1H4; then
		NEEDS_UPDATE=1
	fi

	# Persist migrated values to params file and update server config
	if [[ ${NEEDS_UPDATE} == 1 ]]; then
		persistMigration "${_MIGRATE_ORIG_IPV6}" "${IPV6_CHANGED}"
	fi

	if [[ ${NEEDS_UPDATE} == 0 ]] && [[ ${IPV6_CHANGED} == 1 ]]; then
		quietIPv6Rewrite "${_MIGRATE_ORIG_IPV6}"
	fi
}

function manageMenu() {
	local MENU_OPTION=""
	echo "AmneziaWG server installer (https://github.com/wiresock/amneziawg-install)"
	echo ""
	echo "It looks like AmneziaWG is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Regenerate all client configs (using current server parameters)"
	echo "   5) Uninstall AmneziaWG"
	echo "   6) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		regenerateClients
		;;
	5)
		uninstallAmneziaWG
		;;
	6)
		exit 0
		;;
	esac
}

# Only run main logic when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	# Check for root, virt, OS...
	initialCheck

	# Check if AmneziaWG is already installed and load params
	if [[ -e "${AMNEZIAWG_DIR}/params" ]]; then
		loadParams
		manageMenu
	else
		installAmneziaWG
	fi
fi