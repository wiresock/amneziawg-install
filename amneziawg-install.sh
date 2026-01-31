#!/bin/bash

# AmneziaWG server installer
# https://github.com/wiresock/amneziawg-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 11 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 20 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 20.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 39 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 39 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
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

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
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
		read -rp "Server AmneziaWG S1 [15-150]: " -e -i ${RANDOM_AWG_S1} SERVER_AWG_S1
	done
	until [[ ${SERVER_AWG_S2} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S2} >= 15 )) && (( ${SERVER_AWG_S2} <= 150 )); do
		read -rp "Server AmneziaWG S2 [15-150]: " -e -i ${RANDOM_AWG_S2} SERVER_AWG_S2
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
		read -rp "Server AmneziaWG S3 [15-150]: " -e -i ${RANDOM_AWG_S3} SERVER_AWG_S3
	done
	until [[ ${SERVER_AWG_S4} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S4} >= 15 )) && (( ${SERVER_AWG_S4} <= 150 )); do
		read -rp "Server AmneziaWG S4 [15-150]: " -e -i ${RANDOM_AWG_S4} SERVER_AWG_S4
	done
}

# Parse a range string "min-max" or single value into MIN and MAX variables
# Uses indirect variable assignment via printf -v to set caller's variables by name
function parseRange() {
	local INPUT=$1
	local MIN_VAR_NAME=$2  # Name of variable to store min value (indirect assignment)
	local MAX_VAR_NAME=$3  # Name of variable to store max value (indirect assignment)
	
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
		RANDOM_AWG_H1_MIN=${MIN_VAL}
		RANDOM_AWG_H1_MAX=$((MIN_VAL + RANGE_SIZE))
		RANDOM_AWG_H2_MIN=$((RANDOM_AWG_H1_MAX + GAP))
		RANDOM_AWG_H2_MAX=$((RANDOM_AWG_H2_MIN + RANGE_SIZE))
		RANDOM_AWG_H3_MIN=$((RANDOM_AWG_H2_MAX + GAP))
		RANDOM_AWG_H3_MAX=$((RANDOM_AWG_H3_MIN + RANGE_SIZE))
		RANDOM_AWG_H4_MIN=$((RANDOM_AWG_H3_MAX + GAP))
		RANDOM_AWG_H4_MAX=$((RANDOM_AWG_H4_MIN + RANGE_SIZE))
		return
	fi
	
	local RANDOM_OFFSET_MAX=$((SEGMENT_SIZE - RANGE_SIZE))
	
	# H1 range (segment 0)
	local H1_START=$((MIN_VAL + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H1_MIN=${H1_START}
	RANDOM_AWG_H1_MAX=$((H1_START + RANGE_SIZE))
	
	# H2 range (segment 1, with gap after H1's segment)
	local H2_START=$((MIN_VAL + SEGMENT_SIZE + GAP + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H2_MIN=${H2_START}
	RANDOM_AWG_H2_MAX=$((H2_START + RANGE_SIZE))
	
	# H3 range (segment 2, with gap after H2's segment)
	local H3_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 2 + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H3_MIN=${H3_START}
	RANDOM_AWG_H3_MAX=$((H3_START + RANGE_SIZE))
	
	# H4 range (segment 3, with gap after H3's segment)
	local H4_SEGMENT_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 3))
	local H4_START=$((H4_SEGMENT_START + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	
	# Ensure H4 range maintains consistent size by shifting start if end would exceed MAX_VAL
	# but never encroach into H3's segment (must stay >= H4_SEGMENT_START)
	local H4_END=$((H4_START + RANGE_SIZE))
	if (( H4_END > MAX_VAL )); then
		# Shift start back to maintain RANGE_SIZE
		local H4_SHIFTED_START=$((MAX_VAL - RANGE_SIZE))
		
		# Ensure we don't encroach into H3's segment
		if (( H4_SHIFTED_START >= H4_SEGMENT_START )); then
			H4_START=${H4_SHIFTED_START}
			H4_END=$((H4_START + RANGE_SIZE))
		else
			# Cannot fit full RANGE_SIZE in H4's segment without overlap
			# Keep original position but clamp end to MAX_VAL (reduced range size)
			H4_END=${MAX_VAL}
		fi
	fi
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
		RANDOM_AWG_H1_MAX=$((RANDOM_AWG_H1_MIN + RANGE_SIZE))
		RANDOM_AWG_H2_MIN=$((RANDOM_AWG_H1_MAX + GAP))
		RANDOM_AWG_H2_MAX=$((RANDOM_AWG_H2_MIN + RANGE_SIZE))
		RANDOM_AWG_H3_MIN=$((RANDOM_AWG_H2_MAX + GAP))
		RANDOM_AWG_H3_MAX=$((RANDOM_AWG_H3_MIN + RANGE_SIZE))
		RANDOM_AWG_H4_MIN=$((RANDOM_AWG_H3_MAX + GAP))
		RANDOM_AWG_H4_MAX=$((RANDOM_AWG_H4_MIN + RANGE_SIZE))
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
# Note: This function only checks format, not range validity (min <= max).
# Range validity is enforced separately by validateRange() during user input
# and by the AmneziaWG service when loading the configuration.
function convertHToRangeIfNeeded() {
	local VAR_NAME=$1
	local VALUE=${!VAR_NAME}
	
	# Only convert if value exists and is not already in range format
	# Range format: "min-max" (e.g., "100-200")
	if [[ -n "${VALUE}" ]] && [[ ! "${VALUE}" =~ ^[0-9]+-[0-9]+$ ]]; then
		# Convert single value to range format (e.g., "100" -> "100-100")
		printf -v "$VAR_NAME" '%s' "${VALUE}-${VALUE}"
		return 0  # Conversion was needed
	fi
	return 1  # No conversion needed (already range format or empty)
}

function installQuestions() {
	echo "AmneziaWG server installer (https://github.com/wiresock/amneziawg-install)"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "Public IPv4 or IPv6 address or domain: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_AWG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_AWG_NIC} -lt 16 ]]; do
		read -rp "AmneziaWG interface name: " -e -i awg0 SERVER_AWG_NIC
	done

	until [[ ${SERVER_AWG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Server AmneziaWG IPv4: " -e -i 10.66.66.1 SERVER_AWG_IPV4
	done

	until [[ ${SERVER_AWG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "Server AmneziaWG IPv6: " -e -i fd42:42:42::1 SERVER_AWG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server AmneziaWG port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Adguard DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
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
		read -rp "Server AmneziaWG Jc [1-128]: " -e -i ${RANDOM_AWG_JC} SERVER_AWG_JC
	done

	# Jmin && Jmax
	# Note: Jmin == Jmax is valid - it results in fixed-size junk packets rather than
	# randomized sizes within a range. The protocol accepts Jmin <= Jmax.
	readJminAndJmax
	until [ "${SERVER_AWG_JMIN}" -le "${SERVER_AWG_JMAX}" ]; do
		echo "AmneziaWG requires Jmin <= Jmax"
		readJminAndJmax
	done

	# S1 && S2
	# Note: The constraint S1 + 56 != S2 is required by the AmneziaWG protocol
	# to ensure proper packet obfuscation. The value 56 is the WireGuard handshake
	# initiation message size, and this offset must be avoided.
	generateS1AndS2
	while (( ${RANDOM_AWG_S1} + 56 == ${RANDOM_AWG_S2} )); do
		generateS1AndS2
	done
	readS1AndS2
	while (( ${SERVER_AWG_S1} + 56 == ${SERVER_AWG_S2} )); do
		echo "AmneziaWG requires S1 + 56 != S2"
		readS1AndS2
	done

	# S3 && S4 (AmneziaWG 2.0)
	# Note: Same constraint as S1/S2 - the 56-byte offset must be avoided
	echo -e "\n${GREEN}AmneziaWG 2.0 Features:${NC}"
	generateS3AndS4
	while (( ${RANDOM_AWG_S3} + 56 == ${RANDOM_AWG_S4} )); do
		generateS3AndS4
	done
	readS3AndS4
	while (( ${SERVER_AWG_S3} + 56 == ${SERVER_AWG_S4} )); do
		echo "AmneziaWG requires S3 + 56 != S4"
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
			if ! grep -q "deb-src" /etc/apt/sources.list.d/ubuntu.sources; then
				cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/amneziawg.sources
				sed -i 's/deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources
			fi
		else
			if ! grep -q "^deb-src" /etc/apt/sources.list; then
				cp /etc/apt/sources.list /etc/apt/sources.list.d/amneziawg.sources.list
				sed -i 's/^deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources.list
			fi
		fi
		apt install -y software-properties-common
		add-apt-repository -y ppa:amnezia/ppa
		apt install -y amneziawg amneziawg-tools qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -q "^deb-src" /etc/apt/sources.list; then
			cp /etc/apt/sources.list /etc/apt/sources.list.d/amneziawg.sources.list
			sed -i 's/^deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources.list
		fi
		apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828
		echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		echo "deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		apt update
		apt install -y amneziawg amneziawg-tools qrencode iptables
	elif [[ ${OS} == 'fedora' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		dnf install -y amneziawg-dkms amneziawg-tools qrencode iptables
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		dnf install -y amneziawg-dkms amneziawg-tools qrencode iptables
	fi

	# Ensure configuration directory exists
	mkdir -p "${AMNEZIAWG_DIR}"

	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	SERVER_PRIV_KEY=$(awg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_AWG_NIC=${SERVER_AWG_NIC}
SERVER_AWG_IPV4=${SERVER_AWG_IPV4}
SERVER_AWG_IPV6=${SERVER_AWG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
SERVER_AWG_JC=${SERVER_AWG_JC}
SERVER_AWG_JMIN=${SERVER_AWG_JMIN}
SERVER_AWG_JMAX=${SERVER_AWG_JMAX}
SERVER_AWG_S1=${SERVER_AWG_S1}
SERVER_AWG_S2=${SERVER_AWG_S2}
SERVER_AWG_S3=${SERVER_AWG_S3}
SERVER_AWG_S4=${SERVER_AWG_S4}
SERVER_AWG_H1=${SERVER_AWG_H1}
SERVER_AWG_H2=${SERVER_AWG_H2}
SERVER_AWG_H3=${SERVER_AWG_H3}
SERVER_AWG_H4=${SERVER_AWG_H4}" >"${AMNEZIAWG_DIR}/params"

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

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_AWG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_AWG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"${SERVER_AWG_CONF}"
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
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/awg.conf

	sysctl --system

	systemctl start "awg-quick@${SERVER_AWG_NIC}"
	systemctl enable "awg-quick@${SERVER_AWG_NIC}"

	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Check if AmneziaWG is running
	systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
	AWG_RUNNING=$?

	# AmneziaWG might not work if we updated the kernel. Tell the user to reboot
	if [[ ${AWG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: AmneziaWG does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if AmneziaWG is running with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
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
	
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "${SERVER_AWG_CONF}")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_AWG_IPV4::-1}${DOT_IP}" "${SERVER_AWG_CONF}")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_AWG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Client AmneziaWG IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_AWG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_AWG_IPV4/32" "${SERVER_AWG_CONF}")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_AWG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Client AmneziaWG IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_AWG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_AWG_IPV6}/128" "${SERVER_AWG_CONF}")

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(awg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
	CLIENT_PRE_SHARED_KEY=$(awg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_AWG_IPV4}/32,${CLIENT_AWG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}
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
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${NUMBER_OF_CLIENTS} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# restart AmneziaWG to apply changes
	awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
}

function uninstallAmneziaWG() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/amnezia/amneziawg directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "awg-quick@${SERVER_AWG_NIC}"
		systemctl disable "awg-quick@${SERVER_AWG_NIC}"

		# Disable routing
		rm -f /etc/sysctl.d/awg.conf
		sysctl --system

		# Remove config files
		rm -rf ${AMNEZIAWG_DIR}/*

		if [[ ${OS} == 'ubuntu' ]]; then
			apt remove -y amneziawg amneziawg-tools
			add-apt-repository -ry ppa:amnezia/ppa
			if [[ -e /etc/apt/sources.list.d/ubuntu.sources ]]; then
				rm -f /etc/apt/sources.list.d/amneziawg.sources
			else
				rm -f /etc/apt/sources.list.d/amneziawg.sources.list
			fi
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y amneziawg amneziawg-tools
			rm -f /etc/apt/sources.list.d/amneziawg.sources.list
			apt-key del 57290828
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

function loadParams() {
	source "${AMNEZIAWG_DIR}/params"
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
	
	# Verify server config file exists before attempting migration
	if [[ ! -f "${SERVER_AWG_CONF}" ]]; then
		echo -e "${RED}ERROR: Server configuration file not found: ${SERVER_AWG_CONF}${NC}"
		echo -e "${ORANGE}The params file exists but the config file is missing.${NC}"
		exit 1
	fi
	
	local NEEDS_UPDATE=0
	
	# Migration for pre-2.0 installations: check for missing S3/S4 parameters
	if [[ -z "${SERVER_AWG_S3}" ]] || [[ -z "${SERVER_AWG_S4}" ]]; then
		# Try to read existing S3/S4 from config file before using defaults
		# This handles cases where params file is missing values but config file has them
		local CONF_S3 CONF_S4
		CONF_S3=$(grep -E "^S3 = " "${SERVER_AWG_CONF}" 2>/dev/null | sed 's/^S3 = //')
		CONF_S4=$(grep -E "^S4 = " "${SERVER_AWG_CONF}" 2>/dev/null | sed 's/^S4 = //')
		
		if [[ -n "${CONF_S3}" ]] && [[ -n "${CONF_S4}" ]]; then
			SERVER_AWG_S3="${CONF_S3}"
			SERVER_AWG_S4="${CONF_S4}"
		else
			# Generate random S3/S4 values within the valid range [15-150]
			# ensuring they satisfy the constraint S3 + 56 != S4
			# (56 is the WireGuard handshake initiation message size)
			generateS3AndS4
			while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )); do
				generateS3AndS4
			done
			SERVER_AWG_S3=${RANDOM_AWG_S3}
			SERVER_AWG_S4=${RANDOM_AWG_S4}
		fi
		
		NEEDS_UPDATE=1
	fi
	
	# Migration for pre-2.0 installations: check each H1-H4 independently for conversion
	local H_CONVERTED=0
	if convertHToRangeIfNeeded "SERVER_AWG_H1"; then H_CONVERTED=1; fi
	if convertHToRangeIfNeeded "SERVER_AWG_H2"; then H_CONVERTED=1; fi
	if convertHToRangeIfNeeded "SERVER_AWG_H3"; then H_CONVERTED=1; fi
	if convertHToRangeIfNeeded "SERVER_AWG_H4"; then H_CONVERTED=1; fi
	
	if [[ ${H_CONVERTED} == 1 ]]; then
		NEEDS_UPDATE=1
	fi
	
	# Persist migrated values to params file and update server config
	if [[ ${NEEDS_UPDATE} == 1 ]]; then
		# Show prominent warning BEFORE migration begins
		echo ""
		echo -e "${RED}================================================================================${NC}"
		echo -e "${RED}  IMPORTANT: Migration to AmneziaWG 2.0 format required${NC}"
		echo -e "${RED}================================================================================${NC}"
		echo -e "${RED}  After this migration, existing client configurations will be INCOMPATIBLE.${NC}"
		echo -e "${RED}  You MUST regenerate all client configurations for them to connect.${NC}"
		echo -e "${RED}================================================================================${NC}"
		echo ""
		
		echo -e "${GREEN}Updating configuration with migrated values...${NC}"
		
		# Create backups of both files before migration
		# Note: If the script is interrupted, the .bak files will remain for manual recovery
		if ! cp "${SERVER_AWG_CONF}" "${SERVER_AWG_CONF}.bak"; then
			echo -e "${RED}ERROR: Failed to create backup of configuration file.${NC}"
			exit 1
		fi
		
		if ! cp "${AMNEZIAWG_DIR}/params" "${AMNEZIAWG_DIR}/params.bak"; then
			echo -e "${RED}ERROR: Failed to create backup of params file.${NC}"
			rm -f "${SERVER_AWG_CONF}.bak"
			exit 1
		fi
		
		# Helper function to restore backups and exit on failure
		# Provides detailed error context and allows investigation before exiting
		restoreBackupsAndExit() {
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
		
		if ! echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_AWG_NIC=${SERVER_AWG_NIC}
SERVER_AWG_IPV4=${SERVER_AWG_IPV4}
SERVER_AWG_IPV6=${SERVER_AWG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
SERVER_AWG_JC=${SERVER_AWG_JC}
SERVER_AWG_JMIN=${SERVER_AWG_JMIN}
SERVER_AWG_JMAX=${SERVER_AWG_JMAX}
SERVER_AWG_S1=${SERVER_AWG_S1}
SERVER_AWG_S2=${SERVER_AWG_S2}
SERVER_AWG_S3=${SERVER_AWG_S3}
SERVER_AWG_S4=${SERVER_AWG_S4}
SERVER_AWG_H1=${SERVER_AWG_H1}
SERVER_AWG_H2=${SERVER_AWG_H2}
SERVER_AWG_H3=${SERVER_AWG_H3}
SERVER_AWG_H4=${SERVER_AWG_H4}" >"${AMNEZIAWG_DIR}/params"; then
			restoreBackupsAndExit "ERROR: Failed to write params file."
		fi
		
		# Update server configuration file with migrated values
		echo -e "${GREEN}Updating server configuration file...${NC}"
		
		# Insert or update S3 (try update first, then insert after S2)
		if grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
			if ! sed -i "s|^S3 = .*|S3 = ${SERVER_AWG_S3}|" "${SERVER_AWG_CONF}"; then
				restoreBackupsAndExit "Failed to update S3 in server configuration file."
			fi
		else
			if ! sed -i "/^S2 = .*/a S3 = ${SERVER_AWG_S3}" "${SERVER_AWG_CONF}"; then
				restoreBackupsAndExit "Failed to insert S3 into server configuration file."
			fi
		fi
		
		# Insert or update S4 (try update first, then insert after S3, fallback to after S2)
		if grep -q "^S4 = " "${SERVER_AWG_CONF}"; then
			if ! sed -i "s|^S4 = .*|S4 = ${SERVER_AWG_S4}|" "${SERVER_AWG_CONF}"; then
				restoreBackupsAndExit "Failed to update S4 in server configuration file."
			fi
		elif grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
			if ! sed -i "/^S3 = .*/a S4 = ${SERVER_AWG_S4}" "${SERVER_AWG_CONF}"; then
				restoreBackupsAndExit "Failed to insert S4 after S3 in server configuration file."
			fi
		else
			if ! sed -i "/^S2 = .*/a S4 = ${SERVER_AWG_S4}" "${SERVER_AWG_CONF}"; then
				restoreBackupsAndExit "Failed to insert S4 after S2 in server configuration file."
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
					restoreBackupsAndExit "Failed to update ${H_PARAM} in server configuration file."
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
					restoreBackupsAndExit "Failed to insert ${H_PARAM} into server configuration file."
				fi
			fi
		done
		
		# Migration successful, remove backups
		rm -f "${SERVER_AWG_CONF}.bak" "${AMNEZIAWG_DIR}/params.bak"
		
		# Rename existing client config files to indicate they're outdated
		# This prevents confusion when users try to use old configs after migration
		echo -e "${GREEN}Marking old client configurations as outdated...${NC}"
		local CLIENT_CONFIGS_RENAMED=0
		while IFS= read -r CLIENT_CONF; do
			if [[ -f "${CLIENT_CONF}" ]]; then
				mv "${CLIENT_CONF}" "${CLIENT_CONF}.old"
				echo -e "${ORANGE}  Renamed: ${CLIENT_CONF} -> ${CLIENT_CONF}.old${NC}"
				CLIENT_CONFIGS_RENAMED=$((CLIENT_CONFIGS_RENAMED + 1))
			fi
		done < <(find /home /root -name "${SERVER_AWG_NIC}-client-*.conf" 2>/dev/null)
		
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
		echo -e "${ORANGE}Use option 1 (Add a new user) to create new client configs with updated parameters.${NC}"
		echo ""
	fi
}

function manageMenu() {
	echo "AmneziaWG server installer (https://github.com/wiresock/amneziawg-install)"
	echo ""
	echo "It looks like AmneziaWG is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Uninstall AmneziaWG"
	echo "   5) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
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
		uninstallAmneziaWG
		;;
	5)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if AmneziaWG is already installed and load params
if [[ -e "${AMNEZIAWG_DIR}/params" ]]; then
	loadParams
	manageMenu
else
	installAmneziaWG
fi