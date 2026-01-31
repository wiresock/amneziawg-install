#!/bin/bash

# AmneziaWG server installer
# https://github.com/varckin/amneziawg-install

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
function parseRange() {
	local INPUT=$1
	local MIN_VAR_NAME=$2
	local MAX_VAR_NAME=$3
	
	if [[ ${INPUT} =~ ^([0-9]+)-([0-9]+)$ ]]; then
		printf -v "$MIN_VAR_NAME" '%s' "${BASH_REMATCH[1]}"
		printf -v "$MAX_VAR_NAME" '%s' "${BASH_REMATCH[2]}"
	elif [[ ${INPUT} =~ ^[0-9]+$ ]]; then
		printf -v "$MIN_VAR_NAME" '%s' "${INPUT}"
		printf -v "$MAX_VAR_NAME" '%s' "${INPUT}"
	else
		return 1
	fi
	return 0
}

# Check if two ranges overlap
function rangesOverlap() {
	local MIN1=$1
	local MAX1=$2
	local MIN2=$3
	local MAX2=$4
	
	# Ranges overlap if NOT (max1 < min2 OR max2 < min1)
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
	
	# Calculate available range, rounding down to multiple of 4 to prevent integer division overflow
	local RAW_AVAILABLE=$((MAX_VAL - MIN_VAL - GAP * 3))
	local AVAILABLE_RANGE=$((RAW_AVAILABLE - RAW_AVAILABLE % 4))
	
	# Generate 4 non-overlapping ranges by dividing the available space into 4 segments
	local SEGMENT_SIZE=$((AVAILABLE_RANGE / 4))
	
	# Validate that segment size is larger than range size
	if (( SEGMENT_SIZE <= RANGE_SIZE )); then
		# Fall back to fixed non-overlapping ranges (consistent GAP usage)
		RANDOM_AWG_H1_MIN=5
		RANDOM_AWG_H1_MAX=$((5 + RANGE_SIZE))
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
	local H4_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 3 + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H4_MIN=${H4_START}
	RANDOM_AWG_H4_MAX=$((H4_START + RANGE_SIZE))
	
	# Clamp and resolve overlaps using helper function
	clampAndResolveOverlap "RANDOM_AWG_H1" ${MIN_VAL} ${MAX_VAL} ${RANGE_SIZE} ${GAP} "" ""
	clampAndResolveOverlap "RANDOM_AWG_H2" ${MIN_VAL} ${MAX_VAL} ${RANGE_SIZE} ${GAP} ${RANDOM_AWG_H1_MIN} ${RANDOM_AWG_H1_MAX}
	clampAndResolveOverlap "RANDOM_AWG_H3" ${MIN_VAL} ${MAX_VAL} ${RANGE_SIZE} ${GAP} ${RANDOM_AWG_H2_MIN} ${RANDOM_AWG_H2_MAX}
	clampAndResolveOverlap "RANDOM_AWG_H4" ${MIN_VAL} ${MAX_VAL} ${RANGE_SIZE} ${GAP} ${RANDOM_AWG_H3_MIN} ${RANDOM_AWG_H3_MAX}
	
	# Final validation: ensure all four ranges are non-overlapping
	local HAS_OVERLAP=0
	if (( RANDOM_AWG_H1_MIN <= RANDOM_AWG_H2_MAX && RANDOM_AWG_H1_MAX >= RANDOM_AWG_H2_MIN )); then
		HAS_OVERLAP=1
	elif (( RANDOM_AWG_H1_MIN <= RANDOM_AWG_H3_MAX && RANDOM_AWG_H1_MAX >= RANDOM_AWG_H3_MIN )); then
		HAS_OVERLAP=1
	elif (( RANDOM_AWG_H1_MIN <= RANDOM_AWG_H4_MAX && RANDOM_AWG_H1_MAX >= RANDOM_AWG_H4_MIN )); then
		HAS_OVERLAP=1
	elif (( RANDOM_AWG_H2_MIN <= RANDOM_AWG_H3_MAX && RANDOM_AWG_H2_MAX >= RANDOM_AWG_H3_MIN )); then
		HAS_OVERLAP=1
	elif (( RANDOM_AWG_H2_MIN <= RANDOM_AWG_H4_MAX && RANDOM_AWG_H2_MAX >= RANDOM_AWG_H4_MIN )); then
		HAS_OVERLAP=1
	elif (( RANDOM_AWG_H3_MIN <= RANDOM_AWG_H4_MAX && RANDOM_AWG_H3_MAX >= RANDOM_AWG_H4_MIN )); then
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

# Helper function to clamp a range and resolve overlap with previous range
function clampAndResolveOverlap() {
	local VAR_PREFIX=$1
	local MIN_VAL=$2
	local MAX_VAL=$3
	local RANGE_SIZE=$4
	local GAP=$5
	local PREV_MIN=$6
	local PREV_MAX=$7
	
	local MIN_VAR="${VAR_PREFIX}_MIN"
	local MAX_VAR="${VAR_PREFIX}_MAX"
	local CURR_MIN=${!MIN_VAR}
	local CURR_MAX=${!MAX_VAR}
	
	# Clamp to minimum bound
	if (( CURR_MIN < MIN_VAL )); then
		CURR_MIN=${MIN_VAL}
		CURR_MAX=$((CURR_MIN + RANGE_SIZE))
	fi
	
	# Clamp to maximum bound
	if (( CURR_MAX > MAX_VAL )); then
		CURR_MAX=${MAX_VAL}
		CURR_MIN=$((CURR_MAX - RANGE_SIZE))
		if (( CURR_MIN < MIN_VAL )); then
			CURR_MIN=${MIN_VAL}
		fi
	fi
	
	# Resolve overlap with previous range if provided
	if [[ -n "${PREV_MIN}" ]] && [[ -n "${PREV_MAX}" ]]; then
		if (( CURR_MIN <= PREV_MAX && CURR_MAX >= PREV_MIN )); then
			local NEW_MIN=$((PREV_MAX + GAP))
			local NEW_MAX=$((NEW_MIN + RANGE_SIZE))
			
			if (( NEW_MAX <= MAX_VAL )); then
				CURR_MIN=${NEW_MIN}
				CURR_MAX=${NEW_MAX}
			else
				# Try placing before previous range
				NEW_MAX=$((PREV_MIN - GAP))
				NEW_MIN=$((NEW_MAX - RANGE_SIZE))
				
				if (( NEW_MIN >= MIN_VAL )); then
					CURR_MIN=${NEW_MIN}
					CURR_MAX=${NEW_MAX}
				fi
			fi
		fi
	fi
	
	# Update global variables
	printf -v "$MIN_VAR" '%s' "${CURR_MIN}"
	printf -v "$MAX_VAR" '%s' "${CURR_MAX}"
}

function readHRange() {
	local H_NAME=$1
	local DEFAULT_MIN=$2
	local DEFAULT_MAX=$3
	local RESULT_VAR_MIN="SERVER_AWG_${H_NAME}_MIN"
	local RESULT_VAR_MAX="SERVER_AWG_${H_NAME}_MAX"
	
	local INPUT=""
	local VALID=0
	
	until [[ ${VALID} == 1 ]]; do
		read -rp "Server AmneziaWG ${H_NAME} [5-2147483647] (format: min-max or single value): " -e -i "${DEFAULT_MIN}-${DEFAULT_MAX}" INPUT
		
		if parseRange "${INPUT}" "TEMP_MIN" "TEMP_MAX"; then
			if validateRange "${TEMP_MIN}" "${TEMP_MAX}" 5 2147483647; then
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

function installQuestions() {
	echo "AmneziaWG server installer (https://github.com/varckin/amneziawg-install)"
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
		echo "AmneziaWG requires S1 + 56 must not equal S2"
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
		echo "AmneziaWG requires S3 + 56 must not equal S4"
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
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
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
	
	local NEEDS_UPDATE=0
	
	# Migration for pre-2.0 installations: check for missing S3/S4 parameters
	if [[ -z "${SERVER_AWG_S3}" ]] || [[ -z "${SERVER_AWG_S4}" ]]; then
		echo -e "${ORANGE}WARNING: Your installation predates AmneziaWG 2.0 and is missing S3/S4 parameters.${NC}"
		echo -e "${ORANGE}Setting default values for S3 and S4 for compatibility.${NC}"
		echo ""
		
		# Generate default S3/S4 values.
		# Values 15 and 150 satisfy the constraint S3 + 56 != S4 (15 + 56 = 71 != 150)
		# The 56-byte offset corresponds to the WireGuard handshake initiation message size
		SERVER_AWG_S3=15
		SERVER_AWG_S4=150
		
		NEEDS_UPDATE=1
	fi
	
	# Migration for pre-2.0 installations: check if H1-H4 are single values instead of ranges
	if [[ -n "${SERVER_AWG_H1}" ]] && [[ ! "${SERVER_AWG_H1}" =~ ^[0-9]+-[0-9]+$ ]]; then
		echo -e "${ORANGE}WARNING: Your installation uses legacy single-value H1-H4 parameters.${NC}"
		echo -e "${ORANGE}Converting to range format for AmneziaWG 2.0 compatibility.${NC}"
		echo ""
		
		# Convert single values to ranges (value-value), only if they are non-empty
		SERVER_AWG_H1="${SERVER_AWG_H1}-${SERVER_AWG_H1}"
		if [[ -n "${SERVER_AWG_H2}" ]]; then
			SERVER_AWG_H2="${SERVER_AWG_H2}-${SERVER_AWG_H2}"
		fi
		if [[ -n "${SERVER_AWG_H3}" ]]; then
			SERVER_AWG_H3="${SERVER_AWG_H3}-${SERVER_AWG_H3}"
		fi
		if [[ -n "${SERVER_AWG_H4}" ]]; then
			SERVER_AWG_H4="${SERVER_AWG_H4}-${SERVER_AWG_H4}"
		fi
		NEEDS_UPDATE=1
	fi
	
	# Persist migrated values to params file and update server config
	if [[ ${NEEDS_UPDATE} == 1 ]]; then
		echo -e "${GREEN}Updating params file with migrated values...${NC}"
		
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
			echo -e "${RED}ERROR: Failed to write params file.${NC}"
			exit 1
		fi
		
		# Update server configuration file with migrated values
		echo -e "${GREEN}Updating server configuration file...${NC}"
		
		# Insert or update S3 (try update first, then insert after S2)
		if grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
			if ! sed -i "s/^S3 = .*/S3 = ${SERVER_AWG_S3}/" "${SERVER_AWG_CONF}"; then
				echo -e "${RED}Failed to update S3 in server configuration file.${NC}"
				exit 1
			fi
		else
			if ! sed -i "/^S2 = .*/a S3 = ${SERVER_AWG_S3}" "${SERVER_AWG_CONF}"; then
				echo -e "${RED}Failed to insert S3 into server configuration file.${NC}"
				exit 1
			fi
		fi
		
		# Insert or update S4 (try update first, then insert after S3, fallback to after S2)
		if grep -q "^S4 = " "${SERVER_AWG_CONF}"; then
			if ! sed -i "s/^S4 = .*/S4 = ${SERVER_AWG_S4}/" "${SERVER_AWG_CONF}"; then
				echo -e "${RED}Failed to update S4 in server configuration file.${NC}"
				exit 1
			fi
		elif grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
			if ! sed -i "/^S3 = .*/a S4 = ${SERVER_AWG_S4}" "${SERVER_AWG_CONF}"; then
				echo -e "${RED}Failed to insert S4 after S3 in server configuration file.${NC}"
				exit 1
			fi
		else
			if ! sed -i "/^S2 = .*/a S4 = ${SERVER_AWG_S4}" "${SERVER_AWG_CONF}"; then
				echo -e "${RED}Failed to insert S4 after S2 in server configuration file.${NC}"
				exit 1
			fi
		fi
		
		# Update H1-H4 values
		if ! sed -i "s/^H1 = .*/H1 = ${SERVER_AWG_H1}/" "${SERVER_AWG_CONF}" || \
		   ! sed -i "s/^H2 = .*/H2 = ${SERVER_AWG_H2}/" "${SERVER_AWG_CONF}" || \
		   ! sed -i "s/^H3 = .*/H3 = ${SERVER_AWG_H3}/" "${SERVER_AWG_CONF}" || \
		   ! sed -i "s/^H4 = .*/H4 = ${SERVER_AWG_H4}/" "${SERVER_AWG_CONF}"; then
			echo -e "${RED}Failed to update H1-H4 in server configuration file.${NC}"
			exit 1
		fi
		
		# Reload AmneziaWG configuration
		if systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
			echo -e "${GREEN}Reloading AmneziaWG configuration...${NC}"
			awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
		fi
		
		echo -e "${ORANGE}NOTE: Existing client configurations were not updated.${NC}"
		echo -e "${ORANGE}Regenerate clients to apply new S3/S4 and H1-H4 parameters.${NC}"
		echo ""
	fi
}

function manageMenu() {
	echo "AmneziaWG server installer (https://github.com/varckin/amneziawg-install)"
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