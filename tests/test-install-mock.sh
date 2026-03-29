#!/bin/bash
# Integration test: verify AUTO_INSTALL mode with mocked external commands
# Designed to run inside a Docker container as root
#
# Usage: bash tests/test-install-mock.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== AmneziaWG Integration Test ==="
echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
echo ""

# Ensure running as root inside a container to avoid clobbering real system binaries.
# The test writes mock binaries to /sbin; running on a non-ephemeral host would be destructive.
if [[ "$(id -u)" -ne 0 ]]; then
	echo "ERROR: This test must be run as root (e.g., in a Docker container)"
	exit 1
fi
if [[ ! -f /.dockerenv ]] && ! grep -qE '(/docker|/lxc)' /proc/1/cgroup 2>/dev/null; then
	echo "ERROR: This test must run inside a container (Docker/LXC). Refusing to modify /sbin on a real host."
	exit 1
fi

# Detect OS family for package manager mocking
source /etc/os-release
OS_FAMILY=""
case "${ID}" in
	ubuntu|debian|linuxmint) OS_FAMILY="debian" ;;
	fedora|centos|almalinux|rocky) OS_FAMILY="rhel" ;;
	*) echo "Unsupported OS: ${ID}"; exit 1 ;;
esac

# Create mock commands in /sbin and ensure /sbin mocks take precedence in PATH.
# PATH is explicitly manipulated so that /sbin and /usr/sbin come before the
# existing PATH entries. This ensures mocks take precedence over any real binaries.
export PATH="/sbin:/usr/sbin:${PATH}"
create_mock() {
	local CMD="$1"
	local BODY="$2"
	cat > "/sbin/${CMD}" <<MOCKEOF
#!/bin/bash
${BODY}
MOCKEOF
	chmod +x "/sbin/${CMD}"
}

echo "Setting up mock commands..."

# Mock awg (AmneziaWG CLI tool)
create_mock "awg" '
case "$1" in
	genkey)   echo "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";;
	pubkey)   echo "cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=";;
	genpsk)   echo "cHNrMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM=";;
	syncconf) exit 0;;
	show)
		if [[ "${2:-}" == "all" ]] && [[ "${3:-}" == "dump" ]]; then
			# Tab-separated dump format used by the Rust poller.
			# AmneziaWG emits extra obfuscation params on the interface line
			# (Jc, Jmin, Jmax, S1, S2, H1, H2, H3, H4, + padding) making it
			# 21 fields instead of the standard WireGuard 5.  The parser must
			# handle both.
			printf "awg0\tPRIVATE_KEY\tSVR_PUB_KEY_BASE64=\t51820\t8\t50\t1000\t107\t105\t62\t95321941292\t774489227\t1084244185\t1837068650\t(null)\t(null)\t(null)\t(null)\t(null)\t(null)\toff\n"
			printf "awg0\tCLIENT1_PUB_KEY=\t(none)\t203.0.113.42:12345\t10.8.0.2/32\t1700000000\t1024\t2048\toff\n"
		else
			echo "interface: awg0"
			echo "  public key: cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="
			echo "  private key: (hidden)"
			echo "  listening port: 51820"
			echo "  jc: 4"
			echo "  jmin: 50"
			echo "  jmax: 1000"
			echo ""
			echo "peer: cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="
			echo "  allowed ips: 10.66.66.2/32, fd42:42:42::2/128"
		fi
		;;
	*)        exit 0;;
esac
'

# Mock awg-quick
create_mock "awg-quick" '
case "$1" in
	strip) echo "[Interface]"; echo "PrivateKey = mock";;
	*)     exit 0;;
esac
'

# Mock system commands
create_mock "modprobe" 'exit 0'
create_mock "depmod" 'exit 0'
create_mock "dkms" 'exit 0'
create_mock "sysctl" 'exit 0'
create_mock "lsmod" 'echo "amneziawg 12345 0"'
create_mock "iptables" 'exit 0'
create_mock "ip6tables" 'exit 0'
create_mock "qrencode" 'exit 0'
create_mock "firewall-cmd" 'exit 1'

# The installer and the Rust app both use /usr/bin/awg as the hardcoded path.
# Ensure the mock is also available there.
mkdir -p /usr/bin
cp /sbin/awg /usr/bin/awg

# Mock sudo: the Rust app calls `sudo -n /usr/bin/awg show all dump`.
# In the test harness we simply exec the target command directly (we are root).
create_mock "sudo" '
# Skip -n flag (non-interactive) and exec the rest
shift_args=()
for arg in "$@"; do
	if [[ "$arg" == "-n" ]]; then
		continue
	fi
	shift_args+=("$arg")
done
exec "${shift_args[@]}"
'
# Ensure mock is also at /usr/bin/sudo (Rust uses absolute path)
cp /sbin/sudo /usr/bin/sudo

# Mock systemctl (unit-aware: only awg-quick@* is reported as active after start;
# firewalld stays inactive to ensure the iptables code path is exercised)
create_mock "systemctl" '
# Log every systemctl call for later verification.
echo "$@" >> /tmp/systemctl-calls.log

case "$1" in
	is-active)
		if [[ "${2:-}" == "--quiet" ]]; then
			UNIT="${3:-}"
			if [[ "$UNIT" == awg-quick@* ]]; then
				if [[ -f /tmp/awg-mock-started ]]; then
					exit 0
				else
					exit 1
				fi
			fi
			if [[ "$UNIT" == "amneziawg-web" ]]; then
				if [[ -f /tmp/awg-web-mock-started ]]; then
					exit 0
				else
					exit 1
				fi
			fi
			# All other units (firewalld, etc.) are always inactive
			exit 1
		fi
		exit 1
		;;
	is-enabled)
		if [[ "${2:-}" == "--quiet" ]]; then
			UNIT="${3:-}"
			if [[ "$UNIT" == "amneziawg-web" ]]; then
				if [[ -f /tmp/awg-web-mock-enabled ]]; then
					exit 0
				else
					exit 1
				fi
			fi
			exit 1
		fi
		exit 1
		;;
	start)
		UNIT="${2:-}"
		if [[ "$UNIT" == awg-quick@* ]]; then
			touch /tmp/awg-mock-started
		fi
		if [[ "$UNIT" == "amneziawg-web" ]]; then
			touch /tmp/awg-web-mock-started
		fi
		exit 0
		;;
	stop)
		UNIT="${2:-}"
		if [[ "$UNIT" == "amneziawg-web" ]]; then
			rm -f /tmp/awg-web-mock-started
		fi
		exit 0
		;;
	enable)
		UNIT="${2:-}"
		if [[ "$UNIT" == "amneziawg-web" ]]; then
			touch /tmp/awg-web-mock-enabled
		fi
		exit 0
		;;
	disable)
		UNIT="${2:-}"
		if [[ "$UNIT" == "amneziawg-web" ]]; then
			rm -f /tmp/awg-web-mock-enabled
		fi
		exit 0
		;;
	daemon-reload)
		exit 0
		;;
	*)
		exit 0
		;;
esac
'

# Mock ip command
create_mock "ip" '
case "$1$2" in
	-4addr)   echo "    inet 198.51.100.1/24 scope global eth0";;
	-6addr)   echo "    inet6 2001:db8::1/64 scope global eth0";;
	-4route)  echo "default via 198.51.100.254 dev eth0";;
	-6route)  echo "default via 2001:db8::ffff dev eth0";;
	*)        exit 0;;
esac
'

# Mock add-apt-repository (not present in minimal containers)
create_mock "add-apt-repository" 'exit 0'

# Mock gpg (needed for Debian key import path)
create_mock "gpg" '
if [[ "$*" == *"--show-keys"* ]]; then
	echo "fpr:::::::::75C9DD72C799870E310542E24166F2C257290828:"
elif [[ "$*" == *"--dearmor"* ]]; then
	cat >/dev/null 2>&1 || true
	echo "MOCK_BINARY_KEY_DATA"
else
	exit 0
fi
exit 0
'

# Mock curl (needed for Debian key download path)
create_mock "curl" '
OUTPUT_FILE=""
PREV=""
for ARG in "$@"; do
	if [[ "${PREV}" == "-o" ]]; then
		OUTPUT_FILE="${ARG}"
	fi
	PREV="${ARG}"
done
if [[ -n "${OUTPUT_FILE}" ]]; then
	echo "-----BEGIN PGP PUBLIC KEY BLOCK-----" > "${OUTPUT_FILE}"
	echo "MOCKKEY" >> "${OUTPUT_FILE}"
	echo "-----END PGP PUBLIC KEY BLOCK-----" >> "${OUTPUT_FILE}"
fi
exit 0
'

# Mock package managers
if [[ "${OS_FAMILY}" == "debian" ]]; then
	create_mock "apt" 'exit 0'
	create_mock "apt-get" 'exit 0'
	create_mock "apt-cache" '
case "$1" in
	show) exit 1;;
	*) exit 0;;
esac'
elif [[ "${OS_FAMILY}" == "rhel" ]]; then
	create_mock "dnf" 'exit 0'
fi

# Clean up any previous test state
rm -f /tmp/awg-mock-started

# Ensure necessary directories exist
mkdir -p /etc/apt/sources.list.d /etc/apt/keyrings 2>/dev/null || true
# Create a minimal sources.list for Ubuntu/Debian if it doesn't exist
if [[ "${OS_FAMILY}" == "debian" ]] && [[ ! -f /etc/apt/sources.list ]]; then
	echo "deb http://archive.ubuntu.com/ubuntu/ focal main" > /etc/apt/sources.list
fi

echo "Running installer with AUTO_INSTALL=y..."
echo ""

# Run the installer in AUTO_INSTALL mode
export AUTO_INSTALL=y
bash "${PROJECT_ROOT}/amneziawg-install.sh"
INSTALL_RC=$?

echo ""
echo "=== Verifying installation (exit code: ${INSTALL_RC}) ==="

FAILED=0

if [[ ${INSTALL_RC} -ne 0 ]]; then
	echo "FAIL: Installer exited with non-zero code ${INSTALL_RC}"
	FAILED=$((FAILED + 1))
fi

# Check config directory exists
if [[ -d /etc/amnezia/amneziawg ]]; then
	echo "OK: Config directory exists"
else
	echo "FAIL: Config directory missing"
	FAILED=$((FAILED + 1))
fi

# Check params file
if [[ -f /etc/amnezia/amneziawg/params ]]; then
	echo "OK: params file exists"

	# Verify params file permissions
	PERMS=$(stat -c '%a' /etc/amnezia/amneziawg/params 2>/dev/null)
	if [[ "${PERMS}" == "600" ]]; then
		echo "  OK: params file permissions are 600"
	else
		echo "  FAIL: params file permissions are ${PERMS} (expected 600)"
		FAILED=$((FAILED + 1))
	fi

	# Source params and verify expected variables
	source /etc/amnezia/amneziawg/params
	for VAR in SERVER_PUB_IP SERVER_PUB_NIC SERVER_AWG_NIC SERVER_AWG_IPV4 SERVER_AWG_IPV6 \
		SERVER_PORT SERVER_PRIV_KEY SERVER_PUB_KEY CLIENT_DNS_1 ALLOWED_IPS \
		SERVER_AWG_JC SERVER_AWG_JMIN SERVER_AWG_JMAX \
		SERVER_AWG_S1 SERVER_AWG_S2 SERVER_AWG_S3 SERVER_AWG_S4 \
		SERVER_AWG_H1 SERVER_AWG_H2 SERVER_AWG_H3 SERVER_AWG_H4; do
		if [[ -n "${!VAR:-}" ]]; then
			echo "  OK: ${VAR} is set"
		else
			echo "  FAIL: ${VAR} is empty or missing"
			FAILED=$((FAILED + 1))
		fi
	done

	# Verify auto-detected defaults
	if [[ "${SERVER_AWG_NIC}" == "awg0" ]]; then
		echo "  OK: SERVER_AWG_NIC default is awg0"
	else
		echo "  FAIL: SERVER_AWG_NIC is '${SERVER_AWG_NIC}' (expected 'awg0')"
		FAILED=$((FAILED + 1))
	fi

	if [[ "${SERVER_AWG_IPV4}" == "10.66.66.1" ]]; then
		echo "  OK: SERVER_AWG_IPV4 default is 10.66.66.1"
	else
		echo "  FAIL: SERVER_AWG_IPV4 is '${SERVER_AWG_IPV4}' (expected '10.66.66.1')"
		FAILED=$((FAILED + 1))
	fi
else
	echo "FAIL: params file missing"
	FAILED=$((FAILED + 1))
fi

# Check server config
SERVER_CONF="/etc/amnezia/amneziawg/awg0.conf"
if [[ -f "${SERVER_CONF}" ]]; then
	echo "OK: Server config exists"

	# Verify server config permissions
	PERMS=$(stat -c '%a' "${SERVER_CONF}" 2>/dev/null)
	if [[ "${PERMS}" == "600" ]]; then
		echo "  OK: Server config permissions are 600"
	else
		echo "  FAIL: Server config permissions are ${PERMS} (expected 600)"
		FAILED=$((FAILED + 1))
	fi

	# Verify key parameters exist in server config
	for PARAM in "PrivateKey" "ListenPort" "Address" "Jc" "Jmin" "Jmax" \
		"S1" "S2" "S3" "S4" "H1" "H2" "H3" "H4" \
		"PostUp" "PostDown"; do
		if grep -q "^${PARAM} = \|^${PARAM} " "${SERVER_CONF}"; then
			echo "  OK: ${PARAM} present in server config"
		else
			echo "  FAIL: ${PARAM} missing from server config"
			FAILED=$((FAILED + 1))
		fi
	done

	# Verify a client peer was added
	if grep -q "^### Client client$" "${SERVER_CONF}"; then
		echo "  OK: Default client peer 'client' added"
	else
		echo "  FAIL: Default client peer 'client' not found"
		FAILED=$((FAILED + 1))
	fi

	# Verify peer AllowedIPs contains both IPv4/32 and IPv6/128
	PEER_ALLOWED=$(sed -n '/^### Client client$/,/^$/p' "${SERVER_CONF}" | grep "^AllowedIPs = " | sed 's/^AllowedIPs = //')
	if echo "${PEER_ALLOWED}" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32'; then
		echo "  OK: Peer AllowedIPs contains IPv4/32"
	else
		echo "  FAIL: Peer AllowedIPs missing IPv4/32 (got '${PEER_ALLOWED}')"
		FAILED=$((FAILED + 1))
	fi
	PEER_IPV6_PART=$(echo "${PEER_ALLOWED}" | tr ',' '\n' | grep '/128' | sed 's|/128||')
	if [[ -n "${PEER_IPV6_PART}" ]]; then
		echo "  OK: Peer AllowedIPs contains IPv6/128 (${PEER_IPV6_PART})"
	else
		echo "  FAIL: Peer AllowedIPs missing or empty IPv6/128 (got '${PEER_ALLOWED}')"
		FAILED=$((FAILED + 1))
	fi
else
	echo "FAIL: Server config missing"
	FAILED=$((FAILED + 1))
fi

# Check client config
CLIENT_CONF=$(find /root /home -maxdepth 2 -name "awg0-client-client.conf" 2>/dev/null | head -1)
if [[ -n "${CLIENT_CONF}" ]] && [[ -f "${CLIENT_CONF}" ]]; then
	echo "OK: Client config exists at ${CLIENT_CONF}"

	for PARAM in "PrivateKey" "Address" "DNS" "Jc" "Jmin" "Jmax" \
		"S1" "S2" "S3" "S4" "H1" "H2" "H3" "H4" \
		"PublicKey" "PresharedKey" "Endpoint" "AllowedIPs"; do
		if grep -q "^${PARAM} = " "${CLIENT_CONF}"; then
			echo "  OK: ${PARAM} present in client config"
		else
			echo "  FAIL: ${PARAM} missing from client config"
			FAILED=$((FAILED + 1))
		fi
	done

	# Verify Address line contains both a valid IPv4/32 and IPv6/128 entry
	# Regression test: the interactive path previously skipped IPv6 assignment
	# because IPV6_EXISTS was pre-set to '0' by the free-IP search loop
	CLIENT_ADDR=$(grep "^Address = " "${CLIENT_CONF}" | sed 's/^Address = //')
	if echo "${CLIENT_ADDR}" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32'; then
		echo "  OK: Address contains IPv4/32"
	else
		echo "  FAIL: Address missing IPv4/32 (got '${CLIENT_ADDR}')"
		FAILED=$((FAILED + 1))
	fi
	if echo "${CLIENT_ADDR}" | grep -qE '[0-9a-fA-F:]+/128'; then
		# Further check: the IPv6 part must not be empty (i.e., not just "/128")
		CLIENT_IPV6_PART=$(echo "${CLIENT_ADDR}" | tr ',' '\n' | grep '/128' | sed 's|/128||')
		if [[ -n "${CLIENT_IPV6_PART}" ]]; then
			echo "  OK: Address contains IPv6/128 (${CLIENT_IPV6_PART})"
			# Verify compressed form (RFC 5952): default server IPv6 fd42:42:42::1 always
			# produces client addresses with consecutive zero groups -> must use ::
			if echo "${CLIENT_IPV6_PART}" | grep -q "::"; then
				echo "  OK: IPv6 address uses compressed form (::)"
			else
				echo "  FAIL: IPv6 address is not in compressed form: ${CLIENT_IPV6_PART}"
				FAILED=$((FAILED + 1))
			fi
		else
			echo "  FAIL: Address has /128 suffix but IPv6 address is empty (got '${CLIENT_ADDR}')"
			FAILED=$((FAILED + 1))
		fi
	else
		echo "  FAIL: Address missing IPv6/128 (got '${CLIENT_ADDR}')"
		FAILED=$((FAILED + 1))
	fi
else
	echo "FAIL: Client config not found"
	FAILED=$((FAILED + 1))
fi

# ============================================================
# Validate client config parameter values
# ============================================================
if [[ -n "${CLIENT_CONF}" ]] && [[ -f "${CLIENT_CONF}" ]]; then
	echo ""
	echo "--- Client config parameter validation ---"
	C_PRIVKEY=$(grep "^PrivateKey = " "${CLIENT_CONF}" | sed 's/^PrivateKey = //')
	C_PUBKEY=$(grep "^PublicKey = " "${CLIENT_CONF}" | sed 's/^PublicKey = //')
	C_PSK=$(grep "^PresharedKey = " "${CLIENT_CONF}" | sed 's/^PresharedKey = //')
	C_DNS=$(grep "^DNS = " "${CLIENT_CONF}" | sed 's/^DNS = //')
	C_JC=$(grep "^Jc = " "${CLIENT_CONF}" | sed 's/^Jc = //')
	C_JMIN=$(grep "^Jmin = " "${CLIENT_CONF}" | sed 's/^Jmin = //')
	C_JMAX=$(grep "^Jmax = " "${CLIENT_CONF}" | sed 's/^Jmax = //')
	C_S1=$(grep "^S1 = " "${CLIENT_CONF}" | sed 's/^S1 = //')
	C_S2=$(grep "^S2 = " "${CLIENT_CONF}" | sed 's/^S2 = //')
	C_S3=$(grep "^S3 = " "${CLIENT_CONF}" | sed 's/^S3 = //')
	C_S4=$(grep "^S4 = " "${CLIENT_CONF}" | sed 's/^S4 = //')
	C_H1=$(grep "^H1 = " "${CLIENT_CONF}" | sed 's/^H1 = //')
	C_H2=$(grep "^H2 = " "${CLIENT_CONF}" | sed 's/^H2 = //')
	C_H3=$(grep "^H3 = " "${CLIENT_CONF}" | sed 's/^H3 = //')
	C_H4=$(grep "^H4 = " "${CLIENT_CONF}" | sed 's/^H4 = //')
	C_ENDPOINT=$(grep "^Endpoint = " "${CLIENT_CONF}" | sed 's/^Endpoint = //')

	# Validate key formats: 32-byte WireGuard keys are 44-char base64 strings
	for KEY_LABEL_VALUE in "PrivateKey:${C_PRIVKEY}" "PublicKey:${C_PUBKEY}" "PresharedKey:${C_PSK}"; do
		K_LABEL="${KEY_LABEL_VALUE%%:*}"
		K_VALUE="${KEY_LABEL_VALUE#*:}"
		if [[ "${#K_VALUE}" -eq 44 ]] && [[ "${K_VALUE}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
			echo "  OK: ${K_LABEL} is a valid 44-char base64 key"
		else
			echo "  FAIL: ${K_LABEL} has unexpected format (len=${#K_VALUE}): '${K_VALUE}'"
			FAILED=$((FAILED + 1))
		fi
	done

	# Validate DNS: primary resolver must be a valid IPv4 address
	C_DNS1=$(echo "${C_DNS}" | cut -d',' -f1 | tr -d ' ')
	if [[ "${C_DNS1}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
		echo "  OK: DNS1=${C_DNS1} is a valid IPv4"
	else
		echo "  FAIL: DNS1 is not a valid IPv4: '${C_DNS1}'"
		FAILED=$((FAILED + 1))
	fi

	# Validate Jc [1-128]
	if [[ "${C_JC}" =~ ^[0-9]+$ ]] && (( C_JC >= 1 && C_JC <= 128 )); then
		echo "  OK: Jc=${C_JC} in valid range [1-128]"
	else
		echo "  FAIL: Jc=${C_JC} out of range [1-128]"
		FAILED=$((FAILED + 1))
	fi

	# Validate Jmin/Jmax [1-1280] with Jmin <= Jmax
	if [[ "${C_JMIN}" =~ ^[0-9]+$ ]] && [[ "${C_JMAX}" =~ ^[0-9]+$ ]] && \
	   (( C_JMIN >= 1 && C_JMIN <= 1280 && C_JMAX >= 1 && C_JMAX <= 1280 && C_JMIN <= C_JMAX )); then
		echo "  OK: Jmin=${C_JMIN} Jmax=${C_JMAX} valid (in [1-1280] and Jmin <= Jmax)"
	else
		echo "  FAIL: Jmin/Jmax invalid: Jmin=${C_JMIN} Jmax=${C_JMAX} (must be [1-1280] with Jmin <= Jmax)"
		FAILED=$((FAILED + 1))
	fi

	# Validate S1/S2 [15-150] with AmneziaWG offset constraint (S+56 != other)
	if [[ "${C_S1}" =~ ^[0-9]+$ ]] && [[ "${C_S2}" =~ ^[0-9]+$ ]] && \
	   (( C_S1 >= 15 && C_S1 <= 150 && C_S2 >= 15 && C_S2 <= 150 )); then
		echo "  OK: S1=${C_S1} S2=${C_S2} in valid range [15-150]"
		if (( C_S1 + 56 != C_S2 && C_S2 + 56 != C_S1 )); then
			echo "  OK: S1/S2 satisfy AmneziaWG offset constraint (x+56 != y)"
		else
			echo "  FAIL: S1/S2 violate offset constraint: S1=${C_S1} S2=${C_S2}"
			FAILED=$((FAILED + 1))
		fi
	else
		echo "  FAIL: S1=${C_S1} or S2=${C_S2} out of range [15-150]"
		FAILED=$((FAILED + 1))
	fi

	# Validate S3/S4 [15-150] with AmneziaWG offset constraint
	if [[ "${C_S3}" =~ ^[0-9]+$ ]] && [[ "${C_S4}" =~ ^[0-9]+$ ]] && \
	   (( C_S3 >= 15 && C_S3 <= 150 && C_S4 >= 15 && C_S4 <= 150 )); then
		echo "  OK: S3=${C_S3} S4=${C_S4} in valid range [15-150]"
		if (( C_S3 + 56 != C_S4 && C_S4 + 56 != C_S3 )); then
			echo "  OK: S3/S4 satisfy AmneziaWG offset constraint"
		else
			echo "  FAIL: S3/S4 violate offset constraint: S3=${C_S3} S4=${C_S4}"
			FAILED=$((FAILED + 1))
		fi
	else
		echo "  FAIL: S3=${C_S3} or S4=${C_S4} out of range [15-150]"
		FAILED=$((FAILED + 1))
	fi

	# Validate H1-H4: must be "min-max" range format within [5-2147483647] and non-overlapping
	H_ALL_VALID=1
	declare -a H_RANGE_MINS H_RANGE_MAXS
	for H_IDX in 1 2 3 4; do
		H_VAR="C_H${H_IDX}"
		H_VAL="${!H_VAR}"
		if [[ "${H_VAL}" =~ ^([0-9]+)-([0-9]+)$ ]]; then
			H_LO=$(( 10#${BASH_REMATCH[1]} ))
			H_HI=$(( 10#${BASH_REMATCH[2]} ))
			if (( H_LO >= 5 && H_HI <= 2147483647 && H_LO <= H_HI )); then
				echo "  OK: H${H_IDX}=${H_VAL} valid range within [5-2147483647]"
				H_RANGE_MINS[${H_IDX}]=${H_LO}
				H_RANGE_MAXS[${H_IDX}]=${H_HI}
			else
				echo "  FAIL: H${H_IDX}=${H_VAL} out of bounds [5-2147483647]"
				H_ALL_VALID=0
				FAILED=$((FAILED + 1))
			fi
		else
			echo "  FAIL: H${H_IDX}=${H_VAL} not in 'min-max' range format"
			H_ALL_VALID=0
			FAILED=$((FAILED + 1))
		fi
	done
	if [[ ${H_ALL_VALID} -eq 1 ]]; then
		H_OVERLAP=0
		for A_IDX in 1 2 3; do
			for B_IDX in 2 3 4; do
				(( B_IDX <= A_IDX )) && continue
				if (( H_RANGE_MAXS[A_IDX] >= H_RANGE_MINS[B_IDX] && \
					  H_RANGE_MAXS[B_IDX] >= H_RANGE_MINS[A_IDX] )); then
					echo "  FAIL: H${A_IDX} [${H_RANGE_MINS[A_IDX]}-${H_RANGE_MAXS[A_IDX]}] overlaps H${B_IDX} [${H_RANGE_MINS[B_IDX]}-${H_RANGE_MAXS[B_IDX]}]"
					H_OVERLAP=$((H_OVERLAP + 1))
					FAILED=$((FAILED + 1))
				fi
			done
		done
		if [[ ${H_OVERLAP} -eq 0 ]]; then
			echo "  OK: H1-H4 ranges are non-overlapping"
		fi
	fi

	# Validate Endpoint format: host:port
	# - IPv4:port         e.g. 203.0.113.5:51820
	# - hostname:port     e.g. vpn.example.com:51820
	# - [IPv6]:port       e.g. [2001:db8::1]:51820 (brackets required)
	#
	# We accept either:
	#   (a) hostname/IPv4 with a single ':' separator, or
	#   (b) bracketed IPv6 "[addr]:port",
	# and we enforce port range 1–65535.
	EP_HOST=""
	EP_PORT=""
	EP_PORT_NUM=0
	EP_FORMAT_OK=0
	if [[ "${C_ENDPOINT}" =~ ^(\[[0-9a-fA-F:]+\]):([0-9]{1,5})$ ]]; then
		# Bracketed IPv6: [addr]:port
		EP_HOST="${BASH_REMATCH[1]}"       # includes brackets
		EP_PORT="${BASH_REMATCH[2]}"
		EP_PORT_NUM=$((10#${EP_PORT}))
		EP_FORMAT_OK=1
	elif [[ "${C_ENDPOINT}" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
		# Hostname or IPv4: host:port with a single ':' separator
		EP_HOST="${BASH_REMATCH[1]}"
		EP_PORT="${BASH_REMATCH[2]}"
		EP_PORT_NUM=$((10#${EP_PORT}))
		EP_FORMAT_OK=1
	else
		echo "  FAIL: Endpoint has unexpected format: '${C_ENDPOINT}'"
		FAILED=$((FAILED + 1))
		EP_PORT_NUM=0
	fi

	if (( EP_FORMAT_OK == 1 )); then
		if (( EP_PORT_NUM < 1 || EP_PORT_NUM > 65535 )); then
			echo "  FAIL: Endpoint port out of range (1-65535): '${EP_PORT}'"
			FAILED=$((FAILED + 1))
		else
			# Basic host validation: accept bracketed IPv6, IPv4, or hostname-like strings.
			if [[ "${EP_HOST}" =~ ^\[[0-9a-fA-F:]+\]$ || \
				  "${EP_HOST}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || \
				  "${EP_HOST}" =~ ^[a-zA-Z0-9.-]+$ ]]; then
				echo "  OK: Endpoint format and port valid: ${C_ENDPOINT}"
			else
				echo "  FAIL: Endpoint host part has unexpected format: '${EP_HOST}'"
				FAILED=$((FAILED + 1))
			fi
		fi
	fi
fi

# Check modules-load config
if [[ -f /etc/modules-load.d/amneziawg.conf ]]; then
	echo "OK: modules-load config exists"
	if grep -q "amneziawg" /etc/modules-load.d/amneziawg.conf; then
		echo "  OK: amneziawg module listed"
	else
		echo "  FAIL: amneziawg module not listed"
		FAILED=$((FAILED + 1))
	fi
else
	echo "FAIL: modules-load config missing"
	FAILED=$((FAILED + 1))
fi

# Check sysctl config
if [[ -f /etc/sysctl.d/awg.conf ]]; then
	echo "OK: sysctl config exists"
	if grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.d/awg.conf; then
		echo "  OK: IPv4 forwarding enabled"
	else
		echo "  FAIL: IPv4 forwarding not set"
		FAILED=$((FAILED + 1))
	fi
	if grep -q "net.ipv6.conf.all.forwarding = 1" /etc/sysctl.d/awg.conf; then
		echo "  OK: IPv6 forwarding enabled"
	else
		echo "  FAIL: IPv6 forwarding not set"
		FAILED=$((FAILED + 1))
	fi
else
	echo "FAIL: sysctl config missing"
	FAILED=$((FAILED + 1))
fi

# ============================================================
# awg show: verify interface and peer status
# ============================================================
echo ""
echo "--- awg show verification ---"
AWG_SHOW_OUTPUT=$(awg show 2>&1)
AWG_SHOW_RC=$?
if [[ ${AWG_SHOW_RC} -eq 0 ]]; then
	echo "OK: awg show exited successfully"
else
	echo "FAIL: awg show exited with non-zero code ${AWG_SHOW_RC}"
	FAILED=$((FAILED + 1))
fi
if echo "${AWG_SHOW_OUTPUT}" | grep -q "^interface:"; then
	SHOWN_IFACE=$(echo "${AWG_SHOW_OUTPUT}" | awk '/^interface:/ {print $2}')
	echo "OK: awg show reports interface: ${SHOWN_IFACE}"
	EXPECTED_SERVER_AWG_NIC="${SERVER_AWG_NIC-}"
	if [[ -z "${EXPECTED_SERVER_AWG_NIC}" ]]; then
		echo "  FAIL: SERVER_AWG_NIC is not set (params file may not have been sourced)"
		FAILED=$((FAILED + 1))
	elif [[ "${SHOWN_IFACE}" == "${EXPECTED_SERVER_AWG_NIC}" ]]; then
		echo "  OK: interface name matches SERVER_AWG_NIC (${EXPECTED_SERVER_AWG_NIC})"
	else
		echo "  FAIL: interface '${SHOWN_IFACE}' does not match SERVER_AWG_NIC '${EXPECTED_SERVER_AWG_NIC}'"
		FAILED=$((FAILED + 1))
	fi
	SHOWN_PUBKEY=$(echo "${AWG_SHOW_OUTPUT}" | awk '/^  public key:/ {print $NF}')
	EXPECTED_SERVER_PUB_KEY="${SERVER_PUB_KEY-}"
	if [[ -z "${EXPECTED_SERVER_PUB_KEY}" ]]; then
		echo "  FAIL: SERVER_PUB_KEY is not set (params file may not have been sourced)"
		FAILED=$((FAILED + 1))
	elif [[ -n "${SHOWN_PUBKEY}" ]] && [[ "${SHOWN_PUBKEY}" == "${EXPECTED_SERVER_PUB_KEY}" ]]; then
		echo "  OK: awg show public key matches SERVER_PUB_KEY from params"
	elif [[ -n "${SHOWN_PUBKEY}" ]]; then
		echo "  FAIL: awg show public key differs from SERVER_PUB_KEY"
		FAILED=$((FAILED + 1))
	else
		echo "  FAIL: awg show output missing public key for interface"
		FAILED=$((FAILED + 1))
	fi
else
	echo "FAIL: awg show output missing 'interface:' line"
	echo "  Output: ${AWG_SHOW_OUTPUT}"
	FAILED=$((FAILED + 1))
fi
if echo "${AWG_SHOW_OUTPUT}" | grep -q "^peer:"; then
	PEER_COUNT=$(echo "${AWG_SHOW_OUTPUT}" | grep -c "^peer:")
	echo "OK: awg show reports ${PEER_COUNT} peer(s) (client(s) registered)"
else
	echo "FAIL: awg show output missing 'peer:' entry (expected at least 1 client)"
	FAILED=$((FAILED + 1))
fi

# ============================================================
# Phase 2: Test regenerateClients flow
# ============================================================
echo ""
echo "=== Phase 2: regenerateClients ==="

# Source the install script to load function definitions
# (main block is guarded by BASH_SOURCE check, so only functions are loaded)
source "${PROJECT_ROOT}/amneziawg-install.sh"

# Source params to set server variables
source /etc/amnezia/amneziawg/params
SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

# --- 2a: Add a second client ---
newClient

if grep -q "^### Client client2$" "${SERVER_AWG_CONF}"; then
	echo "OK: Second client 'client2' added"
else
	echo "FAIL: Second client 'client2' not found in server config"
	FAILED=$((FAILED + 1))
fi

CLIENT2_CONF=$(find /root /home -maxdepth 2 -name "awg0-client-client2.conf" 2>/dev/null | head -1)
if [[ -n "${CLIENT2_CONF}" ]] && [[ -f "${CLIENT2_CONF}" ]]; then
	echo "OK: Second client config exists at ${CLIENT2_CONF}"
else
	echo "FAIL: Second client config not found"
	FAILED=$((FAILED + 1))
fi

# --- 2b: Regenerate with modified parameter, verify configs updated ---
ORIG_H1="${SERVER_AWG_H1}"
SERVER_AWG_H1="999-9999"

# Strip ANSI color codes from output so grep patterns match cleanly
REGEN_OUTPUT=$(regenerateClients 2>&1 | sed 's/\x1b\[[0-9;]*m//g')

# Verify client configs were updated with the new H1 value
CLIENT1_CONF="/root/awg0-client-client.conf"
if grep -q "^H1 = 999-9999$" "${CLIENT1_CONF}"; then
	echo "OK: client config updated with new H1 value"
else
	echo "FAIL: client config H1 not updated (expected '999-9999')"
	FAILED=$((FAILED + 1))
fi

CLIENT2_CONF=$(find /root /home -maxdepth 2 -name "awg0-client-client2.conf" 2>/dev/null | head -1)
if [[ -n "${CLIENT2_CONF}" ]] && grep -q "^H1 = 999-9999$" "${CLIENT2_CONF}"; then
	echo "OK: client2 config updated with new H1 value"
else
	echo "FAIL: client2 config H1 not updated"
	FAILED=$((FAILED + 1))
fi

# Verify old H1 value was replaced
if grep -q "^H1 = ${ORIG_H1}$" "${CLIENT1_CONF}"; then
	echo "FAIL: client config still has old H1 value"
	FAILED=$((FAILED + 1))
else
	echo "OK: Old H1 value replaced in client config"
fi

# Verify private keys were preserved (no "generating new key pair" messages)
if echo "${REGEN_OUTPUT}" | grep -q "no existing private key found"; then
	echo "FAIL: Unexpected key regeneration when all client configs exist"
	FAILED=$((FAILED + 1))
else
	echo "OK: Private keys preserved (no regeneration needed)"
fi

# Verify regeneration summary
if echo "${REGEN_OUTPUT}" | grep -q "2 succeeded, 0 failed"; then
	echo "OK: Regeneration summary shows 2 succeeded, 0 failed"
else
	echo "FAIL: Unexpected regeneration summary"
	echo "  Output: $(echo "${REGEN_OUTPUT}" | grep -i 'regeneration complete')"
	FAILED=$((FAILED + 1))
fi

# --- 2c: Key regeneration when client config is missing ---
echo ""
echo "--- Key regeneration test ---"

# Delete client2's config to force key regeneration on next run
rm -f "${CLIENT2_CONF}"
rm -f "${CLIENT2_CONF}.old" 2>/dev/null

REGEN_OUTPUT2=$(regenerateClients 2>&1 | sed 's/\x1b\[[0-9;]*m//g')

# Verify key regeneration was triggered for client2
if echo "${REGEN_OUTPUT2}" | grep -q "client2.*no existing private key found"; then
	echo "OK: Key regeneration triggered for client2 (config was missing)"
else
	echo "FAIL: Key regeneration not triggered for client2 despite missing config"
	FAILED=$((FAILED + 1))
fi

# Verify client1's key was NOT regenerated (its config still exists)
# Match "  client:" with a word boundary to avoid matching "client2:"
if echo "${REGEN_OUTPUT2}" | grep -E "^  client: .*no existing private key" > /dev/null; then
	echo "FAIL: client1 key unexpectedly regenerated"
	FAILED=$((FAILED + 1))
else
	echo "OK: client1 key preserved during second regeneration"
fi

# Verify client2's config was recreated
CLIENT2_REGEN_CONF=$(find /root /home -maxdepth 2 -name "awg0-client-client2.conf" 2>/dev/null | head -1)
if [[ -n "${CLIENT2_REGEN_CONF}" ]] && [[ -f "${CLIENT2_REGEN_CONF}" ]]; then
	echo "OK: client2 config recreated at ${CLIENT2_REGEN_CONF}"
else
	echo "FAIL: client2 config was not recreated"
	FAILED=$((FAILED + 1))
fi

# Verify server config's PublicKey for client2 was updated
if echo "${REGEN_OUTPUT2}" | grep -q "1 client.*new key pairs generated"; then
	echo "OK: Regeneration summary shows 1 new key pair"
else
	echo "FAIL: Regeneration summary doesn't show 1 new key pair"
	FAILED=$((FAILED + 1))
fi

if echo "${REGEN_OUTPUT2}" | grep -q "2 succeeded, 0 failed"; then
	echo "OK: All clients regenerated successfully"
else
	echo "FAIL: Unexpected regeneration summary in key regen test"
	FAILED=$((FAILED + 1))
fi

# ============================================================
# Phase 3: Web panel installer integration test
# ============================================================
#
# Test assumptions / harness notes:
# - systemctl is mocked (daemon-reload, enable, start return exit 0)
# - The amneziawg-web binary is NOT built in this environment; we use a
#   placeholder stub so the installer can copy a valid executable
# - No actual service is started; we validate install artifacts only
# - HTTP endpoints are NOT tested here (no runtime)
# - The test exercises non-interactive mode only (no prompts)
#
echo ""
echo "=== Phase 3: Web panel installer ==="

WEB_UNIFIED="${PROJECT_ROOT}/amneziawg-web.sh"
WEB_INSTALLER="${PROJECT_ROOT}/amneziawg-web-install.sh"
WEB_INSTALLER_IMPL="${PROJECT_ROOT}/amneziawg-web/scripts/amneziawg-web-install.sh"

# Verify unified entry point and all legacy entrypoints are present
if [[ -f "${WEB_UNIFIED}" ]]; then
	echo "OK: Unified entry point exists: ${WEB_UNIFIED}"
else
	echo "FAIL: Unified entry point missing: ${WEB_UNIFIED}"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${PROJECT_ROOT}/amneziawg-web-upgrade.sh" ]]; then
	echo "OK: Legacy upgrade wrapper exists: ${PROJECT_ROOT}/amneziawg-web-upgrade.sh"
else
	echo "FAIL: Legacy upgrade wrapper missing: ${PROJECT_ROOT}/amneziawg-web-upgrade.sh"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${PROJECT_ROOT}/amneziawg-web-uninstall.sh" ]]; then
	echo "OK: Legacy uninstall wrapper exists: ${PROJECT_ROOT}/amneziawg-web-uninstall.sh"
else
	echo "FAIL: Legacy uninstall wrapper missing: ${PROJECT_ROOT}/amneziawg-web-uninstall.sh"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_INSTALLER}" ]]; then
	echo "OK: Root-level entrypoint exists: ${WEB_INSTALLER}"
else
	echo "FAIL: Root-level entrypoint missing: ${WEB_INSTALLER}"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_INSTALLER_IMPL}" ]]; then
	echo "OK: Implementation script exists: ${WEB_INSTALLER_IMPL}"
else
	echo "FAIL: Implementation script missing: ${WEB_INSTALLER_IMPL}"
	FAILED=$((FAILED + 1))
fi

# Create a minimal stub binary so the installer has something to copy.
# We use the mocked awg binary as a placeholder for a valid executable.
STUB_BINARY="/tmp/amneziawg-web-stub"
cat > "${STUB_BINARY}" <<'STUBEOF'
#!/bin/bash
echo "amneziawg-web stub v0.0.0-test"
STUBEOF
chmod +x "${STUB_BINARY}"

# Pre-generate a known-good Argon2id PHC hash to avoid needing python3/argon2 at test time.
# This is a pre-computed hash of the word "testpassword" using standard Argon2id parameters.
# It is safe for testing only — never used in production.
TEST_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$yk42pFBQW/E8b4WUBKF4cEY7sZtTZcFZCByIi1X8E+4'

# Define test paths for the web panel installer and uninstaller.
# The binary install dir can live under /tmp (the uninstaller allows it).
# The data dir and env file must live under /var/ and /etc/ respectively so that
# the uninstaller's safe_rm_dir prefix checks are satisfied during purge tests.
# We are running inside Docker, so writing to /var and /etc is safe.
WEB_TEST_INSTALL_DIR="/tmp/awg-web-test/bin"
WEB_TEST_DATA_DIR="/var/lib/awg-web-test"
WEB_TEST_ENV_FILE="/etc/awg-web-test/env.conf"
WEB_TEST_AWG_CONFIG_DIR="${AMNEZIAWG_DIR}/clients"

# Create the AWG client config directory (populated by Phase 1 install)
mkdir -p "${WEB_TEST_AWG_CONFIG_DIR}" "${WEB_TEST_INSTALL_DIR}" "${WEB_TEST_DATA_DIR}"

echo ""
echo "--- Web installer: missing binary error behavior ---"

# Verify that the installer fails clearly when the binary is not found
WEB_MISS_OUTPUT=$(bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--binary-src "/tmp/nonexistent-binary-xyz" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable 2>&1) || WEB_MISS_RC=$?
WEB_MISS_RC="${WEB_MISS_RC:-0}"

if [[ ${WEB_MISS_RC} -ne 0 ]]; then
	echo "OK: Installer exits non-zero when binary is missing (rc=${WEB_MISS_RC})"
else
	echo "FAIL: Installer should fail when --binary-src does not exist"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_MISS_OUTPUT}" | grep -qi "binary not found\|not found\|missing"; then
	echo "OK: Installer prints helpful error for missing binary"
else
	echo "FAIL: Missing-binary error message not found in output"
	echo "  Output: ${WEB_MISS_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web installer: missing --password-hash error behavior ---"

WEB_NOPW_RC=0
WEB_NOPW_OUTPUT=$(bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--no-start --no-enable 2>&1) || WEB_NOPW_RC=$?

if [[ ${WEB_NOPW_RC} -ne 0 ]]; then
	echo "OK: Installer exits non-zero when --password-hash is missing (rc=${WEB_NOPW_RC})"
else
	echo "FAIL: Installer should fail when --password-hash is not supplied in non-interactive mode"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_NOPW_OUTPUT}" | grep -qi "password\|hash\|required"; then
	echo "OK: Missing-password error message is present"
else
	echo "FAIL: No helpful message about missing password in output"
	echo "  Output: ${WEB_NOPW_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web installer: successful non-interactive install ---"

# Clean any previous partial run
rm -f "${WEB_TEST_ENV_FILE}" "${WEB_TEST_INSTALL_DIR}/amneziawg-web"

WEB_INSTALL_RC=0
WEB_INSTALL_OUTPUT=$(bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable 2>&1) || WEB_INSTALL_RC=$?

if [[ ${WEB_INSTALL_RC} -eq 0 ]]; then
	echo "OK: Installer exited successfully (rc=0)"
else
	echo "FAIL: Installer exited with non-zero code ${WEB_INSTALL_RC}"
	echo "  Output tail: $(echo "${WEB_INSTALL_OUTPUT}" | tail -20)"
	FAILED=$((FAILED + 1))
fi

# Verify binary was installed
if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary installed at ${WEB_TEST_INSTALL_DIR}/amneziawg-web"
else
	echo "FAIL: Binary not found at ${WEB_TEST_INSTALL_DIR}/amneziawg-web"
	FAILED=$((FAILED + 1))
fi

if [[ -x "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Installed binary is executable"
else
	echo "FAIL: Installed binary is not executable"
	FAILED=$((FAILED + 1))
fi

# Verify env file was generated
if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file generated at ${WEB_TEST_ENV_FILE}"
else
	echo "FAIL: Env file not generated at ${WEB_TEST_ENV_FILE}"
	FAILED=$((FAILED + 1))
fi

# Verify env file permissions (should be 0600 — readable only by root)
if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	ENV_PERMS=$(stat -c "%a" "${WEB_TEST_ENV_FILE}")
	if [[ "${ENV_PERMS}" == "600" ]]; then
		echo "OK: Env file has permissions 0600"
	else
		echo "FAIL: Env file permissions are ${ENV_PERMS}, expected 600"
		FAILED=$((FAILED + 1))
	fi
fi

# Verify key variables are present in the env file
for VAR in AUTH_ENABLED AUTH_USERNAME AUTH_PASSWORD_HASH AWG_WEB_LISTEN AWG_WEB_DB AWG_CONFIG_DIR; do
	if grep -q "^${VAR}=" "${WEB_TEST_ENV_FILE}" 2>/dev/null; then
		echo "OK: Env file contains ${VAR}"
	else
		echo "FAIL: Env file missing ${VAR}"
		FAILED=$((FAILED + 1))
	fi
done

# Verify username was written correctly
if grep -q "^AUTH_USERNAME=testadmin$" "${WEB_TEST_ENV_FILE}" 2>/dev/null; then
	echo "OK: Auth username matches --username flag"
else
	echo "FAIL: AUTH_USERNAME not set to 'testadmin'"
	FAILED=$((FAILED + 1))
fi

# Verify password hash was written (not left empty or as placeholder)
if grep -q "^AUTH_PASSWORD_HASH=\$argon2id" "${WEB_TEST_ENV_FILE}" 2>/dev/null; then
	echo "OK: AUTH_PASSWORD_HASH is a non-empty Argon2id hash"
else
	echo "FAIL: AUTH_PASSWORD_HASH is missing or does not look like an Argon2id hash"
	echo "  Value: $(grep "^AUTH_PASSWORD_HASH" "${WEB_TEST_ENV_FILE}" 2>/dev/null || echo '(not found)')"
	FAILED=$((FAILED + 1))
fi

# Verify systemd unit file was placed
if [[ -f /etc/systemd/system/amneziawg-web.service ]]; then
	echo "OK: systemd unit file installed"
else
	echo "FAIL: systemd unit file missing at /etc/systemd/system/amneziawg-web.service"
	FAILED=$((FAILED + 1))
fi

# Verify EnvironmentFile directive is present in the unit file
if grep -q "^EnvironmentFile=" /etc/systemd/system/amneziawg-web.service 2>/dev/null; then
	echo "OK: systemd unit has EnvironmentFile directive"
else
	echo "FAIL: systemd unit is missing EnvironmentFile directive"
	FAILED=$((FAILED + 1))
fi

# Verify ReadOnlyPaths matches the configured config directory
if grep -q "^ReadOnlyPaths=${WEB_TEST_AWG_CONFIG_DIR}" /etc/systemd/system/amneziawg-web.service 2>/dev/null; then
	echo "OK: systemd unit ReadOnlyPaths matches config dir"
else
	echo "FAIL: systemd unit ReadOnlyPaths does not match config dir ${WEB_TEST_AWG_CONFIG_DIR}"
	echo "  Got: $(grep 'ReadOnlyPaths=' /etc/systemd/system/amneziawg-web.service 2>/dev/null || echo 'not found')"
	FAILED=$((FAILED + 1))
fi

# Verify ProtectHome=yes is preserved for non-/home config directories
if grep -q "^ProtectHome=yes" /etc/systemd/system/amneziawg-web.service 2>/dev/null; then
	echo "OK: systemd unit has ProtectHome=yes for non-home config dir"
else
	echo "FAIL: systemd unit should have ProtectHome=yes when config dir is not under /home"
	echo "  Got: $(grep 'ProtectHome=' /etc/systemd/system/amneziawg-web.service 2>/dev/null || echo 'not found')"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web installer: idempotency (re-run with --force) ---"

# Re-run with --force to verify idempotent behaviour (no hard errors)
WEB_RERUN_RC=0
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1 || WEB_RERUN_RC=$?

if [[ ${WEB_RERUN_RC} -eq 0 ]]; then
	echo "OK: Installer is idempotent (re-run with --force succeeded)"
else
	echo "FAIL: Re-run with --force exited non-zero (rc=${WEB_RERUN_RC})"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web installer: ProtectHome relaxed for /home config dir ---"

# When config-dir is under /home, the installer must relax ProtectHome
# to read-only so the service can access the config files.
HOME_CONFIG_DIR="/home/testuser-configs"
mkdir -p "${HOME_CONFIG_DIR}"

WEB_HOME_RC=0
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${HOME_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1 || WEB_HOME_RC=$?

if [[ ${WEB_HOME_RC} -eq 0 ]]; then
	echo "OK: Installer with /home config dir succeeded"
else
	echo "FAIL: Installer with /home config dir exited non-zero (rc=${WEB_HOME_RC})"
	FAILED=$((FAILED + 1))
fi

# Verify ProtectHome was changed to read-only
if grep -q "^ProtectHome=read-only" /etc/systemd/system/amneziawg-web.service 2>/dev/null; then
	echo "OK: ProtectHome=read-only when config dir is under /home"
else
	echo "FAIL: ProtectHome should be read-only when config dir is under /home"
	echo "  Got: $(grep 'ProtectHome=' /etc/systemd/system/amneziawg-web.service 2>/dev/null || echo 'not found')"
	FAILED=$((FAILED + 1))
fi

# Verify ReadOnlyPaths was updated to the /home config dir
if grep -q "^ReadOnlyPaths=${HOME_CONFIG_DIR}" /etc/systemd/system/amneziawg-web.service 2>/dev/null; then
	echo "OK: ReadOnlyPaths updated to ${HOME_CONFIG_DIR}"
else
	echo "FAIL: ReadOnlyPaths should point to ${HOME_CONFIG_DIR}"
	echo "  Got: $(grep 'ReadOnlyPaths=' /etc/systemd/system/amneziawg-web.service 2>/dev/null || echo 'not found')"
	FAILED=$((FAILED + 1))
fi

# Restore the original config dir for subsequent tests
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1 || true
rm -rf "${HOME_CONFIG_DIR}"

echo ""
echo "--- Web installer: sudoers drop-in ---"

# Verify sudoers file was installed
SUDOERS_FILE="/etc/sudoers.d/amneziawg-web"
if [[ -f "${SUDOERS_FILE}" ]]; then
	echo "OK: Sudoers drop-in installed at ${SUDOERS_FILE}"
else
	echo "FAIL: Sudoers drop-in missing at ${SUDOERS_FILE}"
	FAILED=$((FAILED + 1))
fi

# Verify permissions are 0440 (required by sudoers)
if [[ -f "${SUDOERS_FILE}" ]]; then
	SUDOERS_PERMS=$(stat -c "%a" "${SUDOERS_FILE}")
	if [[ "${SUDOERS_PERMS}" == "440" ]]; then
		echo "OK: Sudoers drop-in has permissions 0440"
	else
		echo "FAIL: Sudoers drop-in permissions are ${SUDOERS_PERMS}, expected 440"
		FAILED=$((FAILED + 1))
	fi
fi

# Verify ownership is root:root
if [[ -f "${SUDOERS_FILE}" ]]; then
	SUDOERS_OWNER=$(stat -c "%U:%G" "${SUDOERS_FILE}")
	if [[ "${SUDOERS_OWNER}" == "root:root" ]]; then
		echo "OK: Sudoers drop-in owned by root:root"
	else
		echo "FAIL: Sudoers drop-in owned by ${SUDOERS_OWNER}, expected root:root"
		FAILED=$((FAILED + 1))
	fi
fi

# Verify content: the rule must allow `awg show all dump`, `awg set * peer * remove`,
# `awg syncconf * /dev/stdin`, and `awg-quick strip *`
if [[ -f "${SUDOERS_FILE}" ]]; then
	if grep -q "awg-web.*NOPASSWD:.*/usr/bin/awg show all dump" "${SUDOERS_FILE}"; then
		echo "OK: Sudoers rule grants NOPASSWD for /usr/bin/awg show all dump"
	else
		echo "FAIL: Sudoers rule does not contain expected narrowly-scoped command"
		echo "  Content: $(cat "${SUDOERS_FILE}")"
		FAILED=$((FAILED + 1))
	fi

	# Verify the rule includes the peer-removal command
	if grep -q '/usr/bin/awg set \* peer \* remove' "${SUDOERS_FILE}"; then
		echo "OK: Sudoers rule includes awg set * peer * remove"
	else
		echo "FAIL: Sudoers rule missing peer-removal command"
		echo "  Content: $(cat "${SUDOERS_FILE}")"
		FAILED=$((FAILED + 1))
	fi

	# Verify the rule includes syncconf (for re-enabling peers)
	if grep -q '/usr/bin/awg syncconf \* /dev/stdin' "${SUDOERS_FILE}"; then
		echo "OK: Sudoers rule includes awg syncconf * /dev/stdin"
	else
		echo "FAIL: Sudoers rule missing syncconf command"
		echo "  Content: $(cat "${SUDOERS_FILE}")"
		FAILED=$((FAILED + 1))
	fi

	# Verify the rule includes awg-quick strip (for re-enabling peers)
	if grep -q '/usr/bin/awg-quick strip \*' "${SUDOERS_FILE}"; then
		echo "OK: Sudoers rule includes awg-quick strip *"
	else
		echo "FAIL: Sudoers rule missing awg-quick strip command"
		echo "  Content: $(cat "${SUDOERS_FILE}")"
		FAILED=$((FAILED + 1))
	fi

	# Verify the rule is narrowly scoped (only the expected commands)
	if grep -Eq '^awg-web ALL=\(root\) NOPASSWD: /usr/bin/awg show all dump, /usr/bin/awg set \* peer \* remove, /usr/bin/awg syncconf \* /dev/stdin, /usr/bin/awg-quick strip \*$' "${SUDOERS_FILE}"; then
		echo "OK: Sudoers rule is narrowly scoped (exact commands)"
	else
		echo "FAIL: Sudoers rule may be too broad or incorrectly formatted"
		echo "  Content: $(cat "${SUDOERS_FILE}")"
		FAILED=$((FAILED + 1))
	fi
fi

# Verify the systemd unit does NOT contain NoNewPrivileges=yes
# (this would prevent sudo from working)
if [[ -f /etc/systemd/system/amneziawg-web.service ]]; then
	if grep -q "^NoNewPrivileges=yes" /etc/systemd/system/amneziawg-web.service 2>/dev/null; then
		echo "FAIL: systemd unit still has NoNewPrivileges=yes (incompatible with sudo)"
		FAILED=$((FAILED + 1))
	else
		echo "OK: systemd unit does not set NoNewPrivileges=yes"
	fi
fi

echo ""
echo "=== Phase 3: Web installer tests complete ==="

# ============================================================
# Phase 4: Web panel uninstaller integration test
# ============================================================
#
# Test assumptions / harness notes:
# - systemctl is mocked with state tracking and call logging
#   (/tmp/systemctl-calls.log records every invocation)
# - The amneziawg-web service state is tracked via flag files:
#   /tmp/awg-web-mock-started (is-active) and /tmp/awg-web-mock-enabled (is-enabled)
# - No real service is running; we validate install artifact removal only
# - HTTP endpoints are NOT tested here (no runtime)
# - Tests run in force/non-interactive mode; no user prompts
#
echo ""
echo "=== Phase 4: Web panel uninstaller ==="

WEB_UNINSTALLER_IMPL="${PROJECT_ROOT}/amneziawg-web/scripts/amneziawg-web-uninstall.sh"
WEB_UNINSTALLER="${PROJECT_ROOT}/amneziawg-web-uninstall.sh"

# Verify both entrypoints are present
if [[ -f "${WEB_UNINSTALLER}" ]]; then
	echo "OK: Root-level uninstall entrypoint exists: ${WEB_UNINSTALLER}"
else
	echo "FAIL: Root-level uninstall entrypoint missing: ${WEB_UNINSTALLER}"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_UNINSTALLER_IMPL}" ]]; then
	echo "OK: Implementation script exists: ${WEB_UNINSTALLER_IMPL}"
else
	echo "FAIL: Implementation script missing: ${WEB_UNINSTALLER_IMPL}"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web uninstaller: default (safe) uninstall ---"

# Precondition: verify install artifacts exist before uninstalling
if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Pre-condition: binary exists before uninstall"
else
	echo "FAIL: Pre-condition: binary missing before uninstall test"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Pre-condition: env file exists before uninstall"
else
	echo "FAIL: Pre-condition: env file missing before uninstall test"
	FAILED=$((FAILED + 1))
fi

# Simulate the service being active+enabled so the uninstaller exercises
# stop and disable paths through the mock systemctl.
touch /tmp/awg-web-mock-started
touch /tmp/awg-web-mock-enabled

# Clear systemctl call log before uninstall so we can verify calls
rm -f /tmp/systemctl-calls.log

WEB_UNINSTALL_RC=0
WEB_UNINSTALL_OUTPUT=$(bash "${WEB_UNINSTALLER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--force 2>&1) || WEB_UNINSTALL_RC=$?

if [[ ${WEB_UNINSTALL_RC} -eq 0 ]]; then
	echo "OK: Uninstaller exited successfully (rc=0)"
else
	echo "FAIL: Uninstaller exited with non-zero code ${WEB_UNINSTALL_RC}"
	echo "  Output tail: $(echo "${WEB_UNINSTALL_OUTPUT}" | tail -20)"
	FAILED=$((FAILED + 1))
fi

# Verify binary was removed
if [[ ! -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary removed after uninstall"
else
	echo "FAIL: Binary still exists after uninstall"
	FAILED=$((FAILED + 1))
fi

# Verify systemd unit was removed
if [[ ! -f /etc/systemd/system/amneziawg-web.service ]]; then
	echo "OK: systemd unit removed after uninstall"
else
	echo "FAIL: systemd unit still exists after uninstall"
	FAILED=$((FAILED + 1))
fi

# Verify sudoers drop-in was removed
if [[ ! -f /etc/sudoers.d/amneziawg-web ]]; then
	echo "OK: Sudoers drop-in removed after uninstall"
else
	echo "FAIL: Sudoers drop-in still exists after uninstall"
	FAILED=$((FAILED + 1))
fi

# Verify env file is PRESERVED (safe default)
if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file preserved (safe default, no --purge-config)"
else
	echo "FAIL: Env file was removed — should be preserved by default"
	FAILED=$((FAILED + 1))
fi

# Verify data directory is PRESERVED (safe default)
if [[ -d "${WEB_TEST_DATA_DIR}" ]]; then
	echo "OK: Data directory preserved (safe default, no --purge-data)"
else
	echo "FAIL: Data directory was removed — should be preserved by default"
	FAILED=$((FAILED + 1))
fi

# Verify output mentions what was preserved
if echo "${WEB_UNINSTALL_OUTPUT}" | grep -qi "preserved\|preserved\|Config.*preserved\|Data.*preserved\|env\|data"; then
	echo "OK: Uninstaller mentions preserved items in output"
else
	echo "FAIL: Uninstaller output does not mention preserved items"
	FAILED=$((FAILED + 1))
fi

# Verify systemctl stop was called for amneziawg-web
if grep -q "stop amneziawg-web" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "OK: systemctl stop amneziawg-web was called"
else
	echo "FAIL: systemctl stop amneziawg-web was not called"
	FAILED=$((FAILED + 1))
fi

# Verify systemctl disable was called for amneziawg-web
if grep -q "disable amneziawg-web" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "OK: systemctl disable amneziawg-web was called"
else
	echo "FAIL: systemctl disable amneziawg-web was not called"
	FAILED=$((FAILED + 1))
fi

# Verify daemon-reload was called
if grep -q "daemon-reload" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "OK: systemctl daemon-reload was called"
else
	echo "FAIL: systemctl daemon-reload was not called"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web uninstaller: idempotency (re-run after uninstall) ---"

WEB_RERUN_UNINSTALL_RC=0
bash "${WEB_UNINSTALLER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--force >/dev/null 2>&1 || WEB_RERUN_UNINSTALL_RC=$?

if [[ ${WEB_RERUN_UNINSTALL_RC} -eq 0 ]]; then
	echo "OK: Uninstaller is idempotent (re-run after absent artifacts succeeded)"
else
	echo "FAIL: Uninstaller re-run exited non-zero (rc=${WEB_RERUN_UNINSTALL_RC})"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web uninstaller: --non-interactive alias ---"

# Re-install to restore artifacts
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

WEB_NI_RC=0
bash "${WEB_UNINSTALLER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--non-interactive >/dev/null 2>&1 || WEB_NI_RC=$?

if [[ ${WEB_NI_RC} -eq 0 ]]; then
	echo "OK: Uninstaller works with --non-interactive (alias for --force)"
else
	echo "FAIL: Uninstaller failed with --non-interactive (rc=${WEB_NI_RC})"
	FAILED=$((FAILED + 1))
fi

if [[ ! -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary removed after --non-interactive uninstall"
else
	echo "FAIL: Binary still present after --non-interactive uninstall"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web uninstaller: purge config + data ---"

# Re-install first to restore artifacts
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

# Create a file in the data dir to verify it is truly removed by purge
mkdir -p "${WEB_TEST_DATA_DIR}"
touch "${WEB_TEST_DATA_DIR}/test-db.sqlite"

WEB_PURGE_RC=0
bash "${WEB_UNINSTALLER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--purge-config \
	--purge-data \
	--force >/dev/null 2>&1 || WEB_PURGE_RC=$?

if [[ ${WEB_PURGE_RC} -eq 0 ]]; then
	echo "OK: Purge uninstall exited successfully"
else
	echo "FAIL: Purge uninstall exited non-zero (rc=${WEB_PURGE_RC})"
	FAILED=$((FAILED + 1))
fi

# Verify env directory was purged
if [[ ! -d "$(dirname "${WEB_TEST_ENV_FILE}")" ]]; then
	echo "OK: Env directory removed with --purge-config"
else
	echo "FAIL: Env directory still exists after --purge-config"
	FAILED=$((FAILED + 1))
fi

# Verify data directory was purged
if [[ ! -d "${WEB_TEST_DATA_DIR}" ]]; then
	echo "OK: Data directory removed with --purge-data"
else
	echo "FAIL: Data directory still exists after --purge-data"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web uninstaller: --remove-user ---"

# Re-install to restore artifacts and create the service user
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

# Verify the service user exists before removal
if id awg-web &>/dev/null; then
	echo "OK: Pre-condition: service user 'awg-web' exists before --remove-user"
else
	echo "WARN: Service user 'awg-web' not present (may already have been created by a prior run)"
fi

WEB_RMUSER_RC=0
bash "${WEB_UNINSTALLER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--remove-user \
	--force >/dev/null 2>&1 || WEB_RMUSER_RC=$?

if [[ ${WEB_RMUSER_RC} -eq 0 ]]; then
	echo "OK: Uninstaller with --remove-user exited successfully"
else
	echo "FAIL: Uninstaller with --remove-user exited non-zero (rc=${WEB_RMUSER_RC})"
	FAILED=$((FAILED + 1))
fi

# Verify the service user was removed
if ! id awg-web &>/dev/null; then
	echo "OK: Service user 'awg-web' removed with --remove-user"
else
	echo "FAIL: Service user 'awg-web' still exists after --remove-user"
	FAILED=$((FAILED + 1))
fi

# Verify env file is PRESERVED (--remove-user does not purge config)
if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file preserved (--remove-user does not imply --purge-config)"
else
	echo "FAIL: Env file was removed — --remove-user should not remove config"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Phase 4: Web uninstaller tests complete ==="

# ============================================================
# Phase 5: Web panel upgrade integration test
# ============================================================
#
# Test assumptions / harness notes:
# - systemctl is mocked with state tracking and call logging
#   (/tmp/systemctl-calls.log records every invocation)
# - The amneziawg-web service state is tracked via flag files:
#   /tmp/awg-web-mock-started (is-active) and /tmp/awg-web-mock-enabled (is-enabled)
# - No real service is running; we validate binary replacement and state only
# - HTTP endpoints are NOT tested here (no runtime)
# - Tests run in force/non-interactive mode; no user prompts
#
echo ""
echo "=== Phase 5: Web panel upgrader ==="

WEB_UPGRADER_IMPL="${PROJECT_ROOT}/amneziawg-web/scripts/amneziawg-web-upgrade.sh"
WEB_UPGRADER="${PROJECT_ROOT}/amneziawg-web-upgrade.sh"

# Verify both entrypoints are present
if [[ -f "${WEB_UPGRADER}" ]]; then
	echo "OK: Root-level upgrade entrypoint exists: ${WEB_UPGRADER}"
else
	echo "FAIL: Root-level upgrade entrypoint missing: ${WEB_UPGRADER}"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_UPGRADER_IMPL}" ]]; then
	echo "OK: Implementation script exists: ${WEB_UPGRADER_IMPL}"
else
	echo "FAIL: Implementation script missing: ${WEB_UPGRADER_IMPL}"
	FAILED=$((FAILED + 1))
fi

# Re-install to restore a clean state for upgrade tests
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

echo ""
echo "--- Web upgrader: missing --binary error behavior ---"

WEB_UPGRADE_NOBIN_RC=0
WEB_UPGRADE_NOBIN_OUTPUT=$(bash "${WEB_UPGRADER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--force 2>&1) || WEB_UPGRADE_NOBIN_RC=$?

if [[ ${WEB_UPGRADE_NOBIN_RC} -ne 0 ]]; then
	echo "OK: Upgrader exits non-zero when --binary is missing (rc=${WEB_UPGRADE_NOBIN_RC})"
else
	echo "FAIL: Upgrader should fail when --binary is not supplied"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_UPGRADE_NOBIN_OUTPUT}" | grep -qi "missing\|--binary\|required"; then
	echo "OK: Missing-binary error message is present"
else
	echo "FAIL: No helpful message about missing --binary in output"
	echo "  Output: ${WEB_UPGRADE_NOBIN_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web upgrader: missing source binary error behavior ---"

WEB_UPGRADE_NOSRC_RC=0
WEB_UPGRADE_NOSRC_OUTPUT=$(bash "${WEB_UPGRADER_IMPL}" \
	--binary "/tmp/nonexistent-upgrade-binary-xyz" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--force 2>&1) || WEB_UPGRADE_NOSRC_RC=$?

if [[ ${WEB_UPGRADE_NOSRC_RC} -ne 0 ]]; then
	echo "OK: Upgrader exits non-zero when source binary is missing (rc=${WEB_UPGRADE_NOSRC_RC})"
else
	echo "FAIL: Upgrader should fail when source binary does not exist"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_UPGRADE_NOSRC_OUTPUT}" | grep -qi "not found"; then
	echo "OK: Source-not-found error message is present"
else
	echo "FAIL: No helpful message about missing source binary in output"
	echo "  Output: ${WEB_UPGRADE_NOSRC_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web upgrader: successful upgrade (service active) ---"

# Create a new stub binary with different content to verify replacement
UPGRADE_BINARY="/tmp/amneziawg-web-upgrade-v2"
cat > "${UPGRADE_BINARY}" <<'STUBEOF'
#!/bin/bash
echo "amneziawg-web stub v0.0.2-upgrade-test"
STUBEOF
chmod +x "${UPGRADE_BINARY}"

# Record the content of the old installed binary for comparison
OLD_BINARY_CONTENT=$(cat "${WEB_TEST_INSTALL_DIR}/amneziawg-web")

# Simulate the service being active before upgrade
touch /tmp/awg-web-mock-started
touch /tmp/awg-web-mock-enabled

# Create a data file to ensure data directory is preserved
mkdir -p "${WEB_TEST_DATA_DIR}"
touch "${WEB_TEST_DATA_DIR}/test-db.sqlite"

# Clear systemctl call log before upgrade
rm -f /tmp/systemctl-calls.log

WEB_UPGRADE_RC=0
WEB_UPGRADE_OUTPUT=$(bash "${WEB_UPGRADER_IMPL}" \
	--binary "${UPGRADE_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--force 2>&1) || WEB_UPGRADE_RC=$?

if [[ ${WEB_UPGRADE_RC} -eq 0 ]]; then
	echo "OK: Upgrader exited successfully (rc=0)"
else
	echo "FAIL: Upgrader exited with non-zero code ${WEB_UPGRADE_RC}"
	echo "  Output tail: $(echo "${WEB_UPGRADE_OUTPUT}" | tail -20)"
	FAILED=$((FAILED + 1))
fi

# Verify binary was replaced (content changed)
NEW_BINARY_CONTENT=$(cat "${WEB_TEST_INSTALL_DIR}/amneziawg-web")
if [[ "${NEW_BINARY_CONTENT}" != "${OLD_BINARY_CONTENT}" ]]; then
	echo "OK: Binary content changed after upgrade"
else
	echo "FAIL: Binary content is the same — upgrade did not replace it"
	FAILED=$((FAILED + 1))
fi

# Verify the new binary matches the upgrade source
if [[ "${NEW_BINARY_CONTENT}" == "$(cat "${UPGRADE_BINARY}")" ]]; then
	echo "OK: Installed binary matches upgrade source"
else
	echo "FAIL: Installed binary does not match upgrade source"
	FAILED=$((FAILED + 1))
fi

# Verify binary is still executable
if [[ -x "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Upgraded binary is executable"
else
	echo "FAIL: Upgraded binary is not executable"
	FAILED=$((FAILED + 1))
fi

# Verify env file is preserved
if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file preserved after upgrade"
else
	echo "FAIL: Env file was removed — should be preserved during upgrade"
	FAILED=$((FAILED + 1))
fi

# Verify data directory is preserved
if [[ -d "${WEB_TEST_DATA_DIR}" ]]; then
	echo "OK: Data directory preserved after upgrade"
else
	echo "FAIL: Data directory was removed — should be preserved during upgrade"
	FAILED=$((FAILED + 1))
fi

# Verify data file inside data directory is preserved
if [[ -f "${WEB_TEST_DATA_DIR}/test-db.sqlite" ]]; then
	echo "OK: Data file preserved after upgrade"
else
	echo "FAIL: Data file inside data directory was removed"
	FAILED=$((FAILED + 1))
fi

# Verify systemd unit is preserved
if [[ -f /etc/systemd/system/amneziawg-web.service ]]; then
	echo "OK: systemd unit preserved after upgrade"
else
	echo "FAIL: systemd unit was removed — should be preserved during upgrade"
	FAILED=$((FAILED + 1))
fi

# Verify service was stopped before upgrade (since it was active)
if grep -q "stop amneziawg-web" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "OK: systemctl stop amneziawg-web was called during upgrade"
else
	echo "FAIL: systemctl stop was not called (service was active)"
	FAILED=$((FAILED + 1))
fi

# Verify service was restarted after upgrade (since it was active)
if grep -q "restart amneziawg-web" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "OK: systemctl restart amneziawg-web was called after upgrade"
else
	echo "FAIL: systemctl restart was not called (service was active, should auto-restart)"
	FAILED=$((FAILED + 1))
fi

# Verify upgrade output mentions preserved items
if echo "${WEB_UPGRADE_OUTPUT}" | grep -qi "preserved\|Config.*preserved\|Data.*preserved"; then
	echo "OK: Upgrader mentions preserved items in output"
else
	echo "FAIL: Upgrader output does not mention preserved items"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web upgrader: inactive service (no auto-restart) ---"

# Mark service as inactive
rm -f /tmp/awg-web-mock-started

# Clear systemctl log
rm -f /tmp/systemctl-calls.log

WEB_UPGRADE_INACTIVE_RC=0
bash "${WEB_UPGRADER_IMPL}" \
	--binary "${UPGRADE_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--force >/dev/null 2>&1 || WEB_UPGRADE_INACTIVE_RC=$?

if [[ ${WEB_UPGRADE_INACTIVE_RC} -eq 0 ]]; then
	echo "OK: Upgrader succeeds when service is inactive"
else
	echo "FAIL: Upgrader failed when service is inactive (rc=${WEB_UPGRADE_INACTIVE_RC})"
	FAILED=$((FAILED + 1))
fi

# Verify restart was NOT called (service was inactive and no --restart flag)
if grep -q "restart amneziawg-web" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "FAIL: systemctl restart was called but service was inactive (should not auto-restart)"
	FAILED=$((FAILED + 1))
else
	echo "OK: Service was not restarted (was inactive, correct default)"
fi

# Verify stop was NOT called (service was inactive)
if grep -q "stop amneziawg-web" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "FAIL: systemctl stop was called but service was not active"
	FAILED=$((FAILED + 1))
else
	echo "OK: Service was not stopped (was already inactive)"
fi

echo ""
echo "--- Web upgrader: --restart flag forces restart ---"

# Service is inactive but --restart is given
rm -f /tmp/awg-web-mock-started
rm -f /tmp/systemctl-calls.log

WEB_UPGRADE_FORCE_RESTART_RC=0
bash "${WEB_UPGRADER_IMPL}" \
	--binary "${UPGRADE_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--restart \
	--force >/dev/null 2>&1 || WEB_UPGRADE_FORCE_RESTART_RC=$?

if [[ ${WEB_UPGRADE_FORCE_RESTART_RC} -eq 0 ]]; then
	echo "OK: Upgrader with --restart exited successfully"
else
	echo "FAIL: Upgrader with --restart exited non-zero (rc=${WEB_UPGRADE_FORCE_RESTART_RC})"
	FAILED=$((FAILED + 1))
fi

# Verify restart WAS called (even though service was inactive, --restart was given)
if grep -q "restart amneziawg-web" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "OK: systemctl restart was called with --restart flag"
else
	echo "FAIL: systemctl restart was not called despite --restart flag"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web upgrader: --refresh-unit ---"

# Simulate active service
touch /tmp/awg-web-mock-started
rm -f /tmp/systemctl-calls.log

WEB_UPGRADE_REFRESH_RC=0
bash "${WEB_UPGRADER_IMPL}" \
	--binary "${UPGRADE_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--refresh-unit \
	--force >/dev/null 2>&1 || WEB_UPGRADE_REFRESH_RC=$?

if [[ ${WEB_UPGRADE_REFRESH_RC} -eq 0 ]]; then
	echo "OK: Upgrader with --refresh-unit exited successfully"
else
	echo "FAIL: Upgrader with --refresh-unit exited non-zero (rc=${WEB_UPGRADE_REFRESH_RC})"
	FAILED=$((FAILED + 1))
fi

# Verify daemon-reload was called (for refresh-unit)
if grep -q "daemon-reload" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "OK: systemctl daemon-reload was called after --refresh-unit"
else
	echo "FAIL: systemctl daemon-reload was not called after --refresh-unit"
	FAILED=$((FAILED + 1))
fi

# Verify the unit file still exists
if [[ -f /etc/systemd/system/amneziawg-web.service ]]; then
	echo "OK: systemd unit file present after --refresh-unit"
else
	echo "FAIL: systemd unit file missing after --refresh-unit"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web upgrader: idempotency (re-run upgrade) ---"

WEB_UPGRADE_RERUN_RC=0
bash "${WEB_UPGRADER_IMPL}" \
	--binary "${UPGRADE_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--force >/dev/null 2>&1 || WEB_UPGRADE_RERUN_RC=$?

if [[ ${WEB_UPGRADE_RERUN_RC} -eq 0 ]]; then
	echo "OK: Upgrader is idempotent (re-run succeeded)"
else
	echo "FAIL: Upgrader re-run exited non-zero (rc=${WEB_UPGRADE_RERUN_RC})"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Web upgrader: --non-interactive alias ---"

WEB_UPGRADE_NI_RC=0
bash "${WEB_UPGRADER_IMPL}" \
	--binary "${UPGRADE_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--non-interactive >/dev/null 2>&1 || WEB_UPGRADE_NI_RC=$?

if [[ ${WEB_UPGRADE_NI_RC} -eq 0 ]]; then
	echo "OK: Upgrader works with --non-interactive"
else
	echo "FAIL: Upgrader failed with --non-interactive (rc=${WEB_UPGRADE_NI_RC})"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "=== Phase 5: Web upgrader tests complete ==="

# ============================================================
# Phase 6: Source-build mode integration tests
# ============================================================
#
# Test assumptions / harness notes:
# - A real Rust build is too heavy for the CI integration test harness.
#   Instead, we mock `cargo` to simulate build success/failure.
# - The mock cargo creates a stub binary at the expected output path
#   (target/release/amneziawg-web) when `build --release` is called.
# - We test both the installer and upgrader source-build paths.
# - --binary-src / --binary and --source-dir mutual exclusivity is tested.
# - Missing cargo (without --install-rust) is tested.
#
echo ""
echo "=== Phase 6: Source-build mode ==="

# Create a fake source directory with a Cargo.toml to satisfy source-dir checks
MOCK_SOURCE_DIR="/tmp/awg-web-source-test"
mkdir -p "${MOCK_SOURCE_DIR}"
cat > "${MOCK_SOURCE_DIR}/Cargo.toml" <<'CARGOEOF'
[package]
name = "amneziawg-web"
version = "0.1.0-test"
edition = "2021"
CARGOEOF

# Create a mock cargo that simulates a successful build
MOCK_CARGO="/tmp/mock-cargo"
cat > "${MOCK_CARGO}" <<'MOCKCARGOEOF'
#!/bin/bash
# Mock cargo: simulate a successful build by writing a stub binary
if [[ "$1" == "build" ]]; then
    # Find the directory we're running in (working dir set by cd in the script)
    BUILD_DIR="$(pwd)"
    mkdir -p "${BUILD_DIR}/target/release"
    cat > "${BUILD_DIR}/target/release/amneziawg-web" <<'STUBBIN'
#!/bin/bash
echo "amneziawg-web stub v0.1.0-source-build-test"
STUBBIN
    chmod +x "${BUILD_DIR}/target/release/amneziawg-web"
    exit 0
fi
if [[ "$1" == "--version" ]]; then
    echo "cargo 1.80.0-mock (test harness)"
    exit 0
fi
exit 0
MOCKCARGOEOF
chmod +x "${MOCK_CARGO}"

# Create a failing mock cargo
MOCK_CARGO_FAIL="/tmp/mock-cargo-fail"
cat > "${MOCK_CARGO_FAIL}" <<'MOCKFAILEOF'
#!/bin/bash
if [[ "$1" == "build" ]]; then
    echo "error[E0001]: mock build failure" >&2
    exit 1
fi
if [[ "$1" == "--version" ]]; then
    echo "cargo 1.80.0-mock-fail (test harness)"
    exit 0
fi
exit 0
MOCKFAILEOF
chmod +x "${MOCK_CARGO_FAIL}"

# We need to reinstall a clean state first (Phase 4/5 may have uninstalled)
# But first clean up artifacts from prior phases
rm -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web"
rm -f /etc/systemd/system/amneziawg-web.service
mkdir -p "${WEB_TEST_INSTALL_DIR}" "${WEB_TEST_DATA_DIR}"
mkdir -p "$(dirname "${WEB_TEST_ENV_FILE}")"

echo ""
echo "--- Source-build: installer --source-dir success ---"

# Inject mock cargo into PATH (before real commands)
SAVED_PATH="${PATH}"
export PATH="$(dirname "${MOCK_CARGO}"):${PATH}"
# Replace /tmp/mock-cargo with a symlink named 'cargo'
ln -sf "${MOCK_CARGO}" /tmp/cargo
export PATH="/tmp:${SAVED_PATH}"

WEB_SRC_INSTALL_RC=0
WEB_SRC_INSTALL_OUTPUT=$(bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--source-dir "${MOCK_SOURCE_DIR}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--force \
	--no-start --no-enable 2>&1) || WEB_SRC_INSTALL_RC=$?

if [[ ${WEB_SRC_INSTALL_RC} -eq 0 ]]; then
	echo "OK: Source-build install exited successfully (rc=0)"
else
	echo "FAIL: Source-build install exited with non-zero code ${WEB_SRC_INSTALL_RC}"
	echo "  Output tail: $(echo "${WEB_SRC_INSTALL_OUTPUT}" | tail -20)"
	FAILED=$((FAILED + 1))
fi

# Verify binary was installed
if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary installed via source-build"
else
	echo "FAIL: Binary not found after source-build install"
	FAILED=$((FAILED + 1))
fi

if [[ -x "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Source-built binary is executable"
else
	echo "FAIL: Source-built binary is not executable"
	FAILED=$((FAILED + 1))
fi

# Verify env file was generated
if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file generated after source-build install"
else
	echo "FAIL: Env file not generated after source-build install"
	FAILED=$((FAILED + 1))
fi

# Verify the output mentions building from source
if echo "${WEB_SRC_INSTALL_OUTPUT}" | grep -qi "building\|build\|source\|cargo"; then
	echo "OK: Source-build install mentions build/source in output"
else
	echo "FAIL: Source-build install output does not mention build/source"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Source-build: installer --binary-src and --source-dir mutual exclusivity ---"

WEB_SRC_EXCL_RC=0
WEB_SRC_EXCL_OUTPUT=$(bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--binary-src "${STUB_BINARY}" \
	--source-dir "${MOCK_SOURCE_DIR}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable 2>&1) || WEB_SRC_EXCL_RC=$?

if [[ ${WEB_SRC_EXCL_RC} -ne 0 ]]; then
	echo "OK: Installer rejects --binary-src + --source-dir (rc=${WEB_SRC_EXCL_RC})"
else
	echo "FAIL: Installer should fail when both --binary-src and --source-dir are given"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_SRC_EXCL_OUTPUT}" | grep -qi "mutually exclusive\|exclusive"; then
	echo "OK: Mutual exclusivity error message is present"
else
	echo "FAIL: No helpful mutual-exclusivity message in output"
	echo "  Output: ${WEB_SRC_EXCL_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Source-build: installer missing source directory ---"

WEB_SRC_NODIR_RC=0
WEB_SRC_NODIR_OUTPUT=$(bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--source-dir "/tmp/nonexistent-source-dir-xyz" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable 2>&1) || WEB_SRC_NODIR_RC=$?

if [[ ${WEB_SRC_NODIR_RC} -ne 0 ]]; then
	echo "OK: Installer fails when source directory is missing (rc=${WEB_SRC_NODIR_RC})"
else
	echo "FAIL: Installer should fail when --source-dir does not exist"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_SRC_NODIR_OUTPUT}" | grep -qi "not exist\|not found\|source"; then
	echo "OK: Missing source-dir error message is present"
else
	echo "FAIL: No helpful message about missing source dir"
	echo "  Output: ${WEB_SRC_NODIR_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Source-build: installer missing cargo (no --install-rust) ---"

# Remove mock cargo from PATH
export PATH="${SAVED_PATH}"
# Ensure real cargo is not available by hiding it
HIDE_CARGO_DIR="/tmp/hide-cargo"
mkdir -p "${HIDE_CARGO_DIR}"
# Create a PATH that excludes common cargo locations
CLEAN_PATH=""
while IFS=':' read -ra DIRS; do
	for d in "${DIRS[@]}"; do
		case "${d}" in
			*cargo*|*rustup*) continue ;;
			*) CLEAN_PATH="${CLEAN_PATH:+${CLEAN_PATH}:}${d}" ;;
		esac
	done
done <<< "${SAVED_PATH}"
export PATH="${CLEAN_PATH}"

WEB_SRC_NOCARGO_RC=0
WEB_SRC_NOCARGO_OUTPUT=$(bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--source-dir "${MOCK_SOURCE_DIR}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--force \
	--no-start --no-enable 2>&1) || WEB_SRC_NOCARGO_RC=$?

if [[ ${WEB_SRC_NOCARGO_RC} -ne 0 ]]; then
	echo "OK: Installer fails when cargo is missing (rc=${WEB_SRC_NOCARGO_RC})"
else
	echo "FAIL: Installer should fail when cargo is not available in source-build mode"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_SRC_NOCARGO_OUTPUT}" | grep -qi "cargo\|rust\|toolchain"; then
	echo "OK: Missing cargo error message mentions cargo/rust"
else
	echo "FAIL: No helpful message about missing cargo in output"
	echo "  Output: ${WEB_SRC_NOCARGO_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

# Restore PATH
export PATH="${SAVED_PATH}"

echo ""
echo "--- Source-build: installer build failure ---"

# Use the failing mock cargo
ln -sf "${MOCK_CARGO_FAIL}" /tmp/cargo
export PATH="/tmp:${SAVED_PATH}"

WEB_SRC_BUILDFAIL_RC=0
WEB_SRC_BUILDFAIL_OUTPUT=$(bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--source-dir "${MOCK_SOURCE_DIR}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--force \
	--no-start --no-enable 2>&1) || WEB_SRC_BUILDFAIL_RC=$?

if [[ ${WEB_SRC_BUILDFAIL_RC} -ne 0 ]]; then
	echo "OK: Installer fails when cargo build fails (rc=${WEB_SRC_BUILDFAIL_RC})"
else
	echo "FAIL: Installer should fail when cargo build returns non-zero"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_SRC_BUILDFAIL_OUTPUT}" | grep -qi "build failed\|failed"; then
	echo "OK: Build failure error message is present"
else
	echo "FAIL: No helpful message about build failure"
	echo "  Output: ${WEB_SRC_BUILDFAIL_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

# Restore good mock cargo
ln -sf "${MOCK_CARGO}" /tmp/cargo
export PATH="/tmp:${SAVED_PATH}"

echo ""
echo "--- Source-build: upgrade --source-dir success ---"

# Ensure there's an installed binary to upgrade from
# (Re-install using binary mode to have a known baseline)
rm -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web"
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

# Record old binary content
OLD_BINARY_CONTENT_SRC=$(cat "${WEB_TEST_INSTALL_DIR}/amneziawg-web")

# Clear systemctl log
rm -f /tmp/systemctl-calls.log
# Mark service as active for auto-restart test
touch /tmp/awg-web-mock-started

# Clean any prior source build artifacts
rm -rf "${MOCK_SOURCE_DIR}/target"

WEB_SRC_UPGRADE_RC=0
WEB_SRC_UPGRADE_OUTPUT=$(bash "${WEB_UPGRADER_IMPL}" \
	--source-dir "${MOCK_SOURCE_DIR}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--force 2>&1) || WEB_SRC_UPGRADE_RC=$?

if [[ ${WEB_SRC_UPGRADE_RC} -eq 0 ]]; then
	echo "OK: Source-build upgrade exited successfully (rc=0)"
else
	echo "FAIL: Source-build upgrade exited with non-zero code ${WEB_SRC_UPGRADE_RC}"
	echo "  Output tail: $(echo "${WEB_SRC_UPGRADE_OUTPUT}" | tail -20)"
	FAILED=$((FAILED + 1))
fi

# Verify binary was replaced
NEW_BINARY_CONTENT_SRC=$(cat "${WEB_TEST_INSTALL_DIR}/amneziawg-web")
if [[ "${NEW_BINARY_CONTENT_SRC}" != "${OLD_BINARY_CONTENT_SRC}" ]]; then
	echo "OK: Binary content changed after source-build upgrade"
else
	echo "FAIL: Binary content is the same — source-build upgrade did not replace it"
	FAILED=$((FAILED + 1))
fi

# Verify env file is preserved
if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file preserved after source-build upgrade"
else
	echo "FAIL: Env file was removed — should be preserved during upgrade"
	FAILED=$((FAILED + 1))
fi

# Verify data directory is preserved
if [[ -d "${WEB_TEST_DATA_DIR}" ]]; then
	echo "OK: Data directory preserved after source-build upgrade"
else
	echo "FAIL: Data directory was removed — should be preserved during upgrade"
	FAILED=$((FAILED + 1))
fi

# Verify service was restarted (was active)
if grep -q "restart amneziawg-web" /tmp/systemctl-calls.log 2>/dev/null; then
	echo "OK: systemctl restart was called after source-build upgrade"
else
	echo "FAIL: systemctl restart was not called after source-build upgrade (service was active)"
	FAILED=$((FAILED + 1))
fi

echo ""
echo "--- Source-build: upgrade --binary and --source-dir mutual exclusivity ---"

WEB_UPG_EXCL_RC=0
WEB_UPG_EXCL_OUTPUT=$(bash "${WEB_UPGRADER_IMPL}" \
	--binary "${UPGRADE_BINARY}" \
	--source-dir "${MOCK_SOURCE_DIR}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--force 2>&1) || WEB_UPG_EXCL_RC=$?

if [[ ${WEB_UPG_EXCL_RC} -ne 0 ]]; then
	echo "OK: Upgrader rejects --binary + --source-dir (rc=${WEB_UPG_EXCL_RC})"
else
	echo "FAIL: Upgrader should fail when both --binary and --source-dir are given"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_UPG_EXCL_OUTPUT}" | grep -qi "mutually exclusive\|exclusive"; then
	echo "OK: Upgrade mutual exclusivity error message is present"
else
	echo "FAIL: No helpful mutual-exclusivity message in upgrade output"
	echo "  Output: ${WEB_UPG_EXCL_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

# Restore original PATH
export PATH="${SAVED_PATH}"

echo ""
echo "=== Phase 6: Source-build tests complete ==="

# ============================================================
# Phase 7: Service startup + health probe integration test
# ============================================================
#
# Test assumptions / harness notes:
# - The real Rust binary is NOT available in this test harness
# - Instead, we use an enhanced stub that simulates the service startup chain:
#   1. reads the installer-generated env file
#   2. creates the SQLite database file (simulates create_if_missing)
#   3. starts a minimal HTTP server via python3
#   4. responds to /api/health and /login
# - This catches the real-world regression where the service crash-loops
#   because the database file cannot be created
# - HTTP probing uses python3's urllib (no curl dependency)
# - systemctl is still mocked; we start the binary directly
#
echo ""
echo "=== Phase 7: Service startup + health probe ==="

# Check python3 availability (needed for the HTTP stub server)
if ! command -v python3 &>/dev/null; then
	echo "SKIP: python3 not available — cannot run HTTP health probe"
	echo "  (DB path writability is still validated below)"
	HAVE_PYTHON3=false
else
	echo "OK: python3 available for stub HTTP server"
	HAVE_PYTHON3=true
fi

# Re-install to a known clean state for this phase.
# Use a dedicated test port to avoid conflicts.
WEB_PHASE7_PORT=18742
rm -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web"
rm -f "${WEB_TEST_ENV_FILE}"
rm -rf "${WEB_TEST_DATA_DIR}"
mkdir -p "${WEB_TEST_DATA_DIR}" "${WEB_TEST_INSTALL_DIR}"

bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive \
	--force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--host 127.0.0.1 --port "${WEB_PHASE7_PORT}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

echo ""
echo "--- Phase 7a: Env file DB path writability ---"

# Source the generated env file and verify AWG_WEB_DB is set and writable
if [[ ! -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "FAIL: Env file not found at ${WEB_TEST_ENV_FILE} for startup test"
	FAILED=$((FAILED + 1))
else
	# Read AWG_WEB_DB from the generated env file
	PHASE7_DB_PATH=$(grep '^AWG_WEB_DB=' "${WEB_TEST_ENV_FILE}" | cut -d= -f2-)
	if [[ -z "${PHASE7_DB_PATH}" ]]; then
		echo "FAIL: AWG_WEB_DB not found in generated env file"
		FAILED=$((FAILED + 1))
	else
		echo "OK: AWG_WEB_DB configured as: ${PHASE7_DB_PATH}"

		# The DB file must NOT exist yet (simulates fresh install)
		rm -f "${PHASE7_DB_PATH}"

		# The data directory must exist (installer creates it)
		PHASE7_DB_DIR=$(dirname "${PHASE7_DB_PATH}")
		if [[ -d "${PHASE7_DB_DIR}" ]]; then
			echo "OK: Data directory exists: ${PHASE7_DB_DIR}"
		else
			echo "FAIL: Data directory does not exist: ${PHASE7_DB_DIR}"
			FAILED=$((FAILED + 1))
		fi

		# Simulate what the app does: create the DB file
		if touch "${PHASE7_DB_PATH}" 2>/dev/null; then
			echo "OK: Database file is creatable at ${PHASE7_DB_PATH}"
			rm -f "${PHASE7_DB_PATH}"
		else
			echo "FAIL: Cannot create database file at ${PHASE7_DB_PATH}"
			echo "  This is the exact regression that caused the service crash-loop"
			FAILED=$((FAILED + 1))
		fi
	fi
fi

echo ""
echo "--- Phase 7b: Service startup + HTTP health probe ---"

if [[ "${HAVE_PYTHON3}" != "true" ]]; then
	echo "SKIP: HTTP health probe skipped (python3 not available)"
else
	# Create an enhanced stub binary that simulates service startup
	PHASE7_STUB="${WEB_TEST_INSTALL_DIR}/amneziawg-web"
	cat > "${PHASE7_STUB}" <<'PHASE7STUBEOF'
#!/bin/bash
# Enhanced stub binary for integration testing.
# Simulates amneziawg-web service startup: reads env, creates DB, serves HTTP.

# Validate AWG_WEB_DB is set
if [[ -z "${AWG_WEB_DB}" ]]; then
	echo "ERROR: AWG_WEB_DB is not set" >&2
	exit 1
fi

# Create/touch the database file (simulates SQLx create_if_missing)
DB_PATH="${AWG_WEB_DB}"
# Strip sqlite: URL prefix if present (the Rust app handles this internally).
# Handles both sqlite:///var/lib/foo.db and sqlite:foo.db formats.
DB_PATH="${DB_PATH#sqlite://}"
DB_PATH="${DB_PATH#sqlite:}"

mkdir -p "$(dirname "${DB_PATH}")" 2>/dev/null || true
if ! touch "${DB_PATH}"; then
	echo "ERROR: Cannot create database at ${DB_PATH}" >&2
	exit 1
fi

# Extract port from AWG_WEB_LISTEN
LISTEN="${AWG_WEB_LISTEN:-0.0.0.0:8080}"
PORT="${LISTEN##*:}"

exec python3 -c "
import http.server, json, socketserver, sys, signal
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode())
        elif self.path == '/login':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body>Login</body></html>')
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *args): pass
with socketserver.TCPServer(('127.0.0.1', ${PORT}), H) as s:
    s.serve_forever()
"
PHASE7STUBEOF
	chmod +x "${PHASE7_STUB}"

	# Ensure DB file does not exist before startup
	rm -f "${WEB_TEST_DATA_DIR}/awg-web.db"

	# Start the enhanced stub with the necessary environment variables.
	# We extract specific variables from the env file using grep+cut
	# instead of sourcing it, because the env file contains Argon2 hashes
	# with literal $ characters that bash would try to expand.
	PHASE7_AWG_DB=$(grep '^AWG_WEB_DB=' "${WEB_TEST_ENV_FILE}" | cut -d= -f2-)
	PHASE7_AWG_LISTEN=$(grep '^AWG_WEB_LISTEN=' "${WEB_TEST_ENV_FILE}" | cut -d= -f2-)

	AWG_WEB_DB="${PHASE7_AWG_DB}" AWG_WEB_LISTEN="${PHASE7_AWG_LISTEN}" \
		"${PHASE7_STUB}" &
	PHASE7_PID=$!

	# Poll for the server to come up (max 5 seconds, 100ms intervals)
	PHASE7_UP=false
	for _i in $(seq 1 50); do
		if python3 -c "
import urllib.request, sys
try:
    urllib.request.urlopen('http://127.0.0.1:${WEB_PHASE7_PORT}/api/health', timeout=1)
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
			PHASE7_UP=true
			break
		fi
		sleep 0.1
	done

	if [[ "${PHASE7_UP}" == "true" ]]; then
		echo "OK: Stub service started and is accepting connections"
	else
		echo "FAIL: Stub service did not start within 5 seconds"
		FAILED=$((FAILED + 1))
	fi

	# Probe /api/health and verify JSON response
	if [[ "${PHASE7_UP}" == "true" ]]; then
		HEALTH_RESPONSE=$(python3 -c "
import urllib.request, json, sys
try:
    resp = urllib.request.urlopen('http://127.0.0.1:${WEB_PHASE7_PORT}/api/health', timeout=5)
    data = json.loads(resp.read())
    print(data.get('status', ''))
except Exception as e:
    print(f'error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null) || true

		if [[ "${HEALTH_RESPONSE}" == "ok" ]]; then
			echo "OK: /api/health returned {\"status\": \"ok\"}"
		else
			echo "FAIL: /api/health did not return expected response"
			echo "  Got: ${HEALTH_RESPONSE}"
			FAILED=$((FAILED + 1))
		fi
	fi

	# Probe /login and verify it responds
	if [[ "${PHASE7_UP}" == "true" ]]; then
		LOGIN_RC=0
		python3 -c "
import urllib.request, sys
try:
    resp = urllib.request.urlopen('http://127.0.0.1:${WEB_PHASE7_PORT}/login', timeout=5)
    if resp.status == 200:
        sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null || LOGIN_RC=$?

		if [[ ${LOGIN_RC} -eq 0 ]]; then
			echo "OK: /login endpoint responds with 200"
		else
			echo "FAIL: /login endpoint did not respond"
			FAILED=$((FAILED + 1))
		fi
	fi

	# Verify database file was created by the stub service
	if [[ -f "${WEB_TEST_DATA_DIR}/awg-web.db" ]]; then
		echo "OK: Database file created by service at ${WEB_TEST_DATA_DIR}/awg-web.db"
	else
		echo "FAIL: Database file was not created by service startup"
		echo "  This is the exact regression: service could not create its DB"
		FAILED=$((FAILED + 1))
	fi

	# Clean up: kill the stub server
	if [[ -n "${PHASE7_PID}" ]] && kill -0 "${PHASE7_PID}" 2>/dev/null; then
		kill "${PHASE7_PID}" 2>/dev/null || true
		wait "${PHASE7_PID}" 2>/dev/null || true
		echo "OK: Stub service stopped cleanly"
	fi
fi

echo ""
echo "=== Phase 7: Service startup tests complete ==="

# ============================================================
# Phase 8: Peer visibility via AWG polling
# ============================================================
#
# Test assumptions / harness notes:
# - The mock awg binary supports `show all dump` (tab-separated format)
# - The mock sudo delegates to the actual command (we are root in Docker)
# - The enhanced stub binary runs a python3 HTTP server that also:
#   1. calls `sudo /usr/bin/awg show all dump` (or our mock equivalent)
#   2. stores the output for retrieval via /api/peers
# - This validates the full chain: service → sudo → awg → parse → API
# - This test would have caught the real-box failure (Operation not permitted)
#
echo ""
echo "=== Phase 8: Peer visibility via AWG polling ==="

if [[ "${HAVE_PYTHON3}" != "true" ]]; then
	echo "SKIP: Peer visibility test skipped (python3 not available)"
else
	# Create an enhanced stub that simulates the poller calling sudo awg show all dump
	PHASE8_PORT=18743
	rm -f "${WEB_TEST_ENV_FILE}"
	rm -rf "${WEB_TEST_DATA_DIR}"
	mkdir -p "${WEB_TEST_DATA_DIR}" "${WEB_TEST_INSTALL_DIR}"

	bash "${WEB_INSTALLER_IMPL}" \
		--non-interactive \
		--force \
		--binary-src "${STUB_BINARY}" \
		--install-dir "${WEB_TEST_INSTALL_DIR}" \
		--data-dir "${WEB_TEST_DATA_DIR}" \
		--env-file "${WEB_TEST_ENV_FILE}" \
		--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
		--host 127.0.0.1 --port "${PHASE8_PORT}" \
		--username testadmin \
		--password-hash "${TEST_PASSWORD_HASH}" \
		--no-start --no-enable >/dev/null 2>&1

	# Build a stub that calls sudo /usr/bin/awg show all dump and serves the result
	PHASE8_STUB="${WEB_TEST_INSTALL_DIR}/amneziawg-web"
	cat > "${PHASE8_STUB}" <<'PHASE8STUBEOF'
#!/bin/bash
# Enhanced stub: simulates amneziawg-web with AWG polling.
# 1. Creates DB file
# 2. Calls sudo -n /usr/bin/awg show all dump (or mock equivalent)
# 3. Serves parsed results via /api/peers

if [[ -z "${AWG_WEB_DB}" ]]; then
	echo "ERROR: AWG_WEB_DB is not set" >&2
	exit 1
fi

DB_PATH="${AWG_WEB_DB}"
DB_PATH="${DB_PATH#sqlite://}"
DB_PATH="${DB_PATH#sqlite:}"
mkdir -p "$(dirname "${DB_PATH}")" 2>/dev/null || true
if ! touch "${DB_PATH}"; then
	echo "ERROR: Cannot create database at ${DB_PATH}" >&2
	exit 1
fi

LISTEN="${AWG_WEB_LISTEN:-0.0.0.0:8080}"
PORT="${LISTEN##*:}"

# Call sudo awg show all dump and capture the output.
# This exercises the exact privilege path the real app uses.
AWG_DUMP=$(/usr/bin/sudo -n /usr/bin/awg show all dump 2>&1) || {
	echo "ERROR: sudo awg show all dump failed: ${AWG_DUMP}" >&2
	# Still start the server, but report the error via /api/peers
	AWG_DUMP="POLL_ERROR: ${AWG_DUMP}"
}

# Export for python to read
export AWG_DUMP

exec python3 -c "
import http.server, json, socketserver, sys, signal, os
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))

awg_dump = os.environ.get('AWG_DUMP', '')

# Parse tab-separated awg dump into peer list
peers = []
for line in awg_dump.strip().split('\n'):
    fields = line.split('\t')
    if len(fields) >= 9:
        peers.append({
            'interface': fields[0],
            'public_key': fields[1],
            'endpoint': fields[3] if fields[3] != '(none)' else None,
            'allowed_ips': fields[4],
            'rx_bytes': int(fields[6]) if fields[6].isdigit() else 0,
            'tx_bytes': int(fields[7]) if fields[7].isdigit() else 0,
        })

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode())
        elif self.path == '/api/peers':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'peers': peers, 'raw': awg_dump}).encode())
        elif self.path == '/login':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body>Login</body></html>')
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *args): pass
with socketserver.TCPServer(('127.0.0.1', ${PORT}), H) as s:
    s.serve_forever()
"
PHASE8STUBEOF
	chmod +x "${PHASE8_STUB}"

	rm -f "${WEB_TEST_DATA_DIR}/awg-web.db"

	PHASE8_AWG_DB=$(grep '^AWG_WEB_DB=' "${WEB_TEST_ENV_FILE}" | cut -d= -f2-)
	PHASE8_AWG_LISTEN=$(grep '^AWG_WEB_LISTEN=' "${WEB_TEST_ENV_FILE}" | cut -d= -f2-)

	AWG_WEB_DB="${PHASE8_AWG_DB}" AWG_WEB_LISTEN="${PHASE8_AWG_LISTEN}" \
		"${PHASE8_STUB}" &
	PHASE8_PID=$!

	# Wait for the server to come up
	PHASE8_UP=false
	for _i in $(seq 1 50); do
		if python3 -c "
import urllib.request, sys
try:
    urllib.request.urlopen('http://127.0.0.1:${PHASE8_PORT}/api/health', timeout=1)
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
			PHASE8_UP=true
			break
		fi
		sleep 0.1
	done

	if [[ "${PHASE8_UP}" == "true" ]]; then
		echo "OK: Phase 8 stub service started and is accepting connections"
	else
		echo "FAIL: Phase 8 stub service did not start within 5 seconds"
		FAILED=$((FAILED + 1))
	fi

	# Test 1: Verify the sudo→awg chain works (no "Operation not permitted")
	if [[ "${PHASE8_UP}" == "true" ]]; then
		PEERS_RESPONSE=$(python3 -c "
import urllib.request, json, sys
try:
    resp = urllib.request.urlopen('http://127.0.0.1:${PHASE8_PORT}/api/peers', timeout=5)
    data = json.loads(resp.read())
    print(json.dumps(data))
except Exception as e:
    print(json.dumps({'error': str(e)}))
    sys.exit(1)
" 2>/dev/null) || true

		# Check that the raw dump does NOT contain an error
		if echo "${PEERS_RESPONSE}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
raw = data.get('raw', '')
if 'POLL_ERROR' in raw or 'Operation not permitted' in raw:
    print('ERROR: AWG poll failed: ' + raw)
    sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
			echo "OK: AWG polling succeeded (no permission error)"
		else
			echo "FAIL: AWG polling returned a permission error"
			echo "  This is the exact real-box regression: awg-web user cannot access AWG interface"
			echo "  Response: ${PEERS_RESPONSE}"
			FAILED=$((FAILED + 1))
		fi

		# Test 2: Verify at least one peer is visible
		PEER_COUNT=$(echo "${PEERS_RESPONSE}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(len(data.get('peers', [])))
except:
    print(0)
" 2>/dev/null) || PEER_COUNT=0

		if [[ "${PEER_COUNT}" -gt 0 ]]; then
			echo "OK: /api/peers returned ${PEER_COUNT} peer(s) — peer visibility works"
		else
			echo "FAIL: /api/peers returned 0 peers — peer visibility broken"
			echo "  Response: ${PEERS_RESPONSE}"
			FAILED=$((FAILED + 1))
		fi

		# Test 3: Verify the peer has expected data (public key, endpoint)
		if [[ "${PEER_COUNT}" -gt 0 ]]; then
			HAS_PUBKEY=$(echo "${PEERS_RESPONSE}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
p = data.get('peers', [{}])[0]
print('yes' if p.get('public_key') else 'no')
" 2>/dev/null) || HAS_PUBKEY="no"

			if [[ "${HAS_PUBKEY}" == "yes" ]]; then
				echo "OK: First peer has a public key"
			else
				echo "FAIL: First peer is missing public key"
				FAILED=$((FAILED + 1))
			fi
		fi
	fi

	# Clean up: kill the stub server
	if [[ -n "${PHASE8_PID}" ]] && kill -0 "${PHASE8_PID}" 2>/dev/null; then
		kill "${PHASE8_PID}" 2>/dev/null || true
		wait "${PHASE8_PID}" 2>/dev/null || true
		echo "OK: Phase 8 stub service stopped cleanly"
	fi
fi

echo ""
echo "=== Phase 8: Peer visibility tests complete ==="

# ============================================================
# Phase 9: Root wrapper delegation and standalone bootstrap
# ============================================================
#
# Test scenarios:
# a) Repo-clone scenario: all three root-level wrappers (install, uninstall,
#    upgrade) correctly delegate to the inner scripts when the repository is
#    present locally.
# b) Standalone bootstrap scenario: install/uninstall root wrappers work when
#    the inner scripts are NOT present locally. A mock git simulates a
#    successful bootstrap clone by copying from the local repository checkout,
#    so no network access is required.
# c) Standalone error path: install/uninstall root wrappers exit non-zero with
#    a helpful message when the inner script is missing and git clone fails.
#
echo ""
echo "=== Phase 9: Root wrapper delegation and standalone bootstrap ==="

# ---- Phase 9a: Repo-clone scenario — root wrappers delegate to inner scripts ----
echo ""
echo "--- Phase 9a: Root wrappers with inner scripts present ---"

# Establish a clean installed baseline using the inner installer directly.
rm -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web"
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive --force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

# 9a-1: Uninstall via root wrapper
WEB_ROOT9_UNINSTALL_RC=0
bash "${WEB_UNINSTALLER}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--force >/dev/null 2>&1 || WEB_ROOT9_UNINSTALL_RC=$?

if [[ ${WEB_ROOT9_UNINSTALL_RC} -eq 0 ]]; then
	echo "OK: Root uninstall wrapper delegates to inner script (rc=0)"
else
	echo "FAIL: Root uninstall wrapper exited non-zero (rc=${WEB_ROOT9_UNINSTALL_RC})"
	FAILED=$((FAILED + 1))
fi

if [[ ! -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary removed via root uninstall wrapper"
else
	echo "FAIL: Binary still present after root uninstall wrapper"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file preserved (safe default) by root uninstall wrapper"
else
	echo "FAIL: Env file removed — root uninstall should preserve it by default"
	FAILED=$((FAILED + 1))
fi

# 9a-2: Install via root wrapper
WEB_ROOT9_INSTALL_RC=0
bash "${WEB_INSTALLER}" \
	--non-interactive --force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1 || WEB_ROOT9_INSTALL_RC=$?

if [[ ${WEB_ROOT9_INSTALL_RC} -eq 0 ]]; then
	echo "OK: Root install wrapper delegates to inner script (rc=0)"
else
	echo "FAIL: Root install wrapper exited non-zero (rc=${WEB_ROOT9_INSTALL_RC})"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary installed via root install wrapper"
else
	echo "FAIL: Binary not found after root install wrapper"
	FAILED=$((FAILED + 1))
fi

# 9a-3: Upgrade via root wrapper
PHASE9_UPGRADE_BIN="/tmp/amneziawg-web-phase9-upgrade"
cat > "${PHASE9_UPGRADE_BIN}" <<'PHASE9UPGEOF'
#!/bin/bash
echo "amneziawg-web stub v0.0.0-phase9-upgrade"
PHASE9UPGEOF
chmod +x "${PHASE9_UPGRADE_BIN}"

WEB_ROOT9_UPGRADE_RC=0
bash "${WEB_UPGRADER}" \
	--binary "${PHASE9_UPGRADE_BIN}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--force >/dev/null 2>&1 || WEB_ROOT9_UPGRADE_RC=$?

if [[ ${WEB_ROOT9_UPGRADE_RC} -eq 0 ]]; then
	echo "OK: Root upgrade wrapper delegates to inner script (rc=0)"
else
	echo "FAIL: Root upgrade wrapper exited non-zero (rc=${WEB_ROOT9_UPGRADE_RC})"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]] && \
	[[ "$(sha256sum "${WEB_TEST_INSTALL_DIR}/amneziawg-web" | awk '{print $1}')" == \
	   "$(sha256sum "${PHASE9_UPGRADE_BIN}" | awk '{print $1}')" ]]; then
	echo "OK: Binary replaced via root upgrade wrapper"
else
	echo "FAIL: Binary not replaced via root upgrade wrapper"
	FAILED=$((FAILED + 1))
fi

# ---- Phase 9b: Standalone bootstrap — mock git clone (no inner scripts) ----
echo ""
echo "--- Phase 9b: Standalone bootstrap via mock git clone ---"

# Create a mock git that simulates a successful bootstrap clone by copying the
# local repository checkout.  The real git clone call in the wrapper is:
#   git clone --depth 1 --branch main <url> <target_dir>
# The target_dir is the last positional argument and is already created by
# mktemp before git is invoked, so we copy INTO that existing directory.
PHASE9_MOCK_GIT_DIR="$(mktemp -d /tmp/awg-mock-git.XXXXXX)"
cat > "${PHASE9_MOCK_GIT_DIR}/git" <<PHASE9GITMOCKEOF
#!/bin/bash
# Mock git: simulate a successful clone by copying from the local repository.
if [[ "\$1" == "clone" ]]; then
	# Get the last positional argument (the target directory).
	TARGET=""
	for _a in "\$@"; do TARGET="\${_a}"; done
	cp -r "${PROJECT_ROOT}/." "\${TARGET}/"
	exit 0
fi
exit 0
PHASE9GITMOCKEOF
chmod +x "${PHASE9_MOCK_GIT_DIR}/git"

# Create a standalone directory containing only the root-level wrappers —
# no amneziawg-web/scripts/ directory — to simulate a bare-download scenario.
PHASE9_STANDALONE_DIR="$(mktemp -d /tmp/awg-standalone.XXXXXX)"
cp "${WEB_UNIFIED}"     "${PHASE9_STANDALONE_DIR}/amneziawg-web.sh"
cp "${WEB_INSTALLER}"   "${PHASE9_STANDALONE_DIR}/amneziawg-web-install.sh"
cp "${WEB_UNINSTALLER}" "${PHASE9_STANDALONE_DIR}/amneziawg-web-uninstall.sh"

# Ensure a clean state for the standalone install.
bash "${WEB_UNINSTALLER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--purge-config --purge-data \
	--force >/dev/null 2>&1 || true
rm -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web"
mkdir -p "${WEB_TEST_INSTALL_DIR}" "${WEB_TEST_DATA_DIR}" \
	"$(dirname "${WEB_TEST_ENV_FILE}")"

# 9b-1: Standalone install — root wrapper bootstraps via mock git clone.
WEB_BOOTSTRAP9_INSTALL_RC=0
WEB_BOOTSTRAP9_INSTALL_OUTPUT=$(PATH="${PHASE9_MOCK_GIT_DIR}:${PATH}" \
	bash "${PHASE9_STANDALONE_DIR}/amneziawg-web-install.sh" \
	--non-interactive --force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable 2>&1) || WEB_BOOTSTRAP9_INSTALL_RC=$?

if [[ ${WEB_BOOTSTRAP9_INSTALL_RC} -eq 0 ]]; then
	echo "OK: Standalone install bootstraps via mock git clone (rc=0)"
else
	echo "FAIL: Standalone install via bootstrap clone failed (rc=${WEB_BOOTSTRAP9_INSTALL_RC})"
	echo "  Output tail: $(echo "${WEB_BOOTSTRAP9_INSTALL_OUTPUT}" | tail -10)"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary installed via standalone bootstrap"
else
	echo "FAIL: Binary not found after standalone bootstrap install"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file created via standalone bootstrap install"
else
	echo "FAIL: Env file missing after standalone bootstrap install"
	FAILED=$((FAILED + 1))
fi

# The wrapper prints the clone message to stderr; with 2>&1 it is in OUTPUT.
if echo "${WEB_BOOTSTRAP9_INSTALL_OUTPUT}" | grep -qiE "cloning|clone|bootstrap"; then
	echo "OK: Standalone install output mentions cloning/bootstrapping"
else
	echo "WARN: Standalone install output does not mention cloning (check stderr capture)"
fi

# 9b-2: Standalone uninstall — root wrapper bootstraps via mock git clone.
WEB_BOOTSTRAP9_UNINSTALL_RC=0
WEB_BOOTSTRAP9_UNINSTALL_OUTPUT=$(PATH="${PHASE9_MOCK_GIT_DIR}:${PATH}" \
	bash "${PHASE9_STANDALONE_DIR}/amneziawg-web-uninstall.sh" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--force 2>&1) || WEB_BOOTSTRAP9_UNINSTALL_RC=$?

if [[ ${WEB_BOOTSTRAP9_UNINSTALL_RC} -eq 0 ]]; then
	echo "OK: Standalone uninstall bootstraps via mock git clone (rc=0)"
else
	echo "FAIL: Standalone uninstall via bootstrap clone failed (rc=${WEB_BOOTSTRAP9_UNINSTALL_RC})"
	echo "  Output tail: $(echo "${WEB_BOOTSTRAP9_UNINSTALL_OUTPUT}" | tail -10)"
	FAILED=$((FAILED + 1))
fi

if [[ ! -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary removed via standalone bootstrap uninstall"
else
	echo "FAIL: Binary still present after standalone bootstrap uninstall"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_ENV_FILE}" ]]; then
	echo "OK: Env file preserved (safe default) after standalone bootstrap uninstall"
else
	echo "FAIL: Env file removed — root uninstall should preserve it by default"
	FAILED=$((FAILED + 1))
fi

# ---- Phase 9c: Standalone error path — git clone fails ----
echo ""
echo "--- Phase 9c: Standalone error path — git clone fails ---"

# Create a mock git that is present in PATH but always fails on clone,
# simulating a network failure or an unreachable repository.
PHASE9_FAIL_GIT_DIR="$(mktemp -d /tmp/awg-fail-git.XXXXXX)"
cat > "${PHASE9_FAIL_GIT_DIR}/git" <<'PHASE9FAILGITMOCKEOF'
#!/bin/bash
# Mock git: fail on clone to simulate a network or repository error.
if [[ "$1" == "clone" ]]; then
	echo "fatal: unable to access repository (mock network failure)" >&2
	exit 1
fi
exit 0
PHASE9FAILGITMOCKEOF
chmod +x "${PHASE9_FAIL_GIT_DIR}/git"

PHASE9_STANDALONE_FAIL_DIR="$(mktemp -d /tmp/awg-standalone-fail.XXXXXX)"
cp "${WEB_UNIFIED}"     "${PHASE9_STANDALONE_FAIL_DIR}/amneziawg-web.sh"
cp "${WEB_INSTALLER}"   "${PHASE9_STANDALONE_FAIL_DIR}/amneziawg-web-install.sh"
cp "${WEB_UNINSTALLER}" "${PHASE9_STANDALONE_FAIL_DIR}/amneziawg-web-uninstall.sh"

# 9c-1: Install wrapper — git clone fails → exits non-zero with error message.
WEB_CLONEFAIL9_INSTALL_RC=0
WEB_CLONEFAIL9_INSTALL_OUTPUT=$(PATH="${PHASE9_FAIL_GIT_DIR}:${PATH}" \
	bash "${PHASE9_STANDALONE_FAIL_DIR}/amneziawg-web-install.sh" \
	--non-interactive \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable 2>&1) || WEB_CLONEFAIL9_INSTALL_RC=$?

if [[ ${WEB_CLONEFAIL9_INSTALL_RC} -ne 0 ]]; then
	echo "OK: Standalone install exits non-zero when git clone fails"
else
	echo "FAIL: Standalone install should fail when git clone fails"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_CLONEFAIL9_INSTALL_OUTPUT}" | grep -qiE "failed|error"; then
	echo "OK: Standalone install error message is present when git clone fails"
else
	echo "FAIL: Standalone install missing helpful error message when git clone fails"
	echo "  Output: ${WEB_CLONEFAIL9_INSTALL_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

# 9c-2: Uninstall wrapper — git clone fails → exits non-zero with error message.
WEB_CLONEFAIL9_UNINSTALL_RC=0
WEB_CLONEFAIL9_UNINSTALL_OUTPUT=$(PATH="${PHASE9_FAIL_GIT_DIR}:${PATH}" \
	bash "${PHASE9_STANDALONE_FAIL_DIR}/amneziawg-web-uninstall.sh" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--force 2>&1) || WEB_CLONEFAIL9_UNINSTALL_RC=$?

if [[ ${WEB_CLONEFAIL9_UNINSTALL_RC} -ne 0 ]]; then
	echo "OK: Standalone uninstall exits non-zero when git clone fails"
else
	echo "FAIL: Standalone uninstall should fail when git clone fails"
	FAILED=$((FAILED + 1))
fi

if echo "${WEB_CLONEFAIL9_UNINSTALL_OUTPUT}" | grep -qiE "failed|error"; then
	echo "OK: Standalone uninstall error message is present when git clone fails"
else
	echo "FAIL: Standalone uninstall missing helpful error message when git clone fails"
	echo "  Output: ${WEB_CLONEFAIL9_UNINSTALL_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

# ---- Phase 9 clean-up ----
rm -rf "${PHASE9_STANDALONE_DIR}" "${PHASE9_STANDALONE_FAIL_DIR}"
rm -rf "${PHASE9_MOCK_GIT_DIR}" "${PHASE9_FAIL_GIT_DIR}"
rm -f  "${PHASE9_UPGRADE_BIN}"

echo ""
echo "=== Phase 9: Root wrapper and standalone bootstrap tests complete ==="

# ============================================================
# Phase 10: Unified entry point (amneziawg-web.sh)
# ============================================================
#
# Test scenarios:
# a) help / no-args output
# b) status subcommand
# c) install / uninstall / upgrade via unified script
# d) unknown subcommand error
# e) standalone bootstrap via unified script
#
echo ""
echo "=== Phase 10: Unified entry point (amneziawg-web.sh) ==="

# ---- Phase 10a: help and no-args ----
echo ""
echo "--- Phase 10a: help output and no-args default ---"

# No arguments: should show help and exit 0
UNIFIED_NOARGS_RC=0
UNIFIED_NOARGS_OUTPUT=$(bash "${WEB_UNIFIED}" 2>&1) || UNIFIED_NOARGS_RC=$?

if [[ ${UNIFIED_NOARGS_RC} -eq 0 ]]; then
	echo "OK: Unified script exits 0 with no arguments"
else
	echo "FAIL: Unified script exited non-zero with no arguments (rc=${UNIFIED_NOARGS_RC})"
	FAILED=$((FAILED + 1))
fi

if echo "${UNIFIED_NOARGS_OUTPUT}" | grep -qiE "install|upgrade|uninstall|status|help"; then
	echo "OK: No-args output lists available commands"
else
	echo "FAIL: No-args output does not list available commands"
	FAILED=$((FAILED + 1))
fi

# help subcommand: should list all commands
UNIFIED_HELP_RC=0
UNIFIED_HELP_OUTPUT=$(bash "${WEB_UNIFIED}" help 2>&1) || UNIFIED_HELP_RC=$?

if [[ ${UNIFIED_HELP_RC} -eq 0 ]]; then
	echo "OK: Unified help exits 0"
else
	echo "FAIL: Unified help exited non-zero (rc=${UNIFIED_HELP_RC})"
	FAILED=$((FAILED + 1))
fi

if echo "${UNIFIED_HELP_OUTPUT}" | grep -q "install" && \
   echo "${UNIFIED_HELP_OUTPUT}" | grep -q "upgrade" && \
   echo "${UNIFIED_HELP_OUTPUT}" | grep -q "uninstall" && \
   echo "${UNIFIED_HELP_OUTPUT}" | grep -q "status"; then
	echo "OK: Help output lists install, upgrade, uninstall, status"
else
	echo "FAIL: Help output missing expected commands"
	echo "  Output: $(echo "${UNIFIED_HELP_OUTPUT}" | head -5)"
	FAILED=$((FAILED + 1))
fi

# ---- Phase 10b: unknown subcommand ----
echo ""
echo "--- Phase 10b: unknown subcommand ---"

UNIFIED_UNKNOWN_RC=0
UNIFIED_UNKNOWN_OUTPUT=$(bash "${WEB_UNIFIED}" frobnicate 2>&1) || UNIFIED_UNKNOWN_RC=$?

if [[ ${UNIFIED_UNKNOWN_RC} -ne 0 ]]; then
	echo "OK: Unknown subcommand exits non-zero (rc=${UNIFIED_UNKNOWN_RC})"
else
	echo "FAIL: Unknown subcommand should exit non-zero"
	FAILED=$((FAILED + 1))
fi

if echo "${UNIFIED_UNKNOWN_OUTPUT}" | grep -qiE "unknown|frobnicate"; then
	echo "OK: Unknown subcommand error message is present"
else
	echo "FAIL: Unknown subcommand missing helpful error message"
	FAILED=$((FAILED + 1))
fi

# ---- Phase 10c: status subcommand ----
echo ""
echo "--- Phase 10c: status subcommand ---"

# Re-install so status sees an installed binary
rm -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web"
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive --force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

UNIFIED_STATUS_RC=0
UNIFIED_STATUS_OUTPUT=$(bash "${WEB_UNIFIED}" status \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" 2>&1) || UNIFIED_STATUS_RC=$?

# Strip ANSI color escape codes so anchored grep patterns match cleanly
UNIFIED_STATUS_OUTPUT=$(printf '%s' "${UNIFIED_STATUS_OUTPUT}" | sed 's/\x1b\[[0-9;]*m//g')

if [[ ${UNIFIED_STATUS_RC} -eq 0 ]]; then
	echo "OK: Status subcommand exits 0"
else
	echo "FAIL: Status subcommand exited non-zero (rc=${UNIFIED_STATUS_RC})"
	FAILED=$((FAILED + 1))
fi

if echo "${UNIFIED_STATUS_OUTPUT}" | grep -qiE '^[[:space:]]*Installed:[[:space:]]*yes([[:space:]]|$)'; then
	echo "OK: Status reports installed = yes"
else
	echo "FAIL: Status does not report installed state"
	echo "  Output: ${UNIFIED_STATUS_OUTPUT}"
	FAILED=$((FAILED + 1))
fi

if echo "${UNIFIED_STATUS_OUTPUT}" | grep -qiE '^[[:space:]]*Service:.*(active|inactive)'; then
	echo "OK: Status reports service state"
else
	echo "FAIL: Status does not report service state"
	FAILED=$((FAILED + 1))
fi

# ---- Phase 10d: install + uninstall via unified script ----
echo ""
echo "--- Phase 10d: install and uninstall via unified script ---"

# Uninstall via unified script
bash "${WEB_UNINSTALLER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--force >/dev/null 2>&1 || true
rm -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web"

# Install via unified script
UNIFIED_INSTALL_RC=0
bash "${WEB_UNIFIED}" install \
	--non-interactive --force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1 || UNIFIED_INSTALL_RC=$?

if [[ ${UNIFIED_INSTALL_RC} -eq 0 ]]; then
	echo "OK: Unified install subcommand delegates successfully (rc=0)"
else
	echo "FAIL: Unified install subcommand exited non-zero (rc=${UNIFIED_INSTALL_RC})"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary installed via unified install subcommand"
else
	echo "FAIL: Binary not found after unified install subcommand"
	FAILED=$((FAILED + 1))
fi

# Uninstall via unified script
UNIFIED_UNINSTALL_RC=0
bash "${WEB_UNIFIED}" uninstall \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--force >/dev/null 2>&1 || UNIFIED_UNINSTALL_RC=$?

if [[ ${UNIFIED_UNINSTALL_RC} -eq 0 ]]; then
	echo "OK: Unified uninstall subcommand delegates successfully (rc=0)"
else
	echo "FAIL: Unified uninstall subcommand exited non-zero (rc=${UNIFIED_UNINSTALL_RC})"
	FAILED=$((FAILED + 1))
fi

if [[ ! -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary removed via unified uninstall subcommand"
else
	echo "FAIL: Binary still present after unified uninstall subcommand"
	FAILED=$((FAILED + 1))
fi

# ---- Phase 10e: upgrade via unified script ----
echo ""
echo "--- Phase 10e: upgrade via unified script ---"

# Re-install for upgrade test
bash "${WEB_INSTALLER_IMPL}" \
	--non-interactive --force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable >/dev/null 2>&1

PHASE10_UPGRADE_BIN="/tmp/amneziawg-web-phase10-upgrade"
cat > "${PHASE10_UPGRADE_BIN}" <<'PHASE10UPGEOF'
#!/bin/bash
echo "amneziawg-web stub v0.0.0-phase10-upgrade"
PHASE10UPGEOF
chmod +x "${PHASE10_UPGRADE_BIN}"

UNIFIED_UPGRADE_RC=0
bash "${WEB_UNIFIED}" upgrade \
	--binary "${PHASE10_UPGRADE_BIN}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--force >/dev/null 2>&1 || UNIFIED_UPGRADE_RC=$?

if [[ ${UNIFIED_UPGRADE_RC} -eq 0 ]]; then
	echo "OK: Unified upgrade subcommand delegates successfully (rc=0)"
else
	echo "FAIL: Unified upgrade subcommand exited non-zero (rc=${UNIFIED_UPGRADE_RC})"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]] && \
	[[ "$(sha256sum "${WEB_TEST_INSTALL_DIR}/amneziawg-web" | awk '{print $1}')" == \
	   "$(sha256sum "${PHASE10_UPGRADE_BIN}" | awk '{print $1}')" ]]; then
	echo "OK: Binary replaced via unified upgrade subcommand"
else
	echo "FAIL: Binary not replaced via unified upgrade subcommand"
	FAILED=$((FAILED + 1))
fi

rm -f "${PHASE10_UPGRADE_BIN}"

# ---- Phase 10f: standalone bootstrap via unified script ----
echo ""
echo "--- Phase 10f: standalone bootstrap via unified script ---"

# Create a standalone directory containing only amneziawg-web.sh
PHASE10_STANDALONE_DIR="$(mktemp -d /tmp/awg-standalone-unified.XXXXXX)"
cp "${WEB_UNIFIED}" "${PHASE10_STANDALONE_DIR}/amneziawg-web.sh"

# Ensure a clean state
bash "${WEB_UNINSTALLER_IMPL}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--purge-config --purge-data \
	--force >/dev/null 2>&1 || true
rm -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web"
mkdir -p "${WEB_TEST_INSTALL_DIR}" "${WEB_TEST_DATA_DIR}" \
	"$(dirname "${WEB_TEST_ENV_FILE}")"

# Use mock git from Phase 9 (or create one if clean-up removed it)
PHASE10_MOCK_GIT_DIR="$(mktemp -d /tmp/awg-mock-git-ph10.XXXXXX)"
cat > "${PHASE10_MOCK_GIT_DIR}/git" <<PHASE10GITMOCKEOF
#!/bin/bash
if [[ "\$1" == "clone" ]]; then
	TARGET=""
	for _a in "\$@"; do TARGET="\${_a}"; done
	cp -r "${PROJECT_ROOT}/." "\${TARGET}/"
	exit 0
fi
exit 0
PHASE10GITMOCKEOF
chmod +x "${PHASE10_MOCK_GIT_DIR}/git"

# Install via standalone unified script with mock git
UNIFIED_BOOTSTRAP_RC=0
UNIFIED_BOOTSTRAP_OUTPUT=$(PATH="${PHASE10_MOCK_GIT_DIR}:${PATH}" \
	bash "${PHASE10_STANDALONE_DIR}/amneziawg-web.sh" install \
	--non-interactive --force \
	--binary-src "${STUB_BINARY}" \
	--install-dir "${WEB_TEST_INSTALL_DIR}" \
	--data-dir "${WEB_TEST_DATA_DIR}" \
	--env-file "${WEB_TEST_ENV_FILE}" \
	--config-dir "${WEB_TEST_AWG_CONFIG_DIR}" \
	--username testadmin \
	--password-hash "${TEST_PASSWORD_HASH}" \
	--no-start --no-enable 2>&1) || UNIFIED_BOOTSTRAP_RC=$?

if [[ ${UNIFIED_BOOTSTRAP_RC} -eq 0 ]]; then
	echo "OK: Standalone unified install bootstraps via mock git clone (rc=0)"
else
	echo "FAIL: Standalone unified install via bootstrap clone failed (rc=${UNIFIED_BOOTSTRAP_RC})"
	echo "  Output tail: $(echo "${UNIFIED_BOOTSTRAP_OUTPUT}" | tail -10)"
	FAILED=$((FAILED + 1))
fi

if [[ -f "${WEB_TEST_INSTALL_DIR}/amneziawg-web" ]]; then
	echo "OK: Binary installed via standalone unified bootstrap"
else
	echo "FAIL: Binary not found after standalone unified bootstrap install"
	FAILED=$((FAILED + 1))
fi

if echo "${UNIFIED_BOOTSTRAP_OUTPUT}" | grep -qiE "cloning|clone|bootstrap"; then
	echo "OK: Standalone unified install output mentions cloning/bootstrapping"
else
	echo "WARN: Standalone unified install output does not mention cloning (check stderr capture)"
fi

rm -rf "${PHASE10_STANDALONE_DIR}" "${PHASE10_MOCK_GIT_DIR}"

echo ""
echo "=== Phase 10: Unified entry point tests complete ==="

echo ""
echo "=========================================="
if [[ ${FAILED} -eq 0 ]]; then
	echo "Integration test PASSED"
else
	echo "Integration test FAILED (${FAILED} failures)"
fi
echo "=========================================="

exit ${FAILED}
