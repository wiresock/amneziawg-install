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

# Ensure running as root
if [[ "$(id -u)" -ne 0 ]]; then
	echo "ERROR: This test must be run as root (e.g., in a Docker container)"
	exit 1
fi

# Detect OS family for package manager mocking
source /etc/os-release
OS_FAMILY=""
case "${ID}" in
	ubuntu|debian) OS_FAMILY="debian" ;;
	fedora|centos|almalinux|rocky) OS_FAMILY="rhel" ;;
	*) echo "Unsupported OS: ${ID}"; exit 1 ;;
esac

# Create mock commands in /sbin which is first in PATH after the script's
# PATH manipulation: export PATH="/sbin:/usr/sbin:${PATH}"
# This ensures mocks take precedence over any real binaries.
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

# Mock systemctl
create_mock "systemctl" '
case "$1" in
	is-active)
		if [[ "${2:-}" == "--quiet" ]]; then
			if [[ -f /tmp/awg-mock-started ]]; then
				exit 0
			fi
			exit 1
		fi
		exit 1
		;;
	start)
		touch /tmp/awg-mock-started
		exit 0
		;;
	enable|daemon-reload|disable|stop)
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
else
	echo "FAIL: Client config not found"
	FAILED=$((FAILED + 1))
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

echo ""
echo "=========================================="
if [[ ${FAILED} -eq 0 ]]; then
	echo "Integration test PASSED"
else
	echo "Integration test FAILED (${FAILED} failures)"
fi
echo "=========================================="

exit ${FAILED}
