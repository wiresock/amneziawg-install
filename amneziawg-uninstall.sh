#!/bin/bash

# AmneziaWG server uninstaller
# Standalone script to fully remove AmneziaWG and all its configuration files.
# Based on the uninstall logic from https://github.com/wiresock/amneziawg-install
#
# Usage:
#   sudo bash uninstall-amneziawg.sh
#
# Non-interactive mode (skip confirmation prompt):
#   AUTO_UNINSTALL=y sudo bash uninstall-amneziawg.sh

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"

# Ensure sbin directories are in PATH for modprobe, sysctl, systemctl, etc.
# Some minimal or non-login root shells may not include these by default.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	if [ -n "${PATH:-}" ]; then
		export PATH="/sbin:/usr/sbin:${PATH:-}"
	else
		export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	fi
fi

function isRoot() {
	if [[ "${EUID}" -ne 0 ]]; then
		echo "You need to run this script as root"
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
		echo "Looks like you aren't running this uninstaller on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux or Rocky Linux system"
		exit 1
	fi
}

function detectInterface() {
	# Detect the AmneziaWG interface name from the params file or by scanning config files
	SERVER_AWG_NIC=""

	if [[ -f "${AMNEZIAWG_DIR}/params" ]]; then
		# Try to extract SERVER_AWG_NIC from params file safely
		# We read only the specific variable to avoid sourcing untrusted content
		SERVER_AWG_NIC=$(grep -E "^SERVER_AWG_NIC=" "${AMNEZIAWG_DIR}/params" | head -1 | sed "s/^SERVER_AWG_NIC=//; s/^'//; s/'$//")
	fi

	if [[ -z "${SERVER_AWG_NIC}" ]]; then
		# Fallback: look for .conf files in the AmneziaWG directory
		# Exclude params and other non-interface files
		local CONF_FILE
		CONF_FILE=$(find "${AMNEZIAWG_DIR}" -maxdepth 1 -name '*.conf' -type f 2>/dev/null | head -1)
		if [[ -n "${CONF_FILE}" ]]; then
			SERVER_AWG_NIC=$(basename "${CONF_FILE}" .conf)
		fi
	fi

	if [[ -z "${SERVER_AWG_NIC}" ]]; then
		# Last resort: use default interface name
		SERVER_AWG_NIC="awg0"
	fi

	# Validate interface name to prevent injection
	if ! [[ ${SERVER_AWG_NIC} =~ ^[a-zA-Z0-9_.-]+$ ]] || [[ ${#SERVER_AWG_NIC} -ge 16 ]]; then
		echo -e "${RED}ERROR: Detected interface name '${SERVER_AWG_NIC}' contains invalid characters or is too long.${NC}"
		echo -e "${ORANGE}Please specify the interface manually by setting SERVER_AWG_NIC environment variable.${NC}"
		exit 1
	fi
}

function uninstallAmneziaWG() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the ${AMNEZIAWG_DIR} directory if you want to keep your configuration files.\n${NC}"

	if [[ "${AUTO_UNINSTALL,,}" == "y" ]]; then
		echo -e "${GREEN}AUTO_UNINSTALL: Proceeding with uninstallation automatically.${NC}"
	else
		read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
		REMOVE=${REMOVE:-n}
		if [[ $REMOVE != [yY] ]]; then
			echo ""
			echo "Removal aborted!"
			exit 0
		fi
	fi

	checkOS
	detectInterface

	echo -e "${GREEN}Stopping and disabling AmneziaWG service...${NC}"

	# Stop and disable the service (ignore errors if not running/enabled)
	systemctl stop "awg-quick@${SERVER_AWG_NIC}" 2>/dev/null || true
	systemctl disable "awg-quick@${SERVER_AWG_NIC}" 2>/dev/null || true

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

	echo -e "${GREEN}Removing module auto-load entry...${NC}"

	# Remove module auto-load entry
	rm -f /etc/modules-load.d/amneziawg.conf

	echo -e "${GREEN}Removing routing configuration...${NC}"

	# Disable routing
	# Only remove our conf file; do NOT force ip_forward=0 at runtime because
	# other services (Docker, libvirt, other VPNs) may depend on forwarding.
	# The setting will revert to the system default on next reboot.
	rm -f /etc/sysctl.d/awg.conf

	echo -e "${GREEN}Removing AmneziaWG configuration files...${NC}"

	# Remove config files
	rm -rf "${AMNEZIAWG_DIR:?}"

	echo -e "${GREEN}Removing AmneziaWG packages...${NC}"

	if [[ ${OS} == 'ubuntu' ]]; then
		apt remove -y amneziawg amneziawg-tools 2>/dev/null || true
		add-apt-repository -ry ppa:amnezia/ppa 2>/dev/null || true
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
		apt-get remove -y amneziawg amneziawg-tools 2>/dev/null || true
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
		apt update 2>/dev/null || true
	elif [[ ${OS} == 'fedora' ]]; then
		dnf remove -y amneziawg-dkms amneziawg-tools 2>/dev/null || true
		dnf copr disable -y amneziavpn/amneziawg 2>/dev/null || true
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		dnf remove -y amneziawg-dkms amneziawg-tools 2>/dev/null || true
		dnf copr disable -y amneziavpn/amneziawg 2>/dev/null || true
	fi

	echo -e "${GREEN}Verifying uninstallation...${NC}"

	# Check if AmneziaWG is running
	systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}" 2>/dev/null
	AWG_RUNNING=$?

	if [[ ${AWG_RUNNING} -eq 0 ]]; then
		echo -e "${RED}AmneziaWG failed to uninstall properly.${NC}"
		echo -e "${ORANGE}The service awg-quick@${SERVER_AWG_NIC} is still active.${NC}"
		echo -e "${ORANGE}Try stopping it manually: systemctl stop awg-quick@${SERVER_AWG_NIC}${NC}"
		exit 1
	else
		echo -e "${GREEN}AmneziaWG uninstalled successfully.${NC}"
		exit 0
	fi
}

# Main entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	isRoot
	uninstallAmneziaWG
fi
