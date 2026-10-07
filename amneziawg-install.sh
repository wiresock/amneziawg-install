#!/bin/bash

# AmneziaWG server installer
# https://github.com/wiresock/amneziawg-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"
WEB_PANEL_CONFIG_DIR="${AMNEZIAWG_DIR}/clients"
WEB_PANEL_ENV_FILE="/etc/amneziawg-web/env.conf"
WEB_PANEL_SYSTEMD_UNIT="/etc/systemd/system/amneziawg-web.service"
WEB_PANEL_DATA_DIR="/var/lib/amneziawg-web"
# The web panel's lifecycle-script copy when its configuration names none.
WEB_PANEL_LIFECYCLE_SCRIPT="/usr/local/bin/amneziawg-install.sh"

# Protocol state is deliberately independent from package/tool versions. A
# missing value in an older params file always means AWG 2.0; AWG 3.0 and
# AWG 3.1 are only entered through the explicit, capability-gated migration
# path. Existing AWG 3.0 installations stay on 3.0 until the operator opts in
# to 3.1; newly installed awg tools never imply a protocol upgrade.
AWG_PROTOCOL_VERSION_2="2"
AWG_PROTOCOL_VERSION_3="3"
AWG_PROTOCOL_VERSION_31="3.1"
AWG3_DEFAULT_CONTENT_PADDING_ADDITION="10-100"
AWG3_DEFAULT_REKEY_AFTER_TIME="100-120"
AWG3_DEFAULT_REKEY_TIMEOUT="3-7"
AWG3_DEFAULT_REJECT_AFTER_TIME="150-180"
AWG3_DEFAULT_KEEPALIVE_TIMEOUT="5-15"
# AWG 3.1: RandomTrailers must match on both ends and is the reason to opt in.
# DisableCookies is sender-only and turns off Cookie Reply (anti-DoS), so it
# stays off unless the operator enables it explicitly.
AWG31_DEFAULT_RANDOM_TRAILERS="on"
AWG31_DEFAULT_DISABLE_COOKIES="off"
# Interface keys rewritten/verified as protocol-specific fields. Keep in sync
# with renderAwgProtocolFields and the config match helpers.
AWG_PROTOCOL_CONFIG_KEYS="HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|RandomTrailers|DisableCookies"

# AWG backend (datapath) state: the AmneziaWG kernel module ("kernel") or the
# userspace WireSock BoringTun daemon ("boringtun", experimental). Params
# written before backends existed have no AWG_BACKEND, and that always means the
# kernel module. Every other value fails closed, and the runtime dispatchers
# refuse to operate on an unset or unknown backend.
#
# The backend of an installation is chosen once, by a fresh install, and params
# are authoritative afterwards. The assignment below is the default until params
# are loaded; validateParamsFile then re-derives the backend from params alone.
# It also discards an AWG_BACKEND inherited from the caller's environment, so
# the environment never changes the backend of an existing installation. Only a
# fresh install reads the caller's request, from the copy taken here
# (selectFreshInstallBackend).
AWG_BACKEND_KERNEL="kernel"
AWG_BACKEND_BORINGTUN="boringtun"
_AWG_BACKEND_REQUESTED="${AWG_BACKEND-}"
AWG_BACKEND="${AWG_BACKEND_KERNEL}"

# BoringTun protocol imitation, a BoringTun-only server setting persisted in
# params as AWG_BORINGTUN_IMITATE_PROTOCOL (none, dns, quic, sip, stun or auto)
# and AWG_BORINGTUN_IMITATE_DOMAIN (an optional hostname for dns, quic and sip).
# Like the backend, params are authoritative: validateParamsFile discards both
# names before sourcing params, and only a fresh install reads the caller's
# request, from the copies taken here (selectFreshInstallImitation).
AWG_BT_IMITATE_NONE="none"
_AWG_BT_IMITATE_PROTOCOL_REQUESTED="${AWG_BORINGTUN_IMITATE_PROTOCOL-}"
_AWG_BT_IMITATE_DOMAIN_REQUESTED="${AWG_BORINGTUN_IMITATE_DOMAIN-}"
AWG_BORINGTUN_IMITATE_PROTOCOL="${AWG_BT_IMITATE_NONE}"
AWG_BORINGTUN_IMITATE_DOMAIN=""

# Capability marker. The web panel runs its own copy of this script for client
# lifecycle operations. A fresh BoringTun install requires that copy to carry
# this exact line, read as data (webPanelLifecycleScriptSupportsBoringtun),
# because an older copy would treat a BoringTun host as a kernel host. Later
# installer versions must keep the line unchanged.
AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST="boringtun-host-v1"
# Web mutations may run with read-only /usr. This contract includes reuse of
# identical trusted generated helpers before attempting any temporary write.
# Read as data by the companion web upgrader.
# shellcheck disable=SC2034
AWG_INSTALLER_CAPABILITY_WEB_BORINGTUN="web-boringtun-v1"
# --set-boringtun-imitation accepts auto, and --backend-status reports
# imitation_auto_support. The web panel's privileged helper reads this line as
# data before it passes auto to this script, because an earlier copy of it
# refuses the value. Later installer versions must keep the line unchanged.
# shellcheck disable=SC2034
AWG_INSTALLER_CAPABILITY_BORINGTUN_IMITATION_AUTO="boringtun-imitation-auto-v1"

# The immutable public BoringTun release that fresh BoringTun installs download.
# These values are the installer's only trust anchor for the binary: they are
# embedded here, never read from the network, the environment or a file.
# They name an already published release and are deliberately independent of
# packaging/boringtun/pin.env (the source the artifact pipeline builds) and
# packaging/boringtun/release.env (the release being prepared or published):
# a new release is built, approved and published first, and this installer
# adopts it only in a later, separate change of these values, so until then
# they name an earlier release. tests/test-boringtun-host.sh checks that they
# are internally consistent, and tests/test-boringtun-public-release.sh that
# the release is public with exactly these bytes.
AWG_BT_RELEASE_TAG="boringtun-cli-0.7.1-gb94943906b11-b1"
AWG_BT_RELEASE_BASE_URL="https://github.com/wiresock/amneziawg-install/releases/download/boringtun-cli-0.7.1-gb94943906b11-b1"
AWG_BT_RELEASE_VERSION="0.7.1"
AWG_BT_RELEASE_SOURCE_REPOSITORY="https://github.com/Wiresock-Foundation/wiresock-boringtun"
AWG_BT_RELEASE_SOURCE_COMMIT="b94943906b11641e274b3c950cc905aaf1631c59"
# The release's build number (the tag's -b<build>). It is part of the store
# identity of builds from 2 on (_awgBtReleaseStoreId).
AWG_BT_RELEASE_BUILD="1"
AWG_BT_RELEASE_ASSET_X86_64="boringtun-cli-0.7.1-gb94943906b11-linux-x86_64-musl.tar.gz"
AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64="c6a39a50ccc89f6ac4107d3fe0d530a6f83badc11b405617195e65092e96e7fb"
AWG_BT_RELEASE_BINARY_SHA256_X86_64="1210a3c6780948ea07f301c4fa022c0b4ab634da71db0053f65757c8683470d5"
AWG_BT_RELEASE_ASSET_AARCH64="boringtun-cli-0.7.1-gb94943906b11-linux-aarch64-musl.tar.gz"
AWG_BT_RELEASE_ARCHIVE_SHA256_AARCH64="cf65174fcb25095a2637544fda860d5d033cd4d271ee7ac40e8f457ece75ecce"
AWG_BT_RELEASE_BINARY_SHA256_AARCH64="c6752410b3994007a9ace5f2d93c30c009b2d7478ebed27b01aacc6168a08629"

# Where the BoringTun runtime lives. The generated helpers embed these values
# when they are written, so a helper never reads a path from its environment.
# Tests may reassign them after sourcing, before generating helpers.
AWG_BT_STORE_DIR="/usr/local/lib/amneziawg-install/boringtun"
AWG_BT_LIBEXEC_DIR="/usr/local/libexec/amneziawg-install"
AWG_BT_RUN_DIR="/run/amneziawg-install"
AWG_BT_CONFIG_DIR="/etc/amnezia/amneziawg"
AWG_BT_SYSTEMD_DIR="/etc/systemd/system"
AWG_BT_UNIT_DIRS="/usr/lib/systemd/system /lib/systemd/system"
AWG_BT_SYSTEMD_RUNTIME_DIR="/run/systemd/system"
AWG_BT_WG_SOCKET_DIR="/var/run/wireguard"
AWG_BT_AWG_SOCKET_DIR="/var/run/amneziawg"
AWG_BT_SYS_DIR="/sys"
AWG_BT_PROC_DIR="/proc"
AWG_BT_TUN_DEVICE="/dev/net/tun"
AWG_BT_TRUST_ANCHOR="/"
AWG_BT_TRUSTED_UID=0
AWG_BT_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
AWG_BT_READY_TIMEOUT=10
# How long the binary may take to say whether it runs an imitation mode
# (_awgBtBinaryImitationSupport).
AWG_BT_PROBE_TIMEOUT=10
AWG_BT_HOST_ARCH=""
# Where the SaveConfig-free copy for an emergency awg-quick down goes when the
# runtime directory cannot allocate a new one.
AWG_BT_TMP_DIR="/tmp"
# The installer's load override for an AmneziaWG kernel module that is
# installed on a BoringTun host (_awgBtKernelModuleBlocked).
AWG_BT_MODPROBE_OVERRIDE="/etc/modprobe.d/amneziawg-install-boringtun.conf"
# The standalone amneziawg-proxy, which cannot run in front of BoringTun.
AWG_PROXY_INSTALL_PATHS="/etc/systemd/system/amneziawg-proxy.service /usr/local/bin/amneziawg-proxy /etc/amneziawg-proxy/proxy.toml"

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

# Work around broken IPv6 on cloud VPS providers.  Some providers resolve
# Launchpad / Ubuntu keyserver / COPR hostnames to both A and AAAA records,
# but outbound IPv6 connectivity is broken, causing apt, dnf,
# add-apt-repository, and COPR API calls to hang.
#
# Two complementary mitigations are applied:
#
#  1. APT ForceIPv4 (Debian/Ubuntu only) — a config file in apt.conf.d/
#     forces all apt-based tools (including add-apt-repository, which uses
#     python-apt internally) to use IPv4.  This file is only written when
#     apt-get or apt is present to avoid creating /etc/apt on RPM distros.
#
#  2. gai.conf IPv4-preference rule (all distros) — an IPv4-preference rule
#     is injected into /etc/gai.conf so that glibc's getaddrinfo (and thus
#     Python's socket.getaddrinfo and libcurl used by dnf) *prefers* IPv4.
#     On Ubuntu 24.04 this also fixes a Python traceback from httplib2
#     used by add-apt-repository, which does NOT honour Acquire::ForceIPv4.
APT_FORCE_IPV4_CONF="/etc/apt/apt.conf.d/99amneziawg-force-ipv4"
APT_FORCE_IPV4_SENTINEL="# Managed by amneziawg-install - safe to remove"
GAI_CONF="/etc/gai.conf"
GAI_CONF_SENTINEL="# Added by amneziawg-install - safe to remove"
GAI_CONF_IPV4_RULE="precedence ::ffff:0:0/96 100"
GAI_CONF_IPV4_RULE_REGEX='^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100([[:space:]]*(#.*)?)?$'
AMNEZIA_PPA_URI="https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu"
AMNEZIA_PPA_SOURCES_DIR="/etc/apt/sources.list.d"
# Files the uninstall removes; tests point them below a test root.
AWG_SYSTEMD_UNIT_DIR="/etc/systemd/system"
AWG_MODULES_LOAD_FILE="/etc/modules-load.d/amneziawg.conf"
AWG_SYSCTL_FILE="/etc/sysctl.d/awg.conf"
AWG_APT_KEYRING_FILE="/etc/apt/keyrings/amneziawg.gpg"
AMNEZIA_PPA_SOURCE_CREATED=0
# Suite and architecture chosen by the last successful configureUbuntuAmneziaPpa.
AMNEZIA_PPA_SELECTED_SUITE=""
AMNEZIA_PPA_ARCHITECTURE=""
_APT_IPV4_PREV_TRAP_EXIT=""
_APT_IPV4_PREV_TRAP_INT=""
_APT_IPV4_PREV_TRAP_TERM=""
# Return success when gai.conf has an active (uncommented) IPv4 precedence
# rule for ::ffff:0:0/96 with value 100; commented defaults must not match.
gai_conf_has_active_ipv4_rule() {
	grep -Eq "${GAI_CONF_IPV4_RULE_REGEX}" "${GAI_CONF}" 2>/dev/null
}
enable_apt_ipv4() {
	# Only write the APT ForceIPv4 config on distros that actually use APT,
	# to avoid creating /etc/apt on RPM-based systems.
	if command -v apt-get >/dev/null 2>&1 || command -v apt >/dev/null 2>&1 || [[ -d /etc/apt ]]; then
		mkdir -p /etc/apt/apt.conf.d
		printf '%s\n%s\n' "${APT_FORCE_IPV4_SENTINEL}" 'Acquire::ForceIPv4 "true";' \
			> "${APT_FORCE_IPV4_CONF}"
	fi

	# Prefer IPv4 in the system resolver so all glibc consumers (Python,
	# libcurl/dnf, etc.) connect over IPv4.
	if ! gai_conf_has_active_ipv4_rule; then
		local _gai_existed=0
		[[ -f "${GAI_CONF}" ]] && _gai_existed=1
		printf '\n%s\n%s\n' "${GAI_CONF_SENTINEL}" "${GAI_CONF_IPV4_RULE}" \
			>> "${GAI_CONF}"
		# Only set permissions when we created the file; leave existing
		# ownership/mode untouched so the cleanup path can preserve them.
		if [[ "${_gai_existed}" -eq 0 ]]; then
			chmod 0644 "${GAI_CONF}"
		fi
	fi

	# Save existing trap commands so we can chain them (not just restore).
	# trap -p output is eval-safe by design (bash always emits: trap -- 'body' SIG).
	_APT_IPV4_PREV_TRAP_EXIT="$(trap -p EXIT || true)"
	_APT_IPV4_PREV_TRAP_INT="$(trap -p INT || true)"
	_APT_IPV4_PREV_TRAP_TERM="$(trap -p TERM || true)"
	# Install traps that clean up *and* invoke any prior handler, so
	# pre-existing cleanup logic still runs even if the script exits
	# while IPv4 forcing is active.
	trap '_cleanup_apt_ipv4_and_chain EXIT' EXIT
	trap '_cleanup_apt_ipv4_and_chain INT'  INT
	trap '_cleanup_apt_ipv4_and_chain TERM' TERM
}
# Internal: remove the APT ForceIPv4 config and revert gai.conf changes.
_remove_ipv4_overrides() {
	# Only remove the file if it carries our sentinel.
	if [[ -f "${APT_FORCE_IPV4_CONF}" ]] && grep -qFm1 "${APT_FORCE_IPV4_SENTINEL}" "${APT_FORCE_IPV4_CONF}"; then
		rm -f "${APT_FORCE_IPV4_CONF}"
	fi
	# Remove gai.conf lines we added (if any).  Only act when our sentinel
	# is present so pre-existing admin rules are never touched.  This must
	# be idempotent so interrupted previous runs are also cleaned up.
	if [[ -f "${GAI_CONF}" ]] && grep -qF "${GAI_CONF_SENTINEL}" "${GAI_CONF}"; then
		awk -v sent="${GAI_CONF_SENTINEL}" -v regex="${GAI_CONF_IPV4_RULE_REGEX}" '
			# State machine:
			# 1) skip our sentinel line
			# 2) skip the immediately following active IPv4 rule if present
			# 3) print all other lines unchanged
			$0 == sent { prev_sent=1; next }
			prev_sent == 1 && $0 ~ regex { prev_sent=0; next }
			{ prev_sent=0; print }
		' "${GAI_CONF}" > "${GAI_CONF}.tmp"
		if ! chmod --reference="${GAI_CONF}" "${GAI_CONF}.tmp" || ! chown --reference="${GAI_CONF}" "${GAI_CONF}.tmp"; then
			rm -f "${GAI_CONF}.tmp"
			return 1
		fi
		mv "${GAI_CONF}.tmp" "${GAI_CONF}"
	fi
}
# Internal: remove the config file, restore the previous trap for the
# given signal, then immediately invoke the restored handler so it runs
# during the same exit / signal delivery.
_cleanup_apt_ipv4_and_chain() {
	# Preserve the original exit status so chained handlers see the real value.
	local _saved_status=$?
	local sig="$1"
	_remove_ipv4_overrides
	# Restore + chain: re-install the previous trap (if any), then
	# re-deliver the signal / exit so bash invokes the restored handler.
	# This avoids parsing trap -p output entirely (no sed/eval of bodies).
	local prev_var="_APT_IPV4_PREV_TRAP_${sig}"
	local prev_trap="${!prev_var}"
	if [[ -n "${prev_trap}" ]]; then
		# Re-install the previous trap (e.g. trap -- 'handler' EXIT).
		eval "${prev_trap}"
		# Re-deliver the signal so bash invokes the just-restored handler.
		if [[ "${sig}" == "EXIT" ]]; then
			# For EXIT: exiting re-fires the EXIT trap with the original status.
			exit "${_saved_status}"
		else
			# For INT/TERM: re-raise the signal to invoke the restored handler.
			kill -s "${sig}" "$$" 2>/dev/null || {
				case "${sig}" in
					INT)  exit 130 ;;  # 128 + SIGINT(2)
					TERM) exit 143 ;;  # 128 + SIGTERM(15)
				esac
			}
		fi
	else
		trap - "${sig}"
		if [[ "${sig}" == "EXIT" ]]; then
			# Preserve the original exit status when no prior handler exists.
			exit "${_saved_status}"
		elif [[ "${sig}" == INT || "${sig}" == TERM ]]; then
			# Re-raise the signal so default termination semantics are preserved.
			kill -s "${sig}" "$$" 2>/dev/null || {
				case "${sig}" in
					INT)  exit 130 ;;  # 128 + SIGINT(2)
					TERM) exit 143 ;;  # 128 + SIGTERM(15)
				esac
			}
		fi
	fi
}
disable_apt_ipv4() {
	_remove_ipv4_overrides
	# Restore any previously installed traps.
	if [[ -n "${_APT_IPV4_PREV_TRAP_EXIT}" ]]; then
		eval "${_APT_IPV4_PREV_TRAP_EXIT}"
	else
		trap - EXIT
	fi
	if [[ -n "${_APT_IPV4_PREV_TRAP_INT}" ]]; then
		eval "${_APT_IPV4_PREV_TRAP_INT}"
	else
		trap - INT
	fi
	if [[ -n "${_APT_IPV4_PREV_TRAP_TERM}" ]]; then
		eval "${_APT_IPV4_PREV_TRAP_TERM}"
	else
		trap - TERM
	fi
}

# Return the Ubuntu archive codename that add-apt-repository should use.
# Linux Mint exposes its Ubuntu base in UBUNTU_CODENAME.
function getUbuntuPpaCodename() {
	local CODENAME
	if [[ "${ID:-}" == "linuxmint" ]]; then
		CODENAME="${UBUNTU_CODENAME:-}"
	else
		CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
	fi

	if [[ -z "${CODENAME}" ]] || ! [[ "${CODENAME}" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
		echo -e "${RED}ERROR: Unable to determine a valid Ubuntu codename for the Amnezia PPA.${NC}" >&2
		return 1
	fi

	printf '%s\n' "${CODENAME}"
}

# Reviewed cross-release mappings. Unknown releases must never be mapped
# automatically; every mapping requires package and DKMS compatibility testing.
function getAmneziaPpaFallbackSuite() {
	case "$1" in
		resolute) printf '%s\n' "noble" ;;
		*) return 1 ;;
	esac
}

# Noble currently publishes amneziawg-tools for these architectures. Although
# the Release file advertises i386, the required tools package is absent there.
function isAmneziaPpaFallbackArchitectureSupported() {
	case "$1" in
		amd64 | arm64 | armhf | ppc64el | riscv64 | s390x) return 0 ;;
		*) return 1 ;;
	esac
}

function isValidDpkgArchitecture() {
	[[ "${1:-}" =~ ^[a-z0-9][a-z0-9-]*$ ]]
}

# The native package architecture, as dpkg reports it, is the only value the
# Amnezia PPA source is pinned to. CPU variants such as amd64v3 are an APT
# index choice rather than an architecture, and uname -m names the kernel's
# machine type rather than a Debian architecture.
function getNativeDpkgArchitecture() {
	local ARCHITECTURE
	ARCHITECTURE=$(dpkg --print-architecture 2>/dev/null) || return 1
	isValidDpkgArchitecture "${ARCHITECTURE}" || return 1
	printf '%s\n' "${ARCHITECTURE}"
}

# Print the direct HTTP status for a PPA metadata URL without following
# redirects. A redirect is ambiguous and must remain a 3xx so the caller fails
# closed. Network, TLS, timeout, and tool failures return 2 without inventing a
# status. curl is installed by the normal Ubuntu flow; wget/python3 allow
# recovery from an older partial install before the first apt-get update.
function getAmneziaPpaHttpStatus() {
	local URL="$1"
	local STATUS=""
	local OUTPUT=""

	if command -v curl &>/dev/null; then
		STATUS=$(curl --disable -4 --silent --show-error \
			--connect-timeout 10 --max-time 30 \
			--output /dev/null --write-out '%{http_code}' "${URL}") || return 2
	elif command -v wget &>/dev/null; then
		OUTPUT=$(wget -4 --server-response --spider --max-redirect=0 \
			--timeout=30 --tries=1 "${URL}" 2>&1) || true
		STATUS=$(printf '%s\n' "${OUTPUT}" | awk '
			/^[[:space:]]*HTTP\/[0-9.]+[[:space:]]+[0-9][0-9][0-9]/ { status=$2 }
			END { print status }
		')
	elif command -v python3 &>/dev/null; then
		STATUS=$(python3 - "${URL}" <<'PY'
import sys
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None

request = urllib.request.Request(sys.argv[1], method="GET")
opener = urllib.request.build_opener(NoRedirect())
try:
    with opener.open(request, timeout=30) as response:
        print(response.status)
except urllib.error.HTTPError as error:
    print(error.code)
except (OSError, urllib.error.URLError):
    raise SystemExit(2)
PY
		) || return 2
	else
		return 2
	fi

	if ! [[ "${STATUS}" =~ ^[0-9]{3}$ ]]; then
		return 2
	fi
	printf '%s\n' "${STATUS}"
}

# Tri-state PPA metadata probe:
#   0: suite is available (signed metadata resource exists)
#   1: suite is definitely unavailable (both resources are 404/410)
#   2: status is unknown (network/server/auth/other failure)
function probeAmneziaPpaSuite() {
	local SUITE="$1"
	local RESOURCE
	local STATUS

	for RESOURCE in InRelease Release; do
		STATUS=$(getAmneziaPpaHttpStatus \
			"${AMNEZIA_PPA_URI}/dists/${SUITE}/${RESOURCE}") || return 2
		case "${STATUS}" in
			200) return 0 ;;
			404 | 410) ;;
			*) return 2 ;;
		esac
	done

	return 1
}

# Select the native suite whenever it exists. A fallback is considered only
# after definite native absence, never after a transient or ambiguous failure.
function selectAmneziaPpaSuite() {
	local NATIVE_SUITE="$1"
	local ARCHITECTURE="$2"
	local FALLBACK_SUITE
	local PROBE_RC

	if probeAmneziaPpaSuite "${NATIVE_SUITE}"; then
		PROBE_RC=0
	else
		PROBE_RC=$?
	fi
	case "${PROBE_RC}" in
		0)
			printf '%s\n' "${NATIVE_SUITE}"
			return 0
			;;
		2)
			echo -e "${RED}ERROR: Could not determine whether the Amnezia PPA supports Ubuntu '${NATIVE_SUITE}'.${NC}" >&2
			echo -e "${ORANGE}A network, TLS, rate-limit, or server error occurred. No cross-release fallback was applied.${NC}" >&2
			return 1
			;;
	esac

	FALLBACK_SUITE=$(getAmneziaPpaFallbackSuite "${NATIVE_SUITE}") || {
		echo -e "${RED}ERROR: The Amnezia PPA does not publish packages for Ubuntu '${NATIVE_SUITE}', and no verified fallback is configured.${NC}" >&2
		return 1
	}

	if ! isAmneziaPpaFallbackArchitectureSupported "${ARCHITECTURE}"; then
		echo -e "${RED}ERROR: The verified ${NATIVE_SUITE} -> ${FALLBACK_SUITE} Amnezia PPA fallback is not available for architecture '${ARCHITECTURE}'.${NC}" >&2
		return 1
	fi

	if probeAmneziaPpaSuite "${FALLBACK_SUITE}"; then
		PROBE_RC=0
	else
		PROBE_RC=$?
	fi
	case "${PROBE_RC}" in
		0)
			echo -e "${ORANGE}WARNING: The Amnezia PPA has no native '${NATIVE_SUITE}' repository. Using signed '${FALLBACK_SUITE}' PPA packages from Ubuntu 24.04 for this reviewed compatibility fallback.${NC}" >&2
			printf '%s\n' "${FALLBACK_SUITE}"
			return 0
			;;
		1)
			echo -e "${RED}ERROR: Neither the native '${NATIVE_SUITE}' suite nor its reviewed '${FALLBACK_SUITE}' fallback is available in the Amnezia PPA.${NC}" >&2
			;;
		2)
			echo -e "${RED}ERROR: The native '${NATIVE_SUITE}' suite is unavailable, but the '${FALLBACK_SUITE}' fallback could not be verified because of a network or server error.${NC}" >&2
			echo -e "${ORANGE}No cross-release fallback was applied.${NC}" >&2
			;;
	esac
	return 1
}

# Transform one legacy .list file. Only active deb/deb-src lines whose URI
# token is exactly the Amnezia PPA are considered. Exit codes: 0 matched,
# 3 no match, 4 malformed matching entry.
function _transformAmneziaPpaLegacyFile() {
	local FILE="$1"
	local MODE="$2"
	local SUITE="${3:-}"
	local ARCHITECTURE="${4:-}"

	awk -v mode="${MODE}" -v replacement="${SUITE}" \
		-v target="${AMNEZIA_PPA_URI}" -v host_arch="${ARCHITECTURE}" '
	function is_target_uri(uri, normalized, http_target) {
		normalized=uri
		sub(/\/+$/, "", normalized)
		http_target=target
		sub(/^https:/, "http:", http_target)
		return normalized == target || normalized == http_target
	}
	function contains_target_literal(value, http_target) {
		http_target=target
		sub(/^https:/, "http:", http_target)
		return index(value, target) > 0 || index(value, http_target) > 0
	}
	function dequote_token(value, first, last) {
		first=substr(value, 1, 1)
		last=substr(value, length(value), 1)
		if (length(value) >= 2 && first == "\"" && last == "\"") {
			return substr(value, 2, length(value) - 2)
		}
		return value
	}
	function has_unsupported_quote(value, first, last) {
		first=substr(value, 1, 1)
		last=substr(value, length(value), 1)
		return (first == "\"" && last != "\"") ||
			first == "\047" || last == "\047"
	}
	function hex_value(character) {
		return index("0123456789abcdef", tolower(character)) - 1
	}
	function percent_decode(value, result, i, character, high, low) {
		result=""
		for (i=1; i<=length(value); i++) {
			character=substr(value, i, 1)
			if (character == "%" && i + 2 <= length(value)) {
				high=hex_value(substr(value, i + 1, 1))
				low=hex_value(substr(value, i + 2, 1))
				if (high >= 0 && low >= 0) {
					result=result sprintf("%c", high * 16 + low)
					i += 2
					continue
				}
			}
			result=result character
		}
		return result
	}
	function apt_comment_position(value, i, character, in_options) {
		in_options=0
		for (i=1; i<=length(value); i++) {
			character=substr(value, i, 1)
			if (character == "[") {
				in_options=1
			} else if (character == "]") {
				in_options=0
			} else if (character == "#" && !in_options) {
				return i
			}
		}
		return 0
	}
	function emit_line(value) {
		if (mode != "count") {
			print value
		}
	}
	function csv_contains(value, wanted, count, values, i) {
		count=split(value, values, ",")
		for (i=1; i<=count; i++) {
			if (values[i] == wanted) {
				for (i=1; i<=count; i++) delete values[i]
				return 1
			}
		}
		for (i=1; i<=count; i++) delete values[i]
		return 0
	}
	function options_are_safe(value, count, options, i, option, option_value, arch_value, arch_options) {
		# APT applies a quote-word lexer to option tokens. Reject quoted option
		# text instead of attempting a partial reimplementation that could miss
		# a quoted signature-bypass key.
		if (index(value, "\"") > 0 || index(value, "\047") > 0 ||
			index(value, "\\") > 0 || index(value, "%") > 0) {
			return 0
		}
		arch_options=0
		count=split(value, options, /[[:space:]]+/)
		for (i=1; i<=count; i++) {
			option=tolower(options[i])
			if (option ~ /^(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)$/) {
				for (i=1; i<=count; i++) delete options[i]
				return 0
			}
			if (option ~ /^(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)=/) {
				option_value=substr(option, index(option, "=") + 1)
				if (option_value !~ /^(0|no|false|off|disable|without)$/) {
					for (i=1; i<=count; i++) delete options[i]
					return 0
				}
			}
			if (option ~ /^arch=/) {
				arch_value=substr(option, 6)
				# A second arch= option leaves which list APT applies unclear,
				# so it cannot be normalized to the native architecture safely.
				if (++arch_options > 1 || host_arch == "" ||
					!csv_contains(arch_value, host_arch)) {
					for (i=1; i<=count; i++) delete options[i]
					return 0
				}
			}
			if (option ~ /^arch[-+]=/) {
				# Avoid guessing how additive/subtractive filters interact with
				# the host architecture in an administrator-authored entry.
				for (i=1; i<=count; i++) delete options[i]
				return 0
			}
		}
		for (i=1; i<=count; i++) delete options[i]
		return 1
	}
	# Return the option text with its single arch= option set to exactly the
	# native architecture, appending one when absent. options_are_safe has
	# already rejected arch+=, arch-= and repeated arch= options.
	function native_arch_options(value, lowered, start, trailing) {
		lowered=tolower(value)
		if (match(lowered, /(^|[[:space:]])arch=[^[:space:]]*/)) {
			start=RSTART
			if (substr(lowered, start, 1) ~ /[[:space:]]/) {
				start++
			}
			return substr(value, 1, start - 1) "arch=" host_arch substr(value, RSTART + RLENGTH)
		}
		if (value !~ /[^[:space:]]/) {
			return "arch=" host_arch
		}
		trailing=value
		sub(/^.*[^[:space:]]/, "", trailing)
		sub(/[[:space:]]+$/, "", value)
		return value " arch=" host_arch trailing
	}
	BEGIN {
		found=0
		binary_found=0
		source_found=0
		malformed=0
		if (mode == "set" && host_arch !~ /^[a-z0-9][a-z0-9-]*$/) {
			invalid_host_arch=1
		}
	}
	{
		line=$0
		comment_position=apt_comment_position(line)
		if (comment_position > 0) {
			length_line=comment_position - 1
		} else {
			length_line=length(line)
		}
		position=1
		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}

		type_start=position
		while (position <= length_line && substr(line, position, 1) !~ /[[:space:]]/) {
			position++
		}
		entry_type=substr(line, type_start, position - type_start)
		if (entry_type != "deb" && entry_type != "deb-src") {
			emit_line(line)
			next
		}

		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}
		options=""
		options_start=0
		if (substr(line, position, 1) == "[") {
			options_start=position + 1
			close_offset=index(substr(line, position), "]")
			if (close_offset == 0) {
				if (contains_target_literal(substr(line, 1, length_line))) {
					malformed=1
				}
				emit_line(line)
				next
			}
			options=substr(line, position + 1, close_offset - 2)
			position += close_offset
			while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
				position++
			}
		}

		uri_start=position
		while (position <= length_line && substr(line, position, 1) !~ /[[:space:]]/) {
			position++
		}
		raw_uri=substr(line, uri_start, position - uri_start)
		decoded_uri_token=percent_decode(raw_uri)
		uri=dequote_token(decoded_uri_token)
		if (!is_target_uri(uri)) {
			if (has_unsupported_quote(raw_uri) && contains_target_literal(decoded_uri_token)) {
				malformed=1
			}
			emit_line(line)
			next
		}

		found++
		if (mode == "remove") {
			next
		}
		if (!options_are_safe(options) || invalid_host_arch) {
			malformed=1
			emit_line(line)
			next
		}

		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}
		suite_start=position
		while (position <= length_line && substr(line, position, 1) !~ /[[:space:]]/) {
			position++
		}
		if (suite_start > length_line) {
			malformed=1
			emit_line(line)
			next
		}
		suite_end=position - 1
		suite_value=substr(line, suite_start, suite_end - suite_start + 1)
		if (suite_value !~ /^[a-z0-9][a-z0-9-]*$/) {
			malformed=1
			emit_line(line)
			next
		}

		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}
		component_start=position
		while (position <= length_line && substr(line, position, 1) !~ /[[:space:]]/) {
			position++
		}
		component=substr(line, component_start, position - component_start)
		if (component != "main") {
			malformed=1
			emit_line(line)
			next
		}
		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}
		if (position <= length_line && substr(line, position, 1) != "#") {
			malformed=1
			emit_line(line)
			next
		}

		if (entry_type == "deb") {
			binary_found++
		} else {
			source_found++
		}

		if (mode == "set") {
			# Rewrite the suite first: the options precede it, so their
			# positions are still valid afterwards.
			if (suite_value != replacement) {
				line=substr(line, 1, suite_start - 1) replacement substr(line, suite_end + 1)
			}
			if (options_start > 0) {
				line=substr(line, 1, options_start - 1) native_arch_options(options) \
					substr(line, options_start + length(options))
			} else {
				line=substr(line, 1, uri_start - 1) "[arch=" host_arch "] " substr(line, uri_start)
			}
		}
		emit_line(line)
	}
	END {
		if (mode == "count") {
			print found, binary_found, source_found
		}
		if (malformed) {
			exit 4
		}
		if (!found) {
			exit 3
		}
		if (mode != "remove" && !binary_found) {
			exit 5
		}
	}
	' "${FILE}"
}

# Transform one DEB822 .sources file stanza-by-stanza. A matching stanza must
# contain the Amnezia PPA as its sole URI; mixed-URI stanzas are rejected so an
# unrelated repository can never inherit the fallback suite.
function _transformAmneziaPpaDeb822File() {
	local FILE="$1"
	local MODE="$2"
	local SUITE="${3:-}"
	local ARCHITECTURE="${4:-}"

	awk -v mode="${MODE}" -v replacement="${SUITE}" \
		-v target="${AMNEZIA_PPA_URI}" -v host_arch="${ARCHITECTURE}" '
	function trim(value) {
		gsub(/^[[:space:]]+/, "", value)
		gsub(/[[:space:]]+$/, "", value)
		return value
	}
	function is_target_uri(uri, normalized, http_target) {
		normalized=uri
		sub(/\/+$/, "", normalized)
		http_target=target
		sub(/^https:/, "http:", http_target)
		return normalized == target || normalized == http_target
	}
	function token_list_contains(value, wanted, count, tokens, i, result) {
		result=0
		count=split(trim(value), tokens, /[[:space:]]+/)
		for (i=1; i<=count; i++) {
			if (tokens[i] == wanted) {
				result=1
			}
			delete tokens[i]
		}
		return result
	}
	function is_explicit_false(value, normalized) {
		normalized=tolower(trim(value))
		return normalized ~ /^(0|no|false|off|disable|without)$/
	}
	function is_explicit_true(value, normalized) {
		normalized=tolower(trim(value))
		return normalized ~ /^(1|yes|true|on|enable|with)$/
	}
	function clear_stanza( i) {
		for (i=1; i<=line_count; i++) {
			delete lines[i]
			delete suite_continuation_lines[i]
			delete architecture_continuation_lines[i]
			delete skip_lines[i]
			delete insert_after[i]
		}
		line_count=0
	}
	function emit_stanza( i) {
		if (mode != "count") {
			for (i=1; i<=line_count; i++) {
				if (!skip_lines[i]) {
					print lines[i]
				}
				if (i in insert_after) {
					print insert_after[i]
				}
			}
		}
	}
	# Replace the value on a field line, keeping the field name and spacing.
	# A field whose old value was only on continuation lines gains one space.
	function replace_field_value(line, value, start, finish, prefix) {
		start=index(line, ":") + 1
		while (start <= length(line) && substr(line, start, 1) ~ /[[:space:]]/) {
			start++
		}
		finish=length(line) + 1
		while (finish > start && substr(line, finish - 1, 1) ~ /[[:space:]]/) {
			finish--
		}
		prefix=substr(line, 1, start - 1)
		if (prefix ~ /:$/) {
			prefix=prefix " "
		}
		return prefix value substr(line, finish)
	}
	function process_stanza( i, line, colon, field, value, current_field,
			uri_value, type_value, suite_value, component_value, enabled_value,
			trusted_value, allow_insecure_value, allow_weak_value,
			allow_downgrade_value, architecture_value,
			uri_fields, type_fields, suite_fields, component_fields,
			enabled_fields, trusted_fields, allow_insecure_fields,
			allow_weak_fields, allow_downgrade_fields, architecture_fields,
			architecture_remove_fields, architecture_add_fields, suite_line,
			architecture_line, component_end, syntax_error,
			uri_count, target_count, type_count, type_has_deb,
			type_has_deb_src, type_valid,
			suite_count, suite_valid, component_count, component_valid) {
		if (line_count == 0) {
			return
		}

		current_field=""
		uri_value=""
		type_value=""
		suite_value=""
		component_value=""
		enabled_value=""
		trusted_value=""
		allow_insecure_value=""
		allow_weak_value=""
		allow_downgrade_value=""
		architecture_value=""
		uri_fields=0
		type_fields=0
		suite_fields=0
		component_fields=0
		enabled_fields=0
		trusted_fields=0
		allow_insecure_fields=0
		allow_weak_fields=0
		allow_downgrade_fields=0
		architecture_fields=0
		architecture_remove_fields=0
		architecture_add_fields=0
		suite_line=0
		architecture_line=0
		component_end=0
		syntax_error=0

		for (i=1; i<=line_count; i++) {
			line=lines[i]
			if (line ~ /^#/) {
				continue
			}
			if (line ~ /^[A-Za-z0-9-]+:/) {
				colon=index(line, ":")
				field=tolower(substr(line, 1, colon - 1))
				value=trim(substr(line, colon + 1))
				current_field=field
				if (field == "uris") {
					uri_fields++
					uri_value=(uri_value == "" ? value : uri_value " " value)
				} else if (field == "types") {
					type_fields++
					type_value=(type_value == "" ? value : type_value " " value)
				} else if (field == "suites") {
					suite_fields++
					suite_line=i
					suite_value=(suite_value == "" ? value : suite_value " " value)
				} else if (field == "components") {
					component_fields++
					component_end=i
					component_value=(component_value == "" ? value : component_value " " value)
				} else if (field == "enabled") {
					enabled_fields++
					enabled_value=(enabled_value == "" ? value : enabled_value " " value)
				} else if (field == "trusted") {
					trusted_fields++
					trusted_value=(trusted_value == "" ? value : trusted_value " " value)
				} else if (field == "allow-insecure") {
					allow_insecure_fields++
					allow_insecure_value=(allow_insecure_value == "" ? value : allow_insecure_value " " value)
				} else if (field == "allow-weak") {
					allow_weak_fields++
					allow_weak_value=(allow_weak_value == "" ? value : allow_weak_value " " value)
				} else if (field == "allow-downgrade-to-insecure") {
					allow_downgrade_fields++
					allow_downgrade_value=(allow_downgrade_value == "" ? value : allow_downgrade_value " " value)
				} else if (field == "architectures") {
					architecture_fields++
					architecture_line=i
					architecture_value=(architecture_value == "" ? value : architecture_value " " value)
				} else if (field == "architectures-remove") {
					architecture_remove_fields++
				} else if (field == "architectures-add") {
					architecture_add_fields++
				}
				continue
			}
			if (line ~ /^[[:space:]]+/) {
				value=trim(line)
				if (current_field == "") {
					syntax_error=1
				} else if (current_field == "uris") {
					uri_value=uri_value " " value
				} else if (current_field == "types") {
					type_value=type_value " " value
				} else if (current_field == "suites") {
					suite_value=suite_value " " value
					suite_continuation_lines[i]=1
				} else if (current_field == "components") {
					component_value=component_value " " value
					component_end=i
				} else if (current_field == "enabled") {
					enabled_value=enabled_value " " value
				} else if (current_field == "trusted") {
					trusted_value=trusted_value " " value
				} else if (current_field == "allow-insecure") {
					allow_insecure_value=allow_insecure_value " " value
				} else if (current_field == "allow-weak") {
					allow_weak_value=allow_weak_value " " value
				} else if (current_field == "allow-downgrade-to-insecure") {
					allow_downgrade_value=allow_downgrade_value " " value
				} else if (current_field == "architectures") {
					architecture_value=architecture_value " " value
					architecture_continuation_lines[i]=1
				}
			} else {
				syntax_error=1
				current_field=""
			}
		}

		uri_count=split(trim(uri_value), uri_tokens, /[[:space:]]+/)
		target_count=0
		for (i=1; i<=uri_count; i++) {
			if (is_target_uri(uri_tokens[i])) {
				target_count++
			}
			delete uri_tokens[i]
		}
		if (target_count == 0) {
			emit_stanza()
			clear_stanza()
			return
		}

		found++
		if (uri_fields != 1 || uri_count != 1 || target_count != 1) {
			malformed=1
			emit_stanza()
			clear_stanza()
			return
		}

		if (mode == "remove") {
			# Preserve comments even when removing the repository stanza.
			if (mode != "count") {
				for (i=1; i<=line_count; i++) {
					if (lines[i] ~ /^#/) {
						print lines[i]
					}
				}
			}
			clear_stanza()
			return
		}

		type_count=split(trim(type_value), type_tokens, /[[:space:]]+/)
		type_has_deb=0
		type_has_deb_src=0
		type_valid=(type_count > 0)
		for (i=1; i<=type_count; i++) {
			if (type_tokens[i] == "deb") {
				type_has_deb=1
			} else if (type_tokens[i] == "deb-src") {
				type_has_deb_src=1
			} else {
				type_valid=0
			}
			delete type_tokens[i]
		}

		suite_count=split(trim(suite_value), suite_tokens, /[[:space:]]+/)
		suite_valid=(suite_count > 0)
		for (i=1; i<=suite_count; i++) {
			if (suite_tokens[i] !~ /^[a-z0-9][a-z0-9-]*$/) {
				suite_valid=0
			}
			delete suite_tokens[i]
		}

		component_count=split(trim(component_value), component_tokens, /[[:space:]]+/)
		component_valid=(component_count == 1 && component_tokens[1] == "main")
		for (i=1; i<=component_count; i++) {
			delete component_tokens[i]
		}

		if (syntax_error || type_fields != 1 || !type_valid ||
				suite_fields != 1 || !suite_valid || component_fields != 1 ||
				!component_valid || enabled_fields > 1 ||
				(enabled_fields == 1 && !is_explicit_true(enabled_value)) ||
				trusted_fields > 1 ||
				(trusted_fields == 1 && !is_explicit_false(trusted_value)) ||
				allow_insecure_fields > 1 ||
				(allow_insecure_fields == 1 && !is_explicit_false(allow_insecure_value)) ||
				allow_weak_fields > 1 ||
				(allow_weak_fields == 1 && !is_explicit_false(allow_weak_value)) ||
				allow_downgrade_fields > 1 ||
				(allow_downgrade_fields == 1 && !is_explicit_false(allow_downgrade_value)) ||
				architecture_fields > 1 ||
				(architecture_fields == 1 &&
					(host_arch == "" || !token_list_contains(architecture_value, host_arch))) ||
				architecture_remove_fields > 0 || architecture_add_fields > 0 ||
				invalid_host_arch) {
			# Architectures-Add could re-add a variant such as amd64v3 after
			# the list is normalized, so it is rejected like Architectures-Remove.
			malformed=1
			emit_stanza()
			clear_stanza()
			return
		}

		if (type_has_deb) {
			binary_found++
		}
		if (type_has_deb_src) {
			source_found++
		}

		if (mode == "set" && trim(suite_value) != replacement) {
			lines[suite_line]=replace_field_value(lines[suite_line], replacement)
			for (i=1; i<=line_count; i++) {
				if (suite_continuation_lines[i]) {
					skip_lines[i]=1
				}
			}
		}
		# Pin the source to exactly the native architecture. With APT
		# architecture variants enabled, an unpinned source whose Release file
		# lists amd64v3 is read only through that index, which Launchpad
		# publishes for PPAs without the architecture-specific packages.
		if (mode == "set" && architecture_fields == 1 &&
				trim(architecture_value) != host_arch) {
			lines[architecture_line]=replace_field_value(lines[architecture_line], host_arch)
			for (i=1; i<=line_count; i++) {
				if (architecture_continuation_lines[i]) {
					skip_lines[i]=1
				}
			}
		} else if (mode == "set" && architecture_fields == 0) {
			insert_after[component_end]="Architectures: " host_arch
		}
		emit_stanza()
		clear_stanza()
	}
	BEGIN {
		line_count=0
		found=0
		binary_found=0
		source_found=0
		malformed=0
		if (mode == "set" && host_arch !~ /^[a-z0-9][a-z0-9-]*$/) {
			invalid_host_arch=1
		}
	}
	{
		if ($0 ~ /^[[:space:]]*$/) {
			process_stanza()
			if (mode != "count") {
				print $0
			}
		} else {
			lines[++line_count]=$0
		}
	}
	END {
		process_stanza()
		if (mode == "count") {
			print found, binary_found, source_found
		}
		if (malformed) {
			exit 4
		}
		if (!found) {
			exit 3
		}
		if (mode != "remove" && !binary_found) {
			exit 5
		}
	}
	' "${FILE}"
}

function _transformAmneziaPpaSourceFile() {
	local FILE="$1"
	local MODE="$2"
	local SUITE="${3:-}"
	local ARCHITECTURE="${4:-}"
	case "${FILE}" in
		*.sources) _transformAmneziaPpaDeb822File "${FILE}" "${MODE}" "${SUITE}" "${ARCHITECTURE}" ;;
		*.list) _transformAmneziaPpaLegacyFile "${FILE}" "${MODE}" "${SUITE}" "${ARCHITECTURE}" ;;
		*) return 3 ;;
	esac
}

function isValidAptSourceFilename() {
	local BASENAME="${1##*/}"
	[[ "${BASENAME}" =~ ^[A-Za-z0-9_.-]+\.(list|sources)$ ]]
}

function _preserveAptSourceFinalNewline() {
	local SOURCE_FILE="$1"
	local TRANSFORMED_FILE="$2"
	local FINAL_BYTE_LINE_COUNT

	[[ -s "${SOURCE_FILE}" && -s "${TRANSFORMED_FILE}" ]] || return 0
	FINAL_BYTE_LINE_COUNT=$(tail -c 1 -- "${SOURCE_FILE}" | wc -l) || return 1
	if [[ "${FINAL_BYTE_LINE_COUNT}" -eq 0 ]]; then
		truncate -s -1 -- "${TRANSFORMED_FILE}"
	fi
}

# Return 0 when exactly one usable binary entry exists, 1 when absent, and 2
# when target content is duplicated, unusable, malformed, or unsafe to rewrite.
function amneziaPpaSourceEntriesExist() {
	local SOURCES_DIR="${1:-${AMNEZIA_PPA_SOURCES_DIR}}"
	local ARCHITECTURE="${2:-}"
	local FILE
	local RC
	local ENTRY_COUNTS
	local FILE_TARGET_COUNT
	local FILE_BINARY_COUNT
	local FILE_SOURCE_COUNT
	local TARGET_COUNT=0
	local BINARY_COUNT=0
	local SOURCE_COUNT=0

	[[ -d "${SOURCES_DIR}" ]] || return 1
	if [[ -z "${ARCHITECTURE}" ]]; then
		ARCHITECTURE=$(getNativeDpkgArchitecture) || {
			echo -e "${RED}ERROR: Unable to determine a valid native package architecture with dpkg.${NC}" >&2
			return 2
		}
	fi
	if ! isValidDpkgArchitecture "${ARCHITECTURE}"; then
		echo -e "${RED}ERROR: Invalid package architecture '${ARCHITECTURE}' for the Amnezia PPA source.${NC}" >&2
		return 2
	fi

	for FILE in "${SOURCES_DIR}"/*.sources "${SOURCES_DIR}"/*.list; do
		[[ -e "${FILE}" || -L "${FILE}" ]] || continue
		isValidAptSourceFilename "${FILE}" || continue
		if ENTRY_COUNTS=$(_transformAmneziaPpaSourceFile \
			"${FILE}" "count" "" "${ARCHITECTURE}"); then
			RC=0
		else
			RC=$?
		fi
		case "${RC}" in
			0 | 5)
				if [[ -L "${FILE}" ]]; then
					echo -e "${RED}ERROR: Refusing to modify Amnezia PPA source through symlink: ${FILE}${NC}" >&2
					return 2
				fi
				read -r FILE_TARGET_COUNT FILE_BINARY_COUNT FILE_SOURCE_COUNT <<< "${ENTRY_COUNTS}"
				if ! [[ "${FILE_TARGET_COUNT}" =~ ^[0-9]+$ &&
					"${FILE_BINARY_COUNT}" =~ ^[0-9]+$ &&
					"${FILE_SOURCE_COUNT}" =~ ^[0-9]+$ ]]; then
					return 2
				fi
				TARGET_COUNT=$((TARGET_COUNT + FILE_TARGET_COUNT))
				BINARY_COUNT=$((BINARY_COUNT + FILE_BINARY_COUNT))
				SOURCE_COUNT=$((SOURCE_COUNT + FILE_SOURCE_COUNT))
				;;
			3) ;;
			*)
				echo -e "${RED}ERROR: Unusable, insecure, malformed, or ambiguous Amnezia PPA source entry in ${FILE}.${NC}" >&2
				return 2
				;;
		esac
	done

	if [[ "${TARGET_COUNT}" -eq 0 ]]; then
		return 1
	fi
	if [[ "${BINARY_COUNT}" -eq 0 ]]; then
		echo -e "${RED}ERROR: Existing Amnezia PPA source content has no active binary ('deb') entry for architecture '${ARCHITECTURE}'.${NC}" >&2
		return 2
	fi
	if [[ "${BINARY_COUNT}" -gt 1 ]]; then
		echo -e "${RED}ERROR: Multiple active Amnezia PPA binary entries were found. Remove the duplicate entries before continuing.${NC}" >&2
		return 2
	fi
	if [[ "${SOURCE_COUNT}" -gt 1 ]]; then
		echo -e "${RED}ERROR: Multiple active Amnezia PPA source-package entries were found. Remove the duplicate entries before continuing.${NC}" >&2
		return 2
	fi
	return 0
}

# Set the suite of each exact Amnezia PPA entry and pin it to exactly the
# native dpkg architecture (DEB822 Architectures, legacy arch=), replacing each
# affected file atomically. Unrelated files, stanzas, fields, comments, options,
# and inline signing keys are preserved. Return 2 when no target entry exists.
function setAmneziaPpaSuite() {
	local SUITE="$1"
	local SOURCES_DIR="${2:-${AMNEZIA_PPA_SOURCES_DIR}}"
	local ARCHITECTURE="${3:-}"
	local FILE
	local TMP_FILE
	local RC
	local INDEX
	local ROLLBACK_INDEX
	local FAILED_INDEX=-1
	local ROLLBACK_FAILED=0
	local ENTRY_COUNTS
	local FILE_TARGET_COUNT
	local FILE_BINARY_COUNT
	local FILE_SOURCE_COUNT
	local FILE_CHECKSUM
	local BACKUP_FILE
	local TARGET_COUNT=0
	local BINARY_COUNT=0
	local SOURCE_COUNT=0
	local -a TARGET_FILES=()
	local -a TEMP_FILES=()
	local -a SOURCE_CHECKSUMS=()
	local -a BACKUP_FILES=()
	local -a CHANGED_FLAGS=()

	if ! [[ "${SUITE}" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
		echo -e "${RED}ERROR: Invalid Amnezia PPA suite '${SUITE}'.${NC}" >&2
		return 1
	fi
	[[ -d "${SOURCES_DIR}" ]] || return 2
	if [[ -z "${ARCHITECTURE}" ]]; then
		ARCHITECTURE=$(getNativeDpkgArchitecture) || {
			echo -e "${RED}ERROR: Unable to determine a valid native package architecture with dpkg.${NC}" >&2
			return 1
		}
	fi
	if ! isValidDpkgArchitecture "${ARCHITECTURE}"; then
		echo -e "${RED}ERROR: Invalid package architecture '${ARCHITECTURE}' for the Amnezia PPA source.${NC}" >&2
		return 1
	fi

	# Validate all matching content before creating any staged replacements.
	for FILE in "${SOURCES_DIR}"/*.sources "${SOURCES_DIR}"/*.list; do
		[[ -e "${FILE}" || -L "${FILE}" ]] || continue
		isValidAptSourceFilename "${FILE}" || continue
		if ENTRY_COUNTS=$(_transformAmneziaPpaSourceFile \
			"${FILE}" "count" "" "${ARCHITECTURE}"); then
			RC=0
		else
			RC=$?
		fi
		case "${RC}" in
			0 | 5)
				if [[ -L "${FILE}" ]]; then
					echo -e "${RED}ERROR: Refusing to modify Amnezia PPA source through symlink: ${FILE}${NC}" >&2
					return 1
				fi
				read -r FILE_TARGET_COUNT FILE_BINARY_COUNT FILE_SOURCE_COUNT <<< "${ENTRY_COUNTS}"
				if ! [[ "${FILE_TARGET_COUNT}" =~ ^[0-9]+$ &&
					"${FILE_BINARY_COUNT}" =~ ^[0-9]+$ &&
					"${FILE_SOURCE_COUNT}" =~ ^[0-9]+$ ]]; then
					return 1
				fi
				TARGET_COUNT=$((TARGET_COUNT + FILE_TARGET_COUNT))
				BINARY_COUNT=$((BINARY_COUNT + FILE_BINARY_COUNT))
				SOURCE_COUNT=$((SOURCE_COUNT + FILE_SOURCE_COUNT))
				FILE_CHECKSUM=$(cksum -- "${FILE}") || return 1
				TARGET_FILES+=("${FILE}")
				SOURCE_CHECKSUMS+=("${FILE_CHECKSUM}")
				;;
			3) ;;
			*)
				echo -e "${RED}ERROR: Unusable, insecure, malformed, or ambiguous Amnezia PPA source entry in ${FILE}.${NC}" >&2
				return 1
				;;
		esac
	done

	if [[ "${TARGET_COUNT}" -eq 0 ]]; then
		return 2
	fi
	if [[ "${BINARY_COUNT}" -eq 0 ]]; then
		echo -e "${RED}ERROR: Existing Amnezia PPA source content has no active binary ('deb') entry for architecture '${ARCHITECTURE}'.${NC}" >&2
		return 1
	fi
	if [[ "${BINARY_COUNT}" -gt 1 ]]; then
		echo -e "${RED}ERROR: Multiple active Amnezia PPA binary entries were found. Remove the duplicate entries before continuing.${NC}" >&2
		return 1
	fi
	if [[ "${SOURCE_COUNT}" -gt 1 ]]; then
		echo -e "${RED}ERROR: Multiple active Amnezia PPA source-package entries were found. Remove the duplicate entries before continuing.${NC}" >&2
		return 1
	fi

	for FILE in "${TARGET_FILES[@]}"; do
		if [[ -L "${FILE}" || ! -f "${FILE}" ]]; then
			echo -e "${RED}ERROR: Amnezia PPA source changed while it was being validated: ${FILE}${NC}" >&2
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		fi
		TMP_FILE=$(mktemp "${FILE}.amneziawg.XXXXXX") || {
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		}
		if ! cp --preserve=all -- "${FILE}" "${TMP_FILE}"; then
			rm -f "${TMP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		fi
		if _transformAmneziaPpaSourceFile \
			"${FILE}" "set" "${SUITE}" "${ARCHITECTURE}" > "${TMP_FILE}"; then
			RC=0
		else
			RC=$?
		fi
		case "${RC}" in
			0 | 5)
				if ! _preserveAptSourceFinalNewline "${FILE}" "${TMP_FILE}"; then
					rm -f "${TMP_FILE}"
					for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
					return 1
				fi
				TEMP_FILES+=("${TMP_FILE}")
				;;
			*)
				rm -f "${TMP_FILE}"
				for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
				echo -e "${RED}ERROR: Amnezia PPA source changed while it was being rewritten: ${FILE}${NC}" >&2
				return 1
				;;
		esac
	done

	# Recheck every source after staging so a concurrent administrator edit is
	# never overwritten. Backups let a later per-file rename failure roll back
	# earlier files in the same reconciliation.
	for INDEX in "${!TARGET_FILES[@]}"; do
		if [[ -L "${TARGET_FILES[INDEX]}" || ! -f "${TARGET_FILES[INDEX]}" ]] ||
			[[ "$(cksum -- "${TARGET_FILES[INDEX]}")" != "${SOURCE_CHECKSUMS[INDEX]}" ]]; then
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			echo -e "${RED}ERROR: Amnezia PPA source changed while replacements were being staged: ${TARGET_FILES[INDEX]}${NC}" >&2
			return 1
		fi
		BACKUP_FILE=$(mktemp "${TARGET_FILES[INDEX]}.amneziawg-backup.XXXXXX") || {
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			return 1
		}
		if ! cp --preserve=all -- "${TARGET_FILES[INDEX]}" "${BACKUP_FILE}"; then
			rm -f "${BACKUP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			return 1
		fi
		BACKUP_FILES+=("${BACKUP_FILE}")
		if cmp -s "${TARGET_FILES[INDEX]}" "${TEMP_FILES[INDEX]}"; then
			CHANGED_FLAGS+=("0")
		else
			CHANGED_FLAGS+=("1")
		fi
	done

	for INDEX in "${!TARGET_FILES[@]}"; do
		if [[ -L "${TARGET_FILES[INDEX]}" || ! -f "${TARGET_FILES[INDEX]}" ]] ||
			[[ "$(cksum -- "${TARGET_FILES[INDEX]}")" != "${SOURCE_CHECKSUMS[INDEX]}" ]]; then
			FAILED_INDEX="${INDEX}"
			break
		fi
		if [[ "${CHANGED_FLAGS[INDEX]}" -eq 0 ]]; then
			rm -f "${TEMP_FILES[INDEX]}"
		elif ! mv -f "${TEMP_FILES[INDEX]}" "${TARGET_FILES[INDEX]}"; then
			FAILED_INDEX="${INDEX}"
			break
		fi
	done
	if [[ "${FAILED_INDEX}" -ge 0 ]]; then
		for ((ROLLBACK_INDEX=0; ROLLBACK_INDEX<FAILED_INDEX; ROLLBACK_INDEX++)); do
			if [[ "${CHANGED_FLAGS[ROLLBACK_INDEX]}" -eq 1 ]] &&
				! mv -f "${BACKUP_FILES[ROLLBACK_INDEX]}" "${TARGET_FILES[ROLLBACK_INDEX]}"; then
				ROLLBACK_FAILED=1
			fi
		done
		for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
		for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
		if [[ "${ROLLBACK_FAILED}" -eq 1 ]]; then
			echo -e "${RED}ERROR: Failed to roll back every PPA source after a replacement error. Review ${SOURCES_DIR}.${NC}" >&2
		fi
		return 1
	fi
	for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
	return 0
}

# Remove only exact Amnezia PPA entries, regardless of their suite or filename.
# Empty source files are deleted; files retaining comments or unrelated entries
# remain in place. This is idempotent and is also used for failed-add cleanup.
function removeAmneziaPpaSourceEntries() {
	local SOURCES_DIR="${1:-${AMNEZIA_PPA_SOURCES_DIR}}"
	local FILE
	local TMP_FILE
	local RC
	local INDEX
	local ROLLBACK_INDEX
	local FAILED_INDEX=-1
	local ROLLBACK_FAILED=0
	local FILE_CHECKSUM
	local BACKUP_FILE
	local -a TARGET_FILES=()
	local -a TEMP_FILES=()
	local -a SOURCE_CHECKSUMS=()
	local -a BACKUP_FILES=()

	[[ -d "${SOURCES_DIR}" ]] || return 0

	# Validate every prospective removal before staging any file. In particular,
	# mixed-URI DEB822 stanzas and symlinks are never partially processed.
	for FILE in "${SOURCES_DIR}"/*.sources "${SOURCES_DIR}"/*.list; do
		[[ -e "${FILE}" || -L "${FILE}" ]] || continue
		isValidAptSourceFilename "${FILE}" || continue
		if _transformAmneziaPpaSourceFile "${FILE}" "remove" >/dev/null; then
			RC=0
		else
			RC=$?
		fi
		case "${RC}" in
			0)
				if [[ -L "${FILE}" ]]; then
					echo -e "${RED}ERROR: Refusing to modify Amnezia PPA source through symlink: ${FILE}${NC}" >&2
					return 1
				fi
				FILE_CHECKSUM=$(cksum -- "${FILE}") || return 1
				TARGET_FILES+=("${FILE}")
				SOURCE_CHECKSUMS+=("${FILE_CHECKSUM}")
				;;
			3) ;;
			*)
				echo -e "${RED}ERROR: Malformed or ambiguous Amnezia PPA source entry in ${FILE}.${NC}" >&2
				return 1
				;;
		esac
	done

	for FILE in "${TARGET_FILES[@]}"; do
		if [[ -L "${FILE}" || ! -f "${FILE}" ]]; then
			echo -e "${RED}ERROR: Amnezia PPA source changed while it was being validated: ${FILE}${NC}" >&2
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		fi
		TMP_FILE=$(mktemp "${FILE}.amneziawg.XXXXXX") || {
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		}
		if ! cp --preserve=all -- "${FILE}" "${TMP_FILE}"; then
			rm -f "${TMP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		fi
		if _transformAmneziaPpaSourceFile "${FILE}" "remove" > "${TMP_FILE}"; then
			RC=0
		else
			RC=$?
		fi
		if [[ "${RC}" -ne 0 ]] ||
			! _preserveAptSourceFinalNewline "${FILE}" "${TMP_FILE}"; then
			rm -f "${TMP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			echo -e "${RED}ERROR: Amnezia PPA source changed while it was being removed: ${FILE}${NC}" >&2
			return 1
		fi
		TEMP_FILES+=("${TMP_FILE}")
	done

	for INDEX in "${!TARGET_FILES[@]}"; do
		if [[ -L "${TARGET_FILES[INDEX]}" || ! -f "${TARGET_FILES[INDEX]}" ]] ||
			[[ "$(cksum -- "${TARGET_FILES[INDEX]}")" != "${SOURCE_CHECKSUMS[INDEX]}" ]]; then
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			echo -e "${RED}ERROR: Amnezia PPA source changed while removals were being staged: ${TARGET_FILES[INDEX]}${NC}" >&2
			return 1
		fi
		BACKUP_FILE=$(mktemp "${TARGET_FILES[INDEX]}.amneziawg-backup.XXXXXX") || {
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			return 1
		}
		if ! cp --preserve=all -- "${TARGET_FILES[INDEX]}" "${BACKUP_FILE}"; then
			rm -f "${BACKUP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			return 1
		fi
		BACKUP_FILES+=("${BACKUP_FILE}")
	done

	for INDEX in "${!TARGET_FILES[@]}"; do
		if [[ -L "${TARGET_FILES[INDEX]}" || ! -f "${TARGET_FILES[INDEX]}" ]] ||
			[[ "$(cksum -- "${TARGET_FILES[INDEX]}")" != "${SOURCE_CHECKSUMS[INDEX]}" ]]; then
			FAILED_INDEX="${INDEX}"
			break
		fi
		if grep -q '[^[:space:]]' "${TEMP_FILES[INDEX]}"; then
			if ! mv -f "${TEMP_FILES[INDEX]}" "${TARGET_FILES[INDEX]}"; then
				FAILED_INDEX="${INDEX}"
				break
			fi
		else
			rm -f "${TEMP_FILES[INDEX]}"
			if ! rm -f -- "${TARGET_FILES[INDEX]}"; then
				FAILED_INDEX="${INDEX}"
				break
			fi
		fi
	done
	if [[ "${FAILED_INDEX}" -ge 0 ]]; then
		for ((ROLLBACK_INDEX=0; ROLLBACK_INDEX<FAILED_INDEX; ROLLBACK_INDEX++)); do
			if ! mv -f "${BACKUP_FILES[ROLLBACK_INDEX]}" "${TARGET_FILES[ROLLBACK_INDEX]}"; then
				ROLLBACK_FAILED=1
			fi
		done
		for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
		for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
		if [[ "${ROLLBACK_FAILED}" -eq 1 ]]; then
			echo -e "${RED}ERROR: Failed to roll back every PPA source after a removal error. Review ${SOURCES_DIR}.${NC}" >&2
		fi
		return 1
	fi
	for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
	return 0
}

# Add or reconcile the PPA without letting add-apt-repository update APT before
# a fallback suite can be selected. Existing valid entries are reused, which
# prevents duplicate stanzas on installer reruns.
function configureUbuntuAmneziaPpa() {
	local NATIVE_SUITE="${1:-}"
	local SOURCES_DIR="${2:-${AMNEZIA_PPA_SOURCES_DIR}}"
	local ARCHITECTURE="${3:-}"
	local EXIST_RC
	local SELECTED_SUITE

	AMNEZIA_PPA_SOURCE_CREATED=0
	AMNEZIA_PPA_SELECTED_SUITE=""
	AMNEZIA_PPA_ARCHITECTURE=""
	if [[ -z "${NATIVE_SUITE}" ]]; then
		NATIVE_SUITE=$(getUbuntuPpaCodename) || return 1
	fi
	if [[ -z "${ARCHITECTURE}" ]]; then
		ARCHITECTURE=$(getNativeDpkgArchitecture) || {
			echo -e "${RED}ERROR: Unable to determine the system package architecture.${NC}" >&2
			return 1
		}
	fi
	if ! isValidDpkgArchitecture "${ARCHITECTURE}"; then
		echo -e "${RED}ERROR: Invalid package architecture '${ARCHITECTURE}' for the Amnezia PPA source.${NC}" >&2
		return 1
	fi
	SELECTED_SUITE=$(selectAmneziaPpaSuite "${NATIVE_SUITE}" "${ARCHITECTURE}") || return 1

	if amneziaPpaSourceEntriesExist "${SOURCES_DIR}" "${ARCHITECTURE}"; then
		EXIST_RC=0
	else
		EXIST_RC=$?
	fi
	case "${EXIST_RC}" in
		0)
			if ! setAmneziaPpaSuite "${SELECTED_SUITE}" "${SOURCES_DIR}" "${ARCHITECTURE}"; then
				echo -e "${RED}ERROR: Failed to reconcile the existing Amnezia PPA source.${NC}" >&2
				return 1
			fi
			;;
		1)
			if ! add-apt-repository -y -n ppa:amnezia/ppa; then
				if ! removeAmneziaPpaSourceEntries "${SOURCES_DIR}"; then
					echo -e "${ORANGE}WARNING: Failed to clean up a partial Amnezia PPA source after add-apt-repository failed.${NC}" >&2
				fi
				echo -e "${RED}ERROR: Failed to add Amnezia PPA.${NC}" >&2
				return 1
			fi
			if ! setAmneziaPpaSuite "${SELECTED_SUITE}" "${SOURCES_DIR}" "${ARCHITECTURE}"; then
				if ! removeAmneziaPpaSourceEntries "${SOURCES_DIR}"; then
					echo -e "${ORANGE}WARNING: Failed to clean up the unusable source created by add-apt-repository.${NC}" >&2
				fi
				echo -e "${RED}ERROR: add-apt-repository did not create a usable Amnezia PPA source entry.${NC}" >&2
				return 1
			fi
			AMNEZIA_PPA_SOURCE_CREATED=1
			;;
		*)
			return 1
			;;
	esac

	AMNEZIA_PPA_SELECTED_SUITE="${SELECTED_SUITE}"
	AMNEZIA_PPA_ARCHITECTURE="${ARCHITECTURE}"
	return 0
}

# After the PPA is configured and the package lists refreshed, require an
# installable amneziawg-tools candidate. The candidate record must come from a
# package index (only index records carry Filename): a version known only from
# the dpkg status file cannot be installed or repaired from the PPA. Field names
# in apt-cache show output are not translated, unlike apt-cache policy text.
function checkAmneziaPpaToolsCandidate() {
	local SUITE="$1"
	local ARCHITECTURE="$2"
	local RECORD

	RECORD=$(LC_ALL=C apt-cache show --no-all-versions amneziawg-tools 2>/dev/null) || RECORD=""
	if grep -q '^Filename: ' <<< "${RECORD}"; then
		return 0
	fi

	echo -e "${RED}ERROR: The Amnezia PPA (ppa:amnezia/ppa, ${AMNEZIA_PPA_URI}) has no installable amneziawg-tools package for Ubuntu suite '${SUITE:-unknown}' and architecture '${ARCHITECTURE:-unknown}'.${NC}" >&2
	echo -e "${ORANGE}The package lists were refreshed successfully, so this is not a network failure: the PPA currently publishes no usable amneziawg-tools candidate for this suite and architecture.${NC}" >&2
	echo -e "${ORANGE}Check https://launchpad.net/~amnezia/+archive/ubuntu/ppa/+packages and retry once the package is published.${NC}" >&2
	return 1
}

# Roll back only a source entry created by the current configure call. A
# pre-existing administrator-owned entry is never removed because another
# repository or a transient network failure made apt-get update fail.
# Return 0 when removed, 1 on cleanup failure, and 2 when no new entry is owned.
function cleanupNewlyCreatedUbuntuAmneziaPpa() {
	local SOURCES_DIR="${1:-${AMNEZIA_PPA_SOURCES_DIR}}"

	[[ "${AMNEZIA_PPA_SOURCE_CREATED}" -eq 1 ]] || return 2
	if ! removeAmneziaPpaSourceEntries "${SOURCES_DIR}"; then
		return 1
	fi
	AMNEZIA_PPA_SOURCE_CREATED=0
	return 0
}

# Best-effort reconciliation for an already-installed server. This rechecks the
# native suite on every rerun so a temporary fallback automatically stops being
# used once Launchpad publishes native metadata. Management remains available
# during network outages.
function refreshConfiguredUbuntuAmneziaPpa() {
	local EXIST_RC
	if amneziaPpaSourceEntriesExist "${AMNEZIA_PPA_SOURCES_DIR}"; then
		EXIST_RC=0
	else
		EXIST_RC=$?
	fi
	case "${EXIST_RC}" in
		0)
			enable_apt_ipv4
			if ! configureUbuntuAmneziaPpa "" "${AMNEZIA_PPA_SOURCES_DIR}"; then
				echo -e "${ORANGE}WARNING: Could not refresh the configured Amnezia PPA suite. Leaving the existing entry unchanged.${NC}" >&2
			fi
			disable_apt_ipv4
			;;
		1) return 0 ;;
		*)
			echo -e "${ORANGE}WARNING: Existing Amnezia PPA source content is malformed; automatic suite refresh was skipped.${NC}" >&2
			;;
	esac
	return 0
}

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

# Clear every AWG 3.x-only value before loading persistent state. This is a
# security boundary: exported environment variables must never opt an AWG 2.0
# installation into header protection or alter its generated client configs.
function clearAwg3Params() {
	AWG_HEADER_PROTECTION_KEY=""
	AWG_CONTENT_PADDING_ADDITION=""
	AWG_REKEY_AFTER_TIME=""
	AWG_REKEY_TIMEOUT=""
	AWG_REJECT_AFTER_TIME=""
	AWG_KEEPALIVE_TIMEOUT=""
	clearAwg31Params
}

# Clear AWG 3.1-only values while leaving AWG 3.0 header-protection state.
function clearAwg31Params() {
	AWG_RANDOM_TRAILERS=""
	AWG_DISABLE_COOKIES=""
}

function awgProtocolDisplayName() {
	case "${1:-}" in
		"${AWG_PROTOCOL_VERSION_2}"|2.0) printf '2.0\n' ;;
		"${AWG_PROTOCOL_VERSION_3}"|3.0) printf '3.0\n' ;;
		"${AWG_PROTOCOL_VERSION_31}") printf '3.1\n' ;;
		*) printf '%s\n' "${1:-unknown}" ;;
	esac
}

function awgProtocolUsesHeaderProtection() {
	case "${AWG_PROTOCOL_VERSION}" in
		"${AWG_PROTOCOL_VERSION_3}"|"${AWG_PROTOCOL_VERSION_31}") return 0 ;;
		*) return 1 ;;
	esac
}

function awgProtocolUses31Fields() {
	[[ "${AWG_PROTOCOL_VERSION}" == "${AWG_PROTOCOL_VERSION_31}" ]]
}

# Canonicalize a protocol boolean to the upstream on|off spelling used by
# amneziawg-tools (`parse_bool` also accepts true/false/yes/no/1/0).
function normalizeAwgOnOff() {
	local NAME="$1"
	local VALUE="${2:-}"
	# Trim only leading/trailing whitespace so " on " matches the web parser.
	VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
	VALUE="${VALUE%"${VALUE##*[![:space:]]}"}"
	case "${VALUE,,}" in
		on|true|yes|1)
			printf 'on\n'
			;;
		off|false|no|0)
			printf 'off\n'
			;;
		*)
			echo "ERROR: ${NAME} must be on or off" >&2
			return 1
			;;
	esac
}

# Normalize persisted aliases while preserving the compatibility rule that a
# missing protocol version is AWG 2.0. "3" / "3.0" stay AWG 3.0; they are
# never silently reinterpreted as 3.1.
function normalizeAwgProtocolVersion() {
	case "${AWG_PROTOCOL_VERSION:-}" in
		""|2|2.0)
			AWG_PROTOCOL_VERSION="${AWG_PROTOCOL_VERSION_2}"
			;;
		3|3.0)
			AWG_PROTOCOL_VERSION="${AWG_PROTOCOL_VERSION_3}"
			;;
		3.1)
			AWG_PROTOCOL_VERSION="${AWG_PROTOCOL_VERSION_31}"
			;;
		*)
			echo "ERROR: unsupported AWG_PROTOCOL_VERSION in params; expected 2, 3, or 3.1" >&2
			return 1
			;;
	esac
}

# AWG 3.0 range fields are encoded as one uint16 value or an inclusive
# uint16 range (for example, 10 or 10-100). Empty values are allowed because
# every timing/content-padding field is optional upstream.
function validateAwg3Range() {
	local NAME="$1"
	local VALUE="$2"
	local LOW HIGH

	[[ -n "${VALUE}" ]] || return 0
	if ! [[ "${VALUE}" =~ ^([0-9]{1,5})(-([0-9]{1,5}))?$ ]]; then
		echo "ERROR: ${NAME} must be an integer or inclusive range (for example, 10-20)" >&2
		return 1
	fi
	LOW=$((10#${BASH_REMATCH[1]}))
	HIGH="${BASH_REMATCH[3]:-${BASH_REMATCH[1]}}"
	HIGH=$((10#${HIGH}))
	if (( LOW > 65535 || HIGH > 65535 || LOW > HIGH )); then
		echo "ERROR: ${NAME} must be an ordered range between 0 and 65535" >&2
		return 1
	fi
}

# Validate persisted/generated AWG 3.0 state without ever echoing the header
# key. S1-S4 supply the 12-byte nonce prefix required by header protection.
function validateAwg3Params() {
	local PADDING_NAME PADDING_VALUE

	if ! [[ "${AWG_HEADER_PROTECTION_KEY:-}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
		echo "ERROR: HeaderProtectionKey must be a 32-byte base64 key" >&2
		return 1
	fi
	if command -v awg >/dev/null 2>&1 && \
		! printf '%s\n' "${AWG_HEADER_PROTECTION_KEY}" | awg pubkey >/dev/null 2>&1; then
		echo "ERROR: HeaderProtectionKey is not accepted by the installed awg tool" >&2
		return 1
	fi

	for PADDING_NAME in SERVER_AWG_S1 SERVER_AWG_S2 SERVER_AWG_S3 SERVER_AWG_S4; do
		PADDING_VALUE="${!PADDING_NAME:-}"
		if ! [[ "${PADDING_VALUE}" =~ ^[0-9]{1,5}$ ]] || \
			(( 10#${PADDING_VALUE} < 12 || 10#${PADDING_VALUE} > 65535 )); then
			echo "ERROR: ${PADDING_NAME} must be at least 12 when AWG 3.0 header protection is enabled" >&2
			return 1
		fi
	done

	validateAwg3Range "ContentPaddingAddition" "${AWG_CONTENT_PADDING_ADDITION:-}" || return 1
	validateAwg3Range "RekeyAfterTime" "${AWG_REKEY_AFTER_TIME:-}" || return 1
	validateAwg3Range "RekeyTimeout" "${AWG_REKEY_TIMEOUT:-}" || return 1
	validateAwg3Range "RejectAfterTime" "${AWG_REJECT_AFTER_TIME:-}" || return 1
	validateAwg3Range "KeepaliveTimeout" "${AWG_KEEPALIVE_TIMEOUT:-}" || return 1
}

# Validate and canonicalize AWG 3.1-only booleans. Empty values are invalid
# in 3.1 mode so generated server/client configs always agree.
function validateAwg31Params() {
	local NORMALIZED

	validateAwg3Params || return 1
	NORMALIZED="$(normalizeAwgOnOff "RandomTrailers" "${AWG_RANDOM_TRAILERS:-}")" || return 1
	AWG_RANDOM_TRAILERS="${NORMALIZED}"
	NORMALIZED="$(normalizeAwgOnOff "DisableCookies" "${AWG_DISABLE_COOKIES:-}")" || return 1
	AWG_DISABLE_COOKIES="${NORMALIZED}"
}

# Upstream recommends identical S1-S4 when RandomTrailers is on so random
# packet sizes are less likely to be classified as the wrong handshake type.
# Existing S-values are never rewritten; the operator is warned instead.
function warnIfRandomTrailersSPaddingUnequal() {
	[[ "${AWG_RANDOM_TRAILERS:-}" == "on" ]] || return 0
	if [[ "${SERVER_AWG_S1}" == "${SERVER_AWG_S2}" && \
		"${SERVER_AWG_S1}" == "${SERVER_AWG_S3}" && \
		"${SERVER_AWG_S1}" == "${SERVER_AWG_S4}" ]]; then
		return 0
	fi
	echo "WARNING: RandomTrailers is on, but S1-S4 are not identical (S1=${SERVER_AWG_S1} S2=${SERVER_AWG_S2} S3=${SERVER_AWG_S3} S4=${SERVER_AWG_S4})." >&2
	echo "         Upstream recommends the same S1, S2, S3, and S4 values to reduce packet-type misdetection." >&2
}

# Invalid AWG 3.x-only state normally fails closed. The sole exception is the
# explicit AWG 2.0 downgrade command, which must remain able to remove damaged
# 3.0/3.1 fields and restore an otherwise valid installation to AWG 2.0.
function validatePersistedAwgProtocolState() {
	local ALLOW_INVALID_AWG3_FOR_DOWNGRADE="${1:-0}"

	normalizeAwgProtocolVersion || return 1
	if awgProtocolUses31Fields && ! validateAwg31Params; then
		if [[ "${ALLOW_INVALID_AWG3_FOR_DOWNGRADE}" == "1" ]]; then
			echo "WARNING: invalid AWG 3.1 state will be removed by the requested AWG 2.0 downgrade" >&2
			return 0
		fi
		echo "ERROR: invalid AWG 3.1 protocol state in persisted params" >&2
		return 1
	fi
	if [[ "${AWG_PROTOCOL_VERSION}" == "${AWG_PROTOCOL_VERSION_3}" ]] && ! validateAwg3Params; then
		if [[ "${ALLOW_INVALID_AWG3_FOR_DOWNGRADE}" == "1" ]]; then
			echo "WARNING: invalid AWG 3.0 state will be removed by the requested AWG 2.0 downgrade" >&2
			return 0
		fi
		echo "ERROR: invalid AWG 3.0 protocol state in persisted params" >&2
		return 1
	fi
}

# Explain why an AWG backend value cannot be used by this installer version.
# The value is echoed only when it is a plain token, so a damaged params file
# cannot put control characters into the diagnostics.
function reportUnsupportedAwgBackend() {
	local BACKEND_VALUE="${1:-}"

	if [[ -z "${BACKEND_VALUE}" ]]; then
		echo "ERROR: the AWG backend is not set; refusing to operate on an unknown backend" >&2
	elif [[ "${BACKEND_VALUE}" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
		echo "ERROR: AWG backend '${BACKEND_VALUE}' is not supported by this installer version (supported: ${AWG_BACKEND_KERNEL}, ${AWG_BACKEND_BORINGTUN})" >&2
	else
		echo "ERROR: the configured AWG backend is not supported by this installer version (supported: ${AWG_BACKEND_KERNEL}, ${AWG_BACKEND_BORINGTUN})" >&2
	fi
}

# Normalize the persisted backend. A missing or empty value is the kernel
# backend, which is what every params file written before backends existed
# means; kernel and boringtun stay as they are. Every other value, including
# backends that later installer versions may add, fails closed instead of
# being reinterpreted as the kernel backend.
function normalizeAwgBackend() {
	case "${AWG_BACKEND:-}" in
		""|"${AWG_BACKEND_KERNEL}")
			AWG_BACKEND="${AWG_BACKEND_KERNEL}"
			;;
		"${AWG_BACKEND_BORINGTUN}") ;;
		*)
			reportUnsupportedAwgBackend "${AWG_BACKEND}"
			return 1
			;;
	esac
}

# Choose the backend of a fresh installation from the caller's AWG_BACKEND, as
# it was when the installer was loaded: unset or empty means the kernel
# backend, the default; kernel and boringtun select that backend; anything else
# fails closed. Existing installations never come here: their params decide.
function selectFreshInstallBackend() {
	AWG_BACKEND="${_AWG_BACKEND_REQUESTED}"
	if ! normalizeAwgBackend; then
		echo "ERROR: set AWG_BACKEND to '${AWG_BACKEND_KERNEL}' (the default) or '${AWG_BACKEND_BORINGTUN}' (experimental) for a fresh installation." >&2
		return 1
	fi
}

# Validate the persisted backend after params are sourced, and the settings
# that belong to it.
function validatePersistedAwgBackendState() {
	normalizeAwgBackend || return 1
	validatePersistedBoringtunImitationState
}

# The protocol imitation must suit the backend: a kernel installation has none
# and no hostname, and a BoringTun one a supported protocol and a hostname only
# where that protocol uses one.
function checkBoringtunImitationForBackend() {
	if [[ "${AWG_BACKEND:-}" != "${AWG_BACKEND_BORINGTUN}" ]]; then
		if [[ "${AWG_BORINGTUN_IMITATE_PROTOCOL:-${AWG_BT_IMITATE_NONE}}" != "${AWG_BT_IMITATE_NONE}" || -n "${AWG_BORINGTUN_IMITATE_DOMAIN:-}" ]]; then
			echo "ERROR: protocol imitation is available only with the BoringTun backend (AWG_BACKEND=${AWG_BACKEND_BORINGTUN})." >&2
			return 1
		fi
		return 0
	fi
	_awgBtImitationCheck "${AWG_BORINGTUN_IMITATE_PROTOCOL:-}" "${AWG_BORINGTUN_IMITATE_DOMAIN:-}"
}

# Normalize the persisted imitation. Params written before imitation existed
# have neither key, which means none; a key that is present must hold a valid
# value, and a kernel installation must not carry one other than none.
function validatePersistedBoringtunImitationState() {
	[[ -n "${AWG_BORINGTUN_IMITATE_PROTOCOL+set}" ]] || AWG_BORINGTUN_IMITATE_PROTOCOL="${AWG_BT_IMITATE_NONE}"
	AWG_BORINGTUN_IMITATE_DOMAIN="${AWG_BORINGTUN_IMITATE_DOMAIN:-}"
	checkBoringtunImitationForBackend
}

# Choose the imitation of a fresh installation from the caller's
# AWG_BORINGTUN_IMITATE_PROTOCOL and AWG_BORINGTUN_IMITATE_DOMAIN, as they were
# when the installer was loaded: unset or empty means none. A kernel install
# refuses any other request here, before it changes anything.
function selectFreshInstallImitation() {
	AWG_BORINGTUN_IMITATE_PROTOCOL="${_AWG_BT_IMITATE_PROTOCOL_REQUESTED:-${AWG_BT_IMITATE_NONE}}"
	AWG_BORINGTUN_IMITATE_DOMAIN="${_AWG_BT_IMITATE_DOMAIN_REQUESTED}"
	if ! checkBoringtunImitationForBackend; then
		echo "ERROR: set AWG_BORINGTUN_IMITATE_PROTOCOL to none (the default), dns, quic, sip, stun or auto, and AWG_BORINGTUN_IMITATE_DOMAIN only for dns, quic or sip (never for auto), on a fresh installation with AWG_BACKEND=${AWG_BACKEND_BORINGTUN}." >&2
		return 1
	fi
}

# How the imitation is shown: the protocol, and for dns, quic and sip whether
# the hostname is configured or left to BoringTun.
function boringtunImitationDomainMode() { # <protocol> <domain>
	if ! _awgBtImitationUsesDomain "$1"; then
		printf 'none\n'
	elif [[ -n "$2" ]]; then
		printf 'configured\n'
	else
		printf 'random\n'
	fi
}

function boringtunImitationDisplay() { # <protocol> <domain>
	if [[ "$1" == auto ]]; then
		printf 'auto (chosen per authenticated peer)\n'
		return 0
	fi
	case "$(boringtunImitationDomainMode "$1" "$2")" in
		configured) printf '%s (hostname %s)\n' "$1" "$2" ;;
		random) printf '%s (hostname chosen by BoringTun)\n' "$1" ;;
		*) printf '%s\n' "$1" ;;
	esac
}

# The largest of S1-S4, the S prefixes that imitation shapes.
function boringtunLargestSPrefix() {
	local LARGEST=0 SIZE
	for SIZE in "${SERVER_AWG_S1:-0}" "${SERVER_AWG_S2:-0}" "${SERVER_AWG_S3:-0}" "${SERVER_AWG_S4:-0}"; do
		[[ "${SIZE}" =~ ^[0-9]{1,5}$ ]] || SIZE=0
		((10#${SIZE} > LARGEST)) && LARGEST=$((10#${SIZE}))
	done
	printf '%s\n' "${LARGEST}"
}

# The pinned BoringTun refuses SIP imitation together with header protection
# (AWG 3.0 and 3.1) once any S prefix is 31 bytes or more: the SIP request line
# it writes there would leave the header-protection nonce a few fixed strings.
# Checked before anything changes, so the refusal never surfaces as a failed
# restart.
function checkBoringtunImitationProtocolCompat() { # <protocol> <AWG protocol version>
	[[ "$1" == sip ]] || return 0
	[[ "$2" == "${AWG_PROTOCOL_VERSION_3}" || "$2" == "${AWG_PROTOCOL_VERSION_31}" ]] || return 0
	(($(boringtunLargestSPrefix) >= 31)) || return 0
	echo "ERROR: SIP imitation cannot be combined with AmneziaWG $(awgProtocolDisplayName "$2") on this server." >&2
	echo "BoringTun refuses SIP imitation with header protection while any of S1-S4 is 31 bytes or more (S1=${SERVER_AWG_S1:-} S2=${SERVER_AWG_S2:-} S3=${SERVER_AWG_S3:-} S4=${SERVER_AWG_S4:-}): the SIP request line it writes there leaves the header-protection nonce only a few fixed values." >&2
	echo "Choose dns, quic or stun, or keep SIP with AmneziaWG 2.0. Changing S1-S4 would need new client configs." >&2
	return 1
}

# The trade-offs of a protocol imitation, printed wherever one is chosen or
# kept across a protocol change (design §9.4). They describe the persisted
# S1-S4 and listen port and the given imitation and AWG protocol version; they
# never refuse anything.
function printBoringtunImitationWarnings() { # <protocol> <domain> <AWG protocol version>
	local PROTOCOL="$1" DOMAIN="$2" VERSION="$3"
	[[ "${PROTOCOL}" != "${AWG_BT_IMITATE_NONE}" ]] || return 0
	if [[ "${PROTOCOL}" == auto ]]; then
		printBoringtunAutoImitationWarnings "${VERSION}"
		return 0
	fi
	echo -e "${ORANGE}Protocol imitation: $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}")${NC}"
	echo "- Server side only: BoringTun shapes the S1-S4 prefixes of the packets this server sends. Standard AmneziaWG clients keep sending plain AmneziaWG; client configs do not change."
	case "${PROTOCOL}" in
		dns) echo "- Probes: the listen port answers DNS queries from other hosts with SERVFAIL." ;;
		stun) echo "- Probes: the listen port answers STUN Binding Requests with a Binding Success about 2.6 times the request's size, so it can reflect traffic toward a spoofed source." ;;
		quic) echo "- Probes: the listen port answers QUIC Initials of 1200 bytes or more with Version Negotiation when they offer a version that real servers do not (QUIC v1 and v2 get no reply)." ;;
		sip) echo "- Probes: SIP requests get no reply; BoringTun has no SIP responder." ;;
	esac
	echo "  All probe replies share a budget of 16 KiB/s (BoringTun's default); loopback, link-local, multicast and broadcast sources are never answered."
	echo "- The listen port stays ${SERVER_PORT:-unchanged}: the installer never moves it, because a new port needs new client configs. Imitation is most plausible on the protocol's usual port."
	if [[ "${VERSION}" == "${AWG_PROTOCOL_VERSION_3}" || "${VERSION}" == "${AWG_PROTOCOL_VERSION_31}" ]]; then
		echo -e "${ORANGE}- AmneziaWG $(awgProtocolDisplayName "${VERSION}"): header protection takes its nonce from the first 12 bytes of each S prefix, and imitation shapes those bytes.${NC}"
		case "${PROTOCOL}" in
			dns) echo "  dns leaves 16 random bits: nonces repeat within a few hundred datagrams, and each repeat repeats the header mask, so header masking is much weaker." ;;
			stun) echo "  stun leaves 32 random bits: nonces start to repeat after about 77,000 datagrams, which weakens header masking on long-lived keys." ;;
			quic) echo "  quic leaves the nonce random, so header protection keeps its strength." ;;
			sip) echo "  sip is accepted only while every S prefix is 30 bytes or less, where it stays random." ;;
		esac
		echo "  Payload encryption is unaffected. Under imitation the packets present as ${PROTOCOL} rather than relying on header masking."
	fi
	printBoringtunImitationFillAdvisory "${PROTOCOL}" "${DOMAIN}"
}

# The trade-offs of auto, at the pinned release: BoringTun learns dns, quic, sip
# or stun for each authenticated peer from that client's own pre-handshake
# imitation datagrams, and keeps the configured S1-S4 and H1-H4. What a peer
# learned is not reported by BoringTun, so nothing here or in --backend-status
# claims it. The header-protection policy binds learned protocols as it binds
# fixed ones: an incompatible sip is not activated (that peer stays unresolved
# with random padding), and nothing is weakened or disabled automatically.
function printBoringtunAutoImitationWarnings() { # <AWG protocol version>
	local VERSION="$1"
	echo -e "${ORANGE}Protocol imitation: $(boringtunImitationDisplay auto "")${NC}"
	echo "- BoringTun selects dns, quic, sip or stun separately for each authenticated peer, from the imitation that peer's client sends before its handshake, so clients with different imitation settings can share this server and its port. The protocol a peer learned is kept for that peer and survives roaming."
	echo "- It needs recognizable client traffic: until a client's DNS, QUIC, SIP or STUN pre-handshake datagrams are recognized (a client without imitation sends none, and they can be lost), its peer is unresolved and gets random S padding, as with none."
	echo "- auto does not detect S1-S4, H1-H4 or any other AmneziaWG setting: clients still need this server's values. Client configs do not change."
	echo "- Probes: the listen port may answer DNS, QUIC and STUN probes as those imitations do; SIP probes get no reply. BoringTun does not report which protocol each peer learned, so neither does this installer."
	echo "  All probe replies share a budget of 16 KiB/s (BoringTun's default); loopback, link-local, multicast and broadcast sources are never answered."
	echo "- The listen port stays ${SERVER_PORT:-unchanged}: the installer never moves it, because a new port needs new client configs."
	if [[ "${VERSION}" == "${AWG_PROTOCOL_VERSION_3}" || "${VERSION}" == "${AWG_PROTOCOL_VERSION_31}" ]]; then
		echo -e "${ORANGE}- AmneziaWG $(awgProtocolDisplayName "${VERSION}"): header protection takes its nonce from the first 12 bytes of each S prefix, which a learned imitation shapes.${NC}"
		echo "  A learned dns leaves 16 random bits: nonces repeat within a few hundred datagrams, and each repeat repeats the header mask, so header masking is much weaker for that peer."
		echo "  A learned stun leaves 32 random bits: nonces start to repeat after about 77,000 datagrams, which weakens header masking on long-lived keys."
		echo "  A learned quic leaves the nonce random."
		if (($(boringtunLargestSPrefix) >= 31)); then
			echo "  A learned sip is not activated while any S prefix is 31 bytes or more (S1=${SERVER_AWG_S1:-} S2=${SERVER_AWG_S2:-} S3=${SERVER_AWG_S3:-} S4=${SERVER_AWG_S4:-}): that peer stays unresolved with random padding, and BoringTun logs the refusal."
		else
			echo "  A learned sip stays random while every S prefix is 30 bytes or less; at 31 or more BoringTun would not activate it and would leave that peer unresolved with random padding."
		fi
		echo "  Header protection is never weakened or disabled automatically, and the S and H framing stays as configured. Payload encryption is unaffected."
	fi
}

# Warn, without refusing, about S prefixes too short for the imitation to shape
# completely. The sizes are those of BoringTun's fillers at the pinned release:
# a DNS query needs 32 bytes (a root query) or the hostname's length plus 33
# (a query for it), a STUN header 20, a SIP request line 31 and a QUIC short
# header 1. They describe that release, not limits the installer enforces.
function printBoringtunImitationFillAdvisory() { # <protocol> <domain>
	local PROTOCOL="$1" DOMAIN="$2" NEED=0 NAMED=0 NAME SIZE SHORT="" UNNAMED="" SHORT_N=0 UNNAMED_N=0
	case "${PROTOCOL}" in
		dns)
			NEED=32
			[[ -z "${DOMAIN}" ]] || NAMED=$((${#DOMAIN} + 33))
			;;
		stun) NEED=20 ;;
		sip) NEED=31 ;;
		quic) NEED=1 ;;
		*) return 0 ;;
	esac
	for NAME in S1 S2 S3 S4; do
		SIZE="SERVER_AWG_${NAME}"
		SIZE="${!SIZE:-}"
		[[ "${SIZE}" =~ ^[0-9]{1,5}$ ]] || continue
		if ((10#${SIZE} < NEED)); then
			SHORT+="${SHORT:+, }${NAME}=${SIZE}"
			((SHORT_N += 1))
		elif ((10#${SIZE} < NAMED)); then
			UNNAMED+="${UNNAMED:+, }${NAME}=${SIZE}"
			((UNNAMED_N += 1))
		fi
	done
	if [[ -n "${SHORT}" ]]; then
		echo "- Note: ${SHORT} $( ((SHORT_N == 1)) && echo is || echo are) below the ${NEED} bytes ${PROTOCOL} imitation needs for a complete ${PROTOCOL^^} header; those prefixes are only partly shaped. This is advisory: the S sizes stay as they are."
	fi
	if [[ -n "${UNNAMED}" ]]; then
		echo "- Note: ${UNNAMED} $( ((UNNAMED_N == 1)) && echo is || echo are) below the ${NAMED} bytes a DNS query for ${DOMAIN} needs; those prefixes carry a root query instead. This is advisory: the S sizes stay as they are."
	fi
	return 0
}

# Emit only the protocol-specific [Interface] lines. Callers must redirect
# stdout into a mode-0600 configuration file because the output contains the
# shared HeaderProtectionKey in AWG 3.0/3.1 mode.
function renderAwgProtocolFields() {
	normalizeAwgProtocolVersion || return 1
	awgProtocolUsesHeaderProtection || return 0
	if awgProtocolUses31Fields; then
		validateAwg31Params || return 1
	else
		validateAwg3Params || return 1
	fi

	printf 'HeaderProtectionKey = %s\n' "${AWG_HEADER_PROTECTION_KEY}"
	[[ -z "${AWG_CONTENT_PADDING_ADDITION:-}" ]] || printf 'ContentPaddingAddition = %s\n' "${AWG_CONTENT_PADDING_ADDITION}"
	[[ -z "${AWG_REKEY_AFTER_TIME:-}" ]] || printf 'RekeyAfterTime = %s\n' "${AWG_REKEY_AFTER_TIME}"
	[[ -z "${AWG_REKEY_TIMEOUT:-}" ]] || printf 'RekeyTimeout = %s\n' "${AWG_REKEY_TIMEOUT}"
	[[ -z "${AWG_REJECT_AFTER_TIME:-}" ]] || printf 'RejectAfterTime = %s\n' "${AWG_REJECT_AFTER_TIME}"
	[[ -z "${AWG_KEEPALIVE_TIMEOUT:-}" ]] || printf 'KeepaliveTimeout = %s\n' "${AWG_KEEPALIVE_TIMEOUT}"
	if awgProtocolUses31Fields; then
		printf 'RandomTrailers = %s\n' "${AWG_RANDOM_TRAILERS}"
		printf 'DisableCookies = %s\n' "${AWG_DISABLE_COOKIES}"
	fi
}

# Failure text for capability probes and staged validation. Only the wording
# names the datapath; the probe configuration and readback comparisons are
# shared by every backend. The kernel strings are the historical ones verbatim.
function awgBackendValidationText() {
	if [[ "${AWG_BACKEND:-}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
		case "$1" in
			create) echo "could not start a temporary BoringTun interface (check the verified BoringTun store and /dev/net/tun)" ;;
			readback30) echo "the pinned BoringTun build did not read back AWG 3.0 fields unchanged" ;;
			readback31) echo "the pinned BoringTun build did not read back RandomTrailers/DisableCookies" ;;
			setconf30) echo "awg setconf rejected AWG 3.0 fields on the pinned BoringTun build (upgrade amneziawg-tools)" ;;
			setconf31) echo "awg setconf rejected RandomTrailers/DisableCookies on the pinned BoringTun build (upgrade amneziawg-tools)" ;;
			summary) echo "is not supported by both the installed awg tool and the pinned BoringTun build" ;;
			staged) echo "a staged protocol configuration was rejected by the installed tooling or the pinned BoringTun build" ;;
		esac
		return 0
	fi
	case "$1" in
		create) echo "could not create a temporary amneziawg interface (load the amneziawg kernel module for this kernel)" ;;
		readback30) echo "the running amneziawg kernel module did not read back AWG 3.0 fields unchanged (upgrade the loaded module to match amneziawg-tools)" ;;
		readback31) echo "the running amneziawg kernel module did not read back RandomTrailers/DisableCookies (upgrade both amneziawg-tools and the loaded kernel module to AWG 3.1)" ;;
		setconf30) echo "awg setconf rejected AWG 3.0 fields (upgrade amneziawg-tools and the running amneziawg kernel module together)" ;;
		setconf31) echo "awg setconf rejected RandomTrailers/DisableCookies (upgrade amneziawg-tools and the running amneziawg kernel module to AWG 3.1 together)" ;;
		summary) echo "is not supported by both the installed awg tool and the running kernel module" ;;
		staged) echo "a staged protocol configuration was rejected by the installed tooling or running module" ;;
	esac
}

# Exercise the complete userspace -> generic-netlink -> running-kernel path.
# Version strings are intentionally ignored: distributions can ship a new awg
# binary alongside an older loaded module (or the reverse). The probe succeeds
# only when every required protocol field can be applied and read back unchanged.
function probeAwgProtocolCapability() {
	local REQUIRE_31="${1:-0}"
	local PROBE_KEY="${2:-}"
	local PROBE_DIR PROBE_CONF PROBE_INTERFACE PROBE_EXTRA=""
	local READ_KEY READ_CONTENT READ_REKEY_AFTER READ_REKEY_TIMEOUT
	local READ_REJECT READ_KEEPALIVE READ_TRAILERS READ_COOKIES
	local RC=1 INTERFACE_CREATED=0
	local PROBE_LABEL="AWG 3.0"
	local FAIL_DETAIL=""

	(( REQUIRE_31 )) && PROBE_LABEL="AWG 3.1"

	if [[ -z "${PROBE_KEY}" ]]; then
		PROBE_KEY="$(awg genkey 2>/dev/null)" || PROBE_KEY=""
	fi
	if ! [[ "${PROBE_KEY}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
		echo "ERROR: the installed awg tool could not generate an ${PROBE_LABEL} probe key" >&2
		return 1
	fi
	if ! command -v ip >/dev/null 2>&1 || ! command -v awg >/dev/null 2>&1; then
		echo "ERROR: ${PROBE_LABEL} capability probing requires both ip and awg" >&2
		return 1
	fi

	PROBE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/awg3-probe.XXXXXX")" || {
		echo "ERROR: could not create the private ${PROBE_LABEL} probe directory" >&2
		return 1
	}
	chmod 700 "${PROBE_DIR}"
	PROBE_CONF="${PROBE_DIR}/probe.conf"
	PROBE_INTERFACE="awgp$((BASHPID % 100000000))"
	if (( REQUIRE_31 )); then
		PROBE_EXTRA="RandomTrailers = on
DisableCookies = on
"
	fi

	(
		umask 077
		cat >"${PROBE_CONF}" <<EOF
[Interface]
S1 = 12
S2 = 13
S3 = 14
S4 = 15
HeaderProtectionKey = ${PROBE_KEY}
ContentPaddingAddition = 11-13
RekeyAfterTime = 101-103
RekeyTimeout = 5-7
RejectAfterTime = 181-183
KeepaliveTimeout = 9-11
${PROBE_EXTRA}
EOF
	) || RC=1

	if [[ -s "${PROBE_CONF}" ]] && awgBackendCreateScratchInterface "${PROBE_INTERFACE}" >/dev/null 2>&1; then
		INTERFACE_CREATED=1
		if awg setconf "${PROBE_INTERFACE}" "${PROBE_CONF}" >/dev/null 2>&1; then
			READ_KEY="$(WG_HIDE_KEYS=never awg show "${PROBE_INTERFACE}" header-protection-key 2>/dev/null || true)"
			READ_CONTENT="$(awg show "${PROBE_INTERFACE}" content-padding-addition 2>/dev/null || true)"
			READ_REKEY_AFTER="$(awg show "${PROBE_INTERFACE}" rekey-after-time 2>/dev/null || true)"
			READ_REKEY_TIMEOUT="$(awg show "${PROBE_INTERFACE}" rekey-timeout 2>/dev/null || true)"
			READ_REJECT="$(awg show "${PROBE_INTERFACE}" reject-after-time 2>/dev/null || true)"
			READ_KEEPALIVE="$(awg show "${PROBE_INTERFACE}" keepalive-timeout 2>/dev/null || true)"
			if [[ "${READ_KEY}" == "${PROBE_KEY}" ]] && \
				[[ "${READ_CONTENT}" == "11-13" ]] && \
				[[ "${READ_REKEY_AFTER}" == "101-103" ]] && \
				[[ "${READ_REKEY_TIMEOUT}" == "5-7" ]] && \
				[[ "${READ_REJECT}" == "181-183" ]] && \
				[[ "${READ_KEEPALIVE}" == "9-11" ]]; then
				RC=0
			else
				FAIL_DETAIL="$(awgBackendValidationText readback30)"
			fi
			if (( REQUIRE_31 )) && (( RC == 0 )); then
				READ_TRAILERS="$(awg show "${PROBE_INTERFACE}" random-trailers 2>/dev/null || true)"
				READ_COOKIES="$(awg show "${PROBE_INTERFACE}" disable-cookies 2>/dev/null || true)"
				if [[ "${READ_TRAILERS}" != "on" ]] || [[ "${READ_COOKIES}" != "on" ]]; then
					RC=1
					FAIL_DETAIL="$(awgBackendValidationText readback31)"
				fi
			fi
		else
			if (( REQUIRE_31 )); then
				FAIL_DETAIL="$(awgBackendValidationText setconf31)"
			else
				FAIL_DETAIL="$(awgBackendValidationText setconf30)"
			fi
		fi
	else
		FAIL_DETAIL="$(awgBackendValidationText create)"
	fi

	if (( INTERFACE_CREATED )); then
		awgBackendDestroyScratchInterface "${PROBE_INTERFACE}" >/dev/null 2>&1 || RC=1
	fi
	rm -f -- "${PROBE_CONF}"
	rmdir -- "${PROBE_DIR}" 2>/dev/null || true

	if (( RC != 0 )); then
		echo "ERROR: ${PROBE_LABEL} $(awgBackendValidationText summary)" >&2
		if [[ -n "${FAIL_DETAIL}" ]]; then
			echo "       ${FAIL_DETAIL}" >&2
		else
			echo "       The temporary interface could not apply and read back every ${PROBE_LABEL} field." >&2
		fi
		echo "       Package version strings are ignored; only a live apply/readback probe is accepted." >&2
		return 1
	fi
	return 0
}

function probeAwg3Capability() {
	probeAwgProtocolCapability 0 "${1:-}"
}

function probeAwg31Capability() {
	probeAwgProtocolCapability 1 "${1:-}"
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

# Determine whether an IPv4 address is in a private / non-routable range.
# Returns 0 (true) for RFC1918, CGNAT (100.64/10), link-local (169.254/16),
# loopback (127/8) and the unspecified address; returns 1 otherwise.
# Inputs that aren't a dotted-quad IPv4 literal also return 1 (treated as
# "not known to be private") so callers can pass through hostnames or IPv6
# untouched.
function isPrivateIPv4() {
	local ADDR="${1:-}"
	# Must be a dotted-quad of 0-255 octets to evaluate; otherwise not-private.
	if ! [[ "${ADDR}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
		return 1
	fi

	# Force base-10 interpretation: the IPv4 regex above accepts leading
	# zeros (e.g. "08.0.0.1"), which would otherwise trigger bash octal
	# parsing and noisy "value too great for base" errors in (( ... )).
	local A B
	A=$((10#${ADDR%%.*}))
	B="${ADDR#*.}"
	B=$((10#${B%%.*}))

	# 10.0.0.0/8
	if (( A == 10 )); then return 0; fi
	# 127.0.0.0/8 (loopback)
	if (( A == 127 )); then return 0; fi
	# 172.16.0.0/12
	if (( A == 172 )) && (( B >= 16 && B <= 31 )); then return 0; fi
	# 192.168.0.0/16
	if (( A == 192 && B == 168 )); then return 0; fi
	# 100.64.0.0/10 (CGNAT - used by AWS, some ISPs, etc.)
	if (( A == 100 )) && (( B >= 64 && B <= 127 )); then return 0; fi
	# 169.254.0.0/16 (link-local, also AWS instance metadata)
	if (( A == 169 && B == 254 )); then return 0; fi
	# 0.0.0.0/8 — the script treats the entire "this network"/software block
	# (RFC 1122 §3.2.1.3) as non-public, not just the single unspecified
	# address 0.0.0.0, since none of these are routable on the public internet.
	if (( A == 0 )); then return 0; fi

	return 1
}

# Detect the server's public IPv4 address.
#
# Strategy:
#   1. Iterate all global-scope IPv4 addresses from `ip -4 addr` and pick
#      the first one that is not private/CGNAT/link-local. This handles
#      multi-homed hosts where a private interface is enumerated before a
#      public one, and avoids a needless external request when a public
#      IPv4 is already bound locally.
#   2. If no public IPv4 is found locally (empty list, or all addresses
#      are private — e.g. AWS EC2, GCP, LXC/Docker hosts), query an
#      external echo service over IPv4 (`curl -4 ifconfig.me`, with a
#      fallback) to discover the NAT-mapped public address. This is
#      required because cloud providers like AWS assign the public/Elastic
#      IP via 1:1 NAT and it never appears on the host's interfaces.
#   3. If external lookup fails or returns nothing usable, fall back to the
#      first locally-detected address (which may still be private but is
#      better than empty; the user can override interactively or via env).
#
# Privacy / opt-out:
#   Set AWG_SKIP_PUBLIC_IP_LOOKUP=y (or =1/=true) to disable the external
#   IP-echo step entirely. When disabled, the function only returns the
#   locally-detected address (or empty), avoiding any outbound HTTPS request
#   to third-party services. Useful for air-gapped installs or when the
#   operator wants to set SERVER_PUB_IP explicitly.
#
# Prints the detected address on stdout. Always returns 0; callers should
# check whether the output is empty.
function detectPublicIPv4() {
	local LOCAL_IP=""
	local FIRST_LOCAL_IP=""
	local CANDIDATE
	local PUBLIC_IP=""
	local URL

	# Collect all global-scope IPv4 addresses (multi-homed hosts may have
	# both a private and a public interface). Prefer the first public one
	# so we don't make an unnecessary external request — and don't
	# accidentally return the NAT-mapped egress IP when a directly-bound
	# public IPv4 already exists locally.
	while IFS= read -r CANDIDATE; do
		[[ -z "${CANDIDATE}" ]] && continue
		[[ -z "${FIRST_LOCAL_IP}" ]] && FIRST_LOCAL_IP="${CANDIDATE}"
		if ! isPrivateIPv4 "${CANDIDATE}"; then
			LOCAL_IP="${CANDIDATE}"
			break
		fi
	done < <(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p')

	# If we didn't find a public one, keep the first (private) address as a
	# fall-back so the function still returns something usable when the
	# external lookup fails or is opted out.
	if [[ -z "${LOCAL_IP}" ]]; then
		LOCAL_IP="${FIRST_LOCAL_IP}"
	fi

	# Honour an explicit opt-out so the installer never makes an unsolicited
	# request to a third-party IP-echo service. Accept y/yes/1/true (any case).
	local SKIP="${AWG_SKIP_PUBLIC_IP_LOOKUP:-}"
	SKIP="${SKIP,,}"
	if [[ "${SKIP}" == "y" || "${SKIP}" == "yes" || "${SKIP}" == "1" || "${SKIP}" == "true" ]]; then
		printf '%s\n' "${LOCAL_IP}"
		return 0
	fi

	if [[ -z "${LOCAL_IP}" ]] || isPrivateIPv4 "${LOCAL_IP}"; then
		if command -v curl >/dev/null 2>&1; then
			for URL in "https://ifconfig.me" "https://api.ipify.org" "https://ipv4.icanhazip.com"; do
				PUBLIC_IP="$(curl -4 -fsS --max-time 5 "${URL}" 2>/dev/null | tr -d '[:space:]')"
				if [[ "${PUBLIC_IP}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]] \
					&& ! isPrivateIPv4 "${PUBLIC_IP}"; then
					printf '%s\n' "${PUBLIC_IP}"
					return 0
				fi
				PUBLIC_IP=""
			done
		elif command -v wget >/dev/null 2>&1; then
			for URL in "https://ifconfig.me" "https://api.ipify.org" "https://ipv4.icanhazip.com"; do
				PUBLIC_IP="$(wget -4 -qO- --timeout=5 --tries=1 "${URL}" 2>/dev/null | tr -d '[:space:]')"
				if [[ "${PUBLIC_IP}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]] \
					&& ! isPrivateIPv4 "${PUBLIC_IP}"; then
					printf '%s\n' "${PUBLIC_IP}"
					return 0
				fi
				PUBLIC_IP=""
			done
		fi
	fi

	printf '%s\n' "${LOCAL_IP}"
	return 0
}

# Validate the configured unit path before asking systemd for its effective
# properties. A missing fragment is allowed because PID 1 may still have the
# loaded unit until the next daemon-reload.
function validateWebPanelSystemdUnitPath() {
	if [[ -L "${WEB_PANEL_SYSTEMD_UNIT}" ]]; then
		echo "ERROR: refusing unsafe web panel service unit '${WEB_PANEL_SYSTEMD_UNIT}'" >&2
		return 1
	fi
	if [[ -e "${WEB_PANEL_SYSTEMD_UNIT}" ]]; then
		if [[ ! -f "${WEB_PANEL_SYSTEMD_UNIT}" ]]; then
			echo "ERROR: refusing unsafe web panel service unit '${WEB_PANEL_SYSTEMD_UNIT}'" >&2
			return 1
		fi
	fi
	return 0
}

# Read a normalized property from PID 1. systemd has already merged the unit
# fragment and every drop-in, including list resets and filename precedence.
# Matching FragmentPath prevents a same-named host unit from affecting tests or
# callers that deliberately point WEB_PANEL_SYSTEMD_UNIT somewhere else.
function readWebPanelEffectiveProperty() {
	local property="$1"
	local unit_name load_state fragment_path
	validateWebPanelSystemdUnitPath || return 1
	command -v systemctl >/dev/null 2>&1 || return 1
	unit_name="$(basename -- "${WEB_PANEL_SYSTEMD_UNIT}")"
	load_state="$(systemctl show "${unit_name}" --property=LoadState --value 2>/dev/null)" || return 1
	[[ "${load_state}" == "loaded" ]] || return 1
	fragment_path="$(systemctl show "${unit_name}" --property=FragmentPath --value 2>/dev/null)" || return 1
	[[ "${fragment_path}" == "${WEB_PANEL_SYSTEMD_UNIT}" ]] || return 1

	case "${property}" in
		LoadState) printf '%s\n' "${load_state}" ;;
		FragmentPath) printf '%s\n' "${fragment_path}" ;;
		*) systemctl show "${unit_name}" --property="${property}" --value 2>/dev/null ;;
	esac
}

function validateWebPanelEnvFile() {
	local env_file="$1"
	local required="$2"
	local optional="$3"
	if [[ "${env_file}" != /* || "${env_file}" =~ [[:space:][:cntrl:]] ]]; then
		echo "ERROR: refusing unsafe web panel environment path '${env_file}'" >&2
		return 1
	fi

	if [[ -L "${env_file}" ]]; then
		echo "ERROR: refusing unsafe web panel environment file '${env_file}'" >&2
		return 1
	fi
	if [[ -e "${env_file}" ]]; then
		if [[ ! -f "${env_file}" ]]; then
			echo "ERROR: refusing unsafe web panel environment file '${env_file}'" >&2
			return 1
		fi
	elif [[ "${required}" -eq 1 && "${optional}" -eq 0 ]]; then
		echo "ERROR: web panel environment file '${env_file}' does not exist" >&2
		return 1
	fi
	return 0
}

# Print the ordered effective EnvironmentFile list as OPTIONAL<TAB>PATH. The
# systemctl representation is one normalized "path (ignore_errors=yes|no)"
# entry per line. The base-fragment parser remains as a compatibility fallback
# when PID 1 is unavailable (for example in installer unit tests).
function resolveWebPanelEnvFiles() {
	local effective_files configured_env env_file_metadata optional resolved_files="" index
	local -a env_file_fields=()
	validateWebPanelSystemdUnitPath || return 1
	if effective_files="$(readWebPanelEffectiveProperty EnvironmentFiles)"; then
		while IFS= read -r configured_env; do
			[[ -n "${configured_env}" ]] || continue
			read -r -a env_file_fields <<< "${configured_env}"
			if [[ "${#env_file_fields[@]}" -eq 0 ]] || (( ${#env_file_fields[@]} % 2 != 0 )); then
				echo "ERROR: unsupported systemd EnvironmentFiles value '${configured_env}'" >&2
				return 1
			fi
			for ((index = 0; index < ${#env_file_fields[@]}; index += 2)); do
				configured_env="${env_file_fields[index]}"
				env_file_metadata="${env_file_fields[index + 1]}"
				if [[ ! "${env_file_metadata}" =~ ^\(ignore_errors=(yes|no)\)$ ]]; then
					echo "ERROR: unsupported systemd EnvironmentFiles value '${configured_env} ${env_file_metadata}'" >&2
					return 1
				fi
				optional=0
				[[ "${BASH_REMATCH[1]}" == "yes" ]] && optional=1
				validateWebPanelEnvFile "${configured_env}" 1 "${optional}" || return 1
				printf '%s\t%s\n' "${optional}" "${configured_env}"
			done
		done <<< "${effective_files}"
		return 0
	fi

	if [[ -f "${WEB_PANEL_SYSTEMD_UNIT}" ]]; then
		while IFS= read -r configured_env; do
			optional=0
			if [[ "${configured_env}" == -* ]]; then
				optional=1
				configured_env="${configured_env#-}"
			fi
			configured_env="${configured_env#\"}"
			configured_env="${configured_env%\"}"
			configured_env="${configured_env#\'}"
			configured_env="${configured_env%\'}"
			if [[ -z "${configured_env}" ]]; then
				resolved_files=""
				continue
			fi
			validateWebPanelEnvFile "${configured_env}" 1 "${optional}" || return 1
			resolved_files+="${optional}"$'\t'"${configured_env}"$'\n'
		done < <(sed -n 's/^[[:space:]]*EnvironmentFile=//p' "${WEB_PANEL_SYSTEMD_UNIT}" 2>/dev/null)
		printf '%s' "${resolved_files}"
		return 0
	fi

	validateWebPanelEnvFile "${WEB_PANEL_ENV_FILE}" 0 1 || return 1
	if [[ -f "${WEB_PANEL_ENV_FILE}" ]]; then
		printf '1\t%s\n' "${WEB_PANEL_ENV_FILE}"
	fi
}

# Resolve the final web-panel environment file for legacy installed-panel
# detection. Settings themselves are read from every effective file below.
function resolveWebPanelEnvFile() {
	local entries optional configured_env env_file="${WEB_PANEL_ENV_FILE}"
	entries="$(resolveWebPanelEnvFiles)" || return 1
	while IFS=$'\t' read -r optional configured_env; do
		[[ -n "${configured_env}" ]] || continue
		env_file="${configured_env}"
	done <<< "${entries}"

	printf '%s\n' "${env_file}"
}

# Read one web-panel setting without evaluating shell syntax. EnvironmentFile
# values override inline Environment= values, matching systemd semantics.
function readWebPanelSetting() {
	local setting_name="$1"
	local effective_environment entries optional env_file inline_line inline_assignment value=""
	local -a inline_assignments=()
	if effective_environment="$(readWebPanelEffectiveProperty Environment)"; then
		while IFS= read -r inline_line; do
			read -r -a inline_assignments <<< "${inline_line}"
			for inline_assignment in "${inline_assignments[@]}"; do
				inline_assignment="${inline_assignment#\"}"
				inline_assignment="${inline_assignment%\"}"
				inline_assignment="${inline_assignment#\'}"
				inline_assignment="${inline_assignment%\'}"
				if [[ "${inline_assignment}" == "${setting_name}="* ]]; then
					value="${inline_assignment#*=}"
				fi
			done
		done <<< "${effective_environment}"
	else
		while IFS= read -r inline_assignment; do
			inline_assignment="${inline_assignment#\"}"
			inline_assignment="${inline_assignment%\"}"
			inline_assignment="${inline_assignment#\'}"
			inline_assignment="${inline_assignment%\'}"
			if [[ "${inline_assignment}" == "${setting_name}="* ]]; then
				value="${inline_assignment#*=}"
			fi
		done < <(sed -n 's/^[[:space:]]*Environment=//p' "${WEB_PANEL_SYSTEMD_UNIT}" 2>/dev/null)
	fi

	# EnvironmentFile values are applied after Environment= regardless of where
	# the directives occur, and later files override earlier files.
	entries="$(resolveWebPanelEnvFiles)" || return 1
	while IFS=$'\t' read -r optional env_file; do
		[[ -n "${env_file}" && -f "${env_file}" ]] || continue
		if grep -q "^[[:space:]]*${setting_name}=" "${env_file}" 2>/dev/null; then
			value="$(sed -n "s/^[[:space:]]*${setting_name}=//p" "${env_file}" 2>/dev/null | tail -n 1)"
		fi
	done <<< "${entries}"

	value="${value#\"}"
	value="${value%\"}"
	value="${value#\'}"
	value="${value%\'}"
	printf '%s\n' "${value}"
}

# Resolve the service working directory used for relative database paths.
function resolveWebPanelWorkingDirectory() {
	local working_dir=""
	if working_dir="$(readWebPanelEffectiveProperty WorkingDirectory)"; then
		working_dir="${working_dir:-/}"
	elif [[ -f "${WEB_PANEL_SYSTEMD_UNIT}" ]]; then
		working_dir="$(sed -n 's/^[[:space:]]*WorkingDirectory=//p' "${WEB_PANEL_SYSTEMD_UNIT}" 2>/dev/null | tail -n 1)"
		working_dir="${working_dir#-}"
		working_dir="${working_dir#\"}"
		working_dir="${working_dir%\"}"
		working_dir="${working_dir#\'}"
		working_dir="${working_dir%\'}"
		working_dir="${working_dir:-/}"
	else
		working_dir="${WEB_PANEL_DATA_DIR}"
	fi

	if [[ "${working_dir}" != /* || "${working_dir}" =~ [[:space:][:cntrl:]] ]]; then
		echo "ERROR: refusing unsafe web panel WorkingDirectory '${working_dir}'" >&2
		return 1
	fi
	if [[ "${working_dir}" != "/" ]]; then
		working_dir="${working_dir%/}"
	fi
	printf '%s\n' "${working_dir}"
}

# Print the effective ExecStart argv without evaluating unit-file shell syntax.
# PID 1 exposes the already-merged command as a normalized argv[] property. The
# base-fragment parser is only a compatibility fallback when systemd is absent.
function resolveWebPanelExecStartArgv() {
	local effective_exec line argv resolved_argv="" exec_count=0
	if effective_exec="$(readWebPanelEffectiveProperty ExecStart)"; then
		while IFS= read -r line; do
			[[ -n "${line}" ]] || continue
			if [[ "${line}" != *" argv[]="*" ; ignore_errors="* ]]; then
				echo "ERROR: unsupported systemd ExecStart value '${line}'" >&2
				return 2
			fi
			argv="${line#* argv[]=}"
			argv="${argv%% ; ignore_errors=*}"
			[[ -n "${argv}" ]] || continue
			resolved_argv="${argv}"
			exec_count=$((exec_count + 1))
		done <<< "${effective_exec}"
	elif [[ -f "${WEB_PANEL_SYSTEMD_UNIT}" ]]; then
		while IFS= read -r line; do
			if [[ -z "${line}" ]]; then
				resolved_argv=""
				exec_count=0
				continue
			fi
			resolved_argv="${line}"
			exec_count=$((exec_count + 1))
		done < <(sed -n 's/^[[:space:]]*ExecStart=//p' "${WEB_PANEL_SYSTEMD_UNIT}" 2>/dev/null)
	else
		return 1
	fi

	if [[ "${exec_count}" -eq 0 ]]; then
		return 1
	fi
	if [[ "${exec_count}" -ne 1 ]]; then
		echo "ERROR: expected one effective ExecStart for '${WEB_PANEL_SYSTEMD_UNIT}'" >&2
		return 2
	fi
	printf '%s\n' "${resolved_argv}"
}

# Read one long-option value from the effective ExecStart. Every argument after
# argv[0] must be an option/value pair; this deliberately fails closed if the
# text representation is ambiguous (for example, an argument containing spaces).
function readWebPanelExecStartSetting() {
	local requested_option="$1"
	local exec_argv token option_name option_value value="" found=0 index=1
	local -a exec_args=()
	exec_argv="$(resolveWebPanelExecStartArgv)" || return $?
	read -r -a exec_args <<< "${exec_argv}"
	[[ "${#exec_args[@]}" -gt 0 ]] || return 1

	while [[ "${index}" -lt "${#exec_args[@]}" ]]; do
		token="${exec_args[index]}"
		token="${token#\"}"
		token="${token%\"}"
		token="${token#\'}"
		token="${token%\'}"
		if [[ "${token}" != --* ]]; then
			echo "ERROR: unsupported positional argument in web panel ExecStart" >&2
			return 2
		fi

		case "${token%%=*}" in
			--auth-enabled|--auth-secure-cookie)
				if [[ "${token}" == *=* ]]; then
					echo "ERROR: unsupported value for boolean option '${token%%=*}' in web panel ExecStart" >&2
					return 2
				fi
				index=$((index + 1))
				continue
				;;
			--listen|--database-url|--config-dir|--poll-interval|--proxy-sessions-file|\
			--auth-username|--auth-password-hash|--auth-api-token|--auth-session-ttl-secs)
				;;
			*)
				echo "ERROR: unsupported option '${token%%=*}' in web panel ExecStart" >&2
				return 2
				;;
		esac

		if [[ "${token}" == *=* ]]; then
			option_name="${token%%=*}"
			option_value="${token#*=}"
			index=$((index + 1))
		else
			option_name="${token}"
			index=$((index + 1))
			if [[ "${index}" -ge "${#exec_args[@]}" || "${exec_args[index]}" == --* ]]; then
				echo "ERROR: missing value for '${option_name}' in web panel ExecStart" >&2
				return 2
			fi
			option_value="${exec_args[index]}"
			option_value="${option_value#\"}"
			option_value="${option_value%\"}"
			option_value="${option_value#\'}"
			option_value="${option_value%\'}"
			index=$((index + 1))
		fi

		if [[ "${option_name}" == "${requested_option}" ]]; then
			value="${option_value}"
			found=1
		fi
	done

	[[ "${found}" -eq 1 ]] || return 1
	if [[ "${value}" == *'$'* || "${value}" == *'%'* ]]; then
		echo "ERROR: unsupported variable or specifier in ${requested_option} ExecStart value" >&2
		return 2
	fi
	printf '%s\n' "${value}"
}

# Resolve the web panel's active config directory without sourcing its env file.
# Command-line arguments take precedence over environment values, as in Clap.
function resolveWebPanelConfigDir() {
	local configured_dir exec_config_dir exec_setting_rc
	configured_dir="$(readWebPanelSetting AWG_CONFIG_DIR)" || return 1
	if exec_config_dir="$(readWebPanelExecStartSetting --config-dir)"; then
		configured_dir="${exec_config_dir}"
	else
		exec_setting_rc=$?
		[[ "${exec_setting_rc}" -eq 1 ]] || return "${exec_setting_rc}"
	fi

	if [[ -n "${configured_dir}" ]]; then
		if [[ "${configured_dir}" != /* || "${configured_dir}" =~ [[:space:][:cntrl:]] ]]; then
			echo "ERROR: refusing unsafe AWG_CONFIG_DIR '${configured_dir}'" >&2
			return 1
		fi
		printf '%s\n' "${configured_dir%/}"
		return 0
	fi

	printf '%s\n' "${WEB_PANEL_CONFIG_DIR%/}"
}

# Check if the web panel is installed (via environment file, systemd unit, or active service state).
function isWebPanelInstalled() {
	local env_file
	env_file="$(resolveWebPanelEnvFile 2>/dev/null || true)"
	if [[ (-n "${env_file}" && -f "${env_file}") || -e "${WEB_PANEL_SYSTEMD_UNIT}" ]] || \
		readWebPanelEffectiveProperty LoadState >/dev/null 2>&1; then
		return 0
	fi
	return 1
}

# Use the web database directory as the stable cross-process lifecycle lock.
# Unlike AWG_CONFIG_DIR it exists for the panel's lifetime, including when no
# client has been created yet. Standalone installer use (no panel env file)
# retains the config-directory fallback.
function resolveClientLifecycleLockDir() {
	local env_file database_path exec_database_path exec_setting_rc working_dir database_parent
	env_file="$(resolveWebPanelEnvFile)" || return 1

	if ! isWebPanelInstalled; then
		resolveWebPanelConfigDir
		return
	fi

	database_path="$(readWebPanelSetting AWG_WEB_DB)" || return 1
	database_path="${database_path:-awg-web.db}"
	if exec_database_path="$(readWebPanelExecStartSetting --database-url)"; then
		database_path="${exec_database_path}"
	else
		exec_setting_rc=$?
		[[ "${exec_setting_rc}" -eq 1 ]] || return "${exec_setting_rc}"
	fi
	if [[ "${database_path}" =~ [[:space:][:cntrl:]] ]]; then
		echo "ERROR: refusing unsafe AWG_WEB_DB '${database_path}'" >&2
		return 1
	fi
	case "${database_path}" in
		sqlite://*) database_path="${database_path#sqlite://}" ;;
		sqlite:*) database_path="${database_path#sqlite:}" ;;
	esac
	database_path="${database_path%%\?*}"
	working_dir="$(resolveWebPanelWorkingDirectory)" || return 1

	if [[ -z "${database_path}" || "${database_path}" == ":memory:" ]]; then
		printf '%s\n' "${working_dir}"
		return 0
	fi
	database_parent="$(dirname -- "${database_path}")"
	if [[ "${database_path}" == /* ]]; then
		if [[ "${database_parent}" != "/" ]]; then
			database_parent="${database_parent%/}"
		fi
		printf '%s\n' "${database_parent}"
	elif [[ "${database_parent}" == "." ]]; then
		printf '%s\n' "${working_dir}"
	else
		printf '%s/%s\n' "${working_dir%/}" "${database_parent}"
	fi
}

# Copy a client config file to the web panel config directory so the panel
# can discover and display it.  This is a best-effort operation: if the web
# panel is not installed (directory absent), the copy is silently skipped.
function copyToWebPanelDir() {
	local src_file="$1"
	local panel_config_dir
	panel_config_dir="$(resolveWebPanelConfigDir)" || return 0
	if [[ -d "${panel_config_dir}" && ! -L "${panel_config_dir}" && -f "${src_file}" && ! -L "${src_file}" ]]; then
		local dest
		dest="${panel_config_dir}/$(basename "${src_file}")"
		# Avoid following or overwriting a pre-existing symlink at the destination.
		if [[ -L "${dest}" ]]; then
			# Best-effort: warn and skip rather than risk clobbering the symlink target.
			echo "Warning: refusing to copy '${src_file}' to '${dest}' because destination is a symlink" >&2
			return 0
		fi
		local src_real dest_real
		src_real="$(readlink -f -- "${src_file}" 2>/dev/null || true)"
		dest_real="$(readlink -f -- "${dest}" 2>/dev/null || true)"
		if [[ -z "${dest_real}" || "${src_real}" != "${dest_real}" ]]; then
			cp -f "${src_file}" "${dest}" 2>/dev/null || true
		fi
		# Only adjust ownership and permissions on a regular non-symlink file we just copied.
		if [[ -f "${dest}" && ! -L "${dest}" ]]; then
			# Determine the directory's group; use it if available, otherwise fall back to root.
			local dir_group dest_group
			dir_group="$(stat -c '%G' "${panel_config_dir}" 2>/dev/null || true)"
			if [[ -n "${dir_group}" ]]; then
				dest_group="${dir_group}"
			else
				dest_group="root"
			fi
			# Enforce root ownership and the chosen group before tightening permissions.
			chown "root:${dest_group}" "${dest}" 2>/dev/null || true
			chmod 640 "${dest}" 2>/dev/null || true
		fi
	fi
}

# Remove a client config file from the web panel config directory.
function removeFromWebPanelDir() {
	local filename="$1"
	local panel_config_dir
	panel_config_dir="$(resolveWebPanelConfigDir)" || return 0
	if [[ -d "${panel_config_dir}" && ! -L "${panel_config_dir}" ]]; then
		rm -f -- "${panel_config_dir}/${filename}" 2>/dev/null || true
	fi
}

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
	# Only supported backends are persisted; unset means the kernel backend.
	case "${AWG_BACKEND:-}" in
		""|"${AWG_BACKEND_KERNEL}"|"${AWG_BACKEND_BORINGTUN}") ;;
		*)
			reportUnsupportedAwgBackend "${AWG_BACKEND}"
			return 1
			;;
	esac
	checkBoringtunImitationForBackend || return 1
	# Apply a restrictive umask only while writing the params file to disk,
	# so that subprocesses (apt/dnf, dkms, etc.) are not affected.
	# Every write's status is kept: a write that fails part-way, or a file
	# that cannot be opened, makes the function fail even though the umask is
	# restored after it.
	local OLD_UMASK RC=0
	OLD_UMASK="$(umask)"
	umask 077
	cat >"${OUTPUT_FILE}" <<EOF || RC=1
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
ENABLE_IPV6=$(safeQuoteParam "${ENABLE_IPV6:-}")
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
AWG_BACKEND=$(safeQuoteParam "${AWG_BACKEND:-${AWG_BACKEND_KERNEL}}")
AWG_PROTOCOL_VERSION=$(safeQuoteParam "${AWG_PROTOCOL_VERSION:-${AWG_PROTOCOL_VERSION_2}}")
AWG_HEADER_PROTECTION_KEY=$(safeQuoteParam "${AWG_HEADER_PROTECTION_KEY:-}")
AWG_CONTENT_PADDING_ADDITION=$(safeQuoteParam "${AWG_CONTENT_PADDING_ADDITION:-}")
AWG_REKEY_AFTER_TIME=$(safeQuoteParam "${AWG_REKEY_AFTER_TIME:-}")
AWG_REKEY_TIMEOUT=$(safeQuoteParam "${AWG_REKEY_TIMEOUT:-}")
AWG_REJECT_AFTER_TIME=$(safeQuoteParam "${AWG_REJECT_AFTER_TIME:-}")
AWG_KEEPALIVE_TIMEOUT=$(safeQuoteParam "${AWG_KEEPALIVE_TIMEOUT:-}")
AWG_RANDOM_TRAILERS=$(safeQuoteParam "${AWG_RANDOM_TRAILERS:-}")
AWG_DISABLE_COOKIES=$(safeQuoteParam "${AWG_DISABLE_COOKIES:-}")
EOF
	# Only BoringTun installations persist the protocol imitation, so kernel
	# params keep exactly the keys they had before imitation existed.
	if ((RC == 0)) && [[ "${AWG_BACKEND:-}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
		cat >>"${OUTPUT_FILE}" <<EOF || RC=1
AWG_BORINGTUN_IMITATE_PROTOCOL=$(safeQuoteParam "${AWG_BORINGTUN_IMITATE_PROTOCOL:-${AWG_BT_IMITATE_NONE}}")
AWG_BORINGTUN_IMITATE_DOMAIN=$(safeQuoteParam "${AWG_BORINGTUN_IMITATE_DOMAIN:-}")
EOF
	fi
	umask "${OLD_UMASK}"
	return "${RC}"
}

# The keys serializeParams writes, in its order: AWG_PARAMS_KEYS for every
# backend, then AWG_PARAMS_BORINGTUN_KEYS for BoringTun. A test keeps this list
# equal to what serializeParams writes.
AWG_PARAMS_KEYS="SERVER_PUB_IP SERVER_PUB_NIC SERVER_AWG_NIC SERVER_AWG_IPV4 SERVER_AWG_IPV6 SERVER_PORT SERVER_PRIV_KEY SERVER_PUB_KEY CLIENT_DNS_1 CLIENT_DNS_2 ALLOWED_IPS ENABLE_IPV6 SERVER_AWG_JC SERVER_AWG_JMIN SERVER_AWG_JMAX SERVER_AWG_S1 SERVER_AWG_S2 SERVER_AWG_S3 SERVER_AWG_S4 SERVER_AWG_H1 SERVER_AWG_H2 SERVER_AWG_H3 SERVER_AWG_H4 AWG_BACKEND AWG_PROTOCOL_VERSION AWG_HEADER_PROTECTION_KEY AWG_CONTENT_PADDING_ADDITION AWG_REKEY_AFTER_TIME AWG_REKEY_TIMEOUT AWG_REJECT_AFTER_TIME AWG_KEEPALIVE_TIMEOUT AWG_RANDOM_TRAILERS AWG_DISABLE_COOKIES"
AWG_PARAMS_BORINGTUN_KEYS="AWG_BORINGTUN_IMITATE_PROTOCOL AWG_BORINGTUN_IMITATE_DOMAIN"

function awgParamsCanonicalKeys() { # <backend>
	local KEYS="${AWG_PARAMS_KEYS}"
	[[ "${1:-}" != "${AWG_BACKEND_BORINGTUN}" ]] || KEYS+=" ${AWG_PARAMS_BORINGTUN_KEYS}"
	# shellcheck disable=SC2086 # the key lists are fixed words
	printf '%s\n' ${KEYS}
}

# Whether FILE, as serializeParams writes it, has exactly BACKEND's canonical
# key lines, each once and in order, and no other line: a truncated file, a
# missing or repeated key, an unexpected assignment and a value broken across
# lines all fail.
function awgParamsFileHasCanonicalKeys() { # <file> <backend>
	local LINE KEYS=""
	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		[[ "${LINE}" =~ ^([A-Z][A-Z0-9_]*)= ]] || return 1
		KEYS+="${BASH_REMATCH[1]} "
	done <"$1" || return 1
	[[ "${KEYS}" == "$(awgParamsCanonicalKeys "$2" | tr '\n' ' ')" ]]
}

# A digest of the persisted state in this shell: every key of AWG_PARAMS_KEYS
# with its value, or as unset. It compares two states without printing a value.
function awgParamsStateDigest() {
	local KEY
	for KEY in ${AWG_PARAMS_KEYS}; do
		printf '%s:%s=%s\n' "${KEY}" "${!KEY+set}" "${!KEY-}"
	done | sha256sum | cut -d' ' -f1
}

# Read a staged params file in isolation, as the next loadParams will. Every
# canonical variable is unset first, so a line the file lacks can never be
# filled in from this shell. The file must set every canonical key of its
# backend, and must then pass validateParamsFile (with it as the params of a
# private directory next to the live server config), which validates the
# backend, its imitation and the AWG protocol state. Prints
# "<state digest>|<imitation protocol>|<imitation hostname>". The file is
# installer-generated and private.
function readStagedParamsInIsolation() ( # <staged file> <private check directory>
	local STAGED="$1" CHECK_DIR="$2" KEY CONFIG="${SERVER_AWG_CONF}" INTERFACE="${SERVER_AWG_NIC}"
	# shellcheck disable=SC2086 # the key lists are fixed words
	unset ${AWG_PARAMS_KEYS} ${AWG_PARAMS_BORINGTUN_KEYS}
	# shellcheck source=/dev/null
	if ! source "${STAGED}"; then
		echo "ERROR: the staged params cannot be read." >&2
		return 1
	fi
	for KEY in $(awgParamsCanonicalKeys "${AWG_BACKEND:-}"); do
		if [[ -z "${!KEY+set}" ]]; then
			echo "ERROR: the staged params do not set ${KEY}." >&2
			return 1
		fi
	done
	if ! mkdir -m 0700 -- "${CHECK_DIR}" || ! cp -p -- "${STAGED}" "${CHECK_DIR}/params" ||
		! ln -s -- "${CONFIG}" "${CHECK_DIR}/${INTERFACE}.conf"; then
		echo "ERROR: cannot prepare the check of the staged params." >&2
		return 1
	fi
	AMNEZIAWG_DIR="${CHECK_DIR}"
	if ! validateParamsFile 0 >/dev/null || ! normalizeAwgProtocolVersion >/dev/null; then
		echo "ERROR: the staged params would not load." >&2
		return 1
	fi
	printf '%s|%s|%s\n' "$(awgParamsStateDigest)" "${AWG_BORINGTUN_IMITATE_PROTOCOL:-}" "${AWG_BORINGTUN_IMITATE_DOMAIN:-}"
)

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

# Compress a fully expanded IPv6 address to its canonical compressed form (RFC 5952)
# Replaces the longest run of consecutive zero groups (>= 2) with ::
# Input should be the output of normalizeIPv6() (8 lowercase groups, no leading zeros)
# e.g., fd42:42:42:0:0:0:0:2 -> fd42:42:42::2
function compressIPv6() {
	local ADDR="$1"
	local -a IPV6_PARTS
	IFS=':' read -ra IPV6_PARTS <<< "${ADDR}"

	# Find the longest consecutive run of '0' groups (leftmost if tied)
	local BEST_START=-1
	local BEST_LEN=0
	local CUR_START=-1
	local CUR_LEN=0
	local i

	for (( i = 0; i < 8; i++ )); do
		if [[ "${IPV6_PARTS[$i]}" == "0" ]]; then
			if (( CUR_START == -1 )); then
				CUR_START=$i
				CUR_LEN=1
			else
				(( CUR_LEN++ ))
			fi
			if (( CUR_LEN > BEST_LEN )); then
				BEST_START=$CUR_START
				BEST_LEN=$CUR_LEN
			fi
		else
			CUR_START=-1
			CUR_LEN=0
		fi
	done

	# Per RFC 5952, only compress runs of 2 or more consecutive zero groups
	if (( BEST_LEN < 2 )); then
		local IFS=':'
		echo "${IPV6_PARTS[*]}"
		return
	fi

	# Build the compressed address
	local IFS=':'
	local LEFT_PARTS=("${IPV6_PARTS[@]:0:$BEST_START}")
	local RIGHT_PARTS=("${IPV6_PARTS[@]:$((BEST_START + BEST_LEN))}")
	local LEFT="${LEFT_PARTS[*]}"
	local RIGHT="${RIGHT_PARTS[*]}"

	echo "${LEFT}::${RIGHT}"
}

# Optional self-tests for compressIPv6. These are only run when the installer
# is executed directly with AMNEZIAWG_RUN_IPV6_TESTS=1 in the environment.
# They are intended to guard against regressions in the RFC 5952 logic.
function __compressIPv6_expect() {
	local EXPECTED="$1"
	local INPUT="$2"
	local ACTUAL

	ACTUAL="$(compressIPv6 "${INPUT}")"
	if [[ "${ACTUAL}" != "${EXPECTED}" ]]; then
		echo "compressIPv6 test failed: input='${INPUT}' expected='${EXPECTED}' got='${ACTUAL}'" >&2
		return 1
	fi

	return 0
}

function run_compressIPv6_tests() {
	local FAIL=0

	# Addresses that should NOT compress (no run of >= 2 zero groups)
	__compressIPv6_expect "2001:db8:0:1:2:3:4:5" "2001:db8:0:1:2:3:4:5" || FAIL=1
	__compressIPv6_expect "2001:db8:0:1:2:3:4:0" "2001:db8:0:1:2:3:4:0" || FAIL=1

	# Simple middle run
	__compressIPv6_expect "2001:db8::1:0:0:1" "2001:db8:0:0:1:0:0:1" || FAIL=1

	# Leading zero run
	__compressIPv6_expect "::1:2:3:4:5" "0:0:0:1:2:3:4:5" || FAIL=1

	# Trailing zero run
	__compressIPv6_expect "2001:db8:1:2:3:4::" "2001:db8:1:2:3:4:0:0" || FAIL=1

	# All zeros
	__compressIPv6_expect "::" "0:0:0:0:0:0:0:0" || FAIL=1

	# Longest run chosen over shorter one
	__compressIPv6_expect "2001::1:0:0:1" "2001:0:0:0:1:0:0:1" || FAIL=1

	# Tie case: leftmost longest run wins
	# Two runs of length 2: positions 1–2 and 4–5
	# Input: 2001:0:0:1:0:0:1:1 -> expected: 2001::1:0:0:1:1
	__compressIPv6_expect "2001::1:0:0:1:1" "2001:0:0:1:0:0:1:1" || FAIL=1

	if (( FAIL != 0 )); then
		echo "compressIPv6 self-tests: FAILED" >&2
		return 1
	fi

	echo "compressIPv6 self-tests: OK"
	return 0
}

# Only run self-tests when this script is executed directly and explicitly requested.
if [[ "${BASH_SOURCE[0]}" == "${0}" && "${AMNEZIAWG_RUN_IPV6_TESTS:-0}" == "1" ]]; then
	if run_compressIPv6_tests; then
		exit 0
	else
		exit 1
	fi
fi

function isRoot() {
	if [[ "${EUID}" -ne 0 ]]; then
		echo "You need to run this script as root" >&2
		exit 1
	fi
}

function checkVirt() {
	if ! command -v systemd-detect-virt &>/dev/null; then
		return
	fi

	if [[ "$(systemd-detect-virt)" == "openvz" ]]; then
		echo "OpenVZ is not supported" >&2
		exit 1
	fi

	if [[ "$(systemd-detect-virt)" == "lxc" ]]; then
		echo "LXC is not supported (yet)." >&2
		echo "WireGuard can technically run in an LXC container," >&2
		echo "but the kernel module has to be installed on the host," >&2
		echo "the container has to be run with some specific parameters" >&2
		echo "and only the tools need to be installed in the container." >&2
		exit 1
	fi
}

function checkOS() {
	if [[ ! -f /etc/os-release ]] || [[ ! -r /etc/os-release ]]; then
		echo "Cannot detect OS: /etc/os-release is missing or not readable" >&2
		exit 1
	fi
	# shellcheck source=/etc/os-release
	source /etc/os-release
	OS="${ID}"
	if [[ -z "${OS}" ]]; then
		echo "Cannot detect OS: /etc/os-release is missing the ID field" >&2
		exit 1
	fi
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Debian version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		# Extract major version to handle point-release formats (e.g., "11.7")
		local DEBIAN_MAJOR
		DEBIAN_MAJOR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${DEBIAN_MAJOR} =~ ^[0-9]+$ ]] || [[ ${DEBIAN_MAJOR} -lt 11 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later" >&2
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Ubuntu version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		local RELEASE_YEAR
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${RELEASE_YEAR} =~ ^[0-9]+$ ]] || [[ ${RELEASE_YEAR} -lt 22 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 22.04 or later" >&2
			exit 1
		fi
	elif [[ ${OS} == "linuxmint" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Linux Mint version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		# Linux Mint 21.x is based on Ubuntu 22.04; require major version >= 21
		local MINT_MAJOR
		MINT_MAJOR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${MINT_MAJOR} =~ ^[0-9]+$ ]] || [[ ${MINT_MAJOR} -lt 21 ]]; then
			echo "Your version of Linux Mint (${VERSION_ID}) is not supported. Please use Linux Mint 21 or later" >&2
			exit 1
		fi
		OS=ubuntu # treat Linux Mint as Ubuntu for package management
	elif [[ ${OS} == "fedora" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Fedora version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		# Extract major version to handle potential future format changes
		local FEDORA_MAJOR
		FEDORA_MAJOR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${FEDORA_MAJOR} =~ ^[0-9]+$ ]] || [[ ${FEDORA_MAJOR} -lt 39 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 39 or later" >&2
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect CentOS/AlmaLinux/Rocky version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		if [[ ${VERSION_ID} == 7* ]] || [[ ${VERSION_ID} == 8* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 9 or later" >&2
			exit 1
		fi
	else
		echo "Looks like you aren't running this installer on a supported system (Debian, Ubuntu, Linux Mint, or CentOS)." >&2
		exit 1
	fi
}

function getTemporarilyDisabledRPMFamilyMessage() {
	echo "Fedora, AlmaLinux, and Rocky Linux support is temporarily disabled because verified AmneziaWG 2.0 packages are not currently available for these RPM-based distributions. Please watch this repository's releases and README for support status updates."
}

function ensureSupportedInstallDistro() {
	# Temporary install block for RPM-family rebuild verification status.
	# Keep OS detection intact so existing installs on these distros can still
	# run non-install operations until AWG 2.0 packages are verified.
	if [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		echo "$(getTemporarilyDisabledRPMFamilyMessage)" >&2
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

# Strip the deprecated REMAKE_INITRD directive from the amneziawg DKMS config
# (newer DKMS versions print noisy warnings for it).
function sanitizeAwgDkmsConf() {
	local AWG_DKMS_CONF
	for AWG_DKMS_CONF in /var/lib/dkms/amneziawg/*/source/dkms.conf; do
		[[ -f "${AWG_DKMS_CONF}" ]] && sed -i '/^REMAKE_INITRD=/d' "${AWG_DKMS_CONF}"
	done
}

function aptPackageIsInstalled() {
	dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'
}

function ubuntuKernelTrackMatchesFlavor() {
	local TRACK="$1"
	local FLAVOR="$2"

	[[ "${TRACK}" == "${FLAVOR}" ]] || \
		[[ "${TRACK}" =~ ^${FLAVOR}-(edge|(hwe|lts)-[0-9]{2}\.[0-9]{2}(-edge)?|[0-9]+\.[0-9]+)$ ]]
}

# A header track may be represented by its header meta-package, its image-only
# meta-package, or the complete image+headers meta-package. Treat any of those
# as evidence that this is the administrator-selected kernel track.
function kernelHeaderTrackIsInstalled() {
	local HEADER_META_PKG="$1"
	local TRACK="${HEADER_META_PKG#linux-headers-}"
	local VIRTUAL_TRACK

	[[ "${HEADER_META_PKG}" =~ ^linux-headers-[a-z0-9][a-z0-9.+-]*$ ]] || return 1
	if aptPackageIsInstalled "${HEADER_META_PKG}" || \
			aptPackageIsInstalled "linux-image-${TRACK}" || \
			aptPackageIsInstalled "linux-${TRACK}"; then
		return 0
	fi

	# Ubuntu virtual kernels use the generic ABI suffix. Treat their image/full
	# meta-packages as evidence for the corresponding generic header track.
	if [[ "${OS:-}" == 'ubuntu' ]] && ubuntuKernelTrackMatchesFlavor "${TRACK}" 'generic'; then
		VIRTUAL_TRACK="virtual${TRACK#generic}"
		aptPackageIsInstalled "linux-image-${VIRTUAL_TRACK}" || \
			aptPackageIsInstalled "linux-${VIRTUAL_TRACK}"
	else
		return 1
	fi
}

# Ask APT which header meta-package depends on the exact running-kernel
# package. This correctly distinguishes Ubuntu GA/HWE/cloud families and
# Debian flavors without guessing from architecture alone.
function getAptKernelHeaderMetaPackage() {
	local CURRENT_HEADER_PKG="linux-headers-${1:-$(uname -r)}"
	local RDEPEND
	local EXISTING
	local SEEN
	local -a CANDIDATES=()
	local -a INSTALLED_CANDIDATES=()

	command -v apt-cache &>/dev/null || return 1
	while read -r RDEPEND; do
		RDEPEND="${RDEPEND#|}"
		if [[ "${RDEPEND}" != "${CURRENT_HEADER_PKG}" ]] && \
				[[ "${RDEPEND}" =~ ^linux-headers-[a-z0-9][a-z0-9.+-]*$ ]]; then
			SEEN=0
			for EXISTING in "${CANDIDATES[@]}"; do
				if [[ "${EXISTING}" == "${RDEPEND}" ]]; then
					SEEN=1
					break
				fi
			done
			[[ "${SEEN}" -eq 1 ]] || CANDIDATES+=("${RDEPEND}")
		fi
	done < <(apt-cache rdepends "${CURRENT_HEADER_PKG}" 2>/dev/null)

	[[ "${#CANDIDATES[@]}" -gt 0 ]] || return 1

	# Preserve an already selected kernel family when more than one meta-package
	# points at the same ABI (for example normal and edge HWE tracks). The image
	# meta is important when headers have not been installed yet.
	for RDEPEND in "${CANDIDATES[@]}"; do
		if kernelHeaderTrackIsInstalled "${RDEPEND}"; then
			INSTALLED_CANDIDATES+=("${RDEPEND}")
		fi
	done
	if [[ "${#INSTALLED_CANDIDATES[@]}" -gt 0 ]]; then
		[[ "${#INSTALLED_CANDIDATES[@]}" -eq 1 ]] || return 1
		printf '%s\n' "${INSTALLED_CANDIDATES[0]}"
		return 0
	fi

	# Without installed evidence, select a unique candidate. Preserve the old
	# stable preference only for the exact pair {X, X-edge}; any other set may
	# span different kernel families and must not depend on apt-cache ordering.
	if [[ "${#CANDIDATES[@]}" -eq 1 ]]; then
		printf '%s\n' "${CANDIDATES[0]}"
		return 0
	fi
	if [[ "${#CANDIDATES[@]}" -eq 2 ]]; then
		if [[ "${CANDIDATES[0]}" != *-edge ]] && \
				[[ "${CANDIDATES[1]}" == "${CANDIDATES[0]}-edge" ]]; then
			printf '%s\n' "${CANDIDATES[0]}"
			return 0
		fi
		if [[ "${CANDIDATES[1]}" != *-edge ]] && \
				[[ "${CANDIDATES[0]}" == "${CANDIDATES[1]}-edge" ]]; then
			printf '%s\n' "${CANDIDATES[1]}"
			return 0
		fi
	fi
	return 1
}

# Derive an Ubuntu header meta-package from an installed image meta-package.
# Complete kernel meta-packages depend on their corresponding image metas, so
# image metas cover both installation styles without matching ABI-specific
# support packages. This remains reliable when apt-cache no longer exposes a
# reverse dependency for the currently running (older) ABI after an index
# refresh. Ambiguous multiple tracks are rejected rather than guessed.
function getInstalledUbuntuKernelHeaderMetaPackage() {
	local KERNEL_VER="${1:-$(uname -r)}"
	local FLAVOR
	local PACKAGE
	local STATUS
	local TRACK
	local HEADER_META
	local EXISTING
	local MATCHED
	local SEEN
	local -a FLAVORS=()
	local -a IMAGE_META_PATTERNS=()
	local -a CANDIDATES=()

	case "${KERNEL_VER}" in
		*-generic-64k) FLAVORS=("generic-64k") ;;
		*-generic) FLAVORS=("generic" "virtual") ;;
		*-lowlatency) FLAVORS=("lowlatency") ;;
		*-aws) FLAVORS=("aws") ;;
		*-azure) FLAVORS=("azure") ;;
		*-gcp) FLAVORS=("gcp") ;;
		*-gke) FLAVORS=("gke") ;;
		# ibm-classic installs the same *-ibm ABI under a distinct meta track.
		*-ibm) FLAVORS=("ibm" "ibm-classic") ;;
		*-kvm) FLAVORS=("kvm") ;;
		*-oracle) FLAVORS=("oracle") ;;
		*) return 1 ;;
	esac
	for FLAVOR in "${FLAVORS[@]}"; do
		IMAGE_META_PATTERNS+=("linux-image-${FLAVOR}*")
	done

	while IFS=$'\t' read -r PACKAGE STATUS; do
		[[ "${STATUS}" == 'install ok installed' ]] || continue
		PACKAGE="${PACKAGE%%:*}"
		[[ "${PACKAGE}" == linux-image-* ]] || continue
		TRACK="${PACKAGE#linux-image-}"

		# Restrict prefix globs to real compatible image-meta naming schemes.
		# In particular, generic must not accept generic-64k.
		MATCHED=0
		for FLAVOR in "${FLAVORS[@]}"; do
			if ubuntuKernelTrackMatchesFlavor "${TRACK}" "${FLAVOR}"; then
				MATCHED=1
				break
			fi
		done
		[[ "${MATCHED}" -eq 1 ]] || continue
		HEADER_META="linux-headers-${TRACK}"
		[[ "${HEADER_META}" =~ ^linux-headers-[a-z0-9][a-z0-9.+-]*$ ]] || continue

		SEEN=0
		for EXISTING in "${CANDIDATES[@]}"; do
			if [[ "${EXISTING}" == "${HEADER_META}" ]]; then
				SEEN=1
				break
			fi
		done
		[[ "${SEEN}" -eq 1 ]] || CANDIDATES+=("${HEADER_META}")
	done < <(dpkg-query -W -f='${binary:Package}\t${Status}\n' \
		"${IMAGE_META_PATTERNS[@]}" 2>/dev/null)

	[[ "${#CANDIDATES[@]}" -eq 1 ]] || return 1
	printf '%s\n' "${CANDIDATES[0]}"
}

# Return the header-package prefix for the installed official Debian image that
# owns a kernel release. Debian 11 also ships parallel versioned source tracks
# such as linux-6.1 / linux-signed-6.1-amd64; preserve that series in the
# corresponding linux-headers-6.1-* meta-package.
function getInstalledDebianKernelHeaderPrefix() {
	local KERNEL_VER="$1"
	local DEB_ARCH="$2"
	local IMAGE_PKG
	local PACKAGE_INFO
	local SOURCE_PKG
	local STATUS
	local ERROR_FLAG

	# dpkg-query treats package names as patterns, so reject metacharacters and
	# other characters that cannot occur in an official Debian kernel release.
	[[ "${KERNEL_VER}" =~ ^[a-z0-9][a-z0-9.+~-]*$ ]] || return 1

	for IMAGE_PKG in "linux-image-${KERNEL_VER}" "linux-image-${KERNEL_VER}-unsigned"; do
		if ! PACKAGE_INFO=$(dpkg-query -W \
				-f='${source:Package}|${db:Status-Status}|${db:Status-Eflag}\n' \
				"${IMAGE_PKG}" 2>/dev/null); then
			continue
		fi

		IFS='|' read -r SOURCE_PKG STATUS ERROR_FLAG <<< "${PACKAGE_INFO}"
		[[ "${STATUS}" == 'installed' ]] && [[ "${ERROR_FLAG}" == 'ok' ]] || continue

		if [[ "${SOURCE_PKG}" == 'linux' ]] || \
				[[ "${SOURCE_PKG}" == "linux-signed-${DEB_ARCH}" ]]; then
			printf '%s\n' 'linux-headers'
			return 0
		fi

		if [[ "${SOURCE_PKG}" =~ ^linux-([0-9]+(\.[0-9]+)*)$ ]] || \
				[[ "${SOURCE_PKG}" =~ ^linux-signed-([0-9]+(\.[0-9]+)*)-${DEB_ARCH}$ ]]; then
			printf '%s\n' "linux-headers-${BASH_REMATCH[1]}"
			return 0
		fi
	done

	return 1
}

# Return the installed exact Debian image package and its binary version. The
# binary version (unlike a signed source-package version) can be compared with
# header meta-package versions exposed by APT.
function getInstalledDebianKernelImagePackageVersion() {
	local KERNEL_VER="$1"
	local IMAGE_PKG
	local PACKAGE_INFO
	local IMAGE_VERSION
	local STATUS
	local ERROR_FLAG

	[[ "${KERNEL_VER}" =~ ^[a-z0-9][a-z0-9.+~-]*$ ]] || return 1

	for IMAGE_PKG in "linux-image-${KERNEL_VER}" "linux-image-${KERNEL_VER}-unsigned"; do
		if ! PACKAGE_INFO=$(dpkg-query -W \
				-f='${Version}|${db:Status-Status}|${db:Status-Eflag}\n' \
				"${IMAGE_PKG}" 2>/dev/null); then
			continue
		fi

		IFS='|' read -r IMAGE_VERSION STATUS ERROR_FLAG <<< "${PACKAGE_INFO}"
		[[ "${STATUS}" == 'installed' ]] && [[ "${ERROR_FLAG}" == 'ok' ]] || continue
		[[ "${IMAGE_VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$ ]] || continue
		printf '%s|%s\n' "${IMAGE_PKG}" "${IMAGE_VERSION}"
		return 0
	done

	return 1
}

# A Debian backports kernel can share its rolling meta-package name with
# stable, while backports has a lower default APT priority. Resolve the unique
# available meta-package version from the same ~bpoN lineage and install that
# version explicitly. If the lineage cannot be proven, decline to claim future
# header tracking rather than allowing APT to choose the stable package.
function getDebianKernelHeaderMetaInstallSpec() {
	local KERNEL_VER="$1"
	local HEADER_META_PKG="$2"
	local IMAGE_INFO
	local IMAGE_PKG
	local IMAGE_VERSION
	local BACKPORT_RELEASE
	local PACKAGE_INFO
	local INSTALLED_META_VERSION
	local WANT
	local STATUS
	local ERROR_FLAG
	local MADISON_PACKAGE
	local MADISON_VERSION
	local MADISON_SOURCE
	local MADISON_SUITE
	local ORIGIN_SUITE
	local EXISTING
	local SEEN
	local -a IMAGE_SUITES=()
	local -a META_SUITES=()
	local -a CANDIDATE_VERSIONS=()

	[[ "${HEADER_META_PKG}" =~ ^[a-z0-9][a-z0-9.+-]*$ ]] || return 1

	if ! IMAGE_INFO=$(getInstalledDebianKernelImagePackageVersion "${KERNEL_VER}"); then
		# Raspberry Pi OS tracks do not use Debian's shared stable/backports
		# package names. Ordinary Debian metas require exact image provenance.
		case "${HEADER_META_PKG}" in
			raspberrypi-kernel-headers|linux-headers-rpi-v6|linux-headers-rpi-v7|linux-headers-rpi-v7l|linux-headers-rpi-v8|linux-headers-rpi-2712|linux-headers-rpi-v8-rt)
				printf '%s\n' "${HEADER_META_PKG}"
				return 0
				;;
			*) return 1 ;;
		esac
	fi
	IMAGE_PKG="${IMAGE_INFO%%|*}"
	IMAGE_VERSION="${IMAGE_INFO#*|}"

	if [[ ! "${IMAGE_VERSION}" =~ ~bpo([0-9]+)([+u][0-9]+|$) ]]; then
		printf '%s\n' "${HEADER_META_PKG}"
		return 0
	fi
	BACKPORT_RELEASE="${BASH_REMATCH[1]}"

	command -v apt-cache &>/dev/null || return 1
	# First prove the exact suite that supplied the installed image. Regular
	# backports and backports-sloppy share the same ~bpoN version lineage.
	while IFS='|' read -r MADISON_PACKAGE MADISON_VERSION MADISON_SOURCE; do
		MADISON_PACKAGE="${MADISON_PACKAGE#"${MADISON_PACKAGE%%[![:space:]]*}"}"
		MADISON_PACKAGE="${MADISON_PACKAGE%"${MADISON_PACKAGE##*[![:space:]]}"}"
		MADISON_VERSION="${MADISON_VERSION#"${MADISON_VERSION%%[![:space:]]*}"}"
		MADISON_VERSION="${MADISON_VERSION%"${MADISON_VERSION##*[![:space:]]}"}"
		[[ "${MADISON_PACKAGE}" == "${IMAGE_PKG}" ]] || continue
		[[ "${MADISON_VERSION}" == "${IMAGE_VERSION}" ]] || continue
		[[ "${MADISON_SOURCE}" =~ (^|[[:space:]])([a-z0-9][a-z0-9.+-]*-backports(-sloppy)?)/[a-z0-9][a-z0-9.+-]*([[:space:]]|$) ]] || continue
		MADISON_SUITE="${BASH_REMATCH[2]}"

		SEEN=0
		for EXISTING in "${IMAGE_SUITES[@]}"; do
			if [[ "${EXISTING}" == "${MADISON_SUITE}" ]]; then
				SEEN=1
				break
			fi
		done
		[[ "${SEEN}" -eq 1 ]] || IMAGE_SUITES+=("${MADISON_SUITE}")
	done < <(LC_ALL=C apt-cache madison "${IMAGE_PKG}" 2>/dev/null)

	[[ "${#IMAGE_SUITES[@]}" -eq 1 ]] || return 1
	ORIGIN_SUITE="${IMAGE_SUITES[0]}"

	# Select one current meta version from that exact suite. Also count other
	# backports suites so a shared version cannot hide regular/sloppy ambiguity.
	while IFS='|' read -r MADISON_PACKAGE MADISON_VERSION MADISON_SOURCE; do
		MADISON_PACKAGE="${MADISON_PACKAGE#"${MADISON_PACKAGE%%[![:space:]]*}"}"
		MADISON_PACKAGE="${MADISON_PACKAGE%"${MADISON_PACKAGE##*[![:space:]]}"}"
		MADISON_VERSION="${MADISON_VERSION#"${MADISON_VERSION%%[![:space:]]*}"}"
		MADISON_VERSION="${MADISON_VERSION%"${MADISON_VERSION##*[![:space:]]}"}"
		[[ "${MADISON_PACKAGE}" == "${HEADER_META_PKG}" ]] || continue
		[[ "${MADISON_VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$ ]] || continue
		[[ "${MADISON_VERSION}" =~ ~bpo${BACKPORT_RELEASE}([+u][0-9]+|$) ]] || continue
		[[ "${MADISON_SOURCE}" =~ (^|[[:space:]])([a-z0-9][a-z0-9.+-]*-backports(-sloppy)?)/[a-z0-9][a-z0-9.+-]*([[:space:]]|$) ]] || continue
		MADISON_SUITE="${BASH_REMATCH[2]}"

		SEEN=0
		for EXISTING in "${META_SUITES[@]}"; do
			if [[ "${EXISTING}" == "${MADISON_SUITE}" ]]; then
				SEEN=1
				break
			fi
		done
		[[ "${SEEN}" -eq 1 ]] || META_SUITES+=("${MADISON_SUITE}")

		[[ "${MADISON_SUITE}" == "${ORIGIN_SUITE}" ]] || continue
		SEEN=0
		for EXISTING in "${CANDIDATE_VERSIONS[@]}"; do
			if [[ "${EXISTING}" == "${MADISON_VERSION}" ]]; then
				SEEN=1
				break
			fi
		done
		[[ "${SEEN}" -eq 1 ]] || CANDIDATE_VERSIONS+=("${MADISON_VERSION}")
	done < <(LC_ALL=C apt-cache madison "${HEADER_META_PKG}" 2>/dev/null)

	[[ "${#META_SUITES[@]}" -eq 1 ]] || return 1
	[[ "${META_SUITES[0]}" == "${ORIGIN_SUITE}" ]] || return 1
	[[ "${#CANDIDATE_VERSIONS[@]}" -eq 1 ]] || return 1

	# Never claim future tracking for a held meta, or force an installed
	# newer/different track backward. An older stable meta can still be upgraded
	# to the proven backports candidate.
	if PACKAGE_INFO=$(dpkg-query -W \
			-f='${Version}|${db:Status-Want}|${db:Status-Status}|${db:Status-Eflag}\n' \
			"${HEADER_META_PKG}" 2>/dev/null); then
		IFS='|' read -r INSTALLED_META_VERSION WANT STATUS ERROR_FLAG <<< "${PACKAGE_INFO}"
		[[ "${INSTALLED_META_VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z.+:~_-]*$ ]] || return 1
		if [[ "${STATUS}" == 'installed' ]] && [[ "${ERROR_FLAG}" == 'ok' ]]; then
			[[ "${WANT}" == 'install' ]] || return 1
			if dpkg --compare-versions "${INSTALLED_META_VERSION}" gt "${CANDIDATE_VERSIONS[0]}"; then
				return 1
			fi
		fi
	fi
	printf '%s=%s\n' "${HEADER_META_PKG}" "${CANDIDATE_VERSIONS[0]}"
}

# Return a rolling header package when APT reverse-dependency metadata is not
# available. Installing only linux-headers-$(uname -r) is enough for today's
# DKMS build, but the rolling package is what keeps headers on APT's future
# kernel-upgrade path.
function getKernelHeaderMetaPackage() {
	local KERNEL_VER="${1:-$(uname -r)}"
	local APT_META
	local INSTALLED_META
	local DEB_ARCH
	local DEB_HEADER_FLAVOR
	local DEB_HEADER_PREFIX
	local RPI_FLAVOR

	if APT_META=$(getAptKernelHeaderMetaPackage "${KERNEL_VER}"); then
		printf '%s\n' "${APT_META}"
		return 0
	fi

	if [[ "${OS}" == 'debian' ]]; then
		DEB_ARCH=$(dpkg --print-architecture 2>/dev/null) || return 1

		# Raspberry Pi OS Bookworm tracks have per-flavor rolling headers.
		# Accept only its current +rpt-rpi-* and early -rpiN-rpi-* release
		# formats before applying the general Debian suffix fallbacks below.
		if [[ "${KERNEL_VER}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\+rpt-rpi-(v6|v7|v7l|v8|2712|v8-rt)$ ]] || \
				[[ "${KERNEL_VER}" =~ ^[0-9]+\.[0-9]+\.[0-9]+-rpi[0-9]+-rpi-(v6|v7|v7l|v8|2712|v8-rt)$ ]]; then
			RPI_FLAVOR="${BASH_REMATCH[1]}"
			printf '%s\n' "linux-headers-rpi-${RPI_FLAVOR}"
			return 0
		fi

		if [[ "${KERNEL_VER}" =~ ^[0-9]+\.[0-9]+\.[0-9]+-v(6|7|7l|8)\+$ ]]; then
			printf '%s\n' 'raspberrypi-kernel-headers'
			return 0
		fi

		case "${KERNEL_VER}" in
			*+rpt-rpi|*-rpi[0-9]*-rpi|*-rpi-*) return 1 ;;
			*-rpi)
				[[ "${DEB_ARCH}" == 'armel' ]] || return 1
				DEB_HEADER_FLAVOR='rpi'
				;;
			*-cloud-"${DEB_ARCH}")
				case "${DEB_ARCH}" in
					amd64|arm64) DEB_HEADER_FLAVOR="cloud-${DEB_ARCH}" ;;
					*) return 1 ;;
				esac
				;;
			*-rt-"${DEB_ARCH}")
				case "${DEB_ARCH}" in
					amd64|arm64) DEB_HEADER_FLAVOR="rt-${DEB_ARCH}" ;;
					*) return 1 ;;
				esac
				;;
			*-arm64-16k)
				[[ "${DEB_ARCH}" == 'arm64' ]] || return 1
				DEB_HEADER_FLAVOR='arm64-16k'
				;;
			*-powerpc64le-64k)
				[[ "${DEB_ARCH}" == 'ppc64el' ]] || return 1
				DEB_HEADER_FLAVOR='powerpc64le-64k'
				;;
			*-powerpc64le)
				[[ "${DEB_ARCH}" == 'ppc64el' ]] || return 1
				DEB_HEADER_FLAVOR='powerpc64le'
				;;
			*-rt-armmp)
				[[ "${DEB_ARCH}" == 'armhf' ]] || return 1
				DEB_HEADER_FLAVOR='rt-armmp'
				;;
			*-armmp-lpae)
				[[ "${DEB_ARCH}" == 'armhf' ]] || return 1
				DEB_HEADER_FLAVOR='armmp-lpae'
				;;
			*-armmp)
				[[ "${DEB_ARCH}" == 'armhf' ]] || return 1
				DEB_HEADER_FLAVOR='armmp'
				;;
			*-rt-686-pae)
				[[ "${DEB_ARCH}" == 'i386' ]] || return 1
				DEB_HEADER_FLAVOR='rt-686-pae'
				;;
			*-686-pae)
				[[ "${DEB_ARCH}" == 'i386' ]] || return 1
				DEB_HEADER_FLAVOR='686-pae'
				;;
			*-686)
				[[ "${DEB_ARCH}" == 'i386' ]] || return 1
				DEB_HEADER_FLAVOR='686'
				;;
			*-"${DEB_ARCH}")
				case "${DEB_ARCH}" in
					amd64|arm64|riscv64|s390x) DEB_HEADER_FLAVOR="${DEB_ARCH}" ;;
					*) return 1 ;;
				esac
				;;
			*) return 1 ;;
		esac

		DEB_HEADER_PREFIX=$(getInstalledDebianKernelHeaderPrefix \
			"${KERNEL_VER}" "${DEB_ARCH}") || return 1
		printf '%s\n' "${DEB_HEADER_PREFIX}-${DEB_HEADER_FLAVOR}"
	elif [[ "${OS}" == 'ubuntu' ]]; then
		if INSTALLED_META=$(getInstalledUbuntuKernelHeaderMetaPackage "${KERNEL_VER}"); then
			printf '%s\n' "${INSTALLED_META}"
			return 0
		fi

		case "${KERNEL_VER}" in
			# These suffixes are shared by unversioned, edge, HWE/LTS, and
			# version-pinned tracks. Without package metadata, selecting one
			# is unsafe.
			*-generic-64k|*-generic|*-lowlatency|*-aws|*-azure|*-gcp|*-gke|*-ibm|*-kvm|*-oracle) return 1 ;;
			*-raspi*) printf '%s\n' "linux-headers-raspi" ;;
			*) return 1 ;;
		esac
	else
		return 1
	fi
}

function kernelHeadersAreAvailableForVersion() {
	local KERNEL_VER="${1:-$(uname -r)}"
	[[ -f "/lib/modules/${KERNEL_VER}/build/Makefile" ]]
}

# Install headers for both the running kernel and future kernel upgrades.
# $1 – kernel version string; defaults to the running kernel (uname -r).
# For APT-based systems the caller must have already activated enable_apt_ipv4.
function installKernelHeaders() {
	local KERNEL_VER="${1:-$(uname -r)}"
	if [[ "${OS}" == 'ubuntu' ]] || [[ "${OS}" == 'debian' ]]; then
		local CURRENT_HEADER_INSTALLED=0
		local CURRENT_HEADER_PKG="linux-headers-${KERNEL_VER}"
		local META_HEADER_PKG=""
		local META_HEADER_INSTALL_SPEC=""
		local META_ATTEMPTED=0
		local ROLLING_HEADER_INSTALLED=0

		if META_HEADER_PKG=$(getKernelHeaderMetaPackage "${KERNEL_VER}" 2>/dev/null) && \
				[[ -n "${META_HEADER_PKG}" ]]; then
			if [[ "${OS}" == 'debian' ]]; then
				META_HEADER_INSTALL_SPEC=$(getDebianKernelHeaderMetaInstallSpec \
					"${KERNEL_VER}" "${META_HEADER_PKG}" 2>/dev/null) || META_HEADER_INSTALL_SPEC=""
			else
				META_HEADER_INSTALL_SPEC="${META_HEADER_PKG}"
			fi
		else
			META_HEADER_PKG=""
		fi
		if [[ -z "${META_HEADER_INSTALL_SPEC}" ]]; then
			META_HEADER_PKG=""
			echo -e "${ORANGE}WARNING: Could not determine a safe rolling kernel header meta-package for '${KERNEL_VER}'. The installer will still try headers for the running kernel, but future kernel upgrades may require installing matching headers manually.${NC}" >&2
		fi

		if apt-get install -y "${CURRENT_HEADER_PKG}"; then
			CURRENT_HEADER_INSTALLED=1
		else
			echo -e "${ORANGE}WARNING: Failed to install kernel headers package '${CURRENT_HEADER_PKG}'. Trying alternate header packages...${NC}"

			# Raspberry Pi kernels commonly use one rolling header package instead
			# of a versioned linux-headers-$(uname -r) package.
			if [[ "${META_HEADER_PKG}" == 'raspberrypi-kernel-headers' ]]; then
				META_ATTEMPTED=1
				if apt-get install -y raspberrypi-kernel-headers; then
					ROLLING_HEADER_INSTALLED=1
				else
					echo -e "${ORANGE}WARNING: Failed to install kernel headers package 'raspberrypi-kernel-headers'.${NC}"
				fi
			fi
		fi

		# This is deliberately independent of the running-kernel install above:
		# even when the exact package succeeds, the meta-package is what pulls in
		# matching headers during future APT kernel upgrades.
		if [[ -n "${META_HEADER_PKG}" ]] && \
				[[ "${META_HEADER_PKG}" != "${CURRENT_HEADER_PKG}" ]] && \
				[[ "${META_ATTEMPTED}" -eq 0 ]]; then
			if apt-get install -y "${META_HEADER_INSTALL_SPEC}"; then
				ROLLING_HEADER_INSTALLED=1
			else
				echo -e "${ORANGE}WARNING: Failed to install kernel header meta-package '${META_HEADER_INSTALL_SPEC}'. The current kernel may work, but a future kernel upgrade could require installing matching headers manually.${NC}"
			fi
		fi

		if [[ "${CURRENT_HEADER_INSTALLED}" -ne 1 ]] && \
				kernelHeadersAreAvailableForVersion "${KERNEL_VER}"; then
			CURRENT_HEADER_INSTALLED=1
		fi

		if [[ "${CURRENT_HEADER_INSTALLED}" -ne 1 ]]; then
			if [[ "${ROLLING_HEADER_INSTALLED}" -eq 1 ]]; then
				echo -e "${ORANGE}WARNING: A rolling kernel header meta-package was installed, but headers for the running kernel (${KERNEL_VER}) remain unavailable. DKMS module build may fail until matching headers are installed and the module is rebuilt.${NC}"
			else
				echo -e "${ORANGE}WARNING: Failed to install headers for the running kernel (${KERNEL_VER}). DKMS module build may fail; continuing, but the amneziawg kernel module might not be available until matching headers are installed and the module is rebuilt.${NC}"
			fi
		fi
	elif [[ "${OS}" == 'fedora' ]] || [[ "${OS}" == 'centos' ]] || [[ "${OS}" == 'almalinux' ]] || [[ "${OS}" == 'rocky' ]]; then
		if ! dnf install -y "kernel-devel-${KERNEL_VER}"; then
			echo -e "${ORANGE}WARNING: Failed to install kernel-devel for the running kernel (${KERNEL_VER}). Attempting to install the latest kernel-devel instead.${NC}"
			if ! dnf install -y kernel-devel; then
				echo -e "${ORANGE}WARNING: Failed to install any kernel-devel package. Continuing without kernel headers; DKMS module builds may fail until headers are installed and the system is rebooted.${NC}"
			fi
		fi
	fi
}

# Start awg-quick@${SERVER_AWG_NIC} when the service is inactive.
# Called after any successful module-load path so the interface is available
# for subsequent awg syncconf calls.  Exits with code 1 on failure.
function ensureAwgQuickRunning() {
	if [[ -n "${SERVER_AWG_NIC:-}" ]] && ! systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
		echo -e "${ORANGE}Starting awg-quick@${SERVER_AWG_NIC} (was not running)...${NC}"
		awgBackendPrepareServiceStart
		if ! systemctl start "awg-quick@${SERVER_AWG_NIC}"; then
			echo -e "${RED}ERROR: Failed to start awg-quick@${SERVER_AWG_NIC}.${NC}"
			echo -e "${ORANGE}Check service status with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
			exit 1
		fi
		echo -e "${GREEN}awg-quick@${SERVER_AWG_NIC} started successfully.${NC}"
	fi
}

# Ensure the amneziawg kernel module is built and loaded for the running kernel.
#
# After a kernel upgrade the DKMS module may still be built only for the old
# kernel.  This function detects that situation and automatically:
#   1. Installs the matching kernel headers (if missing)
#   2. Runs dkms autoinstall for the current kernel
#   3. Rebuilds the module dependency cache (depmod -a)
#   4. Loads the module with modprobe
#   5. Starts the awg-quick service if it was not already running, unless the
#      optional first argument is 0 (module-only preparation for probes)
#
# If everything is already fine the function returns immediately (idempotent).
# If repair fails, it prints diagnostic information and exits with code 1.
function ensureAmneziawgKernelModule() {
	local KERNEL_VER
	local START_AWG_QUICK="${1:-1}"
	case "${START_AWG_QUICK}" in
		0|1) ;;
		*)
			echo -e "${RED}ERROR: ensureAmneziawgKernelModule expects service-start mode 0 or 1.${NC}" >&2
			return 1
			;;
	esac
	KERNEL_VER="$(uname -r)"

	# Fast-path: if the module is already loaded, ensure the VPN service is also
	# running before returning unless this is a module-only capability probe.
	if lsmod 2>/dev/null | grep -q '^amneziawg '; then
		[[ "${START_AWG_QUICK}" == "0" ]] || ensureAwgQuickRunning
		return 0
	fi

	# If the module is already built for this kernel, try loading it before
	# falling back to the full repair path.
	if [ -n "$(find "/lib/modules/${KERNEL_VER}" -name 'amneziawg.ko*' -print -quit 2>/dev/null)" ]; then
		if modprobe amneziawg 2>/dev/null && lsmod 2>/dev/null | grep -q '^amneziawg '; then
			# Module loaded successfully; start the VPN service unless the caller is
			# preserving an intentionally stopped or manually managed interface.
			[[ "${START_AWG_QUICK}" == "0" ]] || ensureAwgQuickRunning
			return 0
		fi
	fi

	echo -e "${ORANGE}amneziawg kernel module is not built or loaded for kernel ${KERNEL_VER}.${NC}"
	echo -e "${ORANGE}Attempting automatic repair...${NC}"

	# Install missing kernel headers so DKMS can compile the module.
	# installKernelHeaders() tries candidates in order and warns on failure.
	if [[ "${OS}" == 'ubuntu' ]] || [[ "${OS}" == 'debian' ]]; then
		local HEADERS_PKG="linux-headers-${KERNEL_VER}"
		if ! dpkg-query -W -f='${Status}' "${HEADERS_PKG}" 2>/dev/null | grep -q 'install ok installed'; then
			echo -e "${ORANGE}Kernel headers (${HEADERS_PKG}) are not installed. Installing...${NC}"
			enable_apt_ipv4
			installKernelHeaders "${KERNEL_VER}"
			disable_apt_ipv4
		fi
	elif [[ "${OS}" == 'fedora' ]] || [[ "${OS}" == 'centos' ]] || [[ "${OS}" == 'almalinux' ]] || [[ "${OS}" == 'rocky' ]]; then
		local HEADERS_PKG="kernel-devel-${KERNEL_VER}"
		if ! rpm -q "${HEADERS_PKG}" &>/dev/null; then
			echo -e "${ORANGE}Kernel headers (${HEADERS_PKG}) are not installed. Installing...${NC}"
			enable_apt_ipv4
			installKernelHeaders "${KERNEL_VER}"
			disable_apt_ipv4
		fi
	fi

	# Strip the deprecated REMAKE_INITRD directive to silence newer DKMS warnings
	sanitizeAwgDkmsConf

	# Build the module for the current kernel with DKMS.
	# Even if this step reports failure we still attempt modprobe below: the
	# actual success criterion is whether the .ko ends up loadable, and an
	# earlier partial build can sometimes satisfy that.  modprobe is the
	# definitive check and will produce a clear error if the build truly failed.
	if command -v dkms &>/dev/null; then
		echo -e "${ORANGE}Running: dkms autoinstall -k ${KERNEL_VER}${NC}"
		if ! dkms autoinstall -k "${KERNEL_VER}"; then
			echo -e "${ORANGE}WARNING: dkms autoinstall failed for kernel ${KERNEL_VER}.${NC}"
			local DKMS_LOG
			DKMS_LOG=$(find /var/lib/dkms/amneziawg -name 'make.log' -path "*${KERNEL_VER}*" 2>/dev/null | head -n 1)
			if [[ -n "${DKMS_LOG}" ]]; then
				echo -e "${ORANGE}Last 20 lines of DKMS build log (${DKMS_LOG}):${NC}"
				tail -20 "${DKMS_LOG}"
			else
				echo -e "${ORANGE}Build log not found. Check /var/lib/dkms/amneziawg/ for details.${NC}"
			fi
		fi
	else
		echo -e "${ORANGE}WARNING: dkms is not installed. Cannot rebuild the kernel module.${NC}"
	fi

	# Rebuild the module dependency cache (required for DKMS + compressed modules)
	if command -v depmod &>/dev/null; then
		depmod -a
	fi

	# Attempt to load the module
	if ! modprobe amneziawg; then
		echo -e "${RED}ERROR: amneziawg kernel module could not be loaded for kernel ${KERNEL_VER}.${NC}"
		echo -e "${ORANGE}The module is still not available in /lib/modules/${KERNEL_VER}/${NC}"
		if [[ "${OS}" == 'ubuntu' ]] || [[ "${OS}" == 'debian' ]]; then
			echo -e "${ORANGE}Manual recovery:${NC}"
			echo -e "${ORANGE}  1. apt install -y \"linux-headers-${KERNEL_VER}\"${NC}"
			echo -e "${ORANGE}  2. dkms autoinstall -k \"${KERNEL_VER}\" && depmod -a${NC}"
			echo -e "${ORANGE}  3. modprobe amneziawg${NC}"
			echo -e "${ORANGE}  4. systemctl start \"awg-quick@${SERVER_AWG_NIC:-awg0}\"${NC}"
		elif [[ "${OS}" == 'fedora' ]] || [[ "${OS}" == 'centos' ]] || [[ "${OS}" == 'almalinux' ]] || [[ "${OS}" == 'rocky' ]]; then
			echo -e "${ORANGE}Manual recovery:${NC}"
			echo -e "${ORANGE}  1. dnf install -y \"kernel-devel-${KERNEL_VER}\"${NC}"
			echo -e "${ORANGE}  2. dkms autoinstall -k \"${KERNEL_VER}\" && depmod -a${NC}"
			echo -e "${ORANGE}  3. modprobe amneziawg${NC}"
			echo -e "${ORANGE}  4. systemctl start \"awg-quick@${SERVER_AWG_NIC:-awg0}\"${NC}"
		fi
		exit 1
	fi

	echo -e "${GREEN}amneziawg module loaded successfully for kernel ${KERNEL_VER}.${NC}"

	# The module was just loaded — start the VPN service if it was not running
	# unless the caller requested module-only preparation.
	# After a kernel upgrade the service fails at boot because ExecStartPre
	# (modprobe amneziawg) returns an error; now that the module is available
	# we restart it so the awg interface exists for subsequent awg syncconf calls.
	[[ "${START_AWG_QUICK}" == "0" ]] || ensureAwgQuickRunning
}

# ── AWG backend runtime seam ─────────────────────────────────────────────────
#
# Backend-neutral management code reaches the datapath only through the small
# set of operations below. Each one dispatches on AWG_BACKEND, which
# validateParamsFile (managed installations) or installQuestions (fresh
# installations) has already set. The kernel branches run exactly the commands
# their callers used to run inline. An unset or unknown backend fails closed
# instead of falling back to the kernel module.

# Make sure the selected backend can serve the interface. The calling
# convention is that of the kernel implementation, ensureAmneziawgKernelModule
# [0|1]: mode 1 (the default) also starts awg-quick@<if> when it is inactive,
# and mode 0 only prepares the datapath for capability probes. Failures are
# fatal, as they are in the kernel implementation.
function ensureAwgBackendReady() {
	case "${AWG_BACKEND:-}" in
		"${AWG_BACKEND_KERNEL}")
			ensureAmneziawgKernelModule "$@"
			;;
		"${AWG_BACKEND_BORINGTUN}")
			_awgBtEnsureReady "$@"
			;;
		*)
			reportUnsupportedAwgBackend "${AWG_BACKEND:-}"
			exit 1
			;;
	esac
}

# Prepare a deliberate start or restart of awg-quick@<if> by a management
# operation. The BoringTun drop-in rate-limits starts (StartLimitBurst) so that
# a crashing daemon cannot restart forever; a deliberate restart is not a crash
# loop, so the unit's start counter is reset first. Automatic restarts stay
# limited. The kernel unit is left exactly as it was.
function awgBackendPrepareServiceStart() {
	case "${AWG_BACKEND:-}" in
		"${AWG_BACKEND_BORINGTUN}")
			systemctl reset-failed "awg-quick@${SERVER_AWG_NIC}.service" >/dev/null 2>&1 || true
			;;
		*) ;;
	esac
}

# Create and destroy the throwaway interface that capability probes and staged
# configuration validation apply configurations to. Callers own the interface
# name, output redirection and cleanup.
function awgBackendCreateScratchInterface() {
	local INTERFACE_NAME="$1"

	case "${AWG_BACKEND:-}" in
		"${AWG_BACKEND_KERNEL}")
			ip link add dev "${INTERFACE_NAME}" type amneziawg
			;;
		"${AWG_BACKEND_BORINGTUN}")
			_awgBtScratchCreate "${INTERFACE_NAME}"
			;;
		*)
			reportUnsupportedAwgBackend "${AWG_BACKEND:-}"
			return 1
			;;
	esac
}

function awgBackendDestroyScratchInterface() {
	local INTERFACE_NAME="$1"

	case "${AWG_BACKEND:-}" in
		"${AWG_BACKEND_KERNEL}")
			ip link delete dev "${INTERFACE_NAME}"
			;;
		"${AWG_BACKEND_BORINGTUN}")
			_awgBtScratchDestroy "${INTERFACE_NAME}"
			;;
		*)
			reportUnsupportedAwgBackend "${AWG_BACKEND:-}"
			return 1
			;;
	esac
}

# Bring up an interface that is managed manually rather than by
# awg-quick@<if>.service. Bringing it down stays a plain `awg-quick down`,
# which does not depend on the datapath.
function awgBackendQuickUp() {
	local CONFIG_FILE="$1"

	case "${AWG_BACKEND:-}" in
		"${AWG_BACKEND_KERNEL}")
			awg-quick up "${CONFIG_FILE}"
			;;
		"${AWG_BACKEND_BORINGTUN}")
			_awgBtQuickUp "${CONFIG_FILE}"
			;;
		*)
			reportUnsupportedAwgBackend "${AWG_BACKEND:-}"
			return 1
			;;
	esac
}

# Apply the interface's configuration file to the running interface without
# restarting it, as `awg syncconf <if> <(awg-quick strip <if>)`.
#
# The optional second argument says where `awg syncconf` output goes:
# `--stderr-to-stdout` merges its stderr into stdout for command substitution,
# and a file path receives its stderr. The redirection applies to `awg syncconf`
# alone, exactly as in the former inline call sites, so `awg-quick strip`
# diagnostics still reach the caller's stderr. Callers pass the destination
# here instead of redirecting stderr on the call itself.
function awgSyncInterfaceConfig() {
	local INTERFACE_NAME="$1"
	local SYNCCONF_STDERR="${2:-}"

	case "${AWG_BACKEND:-}" in
		"${AWG_BACKEND_KERNEL}")
			case "${SYNCCONF_STDERR}" in
				"")
					awg syncconf "${INTERFACE_NAME}" <(awg-quick strip "${INTERFACE_NAME}")
					;;
				--stderr-to-stdout)
					awg syncconf "${INTERFACE_NAME}" <(awg-quick strip "${INTERFACE_NAME}") 2>&1
					;;
				*)
					awg syncconf "${INTERFACE_NAME}" <(awg-quick strip "${INTERFACE_NAME}") 2>"${SYNCCONF_STDERR}"
					;;
			esac
			;;
		"${AWG_BACKEND_BORINGTUN}")
			_awgBtSync "${INTERFACE_NAME}" "${SYNCCONF_STDERR}"
			;;
		*)
			reportUnsupportedAwgBackend "${AWG_BACKEND:-}"
			return 1
			;;
	esac
}

# ── BoringTun runtime layer (internal) ───────────────────────────────────────
#
# The supervised BoringTun datapath: store verification, the launcher that
# awg-quick runs as its userspace implementation, the awg-backend-ctl hooks of
# the awg-quick@<if> drop-in, the filtered live sync and scratch interfaces.
# See docs/BORINGTUN_BACKEND_DESIGN.md sections 6 to 8.
#
# awg-boringtun-launch and awg-backend-ctl are generated from the functions
# below with declare -f (_awgBtRenderHelper), so the installer and the helpers
# share one implementation. Functions listed in _AWG_BT_HELPER_FUNCTIONS may use
# only the AWG_BT_* settings that the helpers embed, never other installer
# state, and must work under `set -u`.
#
# Every destructive step acts only on what the runtime can show it owns: the
# state of the current start attempt (<run dir>/<if>.state) for the service,
# and per-attempt records for scratch instances. Processes are identified by
# PID and start time, socket nodes by device and inode, links by ifindex.
# Without that evidence a resource is left alone.
#
# The seam dispatches here when AWG_BACKEND is boringtun, which only a fresh
# BoringTun install (selectFreshInstallBackend) or validated params can set.

# MANIFEST keys of artifact format 1, in the order scripts/boringtun-artifact.sh
# writes them (BTA_MANIFEST_KEYS). A unit test keeps the two lists equal.
AWG_BT_MANIFEST_KEYS="artifact_format name version source_repository source_commit source_date_epoch target os arch libc linkage rust_toolchain rustc cargo build_command build_profile rustflags binary binary_sha256 license third_party_licenses"

# Settings embedded in both helpers, in this order.
_AWG_BT_HELPER_VARIABLES="AWG_BT_STORE_DIR AWG_BT_LIBEXEC_DIR AWG_BT_RUN_DIR AWG_BT_CONFIG_DIR AWG_BT_SYSTEMD_DIR AWG_BT_UNIT_DIRS AWG_BT_WG_SOCKET_DIR AWG_BT_AWG_SOCKET_DIR AWG_BT_SYS_DIR AWG_BT_PROC_DIR AWG_BT_TUN_DEVICE AWG_BT_TRUST_ANCHOR AWG_BT_TRUSTED_UID AWG_BT_PATH AWG_BT_READY_TIMEOUT AWG_BT_PROBE_TIMEOUT AWG_BT_HOST_ARCH AWG_BT_TMP_DIR AWG_BT_MODPROBE_OVERRIDE AWG_BT_MANIFEST_KEYS"

_AWG_BT_VERIFIED_BIN=""
# The MANIFEST version of the release _awgBtVerifyRelease last verified.
_AWG_BT_VERIFIED_VERSION=""
# A verified store release that scratch instances run instead of the one
# current selects, while a binary lifecycle transaction validates it before
# activation (_awgBtValidateReleaseCandidate). Set only by that function and
# reset here, so the environment can never select it.
_AWG_BT_CANDIDATE_RELEASE=""
_AWG_BT_FILE_CHANGED=0
_AWG_BT_HELPERS_CHANGED=0
_AWG_BT_ARGV=()
# The command line of a transient scratch unit (_awgBtScratchUnitArgv).
_AWG_BT_UNIT_ARGV=()
# The start attempt a helper works for (_awgBtCurrentAttempt), its ownership
# state (_awgBtStateLoad), and the UAPI nodes last proven to be a daemon's
# (_awgBtProveUapiNodes).
_AWG_BT_ATTEMPT=""
declare -gA _AWG_BT_STATE=()
_AWG_BT_WG_ID=""
_AWG_BT_AWG_ID=""
# Scratch instances created by this shell, by interface name: the attempt's
# token, its guardian's PID and the guardian's start time.
declare -gA _AWG_BT_SCRATCH_TOKENS=()
declare -gA _AWG_BT_SCRATCH_GUARDS=()
declare -gA _AWG_BT_SCRATCH_GUARD_STARTS=()

function _awgBtErr() {
	printf '%s: %s\n' "${_AWG_BT_PROG:-amneziawg-install}" "$*" >&2
}

# awg-quick's own interface-name pattern.
function _awgBtValidInterfaceName() {
	[[ "${1:-}" =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]]
}

# BoringTun protocol imitation values: the pinned binary's --imitate-protocol
# names, and the protocols that carry a hostname. auto, which BoringTun
# resolves to dns, quic, sip or stun separately for each authenticated peer,
# takes none: the CLI refuses --imitate-domain with it. Releases before
# wiresock-boringtun b94943906b11 do not know auto at all
# (_awgBtBinaryImitationSupport).
function _awgBtImitationProtocolValid() {
	case "${1-}" in
		none | dns | quic | sip | stun | auto) return 0 ;;
	esac
	return 1
}

function _awgBtImitationUsesDomain() {
	case "${1-}" in
		dns | quic | sip) return 0 ;;
	esac
	return 1
}

# An imitation hostname is a strict LDH host name, the binary's rule for DNS
# query names and SIP URIs (is_valid_imitation_host): at most 253 bytes of
# dot-separated labels, each 1-63 ASCII letters, digits and hyphens that neither
# starts nor ends with a hyphen. The binary accepts any printable SNI for quic;
# the installer applies the strict rule to all three protocols. The characters
# are spelled out so that no locale widens the ranges.
function _awgBtImitationDomainValid() {
	local DOMAIN="${1-}"
	local ALNUM='[0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]'
	local INNER='[-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]'
	local LABEL="${ALNUM}(${INNER}{0,61}${ALNUM})?"
	[[ "${DOMAIN}" =~ ^${LABEL}(\.${LABEL})*$ ]] && ((${#DOMAIN} <= 253))
}

# Check a protocol and hostname pair, naming what is wrong.
function _awgBtImitationCheck() { # <protocol> <domain>
	local PROTOCOL="${1-}" DOMAIN="${2-}"
	if ! _awgBtImitationProtocolValid "${PROTOCOL}"; then
		_awgBtErr "unsupported BoringTun imitation protocol $(printf '%q' "${PROTOCOL}") (supported: none, dns, quic, sip, stun, auto)"
		return 1
	fi
	[[ -z "${DOMAIN}" ]] && return 0
	if [[ "${PROTOCOL}" == auto ]]; then
		_awgBtErr "auto takes no hostname: BoringTun chooses dns, quic, sip or stun for each authenticated peer and uses its own generated hostnames"
		return 1
	fi
	if ! _awgBtImitationUsesDomain "${PROTOCOL}"; then
		_awgBtErr "an imitation hostname is used only by dns, quic and sip, not by ${PROTOCOL}"
		return 1
	fi
	if ! _awgBtImitationDomainValid "${DOMAIN}"; then
		_awgBtErr "invalid imitation hostname $(printf '%q' "${DOMAIN}"): use at most 253 characters of dot-separated labels of 1-63 ASCII letters, digits and hyphens, none starting or ending with a hyphen"
		return 1
	fi
}

# Whether the verified BoringTun binary BINARY runs protocol imitation
# PROTOCOL: 0 yes, 1 no, 2 it cannot be told, which callers treat as no. Every
# release this installer can run has none, dns, quic, sip and stun. auto came
# with wiresock-boringtun b94943906b11, and the releases before it report the
# same version (0.7.1), so the binary itself is asked, in a clean environment
# and without creating anything: `--imitate-protocol auto --version` prints its
# version where auto is known, and is a usage error (status 2, "invalid value
# 'auto'") where it is not, because the command line parser checks the value
# before it acts on --version. Any other answer, or none within
# AWG_BT_PROBE_TIMEOUT seconds, is 2.
function _awgBtBinaryImitationSupport() { # <binary> <protocol>
	local OUTPUT RC
	[[ "${2-}" == auto ]] || return 0
	OUTPUT="$(timeout --kill-after=2 "${AWG_BT_PROBE_TIMEOUT}" env -i "PATH=${AWG_BT_PATH}" NO_COLOR=1 "$1" \
		--imitate-protocol auto --version 2>&1 </dev/null)"
	RC=$?
	if ((RC == 0)) && [[ "${OUTPUT}" =~ ^boringtun\ [0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		return 0
	fi
	if ((RC == 2)) && [[ "${OUTPUT}" == *"invalid value 'auto' for '--imitate-protocol"* ]]; then
		return 1
	fi
	return 2
}

# "<uid> <octal mode>" of a path, without following a final symlink.
function _awgBtStatOwnerMode() {
	stat -c '%u %a' -- "$1" 2>/dev/null
}

# A trusted node is not a symlink, is owned by AWG_BT_TRUSTED_UID and is not
# writable by group or other. KIND is dir, file or exec (a file its owner can
# execute). Files may not carry setuid, setgid or sticky bits.
function _awgBtTrustedNode() {
	local NODE="$1" KIND="$2" OWNER="" MODE=""
	[[ ! -L "${NODE}" ]] || return 1
	case "${KIND}" in
		dir) [[ -d "${NODE}" ]] || return 1 ;;
		file | exec) [[ -f "${NODE}" ]] || return 1 ;;
		*) return 1 ;;
	esac
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${NODE}")"
	[[ "${OWNER}" == "${AWG_BT_TRUSTED_UID}" ]] || return 1
	if [[ "${KIND}" == dir ]]; then
		[[ "${MODE}" =~ ^[0-7]{3,4}$ ]] || return 1
	else
		[[ "${MODE}" =~ ^[0-7]{3}$ ]] || return 1
	fi
	(((8#${MODE} & 8#022) == 0)) || return 1
	if [[ "${KIND}" == exec ]]; then
		(((8#${MODE} & 8#100) != 0)) || return 1
	fi
	return 0
}

# Every directory from AWG_BT_TRUST_ANCHOR down to the parent of TARGET must be
# a trusted directory. TARGET must be an absolute, normalized path below the
# anchor. The anchor is / in production; tests anchor at their own root.
function _awgBtTrustedAncestors() {
	local TARGET="$1" ANCHOR="${AWG_BT_TRUST_ANCHOR%/}" REST CURRENT COMPONENT
	[[ "${TARGET}" == /* && "${TARGET}" != *//* && "${TARGET}" != */ ]] || return 1
	[[ "${TARGET}/" != */../* && "${TARGET}/" != */./* ]] || return 1
	if [[ -z "${ANCHOR}" ]]; then
		CURRENT="/"
		REST="${TARGET#/}"
	else
		[[ "${TARGET}" == "${ANCHOR}/"* ]] || return 1
		CURRENT="${ANCHOR}"
		REST="${TARGET#"${ANCHOR}/"}"
	fi
	_awgBtTrustedNode "${CURRENT}" dir || return 1
	while [[ "${REST}" == */* ]]; do
		COMPONENT="${REST%%/*}"
		REST="${REST#*/}"
		CURRENT="${CURRENT%/}/${COMPONENT}"
		_awgBtTrustedNode "${CURRENT}" dir || return 1
	done
	return 0
}

function _awgBtHostArch() {
	local MACHINE="${AWG_BT_HOST_ARCH}"
	if [[ -z "${MACHINE}" ]]; then
		MACHINE="$(uname -m 2>/dev/null)" || return 1
	fi
	case "${MACHINE}" in
		x86_64 | amd64) echo x86_64 ;;
		aarch64 | arm64) echo aarch64 ;;
		*) return 1 ;;
	esac
}

# The name of a release directory in the store:
#   boringtun-cli-<version>-g<commit, 12 hex>[-b<build>]-linux-<arch>-musl
# Build 1 is the name without a build component: the layout of every store
# written before builds were named, which stays valid as it is. A build from 2
# on names its build, so two builds of one source commit never share a
# directory. MANIFEST format 1 has no build field: the build in a name is the
# installer's, given when it stored a release whose binary had the embedded
# SHA-256, and the store is root's alone.
function _awgBtReleaseIdValid() {
	[[ "${1:-}" =~ ^boringtun-cli-[0-9]+\.[0-9]+\.[0-9]+-g[0-9a-f]{12}(-b([2-9]|[1-9][0-9]{1,8}))?-linux-(x86_64|aarch64)-musl$ ]]
}

# Verify the BoringTun store and set _AWG_BT_VERIFIED_BIN to the canonical path
# of the binary that may run. The store is AWG_BT_STORE_DIR/<release>/ as
# unpacked from a pinned artifact archive, and AWG_BT_STORE_DIR/current is a
# link to one release. Every directory on the path, the release, its MANIFEST
# and the binary must be trusted; the MANIFEST must describe this release and
# host; and the binary must match its binary_sha256. The check runs at every
# start. Between it and the exec only root can change these files, because no
# path component is writable by anyone else.
function _awgBtVerifyStore() {
	local STORE="${AWG_BT_STORE_DIR}" RELEASE_ID="" OWNER="" MODE=""
	_AWG_BT_VERIFIED_BIN=""
	if ! _awgBtHostArch >/dev/null; then
		_awgBtErr "BoringTun artifacts exist only for x86_64 and aarch64 hosts"
		return 1
	fi
	if ! _awgBtTrustedAncestors "${STORE}" || ! _awgBtTrustedNode "${STORE}" dir; then
		_awgBtErr "the BoringTun store ${STORE} is missing, or it or a parent directory is writable by someone other than root"
		return 1
	fi
	if [[ ! -L "${STORE}/current" ]]; then
		_awgBtErr "the BoringTun store has no current release link: ${STORE}/current"
		return 1
	fi
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${STORE}/current")"
	RELEASE_ID="$(readlink -- "${STORE}/current" 2>/dev/null)" || RELEASE_ID=""
	if [[ "${OWNER}" != "${AWG_BT_TRUSTED_UID}" ]] || ! _awgBtReleaseIdValid "${RELEASE_ID}"; then
		_awgBtErr "${STORE}/current must be a root-owned link to a release directory in the store"
		return 1
	fi
	_awgBtVerifyRelease "${RELEASE_ID}"
}

# The checks of _awgBtVerifyStore for the release directory RELEASE_ID of the
# store, whether or not current selects it: the installer runs them before it
# points current at a release. Sets _AWG_BT_VERIFIED_BIN.
function _awgBtVerifyRelease() { # <release id>
	local STORE="${AWG_BT_STORE_DIR}" RELEASE_ID="$1" RELEASE BINARY MANIFEST LINE KEY VALUE
	local ARCH ACTUAL_SHA="" CANONICAL_STORE CANONICAL_BINARY BUILD_PART=""
	local -A FIELDS=()
	_AWG_BT_VERIFIED_BIN=""
	_AWG_BT_VERIFIED_VERSION=""
	if ! ARCH="$(_awgBtHostArch)"; then
		_awgBtErr "BoringTun artifacts exist only for x86_64 and aarch64 hosts"
		return 1
	fi
	if ! _awgBtTrustedAncestors "${STORE}" || ! _awgBtTrustedNode "${STORE}" dir; then
		_awgBtErr "the BoringTun store ${STORE} is missing, or it or a parent directory is writable by someone other than root"
		return 1
	fi
	if ! _awgBtReleaseIdValid "${RELEASE_ID}"; then
		_awgBtErr "${RELEASE_ID} is not the name of a BoringTun release directory"
		return 1
	fi
	[[ "${RELEASE_ID}" =~ -g[0-9a-f]{12}(-b[0-9]+)?-linux- ]] && BUILD_PART="${BASH_REMATCH[1]}"
	RELEASE="${STORE}/${RELEASE_ID}"
	BINARY="${RELEASE}/boringtun-cli"
	MANIFEST="${RELEASE}/MANIFEST"
	if ! _awgBtTrustedNode "${RELEASE}" dir || ! _awgBtTrustedNode "${MANIFEST}" file || \
		! _awgBtTrustedNode "${BINARY}" exec; then
		_awgBtErr "the BoringTun release ${RELEASE_ID} is incomplete or writable by someone other than root"
		return 1
	fi
	# MANIFEST is data, never sourced: exactly the format-1 keys, once each.
	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		if [[ ! "${LINE}" =~ ^([a-z0-9_]+)=([^[:cntrl:]]*)$ ]]; then
			_awgBtErr "malformed line in ${MANIFEST}"
			return 1
		fi
		KEY="${BASH_REMATCH[1]}"
		VALUE="${BASH_REMATCH[2]}"
		if [[ " ${AWG_BT_MANIFEST_KEYS} " != *" ${KEY} "* || -n "${FIELDS[${KEY}]+set}" ]]; then
			_awgBtErr "unexpected or repeated key ${KEY} in ${MANIFEST}"
			return 1
		fi
		FIELDS["${KEY}"]="${VALUE}"
	done <"${MANIFEST}"
	for KEY in ${AWG_BT_MANIFEST_KEYS}; do
		if [[ -z "${FIELDS[${KEY}]+set}" ]]; then
			_awgBtErr "${MANIFEST} has no ${KEY}"
			return 1
		fi
	done
	if [[ "${FIELDS[artifact_format]}" != 1 || "${FIELDS[name]}" != boringtun-cli || \
		"${FIELDS[binary]}" != boringtun-cli || "${FIELDS[os]}" != linux || \
		"${FIELDS[libc]}" != musl || "${FIELDS[linkage]}" != static || \
		"${FIELDS[arch]}" != "${ARCH}" || "${FIELDS[target]}" != "${ARCH}-unknown-linux-musl" ]] || \
		! [[ "${FIELDS[version]}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && \
			"${FIELDS[source_commit]}" =~ ^[0-9a-f]{40}$ && \
			"${FIELDS[binary_sha256]}" =~ ^[0-9a-f]{64}$ ]] || \
		[[ "${RELEASE_ID}" != "boringtun-cli-${FIELDS[version]}-g${FIELDS[source_commit]:0:12}${BUILD_PART}-linux-${ARCH}-musl" ]]; then
		_awgBtErr "${MANIFEST} does not describe release ${RELEASE_ID} for this ${ARCH} host"
		return 1
	fi
	ACTUAL_SHA="$(sha256sum -- "${BINARY}" 2>/dev/null)" || ACTUAL_SHA=""
	ACTUAL_SHA="${ACTUAL_SHA%% *}"
	if [[ "${ACTUAL_SHA}" != "${FIELDS[binary_sha256]}" ]]; then
		_awgBtErr "boringtun-cli in ${RELEASE_ID} does not match the binary_sha256 of its MANIFEST"
		return 1
	fi
	CANONICAL_STORE="$(readlink -f -- "${STORE}")" || CANONICAL_STORE=""
	CANONICAL_BINARY="$(readlink -f -- "${BINARY}")" || CANONICAL_BINARY=""
	if [[ -z "${CANONICAL_STORE}" || "${CANONICAL_BINARY}" != "${CANONICAL_STORE}/${RELEASE_ID}/boringtun-cli" ]]; then
		_awgBtErr "boringtun-cli resolves outside the BoringTun store"
		return 1
	fi
	_AWG_BT_VERIFIED_BIN="${CANONICAL_BINARY}"
	_AWG_BT_VERIFIED_VERSION="${FIELDS[version]}"
}

# The runtime file carries launcher settings rendered from params, never read
# from the environment. Format 1 has an allowlist of optional keys:
# IMITATE_PROTOCOL and IMITATE_DOMAIN, the protocol imitation, rendered only
# when it is not none. A file without them, such as the one an earlier
# installer version wrote, means no imitation.
function _awgBtRuntimeFilePath() {
	printf '%s/%s.boringtun\n' "${AWG_BT_CONFIG_DIR}" "$1"
}

function _awgBtRenderRuntimeFile() {
	local PROTOCOL="${AWG_BORINGTUN_IMITATE_PROTOCOL:-none}" DOMAIN="${AWG_BORINGTUN_IMITATE_DOMAIN:-}"
	_awgBtImitationCheck "${PROTOCOL}" "${DOMAIN}" || return 1
	printf '# Managed by amneziawg-install (backend: boringtun). Regenerated from params.\n'
	printf 'FORMAT=1\n'
	if [[ "${PROTOCOL}" != none ]]; then
		printf 'IMITATE_PROTOCOL=%s\n' "${PROTOCOL}"
		[[ -z "${DOMAIN}" ]] || printf 'IMITATE_DOMAIN=%s\n' "${DOMAIN}"
	fi
}

function _awgBtReadRuntimeFile() {
	local FILE LINE KEY VALUE OWNER="" MODE=""
	local -A SEEN=()
	_AWG_BT_IMITATE_PROTOCOL=none
	_AWG_BT_IMITATE_DOMAIN=""
	FILE="$(_awgBtRuntimeFilePath "$1")"
	if [[ -L "${FILE}" || ! -f "${FILE}" ]]; then
		_awgBtErr "the BoringTun runtime file ${FILE} is missing or not a regular file"
		return 1
	fi
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${FILE}")"
	if [[ "${OWNER}" != "${AWG_BT_TRUSTED_UID}" || "${MODE}" != 600 ]] || ! _awgBtTrustedAncestors "${FILE}"; then
		_awgBtErr "the BoringTun runtime file ${FILE} must be owned by root with mode 0600 in a root-owned directory"
		return 1
	fi
	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		[[ -z "${LINE}" || "${LINE}" == "#"* ]] && continue
		if [[ ! "${LINE}" =~ ^([A-Z][A-Z0-9_]*)=([^[:cntrl:]]*)$ ]]; then
			_awgBtErr "malformed line in ${FILE}"
			return 1
		fi
		KEY="${BASH_REMATCH[1]}"
		VALUE="${BASH_REMATCH[2]}"
		if [[ -n "${SEEN[${KEY}]+set}" ]]; then
			_awgBtErr "repeated key ${KEY} in ${FILE}"
			return 1
		fi
		SEEN["${KEY}"]=1
		case "${KEY}" in
			FORMAT)
				if [[ "${VALUE}" != 1 ]]; then
					_awgBtErr "unsupported FORMAT ${VALUE} in ${FILE}"
					return 1
				fi
				;;
			IMITATE_PROTOCOL)
				# none is never rendered: the key's absence says it.
				if [[ "${VALUE}" == none ]] || ! _awgBtImitationProtocolValid "${VALUE}"; then
					_awgBtErr "invalid IMITATE_PROTOCOL in ${FILE}"
					return 1
				fi
				_AWG_BT_IMITATE_PROTOCOL="${VALUE}"
				;;
			IMITATE_DOMAIN)
				_AWG_BT_IMITATE_DOMAIN="${VALUE}"
				;;
			*)
				_awgBtErr "unknown key ${KEY} in ${FILE}"
				return 1
				;;
		esac
	done <"${FILE}"
	if [[ -z "${SEEN[FORMAT]+set}" ]]; then
		_awgBtErr "${FILE} has no FORMAT"
		return 1
	fi
	if [[ -n "${SEEN[IMITATE_DOMAIN]+set}" && -z "${_AWG_BT_IMITATE_DOMAIN}" ]] ||
		! _awgBtImitationCheck "${_AWG_BT_IMITATE_PROTOCOL}" "${_AWG_BT_IMITATE_DOMAIN}"; then
		_awgBtErr "invalid protocol imitation in ${FILE}"
		return 1
	fi
}

function _awgBtPidFile() {
	printf '%s/boringtun-%s.pid\n' "${AWG_BT_RUN_DIR}" "$1"
}

# The private runtime directory: a root-owned 0700 directory, never a symlink.
function _awgBtPrepareRunDir() {
	local OWNER="" MODE=""
	[[ ! -L "${AWG_BT_RUN_DIR}" ]] || return 1
	if [[ ! -d "${AWG_BT_RUN_DIR}" ]]; then
		mkdir -m 0700 -- "${AWG_BT_RUN_DIR}" 2>/dev/null || [[ -d "${AWG_BT_RUN_DIR}" ]] || return 1
	fi
	chmod 0700 -- "${AWG_BT_RUN_DIR}" 2>/dev/null || return 1
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${AWG_BT_RUN_DIR}")"
	[[ ! -L "${AWG_BT_RUN_DIR}" && -d "${AWG_BT_RUN_DIR}" && "${OWNER}" == "${AWG_BT_TRUSTED_UID}" && "${MODE}" == 700 ]]
}

# Replace one state file in the runtime directory atomically. mv -T refuses to
# move the new file into a directory that took the state file's name.
function _awgBtWriteState() {
	local FILE="$1" CONTENT="$2" TMP
	TMP="$(mktemp "${FILE}.XXXXXX")" || return 1
	if printf '%s' "${CONTENT}" >"${TMP}" && mv -fT -- "${TMP}" "${FILE}"; then
		return 0
	fi
	rm -f -- "${TMP}"
	return 1
}

# The live UDP port of the interface, from its UAPI, as a plain number.
function _awgBtListenPort() {
	local PORT
	PORT="$(awg show "$1" listen-port 2>/dev/null)" || return 1
	[[ "${PORT}" =~ ^[0-9]{1,5}$ ]] && ((10#${PORT} <= 65535)) || return 1
	printf '%s\n' "$((10#${PORT}))"
}

# Ready means both UAPI socket paths exist and the daemon answers.
function _awgBtUapiReady() {
	[[ -S "${AWG_BT_WG_SOCKET_DIR}/$1.sock" && -e "${AWG_BT_AWG_SOCKET_DIR}/$1.sock" ]] &&
		_awgBtListenPort "$1" >/dev/null
}

function _awgBtLinkExists() {
	[[ -e "${AWG_BT_SYS_DIR}/class/net/$1" ]]
}

# BoringTun's link is a TUN device, which the kernel's AmneziaWG link is not.
function _awgBtLinkIsTun() {
	[[ -e "${AWG_BT_SYS_DIR}/class/net/$1/tun_flags" ]]
}

function _awgBtLinkIndex() {
	local INDEX
	INDEX="$(cat -- "${AWG_BT_SYS_DIR}/class/net/$1/ifindex" 2>/dev/null)" || return 1
	[[ "${INDEX}" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
	printf '%s\n' "${INDEX}"
}

# The same membership test awg-quick down uses.
function _awgBtListedByAwg() {
	[[ " $(awg show interfaces 2>/dev/null) " == *" $1 "* ]]
}

# The fields of /proc/<pid>/stat that follow the command name: the state
# (field 3) is the first and the start time (field 22) the twentieth.
function _awgBtProcStat() {
	local STAT
	[[ "${1:-}" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
	STAT="$(cat -- "${AWG_BT_PROC_DIR}/$1/stat" 2>/dev/null)" || return 1
	[[ "${STAT}" == *") "* ]] || return 1
	printf '%s\n' "${STAT##*) }"
}

# The start time of a process, which tells it from a later process that reuses
# its PID. A zombie still has one.
function _awgBtProcessStartTime() {
	local -a FIELDS=()
	read -r -a FIELDS <<<"$(_awgBtProcStat "${1:-}")"
	[[ "${FIELDS[19]:-}" =~ ^[0-9]{1,20}$ ]] || return 1
	printf '%s\n' "${FIELDS[19]}"
}

# A PID is alive while /proc lists it and it is neither a zombie nor dead.
function _awgBtProcessAlive() {
	local -a FIELDS=()
	read -r -a FIELDS <<<"$(_awgBtProcStat "${1:-}")"
	[[ -n "${FIELDS[0]:-}" && "${FIELDS[0]}" != [ZXx] ]]
}

# PID is still the live process that started at START. A zombie, a process
# with another start time and a PID that /proc does not list all fail: the
# runtime treats them as gone and never signals them.
function _awgBtProcessIs() {
	local PID="${1:-}" START="${2:-}"
	local -a FIELDS=()
	[[ "${PID}" =~ ^[1-9][0-9]{0,9}$ && "${START}" =~ ^[0-9]{1,20}$ ]] || return 1
	read -r -a FIELDS <<<"$(_awgBtProcStat "${PID}")"
	[[ -n "${FIELDS[0]:-}" && "${FIELDS[0]}" != [ZXx] && "${FIELDS[19]:-}" == "${START}" ]]
}

# Send SIGNAL to PID only while it is the process that started at START. PID 1
# and the calling process are never signalled.
function _awgBtSignalProcess() { # <pid> <start time> <signal>
	[[ "${1:-}" =~ ^[1-9][0-9]{0,9}$ ]] || return 1
	(($1 > 1 && $1 != $$ && $1 != BASHPID)) || return 1
	_awgBtProcessIs "$1" "$2" || return 1
	kill "-$3" "$1" 2>/dev/null
}

# Stop an identified process: SIGTERM, up to five seconds, then SIGKILL, with
# its identity checked again before each signal. It returns 1 only if the
# process still runs. Bash cannot signal through a pidfd, so a PID reused in
# the instant between a check and the kill that follows it remains possible.
function _awgBtStopProcess() { # <pid> <start time>
	local PID="$1" START="$2" I
	_awgBtSignalProcess "${PID}" "${START}" TERM || return 0
	for ((I = 0; I < 50; I++)); do
		_awgBtProcessIs "${PID}" "${START}" || return 0
		sleep 0.1
	done
	_awgBtSignalProcess "${PID}" "${START}" KILL || return 0
	for ((I = 0; I < 30; I++)); do
		_awgBtProcessIs "${PID}" "${START}" || return 0
		sleep 0.1
	done
	return 1
}

# "<device>:<inode>:<raw mode>:<ctime in ns>" of the node at a path, never
# following a final symlink. A UAPI socket node is recorded this way while its
# daemon runs. The kernel reuses a freed inode number at once, so the change
# time is what tells a node from its replacement.
function _awgBtPathId() {
	[[ -e "$1" || -L "$1" ]] || return 1
	stat -c '%d:%i:%f:%.9Z' -- "$1" 2>/dev/null
}

# Whether the node recorded as ID is provably gone from PATH. What is at PATH
# is one of:
#   ABSENT     proven absent (_awgBtPathAbsent): gone, returns 0;
#   DIFFERENT  its identity was read and is not ID: a replacement, gone,
#              returns 0;
#   MATCH      its identity was read and is ID: still there, returns 1;
#   UNKNOWN    its identity cannot be read and its absence cannot be proven:
#              it may still be there, returns 2.
# A failed identity query is never taken for a different or an absent node.
function _awgBtRecordedNodeGone() { # <path> <recorded id>
	local CURRENT
	if CURRENT="$(_awgBtPathId "$1")" && [[ "${CURRENT}" =~ ^[0-9]+:[0-9]+:[0-9a-f]+:[0-9]+\.[0-9]{9}$ ]]; then
		[[ "${CURRENT}" != "$2" ]]
		return
	fi
	_awgBtPathAbsent "$1" && return 0
	return 2
}

# Remove the node at PATH only if it is still the node recorded as ID and the
# process PID/START that created it is gone. An unrecorded node and one whose
# daemon may still serve it are left alone, and that is no failure; neither is
# a recorded node that is provably gone (_awgBtRecordedNodeGone). It fails (1)
# while the exact recorded node of a dead owner may still be there: it is
# still there after the removal, or its identity cannot be read and its
# absence cannot be proven, before or after the removal. That cleanup is
# incomplete, and the record that proves the node BoringTun's must be kept. A
# failed awg query is never evidence either way.
function _awgBtRemoveOwnedPath() { # <path> <id> <pid> <start time>
	[[ -n "$2" && -n "$3" && -n "$4" ]] || return 0
	_awgBtProcessIs "$3" "$4" && return 0
	_awgBtRecordedNodeGone "$1" "$2"
	case $? in
		0) return 0 ;;
		1) ;;
		*) return 1 ;;
	esac
	rm -f -- "$1" 2>/dev/null
	_awgBtRecordedNodeGone "$1" "$2" || return 1
}

# The node at PATH is a UNIX socket that the live process PID/START holds open:
# one of the socket inodes in /proc/<pid>/fd is, by ss's socket diagnostics,
# bound to exactly this file (its inode and device). A socket that another
# process bound at the path, or a node that changed during the check, is not
# the daemon's. Prints the node's identity.
function _awgBtSocketHeldBy() { # <path> <pid> <start time>
	local NODE="$1" PID="$2" START="$3" ID FS_DEV="" FS_INO="" MAJOR MINOR FD LINK HELD=" "
	[[ -S "${NODE}" && ! -L "${NODE}" ]] || return 1
	_awgBtProcessIs "${PID}" "${START}" || return 1
	ID="$(_awgBtPathId "${NODE}")" || return 1
	read -r FS_DEV FS_INO <<<"$(stat -c '%d %i' -- "${NODE}" 2>/dev/null)"
	[[ "${FS_DEV}" =~ ^[0-9]+$ && "${FS_INO}" =~ ^[0-9]+$ ]] || return 1
	MAJOR=$(((FS_DEV >> 8) & 0xfff))
	MINOR=$(((FS_DEV & 0xff) | ((FS_DEV >> 12) & 0xfff00)))
	for FD in "${AWG_BT_PROC_DIR}/${PID}/fd/"*; do
		LINK="$(readlink -- "${FD}" 2>/dev/null)" || continue
		[[ "${LINK}" =~ ^socket:\[([0-9]+)\]$ ]] && HELD+="${BASH_REMATCH[1]} "
	done
	[[ "${HELD}" != " " ]] || return 1
	ss -xlHe 2>/dev/null | awk -v ino="${FS_INO}" -v dev="${FS_DEV}" -v major="${MAJOR}" -v minor="${MINOR}" -v held="${HELD}" '
		{
			vino = ""; vmaj = ""; vmin = ""
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^ino:[0-9]+$/) vino = substr($i, 5)
				if ($i ~ /^dev:[0-9]+\/[0-9]+$/) { split(substr($i, 5), d, "/"); vmaj = d[1]; vmin = d[2] }
			}
			if (vino == ino && ((vmaj == 0 && vmin == dev) || (vmaj == major && vmin == minor)) && index(held, " " $6 " ")) found = 1
		}
		END { exit !found }' || return 1
	_awgBtProcessIs "${PID}" "${START}" || return 1
	[[ "$(_awgBtPathId "${NODE}")" == "${ID}" ]] || return 1
	printf '%s\n' "${ID}"
}

# BoringTun makes the AmneziaWG UAPI path a symlink to its WireGuard socket. A
# symlink cannot be tied to a process, so it counts as the daemon's only while
# it resolves to the socket node just proven to be the daemon's. Prints the
# symlink's own identity.
function _awgBtSymlinkToNode() { # <link> <node path> <node identity>
	local ID
	[[ -L "$1" ]] || return 1
	ID="$(_awgBtPathId "$1")" || return 1
	[[ "$(readlink -f -- "$1" 2>/dev/null)" == "$(readlink -f -- "$2" 2>/dev/null)" ]] || return 1
	[[ "$(_awgBtPathId "$2")" == "$3" && "$(_awgBtPathId "$1")" == "${ID}" ]] || return 1
	printf '%s\n' "${ID}"
}

# Prove which UAPI nodes of the interface belong to the live daemon PID/START
# and set _AWG_BT_WG_ID and _AWG_BT_AWG_ID to their identities, or to "" for a
# node that is absent or not provably the daemon's.
function _awgBtProveUapiNodes() { # <interface> <pid> <start time>
	local WG="${AWG_BT_WG_SOCKET_DIR}/$1.sock" AWG="${AWG_BT_AWG_SOCKET_DIR}/$1.sock"
	_AWG_BT_WG_ID="$(_awgBtSocketHeldBy "${WG}" "$2" "$3")" || _AWG_BT_WG_ID=""
	_AWG_BT_AWG_ID=""
	if [[ -S "${AWG}" && ! -L "${AWG}" ]]; then
		_AWG_BT_AWG_ID="$(_awgBtSocketHeldBy "${AWG}" "$2" "$3")" || _AWG_BT_AWG_ID=""
	elif [[ -n "${_AWG_BT_WG_ID}" ]]; then
		_AWG_BT_AWG_ID="$(_awgBtSymlinkToNode "${AWG}" "${WG}" "${_AWG_BT_WG_ID}")" || _AWG_BT_AWG_ID=""
	fi
	return 0
}

function _awgBtNewToken() {
	local TOKEN
	TOKEN="$(od -An -N16 -tx1 /dev/urandom 2>/dev/null)" || return 1
	TOKEN="${TOKEN//[[:space:]]/}"
	[[ "${TOKEN}" =~ ^[0-9a-f]{32}$ ]] || return 1
	printf '%s\n' "${TOKEN}"
}

# ── Service ownership state ─────────────────────────────────────────────────
# Cleanup authority belongs to one start attempt. The attempt is systemd's
# INVOCATION_ID, which every Exec* command of one activation of
# awg-quick@<if> shares and which is new for every start and restart;
# awgBackendQuickUp passes its own random token the same way. Everything the
# attempt records is named <run dir>/<if>@<attempt>, so no hook ever reads, or
# acts on, what an earlier attempt left behind, and nothing an earlier attempt
# left is deleted by a later one.
#
# <if>@<attempt>.state is a root-owned 0600 file that is replaced atomically,
# parsed against a strict allowlist and never sourced. The hooks write it in
# turn:
#   precheck   ATTEMPT, CONFIG, PRE_EXISTING (a link, socket or awg interface
#              of the name already existed), PHASE=started, then prechecked
#   launcher   PHASE=launching with the daemon's PID and PID_START, the socket
#              nodes proven to be the daemon's (WG_SOCK, AWG_SOCK), then
#              PHASE=launched with the TUN link's IFINDEX
#   poststart  IFINDEX when awg-quick made a kernel link instead
#   stop and poststop  DOWN=failed-intact or failed after a failed down
# Transitions that must hold even when the runtime directory can allocate
# nothing new are flags: precheck creates <if>@<attempt>.<flag>-pending for
# each, and the transition only renames it to <if>@<attempt>.<flag>:
#   up      awg-quick up succeeded, so PostUp ran (poststart)
#   down    an awg-quick down of the owned link is starting
#   done    that awg-quick down succeeded
#   replay  a PostDown replay is starting; its hooks may have run
# Without a readable state of the current attempt nothing is owned, and
# nothing but the service's PID file is removed.
function _awgBtCurrentAttempt() {
	_AWG_BT_ATTEMPT=""
	[[ "${INVOCATION_ID:-}" =~ ^[0-9a-f]{32}$ ]] || return 1
	_AWG_BT_ATTEMPT="${INVOCATION_ID}"
}

function _awgBtAttemptBase() {
	printf '%s/%s@%s\n' "${AWG_BT_RUN_DIR}" "$1" "${_AWG_BT_ATTEMPT}"
}

function _awgBtStateFile() {
	printf '%s.state\n' "$(_awgBtAttemptBase "$1")"
}

function _awgBtFlagsArm() { # <interface>
	local BASE FLAG
	BASE="$(_awgBtAttemptBase "$1")"
	for FLAG in up down "done" replay; do
		_awgBtWriteState "${BASE}.${FLAG}-pending" "" || return 1
	done
}

function _awgBtFlagRaise() { # <interface> <flag>
	local BASE
	BASE="$(_awgBtAttemptBase "$1")"
	[[ -f "${BASE}.$2-pending" && ! -L "${BASE}.$2-pending" && ! -e "${BASE}.$2" ]] || return 1
	mv -T -- "${BASE}.$2-pending" "${BASE}.$2" 2>/dev/null
}

function _awgBtFlagIs() { # <interface> <flag>
	local BASE
	BASE="$(_awgBtAttemptBase "$1")"
	[[ -f "${BASE}.$2" && ! -L "${BASE}.$2" ]]
}

function _awgBtAttemptRemove() { # <interface>
	local BASE
	BASE="$(_awgBtAttemptBase "$1")"
	rm -f -- "${BASE}.state" "${BASE}.up" "${BASE}.up-pending" "${BASE}.down" "${BASE}.down-pending" \
		"${BASE}.done" "${BASE}.done-pending" "${BASE}.replay" "${BASE}.replay-pending"
}

function _awgBtStateValueValid() { # <key> <value>
	case "$1" in
		FORMAT) [[ "$2" == 1 ]] ;;
		ATTEMPT) [[ "$2" =~ ^[0-9a-f]{32}$ ]] ;;
		CONFIG) [[ "$2" =~ ^/[^[:cntrl:]]*\.conf$ ]] ;;
		PRE_EXISTING) [[ "$2" == 0 || "$2" == 1 ]] ;;
		PHASE) [[ "$2" =~ ^(started|prechecked|launching|launched|launch-failed)$ ]] ;;
		PID | IFINDEX) [[ "$2" =~ ^([1-9][0-9]{0,9})?$ ]] ;;
		PID_START) [[ "$2" =~ ^([0-9]{1,20})?$ ]] ;;
		WG_SOCK | AWG_SOCK) [[ "$2" =~ ^([0-9]+:[0-9]+:[0-9a-f]+:[0-9]+\.[0-9]{9})?$ ]] ;;
		DOWN) [[ "$2" =~ ^(none|failed-intact|failed)$ ]] ;;
		*) return 1 ;;
	esac
}

# A fresh record of the current attempt in _AWG_BT_STATE, not yet saved.
function _awgBtStateNew() { # <config>
	[[ -n "${_AWG_BT_ATTEMPT}" ]] || return 1
	_AWG_BT_STATE=([FORMAT]=1 [ATTEMPT]="${_AWG_BT_ATTEMPT}" [CONFIG]="$1" [PRE_EXISTING]=0 [PHASE]=started
		[PID]="" [PID_START]="" [IFINDEX]="" [WG_SOCK]="" [AWG_SOCK]="" [DOWN]=none)
}

function _awgBtStateSave() { # <interface>
	local KEY CONTENT=""
	for KEY in FORMAT ATTEMPT CONFIG PRE_EXISTING PHASE PID PID_START IFINDEX WG_SOCK AWG_SOCK DOWN; do
		_awgBtStateValueValid "${KEY}" "${_AWG_BT_STATE[${KEY}]-}" || return 1
		CONTENT+="${KEY}=${_AWG_BT_STATE[${KEY}]-}"$'\n'
	done
	_awgBtWriteState "$(_awgBtStateFile "$1")" "${CONTENT}"
}

function _awgBtStateLoad() { # <interface>
	local FILE LINE KEY VALUE OWNER="" MODE=""
	_AWG_BT_STATE=()
	[[ -n "${_AWG_BT_ATTEMPT}" ]] || return 1
	FILE="$(_awgBtStateFile "$1")"
	[[ ! -L "${FILE}" && -f "${FILE}" ]] || return 1
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${FILE}")"
	if [[ "${OWNER}" != "${AWG_BT_TRUSTED_UID}" || "${MODE}" != 600 ]]; then
		_awgBtErr "ignoring ${FILE}: it is not a root-owned 0600 file"
		return 1
	fi
	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		if [[ ! "${LINE}" =~ ^([A-Z_]+)=(.*)$ ]]; then
			_AWG_BT_STATE=()
			_awgBtErr "ignoring ${FILE}: malformed line"
			return 1
		fi
		KEY="${BASH_REMATCH[1]}"
		VALUE="${BASH_REMATCH[2]}"
		if [[ -n "${_AWG_BT_STATE[${KEY}]+set}" ]] || ! _awgBtStateValueValid "${KEY}" "${VALUE}"; then
			_AWG_BT_STATE=()
			_awgBtErr "ignoring ${FILE}: unexpected, repeated or invalid ${KEY}"
			return 1
		fi
		_AWG_BT_STATE["${KEY}"]="${VALUE}"
	done <"${FILE}"
	for KEY in FORMAT ATTEMPT CONFIG PRE_EXISTING PHASE PID PID_START IFINDEX WG_SOCK AWG_SOCK DOWN; do
		if [[ -z "${_AWG_BT_STATE[${KEY}]+set}" ]]; then
			_AWG_BT_STATE=()
			_awgBtErr "ignoring ${FILE}: it has no ${KEY}"
			return 1
		fi
	done
	if [[ "${_AWG_BT_STATE[ATTEMPT]}" != "${_AWG_BT_ATTEMPT}" || "${_AWG_BT_STATE[CONFIG]}" != */"$1".conf ]]; then
		_AWG_BT_STATE=()
		_awgBtErr "ignoring ${FILE}: it does not describe attempt ${_AWG_BT_ATTEMPT} of $1"
		return 1
	fi
}

# The one BoringTun command line, shared by the launcher and scratch
# interfaces: an empty environment apart from PATH and NO_COLOR, so no WG_*
# variable reaches the daemon, the foreground daemon, root privileges kept
# (its getlogin() based drop fails under systemd), the quietest log level and
# the protocol imitation, always named. --probe-reply-rate is never passed, so
# the binary's own default applies. The imitation is checked again here, since
# the binary would reject a bad pair only after the launcher started it.
function _awgBtDaemonArgv() { # <binary> <interface> [<protocol> [<domain>]]
	local ENV_BIN PROTOCOL="${3:-none}" DOMAIN="${4:-}"
	_awgBtImitationCheck "${PROTOCOL}" "${DOMAIN}" || return 1
	ENV_BIN="$(command -v env)" || return 1
	_AWG_BT_ARGV=("${ENV_BIN}" -i "PATH=${AWG_BT_PATH}" NO_COLOR=1 "$1" --foreground --disable-drop-privileges --verbosity error
		--imitate-protocol "${PROTOCOL}")
	[[ -z "${DOMAIN}" ]] || _AWG_BT_ARGV+=(--imitate-domain "${DOMAIN}")
	_AWG_BT_ARGV+=("$2")
}

# Close every descriptor above stderr. The daemon and the scratch guardian
# outlive their caller, and an inherited descriptor would keep, for example,
# the installer's lifecycle lock held for as long as they run.
function _awgBtCloseInheritedFds() {
	local FD
	for FD in /proc/self/fd/*; do
		FD="${FD##*/}"
		if [[ "${FD}" =~ ^[0-9]+$ ]] && ((FD > 2)); then
			eval "exec ${FD}>&-" 2>/dev/null
		fi
	done
	return 0
}

# ── awg-boringtun-launch ─────────────────────────────────────────────────────
# awg-quick runs this, as WG_QUICK_USERSPACE_IMPLEMENTATION, with the interface
# name as its only argument, and continues with `awg setconf` as soon as it
# returns. It serves only an attempt that passed precheck, and only while no
# link or UAPI socket of the name exists. It starts the verified BoringTun
# binary as its child and records the child's PID and start time, then each
# socket node as the child creates it, in the attempt's state. Only once the
# UAPI answers does it write the PID file that systemd's Type=forking unit
# tracks. On any failure it stops the child and removes only the socket nodes
# that child was seen to create.
function awgBoringtunLaunchMain() {
	local INTERFACE_NAME="${1:-}" PID_FILE WG_PATH AWG_PATH CHILD CHILD_START="" INDEX="" I LIMIT
	if [[ $# -ne 1 ]] || ! _awgBtValidInterfaceName "${INTERFACE_NAME}"; then
		_awgBtErr "usage: awg-boringtun-launch <interface>"
		return 2
	fi
	_awgBtVerifyStore || return 1
	_awgBtReadRuntimeFile "${INTERFACE_NAME}" || return 1
	# An imitation the verified binary does not know would only surface as a
	# usage error of the daemon; it is refused here, before anything starts.
	if ! _awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "${_AWG_BT_IMITATE_PROTOCOL}"; then
		_awgBtErr "the verified BoringTun binary ${_AWG_BT_VERIFIED_BIN} does not support protocol imitation ${_AWG_BT_IMITATE_PROTOCOL}, or did not say that it does; run amneziawg-install.sh --upgrade-boringtun, or select another imitation with amneziawg-install.sh --set-boringtun-imitation"
		return 1
	fi
	if ! _awgBtPrepareRunDir; then
		_awgBtErr "cannot prepare the private runtime directory ${AWG_BT_RUN_DIR}"
		return 1
	fi
	if ! _awgBtCurrentAttempt || ! _awgBtStateLoad "${INTERFACE_NAME}" || [[ "${_AWG_BT_STATE[PHASE]}" != prechecked ]]; then
		_awgBtErr "${INTERFACE_NAME} has not passed awg-backend-ctl precheck for this start"
		return 1
	fi
	WG_PATH="${AWG_BT_WG_SOCKET_DIR}/${INTERFACE_NAME}.sock"
	AWG_PATH="${AWG_BT_AWG_SOCKET_DIR}/${INTERFACE_NAME}.sock"
	if _awgBtLinkExists "${INTERFACE_NAME}" || [[ -e "${WG_PATH}" || -L "${WG_PATH}" || -e "${AWG_PATH}" || -L "${AWG_PATH}" ]]; then
		_awgBtErr "refusing to start BoringTun: a link or UAPI socket named ${INTERFACE_NAME} appeared after precheck; it is left untouched"
		_awgBtLaunchRefused "${INTERFACE_NAME}"
		return 1
	fi
	PID_FILE="$(_awgBtPidFile "${INTERFACE_NAME}")"
	rm -f -- "${PID_FILE}"
	if ! _awgBtDaemonArgv "${_AWG_BT_VERIFIED_BIN}" "${INTERFACE_NAME}" "${_AWG_BT_IMITATE_PROTOCOL}" "${_AWG_BT_IMITATE_DOMAIN}"; then
		_awgBtLaunchRefused "${INTERFACE_NAME}"
		return 1
	fi
	(
		_awgBtCloseInheritedFds
		exec "${_AWG_BT_ARGV[@]}" </dev/null
	) &
	CHILD=$!
	# Bash reaps a background child as soon as it exits, so its PID alone does
	# not identify it for long; its start time does.
	CHILD_START="$(_awgBtProcessStartTime "${CHILD}")" || CHILD_START=""
	_AWG_BT_STATE[PHASE]=launching
	_AWG_BT_STATE[PID]="${CHILD}"
	_AWG_BT_STATE[PID_START]="${CHILD_START}"
	if [[ -z "${CHILD_START}" ]] || ! _awgBtStateSave "${INTERFACE_NAME}"; then
		_awgBtErr "cannot record the BoringTun daemon of ${INTERFACE_NAME}"
		_awgBtLaunchFailed "${INTERFACE_NAME}" "${CHILD}"
		return 1
	fi
	LIMIT=$((AWG_BT_READY_TIMEOUT * 10))
	for ((I = 0; I < LIMIT; I++)); do
		if ! _awgBtProcessIs "${CHILD}" "${CHILD_START}"; then
			_awgBtErr "boringtun-cli exited before ${INTERFACE_NAME} became ready"
			_awgBtLaunchFailed "${INTERFACE_NAME}" "${CHILD}"
			return 1
		fi
		if ! _awgBtRecordSocketNodes "${INTERFACE_NAME}"; then
			_awgBtErr "cannot record the UAPI sockets of ${INTERFACE_NAME}"
			_awgBtLaunchFailed "${INTERFACE_NAME}" "${CHILD}"
			return 1
		fi
		if [[ -n "${_AWG_BT_STATE[WG_SOCK]}" && -n "${_AWG_BT_STATE[AWG_SOCK]}" ]] &&
			_awgBtLinkIsTun "${INTERFACE_NAME}" && INDEX="$(_awgBtLinkIndex "${INTERFACE_NAME}")" &&
			_awgBtUapiReady "${INTERFACE_NAME}"; then
			# The nodes as the ready daemon holds them, in case they changed
			# since they were first proven.
			_awgBtProveUapiNodes "${INTERFACE_NAME}" "${CHILD}" "${CHILD_START}"
			if [[ -z "${_AWG_BT_WG_ID}" || -z "${_AWG_BT_AWG_ID}" ]]; then
				sleep 0.1
				continue
			fi
			_AWG_BT_STATE[WG_SOCK]="${_AWG_BT_WG_ID}"
			_AWG_BT_STATE[AWG_SOCK]="${_AWG_BT_AWG_ID}"
			_AWG_BT_STATE[PHASE]=launched
			_AWG_BT_STATE[IFINDEX]="${INDEX}"
			if _awgBtStateSave "${INTERFACE_NAME}" && _awgBtWriteState "${PID_FILE}" "${CHILD}"$'\n'; then
				return 0
			fi
			_awgBtErr "cannot record that ${INTERFACE_NAME} is ready"
			_awgBtLaunchFailed "${INTERFACE_NAME}" "${CHILD}"
			return 1
		fi
		sleep 0.1
	done
	_awgBtErr "${INTERFACE_NAME} did not become ready within ${AWG_BT_READY_TIMEOUT} seconds"
	_awgBtLaunchFailed "${INTERFACE_NAME}" "${CHILD}"
	return 1
}

# Record each UAPI node that is now proven to belong to the launched daemon.
function _awgBtRecordSocketNodes() { # <interface>
	local CHANGED=0
	_awgBtProveUapiNodes "$1" "${_AWG_BT_STATE[PID]}" "${_AWG_BT_STATE[PID_START]}"
	if [[ -z "${_AWG_BT_STATE[WG_SOCK]}" && -n "${_AWG_BT_WG_ID}" ]]; then
		_AWG_BT_STATE[WG_SOCK]="${_AWG_BT_WG_ID}"
		CHANGED=1
	fi
	if [[ -z "${_AWG_BT_STATE[AWG_SOCK]}" && -n "${_AWG_BT_AWG_ID}" ]]; then
		_AWG_BT_STATE[AWG_SOCK]="${_AWG_BT_AWG_ID}"
		CHANGED=1
	fi
	((CHANGED == 0)) || _awgBtStateSave "$1"
}

# The launcher refused before it started anything: the attempt owns nothing,
# and awg-quick up stops before any PostUp hook, so poststop may finish it.
function _awgBtLaunchRefused() { # <interface>
	_AWG_BT_STATE[PHASE]=launch-failed
	_awgBtStateSave "$1" || _awgBtErr "cannot record that the launch of $1 failed"
}

# Stop and reap the launcher's child, then remove the socket nodes proven to be
# that child's and the PID file. When all of that succeeded, the attempt is
# recorded as launch-failed: awg-quick up then fails at once, before any
# PostUp hook, which lets poststop finish the attempt.
function _awgBtLaunchFailed() { # <interface> <child pid>
	local CLEAN=1
	# A child whose start time could not be read had already exited and been
	# reaped, so its PID may name another process by now: it is not signalled.
	if [[ -n "${_AWG_BT_STATE[PID_START]-}" ]]; then
		_awgBtStopProcess "$2" "${_AWG_BT_STATE[PID_START]}" || CLEAN=0
	fi
	wait "$2" 2>/dev/null
	_awgBtRemoveOwnedPath "${AWG_BT_WG_SOCKET_DIR}/$1.sock" "${_AWG_BT_STATE[WG_SOCK]-}" "$2" "${_AWG_BT_STATE[PID_START]-}" || CLEAN=0
	_awgBtRemoveOwnedPath "${AWG_BT_AWG_SOCKET_DIR}/$1.sock" "${_AWG_BT_STATE[AWG_SOCK]-}" "$2" "${_AWG_BT_STATE[PID_START]-}" || CLEAN=0
	rm -f -- "$(_awgBtPidFile "$1")"
	if ((CLEAN)); then
		_AWG_BT_STATE[PHASE]=launch-failed
		_awgBtStateSave "$1" || _awgBtErr "cannot record that the launch of $1 failed"
	else
		_awgBtErr "what the failed launch of $1 created is not completely removed; its state is kept"
	fi
}

# Print each value of KEY in the [Interface] section of an awg-quick config,
# NUL-terminated and in file order, parsed the way awg-quick's parse_options
# parses it: `read -r` with the default IFS, text from the first # dropped, the
# key and value split at the first = and trimmed, and keys and section names
# compared case-insensitively. Only [Interface] counts; any other [...] line
# ends it.
function _awgBtInterfaceValues() {
	local CONFIG_FILE="$1" WANTED="$2" LINE STRIPPED KEY VALUE IN_INTERFACE=0 RC=0 RESTORE_NOCASE=0
	local IFS=$' \t\n'
	shopt -q nocasematch || RESTORE_NOCASE=1
	shopt -s nocasematch
	while read -r LINE || [[ -n "${LINE}" ]]; do
		STRIPPED="${LINE%%\#*}"
		KEY="${STRIPPED%%=*}"
		KEY="${KEY#"${KEY%%[![:space:]]*}"}"
		KEY="${KEY%"${KEY##*[![:space:]]}"}"
		VALUE="${STRIPPED#*=}"
		VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
		VALUE="${VALUE%"${VALUE##*[![:space:]]}"}"
		[[ "${KEY}" == "["* ]] && IN_INTERFACE=0
		[[ "${KEY}" == "[Interface]" ]] && IN_INTERFACE=1
		if ((IN_INTERFACE)) && [[ "${KEY}" == "${WANTED}" ]]; then
			printf '%s\0' "${VALUE}"
		fi
	done <"${CONFIG_FILE}" || RC=1
	((RESTORE_NOCASE)) && shopt -u nocasematch
	return "${RC}"
}

# Whether a config sets SaveConfig = true, read like awg-quick's read_bool:
# true or false in any case, the last one wins, anything else is invalid.
# Returns 0 for true, 1 for false or absent, 2 for invalid or unreadable.
function _awgBtSaveConfigEnabled() {
	local VALUE ENABLED=0
	local -a VALUES=()
	[[ -f "$1" && -r "$1" ]] || return 2
	mapfile -d '' -t VALUES < <(_awgBtInterfaceValues "$1" SaveConfig)
	for VALUE in ${VALUES[@]+"${VALUES[@]}"}; do
		case "${VALUE,,}" in
			true) ENABLED=1 ;;
			false) ENABLED=0 ;;
			*) return 2 ;;
		esac
	done
	((ENABLED)) && return 0
	return 1
}

# Replay the [Interface] PostDown hooks of CONFIG after the interface went away
# without awg-quick down running them. Like awg-quick's execute_hooks, each hook
# gets %i replaced and runs in its own shell with `set -e -o pipefail` and
# LC_ALL=C; unlike awg-quick, a failing hook is logged and the rest still run.
# PreDown and SaveConfig are never replayed.
function _awgBtReplayPostDown() { # <interface> <config>
	local INTERFACE_NAME="$1" CONFIG_FILE="$2" HOOK
	local -a HOOKS=()
	if [[ ! -f "${CONFIG_FILE}" || ! -r "${CONFIG_FILE}" ]]; then
		_awgBtErr "cannot replay PostDown hooks: ${CONFIG_FILE} is not readable"
		return 1
	fi
	mapfile -d '' -t HOOKS < <(_awgBtInterfaceValues "${CONFIG_FILE}" PostDown)
	for HOOK in ${HOOKS[@]+"${HOOKS[@]}"}; do
		HOOK="${HOOK//%i/${INTERFACE_NAME}}"
		printf '[#] %s\n' "${HOOK}" >&2
		if ! INTERFACE="${INTERFACE_NAME}" LC_ALL=C bash -e -o pipefail -c "${HOOK}"; then
			_awgBtErr "PostDown hook failed, continuing: ${HOOK}"
		fi
	done
	return 0
}

# awg-quick down was started but did not finish: its PostDown hooks may have
# run in part. They are never run a second time; name them instead.
function _awgBtReportUnfinishedDown() { # <interface> <config>
	local HOOK
	local -a HOOKS=()
	_awgBtErr "awg-quick down of $1 was started but did not finish, so its PostDown hooks may have run in part; they are not replayed, because no hook may run twice. Check by hand what these undo:"
	if [[ -f "$2" && -r "$2" ]]; then
		mapfile -d '' -t HOOKS < <(_awgBtInterfaceValues "$2" PostDown)
	fi
	for HOOK in ${HOOKS[@]+"${HOOKS[@]}"}; do
		_awgBtErr "  PostDown = ${HOOK//%i/$1}"
	done
}

# CONFIG without its [Interface] SaveConfig lines, which are found the way
# awg-quick's parse_options finds them; every other line is copied unchanged.
function _awgBtWithoutSaveConfig() { # <config>
	local LINE STRIPPED KEY IN_INTERFACE=0 RC=0 RESTORE_NOCASE=0
	shopt -q nocasematch || RESTORE_NOCASE=1
	shopt -s nocasematch
	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		STRIPPED="${LINE%%\#*}"
		KEY="${STRIPPED%%=*}"
		KEY="${KEY#"${KEY%%[![:space:]]*}"}"
		KEY="${KEY%"${KEY##*[![:space:]]}"}"
		[[ "${KEY}" == "["* ]] && IN_INTERFACE=0
		[[ "${KEY}" == "[Interface]" ]] && IN_INTERFACE=1
		if ((IN_INTERFACE)) && [[ "${KEY}" == SaveConfig ]]; then
			continue
		fi
		# Every write is checked: the loop's own status is that of its last
		# iteration, which may be a SaveConfig line left out.
		if ! printf '%s\n' "${LINE}"; then
			RC=1
			break
		fi
	done <"$1" || RC=1
	((RESTORE_NOCASE)) && shopt -u nocasematch
	return "${RC}"
}

# One complete attempt at the private down copy under TEMPLATE's directory: a
# new mktemp directory that must be a 0700 directory of the trusted user, the
# config without SaveConfig written into it as <if>.conf (the filter fails on
# any failed write), set to 0600 and checked, and not empty unless the config
# is. Any failure removes this attempt's own directory and fails.
function _awgBtTryDownCopy() { # <mktemp template> <interface> <config>
	local WORK OWNER="" MODE=""
	WORK="$(mktemp -d "$1" 2>/dev/null)" || return 1
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${WORK}")"
	if [[ ! -L "${WORK}" && -d "${WORK}" && "${OWNER}" == "${AWG_BT_TRUSTED_UID}" && "${MODE}" == 700 ]] &&
		{ _awgBtWithoutSaveConfig "$3" >"${WORK}/$2.conf"; } 2>/dev/null &&
		chmod 0600 -- "${WORK}/$2.conf" 2>/dev/null; then
		read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${WORK}/$2.conf")"
		if [[ ! -L "${WORK}/$2.conf" && -f "${WORK}/$2.conf" && "${OWNER}" == "${AWG_BT_TRUSTED_UID}" && "${MODE}" == 600 ]] &&
			[[ -s "${WORK}/$2.conf" || ! -s "$3" ]]; then
			printf '%s\n' "${WORK}"
			return 0
		fi
	fi
	rm -rf -- "${WORK}"
	return 1
}

# A private copy of CONFIG for awg-quick down, <dir>/<if>.conf without its
# SaveConfig lines. BoringTun's UAPI never returns the private key, so a save
# during down would write a keyless configuration over the real one, whatever
# the file said when the interface started. The copy keeps the interface's file
# name, so awg-quick derives the same interface and runs the same hooks. The
# whole copy is made in the runtime directory, and if any step of that fails,
# made again from scratch in AWG_BT_TMP_DIR (/tmp, not an inherited TMPDIR).
# Prints the directory.
function _awgBtDownCopy() { # <interface> <config>
	local WORK=""
	if [[ ! -f "$2" || ! -r "$2" ]]; then
		_awgBtErr "cannot bring $1 down: $2 is not readable"
		return 1
	fi
	if _awgBtPrepareRunDir && WORK="$(_awgBtTryDownCopy "${AWG_BT_RUN_DIR}/down.XXXXXX" "$1" "$2")"; then
		printf '%s\n' "${WORK}"
		return 0
	fi
	if WORK="$(_awgBtTryDownCopy "${AWG_BT_TMP_DIR}/awg-boringtun-down.XXXXXX" "$1" "$2")"; then
		printf '%s\n' "${WORK}"
		return 0
	fi
	_awgBtErr "cannot make a private down copy of $1 in ${AWG_BT_RUN_DIR} or ${AWG_BT_TMP_DIR}"
	return 1
}

# The link of the name is still the owned one: it has the owned ifindex, is of
# the expected kind (tun, kernel or any) and awg lists it.
function _awgBtLinkIsOwned() { # <interface> <tun|kernel|any> <ifindex>
	[[ -n "$3" && "$(_awgBtLinkIndex "$1")" == "$3" ]] || return 1
	case "$2" in
		tun) _awgBtLinkIsTun "$1" || return 1 ;;
		kernel) ! _awgBtLinkIsTun "$1" || return 1 ;;
	esac
	_awgBtListedByAwg "$1"
}

# awg-quick down of the owned link, through a private copy without SaveConfig.
# Preparing the copy can block, so right before the down the attempt's state
# is read again (it must still be this attempt's, with no down started) and the
# link must still be the owned one; only then is the down flag raised and
# awg-quick run. Two modes serve poststart's emergency cleanup: "noflag" when
# the up flag could not be raised either, so poststop will never replay
# PostDown and the down needs no flag, and "stateless" when the state is
# unusable, where only the link is checked again. Returns 0 when awg-quick down
# succeeded, 1 when it failed, 3 when it was not started, and 4 when the link
# or the attempt changed meanwhile, in which case nothing was touched.
function _awgBtGuardedDown() { # <interface> <config> <tun|kernel|any> <ifindex> [noflag|stateless]
	local INTERFACE_NAME="$1" WORK
	WORK="$(_awgBtDownCopy "${INTERFACE_NAME}" "$2")" || return 3
	if [[ "${5:-}" != stateless ]]; then
		if ! _awgBtStateLoad "${INTERFACE_NAME}" || _awgBtFlagIs "${INTERFACE_NAME}" down; then
			rm -rf -- "${WORK}"
			return 4
		fi
	fi
	if ! _awgBtLinkIsOwned "${INTERFACE_NAME}" "$3" "$4"; then
		rm -rf -- "${WORK}"
		return 4
	fi
	if [[ -z "${5:-}" ]] && ! _awgBtFlagRaise "${INTERFACE_NAME}" down; then
		rm -rf -- "${WORK}"
		_awgBtErr "cannot record that awg-quick down of ${INTERFACE_NAME} starts, so it is not run"
		return 3
	fi
	(
		trap 'rm -rf -- "${WORK}"' EXIT
		trap 'exit 1' HUP INT TERM
		awg-quick down "${WORK}/${INTERFACE_NAME}.conf"
	)
}

# Record how a failed guarded down ended: the link survived (awg-quick stops
# before deleting the link, which precedes every PostDown hook) or not.
function _awgBtRecordFailedDown() { # <interface> <ifindex>
	if [[ -n "$2" && "$(_awgBtLinkIndex "$1")" == "$2" ]]; then
		_AWG_BT_STATE[DOWN]=failed-intact
	else
		_AWG_BT_STATE[DOWN]=failed
	fi
	_awgBtStateSave "$1" || _awgBtErr "cannot record how awg-quick down of $1 ended"
}

# `awg-quick strip <if>` without its ListenPort line when that port is already
# the live one. Every UAPI set carrying listen_port makes BoringTun bind a new
# socket pair without closing the old one, so an unchanged port is left out; a
# changed port is kept. Lines are matched the way awg's own config parser reads
# them: comments dropped, whitespace ignored, names case-insensitive. Anything
# ambiguous fails instead of guessing. Diagnostics go to file descriptor $2.
function _awgBtFilteredStrip() {
	local INTERFACE_NAME="$1" DIAG_FD="$2" STRIPPED LINE CLEAN INDEX=0 PORT_INDEX=-1 COUNT=0
	local CONFIGURED="" LIVE="" IN_INTERFACE=0
	local -a LINES=()
	if ! STRIPPED="$(awg-quick strip "${INTERFACE_NAME}")"; then
		printf 'awg-quick strip failed for %s\n' "${INTERFACE_NAME}" >&"${DIAG_FD}"
		return 1
	fi
	mapfile -t LINES <<<"${STRIPPED}"
	for LINE in ${LINES[@]+"${LINES[@]}"}; do
		CLEAN="${LINE%%#*}"
		CLEAN="${CLEAN//[[:space:]]/}"
		if [[ "${CLEAN}" == "["* ]]; then
			IN_INTERFACE=0
			[[ "${CLEAN,,}" == "[interface]" ]] && IN_INTERFACE=1
		elif ((IN_INTERFACE)) && [[ "${CLEAN,,}" == listenport=* ]]; then
			COUNT=$((COUNT + 1))
			PORT_INDEX="${INDEX}"
			CONFIGURED="${CLEAN#*=}"
		fi
		INDEX=$((INDEX + 1))
	done
	if ((COUNT == 0)); then
		printf '%s\n' ${LINES[@]+"${LINES[@]}"}
		return 0
	fi
	if ((COUNT > 1)); then
		printf 'the [Interface] section of %s sets ListenPort more than once\n' "${INTERFACE_NAME}" >&"${DIAG_FD}"
		return 1
	fi
	if ! [[ "${CONFIGURED}" =~ ^[0-9]{1,5}$ ]] || ((10#${CONFIGURED} > 65535)); then
		printf 'the configured ListenPort of %s is not a valid port\n' "${INTERFACE_NAME}" >&"${DIAG_FD}"
		return 1
	fi
	if ! LIVE="$(_awgBtListenPort "${INTERFACE_NAME}")"; then
		printf 'cannot read the live listen port of %s\n' "${INTERFACE_NAME}" >&"${DIAG_FD}"
		return 1
	fi
	for INDEX in "${!LINES[@]}"; do
		if ((INDEX == PORT_INDEX)) && ((10#${CONFIGURED} == LIVE)); then
			continue
		fi
		printf '%s\n' "${LINES[INDEX]}"
	done
}

# The BoringTun form of `awg syncconf <if> <(awg-quick strip <if>)`, with the
# same destinations for awg syncconf's stderr as awgSyncInterfaceConfig: the
# caller's stderr, --stderr-to-stdout, or a file. The filter's own diagnostics
# go to the same place, and awg-quick strip's stderr to the caller's.
function _awgBtSync() {
	local INTERFACE_NAME="$1" DESTINATION="${2:-}" DIAG_FD FILTERED RC=1
	case "${DESTINATION}" in
		"") exec {DIAG_FD}>&2 ;;
		--stderr-to-stdout) exec {DIAG_FD}>&1 ;;
		*) exec {DIAG_FD}>"${DESTINATION}" || return 1 ;;
	esac
	if FILTERED="$(_awgBtFilteredStrip "${INTERFACE_NAME}" "${DIAG_FD}")"; then
		awg syncconf "${INTERFACE_NAME}" <(printf '%s\n' "${FILTERED}") 2>&"${DIAG_FD}"
		RC=$?
	fi
	exec {DIAG_FD}>&-
	return "${RC}"
}

# The installer's load override for an AmneziaWG kernel module installed on a
# BoringTun host. A blacklist line stops only the rtnl-link autoload of
# `ip link add … type amneziawg`; an install command also stops an explicit
# `modprobe amneziawg`. The BoringTun coexistence test shows both on a real
# DKMS module.
function _awgBtRenderModprobeOverride() {
	printf '# Managed by amneziawg-install (backend: boringtun). Removed by its uninstall.\n'
	printf '# Stops the AmneziaWG kernel module from loading, so that awg-quick starts BoringTun.\n'
	printf 'install amneziawg /bin/false\n'
}

# Loading <module or alias> ends in the override's install command. The dry
# run lists, one per line and with a trailing space, what modprobe would do:
# an insmod for each dependency that is not loaded yet, then the action for the
# module itself. The output is parsed as data: every line but the last must
# insmod a dependency by absolute path, none of them AmneziaWG itself, and the
# last must be exactly `install /bin/false`. Anything else counts as not
# blocked.
function _awgBtModprobeActionBlocked() { # <module or alias>
	local OUTPUT LINE MODULE
	local -a LINES=() ACTIONS=()
	OUTPUT="$(modprobe -n -v "$1" 2>/dev/null)" || return 1
	mapfile -t LINES <<<"${OUTPUT}"
	for LINE in "${LINES[@]}"; do
		LINE="${LINE%"${LINE##*[![:space:]]}"}"
		[[ -z "${LINE}" ]] || ACTIONS+=("${LINE}")
	done
	((${#ACTIONS[@]} > 0)) || return 1
	[[ "${ACTIONS[-1]}" == "install /bin/false" ]] || return 1
	for LINE in "${ACTIONS[@]:0:${#ACTIONS[@]}-1}"; do
		[[ "${LINE}" =~ ^insmod\ (/[^[:space:]]+\.ko(\.(gz|xz|zst))?)(\ .*)?$ ]] || return 1
		MODULE="${BASH_REMATCH[1]##*/}"
		[[ "${MODULE%%.ko*}" != amneziawg ]] || return 1
	done
	return 0
}

# The override is in force: the installer's file is in place, trusted and
# unchanged, and modprobe resolves both the module and the rtnl-link alias that
# `ip link add … type amneziawg` requests to that install command.
function _awgBtKernelModuleBlocked() {
	local NAME
	if ! _awgBtTrustedAncestors "${AWG_BT_MODPROBE_OVERRIDE}" || ! _awgBtTrustedNode "${AWG_BT_MODPROBE_OVERRIDE}" file ||
		[[ "$(cat -- "${AWG_BT_MODPROBE_OVERRIDE}" 2>/dev/null)" != "$(_awgBtRenderModprobeOverride)" ]]; then
		return 1
	fi
	command -v modprobe >/dev/null 2>&1 || return 1
	for NAME in amneziawg rtnl-link-amneziawg; do
		_awgBtModprobeActionBlocked "${NAME}" || return 1
	done
	return 0
}

# awg-quick tries `ip link add <if> type amneziawg` first and uses the
# userspace implementation only when that fails and the module is not loaded.
# A loaded module, or one it can autoload, would therefore win silently. An
# installed module is accepted only while the installer's load override is in
# force.
function _awgBtCheckKernelModule() {
	if [[ -e "${AWG_BT_SYS_DIR}/module/amneziawg" ]]; then
		_awgBtErr "the amneziawg kernel module is loaded, so awg-quick would create a kernel interface instead of starting BoringTun; unload it with: modprobe -r amneziawg"
		return 1
	fi
	if ! command -v modinfo >/dev/null 2>&1; then
		_awgBtErr "modinfo is unavailable, so an autoloadable amneziawg kernel module cannot be ruled out"
		return 1
	fi
	if modinfo -n amneziawg >/dev/null 2>&1 && ! _awgBtKernelModuleBlocked; then
		_awgBtErr "the amneziawg kernel module is installed and awg-quick would autoload it instead of starting BoringTun; remove amneziawg-dkms, or block the module with the installer's load override ${AWG_BT_MODPROBE_OVERRIDE}"
		return 1
	fi
	return 0
}

function _awgBtCheckPlatform() {
	if [[ ! -c "${AWG_BT_TUN_DEVICE}" || ! -r "${AWG_BT_TUN_DEVICE}" || ! -w "${AWG_BT_TUN_DEVICE}" ]]; then
		_awgBtErr "${AWG_BT_TUN_DEVICE} is not a usable character device; BoringTun needs TUN support"
		return 1
	fi
	if [[ ! -d "${AWG_BT_PROC_DIR}/sys/net/ipv6" ]]; then
		_awgBtErr "the IPv6 socket family is unavailable (ipv6.disable=1); this BoringTun build always binds an IPv6 socket"
		return 1
	fi
	return 0
}

function _awgBtCheckHelpers() {
	local HELPER
	for HELPER in "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"; do
		if ! _awgBtTrustedAncestors "${HELPER}" || ! _awgBtTrustedNode "${HELPER}" exec; then
			_awgBtErr "${HELPER} is missing or writable by someone other than root"
			return 1
		fi
	done
	return 0
}

# The drop-in changes Type= and replaces ExecStop= and ExecReload=, but keeps
# the packaged `ExecStart=/usr/bin/awg-quick up %i` as the bring-up. Refuse to
# start if that is no longer what the packaged unit runs, or if a local unit
# file replaces the packaged one.
function _awgBtCheckBaseUnit() {
	local DIRECTORY UNIT=""
	for DIRECTORY in ${AWG_BT_UNIT_DIRS}; do
		if [[ -f "${DIRECTORY}/awg-quick@.service" ]]; then
			UNIT="${DIRECTORY}/awg-quick@.service"
			break
		fi
	done
	if [[ -z "${UNIT}" ]]; then
		_awgBtErr "the packaged awg-quick@.service is not installed"
		return 1
	fi
	if ! grep -qxF 'ExecStart=/usr/bin/awg-quick up %i' "${UNIT}" || [[ "$(grep -c '^ExecStart=' "${UNIT}")" != 1 ]]; then
		_awgBtErr "${UNIT} no longer brings the interface up with 'ExecStart=/usr/bin/awg-quick up %i', which the BoringTun drop-in relies on"
		return 1
	fi
	if [[ -e "${AWG_BT_SYSTEMD_DIR}/awg-quick@.service" || -e "${AWG_BT_SYSTEMD_DIR}/awg-quick@$1.service" ]]; then
		_awgBtErr "a unit file in ${AWG_BT_SYSTEMD_DIR} replaces the packaged awg-quick@.service, which the BoringTun drop-in relies on"
		return 1
	fi
	return 0
}

# ExecStartPre: open the current attempt, then refuse to start unless BoringTun
# will really serve the interface, from verified files, with a safe config.
# The attempt, with its flags, is recorded before any check can fail. A link,
# UAPI socket or awg interface of the name that already exists belongs to
# someone else: precheck refuses, and poststop leaves it untouched. What an
# earlier attempt left behind is neither read nor removed.
function _awgBtCtlPrecheck() { # <interface> <config>
	local INTERFACE_NAME="$1" CONFIG_FILE="$2" BASE WG_PATH AWG_PATH PRESENT="" RC=0 FILE
	if ! _awgBtCurrentAttempt; then
		_awgBtErr "no start attempt identity: awg-backend-ctl runs from awg-quick@${INTERFACE_NAME} (INVOCATION_ID) or from awgBackendQuickUp"
		return 1
	fi
	if ! _awgBtPrepareRunDir; then
		_awgBtErr "cannot prepare the private runtime directory ${AWG_BT_RUN_DIR}"
		return 1
	fi
	BASE="$(_awgBtAttemptBase "${INTERFACE_NAME}")"
	for FILE in "${BASE}".*; do
		if [[ -e "${FILE}" || -L "${FILE}" ]]; then
			_awgBtErr "attempt ${_AWG_BT_ATTEMPT} of ${INTERFACE_NAME} was already started"
			return 1
		fi
	done
	if ! command -v ss >/dev/null 2>&1; then
		_awgBtErr "ss (iproute2) is required to tell BoringTun's UAPI socket from any other"
		return 1
	fi
	_awgBtStateNew "${CONFIG_FILE}" || return 1
	WG_PATH="${AWG_BT_WG_SOCKET_DIR}/${INTERFACE_NAME}.sock"
	AWG_PATH="${AWG_BT_AWG_SOCKET_DIR}/${INTERFACE_NAME}.sock"
	_awgBtLinkExists "${INTERFACE_NAME}" && PRESENT+=", the link ${INTERFACE_NAME}"
	[[ -e "${WG_PATH}" || -L "${WG_PATH}" ]] && PRESENT+=", ${WG_PATH}"
	[[ -e "${AWG_PATH}" || -L "${AWG_PATH}" ]] && PRESENT+=", ${AWG_PATH}"
	_awgBtListedByAwg "${INTERFACE_NAME}" && PRESENT+=", an awg interface ${INTERFACE_NAME}"
	[[ -z "${PRESENT}" ]] || _AWG_BT_STATE[PRE_EXISTING]=1
	if ! _awgBtStateSave "${INTERFACE_NAME}" || ! _awgBtFlagsArm "${INTERFACE_NAME}"; then
		_awgBtErr "cannot record the start attempt of ${INTERFACE_NAME} in ${AWG_BT_RUN_DIR}"
		return 1
	fi
	if [[ -n "${PRESENT}" ]]; then
		_awgBtErr "refusing to start BoringTun for ${INTERFACE_NAME}, which already exists (${PRESENT#, }); this start leaves it untouched"
		return 1
	fi
	_awgBtCheckKernelModule || return 1
	_awgBtCheckPlatform || return 1
	_awgBtVerifyStore || return 1
	_awgBtCheckHelpers || return 1
	_awgBtReadRuntimeFile "${INTERFACE_NAME}" || return 1
	_awgBtSaveConfigEnabled "${CONFIG_FILE}" || RC=$?
	case "${RC}" in
		0)
			_awgBtErr "${CONFIG_FILE} sets SaveConfig = true, which BoringTun cannot honour: its UAPI never returns the private key, so saving would erase it"
			return 1
			;;
		1) ;;
		*)
			_awgBtErr "${CONFIG_FILE} is unreadable or has an invalid SaveConfig value"
			return 1
			;;
	esac
	_awgBtCheckBaseUnit "${INTERFACE_NAME}" || return 1
	_AWG_BT_STATE[PHASE]=prechecked
	if ! _awgBtStateSave "${INTERFACE_NAME}"; then
		_awgBtErr "cannot record the start attempt of ${INTERFACE_NAME} in ${AWG_BT_RUN_DIR}"
		return 1
	fi
	return 0
}

# The running instance of the interface is the one the current attempt
# launched: the recorded TUN link, a live daemon with the recorded PID and
# start time that runs the verified binary and that the PID file names, and a
# UAPI that answers on the recorded socket nodes. poststart and
# ensureAwgBackendReady share it.
function _awgBtVerifyActiveInstance() { # <interface>
	local INTERFACE_NAME="$1" PID="" PID_FILE_PID="" EXE="" INDEX=""
	_awgBtVerifyStore || return 1
	if ! _awgBtFlagIs "${INTERFACE_NAME}" up; then
		_awgBtErr "no start of ${INTERFACE_NAME} is recorded as up"
		return 1
	fi
	if ! _awgBtLinkExists "${INTERFACE_NAME}"; then
		_awgBtErr "${INTERFACE_NAME} does not exist"
		return 1
	fi
	if ! _awgBtLinkIsTun "${INTERFACE_NAME}"; then
		_awgBtErr "${INTERFACE_NAME} is not a TUN device, so awg-quick did not start BoringTun"
		return 1
	fi
	if [[ -z "${_AWG_BT_STATE[PID]-}" ]]; then
		_awgBtErr "${INTERFACE_NAME} was not started by the BoringTun launcher"
		return 1
	fi
	INDEX="$(_awgBtLinkIndex "${INTERFACE_NAME}")" || INDEX=""
	if [[ -z "${INDEX}" || "${INDEX}" != "${_AWG_BT_STATE[IFINDEX]}" ]]; then
		_awgBtErr "${INTERFACE_NAME} is not the link that this start created"
		return 1
	fi
	PID="${_AWG_BT_STATE[PID]}"
	read -r PID_FILE_PID <"$(_awgBtPidFile "${INTERFACE_NAME}")" 2>/dev/null || PID_FILE_PID=""
	if [[ "${PID_FILE_PID}" != "${PID}" ]] || ! _awgBtProcessIs "${PID}" "${_AWG_BT_STATE[PID_START]}"; then
		_awgBtErr "$(_awgBtPidFile "${INTERFACE_NAME}") does not name the running BoringTun daemon of ${INTERFACE_NAME}"
		return 1
	fi
	EXE="$(readlink -- "${AWG_BT_PROC_DIR}/${PID}/exe" 2>/dev/null)" || EXE=""
	if [[ "${EXE}" != "${_AWG_BT_VERIFIED_BIN}" ]]; then
		_awgBtErr "process ${PID} is not the verified BoringTun binary ${_AWG_BT_VERIFIED_BIN}"
		return 1
	fi
	if ! _awgBtUapiReady "${INTERFACE_NAME}" || ! _awgBtListedByAwg "${INTERFACE_NAME}"; then
		_awgBtErr "the UAPI of ${INTERFACE_NAME} does not answer"
		return 1
	fi
	_awgBtProveUapiNodes "${INTERFACE_NAME}" "${PID}" "${_AWG_BT_STATE[PID_START]}"
	if [[ -z "${_AWG_BT_WG_ID}" || "${_AWG_BT_WG_ID}" != "${_AWG_BT_STATE[WG_SOCK]}" ||
		"${_AWG_BT_AWG_ID}" != "${_AWG_BT_STATE[AWG_SOCK]}" ]]; then
		_awgBtErr "the UAPI sockets of ${INTERFACE_NAME} are not the ones its BoringTun daemon holds"
		return 1
	fi
	return 0
}

# ExecStartPost: awg-quick up returned successfully, so this attempt created
# the link (awg-quick refuses an existing one) and its PostUp hooks ran. The up
# flag records that first; it only renames a file precheck created. If it
# cannot be raised, or the attempt cannot record the link awg-quick made, or
# its state is unusable, poststop could not bring the interface down safely
# later, so poststart brings it down now (emergency cleanup, which runs
# PreDown and PostDown and never needs the runtime directory to allocate) and
# fails. Then what runs must be the instance this attempt launched.
function _awgBtCtlPoststart() { # <interface> <config>
	local INTERFACE_NAME="$1" CONFIG_FILE="$2" STATE_FILE INDEX="" UP=0 RC=0
	if ! _awgBtCurrentAttempt; then
		_awgBtErr "no start attempt identity; nothing is changed"
		return 1
	fi
	STATE_FILE="$(_awgBtStateFile "${INTERFACE_NAME}")"
	INDEX="$(_awgBtLinkIndex "${INTERFACE_NAME}")" || INDEX=""
	if _awgBtPrepareRunDir && _awgBtStateLoad "${INTERFACE_NAME}"; then
		if [[ ! "${_AWG_BT_STATE[PHASE]}" =~ ^(prechecked|launching|launched)$ || "${_AWG_BT_STATE[CONFIG]}" != "${CONFIG_FILE}" ]] ||
			_awgBtFlagIs "${INTERFACE_NAME}" up; then
			_awgBtErr "no start attempt of ${INTERFACE_NAME} with ${CONFIG_FILE} awaits poststart; nothing is changed"
			return 1
		fi
		_awgBtFlagRaise "${INTERFACE_NAME}" up && UP=1
		if ((UP)) && [[ -z "${_AWG_BT_STATE[IFINDEX]}" ]]; then
			_AWG_BT_STATE[IFINDEX]="${INDEX}"
			_awgBtStateSave "${INTERFACE_NAME}" || UP=2
		fi
		if ((UP == 1)); then
			_awgBtVerifyActiveInstance "${INTERFACE_NAME}"
			return
		fi
		_awgBtErr "cannot record that ${INTERFACE_NAME} is up; bringing it down now so that its PostDown hooks still run"
		if ((UP == 0)); then
			_awgBtGuardedDown "${INTERFACE_NAME}" "${CONFIG_FILE}" any "${_AWG_BT_STATE[IFINDEX]:-${INDEX}}" noflag
		else
			_awgBtGuardedDown "${INTERFACE_NAME}" "${CONFIG_FILE}" any "${_AWG_BT_STATE[IFINDEX]:-${INDEX}}"
		fi
		RC=$?
	elif [[ -d "${AWG_BT_RUN_DIR}" && ! -L "${AWG_BT_RUN_DIR}" && ! -e "${STATE_FILE}" && ! -L "${STATE_FILE}" ]]; then
		_awgBtErr "no start attempt of ${INTERFACE_NAME} is recorded; nothing is changed"
		return 1
	else
		_awgBtErr "the state of ${INTERFACE_NAME} is unusable; bringing it down now so that its PostDown hooks still run"
		_awgBtGuardedDown "${INTERFACE_NAME}" "${CONFIG_FILE}" any "${INDEX}" stateless
		RC=$?
	fi
	case "${RC}" in
		0)
			_awgBtFlagRaise "${INTERFACE_NAME}" "done" || true
			_awgBtErr "${INTERFACE_NAME} was brought down"
			;;
		1)
			_awgBtRecordFailedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[IFINDEX]:-${INDEX}}"
			_awgBtErr "awg-quick down of ${INTERFACE_NAME} failed as well; its state is kept, check its PostDown hooks by hand"
			;;
		4) _awgBtErr "${INTERFACE_NAME} changed while its down was prepared; it is left alone and its state is kept" ;;
		*) _awgBtErr "awg-quick down of ${INTERFACE_NAME} could not be started; its state is kept, check its PostDown hooks by hand" ;;
	esac
	return 1
}

# ExecStop: a clean awg-quick down of the instance the current attempt started,
# which runs PreDown and PostDown, through _awgBtGuardedDown. When that
# instance is already gone (a crash or `ip link del`), stop succeeds without it
# and poststop decides about PostDown.
function _awgBtCtlStop() { # <interface>
	local INTERFACE_NAME="$1" RC
	if ! _awgBtCurrentAttempt || ! _awgBtStateLoad "${INTERFACE_NAME}" || ! _awgBtFlagIs "${INTERFACE_NAME}" up; then
		_awgBtErr "no start of ${INTERFACE_NAME} in this attempt is recorded as up; nothing is brought down"
		return 0
	fi
	if _awgBtFlagIs "${INTERFACE_NAME}" down; then
		_awgBtErr "a down of ${INTERFACE_NAME} was already started in this attempt; it is not repeated"
		return 0
	fi
	if ! _awgBtLinkIsOwned "${INTERFACE_NAME}" tun "${_AWG_BT_STATE[IFINDEX]}"; then
		_awgBtErr "${INTERFACE_NAME} is already gone, so awg-quick down is not run; poststop decides about its PostDown"
		return 0
	fi
	_awgBtGuardedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}" tun "${_AWG_BT_STATE[IFINDEX]}"
	RC=$?
	case "${RC}" in
		0)
			_awgBtFlagRaise "${INTERFACE_NAME}" "done" || _awgBtErr "cannot record that awg-quick down of ${INTERFACE_NAME} succeeded"
			return 0
			;;
		1) _awgBtRecordFailedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[IFINDEX]}" ;;
		4) _awgBtErr "${INTERFACE_NAME} was replaced while its down was prepared; the new link is left alone and cleanup is ambiguous" ;;
	esac
	return 1
}

# ExecStopPost, after every stop, crash and failed start. It acts only on the
# current attempt's state and only on what that attempt owns, and removes the
# state only because of a positive terminal fact:
#  - precheck refused or failed (PHASE=started): awg-quick up never ran;
#  - the launcher failed and cleaned up (PHASE=launch-failed): awg-quick up
#    stops at its first step, before any PostUp hook;
#  - the interface's cleanup completed: the done flag, raised only after an
#    awg-quick down or a replay that completed. A failed replay raises none.
# Anything else keeps the state and says why. In particular a missing up flag
# is not terminal: awg-quick up may have run PostUp even though poststart
# could not record it. Along the way:
#  - the recorded daemon is stopped if it still runs (awgBackendQuickUp has no
#    cgroup for systemd to end); a daemon that does not stop keeps the state;
#  - a down or a replay that was started and did not provably finish has its
#    hooks named, never run again;
#  - a kernel link that awg-quick created for this attempt (the recorded
#    ifindex, not a TUN device) is brought down through _awgBtGuardedDown;
#  - PostDown is replayed once when no link of the name exists any more and no
#    down reached PostDown; the replay flag is raised first, and if it cannot
#    be raised no hook runs;
#  - a different link that took the name is left alone, and PostDown, which
#    may address the interface by name, is not replayed while it exists;
#  - socket nodes are removed only if they are the recorded, proven nodes of a
#    daemon that is gone; if such a node cannot be removed or proven gone
#    (its identity cannot be read and its absence cannot be proven), the
#    state is kept.
function _awgBtCtlPoststop() { # <interface>
	local INTERFACE_NAME="$1" INDEX="" PID START KEEP=0 TERMINAL=0 REPLAY=0 RC
	if ! _awgBtCurrentAttempt || ! _awgBtPrepareRunDir || ! _awgBtStateLoad "${INTERFACE_NAME}"; then
		_awgBtErr "no state of the current start attempt of ${INTERFACE_NAME}; nothing but its PID file is touched"
		rm -f -- "$(_awgBtPidFile "${INTERFACE_NAME}")" 2>/dev/null
		return 0
	fi
	PID="${_AWG_BT_STATE[PID]}"
	START="${_AWG_BT_STATE[PID_START]}"
	if [[ "${_AWG_BT_STATE[PHASE]}" == started || "${_AWG_BT_STATE[PHASE]}" == launch-failed ]]; then
		TERMINAL=1
	else
		if [[ -n "${PID}" && -n "${START}" ]] && ! _awgBtStopProcess "${PID}" "${START}"; then
			_awgBtErr "the BoringTun daemon ${PID} of ${INTERFACE_NAME} does not stop"
			KEEP=1
		fi
		INDEX="$(_awgBtLinkIndex "${INTERFACE_NAME}")" || INDEX=""
		if _awgBtFlagIs "${INTERFACE_NAME}" "done"; then
			TERMINAL=1
		elif ! _awgBtFlagIs "${INTERFACE_NAME}" up; then
			_awgBtErr "awg-quick up of ${INTERFACE_NAME} did not complete, or its completion could not be recorded: PostUp may have run, so PostDown is neither run nor ruled out, and the attempt is kept"
			_awgBtReportUnfinishedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"
		elif _awgBtFlagIs "${INTERFACE_NAME}" replay; then
			_awgBtErr "a PostDown replay of ${INTERFACE_NAME} was started earlier and may not have finished; it is never run again"
			_awgBtReportUnfinishedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"
		elif _awgBtFlagIs "${INTERFACE_NAME}" down; then
			if [[ "${_AWG_BT_STATE[DOWN]}" == failed-intact ]] && ! _awgBtLinkExists "${INTERFACE_NAME}"; then
				REPLAY=1
			else
				_awgBtReportUnfinishedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"
			fi
		elif ! _awgBtLinkExists "${INTERFACE_NAME}"; then
			REPLAY=1
		elif [[ -n "${INDEX}" && "${INDEX}" == "${_AWG_BT_STATE[IFINDEX]}" ]] && ! _awgBtLinkIsTun "${INTERFACE_NAME}"; then
			_awgBtErr "${INTERFACE_NAME} is a kernel AmneziaWG link that this start created; bringing it down"
			_awgBtGuardedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}" kernel "${_AWG_BT_STATE[IFINDEX]}"
			RC=$?
			case "${RC}" in
				0)
					if _awgBtFlagRaise "${INTERFACE_NAME}" "done"; then
						TERMINAL=1
					else
						_awgBtErr "cannot record that awg-quick down of ${INTERFACE_NAME} succeeded"
					fi
					;;
				1)
					_awgBtRecordFailedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[IFINDEX]}"
					_awgBtErr "awg-quick down of ${INTERFACE_NAME} failed; it is left as it is"
					;;
				4) _awgBtErr "${INTERFACE_NAME} changed while its down was prepared; the new link is left alone and cleanup is ambiguous" ;;
				*) _awgBtErr "awg-quick down of ${INTERFACE_NAME} could not be started" ;;
			esac
		elif [[ -n "${INDEX}" && "${INDEX}" == "${_AWG_BT_STATE[IFINDEX]}" ]]; then
			_awgBtErr "${INTERFACE_NAME} is still up; it is left in place and its PostDown hooks are not replayed"
		elif [[ -z "${_AWG_BT_STATE[IFINDEX]}" ]]; then
			_awgBtErr "this start never recorded which link it created, so ${INTERFACE_NAME} is left alone; its PostDown hooks are owed"
			_awgBtReportUnfinishedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"
		else
			_awgBtErr "another link now has the name ${INTERFACE_NAME}; it is left alone, and PostDown is not replayed while it exists: cleanup is ambiguous"
			_awgBtReportUnfinishedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"
		fi
		if ((REPLAY)); then
			if _awgBtFlagRaise "${INTERFACE_NAME}" replay; then
				# done only after a replay that completed; a replay that failed
				# is recorded as started, so its hooks are never run again.
				if ! _awgBtReplayPostDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"; then
					_awgBtErr "the PostDown replay of ${INTERFACE_NAME} did not complete; cleanup is incomplete, and its hooks are never run again"
				elif _awgBtFlagRaise "${INTERFACE_NAME}" "done"; then
					TERMINAL=1
				else
					_awgBtErr "cannot record that the PostDown replay of ${INTERFACE_NAME} finished"
				fi
			else
				_awgBtErr "cannot record that the PostDown replay of ${INTERFACE_NAME} starts, so none of its hooks is run"
			fi
		fi
	fi
	if ! _awgBtRemoveOwnedPath "${AWG_BT_WG_SOCKET_DIR}/${INTERFACE_NAME}.sock" "${_AWG_BT_STATE[WG_SOCK]}" "${PID}" "${START}" ||
		! _awgBtRemoveOwnedPath "${AWG_BT_AWG_SOCKET_DIR}/${INTERFACE_NAME}.sock" "${_AWG_BT_STATE[AWG_SOCK]}" "${PID}" "${START}"; then
		_awgBtErr "a UAPI socket node of the dead BoringTun daemon of ${INTERFACE_NAME} cannot be removed or proven gone; cleanup is incomplete"
		KEEP=1
	fi
	rm -f -- "$(_awgBtPidFile "${INTERFACE_NAME}")"
	if ((TERMINAL && ! KEEP)); then
		_awgBtAttemptRemove "${INTERFACE_NAME}" || _awgBtErr "cannot remove the finished state of ${INTERFACE_NAME}"
	else
		_awgBtErr "the state of this attempt of ${INTERFACE_NAME} is kept: $(_awgBtStateFile "${INTERFACE_NAME}")"
	fi
	return 0
}

# ── awg-backend-ctl ──────────────────────────────────────────────────────────
# The hooks of the BoringTun drop-in for awg-quick@<if>.service. precheck and
# poststart take the config's canonical path as an optional third argument,
# for awgBackendQuickUp; the service uses <config dir>/<if>.conf.
function awgBackendCtlMain() {
	local COMMAND="${1:-}" INTERFACE_NAME="${2:-}" CONFIG_FILE="${3:-}"
	local USAGE="usage: awg-backend-ctl precheck|poststart <interface> [<config>] | sync|stop|poststop <interface>"
	if [[ $# -lt 2 || $# -gt 3 ]] || ! _awgBtValidInterfaceName "${INTERFACE_NAME}"; then
		_awgBtErr "${USAGE}"
		return 2
	fi
	if [[ $# -eq 3 ]]; then
		if [[ "${COMMAND}" != precheck && "${COMMAND}" != poststart ]]; then
			_awgBtErr "${USAGE}"
			return 2
		fi
		if [[ ! "${CONFIG_FILE}" =~ ^/[^[:cntrl:]]*$ || "${CONFIG_FILE}" != */"${INTERFACE_NAME}.conf" ||
			"$(readlink -f -- "${CONFIG_FILE}" 2>/dev/null)" != "${CONFIG_FILE}" ]]; then
			_awgBtErr "the config of ${INTERFACE_NAME} must be given as the canonical absolute path of a ${INTERFACE_NAME}.conf"
			return 2
		fi
	else
		CONFIG_FILE="${AWG_BT_CONFIG_DIR}/${INTERFACE_NAME}.conf"
	fi
	case "${COMMAND}" in
		precheck) _awgBtCtlPrecheck "${INTERFACE_NAME}" "${CONFIG_FILE}" ;;
		poststart) _awgBtCtlPoststart "${INTERFACE_NAME}" "${CONFIG_FILE}" ;;
		sync) _awgBtSync "${INTERFACE_NAME}" ;;
		stop) _awgBtCtlStop "${INTERFACE_NAME}" ;;
		poststop) _awgBtCtlPoststop "${INTERFACE_NAME}" ;;
		*)
			_awgBtErr "${USAGE}"
			return 2
			;;
	esac
}

# Functions the generated helpers carry. Keep in step with their callers.
_AWG_BT_HELPER_FUNCTIONS="_awgBtErr _awgBtReleaseIdValid _awgBtValidInterfaceName _awgBtImitationProtocolValid _awgBtImitationUsesDomain _awgBtImitationDomainValid _awgBtImitationCheck _awgBtBinaryImitationSupport _awgBtStatOwnerMode _awgBtTrustedNode _awgBtTrustedAncestors _awgBtHostArch _awgBtVerifyStore _awgBtVerifyRelease _awgBtRuntimeFilePath _awgBtReadRuntimeFile _awgBtPidFile _awgBtPrepareRunDir _awgBtWriteState _awgBtListenPort _awgBtUapiReady _awgBtLinkExists _awgBtLinkIsTun _awgBtLinkIndex _awgBtListedByAwg _awgBtProcStat _awgBtProcessStartTime _awgBtProcessAlive _awgBtProcessIs _awgBtSignalProcess _awgBtStopProcess _awgBtPathId _awgBtPathAbsent _awgBtRecordedNodeGone _awgBtRemoveOwnedPath _awgBtSocketHeldBy _awgBtSymlinkToNode _awgBtProveUapiNodes _awgBtNewToken _awgBtCurrentAttempt _awgBtAttemptBase _awgBtStateFile _awgBtFlagsArm _awgBtFlagRaise _awgBtFlagIs _awgBtAttemptRemove _awgBtStateValueValid _awgBtStateNew _awgBtStateSave _awgBtStateLoad _awgBtDaemonArgv _awgBtCloseInheritedFds"
_AWG_BT_LAUNCH_FUNCTIONS="awgBoringtunLaunchMain _awgBtRecordSocketNodes _awgBtLaunchRefused _awgBtLaunchFailed"
_AWG_BT_CTL_FUNCTIONS="awgBackendCtlMain _awgBtInterfaceValues _awgBtSaveConfigEnabled _awgBtWithoutSaveConfig _awgBtTryDownCopy _awgBtDownCopy _awgBtLinkIsOwned _awgBtGuardedDown _awgBtRecordFailedDown _awgBtReplayPostDown _awgBtReportUnfinishedDown _awgBtFilteredStrip _awgBtSync _awgBtRenderModprobeOverride _awgBtModprobeActionBlocked _awgBtKernelModuleBlocked _awgBtCheckKernelModule _awgBtCheckPlatform _awgBtCheckHelpers _awgBtCheckBaseUnit _awgBtVerifyActiveInstance _awgBtCtlPrecheck _awgBtCtlPoststart _awgBtCtlStop _awgBtCtlPoststop"

# Emit a generated helper: a fixed header, the embedded AWG_BT_* settings, the
# installer's own functions and a call to the entry point. The output depends
# only on this installer's code and settings, never on the environment.
function _awgBtRenderHelper() {
	local KIND="$1" NAME FUNCTIONS MAIN VARIABLE
	case "${KIND}" in
		launch)
			NAME="awg-boringtun-launch"
			FUNCTIONS="${_AWG_BT_HELPER_FUNCTIONS} ${_AWG_BT_LAUNCH_FUNCTIONS}"
			MAIN="awgBoringtunLaunchMain"
			;;
		ctl)
			NAME="awg-backend-ctl"
			FUNCTIONS="${_AWG_BT_HELPER_FUNCTIONS} ${_AWG_BT_CTL_FUNCTIONS}"
			MAIN="awgBackendCtlMain"
			;;
		*) return 1 ;;
	esac
	printf '#!/bin/bash\n'
	printf '# %s: generated by amneziawg-install from its own functions.\n' "${NAME}"
	printf '# Do not edit: the installer rewrites this file.\n'
	printf 'set -uo pipefail\n'
	printf 'umask 077\n'
	printf 'export LC_ALL=C\n'
	printf 'export PATH=%q\n' "${AWG_BT_PATH}"
	printf '_AWG_BT_PROG=%q\n' "${NAME}"
	printf '_AWG_BT_VERIFIED_BIN=""\n'
	printf '_AWG_BT_VERIFIED_VERSION=""\n'
	printf '_AWG_BT_ARGV=()\n'
	printf '_AWG_BT_IMITATE_PROTOCOL=none\n'
	printf '_AWG_BT_IMITATE_DOMAIN=""\n'
	printf '_AWG_BT_ATTEMPT=""\n'
	printf 'declare -A _AWG_BT_STATE=()\n'
	printf '_AWG_BT_WG_ID=""\n'
	printf '_AWG_BT_AWG_ID=""\n'
	for VARIABLE in ${_AWG_BT_HELPER_VARIABLES}; do
		printf 'readonly %s=%q\n' "${VARIABLE}" "${!VARIABLE}"
	done
	# shellcheck disable=SC2086 # the function lists are fixed words
	declare -f ${FUNCTIONS} || return 1
	printf '%s "$@"\n' "${MAIN}"
	printf 'exit $?\n'
}

# The BoringTun drop-in for awg-quick@<if>.service. The packaged
# `ExecStart=/usr/bin/awg-quick up %i` stays the bring-up.
function _awgBtRenderServiceDropIn() {
	cat <<EOF
# Managed by amneziawg-install (backend: boringtun). Regenerated from params.
[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
RemainAfterExit=no
PIDFile=${AWG_BT_RUN_DIR}/boringtun-%i.pid
TimeoutStartSec=30
Restart=on-failure
RestartSec=3
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch
ExecStartPre=${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl precheck %i
ExecStartPost=${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl poststart %i
ExecReload=
ExecReload=${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl sync %i
ExecStop=
ExecStop=${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl stop %i
ExecStopPost=${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl poststop %i
EOF
}

# Create DIRECTORY with MODE if needed and require it to be trusted.
function _awgBtEnsureDirectory() {
	local DIRECTORY="$1" MODE="$2"
	if [[ -L "${DIRECTORY}" ]]; then
		_awgBtErr "refusing to use ${DIRECTORY}: it is a symlink"
		return 1
	fi
	if [[ ! -d "${DIRECTORY}" ]]; then
		mkdir -p -- "${DIRECTORY}" && chmod "${MODE}" -- "${DIRECTORY}" || return 1
	fi
	if ! _awgBtTrustedAncestors "${DIRECTORY}" || ! _awgBtTrustedNode "${DIRECTORY}" dir; then
		_awgBtErr "${DIRECTORY} or a parent directory is writable by someone other than root"
		return 1
	fi
}

# Replace DEST with stdin atomically, as a root-owned file with MODE. An
# identical file is left alone. _AWG_BT_FILE_CHANGED says whether DEST changed.
function _awgBtWriteManagedFile() {
	local DEST="$1" MODE="$2" TMP CONTENT OWNER="" CURRENT_MODE=""
	_AWG_BT_FILE_CHANGED=0
	if [[ -L "${DEST}" ]] || { [[ -e "${DEST}" ]] && [[ ! -f "${DEST}" ]]; }; then
		_awgBtErr "refusing to replace ${DEST}: it is not a regular file"
		cat >/dev/null
		return 1
	fi
	# Check existing text before allocating in its directory. The web panel's
	# sandbox makes /usr read-only, but may reuse helpers that already have the
	# exact generated contents and trusted ownership/mode. A sentinel preserves
	# every trailing newline when capturing stdin with command substitution.
	CONTENT="$(cat && printf '.')" || return 1
	CONTENT="${CONTENT%.}"
	if [[ -f "${DEST}" ]]; then
		read -r OWNER CURRENT_MODE <<<"$(_awgBtStatOwnerMode "${DEST}")"
		if [[ "${OWNER}" == "${AWG_BT_TRUSTED_UID}" && "${CURRENT_MODE}" == "${MODE#0}" ]] &&
			cmp -s -- "${DEST}" <(printf '%s' "${CONTENT}"); then
			return 0
		fi
	fi
	if ! TMP="$(mktemp "${DEST%/*}/.${DEST##*/}.XXXXXX")"; then
		return 1
	fi
	if ! printf '%s' "${CONTENT}" >"${TMP}" || ! chmod "${MODE}" -- "${TMP}" ||
		{ [[ "${EUID}" -eq 0 ]] && ! chown 0:0 -- "${TMP}"; }; then
		rm -f -- "${TMP}"
		return 1
	fi
	if ! mv -f -- "${TMP}" "${DEST}"; then
		rm -f -- "${TMP}"
		return 1
	fi
	_AWG_BT_FILE_CHANGED=1
}

# _AWG_BT_HELPERS_CHANGED says whether either helper was rewritten.
function _awgBtInstallHelpers() {
	local CONTENT
	_AWG_BT_HELPERS_CHANGED=0
	_awgBtEnsureDirectory "${AWG_BT_LIBEXEC_DIR}" 0755 || return 1
	CONTENT="$(_awgBtRenderHelper launch)" || return 1
	_awgBtWriteManagedFile "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" 0755 <<<"${CONTENT}" || return 1
	((_AWG_BT_FILE_CHANGED == 0)) || _AWG_BT_HELPERS_CHANGED=1
	CONTENT="$(_awgBtRenderHelper ctl)" || return 1
	_awgBtWriteManagedFile "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl" 0755 <<<"${CONTENT}" || return 1
	((_AWG_BT_FILE_CHANGED == 0)) || _AWG_BT_HELPERS_CHANGED=1
}

# Write the runtime file and the drop-in for INTERFACE, then reload systemd.
# The reload runs every time, not only when the drop-in changed: after a reload
# that failed, an unchanged drop-in would otherwise never be reloaded, and
# systemd would go on running the old unit definition.
function _awgBtInstallServiceFiles() {
	local INTERFACE_NAME="$1" DROPIN_DIR CONTENT
	_awgBtValidInterfaceName "${INTERFACE_NAME}" || return 1
	CONTENT="$(_awgBtRenderRuntimeFile)" || return 1
	_awgBtWriteManagedFile "$(_awgBtRuntimeFilePath "${INTERFACE_NAME}")" 0600 <<<"${CONTENT}" || return 1
	DROPIN_DIR="${AWG_BT_SYSTEMD_DIR}/awg-quick@${INTERFACE_NAME}.service.d"
	_awgBtEnsureDirectory "${DROPIN_DIR}" 0755 || return 1
	CONTENT="$(_awgBtRenderServiceDropIn)" || return 1
	_awgBtWriteManagedFile "${DROPIN_DIR}/override.conf" 0644 <<<"${CONTENT}" || return 1
	systemctl daemon-reload || return 1
	return 0
}

# ensureAwgBackendReady for BoringTun, with the kernel implementation's calling
# convention and exit semantics. It verifies an already provisioned store,
# regenerates the helpers and reclaims interrupted scratch instances; mode 1
# also writes the runtime file and drop-in, starts awg-quick@<if> when it is
# inactive, and then requires the active unit to be served by the verified
# BoringTun instance that its start recorded. A unit that is already active on
# another datapath fails closed: nothing is restarted or migrated. It never
# installs or downloads BoringTun and never touches kernel packages.
function _awgBtEnsureReady() {
	local START_AWG_QUICK="${1:-1}"
	case "${START_AWG_QUICK}" in
		0 | 1) ;;
		*)
			echo -e "${RED}ERROR: ensureAwgBackendReady expects service-start mode 0 or 1.${NC}" >&2
			return 1
			;;
	esac
	if ! _awgBtVerifyStore || ! _awgBtCheckPlatform || ! _awgBtInstallHelpers; then
		echo -e "${RED}ERROR: the BoringTun runtime is not ready.${NC}" >&2
		exit 1
	fi
	_awgBtScratchSweep
	[[ "${START_AWG_QUICK}" == 0 ]] && return 0
	if ! _awgBtValidInterfaceName "${SERVER_AWG_NIC:-}" || ! _awgBtInstallServiceFiles "${SERVER_AWG_NIC}"; then
		echo -e "${RED}ERROR: could not write the BoringTun service files for awg-quick@${SERVER_AWG_NIC:-}.${NC}" >&2
		exit 1
	fi
	ensureAwgQuickRunning
	if ! _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}"; then
		echo -e "${RED}ERROR: awg-quick@${SERVER_AWG_NIC} is active but not served by the verified BoringTun instance recorded for it.${NC}" >&2
		echo -e "${ORANGE}This installer version does not move a running interface to another datapath. Stop awg-quick@${SERVER_AWG_NIC} first, and check: journalctl -u awg-quick@${SERVER_AWG_NIC}${NC}" >&2
		exit 1
	fi
}

# The active awg-quick@<if> runs the instance that its current activation (its
# InvocationID) launched, and systemd tracks that daemon as the main process.
function _awgBtCheckServedByBoringtun() { # <interface>
	local ATTEMPT MAIN_PID
	ATTEMPT="$(systemctl show -p InvocationID --value "awg-quick@$1.service" 2>/dev/null)" || ATTEMPT=""
	if ! INVOCATION_ID="${ATTEMPT}" _awgBtCurrentAttempt || ! _awgBtStateLoad "$1"; then
		_awgBtErr "no BoringTun start of the active awg-quick@$1 is recorded"
		return 1
	fi
	_awgBtVerifyActiveInstance "$1" || return 1
	MAIN_PID="$(systemctl show -p MainPID --value "awg-quick@$1.service" 2>/dev/null)" || MAIN_PID=""
	if [[ "${MAIN_PID}" != "${_AWG_BT_STATE[PID]}" ]]; then
		_awgBtErr "systemd does not track the BoringTun daemon of $1 as the main process of awg-quick@$1"
		return 1
	fi
	return 0
}

# awgBackendQuickUp for BoringTun: the service's precheck, awg-quick up with the
# launcher, then poststart, through the same generated helpers systemd uses and
# for the canonical path of the given config, which every step checks and uses.
# A random token is the attempt identity, passed to every step as
# INVOCATION_ID the way systemd passes its own.
function _awgBtQuickUp() {
	local CONFIG_FILE INTERFACE_NAME ATTEMPT CTL="${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"
	CONFIG_FILE="$(readlink -f -- "$1" 2>/dev/null)" || CONFIG_FILE=""
	if ! [[ "${CONFIG_FILE}" =~ ^/[^[:cntrl:]]*/([a-zA-Z0-9_=+.-]{1,15})\.conf$ ]]; then
		_awgBtErr "$1 is not named <interface>.conf"
		return 1
	fi
	INTERFACE_NAME="${BASH_REMATCH[1]}"
	if ! ATTEMPT="$(_awgBtNewToken)"; then
		_awgBtErr "cannot draw a start attempt identity for ${INTERFACE_NAME}"
		return 1
	fi
	if ! INVOCATION_ID="${ATTEMPT}" "${CTL}" precheck "${INTERFACE_NAME}" "${CONFIG_FILE}"; then
		INVOCATION_ID="${ATTEMPT}" "${CTL}" poststop "${INTERFACE_NAME}"
		return 1
	fi
	if ! INVOCATION_ID="${ATTEMPT}" WG_QUICK_USERSPACE_IMPLEMENTATION="${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" \
		awg-quick up "${CONFIG_FILE}"; then
		INVOCATION_ID="${ATTEMPT}" "${CTL}" poststop "${INTERFACE_NAME}"
		return 1
	fi
	if ! INVOCATION_ID="${ATTEMPT}" "${CTL}" poststart "${INTERFACE_NAME}" "${CONFIG_FILE}"; then
		INVOCATION_ID="${ATTEMPT}" "${CTL}" stop "${INTERFACE_NAME}"
		INVOCATION_ID="${ATTEMPT}" "${CTL}" poststop "${INTERFACE_NAME}"
		return 1
	fi
	return 0
}

# ── BoringTun scratch interfaces ─────────────────────────────────────────────
# Throwaway instances for capability probes and staged validation, started from
# the verified binary with the production command line. BoringTun replaces an
# existing UAPI socket path when it binds, which would hijack a live instance of
# the same name, so any sign of the name in use is refused.
#
# Every creation is one attempt with a random token and records in
# <run dir>/scratch: <token>.owner, written once by the creating shell (the
# owner) before anything starts, <token>.guard, written only by the attempt's
# guardian, and, without systemd, <token>.child, written by the daemon's own
# process before it becomes BoringTun. Both are data, parsed like the service state. The
# guardian is a background process that ignores HUP, INT and TERM, holds no
# inherited descriptor, and is the only process that starts the instance:
#  1. It records its own PID and start time (PHASE=starting) before it starts
#     anything, so no instance exists without a recorded guardian.
#  2. It starts the daemon only while the owner lives and has not asked it to
#     stop. Under systemd that is a transient unit named after the token, with
#     a hard RuntimeMaxSec, and the guardian waits for systemd-run to return
#     even if the owner dies meanwhile, so a late unit is still torn down.
#     Without systemd the daemon is the guardian's child: it records its own
#     identity before it execs BoringTun, and does so only while the guardian
#     lives, with a parent-death signal as a second line, so it never runs
#     without a durable record.
#  3. It records the daemon's PID and start time, its socket nodes and the TUN
#     link's ifindex, then PHASE=created.
#  4. When the owner is gone (exit, signal, SIGKILL or zombie) or asks it to
#     stop, it tears the instance down through its records and removes them
#     last.
# The owner's destroy waits for that teardown to finish before it reaps the
# guardian. If the guardian is gone or hangs, the owner reclaims the attempt
# from the records. An attempt whose owner and guardian are both gone is
# reclaimed by the sweep that the next creation, or ensureAwgBackendReady,
# runs. Nothing is ever matched by interface name alone.

_AWG_BT_SCRATCH_OWNER_KEYS="FORMAT TOKEN NAME MODE UNIT OWNER_PID OWNER_START"
_AWG_BT_SCRATCH_GUARD_KEYS="FORMAT TOKEN NAME MODE UNIT GUARD_PID GUARD_START PHASE DAEMON_PID DAEMON_START IFINDEX WG_SOCK AWG_SOCK"
_AWG_BT_SCRATCH_CHILD_KEYS="FORMAT TOKEN CHILD_PID CHILD_START"
_AWG_BT_SCRATCH_CLIENT_KEYS="FORMAT TOKEN CLIENT_PID CLIENT_START"
# How long a reclaim waits for a registered systemd-run client to exit before
# it keeps the attempt's records for a later sweep.
_AWG_BT_SCRATCH_CLIENT_WAIT=35
# The hard lifetime of a transient scratch unit in seconds, which bounds what an
# instance can cost when every other cleanup fails.
_AWG_BT_SCRATCH_MAX_SECONDS=900

function _awgBtScratchDir() {
	printf '%s/scratch\n' "${AWG_BT_RUN_DIR}"
}

function _awgBtPrepareScratchDir() {
	local DIR OWNER="" MODE=""
	_awgBtPrepareRunDir || return 1
	DIR="$(_awgBtScratchDir)"
	[[ ! -L "${DIR}" ]] || return 1
	if [[ ! -d "${DIR}" ]]; then
		mkdir -m 0700 -- "${DIR}" 2>/dev/null || [[ -d "${DIR}" ]] || return 1
	fi
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${DIR}")"
	[[ ! -L "${DIR}" && -d "${DIR}" && "${OWNER}" == "${AWG_BT_TRUSTED_UID}" && "${MODE}" == 700 ]]
}

function _awgBtScratchValueValid() { # <key> <value>
	case "$1" in
		FORMAT) [[ "$2" == 1 ]] ;;
		TOKEN) [[ "$2" =~ ^[0-9a-f]{32}$ ]] ;;
		NAME) [[ "$2" =~ ^[a-zA-Z0-9_-]{1,15}$ ]] ;;
		MODE) [[ "$2" == unit || "$2" == direct ]] ;;
		UNIT) [[ "$2" =~ ^(amneziawg-scratch-[a-zA-Z0-9_-]{1,15}-[0-9a-f]{32})?$ ]] ;;
		OWNER_PID | GUARD_PID | CHILD_PID | CLIENT_PID) [[ "$2" =~ ^[1-9][0-9]{0,9}$ ]] ;;
		OWNER_START | GUARD_START | CHILD_START | CLIENT_START) [[ "$2" =~ ^[0-9]{1,20}$ ]] ;;
		PHASE) [[ "$2" =~ ^(starting|created|teardown)$ ]] ;;
		DAEMON_PID | IFINDEX) [[ "$2" =~ ^([1-9][0-9]{0,9})?$ ]] ;;
		DAEMON_START) [[ "$2" =~ ^([0-9]{1,20})?$ ]] ;;
		WG_SOCK | AWG_SOCK) [[ "$2" =~ ^([0-9]+:[0-9]+:[0-9a-f]+:[0-9]+\.[0-9]{9})?$ ]] ;;
		*) return 1 ;;
	esac
}

# Load a scratch record into the associative array that the third argument
# names. Exactly the given keys, once each, with valid values.
function _awgBtScratchLoad() { # <file> <keys> <array name>
	local FILE="$1" KEYS="$2" LINE KEY VALUE OWNER="" MODE=""
	# shellcheck disable=SC2178 # a nameref to the caller's associative array
	local -n SCRATCH_RECORD="$3"
	SCRATCH_RECORD=()
	[[ ! -L "${FILE}" && -f "${FILE}" ]] || return 1
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${FILE}")"
	[[ "${OWNER}" == "${AWG_BT_TRUSTED_UID}" && "${MODE}" == 600 ]] || return 1
	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		if [[ ! "${LINE}" =~ ^([A-Z_]+)=(.*)$ ]]; then
			SCRATCH_RECORD=()
			return 1
		fi
		KEY="${BASH_REMATCH[1]}"
		VALUE="${BASH_REMATCH[2]}"
		if [[ " ${KEYS} " != *" ${KEY} "* || -n "${SCRATCH_RECORD[${KEY}]+set}" ]] || ! _awgBtScratchValueValid "${KEY}" "${VALUE}"; then
			SCRATCH_RECORD=()
			return 1
		fi
		SCRATCH_RECORD["${KEY}"]="${VALUE}"
	done <"${FILE}"
	for KEY in ${KEYS}; do
		if [[ -z "${SCRATCH_RECORD[${KEY}]+set}" ]]; then
			SCRATCH_RECORD=()
			return 1
		fi
	done
	if [[ "${FILE##*/}" != "${SCRATCH_RECORD[TOKEN]}".* ]]; then
		SCRATCH_RECORD=()
		return 1
	fi
}

function _awgBtScratchSave() { # <file> <keys> <array name>
	local KEY CONTENT=""
	# shellcheck disable=SC2178 # a nameref to the caller's associative array
	local -n SCRATCH_RECORD="$3"
	for KEY in $2; do
		_awgBtScratchValueValid "${KEY}" "${SCRATCH_RECORD[${KEY}]-}" || return 1
		CONTENT+="${KEY}=${SCRATCH_RECORD[${KEY}]-}"$'\n'
	done
	_awgBtWriteState "$1" "${CONTENT}"
}

# The guardian of one attempt; see the section comment. It works on the arrays
# and paths of this function, which the helpers below see through bash's
# dynamic scoping.
function _awgBtScratchGuardian() { # <token>
	local TOKEN="$1" DIR OWNER_FILE GUARD_FILE STOP_FILE GUARD_START SELF RC
	local -A OWNER_RECORD=() GUARD_RECORD=()
	trap '' HUP INT TERM
	_awgBtCloseInheritedFds
	DIR="$(_awgBtScratchDir)"
	OWNER_FILE="${DIR}/${TOKEN}.owner"
	GUARD_FILE="${DIR}/${TOKEN}.guard"
	STOP_FILE="${DIR}/${TOKEN}.stop"
	_awgBtScratchLoad "${OWNER_FILE}" "${_AWG_BT_SCRATCH_OWNER_KEYS}" OWNER_RECORD || exit 1
	# BASHPID is taken here, not inside the command substitution, which is a
	# process of its own.
	SELF="${BASHPID}"
	GUARD_START="$(_awgBtProcessStartTime "${SELF}")" || exit 1
	GUARD_RECORD=([FORMAT]=1 [TOKEN]="${TOKEN}" [NAME]="${OWNER_RECORD[NAME]}" [MODE]="${OWNER_RECORD[MODE]}"
		[UNIT]="${OWNER_RECORD[UNIT]}" [GUARD_PID]="${SELF}" [GUARD_START]="${GUARD_START}" [PHASE]=starting
		[DAEMON_PID]="" [DAEMON_START]="" [IFINDEX]="" [WG_SOCK]="" [AWG_SOCK]="")
	_awgBtScratchSave "${GUARD_FILE}" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD || exit 1
	if _awgBtScratchOwnerWants && _awgBtScratchStart && _awgBtScratchAwaitReady; then
		while _awgBtScratchOwnerWants; do
			sleep 0.2
		done
	fi
	GUARD_RECORD[PHASE]=teardown
	_awgBtScratchSave "${GUARD_FILE}" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD
	_awgBtScratchReclaim "${TOKEN}"
	RC=$?
	# Reap the direct daemon and any systemd-run client.
	wait
	exit "${RC}"
}

# The owner still lives, has not asked for a teardown and has not reclaimed
# the attempt itself. A zombie owner is gone.
function _awgBtScratchOwnerWants() {
	[[ ! -e "${STOP_FILE}" && -e "${OWNER_FILE}" ]] &&
		_awgBtProcessIs "${OWNER_RECORD[OWNER_PID]}" "${OWNER_RECORD[OWNER_START]}"
}

function _awgBtScratchStart() {
	local CLIENT DAEMON
	if [[ "${GUARD_RECORD[MODE]}" == unit ]]; then
		# The systemd-run client registers itself (<token>.client) before it
		# can submit anything, and submits only while this guardian lives:
		# no process that could create the unit is ever unrecorded. The
		# unit's own command refuses to start BoringTun once the attempt is
		# being reclaimed or its records are gone (_awgBtScratchUnitArgv).
		(
			trap - HUP INT TERM
			_awgBtCloseInheritedFds
			_awgBtScratchRegisterSelf CLIENT || exit 1
			exec systemd-run --quiet --collect --unit="${GUARD_RECORD[UNIT]}" -p Type=exec \
				-p RuntimeMaxSec="${_AWG_BT_SCRATCH_MAX_SECONDS}" -- "${_AWG_BT_UNIT_ARGV[@]}" </dev/null >/dev/null 2>&1
		) &
		CLIENT=$!
		# Wait for systemd-run whatever the owner does meanwhile: a unit it
		# still creates must be torn down, not left behind. Whether it
		# reported success does not matter; readiness decides.
		_awgBtScratchAwaitRegistration CLIENT "${CLIENT}" || { wait "${CLIENT}"; return 1; }
		wait "${CLIENT}"
		return 0
	fi
	# Likewise the direct child registers itself (<token>.child) before it
	# becomes BoringTun, and only while this guardian lives. A daemon therefore
	# never runs without a durable record, whenever the guardian dies; the
	# parent-death signal is only a second line.
	(
		trap - HUP INT TERM
		_awgBtCloseInheritedFds
		_awgBtScratchRegisterSelf CHILD || exit 1
		exec setpriv --pdeathsig KILL -- "${_AWG_BT_ARGV[@]}" </dev/null >/dev/null 2>&1
	) &
	DAEMON=$!
	_awgBtScratchAwaitRegistration CHILD "${DAEMON}" || return 1
	GUARD_RECORD[DAEMON_PID]="${DAEMON}"
	GUARD_RECORD[DAEMON_START]="${_AWG_BT_REGISTERED_START}"
	_awgBtScratchSave "${GUARD_FILE}" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD
	return 0
}

# Wait until the forked process has durably registered itself as CHILD or
# CLIENT (<token>.child or .client naming its PID), or is gone. Sets
# _AWG_BT_REGISTERED_START.
function _awgBtScratchAwaitRegistration() { # <CHILD|CLIENT> <pid>
	local I LIMIT FILE KEYS
	local -A REGISTERED_RECORD=()
	FILE="${DIR}/${TOKEN}.${1,,}"
	KEYS="_AWG_BT_SCRATCH_$1_KEYS"
	KEYS="${!KEYS}"
	_AWG_BT_REGISTERED_START=""
	LIMIT=$((AWG_BT_READY_TIMEOUT * 20))
	for ((I = 0; I < LIMIT; I++)); do
		if _awgBtScratchLoad "${FILE}" "${KEYS}" REGISTERED_RECORD && [[ "${REGISTERED_RECORD[$1_PID]}" == "$2" ]]; then
			_AWG_BT_REGISTERED_START="${REGISTERED_RECORD[$1_START]}"
			return 0
		fi
		[[ -d "${AWG_BT_PROC_DIR}/$2" ]] || return 1
		sleep 0.05
	done
	return 1
}

# In the forked child or systemd-run client, before it execs: record its own
# identity durably as <token>.child or .client, then go on only for a
# guardian that still lives.
function _awgBtScratchRegisterSelf() { # <CHILD|CLIENT>
	local START SELF="${BASHPID}" KEYS="_AWG_BT_SCRATCH_$1_KEYS"
	local -A SELF_RECORD=()
	START="$(_awgBtProcessStartTime "${SELF}")" || return 1
	# shellcheck disable=SC2034 # read by _awgBtScratchSave through its name
	SELF_RECORD=([FORMAT]=1 [TOKEN]="${TOKEN}" ["$1_PID"]="${SELF}" ["$1_START"]="${START}")
	_awgBtScratchSave "${DIR}/${TOKEN}.${1,,}" "${!KEYS}" SELF_RECORD || return 1
	# A reclaim marks the attempt before it reads the records, and this
	# process records itself before it reads the mark: either the reclaim
	# sees this record, or this process sees the mark and starts nothing.
	# The reclaim removes the owner record before the mark, and a token's
	# owner record is written once and never again, so the mark is read
	# first and the owner record after it: a mark that is already gone
	# means the owner record is gone too. Either one stops this process,
	# whether or not the guardian still lives.
	[[ ! -e "${DIR}/${TOKEN}.reclaim" ]] || return 1
	_awgBtScratchOwnerRecordValid || return 1
	_awgBtProcessIs "${GUARD_RECORD[GUARD_PID]}" "${GUARD_RECORD[GUARD_START]}"
}

# The attempt's owner record still exists and is the one the guardian read.
function _awgBtScratchOwnerRecordValid() {
	local -A CURRENT_OWNER=()
	_awgBtScratchLoad "${DIR}/${TOKEN}.owner" "${_AWG_BT_SCRATCH_OWNER_KEYS}" CURRENT_OWNER &&
		[[ "${CURRENT_OWNER[OWNER_PID]} ${CURRENT_OWNER[OWNER_START]}" == "${OWNER_RECORD[OWNER_PID]} ${OWNER_RECORD[OWNER_START]}" ]]
}

# The command line of a transient scratch unit: the production command line,
# behind a check that the attempt's owner record still exists and no reclaim
# has begun. A unit that systemd creates late, after its attempt was
# reclaimed, therefore exits at once instead of running BoringTun.
function _awgBtScratchUnitArgv() { # <token>
	local BASH_BIN DIR
	BASH_BIN="$(command -v bash)" || return 1
	DIR="$(_awgBtScratchDir)"
	# shellcheck disable=SC2016 # expanded by the unit's bash, not here
	_AWG_BT_UNIT_ARGV=("${BASH_BIN}" -c '[[ -e "$1" && ! -e "$2" ]] || exit 0; shift 2; exec "$@"' awg-scratch-unit
		"${DIR}/$1.owner" "${DIR}/$1.reclaim" "${_AWG_BT_ARGV[@]}")
}

# Wait until the daemon serves the name, recording what it provably owns,
# while the owner still wants it.
function _awgBtScratchAwaitReady() {
	local NAME="${GUARD_RECORD[NAME]}" I LIMIT MAIN="" START="" INDEX=""
	LIMIT=$((AWG_BT_READY_TIMEOUT * 10))
	for ((I = 0; I < LIMIT; I++)); do
		_awgBtScratchOwnerWants || return 1
		if [[ -z "${GUARD_RECORD[DAEMON_PID]}" ]]; then
			MAIN="$(systemctl show -p MainPID --value "${GUARD_RECORD[UNIT]}.service" 2>/dev/null)" || MAIN=""
			if [[ "${MAIN}" =~ ^[1-9][0-9]{0,9}$ ]] && START="$(_awgBtProcessStartTime "${MAIN}")"; then
				GUARD_RECORD[DAEMON_PID]="${MAIN}"
				GUARD_RECORD[DAEMON_START]="${START}"
				_awgBtScratchSave "${GUARD_FILE}" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD || return 1
			fi
		fi
		if [[ -n "${GUARD_RECORD[DAEMON_PID]}" ]]; then
			_awgBtProcessIs "${GUARD_RECORD[DAEMON_PID]}" "${GUARD_RECORD[DAEMON_START]}" || return 1
			_awgBtScratchRecordSockets || return 1
			if [[ -n "${GUARD_RECORD[WG_SOCK]}" && -n "${GUARD_RECORD[AWG_SOCK]}" ]] && _awgBtLinkIsTun "${NAME}" &&
				INDEX="$(_awgBtLinkIndex "${NAME}")" && _awgBtUapiReady "${NAME}"; then
				_awgBtProveUapiNodes "${NAME}" "${GUARD_RECORD[DAEMON_PID]}" "${GUARD_RECORD[DAEMON_START]}"
				if [[ -n "${_AWG_BT_WG_ID}" && -n "${_AWG_BT_AWG_ID}" ]]; then
					GUARD_RECORD[WG_SOCK]="${_AWG_BT_WG_ID}"
					GUARD_RECORD[AWG_SOCK]="${_AWG_BT_AWG_ID}"
					GUARD_RECORD[IFINDEX]="${INDEX}"
					GUARD_RECORD[PHASE]=created
					_awgBtScratchSave "${GUARD_FILE}" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD && return 0
					GUARD_RECORD[PHASE]=starting
					return 1
				fi
			fi
		fi
		sleep 0.1
	done
	return 1
}

function _awgBtScratchRecordSockets() {
	local CHANGED=0
	_awgBtProveUapiNodes "${GUARD_RECORD[NAME]}" "${GUARD_RECORD[DAEMON_PID]}" "${GUARD_RECORD[DAEMON_START]}"
	if [[ -z "${GUARD_RECORD[WG_SOCK]}" && -n "${_AWG_BT_WG_ID}" ]]; then
		GUARD_RECORD[WG_SOCK]="${_AWG_BT_WG_ID}"
		CHANGED=1
	fi
	if [[ -z "${GUARD_RECORD[AWG_SOCK]}" && -n "${_AWG_BT_AWG_ID}" ]]; then
		GUARD_RECORD[AWG_SOCK]="${_AWG_BT_AWG_ID}"
		CHANGED=1
	fi
	((CHANGED == 0)) || _awgBtScratchSave "${GUARD_FILE}" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD
}

# Remove what remains of one attempt, as its records say. It first marks the
# attempt as being reclaimed (<token>.reclaim), before it reads any record: a
# process that registers itself later sees the mark and starts nothing
# (_awgBtScratchRegisterSelf), and the unit's own command checks it too. Then
# it waits for a registered systemd-run client that still lives: while it
# lives it may still create the unit, so the records are kept (it is never
# signalled). Then it removes the TUN link only
# while it has the recorded ifindex, the transient unit by its attempt-unique
# name, the daemon (from the guardian's record or the direct child's own) only
# while it is the recorded process, and socket nodes only while they are the
# recorded nodes, proven the daemon's, and their daemon is gone. The records
# are removed only when nothing of the attempt is left, so an interrupted or
# incomplete reclaim is retried later.
function _awgBtScratchReclaim() { # <token>
	local TOKEN="$1" DIR NAME MODE UNIT WG_NODE AWG_NODE STATE="" MAIN="" START="" I LEFT=0
	local HAVE_OWNER=0 HAVE_GUARD=0 HAVE_CHILD=0 HAVE_CLIENT=0
	local -A OWNER_RECORD=() GUARD_RECORD=() CHILD_RECORD=() CLIENT_RECORD=()
	DIR="$(_awgBtScratchDir)"
	if [[ ! -e "${DIR}/${TOKEN}.reclaim" ]] && ! _awgBtWriteState "${DIR}/${TOKEN}.reclaim" ""; then
		_awgBtErr "cannot mark scratch attempt ${TOKEN} as being reclaimed; its records are kept"
		LEFT=1
	fi
	_awgBtScratchLoad "${DIR}/${TOKEN}.owner" "${_AWG_BT_SCRATCH_OWNER_KEYS}" OWNER_RECORD && HAVE_OWNER=1
	_awgBtScratchLoad "${DIR}/${TOKEN}.guard" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD && HAVE_GUARD=1
	_awgBtScratchLoad "${DIR}/${TOKEN}.child" "${_AWG_BT_SCRATCH_CHILD_KEYS}" CHILD_RECORD && HAVE_CHILD=1
	_awgBtScratchLoad "${DIR}/${TOKEN}.client" "${_AWG_BT_SCRATCH_CLIENT_KEYS}" CLIENT_RECORD && HAVE_CLIENT=1
	if { ((HAVE_OWNER == 0)) && [[ -e "${DIR}/${TOKEN}.owner" || -L "${DIR}/${TOKEN}.owner" ]]; } ||
		{ ((HAVE_GUARD == 0)) && [[ -e "${DIR}/${TOKEN}.guard" || -L "${DIR}/${TOKEN}.guard" ]]; } ||
		{ ((HAVE_CHILD == 0)) && [[ -e "${DIR}/${TOKEN}.child" || -L "${DIR}/${TOKEN}.child" ]]; } ||
		{ ((HAVE_CLIENT == 0)) && [[ -e "${DIR}/${TOKEN}.client" || -L "${DIR}/${TOKEN}.client" ]]; }; then
		_awgBtErr "the records of scratch attempt ${TOKEN} are unreadable; they and anything they describe are left alone"
		return 1
	fi
	if ((HAVE_OWNER && HAVE_GUARD)) && [[ "${OWNER_RECORD[NAME]} ${OWNER_RECORD[UNIT]}" != "${GUARD_RECORD[NAME]} ${GUARD_RECORD[UNIT]}" ]]; then
		_awgBtErr "the records of scratch attempt ${TOKEN} are inconsistent; they and anything they describe are left alone"
		return 1
	fi
	# A live registered systemd-run client may still create the unit: wait for
	# it, and keep everything while it lives.
	if ((HAVE_CLIENT)); then
		for ((I = 0; I < _AWG_BT_SCRATCH_CLIENT_WAIT * 10; I++)); do
			_awgBtProcessIs "${CLIENT_RECORD[CLIENT_PID]}" "${CLIENT_RECORD[CLIENT_START]}" || break
			sleep 0.1
		done
		if _awgBtProcessIs "${CLIENT_RECORD[CLIENT_PID]}" "${CLIENT_RECORD[CLIENT_START]}"; then
			_awgBtErr "the systemd-run client of scratch attempt ${TOKEN} still runs and may still create its unit; the records are kept"
			return 1
		fi
	fi
	if ((HAVE_OWNER == 0 && HAVE_GUARD == 0)); then
		if ((HAVE_CHILD)) && _awgBtProcessIs "${CHILD_RECORD[CHILD_PID]}" "${CHILD_RECORD[CHILD_START]}"; then
			_awgBtStopProcess "${CHILD_RECORD[CHILD_PID]}" "${CHILD_RECORD[CHILD_START]}" || return 1
		fi
		((LEFT == 0)) || return 1
		rm -f -- "${DIR}/${TOKEN}.child" "${DIR}/${TOKEN}.client" "${DIR}/${TOKEN}.stop"
		rm -f -- "${DIR}/${TOKEN}.reclaim"
		return 0
	fi
	if ((HAVE_GUARD)); then
		NAME="${GUARD_RECORD[NAME]}"
		MODE="${GUARD_RECORD[MODE]}"
		UNIT="${GUARD_RECORD[UNIT]}"
	else
		NAME="${OWNER_RECORD[NAME]}"
		MODE="${OWNER_RECORD[MODE]}"
		UNIT="${OWNER_RECORD[UNIT]}"
		GUARD_RECORD=([DAEMON_PID]="" [DAEMON_START]="" [IFINDEX]="" [WG_SOCK]="" [AWG_SOCK]="")
	fi
	if [[ -z "${GUARD_RECORD[DAEMON_PID]}" ]] && ((HAVE_CHILD)); then
		GUARD_RECORD[DAEMON_PID]="${CHILD_RECORD[CHILD_PID]}"
		GUARD_RECORD[DAEMON_START]="${CHILD_RECORD[CHILD_START]}"
	fi
	WG_NODE="${AWG_BT_WG_SOCKET_DIR}/${NAME}.sock"
	AWG_NODE="${AWG_BT_AWG_SOCKET_DIR}/${NAME}.sock"
	# A daemon that was never recorded is the main process of the attempt's
	# own unit. Socket nodes it holds but that were not recorded yet are
	# recorded now, while it provably still runs and holds them.
	if [[ "${MODE}" == unit && -z "${GUARD_RECORD[DAEMON_PID]}" ]]; then
		MAIN="$(systemctl show -p MainPID --value "${UNIT}.service" 2>/dev/null)" || MAIN=""
		if [[ "${MAIN}" =~ ^[1-9][0-9]{0,9}$ ]] && START="$(_awgBtProcessStartTime "${MAIN}")"; then
			GUARD_RECORD[DAEMON_PID]="${MAIN}"
			GUARD_RECORD[DAEMON_START]="${START}"
		fi
	fi
	if [[ -n "${GUARD_RECORD[DAEMON_PID]}" ]] && _awgBtProcessIs "${GUARD_RECORD[DAEMON_PID]}" "${GUARD_RECORD[DAEMON_START]}"; then
		_awgBtProveUapiNodes "${NAME}" "${GUARD_RECORD[DAEMON_PID]}" "${GUARD_RECORD[DAEMON_START]}"
		[[ -n "${GUARD_RECORD[WG_SOCK]}" ]] || GUARD_RECORD[WG_SOCK]="${_AWG_BT_WG_ID}"
		[[ -n "${GUARD_RECORD[AWG_SOCK]}" ]] || GUARD_RECORD[AWG_SOCK]="${_AWG_BT_AWG_ID}"
		((HAVE_GUARD == 0)) || _awgBtScratchSave "${DIR}/${TOKEN}.guard" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD
	fi
	if [[ -n "${GUARD_RECORD[IFINDEX]}" && "$(_awgBtLinkIndex "${NAME}")" == "${GUARD_RECORD[IFINDEX]}" ]] &&
		_awgBtLinkIsTun "${NAME}"; then
		ip link delete dev "${NAME}" >/dev/null 2>&1
	fi
	if [[ "${MODE}" == unit ]]; then
		systemctl stop "${UNIT}.service" >/dev/null 2>&1
		systemctl reset-failed "${UNIT}.service" >/dev/null 2>&1
		STATE="$(systemctl show -p ActiveState --value "${UNIT}.service" 2>/dev/null)" || STATE=""
		[[ "${STATE}" == inactive || "${STATE}" == failed ]] || LEFT=1
	fi
	if [[ -n "${GUARD_RECORD[DAEMON_PID]}" ]] && ! _awgBtStopProcess "${GUARD_RECORD[DAEMON_PID]}" "${GUARD_RECORD[DAEMON_START]}"; then
		LEFT=1
	fi
	# A recorded node that may still be there keeps the records, also when its
	# identity cannot be read.
	_awgBtRemoveOwnedPath "${WG_NODE}" "${GUARD_RECORD[WG_SOCK]}" "${GUARD_RECORD[DAEMON_PID]}" "${GUARD_RECORD[DAEMON_START]}" || LEFT=1
	_awgBtRemoveOwnedPath "${AWG_NODE}" "${GUARD_RECORD[AWG_SOCK]}" "${GUARD_RECORD[DAEMON_PID]}" "${GUARD_RECORD[DAEMON_START]}" || LEFT=1
	if [[ -n "${GUARD_RECORD[IFINDEX]}" && "$(_awgBtLinkIndex "${NAME}")" == "${GUARD_RECORD[IFINDEX]}" ]]; then
		LEFT=1
	fi
	if [[ -n "${GUARD_RECORD[WG_SOCK]}" && "$(_awgBtPathId "${WG_NODE}")" == "${GUARD_RECORD[WG_SOCK]}" ]] ||
		[[ -n "${GUARD_RECORD[AWG_SOCK]}" && "$(_awgBtPathId "${AWG_NODE}")" == "${GUARD_RECORD[AWG_SOCK]}" ]]; then
		LEFT=1
	fi
	if ((LEFT)); then
		_awgBtErr "scratch interface ${NAME} is not completely removed yet; its records are kept for a later sweep"
		return 1
	fi
	# The owner record goes first and the mark last, so at every moment one of
	# them tells a late registrant to start nothing (_awgBtScratchRegisterSelf).
	rm -f -- "${DIR}/${TOKEN}.owner" || return 1
	rm -f -- "${DIR}/${TOKEN}.guard" "${DIR}/${TOKEN}.child" "${DIR}/${TOKEN}.client" "${DIR}/${TOKEN}.stop"
	rm -f -- "${DIR}/${TOKEN}.reclaim"
}

# Reclaim every attempt whose owner and guardian are both gone: the owner was
# killed together with its guardian, or the guardian was killed and the owner
# exited later. Liveness is proven by PID and start time, never by name, and
# an attempt with an unreadable record is left alone.
function _awgBtScratchSweep() {
	local DIR FILE TOKEN ALIVE
	local -A OWNER_RECORD=() GUARD_RECORD=() SWEPT=()
	DIR="$(_awgBtScratchDir)"
	[[ -d "${DIR}" && ! -L "${DIR}" ]] || return 0
	for FILE in "${DIR}"/*; do
		[[ "${FILE##*/}" =~ ^([0-9a-f]{32})\.(owner|guard|child|client|stop|reclaim)$ ]] || continue
		TOKEN="${BASH_REMATCH[1]}"
		[[ -z "${SWEPT[${TOKEN}]+set}" ]] || continue
		SWEPT["${TOKEN}"]=1
		ALIVE=0
		if _awgBtScratchLoad "${DIR}/${TOKEN}.owner" "${_AWG_BT_SCRATCH_OWNER_KEYS}" OWNER_RECORD; then
			_awgBtProcessIs "${OWNER_RECORD[OWNER_PID]}" "${OWNER_RECORD[OWNER_START]}" && ALIVE=1
		elif [[ -e "${DIR}/${TOKEN}.owner" || -L "${DIR}/${TOKEN}.owner" ]]; then
			continue
		fi
		if _awgBtScratchLoad "${DIR}/${TOKEN}.guard" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD; then
			_awgBtProcessIs "${GUARD_RECORD[GUARD_PID]}" "${GUARD_RECORD[GUARD_START]}" && ALIVE=1
		elif [[ -e "${DIR}/${TOKEN}.guard" || -L "${DIR}/${TOKEN}.guard" ]]; then
			continue
		fi
		((ALIVE)) && continue
		_awgBtScratchReclaim "${TOKEN}"
	done
	return 0
}

function _awgBtScratchCreate() {
	local NAME="$1" TOKEN MODE UNIT="" OWNER OWNER_START GUARD GUARD_START DIR I LIMIT
	local -A OWNER_RECORD=() GUARD_RECORD=()
	if ! [[ "${NAME}" =~ ^[a-zA-Z0-9_-]{1,15}$ ]]; then
		_awgBtErr "invalid scratch interface name ${NAME}"
		return 1
	fi
	if [[ -n "${_AWG_BT_SCRATCH_TOKENS[${NAME}]+set}" ]]; then
		_awgBtErr "scratch interface ${NAME} already exists in this shell"
		return 1
	fi
	if ip link show dev "${NAME}" >/dev/null 2>&1 ||
		[[ -e "${AWG_BT_WG_SOCKET_DIR}/${NAME}.sock" || -L "${AWG_BT_WG_SOCKET_DIR}/${NAME}.sock" ||
			-e "${AWG_BT_AWG_SOCKET_DIR}/${NAME}.sock" || -L "${AWG_BT_AWG_SOCKET_DIR}/${NAME}.sock" ]] ||
		_awgBtListedByAwg "${NAME}"; then
		_awgBtErr "refusing to start scratch interface ${NAME}: the name is already in use"
		return 1
	fi
	OWNER="${BASHPID}"
	if ! OWNER_START="$(_awgBtProcessStartTime "${OWNER}")"; then
		_awgBtErr "cannot identify the shell that owns scratch interface ${NAME}"
		return 1
	fi
	if ! _awgBtPrepareScratchDir; then
		_awgBtErr "cannot prepare the private scratch directory $(_awgBtScratchDir)"
		return 1
	fi
	_awgBtScratchSweep
	# The release current selects, or the candidate a lifecycle transaction
	# validates before it may become current; either is verified here.
	if [[ -n "${_AWG_BT_CANDIDATE_RELEASE}" ]]; then
		_awgBtVerifyRelease "${_AWG_BT_CANDIDATE_RELEASE}" || return 1
	else
		_awgBtVerifyStore || return 1
	fi
	if ! _awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "${AWG_BORINGTUN_IMITATE_PROTOCOL:-none}"; then
		_awgBtErr "the verified BoringTun binary ${_AWG_BT_VERIFIED_BIN} does not support protocol imitation ${AWG_BORINGTUN_IMITATE_PROTOCOL:-none}, or did not say that it does; no scratch instance was started"
		return 1
	fi
	_awgBtDaemonArgv "${_AWG_BT_VERIFIED_BIN}" "${NAME}" "${AWG_BORINGTUN_IMITATE_PROTOCOL:-none}" "${AWG_BORINGTUN_IMITATE_DOMAIN:-}" || return 1
	if ! TOKEN="$(_awgBtNewToken)"; then
		_awgBtErr "cannot draw a token for scratch interface ${NAME}"
		return 1
	fi
	if [[ -d "${AWG_BT_SYSTEMD_RUNTIME_DIR}" ]] && command -v systemd-run >/dev/null 2>&1; then
		MODE=unit
		UNIT="amneziawg-scratch-${NAME}-${TOKEN}"
		_awgBtScratchUnitArgv "${TOKEN}" || return 1
		if [[ "$(systemctl show -p LoadState --value "${UNIT}.service" 2>/dev/null)" != not-found ]]; then
			_awgBtErr "refusing to start scratch interface ${NAME}: the unit ${UNIT} already exists"
			return 1
		fi
	else
		MODE=direct
		if ! command -v setpriv >/dev/null 2>&1; then
			_awgBtErr "setpriv is required to tie a scratch daemon to its guardian"
			return 1
		fi
	fi
	DIR="$(_awgBtScratchDir)"
	OWNER_RECORD=([FORMAT]=1 [TOKEN]="${TOKEN}" [NAME]="${NAME}" [MODE]="${MODE}" [UNIT]="${UNIT}"
		[OWNER_PID]="${OWNER}" [OWNER_START]="${OWNER_START}")
	if ! _awgBtScratchSave "${DIR}/${TOKEN}.owner" "${_AWG_BT_SCRATCH_OWNER_KEYS}" OWNER_RECORD; then
		_awgBtErr "cannot record scratch interface ${NAME}"
		return 1
	fi
	_awgBtScratchGuardian "${TOKEN}" </dev/null >/dev/null 2>&1 &
	GUARD=$!
	if ! GUARD_START="$(_awgBtProcessStartTime "${GUARD}")"; then
		# The guardian exited at once and was reaped, so its PID is not
		# signalled.
		wait "${GUARD}" 2>/dev/null
		_awgBtScratchReclaim "${TOKEN}"
		_awgBtErr "cannot identify the guardian of scratch interface ${NAME}"
		return 1
	fi
	_AWG_BT_SCRATCH_TOKENS["${NAME}"]="${TOKEN}"
	_AWG_BT_SCRATCH_GUARDS["${NAME}"]="${GUARD}"
	_AWG_BT_SCRATCH_GUARD_STARTS["${NAME}"]="${GUARD_START}"
	# systemd-run may take a while; the guardian waits for it in any case.
	LIMIT=$(((AWG_BT_READY_TIMEOUT + 30) * 10))
	for ((I = 0; I < LIMIT; I++)); do
		if _awgBtScratchLoad "${DIR}/${TOKEN}.guard" "${_AWG_BT_SCRATCH_GUARD_KEYS}" GUARD_RECORD; then
			[[ "${GUARD_RECORD[PHASE]}" == created ]] && return 0
			[[ "${GUARD_RECORD[PHASE]}" == teardown ]] && break
		fi
		_awgBtProcessIs "${GUARD}" "${GUARD_START}" || break
		sleep 0.1
	done
	_awgBtErr "scratch interface ${NAME} did not become ready"
	_awgBtScratchDestroy "${NAME}"
	return 1
}

# Ask the guardian to tear the instance down and wait until it has finished,
# then reap it. A guardian that is gone or hangs is replaced by a reclaim from
# the records here.
function _awgBtScratchDestroy() {
	local NAME="$1" TOKEN GUARD GUARD_START DIR I RC=0
	TOKEN="${_AWG_BT_SCRATCH_TOKENS[${NAME}]:-}"
	if [[ -z "${TOKEN}" ]]; then
		_awgBtErr "scratch interface ${NAME} was not started here"
		return 1
	fi
	GUARD="${_AWG_BT_SCRATCH_GUARDS[${NAME}]}"
	GUARD_START="${_AWG_BT_SCRATCH_GUARD_STARTS[${NAME}]}"
	DIR="$(_awgBtScratchDir)"
	if ! { : >"${DIR}/${TOKEN}.stop"; } 2>/dev/null; then
		_awgBtErr "cannot ask the guardian of scratch interface ${NAME} to stop; stopping it"
		_awgBtSignalProcess "${GUARD}" "${GUARD_START}" KILL
	fi
	for ((I = 0; I < 300; I++)); do
		_awgBtProcessIs "${GUARD}" "${GUARD_START}" || break
		sleep 0.1
	done
	if _awgBtProcessIs "${GUARD}" "${GUARD_START}"; then
		_awgBtErr "the guardian of scratch interface ${NAME} did not finish its teardown; stopping it"
		_awgBtSignalProcess "${GUARD}" "${GUARD_START}" KILL
		for ((I = 0; I < 30; I++)); do
			_awgBtProcessIs "${GUARD}" "${GUARD_START}" || break
			sleep 0.1
		done
	fi
	# Reap the guardian. In a shell that is not its parent this fails at once.
	_awgBtProcessIs "${GUARD}" "${GUARD_START}" || wait "${GUARD}" 2>/dev/null
	_awgBtScratchReclaim "${TOKEN}" || RC=1
	unset "_AWG_BT_SCRATCH_TOKENS[${NAME}]" "_AWG_BT_SCRATCH_GUARDS[${NAME}]" "_AWG_BT_SCRATCH_GUARD_STARTS[${NAME}]"
	return "${RC}"
}

# ── BoringTun host installation (experimental) ───────────────────────────────
# A fresh BoringTun install on a Debian or Ubuntu host with systemd, and its
# uninstall. Management of an installed host goes through the runtime layer
# above. Nothing here runs for the kernel backend.
#
# The binary comes from the immutable public release named by the
# AWG_BT_RELEASE_* constants: one exact URL per architecture, the archive
# checked against its embedded SHA-256 before anything is extracted, then the
# archive layout, the MANIFEST, the binary's SHA-256 and its version, and only
# then an atomic install into the store that _awgBtVerifyStore checks at every
# start. A store that already holds a valid release is reused as it is and
# never replaced: upgrades are not part of this installer version.

# The release asset for an architecture (x86_64 or aarch64): sets
# _AWG_BT_REL_ASSET, _AWG_BT_REL_ARCHIVE_ID (the archive's top-level
# directory), _AWG_BT_REL_ID (the store's release directory,
# _awgBtReleaseStoreId: the archive's directory for build 1),
# _AWG_BT_REL_ARCHIVE_SHA256 and _AWG_BT_REL_BINARY_SHA256.
function _awgBtSelectRelease() {
	case "$1" in
		x86_64)
			_AWG_BT_REL_ASSET="${AWG_BT_RELEASE_ASSET_X86_64}"
			_AWG_BT_REL_ARCHIVE_SHA256="${AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64}"
			_AWG_BT_REL_BINARY_SHA256="${AWG_BT_RELEASE_BINARY_SHA256_X86_64}"
			;;
		aarch64)
			_AWG_BT_REL_ASSET="${AWG_BT_RELEASE_ASSET_AARCH64}"
			_AWG_BT_REL_ARCHIVE_SHA256="${AWG_BT_RELEASE_ARCHIVE_SHA256_AARCH64}"
			_AWG_BT_REL_BINARY_SHA256="${AWG_BT_RELEASE_BINARY_SHA256_AARCH64}"
			;;
		*) return 1 ;;
	esac
	_AWG_BT_REL_ARCHIVE_ID="${_AWG_BT_REL_ASSET%.tar.gz}"
	_AWG_BT_REL_ID="$(_awgBtReleaseStoreId "${AWG_BT_RELEASE_VERSION}" "${AWG_BT_RELEASE_SOURCE_COMMIT}" "${AWG_BT_RELEASE_BUILD}" "$1")" || return 1
}

# The store directory of a release: build 1 keeps the name every earlier
# installer gave it, a later build adds -b<build> (_awgBtReleaseIdValid).
function _awgBtReleaseStoreId() { # <version> <source commit> <build> <arch>
	local SUFFIX=""
	[[ "$3" =~ ^[1-9][0-9]{0,8}$ ]] || return 1
	[[ "$3" == 1 ]] || SUFFIX="-b$3"
	printf 'boringtun-cli-%s-g%s%s-linux-%s-musl\n' "$1" "${2:0:12}" "${SUFFIX}" "$4"
}

# Print the paths that show a standalone amneziawg-proxy installation. Its
# uninstaller keeps proxy.toml unless --purge-config is given, and even a
# leftover proxy.toml counts: removing it is the operator's decision.
function boringtunProxyInstallPaths() {
	local CANDIDATE
	for CANDIDATE in ${AWG_PROXY_INSTALL_PATHS}; do
		if [[ -e "${CANDIDATE}" || -L "${CANDIDATE}" ]]; then
			printf '%s\n' "${CANDIDATE}"
		fi
	done
}

# The web panel's lifecycle-script copy, as its service configuration names it.
function webPanelLifecycleScriptPath() {
	local SCRIPT=""
	SCRIPT="$(readWebPanelSetting AWG_INSTALL_SCRIPT 2>/dev/null)" || SCRIPT=""
	printf '%s\n' "${SCRIPT:-${WEB_PANEL_LIFECYCLE_SCRIPT}}"
}

# Succeed when no web panel is installed, or when its lifecycle-script copy
# carries this installer's BoringTun host capability line. The copy is read as
# data, never sourced or run.
function webPanelLifecycleScriptSupportsBoringtun() {
	local SCRIPT
	isWebPanelInstalled || return 0
	SCRIPT="$(webPanelLifecycleScriptPath)"
	[[ -f "${SCRIPT}" && -r "${SCRIPT}" ]] || return 1
	grep -qxF "AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST=\"${AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST}\"" -- "${SCRIPT}"
}

# Decide about an AmneziaWG kernel module before anything is installed. A
# loaded module is never unloaded, and an installed one is blocked only with
# the operator's explicit consent: a prompt, or AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y
# with AUTO_INSTALL. Sets _AWG_BT_WRITE_MODPROBE_OVERRIDE.
function boringtunKernelModuleDecision() {
	local ANSWER=""
	_AWG_BT_WRITE_MODPROBE_OVERRIDE=0
	if [[ -e "${AWG_BT_SYS_DIR}/module/amneziawg" ]]; then
		echo -e "${RED}ERROR: the AmneziaWG kernel module is loaded, so awg-quick would use it instead of BoringTun.${NC}" >&2
		echo -e "${ORANGE}This installer never unloads it. Keep the kernel backend, or stop what uses the module, run 'modprobe -r amneziawg', remove amneziawg-dkms and rerun.${NC}" >&2
		return 1
	fi
	if ! command -v modinfo >/dev/null 2>&1; then
		echo -e "${RED}ERROR: modinfo (kmod) is required to rule out an AmneziaWG kernel module that awg-quick would load instead of BoringTun.${NC}" >&2
		return 1
	fi
	if ! modinfo -n amneziawg >/dev/null 2>&1 || _awgBtKernelModuleBlocked; then
		return 0
	fi
	echo -e "${ORANGE}An AmneziaWG kernel module is installed on this host (for example by amneziawg-dkms).${NC}" >&2
	echo -e "${ORANGE}awg-quick would load it and create a kernel interface instead of starting BoringTun.${NC}" >&2
	echo -e "${ORANGE}The installer can block it with ${AWG_BT_MODPROBE_OVERRIDE} ('install amneziawg /bin/false'). That stops every use of the module on this host until the file is removed; uninstalling this BoringTun installation removes it.${NC}" >&2
	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		if [[ "${AWG_BORINGTUN_BLOCK_KERNEL_MODULE:-}" != "y" ]]; then
			echo -e "${RED}ERROR: refusing to block the kernel module without consent. Remove amneziawg-dkms first, or rerun with AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y.${NC}" >&2
			return 1
		fi
	else
		read -rp "Block the AmneziaWG kernel module on this host? [y/N]: " -e ANSWER
		if [[ "${ANSWER}" != [yY] ]]; then
			echo -e "${RED}ERROR: the kernel module stays usable, so BoringTun cannot be installed. Remove amneziawg-dkms first, or accept the block.${NC}" >&2
			return 1
		fi
	fi
	_AWG_BT_WRITE_MODPROBE_OVERRIDE=1
}

# Everything that must hold before a BoringTun install asks its questions or
# changes the host.
function checkBoringtunHostSupport() {
	local ARCH PROXY_PATHS SCRIPT
	if [[ "${OS}" != "ubuntu" && "${OS}" != "debian" ]]; then
		echo -e "${RED}ERROR: the BoringTun backend is supported only on Debian and Ubuntu hosts.${NC}" >&2
		return 1
	fi
	if ! ARCH="$(_awgBtHostArch)" || ! _awgBtSelectRelease "${ARCH}"; then
		echo -e "${RED}ERROR: BoringTun releases exist only for x86_64 and aarch64 hosts, not for $(uname -m 2>/dev/null).${NC}" >&2
		return 1
	fi
	if [[ ! -d "${AWG_BT_SYSTEMD_RUNTIME_DIR}" ]]; then
		echo -e "${RED}ERROR: the BoringTun backend needs a host running systemd.${NC}" >&2
		return 1
	fi
	PROXY_PATHS="$(boringtunProxyInstallPaths)"
	if [[ -n "${PROXY_PATHS}" ]]; then
		echo -e "${RED}ERROR: the standalone amneziawg-proxy is installed (${PROXY_PATHS//$'\n'/, }).${NC}" >&2
		echo -e "${ORANGE}The BoringTun backend cannot be used behind the standalone proxy. Keep the kernel backend, or uninstall the proxy first with amneziawg-proxy-uninstall.sh --restore-awg --purge-config.${NC}" >&2
		return 1
	fi
	if ! webPanelLifecycleScriptSupportsBoringtun; then
		SCRIPT="$(webPanelLifecycleScriptPath)"
		if [[ -f "${SCRIPT}" ]]; then
			echo -e "${RED}ERROR: the installed web panel runs ${SCRIPT} for client operations, and that copy predates BoringTun host support.${NC}" >&2
			echo -e "${ORANGE}It would treat a BoringTun host as a kernel host. Upgrade the web panel so that it installs this version of amneziawg-install.sh, then rerun.${NC}" >&2
		else
			echo -e "${RED}ERROR: the installed web panel names ${SCRIPT} for client operations, but that copy of amneziawg-install.sh is missing, so its BoringTun support cannot be checked.${NC}" >&2
			echo -e "${ORANGE}Reinstall or upgrade the web panel so that it installs this version of amneziawg-install.sh, then rerun.${NC}" >&2
		fi
		return 1
	fi
	if ! _awgBtCheckPlatform; then
		echo -e "${RED}ERROR: this host cannot run BoringTun.${NC}" >&2
		return 1
	fi
	boringtunKernelModuleDecision
}

# amneziawg-tools and the firewall and QR tools, never the kernel module: the
# tools only recommend amneziawg-dkms, so --no-install-recommends keeps DKMS,
# headers and the module off the host. Runs inside the APT IPv4 window.
function installBoringtunHostPackages() {
	if [[ ${OS} == 'ubuntu' ]]; then
		prepareUbuntuAmneziaPpaForInstall
		apt-get install -y --no-install-recommends amneziawg-tools || { echo -e "${RED}ERROR: amneziawg-tools could not be installed.${NC}"; exit 1; }
		apt-get install -y iptables nftables qrencode || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'debian' ]]; then
		if ! command -v curl &>/dev/null; then
			apt-get update
			apt-get install -y curl || { echo -e "${RED}ERROR: Failed to install curl, which downloads the BoringTun release.${NC}"; exit 1; }
		fi
		configureDebianAmneziaAptSource 0
		apt-get update || { echo -e "${RED}ERROR: Failed to update package index.${NC}"; exit 1; }
		apt-get install -y --no-install-recommends amneziawg-tools || { echo -e "${RED}ERROR: amneziawg-tools could not be installed.${NC}"; exit 1; }
		apt-get install -y qrencode iptables nftables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	fi
}

# Check a release directory against the embedded contract: exactly the four
# regular files, a MANIFEST that describes this exact release (read as data),
# and a binary with the embedded SHA-256. Nothing in it runs.
function _awgBtCheckReleaseDir() { # <dir> <arch>
	local DIR="$1" ARCH="$2" FILE LINE KEY VALUE ACTUAL
	local -A FIELDS=()
	for FILE in LICENSE MANIFEST THIRD-PARTY-LICENSES boringtun-cli; do
		if [[ -L "${DIR}/${FILE}" || ! -f "${DIR}/${FILE}" ]]; then
			echo "ERROR: the BoringTun release has no regular file ${FILE}" >&2
			return 1
		fi
	done
	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		if [[ ! "${LINE}" =~ ^([a-z0-9_]+)=([^[:cntrl:]]*)$ ]]; then
			echo "ERROR: the BoringTun release MANIFEST has a malformed line" >&2
			return 1
		fi
		KEY="${BASH_REMATCH[1]}"
		VALUE="${BASH_REMATCH[2]}"
		if [[ " ${AWG_BT_MANIFEST_KEYS} " != *" ${KEY} "* || -n "${FIELDS[${KEY}]+set}" ]]; then
			echo "ERROR: the BoringTun release MANIFEST has an unexpected or repeated key ${KEY}" >&2
			return 1
		fi
		FIELDS["${KEY}"]="${VALUE}"
	done <"${DIR}/MANIFEST"
	for KEY in ${AWG_BT_MANIFEST_KEYS}; do
		if [[ -z "${FIELDS[${KEY}]+set}" ]]; then
			echo "ERROR: the BoringTun release MANIFEST has no ${KEY}" >&2
			return 1
		fi
	done
	if [[ "${FIELDS[artifact_format]}" != 1 || "${FIELDS[name]}" != boringtun-cli ||
		"${FIELDS[version]}" != "${AWG_BT_RELEASE_VERSION}" ||
		"${FIELDS[source_repository]}" != "${AWG_BT_RELEASE_SOURCE_REPOSITORY}" ||
		"${FIELDS[source_commit]}" != "${AWG_BT_RELEASE_SOURCE_COMMIT}" ||
		"${FIELDS[target]}" != "${ARCH}-unknown-linux-musl" || "${FIELDS[arch]}" != "${ARCH}" ||
		"${FIELDS[os]}" != linux || "${FIELDS[libc]}" != musl || "${FIELDS[linkage]}" != static ||
		"${FIELDS[binary]}" != boringtun-cli || "${FIELDS[binary_sha256]}" != "${_AWG_BT_REL_BINARY_SHA256}" ]]; then
		echo "ERROR: the BoringTun release MANIFEST does not describe ${_AWG_BT_REL_ID} (${AWG_BT_RELEASE_SOURCE_COMMIT})" >&2
		return 1
	fi
	ACTUAL="$(sha256sum -- "${DIR}/boringtun-cli" 2>/dev/null)" || ACTUAL=""
	if [[ "${ACTUAL%% *}" != "${_AWG_BT_REL_BINARY_SHA256}" ]]; then
		echo "ERROR: boringtun-cli does not have the SHA-256 embedded in this installer (${_AWG_BT_REL_BINARY_SHA256})" >&2
		return 1
	fi
}

# The one verification boundary for a release directory in the store, staged
# or already there, before anything in it runs:
#  1. the trusted path: every directory from the trust anchor down, the
#     release directory itself, and exactly the four members as trusted
#     regular files (the binary executable) with a single link each, so no
#     symlink or hard link stands in for them and only root can change them;
#  2. the embedded contract (_awgBtCheckReleaseDir), which reads the MANIFEST
#     as data and hashes the binary;
#  3. the binary is still the node that was hashed and still trusted, and only
#     then does it run, to report the release version.
# A directory that fails is never run and never made current. Between the last
# check and the exec only root could replace the binary.
# With a release id as third argument, DIR is that release in the store and is
# verified against its own MANIFEST (_awgBtVerifyRelease, the runtime's check)
# and the embedded source repository instead of against the pinned release: a
# release an earlier lifecycle operation installed, such as the rollback
# target. Its binary runs (--version) only after the same trust, member and
# hash checks as a pinned candidate.
function _awgBtVerifyCandidate() { # <release dir> <arch> [<installed release id>]
	local DIR="$1" ARCH="$2" FILE KIND MEMBERS NODE_ID VERSION
	local INSTALLED="${3:-}" EXPECTED_VERSION="${AWG_BT_RELEASE_VERSION}" REPOSITORY=""
	if ! _awgBtTrustedAncestors "${DIR}" || ! _awgBtTrustedNode "${DIR}" dir; then
		echo "ERROR: the BoringTun release directory ${DIR}, or a directory above it, is not root-owned or is writable by others" >&2
		return 1
	fi
	MEMBERS="$(find "${DIR}" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | LC_ALL=C sort)" || MEMBERS=""
	if [[ "${MEMBERS}" != $'LICENSE\nMANIFEST\nTHIRD-PARTY-LICENSES\nboringtun-cli' ]]; then
		echo "ERROR: the BoringTun release directory ${DIR} does not hold exactly the release's four files" >&2
		return 1
	fi
	for FILE in LICENSE MANIFEST THIRD-PARTY-LICENSES boringtun-cli; do
		KIND="file"
		[[ "${FILE}" != boringtun-cli ]] || KIND="exec"
		if ! _awgBtTrustedNode "${DIR}/${FILE}" "${KIND}" || [[ "$(stat -c '%h' -- "${DIR}/${FILE}" 2>/dev/null)" != 1 ]]; then
			echo "ERROR: ${DIR}/${FILE} is not a root-owned, single-link regular file that only root can write" >&2
			return 1
		fi
	done
	NODE_ID="$(_awgBtPathId "${DIR}/boringtun-cli")" || return 1
	if [[ -n "${INSTALLED}" ]]; then
		if [[ "${DIR}" != "${AWG_BT_STORE_DIR}/${INSTALLED}" ]] || ! _awgBtVerifyRelease "${INSTALLED}"; then
			echo "ERROR: ${DIR} is not a verified release of the BoringTun store" >&2
			return 1
		fi
		EXPECTED_VERSION="${_AWG_BT_VERIFIED_VERSION}"
		REPOSITORY="$(sed -n 's/^source_repository=//p' "${DIR}/MANIFEST")"
		if [[ "${REPOSITORY}" != "${AWG_BT_RELEASE_SOURCE_REPOSITORY}" ]]; then
			echo "ERROR: ${INSTALLED} was not built from ${AWG_BT_RELEASE_SOURCE_REPOSITORY}" >&2
			return 1
		fi
	else
		_awgBtCheckReleaseDir "${DIR}" "${ARCH}" || return 1
	fi
	if [[ "$(_awgBtPathId "${DIR}/boringtun-cli")" != "${NODE_ID}" ]] || ! _awgBtTrustedNode "${DIR}/boringtun-cli" exec ||
		! _awgBtTrustedNode "${DIR}" dir; then
		echo "ERROR: ${DIR}/boringtun-cli changed while it was verified; it is not run" >&2
		return 1
	fi
	VERSION="$("${DIR}/boringtun-cli" --version 2>/dev/null)" || VERSION=""
	if [[ "${VERSION}" != "boringtun ${EXPECTED_VERSION}" ]]; then
		echo "ERROR: boringtun-cli --version printed '${VERSION}', not 'boringtun ${EXPECTED_VERSION}'" >&2
		return 1
	fi
}

# Download the release archive for ARCH into WORK and unpack it there,
# refusing any archive that is not byte for byte the embedded release.
function _awgBtFetchRelease() { # <work dir> <arch>
	local WORK="$1" ARCH="$2" ARCHIVE ACTUAL NAMES TYPES EXPECTED
	ARCHIVE="${WORK}/${_AWG_BT_REL_ASSET}"
	echo "Downloading ${AWG_BT_RELEASE_BASE_URL}/${_AWG_BT_REL_ASSET}"
	if ! curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --retry-delay 3 --connect-timeout 20 --max-time 600 \
		-o "${ARCHIVE}" "${AWG_BT_RELEASE_BASE_URL}/${_AWG_BT_REL_ASSET}"; then
		echo "ERROR: could not download the BoringTun release ${AWG_BT_RELEASE_TAG}" >&2
		return 1
	fi
	ACTUAL="$(sha256sum -- "${ARCHIVE}" 2>/dev/null)" || ACTUAL=""
	if [[ "${ACTUAL%% *}" != "${_AWG_BT_REL_ARCHIVE_SHA256}" ]]; then
		echo "ERROR: the downloaded ${_AWG_BT_REL_ASSET} does not have the SHA-256 embedded in this installer; nothing was installed" >&2
		return 1
	fi
	# Exactly the release layout, in the order it was packaged: one top-level
	# directory and four regular files. An exact name list also rules out
	# absolute paths, "..", other directories, duplicates and extra members.
	EXPECTED="${_AWG_BT_REL_ARCHIVE_ID}/"$'\n'"${_AWG_BT_REL_ARCHIVE_ID}/LICENSE"$'\n'"${_AWG_BT_REL_ARCHIVE_ID}/MANIFEST"$'\n'"${_AWG_BT_REL_ARCHIVE_ID}/THIRD-PARTY-LICENSES"$'\n'"${_AWG_BT_REL_ARCHIVE_ID}/boringtun-cli"
	NAMES="$(tar -tzf "${ARCHIVE}" 2>/dev/null)" || NAMES=""
	TYPES="$(tar --numeric-owner -tvzf "${ARCHIVE}" 2>/dev/null | cut -c1)" || TYPES=""
	if [[ "${NAMES}" != "${EXPECTED}" || "${TYPES}" != $'d\n-\n-\n-\n-' ]]; then
		echo "ERROR: ${_AWG_BT_REL_ASSET} does not have the expected release layout; nothing was extracted" >&2
		return 1
	fi
	mkdir -m 0700 -- "${WORK}/unpacked" || return 1
	if ! tar -xzf "${ARCHIVE}" -C "${WORK}/unpacked" --no-same-owner --no-same-permissions; then
		echo "ERROR: could not unpack ${_AWG_BT_REL_ASSET}" >&2
		return 1
	fi
	# The download directory may be on a noexec /tmp: nothing runs here.
	_awgBtCheckReleaseDir "${WORK}/unpacked/${_AWG_BT_REL_ARCHIVE_ID}" "${ARCH}"
}

# Put a checked release directory into the store as <store>/<release id>: it is
# staged as a root-owned directory next to its final name, verified there as a
# candidate and renamed into place, so a partial copy never has the release's
# name.
function _awgBtStoreRelease() { # <checked release dir> <arch>
	local SOURCE="$1" ARCH="$2" STAGE FILE
	STAGE="$(mktemp -d "${AWG_BT_STORE_DIR}/.${_AWG_BT_REL_ID}.tmp.XXXXXX")" || return 1
	for FILE in LICENSE MANIFEST THIRD-PARTY-LICENSES; do
		cp -- "${SOURCE}/${FILE}" "${STAGE}/${FILE}" && chmod 0644 -- "${STAGE}/${FILE}" || { rm -rf -- "${STAGE}"; return 1; }
	done
	if ! cp -- "${SOURCE}/boringtun-cli" "${STAGE}/boringtun-cli" || ! chmod 0755 -- "${STAGE}/boringtun-cli" "${STAGE}" ||
		{ [[ "${EUID}" -eq 0 ]] && ! chown -R 0:0 -- "${STAGE}"; } ||
		! _awgBtVerifyCandidate "${STAGE}" "${ARCH}" || ! mv -T -- "${STAGE}" "${AWG_BT_STORE_DIR}/${_AWG_BT_REL_ID}"; then
		rm -rf -- "${STAGE}"
		return 1
	fi
}

# Point <store>/current at the pinned release atomically.
function _awgBtSwitchCurrent() {
	_awgBtSetStoreLink current "${_AWG_BT_REL_ID}"
}

# Point a lifecycle link of the store (current or previous) at a release
# directory atomically: a new relative link, renamed over the old one, so the
# link is never absent or partly written.
function _awgBtSetStoreLink() { # <current|previous> <release id>
	local LINK="${AWG_BT_STORE_DIR}/.$1.tmp.$$"
	[[ "$1" == current || "$1" == previous ]] && _awgBtReleaseIdValid "$2" || return 1
	rm -f -- "${LINK}"
	ln -s -- "$2" "${LINK}" && mv -T -f -- "${LINK}" "${AWG_BT_STORE_DIR}/$1" && return 0
	rm -f -- "${LINK}"
	return 1
}

# Read a lifecycle link of the store. Sets _AWG_BT_LINK_TARGET to the release
# it names and returns 0 for a root-owned symlink whose target is a single
# valid release name (no path, no ..); 2 when the link does not exist; 1 for
# anything else, which is reported.
function _awgBtReadStoreLink() { # <current|previous>
	local LINK="${AWG_BT_STORE_DIR}/$1" OWNER="" MODE="" TARGET=""
	_AWG_BT_LINK_TARGET=""
	[[ -e "${LINK}" || -L "${LINK}" ]] || return 2
	read -r OWNER MODE <<<"$(_awgBtStatOwnerMode "${LINK}")"
	TARGET="$(readlink -- "${LINK}" 2>/dev/null)" || TARGET=""
	if [[ ! -L "${LINK}" || "${OWNER}" != "${AWG_BT_TRUSTED_UID}" ]] || ! _awgBtReleaseIdValid "${TARGET}"; then
		echo "ERROR: ${LINK} must be a root-owned link to a release directory in the store." >&2
		return 1
	fi
	_AWG_BT_LINK_TARGET="${TARGET}"
}

# Make the store hold the pinned release, verified, without touching current
# or previous: a directory already there (an earlier install that stopped
# between the rename and the link, or an earlier release now pinned again) is
# verified as a pinned candidate before it runs; otherwise the release is
# downloaded and stored. Sets _AWG_BT_REL_CREATED to 1 when this call stored
# it. The fresh install and --upgrade-boringtun share it; neither ever reads a
# release from anywhere but this installer's embedded contract.
function _awgBtEnsurePinnedRelease() { # <arch>
	local ARCH="$1" WORK RC=0 CANONICAL_STORE
	_AWG_BT_REL_CREATED=0
	CANONICAL_STORE="$(readlink -f -- "${AWG_BT_STORE_DIR}")" || return 1
	if [[ -e "${AWG_BT_STORE_DIR}/${_AWG_BT_REL_ID}" || -L "${AWG_BT_STORE_DIR}/${_AWG_BT_REL_ID}" ]]; then
		# An earlier install stopped between the rename and the link. The
		# directory is verified as a candidate, trust first, before it runs.
		if ! _awgBtVerifyCandidate "${AWG_BT_STORE_DIR}/${_AWG_BT_REL_ID}" "${ARCH}"; then
			echo -e "${RED}ERROR: ${AWG_BT_STORE_DIR}/${_AWG_BT_REL_ID} exists but is not the verified release. Remove it and rerun.${NC}" >&2
			return 1
		fi
	else
		WORK="$(mktemp -d "${TMPDIR:-/tmp}/amneziawg-boringtun.XXXXXX")" || return 1
		chmod 0700 -- "${WORK}"
		if ! _awgBtFetchRelease "${WORK}" "${ARCH}" || ! _awgBtStoreRelease "${WORK}/unpacked/${_AWG_BT_REL_ARCHIVE_ID}" "${ARCH}"; then
			RC=1
		fi
		rm -rf -- "${WORK}"
		if ((RC)); then
			echo -e "${RED}ERROR: the BoringTun release ${AWG_BT_RELEASE_TAG} could not be installed.${NC}" >&2
			return 1
		fi
		_AWG_BT_REL_CREATED=1
	fi
	if ! _awgBtVerifyRelease "${_AWG_BT_REL_ID}" || [[ "${_AWG_BT_VERIFIED_BIN}" != "${CANONICAL_STORE}/${_AWG_BT_REL_ID}/boringtun-cli" ]]; then
		echo -e "${RED}ERROR: the installed BoringTun release does not verify; current was not changed.${NC}" >&2
		return 1
	fi
}

# Install the embedded release into the store, or reuse the one already there.
# Verify, then commit: a release directory is verified as a candidate (trust
# before anything runs, then its version) and by the runtime's own release
# checks before current is pointed at it, so every failure leaves current as
# it was, or absent.
function installBoringtunRelease() {
	local ARCH CANONICAL_STORE
	if ! ARCH="$(_awgBtHostArch)" || ! _awgBtSelectRelease "${ARCH}"; then
		echo -e "${RED}ERROR: BoringTun releases exist only for x86_64 and aarch64 hosts.${NC}" >&2
		return 1
	fi
	if ! _awgBtEnsureDirectory "${AWG_BT_STORE_DIR%/*}" 0755 || ! _awgBtEnsureDirectory "${AWG_BT_STORE_DIR}" 0755; then
		echo -e "${RED}ERROR: cannot prepare the BoringTun store ${AWG_BT_STORE_DIR}.${NC}" >&2
		return 1
	fi
	CANONICAL_STORE="$(readlink -f -- "${AWG_BT_STORE_DIR}")" || return 1
	if [[ -e "${AWG_BT_STORE_DIR}/current" || -L "${AWG_BT_STORE_DIR}/current" ]]; then
		if _awgBtVerifyStore && [[ "${_AWG_BT_VERIFIED_BIN}" == "${CANONICAL_STORE}/${_AWG_BT_REL_ID}/boringtun-cli" ]] &&
			_awgBtVerifyCandidate "${CANONICAL_STORE}/${_AWG_BT_REL_ID}" "${ARCH}"; then
			echo "The BoringTun release ${AWG_BT_RELEASE_TAG} is already installed and verified; it is reused."
			return 0
		fi
		echo -e "${RED}ERROR: ${AWG_BT_STORE_DIR} already selects a BoringTun release that is not the verified ${_AWG_BT_REL_ID}.${NC}" >&2
		echo -e "${ORANGE}A fresh install never replaces an installed BoringTun binary; on an installed host, --upgrade-boringtun moves it to this installer's pin. Remove ${AWG_BT_STORE_DIR} if nothing uses it, then rerun.${NC}" >&2
		return 1
	fi
	_awgBtEnsurePinnedRelease "${ARCH}" || return 1
	if ! _awgBtSwitchCurrent; then
		echo -e "${RED}ERROR: cannot point ${AWG_BT_STORE_DIR}/current at ${_AWG_BT_REL_ID}.${NC}" >&2
		return 1
	fi
	echo -e "${GREEN}Installed the BoringTun release ${AWG_BT_RELEASE_TAG} (${_AWG_BT_REL_ID}).${NC}"
}

# Write the installer's kernel-module load override and require it to be in
# force (_awgBtKernelModuleBlocked).
function installBoringtunModprobeOverride() {
	local CONTENT
	CONTENT="$(_awgBtRenderModprobeOverride)" || return 1
	if ! _awgBtEnsureDirectory "${AWG_BT_MODPROBE_OVERRIDE%/*}" 0755 ||
		! _awgBtWriteManagedFile "${AWG_BT_MODPROBE_OVERRIDE}" 0644 <<<"${CONTENT}"; then
		echo -e "${RED}ERROR: could not write ${AWG_BT_MODPROBE_OVERRIDE}.${NC}" >&2
		return 1
	fi
	if ! _awgBtKernelModuleBlocked; then
		echo -e "${RED}ERROR: ${AWG_BT_MODPROBE_OVERRIDE} is not in force: modprobe -n -v does not show loading amneziawg and rtnl-link-amneziawg ending in 'install /bin/false'. Another modprobe configuration may take precedence.${NC}" >&2
		return 1
	fi
}

# Before any VPN state is written: prove that BoringTun can serve an AWG 2.0
# interface with the server's chosen parameters here, with a scratch instance
# of the verified binary (the runtime layer's own), and that its teardown
# leaves nothing behind.
function boringtunHostPreflight() {
	local IFACE="awgb$((BASHPID % 100000000))" WORK KEY TOKEN RC=1 CREATED=0 DETAIL=""
	echo "Checking that BoringTun can serve AmneziaWG on this host..."
	if ! _awgBtCheckKernelModule || ! _awgBtCheckPlatform || ! _awgBtVerifyStore || ! _awgBtCheckHelpers ||
		! _awgBtCheckBaseUnit "${SERVER_AWG_NIC}"; then
		echo -e "${RED}ERROR: the BoringTun preflight failed; no VPN configuration was written.${NC}" >&2
		return 1
	fi
	if ! _awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "${AWG_BORINGTUN_IMITATE_PROTOCOL:-none}"; then
		echo -e "${RED}ERROR: the installed BoringTun binary does not support protocol imitation ${AWG_BORINGTUN_IMITATE_PROTOCOL}, or did not say that it does. Choose another AWG_BORINGTUN_IMITATE_PROTOCOL. No VPN configuration was written.${NC}" >&2
		return 1
	fi
	KEY="$(awg genkey 2>/dev/null)" || KEY=""
	WORK="$(mktemp -d "${TMPDIR:-/tmp}/amneziawg-preflight.XXXXXX")" || return 1
	chmod 0700 -- "${WORK}"
	(
		umask 077
		cat >"${WORK}/preflight.conf" <<EOF
[Interface]
PrivateKey = ${KEY}
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
EOF
	)
	if [[ -z "${KEY}" ]]; then
		DETAIL="awg genkey failed"
	elif ! awgBackendCreateScratchInterface "${IFACE}" >/dev/null; then
		DETAIL="a scratch BoringTun instance could not be started"
	else
		CREATED=1
		TOKEN="${_AWG_BT_SCRATCH_TOKENS[${IFACE}]:-}"
		if ! _awgBtLinkIsTun "${IFACE}"; then
			DETAIL="the scratch interface is not a TUN device"
		elif ! _awgBtUapiReady "${IFACE}"; then
			DETAIL="the scratch instance's UAPI does not answer"
		elif ! awg setconf "${IFACE}" "${WORK}/preflight.conf" >/dev/null; then
			DETAIL="awg setconf rejected the AWG 2.0 configuration"
		elif ! _awgBtListenPort "${IFACE}" >/dev/null || ! awg show "${IFACE}" dump >/dev/null 2>&1; then
			DETAIL="awg show did not read the applied configuration back"
		else
			RC=0
		fi
	fi
	if ((CREATED)) && ! awgBackendDestroyScratchInterface "${IFACE}" >/dev/null; then
		RC=1
		DETAIL="${DETAIL:+${DETAIL}; }the scratch instance was not torn down cleanly"
	fi
	if ((CREATED)) && { _awgBtLinkExists "${IFACE}" || [[ -e "${AWG_BT_WG_SOCKET_DIR}/${IFACE}.sock" || -L "${AWG_BT_AWG_SOCKET_DIR}/${IFACE}.sock" ]] ||
		compgen -G "$(_awgBtScratchDir)/${TOKEN:-none}.*" >/dev/null; }; then
		RC=1
		DETAIL="${DETAIL:+${DETAIL}; }the scratch instance left its link, sockets or records behind"
	fi
	rm -rf -- "${WORK}"
	if ((RC)); then
		echo -e "${RED}ERROR: the BoringTun preflight failed: ${DETAIL}. No VPN configuration was written.${NC}" >&2
		return 1
	fi
	echo -e "${GREEN}BoringTun preflight passed: TUN, UAPI and an AWG 2.0 configuration work with the verified binary.${NC}"
}

# A fresh BoringTun installation (AWG_BACKEND=boringtun). The order keeps VPN
# state unwritten until the verified binary has run a scratch interface with
# the chosen parameters; see docs/BORINGTUN_BACKEND_DESIGN.md, section 15.2.
function installBoringtunHost() {
	local ACTIVE=0
	if ! checkBoringtunHostSupport; then
		echo -e "${RED}Nothing was installed.${NC}" >&2
		exit 1
	fi
	installQuestions

	enable_apt_ipv4
	installBoringtunHostPackages
	if ! installBoringtunRelease; then
		disable_apt_ipv4
		exit 1
	fi
	disable_apt_ipv4

	if ((_AWG_BT_WRITE_MODPROBE_OVERRIDE)) && ! installBoringtunModprobeOverride; then
		exit 1
	fi
	if ! _awgBtInstallHelpers; then
		echo -e "${RED}ERROR: could not install the BoringTun helpers into ${AWG_BT_LIBEXEC_DIR}.${NC}" >&2
		exit 1
	fi
	if ! boringtunHostPreflight; then
		exit 1
	fi

	writeAwgServerInstallState

	if ! _awgBtInstallServiceFiles "${SERVER_AWG_NIC}"; then
		echo -e "${RED}ERROR: could not write the BoringTun service files for awg-quick@${SERVER_AWG_NIC}.${NC}" >&2
		exit 1
	fi
	systemctl enable "awg-quick@${SERVER_AWG_NIC}"
	if systemctl start "awg-quick@${SERVER_AWG_NIC}"; then
		if _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}"; then
			ACTIVE=1
		else
			echo -e "${RED}ERROR: awg-quick@${SERVER_AWG_NIC} is active but not served by the verified BoringTun daemon; stopping it.${NC}" >&2
			systemctl stop "awg-quick@${SERVER_AWG_NIC}"
		fi
	fi

	if ((ACTIVE)); then
		if shouldCreateInitialClient; then
			newClient
			echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"
		else
			echo -e "${ORANGE}Skipping initial client generation. You can add users later from this script or the web panel.${NC}"
		fi
		echo -e "\n${GREEN}AmneziaWG is running on the BoringTun backend (experimental).${NC}"
		echo -e "${GREEN}You can check the status of AmneziaWG with: systemctl status awg-quick@${SERVER_AWG_NIC}\n\n${NC}"
		echo -e "${ORANGE}Manage the interface with systemctl or this script; a plain 'awg-quick up' does not start BoringTun.${NC}"
	else
		echo -e "\n${RED}WARNING: AmneziaWG with the BoringTun backend did not start. The service is enabled but stopped; it never falls back to the kernel module.${NC}"
		echo -e "${ORANGE}Skipping client generation because the server interface is not active.${NC}"
		echo -e "${ORANGE}Check: systemctl status awg-quick@${SERVER_AWG_NIC} and journalctl -u awg-quick@${SERVER_AWG_NIC}${NC}"
		exit 1
	fi
}

# The BoringTun daemons of INTERFACE that still run: PIDs whose executable is a
# binary in the store and whose last argument is the interface.
function boringtunDaemonsOf() {
	local INTERFACE_NAME="$1" PROC_PID EXE STORE LAST
	local -a ARGS=()
	STORE="$(readlink -f -- "${AWG_BT_STORE_DIR}" 2>/dev/null)" || STORE=""
	[[ -n "${STORE}" ]] || STORE="${AWG_BT_STORE_DIR}"
	for PROC_PID in "${AWG_BT_PROC_DIR}"/[0-9]*; do
		EXE="$(readlink -- "${PROC_PID}/exe" 2>/dev/null)" || continue
		[[ "${EXE}" == "${STORE}/"*"/boringtun-cli"* || "${EXE}" == "${AWG_BT_STORE_DIR}/"*"/boringtun-cli"* ]] || continue
		mapfile -d '' -t ARGS <"${PROC_PID}/cmdline" 2>/dev/null || continue
		((${#ARGS[@]})) || continue
		LAST="${ARGS[${#ARGS[@]} - 1]}"
		[[ "${LAST}" == "${INTERFACE_NAME}" ]] && printf '%s\n' "${PROC_PID##*/}"
	done
	return 0
}

# Remove a generated helper only if it is byte for byte what this installer
# generates. A file that differs (edited by hand, not the installer's, or
# written by another installer version) is not the installer's to delete: it
# is left in place and reported, and that is not a failure. Returns 1 only when
# a generated helper cannot be removed.
function _awgBtRemoveGeneratedHelper() { # <file> <launch|ctl>
	local FILE="$1" CONTENT
	[[ -e "${FILE}" || -L "${FILE}" ]] || return 0
	CONTENT="$(_awgBtRenderHelper "$2")" || return 1
	if [[ -f "${FILE}" && ! -L "${FILE}" ]] && cmp -s -- "${FILE}" <(printf '%s\n' "${CONTENT}"); then
		if ! rm -f -- "${FILE}" || [[ -e "${FILE}" || -L "${FILE}" ]]; then
			echo -e "${RED}ERROR: ${FILE} could not be removed.${NC}" >&2
			return 1
		fi
		return 0
	fi
	echo -e "${ORANGE}NOTE: ${FILE} is not the file this installer generates (it was edited, or written by someone else or another installer version); it is left in place.${NC}"
	return 0
}

# Whether a process listens on the UNIX socket NODE, from ss's socket
# diagnostics (ss -xlHe). Three outcomes, and only ABSENT allows a removal:
#   0 LIVE     a valid listing row names NODE's path, or its inode and device;
#   1 ABSENT   ss succeeded, every row it printed is valid and none names NODE;
#   2 UNKNOWN  anything else: ss missing or failing, NODE not examinable, or
#              any row, related to NODE or not, that is not exactly the shape
#              iproute2 5.9 to 6.19 print for these flags (Debian 11 and 12,
#              Ubuntu 22.04, 24.04 and 26.04):
#   <u_str|u_dgr|u_seq> <LISTEN|UNCONN> <recv-q> <send-q> <local> <inode> * <port> <->[ ino:<n> dev:<major>/<minor>][ peers:[ <inode>]...]
# where <local> is an absolute path, which always comes with ino and dev, or
# an @abstract name or * without them. Rows are matched as data, never
# evaluated; the path may hold spaces, so the row is anchored on its tail.
_AWG_BT_SS_ROW='^(u_str|u_dgr|u_seq)[[:space:]]+(LISTEN|UNCONN)[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+(.+)[[:space:]]+[0-9]+[[:space:]]+\*[[:space:]]+[0-9]+[[:space:]]+<->([[:space:]]+ino:([0-9]+)[[:space:]]+dev:([0-9]+)/([0-9]+))?([[:space:]]+peers:([[:space:]]+[0-9]+)*)?$'
function _awgBtSocketListenedOn() { # <node>
	local NODE="$1" FS_DEV="" FS_INO="" MAJOR MINOR OUTPUT LINE LOCAL VINO VMAJ VMIN FOUND=0
	[[ -S "${NODE}" && ! -L "${NODE}" ]] || return 2
	command -v ss >/dev/null 2>&1 || return 2
	read -r FS_DEV FS_INO <<<"$(stat -c '%d %i' -- "${NODE}" 2>/dev/null)"
	[[ "${FS_DEV}" =~ ^[0-9]+$ && "${FS_INO}" =~ ^[0-9]+$ ]] || return 2
	MAJOR=$(((FS_DEV >> 8) & 0xfff))
	MINOR=$(((FS_DEV & 0xff) | ((FS_DEV >> 12) & 0xfff00)))
	OUTPUT="$(ss -xlHe 2>/dev/null)" || return 2
	while IFS= read -r LINE; do
		LINE="${LINE%"${LINE##*[![:space:]]}"}"
		[[ -n "${LINE}" ]] || continue
		[[ "${LINE}" =~ ${_AWG_BT_SS_ROW} ]] || return 2
		LOCAL="${BASH_REMATCH[3]}"
		LOCAL="${LOCAL#"${LOCAL%%[![:space:]]*}"}"
		LOCAL="${LOCAL%"${LOCAL##*[![:space:]]}"}"
		VINO="${BASH_REMATCH[5]}"
		VMAJ="${BASH_REMATCH[6]}"
		VMIN="${BASH_REMATCH[7]}"
		case "${LOCAL}" in
			/*) [[ -n "${VINO}" ]] || return 2 ;;
			@?* | \*) [[ -z "${VINO}" ]] || return 2 ;;
			*) return 2 ;;
		esac
		if [[ "${LOCAL}" == "${NODE}" ]] || { [[ "${VINO}" == "${FS_INO}" ]] &&
			{ [[ "${VMAJ}" == 0 && "${VMIN}" == "${FS_DEV}" ]] || [[ "${VMAJ}" == "${MAJOR}" && "${VMIN}" == "${MINOR}" ]]; }; }; then
			FOUND=1
		fi
	done <<<"${OUTPUT}"
	((FOUND)) && return 0
	return 1
}

# Remove the UAPI node at PATH only on positive proof that it is this
# installation's and idle: it is still the node that the start attempt
# recorded as ID, the daemon PID/START that created it is gone, and no process
# listens on it (for the AmneziaWG path, a symlink, on the socket it resolves
# to, which must be in one of the UAPI socket directories). Anything else is
# left in place. What is at PATH is one of:
#   ABSENT     proven absent (_awgBtPathAbsent): the obligation is resolved;
#   DIFFERENT  its identity was read and is not ID: a replacement the attempt
#              did not record, left alone; the obligation is resolved;
#   MATCH      its identity was read and is ID: the node goes only on proof
#              that it is idle;
#   UNKNOWN    its identity cannot be read: it stays, and so must the record.
# A failed identity query is never taken for a different node. Returns 0 when
# the recorded node is gone (removed now, absent, or replaced), and 1 while it
# may still be there: the attempt's record is then the proof of ownership a
# later uninstall needs, and must be kept.
function _awgBtRemoveProvenIdleNode() { # <path> <recorded id> <pid> <start time>
	local NODE="$1" SOCKET TARGET_DIR CURRENT
	_awgBtPathAbsent "${NODE}" && return 0
	[[ -n "$2" ]] || return 0
	if ! CURRENT="$(_awgBtPathId "${NODE}")" || [[ ! "${CURRENT}" =~ ^[0-9]+:[0-9]+:[0-9a-f]+:[0-9]+\.[0-9]{9}$ ]]; then
		_awgBtPathAbsent "${NODE}" && return 0
		return 1
	fi
	[[ "${CURRENT}" == "$2" ]] || return 0
	if [[ -n "$3" && -n "$4" ]] && _awgBtProcessIs "$3" "$4"; then
		return 1
	fi
	SOCKET="${NODE}"
	if [[ -L "${NODE}" ]]; then
		SOCKET="$(readlink -f -- "${NODE}" 2>/dev/null)" || return 1
		TARGET_DIR="${SOCKET%/*}"
		if [[ "${TARGET_DIR}" != "$(readlink -f -- "${AWG_BT_WG_SOCKET_DIR}" 2>/dev/null)" &&
			"${TARGET_DIR}" != "$(readlink -f -- "${AWG_BT_AWG_SOCKET_DIR}" 2>/dev/null)" ]]; then
			return 1
		fi
	fi
	if ! _awgBtPathAbsent "${SOCKET}"; then
		_awgBtSocketListenedOn "${SOCKET}"
		[[ $? -eq 1 ]] || return 1
	fi
	[[ "$(_awgBtPathId "${NODE}")" == "$2" ]] || return 1
	rm -f -- "${NODE}" 2>/dev/null
	_awgBtPathAbsent "${NODE}"
}

# PATH is positively absent: its directory was listed and does not hold it, or
# the directory itself is positively absent. A test like [[ -e ]] is false on
# any error, so it proves nothing; a listing that fails proves nothing either.
function _awgBtPathAbsent() { # <path>
	local DIR="${1%/*}" NAME="${1##*/}" LIST
	[[ -n "${DIR}" ]] || DIR=/
	[[ -n "${NAME}" && "${NAME}" != . && "${NAME}" != .. ]] || return 1
	if LIST="$(find -H "${DIR}" -mindepth 1 -maxdepth 1 -name "${NAME}" -print 2>/dev/null)"; then
		[[ -z "${LIST}" ]]
		return
	fi
	[[ "${DIR}" != / ]] && _awgBtPathAbsent "${DIR}"
}

# The start attempts of INTERFACE that the runtime directory still records,
# one per line: the <attempt> of every <if>@<attempt>.* entry.
function _awgBtRecordedAttempts() { # <interface>
	local FILE NAME
	for FILE in "${AWG_BT_RUN_DIR}/$1@"*; do
		[[ -e "${FILE}" || -L "${FILE}" ]] || continue
		NAME="${FILE##*/}"
		NAME="${NAME#"$1@"}"
		printf '%s\n' "${NAME%%.*}"
	done | LC_ALL=C sort -u
}

# The attempt loaded in _AWG_BT_STATE is finished by the runtime's own terminal
# facts, the ones on which awg-backend-ctl poststop removes an attempt: its
# start never got past the precheck or the launcher, or the interface's
# cleanup completed (the done flag).
function _awgBtAttemptTerminal() { # <interface>
	[[ "${_AWG_BT_STATE[PHASE]}" == started || "${_AWG_BT_STATE[PHASE]}" == launch-failed ]] || _awgBtFlagIs "$1" "done"
}

# Uninstall may remove BoringTun state only after the teardown finished: no
# daemon of INTERFACE runs, and every start attempt the runtime directory still
# records is terminal. poststop keeps an attempt precisely when its cleanup is
# unfinished, for example a PostDown replay that may have run in part; such an
# attempt, or one whose state cannot be read, stops the uninstall before
# anything is removed, with the hooks to check named. Nothing is changed here.
function boringtunTeardownFinished() { # <interface>
	local INTERFACE_NAME="$1" DAEMONS ATTEMPT RC=0
	DAEMONS="$(boringtunDaemonsOf "${INTERFACE_NAME}")"
	if [[ -n "${DAEMONS}" ]]; then
		echo -e "${RED}ERROR: a BoringTun daemon of ${INTERFACE_NAME} is still running (PID ${DAEMONS//$'\n'/, }).${NC}" >&2
		return 1
	fi
	while IFS= read -r ATTEMPT; do
		[[ -n "${ATTEMPT}" ]] || continue
		_AWG_BT_ATTEMPT=""
		if [[ ! "${ATTEMPT}" =~ ^[0-9a-f]{32}$ ]]; then
			echo -e "${RED}ERROR: ${AWG_BT_RUN_DIR} holds ${INTERFACE_NAME}@${ATTEMPT}.*, which is not a start attempt's record.${NC}" >&2
			RC=1
			continue
		fi
		_AWG_BT_ATTEMPT="${ATTEMPT}"
		if ! _awgBtStateLoad "${INTERFACE_NAME}" 2>/dev/null; then
			echo -e "${RED}ERROR: the state of start attempt ${ATTEMPT} of ${INTERFACE_NAME} cannot be read, so its teardown cannot be proven finished.${NC}" >&2
			RC=1
		elif ! _awgBtAttemptTerminal "${INTERFACE_NAME}"; then
			echo -e "${RED}ERROR: the teardown of start attempt ${ATTEMPT} of ${INTERFACE_NAME} did not finish.${NC}" >&2
			_awgBtReportUnfinishedDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"
			RC=1
		fi
	done < <(_awgBtRecordedAttempts "${INTERFACE_NAME}")
	_AWG_BT_ATTEMPT=""
	if ((RC)); then
		echo -e "${ORANGE}The records in ${AWG_BT_RUN_DIR} and the configuration are kept. Check what the named PostDown hooks undo, finish it by hand, then remove ${AWG_BT_RUN_DIR}/${INTERFACE_NAME}@<attempt>.* and rerun the uninstall.${NC}" >&2
	fi
	return "${RC}"
}

# The BoringTun part of an uninstall, after the unit is stopped and
# boringtunTeardownFinished: this interface's finished start attempts, with the
# UAPI nodes they prove to be theirs and idle; the scratch records; the
# generated helpers; the store; the load override. It removes only what is
# provably this installation's, reports everything else, and returns 1 when
# anything it owns, or anything at the interface's UAPI paths, remains, so the
# configuration stays and the uninstall can be rerun.
function uninstallBoringtunRuntime() { # <interface>
	local INTERFACE_NAME="$1" RC=0 ATTEMPT FILE NODE KEEP
	boringtunTeardownFinished "${INTERFACE_NAME}" || return 1
	while IFS= read -r ATTEMPT; do
		[[ -n "${ATTEMPT}" ]] || continue
		_AWG_BT_ATTEMPT="${ATTEMPT}"
		if ! _awgBtStateLoad "${INTERFACE_NAME}" 2>/dev/null || ! _awgBtAttemptTerminal "${INTERFACE_NAME}"; then
			RC=1
			continue
		fi
		# The record goes only after every node it proves to be BoringTun's is
		# gone; while one is kept, the record stays for the next uninstall.
		KEEP=0
		_awgBtRemoveProvenIdleNode "${AWG_BT_AWG_SOCKET_DIR}/${INTERFACE_NAME}.sock" "${_AWG_BT_STATE[AWG_SOCK]}" \
			"${_AWG_BT_STATE[PID]}" "${_AWG_BT_STATE[PID_START]}" || KEEP=1
		_awgBtRemoveProvenIdleNode "${AWG_BT_WG_SOCKET_DIR}/${INTERFACE_NAME}.sock" "${_AWG_BT_STATE[WG_SOCK]}" \
			"${_AWG_BT_STATE[PID]}" "${_AWG_BT_STATE[PID_START]}" || KEEP=1
		if ((KEEP)); then
			echo -e "${RED}ERROR: a UAPI node that start attempt ${ATTEMPT} of ${INTERFACE_NAME} recorded could not be proven idle or removed; the attempt's record is kept as the proof of ownership for the next uninstall.${NC}" >&2
			RC=1
			continue
		fi
		_awgBtAttemptRemove "${INTERFACE_NAME}" 2>/dev/null
		if [[ -n "$(_awgBtRecordedAttempts "${INTERFACE_NAME}" | grep -x "${ATTEMPT}")" ]]; then
			echo -e "${RED}ERROR: the finished start attempt ${ATTEMPT} of ${INTERFACE_NAME} could not be removed from ${AWG_BT_RUN_DIR}.${NC}" >&2
			RC=1
		fi
	done < <(_awgBtRecordedAttempts "${INTERFACE_NAME}")
	_AWG_BT_ATTEMPT=""
	for NODE in "${AWG_BT_AWG_SOCKET_DIR}/${INTERFACE_NAME}.sock" "${AWG_BT_WG_SOCKET_DIR}/${INTERFACE_NAME}.sock"; do
		if ! _awgBtPathAbsent "${NODE}"; then
			echo -e "${RED}ERROR: ${NODE} is not provably an idle UAPI node of this installation (a process may serve it, or nothing records it as BoringTun's); it is left in place. If nothing uses it, remove it and rerun the uninstall.${NC}" >&2
			RC=1
		fi
	done
	FILE="$(_awgBtPidFile "${INTERFACE_NAME}")"
	[[ ! -e "${FILE}" && ! -L "${FILE}" ]] || rm -f -- "${FILE}" || RC=1
	_awgBtScratchSweep 2>/dev/null || true
	rmdir -- "$(_awgBtScratchDir)" 2>/dev/null
	rmdir -- "${AWG_BT_RUN_DIR}" 2>/dev/null
	if [[ -d "${AWG_BT_RUN_DIR}" ]]; then
		echo -e "${ORANGE}NOTE: ${AWG_BT_RUN_DIR} still holds state of other instances; it is left in place.${NC}"
	fi
	_awgBtRemoveGeneratedHelper "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" launch || RC=1
	_awgBtRemoveGeneratedHelper "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl" ctl || RC=1
	rmdir -- "${AWG_BT_LIBEXEC_DIR}" 2>/dev/null
	if [[ -e "${AWG_BT_STORE_DIR}" || -L "${AWG_BT_STORE_DIR}" ]]; then
		rm -rf -- "${AWG_BT_STORE_DIR}" || RC=1
	fi
	rmdir -- "${AWG_BT_STORE_DIR%/*}" 2>/dev/null
	FILE=""
	if [[ -f "${AWG_BT_MODPROBE_OVERRIDE}" && ! -L "${AWG_BT_MODPROBE_OVERRIDE}" &&
		"$(cat -- "${AWG_BT_MODPROBE_OVERRIDE}" 2>/dev/null)" == "$(_awgBtRenderModprobeOverride)" ]]; then
		rm -f -- "${AWG_BT_MODPROBE_OVERRIDE}"
		FILE="${AWG_BT_MODPROBE_OVERRIDE}"
	elif [[ -e "${AWG_BT_MODPROBE_OVERRIDE}" || -L "${AWG_BT_MODPROBE_OVERRIDE}" ]]; then
		echo -e "${ORANGE}NOTE: ${AWG_BT_MODPROBE_OVERRIDE} was changed after it was installed; it is left in place.${NC}"
	fi
	for FILE in "${AWG_BT_STORE_DIR}" "$(_awgBtPidFile "${INTERFACE_NAME}")" ${FILE:+"${FILE}"}; do
		if [[ -e "${FILE}" || -L "${FILE}" ]]; then
			echo -e "${RED}ERROR: ${FILE} could not be removed.${NC}" >&2
			RC=1
		fi
	done
	return "${RC}"
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

# Returns 0 (true) when the host has a usable IPv6 stack, 1 otherwise. Used to
# choose a sensible default for IPv6 support so IPv6-disabled hosts don't produce
# client configs with IPv6 addresses/routes that fail to apply (issue #51).
function ipv6Available() {
	[[ -e /proc/net/if_inet6 ]] || return 1
	local disabled
	disabled="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)"
	[[ "${disabled}" == "1" ]] && return 1
	disabled="$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null)"
	[[ "${disabled}" == "1" ]] && return 1
	return 0
}

function trimWhitespace() {
	local VALUE="$1"
	VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
	VALUE="${VALUE%"${VALUE##*[![:space:]]}"}"
	printf '%s\n' "${VALUE}"
}

# Echo a comma-separated CIDR list with IPv6 entries removed (IPv4 kept). Keeps
# ::/0 and other IPv6 routes out of client AllowedIPs when IPv6 is disabled, so
# clients without an IPv6 address don't fail adding an IPv6 route (issue #51).
function stripIPv6FromList() {
	local OUT="" ENTRY
	local -a PARTS
	IFS=',' read -ra PARTS <<< "$1"
	for ENTRY in "${PARTS[@]}"; do
		ENTRY="${ENTRY//[[:space:]]/}"
		[[ -z "${ENTRY}" ]] && continue
		[[ "${ENTRY}" == *:* ]] && continue
		if [[ -z "${OUT}" ]]; then OUT="${ENTRY}"; else OUT="${OUT},${ENTRY}"; fi
	done
	echo "${OUT}"
}

function prepareClientAllowedIPs() {
	local RAW_ALLOWED_IPS="$1"
	local IPV6_ENABLED="${2:-${ENABLE_IPV6:-y}}"
	local CLIENT_ALLOWED_IPS="${RAW_ALLOWED_IPS}"

	if [[ "${IPV6_ENABLED}" == "n" ]]; then
		CLIENT_ALLOWED_IPS=$(stripIPv6FromList "${RAW_ALLOWED_IPS}")
	fi
	CLIENT_ALLOWED_IPS=$(formatClientAllowedIPs "${CLIENT_ALLOWED_IPS}")
	[[ -n "${CLIENT_ALLOWED_IPS}" ]] || return 1
	printf '%s\n' "${CLIENT_ALLOWED_IPS}"
}

function serverConfigHasIPv6Address() {
	local CONFIG_PATH="$1"
	local IN_INTERFACE=0 LINE TRIMMED KEY VALUE SECTION

	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		TRIMMED=$(trimWhitespace "${LINE}")
		[[ -z "${TRIMMED}" || "${TRIMMED}" == \#* || "${TRIMMED}" == \;* ]] && continue
		if [[ "${TRIMMED}" =~ ^\[(.*)\]$ ]]; then
			SECTION="${BASH_REMATCH[1],,}"
			IN_INTERFACE=0
			[[ "${SECTION}" == "interface" ]] && IN_INTERFACE=1
			continue
		fi
		(( IN_INTERFACE )) || continue
		[[ "${TRIMMED}" == *=* ]] || continue
		KEY=$(trimWhitespace "${TRIMMED%%=*}")
		[[ "${KEY,,}" == "address" ]] || continue
		VALUE=$(trimWhitespace "${TRIMMED#*=}")
		VALUE="${VALUE%%#*}"
		VALUE="${VALUE%%;*}"
		VALUE=$(trimWhitespace "${VALUE}")
		[[ "${VALUE}" == *:* ]] && return 0
	done < "${CONFIG_PATH}"

	return 1
}

# Ask for the protocol imitation of a fresh interactive BoringTun install. The
# caller's AWG_BORINGTUN_IMITATE_* request, already validated, is the default.
function askBoringtunImitation() {
	local -a PROTOCOLS=(none dns quic sip stun auto)
	local CHOICE="" DEFAULT=1 I DOMAIN
	for I in "${!PROTOCOLS[@]}"; do
		[[ "${PROTOCOLS[I]}" == "${AWG_BORINGTUN_IMITATE_PROTOCOL}" ]] && DEFAULT=$((I + 1))
	done
	echo ""
	echo -e "${GREEN}BoringTun protocol imitation (shapes the S1-S4 prefixes this server sends):${NC}"
	echo "Protocol imitation:"
	echo "   1) none (default)"
	echo "   2) dns"
	echo "   3) quic"
	echo "   4) sip"
	echo "   5) stun"
	echo "   6) auto (dns, quic, sip or stun chosen per authenticated peer from its client's traffic)"
	until [[ "${CHOICE}" =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " -e -i "${DEFAULT}" CHOICE
	done
	AWG_BORINGTUN_IMITATE_PROTOCOL="${PROTOCOLS[CHOICE - 1]}"
	DOMAIN=""
	if _awgBtImitationUsesDomain "${AWG_BORINGTUN_IMITATE_PROTOCOL}"; then
		DOMAIN="${AWG_BORINGTUN_IMITATE_DOMAIN}"
		while true; do
			read -rp "Imitation hostname (optional; empty lets BoringTun choose): " -e -i "${DOMAIN}" DOMAIN
			if [[ -z "${DOMAIN}" ]] || _awgBtImitationDomainValid "${DOMAIN}"; then
				break
			fi
			echo "Use at most 253 characters of dot-separated labels of 1-63 ASCII letters, digits and hyphens, none starting or ending with a hyphen."
		done
	fi
	AWG_BORINGTUN_IMITATE_DOMAIN="${DOMAIN}"
}

function installQuestions() {
	# Fresh installs remain on AWG 2.0 regardless of caller environment. AWG 3.0
	# and AWG 3.1 can be enabled only after installation through the explicit
	# capability-gated migration.
	AWG_PROTOCOL_VERSION="${AWG_PROTOCOL_VERSION_2}"
	clearAwg3Params
	# The backend comes from the caller's request as it was when the installer
	# was loaded (kernel unless AWG_BACKEND=boringtun was exported), never from
	# a later assignment.
	selectFreshInstallBackend || exit 1
	# The protocol imitation likewise, and a kernel install refuses one here,
	# before anything is changed.
	selectFreshInstallImitation || exit 1

	# Non-interactive mode: use environment variable overrides or sensible defaults
	# Set AUTO_INSTALL=y to skip all prompts
	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		# Only auto-detect if the operator did not provide an explicit override.
		# An explicit SERVER_PUB_IP (even if private, e.g. for an internal-only
		# deployment) is honoured as-is.
		if [[ -z "${SERVER_PUB_IP:-}" ]]; then
			SERVER_PUB_IP=$(detectPublicIPv4)
			# If auto-detection only yielded a non-routable IPv4 (external
			# lookup disabled or blocked), prefer a global IPv6 over baking
			# a private address into client configs. Keep the private value
			# as a last-resort fallback so the install does not hard-fail
			# on hosts with neither egress to IP-echo services nor a global
			# IPv6 (e.g. AWG_SKIP_PUBLIC_IP_LOOKUP set on an IPv4-only LAN).
			local AUTO_PRIVATE_IPV4=""
			if [[ -n "${SERVER_PUB_IP}" ]] && isPrivateIPv4 "${SERVER_PUB_IP}"; then
				AUTO_PRIVATE_IPV4="${SERVER_PUB_IP}"
				SERVER_PUB_IP=""
			fi
			if [[ -z "${SERVER_PUB_IP}" ]]; then
				SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
			fi
			if [[ -z "${SERVER_PUB_IP}" && -n "${AUTO_PRIVATE_IPV4}" ]]; then
				echo -e "${ORANGE}WARNING: No public IPv4 or global IPv6 detected; falling back to private IPv4 ${AUTO_PRIVATE_IPV4}. Generated client configs will only work from networks that can reach this address. Set SERVER_PUB_IP to override.${NC}"
				SERVER_PUB_IP="${AUTO_PRIVATE_IPV4}"
			fi
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
		# Default IPv6 support from the host's capability unless explicitly set via
		# the ENABLE_IPV6 env var. IPv4-only deployments avoid emitting IPv6
		# addresses/routes that fail to apply on IPv6-disabled systems (issue #51).
		if [[ -z "${ENABLE_IPV6:-}" ]]; then
			if ipv6Available; then ENABLE_IPV6=y; else ENABLE_IPV6=n; fi
		fi
		ENABLE_IPV6="${ENABLE_IPV6,,}"
		if [[ "${ENABLE_IPV6}" != "y" && "${ENABLE_IPV6}" != "n" ]]; then
			echo -e "${RED}ERROR: ENABLE_IPV6 must be 'y' or 'n': ${ENABLE_IPV6}${NC}"
			exit 1
		fi
		if [[ "${ENABLE_IPV6}" == "y" ]]; then
			ALLOWED_IPS=${ALLOWED_IPS:-0.0.0.0/0, ::/0}
		else
			ALLOWED_IPS=${ALLOWED_IPS:-0.0.0.0/0}
		fi
		local RAW_ALLOWED_IPS="${ALLOWED_IPS}"
		if ! ALLOWED_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${ENABLE_IPV6}"); then
			echo -e "${RED}ERROR: ALLOWED_IPS has no usable routes after applying ENABLE_IPV6=${ENABLE_IPV6}: ${RAW_ALLOWED_IPS}${NC}"
			exit 1
		fi

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

		printBoringtunImitationWarnings "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}" "${AWG_PROTOCOL_VERSION}"
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
	SERVER_PUB_IP=$(detectPublicIPv4)
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

	# Ask whether to enable IPv6. The default reflects the host's IPv6 capability
	# so IPv6-disabled systems don't generate broken client configs (issue #51).
	if ipv6Available; then ENABLE_IPV6_DEFAULT="y"; else ENABLE_IPV6_DEFAULT="n"; fi
	ENABLE_IPV6=""
	until [[ "${ENABLE_IPV6,,}" =~ ^(y|n)$ ]]; do
		read -rp "Enable IPv6 support (tunnel + NAT)? [y/n]: " -e -i "${ENABLE_IPV6_DEFAULT}" ENABLE_IPV6
	done
	ENABLE_IPV6="${ENABLE_IPV6,,}"

	if [[ "${ENABLE_IPV6}" == "y" ]]; then
		until isValidIPv6 "${SERVER_AWG_IPV6}"; do
			read -rp "Server AmneziaWG IPv6: " -e -i fd42:42:42::1 SERVER_AWG_IPV6
		done
		# Normalize to expanded form for consistent storage and comparison
		SERVER_AWG_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
	else
		# Keep a valid placeholder for params storage and client IP derivation;
		# it is never written to the server or client configs when IPv6 is off.
		SERVER_AWG_IPV6=$(normalizeIPv6 "fd42:42:42::1")
	fi

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

	if [[ "${ENABLE_IPV6}" == "y" ]]; then ALLOWED_IPS_DEFAULT='0.0.0.0/0, ::/0'; else ALLOWED_IPS_DEFAULT='0.0.0.0/0'; fi
	while true; do
		echo -e "\nAmneziaWG uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i "${ALLOWED_IPS_DEFAULT}" ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="${ALLOWED_IPS_DEFAULT}"
		fi
		if ALLOWED_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${ENABLE_IPV6}"); then
			break
		fi
		echo -e "${ORANGE}AllowedIPs must contain at least one route usable with ENABLE_IPV6=${ENABLE_IPV6}.${NC}"
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

	if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
		askBoringtunImitation
		printBoringtunImitationWarnings "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}" "${AWG_PROTOCOL_VERSION}"
	fi

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your AmneziaWG server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

# Emit the server's PostUp/PostDown firewall rules on stdout.
#
# The backend is chosen in priority order:
#   1. firewalld - when the firewalld service is active.
#   2. nftables  - when the nft binary is available and iptables is either absent
#                  or backed by nf_tables (the default on modern Debian/Ubuntu/
#                  Fedora). Emitting native nft rules avoids the iptables-nft
#                  compatibility layer, which on these systems either inserts the
#                  rules into a backend the kernel does not enforce (so NAT/forward
#                  silently breaks) or aborts awg-quick when the legacy ip6_tables
#                  module is unavailable. See issue #79.
#   3. iptables  - legacy fallback for systems without nft.
#
# Reads the SERVER_* globals populated by installQuestions(). The brace blocks in
# the nft chain definitions are single-quoted so awg-quick's `eval` of each hook
# passes them to nft intact instead of treating { ; } as shell syntax.
function ufwIsActive() {
	local UFW_CONF="${UFW_CONF_PATH:-/etc/ufw/ufw.conf}"
	local UFW_STATUS=""

	if command -v ufw >/dev/null 2>&1; then
		UFW_STATUS="$(ufw status 2>/dev/null || true)"
		if printf '%s\n' "${UFW_STATUS}" | grep -qiE '^Status:[[:space:]]+active'; then
			return 0
		fi
		if printf '%s\n' "${UFW_STATUS}" | grep -qiE '^Status:[[:space:]]+inactive'; then
			return 1
		fi
	fi
	grep -qiE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' "${UFW_CONF}" 2>/dev/null
}

function writeFirewallRules() {
	if systemctl is-active --quiet firewalld 2>/dev/null; then
		local FIREWALLD_IPV4_ADDRESS FIREWALLD_IPV6_ADDRESS FW_PU_V6="" FW_PD_V6=""
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_AWG_IPV4}" | cut -d"." -f1-3)".0"
		if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
			# Derive /64 network address from the normalized IPv6 (first 4 groups + :0:0:0:0)
			FIREWALLD_IPV6_ADDRESS="$(echo "${SERVER_AWG_IPV6}" | cut -d':' -f1-4):0:0:0:0"
			FW_PU_V6=" && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'"
			FW_PD_V6=" && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'"
		fi
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'${FW_PU_V6}
PostUp = firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv4 filter FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = firewall-cmd --direct --add-rule ipv4 mangle FORWARD 0 -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'${FW_PD_V6}
PostDown = firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv4 filter FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = firewall-cmd --direct --remove-rule ipv4 mangle FORWARD 0 -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
			echo "PostUp = firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv6 filter FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = firewall-cmd --direct --add-rule ipv6 mangle FORWARD 0 -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv6 filter FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = firewall-cmd --direct --remove-rule ipv6 mangle FORWARD 0 -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		fi
	elif ufwIsActive && command -v iptables >/dev/null 2>&1; then
		# UFW installs default-drop rules in its own filtering path. Native nft
		# accept rules in a separate base chain cannot reliably override those
		# drops, so use iptables-compatible insertion when UFW is active. This
		# inserts before UFW's final drop while keeping NAT scoped to VPN clients.
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -I FORWARD 2 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = iptables -t mangle -A FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -t mangle -D FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		if [[ "${ENABLE_IPV6:-y}" == "y" ]] && command -v ip6tables >/dev/null 2>&1; then
			echo "PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = ip6tables -I FORWARD 2 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -t mangle -A FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -t mangle -D FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		elif [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
			echo -e "${ORANGE}WARNING: ENABLE_IPV6=y but ip6tables is unavailable; UFW IPv6 firewall rules will not be generated.${NC}" >&2
		fi
	elif command -v nft >/dev/null 2>&1 && { ! command -v iptables >/dev/null 2>&1 || iptables --version 2>/dev/null | grep -qi 'nf_tables'; }; then
		# In dual-stack mode a single inet table covers both IPv4 and IPv6; in
		# IPv4-only mode an ip table avoids opening/forwarding IPv6 at all.
		# PostDown drops the whole table atomically, so no per-rule deletion (and
		# no ordering fragility) is required.
		# The MSS-clamp rule is scoped to 'oifname <awg>' so it only touches traffic
		# entering the tunnel (notably the return-path SYN-ACK) and leaves any other
		# forwarding the host does alone. It must precede the accept rules: it carries
		# no verdict so the packet falls through to them, but an accept would otherwise
		# terminate the chain before the clamp runs. 'tcp flags & (syn|rst) == syn'
		# matches SYN and SYN-ACK (the segments carrying the MSS option); the &/(|)
		# tokens are single-quoted so awg-quick's eval passes them to nft intact.
		local NFT_TABLE="awg-${SERVER_AWG_NIC}" NFT_FAMILY="inet"
		[[ "${ENABLE_IPV6:-y}" == "n" ]] && NFT_FAMILY="ip"
		echo "PostUp = nft add table ${NFT_FAMILY} ${NFT_TABLE}
PostUp = nft add chain ${NFT_FAMILY} ${NFT_TABLE} input '{ type filter hook input priority 0 ; policy accept ; }'
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} input udp dport ${SERVER_PORT} accept
PostUp = nft add chain ${NFT_FAMILY} ${NFT_TABLE} forward '{ type filter hook forward priority 0 ; policy accept ; }'
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} forward oifname ${SERVER_AWG_NIC} tcp flags '&' '(syn|rst)' == syn tcp option maxseg size set rt mtu
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} forward iifname ${SERVER_AWG_NIC} accept
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} forward iifname ${SERVER_PUB_NIC} oifname ${SERVER_AWG_NIC} ct state related,established accept
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} forward iifname ${SERVER_PUB_NIC} oifname ${SERVER_AWG_NIC} drop
PostUp = nft add chain ${NFT_FAMILY} ${NFT_TABLE} postrouting '{ type nat hook postrouting priority 100 ; policy accept ; }'
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} postrouting oifname ${SERVER_PUB_NIC} masquerade
PostDown = nft delete table ${NFT_FAMILY} ${NFT_TABLE}"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -I FORWARD 2 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = iptables -t mangle -A FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -t mangle -D FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		# Emit the ip6tables rules only when IPv6 is enabled and ip6tables is
		# available; otherwise these commands would abort awg-quick.
		if [[ "${ENABLE_IPV6:-y}" == "y" ]] && command -v ip6tables >/dev/null 2>&1; then
			echo "PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = ip6tables -I FORWARD 2 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -t mangle -A FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -t mangle -D FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		elif [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
			echo -e "${ORANGE}WARNING: ENABLE_IPV6=y but ip6tables is unavailable; legacy IPv6 firewall rules will not be generated.${NC}" >&2
		fi
	fi
}

function shouldCreateInitialClient() {
	local CREATE_CLIENT="${CREATE_INITIAL_CLIENT:-}"
	CREATE_CLIENT=$(trimWhitespace "${CREATE_CLIENT}")

	case "${CREATE_CLIENT,,}" in
	y|yes|true|1)
		return 0
		;;
	n|no|false|0)
		return 1
		;;
	esac

	if [[ -n "${CREATE_CLIENT}" ]]; then
		echo -e "${RED}ERROR: CREATE_INITIAL_CLIENT must be y/n, yes/no, true/false, or 1/0: ${CREATE_CLIENT}${NC}"
		if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
			exit 1
		fi
	fi

	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		return 0
	fi

	while true; do
		read -rp "Create an initial client configuration now? [Y/n]: " CREATE_CLIENT
		CREATE_CLIENT=${CREATE_CLIENT:-y}
		case "${CREATE_CLIENT,,}" in
		y|yes)
			return 0
			;;
		n|no)
			return 1
			;;
		*)
			echo -e "${ORANGE}Please answer yes or no.${NC}"
			;;
		esac
	done
}

function formatClientAllowedIPs() {
	local OUT="" ENTRY
	local -a PARTS
	IFS=',' read -ra PARTS <<< "$1"
	for ENTRY in "${PARTS[@]}"; do
		ENTRY="${ENTRY#"${ENTRY%%[![:space:]]*}"}"
		ENTRY="${ENTRY%"${ENTRY##*[![:space:]]}"}"
		[[ -z "${ENTRY}" ]] && continue
		if [[ -z "${OUT}" ]]; then OUT="${ENTRY}"; else OUT="${OUT}, ${ENTRY}"; fi
	done
	printf '%s\n' "${OUT}"
}

# Configure the Amnezia PPA for a fresh Ubuntu install and refresh the package
# indexes: shared by both backends, before their own package installs.
function prepareUbuntuAmneziaPpaForInstall() {
	# Repair a PPA entry left by an older interrupted install before the
	# initial update; otherwise a stale unsupported suite breaks the rerun.
	local EXISTING_PPA_RC
	if amneziaPpaSourceEntriesExist "${AMNEZIA_PPA_SOURCES_DIR}"; then
		EXISTING_PPA_RC=0
	else
		EXISTING_PPA_RC=$?
	fi
	if [[ "${EXISTING_PPA_RC}" -eq 0 ]]; then
		configureUbuntuAmneziaPpa "" "${AMNEZIA_PPA_SOURCES_DIR}" || exit 1
	elif [[ "${EXISTING_PPA_RC}" -ne 1 ]]; then
		exit 1
	fi

	apt-get update || { echo -e "${RED}ERROR: Failed to refresh APT package index.${NC}"; exit 1; }
	apt install -y software-properties-common curl || { echo -e "${RED}ERROR: Failed to install software-properties-common and curl.${NC}"; exit 1; }
	configureUbuntuAmneziaPpa "" "${AMNEZIA_PPA_SOURCES_DIR}" || exit 1
	if ! apt-get -o APT::Update::Error-Mode=any update; then
		local PPA_CLEANUP_RC
		if cleanupNewlyCreatedUbuntuAmneziaPpa "${AMNEZIA_PPA_SOURCES_DIR}"; then
			PPA_CLEANUP_RC=0
		else
			PPA_CLEANUP_RC=$?
		fi
		case "${PPA_CLEANUP_RC}" in
			0)
				echo -e "${RED}ERROR: Failed to update APT package indexes after configuring the Amnezia PPA. The newly created PPA source was removed so future APT operations remain usable.${NC}"
				;;
			1)
				echo -e "${RED}ERROR: Failed to update APT package indexes after configuring the Amnezia PPA, and the newly created source could not be removed safely. Review ${AMNEZIA_PPA_SOURCES_DIR}.${NC}"
				;;
			2)
				echo -e "${RED}ERROR: Failed to update APT package indexes after reconciling the pre-existing Amnezia PPA source. The administrator-owned source was left in place.${NC}"
				;;
		esac
		exit 1
	fi
	checkAmneziaPpaToolsCandidate "${AMNEZIA_PPA_SELECTED_SUITE}" "${AMNEZIA_PPA_ARCHITECTURE}" || exit 1
}

# Add the Amnezia PPA source with its verified signing key for a fresh Debian
# install. INCLUDE_DEB_SRC is 1 for the kernel backend, whose DKMS build needs
# the source entry, and 0 for BoringTun.
function configureDebianAmneziaAptSource() {
	local INCLUDE_DEB_SRC="$1"
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
	# Use -4 to avoid IPv6 timeouts on VPS providers where AAAA records
	# resolve but outbound IPv6 connectivity to keyservers is broken.
	if command -v curl &>/dev/null; then
		curl -4 -fsSL "${KEY_URL}" -o "${TMP_KEY_ASC}" && KEY_FETCH_OK=1
	elif command -v wget &>/dev/null; then
		wget -4 -qO "${TMP_KEY_ASC}" "${KEY_URL}" && KEY_FETCH_OK=1
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
		if [[ "${INCLUDE_DEB_SRC}" == 1 ]]; then
			echo "deb-src [signed-by=/etc/apt/keyrings/amneziawg.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		fi
	fi
}

# Write the state of a fresh installation, which both backends share: server
# keys, params, the server configuration with its firewall hooks, and the
# forwarding sysctls.
function writeAwgServerInstallState() {
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

	# Add server interface. Include the IPv6 address only when IPv6 is enabled.
	local SERVER_ADDRESS="${SERVER_AWG_IPV4}/24"
	if [[ "${ENABLE_IPV6}" == "y" ]]; then
		SERVER_ADDRESS="${SERVER_ADDRESS},${SERVER_AWG_IPV6}/64"
	fi
	local AWG_PROTOCOL_FIELDS=""
	AWG_PROTOCOL_FIELDS="$(renderAwgProtocolFields)" || {
		echo -e "${RED}ERROR: Failed to render protocol-specific server configuration.${NC}"
		exit 1
	}
	echo "[Interface]
Address = ${SERVER_ADDRESS}
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
H4 = ${SERVER_AWG_H4}
${AWG_PROTOCOL_FIELDS}" >"${SERVER_AWG_CONF}"
	chmod 600 "${SERVER_AWG_CONF}"

	# Restore default umask before creating system files and running services
	umask "${OLD_UMASK}"

	writeFirewallRules >>"${SERVER_AWG_CONF}"

	# Enable routing on the server
	mkdir -p /etc/sysctl.d
	chmod 755 /etc/sysctl.d
	echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/awg.conf
	if [[ "${ENABLE_IPV6}" == "y" ]]; then
		echo "net.ipv6.conf.all.forwarding = 1" >>/etc/sysctl.d/awg.conf
	fi
	chmod 644 /etc/sysctl.d/awg.conf

	sysctl -p /etc/sysctl.d/awg.conf
}

function installAmneziaWG() {
	ensureSupportedInstallDistro
	selectFreshInstallBackend || exit 1
	selectFreshInstallImitation || exit 1
	if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
		installBoringtunHost
		return
	fi

	# Run setup questions first
	installQuestions

	# Install AmneziaWG tools and module
	# Force IPv4 preference for all package-manager operations — IPv6 may be
	# resolvable but unreachable on some VPS providers, causing apt, dnf,
	# add-apt-repository, and COPR API calls to hang.
	enable_apt_ipv4
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
		prepareUbuntuAmneziaPpaForInstall
		# Install kernel headers for the running kernel so DKMS can compile the module.
		installKernelHeaders "$(uname -r)"
		apt install -y dkms iptables nftables amneziawg amneziawg-tools qrencode || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -q "^deb-src" /etc/apt/sources.list; then
			# Tag managed file with sentinel so uninstall can verify ownership
			echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources.list
			cat /etc/apt/sources.list >> /etc/apt/sources.list.d/amneziawg.sources.list
			# Convert deb lines to deb-src, tolerating any whitespace while skipping existing deb-src lines
			sed -i -E '/^[[:space:]]*deb-src[[:space:]]/!s/^[[:space:]]*deb[[:space:]]+/deb-src /' /etc/apt/sources.list.d/amneziawg.sources.list
			chmod 644 /etc/apt/sources.list.d/amneziawg.sources.list
		fi
		configureDebianAmneziaAptSource 1
		apt-get update || { echo -e "${RED}ERROR: Failed to update package index.${NC}"; exit 1; }
		# Install kernel headers for the running kernel so DKMS can compile the module.
		installKernelHeaders "$(uname -r)"
		apt-get install -y dkms amneziawg amneziawg-tools qrencode iptables nftables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'fedora' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		# Install kernel headers for the running kernel so DKMS can compile the module.
		installKernelHeaders "$(uname -r)"
		dnf install -y dkms amneziawg-dkms amneziawg-tools qrencode iptables nftables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'centos' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		# Install kernel headers for the running kernel so DKMS can compile the module.
		installKernelHeaders "$(uname -r)"
		dnf install -y dkms amneziawg-dkms amneziawg-tools qrencode iptables nftables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	fi
	disable_apt_ipv4

	# Strip the deprecated REMAKE_INITRD directive from the amneziawg DKMS config.
	sanitizeAwgDkmsConf

	# Force DKMS to build the module for the running kernel only.
	# Using "dkms autoinstall -k" avoids errors from stale kernel directories in
	# /lib/modules/ whose headers are no longer installed (e.g. after a kernel
	# upgrade without reboot).
	# The package post-install hook may not trigger if headers were installed in the
	# same apt transaction, so an explicit autoinstall guarantees the .ko is present.
	if command -v dkms &>/dev/null; then
		if ! dkms autoinstall -k "$(uname -r)"; then
			echo -e "${ORANGE}WARNING: dkms autoinstall failed for kernel $(uname -r).${NC}"
			echo -e "${ORANGE}The amneziawg kernel module may not be available until headers are installed and the module is rebuilt.${NC}"
		fi
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

	# Verify the module was actually built. If the .ko file is missing even after
	# dkms autoinstall, something went wrong during compilation (likely missing
	# kernel headers).  Print an early, actionable warning so the user doesn't have
	# to wait until modprobe to discover the problem.
	if [ -z "$(find "/lib/modules/$(uname -r)" -name 'amneziawg.ko*' -print -quit 2>/dev/null)" ]; then
		echo -e "${ORANGE}WARNING: amneziawg kernel module was NOT built for kernel $(uname -r).${NC}"
		echo -e "${ORANGE}This usually means kernel headers are missing or the DKMS build failed.${NC}"
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			echo -e "${ORANGE}Try: apt install -y \"linux-headers-$(uname -r)\" && dkms autoinstall && depmod -a${NC}"
		elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			echo -e "${ORANGE}Try: dnf install -y \"kernel-devel-$(uname -r)\" && dkms autoinstall && depmod -a${NC}"
		fi
	fi

	# Ensure AmneziaWG kernel module is loaded at boot (before awg-quick service starts)
	mkdir -p /etc/modules-load.d
	chmod 755 /etc/modules-load.d
	if ! grep -qx "amneziawg" /etc/modules-load.d/amneziawg.conf 2>/dev/null; then
		echo "amneziawg" >> /etc/modules-load.d/amneziawg.conf
	fi
	chmod 644 /etc/modules-load.d/amneziawg.conf

	writeAwgServerInstallState

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
		if shouldCreateInitialClient; then
			newClient
			echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"
		else
			echo -e "${ORANGE}Skipping initial client generation. You can add users later from this script or the web panel.${NC}"
		fi
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
	ensureAwgBackendReady
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

		# Prompt for the client's IPv6 only when IPv6 support is enabled (issue #51).
		# When disabled, the safety net below derives a placeholder that is never
		# written to the config.
		if [[ "${ENABLE_IPV6}" == "y" ]]; then
			# Normalize server IPv6 and extract /64 prefix (first 4 groups)
			local NORMALIZED_SERVER_IPV6
			NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
			BASE_IP=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)

			# Reset IPV6_EXISTS so the until-loop below actually prompts the user.
			# The free-IP search loop above already set it to '0' for the first
			# available slot, which would cause the until condition to be immediately
			# true and skip the interactive IPv6 selection entirely.
			IPV6_EXISTS=""

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
	fi

	# Safety net: if CLIENT_AWG_IPV6 was not set (e.g., the interactive IPv6
	# prompt was unexpectedly skipped), derive it from the server's /64 prefix
	# and the selected host number to avoid writing a broken config.
	if [[ -z "${CLIENT_AWG_IPV6}" ]]; then
		CLIENT_AWG_IPV6=$(normalizeIPv6 "${BASE_IPV6}::${DOT_IP}")
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

	# Compress IPv6 to canonical RFC 5952 form for client config display
	local CLIENT_AWG_IPV6_DISPLAY
	CLIENT_AWG_IPV6_DISPLAY=$(compressIPv6 "${CLIENT_AWG_IPV6}")

	# Build the client Address and route list, including IPv6 only when enabled
	# (issue #51): an IPv6 address/route on an IPv4-only client fails to apply.
	local CLIENT_ADDRESS="${CLIENT_AWG_IPV4}/32"
	if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
		CLIENT_ADDRESS="${CLIENT_ADDRESS},${CLIENT_AWG_IPV6_DISPLAY}/128"
	fi
	local CLIENT_ALLOWED_IPS
	if ! CLIENT_ALLOWED_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${ENABLE_IPV6:-y}"); then
		echo -e "${RED}ERROR: ALLOWED_IPS has no usable routes after applying ENABLE_IPV6=${ENABLE_IPV6:-y}: ${ALLOWED_IPS}${NC}"
		return 1
	fi

	# Restrict umask for client config file creation (contains private key)
	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077
	local AWG_PROTOCOL_FIELDS=""
	AWG_PROTOCOL_FIELDS="$(renderAwgProtocolFields)" || {
		umask "${OLD_UMASK}"
		return 1
	}

	# Create client file and add the server as a peer
	echo "[Interface]
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
${AWG_PROTOCOL_FIELDS}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${CLIENT_ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# Restore default umask
	umask "${OLD_UMASK}"

	local client_conf owner_group sudo_home client_chown_ok client_chown_target client_primary_group sudo_chown_target sudo_primary_group
	client_conf="${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
	if ! chmod 600 "${client_conf}"; then
		echo "Warning: failed to set permissions on ${client_conf}" >&2
	fi

	# Copy config to the web panel directory (best-effort) *before* chowning
	# to a non-root user, so the source file is still root-owned and cannot
	# be swapped via a TOCTOU race in a user-writable directory.
	copyToWebPanelDir "${client_conf}"

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

	# Add the client as a peer to the server. Include the IPv6 /128 only when
	# IPv6 is enabled (issue #51).
	local PEER_ALLOWED_IPS="${CLIENT_AWG_IPV4}/32"
	if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
		PEER_ALLOWED_IPS="${PEER_ALLOWED_IPS},${CLIENT_AWG_IPV6}/128"
	fi
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${PEER_ALLOWED_IPS}" >>"${SERVER_AWG_CONF}"

	local sync_err
	sync_err=""
	if ! sync_err="$(awgSyncInterfaceConfig "${SERVER_AWG_NIC}" --stderr-to-stdout)"; then
		echo "ERROR: failed to sync AmneziaWG interface '${SERVER_AWG_NIC}' after adding client '${CLIENT_NAME}'" >&2
		if [[ -n "${sync_err}" ]]; then
			echo "${sync_err}" >&2
		fi
		exit 1
	fi

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

	# Remove config from the web panel directory (best-effort)
	removeFromWebPanelDir "${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# restart AmneziaWG to apply changes
	ensureAwgBackendReady
	awgSyncInterfaceConfig "${SERVER_AWG_NIC}"
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
	local AWG_PROTOCOL_FIELDS=""
	AWG_PROTOCOL_FIELDS="$(renderAwgProtocolFields)" || return 1

	# Preload client names from the server config so the loop does not redirect
	# stdin. This preserves stdin on fd 0 for interactive confirmation prompts
	# (e.g. read -rp ... / [[ -t 0 ]]).
	local -a CLIENT_NAMES=()
	local _CLIENT_ENTRY
	while IFS= read -r _CLIENT_ENTRY; do
		[[ -n "${_CLIENT_ENTRY}" ]] && CLIENT_NAMES+=("${_CLIENT_ENTRY}")
	done < <(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3)

	# Iterate over each client peer block in the server config
	for CLIENT_NAME in "${CLIENT_NAMES[@]}"; do
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
		CLIENT_PUB_KEY=$(echo "${PEER_BLOCK}" | grep -m1 -E "^PublicKey = " | sed 's/^PublicKey = //')
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

		# Normalize then compress IPv6 for canonical display in regenerated client configs
		if [[ -n "${CLIENT_AWG_IPV6}" ]]; then
			CLIENT_AWG_IPV6=$(compressIPv6 "$(normalizeIPv6 "${CLIENT_AWG_IPV6}")")
		fi

		# Build address string, including IPv6 only when the server still has it enabled.
		local CLIENT_ADDRESS="${CLIENT_AWG_IPV4}/32"
		if [[ "${ENABLE_IPV6:-y}" == "y" && -n "${CLIENT_AWG_IPV6}" ]]; then
			CLIENT_ADDRESS="${CLIENT_ADDRESS},${CLIENT_AWG_IPV6}/128"
		fi

		# Route list: drop IPv6 routes whenever the regenerated client will not have
		# an IPv6 address, so it never tries to add a ::/0 route (issue #51).
		local CLIENT_ROUTE_IPV6_ENABLED="${ENABLE_IPV6:-y}"
		if [[ -z "${CLIENT_AWG_IPV6}" ]]; then
			CLIENT_ROUTE_IPV6_ENABLED=n
		fi
		local CLIENT_ROUTE_IPS
		if ! CLIENT_ROUTE_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${CLIENT_ROUTE_IPV6_ENABLED}"); then
			echo -e "${RED}  FAIL: ${CLIENT_NAME} - ALLOWED_IPS has no usable routes after applying ENABLE_IPV6=${CLIENT_ROUTE_IPV6_ENABLED}${NC}"
			FAILED=$((FAILED + 1))
			continue
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
		local -a SEARCH_DIRS=()

		# 1) Resolved HOME_DIR (if any)
		if [[ -n "${HOME_DIR}" ]]; then
			SEARCH_DIRS+=("${HOME_DIR}")
		fi

		# 2) Web panel config directories (if configured/available)
		local PANEL_CONFIG_DIR
		PANEL_CONFIG_DIR="$(resolveWebPanelConfigDir 2>/dev/null || true)"
		if [[ -n "${PANEL_CONFIG_DIR}" ]]; then
			SEARCH_DIRS+=("${PANEL_CONFIG_DIR}")
		fi
		if [[ -n "${WEB_PANEL_CONFIG_DIR}" ]]; then
			SEARCH_DIRS+=("${WEB_PANEL_CONFIG_DIR}")
		fi

		# 3) Root's home (common when run as root or via sudo)
		SEARCH_DIRS+=("/root")

		# 4) All user homes under /home
		for SEARCH_DIR in /home/*; do
			if [[ -d "${SEARCH_DIR}" ]]; then
				SEARCH_DIRS+=("${SEARCH_DIR}")
			fi
		done

		# De-duplicate search directories while preserving search precedence
		local -a UNIQUE_SEARCH_DIRS=()
		for DIR in "${SEARCH_DIRS[@]}"; do
			[[ -z "${DIR}" ]] && continue
			local SEEN=0
			for UDIR in "${UNIQUE_SEARCH_DIRS[@]}"; do
				if [[ "${UDIR}" == "${DIR}" ]]; then
					SEEN=1
					break
				fi
			done
			if [[ ${SEEN} -eq 0 ]]; then
				UNIQUE_SEARCH_DIRS+=("${DIR}")
			fi
		done

		# Scan candidate config files.
		# Check active .conf files first across all directories, then archived .conf.old files.
		for CANDIDATE_DIR in "${UNIQUE_SEARCH_DIRS[@]}"; do
			CLIENT_CONF_CANDIDATES+=("${CANDIDATE_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf")
		done
		for CANDIDATE_DIR in "${UNIQUE_SEARCH_DIRS[@]}"; do
			CLIENT_CONF_CANDIDATES+=("${CANDIDATE_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf.old")
		done

		# Scan candidate config files (including .conf.old, renamed during migration).
		# For each candidate, verify that the private key derives to the public key
		# registered in the server config.  This prevents stale or unrelated configs
		# (e.g. left over from a previous installation in another home directory)
		# from being incorrectly matched by filename alone.
		local MATCHED_CONF=""
		for CANDIDATE in "${CLIENT_CONF_CANDIDATES[@]}"; do
			if [[ -f "${CANDIDATE}" ]]; then
				local CANDIDATE_PRIV_KEY
				CANDIDATE_PRIV_KEY=$(grep -m1 -E "^PrivateKey = " "${CANDIDATE}" | sed 's/^PrivateKey = //')
				if [[ -n "${CANDIDATE_PRIV_KEY}" ]]; then
					local CANDIDATE_PUB_KEY
					CANDIDATE_PUB_KEY=$(echo "${CANDIDATE_PRIV_KEY}" | awg pubkey 2>/dev/null || true)
					if [[ "${CANDIDATE_PUB_KEY}" == "${CLIENT_PUB_KEY}" ]]; then
						CLIENT_PRIV_KEY="${CANDIDATE_PRIV_KEY}"
						MATCHED_CONF="${CANDIDATE}"
						break
					fi
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
			# No existing private key found.
			# If the web panel is installed, rotating keys silently would desynchronize
			# the web panel database and break client connectivity/identity.
			if isWebPanelInstalled; then
				echo -e "${RED}  WARNING: ${CLIENT_NAME}: no existing private key found and amneziawg-web is installed.${NC}" >&2
				echo -e "${RED}  Generating a new key pair will desynchronize the web panel database and break client connectivity.${NC}" >&2
				local CONFIRM_NEW_KEY="n"
				if [[ -t 0 ]]; then
					read -rp "Generate new key pair for ${CLIENT_NAME} anyway? [y/N]: " CONFIRM_NEW_KEY
				fi
				if [[ ! "${CONFIRM_NEW_KEY}" =~ ^[Yy]$ ]]; then
					echo -e "${RED}  FAIL: ${CLIENT_NAME}: skipped to avoid rotating web-managed client identity without existing private key.${NC}" >&2
					FAILED=$((FAILED + 1))
					continue
				fi
			fi

			# Standalone mode, or explicitly confirmed by user in interactive mode:
			# generate a new key pair. Client will need the new config to reconnect.
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
		if [[ -z "${OUTPUT_CONF}" ]]; then
			if [[ -n "${PANEL_CONFIG_DIR}" ]]; then
				OUTPUT_CONF="${PANEL_CONFIG_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
			else
				OUTPUT_CONF="/root/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
			fi
		fi
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
${AWG_PROTOCOL_FIELDS}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${CLIENT_ROUTE_IPS}
EOF

		# Copy regenerated config to the web panel directory (best-effort)
		# *before* chowning to a non-root user, so the source file is still
		# root-owned and cannot be swapped via a TOCTOU race.
		copyToWebPanelDir "${OUTPUT_CONF}"

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
	done

	# If any server-side peer keys were updated, sync the running config
	if (( NEWKEYS > 0 )); then
		ensureAwgBackendReady
		awgSyncInterfaceConfig "${SERVER_AWG_NIC}"
	fi

	echo ""
	echo -e "${GREEN}Regeneration complete: ${REGENERATED} succeeded, ${FAILED} failed.${NC}"
	if (( NEWKEYS > 0 )); then
		echo -e "${ORANGE}${NEWKEYS} client(s) had new key pairs generated (old private key was not found).${NC}"
	fi
	echo -e "${ORANGE}Distribute the new .conf files to your clients.${NC}"
}

function removeInstalledAptPackages() {
	local PACKAGE
	local PACKAGE_STATUS
	local -a INSTALLED_PACKAGES=()

	for PACKAGE in "$@"; do
		if PACKAGE_STATUS=$(dpkg-query -W -f='${db:Status-Abbrev}' "${PACKAGE}" 2>/dev/null) &&
			[[ "${PACKAGE_STATUS}" == i* ]]; then
			INSTALLED_PACKAGES+=("${PACKAGE}")
		fi
	done

	[[ "${#INSTALLED_PACKAGES[@]}" -gt 0 ]] || return 0
	apt remove -y "${INSTALLED_PACKAGES[@]}"
}

# BoringTun: remove the PACKAGES that the package database lists as installed,
# after one complete, successful read of it. Every row of the inventory must be
# a package name and a dpkg status abbreviation, and dpkg itself must be listed
# as installed, because dpkg-query reads a missing database as an empty one
# without an error. A failed or malformed read is an error, never "not
# installed"; so is a failed removal.
function removeBoringtunAptPackages() { # <package>...
	local INVENTORY LINE PACKAGE
	local ROW=$'^([a-z0-9][a-z0-9+.-]+)\t([uihrp][ncHUFWti][ R]?)$'
	local -A STATE=()
	local -a INSTALLED_PACKAGES=()
	# shellcheck disable=SC2016 # dpkg-query fields, not shell variables
	if ! INVENTORY="$(dpkg-query -W -f='${Package}\t${db:Status-Abbrev}\n' 2>/dev/null)"; then
		echo -e "${RED}ERROR: the package database cannot be read (dpkg-query failed).${NC}"
		return 1
	fi
	while IFS= read -r LINE; do
		[[ -n "${LINE}" ]] || continue
		if [[ ! "${LINE}" =~ ${ROW} ]]; then
			echo -e "${RED}ERROR: dpkg-query printed a line that is not a package status: ${LINE}${NC}"
			return 1
		fi
		# A package listed for several architectures is installed when any is.
		[[ "${STATE[${BASH_REMATCH[1]}]:-}" == i* ]] || STATE["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
	done <<<"${INVENTORY}"
	if [[ "${STATE[dpkg]:-}" != ii* ]]; then
		echo -e "${RED}ERROR: the package database read does not list dpkg as installed, so it is not the system's.${NC}"
		return 1
	fi
	for PACKAGE in "$@"; do
		[[ "${STATE[${PACKAGE}]:-}" == i* ]] && INSTALLED_PACKAGES+=("${PACKAGE}")
	done
	[[ "${#INSTALLED_PACKAGES[@]}" -gt 0 ]] || return 0
	apt remove -y "${INSTALLED_PACKAGES[@]}" || return 1
}

# BoringTun: the unit is positively not running. systemd must answer its
# ActiveState, which it does also once the unit file is gone, and the answer
# must be inactive or failed. systemctl is-active is not used: its exit status
# for an inactive unit differs between systemd versions (3 on 252, 4 on 255
# for a removed unit), while a failed query exits 1. A failed query or any
# other state is no proof.
function boringtunServiceInactive() { # <interface>
	local UNIT="awg-quick@$1.service" STATE
	if ! STATE="$(systemctl show -p ActiveState --value "${UNIT}" 2>/dev/null)"; then
		echo -e "${RED}ERROR: the state of ${UNIT} cannot be read.${NC}"
		return 1
	fi
	case "${STATE}" in
		inactive | failed) return 0 ;;
		active | activating | deactivating | reloading | refreshing)
			echo -e "${RED}ERROR: ${UNIT} is still ${STATE}.${NC}"
			return 1
			;;
		*)
			echo -e "${RED}ERROR: systemd reports an unexpected state for ${UNIT}: '${STATE}'.${NC}"
			return 1
			;;
	esac
}

function uninstallAmneziaWG() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/amnezia/amneziawg directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == [yY] ]]; then
		checkOS
		local UNINSTALL_FAILED=0

		systemctl stop "awg-quick@${SERVER_AWG_NIC}"
		systemctl disable "awg-quick@${SERVER_AWG_NIC}"
		local DISABLE_RC=$?

		# With BoringTun, the stop above ran the crash-safe teardown of the
		# supervised daemon. Keep every file while a daemon of the interface
		# still runs, so that a later uninstall can finish the job.
		local BORINGTUN_DAEMONS=""
		if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
			if ((DISABLE_RC != 0)); then
				echo -e "${RED}ERROR: awg-quick@${SERVER_AWG_NIC} could not be disabled; nothing was removed. Fix the cause and rerun the uninstall.${NC}"
				exit 1
			fi
			BORINGTUN_DAEMONS="$(boringtunDaemonsOf "${SERVER_AWG_NIC}")"
			if [[ -n "${BORINGTUN_DAEMONS}" ]]; then
				echo -e "${RED}ERROR: a BoringTun daemon of ${SERVER_AWG_NIC} is still running (PID ${BORINGTUN_DAEMONS//$'\n'/, }) after stopping awg-quick@${SERVER_AWG_NIC}.${NC}"
				echo -e "${ORANGE}Nothing was removed. Check: journalctl -u awg-quick@${SERVER_AWG_NIC}, then rerun the uninstall.${NC}"
				exit 1
			fi
			# Nothing is removed until the teardown is proven finished: a
			# start attempt that poststop kept, such as a PostDown replay that
			# may have run in part, stops the uninstall here.
			if ! boringtunTeardownFinished "${SERVER_AWG_NIC}"; then
				echo -e "${RED}ERROR: the BoringTun teardown of ${SERVER_AWG_NIC} is not proven finished; nothing was removed.${NC}"
				exit 1
			fi
		fi

		# Remove systemd drop-in override created during install
		DROPIN_DIR="${AWG_SYSTEMD_UNIT_DIR}/awg-quick@${SERVER_AWG_NIC:?}.service.d"
		OVERRIDE_FILE="${DROPIN_DIR}/override.conf"
		if [[ -f "${OVERRIDE_FILE}" ]]; then
			rm -f "${OVERRIDE_FILE}"
		fi
		# Remove drop-in directory only if empty to avoid deleting user-managed files
		if [[ -d "${DROPIN_DIR}" ]] && [[ -z "$(ls -A "${DROPIN_DIR}")" ]]; then
			rmdir "${DROPIN_DIR}"
		fi
		systemctl daemon-reload
		local DAEMON_RELOAD_RC=$?

		# Remove module auto-load entry. Only the kernel install writes it; a
		# BoringTun install never does, so there it is someone else's.
		if [[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]]; then
			rm -f "${AWG_MODULES_LOAD_FILE}"
		fi

		# Disable routing
		# Only remove our conf file; do NOT force ip_forward=0 at runtime because
		# other services (Docker, libvirt, other VPNs) may depend on forwarding.
		# The setting will revert to the system default on next reboot.
		rm -f "${AWG_SYSCTL_FILE}"

		# BoringTun: every removal before the commit either worked or fails the
		# uninstall, with the configuration kept for a rerun.
		if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
			local LEFT_BEHIND="" LEFT_FILE
			for LEFT_FILE in "${OVERRIDE_FILE}" "${AWG_SYSCTL_FILE}"; do
				[[ ! -e "${LEFT_FILE}" && ! -L "${LEFT_FILE}" ]] || LEFT_BEHIND+=" ${LEFT_FILE}"
			done
			if [[ -n "${LEFT_BEHIND}" || ${DAEMON_RELOAD_RC} -ne 0 ]]; then
				[[ -z "${LEFT_BEHIND}" ]] || echo -e "${RED}ERROR: could not remove${LEFT_BEHIND}.${NC}"
				[[ ${DAEMON_RELOAD_RC} -eq 0 ]] || echo -e "${RED}ERROR: systemctl daemon-reload failed after the drop-in was removed.${NC}"
				echo -e "${ORANGE}The configuration in ${AMNEZIAWG_DIR} was kept. Fix the cause and rerun the uninstall.${NC}"
				exit 1
			fi
		fi

		# BoringTun: the helpers, the binary store, the load override and runtime
		# state. On failure params stay, so the uninstall can be run again.
		if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]] && ! uninstallBoringtunRuntime "${SERVER_AWG_NIC}"; then
			echo -e "${RED}ERROR: the BoringTun backend could not be removed completely; see the messages above.${NC}"
			echo -e "${ORANGE}The configuration in ${AMNEZIAWG_DIR} was kept. Fix the cause and rerun the uninstall.${NC}"
			exit 1
		fi

		# Remove config files. A BoringTun uninstall removes them last, only
		# after its packages and repository entries are gone, so that until
		# then a rerun finds params and uninstalls again.
		if [[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]]; then
			rm -rf "${AMNEZIAWG_DIR:?}"
		fi

		# A BoringTun host installed only amneziawg-tools. Kernel module packages
		# found there were installed by someone else and are left alone.
		local -a AWG_APT_PACKAGES=(amneziawg amneziawg-tools amneziawg-dkms)
		[[ "${OS}" == 'debian' ]] && AWG_APT_PACKAGES=(amneziawg amneziawg-tools)
		[[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]] && AWG_APT_PACKAGES=(amneziawg-tools)
		# BoringTun removes them strictly: a failed package database read is an
		# error, never "not installed".
		local REMOVE_APT_PACKAGES=removeInstalledAptPackages
		[[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]] && REMOVE_APT_PACKAGES=removeBoringtunAptPackages

		if [[ ${OS} == 'ubuntu' ]]; then
			if ! "${REMOVE_APT_PACKAGES}" "${AWG_APT_PACKAGES[@]}"; then
				echo -e "${RED}ERROR: Failed to remove one or more installed AmneziaWG packages.${NC}"
				UNINSTALL_FAILED=1
			fi
			if ! removeAmneziaPpaSourceEntries "${AMNEZIA_PPA_SOURCES_DIR}"; then
				echo -e "${ORANGE}WARNING: Could not safely remove every Amnezia PPA source entry. Review ${AMNEZIA_PPA_SOURCES_DIR} manually.${NC}"
				UNINSTALL_FAILED=1
			fi
			# Remove both possible auxiliary deb-src files when owned by this
			# installer. Systems upgraded between formats can contain both.
			local MANAGED_SOURCE
			for MANAGED_SOURCE in \
				"${AMNEZIA_PPA_SOURCES_DIR}/amneziawg.sources" \
				"${AMNEZIA_PPA_SOURCES_DIR}/amneziawg.sources.list"; do
				if [[ -f "${MANAGED_SOURCE}" ]] && head -1 "${MANAGED_SOURCE}" | grep -q '# Managed by amneziawg-install'; then
					rm -f "${MANAGED_SOURCE}"
					# BoringTun: a managed repository file that stays blocks the commit.
					[[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]] || [[ ! -e "${MANAGED_SOURCE}" ]] || UNINSTALL_FAILED=1
				elif [[ -f "${MANAGED_SOURCE}" ]]; then
					echo -e "${ORANGE}NOTE: ${MANAGED_SOURCE} was not created by this installer (missing sentinel). Leaving it in place.${NC}"
				fi
			done
			enable_apt_ipv4
			apt-get update || echo -e "${ORANGE}WARNING: Failed to refresh APT indexes after removing the Amnezia PPA.${NC}"
			disable_apt_ipv4
		elif [[ ${OS} == 'debian' ]]; then
			if ! "${REMOVE_APT_PACKAGES}" "${AWG_APT_PACKAGES[@]}"; then
				echo -e "${RED}ERROR: Failed to remove one or more installed AmneziaWG packages.${NC}"
				UNINSTALL_FAILED=1
			fi
			# Only remove source file and keyring if the source file has our sentinel on line 1
			local DEBIAN_SOURCE="${AMNEZIA_PPA_SOURCES_DIR}/amneziawg.sources.list"
			if [[ -f "${DEBIAN_SOURCE}" ]] && head -1 "${DEBIAN_SOURCE}" | grep -q '# Managed by amneziawg-install'; then
				rm -f "${DEBIAN_SOURCE}"
				rm -f "${AWG_APT_KEYRING_FILE}"
				# BoringTun: a managed repository file that stays blocks the commit.
				[[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]] || [[ ! -e "${DEBIAN_SOURCE}" && ! -e "${AWG_APT_KEYRING_FILE}" ]] || UNINSTALL_FAILED=1
			elif [[ -f "${DEBIAN_SOURCE}" ]]; then
				echo -e "${ORANGE}NOTE: ${DEBIAN_SOURCE} was not created by this installer (missing sentinel). Leaving it and keyring in place.${NC}"
			elif [[ -f "${AWG_APT_KEYRING_FILE}" ]]; then
				# Source file is gone (manually deleted) but orphaned keyring remains
				echo -e "${ORANGE}NOTE: Managed source file not found but orphaned keyring detected. Removing keyring.${NC}"
				rm -f "${AWG_APT_KEYRING_FILE}"
				# BoringTun: a managed repository file that stays blocks the commit.
				[[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]] || [[ ! -e "${AWG_APT_KEYRING_FILE}" ]] || UNINSTALL_FAILED=1
			fi
			apt update
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		fi

		# Check if AmneziaWG is running. BoringTun needs positive proof that the
		# unit is not running: a failed query is not "inactive".
		if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
			AWG_RUNNING=0
			boringtunServiceInactive "${SERVER_AWG_NIC}" && AWG_RUNNING=1
		else
			systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
			AWG_RUNNING=$?
		fi

		# BoringTun: the configuration goes last, as the commit of an
		# uninstall whose every step succeeded. Until then it stays, so the
		# next run of the installer offers the uninstall again instead of a
		# fresh install.
		if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
			if [[ ${AWG_RUNNING} -eq 0 || ${UNINSTALL_FAILED} -ne 0 ]]; then
				echo -e "${ORANGE}The configuration in ${AMNEZIAWG_DIR} was kept, so the uninstall can be run again.${NC}"
			else
				rm -rf "${AMNEZIAWG_DIR:?}"
				if [[ -e "${AMNEZIAWG_DIR}" ]]; then
					echo -e "${RED}ERROR: ${AMNEZIAWG_DIR} could not be removed.${NC}"
					UNINSTALL_FAILED=1
				fi
			fi
		fi

		if [[ ${AWG_RUNNING} -eq 0 || ${UNINSTALL_FAILED} -ne 0 ]]; then
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
	local ALLOW_INVALID_AWG3_FOR_DOWNGRADE="${1:-0}"
	# Security: verify params file is safe to source (owned by root, not readable/writable by others)
	# This mitigates the risk of arbitrary code execution or private key exposure
	# Reject symlinks explicitly so we don't accidentally source an unexpected file via a link.
	if [[ -L "${AMNEZIAWG_DIR}/params" ]] || [[ -h "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file must not be a symbolic link: ${AMNEZIAWG_DIR}/params${NC}" >&2
		echo -e "${ORANGE}Remove the symlink and create a regular file owned by root with mode 600 or 400.${NC}" >&2
		return 1
	fi
	if [[ ! -f "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file not found or is not a regular file: ${AMNEZIAWG_DIR}/params${NC}" >&2
		echo -e "${ORANGE}The installer cannot continue without a valid params file.${NC}" >&2
		return 1
	fi
	if [[ ! -r "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file is not readable: ${AMNEZIAWG_DIR}/params${NC}" >&2
		echo -e "${ORANGE}Ensure the file is readable by root and try again.${NC}" >&2
		return 1
	fi
	local PARAMS_OWNER PARAMS_PERMS
	PARAMS_OWNER=$(stat -c '%u' "${AMNEZIAWG_DIR}/params" 2>/dev/null)
	PARAMS_PERMS=$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null)
	if [[ -z "${PARAMS_OWNER}" ]] || [[ -z "${PARAMS_PERMS}" ]]; then
		echo -e "${RED}ERROR: Failed to read file metadata for ${AMNEZIAWG_DIR}/params.${NC}" >&2
		echo -e "${ORANGE}Ensure the file exists and is accessible, then retry.${NC}" >&2
		return 1
	fi
	if [[ "${PARAMS_OWNER}" != "0" ]]; then
		echo -e "${RED}ERROR: ${AMNEZIAWG_DIR}/params is not owned by root (owner UID: ${PARAMS_OWNER}).${NC}" >&2
		echo -e "${ORANGE}This is a security risk. Fix with: chown root:root ${AMNEZIAWG_DIR}/params${NC}" >&2
		return 1
	fi
	# Require mode 600 or 400: the file contains SERVER_PRIV_KEY and must not be
	# readable or writable by group/other. Modes like 644 would leak the private key.
	if [[ "${PARAMS_PERMS}" != "600" ]] && [[ "${PARAMS_PERMS}" != "400" ]]; then
		echo -e "${RED}WARNING: ${AMNEZIAWG_DIR}/params has insecure permissions (${PARAMS_PERMS}).${NC}" >&2
		echo -e "${RED}This file contains the server private key and must not be accessible by non-root users.${NC}" >&2
		# For legacy installs created before strict umask/chmod logic, try to auto-remediate
		# when running as root and the file is owned by root, to avoid locking out management actions.
		if [[ "${EUID}" -eq 0 ]] && [[ "${PARAMS_OWNER}" == "0" ]]; then
			echo -e "${ORANGE}Attempting to fix permissions by setting mode 600 on ${AMNEZIAWG_DIR}/params...${NC}" >&2
			local chmod_err
			if chmod_err=$(chmod 600 "${AMNEZIAWG_DIR}/params" 2>&1); then
				echo -e "${GREEN}Permissions on ${AMNEZIAWG_DIR}/params updated to 600. Continuing.${NC}" >&2
			else
				# chmod failed (e.g. read-only filesystem or immutable file attribute).
				# Re-stat first so the warning shows the actual post-failure mode, not
				# the stale pre-chmod value.  Abort only when group/other WRITE bits
				# remain (privilege-escalation risk); group/other READ-only exposure
				# is warned but allowed so management operations are not blocked.
				local current_mode
				if ! current_mode=$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null); then
					echo -e "${RED}ERROR: Could not re-read permissions on ${AMNEZIAWG_DIR}/params after chmod failure; refusing to source an unverified file as root.${NC}" >&2
					return 1
				fi
				echo -e "${ORANGE}WARNING: Could not fix permissions on ${AMNEZIAWG_DIR}/params (current: ${current_mode}): ${chmod_err}${NC}" >&2
				echo -e "${ORANGE}The filesystem may be read-only or the file may have the immutable attribute set.${NC}" >&2
				echo -e "${ORANGE}Fix when possible: chmod 600 ${AMNEZIAWG_DIR}/params${NC}" >&2
				# Abort if any group/other WRITE bit remains set (mode & 022 != 0).
				# Writable params files are a privilege-escalation risk: a
				# non-root user could inject code that runs as root when the
				# file is sourced.
				if (( (8#${current_mode} & 022) != 0 )); then
					echo -e "${RED}ERROR: ${AMNEZIAWG_DIR}/params is writable by group/other (mode: ${current_mode}). Refusing to source for security reasons.${NC}" >&2
					echo -e "${ORANGE}Fix manually: chmod 600 ${AMNEZIAWG_DIR}/params${NC}" >&2
					return 1
				fi
				# Warn if group/other READ bits remain (mode & 044 != 0).
				# This exposes SERVER_PRIV_KEY but is an information-disclosure
				# risk only; blocking the operation does not un-expose the key,
				# so we warn and continue.
				if (( (8#${current_mode} & 044) != 0 )); then
					echo -e "${ORANGE}WARNING: ${AMNEZIAWG_DIR}/params is readable by group/other (mode: ${current_mode}). The server private key may be exposed to non-root users.${NC}" >&2
				fi
			fi
		else
			echo -e "${ORANGE}Fix with: chmod 600 ${AMNEZIAWG_DIR}/params${NC}" >&2
			return 1
		fi
	fi

	# Params must be authoritative; do not let exported shell variables fill in
	# keys that older params files legitimately lack, select an AWG backend or a
	# BoringTun protocol imitation, or enable AWG 3.0 features.
	unset ENABLE_IPV6 AWG_PROTOCOL_VERSION AWG_HEADER_PROTECTION_KEY \
		AWG_CONTENT_PADDING_ADDITION AWG_REKEY_AFTER_TIME AWG_REKEY_TIMEOUT \
		AWG_REJECT_AFTER_TIME AWG_KEEPALIVE_TIMEOUT AWG_RANDOM_TRAILERS \
		AWG_DISABLE_COOKIES AWG_BACKEND AWG_BORINGTUN_IMITATE_PROTOCOL \
		AWG_BORINGTUN_IMITATE_DOMAIN
	# shellcheck source=/etc/amnezia/amneziawg/params
	if ! source "${AMNEZIAWG_DIR}/params"; then
		echo -e "${RED}ERROR: Failed to load params from ${AMNEZIAWG_DIR}/params.${NC}" >&2
		echo -e "${ORANGE}The file may be corrupted or contain a syntax error. Fix or regenerate it and rerun the installer.${NC}" >&2
		return 1
	fi
	if ! validatePersistedAwgBackendState; then
		echo -e "${RED}ERROR: Invalid AWG backend state in ${AMNEZIAWG_DIR}/params.${NC}" >&2
		return 1
	fi
	if ! validatePersistedAwgProtocolState "${ALLOW_INVALID_AWG3_FOR_DOWNGRADE}"; then
		echo -e "${RED}ERROR: Invalid AWG protocol state in ${AMNEZIAWG_DIR}/params.${NC}" >&2
		return 1
	fi
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	# Verify server config file exists before attempting migration
	if [[ ! -f "${SERVER_AWG_CONF}" ]]; then
		echo -e "${RED}ERROR: Server configuration file not found: ${SERVER_AWG_CONF}${NC}" >&2
		echo -e "${ORANGE}The params file exists but the config file is missing.${NC}" >&2
		return 1
	fi

	# Validate any persisted flag, but use the actual server interface Address as
	# the authority for installed-server management. This keeps bash and the web
	# panel aligned when an operator converts a server to IPv4-only by removing
	# the IPv6 address from the live config (issue #51).
	if [[ -n "${ENABLE_IPV6:-}" ]]; then
		ENABLE_IPV6=$(trimWhitespace "${ENABLE_IPV6}")
		ENABLE_IPV6="${ENABLE_IPV6,,}"
		if [[ "${ENABLE_IPV6}" != "y" && "${ENABLE_IPV6}" != "n" ]]; then
			echo -e "${RED}ERROR: ENABLE_IPV6 in params must be 'y' or 'n': ${ENABLE_IPV6}${NC}" >&2
			return 1
		fi
	fi
	if serverConfigHasIPv6Address "${SERVER_AWG_CONF}"; then
		ENABLE_IPV6=y
	else
		ENABLE_IPV6=n
	fi

	# Validate and normalize SERVER_AWG_IPV6 from params file
	# Older installations may have stored non-normalized or oddly formatted IPv6
	if ! isValidIPv6 "${SERVER_AWG_IPV6}"; then
		echo -e "${RED}ERROR: Invalid IPv6 address in params file: ${SERVER_AWG_IPV6}${NC}" >&2
		echo -e "${ORANGE}Fix the SERVER_AWG_IPV6 value in ${AMNEZIAWG_DIR}/params${NC}" >&2
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
			awgSyncInterfaceConfig "${SERVER_AWG_NIC}"
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
	local ALLOW_INVALID_AWG3_FOR_DOWNGRADE="${1:-0}"
	local SKIP_LEGACY_MIGRATIONS="${2:-0}"
	if ! validateParamsFile "${ALLOW_INVALID_AWG3_FOR_DOWNGRADE}"; then
		echo -e "${RED}Failed to validate params file. Aborting parameter loading.${NC}" >&2
		exit 1
	fi
	# The explicit AWG 2.0 recovery path must not mutate params or configs before
	# the protocol transaction has captured its backups. Any legacy normalization
	# can run on a later ordinary management invocation after the downgrade.
	if [[ "${SKIP_LEGACY_MIGRATIONS}" == "1" ]]; then
		return 0
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

# Return success when an older AWG 2.0 installation still needs the ordinary
# compatibility migration performed by loadParams. Run the migration probes in
# a subshell so generated replacement values never escape into the protocol
# transaction before the operator has accepted that compatibility migration.
function awg2StateNeedsLegacyMigration() (
	if [[ "${_MIGRATE_ORIG_IPV6}" != "${SERVER_AWG_IPV6}" ]]; then
		return 0
	fi
	if migrateS3S4; then
		return 0
	fi
	if migrateH1H4; then
		return 0
	fi
	return 1
)

# Rewrite only AWG 3.0 interface fields, preserving all addresses, keys, peers,
# routes, DNS settings, comments, and firewall hooks byte-for-line otherwise.
# The field file is private because it contains HeaderProtectionKey in mode 3.
function rewriteAwgProtocolConfig() {
	local INPUT_FILE="$1"
	local OUTPUT_FILE="$2"
	local FIELD_FILE="$3"
	local LINE INSERTED=0
	local -a PENDING_BLANK_LINES=()

	(
		umask 077
		while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
			if [[ "${LINE}" =~ ^[[:space:]]*(${AWG_PROTOCOL_CONFIG_KEYS})[[:space:]]*= ]]; then
				continue
			fi
			# Hold only the blank separator immediately before the first peer.
			# AWG 3.0 fields belong before that existing separator; otherwise a
			# newly inserted blank line would survive downgrade and accumulate on
			# every protocol round trip.
			if (( INSERTED == 0 )) && [[ "${LINE}" =~ ^[[:space:]]*$ ]]; then
				PENDING_BLANK_LINES+=("${LINE}")
				continue
			fi
			if (( INSERTED == 0 )) && { [[ "${LINE}" =~ ^[[:space:]]*\[Peer\][[:space:]]*$ ]] || [[ "${LINE}" =~ ^[[:space:]]*###[[:space:]]+Client([[:space:]]|$) ]]; }; then
				if [[ -s "${FIELD_FILE}" ]]; then
					cat -- "${FIELD_FILE}" || exit 1
				fi
				if (( ${#PENDING_BLANK_LINES[@]} > 0 )); then
					printf '%s\n' "${PENDING_BLANK_LINES[@]}"
					PENDING_BLANK_LINES=()
				fi
				INSERTED=1
			elif (( ${#PENDING_BLANK_LINES[@]} > 0 )); then
				printf '%s\n' "${PENDING_BLANK_LINES[@]}"
				PENDING_BLANK_LINES=()
			fi
			printf '%s\n' "${LINE}"
		done <"${INPUT_FILE}"
		if (( INSERTED == 0 )) && [[ -s "${FIELD_FILE}" ]]; then
			cat -- "${FIELD_FILE}" || exit 1
		fi
		if (( ${#PENDING_BLANK_LINES[@]} > 0 )); then
			printf '%s\n' "${PENDING_BLANK_LINES[@]}"
		fi
	) >"${OUTPUT_FILE}" || return 1
}

# Return every regular, non-symlink client config in the known installer/web
# locations. Search roots come from managed server state, the system account
# database, and root-controlled web configuration.
function collectAwgClientConfigCandidates() {
	local OUTPUT_NAME="$1"
	local -n OUTPUT_REF="${OUTPUT_NAME}"
	local -a SEARCH_ROOTS=()
	local ROOT CANDIDATE CANONICAL PANEL_DIR HOME_PATH CLIENT_NAME
	local NULLGLOB_WAS_SET=0
	local -A SEEN_PATHS=()

	OUTPUT_REF=()
	SEARCH_ROOTS+=("${AMNEZIAWG_DIR}/clients" "/root")
	for HOME_PATH in /home/*; do
		[[ -d "${HOME_PATH}" && ! -L "${HOME_PATH}" ]] && SEARCH_ROOTS+=("${HOME_PATH}")
	done
	# getHomeDirForClient supports NSS/LDAP accounts whose homes are outside
	# /home. Resolve each root-controlled managed marker so configs originally
	# written to paths such as /srv/alice remain part of an all-client migration.
	while IFS= read -r CLIENT_NAME; do
		[[ -n "${CLIENT_NAME}" ]] || continue
		HOME_PATH="$(getHomeDirForClient "${CLIENT_NAME}")" || return 1
		if [[ "${HOME_PATH}" == /* && -d "${HOME_PATH}" && ! -L "${HOME_PATH}" ]]; then
			SEARCH_ROOTS+=("${HOME_PATH}")
		fi
	done < <(grep -E '^### Client [A-Za-z0-9_-]{1,15}$' "${SERVER_AWG_CONF}" | cut -d ' ' -f 3)
	PANEL_DIR="$(resolveWebPanelConfigDir 2>/dev/null || true)"
	[[ -z "${PANEL_DIR}" ]] || SEARCH_ROOTS+=("${PANEL_DIR}")

	shopt -q nullglob && NULLGLOB_WAS_SET=1
	shopt -s nullglob
	for ROOT in "${SEARCH_ROOTS[@]}"; do
		[[ -d "${ROOT}" && ! -L "${ROOT}" ]] || continue
		for CANDIDATE in "${ROOT}/${SERVER_AWG_NIC}-client-"*.conf; do
			[[ -f "${CANDIDATE}" && ! -L "${CANDIDATE}" ]] || continue
			CANONICAL="$(readlink -f -- "${CANDIDATE}" 2>/dev/null || true)"
			[[ -n "${CANONICAL}" && -z "${SEEN_PATHS[${CANONICAL}]+present}" ]] || continue
			SEEN_PATHS["${CANONICAL}"]=1
			OUTPUT_REF+=("${CANONICAL}")
		done
	done
	(( NULLGLOB_WAS_SET )) || shopt -u nullglob
}

# Filter discovered files to active peers and require at least one recoverable
# private-key-bearing config for every server peer. This avoids a migration
# that would silently strand a client whose configuration cannot be updated.
function collectActiveAwgClientConfigs() {
	local OUTPUT_NAME="$1"
	# shellcheck disable=SC2178 # OUTPUT_REF is intentionally a nameref to an array.
	local -n OUTPUT_REF="${OUTPUT_NAME}"
	local -a CANDIDATES=()
	local -A ACTIVE_PATHS=()
	local CLIENT_NAME EXPECTED_PUB CANDIDATE PRIVATE_KEY DERIVED_PUB
	local MATCHED_COUNT PEER_COUNT MARKER_COUNT UNIQUE_MARKER_COUNT

	OUTPUT_REF=()
	collectAwgClientConfigCandidates CANDIDATES || return 1
	PEER_COUNT="$(grep -Ec '^[[:space:]]*\[Peer\][[:space:]]*$' "${SERVER_AWG_CONF}" || true)"
	MARKER_COUNT="$(grep -Ec '^### Client [A-Za-z0-9_-]{1,15}$' "${SERVER_AWG_CONF}" || true)"
	UNIQUE_MARKER_COUNT="$(grep -E '^### Client [A-Za-z0-9_-]{1,15}$' "${SERVER_AWG_CONF}" | sort -u | wc -l)"
	UNIQUE_MARKER_COUNT="${UNIQUE_MARKER_COUNT//[[:space:]]/}"
	if (( PEER_COUNT != MARKER_COUNT || MARKER_COUNT != UNIQUE_MARKER_COUNT )); then
		echo "ERROR: every server peer must have one unique installer-managed client marker before changing protocol mode" >&2
		return 1
	fi
	while IFS= read -r CLIENT_NAME; do
		[[ -n "${CLIENT_NAME}" ]] || continue
		if ! [[ "${CLIENT_NAME}" =~ ^[A-Za-z0-9_-]{1,15}$ ]]; then
			echo "ERROR: unsafe client marker in server config; refusing protocol migration" >&2
			return 1
		fi
		EXPECTED_PUB="$(sed -n "/^### Client ${CLIENT_NAME}\$/,/^\$/p" "${SERVER_AWG_CONF}" | sed -n 's/^PublicKey = //p' | head -n1)"
		if [[ -z "${EXPECTED_PUB}" ]]; then
			echo "ERROR: client '${CLIENT_NAME}' has no public key in the server config" >&2
			return 1
		fi
		MATCHED_COUNT=0
		for CANDIDATE in "${CANDIDATES[@]}"; do
			[[ "$(basename -- "${CANDIDATE}")" == "${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf" ]] || continue
			PRIVATE_KEY="$(sed -n 's/^PrivateKey = //p' "${CANDIDATE}" | head -n1)"
			[[ -n "${PRIVATE_KEY}" ]] || continue
			DERIVED_PUB="$(printf '%s\n' "${PRIVATE_KEY}" | awg pubkey 2>/dev/null || true)"
			[[ "${DERIVED_PUB}" == "${EXPECTED_PUB}" ]] || continue
			MATCHED_COUNT=$((MATCHED_COUNT + 1))
			ACTIVE_PATHS["${CANDIDATE}"]=1
		done
		if (( MATCHED_COUNT == 0 )); then
			echo "ERROR: no recoverable configuration was found for client '${CLIENT_NAME}'" >&2
			echo "       Restore or regenerate that client's config before changing protocol mode." >&2
			return 1
		fi
	done < <(grep -E '^### Client ' "${SERVER_AWG_CONF}" | cut -d ' ' -f 3)

	for CANDIDATE in "${CANDIDATES[@]}"; do
		[[ -z "${ACTIVE_PATHS[${CANDIDATE}]+present}" ]] || OUTPUT_REF+=("${CANDIDATE}")
	done
}

# Confirm that one server/client configuration contains exactly the protocol
# fields described by the already-validated persisted params. Field order and
# harmless surrounding whitespace are ignored, but duplicate, missing, stale,
# or mismatched values require a repair transaction.
function awgProtocolConfigMatchesPersistedState() {
	local CONFIG_FILE="$1"
	local LINE KEY VALUE EXPECTED_KEY
	local -A EXPECTED_FIELDS=() SEEN_FIELDS=()

	[[ -f "${CONFIG_FILE}" && ! -L "${CONFIG_FILE}" && -r "${CONFIG_FILE}" ]] || return 2

	if awgProtocolUsesHeaderProtection; then
		EXPECTED_FIELDS[HeaderProtectionKey]="${AWG_HEADER_PROTECTION_KEY}"
		[[ -z "${AWG_CONTENT_PADDING_ADDITION:-}" ]] || EXPECTED_FIELDS[ContentPaddingAddition]="${AWG_CONTENT_PADDING_ADDITION}"
		[[ -z "${AWG_REKEY_AFTER_TIME:-}" ]] || EXPECTED_FIELDS[RekeyAfterTime]="${AWG_REKEY_AFTER_TIME}"
		[[ -z "${AWG_REKEY_TIMEOUT:-}" ]] || EXPECTED_FIELDS[RekeyTimeout]="${AWG_REKEY_TIMEOUT}"
		[[ -z "${AWG_REJECT_AFTER_TIME:-}" ]] || EXPECTED_FIELDS[RejectAfterTime]="${AWG_REJECT_AFTER_TIME}"
		[[ -z "${AWG_KEEPALIVE_TIMEOUT:-}" ]] || EXPECTED_FIELDS[KeepaliveTimeout]="${AWG_KEEPALIVE_TIMEOUT}"
		if awgProtocolUses31Fields; then
			EXPECTED_FIELDS[RandomTrailers]="${AWG_RANDOM_TRAILERS}"
			EXPECTED_FIELDS[DisableCookies]="${AWG_DISABLE_COOKIES}"
		fi
	elif [[ "${AWG_PROTOCOL_VERSION}" != "${AWG_PROTOCOL_VERSION_2}" ]]; then
		return 2
	fi

	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		if [[ "${LINE}" =~ ^[[:space:]]*(${AWG_PROTOCOL_CONFIG_KEYS})[[:space:]]*=[[:space:]]*(.*)$ ]]; then
			KEY="${BASH_REMATCH[1]}"
			VALUE="$(trimWhitespace "${BASH_REMATCH[2]}")"
			awgProtocolUsesHeaderProtection || return 1
			[[ -n "${EXPECTED_FIELDS[${KEY}]+present}" ]] || return 1
			[[ -z "${SEEN_FIELDS[${KEY}]+present}" ]] || return 1
			[[ "${VALUE}" == "${EXPECTED_FIELDS[${KEY}]}" ]] || return 1
			SEEN_FIELDS["${KEY}"]=1
		fi
	done <"${CONFIG_FILE}"

	for EXPECTED_KEY in "${!EXPECTED_FIELDS[@]}"; do
		[[ -n "${SEEN_FIELDS[${EXPECTED_KEY}]+present}" ]] || return 1
	done
	return 0
}

# Return 0 only when persisted protocol state and every recoverable active
# config agree. Return 1 for a repairable mismatch and 2 when the complete
# active-client set cannot be verified safely.
function awgProtocolConfigsMatchPersistedState() {
	local -a CLIENT_PATHS=()
	local CLIENT_PATH CONFIG_STATE_RC

	case "${AWG_PROTOCOL_VERSION}" in
		"${AWG_PROTOCOL_VERSION_2}")
			# Explicit AWG 2.0 state should not retain dormant secrets or settings.
			if [[ -n "${AWG_HEADER_PROTECTION_KEY:-}${AWG_CONTENT_PADDING_ADDITION:-}${AWG_REKEY_AFTER_TIME:-}${AWG_REKEY_TIMEOUT:-}${AWG_REJECT_AFTER_TIME:-}${AWG_KEEPALIVE_TIMEOUT:-}${AWG_RANDOM_TRAILERS:-}${AWG_DISABLE_COOKIES:-}" ]]; then
				return 1
			fi
			;;
		"${AWG_PROTOCOL_VERSION_3}")
			# AWG 3.0 must not retain dormant 3.1-only settings.
			if [[ -n "${AWG_RANDOM_TRAILERS:-}${AWG_DISABLE_COOKIES:-}" ]]; then
				return 1
			fi
			;;
		"${AWG_PROTOCOL_VERSION_31}") ;;
		*) return 2 ;;
	esac

	collectActiveAwgClientConfigs CLIENT_PATHS || return 2
	if awgProtocolConfigMatchesPersistedState "${SERVER_AWG_CONF}"; then
		:
	else
		CONFIG_STATE_RC=$?
		(( CONFIG_STATE_RC == 2 )) && return 2
		return 1
	fi
	for CLIENT_PATH in "${CLIENT_PATHS[@]}"; do
		if awgProtocolConfigMatchesPersistedState "${CLIENT_PATH}"; then
			:
		else
			CONFIG_STATE_RC=$?
			(( CONFIG_STATE_RC == 2 )) && return 2
			return 1
		fi
	done
	return 0
}

# Validate the interface section of every staged config with both awg-quick and
# the running module. Peer/address data is unchanged by this migration; limiting
# setconf to [Interface] also avoids DNS resolution for hostname endpoints.
function validateStagedAwgConfigs() {
	local WORK_DIR="$1"
	shift
	local -a CONFIG_FILES=("$@")
	local VALIDATE_INTERFACE="awgv$((BASHPID % 100000000))"
	local CONFIG_FILE STRIPPED_FILE INTERFACE_FILE LINE CLEAN PORT
	local INDEX=0 RC=0 INTERFACE_CREATED=0 PORTS

	if ! awgBackendCreateScratchInterface "${VALIDATE_INTERFACE}" >/dev/null 2>&1; then
		echo "ERROR: could not create the temporary AWG configuration-validation interface" >&2
		return 1
	fi
	INTERFACE_CREATED=1

	for CONFIG_FILE in "${CONFIG_FILES[@]}"; do
		INDEX=$((INDEX + 1))
		STRIPPED_FILE="${WORK_DIR}/validate-${INDEX}.stripped"
		INTERFACE_FILE="${WORK_DIR}/validate-${INDEX}.interface"
		if ! awg-quick strip "${CONFIG_FILE}" >"${STRIPPED_FILE}" 2>/dev/null; then
			RC=1
			break
		fi
		: >"${INTERFACE_FILE}"
		PORTS=0
		while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
			[[ "${LINE}" =~ ^[[:space:]]*\[Peer\][[:space:]]*$ ]] && break
			# BoringTun binds ListenPort as soon as it is set, even on a link
			# that is down, so a scratch instance given the running server's
			# staged config would collide with the server's own socket. The
			# port is not a protocol field, so BoringTun validation checks it
			# here instead and omits it: one ListenPort at most, read the way
			# awg reads it (comments dropped, whitespace ignored, any case), a
			# decimal number from 1 to 65535 without leading zeros. This is
			# stricter than awg, which also takes 0 and service names, and it
			# checks the syntax only, not whether the port is free.
			if [[ "${AWG_BACKEND:-}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
				CLEAN="${LINE%%#*}"
				CLEAN="${CLEAN//[[:space:]]/}"
				if [[ "${CLEAN,,}" == listenport=* ]]; then
					PORTS=$((PORTS + 1))
					PORT="${CLEAN#*=}"
					if ((PORTS > 1)) || ! [[ "${PORT}" =~ ^[1-9][0-9]{0,4}$ ]] || ((10#${PORT} > 65535)); then
						echo "ERROR: ${CONFIG_FILE} must set ListenPort at most once, to a port number from 1 to 65535" >&2
						RC=1
						break
					fi
					continue
				fi
			fi
			printf '%s\n' "${LINE}" >>"${INTERFACE_FILE}"
		done <"${STRIPPED_FILE}"
		((RC == 0)) || break
		if ! awg setconf "${VALIDATE_INTERFACE}" "${INTERFACE_FILE}" >/dev/null 2>&1; then
			RC=1
			break
		fi
	done

	if (( INTERFACE_CREATED )) && ! awgBackendDestroyScratchInterface "${VALIDATE_INTERFACE}" >/dev/null 2>&1; then
		RC=1
	fi
	if (( RC != 0 )); then
		echo "ERROR: $(awgBackendValidationText staged)" >&2
		return 1
	fi
}

function replaceAwgProtocolFile() {
	local SOURCE_FILE="$1"
	local DEST_FILE="$2"
	local DEST_DIR TEMP_FILE DEST_MODE
	DEST_DIR="$(dirname -- "${DEST_FILE}")"
	DEST_MODE="$(stat -c '%a' -- "${DEST_FILE}" 2>/dev/null || true)"
	case "${DEST_MODE}" in
		600|640) ;;
		*) DEST_MODE=600 ;;
	esac
	TEMP_FILE="$(mktemp "${DEST_DIR}/.$(basename -- "${DEST_FILE}").protocol.XXXXXX")" || return 1
	if ! cp -p -- "${SOURCE_FILE}" "${TEMP_FILE}" || \
		! chown --reference="${DEST_FILE}" -- "${TEMP_FILE}" || \
		! chmod "${DEST_MODE}" "${TEMP_FILE}" || \
		! mv -f -- "${TEMP_FILE}" "${DEST_FILE}"; then
		rm -f -- "${TEMP_FILE}"
		return 1
	fi
}

function cleanupAwgProtocolTransactionDir() {
	local TRANSACTION_DIR="$1"
	local RESOLVED_DIR RESOLVED_ROOT
	RESOLVED_DIR="$(readlink -f -- "${TRANSACTION_DIR}" 2>/dev/null || true)"
	RESOLVED_ROOT="$(readlink -f -- "${AMNEZIAWG_DIR}" 2>/dev/null || true)"
	if [[ -n "${RESOLVED_DIR}" && -n "${RESOLVED_ROOT}" && ! -L "${TRANSACTION_DIR}" && \
		"${RESOLVED_DIR}" == "${RESOLVED_ROOT}/.awg-protocol."* ]]; then
		rm -rf -- "${RESOLVED_DIR}"
	fi
}

function restoreAwgProtocolTransaction() {
	local SERVER_BACKUP="$1"
	local PARAMS_BACKUP="$2"
	local CLIENT_PATHS_NAME="$3"
	local CLIENT_BACKUPS_NAME="$4"
	local -n CLIENT_PATHS_REF="${CLIENT_PATHS_NAME}"
	local -n CLIENT_BACKUPS_REF="${CLIENT_BACKUPS_NAME}"
	local INDEX RESTORE_FAILED=0

	replaceAwgProtocolFile "${SERVER_BACKUP}" "${SERVER_AWG_CONF}" || RESTORE_FAILED=1
	replaceAwgProtocolFile "${PARAMS_BACKUP}" "${AMNEZIAWG_DIR}/params" || RESTORE_FAILED=1
	for INDEX in "${!CLIENT_PATHS_REF[@]}"; do
		replaceAwgProtocolFile "${CLIENT_BACKUPS_REF[${INDEX}]}" "${CLIENT_PATHS_REF[${INDEX}]}" || RESTORE_FAILED=1
	done
	return "${RESTORE_FAILED}"
}

function applyAwgProtocolTransaction() (
	local TRANSACTION_DIR FIELDS_FILE SERVER_STAGE PARAMS_STAGE SERVER_BACKUP PARAMS_BACKUP
	local -a CLIENT_PATHS=() CLIENT_STAGES=() CLIENT_BACKUPS=() VALIDATION_FILES=()
	local CLIENT_PATH INDEX SERVICE_WAS_ACTIVE=0 MANUAL_INTERFACE_ACTIVE=0 APPLY_FAILED=0
	local TRANSACTION_READY=0 TRANSACTION_APPLY_STARTED=0

	# A config that omits AWG 3.0 fields cannot clear those live attributes via
	# syncconf. Cycle a manually managed interface so the kernel receives a fresh
	# setconf from the selected protocol configuration.
	function restartManualAwgInterface() {
		if ip link show dev "${SERVER_AWG_NIC}" >/dev/null 2>&1; then
			awg-quick down "${SERVER_AWG_CONF}" >/dev/null 2>&1 || true
			if ip link show dev "${SERVER_AWG_NIC}" >/dev/null 2>&1; then
				ip link delete dev "${SERVER_AWG_NIC}" >/dev/null 2>&1 || return 1
			fi
		fi
		awgBackendQuickUp "${SERVER_AWG_CONF}" || return 1
		ip link show dev "${SERVER_AWG_NIC}" >/dev/null 2>&1
	}

	# A file rollback is complete only when the runtime state that existed before
	# the transaction is restored as well. Keep command output private here and
	# let each caller report the transaction directory retained for recovery.
	function restorePreviousAwgRuntime() {
		if (( SERVICE_WAS_ACTIVE )); then
			awgBackendPrepareServiceStart
			systemctl restart "awg-quick@${SERVER_AWG_NIC}" >/dev/null 2>&1 && \
				systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
		elif (( MANUAL_INTERFACE_ACTIVE )); then
			restartManualAwgInterface >/dev/null 2>&1
		else
			return 0
		fi
	}

	function rollbackAwgProtocolOnSignal() {
		local EXIT_CODE="$1"
		local RESTORE_FAILED=0
		trap '' HUP INT TERM
		echo "ERROR: protocol migration interrupted; restoring server and client files" >&2
		if (( TRANSACTION_READY != 0 && TRANSACTION_APPLY_STARTED != 0 )); then
			if ! restoreAwgProtocolTransaction "${SERVER_BACKUP}" "${PARAMS_BACKUP}" \
				CLIENT_PATHS CLIENT_BACKUPS >/dev/null 2>&1; then
				RESTORE_FAILED=1
				echo "ERROR: interrupted rollback was incomplete; recovery files remain in ${TRANSACTION_DIR}" >&2
			fi
			if ! restorePreviousAwgRuntime; then
				RESTORE_FAILED=1
				echo "ERROR: interrupted rollback could not reactivate the previous AWG runtime" >&2
				echo "       Recovery files remain in ${TRANSACTION_DIR}" >&2
			fi
		fi
		if (( RESTORE_FAILED == 0 )) && [[ -n "${TRANSACTION_DIR:-}" ]]; then
			cleanupAwgProtocolTransactionDir "${TRANSACTION_DIR}"
		fi
		exit "${EXIT_CODE}"
	}

	trap 'rollbackAwgProtocolOnSignal 129' HUP
	trap 'rollbackAwgProtocolOnSignal 130' INT
	trap 'rollbackAwgProtocolOnSignal 143' TERM

	TRANSACTION_DIR="$(mktemp -d "${AMNEZIAWG_DIR}/.awg-protocol.XXXXXX")" || {
		echo "ERROR: could not create the AWG protocol transaction directory" >&2
		return 1
	}
	chmod 700 "${TRANSACTION_DIR}"
	FIELDS_FILE="${TRANSACTION_DIR}/protocol-fields"
	# awg-quick requires the input basename to be a valid interface-style
	# `<name>.conf`, even when it is used only for `strip` validation.
	SERVER_STAGE="${TRANSACTION_DIR}/server.conf"
	PARAMS_STAGE="${TRANSACTION_DIR}/params.new"
	SERVER_BACKUP="${TRANSACTION_DIR}/server.backup"
	PARAMS_BACKUP="${TRANSACTION_DIR}/params.backup"

	if ! (umask 077; renderAwgProtocolFields >"${FIELDS_FILE}") || \
		! collectActiveAwgClientConfigs CLIENT_PATHS || \
		! cp -p -- "${SERVER_AWG_CONF}" "${SERVER_BACKUP}" || \
		! cp -p -- "${AMNEZIAWG_DIR}/params" "${PARAMS_BACKUP}" || \
		! rewriteAwgProtocolConfig "${SERVER_AWG_CONF}" "${SERVER_STAGE}" "${FIELDS_FILE}" || \
		! serializeParams "${PARAMS_STAGE}"; then
		cleanupAwgProtocolTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi
	chmod 600 "${FIELDS_FILE}" "${SERVER_BACKUP}" "${PARAMS_BACKUP}" "${SERVER_STAGE}" "${PARAMS_STAGE}"
	VALIDATION_FILES+=("${SERVER_STAGE}")

	for INDEX in "${!CLIENT_PATHS[@]}"; do
		CLIENT_PATH="${CLIENT_PATHS[${INDEX}]}"
		CLIENT_STAGES[${INDEX}]="${TRANSACTION_DIR}/client-${INDEX}.conf"
		CLIENT_BACKUPS[${INDEX}]="${TRANSACTION_DIR}/client-${INDEX}.backup"
		if ! cp -p -- "${CLIENT_PATH}" "${CLIENT_BACKUPS[${INDEX}]}" || \
			! rewriteAwgProtocolConfig "${CLIENT_PATH}" "${CLIENT_STAGES[${INDEX}]}" "${FIELDS_FILE}"; then
			cleanupAwgProtocolTransactionDir "${TRANSACTION_DIR}"
			return 1
		fi
		chown --reference="${CLIENT_PATH}" "${CLIENT_STAGES[${INDEX}]}" 2>/dev/null || true
		chmod 600 "${CLIENT_STAGES[${INDEX}]}" "${CLIENT_BACKUPS[${INDEX}]}"
		VALIDATION_FILES+=("${CLIENT_STAGES[${INDEX}]}")
	done

	if ! validateStagedAwgConfigs "${TRANSACTION_DIR}" "${VALIDATION_FILES[@]}"; then
		cleanupAwgProtocolTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi
	TRANSACTION_READY=1

	if systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
		SERVICE_WAS_ACTIVE=1
	elif ip link show dev "${SERVER_AWG_NIC}" >/dev/null 2>&1; then
		MANUAL_INTERFACE_ACTIVE=1
	fi
	TRANSACTION_APPLY_STARTED=1
	if (( SERVICE_WAS_ACTIVE )) && ! systemctl stop "awg-quick@${SERVER_AWG_NIC}"; then
		echo "ERROR: could not stop the AWG service before protocol migration" >&2
		if ! restorePreviousAwgRuntime; then
			echo "ERROR: the previous AWG service could not be restored; recovery files remain in ${TRANSACTION_DIR}" >&2
			return 1
		fi
		cleanupAwgProtocolTransactionDir "${TRANSACTION_DIR}"
		return 1
	elif (( MANUAL_INTERFACE_ACTIVE )) && ! awg-quick down "${SERVER_AWG_CONF}"; then
		echo "ERROR: could not stop the manually active AWG interface before protocol migration" >&2
		if ! restorePreviousAwgRuntime; then
			echo "ERROR: the previous manually managed AWG interface could not be restored; recovery files remain in ${TRANSACTION_DIR}" >&2
			return 1
		fi
		cleanupAwgProtocolTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi

	if ! replaceAwgProtocolFile "${SERVER_STAGE}" "${SERVER_AWG_CONF}" || \
		! replaceAwgProtocolFile "${PARAMS_STAGE}" "${AMNEZIAWG_DIR}/params"; then
		APPLY_FAILED=1
	fi
	if (( APPLY_FAILED == 0 )); then
		for INDEX in "${!CLIENT_PATHS[@]}"; do
			if ! replaceAwgProtocolFile "${CLIENT_STAGES[${INDEX}]}" "${CLIENT_PATHS[${INDEX}]}"; then
				APPLY_FAILED=1
				break
			fi
		done
	fi

	if (( APPLY_FAILED == 0 && SERVICE_WAS_ACTIVE )); then
		awgBackendPrepareServiceStart
		systemctl restart "awg-quick@${SERVER_AWG_NIC}" || APPLY_FAILED=1
	elif (( APPLY_FAILED == 0 && MANUAL_INTERFACE_ACTIVE )); then
		awgBackendQuickUp "${SERVER_AWG_CONF}" || APPLY_FAILED=1
	fi

	if (( APPLY_FAILED != 0 )); then
		echo "ERROR: protocol migration failed; restoring every server and client file" >&2
		if ! restoreAwgProtocolTransaction "${SERVER_BACKUP}" "${PARAMS_BACKUP}" CLIENT_PATHS CLIENT_BACKUPS; then
			echo "ERROR: automatic rollback was incomplete; recovery files remain in ${TRANSACTION_DIR}" >&2
			return 1
		fi
		if ! restorePreviousAwgRuntime; then
			echo "ERROR: automatic rollback restored files but could not reactivate the previous AWG runtime" >&2
			echo "       Recovery files remain in ${TRANSACTION_DIR}" >&2
			return 1
		fi
		cleanupAwgProtocolTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi

	trap - HUP INT TERM
	cleanupAwgProtocolTransactionDir "${TRANSACTION_DIR}"
	return 0
)

function setAwgProtocolMode() (
	local TARGET_MODE="$1"
	local ORIGINAL_PROTOCOL ORIGINAL_KEY ORIGINAL_CONTENT ORIGINAL_REKEY_AFTER
	local ORIGINAL_REKEY_TIMEOUT ORIGINAL_REJECT ORIGINAL_KEEPALIVE
	local ORIGINAL_TRAILERS ORIGINAL_COOKIES TARGET_LABEL
	local NEW_KEY CONFIG_STATE_RC=0 REPAIRING_SAME_MODE=0

	case "${TARGET_MODE}" in
		2|2.0) TARGET_MODE="${AWG_PROTOCOL_VERSION_2}" ;;
		3|3.0) TARGET_MODE="${AWG_PROTOCOL_VERSION_3}" ;;
		3.1) TARGET_MODE="${AWG_PROTOCOL_VERSION_31}" ;;
		*)
			echo "ERROR: protocol mode must be 2, 3, or 3.1" >&2
			return 1
			;;
	esac
	TARGET_LABEL="$(awgProtocolDisplayName "${TARGET_MODE}")"
	# Params must be read only after this process owns the same lifecycle lock as
	# web-native add/remove operations and other protocol changes. Otherwise a
	# concurrent opposite toggle can make an already-active check use stale state.
	acquireClientLifecycleLock || return 1
	# Neither protocol direction may run the older compatibility migrations
	# before the protocol transaction has captured its complete rollback set.
	# Damaged AWG 3.0-only state remains recoverable only through mode 2.
	if [[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_2}" ]]; then
		loadParams 1 1
	else
		loadParams 0 1
	fi
	normalizeAwgProtocolVersion || return 1
	# BoringTun keeps its protocol imitation across protocol changes. AWG 3.x
	# refuses SIP imitation with long S prefixes and weakens header masking
	# under the others, so say so before anything changes.
	if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" && "${TARGET_MODE}" != "${AWG_PROTOCOL_VERSION_2}" ]]; then
		checkBoringtunImitationProtocolCompat "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${TARGET_MODE}" || return 1
		if [[ -z "${_AWG_BT_IMITATION_WARNED:-}" ]]; then
			printBoringtunImitationWarnings "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}" "${TARGET_MODE}"
		fi
	fi
	if [[ "${AWG_PROTOCOL_VERSION}" == "${TARGET_MODE}" ]]; then
		# A persisted AWG 3.x mode is not enough to prove that the currently
		# installed userspace and running kernel still support it. Kernel/package
		# changes can invalidate a previously successful migration, so every
		# explicit enable request must repeat the complete readback probe without
		# rotating the shared key.
		if [[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_3}" || \
			"${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_31}" ]]; then
			# The capability probe needs only the module. Do not start an
			# intentionally stopped service or collide with a manual interface.
			ensureAwgBackendReady 0 >/dev/null 2>&1 || true
			if [[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_31}" ]]; then
				probeAwg31Capability "${AWG_HEADER_PROTECTION_KEY}" || return 1
				# Same-mode 3.1 can turn RandomTrailers on via params without
				# taking the 2.0/3.0 enablement path that already warns.
				warnIfRandomTrailersSPaddingUnequal
			else
				probeAwg3Capability "${AWG_HEADER_PROTECTION_KEY}" || return 1
			fi
		fi
		if awgProtocolConfigsMatchPersistedState; then
			echo "AmneziaWG protocol mode ${TARGET_LABEL} is already active and consistent."
			return 0
		else
			CONFIG_STATE_RC=$?
		fi
		if (( CONFIG_STATE_RC == 2 )); then
			echo "ERROR: could not verify every active client config before repairing AWG protocol mode ${TARGET_LABEL}" >&2
			return 1
		fi
		REPAIRING_SAME_MODE=1
		echo "WARNING: persisted AWG protocol mode ${TARGET_LABEL} does not match every server/client config; repairing the transaction." >&2
	fi
	if (( REPAIRING_SAME_MODE == 0 )) && \
		[[ "${AWG_PROTOCOL_VERSION}" == "${AWG_PROTOCOL_VERSION_2}" ]] && \
		[[ "${TARGET_MODE}" != "${AWG_PROTOCOL_VERSION_2}" ]] && \
		awg2StateNeedsLegacyMigration; then
		echo "ERROR: this installation needs AWG 2.0 compatibility normalization before AWG 3.x can be enabled." >&2
		echo "Run amneziawg-install.sh interactively, complete any prompted migration, and then retry." >&2
		return 1
	fi
	ORIGINAL_PROTOCOL="${AWG_PROTOCOL_VERSION}"
	ORIGINAL_KEY="${AWG_HEADER_PROTECTION_KEY:-}"
	ORIGINAL_CONTENT="${AWG_CONTENT_PADDING_ADDITION:-}"
	ORIGINAL_REKEY_AFTER="${AWG_REKEY_AFTER_TIME:-}"
	ORIGINAL_REKEY_TIMEOUT="${AWG_REKEY_TIMEOUT:-}"
	ORIGINAL_REJECT="${AWG_REJECT_AFTER_TIME:-}"
	ORIGINAL_KEEPALIVE="${AWG_KEEPALIVE_TIMEOUT:-}"
	ORIGINAL_TRAILERS="${AWG_RANDOM_TRAILERS:-}"
	ORIGINAL_COOKIES="${AWG_DISABLE_COOKIES:-}"

	if (( REPAIRING_SAME_MODE )); then
		# AWG 3.x repairs deliberately retain the existing shared key. AWG 2.0
		# repairs also purge dormant 3.x-only values from persisted params.
		# AWG 3.0 repairs must drop leftover 3.1 fields, or the consistency
		# check keeps failing and every --enable-awg3 repeats the repair.
		[[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_2}" ]] && clearAwg3Params
		[[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_3}" ]] && clearAwg31Params
	elif [[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_31}" ]]; then
		ensureAwgBackendReady 0 >/dev/null 2>&1 || true
		if [[ "${AWG_PROTOCOL_VERSION}" == "${AWG_PROTOCOL_VERSION_2}" ]]; then
			NEW_KEY="$(awg genkey 2>/dev/null)" || NEW_KEY=""
			if ! probeAwg31Capability "${NEW_KEY}"; then
				return 1
			fi
			AWG_HEADER_PROTECTION_KEY="${NEW_KEY}"
			AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
			AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
			AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
			AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
			AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
		else
			# 3.0 -> 3.1 keeps the shared header-protection key.
			if ! probeAwg31Capability "${AWG_HEADER_PROTECTION_KEY}"; then
				return 1
			fi
		fi
		AWG_PROTOCOL_VERSION="${AWG_PROTOCOL_VERSION_31}"
		AWG_RANDOM_TRAILERS="${AWG31_DEFAULT_RANDOM_TRAILERS}"
		AWG_DISABLE_COOKIES="${AWG31_DEFAULT_DISABLE_COOKIES}"
		warnIfRandomTrailersSPaddingUnequal
	elif [[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_3}" ]]; then
		ensureAwgBackendReady 0 >/dev/null 2>&1 || true
		if [[ "${AWG_PROTOCOL_VERSION}" == "${AWG_PROTOCOL_VERSION_2}" ]]; then
			NEW_KEY="$(awg genkey 2>/dev/null)" || NEW_KEY=""
			if ! probeAwg3Capability "${NEW_KEY}"; then
				return 1
			fi
			AWG_HEADER_PROTECTION_KEY="${NEW_KEY}"
			AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
			AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
			AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
			AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
			AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
		else
			# 3.1 -> 3.0 keeps the shared header-protection key and 3.0 timings.
			if ! probeAwg3Capability "${AWG_HEADER_PROTECTION_KEY}"; then
				return 1
			fi
		fi
		AWG_PROTOCOL_VERSION="${AWG_PROTOCOL_VERSION_3}"
		clearAwg31Params
	else
		AWG_PROTOCOL_VERSION="${AWG_PROTOCOL_VERSION_2}"
		clearAwg3Params
	fi

	if ! applyAwgProtocolTransaction; then
		AWG_PROTOCOL_VERSION="${ORIGINAL_PROTOCOL}"
		AWG_HEADER_PROTECTION_KEY="${ORIGINAL_KEY}"
		AWG_CONTENT_PADDING_ADDITION="${ORIGINAL_CONTENT}"
		AWG_REKEY_AFTER_TIME="${ORIGINAL_REKEY_AFTER}"
		AWG_REKEY_TIMEOUT="${ORIGINAL_REKEY_TIMEOUT}"
		AWG_REJECT_AFTER_TIME="${ORIGINAL_REJECT}"
		AWG_KEEPALIVE_TIMEOUT="${ORIGINAL_KEEPALIVE}"
		AWG_RANDOM_TRAILERS="${ORIGINAL_TRAILERS}"
		AWG_DISABLE_COOKIES="${ORIGINAL_COOKIES}"
		return 1
	fi

	if (( REPAIRING_SAME_MODE )); then
		echo "AmneziaWG protocol mode ${TARGET_LABEL} state was repaired successfully."
	else
		echo "AmneziaWG protocol mode ${TARGET_LABEL} is now active."
	fi
	echo "All client configuration files were updated; redistribute them before reconnecting clients."
)

# The imitation a running BoringTun daemon was started with, from its command
# line: sets _AWG_BT_DAEMON_PROTOCOL and _AWG_BT_DAEMON_DOMAIN. A daemon started
# without --imitate-protocol, as earlier installer versions did, imitates none.
function _awgBtDaemonImitation() { # <pid>
	local -a ARGS=()
	local I
	_AWG_BT_DAEMON_PROTOCOL=""
	_AWG_BT_DAEMON_DOMAIN=""
	[[ "${1:-}" =~ ^[1-9][0-9]*$ ]] || return 1
	mapfile -d '' -t ARGS <"${AWG_BT_PROC_DIR}/$1/cmdline" 2>/dev/null || return 1
	((${#ARGS[@]})) || return 1
	_AWG_BT_DAEMON_PROTOCOL=none
	for ((I = 0; I + 1 < ${#ARGS[@]}; I++)); do
		case "${ARGS[I]}" in
			--imitate-protocol) _AWG_BT_DAEMON_PROTOCOL="${ARGS[I + 1]}" ;;
			--imitate-domain) _AWG_BT_DAEMON_DOMAIN="${ARGS[I + 1]}" ;;
		esac
	done
	return 0
}

# The active awg-quick@<if> is served by the verified BoringTun instance its
# start recorded (unit active, MainPID, TUN link, UAPI), listens on the
# persisted port, no amneziawg kernel module is loaded, and the daemon runs the
# given imitation.
function verifyBoringtunImitationServed() { # <protocol> <domain>
	local UNIT="awg-quick@${SERVER_AWG_NIC}.service" PORT=""
	if ! systemctl is-active --quiet "${UNIT}"; then
		echo "ERROR: ${UNIT} is not active." >&2
		return 1
	fi
	_awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}" || return 1
	PORT="$(_awgBtListenPort "${SERVER_AWG_NIC}")" || PORT=""
	if [[ "${PORT}" != "${SERVER_PORT}" ]]; then
		echo "ERROR: ${SERVER_AWG_NIC} listens on port ${PORT:-none}, not on ${SERVER_PORT}." >&2
		return 1
	fi
	if [[ -e "${AWG_BT_SYS_DIR}/module/amneziawg" ]]; then
		echo "ERROR: the amneziawg kernel module is loaded." >&2
		return 1
	fi
	if ! _awgBtDaemonImitation "${_AWG_BT_STATE[PID]:-}" ||
		[[ "${_AWG_BT_DAEMON_PROTOCOL}" != "$1" || "${_AWG_BT_DAEMON_DOMAIN}" != "$2" ]]; then
		echo "ERROR: the BoringTun daemon of ${SERVER_AWG_NIC} does not run protocol imitation $(boringtunImitationDisplay "$1" "$2")." >&2
		return 1
	fi
	return 0
}

# Replace DEST with a copy of SOURCE: the same bytes, SOURCE's owner and the
# given mode, renamed into place so that DEST is never partly written.
function replaceFileExactly() { # <source> <dest> <mode>
	local TEMP_FILE
	TEMP_FILE="$(mktemp "$(dirname -- "$2")/.$(basename -- "$2").imitation.XXXXXX")" || return 1
	if ! cp -p -- "$1" "${TEMP_FILE}" || ! chmod "$3" -- "${TEMP_FILE}" || ! mv -f -- "${TEMP_FILE}" "$2"; then
		rm -f -- "${TEMP_FILE}"
		return 1
	fi
}

function cleanupBoringtunImitationTransactionDir() {
	local RESOLVED_DIR RESOLVED_ROOT
	RESOLVED_DIR="$(readlink -f -- "$1" 2>/dev/null || true)"
	RESOLVED_ROOT="$(readlink -f -- "${AMNEZIAWG_DIR}" 2>/dev/null || true)"
	if [[ -n "${RESOLVED_DIR}" && -n "${RESOLVED_ROOT}" && ! -L "$1" &&
		"${RESOLVED_DIR}" == "${RESOLVED_ROOT}/.awg-imitation."* ]]; then
		rm -rf -- "${RESOLVED_DIR}"
	fi
}

# Refuse an imitation that the installed BoringTun binary cannot run, before
# anything is prepared or changed: auto on a release before wiresock-boringtun
# b94943906b11 would otherwise surface only as a failed restart. The release
# current selects is verified and its binary asked (_awgBtBinaryImitationSupport);
# the version string, which those releases share, decides nothing.
function requireBoringtunImitationSupport() { # <protocol>
	local CURRENT="" PINNED="" RC=0
	[[ "$1" == auto ]] || return 0
	if ! _awgBtVerifyStore; then
		echo "ERROR: the BoringTun store does not verify, so whether its binary supports protocol imitation $1 cannot be checked. Nothing was changed." >&2
		return 1
	fi
	CURRENT="$(readlink -- "${AWG_BT_STORE_DIR}/current" 2>/dev/null)" || CURRENT=""
	_awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "$1"
	RC=$?
	((RC == 0)) && return 0
	if ((RC != 1)); then
		echo "ERROR: could not determine whether the installed BoringTun release ${CURRENT} supports protocol imitation $1: its binary did not answer as a release with or without it does. Nothing was changed." >&2
		return 1
	fi
	_awgBtSelectRelease "$(_awgBtHostArch 2>/dev/null)" && PINNED="${_AWG_BT_REL_ID}"
	if [[ -n "${PINNED}" && "${PINNED}" != "${CURRENT}" ]]; then
		echo "ERROR: the installed BoringTun release ${CURRENT} does not support protocol imitation $1. Run 'amneziawg-install.sh --upgrade-boringtun' to move to ${PINNED}, the release this installer pins, then select $1 again. Nothing was changed." >&2
	else
		echo "ERROR: the installed BoringTun release ${CURRENT} does not support protocol imitation $1, and neither does a release this installer can upgrade it to (--upgrade-boringtun). Nothing was changed." >&2
	fi
	return 1
}

# Change the BoringTun protocol imitation (design §9.3). Under the lifecycle
# lock, with params reloaded: identical values change nothing. The unit's state
# decides the rest before any file changes: active applies the change with a
# restart and verifies it, inactive or failed only persists it for the next
# start, and any other state (activating, deactivating, reloading, unknown)
# aborts. The helpers are regenerated before the runtime file gains keys that
# an older launcher would refuse. Params and the runtime file are rendered into
# a private transaction directory and checked: the runtime file with the
# launcher's own parser, params by reading them back, and the server config on
# a scratch BoringTun instance that runs the new imitation. Both files are
# backed up byte for byte with their modes and then replaced atomically. A
# failure, or HUP, INT or TERM, after that restores both files exactly and, if
# the unit was active, restarts it on the previous imitation; every step that
# fails is reported. Client configs never change.
function setBoringtunImitation() ( # <protocol> [<domain> [warned]]
	local PROTOCOL="${1-}" DOMAIN="${2-}" WARNED="${3:-0}"
	local UNIT STATE ACTIVE=0 OLD_PROTOCOL OLD_DOMAIN TRANSACTION_DIR=""
	local PARAMS_FILE RUNTIME_FILE PARAMS_STAGE RUNTIME_STAGE PARAMS_BACKUP RUNTIME_BACKUP
	local PARAMS_MODE RUNTIME_MODE="" RUNTIME_EXISTED=0 APPLY_STARTED=0 CURRENT_STATE STAGED_STATE

	if ! _awgBtImitationCheck "${PROTOCOL}" "${DOMAIN}"; then
		echo "Usage: amneziawg-install.sh --set-boringtun-imitation <none|dns|quic|sip|stun|auto> [hostname]" >&2
		return 1
	fi
	acquireClientLifecycleLock || return 1
	loadParams 0 1
	if [[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]]; then
		echo "ERROR: protocol imitation is available only with the BoringTun backend; this installation uses the ${AWG_BACKEND} backend. Nothing was changed." >&2
		return 1
	fi
	normalizeAwgProtocolVersion || return 1
	OLD_PROTOCOL="${AWG_BORINGTUN_IMITATE_PROTOCOL}"
	OLD_DOMAIN="${AWG_BORINGTUN_IMITATE_DOMAIN}"
	if [[ "${PROTOCOL}" == "${OLD_PROTOCOL}" && "${DOMAIN}" == "${OLD_DOMAIN}" ]]; then
		echo "BoringTun protocol imitation is already $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}"); nothing was changed."
		return 0
	fi
	checkBoringtunImitationProtocolCompat "${PROTOCOL}" "${AWG_PROTOCOL_VERSION}" || return 1
	requireBoringtunImitationSupport "${PROTOCOL}" || return 1

	UNIT="awg-quick@${SERVER_AWG_NIC}.service"
	STATE="$(systemctl show -p ActiveState --value "${UNIT}" 2>/dev/null)" || STATE=""
	case "${STATE}" in
		active) ACTIVE=1 ;;
		inactive | failed) ;;
		*)
			echo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2
			return 1
			;;
	esac
	((WARNED)) || printBoringtunImitationWarnings "${PROTOCOL}" "${DOMAIN}" "${AWG_PROTOCOL_VERSION}"

	# The store, the platform and the helpers. This exits the subshell on
	# failure, before anything is changed.
	_awgBtEnsureReady 0
	if ((ACTIVE)) && ! _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}"; then
		echo "ERROR: ${UNIT} is active but not served by the verified BoringTun instance recorded for it; nothing was changed." >&2
		return 1
	fi

	PARAMS_FILE="${AMNEZIAWG_DIR}/params"
	RUNTIME_FILE="$(_awgBtRuntimeFilePath "${SERVER_AWG_NIC}")"
	PARAMS_MODE="$(stat -c '%a' -- "${PARAMS_FILE}" 2>/dev/null)" || PARAMS_MODE=""
	if [[ -L "${RUNTIME_FILE}" ]] || { [[ -e "${RUNTIME_FILE}" ]] && [[ ! -f "${RUNTIME_FILE}" ]]; }; then
		echo "ERROR: ${RUNTIME_FILE} is not a regular file; nothing was changed." >&2
		return 1
	fi
	if [[ -f "${RUNTIME_FILE}" ]]; then
		RUNTIME_EXISTED=1
		RUNTIME_MODE="$(stat -c '%a' -- "${RUNTIME_FILE}" 2>/dev/null)" || RUNTIME_MODE=""
	fi
	if [[ -z "${PARAMS_MODE}" ]] || { ((RUNTIME_EXISTED)) && [[ -z "${RUNTIME_MODE}" ]]; }; then
		echo "ERROR: cannot read the modes of ${PARAMS_FILE} and ${RUNTIME_FILE}; nothing was changed." >&2
		return 1
	fi

	function restoreBoringtunImitationFiles() {
		local FAILED=0
		if ((RUNTIME_EXISTED)); then
			replaceFileExactly "${RUNTIME_BACKUP}" "${RUNTIME_FILE}" "${RUNTIME_MODE}" || FAILED=1
		else
			rm -f -- "${RUNTIME_FILE}" || FAILED=1
		fi
		replaceFileExactly "${PARAMS_BACKUP}" "${PARAMS_FILE}" "${PARAMS_MODE}" || FAILED=1
		AWG_BORINGTUN_IMITATE_PROTOCOL="${OLD_PROTOCOL}"
		AWG_BORINGTUN_IMITATE_DOMAIN="${OLD_DOMAIN}"
		if ((FAILED)); then
			echo "ERROR: ${PARAMS_FILE} and ${RUNTIME_FILE} could not both be restored." >&2
		fi
		return "${FAILED}"
	}

	function restoreBoringtunImitationRuntime() {
		((ACTIVE)) || return 0
		awgBackendPrepareServiceStart
		if ! systemctl restart "${UNIT}" || ! verifyBoringtunImitationServed "${OLD_PROTOCOL}" "${OLD_DOMAIN}"; then
			echo "ERROR: ${UNIT} could not be restarted on the previous protocol imitation $(boringtunImitationDisplay "${OLD_PROTOCOL}" "${OLD_DOMAIN}"). Check: journalctl -u ${UNIT}" >&2
			return 1
		fi
	}

	function rollbackBoringtunImitation() {
		local FAILED=0
		restoreBoringtunImitationFiles || FAILED=1
		# A restart on files that could not be restored would run neither
		# configuration, so the unit is left to the operator then.
		if ((FAILED == 0)) && ! restoreBoringtunImitationRuntime; then
			FAILED=1
		fi
		if ((FAILED == 0)); then
			echo "The previous protocol imitation $(boringtunImitationDisplay "${OLD_PROTOCOL}" "${OLD_DOMAIN}") was restored." >&2
			cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
		else
			echo "ERROR: the rollback is incomplete; recovery files remain in ${TRANSACTION_DIR}" >&2
		fi
		return "${FAILED}"
	}

	function rollbackBoringtunImitationOnSignal() {
		trap '' HUP INT TERM
		echo "ERROR: the protocol imitation change was interrupted." >&2
		if ((APPLY_STARTED)); then
			rollbackBoringtunImitation
		elif [[ -n "${TRANSACTION_DIR}" ]]; then
			cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
		fi
		exit "$1"
	}

	trap 'rollbackBoringtunImitationOnSignal 129' HUP
	trap 'rollbackBoringtunImitationOnSignal 130' INT
	trap 'rollbackBoringtunImitationOnSignal 143' TERM

	TRANSACTION_DIR="$(mktemp -d "${AMNEZIAWG_DIR}/.awg-imitation.XXXXXX")" || {
		TRANSACTION_DIR=""
		echo "ERROR: could not create the protocol imitation transaction directory; nothing was changed." >&2
		return 1
	}
	chmod 700 -- "${TRANSACTION_DIR}"
	PARAMS_STAGE="${TRANSACTION_DIR}/params.new"
	PARAMS_BACKUP="${TRANSACTION_DIR}/params.backup"
	RUNTIME_STAGE="${TRANSACTION_DIR}/${SERVER_AWG_NIC}.boringtun"
	RUNTIME_BACKUP="${TRANSACTION_DIR}/runtime.backup"

	# The loaded state, without the imitation: the staged params must read
	# back as exactly this plus the requested imitation.
	CURRENT_STATE="$(awgParamsStateDigest)"
	AWG_BORINGTUN_IMITATE_PROTOCOL="${PROTOCOL}"
	AWG_BORINGTUN_IMITATE_DOMAIN="${DOMAIN}"
	if ! cp -p -- "${PARAMS_FILE}" "${PARAMS_BACKUP}" ||
		{ ((RUNTIME_EXISTED)) && ! cp -p -- "${RUNTIME_FILE}" "${RUNTIME_BACKUP}"; } ||
		! serializeParams "${PARAMS_STAGE}" ||
		! (umask 077 && _awgBtRenderRuntimeFile >"${RUNTIME_STAGE}") ||
		! chmod 600 -- "${RUNTIME_STAGE}"; then
		echo "ERROR: could not stage the protocol imitation change; nothing was changed." >&2
		cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi
	# The staged runtime file must read back, through the launcher's parser, as
	# exactly the requested imitation.
	if ! (
		AWG_BT_CONFIG_DIR="${TRANSACTION_DIR}"
		_awgBtReadRuntimeFile "${SERVER_AWG_NIC}" &&
			[[ "${_AWG_BT_IMITATE_PROTOCOL}" == "${PROTOCOL}" && "${_AWG_BT_IMITATE_DOMAIN}" == "${DOMAIN}" ]]
	); then
		echo "ERROR: the staged runtime file does not read back as $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}"); nothing was changed." >&2
		cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi
	# The staged params must be a complete canonical BoringTun params file
	# that loads on its own, and must read back as the current state with only
	# the imitation changed.
	if ! awgParamsFileHasCanonicalKeys "${PARAMS_STAGE}" "${AWG_BACKEND_BORINGTUN}"; then
		echo "ERROR: the staged params are not a complete params file; nothing was changed." >&2
		cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi
	if ! STAGED_STATE="$(readStagedParamsInIsolation "${PARAMS_STAGE}" "${TRANSACTION_DIR}/check")"; then
		echo "ERROR: the staged params do not load on their own; nothing was changed." >&2
		cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi
	if [[ "${STAGED_STATE}" != "${CURRENT_STATE}|${PROTOCOL}|${DOMAIN}" ]]; then
		echo "ERROR: the staged params differ from the current ones in more than the protocol imitation; nothing was changed." >&2
		cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi
	if ! validateStagedAwgConfigs "${TRANSACTION_DIR}" "${SERVER_AWG_CONF}"; then
		echo "ERROR: BoringTun does not accept the server configuration with protocol imitation $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}"); nothing was changed." >&2
		cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
		return 1
	fi

	APPLY_STARTED=1
	if ! _awgBtWriteManagedFile "${RUNTIME_FILE}" 0600 <"${RUNTIME_STAGE}" ||
		! replaceFileExactly "${PARAMS_STAGE}" "${PARAMS_FILE}" "${PARAMS_MODE}"; then
		echo "ERROR: could not write the new protocol imitation; restoring the previous files." >&2
		rollbackBoringtunImitation
		return 1
	fi
	if ((ACTIVE)); then
		awgBackendPrepareServiceStart
		if ! systemctl restart "${UNIT}" || ! verifyBoringtunImitationServed "${PROTOCOL}" "${DOMAIN}"; then
			echo "ERROR: ${UNIT} did not come back on protocol imitation $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}"); restoring the previous one." >&2
			rollbackBoringtunImitation
			return 1
		fi
	fi
	trap - HUP INT TERM
	cleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"
	if ((ACTIVE)); then
		echo "BoringTun protocol imitation is now $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}"); ${UNIT} was restarted with it."
	else
		echo "BoringTun protocol imitation is now $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}"). ${UNIT} is ${STATE} and was not started; the imitation applies at its next start."
	fi
	echo "Client configs are unchanged."
	return 0
)

# Menu option: ask for the imitation, show its trade-offs, confirm enabling one
# under AWG 3.x, then run the transaction, which reloads params under the lock.
function changeBoringtunImitationInteractively() {
	local -a PROTOCOLS=(none dns quic sip stun auto)
	local CHOICE="" DEFAULT=1 I PROTOCOL DOMAIN="" RESPONSE
	normalizeAwgProtocolVersion || return 1
	echo "Current BoringTun protocol imitation: $(boringtunImitationDisplay "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}")"
	echo ""
	for I in "${!PROTOCOLS[@]}"; do
		[[ "${PROTOCOLS[I]}" == "${AWG_BORINGTUN_IMITATE_PROTOCOL}" ]] && DEFAULT=$((I + 1))
	done
	echo "Protocol imitation:"
	echo "   1) none"
	echo "   2) dns"
	echo "   3) quic"
	echo "   4) sip"
	echo "   5) stun"
	echo "   6) auto (dns, quic, sip or stun chosen per authenticated peer from its client's traffic)"
	until [[ "${CHOICE}" =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " -e -i "${DEFAULT}" CHOICE
	done
	PROTOCOL="${PROTOCOLS[CHOICE - 1]}"
	if _awgBtImitationUsesDomain "${PROTOCOL}"; then
		[[ "${PROTOCOL}" != "${AWG_BORINGTUN_IMITATE_PROTOCOL}" ]] || DOMAIN="${AWG_BORINGTUN_IMITATE_DOMAIN}"
		while true; do
			read -rp "Imitation hostname (optional; empty lets BoringTun choose): " -e -i "${DOMAIN}" DOMAIN
			if [[ -z "${DOMAIN}" ]] || _awgBtImitationDomainValid "${DOMAIN}"; then
				break
			fi
			echo "Use at most 253 characters of dot-separated labels of 1-63 ASCII letters, digits and hyphens, none starting or ending with a hyphen."
		done
	fi
	if [[ "${PROTOCOL}" == "${AWG_BORINGTUN_IMITATE_PROTOCOL}" && "${DOMAIN}" == "${AWG_BORINGTUN_IMITATE_DOMAIN}" ]]; then
		echo "Protocol imitation unchanged."
		return 0
	fi
	checkBoringtunImitationProtocolCompat "${PROTOCOL}" "${AWG_PROTOCOL_VERSION}" || return 1
	printBoringtunImitationWarnings "${PROTOCOL}" "${DOMAIN}" "${AWG_PROTOCOL_VERSION}"
	if [[ "${PROTOCOL}" != "${AWG_BT_IMITATE_NONE}" ]] && awgProtocolUsesHeaderProtection; then
		read -rp "Enable ${PROTOCOL} imitation under AWG $(awgProtocolDisplayName "${AWG_PROTOCOL_VERSION}")? [y/N]: " RESPONSE
		[[ "${RESPONSE}" == [Yy] ]] || {
			echo "Protocol imitation change cancelled."
			return 0
		}
	fi
	setBoringtunImitation "${PROTOCOL}" "${DOMAIN}" 1
}

# --backend-status: a read-only key=value report of the installation's backend.
# Every backend prints backend, awg_protocol and service_state; BoringTun adds
# its imitation, the installed and pinned releases and its daemon; the kernel
# backend adds module_state. No keys or other secrets are printed. It exits 0
# for a valid installation and 1 when params or the BoringTun store cannot be
# used. It changes nothing: params with an insecure mode are refused here, not
# repaired as the management commands repair them.
function printBackendStatus() {
	local PARAMS_FILE="${AMNEZIAWG_DIR}/params" OWNER MODE UNIT STATE RC=0
	local INSTALLED=none PINNED="" DAEMON_STATE=stopped DAEMON_PID=""
	local PREVIOUS=none ROLLBACK=no UPGRADE=no DAEMON_RELEASE=none AUTO_SUPPORT=unknown
	if [[ -L "${PARAMS_FILE}" || ! -f "${PARAMS_FILE}" ]]; then
		echo "ERROR: ${PARAMS_FILE} is missing or not a regular file." >&2
		return 1
	fi
	OWNER="$(stat -c '%u' -- "${PARAMS_FILE}" 2>/dev/null)" || OWNER=""
	MODE="$(stat -c '%a' -- "${PARAMS_FILE}" 2>/dev/null)" || MODE=""
	if [[ "${OWNER}" != 0 ]] || [[ "${MODE}" != 600 && "${MODE}" != 400 ]]; then
		echo "ERROR: ${PARAMS_FILE} must be owned by root with mode 600 or 400; --backend-status does not repair it." >&2
		return 1
	fi
	if ! validateParamsFile 0 >/dev/null || ! normalizeAwgProtocolVersion >/dev/null; then
		echo "ERROR: ${PARAMS_FILE} does not describe a valid installation." >&2
		return 1
	fi
	UNIT="awg-quick@${SERVER_AWG_NIC}.service"
	STATE="$(systemctl show -p ActiveState --value "${UNIT}" 2>/dev/null)" || STATE=""
	[[ "${STATE}" =~ ^[a-z-]+$ ]] || STATE=unknown
	printf 'backend=%s\n' "${AWG_BACKEND}"
	printf 'awg_protocol=%s\n' "$(awgProtocolDisplayName "${AWG_PROTOCOL_VERSION}")"
	printf 'service_state=%s\n' "${STATE}"
	if [[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]]; then
		if [[ -e "${AWG_BT_SYS_DIR}/module/amneziawg" ]]; then
			printf 'module_state=loaded\n'
		else
			printf 'module_state=not-loaded\n'
		fi
		return 0
	fi
	printf 'imitation_protocol=%s\n' "${AWG_BORINGTUN_IMITATE_PROTOCOL}"
	printf 'imitation_domain=%s\n' "${AWG_BORINGTUN_IMITATE_DOMAIN}"
	printf 'imitation_domain_mode=%s\n' "$(boringtunImitationDomainMode "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}")"
	if _awgBtSelectRelease "$(_awgBtHostArch 2>/dev/null)"; then
		PINNED="${_AWG_BT_REL_ID}"
	fi
	if _awgBtVerifyStore 2>/dev/null; then
		INSTALLED="$(readlink -- "${AWG_BT_STORE_DIR}/current")"
		# Whether the installed binary runs auto: its own answer, since the
		# releases before it report the same version.
		_awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" auto
		case $? in
			0) AUTO_SUPPORT=supported ;;
			1) AUTO_SUPPORT=unsupported ;;
		esac
	else
		[[ ! -e "${AWG_BT_STORE_DIR}" && ! -L "${AWG_BT_STORE_DIR}" ]] || INSTALLED=invalid
		RC=1
	fi
	_AWG_BT_DAEMON_PROTOCOL=""
	_AWG_BT_DAEMON_DOMAIN=""
	if [[ "${STATE}" == active ]]; then
		if ((RC == 0)) && _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}" 2>/dev/null; then
			DAEMON_STATE=running
			DAEMON_PID="${_AWG_BT_STATE[PID]:-}"
			_awgBtDaemonImitation "${DAEMON_PID}" || true
		else
			DAEMON_STATE=unverified
		fi
	fi
	printf 'installed_release=%s\n' "${INSTALLED}"
	printf 'pinned_release=%s\n' "${PINNED}"
	printf 'daemon_state=%s\n' "${DAEMON_STATE}"
	printf 'daemon_pid=%s\n' "${DAEMON_PID}"
	printf 'daemon_imitation_protocol=%s\n' "${_AWG_BT_DAEMON_PROTOCOL}"
	printf 'daemon_imitation_domain=%s\n' "${_AWG_BT_DAEMON_DOMAIN}"
	# The binary lifecycle (PR 6): the rollback target, whether a rollback or
	# an upgrade to this installer's pin is possible, the release the running
	# daemon executes, and store releases that neither link names.
	_awgBtReadStoreLink previous 2>/dev/null
	case $? in
		0)
			PREVIOUS="${_AWG_BT_LINK_TARGET}"
			if [[ "${PREVIOUS}" == "${INSTALLED}" ]] || ! _awgBtVerifyRelease "${PREVIOUS}" 2>/dev/null; then
				PREVIOUS=invalid
				RC=1
			fi
			;;
		2) PREVIOUS=none ;;
		*)
			PREVIOUS=invalid
			RC=1
			;;
	esac
	[[ "${PREVIOUS}" != none && "${PREVIOUS}" != invalid && "${INSTALLED}" != invalid && "${INSTALLED}" != none ]] && ROLLBACK=yes
	# A rollback refuses a previous binary that cannot run the persisted
	# imitation (auto on an earlier release), so it is not offered then.
	if [[ "${ROLLBACK}" == yes ]] && ! _awgBtReleaseImitationSupport "${PREVIOUS}" "${AWG_BORINGTUN_IMITATE_PROTOCOL}"; then
		ROLLBACK=no
	fi
	[[ "${INSTALLED}" != invalid && "${INSTALLED}" != none && -n "${PINNED}" && "${INSTALLED}" != "${PINNED}" ]] && UPGRADE=yes
	if [[ "${STATE}" == active ]]; then
		[[ -n "${DAEMON_PID}" ]] || DAEMON_PID="$(systemctl show -p MainPID --value "${UNIT}" 2>/dev/null)" || DAEMON_PID=""
		DAEMON_RELEASE=unknown
		[[ ! "${DAEMON_PID}" =~ ^[1-9][0-9]*$ ]] || DAEMON_RELEASE="$(_awgBtDaemonRelease "${DAEMON_PID}")"
	fi
	printf 'previous_release=%s\n' "${PREVIOUS}"
	printf 'rollback_available=%s\n' "${ROLLBACK}"
	printf 'upgrade_available=%s\n' "${UPGRADE}"
	printf 'daemon_release=%s\n' "${DAEMON_RELEASE}"
	printf 'unmanaged_releases=%s\n' "$(_awgBtUnmanagedReleases | grep -c .)"
	# Whether the installed binary runs the imitation mode auto: supported,
	# unsupported, or unknown (also when the store does not verify). It
	# describes the binary only; BoringTun does not report what each peer
	# learned under auto.
	printf 'imitation_auto_support=%s\n' "${AUTO_SUPPORT}"
	return "${RC}"
}

# ── BoringTun binary lifecycle ───────────────────────────────────────────────
# The store keeps at most two managed releases, each named by a root-owned
# relative link: current, which the service runs, and previous, the rollback
# target. Nothing switches the binary implicitly: only --upgrade-boringtun
# moves current to the release pinned by this installer, and only
# --rollback-boringtun moves it to previous. Both validate the target binary
# against this installation's settings on scratch instances before current
# changes, write previous first and current second, and restore both links
# exactly (and the service, if it was active) when activation fails.

# The release a running BoringTun process executes: its store directory, from
# its verified executable path, or "unknown".
function _awgBtDaemonRelease() { # <pid>
	local EXE="" CANONICAL_STORE="" ID=""
	EXE="$(readlink -- "${AWG_BT_PROC_DIR}/$1/exe" 2>/dev/null)" || EXE=""
	CANONICAL_STORE="$(readlink -f -- "${AWG_BT_STORE_DIR}" 2>/dev/null)" || CANONICAL_STORE=""
	ID="${EXE#"${CANONICAL_STORE}"/}"
	ID="${ID%/boringtun-cli}"
	if [[ -n "${CANONICAL_STORE}" && "${EXE}" == "${CANONICAL_STORE}/${ID}/boringtun-cli" ]] && _awgBtReleaseIdValid "${ID}"; then
		printf '%s\n' "${ID}"
	else
		printf 'unknown\n'
	fi
}

# Release directories in the store that neither current nor previous names:
# left by an interrupted transaction or by hand. They are reported, never used
# and never removed automatically.
function _awgBtUnmanagedReleases() {
	local ENTRY NAME CURRENT_ID="" PREVIOUS_ID=""
	_awgBtReadStoreLink current 2>/dev/null && CURRENT_ID="${_AWG_BT_LINK_TARGET}"
	_awgBtReadStoreLink previous 2>/dev/null && PREVIOUS_ID="${_AWG_BT_LINK_TARGET}"
	for ENTRY in "${AWG_BT_STORE_DIR}"/*; do
		NAME="${ENTRY##*/}"
		_awgBtReleaseIdValid "${NAME}" || continue
		[[ "${NAME}" != "${CURRENT_ID}" && "${NAME}" != "${PREVIOUS_ID}" ]] && printf '%s\n' "${NAME}"
	done
	return 0
}

# Remove a release directory of the store that neither link names: only a
# valid release name, a real directory directly in the trusted store, never a
# symlink and never the target of current or previous (re-read here).
function _awgBtPruneRelease() { # <release id>
	local ID="$1" DIR="${AWG_BT_STORE_DIR}/$1" LINK RC CANONICAL_STORE CANONICAL_DIR
	_awgBtReleaseIdValid "${ID}" || return 1
	for LINK in current previous; do
		_awgBtReadStoreLink "${LINK}" 2>/dev/null
		RC=$?
		((RC == 2)) && continue
		((RC == 0)) && [[ "${_AWG_BT_LINK_TARGET}" != "${ID}" ]] || return 1
	done
	CANONICAL_STORE="$(readlink -f -- "${AWG_BT_STORE_DIR}" 2>/dev/null)" || return 1
	CANONICAL_DIR="$(readlink -f -- "${DIR}" 2>/dev/null)" || return 1
	[[ -d "${DIR}" && ! -L "${DIR}" && "${CANONICAL_DIR}" == "${CANONICAL_STORE}/${ID}" ]] &&
		_awgBtTrustedAncestors "${DIR}" && _awgBtTrustedNode "${DIR}" dir || return 1
	rm -rf -- "${DIR}"
}

# The SHA-256 of every file a binary switch must leave as it is: params, the
# server config, the runtime file and every active client config. Compared,
# never printed. Fails when the client set cannot be read or any of the files
# cannot be hashed, so a missing or unreadable file never shortens both
# snapshots alike.
function _awgBtLifecycleConfigHashes() {
	local -a CLIENTS=() FILES=()
	collectActiveAwgClientConfigs CLIENTS >/dev/null 2>&1 || return 1
	FILES=("${AMNEZIAWG_DIR}/params" "${SERVER_AWG_CONF}" "$(_awgBtRuntimeFilePath "${SERVER_AWG_NIC}")" "${CLIENTS[@]}")
	if ! sha256sum -- "${FILES[@]}" 2>/dev/null; then
		return 1
	fi
}

# The generated helpers that start and stop the service must accept every
# release name this installer may select: builds from 2 on are named
# -b<build>, which the helpers of earlier installer versions refuse. So an
# explicit lifecycle operation regenerates them from this installer
# (_awgBtInstallHelpers) before current can change or the service restarts,
# and also when current already is the pinned release, whatever the service's
# state, so that its next start can run what current selects. They are
# derived files and are not put back when an activation fails: they accept
# the earlier release names as well.
function _awgBtReconcileLifecycleHelpers() {
	if ! _awgBtInstallHelpers; then
		echo "ERROR: could not update the BoringTun helpers in ${AWG_BT_LIBEXEC_DIR}; current, previous and the service were not changed." >&2
		return 1
	fi
}

# Prove, before a release may become current, that its binary accepts this
# installation as it is: scratch instances of that release (never the one
# current selects) with the persisted imitation run the capability probe of
# the persisted AWG protocol (3.0 or 3.1) and the staged validation of the
# server config and of every active client config (private copies, so that
# awg-quick strip accepts their names). Nothing is rewritten.
function _awgBtValidateReleaseCandidate() { # <release id> <private work dir>
	local RELEASE="$1" WORK="$2" RC=0 INDEX=0 CLIENT
	local -a CLIENTS=() FILES=("${SERVER_AWG_CONF}")
	_AWG_BT_CANDIDATE_RELEASE="${RELEASE}"
	case "${AWG_PROTOCOL_VERSION}" in
		"${AWG_PROTOCOL_VERSION_3}") probeAwg3Capability "${AWG_HEADER_PROTECTION_KEY}" || RC=1 ;;
		"${AWG_PROTOCOL_VERSION_31}") probeAwg31Capability "${AWG_HEADER_PROTECTION_KEY}" || RC=1 ;;
	esac
	if ((RC == 0)) && ! collectActiveAwgClientConfigs CLIENTS; then
		RC=1
	fi
	if ((RC == 0)); then
		for CLIENT in "${CLIENTS[@]}"; do
			INDEX=$((INDEX + 1))
			if ! (umask 077 && cp -- "${CLIENT}" "${WORK}/client-${INDEX}.conf"); then
				RC=1
				break
			fi
			FILES+=("${WORK}/client-${INDEX}.conf")
		done
	fi
	if ((RC == 0)) && ! validateStagedAwgConfigs "${WORK}" "${FILES[@]}"; then
		RC=1
	fi
	_AWG_BT_CANDIDATE_RELEASE=""
	return "${RC}"
}

# Whether store release RELEASE ID, verified, runs protocol imitation PROTOCOL
# (_awgBtBinaryImitationSupport's 0, 1 or 2); a release that does not verify
# is 2. Sets _AWG_BT_VERIFIED_BIN, as _awgBtVerifyRelease does.
function _awgBtReleaseImitationSupport() { # <release id> <protocol>
	[[ "$2" == auto ]] || return 0
	_awgBtVerifyRelease "$1" 2>/dev/null || return 2
	_awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "$2"
}

# Refuse a lifecycle target whose binary cannot run the persisted imitation,
# before it can become current: a binary that refuses auto would otherwise
# fail only in the scratch validation or, worse, at the restart. The way out
# is a fixed imitation or none first, which every release runs. A target that
# does not verify is left to the candidate verification, which refuses it and
# says why.
function _awgBtLifecycleTargetRunsImitation() { # <upgrade|rollback> <target> <current>
	local RC=0
	[[ "${AWG_BORINGTUN_IMITATE_PROTOCOL}" == auto ]] || return 0
	_awgBtVerifyRelease "$2" 2>/dev/null || return 0
	_awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "${AWG_BORINGTUN_IMITATE_PROTOCOL}"
	RC=$?
	((RC == 0)) && return 0
	if ((RC == 1)); then
		echo "ERROR: $2 does not support the configured protocol imitation ${AWG_BORINGTUN_IMITATE_PROTOCOL}, so it cannot become current. Select a fixed imitation or none first (amneziawg-install.sh --set-boringtun-imitation <none|dns|quic|sip|stun> [hostname]), then run --$1-boringtun again; current is still $3." >&2
	else
		echo "ERROR: could not determine whether $2 supports the configured protocol imitation ${AWG_BORINGTUN_IMITATE_PROTOCOL}; current is still $3." >&2
	fi
	return 1
}

# The interface's peers are the server config's peers.
function _awgBtInterfaceCarriesServerPeers() {
	local LIVE CONFIGURED
	LIVE="$(awg show "${SERVER_AWG_NIC}" peers 2>/dev/null)" || return 1
	CONFIGURED="$(sed -n 's/^[[:space:]]*PublicKey[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' "${SERVER_AWG_CONF}")"
	[[ "$(LC_ALL=C sort <<<"${LIVE}")" == "$(LC_ALL=C sort <<<"${CONFIGURED}")" ]]
}

# The restarted service runs the release current selects, verified as PR 5's
# imitation change verifies it (unit active, MainPID the recorded verified
# binary of current, TUN link, UAPI, listen port, no kernel module, the
# persisted imitation on its command line), and carries the server's peers.
function _awgBtVerifyLifecycleActivation() {
	verifyBoringtunImitationServed "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}" || return 1
	if ! _awgBtInterfaceCarriesServerPeers; then
		echo "ERROR: ${SERVER_AWG_NIC} does not carry the peers of ${SERVER_AWG_CONF}." >&2
		return 1
	fi
}

# --upgrade-boringtun and --rollback-boringtun, one transaction in a subshell:
#  1. under the lifecycle lock, params read without migrations; BoringTun only;
#  2. current must verify, and previous, when present, must be a valid link;
#     the unit's ActiveState decides: active is switched and restarted,
#     inactive and failed are switched and left stopped, anything else (or a
#     state that cannot be read) aborts before any change;
#  3. the target: for an upgrade the release this installer pins (when
#     current already is it, only the helpers are reconciled and a previous
#     that names current is dropped, the service keeps its state, and an
#     active service still running another binary is restarted onto it),
#     downloaded and stored beside current if absent; for a rollback the
#     release previous names;
#  4. the target is verified as a store release, then validated against this
#     installation on scratch instances (_awgBtValidateReleaseCandidate), and
#     params, the server config, the runtime file and every active client
#     config must hash as before;
#  5. previous := current, then current := target, each atomically, so current
#     never names a release that has not passed step 4;
#  6. an active unit is restarted and verified (_awgBtVerifyLifecycleActivation);
#  7. on success the old previous release is removed unless a link names it,
#     so at most two managed releases remain;
#  8. a failure or HUP, INT or TERM after step 5 began restores both links
#     exactly and, if the unit was active, restarts and verifies the original
#     release; a release this transaction stored is removed. Every failing
#     step is reported on its own.
function boringtunBinaryLifecycle() ( # <upgrade|rollback>
	local MODE="$1" ARCH UNIT STATE ACTIVE=0 CURRENT_ID PREVIOUS_ID="" PREVIOUS_EXISTED=0 LINK_RC
	local TARGET CREATED=0 WORK="" SWITCHED=0 RESTARTED=0 REPAIRED=0 HASHES_BEFORE="" HASHES_AFTER="" UNMANAGED
	case "${MODE}" in
		upgrade | rollback) ;;
		*) return 1 ;;
	esac
	acquireClientLifecycleLock || return 1
	loadParams 0 1
	if [[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]]; then
		echo "ERROR: --${MODE}-boringtun applies only to the BoringTun backend; this installation uses the ${AWG_BACKEND} backend. Nothing was changed." >&2
		return 1
	fi
	normalizeAwgProtocolVersion || return 1
	if ! ARCH="$(_awgBtHostArch)" || ! _awgBtSelectRelease "${ARCH}"; then
		echo "ERROR: BoringTun releases exist only for x86_64 and aarch64 hosts." >&2
		return 1
	fi
	if ! _awgBtReadStoreLink current || ! _awgBtVerifyStore; then
		echo "ERROR: the release ${AWG_BT_STORE_DIR}/current selects does not verify; nothing was changed." >&2
		return 1
	fi
	CURRENT_ID="${_AWG_BT_LINK_TARGET}"
	_awgBtReadStoreLink previous
	LINK_RC=$?
	case "${LINK_RC}" in
		0)
			PREVIOUS_ID="${_AWG_BT_LINK_TARGET}"
			PREVIOUS_EXISTED=1
			;;
		2) ;;
		*)
			echo "ERROR: ${AWG_BT_STORE_DIR}/previous is damaged; nothing was changed." >&2
			return 1
			;;
	esac
	UNIT="awg-quick@${SERVER_AWG_NIC}.service"
	STATE="$(systemctl show -p ActiveState --value "${UNIT}" 2>/dev/null)" || STATE=""
	case "${STATE}" in
		active) ACTIVE=1 ;;
		inactive | failed) ;;
		*)
			echo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2
			return 1
			;;
	esac

	if [[ "${MODE}" == upgrade ]]; then
		TARGET="${_AWG_BT_REL_ID}"
		if [[ "${CURRENT_ID}" == "${TARGET}" ]]; then
			if [[ "$(sha256sum -- "${AWG_BT_STORE_DIR}/${TARGET}/boringtun-cli" 2>/dev/null | cut -d' ' -f1)" != "${_AWG_BT_REL_BINARY_SHA256}" ]]; then
				echo "ERROR: ${AWG_BT_STORE_DIR}/${TARGET} is not the release this installer pins (its binary has another SHA-256); nothing was changed." >&2
				return 1
			fi
			# The helpers of an earlier installer version may refuse the
			# release current selects, so they are reconciled here too,
			# before anything else changes; a stopped service stays stopped.
			_awgBtReconcileLifecycleHelpers || return 1
			if ((_AWG_BT_HELPERS_CHANGED)); then
				echo "The BoringTun helpers in ${AWG_BT_LIBEXEC_DIR} were updated to this installer's, which accept ${TARGET}."
			fi
			if ((PREVIOUS_EXISTED)) && [[ "${PREVIOUS_ID}" == "${CURRENT_ID}" ]]; then
				# A switch interrupted between its two link renames left
				# previous naming current. Which release previous named
				# before cannot be known: only the duplicate link is
				# dropped, and every release directory stays as it is,
				# unmanaged, never adopted as the rollback target.
				if ! rm -f -- "${AWG_BT_STORE_DIR}/previous" ||
					[[ -e "${AWG_BT_STORE_DIR}/previous" || -L "${AWG_BT_STORE_DIR}/previous" ]]; then
					echo "ERROR: ${AWG_BT_STORE_DIR}/previous names current and could not be removed; the store is not consistent." >&2
					return 1
				fi
				echo "${AWG_BT_STORE_DIR}/previous named current, which an interrupted switch leaves; that link was removed. No release directory was changed or chosen as the rollback target."
				REPAIRED=1
			fi
			if ((ACTIVE)) && ! _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}" >/dev/null 2>&1; then
				# current was switched, but the service was not restarted
				# onto it (an interrupted transaction): finish that now.
				echo "current already selects ${TARGET}, but ${UNIT} is not served by it; restarting it on ${TARGET}."
				awgBackendPrepareServiceStart
				if ! systemctl restart "${UNIT}" || ! _awgBtVerifyLifecycleActivation; then
					echo "ERROR: ${UNIT} is still not verifiably served by ${TARGET}. Check: journalctl -u ${UNIT}" >&2
					return 1
				fi
				echo "${UNIT} now runs the BoringTun release ${TARGET}."
				return 0
			fi
			if ((REPAIRED || _AWG_BT_HELPERS_CHANGED)); then
				echo "The BoringTun release ${TARGET} that this installer pins is already current."
				if ((_AWG_BT_HELPERS_CHANGED && !ACTIVE)); then
					echo "${UNIT} was left ${STATE}; its next start uses the updated helpers."
				fi
			else
				echo "The BoringTun release ${TARGET} that this installer pins is already current; nothing was changed."
			fi
			UNMANAGED="$(_awgBtUnmanagedReleases)"
			[[ -z "${UNMANAGED}" ]] || echo "NOTE: ${AWG_BT_STORE_DIR} also holds release directories that neither current nor previous names, which were left alone: $(tr '\n' ' ' <<<"${UNMANAGED}")"
			return 0
		fi
	else
		if ((PREVIOUS_EXISTED == 0)) || [[ "${PREVIOUS_ID}" == "${CURRENT_ID}" ]]; then
			echo "ERROR: there is no BoringTun release to roll back to (${AWG_BT_STORE_DIR}/previous is absent or names current); nothing was changed." >&2
			return 1
		fi
		TARGET="${PREVIOUS_ID}"
		# Before anything changes, the helpers included.
		_awgBtLifecycleTargetRunsImitation rollback "${TARGET}" "${CURRENT_ID}" || return 1
	fi
	_awgBtReconcileLifecycleHelpers || return 1

	function abandonBoringtunLifecycle() {
		[[ -z "${WORK}" ]] || rm -rf -- "${WORK}"
		# A release this attempt stored (also when a signal arrived before it
		# could record that) is removed; one that was there before stays.
		if ((CREATED)) || { [[ "${MODE}" == upgrade ]] && [[ "${_AWG_BT_REL_CREATED:-0}" == 1 ]]; }; then
			_awgBtPruneRelease "${TARGET}" || echo "WARNING: could not remove ${AWG_BT_STORE_DIR}/${TARGET}, which this attempt stored." >&2
		fi
	}

	function restoreBoringtunLifecycle() {
		local FAILED=0
		if ! _awgBtSetStoreLink current "${CURRENT_ID}"; then
			echo "ERROR: could not restore ${AWG_BT_STORE_DIR}/current to ${CURRENT_ID}." >&2
			FAILED=1
		fi
		if ((PREVIOUS_EXISTED)); then
			if ! _awgBtSetStoreLink previous "${PREVIOUS_ID}"; then
				echo "ERROR: could not restore ${AWG_BT_STORE_DIR}/previous to ${PREVIOUS_ID}." >&2
				FAILED=1
			fi
		elif ! rm -f -- "${AWG_BT_STORE_DIR}/previous" || [[ -e "${AWG_BT_STORE_DIR}/previous" || -L "${AWG_BT_STORE_DIR}/previous" ]]; then
			echo "ERROR: could not remove ${AWG_BT_STORE_DIR}/previous, which did not exist before." >&2
			FAILED=1
		fi
		# The private copies of the client configs are never needed for a
		# recovery; the store keeps every release this attempt touched.
		[[ -z "${WORK}" ]] || rm -rf -- "${WORK}"
		if ((FAILED)); then
			echo "ERROR: the store links are not restored; ${UNIT} is left as it is. Point current back at ${CURRENT_ID} and previous at ${PREVIOUS_ID:-nothing}, then restart ${UNIT}." >&2
			return 1
		fi
		echo "Restored ${AWG_BT_STORE_DIR}/current to ${CURRENT_ID} and previous to ${PREVIOUS_ID:-none}." >&2
		# Only a service this attempt restarted runs anything else; one that was
		# not restarted still runs the original release.
		if ((ACTIVE && RESTARTED)); then
			awgBackendPrepareServiceStart
			if ! systemctl restart "${UNIT}"; then
				echo "ERROR: the recovery restart of ${UNIT} on ${CURRENT_ID} failed. Check: journalctl -u ${UNIT}" >&2
				return 1
			fi
			if ! _awgBtVerifyLifecycleActivation; then
				echo "ERROR: after the recovery restart, ${UNIT} is not verifiably served by ${CURRENT_ID}. Check: journalctl -u ${UNIT}" >&2
				return 1
			fi
			echo "${UNIT} runs ${CURRENT_ID} again." >&2
		fi
		abandonBoringtunLifecycle
		return 0
	}

	function interruptBoringtunLifecycle() {
		trap '' HUP INT TERM
		echo "ERROR: the BoringTun ${MODE} was interrupted." >&2
		if ((SWITCHED)); then
			restoreBoringtunLifecycle
		else
			abandonBoringtunLifecycle
		fi
		exit "$1"
	}

	trap 'interruptBoringtunLifecycle 129' HUP
	trap 'interruptBoringtunLifecycle 130' INT
	trap 'interruptBoringtunLifecycle 143' TERM

	if [[ "${MODE}" == upgrade ]]; then
		echo "Upgrading BoringTun from ${CURRENT_ID} to ${TARGET}, the release this installer pins (${AWG_BT_RELEASE_TAG})."
		if ! _awgBtEnsurePinnedRelease "${ARCH}"; then
			echo "ERROR: the pinned release could not be made available; nothing was changed." >&2
			return 1
		fi
		CREATED="${_AWG_BT_REL_CREATED}"
	else
		echo "Rolling BoringTun back from ${CURRENT_ID} to ${TARGET}."
	fi
	if ! _awgBtVerifyCandidate "${AWG_BT_STORE_DIR}/${TARGET}" "${ARCH}" "${TARGET}"; then
		echo "ERROR: ${TARGET} does not verify as a release of the BoringTun store; nothing was changed." >&2
		abandonBoringtunLifecycle
		return 1
	fi
	# An upgrade target is only here once downloaded; a rollback target was
	# checked before anything changed.
	if [[ "${MODE}" == upgrade ]] && ! _awgBtLifecycleTargetRunsImitation upgrade "${TARGET}" "${CURRENT_ID}"; then
		abandonBoringtunLifecycle
		return 1
	fi
	if ! WORK="$(mktemp -d "${TMPDIR:-/tmp}/amneziawg-boringtun-lifecycle.XXXXXX")"; then
		WORK=""
		echo "ERROR: cannot create a private directory for the validation; nothing was changed." >&2
		abandonBoringtunLifecycle
		return 1
	fi
	chmod 0700 -- "${WORK}"
	if ! HASHES_BEFORE="$(_awgBtLifecycleConfigHashes)" || [[ -z "${HASHES_BEFORE}" ]]; then
		echo "ERROR: cannot read the configuration of this installation; nothing was changed." >&2
		abandonBoringtunLifecycle
		return 1
	fi
	echo "Validating ${TARGET} against this installation's current settings before it becomes current..."
	if ! _awgBtValidateReleaseCandidate "${TARGET}" "${WORK}"; then
		echo "ERROR: ${TARGET} does not accept this installation's current settings (AWG $(awgProtocolDisplayName "${AWG_PROTOCOL_VERSION}"), imitation $(boringtunImitationDisplay "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}"), the server and client configs); current is still ${CURRENT_ID}." >&2
		abandonBoringtunLifecycle
		return 1
	fi
	if ! HASHES_AFTER="$(_awgBtLifecycleConfigHashes)"; then
		echo "ERROR: cannot read the configuration of this installation after the validation; nothing was changed." >&2
		abandonBoringtunLifecycle
		return 1
	fi
	if [[ "${HASHES_AFTER}" != "${HASHES_BEFORE}" ]]; then
		echo "ERROR: the configuration changed during the validation; nothing was changed." >&2
		abandonBoringtunLifecycle
		return 1
	fi

	SWITCHED=1
	if ! _awgBtSetStoreLink previous "${CURRENT_ID}"; then
		echo "ERROR: could not point ${AWG_BT_STORE_DIR}/previous at ${CURRENT_ID}." >&2
		restoreBoringtunLifecycle
		return 1
	fi
	if ! _awgBtSetStoreLink current "${TARGET}"; then
		echo "ERROR: could not point ${AWG_BT_STORE_DIR}/current at ${TARGET}." >&2
		restoreBoringtunLifecycle
		return 1
	fi
	if ((ACTIVE)); then
		awgBackendPrepareServiceStart
		RESTARTED=1
		if ! systemctl restart "${UNIT}" || ! _awgBtVerifyLifecycleActivation; then
			echo "ERROR: ${UNIT} did not come up verifiably on ${TARGET}; restoring ${CURRENT_ID}." >&2
			restoreBoringtunLifecycle
			return 1
		fi
	fi
	if ! HASHES_AFTER="$(_awgBtLifecycleConfigHashes)"; then
		echo "ERROR: cannot read the configuration of this installation after the switch; restoring ${CURRENT_ID}." >&2
		restoreBoringtunLifecycle
		return 1
	fi
	if [[ "${HASHES_AFTER}" != "${HASHES_BEFORE}" ]]; then
		echo "ERROR: the configuration changed during the switch; restoring ${CURRENT_ID}." >&2
		restoreBoringtunLifecycle
		return 1
	fi
	trap - HUP INT TERM
	SWITCHED=0
	rm -rf -- "${WORK}"
	if ((PREVIOUS_EXISTED)) && [[ "${PREVIOUS_ID}" != "${TARGET}" && "${PREVIOUS_ID}" != "${CURRENT_ID}" ]]; then
		_awgBtPruneRelease "${PREVIOUS_ID}" ||
			echo "WARNING: could not remove ${AWG_BT_STORE_DIR}/${PREVIOUS_ID}, the earlier rollback target." >&2
	fi
	if ((ACTIVE)); then
		echo "BoringTun now runs ${TARGET}; ${UNIT} was restarted on it. previous is ${CURRENT_ID}."
	else
		echo "current is now ${TARGET} and previous ${CURRENT_ID}. ${UNIT} is ${STATE} and was not started; it runs ${TARGET} at its next start."
	fi
	UNMANAGED="$(_awgBtUnmanagedReleases)"
	[[ -z "${UNMANAGED}" ]] || echo "NOTE: ${AWG_BT_STORE_DIR} also holds release directories that neither current nor previous names, which were left alone: $(tr '\n' ' ' <<<"${UNMANAGED}")"
	echo "Params, the server and client configs and the protocol imitation are unchanged."
	return 0
)

function changeAwgProtocolInteractively() {
	local TARGET_MODE RESPONSE CHOICE=""
	normalizeAwgProtocolVersion || return 1
	echo "Current AmneziaWG protocol mode: $(awgProtocolDisplayName "${AWG_PROTOCOL_VERSION}")"
	echo ""
	case "${AWG_PROTOCOL_VERSION}" in
		"${AWG_PROTOCOL_VERSION_2}")
			echo "   1) Enable AWG 3.0 (header protection)"
			echo "   2) Enable AWG 3.1 (header protection + RandomTrailers; DisableCookies stays off)"
			echo "   3) Cancel"
			until [[ ${CHOICE} =~ ^[1-3]$ ]]; do
				read -rp "Select an option [1-3]: " CHOICE
			done
			case "${CHOICE}" in
				1) TARGET_MODE="${AWG_PROTOCOL_VERSION_3}" ;;
				2) TARGET_MODE="${AWG_PROTOCOL_VERSION_31}" ;;
				*) echo "Protocol change cancelled."; return 0 ;;
			esac
			echo -e "${RED}AWG ${TARGET_MODE} cannot communicate with AWG 2.0 clients on this interface.${NC}"
			echo -e "${ORANGE}Every client must support this protocol version and receive its regenerated config.${NC}"
			;;
		"${AWG_PROTOCOL_VERSION_3}")
			echo "   1) Enable AWG 3.1 (adds RandomTrailers; DisableCookies stays off)"
			echo "   2) Return to AWG 2.0"
			echo "   3) Cancel"
			until [[ ${CHOICE} =~ ^[1-3]$ ]]; do
				read -rp "Select an option [1-3]: " CHOICE
			done
			case "${CHOICE}" in
				1) TARGET_MODE="${AWG_PROTOCOL_VERSION_31}" ;;
				2) TARGET_MODE="${AWG_PROTOCOL_VERSION_2}" ;;
				*) echo "Protocol change cancelled."; return 0 ;;
			esac
			;;
		"${AWG_PROTOCOL_VERSION_31}")
			echo "   1) Return to AWG 3.0 (removes RandomTrailers and DisableCookies)"
			echo "   2) Return to AWG 2.0"
			echo "   3) Cancel"
			until [[ ${CHOICE} =~ ^[1-3]$ ]]; do
				read -rp "Select an option [1-3]: " CHOICE
			done
			case "${CHOICE}" in
				1) TARGET_MODE="${AWG_PROTOCOL_VERSION_3}" ;;
				2) TARGET_MODE="${AWG_PROTOCOL_VERSION_2}" ;;
				*) echo "Protocol change cancelled."; return 0 ;;
			esac
			;;
	esac
	if [[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_2}" ]]; then
		echo -e "${ORANGE}This will downgrade the interface and every client config to AWG 2.0.${NC}"
	elif [[ "${TARGET_MODE}" == "${AWG_PROTOCOL_VERSION_31}" ]]; then
		echo -e "${ORANGE}RandomTrailers must match on every client. DisableCookies is not enabled automatically (it disables Cookie Reply / anti-DoS).${NC}"
		if ! [[ "${SERVER_AWG_S1}" == "${SERVER_AWG_S2}" && \
			"${SERVER_AWG_S1}" == "${SERVER_AWG_S3}" && \
			"${SERVER_AWG_S1}" == "${SERVER_AWG_S4}" ]]; then
			echo -e "${ORANGE}Current S1-S4 values differ. Upstream recommends identical S1-S4 when RandomTrailers is on; existing values will be kept.${NC}"
		fi
	fi
	if [[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" && "${TARGET_MODE}" != "${AWG_PROTOCOL_VERSION_2}" ]]; then
		checkBoringtunImitationProtocolCompat "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${TARGET_MODE}" || return 1
		printBoringtunImitationWarnings "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}" "${TARGET_MODE}"
		_AWG_BT_IMITATION_WARNED=1
	fi
	read -rp "Switch this interface to AWG $(awgProtocolDisplayName "${TARGET_MODE}")? [y/N]: " RESPONSE
	[[ "${RESPONSE}" == [Yy] ]] || {
		echo "Protocol change cancelled."
		return 0
	}
	setAwgProtocolMode "${TARGET_MODE}"
}

# Interactive management can remain open while the web panel or another CLI
# changes protocol state. Reload persisted params only after taking the shared
# lifecycle lock, and keep the lock through the complete mutation so a staged
# protocol transaction can never overwrite the result.
function runLockedManagementOperation() (
	local OPERATION="$1"
	acquireClientLifecycleLock || return 1
	loadParams
	"${OPERATION}"
)

function manageMenu() {
	local MENU_OPTION=""
	echo "AmneziaWG server installer (https://github.com/wiresock/amneziawg-install)"
	echo ""
	echo "It looks like AmneziaWG is already installed."
	echo ""
	if [[ "${AWG_BACKEND:-}" == "${AWG_BACKEND_BORINGTUN}" ]]; then
		manageBoringtunMenu
		return
	fi
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Regenerate all client configs (using current server parameters)"
	echo "   5) Change AWG protocol mode (current: $(awgProtocolDisplayName "${AWG_PROTOCOL_VERSION:-${AWG_PROTOCOL_VERSION_2}}"))"
	echo "   6) Uninstall AmneziaWG"
	echo "   7) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-7]$ ]]; do
		read -rp "Select an option [1-7]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		runLockedManagementOperation newClient
		;;
	2)
		listClients
		;;
	3)
		runLockedManagementOperation revokeClient
		;;
	4)
		runLockedManagementOperation regenerateClients
		;;
	5)
		changeAwgProtocolInteractively
		;;
	6)
		runLockedManagementOperation uninstallAmneziaWG
		;;
	7)
		exit 0
		;;
	esac
}

# The management menu of a BoringTun installation: the kernel menu's options,
# numbered as there, plus a change of the protocol imitation before Exit,
# under a line that shows the imitation.
function manageBoringtunMenu() {
	local MENU_OPTION=""
	echo "Backend: BoringTun (experimental); protocol imitation: $(boringtunImitationDisplay "${AWG_BORINGTUN_IMITATE_PROTOCOL:-${AWG_BT_IMITATE_NONE}}" "${AWG_BORINGTUN_IMITATE_DOMAIN:-}")"
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Regenerate all client configs (using current server parameters)"
	echo "   5) Change AWG protocol mode (current: $(awgProtocolDisplayName "${AWG_PROTOCOL_VERSION:-${AWG_PROTOCOL_VERSION_2}}"))"
	echo "   6) Uninstall AmneziaWG"
	echo "   7) Change BoringTun protocol imitation (current: ${AWG_BORINGTUN_IMITATE_PROTOCOL:-${AWG_BT_IMITATE_NONE}})"
	echo "   8) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-8]$ ]]; do
		read -rp "Select an option [1-8]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		runLockedManagementOperation newClient
		;;
	2)
		listClients
		;;
	3)
		runLockedManagementOperation revokeClient
		;;
	4)
		runLockedManagementOperation regenerateClients
		;;
	5)
		changeAwgProtocolInteractively
		;;
	6)
		runLockedManagementOperation uninstallAmneziaWG
		;;
	7)
		changeBoringtunImitationInteractively
		;;
	8)
		exit 0
		;;
	esac
}

# ── Non-interactive client management ─────────────────────────────────────────
#
# These functions support the --add-client and --remove-client flags,
# enabling fully non-interactive client lifecycle management from the
# amneziawg-web panel or other automation tooling.
#
# Contract:
#   --add-client NAME     → validates name, creates client config, exits 0 on success
#   --remove-client NAME  → validates name, removes client config, exits 0 on success
#   --list-clients        → lists all client names (one per line), exits 0
#
# On error, prints a message to stderr and exits with a non-zero code.

CLIENT_LIFECYCLE_LOCK_FD=""

# Acquire the same non-blocking lifecycle lock used by amneziawg-web. The
# persistent state directory is opened read-only, its descriptor identity
# is revalidated against the path, and the descriptor is locked. The root-run
# CLI therefore never creates, truncates, chowns, or chmods a service-writable
# lock pathname. Mutating callers run in a subshell so the descriptor is closed
# automatically; the interactive menu preloader releases it explicitly.
function acquireClientLifecycleLock() {
	local lock_dir panel_installed=0
	local old_umask dir_identity descriptor_identity descriptor_path
	lock_dir="$(resolveClientLifecycleLockDir)" || return 1
	if isWebPanelInstalled; then
		panel_installed=1
	fi

	if ! command -v flock >/dev/null 2>&1; then
		echo "ERROR: flock is required for serialized client lifecycle operations" >&2
		return 1
	fi
	if [[ ! -e "${lock_dir}" && "${panel_installed}" -eq 1 ]]; then
		echo "ERROR: web panel lifecycle directory '${lock_dir}' does not exist" >&2
		return 1
	fi
	if [[ ! -e "${lock_dir}" ]]; then
		old_umask="$(umask)"
		umask 077
		mkdir -p "${lock_dir}" || {
			umask "${old_umask}"
			echo "ERROR: could not create client lifecycle directory '${lock_dir}'" >&2
			return 1
		}
		umask "${old_umask}"
	fi
	if [[ -L "${lock_dir}" || ! -d "${lock_dir}" ]]; then
		echo "ERROR: refusing unsafe client lifecycle directory '${lock_dir}'" >&2
		return 1
	fi
	if ! exec {CLIENT_LIFECYCLE_LOCK_FD}< "${lock_dir}"; then
		echo "ERROR: could not open client lifecycle directory '${lock_dir}'" >&2
		return 1
	fi
	descriptor_path="/proc/${BASHPID}/fd/${CLIENT_LIFECYCLE_LOCK_FD}"
	dir_identity="$(stat -Lc '%d:%i' -- "${lock_dir}" 2>/dev/null || true)"
	descriptor_identity="$(stat -Lc '%d:%i' -- "${descriptor_path}" 2>/dev/null || true)"
	if [[ -L "${lock_dir}" || ! -d "${lock_dir}" || -z "${dir_identity}" || \
		-z "${descriptor_identity}" || "${dir_identity}" != "${descriptor_identity}" ]]; then
		exec {CLIENT_LIFECYCLE_LOCK_FD}>&-
		echo "ERROR: client lifecycle directory changed while it was opened" >&2
		return 1
	fi
	if ! flock -xn "${CLIENT_LIFECYCLE_LOCK_FD}"; then
		exec {CLIENT_LIFECYCLE_LOCK_FD}>&-
		echo "ERROR: another client or protocol management operation is already in progress" >&2
		return 1
	fi
}

function releaseClientLifecycleLock() {
	if [[ -n "${CLIENT_LIFECYCLE_LOCK_FD:-}" ]]; then
		exec {CLIENT_LIFECYCLE_LOCK_FD}>&- || true
		CLIENT_LIFECYCLE_LOCK_FD=""
	fi
}

# The initial interactive menu needs loaded values for display, but must not
# hold the lifecycle lock while waiting for input. Mutating menu actions reload
# again under their own lock through runLockedManagementOperation.
function loadParamsForManagementMenu() {
	local RC=0
	acquireClientLifecycleLock || return 1
	loadParams || RC=$?
	releaseClientLifecycleLock
	return "${RC}"
}

function nonInteractiveAddClient() (
	local CLIENT_NAME="$1"

	# Validate the name format (same rules as interactive mode)
	if [[ -z "${CLIENT_NAME}" ]]; then
		echo "ERROR: client name must not be empty" >&2
		exit 1
	fi
	if ! [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
		echo "ERROR: client name must be alphanumeric (plus underscores/dashes)" >&2
		exit 1
	fi
	if [[ ${#CLIENT_NAME} -gt 15 ]]; then
		echo "ERROR: client name must be at most 15 characters" >&2
		exit 1
	fi
	acquireClientLifecycleLock || exit 1
	# Reload only after locking: a protocol transaction may have completed after
	# this CLI process started but before it acquired the lifecycle lock.
	loadParams

	# Ensure the config path follows the freshly loaded interface name.
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	# Check for duplicate name
	if [[ $(grep -c -xF "### Client ${CLIENT_NAME}" "${SERVER_AWG_CONF}") != 0 ]]; then
		echo "ERROR: a client named '${CLIENT_NAME}' already exists" >&2
		exit 1
	fi

	# Auto-assign the first available IP pair (same logic as AUTO_INSTALL)
	local BASE_IP DOT_IP DOT_EXISTS IPV6_EXISTS CLIENT_AWG_IPV4 CLIENT_AWG_IPV6
	BASE_IP="${SERVER_AWG_IPV4%.*}"

	local NORMALIZED_SERVER_IPV6 BASE_IPV6
	NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
	BASE_IPV6=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)

	local FREE_FOUND=0
	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -cF "${BASE_IP}.${DOT_IP}/32" "${SERVER_AWG_CONF}")
		local CLIENT_IPV6_CANDIDATE
		CLIENT_IPV6_CANDIDATE=$(normalizeIPv6 "${BASE_IPV6}::${DOT_IP}")
		IPV6_EXISTS=0
		while IFS= read -r _existing_ip_cidr; do
			local _existing_ip="${_existing_ip_cidr%/*}"
			local _normalized_existing
			_normalized_existing=$(normalizeIPv6 "${_existing_ip}")
			if [[ "${_normalized_existing}" == "${CLIENT_IPV6_CANDIDATE}" ]]; then
				IPV6_EXISTS=1
				break
			fi
		done < <(grep -oE '([0-9a-fA-F:]+)/128' "${SERVER_AWG_CONF}")
		if [[ ${DOT_EXISTS} == '0' && ${IPV6_EXISTS} == '0' ]]; then
			FREE_FOUND=1
			break
		fi
	done

	if [[ ${FREE_FOUND} -eq 0 ]]; then
		echo "ERROR: no free IP addresses available (max 253 clients)" >&2
		exit 1
	fi

	CLIENT_AWG_IPV4="${BASE_IP}.${DOT_IP}"
	CLIENT_AWG_IPV6=$(normalizeIPv6 "${BASE_IPV6}::${DOT_IP}")

	# Generate key pair
	local CLIENT_PRIV_KEY CLIENT_PUB_KEY CLIENT_PRE_SHARED_KEY
	CLIENT_PRIV_KEY=$(awg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
	CLIENT_PRE_SHARED_KEY=$(awg genpsk)

	# Non-interactive mode writes client configs to a dedicated directory under
	# AMNEZIAWG_DIR with restrictive root-only permissions. This avoids writing
	# into home directories and keeps access scoped to privileged callers.
	local HOME_DIR="${AMNEZIAWG_DIR}/clients"
	mkdir -p "${HOME_DIR}"
	chmod 700 "${HOME_DIR}"

	local CLIENT_DNS="${CLIENT_DNS_1}"
	if [[ -n "${CLIENT_DNS_2}" ]]; then
		CLIENT_DNS="${CLIENT_DNS_1},${CLIENT_DNS_2}"
	fi

	local CLIENT_AWG_IPV6_DISPLAY
	CLIENT_AWG_IPV6_DISPLAY=$(compressIPv6 "${CLIENT_AWG_IPV6}")

	# Include IPv6 in the client Address/route list only when enabled (issue #51).
	local CLIENT_ADDRESS="${CLIENT_AWG_IPV4}/32"
	if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
		CLIENT_ADDRESS="${CLIENT_ADDRESS},${CLIENT_AWG_IPV6_DISPLAY}/128"
	fi
	local CLIENT_ALLOWED_IPS
	if ! CLIENT_ALLOWED_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${ENABLE_IPV6:-y}"); then
		echo -e "${RED}ERROR: ALLOWED_IPS has no usable routes after applying ENABLE_IPV6=${ENABLE_IPV6:-y}: ${ALLOWED_IPS}${NC}"
		return 1
	fi

	# If SERVER_PUB_IP is IPv6, normalize brackets
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		SERVER_PUB_IP="${SERVER_PUB_IP#\[}"
		SERVER_PUB_IP="${SERVER_PUB_IP%\]}"
		SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
	local ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077
	local AWG_PROTOCOL_FIELDS=""
	AWG_PROTOCOL_FIELDS="$(renderAwgProtocolFields)" || exit 1

	echo "[Interface]
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
${AWG_PROTOCOL_FIELDS}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${CLIENT_ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	umask "${OLD_UMASK}"

	local client_conf
	client_conf="${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
	chmod 600 "${client_conf}" 2>/dev/null || true

	# Copy the config to the web panel directory (or adjust permissions in
	# place when the file is already there) so the web panel service user can
	# read it.
	copyToWebPanelDir "${client_conf}"

	# Add peer to server config. Include the IPv6 /128 only when IPv6 is enabled.
	local PEER_ALLOWED_IPS="${CLIENT_AWG_IPV4}/32"
	if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
		PEER_ALLOWED_IPS="${PEER_ALLOWED_IPS},${CLIENT_AWG_IPV6}/128"
	fi
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${PEER_ALLOWED_IPS}" >>"${SERVER_AWG_CONF}"

	# Preserve stdout for the generated client config path expected by callers.
	# Route any informational/repair output from helper setup to stderr.
	ensureAwgBackendReady 1>&2
	# Capture `awg syncconf` stderr in a file that mktemp creates with a unique
	# name and mode 0600, so concurrent invocations never share it. The nested
	# subshell gives the EXIT trap its own scope: the trap removes exactly this
	# file after success, failure or a terminating signal, and cannot replace or
	# outlive any trap of the caller.
	(
		sync_err_file="$(mktemp "${TMPDIR:-/tmp}/amneziawg-syncconf.XXXXXX")" || {
			echo "ERROR: could not create a temporary file for AmneziaWG sync errors" >&2
			exit 1
		}
		trap 'rm -f -- "${sync_err_file}"' EXIT
		if ! awgSyncInterfaceConfig "${SERVER_AWG_NIC}" "${sync_err_file}"; then
			sync_err="$(cat -- "${sync_err_file}" 2>/dev/null || true)"
			echo "ERROR: failed to sync AmneziaWG interface '${SERVER_AWG_NIC}' after adding client '${CLIENT_NAME}'" >&2
			if [[ -n "${sync_err}" ]]; then
				echo "${sync_err}" >&2
			fi
			exit 1
		fi
	) || exit "$?"

	# Print the config path to stdout for the caller
	echo "${client_conf}"
)

function nonInteractiveRemoveClient() (
	local CLIENT_NAME="$1"

	if [[ -z "${CLIENT_NAME}" ]]; then
		echo "ERROR: client name must not be empty" >&2
		exit 1
	fi
	if ! [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
		echo "ERROR: client name contains unsafe characters" >&2
		exit 1
	fi
	if [[ ${#CLIENT_NAME} -gt 15 ]]; then
		echo "ERROR: client name must be at most 15 characters" >&2
		exit 1
	fi
	acquireClientLifecycleLock || exit 1
	loadParams

	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	# Check the client exists
	if [[ $(grep -c -xF "### Client ${CLIENT_NAME}" "${SERVER_AWG_CONF}") == 0 ]]; then
		echo "ERROR: no client named '${CLIENT_NAME}' found" >&2
		exit 1
	fi

	# Remove [Peer] block
	# Note: CLIENT_NAME is validated to [a-zA-Z0-9_-]+ so it cannot contain
	# sed metacharacters — safe to interpolate directly.
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

	# Remove client config file (non-interactive configs are stored under
	# ${AMNEZIAWG_DIR}/clients to keep them in a traversable directory).
	local CLIENT_DIR="${AMNEZIAWG_DIR}/clients"
	rm -f "${CLIENT_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
	removeFromWebPanelDir "${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	local sync_err
	sync_err=""
	ensureAwgBackendReady >&2
	if ! sync_err="$(awgSyncInterfaceConfig "${SERVER_AWG_NIC}" --stderr-to-stdout)"; then
		echo "ERROR: failed to sync AmneziaWG interface '${SERVER_AWG_NIC}' after removing client '${CLIENT_NAME}'" >&2
		if [[ -n "${sync_err}" ]]; then
			echo "${sync_err}" >&2
		fi
		exit 1
	fi

	echo "OK"
)

function nonInteractiveListClients() (
	acquireClientLifecycleLock || exit 1
	loadParams
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 || true
)

# Only run main logic when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	# ── Non-interactive flags ─────────────────────────────────────────────
	#
	# These flags allow automation tooling (e.g. amneziawg-web) to invoke
	# client lifecycle operations without interactive prompts.
	#
	# Usage:
	#   amneziawg-install.sh --add-client <NAME>
	#   amneziawg-install.sh --remove-client <NAME>
	#   amneziawg-install.sh --list-clients
	#   amneziawg-install.sh --protocol-status
	#   amneziawg-install.sh --enable-awg3
	#   amneziawg-install.sh --enable-awg31
	#   amneziawg-install.sh --disable-awg3
	#   amneziawg-install.sh --set-boringtun-imitation <none|dns|quic|sip|stun|auto> [hostname]
	#   amneziawg-install.sh --backend-status
	#   amneziawg-install.sh --upgrade-boringtun
	#   amneziawg-install.sh --rollback-boringtun
	#
	# Requires AmneziaWG to be already installed (params file must exist).
	case "${1:-}" in
		--upgrade-boringtun|--rollback-boringtun)
			if [[ $# -ne 1 ]]; then
				echo "Usage: amneziawg-install.sh --upgrade-boringtun" >&2
				echo "       amneziawg-install.sh --rollback-boringtun" >&2
				exit 1
			fi
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			if [[ "$1" == --upgrade-boringtun ]]; then
				boringtunBinaryLifecycle upgrade
			else
				boringtunBinaryLifecycle rollback
			fi
			exit $?
			;;
		--set-boringtun-imitation|--backend-status)
			if [[ "$1" == --backend-status && $# -ne 1 ]] ||
				[[ "$1" == --set-boringtun-imitation && ($# -lt 2 || $# -gt 3) ]]; then
				echo "Usage: amneziawg-install.sh --set-boringtun-imitation <none|dns|quic|sip|stun|auto> [hostname]" >&2
				echo "       amneziawg-install.sh --backend-status" >&2
				exit 1
			fi
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			if [[ "$1" == --backend-status ]]; then
				printBackendStatus
			else
				setBoringtunImitation "$2" "${3-}"
			fi
			exit $?
			;;
		--protocol-status|--enable-awg3|--enable-awg31|--disable-awg3)
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			case "$1" in
				--protocol-status)
					# Status is a read-only query and must never prompt for or persist
					# an unrelated legacy compatibility migration.
					loadParams 0 1
					printf '%s\n' "${AWG_PROTOCOL_VERSION}"
					;;
				--enable-awg3)
					setAwgProtocolMode 3
					;;
				--enable-awg31)
					setAwgProtocolMode 3.1
					;;
				--disable-awg3)
					setAwgProtocolMode 2
					;;
			esac
			exit $?
			;;
		--add-client)
			if [[ -z "${2:-}" ]]; then
				echo "ERROR: --add-client requires a client name argument" >&2
				exit 1
			fi
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			nonInteractiveAddClient "$2"
			exit $?
			;;
		--remove-client)
			if [[ -z "${2:-}" ]]; then
				echo "ERROR: --remove-client requires a client name argument" >&2
				exit 1
			fi
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			nonInteractiveRemoveClient "$2"
			exit $?
			;;
		--list-clients)
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			nonInteractiveListClients
			exit $?
			;;
	esac

	# ── Default interactive flow ──────────────────────────────────────────
	# Check for root, virt, OS...
	initialCheck

	# Check if AmneziaWG is already installed and load params
	if [[ -e "${AMNEZIAWG_DIR}/params" ]]; then
		if [[ "${OS}" == "ubuntu" ]]; then
			refreshConfiguredUbuntuAmneziaPpa
		fi
		loadParamsForManagementMenu || exit 1
		manageMenu
	else
		installAmneziaWG
	fi
fi
