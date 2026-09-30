#!/bin/bash
# Live coexistence test of the BoringTun host backend with an installed
# AmneziaWG kernel module, on a disposable Ubuntu 26.04 runner where the DKMS
# module builds. It settles which modprobe load override really keeps
# `ip link add … type amneziawg` from autoloading the module (a blacklist line
# or an install command), and proves the installer's behaviour:
#   A. a loaded module: the BoringTun install refuses and never unloads it;
#   B. an installed module: the install refuses without consent, and with
#      AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y installs the load override and
#      starts BoringTun;
#   C. with the override, `ip link add … type amneziawg` no longer loads the
#      module, and neither does `modprobe amneziawg`;
# plus: scratch probes stay on BoringTun, a module loaded behind the override's
# back makes the service's precheck refuse (never the kernel path), and
# uninstall removes the override but neither amneziawg-dkms nor an
# administrator's /etc/modules-load.d/amneziawg.conf.
#
# Requirements: root, systemd, Ubuntu with the running kernel's headers
# available, network access, AWG_DISPOSABLE_HOST_TEST=1.
#
# Usage: AWG_DISPOSABLE_HOST_TEST=1 bash tests/test-boringtun-kernel-coexistence.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"
IF="awg0"
UNIT="awg-quick@${IF}.service"
OVERRIDE="/etc/modprobe.d/amneziawg-install-boringtun.conf"
PROBE_CONF="/etc/modprobe.d/zz-amneziawg-coexistence-probe.conf"
WORK="/run/awg-coexistence"
PASSED=0
FAILED=0

die() {
	echo "ERROR: $*" >&2
	exit 2
}
ok() {
	echo "  OK: $1"
	PASSED=$((PASSED + 1))
}
bad() {
	echo "  FAIL: $1"
	FAILED=$((FAILED + 1))
}
check() {
	local MESSAGE="$1"
	shift
	if "$@"; then ok "${MESSAGE}"; else bad "${MESSAGE}"; fi
}
note() {
	echo "  RESULT: $1"
}
module_loaded() {
	[[ -e /sys/module/amneziawg ]]
}
unload_module() {
	ip link delete awgprobe0 2>/dev/null
	modprobe -r amneziawg 2>/dev/null || rmmod amneziawg 2>/dev/null
	! module_loaded
}

[[ "${AWG_DISPOSABLE_HOST_TEST:-}" == 1 ]] || die "set AWG_DISPOSABLE_HOST_TEST=1 on a disposable host"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -d /run/systemd/system ]] || die "systemd must be PID 1"
[[ ! -e /etc/amnezia/amneziawg/params ]] || die "AmneziaWG is already installed on this host"
mkdir -p "${WORK}"
cleanup() {
	local RC=$?
	trap - EXIT
	if ((FAILED)); then
		journalctl -u "${UNIT}" --no-pager -n 60 2>&1
		cat "${WORK}"/*.log 2>/dev/null | tail -n 80
	fi
	rm -f "${PROBE_CONF}"
	rm -rf "${WORK}"
	exit "${RC}"
}
trap cleanup EXIT

# Every installer run is bounded, so that a failure cannot leave the installer
# waiting at a prompt until the job times out.
INSTALLER_TIMEOUT=900
run_install() { # <log> [VAR=value...]
	local LOG="$1"
	shift
	timeout --kill-after=30 "${INSTALLER_TIMEOUT}" env "$@" AWG_BACKEND=boringtun AUTO_INSTALL=y SERVER_PUB_IP=192.0.2.1 \
		SERVER_AWG_NIC="${IF}" SERVER_PORT=51820 ENABLE_IPV6=n CREATE_INITIAL_CLIENT=n bash "${INSTALLER}" >"${WORK}/${LOG}" 2>&1 </dev/null
}
run_managed() { # <log> <installer argument>
	timeout --kill-after=30 "${INSTALLER_TIMEOUT}" bash "${INSTALLER}" "$2" >"${WORK}/$1" 2>&1 </dev/null
}

echo "=== Build and install the AmneziaWG kernel module (amneziawg-dkms) ==="
uname -srm
# shellcheck source=../amneziawg-install.sh
source "${INSTALLER}"
. /etc/os-release
enable_apt_ipv4
apt-get -o APT::Update::Error-Mode=any update >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg software-properties-common "linux-headers-$(uname -r)" >/dev/null ||
	die "cannot install the running kernel's headers"
configureUbuntuAmneziaPpa "$(getUbuntuPpaCodename)" "${AMNEZIA_PPA_SOURCES_DIR}" "$(dpkg --print-architecture)" || die "cannot configure the PPA"
apt-get -o APT::Update::Error-Mode=any update >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dkms amneziawg-dkms >"${WORK}/dkms.log" 2>&1 ||
	die "cannot install amneziawg-dkms"
dkms autoinstall -k "$(uname -r)" >>"${WORK}/dkms.log" 2>&1
depmod -a
disable_apt_ipv4
check "the AmneziaWG kernel module is installed" modinfo -n amneziawg
modinfo -n amneziawg
check "and loadable" modprobe amneziawg
check "and unloadable" unload_module

echo "=== Investigation: which load override stops the autoload? ==="
probe_override() { # <label> <modprobe.d line>
	local LABEL="$1" LINE="$2" ADD_RC LOADED_BY_LINK LOADED_BY_MODPROBE
	printf '%s\n' "${LINE}" >"${PROBE_CONF}"
	echo "--- ${LABEL}: '${LINE}'"
	echo "    modprobe -n -v amneziawg: $(modprobe -n -v amneziawg 2>&1 | tr '\n' ' ')"
	echo "    modprobe -n -v rtnl-link-amneziawg: $(modprobe -n -v rtnl-link-amneziawg 2>&1 | tr '\n' ' ')"
	ip link add awgprobe0 type amneziawg >/dev/null 2>&1
	ADD_RC=$?
	module_loaded && LOADED_BY_LINK=yes || LOADED_BY_LINK=no
	unload_module
	modprobe amneziawg >/dev/null 2>&1
	module_loaded && LOADED_BY_MODPROBE=yes || LOADED_BY_MODPROBE=no
	unload_module
	rm -f "${PROBE_CONF}"
	note "${LABEL}: ip link add … type amneziawg exited ${ADD_RC}, module loaded by it: ${LOADED_BY_LINK}; explicit modprobe loaded it: ${LOADED_BY_MODPROBE}"
	printf '%s %s %s\n' "${ADD_RC}" "${LOADED_BY_LINK}" "${LOADED_BY_MODPROBE}"
}
read -r _ BL_LINK BL_MODPROBE < <(probe_override "blacklist" "blacklist amneziawg" | tee /dev/stderr | tail -n 1)
read -r IN_RC IN_LINK IN_MODPROBE < <(probe_override "install" "install amneziawg /bin/false" | tee /dev/stderr | tail -n 1)
check "without an override, ip link add … type amneziawg autoloads the module (control)" \
	bash -c 'ip link add awgprobe0 type amneziawg && [[ -e /sys/module/amneziawg ]]'
unload_module
note "blacklist: autoload blocked=$([[ ${BL_LINK} == no ]] && echo yes || echo no), explicit modprobe blocked=$([[ ${BL_MODPROBE} == no ]] && echo yes || echo no)"
note "install /bin/false: autoload blocked=$([[ ${IN_LINK} == no ]] && echo yes || echo no), explicit modprobe blocked=$([[ ${IN_MODPROBE} == no ]] && echo yes || echo no)"
check "the landed form, 'install amneziawg /bin/false', stops the rtnl-link autoload" test "${IN_LINK}" = no -a "${IN_RC}" -ne 0
check "and an explicit modprobe amneziawg" test "${IN_MODPROBE}" = no

echo "=== A. a loaded module ==="
modprobe amneziawg
run_install install-loaded.log
RC=$?
check "the BoringTun install refuses while the module is loaded" test "${RC}" -ne 0
check "  and says so" grep -q "kernel module is loaded" "${WORK}/install-loaded.log"
check "  without unloading it" module_loaded
check "  and without installing anything" test ! -e /etc/amnezia/amneziawg/params -a ! -e /usr/local/lib/amneziawg-install -a ! -e "${OVERRIDE}"
unload_module

echo "=== B. an installed, unloaded module ==="
# The kernel install's boot entry, here as an administrator's own file: a
# BoringTun install never writes it, so its uninstall must leave it as it is.
MODULES_LOAD=/etc/modules-load.d/amneziawg.conf
[[ ! -e "${MODULES_LOAD}" ]] || die "${MODULES_LOAD} already exists on this host"
mkdir -p "${MODULES_LOAD%/*}"
printf '# the administrator'"'"'s own boot entry\namneziawg\n' >"${MODULES_LOAD}"
MODULES_LOAD_SHA="$(sha256sum "${MODULES_LOAD}")"
run_install install-no-consent.log
RC=$?
check "without consent the install refuses" test "${RC}" -ne 0
check "  and names the consent variable" grep -q "AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y" "${WORK}/install-no-consent.log"
check "  and writes no override or params" test ! -e "${OVERRIDE}" -a ! -e /etc/amnezia/amneziawg/params
run_install install-consent.log AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y
RC=$?
tail -n 12 "${WORK}/install-consent.log" | sed 's/^/    | /'
check "with AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y the install succeeds" test "${RC}" -eq 0
check "  and installs the load override" grep -qx 'install amneziawg /bin/false' "${OVERRIDE}"
check "  the unit is active" systemctl is-active --quiet "${UNIT}"
check "  on a TUN device, so BoringTun serves it" test -e "/sys/class/net/${IF}/tun_flags"
check "  its MainPID runs the verified BoringTun binary" \
	bash -c "[[ \"\$(readlink /proc/\$(systemctl show -p MainPID --value ${UNIT})/exe)\" == /usr/local/lib/amneziawg-install/boringtun/*/boringtun-cli ]]"
check "  the kernel module stayed unloaded" bash -c '! [[ -e /sys/module/amneziawg ]]'

echo "=== C. the override in force ==="
echo "    modprobe -n -v amneziawg: $(modprobe -n -v amneziawg 2>&1 | tr '\n' ' ')"
echo "    modprobe -n -v rtnl-link-amneziawg: $(modprobe -n -v rtnl-link-amneziawg 2>&1 | tr '\n' ' ')"
check "ip link add … type amneziawg fails" bash -c '! ip link add awgprobe0 type amneziawg 2>/dev/null'
check "  and does not load the module" bash -c '! [[ -e /sys/module/amneziawg ]]'
check "modprobe amneziawg fails" bash -c '! modprobe amneziawg 2>/dev/null'
check "  and does not load the module" bash -c '! [[ -e /sys/module/amneziawg ]]'
check "the installer's check sees the override in force" bash -c 'source "$1" && _awgBtKernelModuleBlocked' _ "${INSTALLER}"

echo "=== Scratch probes stay on BoringTun with the module installed ==="
check "--enable-awg3 succeeds" run_managed awg3.log --enable-awg3
check "--disable-awg3 succeeds" run_managed awg2.log --disable-awg3
check "  and the module was never loaded" bash -c '! [[ -e /sys/module/amneziawg ]]'
check "  the unit is still served by BoringTun" test -e "/sys/class/net/${IF}/tun_flags"

echo "=== A module loaded behind the override's back ==="
mv "${OVERRIDE}" "${WORK}/override.saved"
modprobe amneziawg
mv "${WORK}/override.saved" "${OVERRIDE}"
check "(the module is loaded)" module_loaded
systemctl restart "${UNIT}" >/dev/null 2>&1
check "a restart fails instead of taking the kernel path" bash -c "! systemctl is-active --quiet '${UNIT}'"
check "  no kernel interface was created" test ! -e "/sys/class/net/${IF}"
check "  the precheck named the loaded module" bash -c "journalctl -u '${UNIT}' --no-pager | grep -q 'kernel module is loaded'"
unload_module
systemctl reset-failed "${UNIT}" >/dev/null 2>&1
systemctl start "${UNIT}"
check "once the module is unloaded, BoringTun starts again" test -e "/sys/class/net/${IF}/tun_flags"

echo "=== Uninstall ==="
# Without params the menu would start a fresh interactive install instead.
if [[ -e /etc/amnezia/amneziawg/params ]]; then
	printf '6\ny\n' | timeout --kill-after=30 "${INSTALLER_TIMEOUT}" bash "${INSTALLER}" >"${WORK}/uninstall.log" 2>&1
	RC=$?
	tail -n 5 "${WORK}/uninstall.log" | sed 's/^/    | /'
else
	echo "    (no params: the install did not complete, so there is nothing to uninstall through the menu)"
	RC=1
fi
check "the uninstall succeeds" test "${RC}" -eq 0
check "  and removes the installer's load override" test ! -e "${OVERRIDE}"
check "  but not amneziawg-dkms, which it did not install" bash -c 'dpkg-query -W -f="\${Status}" amneziawg-dkms | grep -q "install ok installed"'
check "  so the module is loadable again" bash -c 'modprobe amneziawg && [[ -e /sys/module/amneziawg ]]'
check "  and ${MODULES_LOAD}, which it did not write, is byte for byte as it was" \
	test "$(sha256sum "${MODULES_LOAD}" 2>/dev/null)" = "${MODULES_LOAD_SHA}"
rm -f "${MODULES_LOAD}"
unload_module

echo
echo "BoringTun kernel coexistence: ${PASSED} passed, ${FAILED} failed"
((FAILED == 0))
