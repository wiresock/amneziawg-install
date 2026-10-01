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
# It also measures interoperability of AmneziaWG kernel clients with the
# BoringTun server's protocol imitation under AWG 3.0: BoringTun is started
# while the module is unloaded, the module is then loaded behind the
# override's back (the running daemon is unaffected), and a kernel client in a
# network namespace, configured with an installer-generated client config,
# is exercised once per imitation (none, dns, quic, stun):
#   - a sweep of UDP datagram sizes to an echo service on the server's tunnel
#     address; the loss is measured and reported as evidence, never held to a
#     threshold;
#   - a 4 MiB TCP transfer from the server to the kernel client, the direction
#     whose S prefixes BoringTun shapes, which must arrive complete with the
#     sender's SHA-256.
# A handshake that never completes, an echo service that answers nothing, or
# a transfer that does not arrive intact fails the test. SIP is refused under
# AWG 3.0 while any S size is 31 or more; a kernel module that rejects AWG 3.0
# is reported, and the interop then runs under AWG 2.0.
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
	[[ -z "${ECHO_PID:-}" ]] || kill "${ECHO_PID}" 2>/dev/null
	ip netns delete awgk 2>/dev/null
	ip link delete awgkh0 2>/dev/null
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
	[[ -z "${ECHO_PID:-}" ]] || kill "${ECHO_PID}" 2>/dev/null
	ip netns delete awgk 2>/dev/null
	ip link delete awgkh0 2>/dev/null
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

echo "=== Interop: an AmneziaWG kernel client with BoringTun's protocol imitation ==="
KNS="awgk"
KIF="awgk0"
KVETH_HOST="awgkh0"
KVETH_CLIENT="awgkc0"
ECHO_PORT=40007
SERVER_TUNNEL_ADDR=10.66.66.1
load_module_behind_override() {
	mv "${OVERRIDE}" "${WORK}/override.saved" && modprobe amneziawg
	local RC=$?
	mv "${WORK}/override.saved" "${OVERRIDE}"
	return "${RC}"
}
kernel_client_down() {
	ip -n "${KNS}" link delete "${KIF}" 2>/dev/null
	return 0
}
# The client: a kernel amneziawg interface in the namespace, configured from
# the generated client config (never printed).
kernel_client_up() {
	install -m 0600 "${KCLIENT_CONF}" "${WORK}/${KIF}.conf" &&
		awg-quick strip "${WORK}/${KIF}.conf" >"${WORK}/${KIF}.setconf" 2>"${WORK}/kclient-strip.err" &&
		ip -n "${KNS}" link add "${KIF}" type amneziawg &&
		ip netns exec "${KNS}" awg setconf "${KIF}" "${WORK}/${KIF}.setconf" 2>"${WORK}/kclient-setconf.err" &&
		ip -n "${KNS}" addr add "${KCLIENT_ADDR}/32" dev "${KIF}" &&
		ip -n "${KNS}" link set "${KIF}" up &&
		ip -n "${KNS}" route add "${SERVER_TUNNEL_ADDR}/32" dev "${KIF}"
}
kernel_reachable() {
	local I
	for ((I = 0; I < 40; I++)); do
		kernel_ping && return 0
		sleep 0.5
	done
	return 1
}
kernel_ping() {
	ip netns exec "${KNS}" ping -c 1 -W 1 "${SERVER_TUNNEL_ADDR}" >/dev/null 2>&1
}
# Every UDP payload size from 8 to 1300 bytes, three times over, to the echo
# service; prints "<sent> <lost> <lost sizes...>".
loss_sweep() {
	ip netns exec "${KNS}" python3 - "${SERVER_TUNNEL_ADDR}" "${ECHO_PORT}" <<'PY'
import socket, struct, sys, time
dst = (sys.argv[1], int(sys.argv[2]))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setblocking(False)
sizes = list(range(8, 1301)); got = set(); seq = 0
def drain():
    while True:
        try:
            data = s.recv(65535)
        except BlockingIOError:
            return
        if len(data) >= 4:
            got.add(struct.unpack(">I", data[:4])[0])
for _ in range(3):
    for size in sizes:
        s.sendto(struct.pack(">I", seq) + bytes(size - 4), dst); seq += 1
        if seq % 20 == 0:
            time.sleep(0.004); drain()
end = time.time() + 4
while time.time() < end:
    drain(); time.sleep(0.05)
lost = [i for i in range(seq) if i not in got]
print(seq, len(lost), *sorted(set(sizes[i % len(sizes)] for i in lost))[:20])
PY
}
# A 4 MiB transfer from the server's side of the tunnel to a listener on the
# kernel client's tunnel address: the payload travels server -> client
# through BoringTun's shaped datagrams. The sender hashes what it sends and the
# receiver what it receives, independently; prints "<sent bytes> <sent
# SHA-256> <received bytes> <received SHA-256>", with "-" for a side that
# failed. Every step is bounded.
kernel_tcp_transfer() {
	local PORT_TCP=$((41000 + RANDOM % 1000)) RECEIVER SENDER_OUT RECEIVED
	rm -f "${WORK}/kreceived"
	ip netns exec "${KNS}" timeout 120 python3 - "${KCLIENT_ADDR}" "${PORT_TCP}" "${WORK}/kreceived" <<'PY' &
import hashlib, socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(1); s.settimeout(60)
c, _ = s.accept(); c.settimeout(60)
h = hashlib.sha256(); n = 0
while True:
    b = c.recv(65536)
    if not b:
        break
    h.update(b); n += len(b)
open(sys.argv[3], "w").write("%d %s\n" % (n, h.hexdigest()))
PY
	RECEIVER=$!
	for _ in $(seq 1 50); do
		ip netns exec "${KNS}" ss -Hltn "sport = :${PORT_TCP}" 2>/dev/null | grep -q . && break
		sleep 0.1
	done
	SENDER_OUT="$(timeout 120 python3 - "${KCLIENT_ADDR}" "${PORT_TCP}" <<'PY'
import hashlib, os, socket, sys
payload = os.urandom(4 * 1024 * 1024)
c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=30)
c.settimeout(60); c.sendall(payload); c.shutdown(socket.SHUT_WR)
c.recv(1)
c.close()
print(len(payload), hashlib.sha256(payload).hexdigest())
PY
)" || SENDER_OUT="- -"
	wait "${RECEIVER}" 2>/dev/null
	RECEIVED="$(cat "${WORK}/kreceived" 2>/dev/null)"
	printf '%s %s\n' "${SENDER_OUT:-- -}" "${RECEIVED:-- -}"
}
set_imitation_managed() { # <log> <protocol>
	timeout --kill-after=30 "${INSTALLER_TIMEOUT}" bash "${INSTALLER}" --set-boringtun-imitation "$2" >"${WORK}/$1" 2>&1 </dev/null
}

timeout --kill-after=30 "${INSTALLER_TIMEOUT}" bash "${INSTALLER}" --add-client kclient >"${WORK}/kclient-add.private" 2>&1 </dev/null
check "--add-client creates the kernel client's config (kept private)" test "$?" -eq 0
ip netns add "${KNS}"
ip link add "${KVETH_HOST}" type veth peer name "${KVETH_CLIENT}"
ip link set "${KVETH_CLIENT}" netns "${KNS}"
ip addr add 192.0.2.1/24 dev "${KVETH_HOST}"
ip link set "${KVETH_HOST}" up
ip -n "${KNS}" addr add 192.0.2.2/24 dev "${KVETH_CLIENT}"
ip -n "${KNS}" link set "${KVETH_CLIENT}" up
ip -n "${KNS}" link set lo up
python3 -c 'import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, peer = s.recvfrom(65535); s.sendto(data, peer)' "${SERVER_TUNNEL_ADDR}" "${ECHO_PORT}" &
ECHO_PID=$!
check "--enable-awg3 succeeds for the interop" run_managed interop-awg3.log --enable-awg3
KCLIENT_CONF="$(find /etc/amnezia/amneziawg/clients /root /home -maxdepth 2 -name "${IF}-client-kclient.conf" 2>/dev/null | head -n 1)"
KCLIENT_ADDR="$(sed -n 's/^Address = \([0-9.]*\)\/32.*/\1/p' "${KCLIENT_CONF}" | head -n 1)"
INTEROP_PROTOCOL="AWG 3.0"
check "(the module is loaded behind the override for the client)" load_module_behind_override
if ! kernel_client_up; then
	note "the kernel client does not accept the AWG 3.0 config: $(head -c 300 "${WORK}/kclient-setconf.err" | tr '\n' ' ')"
	kernel_client_down
	unload_module
	check "back to AWG 2.0 for the interop" run_managed interop-awg2.log --disable-awg3
	INTEROP_PROTOCOL="AWG 2.0"
	check "(the module is loaded behind the override again)" load_module_behind_override
	kernel_client_up
fi
for PROTOCOL in none dns quic stun; do
	if [[ "${PROTOCOL}" != none ]]; then
		kernel_client_down
		unload_module
		check "${INTEROP_PROTOCOL}: --set-boringtun-imitation ${PROTOCOL} succeeds with the module unloaded" \
			set_imitation_managed "interop-${PROTOCOL}.log" "${PROTOCOL}"
		check "  (the module is loaded behind the override again)" load_module_behind_override
		kernel_client_up
	fi
	check "${INTEROP_PROTOCOL} + ${PROTOCOL}: the running server is still BoringTun" test -e "/sys/class/net/${IF}/tun_flags"
	check "${INTEROP_PROTOCOL} + ${PROTOCOL}: the daemon runs --imitate-protocol ${PROTOCOL}" \
		bash -c '[[ "$(tr "\0" " " <"/proc/$(systemctl show -p MainPID --value "$1")/cmdline")" == *"--imitate-protocol $2 "* ]]' _ "${UNIT}" "${PROTOCOL}"
	if kernel_reachable; then
		ok "${INTEROP_PROTOCOL} + ${PROTOCOL}: the kernel client completes a handshake and reaches the server"
		SENT="" LOST="" LOST_SIZES=""
		read -r SENT LOST LOST_SIZES <<<"$(loss_sweep)"
		# Measurement, not a policy: any loss is reported, and only an echo
		# service that answers nothing fails.
		check "${INTEROP_PROTOCOL} + ${PROTOCOL}: the UDP sweep ran and echoes came back through the tunnel" \
			test -n "${SENT}" -a -n "${LOST}" -a "${LOST:-0}" -lt "${SENT:-0}"
		SENT_BYTES="" SENT_SHA="" GOT_BYTES="" GOT_SHA=""
		read -r SENT_BYTES SENT_SHA GOT_BYTES GOT_SHA <<<"$(kernel_tcp_transfer)"
		check "${INTEROP_PROTOCOL} + ${PROTOCOL}: a 4 MiB TCP transfer from the server to the kernel client completes" \
			test "${SENT_BYTES}" = 4194304 -a -n "${GOT_BYTES}" -a "${GOT_BYTES}" != -
		check "  with the same byte count at both ends (${GOT_BYTES:-?}/${SENT_BYTES:-?})" test "${GOT_BYTES}" = "${SENT_BYTES}"
		check "  and the same SHA-256 at both ends (${GOT_SHA:0:16}…)" test -n "${SENT_SHA}" -a "${SENT_SHA}" != - -a "${GOT_SHA}" = "${SENT_SHA}"
		note "${INTEROP_PROTOCOL} + ${PROTOCOL} imitation, kernel client:"
		echo "    UDP echo: ${LOST:-?} / ${SENT:-?} lost${LOST_SIZES:+ (payload sizes ${LOST_SIZES})}"
		if [[ -n "${SENT_SHA}" && "${SENT_SHA}" != - && "${GOT_SHA}" == "${SENT_SHA}" && "${GOT_BYTES}" == "${SENT_BYTES}" ]]; then
			echo "    TCP server -> client: ${GOT_BYTES} bytes, SHA-256 match"
		else
			echo "    TCP server -> client: sent ${SENT_BYTES:-?} bytes, received ${GOT_BYTES:-?} bytes, SHA-256 mismatch or incomplete"
		fi
	else
		bad "${INTEROP_PROTOCOL} + ${PROTOCOL}: the kernel client completes a handshake and reaches the server"
	fi
done
kill "${ECHO_PID}" 2>/dev/null
kernel_client_down
ip netns delete "${KNS}" 2>/dev/null
ip link delete "${KVETH_HOST}" 2>/dev/null
unload_module
check "the module is unloaded again" bash -c '! [[ -e /sys/module/amneziawg ]]'

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
