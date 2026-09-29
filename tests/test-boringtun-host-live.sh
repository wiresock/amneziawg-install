#!/bin/bash
# Live end-to-end test of the experimental BoringTun host backend on a
# disposable systemd host, for example a GitHub-hosted Ubuntu runner. Unlike
# tests/test-boringtun-runtime-live.sh, nothing is provisioned by hand: the
# installer itself runs `AWG_BACKEND=boringtun AUTO_INSTALL=y`, which installs
# amneziawg-tools from the Amnezia PPA and downloads the immutable public
# BoringTun release. The test then checks the installed host, moves data
# through the tunnel from a client in a network namespace (a second BoringTun,
# configured with the installer-generated client config) under AWG 2.0, 3.0,
# 3.1 and back to 2.0, manages clients, restarts, stops, kills the daemon, and
# finally uninstalls through the menu and audits what is left.
#
# Requirements: root, systemd as PID 1, network access to the Amnezia PPA and
# GitHub, no AmneziaWG kernel module, python3, and AWG_DISPOSABLE_HOST_TEST=1.
# Nothing here is imitation: built-in protocol imitation is not part of this
# installer version.
#
# Usage: AWG_DISPOSABLE_HOST_TEST=1 bash tests/test-boringtun-host-live.sh

set -uo pipefail

# Everything this test prints lands in public CI logs. It therefore runs
# itself under a scan of its own output: once it has finished, no private or
# preshared key of the server or of a client (the test records them in a
# private file, never printing them), no client config and no QR code may
# appear in what it printed. Client configs and QR codes are only ever written
# to private files.
if [[ -z "${AWG_LIVE_SECRET_SCAN:-}" ]]; then
	SCAN_DIR="$(mktemp -d)" || exit 2
	chmod 0700 "${SCAN_DIR}"
	: >"${SCAN_DIR}/secrets"
	AWG_LIVE_SECRET_SCAN="${SCAN_DIR}/secrets" bash "${BASH_SOURCE[0]}" "$@" 2>&1 | tee "${SCAN_DIR}/public.log"
	RC=${PIPESTATUS[0]}
	echo "=== Secret scan of this test's output"
	if [[ ! -s "${SCAN_DIR}/secrets" ]]; then
		echo "  FAIL: no key was recorded to look for"
		RC=1
	elif grep -qF -f "${SCAN_DIR}/secrets" "${SCAN_DIR}/public.log"; then
		echo "  FAIL: a private or preshared key appears in this test's output"
		RC=1
	else
		echo "  OK: none of the $(grep -c . "${SCAN_DIR}/secrets") recorded private and preshared keys appears in this test's output"
	fi
	if grep -qE '(Private|Preshared)Key[[:space:]]*=|^\[(Interface|Peer)\]' "${SCAN_DIR}/public.log"; then
		echo "  FAIL: a client or server config appears in this test's output"
		RC=1
	else
		echo "  OK: no config appears in this test's output"
	fi
	if grep -q '[▀▄█]' "${SCAN_DIR}/public.log"; then
		echo "  FAIL: QR code rows appear in this test's output"
		RC=1
	else
		echo "  OK: no QR code appears in this test's output"
	fi
	rm -rf -- "${SCAN_DIR}"
	exit "${RC}"
fi
# record_secret <value>: a key the output scan looks for, never printed.
record_secret() {
	[[ -n "$1" ]] && printf '%s\n' "$1" >>"${AWG_LIVE_SECRET_SCAN}"
}
# record_config_secrets <config>: its private and preshared keys.
record_config_secrets() {
	local KEY
	while IFS= read -r KEY; do
		record_secret "${KEY}"
	done < <(sed -n 's/^[[:space:]]*\(PrivateKey\|PresharedKey\)[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\2/p' "$1")
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"
IF="awg0"
UNIT="awg-quick@${IF}.service"
PORT=51820
NS="awgcli"
VETH_HOST="awgvh0"
VETH_CLIENT="awgvc0"
HOST_ADDR="192.0.2.1"
CLIENT_ADDR="192.0.2.2"
CLIENT_IF="awgc0"
SERVER_TUNNEL_ADDR="10.66.66.1"
WORK="/var/tmp/awg-host-live"
CLIENT_BIN="${WORK}/boringtun-client"
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
check() { # <message> <command...>
	local MESSAGE="$1"
	shift
	if "$@"; then ok "${MESSAGE}"; else bad "${MESSAGE}"; fi
}
wait_for() { # <seconds> <command...>
	local LIMIT="$1" I
	shift
	for ((I = 0; I < LIMIT * 5; I++)); do
		"$@" && return 0
		sleep 0.2
	done
	return 1
}

[[ "${AWG_DISPOSABLE_HOST_TEST:-}" == 1 ]] ||
	die "this test installs and uninstalls AmneziaWG; set AWG_DISPOSABLE_HOST_TEST=1 on a disposable host"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -d /run/systemd/system ]] || die "systemd must be PID 1"
[[ ! -e /etc/amnezia/amneziawg/params ]] || die "AmneziaWG is already installed on this host"
for TOOL in python3 curl ip sha256sum; do
	command -v "${TOOL}" >/dev/null 2>&1 || die "${TOOL} is required"
done

# The embedded release, read from the installer as data.
installer_value() {
	sed -n "s/^$1=\"\\(.*\\)\"\$/\\1/p" "${INSTALLER}"
}
case "$(uname -m)" in
	x86_64 | amd64) ARCH=x86_64 ARCH_KEY=X86_64 ;;
	aarch64 | arm64) ARCH=aarch64 ARCH_KEY=AARCH64 ;;
	*) die "no BoringTun release for $(uname -m)" ;;
esac
RELEASE_TAG="$(installer_value AWG_BT_RELEASE_TAG)"
ASSET="$(installer_value "AWG_BT_RELEASE_ASSET_${ARCH_KEY}")"
BINARY_SHA256="$(installer_value "AWG_BT_RELEASE_BINARY_SHA256_${ARCH_KEY}")"
RELEASE_ID="${ASSET%.tar.gz}"
STORE="/usr/local/lib/amneziawg-install/boringtun"

main_pid() {
	systemctl show -p MainPID --value "${UNIT}"
}
fd_count() {
	find "/proc/$1/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l
}
peer_count() {
	awg show "${IF}" peers 2>/dev/null | grep -c .
}
# The firewall rules this interface's PostUp hooks added, as the firewall
# lists them: its own nft table when the installer chose nftables, otherwise
# the iptables rules that name the interface, its port or the masquerade on
# the public interface. A rule duplicated by a restart shows as a difference.
# Fails when the rules cannot be read.
owned_firewall() {
	local TABLE SAVED
	TABLE="$(sed -n 's/^PostUp = nft add table \(ip\|inet\) \(awg-[A-Za-z0-9_.-]*\)$/\1 \2/p' "/etc/amnezia/amneziawg/${IF}.conf" | head -n 1)"
	if [[ -n "${TABLE}" ]]; then
		# shellcheck disable=SC2086 # the family and the table's name
		nft list table ${TABLE}
		return
	fi
	SAVED="$(iptables-save)" || return 1
	grep -E -- "(-[io] ${IF}( |$)|--dport ${PORT}( |$)|-o ${PUBLIC_NIC} -j MASQUERADE)" <<<"${SAVED}" | LC_ALL=C sort
}
no_kernel_module() {
	[[ ! -e /sys/module/amneziawg ]]
}
scratch_clean() {
	[[ -z "$(ip -o link show 2>/dev/null | grep -oE ' awg[pvb][0-9]+' || true)" ]] &&
		[[ -z "$(find /run/amneziawg-install/scratch -mindepth 1 2>/dev/null)" ]] &&
		[[ -z "$(systemctl list-units --all --plain --no-legend 'amneziawg-scratch-*' 2>/dev/null)" ]]
}

dump_diagnostics() {
	echo "=== diagnostics"
	systemctl status "${UNIT}" --no-pager 2>&1 | tail -n 25
	journalctl -u "${UNIT}" --no-pager -n 80 2>&1
	ip -d link show 2>&1
	ip -n "${NS}" -d link show 2>&1
	awg show 2>&1
	ls -la /run/amneziawg-install /run/amneziawg-install/scratch /var/run/wireguard /var/run/amneziawg 2>&1
	ss -xlp 2>&1 | grep -E 'wireguard|amneziawg' || true
}

CLIENT_PID=""
LISTENER_PIDS=()
cleanup() {
	local RC=$?
	trap - EXIT
	((FAILED == 0)) || dump_diagnostics
	[[ -n "${CLIENT_PID}" ]] && kill "${CLIENT_PID}" 2>/dev/null
	local PID
	for PID in "${LISTENER_PIDS[@]}"; do
		kill "${PID}" 2>/dev/null
	done
	ip netns delete "${NS}" 2>/dev/null
	ip link delete "${VETH_HOST}" 2>/dev/null
	rm -f "/var/run/wireguard/${CLIENT_IF}.sock" "/var/run/amneziawg/${CLIENT_IF}.sock"
	rm -rf "${WORK}"
	exit "${RC}"
}
trap cleanup EXIT
mkdir -p "${WORK}"
chmod 0700 "${WORK}"

echo "=== Host"
uname -srm
. /etc/os-release
echo "${PRETTY_NAME}"
check "no AmneziaWG kernel module is loaded or installed before the install" \
	bash -c '[[ ! -e /sys/module/amneziawg ]] && ! modinfo -n amneziawg >/dev/null 2>&1'

# The client's network: a namespace joined to the host by a veth pair. The
# server's public address for the clients is the host end.
ip netns add "${NS}" || die "cannot create network namespace ${NS}"
ip link add "${VETH_HOST}" type veth peer name "${VETH_CLIENT}"
ip link set "${VETH_CLIENT}" netns "${NS}"
ip addr add "${HOST_ADDR}/24" dev "${VETH_HOST}"
ip link set "${VETH_HOST}" up
ip -n "${NS}" addr add "${CLIENT_ADDR}/24" dev "${VETH_CLIENT}"
ip -n "${NS}" link set "${VETH_CLIENT}" up
ip -n "${NS}" link set lo up
PUBLIC_NIC="$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
[[ -n "${PUBLIC_NIC}" ]] || die "no default route"

echo "=== Fresh install: AWG_BACKEND=boringtun AUTO_INSTALL=y"
# Without an initial client, so that the install output holds no client
# config or QR code; the client is added below, its output kept private.
env AWG_BACKEND=boringtun AUTO_INSTALL=y SERVER_PUB_IP="${HOST_ADDR}" SERVER_PUB_NIC="${PUBLIC_NIC}" \
	SERVER_AWG_NIC="${IF}" SERVER_PORT="${PORT}" ENABLE_IPV6=n CREATE_INITIAL_CLIENT=n \
	bash "${INSTALLER}" >"${WORK}/install.log" 2>&1 </dev/null
INSTALL_RC=$?
tail -n 25 "${WORK}/install.log" | sed 's/^/    | /'
check "the installer completes" test "${INSTALL_RC}" -eq 0
((INSTALL_RC == 0)) || die "the install failed; nothing more to test"
record_secret "$(sed -n "s/^SERVER_PRIV_KEY='\\(.*\\)'\$/\\1/p" /etc/amnezia/amneziawg/params)"
bash "${INSTALLER}" --add-client client >"${WORK}/client-add.private" 2>&1 </dev/null
check "--add-client creates the test client (its output, config and QR code stay private)" test "$?" -eq 0
check "it downloaded the public release ${RELEASE_TAG}" \
	grep -qF "Downloading https://github.com/wiresock/amneziawg-install/releases/download/${RELEASE_TAG}/${ASSET}" "${WORK}/install.log"
check "the BoringTun preflight passed" grep -qF "BoringTun preflight passed" "${WORK}/install.log"
check "no AmneziaWG kernel module is loaded" no_kernel_module
check "no AmneziaWG kernel module is installed" bash -c '! modinfo -n amneziawg >/dev/null 2>&1'
check "amneziawg-tools is installed" bash -c 'dpkg-query -W -f="\${Status}" amneziawg-tools | grep -q "install ok installed"'
for PACKAGE in amneziawg amneziawg-dkms dkms; do
	check "${PACKAGE} was not pulled in" bash -c "! dpkg-query -W -f='\${Status}' ${PACKAGE} 2>/dev/null | grep -q 'install ok installed'"
done
check "no amneziawg.ko was built" test -z "$(find /lib/modules -name 'amneziawg.ko*' -print -quit 2>/dev/null)"
check "the store selects ${RELEASE_ID}" test "$(readlink "${STORE}/current")" = "${RELEASE_ID}"
check "the installed binary has the embedded SHA-256" test "$(sha256sum "${STORE}/${RELEASE_ID}/boringtun-cli" | cut -d' ' -f1)" = "${BINARY_SHA256}"
check "the embedded SHA-256 is the release contract's" \
	grep -qx "BORINGTUN_RELEASE_BINARY_SHA256_${ARCH_KEY}=${BINARY_SHA256}" "${PROJECT_ROOT}/packaging/boringtun/release.env"
check "the store verifies" bash -c 'source "$1" && _awgBtVerifyStore' _ "${INSTALLER}"
check "the helpers are root-owned, mode 0755" \
	test "$(stat -c '%u %a' /usr/local/libexec/amneziawg-install/awg-boringtun-launch /usr/local/libexec/amneziawg-install/awg-backend-ctl | tr '\n' ' ')" = "0 755 0 755 "
check "params persist AWG_BACKEND='boringtun'" grep -qx "AWG_BACKEND='boringtun'" /etc/amnezia/amneziawg/params
check "the runtime file is root-owned, mode 0600" test "$(stat -c '%u %a' "/etc/amnezia/amneziawg/${IF}.boringtun")" = "0 600"
check "no modules-load entry and no load override were written" test ! -e /etc/modules-load.d/amneziawg.conf -a ! -e /etc/modprobe.d/amneziawg-install-boringtun.conf

check_served() { # <label>
	local PID
	PID="$(main_pid)"
	check "$1: ${UNIT} is active" systemctl is-active --quiet "${UNIT}"
	check "$1: its MainPID runs the verified BoringTun binary" \
		test "$(readlink "/proc/${PID}/exe" 2>/dev/null)" = "$(readlink -f "${STORE}/${RELEASE_ID}/boringtun-cli")"
	check "$1: ${IF} is a TUN device" test -e "/sys/class/net/${IF}/tun_flags"
	check "$1: its UAPI answers" test "$(awg show "${IF}" listen-port 2>/dev/null)" = "${PORT}"
	check "$1: the active instance is the one its start recorded" \
		bash -c 'source "$1" && _awgBtCheckServedByBoringtun "$2"' _ "${INSTALLER}" "${IF}"
	check "$1: no AmneziaWG kernel module is loaded" no_kernel_module
}
check_served "after the install"
check "awg show works" bash -c "awg show '${IF}' >/dev/null"
check "awg show all dump lists the interface" bash -c "awg show all dump | grep -q '^${IF}[[:space:]]'"

# ── Datapath ────────────────────────────────────────────────────────────────
# The client is a copy of the verified binary (outside the store, so the
# uninstall's daemon check never mistakes it for the server) in the namespace.
cp -- "${STORE}/${RELEASE_ID}/boringtun-cli" "${CLIENT_BIN}"
CLIENT_CONF="$(find /root /home -maxdepth 2 -name "${IF}-client-client.conf" 2>/dev/null | head -n 1)"
[[ -n "${CLIENT_CONF}" ]] || die "the installer did not write the test client's config"
record_config_secrets "${CLIENT_CONF}"
CLIENT_TUNNEL_ADDR="$(sed -n 's/^Address = \([0-9.]*\)\/32.*/\1/p' "${CLIENT_CONF}" | head -n 1)"

stop_client() {
	if [[ -n "${CLIENT_PID}" ]]; then
		kill "${CLIENT_PID}" 2>/dev/null
		wait "${CLIENT_PID}" 2>/dev/null
		CLIENT_PID=""
	fi
	rm -f "/var/run/wireguard/${CLIENT_IF}.sock" "/var/run/amneziawg/${CLIENT_IF}.sock"
}
# A client that connects with the installer-generated config as it is now,
# for the current protocol mode, the way a user's client reconnects with a
# redistributed config. awg-quick strip takes the interface name from the file
# name, so the config is copied under the client interface's name first.
start_client() {
	stop_client
	ip netns exec "${NS}" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "${CLIENT_BIN}" --foreground --disable-drop-privileges \
		--verbosity error "${CLIENT_IF}" >"${WORK}/client.log" 2>&1 &
	CLIENT_PID=$!
	if ! wait_for 10 test -S "/var/run/wireguard/${CLIENT_IF}.sock"; then
		sed 's/^/    client | /' "${WORK}/client.log"
		return 1
	fi
	install -m 0600 "${CLIENT_CONF}" "${WORK}/${CLIENT_IF}.conf" &&
		awg-quick strip "${WORK}/${CLIENT_IF}.conf" >"${WORK}/client.setconf" &&
		awg setconf "${CLIENT_IF}" "${WORK}/client.setconf" &&
		ip -n "${NS}" addr add "${CLIENT_TUNNEL_ADDR}/32" dev "${CLIENT_IF}" &&
		ip -n "${NS}" link set "${CLIENT_IF}" up &&
		ip -n "${NS}" route add "${SERVER_TUNNEL_ADDR}/32" dev "${CLIENT_IF}"
}
show_tunnel_state() {
	echo "    --- client ${CLIENT_IF}"
	awg show "${CLIENT_IF}" 2>&1 | sed 's/^/    | /'
	sed 's/^/    client log | /' "${WORK}/client.log"
	echo "    --- server ${IF}"
	awg show "${IF}" 2>&1 | sed 's/^/    | /'
}
tunnel_ping() {
	ip netns exec "${NS}" ping -c 1 -W 1 "${SERVER_TUNNEL_ADDR}" >/dev/null 2>&1
}
# A checksummed TCP transfer from the client to a listener on the server's
# tunnel address.
tcp_transfer() { # <label>
	local LABEL="$1" PORT_TCP=$((40000 + RANDOM % 20000)) SENT GOT
	head -c 4194304 /dev/urandom >"${WORK}/payload"
	SENT="$(sha256sum "${WORK}/payload" | cut -d' ' -f1)"
	rm -f "${WORK}/received.sha256"
	python3 - "${SERVER_TUNNEL_ADDR}" "${PORT_TCP}" "${WORK}/received.sha256" <<'PY' &
import hashlib, socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(1); s.settimeout(60)
c, _ = s.accept(); h = hashlib.sha256()
while True:
    b = c.recv(65536)
    if not b: break
    h.update(b)
open(sys.argv[3], "w").write(h.hexdigest())
PY
	LISTENER_PIDS+=("$!")
	sleep 0.5
	ip netns exec "${NS}" timeout 60 python3 - "${SERVER_TUNNEL_ADDR}" "${PORT_TCP}" "${WORK}/payload" <<'PY'
import socket, sys
c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=30)
c.sendall(open(sys.argv[3], "rb").read()); c.close()
PY
	wait_for 30 test -s "${WORK}/received.sha256"
	GOT="$(cat "${WORK}/received.sha256" 2>/dev/null)"
	check "${LABEL}: a 4 MiB TCP transfer through the tunnel arrives intact (sha256 ${SENT:0:16}…)" test "${GOT}" = "${SENT}"
}
datapath() { # <label>
	if ! start_client; then
		bad "$1: the namespace client could not start with the generated config"
		return
	fi
	if wait_for 20 tunnel_ping; then
		ok "$1: the client in the namespace reaches ${SERVER_TUNNEL_ADDR} through the tunnel (ping)"
	else
		bad "$1: the client in the namespace reaches ${SERVER_TUNNEL_ADDR} through the tunnel (ping)"
		show_tunnel_state
	fi
	tcp_transfer "$1"
}
datapath "AWG 2.0"
check "the server recorded a handshake with the client" \
	bash -c "awg show '${IF}' latest-handshakes | awk '{ if (\$2 > 0) found = 1 } END { exit !found }'"

# ── Client management through the installer ─────────────────────────────────
PID="$(main_pid)"
FDS_BEFORE="$(fd_count "${PID}")"
PEERS_BEFORE="$(peer_count)"
bash "${INSTALLER}" --add-client alice >/dev/null 2>&1
check "--add-client adds a peer" test "$(peer_count)" -eq $((PEERS_BEFORE + 1))
bash "${INSTALLER}" --list-clients >"${WORK}/clients" 2>&1
check "--list-clients lists it" grep -qx alice "${WORK}/clients"
bash "${INSTALLER}" --remove-client alice >/dev/null 2>&1
check "--remove-client removes it" test "$(peer_count)" -eq "${PEERS_BEFORE}"
check "the filtered sync keeps the daemon and its port" test "$(main_pid)" = "${PID}" -a "$(awg show "${IF}" listen-port)" = "${PORT}"
for I in $(seq 1 10); do
	bash "${INSTALLER}" --add-client "cycle${I}" >/dev/null 2>&1
	bash "${INSTALLER}" --remove-client "cycle${I}" >/dev/null 2>&1
done
FDS_AFTER="$(fd_count "${PID}")"
check "BoringTun's descriptor count is stable over 10 add/remove cycles (${FDS_BEFORE} -> ${FDS_AFTER})" test "${FDS_AFTER}" -eq "${FDS_BEFORE}"
check "and the same daemon still serves the interface" test "$(main_pid)" = "${PID}"
check "the test client still reaches the server" wait_for 10 tunnel_ping

# ── Service lifecycle ───────────────────────────────────────────────────────
FIREWALL="$(owned_firewall)"
check "the interface's own firewall rules can be read and are present ($(grep -c . <<<"${FIREWALL}") lines)" test -n "${FIREWALL}"
same_firewall() { # <after what>
	local NOW
	NOW="$(owned_firewall)" || NOW="(unreadable)"
	check "the interface's own firewall rules are exactly as before, none duplicated, $1" test "${NOW}" = "${FIREWALL}"
}
systemctl restart "${UNIT}"
check "restart succeeds" test "$?" -eq 0
check "restart starts a new daemon" test "$(main_pid)" != "${PID}"
check_served "after restart"
check "the client reconnects after the restart" wait_for 20 tunnel_ping
same_firewall "after restart"
systemctl stop "${UNIT}"
check "stop leaves the unit inactive" bash -c "! systemctl is-active --quiet '${UNIT}'"
check "and removes the link and sockets" test ! -e "/sys/class/net/${IF}" -a ! -e "/var/run/wireguard/${IF}.sock"
check "and the interface's firewall rules" test -z "$(owned_firewall 2>/dev/null)"
systemctl start "${UNIT}"
check "start succeeds again" test "$?" -eq 0
check_served "after stop and start"
same_firewall "after stop and start"
PID="$(main_pid)"
RESTARTS="$(systemctl show -p NRestarts --value "${UNIT}")"
kill -KILL "${PID}"
check "systemd restarts the unit after SIGKILL" \
	wait_for 30 bash -c "[[ \"\$(systemctl show -p NRestarts --value '${UNIT}')\" -gt ${RESTARTS} ]] && systemctl is-active --quiet '${UNIT}'"
check_served "after SIGKILL recovery"
same_firewall "after SIGKILL recovery"
check "the client reconnects after the crash" wait_for 20 tunnel_ping

# ── Protocol modes ──────────────────────────────────────────────────────────
protocol_mode() { # <flag> <label> <expected version>
	bash "${INSTALLER}" "$1" >"${WORK}/protocol.log" 2>&1 </dev/null
	local RC=$?
	tail -n 5 "${WORK}/protocol.log" | sed 's/^/    | /'
	check "$2: ${1} succeeds" test "${RC}" -eq 0
	check "$2: the installer reports protocol $3" test "$(bash "${INSTALLER}" --protocol-status 2>/dev/null)" = "$3"
	check "$2: the backend is still BoringTun" grep -qx "AWG_BACKEND='boringtun'" /etc/amnezia/amneziawg/params
	check_served "$2"
	check "$2: no scratch interface, unit or record is left" scratch_clean
	datapath "$2"
}
protocol_mode --enable-awg3 "AWG 3.0" 3
protocol_mode --enable-awg31 "AWG 3.1" 3.1
protocol_mode --disable-awg3 "back to AWG 2.0" 2

# ── Uninstall ───────────────────────────────────────────────────────────────
stop_client
# A socket some other process serves must survive the uninstall.
python3 -c 'import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); time.sleep(600)' /var/run/wireguard/foreign9.sock &
LISTENER_PIDS+=("$!")
wait_for 5 test -S /var/run/wireguard/foreign9.sock
printf '6\ny\n' | bash "${INSTALLER}" >"${WORK}/uninstall.log" 2>&1
UNINSTALL_RC=$?
tail -n 8 "${WORK}/uninstall.log" | sed 's/^/    | /'
check "the uninstall succeeds" test "${UNINSTALL_RC}" -eq 0
check "no BoringTun process remains" bash -c '! pgrep -x boringtun-cli >/dev/null'
check "the unit is inactive and disabled" bash -c "! systemctl is-active --quiet '${UNIT}' && ! systemctl is-enabled --quiet '${UNIT}'"
check "the link is gone" test ! -e "/sys/class/net/${IF}"
check "the store is gone" test ! -e /usr/local/lib/amneziawg-install
check "the helpers are gone" test ! -e /usr/local/libexec/amneziawg-install
check "the drop-in is gone" test ! -e "/etc/systemd/system/${UNIT}.d"
check "the configuration is gone" test ! -e /etc/amnezia/amneziawg
check "the runtime state is gone" test -z "$(find /run/amneziawg-install -mindepth 1 2>/dev/null)"
check "the interface's UAPI sockets are gone" test ! -e "/var/run/wireguard/${IF}.sock" -a ! -e "/var/run/amneziawg/${IF}.sock"
check "a socket another process serves is left alone" test -S /var/run/wireguard/foreign9.sock
check "amneziawg-tools is removed" bash -c '! dpkg-query -W -f="\${Status}" amneziawg-tools 2>/dev/null | grep -q "install ok installed"'
check "no AmneziaWG kernel module appeared at any point" no_kernel_module

echo
echo "BoringTun host live test (${ARCH}): ${PASSED} passed, ${FAILED} failed"
((FAILED == 0))
