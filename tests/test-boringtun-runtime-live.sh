#!/bin/bash
# Live test of the supervised BoringTun runtime on a disposable systemd host,
# for example a GitHub-hosted Ubuntu runner. It is not an installer smoke test:
# the host is provisioned by hand. The test unpacks a packaged boringtun-cli
# archive into the runtime store, selects the BoringTun runtime through the
# installer's internal test hook, and drives awg-quick@<if>.service through
# start, reload, restart, stop, a SIGKILL crash, an operator's `ip link del`,
# repeated unchanged-port syncs and AWG 2.0/3.0/3.1 validation on scratch
# instances. It cleans up after itself, also on failure.
#
# Requirements: root, systemd as PID 1, amneziawg-tools (awg, awg-quick and
# awg-quick@.service) installed without the AmneziaWG kernel module, iptables,
# python3, and AWG_DISPOSABLE_RUNTIME_TEST=1.
#
# Usage: AWG_DISPOSABLE_RUNTIME_TEST=1 bash tests/test-boringtun-runtime-live.sh <archive.tar.gz>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARCHIVE="${1:-}"
IF="awgbt0"
PORT=51899
UNIT="awg-quick@${IF}.service"
HOOK_LOG="/run/awgbt-live-hooks.log"
RULE_COMMENT="awgbt-live-test"
WORK_DIR=""
PASSED=0
FAILED=0

function die() {
	echo "ERROR: $*" >&2
	exit 2
}

function ok() {
	echo "  OK: $1"
	PASSED=$((PASSED + 1))
}

function bad() {
	echo "  FAIL: $1"
	FAILED=$((FAILED + 1))
}

function check() { # <message> <command...>
	local MESSAGE="$1"
	shift
	if "$@"; then ok "${MESSAGE}"; else bad "${MESSAGE}"; fi
}

[[ "${AWG_DISPOSABLE_RUNTIME_TEST:-}" == 1 ]] ||
	die "this test reconfigures systemd, iptables and /usr/local; set AWG_DISPOSABLE_RUNTIME_TEST=1 on a disposable host"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -d /run/systemd/system ]] || die "systemd must be PID 1"
[[ -f "${ARCHIVE}" ]] || die "usage: $0 <boringtun-cli archive.tar.gz>"
for TOOL in awg awg-quick iptables python3 systemd-run; do
	command -v "${TOOL}" >/dev/null 2>&1 || die "${TOOL} is required"
done

# shellcheck source=../amneziawg-install.sh
source "${PROJECT_ROOT}/amneziawg-install.sh"
STEM="$(basename "${ARCHIVE}" .tar.gz)"
BIN="${AWG_BT_STORE_DIR}/${STEM}/boringtun-cli"

function rule_count() {
	iptables -S INPUT 2>/dev/null | grep -c -- "--comment ${RULE_COMMENT}"
}

function main_pid() {
	systemctl show -p MainPID --value "${UNIT}"
}

function fd_count() {
	find "/proc/$1/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l
}

function dump_diagnostics() {
	echo "=== diagnostics"
	systemctl status "${UNIT}" --no-pager 2>&1 | tail -n 20
	journalctl -u "${UNIT}" --no-pager -n 60 2>&1
	ls -la /run/amneziawg-install /var/run/wireguard /var/run/amneziawg 2>&1
	ip -d link show "${IF}" 2>&1
}

function cleanup() {
	local RC=$?
	trap - EXIT
	systemctl stop "${UNIT}" >/dev/null 2>&1
	systemctl reset-failed "${UNIT}" >/dev/null 2>&1
	ip link delete "${IF}" >/dev/null 2>&1
	while iptables -D INPUT -p udp --dport "${PORT}" -m comment --comment "${RULE_COMMENT}" -j ACCEPT 2>/dev/null; do :; done
	rm -rf -- "/etc/systemd/system/awg-quick@${IF}.service.d" "${AWG_BT_LIBEXEC_DIR}" "${AWG_BT_STORE_DIR%/boringtun}" \
		"${AWG_BT_RUN_DIR}" "${AWG_BT_CONFIG_DIR}/${IF}.conf" "${AWG_BT_CONFIG_DIR}/${IF}.boringtun" "${HOOK_LOG}" \
		"${WORK_DIR}"
	rm -f -- "/var/run/wireguard/${IF}.sock" "/var/run/amneziawg/${IF}.sock"
	systemctl daemon-reload
	exit "${RC}"
}
trap cleanup EXIT

echo "=== Host"
uname -srm
awg --version
systemctl --version | head -n 1
if [[ -e /sys/module/amneziawg ]] || modinfo -n amneziawg >/dev/null 2>&1; then
	die "the AmneziaWG kernel module is present; this test needs a host where awg-quick cannot take the kernel path"
fi
ok "no AmneziaWG kernel module is loaded or installed, so awg-quick cannot take the kernel path"
grep -xF 'ExecStart=/usr/bin/awg-quick up %i' /usr/lib/systemd/system/awg-quick@.service /lib/systemd/system/awg-quick@.service 2>/dev/null | head -n 1

echo "=== Provision the BoringTun store by hand"
install -d -m 0755 -o root -g root "${AWG_BT_STORE_DIR%/boringtun}" "${AWG_BT_STORE_DIR}"
tar -xzf "${ARCHIVE}" -C "${AWG_BT_STORE_DIR}" --no-same-owner
chown -R root:root "${AWG_BT_STORE_DIR}"
ln -s "${STEM}" "${AWG_BT_STORE_DIR}/current"
ls -la "${AWG_BT_STORE_DIR}" "${AWG_BT_STORE_DIR}/${STEM}"
check "the store verifies" _awgBtVerifyStore
check "and resolves to the unpacked binary" test "${_AWG_BT_VERIFIED_BIN}" = "$(readlink -f "${BIN}")"

echo "=== Server config and the internal BoringTun runtime"
install -d -m 0700 "${AWG_BT_CONFIG_DIR}"
SERVER_KEY="$(awg genkey)"
PEER_PUB="$(awg genkey | awg pubkey)"
cat >"${AWG_BT_CONFIG_DIR}/${IF}.conf" <<EOF
[Interface]
Address = 10.99.0.1/24
ListenPort = ${PORT}
PrivateKey = ${SERVER_KEY}
Jc = 3
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 30
H1 = 111111
H2 = 222222
H3 = 333333
H4 = 444444
PostUp = iptables -I INPUT -p udp --dport ${PORT} -m comment --comment ${RULE_COMMENT} -j ACCEPT; echo up-%i >>${HOOK_LOG}
PostDown = iptables -D INPUT -p udp --dport ${PORT} -m comment --comment ${RULE_COMMENT} -j ACCEPT; echo down-%i >>${HOOK_LOG}

[Peer]
PublicKey = ${PEER_PUB}
AllowedIPs = 10.99.0.2/32
EOF
chmod 0600 "${AWG_BT_CONFIG_DIR}/${IF}.conf"
: >"${HOOK_LOG}"
_awgInternalSelectBoringtunRuntimeForTesting
# shellcheck disable=SC2034 # read by ensureAwgBackendReady
SERVER_AWG_NIC="${IF}"
(ensureAwgBackendReady 1)
check "ensureAwgBackendReady 1 prepares the runtime and starts ${UNIT}" test "$?" -eq 0
cat "/etc/systemd/system/awg-quick@${IF}.service.d/override.conf"
check "the drop-in is the rendered BoringTun drop-in" \
	cmp -s "/etc/systemd/system/awg-quick@${IF}.service.d/override.conf" <(_awgBtRenderServiceDropIn)

# check_running <label>: everything that must hold while the unit serves.
function check_running() {
	local LABEL="$1" PID CMDLINE ENVIRONMENT
	PID="$(main_pid)"
	check "${LABEL}: ${UNIT} is active" systemctl is-active --quiet "${UNIT}"
	check "${LABEL}: the MainPID is the PID the launcher recorded" \
		test "${PID}" = "$(cat "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid" 2>/dev/null)" -a "${PID}" != 0
	check "${LABEL}: /proc/<MainPID>/exe is the provisioned binary" \
		test "$(readlink "/proc/${PID}/exe")" = "${_AWG_BT_VERIFIED_BIN}"
	CMDLINE="$(tr '\0' ' ' <"/proc/${PID}/cmdline")"
	check "${LABEL}: BoringTun runs in the foreground with the production flags" \
		test "${CMDLINE}" = "${_AWG_BT_VERIFIED_BIN} --foreground --disable-drop-privileges --verbosity error ${IF} "
	ENVIRONMENT="$(tr '\0' '\n' <"/proc/${PID}/environ" | cut -d= -f1 | sort | tr '\n' ' ')"
	check "${LABEL}: BoringTun's environment is only NO_COLOR and PATH (${ENVIRONMENT})" test "${ENVIRONMENT}" = "NO_COLOR PATH "
	check "${LABEL}: ${IF} is a TUN device" test -e "/sys/class/net/${IF}/tun_flags"
	check "${LABEL}: the UAPI answers with the configured port" test "$(awg show "${IF}" listen-port 2>/dev/null)" = "${PORT}"
	check "${LABEL}: awg show lists the server config's peer" grep -q "${PEER_PUB}" <<<"$(awg show "${IF}" peers 2>/dev/null)"
	check "${LABEL}: the .up marker exists" test -e "${AWG_BT_RUN_DIR}/${IF}.up"
	check "${LABEL}: exactly one firewall rule from PostUp is present" test "$(rule_count)" -eq 1
}

function wait_for() { # <seconds> <command...>
	local LIMIT="$1" I
	shift
	for ((I = 0; I < LIMIT * 5; I++)); do
		"$@" && return 0
		sleep 0.2
	done
	return 1
}

function unit_restarted() { # <old pid>
	systemctl is-active --quiet "${UNIT}" && [[ "$(main_pid)" != "$1" && "$(main_pid)" != 0 ]]
}

function unit_inactive() {
	[[ "$(systemctl show -p ActiveState --value "${UNIT}")" == inactive ]]
}

function nothing_left() {
	[[ ! -e "/sys/class/net/${IF}" && ! -e "/var/run/wireguard/${IF}.sock" && ! -e "/var/run/amneziawg/${IF}.sock" &&
		! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid" && ! -e "${AWG_BT_RUN_DIR}/${IF}.up" && "$(rule_count)" -eq 0 ]]
}

echo "=== Start"
check_running "start"

echo "=== Reload"
PID="$(main_pid)"
systemctl reload "${UNIT}"
check "reload succeeds" test "$?" -eq 0
check "reload keeps the same daemon" test "$(main_pid)" = "${PID}"
check_running "reload"

echo "=== Restart"
systemctl restart "${UNIT}"
check "restart succeeds" test "$?" -eq 0
check "restart starts a new daemon" test "$(main_pid)" != "${PID}"
check_running "restart"

echo "=== Stop"
DOWNS_BEFORE="$(grep -c "^down-${IF}$" "${HOOK_LOG}")"
systemctl stop "${UNIT}"
check "stop succeeds" test "$?" -eq 0
check "the unit is inactive" unit_inactive
check "stop ran PostDown once" test "$(grep -c "^down-${IF}$" "${HOOK_LOG}")" -eq $((DOWNS_BEFORE + 1))
check "no link, socket, PID file, marker or firewall rule remains" nothing_left

echo "=== Start again"
systemctl start "${UNIT}"
check "start succeeds" test "$?" -eq 0
check_running "start again"

echo "=== SIGKILL of the BoringTun daemon"
PID="$(main_pid)"
RESTARTS_BEFORE="$(systemctl show -p NRestarts --value "${UNIT}")"
DOWNS_BEFORE="$(grep -c "^down-${IF}$" "${HOOK_LOG}")"
kill -KILL "${PID}"
check "systemd restarts the unit after the crash (Restart=on-failure)" wait_for 30 unit_restarted "${PID}"
check "systemd counted the restart" test "$(systemctl show -p NRestarts --value "${UNIT}")" -gt "${RESTARTS_BEFORE}"
check "ExecStopPost replayed PostDown after the crash" test "$(grep -c "^down-${IF}$" "${HOOK_LOG}")" -eq $((DOWNS_BEFORE + 1))
check_running "after crash and restart"
journalctl -u "${UNIT}" --no-pager -n 40 | grep -E 'signal|Main process exited|Scheduled restart|down-|PostDown|\[#\]' | tail -n 12

echo "=== Operator deletes the interface"
CURSOR="$(journalctl -u "${UNIT}" -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')"
DOWNS_BEFORE="$(grep -c "^down-${IF}$" "${HOOK_LOG}")"
ip link delete "${IF}"
check "the unit stops" wait_for 20 unit_inactive
sleep 5
check "and is not restarted after a clean exit" unit_inactive
check "systemd scheduled no restart" \
	test "$(journalctl -u "${UNIT}" --after-cursor "${CURSOR}" --no-pager | grep -c 'Scheduled restart job')" -eq 0
check "PostDown ran once for the vanished interface" test "$(grep -c "^down-${IF}$" "${HOOK_LOG}")" -eq $((DOWNS_BEFORE + 1))
check "no link, socket, PID file, marker or firewall rule remains" nothing_left

echo "=== Repeated unchanged-port syncs"
systemctl start "${UNIT}"
check "start succeeds" test "$?" -eq 0
PID="$(main_pid)"
FDS_BEFORE="$(fd_count "${PID}")"
for ((I = 0; I < 25; I++)); do
	systemctl reload "${UNIT}" || bad "reload ${I} failed"
	awgSyncInterfaceConfig "${IF}" || bad "awgSyncInterfaceConfig ${I} failed"
done
FDS_AFTER="$(fd_count "${PID}")"
check "50 filtered syncs keep BoringTun's descriptor count (${FDS_BEFORE} -> ${FDS_AFTER})" test "${FDS_AFTER}" -eq "${FDS_BEFORE}"
check "and the same daemon" test "$(main_pid)" = "${PID}"
awg syncconf "${IF}" <(awg-quick strip "${IF}")
awg syncconf "${IF}" <(awg-quick strip "${IF}")
FDS_UNFILTERED="$(fd_count "${PID}")"
check "for contrast, two unfiltered syncs leak descriptors (${FDS_AFTER} -> ${FDS_UNFILTERED})" test "${FDS_UNFILTERED}" -gt "${FDS_AFTER}"
systemctl restart "${UNIT}"
check_running "after the sync checks"

echo "=== AWG 2.0, 3.0 and 3.1 validation on BoringTun scratch instances"
WORK_DIR="$(mktemp -d)"
chmod 0700 "${WORK_DIR}"
cp "${AWG_BT_CONFIG_DIR}/${IF}.conf" "${WORK_DIR}/awgs1.conf"
AWG3_KEY="$(awg genkey)"
{
	sed -n '/^\[Interface\]/,/^\[Peer\]/{/^\[Peer\]/!p}' "${AWG_BT_CONFIG_DIR}/${IF}.conf"
	printf 'S3 = 14\nS4 = 15\nHeaderProtectionKey = %s\nContentPaddingAddition = 11-13\nRekeyAfterTime = 101-103\nRekeyTimeout = 5-7\n' "${AWG3_KEY}"
	printf 'RejectAfterTime = 181-183\nKeepaliveTimeout = 9-11\nRandomTrailers = on\nDisableCookies = off\n'
} >"${WORK_DIR}/awgs2.conf"
chmod 0600 "${WORK_DIR}"/*.conf
(validateStagedAwgConfigs "${WORK_DIR}" "${WORK_DIR}/awgs1.conf" "${WORK_DIR}/awgs2.conf")
check "staged validation of an AWG 2.0 server config and an AWG 3.1 config passes on BoringTun" test "$?" -eq 0
(probeAwg3Capability "${AWG3_KEY}")
check "the AWG 3.0 capability probe passes on BoringTun" test "$?" -eq 0
(probeAwg31Capability "${AWG3_KEY}")
check "the AWG 3.1 capability probe passes on BoringTun" test "$?" -eq 0
printf '[Interface]\nRejectAfterTime = 1-2\n' >"${WORK_DIR}/awgs3.conf"
chmod 0600 "${WORK_DIR}/awgs3.conf"
(validateStagedAwgConfigs "${WORK_DIR}" "${WORK_DIR}/awgs3.conf") 2>"${WORK_DIR}/reject.err"
check "a config BoringTun rejects fails staged validation" test "$?" -ne 0
check "with the BoringTun wording" grep -q "pinned BoringTun build" "${WORK_DIR}/reject.err"
check "the served interface was untouched by the scratch instances" test "$(awg show "${IF}" listen-port)" = "${PORT}"

echo "=== Scratch cleanup, including on signals"
(
	awgBackendCreateScratchInterface awgp9001 >/dev/null 2>&1
	kill -KILL "${BASHPID}"
)
sleep 2
check "SIGKILL of the owning shell still removes its scratch instance" \
	test -z "$(systemctl list-units --all --plain --no-legend 'amneziawg-scratch-*' 2>/dev/null)"
check "no scratch unit remains" test -z "$(systemctl list-units --all --plain --no-legend 'amneziawg-scratch-*' 2>/dev/null)"
check "no scratch link remains" test -z "$(ip -o link show 2>/dev/null | grep -oE ' awg[pv][0-9]+' || true)"
check "no scratch socket remains" test -z "$(find /var/run/wireguard /var/run/amneziawg -name 'awg[pv]*' 2>/dev/null)"

echo "=== Final stop"
systemctl stop "${UNIT}"
check "the final stop leaves nothing behind" nothing_left

echo
echo "BoringTun live runtime: ${PASSED} passed, ${FAILED} failed"
if [[ "${FAILED}" -ne 0 ]]; then
	dump_diagnostics
	exit 1
fi
