#!/bin/bash
# Live test of the supervised BoringTun runtime on a disposable systemd host,
# for example a GitHub-hosted Ubuntu runner. It is not an installer smoke test:
# the host is provisioned by hand. The test unpacks a packaged boringtun-cli
# archive into the runtime store, selects the BoringTun runtime through the
# installer's internal test hook, and drives awg-quick@<if>.service through
# start, reload, restart, stop, a SIGKILL crash, an operator's `ip link del`,
# repeated unchanged-port syncs and AWG 2.0/3.0/3.1 validation on scratch
# instances, and the ownership rules of the runtime: a failed start never
# touches an interface that existed before it, a partial awg-quick down never
# runs a PostDown hook twice, SaveConfig set after the start never erases the
# private key, and a scratch instance whose owner is SIGKILLed is removed. It
# cleans up after itself, also on failure.
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
# A second interface for the partial-down case, and a name that a foreign TUN
# link holds for the pre-existing-interface case.
IF2="awgbt2"
PORT2=51898
FOREIGN="awgbt9"
# An interface for the emergency cleanup with a read-only runtime directory,
# and one for a runtime directory that cannot store the down copy.
IF3="awgbt3"
PORT3=51896
IF4="awgbt4"
PORT4=51895
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
	local NAME
	mountpoint -q "${AWG_BT_RUN_DIR}" && umount "${AWG_BT_RUN_DIR}"
	mountpoint -q "${AWG_BT_RUN_DIR}" && umount "${AWG_BT_RUN_DIR}"
	for NAME in "${IF}" "${IF2}" "${IF3}" "${IF4}" "${FOREIGN}"; do
		systemctl stop "awg-quick@${NAME}.service" >/dev/null 2>&1
		systemctl reset-failed "awg-quick@${NAME}.service" >/dev/null 2>&1
		ip link delete "${NAME}" >/dev/null 2>&1
		rm -rf -- "/etc/systemd/system/awg-quick@${NAME}.service.d" "${AWG_BT_CONFIG_DIR}/${NAME}.conf" \
			"${AWG_BT_CONFIG_DIR}/${NAME}.boringtun"
		rm -f -- "/var/run/wireguard/${NAME}.sock" "/var/run/amneziawg/${NAME}.sock"
	done
	while iptables -D INPUT -p udp --dport "${PORT}" -m comment --comment "${RULE_COMMENT}" -j ACCEPT 2>/dev/null; do :; done
	rm -rf -- "${AWG_BT_LIBEXEC_DIR}" "${AWG_BT_STORE_DIR%/boringtun}" "${AWG_BT_RUN_DIR}" "${HOOK_LOG}" "${WORK_DIR}"
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
WORK_DIR="$(mktemp -d)"
chmod 0700 "${WORK_DIR}"
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
	check "${LABEL}: the unit's current attempt is recorded as up, with the MainPID and its start time" \
		test -e "$(attempt_base).up" -a "$(state_get PID) $(state_get PID_START)" = "${PID} $(_awgBtProcessStartTime "${PID}")"
	check "${LABEL}: exactly one firewall rule from PostUp is present" test "$(rule_count)" -eq 1
}

# The state of the unit's current activation, whose attempt identity is its
# InvocationID.
function attempt_base() {
	printf '%s/%s@%s\n' "${AWG_BT_RUN_DIR}" "${IF}" "$(systemctl show -p InvocationID --value "${UNIT}")"
}

function state_get() { # <key>
	sed -n "s/^$1=//p" "$(attempt_base).state" 2>/dev/null
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
		! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid" && -z "$(find "${AWG_BT_RUN_DIR}" -maxdepth 1 -name "${IF}@*")" &&
		"$(rule_count)" -eq 0 ]]
}

echo "=== Start"
check_running "start"

echo "=== ensureAwgBackendReady on the active unit"
(ensureAwgBackendReady 1)
check "an active unit served by its recorded BoringTun daemon is accepted" test "$?" -eq 0

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

echo "=== SaveConfig set after the start"
cp "${AWG_BT_CONFIG_DIR}/${IF}.conf" "${WORK_DIR}/config-before"
sed -i '/^\[Interface\]$/a SaveConfig = true' "${AWG_BT_CONFIG_DIR}/${IF}.conf"
systemctl stop "${UNIT}"
check "stop succeeds with SaveConfig added while running" test "$?" -eq 0
check "the private key survives: the config is unchanged apart from the added line" \
	test "$(grep -v '^SaveConfig = true$' "${AWG_BT_CONFIG_DIR}/${IF}.conf")" = "$(cat "${WORK_DIR}/config-before")"
cp "${WORK_DIR}/config-before" "${AWG_BT_CONFIG_DIR}/${IF}.conf"
systemctl start "${UNIT}"
check "start again succeeds" test "$?" -eq 0
check_running "after the SaveConfig stop"

echo "=== Stop"
DOWNS_BEFORE="$(grep -c "^down-${IF}$" "${HOOK_LOG}")"
systemctl stop "${UNIT}"
check "stop succeeds" test "$?" -eq 0
check "the unit is inactive" unit_inactive
check "stop ran PostDown once" test "$(grep -c "^down-${IF}$" "${HOOK_LOG}")" -eq $((DOWNS_BEFORE + 1))
check "no link, socket, PID file, state or firewall rule remains" nothing_left

echo "=== Start again"
systemctl start "${UNIT}"
check "start succeeds" test "$?" -eq 0
check_running "start again"

echo "=== SIGKILL of the BoringTun daemon"
CURSOR="$(journalctl -u "${UNIT}" -n 0 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')"
PID="$(main_pid)"
RESTARTS_BEFORE="$(systemctl show -p NRestarts --value "${UNIT}")"
DOWNS_BEFORE="$(grep -c "^down-${IF}$" "${HOOK_LOG}")"
kill -KILL "${PID}"
check "systemd restarts the unit after the crash (Restart=on-failure)" wait_for 30 unit_restarted "${PID}"
check "systemd counted the restart" test "$(systemctl show -p NRestarts --value "${UNIT}")" -gt "${RESTARTS_BEFORE}"
check "ExecStopPost replayed PostDown after the crash" test "$(grep -c "^down-${IF}$" "${HOOK_LOG}")" -eq $((DOWNS_BEFORE + 1))
check "systemd skipped ExecStop for the killed main process; only ExecStopPost ran" \
	test "$(journalctl -u "${UNIT}" --after-cursor "${CURSOR}" --no-pager | grep -c 'is already gone, so awg-quick down is not run')" -eq 0
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
check "ExecStop ran for the cleanly exited daemon and found the interface gone" \
	grep -q "is already gone, so awg-quick down is not run" <<<"$(journalctl -u "${UNIT}" --after-cursor "${CURSOR}" --no-pager)"
check "PostDown ran once for the vanished interface" test "$(grep -c "^down-${IF}$" "${HOOK_LOG}")" -eq $((DOWNS_BEFORE + 1))
check "no link, socket, PID file, state or firewall rule remains" nothing_left

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
# Before upstream #65, every set=1 carrying listen_port bound new sockets
# without closing the old ones, which is why the sync filter exists. The pinned
# build makes rebinding transactional, so unfiltered syncs must not leak either.
awg syncconf "${IF}" <(awg-quick strip "${IF}")
awg syncconf "${IF}" <(awg-quick strip "${IF}")
FDS_UNFILTERED="$(fd_count "${PID}")"
check "two unfiltered syncs no longer leak descriptors with the pinned BoringTun (${FDS_AFTER} -> ${FDS_UNFILTERED})" \
	test "${FDS_UNFILTERED}" -eq "${FDS_AFTER}"
check "and the same daemon still serves the interface" test "$(main_pid)" = "${PID}" -a "$(awg show "${IF}" listen-port)" = "${PORT}"
systemctl restart "${UNIT}"
check_running "after the sync checks"

echo "=== AWG 2.0, 3.0 and 3.1 validation on BoringTun scratch instances"
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

echo "=== SIGKILL of the shell that owns a scratch instance"
SCRATCH_NAME="awgp9001"
rm -f "${WORK_DIR}/token"
(
	awgBackendCreateScratchInterface "${SCRATCH_NAME}" >/dev/null 2>&1 || exit 1
	echo "${_AWG_BT_SCRATCH_TOKENS[${SCRATCH_NAME}]}" >"${WORK_DIR}/token.tmp"
	mv "${WORK_DIR}/token.tmp" "${WORK_DIR}/token"
	exec sleep 120
) &
OWNER_PID=$!
wait_for 40 test -s "${WORK_DIR}/token"
TOKEN="$(cat "${WORK_DIR}/token" 2>/dev/null)"
check "the scratch instance was created before its owner is killed" test -n "${TOKEN}"
SCRATCH_UNIT="amneziawg-scratch-${SCRATCH_NAME}-${TOKEN}.service"
GUARD_RECORD="${AWG_BT_RUN_DIR}/scratch/${TOKEN}.guard"
SCRATCH_PID="$(sed -n 's/^DAEMON_PID=//p' "${GUARD_RECORD}" 2>/dev/null)"
SCRATCH_START="$(sed -n 's/^DAEMON_START=//p' "${GUARD_RECORD}" 2>/dev/null)"
check "its transient unit ${SCRATCH_UNIT} is active" systemctl is-active --quiet "${SCRATCH_UNIT}"
check "its recorded daemon is the unit's main process" \
	test -n "${SCRATCH_PID}" -a "$(systemctl show -p MainPID --value "${SCRATCH_UNIT}")" = "${SCRATCH_PID}"
check "and runs the verified binary" test "$(readlink "/proc/${SCRATCH_PID}/exe")" = "${_AWG_BT_VERIFIED_BIN}"
check "its TUN link exists" test -e "/sys/class/net/${SCRATCH_NAME}/tun_flags"
check "its UAPI answers" awg show "${SCRATCH_NAME}" listen-port
CLIENT_RECORD="${AWG_BT_RUN_DIR}/scratch/${TOKEN}.client"
check "its systemd-run client registered itself by PID and start time" \
	grep -qE '^CLIENT_START=[0-9]+$' "${CLIENT_RECORD}"
check "the unit runs BoringTun behind the attempt's gate" \
	grep -q "${AWG_BT_RUN_DIR}/scratch/${TOKEN}.reclaim" <<<"$(systemctl show -p ExecStart --value "${SCRATCH_UNIT}")"
kill -KILL "${OWNER_PID}"
wait "${OWNER_PID}" 2>/dev/null
function scratch_unit_gone() {
	[[ "$(systemctl show -p ActiveState --value "${SCRATCH_UNIT}")" != active ]]
}
function scratch_daemon_gone() {
	! _awgBtProcessIs "${SCRATCH_PID}" "${SCRATCH_START}"
}
check "that transient unit stops" wait_for 20 scratch_unit_gone
check "that daemon is gone" wait_for 10 scratch_daemon_gone
check "that link is gone" wait_for 10 test ! -e "/sys/class/net/${SCRATCH_NAME}"
check "its sockets are gone" test ! -e "/var/run/wireguard/${SCRATCH_NAME}.sock" -a ! -e "/var/run/amneziawg/${SCRATCH_NAME}.sock"
check "its records are gone" wait_for 10 test ! -e "${GUARD_RECORD}" -a ! -e "${AWG_BT_RUN_DIR}/scratch/${TOKEN}.owner" \
	-a ! -e "${CLIENT_RECORD}" -a ! -e "${AWG_BT_RUN_DIR}/scratch/${TOKEN}.reclaim"
check "no scratch unit remains" test -z "$(systemctl list-units --all --plain --no-legend 'amneziawg-scratch-*' 2>/dev/null)"
check "no scratch link remains" test -z "$(ip -o link show 2>/dev/null | grep -oE ' awg[pv][0-9]+' || true)"
check "no scratch socket remains" test -z "$(find /var/run/wireguard /var/run/amneziawg -name 'awg[pv]*' 2>/dev/null)"

echo "=== A scratch unit that systemd creates after its attempt is being reclaimed"
# The unit a delayed systemd-run client submits once a reclaim has begun: real
# systemd starts it, and its gate ends it before BoringTun runs.
LATE_NAME="awgp9003"
LATE_TOKEN="$(_awgBtNewToken)"
LATE_UNIT="amneziawg-scratch-${LATE_NAME}-${LATE_TOKEN}.service"
_awgBtPrepareScratchDir
printf 'FORMAT=1\nTOKEN=%s\nNAME=%s\nMODE=unit\nUNIT=%s\nOWNER_PID=1\nOWNER_START=0\n' \
	"${LATE_TOKEN}" "${LATE_NAME}" "${LATE_UNIT%.service}" >"${AWG_BT_RUN_DIR}/scratch/${LATE_TOKEN}.owner"
: >"${AWG_BT_RUN_DIR}/scratch/${LATE_TOKEN}.reclaim"
chmod 0600 "${AWG_BT_RUN_DIR}/scratch/${LATE_TOKEN}".*
_awgBtDaemonArgv "${_AWG_BT_VERIFIED_BIN}" "${LATE_NAME}" && _awgBtScratchUnitArgv "${LATE_TOKEN}"
systemd-run --quiet --collect --unit="${LATE_UNIT%.service}" -p Type=exec -p RuntimeMaxSec=60 -- "${_AWG_BT_UNIT_ARGV[@]}" </dev/null >/dev/null 2>&1
check "systemd accepts the late unit" test "$?" -eq 0
check "which ends at once and is collected" wait_for 10 test "$(systemctl show -p LoadState --value "${LATE_UNIT}")" = not-found
check "without creating the scratch link" test ! -e "/sys/class/net/${LATE_NAME}"
check "or its sockets" test ! -e "/var/run/wireguard/${LATE_NAME}.sock" -a ! -e "/var/run/amneziawg/${LATE_NAME}.sock"
rm -f "${AWG_BT_RUN_DIR}/scratch/${LATE_TOKEN}".*

echo "=== A failed start leaves an interface that existed before it alone"
ip tuntap add dev "${FOREIGN}" mode tun
FOREIGN_INDEX="$(cat "/sys/class/net/${FOREIGN}/ifindex")"
# State that an earlier attempt left behind, claiming that link as its own.
STALE="${AWG_BT_RUN_DIR}/${FOREIGN}@00000000000000000000000000000001"
install -d -m 0700 "${AWG_BT_RUN_DIR}"
printf 'FORMAT=1\nATTEMPT=00000000000000000000000000000001\nCONFIG=%s\nPRE_EXISTING=0\nPHASE=launched\nPID=\nPID_START=\nIFINDEX=%s\nWG_SOCK=\nAWG_SOCK=\nDOWN=none\n' \
	"${AWG_BT_CONFIG_DIR}/${FOREIGN}.conf" "${FOREIGN_INDEX}" >"${STALE}.state"
: >"${STALE}.up"
chmod 0600 "${STALE}.state" "${STALE}.up"
STALE_SUM="$(cat "${STALE}.state" "${STALE}.up" | sha256sum)"
sed -e "s/^ListenPort = .*/ListenPort = 51897/" -e '/^PostUp\|^PostDown/d' "${AWG_BT_CONFIG_DIR}/${IF}.conf" >"${AWG_BT_CONFIG_DIR}/${FOREIGN}.conf"
sed -i "/^\[Interface\]$/a PostDown = echo down-%i >>${HOOK_LOG}" "${AWG_BT_CONFIG_DIR}/${FOREIGN}.conf"
chmod 0600 "${AWG_BT_CONFIG_DIR}/${FOREIGN}.conf"
check "service files for ${FOREIGN} are written" _awgBtInstallServiceFiles "${FOREIGN}"
systemctl start "awg-quick@${FOREIGN}.service" 2>/dev/null
check "the start is refused" test "$?" -ne 0
sleep 4
check "the pre-existing link survives, as the same link" test "$(cat "/sys/class/net/${FOREIGN}/ifindex" 2>/dev/null)" = "${FOREIGN_INDEX}"
check "and none of its PostDown hooks ran" test "$(grep -c "^down-${FOREIGN}$" "${HOOK_LOG}")" -eq 0
check "precheck said why" grep -q "already exists" <<<"$(journalctl -u "awg-quick@${FOREIGN}.service" --no-pager -n 50)"
check "the earlier attempt's state neither authorised any cleanup nor was removed" \
	test "$(cat "${STALE}.state" "${STALE}.up" 2>/dev/null | sha256sum)" = "${STALE_SUM}"
rm -f "${STALE}.state" "${STALE}.up"
systemctl stop "awg-quick@${FOREIGN}.service" >/dev/null 2>&1
systemctl reset-failed "awg-quick@${FOREIGN}.service" >/dev/null 2>&1
ip link delete "${FOREIGN}"

echo "=== Emergency cleanup when the runtime directory cannot record anything"
{
	sed -n '/^\[Interface\]/,/^\[Peer\]/{/^\[Peer\]/!p}' "${AWG_BT_CONFIG_DIR}/${IF}.conf" |
		sed -e "s/^ListenPort = .*/ListenPort = ${PORT3}/" -e 's/^Address = .*/Address = 10.97.0.1\/24/' -e '/^PostUp\|^PostDown/d'
	printf 'PostUp = echo up-%%i >>%s\nPostDown = echo down-%%i >>%s\n' "${HOOK_LOG}" "${HOOK_LOG}"
} >"${AWG_BT_CONFIG_DIR}/${IF3}.conf"
chmod 0600 "${AWG_BT_CONFIG_DIR}/${IF3}.conf"
_awgBtInstallServiceFiles "${IF3}" >/dev/null
CTL="${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"
EMERGENCY_ATTEMPT="$(_awgBtNewToken)"
INVOCATION_ID="${EMERGENCY_ATTEMPT}" "${CTL}" precheck "${IF3}" "${AWG_BT_CONFIG_DIR}/${IF3}.conf" &&
	INVOCATION_ID="${EMERGENCY_ATTEMPT}" WG_QUICK_USERSPACE_IMPLEMENTATION="${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" \
		awg-quick up "${AWG_BT_CONFIG_DIR}/${IF3}.conf" >/dev/null 2>&1
check "${IF3} is up with the launcher" test -e "/sys/class/net/${IF3}/tun_flags"
mount --bind "${AWG_BT_RUN_DIR}" "${AWG_BT_RUN_DIR}"
mount -o remount,bind,ro "${AWG_BT_RUN_DIR}"
check "(the runtime directory can no longer allocate or rename)" test "$(touch "${AWG_BT_RUN_DIR}/probe" 2>/dev/null; echo $?)" -ne 0
check "(while the attempt's state is still readable)" test -r "${AWG_BT_RUN_DIR}/${IF3}@${EMERGENCY_ATTEMPT}.state"
INVOCATION_ID="${EMERGENCY_ATTEMPT}" "${CTL}" poststart "${IF3}" "${AWG_BT_CONFIG_DIR}/${IF3}.conf" 2>"${WORK_DIR}/emergency.err"
check "poststart fails when it cannot record that ${IF3} is up" test "$?" -ne 0
check "and brings ${IF3} down itself" wait_for 10 test ! -e "/sys/class/net/${IF3}"
check "with PostDown run exactly once" test "$(grep -c "^down-${IF3}$" "${HOOK_LOG}")" -eq 1
check "from a private copy outside the runtime directory, which is removed" test -z "$(find /tmp -maxdepth 1 -name 'awg-boringtun-down.*')"
umount "${AWG_BT_RUN_DIR}"
INVOCATION_ID="${EMERGENCY_ATTEMPT}" "${CTL}" poststop "${IF3}" 2>"${WORK_DIR}/emergency-poststop.err"
check "the following poststop runs PostDown no second time" test "$(grep -c "^down-${IF3}$" "${HOOK_LOG}")" -eq 1
# Neither up nor done could be recorded on the read-only directory: no
# positive terminal fact exists, so the attempt is kept, not guessed finished.
check "and keeps the attempt, of which nothing terminal could be recorded" \
	test -f "${AWG_BT_RUN_DIR}/${IF3}@${EMERGENCY_ATTEMPT}.state"
check "saying that PostUp may have run" grep -q "PostUp may have run" "${WORK_DIR}/emergency-poststop.err"
rm -f "${AWG_BT_RUN_DIR}/${IF3}@${EMERGENCY_ATTEMPT}".*
cat "${WORK_DIR}/emergency.err"

echo "=== Emergency cleanup when the runtime directory cannot store the down copy"
# The runtime directory is a one-page tmpfs holding only the attempt's state:
# the down copy's directory can be made there, but writing the copy fails with
# ENOSPC. The up flag cannot be raised either. The whole copy is made again in
# /tmp. The config ends with SaveConfig = false, so a write error that the
# filter did not propagate would have left an empty copy passing for complete.
{
	sed -n '/^\[Interface\]/,/^\[Peer\]/{/^\[Peer\]/!p}' "${AWG_BT_CONFIG_DIR}/${IF}.conf" |
		sed -e "s/^ListenPort = .*/ListenPort = ${PORT4}/" -e 's/^Address = .*/Address = 10.96.0.1\/24/' \
			-e '/^PostUp\|^PostDown/d' -e '/^[[:space:]]*[Ss][Aa][Vv][Ee][Cc][Oo][Nn][Ff][Ii][Gg]/d' -e '/^[[:space:]]*$/d'
	printf 'PostUp = echo up-%%i >>%s\n' "${HOOK_LOG}"
	printf 'PostDown = echo down-%%i >>%s; ls -d /tmp/awg-boringtun-down.*/%%i.conf >>%s; ls -d %s/down.* >>%s 2>/dev/null || true\n' \
		"${HOOK_LOG}" "${HOOK_LOG}" "${AWG_BT_RUN_DIR}" "${HOOK_LOG}"
	printf 'PostDown = grep -q "^PostDown" /tmp/awg-boringtun-down.*/%%i.conf && echo copy-has-postdown-%%i >>%s; grep -qi "^SaveConfig" /tmp/awg-boringtun-down.*/%%i.conf || echo copy-without-saveconfig-%%i >>%s\n' \
		"${HOOK_LOG}" "${HOOK_LOG}"
	printf 'SaveConfig = false\n'
} >"${AWG_BT_CONFIG_DIR}/${IF4}.conf"
chmod 0600 "${AWG_BT_CONFIG_DIR}/${IF4}.conf"
_awgBtInstallServiceFiles "${IF4}" >/dev/null
FULL_ATTEMPT="$(_awgBtNewToken)"
INVOCATION_ID="${FULL_ATTEMPT}" "${CTL}" precheck "${IF4}" "${AWG_BT_CONFIG_DIR}/${IF4}.conf" &&
	INVOCATION_ID="${FULL_ATTEMPT}" WG_QUICK_USERSPACE_IMPLEMENTATION="${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" \
		awg-quick up "${AWG_BT_CONFIG_DIR}/${IF4}.conf" >/dev/null 2>&1
check "${IF4} is up with the launcher" test -e "/sys/class/net/${IF4}/tun_flags"
# The attempt's files are copied, not bind-mounted: with shared mount
# propagation (as on a systemd host) a bind of the directory would show the
# tmpfs too.
mkdir -p "${WORK_DIR}/full-before" "${WORK_DIR}/full-after"
cp -a "${AWG_BT_RUN_DIR}/${IF4}@${FULL_ATTEMPT}".* "${WORK_DIR}/full-before/"
mount -t tmpfs -o size=4k,mode=0700,uid=0,gid=0 awgbt-full "${AWG_BT_RUN_DIR}"
cp -a "${WORK_DIR}/full-before/${IF4}@${FULL_ATTEMPT}".* "${AWG_BT_RUN_DIR}/"
rm -f "${AWG_BT_RUN_DIR}/${IF4}@${FULL_ATTEMPT}.up-pending"
check "(the runtime directory can make a directory but not store a file in it)" \
	bash -c 'mkdir "$1/probe" && ! { echo x >"$1/probe/f"; } 2>/dev/null; RC=$?; rm -rf "$1/probe"; exit "${RC}"' _ "${AWG_BT_RUN_DIR}"
INVOCATION_ID="${FULL_ATTEMPT}" "${CTL}" poststart "${IF4}" "${AWG_BT_CONFIG_DIR}/${IF4}.conf" 2>"${WORK_DIR}/full.err"
check "poststart fails when it cannot record that ${IF4} is up" test "$?" -ne 0
check "and brings ${IF4} down itself" wait_for 10 test ! -e "/sys/class/net/${IF4}"
check "with PostDown run exactly once" test "$(grep -c "^down-${IF4}$" "${HOOK_LOG}")" -eq 1
check "from a complete copy made again in /tmp after the failed write" grep -q "^/tmp/awg-boringtun-down\..*/${IF4}.conf$" "${HOOK_LOG}"
check "that copy held the whole config, PostDown hooks included" grep -q "^copy-has-postdown-${IF4}$" "${HOOK_LOG}"
check "and no SaveConfig line" grep -q "^copy-without-saveconfig-${IF4}$" "${HOOK_LOG}"
check "while the failed copy's directory was already removed" test "$(grep -c "^${AWG_BT_RUN_DIR}/down\." "${HOOK_LOG}")" -eq 0
check "and the /tmp copy is removed too" test -z "$(find /tmp -maxdepth 1 -name 'awg-boringtun-down.*')"
# What the attempt recorded goes back to the real runtime directory.
cp -a "${AWG_BT_RUN_DIR}/${IF4}@${FULL_ATTEMPT}".* "${WORK_DIR}/full-after/"
umount "${AWG_BT_RUN_DIR}"
rm -f "${AWG_BT_RUN_DIR}/${IF4}@${FULL_ATTEMPT}".*
cp -a "${WORK_DIR}/full-after/${IF4}@${FULL_ATTEMPT}".* "${AWG_BT_RUN_DIR}/"
INVOCATION_ID="${FULL_ATTEMPT}" "${CTL}" poststop "${IF4}" 2>/dev/null
check "the following poststop runs PostDown no second time" test "$(grep -c "^down-${IF4}$" "${HOOK_LOG}")" -eq 1
check "and removes the finished attempt" test -z "$(find "${AWG_BT_RUN_DIR}" -maxdepth 1 -name "${IF4}@*")"
cat "${WORK_DIR}/full.err"

echo "=== A direct scratch instance records its own identity before it is ready"
(
	# shellcheck disable=SC2034 # read by awgBackendCreateScratchInterface: no systemd, a direct daemon
	AWG_BT_SYSTEMD_RUNTIME_DIR="/nonexistent-systemd"
	awgBackendCreateScratchInterface awgp9002 >/dev/null 2>&1 || exit 1
	TOKEN="${_AWG_BT_SCRATCH_TOKENS[awgp9002]}"
	echo "${TOKEN}" >"${WORK_DIR}/direct-token"
	sed -n 's/^CHILD_PID=//p; s/^CHILD_START=//p' "${AWG_BT_RUN_DIR}/scratch/${TOKEN}.child" | tr '\n' ' ' >"${WORK_DIR}/direct-child"
	sed -n 's/^DAEMON_PID=//p; s/^PHASE=//p' "${AWG_BT_RUN_DIR}/scratch/${TOKEN}.guard" | tr '\n' ' ' >"${WORK_DIR}/direct-guard"
	awgBackendDestroyScratchInterface awgp9002
)
check "a direct scratch instance starts" test "$?" -eq 0
read -r CHILD_PID CHILD_START <"${WORK_DIR}/direct-child"
read -r GUARD_PHASE GUARD_DAEMON <"${WORK_DIR}/direct-guard"
check "its daemon recorded its own PID and start time (${CHILD_PID} ${CHILD_START})" test -n "${CHILD_PID}" -a -n "${CHILD_START}"
check "and the guardian's ready record names that same daemon" test "${GUARD_PHASE} ${GUARD_DAEMON}" = "created ${CHILD_PID}"
check "which is gone after destroy, with every record" \
	test ! -d "/proc/${CHILD_PID}" -a -z "$(find "${AWG_BT_RUN_DIR}/scratch" -name "$(cat "${WORK_DIR}/direct-token").*")"

echo "=== A partial awg-quick down never runs a PostDown hook twice"
{
	sed -n '/^\[Interface\]/,/^\[Peer\]/{/^\[Peer\]/!p}' "${AWG_BT_CONFIG_DIR}/${IF}.conf" |
		sed -e "s/^ListenPort = .*/ListenPort = ${PORT2}/" -e 's/^Address = .*/Address = 10.98.0.1\/24/' -e '/^PostUp\|^PostDown/d'
	printf 'PostDown = echo hook1-%%i >>%s\nPostDown = false\nPostDown = echo hook3-%%i >>%s\n' "${HOOK_LOG}" "${HOOK_LOG}"
} >"${AWG_BT_CONFIG_DIR}/${IF2}.conf"
chmod 0600 "${AWG_BT_CONFIG_DIR}/${IF2}.conf"
check "service files for ${IF2} are written" _awgBtInstallServiceFiles "${IF2}"
systemctl start "awg-quick@${IF2}.service"
check "${IF2} starts" test "$?" -eq 0
systemctl stop "awg-quick@${IF2}.service"
check "PostDown hook 1 ran exactly once" test "$(grep -c "^hook1-${IF2}$" "${HOOK_LOG}")" -eq 1
check "hook 3, after the failing hook 2, was never run by the runtime" test "$(grep -c "^hook3-${IF2}$" "${HOOK_LOG}")" -eq 0
check "poststop reported the unfinished down" \
	grep -q "not replayed, because no hook may run twice" <<<"$(journalctl -u "awg-quick@${IF2}.service" --no-pager -n 80)"
check "and ${IF2} is gone" test ! -e "/sys/class/net/${IF2}" -a ! -e "${AWG_BT_RUN_DIR}/${IF2}.state"
systemctl reset-failed "awg-quick@${IF2}.service" >/dev/null 2>&1

echo "=== Final stop"
systemctl stop "${UNIT}"
check "the final stop leaves nothing behind" nothing_left

echo
echo "BoringTun live runtime: ${PASSED} passed, ${FAILED} failed"
if [[ "${FAILED}" -ne 0 ]]; then
	dump_diagnostics
	exit 1
fi
