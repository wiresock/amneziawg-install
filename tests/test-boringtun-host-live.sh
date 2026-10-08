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
# Under sip, each server packet kind is held to its own S size (a request line
# fits a prefix of 31 bytes or more), and tests/test-boringtun-sip-wire-live.sh
# then checks fixed S sizes, the 30/31 boundary and cookie replies with the
# same verified binary.
#
# It then cycles the built-in protocol imitation through dns, quic, sip, stun
# and none with --set-boringtun-imitation: each time it checks params, the
# runtime file, the daemon's command line and --backend-status, moves data
# through the tunnel while it records the prefixes of the server's datagrams
# on the client's side (which must have the imitated protocol's shape), and
# sends DNS, STUN, QUIC and SIP probes from the client's network (only the
# imitated service may answer, and never SIP) and from loopback (never
# answered). Under dns it also adds and removes a client and moves to AWG 3.0
# and back, which keeps the imitation.
#
# Then the binary lifecycle: a TEST FIXTURE older release made current, the
# real pinned release removed and fetched again by --upgrade-boringtun, a
# --rollback-boringtun to the fixture, an upgrade back and a no-op upgrade,
# each with the tunnel's datapath and an unchanged configuration. The fixture
# relabels the pinned release's own bytes, so these moves never cross a real
# version: they prove the lifecycle's mechanics, not a cross-version rollback.
#
# With AWG_LIVE_PREVIOUS_INSTALLER=<path>, the fresh install runs that earlier
# installer version instead, and everything after it runs this one: the
# upgrade path from an installation without imitation (params without its
# keys, a FORMAT=1 runtime file, the earlier helpers and a running daemon
# started without --imitate-protocol) and with the earlier installer's own
# release. The test first checks that release, read from the earlier
# installer as data: its public download, its store entry and MANIFEST, the
# store's selection and the running daemon. It then upgrades to this
# installer's release with this installer's --upgrade-boringtun, a real
# version transition, and checks the switch, the restarted daemon and
# --backend-status; only then does it hold the host to this installer's
# release.
#
# Requirements: root, systemd as PID 1, network access to the Amnezia PPA and
# GitHub, no AmneziaWG kernel module, python3, and AWG_DISPOSABLE_HOST_TEST=1.
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
	# Fixed strings: in the C locale a bracket expression would match single
	# bytes of other UTF-8 characters, such as the arrow systemd prints.
	if grep -qF -e '▀' -e '▄' -e '█' "${SCAN_DIR}/public.log"; then
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

# The embedded release, read from the installer as data. It is the published
# release this installer installs, which can be older than the release that
# packaging/boringtun/release.env prepares: nothing here reads that file.
installer_value() {
	sed -n "s/^$1=\"\\(.*\\)\"\$/\\1/p" "${INSTALLER}"
}
case "$(uname -m)" in
	x86_64 | amd64) ARCH=x86_64 ARCH_KEY=X86_64 ;;
	aarch64 | arm64) ARCH=aarch64 ARCH_KEY=AARCH64 ;;
	*) die "no BoringTun release for $(uname -m)" ;;
esac
RELEASE_TAG="$(installer_value AWG_BT_RELEASE_TAG)"
RELEASE_BASE_URL="$(installer_value AWG_BT_RELEASE_BASE_URL)"
SOURCE_COMMIT="$(installer_value AWG_BT_RELEASE_SOURCE_COMMIT)"
ASSET="$(installer_value "AWG_BT_RELEASE_ASSET_${ARCH_KEY}")"
ARCHIVE_SHA256="$(installer_value "AWG_BT_RELEASE_ARCHIVE_SHA256_${ARCH_KEY}")"
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
# The firewall rules this interface's PostUp hooks added (its own nft table,
# or the iptables rules that name it), read by fw_* in
# helpers/boringtun-live-firewall.sh: a failed query is never a result.
# shellcheck source=helpers/boringtun-live-firewall.sh
source "${SCRIPT_DIR}/helpers/boringtun-live-firewall.sh"
# shellcheck source=helpers/boringtun-wire-checks.sh
source "${SCRIPT_DIR}/helpers/boringtun-wire-checks.sh"
# shellcheck source=helpers/boringtun-contracts.sh
source "${SCRIPT_DIR}/helpers/boringtun-contracts.sh"
# shellcheck source=helpers/boringtun-lifecycle-fixture.sh
source "${SCRIPT_DIR}/helpers/boringtun-lifecycle-fixture.sh"
# shellcheck source=helpers/boringtun-auto-live.sh
source "${SCRIPT_DIR}/helpers/boringtun-auto-live.sh"
fw_args() {
	FW_ARGS=("/etc/amnezia/amneziawg/${IF}.conf" "${IF}" "${PORT}" "${PUBLIC_NIC}")
}
no_kernel_module() {
	[[ ! -e /sys/module/amneziawg ]]
}
scratch_clean() {
	[[ -z "$(ip -o link show 2>/dev/null | grep -oE ' awg[pvb][0-9]+' || true)" ]] &&
		[[ -z "$(find /run/amneziawg-install/scratch -mindepth 1 2>/dev/null)" ]] &&
		[[ -z "$(systemctl list-units --all --plain --no-legend 'amneziawg-scratch-*' 2>/dev/null)" ]]
}
# fails <command...>: succeeds exactly when the command fails, for the
# negative controls.
fails() {
	! "$@"
}
# file_hashes <file>...: one "<SHA-256>  <file>" line per file, in order, or
# a failure that prints nothing. Every file must be read: the hashing must
# succeed, and its output must name exactly these files, one hash each, so
# that a failed, partial or incomplete read is never a snapshot. Only hashes
# and names are printed, never contents. HASH_COMMAND is the hashing command;
# only the controls below replace it.
HASH_COMMAND=(sha256sum)
file_hashes() {
	local OUTPUT LINE I=0
	local -a FILES=("$@")
	((${#FILES[@]} > 0)) || return 1
	OUTPUT="$("${HASH_COMMAND[@]}" -- "${FILES[@]}")" || return 1
	while IFS= read -r LINE; do
		((I < ${#FILES[@]})) && [[ "${LINE}" =~ ^[0-9a-f]{64}\ \ (.+)$ && "${BASH_REMATCH[1]}" == "${FILES[I]}" ]] || return 1
		I=$((I + 1))
	done <<<"${OUTPUT}"
	((I == ${#FILES[@]})) || return 1
	printf '%s\n' "${OUTPUT}"
}
# snapshot_unchanged <baseline status> <baseline> <snapshot command...>: the
# baseline was read completely, a new snapshot is read completely, and the two
# are the same. Two failed or empty reads never match.
snapshot_unchanged() {
	local NOW
	[[ "$1" == 0 && -n "$2" ]] || return 1
	NOW="$("${@:3}")" || return 1
	[[ -n "${NOW}" && "${NOW}" == "$2" ]]
}
# The configuration whose bytes must survive the binary's moves: params, the
# interface's config and runtime file, every client config the installer keeps
# and the test client's config.
installation_hashes() {
	local -a CLIENTS
	shopt -s nullglob
	CLIENTS=(/etc/amnezia/amneziawg/clients/*.conf)
	shopt -u nullglob
	file_hashes /etc/amnezia/amneziawg/params "/etc/amnezia/amneziawg/${IF}.conf" "/etc/amnezia/amneziawg/${IF}.boringtun" \
		"${CLIENTS[@]}" "${CLIENT_CONF}"
}
# installation_baseline: the snapshot installation_unchanged compares with, in
# HASHES, and in HASHES_RC whether it was read completely.
installation_baseline() {
	HASHES="$(installation_hashes)"
	HASHES_RC=$?
}
installation_unchanged() {
	snapshot_unchanged "${HASHES_RC}" "${HASHES}" installation_hashes
}
HASHES=""
HASHES_RC=1
store_links() {
	printf '%s %s' "$(readlink "${STORE}/current" 2>/dev/null || echo none)" "$(readlink "${STORE}/previous" 2>/dev/null || echo none)"
}
# The release lines of --backend-status, in its order. The command's own exit
# status is checked first: when it fails, whatever it printed, or prints none
# of these lines, this fails and prints nothing, so a failed status is never
# evidence of a state.
release_status() {
	local OUTPUT LINES
	OUTPUT="$(bash "${INSTALLER}" --backend-status 2>&1)" || return 1
	LINES="$(grep -E '^(installed_release|pinned_release|previous_release|rollback_available|upgrade_available|daemon_release)=' <<<"${OUTPUT}")" ||
		return 1
	tr '\n' ' ' <<<"${LINES}"
}
# release_status_is <lines>: --backend-status succeeds, and its release lines
# are exactly these.
release_status_is() {
	local STATUS
	STATUS="$(release_status)" || return 1
	[[ "${STATUS}" == "$1" ]]
}
LIBEXEC=/usr/local/libexec/amneziawg-install
# Whether both installed helpers are exactly the ones this installer renders.
# Each rendering is read in full before the comparison: cmp on a pipe stops at
# the first difference and leaves the renderer writing into a closed pipe. The
# trailing x keeps trailing newlines in both sides.
helpers_are_this_installers() {
	local KIND FILE RENDERED
	for KIND in launch ctl; do
		FILE="${LIBEXEC}/awg-boringtun-launch"
		[[ "${KIND}" == ctl ]] && FILE="${LIBEXEC}/awg-backend-ctl"
		RENDERED="$(bash -c 'source "$1" && _awgBtRenderHelper "$2"' _ "${INSTALLER}" "${KIND}" && echo x)" || return 1
		[[ "$(cat -- "${FILE}" && echo x)" == "${RENDERED}" ]] || return 1
	done
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
	bt_auto_cleanup
	bt_wire_cleanup
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

# ── Controls of the status and configuration checks ─────────────────────────
# release_status_is and installation_unchanged are evidence only if a failed
# command or an incomplete read can never pass them. These controls run the
# same helpers against TEST STUBS and files of their own, never against the
# installation: a --backend-status that prints the expected lines and then
# fails, and hash reads that fail, fail after printing every hash, or succeed
# with a hash missing.
echo "=== Controls of the status and configuration checks (TEST STUBS)"
CONTROLS="${WORK}/controls"
mkdir -p "${CONTROLS}/files"
STATUS_STUB="${CONTROLS}/backend-status-stub.sh"
cat >"${STATUS_STUB}" <<'EOF'
#!/bin/bash
# TEST STUB of `amneziawg-install.sh --backend-status`: prints the fields in
# STUB_FIELDS as status lines, then exits with STUB_RC.
[[ "${1:-}" == --backend-status ]] || exit 64
printf '%s\n' backend=boringtun ${STUB_FIELDS}
[[ "${STUB_RC}" == 0 ]] || echo "TEST STUB: --backend-status failed after printing its fields" >&2
exit "${STUB_RC}"
EOF
cat >"${CONTROLS}/hash-then-fail.sh" <<'EOF'
#!/bin/bash
# TEST STUB of sha256sum: hashes every file, then fails.
sha256sum "$@"
exit 7
EOF
cat >"${CONTROLS}/hash-omit-last.sh" <<'EOF'
#!/bin/bash
# TEST STUB of sha256sum: succeeds, but leaves out the last file.
sha256sum "${@:1:$#-1}"
EOF
chmod 0755 "${STATUS_STUB}" "${CONTROLS}/hash-then-fail.sh" "${CONTROLS}/hash-omit-last.sh"
# with_status_stub <exit status> <fields> <command...>: the command, with the
# TEST STUB in place of this installer's --backend-status.
with_status_stub() {
	local INSTALLER="${STATUS_STUB}"
	local -x STUB_RC="$1" STUB_FIELDS="$2"
	"${@:3}"
}
# with_hash_command <command> <command...>: the second command, with the
# first in place of sha256sum.
with_hash_command() {
	local -a HASH_COMMAND=("$1")
	"${@:2}"
}
FIELDS="installed_release=new pinned_release=new previous_release=old rollback_available=yes upgrade_available=no daemon_release=new"
check "control: release lines from a --backend-status that succeeds are accepted" \
	with_status_stub 0 "${FIELDS}" release_status_is "${FIELDS} "
for RC in 1 7 143; do
	check "control: the same release lines from a --backend-status that exits ${RC} are rejected" \
		fails with_status_stub "${RC}" "${FIELDS}" release_status_is "${FIELDS} "
done
check "control: a --backend-status that succeeds without release lines is rejected" fails with_status_stub 0 "" release_status_is ""

HASH_FILES=("${CONTROLS}/files/params" "${CONTROLS}/files/config" "${CONTROLS}/files/client")
control_hashes() {
	file_hashes "${HASH_FILES[@]}"
}
printf 'params\n' >"${CONTROLS}/files/params"
printf 'config\n' >"${CONTROLS}/files/config"
printf 'client\n' >"${CONTROLS}/files/client"
BASELINE="$(control_hashes)"
BASELINE_RC=$?
check "control: a complete read names each file once, with its hash" \
	test "${BASELINE_RC}" -eq 0 -a "$(cut -d' ' -f3- <<<"${BASELINE}" | tr '\n' ' ')" = "${HASH_FILES[*]} "
check "control: two complete reads of the same files match" snapshot_unchanged "${BASELINE_RC}" "${BASELINE}" control_hashes
printf 'changed\n' >"${CONTROLS}/files/config"
check "control: a changed file does not match" fails snapshot_unchanged "${BASELINE_RC}" "${BASELINE}" control_hashes
printf 'config\n' >"${CONTROLS}/files/config"
mv -- "${CONTROLS}/files/client" "${CONTROLS}/files/client.away"
check "  (with a file unreadable, the raw hashing prints the same partial output each time, and fails)" \
	bash -c 'A="$(sha256sum -- "$@" 2>/dev/null)"; RA=$?; B="$(sha256sum -- "$@" 2>/dev/null)"; RB=$?; [[ -n "${A}" && "${A}" == "${B}" && ${RA} -ne 0 && ${RB} -ne 0 ]]' _ "${HASH_FILES[@]}"
FAILED_READ="$(control_hashes)"
FAILED_READ_RC=$?
check "control: a failed read is no snapshot: it fails and prints nothing" test "${FAILED_READ_RC}" -ne 0 -a -z "${FAILED_READ}"
check "control: two failed reads with the same partial output do not match" \
	fails snapshot_unchanged "${FAILED_READ_RC}" "${FAILED_READ}" control_hashes
check "control: a complete baseline does not match a failed read after it" \
	fails snapshot_unchanged "${BASELINE_RC}" "${BASELINE}" control_hashes
mv -- "${CONTROLS}/files/client.away" "${CONTROLS}/files/client"
check "control: a failed baseline read does not match a complete read after it" \
	fails snapshot_unchanged "${FAILED_READ_RC}" "${FAILED_READ}" control_hashes
check "control: hashing that prints every hash and then fails is no snapshot" \
	fails with_hash_command "${CONTROLS}/hash-then-fail.sh" control_hashes
check "  and does not match a complete baseline" \
	fails with_hash_command "${CONTROLS}/hash-then-fail.sh" snapshot_unchanged "${BASELINE_RC}" "${BASELINE}" control_hashes
check "control: hashing that succeeds but leaves a file out is no snapshot" \
	fails with_hash_command "${CONTROLS}/hash-omit-last.sh" control_hashes
check "  and does not match a complete baseline" \
	fails with_hash_command "${CONTROLS}/hash-omit-last.sh" snapshot_unchanged "${BASELINE_RC}" "${BASELINE}" control_hashes
check "control: the complete files still match after these controls" snapshot_unchanged "${BASELINE_RC}" "${BASELINE}" control_hashes

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
	bash "${AWG_LIVE_PREVIOUS_INSTALLER:-${INSTALLER}}" >"${WORK}/install.log" 2>&1 </dev/null
INSTALL_RC=$?
[[ -z "${AWG_LIVE_PREVIOUS_INSTALLER:-}" ]] ||
	echo "    (installed by the earlier installer ${AWG_LIVE_PREVIOUS_INSTALLER}, with its own release; everything below runs this one)"
tail -n 25 "${WORK}/install.log" | sed 's/^/    | /'
check "the installer completes" test "${INSTALL_RC}" -eq 0
((INSTALL_RC == 0)) || die "the install failed; nothing more to test"
record_secret "$(sed -n "s/^SERVER_PRIV_KEY='\\(.*\\)'\$/\\1/p" /etc/amnezia/amneziawg/params)"
# The log of the operation that downloaded this installer's release: the
# fresh install, or the upgrade from the earlier installer's release below.
RELEASE_LOG="${WORK}/install.log"

# ── The earlier installer's release ─────────────────────────────────────────
# What the earlier installer installed is its own embedded release, read from
# it as data and checked before anything else runs: that installer predates
# AWG_BT_RELEASE_BUILD, so its constants are held to the format without a
# build number (tests/helpers/boringtun-contracts.sh), never to this
# installer's. Its legacy state (params, runtime file and daemon command line)
# is checked here too, before any operation of this installer touches it.
if [[ -n "${AWG_LIVE_PREVIOUS_INSTALLER:-}" ]]; then
	echo "=== The earlier installer's release"
	PREVIOUS="${AWG_LIVE_PREVIOUS_INSTALLER}"
	# Two earlier installers are covered: the last one without protocol
	# imitation (9f5a1afb87f7), whose release constants predate the build
	# number, and the one that embedded the release before this one
	# (c7cd737c221a), with a build number and imitation none.
	if grep -q '^AWG_BT_RELEASE_BUILD=' "${PREVIOUS}"; then
		PROBLEMS="$(btc_embedded_release_problems "${PREVIOUS}")"
		PREV_FORMAT="with a build number"
	else
		PROBLEMS="$(btc_buildless_embedded_release_problems "${PREVIOUS}")"
		PREV_FORMAT="without a build number"
	fi
	PREV_IMITATES=0
	grep -q '^function _awgBtImitationProtocolValid()' "${PREVIOUS}" && PREV_IMITATES=1
	[[ -z "${PROBLEMS}" ]] || sed 's/^/    | /' <<<"${PROBLEMS}"
	check "the earlier installer embeds a consistent release in the format ${PREV_FORMAT}" test -z "${PROBLEMS}"
	PREV_TAG="$(btc_embedded_value "${PREVIOUS}" TAG)"
	PREV_SOURCE_COMMIT="$(btc_embedded_value "${PREVIOUS}" SOURCE_COMMIT)"
	PREV_ASSET="$(btc_embedded_value "${PREVIOUS}" "ASSET_${ARCH_KEY}")"
	PREV_ARCHIVE_SHA256="$(btc_embedded_value "${PREVIOUS}" "ARCHIVE_SHA256_${ARCH_KEY}")"
	PREV_BINARY_SHA256="$(btc_embedded_value "${PREVIOUS}" "BINARY_SHA256_${ARCH_KEY}")"
	PREV_ID="${PREV_ASSET%.tar.gz}"
	echo "    earlier installer's release: ${PREV_TAG}, ${ARCH} binary ${PREV_BINARY_SHA256}"
	echo "    this installer's release:    ${RELEASE_TAG}, ${ARCH} binary ${BINARY_SHA256}"
	check "  it is another release than this installer's, so the upgrade below crosses versions" \
		test "${PREV_TAG}" != "${RELEASE_TAG}" -a "${PREV_ID}" != "${RELEASE_ID}" \
		-a "${PREV_ARCHIVE_SHA256}" != "${ARCHIVE_SHA256}" -a "${PREV_BINARY_SHA256}" != "${BINARY_SHA256}"
	check "it downloaded its own public release ${PREV_TAG}" \
		grep -qF "Downloading https://github.com/wiresock/amneziawg-install/releases/download/${PREV_TAG}/${PREV_ASSET}" "${WORK}/install.log"
	check "  and not this installer's release" bash -c '! grep -qF "/$1/" "$2"' _ "${RELEASE_TAG}" "${WORK}/install.log"
	check "the store selects the earlier release ${PREV_ID}, with no previous release" test "$(store_links)" = "${PREV_ID} none"
	check "  its binary has the earlier installer's embedded SHA-256" \
		test "$(sha256sum "${STORE}/${PREV_ID}/boringtun-cli" 2>/dev/null | cut -d' ' -f1)" = "${PREV_BINARY_SHA256}"
	check "  its MANIFEST names the earlier installer's source commit and binary SHA-256" \
		bash -c 'grep -qx "source_commit=$2" "$1" && grep -qx "binary_sha256=$3" "$1"' _ \
		"${STORE}/${PREV_ID}/MANIFEST" "${PREV_SOURCE_COMMIT}" "${PREV_BINARY_SHA256}"
	curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 -o "${WORK}/${PREV_ASSET}" \
		"https://github.com/wiresock/amneziawg-install/releases/download/${PREV_TAG}/${PREV_ASSET}"
	check "  its public URL serves the earlier installer's embedded archive SHA-256" \
		test "$(sha256sum "${WORK}/${PREV_ASSET}" 2>/dev/null | cut -d' ' -f1)" = "${PREV_ARCHIVE_SHA256}"
	check "  and the installed release is that archive's content" \
		bash -c 'for F in LICENSE MANIFEST THIRD-PARTY-LICENSES boringtun-cli; do tar -xzOf "$1" "$2/$F" | cmp -s - "$3/$F" || exit 1; done' _ \
		"${WORK}/${PREV_ASSET}" "${PREV_ID}" "${STORE}/${PREV_ID}"
	PREV_PID="$(main_pid)"
	PREV_EXE="$(readlink "/proc/${PREV_PID}/exe" 2>/dev/null)"
	check "${UNIT} is active" systemctl is-active --quiet "${UNIT}"
	check "  its daemon executes the earlier release's binary" \
		test -n "${PREV_EXE}" -a "${PREV_EXE}" = "$(readlink -f "${STORE}/${PREV_ID}/boringtun-cli")"
	check "  with the earlier installer's embedded SHA-256" \
		test "$(sha256sum "/proc/${PREV_PID}/exe" 2>/dev/null | cut -d' ' -f1)" = "${PREV_BINARY_SHA256}"
	PREV_ARGS="$(tr '\0' ' ' <"/proc/${PREV_PID}/cmdline")"
	if ((PREV_IMITATES)); then
		check "upgrade: the earlier installer's params persist imitation none" \
			test "$(grep '^AWG_BORINGTUN_' /etc/amnezia/amneziawg/params | tr '\n' ' ')" = "AWG_BORINGTUN_IMITATE_PROTOCOL='none' AWG_BORINGTUN_IMITATE_DOMAIN='' "
		check "upgrade: its daemon names it on its command line" bash -c '[[ "$1" == *" --imitate-protocol none ${2} " ]]' _ "${PREV_ARGS}" "${IF}"
	else
		check "upgrade: the earlier installer's params have no imitation keys" bash -c '! grep -q "^AWG_BORINGTUN_" /etc/amnezia/amneziawg/params'
		check "upgrade: its daemon was started without --imitate-protocol" bash -c '[[ "$1" != *--imitate-protocol* ]]' _ "${PREV_ARGS}"
	fi
	check "upgrade: its runtime file is FORMAT=1 alone" test "$(grep -v '^#' "/etc/amnezia/amneziawg/${IF}.boringtun")" = "FORMAT=1"
	check "upgrade: the earlier binary does not support imitation auto, as its own answer says" \
		bash -c 'source "$1" && _awgBtBinaryImitationSupport "$2" auto; [[ $? == 1 ]]' _ "${INSTALLER}" "${STORE}/${PREV_ID}/boringtun-cli"
	check "  although it reports the same version as this installer's release" \
		test "$("${STORE}/${PREV_ID}/boringtun-cli" --version 2>/dev/null)" = "boringtun $(installer_value AWG_BT_RELEASE_VERSION)"
fi

bash "${INSTALLER}" --add-client client >"${WORK}/client-add.private" 2>&1 </dev/null
check "--add-client creates the test client (its output, config and QR code stay private)" test "$?" -eq 0
CLIENT_CONF="$(find /etc/amnezia/amneziawg/clients /root /home -maxdepth 2 -name "${IF}-client-client.conf" 2>/dev/null | head -n 1)"
[[ -n "${CLIENT_CONF}" ]] || die "the installer did not write the test client's config"
record_config_secrets "${CLIENT_CONF}"

# ── Upgrade from the earlier installer's release ────────────────────────────
# This installer's own --upgrade-boringtun moves the host to its release. The
# upgrade is proven part by part (its exit status, the public download, the
# store's current and previous releases, the restarted daemon's executable and
# hash, and --backend-status); nothing below runs unless every part holds.
# Negative controls show that each part rejects the state the earlier
# installer left, which is what a skipped upgrade, or one that failed and kept
# the earlier daemon, leaves behind.
if [[ -n "${AWG_LIVE_PREVIOUS_INSTALLER:-}" ]]; then
	echo "=== Upgrade from the earlier installer's release: --upgrade-boringtun"
	RELEASE_DOWNLOAD="Downloading https://github.com/wiresock/amneziawg-install/releases/download/${RELEASE_TAG}/${ASSET}"
	upgraded_links() {
		test "$(store_links)" = "${RELEASE_ID} ${PREV_ID}"
	}
	daemon_runs_this_release() {
		local PID
		PID="$(main_pid)"
		[[ -n "${PID}" && "${PID}" != 0 ]] &&
			[[ "$(readlink "/proc/${PID}/exe" 2>/dev/null)" == "$(readlink -f "${STORE}/${RELEASE_ID}/boringtun-cli" 2>/dev/null)" ]] &&
			[[ "$(sha256sum "/proc/${PID}/exe" 2>/dev/null | cut -d' ' -f1)" == "${BINARY_SHA256}" ]]
	}
	UPGRADED_FIELDS="installed_release=${RELEASE_ID} pinned_release=${RELEASE_ID} previous_release=${PREV_ID} rollback_available=yes upgrade_available=no daemon_release=${RELEASE_ID}"
	status_upgraded() {
		release_status_is "${UPGRADED_FIELDS} "
	}
	upgrade_proven() { # <exit status> <log>
		[[ "$1" == 0 ]] && grep -qF "${RELEASE_DOWNLOAD}" "$2" && upgraded_links && daemon_runs_this_release && status_upgraded
	}
	check "this installer's --backend-status sees the earlier release installed and running, and offers its own" \
		release_status_is \
		"installed_release=${PREV_ID} pinned_release=${RELEASE_ID} previous_release=none rollback_available=no upgrade_available=yes daemon_release=${PREV_ID} "
	check "control: the earlier installer's state, as a skipped upgrade leaves it, does not pass as upgraded" \
		fails upgrade_proven 0 "${WORK}/install.log"
	check "control:   its store links are not the upgraded ones" fails upgraded_links
	check "control:   its daemon, the earlier one still running, is not this release's" fails daemon_runs_this_release
	check "control:   its --backend-status is not the upgraded one" fails status_upgraded
	check "control:   the install log has no download of this release" fails grep -qF "${RELEASE_DOWNLOAD}" "${WORK}/install.log"
	installation_baseline
	FAILED_BEFORE_UPGRADE="${FAILED}"
	bash "${INSTALLER}" --upgrade-boringtun >"${WORK}/upgrade-from-previous.log" 2>&1 </dev/null
	UPGRADE_RC=$?
	tail -n 8 "${WORK}/upgrade-from-previous.log" | sed 's/^/    | /'
	check "--upgrade-boringtun succeeds" test "${UPGRADE_RC}" -eq 0
	check "  it downloaded this installer's release ${RELEASE_TAG} from its public URL" \
		grep -qF "${RELEASE_DOWNLOAD}" "${WORK}/upgrade-from-previous.log"
	check "  current is this installer's release and previous the earlier one" upgraded_links
	check "  this release's binary has this installer's embedded SHA-256" \
		test "$(sha256sum "${STORE}/${RELEASE_ID}/boringtun-cli" 2>/dev/null | cut -d' ' -f1)" = "${BINARY_SHA256}"
	check "  the earlier release is kept, unchanged, as previous" \
		test "$(sha256sum "${STORE}/${PREV_ID}/boringtun-cli" 2>/dev/null | cut -d' ' -f1)" = "${PREV_BINARY_SHA256}"
	check "  the daemon was restarted" test "$(main_pid)" != "${PREV_PID}" -a "$(main_pid)" != 0
	check "  the earlier daemon is gone" bash -c '[[ "$(readlink "/proc/$1/exe" 2>/dev/null)" != "$2" ]]' _ "${PREV_PID}" "${PREV_EXE}"
	check "  the running daemon executes this release's binary, with this installer's embedded SHA-256" daemon_runs_this_release
	check "  ${UNIT} runs this release by store name" test "$(bt_unit_release "${UNIT}" "${STORE}")" = "${RELEASE_ID}"
	check "  --backend-status: this release installed, pinned and running, the earlier one previous, rollback available" status_upgraded
	check "  the helpers are now this installer's" helpers_are_this_installers
	check "  params, the runtime file and every config are byte for byte the same, each read completely before and after" \
		installation_unchanged
	check "control: the proof of the upgrade accepts this state" upgrade_proven 0 "${WORK}/upgrade-from-previous.log"
	check "control:   but not with a nonzero exit status, as after a failed upgrade" \
		fails upgrade_proven 1 "${WORK}/upgrade-from-previous.log"
	check "control:   nor with a log that has no download of this release" fails upgrade_proven 0 "${WORK}/install.log"
	check "control:   it accepts a TEST STUB --backend-status that prints the upgraded fields and succeeds" \
		with_status_stub 0 "${UPGRADED_FIELDS}" upgrade_proven 0 "${WORK}/upgrade-from-previous.log"
	check "control:   but not one that prints every upgraded field and then exits nonzero" \
		fails with_status_stub 1 "${UPGRADED_FIELDS}" upgrade_proven 0 "${WORK}/upgrade-from-previous.log"
	((FAILED == FAILED_BEFORE_UPGRADE)) ||
		die "the upgrade from the earlier installer's release is not proven; nothing is checked against this installer's release"
	RELEASE_LOG="${WORK}/upgrade-from-previous.log"
fi

check "it downloaded the public release ${RELEASE_TAG}" \
	grep -qF "Downloading https://github.com/wiresock/amneziawg-install/releases/download/${RELEASE_TAG}/${ASSET}" "${RELEASE_LOG}"
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
check "the installed MANIFEST names the embedded source commit and binary SHA-256" \
	bash -c 'grep -qx "source_commit=$2" "$1" && grep -qx "binary_sha256=$3" "$1"' _ \
	"${STORE}/${RELEASE_ID}/MANIFEST" "${SOURCE_COMMIT}" "${BINARY_SHA256}"
# The same immutable asset again, to show which bytes the installer accepted.
curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 -o "${WORK}/${ASSET}" "${RELEASE_BASE_URL}/${ASSET}"
check "the embedded URL the installer downloaded serves the embedded archive SHA-256" \
	test "$(sha256sum "${WORK}/${ASSET}" 2>/dev/null | cut -d' ' -f1)" = "${ARCHIVE_SHA256}"
check "  and the installed release is that archive's content" \
	bash -c 'for F in LICENSE MANIFEST THIRD-PARTY-LICENSES boringtun-cli; do tar -xzOf "$1" "$2/$F" | cmp -s - "$3/$F" || exit 1; done' _ \
	"${WORK}/${ASSET}" "${ASSET%.tar.gz}" "${STORE}/${RELEASE_ID}"
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
check "the daemon executes the embedded release's binary" \
	test "$(sha256sum "/proc/$(main_pid)/exe" 2>/dev/null | cut -d' ' -f1)" = "${BINARY_SHA256}"
DAEMON_ARGS="$(tr '\0' ' ' <"/proc/$(main_pid)/cmdline")"
if [[ -n "${AWG_LIVE_PREVIOUS_INSTALLER:-}" ]]; then
	if ((PREV_IMITATES)); then
		check "upgrade: params still persist imitation none" grep -qx "AWG_BORINGTUN_IMITATE_PROTOCOL='none'" /etc/amnezia/amneziawg/params
	else
		check "upgrade: params still have no imitation keys" bash -c '! grep -q "^AWG_BORINGTUN_" /etc/amnezia/amneziawg/params'
	fi
	check "upgrade: the runtime file is still FORMAT=1 alone" test "$(grep -v '^#' "/etc/amnezia/amneziawg/${IF}.boringtun")" = "FORMAT=1"
	check "upgrade: the restarted daemon names the imitation that file means, none" \
		bash -c '[[ "$1" == *" --imitate-protocol none ${2} " ]]' _ "${DAEMON_ARGS}" "${IF}"
else
	check "a fresh install imitates none" grep -qx "AWG_BORINGTUN_IMITATE_PROTOCOL='none'" /etc/amnezia/amneziawg/params
	check "and names it on the daemon's command line" bash -c '[[ "$1" == *" --imitate-protocol none ${2} " ]]' _ "${DAEMON_ARGS}" "${IF}"
fi
bash "${INSTALLER}" --backend-status >"${WORK}/status" 2>&1
check "--backend-status reports the BoringTun backend with imitation none and the running daemon" \
	test "$(grep -E '^(backend|imitation_protocol|daemon_state|daemon_imitation_protocol)=' "${WORK}/status" | tr '\n' ' ')" = \
	"backend=boringtun imitation_protocol=none daemon_state=running daemon_imitation_protocol=none "
check "  and the installed release is the pinned one" test "$(grep -c "^\(installed\|pinned\)_release=${RELEASE_ID}\$" "${WORK}/status")" -eq 2
check "awg show works" bash -c "awg show '${IF}' >/dev/null"
check "awg show all dump lists the interface" bash -c "awg show all dump | grep -q '^${IF}[[:space:]]'"

# ── Datapath ────────────────────────────────────────────────────────────────
# The client is a copy of the verified binary (outside the store, so the
# uninstall's daemon check never mistakes it for the server) in the namespace.
cp -- "${STORE}/${RELEASE_ID}/boringtun-cli" "${CLIENT_BIN}"
# Positive controls for the output scan, on private files only: its key list
# finds the keys in the client's config, and its QR pattern finds the rows of
# that config's QR code.
check "the output scan's key list matches the test client's config (private control)" \
	grep -qF -f "${AWG_LIVE_SECRET_SCAN}" "${CLIENT_CONF}"
qrencode -t ansiutf8 -l L <"${CLIENT_CONF}" >"${WORK}/qr.private" 2>/dev/null
check "the output scan's QR pattern matches a real client QR code (private control)" \
	grep -qF -e '▀' -e '▄' -e '█' "${WORK}/qr.private"
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
fw_args
FIREWALL=""
check "the interface's own firewall rules are read successfully and are present" fw_baseline FIREWALL "${FW_ARGS[@]}"
echo "    (${IF} owns $(grep -c . <<<"${FIREWALL}") firewall lines)"
same_firewall() { # <after what>
	check "the interface's own firewall rules are read successfully and are exactly as before, none duplicated, $1" \
		fw_unchanged "${FIREWALL}" "${FW_ARGS[@]}"
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
check "and the interface's firewall rules, which a successful query proves absent" fw_absent "${FW_ARGS[@]}"
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

# ── Protocol imitation ──────────────────────────────────────────────────────
WIRE="${PROJECT_ROOT}/tests/helpers/boringtun-imitation-wire.py"
client_config_hashes() {
	sha256sum /etc/amnezia/amneziawg/clients/*.conf "${CLIENT_CONF}" 2>/dev/null
}
status_line() { # <key>: its line of --backend-status
	bash "${INSTALLER}" --backend-status 2>/dev/null | grep "^$1="
}
params_s() { # <S1|S2|S3|S4>
	sed -n "s/^SERVER_AWG_$1='\\([0-9]*\\)'\$/\\1/p" /etc/amnezia/amneziawg/params
}
params_h() { # <H1|H2|H3|H4>: a number or MIN-MAX
	sed -n "s/^SERVER_AWG_$1='\\([0-9-]*\\)'\$/\\1/p" /etc/amnezia/amneziawg/params
}
# The server's packet layout for the wire helper: S1-S4, then H1-H4.
params_layout() {
	printf '%s,%s,%s,%s,%s,%s,%s,%s' "$(params_s S1)" "$(params_s S2)" "$(params_s S3)" "$(params_s S4)" \
		"$(params_h H1)" "$(params_h H2)" "$(params_h H3)" "$(params_h H4)"
}
# The test client's static public key, from which the mac1 key of the
# server's handshake messages to it derives; the wire helper checks their
# MAC1 consistency with it. Its private key is only piped.
client_public_key() {
	sed -n 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' "${CLIENT_CONF}" | head -n 1 | awg pubkey
}
# Probes from the client's network: only the imitated service answers, never
# SIP, and QUIC only for a version real servers do not offer. From loopback
# nothing is answered.
expect_probes() { # <imitation>
	local KIND EXPECTED GOT LOOPBACK_KIND
	for KIND in dns stun quic quic-v1 sip; do
		EXPECTED=silent
		case "$1:${KIND}" in
			dns:dns) EXPECTED=servfail ;;
			stun:stun) EXPECTED=binding-success ;;
			quic:quic) EXPECTED=version-negotiation ;;
		esac
		GOT="$(ip netns exec "${NS}" python3 "${WIRE}" probe "${KIND}" "${HOST_ADDR}" "${PORT}" 2>&1)"
		check "$1: a ${KIND} probe from ${CLIENT_ADDR} gets ${EXPECTED} (${GOT})" test "${GOT}" = "${EXPECTED}"
	done
	LOOPBACK_KIND="$1"
	[[ "$1" != none ]] || LOOPBACK_KIND=dns
	GOT="$(python3 "${WIRE}" probe "${LOOPBACK_KIND}" 127.0.0.1 "${PORT}" 2>&1)"
	check "$1: a ${LOOPBACK_KIND} probe from loopback is never answered (${GOT})" test "${GOT}" = silent
}
# Data through the tunnel while the client's side records the prefixes of the
# server's datagrams, which must have the imitation's shape.
wire_prefixes() { # <imitation>
	local CAPTURE="${WORK}/prefixes" COUNTS TOTAL MATCHING LAYOUT=()
	# SIP shapes each packet kind by its own S, so its capture records the
	# kind of every datagram, decided from its length and type tag. One that
	# fits two kinds is resolved by MAC1 consistency under the client's
	# public key and receiver-index correlation, in the helper's fixed
	# precedence, never by kind order; what that leaves is ambiguous.
	[[ "$1" != sip ]] || LAYOUT=("$(params_layout)" "$(client_public_key)")
	# The capture is ready before the traffic starts, must still be running
	# when the traffic has passed, and is then stopped by an authorized SIGTERM
	# (tests/helpers/boringtun-wire-checks.sh). A capture that ended before
	# that, failed, or was stopped by anything else does not count. What it
	# recorded is what its packet socket delivered; the checks below hold
	# every recorded relevant datagram to its rule, which is not proof that
	# no datagram escaped the socket.
	if ! bt_wire_capture_start "${NS}" "${VETH_CLIENT}" "${HOST_ADDR}" "${PORT}" 300 "${CAPTURE}" "${LAYOUT[@]}"; then
		bad "$1: the client-side capture started"
		return
	fi
	datapath "$1 imitation"
	if bt_wire_capture_finish "${CAPTURE}" stop 10; then
		ok "$1: the client-side capture ran from before the traffic until its authorized stop ($(wc -l <"${CAPTURE}") records)"
	else
		bad "$1: the client-side capture ran from before the traffic until its authorized stop"
		return
	fi
	if [[ "$1" == sip ]]; then
		# Each kind on its own S: a request line needs a prefix of 31 bytes,
		# so a kind whose S is 31 or more must carry one in every datagram
		# and a shorter one in none. Responses and transport must be seen;
		# the responder sends initiations and cookie replies only in
		# exceptional cases, held to the same rule when they occur. The S
		# sizes here are the installer's random ones;
		# tests/test-boringtun-sip-wire-live.sh covers fixed sizes, the 30/31
		# boundary and cookie replies.
		bt_wire_assert_sip sip "${CAPTURE}" "$(params_s S1),$(params_s S2),$(params_s S3),$(params_s S4)" \
			init:optional response:required cookie:optional transport:required &&
			echo "    (sip: $(bt_wire_pooled_shaped) server datagrams carry a request line)"
		return
	fi
	if ! COUNTS="$(python3 "${WIRE}" classify "$1" "${CAPTURE}")" || [[ ! "${COUNTS}" =~ ^(0|[1-9][0-9]*)\ (0|[1-9][0-9]*)$ ]]; then
		bad "$1: the capture has a valid prefix count ('${COUNTS:-}')"
		return
	fi
	read -r TOTAL MATCHING <<<"${COUNTS}"
	echo "    ($1: ${MATCHING} of ${TOTAL} server datagrams have the imitation's prefix shape)"
	case "$1" in
		dns | stun | quic)
			check "$1: every datagram the server sent has a $1-shaped S prefix (${MATCHING}/${TOTAL})" \
				test "${TOTAL}" -ge 10 -a "${MATCHING}" -eq "${TOTAL}"
			;;
		none)
			check "none: the server sent datagrams (${TOTAL})" test "${TOTAL}" -ge 10
			;;
	esac
}
imitation_step() { # <protocol> [hostname]
	local PROTOCOL="$1" DOMAIN="${2:-}" HASHES RC EXPECTED_RUNTIME="FORMAT=1" ARGS
	HASHES="$(client_config_hashes)"
	echo "--- imitation ${PROTOCOL}${DOMAIN:+ (${DOMAIN})}"
	bash "${INSTALLER}" --set-boringtun-imitation "${PROTOCOL}" ${DOMAIN:+"${DOMAIN}"} >"${WORK}/imitation.log" 2>&1 </dev/null
	RC=$?
	tail -n 14 "${WORK}/imitation.log" | sed 's/^/    | /'
	check "${PROTOCOL}: --set-boringtun-imitation succeeds" test "${RC}" -eq 0
	check "${PROTOCOL}: no client config was rewritten" test "$(client_config_hashes)" = "${HASHES}"
	check "${PROTOCOL}: params persist it" \
		test "$(grep '^AWG_BORINGTUN_' /etc/amnezia/amneziawg/params | tr '\n' ' ')" = "AWG_BORINGTUN_IMITATE_PROTOCOL='${PROTOCOL}' AWG_BORINGTUN_IMITATE_DOMAIN='${DOMAIN}' "
	if [[ "${PROTOCOL}" != none ]]; then
		EXPECTED_RUNTIME+=" IMITATE_PROTOCOL=${PROTOCOL}${DOMAIN:+ IMITATE_DOMAIN=${DOMAIN}}"
	fi
	check "${PROTOCOL}: the runtime file says '${EXPECTED_RUNTIME}'" \
		test "$(grep -v '^#' "/etc/amnezia/amneziawg/${IF}.boringtun" | tr '\n' ' ' | sed 's/ $//')" = "${EXPECTED_RUNTIME}"
	check_served "${PROTOCOL}"
	ARGS="$(tr '\0' ' ' <"/proc/$(main_pid)/cmdline")"
	check "${PROTOCOL}: the daemon runs --imitate-protocol ${PROTOCOL}${DOMAIN:+ --imitate-domain ${DOMAIN}}, the interface last" \
		bash -c '[[ "$1" == *" --imitate-protocol $2 ${3:+--imitate-domain $3 }$4 " ]]' _ "${ARGS}" "${PROTOCOL}" "${DOMAIN}" "${IF}"
	check "${PROTOCOL}: --probe-reply-rate is never passed" bash -c '[[ "$1" != *--probe-reply-rate* ]]' _ "${ARGS}"
	check "${PROTOCOL}: the daemon's environment is only NO_COLOR and PATH" \
		test "$(tr '\0' '\n' <"/proc/$(main_pid)/environ" | cut -d= -f1 | sort | tr '\n' ' ')" = "NO_COLOR PATH "
	check "${PROTOCOL}: --backend-status reports it, and the daemon running it" \
		test "$(bash "${INSTALLER}" --backend-status 2>/dev/null | grep -E '^(imitation_protocol|imitation_domain|daemon_state|daemon_imitation_protocol|daemon_imitation_domain)=' | tr '\n' ' ')" = \
		"imitation_protocol=${PROTOCOL} imitation_domain=${DOMAIN} daemon_state=running daemon_imitation_protocol=${PROTOCOL} daemon_imitation_domain=${DOMAIN} "
	check "${PROTOCOL}: the listen port is still ${PORT}" test "$(awg show "${IF}" listen-port 2>/dev/null)" = "${PORT}"
	check "${PROTOCOL}: no transaction directory is left" bash -c '! compgen -G "/etc/amnezia/amneziawg/.awg-imitation.*" >/dev/null'
	check "${PROTOCOL}: no scratch interface, unit or record is left" scratch_clean
	wire_prefixes "${PROTOCOL}"
	expect_probes "${PROTOCOL}"
}

imitation_step dns example.com
check "dns: the warnings name the DNS probe reply" grep -q "SERVFAIL" "${WORK}/imitation.log"
bash "${INSTALLER}" --set-boringtun-imitation dns example.com >"${WORK}/imitation.log" 2>&1 </dev/null
check "dns: setting the same imitation again changes nothing" grep -q "already dns" "${WORK}/imitation.log"
PEERS_BEFORE="$(peer_count)"
bash "${INSTALLER}" --add-client imitated >/dev/null 2>&1
check "dns: --add-client adds a peer under imitation" test "$(peer_count)" -eq $((PEERS_BEFORE + 1))
bash "${INSTALLER}" --remove-client imitated >/dev/null 2>&1
check "dns: --remove-client removes it" test "$(peer_count)" -eq "${PEERS_BEFORE}"
check "dns: the daemon still runs dns" bash -c '[[ "$(tr "\0" " " <"/proc/$1/cmdline")" == *"--imitate-protocol dns "* ]]' _ "$(main_pid)"

echo "--- AWG 3.0 keeps the imitation"
bash "${INSTALLER}" --enable-awg3 >"${WORK}/protocol.log" 2>&1 </dev/null
RC=$?
tail -n 8 "${WORK}/protocol.log" | sed 's/^/    | /'
check "dns: --enable-awg3 succeeds" test "${RC}" -eq 0
check "  and first states what header protection loses under dns" grep -q "16 random bits" "${WORK}/protocol.log"
check "  params keep the imitation" grep -qx "AWG_BORINGTUN_IMITATE_PROTOCOL='dns'" /etc/amnezia/amneziawg/params
check "  and the daemon runs it" test "$(status_line daemon_imitation_protocol)" = "daemon_imitation_protocol=dns"
check_served "AWG 3.0 with dns imitation"
datapath "AWG 3.0 with dns imitation"
expect_probes dns
LARGEST=0
for NAME in S1 S2 S3 S4; do
	SIZE="$(params_s "${NAME}")"
	((SIZE > LARGEST)) && LARGEST="${SIZE}"
done
if ((LARGEST >= 31)); then
	bash "${INSTALLER}" --set-boringtun-imitation sip >"${WORK}/imitation.log" 2>&1 </dev/null
	RC=$?
	check "AWG 3.0: sip is refused with S sizes up to ${LARGEST}" test "${RC}" -ne 0
	check "  before anything changed" test "$(status_line daemon_imitation_protocol)" = "daemon_imitation_protocol=dns"
fi
bash "${INSTALLER}" --disable-awg3 >"${WORK}/protocol.log" 2>&1 </dev/null
check "back to AWG 2.0 under dns imitation" test "$?" -eq 0
check "  keeps the imitation" test "$(status_line daemon_imitation_protocol)" = "daemon_imitation_protocol=dns"

imitation_step quic cdn.example.org
imitation_step sip pbx.example
imitation_step stun
imitation_step none
datapath "after the imitation cycle"

# ── Imitation auto ──────────────────────────────────────────────────────────
# The installed daemon with --imitate-protocol auto, set through the installer,
# and clients with different imitation settings on the one server port
# (tests/helpers/boringtun-auto-live.sh). The probe responder answers what
# each probe is; SIP and QUIC v1 stay silent, and loopback is never answered.
echo "=== Imitation auto"
auto_status() {
	bash "${INSTALLER}" --backend-status 2>/dev/null |
		grep -E '^(imitation_protocol|imitation_domain|imitation_domain_mode|daemon_state|daemon_imitation_protocol|daemon_imitation_domain|imitation_auto_support)=' |
		tr '\n' ' '
}
check "before auto: the installed binary is reported to support it" test "$(status_line imitation_auto_support)" = "imitation_auto_support=supported"
HASHES_BEFORE_AUTO="$(client_config_hashes)"
PID="$(main_pid)"
bash "${INSTALLER}" --set-boringtun-imitation auto example.com >"${WORK}/imitation.log" 2>&1 </dev/null
RC=$?
check "auto with a hostname is refused" test "${RC}" -ne 0
check "  saying that auto takes none" grep -q "auto takes no hostname" "${WORK}/imitation.log"
check "  before anything changed" test "$(main_pid)" = "${PID}" -a "$(status_line imitation_protocol)" = "imitation_protocol=none"
bt_auto_record_start "AWG 2.0"
bash "${INSTALLER}" --set-boringtun-imitation auto >"${WORK}/imitation.log" 2>&1 </dev/null
RC=$?
tail -n 14 "${WORK}/imitation.log" | sed 's/^/    | /'
check "auto: --set-boringtun-imitation auto succeeds" test "${RC}" -eq 0
check "auto: the warnings explain the per-peer selection" grep -q "for each authenticated peer" "${WORK}/imitation.log"
check "auto: no client config was rewritten" test "$(client_config_hashes)" = "${HASHES_BEFORE_AUTO}"
check "auto: params persist it, without a hostname" \
	test "$(grep '^AWG_BORINGTUN_' /etc/amnezia/amneziawg/params | tr '\n' ' ')" = "AWG_BORINGTUN_IMITATE_PROTOCOL='auto' AWG_BORINGTUN_IMITATE_DOMAIN='' "
check "auto: the runtime file says 'FORMAT=1 IMITATE_PROTOCOL=auto'" \
	test "$(grep -v '^#' "/etc/amnezia/amneziawg/${IF}.boringtun" | tr '\n' ' ' | sed 's/ $//')" = "FORMAT=1 IMITATE_PROTOCOL=auto"
check_served "auto"
ARGS="$(tr '\0' ' ' <"/proc/$(main_pid)/cmdline")"
check "auto: the daemon runs --imitate-protocol auto, the interface last" bash -c '[[ "$1" == *" --imitate-protocol auto ${2} " ]]' _ "${ARGS}" "${IF}"
check "auto: with no --imitate-domain" bash -c '[[ "$1" != *--imitate-domain* ]]' _ "${ARGS}"
check "auto: the daemon's environment is only NO_COLOR and PATH" \
	test "$(tr '\0' '\n' <"/proc/$(main_pid)/environ" | cut -d= -f1 | sort | tr '\n' ' ')" = "NO_COLOR PATH "
check "auto: --backend-status reports auto configured and running, and the binary's support, nothing per peer" \
	test "$(auto_status)" = "imitation_protocol=auto imitation_domain= imitation_domain_mode=none daemon_state=running daemon_imitation_protocol=auto daemon_imitation_domain= imitation_auto_support=supported "
check "auto: the listen port is still ${PORT}" test "$(awg show "${IF}" listen-port 2>/dev/null)" = "${PORT}"
check "auto: no transaction directory is left" bash -c '! compgen -G "/etc/amnezia/amneziawg/.awg-imitation.*" >/dev/null'
check "auto: no scratch interface, unit or record is left" scratch_clean
bash "${INSTALLER}" --set-boringtun-imitation auto >"${WORK}/imitation.log" 2>&1 </dev/null
check "auto: setting it again changes nothing" grep -q "already auto" "${WORK}/imitation.log"
datapath "auto, a client without imitation"
for KIND in dns stun quic quic-v1 sip; do
	EXPECTED=silent
	case "${KIND}" in
		dns) EXPECTED=servfail ;;
		stun) EXPECTED=binding-success ;;
		quic) EXPECTED=version-negotiation ;;
	esac
	GOT="$(ip netns exec "${NS}" python3 "${WIRE}" probe "${KIND}" "${HOST_ADDR}" "${PORT}" 2>&1)"
	check "auto: a ${KIND} probe from ${CLIENT_ADDR} gets ${EXPECTED} (${GOT})" test "${GOT}" = "${EXPECTED}"
done
for KIND in dns stun; do
	GOT="$(python3 "${WIRE}" probe "${KIND}" 127.0.0.1 "${PORT}" 2>&1)"
	check "auto: a ${KIND} probe from loopback is never answered (${GOT})" test "${GOT}" = silent
done
bt_auto_setup
bt_auto_mixed_clients
echo "--- auto: AWG 3.0 keeps auto"
bt_auto_record_start "AWG 3.0"
bash "${INSTALLER}" --enable-awg3 >"${WORK}/protocol.log" 2>&1 </dev/null
RC=$?
tail -n 8 "${WORK}/protocol.log" | sed 's/^/    | /'
check "auto: --enable-awg3 succeeds" test "${RC}" -eq 0
check "  and first states what a learned dns does to header protection" grep -q "A learned dns leaves 16 random bits" "${WORK}/protocol.log"
check "  params keep auto" grep -qx "AWG_BORINGTUN_IMITATE_PROTOCOL='auto'" /etc/amnezia/amneziawg/params
check "  and the daemon runs it" test "$(status_line daemon_imitation_protocol)" = "daemon_imitation_protocol=auto"
check_served "AWG 3.0 with auto"
bt_auto_header_protection
bash "${INSTALLER}" --disable-awg3 >"${WORK}/protocol.log" 2>&1 </dev/null
check "auto: back to AWG 2.0 under auto" test "$?" -eq 0
check "  keeps auto" test "$(status_line daemon_imitation_protocol)" = "daemon_imitation_protocol=auto"
bt_auto_teardown
datapath "auto, after the mixed clients left"

# ── Across releases: auto, a rollback to the earlier release, re-upgrade ────
# With an earlier installer, previous is the earlier installer's own
# published release, whose binary has no auto: a real version transition,
# never a relabelled copy. The rollback must refuse auto and change nothing;
# with a fixed imitation it must move the service onto that binary, keep
# traffic and configuration, and refuse auto there; the upgrade back must
# restore this release without a download, after which auto applies again.
if [[ -n "${AWG_LIVE_PREVIOUS_INSTALLER:-}" ]]; then
	echo "=== Across releases: auto, rollback to ${PREV_ID} and re-upgrade"
	check "current is this installer's release, previous the earlier one" test "$(store_links)" = "${RELEASE_ID} ${PREV_ID}"
	check "status: with auto configured, no rollback is offered to a previous binary without it" \
		release_status_is "installed_release=${RELEASE_ID} pinned_release=${RELEASE_ID} previous_release=${PREV_ID} rollback_available=no upgrade_available=no daemon_release=${RELEASE_ID} "
	installation_baseline
	PID="$(main_pid)"
	lifecycle_log() { # <flag> <log>
		bash "${INSTALLER}" "$1" >"${WORK}/$2" 2>&1 </dev/null
	}
	lifecycle_log --rollback-boringtun rollback-auto.log
	RC=$?
	tail -n 4 "${WORK}/rollback-auto.log" | sed 's/^/    | /'
	check "--rollback-boringtun with auto configured is refused" test "${RC}" -ne 0
	check "  naming the earlier release and auto" grep -qF "${PREV_ID} does not support the configured protocol imitation auto" "${WORK}/rollback-auto.log"
	check "  with the way out: a fixed imitation or none first" grep -q -- "--set-boringtun-imitation" "${WORK}/rollback-auto.log"
	check "  current and previous are unchanged" test "$(store_links)" = "${RELEASE_ID} ${PREV_ID}"
	check "  the daemon was not restarted" test "$(main_pid)" = "${PID}"
	check "  and still executes this release's binary, running auto" \
		bash -c 'daemon() { [[ "$(sha256sum "/proc/$1/exe" 2>/dev/null | cut -d" " -f1)" == "$2" && "$(tr "\0" " " <"/proc/$1/cmdline")" == *"--imitate-protocol auto "* ]]; }; daemon "$@"' _ "$(main_pid)" "${BINARY_SHA256}"
	check "  params, the runtime file and every config are byte for byte the same" installation_unchanged
	check "  the tunnel still carries traffic" wait_for 10 tunnel_ping
	bash "${INSTALLER}" --set-boringtun-imitation quic cdn.example.org >"${WORK}/imitation.log" 2>&1 </dev/null
	check "a fixed imitation, quic, is selected first" test "$?" -eq 0
	check "status: now the rollback is offered" \
		release_status_is "installed_release=${RELEASE_ID} pinned_release=${RELEASE_ID} previous_release=${PREV_ID} rollback_available=yes upgrade_available=no daemon_release=${RELEASE_ID} "
	installation_baseline
	PID="$(main_pid)"
	lifecycle_log --rollback-boringtun rollback-cross.log
	RC=$?
	tail -n 6 "${WORK}/rollback-cross.log" | sed 's/^/    | /'
	check "--rollback-boringtun to the earlier release succeeds" test "${RC}" -eq 0
	check "  current is the earlier release and previous this installer's" test "$(store_links)" = "${PREV_ID} ${RELEASE_ID}"
	check "  the daemon was restarted onto the earlier binary" test "$(main_pid)" != "${PID}" -a "$(bt_unit_release "${UNIT}" "${STORE}")" = "${PREV_ID}"
	check "  which has the earlier installer's embedded SHA-256" \
		test "$(sha256sum "/proc/$(main_pid)/exe" 2>/dev/null | cut -d' ' -f1)" = "${PREV_BINARY_SHA256}"
	check "  and is not this release's binary" test "${PREV_BINARY_SHA256}" != "${BINARY_SHA256}"
	check "  it runs the fixed imitation" \
		bash -c '[[ "$(tr "\0" " " <"/proc/$1/cmdline")" == *" --imitate-protocol quic --imitate-domain cdn.example.org ${2} "* ]]' _ "$(main_pid)" "${IF}"
	check "  status: the earlier release installed and running, this one previous and offered as the upgrade" \
		release_status_is "installed_release=${PREV_ID} pinned_release=${RELEASE_ID} previous_release=${RELEASE_ID} rollback_available=yes upgrade_available=yes daemon_release=${PREV_ID} "
	check "  status: the installed binary does not support auto" test "$(status_line imitation_auto_support)" = "imitation_auto_support=unsupported"
	check "  params, the runtime file and every config are byte for byte the same" installation_unchanged
	check "  the active instance is the one its start recorded" \
		bash -c 'source "$1" && _awgBtCheckServedByBoringtun "$2"' _ "${INSTALLER}" "${IF}"
	wire_prefixes quic
	PID="$(main_pid)"
	bash "${INSTALLER}" --set-boringtun-imitation auto >"${WORK}/imitation.log" 2>&1 </dev/null
	RC=$?
	sed -n '/ERROR/p' "${WORK}/imitation.log" | sed 's/^/    | /'
	check "on the earlier release, auto is refused" test "${RC}" -ne 0
	check "  saying that its binary does not support it" grep -qF "the installed BoringTun release ${PREV_ID} does not support protocol imitation auto" "${WORK}/imitation.log"
	check "  with the upgrade to run" grep -q -- "--upgrade-boringtun" "${WORK}/imitation.log"
	check "  before anything changed" installation_unchanged
	check "  the daemon was not restarted" test "$(main_pid)" = "${PID}"
	lifecycle_log --upgrade-boringtun reupgrade.log
	RC=$?
	tail -n 6 "${WORK}/reupgrade.log" | sed 's/^/    | /'
	check "--upgrade-boringtun back to this release succeeds" test "${RC}" -eq 0
	check "  without downloading it again" bash -c '! grep -q "Downloading" "$1"' _ "${WORK}/reupgrade.log"
	check "  current is this installer's release and previous the earlier one" test "$(store_links)" = "${RELEASE_ID} ${PREV_ID}"
	check "  the daemon executes this release's binary, with this installer's embedded SHA-256" daemon_runs_this_release
	check "  status: back where the upgrade left it" status_upgraded
	check "  params, the runtime file and every config are byte for byte the same" installation_unchanged
	datapath "re-upgraded from ${PREV_ID}"
	bash "${INSTALLER}" --set-boringtun-imitation auto >"${WORK}/imitation.log" 2>&1 </dev/null
	check "after the re-upgrade, auto applies again" test "$?" -eq 0
	check "  and the daemon runs it" bash -c '[[ "$(tr "\0" " " <"/proc/$1/cmdline")" == *" --imitate-protocol auto ${2} "* ]]' _ "$(main_pid)" "${IF}"
	datapath "auto after the re-upgrade"
	bash "${INSTALLER}" --set-boringtun-imitation none >/dev/null 2>&1 </dev/null
	check "back to imitation none" test "$(status_line daemon_imitation_protocol)" = "daemon_imitation_protocol=none"
fi

# ── SIP imitation per packet kind, fixed sizes ──────────────────────────────
# The installer draws S1-S4 at random, so the cycle above checks whichever
# rule those sizes give each kind. tests/test-boringtun-sip-wire-live.sh fixes
# them: the recorded follow-up C sizes with and without cookie replies, every
# server S at 31 and at 30, and a mixed layout, plus negative controls. It runs
# the embedded release's verified binary (the client's copy) as two peers in
# namespaces of its own, apart from the installed host.
echo "=== SIP imitation per packet kind (fixed S sizes)"
check "the fixed-size SIP wire test runs the embedded release's binary" \
	test "$(sha256sum "${CLIENT_BIN}" | cut -d' ' -f1)" = "${BINARY_SHA256}"
bash "${SCRIPT_DIR}/test-boringtun-sip-wire-live.sh" "${CLIENT_BIN}" 2>&1 | sed 's/^/    | /'
SIP_WIRE_RC="${PIPESTATUS[0]}"
check "the fixed-size SIP wire test passes" test "${SIP_WIRE_RC}" -eq 0

# ── Auto hints, fixed layout ────────────────────────────────────────────────
# What an auto server learns, on the same verified binary with fixed layouts
# (tests/test-boringtun-auto-hint-live.sh): a SIP datagram long enough to be
# an AmneziaWG candidate is never a hint, the 27-byte hint is learned, under
# AWG 3.0 BoringTun's own warning shows the header-protection refusal of that
# hint, a recorded STUN client's datagrams are or are not learned by H4 alone,
# and real dns, quic, sip and stun clients are learned under a layout their
# datagrams do not fit; each outcome derived from what reached the server.
echo "=== Auto hints (fixed layout)"
check "the auto hint test runs the embedded release's binary" \
	test "$(sha256sum "${CLIENT_BIN}" | cut -d' ' -f1)" = "${BINARY_SHA256}"
bash "${SCRIPT_DIR}/test-boringtun-auto-hint-live.sh" "${CLIENT_BIN}" 2>&1 | sed 's/^/    | /'
AUTO_HINT_RC="${PIPESTATUS[0]}"
check "the auto hint test passes" test "${AUTO_HINT_RC}" -eq 0

# ── The server-side record's completeness ───────────────────────────────────
# The record the auto checks derive their expectations from, on a real
# packet socket: arrival stamps, drain at the stop, drops and end markers
# (tests/test-boringtun-record-live.sh).
echo "=== Record completeness"
bash "${SCRIPT_DIR}/test-boringtun-record-live.sh" 2>&1 | sed 's/^/    | /'
RECORD_LIVE_RC="${PIPESTATUS[0]}"
check "the record completeness test passes" test "${RECORD_LIVE_RC}" -eq 0

# ── Binary lifecycle ────────────────────────────────────────────────────────
# A TEST FIXTURE older release (tests/helpers/boringtun-lifecycle-fixture.sh:
# the verified binary under a synthetic source commit) is made current, as an
# earlier installer would have left it, and the real pinned release, removed
# from the store, is the upgrade target: --upgrade-boringtun downloads and
# verifies it through the public release path, validates it, switches and
# restarts; --rollback-boringtun returns to the fixture; a second upgrade
# toggles back without a download, and a third is a no-op.
echo "=== Binary lifecycle"
lifecycle() { # <flag> <log>
	bash "${INSTALLER}" "$1" >"${WORK}/$2" 2>&1 </dev/null
}
bash "${INSTALLER}" --set-boringtun-imitation dns example.com >/dev/null 2>&1 </dev/null
check "the lifecycle runs under dns imitation" test "$(status_line daemon_imitation_protocol)" = "daemon_imitation_protocol=dns"
FIXTURE_ID="$(bt_fixture_release "${STORE}" "${RELEASE_ID}")"
check "a TEST FIXTURE older release is built in the store (${FIXTURE_ID})" test -n "${FIXTURE_ID}" -a -d "${STORE}/${FIXTURE_ID}"
check "  and verifies as a store release" bash -c 'source "$1" && _awgBtVerifyRelease "$2"' _ "${INSTALLER}" "${FIXTURE_ID}"
bt_fixture_make_current "${STORE}" "${FIXTURE_ID}"
rm -rf -- "${STORE:?}/${RELEASE_ID}"
systemctl restart "${UNIT}"
check "the service runs the fixture release" test "$(bt_unit_release "${UNIT}" "${STORE}")" = "${FIXTURE_ID}"
datapath "on the fixture release"
installation_baseline
bash "${INSTALLER}" --backend-status >"${WORK}/status" 2>&1
check "status: installed is the fixture, the pin is offered as an upgrade, no previous" \
	test "$(grep -E '^(installed_release|pinned_release|previous_release|rollback_available|upgrade_available|daemon_release)=' "${WORK}/status" | tr '\n' ' ')" = \
	"installed_release=${FIXTURE_ID} pinned_release=${RELEASE_ID} previous_release=none rollback_available=no upgrade_available=yes daemon_release=${FIXTURE_ID} "
PID="$(main_pid)"
lifecycle --upgrade-boringtun upgrade.log
RC=$?
tail -n 6 "${WORK}/upgrade.log" | sed 's/^/    | /'
check "--upgrade-boringtun succeeds" test "${RC}" -eq 0
check "  it downloaded the pinned release from its public URL" \
	grep -qF "Downloading https://github.com/wiresock/amneziawg-install/releases/download/${RELEASE_TAG}/${ASSET}" "${WORK}/upgrade.log"
check "  current is the pinned release and previous the fixture" test "$(store_links)" = "${RELEASE_ID} ${FIXTURE_ID}"
check "  the pinned binary has the embedded SHA-256" test "$(sha256sum "${STORE}/${RELEASE_ID}/boringtun-cli" | cut -d' ' -f1)" = "${BINARY_SHA256}"
check "  the daemon was restarted onto it" test "$(main_pid)" != "${PID}" -a "$(bt_unit_release "${UNIT}" "${STORE}")" = "${RELEASE_ID}"
check_served "after the upgrade"
check "  the imitation is kept" bash -c '[[ "$(tr "\0" " " <"/proc/$1/cmdline")" == *"--imitate-protocol dns --imitate-domain example.com "* ]]' _ "$(main_pid)"
check "  params, the runtime file and every config are byte for byte the same" installation_unchanged
check "  no scratch interface, unit or record is left" scratch_clean
datapath "after the upgrade"
bash "${INSTALLER}" --backend-status >"${WORK}/status" 2>&1
check "status after the upgrade" \
	test "$(grep -E '^(installed_release|previous_release|rollback_available|upgrade_available|daemon_release)=' "${WORK}/status" | tr '\n' ' ')" = \
	"installed_release=${RELEASE_ID} previous_release=${FIXTURE_ID} rollback_available=yes upgrade_available=no daemon_release=${RELEASE_ID} "
lifecycle --rollback-boringtun rollback.log
RC=$?
tail -n 4 "${WORK}/rollback.log" | sed 's/^/    | /'
check "--rollback-boringtun succeeds" test "${RC}" -eq 0
check "  current is the fixture again and previous the pinned release" test "$(store_links)" = "${FIXTURE_ID} ${RELEASE_ID}"
check "  the daemon runs the fixture's binary" test "$(bt_unit_release "${UNIT}" "${STORE}")" = "${FIXTURE_ID}"
check "  the configuration is unchanged" installation_unchanged
datapath "after the rollback"
lifecycle --upgrade-boringtun upgrade2.log
check "a second --upgrade-boringtun toggles back" test "$?" -eq 0 -a "$(store_links)" = "${RELEASE_ID} ${FIXTURE_ID}"
check "  without downloading again" bash -c '! grep -q "Downloading" "$1"' _ "${WORK}/upgrade2.log"
check "  on the pinned binary" test "$(bt_unit_release "${UNIT}" "${STORE}")" = "${RELEASE_ID}"
PID="$(main_pid)"
lifecycle --upgrade-boringtun upgrade3.log
check "a third --upgrade-boringtun is a no-op" grep -q "already current; nothing was changed" "${WORK}/upgrade3.log"
check "  that restarted nothing" test "$(main_pid)" = "${PID}"
check "  and left the configuration as it was" installation_unchanged
datapath "after the lifecycle"

# ── Binary lifecycle with the previous installer version's helpers ──────────
# With AWG_LIVE_BASE_INSTALLER=<PR 6 base installer>: the helpers that version
# renders replace this one's, and a TEST FIXTURE build 2 of the pinned source
# commit, whose -b2 name those helpers refuse, becomes previous. The rollback
# to it must first bring the helpers up to this installer's, so that systemd's
# restart, which runs them, accepts it; the upgrade then returns to the pin.
if [[ -n "${AWG_LIVE_BASE_INSTALLER:-}" ]]; then
	echo "=== Binary lifecycle with the previous installer version's helpers"
	bash -c 'source "$1" >/dev/null && _awgBtInstallHelpers' _ "${AWG_LIVE_BASE_INSTALLER}"
	if helpers_are_this_installers; then
		bad "the previous installer version's helpers are installed"
	else
		ok "the previous installer version's helpers are installed"
	fi
	B2_ID="$(bt_fixture_build2 "${STORE}" "${RELEASE_ID}")"
	check "a TEST FIXTURE build 2 of the pinned commit is built (${B2_ID})" test -n "${B2_ID}" -a -d "${STORE}/${B2_ID}"
	bt_fixture_make_previous "${STORE}" "${B2_ID}"
	installation_baseline
	lifecycle --rollback-boringtun rollback-b2.log
	RC=$?
	tail -n 4 "${WORK}/rollback-b2.log" | sed 's/^/    | /'
	check "--rollback-boringtun to the -b2 release succeeds" test "${RC}" -eq 0
	check "  the helpers are now this installer's" helpers_are_this_installers
	check "  current is the -b2 release and previous the pin" test "$(store_links)" = "${B2_ID} ${RELEASE_ID}"
	check "  systemd restarted the service through the reconciled helpers onto it" test "$(bt_unit_release "${UNIT}" "${STORE}")" = "${B2_ID}"
	check "  the active instance is the one its start recorded" \
		bash -c 'source "$1" && _awgBtCheckServedByBoringtun "$2"' _ "${INSTALLER}" "${IF}"
	check "  ${IF} is a TUN device with its UAPI answering" test -e "/sys/class/net/${IF}/tun_flags" -a "$(awg show "${IF}" listen-port 2>/dev/null)" = "${PORT}"
	check "  the configuration is unchanged" installation_unchanged
	datapath "on the -b2 release"
	lifecycle --upgrade-boringtun upgrade-b2.log
	check "--upgrade-boringtun returns to the pin" test "$?" -eq 0 -a "$(store_links)" = "${RELEASE_ID} ${B2_ID}"
	check "  the service runs the pinned binary" test "$(bt_unit_release "${UNIT}" "${STORE}")" = "${RELEASE_ID}"
	check "  the configuration is unchanged" installation_unchanged
	datapath "back on the pinned release"

	# The pin already current while the service is stopped and the previous
	# installer version's helpers are installed, which refuse it: the upgrade
	# must reconcile them without starting the service, and the next ordinary
	# start must then run it. A TEST FIXTURE copy of this installer pins the
	# -b2 build (the same commit and binary as build 1); nothing is published.
	echo "=== The pin already current and stopped, with the previous installer version's helpers"
	B2_INSTALLER="${WORK}/installer-pinning-test-fixture-b2.sh"
	sed 's/^AWG_BT_RELEASE_BUILD="1"$/AWG_BT_RELEASE_BUILD="2"/' "${INSTALLER}" >"${B2_INSTALLER}"
	check "a TEST FIXTURE copy of this installer pins the -b2 build" test "$(grep -c '^AWG_BT_RELEASE_BUILD="2"$' "${B2_INSTALLER}")" = 1
	lifecycle --rollback-boringtun rollback-b2-again.log
	check "  --rollback-boringtun makes the -b2 release current again" test "$?" -eq 0 -a "$(store_links)" = "${B2_ID} ${RELEASE_ID}"
	systemctl stop "${UNIT}"
	check "  the service is stopped" bash -c "! systemctl is-active --quiet '${UNIT}'"
	bash -c 'source "$1" >/dev/null && _awgBtInstallHelpers' _ "${AWG_LIVE_BASE_INSTALLER}"
	if helpers_are_this_installers; then
		bad "  the previous installer version's helpers are installed again"
	else
		ok "  the previous installer version's helpers are installed again"
	fi
	check "  (which refuse current -b2: the next start would fail)" \
		bash -c '! bash -c '\''source <(head -n -2 "$1") >/dev/null 2>&1 && _awgBtVerifyStore'\'' _ "$1" 2>/dev/null' _ "${LIBEXEC}/awg-boringtun-launch"
	STARTS_BEFORE="$(systemctl show -p InvocationID -p ActiveEnterTimestampMonotonic --value "${UNIT}" | tr '\n' ' ')"
	installation_baseline
	bash "${B2_INSTALLER}" --upgrade-boringtun >"${WORK}/upgrade-pinned-b2.log" 2>&1 </dev/null
	RC=$?
	sed 's/^/    | /' "${WORK}/upgrade-pinned-b2.log"
	check "--upgrade-boringtun with the -b2 pin already current succeeds" test "${RC}" -eq 0
	check "  it downloads nothing" bash -c '! grep -q "Downloading" "$1"' _ "${WORK}/upgrade-pinned-b2.log"
	check "  current and previous are unchanged" test "$(store_links)" = "${B2_ID} ${RELEASE_ID}"
	check "  the service was neither started nor restarted" \
		test "$(systemctl show -p InvocationID -p ActiveEnterTimestampMonotonic --value "${UNIT}" | tr '\n' ' ')" = "${STARTS_BEFORE}"
	check "  and is still stopped" bash -c "! systemctl is-active --quiet '${UNIT}'"
	check "  both helpers are reconciled" helpers_are_this_installers
	check "  it says so, and that the service was left stopped" \
		bash -c 'grep -q "helpers in .* were updated" "$1" && grep -q "was left inactive" "$1" && ! grep -q "nothing was changed" "$1"' _ "${WORK}/upgrade-pinned-b2.log"
	check "  the configuration is unchanged" installation_unchanged
	check "a plain systemctl start then succeeds" systemctl start "${UNIT}"
	check "  the service runs the -b2 binary current selects" test "$(bt_unit_release "${UNIT}" "${STORE}")" = "${B2_ID}"
	check "  the active instance is the one its start recorded" \
		bash -c 'source "$1" && _awgBtCheckServedByBoringtun "$2"' _ "${INSTALLER}" "${IF}"
	check "  ${IF} is a TUN device with its UAPI answering" test -e "/sys/class/net/${IF}/tun_flags" -a "$(awg show "${IF}" listen-port 2>/dev/null)" = "${PORT}"
	datapath "started on the already current -b2 release"
	lifecycle --upgrade-boringtun upgrade-b2-again.log
	check "--upgrade-boringtun returns to the pin again" test "$?" -eq 0 -a "$(store_links)" = "${RELEASE_ID} ${B2_ID}"
	check "  the service runs the pinned binary" test "$(bt_unit_release "${UNIT}" "${STORE}")" = "${RELEASE_ID}"
fi

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
