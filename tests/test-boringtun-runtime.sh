#!/usr/bin/env bash

# Unit tests for the internal BoringTun runtime layer of amneziawg-install.sh:
# the generated awg-boringtun-launch and awg-backend-ctl helpers, store and
# runtime-file verification, the per-attempt ownership state, the service
# drop-in, the ListenPort-filtered sync and scratch interfaces. Nothing here
# needs root, a network namespace, systemd or a real BoringTun. A fixture store
# holds a fake boringtun-cli, a small C program compiled here so that
# /proc/<pid>/exe really is the verified binary, which runs a script that
# creates real UAPI sockets. A TUN link is a sysfs entry that links to the
# daemon's /proc/<pid>/cwd, so it disappears when the daemon dies, as a real
# TUN device does. Mocks stand in for awg, awg-quick, ip, modinfo, systemd-run,
# systemctl, mktemp (to inject failures), nft and iptables. The generated
# helpers are executed, not just the functions they are built from.
#
# Requires a C compiler (cc), python3 and setpriv. Set AWG_QUICK_REFERENCE to
# an awg-quick script (for example /usr/bin/awg-quick) to also compare the
# parsers with awg-quick's own and to run awg-quick's real down/SaveConfig path.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"

for TOOL in cc python3 setpriv; do
	if ! command -v "${TOOL}" >/dev/null 2>&1; then
		echo "ERROR: ${TOOL} is required for the BoringTun runtime tests" >&2
		exit 1
	fi
done

# shellcheck source=../amneziawg-install.sh
source "${INSTALLER}"

T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-runtime-tests.XXXXXX")"
T="$(CDPATH='' cd -- "${T}" && pwd -P)"
chmod 0755 "${T}"
S="${T}/state"
MOCKBIN="${T}/mockbin"
TUNROOT="${T}/tun"
mkdir -p "${S}/live" "${S}/units" "${S}/strip" "${S}/port" "${MOCKBIN}" "${TUNROOT}"

PASS=0
FAIL=0

cleanup() {
	local F
	for F in "${S}"/live/* "${S}"/units/*; do
		[[ -f "${F}" ]] || continue
		kill -KILL "$(cat "${F}" 2>/dev/null)" 2>/dev/null
	done
	# Decoy processes that tests prove are never signalled.
	for F in $(cat "${T}/decoys" 2>/dev/null); do
		kill -KILL "${F}" 2>/dev/null
	done
	pkill -KILL -P "$$" 2>/dev/null
	rm -rf -- "${T}"
}
trap cleanup EXIT

ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}

not_ok() {
	printf '  FAIL: %s\n' "$1" >&2
	FAIL=$((FAIL + 1))
}

assert_eq() {
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected:\n%s\n    actual:\n%s\n' "$(sed 's/^/      /' <<<"$1")" "$(sed 's/^/      /' <<<"$2")" >&2
	fi
}

assert_rc() {
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3 (expected rc=$1, got rc=$2)"
	fi
}

assert_contains() {
	if [[ "$2" == *"$1"* ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected to contain: %s\n    actual: %s\n' "$1" "$2" >&2
	fi
}

assert_not_contains() {
	if [[ "$2" != *"$1"* ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected not to contain: %s\n    actual: %s\n' "$1" "$2" >&2
	fi
}

assert_true() {
	local NAME="$1"
	shift
	if "$@"; then ok "${NAME}"; else not_ok "${NAME}"; fi
}

# wait_until <seconds> <command...>: poll every 0.1 s.
wait_until() {
	local LIMIT="$1" I
	shift
	for ((I = 0; I < LIMIT * 10; I++)); do
		"$@" && return 0
		sleep 0.1
	done
	return 1
}

# ── Settings for the helpers under test ──────────────────────────────────────
AWG_BT_TRUST_ANCHOR="${T}"
AWG_BT_TRUSTED_UID="$(id -u)"
AWG_BT_STORE_DIR="${T}/lib/boringtun"
AWG_BT_LIBEXEC_DIR="${T}/libexec"
AWG_BT_RUN_DIR="${T}/run/amneziawg-install"
AWG_BT_CONFIG_DIR="${T}/etc/amneziawg"
AWG_BT_SYSTEMD_DIR="${T}/etc/systemd"
AWG_BT_UNIT_DIRS="${T}/usr/lib/systemd ${T}/lib/systemd"
AWG_BT_SYSTEMD_RUNTIME_DIR="${T}/run/systemd-absent"
AWG_BT_WG_SOCKET_DIR="${T}/run/wireguard"
AWG_BT_AWG_SOCKET_DIR="${T}/run/amneziawg"
AWG_BT_SYS_DIR="${T}/sys"
AWG_BT_PROC_DIR="/proc"
AWG_BT_TUN_DEVICE="/dev/null"
AWG_BT_PATH="${MOCKBIN}:/usr/local/bin:/usr/bin:/bin"
AWG_BT_READY_TIMEOUT=5
AWG_BT_HOST_ARCH="x86_64"
AWG_BT_TMP_DIR="${T}/tmp"
AWG_BT_MODPROBE_OVERRIDE="${T}/etc/modprobe.d/amneziawg-install-boringtun.conf"
NET="${AWG_BT_SYS_DIR}/class/net"
mkdir -p "${T}/lib" "${T}/run" "${AWG_BT_CONFIG_DIR}" "${AWG_BT_SYSTEMD_DIR}" \
	"${T}/usr/lib/systemd" "${AWG_BT_WG_SOCKET_DIR}" "${AWG_BT_AWG_SOCKET_DIR}" "${NET}" \
	"${AWG_BT_SYS_DIR}/module" "${T}/run/systemd-present" "${AWG_BT_TMP_DIR}"
chmod 0700 "${AWG_BT_CONFIG_DIR}"
PATH="${MOCKBIN}:${PATH}"
SCRATCH_DIR="${AWG_BT_RUN_DIR}/scratch"

cat >"${T}/usr/lib/systemd/awg-quick@.service" <<'EOF'
[Unit]
Description=WireGuard via wg-quick(8) for %I

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/awg-quick up %i
ExecStop=/usr/bin/awg-quick down %i
ExecReload=/bin/bash -c 'exec /usr/bin/awg-quick syncconf %i <(exec /usr/bin/awg-quick strip %i)'
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity
EOF

# ── Mocks ────────────────────────────────────────────────────────────────────
# A link <if> exists while $NET/<if> exists: a directory for a kernel link, a
# symlink to /proc/<daemon>/cwd for a TUN link. An interface is live for awg
# while $S/live/<if> holds "yes" or a running PID; $S/awg-fail makes every awg
# query fail, like a transient UAPI error.
cat >"${MOCKBIN}/awg" <<EOF
#!/bin/bash
S='${S}'
EOF
cat >>"${MOCKBIN}/awg" <<'EOF'
live() {
	local V
	[[ -f "${S}/live/$1" ]] || return 1
	V="$(cat "${S}/live/$1")"
	[[ "${V}" == yes ]] && return 0
	kill -0 "${V}" 2>/dev/null
}
echo "awg $*" >>"${S}/log"
if [[ "$1" == show || "$1" == showconf ]] && [[ -f "${S}/awg-fail" ]]; then
	echo "Unable to access interface: Connection refused" >&2
	exit 1
fi
if [[ "$1" == show && "$2" == interfaces ]]; then
	OUT=""
	for F in "${S}"/live/*; do
		[[ -e "${F}" ]] || continue
		live "${F##*/}" && OUT+="${F##*/} "
	done
	echo "${OUT% }"
	exit 0
fi
if [[ "$1" == show && $# -eq 3 ]]; then
	live "$2" || exit 1
	case "$3" in
		listen-port) cat "${S}/port/$2" 2>/dev/null || echo 51820 ;;
		fwmark) echo off ;;
		allowed-ips) echo "p	10.66.66.2/32" ;;
	esac
	exit 0
fi
if [[ "$1" == show && $# -eq 2 ]]; then
	live "$2" || exit 1
	echo "interface: $2"
	exit 0
fi
if [[ "$1" == showconf ]]; then
	live "$2" || exit 1
	# BoringTun's UAPI never returns the private key.
	printf '[Interface]\nListenPort = 51820\n\n[Peer]\nPublicKey = p\nAllowedIPs = 10.66.66.2/32\n'
	exit 0
fi
if [[ "$1" == setconf ]]; then
	cat "$3" >"${S}/setconf-input"
	exit 0
fi
if [[ "$1" == syncconf ]]; then
	cat "$3" >"${S}/syncconf-input"
	echo "syncconf-error-line" >&2
	exit "$(cat "${S}/syncconf-rc" 2>/dev/null || echo 0)"
fi
exit 0
EOF

# awg-quick: `up` refuses an existing link, takes the kernel path when
# $S/kernel-wins exists and otherwise runs the userspace implementation, then
# runs PostUp and deletes the link again if a hook fails (awg-quick's EXIT
# trap). `down` records the config it was given and runs PreDown, deletes the
# link, then runs PostDown, stopping at the first failing hook like awg-quick.
cat >"${MOCKBIN}/awg-quick" <<EOF
#!/bin/bash
S='${S}'
NET='${NET}'
CONFIG_DIR='${AWG_BT_CONFIG_DIR}'
EOF
cat >>"${MOCKBIN}/awg-quick" <<'EOF'
echo "awg-quick $* impl=${WG_QUICK_USERSPACE_IMPLEMENTATION:-}" >>"${S}/log"
hooks() { # <config> <key>
	grep -iE "^[[:space:]]*$2[[:space:]]*=" "$1" | sed -E 's/^[^=]*=[[:space:]]*//'
}
run_hooks() { # <config> <key> <interface>
	local H N=0
	while IFS= read -r H; do
		H="${H//%i/$3}"
		echo "[#] ${H}" >&2
		bash -c "${H}" || return 1
		N=$((N + 1))
		# $S/down-hold stops a down after its first PostDown hook.
		if [[ "$2" == PostDown && ${N} -eq 1 && -f "${S}/down-hold" ]]; then
			echo "$$" >"${S}/down-waiting"
			while [[ ! -f "${S}/down-release" ]]; do sleep 0.05; done
		fi
	done < <(hooks "$1" "$2")
}
config_of() {
	if [[ "$1" == */* ]]; then
		NAME="${1##*/}"
		NAME="${NAME%.conf}"
		CONF="$1"
	else
		NAME="$1"
		CONF="${CONFIG_DIR}/$1.conf"
	fi
}
case "$1" in
	strip)
		[[ -f "${S}/strip-fail" ]] && { echo "strip failed" >&2; exit 1; }
		if [[ "$2" == */* ]]; then
			grep -vE '^(Address|PostUp|PostDown) ' "$2"
		else
			cat "${S}/strip/$2"
		fi
		;;
	down)
		config_of "$2"
		cp "${CONF}" "${S}/down-config"
		echo "${CONF}" >"${S}/down-path"
		stat -c '%u %a' -- "${CONF%/*}" "${CONF}" | tr '\n' ' ' >"${S}/down-modes"
		[[ -f "${S}/down-rc" ]] && exit "$(cat "${S}/down-rc")"
		[[ " $(awg show interfaces) " == *" ${NAME} "* ]] || { echo "awg-quick: \`${NAME}' is not a WireGuard interface" >&2; exit 1; }
		run_hooks "${CONF}" PreDown "${NAME}" || exit 1
		ip link delete dev "${NAME}" || exit 1
		run_hooks "${CONF}" PostDown "${NAME}" || exit 1
		exit 0
		;;
	up)
		config_of "$2"
		if [[ -e "${NET}/${NAME}" || -L "${NET}/${NAME}" ]]; then
			echo "awg-quick: \`${NAME}' already exists" >&2
			exit 1
		fi
		if [[ -f "${S}/kernel-wins" ]]; then
			ip link add dev "${NAME}" type amneziawg || exit 1
			echo yes >"${S}/live/${NAME}"
		elif [[ -n "${WG_QUICK_USERSPACE_IMPLEMENTATION:-}" ]]; then
			"${WG_QUICK_USERSPACE_IMPLEMENTATION}" "${NAME}" || exit 1
		fi
		if [[ -f "${S}/up-rc" ]]; then
			ip link delete dev "${NAME}"
			exit "$(cat "${S}/up-rc")"
		fi
		run_hooks "${CONF}" PostUp "${NAME}" || { ip link delete dev "${NAME}"; exit 1; }
		exit 0
		;;
esac
EOF

cat >"${MOCKBIN}/modinfo" <<EOF
#!/bin/bash
echo "modinfo \$*" >>'${S}/log'
exit "\$(cat '${S}/modinfo-rc' 2>/dev/null || echo 1)"
EOF

# modprobe -n -v <name>: what modprobe would do. By default both the module and
# its rtnl-link alias resolve to the installer's install command.
cat >"${MOCKBIN}/modprobe" <<EOF
#!/bin/bash
echo "modprobe \$*" >>'${S}/log'
NAME="\${!#}"
if [[ -f "${S}/modprobe-\${NAME}" ]]; then cat "${S}/modprobe-\${NAME}"; else echo 'install /bin/false '; fi
exit "\$(cat '${S}/modprobe-rc' 2>/dev/null || echo 0)"
EOF

cat >"${MOCKBIN}/ip" <<EOF
#!/bin/bash
S='${S}'
NET='${NET}'
EOF
cat >>"${MOCKBIN}/ip" <<'EOF'
echo "ip $*" >>"${S}/log"
next_index() {
	local N
	N="$(cat "${S}/ifindex" 2>/dev/null || echo 100)"
	N=$((N + 1))
	echo "${N}" >"${S}/ifindex"
	echo "${N}"
}
if [[ "$1 $2 $3" == "link show dev" ]]; then
	[[ -e "${NET}/$4" ]]
	exit
fi
if [[ "$1 $2 $3" == "link add dev" ]]; then
	[[ -e "${NET}/$4" || -L "${NET}/$4" ]] && exit 2
	mkdir "${NET}/$4" && next_index >"${NET}/$4/ifindex"
	exit
fi
if [[ "$1 $2 $3" == "link delete dev" ]]; then
	L="${NET}/$4"
	if [[ -L "${L}" ]]; then
		TARGET="$(readlink "${L}")"
		PID="${TARGET#/proc/}"
		PID="${PID%%/*}"
		[[ -e "${L}" ]] || { rm -f "${L}"; exit 1; }
		rm -f "${L}"
		kill -TERM "${PID}" 2>/dev/null
		for _ in $(seq 30); do [[ -d "/proc/${PID}" ]] || break; sleep 0.1; done
		exit 0
	fi
	if [[ -d "${L}" ]]; then
		rm -rf "${L}" "${S}/live/$4"
		exit 0
	fi
	exit 1
fi
if [[ "$1 $2 $3 $4" == "-all -brief address show" ]]; then
	echo "$6             UNKNOWN        10.66.66.1/24"
	exit 0
fi
exit 0
EOF

# systemd-run starts the command in the background and records its PID as the
# unit's main process. $S/systemd-run-hold makes it wait for
# $S/systemd-run-release (after touching $S/systemd-run-waiting);
# $S/systemd-run-lost starts the unit but reports failure; $S/systemd-run-fail
# fails without starting anything, after creating the link a concurrent creator
# named in it made. As with --collect, a unit whose main process exited is
# gone; $S/unit-pids lists every main process started.
cat >"${MOCKBIN}/systemd-run" <<EOF
#!/bin/bash
S='${S}'
NET='${NET}'
EOF
cat >>"${MOCKBIN}/systemd-run" <<'EOF'
echo "systemd-run $*" >>"${S}/log"
UNIT=""
while [[ $# -gt 0 && "$1" != "--" ]]; do
	[[ "$1" == --unit=* ]] && UNIT="${1#--unit=}"
	shift
done
shift
if [[ -f "${S}/systemd-run-hold" ]]; then
	: >"${S}/systemd-run-waiting"
	while [[ ! -f "${S}/systemd-run-release" ]]; do sleep 0.05; done
fi
if [[ -f "${S}/systemd-run-fail" ]]; then
	RACER="$(cat "${S}/systemd-run-fail")"
	[[ -n "${RACER}" ]] && mkdir -p "${NET}/${RACER}"
	exit 1
fi
"$@" </dev/null >/dev/null 2>&1 &
MAIN=$!
echo "${MAIN}" >"${S}/units/${UNIT}"
echo "${MAIN}" >>"${S}/unit-pids"
# --collect: the unit goes away once its main process has exited.
(
	while kill -0 "${MAIN}" 2>/dev/null; do sleep 0.05; done
	[[ "$(cat "${S}/units/${UNIT}" 2>/dev/null)" != "${MAIN}" ]] || rm -f "${S}/units/${UNIT}"
) </dev/null >/dev/null 2>&1 &
[[ -f "${S}/systemd-run-lost" ]] && exit 1
exit 0
EOF

# systemctl answers for the units systemd-run started and for awg-quick@<if>
# units marked with $S/active-<unit> (and $S/mainpid-<unit>). $S/stop-hold
# makes `stop` wait for $S/stop-release. $S/daemon-reload-rc sets the status
# of daemon-reload.
cat >"${MOCKBIN}/systemctl" <<EOF
#!/bin/bash
S='${S}'
EOF
cat >>"${MOCKBIN}/systemctl" <<'EOF'
echo "systemctl $*" >>"${S}/log"
UNIT="${*: -1}"
UNIT="${UNIT%.service}"
running() {
	[[ -f "${S}/units/${UNIT}" ]] && kill -0 "$(cat "${S}/units/${UNIT}")" 2>/dev/null
}
case "$1" in
	is-active)
		running && exit 0
		[[ -f "${S}/active-${UNIT}" ]] && exit 0
		exit 3
		;;
	stop)
		if [[ -f "${S}/stop-hold" ]]; then
			: >"${S}/stop-waiting"
			while [[ ! -f "${S}/stop-release" ]]; do sleep 0.05; done
		fi
		if [[ -f "${S}/units/${UNIT}" ]]; then
			PID="$(cat "${S}/units/${UNIT}")"
			kill -TERM "${PID}" 2>/dev/null
			for _ in $(seq 30); do kill -0 "${PID}" 2>/dev/null || break; sleep 0.1; done
			kill -KILL "${PID}" 2>/dev/null
			rm -f "${S}/units/${UNIT}"
		fi
		exit 0
		;;
	reset-failed) exit 0 ;;
	start)
		touch "${S}/active-${UNIT}"
		exit 0
		;;
	daemon-reload) exit "$(cat "${S}/daemon-reload-rc" 2>/dev/null || echo 0)" ;;
	show)
		case "$3" in
			LoadState)
				if [[ -f "${S}/units/${UNIT}" || -f "${S}/known-${UNIT}" ]]; then echo loaded; else echo not-found; fi
				;;
			ActiveState)
				if running || [[ -f "${S}/active-${UNIT}" ]]; then echo active; else echo inactive; fi
				;;
			InvocationID)
				cat "${S}/invocation-${UNIT}" 2>/dev/null
				;;
			MainPID)
				if running; then
					cat "${S}/units/${UNIT}"
				elif [[ -f "${S}/mainpid-${UNIT}" ]]; then
					cat "${S}/mainpid-${UNIT}"
				else
					echo 0
				fi
				;;
		esac
		exit 0
		;;
esac
exit 0
EOF

# mktemp fails when its arguments contain the text in $S/mktemp-fail.
cat >"${MOCKBIN}/mktemp" <<EOF
#!/bin/bash
S='${S}'
REAL='$(command -v mktemp)'
EOF
cat >>"${MOCKBIN}/mktemp" <<'EOF'
# $S/mktemp-fail: fail when the arguments contain any of its lines.
if [[ -f "${S}/mktemp-fail" ]]; then
	while IFS= read -r PATTERN; do
		[[ -n "${PATTERN}" && "$*" == *"${PATTERN}"* ]] && { echo "mktemp: injected failure" >&2; exit 1; }
	done <"${S}/mktemp-fail"
fi
# $S/mktemp-obstruct: make a matching directory as asked, with a directory in
# the way of the file named in $S/mktemp-obstruct-name, so writing it fails.
if [[ -f "${S}/mktemp-obstruct" && "$*" == *"$(cat "${S}/mktemp-obstruct")"* ]]; then
	DIR="$("${REAL}" "$@")" || exit 1
	mkdir -- "${DIR}/$(cat "${S}/mktemp-obstruct-name")"
	printf '%s\n' "${DIR}"
	exit 0
fi
# $S/mktemp-hold: once, block a matching call until $S/mktemp-release exists;
# $S/mktemp-hold-b, -waiting-b and -release-b are a second, independent slot.
for SLOT in "" -b; do
	if [[ -f "${S}/mktemp-hold${SLOT}" && "$*" == *"$(cat "${S}/mktemp-hold${SLOT}")"* ]]; then
		rm -f "${S}/mktemp-hold${SLOT}"
		echo "$$" >"${S}/mktemp-waiting${SLOT}"
		while [[ ! -f "${S}/mktemp-release${SLOT}" ]]; do sleep 0.02; done
	fi
done
exec "${REAL}" "$@"
EOF
# mv, rm and chmod fail when their arguments contain the text in
# $S/<tool>-fail.
# $S/<tool>-hold blocks a matching call once until $S/<tool>-release exists,
# before it runs; $S/<tool>-hold-after does the same after it ran. Each
# touches $S/<tool>-waiting or $S/<tool>-waiting-after while it waits.
for TOOL in mv rm chmod; do
	cat >"${MOCKBIN}/${TOOL}" <<EOF
#!/bin/bash
S='${S}'
TOOL='${TOOL}'
REAL='$(command -v "${TOOL}")'
REAL_RM='$(command -v rm)'
EOF
	cat >>"${MOCKBIN}/${TOOL}" <<'EOF'
if [[ -f "${S}/${TOOL}-fail" && "$*" == *"$(cat "${S}/${TOOL}-fail")"* ]]; then
	echo "${TOOL}: injected failure" >&2
	exit 1
fi
BEFORE=0
AFTER=0
if [[ -f "${S}/${TOOL}-hold" && "$*" == *"$(cat "${S}/${TOOL}-hold")"* ]]; then
	"${REAL_RM}" -f "${S}/${TOOL}-hold"
	BEFORE=1
fi
if [[ -f "${S}/${TOOL}-hold-after" && "$*" == *"$(cat "${S}/${TOOL}-hold-after")"* ]]; then
	"${REAL_RM}" -f "${S}/${TOOL}-hold-after"
	AFTER=1
fi
if ((BEFORE)); then
	: >"${S}/${TOOL}-waiting"
	while [[ ! -f "${S}/${TOOL}-release" ]]; do sleep 0.02; done
fi
"${REAL}" "$@"
RC=$?
if ((AFTER)); then
	: >"${S}/${TOOL}-waiting-after"
	while [[ ! -f "${S}/${TOOL}-release-after" ]]; do sleep 0.02; done
fi
exit "${RC}"
EOF
done
for TOOL in nft iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore; do
	printf '#!/bin/bash\nexit 0\n' >"${MOCKBIN}/${TOOL}"
done
chmod 0755 "${MOCKBIN}"/*
# A setpriv that sets no parent-death signal, installed by tests that need a
# direct scratch daemon to outlive its guardian.
NO_PDEATHSIG_SETPRIV='#!/bin/bash
while [[ "$1" != -- ]]; do shift; done
shift
exec "$@"'
REAL_MKTEMP="$(sed -n "s/^REAL='\(.*\)'$/\1/p" "${MOCKBIN}/mktemp")"
[[ "${REAL_MKTEMP}" != "${MOCKBIN}/mktemp" ]] || { echo "ERROR: no real mktemp" >&2; exit 1; }

# ── The fake boringtun-cli ───────────────────────────────────────────────────
# A C program that stays the daemon process (so /proc/<pid>/exe is the store
# binary), makes $TUNROOT/<pid> its working directory, forwards TERM, INT and
# HUP to a worker script and dies with it; the worker dies with the daemon.
# Like BoringTun, the daemon process itself binds and holds the listening UAPI
# socket: the worker asks for it by writing the path to $TUNROOT/<pid>/bind.
# The worker's behaviour comes from $S/fake-mode:
#   ready (default)   socket, symlink, then the TUN link, then live
#   exit              exits 3 at once
#   hang              never creates anything
#   slow              waits 1.5 s first
#   hold              waits for $S/fake-release before anything else
#   socket-exit       creates its socket, waits 0.5 s and exits 4
#   foreign           binds its own socket elsewhere, while a separate process
#                     (the competitor) holds a listening socket at the UAPI path
# A TERM removes what it created; a SIGKILL leaves the sockets behind.
FAKE_WORKER="${T}/fake-worker"
cat >"${FAKE_WORKER}" <<EOF
#!/bin/bash
S='${S}'
WGDIR='${AWG_BT_WG_SOCKET_DIR}'
AWGDIR='${AWG_BT_AWG_SOCKET_DIR}'
NET='${NET}'
TUNROOT='${TUNROOT}'
EOF
cat >>"${FAKE_WORKER}" <<'EOF'
IF="${!#}"
DAEMON="${PPID}"
printf '%s\n' "$@" >"${S}/argv-${IF}"
env | sort >"${S}/env-${IF}"
ls -1 "/proc/${DAEMON}/fd" | sort -n | tr '\n' ' ' >"${S}/fds-${IF}"
MODE="$(cat "${S}/fake-mode" 2>/dev/null || echo ready)"
case "${MODE}" in
	exit) exit 3 ;;
	hang) echo "${DAEMON}" >"${S}/hang-pid"; exec sleep 60 ;;
	slow) sleep 1.5 ;;
	hold) while [[ ! -f "${S}/fake-release" ]]; do sleep 0.02; done ;;
esac
daemon_binds() { # <path>: the daemon process binds and holds the socket
	echo "$1" >"${TUNROOT}/${DAEMON}/bind.tmp"
	mv "${TUNROOT}/${DAEMON}/bind.tmp" "${TUNROOT}/${DAEMON}/bind"
	while [[ ! -e "${TUNROOT}/${DAEMON}/bound" ]]; do sleep 0.01; done
}
OWN_SOCK="${WGDIR}/${IF}.sock"
if [[ "${MODE}" == foreign ]]; then
	OWN_SOCK="${WGDIR}/.shadow-${IF}.sock"
	daemon_binds "${OWN_SOCK}"
	python3 -c 'import socket, sys, time; s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(); open(sys.argv[2], "w").write("ok"); time.sleep(120)' \
		"${WGDIR}/${IF}.sock" "${S}/foreign-ready" </dev/null >/dev/null 2>&1 &
	echo "$!" >"${S}/foreign-pid"
	while [[ ! -e "${S}/foreign-ready" ]]; do sleep 0.01; done
else
	daemon_binds "${WGDIR}/${IF}.sock"
fi
ln -sf "${WGDIR}/${IF}.sock" "${AWGDIR}/${IF}.sock"
case "${MODE}" in
	socket-exit) sleep 0.5; exit 4 ;;
esac
trap 'rm -f "${S}/live/${IF}" "${OWN_SOCK}" "${AWGDIR}/${IF}.sock"; [[ "$(readlink "${NET}/${IF}" 2>/dev/null)" == "/proc/${DAEMON}/cwd" ]] && rm -f "${NET}/${IF}"; exit 0' TERM
N="$(cat "${S}/ifindex" 2>/dev/null || echo 100)"
N=$((N + 1))
echo "${N}" >"${S}/ifindex"
echo "${N}" >"${TUNROOT}/${DAEMON}/ifindex"
: >"${TUNROOT}/${DAEMON}/tun_flags"
ln -sfn "/proc/${DAEMON}/cwd" "${NET}/${IF}"
echo "${DAEMON}" >"${S}/live/${IF}"
while :; do
	sleep 0.2 &
	wait $!
done
EOF
cat >"${T}/fake-daemon.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile pid_t child = 0;

static void forward(int sig) {
	if (child > 0)
		kill(child, sig);
}

int main(int argc, char **argv) {
	char dir[4096];
	struct sigaction sa;
	char **args;
	int status = 0;

	snprintf(dir, sizeof dir, "%s/%d", TUNROOT, (int)getpid());
	mkdir(dir, 0755);
	if (chdir(dir) != 0)
		return 111;
	/* The signals ignored at start, before this program handles any. */
	{
		char line[256];
		FILE *in = fopen("/proc/self/status", "r");
		FILE *out = fopen("sigign", "w");
		while (in && out && fgets(line, sizeof line, in))
			if (strncmp(line, "SigIgn:", 7) == 0)
				fputs(line + 7, out);
		if (in)
			fclose(in);
		if (out)
			fclose(out);
	}
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = forward;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	args = calloc((size_t)argc + 2, sizeof *args);
	if (args == NULL)
		return 112;
	args[0] = "/bin/bash";
	args[1] = WORKER;
	for (int i = 1; i < argc; i++)
		args[i + 1] = argv[i];
	child = fork();
	if (child == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		execv(args[0], args);
		_exit(127);
	}
	if (child < 0)
		return 113;
	for (;;) {
		pid_t done = waitpid(child, &status, WNOHANG);
		FILE *req;
		if (done == child || (done < 0 && errno != EINTR))
			break;
		req = fopen("bind", "r");
		if (req != NULL) {
			char path[108];
			struct sockaddr_un addr;
			int fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fgets(path, sizeof path, req) != NULL)
				path[strcspn(path, "\n")] = 0;
			fclose(req);
			memset(&addr, 0, sizeof addr);
			addr.sun_family = AF_UNIX;
			strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);
			if (fd >= 0 && bind(fd, (struct sockaddr *)&addr, sizeof addr) == 0)
				listen(fd, 16);
			rename("bind", "bound");
		}
		usleep(10000);
	}
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 128 + WTERMSIG(status);
}
EOF
FAKE_BIN_SOURCE="${T}/fake-boringtun-cli"
if ! cc -O1 -o "${FAKE_BIN_SOURCE}" -DWORKER="\"${FAKE_WORKER}\"" -DTUNROOT="\"${TUNROOT}\"" "${T}/fake-daemon.c"; then
	echo "ERROR: could not compile the fake boringtun-cli" >&2
	exit 1
fi

FAKE_COMMIT="0123456789abcdef0123456789abcdef01234567"
RELEASE_ID="boringtun-cli-0.7.1-g0123456789ab-linux-x86_64-musl"
RELEASE="${AWG_BT_STORE_DIR}/${RELEASE_ID}"

# make_store: an x86_64 store with one release and a current link.
make_store() {
	local ARCH=x86_64 SHA
	rm -rf -- "${AWG_BT_STORE_DIR}"
	mkdir -p "${RELEASE}"
	chmod 0755 "${AWG_BT_STORE_DIR}" "${RELEASE}"
	cp "${FAKE_BIN_SOURCE}" "${RELEASE}/boringtun-cli"
	chmod 0755 "${RELEASE}/boringtun-cli"
	SHA="$(sha256sum "${RELEASE}/boringtun-cli" | cut -d' ' -f1)"
	cat >"${RELEASE}/MANIFEST" <<EOF
artifact_format=1
name=boringtun-cli
version=0.7.1
source_repository=https://github.com/Wiresock-Foundation/wiresock-boringtun
source_commit=${FAKE_COMMIT}
source_date_epoch=1790285008
target=${ARCH}-unknown-linux-musl
os=linux
arch=${ARCH}
libc=musl
linkage=static
rust_toolchain=1.98.1
rustc=rustc 1.98.1 (48a229cea 2026-09-01)
cargo=cargo 1.98.1 (797e8a9bc 2026-08-05)
build_command=cargo build --release --locked -p boringtun-cli --bin boringtun-cli --target ${ARCH}-unknown-linux-musl
build_profile=release,strip=symbols
rustflags=--remap-path-prefix=<source>=/boringtun --remap-path-prefix=<cargo-home>=/cargo
binary=boringtun-cli
binary_sha256=${SHA}
license=LICENSE (BSD-3-Clause)
third_party_licenses=THIRD-PARTY-LICENSES
EOF
	chmod 0644 "${RELEASE}/MANIFEST"
	echo "BSD-3-Clause" >"${RELEASE}/LICENSE"
	echo "THIRD-PARTY LICENSES FOR boringtun-cli" >"${RELEASE}/THIRD-PARTY-LICENSES"
	ln -s "${RELEASE_ID}" "${AWG_BT_STORE_DIR}/current"
}

write_runtime_file() { # <if> [content]
	local FILE="${AWG_BT_CONFIG_DIR}/${1}.boringtun"
	rm -f -- "${FILE}"
	printf '%s' "${2-$(_awgBtRenderRuntimeFile)$'\n'}" >"${FILE}"
	chmod 0600 "${FILE}"
}

SERVER_KEY_LINE="PrivateKey = cHJpdmF0ZS1rZXktZm9yLXRlc3RzLW9ubHktMDAwMDA9"
write_server_config() { # <if> [extra interface lines] [directory]
	local DIR="${3:-${AWG_BT_CONFIG_DIR}}"
	cat >"${DIR}/$1.conf" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
${SERVER_KEY_LINE}
${2:-}

[Peer]
PublicKey = p
AllowedIPs = 10.66.66.2/32
EOF
	chmod 0600 "${DIR}/$1.conf"
}

# A new activation of awg-quick@<if>: systemd gives every one its own
# INVOCATION_ID, which the helpers take as the start attempt's identity.
new_activation() {
	INVOCATION_ID="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
	export INVOCATION_ID
}
new_activation

# Take over the attempt that awgBackendQuickUp drew for <if>.
adopt_attempt() { # <if>
	local FILE
	FILE="$(ls "${AWG_BT_RUN_DIR}/$1@"*.state 2>/dev/null | head -n 1)"
	FILE="${FILE##*@}"
	INVOCATION_ID="${FILE%.state}"
	export INVOCATION_ID
}

# precheck always opens a new attempt, as each start of the unit does.
ctl_precheck() {
	new_activation
	"${CTL}" precheck "$@"
}

# Stop every daemon a test started and forget all state.
reset_state() {
	local F
	for F in "${S}"/live/* "${S}"/units/*; do
		[[ -f "${F}" ]] || continue
		kill -KILL "$(cat "${F}" 2>/dev/null)" 2>/dev/null
	done
	sleep 0.1
	rm -rf -- "${S}" "${AWG_BT_RUN_DIR}"
	mkdir -p "${S}/live" "${S}/units" "${S}/strip" "${S}/port"
	: >"${S}/log"
	rm -f -- "${AWG_BT_WG_SOCKET_DIR}"/* "${AWG_BT_WG_SOCKET_DIR}"/.shadow-* "${AWG_BT_AWG_SOCKET_DIR}"/*
	rm -rf -- "${NET:?}"/* "${AWG_BT_SYS_DIR}/module"/* "${AWG_BT_TMP_DIR:?}"/*
	[[ -f "${T}/decoys" ]] || : >"${T}/decoys"
	new_activation
}

install_helpers() {
	rm -rf -- "${AWG_BT_LIBEXEC_DIR}"
	_awgBtInstallHelpers
}

LAUNCH="${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
CTL="${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"

# run <command...>: sets RC, OUT (stdout) and ERR (stderr).
run() {
	"$@" >"${T}/out" 2>"${T}/err"
	RC=$?
	OUT="$(cat "${T}/out")"
	ERR="$(cat "${T}/err")"
}

# ensureAwgBackendReady exits on failure, like the kernel implementation.
in_subshell() {
	("$@")
}

pid_alive() {
	[[ "${1:-}" =~ ^[0-9]+$ ]] && kill -0 "$1" 2>/dev/null
}

pid_gone() {
	[[ ! -d "/proc/${1:-0}" ]] || [[ "$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)" == Z ]]
}

# The state and flags of the current attempt.
state_file() { # <if>
	printf '%s/%s@%s.state\n' "${AWG_BT_RUN_DIR}" "$1" "${INVOCATION_ID}"
}

state_get() { # <if> <key>
	sed -n "s/^$2=//p" "$(state_file "$1")" 2>/dev/null
}

flag_is() { # <if> <flag>
	[[ -f "${AWG_BT_RUN_DIR}/$1@${INVOCATION_ID}.$2" ]]
}

hook_count() { # <line>
	grep -cxF -- "$1" "${HOOK_LOG}" 2>/dev/null
}

# What systemd does for awg-quick@<if> with the BoringTun drop-in.
service_start() { # <if>
	ctl_precheck "$1" || { "${CTL}" poststop "$1"; return 1; }
	WG_QUICK_USERSPACE_IMPLEMENTATION="${LAUNCH}" awg-quick up "$1" || { "${CTL}" poststop "$1"; return 1; }
	"${CTL}" poststart "$1" || { "${CTL}" poststop "$1"; return 1; }
}

# ExecStop, then the cgroup kill of whatever still runs, then ExecStopPost.
service_stop() { # <if>
	local PID
	"${CTL}" stop "$1"
	STOP_RC=$?
	PID="$(state_get "$1" PID)"
	if [[ -n "${PID}" ]] && pid_alive "${PID}"; then
		kill -TERM "${PID}" 2>/dev/null
		wait_until 3 pid_gone "${PID}"
	fi
	"${CTL}" poststop "$1"
}

# A crash: SIGKILL, then ExecStop and ExecStopPost.
service_crash() { # <if>
	local PID
	PID="$(state_get "$1" PID)"
	kill -KILL "${PID}"
	wait_until 3 pid_gone "${PID}"
	"${CTL}" stop "$1"
	STOP_RC=$?
	"${CTL}" poststop "$1"
}

nothing_left() { # <if>
	[[ ! -e "${NET}/$1" && ! -e "${AWG_BT_WG_SOCKET_DIR}/$1.sock" && ! -L "${AWG_BT_AWG_SOCKET_DIR}/$1.sock" &&
		! -e "${AWG_BT_RUN_DIR}/boringtun-$1.pid" ]] && ! compgen -G "${AWG_BT_RUN_DIR}/$1@*" >/dev/null
}

bind_socket() { # <path>
	python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$1"
}

echo "=== The activation boundary ==="
assert_eq "kernel" "${AWG_BACKEND}" "a sourced installer starts on the kernel backend"
assert_eq "kernel" \
	"$(env AWG_BACKEND=boringtun _AWG_BORINGTUN_RUNTIME_INTERNAL=1 bash -c 'source "$1"; echo "${AWG_BACKEND}"' _ "${INSTALLER}")" \
	"an exported AWG_BACKEND is discarded when the installer loads"
assert_eq "0" "$(grep -c '_AWG_BORINGTUN_RUNTIME_INTERNAL\|_awgInternalSelectBoringtunRuntimeForTesting\|_awgBtRuntimeSelected' "${INSTALLER}")" \
	"the installer has no internal activation flag or selector any more"
# Exported variables, including the removed internal flag, never reach the
# BoringTun branches: the dispatchers still take the kernel path.
run env AWG_BACKEND=boringtun _AWG_BORINGTUN_RUNTIME_INTERNAL=1 bash -c \
	'source "$1"; ip() { echo "ip $*"; }; awgBackendCreateScratchInterface awgp1' _ "${INSTALLER}"
assert_eq "ip link add dev awgp1 type amneziawg" "${OUT}" "exported AWG_BACKEND=boringtun and the old internal flag still dispatch to the kernel"
run bash -c 'source "$1"; AWG_BACKEND=boringtun; normalizeAwgBackend && echo "${AWG_BACKEND}"' _ "${INSTALLER}"
assert_rc 0 "${RC}" "a persisted AWG_BACKEND=boringtun is supported"
assert_eq "boringtun" "${OUT}" "and normalizes to boringtun"
run bash -c 'source "$1"; AWG_BACKEND=boringtun; SERVER_PUB_IP=x; serializeParams "$2"' _ "${INSTALLER}" "${T}/params-out"
assert_rc 0 "${RC}" "serializeParams persists the BoringTun backend"
assert_eq "AWG_BACKEND='boringtun'" "$(grep '^AWG_BACKEND=' "${T}/params-out")" "as AWG_BACKEND='boringtun'"
run bash -c 'source "$1"; AWG_BACKEND=boringtun; ip() { echo "ip $*"; }; _awgBtScratchCreate() { echo "bt-scratch $*"; }; awgBackendCreateScratchInterface awgp1' _ "${INSTALLER}"
assert_eq "bt-scratch awgp1" "${OUT}" "a validated AWG_BACKEND=boringtun dispatches to the BoringTun runtime, never to the kernel"

echo "=== Kernel invariance of shared text and the kernel drop-in ==="
assert_eq "could not create a temporary amneziawg interface (load the amneziawg kernel module for this kernel)
the running amneziawg kernel module did not read back AWG 3.0 fields unchanged (upgrade the loaded module to match amneziawg-tools)
the running amneziawg kernel module did not read back RandomTrailers/DisableCookies (upgrade both amneziawg-tools and the loaded kernel module to AWG 3.1)
awg setconf rejected AWG 3.0 fields (upgrade amneziawg-tools and the running amneziawg kernel module together)
awg setconf rejected RandomTrailers/DisableCookies (upgrade amneziawg-tools and the running amneziawg kernel module to AWG 3.1 together)
is not supported by both the installed awg tool and the running kernel module
a staged protocol configuration was rejected by the installed tooling or running module" \
	"$(for K in create readback30 readback31 setconf30 setconf31 summary staged; do AWG_BACKEND=kernel awgBackendValidationText "${K}"; done)" \
	"kernel probe and validation messages are the historical text verbatim"
KERNEL_DROPIN="$(declare -f installAmneziaWG | awk '/override.conf" <<.EOF.$/{p=1; next} p && /^EOF$/{exit} p')"
assert_eq "[Unit]
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=modprobe amneziawg" "${KERNEL_DROPIN}" "the kernel drop-in written by installAmneziaWG is unchanged"
assert_not_contains "WG_QUICK_USERSPACE_IMPLEMENTATION" "$(declare -f installAmneziaWG ensureAmneziawgKernelModule)" \
	"kernel install and repair never set a userspace implementation"

echo "=== Generated helpers ==="
make_store
install_helpers
assert_rc 0 "$?" "helpers are generated into the libexec directory"
assert_eq "755 755" "$(stat -c '%a' "${LAUNCH}") $(stat -c '%a' "${CTL}")" "both helpers are executable, mode 0755"
FIRST_LAUNCH="$(cat "${LAUNCH}")"
_awgBtInstallHelpers
assert_eq "0" "${_AWG_BT_FILE_CHANGED}" "regenerating unchanged helpers leaves them alone"
assert_eq "${FIRST_LAUNCH}" "$(_awgBtRenderHelper launch)" "helper output is deterministic"
assert_eq "${FIRST_LAUNCH}" "$(env SERVER_PRIV_KEY=secret WG_LOG_FILE=/x AWG_BT_STORE_DIR=/evil AWG_BT_MODPROBE_OVERRIDE=/evil TMPD="${AWG_BT_TMP_DIR}" MPO="${AWG_BT_MODPROBE_OVERRIDE}" bash -c 'source "$1"; AWG_BT_TRUST_ANCHOR="$2"; AWG_BT_TRUSTED_UID="$3"; AWG_BT_STORE_DIR="$4"; AWG_BT_LIBEXEC_DIR="$5"; AWG_BT_RUN_DIR="$6"; AWG_BT_CONFIG_DIR="$7"; AWG_BT_SYSTEMD_DIR="$8"; AWG_BT_UNIT_DIRS="$9"; shift 9; AWG_BT_SYSTEMD_RUNTIME_DIR="$1"; AWG_BT_WG_SOCKET_DIR="$2"; AWG_BT_AWG_SOCKET_DIR="$3"; AWG_BT_SYS_DIR="$4"; AWG_BT_PROC_DIR="$5"; AWG_BT_TUN_DEVICE="$6"; AWG_BT_PATH="$7"; AWG_BT_READY_TIMEOUT="$8"; AWG_BT_HOST_ARCH="$9"; AWG_BT_TMP_DIR="${TMPD}"; AWG_BT_MODPROBE_OVERRIDE="${MPO}"; _awgBtRenderHelper launch' _ \
	"${INSTALLER}" "${AWG_BT_TRUST_ANCHOR}" "${AWG_BT_TRUSTED_UID}" "${AWG_BT_STORE_DIR}" "${AWG_BT_LIBEXEC_DIR}" \
	"${AWG_BT_RUN_DIR}" "${AWG_BT_CONFIG_DIR}" "${AWG_BT_SYSTEMD_DIR}" "${AWG_BT_UNIT_DIRS}" "${AWG_BT_SYSTEMD_RUNTIME_DIR}" \
	"${AWG_BT_WG_SOCKET_DIR}" "${AWG_BT_AWG_SOCKET_DIR}" "${AWG_BT_SYS_DIR}" "${AWG_BT_PROC_DIR}" "${AWG_BT_TUN_DEVICE}" \
	"${AWG_BT_PATH}" "${AWG_BT_READY_TIMEOUT}" "${AWG_BT_HOST_ARCH}")" \
	"the environment of the generating shell never reaches a generated helper"
SERVER_PRIV_KEY="c2VjcmV0LWtleS1uZXZlci1pbi1oZWxwZXJzLTAwMDA9"
assert_not_contains "${SERVER_PRIV_KEY}" "$(_awgBtRenderHelper launch)$(_awgBtRenderHelper ctl)" "no params value is embedded in a helper"
unset SERVER_PRIV_KEY
assert_contains "readonly AWG_BT_STORE_DIR=" "${FIRST_LAUNCH}" "helpers embed their paths as read-only settings"
assert_contains "export PATH=" "${FIRST_LAUNCH}" "helpers set their own PATH"
assert_contains "declare -A _AWG_BT_STATE=()" "${FIRST_LAUNCH}" "helpers declare the ownership state they parse"
assert_true "the generated launcher is valid bash" bash -n "${LAUNCH}"
assert_true "the generated awg-backend-ctl is valid bash" bash -n "${CTL}"
for FUNCTION in $(grep -oE '\b_awgBt[A-Za-z]+\b' <(declare -f ${_AWG_BT_HELPER_FUNCTIONS} ${_AWG_BT_CTL_FUNCTIONS} ${_AWG_BT_LAUNCH_FUNCTIONS}) | sort -u); do
	if declare -F "${FUNCTION}" >/dev/null && [[ " ${_AWG_BT_HELPER_FUNCTIONS} ${_AWG_BT_CTL_FUNCTIONS} ${_AWG_BT_LAUNCH_FUNCTIONS} " != *" ${FUNCTION} "* ]]; then
		not_ok "a helper calls ${FUNCTION}, which the helpers do not carry"
	fi
done
ok "every _awgBt function a helper calls is carried by the helpers"
ln -s "${T}/elsewhere" "${T}/symlink-dest"
_awgBtWriteManagedFile "${T}/symlink-dest" 0644 <<<"x" 2>/dev/null
assert_rc 1 "$?" "a managed file is never written through a symlink"
assert_true "and the symlink target is not created" test ! -e "${T}/elsewhere"
mkdir -p "${T}/state-dir-target"
_awgBtWriteState "${T}/state-dir-target" "x" 2>/dev/null
assert_rc 1 "$?" "a state file is never moved into a directory that took its name"
assert_eq "" "$(find "${T}/state-dir-target" -mindepth 1)" "and nothing is written into that directory"
MANIFEST_KEYS_IN_SCRIPT="$(sed -n 's/^BTA_MANIFEST_KEYS="\(.*\)"$/\1/p' "${PROJECT_ROOT}/scripts/boringtun-artifact.sh")"
assert_eq "${MANIFEST_KEYS_IN_SCRIPT}" "${AWG_BT_MANIFEST_KEYS}" \
	"the installer reads exactly the MANIFEST keys the artifact script writes"

echo "=== Service drop-in and daemon-reload (S8) ==="
GOLDEN_DROPIN='# Managed by amneziawg-install (backend: boringtun). Regenerated from params.
[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
RemainAfterExit=no
PIDFile=/run/amneziawg-install/boringtun-%i.pid
TimeoutStartSec=30
Restart=on-failure
RestartSec=3
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=/usr/local/libexec/amneziawg-install/awg-boringtun-launch
ExecStartPre=/usr/local/libexec/amneziawg-install/awg-backend-ctl precheck %i
ExecStartPost=/usr/local/libexec/amneziawg-install/awg-backend-ctl poststart %i
ExecReload=
ExecReload=/usr/local/libexec/amneziawg-install/awg-backend-ctl sync %i
ExecStop=
ExecStop=/usr/local/libexec/amneziawg-install/awg-backend-ctl stop %i
ExecStopPost=/usr/local/libexec/amneziawg-install/awg-backend-ctl poststop %i'
assert_eq "${GOLDEN_DROPIN}" "$(bash -c 'source "$1"; _awgBtRenderServiceDropIn' _ "${INSTALLER}")" \
	"the production drop-in matches the golden text"
reset_state
rm -rf -- "${AWG_BT_SYSTEMD_DIR:?}"/*
_awgBtInstallServiceFiles awgbt0
assert_rc 0 "$?" "service files are written for an interface"
assert_eq "644" "$(stat -c '%a' "${AWG_BT_SYSTEMD_DIR}/awg-quick@awgbt0.service.d/override.conf")" "the drop-in is mode 0644"
assert_eq "600" "$(stat -c '%a' "${AWG_BT_CONFIG_DIR}/awgbt0.boringtun")" "the runtime file is mode 0600"
assert_eq "1" "$(grep -c '^systemctl daemon-reload' "${S}/log")" "writing service files reloads systemd"
rm -rf -- "${AWG_BT_SYSTEMD_DIR:?}"/*
: >"${S}/log"
echo 1 >"${S}/daemon-reload-rc"
_awgBtInstallServiceFiles awgbt0
assert_rc 1 "$?" "a failing daemon-reload after a new drop-in fails the reconciliation"
_awgBtInstallServiceFiles awgbt0
assert_rc 1 "$?" "a retry with the now identical drop-in still fails while daemon-reload fails"
assert_eq "2" "$(grep -c '^systemctl daemon-reload' "${S}/log")" "and it retried daemon-reload although the drop-in was unchanged"
rm -f "${S}/daemon-reload-rc"
_awgBtInstallServiceFiles awgbt0
assert_rc 0 "$?" "the next retry succeeds once daemon-reload succeeds"
assert_eq "3" "$(grep -c '^systemctl daemon-reload' "${S}/log")" "because daemon-reload ran again"
_awgBtInstallServiceFiles 'bad/name' 2>/dev/null
assert_rc 1 "$?" "service files are refused for an invalid interface name"

echo "=== Store verification (through the generated launcher) ==="
IF=awgbt0
# launch_expect_refused <label> <expected stderr fragment>: the launcher must
# fail before starting BoringTun.
launch_expect_refused() {
	rm -f "${S}/argv-${IF}"
	run "${LAUNCH}" "${IF}"
	if [[ "${RC}" != 0 && ! -e "${S}/argv-${IF}" && "${ERR}" == *"$2"* ]]; then
		ok "$1"
	else
		not_ok "$1 (rc=${RC}, started=$([[ -e "${S}/argv-${IF}" ]] && echo yes || echo no), stderr: ${ERR})"
	fi
}
reset_state
make_store
install_helpers
write_runtime_file "${IF}"

rm "${AWG_BT_STORE_DIR}/current"
launch_expect_refused "a store without a current link is refused" "no current release link"
ln -s "../elsewhere" "${AWG_BT_STORE_DIR}/current"
launch_expect_refused "a current link out of the store is refused" "must be a root-owned link"
rm "${AWG_BT_STORE_DIR}/current"
mkdir "${AWG_BT_STORE_DIR}/current"
launch_expect_refused "a current that is not a link is refused" "no current release link"
rmdir "${AWG_BT_STORE_DIR}/current"
ln -s "${RELEASE_ID}" "${AWG_BT_STORE_DIR}/current"

chmod 0775 "${RELEASE}"
launch_expect_refused "a group-writable release directory is refused" "writable by someone other than root"
chmod 0755 "${RELEASE}"
chmod 0777 "${AWG_BT_STORE_DIR}"
launch_expect_refused "a world-writable store directory is refused" "writable by someone other than root"
chmod 0755 "${AWG_BT_STORE_DIR}"
chmod 0775 "${T}/lib"
launch_expect_refused "a group-writable parent directory of the store is refused" "writable by someone other than root"
chmod 0755 "${T}/lib"
chmod 0775 "${RELEASE}/boringtun-cli"
launch_expect_refused "a group-writable binary is refused" "writable by someone other than root"
chmod 0644 "${RELEASE}/boringtun-cli"
launch_expect_refused "a non-executable binary is refused" "writable by someone other than root"
chmod 0755 "${RELEASE}/boringtun-cli"
chmod 0666 "${RELEASE}/MANIFEST"
launch_expect_refused "a writable MANIFEST is refused" "writable by someone other than root"
chmod 0644 "${RELEASE}/MANIFEST"
mv "${RELEASE}/boringtun-cli" "${T}/outside-binary"
ln -s "${T}/outside-binary" "${RELEASE}/boringtun-cli"
launch_expect_refused "a binary that is a symlink out of the store is refused" "incomplete or writable"
rm "${RELEASE}/boringtun-cli"
mv "${T}/outside-binary" "${RELEASE}/boringtun-cli"

cp "${RELEASE}/MANIFEST" "${T}/manifest.good"
manifest_case() { # <label> <fragment> <sed expression or "append:<line>">
	cp "${T}/manifest.good" "${RELEASE}/MANIFEST"
	if [[ "$3" == append:* ]]; then
		printf '%s\n' "${3#append:}" >>"${RELEASE}/MANIFEST"
	else
		sed -i "$3" "${RELEASE}/MANIFEST"
	fi
	launch_expect_refused "$1" "$2"
}
manifest_case "a MANIFEST without binary_sha256 is refused" "has no binary_sha256" '/^binary_sha256=/d'
manifest_case "a repeated MANIFEST key is refused" "unexpected or repeated key arch" 'append:arch=x86_64'
manifest_case "an unknown MANIFEST key is refused" "unexpected or repeated key channel" 'append:channel=stable'
manifest_case "a malformed MANIFEST line is refused" "malformed line" 'append:not a key value line'
manifest_case "a MANIFEST for another architecture is refused" "does not describe release" 's/^arch=x86_64$/arch=aarch64/'
manifest_case "a MANIFEST whose commit does not name the release is refused" "does not describe release" 's/^source_commit=0/source_commit=f/'
manifest_case "a MANIFEST of another artifact format is refused" "does not describe release" 's/^artifact_format=1$/artifact_format=2/'
manifest_case "a binary that does not match binary_sha256 is refused" "does not match the binary_sha256" 's/^binary_sha256=.*/binary_sha256=0000000000000000000000000000000000000000000000000000000000000000/'
cp "${T}/manifest.good" "${RELEASE}/MANIFEST"
run bash -c 'source "$1"; AWG_BT_TRUST_ANCHOR="$2"; AWG_BT_TRUSTED_UID=12345; AWG_BT_STORE_DIR="$3"; AWG_BT_HOST_ARCH=x86_64; _awgBtVerifyStore' _ "${INSTALLER}" "${T}" "${AWG_BT_STORE_DIR}"
assert_rc 1 "${RC}" "a store not owned by the trusted user is refused"
run bash -c 'source "$1"; AWG_BT_TRUST_ANCHOR="$2"; AWG_BT_TRUSTED_UID="$3"; AWG_BT_STORE_DIR="$4"; AWG_BT_HOST_ARCH=riscv64; _awgBtVerifyStore' _ "${INSTALLER}" "${T}" "${AWG_BT_TRUSTED_UID}" "${AWG_BT_STORE_DIR}"
assert_rc 1 "${RC}" "a host without BoringTun artifacts is refused"
_awgBtVerifyStore
VERIFIED_BIN="$(readlink -f "${RELEASE}/boringtun-cli")"
assert_eq "${VERIFIED_BIN}" "${_AWG_BT_VERIFIED_BIN}" "a good store yields the canonical binary path"

echo "=== Runtime file ==="
runtime_case() { # <label> <fragment> <content> [mode]
	write_runtime_file "${IF}" "$3"
	[[ -z "${4:-}" ]] || chmod "$4" "${AWG_BT_CONFIG_DIR}/${IF}.boringtun"
	launch_expect_refused "$1" "$2"
}
rm -f "${AWG_BT_CONFIG_DIR}/${IF}.boringtun"
launch_expect_refused "a missing runtime file is refused" "missing or not a regular file"
runtime_case "a runtime file with mode 0644 is refused" "mode 0600" $'FORMAT=1\n' 0644
runtime_case "a repeated runtime key is refused" "repeated key FORMAT" $'FORMAT=1\nFORMAT=1\n'
runtime_case "an unknown runtime key is refused" "unknown key IMITATE_PROTOCOL" $'FORMAT=1\nIMITATE_PROTOCOL=dns\n'
runtime_case "a malformed runtime line is refused" "malformed line" $'FORMAT=1\nexport X=1\n'
runtime_case "a runtime file without FORMAT is refused" "has no FORMAT" $'# comment only\n'
runtime_case "an unsupported runtime FORMAT is refused" "unsupported FORMAT 2" $'FORMAT=2\n'
runtime_case "shell syntax in the runtime file is refused, never evaluated" "malformed line" $'FORMAT=1\n$(touch '"${T}"'/pwned)\n'
assert_true "and nothing in it was executed" test ! -e "${T}/pwned"
rm -f "${AWG_BT_CONFIG_DIR}/${IF}.boringtun"
ln -s "${T}/manifest.good" "${AWG_BT_CONFIG_DIR}/${IF}.boringtun"
launch_expect_refused "a runtime file that is a symlink is refused" "missing or not a regular file"
rm -f "${AWG_BT_CONFIG_DIR}/${IF}.boringtun"
write_runtime_file "${IF}"
run bash -c 'source "$1"; AWG_BT_TRUST_ANCHOR="$2"; AWG_BT_TRUSTED_UID=12345; AWG_BT_CONFIG_DIR="$3"; _awgBtReadRuntimeFile "$4"' _ "${INSTALLER}" "${T}" "${AWG_BT_CONFIG_DIR}" "${IF}"
assert_rc 1 "${RC}" "a runtime file not owned by the trusted user is refused"

echo "=== Launcher ==="
for BAD in "" "abcdefghijklmnop" "a b" "a/b" "../x" '$(id)' "a;b" "-x!"; do
	rm -f "${S}"/argv-*
	run "${LAUNCH}" "${BAD}"
	if [[ "${RC}" == 2 ]] && ! compgen -G "${S}/argv-*" >/dev/null; then
		ok "invalid interface name '${BAD}' is refused before anything starts"
	else
		not_ok "invalid interface name '${BAD}' is refused before anything starts (rc=${RC})"
	fi
done
run "${LAUNCH}" awgbt0 extra
assert_rc 2 "${RC}" "the launcher takes exactly one argument"

reset_state
write_runtime_file "${IF}"
write_server_config "${IF}"
launch_expect_refused "the launcher refuses an interface that has not passed precheck" "has not passed awg-backend-ctl precheck"
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
ctl_precheck "${IF}" 2>/dev/null
rmdir "${AWG_BT_SYS_DIR}/module/amneziawg"
assert_eq "started" "$(state_get "${IF}" PHASE)" "(a refused precheck leaves PHASE=started)"
launch_expect_refused "the launcher refuses an attempt whose precheck failed" "has not passed awg-backend-ctl precheck"

# launch_ready: a precheck followed by the launcher, as awg-quick@<if> runs them.
launch_ready() {
	ctl_precheck "${IF}" && "${LAUNCH}" "${IF}"
}
reset_state
write_runtime_file "${IF}"
ctl_precheck "${IF}"
assert_rc 0 "$?" "precheck opens a start attempt"
assert_eq "0 prechecked" "$(state_get "${IF}" PRE_EXISTING) $(state_get "${IF}" PHASE)" \
	"which records that nothing of the name existed and that every check passed"
exec 7>"${T}/held-descriptor"
run env WG_TUN_FD=3 WG_UAPI_FD=4 WG_LOG_FILE=/tmp/leak WG_LOG_LEVEL=trace WG_SUDO=true \
	WG_IMITATE_PROTOCOL=dns WG_IMITATE_DOMAIN=example.com WG_THREADS=64 LD_PRELOAD=/tmp/evil.so \
	SERVER_PRIV_KEY=secret "${LAUNCH}" "${IF}"
exec 7>&-
assert_rc 0 "${RC}" "the launcher succeeds once the daemon is ready"
assert_eq "0 1 2 " "$(cat "${S}/fds-${IF}")" "no descriptor of the caller, such as a held lock, reaches the daemon"
PID="$(cat "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid" 2>/dev/null)"
assert_eq "$(cat "${S}/live/${IF}" 2>/dev/null)" "${PID}" "the PID file names the running daemon"
assert_true "the daemon keeps running after the launcher exits" pid_alive "${PID}"
assert_eq "${VERIFIED_BIN}" "$(readlink "/proc/${PID}/exe")" "the daemon's executable is the verified store binary"
assert_eq "--foreground
--disable-drop-privileges
--verbosity
error
${IF}" "$(cat "${S}/argv-${IF}")" "the daemon gets exactly the production arguments"
assert_eq "${VERIFIED_BIN}" "$(tr '\0' '\n' <"/proc/${PID}/cmdline" | sed -n 1p)" \
	"the daemon runs the verified store binary by its canonical path"
ENV_NAMES="$(cut -d= -f1 "${S}/env-${IF}" | grep -vxE 'PWD|SHLVL|_' | tr '\n' ' ')"
assert_eq "NO_COLOR PATH " "${ENV_NAMES}" "the daemon's environment holds only PATH and NO_COLOR"
assert_eq "PATH=${AWG_BT_PATH}" "$(grep '^PATH=' "${S}/env-${IF}")" "with the helper's fixed PATH"
assert_eq "700" "$(stat -c '%a' "${AWG_BT_RUN_DIR}")" "the runtime directory is private (0700)"
assert_eq "600" "$(stat -c '%a' "$(state_file "${IF}")")" "the state file is private (0600)"
assert_eq "launched ${PID} $(_awgBtProcessStartTime "${PID}")" \
	"$(state_get "${IF}" PHASE) $(state_get "${IF}" PID) $(state_get "${IF}" PID_START)" \
	"the state records the daemon by PID and start time"
assert_eq "$(_awgBtPathId "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock") $(_awgBtPathId "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock") $(cat "${NET}/${IF}/ifindex")" \
	"$(state_get "${IF}" WG_SOCK) $(state_get "${IF}" AWG_SOCK) $(state_get "${IF}" IFINDEX)" \
	"and its socket nodes and TUN link"
assert_eq "$(state_get "${IF}" WG_SOCK)" "$(_awgBtSocketHeldBy "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "${PID}" "$(_awgBtProcessStartTime "${PID}")")" \
	"S2b: the recorded socket is one the daemon itself holds, by its descriptors and the socket diagnostics"
bash -c 'sleep 60 </dev/null >/dev/null 2>&1 & echo $!' | tee -a "${T}/decoys" >"${T}/other-pid"
assert_eq "" "$(_awgBtSocketHeldBy "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "$(cat "${T}/other-pid")" "$(_awgBtProcessStartTime "$(cat "${T}/other-pid")")")" \
	"S2b: no other process is taken for its holder"
kill -TERM "${PID}"
wait_until 3 pid_gone "${PID}"

reset_state
write_runtime_file "${IF}"
ctl_precheck "${IF}"
echo slow >"${S}/fake-mode"
"${LAUNCH}" "${IF}" >/dev/null 2>&1 &
LAUNCHER_PID=$!
sleep 0.8
assert_true "no PID file exists while the daemon is not ready yet" test ! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
wait "${LAUNCHER_PID}"
assert_rc 0 "$?" "the launcher succeeds after a slow start"
assert_true "the PID file appears after readiness" test -s "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
kill -TERM "$(cat "${S}/live/${IF}")" 2>/dev/null
sleep 0.5

reset_state
write_runtime_file "${IF}"
echo exit >"${S}/fake-mode"
SECONDS=0
run launch_ready
assert_rc 1 "${RC}" "a daemon that exits at once fails the launch"
assert_contains "exited before ${IF} became ready" "${ERR}" "and the early exit is reported"
assert_true "and it is reported without waiting for the timeout" test "${SECONDS}" -lt 3
assert_true "and no PID file is left" test ! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"

reset_state
write_runtime_file "${IF}"
echo socket-exit >"${S}/fake-mode"
run launch_ready
assert_rc 1 "${RC}" "a daemon that dies after binding its socket fails the launch"
assert_true "and the socket nodes it was seen to create are removed" test ! -e "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" -a ! -L "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"

# S2a: another process holds a live socket at the UAPI path; the daemon holds
# its own socket elsewhere, so the path is never the daemon's.
AWG_BT_READY_TIMEOUT=2
install_helpers
AWG_BT_READY_TIMEOUT=5
reset_state
write_runtime_file "${IF}"
echo foreign >"${S}/fake-mode"
run launch_ready
FOREIGN_PID="$(cat "${S}/foreign-pid" 2>/dev/null)"
assert_rc 1 "${RC}" "S2a: a daemon whose UAPI path another process holds never becomes ready"
assert_eq "" "$(state_get "${IF}" WG_SOCK)$(state_get "${IF}" AWG_SOCK)" "S2a: the foreign socket is never recorded as the daemon's"
assert_true "S2a: and the competitor's live socket is left in place" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
assert_true "S2a: (still held by the competitor)" pid_alive "${FOREIGN_PID}"
run ctl_precheck "${IF}"
assert_rc 1 "${RC}" "S2a: the next precheck refuses the name instead of guessing"
assert_contains "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "${ERR}" "S2a: and names the socket it will not remove"
kill -KILL "${FOREIGN_PID}" 2>/dev/null
rm -f "${S}/fake-mode"
install_helpers

# A helper set with a one-second readiness timeout.
AWG_BT_READY_TIMEOUT=1
install_helpers
AWG_BT_READY_TIMEOUT=5
reset_state
write_runtime_file "${IF}"
echo hang >"${S}/fake-mode"
SECONDS=0
run launch_ready
assert_rc 1 "${RC}" "a daemon that never becomes ready fails the launch"
assert_contains "did not become ready within 1 seconds" "${ERR}" "and the timeout is reported"
assert_true "and the launch gives up after the bounded wait" test "${SECONDS}" -lt 5
HANG_PID="$(cat "${S}/hang-pid" 2>/dev/null)"
assert_true "and the tracked daemon was stopped" wait_until 3 pid_gone "${HANG_PID}"
assert_true "and no PID file is left" test ! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
assert_eq "launch-failed" "$(state_get "${IF}" PHASE)" "S9: the cleaned-up failed launch is recorded as launch-failed"
install_helpers

reset_state
write_runtime_file "${IF}"
ctl_precheck "${IF}"
bind_socket "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
launch_expect_refused "the launcher refuses a socket that appeared after precheck" "appeared after precheck"
assert_true "and leaves that socket alone" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
assert_eq "launch-failed" "$(state_get "${IF}" PHASE)" "S9: a launcher that started nothing records the attempt as launch-failed"
run "${CTL}" poststop "${IF}"
assert_true "S9: which poststop finishes: nothing owned was created" test ! -e "$(state_file "${IF}")"
assert_true "S9: and leaves the foreign socket alone" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
rm -f "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
reset_state
write_runtime_file "${IF}"
ctl_precheck "${IF}"
mkdir "${NET}/${IF}"
launch_expect_refused "the launcher refuses a link that appeared after precheck" "appeared after precheck"
assert_true "and leaves that link alone" test -d "${NET}/${IF}"

echo "=== awg-backend-ctl precheck ==="
reset_state
install_helpers
write_runtime_file "${IF}"
write_server_config "${IF}"
run ctl_precheck "${IF}"
assert_rc 0 "${RC}" "precheck passes on a verified host"
run ctl_precheck
assert_rc 2 "${RC}" "awg-backend-ctl requires a command and an interface"
run ctl_precheck 'bad name'
assert_rc 2 "${RC}" "awg-backend-ctl refuses an invalid interface name"
run "${CTL}" frobnicate "${IF}"
assert_rc 2 "${RC}" "awg-backend-ctl refuses an unknown command"
run "${CTL}" stop "${IF}" "${AWG_BT_CONFIG_DIR}/${IF}.conf"
assert_rc 2 "${RC}" "only precheck and poststart take a config"
run ctl_precheck "${IF}" "relative/${IF}.conf"
assert_rc 2 "${RC}" "a relative config path is refused"
run ctl_precheck "${IF}" "${AWG_BT_CONFIG_DIR}/other.conf"
assert_rc 2 "${RC}" "a config not named after the interface is refused"
ln -sf "${AWG_BT_CONFIG_DIR}/${IF}.conf" "${T}/${IF}.conf"
run ctl_precheck "${IF}" "${T}/${IF}.conf"
assert_rc 2 "${RC}" "a config path that is not canonical is refused"
rm -f "${T}/${IF}.conf"

precheck_refused() { # <label> <fragment>
	run ctl_precheck "${IF}"
	if [[ "${RC}" != 0 && "${ERR}" == *"$2"* ]]; then ok "$1"; else not_ok "$1 (rc=${RC}: ${ERR})"; fi
}
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
precheck_refused "precheck refuses while the amneziawg kernel module is loaded" "kernel module is loaded"
rmdir "${AWG_BT_SYS_DIR}/module/amneziawg"
echo 0 >"${S}/modinfo-rc"
precheck_refused "precheck refuses when the kernel module is installed and autoloadable" "would autoload it"
rm -f "${S}/modinfo-rc"
assert_contains "modinfo -n amneziawg" "$(cat "${S}/log")" "the autoload check asks modinfo for the module"
mv "${MOCKBIN}/modinfo" "${T}/modinfo.saved"
if ! PATH="${AWG_BT_PATH}" command -v modinfo >/dev/null 2>&1; then
	precheck_refused "precheck fails closed when modinfo is unavailable" "modinfo is unavailable"
else
	ok "precheck fails closed when modinfo is unavailable (skipped: a real modinfo is on the helper PATH)"
fi
mv "${T}/modinfo.saved" "${MOCKBIN}/modinfo"

# An installed module is accepted only while the installer's load override is
# in force: its exact, trusted file, and modprobe resolving both the module and
# the rtnl-link alias to that install command.
OVERRIDE="${AWG_BT_MODPROBE_OVERRIDE}"
module_check() { # <expected rc> <label>
	run _awgBtCheckKernelModule
	assert_rc "$1" "${RC}" "$2"
}
mkdir -p "${OVERRIDE%/*}"
chmod 0755 "${T}/etc" "${OVERRIDE%/*}"
echo 0 >"${S}/modinfo-rc"
_awgBtRenderModprobeOverride >"${OVERRIDE}"
chmod 0644 "${OVERRIDE}"
: >"${S}/log"
module_check 0 "an installed module blocked by the installer's override passes the module check"
assert_contains "modprobe -n -v amneziawg" "$(cat "${S}/log")" "the override is checked for the module name"
assert_contains "modprobe -n -v rtnl-link-amneziawg" "$(cat "${S}/log")" "and for the rtnl-link alias that ip link add requests"
assert_eq "install amneziawg /bin/false" "$(grep -v '^#' "${OVERRIDE}")" "the override's only directive is 'install amneziawg /bin/false'"
precheck_ok_with_override() {
	run ctl_precheck "${IF}"
	if [[ "${ERR}" != *"kernel module"* && "${ERR}" != *"autoload"* ]]; then ok "$1"; else not_ok "$1 (rc=${RC}: ${ERR})"; fi
}
precheck_ok_with_override "precheck does not refuse a module that the override blocks"
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
precheck_refused "a loaded module is refused even with the override in place" "kernel module is loaded"
rmdir "${AWG_BT_SYS_DIR}/module/amneziawg"
printf '%s\n# local edit\n' "$(_awgBtRenderModprobeOverride)" >"${OVERRIDE}"
module_check 1 "a changed override file does not count"
printf 'blacklist amneziawg\n' >"${OVERRIDE}"
module_check 1 "a blacklist line instead of the install command does not count"
_awgBtRenderModprobeOverride >"${OVERRIDE}"
chmod 0664 "${OVERRIDE}"
module_check 1 "a group-writable override file does not count"
chmod 0644 "${OVERRIDE}"
mv "${OVERRIDE}" "${T}/override.real"
ln -s "${T}/override.real" "${OVERRIDE}"
module_check 1 "an override that is a symlink does not count"
rm -f "${OVERRIDE}"
mv "${T}/override.real" "${OVERRIDE}"
chmod 0777 "${OVERRIDE%/*}"
module_check 1 "an override in a directory writable by others does not count"
chmod 0755 "${OVERRIDE%/*}"
echo "insmod /lib/modules/x/amneziawg.ko" >"${S}/modprobe-amneziawg"
module_check 1 "an override that another modprobe configuration outranks does not count"
rm -f "${S}/modprobe-amneziawg"
echo "insmod /lib/modules/x/amneziawg.ko" >"${S}/modprobe-rtnl-link-amneziawg"
module_check 1 "an override that does not cover the rtnl-link alias does not count"
rm -f "${S}/modprobe-rtnl-link-amneziawg"

# modprobe -n -v as the Ubuntu 26.04 coexistence job printed it: the
# dependencies it would load first, then the block command, each line ending
# in a space. The dependency lines disappear once those modules are loaded.
REAL_DEPS=(
	"insmod /lib/modules/7.0.0-1012-azure/kernel/net/ipv4/udp_tunnel.ko.zst"
	"insmod /lib/modules/7.0.0-1012-azure/kernel/net/ipv6/ip6_udp_tunnel.ko.zst"
	"insmod /lib/modules/7.0.0-1012-azure/kernel/lib/crypto/libcurve25519.ko.zst"
)
modprobe_output() { # <name> <line>..., each written with modprobe's trailing space
	local NAME="$1"
	shift
	if (($#)); then printf '%s \n' "$@"; fi >"${S}/modprobe-${NAME}"
}
modprobe_reset() {
	rm -f "${S}/modprobe-amneziawg" "${S}/modprobe-rtnl-link-amneziawg"
}
modprobe_output amneziawg "${REAL_DEPS[@]}" "install /bin/false"
assert_eq "insmod /lib/modules/7.0.0-1012-azure/kernel/net/ipv4/udp_tunnel.ko.zst " "$(head -n 1 "${S}/modprobe-amneziawg")" "the fixture keeps modprobe's trailing space"
module_check 0 "the real output with dependency insmods before 'install /bin/false' counts for the module"
modprobe_reset
modprobe_output rtnl-link-amneziawg "${REAL_DEPS[@]}" "install /bin/false"
module_check 0 "and for the rtnl-link alias"
modprobe_output amneziawg "${REAL_DEPS[@]}" "install /bin/false"
module_check 0 "and for both at once"
install_helpers
precheck_ok_with_override "the generated precheck accepts the real output too"
modprobe_output amneziawg "insmod /lib/modules/x/kernel/net/ipv4/udp_tunnel.ko.zst opt=1" "install /bin/false"
module_check 0 "a dependency insmod with module options is still a dependency"
refused_output() { # <label> <line>... of the output for amneziawg
	local LABEL="$1"
	shift
	modprobe_reset
	modprobe_output amneziawg "$@"
	module_check 1 "${LABEL}"
}
refused_output "dependencies followed by a real insmod of amneziawg.ko do not count" \
	"${REAL_DEPS[@]}" "insmod /lib/modules/7.0.0-1012-azure/updates/dkms/amneziawg.ko.zst"
refused_output "an insmod of amneziawg before 'install /bin/false' does not count" \
	"insmod /lib/modules/x/updates/dkms/amneziawg.ko.zst" "install /bin/false"
refused_output "an uncompressed amneziawg.ko among the dependencies does not count" \
	"${REAL_DEPS[0]}" "insmod /lib/modules/x/extra/amneziawg.ko" "install /bin/false"
refused_output "'install /bin/true' does not count" "${REAL_DEPS[@]}" "install /bin/true"
refused_output "'install /usr/bin/false' does not count" "install /usr/bin/false"
refused_output "'install sh -c false' does not count" "install sh -c false"
refused_output "'install /bin/false' followed by another action does not count" \
	"install /bin/false" "insmod /lib/modules/x/kernel/net/ipv4/udp_tunnel.ko.zst"
refused_output "'install /bin/false' twice does not count" "install /bin/false" "install /bin/false"
refused_output "'install /bin/false' with more on its line does not count" "install /bin/false; insmod /x/amneziawg.ko"
refused_output "a dependency action that is not an insmod does not count" "rmmod udp_tunnel" "install /bin/false"
refused_output "a dependency's own install command, which can load anything, does not count" \
	"install /sbin/modprobe --ignore-install amneziawg" "install /bin/false"
refused_output "a relative insmod path does not count" "insmod udp_tunnel.ko" "install /bin/false"
refused_output "empty output does not count"
refused_output "output of blank lines only does not count" "" " "
modprobe_reset
echo 1 >"${S}/modprobe-rc"
module_check 1 "a failing modprobe dry run does not count"
rm -f "${S}/modprobe-rc"
mv "${MOCKBIN}/modprobe" "${T}/modprobe.saved"
if ! PATH="${AWG_BT_PATH}" command -v modprobe >/dev/null 2>&1; then
	module_check 1 "without modprobe the override cannot be proven in force"
else
	ok "without modprobe the override cannot be proven in force (skipped: a real modprobe is on the helper PATH)"
fi
mv "${T}/modprobe.saved" "${MOCKBIN}/modprobe"
module_check 0 "the restored override passes again"
rm -f "${OVERRIDE}" "${S}/modinfo-rc"
module_check 0 "without an installed module the override is irrelevant"

AWG_BT_TUN_DEVICE="${T}/no-tun"
install_helpers
precheck_refused "precheck refuses without a TUN device" "not a usable character device"
AWG_BT_TUN_DEVICE="${T}/state/log"
install_helpers
precheck_refused "precheck refuses a TUN path that is not a character device" "not a usable character device"
AWG_BT_TUN_DEVICE="/dev/null"
AWG_BT_PROC_DIR="${T}/proc-no-ipv6"
mkdir -p "${AWG_BT_PROC_DIR}/sys/net"
install_helpers
precheck_refused "precheck refuses when the IPv6 socket family is unavailable" "IPv6 socket family is unavailable"
AWG_BT_PROC_DIR="/proc"
install_helpers

cp "${RELEASE}/MANIFEST" "${T}/manifest.good"
sed -i 's/^binary_sha256=.*/binary_sha256=0000000000000000000000000000000000000000000000000000000000000000/' "${RELEASE}/MANIFEST"
precheck_refused "precheck refuses a binary that fails verification" "does not match the binary_sha256"
cp "${T}/manifest.good" "${RELEASE}/MANIFEST"
chmod 0775 "${CTL}"
precheck_refused "precheck refuses a helper that others can modify" "writable by someone other than root"
chmod 0755 "${CTL}"
write_runtime_file "${IF}" $'FORMAT=1\nFORMAT=1\n'
precheck_refused "precheck refuses an invalid runtime file" "repeated key FORMAT"
write_runtime_file "${IF}"

for SAVE in "SaveConfig = true" "saveconfig=TRUE" "SaveConfig = false
SaveConfig = true"; do
	write_server_config "${IF}" "${SAVE}"
	precheck_refused "precheck refuses SaveConfig enabled ($(tr '\n' ';' <<<"${SAVE}"))" "SaveConfig = true"
done
write_server_config "${IF}" "SaveConfig = maybe"
precheck_refused "precheck refuses an invalid SaveConfig value, as awg-quick would" "invalid SaveConfig"
write_server_config "${IF}" "SaveConfig = true
SaveConfig = false"
run ctl_precheck "${IF}"
assert_rc 0 "${RC}" "the last SaveConfig wins, as in awg-quick"
printf '[Interface]\nPrivateKey = k\n[Peer]\nSaveConfig = true\n' >"${AWG_BT_CONFIG_DIR}/${IF}.conf"
run ctl_precheck "${IF}"
assert_rc 0 "${RC}" "SaveConfig outside [Interface] is ignored, as in awg-quick"
rm -f "${AWG_BT_CONFIG_DIR}/${IF}.conf"
precheck_refused "precheck refuses when the server config is missing" "unreadable or has an invalid SaveConfig"
write_server_config "${IF}"

mv "${T}/usr/lib/systemd/awg-quick@.service" "${T}/unit.saved"
precheck_refused "precheck refuses when the packaged unit is missing" "is not installed"
sed 's#^ExecStart=.*#ExecStart=/usr/bin/awg-quick up-custom %i#' "${T}/unit.saved" >"${T}/usr/lib/systemd/awg-quick@.service"
precheck_refused "precheck refuses a packaged unit with another bring-up" "no longer brings the interface up"
mv "${T}/unit.saved" "${T}/usr/lib/systemd/awg-quick@.service"
touch "${AWG_BT_SYSTEMD_DIR}/awg-quick@.service"
precheck_refused "precheck refuses a local unit that replaces the packaged one" "replaces the packaged"
rm -f "${AWG_BT_SYSTEMD_DIR}/awg-quick@.service"

echo "=== B1: a failed start never touches what existed before it ==="
HOOK_LOG="${T}/hooks.log"
write_server_config "${IF}" "PostUp = echo up >>${HOOK_LOG}
PreDown = echo predown >>${HOOK_LOG}
PostDown = echo down >>${HOOK_LOG}"
# A: a kernel AmneziaWG interface of the name exists and the module is loaded.
reset_state
: >"${HOOK_LOG}"
mkdir "${NET}/${IF}"
echo 7 >"${NET}/${IF}/ifindex"
echo yes >"${S}/live/${IF}"
bind_socket "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
run service_start "${IF}"
assert_rc 1 "${RC}" "B1-A: the start is refused"
assert_contains "already exists" "${ERR}" "B1-A: precheck names what already exists"
assert_true "B1-A: the pre-existing kernel interface survives the failed start" test -d "${NET}/${IF}" -a -f "${S}/live/${IF}"
assert_true "B1-A: and so does its socket" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "B1-A: ExecStopPost never runs awg-quick down on it"
assert_not_contains "ip link delete" "$(cat "${S}/log")" "B1-A: and never deletes a link"
assert_eq "" "$(cat "${HOOK_LOG}")" "B1-A: and runs none of its hooks"
assert_true "B1-A: the attempt's state is gone" test ! -e "${AWG_BT_RUN_DIR}/${IF}.state"
# The same with a kernel link but no module: precheck refuses on the link.
rmdir "${AWG_BT_SYS_DIR}/module/amneziawg"
run service_start "${IF}"
assert_rc 1 "${RC}" "B1-A: a pre-existing link alone also makes precheck refuse"
assert_true "B1-A: and it survives too" test -d "${NET}/${IF}"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "B1-A: still without awg-quick down"
# B: no link at precheck; awg-quick's kernel-first path wins afterwards.
reset_state
: >"${HOOK_LOG}"
touch "${S}/kernel-wins"
run service_start "${IF}"
rm -f "${S}/kernel-wins"
assert_rc 1 "${RC}" "B1-B: a start where awg-quick took the kernel path fails in poststart"
assert_contains "is not a TUN device" "${ERR}" "B1-B: poststart says why"
assert_contains "awg-quick down ${AWG_BT_RUN_DIR}/down." "$(cat "${S}/log")" \
	"B1-B: ExecStopPost brings down the kernel link this attempt created, through a SaveConfig-free copy"
assert_true "B1-B: that link is gone" test ! -e "${NET}/${IF}"
assert_eq "up
predown
down" "$(cat "${HOOK_LOG}")" "B1-B: its PostUp ran once and awg-quick down ran PreDown and PostDown once"
assert_true "B1-B: nothing is left" nothing_left "${IF}"

# A crash, then an operator's kernel link of the same name before poststop.
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
: >"${S}/log"
# (A real TUN device vanishes with its daemon; the fixture's dangling entry is removed.)
rm -f "${NET}/${IF}"
ip link add dev "${IF}" type amneziawg
echo yes >"${S}/live/${IF}"
"${CTL}" stop "${IF}" 2>/dev/null
run "${CTL}" poststop "${IF}"
assert_true "B1: a link of the name that replaced the crashed one survives" test -d "${NET}/${IF}"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "B1: and is never brought down"
assert_eq "up" "$(cat "${HOOK_LOG}")" "B1: PostDown, which may address the name, is not replayed while another link has it"
assert_contains "cleanup is ambiguous" "${ERR}" "B1: the ambiguity is reported"
assert_true "B1: and the attempt's state is kept for diagnosis" test -f "$(state_file "${IF}")"
ip link delete dev "${IF}"

# B1a: an earlier attempt's state never authorises the current attempt's
# cleanup. Attempt A takes the kernel path and its poststop never runs, so its
# state (up, with the kernel link's ifindex) stays behind with the link.
reset_state
: >"${HOOK_LOG}"
touch "${S}/kernel-wins"
ctl_precheck "${IF}" && WG_QUICK_USERSPACE_IMPLEMENTATION="${LAUNCH}" awg-quick up "${IF}" && "${CTL}" poststart "${IF}" 2>/dev/null
rm -f "${S}/kernel-wins"
ATTEMPT_A="${INVOCATION_ID}"
STALE_FILES="$(ls "${AWG_BT_RUN_DIR}/${IF}@${ATTEMPT_A}".* | sort)"
assert_true "B1a: (attempt A left an up state for the kernel link behind)" flag_is "${IF}" up
: >"${S}/log"
# Attempt B: its precheck fails before it can record anything.
new_activation
echo "${AWG_BT_RUN_DIR}" >"${S}/chmod-fail"
"${CTL}" precheck "${IF}" 2>/dev/null
assert_rc 1 "$?" "B1a: attempt B's precheck fails before recording anything"
rm -f "${S}/chmod-fail"
run "${CTL}" poststop "${IF}"
assert_true "B1a: B's poststop leaves the pre-existing link alone" test -d "${NET}/${IF}"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "B1a: and never runs awg-quick down"
assert_eq "up" "$(cat "${HOOK_LOG}")" "B1a: and runs none of its hooks"
assert_eq "${STALE_FILES}" "$(ls "${AWG_BT_RUN_DIR}/${IF}@${ATTEMPT_A}".* | sort)" "B1a: and neither reads nor removes A's state"
# Attempt C: its precheck refuses the existing link; its poststop is as harmless.
run service_start "${IF}"
assert_rc 1 "${RC}" "B1a: attempt C refuses the existing link"
assert_true "B1a: C's poststop leaves it alone too" test -d "${NET}/${IF}"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "B1a: still without awg-quick down"
assert_eq "${STALE_FILES}" "$(ls "${AWG_BT_RUN_DIR}/${IF}@${ATTEMPT_A}".* | sort)" "B1a: and A's state is still untouched"
ip link delete dev "${IF}"

# B1b: the owned link is replaced while the down copy is being prepared.
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
echo "/down." >"${S}/mktemp-hold"
"${CTL}" stop "${IF}" 2>"${T}/stop.err" &
STOPPER=$!
wait_until 5 test -s "${S}/mktemp-waiting"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
rm -f "${NET}/${IF}"
ip link add dev "${IF}" type amneziawg
echo yes >"${S}/live/${IF}"
REPLACEMENT_INDEX="$(cat "${NET}/${IF}/ifindex")"
: >"${S}/log"
touch "${S}/mktemp-release"
wait "${STOPPER}"
assert_rc 1 "$?" "B1b: stop fails when the link changed while its down was prepared"
rm -f "${S}"/mktemp-*
assert_eq "${REPLACEMENT_INDEX}" "$(cat "${NET}/${IF}/ifindex" 2>/dev/null)" "B1b: the replacement link survives"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "B1b: awg-quick down is never run against it"
assert_contains "replaced while its down was prepared" "$(cat "${T}/stop.err")" "B1b: and the ambiguity is reported"
assert_true "B1b: no down was recorded as started" test ! -e "${AWG_BT_RUN_DIR}/${IF}@${INVOCATION_ID}.down"
run "${CTL}" poststop "${IF}"
assert_eq "up" "$(cat "${HOOK_LOG}")" "B1b: poststop does not replay PostDown while the replacement holds the name"
assert_true "B1b: the replacement still survives" test -d "${NET}/${IF}"
ip link delete dev "${IF}"

echo "=== awg-backend-ctl poststart ==="
write_server_config "${IF}" "PostUp = echo up >>${HOOK_LOG}
PreDown = echo predown >>${HOOK_LOG}
PostDown = echo down >>${HOOK_LOG}"
# launch_up: precheck and awg-quick up with the launcher, without poststart.
launch_up() {
	ctl_precheck "${IF}" && WG_QUICK_USERSPACE_IMPLEMENTATION="${LAUNCH}" awg-quick up "${IF}"
}
poststart_refused() { # <label> <fragment>
	run "${CTL}" poststart "${IF}"
	if [[ "${RC}" != 0 && "${ERR}" == *"$2"* ]]; then ok "$1"; else not_ok "$1 (rc=${RC}: ${ERR})"; fi
	assert_true "  and the attempt is recorded as up for poststop" flag_is "${IF}" up
	service_stop "${IF}"
}
reset_state
: >"${HOOK_LOG}"
launch_up
run "${CTL}" poststart "${IF}"
assert_rc 0 "${RC}" "poststart accepts the verified BoringTun serving a TUN interface"
assert_true "and records the attempt as up" flag_is "${IF}" up
service_stop "${IF}"
reset_state
launch_up
echo 999999 >"${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
poststart_refused "poststart refuses a PID file that does not name the launched daemon" "does not name the running BoringTun daemon"
reset_state
launch_up
sed -i 's/^PID_START=.*/PID_START=1/' "$(state_file "${IF}")"
poststart_refused "poststart refuses a daemon whose start time is not the recorded one" "does not name the running BoringTun daemon"
reset_state
launch_up
touch "${S}/awg-fail"
poststart_refused "poststart refuses when the UAPI does not answer" "does not answer"
rm -f "${S}/awg-fail"
reset_state
launch_up
rm -f "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"
ln -s "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"
poststart_refused "poststart refuses a socket node that is not the one the daemon created" "are not the ones its BoringTun daemon holds"
reset_state
launch_up
sed -i 's/^IFINDEX=.*/IFINDEX=1/' "$(state_file "${IF}")"
poststart_refused "poststart refuses a link that is not the one this start created" "is not the link that this start created"

reset_state
launch_up
cp "${RELEASE}/boringtun-cli" "${T}/replacement"
mv -f "${T}/replacement" "${RELEASE}/boringtun-cli"
poststart_refused "poststart refuses a daemon whose executable is no longer the verified file" "is not the verified BoringTun binary"

reset_state
run "${CTL}" poststart "${IF}"
assert_rc 1 "${RC}" "poststart without a recorded attempt fails"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "and brings nothing down"

echo "=== S9: poststart when the attempt cannot be recorded ==="
# The up flag cannot be raised: poststart brings the interface down itself.
reset_state
: >"${HOOK_LOG}"
launch_up
echo ".up-pending" >"${S}/mv-fail"
run "${CTL}" poststart "${IF}"
rm -f "${S}/mv-fail"
assert_rc 1 "${RC}" "S9: poststart fails when it cannot record that the interface is up"
assert_contains "bringing it down now" "${ERR}" "S9: and brings the interface down itself"
assert_eq "up
predown
down" "$(cat "${HOOK_LOG}")" "S9: PostUp's work is undone at once: PreDown and PostDown ran once"
assert_true "S9: the link is gone" test ! -e "${NET}/${IF}"
run "${CTL}" poststop "${IF}"
assert_eq "3" "$(wc -l <"${HOOK_LOG}")" "S9: the following poststop does not run PostDown again"
assert_true "S9: and, the cleanup being complete, leaves nothing" nothing_left "${IF}"
# S9a: the kernel path; the runtime directory cannot allocate, so the link
# cannot be recorded; /tmp can: emergency cleanup succeeds from there.
reset_state
: >"${HOOK_LOG}"
touch "${S}/kernel-wins"
launch_up
rm -f "${S}/kernel-wins"
echo "${AWG_BT_RUN_DIR}/" >"${S}/mktemp-fail"
run "${CTL}" poststart "${IF}"
rm -f "${S}/mktemp-fail"
assert_rc 1 "${RC}" "S9a: poststart fails when the runtime directory cannot record the link"
assert_contains "awg-quick down ${AWG_BT_TMP_DIR}/awg-boringtun-down." "$(cat "${S}/log")" "S9a: the down copy comes from the temporary directory"
assert_eq "up
predown
down" "$(cat "${HOOK_LOG}")" "S9a: and the emergency down runs PreDown and PostDown once"
assert_true "S9a: the link is gone" test ! -e "${NET}/${IF}"
assert_eq "" "$(find "${AWG_BT_TMP_DIR}" -mindepth 1)" "S9a: the private copy is removed"
run "${CTL}" poststop "${IF}"
assert_eq "3" "$(wc -l <"${HOOK_LOG}")" "S9a: poststop runs no hook again"
assert_true "S9a: and the completed cleanup leaves nothing" nothing_left "${IF}"
# S9b/S9c: neither directory can allocate the copy: the state stays, marked
# up, and nothing claims the owed PostDown ran.
reset_state
: >"${HOOK_LOG}"
touch "${S}/kernel-wins"
launch_up
rm -f "${S}/kernel-wins"
printf '%s\n' "${AWG_BT_RUN_DIR}/" "${AWG_BT_TMP_DIR}/" >"${S}/mktemp-fail"
run "${CTL}" poststart "${IF}"
rm -f "${S}/mktemp-fail"
assert_rc 1 "${RC}" "S9b: poststart fails when no down copy can be made"
assert_contains "could not be started" "${ERR}" "S9b: and says the cleanup did not run"
assert_eq "up" "$(cat "${HOOK_LOG}")" "S9b: no PreDown or PostDown is claimed"
assert_true "S9b: the attempt stays recorded as up with no down" \
	test -f "$(state_file "${IF}")" -a -e "${AWG_BT_RUN_DIR}/${IF}@${INVOCATION_ID}.up" -a ! -e "${AWG_BT_RUN_DIR}/${IF}@${INVOCATION_ID}.down"
for ROUND in 1 2; do
	run "${CTL}" poststop "${IF}"
	assert_true "S9c: poststop (${ROUND}) keeps the state of the unfinished cleanup" test -f "$(state_file "${IF}")"
	assert_eq "up" "$(cat "${HOOK_LOG}")" "S9c: and runs no hook blindly (${ROUND})"
	assert_true "S9c: and leaves the link alone (${ROUND})" test -d "${NET}/${IF}"
done
assert_contains "its PostDown hooks are owed" "${ERR}" "S9c: the owed cleanup is reported"
ip link delete dev "${IF}"
# S9d: PostUp ran, the up flag cannot be raised and no emergency copy can be
# made; storage then recovers. The missing up flag is not terminal: poststop
# keeps the attempt and names the owed PostDown instead of forgetting it.
reset_state
: >"${HOOK_LOG}"
launch_up
echo ".up-pending" >"${S}/mv-fail"
printf '%s\n' "${AWG_BT_RUN_DIR}/" "${AWG_BT_TMP_DIR}/" >"${S}/mktemp-fail"
run "${CTL}" poststart "${IF}"
rm -f "${S}/mv-fail" "${S}/mktemp-fail"
assert_rc 1 "${RC}" "S9d: poststart fails when neither the up flag nor a down copy can be made"
assert_eq "up" "$(cat "${HOOK_LOG}")" "S9d: (PostUp ran; no PreDown or PostDown is claimed)"
assert_true "S9d: (the up flag is missing)" test ! -e "${AWG_BT_RUN_DIR}/${IF}@${INVOCATION_ID}.up"
for ROUND in 1 2; do
	run "${CTL}" poststop "${IF}"
	assert_true "S9d: poststop (${ROUND}) keeps the attempt: a missing up flag is not terminal" test -f "$(state_file "${IF}")"
	assert_eq "up" "$(cat "${HOOK_LOG}")" "S9d: and runs no hook blindly (${ROUND})"
done
assert_contains "PostUp may have run" "${ERR}" "S9d: poststop says PostUp may have run"
assert_contains "PostDown = echo down" "${ERR}" "S9d: and names the PostDown that is owed"
# S9e/S9f: the runtime directory allocates the copy, but writing it (S9e) or
# setting its mode (S9f) fails: the whole copy is made again in
# AWG_BT_TMP_DIR, not TMPDIR, and only the failed attempt's directory goes.
# The config ends its [Interface] section with SaveConfig = false.
write_server_config "${IF}" "PostUp = echo up >>${HOOK_LOG}
PreDown = echo predown >>${HOOK_LOG}
PostDown = echo down >>${HOOK_LOG}
SaveConfig = false"
for CASE in write chmod; do
	reset_state
	: >"${HOOK_LOG}"
	launch_up
	echo ".up-pending" >"${S}/mv-fail"
	if [[ "${CASE}" == write ]]; then
		echo "${AWG_BT_RUN_DIR}/down." >"${S}/mktemp-obstruct"
		echo "${IF}.conf" >"${S}/mktemp-obstruct-name"
	else
		echo "${AWG_BT_RUN_DIR}/down." >"${S}/chmod-fail"
	fi
	run env TMPDIR="${T}/elsewhere" "${CTL}" poststart "${IF}"
	rm -f "${S}/mv-fail" "${S}/mktemp-obstruct" "${S}/mktemp-obstruct-name" "${S}/chmod-fail"
	assert_rc 1 "${RC}" "S9 (${CASE}): poststart fails when it cannot record that the interface is up"
	assert_contains "awg-quick down ${AWG_BT_TMP_DIR}/awg-boringtun-down." "$(cat "${S}/log")" \
		"S9 (${CASE}): a failed ${CASE} of the runtime copy is retried whole in AWG_BT_TMP_DIR"
	assert_eq "${AWG_BT_TMP_DIR}" "$(dirname "$(dirname "$(cat "${S}/down-path")")")" "S9 (${CASE}): (not in TMPDIR)"
	assert_eq "${IF}.conf" "$(basename "$(cat "${S}/down-path")")" "S9 (${CASE}): the copy keeps the interface's file name"
	assert_eq "$(id -u) 700 $(id -u) 600 " "$(cat "${S}/down-modes")" "S9 (${CASE}): a 0700 directory and a 0600 copy of the trusted user"
	assert_eq "$(grep -vi '^SaveConfig' "${AWG_BT_CONFIG_DIR}/${IF}.conf")" "$(cat "${S}/down-config")" \
		"S9 (${CASE}): the copy awg-quick down read is the complete config, hooks included, without SaveConfig"
	assert_eq "up
predown
down" "$(cat "${HOOK_LOG}")" "S9 (${CASE}): the emergency down runs PreDown and PostDown once"
	assert_eq "" "$(find "${AWG_BT_RUN_DIR}" "${AWG_BT_TMP_DIR}" -name 'down.*' -o -name 'awg-boringtun-down.*')" \
		"S9 (${CASE}): both the failed and the used copy directories are removed"
	run "${CTL}" poststop "${IF}"
	assert_eq "3" "$(wc -l <"${HOOK_LOG}")" "S9 (${CASE}): poststop runs no hook again"
	assert_true "S9 (${CASE}): and the completed cleanup leaves nothing" nothing_left "${IF}"
done
write_server_config "${IF}" "PostUp = echo up >>${HOOK_LOG}
PreDown = echo predown >>${HOOK_LOG}
PostDown = echo down >>${HOOK_LOG}"
# S9g: the exact recorded socket of the dead daemon cannot be unlinked: the
# attempt is kept and the cleanup reported incomplete; a later poststop
# removes the socket and finishes the attempt without running a hook again.
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
"${CTL}" stop "${IF}" 2>/dev/null
echo "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" >"${S}/rm-fail"
run "${CTL}" poststop "${IF}"
rm -f "${S}/rm-fail"
assert_true "S9g: (the owned socket could not be removed)" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
assert_true "S9g: the attempt is kept while its owned socket remains" test -f "$(state_file "${IF}")"
assert_contains "cleanup is incomplete" "${ERR}" "S9g: and the cleanup is reported incomplete"
assert_eq "up
down" "$(cat "${HOOK_LOG}")" "S9g: (PostDown was replayed once)"
run "${CTL}" poststop "${IF}"
assert_true "S9g: a later poststop removes the socket" test ! -e "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
assert_eq "up
down" "$(cat "${HOOK_LOG}")" "S9g: without running PostDown again"
assert_true "S9g: and finishes the attempt" nothing_left "${IF}"
# S9h: the PostDown replay cannot read the config. The replay was recorded as
# started, so its hooks are never run again, and no done flag and no removal
# follow a replay that did not complete.
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
"${CTL}" stop "${IF}" 2>/dev/null
mv "${AWG_BT_CONFIG_DIR}/${IF}.conf" "${T}/config-away"
run "${CTL}" poststop "${IF}"
mv "${T}/config-away" "${AWG_BT_CONFIG_DIR}/${IF}.conf"
assert_true "S9h: a replay that could not read the config keeps the attempt" test -f "$(state_file "${IF}")"
assert_true "S9h: raises no done flag" test ! -e "${AWG_BT_RUN_DIR}/${IF}@${INVOCATION_ID}.done"
assert_eq "up" "$(cat "${HOOK_LOG}")" "S9h: (no PostDown hook ran)"
assert_contains "did not complete" "${ERR}" "S9h: and reports the cleanup as incomplete"
run "${CTL}" poststop "${IF}"
assert_eq "up" "$(cat "${HOOK_LOG}")" "S9h: a later poststop, with the config back, starts no second replay"
assert_true "S9h: and keeps the attempt for the operator" test -f "$(state_file "${IF}")"
assert_contains "never run again" "${ERR}" "S9h: saying why"
# The state directory replaced by a file.
reset_state
: >"${HOOK_LOG}"
launch_up
PID="$(state_get "${IF}" PID)"
rm -rf "${AWG_BT_RUN_DIR}"
touch "${AWG_BT_RUN_DIR}"
run "${CTL}" poststart "${IF}"
assert_rc 1 "${RC}" "S9: poststart fails when the state directory is unusable"
assert_eq "up
predown
down" "$(cat "${HOOK_LOG}")" "S9: and still runs PreDown and PostDown once, from a temporary copy"
assert_true "S9: the daemon is gone with its link" wait_until 3 pid_gone "${PID}"
run "${CTL}" poststop "${IF}"
assert_eq "3" "$(wc -l <"${HOOK_LOG}")" "S9: poststop without a state replays nothing"
rm -f "${AWG_BT_RUN_DIR}"
# The state file replaced by a directory.
reset_state
: >"${HOOK_LOG}"
launch_up
rm -f "$(state_file "${IF}")"
mkdir "$(state_file "${IF}")"
run "${CTL}" poststart "${IF}"
assert_rc 1 "${RC}" "S9: poststart fails when the state file is unusable"
assert_eq "up
predown
down" "$(cat "${HOOK_LOG}")" "S9: and still undoes PostUp once"
rmdir "$(state_file "${IF}")"
# precheck without a usable state directory records nothing and starts nothing.
reset_state
: >"${HOOK_LOG}"
mkdir -p "${T}/run"
touch "${AWG_BT_RUN_DIR}"
run service_start "${IF}"
assert_rc 1 "${RC}" "S9: a precheck that cannot record its attempt refuses to start"
assert_not_contains "awg-quick up" "$(cat "${S}/log")" "S9: and nothing is brought up"
assert_eq "" "$(cat "${HOOK_LOG}")" "S9: and no hook runs"
rm -f "${AWG_BT_RUN_DIR}"
# A PostUp hook that fails part way: awg-quick's own trap deletes the link and,
# as upstream, runs no PostDown; poststop replays nothing either. A missing up
# flag is no proof that no PostUp ran, so the attempt is kept.
reset_state
: >"${HOOK_LOG}"
write_server_config "${IF}" "PostUp = echo up1 >>${HOOK_LOG}
PostUp = false
PostDown = echo down >>${HOOK_LOG}"
run service_start "${IF}"
assert_rc 1 "${RC}" "S9: a failing second PostUp fails the start"
assert_eq "up1" "$(cat "${HOOK_LOG}")" "S9: as with awg-quick itself, PostDown is not run for a partial PostUp"
assert_true "S9: the link is gone" test ! -e "${NET}/${IF}"
assert_true "S9: and the attempt is kept, because PostUp may have run" test -f "$(state_file "${IF}")"
assert_contains "PostUp may have run" "${ERR}" "S9: and poststop says why"

echo "=== Stop, crash and poststop (S1, S2) ==="
write_server_config "${IF}" "PostUp = echo up >>${HOOK_LOG}
PreDown = echo predown >>${HOOK_LOG}
PostDown = echo down1 >>${HOOK_LOG}
PostDown = echo down2 >>${HOOK_LOG}"
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
assert_rc 0 "$?" "the service starts"
service_stop "${IF}"
assert_rc 0 "${STOP_RC}" "a clean stop succeeds"
assert_eq "up
predown
down1
down2" "$(cat "${HOOK_LOG}")" "a clean stop runs PreDown and PostDown once, and poststop replays nothing"
assert_true "and nothing is left" nothing_left "${IF}"

reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
service_crash "${IF}"
assert_rc 0 "${STOP_RC}" "stop succeeds after a crash without running awg-quick down"
assert_eq "up
down1
down2" "$(cat "${HOOK_LOG}")" "poststop replays PostDown exactly once after a crash, without PreDown"
assert_true "and removes the dead daemon's own socket nodes" nothing_left "${IF}"
run "${CTL}" poststop "${IF}"
assert_eq "3" "$(wc -l <"${HOOK_LOG}")" "a second poststop replays nothing"

reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
ip link delete dev "${IF}"
wait_until 3 pid_gone "${PID}"
"${CTL}" stop "${IF}"
"${CTL}" poststop "${IF}"
assert_eq "up
down1
down2" "$(cat "${HOOK_LOG}")" "after an operator's ip link del PostDown is replayed once"

# S1: awg-quick down enters PostDown; hook 1 succeeds, hook 2 fails, hook 3
# would succeed.
write_server_config "${IF}" "PostDown = echo hook1 >>${HOOK_LOG}
PostDown = false
PostDown = echo hook3 >>${HOOK_LOG}"
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
service_stop "${IF}"
assert_rc 1 "${STOP_RC}" "S1: stop reports the failed awg-quick down"
assert_eq "hook1" "$(cat "${HOOK_LOG}")" "S1: hook 1 ran exactly once and hook 3 was never run by the runtime"
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
"${CTL}" stop "${IF}" 2>/dev/null
PID="$(state_get "${IF}" PID)"
assert_eq "failed" "$(state_get "${IF}" DOWN)" "S1: the attempt records that the down failed after the link was deleted"
wait_until 3 pid_gone "${PID}"
run "${CTL}" poststop "${IF}"
assert_contains "PostDown = echo hook1" "${ERR}" "S1: poststop names the hooks it will not run again"
assert_eq "hook1" "$(cat "${HOOK_LOG}")" "S1: and runs none of them"
# stop is killed while awg-quick down is inside PostDown.
write_server_config "${IF}" "PostDown = echo hook1 >>${HOOK_LOG}
PostDown = echo hook2 >>${HOOK_LOG}"
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
touch "${S}/down-hold"
"${CTL}" stop "${IF}" 2>/dev/null &
STOPPER=$!
wait_until 5 test -s "${S}/down-waiting"
kill -KILL "${STOPPER}" "$(cat "${S}/down-waiting")"
wait "${STOPPER}" 2>/dev/null
rm -f "${S}/down-hold" "${S}/down-waiting"
assert_true "S1: a stop killed inside awg-quick down leaves the down recorded as started, not done" \
	test -e "${AWG_BT_RUN_DIR}/${IF}@${INVOCATION_ID}.down" -a ! -e "${AWG_BT_RUN_DIR}/${IF}@${INVOCATION_ID}.done"
wait_until 3 pid_gone "${PID}"
run "${CTL}" poststop "${IF}"
assert_eq "hook1" "$(cat "${HOOK_LOG}")" "S1: and poststop runs no hook of the interrupted down again"
assert_contains "PostDown = echo hook2" "${ERR}" "S1: but names the hooks that may not have run"
write_server_config "${IF}" "PostDown = echo hook1 >>${HOOK_LOG}
PostDown = false
PostDown = echo hook3 >>${HOOK_LOG}"
# S1a: the replay cannot be recorded as started: no hook runs.
write_server_config "${IF}" "PostDown = echo hook1 >>${HOOK_LOG}
PostDown = echo hook2 >>${HOOK_LOG}"
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
"${CTL}" stop "${IF}" 2>/dev/null
echo ".replay-pending" >"${S}/mv-fail"
run "${CTL}" poststop "${IF}"
rm -f "${S}/mv-fail"
assert_eq "" "$(cat "${HOOK_LOG}")" "S1a: when the replay cannot be recorded as started, no replay hook runs"
assert_contains "none of its hooks is run" "${ERR}" "S1a: and that is reported"
assert_true "S1a: and the state is kept" test -f "$(state_file "${IF}")"
run "${CTL}" poststop "${IF}"
assert_eq "hook1
hook2" "$(cat "${HOOK_LOG}")" "S1a: a later poststop that can record it replays once, as no hook ran before"
assert_true "S1a: and then leaves nothing" nothing_left "${IF}"
# S1b: the replay is interrupted after its first hook.
write_server_config "${IF}" "PostDown = echo hook1 >>${HOOK_LOG}; echo \$\$ >${S}/hook-pid; exec sleep 30
PostDown = echo hook2 >>${HOOK_LOG}"
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
"${CTL}" stop "${IF}" 2>/dev/null
rm -f "${S}/hook-pid"
"${CTL}" poststop "${IF}" 2>/dev/null &
REPLAYER=$!
wait_until 5 test -s "${S}/hook-pid"
kill -KILL "${REPLAYER}" "$(cat "${S}/hook-pid")"
wait "${REPLAYER}" 2>/dev/null
assert_eq "hook1" "$(cat "${HOOK_LOG}")" "S1b: (the replay died after its first hook)"
run "${CTL}" poststop "${IF}"
assert_eq "hook1" "$(cat "${HOOK_LOG}")" "S1b: a later poststop never runs hook 1, or any hook, again"
assert_contains "may not have finished; it is never run again" "${ERR}" "S1b: and reports the replay as incomplete"
assert_true "S1b: the state is kept for diagnosis" test -f "$(state_file "${IF}")"
# S1c: all hooks ran, but the finished state cannot be removed.
write_server_config "${IF}" "PostDown = echo hook1 >>${HOOK_LOG}
PostDown = echo hook2 >>${HOOK_LOG}"
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
"${CTL}" stop "${IF}" 2>/dev/null
echo "@${INVOCATION_ID}.state" >"${S}/rm-fail"
"${CTL}" poststop "${IF}" 2>/dev/null
rm -f "${S}/rm-fail"
assert_eq "hook1
hook2" "$(cat "${HOOK_LOG}")" "S1c: (the replay ran both hooks)"
assert_true "S1c: (its state could not be removed)" test -f "$(state_file "${IF}")"
run "${CTL}" poststop "${IF}"
assert_eq "hook1
hook2" "$(cat "${HOOK_LOG}")" "S1c: a later poststop never replays them a second time"
write_server_config "${IF}" "PostDown = echo hook1 >>${HOOK_LOG}
PostDown = false
PostDown = echo hook3 >>${HOOK_LOG}"
# The crash case still replays once.
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
service_crash "${IF}"
assert_eq "hook1
hook3" "$(cat "${HOOK_LOG}")" "S1: after a crash, when awg-quick down never ran, PostDown is replayed once, past the failing hook"
# A down that fails before deleting the link never reached PostDown.
write_server_config "${IF}" "PreDown = false
PostDown = echo hook1 >>${HOOK_LOG}"
reset_state
: >"${HOOK_LOG}"
service_start "${IF}"
"${CTL}" stop "${IF}" 2>/dev/null
assert_eq "failed-intact" "$(state_get "${IF}" DOWN)" "S1: a down that failed before deleting the link is recorded as such"
service_stop "${IF}" 2>/dev/null
assert_eq "hook1" "$(cat "${HOOK_LOG}")" "S1: then PostDown, which never started, is replayed exactly once"
assert_true "S1: and nothing is left" nothing_left "${IF}"

echo "=== S2: socket nodes are removed only with proof of ownership and death ==="
reset_state
bind_socket "${T}/probe.sock"
python3 -c 'import socket, sys, time; s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(); time.sleep(60)' \
	"${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" &
LISTENER=$!
wait_until 3 test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
LISTENER_START="$(_awgBtProcessStartTime "${LISTENER}")"
LISTENER_ID="$(_awgBtPathId "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock")"
touch "${S}/awg-fail"
_awgBtRemoveOwnedPath "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "${LISTENER_ID}" "${LISTENER}" "${LISTENER_START}"
assert_true "S2: the live listening socket of its recorded owner survives a failing awg query" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
_awgBtRemoveOwnedPath "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "" "${LISTENER}" "${LISTENER_START}"
assert_true "S2: a socket without a recorded node is never removed" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
rm -f "${S}/awg-fail"
kill -KILL "${LISTENER}"
wait "${LISTENER}" 2>/dev/null
rm -f "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
bind_socket "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
_awgBtRemoveOwnedPath "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "${LISTENER_ID}" "${LISTENER}" "${LISTENER_START}"
assert_true "S2: a replacement node at the path is never removed, although its recorded owner is dead" \
	test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
NODE_ID="$(_awgBtPathId "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock")"
sleep 0.01
touch -c "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
_awgBtRemoveOwnedPath "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "${NODE_ID}" "${LISTENER}" "${LISTENER_START}"
assert_true "S2: a node changed since it was recorded (same inode and mode, new change time) is never removed" 	test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
_awgBtRemoveOwnedPath "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "$(_awgBtPathId "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock")" "${LISTENER}" "${LISTENER_START}"
assert_true "S2: the recorded node of a dead owner is removed" test ! -e "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
# Through poststop: a crash, then a foreign replacement of the socket.
write_server_config "${IF}"
reset_state
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
rm -f "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
bind_socket "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
touch "${S}/awg-fail"
"${CTL}" stop "${IF}" 2>/dev/null
"${CTL}" poststop "${IF}" 2>/dev/null
rm -f "${S}/awg-fail"
assert_true "S2: poststop keeps a socket that replaced the dead daemon's" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
assert_true "S2: and removes the dead daemon's other, recorded node" test ! -L "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"

echo "=== S5: SaveConfig never writes a keyless config over the real one ==="
# S9: a failed write in the filter is never masked by a later line that is
# left out, such as a final SaveConfig = false.
printf '[Interface]\nAddress = 10.1.1.1/24\nPostDown = echo down\nSaveConfig = false\n' >"${T}/filter.conf"
( _awgBtWithoutSaveConfig "${T}/filter.conf" >/dev/full ) 2>"${T}/filter.err"
assert_rc 1 "$?" "S9: the SaveConfig filter fails when writing its output fails, even before a final SaveConfig line"
assert_contains "No space left on device" "$(cat "${T}/filter.err")" "S9: (the write error really occurred)"
assert_eq "[Interface]
Address = 10.1.1.1/24
PostDown = echo down" "$(_awgBtWithoutSaveConfig "${T}/filter.conf")" "S9: and writes the whole config but SaveConfig when it can"
reset_state
: >"${HOOK_LOG}"
write_server_config "${IF}" "PostDown = echo down >>${HOOK_LOG}"
service_start "${IF}"
printf 'SaveConfig = true\n' >"${T}/save-line"
sed -i '/^\[Interface\]$/r '"${T}/save-line" "${AWG_BT_CONFIG_DIR}/${IF}.conf"
cp "${AWG_BT_CONFIG_DIR}/${IF}.conf" "${T}/config-before-stop"
service_stop "${IF}"
assert_contains "${AWG_BT_RUN_DIR}/down." "$(cat "${S}/down-path")" "S5: stop brings the interface down through a private copy"
assert_not_contains "SaveConfig" "$(cat "${S}/down-config")" "S5: which has no SaveConfig, although it was set after the start"
assert_eq "$(grep -v SaveConfig "${T}/config-before-stop")" "$(cat "${S}/down-config")" "S5: and is otherwise the config itself"
assert_eq "$(cat "${T}/config-before-stop")" "$(cat "${AWG_BT_CONFIG_DIR}/${IF}.conf")" "S5: the config file is untouched"
assert_eq "down" "$(cat "${HOOK_LOG}")" "S5: and its PostDown ran"
assert_eq "" "$(find "${AWG_BT_RUN_DIR}" -name 'down.*')" "S5: the private copy is removed"
# The exact config of awgBackendQuickUp.
mkdir -p "${T}/alt"
chmod 0700 "${T}/alt"
write_server_config "${IF}" "SaveConfig = true" "${T}/alt"
write_server_config "${IF}"
AWG_BACKEND="${AWG_BACKEND_BORINGTUN}"
reset_state
run awgBackendQuickUp "${T}/alt/${IF}.conf"
assert_rc 1 "${RC}" "S5: quick-up checks SaveConfig in the exact config it is given"
assert_contains "${T}/alt/${IF}.conf sets SaveConfig = true" "${ERR}" "S5: and names that file"
assert_not_contains "awg-quick up" "$(cat "${S}/log")" "S5: and brings nothing up"
write_server_config "${IF}" "" "${T}/alt"
write_server_config "${IF}" "SaveConfig = true"
reset_state
run awgBackendQuickUp "${T}/alt/${IF}.conf"
assert_rc 0 "${RC}" "S5: quick-up of a clean alternative config is not blocked by the default config"
adopt_attempt "${IF}"
assert_eq "${T}/alt/${IF}.conf" "$(state_get "${IF}" CONFIG)" "S5: and the attempt records that exact config"
sed -i '/^\[Interface\]$/r '"${T}/save-line" "${T}/alt/${IF}.conf"
"${CTL}" stop "${IF}"
assert_eq "$(grep -v SaveConfig "${T}/alt/${IF}.conf")" "$(cat "${S}/down-config")" \
	"S5: stop brings it down with the recorded config, without the SaveConfig added since"
"${CTL}" poststop "${IF}"
write_server_config "${IF}"
AWG_BACKEND=kernel

if [[ -n "${AWG_QUICK_REFERENCE:-}" && -r "${AWG_QUICK_REFERENCE}" ]]; then
	# awg-quick itself, unchanged except that it does not re-exec through sudo.
	mkdir -p "${T}/refbin"
	awk '{print} /^# ~~ function override insertion point ~~$/{print "auto_su() { :; }"}' "${AWG_QUICK_REFERENCE}" >"${T}/refbin/awg-quick"
	chmod 0755 "${T}/refbin/awg-quick"
	assert_true "the reference awg-quick has its override insertion point" grep -q '^auto_su() { :; }$' "${T}/refbin/awg-quick"
	reset_state
	write_server_config "${IF}"
	service_start "${IF}"
	sed -i '/^\[Interface\]$/a SaveConfig = true' "${AWG_BT_CONFIG_DIR}/${IF}.conf"
	cp "${AWG_BT_CONFIG_DIR}/${IF}.conf" "${T}/config-before-stop"
	AWG_BT_PATH="${T}/refbin:${MOCKBIN}:/usr/local/bin:/usr/bin:/bin"
	install_helpers
	run "${CTL}" stop "${IF}"
	assert_rc 0 "${RC}" "S5: awg-quick's real down path stops the instance"
	assert_contains "${SERVER_KEY_LINE}" "$(cat "${AWG_BT_CONFIG_DIR}/${IF}.conf")" \
		"S5: with SaveConfig added after the start, the real awg-quick down keeps the PrivateKey"
	assert_eq "$(cat "${T}/config-before-stop")" "$(cat "${AWG_BT_CONFIG_DIR}/${IF}.conf")" "S5: and the config is byte for byte unchanged"
	"${CTL}" poststop "${IF}"
	AWG_BT_PATH="${MOCKBIN}:/usr/local/bin:/usr/bin:/bin"
	install_helpers
	# The control: the same real awg-quick run on the config itself erases the key.
	reset_state
	write_server_config "${IF}"
	service_start "${IF}"
	sed -i '/^\[Interface\]$/a SaveConfig = true' "${AWG_BT_CONFIG_DIR}/${IF}.conf"
	"${T}/refbin/awg-quick" down "${AWG_BT_CONFIG_DIR}/${IF}.conf" >/dev/null 2>&1
	assert_not_contains "PrivateKey" "$(cat "${AWG_BT_CONFIG_DIR}/${IF}.conf")" \
		"S5 control: awg-quick down on the config itself saves BoringTun's keyless showconf over it"
	"${CTL}" poststop "${IF}" 2>/dev/null
	write_server_config "${IF}"
else
	echo "  (skipped awg-quick's real SaveConfig path: set AWG_QUICK_REFERENCE)"
fi

echo "=== PostDown and SaveConfig parsing parity with awg-quick ==="
PARITY_DIR="${T}/parity"
mkdir -p "${PARITY_DIR}"
# Each fixture: file name, content, expected PostDown values (one per line).
parity_fixture() { # <name> <content> <expected>
	printf '%s' "$2" >"${PARITY_DIR}/$1.conf"
	chmod 0600 "${PARITY_DIR}/$1.conf"
	assert_eq "$3" "$(_awgBtInterfaceValues "${PARITY_DIR}/$1.conf" PostDown | tr '\0' '\n')" "PostDown parsing: $1"
}
parity_fixture comments $'[Interface]\nPostDown = a # trailing comment\n# PostDown = commented\nPostDown = b#tight\n' $'a\nb'
parity_fixture casing $'[interface]\npostdown = lower\nPOSTDOWN = upper\nPostDown=tight\n' $'lower\nupper\ntight'
parity_fixture whitespace $'  [Interface]  \n\t PostDown \t=\t spaced  value \t\n' 'spaced  value'
parity_fixture sections $'PostDown = before-any-section\n[Interface]\nPostDown = in-interface\n[Peer]\nPostDown = in-peer\n[Interface]\nPostDown = again\n' $'in-interface\nagain'
parity_fixture header-spacing $'[ Interface ]\nPostDown = not-interface\n' ''
parity_fixture equals $'[Interface]\nPostDown = iptables -A X -m comment --comment a=b\n' 'iptables -A X -m comment --comment a=b'
parity_fixture no-equals $'[Interface]\nPostDown\n' 'PostDown'
parity_fixture crlf $'[Interface]\r\nPostDown = crlf-value\r\n' 'crlf-value'
parity_fixture no-eol $'[Interface]\nPostDown = last-line' 'last-line'
parity_fixture percent-i $'[Interface]\nPostDown = ip link del %i-peer; echo %i\n' 'ip link del %i-peer; echo %i'
SAVE_FIXTURE=$'SaveConfig = true\n[interface]\n  saveCONFIG = true # c\nPostDown = keep\nSaveConfig=false\n[Peer]\nSaveConfig = true\n[Interface]\n\tSaveConfig\t=\ttrue\r\n'
printf '%s' "${SAVE_FIXTURE}" >"${PARITY_DIR}/savecfg.conf"
assert_eq $'SaveConfig = true\n[interface]\nPostDown = keep\n[Peer]\nSaveConfig = true\n[Interface]' \
	"$(_awgBtWithoutSaveConfig "${PARITY_DIR}/savecfg.conf")" \
	"the down copy drops exactly the [Interface] SaveConfig lines and keeps every other line"

if [[ -n "${AWG_QUICK_REFERENCE:-}" && -r "${AWG_QUICK_REFERENCE}" ]]; then
	# Run awg-quick's own parse_options and read_bool, taken from the given
	# script at test time, on every fixture and compare PostDown and SaveConfig.
	REFERENCE_FUNCTIONS="$(sed -n '/^parse_options() {/,/^}/p; /^read_bool() {/,/^}/p' "${AWG_QUICK_REFERENCE}")"
	for FIXTURE in "${PARITY_DIR}"/*.conf; do
		[[ "${FIXTURE}" == */savecfg.conf ]] && continue
		REFERENCE="$(bash -c 'shopt -s extglob; die() { echo "DIE"; exit 1; }; eval "$1"; ADDRESSES=(); DNS=(); DNS_SEARCH=(); PRE_UP=(); POST_UP=(); PRE_DOWN=(); POST_DOWN=(); SAVE_CONFIG=0; parse_options "$2" 2>/dev/null; printf "%s\n" "${POST_DOWN[@]}"' _ "${REFERENCE_FUNCTIONS}" "${FIXTURE}")"
		assert_eq "${REFERENCE}" "$(_awgBtInterfaceValues "${FIXTURE}" PostDown | tr '\0' '\n')" \
			"PostDown matches awg-quick's parse_options for ${FIXTURE##*/}"
	done
	for SAVE in "true" "True" "false" "TRUE" "maybe"; do
		printf '[Interface]\nSaveConfig = %s\n' "${SAVE}" >"${PARITY_DIR}/save.conf"
		REFERENCE="$(bash -c 'shopt -s extglob; die() { echo invalid; exit 1; }; eval "$1"; SAVE_CONFIG=0; parse_options "$2" 2>/dev/null; echo "${SAVE_CONFIG}"' _ "${REFERENCE_FUNCTIONS}" "${PARITY_DIR}/save.conf")"
		_awgBtSaveConfigEnabled "${PARITY_DIR}/save.conf"
		case "$?" in 0) OURS=1 ;; 1) OURS=0 ;; *) OURS=invalid ;; esac
		assert_eq "${REFERENCE}" "${OURS}" "SaveConfig = ${SAVE} is read as awg-quick reads it"
	done
	rm -f "${PARITY_DIR}/save.conf"
	mkdir -p "${PARITY_DIR}/copy"
	_awgBtWithoutSaveConfig "${PARITY_DIR}/savecfg.conf" >"${PARITY_DIR}/copy/savecfg.conf"
	REFERENCE="$(bash -c 'shopt -s extglob; die() { echo "DIE: $*"; exit 1; }; eval "$1"; ADDRESSES=(); DNS=(); DNS_SEARCH=(); PRE_UP=(); POST_UP=(); PRE_DOWN=(); POST_DOWN=(); SAVE_CONFIG=0; parse_options "$2" 2>/dev/null; echo "save=${SAVE_CONFIG} postdown=${POST_DOWN[*]}"' _ "${REFERENCE_FUNCTIONS}" "${PARITY_DIR}/copy/savecfg.conf")"
	assert_eq "save=0 postdown=keep" "${REFERENCE}" "awg-quick reads the down copy with SaveConfig off and the same hooks"
else
	echo "  (skipped the comparison with awg-quick itself: set AWG_QUICK_REFERENCE)"
fi

echo "=== ListenPort-filtered live sync ==="
reset_state
install_helpers
echo yes >"${S}/live/${IF}"
STRIP_WITH_PORT=$'[Interface]\nPrivateKey = k\nListenPort = 51820\nJc = 4\n\n[Peer]\nPublicKey = p\nAllowedIPs = 10.66.66.2/32'
printf '%s\n' "${STRIP_WITH_PORT}" >"${S}/strip/${IF}"
echo 51820 >"${S}/port/${IF}"
run "${CTL}" sync "${IF}"
assert_rc 0 "${RC}" "sync succeeds"
assert_eq $'[Interface]\nPrivateKey = k\nJc = 4\n\n[Peer]\nPublicKey = p\nAllowedIPs = 10.66.66.2/32' "$(cat "${S}/syncconf-input")" \
	"an unchanged ListenPort line is left out of awg syncconf and nothing else changes"
echo 51821 >"${S}/port/${IF}"
run "${CTL}" sync "${IF}"
assert_eq "${STRIP_WITH_PORT}" "$(cat "${S}/syncconf-input")" "a changed ListenPort is kept"
printf '[Interface]\nlistenport=51821 # comment\n' >"${S}/strip/${IF}"
run "${CTL}" sync "${IF}"
assert_eq "[Interface]" "$(cat "${S}/syncconf-input")" "ListenPort is recognised like awg does: any case, comments, no spaces"
printf '[Interface]\nPrivateKey = k\n' >"${S}/strip/${IF}"
run "${CTL}" sync "${IF}"
assert_eq $'[Interface]\nPrivateKey = k' "$(cat "${S}/syncconf-input")" "a config without ListenPort is passed unchanged"
sync_refused() { # <label> <fragment>
	rm -f "${S}/syncconf-input"
	run "${CTL}" sync "${IF}"
	if [[ "${RC}" != 0 && ! -e "${S}/syncconf-input" && "${ERR}" == *"$2"* ]]; then ok "$1"; else not_ok "$1 (rc=${RC}: ${ERR})"; fi
}
printf '[Interface]\nListenPort = 51821\nListenPort = 51821\n' >"${S}/strip/${IF}"
sync_refused "two ListenPort lines fail safely without a syncconf" "more than once"
printf '[Interface]\nListenPort = 99999\n' >"${S}/strip/${IF}"
sync_refused "an invalid configured ListenPort fails safely" "not a valid port"
printf '[Interface]\nListenPort = 51821\n' >"${S}/strip/${IF}"
echo "garbage" >"${S}/port/${IF}"
sync_refused "an unreadable live port fails safely" "cannot read the live listen port"
rm -f "${S}/live/${IF}"
sync_refused "a dead interface fails safely" "cannot read the live listen port"
echo yes >"${S}/live/${IF}"
touch "${S}/strip-fail"
sync_refused "a failing awg-quick strip fails safely" "awg-quick strip failed"
rm -f "${S}/strip-fail"

echo 51821 >"${S}/port/${IF}"
printf '[Interface]\nListenPort = 51821\n' >"${S}/strip/${IF}"
AWG_BACKEND="${AWG_BACKEND_BORINGTUN}"
run awgSyncInterfaceConfig "${IF}" --stderr-to-stdout
assert_eq "syncconf-error-line" "${OUT}" "--stderr-to-stdout puts awg syncconf's stderr on stdout"
run awgSyncInterfaceConfig "${IF}" "${T}/sync.err"
assert_eq "syncconf-error-line" "$(cat "${T}/sync.err")" "a file destination receives awg syncconf's stderr"
assert_eq "" "${ERR}" "and nothing else reaches the caller's stderr"
echo 1 >"${S}/syncconf-rc"
run awgSyncInterfaceConfig "${IF}"
assert_rc 1 "${RC}" "awg syncconf's failure status is returned"
rm -f "${S}/syncconf-rc"
printf '[Interface]\nListenPort = 1\nListenPort = 2\n' >"${S}/strip/${IF}"
run awgSyncInterfaceConfig "${IF}" "${T}/sync.err"
assert_contains "more than once" "$(cat "${T}/sync.err")" "filter diagnostics go where awg syncconf's stderr goes"
AWG_BACKEND=kernel
: >"${S}/log"
printf '[Interface]\nListenPort = 51821\n' >"${S}/strip/${IF}"
run awgSyncInterfaceConfig "${IF}"
assert_eq "[Interface]
ListenPort = 51821" "$(cat "${S}/syncconf-input")" "the kernel sync still sends ListenPort unfiltered"
assert_not_contains "listen-port" "$(cat "${S}/log")" "and never asks for the live port"

echo "=== Scratch interfaces: collisions and the lifecycle ==="
AWG_BACKEND="${AWG_BACKEND_BORINGTUN}"
reset_state
SYSTEMD_PRESENT="${T}/run/systemd-present"
SYSTEMD_ABSENT="${T}/run/systemd-absent"
scratch_refused() { # <label>
	: >"${S}/log"
	run awgBackendCreateScratchInterface awgp1
	if [[ "${RC}" != 0 && "${ERR}" == *"already in use"* ]] && ! grep -q 'systemd-run' "${S}/log"; then
		ok "$1"
	else
		not_ok "$1 (rc=${RC}: ${ERR})"
	fi
}
mkdir "${NET}/awgp1"
scratch_refused "a scratch name with an existing link is refused"
rmdir "${NET}/awgp1"
touch "${AWG_BT_WG_SOCKET_DIR}/awgp1.sock"
scratch_refused "a scratch name with an existing wireguard socket path is refused"
rm -f "${AWG_BT_WG_SOCKET_DIR}/awgp1.sock"
ln -s /nonexistent "${AWG_BT_AWG_SOCKET_DIR}/awgp1.sock"
scratch_refused "a scratch name with an existing amneziawg socket link is refused"
rm -f "${AWG_BT_AWG_SOCKET_DIR}/awgp1.sock"
echo yes >"${S}/live/awgp1"
scratch_refused "a scratch name that awg already lists is refused"
rm -f "${S}/live/awgp1"
run awgBackendCreateScratchInterface 'bad=name'
assert_rc 1 "${RC}" "a scratch name outside [a-zA-Z0-9_-] is refused"

# records_gone <token>: neither record of the attempt remains.
records_gone() {
	[[ ! -e "${SCRATCH_DIR}/$1.owner" && ! -e "${SCRATCH_DIR}/$1.guard" && ! -e "${SCRATCH_DIR}/$1.child" &&
		! -e "${SCRATCH_DIR}/$1.client" && ! -e "${SCRATCH_DIR}/$1.stop" && ! -e "${SCRATCH_DIR}/$1.reclaim" ]]
}
record_get() { # <token> <owner|guard|child|client> <key>
	sed -n "s/^$3=//p" "${SCRATCH_DIR}/$1.$2" 2>/dev/null
}
scratch_gone() { # <name> <token>
	[[ ! -e "${NET}/$1" && ! -e "${AWG_BT_WG_SOCKET_DIR}/$1.sock" && ! -L "${AWG_BT_AWG_SOCKET_DIR}/$1.sock" ]] &&
		records_gone "$2" && ! compgen -G "${S}/units/amneziawg-scratch-$1-*" >/dev/null
}

AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_PRESENT}"
ORIGINAL_EXIT_TRAP="$(trap -p EXIT)"
: >"${S}/log"
awgBackendCreateScratchInterface awgp1 2>"${T}/err"
assert_rc 0 "$?" "under systemd a scratch interface starts in a transient unit"
TOKEN="${_AWG_BT_SCRATCH_TOKENS[awgp1]:-}"
UNIT="amneziawg-scratch-awgp1-${TOKEN}"
assert_eq "systemd-run --quiet --collect --unit=${UNIT} -p Type=exec -p RuntimeMaxSec=900 -- $(command -v bash) -c [[ -e \"\$1\" && ! -e \"\$2\" ]] || exit 0; shift 2; exec \"\$@\" awg-scratch-unit ${SCRATCH_DIR}/${TOKEN}.owner ${SCRATCH_DIR}/${TOKEN}.reclaim $(command -v env) -i PATH=${AWG_BT_PATH} NO_COLOR=1 ${VERIFIED_BIN} --foreground --disable-drop-privileges --verbosity error awgp1" \
	"$(grep '^systemd-run' "${S}/log")" "the unit is named after the attempt's token, has a hard lifetime and runs the production command line behind the attempt's gate"
UNIT_PID="$(cat "${S}/units/${UNIT}")"
assert_true "and the daemon is running" pid_alive "${UNIT_PID}"
GUARD_PID="${_AWG_BT_SCRATCH_GUARDS[awgp1]:-}"
assert_true "and a guardian watches the shell that owns it" pid_alive "${GUARD_PID}"
assert_eq "created ${UNIT_PID} ${GUARD_PID} ${BASHPID}" \
	"$(record_get "${TOKEN}" guard PHASE) $(record_get "${TOKEN}" guard DAEMON_PID) $(record_get "${TOKEN}" guard GUARD_PID) $(record_get "${TOKEN}" owner OWNER_PID)" \
	"the records name the daemon, the guardian and the owner"
assert_eq "600 600 700" "$(stat -c '%a' "${SCRATCH_DIR}/${TOKEN}.owner" "${SCRATCH_DIR}/${TOKEN}.guard" "${SCRATCH_DIR}" | tr '\n' ' ' | sed 's/ $//')" \
	"the records are private"
awgBackendDestroyScratchInterface awgp1
assert_rc 0 "$?" "the scratch interface is destroyed"
assert_true "its daemon is gone" pid_gone "${UNIT_PID}"
assert_true "no link, unit, socket or record remains" scratch_gone awgp1 "${TOKEN}"
assert_contains "ip link delete dev awgp1" "$(cat "${S}/log")" "destroy deletes the recorded link"
assert_true "the guardian finished before destroy returned and was reaped" test ! -d "/proc/${GUARD_PID}"
assert_eq "${ORIGINAL_EXIT_TRAP}" "$(trap -p EXIT)" "the caller's EXIT trap is never touched"

AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_ABSENT}"
bash -c 'sleep 300 </dev/null >/dev/null 2>&1 & echo $!' | tee -a "${T}/decoys" >"${T}/decoy-pid"
DECOY_PID="$(cat "${T}/decoy-pid")"
awgBackendCreateScratchInterface awgv2 2>/dev/null
assert_rc 0 "$?" "without systemd a scratch interface is a tracked process"
TOKEN="${_AWG_BT_SCRATCH_TOKENS[awgv2]:-}"
CHILD_PID="$(record_get "${TOKEN}" guard DAEMON_PID)"
assert_true "and it is running" pid_alive "${CHILD_PID}"
assert_eq "${CHILD_PID} $(_awgBtProcessStartTime "${CHILD_PID}")" \
	"$(record_get "${TOKEN}" child CHILD_PID) $(record_get "${TOKEN}" child CHILD_START)" \
	"S3: the daemon recorded its own identity before readiness was declared"
assert_eq "${_AWG_BT_SCRATCH_GUARDS[awgv2]:-}" "$(awk '{print $4}' "/proc/${CHILD_PID}/stat")" "whose parent is its guardian"
SIGIGN="$(tr -d '[:space:]' <"${TUNROOT}/${CHILD_PID}/sigign")"
assert_true "and which does not inherit the guardian's ignored HUP, INT and TERM" test "$((16#${SIGIGN} & 16#4003))" -eq 0
awgBackendDestroyScratchInterface awgv2
assert_true "destroying it stops the daemon" pid_gone "${CHILD_PID}"
assert_true "and leaves nothing" scratch_gone awgv2 "${TOKEN}"
assert_true "an unrelated process is never signalled" pid_alive "${DECOY_PID}"
kill -KILL "${DECOY_PID}"
run awgBackendDestroyScratchInterface awgv9
assert_rc 1 "${RC}" "a scratch interface that was not started here is never destroyed"

echo exit >"${S}/fake-mode"
run awgBackendCreateScratchInterface awgv3
assert_rc 1 "${RC}" "a scratch daemon that exits at once fails the creation"
assert_eq "0 0 0" "${#_AWG_BT_SCRATCH_TOKENS[@]} ${#_AWG_BT_SCRATCH_GUARDS[@]} ${#_AWG_BT_SCRATCH_GUARD_STARTS[@]}" \
	"and nothing stays tracked, guardian included"
assert_eq "" "$(find "${SCRATCH_DIR}" -mindepth 1)" "and no record is left"
rm -f "${S}/fake-mode"

echo "=== S3: scratch cleanup whenever the owner goes away ==="
AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_PRESENT}"
(
	trap 'echo "previous handler ran" >"${T}/prev-exit"' EXIT
	awgBackendCreateScratchInterface awgp5 2>/dev/null
	echo "${_AWG_BT_SCRATCH_TOKENS[awgp5]:-}" >"${T}/token"
	exit 7
)
assert_rc 7 "$?" "a shell that exits with a scratch interface keeps its exit status"
TOKEN="$(cat "${T}/token")"
assert_true "the scratch instance is cleaned up after EXIT" wait_until 5 scratch_gone awgp5 "${TOKEN}"
assert_eq "previous handler ran" "$(cat "${T}/prev-exit" 2>/dev/null)" "the EXIT handler installed before still runs"

for SIGNAL in TERM INT HUP KILL; do
	rm -f "${T}/token"
	(
		awgBackendCreateScratchInterface awgp6 2>/dev/null
		echo "${_AWG_BT_SCRATCH_TOKENS[awgp6]:-}" >"${T}/token"
		kill -s "${SIGNAL}" "${BASHPID}"
		sleep 5
		echo "not reached" >"${T}/not-reached"
	)
	RC=$?
	TOKEN="$(cat "${T}/token")"
	assert_true "SIG${SIGNAL} of the owning shell cleans up its scratch instance" wait_until 5 scratch_gone awgp6 "${TOKEN}"
	assert_true "and SIG${SIGNAL} still terminates the shell (rc=${RC})" test ! -e "${T}/not-reached" -a "${RC}" -ne 0
	rm -f "${T}/not-reached"
done

# A driver that owns scratch instances from its own process.
{
	declare -p AWG_BT_TRUST_ANCHOR AWG_BT_TRUSTED_UID AWG_BT_STORE_DIR AWG_BT_LIBEXEC_DIR AWG_BT_RUN_DIR \
		AWG_BT_CONFIG_DIR AWG_BT_SYSTEMD_DIR AWG_BT_UNIT_DIRS AWG_BT_WG_SOCKET_DIR AWG_BT_AWG_SOCKET_DIR \
		AWG_BT_SYS_DIR AWG_BT_PROC_DIR AWG_BT_TUN_DEVICE AWG_BT_PATH AWG_BT_READY_TIMEOUT AWG_BT_HOST_ARCH \
		SYSTEMD_PRESENT SYSTEMD_ABSENT MOCKBIN
} >"${T}/settings.sh"
cat >"${T}/owner.sh" <<'EOF'
#!/bin/bash
# owner.sh <installer> <settings> unit|direct create <name> <token file> [hold]
# owner.sh <installer> <settings> unit|direct sweep
# owner.sh <installer> <settings> unit|direct reclaim <token>
source "$1"
source "$2"
if [[ "$3" == unit ]]; then AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_PRESENT}"; else AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_ABSENT}"; fi
PATH="${MOCKBIN}:${PATH}"
[[ -z "${CLIENT_WAIT:-}" ]] || _AWG_BT_SCRATCH_CLIENT_WAIT="${CLIENT_WAIT}"
AWG_BACKEND="${AWG_BACKEND_BORINGTUN}"
case "$4" in
	create)
		awgBackendCreateScratchInterface "$5" >/dev/null 2>&1 || exit 1
		echo "${_AWG_BT_SCRATCH_TOKENS[$5]:-}" >"$6.tmp" && mv "$6.tmp" "$6"
		[[ "${7:-}" == hold ]] && exec sleep 120
		exit 0
		;;
	sweep)
		_awgBtScratchSweep
		;;
	reclaim)
		_awgBtScratchReclaim "$5"
		;;
esac
EOF
chmod 0755 "${T}/owner.sh"
# The owner process itself (not a subshell around it), so that $! names it.
OWNER_CMD=("${T}/owner.sh" "${INSTALLER}" "${T}/settings.sh")
owner() { # unit|direct <args...>
	"${OWNER_CMD[@]}" "$@"
}

# Owner death while systemd-run is still on its way.
reset_state
touch "${S}/systemd-run-hold"
"${OWNER_CMD[@]}" unit create awgp7 "${T}/token" &
OWNER_PID=$!
wait_until 5 test -e "${S}/systemd-run-waiting"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
kill -KILL "${OWNER_PID}"
wait "${OWNER_PID}" 2>/dev/null
touch "${S}/systemd-run-release"
assert_true "S3: a unit that systemd-run creates after its owner died is torn down" \
	wait_until 10 scratch_gone awgp7 "${TOKEN}"
assert_contains "systemd-run --quiet --collect --unit=amneziawg-scratch-awgp7-${TOKEN}" "$(cat "${S}/log")" \
	"S3: (the unit was really created late)"
rm -f "${S}"/systemd-run-*

# systemd-run creates the unit but its answer is lost.
reset_state
touch "${S}/systemd-run-lost"
awgBackendCreateScratchInterface awgp8 2>/dev/null
assert_rc 0 "$?" "S3: a unit whose systemd-run answer was lost is still recognised by its token and used"
TOKEN="${_AWG_BT_SCRATCH_TOKENS[awgp8]:-}"
rm -f "${S}/systemd-run-lost"
awgBackendDestroyScratchInterface awgp8
assert_true "S3: and it is torn down" scratch_gone awgp8 "${TOKEN}"

# systemd-run fails and creates nothing; a concurrent creator took the name.
reset_state
echo awgv5 >"${S}/systemd-run-fail"
run awgBackendCreateScratchInterface awgv5
assert_rc 1 "${RC}" "S3: a failing systemd-run fails the creation"
assert_true "S3: and a link that a concurrent creator made is never deleted" test -d "${NET}/awgv5"
assert_eq "" "$(grep '^systemctl stop' "${S}/log" | grep -v -- "-awgv5-[0-9a-f]\{32\}.service$")" \
	"S3: and no unit but the attempt's own, token-named one is ever stopped"
assert_eq "0 " "${#_AWG_BT_SCRATCH_TOKENS[@]} $(find "${SCRATCH_DIR}" -mindepth 1)" "S3: and nothing stays tracked or recorded"
rm -f "${S}/systemd-run-fail"

# The guardian is killed before the daemon is launched (systemd-run pending).
reset_state
touch "${S}/systemd-run-hold"
"${OWNER_CMD[@]}" unit create awgp9 "${T}/token" &
OWNER_PID=$!
wait_until 5 test -e "${S}/systemd-run-waiting"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
wait_until 5 test -n "$(record_get "${TOKEN}" client CLIENT_PID)"
kill -KILL "$(record_get "${TOKEN}" guard GUARD_PID)"
touch "${S}/systemd-run-release"
wait "${OWNER_PID}"
assert_rc 1 "$?" "S3: creation fails when its guardian dies before the daemon starts"
assert_true "S3: and the owner still removes the late unit through the records" scratch_gone awgp9 "${TOKEN}"
rm -f "${S}"/systemd-run-*

# The guardian is killed, then the owner; a later run sweeps.
for MODE in direct unit; do
	reset_state
	rm -f "${T}/token"
	"${OWNER_CMD[@]}" "${MODE}" create awgv6 "${T}/token" hold &
	OWNER_PID=$!
	wait_until 10 test -s "${T}/token"
	TOKEN="$(cat "${T}/token")"
	DAEMON="$(record_get "${TOKEN}" guard DAEMON_PID)"
	kill -KILL "$(record_get "${TOKEN}" guard GUARD_PID)"
	if [[ "${MODE}" == direct ]]; then
		assert_true "S3 (${MODE}): the daemon dies with its killed guardian" wait_until 3 pid_gone "${DAEMON}"
	else
		sleep 0.5
		assert_true "S3 (${MODE}): the unit outlives a killed guardian" pid_alive "${DAEMON}"
	fi
	kill -KILL "${OWNER_PID}"
	wait "${OWNER_PID}" 2>/dev/null
	sleep 0.5
	assert_true "S3 (${MODE}): after guardian and owner died, the records remain for recovery" test -e "${SCRATCH_DIR}/${TOKEN}.guard"
	if [[ "${MODE}" == direct ]]; then
		owner "${MODE}" sweep
	else
		# Here the sweep comes from the next creation in another shell.
		AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_PRESENT}"
		awgBackendCreateScratchInterface awgv0 2>/dev/null
		awgBackendDestroyScratchInterface awgv0
	fi
	assert_true "S3 (${MODE}): a later run's sweep reclaims the instance" scratch_gone awgv6 "${TOKEN}"
	assert_true "S3 (${MODE}): its daemon is gone" pid_gone "${DAEMON}"
done

# destroy interrupted: the stop request is made, then the owner dies.
reset_state
rm -f "${T}/token"
"${OWNER_CMD[@]}" unit create awgv7 "${T}/token" hold &
OWNER_PID=$!
wait_until 10 test -s "${T}/token"
TOKEN="$(cat "${T}/token")"
: >"${SCRATCH_DIR}/${TOKEN}.stop"
kill -KILL "${OWNER_PID}"
wait "${OWNER_PID}" 2>/dev/null
assert_true "S3: a destroy interrupted after its stop request still completes in the guardian" wait_until 5 scratch_gone awgv7 "${TOKEN}"

# teardown interrupted: the guardian dies inside systemctl stop.
reset_state
rm -f "${T}/token"
"${OWNER_CMD[@]}" unit create awgv8 "${T}/token" hold &
OWNER_PID=$!
wait_until 10 test -s "${T}/token"
TOKEN="$(cat "${T}/token")"
GUARD="$(record_get "${TOKEN}" guard GUARD_PID)"
touch "${S}/stop-hold"
kill -KILL "${OWNER_PID}"
wait "${OWNER_PID}" 2>/dev/null
wait_until 5 test -e "${S}/stop-waiting"
kill -KILL "${GUARD}"
sleep 0.2
touch "${S}/stop-release"
sleep 0.5
assert_eq "teardown" "$(record_get "${TOKEN}" guard PHASE)" "S3: a guardian killed during teardown leaves its records"
rm -f "${S}"/stop-*
owner unit sweep
assert_true "S3: and the next sweep finishes the teardown" scratch_gone awgv8 "${TOKEN}"

# S3a: the guardian dies before the direct child has registered: the child
# then never becomes BoringTun.
reset_state
rm -f "${T}/token" "${S}"/argv-awgv5
echo ".child." >"${S}/mktemp-hold"
"${OWNER_CMD[@]}" direct create awgv5 "${T}/token" &
OWNER_PID=$!
wait_until 10 test -s "${S}/mktemp-waiting"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
kill -KILL "$(record_get "${TOKEN}" guard GUARD_PID)"
touch "${S}/mktemp-release"
wait "${OWNER_PID}"
assert_rc 1 "$?" "S3a: creation fails when the guardian dies before its child registered"
rm -f "${S}"/mktemp-*
assert_true "S3a: the child, registered after its guardian died, never started BoringTun" test ! -e "${S}/argv-awgv5"
assert_true "S3a: and nothing of the attempt is left" wait_until 5 scratch_gone awgv5 "${TOKEN}"
# S3b: the guardian dies after the child registered, before readiness, and no
# parent-death signal ends the daemon: the owner reclaims it from the record.
reset_state
rm -f "${T}/token"
printf '%s\n' "${NO_PDEATHSIG_SETPRIV}" >"${MOCKBIN}/setpriv"
chmod 0755 "${MOCKBIN}/setpriv"
echo hold >"${S}/fake-mode"
"${OWNER_CMD[@]}" direct create awgv5 "${T}/token" &
OWNER_PID=$!
wait_until 10 test -e "${S}/argv-awgv5"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
DAEMON="$(record_get "${TOKEN}" child CHILD_PID)"
assert_true "S3b: (the daemon runs and has registered itself)" pid_alive "${DAEMON}"
kill -KILL "$(record_get "${TOKEN}" guard GUARD_PID)"
wait "${OWNER_PID}"
assert_rc 1 "$?" "S3b: creation fails when the guardian dies before readiness"
assert_true "S3b: and the owner stops the registered daemon from its record" wait_until 5 pid_gone "${DAEMON}"
assert_true "S3b: and nothing of the attempt is left" wait_until 5 scratch_gone awgv5 "${TOKEN}"
rm -f "${S}/fake-mode"
# S3c: guardian and owner both die after readiness; the daemon survives them
# (no parent-death signal); a later run's sweep reclaims it.
reset_state
rm -f "${T}/token"
"${OWNER_CMD[@]}" direct create awgv5 "${T}/token" hold &
OWNER_PID=$!
wait_until 10 test -s "${T}/token"
TOKEN="$(cat "${T}/token")"
DAEMON="$(record_get "${TOKEN}" child CHILD_PID)"
kill -KILL "$(record_get "${TOKEN}" guard GUARD_PID)"
kill -KILL "${OWNER_PID}"
wait "${OWNER_PID}" 2>/dev/null
sleep 0.3
assert_true "S3c: (the daemon survives its guardian and owner)" pid_alive "${DAEMON}"
owner direct sweep
assert_true "S3c: the next sweep stops it by its recorded identity" wait_until 5 pid_gone "${DAEMON}"
assert_true "S3c: and removes its sockets and records" scratch_gone awgv5 "${TOKEN}"
rm -f "${MOCKBIN}/setpriv"
# S3d: systemd-run is delayed while both guardian and owner die; the unit it
# creates late is reclaimed by the next sweep.
reset_state
rm -f "${T}/token"
touch "${S}/systemd-run-hold"
"${OWNER_CMD[@]}" unit create awgp7 "${T}/token" &
OWNER_PID=$!
wait_until 5 test -e "${S}/systemd-run-waiting"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
wait_until 5 test -n "$(record_get "${TOKEN}" client CLIENT_PID)"
kill -KILL "$(record_get "${TOKEN}" guard GUARD_PID)" "${OWNER_PID}"
wait "${OWNER_PID}" 2>/dev/null
touch "${S}/systemd-run-release"
wait_until 5 compgen -G "${S}/units/amneziawg-scratch-awgp7-${TOKEN}" >/dev/null
assert_true "S3d: (the unit was created after guardian and owner died)" test -e "${S}/units/amneziawg-scratch-awgp7-${TOKEN}"
owner unit sweep
assert_true "S3d: the next sweep reclaims the late unit" scratch_gone awgp7 "${TOKEN}"
rm -f "${S}"/systemd-run-*
# S3e: the systemd-run client registered itself and is held before it submits
# the unit while owner and guardian are killed. The sweep keeps every record
# and never signals the client; the unit it submits after that never runs
# BoringTun; the next sweep leaves nothing.
reset_state
rm -f "${T}/token"
touch "${S}/systemd-run-hold"
"${OWNER_CMD[@]}" unit create awgp7 "${T}/token" &
OWNER_PID=$!
wait_until 5 test -e "${S}/systemd-run-waiting"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
CLIENT="$(record_get "${TOKEN}" client CLIENT_PID)"
assert_true "S3e: the process in systemd-run is the client that registered itself" \
	grep -q systemd-run "/proc/${CLIENT}/cmdline"
assert_eq "$(_awgBtProcessStartTime "${CLIENT}")" "$(record_get "${TOKEN}" client CLIENT_START)" "S3e: by its PID and start time"
kill -KILL "$(record_get "${TOKEN}" guard GUARD_PID)" "${OWNER_PID}"
wait "${OWNER_PID}" 2>/dev/null
CLIENT_WAIT=1 owner unit sweep
assert_true "S3e: a sweep keeps every record while the registered client lives" \
	test -f "${SCRATCH_DIR}/${TOKEN}.owner" -a -f "${SCRATCH_DIR}/${TOKEN}.guard" -a -f "${SCRATCH_DIR}/${TOKEN}.client"
assert_true "S3e: and never signals the client" pid_alive "${CLIENT}"
touch "${S}/systemd-run-release"
assert_true "S3e: (the client then submits the unit and exits)" wait_until 5 pid_gone "${CLIENT}"
assert_true "S3e: (the late unit was created)" wait_until 5 test -s "${S}/unit-pids"
assert_true "S3e: the late unit exits at once" wait_until 5 pid_gone "$(cat "${S}/unit-pids")"
assert_true "S3e: without running BoringTun" test ! -e "${S}/argv-awgp7"
CLIENT_WAIT=1 owner unit sweep
assert_true "S3e: the next sweep leaves nothing" scratch_gone awgp7 "${TOKEN}"
sleep 0.3
assert_true "S3e: and nothing comes back" scratch_gone awgp7 "${TOKEN}"
rm -f "${S}"/systemd-run-*
# S3f: the client's own record is durable before anything can be submitted:
# while that write is held, systemd-run is never invoked.
reset_state
rm -f "${T}/token"
echo ".client." >"${S}/mktemp-hold"
"${OWNER_CMD[@]}" unit create awgp7 "${T}/token" &
OWNER_PID=$!
wait_until 5 test -e "${S}/mktemp-waiting"
sleep 0.5
assert_eq "" "$(grep '^systemd-run' "${S}/log")" "S3f: no systemd-run is invoked before the client's own record is durable"
touch "${S}/mktemp-release"
wait "${OWNER_PID}"
assert_rc 0 "$?" "S3f: and the creation then succeeds"
TOKEN="$(cat "${T}/token")"
assert_true "S3f: and its owner's exit still tears it down" wait_until 10 scratch_gone awgp7 "${TOKEN}"
rm -f "${S}"/mktemp-*
# S3h: a reclaim marks the attempt before it reads any record, and the client
# reads the mark after recording itself. A client that registers after a
# reclaim began sees the mark and submits nothing.
reset_state
rm -f "${T}/token"
echo ".client." >"${S}/mktemp-hold"
"${OWNER_CMD[@]}" unit create awgp7 "${T}/token" &
OWNER_PID=$!
wait_until 5 test -e "${S}/mktemp-waiting"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
printf '' >"${SCRATCH_DIR}/${TOKEN}.reclaim"
chmod 0600 "${SCRATCH_DIR}/${TOKEN}.reclaim"
touch "${S}/mktemp-release"
wait "${OWNER_PID}"
assert_rc 1 "$?" "S3h: a creation whose attempt is being reclaimed fails"
assert_eq "" "$(grep '^systemd-run' "${S}/log")" "S3h: its client, registered after the reclaim mark, submits nothing"
assert_true "S3h: and nothing of the attempt is left" wait_until 10 scratch_gone awgp7 "${TOKEN}"
rm -f "${S}"/mktemp-*
# S3i: the other order. A reclaim is held before it marks the attempt while
# the client is held before it records itself; the client then registers and
# blocks in systemd-run, and the reclaim goes on: it sees the client, keeps
# every record and never signals it.
reset_state
rm -f "${T}/token"
touch "${S}/systemd-run-hold"
echo ".client." >"${S}/mktemp-hold"
"${OWNER_CMD[@]}" unit create awgp7 "${T}/token" &
OWNER_PID=$!
wait_until 5 test -e "${S}/mktemp-waiting"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
echo ".reclaim." >"${S}/mktemp-hold-b"
CLIENT_WAIT=1 owner unit reclaim "${TOKEN}" &
RECLAIM_PID=$!
wait_until 5 test -e "${S}/mktemp-waiting-b"
touch "${S}/mktemp-release"
wait_until 5 test -e "${S}/systemd-run-waiting"
CLIENT="$(record_get "${TOKEN}" client CLIENT_PID)"
touch "${S}/mktemp-release-b"
wait "${RECLAIM_PID}"
assert_rc 1 "$?" "S3i: a reclaim racing a registering client does not finish"
assert_true "S3i: it keeps every record while the client that registered meanwhile lives" \
	test -f "${SCRATCH_DIR}/${TOKEN}.owner" -a -f "${SCRATCH_DIR}/${TOKEN}.guard" -a -f "${SCRATCH_DIR}/${TOKEN}.client"
assert_true "S3i: and never signals it" pid_alive "${CLIENT}"
touch "${S}/systemd-run-release"
wait "${OWNER_PID}" 2>/dev/null
assert_true "S3i: the unit submitted after the mark never runs BoringTun" test ! -e "${S}/argv-awgp7"
assert_true "S3i: and the attempt is then torn down completely" wait_until 15 scratch_gone awgp7 "${TOKEN}"
rm -f "${S}"/mktemp-* "${S}"/systemd-run-*
# S3j/S3k: a direct child registers while its guardian's own teardown reclaims
# the attempt. The child is held before it records itself; its owner dies;
# the guardian's wait for the registration runs out and its reclaim is held
# just before it removes the records; the child records itself and is held
# again before its checks. S3j resumes the child after the reclaim finished,
# S3k while the reclaim is still held. The guardian is alive (in wait) in both.
for CASE in S3j S3k; do
	reset_state
	rm -f "${T}/token"
	echo ".child." >"${S}/mktemp-hold"
	"${OWNER_CMD[@]}" direct create awgp7 "${T}/token" &
	OWNER_PID=$!
	wait_until 5 test -s "${S}/mktemp-waiting"
	TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
	GUARD="$(record_get "${TOKEN}" guard GUARD_PID)"
	echo "${TOKEN}.owner" >"${S}/rm-hold"
	echo "${TOKEN}.child" >"${S}/mv-hold-after"
	kill -KILL "${OWNER_PID}"
	wait "${OWNER_PID}" 2>/dev/null
	assert_true "${CASE}: (the guardian's reclaim is held before it removes the records)" \
		wait_until $((AWG_BT_READY_TIMEOUT + 10)) test -e "${S}/rm-waiting"
	touch "${S}/mktemp-release"
	assert_true "${CASE}: (the child recorded itself after the reclaim read the records)" \
		wait_until 5 test -e "${S}/mv-waiting-after"
	CHILD="$(record_get "${TOKEN}" child CHILD_PID)"
	assert_true "${CASE}: (the reclaim's read of the records did not see it)" test -n "${CHILD}"
	if [[ "${CASE}" == S3j ]]; then
		touch "${S}/rm-release"
		assert_true "${CASE}: (the reclaim removed every record)" wait_until 5 test ! -e "${SCRATCH_DIR}/${TOKEN}.owner" -a ! -e "${SCRATCH_DIR}/${TOKEN}.reclaim"
		assert_true "${CASE}: (the guardian still lives)" pid_alive "${GUARD}"
		touch "${S}/mv-release-after"
	else
		touch "${S}/mv-release-after"
		assert_true "${CASE}: (the child finished its checks while the reclaim is held)" wait_until 5 pid_gone "${CHILD}"
		touch "${S}/rm-release"
	fi
	assert_true "${CASE}: the late child exits" wait_until 5 pid_gone "${CHILD}"
	assert_true "${CASE}: without ever running BoringTun" test ! -e "${S}/argv-awgp7"
	assert_true "${CASE}: and the guardian finishes" wait_until 5 pid_gone "${GUARD}"
	assert_true "${CASE}: leaving no daemon, socket, link or record" scratch_gone awgp7 "${TOKEN}"
	kill -KILL "${CHILD}" 2>/dev/null
	rm -f "${S}"/mktemp-* "${S}"/rm-* "${S}"/mv-*
done
# S3l: its guardian killed, the owner's destroy begins a reclaim, held while the
# owner record is still valid. The child, released only then, sees the
# cancellation and starts nothing, with no guardian to rely on.
reset_state
rm -f "${T}/token"
echo ".child." >"${S}/mktemp-hold"
"${OWNER_CMD[@]}" direct create awgp7 "${T}/token" &
OWNER_PID=$!
wait_until 5 test -s "${S}/mktemp-waiting"
TOKEN="$(basename "$(ls "${SCRATCH_DIR}"/*.owner)" .owner)"
echo "${TOKEN}.owner" >"${S}/rm-hold"
kill -KILL "$(record_get "${TOKEN}" guard GUARD_PID)"
assert_true "S3l: (the owner's reclaim is held before it removes the records)" wait_until 10 test -e "${S}/rm-waiting"
assert_true "S3l: (the owner record is still valid and the attempt marked as being reclaimed)" \
	test -n "$(record_get "${TOKEN}" owner OWNER_PID)" -a -e "${SCRATCH_DIR}/${TOKEN}.reclaim"
touch "${S}/mktemp-release"
wait_until 5 test -n "$(record_get "${TOKEN}" child CHILD_PID)"
CHILD="$(record_get "${TOKEN}" child CHILD_PID)"
assert_true "S3l: a child of a cancelled attempt exits although its owner record is valid" wait_until 5 pid_gone "${CHILD}"
assert_true "S3l: without running BoringTun" test ! -e "${S}/argv-awgp7"
touch "${S}/rm-release"
wait "${OWNER_PID}" 2>/dev/null
assert_true "S3l: and the owner's reclaim leaves nothing" wait_until 10 scratch_gone awgp7 "${TOKEN}"
kill -KILL "${CHILD}" 2>/dev/null
rm -f "${S}"/mktemp-* "${S}"/rm-*
# A foreign socket at a scratch instance's UAPI path is never taken for its own.
reset_state
AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_ABSENT}"
echo foreign >"${S}/fake-mode"
run awgBackendCreateScratchInterface awgv5
FOREIGN_PID="$(cat "${S}/foreign-pid" 2>/dev/null)"
assert_rc 1 "${RC}" "S2: a scratch daemon whose UAPI path another process holds never becomes ready"
assert_true "S2: and the competitor's socket is left in place" test -S "${AWG_BT_WG_SOCKET_DIR}/awgv5.sock"
kill -KILL "${FOREIGN_PID}" 2>/dev/null
rm -f "${S}/fake-mode" "${AWG_BT_WG_SOCKET_DIR}/awgv5.sock"
AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_PRESENT}"

# A zombie owner: its parent never reaps it.
reset_state
rm -f "${T}/token"
bash -c '"$@" & exec sleep 60' _ "${T}/owner.sh" "${INSTALLER}" "${T}/settings.sh" unit create awgv9 "${T}/token" &
REAPER=$!
wait_until 10 test -s "${T}/token"
TOKEN="$(cat "${T}/token")"
assert_true "S3: a scratch instance whose owner is a zombie is torn down" wait_until 5 scratch_gone awgv9 "${TOKEN}"
kill -KILL "${REAPER}"
wait "${REAPER}" 2>/dev/null

echo "=== The stale sweep touches only what records prove dead ==="
reset_state
awgBackendCreateScratchInterface awgp2 2>/dev/null
TOKEN_A="${_AWG_BT_SCRATCH_TOKENS[awgp2]:-}"
owner unit sweep
assert_true "a sweep in another process leaves an attempt with a live owner alone" test -e "${SCRATCH_DIR}/${TOKEN_A}.guard" -a -e "${NET}/awgp2"
awgBackendCreateScratchInterface awgp3 2>/dev/null
assert_true "the owner's own next creation (which sweeps) keeps its first instance" test -e "${SCRATCH_DIR}/${TOKEN_A}.guard" -a -e "${NET}/awgp2"
awgBackendDestroyScratchInterface awgp3
awgBackendDestroyScratchInterface awgp2
BOGUS="0123456789abcdef0123456789abcdef"
printf 'FORMAT=1\n' >"${SCRATCH_DIR}/${BOGUS}.owner"
chmod 0644 "${SCRATCH_DIR}/${BOGUS}.owner"
mkdir "${NET}/awgp4"
touch "${S}/known-amneziawg-scratch-awgp4-${BOGUS}"
: >"${S}/log"
owner unit sweep
assert_true "an unreadable record is left alone" test -e "${SCRATCH_DIR}/${BOGUS}.owner"
assert_true "and a foreign link of a scratch-like name is never touched" test -d "${NET}/awgp4"
assert_eq "" "$(grep -E '^(systemctl stop|ip link delete)' "${S}/log")" "and no unit or link is stopped or deleted by name"
rm -f "${SCRATCH_DIR}/${BOGUS}.owner" "${S}/known-amneziawg-scratch-awgp4-${BOGUS}"
rmdir "${NET}/awgp4"

echo "=== S4: signals only reach identified processes ==="
assert_true "PID 1 is never signalled" test "$(_awgBtSignalProcess 1 "$(_awgBtProcessStartTime 1 || echo 0)" TERM; echo $?)" = 1
assert_true "the calling shell is never signalled" test "$(_awgBtSignalProcess "$$" "$(_awgBtProcessStartTime "$$")" TERM; echo $?)" = 1
# A zombie: a child whose parent execs sleep and so never reaps it.
bash -c 'sleep 0.3 & echo "$!" >"$1"; exec sleep 30' _ "${T}/zombie-pid" &
ZOMBIE_PARENT=$!
wait_until 3 test -s "${T}/zombie-pid"
ZOMBIE="$(cat "${T}/zombie-pid")"
ZOMBIE_START="$(_awgBtProcessStartTime "${ZOMBIE}")"
wait_until 3 test "$(awk '{print $3}' "/proc/${ZOMBIE}/stat" 2>/dev/null)" = Z
assert_eq "Z" "$(awk '{print $3}' "/proc/${ZOMBIE}/stat")" "(a child its parent never reaps is a zombie)"
assert_true "a zombie is not the live process it was" test "$(_awgBtProcessIs "${ZOMBIE}" "${ZOMBIE_START}"; echo $?)" = 1
assert_true "and stopping it succeeds without a signal" _awgBtStopProcess "${ZOMBIE}" "${ZOMBIE_START}"
kill -KILL "${ZOMBIE_PARENT}"
wait "${ZOMBIE_PARENT}" 2>/dev/null
bash -c 'sleep 300 </dev/null >/dev/null 2>&1 & echo $!' | tee -a "${T}/decoys" >"${T}/decoy-pid"
DECOY_PID="$(cat "${T}/decoy-pid")"
DECOY_START="$(_awgBtProcessStartTime "${DECOY_PID}")"
_awgBtStopProcess "${DECOY_PID}" "$((DECOY_START + 1))"
assert_true "a PID whose start time changed is never signalled" pid_alive "${DECOY_PID}"
# A reused daemon PID in stale records.
reset_state
mkdir -p "${SCRATCH_DIR}"
chmod 0700 "${SCRATCH_DIR}"
printf 'FORMAT=1\nTOKEN=%s\nNAME=awgp4\nMODE=direct\nUNIT=\nOWNER_PID=%s\nOWNER_START=1\n' "${BOGUS}" "${DECOY_PID}" >"${SCRATCH_DIR}/${BOGUS}.owner"
printf 'FORMAT=1\nTOKEN=%s\nNAME=awgp4\nMODE=direct\nUNIT=\nGUARD_PID=%s\nGUARD_START=1\nPHASE=created\nDAEMON_PID=%s\nDAEMON_START=1\nIFINDEX=\nWG_SOCK=\nAWG_SOCK=\n' \
	"${BOGUS}" "${DECOY_PID}" "${DECOY_PID}" >"${SCRATCH_DIR}/${BOGUS}.guard"
chmod 0600 "${SCRATCH_DIR}/${BOGUS}".*
owner direct sweep
assert_true "a sweep never signals a process that reused a recorded daemon, guardian or owner PID" pid_alive "${DECOY_PID}"
assert_true "and it removes the dead attempt's records" records_gone "${BOGUS}"
# S3g: a reused systemd-run client PID. Owner, guardian and client records
# all name a live process whose start time differs: the sweep neither waits
# for it nor signals it, and reclaims the attempt.
reset_state
mkdir -p "${SCRATCH_DIR}"
chmod 0700 "${SCRATCH_DIR}"
BOGUS_UNIT="amneziawg-scratch-awgp4-${BOGUS}"
printf 'FORMAT=1\nTOKEN=%s\nNAME=awgp4\nMODE=unit\nUNIT=%s\nOWNER_PID=%s\nOWNER_START=1\n' "${BOGUS}" "${BOGUS_UNIT}" "${DECOY_PID}" >"${SCRATCH_DIR}/${BOGUS}.owner"
printf 'FORMAT=1\nTOKEN=%s\nNAME=awgp4\nMODE=unit\nUNIT=%s\nGUARD_PID=%s\nGUARD_START=1\nPHASE=starting\nDAEMON_PID=\nDAEMON_START=\nIFINDEX=\nWG_SOCK=\nAWG_SOCK=\n' \
	"${BOGUS}" "${BOGUS_UNIT}" "${DECOY_PID}" >"${SCRATCH_DIR}/${BOGUS}.guard"
printf 'FORMAT=1\nTOKEN=%s\nCLIENT_PID=%s\nCLIENT_START=%s\n' "${BOGUS}" "${DECOY_PID}" "$((DECOY_START + 1))" >"${SCRATCH_DIR}/${BOGUS}.client"
chmod 0600 "${SCRATCH_DIR}/${BOGUS}".*
SECONDS=0
CLIENT_WAIT=30 owner unit sweep
assert_true "S3g: a sweep never signals a process that reused a recorded client PID" pid_alive "${DECOY_PID}"
assert_true "S3g: and does not wait for it as for a live client" test "${SECONDS}" -lt 10
assert_true "S3g: and removes the dead attempt's records" records_gone "${BOGUS}"
# The same records naming the live process by its real start time: it is a
# registered client that may still submit the unit. The sweep keeps every
# record, never signals it, and bars the unit from starting BoringTun.
printf 'FORMAT=1\nTOKEN=%s\nNAME=awgp4\nMODE=unit\nUNIT=%s\nOWNER_PID=%s\nOWNER_START=1\n' "${BOGUS}" "${BOGUS_UNIT}" "${DECOY_PID}" >"${SCRATCH_DIR}/${BOGUS}.owner"
printf 'FORMAT=1\nTOKEN=%s\nNAME=awgp4\nMODE=unit\nUNIT=%s\nGUARD_PID=%s\nGUARD_START=1\nPHASE=starting\nDAEMON_PID=\nDAEMON_START=\nIFINDEX=\nWG_SOCK=\nAWG_SOCK=\n' \
	"${BOGUS}" "${BOGUS_UNIT}" "${DECOY_PID}" >"${SCRATCH_DIR}/${BOGUS}.guard"
printf 'FORMAT=1\nTOKEN=%s\nCLIENT_PID=%s\nCLIENT_START=%s\n' "${BOGUS}" "${DECOY_PID}" "${DECOY_START}" >"${SCRATCH_DIR}/${BOGUS}.client"
chmod 0600 "${SCRATCH_DIR}/${BOGUS}".*
: >"${S}/log"
CLIENT_WAIT=1 owner unit sweep
assert_true "S3g: a sweep keeps the records while a registered client lives" \
	test -f "${SCRATCH_DIR}/${BOGUS}.owner" -a -f "${SCRATCH_DIR}/${BOGUS}.guard" -a -f "${SCRATCH_DIR}/${BOGUS}.client"
assert_true "S3g: and marks the attempt as being reclaimed" test -f "${SCRATCH_DIR}/${BOGUS}.reclaim"
assert_true "S3g: and never signals the client" pid_alive "${DECOY_PID}"
assert_eq "" "$(grep "^systemctl stop ${BOGUS_UNIT}" "${S}/log")" "S3g: and does not trust a stop of the unit while its client may still submit it"
rm -f "${SCRATCH_DIR}/${BOGUS}".*
# A reused guardian PID in the owner's tracking.
AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_ABSENT}"
awgBackendCreateScratchInterface awgv4 2>/dev/null
TOKEN="${_AWG_BT_SCRATCH_TOKENS[awgv4]:-}"
REAL_GUARD="${_AWG_BT_SCRATCH_GUARDS[awgv4]:-}"
_AWG_BT_SCRATCH_GUARDS[awgv4]="${DECOY_PID}"
_AWG_BT_SCRATCH_GUARD_STARTS[awgv4]="$((DECOY_START + 1))"
awgBackendDestroyScratchInterface awgv4 2>/dev/null
assert_true "destroy never signals a process that reused the guardian's PID" pid_alive "${DECOY_PID}"
assert_true "and the instance is still removed" wait_until 5 scratch_gone awgv4 "${TOKEN}"
wait "${REAL_GUARD}" 2>/dev/null
kill -KILL "${DECOY_PID}" 2>/dev/null

echo "=== Capability probe and staged validation on the BoringTun seam ==="
reset_state
AWG_BT_SYSTEMD_RUNTIME_DIR="${SYSTEMD_ABSENT}"
echo exit >"${S}/fake-mode"
run probeAwgProtocolCapability 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
assert_rc 1 "${RC}" "a probe fails when no BoringTun scratch interface can start"
assert_contains "AWG 3.1 is not supported by both the installed awg tool and the pinned BoringTun build" "${ERR}" "the probe failure names BoringTun"
assert_contains "could not start a temporary BoringTun interface" "${ERR}" "with a BoringTun-specific detail"
assert_not_contains "type amneziawg" "$(cat "${S}/log")" "a BoringTun probe never creates a kernel link"
rm -f "${S}/fake-mode"

staged() { # <interface lines> → sets RC, ERR; the config has a [Peer] after them
	printf '[Interface]\nAddress = 10.66.66.1/24\nPrivateKey = k\n%s\nS1 = 20\n\n[Peer]\nPublicKey = p\n' "$1" >"${T}/awgs1.conf"
	rm -f "${S}/setconf-input"
	run validateStagedAwgConfigs "${T}" "${T}/awgs1.conf"
}
reset_state
staged "ListenPort = 51820"
assert_rc 0 "${RC}" "staged validation passes on a BoringTun scratch instance"
assert_eq $'[Interface]\nPrivateKey = k\nS1 = 20' "$(cat "${S}/setconf-input")" \
	"BoringTun validation applies the [Interface] section without ListenPort, which the running server holds"
assert_eq "" "$(find "${NET}" "${AWG_BT_WG_SOCKET_DIR}" "${SCRATCH_DIR}" -mindepth 1)" "and leaves no scratch instance behind"
for PORT_LINE in "listenport=51820 # comment" "  LISTENPORT =  1" "ListenPort = 65535" "ListenPort = 5 1820" ""; do
	staged "${PORT_LINE}"
	assert_rc 0 "${RC}" "S7: '${PORT_LINE}' is accepted"
	assert_not_contains "istenPort" "$(cat "${S}/setconf-input" 2>/dev/null)" "S7: and omitted from the scratch instance, which binds no port"
done
for PORT_LINE in "ListenPort =" "ListenPort = abc" "ListenPort = -1" "ListenPort = 0" "ListenPort = 65536" \
	"ListenPort = 051820" "ListenPort = 99999999999999999999" $'ListenPort = 51820\nListenPort = 51820' $'ListenPort = 51820\nListenPort = 51821'; do
	staged "${PORT_LINE}"
	assert_rc 1 "${RC}" "S7: '$(tr '\n' ';' <<<"${PORT_LINE}")' is rejected"
	assert_contains "must set ListenPort at most once, to a port number from 1 to 65535" "${ERR}" "S7: with a reason"
	assert_true "S7: before anything is applied" test ! -e "${S}/setconf-input"
done
AWG_BACKEND=kernel
reset_state
staged "ListenPort = 51820"
assert_rc 0 "${RC}" "kernel staged validation still passes"
assert_contains "ListenPort = 51820" "$(cat "${S}/setconf-input")" "and the kernel scratch link still gets ListenPort"
assert_contains "type amneziawg" "$(cat "${S}/log")" "with a kernel scratch link"
staged "ListenPort = abc"
assert_contains "ListenPort = abc" "$(cat "${S}/setconf-input")" "the kernel path still leaves ListenPort to awg setconf, unchanged"
AWG_BACKEND="${AWG_BACKEND_BORINGTUN}"

echo "=== ensureAwgBackendReady (S6) and awgBackendQuickUp ==="
reset_state
rm -rf -- "${AWG_BT_LIBEXEC_DIR}" "${AWG_BT_SYSTEMD_DIR:?}"/*
rm -f "${AWG_BT_CONFIG_DIR}/${IF}.boringtun"
write_server_config "${IF}"
# shellcheck disable=SC2034 # read by ensureAwgBackendReady
SERVER_AWG_NIC="${IF}"
run in_subshell ensureAwgBackendReady 0
assert_rc 0 "${RC}" "mode 0 prepares the runtime for probes"
assert_true "and writes the helpers" test -x "${LAUNCH}" -a -x "${CTL}"
assert_true "but no service files" test ! -e "${AWG_BT_CONFIG_DIR}/${IF}.boringtun" -a ! -e "${AWG_BT_SYSTEMD_DIR}/awg-quick@${IF}.service.d/override.conf"
assert_not_contains "systemctl start" "$(cat "${S}/log")" "and never touches the service"
run in_subshell ensureAwgBackendReady 2
assert_rc 1 "${RC}" "an invalid mode is refused"

reset_state
mkdir "${NET}/${IF}"
echo 9 >"${NET}/${IF}/ifindex"
echo yes >"${S}/live/${IF}"
touch "${S}/active-awg-quick@${IF}"
run in_subshell ensureAwgBackendReady 1
assert_rc 1 "${RC}" "S6: an awg-quick@<if> already active on the kernel module is not accepted as BoringTun"
assert_contains "is active but not served by the verified BoringTun instance" "${ERR}" "S6: with a useful error"
assert_not_contains "systemctl start" "$(cat "${S}/log")" "S6: and it is neither restarted nor migrated"
assert_not_contains "systemctl restart" "$(cat "${S}/log")" "S6: (no restart either)"
assert_true "S6: the kernel interface is left as it was" test -d "${NET}/${IF}"

reset_state
service_start "${IF}"
PID="$(state_get "${IF}" PID)"
touch "${S}/active-awg-quick@${IF}"
echo "${PID}" >"${S}/mainpid-awg-quick@${IF}"
echo "${INVOCATION_ID}" >"${S}/invocation-awg-quick@${IF}"
run in_subshell ensureAwgBackendReady 1
assert_rc 0 "${RC}" "S6: an active awg-quick@<if> served by its tracked BoringTun daemon is accepted"
assert_not_contains "systemctl start" "$(cat "${S}/log")" "S6: without starting it again"
echo 1 >"${S}/mainpid-awg-quick@${IF}"
run in_subshell ensureAwgBackendReady 1
assert_rc 1 "${RC}" "S6: it is refused when systemd's MainPID is not the tracked daemon"
echo "${PID}" >"${S}/mainpid-awg-quick@${IF}"
kill -KILL "${PID}"
wait_until 3 pid_gone "${PID}"
run in_subshell ensureAwgBackendReady 1
assert_rc 1 "${RC}" "S6: and when the tracked daemon is gone"
"${CTL}" stop "${IF}"
"${CTL}" poststop "${IF}"

reset_state
run in_subshell ensureAwgBackendReady 1
assert_rc 1 "${RC}" "S6: a started unit that did not produce the recorded BoringTun instance fails"
assert_contains "systemctl start awg-quick@${IF}" "$(cat "${S}/log")" "S6: (the inactive unit was started)"
sed -i 's/^binary_sha256=.*/binary_sha256=0000000000000000000000000000000000000000000000000000000000000000/' "${RELEASE}/MANIFEST"
run in_subshell ensureAwgBackendReady 0
assert_rc 1 "${RC}" "a store that fails verification makes ensureAwgBackendReady exit 1"
assert_not_contains "apt" "$(cat "${S}/log")" "and nothing is installed or downloaded"
cp "${T}/manifest.good" "${RELEASE}/MANIFEST"

reset_state
install_helpers
write_runtime_file "${IF}"
write_server_config "${IF}"
run awgBackendQuickUp "${AWG_BT_CONFIG_DIR}/${IF}.conf"
assert_rc 0 "${RC}" "quick-up brings up a verified BoringTun instance"
assert_contains "awg-quick up ${AWG_BT_CONFIG_DIR}/${IF}.conf impl=${LAUNCH}" "$(cat "${S}/log")" "with the launcher as awg-quick's userspace implementation"
adopt_attempt "${IF}"
assert_true "and records its own attempt as up" flag_is "${IF}" up
"${CTL}" stop "${IF}"
"${CTL}" poststop "${IF}"
assert_true "and it comes down cleanly" nothing_left "${IF}"
reset_state
touch "${S}/kernel-wins"
run awgBackendQuickUp "${AWG_BT_CONFIG_DIR}/${IF}.conf"
rm -f "${S}/kernel-wins"
assert_rc 1 "${RC}" "quick-up fails when awg-quick took the kernel path"
assert_contains "awg-quick down" "$(cat "${S}/log")" "and takes the interface it created down again"
assert_true "and leaves nothing" nothing_left "${IF}"
reset_state
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
run awgBackendQuickUp "${AWG_BT_CONFIG_DIR}/${IF}.conf"
assert_rc 1 "${RC}" "quick-up runs the same precheck as the service"
assert_not_contains "awg-quick up" "$(cat "${S}/log")" "and stops before awg-quick when it fails"
assert_true "and leaves no state" test -z "$(compgen -G "${AWG_BT_RUN_DIR}/${IF}@*")"
rm -rf "${AWG_BT_SYS_DIR}/module/amneziawg"
AWG_BACKEND=kernel

echo
echo "BoringTun runtime tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
