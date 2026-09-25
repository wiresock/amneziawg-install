#!/usr/bin/env bash

# Unit tests for the internal BoringTun runtime layer of amneziawg-install.sh:
# the generated awg-boringtun-launch and awg-backend-ctl helpers, store and
# runtime-file verification, the service drop-in, the ListenPort-filtered sync
# and scratch interfaces. Nothing here needs root, a network namespace, systemd
# or a real BoringTun: a fixture store holds a fake boringtun-cli that creates
# real UAPI sockets in a private directory, and mocks stand in for awg,
# awg-quick, ip, modinfo, systemd-run and systemctl. The generated helpers are
# executed, not just the functions they are built from.
#
# Set AWG_QUICK_REFERENCE to an awg-quick script (for example
# /usr/bin/awg-quick) to also compare the PostDown/SaveConfig parser against
# awg-quick's own parse_options.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"

# shellcheck source=../amneziawg-install.sh
source "${INSTALLER}"

T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-runtime-tests.XXXXXX")"
T="$(CDPATH='' cd -- "${T}" && pwd -P)"
chmod 0755 "${T}"
S="${T}/state"
MOCKBIN="${T}/mockbin"
mkdir -p "${S}/live" "${S}/links" "${S}/units" "${S}/strip" "${S}/port" "${MOCKBIN}"

PASS=0
FAIL=0

cleanup() {
	local F
	for F in "${S}"/live/* "${S}"/units/*; do
		[[ -f "${F}" ]] || continue
		kill -KILL "$(cat "${F}" 2>/dev/null)" 2>/dev/null
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
mkdir -p "${T}/lib" "${T}/run" "${AWG_BT_CONFIG_DIR}" "${AWG_BT_SYSTEMD_DIR}" \
	"${T}/usr/lib/systemd" "${AWG_BT_WG_SOCKET_DIR}" "${AWG_BT_AWG_SOCKET_DIR}" "${AWG_BT_SYS_DIR}/class/net" \
	"${AWG_BT_SYS_DIR}/module"
chmod 0700 "${AWG_BT_CONFIG_DIR}"
PATH="${MOCKBIN}:${PATH}"

cat >"${T}/usr/lib/systemd/awg-quick@.service" <<'EOF'
[Unit]
Description=WireGuard via wg-quick(8) for %I

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/awg-quick up %i
ExecStop=/usr/bin/awg-quick down %i
ExecReload=/bin/bash -c 'exec /usr/bin/awg syncconf %i <(exec /usr/bin/awg-quick strip %i)'
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity
EOF

# ── Mocks ────────────────────────────────────────────────────────────────────
# awg: an interface is live while $S/live/<if> holds "yes" or a running PID.
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
if [[ "$1" == show && "$2" == interfaces ]]; then
	OUT=""
	for F in "${S}"/live/*; do
		[[ -e "${F}" ]] || continue
		live "${F##*/}" && OUT+="${F##*/} "
	done
	echo "${OUT% }"
	exit 0
fi
if [[ "$1" == show && $# -eq 3 && "$3" == listen-port ]]; then
	live "$2" || exit 1
	cat "${S}/port/$2" 2>/dev/null || echo 51820
	exit 0
fi
if [[ "$1" == show && $# -eq 2 ]]; then
	live "$2" || exit 1
	echo "interface: $2"
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

cat >"${MOCKBIN}/awg-quick" <<EOF
#!/bin/bash
S='${S}'
EOF
cat >>"${MOCKBIN}/awg-quick" <<'EOF'
echo "awg-quick $* impl=${WG_QUICK_USERSPACE_IMPLEMENTATION:-}" >>"${S}/log"
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
		exit "$(cat "${S}/down-rc" 2>/dev/null || echo 0)"
		;;
	up)
		NAME="${2##*/}"
		NAME="${NAME%.conf}"
		if [[ -n "${WG_QUICK_USERSPACE_IMPLEMENTATION:-}" ]]; then
			"${WG_QUICK_USERSPACE_IMPLEMENTATION}" "${NAME}" || exit 1
		fi
		exit "$(cat "${S}/up-rc" 2>/dev/null || echo 0)"
		;;
esac
EOF

cat >"${MOCKBIN}/modinfo" <<EOF
#!/bin/bash
echo "modinfo \$*" >>'${S}/log'
exit "\$(cat '${S}/modinfo-rc' 2>/dev/null || echo 1)"
EOF

# ip: a link exists while $S/links/<if> exists; deleting one stops its daemon.
cat >"${MOCKBIN}/ip" <<EOF
#!/bin/bash
S='${S}'
EOF
cat >>"${MOCKBIN}/ip" <<'EOF'
echo "ip $*" >>"${S}/log"
if [[ "$1 $2 $3" == "link show dev" ]]; then
	[[ -e "${S}/links/$4" ]]
	exit
fi
if [[ "$1 $2 $3" == "link add dev" ]]; then
	echo kernel >"${S}/links/$4"
	exit 0
fi
if [[ "$1 $2 $3" == "link delete dev" ]]; then
	[[ -e "${S}/links/$4" ]] || exit 1
	PID="$(cat "${S}/links/$4")"
	rm -f "${S}/links/$4"
	[[ "${PID}" =~ ^[0-9]+$ ]] && kill -TERM "${PID}" 2>/dev/null
	exit 0
fi
exit 0
EOF

# systemd-run starts the command in the background and records its PID for
# systemctl; systemctl answers for those units and logs everything else.
cat >"${MOCKBIN}/systemd-run" <<EOF
#!/bin/bash
S='${S}'
EOF
cat >>"${MOCKBIN}/systemd-run" <<'EOF'
echo "systemd-run $*" >>"${S}/log"
UNIT=""
while [[ $# -gt 0 && "$1" != "--" ]]; do
	[[ "$1" == --unit=* ]] && UNIT="${1#--unit=}"
	shift
done
shift
if [[ -f "${S}/systemd-run-fail" ]]; then
	# A name in the file stands for a concurrent creator that won the race.
	RACER="$(cat "${S}/systemd-run-fail")"
	[[ -n "${RACER}" ]] && echo 1 >"${S}/links/${RACER}"
	exit 1
fi
"$@" </dev/null >/dev/null 2>&1 &
echo "$!" >"${S}/units/${UNIT}"
exit 0
EOF

cat >"${MOCKBIN}/systemctl" <<EOF
#!/bin/bash
S='${S}'
EOF
cat >>"${MOCKBIN}/systemctl" <<'EOF'
echo "systemctl $*" >>"${S}/log"
case "$1" in
	is-active)
		UNIT="${*: -1}"
		if [[ -f "${S}/units/${UNIT}" ]]; then
			kill -0 "$(cat "${S}/units/${UNIT}")" 2>/dev/null && exit 0
			rm -f "${S}/units/${UNIT}"
			exit 3
		fi
		[[ -f "${S}/active-${UNIT}" ]] && exit 0
		exit 3
		;;
	stop)
		if [[ -f "${S}/units/$2" ]]; then
			PID="$(cat "${S}/units/$2")"
			kill -TERM "${PID}" 2>/dev/null
			for _ in $(seq 30); do kill -0 "${PID}" 2>/dev/null || break; sleep 0.1; done
			rm -f "${S}/units/$2"
		fi
		exit 0
		;;
	start)
		touch "${S}/active-$2"
		exit 0
		;;
	show)
		UNIT="${*: -1}"
		UNIT="${UNIT%.service}"
		if [[ -f "${S}/units/${UNIT}" || -f "${S}/known-${UNIT}" ]]; then
			echo loaded
		else
			echo not-found
		fi
		exit 0
		;;
esac
exit 0
EOF
chmod 0755 "${MOCKBIN}"/*

# The fake boringtun-cli. The launcher runs it with an empty environment, so its
# paths are baked in and its behaviour comes from $S/fake-mode.
FAKE_BIN_SOURCE="${T}/fake-boringtun-cli"
cat >"${FAKE_BIN_SOURCE}" <<EOF
#!/bin/bash
S='${S}'
WGDIR='${AWG_BT_WG_SOCKET_DIR}'
AWGDIR='${AWG_BT_AWG_SOCKET_DIR}'
SYSDIR='${AWG_BT_SYS_DIR}'
EOF
cat >>"${FAKE_BIN_SOURCE}" <<'EOF'
IF="${!#}"
printf '%s\n' "$@" >"${S}/argv-${IF}"
env | sort >"${S}/env-${IF}"
ls -1 "/proc/$$/fd" | sort -n | tr '\n' ' ' >"${S}/fds-${IF}"
MODE="$(cat "${S}/fake-mode" 2>/dev/null || echo ready)"
case "${MODE}" in
	exit) exit 3 ;;
	hang) echo "$$" >"${S}/hang-pid"; exec sleep 60 ;;
	slow) sleep 1.5 ;;
esac
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${WGDIR}/${IF}.sock"
ln -sf "${WGDIR}/${IF}.sock" "${AWGDIR}/${IF}.sock"
if [[ "${MODE}" == socket-exit ]]; then
	exit 4
fi
echo "$$" >"${S}/live/${IF}"
echo "$$" >"${S}/links/${IF}"
mkdir -p "${SYSDIR}/class/net/${IF}"
touch "${SYSDIR}/class/net/${IF}/tun_flags"
trap 'rm -rf "${S}/live/${IF}" "${S}/links/${IF}" "${WGDIR}/${IF}.sock" "${AWGDIR}/${IF}.sock" "${SYSDIR}/class/net/${IF}"; exit 0' TERM
while :; do
	sleep 0.2 &
	wait $!
done
EOF

FAKE_COMMIT="0123456789abcdef0123456789abcdef01234567"
RELEASE_ID="boringtun-cli-0.7.1-g0123456789ab-linux-x86_64-musl"

# make_store: an x86_64 store with one release and a current link.
make_store() {
	local ARCH=x86_64 RELEASE="${AWG_BT_STORE_DIR}/${RELEASE_ID}" SHA
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

write_runtime_file() { # [content]
	local FILE="${AWG_BT_CONFIG_DIR}/${1}.boringtun"
	rm -f -- "${FILE}"
	printf '%s' "${2-$(_awgBtRenderRuntimeFile)$'\n'}" >"${FILE}"
	chmod 0600 "${FILE}"
}

write_server_config() { # <if> [extra interface lines]
	cat >"${AWG_BT_CONFIG_DIR}/$1.conf" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = cHJpdmF0ZS1rZXktZm9yLXRlc3RzLW9ubHktMDAwMDA9
${2:-}
EOF
	chmod 0600 "${AWG_BT_CONFIG_DIR}/$1.conf"
}

reset_state() {
	local F
	for F in "${S}"/live/* "${S}"/units/*; do
		[[ -f "${F}" ]] || continue
		kill -KILL "$(cat "${F}" 2>/dev/null)" 2>/dev/null
	done
	rm -rf -- "${S}" "${AWG_BT_RUN_DIR}"
	mkdir -p "${S}/live" "${S}/links" "${S}/units" "${S}/strip" "${S}/port"
	: >"${S}/log"
	rm -f -- "${AWG_BT_WG_SOCKET_DIR}"/* "${AWG_BT_AWG_SOCKET_DIR}"/*
	rm -rf -- "${AWG_BT_SYS_DIR}/class/net"/* "${AWG_BT_SYS_DIR}/module"/*
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

echo "=== The internal activation boundary ==="
assert_eq "kernel 0" "${AWG_BACKEND} ${_AWG_BORINGTUN_RUNTIME_INTERNAL}" \
	"a sourced installer starts on the kernel backend with the BoringTun runtime off"
assert_eq "kernel 0" \
	"$(env AWG_BACKEND=boringtun _AWG_BORINGTUN_RUNTIME_INTERNAL=1 bash -c 'source "$1"; echo "${AWG_BACKEND} ${_AWG_BORINGTUN_RUNTIME_INTERNAL}"' _ "${INSTALLER}")" \
	"exported AWG_BACKEND and _AWG_BORINGTUN_RUNTIME_INTERNAL are discarded when the installer loads"
assert_eq "0" "$(grep -v '^[[:space:]]*#' "${INSTALLER}" | grep -v '^function _awgInternalSelectBoringtunRuntimeForTesting()' |
	grep -c '_awgInternalSelectBoringtunRuntimeForTesting')" "nothing in the installer calls the internal selection"
run bash -c 'source "$1"; AWG_BACKEND=boringtun; normalizeAwgBackend' _ "${INSTALLER}"
assert_rc 1 "${RC}" "a persisted AWG_BACKEND=boringtun is still unsupported"
run bash -c 'source "$1"; _awgInternalSelectBoringtunRuntimeForTesting; validatePersistedAwgBackendState' _ "${INSTALLER}"
assert_rc 1 "${RC}" "params validation rejects boringtun even after the internal selection"
run bash -c 'source "$1"; AWG_BACKEND=boringtun; awgBackendCreateScratchInterface awgp1' _ "${INSTALLER}"
assert_rc 1 "${RC}" "without the internal selection a BoringTun scratch interface is refused"
assert_contains "not supported by this installer version" "${ERR}" "and reported as an unsupported backend"
run bash -c 'source "$1"; AWG_BACKEND=boringtun; ensureAwgBackendReady 0' _ "${INSTALLER}"
assert_rc 1 "${RC}" "without the internal selection ensureAwgBackendReady exits 1"
run bash -c 'source "$1"; AWG_BACKEND=boringtun; awgSyncInterfaceConfig awg0' _ "${INSTALLER}"
assert_rc 1 "${RC}" "without the internal selection awgSyncInterfaceConfig refuses"
run bash -c 'source "$1"; AWG_BACKEND=boringtun; awgBackendQuickUp /etc/amnezia/amneziawg/awg0.conf' _ "${INSTALLER}"
assert_rc 1 "${RC}" "without the internal selection awgBackendQuickUp refuses"
run bash -c 'source "$1"; _awgInternalSelectBoringtunRuntimeForTesting; SERVER_PUB_IP=x; serializeParams "$2"' _ "${INSTALLER}" "${T}/params-out"
assert_rc 1 "${RC}" "serializeParams refuses to persist the internal BoringTun selection"
assert_true "and writes no params file" test ! -e "${T}/params-out"
run bash -c 'source "$1"; _AWG_BORINGTUN_RUNTIME_INTERNAL=1; AWG_BACKEND=kernel; declare -f awgBackendCreateScratchInterface >/dev/null; _awgBtRuntimeSelected' _ "${INSTALLER}"
assert_rc 1 "${RC}" "the internal flag alone does not select BoringTun while AWG_BACKEND is kernel"

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
assert_eq "${FIRST_LAUNCH}" "$(env SERVER_PRIV_KEY=secret WG_LOG_FILE=/x AWG_BT_STORE_DIR=/evil bash -c 'source "$1"; AWG_BT_TRUST_ANCHOR="$2"; AWG_BT_TRUSTED_UID="$3"; AWG_BT_STORE_DIR="$4"; AWG_BT_LIBEXEC_DIR="$5"; AWG_BT_RUN_DIR="$6"; AWG_BT_CONFIG_DIR="$7"; AWG_BT_SYSTEMD_DIR="$8"; AWG_BT_UNIT_DIRS="$9"; shift 9; AWG_BT_SYSTEMD_RUNTIME_DIR="$1"; AWG_BT_WG_SOCKET_DIR="$2"; AWG_BT_AWG_SOCKET_DIR="$3"; AWG_BT_SYS_DIR="$4"; AWG_BT_PROC_DIR="$5"; AWG_BT_TUN_DEVICE="$6"; AWG_BT_PATH="$7"; AWG_BT_READY_TIMEOUT="$8"; AWG_BT_HOST_ARCH="$9"; _awgBtRenderHelper launch' _ \
	"${INSTALLER}" "${AWG_BT_TRUST_ANCHOR}" "${AWG_BT_TRUSTED_UID}" "${AWG_BT_STORE_DIR}" "${AWG_BT_LIBEXEC_DIR}" \
	"${AWG_BT_RUN_DIR}" "${AWG_BT_CONFIG_DIR}" "${AWG_BT_SYSTEMD_DIR}" "${AWG_BT_UNIT_DIRS}" "${AWG_BT_SYSTEMD_RUNTIME_DIR}" \
	"${AWG_BT_WG_SOCKET_DIR}" "${AWG_BT_AWG_SOCKET_DIR}" "${AWG_BT_SYS_DIR}" "${AWG_BT_PROC_DIR}" "${AWG_BT_TUN_DEVICE}" \
	"${AWG_BT_PATH}" "${AWG_BT_READY_TIMEOUT}" "${AWG_BT_HOST_ARCH}")" \
	"the environment of the generating shell never reaches a helper"
SERVER_PRIV_KEY="c2VjcmV0LWtleS1uZXZlci1pbi1oZWxwZXJzLTAwMDA9"
assert_not_contains "${SERVER_PRIV_KEY}" "$(_awgBtRenderHelper launch)$(_awgBtRenderHelper ctl)" "no params value is embedded in a helper"
unset SERVER_PRIV_KEY
assert_contains "readonly AWG_BT_STORE_DIR=" "${FIRST_LAUNCH}" "helpers embed their paths as read-only settings"
assert_contains "export PATH=" "${FIRST_LAUNCH}" "helpers set their own PATH"
assert_true "the generated launcher is valid bash" bash -n "${LAUNCH}"
assert_true "the generated awg-backend-ctl is valid bash" bash -n "${CTL}"
ln -s "${T}/elsewhere" "${T}/symlink-dest"
_awgBtWriteManagedFile "${T}/symlink-dest" 0644 <<<"x" 2>/dev/null
assert_rc 1 "$?" "a managed file is never written through a symlink"
assert_true "and the symlink target is not created" test ! -e "${T}/elsewhere"
MANIFEST_KEYS_IN_SCRIPT="$(sed -n 's/^BTA_MANIFEST_KEYS="\(.*\)"$/\1/p' "${PROJECT_ROOT}/scripts/boringtun-artifact.sh")"
assert_eq "${MANIFEST_KEYS_IN_SCRIPT}" "${AWG_BT_MANIFEST_KEYS}" \
	"the installer reads exactly the MANIFEST keys the artifact script writes"

echo "=== Service drop-in ==="
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
assert_eq "1" "$(grep -c '^systemctl daemon-reload' "${S}/log")" "a new drop-in triggers one daemon-reload"
_awgBtInstallServiceFiles awgbt0
assert_eq "1" "$(grep -c '^systemctl daemon-reload' "${S}/log")" "an unchanged drop-in triggers no further daemon-reload"
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
RELEASE="${AWG_BT_STORE_DIR}/${RELEASE_ID}"

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
assert_eq "$(readlink -f "${RELEASE}/boringtun-cli")" "${_AWG_BT_VERIFIED_BIN}" "a good store yields the canonical binary path"

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
exec 7>"${T}/held-descriptor"
run env WG_TUN_FD=3 WG_UAPI_FD=4 WG_LOG_FILE=/tmp/leak WG_LOG_LEVEL=trace WG_SUDO=true \
	WG_IMITATE_PROTOCOL=dns WG_IMITATE_DOMAIN=example.com WG_THREADS=64 LD_PRELOAD=/tmp/evil.so \
	SERVER_PRIV_KEY=secret "${LAUNCH}" "${IF}"
exec 7>&-
assert_rc 0 "${RC}" "the launcher succeeds once the daemon is ready"
assert_eq "0 1 2 255 " "$(cat "${S}/fds-${IF}")" "no descriptor of the caller, such as a held lock, reaches the daemon"
PID="$(cat "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid" 2>/dev/null)"
assert_eq "$(cat "${S}/live/${IF}" 2>/dev/null)" "${PID}" "the PID file names the running daemon"
assert_true "the daemon keeps running after the launcher exits" pid_alive "${PID}"
assert_eq "--foreground
--disable-drop-privileges
--verbosity
error
${IF}" "$(cat "${S}/argv-${IF}")" "the daemon gets exactly the production arguments"
assert_eq "$(readlink -f "${RELEASE}/boringtun-cli")" "$(tr '\0' '\n' <"/proc/${PID}/cmdline" | sed -n 2p)" \
	"the daemon runs the verified store binary"
ENV_NAMES="$(cut -d= -f1 "${S}/env-${IF}" | grep -vxE 'PWD|SHLVL|_' | tr '\n' ' ')"
assert_eq "NO_COLOR PATH " "${ENV_NAMES}" "the daemon's environment holds only PATH and NO_COLOR"
assert_eq "PATH=${AWG_BT_PATH}" "$(grep '^PATH=' "${S}/env-${IF}")" "with the helper's fixed PATH"
assert_eq "700" "$(stat -c '%a' "${AWG_BT_RUN_DIR}")" "the runtime directory is private (0700)"
kill -TERM "${PID}"
sleep 0.5

reset_state
write_runtime_file "${IF}"
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
run "${LAUNCH}" "${IF}"
assert_rc 1 "${RC}" "a daemon that exits at once fails the launch"
assert_contains "exited before ${IF} became ready" "${ERR}" "and the early exit is reported"
assert_true "and it is reported without waiting for the timeout" test "${SECONDS}" -lt 3
assert_true "and no PID file is left" test ! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"

reset_state
write_runtime_file "${IF}"
echo socket-exit >"${S}/fake-mode"
run "${LAUNCH}" "${IF}"
assert_rc 1 "${RC}" "a daemon that dies after binding its socket fails the launch"
assert_true "and its stale sockets are removed" test ! -e "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" -a ! -e "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"

# A helper set with a one-second readiness timeout.
AWG_BT_READY_TIMEOUT=1
install_helpers
AWG_BT_READY_TIMEOUT=5
reset_state
write_runtime_file "${IF}"
echo hang >"${S}/fake-mode"
SECONDS=0
run "${LAUNCH}" "${IF}"
assert_rc 1 "${RC}" "a daemon that never becomes ready fails the launch"
assert_contains "did not become ready within 1 seconds" "${ERR}" "and the timeout is reported"
assert_true "and the launch gives up after the bounded wait" test "${SECONDS}" -lt 5
sleep 0.3
HANG_PID="$(cat "${S}/hang-pid" 2>/dev/null)"
assert_true "and the tracked daemon was stopped" test -n "${HANG_PID}" -a ! -d "/proc/${HANG_PID}"
assert_true "and no PID file is left" test ! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
install_helpers

reset_state
write_runtime_file "${IF}"
echo yes >"${S}/live/${IF}"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
run "${LAUNCH}" "${IF}"
assert_rc 1 "${RC}" "the launcher refuses a name whose UAPI socket already answers"
assert_contains "a live daemon already answers" "${ERR}" "and says why"
assert_true "and leaves the live daemon's socket alone" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
assert_true "and starts nothing" test ! -e "${S}/argv-${IF}"

echo "=== awg-backend-ctl precheck ==="
reset_state
install_helpers
write_runtime_file "${IF}"
write_server_config "${IF}"
run "${CTL}" precheck "${IF}"
assert_rc 0 "${RC}" "precheck passes on a verified host"
run "${CTL}" precheck
assert_rc 2 "${RC}" "awg-backend-ctl requires a command and an interface"
run "${CTL}" precheck 'bad name'
assert_rc 2 "${RC}" "awg-backend-ctl refuses an invalid interface name"
run "${CTL}" frobnicate "${IF}"
assert_rc 2 "${RC}" "awg-backend-ctl refuses an unknown command"

precheck_refused() { # <label> <fragment>
	run "${CTL}" precheck "${IF}"
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
run "${CTL}" precheck "${IF}"
assert_rc 0 "${RC}" "the last SaveConfig wins, as in awg-quick"
write_server_config "${IF}" "
[Peer]
SaveConfig = true"
run "${CTL}" precheck "${IF}"
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

echo "=== awg-backend-ctl poststart ==="
# A fake /proc with one process whose exe is the verified binary.
FAKE_PROC="${T}/proc"
mkdir -p "${FAKE_PROC}/4242" "${FAKE_PROC}/sys/net/ipv6"
AWG_BT_PROC_DIR="${FAKE_PROC}"
install_helpers
VERIFIED_BIN="$(readlink -f "${RELEASE}/boringtun-cli")"
poststart_setup() {
	reset_state
	mkdir -p "${AWG_BT_SYS_DIR}/class/net/${IF}" "${AWG_BT_RUN_DIR}"
	chmod 0700 "${AWG_BT_RUN_DIR}"
	touch "${AWG_BT_SYS_DIR}/class/net/${IF}/tun_flags"
	echo "4242 (boringtun-cli) S 1 4242" >"${FAKE_PROC}/4242/stat"
	ln -sfn "${VERIFIED_BIN}" "${FAKE_PROC}/4242/exe"
	echo 4242 >"${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
	echo yes >"${S}/live/${IF}"
	python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
	ln -sf "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"
}
poststart_refused() { # <label> <fragment>
	run "${CTL}" poststart "${IF}"
	if [[ "${RC}" != 0 && "${ERR}" == *"$2"* ]]; then ok "$1"; else not_ok "$1 (rc=${RC}: ${ERR})"; fi
	assert_true "  and the .up marker is kept for poststop" test -e "${AWG_BT_RUN_DIR}/${IF}.up"
}
poststart_setup
run "${CTL}" poststart "${IF}"
assert_rc 0 "${RC}" "poststart accepts the verified BoringTun serving a TUN interface"
assert_true "and writes the .up marker" test -e "${AWG_BT_RUN_DIR}/${IF}.up"
poststart_setup
rm -rf "${AWG_BT_SYS_DIR}/class/net/${IF}/tun_flags"
poststart_refused "poststart refuses an interface that is not a TUN device" "not a TUN device"
poststart_setup
rm -rf "${AWG_BT_SYS_DIR}/class/net/${IF}"
poststart_refused "poststart refuses when the interface is missing" "does not exist"
poststart_setup
echo "4242 (boringtun-cli) Z 1 4242" >"${FAKE_PROC}/4242/stat"
poststart_refused "poststart refuses a dead (zombie) PID" "does not name a running process"
poststart_setup
rm -f "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
poststart_refused "poststart refuses a missing PID file" "does not name a running process"
poststart_setup
ln -sfn /usr/bin/sleep "${FAKE_PROC}/4242/exe"
poststart_refused "poststart refuses a PID whose executable is not the verified binary" "is not the verified BoringTun binary"
poststart_setup
rm -f "${S}/live/${IF}"
poststart_refused "poststart refuses when the UAPI does not answer" "does not answer"
AWG_BT_PROC_DIR="/proc"
install_helpers

echo "=== awg-backend-ctl stop ==="
reset_state
mkdir -p "${AWG_BT_RUN_DIR}"
touch "${AWG_BT_RUN_DIR}/${IF}.up"
echo yes >"${S}/live/${IF}"
run "${CTL}" stop "${IF}"
assert_rc 0 "${RC}" "stop runs a clean awg-quick down"
assert_contains "awg-quick down ${IF}" "$(cat "${S}/log")" "stop brings the interface down with awg-quick"
assert_true "a clean down clears the .up marker" test ! -e "${AWG_BT_RUN_DIR}/${IF}.up"
touch "${AWG_BT_RUN_DIR}/${IF}.up"
echo 1 >"${S}/down-rc"
run "${CTL}" stop "${IF}"
assert_rc 1 "${RC}" "a failing awg-quick down fails stop"
assert_true "and keeps the .up marker" test -e "${AWG_BT_RUN_DIR}/${IF}.up"
rm -f "${S}/down-rc" "${S}/live/${IF}"
: >"${S}/log"
run "${CTL}" stop "${IF}"
assert_rc 0 "${RC}" "stop succeeds when the interface is already gone"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "and does not run awg-quick down"
assert_true "and keeps the .up marker for poststop" test -e "${AWG_BT_RUN_DIR}/${IF}.up"

echo "=== awg-backend-ctl poststop ==="
HOOK_LOG="${T}/hooks.log"
write_server_config "${IF}" "PostUp = echo up-%i >>${HOOK_LOG}
PreDown = echo predown-%i >>${HOOK_LOG}
PostDown = echo first-%i >>${HOOK_LOG}
PostDown = false
PostDown = echo third-%i >>${HOOK_LOG}; echo same-hook >>${HOOK_LOG}
SaveConfig = false"
poststop_setup() {
	reset_state
	: >"${HOOK_LOG}"
	mkdir -p "${AWG_BT_RUN_DIR}"
	echo 4242 >"${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
}
poststop_setup
run "${CTL}" poststop "${IF}"
assert_rc 0 "${RC}" "poststop after a clean stop succeeds"
assert_eq "" "$(cat "${HOOK_LOG}")" "a clean stop replays no hooks"
assert_true "and removes the PID file" test ! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"

poststop_setup
touch "${AWG_BT_RUN_DIR}/${IF}.up"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
ln -sf "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"
run "${CTL}" poststop "${IF}"
assert_rc 0 "${RC}" "poststop after a crash succeeds even though a hook failed"
assert_eq "first-${IF}
third-${IF}
same-hook" "$(cat "${HOOK_LOG}")" "a crash replays PostDown in order with %i substituted, past a failing hook, without PreDown"
assert_contains "PostDown hook failed, continuing: false" "${ERR}" "the failing hook is reported"
assert_true "the stale UAPI sockets of the dead daemon are removed" test ! -e "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock" -a ! -L "${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"
assert_true "the marker and PID file are removed" test ! -e "${AWG_BT_RUN_DIR}/${IF}.up" -a ! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
run "${CTL}" poststop "${IF}"
assert_eq "first-${IF}
third-${IF}
same-hook" "$(cat "${HOOK_LOG}")" "a second poststop replays nothing again"

poststop_setup
touch "${AWG_BT_RUN_DIR}/${IF}.up"
echo yes >"${S}/live/${IF}"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
run "${CTL}" poststop "${IF}"
assert_true "the socket of a live daemon is never removed" test -S "${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"

poststop_setup
touch "${AWG_BT_RUN_DIR}/${IF}.up"
mkdir -p "${AWG_BT_SYS_DIR}/class/net/${IF}"
echo yes >"${S}/live/${IF}"
run "${CTL}" poststop "${IF}"
assert_contains "awg-quick down ${IF}" "$(cat "${S}/log")" "a surviving kernel AmneziaWG link is removed with awg-quick down"
assert_eq "" "$(cat "${HOOK_LOG}")" "after that clean down PostDown is not replayed a second time"
assert_true "and the marker is removed" test ! -e "${AWG_BT_RUN_DIR}/${IF}.up"

poststop_setup
touch "${AWG_BT_RUN_DIR}/${IF}.up"
mkdir -p "${AWG_BT_SYS_DIR}/class/net/${IF}"
echo yes >"${S}/live/${IF}"
echo 1 >"${S}/down-rc"
run "${CTL}" poststop "${IF}"
assert_eq "first-${IF}
third-${IF}
same-hook" "$(cat "${HOOK_LOG}")" "when awg-quick down of a kernel link fails, PostDown is still replayed"
rm -f "${S}/down-rc"

poststop_setup
mkdir -p "${AWG_BT_SYS_DIR}/class/net/${IF}"
run "${CTL}" poststop "${IF}"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "an unrelated non-AmneziaWG link of the same name is left alone"

poststop_setup
touch "${AWG_BT_RUN_DIR}/${IF}.up"
mkdir -p "${AWG_BT_SYS_DIR}/class/net/${IF}"
touch "${AWG_BT_SYS_DIR}/class/net/${IF}/tun_flags"
run "${CTL}" poststop "${IF}"
assert_not_contains "awg-quick down" "$(cat "${S}/log")" "a TUN link is never taken down with awg-quick by poststop"
assert_contains "first-${IF}" "$(cat "${HOOK_LOG}")" "and the marker still replays PostDown"

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

if [[ -n "${AWG_QUICK_REFERENCE:-}" && -r "${AWG_QUICK_REFERENCE}" ]]; then
	# Run awg-quick's own parse_options and read_bool, taken from the given
	# script at test time, on every fixture and compare PostDown and SaveConfig.
	REFERENCE_FUNCTIONS="$(sed -n '/^parse_options() {/,/^}/p; /^read_bool() {/,/^}/p' "${AWG_QUICK_REFERENCE}")"
	for FIXTURE in "${PARITY_DIR}"/*.conf; do
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
_awgInternalSelectBoringtunRuntimeForTesting
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
_AWG_BORINGTUN_RUNTIME_INTERNAL=0
: >"${S}/log"
printf '[Interface]\nListenPort = 51821\n' >"${S}/strip/${IF}"
run awgSyncInterfaceConfig "${IF}"
assert_eq "[Interface]
ListenPort = 51821" "$(cat "${S}/syncconf-input")" "the kernel sync still sends ListenPort unfiltered"
assert_not_contains "listen-port" "$(cat "${S}/log")" "and never asks for the live port"

echo "=== Scratch interfaces ==="
_awgInternalSelectBoringtunRuntimeForTesting
reset_state
scratch_refused() { # <label>
	: >"${S}/log"
	run awgBackendCreateScratchInterface awgp1
	if [[ "${RC}" != 0 && "${ERR}" == *"already in use"* ]] && ! grep -q 'systemd-run' "${S}/log"; then
		ok "$1"
	else
		not_ok "$1 (rc=${RC}: ${ERR})"
	fi
}
echo 1 >"${S}/links/awgp1"
scratch_refused "a scratch name with an existing link is refused"
rm -f "${S}/links/awgp1"
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

mkdir -p "${T}/run/systemd-present"
AWG_BT_SYSTEMD_RUNTIME_DIR="${T}/run/systemd-present"
ORIGINAL_EXIT_TRAP="$(trap -p EXIT)"
: >"${S}/log"
awgBackendCreateScratchInterface awgp1 2>"${T}/err"
assert_rc 0 "$?" "under systemd a scratch interface starts in a transient unit"
assert_eq "systemd-run --quiet --collect --unit=amneziawg-scratch-awgp1 -p Type=exec -- $(command -v env) -i PATH=${AWG_BT_PATH} NO_COLOR=1 ${VERIFIED_BIN} --foreground --disable-drop-privileges --verbosity error awgp1" \
	"$(grep '^systemd-run' "${S}/log")" "the transient unit runs the production command line"
UNIT_PID="$(cat "${S}/units/amneziawg-scratch-awgp1")"
assert_true "and the daemon is running" pid_alive "${UNIT_PID}"
GUARD_PID="${_AWG_BT_SCRATCH_GUARDS[awgp1]}"
assert_true "and a guardian watches the shell that owns it" pid_alive "${GUARD_PID}"
awgBackendDestroyScratchInterface awgp1
assert_rc 0 "$?" "the scratch interface is destroyed"
sleep 0.3
assert_true "its daemon is gone" test ! -d "/proc/${UNIT_PID}"
assert_true "no link, unit or socket remains" test ! -e "${S}/links/awgp1" -a ! -e "${S}/units/amneziawg-scratch-awgp1" -a ! -e "${AWG_BT_WG_SOCKET_DIR}/awgp1.sock"
assert_eq "ip link delete dev awgp1" "$(grep -o 'ip link delete dev awgp1' "${S}/log")" "destroy deletes the link first"
assert_true "the guardian is stopped with it" test ! -d "/proc/${GUARD_PID}"
assert_eq "${ORIGINAL_EXIT_TRAP}" "$(trap -p EXIT)" "the caller's EXIT trap is never touched"

AWG_BT_SYSTEMD_RUNTIME_DIR="${T}/run/systemd-absent"
sleep 300 &
DECOY_PID=$!
awgBackendCreateScratchInterface awgv2 2>/dev/null
assert_rc 0 "$?" "without systemd a scratch interface is a tracked child"
CHILD_PID="${_AWG_BT_SCRATCH_PIDS[awgv2]}"
assert_true "and it is running" pid_alive "${CHILD_PID}"
awgBackendDestroyScratchInterface awgv2
sleep 0.3
assert_true "destroying it stops the tracked child" test ! -d "/proc/${CHILD_PID}"
assert_true "an unrelated process is never signalled" pid_alive "${DECOY_PID}"
kill "${DECOY_PID}" 2>/dev/null
wait "${DECOY_PID}" 2>/dev/null
run awgBackendDestroyScratchInterface awgv9
assert_rc 1 "${RC}" "a scratch interface that was not started here is never destroyed"

echo exit >"${S}/fake-mode"
run awgBackendCreateScratchInterface awgv3
assert_rc 1 "${RC}" "a scratch daemon that exits at once fails the creation"
assert_eq "0 0 0" "${#_AWG_BT_SCRATCH_UNITS[@]} ${#_AWG_BT_SCRATCH_PIDS[@]} ${#_AWG_BT_SCRATCH_GUARDS[@]}" \
	"and nothing stays tracked, guardian included"
rm -f "${S}/fake-mode"

sleep 300 &
DECOY_PID=$!
DECOY_START="$(_awgBtProcessStartTime "${DECOY_PID}")"
_awgBtStopProcess "${DECOY_PID}" "$((DECOY_START + 1))"
assert_true "a PID whose start time changed is never signalled" pid_alive "${DECOY_PID}"
_awgBtStopProcess "${DECOY_PID}" "${DECOY_START}"
wait "${DECOY_PID}" 2>/dev/null
assert_true "the same PID with its recorded start time is stopped" test ! -d "/proc/${DECOY_PID}"

AWG_BT_SYSTEMD_RUNTIME_DIR="${T}/run/systemd-present"
touch "${S}/known-amneziawg-scratch-awgv4"
: >"${S}/log"
run awgBackendCreateScratchInterface awgv4
assert_rc 1 "${RC}" "a scratch name whose unit systemd already knows is refused"
assert_contains "already exists" "${ERR}" "and the refusal names the unit"
assert_not_contains "systemd-run" "$(cat "${S}/log")" "and nothing is started over it"
assert_not_contains "systemctl stop" "$(cat "${S}/log")" "and the existing unit is never stopped"
rm -f "${S}/known-amneziawg-scratch-awgv4"

echo awgv5 >"${S}/systemd-run-fail"
: >"${S}/log"
run awgBackendCreateScratchInterface awgv5
assert_rc 1 "${RC}" "a failing systemd-run fails the creation"
assert_not_contains "systemctl stop" "$(cat "${S}/log")" "and never stops a unit it did not start"
assert_true "and never deletes a link that a concurrent creator made" test -e "${S}/links/awgv5"
assert_eq "0 0 0" "${#_AWG_BT_SCRATCH_UNITS[@]} ${#_AWG_BT_SCRATCH_PIDS[@]} ${#_AWG_BT_SCRATCH_GUARDS[@]}" 	"and its guardian is stopped and nothing stays tracked"
rm -f "${S}/systemd-run-fail" "${S}/links/awgv5"

(
	trap 'echo "previous handler ran" >"${T}/prev-exit"' EXIT
	awgBackendCreateScratchInterface awgp5 2>/dev/null
	cat "${S}/units/amneziawg-scratch-awgp5" >"${T}/scratch-pid"
	exit 7
)
assert_rc 7 "$?" "a shell that exits with a scratch interface keeps its exit status"
sleep 1
assert_true "the scratch daemon is cleaned up on EXIT" test ! -d "/proc/$(cat "${T}/scratch-pid")"
assert_true "the transient unit is gone" test ! -e "${S}/units/amneziawg-scratch-awgp5"
assert_eq "previous handler ran" "$(cat "${T}/prev-exit" 2>/dev/null)" "the EXIT handler installed before still runs"

for SIGNAL in TERM INT HUP KILL; do
	(
		awgBackendCreateScratchInterface awgp6 2>/dev/null
		cat "${S}/units/amneziawg-scratch-awgp6" >"${T}/scratch-pid"
		kill -s "${SIGNAL}" "${BASHPID}"
		sleep 5
		echo "not reached" >"${T}/not-reached"
	)
	RC=$?
	sleep 1
	assert_true "SIG${SIGNAL} of the owning shell cleans up the scratch daemon" test ! -d "/proc/$(cat "${T}/scratch-pid")" -a ! -e "${S}/units/amneziawg-scratch-awgp6"
	assert_true "and SIG${SIGNAL} still terminates the shell (rc=${RC})" test ! -e "${T}/not-reached" -a "${RC}" -ne 0
	rm -f "${T}/not-reached"
done
assert_eq "" "$(find "${S}/units" "${S}/links" -mindepth 1)" "no scratch unit or link is left behind"
assert_eq "" "$(find "${AWG_BT_WG_SOCKET_DIR}" "${AWG_BT_AWG_SOCKET_DIR}" -mindepth 1)" "no scratch socket is left behind"

echo "=== Capability probe and staged validation on the BoringTun seam ==="
reset_state
AWG_BT_SYSTEMD_RUNTIME_DIR="${T}/run/systemd-absent"
: >"${S}/log"
touch "${S}/fake-mode"
echo exit >"${S}/fake-mode"
run probeAwgProtocolCapability 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
assert_rc 1 "${RC}" "a probe fails when no BoringTun scratch interface can start"
assert_contains "AWG 3.1 is not supported by both the installed awg tool and the pinned BoringTun build" "${ERR}" "the probe failure names BoringTun"
assert_contains "could not start a temporary BoringTun interface" "${ERR}" "with a BoringTun-specific detail"
assert_not_contains "type amneziawg" "$(cat "${S}/log")" "a BoringTun probe never creates a kernel link"
rm -f "${S}/fake-mode"

printf '[Interface]\nAddress = 10.66.66.1/24\nPrivateKey = k\nListenPort = 51820\nS1 = 20\n\n[Peer]\nPublicKey = p\n' >"${T}/awgs1.conf"
reset_state
run validateStagedAwgConfigs "${T}" "${T}/awgs1.conf"
assert_rc 0 "${RC}" "staged validation passes on a BoringTun scratch instance"
assert_eq $'[Interface]\nPrivateKey = k\nS1 = 20' "$(cat "${S}/setconf-input")" \
	"BoringTun validation applies the [Interface] section without ListenPort, which the running server holds"
assert_eq "" "$(find "${S}/links" "${AWG_BT_WG_SOCKET_DIR}" -mindepth 1)" "and leaves no scratch instance behind"
AWG_BACKEND=kernel
_AWG_BORINGTUN_RUNTIME_INTERNAL=0
reset_state
run validateStagedAwgConfigs "${T}" "${T}/awgs1.conf"
assert_rc 0 "${RC}" "kernel staged validation still passes"
assert_contains "ListenPort = 51820" "$(cat "${S}/setconf-input")" "and the kernel scratch link still gets ListenPort"
assert_contains "type amneziawg" "$(cat "${S}/log")" "with a kernel scratch link"
_awgInternalSelectBoringtunRuntimeForTesting

echo "=== ensureAwgBackendReady and awgBackendQuickUp ==="
reset_state
rm -rf -- "${AWG_BT_LIBEXEC_DIR}" "${AWG_BT_SYSTEMD_DIR:?}"/*
rm -f "${AWG_BT_CONFIG_DIR}/${IF}.boringtun"
# shellcheck disable=SC2034 # read by ensureAwgBackendReady
SERVER_AWG_NIC="${IF}"
run in_subshell ensureAwgBackendReady 0
assert_rc 0 "${RC}" "mode 0 prepares the runtime for probes"
assert_true "and writes the helpers" test -x "${LAUNCH}" -a -x "${CTL}"
assert_true "but no service files" test ! -e "${AWG_BT_CONFIG_DIR}/${IF}.boringtun" -a ! -e "${AWG_BT_SYSTEMD_DIR}/awg-quick@${IF}.service.d/override.conf"
assert_not_contains "systemctl start" "$(cat "${S}/log")" "and never touches the service"
run in_subshell ensureAwgBackendReady 2
assert_rc 1 "${RC}" "an invalid mode is refused"
echo yes >"${S}/live/${IF}"
run in_subshell ensureAwgBackendReady 1
assert_rc 0 "${RC}" "mode 1 prepares and starts the service"
assert_true "and writes the runtime file and drop-in" test -f "${AWG_BT_CONFIG_DIR}/${IF}.boringtun" -a -f "${AWG_BT_SYSTEMD_DIR}/awg-quick@${IF}.service.d/override.conf"
assert_contains "systemctl start awg-quick@${IF}" "$(cat "${S}/log")" "and starts awg-quick@<if> when it is inactive"
rm -f "${S}/live/${IF}"
run in_subshell ensureAwgBackendReady 1
assert_rc 1 "${RC}" "mode 1 fails when the interface does not answer on its UAPI"
sed -i 's/^binary_sha256=.*/binary_sha256=0000000000000000000000000000000000000000000000000000000000000000/' "${RELEASE}/MANIFEST"
run in_subshell ensureAwgBackendReady 0
assert_rc 1 "${RC}" "a store that fails verification makes ensureAwgBackendReady exit 1"
assert_not_contains "apt" "$(cat "${S}/log")" "and nothing is installed or downloaded"
cp "${T}/manifest.good" "${RELEASE}/MANIFEST"

reset_state
install_helpers
write_runtime_file "${IF}"
write_server_config "${IF}"
: >"${S}/log"
run awgBackendQuickUp "${AWG_BT_CONFIG_DIR}/${IF}.conf"
assert_contains "awg-quick up ${AWG_BT_CONFIG_DIR}/${IF}.conf impl=${LAUNCH}" "$(cat "${S}/log")" "quick-up runs awg-quick up with the launcher as the userspace implementation"
assert_rc 1 "${RC}" "quick-up fails when poststart cannot verify the daemon (the fake is not the verified executable)"
assert_contains "awg-quick down" "$(cat "${S}/log")" "and takes the interface down again"
assert_true "and poststop leaves no PID file" test ! -e "${AWG_BT_RUN_DIR}/boringtun-${IF}.pid"
reset_state
write_runtime_file "${IF}"
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
: >"${S}/log"
run awgBackendQuickUp "${AWG_BT_CONFIG_DIR}/${IF}.conf"
assert_rc 1 "${RC}" "quick-up runs the same precheck as the service"
assert_not_contains "awg-quick up" "$(cat "${S}/log")" "and stops before awg-quick when it fails"
rm -rf "${AWG_BT_SYS_DIR}/module/amneziawg"
AWG_BACKEND=kernel
_AWG_BORINGTUN_RUNTIME_INTERNAL=0

echo
echo "BoringTun runtime tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
