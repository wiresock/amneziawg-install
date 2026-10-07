#!/usr/bin/env bash
# shellcheck disable=SC2034 # the suite sets globals that the sourced installer reads

# Unit tests for the BoringTun imitation mode auto in amneziawg-install.sh:
# validation and the hostname refusal, params, fresh-install selection and the
# install question, the runtime file, the daemon's command line, the warnings,
# the --set-boringtun-imitation transaction (active, inactive and failed
# units, restart failure and the restoration of the previous files), the
# refusal of auto on an installed binary that does not support it, the
# launcher's and the scratch instances' refusal, --backend-status and the
# management menu. Nothing here needs root, the network or systemd: every path
# is anchored below a test root, and mocks and function stubs stand in for
# systemctl, the scratch validation and the verification of a running daemon.
#
# The store holds TEST FIXTURE releases, never published ones. Their
# boringtun-cli is a script that parses --imitate-protocol as clap does in the
# real binaries: a value outside its list is a usage error (status 2) before
# --version is acted on. One fixture knows auto, as wiresock-boringtun
# b94943906b11 does; the other does not, as ae2ab44e9a68 and earlier do. Both
# report version 0.7.1, as those releases do, so the version string can never
# tell them apart.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"

if [[ "${EUID}" -eq 0 && "${AWG_DISPOSABLE_HOST_TEST:-}" != 1 ]]; then
	echo "ERROR: run the BoringTun auto imitation tests as an unprivileged user; as root they run only on a disposable host with AWG_DISPOSABLE_HOST_TEST=1" >&2
	exit 2
fi

# shellcheck source=../amneziawg-install.sh
source "${INSTALLER}"

T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-imitation-auto-tests.XXXXXX")"
T="$(CDPATH='' cd -- "${T}" && pwd -P)"
chmod 0755 "${T}"
S="${T}/state"
MOCKBIN="${T}/mockbin"
mkdir -p "${S}" "${MOCKBIN}"

PASS=0
FAIL=0
BACKGROUND=()

cleanup() {
	local PID
	for PID in "${BACKGROUND[@]}"; do
		kill -KILL "${PID}" 2>/dev/null
	done
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
		not_ok "$3 (expected rc=$1, got rc=$2; stdout: ${OUT:-}; stderr: ${ERR:-})"
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

assert_false() {
	local NAME="$1"
	shift
	if "$@"; then not_ok "${NAME}"; else ok "${NAME}"; fi
}

# run <command...>: in a subshell, since installer functions may exit. Sets RC,
# OUT (stdout) and ERR (stderr); stdin is RUN_INPUT when set.
run() {
	if [[ -n "${RUN_INPUT:-}" ]]; then
		("$@") >"${T}/out" 2>"${T}/err" <<<"${RUN_INPUT}"
	else
		("$@") >"${T}/out" 2>"${T}/err" </dev/null
	fi
	RC=$?
	OUT="$(cat "${T}/out")"
	ERR="$(cat "${T}/err")"
}

# ── Settings under test: everything below the test root ─────────────────────
# shellcheck disable=SC2034 # read by the sourced installer's functions
{
AWG_BT_TRUST_ANCHOR="${T}"
AWG_BT_TRUSTED_UID="$(id -u)"
AWG_BT_STORE_DIR="${T}/usr/local/lib/amneziawg-install/boringtun"
AWG_BT_LIBEXEC_DIR="${T}/usr/local/libexec/amneziawg-install"
AWG_BT_RUN_DIR="${T}/run/amneziawg-install"
AWG_BT_CONFIG_DIR="${T}/etc/amnezia/amneziawg"
AWG_BT_SYSTEMD_DIR="${T}/etc/systemd/system"
AWG_BT_SYSTEMD_RUNTIME_DIR="${T}/run/systemd/system"
AWG_BT_WG_SOCKET_DIR="${T}/run/wireguard"
AWG_BT_AWG_SOCKET_DIR="${T}/run/amneziawg"
AWG_BT_SYS_DIR="${T}/sys"
AWG_BT_PROC_DIR="/proc"
AWG_BT_PATH="${MOCKBIN}:/usr/local/bin:/usr/bin:/bin"
AWG_BT_HOST_ARCH="x86_64"
AWG_BT_TMP_DIR="${T}/tmp"
AMNEZIAWG_DIR="${T}/etc/amnezia/amneziawg"
WEB_PANEL_CONFIG_DIR="${AMNEZIAWG_DIR}/clients"
TMPDIR="${T}/tmp"
}
mkdir -p "${AMNEZIAWG_DIR}/clients" "${T}/usr/local/lib" "${T}/usr/local/libexec" "${T}/run" "${T}/tmp" "${T}/sys/module"
chmod -R go-w "${T}"
PATH="${MOCKBIN}:${PATH}"

# systemctl: `show -p ActiveState` prints <state>/active-state; restart fails
# while <state>/restart-rc holds a nonzero line (one line per call, the last
# repeating); everything is logged.
cat >"${MOCKBIN}/systemctl" <<EOF
#!/bin/bash
echo "systemctl \$*" >>'${S}/log'
case "\$1" in
	show)
		[[ "\$*" == *ActiveState* ]] || exit 1
		cat '${S}/active-state' 2>/dev/null
		exit 0
		;;
	is-active)
		[[ "\$(cat '${S}/active-state' 2>/dev/null)" == active ]]
		exit
		;;
	restart)
		RC=0
		if [[ -s '${S}/restart-rc' ]]; then
			RC="\$(head -n 1 '${S}/restart-rc')"
			[[ "\$(wc -l <'${S}/restart-rc')" -gt 1 ]] && sed -i 1d '${S}/restart-rc'
		fi
		exit "\${RC}"
		;;
esac
exit 0
EOF
# stat: params are reported as root's, as validateParamsFile requires;
# everything else is the real stat.
cat >"${MOCKBIN}/stat" <<'EOF'
#!/bin/bash
LAST="${!#}"
if [[ "${LAST}" == */params && "$*" == *"-c %u "* ]]; then
	printf '0\n'
	exit 0
fi
exec /usr/bin/stat "$@"
EOF
chmod 0755 "${MOCKBIN}"/*

# ── Function stubs ───────────────────────────────────────────────────────────
# The lifecycle lock, the backend readiness (which here only regenerates the
# helpers), the proof that the active unit is the recorded BoringTun instance,
# the scratch validation and the verification of a restarted daemon. Each is
# logged. The store and the binary's own answer about auto are never stubbed.
acquireClientLifecycleLock() {
	echo "lock" >>"${S}/log"
}
_awgBtEnsureReady() {
	echo "ensure-ready $*" >>"${S}/log"
	_awgBtInstallHelpers || exit 1
}
_awgBtCheckServedByBoringtun() {
	echo "served $*" >>"${S}/log"
	[[ -f "${S}/daemon-pid" ]] && _AWG_BT_STATE[PID]="$(cat "${S}/daemon-pid")"
	return "$(cat "${S}/served-rc" 2>/dev/null || echo 0)"
}
validateStagedAwgConfigs() {
	echo "validate ${2##*/} protocol=${AWG_BORINGTUN_IMITATE_PROTOCOL} domain=${AWG_BORINGTUN_IMITATE_DOMAIN}" >>"${S}/log"
	return "$(cat "${S}/validate-rc" 2>/dev/null || echo 0)"
}
verifyBoringtunImitationServed() {
	local RC=0
	echo "verify $1|$2" >>"${S}/log"
	if [[ -s "${S}/verify-rc" ]]; then
		RC="$(head -n 1 "${S}/verify-rc")"
		[[ "$(wc -l <"${S}/verify-rc")" -gt 1 ]] && sed -i 1d "${S}/verify-rc"
	fi
	return "${RC}"
}

# ── TEST FIXTURE releases ────────────────────────────────────────────────────
# fixture_binary <file> <protocols> [<label>]: a boringtun-cli that knows the
# given --imitate-protocol values and reports version 0.7.1. It logs every
# invocation to <state>/exec. Like clap, it refuses an unknown value with a
# usage error and status 2 when it reaches it, before --version; --version
# prints the version and exits 0. Any other argument is skipped.
fixture_binary() {
	cat >"$1" <<EOF
#!/bin/sh
# TEST FIXTURE boringtun-cli (${3:-fixture}), knows: $2
echo "exec ${3:-fixture} \$*" >>'${S}/exec'
while [ \$# -gt 0 ]; do
	case "\$1" in
		--imitate-protocol)
			case " $2 " in
				*" \$2 "*) shift 2; continue ;;
			esac
			echo "error: invalid value '\$2' for '--imitate-protocol <imitate-protocol>'" >&2
			echo "  [possible values: $(sed 's/ /, /g' <<<"$2")]" >&2
			echo "" >&2
			echo "For more information, try '--help'." >&2
			exit 2
			;;
		--version) echo "boringtun 0.7.1"; exit 0 ;;
		*) shift ;;
	esac
done
exit 0
EOF
	chmod 0755 "$1"
}
REPOSITORY="${AWG_BT_RELEASE_SOURCE_REPOSITORY}"
# store_release <release id> <source commit> <protocols> <label>: a release
# directory of the store, with a MANIFEST that describes it.
store_release() {
	local ID="$1" COMMIT="$2" DIR="${AWG_BT_STORE_DIR}/$1" KEY
	mkdir -p "${DIR}"
	fixture_binary "${DIR}/boringtun-cli" "$3" "$4"
	printf 'BSD-3-Clause fixture\n' >"${DIR}/LICENSE"
	printf 'fixture notices\n' >"${DIR}/THIRD-PARTY-LICENSES"
	local -A M=(
		[artifact_format]=1 [name]=boringtun-cli [version]=0.7.1
		[source_repository]="${REPOSITORY}" [source_commit]="${COMMIT}"
		[source_date_epoch]=1790626003 [target]=x86_64-unknown-linux-musl [os]=linux [arch]=x86_64 [libc]=musl
		[linkage]=static [rust_toolchain]=1.98.1 [rustc]="rustc 1.98.1" [cargo]="cargo 1.98.1"
		[build_command]="cargo build --release --locked -p boringtun-cli" [build_profile]="release,strip=symbols"
		[rustflags]="--remap-path-prefix=<source>=/boringtun" [binary]=boringtun-cli
		[binary_sha256]="$(sha256sum "${DIR}/boringtun-cli" | cut -d' ' -f1)"
		[license]="LICENSE (BSD-3-Clause)" [third_party_licenses]=THIRD-PARTY-LICENSES
	)
	for KEY in ${AWG_BT_MANIFEST_KEYS}; do
		printf '%s=%s\n' "${KEY}" "${M[${KEY}]}"
	done >"${DIR}/MANIFEST"
	chmod 0755 "${DIR}"
	chmod 0644 "${DIR}/LICENSE" "${DIR}/MANIFEST" "${DIR}/THIRD-PARTY-LICENSES"
}
mkdir -p "${AWG_BT_STORE_DIR}"
chmod 0755 "${T}/usr/local/lib/amneziawg-install" "${AWG_BT_STORE_DIR}"
AUTO_COMMIT="aaaaaaaaaaaa11111111111111111111111111aa"
LEGACY_COMMIT="bbbbbbbbbbbb22222222222222222222222222bb"
AUTO_ID="boringtun-cli-0.7.1-g${AUTO_COMMIT:0:12}-linux-x86_64-musl"
LEGACY_ID="boringtun-cli-0.7.1-g${LEGACY_COMMIT:0:12}-linux-x86_64-musl"
store_release "${AUTO_ID}" "${AUTO_COMMIT}" "none dns quic sip stun auto" auto-capable
store_release "${LEGACY_ID}" "${LEGACY_COMMIT}" "none dns quic sip stun" legacy
# select_current <auto|legacy|-> [previous auto|legacy]: what current (and
# previous) name.
select_current() {
	rm -f -- "${AWG_BT_STORE_DIR}/current" "${AWG_BT_STORE_DIR}/previous"
	case "$1" in
		auto) ln -s -- "${AUTO_ID}" "${AWG_BT_STORE_DIR}/current" ;;
		legacy) ln -s -- "${LEGACY_ID}" "${AWG_BT_STORE_DIR}/current" ;;
	esac
	case "${2:-}" in
		auto) ln -s -- "${AUTO_ID}" "${AWG_BT_STORE_DIR}/previous" ;;
		legacy) ln -s -- "${LEGACY_ID}" "${AWG_BT_STORE_DIR}/previous" ;;
	esac
	: >"${S}/exec"
}

# ── Fixture installation ─────────────────────────────────────────────────────
MOCK_KEY="bW9ja2tleW1vY2trZXltb2NrZXltb2Nra2V5bW9ja2s="
CLIENT_CONF="${AMNEZIAWG_DIR}/clients/awg0-client-alice.conf"
RUNTIME_FILE="${AMNEZIAWG_DIR}/awg0.boringtun"

# make_install <backend> [protocol] [domain] [AWG version] [S1 S2 S3 S4]:
# params, server and client configs and, for BoringTun, the runtime file, as
# an installation of that state leaves them, an active unit, a clean log, and
# current selecting the auto-capable fixture.
make_install() {
	rm -rf -- "${AMNEZIAWG_DIR}"
	mkdir -p "${AMNEZIAWG_DIR}/clients"
	chmod 0755 "${AMNEZIAWG_DIR}"
	rm -f -- "${S}"/*
	SERVER_PUB_IP="198.51.100.10"
	SERVER_PUB_NIC="eth0"
	SERVER_AWG_NIC="awg0"
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/awg0.conf"
	SERVER_AWG_IPV4="10.66.66.1"
	SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"
	SERVER_PORT="51820"
	SERVER_PRIV_KEY="${MOCK_KEY}"
	SERVER_PUB_KEY="c2VydmVycHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo="
	CLIENT_DNS_1="1.1.1.1"
	CLIENT_DNS_2="1.0.0.1"
	ALLOWED_IPS="0.0.0.0/0"
	ENABLE_IPV6="n"
	SERVER_AWG_JC="4"
	SERVER_AWG_JMIN="10"
	SERVER_AWG_JMAX="50"
	SERVER_AWG_S1="${5:-20}"
	SERVER_AWG_S2="${6:-30}"
	SERVER_AWG_S3="${7:-40}"
	SERVER_AWG_S4="${8:-50}"
	SERVER_AWG_H1="100-200"
	SERVER_AWG_H2="300-400"
	SERVER_AWG_H3="500-600"
	SERVER_AWG_H4="700-800"
	AWG_BACKEND="$1"
	AWG_BORINGTUN_IMITATE_PROTOCOL="${2:-none}"
	AWG_BORINGTUN_IMITATE_DOMAIN="${3:-}"
	AWG_PROTOCOL_VERSION="${4:-2}"
	clearAwg3Params
	if [[ "${AWG_PROTOCOL_VERSION}" != 2 ]]; then
		AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
		AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
		AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
		AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
		AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
		AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
		if [[ "${AWG_PROTOCOL_VERSION}" == 3.1 ]]; then
			AWG_RANDOM_TRAILERS="${AWG31_DEFAULT_RANDOM_TRAILERS}"
			AWG_DISABLE_COOKIES="${AWG31_DEFAULT_DISABLE_COOKIES}"
		fi
	fi
	cat >"${SERVER_AWG_CONF}" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIV_KEY}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

### Client alice
[Peer]
PublicKey = cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=
AllowedIPs = 10.66.66.2/32
EOF
	cat >"${CLIENT_CONF}" <<EOF
[Interface]
PrivateKey = ${MOCK_KEY}
Address = 10.66.66.2/32

[Peer]
PublicKey = ${SERVER_PUB_KEY}
Endpoint = 198.51.100.10:51820
AllowedIPs = 0.0.0.0/0
EOF
	chmod 600 "${SERVER_AWG_CONF}" "${CLIENT_CONF}"
	# A persisted auto is written as an installer that supports it writes it,
	# whatever this installer's own validation says (before the change, none
	# does, and the persisted keys are then what the tests read back).
	if ! serializeParams "${AMNEZIAWG_DIR}/params" 2>/dev/null; then
		local P="${AWG_BORINGTUN_IMITATE_PROTOCOL}"
		AWG_BORINGTUN_IMITATE_PROTOCOL=none
		serializeParams "${AMNEZIAWG_DIR}/params" || return 1
		sed -i "s/^AWG_BORINGTUN_IMITATE_PROTOCOL=.*/AWG_BORINGTUN_IMITATE_PROTOCOL='${P}'/" "${AMNEZIAWG_DIR}/params"
		AWG_BORINGTUN_IMITATE_PROTOCOL="${P}"
	fi
	chmod 600 "${AMNEZIAWG_DIR}/params"
	if [[ "$1" == boringtun ]]; then
		if ! _awgBtRenderRuntimeFile >"${RUNTIME_FILE}" 2>/dev/null; then
			printf '# Managed by amneziawg-install (backend: boringtun). Regenerated from params.\nFORMAT=1\nIMITATE_PROTOCOL=%s\n' \
				"${AWG_BORINGTUN_IMITATE_PROTOCOL}" >"${RUNTIME_FILE}"
		fi
		chmod 600 "${RUNTIME_FILE}"
	fi
	echo active >"${S}/active-state"
	select_current auto
	: >"${S}/log"
}

# The mode and hash of every file a change of imitation may or may not touch.
snapshot() {
	local FILE
	for FILE in "${AMNEZIAWG_DIR}/params" "${RUNTIME_FILE}" "${SERVER_AWG_CONF}" "${CLIENT_CONF}"; do
		if [[ -e "${FILE}" ]]; then
			printf '%s %s %s\n' "${FILE##*/}" "$(/usr/bin/stat -c %a "${FILE}")" "$(sha256sum <"${FILE}" | cut -d' ' -f1)"
		else
			printf '%s absent\n' "${FILE##*/}"
		fi
	done
}

params_value() { # <key>: the value as the installer would source it
	(
		unset "$1"
		# shellcheck source=/dev/null
		source "${AMNEZIAWG_DIR}/params"
		printf '%s' "${!1-<unset>}"
	)
}

transaction_dirs() {
	compgen -G "${AMNEZIAWG_DIR}/.awg-imitation.*" | wc -l
}

load_params() {
	loadParams 0 1 >/dev/null
	printf '%s|%s|%s' "${AWG_BACKEND}" "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}"
}

echo "=== Protocol and hostname ==="
assert_true "auto is an imitation protocol" _awgBtImitationProtocolValid auto
for PROTOCOL in AUTO Auto "auto " " auto" "auto,dns" automatic; do
	assert_false "'${PROTOCOL}' is not an imitation protocol" _awgBtImitationProtocolValid "${PROTOCOL}"
done
assert_false "auto carries no hostname" _awgBtImitationUsesDomain auto
assert_true "auto without a hostname is a valid imitation" _awgBtImitationCheck auto ""
run _awgBtImitationCheck auto example.com
assert_rc 1 "${RC}" "auto with a hostname is refused"
assert_contains "auto takes no hostname" "${ERR}" "  and the refusal says that auto takes none"
run _awgBtImitationCheck ssh ""
assert_contains "supported: none, dns, quic, sip, stun, auto" "${ERR}" "the supported protocols include auto"
for PAIR in "none|" "dns|" "dns|example.com" "quic|cdn.example.org" "sip|pbx.example" "stun|"; do
	assert_true "the fixed imitation '${PAIR}' is still valid" _awgBtImitationCheck "${PAIR%%|*}" "${PAIR#*|}"
done
assert_eq "none" "$(boringtunImitationDomainMode auto "")" "auto's hostname mode is none"
assert_contains "auto" "$(boringtunImitationDisplay auto "")" "auto is displayed as auto"
assert_contains "per authenticated peer" "$(boringtunImitationDisplay auto "")" "  chosen per authenticated peer"

echo "=== Params ==="
make_install boringtun auto
rm -f -- "${T}/params.out"
AWG_BACKEND=boringtun AWG_BORINGTUN_IMITATE_PROTOCOL=auto AWG_BORINGTUN_IMITATE_DOMAIN="" run serializeParams "${T}/params.out"
assert_rc 0 "${RC}" "serializeParams writes auto"
assert_eq "AWG_BORINGTUN_IMITATE_PROTOCOL='auto'
AWG_BORINGTUN_IMITATE_DOMAIN=''" "$(tail -n 2 "${T}/params.out" 2>/dev/null)" "  BoringTun params persist auto, without a hostname"
AWG_BACKEND=boringtun AWG_BORINGTUN_IMITATE_PROTOCOL=auto AWG_BORINGTUN_IMITATE_DOMAIN=example.com run serializeParams "${T}/params.out"
assert_rc 1 "${RC}" "but never auto with a hostname"
AWG_BACKEND=kernel AWG_BORINGTUN_IMITATE_PROTOCOL=auto AWG_BORINGTUN_IMITATE_DOMAIN="" run serializeParams "${T}/params.out"
assert_rc 1 "${RC}" "nor kernel params with auto"
run load_params
assert_eq "0 boringtun|auto|" "${RC} ${OUT}" "persisted auto loads"
AWG_BORINGTUN_IMITATE_PROTOCOL=dns AWG_BORINGTUN_IMITATE_DOMAIN=evil.example run load_params
assert_eq "boringtun|auto|" "${OUT}" "  and the environment never overrides it"
make_install boringtun auto
sed -i "s/^AWG_BORINGTUN_IMITATE_DOMAIN=.*/AWG_BORINGTUN_IMITATE_DOMAIN='a.example'/" "${AMNEZIAWG_DIR}/params"
run load_params
assert_rc 1 "${RC}" "persisted auto with a hostname is damaged params"
make_install kernel
printf "AWG_BORINGTUN_IMITATE_PROTOCOL='auto'\n" >>"${AMNEZIAWG_DIR}/params"
run load_params
assert_rc 1 "${RC}" "kernel params that carry auto are damaged"
assert_contains "only with the BoringTun backend" "${ERR}" "  because imitation is BoringTun-only"

echo "=== Fresh-install selection ==="
select_fresh() { # <backend> <protocol request> <domain request>
	AWG_BACKEND="$1"
	_AWG_BT_IMITATE_PROTOCOL_REQUESTED="$2"
	_AWG_BT_IMITATE_DOMAIN_REQUESTED="$3"
	selectFreshInstallImitation || return 1
	printf '%s|%s' "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}"
}
run select_fresh boringtun auto ""
assert_eq "0 auto|" "${RC} ${OUT}" "AWG_BORINGTUN_IMITATE_PROTOCOL=auto selects auto on a fresh BoringTun install"
run select_fresh boringtun auto example.com
assert_rc 1 "${RC}" "auto with AWG_BORINGTUN_IMITATE_DOMAIN is refused"
assert_contains "auto" "${ERR}" "  and the guidance names auto"
run select_fresh kernel auto ""
assert_rc 1 "${RC}" "a kernel install refuses auto"
assert_contains "only with the BoringTun backend" "${ERR}" "  because it needs BoringTun"
run select_fresh boringtun "" ""
assert_eq "0 none|" "${RC} ${OUT}" "without a request the default is still none"

ask() { # <requested protocol> <requested domain>
	AWG_BORINGTUN_IMITATE_PROTOCOL="$1"
	AWG_BORINGTUN_IMITATE_DOMAIN="$2"
	askBoringtunImitation >/dev/null
	printf '%s|%s' "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}"
}
RUN_INPUT=$'6\n1' run ask none ""
assert_eq "auto|" "${OUT}" "the install question: 6 is auto, and asks no hostname"
RUN_INPUT=$'6\n1' run ask dns example.com
assert_eq "auto|" "${OUT}" "  a requested hostname is dropped with auto"
RUN_INPUT=$'6\n1' run ask auto ""
assert_eq "auto|" "${OUT}" "  a requested auto can be kept"
RUN_INPUT=$'1' run bash -c 'source "$1"; askBoringtunImitation' _ "${INSTALLER}"
assert_contains "6) auto" "${OUT}" "the question lists auto"
assert_contains "1) none (default)" "${OUT}" "  and none stays the default"
RUN_INPUT=$'2\nexample.com' run ask none ""
assert_eq "dns|example.com" "${OUT}" "the fixed protocols keep their numbers"

echo "=== Runtime file and command line ==="
render_runtime() {
	AWG_BORINGTUN_IMITATE_PROTOCOL="$1"
	AWG_BORINGTUN_IMITATE_DOMAIN="$2"
	_awgBtRenderRuntimeFile
}
run render_runtime auto ""
assert_eq "# Managed by amneziawg-install (backend: boringtun). Regenerated from params.
FORMAT=1
IMITATE_PROTOCOL=auto" "${OUT}" "auto renders its protocol and no hostname"
run render_runtime auto example.com
assert_rc 1 "${RC}" "auto with a hostname is never rendered"
make_install boringtun
read_runtime() {
	printf '%s\n' "$@" >"${RUNTIME_FILE}"
	chmod 600 "${RUNTIME_FILE}"
	_awgBtReadRuntimeFile awg0 || return 1
	printf '%s|%s' "${_AWG_BT_IMITATE_PROTOCOL}" "${_AWG_BT_IMITATE_DOMAIN}"
}
run read_runtime FORMAT=1 IMITATE_PROTOCOL=auto
assert_eq "0 auto|" "${RC} ${OUT}" "the launcher's parser reads back auto"
run read_runtime FORMAT=1 IMITATE_PROTOCOL=auto IMITATE_DOMAIN=example.com
assert_rc 1 "${RC}" "and refuses a runtime file with auto and a hostname"
run read_runtime FORMAT=1 IMITATE_PROTOCOL=AUTO
assert_rc 1 "${RC}" "  and one with another spelling"

argv_of() { # <protocol> [<domain>]
	_awgBtDaemonArgv /store/boringtun-cli awg0 "$@" || return 1
	printf '%s\n' "${_AWG_BT_ARGV[@]}"
}
run argv_of auto
assert_eq "--imitate-protocol auto awg0" "$(tail -n 3 <<<"${OUT}" | tr '\n' ' ' | sed 's/ $//')" \
	"the daemon runs --imitate-protocol auto, with no --imitate-domain, the interface last"
assert_not_contains "--imitate-domain" "${OUT}" "  (no --imitate-domain at all)"
run argv_of auto example.com
assert_rc 1 "${RC}" "auto with a hostname never becomes a command line"
run argv_of quic cdn.example.org
assert_eq "--imitate-protocol quic --imitate-domain cdn.example.org awg0" "$(tail -n 5 <<<"${OUT}" | tr '\n' ' ' | sed 's/ $//')" \
	"a fixed protocol keeps its command line"

echo "=== What an installed binary supports ==="
# The binary itself is asked; its version string is the same for both.
assert_eq "boringtun 0.7.1|boringtun 0.7.1" \
	"$("${AWG_BT_STORE_DIR}/${AUTO_ID}/boringtun-cli" --version)|$("${AWG_BT_STORE_DIR}/${LEGACY_ID}/boringtun-cli" --version)" \
	"(the two TEST FIXTURE binaries report the same version)"
run _awgBtBinaryImitationSupport "${AWG_BT_STORE_DIR}/${AUTO_ID}/boringtun-cli" auto
assert_rc 0 "${RC}" "a binary that knows auto supports it"
run _awgBtBinaryImitationSupport "${AWG_BT_STORE_DIR}/${LEGACY_ID}/boringtun-cli" auto
assert_rc 1 "${RC}" "a binary that refuses the value does not"
: >"${S}/exec"
for PROTOCOL in none dns quic sip stun; do
	run _awgBtBinaryImitationSupport "${AWG_BT_STORE_DIR}/${LEGACY_ID}/boringtun-cli" "${PROTOCOL}"
	assert_rc 0 "${RC}" "every release this installer runs supports ${PROTOCOL}"
done
assert_eq "" "$(cat "${S}/exec")" "  without running the binary for a fixed protocol"
run _awgBtBinaryImitationSupport "${AWG_BT_STORE_DIR}/${AUTO_ID}/boringtun-cli" auto
assert_eq "exec auto-capable --imitate-protocol auto --version" "$(cat "${S}/exec")" \
	"auto is asked with --imitate-protocol auto --version, which starts no device"
UNSURE="${T}/unsure"
mkdir -p "${UNSURE}"
printf '#!/bin/sh\necho "something else"\nexit 0\n' >"${UNSURE}/prints-other"
printf '#!/bin/sh\necho "boringtun 0.7.1"\nexit 1\n' >"${UNSURE}/fails"
printf '#!/bin/sh\necho "error: invalid value '"'"'auto'"'"' for '"'"'--imitate-protocol <imitate-protocol>'"'"'" >&2\nexit 1\n' >"${UNSURE}/refuses-with-1"
printf '#!/bin/sh\nexit 2\n' >"${UNSURE}/silent-2"
chmod 0755 "${UNSURE}"/*
for NAME in prints-other fails refuses-with-1 silent-2; do
	run _awgBtBinaryImitationSupport "${UNSURE}/${NAME}" auto
	assert_rc 2 "${RC}" "an answer that is neither (${NAME}) is unknown, never support"
done
printf '#!/bin/sh\nexec sleep 30\n' >"${UNSURE}/hangs"
chmod 0755 "${UNSURE}/hangs"
START="${SECONDS}"
AWG_BT_PROBE_TIMEOUT=1 run _awgBtBinaryImitationSupport "${UNSURE}/hangs" auto
assert_rc 2 "${RC}" "a binary that does not answer is unknown"
assert_true "  and is stopped after the probe timeout" test $((SECONDS - START)) -lt 10
printf '#!/bin/sh\n[ -z "${WG_IMITATE_PROTOCOL+x}${LD_PRELOAD+x}" ] && [ "$NO_COLOR" = 1 ] && echo "boringtun 0.7.1"\n' >"${UNSURE}/env-check"
chmod 0755 "${UNSURE}/env-check"
WG_IMITATE_PROTOCOL=bogus LD_PRELOAD="" run _awgBtBinaryImitationSupport "${UNSURE}/env-check" auto
assert_rc 0 "${RC}" "the probe runs the binary with a clean environment (only NO_COLOR and PATH)"

echo "=== --set-boringtun-imitation auto ==="
set_imitation() {
	setBoringtunImitation "$@"
}
make_install boringtun
BEFORE="$(snapshot)"
run set_imitation auto example.com
assert_rc 1 "${RC}" "auto with a hostname is refused"
assert_contains "auto takes no hostname" "${ERR}" "  saying that auto takes none"
assert_contains "<none|dns|quic|sip|stun|auto>" "${ERR}" "  with a usage that lists auto"
assert_eq "" "$(cat "${S}/log")" "  before the lock is taken"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"

make_install boringtun
BEFORE="$(snapshot)"
run set_imitation auto
assert_rc 0 "${RC}" "active, auto-capable binary: auto is applied"
assert_eq "lock
systemctl show -p ActiveState --value awg-quick@awg0.service
ensure-ready 0
served awg0
validate awg0.conf protocol=auto domain=
systemctl reset-failed awg-quick@awg0.service
systemctl restart awg-quick@awg0.service
verify auto|" "$(cat "${S}/log")" \
	"  lock, state, helpers, proof of the running instance, scratch validation of auto, restart, verification of auto"
assert_eq "auto|" "$(params_value AWG_BORINGTUN_IMITATE_PROTOCOL)|$(params_value AWG_BORINGTUN_IMITATE_DOMAIN)" "  params hold auto, without a hostname"
assert_eq "FORMAT=1 IMITATE_PROTOCOL=auto " "$(grep -v '^#' "${RUNTIME_FILE}" | tr '\n' ' ')" "  so does the runtime file"
assert_contains "exec auto-capable --imitate-protocol auto --version" "$(cat "${S}/exec")" "  the installed binary was asked first"
assert_contains "restarted with it" "${OUT}" "  the restart is reported"
assert_contains "per authenticated peer" "${OUT}" "  the warnings say that auto selects per authenticated peer"
assert_eq "$(sed -n '3,4p' <<<"${BEFORE}")" "$(snapshot | sed -n '3,4p')" "  server and client configs are unchanged"
assert_eq "0" "$(transaction_dirs)" "  no transaction directory is left"
run set_imitation auto
assert_rc 0 "${RC}" "auto again is a no-op"
assert_contains "already auto" "${OUT}" "  reported as such"
run set_imitation dns example.com
assert_rc 0 "${RC}" "from auto back to a fixed protocol"
assert_eq "FORMAT=1 IMITATE_PROTOCOL=dns IMITATE_DOMAIN=example.com " "$(grep -v '^#' "${RUNTIME_FILE}" | tr '\n' ' ')" "  restores its runtime file"
run set_imitation none
assert_eq "$(sed -n 1,2p <<<"${BEFORE}")" "$(snapshot | sed -n 1,2p)" "  and none restores params and the runtime file byte for byte"

for STATE in inactive failed; do
	make_install boringtun
	echo "${STATE}" >"${S}/active-state"
	run set_imitation auto
	assert_rc 0 "${RC}" "${STATE}, auto-capable binary: auto is persisted"
	assert_eq "auto" "$(params_value AWG_BORINGTUN_IMITATE_PROTOCOL)" "${STATE}: params hold auto"
	assert_eq "FORMAT=1 IMITATE_PROTOCOL=auto " "$(grep -v '^#' "${RUNTIME_FILE}" | tr '\n' ' ')" "${STATE}: so does the runtime file"
	assert_not_contains "systemctl restart" "$(cat "${S}/log")" "${STATE}: the unit is not started"
	assert_contains "was not started" "${OUT}" "${STATE}: and the operator is told when it applies"
done

for STATE in active inactive failed; do
	make_install boringtun dns example.com
	echo "${STATE}" >"${S}/active-state"
	select_current legacy
	BEFORE="$(snapshot)"
	run set_imitation auto
	assert_rc 1 "${RC}" "${STATE}, binary without auto: auto is refused"
	assert_contains "${LEGACY_ID}" "${ERR}" "${STATE}:   naming the installed release"
	assert_contains "does not support protocol imitation auto" "${ERR}" "${STATE}:   saying it lacks auto"
	assert_contains "--upgrade-boringtun" "${ERR}" "${STATE}:   with the upgrade to run"
	assert_contains "Nothing was changed" "${ERR}" "${STATE}:   and that nothing changed"
	assert_eq "${BEFORE}" "$(snapshot)" "${STATE}:   params and the runtime file are unchanged"
	assert_not_contains "validate" "$(cat "${S}/log")" "${STATE}:   before the scratch validation"
	assert_not_contains "systemctl restart" "$(cat "${S}/log")" "${STATE}:   and nothing was restarted"
	assert_eq "0" "$(transaction_dirs)" "${STATE}:   no transaction directory was made"
	assert_eq "exec legacy --imitate-protocol auto --version" "$(cat "${S}/exec")" "${STATE}:   the binary was asked, and never started"
done
make_install boringtun none
select_current legacy
run set_imitation stun
assert_rc 0 "${RC}" "a binary without auto still takes a fixed protocol"
run set_imitation quic cdn.example.org
assert_rc 0 "${RC}" "  with a hostname too"

make_install boringtun
rm -f -- "${AWG_BT_STORE_DIR}/current"
ln -s -- missing-release "${AWG_BT_STORE_DIR}/current"
BEFORE="$(snapshot)"
run set_imitation auto
assert_rc 1 "${RC}" "a store that does not verify cannot take auto"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"

make_install boringtun
rm -f -- "${AWG_BT_STORE_DIR}/current"
mkdir -p "${AWG_BT_STORE_DIR}/boringtun-cli-0.7.1-gcccccccccccc-linux-x86_64-musl"
store_release boringtun-cli-0.7.1-gcccccccccccc-linux-x86_64-musl cccccccccccc3333333333333333333333333333 "none dns quic sip stun auto" unsure
printf '#!/bin/sh\necho "exec unsure $*" >>%s\necho garbage\nexit 0\n' "${S}/exec" >"${AWG_BT_STORE_DIR}/boringtun-cli-0.7.1-gcccccccccccc-linux-x86_64-musl/boringtun-cli"
sed -i "s/^binary_sha256=.*/binary_sha256=$(sha256sum "${AWG_BT_STORE_DIR}/boringtun-cli-0.7.1-gcccccccccccc-linux-x86_64-musl/boringtun-cli" | cut -d' ' -f1)/" \
	"${AWG_BT_STORE_DIR}/boringtun-cli-0.7.1-gcccccccccccc-linux-x86_64-musl/MANIFEST"
ln -s -- boringtun-cli-0.7.1-gcccccccccccc-linux-x86_64-musl "${AWG_BT_STORE_DIR}/current"
BEFORE="$(snapshot)"
run set_imitation auto
assert_rc 1 "${RC}" "a binary whose answer is unclear cannot take auto"
assert_contains "could not determine" "${ERR}" "  and the error says so"
assert_eq "${BEFORE}" "$(snapshot)" "  nothing changed"
rm -rf -- "${AWG_BT_STORE_DIR}/boringtun-cli-0.7.1-gcccccccccccc-linux-x86_64-musl"

# A persisted auto on a binary without it, as a manual store change or an
# interrupted operation could leave it: a fixed protocol or none is the way
# out, and is accepted.
make_install boringtun auto
select_current legacy
echo failed >"${S}/active-state"
run set_imitation none
assert_rc 0 "${RC}" "auto on a binary without it: none is accepted"
assert_eq "none" "$(params_value AWG_BORINGTUN_IMITATE_PROTOCOL)" "  and persisted"
make_install boringtun auto
select_current legacy
echo failed >"${S}/active-state"
run set_imitation quic
assert_rc 0 "${RC}" "  and so is a fixed protocol"

rollback_case() { # <label> <restart rc lines> <verify rc lines>
	make_install boringtun dns example.com
	chmod 400 "${AMNEZIAWG_DIR}/params"
	printf '%s\n' $2 >"${S}/restart-rc"
	printf '%s\n' $3 >"${S}/verify-rc"
	BEFORE="$(snapshot)"
	run set_imitation auto
	assert_rc 1 "${RC}" "$1: the change to auto fails"
	assert_eq "${BEFORE}" "$(snapshot)" "$1: params and the runtime file are restored byte for byte, with their modes"
	assert_contains "was restored" "${ERR}" "$1: the restoration is reported"
	assert_eq "0" "$(transaction_dirs)" "$1: no transaction directory is left"
}
rollback_case "restart fails" "1 0" "0"
assert_eq "verify dns|example.com" "$(grep '^verify' "${S}/log")" "restart fails: the previous imitation is restarted and verified"
rollback_case "the restarted daemon does not run auto" "0" "1 0"
assert_eq "verify auto|
verify dns|example.com" "$(grep '^verify' "${S}/log")" "unverified: auto was checked, then the previous imitation"
make_install boringtun dns example.com
echo 1 >"${S}/validate-rc"
BEFORE="$(snapshot)"
run set_imitation auto
assert_rc 1 "${RC}" "a configuration the scratch instance refuses under auto is not applied"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"
assert_not_contains "restart" "$(cat "${S}/log")" "  nor restarted"

echo "=== Header protection ==="
make_install boringtun none "" 3 40 50 60 70
run checkBoringtunImitationProtocolCompat auto 3
assert_rc 0 "${RC}" "AWG 3.0 with S sizes over 30: auto is not refused, as sip would be"
run checkBoringtunImitationProtocolCompat sip 3
assert_rc 1 "${RC}" "  (while sip still is)"
run set_imitation auto
assert_rc 0 "${RC}" "  auto is applied there"
assert_contains "random" "${OUT}" "  and the warning says what a learned sip that header protection refuses leaves"
assert_contains "16 random bits" "${OUT}" "  and what a learned dns does to header protection"
assert_contains "32 random bits" "${OUT}" "  and a learned stun"

echo "=== Warnings ==="
warnings() { # <AWG version>
	SERVER_PORT=51820
	SERVER_AWG_S1=150 SERVER_AWG_S2=150 SERVER_AWG_S3=150 SERVER_AWG_S4=150
	printBoringtunImitationWarnings auto "" "$1"
}
run warnings 2
assert_contains "Protocol imitation: auto" "${OUT}" "the warnings name auto"
assert_contains "per authenticated peer" "${OUT}" "  selection is per authenticated peer"
assert_contains "recognizable" "${OUT}" "  and needs recognizable client traffic"
assert_contains "does not detect" "${OUT}" "  and auto does not detect the client's S1-S4 or H1-H4"
assert_contains "random S padding" "${OUT}" "  an unresolved peer gets random padding"
assert_contains "best effort" "${OUT}" "  auto is best effort"
assert_contains "also fits this server's AmneziaWG S/H framing is taken for AmneziaWG traffic" "${OUT}" \
	"  a datagram that arrives but fits the configured S/H framing is no hint"
assert_contains "A working tunnel, and auto configured and running, do not show that any peer is imitated" "${OUT}" \
	"  neither a working tunnel nor a running auto shows successful imitation"
assert_not_contains "%" "${OUT}" "  no per-datagram share is offered as a chance of anything"
assert_not_contains "guarantee" "${OUT}" "  nothing is said to guarantee learning"
# The README's auto section as one line, so that a phrase may wrap.
README_AUTO="$(sed -n '/^\*\*`auto` (opt-in)\.\*\*/,/^A change is one transaction/p' "${PROJECT_ROOT}/README.md" | tr -s ' \r\n' ' ')"
assert_contains "best effort" "${README_AUTO}" "README: auto is best effort"
assert_contains "fits this server's AmneziaWG S/H framing" "${README_AUTO}" \
	"README: a delivered datagram that fits the configured S/H framing is no hint"
assert_contains "do not show that any peer is imitated" "${README_AUTO}" \
	"README: neither a working tunnel nor a running auto shows successful imitation"
assert_not_contains "16 random bits" "${OUT}" "  AWG 2.0 has no header-protection warning"
run warnings 3.1
assert_contains "header protection" "${OUT}" "AWG 3.1: the header-protection trade-offs are stated"

echo "=== Launcher and scratch instances ==="
make_install boringtun auto
select_current legacy
launch() {
	_awgBtPrepareRunDir() {
		echo "prepare-run-dir" >>"${S}/log"
		return 1
	}
	awgBoringtunLaunchMain awg0
}
run launch
assert_rc 1 "${RC}" "the launcher refuses auto on a binary without it"
assert_contains "does not support protocol imitation auto" "${ERR}" "  the launcher says that the binary lacks auto"
assert_contains "--upgrade-boringtun" "${ERR}" "  and what to run"
assert_eq "exec legacy --imitate-protocol auto --version" "$(cat "${S}/exec")" "  the binary was asked, never started as a daemon"
assert_not_contains "prepare-run-dir" "$(cat "${S}/log")" "  before any runtime state is prepared"
select_current auto
run launch
assert_contains "prepare-run-dir" "$(cat "${S}/log")" "an auto-capable binary passes the check and the launch continues"
HELPER="$(_awgBtRenderHelper launch)"
assert_contains "_awgBtBinaryImitationSupport ()" "${HELPER}" "the generated launcher carries the check"
assert_contains "readonly AWG_BT_PROBE_TIMEOUT=" "${HELPER}" "  and its embedded timeout"

scratch() {
	_awgBtPrepareScratchDir() { return 0; }
	_awgBtScratchSweep() { return 0; }
	_awgBtDaemonArgv() {
		echo "argv $*" >>"${S}/log"
		return 1
	}
	AWG_BORINGTUN_IMITATE_PROTOCOL=auto
	AWG_BORINGTUN_IMITATE_DOMAIN=""
	_AWG_BT_CANDIDATE_RELEASE="${1:-}"
	_awgBtScratchCreate awgs0
}
make_install boringtun auto
select_current legacy
run scratch
assert_rc 1 "${RC}" "a scratch instance of a binary without auto is refused under auto"
assert_contains "does not support protocol imitation auto" "${ERR}" "  the scratch refusal says that the binary lacks auto"
assert_not_contains "argv" "$(cat "${S}/log")" "  before any daemon command line exists"
select_current auto
run scratch
assert_contains "argv ${AWG_BT_STORE_DIR}/${AUTO_ID}/boringtun-cli awgs0 auto " "$(cat "${S}/log")" "an auto-capable binary gets its scratch command line"
: >"${S}/log"
run scratch "${LEGACY_ID}"
assert_rc 1 "${RC}" "a candidate release without auto is refused under auto, even while current has it"
assert_not_contains "argv" "$(cat "${S}/log")" "  before any daemon command line exists"

echo "=== Fresh install preflight ==="
preflight() {
	_awgBtCheckKernelModule() { return 0; }
	_awgBtCheckPlatform() { return 0; }
	_awgBtCheckHelpers() { return 0; }
	_awgBtCheckBaseUnit() { return 0; }
	awgBackendCreateScratchInterface() {
		echo "scratch" >>"${S}/log"
		return 1
	}
	AWG_BORINGTUN_IMITATE_PROTOCOL=auto
	AWG_BORINGTUN_IMITATE_DOMAIN=""
	boringtunHostPreflight
}
make_install boringtun
select_current legacy
run preflight
assert_rc 1 "${RC}" "a fresh install with auto refuses a binary without it in the preflight"
assert_contains "does not support protocol imitation auto" "${ERR}" "  the preflight says that the binary lacks auto"
assert_contains "No VPN configuration was written" "${ERR}" "  before any VPN state is written"
assert_not_contains "scratch" "$(cat "${S}/log")" "  before any scratch instance"

echo "=== --backend-status ==="
status() {
	printBackendStatus
}
make_install boringtun auto
echo inactive >"${S}/active-state"
run status
assert_rc 0 "${RC}" "an auto installation reports status 0"
assert_contains $'imitation_protocol=auto\nimitation_domain=\nimitation_domain_mode=none' "${OUT}" "  auto is configured, without a hostname"
assert_contains "imitation_auto_support=supported" "${OUT}" "  the installed binary supports auto"
assert_not_contains "learned" "${OUT}" "  no per-peer learned state is reported, as the daemon exposes none"
bash -c 'sleep 60; :' boringtun-cli --foreground --imitate-protocol auto awg0 &
BACKGROUND+=("$!")
echo "$!" >"${S}/daemon-pid"
echo active >"${S}/active-state"
run status
assert_contains $'daemon_state=running' "${OUT}" "active: the verified daemon runs"
assert_contains $'daemon_imitation_protocol=auto\ndaemon_imitation_domain=' "${OUT}" "  and runs auto, from its command line"
select_current legacy
run status
assert_contains "imitation_auto_support=unsupported" "${OUT}" "a binary without auto is reported as such"
make_install boringtun
rm -f -- "${AWG_BT_STORE_DIR}/current"
run status
assert_contains "imitation_auto_support=unknown" "${OUT}" "without a verified store the support is unknown"

echo "=== Menu and usage ==="
interactive() {
	setBoringtunImitation() { echo "set $*"; }
	AWG_BACKEND=boringtun
	AWG_PROTOCOL_VERSION="$1"
	AWG_BORINGTUN_IMITATE_PROTOCOL="${2:-none}"
	AWG_BORINGTUN_IMITATE_DOMAIN=""
	SERVER_AWG_S1=40 SERVER_AWG_S2=50 SERVER_AWG_S3=60 SERVER_AWG_S4=70
	changeBoringtunImitationInteractively
}
RUN_INPUT=$'6\n1' run interactive 2
assert_contains "6) auto" "${OUT}" "the change menu lists auto"
assert_eq "set auto  1" "$(tail -n 1 <<<"${OUT}")" "AWG 2.0: 6 selects auto, asks no hostname and runs the transaction"
RUN_INPUT=$'6\n1\nn' run interactive 3
assert_contains "Protocol imitation change cancelled." "${OUT}" "AWG 3.0: enabling auto asks first, and N cancels"
RUN_INPUT=$'6\ny\n1' run interactive 3
assert_eq "set auto  1" "$(tail -n 1 <<<"${OUT}")" "AWG 3.0 with S sizes over 30: auto is not refused, and y enables it"
RUN_INPUT=$'6\n1' run interactive 2 auto
assert_contains "unchanged" "${OUT}" "with auto current, choosing it again changes nothing"
run bash "${INSTALLER}" --set-boringtun-imitation
assert_contains "Usage: amneziawg-install.sh --set-boringtun-imitation <none|dns|quic|sip|stun|auto> [hostname]" "${ERR}" "the usage lists auto"

echo
echo "BoringTun auto imitation tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
