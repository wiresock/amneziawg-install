#!/usr/bin/env bash
# shellcheck disable=SC2034 # the suite sets globals that the sourced installer reads

# Unit tests for BoringTun protocol imitation in amneziawg-install.sh: the
# hostname and protocol validators, the params boundary (persisted keys, the
# environment that never overrides them, kernel params that must not carry
# them), fresh-install selection, the runtime file and the daemon's command
# line, the trade-off warnings and the S-size advisory, the SIP refusal under
# AWG 3.x, the --set-boringtun-imitation transaction with its rollback,
# --backend-status, and the management menus. Nothing here needs root, the
# network or systemd: every path is anchored below a test root, and mocks and
# function stubs stand in for systemctl, the scratch validation and the
# verification of a running daemon.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"

# Every path the suite touches is redirected below its private test root, and
# still it refuses root outside a disposable host, before anything is sourced.
if [[ "${EUID}" -eq 0 && "${AWG_DISPOSABLE_HOST_TEST:-}" != 1 ]]; then
	echo "ERROR: run the BoringTun imitation tests as an unprivileged user; as root they run only on a disposable host with AWG_DISPOSABLE_HOST_TEST=1" >&2
	exit 2
fi

# shellcheck source=../amneziawg-install.sh
source "${INSTALLER}"

T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-imitation-tests.XXXXXX")"
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
# repeating); restart sends TERM to its caller once when <state>/restart-term
# exists; everything is logged.
cat >"${MOCKBIN}/systemctl" <<EOF
#!/bin/bash
echo "systemctl \$*" >>'${S}/log'
case "\$1" in
	show)
		[[ "\$*" == *ActiveState* ]] || exit 1
		[[ -f '${S}/show-fails' ]] && exit 1
		cat '${S}/active-state' 2>/dev/null
		exit 0
		;;
	is-active)
		[[ "\$(cat '${S}/active-state' 2>/dev/null)" == active ]]
		exit
		;;
	restart)
		if [[ -f '${S}/restart-term' ]]; then
			rm -f '${S}/restart-term'
			kill -TERM "\${PPID}"
		fi
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
# helpers, as the real one does after verifying the store), the proof that the
# active unit is the recorded BoringTun instance, the scratch validation and
# the verification of a restarted daemon. Each is logged.
acquireClientLifecycleLock() {
	echo "lock" >>"${S}/log"
}
_awgBtEnsureReady() {
	echo "ensure-ready $* runtime=[$(grep -v '^#' "$(_awgBtRuntimeFilePath "${SERVER_AWG_NIC}")" 2>/dev/null | tr '\n' ' ')]" >>"${S}/log"
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

# ── Fixture installation ─────────────────────────────────────────────────────
MOCK_KEY="bW9ja2tleW1vY2trZXltb2NrZXltb2Nra2V5bW9ja2s="
CLIENT_CONF="${AMNEZIAWG_DIR}/clients/awg0-client-alice.conf"
RUNTIME_FILE="${AMNEZIAWG_DIR}/awg0.boringtun"

# make_install <backend> [protocol] [domain] [AWG version] [S1 S2 S3 S4]:
# params, server and client configs and, for BoringTun, the runtime file, as
# an installation of that state leaves them, and a clean log.
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
	serializeParams "${AMNEZIAWG_DIR}/params" || return 1
	chmod 600 "${AMNEZIAWG_DIR}/params"
	if [[ "$1" == boringtun ]]; then
		_awgBtRenderRuntimeFile >"${RUNTIME_FILE}" || return 1
		chmod 600 "${RUNTIME_FILE}"
	fi
	echo active >"${S}/active-state"
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

echo "=== Protocols and hostnames ==="
for PROTOCOL in none dns quic sip stun; do
	assert_true "${PROTOCOL} is an imitation protocol" _awgBtImitationProtocolValid "${PROTOCOL}"
done
for PROTOCOL in "" NONE DNS http tls "dns " " dns" "dns,quic" wireguard; do
	if _awgBtImitationProtocolValid "${PROTOCOL}"; then
		not_ok "'${PROTOCOL}' is not an imitation protocol"
	else
		ok "'${PROTOCOL}' is not an imitation protocol"
	fi
done
for PROTOCOL in dns quic sip; do
	assert_true "${PROTOCOL} carries a hostname" _awgBtImitationUsesDomain "${PROTOCOL}"
done
for PROTOCOL in none stun; do
	if _awgBtImitationUsesDomain "${PROTOCOL}"; then not_ok "${PROTOCOL} carries no hostname"; else ok "${PROTOCOL} carries no hostname"; fi
done
LABEL63="$(printf 'a%.0s' {1..63})"
LABEL64="${LABEL63}a"
# 253 characters: four labels of 63 and one of 1, joined by dots.
NAME253="${LABEL63}.${LABEL63}.${LABEL63}.${LABEL63:0:61}"
for DOMAIN in example.com a a.b xn--80ak6aa92e.com 1.2.3.4 a-b.c--d.example EXAMPLE.Com "${LABEL63}.com" "${NAME253}"; do
	assert_true "'${DOMAIN:0:40}' (${#DOMAIN}) is a valid hostname" _awgBtImitationDomainValid "${DOMAIN}"
done
for DOMAIN in "" . .example example. -a.com a-.com a..b "a b.com" a_b.com "a/b" "a:b" 'a$b' \
	$'a\nb' $'a\tb' "exämple.com" "${LABEL64}.com" "${NAME253}a" "a.-b" "a.b-" "*.example.com" "a;b"; do
	if _awgBtImitationDomainValid "${DOMAIN}"; then
		not_ok "$(printf '%q' "${DOMAIN:0:40}") is not a valid hostname"
	else
		ok "$(printf '%q' "${DOMAIN:0:40}") is not a valid hostname"
	fi
done
run _awgBtImitationCheck stun example.com
assert_rc 1 "${RC}" "a hostname with stun is refused"
assert_contains "used only by dns, quic and sip, not by stun" "${ERR}" "and the refusal says which protocols take one"
run _awgBtImitationCheck none example.com
assert_rc 1 "${RC}" "a hostname with none is refused"
run _awgBtImitationCheck quic "a b"
assert_rc 1 "${RC}" "quic takes only LDH hostnames here, although the binary accepts any printable SNI"
assert_contains "invalid imitation hostname" "${ERR}" "and the hostname rule is explained"
run _awgBtImitationCheck ssh ""
assert_rc 1 "${RC}" "an unknown protocol is refused"
assert_contains "supported: none, dns, quic, sip, stun" "${ERR}" "and the supported protocols are listed"
run _awgBtImitationCheck $'dns\e[31m' ""
assert_not_contains $'\e' "${ERR}" "control characters are quoted, never echoed raw"
for PAIR in "none|" "dns|" "dns|example.com" "quic|cdn.example.org" "sip|pbx.example" "stun|"; do
	assert_true "'${PAIR}' is a valid imitation" _awgBtImitationCheck "${PAIR%%|*}" "${PAIR#*|}"
done

echo "=== Params ==="
make_install kernel
assert_eq "0" "$(grep -c AWG_BORINGTUN_ "${AMNEZIAWG_DIR}/params")" "kernel params carry no imitation keys"
assert_eq "AWG_DISABLE_COOKIES=''" "$(tail -n 1 "${AMNEZIAWG_DIR}/params")" "and end where they always ended"
make_install boringtun
assert_eq "AWG_BORINGTUN_IMITATE_PROTOCOL='none'
AWG_BORINGTUN_IMITATE_DOMAIN=''" "$(tail -n 2 "${AMNEZIAWG_DIR}/params")" "BoringTun params persist imitation none"
make_install boringtun dns example.com
assert_eq "dns example.com" "$(params_value AWG_BORINGTUN_IMITATE_PROTOCOL) $(params_value AWG_BORINGTUN_IMITATE_DOMAIN)" \
	"and a dns imitation with its hostname"
AWG_BACKEND=kernel AWG_BORINGTUN_IMITATE_PROTOCOL=dns AWG_BORINGTUN_IMITATE_DOMAIN="" run serializeParams "${T}/params.out"
assert_rc 1 "${RC}" "kernel params with an imitation are never written"
AWG_BACKEND=boringtun AWG_BORINGTUN_IMITATE_PROTOCOL=stun AWG_BORINGTUN_IMITATE_DOMAIN=example.com run serializeParams "${T}/params.out"
assert_rc 1 "${RC}" "nor BoringTun params with an invalid imitation"

load_params() {
	loadParams 0 1 >/dev/null
	printf '%s|%s|%s' "${AWG_BACKEND}" "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}"
}
make_install boringtun quic cdn.example.org
AWG_BORINGTUN_IMITATE_PROTOCOL=sip AWG_BORINGTUN_IMITATE_DOMAIN=evil.example run load_params
assert_eq "boringtun|quic|cdn.example.org" "${OUT}" "params decide the imitation; the environment never overrides it"
make_install boringtun
sed -i '/^AWG_BORINGTUN_/d' "${AMNEZIAWG_DIR}/params"
export AWG_BORINGTUN_IMITATE_PROTOCOL=dns AWG_BORINGTUN_IMITATE_DOMAIN=example.com
run load_params
export -n AWG_BORINGTUN_IMITATE_PROTOCOL AWG_BORINGTUN_IMITATE_DOMAIN
assert_eq "boringtun|none|" "${OUT}" "params written before imitation existed mean none, even with exported variables"
make_install kernel
export AWG_BORINGTUN_IMITATE_PROTOCOL=dns
run load_params
export -n AWG_BORINGTUN_IMITATE_PROTOCOL
assert_eq "kernel|none|" "${OUT}" "a kernel installation loads with imitation none, whatever the environment says"
params_case() { # <label> <sed expression or append:line> <expected rc> [stderr fragment]
	make_install "${BACKEND_UNDER_TEST}"
	if [[ "$2" == append:* ]]; then
		printf '%s\n' "${2#append:}" >>"${AMNEZIAWG_DIR}/params"
	else
		sed -i "$2" "${AMNEZIAWG_DIR}/params"
	fi
	run load_params
	assert_rc "$3" "${RC}" "$1"
	[[ -z "${4:-}" ]] || assert_contains "$4" "${ERR}" "  and the error says why"
}
BACKEND_UNDER_TEST=kernel
params_case "kernel params that carry a dns imitation are damaged" "append:AWG_BORINGTUN_IMITATE_PROTOCOL='dns'" 1 "only with the BoringTun backend"
params_case "kernel params that carry an imitation hostname are damaged" "append:AWG_BORINGTUN_IMITATE_DOMAIN='example.com'" 1 "only with the BoringTun backend"
params_case "kernel params that say imitation none load" "append:AWG_BORINGTUN_IMITATE_PROTOCOL='none'" 0
BACKEND_UNDER_TEST=boringtun
params_case "an unsupported persisted protocol is refused" "s/^AWG_BORINGTUN_IMITATE_PROTOCOL=.*/AWG_BORINGTUN_IMITATE_PROTOCOL='DNS'/" 1 "unsupported BoringTun imitation protocol"
params_case "an empty persisted protocol is refused" "s/^AWG_BORINGTUN_IMITATE_PROTOCOL=.*/AWG_BORINGTUN_IMITATE_PROTOCOL=''/" 1 "Invalid AWG backend state"
params_case "a persisted hostname with stun is refused" "s/^AWG_BORINGTUN_IMITATE_PROTOCOL=.*/AWG_BORINGTUN_IMITATE_PROTOCOL='stun'/; s/^AWG_BORINGTUN_IMITATE_DOMAIN=.*/AWG_BORINGTUN_IMITATE_DOMAIN='a.example'/" 1 "not by stun"
params_case "an invalid persisted hostname is refused" "s/^AWG_BORINGTUN_IMITATE_PROTOCOL=.*/AWG_BORINGTUN_IMITATE_PROTOCOL='dns'/; s/^AWG_BORINGTUN_IMITATE_DOMAIN=.*/AWG_BORINGTUN_IMITATE_DOMAIN='a_b.example'/" 1 "invalid imitation hostname"

echo "=== Fresh-install selection ==="
select_fresh() { # <backend> <protocol request> <domain request>
	AWG_BACKEND="$1"
	_AWG_BT_IMITATE_PROTOCOL_REQUESTED="$2"
	_AWG_BT_IMITATE_DOMAIN_REQUESTED="$3"
	selectFreshInstallImitation || return 1
	printf '%s|%s' "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}"
}
run select_fresh boringtun "" ""
assert_eq "0 none|" "${RC} ${OUT}" "a BoringTun install without a request imitates none"
run select_fresh boringtun dns example.com
assert_eq "0 dns|example.com" "${RC} ${OUT}" "a BoringTun install takes the requested protocol and hostname"
run select_fresh boringtun stun ""
assert_eq "0 stun|" "${RC} ${OUT}" "stun without a hostname"
for BAD in "boringtun|http|" "boringtun|none|example.com" "boringtun|stun|example.com" "boringtun|dns|bad_name" "boringtun||example.com"; do
	IFS='|' read -r B P D <<<"${BAD}"
	run select_fresh "${B}" "${P}" "${D}"
	assert_rc 1 "${RC}" "a fresh install refuses AWG_BACKEND=${B} with protocol '${P}' and hostname '${D}'"
done
run select_fresh kernel "" ""
assert_eq "0 none|" "${RC} ${OUT}" "a kernel install without a request is unchanged"
run select_fresh kernel none ""
assert_eq "0 none|" "${RC} ${OUT}" "and explicit none is harmless there"
run select_fresh kernel dns ""
assert_rc 1 "${RC}" "a kernel install refuses a dns imitation"
assert_contains "only with the BoringTun backend" "${ERR}" "and says it needs BoringTun"
run select_fresh kernel "" example.com
assert_rc 1 "${RC}" "a kernel install refuses an imitation hostname"
run bash -c 'AWG_BORINGTUN_IMITATE_PROTOCOL=quic AWG_BORINGTUN_IMITATE_DOMAIN=a.example source "$1"; AWG_BORINGTUN_IMITATE_PROTOCOL=sip; AWG_BORINGTUN_IMITATE_DOMAIN=b.example; AWG_BACKEND=boringtun; selectFreshInstallImitation && printf "%s|%s" "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}"' _ "${INSTALLER}"
assert_eq "quic|a.example" "${OUT}" "the request is the one the installer was started with, not a later assignment"

# A kernel install with an imitation request stops before it changes anything.
fresh_kernel_install() {
	ensureSupportedInstallDistro() { :; }
	installQuestions() { echo "installQuestions" >>"${S}/log"; }
	enable_apt_ipv4() { echo "enable_apt_ipv4" >>"${S}/log"; }
	installBoringtunHost() { echo "installBoringtunHost" >>"${S}/log"; }
	_AWG_BACKEND_REQUESTED="$1"
	_AWG_BT_IMITATE_PROTOCOL_REQUESTED="$2"
	_AWG_BT_IMITATE_DOMAIN_REQUESTED="$3"
	installAmneziaWG
}
: >"${S}/log"
run fresh_kernel_install "" sip ""
assert_rc 1 "${RC}" "a kernel install with AWG_BORINGTUN_IMITATE_PROTOCOL=sip fails"
assert_eq "" "$(cat "${S}/log")" "before any question or package step"
run fresh_kernel_install kernel "" pbx.example
assert_rc 1 "${RC}" "and one with only a hostname too"

ask() { # <requested protocol> <requested domain>
	AWG_BORINGTUN_IMITATE_PROTOCOL="$1"
	AWG_BORINGTUN_IMITATE_DOMAIN="$2"
	askBoringtunImitation >/dev/null
	printf '%s|%s' "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${AWG_BORINGTUN_IMITATE_DOMAIN}"
}
RUN_INPUT=$'1' run ask none ""
assert_eq "none|" "${OUT}" "the interactive question: 1 is none"
RUN_INPUT=$'2\nexample.com' run ask none ""
assert_eq "dns|example.com" "${OUT}" "2 is dns, followed by an optional hostname"
RUN_INPUT=$'3\n' run ask none ""
assert_eq "quic|" "${OUT}" "an empty hostname leaves it to BoringTun"
RUN_INPUT=$'4\nbad name\n-x.example\npbx.example' run ask none ""
assert_eq "sip|pbx.example" "${OUT}" "invalid hostnames are asked again"
RUN_INPUT=$'9\nx\n5' run ask none ""
assert_eq "stun|" "${OUT}" "an out-of-range answer is asked again, and stun asks no hostname"
RUN_INPUT=$'5' run ask dns example.com
assert_eq "stun|" "${OUT}" "a requested hostname is dropped with a protocol that takes none"
RUN_INPUT=$'1' run bash -c 'source "$1"; askBoringtunImitation' _ "${INSTALLER}"
assert_contains "1) none (default)" "${OUT}" "the question offers none as the default"
assert_contains "5) stun" "${OUT}" "and lists all five protocols"

echo "=== Runtime file and command line ==="
render_runtime() {
	AWG_BORINGTUN_IMITATE_PROTOCOL="$1"
	AWG_BORINGTUN_IMITATE_DOMAIN="$2"
	_awgBtRenderRuntimeFile
}
run render_runtime none ""
assert_eq "# Managed by amneziawg-install (backend: boringtun). Regenerated from params.
FORMAT=1" "${OUT}" "imitation none renders the earlier installer's runtime file byte for byte"
run render_runtime dns example.com
assert_eq "# Managed by amneziawg-install (backend: boringtun). Regenerated from params.
FORMAT=1
IMITATE_PROTOCOL=dns
IMITATE_DOMAIN=example.com" "${OUT}" "a dns imitation adds its protocol and hostname"
run render_runtime quic ""
assert_eq "IMITATE_PROTOCOL=quic" "$(tail -n 1 <<<"${OUT}")" "a hostname left to BoringTun is not rendered"
run render_runtime stun a.example
assert_rc 1 "${RC}" "an invalid imitation is never rendered"

read_back() { # <protocol> <domain>
	render_runtime "$1" "$2" >"${RUNTIME_FILE}" || return 1
	chmod 600 "${RUNTIME_FILE}"
	_awgBtReadRuntimeFile awg0 || return 1
	printf '%s|%s' "${_AWG_BT_IMITATE_PROTOCOL}" "${_AWG_BT_IMITATE_DOMAIN}"
}
make_install boringtun
for PAIR in "none|" "dns|example.com" "quic|" "sip|pbx.example" "stun|"; do
	run read_back "${PAIR%%|*}" "${PAIR#*|}"
	assert_eq "${PAIR}" "${OUT}" "the launcher's parser reads back '${PAIR}'"
done

argv_of() { # <protocol> [<domain>]
	_awgBtDaemonArgv /store/boringtun-cli awg0 "$@" || return 1
	printf '%s\n' "${_AWG_BT_ARGV[@]}"
}
ENV_BIN="$(command -v env)"
run argv_of none
assert_eq "${ENV_BIN}
-i
PATH=${AWG_BT_PATH}
NO_COLOR=1
/store/boringtun-cli
--foreground
--disable-drop-privileges
--verbosity
error
--imitate-protocol
none
awg0" "${OUT}" "the daemon's command line always names the imitation, none included"
run argv_of dns example.com
assert_eq "--imitate-protocol dns --imitate-domain example.com awg0" "$(tail -n 5 <<<"${OUT}" | tr '\n' ' ' | sed 's/ $//')" \
	"dns with a hostname adds --imitate-domain, the interface last"
run argv_of sip
assert_eq "--imitate-protocol sip awg0" "$(tail -n 3 <<<"${OUT}" | tr '\n' ' ' | sed 's/ $//')" "sip without a hostname"
run bash -c 'source "$1"; _awgBtDaemonArgv /b awg0 && printf "%s " "${_AWG_BT_ARGV[@]}"' _ "${INSTALLER}"
assert_contains "--imitate-protocol none awg0" "${OUT}" "a caller that names no imitation gets none"
assert_not_contains "--probe-reply-rate" "$(declare -f _awgBtDaemonArgv)" "--probe-reply-rate is never passed, so BoringTun's default budget applies"
run argv_of none example.com
assert_rc 1 "${RC}" "an invalid pair never becomes a command line"
run argv_of NONE
assert_rc 1 "${RC}" "nor an unknown protocol"

# The scratch instance of staged validation runs the persisted imitation.
scratch_argv() {
	_awgBtVerifyStore() { _AWG_BT_VERIFIED_BIN=/store/boringtun-cli; }
	_awgBtDaemonArgv() {
		echo "argv $*" >>"${S}/log"
		return 1
	}
	AWG_BORINGTUN_IMITATE_PROTOCOL=dns
	AWG_BORINGTUN_IMITATE_DOMAIN=example.com
	_awgBtScratchCreate awgs0
}
: >"${S}/log"
run scratch_argv
assert_eq "argv /store/boringtun-cli awgs0 dns example.com" "$(grep '^argv' "${S}/log")" \
	"a scratch BoringTun instance runs the persisted imitation, so staged validation checks it"

HELPER="$(_awgBtRenderHelper launch)"
assert_contains "_AWG_BT_IMITATE_PROTOCOL=none" "${HELPER}" "the launcher starts from imitation none"
for FUNCTION in _awgBtImitationProtocolValid _awgBtImitationUsesDomain _awgBtImitationDomainValid _awgBtImitationCheck; do
	assert_contains "${FUNCTION} ()" "${HELPER}" "the launcher carries ${FUNCTION}"
done
assert_contains '"${_AWG_BT_IMITATE_PROTOCOL}" "${_AWG_BT_IMITATE_DOMAIN}"' "$(declare -f awgBoringtunLaunchMain)" \
	"the launcher passes the runtime file's imitation to the daemon"

echo "=== Warnings ==="
warnings() { # <protocol> <domain> <version> [S1 S2 S3 S4]
	SERVER_PORT=51820
	SERVER_AWG_S1="${4:-150}" SERVER_AWG_S2="${5:-150}" SERVER_AWG_S3="${6:-150}" SERVER_AWG_S4="${7:-150}"
	printBoringtunImitationWarnings "$1" "$2" "$3"
}
run warnings none "" 3
assert_eq "" "${OUT}" "imitation none has no trade-offs to print"
run warnings dns example.com 2
assert_contains "Server side only" "${OUT}" "dns: shaping is server-side only"
assert_contains "client configs do not change" "${OUT}" "  and client configs do not change"
assert_contains "SERVFAIL" "${OUT}" "  DNS probes get SERVFAIL"
assert_contains "16 KiB/s" "${OUT}" "  replies share the aggregate budget"
assert_contains "loopback, link-local, multicast and broadcast sources are never answered" "${OUT}" "  and some sources are never answered"
assert_contains "listen port stays 51820" "${OUT}" "  the port is never moved"
assert_not_contains "header protection" "${OUT}" "  AWG 2.0 has no header-protection warning"
assert_not_contains "Note:" "${OUT}" "  S prefixes of 150 bytes need no advisory"
run warnings stun "" 2
assert_contains "Binding Success about 2.6 times" "${OUT}" "stun: the reply amplification is stated"
run warnings quic "" 2
assert_contains "1200 bytes or more with Version Negotiation when they offer a version that real servers do not (QUIC v1 and v2 get no reply)" "${OUT}" "quic: Version Negotiation for full-size Initials of versions real servers do not offer"
run warnings sip "" 2
assert_contains "no SIP responder" "${OUT}" "sip: no probe replies"
run warnings dns "" 3
assert_contains "AmneziaWG 3.0: header protection takes its nonce" "${OUT}" "AWG 3.0: the header-protection trade-off is stated"
assert_contains "16 random bits" "${OUT}" "  dns leaves a 16-bit nonce"
assert_contains "Payload encryption is unaffected" "${OUT}" "  and confidentiality is unaffected"
run warnings stun "" 3.1
assert_contains "AmneziaWG 3.1" "${OUT}" "AWG 3.1 gets the same warning"
assert_contains "77,000 datagrams" "${OUT}" "  stun leaves a 32-bit nonce"
run warnings quic "" 3
assert_contains "keeps its strength" "${OUT}" "  quic leaves the nonce random"
# The S-size advisory: dns 32 (hostname length + 33), stun 20, sip 31, quic 1.
run warnings dns "" 2 31 32 150 150
assert_contains "Note: S1=31 is below the 32 bytes dns imitation needs" "${OUT}" "dns: an S of 31 is flagged, 32 is not"
assert_not_contains "S2=32" "${OUT}" "  (32 is enough)"
run warnings dns example.com 2 32 43 44 150
assert_contains "Note: S1=32, S2=43 are below the 44 bytes a DNS query for example.com needs" "${OUT}" \
	"dns with a hostname: below its length + 33 the prefix carries a root query"
assert_not_contains "S3=44" "${OUT}" "  (44 is enough for example.com)"
run warnings stun "" 2 19 20 150 150
assert_contains "Note: S1=19 is below the 20 bytes stun imitation needs" "${OUT}" "stun: 19 is flagged, 20 is not"
run warnings sip "" 2 15 30 31 150
assert_contains "Note: S1=15, S2=30 are below the 31 bytes sip imitation needs" "${OUT}" "sip: below 31 is flagged"
run warnings quic "" 2 1 15 15 15
assert_not_contains "Note:" "${OUT}" "quic needs only the first byte"
assert_rc 0 "${RC}" "the advisory never refuses"

echo "=== SIP under AWG 3.x ==="
compat() { # <protocol> <version> <S1 S2 S3 S4>
	SERVER_AWG_S1="$3" SERVER_AWG_S2="$4" SERVER_AWG_S3="$5" SERVER_AWG_S4="$6"
	checkBoringtunImitationProtocolCompat "$1" "$2"
}
run compat sip 3 20 30 31 20
assert_rc 1 "${RC}" "sip with AWG 3.0 and an S of 31 is refused, as the pinned BoringTun refuses it"
assert_contains "S1-S4 is 31 bytes or more" "${ERR}" "  and the S sizes are named"
run compat sip 3.1 150 15 15 15
assert_rc 1 "${RC}" "sip with AWG 3.1 and S1=150 is refused"
run compat sip 3 30 30 30 30
assert_rc 0 "${RC}" "sip with AWG 3.0 and every S at 30 or less is accepted"
run compat sip 2 150 150 150 150
assert_rc 0 "${RC}" "sip with AWG 2.0 is always accepted"
for PROTOCOL in none dns quic stun; do
	run compat "${PROTOCOL}" 3.1 150 150 150 150
	assert_rc 0 "${RC}" "${PROTOCOL} with AWG 3.1 is accepted"
done

# A protocol change keeps the imitation, refuses sip where BoringTun would,
# and states the AWG 3.x trade-off first.
protocol_mode() { # <backend> <protocol> <target mode>
	loadParams() {
		AWG_BACKEND="${MODE_BACKEND}"
		AWG_BORINGTUN_IMITATE_PROTOCOL="${MODE_PROTOCOL}"
		AWG_BORINGTUN_IMITATE_DOMAIN=""
		AWG_PROTOCOL_VERSION="${MODE_FROM:-2}"
		SERVER_AWG_S1=40 SERVER_AWG_S2=50 SERVER_AWG_S3=60 SERVER_AWG_S4=70
	}
	awg2StateNeedsLegacyMigration() { return 1; }
	ensureAwgBackendReady() { :; }
	awg() { echo "${MOCK_KEY}"; }
	probeAwg3Capability() { :; }
	applyAwgProtocolTransaction() { echo "transaction protocol=${AWG_PROTOCOL_VERSION} imitation=${AWG_BORINGTUN_IMITATE_PROTOCOL}" >>"${S}/log"; }
	MODE_BACKEND="$1" MODE_PROTOCOL="$2"
	setAwgProtocolMode "$3"
}
: >"${S}/log"
run protocol_mode boringtun sip 3
assert_rc 1 "${RC}" "--enable-awg3 under sip imitation with S sizes over 30 is refused"
assert_eq "lock" "$(cat "${S}/log")" "  before any transaction"
: >"${S}/log"
run protocol_mode boringtun dns 3
assert_rc 0 "${RC}" "--enable-awg3 under dns imitation proceeds"
assert_contains "16 random bits" "${OUT}" "  after stating the header-protection trade-off"
assert_contains "transaction protocol=3 imitation=dns" "$(cat "${S}/log")" "  and keeps the imitation"
: >"${S}/log"
MODE_FROM=3 run protocol_mode boringtun sip 2
assert_rc 0 "${RC}" "returning to AWG 2.0 under sip imitation is never refused"
: >"${S}/log"
run protocol_mode kernel none 3
assert_not_contains "imitation" "${OUT}${ERR}" "a kernel protocol change prints nothing about imitation"

echo "=== --set-boringtun-imitation ==="
set_imitation() {
	setBoringtunImitation "$@"
}
make_install boringtun
BEFORE="$(snapshot)"
for BAD in "http" "none example.com" "stun a.example" "dns bad_name" "DNS"; do
	# shellcheck disable=SC2086 # the cases are words
	run set_imitation ${BAD}
	assert_rc 1 "${RC}" "'${BAD}' is refused"
done
assert_eq "" "$(cat "${S}/log")" "invalid arguments are refused before the lock is taken"
assert_eq "${BEFORE}" "$(snapshot)" "and nothing changed"

make_install kernel
BEFORE="$(snapshot)"
run set_imitation dns
assert_rc 1 "${RC}" "a kernel installation has no imitation to change"
assert_contains "only with the BoringTun backend" "${ERR}" "  and says so"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"

make_install boringtun dns example.com
BEFORE="$(snapshot)"
run set_imitation dns example.com
assert_rc 0 "${RC}" "the current imitation is a no-op"
assert_contains "already dns (hostname example.com)" "${OUT}" "  reported as such"
assert_not_contains "ensure-ready" "$(cat "${S}/log")" "  without touching the runtime"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"

for STATE in activating deactivating reloading refreshing maintenance ""; do
	make_install boringtun
	echo "${STATE}" >"${S}/active-state"
	BEFORE="$(snapshot)"
	run set_imitation dns
	assert_rc 1 "${RC}" "a unit that is '${STATE:-unknown}' aborts the change"
	assert_eq "${BEFORE}" "$(snapshot)" "  before anything changed"
	assert_not_contains "ensure-ready" "$(cat "${S}/log")" "  or anything was prepared"
done
make_install boringtun
touch "${S}/show-fails"
run set_imitation dns
assert_rc 1 "${RC}" "an unreadable unit state aborts the change"

make_install boringtun none "" 3 40 50 60 70
BEFORE="$(snapshot)"
run set_imitation sip
assert_rc 1 "${RC}" "sip under AWG 3.0 with S sizes over 30 is refused"
assert_eq "${BEFORE}" "$(snapshot)" "  before anything changed"
assert_not_contains "ensure-ready" "$(cat "${S}/log")" "  or anything was prepared"
make_install boringtun none "" 3 20 25 30 30
run set_imitation sip
assert_rc 0 "${RC}" "sip under AWG 3.0 with every S at 30 or less is accepted"

for STATE in inactive failed; do
	make_install boringtun
	echo "${STATE}" >"${S}/active-state"
	CONF_BEFORE="$(snapshot | sed -n '3,4p')"
	run set_imitation dns example.com
	assert_rc 0 "${RC}" "${STATE}: the change is persisted"
	assert_eq "dns example.com" "$(params_value AWG_BORINGTUN_IMITATE_PROTOCOL) $(params_value AWG_BORINGTUN_IMITATE_DOMAIN)" "${STATE}: params hold the new imitation"
	assert_eq "FORMAT=1 IMITATE_PROTOCOL=dns IMITATE_DOMAIN=example.com " "$(grep -v '^#' "${RUNTIME_FILE}" | tr '\n' ' ')" "${STATE}: so does the runtime file"
	assert_eq "600 600" "$(/usr/bin/stat -c %a "${AMNEZIAWG_DIR}/params") $(/usr/bin/stat -c %a "${RUNTIME_FILE}")" "${STATE}: both keep mode 0600"
	assert_not_contains "systemctl restart" "$(cat "${S}/log")" "${STATE}: the unit is not started"
	assert_contains "was not started" "${OUT}" "${STATE}: and the operator is told when it applies"
	assert_eq "${CONF_BEFORE}" "$(snapshot | sed -n '3,4p')" "${STATE}: server and client configs are unchanged"
	assert_eq "0" "$(transaction_dirs)" "${STATE}: no transaction directory is left"
done

make_install boringtun
BEFORE="$(snapshot)"
run set_imitation quic cdn.example.org
assert_rc 0 "${RC}" "active: the change is applied"
LOG="$(cat "${S}/log")"
assert_eq "lock
systemctl show -p ActiveState --value awg-quick@awg0.service
ensure-ready 0 runtime=[FORMAT=1 ]
served awg0
validate awg0.conf protocol=quic domain=cdn.example.org
systemctl reset-failed awg-quick@awg0.service
systemctl restart awg-quick@awg0.service
verify quic|cdn.example.org" "${LOG}" \
	"active: lock, state, helpers before the runtime file changes, proof of the running instance, scratch validation of the new imitation, restart, verification"
assert_eq "FORMAT=1 IMITATE_PROTOCOL=quic IMITATE_DOMAIN=cdn.example.org " "$(grep -v '^#' "${RUNTIME_FILE}" | tr '\n' ' ')" "active: the runtime file holds the new imitation"
assert_contains "restarted with it" "${OUT}" "active: and the restart is reported"
assert_contains "Client configs are unchanged." "${OUT}" "  client configs are unchanged"
assert_eq "$(sed -n '3,4p' <<<"${BEFORE}")" "$(snapshot | sed -n '3,4p')" "  and they are"
assert_eq "0" "$(transaction_dirs)" "  no transaction directory is left"
run set_imitation none
assert_eq "# Managed by amneziawg-install (backend: boringtun). Regenerated from params.
FORMAT=1" "$(cat "${RUNTIME_FILE}")" "back to none, the runtime file is the earlier installer's again"
assert_eq "$(sed -n 1p <<<"${BEFORE}")" "$(snapshot | sed -n 1p)" "and params are byte for byte what they were"

make_install boringtun
chmod 400 "${AMNEZIAWG_DIR}/params"
run set_imitation stun
assert_rc 0 "${RC}" "params with mode 0400 are changed"
assert_eq "400" "$(/usr/bin/stat -c %a "${AMNEZIAWG_DIR}/params")" "  and keep mode 0400"

make_install boringtun
echo 1 >"${S}/served-rc"
BEFORE="$(snapshot)"
run set_imitation dns
assert_rc 1 "${RC}" "an active unit that is not the recorded BoringTun instance is left alone"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"

make_install boringtun
echo 1 >"${S}/validate-rc"
BEFORE="$(snapshot)"
run set_imitation sip pbx.example
assert_rc 1 "${RC}" "a configuration BoringTun refuses with the new imitation is not applied"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"
assert_not_contains "restart" "$(cat "${S}/log")" "  nor restarted"
assert_eq "0" "$(transaction_dirs)" "  no transaction directory is left"

rollback_case() { # <label> <restart rc lines> <verify rc lines> <expected rc> [params mode]
	make_install boringtun dns example.com
	[[ -z "${5:-}" ]] || chmod "$5" "${AMNEZIAWG_DIR}/params"
	printf '%s\n' $2 >"${S}/restart-rc"
	printf '%s\n' $3 >"${S}/verify-rc"
	BEFORE="$(snapshot)"
	run set_imitation stun
	assert_rc "$4" "${RC}" "$1: the change fails"
	assert_eq "${BEFORE}" "$(snapshot)" "$1: params and the runtime file are restored byte for byte, with their modes"
}
rollback_case "restart fails" "1 0" "0" 1 400
assert_eq "verify dns|example.com" "$(grep '^verify' "${S}/log")" "restart fails: the previous imitation is restarted and verified"
assert_eq "2" "$(grep -c 'systemctl restart' "${S}/log")" "  (a second restart)"
assert_contains "was restored" "${ERR}" "  and the rollback is reported"
assert_eq "0" "$(transaction_dirs)" "  no transaction directory is left"
rollback_case "the restarted daemon is not verified" "0" "1 0" 1
assert_eq "verify stun|
verify dns|example.com" "$(grep '^verify' "${S}/log")" "unverified: the new daemon was checked, then the previous one"
rollback_case "the rollback restart fails too" "1" "0" 1
assert_contains "did not come back on protocol imitation stun" "${ERR}" "both failures are reported: the change"
assert_contains "could not be restarted on the previous protocol imitation dns" "${ERR}" "  and the rollback's restart"
assert_contains "recovery files remain in" "${ERR}" "  with where the recovery files are"
assert_eq "1" "$(transaction_dirs)" "  which are kept"
assert_true "  and hold the backups" test -f "$(compgen -G "${AMNEZIAWG_DIR}/.awg-imitation.*")/params.backup"

make_install boringtun dns example.com
rm -f "${RUNTIME_FILE}"
echo 1 >"${S}/restart-rc"
run set_imitation quic
assert_rc 1 "${RC}" "a runtime file that did not exist before"
assert_true "  does not exist after the rollback either" test ! -e "${RUNTIME_FILE}"

make_install boringtun dns example.com
chmod 400 "${AMNEZIAWG_DIR}/params"
touch "${S}/restart-term"
BEFORE="$(snapshot)"
run set_imitation sip
assert_rc 143 "${RC}" "TERM during the restart ends the change"
assert_eq "${BEFORE}" "$(snapshot)" "  after restoring both files exactly"
assert_eq "verify dns|example.com" "$(grep '^verify' "${S}/log")" "  and the previous imitation is running again"
assert_contains "interrupted" "${ERR}" "  and the interruption is reported"
assert_eq "0" "$(transaction_dirs)" "  no transaction directory is left"

echo "=== Complete staged params ==="
# A real partial write: cat becomes a wrapper that, once armed with
# "<input prefix> <byte limit>" in <state>/partial-write, runs the real cat on
# the first input that starts with that prefix under RLIMIT_FSIZE (prlimit),
# with SIGXFSZ ignored. The kernel stops the write at the limit and cat fails
# with EFBIG ("File too large"). "keep" limits the file to its current size,
# for an append. Every other run is the real cat.
REAL_CAT="$(PATH=/usr/bin:/bin command -v cat)"
cat >"${MOCKBIN}/cat" <<EOF
#!/bin/bash
if [[ \$# -eq 0 && -s '${S}/partial-write' ]]; then
	read -r PREFIX LIMIT <'${S}/partial-write'
	IN="\$(mktemp '${T}/cat-in.XXXXXX')"
	'${REAL_CAT}' >"\${IN}"
	if [[ "\$(head -c "\${#PREFIX}" "\${IN}")" == "\${PREFIX}" ]]; then
		rm -f '${S}/partial-write'
		[[ "\${LIMIT}" == keep ]] && LIMIT="\$(stat -L -c %s /proc/\$\$/fd/1)"
		trap '' XFSZ
		exec prlimit --fsize="\${LIMIT}" '${REAL_CAT}' "\${IN}"
	fi
	exec '${REAL_CAT}' "\${IN}"
fi
exec '${REAL_CAT}' "\$@"
EOF
chmod 0755 "${MOCKBIN}/cat"
hash -r
partial_write() { # <input prefix> <byte limit|keep>
	printf '%s %s\n' "$1" "$2" >"${S}/partial-write"
}
# The bytes of the first 25 canonical lines: up to AWG_PROTOCOL_VERSION, so
# AWG_HEADER_PROTECTION_KEY and every later key are cut off.
prefix_bytes() {
	head -n 25 "${AMNEZIAWG_DIR}/params" | wc -c
}
# serializeParams of the state make_install left in this shell; prints
# "<rc> umask-restored|umask-changed".
serialize() { # <output file>
	local BEFORE_UMASK RC
	BEFORE_UMASK="$(umask)"
	serializeParams "$1"
	RC=$?
	printf '%s %s' "${RC}" "$([[ "$(umask)" == "${BEFORE_UMASK}" ]] && echo umask-restored || echo umask-changed)"
}
keys_of() { # <file>
	sed -n 's/^\([A-Z][A-Z0-9_]*\)=.*/\1/p' "$1" | tr '\n' ' '
}

make_install boringtun dns example.com 3
CANONICAL="${T}/canonical.params"
cp -- "${AMNEZIAWG_DIR}/params" "${CANONICAL}"
run serialize "${T}/ser.ok"
assert_eq "0 umask-restored" "${OUT}" "serializeParams succeeds and restores the umask"
assert_true "  and writes the canonical params byte for byte" cmp -s "${T}/ser.ok" "${CANONICAL}"
assert_eq "$(awgParamsCanonicalKeys boringtun | tr '\n' ' ')" "$(keys_of "${T}/ser.ok")" \
	"the canonical key list is exactly the keys serializeParams writes for BoringTun"
run serialize "${T}/no-such-directory/params"
assert_eq "1 umask-restored" "${OUT}" "serializeParams fails when its output cannot be opened, and restores the umask"
partial_write SERVER_PUB_IP= 0
run serialize "${T}/ser.empty"
assert_eq "1 umask-restored" "${OUT}" "serializeParams fails when the params write fails before any byte"
assert_true "  (the injected kernel write limit was applied)" test ! -e "${S}/partial-write"
assert_eq "0" "$(wc -c <"${T}/ser.empty")" "  and nothing was written"
partial_write SERVER_PUB_IP= "$(prefix_bytes)"
run serialize "${T}/ser.partial"
assert_eq "1 umask-restored" "${OUT}" "serializeParams fails when the params write stops part-way"
assert_eq "25" "$(wc -l <"${T}/ser.partial")" "  (the kernel stopped it after 25 lines)"
assert_eq "0" "$(grep -c '^AWG_BORINGTUN_' "${T}/ser.partial")" "  and the imitation is not appended after a failed write"
partial_write AWG_BORINGTUN_IMITATE_PROTOCOL= keep
run serialize "${T}/ser.append"
assert_eq "1 umask-restored" "${OUT}" "serializeParams fails when the imitation append fails"
assert_true "  (the injected kernel write limit was applied)" test ! -e "${S}/partial-write"
make_install kernel
run serialize "${T}/ser.kernel"
assert_eq "0" "${OUT%% *}" "kernel: serializeParams succeeds"
assert_eq "$(awgParamsCanonicalKeys kernel | tr '\n' ' ')" "$(keys_of "${T}/ser.kernel")" \
	"the canonical key list is exactly the keys serializeParams writes for the kernel backend"
partial_write SERVER_PUB_IP= "$(prefix_bytes)"
run serialize "${T}/ser.kernel-partial"
assert_eq "1" "${OUT%% *}" "kernel: a params write that stops part-way fails too"

make_install boringtun dns example.com 3
schema() { # <label> <expected rc> <command editing the copy...>
	cp -- "${CANONICAL}" "${T}/schema.params"
	"${@:3}"
	run awgParamsFileHasCanonicalKeys "${T}/schema.params" boringtun
	assert_rc "$2" "${RC}" "$1"
}
schema "a complete BoringTun params file has the canonical keys" 0 true
schema "a truncated one does not" 1 sed -i '26,$d' "${T}/schema.params"
schema "nor one without SERVER_PORT" 1 sed -i '/^SERVER_PORT=/d' "${T}/schema.params"
schema "nor one with a repeated key" 1 sed -i '$a SERVER_PORT='"'"'51820'"'" "${T}/schema.params"
schema "nor one with an unexpected key" 1 sed -i '$a EXTRA_SETTING='"'"'x'"'" "${T}/schema.params"
schema "nor one with a stray line" 1 sed -i '$a # comment' "${T}/schema.params"
schema "nor one without the imitation keys" 1 sed -i '/^AWG_BORINGTUN_/d' "${T}/schema.params"
run awgParamsFileHasCanonicalKeys "${T}/ser.kernel" boringtun
assert_rc 1 "${RC}" "kernel params are not BoringTun params"

# The isolated read-back: no variable of this shell fills in a missing line.
isolated() { # <staged file>
	loadParams 0 1 >/dev/null
	readStagedParamsInIsolation "$1" "${T}/check.$$.${RANDOM}"
}
staged_without() { # <key>: the canonical file without that key's line
	grep -v "^$1=" "${CANONICAL}" >"${T}/staged.params"
	chmod 600 "${T}/staged.params"
}
cp -- "${CANONICAL}" "${T}/staged.params"
run isolated "${T}/staged.params"
assert_rc 0 "${RC}" "a complete staged file reads back in isolation"
assert_eq "dns|example.com" "${OUT#*|}" "  with its imitation"
for KEY in SERVER_PRIV_KEY SERVER_PORT SERVER_AWG_S4 AWG_PROTOCOL_VERSION AWG_HEADER_PROTECTION_KEY; do
	staged_without "${KEY}"
	run isolated "${T}/staged.params"
	assert_rc 1 "${RC}" "a staged file without ${KEY} is refused although this shell has ${KEY}"
	assert_contains "do not set ${KEY}" "${ERR}" "  because ${KEY} is missing"
done
sed "s/^AWG_HEADER_PROTECTION_KEY=.*/AWG_HEADER_PROTECTION_KEY='not-a-key'/" "${CANONICAL}" >"${T}/staged.params"
chmod 600 "${T}/staged.params"
run isolated "${T}/staged.params"
assert_rc 1 "${RC}" "a staged file with an invalid header-protection key does not load"
assert_contains "would not load" "${ERR}" "  because its AWG protocol state is validated"

# The transaction: a partial write of the staged params under AWG 3.x changes
# nothing, before anything is applied.
for VERSION in 3 3.1; do
	make_install boringtun dns example.com "${VERSION}"
	chmod 400 "${AMNEZIAWG_DIR}/params"
	BEFORE="$(snapshot)"
	partial_write SERVER_PUB_IP= "$(prefix_bytes)"
	run setBoringtunImitation stun
	assert_rc 1 "${RC}" "AWG ${VERSION}: a staged params write that stops part-way fails the change"
	assert_true "AWG ${VERSION}:   (the injected kernel write limit was applied)" test ! -e "${S}/partial-write"
	assert_not_contains "systemctl restart" "$(cat "${S}/log")" "AWG ${VERSION}:   no restart"
	assert_not_contains "is now stun" "${OUT}" "AWG ${VERSION}:   no success message"
	assert_not_contains "was restored" "${ERR}" "AWG ${VERSION}:   no rollback was needed: it failed before anything was applied"
	assert_eq "${BEFORE}" "$(snapshot)" "AWG ${VERSION}:   params and the runtime file are byte for byte and mode for mode as they were"
	assert_eq "0" "$(transaction_dirs)" "AWG ${VERSION}:   the staging directory is removed"
	run load_params
	assert_eq "0 boringtun|dns|example.com" "${RC} ${OUT}" "AWG ${VERSION}:   and params still load"
done
make_install boringtun dns example.com 3
BEFORE="$(snapshot)"
partial_write AWG_BORINGTUN_IMITATE_PROTOCOL= keep
run setBoringtunImitation stun
assert_rc 1 "${RC}" "a failed imitation append fails the change"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"
assert_not_contains "systemctl restart" "$(cat "${S}/log")" "  no restart"

# Staged params that are complete and load, but are not the current state
# plus the imitation, are refused too.
eval "$(declare -f serializeParams | sed '1s/serializeParams/realSerializeParams/')"
stage_altered() { # <sed expression applied to the staged params>
	serializeParams() {
		realSerializeParams "$@" || return
		sed -i "${STAGE_EDIT}" "$1"
	}
	setBoringtunImitation stun
}
make_install boringtun dns example.com 3
BEFORE="$(snapshot)"
STAGE_EDIT="s/^SERVER_AWG_S4=.*/SERVER_AWG_S4='51'/" run stage_altered
assert_rc 1 "${RC}" "staged params that change S4 are refused"
assert_contains "differ from the current ones in more than the protocol imitation" "${ERR}" "  as more than the imitation"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"
STAGE_EDIT='$a SERVER_PORT='"'"'51820'"'" run stage_altered
assert_rc 1 "${RC}" "staged params with a repeated key are refused"
assert_contains "not a complete params file" "${ERR}" "  as incomplete"
assert_eq "${BEFORE}" "$(snapshot)" "  and nothing changed"

echo "=== Upgrade from the previous installer ==="
# Params without the imitation keys, a FORMAT=1 runtime file and helpers that
# know nothing of imitation, as the previous installer version leaves them.
make_install boringtun
sed -i '/^AWG_BORINGTUN_/d' "${AMNEZIAWG_DIR}/params"
mkdir -p "${AWG_BT_LIBEXEC_DIR}"
printf '#!/bin/bash\n# awg-boringtun-launch of the previous version\n' >"${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
printf '#!/bin/bash\n# awg-backend-ctl of the previous version\n' >"${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"
chmod 0755 "${AWG_BT_LIBEXEC_DIR}"/*
RUNTIME_BEFORE="$(sha256sum <"${RUNTIME_FILE}")"
run load_params
assert_eq "boringtun|none|" "${OUT}" "previous params load with imitation none"
run bash -c 'source "$1" >/dev/null; AWG_BT_CONFIG_DIR="$2"; AWG_BT_TRUST_ANCHOR="$3"; AWG_BT_TRUSTED_UID="$4"; AWG_BORINGTUN_IMITATE_PROTOCOL=none; _awgBtWriteManagedFile "$5" 0600 < <(_awgBtRenderRuntimeFile) && echo "${_AWG_BT_FILE_CHANGED}"' \
	_ "${INSTALLER}" "${AWG_BT_CONFIG_DIR}" "${T}" "${AWG_BT_TRUSTED_UID}" "${RUNTIME_FILE}"
assert_eq "0" "${OUT}" "and every management run leaves their runtime file as it is"
run set_imitation dns
assert_rc 0 "${RC}" "then enabling dns succeeds"
assert_contains "ensure-ready 0 runtime=[FORMAT=1 ]" "$(cat "${S}/log")" \
	"the helpers are regenerated while the runtime file is still the previous one"
assert_not_contains "previous version" "$(cat "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch")" "  so the launcher that reads IMITATE_PROTOCOL is the new one"
assert_contains "_awgBtImitationCheck" "$(cat "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch")" "  (it carries the imitation check)"
assert_eq "dns" "$(params_value AWG_BORINGTUN_IMITATE_PROTOCOL)" "params gain the keys"
assert_true "and the runtime file its imitation" test "$(sha256sum <"${RUNTIME_FILE}")" != "${RUNTIME_BEFORE}"

echo "=== --backend-status ==="
status() {
	_awgBtVerifyStore() {
		[[ -f "${S}/store-ok" ]] || return 1
		_AWG_BT_VERIFIED_BIN=/store/boringtun-cli
	}
	printBackendStatus
}
make_install boringtun dns example.com 2
echo inactive >"${S}/active-state"
mkdir -p "${AWG_BT_STORE_DIR}"
ln -sfn "${AWG_BT_RELEASE_ASSET_X86_64%.tar.gz}" "${AWG_BT_STORE_DIR}/current"
touch "${S}/store-ok"
run status
assert_rc 0 "${RC}" "a valid BoringTun installation reports status 0"
assert_eq "backend=boringtun
awg_protocol=2.0
service_state=inactive
imitation_protocol=dns
imitation_domain=example.com
imitation_domain_mode=configured
installed_release=${AWG_BT_RELEASE_ASSET_X86_64%.tar.gz}
pinned_release=${AWG_BT_RELEASE_ASSET_X86_64%.tar.gz}
daemon_state=stopped
daemon_pid=
daemon_imitation_protocol=
daemon_imitation_domain=" "${OUT}" "the BoringTun report, key by key"
assert_not_contains "${MOCK_KEY}" "${OUT}${ERR}" "  no key is printed"

make_install boringtun quic "" 3
bash -c 'sleep 60; :' boringtun-cli --foreground --imitate-protocol quic awg0 &
BACKGROUND+=("$!")
echo "$!" >"${S}/daemon-pid"
mkdir -p "${AWG_BT_STORE_DIR}"
touch "${S}/store-ok"
run status
assert_contains $'awg_protocol=3.0\nservice_state=active' "${OUT}" "an active AWG 3.0 installation"
assert_contains "imitation_domain_mode=random" "${OUT}" "  a hostname left to BoringTun is 'random'"
assert_contains $'daemon_state=running\ndaemon_pid='"$(cat "${S}/daemon-pid")" "${OUT}" "  the verified daemon and its PID"
assert_contains $'daemon_imitation_protocol=quic\ndaemon_imitation_domain=' "${OUT}" "  and the imitation it runs, from its command line"
assert_not_contains "${MOCK_KEY}" "${OUT}${ERR}" "  no key is printed, not even the header-protection key"
echo 1 >"${S}/served-rc"
run status
assert_contains "daemon_state=unverified" "${OUT}" "an active unit that is not the recorded daemon is 'unverified'"
assert_rc 0 "${RC}" "  which is a runtime state, not a damaged installation"

make_install boringtun stun
rm -f "${S}/store-ok"
run status
assert_rc 1 "${RC}" "a BoringTun installation whose store does not verify reports status 1"
assert_contains "installed_release=invalid" "${OUT}" "  and says so"
assert_contains "imitation_domain_mode=none" "${OUT}" "  (stun takes no hostname)"

make_install kernel
run status
assert_eq "backend=kernel
awg_protocol=2.0
service_state=active
module_state=not-loaded" "${OUT}" "the kernel report, key by key"
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
run status
assert_contains "module_state=loaded" "${OUT}" "  with the module loaded"
rmdir "${AWG_BT_SYS_DIR}/module/amneziawg"

make_install boringtun
chmod 644 "${AMNEZIAWG_DIR}/params"
run status
assert_rc 1 "${RC}" "params with an insecure mode are refused"
assert_contains "does not repair it" "${ERR}" "  by the status itself, before params are read"
assert_eq "644" "$(/usr/bin/stat -c %a "${AMNEZIAWG_DIR}/params")" "  and not repaired: the status changes nothing"
make_install kernel
printf "AWG_BORINGTUN_IMITATE_PROTOCOL='sip'\n" >>"${AMNEZIAWG_DIR}/params"
run status
assert_rc 1 "${RC}" "damaged params report status 1"
assert_eq "" "${OUT}" "  and no key=value lines"

run bash "${INSTALLER}" --backend-status extra
assert_rc 1 "${RC}" "--backend-status takes no argument"
run bash "${INSTALLER}" --set-boringtun-imitation
assert_rc 1 "${RC}" "--set-boringtun-imitation needs a protocol"
assert_contains "Usage: amneziawg-install.sh --set-boringtun-imitation <none|dns|quic|sip|stun> [hostname]" "${ERR}" "  and prints its usage"
run bash "${INSTALLER}" --set-boringtun-imitation dns a.example extra
assert_rc 1 "${RC}" "and at most a hostname after it"

echo "=== Menus ==="
menu() { # <backend>
	changeBoringtunImitationInteractively() { echo "change-imitation"; }
	changeAwgProtocolInteractively() { echo "change-protocol"; }
	runLockedManagementOperation() { echo "locked $1"; }
	listClients() { echo "list"; }
	AWG_BACKEND="$1"
	manageMenu
}
make_install boringtun dns example.com
RUN_INPUT=7 run menu boringtun
assert_contains "Backend: BoringTun (experimental); protocol imitation: dns (hostname example.com)" "${OUT}" "the BoringTun menu shows the imitation"
assert_contains "7) Change BoringTun protocol imitation (current: dns)" "${OUT}" "  and offers to change it"
assert_contains "8) Exit" "${OUT}" "  in eight options"
assert_eq "change-imitation" "$(tail -n 1 <<<"${OUT}")" "  option 7 changes the imitation"
RUN_INPUT=6 run menu boringtun
assert_eq "locked uninstallAmneziaWG" "$(tail -n 1 <<<"${OUT}")" "  option 6 still uninstalls, as in the kernel menu"
make_install kernel
RUN_INPUT=6 run menu kernel
assert_not_contains "imitation" "${OUT}" "the kernel menu says nothing about imitation"
assert_contains "7) Exit" "${OUT}" "  and keeps its seven options"
assert_eq "locked uninstallAmneziaWG" "$(tail -n 1 <<<"${OUT}")" "  where option 6 still uninstalls"

interactive() { # <AWG version>
	setBoringtunImitation() { echo "set $*"; }
	AWG_BACKEND=boringtun
	AWG_PROTOCOL_VERSION="$1"
	AWG_BORINGTUN_IMITATE_PROTOCOL=none
	AWG_BORINGTUN_IMITATE_DOMAIN=""
	SERVER_AWG_S1=40 SERVER_AWG_S2=50 SERVER_AWG_S3=60 SERVER_AWG_S4=70
	changeBoringtunImitationInteractively
}
RUN_INPUT=$'2\nexample.com' run interactive 2
assert_eq "set dns example.com 1" "$(tail -n 1 <<<"${OUT}")" "AWG 2.0: the choice goes to the transaction, which is told the warnings were shown"
assert_contains "SERVFAIL" "${OUT}" "  after the warnings"
assert_not_contains "[y/N]" "${OUT}" "  without a confirmation"
RUN_INPUT=$'2\n\nn' run interactive 3
assert_contains "Protocol imitation change cancelled." "${OUT}" "AWG 3.0: enabling an imitation asks first, and N cancels"
assert_not_contains "set dns" "${OUT}" "  without running the transaction"
RUN_INPUT=$'5\ny' run interactive 3.1
assert_eq "set stun  1" "$(tail -n 1 <<<"${OUT}")" "AWG 3.1: y enables it"
RUN_INPUT=$'4\n' run interactive 3
assert_rc 1 "${RC}" "AWG 3.0: sip with S sizes over 30 is refused before the question"
assert_not_contains "set sip" "${OUT}" "  and nothing runs"
RUN_INPUT=$'1' run interactive 3
assert_contains "unchanged" "${OUT}" "choosing the current imitation changes nothing"

echo
echo "BoringTun imitation tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
