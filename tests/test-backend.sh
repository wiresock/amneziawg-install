#!/usr/bin/env bash

# AWG backend (datapath) state and the runtime seam through which
# backend-neutral management code reaches the datapath. This installer version
# supports only the kernel backend, so these tests pin two properties: every
# seam operation runs exactly the kernel commands its call sites ran before the
# seam existed, and every other backend value fails closed without running a
# datapath command.

# The test intentionally sets globals consumed by functions sourced from the
# installer; ShellCheck cannot follow those cross-file references.
# shellcheck disable=SC2034

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/awg-backend-tests.XXXXXX")"
BIN_DIR="${TEST_ROOT}/bin"
STAT_BIN_DIR="${TEST_ROOT}/stat-bin"
TEST_TMPDIR="${TEST_ROOT}/tmp"
mkdir -p "${BIN_DIR}" "${STAT_BIN_DIR}" "${TEST_TMPDIR}"

cleanup() {
	rm -rf -- "${TEST_ROOT}"
}
trap cleanup EXIT

PASS=0
FAIL=0

ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}

not_ok() {
	printf '  FAIL: %s\n' "$1" >&2
	FAIL=$((FAIL + 1))
}

# Compare exact (possibly multi-line) values and show both sides on failure.
assert_eq() {
	local EXPECTED="$1"
	local ACTUAL="$2"
	local NAME="$3"
	if [[ "${ACTUAL}" == "${EXPECTED}" ]]; then
		ok "${NAME}"
	else
		not_ok "${NAME}"
		printf '    expected:\n%s\n    actual:\n%s\n' \
			"$(sed 's/^/      /' <<<"${EXPECTED}")" \
			"$(sed 's/^/      /' <<<"${ACTUAL}")" >&2
	fi
}

# shellcheck source=../amneziawg-install.sh
source "${INSTALLER}"

MOCK_KEY="YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
MOCK_PUB="cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="
MOCK_PSK="cHNrMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM="
# What `awg-quick strip <interface>` prints for the running server. It keeps
# ListenPort, which the sync operation must hand to `awg syncconf` unfiltered.
STRIPPED_SERVER_CONFIG="[Interface]
ListenPort = 51820
PrivateKey = ${MOCK_KEY}

[Peer]
PublicKey = ${MOCK_PUB}
AllowedIPs = 10.66.66.2/32"
# The awg mock logs file input on one line, with each newline shown as '|'.
STRIPPED_SERVER_CONFIG_LOGGED="$(tr '\n' '|' <<<"${STRIPPED_SERVER_CONFIG}")"
BT_CALL_LOG="${TEST_ROOT}/calls.log"
export MOCK_KEY MOCK_PUB MOCK_PSK STRIPPED_SERVER_CONFIG BT_CALL_LOG
export BT_SERVER_INTERFACE="awgt0"

# Every mock appends one line per invocation to BT_CALL_LOG, so each test can
# compare the exact, ordered sequence of datapath commands.
cat >"${BIN_DIR}/awg" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
	genkey)
		printf 'awg genkey\n' >>"${BT_CALL_LOG}"
		printf '%s\n' "${MOCK_KEY}"
		;;
	pubkey)
		read -r _key
		printf 'awg pubkey\n' >>"${BT_CALL_LOG}"
		printf '%s\n' "${MOCK_PUB}"
		;;
	genpsk)
		printf 'awg genpsk\n' >>"${BT_CALL_LOG}"
		printf '%s\n' "${MOCK_PSK}"
		;;
	setconf)
		printf 'awg setconf %s %s\n' "${2:-}" "${3:-}" >>"${BT_CALL_LOG}"
		[[ "${BT_FAIL_SETCONF:-0}" == "0" ]] || exit 1
		;;
	syncconf)
		# Read the whole input before logging so the strip line always comes first.
		content="$(tr '\n' '|' <"${3:-/dev/null}")"
		printf 'awg syncconf %s <%s>\n' "${2:-}" "${content}" >>"${BT_CALL_LOG}"
		printf 'SYNC-STDOUT\n'
		printf 'SYNC-STDERR\n' >&2
		exit "${BT_SYNC_RC:-0}"
		;;
	show)
		printf 'awg show %s %s\n' "${2:-}" "${3:-}" >>"${BT_CALL_LOG}"
		case "${3:-}" in
			header-protection-key) printf '%s\n' "${MOCK_KEY}" ;;
			content-padding-addition) printf '11-13\n' ;;
			rekey-after-time) printf '101-103\n' ;;
			rekey-timeout) printf '5-7\n' ;;
			reject-after-time) printf '181-183\n' ;;
			keepalive-timeout) printf '9-11\n' ;;
			random-trailers|disable-cookies) printf 'on\n' ;;
			*) exit 1 ;;
		esac
		;;
	*)
		printf 'awg %s\n' "$*" >>"${BT_CALL_LOG}"
		exit 1
		;;
esac
EOF

cat >"${BIN_DIR}/awg-quick" <<'EOF'
#!/usr/bin/env bash
printf 'awg-quick %s\n' "$*" >>"${BT_CALL_LOG}"
case "${1:-}" in
	strip)
		printf 'STRIP-WARNING %s\n' "${2:-}" >&2
		if [[ -f "${2:-}" ]]; then
			sed -E '/^(Address|DNS|PostUp|PostDown)[[:space:]]*=/d' "$2"
		else
			printf '%s\n' "${STRIPPED_SERVER_CONFIG}"
		fi
		;;
	up)
		if [[ "${BT_FAIL_UP:-0}" != "0" ]]; then
			printf 'UP-STDERR\n' >&2
			exit 1
		fi
		[[ -z "${BT_MANUAL_STATE:-}" ]] || : >"${BT_MANUAL_STATE}"
		printf 'UP-STDOUT\n'
		;;
	down)
		[[ -z "${BT_MANUAL_STATE:-}" ]] || rm -f -- "${BT_MANUAL_STATE}"
		;;
	*) exit 1 ;;
esac
EOF

cat >"${BIN_DIR}/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >>"${BT_CALL_LOG}"
if [[ "${1:-}" == "link" && "${2:-}" == "show" ]]; then
	[[ "${4:-}" == "${BT_SERVER_INTERFACE:-}" && -n "${BT_MANUAL_STATE:-}" && -e "${BT_MANUAL_STATE}" ]]
	exit
fi
if [[ "${1:-}" == "link" && "${2:-}" == "add" ]]; then
	[[ "${BT_FAIL_LINK_ADD:-0}" == "0" ]] || exit 2
fi
if [[ "${1:-}" == "link" && "${2:-}" == "delete" ]]; then
	[[ "${BT_FAIL_LINK_DELETE:-0}" == "0" ]] || exit 3
fi
exit 0
EOF

cat >"${BIN_DIR}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"${BT_CALL_LOG}"
case "${1:-}" in
	is-active) [[ "${BT_SERVICE_ACTIVE:-0}" == "1" ]] ;;
	*) exit 0 ;;
esac
EOF

cat >"${BIN_DIR}/qrencode" <<'EOF'
#!/usr/bin/env bash
printf 'qrencode %s\n' "$*" >>"${BT_CALL_LOG}"
cat >/dev/null
EOF

cat >"${BIN_DIR}/getent" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF

# validateParamsFile requires a root-owned mode-0600 params file. Tests that
# load params put this directory first in PATH to report exactly that.
cat >"${STAT_BIN_DIR}/stat" <<'EOF'
#!/usr/bin/env bash
fmt=""
while [[ "${1:-}" == -* ]]; do
	case "$1" in
		-c) fmt="${2:-}"; shift 2 ;;
		*) shift ;;
	esac
done
case "${fmt}" in
	%u) printf '0\n' ;;
	%a) printf '600\n' ;;
	*) exit 1 ;;
esac
EOF

chmod +x "${BIN_DIR}"/* "${STAT_BIN_DIR}/stat"
export PATH="${BIN_DIR}:${PATH}"
export TMPDIR="${TEST_TMPDIR}"

reset_calls() {
	: >"${BT_CALL_LOG}"
}

raw_calls() {
	cat "${BT_CALL_LOG}"
}

# The call log with run-specific parts replaced by placeholders: the test root,
# the PID embedded in scratch interface names, and random mktemp suffixes.
normalized_calls() {
	local LOG
	LOG="$(cat "${BT_CALL_LOG}")"
	[[ -n "${LOG}" ]] || return 0
	LOG="${LOG//"${TEST_ROOT}"/<ROOT>}"
	sed -E \
		-e 's/awgp[0-9]+/awgp<PID>/g' \
		-e 's/awgv[0-9]+/awgv<PID>/g' \
		-e 's/awg3-probe\.[A-Za-z0-9]+/awg3-probe.<X>/g' \
		-e 's/\.awg-protocol\.[A-Za-z0-9]+/.awg-protocol.<X>/g' <<<"${LOG}"
}

# Pass when the log names exactly one scratch interface, so the interface a
# probe or validation deleted is the one it created.
assert_single_scratch_interface() {
	local PATTERN="$1"
	local NAME="$2"
	local -a INTERFACES=()
	mapfile -t INTERFACES < <(grep -oE 'awg[pv][0-9]+' "${BT_CALL_LOG}" | sort -u)
	if (( ${#INTERFACES[@]} == 1 )) && [[ "${INTERFACES[0]}" =~ ${PATTERN} ]]; then
		ok "${NAME}"
	else
		not_ok "${NAME} (scratch interfaces: ${INTERFACES[*]:-none})"
	fi
}

# Run a command in a subshell and keep its exit status, stdout and stderr in
# RUN_RC, RUN_OUT and RUN_ERR. Stdin is RUN_INPUT when set, else /dev/null.
run_captured() {
	reset_calls
	if [[ -n "${RUN_INPUT:-}" ]]; then
		("$@") >"${TEST_ROOT}/run.out" 2>"${TEST_ROOT}/run.err" <<<"${RUN_INPUT}"
	else
		("$@") >"${TEST_ROOT}/run.out" 2>"${TEST_ROOT}/run.err" </dev/null
	fi
	RUN_RC=$?
	RUN_OUT="$(cat "${TEST_ROOT}/run.out")"
	RUN_ERR="$(cat "${TEST_ROOT}/run.err")"
}

# Put AWG_BACKEND into one of the states under test. "unset" and "empty" are
# keywords; anything else is the literal backend value.
apply_backend_case() {
	case "$1" in
		unset) unset AWG_BACKEND ;;
		empty) AWG_BACKEND="" ;;
		*) AWG_BACKEND="$1" ;;
	esac
}

expected_rejection() {
	case "$1" in
		unset|empty)
			printf '%s' "ERROR: the AWG backend is not set; refusing to operate on an unknown backend"
			;;
		*)
			printf '%s' "ERROR: AWG backend '$1' is not supported by this installer version (supported: kernel)"
			;;
	esac
}

# A complete AWG 2.0 server with one managed client, alice, below FIXTURE_DIR.
setup_fixture() {
	local FIXTURE_DIR="$1"
	rm -rf -- "${FIXTURE_DIR}"
	AMNEZIAWG_DIR="${FIXTURE_DIR}/state"
	WEB_PANEL_CONFIG_DIR="${AMNEZIAWG_DIR}/clients"
	WEB_PANEL_ENV_FILE="${FIXTURE_DIR}/missing-web-panel.env"
	WEB_PANEL_SYSTEMD_UNIT="${FIXTURE_DIR}/missing-web-panel.service"
	SERVER_AWG_NIC="awgt0"
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
	mkdir -p "${AMNEZIAWG_DIR}/clients"
	SERVER_PUB_IP="198.51.100.10"
	SERVER_PUB_NIC="eth0"
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
	SERVER_AWG_S1="20"
	SERVER_AWG_S2="30"
	SERVER_AWG_S3="40"
	SERVER_AWG_S4="50"
	SERVER_AWG_H1="100-200"
	SERVER_AWG_H2="300-400"
	SERVER_AWG_H3="500-600"
	SERVER_AWG_H4="700-800"
	AWG_BACKEND="${AWG_BACKEND_KERNEL}"
	AWG_PROTOCOL_VERSION=2
	clearAwg3Params
	cat >"${SERVER_AWG_CONF}" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
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
PublicKey = ${MOCK_PUB}
PresharedKey = ${MOCK_PSK}
AllowedIPs = 10.66.66.2/32
EOF
	cat >"${AMNEZIAWG_DIR}/clients/${SERVER_AWG_NIC}-client-alice.conf" <<EOF
[Interface]
PrivateKey = ${MOCK_KEY}
Address = 10.66.66.2/32
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${MOCK_PSK}
Endpoint = ${SERVER_PUB_IP}:${SERVER_PORT}
AllowedIPs = 0.0.0.0/0
EOF
	chmod 600 "${SERVER_AWG_CONF}"
	chmod 640 "${AMNEZIAWG_DIR}/clients/${SERVER_AWG_NIC}-client-alice.conf"
	serializeParams "${AMNEZIAWG_DIR}/params"
	chmod 600 "${AMNEZIAWG_DIR}/params"
}

set_awg3_state() {
	AWG_PROTOCOL_VERSION=3
	AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
	AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
	AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
	AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
	AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
	AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
}

# Replace the installer functions that need root, locks or a web panel with
# recorders. The kernel readiness recorder stands in for the DKMS/modprobe
# repair logic, which has its own tests.
mock_management() {
	acquireClientLifecycleLock() { printf 'fn acquireClientLifecycleLock\n' >>"${BT_CALL_LOG}"; }
	loadParams() { printf 'fn loadParams[%s]\n' "$*" >>"${BT_CALL_LOG}"; }
	ensureAmneziawgKernelModule() { printf 'fn ensureAmneziawgKernelModule[%s]\n' "$*" >>"${BT_CALL_LOG}"; }
	copyToWebPanelDir() { printf 'fn copyToWebPanelDir[%s]\n' "$*" >>"${BT_CALL_LOG}"; }
	removeFromWebPanelDir() { printf 'fn removeFromWebPanelDir[%s]\n' "$*" >>"${BT_CALL_LOG}"; }
	getHomeDirForClient() {
		mkdir -p "${AMNEZIAWG_DIR}/home/$1"
		printf '%s\n' "${AMNEZIAWG_DIR}/home/$1"
	}
	isWebPanelInstalled() { return 1; }
}

echo "=== AWG backend state ==="

assert_eq "kernel" "${AWG_BACKEND_KERNEL}" "the kernel backend is persisted as 'kernel'"

FRESH_SOURCE_BACKEND="$(
	# shellcheck disable=SC2016
	AWG_BACKEND="boringtun" bash -c 'source "$1" && printf "%s" "${AWG_BACKEND}"' _ "${INSTALLER}"
)"
assert_eq "kernel" "${FRESH_SOURCE_BACKEND}" \
	"sourcing the installer replaces an AWG_BACKEND exported by the caller with the kernel default"

# Run a backend state function in a subshell. Prints "<status>|<AWG_BACKEND
# afterwards>" and keeps stderr in STATE_ERR_FILE.
STATE_ERR_FILE="${TEST_ROOT}/backend-state.err"
backend_state_case() {
	local STATE_FUNCTION="$1"
	local CASE="$2"
	(
		apply_backend_case "${CASE}"
		"${STATE_FUNCTION}" 2>"${STATE_ERR_FILE}"
		printf '%s|%s' "$?" "${AWG_BACKEND-<unset>}"
	)
}

assert_eq "0|kernel" "$(backend_state_case normalizeAwgBackend unset)" \
	"a missing AWG_BACKEND normalizes to the kernel backend"
assert_eq "" "$(cat "${STATE_ERR_FILE}")" "normalizing a missing AWG_BACKEND prints nothing"
assert_eq "0|kernel" "$(backend_state_case normalizeAwgBackend empty)" \
	"an empty AWG_BACKEND normalizes to the kernel backend"
assert_eq "0|kernel" "$(backend_state_case normalizeAwgBackend kernel)" \
	"AWG_BACKEND=kernel is valid"
assert_eq "" "$(cat "${STATE_ERR_FILE}")" "a valid AWG_BACKEND prints nothing"
assert_eq "1|boringtun" "$(backend_state_case normalizeAwgBackend boringtun)" \
	"AWG_BACKEND=boringtun is rejected and left unchanged"
assert_eq "$(expected_rejection boringtun)" "$(cat "${STATE_ERR_FILE}")" \
	"the boringtun rejection says this installer version does not support it"
for BACKEND_VALUE in userspace Kernel KERNEL " kernel" "kernel " kernel0 wireguard-go; do
	assert_eq "1|${BACKEND_VALUE}" "$(backend_state_case normalizeAwgBackend "${BACKEND_VALUE}")" \
		"AWG_BACKEND='${BACKEND_VALUE}' is rejected, not normalized"
done
UNSAFE_BACKEND_VALUE=$'boringtun\n\e[31mspoofed'
if [[ "$(backend_state_case normalizeAwgBackend "${UNSAFE_BACKEND_VALUE}")" == "1|${UNSAFE_BACKEND_VALUE}" ]]; then
	ok "a backend value with control characters is rejected"
else
	not_ok "a backend value with control characters is rejected"
fi
assert_eq "ERROR: the configured AWG backend is not supported by this installer version (supported: kernel)" \
	"$(cat "${STATE_ERR_FILE}")" "the rejection does not echo a value that contains control characters"

assert_eq "0|kernel" "$(backend_state_case validatePersistedAwgBackendState unset)" \
	"persisted state without AWG_BACKEND validates as the kernel backend"
assert_eq "0|kernel" "$(backend_state_case validatePersistedAwgBackendState kernel)" \
	"persisted AWG_BACKEND=kernel validates"
assert_eq "1|boringtun" "$(backend_state_case validatePersistedAwgBackendState boringtun)" \
	"persisted AWG_BACKEND=boringtun fails validation"
assert_eq "1|userspace" "$(backend_state_case validatePersistedAwgBackendState userspace)" \
	"a persisted AWG_BACKEND with an arbitrary value fails validation"

echo "=== AWG backend persistence ==="

PARAMS_FIXTURE="${TEST_ROOT}/params-fixture"
setup_fixture "${PARAMS_FIXTURE}"
CURRENT_PARAMS="${TEST_ROOT}/params.current"
cp -p "${AMNEZIAWG_DIR}/params" "${CURRENT_PARAMS}"
assert_eq "AWG_BACKEND='kernel'" "$(grep '^AWG_BACKEND=' "${CURRENT_PARAMS}")" \
	"serializeParams persists AWG_BACKEND='kernel' exactly once"

UNSET_BACKEND_PARAMS="${TEST_ROOT}/params.unset-backend"
(
	unset AWG_BACKEND
	serializeParams "${UNSET_BACKEND_PARAMS}"
)
assert_eq "AWG_BACKEND='kernel'" "$(grep '^AWG_BACKEND=' "${UNSET_BACKEND_PARAMS}")" \
	"serializeParams persists the kernel backend when AWG_BACKEND is unset"

LEGACY_PARAMS="${TEST_ROOT}/params.legacy"
grep -v '^AWG_BACKEND=' "${CURRENT_PARAMS}" >"${LEGACY_PARAMS}"

# Install params for the fixture from a base file plus optional extra lines.
install_params() {
	local BASE_FILE="$1"
	shift
	{
		cat "${BASE_FILE}"
		(( $# == 0 )) || printf '%s\n' "$@"
	} >"${PARAMS_FIXTURE}/state/params"
	chmod 600 "${PARAMS_FIXTURE}/state/params"
}

# Validate the fixture params in a subshell and print "<status>|<AWG_BACKEND
# afterwards>". With "exported", AWG_BACKEND=boringtun is first exported the
# way a caller's environment would provide it. Stderr is kept in
# VALIDATE_ERR_FILE.
VALIDATE_ERR_FILE="${TEST_ROOT}/validate-params.err"
run_validate_params() {
	local MODE="$1"
	(
		PATH="${STAT_BIN_DIR}:${PATH}"
		AMNEZIAWG_DIR="${PARAMS_FIXTURE}/state"
		if [[ "${MODE}" == "exported" ]]; then
			export AWG_BACKEND="boringtun"
		fi
		validateParamsFile >/dev/null 2>"${VALIDATE_ERR_FILE}"
		printf '%s|%s' "$?" "${AWG_BACKEND-<unset>}"
	)
}

install_params "${CURRENT_PARAMS}"
assert_eq "0|kernel" "$(run_validate_params plain)" \
	"params with AWG_BACKEND='kernel' load as the kernel backend"
assert_eq "0|kernel" "$(run_validate_params exported)" \
	"an exported AWG_BACKEND=boringtun does not override AWG_BACKEND='kernel' in params"

install_params "${LEGACY_PARAMS}"
assert_eq "0|kernel" "$(run_validate_params plain)" \
	"params written before AWG_BACKEND existed load as the kernel backend"
assert_eq "0|kernel" "$(run_validate_params exported)" \
	"an exported AWG_BACKEND=boringtun does not fill in a backend that params lack"

install_params "${LEGACY_PARAMS}" "AWG_BACKEND=''"
assert_eq "0|kernel" "$(run_validate_params plain)" \
	"an empty persisted AWG_BACKEND loads as the kernel backend"

for BACKEND_VALUE in boringtun userspace; do
	install_params "${LEGACY_PARAMS}" "AWG_BACKEND='${BACKEND_VALUE}'"
	VALIDATE_RESULT="$(run_validate_params plain)"
	VALIDATE_ERR="$(cat "${VALIDATE_ERR_FILE}")"
	if [[ "${VALIDATE_RESULT}" == "1|"* ]] && \
		[[ "${VALIDATE_ERR}" == *"$(expected_rejection "${BACKEND_VALUE}")"* ]] && \
		[[ "${VALIDATE_ERR}" == *"Invalid AWG backend state in ${PARAMS_FIXTURE}/state/params"* ]]; then
		ok "params with AWG_BACKEND='${BACKEND_VALUE}' fail validation with an unsupported-backend error"
	else
		not_ok "params with AWG_BACKEND='${BACKEND_VALUE}' fail validation with an unsupported-backend error (result '${VALIDATE_RESULT}', stderr '${VALIDATE_ERR}')"
	fi
done

# Load params the way management operations do (0 0 are the loadParams
# defaults), then attempt datapath operations that must never run.
install_params "${LEGACY_PARAMS}" "AWG_BACKEND='boringtun'"
reset_calls
LOAD_ERR="$(
	(
		PATH="${STAT_BIN_DIR}:${PATH}"
		AMNEZIAWG_DIR="${PARAMS_FIXTURE}/state"
		ensureAmneziawgKernelModule() { printf 'fn ensureAmneziawgKernelModule[%s]\n' "$*" >>"${BT_CALL_LOG}"; }
		loadParams 0 0
		ensureAwgBackendReady
		awgSyncInterfaceConfig "${SERVER_AWG_NIC}"
	) 2>&1 >/dev/null
)"
LOAD_RC=$?
if (( LOAD_RC != 0 )) && [[ ! -s "${BT_CALL_LOG}" ]] && \
	[[ "${LOAD_ERR}" == *"Failed to validate params file"* ]]; then
	ok "loadParams aborts on an unsupported persisted backend before any datapath operation"
else
	not_ok "loadParams aborts on an unsupported persisted backend before any datapath operation (rc ${LOAD_RC}, calls '$(raw_calls)')"
fi

install_params "${CURRENT_PARAMS}"
ROUND_TRIP_PARAMS="${TEST_ROOT}/params.round-trip"
(
	PATH="${STAT_BIN_DIR}:${PATH}"
	AMNEZIAWG_DIR="${PARAMS_FIXTURE}/state"
	AWG_BACKEND="stale-in-memory-value"
	validateParamsFile >/dev/null 2>&1 || exit 1
	serializeParams "${ROUND_TRIP_PARAMS}"
)
if cmp -s "${CURRENT_PARAMS}" "${ROUND_TRIP_PARAMS}"; then
	ok "params round-trip byte-for-byte through validateParamsFile and serializeParams"
else
	not_ok "params round-trip byte-for-byte through validateParamsFile and serializeParams"
fi

echo "=== Fresh installation ==="

FRESH_PARAMS="${TEST_ROOT}/params.fresh"
FRESH_BACKEND="$(
	export AWG_BACKEND="boringtun"
	AUTO_INSTALL=y
	SERVER_PUB_IP="198.51.100.20"
	SERVER_PUB_NIC="eth0"
	SERVER_AWG_NIC="awg0"
	SERVER_PORT="51820"
	ENABLE_IPV6="n"
	installQuestions >/dev/null 2>&1 || exit 1
	serializeParams "${FRESH_PARAMS}"
	printf '%s' "${AWG_BACKEND}"
)"
assert_eq "kernel" "${FRESH_BACKEND}" \
	"AUTO_INSTALL answers select the kernel backend even with AWG_BACKEND=boringtun exported"
assert_eq "AWG_BACKEND='kernel'" "$(grep '^AWG_BACKEND=' "${FRESH_PARAMS}" 2>/dev/null)" \
	"a fresh installation persists AWG_BACKEND='kernel'"

echo "=== Backend readiness dispatch ==="

# Run ensureAwgBackendReady in a subshell with a recording kernel
# implementation. The subshell logs "returned <status>" when the dispatcher
# returns, so a fatal exit leaves no such line. Sets ENSURE_RC.
ENSURE_ERR_FILE="${TEST_ROOT}/ensure.err"
run_ensure_case() {
	local CASE="$1"
	shift
	reset_calls
	(
		ensureAmneziawgKernelModule() {
			printf 'fn ensureAmneziawgKernelModule[%s]\n' "$*" >>"${BT_CALL_LOG}"
			[[ "${BT_KERNEL_ENSURE_EXIT:-0}" == "0" ]] || exit 1
			return "${BT_KERNEL_ENSURE_RC:-0}"
		}
		apply_backend_case "${CASE}"
		ensureAwgBackendReady "$@"
		printf 'returned %s\n' "$?" >>"${BT_CALL_LOG}"
	) >/dev/null 2>"${ENSURE_ERR_FILE}"
	ENSURE_RC=$?
}

run_ensure_case kernel 0
assert_eq "0" "${ENSURE_RC}" "kernel readiness in mode 0 succeeds"
assert_eq $'fn ensureAmneziawgKernelModule[0]\nreturned 0' "$(raw_calls)" \
	"kernel readiness passes mode 0 to ensureAmneziawgKernelModule"
run_ensure_case kernel 1
assert_eq $'fn ensureAmneziawgKernelModule[1]\nreturned 0' "$(raw_calls)" \
	"kernel readiness passes mode 1 to ensureAmneziawgKernelModule"
run_ensure_case kernel
assert_eq $'fn ensureAmneziawgKernelModule[]\nreturned 0' "$(raw_calls)" \
	"kernel readiness without a mode leaves ensureAmneziawgKernelModule on its default"
BT_KERNEL_ENSURE_RC=5 run_ensure_case kernel 1
assert_eq $'fn ensureAmneziawgKernelModule[1]\nreturned 5' "$(raw_calls)" \
	"kernel readiness returns the kernel implementation's status unchanged"
BT_KERNEL_ENSURE_EXIT=1 run_ensure_case kernel 1
if (( ENSURE_RC == 1 )) && [[ "$(raw_calls)" == "fn ensureAmneziawgKernelModule[1]" ]]; then
	ok "a fatal kernel readiness failure still ends the calling shell"
else
	not_ok "a fatal kernel readiness failure still ends the calling shell (rc ${ENSURE_RC}, calls '$(raw_calls)')"
fi

for BACKEND_CASE in unset empty boringtun userspace; do
	run_ensure_case "${BACKEND_CASE}" 1
	if (( ENSURE_RC == 1 )) && [[ ! -s "${BT_CALL_LOG}" ]] && \
		[[ "$(cat "${ENSURE_ERR_FILE}")" == "$(expected_rejection "${BACKEND_CASE}")" ]]; then
		ok "readiness exits without calling the kernel implementation when AWG_BACKEND is ${BACKEND_CASE}"
	else
		not_ok "readiness exits without calling the kernel implementation when AWG_BACKEND is ${BACKEND_CASE} (rc ${ENSURE_RC}, calls '$(raw_calls)', stderr '$(cat "${ENSURE_ERR_FILE}")')"
	fi
done

# The protocol-mode call sites discard readiness output and add `|| true`; an
# unsupported backend must still stop them, as a failed kernel repair does.
reset_calls
(
	ensureAmneziawgKernelModule() { printf 'fn ensureAmneziawgKernelModule[%s]\n' "$*" >>"${BT_CALL_LOG}"; }
	AWG_BACKEND="boringtun"
	ensureAwgBackendReady 0 >/dev/null 2>&1 || true
	printf 'continued\n' >>"${BT_CALL_LOG}"
)
GUARDED_RC=$?
if (( GUARDED_RC == 1 )) && [[ ! -s "${BT_CALL_LOG}" ]]; then
	ok "an unsupported backend stops the caller even behind '|| true'"
else
	not_ok "an unsupported backend stops the caller even behind '|| true' (rc ${GUARDED_RC}, calls '$(raw_calls)')"
fi

echo "=== Datapath operations ==="

SYNC_ERR_FILE="${TEST_ROOT}/syncconf.err"
QUICK_UP_CONF="${TEST_ROOT}/awgt0.conf"

# Every datapath operation must refuse an unset or unknown backend without
# running a command or creating the requested stderr file.
check_rejected_operation() {
	local CASE="$1"
	local LABEL="$2"
	shift 2
	local ERR RC
	rm -f -- "${SYNC_ERR_FILE}"
	reset_calls
	ERR="$(
		(
			apply_backend_case "${CASE}"
			"$@"
		) 2>&1 >/dev/null
	)"
	RC=$?
	if (( RC == 1 )) && [[ ! -s "${BT_CALL_LOG}" ]] && [[ ! -e "${SYNC_ERR_FILE}" ]] && \
		[[ "${ERR}" == "$(expected_rejection "${CASE}")" ]]; then
		ok "${LABEL} fails closed when AWG_BACKEND is ${CASE}"
	else
		not_ok "${LABEL} fails closed when AWG_BACKEND is ${CASE} (rc ${RC}, calls '$(raw_calls)', stderr '${ERR}')"
	fi
}

for BACKEND_CASE in unset empty boringtun; do
	check_rejected_operation "${BACKEND_CASE}" "scratch interface creation" \
		awgBackendCreateScratchInterface awgp4242
	check_rejected_operation "${BACKEND_CASE}" "scratch interface deletion" \
		awgBackendDestroyScratchInterface awgp4242
	check_rejected_operation "${BACKEND_CASE}" "manual quick-up" \
		awgBackendQuickUp "${QUICK_UP_CONF}"
	check_rejected_operation "${BACKEND_CASE}" "interface sync" \
		awgSyncInterfaceConfig awgt0
	check_rejected_operation "${BACKEND_CASE}" "interface sync with captured stderr" \
		awgSyncInterfaceConfig awgt0 --stderr-to-stdout
	check_rejected_operation "${BACKEND_CASE}" "interface sync with a stderr file" \
		awgSyncInterfaceConfig awgt0 "${SYNC_ERR_FILE}"
done

run_captured awgBackendCreateScratchInterface awgp4242
assert_eq "0" "${RUN_RC}" "kernel scratch interface creation succeeds"
assert_eq "ip link add dev awgp4242 type amneziawg" "$(raw_calls)" \
	"kernel scratch interface creation runs 'ip link add dev <if> type amneziawg'"
BT_FAIL_LINK_ADD=1 run_captured awgBackendCreateScratchInterface awgp4242
assert_eq "2" "${RUN_RC}" "kernel scratch interface creation returns the ip status unchanged"

run_captured awgBackendDestroyScratchInterface awgp4242
assert_eq "0" "${RUN_RC}" "kernel scratch interface deletion succeeds"
assert_eq "ip link delete dev awgp4242" "$(raw_calls)" \
	"kernel scratch interface deletion runs 'ip link delete dev <if>'"
BT_FAIL_LINK_DELETE=1 run_captured awgBackendDestroyScratchInterface awgp4242
assert_eq "3" "${RUN_RC}" "kernel scratch interface deletion returns the ip status unchanged"

# Everything a caller can observe: status, both output streams and commands.
command_transcript() {
	run_captured "$@"
	printf 'rc=%s\n--- stdout\n%s\n--- stderr\n%s\n--- calls\n%s\n' \
		"${RUN_RC}" "${RUN_OUT}" "${RUN_ERR}" "$(raw_calls)"
}

assert_eq "rc=0
--- stdout
UP-STDOUT
--- stderr

--- calls
awg-quick up ${QUICK_UP_CONF}" "$(command_transcript awgBackendQuickUp "${QUICK_UP_CONF}")" \
	"manual quick-up runs 'awg-quick up <conf>' and nothing else"
for FAIL_UP in 0 1; do
	assert_eq "$(export BT_FAIL_UP="${FAIL_UP}"; command_transcript awg-quick up "${QUICK_UP_CONF}")" \
		"$(export BT_FAIL_UP="${FAIL_UP}"; command_transcript awgBackendQuickUp "${QUICK_UP_CONF}")" \
		"manual quick-up is indistinguishable from 'awg-quick up <conf>' (awg-quick exit ${FAIL_UP})"
done

echo "=== Interface configuration sync ==="

SERVER_AWG_NIC="awgt0"

# The three forms the management call sites used before the seam existed:
# plain (revoke, regenerate, migration reload), stderr merged into a command
# substitution (interactive add, non-interactive remove) and stderr written to
# a file (non-interactive add).
legacy_sync_plain() {
	awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
}
legacy_sync_captured() {
	local sync_err
	if ! sync_err="$(awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}") 2>&1)"; then
		printf 'failed, captured: %s\n' "${sync_err}"
		return 1
	fi
	printf 'captured: %s\n' "${sync_err}"
}
legacy_sync_file() {
	awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}") 2>"${SYNC_ERR_FILE}"
}
seam_sync_plain() {
	awgSyncInterfaceConfig "${SERVER_AWG_NIC}"
}
seam_sync_captured() {
	local sync_err
	if ! sync_err="$(awgSyncInterfaceConfig "${SERVER_AWG_NIC}" --stderr-to-stdout)"; then
		printf 'failed, captured: %s\n' "${sync_err}"
		return 1
	fi
	printf 'captured: %s\n' "${sync_err}"
}
seam_sync_file() {
	awgSyncInterfaceConfig "${SERVER_AWG_NIC}" "${SYNC_ERR_FILE}"
}

sync_transcript() {
	local STDERR_FILE_CONTENT="<absent>"
	rm -f -- "${SYNC_ERR_FILE}"
	command_transcript "$1"
	[[ ! -e "${SYNC_ERR_FILE}" ]] || STDERR_FILE_CONTENT="$(cat "${SYNC_ERR_FILE}")"
	printf -- '--- stderr file\n%s\n' "${STDERR_FILE_CONTENT}"
}

SYNC_CALLS="awg-quick strip awgt0
awg syncconf awgt0 <${STRIPPED_SERVER_CONFIG_LOGGED}>"

for SYNC_RC in 0 1; do
	for SYNC_FORM in plain captured file; do
		assert_eq "$(export BT_SYNC_RC="${SYNC_RC}"; sync_transcript "legacy_sync_${SYNC_FORM}")" \
			"$(export BT_SYNC_RC="${SYNC_RC}"; sync_transcript "seam_sync_${SYNC_FORM}")" \
			"sync (${SYNC_FORM} form) is indistinguishable from the former inline command (syncconf exit ${SYNC_RC})"
	done
done

assert_eq "rc=0
--- stdout
SYNC-STDOUT
--- stderr
STRIP-WARNING awgt0
SYNC-STDERR
--- calls
${SYNC_CALLS}
--- stderr file
<absent>" "$(sync_transcript seam_sync_plain)" \
	"sync runs 'awg syncconf <if> <(awg-quick strip <if>)' and leaves both stderr streams alone"
assert_eq "rc=0
--- stdout
captured: SYNC-STDOUT
SYNC-STDERR
--- stderr
STRIP-WARNING awgt0
--- calls
${SYNC_CALLS}
--- stderr file
<absent>" "$(sync_transcript seam_sync_captured)" \
	"captured sync merges only syncconf stderr into the capture; strip diagnostics stay on stderr"
assert_eq "rc=0
--- stdout
SYNC-STDOUT
--- stderr
STRIP-WARNING awgt0
--- calls
${SYNC_CALLS}
--- stderr file
SYNC-STDERR" "$(sync_transcript seam_sync_file)" \
	"file sync writes only syncconf stderr to the file; strip diagnostics stay on stderr"

sync_transcript seam_sync_plain >/dev/null
if grep -Fqx "awg syncconf awgt0 <${STRIPPED_SERVER_CONFIG_LOGGED}>" "${BT_CALL_LOG}" && \
	[[ "${STRIPPED_SERVER_CONFIG_LOGGED}" == *"|ListenPort = 51820|"* ]]; then
	ok "sync hands awg syncconf the stripped configuration unfiltered, ListenPort included"
else
	not_ok "sync hands awg syncconf the stripped configuration unfiltered, ListenPort included"
fi

echo "=== Scratch interfaces: capability probes and staged validation ==="

PROBE_CONF_LOGGED="<ROOT>/tmp/awg3-probe.<X>/probe.conf"
PROBE_CALLS_30="ip link add dev awgp<PID> type amneziawg
awg setconf awgp<PID> ${PROBE_CONF_LOGGED}
awg show awgp<PID> header-protection-key
awg show awgp<PID> content-padding-addition
awg show awgp<PID> rekey-after-time
awg show awgp<PID> rekey-timeout
awg show awgp<PID> reject-after-time
awg show awgp<PID> keepalive-timeout"

run_captured probeAwg3Capability "${MOCK_KEY}"
assert_eq "0" "${RUN_RC}" "the AWG 3.0 probe succeeds on a capable kernel datapath"
assert_eq "${PROBE_CALLS_30}
ip link delete dev awgp<PID>" "$(normalized_calls)" \
	"the AWG 3.0 probe creates, uses and deletes a kernel scratch interface in order"
assert_single_scratch_interface '^awgp[0-9]+$' "the AWG 3.0 probe deletes the scratch interface it created"

run_captured probeAwg31Capability "${MOCK_KEY}"
assert_eq "0" "${RUN_RC}" "the AWG 3.1 probe succeeds on a capable kernel datapath"
assert_eq "${PROBE_CALLS_30}
awg show awgp<PID> random-trailers
awg show awgp<PID> disable-cookies
ip link delete dev awgp<PID>" "$(normalized_calls)" \
	"the AWG 3.1 probe creates, uses and deletes a kernel scratch interface in order"
assert_single_scratch_interface '^awgp[0-9]+$' "the AWG 3.1 probe deletes the scratch interface it created"

BT_FAIL_LINK_ADD=1 run_captured probeAwg3Capability "${MOCK_KEY}"
if (( RUN_RC == 1 )) && [[ "$(normalized_calls)" == "ip link add dev awgp<PID> type amneziawg" ]] && \
	[[ "${RUN_ERR}" == *"could not create a temporary amneziawg interface"* ]]; then
	ok "a failed scratch interface creation fails the probe without further commands"
else
	not_ok "a failed scratch interface creation fails the probe without further commands (rc ${RUN_RC}, calls '$(normalized_calls)')"
fi

BT_FAIL_SETCONF=1 run_captured probeAwg3Capability "${MOCK_KEY}"
assert_eq "1" "${RUN_RC}" "a rejected probe configuration fails the probe"
assert_eq "ip link add dev awgp<PID> type amneziawg
awg setconf awgp<PID> ${PROBE_CONF_LOGGED}
ip link delete dev awgp<PID>" "$(normalized_calls)" \
	"a rejected probe configuration still deletes the scratch interface"

BT_FAIL_LINK_DELETE=1 run_captured probeAwg3Capability "${MOCK_KEY}"
assert_eq "1" "${RUN_RC}" "a failed scratch interface deletion fails the probe"
assert_eq "${PROBE_CALLS_30}
ip link delete dev awgp<PID>" "$(normalized_calls)" \
	"a failed scratch interface deletion happens after the complete probe"

VALIDATION_WORK="${TEST_ROOT}/validate"
mkdir -p "${VALIDATION_WORK}"
printf '[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = %s\nS1 = 20\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n' \
	"${MOCK_KEY}" "${MOCK_PUB}" >"${VALIDATION_WORK}/server.conf"
printf '[Interface]\nPrivateKey = %s\nDNS = 1.1.1.1\nS1 = 20\n\n[Peer]\nPublicKey = %s\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n' \
	"${MOCK_KEY}" "${MOCK_PUB}" >"${VALIDATION_WORK}/client-0.conf"
VALIDATION_CALLS="ip link add dev awgv<PID> type amneziawg
awg-quick strip <ROOT>/validate/server.conf
awg setconf awgv<PID> <ROOT>/validate/validate-1.interface
awg-quick strip <ROOT>/validate/client-0.conf
awg setconf awgv<PID> <ROOT>/validate/validate-2.interface
ip link delete dev awgv<PID>"

run_captured validateStagedAwgConfigs "${VALIDATION_WORK}" \
	"${VALIDATION_WORK}/server.conf" "${VALIDATION_WORK}/client-0.conf"
assert_eq "0" "${RUN_RC}" "staged validation accepts configurations the kernel datapath applies"
assert_eq "${VALIDATION_CALLS}" "$(normalized_calls)" \
	"staged validation applies every staged config to one kernel scratch interface, then deletes it"
assert_single_scratch_interface '^awgv[0-9]+$' "staged validation deletes the scratch interface it created"

BT_FAIL_LINK_ADD=1 run_captured validateStagedAwgConfigs "${VALIDATION_WORK}" \
	"${VALIDATION_WORK}/server.conf" "${VALIDATION_WORK}/client-0.conf"
if (( RUN_RC == 1 )) && [[ "$(normalized_calls)" == "ip link add dev awgv<PID> type amneziawg" ]] && \
	[[ "${RUN_ERR}" == "ERROR: could not create the temporary AWG configuration-validation interface" ]]; then
	ok "staged validation stops when the scratch interface cannot be created"
else
	not_ok "staged validation stops when the scratch interface cannot be created (rc ${RUN_RC}, calls '$(normalized_calls)', stderr '${RUN_ERR}')"
fi

BT_FAIL_SETCONF=1 run_captured validateStagedAwgConfigs "${VALIDATION_WORK}" \
	"${VALIDATION_WORK}/server.conf" "${VALIDATION_WORK}/client-0.conf"
assert_eq "1" "${RUN_RC}" "staged validation rejects a configuration the datapath refuses"
assert_eq "ip link add dev awgv<PID> type amneziawg
awg-quick strip <ROOT>/validate/server.conf
awg setconf awgv<PID> <ROOT>/validate/validate-1.interface
ip link delete dev awgv<PID>" "$(normalized_calls)" \
	"staged validation stops at the first rejected configuration and still deletes the scratch interface"

BT_FAIL_LINK_DELETE=1 run_captured validateStagedAwgConfigs "${VALIDATION_WORK}" \
	"${VALIDATION_WORK}/server.conf" "${VALIDATION_WORK}/client-0.conf"
assert_eq "1" "${RUN_RC}" "a failed scratch interface deletion fails staged validation"
assert_eq "${VALIDATION_CALLS}" "$(normalized_calls)" \
	"a failed scratch interface deletion happens after every staged config was applied"

echo "=== Protocol transaction runtime restart ==="

# Only the commands that touch the datapath or the service; the transaction's
# key checks and web-panel probes are covered by tests/test-awg3.sh.
datapath_calls() {
	normalized_calls | grep -E '^(ip |awg-quick |awg setconf |systemctl (is-active|stop|restart) )' || true
}

scenario_manual_transaction() {
	setup_fixture "${TEST_ROOT}/fixture-transaction"
	export BT_MANUAL_STATE="${TEST_ROOT}/fixture-transaction/manual-interface.active"
	: >"${BT_MANUAL_STATE}"
	set_awg3_state
	applyAwgProtocolTransaction
}
TRANSACTION_STATE="<ROOT>/fixture-transaction/state"
TRANSACTION_DIR="${TRANSACTION_STATE}/.awg-protocol.<X>"
TRANSACTION_CALLS="ip link add dev awgv<PID> type amneziawg
awg-quick strip ${TRANSACTION_DIR}/server.conf
awg setconf awgv<PID> ${TRANSACTION_DIR}/validate-1.interface
awg-quick strip ${TRANSACTION_DIR}/client-0.conf
awg setconf awgv<PID> ${TRANSACTION_DIR}/validate-2.interface
ip link delete dev awgv<PID>
systemctl is-active --quiet awg-quick@awgt0
ip link show dev awgt0
awg-quick down ${TRANSACTION_STATE}/awgt0.conf
awg-quick up ${TRANSACTION_STATE}/awgt0.conf"

run_captured scenario_manual_transaction
assert_eq "0" "${RUN_RC}" "a protocol transaction on a manually managed interface succeeds"
assert_eq "${TRANSACTION_CALLS}" "$(datapath_calls)" \
	"the transaction validates on a scratch interface, then cycles the manual interface with awg-quick down/up"
if [[ -e "${TEST_ROOT}/fixture-transaction/manual-interface.active" ]]; then
	ok "the manually managed interface is up again after the transaction"
else
	not_ok "the manually managed interface is up again after the transaction"
fi

BT_FAIL_UP=1 run_captured scenario_manual_transaction
if (( RUN_RC == 1 )) && [[ "${RUN_ERR}" == *"could not reactivate the previous AWG runtime"* ]]; then
	ok "a failed manual quick-up rolls back and reports the unrecoverable runtime"
else
	not_ok "a failed manual quick-up rolls back and reports the unrecoverable runtime (rc ${RUN_RC}, stderr '${RUN_ERR}')"
fi
assert_eq "${TRANSACTION_CALLS}
ip link show dev awgt0
awg-quick up ${TRANSACTION_STATE}/awgt0.conf" "$(datapath_calls)" \
	"rollback restarts the manual interface through the same quick-up"

echo "=== Management operations: datapath command sequences ==="

scenario_add_client() {
	setup_fixture "${TEST_ROOT}/fixture-add"
	mock_management
	nonInteractiveAddClient bob
}
ADD_CLIENT_CALLS="fn acquireClientLifecycleLock
fn loadParams[]
awg genkey
awg pubkey
awg genpsk
fn copyToWebPanelDir[<ROOT>/fixture-add/state/clients/awgt0-client-bob.conf]
fn ensureAmneziawgKernelModule[]
${SYNC_CALLS}"

run_captured scenario_add_client
assert_eq "0" "${RUN_RC}" "non-interactive client add succeeds"
assert_eq "${ADD_CLIENT_CALLS}" "$(normalized_calls)" \
	"non-interactive client add readies the kernel datapath, then syncs the interface"
assert_eq "${TEST_ROOT}/fixture-add/state/clients/awgt0-client-bob.conf" "$(tail -n 1 <<<"${RUN_OUT}")" \
	"non-interactive client add still prints the client config path last"
assert_eq "STRIP-WARNING awgt0" "${RUN_ERR}" \
	"non-interactive client add keeps syncconf stderr out of stderr on success"

BT_SYNC_RC=1 run_captured scenario_add_client
assert_eq "1" "${RUN_RC}" "non-interactive client add fails when the sync fails"
assert_eq "${ADD_CLIENT_CALLS}" "$(normalized_calls)" \
	"a failed sync after a client add runs the same commands"
assert_eq "STRIP-WARNING awgt0
ERROR: failed to sync AmneziaWG interface 'awgt0' after adding client 'bob'
SYNC-STDERR" "${RUN_ERR}" "a failed sync after a client add reports the syncconf stderr"

scenario_remove_client() {
	setup_fixture "${TEST_ROOT}/fixture-remove"
	mock_management
	nonInteractiveRemoveClient alice
}
REMOVE_CLIENT_CALLS="fn acquireClientLifecycleLock
fn loadParams[]
fn removeFromWebPanelDir[awgt0-client-alice.conf]
fn ensureAmneziawgKernelModule[]
${SYNC_CALLS}"

run_captured scenario_remove_client
assert_eq "0" "${RUN_RC}" "non-interactive client remove succeeds"
assert_eq "${REMOVE_CLIENT_CALLS}" "$(normalized_calls)" \
	"non-interactive client remove readies the kernel datapath, then syncs the interface"
assert_eq "OK" "${RUN_OUT}" "non-interactive client remove prints only OK"
assert_eq "STRIP-WARNING awgt0" "${RUN_ERR}" \
	"non-interactive client remove keeps syncconf output out of stderr on success"

BT_SYNC_RC=1 run_captured scenario_remove_client
assert_eq "1" "${RUN_RC}" "non-interactive client remove fails when the sync fails"
assert_eq "" "${RUN_OUT}" "a failed sync after a client remove prints nothing on stdout"
assert_eq "STRIP-WARNING awgt0
ERROR: failed to sync AmneziaWG interface 'awgt0' after removing client 'alice'
SYNC-STDOUT
SYNC-STDERR" "${RUN_ERR}" "a failed sync after a client remove reports the captured syncconf output"

scenario_new_client() {
	setup_fixture "${TEST_ROOT}/fixture-new-client"
	mock_management
	AUTO_INSTALL=y
	newClient
}
run_captured scenario_new_client
assert_eq "0" "${RUN_RC}" "interactive client add succeeds"
assert_eq "fn ensureAmneziawgKernelModule[]
awg genkey
awg pubkey
awg genpsk
fn copyToWebPanelDir[<ROOT>/fixture-new-client/state/home/client/awgt0-client-client.conf]
${SYNC_CALLS}
qrencode -t ansiutf8 -l L" "$(normalized_calls)" \
	"interactive client add readies the kernel datapath before key generation and syncs after writing"

scenario_revoke_client() {
	setup_fixture "${TEST_ROOT}/fixture-revoke"
	mock_management
	revokeClient
}
RUN_INPUT="1" run_captured scenario_revoke_client
assert_eq "0" "${RUN_RC}" "interactive client revoke succeeds"
assert_eq "fn removeFromWebPanelDir[awgt0-client-alice.conf]
fn ensureAmneziawgKernelModule[]
${SYNC_CALLS}" "$(normalized_calls)" \
	"interactive client revoke readies the kernel datapath, then syncs the interface"

scenario_regenerate_clients() {
	setup_fixture "${TEST_ROOT}/fixture-regenerate"
	mock_management
	# Without the old private key the client gets a new key pair, which is the
	# case where the server interface must be synced.
	rm -f -- "${AMNEZIAWG_DIR}/clients/${SERVER_AWG_NIC}-client-alice.conf"
	resolveWebPanelConfigDir() { printf '%s\n' "${AMNEZIAWG_DIR}/panel"; }
	regenerateClients
}
run_captured scenario_regenerate_clients
assert_eq "0" "${RUN_RC}" "client regeneration with new keys succeeds"
assert_eq "awg genkey
awg pubkey
fn copyToWebPanelDir[<ROOT>/fixture-regenerate/state/home/alice/awgt0-client-alice.conf]
qrencode -t ansiutf8 -l L
fn ensureAmneziawgKernelModule[]
${SYNC_CALLS}" "$(normalized_calls)" \
	"client regeneration with new keys readies the kernel datapath, then syncs the interface"

scenario_migration_reload() {
	setup_fixture "${TEST_ROOT}/fixture-migration"
	mock_management
	export BT_SERVICE_ACTIVE=1
	AUTO_INSTALL=y
	persistMigration "${SERVER_AWG_IPV6}" 0
}
run_captured scenario_migration_reload
assert_eq "0" "${RUN_RC}" "a legacy parameter migration with an active service succeeds"
assert_eq "systemctl is-active --quiet awg-quick@awgt0
awg-quick strip awgt0
${SYNC_CALLS}" "$(normalized_calls)" \
	"a legacy parameter migration validates with awg-quick strip, then syncs the running interface"

# Enabling AWG 3.0 readies the datapath in mode 0 before the capability probe.
scenario_protocol_mode() {
	setup_fixture "${TEST_ROOT}/fixture-protocol-mode"
	mock_management
	loadParams() {
		printf 'fn loadParams[%s]\n' "$*" >>"${BT_CALL_LOG}"
		AWG_BACKEND="${BT_LOADED_BACKEND:-kernel}"
	}
	awg2StateNeedsLegacyMigration() { return 1; }
	probeAwg3Capability() { printf 'fn probeAwg3Capability\n' >>"${BT_CALL_LOG}"; }
	applyAwgProtocolTransaction() { printf 'fn applyAwgProtocolTransaction\n' >>"${BT_CALL_LOG}"; }
	setAwgProtocolMode 3
}
run_captured scenario_protocol_mode
assert_eq "0" "${RUN_RC}" "enabling AWG 3.0 succeeds with the kernel backend"
assert_eq "fn acquireClientLifecycleLock
fn loadParams[0 1]
fn ensureAmneziawgKernelModule[0]
awg genkey
fn probeAwg3Capability
fn applyAwgProtocolTransaction" "$(normalized_calls)" \
	"enabling AWG 3.0 readies the kernel datapath in mode 0 before probing"

BT_LOADED_BACKEND="boringtun" run_captured scenario_protocol_mode
assert_eq "1" "${RUN_RC}" "enabling AWG 3.0 fails when the loaded backend is unsupported"
assert_eq "fn acquireClientLifecycleLock
fn loadParams[0 1]" "$(normalized_calls)" \
	"an unsupported loaded backend stops protocol changes before the datapath, probe or transaction"

echo "=== Seam routing ==="

# The kernel commands above cannot show whether management code reached them
# through the seam or around it, yet a bypass would skip every other backend.
# Wrap each seam operation so the call log records it, then require every
# datapath command to follow a call of the seam operation that owns it.
SEAM_OPERATIONS=(ensureAwgBackendReady awgBackendCreateScratchInterface
	awgBackendDestroyScratchInterface awgBackendQuickUp awgSyncInterfaceConfig)
wrap_seam_operations() {
	local OPERATION
	for OPERATION in "${SEAM_OPERATIONS[@]}"; do
		eval "seam_original_$(declare -f "${OPERATION}")"
		eval "${OPERATION}() {
			printf 'seam %s[%s]\n' '${OPERATION}' \"\$*\" >>\"\${BT_CALL_LOG}\"
			seam_original_${OPERATION} \"\$@\"
		}"
	done
}

with_wrapped_seam() {
	wrap_seam_operations
	"$@"
}

# Each seam call authorizes exactly one datapath command. `awg-quick down`,
# `awg setconf` on a scratch interface and deleting the production interface
# are backend-neutral and stay outside the seam.
assert_datapath_through_seam() {
	local NAME="$1"
	local REPORT
	REPORT="$(awk '
		function need(operation) {
			checked++
			if (last != operation) {
				printf "%s (after %s)\n", $0, (last == "" ? "no seam call" : last)
			}
			last = ""
		}
		/^seam / { last = $2; sub(/\[.*/, "", last); next }
		/^ip link add dev / { need("awgBackendCreateScratchInterface"); next }
		/^ip link delete dev awg[pv][0-9]+$/ { need("awgBackendDestroyScratchInterface"); next }
		/^awg-quick up / { need("awgBackendQuickUp"); next }
		/^awg syncconf / { need("awgSyncInterfaceConfig"); next }
		/^fn ensureAmneziawgKernelModule\[/ { need("ensureAwgBackendReady"); next }
		END { if (checked == 0) print "no datapath command was issued" }
	' "${BT_CALL_LOG}")"
	if [[ -z "${REPORT}" ]]; then
		ok "${NAME}"
	else
		not_ok "${NAME}: ${REPORT}"
	fi
}

run_captured with_wrapped_seam probeAwg3Capability "${MOCK_KEY}"
assert_datapath_through_seam "the AWG 3.0 probe reaches the datapath only through the seam"
run_captured with_wrapped_seam probeAwg31Capability "${MOCK_KEY}"
assert_datapath_through_seam "the AWG 3.1 probe reaches the datapath only through the seam"
run_captured with_wrapped_seam validateStagedAwgConfigs "${VALIDATION_WORK}" \
	"${VALIDATION_WORK}/server.conf" "${VALIDATION_WORK}/client-0.conf"
assert_datapath_through_seam "staged validation reaches the datapath only through the seam"
run_captured with_wrapped_seam scenario_manual_transaction
assert_datapath_through_seam "a protocol transaction reaches the datapath only through the seam"
BT_FAIL_UP=1 run_captured with_wrapped_seam scenario_manual_transaction
assert_datapath_through_seam "a protocol transaction rollback reaches the datapath only through the seam"
run_captured with_wrapped_seam scenario_add_client
assert_datapath_through_seam "non-interactive client add reaches the datapath only through the seam"
run_captured with_wrapped_seam scenario_remove_client
assert_datapath_through_seam "non-interactive client remove reaches the datapath only through the seam"
run_captured with_wrapped_seam scenario_new_client
assert_datapath_through_seam "interactive client add reaches the datapath only through the seam"
RUN_INPUT="1" run_captured with_wrapped_seam scenario_revoke_client
assert_datapath_through_seam "interactive client revoke reaches the datapath only through the seam"
run_captured with_wrapped_seam scenario_regenerate_clients
assert_datapath_through_seam "client regeneration reaches the datapath only through the seam"
run_captured with_wrapped_seam scenario_migration_reload
assert_datapath_through_seam "a legacy parameter migration reaches the datapath only through the seam"
run_captured with_wrapped_seam scenario_protocol_mode
assert_datapath_through_seam "enabling AWG 3.0 reaches the datapath only through the seam"

printf '\n%d tests, %d failures\n' "$((PASS + FAIL))" "${FAIL}"
(( FAIL == 0 ))
