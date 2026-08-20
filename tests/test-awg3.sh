#!/usr/bin/env bash

# The test intentionally sets globals consumed by functions sourced from the
# installer; ShellCheck cannot follow those cross-file references.
# shellcheck disable=SC2034

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/awg3-tests.XXXXXX")"
BIN_DIR="${TEST_ROOT}/bin"
TEST_TMPDIR="${TEST_ROOT}/tmp"
mkdir -p "${BIN_DIR}" "${TEST_TMPDIR}"

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

assert_eq() {
	local EXPECTED="$1"
	local ACTUAL="$2"
	local NAME="$3"
	if [[ "${ACTUAL}" == "${EXPECTED}" ]]; then
		ok "${NAME}"
	else
		not_ok "${NAME} (expected '${EXPECTED}', got '${ACTUAL}')"
	fi
}

# shellcheck source=../amneziawg-install.sh
source "${PROJECT_ROOT}/amneziawg-install.sh"

MOCK_KEY="YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
export MOCK_KEY

cat >"${BIN_DIR}/awg" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
	genkey)
		printf '%s\n' "${MOCK_KEY}"
		;;
	pubkey)
		read -r _key
		printf '%s\n' 'cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A='
		;;
	setconf)
		[[ "${AWG3_TEST_FAIL_SET:-0}" == "0" ]] || exit 1
		if grep -q '^HeaderProtectionKey = ' "$3"; then
			grep -q '^ContentPaddingAddition = ' "$3" || exit 1
		fi
		;;
	syncconf)
		exit 0
		;;
	show)
		case "${3:-}" in
			header-protection-key) printf '%s\n' "${MOCK_KEY}" ;;
			content-padding-addition) printf '%s\n' "${AWG3_TEST_CONTENT_READBACK:-11-13}" ;;
			rekey-after-time) printf '%s\n' '101-103' ;;
			rekey-timeout) printf '%s\n' '5-7' ;;
			reject-after-time) printf '%s\n' '181-183' ;;
			keepalive-timeout) printf '%s\n' '9-11' ;;
			*) exit 1 ;;
		esac
		;;
	*) exit 1 ;;
esac
EOF
chmod +x "${BIN_DIR}/awg"

cat >"${BIN_DIR}/ip" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${AWG3_TEST_IP_LOG}"
if [[ "${1:-}" == "link" && "${2:-}" == "show" ]]; then
	if [[ "${4:-}" == "${AWG3_TEST_SERVER_INTERFACE:-}" && \
		-n "${AWG3_TEST_MANUAL_STATE:-}" && -e "${AWG3_TEST_MANUAL_STATE}" ]]; then
		exit 0
	fi
	exit 1
fi
if [[ "${1:-}" == "link" && "${2:-}" == "delete" && \
	"${4:-}" == "${AWG3_TEST_SERVER_INTERFACE:-}" && -n "${AWG3_TEST_MANUAL_STATE:-}" ]]; then
	rm -f -- "${AWG3_TEST_MANUAL_STATE}"
fi
exit 0
EOF
chmod +x "${BIN_DIR}/ip"

cat >"${BIN_DIR}/awg-quick" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
	strip)
		[[ -f "${2:-}" ]] || exit 1
		[[ "$(basename -- "${2}")" =~ ^[a-zA-Z0-9_=+.-]{1,15}\.conf$ ]] || exit 1
		sed -E '/^(Address|DNS|PostUp|PostDown)[[:space:]]*=/d' "$2"
		;;
	down)
		printf 'down %s\n' "${2:-}" >>"${AWG3_TEST_AWG_QUICK_LOG}"
		[[ "${AWG3_TEST_FAIL_MANUAL_DOWN:-0}" != "1" ]] || exit 1
		[[ -z "${AWG3_TEST_MANUAL_STATE:-}" ]] || rm -f -- "${AWG3_TEST_MANUAL_STATE}"
		;;
	up)
		printf 'up %s\n' "${2:-}" >>"${AWG3_TEST_AWG_QUICK_LOG}"
		[[ "${AWG3_TEST_FAIL_MANUAL_UP:-0}" != "1" ]] || exit 1
		if [[ -n "${AWG3_TEST_MANUAL_STATE:-}" ]]; then
			: >"${AWG3_TEST_MANUAL_STATE}"
		fi
		;;
	*) exit 1 ;;
esac
EOF
chmod +x "${BIN_DIR}/awg-quick"

cat >"${BIN_DIR}/getent" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "passwd" && "${2:-}" == "alice" && -n "${AWG3_TEST_CUSTOM_HOME:-}" ]]; then
	printf 'alice:x:1001:1001:Alice:%s:/bin/bash\n' "${AWG3_TEST_CUSTOM_HOME}"
	exit 0
fi
exit 2
EOF
chmod +x "${BIN_DIR}/getent"

cat >"${BIN_DIR}/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
	is-active)
		[[ "${AWG3_TEST_SERVICE_ACTIVE:-0}" == "1" ]]
		;;
	restart)
		if [[ -n "${AWG3_TEST_SYSTEMCTL_LOG:-}" ]]; then
			printf 'restart %s\n' "${2:-}" >>"${AWG3_TEST_SYSTEMCTL_LOG}"
		fi
		if [[ -n "${AWG3_TEST_RESTART_FAIL_STATE:-}" && -f "${AWG3_TEST_RESTART_FAIL_STATE}" ]]; then
			remaining="$(cat "${AWG3_TEST_RESTART_FAIL_STATE}" 2>/dev/null || printf '0')"
			if [[ "${remaining}" =~ ^[0-9]+$ ]] && (( remaining > 0 )); then
				printf '%s\n' "$((remaining - 1))" >"${AWG3_TEST_RESTART_FAIL_STATE}"
				exit 1
			fi
		fi
		[[ "${AWG3_TEST_RESTART_FAIL:-0}" != "1" ]]
		;;
	stop)
		if [[ "${AWG3_TEST_SIGNAL_ON_STOP:-0}" == "1" ]]; then
			kill -TERM "${PPID}"
		fi
		;;
	*) exit 0 ;;
esac
EOF
chmod +x "${BIN_DIR}/systemctl"

export PATH="${BIN_DIR}:${PATH}"
export TMPDIR="${TEST_TMPDIR}"
export AWG3_TEST_IP_LOG="${TEST_ROOT}/ip.log"
export AWG3_TEST_AWG_QUICK_LOG="${TEST_ROOT}/awg-quick.log"

echo "=== AWG 3.0 compatibility and capability helpers ==="

AWG_PROTOCOL_VERSION=""
normalizeAwgProtocolVersion
assert_eq "2" "${AWG_PROTOCOL_VERSION}" "missing protocol state normalizes to AWG 2.0"

AWG_PROTOCOL_VERSION="2.0"
normalizeAwgProtocolVersion
assert_eq "2" "${AWG_PROTOCOL_VERSION}" "legacy 2.0 alias normalizes to AWG 2.0"

AWG_PROTOCOL_VERSION="2"
AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
AWG_CONTENT_PADDING_ADDITION="10-100"
assert_eq "" "$(renderAwgProtocolFields)" "AWG 2.0 rendering omits every AWG 3.0 field"

SERVER_AWG_S1=12
SERVER_AWG_S2=13
SERVER_AWG_S3=14
SERVER_AWG_S4=15
AWG_PROTOCOL_VERSION=3
AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
AWG_CONTENT_PADDING_ADDITION="10-100"
AWG_REKEY_AFTER_TIME="100-120"
AWG_REKEY_TIMEOUT="3-7"
AWG_REJECT_AFTER_TIME="150-180"
AWG_KEEPALIVE_TIMEOUT="5-15"
FIELDS="$(renderAwgProtocolFields)"
if grep -q '^HeaderProtectionKey = ' <<<"${FIELDS}" && \
	grep -q '^ContentPaddingAddition = 10-100$' <<<"${FIELDS}" && \
	grep -q '^KeepaliveTimeout = 5-15$' <<<"${FIELDS}"; then
	ok "AWG 3.0 rendering includes validated optional fields"
else
	not_ok "AWG 3.0 rendering includes validated optional fields"
fi

if validateAwg3Range "test" "20-10" >/dev/null 2>&1; then
	not_ok "descending AWG 3.0 ranges are rejected"
else
	ok "descending AWG 3.0 ranges are rejected"
fi
if validateAwg3Range "test" "65536" >/dev/null 2>&1; then
	not_ok "out-of-range AWG 3.0 values are rejected"
else
	ok "out-of-range AWG 3.0 values are rejected"
fi
if validateAwg3Range "test" "999999999999999999999999" >/dev/null 2>&1; then
	not_ok "oversized AWG 3.0 values are rejected without arithmetic overflow"
else
	ok "oversized AWG 3.0 values are rejected without arithmetic overflow"
fi

SERVER_AWG_S4=11
ERROR_OUTPUT="$(validateAwg3Params 2>&1 || true)"
if [[ "${ERROR_OUTPUT}" == *"SERVER_AWG_S4 must be at least 12"* ]] && \
	[[ "${ERROR_OUTPUT}" != *"${MOCK_KEY}"* ]]; then
	ok "header-protection padding errors reject S1-S4 below 12 without leaking the key"
else
	not_ok "header-protection padding errors reject S1-S4 below 12 without leaking the key"
fi
SERVER_AWG_S4=15

AWG_HEADER_PROTECTION_KEY="invalid"
if validatePersistedAwgProtocolState >/dev/null 2>&1; then
	not_ok "invalid AWG 3.0 state fails closed for normal management operations"
else
	ok "invalid AWG 3.0 state fails closed for normal management operations"
fi
if validatePersistedAwgProtocolState 1 >/dev/null 2>&1; then
	ok "explicit AWG 2.0 downgrade can recover from damaged AWG 3.0-only state"
else
	not_ok "explicit AWG 2.0 downgrade can recover from damaged AWG 3.0-only state"
fi
AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"

RECOVERY_MIGRATION_LOG="${TEST_ROOT}/recovery-migrations.log"
: >"${RECOVERY_MIGRATION_LOG}"
if (
	validateParamsFile() { return 0; }
	migrateS3S4() { printf 's3s4\n' >>"${RECOVERY_MIGRATION_LOG}"; return 0; }
	migrateH1H4() { printf 'h1h4\n' >>"${RECOVERY_MIGRATION_LOG}"; return 0; }
	persistMigration() { printf 'persist\n' >>"${RECOVERY_MIGRATION_LOG}"; }
	quietIPv6Rewrite() { printf 'ipv6\n' >>"${RECOVERY_MIGRATION_LOG}"; }
	loadParams 1 1
) && [[ ! -s "${RECOVERY_MIGRATION_LOG}" ]]; then
	ok "AWG 2.0 recovery loading does not mutate legacy protocol state before the transaction"
else
	not_ok "AWG 2.0 recovery loading does not mutate legacy protocol state before the transaction"
fi

ENABLE_LEGACY_ORDER="${TEST_ROOT}/enable-legacy-order.log"
: >"${ENABLE_LEGACY_ORDER}"
if (
	AWG_PROTOCOL_VERSION=2
	acquireClientLifecycleLock() { printf 'lock\n' >>"${ENABLE_LEGACY_ORDER}"; }
	loadParams() {
		printf 'load-%s-%s\n' "${1:-}" "${2:-}" >>"${ENABLE_LEGACY_ORDER}"
		AWG_PROTOCOL_VERSION=2
	}
	awg2StateNeedsLegacyMigration() {
		printf 'legacy\n' >>"${ENABLE_LEGACY_ORDER}"
		return 0
	}
	probeAwg3Capability() { printf 'probe\n' >>"${ENABLE_LEGACY_ORDER}"; }
	applyAwgProtocolTransaction() { printf 'apply\n' >>"${ENABLE_LEGACY_ORDER}"; }
	if setAwgProtocolMode 3 >/dev/null 2>&1; then
		exit 1
	fi
) && [[ "$(paste -sd, "${ENABLE_LEGACY_ORDER}")" == "lock,load-0-1,legacy" ]]; then
	ok "AWG 3.0 enablement rejects pending AWG 2.0 migration before capability probing or writes"
else
	not_ok "AWG 3.0 enablement rejects pending AWG 2.0 migration before capability probing or writes"
fi

ENABLE_MODULE_ONLY_LOG="${TEST_ROOT}/enable-module-only.log"
: >"${ENABLE_MODULE_ONLY_LOG}"
if (
	AWG_PROTOCOL_VERSION=2
	clearAwg3Params
	acquireClientLifecycleLock() { printf 'lock\n' >>"${ENABLE_MODULE_ONLY_LOG}"; }
	loadParams() {
		printf 'load\n' >>"${ENABLE_MODULE_ONLY_LOG}"
		AWG_PROTOCOL_VERSION=2
	}
	awg2StateNeedsLegacyMigration() { return 1; }
	ensureAmneziawgKernelModule() { printf 'ensure-module-%s\n' "${1:-}" >>"${ENABLE_MODULE_ONLY_LOG}"; }
	probeAwg3Capability() { printf 'probe\n' >>"${ENABLE_MODULE_ONLY_LOG}"; }
	applyAwgProtocolTransaction() { printf 'apply\n' >>"${ENABLE_MODULE_ONLY_LOG}"; }
	setAwgProtocolMode 3 >/dev/null 2>&1
) && [[ "$(paste -sd, "${ENABLE_MODULE_ONLY_LOG}")" == "lock,load,ensure-module-0,probe,apply" ]]; then
	ok "AWG 3.0 transitions prepare the module without starting the managed service"
else
	not_ok "AWG 3.0 transitions prepare the module without starting the managed service"
fi

PROTOCOL_LOCK_ORDER="${TEST_ROOT}/protocol-lock-order.log"
: >"${PROTOCOL_LOCK_ORDER}"
if (
	AWG_PROTOCOL_VERSION=2
	acquireClientLifecycleLock() { printf 'lock\n' >>"${PROTOCOL_LOCK_ORDER}"; }
	loadParams() {
		printf 'load\n' >>"${PROTOCOL_LOCK_ORDER}"
		AWG_PROTOCOL_VERSION=3
		AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
	}
	applyAwgProtocolTransaction() {
		printf 'apply-%s\n' "${AWG_PROTOCOL_VERSION}" >>"${PROTOCOL_LOCK_ORDER}"
		[[ "${AWG_PROTOCOL_VERSION}" == "2" ]]
	}
	setAwgProtocolMode 2 >/dev/null
) && [[ "$(paste -sd, "${PROTOCOL_LOCK_ORDER}")" == "lock,load,apply-2" ]]; then
	ok "protocol changes lock and reload persisted state before deciding a toggle is a no-op"
else
	not_ok "protocol changes lock and reload persisted state before deciding a toggle is a no-op"
fi

MANAGEMENT_LOCK_ORDER="${TEST_ROOT}/management-lock-order.log"
: >"${MANAGEMENT_LOCK_ORDER}"
if (
	AWG_PROTOCOL_VERSION=2
	acquireClientLifecycleLock() { printf 'lock\n' >>"${MANAGEMENT_LOCK_ORDER}"; }
	loadParams() {
		printf 'load\n' >>"${MANAGEMENT_LOCK_ORDER}"
		AWG_PROTOCOL_VERSION=3
	}
	_testManagementMutation() { printf 'mutate-%s\n' "${AWG_PROTOCOL_VERSION}" >>"${MANAGEMENT_LOCK_ORDER}"; }
	runLockedManagementOperation _testManagementMutation
) && [[ "$(paste -sd, "${MANAGEMENT_LOCK_ORDER}")" == "lock,load,mutate-3" ]]; then
	ok "interactive mutations lock and reload current protocol state before writing"
else
	not_ok "interactive mutations lock and reload current protocol state before writing"
fi

MENU_LOAD_LOCK_ORDER="${TEST_ROOT}/menu-load-lock-order.log"
: >"${MENU_LOAD_LOCK_ORDER}"
if (
	acquireClientLifecycleLock() { printf 'lock\n' >>"${MENU_LOAD_LOCK_ORDER}"; }
	loadParams() { printf 'load\n' >>"${MENU_LOAD_LOCK_ORDER}"; }
	releaseClientLifecycleLock() { printf 'release\n' >>"${MENU_LOAD_LOCK_ORDER}"; }
	loadParamsForManagementMenu
) && [[ "$(paste -sd, "${MENU_LOAD_LOCK_ORDER}")" == "lock,load,release" ]]; then
	ok "interactive menu preload releases the lifecycle lock before waiting for input"
else
	not_ok "interactive menu preload releases the lifecycle lock before waiting for input"
fi

SAME_MODE_REPAIR_LOG="${TEST_ROOT}/same-mode-repair.log"
: >"${SAME_MODE_REPAIR_LOG}"
if (
	AWG_PROTOCOL_VERSION=3
	AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
	AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
	AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
	AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
	AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
	AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
	acquireClientLifecycleLock() { printf 'lock\n' >>"${SAME_MODE_REPAIR_LOG}"; }
	loadParams() { printf 'load-%s-%s\n' "${1:-}" "${2:-}" >>"${SAME_MODE_REPAIR_LOG}"; }
	ensureAmneziawgKernelModule() { printf 'ensure-module-%s\n' "${1:-}" >>"${SAME_MODE_REPAIR_LOG}"; }
	awgProtocolConfigsMatchPersistedState() { printf 'verify\n' >>"${SAME_MODE_REPAIR_LOG}"; return 1; }
	probeAwg3Capability() { printf 'probe-%s\n' "$1" >>"${SAME_MODE_REPAIR_LOG}"; }
	applyAwgProtocolTransaction() {
		printf 'apply-%s-%s\n' "${AWG_PROTOCOL_VERSION}" "${AWG_HEADER_PROTECTION_KEY}" >>"${SAME_MODE_REPAIR_LOG}"
	}
	setAwgProtocolMode 3 >/dev/null 2>&1
) && [[ "$(paste -sd, "${SAME_MODE_REPAIR_LOG}")" == "lock,load-0-1,ensure-module-0,probe-${MOCK_KEY},verify,apply-3-${MOCK_KEY}" ]]; then
	ok "same-mode AWG 3.0 requests re-probe support and repair without rotating the key"
else
	not_ok "same-mode AWG 3.0 requests re-probe support and repair without rotating the key"
fi

SAME_MODE_AWG3_PROBE_LOG="${TEST_ROOT}/same-mode-awg3-probe.log"
: >"${SAME_MODE_AWG3_PROBE_LOG}"
if (
	AWG_PROTOCOL_VERSION=3
	AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
	AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
	AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
	AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
	AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
	AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
	acquireClientLifecycleLock() { printf 'lock\n' >>"${SAME_MODE_AWG3_PROBE_LOG}"; }
	loadParams() { printf 'load\n' >>"${SAME_MODE_AWG3_PROBE_LOG}"; }
	ensureAmneziawgKernelModule() { printf 'ensure-module-%s\n' "${1:-}" >>"${SAME_MODE_AWG3_PROBE_LOG}"; }
	probeAwg3Capability() { printf 'probe-%s\n' "$1" >>"${SAME_MODE_AWG3_PROBE_LOG}"; return 1; }
	awgProtocolConfigsMatchPersistedState() { printf 'unexpected-verify\n' >>"${SAME_MODE_AWG3_PROBE_LOG}"; }
	applyAwgProtocolTransaction() { printf 'unexpected-apply\n' >>"${SAME_MODE_AWG3_PROBE_LOG}"; }
	if setAwgProtocolMode 3 >/dev/null 2>&1; then
		exit 1
	fi
) && [[ "$(paste -sd, "${SAME_MODE_AWG3_PROBE_LOG}")" == "lock,load,ensure-module-0,probe-${MOCK_KEY}" ]]; then
	ok "same-mode AWG 3.0 requests fail closed when the current kernel probe fails"
else
	not_ok "same-mode AWG 3.0 requests fail closed when the current kernel probe fails"
fi

SAME_MODE_NOOP_LOG="${TEST_ROOT}/same-mode-noop.log"
: >"${SAME_MODE_NOOP_LOG}"
if (
	AWG_PROTOCOL_VERSION=2
	clearAwg3Params
	acquireClientLifecycleLock() { printf 'lock\n' >>"${SAME_MODE_NOOP_LOG}"; }
	loadParams() { printf 'load\n' >>"${SAME_MODE_NOOP_LOG}"; }
	awgProtocolConfigsMatchPersistedState() { printf 'verify\n' >>"${SAME_MODE_NOOP_LOG}"; return 0; }
	applyAwgProtocolTransaction() { printf 'unexpected-apply\n' >>"${SAME_MODE_NOOP_LOG}"; return 1; }
	setAwgProtocolMode 2 >/dev/null 2>&1
) && [[ "$(paste -sd, "${SAME_MODE_NOOP_LOG}")" == "lock,load,verify" ]]; then
	ok "same-mode requests remain no-ops when persisted state and configs agree"
else
	not_ok "same-mode requests remain no-ops when persisted state and configs agree"
fi

: >"${AWG3_TEST_IP_LOG}"
if probeAwg3Capability "${MOCK_KEY}"; then
	if grep -q '^link add dev awgp' "${AWG3_TEST_IP_LOG}" && \
		grep -q '^link delete dev awgp' "${AWG3_TEST_IP_LOG}"; then
		ok "capability probe applies, reads back, and removes its temporary interface"
	else
		not_ok "capability probe applies, reads back, and removes its temporary interface"
	fi
else
	not_ok "capability probe accepts matching userspace/kernel readback"
fi

: >"${AWG3_TEST_IP_LOG}"
AWG3_TEST_FAIL_SET=1
export AWG3_TEST_FAIL_SET
if probeAwg3Capability "${MOCK_KEY}" >/dev/null 2>&1; then
	not_ok "capability probe fails closed when netlink application fails"
else
	if grep -q '^link delete dev awgp' "${AWG3_TEST_IP_LOG}"; then
		ok "capability probe fails closed and cleans up after netlink failure"
	else
		not_ok "capability probe fails closed and cleans up after netlink failure"
	fi
fi
unset AWG3_TEST_FAIL_SET

: >"${AWG3_TEST_IP_LOG}"
AWG3_TEST_CONTENT_READBACK="11-14"
export AWG3_TEST_CONTENT_READBACK
if probeAwg3Capability "${MOCK_KEY}" >/dev/null 2>&1; then
	not_ok "capability probe rejects mismatched kernel readback"
else
	if grep -q '^link delete dev awgp' "${AWG3_TEST_IP_LOG}"; then
		ok "capability probe rejects mismatched readback and cleans up"
	else
		not_ok "capability probe rejects mismatched readback and cleans up"
	fi
fi
unset AWG3_TEST_CONTENT_READBACK

# Build a complete AWG 2.0 fixture and exercise both directions of the file
# transaction. The active client key must match its server peer key.
AMNEZIAWG_DIR="${TEST_ROOT}/state"
WEB_PANEL_CONFIG_DIR="${AMNEZIAWG_DIR}/clients"
SERVER_AWG_NIC="awgt0"
export AWG3_TEST_SERVER_INTERFACE="${SERVER_AWG_NIC}"
SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
mkdir -p "${AMNEZIAWG_DIR}/clients"
SERVER_PUB_IP="198.51.100.10"
SERVER_PUB_NIC="eth0"
SERVER_AWG_IPV4="10.66.66.1"
SERVER_AWG_IPV6="fd42:42:42::1"
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
EXPECTED_CLIENT_PUB="cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="
AWG_PROTOCOL_VERSION=2
clearAwg3Params

cat >"${SERVER_AWG_CONF}" <<EOF
[Interface]
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
PublicKey = ${EXPECTED_CLIENT_PUB}
PresharedKey = cHNrMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM=
AllowedIPs = 10.66.66.2/32
EOF
CLIENT_CONF="${AMNEZIAWG_DIR}/clients/${SERVER_AWG_NIC}-client-alice.conf"
cat >"${CLIENT_CONF}" <<EOF
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
PresharedKey = cHNrMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM=
Endpoint = 198.51.100.10:51820
AllowedIPs = 0.0.0.0/0
EOF
chmod 600 "${SERVER_AWG_CONF}"
chmod 640 "${CLIENT_CONF}"
serializeParams "${AMNEZIAWG_DIR}/params"
chmod 600 "${AMNEZIAWG_DIR}/params"

if awgProtocolConfigsMatchPersistedState; then
	ok "AWG 2.0 consistency verification accepts matching server and client configs"
else
	not_ok "AWG 2.0 consistency verification accepts matching server and client configs"
fi

AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
if awgProtocolConfigsMatchPersistedState >/dev/null 2>&1; then
	not_ok "AWG 2.0 consistency verification rejects dormant AWG 3.0 params"
else
	ok "AWG 2.0 consistency verification rejects dormant AWG 3.0 params"
fi
clearAwg3Params

CLIENT_CONSISTENCY_BACKUP="${TEST_ROOT}/client-consistency.backup"
cp -p "${CLIENT_CONF}" "${CLIENT_CONSISTENCY_BACKUP}"
printf '\nHeaderProtectionKey = %s\n' "${MOCK_KEY}" >>"${CLIENT_CONF}"
if awgProtocolConfigsMatchPersistedState >/dev/null 2>&1; then
	not_ok "AWG 2.0 consistency verification rejects stale client protocol fields"
else
	ok "AWG 2.0 consistency verification rejects stale client protocol fields"
fi
cp -p "${CLIENT_CONSISTENCY_BACKUP}" "${CLIENT_CONF}"

SERVER_MANAGED_BACKUP="${TEST_ROOT}/server-managed.backup"
cp -p "${SERVER_AWG_CONF}" "${SERVER_MANAGED_BACKUP}"
printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.66.66.99/32\n' \
	"${EXPECTED_CLIENT_PUB}" >>"${SERVER_AWG_CONF}"
declare -a UNMANAGED_CLIENTS=()
if collectActiveAwgClientConfigs UNMANAGED_CLIENTS >/dev/null 2>&1; then
	not_ok "protocol migration rejects an unmarked server peer"
else
	ok "protocol migration rejects an unmarked server peer"
fi
cp -p "${SERVER_MANAGED_BACKUP}" "${SERVER_AWG_CONF}"

CUSTOM_HOME="${TEST_ROOT}/custom-home"
CUSTOM_CLIENT_CONF="${CUSTOM_HOME}/${SERVER_AWG_NIC}-client-alice.conf"
mkdir -p "${CUSTOM_HOME}"
cp -p "${CLIENT_CONF}" "${CUSTOM_CLIENT_CONF}"
export AWG3_TEST_CUSTOM_HOME="${CUSTOM_HOME}"
declare -a CUSTOM_HOME_CANDIDATES=()
CUSTOM_CLIENT_CANONICAL="$(readlink -f -- "${CUSTOM_CLIENT_CONF}")"
CUSTOM_HOME_FOUND=0
if collectAwgClientConfigCandidates CUSTOM_HOME_CANDIDATES; then
	for CANDIDATE in "${CUSTOM_HOME_CANDIDATES[@]}"; do
		[[ "${CANDIDATE}" == "${CUSTOM_CLIENT_CANONICAL}" ]] && CUSTOM_HOME_FOUND=1
	done
fi
if (( CUSTOM_HOME_FOUND )); then
	ok "protocol migration discovers managed client configs in NSS custom home directories"
else
	not_ok "protocol migration discovers managed client configs in NSS custom home directories"
fi
unset AWG3_TEST_CUSTOM_HOME
rm -rf -- "${CUSTOM_HOME}"

ROUND_TRIP_SERVER_BEFORE="$(sha256sum "${SERVER_AWG_CONF}")"
ROUND_TRIP_PARAMS_BEFORE="$(sha256sum "${AMNEZIAWG_DIR}/params")"
ROUND_TRIP_CLIENT_BEFORE="$(sha256sum "${CLIENT_CONF}")"
AWG_PROTOCOL_VERSION=3
AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
if applyAwgProtocolTransaction && \
	grep -q "^AWG_PROTOCOL_VERSION='3'$" "${AMNEZIAWG_DIR}/params" && \
	grep -q "^HeaderProtectionKey = ${MOCK_KEY}$" "${SERVER_AWG_CONF}" && \
	grep -q "^HeaderProtectionKey = ${MOCK_KEY}$" "${CLIENT_CONF}" && \
	[[ "$(stat -c '%a' "${CLIENT_CONF}")" == "640" ]]; then
	ok "AWG 3.0 transaction updates params, server, and every active client"
else
	not_ok "AWG 3.0 transaction updates params, server, and every active client"
fi

if awgProtocolConfigsMatchPersistedState; then
	ok "AWG 3.0 consistency verification accepts matching server and client fields"
else
	not_ok "AWG 3.0 consistency verification accepts matching server and client fields"
fi

CLIENT_AWG3_CONSISTENCY_BACKUP="${TEST_ROOT}/client-awg3-consistency.backup"
cp -p "${CLIENT_CONF}" "${CLIENT_AWG3_CONSISTENCY_BACKUP}"
sed -i 's/^RekeyTimeout = .*/RekeyTimeout = 99/' "${CLIENT_CONF}"
if awgProtocolConfigsMatchPersistedState >/dev/null 2>&1; then
	not_ok "AWG 3.0 consistency verification rejects a mismatched client field"
else
	ok "AWG 3.0 consistency verification rejects a mismatched client field"
fi
cp -p "${CLIENT_AWG3_CONSISTENCY_BACKUP}" "${CLIENT_CONF}"

AWG_PROTOCOL_VERSION=2
clearAwg3Params
: >"${AWG3_TEST_AWG_QUICK_LOG}"
AWG3_TEST_MANUAL_STATE="${TEST_ROOT}/manual-interface.active"
export AWG3_TEST_MANUAL_STATE
: >"${AWG3_TEST_MANUAL_STATE}"
if applyAwgProtocolTransaction && \
	grep -q "^AWG_PROTOCOL_VERSION='2'$" "${AMNEZIAWG_DIR}/params" && \
	! grep -q '^HeaderProtectionKey = ' "${SERVER_AWG_CONF}" && \
	! grep -q '^HeaderProtectionKey = ' "${CLIENT_CONF}" && \
	[[ "$(sha256sum "${SERVER_AWG_CONF}")" == "${ROUND_TRIP_SERVER_BEFORE}" ]] && \
	[[ "$(sha256sum "${AMNEZIAWG_DIR}/params")" == "${ROUND_TRIP_PARAMS_BEFORE}" ]] && \
	[[ "$(sha256sum "${CLIENT_CONF}")" == "${ROUND_TRIP_CLIENT_BEFORE}" ]] && \
	[[ -e "${AWG3_TEST_MANUAL_STATE}" ]] && \
	[[ "$(sed -n '1p' "${AWG3_TEST_AWG_QUICK_LOG}")" == "down ${SERVER_AWG_CONF}" ]] && \
	[[ "$(sed -n '2p' "${AWG3_TEST_AWG_QUICK_LOG}")" == "up ${SERVER_AWG_CONF}" ]]; then
	ok "AWG 2.0 downgrade is byte-identical and recreates a manually active interface"
else
	not_ok "AWG 2.0 downgrade is byte-identical and recreates a manually active interface"
fi
unset AWG3_TEST_MANUAL_STATE

SERVER_BEFORE="$(sha256sum "${SERVER_AWG_CONF}")"
PARAMS_BEFORE="$(sha256sum "${AMNEZIAWG_DIR}/params")"
CLIENT_BEFORE="$(sha256sum "${CLIENT_CONF}")"
AWG_PROTOCOL_VERSION=3
AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
AWG3_TEST_RESTART_FAIL_STATE="${TEST_ROOT}/restart-fail-state"
AWG3_TEST_SYSTEMCTL_LOG="${TEST_ROOT}/systemctl.log"
printf '1\n' >"${AWG3_TEST_RESTART_FAIL_STATE}"
: >"${AWG3_TEST_SYSTEMCTL_LOG}"
export AWG3_TEST_SERVICE_ACTIVE=1 AWG3_TEST_RESTART_FAIL_STATE AWG3_TEST_SYSTEMCTL_LOG
if applyAwgProtocolTransaction >/dev/null 2>&1; then
	not_ok "failed service apply triggers rollback"
elif [[ "$(sha256sum "${SERVER_AWG_CONF}")" == "${SERVER_BEFORE}" ]] && \
	[[ "$(sha256sum "${AMNEZIAWG_DIR}/params")" == "${PARAMS_BEFORE}" ]] && \
	[[ "$(sha256sum "${CLIENT_CONF}")" == "${CLIENT_BEFORE}" ]] && \
	[[ "$(grep -c '^restart ' "${AWG3_TEST_SYSTEMCTL_LOG}")" == "2" ]] && \
	! compgen -G "${AMNEZIAWG_DIR}/.awg-protocol.*" >/dev/null; then
	ok "failed service apply restores files and reactivates the previous service"
else
	not_ok "failed service apply restores files and reactivates the previous service"
fi
unset AWG3_TEST_SERVICE_ACTIVE

printf '2\n' >"${AWG3_TEST_RESTART_FAIL_STATE}"
: >"${AWG3_TEST_SYSTEMCTL_LOG}"
export AWG3_TEST_SERVICE_ACTIVE=1 AWG3_TEST_RESTART_FAIL_STATE AWG3_TEST_SYSTEMCTL_LOG
ROLLBACK_OUTPUT="$(applyAwgProtocolTransaction 2>&1 || true)"
mapfile -t RETAINED_TRANSACTIONS < <(compgen -G "${AMNEZIAWG_DIR}/.awg-protocol.*" || true)
if [[ "${ROLLBACK_OUTPUT}" == *"could not reactivate the previous AWG runtime"* ]] && \
	[[ "${#RETAINED_TRANSACTIONS[@]}" -eq 1 ]] && \
	[[ "$(grep -c '^restart ' "${AWG3_TEST_SYSTEMCTL_LOG}")" == "2" ]]; then
	ok "failed rollback reactivation is reported and retains recovery files"
else
	not_ok "failed rollback reactivation is reported and retains recovery files"
fi
for RETAINED_TRANSACTION in "${RETAINED_TRANSACTIONS[@]}"; do
	cleanupAwgProtocolTransactionDir "${RETAINED_TRANSACTION}"
done
unset AWG3_TEST_SERVICE_ACTIVE AWG3_TEST_RESTART_FAIL_STATE AWG3_TEST_SYSTEMCTL_LOG

SERVER_BEFORE="$(sha256sum "${SERVER_AWG_CONF}")"
PARAMS_BEFORE="$(sha256sum "${AMNEZIAWG_DIR}/params")"
CLIENT_BEFORE="$(sha256sum "${CLIENT_CONF}")"
export AWG3_TEST_SERVICE_ACTIVE=1 AWG3_TEST_SIGNAL_ON_STOP=1
if applyAwgProtocolTransaction >/dev/null 2>&1; then
	not_ok "interrupted protocol migration returns failure"
elif [[ "$(sha256sum "${SERVER_AWG_CONF}")" == "${SERVER_BEFORE}" ]] && \
	[[ "$(sha256sum "${AMNEZIAWG_DIR}/params")" == "${PARAMS_BEFORE}" ]] && \
	[[ "$(sha256sum "${CLIENT_CONF}")" == "${CLIENT_BEFORE}" ]]; then
	ok "interrupted protocol migration restores params, server, and client files"
else
	not_ok "interrupted protocol migration restores params, server, and client files"
fi
unset AWG3_TEST_SERVICE_ACTIVE AWG3_TEST_SIGNAL_ON_STOP

printf '\n%d tests, %d failures\n' "$((PASS + FAIL))" "${FAIL}"
(( FAIL == 0 ))
