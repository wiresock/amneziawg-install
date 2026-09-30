#!/usr/bin/env bash
# Kernel-path equivalence, management scenarios: sources the given installer
# with command-logging mocks, drives every management path the backend seam
# touches (AWG 3.x probes and validation, the protocol transaction, protocol
# modes, client add/remove/regenerate, migrations) on the kernel backend, and
# writes one normalized transcript per scenario: exit code, stdout, stderr, the
# ordered external-command log and a hash of every file the scenario owns.
# Params lose their AWG_BACKEND line before hashing: persisting it is the one
# intended format change. Run by run-kernel-equivalence.sh against a base
# revision and the working tree; the transcripts must be identical.
#
# Usage: kernel-scenarios.sh <amneziawg-install.sh> <output-dir>

# shellcheck disable=SC2034 # the scenarios set variables the sourced installer reads
INSTALLER="$(readlink -f "$1")"
OUT_DIR="$2"
mkdir -p "${OUT_DIR}"
ROOT="$(mktemp -d /tmp/seam-harness.XXXXXX)"
BIN="${ROOT}/bin"
mkdir -p "${BIN}"
export ROOT
export HARNESS_LOG="${ROOT}/calls.log"
export MOCK_KEY="YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
export MOCK_PUB="cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A="
export MOCK_PSK="cHNrMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM="

cat >"${BIN}/awg" <<'EOF'
#!/usr/bin/env bash
join() { tr '\n' '|' <"$1"; }
case "${1:-}" in
	genkey) printf 'awg genkey\n' >>"${HARNESS_LOG}"; printf '%s\n' "${MOCK_KEY}" ;;
	pubkey) read -r _k; printf 'awg pubkey\n' >>"${HARNESS_LOG}"; printf '%s\n' "${MOCK_PUB}" ;;
	genpsk) printf 'awg genpsk\n' >>"${HARNESS_LOG}"; printf '%s\n' "${MOCK_PSK}" ;;
	setconf)
		printf 'awg setconf %s <%s>\n' "$2" "$(join "$3")" >>"${HARNESS_LOG}"
		[[ "${H_FAIL_SETCONF:-0}" == "0" ]] || { echo "SETCONF-STDERR" >&2; exit 1; }
		;;
	syncconf)
		# Read the whole input first so the strip log line always precedes this one.
		CONTENT="$(join "$3")"
		printf 'awg syncconf %s <%s>\n' "$2" "${CONTENT}" >>"${HARNESS_LOG}"
		echo "SYNC-STDOUT"
		echo "SYNC-STDERR" >&2
		exit "${H_SYNC_RC:-0}"
		;;
	show)
		printf 'awg show %s %s hide=%s\n' "${2:-}" "${3:-}" "${WG_HIDE_KEYS:-unset}" >>"${HARNESS_LOG}"
		case "${3:-}" in
			header-protection-key) printf '%s\n' "${MOCK_KEY}" ;;
			content-padding-addition) printf '%s\n' "${H_CONTENT_READBACK:-11-13}" ;;
			rekey-after-time) printf '101-103\n' ;;
			rekey-timeout) printf '5-7\n' ;;
			reject-after-time) printf '181-183\n' ;;
			keepalive-timeout) printf '9-11\n' ;;
			random-trailers) printf '%s\n' "${H_TRAILERS_READBACK:-on}" ;;
			disable-cookies) printf 'on\n' ;;
			*) exit 1 ;;
		esac
		;;
	*) printf 'awg %s\n' "$*" >>"${HARNESS_LOG}" ;;
esac
EOF

cat >"${BIN}/awg-quick" <<'EOF'
#!/usr/bin/env bash
printf 'awg-quick %s\n' "$*" >>"${HARNESS_LOG}"
case "${1:-}" in
	strip)
		echo "WARN-STRIP ${2:-}" >&2
		if [[ -f "${2:-}" ]]; then
			sed -E '/^(Address|DNS|PostUp|PostDown)[[:space:]]*=/d' "$2"
		else
			printf '[Interface]\nListenPort = 51820\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.66.66.2/32\n' "${MOCK_KEY}" "${MOCK_PUB}"
		fi
		;;
	down)
		[[ "${H_FAIL_MANUAL_DOWN:-0}" != "1" ]] || exit 1
		[[ -z "${H_MANUAL_STATE:-}" ]] || rm -f -- "${H_MANUAL_STATE}"
		;;
	up)
		[[ "${H_FAIL_MANUAL_UP:-0}" != "1" ]] || { echo "UP-STDERR" >&2; exit 1; }
		[[ -z "${H_MANUAL_STATE:-}" ]] || : >"${H_MANUAL_STATE}"
		echo "UP-STDOUT"
		;;
esac
EOF

cat >"${BIN}/ip" <<'EOF'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >>"${HARNESS_LOG}"
if [[ "${1:-}" == "link" && "${2:-}" == "show" ]]; then
	[[ "${4:-}" == "${H_SERVER_IFACE:-}" && -n "${H_MANUAL_STATE:-}" && -e "${H_MANUAL_STATE}" ]]
	exit $?
fi
if [[ "${1:-}" == "link" && "${2:-}" == "add" ]]; then
	[[ "${H_FAIL_LINK_ADD:-0}" == "0" ]] || { echo "LINK-ADD-STDERR" >&2; exit 2; }
	echo "LINK-ADD-STDOUT"
	exit 0
fi
if [[ "${1:-}" == "link" && "${2:-}" == "delete" ]]; then
	if [[ "${4:-}" == "${H_SERVER_IFACE:-}" && -n "${H_MANUAL_STATE:-}" ]]; then
		rm -f -- "${H_MANUAL_STATE}"
	fi
	[[ "${H_FAIL_LINK_DELETE:-0}" == "0" ]] || exit 1
	exit 0
fi
exit 0
EOF

cat >"${BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"${HARNESS_LOG}"
case "${1:-}" in
	is-active) [[ "${H_SERVICE_ACTIVE:-0}" == "1" ]] ;;
	*) exit 0 ;;
esac
EOF

cat >"${BIN}/qrencode" <<'EOF'
#!/usr/bin/env bash
printf 'qrencode %s\n' "$*" >>"${HARNESS_LOG}"
cat >/dev/null
echo "QR"
EOF

cat >"${BIN}/getent" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF
chmod +x "${BIN}"/*
export PATH="${BIN}:${PATH}"
export TMPDIR="${ROOT}/tmp"
mkdir -p "${TMPDIR}"

# shellcheck disable=SC1090
source "${INSTALLER}"

normalize() {
	sed -E \
		-e "s#${ROOT}#<ROOT>#g" \
		-e 's#awgp[0-9]+#awgp<PID>#g' \
		-e 's#awgv[0-9]+#awgv<PID>#g' \
		-e 's#/dev/fd/[0-9]+#/dev/fd/<N>#g' \
		-e 's#/proc/self/fd/[0-9]+#/proc/self/fd/<N>#g' \
		-e 's#awg3-probe\.[A-Za-z0-9]{6}#awg3-probe.<X>#g' \
		-e 's#\.awg-protocol\.[A-Za-z0-9]{6}#.awg-protocol.<X>#g' \
		-e 's#params\.(tmp\.)?[A-Za-z0-9]{6}#params.<X>#g' \
		-e 's#\.protocol\.[A-Za-z0-9]{6}#.protocol.<X>#g'
}

snapshot() {
	# Hash every regular file below the scenario state directory. Params lose the
	# AWG_BACKEND line first: persisting it is the one intended format change.
	local dir="$1" f
	[[ -d "${dir}" ]] || return 0
	while IFS= read -r f; do
		if [[ "$(basename "${f}")" == params ]]; then
			printf '%s %s\n' "$(grep -v '^AWG_BACKEND=' "${f}" | sha256sum | cut -c1-16)" "${f}"
		else
			printf '%s %s\n' "$(sha256sum <"${f}" | cut -c1-16)" "${f}"
		fi
	done < <(find "${dir}" -type f ! -path '*/.awg-protocol.*' | sort)
}

run_scenario() {
	local name="$1"
	shift
	local sdir="${ROOT}/s-${name}"
	mkdir -p "${sdir}"
	: >"${HARNESS_LOG}"
	local rc
	(
		cd "${sdir}" || exit 99
		"$@"
	) >"${sdir}/stdout" 2>"${sdir}/stderr" </dev/null
	rc=$?
	{
		printf '=== %s ===\nrc=%s\n--- stdout\n' "${name}" "${rc}"
		cat "${sdir}/stdout"
		printf -- '--- stderr\n'
		cat "${sdir}/stderr"
		printf -- '--- calls\n'
		cat "${HARNESS_LOG}"
		printf -- '--- files\n'
		snapshot "${sdir}/state"
	} | normalize >"${OUT_DIR}/${name}.txt"
}

run_scenario_stdin() {
	local name="$1" input="$2"
	shift 2
	local sdir="${ROOT}/s-${name}"
	mkdir -p "${sdir}"
	: >"${HARNESS_LOG}"
	local rc
	(
		cd "${sdir}" || exit 99
		"$@"
	) >"${sdir}/stdout" 2>"${sdir}/stderr" <<<"${input}"
	rc=$?
	{
		printf '=== %s ===\nrc=%s\n--- stdout\n' "${name}" "${rc}"
		cat "${sdir}/stdout"
		printf -- '--- stderr\n'
		cat "${sdir}/stderr"
		printf -- '--- calls\n'
		cat "${HARNESS_LOG}"
		printf -- '--- files\n'
		snapshot "${sdir}/state"
	} | normalize >"${OUT_DIR}/${name}.txt"
}

# ── Fixture: a complete AWG 2.0 server with one managed client ──────────────
setup_fixture() {
	local sdir="$1"
	AMNEZIAWG_DIR="${sdir}/state"
	WEB_PANEL_CONFIG_DIR="${AMNEZIAWG_DIR}/clients"
	WEB_PANEL_ENV_FILE="${sdir}/missing-env.conf"
	WEB_PANEL_SYSTEMD_UNIT="${sdir}/missing.service"
	SERVER_AWG_NIC="awgt0"
	export H_SERVER_IFACE="${SERVER_AWG_NIC}"
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
	mkdir -p "${AMNEZIAWG_DIR}/clients"
	SERVER_PUB_IP="198.51.100.10"; SERVER_PUB_NIC="eth0"
	SERVER_AWG_IPV4="10.66.66.1"; SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"
	SERVER_PORT="51820"; SERVER_PRIV_KEY="${MOCK_KEY}"
	SERVER_PUB_KEY="c2VydmVycHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo="
	CLIENT_DNS_1="1.1.1.1"; CLIENT_DNS_2="1.0.0.1"
	ALLOWED_IPS="0.0.0.0/0"; ENABLE_IPV6="n"
	SERVER_AWG_JC="4"; SERVER_AWG_JMIN="10"; SERVER_AWG_JMAX="50"
	SERVER_AWG_S1="20"; SERVER_AWG_S2="30"; SERVER_AWG_S3="40"; SERVER_AWG_S4="50"
	SERVER_AWG_H1="100-200"; SERVER_AWG_H2="300-400"; SERVER_AWG_H3="500-600"; SERVER_AWG_H4="700-800"
	AWG_PROTOCOL_VERSION=2
	clearAwg3Params
	cat >"${SERVER_AWG_CONF}" <<EOC
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIV_KEY}
Jc = 4
Jmin = 10
Jmax = 50
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
EOC
	cat >"${AMNEZIAWG_DIR}/clients/${SERVER_AWG_NIC}-client-alice.conf" <<EOC
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
Endpoint = 198.51.100.10:51820
AllowedIPs = 0.0.0.0/0
EOC
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

mock_management() {
	acquireClientLifecycleLock() { printf 'fn acquireClientLifecycleLock\n' >>"${HARNESS_LOG}"; }
	loadParams() { printf 'fn loadParams %s\n' "$*" >>"${HARNESS_LOG}"; }
	ensureAmneziawgKernelModule() { printf 'fn ensureAmneziawgKernelModule [%s]\n' "$*" >>"${HARNESS_LOG}"; }
	copyToWebPanelDir() { printf 'fn copyToWebPanelDir %s\n' "$*" >>"${HARNESS_LOG}"; }
	removeFromWebPanelDir() { printf 'fn removeFromWebPanelDir %s\n' "$*" >>"${HARNESS_LOG}"; }
	getHomeDirForClient() { mkdir -p "${AMNEZIAWG_DIR}/home/$1"; printf '%s\n' "${AMNEZIAWG_DIR}/home/$1"; }
	isWebPanelInstalled() { return 1; }
}

# ── Scenarios ────────────────────────────────────────────────────────────────
sc_probe3_ok() { probeAwg3Capability "${MOCK_KEY}"; }
sc_probe31_ok() { probeAwg31Capability "${MOCK_KEY}"; }
sc_probe3_setconf_fail() { H_FAIL_SETCONF=1 probeAwg3Capability "${MOCK_KEY}"; }
sc_probe3_readback_mismatch() { H_CONTENT_READBACK=11-14 probeAwg3Capability "${MOCK_KEY}"; }
sc_probe31_trailers_mismatch() { H_TRAILERS_READBACK=off probeAwg31Capability "${MOCK_KEY}"; }
sc_probe3_link_add_fail() { H_FAIL_LINK_ADD=1 probeAwg3Capability "${MOCK_KEY}"; }
sc_probe3_link_delete_fail() { H_FAIL_LINK_DELETE=1 probeAwg3Capability "${MOCK_KEY}"; }
sc_probe3_generated_key() { probeAwgProtocolCapability 0; }

stage_files() {
	local w="$1"
	mkdir -p "${w}"
	printf '[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = %s\nS1 = 20\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n' "${MOCK_KEY}" "${MOCK_PUB}" >"${w}/server.conf"
	printf '[Interface]\nPrivateKey = %s\nDNS = 1.1.1.1\nS1 = 20\n\n[Peer]\nPublicKey = %s\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n' "${MOCK_KEY}" "${MOCK_PUB}" >"${w}/client-0.conf"
}
sc_validate_ok() { local w="${PWD}/work"; stage_files "${w}"; validateStagedAwgConfigs "${w}" "${w}/server.conf" "${w}/client-0.conf"; }
sc_validate_setconf_fail() { local w="${PWD}/work"; stage_files "${w}"; H_FAIL_SETCONF=1 validateStagedAwgConfigs "${w}" "${w}/server.conf" "${w}/client-0.conf"; }
sc_validate_link_add_fail() { local w="${PWD}/work"; stage_files "${w}"; H_FAIL_LINK_ADD=1 validateStagedAwgConfigs "${w}" "${w}/server.conf"; }
sc_validate_link_delete_fail() { local w="${PWD}/work"; stage_files "${w}"; H_FAIL_LINK_DELETE=1 validateStagedAwgConfigs "${w}" "${w}/server.conf"; }

sc_tx_manual_enable3() {
	setup_fixture "${PWD}"
	export H_MANUAL_STATE="${PWD}/manual.active"; : >"${H_MANUAL_STATE}"
	set_awg3_state
	applyAwgProtocolTransaction
}
sc_tx_manual_up_fail() {
	setup_fixture "${PWD}"
	export H_MANUAL_STATE="${PWD}/manual.active"; : >"${H_MANUAL_STATE}"
	set_awg3_state
	H_FAIL_MANUAL_UP=1 applyAwgProtocolTransaction
}
sc_tx_manual_down_fail() {
	setup_fixture "${PWD}"
	export H_MANUAL_STATE="${PWD}/manual.active"; : >"${H_MANUAL_STATE}"
	set_awg3_state
	H_FAIL_MANUAL_DOWN=1 applyAwgProtocolTransaction
}
sc_tx_service_enable3() {
	setup_fixture "${PWD}"
	set_awg3_state
	H_SERVICE_ACTIVE=1 applyAwgProtocolTransaction
}
sc_tx_no_runtime() {
	setup_fixture "${PWD}"
	set_awg3_state
	applyAwgProtocolTransaction
}

sc_mode3_from2() {
	setup_fixture "${PWD}"
	mock_management
	awg2StateNeedsLegacyMigration() { return 1; }
	probeAwg3Capability() { printf 'fn probeAwg3Capability %s\n' "$*" >>"${HARNESS_LOG}"; }
	applyAwgProtocolTransaction() { printf 'fn applyAwgProtocolTransaction %s\n' "${AWG_PROTOCOL_VERSION}" >>"${HARNESS_LOG}"; }
	setAwgProtocolMode 3
}
sc_mode31_from2() {
	setup_fixture "${PWD}"
	mock_management
	awg2StateNeedsLegacyMigration() { return 1; }
	probeAwg31Capability() { printf 'fn probeAwg31Capability\n' >>"${HARNESS_LOG}"; }
	applyAwgProtocolTransaction() { printf 'fn applyAwgProtocolTransaction %s\n' "${AWG_PROTOCOL_VERSION}" >>"${HARNESS_LOG}"; }
	setAwgProtocolMode 3.1
}
sc_mode3_same() {
	setup_fixture "${PWD}"
	set_awg3_state
	mock_management
	probeAwg3Capability() { printf 'fn probeAwg3Capability %s\n' "$*" >>"${HARNESS_LOG}"; }
	awgProtocolConfigsMatchPersistedState() { printf 'fn verify\n' >>"${HARNESS_LOG}"; return 0; }
	setAwgProtocolMode 3
}
sc_mode31_from3() {
	setup_fixture "${PWD}"
	set_awg3_state
	mock_management
	awg2StateNeedsLegacyMigration() { return 1; }
	probeAwg31Capability() { printf 'fn probeAwg31Capability %s\n' "$*" >>"${HARNESS_LOG}"; }
	applyAwgProtocolTransaction() { printf 'fn applyAwgProtocolTransaction %s\n' "${AWG_PROTOCOL_VERSION}" >>"${HARNESS_LOG}"; }
	setAwgProtocolMode 3.1
}
sc_mode3_ensure_exits() {
	# The readiness step is fatal inside the protocol subshell even behind `|| true`.
	setup_fixture "${PWD}"
	mock_management
	ensureAmneziawgKernelModule() { printf 'fn ensureAmneziawgKernelModule [%s]\n' "$*" >>"${HARNESS_LOG}"; echo "ENSURE-FAILED" >&2; exit 1; }
	awg2StateNeedsLegacyMigration() { return 1; }
	probeAwg3Capability() { printf 'fn probeAwg3Capability\n' >>"${HARNESS_LOG}"; }
	setAwgProtocolMode 3
}

sc_niac_add() { setup_fixture "${PWD}"; mock_management; nonInteractiveAddClient bob; }
sc_niac_add_sync_fail() { setup_fixture "${PWD}"; mock_management; H_SYNC_RC=1 nonInteractiveAddClient bob; }
sc_niac_remove() { setup_fixture "${PWD}"; mock_management; nonInteractiveRemoveClient alice; }
sc_niac_remove_sync_fail() { setup_fixture "${PWD}"; mock_management; H_SYNC_RC=1 nonInteractiveRemoveClient alice; }
sc_niac_add_ensure_fails() {
	setup_fixture "${PWD}"; mock_management
	ensureAmneziawgKernelModule() { printf 'fn ensureAmneziawgKernelModule [%s]\n' "$*" >>"${HARNESS_LOG}"; echo "ENSURE-FAILED" >&2; exit 1; }
	nonInteractiveAddClient bob
}

sc_new_client_auto() { setup_fixture "${PWD}"; mock_management; AUTO_INSTALL=y newClient; }
sc_new_client_sync_fail() { setup_fixture "${PWD}"; mock_management; AUTO_INSTALL=y H_SYNC_RC=1 newClient; }
sc_revoke_client() { setup_fixture "${PWD}"; mock_management; revokeClient; }
sc_revoke_client_sync_fail() { setup_fixture "${PWD}"; mock_management; H_SYNC_RC=1 revokeClient; }
sc_regenerate_newkey() {
	setup_fixture "${PWD}"; mock_management
	rm -f "${AMNEZIAWG_DIR}/clients/${SERVER_AWG_NIC}-client-alice.conf"
	resolveWebPanelConfigDir() { printf '%s\n' "${AMNEZIAWG_DIR}/panel"; }
	regenerateClients
}
sc_regenerate_keep() {
	setup_fixture "${PWD}"; mock_management
	resolveWebPanelConfigDir() { printf '%s\n' "${AMNEZIAWG_DIR}/clients"; }
	regenerateClients
}
sc_persist_migration_active() {
	setup_fixture "${PWD}"; mock_management
	H_SERVICE_ACTIVE=1 AUTO_INSTALL=y persistMigration "${SERVER_AWG_IPV6}" 0
}
sc_persist_migration_inactive() {
	setup_fixture "${PWD}"; mock_management
	AUTO_INSTALL=y persistMigration "${SERVER_AWG_IPV6}" 0
}

for sc in probe3_ok probe31_ok probe3_setconf_fail probe3_readback_mismatch probe31_trailers_mismatch \
	probe3_link_add_fail probe3_link_delete_fail probe3_generated_key \
	validate_ok validate_setconf_fail validate_link_add_fail validate_link_delete_fail \
	tx_manual_enable3 tx_manual_up_fail tx_manual_down_fail tx_service_enable3 tx_no_runtime \
	mode3_from2 mode31_from2 mode3_same mode31_from3 mode3_ensure_exits \
	niac_add niac_add_sync_fail niac_remove niac_remove_sync_fail niac_add_ensure_fails \
	new_client_auto new_client_sync_fail regenerate_newkey regenerate_keep \
	persist_migration_active persist_migration_inactive; do
	run_scenario "${sc}" "sc_${sc}"
done
run_scenario_stdin revoke_client "1" sc_revoke_client
run_scenario_stdin revoke_client_sync_fail "1" sc_revoke_client_sync_fail

rm -rf -- "${ROOT}"
printf 'scenarios written: %s\n' "$(find "${OUT_DIR}" -name '*.txt' | wc -l)"
