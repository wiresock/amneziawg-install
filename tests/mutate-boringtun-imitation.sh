#!/usr/bin/env bash

# Mutation check for BoringTun protocol imitation. Each mutant breaks one rule
# of the persisted model, the runtime file, the daemon's command line, the
# warnings, the SIP refusal, the --set-boringtun-imitation transaction,
# --backend-status or the menus in a private copy of the repository, and the
# named test suite must then fail with the named assertion. A mutant that no
# longer applies (its code changed) or that survives fails this script.
#
# It runs a test suite once per mutant, so it is not part of CI. Run it after
# changing protocol imitation, with the suites' own requirements:
#
#   bash tests/mutate-boringtun-imitation.sh [-j JOBS] [NAME...]

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=helpers/mutation-engine.sh
source "${SCRIPT_DIR}/helpers/mutation-engine.sh"

mutation_suite test-boringtun-imitation '^BoringTun imitation tests: ([0-9]+) passed, ([0-9]+) failed$' '^  FAIL: '
mutation_suite test-boringtun-runtime '^BoringTun runtime tests: ([0-9]+) passed, ([0-9]+) failed$' '^  FAIL: '
mutation_suite test-boringtun-imitation-auto '^BoringTun auto imitation tests: ([0-9]+) passed, ([0-9]+) failed$' '^  FAIL: '

INSTALLER=amneziawg-install.sh
T=$'\t'
# mutant <name> <suite> <text a failing assertion contains> <exact text, present exactly once> <replacement>
mutant() {
	mutation_add "$1" "$2" "${INSTALLER}" "$3" "$4" "$5"
}

# The persisted model and its environment boundary.
mutant env_overrides_protocol test-boringtun-imitation "even with exported variables" \
	'AWG_DISABLE_COOKIES AWG_BACKEND AWG_BORINGTUN_IMITATE_PROTOCOL \' 'AWG_DISABLE_COOKIES AWG_BACKEND \'
mutant request_read_late test-boringtun-imitation "the request is the one the installer was started with" \
	'AWG_BORINGTUN_IMITATE_PROTOCOL="${_AWG_BT_IMITATE_PROTOCOL_REQUESTED:-${AWG_BT_IMITATE_NONE}}"' \
	'AWG_BORINGTUN_IMITATE_PROTOCOL="${AWG_BORINGTUN_IMITATE_PROTOCOL:-${AWG_BT_IMITATE_NONE}}"'
mutant kernel_accepts_imitation test-boringtun-imitation "kernel params that carry a dns imitation are damaged" \
	'echo "ERROR: protocol imitation is available only with the BoringTun backend (AWG_BACKEND=${AWG_BACKEND_BORINGTUN})." >&2'$'\n'"${T}${T}${T}return 1" ':'
mutant kernel_params_get_keys test-boringtun-imitation "kernel params carry no imitation keys" \
	'if ((RC == 0)) && [[ "${AWG_BACKEND:-}" == "${AWG_BACKEND_BORINGTUN}" ]]; then' 'if ((RC == 0)); then'
mutant empty_protocol_is_none test-boringtun-imitation "an empty persisted protocol is refused" \
	'[[ -n "${AWG_BORINGTUN_IMITATE_PROTOCOL+set}" ]] || AWG_BORINGTUN_IMITATE_PROTOCOL="${AWG_BT_IMITATE_NONE}"' \
	'AWG_BORINGTUN_IMITATE_PROTOCOL="${AWG_BORINGTUN_IMITATE_PROTOCOL:-${AWG_BT_IMITATE_NONE}}"'
mutant hostname_hyphen_edges test-boringtun-imitation "-a.com is not a valid hostname" \
	'local LABEL="${ALNUM}(${INNER}{0,61}${ALNUM})?"' 'local LABEL="${INNER}{1,63}"'
mutant hostname_unbounded test-boringtun-imitation "is not a valid hostname" \
	'[[ "${DOMAIN}" =~ ^${LABEL}(\.${LABEL})*$ ]] && ((${#DOMAIN} <= 253))' '[[ "${DOMAIN}" =~ ^${LABEL}(\.${LABEL})*$ ]]'
mutant hostname_with_stun test-boringtun-imitation "a hostname with stun is refused" \
	$'\tif ! _awgBtImitationUsesDomain "${PROTOCOL}"; then\n\t\t_awgBtErr' $'\tif false; then\n\t\t_awgBtErr'

# The runtime file, the launcher and the daemon's command line.
mutant runtime_renders_none test-boringtun-imitation "imitation none renders the earlier installer's runtime file byte for byte" \
	$'\tif [[ "${PROTOCOL}" != none ]]; then\n\t\tprintf \'IMITATE_PROTOCOL=%s\\n\'' $'\tif true; then\n\t\tprintf \'IMITATE_PROTOCOL=%s\\n\''
mutant runtime_parser_accepts_none test-boringtun-runtime "IMITATE_PROTOCOL=none is refused" \
	'if [[ "${VALUE}" == none ]] || ! _awgBtImitationProtocolValid "${VALUE}"; then' 'if ! _awgBtImitationProtocolValid "${VALUE}"; then'
mutant runtime_empty_domain test-boringtun-runtime "an empty IMITATE_DOMAIN is refused" \
	'if [[ -n "${SEEN[IMITATE_DOMAIN]+set}" && -z "${_AWG_BT_IMITATE_DOMAIN}" ]] ||' 'if false ||'
mutant runtime_pair_unchecked test-boringtun-runtime "an IMITATE_DOMAIN for stun is refused" \
	$'\t\t! _awgBtImitationCheck "${_AWG_BT_IMITATE_PROTOCOL}" "${_AWG_BT_IMITATE_DOMAIN}"; then' $'\t\tfalse; then'
mutant argv_without_protocol test-boringtun-runtime "the daemon gets exactly the production arguments" \
	$'--verbosity error\n\t\t--imitate-protocol "${PROTOCOL}")' $'--verbosity error)'
mutant argv_without_domain test-boringtun-runtime "the daemon gets the runtime file's protocol and hostname" \
	'[[ -z "${DOMAIN}" ]] || _AWG_BT_ARGV+=(--imitate-domain "${DOMAIN}")' ':'
mutant launcher_ignores_runtime_file test-boringtun-runtime "the daemon gets the runtime file's protocol and hostname" \
	'"${INTERFACE_NAME}" "${_AWG_BT_IMITATE_PROTOCOL}" "${_AWG_BT_IMITATE_DOMAIN}"; then' '"${INTERFACE_NAME}"; then'
mutant scratch_without_imitation test-boringtun-imitation "a scratch BoringTun instance runs the persisted imitation" \
	'"${NAME}" "${AWG_BORINGTUN_IMITATE_PROTOCOL:-none}" "${AWG_BORINGTUN_IMITATE_DOMAIN:-}" || return 1' '"${NAME}" || return 1'
mutant helper_without_check test-boringtun-imitation "the launcher carries _awgBtImitationCheck" \
	'_awgBtImitationDomainValid _awgBtImitationCheck _awgBtBinaryImitationSupport _awgBtStatOwnerMode' \
	'_awgBtImitationDomainValid _awgBtBinaryImitationSupport _awgBtStatOwnerMode'

# The warnings and the SIP refusal under AWG 3.x.
mutant sip_not_refused test-boringtun-imitation "sip with AWG 3.0 and an S of 31 is refused" \
	'(($(boringtunLargestSPrefix) >= 31)) || return 0' 'return 0'
mutant largest_skips_s3 test-boringtun-imitation "sip with AWG 3.0 and an S of 31 is refused" \
	'"${SERVER_AWG_S2:-0}" "${SERVER_AWG_S3:-0}" "${SERVER_AWG_S4:-0}"' '"${SERVER_AWG_S2:-0}" "${SERVER_AWG_S4:-0}"'
mutant protocol_change_skips_sip_check test-boringtun-imitation "--enable-awg3 under sip imitation with S sizes over 30 is refused" \
	$'\t\tcheckBoringtunImitationProtocolCompat "${AWG_BORINGTUN_IMITATE_PROTOCOL}" "${TARGET_MODE}" || return 1\n\t\tif [[ -z' \
	$'\t\tif [[ -z'
mutant advisory_off_by_one test-boringtun-imitation "(32 is enough)" \
	'if ((10#${SIZE} < NEED)); then' 'if ((10#${SIZE} <= NEED)); then'
mutant advisory_dns_hostname test-boringtun-imitation "dns with a hostname" \
	'[[ -z "${DOMAIN}" ]] || NAMED=$((${#DOMAIN} + 33))' '[[ -z "${DOMAIN}" ]] || NAMED=$((${#DOMAIN} + 32))'
mutant no_awg3_warning test-boringtun-imitation "AWG 3.0: the header-protection trade-off is stated" \
	$'\tif [[ "${VERSION}" == "${AWG_PROTOCOL_VERSION_3}" || "${VERSION}" == "${AWG_PROTOCOL_VERSION_31}" ]]; then\n\t\techo -e' \
	$'\tif false; then\n\t\techo -e'

# The --set-boringtun-imitation transaction.
mutant no_noop test-boringtun-imitation "without touching the runtime" \
	$'\t\techo "BoringTun protocol imitation is already $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}"); nothing was changed."\n\t\treturn 0' \
	$'\t\techo "BoringTun protocol imitation is already $(boringtunImitationDisplay "${PROTOCOL}" "${DOMAIN}"); nothing was changed."'
mutant transitional_state_accepted test-boringtun-imitation "a unit that is 'activating' aborts the change" \
	$'\t\tactive) ACTIVE=1 ;;\n\t\tinactive | failed) ;;\n\t\t*)\n\t\t\techo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2\n\t\t\treturn 1\n\t\t\t;;\n\tesac\n\t((WARNED))' $'\t\tactive) ACTIVE=1 ;;\n\t\tinactive | failed | activating) ;;\n\t\t*)\n\t\t\techo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2\n\t\t\treturn 1\n\t\t\t;;\n\tesac\n\t((WARNED))'
mutant failed_unit_restarted test-boringtun-imitation "failed: the unit is not started" \
	$'\t\tactive) ACTIVE=1 ;;\n\t\tinactive | failed) ;;\n\t\t*)\n\t\t\techo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2\n\t\t\treturn 1\n\t\t\t;;\n\tesac\n\t((WARNED))' $'\t\tactive | failed) ACTIVE=1 ;;\n\t\tinactive) ;;\n\t\t*)\n\t\t\techo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2\n\t\t\treturn 1\n\t\t\t;;\n\tesac\n\t((WARNED))'
mutant helpers_not_reconciled test-boringtun-imitation "the helpers are regenerated while the runtime file is still the previous one" \
	$'\t_awgBtEnsureReady 0\n\tif ((ACTIVE)) && ! _awgBtCheckServedByBoringtun' $'\tif ((ACTIVE)) && ! _awgBtCheckServedByBoringtun'
mutant running_instance_unproven test-boringtun-imitation "an active unit that is not the recorded BoringTun instance is left alone" \
	'if ((ACTIVE)) && ! _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}"; then' 'if false; then'
mutant staged_validation_skipped test-boringtun-imitation "a configuration BoringTun refuses with the new imitation is not applied" \
	'if ! validateStagedAwgConfigs "${TRANSACTION_DIR}" "${SERVER_AWG_CONF}"; then' 'if false; then'
mutant params_mode_normalized test-boringtun-imitation "and keep mode 0400" \
	'! replaceFileExactly "${PARAMS_STAGE}" "${PARAMS_FILE}" "${PARAMS_MODE}"; then' '! replaceFileExactly "${PARAMS_STAGE}" "${PARAMS_FILE}" 600; then'
mutant rollback_mode_normalized test-boringtun-imitation "restart fails: params and the runtime file are restored byte for byte, with their modes" \
	'replaceFileExactly "${PARAMS_BACKUP}" "${PARAMS_FILE}" "${PARAMS_MODE}" || FAILED=1' 'replaceFileExactly "${PARAMS_BACKUP}" "${PARAMS_FILE}" 600 || FAILED=1'
mutant rollback_keeps_new_runtime test-boringtun-imitation "restart fails: params and the runtime file are restored byte for byte, with their modes" \
	'replaceFileExactly "${RUNTIME_BACKUP}" "${RUNTIME_FILE}" "${RUNTIME_MODE}" || FAILED=1' ':'
mutant rollback_no_restart test-boringtun-imitation "restart fails: the previous imitation is restarted and verified" \
	$'\t\t((ACTIVE)) || return 0\n\t\tawgBackendPrepareServiceStart' $'\t\treturn 0\n\t\tawgBackendPrepareServiceStart'
mutant restart_not_verified test-boringtun-imitation "the restarted daemon is not verified: the change fails" \
	'if ! systemctl restart "${UNIT}" || ! verifyBoringtunImitationServed "${PROTOCOL}" "${DOMAIN}"; then' 'if ! systemctl restart "${UNIT}"; then'
mutant no_term_trap test-boringtun-imitation "after restoring both files exactly" \
	$'\ttrap \'rollbackBoringtunImitationOnSignal 143\' TERM\n' ''
mutant rollback_dir_removed_on_failure test-boringtun-imitation "which are kept" \
	$'\t\telse\n\t\t\techo "ERROR: the rollback is incomplete; recovery files remain in ${TRANSACTION_DIR}" >&2' \
	$'\t\telse\n\t\t\tcleanupBoringtunImitationTransactionDir "${TRANSACTION_DIR}"\n\t\t\techo "ERROR: the rollback is incomplete; recovery files remain in ${TRANSACTION_DIR}" >&2'

# Complete staged params (review item 23): a params write that fails
# part-way, or staged params that are incomplete, do not load on their own or
# change more than the imitation, never get committed.
mutant serializer_ignores_body_failure test-boringtun-imitation "serializeParams fails when the params write stops part-way" \
	'cat >"${OUTPUT_FILE}" <<EOF || RC=1' 'cat >"${OUTPUT_FILE}" <<EOF'
mutant serializer_ignores_append_failure test-boringtun-imitation "serializeParams fails when the imitation append fails" \
	'cat >>"${OUTPUT_FILE}" <<EOF || RC=1' 'cat >>"${OUTPUT_FILE}" <<EOF'
mutant staged_check_omits_server_port test-boringtun-imitation "because SERVER_PORT is missing" \
	' SERVER_AWG_IPV6 SERVER_PORT SERVER_PRIV_KEY ' ' SERVER_AWG_IPV6 SERVER_PRIV_KEY '
mutant staged_check_inherits_parent test-boringtun-imitation "because SERVER_PRIV_KEY is missing" \
	$'\tunset ${AWG_PARAMS_KEYS} ${AWG_PARAMS_BORINGTUN_KEYS}\n\t# shellcheck source=/dev/null\n\tif ! source "${STAGED}"; then' \
	$'\t# shellcheck source=/dev/null\n\tif ! source "${STAGED}"; then'
mutant staged_check_skips_protocol_state test-boringtun-imitation "a staged file with an invalid header-protection key does not load" \
	$'if ! validateParamsFile 0 >/dev/null || ! normalizeAwgProtocolVersion >/dev/null; then\n\t\techo "ERROR: the staged params would not load." >&2' \
	$'if false; then\n\t\techo "ERROR: the staged params would not load." >&2'
mutant staged_schema_unchecked test-boringtun-imitation "staged params with a repeated key are refused" \
	'if ! awgParamsFileHasCanonicalKeys "${PARAMS_STAGE}" "${AWG_BACKEND_BORINGTUN}"; then' 'if false; then'
mutant staged_state_not_compared test-boringtun-imitation "staged params that change S4 are refused" \
	'if [[ "${STAGED_STATE}" != "${CURRENT_STATE}|${PROTOCOL}|${DOMAIN}" ]]; then' 'if false; then'

# --backend-status and the menus.
mutant status_mode_unchecked test-boringtun-imitation "by the status itself, before params are read" \
	'if [[ "${OWNER}" != 0 ]] || [[ "${MODE}" != 600 && "${MODE}" != 400 ]]; then' 'if false; then'
mutant status_bad_store_ok test-boringtun-imitation "a BoringTun installation whose store does not verify reports status 1" \
	$'\t\t[[ ! -e "${AWG_BT_STORE_DIR}" && ! -L "${AWG_BT_STORE_DIR}" ]] || INSTALLED=invalid\n\t\tRC=1' \
	$'\t\t[[ ! -e "${AWG_BT_STORE_DIR}" && ! -L "${AWG_BT_STORE_DIR}" ]] || INSTALLED=invalid'
mutant status_daemon_unproven test-boringtun-imitation "an active unit that is not the recorded daemon is 'unverified'" \
	'if ((RC == 0)) && _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}" 2>/dev/null; then' 'if ((RC == 0)); then'
mutant kernel_menu_changed test-boringtun-imitation "the kernel menu says nothing about imitation" \
	$'\tif [[ "${AWG_BACKEND:-}" == "${AWG_BACKEND_BORINGTUN}" ]]; then\n\t\tmanageBoringtunMenu' $'\tif true; then\n\t\tmanageBoringtunMenu'
mutant awg3_not_confirmed test-boringtun-imitation "AWG 3.0: enabling an imitation asks first, and N cancels" \
	'if [[ "${PROTOCOL}" != "${AWG_BT_IMITATE_NONE}" ]] && awgProtocolUsesHeaderProtection; then' 'if false; then'

# Imitation auto: its values, the binary's own answer about it, and every
# place that must refuse it on a binary without it.
AUTO=test-boringtun-imitation-auto
mutant auto_not_a_protocol "${AUTO}" "auto is an imitation protocol" \
	'none | dns | quic | sip | stun | auto) return 0 ;;' 'none | dns | quic | sip | stun) return 0 ;;'
mutant auto_hostname_generic "${AUTO}" "and the refusal says that auto takes none" \
	$'\tif [[ "${PROTOCOL}" == auto ]]; then\n\t\t_awgBtErr "auto takes no hostname' $'\tif false; then\n\t\t_awgBtErr "auto takes no hostname'
mutant probe_always_yes "${AUTO}" "a binary that refuses the value does not" \
	$'\t[[ "${2-}" == auto ]] || return 0\n\tOUTPUT=' $'\treturn 0\n\tOUTPUT='
mutant probe_unclear_is_yes "${AUTO}" "an answer that is neither (prints-other) is unknown, never support" \
	$'\tif ((RC == 0)) && [[ "${OUTPUT}" =~ ^boringtun\\ [0-9]+\\.[0-9]+\\.[0-9]+$ ]]; then' $'\tif ((RC == 0)); then'
mutant probe_any_error_is_no "${AUTO}" "an answer that is neither (refuses-with-1) is unknown, never support" \
	$'\tif ((RC == 2)) && [[ "${OUTPUT}" == *"invalid value \'auto\' for \'--imitate-protocol"* ]]; then' $'\tif ((RC != 0)); then'
mutant probe_inherits_environment "${AUTO}" "the probe runs the binary with a clean environment" \
	'env -i "PATH=${AWG_BT_PATH}" NO_COLOR=1 "$1" \' 'env "PATH=${AWG_BT_PATH}" NO_COLOR=1 "$1" \'
mutant probe_unbounded "${AUTO}" "and is stopped after the probe timeout" \
	'OUTPUT="$(timeout --kill-after=2 "${AWG_BT_PROBE_TIMEOUT}" env -i' 'OUTPUT="$(env -i'
mutant set_without_support_check "${AUTO}" "active, binary without auto: auto is refused" \
	$'\trequireBoringtunImitationSupport "${PROTOCOL}" || return 1\n' ''
mutant set_support_unclear_accepted "${AUTO}" "a binary whose answer is unclear cannot take auto" \
	$'\t((RC == 0)) && return 0\n\tif ((RC != 1)); then' $'\t((RC != 1)) && return 0\n\tif ((RC != 1)); then'
mutant launcher_without_support_check "${AUTO}" "the launcher says that the binary lacks auto" \
	'if ! _awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "${_AWG_BT_IMITATE_PROTOCOL}"; then' 'if false; then'
mutant scratch_without_support_check "${AUTO}" "the scratch refusal says that the binary lacks auto" \
	'if ! _awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "${AWG_BORINGTUN_IMITATE_PROTOCOL:-none}"; then'$'\n'"${T}${T}_awgBtErr" \
	'if false; then'$'\n'"${T}${T}_awgBtErr"
mutant preflight_without_support_check "${AUTO}" "the preflight says that the binary lacks auto" \
	'if ! _awgBtBinaryImitationSupport "${_AWG_BT_VERIFIED_BIN}" "${AWG_BORINGTUN_IMITATE_PROTOCOL:-none}"; then'$'\n'"${T}${T}echo -e" \
	'if false; then'$'\n'"${T}${T}echo -e"
mutant status_support_unreported "${AUTO}" "the installed binary supports auto" \
	'0) AUTO_SUPPORT=supported ;;' '0) ;;'
mutant auto_warnings_generic "${AUTO}" "and needs recognizable client traffic" \
	$'\tif [[ "${PROTOCOL}" == auto ]]; then\n\t\tprintBoringtunAutoImitationWarnings' $'\tif false; then\n\t\tprintBoringtunAutoImitationWarnings'
mutant auto_refused_like_sip "${AUTO}" "AWG 3.0 with S sizes over 30: auto is not refused, as sip would be" \
	$'\t[[ "$1" == sip ]] || return 0\n\t[[ "$2" ==' $'\t[[ "$1" == sip || "$1" == auto ]] || return 0\n\t[[ "$2" =='
mutant change_menu_without_auto "${AUTO}" "AWG 2.0: 6 selects auto, asks no hostname and runs the transaction" \
	$'\tlocal -a PROTOCOLS=(none dns quic sip stun auto)\n\tlocal CHOICE="" DEFAULT=1 I PROTOCOL' $'\tlocal -a PROTOCOLS=(none dns quic sip stun)\n\tlocal CHOICE="" DEFAULT=1 I PROTOCOL'

mutation_main "BoringTun imitation" "${PROJECT_ROOT}" "$@"
