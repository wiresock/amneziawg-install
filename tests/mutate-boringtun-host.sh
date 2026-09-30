#!/usr/bin/env bash

# Mutation check for the BoringTun host installation. Each mutant breaks one
# rule of the fresh install, its guards or its uninstall in a private copy of
# the repository, and the named test suite must then fail. A mutant that no
# longer applies (its code changed) or that survives fails this script.
#
# It runs a test suite once per mutant, so it is not part of CI. Run it after
# changing the host installation, with the suites' own requirements:
#
#   bash tests/mutate-boringtun-host.sh [-j JOBS] [NAME...]

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=helpers/mutation-engine.sh
source "${SCRIPT_DIR}/helpers/mutation-engine.sh"

INSTALLER=amneziawg-install.sh
PROXY_INSTALLER=amneziawg-proxy/scripts/amneziawg-proxy-install.sh
# mutant <name> <suite> <file> <exact text, present exactly once> <replacement>
mutant() {
	mutation_add "$1" "$2" "$3" "" "$4" "$5"
}
# mutant_expect <name> <suite> <file> <text a failing assertion contains> <exact text> <replacement>
mutant_expect() {
	mutation_add "$1" "$2" "$3" "$4" "$5" "$6"
}

# The download-and-verify transaction.
mutant archive_hash_ignored test-boringtun-host "${INSTALLER}" \
	'if [[ "${ACTUAL%% *}" != "${_AWG_BT_REL_ARCHIVE_SHA256}" ]]; then' 'if false; then'
mutant binary_hash_ignored test-boringtun-host "${INSTALLER}" \
	'if [[ "${ACTUAL%% *}" != "${_AWG_BT_REL_BINARY_SHA256}" ]]; then' 'if false; then'
mutant member_list_ignored test-boringtun-host "${INSTALLER}" \
	'if [[ "${NAMES}" != "${EXPECTED}" || "${TYPES}" != $'"'"'d\n-\n-\n-\n-'"'"' ]]; then' \
	'if [[ "${TYPES}" != $'"'"'d\n-\n-\n-\n-'"'"' ]]; then'
mutant member_types_ignored test-boringtun-host "${INSTALLER}" \
	'if [[ "${NAMES}" != "${EXPECTED}" || "${TYPES}" != $'"'"'d\n-\n-\n-\n-'"'"' ]]; then' \
	'if [[ "${NAMES}" != "${EXPECTED}" ]]; then'
mutant manifest_commit_ignored test-boringtun-host "${INSTALLER}" \
	'"${FIELDS[source_commit]}" != "${AWG_BT_RELEASE_SOURCE_COMMIT}" ||' ''
mutant version_ignored test-boringtun-host "${INSTALLER}" \
	'if [[ "${VERSION}" != "boringtun ${AWG_BT_RELEASE_VERSION}" ]]; then' 'if false; then'
mutant_expect version_run_outside_store test-boringtun-host "${INSTALLER}" "ran only from the store" \
	'_awgBtCheckReleaseDir "${WORK}/unpacked/${_AWG_BT_REL_ID}" "${ARCH}"' '_awgBtVerifyCandidate "${WORK}/unpacked/${_AWG_BT_REL_ID}" "${ARCH}"'
# B1: a release directory in the store is trusted before it runs, and fully
# verified before current points at it.
mutant_expect candidate_runs_before_trust test-boringtun-host "${INSTALLER}" "its binary never runs" \
	$'\tlocal DIR="$1" ARCH="$2" FILE KIND MEMBERS NODE_ID VERSION\n' \
	$'\tlocal DIR="$1" ARCH="$2" FILE KIND MEMBERS NODE_ID VERSION\n\t"${DIR}/boringtun-cli" --version >/dev/null 2>&1\n'
mutant_expect switch_before_verification test-boringtun-host "${INSTALLER}" "current stays absent" \
	'if ! _awgBtVerifyRelease "${_AWG_BT_REL_ID}" ||' 'if ! _awgBtSwitchCurrent || ! _awgBtVerifyRelease "${_AWG_BT_REL_ID}" ||'
mutant_expect candidate_dir_trust_skipped test-boringtun-host "${INSTALLER}" "  as untrusted" \
	$'\tif ! _awgBtTrustedAncestors "${DIR}" || ! _awgBtTrustedNode "${DIR}" dir; then\n\t\techo "ERROR: the BoringTun release directory' \
	$'\tif false; then\n\t\techo "ERROR: the BoringTun release directory'
mutant_expect candidate_member_trust_skipped test-boringtun-host "${INSTALLER}" "  its binary never runs" \
	'if ! _awgBtTrustedNode "${DIR}/${FILE}" "${KIND}" || [[ "$(stat -c '"'%h'"' -- "${DIR}/${FILE}" 2>/dev/null)" != 1 ]]; then' 'if false; then'
mutant_expect candidate_not_rechecked_before_run test-boringtun-host "${INSTALLER}" "  the replacement never runs" \
	'if [[ "$(_awgBtPathId "${DIR}/boringtun-cli")" != "${NODE_ID}" ]] || ! _awgBtTrustedNode "${DIR}/boringtun-cli" exec ||' 'if false ||'
mutant_expect current_changed_on_version_failure test-boringtun-host "${INSTALLER}" "and current stays absent" \
	$'\t\tif ! _awgBtVerifyCandidate "${AWG_BT_STORE_DIR}/${_AWG_BT_REL_ID}" "${ARCH}"; then\n' \
	$'\t\tif ! _awgBtVerifyCandidate "${AWG_BT_STORE_DIR}/${_AWG_BT_REL_ID}" "${ARCH}"; then\n\t\t\t_awgBtSwitchCurrent\n'
mutant installed_release_replaced test-boringtun-host "${INSTALLER}" \
	'if [[ -e "${AWG_BT_STORE_DIR}/current" || -L "${AWG_BT_STORE_DIR}/current" ]]; then' 'if false; then'
# Packages.
mutant boringtun_pulls_dkms test-boringtun-host "${INSTALLER}" \
	$'apt-get install -y --no-install-recommends amneziawg-tools || { echo -e "${RED}ERROR: amneziawg-tools could not be installed.${NC}"; exit 1; }\n\t\tapt-get install -y iptables' \
	$'apt-get install -y amneziawg-tools || { echo -e "${RED}ERROR: amneziawg-tools could not be installed.${NC}"; exit 1; }\n\t\tapt-get install -y iptables'
mutant boringtun_gets_deb_src test-boringtun-host "${INSTALLER}" \
	'configureDebianAmneziaAptSource 0' 'configureDebianAmneziaAptSource 1'
# Backend selection and persistence.
mutant env_survives_load test-backend "${INSTALLER}" \
	$'_AWG_BACKEND_REQUESTED="${AWG_BACKEND-}"\nAWG_BACKEND="${AWG_BACKEND_KERNEL}"' \
	$'_AWG_BACKEND_REQUESTED="${AWG_BACKEND-}"\nAWG_BACKEND="${AWG_BACKEND:-${AWG_BACKEND_KERNEL}}"'
mutant env_fills_persisted_backend test-backend "${INSTALLER}" \
	'AWG_DISABLE_COOKIES AWG_BACKEND' 'AWG_DISABLE_COOKIES'
mutant fresh_ignores_request test-backend "${INSTALLER}" \
	'AWG_BACKEND="${_AWG_BACKEND_REQUESTED}"' 'AWG_BACKEND="${AWG_BACKEND_KERNEL}"'
mutant unknown_backend_is_kernel test-backend "${INSTALLER}" \
	$'\t\t"${AWG_BACKEND_BORINGTUN}") ;;\n\t\t*)\n\t\t\treportUnsupportedAwgBackend "${AWG_BACKEND}"\n\t\t\treturn 1' \
	$'\t\t"${AWG_BACKEND_BORINGTUN}") ;;\n\t\t*)\n\t\t\tAWG_BACKEND="${AWG_BACKEND_KERNEL}"'
# Guards.
mutant proxy_guard_skipped test-boringtun-host "${INSTALLER}" \
	'if [[ -n "${PROXY_PATHS}" ]]; then' 'if false; then'
mutant proxy_toml_not_a_signal test-boringtun-host "${INSTALLER}" \
	' /usr/local/bin/amneziawg-proxy /etc/amneziawg-proxy/proxy.toml"' ' /usr/local/bin/amneziawg-proxy"'
mutant web_guard_skipped test-boringtun-host "${INSTALLER}" \
	'if ! webPanelLifecycleScriptSupportsBoringtun; then' 'if false; then'
mutant web_marker_substring test-boringtun-host "${INSTALLER}" \
	'grep -qxF "AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST=' 'grep -qF "AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST='
mutant proxy_installer_accepts_boringtun test-proxy-scripts "${PROXY_INSTALLER}" \
	'if ! awg_backend_is_proxy_compatible "${backend}"; then' 'if false; then'
mutant proxy_installer_reads_env_backend test-proxy-scripts "${PROXY_INSTALLER}" \
	"backend=\"\$(bash -c 'unset AWG_BACKEND; . \"\$1\"" "backend=\"\$(bash -c '. \"\$1\""
# S4: an existing params file that cannot be trusted never falls through to
# the legacy .conf discovery.
mutant_expect proxy_untrusted_params_fall_through test-proxy-scripts "${PROXY_INSTALLER}" "refused too, never read as legacy" \
	'    if [[ -e "${params_file}" || -L "${params_file}" ]]; then' '    if false; then'
mutant_expect proxy_unloadable_params_accepted test-proxy-scripts "${PROXY_INSTALLER}" "refused as unreadable, with the reason" \
	$' ||\n            ! bash -c \'. "$1" >/dev/null 2>&1\' _ "${params_file}"; then' '; then'
# Kernel module.
mutant loaded_module_accepted test-boringtun-host "${INSTALLER}" \
	$'\tif [[ -e "${AWG_BT_SYS_DIR}/module/amneziawg" ]]; then\n\t\techo -e "${RED}ERROR: the AmneziaWG kernel module is loaded, so awg-quick would use it' \
	$'\tif false; then\n\t\techo -e "${RED}ERROR: the AmneziaWG kernel module is loaded, so awg-quick would use it'
mutant module_blocked_without_consent test-boringtun-host "${INSTALLER}" \
	'if [[ "${AWG_BORINGTUN_BLOCK_KERNEL_MODULE:-}" != "y" ]]; then' 'if false; then'
mutant installed_module_takes_kernel_path test-boringtun-runtime "${INSTALLER}" \
	'if modinfo -n amneziawg >/dev/null 2>&1 && ! _awgBtKernelModuleBlocked; then' 'if false; then'
mutant override_not_proven_in_force test-boringtun-runtime "${INSTALLER}" \
	$'\tfor NAME in amneziawg rtnl-link-amneziawg; do\n\t\t_awgBtModprobeActionBlocked "${NAME}" || return 1\n\tdone\n' ''
# The modprobe dry run, parsed as data. The first mutant restores the check
# that refused the real Ubuntu 26.04 output, where dependency insmods precede
# the install command.
mutant modprobe_output_exact_match test-boringtun-host "${INSTALLER}" \
	$'\tmapfile -t LINES <<<"${OUTPUT}"\n' \
	$'\t[[ "${OUTPUT}" =~ ^install\\ /bin/false[[:space:]]*$ ]] || return 1\n\tmapfile -t LINES <<<"${OUTPUT}"\n'
mutant any_final_install_accepted test-boringtun-runtime "${INSTALLER}" \
	'[[ "${ACTIONS[-1]}" == "install /bin/false" ]] || return 1' '[[ "${ACTIONS[-1]}" == install\ * ]] || return 1'
mutant dependency_lines_unchecked test-boringtun-runtime "${INSTALLER}" \
	$'\tfor LINE in "${ACTIONS[@]:0:${#ACTIONS[@]}-1}"; do\n\t\t[[ "${LINE}" =~ ^insmod\\ (/[^[:space:]]+\\.ko(\\.(gz|xz|zst))?)(\\ .*)?$ ]] || return 1\n\t\tMODULE="${BASH_REMATCH[1]##*/}"\n\t\t[[ "${MODULE%%.ko*}" != amneziawg ]] || return 1\n\tdone\n' ''
mutant amneziawg_insmod_counts_as_dependency test-boringtun-runtime "${INSTALLER}" \
	$'\t\t[[ "${MODULE%%.ko*}" != amneziawg ]] || return 1\n' ''
# Deliberate restarts and the drop-in's start rate limit.
mutant restart_keeps_start_limit test-backend "${INSTALLER}" \
	$'\t\t\tsystemctl reset-failed "awg-quick@${SERVER_AWG_NIC}.service" >/dev/null 2>&1 || true\n' $'\t\t\t:\n'
# The fresh install's order and start.
mutant preflight_skipped test-boringtun-host "${INSTALLER}" \
	$'\tif ! boringtunHostPreflight; then\n\t\texit 1\n\tfi\n' ''
mutant preflight_leak_ignored test-boringtun-host "${INSTALLER}" \
	'DETAIL="${DETAIL:+${DETAIL}; }the scratch instance left its link, sockets or records behind"' 'RC="${RC}"'
mutant start_on_another_datapath test-boringtun-host "${INSTALLER}" \
	'if _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}"; then' 'if true; then'
# Uninstall.
mutant uninstall_removes_foreign_dkms test-boringtun-host "${INSTALLER}" \
	'[[ "${AWG_BACKEND}" == "${AWG_BACKEND_BORINGTUN}" ]] && AWG_APT_PACKAGES=(amneziawg-tools)' ':'
mutant_expect uninstall_ignores_running_daemon test-boringtun-host "${INSTALLER}" "refuses while a daemon of the interface runs" \
	$'\tDAEMONS="$(boringtunDaemonsOf "${INTERFACE_NAME}")"\n\tif [[ -n "${DAEMONS}" ]]; then' \
	$'\tDAEMONS="$(boringtunDaemonsOf "${INTERFACE_NAME}")"\n\tif false; then'
# B2: a UAPI node goes only on positive proof that it is this installation's
# and idle.
mutant_expect uninstall_removes_served_socket test-boringtun-host "${INSTALLER}" "A: a recorded socket that a live process listens on" \
	$'\t\t_awgBtSocketListenedOn "${SOCKET}"\n\t\t[[ $? -eq 1 ]] || return 1' $'\t\t:'
mutant_expect ss_failure_treated_as_idle test-boringtun-host "${INSTALLER}" "C: when ss says 'exit 1'" \
	'OUTPUT="$(ss -xlHe 2>/dev/null)" || return 2' 'OUTPUT="$(ss -xlHe 2>/dev/null)" || return 1'
mutant_expect malformed_ss_output_accepted test-boringtun-host "${INSTALLER}" "D: when ss says" \
	'END { if (bad) exit 2; exit found ? 0 : 1 }' 'END { exit found ? 0 : 1 }'
mutant_expect alias_target_liveness_unchecked test-boringtun-host "${INSTALLER}" "  the alias stays" \
	$'\tif [[ -e "${SOCKET}" || -L "${SOCKET}" ]]; then\n\t\t_awgBtSocketListenedOn' \
	$'\tif [[ ! -L "${NODE}" ]] && [[ -e "${SOCKET}" || -L "${SOCKET}" ]]; then\n\t\t_awgBtSocketListenedOn'
mutant_expect alias_outside_uapi_dirs_followed test-boringtun-host "${INSTALLER}" "resolves outside the UAPI socket directories" \
	$'\t\tif [[ "${TARGET_DIR}" != "$(readlink -f -- "${AWG_BT_WG_SOCKET_DIR}" 2>/dev/null)" &&' $'\t\tif false &&'
# The node's identity is checked first and again right before the unlink;
# without the record, both go.
mutation_add unrecorded_node_removed test-boringtun-host "${INSTALLER}" "replaced the recorded node" \
	$'\tif [[ -z "$2" || "$(_awgBtPathId "${NODE}")" != "$2" ]]; then\n\t\treturn 1' $'\tif false; then\n\t\treturn 1' \
	$'\t[[ "$(_awgBtPathId "${NODE}")" == "$2" ]] || return 1\n\trm -f' $'\trm -f'
# B3: helpers go only when they are byte for byte the installer's.
mutant_expect helper_header_is_ownership test-boringtun-host "${INSTALLER}" "a helper changed by one byte stays" \
	$'cmp -s -- "${FILE}" <(printf \'%s\\n\' "${CONTENT}")' \
	$'grep -qxF "# ${FILE##*/}: generated by amneziawg-install from its own functions." "${FILE}"'
mutant_expect boringtun_deletes_modules_load test-boringtun-host "${INSTALLER}" "byte for byte as it was" \
	$'\t\tif [[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]]; then\n\t\t\trm -f "${AWG_MODULES_LOAD_FILE}"' \
	$'\t\tif true; then\n\t\t\trm -f "${AWG_MODULES_LOAD_FILE}"'
# S1: unfinished teardown evidence is kept.
mutant_expect unfinished_replay_discarded test-boringtun-host "${INSTALLER}" "did not finish" \
	$'\t[[ "${_AWG_BT_STATE[PHASE]}" == started || "${_AWG_BT_STATE[PHASE]}" == launch-failed ]] || _awgBtFlagIs "$1" "done"' $'\ttrue'
mutant_expect teardown_gate_skipped test-boringtun-host "${INSTALLER}" "before the drop-in, the sysctl file or params are removed" \
	$'\t\t\tif ! boringtunTeardownFinished "${SERVER_AWG_NIC}"; then' $'\t\t\tif false; then'
# S2: a helper that cannot be removed fails the uninstall.
mutant_expect helper_rm_ignored test-boringtun-host "${INSTALLER}" "S2: a generated helper that cannot be removed" \
	'_awgBtRemoveGeneratedHelper "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl" ctl || RC=1' \
	'_awgBtRemoveGeneratedHelper "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl" ctl'
# S3: the configuration goes last, and only after every step succeeded.
mutant_expect config_removed_before_packages test-boringtun-host "${INSTALLER}" "the configuration is still there while packages are removed" \
	$'\t\tif [[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]]; then\n\t\t\trm -rf "${AMNEZIAWG_DIR:?}"' \
	$'\t\tif true; then\n\t\t\trm -rf "${AMNEZIAWG_DIR:?}"'
mutant_expect config_removed_after_failure test-boringtun-host "${INSTALLER}" "and keeps params, so a rerun uninstalls again" \
	$'\t\t\tif [[ ${AWG_RUNNING} -eq 0 || ${UNINSTALL_FAILED} -ne 0 ]]; then\n\t\t\t\techo -e "${ORANGE}The configuration in' \
	$'\t\t\tif false; then\n\t\t\t\techo -e "${ORANGE}The configuration in'
mutant uninstall_drops_params_on_failure test-boringtun-host "${INSTALLER}" \
	$'The configuration in ${AMNEZIAWG_DIR} was kept. Fix the cause and rerun the uninstall.${NC}"\n\t\t\texit 1' \
	$'The configuration in ${AMNEZIAWG_DIR} was kept. Fix the cause and rerun the uninstall.${NC}"'

mutation_main "BoringTun host" "${PROJECT_ROOT}" "$@"
