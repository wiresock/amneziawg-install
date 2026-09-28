#!/usr/bin/env bash

# Mutation check for the internal BoringTun runtime layer. Each mutant breaks
# one rule of the runtime in a private copy of amneziawg-install.sh, and
# tests/test-boringtun-runtime.sh must then fail. A mutant that no longer
# applies (its code changed) or that survives fails this script.
#
# It runs the unit suite once per mutant, so it is not part of CI. Run it after
# changing the runtime, with the unit suite's own requirements (cc, python3,
# setpriv):
#
#   bash tests/mutate-boringtun-runtime.sh [-j JOBS] [NAME...]

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
JOBS=4
if [[ "${1:-}" == -j ]]; then
	JOBS="${2:?}"
	shift 2
fi

declare -a NAMES=() EDITS=()
SEP=$'\x1f'
# mutant <name> <exact text, present exactly once> <replacement> [<text> <replacement>]...
# Several edits make one mutant; each must apply exactly once.
mutant() {
	local EDIT=""
	NAMES+=("$1")
	shift
	while (($# >= 2)); do
		EDIT+="$1${SEP}$2${SEP}"
		shift 2
	done
	EDITS+=("${EDIT}")
}

T=$'\t'

# Activation boundary and store verification.
mutant dispatch_without_internal_flag '[[ "${_AWG_BORINGTUN_RUNTIME_INTERNAL}" == 1 && "${AWG_BACKEND:-}" == "${AWG_BACKEND_BORINGTUN}" ]]' 	'[[ "${AWG_BACKEND:-}" == "${AWG_BACKEND_BORINGTUN}" ]]'
mutant no_sha_check 'if [[ "${ACTUAL_SHA}" != "${FIELDS[binary_sha256]}" ]]; then' 'if false; then'
mutant no_mode_check '(((8#${MODE} & 8#022) == 0)) || return 1' ':'
mutant no_ancestor_check $'function _awgBtTrustedAncestors() {\n' $'function _awgBtTrustedAncestors() {\n\treturn 0\n'
mutant runtime_unknown_key_ok '_awgBtErr "unknown key ${KEY} in ${FILE}"'$'\n'"${T}${T}${T}${T}return 1" ':'
# The daemon's command line and descriptors.
mutant env_not_scrubbed '_AWG_BT_ARGV=("${ENV_BIN}" -i ' '_AWG_BT_ARGV=("${ENV_BIN}" '
mutant no_foreground '"$1" --foreground --disable-drop-privileges' '"$1" --disable-drop-privileges'
mutant descriptors_not_closed $'function _awgBtCloseInheritedFds() {\n' $'function _awgBtCloseInheritedFds() {\n\treturn 0\n'
mutant launch_without_precheck '[[ "${_AWG_BT_STATE[PHASE]}" != prechecked ]]' 'false'
# precheck.
mutant no_module_loaded_check 'if [[ -e "${AWG_BT_SYS_DIR}/module/amneziawg" ]]; then' 'if false; then'
mutant no_autoload_check 'if modinfo -n amneziawg >/dev/null 2>&1; then' 'if false; then'
mutant no_saveconfig_check '_awgBtSaveConfigEnabled "${CONFIG_FILE}" || RC=$?' 'RC=1'
mutant b1_no_preexisting_refusal 'if [[ -n "${PRESENT}" ]]; then' 'if false; then'
# poststart and the shared active-instance check.
mutant no_tun_check $'if ! _awgBtLinkIsTun "${INTERFACE_NAME}"; then\n\t\t_awgBtErr "${INTERFACE_NAME} is not a TUN device' \
	$'if false; then\n\t\t_awgBtErr "${INTERFACE_NAME} is not a TUN device'
mutant no_exe_check 'if [[ "${EXE}" != "${_AWG_BT_VERIFIED_BIN}" ]]; then' 'if false; then'
# Attempt identity and the guarded down (B1).
mutant b1_ignore_attempt_identity '_AWG_BT_ATTEMPT="${INVOCATION_ID}"' '_AWG_BT_ATTEMPT=00000000000000000000000000000000'
mutant b1_skip_final_ifindex_recheck $'\tif ! _awgBtLinkIsOwned "${INTERFACE_NAME}" "$3" "$4"; then' $'\tif false; then'
# Not a mutant: poststop's own ifindex test before a kernel down is repeated,
# after the blocking preparation, inside _awgBtGuardedDown, so removing only
# the first changes nothing observable.
# Replay durability and the down record (S1).
mutant s1_replay_without_durable_intent 'if _awgBtFlagRaise "${INTERFACE_NAME}" replay; then' \
	'if _awgBtFlagRaise "${INTERFACE_NAME}" replay || true; then'
# Not a mutant: skipping poststop's "replay already started" branch cannot run
# a hook twice, because the replay flag can be raised only once.
mutant s1_down_not_recorded_before_down $'\tif [[ -z "${5:-}" ]] && ! _awgBtFlagRaise "${INTERFACE_NAME}" down; then' $'\tif false; then'
mutant s1_failed_down_counts_as_intact \
	$'\tif [[ -n "$2" && "$(_awgBtLinkIndex "$1")" == "$2" ]]; then\n\t\t_AWG_BT_STATE[DOWN]=failed-intact' \
	$'\tif true; then\n\t\t_AWG_BT_STATE[DOWN]=failed-intact'
mutant s1_replay_after_partial_down \
	'if [[ "${_AWG_BT_STATE[DOWN]}" == failed-intact ]] && ! _awgBtLinkExists "${INTERFACE_NAME}"; then' \
	'if ! _awgBtLinkExists "${INTERFACE_NAME}"; then'
# Emergency cleanup and nonterminal state (S9).
mutant s9_no_emergency_down '"${INTERFACE_NAME}" "${CONFIG_FILE}" any "${_AWG_BT_STATE[IFINDEX]:-${INDEX}}" noflag' \
	'"${INTERFACE_NAME}" /nonexistent any "${_AWG_BT_STATE[IFINDEX]:-${INDEX}}" noflag'
mutant s9_emergency_needs_run_dir 'if WORK="$(_awgBtTryDownCopy "${AWG_BT_TMP_DIR}/awg-boringtun-down.XXXXXX" "$1" "$2")"; then' 'if false; then'
# The old ordering: /tmp only when the runtime directory cannot allocate, so a
# failed write or chmod there ends the down copy.
mutant s9_down_copy_no_retry_after_write \
	$'\tif _awgBtPrepareRunDir && WORK="$(_awgBtTryDownCopy "${AWG_BT_RUN_DIR}/down.XXXXXX" "$1" "$2")"; then' \
	$'\tif _awgBtPrepareRunDir && WORK="$(mktemp -d "${AWG_BT_RUN_DIR}/down.XXXXXX" 2>/dev/null)"; then\n\t\trm -rf -- "${WORK}"\n\t\tWORK="$(_awgBtTryDownCopy "${AWG_BT_RUN_DIR}/down.XXXXXX" "$1" "$2")" || return 1'
# A failed replay is not terminal, and the SaveConfig filter fails on any
# failed write.
mutant s9_replay_result_ignored 'if ! _awgBtReplayPostDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"; then' \
	'_awgBtReplayPostDown "${INTERFACE_NAME}" "${_AWG_BT_STATE[CONFIG]}"; if false; then'
mutant s9_done_after_failed_replay 'cleanup is incomplete, and its hooks are never run again"' \
	'cleanup is incomplete, and its hooks are never run again"; _awgBtFlagRaise "${INTERFACE_NAME}" "done"'
mutant s9_filter_masks_write_error $'\t\tif ! printf \'%s\\n\' "${LINE}"; then\n\t\t\tRC=1\n\t\t\tbreak\n\t\tfi\n' \
	$'\t\tprintf \'%s\\n\' "${LINE}"\n'
mutant s9_remove_incomplete_state 'if ((TERMINAL && ! KEEP)); then' 'if ((! KEEP)); then'
mutant s9_missing_up_is_terminal $'elif ! _awgBtFlagIs "${INTERFACE_NAME}" up; then\n\t\t\t_awgBtErr "awg-quick up of' \
	$'elif ! _awgBtFlagIs "${INTERFACE_NAME}" up; then\n\t\t\tTERMINAL=1\n\t\t\t_awgBtErr "awg-quick up of'
mutant s9_socket_unlink_failure_ignored \
	$'cannot be removed; cleanup is incomplete"\n\t\tKEEP=1' $'cannot be removed; cleanup is incomplete"'
# Socket ownership (S2).
mutant s2_remove_replaced_node '[[ "${CURRENT}" == "$2" ]] || return 0' ':'
mutant s2_remove_while_owner_lives '_awgBtProcessIs "$3" "$4" && return 0' ':'
mutant s2_record_without_fd_proof 'ss -xlHe 2>/dev/null | awk' 'true || ss -xlHe 2>/dev/null | awk'
mutant s2_inode_only_identity "stat -c '%d:%i:%f:%.9Z'" "stat -c '%d:%i:%f:0.000000000'"
# SaveConfig (S5).
mutant s5_down_keeps_saveconfig '_awgBtWithoutSaveConfig "$3" >"${WORK}/$2.conf"' 'cat -- "$3" >"${WORK}/$2.conf"'
mutant s5_quickup_default_config 'if ! INVOCATION_ID="${ATTEMPT}" "${CTL}" precheck "${INTERFACE_NAME}" "${CONFIG_FILE}"; then' 'if ! INVOCATION_ID="${ATTEMPT}" "${CTL}" precheck "${INTERFACE_NAME}"; then'
# ensureAwgBackendReady (S6).
mutant s6_no_active_check 'if ! _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}"; then' 'if false; then'
mutant s6_no_mainpid_check 'if [[ "${MAIN_PID}" != "${_AWG_BT_STATE[PID]}" ]]; then' 'if false; then'
# ListenPort in staged validation (S7).
mutant s7_no_port_validation 'if ((PORTS > 1)) || ! [[ "${PORT}" =~ ^[1-9][0-9]{0,4}$ ]] || ((10#${PORT} > 65535)); then' 'if false; then'
# daemon-reload (S8).
mutant s8_reload_only_on_change $'\tsystemctl daemon-reload || return 1\n\treturn 0' $'\t((_AWG_BT_FILE_CHANGED == 0)) || systemctl daemon-reload || return 1\n\treturn 0'
# Process identity (S4).
mutant s4_signal_without_identity $'\t_awgBtProcessIs "$1" "$2" || return 1\n\tkill "-$3" "$1"' $'\tkill "-$3" "$1"'
mutant s4_zombie_counts_as_alive '[[ -n "${FIELDS[0]:-}" && "${FIELDS[0]}" != [ZXx] && "${FIELDS[19]:-}" == "${START}" ]]' '[[ -n "${FIELDS[0]:-}" && "${FIELDS[19]:-}" == "${START}" ]]'
# Scratch lifecycle (S3) and the sweep.
mutant s3_no_scratch_collision_check '_awgBtErr "refusing to start scratch interface ${NAME}: the name is already in use"'$'\n'"${T}${T}return 1" ':'
mutant s3_no_pdeathsig 'exec setpriv --pdeathsig KILL -- "${_AWG_BT_ARGV[@]}"' 'exec "${_AWG_BT_ARGV[@]}"'
mutant s3_daemon_keeps_ignored_signals $'\t\ttrap - HUP INT TERM\n\t\t_awgBtCloseInheritedFds\n\t\t_awgBtScratchRegisterSelf CHILD' $'\t\t_awgBtCloseInheritedFds\n\t\t_awgBtScratchRegisterSelf CHILD'
mutant s3_child_execs_without_guardian $'\t_awgBtProcessIs "${GUARD_RECORD[GUARD_PID]}" "${GUARD_RECORD[GUARD_START]}"\n}' $'\ttrue\n}'
mutant s3_child_not_registered $'\t\t_awgBtScratchRegisterSelf CHILD || exit 1\n' ''
# The old ordering: the guardian records the systemd-run client after the
# fork, so the client can submit the unit before any record names it.
mutant s3_parent_records_client \
	$'\t\t\t_awgBtScratchRegisterSelf CLIENT || exit 1\n' '' \
	'_awgBtScratchAwaitRegistration CLIENT "${CLIENT}" || { wait "${CLIENT}"; return 1; }' \
	'local -A CLIENT_RECORD=(); local CLIENT_START; if CLIENT_START="$(_awgBtProcessStartTime "${CLIENT}")"; then CLIENT_RECORD=([FORMAT]=1 [TOKEN]="${TOKEN}" [CLIENT_PID]="${CLIENT}" [CLIENT_START]="${CLIENT_START}"); _awgBtScratchSave "${DIR}/${TOKEN}.client" "${_AWG_BT_SCRATCH_CLIENT_KEYS}" CLIENT_RECORD; fi'
# Either side of the reclaim handshake alone: the client ignores the mark, or
# the reclaim reads the records before it marks the attempt. Not a mutant:
# marking between the record loads and their existence check, because a
# record that appears after its load then fails that check as unreadable and
# the reclaim keeps everything.
mutant s3_client_ignores_reclaim_mark $'\t[[ ! -e "${DIR}/${TOKEN}.reclaim" ]] || return 1\n' ''
mutant s3_reclaim_marks_after_reading \
	$'\tif [[ ! -e "${DIR}/${TOKEN}.reclaim" ]] && ! _awgBtWriteState "${DIR}/${TOKEN}.reclaim" ""; then\n\t\t_awgBtErr "cannot mark scratch attempt ${TOKEN} as being reclaimed; its records are kept"\n\t\tLEFT=1\n\tfi\n' '' \
	$'\t# A live registered systemd-run client may still create the unit: wait for\n' \
	$'\tif [[ ! -e "${DIR}/${TOKEN}.reclaim" ]] && ! _awgBtWriteState "${DIR}/${TOKEN}.reclaim" ""; then\n\t\tLEFT=1\n\tfi\n\t# A live registered systemd-run client may still create the unit: wait for\n'
# A registrant must see both the owner record and no mark; the reclaim removes
# the owner record before the mark.
mutant s3_child_skips_owner_check $'\t_awgBtScratchOwnerRecordValid || return 1\n' ''
mutant s3_child_ignores_owner_and_mark \
	$'\t[[ ! -e "${DIR}/${TOKEN}.reclaim" ]] || return 1\n\t_awgBtScratchOwnerRecordValid || return 1\n' ''
mutant s3_reclaim_unmarks_first $'\trm -f -- "${DIR}/${TOKEN}.owner" || return 1\n' \
	$'\trm -f -- "${DIR}/${TOKEN}.reclaim"\n\trm -f -- "${DIR}/${TOKEN}.owner" || return 1\n'
mutant s3_sweep_reclaims_while_client_lives \
	$'the records are kept"\n\t\t\treturn 1' $'the records are kept"'
mutant s3_unit_without_gate \
	"'[[ -e \"\$1\" && ! -e \"\$2\" ]] || exit 0; shift 2; exec \"\$@\"'" "'shift 2; exec \"\$@\"'"
mutant s3_reclaim_leaves_unit $'\t\tsystemctl stop "${UNIT}.service" >/dev/null 2>&1\n' ''
mutant s3_sweep_ignores_liveness '((ALIVE)) && continue' ':'
mutant s3_no_sweep $'\t_awgBtScratchSweep\n\t_awgBtVerifyStore || return 1' $'\t_awgBtVerifyStore || return 1'
# The ListenPort filter and the awg-quick parser.
mutant filter_always_strips '((INDEX == PORT_INDEX)) && ((10#${CONFIGURED} == LIVE))' '((INDEX == PORT_INDEX))'
mutant filter_never_strips '((INDEX == PORT_INDEX)) && ((10#${CONFIGURED} == LIVE))' 'false'
mutant parser_case_sensitive $'\tshopt -s nocasematch\n\twhile read -r LINE' $'\twhile read -r LINE'

if [[ $# -gt 0 ]]; then
	declare -a SELECTED=()
	for NAME in "$@"; do
		FOUND=0
		for I in "${!NAMES[@]}"; do
			[[ "${NAMES[I]}" == "${NAME}" ]] && SELECTED+=("${I}") && FOUND=1
		done
		((FOUND)) || { echo "unknown mutant ${NAME}" >&2; exit 2; }
	done
else
	SELECTED=("${!NAMES[@]}")
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-mutants.XXXXXX")"
trap 'rm -rf -- "${WORK}"' EXIT

run_one() { # <index>
	local I="$1" DIR="${WORK}/m$1" OUT RC SUMMARY P
	local -a PAIRS=()
	mkdir -p "${DIR}/tests" "${DIR}/scripts"
	cp "${PROJECT_ROOT}/tests/test-boringtun-runtime.sh" "${DIR}/tests/"
	cp "${PROJECT_ROOT}/scripts/boringtun-artifact.sh" "${DIR}/scripts/"
	cp "${PROJECT_ROOT}/amneziawg-install.sh" "${DIR}/amneziawg-install.sh"
	mapfile -d "${SEP}" -t PAIRS < <(printf '%s' "${EDITS[I]}")
	for ((P = 0; P + 1 < ${#PAIRS[@]}; P += 2)); do
		if ! OLD="${PAIRS[P]}" NEW="${PAIRS[P + 1]}" perl -0777 -ne '
			my $o = $ENV{OLD}; my $n = $ENV{NEW};
			my $c = () = /\Q$o\E/g;
			die "edit '"$((P / 2 + 1))"' matches $c times\n" unless $c == 1;
			s/\Q$o\E/$n/; print;' "${DIR}/amneziawg-install.sh" >"${DIR}/mutated.sh" 2>"${DIR}/apply.err"; then
			printf '%-38s DID NOT APPLY (%s)\n' "${NAMES[I]}" "$(cat "${DIR}/apply.err")"
			return
		fi
		mv -- "${DIR}/mutated.sh" "${DIR}/amneziawg-install.sh"
	done
	OUT="$(cd "${DIR}" && timeout 900 bash tests/test-boringtun-runtime.sh 2>&1)"
	RC=$?
	SUMMARY="$(grep 'runtime tests:' <<<"${OUT}" | tail -n 1)"
	if ((RC == 0)); then
		printf '%-38s SURVIVED (%s)\n' "${NAMES[I]}" "${SUMMARY}"
	else
		printf '%-38s caught: %s | %s\n' "${NAMES[I]}" "${SUMMARY:-no summary, rc=${RC}}" \
			"$(grep -m1 'FAIL:' <<<"${OUT}" | sed 's/^ *//' | cut -c1-100)"
	fi
}

for I in "${SELECTED[@]}"; do
	while (($(jobs -rp | wc -l) >= JOBS)); do
		wait -n
	done
	run_one "${I}" >"${WORK}/result.${I}" &
done
wait

BAD=0
for I in "${SELECTED[@]}"; do
	cat "${WORK}/result.${I}"
	grep -qE 'SURVIVED|DID NOT APPLY' "${WORK}/result.${I}" && BAD=$((BAD + 1))
done
echo
echo "BoringTun runtime mutants: $((${#SELECTED[@]} - BAD)) of ${#SELECTED[@]} caught"
((BAD == 0))
