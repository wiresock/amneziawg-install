#!/usr/bin/env bash

# Mutation check for the BoringTun binary lifecycle (--upgrade-boringtun,
# --rollback-boringtun). Each mutant breaks one rule of the release identity,
# the store links, the validation of a target before it becomes current, the
# restoration after a failure, retention or the status in a private copy of
# the repository, and tests/test-boringtun-lifecycle.sh must then fail with
# the named assertion. A mutant that no longer applies (its code changed) or
# that survives fails this script.
#
# It runs the suite once per mutant, so it is not part of CI:
#
#   bash tests/mutate-boringtun-lifecycle.sh [-j JOBS] [NAME...]

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=helpers/mutation-engine.sh
source "${SCRIPT_DIR}/helpers/mutation-engine.sh"

mutation_suite test-boringtun-lifecycle '^BoringTun lifecycle tests: ([0-9]+) passed, ([0-9]+) failed$' '^  FAIL: '

INSTALLER=amneziawg-install.sh
SUITE=test-boringtun-lifecycle
# mutant <name> <text a failing assertion contains> <exact text, present exactly once> <replacement>
mutant() {
	mutation_add "$1" "${SUITE}" "${INSTALLER}" "$2" "$3" "$4"
}

# Release identity: build 1 keeps the legacy name, later builds name theirs.
mutant build1_gets_named "the published build 1 keeps the store name PR 4 and PR 5 installs gave it" \
	'[[ "$3" == 1 ]] || SUFFIX="-b$3"' 'SUFFIX="-b$3"'
mutant build_ignored "and not their store directories" \
	'[[ "$3" == 1 ]] || SUFFIX="-b$3"' ':'
mutant build_binding_dropped "b2 verifies under its own name" \
	'-g${FIELDS[source_commit]:0:12}${BUILD_PART}-linux-${ARCH}-musl" ]]; then' '-g${FIELDS[source_commit]:0:12}-linux-${ARCH}-musl" ]]; then'

# Links and the target.
mutant link_target_unchecked "previous is an absolute link:   because of it" \
	'if [[ ! -L "${LINK}" || "${OWNER}" != "${AWG_BT_TRUSTED_UID}" ]] || ! _awgBtReleaseIdValid "${TARGET}"; then' 'if [[ ! -L "${LINK}" ]]; then'
mutant rollback_to_current "a rollback whose previous names current fails" \
	'if ((PREVIOUS_EXISTED == 0)) || [[ "${PREVIOUS_ID}" == "${CURRENT_ID}" ]]; then' 'if ((PREVIOUS_EXISTED == 0)); then'
mutant installed_repository_unchecked "a MANIFEST of another source repository" \
	'if [[ "${REPOSITORY}" != "${AWG_BT_RELEASE_SOURCE_REPOSITORY}" ]]; then' 'if false; then'
mutant installed_version_from_pin "the rollback succeeds" \
	'		EXPECTED_VERSION="${_AWG_BT_VERIFIED_VERSION}"' '		:'

# Validation of the target before it becomes current.
mutant target_not_validated "a previous binary that rejects the current AWG 3.0 settings is refused" \
	'if ! _awgBtValidateReleaseCandidate "${TARGET}" "${WORK}"; then' 'if false; then'
mutant scratch_ignores_candidate "a scratch instance of a candidate runs the candidate's verified binary, not current's" \
	'if [[ -n "${_AWG_BT_CANDIDATE_RELEASE}" ]]; then' 'if false; then'
mutant candidate_from_environment "the environment never selects a candidate" \
	$'activation (_awgBtValidateReleaseCandidate). Set only by that function and\n# reset here, so the environment can never select it.\n_AWG_BT_CANDIDATE_RELEASE=""' \
	$'activation (_awgBtValidateReleaseCandidate). Set only by that function and\n# reset here, so the environment can never select it.\n_AWG_BT_CANDIDATE_RELEASE="${_AWG_BT_CANDIDATE_RELEASE:-}"'
mutant probe_skipped "the AWG 3.0 probe ran on the new binary with the persisted key" \
	'"${AWG_PROTOCOL_VERSION_3}") probeAwg3Capability "${AWG_HEADER_PROTECTION_KEY}" || RC=1 ;;' '"${AWG_PROTOCOL_VERSION_3}") ;;'
mutant clients_not_validated "the new binary validated the server and both client configs" \
	'			FILES+=("${WORK}/client-${INDEX}.conf")' '			:'

# Gates before any change.
mutant kernel_allowed "a kernel installation has no BoringTun binary to upgrade" \
	$'\tif [[ "${AWG_BACKEND}" != "${AWG_BACKEND_BORINGTUN}" ]]; then\n\t\techo "ERROR: --${MODE}-boringtun applies' \
	$'\tif false; then\n\t\techo "ERROR: --${MODE}-boringtun applies'
mutant transitional_accepted "'activating': the upgrade aborts" \
	$'\t\tactive) ACTIVE=1 ;;\n\t\tinactive | failed) ;;\n\t\t*)\n\t\t\techo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2\n\t\t\treturn 1\n\t\t\t;;\n\tesac\n\n\tif [[ "${MODE}" == upgrade ]]; then' \
	$'\t\tactive) ACTIVE=1 ;;\n\t\tinactive | failed | activating) ;;\n\t\t*)\n\t\t\techo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2\n\t\t\treturn 1\n\t\t\t;;\n\tesac\n\n\tif [[ "${MODE}" == upgrade ]]; then'
mutant failed_unit_started "failed: the service is not started" \
	$'\t\tactive) ACTIVE=1 ;;\n\t\tinactive | failed) ;;\n\t\t*)\n\t\t\techo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2\n\t\t\treturn 1\n\t\t\t;;\n\tesac\n\n\tif [[ "${MODE}" == upgrade ]]; then' \
	$'\t\tactive | failed) ACTIVE=1 ;;\n\t\tinactive) ;;\n\t\t*)\n\t\t\techo "ERROR: ${UNIT} is ${STATE:-in an unknown state}; nothing was changed. Retry once it is active, inactive or failed." >&2\n\t\t\treturn 1\n\t\t\t;;\n\tesac\n\n\tif [[ "${MODE}" == upgrade ]]; then'
mutant noop_ignores_live_daemon "and says so instead of reporting a no-op" \
	'if ((ACTIVE)) && ! _awgBtCheckServedByBoringtun "${SERVER_AWG_NIC}" >/dev/null 2>&1; then' 'if false; then'

# The switch, and its restoration.
mutant current_before_previous "previous is written before current" \
	$'\tif ! _awgBtSetStoreLink previous "${CURRENT_ID}"; then\n\t\techo "ERROR: could not point ${AWG_BT_STORE_DIR}/previous at ${CURRENT_ID}." >&2\n\t\trestoreBoringtunLifecycle\n\t\treturn 1\n\tfi\n\tif ! _awgBtSetStoreLink current "${TARGET}"; then\n\t\techo "ERROR: could not point ${AWG_BT_STORE_DIR}/current at ${TARGET}." >&2\n\t\trestoreBoringtunLifecycle\n\t\treturn 1\n\tfi' \
	$'\tif ! _awgBtSetStoreLink current "${TARGET}"; then\n\t\techo "ERROR: could not point ${AWG_BT_STORE_DIR}/current at ${TARGET}." >&2\n\t\trestoreBoringtunLifecycle\n\t\treturn 1\n\tfi\n\tif ! _awgBtSetStoreLink previous "${CURRENT_ID}"; then\n\t\techo "ERROR: could not point ${AWG_BT_STORE_DIR}/previous at ${CURRENT_ID}." >&2\n\t\trestoreBoringtunLifecycle\n\t\treturn 1\n\tfi'
mutant previous_not_restored "previous, already written, is restored" \
	$'\t\t\tif ! _awgBtSetStoreLink previous "${PREVIOUS_ID}"; then' $'\t\t\tif false; then'
mutant no_recovery_restart "restart fails: the original release is restarted" \
	'if ((ACTIVE && RESTARTED)); then' 'if false; then'
mutant recovery_restart_always "writing previous fails: no restart, as none had happened" \
	'if ((ACTIVE && RESTARTED)); then' 'if ((ACTIVE)); then'
mutant activation_unverified "unverified: a second restart, on the original" \
	'if ! systemctl restart "${UNIT}" || ! _awgBtVerifyLifecycleActivation; then
			echo "ERROR: ${UNIT} did not come up verifiably on ${TARGET}; restoring ${CURRENT_ID}." >&2' \
	'if ! systemctl restart "${UNIT}"; then
			echo "ERROR: ${UNIT} did not come up verifiably on ${TARGET}; restoring ${CURRENT_ID}." >&2'
mutant peers_unchecked "an interface without the server's peers fails the activation" \
	'if ! _awgBtInterfaceCarriesServerPeers; then' 'if false; then'
mutant no_term_trap "after restoring both links and removing the downloaded release" \
	$'\ttrap \'interruptBoringtunLifecycle 143\' TERM\n' ''
mutant downloaded_target_kept "current unchanged, and the release this attempt downloaded is removed" \
	'if ((CREATED)) || { [[ "${MODE}" == upgrade ]] && [[ "${_AWG_BT_REL_CREATED:-0}" == 1 ]]; }; then' 'if false; then'

# Retention.
mutant old_previous_kept "the old previous is removed once the new state is final" \
	'if ((PREVIOUS_EXISTED)) && [[ "${PREVIOUS_ID}" != "${TARGET}" && "${PREVIOUS_ID}" != "${CURRENT_ID}" ]]; then' 'if false; then'
mutant prune_ignores_links "pruning never removes the release current names" \
	$'\t\t((RC == 0)) && [[ "${_AWG_BT_LINK_TARGET}" != "${ID}" ]] || return 1' $'\t\t:'
mutant prune_follows_symlinks "pruning never removes a symlink named like a release" \
	$'[[ -d "${DIR}" && ! -L "${DIR}" && "${CANONICAL_DIR}" == "${CANONICAL_STORE}/${ID}" ]] &&\n\t\t_awgBtTrustedAncestors "${DIR}" && _awgBtTrustedNode "${DIR}" dir || return 1' \
	'[[ -e "${DIR}" ]] || return 1'

# Status.
mutant status_previous_equal_current "a previous that names current is invalid" \
	'if [[ "${PREVIOUS}" == "${INSTALLED}" ]] || ! _awgBtVerifyRelease "${PREVIOUS}" 2>/dev/null; then' 'if ! _awgBtVerifyRelease "${PREVIOUS}" 2>/dev/null; then'
mutant status_no_daemon_release "and is shown to run the old release" \
	'[[ ! "${DAEMON_PID}" =~ ^[1-9][0-9]*$ ]] || DAEMON_RELEASE="$(_awgBtDaemonRelease "${DAEMON_PID}")"' ':'

mutation_main "BoringTun lifecycle" "${PROJECT_ROOT}" "$@"
