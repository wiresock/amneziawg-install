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
JOBS=4
if [[ "${1:-}" == -j ]]; then
	JOBS="${2:?}"
	shift 2
fi

declare -a NAMES=() SUITES=() FILES=() EDITS=()
SEP=$'\x1f'
INSTALLER=amneziawg-install.sh
PROXY_INSTALLER=amneziawg-proxy/scripts/amneziawg-proxy-install.sh
# mutant <name> <suite> <file> <exact text, present exactly once> <replacement>
mutant() {
	NAMES+=("$1")
	SUITES+=("$2")
	FILES+=("$3")
	EDITS+=("$4${SEP}$5${SEP}")
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
mutant version_run_outside_store test-boringtun-host "${INSTALLER}" \
	'_awgBtCheckReleaseDir "${WORK}/unpacked/${_AWG_BT_REL_ID}" "${ARCH}" 0' '_awgBtCheckReleaseDir "${WORK}/unpacked/${_AWG_BT_REL_ID}" "${ARCH}"'
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
# Kernel module.
mutant loaded_module_accepted test-boringtun-host "${INSTALLER}" \
	$'\tif [[ -e "${AWG_BT_SYS_DIR}/module/amneziawg" ]]; then\n\t\techo -e "${RED}ERROR: the AmneziaWG kernel module is loaded, so awg-quick would use it' \
	$'\tif false; then\n\t\techo -e "${RED}ERROR: the AmneziaWG kernel module is loaded, so awg-quick would use it'
mutant module_blocked_without_consent test-boringtun-host "${INSTALLER}" \
	'if [[ "${AWG_BORINGTUN_BLOCK_KERNEL_MODULE:-}" != "y" ]]; then' 'if false; then'
mutant installed_module_takes_kernel_path test-boringtun-runtime "${INSTALLER}" \
	'if modinfo -n amneziawg >/dev/null 2>&1 && ! _awgBtKernelModuleBlocked; then' 'if false; then'
mutant override_not_proven_in_force test-boringtun-runtime "${INSTALLER}" \
	$'\tfor NAME in amneziawg rtnl-link-amneziawg; do\n\t\tOUTPUT="$(modprobe -n -v "${NAME}" 2>/dev/null)" || return 1\n\t\t[[ "${OUTPUT}" =~ ^install\\ /bin/false[[:space:]]*$ ]] || return 1\n\tdone\n' ''
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
mutant uninstall_removes_served_socket test-boringtun-host "${INSTALLER}" \
	$'\t\tif [[ -n "${LISTENERS}" ]]; then' $'\t\tif false; then'
mutant uninstall_ignores_running_daemon test-boringtun-host "${INSTALLER}" \
	$'\tDAEMONS="$(boringtunDaemonsOf "${INTERFACE_NAME}")"\n\tif [[ -n "${DAEMONS}" ]]; then' \
	$'\tDAEMONS="$(boringtunDaemonsOf "${INTERFACE_NAME}")"\n\tif false; then'
mutant uninstall_removes_foreign_helper test-boringtun-host "${INSTALLER}" \
	'if [[ "${LINE}" == "# ${NAME}: generated by amneziawg-install from its own functions." ]]; then' 'if true; then'
mutant uninstall_drops_params_on_failure test-boringtun-host "${INSTALLER}" \
	$'The configuration in ${AMNEZIAWG_DIR} was kept. Fix the cause and rerun the uninstall.${NC}"\n\t\t\texit 1' \
	$'The configuration in ${AMNEZIAWG_DIR} was kept. Fix the cause and rerun the uninstall.${NC}"'

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

WORK="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-host-mutants.XXXXXX")"
trap 'rm -rf -- "${WORK}"' EXIT
(cd "${PROJECT_ROOT}" && git ls-files -z | tar --null -T - -cf -) >"${WORK}/tree.tar"

run_one() { # <index>
	local I="$1" DIR="${WORK}/m$1" OUT RC SUMMARY P TARGET
	local -a PAIRS=()
	mkdir -p "${DIR}"
	tar -xf "${WORK}/tree.tar" -C "${DIR}"
	TARGET="${DIR}/${FILES[I]}"
	mapfile -d "${SEP}" -t PAIRS < <(printf '%s' "${EDITS[I]}")
	for ((P = 0; P + 1 < ${#PAIRS[@]}; P += 2)); do
		if ! OLD="${PAIRS[P]}" NEW="${PAIRS[P + 1]}" perl -0777 -ne '
			my $o = $ENV{OLD}; my $n = $ENV{NEW};
			my $c = () = /\Q$o\E/g;
			die "edit matches $c times\n" unless $c == 1;
			s/\Q$o\E/$n/; print;' "${TARGET}" >"${DIR}/mutated" 2>"${DIR}/apply.err"; then
			printf '%-38s DID NOT APPLY (%s)\n' "${NAMES[I]}" "$(cat "${DIR}/apply.err")"
			return
		fi
		cat -- "${DIR}/mutated" >"${TARGET}"
	done
	OUT="$(cd "${DIR}" && timeout 900 bash "tests/${SUITES[I]}.sh" 2>&1)"
	RC=$?
	SUMMARY="$(grep -E 'passed, [0-9]+ failed|tests, [0-9]+ failures|Results:' <<<"${OUT}" | tail -n 1)"
	if ((RC == 0)); then
		printf '%-38s SURVIVED %s (%s)\n' "${NAMES[I]}" "${SUITES[I]}" "${SUMMARY}"
	else
		printf '%-38s caught by %s: %s | %s\n' "${NAMES[I]}" "${SUITES[I]}" "${SUMMARY:-no summary, rc=${RC}}" \
			"$(grep -m1 -E 'FAIL|not ok' <<<"${OUT}" | sed 's/^ *//' | cut -c1-90)"
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
echo "BoringTun host mutants: $((${#SELECTED[@]} - BAD)) of ${#SELECTED[@]} caught"
((BAD == 0))
