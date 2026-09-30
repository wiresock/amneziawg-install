#!/usr/bin/env bash
# Shared engine of the BoringTun mutation runners (tests/mutate-*.sh). A runner
# sources it, declares its mutants with mutation_add and calls mutation_main.
#
# A mutant counts as caught only when it was validly tested:
#   1. the repository snapshot was created and holds every file involved;
#   2. every suite involved passes unmutated on that snapshot (the baseline);
#   3. each edit of the mutant applies exactly once;
#   4. the mutated file still passes `bash -n`, unless a syntax error is the
#      mutation itself (expectation @syntax);
#   5. the suite started and printed its own summary line;
#   6. that summary counts at least one failed assertion, and, when the mutant
#      names an expected failure, a failing assertion contains it.
# A mutant whose suite passes SURVIVED. Anything else (an edit that does not
# apply, a syntax error, a missing suite, exit 126 or 127, a timeout, no
# summary, a failure that is not a failed assertion) is INVALID: the mutant was
# not tested, and the runner fails. The harness itself fails (exit 2) when the
# snapshot or a baseline fails.
#
# The engine's own behaviour is tested by tests/test-mutation-engine.sh.

MUTATION_SEP=$'\x1f'
MUTATION_TIMEOUT="${MUTATION_TIMEOUT:-900}"
declare -a MUTATION_NAMES=() MUTATION_SUITES=() MUTATION_FILES=() MUTATION_EXPECT=() MUTATION_EDITS=()

# mutation_add <name> <suite> <file> <expected failure, @syntax or ""> <old> <new> [<old> <new>]...
# The suite is tests/<suite>.sh; the file is relative to the repository root.
# Several edits make one mutant; each must apply exactly once.
mutation_add() {
	local EDIT=""
	MUTATION_NAMES+=("$1")
	MUTATION_SUITES+=("$2")
	MUTATION_FILES+=("$3")
	MUTATION_EXPECT+=("$4")
	shift 4
	while (($# >= 2)); do
		EDIT+="$1${MUTATION_SEP}$2${MUTATION_SEP}"
		shift 2
	done
	MUTATION_EDITS+=("${EDIT}")
}

# The failed-assertion count in a suite's summary line ("N passed, M failed",
# "N tests, M failures", "Results: N/T passed, M failed"), or nothing.
_mutation_failed_count() { # <output>
	grep -E '[0-9]+ (failed|failures)([^0-9]|$)' <<<"$1" | tail -n 1 | sed -E 's/.*[^0-9]([0-9]+) (failed|failures).*/\1/'
}

# Extract the snapshot into DIR.
_mutation_extract() { # <dir>
	mkdir -p "$1" && tar -xf "${MUTATION_WORK}/tree.tar" -C "$1"
}

# Run a suite in DIR with the timeout. Sets _MUTATION_OUT and _MUTATION_RC.
_mutation_run_suite() { # <dir> <suite>
	_MUTATION_OUT="$(cd "$1" && timeout --kill-after=30 "${MUTATION_TIMEOUT}" bash "tests/$2.sh" 2>&1)"
	_MUTATION_RC=$?
}

_mutation_one() { # <index>
	local I="$1" DIR="${MUTATION_WORK}/m$1" TARGET P FAILED EXPECT="${MUTATION_EXPECT[$1]}" FIRST
	local -a PAIRS=()
	local NAME="${MUTATION_NAMES[I]}" SUITE="${MUTATION_SUITES[I]}"
	if ! _mutation_extract "${DIR}"; then
		printf '%-38s INVALID (the snapshot could not be extracted)\n' "${NAME}"
		return
	fi
	TARGET="${DIR}/${MUTATION_FILES[I]}"
	if [[ ! -f "${TARGET}" ]]; then
		printf '%-38s INVALID (no file %s)\n' "${NAME}" "${MUTATION_FILES[I]}"
		return
	fi
	mapfile -d "${MUTATION_SEP}" -t PAIRS < <(printf '%s' "${MUTATION_EDITS[I]}")
	if ((${#PAIRS[@]} < 2)); then
		printf '%-38s INVALID (no edit)\n' "${NAME}"
		return
	fi
	for ((P = 0; P + 1 < ${#PAIRS[@]}; P += 2)); do
		if ! OLD="${PAIRS[P]}" NEW="${PAIRS[P + 1]}" perl -0777 -ne '
			my $o = $ENV{OLD}; my $n = $ENV{NEW};
			my $c = () = /\Q$o\E/g;
			die "edit '"$((P / 2 + 1))"' matches $c times\n" unless $c == 1;
			s/\Q$o\E/$n/; print;' "${TARGET}" >"${DIR}/.mutated" 2>"${DIR}/.apply.err"; then
			printf '%-38s INVALID (did not apply: %s)\n' "${NAME}" "$(tr '\n' ' ' <"${DIR}/.apply.err")"
			return
		fi
		cat -- "${DIR}/.mutated" >"${TARGET}"
	done
	if cmp -s "${TARGET}" <(tar -xOf "${MUTATION_WORK}/tree.tar" "${MUTATION_FILES[I]}"); then
		printf '%-38s INVALID (the edits leave the file unchanged)\n' "${NAME}"
		return
	fi
	if [[ "${EXPECT}" != @syntax ]] && ! bash -n "${TARGET}" 2>"${DIR}/.syntax.err"; then
		printf '%-38s INVALID (the mutated file has a syntax error: %s)\n' "${NAME}" "$(head -n 1 "${DIR}/.syntax.err")"
		return
	fi
	if [[ ! -f "${DIR}/tests/${SUITE}.sh" ]]; then
		printf '%-38s INVALID (no suite tests/%s.sh)\n' "${NAME}" "${SUITE}"
		return
	fi
	_mutation_run_suite "${DIR}" "${SUITE}"
	case "${_MUTATION_RC}" in
		124 | 137)
			printf '%-38s INVALID (%s timed out after %ss)\n' "${NAME}" "${SUITE}" "${MUTATION_TIMEOUT}"
			return
			;;
		126 | 127)
			printf '%-38s INVALID (%s could not run: exit %s)\n' "${NAME}" "${SUITE}" "${_MUTATION_RC}"
			return
			;;
	esac
	FAILED="$(_mutation_failed_count "${_MUTATION_OUT}")"
	if [[ -z "${FAILED}" ]]; then
		printf '%-38s INVALID (%s printed no summary; exit %s)\n' "${NAME}" "${SUITE}" "${_MUTATION_RC}"
		return
	fi
	if ((_MUTATION_RC == 0 && FAILED == 0)); then
		printf '%-38s SURVIVED %s\n' "${NAME}" "${SUITE}"
		return
	fi
	if ((FAILED == 0 || _MUTATION_RC == 0)); then
		printf '%-38s INVALID (%s exited %s with %s failed assertions)\n' "${NAME}" "${SUITE}" "${_MUTATION_RC}" "${FAILED}"
		return
	fi
	FIRST="$(grep -m1 -E 'FAIL|not ok' <<<"${_MUTATION_OUT}" | sed 's/^ *//' | cut -c1-90)"
	if [[ -n "${EXPECT}" && "${EXPECT}" != @syntax ]] && ! grep -E 'FAIL|not ok' <<<"${_MUTATION_OUT}" | grep -qF -- "${EXPECT}"; then
		printf '%-38s INVALID (%s failed, but no failing assertion mentions "%s"; first: %s)\n' "${NAME}" "${SUITE}" "${EXPECT}" "${FIRST}"
		return
	fi
	printf '%-38s CAUGHT by %s (%s failed): %s\n' "${NAME}" "${SUITE}" "${FAILED}" "${FIRST}"
}

# mutation_main <label> <repository root> [-j JOBS] [NAME...]
mutation_main() {
	local LABEL="$1" ROOT="$2" JOBS=4 NAME FOUND I SUITE BAD=0 FAILED FILE
	local -a SELECTED=() SUITES=()
	shift 2
	if [[ "${1:-}" == -j ]]; then
		JOBS="${2:?}"
		shift 2
	fi
	if (($#)); then
		for NAME in "$@"; do
			FOUND=0
			for I in "${!MUTATION_NAMES[@]}"; do
				[[ "${MUTATION_NAMES[I]}" == "${NAME}" ]] && SELECTED+=("${I}") && FOUND=1
			done
			((FOUND)) || { echo "unknown mutant ${NAME}" >&2; return 2; }
		done
	else
		SELECTED=("${!MUTATION_NAMES[@]}")
	fi
	((${#SELECTED[@]})) || { echo "HARNESS FAILURE: no mutants" >&2; return 2; }
	MUTATION_WORK="$(mktemp -d "${TMPDIR:-/tmp}/mutants.XXXXXX")" || return 2
	# shellcheck disable=SC2064 # expand the work directory now
	trap "rm -rf -- '${MUTATION_WORK}'" EXIT
	if ! (cd "${ROOT}" && git ls-files -z >"${MUTATION_WORK}/files" && [[ -s "${MUTATION_WORK}/files" ]] &&
		tar --null -T "${MUTATION_WORK}/files" -cf "${MUTATION_WORK}/tree.tar"); then
		echo "HARNESS FAILURE: cannot snapshot the repository at ${ROOT}" >&2
		return 2
	fi
	for I in "${SELECTED[@]}"; do
		for FILE in "${MUTATION_FILES[I]}" "tests/${MUTATION_SUITES[I]}.sh"; do
			if ! tar -tf "${MUTATION_WORK}/tree.tar" "${FILE}" >/dev/null 2>&1; then
				echo "HARNESS FAILURE: the snapshot has no ${FILE} (mutant ${MUTATION_NAMES[I]})" >&2
				return 2
			fi
		done
		[[ " ${SUITES[*]} " == *" ${MUTATION_SUITES[I]} "* ]] || SUITES+=("${MUTATION_SUITES[I]}")
	done
	for SUITE in "${SUITES[@]}"; do
		_mutation_extract "${MUTATION_WORK}/baseline-${SUITE}" || { echo "HARNESS FAILURE: cannot extract the snapshot" >&2; return 2; }
		_mutation_run_suite "${MUTATION_WORK}/baseline-${SUITE}" "${SUITE}"
		FAILED="$(_mutation_failed_count "${_MUTATION_OUT}")"
		if ((_MUTATION_RC != 0)) || [[ "${FAILED}" != 0 ]]; then
			echo "HARNESS FAILURE: unmutated, ${SUITE} does not pass (exit ${_MUTATION_RC}, failed: ${FAILED:-no summary})" >&2
			grep -m5 -E 'FAIL|not ok|ERROR' <<<"${_MUTATION_OUT}" | sed 's/^/    /' >&2
			return 2
		fi
		echo "baseline: ${SUITE} passes unmutated"
		rm -rf -- "${MUTATION_WORK}/baseline-${SUITE}"
	done
	for I in "${SELECTED[@]}"; do
		while (($(jobs -rp | wc -l) >= JOBS)); do
			wait -n
		done
		_mutation_one "${I}" >"${MUTATION_WORK}/result.${I}" &
	done
	wait
	for I in "${SELECTED[@]}"; do
		if [[ -s "${MUTATION_WORK}/result.${I}" ]]; then
			cat "${MUTATION_WORK}/result.${I}"
		else
			printf '%-38s INVALID (no result)\n' "${MUTATION_NAMES[I]}"
			BAD=$((BAD + 1))
			continue
		fi
		grep -q ' CAUGHT by ' "${MUTATION_WORK}/result.${I}" || BAD=$((BAD + 1))
	done
	echo
	echo "${LABEL} mutants: $((${#SELECTED[@]} - BAD)) of ${#SELECTED[@]} caught, each validly tested"
	((BAD == 0))
}
