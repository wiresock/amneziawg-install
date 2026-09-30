#!/usr/bin/env bash
# Shared engine of the BoringTun mutation runners (tests/mutate-*.sh). A runner
# sources it, declares its mutants with mutation_add and calls mutation_main.
#
# A mutant counts as caught only when it was validly tested:
#   1. the repository snapshot was created and holds every file involved;
#   2. every suite involved has a declared result format (mutation_suite) and
#      passes unmutated on that snapshot (the baseline);
#   3. each edit of the mutant applies exactly once and changes the file;
#   4. the mutated file still passes `bash -n`: a mutant that breaks the
#      syntax tests nothing about behaviour, so it is INVALID, never caught;
#   5. the suite's own final summary, in its declared format, counts at least
#      one failed assertion;
#   6. at least one line of the output is an assertion failure in the suite's
#      declared format and, when the mutant names an expected failure, one of
#      those lines contains it.
# A mutant whose suite passes SURVIVED. Anything else (an edit that does not
# apply, a syntax error, a missing suite, exit 126 or 127, a timeout, no
# summary in the declared format, text such as "1 failed prerequisite check"
# that is no summary, a summary without an assertion failure) is INVALID: the
# mutant was not tested, and the runner fails. The harness itself fails (exit
# 2) when the snapshot or a baseline fails, or a suite has no declared format.
#
# The engine's own behaviour is tested by tests/test-mutation-engine.sh.

MUTATION_SEP=$'\x1f'
MUTATION_TIMEOUT="${MUTATION_TIMEOUT:-900}"
declare -a MUTATION_NAMES=() MUTATION_SUITES=() MUTATION_FILES=() MUTATION_EXPECT=() MUTATION_EDITS=()
declare -A MUTATION_SUMMARY=() MUTATION_FAILURE=()

# mutation_suite <suite> <summary ERE> <assertion failure ERE>: how tests/<suite>.sh
# reports. The summary ERE matches a whole line, and its last group captures
# the number of failed assertions; the failure ERE matches the lines that
# record one failed assertion.
mutation_suite() {
	MUTATION_SUMMARY["$1"]="$2"
	MUTATION_FAILURE["$1"]="$3"
}

# mutation_add <name> <suite> <file> <expected failure or ""> <old> <new> [<old> <new>]...
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

# The failed-assertion count of SUITE's final summary in OUTPUT: the last
# whole line that matches its declared summary ERE, or nothing.
_mutation_failed_count() { # <suite> <output>
	local LINE COUNT=""
	while IFS= read -r LINE; do
		if [[ "${LINE}" =~ ${MUTATION_SUMMARY[$1]} ]]; then
			COUNT="${BASH_REMATCH[${#BASH_REMATCH[@]} - 1]}"
		fi
	done <<<"$2"
	[[ "${COUNT}" =~ ^[0-9]+$ ]] && printf '%s\n' "${COUNT}"
}

# The lines of OUTPUT that record a failed assertion of SUITE.
_mutation_failures() { # <suite> <output>
	grep -E -- "${MUTATION_FAILURE[$1]}" <<<"$2"
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
	local I="$1" DIR="${MUTATION_WORK}/m$1" TARGET P FAILED FAILURES EXPECT="${MUTATION_EXPECT[$1]}" FIRST
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
	if ! bash -n "${TARGET}" 2>"${DIR}/.syntax.err"; then
		printf '%-38s INVALID (the mutated file has a syntax error, so no behaviour was tested: %s)\n' "${NAME}" "$(head -n 1 "${DIR}/.syntax.err")"
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
	FAILED="$(_mutation_failed_count "${SUITE}" "${_MUTATION_OUT}")"
	if [[ -z "${FAILED}" ]]; then
		printf '%-38s INVALID (%s printed no summary in its format; exit %s)\n' "${NAME}" "${SUITE}" "${_MUTATION_RC}"
		return
	fi
	FAILURES="$(_mutation_failures "${SUITE}" "${_MUTATION_OUT}")"
	if ((_MUTATION_RC == 0 && FAILED == 0)) && [[ -z "${FAILURES}" ]]; then
		printf '%-38s SURVIVED %s\n' "${NAME}" "${SUITE}"
		return
	fi
	if ((FAILED == 0 || _MUTATION_RC == 0)); then
		printf '%-38s INVALID (%s exited %s with %s failed assertions in its summary)\n' "${NAME}" "${SUITE}" "${_MUTATION_RC}" "${FAILED}"
		return
	fi
	if [[ -z "${FAILURES}" ]]; then
		printf '%-38s INVALID (%s summarised %s failed, but printed no assertion failure)\n' "${NAME}" "${SUITE}" "${FAILED}"
		return
	fi
	FIRST="$(head -n 1 <<<"${FAILURES}" | sed 's/^ *//' | cut -c1-90)"
	if [[ -n "${EXPECT}" ]] && ! grep -qF -- "${EXPECT}" <<<"${FAILURES}"; then
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
		if [[ -z "${MUTATION_SUMMARY[${SUITE}]:-}" || -z "${MUTATION_FAILURE[${SUITE}]:-}" ]]; then
			echo "HARNESS FAILURE: ${SUITE} has no declared summary and failure format (mutation_suite)" >&2
			return 2
		fi
	done
	for SUITE in "${SUITES[@]}"; do
		_mutation_extract "${MUTATION_WORK}/baseline-${SUITE}" || { echo "HARNESS FAILURE: cannot extract the snapshot" >&2; return 2; }
		_mutation_run_suite "${MUTATION_WORK}/baseline-${SUITE}" "${SUITE}"
		FAILED="$(_mutation_failed_count "${SUITE}" "${_MUTATION_OUT}")"
		if ((_MUTATION_RC != 0)) || [[ "${FAILED}" != 0 ]] || [[ -n "$(_mutation_failures "${SUITE}" "${_MUTATION_OUT}")" ]]; then
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
