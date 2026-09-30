#!/usr/bin/env bash

# Self-tests of tests/helpers/mutation-engine.sh, the engine of the BoringTun
# mutation runners. A toy repository with toy suites checks that only a mutant
# whose suite reports a failed assertion counts as caught, and that every way a
# mutant can go untested (no snapshot, a missing or failing suite, an edit that
# does not apply, a syntax error, a timeout, exit 127, no summary, the wrong
# failing assertion) is reported as INVALID or as a harness failure, and fails
# the run.
#
# Requires git and perl.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ENGINE="${SCRIPT_DIR}/helpers/mutation-engine.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/mutation-engine-tests.XXXXXX")"
trap 'rm -rf -- "${T}"' EXIT

PASS=0
FAIL=0
ok() {
	echo "  OK: $1"
	PASS=$((PASS + 1))
}
not_ok() {
	echo "  FAIL: $1"
	FAIL=$((FAIL + 1))
}
check() { # <label> <command...>
	local LABEL="$1"
	shift
	if "$@"; then ok "${LABEL}"; else not_ok "${LABEL}"; fi
}

# The toy repository: tool.sh and suites that check it.
REPO="${T}/repo"
mkdir -p "${REPO}/tests/helpers"
cp -- "${ENGINE}" "${REPO}/tests/helpers/mutation-engine.sh"
cat >"${REPO}/tool.sh" <<'EOF'
#!/bin/bash
# A toy tool.
double() { echo $(($1 * 2)); }
RUNNER=true
EOF
cat >"${REPO}/tests/test-toy.sh" <<'EOF'
#!/bin/bash
source ./tool.sh
F=0
if [[ "$(double 2)" == 4 ]]; then echo "  OK: double 2 is 4"; else echo "  FAIL: double 2 is 4"; F=1; fi
if [[ "${EXIT_EARLY:-}" == 1 ]]; then exit 1; fi
echo "Toy tests: $((1 - F)) passed, ${F} failed"
exit "${F}"
EOF
cat >"${REPO}/tests/test-runs.sh" <<'EOF'
#!/bin/bash
source ./tool.sh
"${RUNNER}" || exit $?
echo "Runs tests: 1 passed, 0 failed"
EOF
cat >"${REPO}/tests/test-slow.sh" <<'EOF'
#!/bin/bash
source ./tool.sh
[[ "${SLOW:-}" == 1 ]] && sleep 30
echo "Slow tests: 1 passed, 0 failed"
EOF
cat >"${REPO}/tests/test-early.sh" <<'EOF'
#!/bin/bash
source ./tool.sh
[[ "${EARLY:-}" == 1 ]] && exit 1
echo "Early tests: 1 passed, 0 failed"
EOF
(cd "${REPO}" && git init -q && git add -A) || { echo "ERROR: git is required" >&2; exit 1; }

# run_toy <label> <mutant declarations...>: a runner with these mutants.
# Sets RC and OUT.
run_toy() {
	local NAME="$1"
	shift
	{
		echo 'set -uo pipefail'
		echo 'source "$(dirname "${BASH_SOURCE[0]}")/helpers/mutation-engine.sh"'
		printf '%s\n' "$@"
		echo 'mutation_main "Toy" "${ROOT}" -j 2'
	} >"${REPO}/tests/mutate-${NAME}.sh"
	OUT="$(ROOT="${ROOT:-${REPO}}" MUTATION_TIMEOUT="${MUTATION_TIMEOUT:-60}" bash "${REPO}/tests/mutate-${NAME}.sh" 2>&1)"
	RC=$?
}

echo "=== A validly caught mutant"
run_toy caught "mutation_add breaks_double test-toy tool.sh 'double 2 is 4' '\$((\$1 * 2))' '\$((\$1 * 3))'"
check "is CAUGHT" grep -q 'breaks_double *CAUGHT by test-toy (1 failed): FAIL: double 2 is 4' <<<"${OUT}"
check "after the unmutated suite passed" grep -q 'baseline: test-toy passes unmutated' <<<"${OUT}"
check "and the run passes" test "${RC}" -eq 0

echo "=== A surviving mutant"
run_toy survived "mutation_add comment_only test-toy tool.sh '' 'A toy tool.' 'A toy tool, edited.'"
check "is SURVIVED" grep -q 'comment_only *SURVIVED test-toy' <<<"${OUT}"
check "and fails the run" test "${RC}" -ne 0

echo "=== A mutant that does not apply"
run_toy notapply "mutation_add gone test-toy tool.sh '' 'no such text' 'x'"
check "is INVALID (did not apply)" grep -q 'gone *INVALID (did not apply: edit 1 matches 0 times' <<<"${OUT}"
check "and fails the run" test "${RC}" -ne 0
run_toy twice "mutation_add twice test-toy tool.sh '' 'o' 'x'"
check "an edit that matches more than once is INVALID" grep -q 'twice *INVALID (did not apply: edit 1 matches' <<<"${OUT}"

echo "=== A mutant that breaks the syntax"
run_toy syntax "mutation_add broken test-toy tool.sh '' 'double() {' 'double() {{ ('"
check "is INVALID (syntax error), not caught" grep -q 'broken *INVALID (the mutated file has a syntax error' <<<"${OUT}"
check "and fails the run" test "${RC}" -ne 0
run_toy syntaxok "mutation_add broken_on_purpose test-toy tool.sh @syntax 'double() {' 'double() {{ ('"
check "unless the syntax error is the mutation (@syntax)" grep -q 'broken_on_purpose *CAUGHT' <<<"${OUT}"

echo "=== A timeout"
MUTATION_TIMEOUT=2 run_toy timeout "mutation_add slow test-slow tool.sh '' 'RUNNER=true' \$'RUNNER=true\nSLOW=1'"
check "is INVALID (timed out), not caught" grep -q 'slow *INVALID (test-slow timed out after 2s)' <<<"${OUT}"
check "and fails the run" test "${RC}" -ne 0

echo "=== Exit 127"
run_toy exit127 "mutation_add missing_command test-runs tool.sh '' 'RUNNER=true' 'RUNNER=/nonexistent/command'"
check "is INVALID (could not run), not caught" grep -q 'missing_command *INVALID (test-runs could not run: exit 127)' <<<"${OUT}"
check "and fails the run" test "${RC}" -ne 0

echo "=== No summary"
run_toy early "mutation_add exits_early test-early tool.sh '' 'RUNNER=true' \$'RUNNER=true\nEARLY=1'"
check "a suite that stops without its summary is INVALID" grep -q 'exits_early *INVALID (test-early printed no summary; exit 1)' <<<"${OUT}"
check "and fails the run" test "${RC}" -ne 0

echo "=== The wrong failing assertion"
run_toy wrong "mutation_add wrong_reason test-toy tool.sh 'an assertion that does not exist' '\$((\$1 * 2))' '\$((\$1 * 3))'"
check "is INVALID when no failing assertion names the expected one" \
	grep -q 'wrong_reason *INVALID (test-toy failed, but no failing assertion mentions "an assertion that does not exist"; first: FAIL: double 2 is 4)' <<<"${OUT}"
check "and fails the run" test "${RC}" -ne 0

echo "=== Harness failures"
run_toy nosuite "mutation_add no_suite test-missing tool.sh '' 'A toy tool.' 'x'"
check "a missing suite is a harness failure" grep -q 'HARNESS FAILURE: the snapshot has no tests/test-missing.sh' <<<"${OUT}"
check "  exit 2" test "${RC}" -eq 2
mkdir -p "${T}/not-a-repository"
ROOT="${T}/not-a-repository" run_toy nosnapshot "mutation_add breaks_double test-toy tool.sh '' 'x' 'y'"
check "a snapshot that cannot be made is a harness failure" grep -q 'HARNESS FAILURE: cannot snapshot the repository' <<<"${OUT}"
check "  exit 2" test "${RC}" -eq 2
cp -- "${REPO}/tool.sh" "${T}/tool.good"
sed -i 's/\* 2/* 5/' "${REPO}/tool.sh"
(cd "${REPO}" && git add -A)
run_toy baseline "mutation_add breaks_double test-toy tool.sh '' '\$((\$1 * 5))' '\$((\$1 * 3))'"
check "a suite that fails unmutated is a harness failure" grep -q 'HARNESS FAILURE: unmutated, test-toy does not pass' <<<"${OUT}"
check "  and no mutant is reported caught" bash -c '! grep -q CAUGHT <<<"$1"' _ "${OUT}"
check "  exit 2" test "${RC}" -eq 2
cp -- "${T}/tool.good" "${REPO}/tool.sh"
(cd "${REPO}" && git add -A)

echo
echo "Mutation engine tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
