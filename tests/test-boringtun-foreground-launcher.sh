#!/usr/bin/env bash

# Unit tests for tests/helpers/boringtun-foreground-launcher.sh, the CI-only
# launcher that the artifact workflow hands to BoringTun's interop harnesses. A
# shell script stands in for boringtun-cli: it records how it was started, then
# runs until it is killed, or exits at once when asked to. No network namespace,
# TUN device or root is needed.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LAUNCHER="${SCRIPT_DIR}/helpers/boringtun-foreground-launcher.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-launcher-tests.XXXXXX")"
TEST_ROOT="$(CDPATH='' cd -- "${TEST_ROOT}" && pwd -P)"
REAL="${TEST_ROOT}/real/boringtun-cli"
RECORD="${TEST_ROOT}/record"
mkdir -p "${TEST_ROOT}/real" "${TEST_ROOT}/path"

cleanup() {
	local PID
	[[ -f "${TEST_ROOT}/pids" ]] && while read -r PID; do
		kill "${PID}" 2>/dev/null
	done <"${TEST_ROOT}/pids"
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
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected:\n%s\n    actual:\n%s\n' \
			"$(sed 's/^/      /' <<<"$1")" "$(sed 's/^/      /' <<<"$2")" >&2
	fi
}

# assert_true <name> <command...>
assert_true() {
	local NAME="$1"
	shift
	if "$@"; then ok "${NAME}"; else not_ok "${NAME}"; fi
}

assert_contains() {
	if [[ "$2" == *"$1"* ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected to contain: %s\n    actual: %s\n' "$1" "$2" >&2
	fi
}

# The stand-in for boringtun-cli. It writes its record atomically, so a record
# that exists is complete, then either exits with FAKE_EXIT or runs until it is
# killed.
write_fake() { # <path>
	cat >"$1" <<'FAKE'
#!/usr/bin/env bash
{
	printf 'exe=%s\n' "$0"
	for a in "$@"; do printf 'arg=%s\n' "$a"; done
	printf 'real_env=%s\n' "${BORINGTUN_REAL_CLI-<unset>}"
	printf 'log_level=%s\n' "${WG_LOG_LEVEL-<unset>}"
	printf 'pid=%s\n' "$$"
	printf 'sid=%s\n' "$(awk '{ print $6 }' "/proc/$$/stat")"
} >"${FAKE_RECORD}.tmp"
mv "${FAKE_RECORD}.tmp" "${FAKE_RECORD}"
echo "fake stdout"
echo "fake stderr" >&2
[ -z "${FAKE_EXIT:-}" ] || exit "${FAKE_EXIT}"
exec sleep 60
FAKE
	chmod +x "$1"
}
write_fake "${REAL}"

# A boringtun-cli first in PATH, which the launcher must never start.
cat >"${TEST_ROOT}/path/boringtun-cli" <<FAKE
#!/usr/bin/env bash
touch "${TEST_ROOT}/impostor-ran"
exec sleep 60
FAKE
chmod +x "${TEST_ROOT}/path/boringtun-cli"

# Run the launcher with <real> as BORINGTUN_REAL_CLI ("-" leaves it unset) and
# the given arguments. Its output goes to files, not a pipe: the child inherits
# them, and a pipe would stay open until the child exits. Sets RUN_RC, RUN_OUT,
# RUN_ERR and RUN_SECONDS.
run_launcher() { # <real> [args...]
	local REAL_ARG="$1"
	shift
	rm -f "${RECORD}" "${TEST_ROOT}/impostor-ran"
	local -a ENV_ARGS=(env -u BORINGTUN_REAL_CLI)
	[[ "${REAL_ARG}" == - ]] || ENV_ARGS+=("BORINGTUN_REAL_CLI=${REAL_ARG}")
	local START=${SECONDS}
	"${ENV_ARGS[@]}" PATH="${TEST_ROOT}/path:${PATH}" FAKE_RECORD="${RECORD}" \
		WG_LOG_LEVEL=debug ${RUN_EXTRA_ENV[@]+"${RUN_EXTRA_ENV[@]}"} \
		timeout 20 "${LAUNCHER}" "$@" >"${TEST_ROOT}/out" 2>"${TEST_ROOT}/err"
	RUN_RC=$?
	RUN_SECONDS=$((SECONDS - START))
	RUN_OUT="$(cat "${TEST_ROOT}/out")"
	RUN_ERR="$(cat "${TEST_ROOT}/err")"
}
RUN_EXTRA_ENV=()

# Wait up to 5 s for the fake's record and remember its PID for cleanup.
read_record() {
	local I
	for ((I = 0; I < 50; I++)); do
		[[ -f "${RECORD}" ]] && break
		sleep 0.1
	done
	RECORDED="$(cat "${RECORD}" 2>/dev/null)"
	CHILD_PID="$(sed -n 's/^pid=//p' <<<"${RECORDED}")"
	[[ -z "${CHILD_PID}" ]] || echo "${CHILD_PID}" >>"${TEST_ROOT}/pids"
}

args_of() {
	sed -n 's/^arg=//p' <<<"${RECORDED}"
}

stop_child() {
	[[ -n "${CHILD_PID:-}" ]] && kill "${CHILD_PID}" 2>/dev/null
	CHILD_PID=""
}

echo "Launching the real binary in the foreground"

run_launcher "${REAL}" --disable-drop-privileges --imitate-protocol dns --imitate-domain "a b.example" awg0
read_record
assert_eq 0 "${RUN_RC}" "a started child is a successful launch"
assert_eq "exe=${REAL}" "$(sed -n 1p <<<"${RECORDED}")" "the binary named by BORINGTUN_REAL_CLI runs, by its absolute path"
assert_eq "--foreground
--disable-drop-privileges
--imitate-protocol
dns
--imitate-domain
a b.example
awg0" "$(args_of)" "--foreground comes first, then every harness argument in order, the interface last"
assert_eq "real_env=<unset>" "$(grep '^real_env=' <<<"${RECORDED}")" "BORINGTUN_REAL_CLI is not passed on to the child"
assert_eq "log_level=debug" "$(grep '^log_level=' <<<"${RECORDED}")" "the rest of the caller's environment reaches the child"
assert_true "a boringtun-cli in PATH is not started" test ! -e "${TEST_ROOT}/impostor-ran"
if [[ "${RUN_SECONDS}" -le 3 ]]; then
	ok "the launcher returns while the child keeps running"
else
	not_ok "the launcher returns while the child keeps running (took ${RUN_SECONDS}s)"
fi
if [[ -n "${CHILD_PID}" ]] && kill -0 "${CHILD_PID}" 2>/dev/null; then
	ok "the child is still running after the launcher exits"
else
	not_ok "the child is still running after the launcher exits"
fi
assert_eq "sid=$(awk '{ print $6 }' "/proc/$$/stat")" "$(grep '^sid=' <<<"${RECORDED}")" \
	"the child stays in the caller's session: nothing daemonizes it"
sleep 0.2
assert_eq "fake stdout" "${RUN_OUT}" "without WG_LOG_FILE the child writes to the launcher's stdout"
assert_eq "fake stderr" "${RUN_ERR}" "and to its stderr"
stop_child

RUN_EXTRA_ENV=("WG_LOG_FILE=${TEST_ROOT}/bt.log")
run_launcher "${REAL}" --disable-drop-privileges awg1
read_record
RUN_EXTRA_ENV=()
sleep 0.2
assert_eq 0 "${RUN_RC}" "a launch with WG_LOG_FILE succeeds"
assert_eq "fake stdout
fake stderr" "$(cat "${TEST_ROOT}/bt.log" 2>/dev/null)" "with WG_LOG_FILE the child's stdout and stderr go to that file"
assert_eq "" "${RUN_OUT}${RUN_ERR}" "and nothing to the launcher's own output"
stop_child

echo "An existing foreground flag"

for FLAG in -f --foreground; do
	run_launcher "${REAL}" "${FLAG}" --disable-drop-privileges awg0
	read_record
	assert_eq "${FLAG}
--disable-drop-privileges
awg0" "$(args_of)" "${FLAG} already given: the arguments are passed on unchanged"
	stop_child
done

run_launcher "${REAL}" --disable-drop-privileges -- -f
read_record
assert_eq "--foreground
--disable-drop-privileges
--
-f" "$(args_of)" "a -f after -- is positional, so --foreground is still added"
stop_child

echo "Refusing to start anything else"

run_launcher - --disable-drop-privileges awg0
assert_eq 1 "${RUN_RC}" "BORINGTUN_REAL_CLI unset fails"
assert_contains "BORINGTUN_REAL_CLI is not set" "${RUN_ERR}" "and says so"
assert_true "and starts nothing" test ! -e "${RECORD}" -a ! -e "${TEST_ROOT}/impostor-ran"

run_launcher "" awg0
assert_eq 1 "${RUN_RC}" "an empty BORINGTUN_REAL_CLI fails"

run_launcher boringtun-cli awg0
assert_eq 1 "${RUN_RC}" "a bare name fails even though PATH has one"
assert_contains "not an absolute path" "${RUN_ERR}" "and is reported as not absolute"
assert_true "and PATH is not searched" test ! -e "${TEST_ROOT}/impostor-ran"

run_launcher "real/boringtun-cli" awg0
assert_eq 1 "${RUN_RC}" "a relative path fails"

run_launcher "${TEST_ROOT}/missing/boringtun-cli" awg0
assert_eq 1 "${RUN_RC}" "a missing file fails"
assert_contains "not an executable file" "${RUN_ERR}" "and is reported as not executable"

cp "${REAL}" "${TEST_ROOT}/real/not-executable"
chmod -x "${TEST_ROOT}/real/not-executable"
run_launcher "${TEST_ROOT}/real/not-executable" awg0
assert_eq 1 "${RUN_RC}" "a file without the execute bit fails"
assert_true "and is not run" test ! -e "${RECORD}"

run_launcher "${TEST_ROOT}/real" awg0
assert_eq 1 "${RUN_RC}" "a directory fails"

run_launcher "${LAUNCHER}" awg0
assert_eq 1 "${RUN_RC}" "the launcher itself fails"
assert_contains "names this launcher" "${RUN_ERR}" "and is reported as a loop"

ln -s "${LAUNCHER}" "${TEST_ROOT}/real/launcher-link"
run_launcher "${TEST_ROOT}/real/launcher-link" awg0
assert_eq 1 "${RUN_RC}" "a symlink to the launcher fails"
assert_contains "names this launcher" "${RUN_ERR}" "and is reported as a loop"

cp "${LAUNCHER}" "${TEST_ROOT}/real/launcher-copy"
run_launcher "${TEST_ROOT}/real/launcher-copy" awg0
assert_eq 1 "${RUN_RC}" "a copy of the launcher fails instead of starting itself again"
assert_contains "exited at once" "${RUN_ERR}" "because the copy finds BORINGTUN_REAL_CLI unset and exits"
if [[ "${RUN_SECONDS}" -le 3 ]]; then ok "and does so at once"; else not_ok "and does so at once (took ${RUN_SECONDS}s)"; fi

echo "A child that exits at once"

RUN_EXTRA_ENV=(FAKE_EXIT=3)
run_launcher "${REAL}" --disable-drop-privileges awg0
RUN_EXTRA_ENV=()
assert_eq 1 "${RUN_RC}" "a child that exits at once fails the launch"
assert_contains "exited at once with status 3" "${RUN_ERR}" "and its status is reported"

RUN_EXTRA_ENV=(FAKE_EXIT=0)
run_launcher "${REAL}" --disable-drop-privileges awg0
RUN_EXTRA_ENV=()
assert_eq 1 "${RUN_RC}" "a child that exits at once with status 0 still fails the launch"

printf '\177ELF\0\0\0\0garbage' >"${TEST_ROOT}/real/garbage"
chmod +x "${TEST_ROOT}/real/garbage"
run_launcher "${TEST_ROOT}/real/garbage" awg0
assert_eq 1 "${RUN_RC}" "an executable file that cannot be run fails the launch"
assert_contains "exited at once with status 126" "${RUN_ERR}" "with the shell's cannot-execute status"

RUN_EXTRA_ENV=("WG_LOG_FILE=${TEST_ROOT}/no-such-dir/bt.log")
run_launcher "${REAL}" --disable-drop-privileges awg0
RUN_EXTRA_ENV=()
assert_eq 1 "${RUN_RC}" "a WG_LOG_FILE that cannot be created fails the launch"
assert_true "and the binary is not started" test ! -e "${RECORD}"

echo
echo "Passed: ${PASS}, failed: ${FAIL}"
[[ "${FAIL}" -eq 0 ]]
