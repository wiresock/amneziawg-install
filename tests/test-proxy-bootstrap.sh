#!/usr/bin/env bash
# Launcher-level tests for the standalone amneziawg-proxy bootstrap path.

set -uo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: Run this test as root so amneziawg-proxy.sh reaches its dispatcher." >&2
    exit 1
fi

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
PROXY_LAUNCHER="${PROJECT_ROOT}/amneziawg-proxy.sh"

TEST_ROOT="$(mktemp -d)"
STANDALONE_DIR="${TEST_ROOT}/standalone"
MOCK_BIN_DIR="${TEST_ROOT}/mock-bin"
TARGET_LOG="${TEST_ROOT}/bootstrap-target.log"
INNER_LOG="${TEST_ROOT}/inner-script.log"
NOEXEC_ROOT="${TEST_ROOT}/noexec"
TMP_ROOT="${TEST_ROOT}/tmp-root"
BUILD_ROOT="${TEST_ROOT}/build-root"
RELATIVE_CWD="${TEST_ROOT}/relative-cwd"
NOEXEC_MOUNTED=0

cleanup() {
    if [[ "${NOEXEC_MOUNTED}" -eq 1 ]]; then
        umount "${NOEXEC_ROOT}" 2>/dev/null || true
    fi
    rm -rf -- "${TEST_ROOT}"
}

trap cleanup EXIT

mkdir -p "${STANDALONE_DIR}" "${MOCK_BIN_DIR}" "${NOEXEC_ROOT}" \
    "${TMP_ROOT}" "${BUILD_ROOT}" "${RELATIVE_CWD}/relative tmp"
cp "${PROXY_LAUNCHER}" "${STANDALONE_DIR}/amneziawg-proxy.sh"

REAL_CHMOD="$(command -v chmod)"
SYSTEM_PATH="${PATH}"

if ! mount -t tmpfs -o size=4m,noexec,nosuid,nodev tmpfs "${NOEXEC_ROOT}"; then
    echo "ERROR: Could not create the isolated noexec filesystem required by this test." >&2
    exit 1
fi
NOEXEC_MOUNTED=1
printf '#!/bin/sh\nexit 0\n' > "${NOEXEC_ROOT}/probe"
"${REAL_CHMOD}" 700 "${NOEXEC_ROOT}/probe"
if "${NOEXEC_ROOT}/probe" >/dev/null 2>&1; then
    echo "ERROR: The isolated test filesystem unexpectedly permits direct execution." >&2
    exit 1
fi
rm -f -- "${NOEXEC_ROOT}/probe"

cat > "${MOCK_BIN_DIR}/git" <<'MOCK_GIT'
#!/usr/bin/env bash
if [[ "${1:-}" != "clone" ]]; then
    exit 0
fi

target="${!#}"
printf '%s\n' "${target}" > "${PROXY_BOOTSTRAP_TARGET_LOG}"
mkdir -p "${target}/amneziawg-proxy/scripts"
for script in \
    amneziawg-proxy-install.sh \
    amneziawg-proxy-upgrade.sh \
    amneziawg-proxy-uninstall.sh; do
    cat > "${target}/amneziawg-proxy/scripts/${script}" <<'INNER_SCRIPT'
#!/usr/bin/env bash
printf '%s|%s|%s\n' "$(basename -- "$0")" "${TMPDIR:-}" "$*" > "${PROXY_INNER_LOG}"
INNER_SCRIPT
done
MOCK_GIT

"${REAL_CHMOD}" +x "${MOCK_BIN_DIR}/git"

TESTS_RUN=0
TESTS_FAILED=0

fail() {
    echo "  FAIL: $*"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

run_launcher() {
    local working_dir="$1"
    shift
    local -a environment=()
    while [[ $# -gt 0 && "$1" != "--" ]]; do
        environment+=("$1")
        shift
    done
    [[ "${1:-}" == "--" ]] || return 2
    shift
    (
        cd "${working_dir}" || exit
        env \
            PATH="${MOCK_BIN_DIR}:${SYSTEM_PATH}" \
            PROXY_BOOTSTRAP_TARGET_LOG="${TARGET_LOG}" \
            PROXY_INNER_LOG="${INNER_LOG}" \
            "${environment[@]}" \
            bash "${STANDALONE_DIR}/amneziawg-proxy.sh" "$@"
    ) >/dev/null 2>&1
}

assert_bootstrap() {
    local name="$1"
    local expected_root="$2"
    local expected_script="$3"
    shift 3
    local rc=0 target="" inner=""

    TESTS_RUN=$((TESTS_RUN + 1))
    : > "${TARGET_LOG}"
    : > "${INNER_LOG}"
    run_launcher "$@" || rc=$?
    target="$(<"${TARGET_LOG}")"
    inner="$(<"${INNER_LOG}")"

    if [[ "${rc}" -ne 0 ]]; then
        fail "${name}: launcher exited ${rc}"
        return
    fi
    if [[ "${target}" != "${expected_root%/}"/amneziawg-install.* ]]; then
        fail "${name}: expected bootstrap below '${expected_root}', got '${target}'"
        return
    fi
    if [[ "${inner}" != "${expected_script}|${target}/.tmp|"* ]]; then
        fail "${name}: inner script/TMPDIR mismatch: '${inner}'"
        return
    fi
    if [[ -e "${target}" ]]; then
        fail "${name}: bootstrap directory was not cleaned up: '${target}'"
        return
    fi
    echo "  OK: ${name}"
}

echo "=== standalone proxy bootstrap ==="

assert_bootstrap \
    "TMPDIR is preferred and propagated" \
    "${TMP_ROOT}" \
    "amneziawg-proxy-install.sh" \
    "${TEST_ROOT}" \
    TMPDIR="${TMP_ROOT}" \
    -- \
    install

assert_bootstrap \
    "AMNEZIAWG_BUILD_ROOT takes precedence" \
    "${BUILD_ROOT}" \
    "amneziawg-proxy-install.sh" \
    "${TEST_ROOT}" \
    AMNEZIAWG_BUILD_ROOT="${BUILD_ROOT}" \
    TMPDIR="${TMP_ROOT}" \
    -- \
    install

RELATIVE_TMP_ROOT="$(CDPATH='' cd -- "${RELATIVE_CWD}/relative tmp" && pwd -P)"
assert_bootstrap \
    "relative TMPDIR is canonicalized" \
    "${RELATIVE_TMP_ROOT}" \
    "amneziawg-proxy-install.sh" \
    "${RELATIVE_CWD}" \
    TMPDIR="relative tmp" \
    -- \
    install

FALLBACK_ROOT=""
for candidate in /var/tmp /tmp; do
    probe_dir="$(mktemp -d "${candidate%/}/awg-proxy-bootstrap-test.XXXXXX" 2>/dev/null || true)"
    if [[ -n "${probe_dir}" ]]; then
        printf '#!/bin/sh\nexit 0\n' > "${probe_dir}/probe"
        "${REAL_CHMOD}" 700 "${probe_dir}/probe"
        if "${probe_dir}/probe" >/dev/null 2>&1; then
            FALLBACK_ROOT="${candidate}"
            rm -rf -- "${probe_dir}"
            break
        fi
        rm -rf -- "${probe_dir}"
    fi
done

if [[ -z "${FALLBACK_ROOT}" ]]; then
    fail "no executable /var/tmp or /tmp fallback is available"
else
    assert_bootstrap \
        "install rejects a noexec TMPDIR" \
        "${FALLBACK_ROOT}" \
        "amneziawg-proxy-install.sh" \
        "${TEST_ROOT}" \
        TMPDIR="${NOEXEC_ROOT}" \
        -- \
        install

    assert_bootstrap \
        "upgrade rejects a noexec TMPDIR" \
        "${FALLBACK_ROOT}" \
        "amneziawg-proxy-upgrade.sh" \
        "${TEST_ROOT}" \
        TMPDIR="${NOEXEC_ROOT}" \
        -- \
        upgrade
fi

assert_bootstrap \
    "uninstall accepts a writable noexec TMPDIR" \
    "${NOEXEC_ROOT}" \
    "amneziawg-proxy-uninstall.sh" \
    "${TEST_ROOT}" \
    TMPDIR="${NOEXEC_ROOT}" \
    -- \
    uninstall

printf '\n%d tests, %d failures\n' "${TESTS_RUN}" "${TESTS_FAILED}"
[[ "${TESTS_FAILED}" -eq 0 ]]
