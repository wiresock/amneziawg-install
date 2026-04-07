#!/usr/bin/env bash
# Unit tests for amneziawg-proxy install/uninstall helper functions.
#
# Tests helper functions by sourcing the real install/uninstall scripts in
# isolated subshells, so regressions in the actual implementations are caught.
# Covers: is_positive_integer, escape_sed_replacement, safe_rm_dir safety
# guards, and --purge-config / --purge-data path restrictions.
#
# Usage: bash tests/test-proxy-scripts.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_SCRIPT="${PROJECT_ROOT}/amneziawg-proxy/scripts/amneziawg-proxy-install.sh"
UNINSTALL_SCRIPT="${PROJECT_ROOT}/amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

function assert_rc() {
    local expected_rc="$1"
    shift
    local actual_rc=0
    ( "$@" ) 2>/dev/null || actual_rc=$?
    local msg="$*"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "${expected_rc}" == "${actual_rc}" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "  FAIL: ${msg} -> exit code (expected ${expected_rc}, got ${actual_rc})"
    fi
}

function assert_eq() {
    local expected="$1"
    local actual="$2"
    local msg="${3:-assertion}"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "${expected}" == "${actual}" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "  FAIL: ${msg} (expected '${expected}', got '${actual}')"
    fi
}

# ── Stub helpers used by test-local functions (purge checks, etc.) ────────────

die()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN: $*" >&2; }
info() { :; }

# ── Helpers sourced from the real scripts in isolated subshells ───────────────

run_install_helper() {
    local helper_name="$1"
    shift
    local -a helper_args=("$@")
    (
        set --  # Clear $@ so the sourced script's arg parser sees no args
        source "${INSTALL_SCRIPT}" 2>/dev/null
        # Suppress logging so test output stays clean
        info()  { :; }
        warn()  { :; }
        step()  { :; }
        error() { :; }
        "${helper_name}" "${helper_args[@]}"
    )
}

run_uninstall_helper() {
    local helper_name="$1"
    shift
    local -a helper_args=("$@")
    (
        set --  # Clear $@ so the sourced script's top-level arg parser sees no args
        source "${UNINSTALL_SCRIPT}" 2>/dev/null
        info() { :; }
        warn() { :; }
        "${helper_name}" "${helper_args[@]}"
    )
}

is_positive_integer() { run_install_helper  is_positive_integer  "$@"; }
escape_sed_replacement() { run_install_helper escape_sed_replacement "$@"; }
safe_rm_dir()           { run_uninstall_helper safe_rm_dir          "$@"; }

# ── is_positive_integer ───────────────────────────────────────────────────────

echo "=== is_positive_integer ==="
assert_rc 0 is_positive_integer "1"
assert_rc 0 is_positive_integer "42"
assert_rc 0 is_positive_integer "300"
assert_rc 1 is_positive_integer "0"
assert_rc 1 is_positive_integer "-1"
assert_rc 1 is_positive_integer ""
assert_rc 1 is_positive_integer "abc"
assert_rc 1 is_positive_integer "1.5"

# ── escape_sed_replacement ────────────────────────────────────────────────────

echo "=== escape_sed_replacement ==="
# No special chars → unchanged
assert_eq "/usr/local/bin" "$(escape_sed_replacement '/usr/local/bin')" "plain path"

# Ampersand → escaped
assert_eq "foo\\&bar" "$(escape_sed_replacement 'foo&bar')" "ampersand"

# Backslash → escaped
assert_eq "foo\\\\bar" "$(escape_sed_replacement 'foo\bar')" "backslash"

# Pipe (sed delimiter) → escaped
assert_eq "foo\\|bar" "$(escape_sed_replacement 'foo|bar')" "pipe"

# All three combined
RAW='a\b&c|d'
ESCAPED="$(escape_sed_replacement "${RAW}")"
assert_eq 'a\\b\&c\|d' "${ESCAPED}" "all special chars combined"

# Verify escaped value works safely inside sed s|…|…|
UNIT_BEFORE='ExecStart=/placeholder'
ESCAPED_LINE="$(escape_sed_replacement "ExecStart=/path/with|pipe")"
AFTER="$(printf '%s\n' "${UNIT_BEFORE}" | sed "s|ExecStart=.*|${ESCAPED_LINE}|")"
assert_eq 'ExecStart=/path/with|pipe' "${AFTER}" "sed replacement with pipe in path"

# ── safe_rm_dir guards ────────────────────────────────────────────────────────

echo "=== safe_rm_dir guards ==="

# Non-absolute path → die (exit 1)
assert_rc 1 safe_rm_dir "relative/path" "/var/"

# Path containing .. → die
assert_rc 1 safe_rm_dir "/etc/../var/lib/x" "/var/"

# Path containing . component → die
assert_rc 1 safe_rm_dir "/var/./lib/x" "/var/"

# Suspiciously short path → die
assert_rc 1 safe_rm_dir "/etc" "/etc"

# Trailing slash stripped → still short → die
assert_rc 1 safe_rm_dir "/etc/" "/etc/"

# Prefix mismatch → die
assert_rc 1 safe_rm_dir "/var/lib/amneziawg-proxy" "/etc/"

# Valid path under expected prefix (directory not present → no-op, exit 0)
assert_rc 0 safe_rm_dir "/var/lib/amneziawg-proxy" "/var/lib/"

# Symlink → die
TMPLINK_DIR="$(mktemp -d)"
TMPDIR_TARGET="$(mktemp -d)"
TMPLINK="${TMPLINK_DIR}/test-symlink"
ln -s "${TMPDIR_TARGET}" "${TMPLINK}"
assert_rc 1 safe_rm_dir "${TMPLINK}" "/tmp/"
rm -f "${TMPLINK}"
rm -rf "${TMPDIR_TARGET}"
rm -rf "${TMPLINK_DIR}"

# Valid: actually remove a temp directory
TMPD="$(mktemp -d)"
SUBDIR="${TMPD}/amneziawg-proxy"
mkdir -p "${SUBDIR}"
assert_rc 0 safe_rm_dir "${SUBDIR}" "${TMPD}/"
if [[ -d "${SUBDIR}" ]]; then
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
    echo "  FAIL: safe_rm_dir did not remove directory"
else
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
fi
rm -rf "${TMPD}"

# ── --purge-config case restrictions ─────────────────────────────────────────
#
# Exercise the real validate_purge_config_dir() function sourced from the
# uninstaller so tests catch regressions in the actual restriction logic.

echo "=== purge_config case restrictions ==="

purge_config_check() {
    run_uninstall_helper validate_purge_config_dir "$@"
}

assert_rc 0 purge_config_check "/etc/amneziawg-proxy"
assert_rc 0 purge_config_check "/etc/amneziawg-proxy/subdir"
assert_rc 0 purge_config_check "/etc/amneziawg-proxy/"
assert_rc 1 purge_config_check "/etc"
assert_rc 1 purge_config_check "/etc/other"
assert_rc 1 purge_config_check "/custom/path"
assert_rc 1 purge_config_check "/var/lib/something"

# ── --purge-data case restrictions ────────────────────────────────────────────

echo "=== purge_data case restrictions ==="

purge_data_check() {
    run_uninstall_helper validate_purge_data_dir "$@"
}

assert_rc 0 purge_data_check "/var/lib/amneziawg-proxy"
assert_rc 0 purge_data_check "/var/lib/amneziawg-proxy/subdir"
assert_rc 0 purge_data_check "/var/lib/amneziawg-proxy/"
assert_rc 1 purge_data_check "/var"
assert_rc 1 purge_data_check "/var/lib/other"
assert_rc 1 purge_data_check "/etc/ssl"
assert_rc 1 purge_data_check "/custom/data"

# ── --help exits 0 ────────────────────────────────────────────────────────────

echo "=== --help exits 0 ==="
assert_rc 0 bash "${INSTALL_SCRIPT}"   --help
assert_rc 0 bash "${UNINSTALL_SCRIPT}" --help

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "Results: ${TESTS_PASSED}/${TESTS_RUN} passed, ${TESTS_FAILED} failed"
echo "=========================================="

if (( TESTS_FAILED > 0 )); then
    exit 1
fi
