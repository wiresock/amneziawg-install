#!/usr/bin/env bash
# Unit tests for amneziawg-proxy install/uninstall helper functions.
#
# Tests helper functions by sourcing the real install/uninstall scripts in
# isolated subshells, so regressions in the actual implementations are caught.
# Covers: is_positive_integer, escape_sed_replacement, _is_valid_ip_literal,
# _format_host_for_socketaddr, validate_config, extract_endpoint_port,
# read_proxy_config_ports, safe_rm_dir safety guards, --purge-config /
# --purge-data path restrictions, --config-file trailing-slash rejection, and
# reconfigure_awg_listen_port edit/backup/restart decision logic.
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
    ( "$@" ) >/dev/null 2>&1 || actual_rc=$?
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
_is_valid_ip_literal()       { run_install_helper _is_valid_ip_literal       "$@"; }
_format_host_for_socketaddr() { run_install_helper _format_host_for_socketaddr "$@"; }

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
TMPPREFIX_ROOT="$(mktemp -d)"
TMPPREFIX="${TMPPREFIX_ROOT}/var/lib/"
TMPPATH="${TMPPREFIX}amneziawg-proxy"
mkdir -p "${TMPPREFIX}"
assert_rc 0 safe_rm_dir "${TMPPATH}" "${TMPPREFIX}"
rm -rf "${TMPPREFIX_ROOT}"

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

# ── extract_endpoint_port ─────────────────────────────────────────────────────

echo "=== extract_endpoint_port ==="

extract_endpoint_port() {
    run_uninstall_helper extract_endpoint_port "$@"
}

# IPv4 host:port
result="$(extract_endpoint_port "0.0.0.0:51820")"
assert_eq "51820" "${result}" "extract_endpoint_port 0.0.0.0:51820"

# hostname:port
result="$(extract_endpoint_port "localhost:443")"
assert_eq "443" "${result}" "extract_endpoint_port localhost:443"

# Bracketed IPv6 [::1]:port
result="$(extract_endpoint_port "[::1]:51820")"
assert_eq "51820" "${result}" "extract_endpoint_port [::1]:51820"

# Bracketed IPv6 full address
result="$(extract_endpoint_port "[2001:db8::1]:8080")"
assert_eq "8080" "${result}" "extract_endpoint_port [2001:db8::1]:8080"

# Quoted endpoint (as read from TOML)
result="$(extract_endpoint_port '"127.0.0.1:51821"')"
assert_eq "51821" "${result}" "extract_endpoint_port quoted 127.0.0.1:51821"

# Quoted bracketed IPv6
result="$(extract_endpoint_port '"[::1]:9999"')"
assert_eq "9999" "${result}" "extract_endpoint_port quoted [::1]:9999"

# Whitespace around endpoint
result="$(extract_endpoint_port "  10.0.0.1:12345  ")"
assert_eq "12345" "${result}" "extract_endpoint_port whitespace 10.0.0.1:12345"

# Invalid: empty string
assert_rc 1 extract_endpoint_port ""

# Invalid: no port
assert_rc 1 extract_endpoint_port "hostname-only"

# Invalid: bare IPv6 without brackets (ambiguous — contains multiple colons)
# The regex ^[^:]+:([0-9]+)$ won't match because the host part contains colons,
# so extract_endpoint_port should return non-zero.
assert_rc 1 extract_endpoint_port "::1:51820"

# ── read_proxy_config_ports (inline comment stripping) ───────────────────────

echo "=== read_proxy_config_ports ==="

# Helper: call read_proxy_config_ports in a subshell and echo the parsed ports
run_read_ports() {
    local cfg="$1"
    (
        set --
        source "${UNINSTALL_SCRIPT}" 2>/dev/null
        info() { :; }
        warn() { :; }
        PROXY_LISTEN_PORT=""
        PROXY_BACKEND_PORT=""
        read_proxy_config_ports "${cfg}" || true
        printf '%s|%s\n' "${PROXY_LISTEN_PORT}" "${PROXY_BACKEND_PORT}"
    )
}

# Plain values without comments
tmp_cfg="$(mktemp)"
cat > "${tmp_cfg}" <<'TOML'
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
TOML
result="$(run_read_ports "${tmp_cfg}")"
assert_eq "51820|51821" "${result}" "read_proxy_config_ports plain values"
rm -f "${tmp_cfg}"

# Values with inline comments
tmp_cfg="$(mktemp)"
cat > "${tmp_cfg}" <<'TOML'
listen = "0.0.0.0:51820" # public listener
backend = "127.0.0.1:51821"  # loopback backend
TOML
result="$(run_read_ports "${tmp_cfg}")"
assert_eq "51820|51821" "${result}" "read_proxy_config_ports inline comments"
rm -f "${tmp_cfg}"

# IPv6 bracketed values with inline comment
tmp_cfg="$(mktemp)"
cat > "${tmp_cfg}" <<'TOML'
listen = "[::]:51820"  # bind all IPv6
backend = "[::1]:51821" # loopback v6
TOML
result="$(run_read_ports "${tmp_cfg}")"
assert_eq "51820|51821" "${result}" "read_proxy_config_ports IPv6 with comments"
rm -f "${tmp_cfg}"

# ── _is_valid_ip_literal ──────────────────────────────────────────────────────

echo "=== _is_valid_ip_literal ==="
# Valid IPv4
assert_rc 0 _is_valid_ip_literal "0.0.0.0"
assert_rc 0 _is_valid_ip_literal "127.0.0.1"
assert_rc 0 _is_valid_ip_literal "192.168.1.100"
# Valid IPv6
assert_rc 0 _is_valid_ip_literal "::1"
assert_rc 0 _is_valid_ip_literal "::"
assert_rc 0 _is_valid_ip_literal "2001:db8::1"
# Bracketed IPv6
assert_rc 0 _is_valid_ip_literal "[::1]"
assert_rc 0 _is_valid_ip_literal "[2001:db8::1]"
# Hostnames → rejected
assert_rc 1 _is_valid_ip_literal "localhost"
assert_rc 1 _is_valid_ip_literal "example.com"
assert_rc 1 _is_valid_ip_literal "my-server"
# Empty → rejected
assert_rc 1 _is_valid_ip_literal ""
# Invalid IPv4 octets → rejected
assert_rc 1 _is_valid_ip_literal "999.999.999.999"
assert_rc 1 _is_valid_ip_literal "256.0.0.1"
# Malformed IPv6 → rejected
assert_rc 1 _is_valid_ip_literal ":::"
assert_rc 1 _is_valid_ip_literal "2001:db8::1::2"
assert_rc 1 _is_valid_ip_literal "::gggg"
assert_rc 1 _is_valid_ip_literal "12345::1"
assert_rc 1 _is_valid_ip_literal "2001:db8:85a3::8a2e:370:7334:extra:fields"
# Mismatched brackets (only opening or only closing)
assert_rc 1 _is_valid_ip_literal "[::1"
assert_rc 1 _is_valid_ip_literal "::1]"
assert_rc 1 _is_valid_ip_literal "[127.0.0.1"
assert_rc 1 _is_valid_ip_literal "127.0.0.1]"
# Bracketed IPv4 → rejected (brackets are IPv6-only in SocketAddr; [x.x.x.x]:port is invalid)
assert_rc 1 _is_valid_ip_literal "[127.0.0.1]"
assert_rc 1 _is_valid_ip_literal "[0.0.0.0]"
assert_rc 1 _is_valid_ip_literal "[192.168.1.1]"

# ── _format_host_for_socketaddr ───────────────────────────────────────────────

echo "=== _format_host_for_socketaddr ==="
# IPv4 unchanged
assert_eq "0.0.0.0" "$(_format_host_for_socketaddr "0.0.0.0")" "format IPv4"
assert_eq "127.0.0.1" "$(_format_host_for_socketaddr "127.0.0.1")" "format IPv4 loopback"
# Bare IPv6 → bracketed
assert_eq "[::1]" "$(_format_host_for_socketaddr "::1")" "format bare IPv6"
assert_eq "[2001:db8::1]" "$(_format_host_for_socketaddr "2001:db8::1")" "format bare IPv6 full"
assert_eq "[::]" "$(_format_host_for_socketaddr "::")" "format bare IPv6 wildcard"
# Already bracketed → unchanged
assert_eq "[::1]" "$(_format_host_for_socketaddr "[::1]")" "format already bracketed"

# ── validate_config (cross-field) ─────────────────────────────────────────────

echo "=== validate_config ==="
run_validate_config() {
    local protocol="$1" quic_hs="$2" dns_fwd="$3"
    local dns_upstream="${4:-1.1.1.1:53}"
    (
        set --
        source "${INSTALL_SCRIPT}" 2>/dev/null
        info()  { :; }
        warn()  { :; }
        step()  { :; }
        error() { :; }
        PROTOCOL="${protocol}"
        QUIC_HANDSHAKE_ENABLED="${quic_hs}"
        DNS_FORWARD_ENABLED="${dns_fwd}"
        DNS_UPSTREAM="${dns_upstream}"
        validate_config
    )
}
# Valid combinations
assert_rc 0 run_validate_config "quic" "true" "false"
assert_rc 0 run_validate_config "auto" "true" "true"
assert_rc 0 run_validate_config "dns"  "false" "true"
assert_rc 0 run_validate_config "sip"  "false" "false"
# Invalid: quic_handshake with dns protocol
assert_rc 1 run_validate_config "dns"  "true" "false"
assert_rc 1 run_validate_config "sip"  "true" "false"
# Invalid: dns_forward with quic protocol
assert_rc 1 run_validate_config "quic" "false" "true"
assert_rc 1 run_validate_config "sip"  "false" "true"
# Invalid: unsupported protocol name
assert_rc 1 run_validate_config "invalid" "false" "false"
assert_rc 1 run_validate_config "udp"     "false" "false"
assert_rc 1 run_validate_config ""        "false" "false"

# ── _validate_dns_upstream ────────────────────────────────────────────────────

echo "=== _validate_dns_upstream ==="
_validate_dns_upstream() { run_install_helper _validate_dns_upstream "$@"; }
# Valid: IPv4 host:port
assert_rc 0 _validate_dns_upstream "1.1.1.1:53"
assert_rc 0 _validate_dns_upstream "8.8.8.8:53"
assert_rc 0 _validate_dns_upstream "192.168.1.1:5353"
# Valid: bracketed IPv6
assert_rc 0 _validate_dns_upstream "[::1]:53"
assert_rc 0 _validate_dns_upstream "[2001:db8::1]:53"
# Invalid: no port
assert_rc 1 _validate_dns_upstream "1.1.1.1"
# Invalid: port out of range
assert_rc 1 _validate_dns_upstream "1.1.1.1:0"
assert_rc 1 _validate_dns_upstream "1.1.1.1:99999"
# Invalid: hostname (not IP literal)
assert_rc 1 _validate_dns_upstream "localhost:53"
assert_rc 1 _validate_dns_upstream "dns.google:53"
# Invalid: empty
assert_rc 1 _validate_dns_upstream ""
# Invalid: bare IPv6 without brackets
assert_rc 1 _validate_dns_upstream "::1:53"
# Invalid DNS_UPSTREAM in validate_config (dns_forward=true)
assert_rc 1 run_validate_config "dns" "false" "true" "localhost:53"
assert_rc 1 run_validate_config "dns" "false" "true" "not-a-host"
assert_rc 0 run_validate_config "dns" "false" "true" "[::1]:53"

# ── Helper: call non_interactive_validate in a sourced subshell ───────────────
#
# run_niv_with VAR_NAME VAR_VALUE [VAR2 VAL2 ...]
#   Sources the installer, sets sane defaults, then overrides specific
#   variables by name using printf -v (avoids eval/quoting issues with
#   special characters in values). Calls non_interactive_validate().
#   Returns its exit code; stderr is captured by the caller.
run_niv_with() {
    # Build a bash -c script that accepts var-name/value pairs as positional
    # arguments beyond the script name, using printf -v for safe assignment.
    local _script
    _script='
        set -uo pipefail
        source "${INSTALL_SCRIPT}"

        # Sane defaults that satisfy all other checks.
        NON_INTERACTIVE="true"
        LISTEN_PORT="51820"
        BACKEND_PORT="51821"
        LISTEN_HOST="127.0.0.1"
        BACKEND_HOST="127.0.0.1"
        PROTOCOL="sip"
        SESSION_TTL="60"
        RATE_LIMIT="10"
        QUIC_HANDSHAKE_ENABLED="false"
        QUIC_DOMAIN=""
        DNS_FORWARD_ENABLED="false"
        DNS_UPSTREAM=""
        INSTALL_DIR="/usr/local/bin"
        CONFIG_FILE="/etc/amneziawg-proxy/proxy.toml"
        DATA_DIR="/var/lib/amneziawg-proxy"
        AWG_DIR="/etc/amnezia/amneziawg"

        # Apply caller-supplied var=value pairs (positional args after "_").
        # In bash -c "script" name arg1 arg2 ..., $0=name, $1=arg1, $2=arg2.
        # So $1/$2 are already the first VAR_NAME/VAR_VALUE pair.
        while [[ $# -ge 2 ]]; do
            printf -v "$1" "%s" "$2"
            shift 2
        done

        non_interactive_validate
        validate_config
    '
    INSTALL_SCRIPT="${INSTALL_SCRIPT}" bash -c "${_script}" _ "$@" 2>&1
}

# assert_niv_rejects VAR_NAME VAR_VALUE description
#   Asserts that run_niv_with with the given override rejects with exit code 1
#   AND that stderr contains "must not contain".
assert_niv_rejects() {
    local var_name="$1"
    local var_value="$2"
    local description="$3"
    shift 3
    # Any additional VAR VALUE pairs are prepended to the positional list.
    local _output _rc _has_msg=0
    _output=$(run_niv_with "${var_name}" "${var_value}" "$@") && _rc=0 || _rc=$?
    echo "${_output}" | grep -qF 'must not contain' && _has_msg=1

    assert_eq "1" "${_rc}"      "${description}: exit code 1"
    assert_eq "1" "${_has_msg}" "${description}: 'must not contain' in stderr"
}

# assert_niv_rc EXPECTED_RC VAR_NAME VAR_VALUE description [extra pairs...]
#   Asserts that run_niv_with exits with the expected return code.
assert_niv_rc() {
    local expected_rc="$1"
    local var_name="$2"
    local var_value="$3"
    local description="$4"
    shift 4
    local _rc
    run_niv_with "${var_name}" "${var_value}" "$@" >/dev/null && _rc=0 || _rc=$?
    assert_eq "${expected_rc}" "${_rc}" "${description}: exit code ${expected_rc}"
}

# assert_niv_accepts VAR_NAME VAR_VALUE description
#   Asserts that run_niv_with accepts the given override (rc 0).
assert_niv_accepts() {
    local var_name="$1"
    local var_value="$2"
    local description="$3"
    shift 3
    local _rc
    run_niv_with "${var_name}" "${var_value}" "$@" >/dev/null && _rc=0 || _rc=$?
    assert_eq "0" "${_rc}" "${description}: exit code 0"
}

# ── AWG_DIR TOML-unsafe rejection ─────────────────────────────────────────────

echo "=== AWG_DIR TOML-unsafe rejection ==="
assert_niv_rejects "AWG_DIR" '/etc/amnezia/"awg'      "AWG_DIR with quotes"
assert_niv_rejects "AWG_DIR" '/etc/amnezia/awg\dir'   "AWG_DIR with backslash"
assert_niv_rejects "AWG_DIR" '/etc/amnezia/%awg'      "AWG_DIR with percent"

# ── Path option quote/backslash rejection ─────────────────────────────────────

echo "=== Path option quote/backslash/percent rejection ==="
assert_niv_rejects "INSTALL_DIR" '/usr/local/"bin'          "--install-dir with quote"
assert_niv_rejects "INSTALL_DIR" '/usr/local/bi\n'          "--install-dir with backslash"
assert_niv_rejects "INSTALL_DIR" '/usr/local/%hbin'         "--install-dir with percent"
assert_niv_rejects "CONFIG_FILE" '/etc/proxy/"proxy.toml'   "--config-file with quote"
assert_niv_rejects "DATA_DIR"    '/var/lib/proxy\data'      "--data-dir with backslash"
assert_niv_rejects "DATA_DIR"    '/var/lib/%proxy'          "--data-dir with percent"

# ── CONFIG_FILE trailing-slash rejection ──────────────────────────────────────

echo "=== CONFIG_FILE trailing-slash rejection ==="
assert_niv_rc 1 "CONFIG_FILE" '/etc/amneziawg-proxy/'   "--config-file trailing slash rejected"
assert_niv_rc 1 "CONFIG_FILE" '/etc/amneziawg-proxy//'  "--config-file double trailing slash rejected"

# ── Conditional TOML emission (quic_certificate_domain / dns_upstream) ────────

echo "=== Conditional TOML emission ==="
# --quic-domain with TOML-unsafe chars should NOT cause failure when
# QUIC handshake is disabled (field is not validated in that case).
assert_niv_accepts "QUIC_DOMAIN" 'bad"domain' \
    "--quic-domain TOML-unsafe accepted when QUIC handshake disabled"
# --quic-domain with TOML-unsafe chars SHOULD be rejected when QUIC handshake enabled.
assert_niv_rejects "QUIC_DOMAIN" 'bad"domain' \
    "--quic-domain TOML-unsafe rejected when QUIC handshake enabled" \
    "QUIC_HANDSHAKE_ENABLED" "true" "PROTOCOL" "quic"

# --dns-upstream with invalid value should NOT cause failure when DNS forwarding is disabled.
assert_niv_accepts "DNS_UPSTREAM" 'not-valid' \
    "--dns-upstream invalid value accepted when DNS forwarding disabled"
# --dns-upstream with invalid value SHOULD be rejected when DNS forwarding enabled.
assert_niv_rc 1 "DNS_UPSTREAM" 'not-valid' \
    "--dns-upstream invalid value rejected when DNS forwarding enabled" \
    "DNS_FORWARD_ENABLED" "true" "PROTOCOL" "dns"

# ── --help exits 0 ────────────────────────────────────────────────────────────

echo "=== --help exits 0 ==="
assert_rc 0 bash "${INSTALL_SCRIPT}"   --help
assert_rc 0 bash "${UNINSTALL_SCRIPT}" --help

# ── reconfigure_awg_listen_port ───────────────────────────────────────────────
#
# Run reconfigure_awg_listen_port() in a subshell with a temp AWG conf file.
# Prints: exit_code|ListenPort_value|ListenAddr_value|backup_file_count

echo "=== reconfigure_awg_listen_port ==="

_run_reconfigure() {
    local conf_content="$1"
    local backend_port="${2:-51821}"
    local backend_host="${3:-127.0.0.1}"
    local tmpdir conf_file
    tmpdir="$(mktemp -d)"
    conf_file="${tmpdir}/awg0.conf"
    printf '%s\n' "${conf_content}" > "${conf_file}"

    local rc=0
    (
        set --
        # shellcheck disable=SC1090
        source "${INSTALL_SCRIPT}" 2>/dev/null
        info()      { :; }
        warn()      { :; }
        step()      { :; }
        error()     { :; }
        systemctl() { return 1; }  # mock: service not active → skip restart
        AWG_CONF_FILE="${conf_file}"
        BACKEND_PORT="${backend_port}"
        BACKEND_HOST="${backend_host}"
        AWG_NIC="awg0"
        NON_INTERACTIVE="true"
        reconfigure_awg_listen_port
    ) 2>/dev/null
    rc=$?

    local result_port result_addr backup_count
    result_port="$(grep -i '^[[:space:]]*ListenPort[[:space:]]*=' "${conf_file}" 2>/dev/null \
        | head -1 | sed -E 's/^[^=]*=[[:space:]]*//' | sed 's/[;#].*//' | tr -d '[:space:]')" || true
    result_addr="$(grep -i '^[[:space:]]*ListenAddr[[:space:]]*=' "${conf_file}" 2>/dev/null \
        | head -1 | sed -E 's/^[^=]*=[[:space:]]*//' | sed 's/[;#].*//' | tr -d '[:space:]')" || true
    backup_count="$(find "${tmpdir}" -name 'awg0.conf.bak.*' 2>/dev/null | wc -l | tr -d ' ')"

    printf '%s\n' "${rc}|${result_port}|${result_addr}|${backup_count}"
    rm -rf "${tmpdir}"
}

# port already matches, no ListenAddr directive → no edit, no backup (rc 0)
_result="$(_run_reconfigure $'[Interface]\nListenPort = 51821' 51821 127.0.0.1)"
_rc="${_result%%|*}"; _port="$(echo "${_result}" | cut -d'|' -f2)"
_addr="$(echo "${_result}" | cut -d'|' -f3)"; _baks="${_result##*|}"
assert_eq "0"     "${_rc}"   "reconfigure: port ok, no ListenAddr → rc 0"
assert_eq "51821" "${_port}" "reconfigure: port ok, no ListenAddr → port unchanged"
assert_eq ""      "${_addr}" "reconfigure: port ok, no ListenAddr → no addr added"
assert_eq "0"     "${_baks}" "reconfigure: port ok, no ListenAddr → no backup"

# port needs change, no ListenAddr directive → port updated, backup, no addr added
_result="$(_run_reconfigure $'[Interface]\nListenPort = 51820' 51821 127.0.0.1)"
_rc="${_result%%|*}"; _port="$(echo "${_result}" | cut -d'|' -f2)"
_addr="$(echo "${_result}" | cut -d'|' -f3)"; _baks="${_result##*|}"
assert_eq "0"     "${_rc}"   "reconfigure: port change, no ListenAddr → rc 0"
assert_eq "51821" "${_port}" "reconfigure: port change, no ListenAddr → port updated"
assert_eq ""      "${_addr}" "reconfigure: port change, no ListenAddr → no addr added"
assert_eq "1"     "${_baks}" "reconfigure: port change, no ListenAddr → backup created"

# port needs change, ListenAddr present → both updated, backup
_result="$(_run_reconfigure $'[Interface]\nListenPort = 51820\nListenAddr = 0.0.0.0' 51821 127.0.0.1)"
_rc="${_result%%|*}"; _port="$(echo "${_result}" | cut -d'|' -f2)"
_addr="$(echo "${_result}" | cut -d'|' -f3)"; _baks="${_result##*|}"
assert_eq "0"         "${_rc}"   "reconfigure: port+addr change → rc 0"
assert_eq "51821"     "${_port}" "reconfigure: port+addr change → port updated"
assert_eq "127.0.0.1" "${_addr}" "reconfigure: port+addr change → addr updated"
assert_eq "1"         "${_baks}" "reconfigure: port+addr change → backup created"

# port already matches, ListenAddr present but wrong → addr-only update, backup
_result="$(_run_reconfigure $'[Interface]\nListenPort = 51821\nListenAddr = 0.0.0.0' 51821 127.0.0.1)"
_rc="${_result%%|*}"; _port="$(echo "${_result}" | cut -d'|' -f2)"
_addr="$(echo "${_result}" | cut -d'|' -f3)"; _baks="${_result##*|}"
assert_eq "0"         "${_rc}"   "reconfigure: addr-only change → rc 0"
assert_eq "51821"     "${_port}" "reconfigure: addr-only change → port unchanged"
assert_eq "127.0.0.1" "${_addr}" "reconfigure: addr-only change → addr updated"
assert_eq "1"         "${_baks}" "reconfigure: addr-only change → backup created"

# port and addr already correct → no edit, no backup (early return)
_result="$(_run_reconfigure $'[Interface]\nListenPort = 51821\nListenAddr = 127.0.0.1' 51821 127.0.0.1)"
_rc="${_result%%|*}"; _port="$(echo "${_result}" | cut -d'|' -f2)"
_addr="$(echo "${_result}" | cut -d'|' -f3)"; _baks="${_result##*|}"
assert_eq "0"         "${_rc}"   "reconfigure: already correct → rc 0"
assert_eq "51821"     "${_port}" "reconfigure: already correct → port unchanged"
assert_eq "127.0.0.1" "${_addr}" "reconfigure: already correct → addr unchanged"
assert_eq "0"         "${_baks}" "reconfigure: already correct → no backup"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "Results: ${TESTS_PASSED}/${TESTS_RUN} passed, ${TESTS_FAILED} failed"
echo "=========================================="

if (( TESTS_FAILED > 0 )); then
    exit 1
fi
