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

# ── AWG_DIR TOML-unsafe rejection ─────────────────────────────────────────────

echo "=== AWG_DIR TOML-unsafe rejection ==="
# AWG_DIR with quotes should be rejected
assert_rc 1 bash "${INSTALL_SCRIPT}" --non-interactive --listen-port 51820 \
    --awg-dir '/etc/amnezia/"awg'
# AWG_DIR with backslash should be rejected
assert_rc 1 bash "${INSTALL_SCRIPT}" --non-interactive --listen-port 51820 \
    --awg-dir '/etc/amnezia/awg\dir'

# ── Path option quote/backslash rejection ─────────────────────────────────────

echo "=== Path option quote/backslash rejection ==="
# --install-dir with quote should be rejected
assert_rc 1 bash "${INSTALL_SCRIPT}" --non-interactive --listen-port 51820 \
    --install-dir '/usr/local/"bin'
# --install-dir with backslash should be rejected
assert_rc 1 bash "${INSTALL_SCRIPT}" --non-interactive --listen-port 51820 \
    --install-dir '/usr/local/bi\n'
# --config-file with quote should be rejected
assert_rc 1 bash "${INSTALL_SCRIPT}" --non-interactive --listen-port 51820 \
    --config-file '/etc/proxy/"proxy.toml'
# --data-dir with backslash should be rejected
assert_rc 1 bash "${INSTALL_SCRIPT}" --non-interactive --listen-port 51820 \
    --data-dir '/var/lib/proxy\data'

# ── Conditional TOML emission (quic_certificate_domain / dns_upstream) ────────

echo "=== Conditional TOML emission ==="
# --quic-domain with TOML-unsafe chars should NOT cause failure when
# QUIC handshake is disabled (field not emitted into proxy.toml).
# The installer will fail at preflight (not root) before file I/O, which is
# expected — we just verify it does NOT die with a TOML-unsafe-chars error.
_quic_domain_disabled_output=$(bash "${INSTALL_SCRIPT}" --non-interactive \
    --listen-port 51820 --quic-domain 'bad"domain' 2>&1 || true)
_quic_domain_has_toml_err=0
echo "${_quic_domain_disabled_output}" | grep -qiE 'quic.*domain.*quotes|quic.*domain.*toml' \
    && _quic_domain_has_toml_err=1
assert_eq "0" "${_quic_domain_has_toml_err}" \
    "--quic-domain TOML-unsafe chars accepted when QUIC handshake disabled"

# Same for --dns-upstream with invalid value when DNS forwarding is disabled
_dns_upstream_disabled_output=$(bash "${INSTALL_SCRIPT}" --non-interactive \
    --listen-port 51820 --dns-upstream 'not-valid' 2>&1 || true)
_dns_upstream_has_err=0
echo "${_dns_upstream_disabled_output}" | grep -qiE 'dns.*upstream.*host|dns.*upstream.*ip' \
    && _dns_upstream_has_err=1
assert_eq "0" "${_dns_upstream_has_err}" \
    "--dns-upstream invalid value accepted when DNS forwarding disabled"

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
