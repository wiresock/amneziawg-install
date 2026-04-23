#!/usr/bin/env bash
# amneziawg-proxy-uninstall.sh
# Uninstaller for the amneziawg-proxy UDP obfuscation proxy.
#
# Usage:
#   sudo ./amneziawg-proxy-uninstall.sh                         # interactive (safe defaults)
#   sudo ./amneziawg-proxy-uninstall.sh --force                  # non-interactive, safe defaults
#   sudo ./amneziawg-proxy-uninstall.sh --purge-config --force
#   sudo ./amneziawg-proxy-uninstall.sh --help
#
# Default behavior (safe):
#   - stops and disables the systemd service
#   - removes the installed binary
#   - removes the systemd unit file
#   - reloads the systemd daemon
#   - PRESERVES: proxy.toml config file, data directory
#
# Purge flags (must be explicit):
#   --purge-config   remove /etc/amneziawg-proxy/ (proxy.toml and directory)
#   --purge-data     remove the data/working directory
#   --restore-awg    restore AWG listen port from the proxy config backup
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────

readonly SERVICE_NAME="amneziawg-proxy"
readonly SYSTEMD_UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly DEFAULT_CONFIG_DIR="/etc/amneziawg-proxy"
readonly DEFAULT_CONFIG_FILE="/etc/amneziawg-proxy/proxy.toml"
readonly DEFAULT_DATA_DIR="/var/lib/amneziawg-proxy"
readonly DEFAULT_AWG_DIR="/etc/amnezia/amneziawg"
readonly BINARY_NAME="amneziawg-proxy"

# ── Defaults ───────────────────────────────────────────────────────────────────

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
CONFIG_DIR="${DEFAULT_CONFIG_DIR}"
CONFIG_FILE="${DEFAULT_CONFIG_FILE}"
DATA_DIR="${DEFAULT_DATA_DIR}"
AWG_DIR="${DEFAULT_AWG_DIR}"

# Track which path flags were explicitly provided by the caller.
# When a flag is absent, main() auto-derives the path from the installed
# systemd unit (ExecStart / WorkingDirectory) so that custom installs are
# correctly handled without the caller having to repeat all the path flags.
_FLAG_INSTALL_DIR=false
_FLAG_CONFIG_FILE=false
_FLAG_DATA_DIR=false

PURGE_CONFIG="false"
PURGE_DATA="false"
RESTORE_AWG="false"
FORCE="false"

# ── Output helpers ─────────────────────────────────────────────────────────────

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }

info()  { printf '[INFO]  %s\n' "$*"; }
warn()  { yellow "[WARN]  $*" >&2; }
die()   { red    "[ERROR] $*" >&2; exit 1; }

# Source shared helpers (validate_params_file, etc.)
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=amneziawg-proxy-common.sh
. "${SCRIPT_DIR}/amneziawg-proxy-common.sh"

# ── Usage ──────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Uninstall the amneziawg-proxy UDP obfuscation proxy.

Safe defaults:
  Removes:   systemd service, installed binary
  Preserves: proxy.toml config, data directory

Options:
  --install-dir DIR    Binary install directory  (default: ${DEFAULT_INSTALL_DIR})
  --config-file FILE   Proxy config file path    (default: ${DEFAULT_CONFIG_FILE})
  --data-dir DIR       Data directory            (default: ${DEFAULT_DATA_DIR})
  --awg-dir DIR        AmneziaWG config dir      (default: ${DEFAULT_AWG_DIR})
  --purge-config       Also remove config directory (only ${DEFAULT_CONFIG_DIR} or subdirs)
  --purge-data         Also remove data/working directory (only ${DEFAULT_DATA_DIR} or subdirs)
  --restore-awg        Restore AWG listen port from a backup created by the installer
  --force              Skip confirmation prompts
  --non-interactive    Alias for --force; suitable for CI/automation
  --help               Show this help

Purge example:
  sudo $0 --purge-config --purge-data --force

Restore AWG listen port and full purge:
  sudo $0 --restore-awg --purge-config --purge-data --force

EOF
}

# ── Argument parsing ───────────────────────────────────────────────────────────

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-dir)
                [[ $# -ge 2 ]] || die "Missing value for option: $1  (use --help for usage)"
                INSTALL_DIR="$2"; _FLAG_INSTALL_DIR=true; shift 2 ;;
            --config-file)
                [[ $# -ge 2 ]] || die "Missing value for option: $1  (use --help for usage)"
                [[ "$2" != */ ]] || die "--config-file must be a file path, not a directory-style path ending with '/': $2"
                CONFIG_FILE="$2"; CONFIG_DIR="$(dirname -- "${CONFIG_FILE}")"; _FLAG_CONFIG_FILE=true; shift 2 ;;
            --data-dir)
                [[ $# -ge 2 ]] || die "Missing value for option: $1  (use --help for usage)"
                DATA_DIR="$2"; _FLAG_DATA_DIR=true; shift 2 ;;
            --awg-dir)
                [[ $# -ge 2 ]] || die "Missing value for option: $1  (use --help for usage)"
                AWG_DIR="$2"; shift 2 ;;
            --purge-config)     PURGE_CONFIG="true"; shift ;;
            --purge-data)       PURGE_DATA="true"; shift ;;
            --restore-awg)      RESTORE_AWG="true"; shift ;;
            --force)            FORCE="true"; shift ;;
            --non-interactive)  FORCE="true"; shift ;;
            --help|-h)          usage; exit 0 ;;
            *) die "Unknown option: $1  (use --help for usage)" ;;
        esac
    done
fi

# ── Confirmation helper ────────────────────────────────────────────────────────

confirm() {
    local msg="$1"
    local default="${2:-false}"
    if [[ "${FORCE}" == "true" ]]; then
        return 0
    fi
    local prompt
    if [[ "${default}" == "true" ]]; then
        prompt="${msg} [Y/n] "
    else
        prompt="${msg} [y/N] "
    fi
    local reply
    if ! read -r -p "${prompt}" reply; then
        warn "No input available (EOF); treating as 'no'."
        return 1
    fi
    reply="${reply:-${default}}"
    case "${reply}" in
        [Yy]*|true) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Safe rm helpers ────────────────────────────────────────────────────────────

safe_rm_file() {
    local f="$1"
    if [[ -z "${f}" ]]; then
        warn "safe_rm_file: empty path, skipping"
        return 0
    fi
    if [[ -f "${f}" ]] || [[ -L "${f}" ]]; then
        rm -f -- "${f}"
        info "Removed: ${f}"
    else
        info "Already absent: ${f}"
    fi
}

# _normalize_path: collapse consecutive slashes and strip trailing slashes so
# that equivalent paths (e.g. /etc//amneziawg-proxy/ and /etc/amneziawg-proxy)
# compare equal.  Root (/) is returned as-is.
_normalize_path() {
    local _p="${1:-}"
    [[ -z "${_p}" ]] && { printf '%s' ""; return; }
    _p="$(printf '%s' "${_p}" | sed 's|//*|/|g')"
    if [[ "${_p}" != "/" ]]; then
        _p="${_p%/}"
        [[ -z "${_p}" ]] && _p="/"
    fi
    printf '%s' "${_p}"
}

# _canon_path: canonicalize a path, resolving symlinked parent directories.
# Attempts in order:
#   1. realpath -m  (GNU coreutils; path need not exist)
#   2. realpath     (without -m; path must exist)
#   3. python3 os.path.realpath  (path need not exist)
#   4. pure-bash fallback via cd -P / pwd -P on the parent directory, then
#      append the basename verbatim
#   5. die — canonicalization is required for safe deletion; if no method is
#      available the operation is aborted to prevent bypassing prefix checks.
_canon_path() {
    local p
    if [[ "${1}" == "/" ]]; then
        p="/"
    else
        p="${1%/}"
        [[ -n "${p}" ]] || p="/"
    fi
    local result
    if result="$(realpath -m -- "${p}" 2>/dev/null)" && [[ -n "${result}" ]]; then
        printf '%s' "${result}"; return
    fi
    if [[ -e "${p}" ]] && result="$(realpath -- "${p}" 2>/dev/null)" && [[ -n "${result}" ]]; then
        printf '%s' "${result}"; return
    fi
    if command -v python3 &>/dev/null; then
        # ${p} is passed as a positional argument (sys.argv[1]), not embedded in code.
        result="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${p}" 2>/dev/null)"
        if [[ -n "${result}" ]]; then printf '%s' "${result}"; return; fi
    fi
    # Pure-bash fallback: resolve symlinks in the parent directory (cd -P), then
    # append the basename.  By the time this path is reached, callers have
    # already verified that ${p} is absolute, so dirname always yields an
    # absolute path.  cd -P resolves any symlink components in the parent;
    # the basename is appended verbatim so the result may differ from a full
    # canonical resolution of the target itself (which is fine for a prefix
    # boundary check on a not-yet-existing path).
    local parent_dir basename_part parent_real
    parent_dir="$(dirname "${p}")"
    basename_part="$(basename "${p}")"
    if parent_real="$(cd -P -- "${parent_dir}" 2>/dev/null && pwd -P 2>/dev/null)"; then
        result="${parent_real}/${basename_part}"
        if [[ -n "${result}" ]]; then printf '%s' "${result}"; return; fi
    fi
    die "path canonicalization unavailable (neither realpath nor python3 found); cannot safely validate '${p}' for deletion"
}

# Return 0 (true) when a path contains '.' or '..' path components.
_path_has_dot_components() {
    local p="$1"
    [[ "${p}" == */./* || "${p}" == */../* || "${p}" == */. || "${p}" == */.. ]]
}

safe_rm_dir() {
    local d="$1"
    local prefix="$2"
    if [[ -z "${d}" ]]; then
        warn "safe_rm_dir: empty path, skipping"
        return 0
    fi
    # Validate prefix argument before using it as a safety boundary
    if [[ -z "${prefix}" ]]; then
        die "safe_rm_dir: empty prefix — refusing to operate without a safety boundary"
    fi
    if [[ "${prefix}" != /* ]]; then
        die "safe_rm_dir: prefix must be absolute, got '${prefix}'"
    fi
    if [[ "/${prefix}/" == *"/../"* || "/${prefix}/" == *"/./"* ]]; then
        die "safe_rm_dir: prefix must not contain '.' or '..' components: ${prefix}"
    fi
    # Normalize: strip any trailing slash so prefix and length checks are consistent
    d="${d%/}"
    if [[ "${d}" != /* ]]; then
        die "Refusing to remove non-absolute path: ${d}"
    fi
    if [[ "/${d}/" == *"/../"* || "/${d}/" == *"/./"* ]]; then
        die "Refusing to remove path containing '..' or '.' components: ${d}"
    fi
    # Refuse symlinks: rm -rf on a symlink with trailing slash follows into target
    if [[ -L "${d}" ]]; then
        die "Refusing to remove symlink: ${d}"
    fi
    if [[ "${#d}" -lt 5 ]]; then
        die "Refusing to remove suspiciously short path: ${d}"
    fi
    # Canonicalize both paths (resolves symlinked parents) then compare on
    # path-component boundaries to prevent prefix-name collisions
    # (e.g. /var/lib/amneziawg-proxy-evil passing a /var/lib/amneziawg-proxy prefix).
    local d_canon prefix_canon
    d_canon="$(_canon_path "${d}")"
    prefix_canon="$(_canon_path "${prefix%/}")"
    if [[ "${d_canon}" != "${prefix_canon}" && "${d_canon}" != "${prefix_canon}/"* ]]; then
        die "Refusing to remove '${d}' (resolved: '${d_canon}'): not under expected prefix '${prefix_canon}'"
    fi
    if [[ -d "${d_canon}" ]]; then
        rm -rf -- "${d_canon}"
        info "Removed directory: ${d_canon}"
    else
        info "Already absent: ${d_canon}"
    fi
}

# ── systemd helpers ────────────────────────────────────────────────────────────

HAVE_SYSTEMCTL="false"
if command -v systemctl &>/dev/null; then
    HAVE_SYSTEMCTL="true"
fi

systemctl_if_active() {
    local verb="$1"
    local unit="$2"
    if [[ "${HAVE_SYSTEMCTL}" != "true" ]]; then
        info "systemctl not available, skipping ${verb}: ${unit}"
        return 0
    fi
    if systemctl is-active --quiet -- "${unit}" 2>/dev/null; then
        systemctl "${verb}" -- "${unit}" && info "Service ${verb}ped: ${unit}" || \
            warn "Could not ${verb} ${unit} (already stopped?)"
    else
        info "Service not active, skipping ${verb}: ${unit}"
    fi
}

systemctl_if_enabled() {
    local verb="$1"
    local unit="$2"
    if [[ "${HAVE_SYSTEMCTL}" != "true" ]]; then
        info "systemctl not available, skipping ${verb}: ${unit}"
        return 0
    fi
    if systemctl is-enabled --quiet -- "${unit}" 2>/dev/null; then
        systemctl "${verb}" -- "${unit}" && info "Service ${verb}d: ${unit}" || \
            warn "Could not ${verb} ${unit}"
    else
        info "Service not enabled, skipping ${verb}: ${unit}"
    fi
}

# ── AWG restore ────────────────────────────────────────────────────────────────

# Extract the numeric port from an endpoint string.
# Supports:
#   - host:port          (IPv4 or hostname)
#   - [ipv6-address]:port
# Returns the numeric port on stdout, or nothing if it cannot be parsed.
extract_endpoint_port() {
    local endpoint="$1"
    endpoint="$(printf '%s' "${endpoint}" | tr -d "[:space:]\"'")"
    if [[ "${endpoint}" =~ ^\[[^\]]+\]:([0-9]+)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    if [[ "${endpoint}" =~ ^[^:]+:([0-9]+)$ ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

# Read listen and backend ports from the proxy config file.
read_proxy_config_ports() {
    local cfg="$1"
    if [[ ! -f "${cfg}" ]]; then
        return 1
    fi

    local listen_value backend_value
    # Extract listen port from: listen = "host:port" or listen = "[ipv6]:port"
    listen_value="$(grep -E '^[[:space:]]*listen[[:space:]]*=' "${cfg}" \
        | head -1 | sed -e 's/^[^=]*=[[:space:]]*//' -e 's/[[:space:]]*#.*$//' -e 's/[[:space:]]*$//')" || true
    PROXY_LISTEN_PORT="$(extract_endpoint_port "${listen_value}")" || true

    # Extract backend port from: backend = "host:port" or backend = "[ipv6]:port"
    backend_value="$(grep -E '^[[:space:]]*backend[[:space:]]*=' "${cfg}" \
        | head -1 | sed -e 's/^[^=]*=[[:space:]]*//' -e 's/[[:space:]]*#.*$//' -e 's/[[:space:]]*$//')" || true
    PROXY_BACKEND_PORT="$(extract_endpoint_port "${backend_value}")" || true

    [[ -n "${PROXY_LISTEN_PORT}" ]]
}

restore_awg_listen_port() {
    info "Attempting to restore AWG listen port..."

    local PROXY_LISTEN_PORT=""
    local PROXY_BACKEND_PORT=""

    if ! read_proxy_config_ports "${CONFIG_FILE}"; then
        warn "Could not read proxy config at ${CONFIG_FILE}; skipping AWG restore."
        return 0
    fi

    if [[ -z "${PROXY_LISTEN_PORT}" ]]; then
        warn "Could not determine original AWG listen port from proxy config; skipping restore."
        return 0
    fi

    # Validate that the parsed port is a plain integer in 1–65535 range.
    if ! [[ "${PROXY_LISTEN_PORT}" =~ ^[0-9]+$ ]] || \
       (( 10#${PROXY_LISTEN_PORT} < 1 || 10#${PROXY_LISTEN_PORT} > 65535 )); then
        warn "Parsed listen port '${PROXY_LISTEN_PORT}' is not a valid port number; skipping restore."
        return 0
    fi

    info "Proxy was listening on port ${PROXY_LISTEN_PORT}."
    if [[ -n "${PROXY_BACKEND_PORT}" ]]; then
        info "AWG backend was on port ${PROXY_BACKEND_PORT}."
    fi

    # Find the AWG config file
    local awg_conf=""
    local awg_nic=""

    # Try params file first
    local params_file="${AWG_DIR}/params"
    if validate_params_file "${params_file}"; then
        awg_nic="$(bash -c '. "$1" 2>/dev/null && printf "%s" "${SERVER_AWG_NIC:-}"' _ "${params_file}")"
    fi

    if [[ -n "${awg_nic}" ]]; then
        awg_conf="${AWG_DIR}/${awg_nic}.conf"
    else
        awg_conf="$(find "${AWG_DIR}" -maxdepth 1 -name '*.conf' 2>/dev/null | sort | head -1 || true)"
        awg_nic="$(basename "${awg_conf}" .conf 2>/dev/null || true)"
    fi

    if [[ -z "${awg_conf}" ]] || [[ ! -f "${awg_conf}" ]]; then
        warn "AWG config not found; skipping listen port restore."
        return 0
    fi

    # Look for a backup file created by the installer
    local latest_backup
    latest_backup="$(find "${AWG_DIR}" -maxdepth 1 \
        -name "$(basename "${awg_conf}").bak.*" 2>/dev/null | sort | tail -1 || true)"

    if [[ -n "${latest_backup}" ]]; then
        info "Found AWG config backup: ${latest_backup}"
        if confirm "Restore AWG config from backup ${latest_backup}?" "true"; then
            cp -f -- "${latest_backup}" "${awg_conf}"
            info "Restored AWG config from: ${latest_backup}"

            # Restart the interface
            if [[ "${HAVE_SYSTEMCTL}" == "true" ]] && \
               systemctl is-active --quiet -- "awg-quick@${awg_nic}" 2>/dev/null; then
                info "Restarting AWG interface ${awg_nic}..."
                if ! systemctl restart -- "awg-quick@${awg_nic}"; then
                    warn "Failed to restart awg-quick@${awg_nic}."
                    warn "Run manually: sudo systemctl restart -- awg-quick@${awg_nic}"
                else
                    info "AWG interface ${awg_nic} restarted with original config."
                fi
            elif [[ "${HAVE_SYSTEMCTL}" != "true" ]]; then
                warn "systemctl not available; restart awg-quick@${awg_nic} manually."
            else
                warn "AWG interface awg-quick@${awg_nic} is not active."
                warn "Start it with: sudo systemctl start -- awg-quick@${awg_nic}"
            fi
            return 0
        else
            info "Skipping AWG config restore (user declined)."
            return 0
        fi
    fi

    # No backup: update the ListenPort back to the original
    info "No backup found; updating ListenPort to ${PROXY_LISTEN_PORT} in ${awg_conf}..."
    if grep -qi '^[[:space:]]*ListenPort[[:space:]]*=' "${awg_conf}"; then
        sed -i "s|^[[:space:]]*ListenPort[[:space:]]*=.*|ListenPort = ${PROXY_LISTEN_PORT}|i" \
            "${awg_conf}"
        info "Updated AWG ListenPort → ${PROXY_LISTEN_PORT}"
    else
        warn "ListenPort not found in ${awg_conf}; manual update may be required."
    fi

    # No backup means we cannot safely restore the original ListenAddr.
    # Warn if the current config still appears loopback-bound so operators
    # know additional manual changes may be required.
    local listen_addr_raw
    listen_addr_raw="$(sed -nE \
        's/^[[:space:]]*ListenAddr[[:space:]]*=[[:space:]]*"?([^"#;[:space:]]+)"?.*$/\1/ip' \
        "${awg_conf}" | tail -1)"
    if [[ -n "${listen_addr_raw}" ]] && \
       [[ "${listen_addr_raw,,}" =~ ^(127\.[0-9]+\.[0-9]+\.[0-9]+|::1|localhost)$ ]]; then
        warn "No AWG config backup was found, and ${awg_conf} still sets ListenAddr = ${listen_addr_raw}."
        warn "This appears to bind AWG to loopback only; public connectivity may remain unavailable."
        warn "Review/remove/reset ListenAddr manually if AWG should listen on a non-loopback address."
    fi

    # Restart the interface
    if [[ "${HAVE_SYSTEMCTL}" == "true" ]] && \
       systemctl is-active --quiet -- "awg-quick@${awg_nic}" 2>/dev/null; then
        info "Restarting AWG interface ${awg_nic}..."
        if ! systemctl restart -- "awg-quick@${awg_nic}"; then
            warn "Failed to restart awg-quick@${awg_nic}."
            warn "Run manually: sudo systemctl restart -- awg-quick@${awg_nic}"
        else
            info "AWG interface ${awg_nic} restarted."
        fi
    elif [[ "${HAVE_SYSTEMCTL}" != "true" ]]; then
        warn "systemctl not available; restart awg-quick@${awg_nic} manually."
    else
        warn "AWG interface awg-quick@${awg_nic} is not active."
        warn "Start it with: sudo systemctl start -- awg-quick@${awg_nic}"
    fi
}

# ── Purge restriction validators ──────────────────────────────────────────────

# validate_purge_config_dir: die if CONFIG_DIR is outside DEFAULT_CONFIG_DIR.
# Extracted so tests can exercise the real restriction logic.
validate_purge_config_dir() {
    local config_dir="${1%/}"
    case "${config_dir}" in
        "${DEFAULT_CONFIG_DIR}")
            ;;
        "${DEFAULT_CONFIG_DIR}"/*)
            ;;
        /etc)
            die "--purge-config refuses to purge '/etc'; only '${DEFAULT_CONFIG_DIR}' or its subdirectories may be removed"
            ;;
        /etc/*)
            die "--purge-config only supports '${DEFAULT_CONFIG_DIR}' or its subdirectories; refusing to purge '${config_dir}'"
            ;;
        *)
            die "--purge-config only supports config directories under '${DEFAULT_CONFIG_DIR}'; refusing to purge '${config_dir}'"
            ;;
    esac
}

# validate_purge_data_dir: die if DATA_DIR is outside DEFAULT_DATA_DIR.
# Extracted so tests can exercise the real restriction logic.
validate_purge_data_dir() {
    local data_dir="${1%/}"
    case "${data_dir}" in
        "${DEFAULT_DATA_DIR}")
            ;;
        "${DEFAULT_DATA_DIR}"/*)
            ;;
        /var)
            die "--purge-data refuses to purge '/var'; only '${DEFAULT_DATA_DIR}' or its subdirectories may be removed"
            ;;
        /var/*)
            die "--purge-data only supports '${DEFAULT_DATA_DIR}' or its subdirectories; refusing to purge '${data_dir}'"
            ;;
        *)
            die "--purge-data only supports data directories under '${DEFAULT_DATA_DIR}'; refusing to purge '${data_dir}'"
            ;;
    esac
}

# ── Summary / plan ─────────────────────────────────────────────────────────────

print_plan() {
    printf '\n'
    printf '=== amneziawg-proxy uninstall plan ===\n'
    printf '\n'
    printf 'Will REMOVE:\n'
    printf '  Binary:       %s\n'  "${INSTALL_DIR}/${BINARY_NAME}"
    printf '  Systemd unit: %s\n'  "${SYSTEMD_UNIT_DEST}"
    printf '  Service:      stop + disable %s\n' "${SERVICE_NAME}"
    printf '\n'
    printf 'Will PRESERVE (unless purge flags are given):\n'
    if [[ "${PURGE_CONFIG}" != "true" ]]; then
        printf '  Config:   %s  [preserved]\n' "${CONFIG_DIR}"
    else
        local _cfg_stripped="${CONFIG_DIR%/}"
        case "${_cfg_stripped}" in
            "${DEFAULT_CONFIG_DIR}"|"${DEFAULT_CONFIG_DIR}"/*)
                printf '  Config:   %s  [WILL BE REMOVED --purge-config]\n' "${CONFIG_DIR}"
                ;;
            *)
                printf '  Config:   %s  [PURGE WILL FAIL — outside %s]\n' "${CONFIG_DIR}" "${DEFAULT_CONFIG_DIR}"
                ;;
        esac
    fi
    if [[ "${PURGE_DATA}" != "true" ]]; then
        printf '  Data dir: %s  [preserved]\n' "${DATA_DIR}"
    else
        local _data_stripped="${DATA_DIR%/}"
        case "${_data_stripped}" in
            "${DEFAULT_DATA_DIR}"|"${DEFAULT_DATA_DIR}"/*)
                printf '  Data dir: %s  [WILL BE REMOVED --purge-data]\n' "${DATA_DIR}"
                ;;
            *)
                printf '  Data dir: %s  [PURGE WILL FAIL — outside %s]\n' "${DATA_DIR}" "${DEFAULT_DATA_DIR}"
                ;;
        esac
    fi
    if [[ "${RESTORE_AWG}" == "true" ]]; then
        printf '\n'
        printf 'AWG restore:  will attempt to restore AWG listen port [--restore-awg]\n'
    fi
    printf '\n'
}

# ── Main uninstall ─────────────────────────────────────────────────────────────

main() {
    # If the systemd unit is installed and a path flag was not explicitly
    # provided, auto-derive the missing paths from the unit's ExecStart and
    # WorkingDirectory directives.  This ensures that a custom-path install
    # (--install-dir / --config-file / --data-dir) is correctly uninstalled
    # without requiring the caller to repeat every path flag.
    if [[ -f "${SYSTEMD_UNIT_DEST}" ]]; then
        local _unit_exec_line _unit_exec _unit_cfg _unit_workdir _unit_rest
        _unit_exec_line="$(grep -m1 '^ExecStart=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null)" || true
        _unit_exec=""
        _unit_cfg=""
        if [[ -n "${_unit_exec_line}" ]]; then
            read -r _unit_exec _unit_cfg _unit_rest <<< "${_unit_exec_line#ExecStart=}" || true
            # Strip surrounding double or single quotes that may appear in
            # manually-edited unit files (e.g. ExecStart="/path/bin" "/path/cfg")
            _unit_exec="${_unit_exec#\"}"; _unit_exec="${_unit_exec%\"}"
            _unit_exec="${_unit_exec#\'}"; _unit_exec="${_unit_exec%\'}"
            _unit_cfg="${_unit_cfg#\"}";   _unit_cfg="${_unit_cfg%\"}"
            _unit_cfg="${_unit_cfg#\'}";   _unit_cfg="${_unit_cfg%\'}"
        fi
        _unit_workdir="$(grep -m1 '^WorkingDirectory=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null \
                       | sed 's/^WorkingDirectory=//')" || true

        if [[ "${_FLAG_INSTALL_DIR}" == "false" ]]; then
            if [[ "${_unit_exec}" == /* ]]; then
                INSTALL_DIR="$(dirname -- "${_unit_exec}")"
                info "Auto-derived --install-dir from systemd unit: ${INSTALL_DIR}"
            elif [[ -n "${_unit_exec}" ]]; then
                warn "Could not derive --install-dir from unit ExecStart (unexpected format: '${_unit_exec}'); falling back to default: ${INSTALL_DIR}"
            fi
        fi
        if [[ "${_FLAG_CONFIG_FILE}" == "false" ]]; then
            if [[ "${_unit_cfg}" == /* ]]; then
                CONFIG_FILE="${_unit_cfg}"
                CONFIG_DIR="$(dirname -- "${CONFIG_FILE}")"
                info "Auto-derived --config-file from systemd unit: ${CONFIG_FILE}"
            elif [[ -n "${_unit_cfg}" ]]; then
                warn "Could not derive --config-file from unit ExecStart (unexpected format: '${_unit_cfg}'); falling back to default: ${CONFIG_FILE}"
            fi
        fi
        if [[ "${_FLAG_DATA_DIR}" == "false" && -n "${_unit_workdir}" ]]; then
            DATA_DIR="${_unit_workdir}"
            info "Auto-derived --data-dir from systemd unit: ${DATA_DIR}"
        fi
    fi

    # Validate user-provided paths before performing any destructive operations.
    # Relative paths or paths containing whitespace/newlines could lead to
    # removing unintended files or injecting extra arguments.
    local _pvar _pval _flag
    for _pvar in INSTALL_DIR CONFIG_FILE DATA_DIR AWG_DIR; do
        _pval="${!_pvar}"
        _flag="--${_pvar//_/-}"; _flag="${_flag,,}"
        if [[ -z "${_pval}" ]]; then
            die "${_flag} must not be empty."
        fi
        if [[ "${_pval}" != /* ]]; then
            die "${_flag} must be an absolute path (got: '${_pval}')."
        fi
        if [[ "${_pval}" == *$'\n'* || "${_pval}" == *$'\r'* || "${_pval}" == *[[:space:]]* ]]; then
            die "${_flag} must not contain whitespace or newlines."
        fi
        if _path_has_dot_components "${_pval}"; then
            die "${_flag} must not contain '.' or '..' path components (got: '${_pval}')."
        fi
    done

    # Normalize CONFIG_DIR and DATA_DIR: collapse consecutive slashes and strip
    # trailing slashes so that case-matches against DEFAULT_*_DIR are correct
    # even for paths like /etc//amneziawg-proxy/ or /var/lib/amneziawg-proxy/
    CONFIG_DIR="$(_normalize_path "${CONFIG_DIR}")"
    DATA_DIR="$(_normalize_path "${DATA_DIR}")"

    # Validate purge directory restrictions early, before any destructive work,
    # so invalid --purge-config/--purge-data arguments fail fast and predictably
    # rather than after service/binary removal.
    if [[ "${PURGE_CONFIG}" == "true" ]]; then
        validate_purge_config_dir "${CONFIG_DIR}"
    fi
    if [[ "${PURGE_DATA}" == "true" ]]; then
        validate_purge_data_dir "${DATA_DIR}"
    fi

    print_plan

    if ! confirm "Proceed with uninstall?" "false"; then
        info "Uninstall cancelled."
        exit 0
    fi

    # 1. Optional: restore AWG listen port before stopping the proxy
    if [[ "${RESTORE_AWG}" == "true" ]]; then
        restore_awg_listen_port
    fi

    # 2. Stop and disable service
    info "Stopping service..."
    systemctl_if_active  "stop"    "${SERVICE_NAME}"
    info "Disabling service..."
    systemctl_if_enabled "disable" "${SERVICE_NAME}"

    # 3. Remove systemd unit and reload
    safe_rm_file "${SYSTEMD_UNIT_DEST}"
    if [[ "${HAVE_SYSTEMCTL}" == "true" ]]; then
        if systemctl daemon-reload; then
            info "Reloaded systemd daemon"
        else
            warn "systemctl daemon-reload failed (non-systemd environment?)"
        fi
    fi

    # 4. Remove binary
    local binary_path="${INSTALL_DIR}/${BINARY_NAME}"
    safe_rm_file "${binary_path}"

    # 5. Optional: purge config
    if [[ "${PURGE_CONFIG}" == "true" ]]; then
        if [[ "${FORCE}" != "true" ]]; then
            if ! confirm "PURGE config directory '${CONFIG_DIR}'? THIS IS IRREVERSIBLE." "false"; then
                info "Skipping config purge."
                PURGE_CONFIG="false"
            fi
        fi
        if [[ "${PURGE_CONFIG}" == "true" ]]; then
            case "${CONFIG_DIR}" in
                "${DEFAULT_CONFIG_DIR}")
                    safe_rm_dir "${CONFIG_DIR}" "${DEFAULT_CONFIG_DIR}"
                    ;;
                "${DEFAULT_CONFIG_DIR}"/*)
                    safe_rm_dir "${CONFIG_DIR}" "${DEFAULT_CONFIG_DIR}/"
                    ;;
            esac
        fi
    fi

    # 6. Optional: purge data
    if [[ "${PURGE_DATA}" == "true" ]]; then
        if [[ "${FORCE}" != "true" ]]; then
            if ! confirm "PURGE data directory '${DATA_DIR}'?" "false"; then
                info "Skipping data purge."
                PURGE_DATA="false"
            fi
        fi
        if [[ "${PURGE_DATA}" == "true" ]]; then
            case "${DATA_DIR}" in
                "${DEFAULT_DATA_DIR}")
                    safe_rm_dir "${DATA_DIR}" "${DEFAULT_DATA_DIR}/"
                    ;;
                "${DEFAULT_DATA_DIR}"/*)
                    safe_rm_dir "${DATA_DIR}" "${DEFAULT_DATA_DIR}/"
                    ;;
            esac
        fi
    fi

    printf '\n'
    green "=== amneziawg-proxy uninstall complete ==="
    printf '\n'
    if [[ "${PURGE_CONFIG}" != "true" ]]; then
        info "Config preserved: ${CONFIG_DIR}"
        info "Re-install with: sudo ./amneziawg-proxy.sh"
    fi
    if [[ "${PURGE_DATA}" != "true" ]]; then
        info "Data preserved: ${DATA_DIR}"
    fi
    if [[ "${RESTORE_AWG}" != "true" ]]; then
        info "Note: AmneziaWG listen port was NOT restored automatically."
        info "      If needed, run: sudo ./amneziawg-proxy-uninstall.sh --restore-awg"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This script must be run as root (e.g. sudo $0)"
    fi
    main "$@"
fi
