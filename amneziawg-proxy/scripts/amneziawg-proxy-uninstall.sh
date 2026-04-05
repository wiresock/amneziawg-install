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
  --purge-config       Also remove config directory (${DEFAULT_CONFIG_DIR})
  --purge-data         Also remove data/working directory (${DEFAULT_DATA_DIR})
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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)      INSTALL_DIR="$2"; shift 2 ;;
        --config-file)      CONFIG_FILE="$2"; CONFIG_DIR="$(dirname "${CONFIG_FILE}")"; shift 2 ;;
        --data-dir)         DATA_DIR="$2"; shift 2 ;;
        --awg-dir)          AWG_DIR="$2"; shift 2 ;;
        --purge-config)     PURGE_CONFIG="true"; shift ;;
        --purge-data)       PURGE_DATA="true"; shift ;;
        --restore-awg)      RESTORE_AWG="true"; shift ;;
        --force)            FORCE="true"; shift ;;
        --non-interactive)  FORCE="true"; shift ;;
        --help|-h)          usage; exit 0 ;;
        *) die "Unknown option: $1  (use --help for usage)" ;;
    esac
done

# ── Root check ─────────────────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    die "This script must be run as root (e.g. sudo $0)"
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
    read -r -p "${prompt}" reply
    reply="${reply:-${default}}"
    case "${reply}" in
        [Yy]*|true) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Safe rm helpers ────────────────────────────────────────────────────────────

# Validate a params file is safe to source: must be a regular file (not a
# symlink), owned by root, and have permissions 600 or 400.
# Returns 0 if safe, 1 with a warning if not.
validate_params_file() {
    local f="$1"
    if [[ -L "${f}" ]] || [[ -h "${f}" ]]; then
        warn "Ignoring params file — must not be a symbolic link: ${f}"
        return 1
    fi
    if [[ ! -f "${f}" ]]; then
        return 1
    fi
    local owner perms
    owner="$(stat -c '%u' "${f}" 2>/dev/null || true)"
    perms="$(stat -c '%a' "${f}" 2>/dev/null || true)"
    if [[ "${owner}" != "0" ]]; then
        warn "Ignoring params file — not owned by root (owner UID: ${owner}): ${f}"
        return 1
    fi
    if [[ "${perms}" != "600" ]] && [[ "${perms}" != "400" ]]; then
        warn "Ignoring params file — insecure permissions (${perms}); expected 600 or 400: ${f}"
        return 1
    fi
    return 0
}

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

safe_rm_dir() {
    local d="$1"
    local prefix="$2"
    if [[ -z "${d}" ]]; then
        warn "safe_rm_dir: empty path, skipping"
        return 0
    fi
    if [[ "${#d}" -lt 5 ]]; then
        die "Refusing to remove suspiciously short path: ${d}"
    fi
    if [[ "${d}" != "${prefix}"* ]]; then
        die "Refusing to remove '${d}': does not start with expected prefix '${prefix}'"
    fi
    if [[ -d "${d}" ]]; then
        rm -rf -- "${d}"
        info "Removed directory: ${d}"
    else
        info "Already absent: ${d}"
    fi
}

# ── systemd helpers ────────────────────────────────────────────────────────────

systemctl_if_active() {
    local verb="$1"
    local unit="$2"
    if systemctl is-active --quiet "${unit}" 2>/dev/null; then
        systemctl "${verb}" "${unit}" && info "Service ${verb}ped: ${unit}" || \
            warn "Could not ${verb} ${unit} (already stopped?)"
    else
        info "Service not active, skipping ${verb}: ${unit}"
    fi
}

systemctl_if_enabled() {
    local verb="$1"
    local unit="$2"
    if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
        systemctl "${verb}" "${unit}" && info "Service ${verb}d: ${unit}" || \
            warn "Could not ${verb} ${unit}"
    else
        info "Service not enabled, skipping ${verb}: ${unit}"
    fi
}

# ── AWG restore ────────────────────────────────────────────────────────────────

# Read listen and backend ports from the proxy config file.
read_proxy_config_ports() {
    local cfg="$1"
    if [[ ! -f "${cfg}" ]]; then
        return 1
    fi

    # Extract listen port from: listen = "host:port"
    PROXY_LISTEN_PORT="$(grep -E '^[[:space:]]*listen[[:space:]]*=' "${cfg}" \
        | head -1 | sed 's/.*=[[:space:]]*//' | tr -d '"' | \
        awk -F: '{print $NF}' | tr -d '[:space:]')" || true

    # Extract backend port from: backend = "host:port"
    PROXY_BACKEND_PORT="$(grep -E '^[[:space:]]*backend[[:space:]]*=' "${cfg}" \
        | head -1 | sed 's/.*=[[:space:]]*//' | tr -d '"' | \
        awk -F: '{print $NF}' | tr -d '[:space:]')" || true

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
        awg_nic="$(bash -c ". '${params_file}' 2>/dev/null && printf '%s' \"\${SERVER_AWG_NIC:-}\"")"
    fi

    if [[ -n "${awg_nic}" ]]; then
        awg_conf="${AWG_DIR}/${awg_nic}.conf"
    else
        awg_conf="$(find "${AWG_DIR}" -maxdepth 1 -name '*.conf' | sort | head -1 2>/dev/null || true)"
        awg_nic="$(basename "${awg_conf}" .conf 2>/dev/null || true)"
    fi

    if [[ -z "${awg_conf}" ]] || [[ ! -f "${awg_conf}" ]]; then
        warn "AWG config not found; skipping listen port restore."
        return 0
    fi

    # Look for a backup file created by the installer
    local latest_backup
    latest_backup="$(find "${AWG_DIR}" -maxdepth 1 \
        -name "$(basename "${awg_conf}").bak.*" | sort | tail -1 2>/dev/null || true)"

    if [[ -n "${latest_backup}" ]]; then
        info "Found AWG config backup: ${latest_backup}"
        if confirm "Restore AWG config from backup ${latest_backup}?" "true"; then
            cp "${latest_backup}" "${awg_conf}"
            info "Restored AWG config from: ${latest_backup}"

            # Restart the interface
            if systemctl is-active --quiet "awg-quick@${awg_nic}" 2>/dev/null; then
                info "Restarting AWG interface ${awg_nic}..."
                if ! systemctl restart "awg-quick@${awg_nic}"; then
                    warn "Failed to restart awg-quick@${awg_nic}."
                    warn "Run manually: sudo systemctl restart awg-quick@${awg_nic}"
                else
                    info "AWG interface ${awg_nic} restarted with original config."
                fi
            else
                warn "AWG interface awg-quick@${awg_nic} is not active."
                warn "Start it with: sudo systemctl start awg-quick@${awg_nic}"
            fi
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

    # Restart the interface
    if systemctl is-active --quiet "awg-quick@${awg_nic}" 2>/dev/null; then
        info "Restarting AWG interface ${awg_nic}..."
        if ! systemctl restart "awg-quick@${awg_nic}"; then
            warn "Failed to restart awg-quick@${awg_nic}."
            warn "Run manually: sudo systemctl restart awg-quick@${awg_nic}"
        else
            info "AWG interface ${awg_nic} restarted."
        fi
    fi
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
        printf '  Config:   %s  [WILL BE REMOVED --purge-config]\n' "${CONFIG_DIR}"
    fi
    if [[ "${PURGE_DATA}" != "true" ]]; then
        printf '  Data dir: %s  [preserved]\n' "${DATA_DIR}"
    else
        printf '  Data dir: %s  [WILL BE REMOVED --purge-data]\n' "${DATA_DIR}"
    fi
    if [[ "${RESTORE_AWG}" == "true" ]]; then
        printf '\n'
        printf 'AWG restore:  will attempt to restore AWG listen port [--restore-awg]\n'
    fi
    printf '\n'
}

# ── Main uninstall ─────────────────────────────────────────────────────────────

main() {
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
    if command -v systemctl &>/dev/null; then
        systemctl daemon-reload
        info "Reloaded systemd daemon"
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
            safe_rm_dir "${CONFIG_DIR}" "/etc/"
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
            safe_rm_dir "${DATA_DIR}" "/var/"
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
        info "      If needed, run: sudo ./amneziawg-proxy.sh (select Uninstall → --restore-awg)"
    fi
}

main "$@"
