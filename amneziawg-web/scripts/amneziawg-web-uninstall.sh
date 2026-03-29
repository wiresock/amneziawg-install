#!/usr/bin/env bash
# amneziawg-web-uninstall.sh
# Companion uninstall script for the amneziawg-web management panel.
#
# Usage:
#   sudo ./amneziawg-web-uninstall.sh                         # interactive (safe defaults)
#   sudo ./amneziawg-web-uninstall.sh --force                  # non-interactive, safe defaults
#   sudo ./amneziawg-web-uninstall.sh --purge-config --purge-data --force
#   sudo ./amneziawg-web-uninstall.sh --help
#
# Default behavior (safe):
#   - stops and disables the systemd service
#   - removes the installed binary
#   - removes AWG lifecycle script only when it was installed by amneziawg-web
#   - removes the systemd unit file
#   - reloads systemd daemon
#   - PRESERVES: env/config file, data directory, service user
#
# Purge flags (must be explicit):
#   --purge-config   remove /etc/amneziawg-web/ (env file and directory)
#   --purge-data     remove the data directory (SQLite DB and all data)
#   --remove-user    remove the service user account (awg-web)
#
# Assumed install paths (same defaults as the installer):
#   Binary:       /usr/local/bin/amneziawg-web
#   AWG script:   /usr/local/bin/amneziawg-install.sh
#   Env file:     /etc/amneziawg-web/env.conf
#   Env dir:      /etc/amneziawg-web/
#   Data dir:     /var/lib/amneziawg-web/
#   Systemd unit: /etc/systemd/system/amneziawg-web.service
#   Service user: awg-web
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────

readonly SERVICE_NAME="amneziawg-web"
readonly SERVICE_USER="awg-web"
readonly SYSTEMD_UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
readonly SUDOERS_FILE="/etc/sudoers.d/amneziawg-web"
readonly AWG_INSTALL_SCRIPT_DEST="/usr/local/bin/amneziawg-install.sh"
readonly AWG_INSTALL_SCRIPT_MARKER_NAME="installed-awg-script.path"
readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly DEFAULT_DATA_DIR="/var/lib/amneziawg-web"
readonly DEFAULT_ENV_DIR="/etc/amneziawg-web"
readonly DEFAULT_ENV_FILE="/etc/amneziawg-web/env.conf"
readonly BINARY_NAME="amneziawg-web"

# ── Defaults ───────────────────────────────────────────────────────────────────

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
DATA_DIR="${DEFAULT_DATA_DIR}"
ENV_DIR="${DEFAULT_ENV_DIR}"
ENV_FILE="${DEFAULT_ENV_FILE}"

PURGE_CONFIG="false"
PURGE_DATA="false"
REMOVE_USER="false"
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

Uninstall the amneziawg-web management panel.

Safe defaults:
  Removes:   systemd service, installed binary
  Preserves: env/config file, data directory, service user

Options:
  --install-dir DIR    Binary install directory  (default: ${DEFAULT_INSTALL_DIR})
  --data-dir DIR       Data directory            (default: ${DEFAULT_DATA_DIR})
  --env-file FILE      Env/config file path      (default: ${DEFAULT_ENV_FILE})
  --purge-config       Also remove env/config directory (${DEFAULT_ENV_DIR})
  --purge-data         Also remove data directory and all data (${DEFAULT_DATA_DIR})
  --remove-user        Also remove the service user (${SERVICE_USER})
  --force              Skip confirmation prompts
  --non-interactive    Alias for --force; suitable for CI/automation
  --help               Show this help

Purge example:
  sudo $0 --purge-config --purge-data --force

EOF
}

# ── Argument parsing ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)        INSTALL_DIR="$2"; shift 2 ;;
        --data-dir)           DATA_DIR="$2"; shift 2 ;;
        --env-file)           ENV_FILE="$2"; ENV_DIR="$(dirname "${ENV_FILE}")"; shift 2 ;;
        --purge-config)       PURGE_CONFIG="true"; shift ;;
        --purge-data)         PURGE_DATA="true"; shift ;;
        --remove-user)        REMOVE_USER="true"; shift ;;
        --force)              FORCE="true"; shift ;;
        --non-interactive)    FORCE="true"; shift ;;
        --help|-h)            usage; exit 0 ;;
        *) die "Unknown option: $1  (use --help for usage)" ;;
    esac
done

normalize_path() {
    if command -v realpath >/dev/null 2>&1; then
        realpath -m -- "$1"
    elif command -v readlink >/dev/null 2>&1; then
        readlink -f -- "$1"
    else
        die "Neither realpath nor readlink is available; cannot normalize paths"
    fi
}

ENV_FILE="$(normalize_path "${ENV_FILE}")"
ENV_DIR="$(normalize_path "${ENV_DIR}")"

if [[ "${ENV_FILE}" != /* ]]; then
    die "Env file path must be absolute after normalization: ${ENV_FILE}"
fi
if [[ "${ENV_DIR}" != /* ]]; then
    die "Env directory path must be absolute after normalization: ${ENV_DIR}"
fi
if [[ "${ENV_DIR}" == "/etc" ]]; then
    die "Env directory must not be /etc itself: ${ENV_DIR}"
fi
if [[ "${ENV_DIR}" != /etc/* ]]; then
    die "Env directory must reside under /etc: ${ENV_DIR}"
fi

# ── Root check ─────────────────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    die "This script must be run as root (e.g. sudo $0)"
fi

# ── Confirmation helper ────────────────────────────────────────────────────────

# confirm MSG DEFAULT_YES
# Returns 0 if confirmed, 1 if declined.
# In force/non-interactive mode always returns 0.
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

# safe_rm_file FILE
# Removes FILE only if it exists and is a regular file or symlink.
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

# safe_rm_dir DIR EXPECTED_PREFIX
# Removes DIR only if it exists, is a directory, and starts with EXPECTED_PREFIX.
# Refuses to remove directories with suspicious paths.
safe_rm_dir() {
    local d="$1"
    local prefix="$2"
    if [[ -z "${d}" ]]; then
        warn "safe_rm_dir: empty path, skipping"
        return 0
    fi
    # Guard: path must start with the expected prefix and be at least 5 chars
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

# ── Summary / plan ─────────────────────────────────────────────────────────────

print_plan() {
    local marker_path="${ENV_DIR}/${AWG_INSTALL_SCRIPT_MARKER_NAME}"
    local awg_script_plan_path="${AWG_INSTALL_SCRIPT_DEST}"
    if [[ -f "${marker_path}" ]]; then
        local marker_target
        marker_target="$(head -n 1 "${marker_path}" 2>/dev/null || true)"
        if is_safe_awg_script_path "${marker_target}"; then
            awg_script_plan_path="${marker_target}"
        fi
    fi

    printf '\n'
    printf '=== amneziawg-web uninstall plan ===\n'
    printf '\n'
    printf 'Will REMOVE:\n'
    printf '  Binary:       %s\n'  "${INSTALL_DIR}/${BINARY_NAME}"
    printf '  AWG script:   %s (if installed by amneziawg-web)\n'  "${awg_script_plan_path}"
    printf '  Systemd unit: %s\n'  "${SYSTEMD_UNIT_DEST}"
    printf '  Sudoers:      %s\n'  "${SUDOERS_FILE}"
    printf '  Service:      stop + disable %s\n' "${SERVICE_NAME}"
    printf '\n'
    printf 'Will PRESERVE (unless purge flags are given):\n'
    if [[ "${PURGE_CONFIG}" != "true" ]]; then
        printf '  Env/config:   %s  [preserved]\n' "${ENV_DIR}"
    else
        printf '  Env/config:   %s  [WILL BE REMOVED --purge-config]\n' "${ENV_DIR}"
    fi
    if [[ "${PURGE_DATA}" != "true" ]]; then
        printf '  Data dir:     %s  [preserved]\n' "${DATA_DIR}"
    else
        printf '  Data dir:     %s  [WILL BE REMOVED --purge-data]\n' "${DATA_DIR}"
    fi
    if [[ "${REMOVE_USER}" != "true" ]]; then
        printf '  Service user: %s  [preserved]\n' "${SERVICE_USER}"
    else
        printf '  Service user: %s  [WILL BE REMOVED --remove-user]\n' "${SERVICE_USER}"
    fi
    printf '\n'
}

is_safe_awg_script_path() {
    local path="$1"
    if [[ "${path}" != /* ]] || [[ "${path}" =~ [[:space:],] ]]; then
        return 1
    fi

    local filename="${path##*/}"
    if [[ "${filename}" != "amneziawg-install.sh" ]]; then
        return 1
    fi

    case "${path}" in
        /usr/local/bin/amneziawg-install.sh|\
        /usr/bin/amneziawg-install.sh|\
        /opt/amneziawg-web/bin/amneziawg-install.sh)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

remove_managed_awg_install_script() {
    local marker_path="${ENV_DIR}/${AWG_INSTALL_SCRIPT_MARKER_NAME}"

    if [[ ! -f "${marker_path}" ]]; then
        info "Preserving AWG lifecycle script because it is not marked as installer-managed (no marker file found)"
        return 0
    fi

    local marker_target
    marker_target="$(head -n 1 "${marker_path}" 2>/dev/null || true)"
    if ! is_safe_awg_script_path "${marker_target}"; then
        warn "AWG lifecycle script marker contains unsafe path '${marker_target}', preserving AWG script"
        return 0
    fi

    safe_rm_file "${marker_target}"
    safe_rm_file "${marker_path}"
}

# ── Main uninstall ─────────────────────────────────────────────────────────────

main() {
    print_plan

    if ! confirm "Proceed with uninstall?" "false"; then
        info "Uninstall cancelled."
        exit 0
    fi

    # 1. Stop and disable service
    info "Stopping service..."
    systemctl_if_active  "stop"    "${SERVICE_NAME}"
    info "Disabling service..."
    systemctl_if_enabled "disable" "${SERVICE_NAME}"

    # 2. Remove systemd unit and reload
    safe_rm_file "${SYSTEMD_UNIT_DEST}"
    if command -v systemctl &>/dev/null; then
        systemctl daemon-reload
        info "Reloaded systemd daemon"
    fi

    # 3. Remove sudoers drop-in
    safe_rm_file "${SUDOERS_FILE}"

    # 4. Remove binary
    local binary_path="${INSTALL_DIR}/${BINARY_NAME}"
    # Sanity-check the binary path before removing it
    if [[ "${binary_path}" != "${INSTALL_DIR}/${BINARY_NAME}" ]] || \
       [[ "${INSTALL_DIR}" != "/usr/local/bin" && \
          "${INSTALL_DIR}" != "/usr/bin" && \
          "${INSTALL_DIR}" != "/opt/amneziawg-web/bin" && \
          ! "${INSTALL_DIR}" =~ ^/tmp/ ]]; then
        # Non-standard path: still remove, but print a warning
        warn "Non-standard install dir: ${INSTALL_DIR}"
    fi
    safe_rm_file "${binary_path}"

    # 5. Remove installer-managed AWG lifecycle script
    remove_managed_awg_install_script

    # 6. Optional: purge config
    if [[ "${PURGE_CONFIG}" == "true" ]]; then
        if [[ "${FORCE}" != "true" ]]; then
            if ! confirm "PURGE config/env directory '${ENV_DIR}'? THIS IS IRREVERSIBLE." "false"; then
                info "Skipping config purge."
                PURGE_CONFIG="false"
            fi
        fi
        if [[ "${PURGE_CONFIG}" == "true" ]]; then
            safe_rm_dir "${ENV_DIR}" "/etc/"
        fi
    fi

    # 7. Optional: purge data
    if [[ "${PURGE_DATA}" == "true" ]]; then
        if [[ "${FORCE}" != "true" ]]; then
            if ! confirm "PURGE data directory '${DATA_DIR}'? ALL DATABASE DATA WILL BE LOST." "false"; then
                info "Skipping data purge."
                PURGE_DATA="false"
            fi
        fi
        if [[ "${PURGE_DATA}" == "true" ]]; then
            safe_rm_dir "${DATA_DIR}" "/var/"
        fi
    fi

    # 8. Optional: remove service user
    if [[ "${REMOVE_USER}" == "true" ]]; then
        if [[ "${FORCE}" != "true" ]]; then
            if ! confirm "Remove service user '${SERVICE_USER}'?" "false"; then
                info "Skipping user removal."
                REMOVE_USER="false"
            fi
        fi
        if [[ "${REMOVE_USER}" == "true" ]]; then
            if id "${SERVICE_USER}" &>/dev/null; then
                userdel "${SERVICE_USER}" \
                    && info "Removed service user: ${SERVICE_USER}" \
                    || warn "Could not remove service user: ${SERVICE_USER}"
            else
                info "Service user already absent: ${SERVICE_USER}"
            fi
        fi
    fi

    printf '\n'
    green "=== amneziawg-web uninstall complete ==="
    printf '\n'
    if [[ "${PURGE_CONFIG}" != "true" ]]; then
        info "Config/env preserved: ${ENV_DIR}"
        info "Re-install with:  sudo ./amneziawg-web-install.sh --force"
    fi
    if [[ "${PURGE_DATA}" != "true" ]]; then
        info "Data preserved:   ${DATA_DIR}"
    fi
}

main "$@"
