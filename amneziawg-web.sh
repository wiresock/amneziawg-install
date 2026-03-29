#!/usr/bin/env bash
# amneziawg-web.sh — unified entry point for the amneziawg-web management panel.
#
# Usage:
#   sudo ./amneziawg-web.sh install [OPTIONS]    Install the web panel
#   sudo ./amneziawg-web.sh upgrade [OPTIONS]    Upgrade the web panel binary
#   sudo ./amneziawg-web.sh uninstall [OPTIONS]  Uninstall the web panel
#   ./amneziawg-web.sh status                    Show installation status
#   ./amneziawg-web.sh help                      Show this help
#
# Run any command with --help for command-specific options.
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

# To avoid privilege-escalation via environment injection, overrides are ignored when EUID=0.
readonly DEFAULT_REPO_URL="https://github.com/wiresock/amneziawg-install.git"
readonly DEFAULT_REPO_REF="main"

_AWG_IS_ROOT=1
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    _AWG_IS_ROOT=0
fi

if [[ "${_AWG_IS_ROOT}" -eq 0 ]]; then
    # Non-root: honor environment overrides for pinning.
    readonly REPO_URL="${REPO_URL:-${DEFAULT_REPO_URL}}"
    readonly REPO_REF="${REPO_REF:-${DEFAULT_REPO_REF}}"
else
    # Root: ignore environment overrides to avoid cloning arbitrary code as root.
    readonly REPO_URL="${DEFAULT_REPO_URL}"
    readonly REPO_REF="${DEFAULT_REPO_REF}"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${SCRIPT_DIR}/amneziawg-web/scripts"
BOOTSTRAP_DIR=""

# ── Defaults (mirror inner scripts) ──────────────────────────────────────────

readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly DEFAULT_ENV_FILE="/etc/amneziawg-web/env.conf"
readonly DEFAULT_DATA_DIR="/var/lib/amneziawg-web"
readonly SERVICE_NAME="amneziawg-web"
readonly BINARY_NAME="amneziawg-web"

# ── Output helpers ───────────────────────────────────────────────────────────

# Enable colors only if stdout is a TTY and NO_COLOR is not set.
# Per https://no-color.org/, the variable's presence (even if empty) disables color.
if [[ -t 1 ]] && [[ -z "${NO_COLOR+x}" ]]; then
    _AWG_COLOR=1
else
    _AWG_COLOR=0
fi

red() {
    if [[ "${_AWG_COLOR}" -eq 1 ]]; then
        printf '\033[0;31m%s\033[0m\n' "$*"
    else
        printf '%s\n' "$*"
    fi
}

green() {
    if [[ "${_AWG_COLOR}" -eq 1 ]]; then
        printf '\033[0;32m%s\033[0m\n' "$*"
    else
        printf '%s\n' "$*"
    fi
}

yellow() {
    if [[ "${_AWG_COLOR}" -eq 1 ]]; then
        printf '\033[0;33m%s\033[0m\n' "$*"
    else
        printf '%s\n' "$*"
    fi
}

# ── Clean-up ─────────────────────────────────────────────────────────────────

cleanup() {
    if [[ -n "${BOOTSTRAP_DIR}" ]] && [[ -d "${BOOTSTRAP_DIR}" ]]; then
        rm -rf "${BOOTSTRAP_DIR}"
    fi
}

trap cleanup EXIT

# ── Bootstrap ────────────────────────────────────────────────────────────────

bootstrap_repo_if_needed() {
    local target_script="$1"
    if [[ -f "${target_script}" ]]; then
        return 0
    fi

    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: Script not found at: ${target_script}" >&2
        echo "       Install git and re-run, or clone ${REPO_URL} manually." >&2
        exit 1
    fi

    BOOTSTRAP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amneziawg-install.XXXXXX")"

    echo "Required scripts not found locally. Cloning ${REPO_URL} (${REPO_REF}) into ${BOOTSTRAP_DIR} ..." >&2
    if ! GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "${REPO_REF}" "${REPO_URL}" "${BOOTSTRAP_DIR}" >&2; then
        echo "ERROR: Failed to clone ${REPO_URL}" >&2
        echo "       Clone the repository manually and re-run." >&2
        exit 1
    fi

    SCRIPTS_DIR="${BOOTSTRAP_DIR}/amneziawg-web/scripts"
}

# ── Subcommand dispatch helper ───────────────────────────────────────────────

run_inner_script() {
    local script_name="$1"
    shift

    local target="${SCRIPTS_DIR}/${script_name}"
    bootstrap_repo_if_needed "${target}"
    # Re-evaluate after bootstrap (SCRIPTS_DIR may have changed)
    target="${SCRIPTS_DIR}/${script_name}"

    if [[ ! -f "${target}" ]]; then
        echo "ERROR: ${script_name} not found after cloning: ${target}" >&2
        exit 1
    fi

    local exit_code=0
    bash "${target}" "$@" || exit_code=$?
    exit "${exit_code}"
}

# ── Subcommand: install ──────────────────────────────────────────────────────

cmd_install()   { run_inner_script "amneziawg-web-install.sh" "$@"; }

# ── Subcommand: upgrade ──────────────────────────────────────────────────────

cmd_upgrade()   { run_inner_script "amneziawg-web-upgrade.sh" "$@"; }

# ── Subcommand: uninstall ────────────────────────────────────────────────────

cmd_uninstall() { run_inner_script "amneziawg-web-uninstall.sh" "$@"; }

# ── Subcommand: status ───────────────────────────────────────────────────────

cmd_status() {
    local install_dir="${DEFAULT_INSTALL_DIR}"
    local env_file="${DEFAULT_ENV_FILE}"
    local data_dir="${DEFAULT_DATA_DIR}"

    # Allow overriding paths for non-default installs
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-dir)
                if [[ $# -lt 2 ]]; then
                    echo "Missing value for --install-dir" >&2; exit 1
                fi
                install_dir="$2"; shift 2 ;;
            --env-file)
                if [[ $# -lt 2 ]]; then
                    echo "Missing value for --env-file" >&2; exit 1
                fi
                env_file="$2"; shift 2 ;;
            --data-dir)
                if [[ $# -lt 2 ]]; then
                    echo "Missing value for --data-dir" >&2; exit 1
                fi
                data_dir="$2"; shift 2 ;;
            --help)
                cat <<EOF
Usage: $0 status [--install-dir DIR] [--env-file FILE] [--data-dir DIR]

Show the current installation status of the amneziawg-web management panel.
EOF
                exit 0 ;;
            *) echo "Unknown option: $1" >&2; exit 1 ;;
        esac
    done

    local binary="${install_dir}/${BINARY_NAME}"

    printf '\n'
    printf '=== amneziawg-web status ===\n'
    printf '\n'

    # Binary
    if [[ -f "${binary}" ]]; then
        green "  Installed:    yes"
        printf '  Binary:       %s\n' "${binary}"
    else
        red   "  Installed:    no"
        printf '  Binary:       %s (not found)\n' "${binary}"
    fi

    # Env/config file
    if [[ -f "${env_file}" ]]; then
        printf '  Config:       %s\n' "${env_file}"
    else
        printf '  Config:       %s (not found)\n' "${env_file}"
    fi

    # Data directory
    if [[ -d "${data_dir}" ]]; then
        printf '  Data dir:     %s\n' "${data_dir}"
    else
        printf '  Data dir:     %s (not found)\n' "${data_dir}"
    fi

    # Service state (best-effort; systemctl may not be present)
    if command -v systemctl &>/dev/null; then
        local svc_active="inactive"
        local svc_enabled="disabled"
        if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
            svc_active="active"
        fi
        if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
            svc_enabled="enabled"
        fi
        printf '  Service:      %s (%s)\n' "${svc_active}" "${svc_enabled}"
    else
        printf '  Service:      systemctl not available\n'
    fi

    # Access URL (parse from env file if present)
    if [[ -f "${env_file}" ]]; then
        local listen
        listen="$(grep '^AWG_WEB_LISTEN=' "${env_file}" 2>/dev/null | cut -d= -f2- || true)"
        if [[ -n "${listen}" ]]; then
            printf '  Access URL:   http://%s\n' "${listen}"
        fi
    fi

    printf '\n'
}

# ── Help ─────────────────────────────────────────────────────────────────────

cmd_help() {
    cat <<EOF
amneziawg-web — unified management script for the AmneziaWG web panel.

Usage:
  $0 <command> [options]

Commands:
  install      Install the web panel (build or use a pre-built binary)
  upgrade      Upgrade the web panel binary
  uninstall    Uninstall the web panel
  status       Show installation status and service state
  help         Show this help message

Examples:
  sudo $0 install                          Interactive install (auto-detects source)
  sudo $0 install --install-rust           Install and auto-install Rust if needed
  sudo $0 install --binary-src ./bin/web   Install with a pre-built binary
  sudo $0 upgrade --binary ./new-binary    Upgrade with a specific binary
  sudo $0 upgrade --source-dir ./src       Rebuild from source and upgrade
  sudo $0 uninstall --force                Uninstall (safe defaults, no prompt)
  sudo $0 uninstall --purge-config \\
                    --purge-data --force    Full purge
  $0 status                                Show current installation status

Run '$0 <command> --help' for command-specific options.
EOF
}

# ── Main dispatch ────────────────────────────────────────────────────────────

if [[ $# -eq 0 ]]; then
    cmd_help
    exit 0
fi

command="$1"
shift

case "${command}" in
    install)    cmd_install "$@" ;;
    upgrade)    cmd_upgrade "$@" ;;
    uninstall)  cmd_uninstall "$@" ;;
    status)     cmd_status "$@" ;;
    help|--help|-h)
                cmd_help ;;
    *)
        echo "Unknown command: ${command}" >&2
        echo "Run '$0 help' for available commands." >&2
        exit 1
        ;;
esac
