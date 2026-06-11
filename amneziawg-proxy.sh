#!/usr/bin/env bash
# amneziawg-proxy.sh
# Single entry point for installing and managing the amneziawg-proxy UDP
# obfuscation proxy.
#
# Behaviour mirrors amneziawg-install.sh:
#   • If the proxy is NOT installed → runs the interactive installer.
#   • If the proxy IS  installed    → shows a management menu with options
#     to view status, tail logs, upgrade, reconfigure, uninstall, or exit.
#
# Recommended workflow:
#   sudo ./amneziawg-install.sh      # 1. install AmneziaWG
#   sudo ./amneziawg-proxy.sh        # 2. install / manage the UDP proxy
#
# All installer logic lives in amneziawg-proxy/scripts/.
# This file is a thin dispatcher that forwards to those scripts.
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

# This script always requires root; env overrides are never honored to prevent
# privilege-escalation via environment injection.
readonly REPO_URL="https://github.com/wiresock/amneziawg-install.git"
readonly REPO_REF="main"

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPTS_DIR="${SCRIPT_DIR}/amneziawg-proxy/scripts"
BOOTSTRAP_DIR=""

INSTALLER="${SCRIPTS_DIR}/amneziawg-proxy-install.sh"
UPGRADER="${SCRIPTS_DIR}/amneziawg-proxy-upgrade.sh"
UNINSTALLER="${SCRIPTS_DIR}/amneziawg-proxy-uninstall.sh"

# ── Clean-up ─────────────────────────────────────────────────────────────────

cleanup() {
    if [[ -n "${BOOTSTRAP_DIR}" ]] && [[ -d "${BOOTSTRAP_DIR}" ]]; then
        rm -rf "${BOOTSTRAP_DIR}"
    fi
}

trap cleanup EXIT

# ── Git auto-install ──────────────────────────────────────────────────────────

# Detect the system package manager and set _PKG_MGR to the install command.
# Returns 1 if no supported package manager is found.
detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        _PKG_MGR="apt-get"
    elif command -v dnf >/dev/null 2>&1; then
        _PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then
        _PKG_MGR="yum"
    else
        return 1
    fi
    return 0
}

# Attempt to install git after prompting the user for confirmation.
# Skips silently (returns 1) when not root or not on a TTY.
install_git() {
    if ! detect_package_manager; then
        return 1
    fi

    # Non-interactive — cannot prompt
    if [[ ! -t 0 ]]; then
        return 1
    fi

    warn "git is not installed, but is required to fetch the repository."
    printf 'Would you like to install git now using %s? [y/N] ' "${_PKG_MGR}"
    local answer
    read -r answer || return 1
    case "${answer}" in
        [Yy]|[Yy][Ee][Ss]) ;;
        *) return 1 ;;
    esac

    echo "Installing git ..."
    local install_log
    install_log="$(mktemp "${TMPDIR:-/tmp}/awg-git-install.XXXXXX")"
    local install_rc=0
    if [[ "${_PKG_MGR}" == "apt-get" ]]; then
        apt-get update -qq >>"${install_log}" 2>&1 || install_rc=$?
        if [[ "${install_rc}" -eq 0 ]]; then
            apt-get install -y -qq git >>"${install_log}" 2>&1 || install_rc=$?
        fi
    else
        "${_PKG_MGR}" install -y git >>"${install_log}" 2>&1 || install_rc=$?
    fi

    if ! command -v git >/dev/null 2>&1; then
        printf '\033[0;31mERROR: Failed to install git (exit code %s).\033[0m\n' "${install_rc}" >&2
        if [[ -s "${install_log}" ]]; then
            echo "--- package manager output ---" >&2
            tail -20 "${install_log}" >&2
            echo "------------------------------" >&2
        fi
        rm -f "${install_log}"
        return 1
    fi
    rm -f "${install_log}"

    printf '\033[0;32mgit installed successfully.\033[0m\n'
    return 0
}

# ── Bootstrap ────────────────────────────────────────────────────────────────

bootstrap_repo_if_needed() {
    local target_script="$1"
    if [[ -f "${target_script}" ]]; then
        return 0
    fi

    if ! command -v git >/dev/null 2>&1; then
        if ! install_git; then
            echo "ERROR: Script not found at: ${target_script}" >&2
            echo "       Install git and re-run, or clone ${REPO_URL} manually." >&2
            exit 1
        fi
    fi

    BOOTSTRAP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amneziawg-install.XXXXXX")"

    echo "Required scripts not found locally. Cloning ${REPO_URL} (${REPO_REF}) into ${BOOTSTRAP_DIR} ..." >&2
    if ! GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "${REPO_REF}" "${REPO_URL}" "${BOOTSTRAP_DIR}" >&2; then
        echo "ERROR: Failed to clone ${REPO_URL}" >&2
        echo "       Clone the repository manually and re-run." >&2
        exit 1
    fi

    SCRIPTS_DIR="${BOOTSTRAP_DIR}/amneziawg-proxy/scripts"
    INSTALLER="${SCRIPTS_DIR}/amneziawg-proxy-install.sh"
    UPGRADER="${SCRIPTS_DIR}/amneziawg-proxy-upgrade.sh"
    UNINSTALLER="${SCRIPTS_DIR}/amneziawg-proxy-uninstall.sh"

    if [[ ! -f "${INSTALLER}" ]] || [[ ! -f "${UPGRADER}" ]] || [[ ! -f "${UNINSTALLER}" ]]; then
        echo "ERROR: Cloned repository is missing required scripts in ${SCRIPTS_DIR}" >&2
        echo "       The repository layout may have changed. Clone ${REPO_URL} manually." >&2
        exit 1
    fi
}

readonly SERVICE_NAME="amneziawg-proxy"
readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly SYSTEMD_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

# Derive the binary path from the installed systemd unit when available.
# If the unit exists, parse ExecStart to find where the binary actually lives
# (supports non-default --install-dir deployments).  Fall back to the default
# path only when the unit is absent.
_get_binary_path() {
    if [[ -f "${SYSTEMD_UNIT}" ]]; then
        local exec_start
        exec_start="$(grep -m1 '^ExecStart=' "${SYSTEMD_UNIT}" 2>/dev/null || true)"
        if [[ -n "${exec_start}" ]]; then
            # ExecStart=/path/to/amneziawg-proxy /path/to/proxy.toml
            # Split the payload into tokens and strip surrounding quotes from
            # the first token (the binary path) so quoted unit files are handled.
            local exec_payload bin_path rest
            exec_payload="${exec_start#ExecStart=}"
            read -r bin_path rest <<< "${exec_payload}"
            if [[ -n "${bin_path}" ]]; then
                if [[ "${bin_path}" == \"*\" ]]; then
                    bin_path="${bin_path#\"}"
                    bin_path="${bin_path%\"}"
                elif [[ "${bin_path}" == \'*\' ]]; then
                    bin_path="${bin_path#\'}"
                    bin_path="${bin_path%\'}"
                fi
                if [[ -n "${bin_path}" && "$(basename -- "${bin_path}")" == 'amneziawg-proxy' ]]; then
                    printf '%s' "${bin_path}"
                    return
                fi
            fi
        fi
    fi
    printf '%s' "${DEFAULT_INSTALL_DIR}/amneziawg-proxy"
}

BINARY_PATH="$(_get_binary_path)"

# ── Helpers ───────────────────────────────────────────────────────────────────

die()  { printf '\033[0;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
warn() { printf '\033[0;33m[WARN] \033[0m %s\n' "$*" >&2; }

usage() {
    cat <<EOF
amneziawg-proxy - unified management script for the AmneziaWG UDP proxy.

Usage:
  sudo $0 [installer-options]              Install or manage the proxy
  sudo $0 upgrade [upgrade-options]        Upgrade the proxy binary
  sudo $0 install [installer-options]      Run the installer explicitly
  sudo $0 uninstall [uninstall-options]    Run the uninstaller explicitly
  sudo $0 help                             Show this help

Common upgrade examples:
  sudo $0 upgrade --source-dir ./amneziawg-proxy
  sudo $0 upgrade --binary ./target/release/amneziawg-proxy
  sudo $0 upgrade --source-dir ./amneziawg-proxy --force --restart

Run inner commands with --help for command-specific options.
EOF
}

run_script() {
    local target_var="$1"
    shift

    local target="${!target_var}"
    bootstrap_repo_if_needed "${target}"
    target="${!target_var}"

    local rc=0
    bash "${target}" "$@" || rc=$?
    exit "${rc}"
}

# ── Installation detection ────────────────────────────────────────────────────

is_proxy_installed() {
    [[ -x "${BINARY_PATH}" ]] || [[ -f "${SYSTEMD_UNIT}" ]]
}

# ── Management menu ───────────────────────────────────────────────────────────

manage_menu() {
    echo "amneziawg-proxy (https://github.com/wiresock/amneziawg-install)"
    echo ""
    echo "It looks like amneziawg-proxy is already installed."
    echo ""
    echo "What do you want to do?"
    echo "   1) Show service status"
    echo "   2) Tail service logs"
    echo "   3) Upgrade binary"
    echo "   4) Reconfigure (re-run installer)"
    echo "   5) Uninstall amneziawg-proxy"
    echo "   6) Exit"

    local option=""
    until [[ "${option}" =~ ^[1-6]$ ]]; do
        if ! read -rp "Select an option [1-6]: " option; then
            die "No input available; cannot read menu selection."
        fi
    done

    case "${option}" in
        1)
            if ! command -v systemctl &>/dev/null; then
                warn "systemctl is not available on this system."
            else
                systemctl status "${SERVICE_NAME}" --no-pager || true
            fi
            ;;
        2)
            if ! command -v journalctl &>/dev/null; then
                warn "journalctl is not available on this system."
            else
                local journalctl_status=0
                journalctl -u "${SERVICE_NAME}" -f --no-pager || journalctl_status=$?
                if [[ "${journalctl_status}" -ne 0 && "${journalctl_status}" -ne 130 ]]; then
                    warn "Failed to read logs for ${SERVICE_NAME} via journalctl."
                fi
            fi
            ;;
        3)
            run_script UPGRADER
            ;;
        4)
            run_script INSTALLER
            ;;
        5)
            bootstrap_repo_if_needed "${UNINSTALLER}"

            echo ""
            echo "Uninstall options:"
            echo "   1) Uninstall with safe defaults"
            echo "   2) Uninstall and restore AWG"
            echo "   3) Uninstall and purge generated config (default path only)"
            echo "   4) Uninstall and purge data (default path only)"
            echo "   5) Uninstall and purge config + data (default paths only)"
            echo "   6) Cancel"

            local uninstall_option=""
            local -a uninstall_args=()
            until [[ "${uninstall_option}" =~ ^[1-6]$ ]]; do
                if ! read -rp "Select an uninstall option [1-6]: " uninstall_option; then
                    die "No input available; cannot read uninstall selection."
                fi
            done

            case "${uninstall_option}" in
                1)
                    ;;
                2)
                    uninstall_args=(--restore-awg)
                    ;;
                3)
                    uninstall_args=(--purge-config)
                    ;;
                4)
                    uninstall_args=(--purge-data)
                    ;;
                5)
                    uninstall_args=(--purge-config --purge-data)
                    ;;
                6)
                    exit 0
                    ;;
            esac

            local rc=0
            bash "${UNINSTALLER}" "${uninstall_args[@]}" || rc=$?
            exit "${rc}"
            ;;
        6)
            exit 0
            ;;
    esac
}

# ── Entrypoint ────────────────────────────────────────────────────────────────

if [[ $# -gt 0 ]]; then
    case "$1" in
        help|--help|-h)
            usage
            exit 0
            ;;
    esac
fi

if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root (use sudo)."
fi

if [[ $# -gt 0 ]]; then
    command="$1"
    case "${command}" in
        upgrade)
            shift
            run_script UPGRADER "$@"
            ;;
        install)
            shift
            run_script INSTALLER "$@"
            ;;
        uninstall)
            shift
            run_script UNINSTALLER "$@"
            ;;
    esac
fi

if is_proxy_installed; then
    manage_menu "$@"
else
    run_script INSTALLER "$@"
fi
