#!/usr/bin/env bash
# amneziawg-proxy.sh
# Single entry point for installing and managing the amneziawg-proxy UDP
# obfuscation proxy.
#
# Behaviour mirrors amneziawg-install.sh:
#   • If the proxy is NOT installed → runs the interactive installer.
#   • If the proxy IS  installed    → shows a management menu with options
#     to view status, tail logs, reconfigure, uninstall, or exit.
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

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPTS_DIR="${SCRIPT_DIR}/amneziawg-proxy/scripts"
BOOTSTRAP_DIR=""

INSTALLER="${SCRIPTS_DIR}/amneziawg-proxy-install.sh"
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
    if [[ "${_AWG_IS_ROOT}" -eq 0 ]]; then
        return 1
    fi

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
    UNINSTALLER="${SCRIPTS_DIR}/amneziawg-proxy-uninstall.sh"
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
    echo "   3) Reconfigure (re-run installer)"
    echo "   4) Uninstall amneziawg-proxy"
    echo "   5) Exit"

    local option=""
    until [[ "${option}" =~ ^[1-5]$ ]]; do
        if ! read -rp "Select an option [1-5]: " option; then
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
            bootstrap_repo_if_needed "${INSTALLER}"
            exec bash "${INSTALLER}"
            ;;
        4)
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

            exec bash "${UNINSTALLER}" "${uninstall_args[@]}"
            ;;
        5)
            exit 0
            ;;
    esac
}

# ── Entrypoint ────────────────────────────────────────────────────────────────

if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root (use sudo)."
fi

if is_proxy_installed; then
    manage_menu "$@"
else
    bootstrap_repo_if_needed "${INSTALLER}"
    exec bash "${INSTALLER}" "$@"
fi
