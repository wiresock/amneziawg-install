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

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALLER="${SCRIPT_DIR}/amneziawg-proxy/scripts/amneziawg-proxy-install.sh"
UNINSTALLER="${SCRIPT_DIR}/amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh"

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
            # Strip "ExecStart=" prefix and take the first token (the binary).
            local bin_path
            bin_path="$(printf '%s' "${exec_start#ExecStart=}" | awk '{print $1}')"
            if [[ -n "${bin_path}" ]]; then
                printf '%s' "${bin_path}"
                return
            fi
        fi
    fi
    printf '%s' "${DEFAULT_INSTALL_DIR}/amneziawg-proxy"
}

BINARY_PATH="$(_get_binary_path)"

# ── Helpers ───────────────────────────────────────────────────────────────────

die()  { printf '\033[0;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
warn() { printf '\033[0;33m[WARN] \033[0m %s\n' "$*" >&2; }

require_inner_script() {
    local path="$1"
    if [[ ! -f "${path}" ]]; then
        die "Script not found at: ${path}
Make sure you cloned the full repository."
    fi
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
            require_inner_script "${INSTALLER}"
            exec bash "${INSTALLER}"
            ;;
        4)
            require_inner_script "${UNINSTALLER}"

            echo ""
            echo "Uninstall options:"
            echo "   1) Uninstall with safe defaults"
            echo "   2) Uninstall and restore AWG"
            echo "   3) Uninstall and purge generated config"
            echo "   4) Uninstall and purge data"
            echo "   5) Uninstall and purge config + data"
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

            exec bash "${UNINSTALLER}" ${uninstall_args[@]+"${uninstall_args[@]}"}
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
    require_inner_script "${INSTALLER}"
    exec bash "${INSTALLER}" "$@"
fi
