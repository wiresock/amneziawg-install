#!/usr/bin/env bash
# amneziawg-web-upgrade.sh
# Companion upgrade script for the amneziawg-web management panel.
#
# Usage:
#   sudo ./amneziawg-web-upgrade.sh --source-dir ./amneziawg-web
#   sudo ./amneziawg-web-upgrade.sh --binary ./target/release/amneziawg-web
#   sudo ./amneziawg-web-upgrade.sh --help
#
# Default behavior:
#   - builds from source (--source-dir) or uses a supplied binary (--binary)
#   - verifies the existing installation is present and valid
#   - replaces the installed binary with the new one
#   - restarts the service if it was active before the upgrade
#   - PRESERVES: env/config file, data directory, service user, systemd unit
#
# Optional flags:
#   --restart          force-restart the service after upgrade (even if inactive)
#   --no-restart       skip restarting the service after upgrade
#   --refresh-unit     reinstall the systemd unit file from the repository copy
#   --install-rust     install Rust toolchain via rustup if missing (source mode)
#
# Assumed install paths (same defaults as the installer):
#   Binary:       /usr/local/bin/amneziawg-web
#   Env file:     /etc/amneziawg-web/env.conf
#   Data dir:     /var/lib/amneziawg-web/
#   Systemd unit: /etc/systemd/system/amneziawg-web.service
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────

readonly SERVICE_NAME="amneziawg-web"
readonly SERVICE_USER="awg-web"
readonly SYSTEMD_UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
readonly SUDOERS_FILE="/etc/sudoers.d/amneziawg-web"
readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly DEFAULT_ENV_FILE="/etc/amneziawg-web/env.conf"
readonly DEFAULT_DATA_DIR="/var/lib/amneziawg-web"
readonly BINARY_NAME="amneziawg-web"

# Script location (for finding the service unit file relative to the repo)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ───────────────────────────────────────────────────────────────────

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
ENV_FILE="${DEFAULT_ENV_FILE}"
DATA_DIR="${DEFAULT_DATA_DIR}"
BINARY_SRC=""
SOURCE_DIR=""
INSTALL_RUST=false

FORCE="false"
RESTART_MODE=""          # "" = auto-detect, "yes" = always, "no" = never
REFRESH_UNIT="false"

# ── Output helpers ─────────────────────────────────────────────────────────────

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }

info()  { printf '[INFO]  %s\n' "$*"; }
warn()  { yellow "[WARN]  $*" >&2; }
die()   { red    "[ERROR] $*" >&2; exit 1; }

# Adjust ReadOnlyPaths and ProtectHome in the installed service unit to match
# the configured AWG_CONFIG_DIR (mirrors the same function in the installer).
adjust_unit_hardening() {
    local unit_file="$1"
    local config_dir="$2"

    [[ -f "${unit_file}" ]] || return 0

    # Normalize: strip trailing slashes for consistent comparison
    config_dir="${config_dir%/}"

    # 1. Update ReadOnlyPaths to include the actual config directory
    if grep -q '^ReadOnlyPaths=' "${unit_file}" 2>/dev/null; then
        local current_ro
        current_ro="$(grep '^ReadOnlyPaths=' "${unit_file}" | head -1 | cut -d= -f2-)"
        current_ro="${current_ro%/}"
        if [[ "${config_dir}" != "${current_ro}" ]] \
                && [[ "${config_dir}" != "${current_ro}/"* ]]; then
            sed -i "s|^ReadOnlyPaths=.*|ReadOnlyPaths=${config_dir}|" "${unit_file}"
            info "Updated ReadOnlyPaths to ${config_dir}"
        fi
    fi

    # 2. If the config directory lives under /home, relax ProtectHome
    case "${config_dir}" in
        /home|/home/*)
            if grep -q '^ProtectHome=yes' "${unit_file}" 2>/dev/null; then
                sed -i 's|^ProtectHome=yes|ProtectHome=read-only|' "${unit_file}"
                info "Changed ProtectHome to read-only (config dir is under /home)."
            fi
            ;;
    esac
}

# ── Usage ──────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: sudo $0 [--binary PATH | --source-dir DIR] [options]

Upgrade the amneziawg-web management panel binary.

Preserves: env/config file, data directory, service user, systemd unit.

Binary source (choose one):
  --binary PATH        Path to the replacement binary
  --source-dir DIR     Build from source in DIR (Rust crate directory).
                       If neither is given, auto-detects from repo layout.
  --install-rust       Install the Rust toolchain via rustup if cargo is
                       not found (source-build mode only).

Options:
  --install-dir DIR    Binary install directory  (default: ${DEFAULT_INSTALL_DIR})
  --env-file FILE      Env/config file path      (default: ${DEFAULT_ENV_FILE})
  --data-dir DIR       Data directory            (default: ${DEFAULT_DATA_DIR})
  --restart            Always restart service after upgrade
  --no-restart         Never restart service after upgrade
  --refresh-unit       Reinstall systemd unit from repository copy
  --force              Skip confirmation prompts
  --non-interactive    Alias for --force; suitable for CI/automation
  --help               Show this help

Default restart behavior:
  If the service was active before upgrade, it is restarted automatically.
  If the service was inactive, it is left inactive unless --restart is given.

Examples:
  # Upgrade from source (recommended)
  sudo $0 --source-dir ./amneziawg-web

  # Upgrade with pre-built binary
  sudo $0 --binary ./target/release/amneziawg-web

  # CI/automation upgrade, always restart
  sudo $0 --source-dir ./amneziawg-web --force --restart

  # Upgrade and refresh the systemd unit file
  sudo $0 --binary ./amneziawg-web --refresh-unit --force

EOF
}

# ── Argument parsing ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)             BINARY_SRC="$2"; shift 2 ;;
        --source-dir)         SOURCE_DIR="$2"; shift 2 ;;
        --install-rust)       INSTALL_RUST="true"; shift ;;
        --install-dir)        INSTALL_DIR="$2"; shift 2 ;;
        --env-file)           ENV_FILE="$2"; shift 2 ;;
        --data-dir)           DATA_DIR="$2"; shift 2 ;;
        --restart)            RESTART_MODE="yes"; shift ;;
        --no-restart)         RESTART_MODE="no"; shift ;;
        --refresh-unit)       REFRESH_UNIT="true"; shift ;;
        --force)              FORCE="true"; shift ;;
        --non-interactive)    FORCE="true"; shift ;;
        --help|-h)            usage; exit 0 ;;
        *) die "Unknown option: $1  (use --help for usage)" ;;
    esac
done

# --binary and --source-dir are mutually exclusive
if [[ -n "${BINARY_SRC}" ]] && [[ -n "${SOURCE_DIR}" ]]; then
    die "--binary and --source-dir are mutually exclusive.
Use --binary to provide a pre-built binary, or --source-dir to build from source."
fi

# ── Root check ─────────────────────────────────────────────────────────────────

if [[ "$(id -u)" -ne 0 ]]; then
    die "This script must be run as root (e.g. sudo $0)"
fi

# ── Source-build support ───────────────────────────────────────────────────────

# Ensure the Rust toolchain (cargo) is available.
ensure_rust_toolchain() {
    if command -v cargo &>/dev/null; then
        info "Rust toolchain found: $(cargo --version 2>/dev/null || echo 'unknown')"
        return 0
    fi

    if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
        export PATH="${HOME}/.cargo/bin:${PATH}"
        info "Rust toolchain found: $(cargo --version 2>/dev/null || echo 'unknown')"
        return 0
    fi

    if [[ "${INSTALL_RUST}" != "true" ]]; then
        die "Rust toolchain (cargo) is required to build from source but was not found.
Install Rust with:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
Or re-run with --install-rust to install automatically."
    fi

    info "Installing Rust toolchain via rustup..."
    if ! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>&1; then
        die "Failed to install Rust toolchain via rustup."
    fi

    if [[ -f "${HOME}/.cargo/env" ]]; then
        # shellcheck source=/dev/null
        . "${HOME}/.cargo/env"
    fi
    export PATH="${HOME}/.cargo/bin:${PATH}"

    if ! command -v cargo &>/dev/null; then
        die "Rust toolchain installation succeeded but cargo is still not in PATH."
    fi
    info "Rust toolchain installed: $(cargo --version 2>/dev/null || echo 'unknown')"
}

# Auto-detect source directory from repo layout.
detect_source_dir() {
    if [[ -n "${SOURCE_DIR}" ]]; then
        return 0
    fi
    local candidate="${SCRIPT_DIR}/.."
    if [[ -f "${candidate}/Cargo.toml" ]]; then
        SOURCE_DIR="$(cd "${candidate}" && pwd)"
    fi
}

# Build from source. Sets BINARY_SRC on success.
build_from_source() {
    info "Building from source..."

    if [[ ! -d "${SOURCE_DIR}" ]]; then
        die "Source directory does not exist: ${SOURCE_DIR}"
    fi

    if [[ ! -f "${SOURCE_DIR}/Cargo.toml" ]]; then
        die "No Cargo.toml found in source directory: ${SOURCE_DIR}
Expected the amneziawg-web Rust crate directory."
    fi

    ensure_rust_toolchain

    info "Building in: ${SOURCE_DIR}"
    info "Running: cargo build --release --locked"

    if ! (cd "${SOURCE_DIR}" && cargo build --release --locked); then
        die "Build failed. Check the output above for errors."
    fi

    local built_binary="${SOURCE_DIR}/target/release/amneziawg-web"
    if [[ ! -f "${built_binary}" ]]; then
        die "Build completed but binary not found at: ${built_binary}"
    fi

    BINARY_SRC="${built_binary}"
    if [[ ! -x "${BINARY_SRC}" ]]; then
        chmod +x "${BINARY_SRC}"
    fi
    info "Built binary: ${BINARY_SRC}"
}

# ── Resolve binary source ─────────────────────────────────────────────────────

# If --source-dir was given or auto-detected, build from source.
# Otherwise, require --binary.
if [[ -z "${BINARY_SRC}" ]]; then
    if [[ -z "${SOURCE_DIR}" ]]; then
        detect_source_dir
    fi

    if [[ -n "${SOURCE_DIR}" ]]; then
        build_from_source
    else
        die "Missing required flag: --binary PATH or --source-dir DIR
Usage: sudo $0 --source-dir ./amneziawg-web
       sudo $0 --binary ./target/release/amneziawg-web"
    fi
fi

# ── Validation ─────────────────────────────────────────────────────────────────

if [[ ! -f "${BINARY_SRC}" ]]; then
    die "Source binary not found: ${BINARY_SRC}"
fi

if [[ ! -x "${BINARY_SRC}" ]]; then
    die "Source binary is not executable: ${BINARY_SRC}
Run: chmod +x ${BINARY_SRC}"
fi

# Verify destination directory exists
if [[ ! -d "${INSTALL_DIR}" ]]; then
    die "Install directory does not exist: ${INSTALL_DIR}
Has the web panel been installed? Run amneziawg-web-install.sh first."
fi

# Verify existing binary is present (upgrade requires a prior install)
DEST_BINARY="${INSTALL_DIR}/${BINARY_NAME}"
if [[ ! -f "${DEST_BINARY}" ]]; then
    die "Existing binary not found at: ${DEST_BINARY}
Has the web panel been installed? Run amneziawg-web-install.sh first."
fi

# Validate refresh-unit: check the repo unit file exists
UNIT_SRC="${SCRIPT_DIR}/../packaging/amneziawg-web.service"
if [[ "${REFRESH_UNIT}" == "true" ]] && [[ ! -f "${UNIT_SRC}" ]]; then
    die "Unit file not found in repository: ${UNIT_SRC}
Make sure you cloned the full repository."
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

# ── Service state detection ────────────────────────────────────────────────────

detect_service_state() {
    SERVICE_WAS_ACTIVE="false"

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        SERVICE_WAS_ACTIVE="true"
    fi
}

# Decide whether to restart after upgrade
should_restart() {
    case "${RESTART_MODE}" in
        yes) return 0 ;;
        no)  return 1 ;;
        *)
            # Auto: restart only if the service was active before
            if [[ "${SERVICE_WAS_ACTIVE}" == "true" ]]; then
                return 0
            fi
            return 1
            ;;
    esac
}

# ── Summary / plan ─────────────────────────────────────────────────────────────

print_plan() {
    local restart_label
    if should_restart; then
        restart_label="yes"
    else
        restart_label="no"
    fi

    printf '\n'
    printf '=== amneziawg-web upgrade plan ===\n'
    printf '\n'
    printf 'Will REPLACE:\n'
    printf '  Binary:       %s  ←  %s\n' "${DEST_BINARY}" "${BINARY_SRC}"
    printf '\n'
    printf 'Service:\n'
    printf '  Status:       %s\n' "$(if [[ "${SERVICE_WAS_ACTIVE}" == "true" ]]; then echo "active"; else echo "inactive"; fi)"
    printf '  Restart:      %s\n' "${restart_label}"
    if [[ "${REFRESH_UNIT}" == "true" ]]; then
        printf '  Refresh unit: yes (%s)\n' "${UNIT_SRC}"
    fi
    printf '\n'
    printf 'Will PRESERVE:\n'
    printf '  Env/config:   %s\n' "${ENV_FILE}"
    printf '  Data dir:     %s\n' "${DATA_DIR}"
    printf '  Systemd unit: %s%s\n' "${SYSTEMD_UNIT_DEST}" \
        "$(if [[ "${REFRESH_UNIT}" == "true" ]]; then echo "  [will be refreshed]"; fi)"
    printf '\n'
}

# ── Main upgrade ───────────────────────────────────────────────────────────────

main() {
    detect_service_state

    print_plan

    if ! confirm "Proceed with upgrade?" "false"; then
        info "Upgrade cancelled."
        exit 0
    fi

    # 1. Stop service if it was active (clean shutdown before binary swap)
    if [[ "${SERVICE_WAS_ACTIVE}" == "true" ]]; then
        info "Stopping service..."
        systemctl stop "${SERVICE_NAME}" && info "Service stopped: ${SERVICE_NAME}" || \
            warn "Could not stop ${SERVICE_NAME} (may already be stopped)"
    else
        info "Service not active; skipping stop."
    fi

    # 2. Replace binary using safe temp-file + move approach
    info "Replacing binary..."
    local tmp_dest="${DEST_BINARY}.upgrade-tmp"
    # Remove any stale temp file from a previous failed upgrade
    rm -f -- "${tmp_dest}"

    # Copy to temp file in the same directory (same filesystem for atomic mv)
    if ! cp -- "${BINARY_SRC}" "${tmp_dest}"; then
        die "Failed to copy binary to: ${tmp_dest}"
    fi
    chmod 0755 "${tmp_dest}"

    # Atomic move: rename in the same directory
    if ! mv -f -- "${tmp_dest}" "${DEST_BINARY}"; then
        rm -f -- "${tmp_dest}"
        die "Failed to move upgraded binary to: ${DEST_BINARY}"
    fi
    info "Replaced binary: ${DEST_BINARY}"

    # 3. Ensure the sudoers drop-in is up-to-date.
    #    Always rewrite so that upgrades from older versions pick up the
    #    additional `awg syncconf` / `awg-quick strip` and install-script rules.
    local rule_awg="${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/awg show all dump, /usr/bin/awg set * peer * remove, /usr/bin/awg syncconf * /dev/stdin, /usr/bin/awg-quick strip *"
    local rule_install="${SERVICE_USER} ALL=(root) NOPASSWD: /usr/local/bin/amneziawg-install.sh --add-client *, /usr/local/bin/amneziawg-install.sh --remove-client *, /usr/local/bin/amneziawg-install.sh --list-clients"
    info "Installing/updating sudoers drop-in: ${SUDOERS_FILE}"
    mkdir -p "$(dirname "${SUDOERS_FILE}")"
    printf '# Allow amneziawg-web service to manage AWG state and peers.\n' \
        > "${SUDOERS_FILE}"
    printf '# Installed by amneziawg-web-upgrade.sh – do not edit manually.\n' \
        >> "${SUDOERS_FILE}"
    printf '%s\n' "${rule_awg}" >> "${SUDOERS_FILE}"
    printf '# Allow amneziawg-web to manage clients via the install script.\n' \
        >> "${SUDOERS_FILE}"
    printf '%s\n' "${rule_install}" >> "${SUDOERS_FILE}"
    chmod 0440 "${SUDOERS_FILE}"
    chown root:root "${SUDOERS_FILE}"
    if command -v visudo &>/dev/null; then
        if visudo -cf "${SUDOERS_FILE}" &>/dev/null; then
            info "Sudoers file validated: ${SUDOERS_FILE}"
        else
            warn "visudo validation failed for ${SUDOERS_FILE}."
            warn "Removing broken sudoers file to protect system integrity."
            rm -f "${SUDOERS_FILE}"
            die "Sudoers file syntax check failed. This should not happen with the default rule.
Please report this issue."
        fi
    fi

    # 4. Optional: refresh systemd unit file
    if [[ "${REFRESH_UNIT}" == "true" ]]; then
        info "Refreshing systemd unit..."

        # Install the unit file with EnvironmentFile directive enabled
        local tmp_unit="${SYSTEMD_UNIT_DEST}.upgrade-tmp"
        if ! cp -- "${UNIT_SRC}" "${tmp_unit}"; then
            rm -f -- "${tmp_unit}"
            die "Failed to copy unit file to: ${tmp_unit}"
        fi

        # Enable the EnvironmentFile line (same as installer does)
        if [[ -f "${ENV_FILE}" ]]; then
            sed -i "s|^#EnvironmentFile=.*|EnvironmentFile=${ENV_FILE}|" "${tmp_unit}" 2>/dev/null || true
        fi

        mv -f -- "${tmp_unit}" "${SYSTEMD_UNIT_DEST}"
        info "Refreshed unit file: ${SYSTEMD_UNIT_DEST}"

        # Adjust ReadOnlyPaths / ProtectHome for the configured config directory.
        # Read AWG_CONFIG_DIR from the env file if it exists.
        local awg_config_dir=""
        if [[ -f "${ENV_FILE}" ]]; then
            awg_config_dir="$(grep '^AWG_CONFIG_DIR=' "${ENV_FILE}" 2>/dev/null | cut -d= -f2- || true)"
            # Strip surrounding quotes (single or double) in case the value was quoted
            awg_config_dir="${awg_config_dir#\"}"
            awg_config_dir="${awg_config_dir%\"}"
            awg_config_dir="${awg_config_dir#\'}"
            awg_config_dir="${awg_config_dir%\'}"
        fi
        if [[ -n "${awg_config_dir}" ]]; then
            adjust_unit_hardening "${SYSTEMD_UNIT_DEST}" "${awg_config_dir}"
        fi

        systemctl daemon-reload
        info "Reloaded systemd daemon"
    fi

    # 5. Restart or start service based on policy
    if should_restart; then
        info "Restarting service..."
        systemctl restart "${SERVICE_NAME}" && info "Service restarted: ${SERVICE_NAME}" || \
            warn "Could not restart ${SERVICE_NAME}"
    else
        info "Service not restarted (was inactive; use --restart to force)."
    fi

    printf '\n'
    green "=== amneziawg-web upgrade complete ==="
    printf '\n'
    info "Config preserved: ${ENV_FILE}"
    info "Data preserved:   ${DATA_DIR}"
    if should_restart; then
        info "Service status:   restarted"
    else
        info "Service status:   not restarted (use: sudo systemctl start ${SERVICE_NAME})"
    fi
}

main "$@"
