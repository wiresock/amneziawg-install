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
readonly DEFAULT_AWG_INSTALL_SCRIPT="/usr/local/bin/amneziawg-install.sh"
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

validate_awg_config_dir() {
    local dir_path_raw="$1"
    local dir_path
    local resolved_path

    # Reject empty or non-absolute paths.
    if [[ -z "${dir_path_raw}" ]]; then
        warn "AWG_CONFIG_DIR is empty; skipping automatic ownership/permission changes."
        return 1
    fi
    if [[ "${dir_path_raw}" != /* ]]; then
        warn "AWG_CONFIG_DIR '${dir_path_raw}' is not an absolute path; skipping automatic ownership/permission changes."
        return 1
    fi

    # Reject paths containing whitespace or control characters — they break
    # systemd unit ReadWritePaths= directives and sudoers entries.
    if [[ "${dir_path_raw}" =~ [[:space:][:cntrl:]] ]]; then
        warn "AWG_CONFIG_DIR '${dir_path_raw}' contains whitespace or control characters; rejecting."
        return 1
    fi

    # Normalize: strip trailing slashes (but keep "/" as-is).
    dir_path="${dir_path_raw%/}"
    if [[ -z "${dir_path}" ]]; then
        dir_path="/"
    fi

    # Reject paths that contain symlink components (TOCTOU defense: a symlink
    # target could change between validation and the subsequent chown/chmod).
    local check_path="${dir_path}"
    while [[ "${check_path}" != "/" && "${check_path}" != "." ]]; do
        if [[ -L "${check_path}" ]]; then
            warn "AWG_CONFIG_DIR '${dir_path_raw}' contains a symbolic link at '${check_path}'; skipping automatic ownership/permission changes."
            return 1
        fi
        check_path="$(dirname "${check_path}")"
    done

    # Try to resolve the real path to canonicalize and catch any remaining
    # indirection (e.g. /foo/../etc).
    resolved_path="${dir_path}"
    if command -v realpath >/dev/null 2>&1; then
        local resolved_tmp
        if resolved_tmp="$(realpath -m -- "${dir_path}" 2>/dev/null)"; then
            resolved_path="${resolved_tmp}"
        fi
    elif command -v readlink >/dev/null 2>&1; then
        local resolved_tmp
        if resolved_tmp="$(readlink -f -- "${dir_path}" 2>/dev/null)"; then
            resolved_path="${resolved_tmp}"
        fi
    fi
    dir_path="${resolved_path}"

    # Reject sensitive system directories that should never have their
    # ownership changed to the service user.  In addition to exact matches,
    # block any path under sensitive prefixes unless it falls within an
    # explicitly allowed subtree (e.g. /etc/amnezia/amneziawg/*).
    case "${dir_path}" in
        "/"|"/home"|"/tmp")
            warn "AWG_CONFIG_DIR '${dir_path}' is a sensitive system path; skipping automatic ownership/permission changes. Please adjust it manually if needed."
            return 1
            ;;
        /etc/amnezia/amneziawg/*)
            # Allowed subtree — fall through to return 0
            ;;
        /etc|/etc/*)
            warn "AWG_CONFIG_DIR '${dir_path}' is under /etc (only /etc/amnezia/amneziawg/* is allowed); skipping automatic ownership/permission changes."
            return 1
            ;;
        /var/lib/amneziawg-web/*)
            # Allowed subtree — fall through to return 0
            ;;
        /var|/var/*)
            warn "AWG_CONFIG_DIR '${dir_path}' is under /var (only /var/lib/amneziawg-web/* is allowed); skipping automatic ownership/permission changes."
            return 1
            ;;
        /sys|/sys/*|/proc|/proc/*|/dev|/dev/*|/boot|/boot/*|/run|/run/*|/lib|/lib/*|/lib64|/lib64/*|/bin|/bin/*|/sbin|/sbin/*|/usr|/usr/*|/opt|/opt/*)
            warn "AWG_CONFIG_DIR '${dir_path}' is a sensitive system path; skipping automatic ownership/permission changes. Please adjust it manually if needed."
            return 1
            ;;
    esac

    return 0
}

# Check whether a script file is safe to embed in a sudoers rule:
# - must be a regular file (not a symlink)
# - must be executable
# - must be owned by root:root
# - must not be group or world-writable
# Returns 0 (safe) or 1 (unsafe).
is_script_safe_for_sudoers() {
    local script_path="$1"

    if [[ ! -f "${script_path}" ]] || [[ -L "${script_path}" ]]; then
        return 1
    fi
    if [[ ! -x "${script_path}" ]]; then
        return 1
    fi

    local owner_uid owner_gid mode
    owner_uid="$(stat -c '%u' "${script_path}" 2>/dev/null || echo "")"
    owner_gid="$(stat -c '%g' "${script_path}" 2>/dev/null || echo "")"
    mode="$(stat -c '%a' "${script_path}" 2>/dev/null || echo "")"
    if [[ -z "${owner_uid}" ]] || [[ -z "${owner_gid}" ]] || [[ -z "${mode}" ]]; then
        return 1
    fi
    if [[ ! "${mode}" =~ ^[0-7]{3,4}$ ]]; then
        return 1
    fi

    # Require root ownership and no group/other write bits.
    if [[ "${owner_uid}" != "0" ]] || [[ "${owner_gid}" != "0" ]]; then
        return 1
    fi
    local mode_octal
    mode_octal=$((8#${mode}))
    if (( (mode_octal & 8#022) != 0 )); then
        return 1
    fi

    return 0
}

# Validate that the install script path points to amneziawg-install.sh in a
# trusted root-controlled directory.  Returns 0 on success, 1 on failure.
validate_awg_install_script_path_policy() {
    local script_path="$1"
    local script_name script_dir
    script_name="$(basename "${script_path}")"
    script_dir="$(dirname "${script_path}")"

    if [[ "${script_name}" != "amneziawg-install.sh" ]]; then
        return 1
    fi

    case "${script_dir}" in
        /usr/local/bin|/usr/bin|/opt/amneziawg-web/bin)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Full validation of install script path for sudoers embedding:
# checks policy (trusted directory, correct filename) and, if the directory
# exists, verifies root ownership and no group/other-writable permissions.
# Returns 0 on success, 1 on failure.
validate_awg_install_script_path() {
    local script_path="$1"
    local script_dir
    script_dir="$(dirname "${script_path}")"

    if ! validate_awg_install_script_path_policy "${script_path}"; then
        return 1
    fi

    if [[ -d "${script_dir}" ]]; then
        local dir_uid dir_gid dir_mode
        dir_uid="$(stat -c '%u' "${script_dir}" 2>/dev/null || echo "")"
        dir_gid="$(stat -c '%g' "${script_dir}" 2>/dev/null || echo "")"
        dir_mode="$(stat -c '%a' "${script_dir}" 2>/dev/null || echo "")"
        if [[ -z "${dir_uid}" ]] || [[ -z "${dir_gid}" ]] || [[ -z "${dir_mode}" ]]; then
            return 1
        fi
        if [[ ! "${dir_mode}" =~ ^[0-7]{3,4}$ ]]; then
            return 1
        fi

        if [[ "${dir_uid}" != "0" ]] || [[ "${dir_gid}" != "0" ]]; then
            return 1
        fi
        local dir_mode_octal
        dir_mode_octal=$((8#${dir_mode}))
        if (( (dir_mode_octal & 8#022) != 0 )); then
            return 1
        fi
    fi

    return 0
}

# Adjust ReadWritePaths and ProtectHome in the installed service unit to match
# the configured AWG_CONFIG_DIR (mirrors the same function in the installer).
adjust_unit_hardening() {
    local unit_file="$1"
    local config_dir="$2"

    [[ -f "${unit_file}" ]] || return 0

    # Normalize: resolve symlinks and strip trailing slashes so the case
    # checks match the actual filesystem location.
    local resolved
    if resolved="$(readlink -f -- "${config_dir}" 2>/dev/null)"; then
        config_dir="${resolved}"
    fi
    config_dir="${config_dir%/}"

    # 1. Update ReadWritePaths for the AWG config directory.
    #    Also handle legacy ReadOnlyPaths left over from older installs.
    #    The server config root (/etc/amnezia/amneziawg) must always remain in
    #    ReadWritePaths because direct client creation appends peer blocks to
    #    /etc/amnezia/amneziawg/*.conf.  If AWG_CONFIG_DIR is outside that tree,
    #    a separate ReadWritePaths entry is added to cover both paths.
    local etc_dir="/etc/amnezia/amneziawg"

    if grep -q '^ReadOnlyPaths=' "${unit_file}" 2>/dev/null; then
        # Upgrade: replace ReadOnlyPaths with ReadWritePaths.
        if [[ "${config_dir}" == "${etc_dir}" ]] \
                || [[ "${config_dir}" == "${etc_dir}/"* ]]; then
            sed -i "s|^ReadOnlyPaths=.*|ReadWritePaths=${etc_dir}|" "${unit_file}"
        else
            # Replace the legacy line, then append an extra ReadWritePaths line.
            sed -i "s|^ReadOnlyPaths=.*|ReadWritePaths=${etc_dir}|" "${unit_file}"
            sed -i "/^ReadWritePaths=${etc_dir//\//\\/}\$/a ReadWritePaths=${config_dir}" "${unit_file}"
        fi
        info "Replaced ReadOnlyPaths with ReadWritePaths (${etc_dir}, ${config_dir})"
    elif grep -q '^ReadWritePaths=' "${unit_file}" 2>/dev/null; then
        # Scan existing non-DATA_DIR ReadWritePaths entries.
        local data_base="${DATA_DIR%/}"
        local has_etc_dir=false
        local has_config_dir=false

        while IFS=: read -r _ln line; do
            local val="${line#ReadWritePaths=}"
            val="${val%/}"
            if [[ "${val}" == "${data_base}" ]] || [[ "${val}" == "${data_base}/"* ]]; then
                continue
            fi
            if [[ "${val}" == "${etc_dir}" ]] || [[ "${etc_dir}" == "${val}/"* ]]; then
                has_etc_dir=true
            fi
            if [[ "${val}" == "${config_dir}" ]] || [[ "${config_dir}" == "${val}/"* ]]; then
                has_config_dir=true
            fi
        done < <(grep -n '^ReadWritePaths=' "${unit_file}")

        if ! ${has_etc_dir}; then
            local data_linenum=""
            data_linenum=$(grep -n -F "ReadWritePaths=${data_base}" "${unit_file}" | head -1 | cut -d: -f1 || true)
            if [[ -n "${data_linenum}" ]]; then
                sed -i "${data_linenum}i\\ReadWritePaths=${etc_dir}" "${unit_file}"
            else
                local last_rw
                last_rw=$(grep -n '^ReadWritePaths=' "${unit_file}" | tail -1 | cut -d: -f1)
                sed -i "${last_rw}a\\ReadWritePaths=${etc_dir}" "${unit_file}"
            fi
            info "Added ReadWritePaths=${etc_dir}"
        fi

        if ! ${has_config_dir}; then
            local data_linenum2=""
            data_linenum2=$(grep -n -F "ReadWritePaths=${data_base}" "${unit_file}" | head -1 | cut -d: -f1 || true)
            if [[ -n "${data_linenum2}" ]]; then
                sed -i "${data_linenum2}i\\ReadWritePaths=${config_dir}" "${unit_file}"
            else
                local last_rw2
                last_rw2=$(grep -n '^ReadWritePaths=' "${unit_file}" | tail -1 | cut -d: -f1)
                sed -i "${last_rw2}a\\ReadWritePaths=${config_dir}" "${unit_file}"
            fi
            info "Added ReadWritePaths=${config_dir}"
        fi
    fi

    # 2. Make ProtectHome deterministic based on the current config_dir:
    #    - For /home or /root paths: relax to read-only so the service can read configs.
    #    - For all other paths: ensure ProtectHome=yes for maximum sandboxing.
    case "${config_dir}" in
        /root|/root/*|/home|/home/*)
            if grep -q '^ProtectHome=yes' "${unit_file}" 2>/dev/null; then
                sed -i 's|^ProtectHome=yes|ProtectHome=read-only|' "${unit_file}"
                info "Changed ProtectHome to read-only (config dir is under /home or /root)."
            fi
            ;;
        *)
            if grep -q '^ProtectHome=read-only' "${unit_file}" 2>/dev/null; then
                sed -i 's|^ProtectHome=read-only|ProtectHome=yes|' "${unit_file}"
                info "Restored ProtectHome to yes (config dir is not under /home or /root)."
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
Has the web panel been installed? Run: sudo ./amneziawg-web.sh install"
fi

# Verify existing binary is present (upgrade requires a prior install)
DEST_BINARY="${INSTALL_DIR}/${BINARY_NAME}"
if [[ ! -f "${DEST_BINARY}" ]]; then
    die "Existing binary not found at: ${DEST_BINARY}
Has the web panel been installed? Run: sudo ./amneziawg-web.sh install"
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

    # Determine the install script path for sudoers.
    # We use grep instead of sourcing the env file to avoid triggering
    # `set -u` errors from other variables (e.g. $argon2id in password hashes).
    # Precedence:
    #   1. AWG_INSTALL_SCRIPT environment variable (if set)
    #   2. AWG_INSTALL_SCRIPT from the env file (if present)
    local rule_awg="${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/awg show all dump, /usr/bin/awg set * peer * remove, /usr/bin/awg syncconf * /dev/stdin, /usr/bin/awg-quick strip *"
    # Direct client lifecycle in native Rust: read params/server config and
    # rewrite or append peer blocks.
    local rule_direct="${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/cat -- /etc/amnezia/amneziawg/params, /usr/bin/cat -- /etc/amnezia/amneziawg/*.conf, /usr/bin/tee -- /etc/amnezia/amneziawg/*.conf, /usr/bin/tee -a -- /etc/amnezia/amneziawg/*.conf"
    info "Installing/updating sudoers drop-in: ${SUDOERS_FILE}"
    mkdir -p "$(dirname "${SUDOERS_FILE}")"
    printf '# Allow amneziawg-web service to manage AWG state and peers.\n' \
        > "${SUDOERS_FILE}"
    printf '# Installed by amneziawg-web-upgrade.sh – do not edit manually.\n' \
        >> "${SUDOERS_FILE}"
    printf '%s\n' "${rule_awg}" >> "${SUDOERS_FILE}"
    printf '# Allow amneziawg-web to manage clients directly in Rust (read/rewrite config).\n' \
        >> "${SUDOERS_FILE}"
    printf '%s\n' "${rule_direct}" >> "${SUDOERS_FILE}"
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

    # 3b. Ensure AWG_CONFIG_DIR is writable by the service user.
    #     Direct client creation writes config files into AWG_CONFIG_DIR, so
    #     the directory must exist and be owned by the service user. Older
    #     installs may have left it root-owned; fix that here.
    local awg_config_dir_upgrade=""
    if [[ -f "${ENV_FILE}" ]]; then
        awg_config_dir_upgrade="$(grep '^AWG_CONFIG_DIR=' "${ENV_FILE}" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
        awg_config_dir_upgrade="${awg_config_dir_upgrade#\"}"
        awg_config_dir_upgrade="${awg_config_dir_upgrade%\"}"
        awg_config_dir_upgrade="${awg_config_dir_upgrade#\'}"
        awg_config_dir_upgrade="${awg_config_dir_upgrade%\'}"
    fi
    # Fall back to the default clients directory used by the installer.
    awg_config_dir_upgrade="${awg_config_dir_upgrade:-/etc/amnezia/amneziawg/clients}"

    # Reject paths containing whitespace or control characters early.  These
    # break systemd ReadWritePaths= directives and sudoers entries.
    if [[ "${awg_config_dir_upgrade}" =~ [[:space:][:cntrl:]] ]]; then
        warn "AWG_CONFIG_DIR '${awg_config_dir_upgrade}' contains whitespace or control characters; skipping config-dir adjustments."
        awg_config_dir_upgrade=""
    fi

    if [[ -n "${awg_config_dir_upgrade}" ]] && validate_awg_config_dir "${awg_config_dir_upgrade}"; then
        if [[ -d "${awg_config_dir_upgrade}" ]]; then
            chown "${SERVICE_USER}:${SERVICE_USER}" "${awg_config_dir_upgrade}" 2>/dev/null \
                && info "Set ownership of ${awg_config_dir_upgrade} to ${SERVICE_USER}." \
                || warn "Could not change ownership of ${awg_config_dir_upgrade}. Direct client creation may fail."
            chmod 0700 "${awg_config_dir_upgrade}" 2>/dev/null \
                && info "Set permissions of ${awg_config_dir_upgrade} to 0700." \
                || warn "Could not change permissions of ${awg_config_dir_upgrade}. Direct client creation may fail."
            # Ensure existing client config files are owned by the service user
            # so they are readable after the directory ownership change.
            if compgen -G "${awg_config_dir_upgrade}/*.conf" > /dev/null 2>&1; then
                chown "${SERVICE_USER}:${SERVICE_USER}" "${awg_config_dir_upgrade}"/*.conf 2>/dev/null \
                    && info "Adjusted ownership of existing client configs in ${awg_config_dir_upgrade} to ${SERVICE_USER}." \
                    || warn "Could not change ownership of existing client configs in ${awg_config_dir_upgrade}. They may not be readable by ${SERVICE_USER}."
            fi
        else
            mkdir -p "${awg_config_dir_upgrade}" 2>/dev/null \
                && chown "${SERVICE_USER}:${SERVICE_USER}" "${awg_config_dir_upgrade}" \
                && chmod 0700 "${awg_config_dir_upgrade}" \
                && info "Created config directory: ${awg_config_dir_upgrade}" \
                || warn "Could not create ${awg_config_dir_upgrade}. Direct client creation may fail until the directory is created with correct ownership."
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

        # Adjust ReadWritePaths / ProtectHome for the configured config directory.
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
            # Reject paths with whitespace/control chars before writing into
            # the systemd unit file (ReadWritePaths= is whitespace-delimited).
            if [[ "${awg_config_dir}" =~ [[:space:][:cntrl:]] ]]; then
                warn "AWG_CONFIG_DIR '${awg_config_dir}' contains whitespace or control characters; skipping unit hardening."
            else
                adjust_unit_hardening "${SYSTEMD_UNIT_DEST}" "${awg_config_dir}"
            fi
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
