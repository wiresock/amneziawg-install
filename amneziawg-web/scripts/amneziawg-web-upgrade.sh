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
readonly DEFAULT_AWG_INSTALL_SCRIPT_DEST="/usr/local/bin/amneziawg-install.sh"
readonly PRIVILEGED_HELPER_NAME="amneziawg-web-privileged"
readonly PRIVILEGED_HELPER_DEST="/usr/local/libexec/${PRIVILEGED_HELPER_NAME}"
readonly BUILD_MIN_FREE_KB="2097152"

# Script location (for finding the service unit file relative to the repo)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=../../scripts/amneziawg-cargo-build.sh
. "${SCRIPT_DIR}/../../scripts/amneziawg-cargo-build.sh"

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

STAGED_BINARY=""
STAGED_AWG_INSTALL_SCRIPT=""
STAGED_HELPER=""
STAGED_SUDOERS=""
ROLLBACK_BINARY=""
ROLLBACK_AWG_INSTALL_SCRIPT=""
ROLLBACK_HELPER=""
ROLLBACK_SUDOERS=""
HAD_LIVE_BINARY="false"
HAD_LIVE_AWG_INSTALL_SCRIPT="false"
HAD_LIVE_HELPER="false"
HAD_LIVE_SUDOERS="false"
SERVICE_WAS_ACTIVE="false"
BINARY_COMMITTED="false"
AWG_INSTALL_SCRIPT_COMMITTED="false"
HELPER_COMMITTED="false"
SUDOERS_COMMITTED="false"
BINARY_RENAME_STARTED="false"
AWG_INSTALL_SCRIPT_RENAME_STARTED="false"
HELPER_RENAME_STARTED="false"
SUDOERS_RENAME_STARTED="false"
AWG_INSTALL_SCRIPT_DEST=""
AWG_INSTALL_SCRIPT_SRC=""
REFRESH_AWG_INSTALL_SCRIPT="false"
TRANSACTION_ACTIVE="false"
ACTIVATION_COMPLETE="false"
ROLLBACK_FAILED="false"

cleanup_staged_artifacts() {
    local exit_code=$?

    # Do not let a second signal interrupt recovery. A signal can arrive after
    # an atomic rename but before Bash updates the corresponding state flag;
    # refresh_commit_state resolves only that narrow window by checking that
    # the staged pathname disappeared after its rename was explicitly started.
    trap '' HUP INT TERM
    if [[ "${TRANSACTION_ACTIVE}" == "true" && "${ACTIVATION_COMPLETE}" != "true" ]]; then
        refresh_commit_state
        if [[ "${BINARY_COMMITTED}" == "true" || \
              "${AWG_INSTALL_SCRIPT_COMMITTED}" == "true" || \
              "${HELPER_COMMITTED}" == "true" || \
              "${SUDOERS_COMMITTED}" == "true" ]]; then
            if systemctl stop "${SERVICE_NAME}" 2>/dev/null; then
                if ! rollback_runtime_artifacts; then
                    ROLLBACK_FAILED="true"
                fi
            else
                warn "Could not stop ${SERVICE_NAME}; leaving rollback copies for manual recovery."
                ROLLBACK_FAILED="true"
            fi
        fi
        if [[ "${ROLLBACK_FAILED}" != "true" ]]; then
            TRANSACTION_ACTIVE="false"
        fi
        if [[ "${exit_code}" -eq 0 ]]; then
            exit_code=1
        fi
    fi

    if [[ -n "${STAGED_BINARY}" ]]; then
        rm -f -- "${STAGED_BINARY}" 2>/dev/null || true
    fi
    if [[ -n "${STAGED_AWG_INSTALL_SCRIPT}" ]]; then
        rm -f -- "${STAGED_AWG_INSTALL_SCRIPT}" 2>/dev/null || true
    fi
    if [[ -n "${STAGED_HELPER}" ]]; then
        rm -f -- "${STAGED_HELPER}" 2>/dev/null || true
    fi
    if [[ -n "${STAGED_SUDOERS}" ]]; then
        rm -f -- "${STAGED_SUDOERS}" 2>/dev/null || true
    fi
    if [[ -n "${ROLLBACK_BINARY}" ]] && \
            [[ "${ROLLBACK_FAILED}" != "true" || "${BINARY_COMMITTED}" != "true" ]]; then
        rm -f -- "${ROLLBACK_BINARY}" 2>/dev/null || true
        ROLLBACK_BINARY=""
    fi
    if [[ -n "${ROLLBACK_AWG_INSTALL_SCRIPT}" ]] && \
            [[ "${ROLLBACK_FAILED}" != "true" || "${AWG_INSTALL_SCRIPT_COMMITTED}" != "true" ]]; then
        rm -f -- "${ROLLBACK_AWG_INSTALL_SCRIPT}" 2>/dev/null || true
        ROLLBACK_AWG_INSTALL_SCRIPT=""
    fi
    if [[ -n "${ROLLBACK_HELPER}" ]] && \
            [[ "${ROLLBACK_FAILED}" != "true" || "${HELPER_COMMITTED}" != "true" ]]; then
        rm -f -- "${ROLLBACK_HELPER}" 2>/dev/null || true
        ROLLBACK_HELPER=""
    fi
    if [[ -n "${ROLLBACK_SUDOERS}" ]] && \
            [[ "${ROLLBACK_FAILED}" != "true" || "${SUDOERS_COMMITTED}" != "true" ]]; then
        rm -f -- "${ROLLBACK_SUDOERS}" 2>/dev/null || true
        ROLLBACK_SUDOERS=""
    fi

    if [[ "${exit_code}" -ne 0 ]] && \
            [[ "${SERVICE_WAS_ACTIVE}" == "true" ]] && \
            [[ "${ROLLBACK_FAILED}" != "true" ]]; then
        if systemctl start "${SERVICE_NAME}" && \
                systemctl is-active --quiet "${SERVICE_NAME}"; then
            info "Restored the previously active service after upgrade failure."
        else
            warn "Previous artifacts are intact, but ${SERVICE_NAME} could not be restarted."
        fi
    fi

    if [[ "${ROLLBACK_FAILED}" == "true" ]]; then
        report_retained_rollback_artifacts
    fi

    awg_cleanup_cargo_build
    return "${exit_code}"
}

trap cleanup_staged_artifacts EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
    local resolved_ok=0
    resolved_path="${dir_path}"
    if command -v realpath >/dev/null 2>&1; then
        local resolved_tmp
        if resolved_tmp="$(realpath -m -- "${dir_path}" 2>/dev/null)"; then
            resolved_path="${resolved_tmp}"
            resolved_ok=1
        fi
    elif command -v readlink >/dev/null 2>&1; then
        local resolved_tmp
        if resolved_tmp="$(readlink -f -- "${dir_path}" 2>/dev/null)"; then
            resolved_path="${resolved_tmp}"
            resolved_ok=1
        fi
    fi

    if [[ "${resolved_ok}" -ne 1 ]]; then
        if [[ "${dir_path}" == *"/../"* || "${dir_path}" == "../"* || "${dir_path}" == *"/.." || \
              "${dir_path}" == *"/./"*  || "${dir_path}" == "./"*  || "${dir_path}" == *"/." ]]; then
            warn "AWG_CONFIG_DIR '${dir_path_raw}' contains '.' or '..' segments; skipping automatic ownership/permission changes."
            return 1
        fi
    fi
    dir_path="${resolved_path}"

    # Reject sensitive system directories that should never have their
    # ownership changed to the service user.  In addition to exact matches,
    # block any path under sensitive prefixes unless it falls within an
    # explicitly allowed subtree (e.g. /etc/amnezia/amneziawg/*).
    case "${dir_path}" in
        "/"|"/home"|"/root"|"/tmp")
            warn "AWG_CONFIG_DIR '${dir_path}' is a sensitive system path; skipping automatic ownership/permission changes. Please adjust it manually if needed."
            return 1
            ;;
        /home/*|/root/*)
            warn "AWG_CONFIG_DIR '${dir_path}' is under a user home directory; skipping automatic ownership/permission changes. Please adjust it manually if needed."
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
    local config_dir_sed="${config_dir//\\/\\\\}"

    if grep -q '^ReadOnlyPaths=' "${unit_file}" 2>/dev/null; then
        # Upgrade: replace ReadOnlyPaths with ReadWritePaths.
        if [[ "${config_dir}" == "${etc_dir}" ]] \
                || [[ "${config_dir}" == "${etc_dir}/"* ]]; then
            sed -i "s|^ReadOnlyPaths=.*|ReadWritePaths=${etc_dir}|" "${unit_file}"
        else
            # Replace the legacy line, then append an extra ReadWritePaths line.
            sed -i "s|^ReadOnlyPaths=.*|ReadWritePaths=${etc_dir}|" "${unit_file}"
            sed -i "/^ReadWritePaths=${etc_dir//\//\\/}\$/a ReadWritePaths=${config_dir_sed}" "${unit_file}"
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
                sed -i "${data_linenum2}i\\ReadWritePaths=${config_dir_sed}" "${unit_file}"
            else
                local last_rw2
                last_rw2=$(grep -n '^ReadWritePaths=' "${unit_file}" | tail -1 | cut -d: -f1)
                sed -i "${last_rw2}a\\ReadWritePaths=${config_dir_sed}" "${unit_file}"
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

    if ! awg_prepare_cargo_build "${SOURCE_DIR}" "amneziawg-web" "${BUILD_MIN_FREE_KB}"; then
        die "No suitable build environment is available for amneziawg-web."
    fi

    info "Building in: ${SOURCE_DIR}"
    info "Running: cargo build --release --locked"

    if ! (cd "${SOURCE_DIR}" && cargo build --release --locked); then
        die "Build failed. Check the output above for errors."
    fi

    local built_binary
    built_binary="$(awg_cargo_release_binary "amneziawg-web")"
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

resolve_awg_install_script_refresh() {
    local marker_path
    local marker_managed="false"
    local resolved_path="${DEFAULT_AWG_INSTALL_SCRIPT_DEST}"
    local configured_path=""
    local script_dir=""
    local dir_uid="" dir_gid="" dir_mode="" dir_mode_octal=0

    marker_path="$(dirname "${ENV_FILE}")/installed-awg-script.path"

    # The root-owned marker is authoritative for the privileged helper. Older
    # installations may use a non-default allowlisted destination.
    if [[ -L "${marker_path}" ]] || \
            { [[ -e "${marker_path}" ]] && [[ ! -f "${marker_path}" ]]; }; then
        die "AWG lifecycle-script marker is not a safe regular file: ${marker_path}"
    fi
    if [[ -f "${marker_path}" && ! -L "${marker_path}" ]]; then
        marker_managed="true"
        resolved_path="$(head -n 1 "${marker_path}" 2>/dev/null || true)"
        if tail -n +2 "${marker_path}" 2>/dev/null | grep -q '[^[:space:]]'; then
            die "AWG lifecycle-script marker has unexpected trailing content: ${marker_path}"
        fi
    elif [[ -n "${AWG_INSTALL_SCRIPT:-}" ]]; then
        resolved_path="${AWG_INSTALL_SCRIPT}"
    elif [[ -f "${ENV_FILE}" ]]; then
        configured_path="$(grep -E '^AWG_INSTALL_SCRIPT=' "${ENV_FILE}" 2>/dev/null | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" || true)"
        if [[ -n "${configured_path}" ]]; then
            resolved_path="${configured_path}"
        fi
    fi

    AWG_INSTALL_SCRIPT_DEST="${resolved_path}"
    AWG_INSTALL_SCRIPT_SRC="${SCRIPT_DIR}/../../amneziawg-install.sh"

    # The installer deliberately leaves no marker when it preserves an
    # operator-managed script. Without that explicit ownership record, the
    # upgrader must not take ownership or overwrite the path, even when the
    # repository contains a newer lifecycle script.
    if [[ "${marker_managed}" != "true" ]]; then
        warn "No installer ownership marker found; preserving unmanaged AWG lifecycle script: ${AWG_INSTALL_SCRIPT_DEST}"
        warn "AWG protocol controls require an installer-managed lifecycle script; re-run the web installer with --force to replace and register it."
        REFRESH_AWG_INSTALL_SCRIPT="false"
        return 0
    fi

    if [[ "${resolved_path}" != /* ]] || [[ "${resolved_path}" =~ [[:space:],] ]]; then
        die "AWG lifecycle-script destination is invalid: ${resolved_path}"
    fi
    case "${resolved_path}" in
        /usr/local/bin/amneziawg-install.sh|/usr/bin/amneziawg-install.sh|\
        /opt/amneziawg-web/bin/amneziawg-install.sh)
            ;;
        *)
            die "AWG lifecycle-script destination is outside trusted locations: ${resolved_path}"
            ;;
    esac

    script_dir="$(dirname "${resolved_path}")"
    if [[ ! -d "${script_dir}" ]] || [[ -L "${script_dir}" ]]; then
        die "AWG lifecycle-script directory is missing or unsafe: ${script_dir}"
    fi
    dir_uid="$(stat -c '%u' "${script_dir}" 2>/dev/null || true)"
    dir_gid="$(stat -c '%g' "${script_dir}" 2>/dev/null || true)"
    dir_mode="$(stat -c '%a' "${script_dir}" 2>/dev/null || true)"
    if [[ "${dir_uid}" != "0" || "${dir_gid}" != "0" || ! "${dir_mode}" =~ ^[0-7]{3,4}$ ]]; then
        die "AWG lifecycle-script directory must be a root-owned trusted directory: ${script_dir}"
    fi
    dir_mode_octal=$((8#${dir_mode}))
    if (( (dir_mode_octal & 8#022) != 0 )); then
        die "AWG lifecycle-script directory must not be group or world-writable: ${script_dir}"
    fi
    if [[ -L "${resolved_path}" ]] || \
            { [[ -e "${resolved_path}" ]] && [[ ! -f "${resolved_path}" ]]; }; then
        die "AWG lifecycle-script destination is not a safe regular file: ${resolved_path}"
    fi

    if [[ -f "${AWG_INSTALL_SCRIPT_SRC}" && ! -L "${AWG_INSTALL_SCRIPT_SRC}" ]]; then
        REFRESH_AWG_INSTALL_SCRIPT="true"
        return 0
    fi

    # A standalone binary-only updater can still be used when the installed
    # lifecycle script already implements the protocol contract expected by
    # the refreshed helper. Fail before stopping the service otherwise.
    if [[ -x "${AWG_INSTALL_SCRIPT_DEST}" ]] && \
            grep -q -- '--protocol-status' "${AWG_INSTALL_SCRIPT_DEST}" && \
            grep -q -- '--enable-awg3' "${AWG_INSTALL_SCRIPT_DEST}" && \
            grep -q -- '--disable-awg3' "${AWG_INSTALL_SCRIPT_DEST}"; then
        warn "Repository lifecycle script is unavailable; preserving compatible installed script: ${AWG_INSTALL_SCRIPT_DEST}"
        REFRESH_AWG_INSTALL_SCRIPT="false"
        return 0
    fi

    die "Repository lifecycle script is required to upgrade this older installation: ${AWG_INSTALL_SCRIPT_SRC}"
}

resolve_awg_install_script_refresh

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
    if [[ "${REFRESH_AWG_INSTALL_SCRIPT}" == "true" ]]; then
        printf '  AWG script:   %s  ←  %s\n' "${AWG_INSTALL_SCRIPT_DEST}" "${AWG_INSTALL_SCRIPT_SRC}"
    fi
    printf '  Helper:       %s\n' "${PRIVILEGED_HELPER_DEST}"
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

stage_awg_install_script() {
    if [[ "${REFRESH_AWG_INSTALL_SCRIPT}" != "true" ]]; then
        return 0
    fi

    STAGED_AWG_INSTALL_SCRIPT="$(mktemp "${AWG_INSTALL_SCRIPT_DEST}.upgrade-tmp.XXXXXX")" \
        || die "Could not create temporary AWG lifecycle script"
    install -m 0755 -o root -g root -- \
        "${AWG_INSTALL_SCRIPT_SRC}" "${STAGED_AWG_INSTALL_SCRIPT}" \
        || die "Could not stage AWG lifecycle script"
    if ! /bin/bash -n "${STAGED_AWG_INSTALL_SCRIPT}"; then
        die "Staged AWG lifecycle script failed its Bash syntax check"
    fi
    for required_flag in --protocol-status --enable-awg3 --disable-awg3; do
        if ! grep -q -- "${required_flag}" "${STAGED_AWG_INSTALL_SCRIPT}"; then
            die "Staged AWG lifecycle script is missing required flag: ${required_flag}"
        fi
    done
    info "Staged AWG lifecycle script: ${AWG_INSTALL_SCRIPT_DEST}"
}

stage_privileged_helper() {
    local helper_src="${SCRIPT_DIR}/${PRIVILEGED_HELPER_NAME}"
    local helper_dir
    helper_dir="$(dirname "${PRIVILEGED_HELPER_DEST}")"

    if [[ ! -f "${helper_src}" ]] || [[ -L "${helper_src}" ]]; then
        die "Privileged helper source is missing or unsafe: ${helper_src}"
    fi
    if [[ -L "${helper_dir}" ]]; then
        die "Refusing to install privileged helper through symlinked directory: ${helper_dir}"
    fi
    if [[ -L "${PRIVILEGED_HELPER_DEST}" ]]; then
        die "Refusing to replace symlink at privileged helper path: ${PRIVILEGED_HELPER_DEST}"
    fi
    if [[ -e "${PRIVILEGED_HELPER_DEST}" ]] && [[ ! -f "${PRIVILEGED_HELPER_DEST}" ]]; then
        die "Privileged helper destination is not a regular file: ${PRIVILEGED_HELPER_DEST}"
    fi

    install -d -m 0755 -o root -g root -- "${helper_dir}"
    STAGED_HELPER="$(mktemp "${PRIVILEGED_HELPER_DEST}.tmp.XXXXXX")" \
        || die "Could not create temporary privileged helper"
    install -m 0755 -o root -g root -- "${helper_src}" "${STAGED_HELPER}" \
        || die "Could not stage privileged helper"
    if ! /bin/bash -n "${STAGED_HELPER}"; then
        die "Staged privileged helper failed its Bash syntax check"
    fi
    info "Staged privileged helper: ${PRIVILEGED_HELPER_DEST}"
}

stage_sudoers() {
    local rule="${SERVICE_USER} ALL=(root) NOPASSWD: ${PRIVILEGED_HELPER_DEST}"

    info "Staging sudoers drop-in: ${SUDOERS_FILE}"
    mkdir -p "$(dirname "${SUDOERS_FILE}")"
    STAGED_SUDOERS="$(mktemp "${SUDOERS_FILE}.tmp.XXXXXX")" \
        || die "Could not create temporary sudoers file"
    printf '# Allow amneziawg-web service to manage AWG state and peers.\n' \
        > "${STAGED_SUDOERS}"
    printf '# Installed by amneziawg-web-upgrade.sh – do not edit manually.\n' \
        >> "${STAGED_SUDOERS}"
    printf '%s\n' "${rule}" >> "${STAGED_SUDOERS}"
    chmod 0440 "${STAGED_SUDOERS}"
    chown root:root "${STAGED_SUDOERS}"

    if command -v visudo &>/dev/null; then
        local visudo_output=""
        if visudo_output="$(visudo -cf "${STAGED_SUDOERS}" 2>&1)"; then
            info "Staged sudoers rule validated: ${SUDOERS_FILE}"
        else
            warn "visudo validation failed for generated sudoers rule:"
            if [[ -n "${visudo_output}" ]]; then
                printf '%s\n' "${visudo_output}" >&2
            fi
            die "Sudoers file syntax check failed; the existing rule was preserved."
        fi
    else
        info "visudo not available; skipping syntax check."
    fi
}

stage_binary() {
    STAGED_BINARY="$(mktemp "${DEST_BINARY}.upgrade-tmp.XXXXXX")" \
        || die "Could not create temporary application binary"
    install -m 0755 -o root -g root -- "${BINARY_SRC}" "${STAGED_BINARY}" \
        || die "Could not stage upgraded binary"
    info "Staged upgraded binary: ${DEST_BINARY}"
}

stage_rollback_artifacts() {
    if [[ -L "${DEST_BINARY}" ]] || \
            { [[ -e "${DEST_BINARY}" ]] && [[ ! -f "${DEST_BINARY}" ]]; }; then
        die "Refusing to replace unsafe binary destination: ${DEST_BINARY}"
    fi
    if [[ -f "${DEST_BINARY}" ]]; then
        ROLLBACK_BINARY="$(mktemp "${DEST_BINARY}.rollback.XXXXXX")" \
            || die "Could not create application-binary rollback file"
        cp -a -- "${DEST_BINARY}" "${ROLLBACK_BINARY}" \
            || die "Could not back up the installed application binary"
        HAD_LIVE_BINARY="true"
    fi

    if [[ "${REFRESH_AWG_INSTALL_SCRIPT}" == "true" ]] && \
            [[ -f "${AWG_INSTALL_SCRIPT_DEST}" ]]; then
        ROLLBACK_AWG_INSTALL_SCRIPT="$(mktemp "${AWG_INSTALL_SCRIPT_DEST}.rollback.XXXXXX")" \
            || die "Could not create AWG lifecycle-script rollback file"
        cp -a -- "${AWG_INSTALL_SCRIPT_DEST}" "${ROLLBACK_AWG_INSTALL_SCRIPT}" \
            || die "Could not back up the installed AWG lifecycle script"
        HAD_LIVE_AWG_INSTALL_SCRIPT="true"
    fi

    if [[ -f "${PRIVILEGED_HELPER_DEST}" ]]; then
        ROLLBACK_HELPER="$(mktemp "${PRIVILEGED_HELPER_DEST}.rollback.XXXXXX")" \
            || die "Could not create privileged-helper rollback file"
        cp -a -- "${PRIVILEGED_HELPER_DEST}" "${ROLLBACK_HELPER}" \
            || die "Could not back up the installed privileged helper"
        HAD_LIVE_HELPER="true"
    fi

    if [[ -L "${SUDOERS_FILE}" ]] || \
            { [[ -e "${SUDOERS_FILE}" ]] && [[ ! -f "${SUDOERS_FILE}" ]]; }; then
        die "Refusing to replace unsafe sudoers destination: ${SUDOERS_FILE}"
    fi
    if [[ -f "${SUDOERS_FILE}" ]]; then
        ROLLBACK_SUDOERS="$(mktemp "${SUDOERS_FILE}.rollback.XXXXXX")" \
            || die "Could not create sudoers rollback file"
        cp -a -- "${SUDOERS_FILE}" "${ROLLBACK_SUDOERS}" \
            || die "Could not back up the installed sudoers drop-in"
        HAD_LIVE_SUDOERS="true"
    fi
}

rollback_runtime_artifacts() {
    local rollback_ok="true"

    # Restore authorization first so the old binary regains its original
    # command permissions before the transitional helper is removed.
    if [[ "${SUDOERS_COMMITTED}" == "true" ]]; then
        if [[ "${HAD_LIVE_SUDOERS}" == "true" ]]; then
            if mv -fT -- "${ROLLBACK_SUDOERS}" "${SUDOERS_FILE}"; then
                ROLLBACK_SUDOERS=""
                SUDOERS_COMMITTED="false"
            else
                rollback_ok="false"
            fi
        elif rm -f -- "${SUDOERS_FILE}"; then
            SUDOERS_COMMITTED="false"
        else
            rollback_ok="false"
        fi
    fi

    if [[ "${HELPER_COMMITTED}" == "true" ]]; then
        if [[ "${HAD_LIVE_HELPER}" == "true" ]]; then
            if mv -fT -- "${ROLLBACK_HELPER}" "${PRIVILEGED_HELPER_DEST}"; then
                ROLLBACK_HELPER=""
                HELPER_COMMITTED="false"
            else
                rollback_ok="false"
            fi
        elif rm -f -- "${PRIVILEGED_HELPER_DEST}"; then
            HELPER_COMMITTED="false"
        else
            rollback_ok="false"
        fi
    fi

    if [[ "${AWG_INSTALL_SCRIPT_COMMITTED}" == "true" ]]; then
        if [[ "${HAD_LIVE_AWG_INSTALL_SCRIPT}" == "true" ]]; then
            if mv -fT -- "${ROLLBACK_AWG_INSTALL_SCRIPT}" "${AWG_INSTALL_SCRIPT_DEST}"; then
                ROLLBACK_AWG_INSTALL_SCRIPT=""
                AWG_INSTALL_SCRIPT_COMMITTED="false"
            else
                rollback_ok="false"
            fi
        elif rm -f -- "${AWG_INSTALL_SCRIPT_DEST}"; then
            AWG_INSTALL_SCRIPT_COMMITTED="false"
        else
            rollback_ok="false"
        fi
    fi

    # Restore the old application last, after its matching authorization and
    # helper are back in place. Fresh-install-style destinations are removed.
    if [[ "${BINARY_COMMITTED}" == "true" ]]; then
        if [[ "${HAD_LIVE_BINARY}" == "true" ]]; then
            if mv -fT -- "${ROLLBACK_BINARY}" "${DEST_BINARY}"; then
                ROLLBACK_BINARY=""
                BINARY_COMMITTED="false"
            else
                rollback_ok="false"
            fi
        elif rm -f -- "${DEST_BINARY}"; then
            BINARY_COMMITTED="false"
        else
            rollback_ok="false"
        fi
    fi

    [[ "${rollback_ok}" == "true" ]]
}

refresh_commit_state() {
    if [[ "${AWG_INSTALL_SCRIPT_RENAME_STARTED}" == "true" ]] && \
            [[ -n "${STAGED_AWG_INSTALL_SCRIPT}" ]] && \
            [[ ! -e "${STAGED_AWG_INSTALL_SCRIPT}" ]] && \
            [[ -e "${AWG_INSTALL_SCRIPT_DEST}" ]]; then
        AWG_INSTALL_SCRIPT_COMMITTED="true"
    fi

    if [[ "${HELPER_RENAME_STARTED}" == "true" ]] && \
            [[ -n "${STAGED_HELPER}" ]] && [[ ! -e "${STAGED_HELPER}" ]] && \
            [[ -e "${PRIVILEGED_HELPER_DEST}" ]]; then
        HELPER_COMMITTED="true"
    fi

    if [[ "${SUDOERS_RENAME_STARTED}" == "true" ]] && \
            [[ -n "${STAGED_SUDOERS}" ]] && [[ ! -e "${STAGED_SUDOERS}" ]] && \
            [[ -e "${SUDOERS_FILE}" ]]; then
        SUDOERS_COMMITTED="true"
    fi

    if [[ "${BINARY_RENAME_STARTED}" == "true" ]] && \
            [[ -n "${STAGED_BINARY}" ]] && [[ ! -e "${STAGED_BINARY}" ]] && \
            [[ -e "${DEST_BINARY}" ]]; then
        BINARY_COMMITTED="true"
    fi
}

report_retained_rollback_artifacts() {
    if [[ -n "${ROLLBACK_BINARY}" ]] && [[ -e "${ROLLBACK_BINARY}" ]]; then
        warn "Retained application-binary recovery copy: ${ROLLBACK_BINARY}"
    fi
    if [[ -n "${ROLLBACK_HELPER}" ]] && [[ -e "${ROLLBACK_HELPER}" ]]; then
        warn "Retained helper recovery copy: ${ROLLBACK_HELPER}"
    fi
    if [[ -n "${ROLLBACK_AWG_INSTALL_SCRIPT}" ]] && \
            [[ -e "${ROLLBACK_AWG_INSTALL_SCRIPT}" ]]; then
        warn "Retained AWG lifecycle-script recovery copy: ${ROLLBACK_AWG_INSTALL_SCRIPT}"
    fi
    if [[ -n "${ROLLBACK_SUDOERS}" ]] && [[ -e "${ROLLBACK_SUDOERS}" ]]; then
        warn "Retained sudoers recovery copy: ${ROLLBACK_SUDOERS}"
    fi
}

abort_commit_with_rollback() {
    local reason="$1"

    die "${reason}; the previous runtime generation will be restored."
}

discard_rollback_artifacts() {
    if [[ -n "${ROLLBACK_BINARY}" ]]; then
        if rm -f -- "${ROLLBACK_BINARY}"; then
            ROLLBACK_BINARY=""
        else
            warn "Could not remove application-binary rollback file: ${ROLLBACK_BINARY}"
        fi
    fi
    if [[ -n "${ROLLBACK_HELPER}" ]]; then
        if rm -f -- "${ROLLBACK_HELPER}"; then
            ROLLBACK_HELPER=""
        else
            warn "Could not remove helper rollback file: ${ROLLBACK_HELPER}"
        fi
    fi
    if [[ -n "${ROLLBACK_AWG_INSTALL_SCRIPT}" ]]; then
        if rm -f -- "${ROLLBACK_AWG_INSTALL_SCRIPT}"; then
            ROLLBACK_AWG_INSTALL_SCRIPT=""
        else
            warn "Could not remove AWG lifecycle-script rollback file: ${ROLLBACK_AWG_INSTALL_SCRIPT}"
        fi
    fi
    if [[ -n "${ROLLBACK_SUDOERS}" ]]; then
        if rm -f -- "${ROLLBACK_SUDOERS}"; then
            ROLLBACK_SUDOERS=""
        else
            warn "Could not remove sudoers rollback file: ${ROLLBACK_SUDOERS}"
        fi
    fi
}

finalize_transaction() {
    ACTIVATION_COMPLETE="true"
    TRANSACTION_ACTIVE="false"
    discard_rollback_artifacts
}

commit_staged_artifacts() {
    TRANSACTION_ACTIVE="true"
    if [[ "${REFRESH_AWG_INSTALL_SCRIPT}" == "true" ]]; then
        AWG_INSTALL_SCRIPT_RENAME_STARTED="true"
        if ! mv -fT -- "${STAGED_AWG_INSTALL_SCRIPT}" "${AWG_INSTALL_SCRIPT_DEST}"; then
            abort_commit_with_rollback "Could not install staged AWG lifecycle script"
        fi
        AWG_INSTALL_SCRIPT_COMMITTED="true"
        AWG_INSTALL_SCRIPT_RENAME_STARTED="false"
        STAGED_AWG_INSTALL_SCRIPT=""
        info "Installed AWG lifecycle script: ${AWG_INSTALL_SCRIPT_DEST}"
    fi

    HELPER_RENAME_STARTED="true"
    if ! mv -fT -- "${STAGED_HELPER}" "${PRIVILEGED_HELPER_DEST}"; then
        abort_commit_with_rollback "Could not install staged privileged helper"
    fi
    HELPER_COMMITTED="true"
    HELPER_RENAME_STARTED="false"
    STAGED_HELPER=""
    info "Installed privileged helper: ${PRIVILEGED_HELPER_DEST}"

    SUDOERS_RENAME_STARTED="true"
    if ! mv -fT -- "${STAGED_SUDOERS}" "${SUDOERS_FILE}"; then
        abort_commit_with_rollback "Could not install staged sudoers drop-in"
    fi
    SUDOERS_COMMITTED="true"
    SUDOERS_RENAME_STARTED="false"
    STAGED_SUDOERS=""
    info "Installed sudoers drop-in: ${SUDOERS_FILE}"

    # Commit the application last so it never runs without the matching
    # helper and authorization rule already in place.
    BINARY_RENAME_STARTED="true"
    if ! mv -fT -- "${STAGED_BINARY}" "${DEST_BINARY}"; then
        abort_commit_with_rollback "Could not install staged application binary"
    fi
    BINARY_COMMITTED="true"
    BINARY_RENAME_STARTED="false"
    STAGED_BINARY=""
    info "Replaced binary: ${DEST_BINARY}"
}

# ── Main upgrade ───────────────────────────────────────────────────────────────

main() {
    detect_service_state

    print_plan

    if ! confirm "Proceed with upgrade?" "false"; then
        info "Upgrade cancelled."
        exit 0
    fi

    # 1. Validate and stage every replacement before stopping the service.
    #    Each temporary file is in its destination directory, so the final
    #    renames are atomic and any staging failure leaves the live install
    #    untouched.
    stage_privileged_helper
    stage_sudoers
    stage_binary
    stage_awg_install_script
    stage_rollback_artifacts

    # 2. Stop service if it was active (clean shutdown before artifact swap).
    if [[ "${SERVICE_WAS_ACTIVE}" == "true" ]]; then
        info "Stopping service..."
        if systemctl stop "${SERVICE_NAME}"; then
            info "Service stopped: ${SERVICE_NAME}"
        else
            die "Could not stop ${SERVICE_NAME}; staged artifacts were not installed."
        fi
    else
        info "Service not active; skipping stop."
    fi

    # 3. Commit the lifecycle script, helper, and sudoers first, then the
    #    matching application last.
    commit_staged_artifacts

    # 3a. Ensure AWG_CONFIG_DIR is writable by the service user.
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

    if [[ -f "${ENV_FILE}" ]] && ! grep -q '^AWG_PROXY_SESSIONS_FILE=' "${ENV_FILE}" 2>/dev/null; then
        {
            printf '\n'
            printf '# Proxy active-session status file (written by amneziawg-proxy)\n'
            printf 'AWG_PROXY_SESSIONS_FILE=/var/lib/amneziawg-proxy/sessions.json\n'
        } >>"${ENV_FILE}" && info "Added AWG_PROXY_SESSIONS_FILE to ${ENV_FILE}."
    fi

    if [[ -d /var/lib/amneziawg-proxy ]]; then
        chown root:"${SERVICE_USER}" /var/lib/amneziawg-proxy 2>/dev/null \
            && chmod 2750 /var/lib/amneziawg-proxy 2>/dev/null \
            && info "Configured /var/lib/amneziawg-proxy for proxy status sharing." \
            || warn "Could not adjust /var/lib/amneziawg-proxy permissions; proxy sessions may be unavailable."
    fi

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

        # Verify and (best-effort) remediate traversal permissions for parent
        # directories. Fixing only AWG_CONFIG_DIR itself is insufficient when
        # ancestors (e.g. /etc/amnezia/amneziawg) block execute/traverse.
        if command -v sudo >/dev/null 2>&1; then
            if ! sudo -u "${SERVICE_USER}" test -x "${awg_config_dir_upgrade}" 2>/dev/null; then
                warn "Service user '${SERVICE_USER}' cannot traverse '${awg_config_dir_upgrade}' – attempting parent-directory traversal fix."

                local current_dir="${awg_config_dir_upgrade}"
                while [[ -n "${current_dir}" && "${current_dir}" != "/" ]]; do
                    local parent_dir
                    parent_dir="$(dirname "${current_dir}")"
                    if [[ "${parent_dir}" == "${current_dir}" || "${parent_dir}" == "/" ]]; then
                        break
                    fi

                    if [[ -d "${parent_dir}" && ! -L "${parent_dir}" ]] \
                            && ! sudo -u "${SERVICE_USER}" test -x "${parent_dir}" 2>/dev/null; then
                        if command -v setfacl >/dev/null 2>&1; then
                            if setfacl -m "u:${SERVICE_USER}:x" "${parent_dir}" 2>/dev/null; then
                                info "Granted traverse ACL for ${SERVICE_USER} on ${parent_dir}."
                            else
                                warn "Failed to adjust ACL on ${parent_dir}."
                            fi
                        else
                            # Fallback without ACL support: only relax traversal on known-safe prefixes.
                            if [[ "${awg_config_dir_upgrade}" == /etc/amnezia/amneziawg* ]] && [[ "${parent_dir}" == /etc/amnezia/amneziawg* ]]; then
                                chmod o+x "${parent_dir}" 2>/dev/null \
                                    && info "Added traverse permission (o+x) on ${parent_dir} for service access." \
                                    || warn "Could not set o+x on ${parent_dir}."
                                warn "Consider installing ACL tools for a more targeted permission grant."
                            else
                                warn "Refusing to broaden permissions on ancestor directory '${parent_dir}' outside allowed prefix '/etc/amnezia/amneziawg*'."
                                warn "Install ACL tools (e.g. apt install acl) or adjust directory ownership/permissions so ${SERVICE_USER} can traverse ancestors of '${awg_config_dir_upgrade}'."
                            fi
                        fi
                    fi

                    current_dir="${parent_dir}"
                done

                if ! sudo -u "${SERVICE_USER}" test -x "${awg_config_dir_upgrade}" 2>/dev/null; then
                    warn "Service user '${SERVICE_USER}' may still be unable to traverse all parent directories of '${awg_config_dir_upgrade}'."
                    warn "Ensure each parent directory grants execute ('x') permission to '${SERVICE_USER}' or rerun installer filesystem setup."
                else
                    info "Traversal permissions for '${SERVICE_USER}' on '${awg_config_dir_upgrade}' and its parents look correct."
                fi
            fi
        else
            warn "Could not verify traversal permissions for '${SERVICE_USER}' (sudo not available)."
            warn "Ensure all parent directories of '${awg_config_dir_upgrade}' grant execute ('x') permission to '${SERVICE_USER}'."
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
        if systemctl restart "${SERVICE_NAME}"; then
            if systemctl is-active --quiet "${SERVICE_NAME}"; then
                info "Service restarted and active: ${SERVICE_NAME}"
                finalize_transaction
            else
                die "${SERVICE_NAME} restart returned success but the service is inactive."
            fi
        else
            die "Could not restart ${SERVICE_NAME}."
        fi
    else
        info "Service not restarted (was inactive; use --restart to force)."
        finalize_transaction
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
