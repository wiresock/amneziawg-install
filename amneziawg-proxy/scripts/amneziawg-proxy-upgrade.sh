#!/usr/bin/env bash
# amneziawg-proxy-upgrade.sh
# Companion upgrade script for the amneziawg-proxy UDP obfuscation proxy.
#
# Usage:
#   sudo ./amneziawg-proxy-upgrade.sh --source-dir ./amneziawg-proxy
#   sudo ./amneziawg-proxy-upgrade.sh --binary ./target/release/amneziawg-proxy
#   sudo ./amneziawg-proxy-upgrade.sh --help
#
# Default behavior:
#   - builds from source (--source-dir) or uses a supplied binary
#   - infers existing install/config/data paths from the systemd unit
#   - replaces only the installed proxy binary
#   - restarts the service if it was active before the upgrade
#   - PRESERVES: proxy.toml, AWG config, data directory, systemd unit
#
# Optional flags:
#   --restart          force-restart the service after upgrade (even if inactive)
#   --no-restart       skip restarting the service after upgrade
#   --refresh-unit     reinstall the systemd unit template from the repository
#   --install-rust     install Rust toolchain via rustup if missing (source mode)
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

# -- Constants ----------------------------------------------------------------

readonly SERVICE_NAME="amneziawg-proxy"
readonly SYSTEMD_UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly DEFAULT_CONFIG_FILE="/etc/amneziawg-proxy/proxy.toml"
readonly DEFAULT_DATA_DIR="/var/lib/amneziawg-proxy"
readonly BINARY_NAME="amneziawg-proxy"

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# -- Defaults -----------------------------------------------------------------

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
CONFIG_FILE="${DEFAULT_CONFIG_FILE}"
DATA_DIR="${DEFAULT_DATA_DIR}"
BINARY_SRC=""
SOURCE_DIR=""
INSTALL_RUST=false

FORCE=false
RESTART_MODE=""          # "" = auto-detect, "yes" = always, "no" = never
REFRESH_UNIT=false

INSTALL_DIR_SET=false
CONFIG_FILE_SET=false
DATA_DIR_SET=false

# -- Output helpers ------------------------------------------------------------

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }

info() { printf '[INFO]  %s\n' "$*"; }
warn() { yellow "[WARN]  $*" >&2; }
die()  { red "[ERROR] $*" >&2; exit 1; }

require_bash_43() {
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
        die "Bash 4.3 or newer is required."
    fi
}

# -- Usage ---------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo $0 [--binary PATH | --binary-src PATH | --source-dir DIR] [options]

Upgrade the amneziawg-proxy binary.

Preserves: proxy.toml, AWG configuration, data directory, and systemd unit.

Binary source (choose one):
  --binary PATH        Path to the replacement binary
  --binary-src PATH    Alias for --binary
  --source-dir DIR     Build from source in DIR (Rust crate directory).
                       If neither is given, auto-detects from repo layout.
  --install-rust       Install the Rust toolchain via rustup if cargo is
                       not found (source-build mode only).

Options:
  --install-dir DIR    Binary install directory  (default: inferred or ${DEFAULT_INSTALL_DIR})
  --config-file FILE   Proxy config file path    (default: inferred or ${DEFAULT_CONFIG_FILE})
  --data-dir DIR       Service working directory (default: inferred or ${DEFAULT_DATA_DIR})
  --restart            Always restart service after upgrade
  --no-restart         Never restart service after upgrade
  --refresh-unit       Reinstall systemd unit from repository template
  --force              Skip confirmation prompts
  --non-interactive    Alias for --force; suitable for CI/automation
  --help               Show this help

Default restart behavior:
  If the service was active before upgrade, it is restarted automatically.
  If the service was inactive, it is left inactive unless --restart is given.

Examples:
  sudo $0 --source-dir ./amneziawg-proxy
  sudo $0 --binary ./target/release/amneziawg-proxy
  sudo $0 --source-dir ./amneziawg-proxy --force --restart
  sudo $0 --binary ./amneziawg-proxy --refresh-unit --force

EOF
}

# -- Argument parsing ----------------------------------------------------------

require_value() {
    local opt="$1"
    local value="${2:-}"
    if [[ -z "${value}" ]]; then
        die "Missing value for ${opt}"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --binary|--binary-src)
                require_value "$1" "${2:-}"
                BINARY_SRC="$2"; shift 2 ;;
            --source-dir)
                require_value "$1" "${2:-}"
                SOURCE_DIR="$2"; shift 2 ;;
            --install-rust)
                INSTALL_RUST=true; shift ;;
            --install-dir)
                require_value "$1" "${2:-}"
                INSTALL_DIR="$2"; INSTALL_DIR_SET=true; shift 2 ;;
            --config-file)
                require_value "$1" "${2:-}"
                CONFIG_FILE="$2"; CONFIG_FILE_SET=true; shift 2 ;;
            --data-dir)
                require_value "$1" "${2:-}"
                DATA_DIR="$2"; DATA_DIR_SET=true; shift 2 ;;
            --restart)
                RESTART_MODE="yes"; shift ;;
            --no-restart)
                RESTART_MODE="no"; shift ;;
            --refresh-unit)
                REFRESH_UNIT=true; shift ;;
            --force|--non-interactive)
                FORCE=true; shift ;;
            --help|-h)
                usage; exit 0 ;;
            *)
                die "Unknown option: $1 (use --help for usage)" ;;
        esac
    done

    if [[ -n "${BINARY_SRC}" ]] && [[ -n "${SOURCE_DIR}" ]]; then
        die "--binary/--binary-src and --source-dir are mutually exclusive."
    fi
}

# -- Existing install discovery ------------------------------------------------

strip_quotes() {
    local value="$1"
    if [[ "${value}" == \"*\" ]]; then
        value="${value#\"}"
        value="${value%\"}"
    elif [[ "${value}" == \'*\' ]]; then
        value="${value#\'}"
        value="${value%\'}"
    fi
    printf '%s' "${value}"
}

read_existing_unit_paths() {
    if [[ ! -f "${SYSTEMD_UNIT_DEST}" ]]; then
        return 0
    fi

    local exec_start payload bin_path cfg_path _rest
    exec_start="$(grep -m1 '^ExecStart=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null || true)"
    if [[ -n "${exec_start}" ]]; then
        payload="${exec_start#ExecStart=}"
        payload="${payload#-}"
        read -r bin_path cfg_path _rest <<< "${payload}"
        bin_path="$(strip_quotes "${bin_path:-}")"
        cfg_path="$(strip_quotes "${cfg_path:-}")"

        if [[ -n "${bin_path}" && "$(basename -- "${bin_path}")" == "${BINARY_NAME}" ]]; then
            if [[ "${INSTALL_DIR_SET}" != "true" ]]; then
                INSTALL_DIR="$(dirname -- "${bin_path}")"
            fi
        fi

        if [[ -n "${cfg_path}" && "${cfg_path}" == /* && "${CONFIG_FILE_SET}" != "true" ]]; then
            CONFIG_FILE="${cfg_path}"
        fi
    fi

    local working_dir
    working_dir="$(grep -m1 '^WorkingDirectory=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null || true)"
    if [[ -n "${working_dir}" && "${DATA_DIR_SET}" != "true" ]]; then
        working_dir="${working_dir#WorkingDirectory=}"
        working_dir="$(strip_quotes "${working_dir}")"
        if [[ -n "${working_dir}" && "${working_dir}" == /* ]]; then
            DATA_DIR="${working_dir}"
        fi
    fi
}

DEST_BINARY="${INSTALL_DIR}/${BINARY_NAME}"
CONFIG_DIR="$(dirname -- "${CONFIG_FILE}")"
UNIT_SRC="${SCRIPT_DIR}/../packaging/${SERVICE_NAME}.service"

# -- Source-build support ------------------------------------------------------

ensure_rust_toolchain() {
    local home_dir="${HOME:-/root}"

    if command -v cargo >/dev/null 2>&1; then
        info "Rust toolchain found: $(cargo --version 2>/dev/null || echo 'unknown')"
        return 0
    fi

    if [[ -x "${home_dir}/.cargo/bin/cargo" ]]; then
        export PATH="${home_dir}/.cargo/bin:${PATH}"
        info "Rust toolchain found: $(cargo --version 2>/dev/null || echo 'unknown')"
        return 0
    fi

    if [[ "${INSTALL_RUST}" != "true" ]]; then
        die "Rust toolchain (cargo) is required to build from source but was not found.
Install Rust with:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
Or re-run with --install-rust to install automatically."
    fi

    if ! command -v curl >/dev/null 2>&1; then
        die "Automatic Rust installation requires curl, but curl was not found.
Install curl (e.g. apt-get install curl), or install Rust manually and re-run."
    fi

    if [[ -z "${SSL_CERT_FILE:-}" && -z "${SSL_CERT_DIR:-}" ]] \
        && [[ ! -f /etc/ssl/certs/ca-certificates.crt ]] \
        && [[ ! -f /etc/pki/tls/certs/ca-bundle.crt ]] \
        && [[ ! -f /etc/ssl/ca-bundle.pem ]] \
        && [[ ! -f /etc/pki/tls/cacert.pem ]] \
        && [[ ! -f /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ]] \
        && [[ ! -d /etc/ssl/certs ]]; then
        die "Automatic Rust installation requires CA certificates for HTTPS downloads, but none were found.
Install the ca-certificates package, or install Rust manually and re-run."
    fi

    if [[ -z "${HOME:-}" ]]; then
        export HOME="${home_dir}"
    fi

    info "Installing Rust toolchain via rustup..."
    if ! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable; then
        die "Failed to install Rust toolchain via rustup."
    fi

    if [[ -f "${home_dir}/.cargo/env" ]]; then
        # shellcheck source=/dev/null
        . "${home_dir}/.cargo/env"
    fi
    export PATH="${home_dir}/.cargo/bin:${PATH}"

    if ! command -v cargo >/dev/null 2>&1; then
        die "Rust toolchain installation succeeded but cargo is still not in PATH."
    fi
    info "Rust toolchain installed: $(cargo --version 2>/dev/null || echo 'unknown')"
}

detect_source_dir() {
    if [[ -n "${SOURCE_DIR}" ]]; then
        return 0
    fi

    local candidate="${SCRIPT_DIR}/.."
    if [[ -f "${candidate}/Cargo.toml" ]]; then
        SOURCE_DIR="$(CDPATH='' cd -- "${candidate}" && pwd -P)"
    fi
}

build_from_source() {
    info "Building amneziawg-proxy from source..."

    if [[ ! -d "${SOURCE_DIR}" ]]; then
        die "Source directory does not exist: ${SOURCE_DIR}"
    fi

    if [[ ! -f "${SOURCE_DIR}/Cargo.toml" ]]; then
        die "No Cargo.toml found in source directory: ${SOURCE_DIR}
Expected the amneziawg-proxy Rust crate directory."
    fi

    warn "Source builds run cargo as root. Cargo build scripts and proc-macros execute code from the source tree."
    if ! confirm "Only continue if you trust this source tree. Build as root?" "false"; then
        die "Source build cancelled. Build the binary as an unprivileged user and re-run with --binary PATH."
    fi

    ensure_rust_toolchain

    info "Building in: ${SOURCE_DIR}"
    info "Running: cargo build --release --locked"

    if ! (cd "${SOURCE_DIR}" && cargo build --release --locked); then
        die "Build failed. Check the output above for errors.
Ensure build dependencies are installed (gcc, pkg-config, libssl-dev or equivalent)."
    fi

    local built_binary="${SOURCE_DIR}/target/release/${BINARY_NAME}"
    if [[ ! -f "${built_binary}" ]]; then
        die "Build completed but binary not found at: ${built_binary}"
    fi

    BINARY_SRC="${built_binary}"
    if [[ ! -x "${BINARY_SRC}" ]]; then
        chmod +x -- "${BINARY_SRC}"
    fi
    info "Built binary: ${BINARY_SRC}"
}

# -- Confirmation / service helpers -------------------------------------------

confirm() {
    local msg="$1"
    local default="${2:-false}"
    if [[ "${FORCE}" == "true" ]]; then
        return 0
    fi

    local prompt reply
    if [[ "${default}" == "true" ]]; then
        prompt="${msg} [Y/n] "
    else
        prompt="${msg} [y/N] "
    fi
    if ! read -r -p "${prompt}" reply; then
        reply="${default}"
    fi
    reply="${reply:-${default}}"
    case "${reply}" in
        [Yy]*|true) return 0 ;;
        *) return 1 ;;
    esac
}

detect_service_state() {
    SERVICE_WAS_ACTIVE=false
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        SERVICE_WAS_ACTIVE=true
    fi
}

should_restart() {
    case "${RESTART_MODE}" in
        yes) return 0 ;;
        no)  return 1 ;;
        *)
            [[ "${SERVICE_WAS_ACTIVE}" == "true" ]]
            ;;
    esac
}

escape_sed_replacement() {
    printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}

path_in_array() {
    local needle="$1"
    shift

    local needle_path="${needle#-}"
    local path
    for path in "$@"; do
        if [[ "${path#-}" == "${needle_path}" ]]; then
            return 0
        fi
    done
    return 1
}

append_unique_paths_from_unit_line() {
    local unit_line="$1"
    local -n target_paths="$2"

    local path
    local -a parsed_paths=()
    read -r -a parsed_paths <<< "${unit_line#*=}"
    for path in "${parsed_paths[@]}"; do
        if [[ -n "${path}" ]] && ! path_in_array "${path}" "${target_paths[@]}"; then
            target_paths+=("${path}")
        fi
    done
}

validate_config_file_path() {
    if [[ -z "${CONFIG_FILE}" ]]; then
        die "--config-file must not be empty."
    fi
    if [[ "${CONFIG_FILE}" == */ ]]; then
        die "--config-file must be a file path, not a directory-style path ending with '/': ${CONFIG_FILE}."
    fi
    if [[ -d "${CONFIG_FILE}" ]]; then
        die "--config-file must not point to an existing directory: ${CONFIG_FILE}."
    fi
}

path_has_dot_components() {
    local path="$1"
    [[ "${path}" == "." || "${path}" == ".." || "${path}" == */./* || "${path}" == */../* || "${path}" == */. || "${path}" == */.. ]]
}

validate_upgrade_paths() {
    local path_var path_val flag_name
    for path_var in INSTALL_DIR CONFIG_FILE DATA_DIR; do
        path_val="${!path_var}"
        flag_name="--${path_var//_/-}"
        flag_name="${flag_name,,}"

        if [[ -z "${path_val}" ]]; then
            die "${flag_name} must not be empty."
        fi
        if [[ "${path_val}" != /* ]]; then
            die "${flag_name} must be an absolute path (got: '${path_val}')."
        fi
        if [[ "${path_val}" == *$'\n'* || "${path_val}" == *$'\r'* || "${path_val}" == *[[:space:]]* ]]; then
            die "${flag_name} must not contain whitespace or newlines."
        fi
        if path_has_dot_components "${path_val}"; then
            die "${flag_name} must not contain '.' or '..' path components (got: '${path_val}')."
        fi
    done

    validate_config_file_path
}

refresh_unit_file() {
    info "Refreshing systemd unit..."

    local tmp_unit="${SYSTEMD_UNIT_DEST}.upgrade-tmp"
    rm -f -- "${tmp_unit}"
    if ! cp -- "${UNIT_SRC}" "${tmp_unit}"; then
        rm -f -- "${tmp_unit}"
        die "Failed to copy unit file to: ${tmp_unit}"
    fi

    local -a read_only_paths=("-/etc/amnezia" "${CONFIG_DIR}")
    local -a read_write_paths=("${DATA_DIR}")
    if [[ -f "${SYSTEMD_UNIT_DEST}" ]]; then
        local existing_ro existing_rw
        existing_ro="$(grep -m1 '^ReadOnlyPaths=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null || true)"
        if [[ -n "${existing_ro}" ]]; then
            append_unique_paths_from_unit_line "${existing_ro}" read_only_paths
        fi

        existing_rw="$(grep -m1 '^ReadWritePaths=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null || true)"
        if [[ -n "${existing_rw}" ]]; then
            append_unique_paths_from_unit_line "${existing_rw}" read_write_paths
        fi
    fi

    local esc_exec esc_workdir esc_ro esc_rw
    esc_exec="$(escape_sed_replacement "ExecStart=${DEST_BINARY} ${CONFIG_FILE}")"
    esc_workdir="$(escape_sed_replacement "WorkingDirectory=${DATA_DIR}")"
    esc_ro="$(escape_sed_replacement "ReadOnlyPaths=${read_only_paths[*]}")"
    esc_rw="$(escape_sed_replacement "ReadWritePaths=${read_write_paths[*]}")"

    sed -i "s|^ExecStart=.*|${esc_exec}|" "${tmp_unit}"
    sed -i "s|^WorkingDirectory=.*|${esc_workdir}|" "${tmp_unit}"
    sed -i "s|^ReadOnlyPaths=.*|${esc_ro}|" "${tmp_unit}"
    sed -i "s|^ReadWritePaths=.*|${esc_rw}|" "${tmp_unit}"

    mv -f -- "${tmp_unit}" "${SYSTEMD_UNIT_DEST}"
    chmod 0644 "${SYSTEMD_UNIT_DEST}"
    systemctl daemon-reload
    info "Refreshed unit file: ${SYSTEMD_UNIT_DEST}"
}

adjust_status_sharing_permissions() {
    if [[ -d "${DATA_DIR}" ]] && getent group awg-web >/dev/null 2>&1; then
        chown root:awg-web "${DATA_DIR}" 2>/dev/null \
            && chmod 2750 "${DATA_DIR}" 2>/dev/null \
            && info "Configured ${DATA_DIR} for status sharing with awg-web." \
            || warn "Could not adjust ${DATA_DIR} permissions; web proxy sessions may be unavailable."
    fi
}

prepare_upgrade() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This script must be run as root (e.g. sudo $0)"
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemd is required but 'systemctl' was not found."
    fi

    read_existing_unit_paths

    DEST_BINARY="${INSTALL_DIR}/${BINARY_NAME}"
    validate_upgrade_paths
    CONFIG_DIR="$(dirname -- "${CONFIG_FILE}")"
    UNIT_SRC="${SCRIPT_DIR}/../packaging/${SERVICE_NAME}.service"

    if [[ -z "${BINARY_SRC}" ]]; then
        if [[ -z "${SOURCE_DIR}" ]]; then
            detect_source_dir
        fi

        if [[ -n "${SOURCE_DIR}" ]]; then
            build_from_source
        else
            die "Missing required flag: --binary PATH, --binary-src PATH, or --source-dir DIR
Usage: sudo $0 --source-dir ./amneziawg-proxy
       sudo $0 --binary ./target/release/amneziawg-proxy"
        fi
    fi

    if [[ ! -f "${BINARY_SRC}" ]]; then
        die "Source binary not found: ${BINARY_SRC}"
    fi

    if [[ ! -x "${BINARY_SRC}" ]]; then
        chmod +x -- "${BINARY_SRC}" || die "Source binary is not executable: ${BINARY_SRC}"
    fi

    if [[ ! -d "${INSTALL_DIR}" ]]; then
        die "Install directory does not exist: ${INSTALL_DIR}
Has the proxy been installed? Run: sudo ./amneziawg-proxy.sh"
    fi

    if [[ ! -f "${DEST_BINARY}" ]]; then
        die "Existing binary not found at: ${DEST_BINARY}
Has the proxy been installed? Run: sudo ./amneziawg-proxy.sh"
    fi

    if [[ ! -f "${SYSTEMD_UNIT_DEST}" ]]; then
        die "Systemd unit not found at: ${SYSTEMD_UNIT_DEST}
Has the proxy been installed? Run: sudo ./amneziawg-proxy.sh"
    fi

    if [[ "${REFRESH_UNIT}" == "true" && ! -f "${UNIT_SRC}" ]]; then
        die "Unit file not found in repository: ${UNIT_SRC}
Make sure you cloned the full repository."
    fi
}

print_plan() {
    local restart_label
    if should_restart; then
        restart_label="yes"
    else
        restart_label="no"
    fi

    printf '\n'
    printf '=== amneziawg-proxy upgrade plan ===\n'
    printf '\n'
    printf 'Will REPLACE:\n'
    printf '  Binary:       %s  <-  %s\n' "${DEST_BINARY}" "${BINARY_SRC}"
    printf '\n'
    printf 'Service:\n'
    printf '  Status:       %s\n' "$(if [[ "${SERVICE_WAS_ACTIVE}" == "true" ]]; then echo "active"; else echo "inactive"; fi)"
    printf '  Restart:      %s\n' "${restart_label}"
    if [[ "${REFRESH_UNIT}" == "true" ]]; then
        printf '  Refresh unit: yes (%s)\n' "${UNIT_SRC}"
    fi
    printf '\n'
    printf 'Will PRESERVE:\n'
    printf '  Proxy config: %s\n' "${CONFIG_FILE}"
    printf '  Data dir:     %s\n' "${DATA_DIR}"
    printf '  AWG config:   unchanged\n'
    printf '  Systemd unit: %s%s\n' "${SYSTEMD_UNIT_DEST}" \
        "$(if [[ "${REFRESH_UNIT}" == "true" ]]; then echo "  [will be refreshed]"; fi)"
    printf '\n'
}

# -- Main upgrade --------------------------------------------------------------

main() {
    parse_args "$@"
    require_bash_43
    prepare_upgrade
    detect_service_state
    print_plan

    if ! confirm "Proceed with upgrade?" "false"; then
        info "Upgrade cancelled."
        exit 0
    fi

    if [[ "${SERVICE_WAS_ACTIVE}" == "true" ]]; then
        info "Stopping service..."
        if systemctl stop "${SERVICE_NAME}"; then
            info "Service stopped: ${SERVICE_NAME}"
        elif systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
            die "Failed to stop ${SERVICE_NAME}; service is still active. Upgrade aborted before replacing the binary."
        else
            warn "Could not confirm a clean stop for ${SERVICE_NAME}, but it is no longer active."
        fi
    else
        info "Service not active; skipping stop."
    fi

    info "Replacing binary..."
    local tmp_dest="${DEST_BINARY}.upgrade-tmp"
    rm -f -- "${tmp_dest}"

    if ! cp -- "${BINARY_SRC}" "${tmp_dest}"; then
        die "Failed to copy binary to: ${tmp_dest}"
    fi
    chmod 0755 "${tmp_dest}"

    if ! mv -f -- "${tmp_dest}" "${DEST_BINARY}"; then
        rm -f -- "${tmp_dest}"
        die "Failed to move upgraded binary to: ${DEST_BINARY}"
    fi
    info "Replaced binary: ${DEST_BINARY}"

    if [[ "${REFRESH_UNIT}" == "true" ]]; then
        refresh_unit_file
    fi

    adjust_status_sharing_permissions

    if should_restart; then
        info "Restarting service..."
        if ! systemctl restart "${SERVICE_NAME}"; then
            die "Failed to restart ${SERVICE_NAME}. The binary was upgraded, but the service may be stopped.
Check service logs with: sudo journalctl -u ${SERVICE_NAME} -e"
        fi
        info "Service restarted: ${SERVICE_NAME}"
    elif [[ "${RESTART_MODE}" == "no" ]]; then
        info "Service not restarted (--no-restart requested; use: sudo systemctl start ${SERVICE_NAME})"
    else
        info "Service not restarted (was inactive; use --restart to force)."
    fi

    printf '\n'
    green "=== amneziawg-proxy upgrade complete ==="
    printf '\n'
    info "Proxy config preserved: ${CONFIG_FILE}"
    info "Data preserved:         ${DATA_DIR}"
    info "AWG config preserved:   unchanged"
    if should_restart; then
        info "Service status:         restarted"
    elif [[ "${RESTART_MODE}" == "no" ]]; then
        info "Service status:         not restarted (--no-restart requested; use: sudo systemctl start ${SERVICE_NAME})"
    else
        info "Service status:         not restarted (use: sudo systemctl start ${SERVICE_NAME})"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
