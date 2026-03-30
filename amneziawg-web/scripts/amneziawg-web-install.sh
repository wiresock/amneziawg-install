#!/usr/bin/env bash
# amneziawg-web-install.sh
# Companion installer for the amneziawg-web management panel.
#
# Usage:
#   sudo ./amneziawg-web-install.sh              # interactive
#   sudo ./amneziawg-web-install.sh --help        # show options
#   sudo ./amneziawg-web-install.sh --non-interactive [options...]
#
# The installer:
#   1. Runs preflight checks (root, systemd, AWG binary, application binary)
#   2. Creates the service user and required directories
#   3. Installs the binary to /usr/local/bin
#   4. Writes /etc/amneziawg-web/env.conf
#   5. Installs and optionally enables the systemd service
#
# Dependencies: bash 4+, openssl, systemd, python3 (for Argon2 hash) or argon2 CLI
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

readonly SERVICE_NAME="amneziawg-web"
readonly SERVICE_USER="awg-web"
readonly SYSTEMD_UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
readonly SUDOERS_FILE="/etc/sudoers.d/amneziawg-web"

# Default paths
readonly DEFAULT_BINARY_SRC="./target/release/amneziawg-web"
readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly DEFAULT_DATA_DIR="/var/lib/amneziawg-web"
readonly DEFAULT_ENV_DIR="/etc/amneziawg-web"
readonly DEFAULT_ENV_FILE="/etc/amneziawg-web/env.conf"
readonly DEFAULT_AWG_CONFIG_DIR="/etc/amneziawg/clients"
readonly DEFAULT_LISTEN_HOST="127.0.0.1"
readonly DEFAULT_LISTEN_PORT="8080"
readonly DEFAULT_POLL_INTERVAL="30"
readonly DEFAULT_SESSION_TTL="86400"
readonly DEFAULT_USERNAME="admin"

# Script location (for finding the service unit file relative to the repo)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Logging ───────────────────────────────────────────────────────────────────

info()  { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
error() { printf "${RED}[✗]${NC} %s\n" "$*" >&2; }
die()   { error "$*"; exit 1; }
step()  { printf "\n${BOLD}${CYAN}==> %s${NC}\n" "$*"; }

# ── Configuration (populated by parse_args / interactive_setup) ───────────────

NON_INTERACTIVE=false
BINARY_SRC=""
SOURCE_DIR=""
INSTALL_RUST=false
INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
DATA_DIR="${DEFAULT_DATA_DIR}"
ENV_DIR="${DEFAULT_ENV_DIR}"
ENV_FILE="${DEFAULT_ENV_FILE}"
AWG_CONFIG_DIR="${DEFAULT_AWG_CONFIG_DIR}"
AWG_CONFIG_DIR_SET=false
AWG_DETECTED_HOME_DIR=""     # set by detect_awg_config_dir when configs are in a home dir
LISTEN_HOST="${DEFAULT_LISTEN_HOST}"
LISTEN_PORT="${DEFAULT_LISTEN_PORT}"
POLL_INTERVAL="${DEFAULT_POLL_INTERVAL}"
SESSION_TTL="${DEFAULT_SESSION_TTL}"
USERNAME="${DEFAULT_USERNAME}"
PASSWORD_HASH=""          # pre-hashed; takes precedence over PASSWORD
PASSWORD=""               # plaintext; only accepted interactively or with explicit flag
ENABLE_SERVICE=true
START_SERVICE=true
FORCE=false               # overwrite existing env.conf without prompt

# ── Usage ─────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
amneziawg-web installer

Usage:
  $0 [OPTIONS]

Binary source (choose one):
  --source-dir DIR          Build from source in DIR (Rust crate directory).
                            If neither --source-dir nor --binary-src is given,
                            the installer auto-detects the source directory
                            from the repository layout.
  --binary-src PATH         Path to a pre-built amneziawg-web binary.
                            Mutually exclusive with --source-dir.
  --install-rust            Install the Rust toolchain via rustup if cargo is
                            not found. Without this flag, a missing toolchain
                            is a fatal error.

Options:
  -h, --help                Show this help and exit
  --non-interactive         Run without prompts; fail if required values are missing
  --install-dir DIR         Directory to install the binary into
                            (default: ${DEFAULT_INSTALL_DIR})
  --data-dir DIR            Directory for the SQLite database
                            (default: ${DEFAULT_DATA_DIR})
  --env-file FILE           Path for the generated environment file
                            (default: ${DEFAULT_ENV_FILE})
  --config-dir DIR          AWG client config directory
                            (default: ${DEFAULT_AWG_CONFIG_DIR})
  --host HOST               Bind host (default: ${DEFAULT_LISTEN_HOST})
  --port PORT               Bind port (default: ${DEFAULT_LISTEN_PORT})
  --username NAME           Admin username (default: ${DEFAULT_USERNAME})
  --password-hash HASH      Argon2id PHC hash of the admin password
                            Generate with:
                              python3 -c "import argon2; print(argon2.PasswordHasher().hash('pw'))"
  --poll-interval SECS      Polling interval in seconds (default: ${DEFAULT_POLL_INTERVAL})
  --session-ttl SECS        Session lifetime in seconds (default: ${DEFAULT_SESSION_TTL})
  --no-enable               Do not enable the systemd service at boot
  --no-start                Do not start the systemd service immediately
  --force                   Overwrite existing env.conf without prompting

Examples:
  # Install from a repository checkout (recommended)
  sudo $0

  # Install from a repository checkout and auto-install Rust if needed
  sudo $0 --install-rust

  # Non-interactive source install
  sudo $0 \\
    --non-interactive \\
    --username admin \\
    --password-hash '\$argon2id\$v=19\$m=65536,t=3,p=4\$...'

  # Pre-built binary (advanced / CI)
  sudo $0 \\
    --non-interactive \\
    --binary-src ./target/release/amneziawg-web \\
    --username admin \\
    --password-hash '\$argon2id\$v=19\$...'
EOF
}

# ── Argument parsing ───────────────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage; exit 0 ;;
            --non-interactive)
                NON_INTERACTIVE=true; shift ;;
            --binary-src)
                BINARY_SRC="$2"; shift 2 ;;
            --source-dir)
                SOURCE_DIR="$2"; shift 2 ;;
            --install-rust)
                INSTALL_RUST=true; shift ;;
            --install-dir)
                INSTALL_DIR="$2"; shift 2 ;;
            --data-dir)
                DATA_DIR="$2"; shift 2 ;;
            --env-file)
                ENV_FILE="$2"
                ENV_DIR="$(dirname "${ENV_FILE}")"
                shift 2 ;;
            --config-dir)
                AWG_CONFIG_DIR="$2"; AWG_CONFIG_DIR_SET=true; shift 2 ;;
            --host)
                LISTEN_HOST="$2"; shift 2 ;;
            --port)
                LISTEN_PORT="$2"; shift 2 ;;
            --username)
                USERNAME="$2"; shift 2 ;;
            --password-hash)
                PASSWORD_HASH="$2"; shift 2 ;;
            --poll-interval)
                POLL_INTERVAL="$2"; shift 2 ;;
            --session-ttl)
                SESSION_TTL="$2"; shift 2 ;;
            --no-enable)
                ENABLE_SERVICE=false; shift ;;
            --no-start)
                START_SERVICE=false; shift ;;
            --force)
                FORCE=true; shift ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1 ;;
        esac
    done

    # --binary-src and --source-dir are mutually exclusive
    if [[ -n "${BINARY_SRC}" ]] && [[ -n "${SOURCE_DIR}" ]]; then
        die "--binary-src and --source-dir are mutually exclusive.
Use --binary-src to provide a pre-built binary, or --source-dir to build from source."
    fi
}

# ── Preflight checks ──────────────────────────────────────────────────────────

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This installer must be run as root (use sudo)."
    fi
}

check_systemd() {
    if ! command -v systemctl &>/dev/null; then
        die "systemd is required but 'systemctl' was not found. \
Only systemd-based Linux distributions are supported."
    fi
}

check_awg_binary() {
    if [[ ! -x "/usr/bin/awg" ]]; then
        die "AWG binary not found or not executable at: /usr/bin/awg
Install AmneziaWG first (https://github.com/wiresock/amneziawg-install)."
    fi
    info "AWG binary: /usr/bin/awg"
}

# ── Source-build support ──────────────────────────────────────────────────────

# Ensure the Rust toolchain (cargo) is available.
# If --install-rust was given and cargo is missing, installs via rustup.
ensure_rust_toolchain() {
    if command -v cargo &>/dev/null; then
        info "Rust toolchain found: $(cargo --version 2>/dev/null || echo 'unknown')"
        return 0
    fi

    # Also check common rustup location for root installs
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

    # Source the cargo environment
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

# Auto-detect the source directory from the repository layout.
# Returns the resolved path in SOURCE_DIR or leaves it empty.
detect_source_dir() {
    # Explicit --source-dir takes precedence
    if [[ -n "${SOURCE_DIR}" ]]; then
        return 0
    fi

    # Try to find the Cargo.toml relative to the script location (repo layout):
    # SCRIPT_DIR = amneziawg-web/scripts/  →  amneziawg-web/ has Cargo.toml
    local candidate="${SCRIPT_DIR}/.."
    if [[ -f "${candidate}/Cargo.toml" ]]; then
        SOURCE_DIR="$(cd "${candidate}" && pwd)"
    fi
}

# Build the web application from source using cargo build --release.
# Sets BINARY_SRC to the built binary on success.
build_from_source() {
    step "Building from source"

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
        die "Build failed. Check the output above for errors.
Ensure build dependencies are installed (gcc, pkg-config, libssl-dev or equivalent)."
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

locate_app_binary() {
    # If a source directory is set (explicit or auto-detected), build from source
    if [[ -n "${SOURCE_DIR}" ]]; then
        build_from_source
        return 0
    fi

    # If --binary-src was provided, use it; otherwise try the default location.
    if [[ -z "${BINARY_SRC}" ]]; then
        # Look relative to the script location first (repo layout)
        local repo_build="${SCRIPT_DIR}/../target/release/amneziawg-web"
        if [[ -f "${repo_build}" ]]; then
            BINARY_SRC="${repo_build}"
        elif [[ -f "${DEFAULT_BINARY_SRC}" ]]; then
            BINARY_SRC="${DEFAULT_BINARY_SRC}"
        fi
    fi

    if [[ -z "${BINARY_SRC}" ]] || [[ ! -f "${BINARY_SRC}" ]]; then
        die "Application binary not found.
Run the installer from a repository checkout, build from source with --source-dir, or provide a pre-built binary with --binary-src.
Example:
  sudo $0
  sudo $0 --binary-src ./target/release/amneziawg-web"
    fi

    if [[ ! -x "${BINARY_SRC}" ]]; then
        chmod +x "${BINARY_SRC}"
    fi

    info "Application binary: ${BINARY_SRC}"
}

preflight_checks() {
    step "Preflight checks"
    check_root
    check_systemd
    check_awg_binary

    # Auto-detect source directory if no binary and no source dir were specified
    if [[ -z "${BINARY_SRC}" ]] && [[ -z "${SOURCE_DIR}" ]]; then
        detect_source_dir
    fi

    locate_app_binary
    info "All preflight checks passed."
}

# ── Hash generation ────────────────────────────────────────────────────────────

# Try to generate an Argon2id PHC hash using python3 + argon2-cffi.
# Password is passed via environment variable to avoid shell quoting issues
# and to keep it off the process command line.
# Returns: hash string on stdout, or returns non-zero.
hash_with_python3() {
    local password="$1"
    # Export password via env var; the assignment is scoped to this subprocess only.
    AMNEZIAWG_HASH_PW="${password}" python3 - <<'PYEOF' 2>/dev/null
import sys, os
try:
    import argon2
    ph = argon2.PasswordHasher()
    pw = os.environ.get("AMNEZIAWG_HASH_PW", "")
    print(ph.hash(pw))
except ImportError:
    sys.exit(1)
PYEOF
}

# Try to generate an Argon2id PHC hash using the argon2 CLI tool.
# Parameters match the python3 argon2-cffi defaults: m=65536, t=3, p=4, l=32
hash_with_argon2_cli() {
    local password="$1"
    if ! command -v argon2 &>/dev/null; then
        return 1
    fi
    local salt
    salt="$(openssl rand -base64 16)"
    # argon2 CLI: -m is log2(memory in KiB), so 16 = 2^16 = 65536 KiB
    printf '%s' "${password}" | argon2 "${salt}" -id -t 3 -m 16 -p 4 -l 32 -e 2>/dev/null
}

# Generate Argon2id hash for a password; sets PASSWORD_HASH on success.
generate_hash() {
    local password="$1"
    local hash=""

    hash="$(hash_with_python3 "${password}")" && {
        PASSWORD_HASH="${hash}"
        return 0
    }

    warn "python3 argon2-cffi not available; trying argon2 CLI..."
    hash="$(hash_with_argon2_cli "${password}")" && {
        PASSWORD_HASH="${hash}"
        return 0
    }

    return 1
}

# ── Prompts ────────────────────────────────────────────────────────────────────

# prompt_default VAR_NAME "Prompt text" "default"
prompt_default() {
    local var_name="$1"
    local prompt_text="$2"
    local default_val="$3"
    local user_input

    if [[ -n "${default_val}" ]]; then
        printf "%s [%s]: " "${prompt_text}" "${default_val}"
    else
        printf "%s: " "${prompt_text}"
    fi
    read -r user_input
    if [[ -z "${user_input}" ]]; then
        printf -v "${var_name}" '%s' "${default_val}"
    else
        printf -v "${var_name}" '%s' "${user_input}"
    fi
}

# prompt_yesno VAR_NAME "Prompt text" default_bool
prompt_yesno() {
    local var_name="$1"
    local prompt_text="$2"
    local default_bool="$3"
    local hint
    local user_input

    if [[ "${default_bool}" == true ]]; then
        hint="Y/n"
    else
        hint="y/N"
    fi

    printf "%s [%s]: " "${prompt_text}" "${hint}"
    read -r user_input
    user_input="${user_input,,}"  # lowercase

    if [[ -z "${user_input}" ]]; then
        printf -v "${var_name}" '%s' "${default_bool}"
    elif [[ "${user_input}" == "y" || "${user_input}" == "yes" ]]; then
        printf -v "${var_name}" '%s' "true"
    else
        printf -v "${var_name}" '%s' "false"
    fi
}

# Prompt for a password twice; does not echo.
prompt_password() {
    local pass1 pass2
    while true; do
        printf "Admin password: "
        read -rs pass1
        printf "\n"
        if [[ -z "${pass1}" ]]; then
            warn "Password cannot be empty. Please try again."
            continue
        fi
        printf "Confirm password: "
        read -rs pass2
        printf "\n"
        if [[ "${pass1}" != "${pass2}" ]]; then
            warn "Passwords do not match. Please try again."
            continue
        fi
        PASSWORD="${pass1}"
        break
    done
}

interactive_setup() {
    step "Interactive configuration"

    cat <<EOF

You will be prompted for installation settings.
Press Enter to accept the default shown in brackets.

EOF

    prompt_default INSTALL_DIR "Binary install directory" "${INSTALL_DIR}"
    prompt_default DATA_DIR    "Data directory (SQLite DB)" "${DATA_DIR}"
    prompt_default ENV_FILE    "Environment file path" "${ENV_FILE}"
    ENV_DIR="$(dirname "${ENV_FILE}")"
    prompt_default AWG_CONFIG_DIR "AWG client config directory" "${AWG_CONFIG_DIR}"
    prompt_default LISTEN_HOST "Bind host" "${LISTEN_HOST}"
    prompt_default LISTEN_PORT "Bind port" "${LISTEN_PORT}"
    prompt_default POLL_INTERVAL "Poll interval (seconds)" "${POLL_INTERVAL}"
    prompt_default USERNAME "Admin username" "${USERNAME}"

    # Password: only prompt if no hash was supplied
    if [[ -z "${PASSWORD_HASH}" ]]; then
        printf "\n"
        info "Generating Argon2id password hash..."
        prompt_password

        if ! generate_hash "${PASSWORD}"; then
            warn "Could not generate Argon2id hash automatically."
            printf "\nGenerate a hash manually with:\n"
            printf "  python3 -c \"import argon2; print(argon2.PasswordHasher().hash('yourpassword'))\"\n"
            printf "Then re-run the installer with: --password-hash '<hash>'\n\n"
            die "Unable to generate password hash. Install python3-argon2 or the argon2 CLI and try again."
        fi
        # Clear plaintext password from memory
        PASSWORD=""
        info "Password hash generated."
    fi

    printf "\n"
    prompt_yesno ENABLE_SERVICE "Enable service at boot?" "${ENABLE_SERVICE}"
    prompt_yesno START_SERVICE  "Start service now?" "${START_SERVICE}"

    printf "\n"
    printf "${BOLD}Configuration summary:${NC}\n"
    printf "  Binary src:       %s\n" "${BINARY_SRC}"
    printf "  Install dir:      %s\n" "${INSTALL_DIR}"
    printf "  Data dir:         %s\n" "${DATA_DIR}"
    printf "  Env file:         %s\n" "${ENV_FILE}"
    printf "  Config dir:       %s\n" "${AWG_CONFIG_DIR}"
    printf "  Listen:           %s:%s\n" "${LISTEN_HOST}" "${LISTEN_PORT}"
    printf "  Username:         %s\n" "${USERNAME}"
    printf "  Enable at boot:   %s\n" "${ENABLE_SERVICE}"
    printf "  Start now:        %s\n" "${START_SERVICE}"
    printf "\n"

    local proceed
    prompt_yesno proceed "Proceed with installation?" "true"
    if [[ "${proceed}" != "true" ]]; then
        info "Installation cancelled."
        exit 0
    fi
}

# Try to detect the directory where amneziawg-install.sh stores client configs.
# The installer writes files like  awg0-client-<name>.conf  into the invoking
# user's home directory (resolved via getHomeDirForClient).  If the default
# AWG_CONFIG_DIR has not been overridden and we can find existing client
# configs, use their parent directory as the default so the web panel discovers
# them without manual configuration.
detect_awg_config_dir() {
    # Only auto-detect when no explicit --config-dir was provided.
    if [[ "${AWG_CONFIG_DIR_SET}" == "true" ]]; then
        return 0
    fi

    # First, check whether the current default directory already contains
    # valid client configs.  If so, no need to scan home directories.
    local default_cfg=""
    default_cfg="$(compgen -G "${DEFAULT_AWG_CONFIG_DIR}/awg*-client-*.conf" 2>/dev/null | head -n 1 || true)"
    if [[ -n "${default_cfg}" ]] && [[ -f "${default_cfg}" && -r "${default_cfg}" ]] && \
        grep -qE '^[[:space:]]*\[Interface\]' "${default_cfg}" 2>/dev/null; then
        info "Default config directory ${DEFAULT_AWG_CONFIG_DIR} already contains client configs; skipping auto-detection."
        return 0
    fi

    # Search common locations for AWG client configs.
    # Priority: SUDO_USER's home, root's home, any /home/* directory.
    local -a search_dirs=()

    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_home=""
        if command -v getent &>/dev/null; then
            sudo_home="$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6)"
        fi
        if [[ -z "${sudo_home}" ]] && [[ -d "/home/${SUDO_USER}" ]]; then
            sudo_home="/home/${SUDO_USER}"
        fi
        if [[ -n "${sudo_home}" ]] && [[ -d "${sudo_home}" ]]; then
            search_dirs+=("${sudo_home}")
        fi
    fi

    search_dirs+=("/root")

    # Scanning all /home/* directories is disabled by default to avoid
    # reading other users' configs on multi-user systems.  Set
    # AMNEZIAWG_WEB_SCAN_ALL_HOMES=1 to enable.
    if [[ "${AMNEZIAWG_WEB_SCAN_ALL_HOMES:-0}" == "1" ]]; then
        for d in /home/*/; do
            if [[ -d "${d}" ]]; then
                search_dirs+=("${d%/}")
            fi
        done
    fi

    for dir in "${search_dirs[@]}"; do
        # Look for the AWG client config naming pattern (files like awg*-client-*.conf)
        # Use a narrower glob and verify the file looks like an AWG config by checking
        # for an [Interface] section before trusting the directory.
        local cfg_file=""
        cfg_file="$(compgen -G "${dir}/awg*-client-*.conf" | head -n 1 || true)"
        if [[ -n "${cfg_file}" ]] && [[ -f "${cfg_file}" && -r "${cfg_file}" ]] && \
            grep -qE '^[[:space:]]*\[Interface\]' "${cfg_file}" 2>/dev/null; then

            # Determine whether this is a home directory (/root or /home/<user>).
            # Do not point AWG_CONFIG_DIR at the home directory itself, because
            # later filesystem hardening only grants execute (x) on home dirs,
            # which is insufficient for std::fs::read_dir().  Instead, record the
            # source home directory so setup_filesystem() can create a dedicated
            # subdirectory and populate it with symlinks after user confirmation.
            local detected_is_home=0
            case "${dir}" in
                /root)
                    detected_is_home=1
                    ;;
                /home/*)
                    local detected_rel="${dir#/home/}"
                    if [[ "${detected_rel}" != *"/"* ]]; then
                        detected_is_home=1
                    fi
                    ;;
            esac

            if [[ ${detected_is_home} -eq 1 ]]; then
                # Record the source home directory for deferred subdirectory
                # creation in setup_filesystem().  Set AWG_CONFIG_DIR to the
                # target subdirectory path so the rest of the installer sees
                # the intended final directory (read-only at this stage).
                AWG_DETECTED_HOME_DIR="${dir}"
                AWG_CONFIG_DIR="${dir}/amneziawg-clients"
            else
                AWG_CONFIG_DIR="${dir}"
            fi

            info "Auto-detected AWG client config directory: ${AWG_CONFIG_DIR}"
            return 0
        fi
    done
}

non_interactive_validate() {
    # In non-interactive mode, a password hash is required.
    if [[ -z "${PASSWORD_HASH}" ]]; then
        die "Non-interactive mode requires --password-hash.
Generate with:
  python3 -c \"import argon2; print(argon2.PasswordHasher().hash('yourpassword'))\""
    fi
}

# ── Filesystem setup ───────────────────────────────────────────────────────────

# Apply a read ACL to the resolved target of a symlinked config file,
# but only if the target resides within an allowed directory (target_dir
# or AWG_DETECTED_HOME_DIR).  This prevents granting the service user
# access to arbitrary files via crafted symlinks.
# Usage: _apply_acl_to_symlink_target <link_path> <target_dir> <service_user>
_apply_acl_to_symlink_target() {
    local link="$1" base_dir="$2" svc_user="$3"
    local target_path
    target_path="$(readlink -f -- "${link}" 2>/dev/null || true)"
    if [[ -z "${target_path}" || ! -f "${target_path}" ]]; then
        return
    fi
    local allowed=0
    case "${target_path}" in
        "${base_dir}"/*)  allowed=1 ;;
    esac
    if [[ -n "${AWG_DETECTED_HOME_DIR}" ]]; then
        case "${target_path}" in
            "${AWG_DETECTED_HOME_DIR}"/*)  allowed=1 ;;
        esac
    fi
    if [[ ${allowed} -eq 1 ]]; then
        setfacl -m "u:${svc_user}:r" "${target_path}" 2>/dev/null || true
    else
        warn "Skipping ACL on symlink target ${target_path}: outside allowed directories."
    fi
}

setup_filesystem() {
    step "Filesystem setup"

    # Create service user if it does not exist
    if ! id "${SERVICE_USER}" &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
        info "Created system user: ${SERVICE_USER}"
    else
        info "System user already exists: ${SERVICE_USER}"
    fi

    # Data directory (owned by service user)
    if [[ ! -d "${DATA_DIR}" ]]; then
        mkdir -p "${DATA_DIR}"
        info "Created data directory: ${DATA_DIR}"
    else
        info "Data directory already exists: ${DATA_DIR}"
    fi
    chown "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
    chmod 0750 "${DATA_DIR}"

    # Env / config directory (root-owned, 0700)
    if [[ ! -d "${ENV_DIR}" ]]; then
        mkdir -p "${ENV_DIR}"
        info "Created env directory: ${ENV_DIR}"
    else
        info "Env directory already exists: ${ENV_DIR}"
    fi
    chown root:root "${ENV_DIR}"
    chmod 0700 "${ENV_DIR}"

    # If auto-detection found configs in a home directory, create the dedicated
    # subdirectory and populate it with symlinks now (deferred from detect to
    # avoid filesystem side effects before user confirmation).
    # Only perform this auto-symlink step if AWG_CONFIG_DIR still matches the
    # directory derived from the detected home. This avoids acting on stale
    # detection results when the user has overridden AWG_CONFIG_DIR.
    if [[ -n "${AWG_DETECTED_HOME_DIR}" ]]; then
        local expected_dir="${AWG_DETECTED_HOME_DIR}/amneziawg-clients"
        if [[ "${AWG_CONFIG_DIR}" != "${expected_dir}" ]]; then
            info "Skipping auto-detected config symlinks: AWG_CONFIG_DIR (${AWG_CONFIG_DIR}) no longer matches ${expected_dir}."
            AWG_DETECTED_HOME_DIR=""
        fi
    fi
    if [[ -n "${AWG_DETECTED_HOME_DIR}" ]]; then
        local dest_dir="${AWG_CONFIG_DIR}"
        if [[ ! -d "${dest_dir}" ]]; then
            mkdir -p "${dest_dir}" || {
                warn "Failed to create ${dest_dir}; skipping auto-detected config symlinks."
                AWG_DETECTED_HOME_DIR=""
            }
            # Best-effort permission tightening; failures here should not abort install.
            chmod 750 "${dest_dir}" 2>/dev/null || true
        fi

        if [[ -n "${AWG_DETECTED_HOME_DIR}" ]]; then
            # Symlink all matching client configs into the dedicated directory so
            # the web panel can safely scan them.  Only link real regular files
            # (not symlinks) to avoid inadvertently granting the service user
            # read access to arbitrary files outside the intended config set.
            (
                shopt -s nullglob
                for f in "${AWG_DETECTED_HOME_DIR}"/awg*-client-*.conf; do
                    if [[ -f "${f}" && ! -L "${f}" && -r "${f}" ]]; then
                        link_name="${dest_dir}/$(basename "${f}")"
                        # Do not overwrite existing non-symlink files.
                        if [[ -e "${link_name}" && ! -L "${link_name}" ]]; then
                            warn "Skipping ${f}: destination ${link_name} already exists and is not a symlink."
                            continue
                        fi
                        # If symlink already points to the same target, skip.
                        if [[ -L "${link_name}" ]]; then
                            existing_target="$(readlink -f "${link_name}" 2>/dev/null || true)"
                            new_target="$(readlink -f "${f}" 2>/dev/null || true)"
                            if [[ -n "${existing_target}" && "${existing_target}" == "${new_target}" ]]; then
                                continue
                            fi
                        fi
                        ln -sf "${f}" "${link_name}" 2>/dev/null || true
                    fi
                done
            )
            info "Symlinked client configs from ${AWG_DETECTED_HOME_DIR} into ${dest_dir}."
        fi
    fi

    # Give the service user read access to the AWG config directory if it exists
    if [[ -d "${AWG_CONFIG_DIR}" ]]; then
        # Best-effort: add to group owning the directory
        local awg_group
        awg_group="$(stat -c '%G' "${AWG_CONFIG_DIR}")"
        if [[ "${awg_group}" != "root" ]] && ! id -Gn "${SERVICE_USER}" | grep -qw "${awg_group}"; then
            usermod -aG "${awg_group}" "${SERVICE_USER}" 2>/dev/null \
                || warn "Could not add ${SERVICE_USER} to group ${awg_group}. \
You may need to grant read access to ${AWG_CONFIG_DIR} manually."
        fi

        # AWG_CONFIG_DIR is already normalized in main(), but resolve again as
        # defense-in-depth in case setup_filesystem is called from elsewhere.
        local target_dir="${AWG_CONFIG_DIR%/}"
        local resolved
        if resolved="$(readlink -f -- "${target_dir}" 2>/dev/null)"; then
            target_dir="${resolved}"
        fi

        # Grant the service user read access to existing *.conf files and set
        # a default ACL so that future files created by amneziawg-install.sh
        # are also readable — even when those files are created with mode 600.
        if command -v setfacl >/dev/null 2>&1; then

            # Refuse to modify ACLs on clearly unsafe, broad system directories.
            local unsafe_dir=0
            case "${target_dir}" in
                /|/etc|/home|/var|/var/lib|/tmp|/usr|/usr/local|/opt|/bin|/sbin|\
                /proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/boot|/boot/*|\
                /lib|/lib/*|/lib32|/lib32/*|/lib64|/lib64/*)
                    unsafe_dir=1
                    ;;
            esac

            if [[ ${unsafe_dir} -eq 1 ]]; then
                warn "Refusing to modify ACLs on unsafe directory ${target_dir} (from AWG_CONFIG_DIR=${AWG_CONFIG_DIR})."
            else
                # Determine whether this is a home directory (/root or /home/<user>).
                local is_home_dir=0
                case "${target_dir}" in
                    /root)
                        is_home_dir=1
                        ;;
                    /home/*)
                        # Strip the /home/ prefix; if there are no further slashes, this is /home/<user>
                        local rel_path="${target_dir#/home/}"
                        if [[ "${rel_path}" != *"/"* ]]; then
                            is_home_dir=1
                        fi
                        ;;
                esac

                # Grant ACL on the config directory so the service can access it.
                # On home directories (/root or /home/<user>), only grant traverse (x)
                # to avoid exposing unrelated filenames.  The web panel uses
                # std::fs::read_dir() which requires directory read (r), so configs
                # stored directly in a home directory will not be auto-discovered.
                # For full discovery, use a dedicated subdirectory where rx is safe.
                if [[ ${is_home_dir} -eq 1 ]]; then
                    setfacl -m "u:${SERVICE_USER}:x" "${target_dir}" 2>/dev/null \
                        && info "Granted traverse-only ACL for ${SERVICE_USER} on ${target_dir}." \
                        || warn "setfacl failed on ${target_dir}."
                    warn "Config directory ${target_dir} is a home directory."
                    warn "Only traverse (x) permission was granted to avoid exposing unrelated files."
                    warn "The web panel may not auto-discover configs here (read_dir requires rx)."
                    warn "For full support, use a dedicated subdirectory (e.g. ${target_dir}/amneziawg-clients)."
                else
                    setfacl -m "u:${SERVICE_USER}:rx" "${target_dir}" 2>/dev/null \
                        && info "Granted read+traverse ACL for ${SERVICE_USER} on ${target_dir}." \
                        || warn "setfacl failed on ${target_dir}."
                fi

                # Default ACL: new files inherit read for the service user, and
                # new directories inherit read+execute (traverse).  Using rX grants
                # execute only on directories while keeping regular files non-executable.
                # Avoid setting a default ACL on a home directory itself (e.g. /home/<user> or /root),
                # since that would grant the service user access to all future files in the home.
                if [[ ${is_home_dir} -eq 0 ]]; then
                    setfacl -d -m "u:${SERVICE_USER}:rX" "${target_dir}" 2>/dev/null \
                        && info "Set default ACL for future configs in ${target_dir}." \
                        || warn "setfacl -d failed on ${target_dir}."
                else
                    info "Skipping default ACL on ${target_dir} because it appears to be a home directory; future configs may need manual ACLs."
                fi

                # Apply read ACL to any existing config files.
                # For home directories, restrict to expected client config patterns
                # so we don't grant the service user access to unrelated *.conf files.
                if [[ ${is_home_dir} -eq 0 ]]; then
                    # Dedicated config directory: all top-level *.conf files.
                    find "${target_dir}" -maxdepth 1 -name '*.conf' -type f -print0 2>/dev/null \
                        | while IFS= read -r -d '' cf; do
                            setfacl -m "u:${SERVICE_USER}:r" "${cf}" 2>/dev/null || true
                        done || true
                    # Also handle symlinked configs by applying ACLs to their real targets,
                    # which are often mode 600 and would otherwise be unreadable.
                    # Validate that resolved targets stay within allowed directories
                    # to avoid granting the service user access to unrelated files.
                    find "${target_dir}" -maxdepth 1 -name '*.conf' -type l -print0 2>/dev/null \
                        | while IFS= read -r -d '' link; do
                            _apply_acl_to_symlink_target "${link}" "${target_dir}" "${SERVICE_USER}"
                        done || true
                    # Log only if there were any .conf files (regular or symlinked)
                    if compgen -G "${target_dir}/*.conf" > /dev/null 2>&1; then
                        info "Applied read ACL to existing config files and symlink targets."
                    fi
                else
                    # Home directory: limit to expected AmneziaWG client configs.
                    find "${target_dir}" -maxdepth 1 -name 'awg*-client-*.conf' -type f -print0 2>/dev/null \
                        | while IFS= read -r -d '' cf; do
                            setfacl -m "u:${SERVICE_USER}:r" "${cf}" 2>/dev/null || true
                        done || true
                    # Also handle symlinked configs by applying ACLs to their real targets.
                    # Validate that resolved targets stay within allowed directories.
                    find "${target_dir}" -maxdepth 1 -name 'awg*-client-*.conf' -type l -print0 2>/dev/null \
                        | while IFS= read -r -d '' link; do
                            _apply_acl_to_symlink_target "${link}" "${target_dir}" "${SERVICE_USER}"
                        done || true
                    # Log only if there were any matching client config files
                    if compgen -G "${target_dir}/awg*-client-*.conf" > /dev/null 2>&1; then
                        info "Applied read ACL to existing client config files and symlink targets in home directory."
                    fi
                fi
            fi
        elif [[ "${AWG_CONFIG_DIR}" != "${DEFAULT_AWG_CONFIG_DIR}" ]]; then
            warn "setfacl is not installed but AWG_CONFIG_DIR (${AWG_CONFIG_DIR}) is non-default."
            warn "The service user ${SERVICE_USER} may not be able to read client configs."
            warn "Install the 'acl' package (e.g. apt install acl) and re-run, or manually adjust permissions."
        fi

        # For directories under /home or /root, the parent directory is typically
        # mode 700/750.  Ensure the service user can traverse into it so that
        # the service can reach the config files.
        # Use the resolved target_dir so symlinks are handled consistently.
        case "${target_dir}" in
            /root/*)
                # Config is under /root (e.g. /root/awg-configs).  /root is
                # typically mode 0700, so the service user needs traverse (x)
                # permission to reach the subdirectory.
                if [[ -d /root ]]; then
                    local root_perms
                    root_perms="$(stat -c '%a' /root)"
                    local root_other_x=$(( 8#${root_perms} & 8#001 ))
                    # Only treat "other+x" as sufficient for traversal. The service user is
                    # not in the root group, so "group+x" on /root does not help it.
                    if [[ ${root_other_x} -eq 0 ]]; then
                        if command -v setfacl >/dev/null 2>&1; then
                            setfacl -m "u:${SERVICE_USER}:x" /root 2>/dev/null \
                                && info "Granted traverse ACL for ${SERVICE_USER} on /root." \
                                || warn "setfacl failed on /root. You may need to \
grant traverse access manually: sudo setfacl -m u:${SERVICE_USER}:x /root"
                        else
                            warn "Config directory is under /root but 'setfacl' is not available. \
Ensure user ${SERVICE_USER} can traverse /root (e.g., via ACL) or configs may be unreadable."
                        fi
                    fi
                fi
                ;;
            /home/*)
                # Extract the top-level home directory (/home/<user>).
                # Linux home directories are always at depth 3.
                local home_dir
                home_dir="$(echo "${target_dir}" | cut -d/ -f1-3)"
                if [[ -d "${home_dir}" ]]; then
                    # Check whether the awg-web user can traverse into the
                    # home directory (needs at least the execute bit for
                    # "other" or "group" if the user is in the owning group).
                    local home_perms
                    home_perms="$(stat -c '%a' "${home_dir}")"
                    local other_x=$(( 8#${home_perms} & 8#001 ))
                    local group_x=$(( 8#${home_perms} & 8#010 ))
                    if [[ ${other_x} -eq 0 ]] && [[ ${group_x} -eq 0 ]]; then
                        # Prefer setfacl (POSIX ACL) for a targeted per-user
                        # grant that avoids opening the directory to everyone.
                        if command -v setfacl >/dev/null 2>&1; then
                            setfacl -m "u:${SERVICE_USER}:x" "${home_dir}" 2>/dev/null \
                                && info "Granted traverse ACL for ${SERVICE_USER} on ${home_dir}." \
                                || warn "setfacl failed on ${home_dir}. You may need to \
grant traverse access manually: sudo setfacl -m u:${SERVICE_USER}:x ${home_dir}"
                        else
                            chmod o+x "${home_dir}" 2>/dev/null \
                                && info "Added traverse permission (o+x) on ${home_dir} for service access." \
                                || warn "Could not set o+x on ${home_dir}. The service may not be \
able to read configs.  Run: sudo chmod o+x ${home_dir}"
                            warn "Consider installing ACL tools (apt install acl) for a more \
targeted permission grant."
                        fi
                    fi
                fi
                ;;
        esac
    fi
}

# ── Binary installation ────────────────────────────────────────────────────────

install_binary() {
    step "Installing binary"

    local dest="${INSTALL_DIR}/amneziawg-web"
    install -m 0755 "${BINARY_SRC}" "${dest}"
    info "Installed binary: ${dest}"
}

# ── Sudoers drop-in ───────────────────────────────────────────────────────────

install_sudoers() {
    step "Installing sudoers rule for AWG access"

    # The web service runs as a non-root user but needs to:
    # 1. Read AWG interface state via `awg show all dump` (CAP_NET_ADMIN).
    # 2. Remove disabled peers via `awg set <iface> peer <key> remove`.
    # 3. Sync interface config via `awg syncconf` + `awg-quick strip` to
    #    restore re-enabled peers to the running interface.
    #
    # Instead of running the whole service as root, we install a tightly-scoped
    # sudoers rule that grants the service user passwordless sudo for only
    # these commands.
    local rule="${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/awg show all dump, /usr/bin/awg set * peer * remove, /usr/bin/awg syncconf * /dev/stdin, /usr/bin/awg-quick strip *"

    info "Sudoers rule: ${rule}"

    # Ensure the sudoers drop-in directory exists (may be absent in minimal
    # containers or stripped images).
    mkdir -p "$(dirname "${SUDOERS_FILE}")"

    # Write with strict permissions first, then validate.
    printf '# Allow amneziawg-web service to manage AWG state and peers.\n' \
        > "${SUDOERS_FILE}"
    printf '# Installed by amneziawg-web-install.sh – do not edit manually.\n' \
        >> "${SUDOERS_FILE}"
    printf '%s\n' "${rule}" >> "${SUDOERS_FILE}"

    chmod 0440 "${SUDOERS_FILE}"
    chown root:root "${SUDOERS_FILE}"

    # Validate syntax if visudo is available (best-effort).
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
    else
        info "visudo not available; skipping syntax check."
    fi

    info "Installed sudoers drop-in: ${SUDOERS_FILE}"
}

# ── Environment file generation ───────────────────────────────────────────────

write_env_file() {
    step "Writing environment file"

    if [[ -f "${ENV_FILE}" ]] && [[ "${FORCE}" != "true" ]]; then
        if [[ "${NON_INTERACTIVE}" == "true" ]]; then
            warn "Env file already exists: ${ENV_FILE}. Use --force to overwrite."
            warn "Skipping env file generation; using existing file."
            return 0
        fi

        local overwrite
        prompt_yesno overwrite \
            "Env file already exists: ${ENV_FILE}. Overwrite?" "false"
        if [[ "${overwrite}" != "true" ]]; then
            warn "Keeping existing env file."
            return 0
        fi
    fi

    # Write env file with mode 0600 (umask trick to avoid brief world-readable window)
    local old_umask
    old_umask="$(umask)"
    umask 077

    cat >"${ENV_FILE}" <<ENVEOF
# amneziawg-web environment configuration
# Generated by amneziawg-web-install.sh
# Manage with: sudo systemctl restart ${SERVICE_NAME}

# ── Authentication ────────────────────────────────────────────────────────────
AUTH_ENABLED=true
AUTH_USERNAME=${USERNAME}
AUTH_PASSWORD_HASH=${PASSWORD_HASH}
AUTH_SESSION_TTL_SECS=${SESSION_TTL}
AUTH_SECURE_COOKIE=false

# Optional bearer token for headless API access.
# Uncomment and set to a 32-byte hex secret: openssl rand -hex 32
# AUTH_API_TOKEN=

# ── Server ────────────────────────────────────────────────────────────────────
AWG_WEB_LISTEN=${LISTEN_HOST}:${LISTEN_PORT}
AWG_WEB_DB=${DATA_DIR}/awg-web.db

# ── AWG integration ───────────────────────────────────────────────────────────
AWG_CONFIG_DIR=${AWG_CONFIG_DIR}
AWG_POLL_INTERVAL=${POLL_INTERVAL}

# ── Logging ───────────────────────────────────────────────────────────────────
RUST_LOG=amneziawg_web=info
ENVEOF

    umask "${old_umask}"

    chown root:root "${ENV_FILE}"
    chmod 0600 "${ENV_FILE}"
    info "Wrote env file: ${ENV_FILE}"

    # Remind operator to set AUTH_SECURE_COOKIE=true if not localhost
    if [[ "${LISTEN_HOST}" != "127.0.0.1" && "${LISTEN_HOST}" != "localhost" ]]; then
        warn "Panel is bound to ${LISTEN_HOST}. Set AUTH_SECURE_COOKIE=true in"
        warn "${ENV_FILE} once you have TLS configured."
    fi
}

# ── systemd service ────────────────────────────────────────────────────────────

find_unit_template() {
    # Look for the service unit file relative to the script (repo layout)
    local candidate="${SCRIPT_DIR}/../packaging/${SERVICE_NAME}.service"
    if [[ -f "${candidate}" ]]; then
        printf '%s' "$(realpath "${candidate}")"
        return 0
    fi
    # Not found; caller must embed inline
    return 1
}

# Adjust ReadOnlyPaths and ProtectHome in the installed service unit to match
# the user's configured AWG_CONFIG_DIR.  The packaged template hard-codes
# ReadOnlyPaths=/etc/amneziawg and ProtectHome=yes which is correct for the
# default config directory.  When a custom directory is chosen — especially
# one under /home — we need to relax the sandboxing so the service can read
# the config files.
adjust_unit_hardening() {
    local unit_file="$1"
    local config_dir="$2"

    [[ -f "${unit_file}" ]] || return 0

    # Normalize: resolve symlinks and strip trailing slashes so the case
    # checks match the actual filesystem location (AWG_CONFIG_DIR is already
    # normalized in main(), but resolve again as defense-in-depth).
    local resolved
    if resolved="$(readlink -f -- "${config_dir}" 2>/dev/null)"; then
        config_dir="${resolved}"
    fi
    config_dir="${config_dir%/}"

    # 1. Update ReadOnlyPaths to include the actual config directory
    if grep -q '^ReadOnlyPaths=' "${unit_file}" 2>/dev/null; then
        local current_ro
        current_ro="$(grep '^ReadOnlyPaths=' "${unit_file}" | head -1 | cut -d= -f2-)"
        current_ro="${current_ro%/}"
        # If the configured directory is already covered, nothing to do
        if [[ "${config_dir}" != "${current_ro}" ]] \
                && [[ "${config_dir}" != "${current_ro}/"* ]]; then
            # Escape sed replacement metacharacters (& and the | delimiter)
            # to prevent path contents from corrupting the unit file.
            local escaped_dir="${config_dir//&/\\&}"
            escaped_dir="${escaped_dir//|/\\|}"
            sed -i "s|^ReadOnlyPaths=.*|ReadOnlyPaths=${escaped_dir}|" "${unit_file}"
            info "Updated ReadOnlyPaths to ${config_dir}"
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

install_service_unit() {
    step "Installing systemd service"

    local unit_src
    if unit_src="$(find_unit_template)"; then
        info "Using service unit: ${unit_src}"

        if [[ -f "${SYSTEMD_UNIT_DEST}" ]] && [[ "${FORCE}" != "true" ]]; then
            warn "Service unit already exists: ${SYSTEMD_UNIT_DEST}."
            warn "Skipping. Use --force to overwrite."
        else
            install -m 0644 "${unit_src}" "${SYSTEMD_UNIT_DEST}"
            info "Installed service unit: ${SYSTEMD_UNIT_DEST}"
        fi
    else
        # Embed a minimal unit inline if the packaging file is not available
        warn "packaging/${SERVICE_NAME}.service not found; writing minimal inline unit."
        if [[ -f "${SYSTEMD_UNIT_DEST}" ]] && [[ "${FORCE}" != "true" ]]; then
            warn "Service unit already exists: ${SYSTEMD_UNIT_DEST}. Skipping."
        else
            cat >"${SYSTEMD_UNIT_DEST}" <<UNITEOF
[Unit]
Description=AmneziaWG Web Management Panel
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/amneziawg-web
WorkingDirectory=${DATA_DIR}
EnvironmentFile=${ENV_FILE}
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=${AWG_CONFIG_DIR}
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
UNITEOF
            chmod 0644 "${SYSTEMD_UNIT_DEST}"
            info "Wrote inline service unit: ${SYSTEMD_UNIT_DEST}"
        fi
    fi

    # Ensure the EnvironmentFile line in the installed unit points to our env file
    if grep -q '^#EnvironmentFile=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null; then
        sed -i "s|^#EnvironmentFile=.*|EnvironmentFile=${ENV_FILE}|" "${SYSTEMD_UNIT_DEST}"
        info "Enabled EnvironmentFile in service unit."
    elif ! grep -q '^EnvironmentFile=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null; then
        # No EnvironmentFile directive at all; insert after the ExecStart line
        sed -i "/^ExecStart=/a EnvironmentFile=${ENV_FILE}" "${SYSTEMD_UNIT_DEST}"
        info "Added EnvironmentFile directive to service unit."
    fi

    # Adjust ReadOnlyPaths / ProtectHome for the configured AWG config directory
    adjust_unit_hardening "${SYSTEMD_UNIT_DEST}" "${AWG_CONFIG_DIR}"

    systemctl daemon-reload
    info "systemd daemon reloaded."

    if [[ "${ENABLE_SERVICE}" == "true" ]]; then
        systemctl enable "${SERVICE_NAME}"
        info "Service enabled at boot."
    fi

    if [[ "${START_SERVICE}" == "true" ]]; then
        systemctl restart "${SERVICE_NAME}"
        info "Service started."
    fi
}

# ── Post-install summary ───────────────────────────────────────────────────────

print_summary() {
    local listen_addr="${LISTEN_HOST}:${LISTEN_PORT}"
    local panel_url="http://${listen_addr}"
    if [[ "${LISTEN_HOST}" == "127.0.0.1" || "${LISTEN_HOST}" == "localhost" ]]; then
        panel_url="http://127.0.0.1:${LISTEN_PORT}"
    fi

    printf "\n${BOLD}${GREEN}══════════════════════════════════════════════════════${NC}\n"
    printf "${BOLD}${GREEN}  amneziawg-web installation complete!${NC}\n"
    printf "${BOLD}${GREEN}══════════════════════════════════════════════════════${NC}\n\n"

    printf "${BOLD}Panel access:${NC}\n"
    printf "  URL:              %s\n" "${panel_url}"
    printf "  Admin username:   %s\n" "${USERNAME}"
    printf "\n"

    printf "${BOLD}Configuration:${NC}\n"
    printf "  Binary:           %s/amneziawg-web\n" "${INSTALL_DIR}"
    printf "  Database:         %s/awg-web.db\n" "${DATA_DIR}"
    printf "  Env file:         %s\n" "${ENV_FILE}"
    printf "  Sudoers:          %s\n" "${SUDOERS_FILE}"
    printf "  Service:          %s\n" "${SERVICE_NAME}"
    printf "\n"

    printf "${BOLD}Service management:${NC}\n"
    printf "  Status:           sudo systemctl status %s\n" "${SERVICE_NAME}"
    printf "  Logs:             sudo journalctl -u %s -f\n" "${SERVICE_NAME}"
    printf "  Restart:          sudo systemctl restart %s\n" "${SERVICE_NAME}"
    printf "\n"

    if [[ "${LISTEN_HOST}" == "127.0.0.1" || "${LISTEN_HOST}" == "localhost" ]]; then
        printf "${BOLD}${YELLOW}Reverse proxy:${NC}\n"
        printf "  The panel is listening on localhost only. To make it accessible\n"
        printf "  from a browser, configure nginx or Caddy to proxy %s\n" "${panel_url}"
        printf "  and terminate TLS. Then set AUTH_SECURE_COOKIE=true in:\n"
        printf "  %s\n" "${ENV_FILE}"
        printf "  See docs/DEPLOYMENT.md for nginx and Caddy examples.\n"
        printf "\n"
    else
        printf "${BOLD}${RED}Warning:${NC}\n"
        printf "  The panel is bound to %s. Ensure it is protected by a\n" "${LISTEN_HOST}"
        printf "  firewall or reverse proxy. Set AUTH_SECURE_COOKIE=true when\n"
        printf "  TLS is configured.\n\n"
    fi

    printf "${BOLD}To change the admin password:${NC}\n"
    printf "  1. Generate a new hash:\n"
    printf "       python3 -c \"import argon2; print(argon2.PasswordHasher().hash('newpassword'))\"\n"
    printf "  2. Update AUTH_PASSWORD_HASH in %s\n" "${ENV_FILE}"
    printf "  3. sudo systemctl restart %s\n" "${SERVICE_NAME}"
    printf "\n"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"
    preflight_checks
    detect_awg_config_dir

    # Best-effort normalization: resolve AWG_CONFIG_DIR to a canonical path
    # when the directory already exists.  readlink -f requires the path to
    # exist; when it does not (e.g. auto-detected subdirectory not yet
    # created), we fall back to ensuring the path is absolute and stripped
    # of trailing slashes.
    local resolved
    if resolved="$(readlink -f -- "${AWG_CONFIG_DIR}" 2>/dev/null)"; then
        AWG_CONFIG_DIR="${resolved}"
    else
        # Ensure the path is absolute even when readlink -f fails.
        case "${AWG_CONFIG_DIR}" in
            /*) ;;  # already absolute
            *)
                local parent_dir abs_parent
                parent_dir="$(dirname -- "${AWG_CONFIG_DIR}")"
                if [ -d "${parent_dir}" ]; then
                    # Parent directory exists: we can safely normalize via cd + pwd.
                    # Only update AWG_CONFIG_DIR if we obtained a non-empty absolute path.
                    if abs_parent="$(cd -- "${parent_dir}" 2>/dev/null && pwd)"; then
                        if [ -n "${abs_parent}" ]; then
                            AWG_CONFIG_DIR="${abs_parent}/$(basename -- "${AWG_CONFIG_DIR}")"
                        fi
                    fi
                else
                    # Parent directory does not exist: resolve relative to current working directory.
                    # This avoids constructing an incorrect root-relative path like "/basename".
                    AWG_CONFIG_DIR="$(pwd)/${AWG_CONFIG_DIR#./}"
                fi
                ;;
        esac
    fi
    AWG_CONFIG_DIR="${AWG_CONFIG_DIR%/}"

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        non_interactive_validate
    else
        interactive_setup
    fi

    setup_filesystem
    install_binary
    install_sudoers
    write_env_file
    install_service_unit
    print_summary
}

main "$@"
