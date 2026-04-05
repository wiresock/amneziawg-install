#!/usr/bin/env bash
# amneziawg-proxy-install.sh
# Installer for the amneziawg-proxy UDP obfuscation proxy.
#
# Usage:
#   sudo ./amneziawg-proxy-install.sh              # interactive
#   sudo ./amneziawg-proxy-install.sh --help        # show options
#   sudo ./amneziawg-proxy-install.sh --non-interactive [options...]
#
# The installer:
#   1. Runs preflight checks (root, systemd, AWG binary + config)
#   2. Auto-detects the current AmneziaWG interface configuration
#   3. Interactively or non-interactively collects proxy settings
#   4. Builds the proxy binary from source (or accepts a pre-built binary)
#   5. Installs the binary to /usr/local/bin
#   6. Writes /etc/amneziawg-proxy/proxy.toml
#   7. Reconfigures the AWG interface to listen on loopback (127.0.0.1:BACKEND_PORT)
#      so the proxy becomes the public-facing endpoint
#   8. Installs and optionally enables the systemd service
#
# Deployment topology after installation:
#   VPN clients → 0.0.0.0:LISTEN_PORT (proxy) → 127.0.0.1:BACKEND_PORT (AWG)
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

readonly SERVICE_NAME="amneziawg-proxy"
readonly SYSTEMD_UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"

# Default paths
readonly DEFAULT_BINARY_SRC="./target/release/amneziawg-proxy"
readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly DEFAULT_CONFIG_DIR="/etc/amneziawg-proxy"
readonly DEFAULT_CONFIG_FILE="/etc/amneziawg-proxy/proxy.toml"
readonly DEFAULT_DATA_DIR="/var/lib/amneziawg-proxy"
readonly DEFAULT_AWG_DIR="/etc/amnezia/amneziawg"

# Default proxy settings
readonly DEFAULT_LISTEN_HOST="0.0.0.0"
readonly DEFAULT_BACKEND_HOST="127.0.0.1"
readonly DEFAULT_BACKEND_PORT="51821"
readonly DEFAULT_PROTOCOL="quic"
readonly DEFAULT_SESSION_TTL="300"
readonly DEFAULT_RATE_LIMIT="5"
readonly DEFAULT_DNS_UPSTREAM="1.1.1.1:53"
readonly DEFAULT_QUIC_DOMAIN="cloudflare.com"

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
CONFIG_DIR="${DEFAULT_CONFIG_DIR}"
CONFIG_FILE="${DEFAULT_CONFIG_FILE}"
DATA_DIR="${DEFAULT_DATA_DIR}"
AWG_DIR="${DEFAULT_AWG_DIR}"
FORCE=false
ENABLE_SERVICE=true
START_SERVICE=true

# Proxy network settings
LISTEN_HOST="${DEFAULT_LISTEN_HOST}"
LISTEN_PORT=""           # auto-detected from AWG config
BACKEND_HOST="${DEFAULT_BACKEND_HOST}"
BACKEND_PORT="${DEFAULT_BACKEND_PORT}"

# Proxy behaviour settings
PROTOCOL="${DEFAULT_PROTOCOL}"
SESSION_TTL="${DEFAULT_SESSION_TTL}"
RATE_LIMIT="${DEFAULT_RATE_LIMIT}"
DNS_FORWARD_ENABLED=false
DNS_UPSTREAM="${DEFAULT_DNS_UPSTREAM}"
QUIC_HANDSHAKE_ENABLED=false
QUIC_DOMAIN="${DEFAULT_QUIC_DOMAIN}"

# AWG config path (auto-detected)
AWG_CONF_FILE=""
AWG_NIC=""

# ── Usage ─────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
amneziawg-proxy installer

Usage:
  $0 [OPTIONS]

Binary source (choose one):
  --source-dir DIR          Build from source in DIR (Rust crate directory).
                            If neither --source-dir nor --binary-src is given,
                            the installer auto-detects the source directory
                            from the repository layout.
  --binary-src PATH         Path to a pre-built amneziawg-proxy binary.
                            Mutually exclusive with --source-dir.
  --install-rust            Install the Rust toolchain via rustup if cargo is
                            not found. Without this flag, a missing toolchain
                            is a fatal error.

Network options:
  --listen-host HOST        Public-facing bind host (default: ${DEFAULT_LISTEN_HOST})
  --listen-port PORT        Public-facing UDP port (default: auto-detected from AWG)
  --backend-host HOST       Loopback host for AWG backend (default: ${DEFAULT_BACKEND_HOST})
  --backend-port PORT       New AWG listening port after rebind (default: ${DEFAULT_BACKEND_PORT})

Proxy behaviour:
  --protocol PROTO          Protocol to imitate: quic, dns, sip, auto
                            (default: ${DEFAULT_PROTOCOL})
  --session-ttl SECS        Idle session timeout in seconds (default: ${DEFAULT_SESSION_TTL})
  --rate-limit N            Max probe responses per client per second (default: ${DEFAULT_RATE_LIMIT})
  --dns-forward             Enable DNS query forwarding to an upstream resolver
  --dns-upstream ADDR       Upstream DNS resolver host:port (default: ${DEFAULT_DNS_UPSTREAM})
                            Implies --dns-forward when set.
  --quic-handshake          Enable stateful QUIC handshake continuation responder
  --quic-domain DOMAIN      TLS SNI domain for QUIC handshake (default: ${DEFAULT_QUIC_DOMAIN})

Paths:
  -h, --help                Show this help and exit
  --non-interactive         Run without prompts; fail if required values are missing
  --install-dir DIR         Directory to install the binary (default: ${DEFAULT_INSTALL_DIR})
  --config-file FILE        Path for the generated proxy.toml (default: ${DEFAULT_CONFIG_FILE})
  --data-dir DIR            Working directory for the service (default: ${DEFAULT_DATA_DIR})
  --awg-dir DIR             AmneziaWG config directory (default: ${DEFAULT_AWG_DIR})
  --no-enable               Do not enable the systemd service at boot
  --no-start                Do not start the systemd service immediately
  --force                   Overwrite existing config without prompting

Examples:
  # Interactive install (auto-detects AWG config, builds from source)
  sudo $0

  # Source install with auto Rust setup
  sudo $0 --source-dir ./amneziawg-proxy --install-rust

  # Non-interactive: QUIC imitation on port 51820 → loopback :51821
  sudo $0 \\
    --non-interactive \\
    --listen-port 51820 \\
    --protocol quic

  # DNS forwarding mode
  sudo $0 \\
    --non-interactive \\
    --listen-port 51820 \\
    --protocol dns \\
    --dns-forward \\
    --dns-upstream 1.1.1.1:53
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
            --config-file)
                CONFIG_FILE="$2"
                CONFIG_DIR="$(dirname "${CONFIG_FILE}")"
                shift 2 ;;
            --data-dir)
                DATA_DIR="$2"; shift 2 ;;
            --awg-dir)
                AWG_DIR="$2"; shift 2 ;;
            --listen-host)
                LISTEN_HOST="$2"; shift 2 ;;
            --listen-port)
                LISTEN_PORT="$2"; shift 2 ;;
            --backend-host)
                BACKEND_HOST="$2"; shift 2 ;;
            --backend-port)
                BACKEND_PORT="$2"; shift 2 ;;
            --protocol)
                PROTOCOL="$2"; shift 2 ;;
            --session-ttl)
                SESSION_TTL="$2"; shift 2 ;;
            --rate-limit)
                RATE_LIMIT="$2"; shift 2 ;;
            --dns-forward)
                DNS_FORWARD_ENABLED=true; shift ;;
            --dns-upstream)
                DNS_UPSTREAM="$2"
                DNS_FORWARD_ENABLED=true
                shift 2 ;;
            --quic-handshake)
                QUIC_HANDSHAKE_ENABLED=true; shift ;;
            --quic-domain)
                QUIC_DOMAIN="$2"; shift 2 ;;
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
        die "systemd is required but 'systemctl' was not found.
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

# ── AWG configuration detection ───────────────────────────────────────────────

# Detect the active AmneziaWG interface and its config file.
# Sets AWG_NIC, AWG_CONF_FILE, and LISTEN_PORT (if not already set).
detect_awg_config() {
    step "Detecting AmneziaWG configuration"

    local params_file="${AWG_DIR}/params"

    # Try to read the params file saved by amneziawg-install.sh
    if [[ -f "${params_file}" ]]; then
        # Source params in a subshell to avoid polluting current environment.
        local nic port
        nic="$(bash -c ". '${params_file}' 2>/dev/null && printf '%s' \"\${SERVER_AWG_NIC:-}\"")"
        port="$(bash -c ". '${params_file}' 2>/dev/null && printf '%s' \"\${SERVER_PORT:-}\"")"

        if [[ -n "${nic}" ]]; then
            AWG_NIC="${nic}"
            info "Detected AWG interface: ${AWG_NIC}"
        fi
        if [[ -n "${port}" ]] && [[ -z "${LISTEN_PORT}" ]]; then
            LISTEN_PORT="${port}"
            info "Detected AWG listen port: ${LISTEN_PORT}"
        fi
    fi

    # Locate the server config file
    if [[ -n "${AWG_NIC}" ]]; then
        local candidate="${AWG_DIR}/${AWG_NIC}.conf"
        if [[ -f "${candidate}" ]]; then
            AWG_CONF_FILE="${candidate}"
            info "AWG config file: ${AWG_CONF_FILE}"
        fi
    else
        # Fall back: scan for any .conf file in the AWG directory
        local first_conf
        first_conf="$(find "${AWG_DIR}" -maxdepth 1 -name '*.conf' | sort | head -1 2>/dev/null || true)"
        if [[ -n "${first_conf}" ]]; then
            AWG_CONF_FILE="${first_conf}"
            AWG_NIC="$(basename "${first_conf}" .conf)"
            info "Using AWG config file: ${AWG_CONF_FILE} (interface: ${AWG_NIC})"
        fi
    fi

    # Try to read the listen port from the config file if not found yet
    if [[ -z "${LISTEN_PORT}" ]] && [[ -f "${AWG_CONF_FILE}" ]]; then
        local conf_port
        conf_port="$(grep -i '^[[:space:]]*ListenPort[[:space:]]*=' "${AWG_CONF_FILE}" \
                    | head -1 | sed 's/.*=[[:space:]]*//' | tr -d '[:space:]')"
        if [[ -n "${conf_port}" ]]; then
            LISTEN_PORT="${conf_port}"
            info "Detected AWG listen port from config: ${LISTEN_PORT}"
        fi
    fi

    if [[ -z "${AWG_CONF_FILE}" ]]; then
        warn "Could not auto-detect AmneziaWG config file in ${AWG_DIR}."
        warn "You can specify the interface manually when prompted."
    fi

    if [[ -z "${LISTEN_PORT}" ]]; then
        warn "Could not auto-detect AmneziaWG listen port."
        warn "You will be prompted to enter it manually."
    fi
}

# ── Source-build support ──────────────────────────────────────────────────────

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

detect_source_dir() {
    if [[ -n "${SOURCE_DIR}" ]]; then
        return 0
    fi

    # SCRIPT_DIR = amneziawg-proxy/scripts/ → amneziawg-proxy/ has Cargo.toml
    local candidate="${SCRIPT_DIR}/.."
    if [[ -f "${candidate}/Cargo.toml" ]]; then
        SOURCE_DIR="$(cd "${candidate}" && pwd)"
    fi
}

build_from_source() {
    step "Building amneziawg-proxy from source"

    if [[ ! -d "${SOURCE_DIR}" ]]; then
        die "Source directory does not exist: ${SOURCE_DIR}"
    fi

    if [[ ! -f "${SOURCE_DIR}/Cargo.toml" ]]; then
        die "No Cargo.toml found in source directory: ${SOURCE_DIR}
Expected the amneziawg-proxy Rust crate directory."
    fi

    ensure_rust_toolchain

    info "Building in: ${SOURCE_DIR}"
    info "Running: cargo build --release --locked"

    if ! (cd "${SOURCE_DIR}" && cargo build --release --locked); then
        die "Build failed. Check the output above for errors.
Ensure build dependencies are installed (gcc, pkg-config, libssl-dev or equivalent)."
    fi

    local built_binary="${SOURCE_DIR}/target/release/amneziawg-proxy"
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
    if [[ -n "${SOURCE_DIR}" ]]; then
        build_from_source
        return 0
    fi

    if [[ -z "${BINARY_SRC}" ]]; then
        local repo_build="${SCRIPT_DIR}/../target/release/amneziawg-proxy"
        if [[ -f "${repo_build}" ]]; then
            BINARY_SRC="${repo_build}"
        elif [[ -f "${DEFAULT_BINARY_SRC}" ]]; then
            BINARY_SRC="${DEFAULT_BINARY_SRC}"
        fi
    fi

    if [[ -z "${BINARY_SRC}" ]] || [[ ! -f "${BINARY_SRC}" ]]; then
        die "Proxy binary not found.
Build from source with --source-dir, or provide a pre-built binary with --binary-src.
Example:
  sudo $0 --source-dir ./amneziawg-proxy
  sudo $0 --binary-src ./target/release/amneziawg-proxy"
    fi

    if [[ ! -x "${BINARY_SRC}" ]]; then
        chmod +x "${BINARY_SRC}"
    fi

    info "Proxy binary: ${BINARY_SRC}"
}

preflight_checks() {
    step "Preflight checks"
    check_root
    check_systemd
    check_awg_binary

    # Auto-detect AWG configuration
    detect_awg_config

    # Auto-detect source directory if no binary and no source dir were specified
    if [[ -z "${BINARY_SRC}" ]] && [[ -z "${SOURCE_DIR}" ]]; then
        detect_source_dir
    fi

    locate_app_binary
    info "All preflight checks passed."
}

# ── Prompts ────────────────────────────────────────────────────────────────────

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
    user_input="${user_input,,}"

    if [[ -z "${user_input}" ]]; then
        printf -v "${var_name}" '%s' "${default_bool}"
    elif [[ "${user_input}" == "y" || "${user_input}" == "yes" ]]; then
        printf -v "${var_name}" '%s' "true"
    else
        printf -v "${var_name}" '%s' "false"
    fi
}

prompt_protocol() {
    printf "\nProtocol to imitate:\n"
    printf "  1) quic  — QUIC/UDP (recommended; best DPI evasion)\n"
    printf "  2) dns   — DNS/UDP (works where only DNS is allowed)\n"
    printf "  3) sip   — SIP/UDP (VoIP-heavy networks)\n"
    printf "  4) auto  — auto-detect from incoming probe\n"
    printf "\n"

    local choice
    local default_choice="1"
    case "${PROTOCOL}" in
        quic) default_choice="1" ;;
        dns)  default_choice="2" ;;
        sip)  default_choice="3" ;;
        auto) default_choice="4" ;;
    esac

    prompt_default choice "Protocol choice" "${default_choice}"
    case "${choice}" in
        1) PROTOCOL="quic" ;;
        2) PROTOCOL="dns"  ;;
        3) PROTOCOL="sip"  ;;
        4) PROTOCOL="auto" ;;
        *) PROTOCOL="${choice}" ;; # allow typing the name directly
    esac
}

interactive_setup() {
    step "Interactive configuration"

    cat <<EOF

You will be prompted for proxy settings.
Press Enter to accept the default shown in brackets.

EOF

    # Network
    printf "${BOLD}Network settings:${NC}\n"

    prompt_default LISTEN_HOST "Proxy public bind host" "${LISTEN_HOST}"

    local port_prompt="Public UDP port (clients connect here)"
    if [[ -n "${LISTEN_PORT}" ]]; then
        prompt_default LISTEN_PORT "${port_prompt}" "${LISTEN_PORT}"
    else
        while true; do
            prompt_default LISTEN_PORT "${port_prompt}" ""
            if [[ "${LISTEN_PORT}" =~ ^[0-9]+$ ]] && \
               (( LISTEN_PORT >= 1 && LISTEN_PORT <= 65535 )); then
                break
            fi
            warn "Port must be a number between 1 and 65535."
        done
    fi

    prompt_default BACKEND_HOST "AWG backend bind host (loopback)" "${BACKEND_HOST}"
    prompt_default BACKEND_PORT "AWG backend port (AWG will be moved here)" "${BACKEND_PORT}"

    # Protocol
    printf "\n${BOLD}Protocol imitation:${NC}\n"
    prompt_protocol

    if [[ "${PROTOCOL}" == "quic" || "${PROTOCOL}" == "auto" ]]; then
        printf "\n"
        prompt_yesno QUIC_HANDSHAKE_ENABLED \
            "Enable stateful QUIC handshake responder? (more realistic, uses more memory)" \
            "${QUIC_HANDSHAKE_ENABLED}"
        if [[ "${QUIC_HANDSHAKE_ENABLED}" == "true" ]]; then
            prompt_default QUIC_DOMAIN \
                "TLS SNI domain for QUIC handshake certificate" \
                "${QUIC_DOMAIN}"
        fi
    fi

    if [[ "${PROTOCOL}" == "dns" || "${PROTOCOL}" == "auto" ]]; then
        printf "\n"
        prompt_yesno DNS_FORWARD_ENABLED \
            "Forward DNS probe queries to an upstream resolver? (instead of SERVFAIL)" \
            "${DNS_FORWARD_ENABLED}"
        if [[ "${DNS_FORWARD_ENABLED}" == "true" ]]; then
            prompt_default DNS_UPSTREAM \
                "Upstream DNS resolver (host:port)" \
                "${DNS_UPSTREAM}"
        fi
    fi

    printf "\n${BOLD}Advanced settings:${NC}\n"
    prompt_default SESSION_TTL  "Idle session timeout (seconds)" "${SESSION_TTL}"
    prompt_default RATE_LIMIT   "Max probe responses per client per second" "${RATE_LIMIT}"

    # Paths
    printf "\n${BOLD}Installation paths:${NC}\n"
    prompt_default INSTALL_DIR  "Binary install directory" "${INSTALL_DIR}"
    prompt_default CONFIG_FILE  "Proxy config file path" "${CONFIG_FILE}"
    CONFIG_DIR="$(dirname "${CONFIG_FILE}")"
    prompt_default DATA_DIR     "Service working directory" "${DATA_DIR}"

    printf "\n${BOLD}Service options:${NC}\n"
    prompt_yesno ENABLE_SERVICE "Enable service at boot?" "${ENABLE_SERVICE}"
    prompt_yesno START_SERVICE  "Start service now?" "${START_SERVICE}"

    # Summary
    printf "\n${BOLD}Configuration summary:${NC}\n"
    printf "  Binary src:       %s\n"  "${BINARY_SRC}"
    printf "  Install dir:      %s\n"  "${INSTALL_DIR}"
    printf "  Config file:      %s\n"  "${CONFIG_FILE}"
    printf "  Data dir:         %s\n"  "${DATA_DIR}"
    printf "  Listen:           %s:%s\n" "${LISTEN_HOST}" "${LISTEN_PORT}"
    printf "  AWG backend:      %s:%s\n" "${BACKEND_HOST}" "${BACKEND_PORT}"
    printf "  Protocol:         %s\n"  "${PROTOCOL}"
    printf "  Session TTL:      %s s\n" "${SESSION_TTL}"
    printf "  Rate limit:       %s/s\n" "${RATE_LIMIT}"
    if [[ "${PROTOCOL}" == "quic" || "${PROTOCOL}" == "auto" ]]; then
        printf "  QUIC handshake:   %s\n" "${QUIC_HANDSHAKE_ENABLED}"
        if [[ "${QUIC_HANDSHAKE_ENABLED}" == "true" ]]; then
            printf "  QUIC domain:      %s\n" "${QUIC_DOMAIN}"
        fi
    fi
    if [[ "${PROTOCOL}" == "dns" || "${PROTOCOL}" == "auto" ]]; then
        printf "  DNS forward:      %s\n" "${DNS_FORWARD_ENABLED}"
        if [[ "${DNS_FORWARD_ENABLED}" == "true" ]]; then
            printf "  DNS upstream:     %s\n" "${DNS_UPSTREAM}"
        fi
    fi
    if [[ -n "${AWG_CONF_FILE}" ]]; then
        printf "  AWG config:       %s\n" "${AWG_CONF_FILE}"
    fi
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

non_interactive_validate() {
    if [[ -z "${LISTEN_PORT}" ]]; then
        die "Non-interactive mode requires --listen-port (could not auto-detect from AWG config).
Re-run with: --listen-port <port>"
    fi

    if ! [[ "${LISTEN_PORT}" =~ ^[0-9]+$ ]] || \
       (( LISTEN_PORT < 1 || LISTEN_PORT > 65535 )); then
        die "Invalid --listen-port: ${LISTEN_PORT}. Must be 1–65535."
    fi

    if ! [[ "${BACKEND_PORT}" =~ ^[0-9]+$ ]] || \
       (( BACKEND_PORT < 1 || BACKEND_PORT > 65535 )); then
        die "Invalid --backend-port: ${BACKEND_PORT}. Must be 1–65535."
    fi

    case "${PROTOCOL}" in
        quic|dns|sip|auto) ;;
        *) die "Invalid --protocol '${PROTOCOL}'. Must be one of: quic, dns, sip, auto." ;;
    esac
}

# ── Filesystem setup ───────────────────────────────────────────────────────────

setup_filesystem() {
    step "Filesystem setup"

    # Config directory (root-owned, 0700)
    if [[ ! -d "${CONFIG_DIR}" ]]; then
        mkdir -p "${CONFIG_DIR}"
        info "Created config directory: ${CONFIG_DIR}"
    else
        info "Config directory already exists: ${CONFIG_DIR}"
    fi
    chown root:root "${CONFIG_DIR}"
    chmod 0700 "${CONFIG_DIR}"

    # Data/working directory
    if [[ ! -d "${DATA_DIR}" ]]; then
        mkdir -p "${DATA_DIR}"
        info "Created data directory: ${DATA_DIR}"
    else
        info "Data directory already exists: ${DATA_DIR}"
    fi
    chown root:root "${DATA_DIR}"
    chmod 0750 "${DATA_DIR}"
}

# ── Binary installation ────────────────────────────────────────────────────────

install_binary() {
    step "Installing binary"

    local dest="${INSTALL_DIR}/amneziawg-proxy"
    install -m 0755 "${BINARY_SRC}" "${dest}"
    info "Installed binary: ${dest}"
}

# ── Proxy config (proxy.toml) ─────────────────────────────────────────────────

write_proxy_config() {
    step "Writing proxy configuration"

    if [[ -f "${CONFIG_FILE}" ]] && [[ "${FORCE}" != "true" ]]; then
        if [[ "${NON_INTERACTIVE}" == "true" ]]; then
            warn "Config file already exists: ${CONFIG_FILE}. Use --force to overwrite."
            warn "Skipping config generation; using existing file."
            return 0
        fi

        local overwrite
        prompt_yesno overwrite \
            "Config file already exists: ${CONFIG_FILE}. Overwrite?" "false"
        if [[ "${overwrite}" != "true" ]]; then
            warn "Keeping existing config file."
            return 0
        fi
    fi

    local old_umask
    old_umask="$(umask)"
    umask 077

    # Determine AWG config path line
    local awg_config_line=""
    if [[ -n "${AWG_CONF_FILE}" ]]; then
        awg_config_line="awg_config = \"${AWG_CONF_FILE}\""
    else
        awg_config_line="# awg_config = \"/etc/amnezia/amneziawg/${AWG_NIC:-awg0}.conf\""
    fi

    # Bool helpers
    local dns_fwd_toml="false"
    [[ "${DNS_FORWARD_ENABLED}" == "true" ]] && dns_fwd_toml="true"

    local quic_hs_toml="false"
    [[ "${QUIC_HANDSHAKE_ENABLED}" == "true" ]] && quic_hs_toml="true"

    cat >"${CONFIG_FILE}" <<TOMLEOF
# amneziawg-proxy configuration
# Generated by amneziawg-proxy-install.sh
# Manage with: sudo systemctl restart ${SERVICE_NAME}
#
# Deployment topology:
#   VPN clients → ${LISTEN_HOST}:${LISTEN_PORT} (this proxy)
#                 → ${BACKEND_HOST}:${BACKEND_PORT} (AmneziaWG)

# ── Network ───────────────────────────────────────────────────────────────────

# Address this proxy listens on for client traffic.
listen = "${LISTEN_HOST}:${LISTEN_PORT}"

# Address of the AmneziaWG backend (AWG should be reconfigured to bind here).
backend = "${BACKEND_HOST}:${BACKEND_PORT}"

# ── Protocol imitation ────────────────────────────────────────────────────────

# Protocol to imitate: "quic", "dns", "sip", or "auto"
imitate_protocol = "${PROTOCOL}"

# QUIC handshake continuation responder (stateful; more realistic).
quic_handshake_enabled = ${quic_hs_toml}

# TLS SNI domain used in the QUIC handshake certificate.
quic_certificate_domain = "${QUIC_DOMAIN}"

# Forward DNS probe queries to an upstream resolver instead of always
# returning a synthetic SERVFAIL response.
dns_forward_enabled = ${dns_fwd_toml}

# Upstream DNS resolver (host:port) used when dns_forward_enabled = true.
dns_upstream = "${DNS_UPSTREAM}"

# Timeout for upstream DNS query forwarding in milliseconds.
dns_upstream_timeout_ms = 1500

# ── Sessions ──────────────────────────────────────────────────────────────────

# Idle session timeout in seconds. Sessions are reaped after this period.
session_ttl_secs = ${SESSION_TTL}

# Cleanup sweep interval in seconds.
cleanup_interval_secs = 60

# Maximum number of concurrent client sessions.
max_sessions = 10000

# ── Rate limiting ─────────────────────────────────────────────────────────────

# Maximum probe responses sent per client per second.
rate_limit_per_sec = ${RATE_LIMIT}

# ── AmneziaWG obfuscation parameters ─────────────────────────────────────────

# Path to the AmneziaWG server config file.
# When set, obfuscation parameters (S1-S4, H1-H4) are loaded and used for
# packet classification and per-type padding transformation.
${awg_config_line}
TOMLEOF

    umask "${old_umask}"

    chown root:root "${CONFIG_FILE}"
    chmod 0600 "${CONFIG_FILE}"
    info "Wrote proxy config: ${CONFIG_FILE}"
}

# ── Reconfigure AmneziaWG to listen on loopback ───────────────────────────────

reconfigure_awg_listen_port() {
    step "Reconfiguring AmneziaWG listen port"

    if [[ -z "${AWG_CONF_FILE}" ]]; then
        warn "AWG config file not found; skipping listen-port reconfiguration."
        warn "You must manually change ListenPort in your AWG config to ${BACKEND_PORT}"
        warn "and restart the interface so the proxy can become the public endpoint."
        return 0
    fi

    # Read the current listen port from the config
    local current_listen
    current_listen="$(grep -i '^[[:space:]]*ListenPort[[:space:]]*=' "${AWG_CONF_FILE}" \
                     | head -1 | sed 's/.*=[[:space:]]*//' | tr -d '[:space:]')" || true

    local current_addr
    current_addr="$(grep -i '^[[:space:]]*ListenAddr[[:space:]]*=' "${AWG_CONF_FILE}" \
                   | head -1 | sed 's/.*=[[:space:]]*//' | tr -d '[:space:]')" || true

    # Determine if reconfiguration is needed
    local needs_port_change=false
    local needs_addr_change=false

    if [[ "${current_listen}" != "${BACKEND_PORT}" ]]; then
        needs_port_change=true
    fi

    # Check if AWG is already bound to the loopback address
    # (AWG uses ListenAddr or binds to 0.0.0.0 by default)
    if [[ -z "${current_addr}" ]] || [[ "${current_addr}" == "0.0.0.0" ]]; then
        needs_addr_change=true
    elif [[ "${current_addr}" != "${BACKEND_HOST}" ]]; then
        needs_addr_change=true
    fi

    if [[ "${needs_port_change}" == "false" ]] && [[ "${needs_addr_change}" == "false" ]]; then
        info "AWG already configured for backend address ${BACKEND_HOST}:${BACKEND_PORT}."
        return 0
    fi

    info "Current AWG listen: ${current_addr:-0.0.0.0}:${current_listen:-unknown}"
    info "Reconfiguring AWG to listen on: ${BACKEND_HOST}:${BACKEND_PORT}"

    # Back up the config file before modifying it
    local backup
    backup="${AWG_CONF_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    cp "${AWG_CONF_FILE}" "${backup}"
    info "Backed up AWG config to: ${backup}"

    # Update ListenPort in the [Interface] section
    if [[ "${needs_port_change}" == "true" ]]; then
        if grep -qi '^[[:space:]]*ListenPort[[:space:]]*=' "${AWG_CONF_FILE}"; then
            sed -i "s|^[[:space:]]*ListenPort[[:space:]]*=.*|ListenPort = ${BACKEND_PORT}|i" \
                "${AWG_CONF_FILE}"
        else
            # Insert after [Interface] header
            sed -i '/^\[Interface\]/a ListenPort = '"${BACKEND_PORT}" "${AWG_CONF_FILE}"
        fi
        info "Updated ListenPort → ${BACKEND_PORT}"
    fi

    # Update or insert ListenAddr to restrict AWG to loopback
    # Note: AmneziaWG supports ListenAddr in newer versions; otherwise use
    # the Address field approach (not needed for proxy topology).
    # We add a comment regardless so operators know the intent.
    if [[ "${needs_addr_change}" == "true" ]]; then
        if grep -qi '^[[:space:]]*ListenAddr[[:space:]]*=' "${AWG_CONF_FILE}"; then
            sed -i "s|^[[:space:]]*ListenAddr[[:space:]]*=.*|ListenAddr = ${BACKEND_HOST}|i" \
                "${AWG_CONF_FILE}"
            info "Updated ListenAddr → ${BACKEND_HOST}"
        else
            # AmneziaWG may not support ListenAddr; add as a comment note only
            warn "AmneziaWG does not use a ListenAddr directive in all versions."
            warn "To restrict AWG to loopback, use firewall rules or bind via the"
            warn "awg-quick PostUp hook. Example PostUp firewall rule:"
            warn "  PostUp = iptables -I INPUT -p udp --dport ${BACKEND_PORT} ! -s ${BACKEND_HOST}/8 -j DROP"
        fi
    fi

    # Restart the AWG interface if it is currently active
    local nic="${AWG_NIC:-awg0}"
    if systemctl is-active --quiet "awg-quick@${nic}" 2>/dev/null; then
        info "Restarting AWG interface ${nic} to apply new listen port..."
        if ! systemctl restart "awg-quick@${nic}"; then
            warn "Failed to restart awg-quick@${nic}. You may need to restart it manually:"
            warn "  sudo systemctl restart awg-quick@${nic}"
        else
            info "AWG interface ${nic} restarted."
        fi
    else
        warn "AWG interface service awg-quick@${nic} is not active."
        warn "After starting the proxy, bring up the interface with:"
        warn "  sudo systemctl start awg-quick@${nic}"
    fi
}

# ── systemd service ────────────────────────────────────────────────────────────

find_unit_template() {
    local candidate="${SCRIPT_DIR}/../packaging/${SERVICE_NAME}.service"
    if [[ -f "${candidate}" ]]; then
        printf '%s' "$(realpath "${candidate}")"
        return 0
    fi
    return 1
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
        warn "packaging/${SERVICE_NAME}.service not found; writing minimal inline unit."
        if [[ -f "${SYSTEMD_UNIT_DEST}" ]] && [[ "${FORCE}" != "true" ]]; then
            warn "Service unit already exists: ${SYSTEMD_UNIT_DEST}. Skipping."
        else
            cat >"${SYSTEMD_UNIT_DEST}" <<UNITEOF
[Unit]
Description=AmneziaWG UDP Proxy (DPI obfuscation layer)
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
User=root
ExecStart=${INSTALL_DIR}/amneziawg-proxy ${CONFIG_FILE}
WorkingDirectory=${DATA_DIR}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/amnezia ${CONFIG_DIR}
ReadWritePaths=${DATA_DIR}
Environment=RUST_LOG=amneziawg_proxy=info

[Install]
WantedBy=multi-user.target
UNITEOF
            chmod 0644 "${SYSTEMD_UNIT_DEST}"
            info "Wrote inline service unit: ${SYSTEMD_UNIT_DEST}"
        fi
    fi

    # Ensure ExecStart points to the correct config file
    if grep -q '^ExecStart=' "${SYSTEMD_UNIT_DEST}" 2>/dev/null; then
        sed -i "s|^ExecStart=.*|ExecStart=${INSTALL_DIR}/amneziawg-proxy ${CONFIG_FILE}|" \
            "${SYSTEMD_UNIT_DEST}"
        info "Updated ExecStart in service unit."
    fi

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
    printf "\n${BOLD}${GREEN}══════════════════════════════════════════════════════${NC}\n"
    printf "${BOLD}${GREEN}  amneziawg-proxy installation complete!${NC}\n"
    printf "${BOLD}${GREEN}══════════════════════════════════════════════════════${NC}\n\n"

    printf "${BOLD}Proxy endpoint:${NC}\n"
    printf "  Clients connect to:   %s:%s (UDP)\n" "${LISTEN_HOST}" "${LISTEN_PORT}"
    printf "  AWG backend:          %s:%s (UDP)\n" "${BACKEND_HOST}" "${BACKEND_PORT}"
    printf "  Protocol imitation:   %s\n" "${PROTOCOL}"
    printf "\n"

    printf "${BOLD}Configuration:${NC}\n"
    printf "  Binary:               %s/amneziawg-proxy\n" "${INSTALL_DIR}"
    printf "  Proxy config:         %s\n" "${CONFIG_FILE}"
    printf "  Service:              %s\n" "${SERVICE_NAME}"
    if [[ -n "${AWG_CONF_FILE}" ]]; then
        printf "  AWG config:           %s\n" "${AWG_CONF_FILE}"
    fi
    printf "\n"

    printf "${BOLD}Service management:${NC}\n"
    printf "  Status:   sudo systemctl status %s\n" "${SERVICE_NAME}"
    printf "  Logs:     sudo journalctl -u %s -f\n" "${SERVICE_NAME}"
    printf "  Restart:  sudo systemctl restart %s\n" "${SERVICE_NAME}"
    printf "\n"

    if [[ -n "${AWG_CONF_FILE}" ]]; then
        printf "${BOLD}${YELLOW}Important:${NC}\n"
        printf "  AmneziaWG has been reconfigured to listen on %s:%s.\n" \
            "${BACKEND_HOST}" "${BACKEND_PORT}"
        printf "  VPN clients should continue to connect to port %s.\n" "${LISTEN_PORT}"
        printf "  The proxy handles all public traffic and forwards to AWG.\n"
        printf "\n"
    fi

    printf "${BOLD}To uninstall:${NC}\n"
    printf "  sudo ./amneziawg-proxy-uninstall.sh\n"
    printf "\n"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"
    preflight_checks

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        non_interactive_validate
    else
        interactive_setup
    fi

    setup_filesystem
    install_binary
    write_proxy_config
    reconfigure_awg_listen_port
    install_service_unit
    print_summary
}

main "$@"
