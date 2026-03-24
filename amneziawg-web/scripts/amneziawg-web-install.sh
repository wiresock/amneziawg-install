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

# Default paths
readonly DEFAULT_BINARY_SRC="./target/release/amneziawg-web"
readonly DEFAULT_INSTALL_DIR="/usr/local/bin"
readonly DEFAULT_DATA_DIR="/var/lib/amneziawg-web"
readonly DEFAULT_ENV_DIR="/etc/amneziawg-web"
readonly DEFAULT_ENV_FILE="/etc/amneziawg-web/env.conf"
readonly DEFAULT_AWG_BINARY="/usr/bin/awg"
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
INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
DATA_DIR="${DEFAULT_DATA_DIR}"
ENV_DIR="${DEFAULT_ENV_DIR}"
ENV_FILE="${DEFAULT_ENV_FILE}"
AWG_BINARY="${DEFAULT_AWG_BINARY}"
AWG_CONFIG_DIR="${DEFAULT_AWG_CONFIG_DIR}"
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

Options:
  -h, --help                Show this help and exit
  --non-interactive         Run without prompts; fail if required values are missing
  --binary-src PATH         Path to the compiled amneziawg-web binary
                            (default: ${DEFAULT_BINARY_SRC})
  --install-dir DIR         Directory to install the binary into
                            (default: ${DEFAULT_INSTALL_DIR})
  --data-dir DIR            Directory for the SQLite database
                            (default: ${DEFAULT_DATA_DIR})
  --env-file FILE           Path for the generated environment file
                            (default: ${DEFAULT_ENV_FILE})
  --awg-binary PATH         Path to the awg binary
                            (default: ${DEFAULT_AWG_BINARY})
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
  # Interactive install
  sudo $0

  # Non-interactive install (localhost only, auth enabled)
  sudo $0 \\
    --non-interactive \\
    --binary-src /path/to/amneziawg-web \\
    --username admin \\
    --password-hash '\$argon2id\$v=19\$m=65536,t=3,p=4\$...'

  # Non-interactive, custom paths
  sudo $0 \\
    --non-interactive \\
    --binary-src ./target/release/amneziawg-web \\
    --data-dir /opt/amneziawg-web/data \\
    --env-file /opt/amneziawg-web/env.conf \\
    --host 0.0.0.0 --port 9090 \\
    --username admin \\
    --password-hash '\$argon2id\$v=19\$...' \\
    --no-start
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
            --install-dir)
                INSTALL_DIR="$2"; shift 2 ;;
            --data-dir)
                DATA_DIR="$2"; shift 2 ;;
            --env-file)
                ENV_FILE="$2"
                ENV_DIR="$(dirname "${ENV_FILE}")"
                shift 2 ;;
            --awg-binary)
                AWG_BINARY="$2"; shift 2 ;;
            --config-dir)
                AWG_CONFIG_DIR="$2"; shift 2 ;;
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
    if [[ ! -x "${AWG_BINARY}" ]]; then
        die "AWG binary not found or not executable at: ${AWG_BINARY}
Install AmneziaWG first (https://github.com/wiresock/amneziawg-install) \
or specify the path with --awg-binary."
    fi
    info "AWG binary: ${AWG_BINARY}"
}

locate_app_binary() {
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
Build it first with:
  cd amneziawg-web && cargo build --release
Then run the installer again, or specify the path with --binary-src."
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
    prompt_default AWG_BINARY     "Path to awg binary" "${AWG_BINARY}"
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
    printf "  AWG binary:       %s\n" "${AWG_BINARY}"
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

non_interactive_validate() {
    # In non-interactive mode, a password hash is required.
    if [[ -z "${PASSWORD_HASH}" ]]; then
        die "Non-interactive mode requires --password-hash.
Generate with:
  python3 -c \"import argon2; print(argon2.PasswordHasher().hash('yourpassword'))\""
    fi
}

# ── Filesystem setup ───────────────────────────────────────────────────────────

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
    fi
}

# ── Binary installation ────────────────────────────────────────────────────────

install_binary() {
    step "Installing binary"

    local dest="${INSTALL_DIR}/amneziawg-web"
    install -m 0755 "${BINARY_SRC}" "${dest}"
    info "Installed binary: ${dest}"
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
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/amneziawg
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

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        non_interactive_validate
    else
        interactive_setup
    fi

    setup_filesystem
    install_binary
    write_env_file
    install_service_unit
    print_summary
}

main "$@"
