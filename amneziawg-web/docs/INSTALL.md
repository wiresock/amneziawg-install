# Installation Guide

This guide covers building and deploying `amneziawg-web` on a Linux host.

For a quick orientation, see the [README](../README.md).
For production hardening details, see [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Quick install (recommended)

The installer builds from source by default. When you run it from a repository
checkout, it auto-detects the source directory for you. It lives at the repository root next to `amneziawg-install.sh`:

```bash
git clone https://github.com/wiresock/amneziawg-install.git
cd amneziawg-install

# 1. Install AmneziaWG (if not already done)
sudo ./amneziawg-install.sh

# 2. Install the web panel (builds from source)
sudo ./amneziawg-web-install.sh
```

If Rust is not installed, add `--install-rust` to automatically install the toolchain:

```bash
sudo ./amneziawg-web-install.sh --install-rust
```

If you have a pre-built binary, use `--binary-src` instead:

```bash
sudo ./amneziawg-web-install.sh --binary-src ./target/release/amneziawg-web
```

The root-level `amneziawg-web-install.sh` is a thin legacy wrapper that delegates to
`amneziawg-web.sh install`, which in turn runs
`amneziawg-web/scripts/amneziawg-web-install.sh`. All installer logic lives in
the sub-script; the root-level files exist purely for operator convenience so both
installers are discoverable in the same place.

If you download only `amneziawg-web.sh` (or both `amneziawg-web-install.sh` and
`amneziawg-web.sh`), the script will shallow-clone the repository to a temporary
directory automatically before continuing. This bootstrap step requires `git` to be
installed and available in `PATH`; if `git` is missing, the script will fail early
with an error and exit without making changes.

The installer handles user creation, directory setup, environment file generation,
and systemd service installation. See [Installer reference](#installer-reference)
for all options.

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Linux | Any modern kernel | x86_64 or aarch64 |
| Rust toolchain | 1.75+ | Install via [rustup](https://rustup.rs/) or use `--install-rust` |
| AmneziaWG | Any release | `awg` binary must be at `/usr/bin/awg` |
| SQLite | 3.x | No separate install needed — embedded in binary via sqlx |
| Reverse proxy | nginx ≥ 1.18 or Caddy 2 | Required for TLS in production |

`amneziawg-web` does **not** require a separate database server, Redis, or container runtime.

> **Note:** If you use `--source-dir` to build from source, Rust must be installed.
> The installer can install Rust for you with `--install-rust`. If you use `--binary-src`
> to provide a pre-built binary, Rust is not required on the target host.

---

## 1. Build from source

The installer can build from source automatically (see [Quick install](#quick-install-recommended)).
To build manually:

```bash
# Clone the repo (or download a release tarball)
git clone https://github.com/wiresock/amneziawg-install.git
cd amneziawg-install/amneziawg-web

# Build the release binary
cargo build --release

# Verify
./target/release/amneziawg-web --version
```

The compiled binary is at `target/release/amneziawg-web` (~10–15 MB, statically linked except for libc).

---

## 2. Install the binary

```bash
sudo install -m 0755 target/release/amneziawg-web /usr/local/bin/amneziawg-web
```

---

## 3. Create a system user and directories

```bash
# Dedicated non-root service user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin awg-web

# Database directory (writable by service user)
sudo mkdir -p /var/lib/amneziawg-web
sudo chown awg-web:awg-web /var/lib/amneziawg-web

# Config directory for the environment file (root-owned, mode 700)
sudo mkdir -p /etc/amneziawg-web
sudo chmod 0700 /etc/amneziawg-web
```

---

## 4. AWG binary and privilege setup

`amneziawg-web` calls `sudo /usr/bin/awg show all dump` to read tunnel state,
`sudo /usr/bin/awg set … peer … remove` to disable peers, and
`sudo /usr/bin/awg syncconf` + `sudo /usr/bin/awg-quick strip` to re-enable
peers.  The service runs as a dedicated non-root user (`awg-web`) and uses
tightly-scoped sudoers rules for only these commands.

### Automated setup (installer)

The installer (`amneziawg-web-install.sh`) handles all of this automatically:

- Installs a sudoers drop-in at `/etc/sudoers.d/amneziawg-web`
- Validates the file with `visudo -cf` (if available)
- Sets permissions to `0440` (required by sudoers)

### Manual setup

If installing manually, create the sudoers rule:

```bash
echo 'awg-web ALL=(root) NOPASSWD: /usr/bin/awg show all dump, /usr/bin/awg set * peer * remove, /usr/bin/awg syncconf * /dev/stdin, /usr/bin/awg-quick strip *' \
  | sudo tee /etc/sudoers.d/amneziawg-web > /dev/null
sudo chmod 0440 /etc/sudoers.d/amneziawg-web
```

Verify it works:

```bash
sudo -u awg-web sudo -n /usr/bin/awg show all dump
```

### Why sudoers?

Managing AWG interfaces requires `CAP_NET_ADMIN`, which is only
available to root.  Rather than running the whole web service as root,
we grant the service user passwordless sudo for a small, fixed set of
commands:

- `awg show all dump` – read tunnel state (read-only)
- `awg set … peer … remove` – disable a peer by removing it from the running interface
- `awg syncconf` + `awg-quick strip` – re-enable a peer by syncing a sanitized on-disk config

This follows the principle of least privilege.

**Important:** The systemd unit does **not** set `NoNewPrivileges=yes`
because that would block the `sudo` escalation.  All other hardening
directives (`ProtectSystem=strict`, `ProtectHome=yes`, etc.) remain
active.

### Installed files

| File | Purpose | Permissions |
|---|---|---|
| `/etc/sudoers.d/amneziawg-web` | Allows `awg-web` to run `awg show all dump`, `awg set … peer … remove`, `awg syncconf`, and `awg-quick strip` as root | `0440 root:root` |

The uninstaller removes this file.  The upgrader creates it if missing.

Client config files are expected in `AWG_CONFIG_DIR` (default:
`/etc/amneziawg/clients`).  Each file should be a standard WireGuard/AmneziaWG
`*.conf` with a `[Peer] PublicKey` entry matching a live tunnel peer.

The service user needs **read** access to the config directory:

```bash
# Option A: add awg-web to the group that owns the directory
sudo usermod -aG amneziawg awg-web

# Option B: grant read permission explicitly
sudo chmod o+rx /etc/amneziawg/clients
```

---

## 5. Generate a password hash

```bash
python3 -c "import argon2; print(argon2.PasswordHasher().hash('yourpassword'))"
```

Output looks like:
```
$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
```

Store this in `AUTH_PASSWORD_HASH`. **Never store the plaintext password.**

---

## 6. Create the environment file

```bash
sudo tee /etc/amneziawg-web/env.conf << 'EOF'
# Authentication
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$REPLACE_THIS
AUTH_SESSION_TTL_SECS=86400
AUTH_SECURE_COOKIE=true

# Optional: headless API access
# AUTH_API_TOKEN=

# Server
AWG_WEB_LISTEN=127.0.0.1:8080
AWG_WEB_DB=/var/lib/amneziawg-web/awg-web.db
AWG_CONFIG_DIR=/etc/amneziawg/clients
AWG_POLL_INTERVAL=30
RUST_LOG=amneziawg_web=info
EOF

sudo chmod 0600 /etc/amneziawg-web/env.conf
sudo chown root:root /etc/amneziawg-web/env.conf
```

**`AWG_WEB_DB` accepts:**
- a plain filesystem path: `/var/lib/amneziawg-web/awg-web.db` (recommended)
- a relative path: `awg-web.db` (resolved relative to `WorkingDirectory`)
- a SQLite URL: `sqlite:///var/lib/amneziawg-web/awg-web.db`

The database file is created automatically if it does not exist (the directory must be writable by the service user).

To generate a bearer token for API access:

```bash
openssl rand -hex 32
```

---

## 7. Run manually (development / smoke test)

```bash
# Minimal, auth off
./target/release/amneziawg-web

# With environment file
set -a; source /etc/amneziawg-web/env.conf; set +a
./target/release/amneziawg-web

# Check it's up
curl http://127.0.0.1:8080/api/health
# → {"status":"ok"}
```

---

## 8. Install the systemd service

```bash
# Copy the unit file
sudo cp packaging/amneziawg-web.service /etc/systemd/system/

# Enable the EnvironmentFile line
sudo sed -i 's|#EnvironmentFile=|EnvironmentFile=|' \
    /etc/systemd/system/amneziawg-web.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now amneziawg-web

# Check status
sudo systemctl status amneziawg-web
sudo journalctl -u amneziawg-web -f
```

---

## 9. Reverse proxy (required for production)

The panel should **not** be exposed directly on a public interface.
Use nginx or Caddy to terminate TLS and proxy to `127.0.0.1:8080`.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name awg.example.com;

    ssl_certificate     /etc/letsencrypt/live/awg.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/awg.example.com/privkey.pem;

    # Recommended: restrict to trusted IP ranges
    allow 10.0.0.0/8;
    deny all;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

### Caddy

```caddy
awg.example.com {
    @allowed remote_ip 10.0.0.0/8
    handle @allowed {
        reverse_proxy 127.0.0.1:8080
    }
    respond "Forbidden" 403
}
```

After adding a reverse proxy, set `AUTH_SECURE_COOKIE=true` in your environment file and restart the service.

---

## 10. Docker (optional)

A multi-stage `Dockerfile` is provided in the repository root.

```bash
docker build -t amneziawg-web .

docker run -d \
  --name amneziawg-web \
  -p 127.0.0.1:8080:8080 \
  -v /var/lib/amneziawg-web:/data \
  -v /etc/amneziawg/clients:/etc/amneziawg/clients:ro \
  -e AUTH_ENABLED=true \
  -e AUTH_USERNAME=admin \
  -e AUTH_PASSWORD_HASH='$argon2id$...' \
  -e AWG_WEB_DB=/data/awg-web.db \
  amneziawg-web
```

**Docker limitations:**
- The `awg` binary is not bundled in the Docker image. You must either bind-mount
  it from the host or use `--network=host` to access the AWG kernel module.
- For most deployments, running as a systemd service (steps 8–9 above) is simpler.

---

## Environment variable reference

| Variable | Default | Description |
|---|---|---|
| `AWG_WEB_LISTEN` | `0.0.0.0:8080` | TCP bind address |
| `AWG_WEB_DB` | `awg-web.db` | SQLite database path |
| `AWG_CONFIG_DIR` | `/etc/amneziawg/clients` | Client `.conf` directory |
| `AWG_POLL_INTERVAL` | `30` | Poll interval in seconds |
| `RUST_LOG` | `amneziawg_web=info` | Log verbosity |
| `AUTH_ENABLED` | `false` | Enable auth; set `true` in production |
| `AUTH_USERNAME` | `admin` | Admin username |
| `AUTH_PASSWORD_HASH` | *(empty)* | Argon2id PHC string |
| `AUTH_API_TOKEN` | *(absent)* | Bearer token for API-only clients |
| `AUTH_SECURE_COOKIE` | `false` | Add `Secure` flag to session cookie |
| `AUTH_SESSION_TTL_SECS` | `86400` | Session lifetime (seconds) |

---

## Upgrading

1. Build the new binary with `cargo build --release`.
2. Copy it to `/usr/local/bin/amneziawg-web`.
3. `sudo systemctl restart amneziawg-web`.

Database migrations run automatically on startup.

---

## Installer reference

The companion installer script `amneziawg-web-install.sh` (root-level) automates
the full installation process.

### Interactive mode

```bash
sudo ./amneziawg-web-install.sh
```

You will be prompted for all important settings; press Enter to accept the defaults.

### Non-interactive mode

```bash
# Source-build (recommended)
HASH="$(python3 -c "import argon2; print(argon2.PasswordHasher().hash('yourpassword'))")"

sudo ./amneziawg-web-install.sh \
  --non-interactive \
  --source-dir ./amneziawg-web \
  --username admin \
  --password-hash "${HASH}"

# Pre-built binary (advanced / CI)
sudo ./amneziawg-web-install.sh \
  --non-interactive \
  --binary-src ./target/release/amneziawg-web \
  --username admin \
  --password-hash "${HASH}"
```

### All options

| Option | Default | Description |
|---|---|---|
| `--source-dir DIR` | *(auto-detected)* | Build from source in this directory |
| `--binary-src PATH` | `./target/release/amneziawg-web` | Path to a pre-built binary |
| `--install-rust` | *(off)* | Install Rust via rustup if cargo is missing |
| `--install-dir DIR` | `/usr/local/bin` | Binary installation directory |
| `--data-dir DIR` | `/var/lib/amneziawg-web` | SQLite database directory |
| `--env-file FILE` | `/etc/amneziawg-web/env.conf` | Generated environment file path |
| `--config-dir DIR` | `/etc/amneziawg/clients` | AWG client config directory |
| `--host HOST` | `127.0.0.1` | Bind host |
| `--port PORT` | `8080` | Bind port |
| `--username NAME` | `admin` | Admin username |
| `--password-hash HASH` | *(required in non-interactive)* | Argon2id PHC hash |
| `--poll-interval SECS` | `30` | Polling interval |
| `--session-ttl SECS` | `86400` | Session lifetime |
| `--no-enable` | — | Skip enabling service at boot |
| `--no-start` | — | Skip starting service immediately |
| `--force` | — | Overwrite existing env.conf without prompting |
| `--non-interactive` | — | Run without prompts |

> `--source-dir` and `--binary-src` are mutually exclusive. Use `--source-dir` to
> build from source, or `--binary-src` to install a pre-built binary.

### What the installer does

1. **Preflight checks** – verifies root, systemd, AWG binary, and application binary (or source)
2. **Build** – *(source mode only)* verifies Rust toolchain and runs `cargo build --release`
3. **User + directories** – creates `awg-web` system user, data dir (`0750`), env dir (`0700`)
4. **Binary install** – copies binary to `--install-dir`
5. **Sudoers** – installs `/etc/sudoers.d/amneziawg-web` (`0440`) granting `awg-web` passwordless sudo for AWG inspection, peer removal, and config sync
6. **Env file** – writes all runtime variables to `--env-file` with mode `0600`
7. **Service** – installs systemd unit, reloads daemon, optionally enables and starts

### Re-running / upgrading

The installer is idempotent:
- System user is not recreated if it exists
- Existing env file is preserved unless `--force` is given
- Existing service unit is preserved unless `--force` is given

To upgrade, use the dedicated upgrade script (see [Upgrade reference](#upgrade-reference)):

```bash
# Rebuild from source and upgrade
sudo ./amneziawg-web-upgrade.sh --source-dir ./amneziawg-web

# Or upgrade with a pre-built binary
sudo ./amneziawg-web-upgrade.sh --binary ./target/release/amneziawg-web
```

---

## Upgrade reference

A companion upgrade script is provided at the repository root:

```bash
# Rebuild from source and upgrade (recommended)
sudo ./amneziawg-web-upgrade.sh --source-dir ./amneziawg-web

# Or upgrade with a pre-built binary
sudo ./amneziawg-web-upgrade.sh --binary ./target/release/amneziawg-web
```

Like the installer, the root-level `amneziawg-web-upgrade.sh` is a thin legacy wrapper
that delegates to `amneziawg-web.sh`, which in turn runs
`amneziawg-web/scripts/amneziawg-web-upgrade.sh`.

If the web panel was installed via the standalone wrapper and the repository files are
not present locally, `amneziawg-web.sh` will shallow-clone the repository to a
temporary directory automatically (source-mode upgrades will then build from that
checkout). Only the wrapper script itself needs to be present; the repository tree is
fetched on demand when missing.

### Default behavior

The upgrade script replaces the installed binary while preserving everything else:

| Action | What happens |
|---|---|
| **Built** | *(source mode)* compiled from source via `cargo build --release` |
| **Replaced** | installed binary (`/usr/local/bin/amneziawg-web`) |
| **Restarted** | service (only if it was active before upgrade) |
| **Preserved** | env/config directory (`/etc/amneziawg-web/`) |
| **Preserved** | data directory (`/var/lib/amneziawg-web/`) |
| **Preserved** | systemd unit file (unless `--refresh-unit` is given) |
| **Preserved** | service user (`awg-web`) |

### Restart behavior

By default, the upgrade script detects whether the service was running:
- If **active**: the service is stopped, the binary is replaced, and the service is restarted
- If **inactive**: the binary is replaced; the service is left inactive

Use `--restart` to force a restart even if the service was inactive, or `--no-restart`
to skip restarting entirely.

### Interactive mode

```bash
sudo ./amneziawg-web-upgrade.sh --source-dir ./amneziawg-web
```

The script prints a plan showing what will be replaced and what will be preserved,
then asks for confirmation.

### Non-interactive mode

```bash
sudo ./amneziawg-web-upgrade.sh --source-dir ./amneziawg-web --force
# or equivalently:
sudo ./amneziawg-web-upgrade.sh --source-dir ./amneziawg-web --non-interactive
```

### CI/automation example

```bash
sudo ./amneziawg-web-upgrade.sh \
  --source-dir ./amneziawg-web \
  --force --restart

# Or with a pre-built binary:
sudo ./amneziawg-web-upgrade.sh \
  --binary ./target/release/amneziawg-web \
  --force --restart
```

### Refreshing the systemd unit

If the service unit file has changed in the repository, use `--refresh-unit`:

```bash
sudo ./amneziawg-web-upgrade.sh \
  --source-dir ./amneziawg-web \
  --refresh-unit --force
```

This reinstalls the unit file from the repository copy and reloads the systemd daemon.
The `EnvironmentFile` directive is automatically updated to match your `--env-file` path.

### All options

| Option | Default | Description |
|---|---|---|
| `--source-dir DIR` | *(auto-detected)* | Build from source in this directory |
| `--binary PATH` | — | Path to a pre-built replacement binary |
| `--install-rust` | *(off)* | Install Rust via rustup if cargo is missing |
| `--install-dir DIR` | `/usr/local/bin` | Binary install directory |
| `--env-file FILE` | `/etc/amneziawg-web/env.conf` | Env/config file path |
| `--data-dir DIR` | `/var/lib/amneziawg-web` | Data directory |
| `--restart` | *(off)* | Always restart service after upgrade |
| `--no-restart` | *(off)* | Never restart service after upgrade |
| `--refresh-unit` | *(off)* | Reinstall systemd unit from repository copy |
| `--force` | *(off)* | Skip confirmation prompts |
| `--non-interactive` | *(off)* | Alias for `--force`; suitable for CI/automation |
| `--help` | — | Show usage |

> `--source-dir` and `--binary` are mutually exclusive. If neither is given,
> the script auto-detects the source directory from the repository layout.

### Path assumptions

The upgrade script assumes the same default paths as the installer. If you used
custom `--install-dir`, `--data-dir`, or `--env-file` during installation,
pass the same values to the upgrade script:

```bash
sudo ./amneziawg-web-upgrade.sh \
  --source-dir ./amneziawg-web \
  --install-dir /opt/awg/bin \
  --env-file /opt/awg/env.conf \
  --data-dir /opt/awg/data \
  --force
```

### What the upgrade script does

1. **Resolve binary** – builds from source (`--source-dir`) or uses provided binary (`--binary`)
2. **Validate** – verifies the existing installation and source binary
3. **Plan** – prints what will be replaced and what will be preserved
4. **Confirm** – asks for confirmation (skipped with `--force`)
5. **Stop** – stops the service if it was active
6. **Replace binary** – copies source to temp file, then atomically moves it
7. **Refresh unit** – *(only with `--refresh-unit`)* reinstalls the unit file, reloads daemon
8. **Restart** – restarts the service based on restart policy

---

## Uninstaller reference

A companion uninstall script is provided at the repository root:

```bash
sudo ./amneziawg-web-uninstall.sh
```

Like the installer, the root-level `amneziawg-web-uninstall.sh` is a thin legacy wrapper
that delegates to `amneziawg-web.sh`, which in turn runs
`amneziawg-web/scripts/amneziawg-web-uninstall.sh`.

If the web panel was installed via the standalone wrapper and the repository files are
not present locally, `amneziawg-web.sh` will shallow-clone the repository to a
temporary directory automatically:

```bash
# Works even if you never cloned the repository
sudo ./amneziawg-web-uninstall.sh
```

### Default behavior (safe)

By default, the uninstaller removes the service integration and installed binary
while preserving all configuration and data:

| Action | What happens |
|---|---|
| **Removed** | systemd service (stopped + disabled) |
| **Removed** | systemd unit file (`/etc/systemd/system/amneziawg-web.service`) |
| **Removed** | sudoers drop-in (`/etc/sudoers.d/amneziawg-web`) |
| **Removed** | installed binary (`/usr/local/bin/amneziawg-web`) |
| **Reloaded** | systemd daemon |
| **Preserved** | env/config directory (`/etc/amneziawg-web/`) |
| **Preserved** | data directory (`/var/lib/amneziawg-web/`) |
| **Preserved** | service user (`awg-web`) |

This makes uninstall reversible — re-install with `./amneziawg-web-install.sh --force`
and your configuration and database are still in place.

### Interactive mode

```bash
sudo ./amneziawg-web-uninstall.sh
```

The script prints a plan showing what will be removed and what will be preserved,
then asks for confirmation before proceeding.

### Non-interactive mode

```bash
sudo ./amneziawg-web-uninstall.sh --force
# or equivalently:
sudo ./amneziawg-web-uninstall.sh --non-interactive
```

### Purge flags

To remove configuration or data, you must explicitly request it:

```bash
# Remove config + data, no prompts
sudo ./amneziawg-web-uninstall.sh --purge-config --purge-data --force

# Full cleanup including service user
sudo ./amneziawg-web-uninstall.sh --purge-config --purge-data --remove-user --force
```

### All options

| Option | Default | Description |
|---|---|---|
| `--install-dir DIR` | `/usr/local/bin` | Binary install directory |
| `--data-dir DIR` | `/var/lib/amneziawg-web` | Data directory |
| `--env-file FILE` | `/etc/amneziawg-web/env.conf` | Env/config file path |
| `--purge-config` | *(off)* | Also remove env/config directory |
| `--purge-data` | *(off)* | Also remove data directory and all data |
| `--remove-user` | *(off)* | Also remove the service user (`awg-web`) |
| `--force` | *(off)* | Skip confirmation prompts |
| `--non-interactive` | *(off)* | Alias for `--force`; suitable for CI/automation |
| `--help` | — | Show usage |

### Path assumptions

The uninstaller assumes the same default paths as the installer. If you used
custom `--install-dir`, `--data-dir`, or `--env-file` during installation,
pass the same values to the uninstaller:

```bash
sudo ./amneziawg-web-uninstall.sh \
  --install-dir /opt/awg/bin \
  --data-dir /opt/awg/data \
  --env-file /opt/awg/env.conf \
  --force
```

### What the uninstaller does

1. **Plan** – prints what will be removed and what will be preserved
2. **Confirm** – asks for confirmation (skipped with `--force`)
3. **Stop + disable** – gracefully stops and disables the systemd service
4. **Remove unit** – deletes the systemd unit file, reloads daemon
5. **Remove sudoers** – deletes `/etc/sudoers.d/amneziawg-web`
6. **Remove binary** – deletes the installed binary
7. **Purge config** – *(only with `--purge-config`)* removes the env/config directory
8. **Purge data** – *(only with `--purge-data`)* removes the data directory
9. **Remove user** – *(only with `--remove-user`)* removes the service user
