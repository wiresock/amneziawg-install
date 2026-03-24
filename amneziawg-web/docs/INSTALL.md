# Installation Guide

This guide covers building and deploying `amneziawg-web` on a Linux host.

For a quick orientation, see the [README](../README.md).
For production hardening details, see [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Linux | Any modern kernel | x86_64 or aarch64 |
| Rust toolchain | 1.75+ | Install via [rustup](https://rustup.rs/) |
| AmneziaWG | Any release | `awg` binary must be at `/usr/bin/awg` |
| SQLite | 3.x | No separate install needed — embedded in binary via sqlx |
| Reverse proxy | nginx ≥ 1.18 or Caddy 2 | Required for TLS in production |

`amneziawg-web` does **not** require a separate database server, Redis, or container runtime.

---

## 1. Build from source

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

## 4. AWG binary and config directory

`amneziawg-web` calls `/usr/bin/awg show all dump` to read tunnel state.

- The `awg` binary must exist at `/usr/bin/awg` (or you can symlink it there).
- The service user (`awg-web`) must be able to execute it.  On most systems this
  requires adding `awg-web` to the group that owns the AWG socket, or setting
  `CAP_NET_ADMIN` — follow your distribution's AWG installation guide.

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
