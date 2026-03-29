# Deployment Guide

This document describes how to run `amneziawg-web` in production as a
private self-hosted service.

---

## Prerequisites

- Linux host with `amneziawg-web` binary compiled or installed at
  `/usr/local/bin/amneziawg-web`
- A reverse proxy (nginx, Caddy) in front for TLS termination
- `AUTH_ENABLED=true` with a valid `AUTH_PASSWORD_HASH`

---

## 1. Build the binary

```bash
cd amneziawg-web
cargo build --release
sudo install -m 0755 target/release/amneziawg-web /usr/local/bin/amneziawg-web
```

---

## 2. Create a system user and directories

```bash
# Dedicated non-root service user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin awg-web

# Database directory
sudo mkdir -p /var/lib/amneziawg-web
sudo chown awg-web:awg-web /var/lib/amneziawg-web

# Config directory for environment variables (keep secrets here)
sudo mkdir -p /etc/amneziawg-web
sudo chmod 0700 /etc/amneziawg-web
```

---

## 3. Generate a password hash

```bash
python3 -c "import argon2; print(argon2.PasswordHasher().hash('yourpassword'))"
```

The output looks like:
```
$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
```

---

## 4. Create the environment file

```bash
sudo tee /etc/amneziawg-web/env.conf << 'EOF'
AUTH_ENABLED=true
AUTH_USERNAME=admin
AUTH_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$REPLACE_THIS
AUTH_SESSION_TTL_SECS=86400
AUTH_SECURE_COOKIE=true
AUTH_API_TOKEN=

AWG_WEB_LISTEN=127.0.0.1:8080
AWG_WEB_DB=/var/lib/amneziawg-web/awg-web.db
AWG_CONFIG_DIR=/etc/amneziawg/clients
AWG_POLL_INTERVAL=30
RUST_LOG=amneziawg_web=info
EOF

sudo chmod 0600 /etc/amneziawg-web/env.conf
sudo chown root:root /etc/amneziawg-web/env.conf
```

Set `AUTH_API_TOKEN` to a long random string if you need headless API access:

```bash
openssl rand -hex 32
```

---

## 5. Configure AWG access (sudoers)

The service runs as `awg-web` (non-root) but needs to manage AWG interface
state.  Install a tightly-scoped sudoers rule:

```bash
echo 'awg-web ALL=(root) NOPASSWD: /usr/bin/awg show all dump, /usr/bin/awg set * peer * remove, /usr/bin/awg syncconf * /dev/stdin, /usr/bin/awg-quick strip *' \
  | sudo tee /etc/sudoers.d/amneziawg-web > /dev/null
sudo chmod 0440 /etc/sudoers.d/amneziawg-web
```

Verify:

```bash
sudo -u awg-web sudo -n /usr/bin/awg show all dump
```

> The installer does this automatically.  Manual setup is only needed for
> deployments that bypass the installer.

---

## 6. Install the systemd service

```bash
sudo cp packaging/amneziawg-web.service /etc/systemd/system/
# Uncomment the EnvironmentFile line in the unit file:
sudo sed -i 's|#EnvironmentFile=|EnvironmentFile=|' /etc/systemd/system/amneziawg-web.service

sudo systemctl daemon-reload
sudo systemctl enable --now amneziawg-web
sudo systemctl status amneziawg-web
```

---

## 7. Reverse proxy (nginx)

The panel listens on `127.0.0.1:8080` by default.  Terminate TLS with
nginx and proxy to the local socket.

```nginx
server {
    listen 443 ssl http2;
    server_name awg.example.com;

    ssl_certificate     /etc/letsencrypt/live/awg.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/awg.example.com/privkey.pem;

    # Restrict access to trusted IPs only (highly recommended)
    allow 10.0.0.0/8;
    deny all;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

> **Important:** The `X-Forwarded-For` header is used by the login rate
> limiter to identify clients by IP.  Only set this header from a trusted
> reverse proxy; never expose `amneziawg-web` directly on a public network.

### Caddy equivalent

```caddy
awg.example.com {
    @allowed remote_ip 10.0.0.0/8
    handle @allowed {
        reverse_proxy 127.0.0.1:8080
    }
    respond "Forbidden" 403
}
```

---

## 8. HTTPS and secure cookies

Set `AUTH_SECURE_COOKIE=true` whenever the panel is served over HTTPS.
This adds the `Secure` flag to the session cookie, preventing it from
being sent over plain HTTP.

---

## 9. Security notes

### CSRF protection

Every HTML form includes a hidden `csrf_token` field.

- **Login form** (`POST /login`): uses a short-lived (10-minute)
  pre-login CSRF token stored server-side.  Single-use: consumed on
  validation.
- **Logout form** (`POST /logout`) and **edit form** (`POST /peers/:id`):
  use a per-session CSRF token returned at login and stored in the
  session entry.

When `AUTH_ENABLED=false`, CSRF checks are bypassed.

### Login rate limiting

`POST /login` is rate-limited to **5 attempts per 5-minute window**
per client IP.  On the 6th attempt the response is `429 Too Many Requests`.

The IP is extracted from `X-Forwarded-For` (first entry) or `X-Real-IP`
headers.  Without a reverse proxy, all attempts are keyed to `"unknown"`
(global limit — document this if relevant to your deployment).

### SameSite cookies

Session cookies are set with `SameSite=Lax`.  This prevents:
- Cross-origin POST form submissions (CSRF via foreign pages)
- CSRF on simple same-site navigation

For stronger protection, set `SameSite=Strict` (future option).

### Private network deployment

The panel is designed for deployment on a private network (VPN, LAN,
internal-only reverse proxy).  It is not hardened for direct public
internet exposure.

---

## 10. Troubleshooting

### Peer polling fails with "Operation not permitted"

If the service logs show:

```
awg show all dump failed
Unable to access interface awg0: Operation not permitted
```

This means the sudoers rule is missing or incorrect.  Fix it:

```bash
# Verify the file exists
cat /etc/sudoers.d/amneziawg-web

# Expected content:
# awg-web ALL=(root) NOPASSWD: /usr/bin/awg show all dump, /usr/bin/awg set * peer * remove, /usr/bin/awg syncconf * /dev/stdin, /usr/bin/awg-quick strip *

# Test it manually
sudo -u awg-web sudo -n /usr/bin/awg show all dump

# If missing, recreate:
echo 'awg-web ALL=(root) NOPASSWD: /usr/bin/awg show all dump, /usr/bin/awg set * peer * remove, /usr/bin/awg syncconf * /dev/stdin, /usr/bin/awg-quick strip *' \
  | sudo tee /etc/sudoers.d/amneziawg-web > /dev/null
sudo chmod 0440 /etc/sudoers.d/amneziawg-web
sudo systemctl restart amneziawg-web
```

### Service fails to start after upgrade

If the systemd unit still has `NoNewPrivileges=yes`, sudo will not work.
Refresh the unit file:

```bash
sudo ./amneziawg-web.sh upgrade --source-dir ./amneziawg-web --refresh-unit --force
```

---

## 11. Remaining limitations before broader production use

| Area | Status | Recommended action |
|------|--------|--------------------|
| Session store | In-memory; lost on restart | Add DB-backed session store |
| CSRF tokens | SameSite=Lax + per-form tokens | Add SameSite=Strict option |
| Rate limit IP | Trusts X-Forwarded-For | Validate at proxy layer |
| TLS | Handled by reverse proxy | Use Caddy/nginx with Let's Encrypt |
| Multi-user | Not implemented | Future feature |
