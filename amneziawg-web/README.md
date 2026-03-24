# amneziawg-web

A self-hosted web panel that provides **visibility and management** for
[AmneziaWG (AWG)](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
installations managed via the
[amneziawg-install](https://github.com/wiresock/amneziawg-install) script.

> **Status:** MVP – background poller, traffic history, config discovery, peer rename/comment, session cookie authentication, CSRF protection, login rate limiting · production-ready only behind a trusted reverse proxy (see [Security](#security) and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md))

---

## What is implemented

- **Background poller** – calls `awg show all dump` every N seconds (default: 30), stores per-peer snapshots in SQLite, keeps the `peers` table up-to-date, and runs a config-discovery scan after each AWG poll.
- **Config discovery** – scans `AWG_CONFIG_DIR` for `*.conf` files, extracts `[Peer] PublicKey`, and maps each config file to the corresponding live peer.
- **Peer rename / comment** – `PATCH /api/peers/:id` and a plain-HTML form on `/peers/:id`.
- **Session cookie authentication** – single-admin login via `GET /login` + `POST /login`; optional bearer-token for headless API access; configurable via environment variables.
- **CSRF protection** – every HTML form carries a hidden `csrf_token` field; `POST /login` uses a short-lived pre-login token; write forms use per-session tokens.
- **Login rate limiting** – 5 attempts per 5-minute window per client IP; returns `429 Too Many Requests` when exceeded.
- **`GET /`** – server-rendered HTML peer list.
- **`GET /peers/:id`** – server-rendered HTML peer detail + edit form.
- **`GET /api/health`** – liveness probe (always public).
- **`GET /api/peers`** – peer list JSON.
- **`GET /api/peers/:id`** – peer detail JSON (50 most-recent snapshots).
- **`GET /api/peers/:id/history?range=24h|7d|30d`** – traffic history.
- **Status derivation** – `online` / `inactive` / `disabled` / `unlinked`.
- **Display-name fallback** – `display_name` → `config_name` → `peer-<key-prefix>`.

---

## Quick start

```bash
cd amneziawg-web
cargo build --release

# Development: auth off
./target/release/amneziawg-web

# Production: auth on
export AUTH_ENABLED=true
export AUTH_USERNAME=admin
export AUTH_PASSWORD_HASH="$(\
  python3 -c "import argon2; print(argon2.PasswordHasher().hash('your-password'))")"
./target/release/amneziawg-web
```

---

## Configuration

| Env var               | Default                      | Description                                         |
|-----------------------|------------------------------|-----------------------------------------------------|
| `AWG_WEB_LISTEN`      | `0.0.0.0:8080`               | TCP bind address                                    |
| `AWG_WEB_DB`          | `awg-web.db`                 | Path to SQLite file                                 |
| `AWG_CONFIG_DIR`      | `/etc/amneziawg/clients`     | Directory of client `.conf` files                   |
| `AWG_POLL_INTERVAL`   | `30`                         | Polling interval in seconds                         |
| `RUST_LOG`            | `amneziawg_web=info`         | Log level filter                                    |
| `AUTH_ENABLED`        | `false`                      | Enable authentication (set `true` in production)    |
| `AUTH_USERNAME`       | `admin`                      | Admin username                                      |
| `AUTH_PASSWORD_HASH`  | *(empty)*                    | Argon2id PHC string of the admin password           |
| `AUTH_API_TOKEN`      | *(absent)*                   | Optional static bearer token for API access         |
| `AUTH_SECURE_COOKIE`  | `false`                      | Set `Secure` flag on session cookie (enable for HTTPS) |
| `AUTH_SESSION_TTL_SECS` | `86400`                    | Session lifetime in seconds (default 24 h)          |

---

## Authentication

### Generate a password hash

```bash
python3 -c "import argon2; print(argon2.PasswordHasher().hash('yourpassword'))"
```

The resulting string looks like:  
`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`

Store it in `AUTH_PASSWORD_HASH`.

### Login / logout

- Navigate to `http://<host>:<port>/login`.
- Enter username and password.
- On success, a session cookie (`awg_session`) is set (`HttpOnly`, `SameSite=Lax`).
- The logout button on every page clears the session.

### Bearer token (API)

For headless automation, set `AUTH_API_TOKEN` to a long random string:

```bash
export AUTH_API_TOKEN="$(openssl rand -hex 32)"
curl -H "Authorization: Bearer $AUTH_API_TOKEN" http://localhost:8080/api/peers
```

Bearer tokens only work for `/api/` paths.  HTML pages always require a session cookie.

### AUTH_ENABLED=false

When `AUTH_ENABLED=false`, all requests are accepted without credentials.  
**Never expose this on a public network.**

---

## Peer naming

| Priority | Source             | When used                              |
|----------|--------------------|----------------------------------------|
| 1        | `display_name`     | User has explicitly set a name         |
| 2        | `config_name`      | Matching `*.conf` file was discovered  |
| 3        | `peer-<prefix>`    | Fallback from the public key prefix    |

### Update a name or comment

**Via the API:**

```http
PATCH /api/peers/:id
Content-Type: application/json
Authorization: Bearer <token>

{ "display_name": "Ivan iPhone", "comment": "Main phone" }
```

- Both fields are optional. Absent fields are left unchanged.
- Empty / blank strings clear the field (set to NULL).
- `display_name` max 128 chars; `comment` max 512 chars.
- Returns 404 if the peer does not exist.

**Via the HTML UI:** Navigate to `/peers/:id` and fill in the "Edit peer" form.

---

## API

| Method | Path                     | Auth required | Description                         |
|--------|--------------------------|---------------|-------------------------------------|
| GET    | `/`                      | Yes           | HTML peer list                      |
| GET    | `/peers/:id`             | Yes           | HTML peer detail + edit form        |
| POST   | `/peers/:id`             | Yes           | HTML form submit (PRG redirect)     |
| GET    | `/login`                 | No            | Login form                          |
| POST   | `/login`                 | No            | Validate credentials, set cookie    |
| POST   | `/logout`                | No            | Clear session cookie                |
| GET    | `/api/health`            | No            | Liveness probe                      |
| GET    | `/api/peers`             | Yes           | List all peers                      |
| GET    | `/api/peers/:id`         | Yes           | Get one peer by integer ID          |
| PATCH  | `/api/peers/:id`         | Yes           | Update display name and/or comment  |
| GET    | `/api/peers/:id/history` | Yes           | Traffic history (`range=24h|7d|30d`)|

---

## Security

### What is in place

- Passwords stored as Argon2id PHC strings (never plaintext).
- Session IDs are 32 bytes from `OsRng` (cryptographically random, 64-char hex).
- Session cookies: `HttpOnly`, `SameSite=Lax`, configurable lifetime.
- HTML output is escaped via `esc()` – XSS safe.
- Private keys are never stored or logged.
- **CSRF protection**: every HTML form embeds a hidden `csrf_token`.  Login uses a short-lived (10-min, single-use) pre-login token.  Write forms use a per-session token.
- **Login rate limiting**: 5 attempts per 5-minute window per client IP; 429 on excess.

### What requires additional hardening before public exposure

| Risk | Recommended mitigation |
|------|------------------------|
| `Secure` cookie flag off by default | Set `AUTH_SECURE_COOKIE=true` when using HTTPS |
| Sessions lost on restart (in-memory store) | Acceptable for MVP; add DB-backed session store if needed |
| Rate limit trusts `X-Forwarded-For` | Validate at the reverse proxy layer |
| Single admin, no RBAC | Add roles in a future PR |

### Deployment recommendation

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for a full guide including
systemd service installation, nginx configuration, and environment setup.

In summary, run behind a reverse proxy (nginx, Caddy) that:
- Terminates TLS
- Sets `AUTH_SECURE_COOKIE=true`
- Restricts to trusted IP ranges
- Sets `X-Forwarded-For` header for accurate rate-limit keying

---

## Development

```bash
cargo test                        # 138 tests
cargo fmt --check
cargo clippy -- -D warnings
```

---

## License

MIT – see [`LICENSE`](LICENSE).
