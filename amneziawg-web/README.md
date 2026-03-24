# amneziawg-web

A self-hosted web panel for **visibility and management** of
[AmneziaWG (AWG)](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
installations managed via the
[amneziawg-install](https://github.com/wiresock/amneziawg-install) script.

> **Status: v0.1.0** – feature-complete for private self-hosted deployment.
> Suitable for single-admin home or corporate VPN monitoring behind a reverse proxy.

---

## Why this exists (vs. a status script)

A shell script like `awg show` gives you a live snapshot of the tunnel.
`amneziawg-web` adds persistent history, a browser UI, edit capabilities, authentication, and an audit trail — without requiring any external database or container infrastructure.

| Capability | `awg show` | amneziawg-web |
|---|---|---|
| Live peer status | ✓ | ✓ |
| Traffic history (24 h / 7 d / 30 d) | ✗ | ✓ |
| Peer rename + comment | ✗ | ✓ |
| Browser-accessible UI | ✗ | ✓ |
| JSON API | ✗ | ✓ |
| Session authentication | ✗ | ✓ |
| Audit log of admin actions | ✗ | ✓ |
| Config file association | ✗ | ✓ |

---

## Screenshots

> *Screenshots for the v0.1.0 release will appear here.*

| Peer list | Peer detail |
|---|---|
| *(peer list screenshot)* | *(peer detail + edit form screenshot)* |

---

## Feature list

- **Background poller** – polls `awg show all dump` every N seconds, stores
  per-peer traffic snapshots in SQLite, keeps the `peers` table current.
- **Config discovery** – scans `AWG_CONFIG_DIR` for `*.conf` files, correlates
  each config file with its live peer by public key.
- **Peer rename / comment** – `PATCH /api/peers/:id` (JSON) and
  `POST /peers/:id` (HTML form) with normalisation and field-level validation.
- **Traffic history** – counter-reset-safe per-snapshot deltas over 24 h / 7 d / 30 d.
- **Session cookie authentication** – Argon2id password verification,
  32-byte cryptographically random session IDs, configurable TTL.
- **Bearer token** – optional static token for headless API access.
- **CSRF protection** – per-session tokens on all write forms;
  short-lived single-use pre-login token on the login form.
- **Login rate limiting** – 5 attempts per 5-minute window per client IP.
- **Audit logging** – `peer_updated`, `login_success`, `login_failed`, `logout`
  written to the `events` table; queryable via `GET /api/events`.
- **Server-rendered HTML** – peer list, peer detail, edit form, recent activity — no JavaScript framework.
- **Zero external dependencies** – single binary + one SQLite file.

---

## Architecture

```
┌────────────────────────────────────────────────────┐
│                     Host OS                        │
│                                                    │
│  ┌──────────┐    ┌──────────────────────────────┐  │
│  │ AWG kern │◄───│     awg show all dump        │  │
│  │  module  │    └──────────┬───────────────────┘  │
│  └──────────┘               │                      │
│                             ▼                      │
│  ┌──────────────────────────────────────────────┐  │
│  │           amneziawg-web (this binary)        │  │
│  │                                              │  │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────┐ │  │
│  │  │  Poller  │  │ SQLite   │  │ axum HTTP  │ │  │
│  │  │ (tokio)  │─►│  (sqlx)  │◄─│  router   │ │  │
│  │  └──────────┘  └──────────┘  └────────────┘ │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  /etc/amneziawg/clients/*.conf                     │
└────────────────────────────────────────────────────┘
         ▲
  reverse proxy (nginx / Caddy)
         ▲
     browser / curl
```

The binary is a single async Tokio process. The poller and HTTP server run concurrently.
All state is in one SQLite file. No Redis, no Postgres, no container required.

---

## Quick start

### Using the installer (recommended for production)

The installer lives at the repository root, next to `amneziawg-install.sh`:

```bash
# 1. Install AmneziaWG (if not already done)
sudo ./amneziawg-install.sh

# 2. Build the web panel binary
cd amneziawg-web && cargo build --release && cd ..

# 3. Install the web panel
sudo ./amneziawg-web-install.sh
```

The installer handles user creation, directory setup, environment file generation,
password hashing, and systemd service installation interactively.
For non-interactive / automated installs, see [docs/INSTALL.md](docs/INSTALL.md).

### Manual / development

```bash
cd amneziawg-web
cargo build --release

# Development – auth disabled, local use only
./target/release/amneziawg-web

# Production – generate a password hash first
python3 -c "import argon2; print(argon2.PasswordHasher().hash('yourpassword'))"

AUTH_ENABLED=true \
AUTH_USERNAME=admin \
AUTH_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$...$...' \
./target/release/amneziawg-web
```

For a full production setup, see [docs/INSTALL.md](docs/INSTALL.md).

---

## Configuration

All settings are read from environment variables (or a `.env`-style file via systemd `EnvironmentFile`).

| Variable | Default | Description |
|---|---|---|
| `AWG_WEB_LISTEN` | `0.0.0.0:8080` | TCP bind address |
| `AWG_WEB_DB` | `awg-web.db` | Path to SQLite database file |
| `AWG_CONFIG_DIR` | `/etc/amneziawg/clients` | Directory of client `.conf` files |
| `AWG_POLL_INTERVAL` | `30` | Polling interval in seconds |
| `RUST_LOG` | `amneziawg_web=info` | Log level (`error`/`warn`/`info`/`debug`) |
| `AUTH_ENABLED` | `false` | Enable authentication (set `true` in production) |
| `AUTH_USERNAME` | `admin` | Admin username |
| `AUTH_PASSWORD_HASH` | *(empty)* | Argon2id PHC string |
| `AUTH_API_TOKEN` | *(absent)* | Static bearer token for headless API access |
| `AUTH_SECURE_COOKIE` | `false` | Add `Secure` flag to session cookie (use with HTTPS) |
| `AUTH_SESSION_TTL_SECS` | `86400` | Session lifetime in seconds (default 24 h) |

See [`.env.example`](.env.example) for a ready-to-copy template.

---

## API reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/` | Yes | HTML peer list |
| `GET` | `/peers/:id` | Yes | HTML peer detail + edit form + activity |
| `POST` | `/peers/:id` | Yes | HTML form update (PRG redirect) |
| `GET` | `/login` | No | Login form |
| `POST` | `/login` | No | Validate credentials, set cookie |
| `POST` | `/logout` | No | Clear session cookie |
| `GET` | `/api/health` | No | Liveness probe `{"status":"ok"}` |
| `GET` | `/api/peers` | Yes | List all peers |
| `GET` | `/api/peers/:id` | Yes | Peer detail (50 recent snapshots) |
| `PATCH` | `/api/peers/:id` | Yes | Update `display_name` and/or `comment` |
| `GET` | `/api/peers/:id/history` | Yes | Traffic history (`?range=24h\|7d\|30d`) |
| `GET` | `/api/events` | Yes | Audit log (`?peer_id=`, `?event_type=`, `?limit=`) |

---

## Security model

| Measure | Detail |
|---|---|
| Password storage | Argon2id PHC — never plaintext |
| Session IDs | 32 bytes from `OsRng`, 64-char hex |
| Cookie flags | `HttpOnly`, `SameSite=Lax`; `Secure` opt-in |
| XSS | All HTML output escaped via `esc()` |
| CSRF | Per-session token on write forms; short-lived pre-login token |
| Rate limiting | 5 login attempts per 5-minute window per IP; `429` on excess |
| Audit log | Every peer write, login, and logout recorded |
| No shell injection | AWG binary called via `Command::new()` with explicit args |

### Known limitations for v0.1.0

- Session store is in-memory; sessions are lost on restart.
- Single admin account; no RBAC.
- Not hardened for direct public internet exposure — use behind a reverse proxy.
- `Secure` cookie flag is opt-in (set `AUTH_SECURE_COOKIE=true` for HTTPS deployments).

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full deployment guide including
nginx and Caddy configurations.

---

## Peer naming

Names are resolved in priority order:

| Priority | Source | When used |
|---|---|---|
| 1 | `display_name` | Explicitly set by admin |
| 2 | `config_name` | Stem of matching `*.conf` file |
| 3 | `peer-<prefix>` | First 8 chars of public key |

---

## Development

```bash
# Run tests
cargo test           # 155 tests

# Check formatting
cargo fmt --check

# Check lints
cargo clippy -- -D warnings

# Run in dev mode (auth off)
cargo run
```

---

## Deployment

For a complete production deployment (binary install, systemd service, nginx,
environment file): see [docs/INSTALL.md](docs/INSTALL.md) and
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

Docker is also supported — see [`Dockerfile`](Dockerfile).

---

## Current limitations

- No traffic charts (data is stored; charts are a planned UI feature).
- No peer disable/enable from the UI.
- No client config download from the UI.
- Sessions reset on service restart (in-memory store).
- Single admin account (multi-user is planned).

---

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full epic list.

Recommended next steps after v0.1.0:
1. **Publish v0.1.0** – tag the release, binary upload
2. **Persistent sessions** – DB-backed session store
3. **Peer management** – enable/disable, config download
4. **Export / backup** – SQLite dump endpoint

---

## License

MIT — see [`LICENSE`](LICENSE).
