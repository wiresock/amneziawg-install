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
- **Old-peer cleanup** – disabled peers with no linked client config can have
  their saved metadata and traffic history deleted from the panel. The public
  key remains archived and disabled so enforcement can continue.
- **Traffic history** – counter-reset-safe per-snapshot deltas over 24 h / 7 d / 30 d.
- **Proxy session visibility** – when `amneziawg-proxy` is enabled (AmneziaWG 2.0
  interfaces only), reads its local status file and shows active remote client sessions
  on the peer list.
- **Session cookie authentication** – Argon2id password verification,
  32-byte cryptographically random session IDs, configurable TTL.
- **Bearer token** – optional static token for headless API access.
- **CSRF protection** – per-session tokens on all write forms;
  short-lived single-use pre-login token on the login form.
- **Login rate limiting** – 5 attempts per 5-minute window per client IP.
- **Audit logging** – `peer_updated`, `peer_archived`, `peer_restored`,
  `login_success`, `login_failed`, `logout`,
  `user_create_requested`, `user_created`, `user_create_failed`,
  `user_remove_requested`, `user_removed`, `user_remove_failed`
  written to the `events` table; queryable via `GET /api/events`.
- **User lifecycle** – add and remove AmneziaWG clients directly from the panel,
  implemented natively in Rust (no install-script bridge for lifecycle operations).
- **Server-rendered HTML** – peer list, peer detail, edit form, add/remove user,
  recent activity — no JavaScript framework.
- **Zero external services** – one application binary, one root-owned helper,
  and one SQLite file; no separate database or container runtime.

---

## Architecture

```
┌────────────────────────────────────────────────────┐
│                     Host OS                        │
│                                                    │
│  ┌──────────┐    ┌──────────────────────────────┐  │
│  │ AWG kern │◄───│ validated helper (root:root) │  │
│  │  module  │    │ mode 0755; fixed commands    │  │
│  └──────────┘    └──────────▲───────────────────┘  │
│                             │ exact sudoers path    │
│  ┌──────────────────────────┴───────────────────┐  │
│  │      amneziawg-web (runs as awg-web user)    │  │
│  │                                              │  │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────┐ │  │
│  │  │  Poller  │  │ SQLite   │  │ axum HTTP  │ │  │
│  │  │ (tokio)  │─►│  (sqlx)  │◄─│  router   │ │  │
│  │  └──────────┘  └──────────┘  └────────────┘ │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  /usr/local/libexec/amneziawg-web-privileged      │
│  /etc/sudoers.d/amneziawg-web                     │
│  /etc/amnezia/amneziawg/clients/*.conf            │
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

The installer lives at the repository root, next to `amneziawg-install.sh`.
If you run it from a repository checkout, it auto-detects `./amneziawg-web` and builds from source automatically:

```bash
git clone https://github.com/wiresock/amneziawg-install.git
cd amneziawg-install

# 1. Install AmneziaWG (if not already done)
sudo ./amneziawg-install.sh

# 2. Install the web panel (builds from source automatically)
sudo ./amneziawg-web.sh install

# Or install Rust automatically if not present:
sudo ./amneziawg-web.sh install --install-rust
```

If you prefer not to clone the repository with Git, download just
`amneziawg-web.sh`. It handles cloning and build steps automatically (this
requires `git` to be installed).
If `git` is not available, build `amneziawg-web` manually and use `--binary-src` as shown below.

If you already have a pre-built binary:

```bash
sudo ./amneziawg-web.sh install --binary-src ./target/release/amneziawg-web
```

The installer handles user creation, directory setup, privileged-helper installation,
environment file generation, password hashing, and systemd service installation
interactively.
For non-interactive / automated installs, see [docs/INSTALL.md](docs/INSTALL.md).

### Upgrading

To upgrade by rebuilding from source:

```bash
sudo ./amneziawg-web.sh upgrade
```

To upgrade with a pre-built binary:

```bash
sudo ./amneziawg-web.sh upgrade --binary ./target/release/amneziawg-web
```

The upgrade script replaces the binary, root-owned privileged helper, and the AWG
lifecycle script when its installer ownership marker is present, then restarts the
service if it was running. Unmarked operator-managed lifecycle scripts, configuration,
data, and the systemd unit are preserved by default.
See [docs/INSTALL.md](docs/INSTALL.md) for full details.

### Uninstalling

To remove the web panel:

```bash
# Safe uninstall: removes service + helper + binary, preserves config/data
sudo ./amneziawg-web.sh uninstall

# Full purge: also removes config and data
sudo ./amneziawg-web.sh uninstall --purge-config --purge-data --force
```

By default the uninstaller is safe: it stops the service and removes the helper and
application binary but keeps your configuration and database intact. See
[docs/INSTALL.md](docs/INSTALL.md) for full details.

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
| `AWG_WEB_DB` | `awg-web.db` | Path to SQLite database file (created automatically) |
| `AWG_CONFIG_DIR` | `/etc/amnezia/amneziawg/clients` | Directory of client `.conf` files |
| `AWG_POLL_INTERVAL` | `30` | Polling interval in seconds |
| `AWG_PROXY_SESSIONS_FILE` | `/var/lib/amneziawg-proxy/sessions.json` | Optional proxy active-session status file |
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
| `GET` | `/` | Yes | HTML peer list + add user form; `?show_archived=true` includes archived disabled keys |
| `GET` | `/peers/:id` | Yes | HTML peer detail + edit form + remove user + activity |
| `GET` | `/archived/peers/:id` | Yes | Minimal archived-key detail and retained audit activity |
| `POST` | `/peers/:id` | Yes | HTML form update (PRG redirect) |
| `POST` | `/admin/peers/:id/archive` | Yes | Delete an eligible disabled peer's saved metadata and traffic history, then hide its retained key |
| `POST` | `/admin/peers/:id/restore` | Yes | Return an archived key to the normal list as a blank, still-disabled peer |
| `POST` | `/admin/users/add` | Yes | HTML form: add new user (PRG redirect) |
| `POST` | `/admin/users/:id/remove` | Yes | HTML form: remove user (PRG redirect) |
| `POST` | `/admin/protocol/enable-awg3` | Yes | Confirmed HTML form: probe support and atomically migrate the interface plus all clients to AWG 3.0 (incompatible with `amneziawg-proxy`) |
| `POST` | `/admin/protocol/disable-awg3` | Yes | Confirmed HTML form: atomically return the interface plus all clients to AWG 2.0 |
| `GET` | `/login` | No | Login form |
| `POST` | `/login` | No | Validate credentials, set cookie |
| `POST` | `/logout` | No | Clear session cookie |
| `GET` | `/api/health` | No | Liveness probe `{"status":"ok"}` |
| `GET` | `/api/peers` | Yes | List normal peers; `?include_archived=true` also returns archived summaries with `archived: true`; proxied peers carry `proxy_remote_addr` |
| `GET` | `/api/peers/:id` | Yes | Normal peer detail (50 recent snapshots, `proxy_remote_addr` when proxied); archived keys return `404` |
| `PATCH` | `/api/peers/:id` | Yes | Update `display_name` and/or `comment` |
| `GET` | `/api/peers/:id/history` | Yes | Traffic history (`?range=24h\|7d\|30d`) |
| `GET` | `/api/system/status` | Yes | System time, boot time, and uptime context for current counters (`server_*` aliases are retained for compatibility) |
| `GET` | `/api/proxy/sessions` | Yes | Active sessions reported by `amneziawg-proxy` status file; sessions carry `peer_id`/`peer_name` when the backend socket matches a peer endpoint |
| `GET` | `/api/events` | Yes | Audit log (`?peer_id=`, `?event_type=`, `?limit=`) |
| `POST` | `/api/admin/users` | Yes | JSON API: create user `{"name":"...","comment":"optional note"}` (`comment` optional, max 512 characters) |
| `POST` | `/api/admin/users/:id/remove` | Yes | JSON API: remove user |
| `GET` | `/api/admin/protocol` | Yes | Normalized protocol status (`2.0` for legacy/missing state, otherwise `3.0`) |

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
| Audit log | Every peer write, protocol migration, login, and logout recorded |
| No shell injection | The helper is called via `Command::new()` with explicit arguments and invokes fixed absolute binaries without shell interpolation |
| AWG access | The sudoers rule allows only a root-owned validating helper; no command-argument globs are granted |

### AWG privilege model

The service runs as a dedicated non-root user (`awg-web`).  Managing AWG
interface state requires root-level `CAP_NET_ADMIN`.  Rather than running
the entire service as root, the installer places a validating helper at
`/usr/local/libexec/amneziawg-web-privileged` (`0755 root:root`) and configures
the sudoers drop-in at `/etc/sudoers.d/amneziawg-web` to allow only that exact
executable path:

```
awg-web ALL=(root) NOPASSWD: /usr/local/libexec/amneziawg-web-privileged
```

The helper accepts only the supported subcommands and validates argument
counts, interface and client names, peer keys, AllowedIPs, and configuration
paths. Server-config mutations are semantic: it reconstructs only a validated
peer block or removes one exact managed-client block while holding a stable
lock, then atomically replaces the file. State reads redact private keys and
PSKs and expose only the fields the panel needs. Reconciliation accepts only
validated disabled-peer keys and derives the trusted config inside the helper,
so the service cannot read or submit arbitrary root-owned configuration
content. This keeps dynamic arguments out of sudoers while providing the AWG
inspection, peer management, and config synchronization the panel requires.
Application invocations use `Command::new()` with explicit argument arrays —
no shell interpolation.

Protocol migration is also routed through the helper. It resolves only the
root-owned lifecycle script recorded beside the service's configured
environment file, accepts only fixed enable/disable operations, and suppresses
script output. The header-protection key is provided to the unprivileged
process only through the existing safe-parameter projection needed to create
AWG 3.0 client configs; it is never rendered in HTML, returned by the status
API, or written to application logs.

> [!WARNING]
> **Compatibility with amneziawg-proxy:**
> `amneziawg-proxy` is compatible **only with AmneziaWG 2.0**. Enabling AWG 3.0 via
> `/admin/protocol/enable-awg3` will cause `amneziawg-proxy` to fail packet classification
> and stop camouflaging traffic. If `amneziawg-proxy` is in use, keep the interface on AWG 2.0.

**Troubleshooting:** If peer polling fails with "Operation not permitted",
verify the sudoers file exists and is correct:

```bash
cat /etc/sudoers.d/amneziawg-web
sudo -u awg-web sudo -n /usr/local/libexec/amneziawg-web-privileged show-all
```

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
| 2 | `friendly_name` | Derived from config filename (e.g. `awg0-client-gramm.conf` → `gramm`) |
| 3 | `config_name` | Stem of matching `*.conf` file (e.g. `awg0-client-gramm`) |
| 4 | `peer-<prefix>` | First 8 chars of public key |

The `friendly_name` is automatically extracted from the config filename when
it matches the `*-client-<suffix>` pattern used by the AmneziaWG installer.

## Peer status model

Peer status is split into two independent dimensions:

| Dimension | Values | Meaning |
|---|---|---|
| **Connection** (`connection_status`) | `online`, `inactive`, `never`, `disabled` | Network activity state |
| **Identity** (`identity_status`) | `linked`, `unlinked` | Config file mapping state |

The legacy `status` field is still present in the API for backward compatibility.

### Archived disabled keys

The **Forget old peer data** action is available only when a peer is disabled,
has no linked client configuration, and has finished lifecycle reconciliation.
It atomically clears the current peer record's display metadata, observed
network state, counters, config mapping, and traffic snapshots, then hides the
row from normal lists and detail/data routes.

The panel retains the peer ID, public key, disabled state, timestamps, and audit
history. Audit payloads may contain earlier names or comments. AmneziaWG config
files are not changed, and this feature is not forensic secure erasure. The
archived key stays in disabled-key enforcement; returning it to the peer list
does not recover deleted data and leaves it disabled.

---

## Development

```bash
# Run tests
cargo test           # 204 tests

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
