# MVP Definition

## Implemented

| # | Feature                                   | Notes                                                                    |
|---|-------------------------------------------|--------------------------------------------------------------------------|
| 1 | `awg show all dump` integration           | Read-only; no shell interpolation                                        |
| 2 | Background poller (every N seconds)       | Default 30 s; degrades gracefully if AWG absent                          |
| 3 | Peer snapshots stored in SQLite           | `snapshots` table; persistent history                                    |
| 4 | `peers` table kept up-to-date             | Upsert on every poll; includes `allowed_ips`                             |
| 5 | `GET /api/peers` – peer listing           | Status, name, endpoint, handshake, RX/TX, config fields                  |
| 6 | `GET /api/peers/:id` – peer detail        | 50 recent snapshots; 404 on missing peer                                 |
| 7 | `GET /api/peers/:id/history` – history    | `range=24h\|7d\|30d`; counter-reset safe                                 |
| 8 | `PATCH /api/peers/:id` – rename/comment   | Partial update; normalisation; 404 on missing peer                       |
| 9 | Status derivation                         | `online`/`inactive`/`disabled`/`unlinked`                                |
|10 | Display-name fallback chain               | `display_name` → config stem → `peer-<prefix>`                           |
|11 | Schema migrations `0001` + `0002`         | `config_name`, `config_path` on `peers`                                  |
|12 | `GET /` – HTML peer list page             | Server-rendered; no JS framework; nav bar with logout                    |
|13 | `GET /peers/:id` – HTML peer detail page  | Identity block + edit form + recent snapshots; nav bar with logout       |
|14 | `POST /peers/:id` – HTML form submit      | PRG redirect; same normalisation as PATCH API                            |
|15 | Config discovery (`config_store`)         | Scans `*.conf`, extracts `[Peer] PublicKey` + `Address`                  |
|16 | Config-to-peer mapping in poller          | Sets `has_config`, `config_name`, `config_path`; idempotent              |
|17 | `unlinked` status driven by `has_config`  | Correct once config mapping runs                                         |
|18 | Session cookie authentication             | `GET /login`, `POST /login`, `POST /logout`; Argon2id, `SameSite=Lax`   |
|19 | Auth middleware on all protected routes   | HTML → redirect `/login`; API → 401 JSON; health always public           |
|20 | Optional bearer token for API             | `Authorization: Bearer <token>` via `AUTH_API_TOKEN`                     |
|21 | 113 unit + integration tests              | Auth, domain, DB, config, history, web handler layers covered            |

---

## Authentication model

Single-admin session cookie auth.

### Session flow

1. `GET /login` renders a plain-HTML login form.
2. `POST /login` validates username + Argon2id password hash.
3. On success: a 32-byte random session token is stored in an in-memory `HashMap` and sent as an `HttpOnly; SameSite=Lax` cookie.
4. Subsequent requests: middleware extracts the cookie, looks up the token, checks expiry (24 h).
5. `POST /logout` removes the token from the store and clears the cookie.

### Bearer token (optional)

Set `AUTH_API_TOKEN` to allow headless API access via `Authorization: Bearer <token>` header.  Only works for `/api/` paths.

### Protected routes

| Route class | Unauthenticated response |
|-------------|--------------------------|
| `GET /`, `GET /peers/:id`, `POST /peers/:id` | 303 redirect → `/login` |
| `GET /api/peers`, `GET /api/peers/:id`, `PATCH /api/peers/:id`, `GET /api/peers/:id/history` | 401 JSON `{"error":"authentication required"}` |
| `GET /api/health`, `GET /login`, `POST /login`, `POST /logout` | Always public |

### Password hash generation

```bash
python3 -c "import argon2; print(argon2.PasswordHasher().hash('yourpassword'))"
```

---

## Peer naming

Every peer resolves its display name through this fallback chain:

1. **`display_name`** – explicitly set via `PATCH /api/peers/:id` or the HTML edit form.
2. **`config_name`** – stem of the matching `.conf` filename (e.g. `"ivan-iphone"`).
3. **`peer-<8-char-prefix>`** – generated from the first 8 characters of the public key.

### Normalisation rules

| Field          | Max length | Trim | Empty/blank → |
|----------------|-----------|------|----------------|
| `display_name` | 128 chars  | Yes  | `NULL` (clear) |
| `comment`      | 512 chars  | Yes  | `NULL` (clear) |

---

## Security notes

| Property | Status |
|----------|--------|
| Password plaintext stored | ✗ Never; Argon2id only |
| Password logged | ✗ Never |
| Auth headers logged | ✗ Never |
| Session IDs | 32-byte OsRng, 64-char hex |
| Cookie flags | `HttpOnly`, `SameSite=Lax`; `Secure` opt-in via `AUTH_SECURE_COOKIE` |
| Session TTL | Configurable via `AUTH_SESSION_TTL_SECS` (default 24 h) |
| XSS | `esc()` on all HTML output |
| CSRF | Per-session and pre-login CSRF tokens on all HTML forms |
| Login rate limiting | 5 per 5-minute window per IP; 429 on excess |
| Constant-time password check | ✓ via argon2 crate |
| Constant-time CSRF comparison | ✓ via folded-XOR `csrf_eq()` |

---

## What is still missing before full production hardening

- **HTTPS** – TLS termination must be provided by a reverse proxy; set `AUTH_SECURE_COOKIE=true`.
- **Persistent session store** – current in-memory store resets on restart.
- **Traffic charts** – snapshots table exists but no chart is rendered.
- **Audit logging** – write actions (peer edits) are not logged to an audit trail.
