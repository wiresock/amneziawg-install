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
| 9 | Status derivation (split model)           | Connection: `online`/`inactive`/`never`/`disabled`; Identity: `linked`/`unlinked` |
|10 | Display-name fallback chain               | `display_name` → `friendly_name` → config stem → `peer-<prefix>`         |
|11 | Schema migrations `0001`–`0004`           | `config_name`, `config_path`, `friendly_name` on `peers`                 |
|12 | `GET /` – HTML peer list page             | Server-rendered; no JS framework; nav bar with logout                    |
|13 | `GET /peers/:id` – HTML peer detail page  | Identity block + edit form + recent snapshots; nav bar with logout       |
|14 | `POST /peers/:id` – HTML form submit      | PRG redirect; same normalisation as PATCH API                            |
|15 | Config discovery (`config_store`)         | Scans `*.conf`, extracts `[Peer] PublicKey` + `Address`; derives friendly name |
|16 | Config-to-peer mapping in poller          | Key match first, then AllowedIPs fallback; sets `has_config`, `config_name`, `friendly_name` |
|17 | Identity status driven by `has_config`    | `linked` / `unlinked` – separate from connection status                  |
|18 | Session cookie authentication             | `GET /login`, `POST /login`, `POST /logout`; Argon2id, `SameSite=Lax`   |
|19 | Auth middleware on all protected routes   | HTML → redirect `/login`; API → 401 JSON; health always public           |
|20 | Optional bearer token for API             | `Authorization: Bearer <token>` via `AUTH_API_TOKEN`                     |
|21 | 232 unit + integration tests              | Auth, domain, DB, config, history, web handler, script bridge layers     |
|22 | User create (direct)                     | `POST /api/admin/users`, HTML form at `/admin/users/add`; validates name; creates client directly via AWG commands (no install script) |
|23 | User remove via install script            | `POST /api/admin/users/:id/remove`, HTML form at `/admin/users/:id/remove`; confirmation required; reuses `amneziawg-install.sh --remove-client` |
|24 | Script bridge layer                       | `admin/script_bridge.rs`; explicit subprocess args; no shell interpolation; timeout handling; used for `--remove-client` and `--list-clients` only |
|25 | User lifecycle audit events               | `user_create_requested`, `user_created`, `user_create_failed`, `user_remove_requested`, `user_removed`, `user_remove_failed` |
|26 | Post-action config rescan                 | `poller::rescan_configs()` called after create/remove; no manual restart needed |

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
2. **`friendly_name`** – derived from the config filename by stripping the
   `*-client-` prefix (e.g. `"awg0-client-gramm.conf"` → `"gramm"`).
3. **`config_name`** – stem of the matching `.conf` filename (e.g. `"awg0-client-gramm"`).
4. **`peer-<8-char-prefix>`** – generated from the first 8 characters of the public key.

The `friendly_name` extraction uses the pattern `*-client-<suffix>` which is
the format created by the AmneziaWG install workflow.  If the filename does
not match this pattern, the full stem is used as the friendly name.

### Normalisation rules

| Field          | Max length | Trim | Empty/blank → |
|----------------|-----------|------|----------------|
| `display_name` | 128 chars  | Yes  | `NULL` (clear) |
| `comment`      | 512 chars  | Yes  | `NULL` (clear) |

---

## Peer status model

Peer status is split into two independent dimensions:

### Connection status (`connection_status`)

Describes the peer's network activity:

| Value      | Meaning |
|------------|---------|
| `online`   | Handshake within the last 3 minutes |
| `inactive` | Stale handshake (older than threshold) |
| `never`    | No handshake has ever been observed |
| `disabled` | Administratively disabled |

### Identity status (`identity_status`)

Describes whether the peer has been matched to a config file:

| Value      | Meaning |
|------------|---------|
| `linked`   | Peer matched to a `.conf` file (by public key or AllowedIPs) |
| `unlinked` | No matching config file found |

The legacy `status` field is still present in the API for backward
compatibility.  It combines both dimensions: `disabled` > `unlinked` >
`online` / `inactive`.

### Config matching strategy

The poller uses a layered matching strategy:

1. **Exact public-key match** – the `[Peer] PublicKey` in the client config
   is matched against the peer's public key from `awg show all dump`.
2. **AllowedIPs fallback** – if no key match is found, the config's
   `[Interface] Address` field is compared with the peer's `allowed_ips`.
   Only used when the match is unambiguous (exactly one candidate).
3. **No match** – the peer remains `unlinked` and uses a fallback name.

Diagnostic logging reports key matches, IP matches, ambiguous matches, and
unmatched configs at each polling cycle.

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
| Audit logging | ✓ `events` table; `peer_updated`, `login_success`, `login_failed`, `logout` |

---

## Audit logging

All write actions and auth events are appended to the `events` table and
never modify the same row in-place.

### Events logged

| Event type | When | Payload fields |
|---|---|---|
| `peer_updated` | `PATCH /api/peers/:id` and `POST /peers/:id` | `old_display_name`, `new_display_name`, `old_comment`, `new_comment` |
| `peer_disabled` | Enable/disable peer | `old_disabled`, `new_disabled` |
| `user_create_requested` | Before invoking install script to add client | `name` |
| `user_created` | After successful client creation | `name`, `config_path` |
| `user_create_failed` | After failed client creation | `name`, `error` |
| `user_remove_requested` | Before invoking install script to remove client | `peer_id`, `name` |
| `user_removed` | After successful client removal | `peer_id`, `name` |
| `user_remove_failed` | After failed client removal | `peer_id`, `name`, `error` |
| `login_success` | Successful `POST /login` | *(none)* |
| `login_failed`  | Failed credential check on `POST /login` | *(none)* |
| `logout`        | `POST /logout` | *(none)* |

### Actor model

For the current single-admin setup, `actor` is always the value of
`AUTH_USERNAME` (default `"admin"`). The field is stored verbatim so it
can be extended to multi-user attribution in the future without a schema
migration.

### Limitations

- No sensitive data is included in payloads (no passwords or tokens).
- Audit records are stored in the same SQLite database; they are lost if
  the database file is deleted or overwritten.
- Actor attribution is user-level only (no session or IP in the event record).
- The `events` table is append-only but not tamper-evident (no signatures).

---

## What is still missing before full production hardening

- **HTTPS** – TLS termination must be provided by a reverse proxy; set `AUTH_SECURE_COOKIE=true`.
- **Persistent session store** – current in-memory store resets on restart.
- **Traffic charts** – snapshots table exists but no chart is rendered.
