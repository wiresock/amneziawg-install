# Roadmap

## Epic 1 – Core AWG Integration ✅ complete

- [x] Execute `awg show all dump` via `std::process::Command`
- [x] Parse output into `AwgInterface` / `AwgPeer` structs
- [x] Handle missing binary gracefully (warn + skip cycle)
- [x] `allowed_ips` saved in `peers` table on every poll

---

## Epic 2 – Config Discovery ✅ complete

- [x] Scan config directory for `*.conf` files (non-recursive)
- [x] Extract `[Peer] PublicKey` + `[Interface] Address`
- [x] Schema columns `config_name`, `config_path` added to `peers`
- [x] Poller runs config scan after each AWG poll cycle
- [x] Idempotent mapping: clear-then-apply on every cycle
- [x] Warn+skip on unreadable files; skip-on-missing-dir
- [x] `unlinked` status correctly driven by `has_config`

---

## Epic 3 – Database & Migrations ✅ complete

- [x] SQLite via sqlx; `peers`, `snapshots`, `events`, `interfaces`, `users` tables
- [x] Migrations `0001` (schema) + `0002` (`config_name`, `config_path`)
- [x] `update_peer_metadata` for rename/comment support

---

## Epic 4 – Poller & Snapshots ✅ complete

- [x] Background Tokio task, configurable interval
- [x] Snapshot insertion per poll; peer upsert (including `allowed_ips`)
- [x] Config mapping step after AWG step; logged per cycle

---

## Epic 5 – Traffic History & Basic UI ✅ complete

- [x] `GET /api/peers/:id/history?range=24h|7d|30d`
- [x] Per-snapshot deltas with counter-reset handling
- [x] `GET /` – server-rendered HTML peer list
- [x] `GET /peers/:id` – server-rendered HTML peer detail + edit form

---

## Epic 6 – Peer Rename & Comment ✅ complete

- [x] `normalize_display_name()` / `normalize_comment()` in domain layer
- [x] `update_peer_metadata(pool, id, name, comment)` DB function
- [x] `PATCH /api/peers/:id` – JSON API endpoint (partial update)
- [x] `POST /peers/:id` – HTML form endpoint (PRG redirect)

---

## Epic 7 – Authentication ✅ complete

- [x] `AuthConfig` struct with `enabled`, `username`, `password_hash`, `api_token`, `secure_cookie`
- [x] Argon2id password verification (constant-time)
- [x] In-memory session store with lazy expiry cleanup
- [x] 32-byte `OsRng` session IDs
- [x] `GET /login` + `POST /login` + `POST /logout`
- [x] Auth middleware protecting all HTML + API routes
- [x] HTML → redirect to `/login`; API → 401 JSON
- [x] Optional bearer token via `AUTH_API_TOKEN`
- [x] Logout button in nav bar on all pages
- [x] `AUTH_ENABLED`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`, `AUTH_API_TOKEN`, `AUTH_SECURE_COOKIE` env vars
- [x] Health endpoint stays public
- [x] 29 new auth-specific tests

---

## Epic 8 – Deployment Hardening 🔲 planned

- [ ] CSRF tokens on write forms (depth-in-defence beyond `SameSite=Lax`)
- [ ] Rate limiting on `/login` (brute-force protection)
- [ ] Persistent session store (DB-backed; survive restarts)
- [ ] Systemd service unit file
- [ ] Reverse-proxy config examples (nginx, Caddy)
- [ ] `AUTH_SECURE_COOKIE=true` enforced when TLS is detected

---

## Epic 9 – Admin Write Actions 🔲 planned

- [ ] Enable / disable peer (`PATCH /api/peers/:id` with `"disabled": true/false`)
- [ ] Download client config (`GET /api/peers/:id/config`)
- [ ] Audit log viewer (`events` table; `peer_updated` event)

---

## Recommended next step

Choose one of:

1. **Deployment hardening** (Epic 8 starter) – CSRF tokens + rate limiting + systemd unit + reverse proxy docs.  Smallest path to a production-ready deployment guide.
2. **Audit logging** – add `peer_updated` events with old/new name and timestamp; viewer on `/admin/events`.

Both are small and clean.  Deployment hardening is recommended first because authentication is now in place.
