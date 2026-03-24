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

## Epic 8 – Deployment Hardening ✅ complete

- [x] CSRF tokens on all HTML write forms (`POST /login`, `POST /logout`, `POST /peers/:id`)
- [x] Login rate limiting: 5 attempts per 5-minute window per IP; 429 on excess
- [x] Configurable session TTL via `AUTH_SESSION_TTL_SECS` (default 24 h)
- [x] Systemd service unit file (`packaging/amneziawg-web.service`)
- [x] Reverse-proxy config examples in `docs/DEPLOYMENT.md` (nginx, Caddy)
- [x] Constant-time CSRF token comparison (`csrf_eq()`)
- [x] Pre-login CSRF token store (short-lived, single-use)
- [x] Tests for CSRF, rate limiting, session expiry, valid/invalid CSRF flows

---

## Epic 9 – Admin Write Actions 🔲 planned

- [ ] Enable / disable peer (`PATCH /api/peers/:id` with `"disabled": true/false`)
- [ ] Download client config (`GET /api/peers/:id/config`)
- [ ] Audit log viewer (`events` table; `peer_updated` event)

---

## Recommended next step

Choose one of:

1. **Audit logging** – add `peer_updated` events with old/new name, timestamp, and actor; viewer on `/admin/events`.
2. **Persistent session store** – DB-backed sessions that survive restarts; useful for long-running deployments.

Audit logging is recommended next as it has no frontend dependencies and provides operational value immediately.
