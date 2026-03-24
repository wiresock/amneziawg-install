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

## Epic 9 – Audit Logging ✅ complete

- [x] `events` table (existed from initial migration); added `peer_id` INTEGER FK column via migration `0003`
- [x] `src/db/events.rs` – `EventRow`, `EVT_*` constants, `log_event()`, `list_events()`
- [x] `GET /api/events` – filterable by `peer_id`, `event_type`, `limit`
- [x] `peer_updated` event logged from `PATCH /api/peers/:id` and `POST /peers/:id`
- [x] `login_success`, `login_failed`, `logout` events logged from auth handlers
- [x] Recent activity shown on `/peers/:id` HTML page (last 20 events)
- [x] Logging is fire-and-forget – never breaks main operation
- [x] 17 new audit-related tests (155 total)

---

## Epic 10 – Admin Write Actions 🔲 planned

- [ ] Enable / disable peer (`PATCH /api/peers/:id` with `"disabled": true/false`)
- [ ] Download client config (`GET /api/peers/:id/config`)

---

## Recommended next step

Choose one of:

1. **Persistent session store** – DB-backed sessions that survive restarts.
2. **Export / backup and restore** – SQLite dump endpoint or file download.
3. **Release packaging** – `.deb`/`.rpm` package or Docker image with the binary + systemd unit.

---

## Epic 11 – Release Preparation ✅ complete

- [x] README overhaul: screenshot placeholders, architecture diagram, feature comparison table, "vs status script" section
- [x] `docs/INSTALL.md`: full installation guide (prerequisites, build, systemd, Docker, reverse proxy)
- [x] `.env.example`: all variables documented with comments and safe defaults
- [x] `Dockerfile` + `.dockerignore`: multi-stage build, slim Debian runtime, non-root user
- [x] `CONTRIBUTING.md`: bug reporting, PR guidelines, security note
- [x] `docs/RELEASE.md`: v0.1.0 release checklist and release notes template
- [x] `docs/ROADMAP.md` updated with all complete epics
- [x] Terminology and cross-links consistent across all docs

---

## Recommended next steps after v0.1.0

1. **Publish v0.1.0** – tag the release, optional binary upload to GitHub Releases
2. **Persistent session store** – DB-backed sessions that survive restarts
3. **Peer management** – enable/disable (`PATCH /api/peers/:id` with `disabled` flag), config download
4. **Export / backup** – SQLite dump or JSON export endpoint
