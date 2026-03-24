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
- [x] `has_config`, `config_name`, `config_path` populated for matched peers
- [x] `unlinked` status correctly driven by `has_config`

---

## Epic 3 – Database & Migrations ✅ complete

- [x] SQLite via sqlx; `peers`, `snapshots`, `events`, `interfaces`, `users` tables
- [x] Migrations `0001` (schema) + `0002` (`config_name`, `config_path`)
- [x] `PeerRow`/`SnapshotRow` + query fns + `connect_for_test` helper
- [x] `find_snapshots_since` for history queries (ascending, time-bounded)
- [x] `clear_all_config_mappings` + `apply_config_mapping` for idempotent mapping
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
- [x] Edit form with pre-filled values in peer detail page
- [x] `has_config` field in `GET /api/peers` summary response

---

## Epic 7 – Admin Actions 🔲 planned

- [ ] Enable / disable peer (`PATCH /api/peers/:id` with `"disabled": true/false`)
- [ ] Download client config (`GET /api/peers/:id/config`)
- [ ] Audit log viewer (`events` table)

---

## Epic 8 – Auth & Hardening 🔲 planned

- [ ] Session-based authentication
- [ ] Admin vs. viewer roles
- [ ] Rate limiting
- [ ] CSRF protection (already partially mitigated: no state-changing GET handlers)

---

## Recommended next step

**Authentication layer** (Epic 8 starter):
- Session cookie auth for the HTML pages
- API key support for the JSON endpoints
- Required before any public deployment

This is the most important missing safety feature.  The rename/comment feature
(Epic 6) is already useful internally but must be protected before exposing
the panel on the public internet.
