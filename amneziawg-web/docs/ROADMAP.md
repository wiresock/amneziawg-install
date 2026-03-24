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

---

## Epic 4 – Poller & Snapshots ✅ complete

- [x] Background Tokio task, configurable interval
- [x] Snapshot insertion per poll; peer upsert (including `allowed_ips`)
- [x] Config mapping step after AWG step; logged per cycle
- [x] Rich logging: peer count, snapshot count, elapsed time, per-peer failures

---

## Epic 5 – Traffic History & Basic UI ✅ complete

- [x] `GET /api/peers/:id/history?range=24h|7d|30d`
- [x] Per-snapshot deltas with counter-reset handling (`saturating_sub`)
- [x] Summary totals (`rx_total_delta`, `tx_total_delta`)
- [x] `GET /` – server-rendered HTML peer list (table)
- [x] `GET /peers/:id` – server-rendered HTML peer detail (identity + snapshots)
- [x] `esc()` helper for XSS-safe HTML generation
- [x] Human-readable byte formatting (`fmt_bytes`)

---

## Epic 6 – Peer Details Enhancements 🔲 planned

- [ ] Traffic sparkline SVG or simple ASCII chart in peer detail page
- [ ] Pagination / search on peer list page
- [ ] History chart linking from peer detail page
- [ ] "Never seen" / "first seen" timestamps

---

## Epic 7 – Admin Actions 🔲 planned

- [ ] Rename / comment peer (`POST /api/peers/:id/rename`)
- [ ] Enable / disable peer
- [ ] Download client config
- [ ] Audit log viewer (`events` table)

---

## Epic 8 – Auth & Hardening 🔲 planned

- [ ] Session-based authentication
- [ ] Admin vs. viewer roles
- [ ] Rate limiting
- [ ] CSRF protection

---

## Recommended next step

**Basic rename/comment actions** (Epic 7 starter):
- `POST /api/peers/:id` with `{ "display_name": "...", "comment": "..." }`
- No destructive actions; just metadata writes
- Makes the UI immediately more useful for labelling peers

Alternatively, **authentication layer** (Epic 8 starter):
- Basic session cookie auth for the HTML pages
- API key support for the JSON endpoints
- Required before any public deployment

Prefer the smallest complete useful increment.
