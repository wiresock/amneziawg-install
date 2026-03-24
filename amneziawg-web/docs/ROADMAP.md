# Roadmap

## Epic 1 – Core AWG Integration ✅ complete

- [x] Execute `awg show all dump` via `std::process::Command`
- [x] Parse output into `AwgInterface` / `AwgPeer` structs
- [x] Handle missing binary gracefully (warn + skip cycle)
- [x] `allowed_ips` saved in `peers` table on every poll

---

## Epic 2 – Config Discovery ⏳ scaffolded, not wired

- [x] Scan config directory for `*.conf` files (module exists)
- [x] Extract `PublicKey` + `Address` from config files
- [x] Schema columns `config_name`, `config_path` added to `peers`
- [ ] Wire poller to scan config directory and populate `config_name`/`config_path`
- [ ] Mark peers without a matching config as `unlinked`

---

## Epic 3 – Database & Migrations ✅ complete

- [x] SQLite via sqlx; `peers`, `snapshots`, `events`, `interfaces`, `users` tables
- [x] Migrations `0001` (schema) + `0002` (`config_name`, `config_path`)
- [x] `PeerRow`/`SnapshotRow` + query fns + `connect_for_test` helper
- [x] `find_snapshots_since` for history queries (ascending, time-bounded)

---

## Epic 4 – Poller & Snapshots ✅ complete

- [x] Background Tokio task, configurable interval
- [x] Snapshot insertion per poll; peer upsert (including `allowed_ips`)
- [x] Rich logging: peer count, snapshot count, elapsed time, per-peer failures
- [ ] Counter-reset detection in poller (future: flag resets in snapshots table)

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

**Config discovery and mapping integration into poller** (Epic 2):
- Scan `/etc/amneziawg/clients/*.conf` on each poll cycle
- Match config public keys to live peers
- Populate `config_name` / `config_path` / `has_config` in the `peers` table
- This unlocks proper `unlinked` status and named configs in the UI

Alternatively, **basic rename/comment actions** (Epic 7 starter):
- `POST /api/peers/:id` with `{ "display_name": "...", "comment": "..." }`
- No destructive actions; just metadata writes
- Makes the UI immediately more useful

Prefer the smallest complete useful increment.
