# Roadmap

## Epic 1 – Core AWG Integration ✅ complete

- [x] Execute `awg show all dump` via `std::process::Command`
- [x] Parse output into `AwgInterface` / `AwgPeer` structs
- [x] Handle missing binary gracefully (warn + skip cycle)
- [x] `allowed_ips` saved in `peers` table on every poll

> Remaining: verify field layout against a live AWG binary.

---

## Epic 2 – Config Discovery ⏳ scaffolded, not wired

- [x] Scan config directory for `*.conf` files (module exists)
- [x] Extract `PublicKey` + `Address` from config files
- [x] Schema columns `config_name`, `config_path` added to `peers`
- [ ] Wire poller to scan config directory and populate `config_name`/`config_path`
- [ ] Mark peers without a matching config as `unlinked`
- [ ] Watch directory for new/removed configs

---

## Epic 3 – Database & Migrations ✅ complete

- [x] SQLite via sqlx
- [x] `peers`, `snapshots`, `events`, `interfaces`, `users` tables
- [x] Migration `0002`: `config_name`, `config_path` columns
- [x] Query layer (`src/db/peers.rs`) with `PeerRow`, `SnapshotRow`, query fns + tests
- [x] `connect_for_test` helper (max 1 connection, in-memory)
- [ ] Repository methods for `events` and `interfaces` tables

---

## Epic 4 – Poller & Snapshots ✅ complete

- [x] Background Tokio task, configurable interval
- [x] Snapshot insertion per poll
- [x] Peer upsert (including `allowed_ips`)
- [x] Rich logging: peer count, snapshot count, elapsed time, failures per-peer
- [ ] Counter-reset detection (detect rx/tx decrease)
- [ ] Poller pause/resume

---

## Epic 5 – Read-only UI 🔲 planned

- [ ] Peer list page (server-rendered HTML via askama or JSON API + minimal JS)
- [ ] Per-peer detail page with snapshot history
- [ ] RX/TX sparklines
- [ ] Status badges

**Recommended next PR**: traffic history aggregation endpoint +
basic HTML peer-list page.

---

## Epic 6 – Peer Details Page 🔲 planned

- [ ] Snapshot history chart
- [ ] Display name editing (admin action)
- [ ] Comment / notes field
- [ ] Config download button

---

## Epic 7 – Admin Actions 🔲 planned

- [ ] Rename / comment peer
- [ ] Enable / disable peer
- [ ] Download client config
- [ ] Audit log viewer (`events` table)

---

## Epic 8 – Auth & Hardening 🔲 planned

- [ ] Session-based authentication
- [ ] Admin vs. viewer roles
- [ ] Rate limiting
- [ ] CSRF protection
- [ ] Input validation for all write endpoints

---

## Epic 9 – Deployment 🔲 planned

- [ ] systemd unit file
- [ ] Dockerfile
- [ ] Reverse-proxy example configs (nginx, caddy)
- [ ] Optional post-install hook for `amneziawg-install.sh`
