# Roadmap

## Epic 1 – Core AWG Integration ✅ (scaffold complete)

- [x] Execute `awg show all dump` via `std::process::Command`
- [x] Parse output into `AwgInterface` / `AwgPeer` structs
- [x] Handle missing binary gracefully
- [ ] Verify field layout against production AWG binary
- [ ] Add integration test with a mock `awg` binary

---

## Epic 2 – Config Discovery ✅ (scaffold complete)

- [x] Scan config directory for `*.conf` files
- [x] Extract `PublicKey` + `Address` from config files
- [x] Map configs to peers via public key
- [ ] Handle `unlinked` peers (seen in AWG but no config file)
- [ ] Watch directory for new/removed configs

---

## Epic 3 – Database & Migrations ✅ (scaffold complete)

- [x] SQLite via sqlx
- [x] `peers`, `snapshots`, `events`, `interfaces`, `users` tables
- [ ] Repository pattern for each entity
- [ ] Unit tests for all DB operations

---

## Epic 4 – Poller & Snapshots ✅ (scaffold complete)

- [x] Background Tokio task
- [x] Configurable interval
- [x] Snapshot insertion per poll
- [x] Peer upsert
- [ ] Counter-reset detection
- [ ] Poller pause/resume

---

## Epic 5 – Read-only UI (planned)

- [ ] Peer list page (server-rendered HTML via askama or JSON API + minimal JS)
- [ ] Per-peer detail page
- [ ] RX/TX sparklines
- [ ] Status badges

---

## Epic 6 – Peer Details Page (planned)

- [ ] Snapshot history chart
- [ ] Display name editing
- [ ] Comment / notes field
- [ ] Config download button

---

## Epic 7 – Admin Actions (planned)

- [ ] Rename / comment peer
- [ ] Enable / disable peer
- [ ] Download client config
- [ ] Audit log viewer

---

## Epic 8 – Auth & Hardening (planned)

- [ ] Session-based authentication
- [ ] Admin vs. viewer roles
- [ ] Rate limiting
- [ ] CSRF protection
- [ ] Input validation for all admin endpoints

---

## Epic 9 – Deployment (planned)

- [ ] systemd unit file
- [ ] Dockerfile
- [ ] Integration with `amneziawg-install.sh` post-install hook (optional)
- [ ] Reverse-proxy example configs (nginx, caddy)
