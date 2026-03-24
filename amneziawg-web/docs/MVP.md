# MVP Definition

## Implemented in this milestone

| # | Feature                                   | Notes                                         |
|---|-------------------------------------------|-----------------------------------------------|
| 1 | `awg show all dump` integration            | Read-only; no shell interpolation             |
| 2 | Background poller (every N seconds)       | Default 30 s; degrades gracefully if AWG absent|
| 3 | Peer snapshots stored in SQLite           | `snapshots` table; persistent history         |
| 4 | `peers` table kept up-to-date             | Upsert on every poll; includes `allowed_ips`  |
| 5 | `GET /api/peers` – real peer listing      | Status, name, endpoint, handshake, RX/TX      |
| 6 | `GET /api/peers/:id` – peer detail        | 50 recent snapshots; 404 on missing peer      |
| 7 | Status derivation                         | `online`/`inactive`/`disabled`/`unlinked`     |
| 8 | Display-name fallback chain               | `display_name` → config stem → `peer-<prefix>`|
| 9 | Schema migration `0002`                   | Added `config_name`, `config_path` to `peers` |
|10 | 36 unit + integration tests               | All passing; DB, domain, web layers covered   |

---

## Excluded from this milestone

- Authentication / authorisation
- HTML/web UI (peer-list page)
- Config-file discovery (scanning `/etc/amneziawg/clients/`)
- Admin write actions (rename, disable, config download)
- Traffic history charts
- Multi-server support

---

## Acceptance Criteria

1. `cargo build --release` succeeds without errors.
2. `cargo test` passes all 36 tests.
3. `GET /api/peers` returns a JSON array (not a placeholder object).
4. `GET /api/peers/:id` returns HTTP 200 with peer detail for a valid ID.
5. `GET /api/peers/:id` returns HTTP 404 for an unknown ID.
6. Status is derived correctly for `online`, `inactive`, `disabled`, `unlinked`.
7. Display name falls back to config stem, then to `peer-<first-8-chars>`.
8. Private keys do not appear in any API response.
9. Poller logs peer count, snapshot count, and elapsed time each cycle.
10. Poller degrades gracefully (logs a warning) when `/usr/bin/awg` is absent.

---

## Remaining assumptions about AWG dump format

- Field layout matches WireGuard `wg show all dump` (5 interface fields, 9 peer fields).
- `allowed_ips` field uses comma-separated CIDRs.
- Timestamps are Unix epoch integers; `0` means no handshake.
- `(none)` is the sentinel for absent string values.

> **TODO**: Verify on a live AWG host and update `src/awg/mod.rs` if the format differs.

---

## What is still missing before production use

- **Authentication** – the API is completely unauthenticated; must run behind a
  trusted reverse proxy until auth middleware is added.
- **HTTPS** – TLS termination is assumed to be provided by a reverse proxy.
- **Config discovery** – `config_name` / `config_path` are `NULL` for all peers
  until the poller is extended to scan the client config directory.
- **UI** – there is no HTML interface yet; the service is API-only.
