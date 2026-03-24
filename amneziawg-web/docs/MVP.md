# MVP Definition

## Implemented

| # | Feature                                   | Notes                                           |
|---|-------------------------------------------|-------------------------------------------------|
| 1 | `awg show all dump` integration            | Read-only; no shell interpolation               |
| 2 | Background poller (every N seconds)       | Default 30 s; degrades gracefully if AWG absent |
| 3 | Peer snapshots stored in SQLite           | `snapshots` table; persistent history           |
| 4 | `peers` table kept up-to-date             | Upsert on every poll; includes `allowed_ips`    |
| 5 | `GET /api/peers` – real peer listing      | Status, name, endpoint, handshake, RX/TX        |
| 6 | `GET /api/peers/:id` – peer detail        | 50 recent snapshots; 404 on missing peer        |
| 7 | `GET /api/peers/:id/history` – history    | `range=24h\|7d\|30d`; counter-reset safe        |
| 8 | Status derivation                         | `online`/`inactive`/`disabled`/`unlinked`       |
| 9 | Display-name fallback chain               | `display_name` → config stem → `peer-<prefix>`  |
|10 | Schema migrations `0001` + `0002`         | `config_name`, `config_path` on `peers`         |
|11 | `GET /` – HTML peer list page             | Server-rendered; no JS framework                |
|12 | `GET /peers/:id` – HTML peer detail page  | Identity block + recent snapshots table         |
|13 | 56 unit + integration tests               | DB, domain, history, web layers covered         |

---

## Counter-reset handling

WireGuard byte counters are monotonic within a kernel session.  They reset to
zero when the AWG interface is restarted (e.g. after a reboot or module reload).

Detection: when `current_counter < previous_counter`, a reset is assumed.
Handling: the delta for that step is set to **0** (`u64::saturating_sub`).
Summary totals are the sum of all non-negative deltas, so a reset does not
subtract from reported cumulative traffic.

---

## Remaining assumptions about AWG dump format

- Field layout matches `wg show all dump` (5 interface fields, 9 peer fields).
- `allowed_ips` field uses comma-separated CIDRs.
- Timestamps are Unix epoch integers; `0` means no handshake.
- `(none)` is the sentinel for absent string values.

> **TODO**: Verify on a live AWG host and update `src/awg/mod.rs` if the format differs.

---

## What is still missing before production use

- **Authentication** – the API and HTML pages are completely unauthenticated;
  must run behind a trusted reverse proxy until auth middleware is added.
- **HTTPS** – TLS termination is assumed to be provided by a reverse proxy.
- **Config discovery** – `config_name` / `config_path` are `NULL` for all peers
  until the poller is extended to scan the client config directory (Epic 2).
- **Traffic charts** – the HTML page shows a table of recent snapshots but no
  graphical chart.  Requires either a JS chart library or a sparkline SVG generator.
- **Peer management** – rename, disable/enable, config download (Epics 7–8).
