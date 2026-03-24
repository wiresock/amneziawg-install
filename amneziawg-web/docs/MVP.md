# MVP Definition

## Implemented

| # | Feature                                   | Notes                                                    |
|---|-------------------------------------------|----------------------------------------------------------|
| 1 | `awg show all dump` integration           | Read-only; no shell interpolation                        |
| 2 | Background poller (every N seconds)       | Default 30 s; degrades gracefully if AWG absent          |
| 3 | Peer snapshots stored in SQLite           | `snapshots` table; persistent history                    |
| 4 | `peers` table kept up-to-date             | Upsert on every poll; includes `allowed_ips`             |
| 5 | `GET /api/peers` – real peer listing      | Status, name, endpoint, handshake, RX/TX, config fields  |
| 6 | `GET /api/peers/:id` – peer detail        | 50 recent snapshots; 404 on missing peer                 |
| 7 | `GET /api/peers/:id/history` – history    | `range=24h\|7d\|30d`; counter-reset safe                 |
| 8 | Status derivation                         | `online`/`inactive`/`disabled`/`unlinked`                |
| 9 | Display-name fallback chain               | `display_name` → config stem → `peer-<prefix>`           |
|10 | Schema migrations `0001` + `0002`         | `config_name`, `config_path` on `peers`                  |
|11 | `GET /` – HTML peer list page             | Server-rendered; no JS framework                         |
|12 | `GET /peers/:id` – HTML peer detail page  | Identity block + recent snapshots table                  |
|13 | Config discovery (`config_store`)         | Scans `*.conf`, extracts `[Peer] PublicKey` + `Address`  |
|14 | Config-to-peer mapping in poller          | Sets `has_config`, `config_name`, `config_path`; idempotent |
|15 | `unlinked` status driven by `has_config`  | Correct once config mapping runs                         |
|16 | 64 unit + integration tests               | DB, domain, history, config, web layers covered          |

---

## Config discovery

The poller scans `AWG_CONFIG_DIR` (default `/etc/amneziawg/clients`) after each
AWG poll.  For each `*.conf` file:

1. The filename stem becomes `config_name`.
2. The `[Peer] PublicKey` field is matched against live peers.
3. Matching peers get `has_config = 1`, `config_name`, `config_path` set.

The mapping is idempotent:
- All config fields are cleared at the start of each scan.
- Re-applied from current files.
- Removed config files → peer reverts to `unlinked` on next cycle.

Individual unreadable files are warned and skipped; the rest continue.

---

## Counter-reset handling

WireGuard byte counters are monotonic within a kernel session.  They reset to
zero when the AWG interface is restarted (e.g. after a reboot or module reload).

Detection: when `current_counter < previous_counter`, a reset is assumed.
Handling: the delta for that step is set to **0** (`u64::saturating_sub`).
Summary totals are the sum of all non-negative deltas, so a reset does not
subtract from reported cumulative traffic.

---

## What is still missing before production use

- **Authentication** – the API and HTML pages are completely unauthenticated.
- **HTTPS** – TLS termination is assumed to be provided by a reverse proxy.
- **Traffic charts** – the HTML page shows a table of snapshots but no chart.
- **Peer management** – rename, disable/enable, config download (Epics 7–8).
