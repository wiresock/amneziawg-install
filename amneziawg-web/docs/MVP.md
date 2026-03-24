# MVP Definition

## Implemented

| # | Feature                                   | Notes                                                        |
|---|-------------------------------------------|--------------------------------------------------------------|
| 1 | `awg show all dump` integration           | Read-only; no shell interpolation                            |
| 2 | Background poller (every N seconds)       | Default 30 s; degrades gracefully if AWG absent              |
| 3 | Peer snapshots stored in SQLite           | `snapshots` table; persistent history                        |
| 4 | `peers` table kept up-to-date             | Upsert on every poll; includes `allowed_ips`                 |
| 5 | `GET /api/peers` – peer listing           | Status, name, endpoint, handshake, RX/TX, config fields      |
| 6 | `GET /api/peers/:id` – peer detail        | 50 recent snapshots; 404 on missing peer                     |
| 7 | `GET /api/peers/:id/history` – history    | `range=24h\|7d\|30d`; counter-reset safe                     |
| 8 | `PATCH /api/peers/:id` – rename/comment   | Partial update; normalisation; 404 on missing peer           |
| 9 | Status derivation                         | `online`/`inactive`/`disabled`/`unlinked`                    |
|10 | Display-name fallback chain               | `display_name` → config stem → `peer-<prefix>`               |
|11 | Schema migrations `0001` + `0002`         | `config_name`, `config_path` on `peers`                      |
|12 | `GET /` – HTML peer list page             | Server-rendered; no JS framework                             |
|13 | `GET /peers/:id` – HTML peer detail page  | Identity block + edit form + recent snapshots                |
|14 | `POST /peers/:id` – HTML form submit      | PRG redirect; same normalisation as PATCH API                |
|15 | Config discovery (`config_store`)         | Scans `*.conf`, extracts `[Peer] PublicKey` + `Address`      |
|16 | Config-to-peer mapping in poller          | Sets `has_config`, `config_name`, `config_path`; idempotent  |
|17 | `unlinked` status driven by `has_config`  | Correct once config mapping runs                             |
|18 | 84 unit + integration tests               | Domain, DB, config, history, web handler layers covered      |

---

## Peer naming

Every peer resolves its display name through this fallback chain:

1. **`display_name`** – explicitly set by the user via `PATCH /api/peers/:id` or the HTML edit form.
2. **`config_name`** – stem of the matching `.conf` filename (e.g. `"ivan-iphone"`).
3. **`peer-<8-char-prefix>`** – generated from the first 8 characters of the public key.

### Normalisation rules for user-supplied values

| Field          | Max length | Trim | Empty/blank → |
|----------------|-----------|------|----------------|
| `display_name` | 128 chars  | Yes  | `NULL` (clear) |
| `comment`      | 512 chars  | Yes  | `NULL` (clear) |

---

## Config discovery

The poller scans `AWG_CONFIG_DIR` (default `/etc/amneziawg/clients`) after each AWG poll:

1. `config_store::scan(dir)` finds all `*.conf` files (non-recursive).
2. `clear_all_config_mappings` resets all peers to `has_config=0`.
3. For each config with a `[Peer] PublicKey`, `apply_config_mapping` updates the matching peer.
4. Peers with no matching config remain `has_config=0` → status `unlinked`.

---

## Counter-reset handling

When the AWG interface restarts, byte counters reset to zero.  The history endpoint
detects a reset when `current_counter < previous_counter` and uses **0** as the delta
(`u64::saturating_sub`).  This prevents negative deltas in summary totals.

---

## What is still missing before production use

- **Authentication** – the API and HTML pages are completely unauthenticated.
- **HTTPS** – TLS termination is assumed to be provided by a reverse proxy.
- **Traffic charts** – snapshots table exists but no chart is rendered.
- **Enable/disable peer** – planned in Epic 7.
