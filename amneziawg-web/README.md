# amneziawg-web

A self-hosted web panel that provides **visibility and basic management** for
[AmneziaWG (AWG)](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
installations managed via the
[amneziawg-install](https://github.com/wiresock/amneziawg-install) script.

> **Status:** read-only monitoring panel with traffic history, config discovery, and basic HTML UI · auth not yet available

---

## What is implemented

- **Background poller** – calls `awg show all dump` every N seconds (default: 30),
  stores per-peer snapshots in SQLite, keeps the `peers` table up-to-date, and
  runs a config-discovery scan after each AWG poll.
- **Config discovery** – scans `/etc/amneziawg/clients/` for `*.conf` files,
  extracts the `[Peer] PublicKey` and `[Interface] Address` fields, and maps
  each config file to the corresponding live peer by public key.
- **`GET /`** – server-rendered HTML peer list (name, status, endpoint, handshake, RX, TX).
- **`GET /peers/:id`** – server-rendered HTML peer detail page (identity, latest stats, recent snapshots).
- **`GET /api/health`** – liveness probe.
- **`GET /api/peers`** – returns all known peers with resolved name, status,
  allowed IPs, endpoint, handshake time, RX/TX counters, and config metadata.
- **`GET /api/peers/:id`** – returns full peer detail including 50 most-recent snapshots.
- **`GET /api/peers/:id/history?range=24h|7d|30d`** – returns per-snapshot RX/TX history
  with deltas and summary totals. Counter resets are handled gracefully (zero delta).
- **Status derivation** – `online` / `inactive` / `disabled` / `unlinked`
  based on last-handshake age and config presence.
- **Display-name fallback** – `display_name` → `config_name` → `peer-<key-prefix>`.

## What is NOT yet implemented

- Authentication (planned: session tokens or Basic Auth – Epic 8)
- Admin write actions: rename, disable, config download (Epics 7–8)
- Traffic charts / sparklines in the HTML pages
- Peer creation or deletion

---

## Quick start

```bash
cd amneziawg-web
cargo build --release

# Defaults: listen 0.0.0.0:8080, DB awg-web.db
./target/release/amneziawg-web
```

---

## Configuration

| Env var             | Default                      | Description                        |
|---------------------|------------------------------|------------------------------------|
| `AWG_WEB_LISTEN`    | `0.0.0.0:8080`               | TCP bind address                   |
| `AWG_WEB_DB`        | `awg-web.db`                 | Path to SQLite file                |
| `AWG_CONFIG_DIR`    | `/etc/amneziawg/clients`     | Directory of client `.conf` files  |
| `AWG_POLL_INTERVAL` | `30`                         | Polling interval in seconds        |
| `RUST_LOG`          | `amneziawg_web=info`         | Log level filter                   |

---

## Config discovery

After each AWG poll, the poller scans `AWG_CONFIG_DIR` for `*.conf` files.

For each file:
1. The `[Peer] PublicKey` field is extracted – this is the server endpoint's public
   key as seen by the client config, which also appears in `awg show` output.
2. The peer row matching that public key is updated with `has_config = 1`,
   `config_name` (filename stem), and `config_path` (absolute path).

Peers with no matching config file have `has_config = 0` and are shown as
**unlinked** in the UI and API.

The mapping is **idempotent**: all config fields are reset at the start of each
scan and re-applied from the current set of files.  Removing a config file will
automatically mark the peer as unlinked on the next poll cycle.

Config files that cannot be read are logged as warnings and skipped; the rest of
the scan continues.  If the config directory does not exist, the mapping step is
skipped entirely (peers remain unlinked).

---

## API

| Method | Path                          | Description                                      |
|--------|-------------------------------|--------------------------------------------------|
| GET    | `/`                           | HTML peer list page                              |
| GET    | `/peers/:id`                  | HTML peer detail page                            |
| GET    | `/api/health`                 | Liveness probe – `{"status":"ok"}`               |
| GET    | `/api/peers`                  | List all peers (array of summary DTOs)           |
| GET    | `/api/peers/:id`              | Get one peer by integer ID (detail DTO)          |
| GET    | `/api/peers/:id/history`      | Traffic history (default `range=24h`)            |

### Traffic history ranges

| Parameter  | Window       |
|------------|--------------|
| `range=24h`| Last 24 hours |
| `range=7d` | Last 7 days   |
| `range=30d`| Last 30 days  |

### Counter-reset handling

AWG byte counters are monotonic within a kernel session.  When the AWG
interface is restarted the counters reset to zero.  The history endpoint
detects a reset when a snapshot's counter is *lower* than the previous
snapshot's counter, and uses **0** as the delta for that step
(`u64::saturating_sub`).  This prevents negative deltas and avoids
subtracting traffic from summary totals.

### Status values

| Value      | Meaning                                                              |
|------------|----------------------------------------------------------------------|
| `online`   | Last handshake within 180 s                                          |
| `inactive` | Has a config file but no recent handshake                            |
| `disabled` | Administratively disabled via the `disabled` flag in the DB          |
| `unlinked` | Seen in `awg show` but no matching config file found                 |

---

## AWG dump format assumptions

`awg show all dump` output is assumed to follow the `wg show all dump`
tab-separated format:

- **Interface line** (5 fields): `interface private_key public_key listen_port fwmark`
- **Peer line** (9 fields): `interface public_key preshared_key endpoint allowed_ips latest_handshake rx_bytes tx_bytes persistent_keepalive`

Private-key fields are read and immediately discarded.

---

## Development

```bash
cargo test                        # 64 tests
cargo fmt --check
cargo clippy -- -D warnings
```

---

## Security

- Private keys are **never** logged or stored.
- `awg` is invoked with an absolute path; no shell interpolation is used.
- HTML output is escaped with `esc()` to prevent XSS.
- The service must run behind a trusted reverse proxy until authentication is added.

---

## License

MIT – see [`LICENSE`](LICENSE).
