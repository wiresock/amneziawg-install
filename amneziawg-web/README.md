# amneziawg-web

A self-hosted web panel that provides **visibility and basic management** for
[AmneziaWG (AWG)](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
installations managed via the
[amneziawg-install](https://github.com/wiresock/amneziawg-install) script.

> **Status:** read-only monitoring panel with traffic history, config discovery, peer renaming, and basic HTML UI · auth not yet available

---

## What is implemented

- **Background poller** – calls `awg show all dump` every N seconds (default: 30),
  stores per-peer snapshots in SQLite, keeps the `peers` table up-to-date, and
  runs a config-discovery scan after each AWG poll.
- **Config discovery** – scans `/etc/amneziawg/clients/` for `*.conf` files,
  extracts the `[Peer] PublicKey` and `[Interface] Address` fields, and maps
  each config file to the corresponding live peer by public key.
- **Peer rename / comment** – `PATCH /api/peers/:id` accepts JSON
  `{"display_name": "...", "comment": "..."}` and saves the values in the DB.
  The HTML detail page also provides a plain-HTML edit form.
- **`GET /`** – server-rendered HTML peer list (name, status, endpoint, handshake, RX, TX).
- **`GET /peers/:id`** – server-rendered HTML peer detail page with an edit form.
- **`GET /api/health`** – liveness probe.
- **`GET /api/peers`** – returns all known peers with resolved name, status,
  allowed IPs, endpoint, handshake time, RX/TX counters, and config metadata.
- **`GET /api/peers/:id`** – returns full peer detail including 50 most-recent snapshots.
- **`GET /api/peers/:id/history?range=24h|7d|30d`** – traffic history with deltas and summary totals.
- **Status derivation** – `online` / `inactive` / `disabled` / `unlinked`
  based on last-handshake age and config presence.
- **Display-name fallback** – `display_name` → `config_name` → `peer-<key-prefix>`.

## What is NOT yet implemented

- Authentication (planned: session tokens or Basic Auth)
- Admin write actions: enable/disable, config download
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

## Peer naming

Every peer is assigned a human-readable name resolved through this fallback chain:

| Priority | Source         | When used                                          |
|----------|----------------|----------------------------------------------------|
| 1        | `display_name` | User has explicitly set a name via the edit form or API |
| 2        | `config_name`  | A matching `*.conf` file was discovered             |
| 3        | `peer-<8-char-prefix>` | Fallback generated from the public key prefix |

### Updating a name or comment

**Via the API:**

```http
PATCH /api/peers/:id
Content-Type: application/json

{ "display_name": "Ivan iPhone", "comment": "Main phone" }
```

- Both fields are optional. Absent fields are left unchanged.
- Empty or blank strings clear the field (set to NULL).
- `display_name` is capped at 128 characters; `comment` at 512.
- Returns the full peer detail DTO.
- `404` if the peer does not exist.

**Via the HTML UI:**

Navigate to `/peers/:id` and fill in the "Edit peer" form.

---

## Config discovery

After each AWG poll, the poller scans `AWG_CONFIG_DIR` for `*.conf` files.

For each file:
1. The `[Peer] PublicKey` field is extracted.
2. The peer row matching that public key is updated with `has_config = 1`,
   `config_name` (filename stem), and `config_path` (absolute path).

Peers with no matching config file have `has_config = 0` and are shown as
**unlinked** in the UI and API.

The mapping is **idempotent**: all config fields are reset at the start of each
scan and re-applied from the current set of files.

---

## API

| Method | Path                          | Description                                      |
|--------|-------------------------------|--------------------------------------------------|
| GET    | `/`                           | HTML peer list page                              |
| GET    | `/peers/:id`                  | HTML peer detail + edit form                     |
| POST   | `/peers/:id`                  | HTML form submit (redirect back on success)      |
| GET    | `/api/health`                 | Liveness probe – `{"status":"ok"}`               |
| GET    | `/api/peers`                  | List all peers                                   |
| GET    | `/api/peers/:id`              | Get one peer by integer ID                       |
| PATCH  | `/api/peers/:id`              | Update display name and/or comment               |
| GET    | `/api/peers/:id/history`      | Traffic history (`range=24h|7d|30d`)             |

### Status values

| Value      | Meaning                                                              |
|------------|----------------------------------------------------------------------|
| `online`   | Last handshake within 180 s                                          |
| `inactive` | Has a config file but no recent handshake                            |
| `disabled` | Administratively disabled via the `disabled` flag in the DB          |
| `unlinked` | Seen in `awg show` but no matching config file found                 |

---

## Development

```bash
cargo test                        # 84 tests
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
