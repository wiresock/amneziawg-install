# amneziawg-web

A self-hosted web panel that provides **visibility and basic management** for
[AmneziaWG (AWG)](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
installations managed via the
[amneziawg-install](https://github.com/wiresock/amneziawg-install) script.

> **Status:** read-only peer listing implemented · auth not yet available

---

## What is implemented

- **Background poller** – calls `awg show all dump` every N seconds (default: 30),
  stores per-peer snapshots in SQLite, and keeps the `peers` table up-to-date.
- **`GET /api/health`** – liveness probe.
- **`GET /api/peers`** – returns all known peers with resolved name, status,
  allowed IPs, endpoint, handshake time, and RX/TX counters.
- **`GET /api/peers/:id`** – returns full peer detail including the 50 most
  recent snapshots.
- **Status derivation** – `online` / `inactive` / `disabled` / `unlinked`
  based on last-handshake age (configurable threshold, default 180 s).
- **Display-name fallback** – `display_name` → config filename stem → `peer-<key-prefix>`.

## What is NOT yet implemented

- Authentication (planned: session tokens or Basic Auth – Epic 8)
- HTML/web UI (planned: askama templates – Epics 5–6)
- Config-file discovery (poller does not yet scan `/etc/amneziawg/clients/` – Epic 2)
- Admin write actions: rename, disable, config download (Epics 7–8)
- Traffic history aggregation and charts (Epic 5)

---

## Non-goals

`amneziawg-web` is an **overlay**, not a replacement.  It does **not**:

- Replace or modify the `amneziawg-install.sh` workflow
- Generate WireGuard keys or create new peer configs
- Replace `awg` / `wg-quick` as the primary VPN management tool

---

## Quick start

```bash
# Build
cd amneziawg-web
cargo build --release

# Run (defaults to listening on 0.0.0.0:8080)
AWG_WEB_DB=./awg-web.db ./target/release/amneziawg-web

# Or via environment file
cp .env.example .env
# Edit .env, then:
./target/release/amneziawg-web
```

---

## Configuration

All options can be set via CLI flags or environment variables:

| Env var             | Default                      | Description                        |
|---------------------|------------------------------|------------------------------------|
| `AWG_WEB_LISTEN`    | `0.0.0.0:8080`               | TCP bind address                   |
| `AWG_WEB_DB`        | `awg-web.db`                 | Path to SQLite file                |
| `AWG_CONFIG_DIR`    | `/etc/amneziawg/clients`     | Directory of client `.conf` files  |
| `AWG_POLL_INTERVAL` | `30`                         | Polling interval in seconds        |
| `RUST_LOG`          | `amneziawg_web=info`         | Log level filter                   |

---

## API

| Method | Path              | Description                              |
|--------|-------------------|------------------------------------------|
| GET    | `/api/health`     | Liveness probe – `{"status":"ok"}`       |
| GET    | `/api/peers`      | List all peers (array of summary DTOs)   |
| GET    | `/api/peers/:id`  | Get one peer by integer ID (detail DTO)  |

### Example – peer summary

```json
{
  "id": 1,
  "name": "Ivan iPhone",
  "public_key": "BASE64KEY==",
  "config_name": "ivan-iphone",
  "allowed_ips": "10.8.0.2/32",
  "endpoint": "203.0.113.10:51820",
  "latest_handshake_at": "2026-03-24T10:00:00Z",
  "rx_bytes": 123456,
  "tx_bytes": 654321,
  "status": "online"
}
```

### Status values

| Value      | Meaning                                                          |
|------------|------------------------------------------------------------------|
| `online`   | Last handshake within 180 s                                      |
| `inactive` | Has a config or display name, but no recent handshake            |
| `disabled` | Administratively disabled via the `disabled` flag in the DB      |
| `unlinked` | Seen in `awg show` but no config file matched and no name set    |

---

## AWG dump format assumptions

`awg show all dump` output is assumed to follow the WireGuard `wg show all dump`
tab-separated format:

- **Interface line** (5 fields): `interface private_key public_key listen_port fwmark`
- **Peer line** (9 fields): `interface public_key preshared_key endpoint allowed_ips latest_handshake rx_bytes tx_bytes persistent_keepalive`

Private-key fields are read and immediately discarded.  If the AWG binary uses
a different layout, update `src/awg/mod.rs::parse_dump()`.

---

## Development

```bash
cargo test            # run all tests (36 as of this milestone)
cargo fmt             # format code
cargo clippy -- -D warnings   # lint
```

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) – system design
- [`docs/MVP.md`](docs/MVP.md) – MVP scope and acceptance criteria
- [`docs/ROADMAP.md`](docs/ROADMAP.md) – development roadmap
- [`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md) – product specification

---

## Security

- Private keys are **never** logged or stored.
- `awg` is invoked with an absolute path; no shell interpolation is used.
- Config file paths are validated before access (non-recursive directory scan).

---

## License

MIT – see [`LICENSE`](LICENSE).
