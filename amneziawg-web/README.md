# amneziawg-web

A self-hosted web panel that provides **visibility and basic management** for
[AmneziaWG (AWG)](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
installations managed via the
[amneziawg-install](https://github.com/wiresock/amneziawg-install) script.

> **Status:** early scaffold / MVP in progress

---

## What it does

- Reads live peer state from `awg show all dump`
- Stores time-series snapshots in a local SQLite database
- Exposes a minimal REST API (and eventually a web UI) for:
  - listing peers with RX/TX stats and last-handshake
  - assigning display names and comments
  - enabling / disabling peers
  - downloading client configs

---

## Non-goals

`amneziawg-web` is an **overlay**, not a replacement.  It does **not**:

- Replace or modify the `amneziawg-install.sh` workflow
- Manage keys, generate configs from scratch, or touch `wg-quick`
- Replace `awg` / `wg-quick` as the primary tool

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

## API endpoints

| Method | Path            | Description                    |
|--------|-----------------|--------------------------------|
| GET    | `/api/health`   | Liveness probe                 |
| GET    | `/api/peers`    | List all known peers (stub)    |
| GET    | `/api/peers/:id`| Get peer by public key (stub)  |

---

## Development

```bash
# Run tests
cargo test

# Format
cargo fmt

# Lint
cargo clippy -- -D warnings
```

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) – system design
- [`docs/MVP.md`](docs/MVP.md) – MVP scope and acceptance criteria
- [`docs/ROADMAP.md`](docs/ROADMAP.md) – development roadmap
- [`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md) – product specification
- [`docs/COPILOT_TASK.md`](docs/COPILOT_TASK.md) – original bootstrap task

---

## Security

- Private keys are **never** logged or stored.
- `awg` is invoked with an absolute path; no shell interpolation is used.
- All config file paths are validated before access.
- See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for security constraints.

---

## License

MIT – see [`LICENSE`](LICENSE).
