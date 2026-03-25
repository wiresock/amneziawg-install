# Architecture

## Overview

`amneziawg-web` is a thin overlay that reads from a running
[AmneziaWG](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
installation and exposes the information via a REST API and (eventually) a
server-rendered HTML UI.

```
┌────────────────────────────────────────────┐
│                  Host OS                   │
│                                            │
│   ┌──────────┐    ┌──────────────────────┐ │
│   │ AWG kern │◄───│  awg show all dump   │ │
│   │  module  │    └──────────┬───────────┘ │
│   └──────────┘               │             │
│                              ▼             │
│   ┌──────────────────────────────────────┐ │
│   │         amneziawg-web (this app)     │ │
│   │                                      │ │
│   │  ┌─────────┐  ┌──────┐  ┌─────────┐ │ │
│   │  │  Poller │  │  DB  │  │  Web    │ │ │
│   │  │ (tokio) │  │SQLite│  │ (axum)  │ │ │
│   │  └────┬────┘  └──────┘  └────┬────┘ │ │
│   │       │                      │      │ │
│   │       └──────────────────────┘      │ │
│   └──────────────────────────────────────┘ │
│                                            │
│   /etc/amneziawg/clients/*.conf            │
└────────────────────────────────────────────┘
```

---

## Components

### `awg` module (`src/awg/`)

Executes `awg show all dump` via `std::process::Command` – **no shell
interpolation**.  Parses the tab-separated output into Rust structs.

**Security constraints:**
- The binary path is hard-coded as `/usr/bin/awg`.
- Private key fields in the output are read and immediately discarded.
- Parsed output is never interpolated back into shell commands.

**Assumptions / TODOs:**
- The field layout (5 fields for interface, 9 for peer) was derived from the
  WireGuard `wg show all dump` format.  Verify against the actual AWG binary.
- If AWG uses a different field layout, update `parse_dump()` accordingly.

---

### `config_store` module (`src/config_store/`)

Scans `/etc/amneziawg/clients/*.conf` (configurable) for client config files.
Extracts `PublicKey` from the `[Peer]` section to correlate configs with live
peers.

**Assumptions / TODOs:**
- AWG split-tunnel configs put the *server* public key in `[Peer]`.  Verify
  whether the `PublicKey` seen in `awg show` belongs to the client or server.
- Path traversal is prevented by reading only non-recursive directory entries.

---

### `db` module (`src/db/`)

Thin wrapper around a `sqlx::SqlitePool`.  Migrations are embedded in the
binary via `sqlx::migrate!("./migrations")`.

---

### `poller` module (`src/poller/`)

A Tokio background task that wakes every `AWG_POLL_INTERVAL` seconds,
calls `awg::show_all_dump()`, and:

1. Inserts a row into `snapshots` for each peer.
2. Upserts each peer into the `peers` table.
3. Handles counter resets (values are stored as-is; UI layer detects
   decreases).

---

### `web` module (`src/web/`)

Axum HTTP router.  All handlers are currently stubs returning JSON
placeholders.  Authentication is planned for a later milestone.

---

### `admin` module (`src/admin/`)

Command structs for admin actions (rename peer, enable/disable peer, etc.).
These will be wired up to web handlers in a later milestone.

---

## Data Flow

```
1. Poller wakes (every 30 s by default)
2. Calls awg::show_all_dump()
   → executes: /usr/bin/awg show all dump
3. Parses output into Vec<AwgInterface>
4. For each peer:
   a. INSERT INTO snapshots
   b. UPSERT INTO peers
5. HTTP handler reads from DB and returns JSON
```

---

## Storage Model

SQLite is chosen for its zero-infrastructure footprint.  A single
`awg-web.db` file contains:

| Table        | Purpose                                         |
|--------------|-------------------------------------------------|
| `peers`      | Canonical peer records with display metadata     |
| `snapshots`  | Time-series of per-poll stats                   |
| `interfaces` | Discovered AWG interfaces                       |
| `events`     | Audit log of admin actions                      |
| `users`      | Application user accounts (admin/viewer roles)  |

---

## Reasoning

- **Rust + axum + tokio**: type-safety, async I/O, minimal runtime overhead.
- **SQLite**: no external DB required; sufficient for a single-node VPN panel.
- **Overlay design**: `amneziawg-install.sh` remains the source of truth for
  AWG configuration; this app only reads and annotates.
- **No shell interpolation**: all external commands use `Command::new()` with
  explicit argument arrays to prevent injection.
