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
│   │ AWG kern │◄───│ privileged helper    │ │
│   │  module  │    │ (root:root, 0755)    │ │
│   └──────────┘    └──────────▲───────────┘ │
│                              │ exact sudo  │
│   ┌──────────────────────────┴───────────┐ │
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
│   /etc/amnezia/amneziawg/clients/*.conf            │
└────────────────────────────────────────────┘
```

---

## Components

### `awg` module (`src/awg/`)

Executes the root-owned privileged helper through `sudo` and
`std::process::Command` – **no shell interpolation**.  Parses AWG's
tab-separated `show all dump` output into Rust structs.

**Security constraints:**
- The sudo path and helper path are hard-coded as `/usr/bin/sudo` and
  `/usr/local/libexec/amneziawg-web-privileged`.
- The sudoers drop-in grants access only to that exact helper path; dynamic
  command arguments are not expressed as sudoers globs.
- The helper redacts interface private keys and peer PSKs before output crosses
  into the service process.
- Parsed output is never interpolated back into shell commands.

**Assumptions / TODOs:**
- The field layout (5 fields for interface, 9 for peer) was derived from the
  WireGuard `wg show all dump` format.  Verify against the actual AWG binary.
- If AWG uses a different field layout, update `parse_dump()` accordingly.

---

### Privileged helper (`scripts/amneziawg-web-privileged`)

Installed at `/usr/local/libexec/amneziawg-web-privileged` as
`0755 root:root`.  It is the sole executable authorized by
`/etc/sudoers.d/amneziawg-web` for the `awg-web` service user.

The helper allow-lists subcommands and validates each argument count,
interface/client name, peer key, and AllowedIPs value. It rejects unsafe
paths, symbolic links, hard links, and non-regular config files. Parameter and
server-state reads are semantic projections that omit private keys, PSKs, and
privileged interface directives. Live reconciliation accepts only a bounded
list of disabled public keys; the helper derives and filters the trusted
root-owned config internally before invoking `awg syncconf`.
Peer additions and removals are semantic operations: the helper holds a stable
per-interface lock, reconstructs an approved peer block or removes one exact
managed-client block, and atomically replaces the config.  Arbitrary config
content, raw file reads, arbitrary `syncconf` stdin, and unknown operations are
rejected rather than forwarded.

---

### `config_store` module (`src/config_store/`)

Scans `/etc/amnezia/amneziawg/clients/*.conf` (configurable) for client config files.
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
   → executes: /usr/bin/sudo -n /usr/local/libexec/amneziawg-web-privileged show-all
3. Helper validates `show-all` and executes: /usr/bin/awg show all dump
4. Parses output into Vec<AwgInterface>
5. For each peer:
   a. INSERT INTO snapshots
   b. UPSERT INTO peers
6. HTTP handler reads from DB and returns JSON
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
