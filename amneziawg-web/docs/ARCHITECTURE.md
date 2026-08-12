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
managed-client block, optionally after checking its expected public key under
the same lock, and atomically replaces the config.  Arbitrary config
content, raw file reads, arbitrary `syncconf` stdin, and unknown operations are
rejected rather than forwarded.

The web panel holds an advisory lock on its open persistent state directory
(the parent of the SQLite database) across the complete managed-client
lifecycle, including database persistence and client-config cleanup. Supported
installer `--add-client` and `--remove-client` operations resolve and lock the
same directory descriptor from the installed service configuration. This inode
remains available when the client-config directory is absent, prevents an
out-of-band same-name replacement during web lifecycle work, and avoids a
mutable lock pathname in a service-writable directory.

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

1. Removes due managed users through the same native lifecycle command used
   by manual deletion. The first pass runs immediately at service startup.
2. Inserts a row into `snapshots` for each non-archived peer.
3. Upserts each non-archived peer into the `peers` table.
4. Handles counter resets (values are stored as-is; UI layer detects
   decreases).

Both snapshot insertion and live-field upserts are SQL-guarded by the
`archived` flag. This prevents an in-flight or later poll from repopulating a
key whose panel data was cleared.

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
   a. conditionally INSERT INTO snapshots when the key is not archived
   b. UPSERT live fields only when the existing row is not archived
6. HTTP handler reads from DB and returns JSON
```

---

## Storage Model

SQLite is chosen for its zero-infrastructure footprint.  A single
`awg-web.db` file contains:

| Table        | Purpose                                         |
|--------------|-------------------------------------------------|
| `peers`      | Canonical peer records, optional UTC expiration metadata, and archived disabled-key tombstones |
| `snapshots`  | Time-series of per-poll stats                   |
| `interfaces` | Discovered AWG interfaces                       |
| `events`     | Audit log of admin actions                      |
| `users`      | Application user accounts (admin/viewer roles)  |

### Archived-key invariant

An archived row retains its ID and public key, remains disabled, has no config
mapping or pending lifecycle sync, and has no traffic snapshots. Archived rows
are hidden from normal peer/detail/history/usage/config routes but remain in
the disabled-key set used by interface enforcement. Config mapping and poller
writes contain `archived = 0` guards.

Archiving is serialized with the config clear-and-remap sequence, so its
eligibility check cannot mistake a linked peer for an unlinked one during the
mapping window. The archive state transition, snapshot deletion, and
`peer_archived` audit event are one SQLite transaction. Existing audit rows
are retained; returning an archived key records `peer_restored`, leaves it
disabled, and does not restore deleted metadata or history.

### Removal retry invariant

Before the native removal path performs its first external mutation it sets a
durable `removal_pending` flag. Stale-peer cleanup and archiving exclude those
rows, preserving the identity and metadata needed to resume a partial manual
or expiration removal. Expiration edits reject removal-pending rows so an
administrator cannot cancel the automatic retry by clearing or extending its
deadline. Manual retry actions use the durable managed client name even after
config discovery fields are cleared. Successful removal uses the normal
peer-row deletion path, so the retry marker cannot become stale state.

---

## Reasoning

- **Rust + axum + tokio**: type-safety, async I/O, minimal runtime overhead.
- **SQLite**: no external DB required; sufficient for a single-node VPN panel.
- **Overlay design**: `amneziawg-install.sh` remains the source of truth for
  AWG configuration; this app only reads and annotates.
- **No shell interpolation**: all external commands use `Command::new()` with
  explicit argument arrays to prevent injection.
