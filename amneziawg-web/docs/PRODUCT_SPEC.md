# Product Specification

## Problem Statement

Operators running self-hosted AmneziaWG VPN servers have no visibility into
peer activity beyond running `awg show` on the command line.  There is no
persistent history, no ability to annotate peers with friendly names, and no
web interface for non-technical administrators.

---

## Goals

1. **Visibility** – display all peers with real-time stats and status.
2. **Annotation** – allow assigning display names and comments to peers.
3. **History** – store periodic snapshots to show activity over time.
4. **Non-invasiveness** – do not modify AWG configuration; act as a read-only
   overlay with optional lightweight write operations (display name, disable).
5. **Simplicity** – single binary, single SQLite file, no external services.

---

## Domain Model

### Peer

The central entity, identified by `public_key` (WireGuard public key).

| Field              | Type     | Source          |
|--------------------|----------|-----------------|
| `public_key`       | string   | `awg show`      |
| `display_name`     | string?  | DB (user input) |
| `comment`          | string?  | DB (user input) |
| `endpoint`         | string?  | `awg show`      |
| `allowed_ips`      | []string | `awg show`      |
| `last_handshake`   | datetime?| `awg show`      |
| `rx_bytes`         | u64      | `awg show`      |
| `tx_bytes`         | u64      | `awg show`      |
| `status`           | enum     | derived         |
| `disabled`         | bool     | DB (admin)      |
| `archived`         | bool     | DB (admin)      |
| `has_config`       | bool     | config scanner  |

### PeerStatus

Derived from `last_handshake`, `disabled`, and `has_config`:

- **online** – handshake within the last 3 minutes
- **inactive** – has config but no recent handshake
- **disabled** – administratively disabled
- **unlinked** – seen in `awg show` but no matching config file

### Snapshot

A point-in-time record of a peer's stats, written every poll cycle.

### Event

An audit log entry for every admin action.

### Archived disabled key

An operator may forget the saved data for an obsolete peer only after it is
disabled, unlinked from a client config, and no longer waiting for lifecycle
reconciliation. The operation deletes current metadata and all traffic
snapshots, then hides the row from normal views while retaining its ID, public
key, disabled state, timestamps, and audit history.

Archived keys remain part of disabled-key enforcement and cannot be
repopulated by polling or config discovery. Returning a key to the normal peer
list creates a blank, still-disabled row; deleted metadata and history are not
restored. Historical audit payloads may still contain earlier values, so this
is an operational cleanup feature rather than forensic secure erasure.

---

## Constraints

- Must not require root access beyond what `awg show` needs (typically the
  binary is setuid or run by a privileged user).
- Must not modify `/etc/amneziawg/` or any AWG config file.
- Private keys must never be stored, logged, or transmitted.
- All file path access must be validated to prevent traversal.
- No shell interpolation of user-supplied data.

---

## System Boundaries

```
┌─────────────────────────────────────────────────────┐
│                  amneziawg-web                      │
│                                                     │
│  IN SCOPE                                           │
│  • Read peer stats via `awg show all dump`          │
│  • Scan client config directory (read-only)         │
│  • Store snapshots + metadata in SQLite             │
│  • Serve REST API / HTML UI                         │
│  • Admin actions: rename, disable, download config  │
│                                                     │
│  OUT OF SCOPE                                       │
│  • Generating new client configs or keys            │
│  • Managing AWG interfaces (up/down)                │
│  • Modifying `wg-quick` or AWG config files         │
│  • User creation / key distribution                 │
└─────────────────────────────────────────────────────┘
```
