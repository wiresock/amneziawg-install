# MVP Definition

## Included in MVP

| # | Feature                               | Notes                                     |
|---|---------------------------------------|-------------------------------------------|
| 1 | `awg show all dump` integration        | Read-only; no writes to AWG config        |
| 2 | Peer list with RX/TX, handshake, endpoint | Polled every 30 s                     |
| 3 | Peer status derivation                | online / inactive / disabled / unlinked   |
| 4 | SQLite storage (peers + snapshots)    | Persistent across restarts                |
| 5 | REST API `/api/health`, `/api/peers`  | JSON responses                            |
| 6 | Display name + comment per peer       | Stored in DB, not in AWG config           |
| 7 | Enable / disable peer                 | Admin action (stub; UI TBD)               |
| 8 | Config file discovery                 | Scan `/etc/amneziawg/clients/*.conf`      |
| 9 | Audit log                             | Events table in DB                        |
|10 | Config download                       | Serve existing `.conf` file to admin      |

---

## Excluded from MVP

- Authentication / authorisation (planned: session tokens or Basic Auth)
- HTTPS termination (assumed to be handled by a reverse proxy)
- Real-time WebSocket updates
- Multi-user management UI
- AWG key generation / peer creation
- Email notifications
- Metrics export (Prometheus)
- Mobile-friendly UI
- Multi-server support

---

## Acceptance Criteria

1. `cargo build --release` succeeds with no errors.
2. `cargo test` passes all unit tests.
3. Service starts, connects to DB, and runs migrations without errors.
4. `GET /api/health` returns `{"status":"ok"}` with HTTP 200.
5. Poller runs without crashing when AWG binary is absent (degrades gracefully).
6. AWG output parser correctly handles:
   - an interface with zero peers
   - a peer with no handshake
   - a peer with a reset counter (rx/tx = 0 after non-zero)
7. Config scanner correctly identifies `.conf` files and ignores other files.
