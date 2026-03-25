# Copilot Task: Bootstrap AmneziaWG Web Panel

This file documents the original task that was used to bootstrap this
repository.  It is kept for reference so future contributors can understand
the initial design intent.

See the full task description in the GitHub issue or PR that created this
scaffold.

## Summary

- Create a Rust-based web panel for AmneziaWG visibility and management
- Non-invasive overlay on top of `amneziawg-install.sh`
- Tech stack: axum, tokio, sqlx + SQLite, serde, tracing, clap
- Bootstrap scope: project structure, docs, migrations, AWG integration, CI

## Open Questions

1. Does `awg show all dump` in AmneziaWG use the same 5/9 field format as
   standard WireGuard `wg show all dump`?  If not, the parser in
   `src/awg/mod.rs` needs updating.

2. In split AWG client configs, does `[Peer] PublicKey` refer to the server's
   public key or the client's?  This affects peer-to-config mapping.

3. Should the web panel listen only on localhost (behind a reverse proxy) or
   support direct TLS termination?

4. What is the preferred authentication mechanism (Basic Auth, session tokens,
   OIDC)?

## Assumptions

- AWG dump format matches the WireGuard `wg show all dump` specification.
- Client configs follow the standard `[Interface]` + `[Peer]` WireGuard format.
- The application runs as a systemd service with access to `/usr/bin/awg`.
- SQLite is sufficient for a single-node deployment.

## Next Recommended Steps

1. Verify AWG dump format on a live host and fix the parser if needed.
2. Implement DB repository methods for `peers` and `snapshots`.
3. Wire up `/api/peers` to return real data from the DB.
4. Add authentication middleware.
5. Build the first HTML peer-list page.
