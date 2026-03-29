# Release Checklist

This document tracks the steps to publish a new release of `amneziawg-web`.

---

## v0.1.0 – initial release

### Pre-release checklist

- [x] All epics 1–9 complete (see [ROADMAP.md](ROADMAP.md))
- [x] `cargo test` passes (155 tests)
- [x] `cargo clippy -- -D warnings` passes
- [x] `cargo fmt --check` passes
- [x] `Cargo.toml` version is `0.1.0`
- [x] `LICENSE` file present (MIT)
- [x] `README.md` is polished and GitHub-ready
- [x] `docs/INSTALL.md` covers full install and uninstall flow
- [x] `docs/DEPLOYMENT.md` covers production hardening
- [x] `.env.example` covers all runtime variables
- [x] `packaging/amneziawg-web.service` is up-to-date
- [x] `Dockerfile` and `.dockerignore` present
- [x] `CONTRIBUTING.md` present
- [ ] Build and smoke-test the release binary on target OS
- [ ] Tag `v0.1.0` in git
- [ ] Create GitHub release with:
  - Release notes (see below)
  - Compiled binary attachment (optional)

### Known limitations for v0.1.0

See the "Current limitations" section of [README.md](../README.md):

- Sessions reset on service restart (in-memory store)
- Single admin account (no RBAC)
- No traffic charts in UI
- Not designed for direct public internet exposure

---

## Release notes template

```
## v0.1.0 – Initial release

**amneziawg-web** is a self-hosted web panel for AmneziaWG (AWG)
visibility and management.

### What's in v0.1.0

- Background poller with traffic snapshot history
- Config file discovery and peer correlation
- Peer rename and comment via API and HTML form
- Session cookie authentication with Argon2id
- CSRF protection and login rate limiting
- Audit logging for peer writes and auth events
- `/api/events` endpoint with filters
- Systemd service unit and deployment guide
- Docker support
- Companion uninstall script with safe defaults and explicit purge flags
- Companion upgrade script for safe in-place binary replacement
- Source-first install and upgrade (`--source-dir` builds from repo checkout)
- Automatic Rust toolchain installation (`--install-rust`)
- Sudoers-based privilege model for non-root AWG access (`/etc/sudoers.d/amneziawg-web`)

### Installation

See [docs/INSTALL.md](docs/INSTALL.md) for full instructions.

### Upgrading

```bash
# Rebuild from source and upgrade
sudo ./amneziawg-web.sh upgrade --source-dir ./amneziawg-web

# Or with a pre-built binary
sudo ./amneziawg-web.sh upgrade --binary ./target/release/amneziawg-web
```

See the "Upgrade reference" section in [docs/INSTALL.md](docs/INSTALL.md).

### Uninstalling

See the "Uninstaller reference" section in [docs/INSTALL.md](docs/INSTALL.md).

### Upgrade notes

This is the first release. No migration from a previous version is needed.
```

---

## Release procedure

```bash
# 1. Ensure all checks pass
cargo test
cargo clippy -- -D warnings
cargo fmt --check

# 2. Bump version in Cargo.toml if needed
# (currently at 0.1.0)

# 3. Commit any last changes
git add -A
git commit -m "chore: prepare v0.1.0 release"

# 4. Tag
git tag -a v0.1.0 -m "v0.1.0 – initial release"
git push origin v0.1.0

# 5. Build release binary
cargo build --release --locked
```

---

## Future release process

For subsequent releases:

1. Update `Cargo.toml` version (`0.2.0`, etc.)
2. Update this checklist for new features
3. Follow the same tag + GitHub release workflow
