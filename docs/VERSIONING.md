# Component Versioning

This repository versions the source-buildable components independently while
keeping their major version aligned.

## Sources of Truth

- Web panel: `amneziawg-web/Cargo.toml`
- Proxy: `amneziawg-proxy/Cargo.toml`
- Component path and tag policy: `.github/versioning/components.json`

The matching `Cargo.lock` package entry must always be kept in sync with the
component's `Cargo.toml` version.

## Version Semantics

Versions use `MAJOR.MINOR.PATCH`.

- `MAJOR` is shared by all components and configured as `project_major`.
- `MINOR` is updated manually when a component needs a meaningful release-line
  bump.
- `PATCH` is bumped automatically by CI after a merged PR changes that
  component.

The web panel and proxy are independent. A web-only PR bumps and tags only the
web panel version; a proxy-only PR bumps and tags only the proxy version.

## Automatic Patch Bumps

The `Component Versions` workflow runs after a PR is merged into `main`.

It detects changed files using `.github/versioning/components.json`:

- `amneziawg-web/**` and `amneziawg-web.sh` map to `web`.
- `amneziawg-proxy/**` and `amneziawg-proxy.sh` map to `proxy`.

For each changed component, CI increments the patch version in both
`Cargo.toml` and `Cargo.lock`, commits the result back to `main`, and creates an
annotated component tag:

- `web-vX.Y.Z`
- `proxy-vX.Y.Z`

No binary release artifacts are published. Consumers should build from source
at the desired component tag.

If a PR manually changes a component's package version, CI treats that component
as manually versioned and does not add an extra patch bump for it.

## Manual Minor or Major Bumps

For a manual minor bump, update the component's `Cargo.toml` version and matching
`Cargo.lock` package entry in the same PR, usually resetting patch to `0`.

For a shared major bump:

1. Update `project_major` in `.github/versioning/components.json`.
2. Update all component `Cargo.toml` versions to the new major.
3. Update all matching `Cargo.lock` package entries.

Run the validation helper before opening the PR:

```bash
python3 scripts/versioning/component_versions.py validate
```

## Source Builds

Build a component from the tag you want:

```bash
git fetch --tags
git checkout web-v0.1.3
cd amneziawg-web
cargo build --release --locked
```

```bash
git fetch --tags
git checkout proxy-v0.1.3
cd amneziawg-proxy
cargo build --release --locked
```
