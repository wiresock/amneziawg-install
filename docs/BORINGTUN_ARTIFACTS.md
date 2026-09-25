# BoringTun build artifacts

This repository builds static `boringtun-cli` binaries from a pinned commit of
[WireSock BoringTun](https://github.com/Wiresock-Foundation/wiresock-boringtun),
for a future userspace AmneziaWG backend (see
[BORINGTUN_BACKEND_DESIGN.md](BORINGTUN_BACKEND_DESIGN.md)).

**Status: CI only.** The artifacts are uploaded as GitHub Actions workflow
artifacts. They are not a distribution channel: `amneziawg-install.sh` does not
download, verify or install them, and nothing is published as a GitHub Release.
Publishing binaries from this repository is a separate maintainer decision.

## Source pin

[`packaging/boringtun/pin.env`](../packaging/boringtun/pin.env) is the only place
the source is defined:

| Key | Meaning |
|---|---|
| `BORINGTUN_REPOSITORY` | `https://github.com/<owner>/<repo>` of the source |
| `BORINGTUN_COMMIT` | Full 40-character commit SHA. Never a branch or tag. |
| `BORINGTUN_VERSION` | Version that `boringtun-cli --version` must report |
| `BORINGTUN_RUST_TOOLCHAIN` | Exact Rust release used to build |
| `BORINGTUN_ARTIFACT_FORMAT` | Version of the archive layout and `MANIFEST` format |

The file is data: `scripts/boringtun-artifact.sh` parses it with a strict
`KEY=VALUE` grammar and never sources it. Every workflow job reads the pin
through that script, and a unit test fails if the commit appears in any other
script, workflow or configuration file.

The current pin is `e4e4dc85ec039d40bbc92b3667b7fc92966b1b0a` (boringtun-cli
0.7.1), the upstream `master` that the backend design was validated against.

A pin bump is a reviewed change to `pin.env`, together with any policy change in
`packaging/boringtun/`. The artifact workflow runs automatically for it.

## Artifacts

| Architecture | Target | Built on |
|---|---|---|
| x86_64 | `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| aarch64 | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |

Both are built natively, without cross toolchains. The binaries are static
executables with no program interpreter and no shared library dependencies, so
they need no Rust, Cargo, kernel headers or DKMS on the target. With the Rust
defaults for each target, the x86_64 binary is a static PIE, while the aarch64
binary is a static non-PIE executable, so its own code is not
address-randomized.

Archives are named
`boringtun-cli-<version>-g<commit12>-linux-<arch>-musl.tar.gz`, for example
`boringtun-cli-0.7.1-ge4e4dc85ec03-linux-x86_64-musl.tar.gz`. Each holds one
directory with the same name, containing:

| File | Content |
|---|---|
| `boringtun-cli` | The binary, mode 0755 |
| `LICENSE` | BoringTun's `LICENSE.md` (BSD-3-Clause) |
| `THIRD-PARTY-LICENSES` | Licenses of the Rust crates linked into the binary |
| `MANIFEST` | `key=value` provenance: source repository and commit, CLI version, target, architecture, libc, toolchain versions, build command and profile, the binary's SHA-256 and the format version |

`SHA256SUMS` lists the archives in `sha256sum` format.

Archives are deterministic: members in name order, owner and group 0, fixed
modes, the pinned commit's time as every mtime, and gzip without a name or
timestamp. `MANIFEST` records no build-host paths or build time.

## Toolchain and build

Rust **1.98.1**, the release BoringTun's own CI used to test the pinned commit.
The CLI's lockfile (version 4) and several locked crates require a modern
toolchain; BoringTun's `rust-version = "1.75"` applies only to a Windows library
build that rewrites the lockfile.

The build command is:

```bash
cargo build --release --locked -p boringtun-cli --bin boringtun-cli --target <target>
```

`boringtun-cli` depends on the `boringtun` library with its `device` feature,
so `--features device` is neither needed nor valid for this package. The script
also:

- refuses a source whose `HEAD` is not the pinned commit, a tree with any local
  change, and Cargo configuration outside the pinned source (parent directories
  or `CARGO_HOME`). The source's own tracked `.cargo/config.toml` is part of the
  pin and is honoured;
- runs Cargo in a scrubbed environment, so caller `RUSTFLAGS`, `CC`, `CFLAGS`
  and locale settings cannot change the build;
- strips symbols (`CARGO_PROFILE_RELEASE_STRIP=symbols`) and remaps the source
  and Cargo home paths with `--remap-path-prefix`, passed through `--config` so
  that it adds to, rather than replaces, rustflags defined by the pinned source;
- fails if the build changes `Cargo.lock` or the source, produces no binary,
  embeds a local path, links dynamically, targets the wrong architecture or
  reports a version other than the pinned one. It never runs `cargo update`.

The `ring` crate compiles C and assembly for the musl targets with `musl-gcc`
from Ubuntu's `musl-tools` package.

## Reproducing a build locally

On an x86_64 or aarch64 Linux host with `git`, `musl-tools`, `binutils` and
rustup:

```bash
eval "$(bash scripts/boringtun-artifact.sh pin)"
git clone https://github.com/Wiresock-Foundation/wiresock-boringtun /tmp/boringtun-src
git -C /tmp/boringtun-src checkout --detach "$BORINGTUN_COMMIT"
rustup toolchain install "$BORINGTUN_RUST_TOOLCHAIN" --profile minimal \
    --target "$(uname -m)-unknown-linux-musl"
bash scripts/boringtun-artifact.sh build /tmp/boringtun-src "$(uname -m)-unknown-linux-musl" /tmp/boringtun-build
```

The `pin` output is validated `KEY=VALUE` data, so evaluating it is safe. To
package, first generate `THIRD-PARTY-LICENSES` (this needs `cargo-deny` 0.20.2
and `cargo-about` 0.9.2, installed with
`cargo install --locked cargo-deny@0.20.2` and
`cargo install --locked --features cli cargo-about@0.9.2`):

```bash
bash scripts/boringtun-artifact.sh licenses /tmp/boringtun-src /tmp/THIRD-PARTY-LICENSES
mkdir -p /tmp/boringtun-dist
bash scripts/boringtun-artifact.sh package /tmp/boringtun-build /tmp/boringtun-src /tmp/THIRD-PARTY-LICENSES /tmp/boringtun-dist
bash scripts/boringtun-artifact.sh checksums /tmp/boringtun-dist
```

Keep build and output directories outside this repository. The same toolchain
and C compiler produce the same binary, whatever the source, target or Cargo
home paths.

## Verifying an artifact

```bash
sha256sum -c SHA256SUMS
bash scripts/boringtun-artifact.sh verify-archive boringtun-cli-*-linux-"$(uname -m)"-musl.tar.gz /tmp/boringtun-check
```

`verify-archive` checks the archive name against the pin, the exact member list,
member types, modes and owners before extracting. It then checks `MANIFEST`
against the pin and the binary's hash, the license files, and the binary itself:
architecture, static linkage, `--version` and `--help`. As root,
`device-smoke <binary>` also creates a TUN device, queries its UAPI socket and
checks that the device disappears when the daemon stops.

## What CI checks

[`.github/workflows/boringtun-artifacts.yml`](../.github/workflows/boringtun-artifacts.yml)
runs on pushes to any branch that change `packaging/boringtun/`, the script,
the interop launcher or the workflow, and on manual dispatch. Pull requests from
branches of this repository are built by those pushes, so the `pull_request`
event builds only pull requests from forks, and a change is not built twice. The
workflow has read-only repository permissions and uses only GitHub-owned
actions.

1. **License and dependency gate**: `cargo-deny` checks advisories, bans,
   licenses and sources (crates.io only) for the binary's dependency graph, and
   `cargo-about` generates `THIRD-PARTY-LICENSES` offline.
2. **Build**, per architecture on a native runner: two builds in independent
   directories must be byte-identical, two packagings must be byte-identical,
   the archive must pass `verify-archive`, and `device-smoke` runs as root.
3. **Interop**, per architecture: BoringTun's `scripts/awg-go-interop.sh` and
   `scripts/awg31-interop.sh`, at the pinned commit, against the packaged binary
   and `amneziawg-go` built from the commit that `awg31-interop.sh` pins. The
   binary runs in the foreground, as the planned runtime runs it; see
   [Interop coverage](#interop-coverage). A watchdog stops a harness that runs
   too long and records the state of every daemon it started.
4. **SHA256SUMS** over both archives, uploaded with them as
   `boringtun-cli-artifacts`.

The unit tests for the script (`tests/test-boringtun-artifact.sh`) and for the
foreground launcher (`tests/test-boringtun-foreground-launcher.sh`) run in the
regular test workflow without compiling Rust.

## Licensing

BoringTun is BSD-3-Clause; its notice ships as `LICENSE`. At the current pin
the binary links 89 crates under Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause,
ISC and Unicode-3.0, all of which `THIRD-PARTY-LICENSES` reproduces. The
policy lives in `packaging/boringtun/deny.toml` and `about.toml`:

- any other license, or a crate whose license cannot be determined, fails;
- only crates.io sources are allowed;
- any RustSec advisory fails, except RUSTSEC-2025-0069. That advisory reports
  that `daemonize` 0.5.0, a direct dependency of `boringtun-cli`, is
  unmaintained; it is not a vulnerability. The crate runs only when the daemon
  is started without `--foreground`. This project does not change BoringTun;
  the finding needs an upstream decision before public distribution;
- a crate linked into the binary that ships an Apache-2.0 `NOTICE` file fails
  the gate, because `THIRD-PARTY-LICENSES` does not reproduce `NOTICE`
  contents. None does at the current pin; the `COPYRIGHT` files of `rand_core`,
  `rand_chacha` and `symlink` only restate their dual license.

The advisory database is fetched live, so a new advisory can fail a rebuild of
an unchanged pin. This is intended. Before public distribution, the maintainers
still need to review the generated notices and decide on the release channel
and on build provenance attestation.

## Interop coverage

At the pinned commit, both userspace harnesses start
`boringtun-cli --disable-drop-privileges [flags] <interface>` without `-f`, so
the daemon forks itself into the background, and then wait for its UAPI socket.
On native aarch64 runners that self-daemonizing path hung intermittently, in 3
of 4 interop jobs, before the socket appeared. The watchdog found the launching
process waiting for its forked child, and every forked process blocked in a
futex wait.
The x86_64 runs did not hang. The observed hang is a deadlock in BoringTun's
daemonization and fork path. Its exact cause was not established, and it is
not fixed here.

The planned runtime does not use self-daemonization: it runs
`boringtun-cli --foreground` under a service manager. CI therefore tests that
mode. The harnesses get
[`tests/helpers/boringtun-foreground-launcher.sh`](../tests/helpers/boringtun-foreground-launcher.sh)
as their `boringtun-cli`. It starts the packaged binary, whose absolute path is
in `BORINGTUN_REAL_CLI`, with `--foreground` and the harness's own arguments as a
background child in the harness's namespace, and returns. The harnesses, their
assertions and their teardown are unchanged. Because the foreground daemon logs
to stdout instead of `WG_LOG_FILE`, the launcher sends its output to that file,
where the harnesses look for it on failure. Before the harnesses run, a CI step
checks the running daemon that the launcher started: the packaged binary, with
`--foreground`, the only process in its namespace, still in the caller's session,
and stopped by `SIGTERM`. The launcher is for CI only and is never installed.

The userspace harnesses run in CI. The kernel-module harness,
`scripts/awg-interop-poc.sh`, does not: it needs an AmneziaWG kernel module
built for the runner kernel, plus `awg`, which the hosted runners do not provide
without installing DKMS packages. It is deferred to a dedicated environment,
such as the kernel coexistence tests planned for the host install work.

## Not yet done

The installer does not use these artifacts. Before it can, the project needs a
published, immutable release channel, the artifact SHA-256 values embedded in
`amneziawg-install.sh`, download and verification on the target, and the
BoringTun runtime backend itself.
