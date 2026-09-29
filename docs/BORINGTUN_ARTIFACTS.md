# BoringTun build artifacts

This repository builds static `boringtun-cli` binaries from a pinned commit of
[WireSock BoringTun](https://github.com/Wiresock-Foundation/wiresock-boringtun),
for a future userspace AmneziaWG backend (see
[BORINGTUN_BACKEND_DESIGN.md](BORINGTUN_BACKEND_DESIGN.md)).

**Status: built and attested; not published yet.** Four separate stages handle
the artifacts, and only the first two run on their own:

| Stage | What happens | Where |
|---|---|---|
| Artifact build | The pinned source is built, packaged, verified and interop-tested; the archives are uploaded as workflow artifacts | BoringTun Artifacts workflow: pushes that change the recipe, manual dispatch |
| Attestation | Each archive gets a signed SLSA build provenance attestation; never for a pull request | the same workflow's `attest` job |
| Publication | For one reviewed, attested run, every check against the release contract, then a GitHub Release | BoringTun Release workflow: manual dispatch only ([Publishing a release](#publishing-a-release)) |
| Installer consumption | `amneziawg-install` downloads the archive for the host's architecture from the exact release URL and checks it against SHA-256 values embedded in the installer | not implemented yet (PR 4) |

No release has been published. Workflow artifacts expire after 90 days and are
not a distribution channel; the installer will only ever use release assets.

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

The current pin is `71d88784ad29dc95871c105e26cc62f6acdd565b` (boringtun-cli
0.7.1, tree `6f0f0a32a197fe71fb66c074cb1e56caf7024dd8`), the frozen baseline
for the first `amneziawg-install` integration. Upstream also tags it
`awg3.1-integration-2026-09-28` (tag object
`eb30d9694381f3da97f569cbde7b09aad256cd4b`); the tag is informational only, and
builds and installer trust anchors use the commit. It descends from
`e4e4dc85ec039d40bbc92b3667b7fc92966b1b0a`, the commit the backend design was
validated against, by upstream pull requests #58 to #66: noise and device fixes,
including transactional listen-port rebinding (#65) and releasing a device's
write intent when a mutation unwinds (#66), and JNI bindings. Its shipped
dependency graph is unchanged: the one lockfile change is a test-only
dependency.

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

The maintainers accept the aarch64 non-PIE binary for the first experimental
release. The trade-off: the daemon runs as root and parses untrusted network
packets, and because its code sits at a fixed address, exploiting a
memory-safety bug in it would not require an address leak first. Most of the
code is memory-safe Rust, the stack is not executable, relocations are
read-only after start-up, and stack, heap and memory mappings are still
randomized. Building it as a static PIE is a separate hardening follow-up; it
changes the build recipe, and so the build number of the next release.

Archives are named
`boringtun-cli-<version>-g<commit12>-linux-<arch>-musl.tar.gz`, for example
`boringtun-cli-0.7.1-g71d88784ad29-linux-x86_64-musl.tar.gz`. Each holds one
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
gh attestation verify boringtun-cli-*-linux-"$(uname -m)"-musl.tar.gz --repo wiresock/amneziawg-install \
    --cert-identity https://github.com/wiresock/amneziawg-install/.github/workflows/boringtun-artifacts.yml@refs/heads/main \
    --source-digest <commit> --source-ref refs/heads/main --deny-self-hosted-runners
```

`verify-archive` checks the archive name against the pin, the exact member list,
member types, modes and owners before extracting. It then checks `MANIFEST`
against the pin and the binary's hash, the license files and their required
notices, and the binary itself: architecture, static linkage, `--version` and
`--help`. `verify-archive-static` does the same without running the binary, for
an archive of another architecture. `verify-test-archive` skips only the
required-notices check, for the BoringTun Runtime workflow's never-uploaded
test archive with placeholder notices; nothing that is published uses it.
`gh attestation verify` checks the archive's
build provenance: that this repository's artifacts workflow built exactly these
bytes, on a GitHub-hosted runner, from `<commit>` of `main` (for a release, the
commit its tag points at). `--cert-identity` must equal the signing workflow's
identity exactly; `--signer-workflow` would only match its beginning, so a
workflow whose file name merely starts with `boringtun-artifacts.yml` would
pass it. As root,
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
   `cargo-about` generates `THIRD-PARTY-LICENSES` offline, which must carry
   every notice in `packaging/boringtun/required-notices`.
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
5. **Build provenance attestation** of both archives, with GitHub's
   `actions/attest-build-provenance`, except for pull requests. This job alone
   has `id-token: write` and `attestations: write`; every other job can only
   read. The attestation is stored by GitHub, not in the archives, whose bytes
   it does not change.

The unit tests for the script (`tests/test-boringtun-artifact.sh`) and for the
foreground launcher (`tests/test-boringtun-foreground-launcher.sh`) run in the
regular test workflow without compiling Rust.

## Licensing

BoringTun is BSD-3-Clause; its notice ships as `LICENSE`. At the current pin
`THIRD-PARTY-LICENSES` covers 88 crates under Apache-2.0, MIT, BSD-2-Clause,
BSD-3-Clause, ISC and Unicode-3.0: the crates linked into the binary, BoringTun's
own `boringtun` and `boringtun-cli`, and the procedural macros used to compile
them. The policy lives in `packaging/boringtun/deny.toml` and `about.toml`:

- any other license, or a crate whose license cannot be determined, fails;
- only crates.io sources are allowed;
- any RustSec advisory fails, except RUSTSEC-2025-0069, which reports that
  `daemonize` 0.5.0, a direct dependency of `boringtun-cli`, is unmaintained.
  The maintainers accepted it for the experimental release: "We accept
  RUSTSEC-2025-0069 for this experimental release because it is an
  unmaintained advisory, not a disclosed vulnerability, and WireSock runs
  boringtun-cli exclusively in foreground mode. The exception remains pinned
  to this advisory and will be removed if upstream removes or replaces
  daemonize." The crate runs only when `boringtun-cli` is started without
  `--foreground`;
- a crate linked into the binary that ships an Apache-2.0 `NOTICE` file fails
  the gate, because `THIRD-PARTY-LICENSES` does not reproduce `NOTICE`
  contents. None does at the current pin; the `COPYRIGHT` files of `rand_core`,
  `rand_chacha` and `symlink` only restate their dual license;
- the generated file must carry every copyright line listed in
  `required-notices`, in the section of its crate, and no crate but BoringTun's
  own may be attributed only through a placeholder notice
  (`Copyright (c) <year> <owner>`), the bare SPDX text that cargo-about falls
  back to when it cannot match a crate's license file.

`curve25519-dalek` 4.1.3 is why the last rule exists. It is BSD-3-Clause only,
and its single `LICENSE` file holds two notices: its authors' (isis agora
lovecruft, Henry de Valence) and The Go Authors', for code derived from Adam
Langley's Go ed25519. cargo-about does not match that combined file, and the
artifacts built before this was noticed attributed the crate through the
placeholder text alone, without either copyright notice. `about.toml` now
reproduces the file verbatim, pinned by its checksum, and `required-notices`
makes a regression fail the build and the release. BoringTun's own crates stay
attributed through the placeholder in `THIRD-PARTY-LICENSES`; their notice is
`LICENSE`. Some `ring` entries quote the source files that carry their ISC
notices, code included; that is how cargo-about attributes them and is left as
generated.

The advisory database is fetched live, so a new advisory can fail a rebuild of
an unchanged pin. This is intended.

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

## Publishing a release

Releases are GitHub Releases of this repository, one per build, with exactly
three assets: the x86_64 archive, the aarch64 archive and `SHA256SUMS`. The
licenses ship inside each archive; the build provenance lives in GitHub's
attestation store. An installer uses exact URLs, never "latest" or any API
lookup:

```
https://github.com/wiresock/amneziawg-install/releases/download/<tag>/<asset>
```

### Release contract

[`packaging/boringtun/release.env`](../packaging/boringtun/release.env) names one
exact release. `scripts/boringtun-release.sh contract` parses it with the same
strict grammar as `pin.env` and refuses any disagreement with the pin:

| Key | Meaning |
|---|---|
| `BORINGTUN_RELEASE_FORMAT` | Version of this file's format: `1` |
| `BORINGTUN_RELEASE_STATE` | `candidate` (checkable, never published) or `approved` |
| `BORINGTUN_RELEASE_SOURCE_COMMIT`, `_VERSION`, `_ARTIFACT_FORMAT` | Must equal the pin |
| `BORINGTUN_RELEASE_BUILD` | Build number for this source commit; it goes up with every change of toolchain, build flags, packaging or notices that changes the bytes |
| `BORINGTUN_RELEASE_TAG` | Must be `boringtun-cli-<version>-g<commit12>-b<build>` |
| `BORINGTUN_RELEASE_ASSET_<ARCH>` | Must be the archive name the pin gives |
| `BORINGTUN_RELEASE_ARCHIVE_SHA256_<ARCH>` | SHA-256 of the archive |
| `BORINGTUN_RELEASE_BINARY_SHA256_<ARCH>` | SHA-256 of the `boringtun-cli` inside it |

`<ARCH>` is `X86_64` and `AARCH64`. The release title is derived:
`BoringTun CLI <version> (WireSock <commit12>), build <build> (experimental)`.
A published tag is never reused or moved, so once a build is public, any other
bytes need a new build number. The contract holds a `candidate` of build 1 of
the frozen integration baseline. Nothing built from the earlier pin
`e4e4dc85ec03` is ever to be published: its archives lacked the
curve25519-dalek notices, and it is no longer the pin.

### The BoringTun Release workflow

`.github/workflows/boringtun-release.yml` runs only when dispatched, with the ID
of a BoringTun Artifacts run, the full SHA of the commit that run built, and a
mode, `dry-run` (the default) or `publish`. It never builds anything. The
`verify` job, which can only read, runs `boringtun-release.sh dry-run`, and
refuses unless:

- the contract is valid and matches the pin;
- the run is this repository's own run of the artifacts workflow, triggered by
  a push or a manual dispatch (not a pull request), completed with success, for
  exactly the given commit, on `main`, and that commit is part of `main`;
- the downloaded artifact is exactly the two archives and `SHA256SUMS`, as
  regular files, with `SHA256SUMS` byte for byte as the contract gives it;
- each archive has the contract's SHA-256, and passes `verify-archive-static`:
  exact members without links or traversal, owners and modes, `MANIFEST` for
  the pinned repository, commit, version, target and artifact format, the
  binary's SHA-256 against `MANIFEST` and against the contract, the license
  files and their required notices, and a static binary of the right
  architecture;
- each archive has a build provenance attestation signed by exactly the
  artifacts workflow of this repository on `main` (the certificate identity
  `https://github.com/<repo>/.github/workflows/boringtun-artifacts.yml@refs/heads/main`),
  for that commit and `refs/heads/main`, from a GitHub-hosted runner;
- no tag of that name exists and no release has that tag or title.

It then prints the exact tag, title, assets, archive and binary hashes and
release notes it would publish, and changes nothing. The same checks run locally:

```bash
GITHUB_REPOSITORY=wiresock/amneziawg-install bash scripts/boringtun-release.sh \
    dry-run <run-id> <commit> main /tmp/boringtun-release-check
```

With `mode=publish`, the `publish` job, the only one with `contents: write`,
refuses unless the workflow was dispatched on `main` and the contract is
`approved`. It repeats every check with its own download (it can also see
draft releases), then creates a draft pre-release for the commit, uploads the
three assets (the upload API refuses an existing name, and nothing is deleted
or replaced), reads every asset back and compares its SHA-256, checks again
that the tag and release are still free, and only then publishes. After
publication it checks that the tag points at the commit and that the public
download URLs serve the verified bytes. A failure after the draft exists leaves
the draft for inspection.

The maintainers should enable GitHub's immutable releases setting for this
repository before the first publication, so that a published
release's tag and assets cannot be changed afterwards. It is a repository
setting that no workflow changes.

### From a pin to a release

1. Update `pin.env` and the build recipe if needed, in a reviewed change.
2. The BoringTun Artifacts workflow builds reproducibly and attests the
   archives; on `main`, dispatch it if the change did not trigger it.
3. Review the exact hashes of that run.
4. Update `release.env` in a reviewed change: build number, tag, hashes, and
   still `candidate`.
5. Dispatch BoringTun Release with `mode=dry-run` for the run on `main` that
   built the reviewed commit.
6. The maintainers approve: `BORINGTUN_RELEASE_STATE=approved` in a reviewed
   change.
7. Dispatch BoringTun Release with `mode=publish`.
8. Embed the release constants (tag, asset names, archive and binary SHA-256)
   in `amneziawg-install.sh` (PR 4).

## Not yet done

The installer's internal BoringTun runtime layer can already run an unpacked
archive: the archive's top-level directory becomes a release in
`/usr/local/lib/amneziawg-install/boringtun/`, and every start checks it against
its `MANIFEST` (see §21.1 of [BORINGTUN_BACKEND_DESIGN.md](BORINGTUN_BACKEND_DESIGN.md)).
Only CI populates that store today.

No release is published, and the installer does not download anything yet.
PR 4 embeds the constants of the first published release in
`amneziawg-install.sh`, downloads and verifies the archive on the target, and
makes the BoringTun backend selectable.
