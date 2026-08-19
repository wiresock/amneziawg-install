# Implementation plan for issues #102 and #103

This plan covers two pull requests:

1. Resource-safe Rust builds for `amneziawg-web` and `amneziawg-proxy`.
2. Optional AmneziaWG 3.0 support with backward-compatible AmneziaWG 2.x behavior.

## PR 1: Harden Rust builds on resource-constrained hosts

### Goals

- Make source installation and upgrade work on the low-resource VM described in
  issue #102 without requiring manual Cargo environment overrides.
- Apply the same policy to `amneziawg-web` and `amneziawg-proxy`.
- Preserve explicit, valid operator overrides and normal Cargo behavior on
  resource-rich hosts.
- Fail before compilation with actionable diagnostics when no usable build
  filesystem exists.

### Implementation

1. Add a repository-level shell helper shared by the web and proxy installers
   and upgraders.
2. Before a source build, inspect:
   - available bytes and inodes on the Cargo target filesystem;
   - whether the filesystem is writable and executable;
   - available CPUs;
   - `MemAvailable` plus `SwapFree` from `/proc/meminfo`, capped by effective
     cgroup v1/v2 memory and swap limits when present.
3. Respect an explicit `CARGO_TARGET_DIR` after resolving it against the crate
   directory. If it cannot satisfy the build requirements, fail with a precise
   diagnostic rather than silently ignoring it.
4. When the crate's normal `target` filesystem is unsuitable, create a private
   temporary Cargo target below the first suitable build root. Candidate roots
   include a validated operator override, `TMPDIR`, `/var/tmp`, `/var/cache`,
   and `/tmp`.
5. Place compiler temporary files on the selected build filesystem. Track the
   actual target directory so each caller locates the resulting release binary
   correctly.
6. On a one-vCPU or low-memory host, default `CARGO_BUILD_JOBS` to `1` unless
   the operator supplied it. Preserve explicit Cargo and linker settings.
7. Print the selected source, target, temporary directory, free-space figures,
   job policy, and linker policy before invoking Cargo.
8. Clean up only temporary build directories created by the helper. Never
   remove a caller-provided target directory or the crate's normal `target`.
9. Align both standalone launchers' pre-clone temporary-directory handling so
   the repository can be bootstrapped when `/tmp` is small or unsuitable.
10. Document the automatic policy and the supported build-root override.

Disk thresholds will be component-specific and based on clean-build
measurements with a safety margin. They must be constants in the calling
scripts rather than hidden inside the shared helper.

### Tests

- Unit-test filesystem selection, free-space/inode parsing, noexec rejection,
  CPU/memory classification, explicit overrides, and cleanup safety.
- Cover web install and upgrade in `tests/test-install-mock.sh`.
- Cover proxy install and upgrade in `tests/test-proxy-scripts.sh`.
- Cover standalone bootstrap behavior for both launchers.
- Add a constrained integration build that compiles both crates sequentially
  with one vCPU, 1 GiB RAM, and a small tmpfs-backed `/tmp` when CI facilities
  permit those limits.

### Acceptance criteria

- Both applications build on a one-vCPU, 1 GiB host with a small `/tmp` when an
  executable filesystem with sufficient disk space is available.
- No manual `TMPDIR`, `CARGO_BUILD_JOBS`, or target-linker workaround is needed
  for the issue #102 environment.
- Explicit valid overrides continue to work; invalid ones fail clearly.
- Resource-rich systems retain Cargo's default parallelism.
- Install and upgrade locate the binary correctly with both normal and external
  Cargo target directories.

## PR 2: Optional AmneziaWG 3.0 support

### Compatibility contract

- Missing protocol-version state means AmneziaWG 2.x.
- Fresh and existing installations remain on AmneziaWG 2.x by default.
- Installer, web-panel, and package upgrades never change the VPN protocol.
- AmneziaWG 3.0 is enabled only by an explicit administrative operation.
- AmneziaWG 2.x and 3.0 peers are not mixed on one interface because header
  protection is interface-wide. Parallel operation requires separate
  interfaces and ports.

### Implementation

1. Persist an explicit protocol mode and optional AmneziaWG 3.0 parameters:
   `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`,
   `RekeyTimeout`, `RejectAfterTime`, and `KeepaliveTimeout`.
2. Treat old parameter files with none of these fields as valid 2.x state.
   Unset every optional variable before sourcing the parameter file so an
   inherited environment cannot enable features.
3. Add a runtime capability probe used only when 3.0 is requested. The probe
   creates a temporary interface, applies every supported 3.0 field through
   the installed `awg` tool, reads the values back from the running kernel
   module, and always removes the interface.
4. Fail closed if userspace parsing, netlink application, or readback fails.
   Do not rely on package names or version strings alone.
5. Centralize conditional server/client configuration rendering and use it for
   initial generation, client creation, regeneration, and non-interactive
   flows.
6. Extend the web panel's parameter model and renderer with optional fields.
7. Validate the header-protection key, numeric/range syntax, and the `S1`-`S4`
   minimum required by header protection. Validate generated files with the
   installed tooling before applying them.
8. Implement enable and downgrade as transactions: probe, back up all state,
   generate one shared header-protection key, regenerate every server/client
   configuration, validate all outputs, apply, and roll back all files on any
   failure.
9. Never print the header-protection key. Keep parameter files and backups at
   mode `0600`.
10. Add CLI/menu and web-panel controls with a warning that all clients must
    support the selected protocol mode.

### Tests

- Existing 2.x parameter files and configurations remain unchanged during
  ordinary install-script and web-panel upgrades.
- New and old userspace/kernel combinations fail the capability probe safely.
- All generated 3.0 server and client configurations contain the same header
  key and pass the installed parser.
- Invalid keys, ranges, and incompatible `S1`-`S4` values are rejected.
- Migration failure restores the complete 2.x state.
- Downgrade removes all 3.0-only fields and regenerates every client.
- The disposable Ubuntu live test applies and reads back all 3.0 fields on a
  temporary interface.

### Acceptance criteria

- Installing new project code makes no protocol or configuration change to an
  existing 2.x deployment.
- 3.0 cannot be enabled unless the installed tool and running kernel module
  pass the runtime probe.
- Enabling or disabling 3.0 is atomic across server state and every client
  configuration.
- A failed operation leaves the prior working configuration active.
