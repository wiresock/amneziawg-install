# WireSock BoringTun as an Alternative AmneziaWG Backend

**Status:** architecture proposal (design only; no production code is changed by this document)
**Date:** 2026-09-25
**Scope:** `amneziawg-install` (installer, web panel, proxy scripts). WireSock BoringTun is an
external, pinned component with its current public and runtime interfaces. Nothing in this
proposal requires a change to `wiresock-boringtun`.

---

## 0. Reading guide

### Evidence labels

| Label | Meaning |
|---|---|
| **FACT** | Confirmed by reading source at the revisions listed below. |
| **VERIFIED** | Confirmed by a live experiment (see [Appendix A](#appendix-a--experiment-log)). |
| **INFERRED** | Follows from source; not exercised live. |
| **PROPOSAL** | A design decision proposed by this document. |
| **OPEN** | Unresolved; needs a decision, a measurement or a test. |

### Revisions examined

| Repository | Revision | Notes |
|---|---|---|
| `wiresock/amneziawg-install` | `67fd5ce` (main, 2026-09-24) | All line numbers in this document refer to this revision. |
| `Wiresock-Foundation/wiresock-boringtun` | `e4e4dc8` (master, 2026-09-24) | `boringtun-cli` reports version `0.7.1`. |
| `amnezia-vpn/amneziawg-tools` | `ee0f0a9` (v3.1.20260812) | The Amnezia PPA currently ships this exact commit for focal and noble, amd64 and arm64. |
| `amnezia-vpn/amneziawg-linux-kernel-module` | `4569c4c` | The PPA's `amneziawg-dkms` is built from this commit. |
| `amnezia-vpn/amneziawg-go` | `b5928ef` | Reference only. |

### Live test environment

WSL2 running Ubuntu 24.04.4 with kernel 6.18 and systemd 255. **No AmneziaWG kernel module
was available**, so coexistence with the module was analysed from source only. BoringTun was
built from `e4e4dc8`; `awg` and `awg-quick` were built from `ee0f0a9`; the packaged
`awg-quick@.service` came from the tools repository. Datapath tests used network namespaces
and veth pairs. WSL2 is not a production host, but the behaviours relied on here (systemd
unit semantics, TUN, Unix sockets, netlink) are not WSL-specific. All test artefacts were
removed afterwards.

---

## 1. Executive summary

**Conclusion.** WireSock BoringTun can be added as a second, explicitly selected server
backend without modifying BoringTun and without changing behaviour for existing kernel
installations. The installer's management model carries over almost unchanged. That model
is: `awg` for live configuration, `awg-quick` for bring-up, the params file as the source of
truth, and transactional protocol changes.

Key findings and decisions:

- **Keep `awg-quick@<if>.service` as the lifecycle manager for both backends** (PROPOSAL,
  VERIFIED feasible). `awg-quick` already starts a userspace implementation through
  `WG_QUICK_USERSPACE_IMPLEMENTATION`. With BoringTun, start, hooks, reload, restart and
  stop all worked under systemd. The backend is expressed only through the installer-owned
  drop-in, a small launcher and a per-interface runtime file.
- **Backend selection must be made deterministic by the installer.** `awg-quick` always tries
  `ip link add … type amneziawg` first. When the kernel module is loaded or can be
  autoloaded, BoringTun is never started. The BoringTun drop-in therefore adds a precheck and
  a post-start verification, plus a PID-file contract that makes such a start fail closed
  (VERIFIED).
- **BoringTun behaviours the installer must compensate for** (none of them blocking):
  - Every `awg syncconf` whose input contains `ListenPort` leaks two sockets. Omitting an
    unchanged `ListenPort` avoids the leak (VERIFIED).
  - The default privilege drop fails under systemd, so `WG_SUDO=true` or
    `--disable-drop-privileges` is required. The value `1` is rejected (VERIFIED).
  - Daemon-mode logging is lost, so BoringTun runs in the foreground under a launcher
    (VERIFIED).
  - The private key is never exported over the UAPI. `awg showconf` therefore lacks it, and
    `SaveConfig` must be refused (VERIFIED).
  - The IPv6 socket family is always required (INFERRED).
- **AWG 2.0 / 3.0 / 3.1 validation stays backend-independent.** Only the "scratch interface"
  primitive differs. The installer's exact AWG 3.1 probe was applied and read back
  identically on a BoringTun scratch interface (VERIFIED).
- **Persisted state:** `AWG_BACKEND` (missing means `kernel`),
  `AWG_BORINGTUN_IMITATE_PROTOCOL` and `AWG_BORINGTUN_IMITATE_DOMAIN`, all in the existing
  params file.
- **Distribution:** statically linked binaries built by this repository's CI from a pinned
  BoringTun commit. The SHA-256 of each artifact is embedded in the installer. Source build
  is an opt-in fallback, and no Rust is needed on targets.
- **Proxy:** the proxy's Rust implementation is never touched. No proxy goes in front of
  BoringTun. The proxy installer script gains a small guard in the phase that makes BoringTun
  selectable.
- **Web panel:** mostly invisible. The only required change is the same `ListenPort` filter in
  the privileged helper's reconciliation, which is a no-op for the kernel module. The rest is
  wording and version display.
- **Containers** need `/dev/net/tun`, `CAP_NET_ADMIN`, a published UDP port and namespaced
  forwarding sysctls. They do not need the module, DKMS, headers, `/lib/modules` or
  `CAP_SYS_MODULE`. Containers should be a separate deliverable, and the abstraction is
  shaped for them from day one.
- **LXC:** the kernel backend keeps today's rejection. The BoringTun backend is allowed
  after a capability preflight.
- **First PR:** introduce the backend seam and the persisted `AWG_BACKEND` field with a
  kernel-only implementation and zero behaviour change.

---

## 2. Current architecture and kernel assumptions

### 2.1 Runtime model today (FACT)

- `amneziawg-install.sh` (7,764 lines) is a single Bash script. It offers an interactive
  menu and non-interactive flags: `--add-client`, `--remove-client`, `--list-clients`,
  `--protocol-status`, `--enable-awg3`, `--enable-awg31` and `--disable-awg3`. Its main block
  is guarded by `BASH_SOURCE`, so tests source the functions directly.
- **Persistent state** lives in three places:
  - `/etc/amnezia/amneziawg/params` holds shell-quoted `KEY='value'` pairs. It is root-owned
    with mode 0600 and is sourced only after `validateParamsFile`.
  - The server config `/etc/amnezia/amneziawg/<if>.conf` uses the `awg-quick` format,
    including PostUp/PostDown firewall hooks.
  - Client configs live in home directories or in `/etc/amnezia/amneziawg/clients`.
- **Datapath lifecycle** uses the packaged `awg-quick@<if>.service` (`Type=oneshot`,
  `RemainAfterExit=yes`). An installer drop-in adds `ExecStartPre=modprobe amneziawg` and
  network-online ordering.
- **Live changes** go through `awg syncconf <if> <(awg-quick strip <if>)`. Protocol mode
  changes are staged, validated, applied and rolled back as one transaction that restarts
  the service.
- **Serialization** uses a lifecycle `flock` on a directory shared with the web panel.
- **Web panel.** `amneziawg-web` runs as the `awg-web` user and performs every privileged
  action through the root-owned helper `amneziawg-web-privileged` via sudo. Client add,
  remove and reconcile are native to the panel. Protocol migrations call the panel's
  installed copy of `amneziawg-install.sh`.
- **Proxy.** `amneziawg-proxy` is a separate UDP service in front of AWG 2.0 that moves
  AWG's `ListenPort` to a backend port. Its installer refuses AWG 3.x.

### 2.2 Inventory of kernel assumptions

| # | Area | Location at `67fd5ce` | Kernel assumption | Consequence for BoringTun |
|---|---|---|---|---|
| K1 | Packages (Ubuntu) | `installAmneziaWG`, l.4676–4677 | Installs headers, `dkms` and `amneziawg` (DKMS metapackage) | Only `amneziawg-tools` is needed, installed with `--no-install-recommends` (see §12.8). |
| K2 | Packages (Debian) | l.4773–4774 | Same | Same. |
| K3 | Packages (RPM) | l.4780–4788 | `amneziawg-dkms` | RPM installs stay disabled (`ensureSupportedInstallDistro`, l.2849). |
| K4 | `deb-src` sources | l.4611–4640 (Ubuntu), l.4680–4687 (Debian) | Source repositories added for DKMS builds | Not needed; the host's APT config is left untouched. |
| K5 | Kernel headers | `installKernelHeaders` l.3432 and helpers l.2924–3429 | Headers for DKMS | Not needed. |
| K6 | DKMS build | `sanitizeAwgDkmsConf` l.2917; l.4793–4830 | Builds and checks `amneziawg.ko` | Not needed. |
| K7 | Boot-time module load | l.4833–4838, `/etc/modules-load.d/amneziawg.conf` | Module loaded at boot | Must never be created. |
| K8 | Unit drop-in | l.4912–4923 | `ExecStartPre=modprobe amneziawg` | Replaced by a backend-specific drop-in (§7.4). |
| K9 | Service start gate | l.4935 (`if modprobe amneziawg`) | Start only if the module loads | Replaced by backend readiness. |
| K10 | Diagnostics | l.3624–3637, l.4938–4957, l.4979–4993 | Headers, DKMS and `lsmod` hints | Backend-specific hints. |
| K11 | Runtime repair | `ensureAmneziawgKernelModule` l.3538 | Headers → DKMS → `depmod` → `modprobe`; exits on failure | Backend-neutral `ensureAwgBackendReady`. |
| K12 | Repair call sites | l.5003, 5387, 5757, 7109, 7158, 7181, 7595, 7651 | As K11 | Dispatch through the seam. |
| K13 | Service auto-start | `ensureAwgQuickRunning` l.3513 | Backend-neutral | Reused. |
| K14 | Capability probe | `probeAwgProtocolCapability` l.1731 (`ip link add` l.1786, messages l.1803–1817) | Scratch interface of type `amneziawg` | Scratch-interface primitive (§8). |
| K15 | Staged validation | `validateStagedAwgConfigs` l.6810 (`ip link add` l.6818) | Same | Same primitive. |
| K16 | Manual interface cycling | `applyAwgProtocolTransaction` l.6900; `restartManualAwgInterface` l.6909; manual `awg-quick up` l.6916, l.7046 | Plain `awg-quick up` creates the datapath | Needs a backend wrapper (`awgBackendQuickUp`). |
| K17 | Live sync | l.5315, 5388, 5758, 6459, 7596, 7652; web helper l.638; packaged `ExecReload` | `syncconf` is idempotent | BoringTun leaks sockets when `ListenPort` is sent (§6.1). |
| K18 | Virtualization | `checkVirt` l.2749 | LXC rejected because the module must exist on the host | Allowed for BoringTun after a preflight (§14). |
| K19 | Uninstall | `uninstallAmneziaWG` l.5785 (modules-load l.5811, packages l.5823 and l.5847) | Kernel artefacts | Backend-specific cleanup. |
| K20 | Params security boundary | `validateParamsFile` `unset` list, l.5972 | — | New keys must be added. |
| K21 | Web version display | `amneziawg-web/src/system_versions.rs`, `detect_amneziawg` l.81 | `modinfo amneziawg` | Optional BoringTun version display. |
| K22 | Web UI text | `amneziawg-web/src/web/mod.rs` l.4026 | "probes kernel support" | Wording. |
| K23 | Web helper binaries | `amneziawg-web-privileged`: `/usr/bin/awg`, `/usr/bin/awg-quick` | Packaged tools | Unchanged; the tools still come from the PPA. |
| K24 | Proxy installer | `amneziawg-proxy/scripts/amneziawg-proxy-install.sh` l.325–370 (AWG 2.0 gate), l.1512–1680 (rebind and restart) | Proxy fronts the AWG datapath | Must also refuse the BoringTun backend (§10). |
| K25 | Tests | `tests/test-functions.sh` l.658–910; `tests/test-awg3.sh` l.455–485 and l.854–870 (`link add dev awgp`); `tests/test-install-mock.sh` l.121–125 (mocks) and l.790–801 (modules-load); `tests/test-ubuntu-resolute-live.sh` | Kernel | Keep all; add BoringTun equivalents. |
| K26 | Documentation | `README.md`, web and proxy docs | Kernel module wording | Update when BoringTun becomes user-facing. |

### 2.3 What is already backend-neutral (FACT)

- **All live configuration goes through `awg`.** The tools talk netlink to the kernel module
  or connect to `/var/run/amneziawg/<if>.sock` for a userspace implementation, transparently
  (`ipc-uapi-unix.h`). This covers `awg show`, `awg show all dump`, `awg setconf`,
  `awg syncconf` and `awg set … peer … remove`.
- **Config rendering and validation** do not depend on the datapath. This includes server
  and client templates, `renderAwgProtocolFields` (l.1706) and parameter validation.
- **The protocol transaction** does not depend on the datapath either: backup, stage,
  validate, apply, roll back and signal traps. The exceptions are K14–K16.
- **Firewall hooks** reference only the interface name. A TUN device and a kernel link both
  appear as `awg0`.
- **The web panel** uses `awg show all dump`, `awg set … peer … remove` and `awg syncconf`
  through the helper, plus `SERVER_PUB_KEY` from params. It never uses the interface's own
  key from the dump (see §11.1).

---

## 3. Proposed backend abstraction

### 3.1 Principles (PROPOSAL)

1. **Explicit and persisted.** The backend is chosen at install time and stored in params. It
   is never inferred from the environment of an existing installation, and it never changes
   because of an upgrade, a kernel update or a DKMS failure.
2. **Deterministic and fail-closed.** A BoringTun installation never runs on the kernel
   module, and a kernel installation never falls back to userspace. When the requested
   datapath cannot be guaranteed, the operation fails with an actionable message.
3. **Kernel path unchanged.** The kernel implementations are today's code, reached through
   the seam, with the same commands, files and messages.
4. **Single-sourced policy.** Client management, protocol validation and transactions stay
   backend-neutral. Only primitives differ.
5. **No service-manager assumptions inside datapath primitives.** This prepares for
   containers.
6. **Pure renderers.** Derived artefacts such as drop-ins and runtime files are produced by
   side-effect-free functions from params. Installation, repair, migration and container
   images can then reuse them.

### 3.2 Layers

```
+-------------------------------------------------------------------+
| Flows: install, menu, --add/--remove/--list-client, protocol      |
| modes, regenerate, uninstall, (future) backend migration          |
+-------------------------------------------------------------------+
| Backend-neutral services: params model + validation, config       |
| rendering, capability probe + staged validation, protocol         |
| transaction, client lifecycle, lifecycle lock                     |
+-------------------------------------------------------------------+
| Backend interface: awgBackend*, ensureAwgBackendReady,            |
| awgSyncInterfaceConfig                                            |
+--------------------------------+----------------------------------+
| kernel implementation          | boringtun implementation         |
| (today's code, unchanged)      | (binary store, launcher,         |
|                                |  drop-in, scratch daemons)       |
+--------------------------------+----------------------------------+
| Shared runtime contract: awg (netlink or UAPI), awg-quick,        |
| awg-quick@<if>.service                                            |
+-------------------------------------------------------------------+
```

### 3.3 Backend interface (PROPOSAL)

| Operation | Replaces or encapsulates | kernel | boringtun |
|---|---|---|---|
| `normalizeAwgBackend`, `validatePersistedAwgBackendState` | New, modelled on `normalizeAwgProtocolVersion` (l.1581) and `validatePersistedAwgProtocolState` (l.1681); called from `validateParamsFile` (l.5888) | `''` or `kernel` | Also validates imitation keys (§9.2). |
| `awgBackendRequestedForInstall` | New; fresh installs only; called from `initialCheck` (l.2909) and `installQuestions` (l.4092) | Default | `AWG_BACKEND=boringtun` in the environment. |
| `awgBackendPreflight install\|manage` | Kernel-only view of `checkVirt` (l.2749) | Today's `checkVirt` | Capability preflight (§14). |
| `awgBackendInstallPackages`, `awgBackendInstallRuntime` | Package block of `installAmneziaWG` (l.4610–4789) | Unchanged | `amneziawg-tools` without recommends, plus the pinned binary (§12). |
| `awgBackendPrepareBoot` | l.4793–4838 | DKMS autoinstall, `depmod`, `.ko` check, modules-load | Nothing (optional module load override, §7.11). |
| `awgBackendRenderServiceDropIn`, `awgBackendWriteServiceDropIn` | Heredoc at l.4914 | Byte-identical text | Supervised drop-in (§7.4). |
| `awgBackendStartService` | l.4933–4960 | `modprobe` gate, start, hints | Start, verification, hints. |
| `ensureAwgBackendReady [0\|1]` | 8 call sites of `ensureAmneziawgKernelModule` (l.3538) | `ensureAmneziawgKernelModule "$@"`, unchanged | Binary, helper and runtime checks; starts the service in mode 1 (§6.3). |
| `awgBackendCreateScratchInterface`, `awgBackendDestroyScratchInterface` | `ip link add`/`delete` in `probeAwgProtocolCapability` (l.1731) and `validateStagedAwgConfigs` (l.6810) | `ip link add dev NAME type amneziawg` / `ip link delete dev NAME` | Transient BoringTun instance (§8.4). |
| `awgBackendQuickUp CONF` | Manual `awg-quick up` at l.6916 and l.7046 | `awg-quick up CONF` | Precheck, then `awg-quick up` with the launcher. |
| `awgSyncInterfaceConfig IFACE` | The six `awg syncconf` sites (K17) | Exactly `awg syncconf IFACE <(awg-quick strip IFACE)` | Same, minus an unchanged `ListenPort` line (§6.4). |
| `awgBackendUninstall` | Backend part of `uninstallAmneziaWG` (l.5811, 5823, 5847) | Unchanged | Helpers, drop-in, runtime files, binary store, load-override file, stale sockets. |
| `awgBackendStatus` | New `--backend-status` | Module state | Binary, pin, imitation and daemon state. |
| `awgBackendFailureHints` | Hint blocks (K10) | Unchanged text | Journal, precheck and preflight hints. |

### 3.4 Dispatch and naming (PROPOSAL)

- Dispatch functions use `case "${AWG_BACKEND}" in kernel) … ;; boringtun) … ;; *) fail ;; esac`.
  The kernel branch calls existing functions under their existing names (for example
  `ensureAmneziawgKernelModule`), so existing unit tests keep testing the kernel code
  unchanged.
- `AWG_BACKEND` is always normalized before dispatch. `validateParamsFile` sets it for
  managed installations and `installQuestions` sets it for fresh ones. From the first PR that
  accepts `boringtun`, an unset value at dispatch time is a programming error that fails
  closed.
- Kernel implementations keep their exit semantics. For example, `ensureAmneziawgKernelModule`
  exits 1. The BoringTun implementations mirror those semantics so callers do not change.

### 3.5 Deliberately not backend-specific

- Server and client config formats. Clients never learn which backend the server runs, which
  is what makes a later backend migration client-transparent.
- `writeFirewallRules` (l.4423) and the generated PostUp/PostDown hooks.
- Client IP allocation, key handling and web-panel copies.
- Probe field values and readback comparisons.
- The lifecycle lock.

A future `amneziawg-go` backend fits the same interface: its launcher would be
`amneziawg-go -f` and its UAPI is identical. It is not proposed now.

---

## 4. Persisted configuration and state model

### 4.1 New params keys (PROPOSAL)

| Key | Values | Missing or empty means | Notes |
|---|---|---|---|
| `AWG_BACKEND` | `kernel`, `boringtun` | `kernel` | Set at install time; changed only by an explicit, future migration command. |
| `AWG_BORINGTUN_IMITATE_PROTOCOL` | `none`, `dns`, `quic`, `sip`, `stun` | `none` | Valid only with `boringtun`. Mirrors BoringTun's `--imitate-protocol`. |
| `AWG_BORINGTUN_IMITATE_DOMAIN` | hostname | BoringTun generates a random name | Valid only with `dns`, `quic` or `sip`. Mirrors `--imitate-domain`. |

The `AWG_` prefix matches the existing protocol state. The `BORINGTUN_` infix makes the
scope explicit, so a kernel installation carrying imitation keys is visibly invalid rather
than silently ignored. `serializeParams` (l.2460) writes all three keys, with empty strings
where unused, exactly as it already does for AWG 3.x keys under AWG 2.0.

### 4.2 Normalization, validation and the environment boundary (PROPOSAL)

- **`AWG_BACKEND`:** `''` or `kernel` normalize to `kernel`, and `boringtun` stays
  `boringtun`. Any other value fails closed with "unsupported AWG_BACKEND in params".
- **Kernel with imitation keys** is invalid persisted state and is reported, never silently
  cleared. Repair is an explicit command, following the existing rule that damaged AWG 3.x
  state is repaired only by the explicit downgrade.
- **BoringTun values:**
  - An empty protocol means `none`.
  - A domain is accepted only for `dns`, `quic` and `sip`.
  - The domain is validated with the same rules as BoringTun's `is_valid_imitation_host`
    (FACT): labels of ASCII letters, digits and hyphens, each 1–63 characters, no leading or
    trailing hyphen or dot, at most 253 characters in total. BoringTun exits with status 1 on
    a domain it rejects (FACT) and on a domain given with `stun` (VERIFIED). Mirroring the
    rules means the daemon never refuses a value the installer accepted.
- **Environment boundary.** The three keys join the `unset` list in `validateParamsFile`
  (l.5972). Exported variables therefore cannot alter an existing installation, which is the
  same security boundary as the AWG 3.x keys. Environment values are honoured only by a fresh
  install. When an existing installation is managed while a conflicting `AWG_BACKEND` is
  exported, the installer prints that the variable is ignored.
- **Virtualization check before params are loaded.** `checkVirt` runs in `initialCheck`
  before params are loaded. It reads `AWG_BACKEND` with a non-sourcing parser, the same
  technique as the web helper's `emit_protocol_status`, only to choose the virtualization
  policy. The authoritative load remains `validateParamsFile`.

### 4.3 Derived artefacts (rendered from params, regenerable)

| Artefact | kernel | boringtun |
|---|---|---|
| `/etc/systemd/system/awg-quick@<if>.service.d/override.conf` | Today's content, byte-identical | Supervised drop-in (§7.4) |
| `/etc/modules-load.d/amneziawg.conf` | As today | Never created |
| `/etc/amnezia/amneziawg/<if>.boringtun` | Absent | Launcher runtime file, root-owned 0600, with `IMITATE_PROTOCOL=` and `IMITATE_DOMAIN=` |
| `/etc/modprobe.d/amneziawg-install-boringtun.conf` | Absent | Only when the module exists on disk and the operator accepts a module load override (§7.11) |

The runtime file deliberately uses a non-`.conf` extension. Nothing that scans `*.conf` in
the AWG directory picks it up: the proxy installer's fallback detection and the web helper's
path validation. It is removed with the directory on uninstall.

### 4.4 Installed artefacts and runtime state (PROPOSAL)

```
/usr/local/lib/amneziawg-install/boringtun/
    <release-id>/boringtun-cli          root:root 0755
    <release-id>/MANIFEST               source repo, commit, release id, target, sha256, channel
    <release-id>/LICENSE                BSD-3-Clause notice (redistribution requirement)
    <release-id>/THIRD-PARTY-LICENSES
    current  -> <release-id>
    previous -> <older release-id>      (rollback target, if any)
/usr/local/libexec/amneziawg-install/
    awg-boringtun-launch                entry point handed to awg-quick
    awg-backend-ctl                     precheck | poststart | stop | poststop | sync
/run/amneziawg-install/                 tmpfs, root 0700
    boringtun-<if>.pid, <if>.up
/var/run/wireguard/<if>.sock            created and removed by BoringTun
/var/run/amneziawg/<if>.sock            symlink created by BoringTun (awg searches here)
```

### 4.5 Readers of params (FACT)

- **The installer** sources params after validation.
- **The web helper** runs `emit_safe_params` (helper l.378), which is an allowlist. Unknown
  keys are not emitted, so the new keys stay invisible to the panel until they are
  deliberately allowlisted. All three are non-secret.
- **The proxy installer** sources params in a subshell for `SERVER_AWG_NIC`, `SERVER_PORT` and
  `AWG_PROTOCOL_VERSION` only. Extra keys are harmless.

### 4.6 Compatibility across installer versions

- **Old params files** have no backend key and normalize to `kernel`.
- **New params read by an older installer.** `AWG_BACKEND='kernel'` is ignored and harmless.
  `AWG_BACKEND='boringtun'` is also ignored, so the older script would run its kernel repair
  logic on a BoringTun host: installing headers, running DKMS and calling `modprobe`. That
  cannot be fixed retroactively. Mitigations:
  - The installer refuses to install or switch to BoringTun while an installed web panel's
    lifecycle-script copy (`/usr/local/bin/amneziawg-install.sh`) lacks backend support.
  - Documentation states that BoringTun hosts need a backend-aware installer.
  - **OPEN:** a params format version for future schema changes.

### 4.7 Invalid combinations

| Backend | Protocol | Standalone proxy | Built-in imitation | Allowed | Enforced by |
|---|---|---|---|---|---|
| kernel | 2.0 | absent or present | — | yes (unchanged) | — |
| kernel | 3.0 / 3.1 | absent | — | yes (unchanged) | — |
| kernel | 3.0 / 3.1 | present | — | **no** | Proxy installer today (l.358). **New:** the installer refuses `--enable-awg3`/`--enable-awg31` while the proxy is installed. This is a behaviour change that needs maintainer sign-off (§10.1). |
| kernel | any | any | set | **no** | Params validation (§4.2) |
| boringtun | 2.0 / 3.0 / 3.1 | absent | `none` | yes | — |
| boringtun | 2.0 | absent | dns / quic / sip / stun | yes | — |
| boringtun | 3.0 / 3.1 | absent | dns / quic / sip / stun | yes, with an explicit warning (§9.4) | Installer warning and confirmation |
| boringtun | any | present | any | **no** | Installer refuses BoringTun while a proxy is installed; the proxy installer refuses a BoringTun backend (§10.4) |

---

## 5. Kernel backend behaviour

**Unchanged (PROPOSAL, and a hard requirement):**

- Package set, headers, `deb-src` handling, DKMS, `depmod` and modules-load.
- The drop-in text, including `ExecStartPre=modprobe amneziawg`.
- The `modprobe` start gate and all diagnostic text.
- `ensureAmneziawgKernelModule`'s repair behaviour and exit semantics.
- The probe's scratch interfaces `awgp…` and `awgv…` of type `amneziawg`.
- The exact `awg syncconf` idiom.
- LXC and OpenVZ rejection, and uninstall.

**Determinism today (FACT).** `awg-quick` falls back to
`${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}` when `ip link add … type amneziawg`
fails and `/sys/module/amneziawg` is absent (tools `wg-quick/linux.bash` l.88–96).
The drop-in's `ExecStartPre=modprobe amneziawg` fails the unit before that fallback can run
when the module cannot load. The kernel backend therefore never silently switches to
userspace after a kernel update. This must be preserved, so kernel units never set
`WG_QUICK_USERSPACE_IMPLEMENTATION`.

**The only kernel-visible change.** Params gain `AWG_BACKEND='kernel'` and two empty
imitation keys the next time the file is rewritten.

**Deliberately out of scope for the kernel path:**

- Signal-safe cleanup of kernel scratch interfaces. Today an interrupt during a probe can
  leave an `awgpNNN` link.
- Enforcement of "proxy plus AWG 3.x". This is proposed separately (§10.1).

---

## 6. BoringTun backend behaviour

### 6.1 Facts about BoringTun that shape the design

| Topic | Finding | Evidence |
|---|---|---|
| CLI | `boringtun-cli [-f/--foreground] <IF>`. Environment equivalents include `WG_THREADS` (default 4), `WG_LOG_LEVEL` (`error`, `info`, `debug` or `trace`; there is no `warn`), `WG_LOG_FILE` (default `/tmp/boringtun.out`), `WG_SUDO` (`--disable-drop-privileges`), `WG_UAPI_FD`, `WG_TUN_FD`, `WG_IMITATE_PROTOCOL`, `WG_IMITATE_DOMAIN` and `WG_PROBE_REPLY_RATE`. | FACT |
| Boolean environment values | `WG_SUDO` accepts only `true` or `false`; `WG_SUDO=1` is rejected by argument parsing. | VERIFIED |
| Startup validation | Invalid imitation values are rejected before daemonizing, with exit status 1 or 2. | VERIFIED |
| TUN | Opens `/dev/net/tun` as a multi-queue TUN (`tun_flags 0x1101`, 4 queues). It is not persistent, so the link disappears when the process dies. | VERIFIED |
| UAPI sockets | Binds `/var/run/wireguard/<if>.sock` and symlinks `/var/run/amneziawg/<if>.sock`. Directories and socket are root-only (mode 0750). | VERIFIED |
| Stale sockets | A pre-existing socket path is replaced at startup. A stale socket left by a dead daemon is ignored by `awg show interfaces`. | VERIFIED |
| Socket watchdog | The daemon exits within about a second if its socket file is deleted. | FACT (`register_monitor`) |
| Interface removal | `ip link delete <if>` makes the daemon exit and remove its sockets. After SIGKILL the link disappears and the sockets remain. | VERIFIED |
| UAPI coverage | Every `[Interface]` key the installer writes is supported: Jc/Jmin/Jmax, S1–S4, H1–H4 ranges, `HeaderProtectionKey`, `ContentPaddingAddition`, the four timers, `RandomTrailers` and `DisableCookies`. `I1`–`I5` are accepted and ignored. | FACT, VERIFIED readback |
| Stricter validation | BoringTun enforces timer floors that the kernel module and amneziawg-go do not, and rejects S sizes that cannot form a datagram. | FACT |
| Keys | The private key is never returned by `get=1`. The tools do not parse BoringTun's `own_public_key`. `awg show` therefore prints no interface key, `awg show all dump` prints `(none)` for both key columns, and `awg showconf` has no `PrivateKey`. | FACT, VERIFIED |
| Privilege drop | By default BoringTun drops to the `getlogin()` user. Under systemd this fails with `NULL from getlogin` and the daemon exits 1. `--disable-drop-privileges` is required, so the daemon runs as root. | VERIFIED |
| Logging | In daemon mode the log writer is lost after the fork, and the log file stays empty (upstream README says the same). In foreground mode logs go to stderr. `tracing-subscriber` 0.3.23 honours `NO_COLOR`. | VERIFIED, FACT |
| Listen sockets | Binds `0.0.0.0:<port>` and `[::]:<port>` and has no bind-address option. It works with `net.ipv6.conf.all.disable_ipv6=1`. With the `ipv6.disable=1` boot option, the IPv6 socket cannot be created and startup is expected to fail. | VERIFIED; the boot-option case is INFERRED |
| Listen-port re-bind leak | Every `set=1` carrying `listen_port` binds new sockets without closing the old ones. One `awg syncconf` whose input contains `ListenPort` adds 2 fds; 50 of them left 102 sockets on the port. Input without `ListenPort` causes no growth and keeps the port. Three of 200 pings were lost during 20 back-to-back syncconfs (single run). Under systemd's default soft `NOFILE` limit of 1024, the daemon would exhaust descriptors after roughly 500 syncconfs. | VERIFIED; the exhaustion estimate is INFERRED |
| Datapath | A BoringTun server with AWG 3.1 (header protection, content padding, timers, RandomTrailers) and DNS imitation, talking to a plain BoringTun client in network namespaces, passed ping and a 16 MiB TCP transfer with a matching SHA-256. Interop with amneziawg-go and the kernel module is covered by upstream harnesses in `scripts/`, which were not run here. | VERIFIED; interop is FACT |
| Probe responder | With imitation set, the listen port answers DNS (SERVFAIL), STUN (Binding Success) and QUIC (Version Negotiation). SIP is detected but not answered. Loopback sources are never answered. Replies share an aggregate byte budget. A DNS probe from a non-loopback source received a 33-byte SERVFAIL, and one from 127.0.0.1 got no reply. | FACT, VERIFIED |
| Version | `boringtun 0.7.1`. No commit is embedded, so provenance must come from the installer's manifest. | VERIFIED |
| Releases | Upstream CI publishes no binary release artefacts. | FACT |

### 6.2 Host behaviour summary (PROPOSAL)

- **Datapath:** a TUN device named `<if>`, created by BoringTun, which `awg-quick` starts
  through the launcher.
- **Configuration:** config files, `awg` tools, the unit name and the firewall hooks are
  identical to the kernel backend.
- **Packages:** `amneziawg-tools` from the Amnezia PPA with `--no-install-recommends`, plus
  `nftables`, `iptables` and `qrencode`. No headers, DKMS or `deb-src`.
- **Kernel updates:** nothing to rebuild.

### 6.3 `ensureAwgBackendReady` for BoringTun (PROPOSAL)

- **Mode 0 (probe preparation):**
  - The binary store and `current` link are valid, root-owned and not writable by
    group/other, and the binary checksum matches its `MANIFEST`.
  - `/dev/net/tun` is a character device.
  - The IPv6 socket family exists (`/proc/sys/net/ipv6`).
  - The helpers are present.
  - Mode 0 never touches the service.
- **Mode 1 (before live changes):**
  - Everything in mode 0.
  - The drop-in and runtime file exist. A missing one is regenerated from params; a
    differing one produces a warning and is left for an explicit reconcile command.
  - The unit is started if inactive, reusing `ensureAwgQuickRunning`.
  - The interface answers `awg show <if> listen-port`.
- **Failures** exit 1 with BoringTun-specific hints, exactly like the kernel path.

### 6.4 Live configuration and the `ListenPort` filter (PROPOSAL)

`awgSyncInterfaceConfig` for BoringTun takes `awg-quick strip <if>`, drops the `ListenPort = N`
line when `awg show <if> listen-port` already equals N, and runs `awg syncconf`. If the
configured port differs from the running port, the line is kept and the operator accepts one
leaked socket pair; port changes normally go through a restart anyway.

The rule is semantically neutral for the kernel module, where a same-port set is a no-op.
In the installer it is nevertheless applied only to BoringTun, so the kernel code path stays
byte-identical. The BoringTun drop-in overrides `ExecReload` to use the same filtered sync.
The web helper applies the equality rule for both backends (§11.2).

### 6.5 Performance (OPEN)

BoringTun is userspace, with 4 worker threads and a multi-queue TUN. It does not use TUN
offloads: `ip -d link` shows `vnet_hdr off`. Expect lower throughput and higher CPU use than
the kernel module. Measure with `iperf3` on real VMs (x86_64 and aarch64, several core
counts) before recommending BoringTun for high-throughput servers. `WG_THREADS` is not
exposed in the first version.

---

## 7. systemd and awg-quick integration

### 7.1 How awg-quick runs a userspace implementation (FACT)

In `wg-quick/linux.bash`, `add_if` (l.88–96 at `ee0f0a9`) first runs
`ip link add "$INTERFACE" type amneziawg`. Only if that fails does it check two things:
whether `/sys/module/amneziawg` is absent, and whether the command named by
`WG_QUICK_USERSPACE_IMPLEMENTATION` exists. The default command is `amneziawg-go`. When both
checks pass, it prints a fallback notice and runs that command with the interface name as
its only argument.

Consequences:

- **One argument.** The implementation receives only the interface name. Everything else must
  come from the environment or from fixed files.
- **Readiness is the implementation's job.** `awg-quick` continues with `awg setconf` as soon
  as the command returns.
- **Kernel first.** If the module is loaded, or can be autoloaded (it declares
  `MODULE_ALIAS_RTNL_LINK`), a kernel interface is created and BoringTun never runs.
- **Teardown.** `cmd_down` and `del_if` delete the link. BoringTun exits because its TUN
  device disappears; `awg-quick` never signals it.

### 7.2 Decision: `awg-quick@<if>.service` stays the lifecycle manager (PROPOSAL)

This was verified with BoringTun under systemd 255:

- **Start:** the fallback launched the implementation, followed by `awg setconf`, addresses,
  MTU and PostUp hooks.
- **Queries:** `awg show` and `awg showconf` worked.
- **Reload and restart:** `systemctl reload` (syncconf) and restart both worked.
- **Stop:** the link was removed, the daemon exited, its sockets were removed and PostDown
  hooks ran.

The installer, web panel, proxy scripts and operators keep one unit name. Hooks, firewall
handling and `awg-quick strip` stay identical across backends.

### 7.3 Alternatives considered

| Alternative | Why it is not proposed |
|---|---|
| A dedicated `amneziawg-boringtun@.service` with its own bring-up | It would re-implement `awg-quick`: addresses, MTU, routes, DNS, hooks and `SaveConfig`. It diverges between backends and breaks the unit name the web panel and proxy rely on. |
| A separate daemon unit plus `awg-quick@` attaching to it | `awg-quick up` refuses an interface that already exists (FACT). |
| A generated copy of `awg-quick` with an overridden `add_if` | Forks an external script, which goes stale on tools upgrades. |
| A PATH shim for `ip` that rejects `type amneziawg` | `awg-quick` prepends its own directory to PATH, and `/usr/bin/ip` exists on Ubuntu 24.04 (VERIFIED), so the shim is never used. |
| An upstream `awg-quick` option to force userspace | It would be the cleanest fix but does not exist and is not required. Could be requested upstream (OPEN). |

### 7.4 The BoringTun drop-in (PROPOSAL)

The installer renders this for BoringTun. The packaged `ExecStart=/usr/bin/awg-quick up %i`
is kept.

```ini
# Managed by amneziawg-install (backend: boringtun). Regenerated from params.
[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=forking
RemainAfterExit=no
PIDFile=/run/amneziawg-install/boringtun-%i.pid
TimeoutStartSec=30
Restart=on-failure
RestartSec=3
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=/usr/local/libexec/amneziawg-install/awg-boringtun-launch
ExecStartPre=/usr/local/libexec/amneziawg-install/awg-backend-ctl precheck %i
ExecStartPost=/usr/local/libexec/amneziawg-install/awg-backend-ctl poststart %i
ExecReload=
ExecReload=/usr/local/libexec/amneziawg-install/awg-backend-ctl sync %i
ExecStop=
ExecStop=/usr/local/libexec/amneziawg-install/awg-backend-ctl stop %i
ExecStopPost=/usr/local/libexec/amneziawg-install/awg-backend-ctl poststop %i
```

| Directive | Purpose |
|---|---|
| `Type=forking`, `PIDFile=`, `RemainAfterExit=no` | systemd tracks the BoringTun process as the main PID. A crash becomes a unit failure rather than a silent outage behind "active (exited)". Only the launcher writes the PID file, so a start in which `awg-quick` took another datapath cannot become active (VERIFIED: it times out, fails, runs `ExecStopPost` and cleans up the cgroup). |
| `TimeoutStartSec=30` | Bounds that fail-closed wait. Without it, systemd keeps waiting for its default start timeout; the unit was still activating after 60 seconds in testing (VERIFIED). |
| `Restart=on-failure`, `RestartSec=3` | Restarts after a crash; restart after SIGKILL was verified. A clean exit (for example an operator's `ip link del`) does not restart the unit. |
| `StartLimitIntervalSec=120`, `StartLimitBurst=5` | Stops restart loops caused by configuration errors. |
| `Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=` | The only environment variable the unit sets. All BoringTun options come from the launcher (§7.6). |
| `ExecStartPre=… precheck` | Refuses to start when the kernel module is loaded or autoloadable, the binary fails verification, the runtime file is invalid, `/dev/net/tun` is missing or the IPv6 socket family is absent (§7.11). |
| `ExecStartPost=… poststart` | Verifies that the link is a TUN device, that the PID file points at a live process whose `/proc/<pid>/exe` is the store binary, and that the UAPI responds. Then writes `/run/amneziawg-install/<if>.up`. |
| `ExecReload=… sync` | Filtered sync (§6.4) instead of the packaged unfiltered one. |
| `ExecStop=… stop` | Runs `awg-quick down %i` for the interface its start recorded, after recording the attempt (as implemented, §21.1). If the interface is already gone it exits 0 without `awg-quick down`, and `poststop` replays PostDown. |
| `ExecStopPost=… poststop` | Crash-safe teardown (§7.9). Runs after every stop, including crashes and failed starts (VERIFIED). |

### 7.5 Launcher contract (PROPOSAL)

`awg-boringtun-launch <if>` is what `awg-quick` executes. It:

1. Validates `<if>` against `awg-quick`'s own name pattern, `^[a-zA-Z0-9_=+.-]{1,15}$`.
2. Resolves `…/boringtun/current/boringtun-cli`. It requires the real path to be inside the
   store, the file to be root-owned and not group/other-writable (directories included), and
   its SHA-256 to equal the `MANIFEST`.
3. Reads `/etc/amnezia/amneziawg/<if>.boringtun`. The file must be root-owned, a regular file,
   not a symlink and mode 0600. Only the allowlisted keys are accepted, each with a strict
   regular expression. A missing file fails closed; `ensureAwgBackendReady` regenerates it
   from params.
4. Creates `/run/amneziawg-install` (0700) and removes a stale PID file for `<if>`.
5. Starts BoringTun as a detached child, with no inherited environment except `PATH` and
   `NO_COLOR=1`:
   `boringtun-cli --foreground --disable-drop-privileges --verbosity error
   [--imitate-protocol P] [--imitate-domain D] <if>`.
   Its stdout and stderr inherit the unit's journal stream.
6. Waits up to 10 seconds. Readiness means the socket exists, the symlink exists and
   `awg show <if> listen-port` succeeds. It fails immediately if the child exits.
7. Writes the PID file and exits 0. On any failure it kills the child, removes only this
   interface's socket paths and exits non-zero, so `awg-quick` deletes the link and fails.

Implementation suggestion: the helpers are generated by the installer from functions defined
in `amneziawg-install.sh` itself, emitted with `declare -f`. The installer is often run as a
single downloaded file, and this keeps the logic single-sourced and unit-testable by sourcing.

### 7.6 Environment injection (PROPOSAL)

- **Nothing inherited reaches BoringTun.** The unit environment passes through `awg-quick` to
  the launcher, but the launcher starts BoringTun with `env -i` and explicit flags. Inherited
  `WG_*` variables therefore cannot alter the daemon: `WG_TUN_FD`, `WG_UAPI_FD`,
  `WG_LOG_FILE` and `WG_IMITATE_*`. This was a real risk because BoringTun reads all of them
  (FACT).
- **Imitation comes from the runtime file, not `Environment=`.** A systemd start, the
  installer's manual `awgBackendQuickUp` and a container entrypoint then behave identically,
  and the values are validated where they are used.
- **The runtime file is rendered from params.** Params remain the only source of truth.

### 7.7 Logs

- **Journal.** Daemon output appears under `journalctl -u awg-quick@<if>` (VERIFIED with the
  launcher approach). `NO_COLOR=1` suppresses ANSI sequences, which were otherwise visible in
  the journal (VERIFIED).
- **Verbosity.** The default is `error`, as quiet as the kernel. BoringTun emits important
  warnings at WARN, for example the header-protection plus imitation notice. Its CLI has no
  `warn` level, so they appear only at `info` or above (VERIFIED). The installer therefore
  prints its own warnings. **OPEN:** expose the log level.
- **Expected noise.** Each start logs `Error: Unknown device type.` from `awg-quick`'s kernel
  attempt (VERIFIED). This is expected and must be documented.

### 7.8 Restart and failure semantics (VERIFIED with the directives above)

| Event | Observed systemd behaviour | Design response |
|---|---|---|
| `systemctl stop` | `ExecStop` runs: `awg-quick down` succeeds and PostDown runs. Then `ExecStopPost` runs with `SERVICE_RESULT=success`. | `stop` records the completed down; `poststop` has nothing to do. |
| Daemon crash (SIGKILL) | `ExecStop` does **not** run. `ExecStopPost` runs with `SERVICE_RESULT=signal`. The unit restarts after `RestartSec`, and PostUp runs again without a PostDown in between. | `poststop` sees an attempt that is up and was never brought down, and replays PostDown once (§7.9, §21.1). |
| Operator runs `ip link del <if>` | The daemon exits 0. `ExecStop` runs; as implemented, `stop` finds the interface gone and does not run `awg-quick down` (§21.1). `ExecStopPost` runs. The unit becomes inactive and is not restarted. | `poststop` replays PostDown once. |
| `awg-quick` used another datapath, so no PID file was written (simulated with an implementation that does not write it) | The unit stays "activating" until `TimeoutStartSec`, then fails with `timeout`, kills its cgroup and runs `ExecStopPost`. `Restart=` retries. | `poststop` removes a surviving non-TUN link with `awg-quick down`, which runs PostDown. Start limits stop the loop. |
| `ExecStartPost` fails | `ExecStop` is skipped and `ExecStopPost` runs. | Same cleanup. |
| Reload | `ExecReload` works with `Type=forking`. | Filtered sync. |

Without supervision (plain `Type=oneshot`), a BoringTun crash left the unit "active (exited)"
while the interface was gone and `awg syncconf` failed (VERIFIED). That is why supervision is
proposed.

### 7.9 Crash-safe teardown (PROPOSAL)

> As implemented in PR 3, the `.up` marker below is replaced by the per-attempt
> ownership state and flags of §21.1, which also record whether `awg-quick
> down` or a replay was started, so no PostDown hook is ever run twice.

`poststop <if>`:

1. **Link still present and not TUN.** A kernel link, created because `awg-quick` took the
   kernel path, is valid for `awg-quick`, so `poststop` runs `awg-quick down <if>`. That runs
   the configured PostDown hooks and deletes the link.
2. **`.up` marker present.** The interface disappeared without a clean `awg-quick down`.
   `poststop` replays the `[Interface]` PostDown hooks from the server config, using a parser
   that matches `awg-quick`'s `parse_options`: comments stripped at the first `#`, keys
   trimmed and case-insensitive, only the `[Interface]` section, original order, `%i`
   substituted. Each hook runs in its own `bash -c`, and errors are logged and ignored.
   PreDown and `SaveConfig` are never run.
3. **Stale sockets.** `poststop` removes `/var/run/wireguard/<if>.sock` and
   `/var/run/amneziawg/<if>.sock` only if `awg show <if>` fails. Deleting a live daemon's
   socket would terminate that daemon (FACT).
4. It removes the PID file and marker.

Replay keeps the server config identical across backends and covers operator-added hooks.
The alternative, generating idempotent firewall hooks, would change `writeFirewallRules`
output for one backend only.

### 7.10 `awg-quick down` with the userspace implementation (VERIFIED)

`cmd_down` lists interfaces with `awg show interfaces`, which includes userspace interfaces
through their sockets. It then runs PreDown, the optional `SaveConfig`, `ip link delete`,
its own DNS and firewall cleanup, and PostDown. BoringTun exits within about a second once
its TUN device disappears and removes its sockets on exit. `awg-quick` never signals the
daemon. Anything left in the cgroup is killed by systemd's `KillMode`.

`SaveConfig = true` must be rejected for BoringTun, both by params validation and by the
precheck. Because `awg showconf` lacks `PrivateKey`, saving would erase the server's private
key. The installer never writes `SaveConfig`, but an operator might add it.

### 7.11 An AmneziaWG kernel module on a BoringTun host

**Facts.** The module declares `MODULE_ALIAS_RTNL_LINK`, so `ip link add … type amneziawg`
autoloads it when it is installed on disk. `awg-quick` tries the kernel first. Containers
share the host kernel, so a module loaded on the host is usable inside a container's network
namespace (INFERRED).

**Design (PROPOSAL):**

1. **Precheck refuses to start** if `/sys/module/amneziawg` exists, or if the module is
   present on disk (`modinfo -n amneziawg` succeeds) and the installer's load-override file is
   absent. The message offers four remedies:
   - Unload the module with `modprobe -r amneziawg`.
   - Remove `amneziawg-dkms`.
   - Accept `/etc/modprobe.d/amneziawg-install-boringtun.conf`, a load override that stops
     the module from being loaded on this host.
   - Switch the backend.
2. **Poststart verifies TUN and process identity.** This catches autoload races and cases the
   precheck cannot see, such as a container on a host whose module can autoload.
3. **The PID-file contract** ensures a kernel-path start never becomes active (§7.8).
4. **Package hygiene.** `--no-install-recommends` keeps DKMS off BoringTun hosts. The install
   preflight detects existing module packages and offers the load override.

**Which load override (DECIDED in PR 4: `install amneziawg /bin/false`; see §21.2).** A modprobe
`blacklist amneziawg` line makes modprobe ignore the module's aliases. The PR 4 coexistence
job showed that this stops the kernel's own `rtnl-link-amneziawg` request, which is what
`ip link add … type amneziawg` triggers, but not an explicit `modprobe amneziawg`.
`install amneziawg /bin/false` blocked both. It is therefore the safer choice, but a later
migration back to the kernel must remove it first (§20). Note that `modprobe -n` succeeds for
a module with an `install` override, so the precheck checks the override file and parses the
actions the dry run lists rather than relying on its exit status.
5. **Scratch interfaces for probes and validation launch BoringTun directly.** They never call
   `ip link add … type amneziawg`, so they are deterministic regardless of the module.

### 7.12 Manual and non-systemd operation (PROPOSAL)

- `awgBackendQuickUp <conf>` runs the precheck and then
  `WG_QUICK_USERSPACE_IMPLEMENTATION=<launcher> awg-quick up <conf>`. The transaction's
  manual-interface path uses it, and so do containers.
- A plain `awg-quick up awg0` on a BoringTun host fails with `Unknown device type` unless
  `amneziawg-go` happens to be installed. Documentation must point operators to
  `systemctl` or the installer.

---

## 8. AWG 2.0 / 3.0 / 3.1 validation design

### 8.1 Today (FACT)

- **Capability probe.** `probeAwgProtocolCapability REQUIRE_31 KEY` (l.1731):
  - Creates the scratch link `awgp<BASHPID % 10^8>`.
  - Applies S1–S4 of 12–15, a header-protection key, `ContentPaddingAddition 11-13` and the
    four timers, plus RandomTrailers and DisableCookies for 3.1.
  - Reads every field back with `awg show <if> <field>` and compares, then deletes the link.
  - Its error text names the kernel module.
- **Staged validation.** `validateStagedAwgConfigs` (l.6810) creates `awgv…` and runs
  `awg setconf` on the stripped `[Interface]` section of every staged config.
- **Locking and re-probing.** Both run under the lifecycle lock from `setAwgProtocolMode`
  (l.7069). A same-mode enable request re-probes without rotating the key.

### 8.2 Abstraction boundary (PROPOSAL)

Only three things become backend-specific: create a scratch interface, destroy it (with
guaranteed cleanup), and the failure detail text. The probe configuration, readback
comparisons, staged-file generation, transaction and rollback stay single-sourced. In
`probeAwgProtocolCapability`, the `ip link add dev "${PROBE_INTERFACE}" type amneziawg`
condition becomes `awgBackendCreateScratchInterface "${PROBE_INTERFACE}"`, and the delete
becomes `awgBackendDestroyScratchInterface`. `validateStagedAwgConfigs` changes the same way.

### 8.3 Kernel scratch interface (unchanged)

`ip link add dev NAME type amneziawg` and `ip link delete dev NAME`. The existing tests
assert these commands in `tests/test-awg3.sh`.

### 8.4 BoringTun scratch interface (PROPOSAL)

- **Preconditions.** The lifecycle lock is held and the name is unused: no link, no socket
  path and not listed by `awg show interfaces`. BoringTun replaces an existing socket path
  when it binds, which would hijack a live instance with the same name, so the check is
  mandatory.
- **Binary and flags.** The production `current` binary is used with the production startup
  flags from params, so validation exercises exactly what will run. Today UAPI validation
  does not depend on startup flags, but that may change.
- **Launch through a transient unit** when systemd is PID 1:
  `systemd-run --unit=amneziawg-scratch-<name> --collect -p Type=exec boringtun-cli
  --foreground --disable-drop-privileges [flags] <name>`. Without systemd (containers) it is
  launched directly in the background. The transient unit is needed for two reasons:
  - The daemon gets its own cgroup, so cleanup is a clean kill.
  - It runs outside the caller's sandbox. A web-triggered migration runs the installer inside
    `amneziawg-web.service`, which has `ProtectSystem=strict`. There, `/run` is read-only
    unless `ProtectControlGroups=yes` is also set; on systemd 255 that combination
    re-mounts `/run` read-write (VERIFIED). Relying on that quirk would be fragile.
    Requesting a transient unit from inside the sandbox works (VERIFIED, E8). `awg` inside
    the sandbox can read and write the resulting UAPI socket even when `/run` is read-only
    (VERIFIED, E11).
- **Readiness.** Wait up to 10 seconds for `/var/run/amneziawg/<name>.sock` and a successful
  `awg show <name> listen-port`. Fail if the process exits first.
- **Use.** The existing `awg setconf` and `awg show` calls are unchanged.
- **Destroy.**
  1. `ip link delete dev <name>`; the daemon exits (VERIFIED).
  2. Stop the transient unit, or kill the tracked PID.
  3. Remove this name's socket paths if they remain.
- **Guaranteed cleanup.** The scratch lifecycle runs in a subshell with
  `trap … EXIT HUP INT TERM`. Cleanup targets tracked PIDs and unit names, never `pkill -f`:
  during testing a `pkill -f` pattern matched its own invoking shell (VERIFIED hazard).
- **Sweep.** Under the lock, leftover `awgp*` and `awgv*` scratch units, links and sockets from
  interrupted runs are removed. Under the lock no other installer operation can own them.

### 8.5 Verified probe equivalence

The installer's exact AWG 3.1 probe configuration was applied to a BoringTun scratch
interface. All eight readbacks matched: the header-protection key, content padding
`11-13`, the timers `101-103`, `5-7`, `181-183` and `9-11`, `random-trailers on` and
`disable-cookies on`. Staged `[Interface]`-only `setconf` of a full server config succeeded,
and `ip link delete` ended the daemon and removed its sockets (VERIFIED).

### 8.6 Why validation must run on BoringTun

The two datapaths accept different configurations. BoringTun enforces timer floors that
neither amneziawg-go nor the kernel module check, rejects unknown `[Interface]` keys and
rejects S sizes that cannot form a datagram (FACT). A configuration validated on the kernel
could fail on BoringTun, so validation must use the datapath that will run.

### 8.7 Messages

`FAIL_DETAIL` becomes backend-specific. For example: "the pinned BoringTun build rejected AWG
3.0 fields (run --upgrade-boringtun or upgrade amneziawg-tools)". For the kernel, today's text
is kept verbatim.

### 8.8 Transaction integration

- **`applyAwgProtocolTransaction`.** The service path is unchanged (`systemctl stop` and
  `restart`). The manual-interface path uses `awgBackendQuickUp`. Rollback is unchanged.
- **For BoringTun,** a restart re-reads the runtime file. Protocol transactions never change
  imitation settings, and imitation changes are a separate transaction (§9.3).
- **Same-mode re-probing** without key rotation is preserved for both backends.

---

## 9. Protocol imitation design

### 9.1 BoringTun facts

- **Startup-only.** Imitation has no UAPI key; it exists only as startup flags. BoringTun keeps
  the setting across `set=1` transactions, so `awg syncconf` does not disable it (FACT).
  Changing it therefore requires a restart.
- **Protocols:** `none`, `dns`, `quic`, `sip` and `stun`. A domain is used only by `dns`,
  `quic` and `sip`, and is refused with the others (FACT, VERIFIED).
- **Server-side only.** The server shapes the S-prefixes of the packets it sends. A client
  strips S bytes without looking at them. A DNS-imitating BoringTun server interoperated with
  a non-imitating client, and server-to-client datagrams began with a well-formed DNS header
  (flags `0x0120`, QDCOUNT 1, ARCOUNT 1) (VERIFIED). Client-to-server traffic is shaped only
  if the client itself imitates, for example WireSock Secure Connect or a BoringTun-based
  client. Standard AmneziaWG clients leave that direction plain.
- **Probe replies.** Replying to unauthenticated probes turns on by default when a protocol is
  set, subject to an aggregate byte budget. It can be disabled with
  `--probe-reply-rate 0` (FACT).
- **At the pinned commit `71d8878`** (FACT, from its source, and VERIFIED by the PR 5 live
  test): only a probe of the imitated protocol is answered. A DNS query gets `SERVFAIL`, a STUN
  Binding Request a Binding Success, and a QUIC long-header packet of at least 1200 bytes gets
  Version Negotiation only when its version is not one real servers accept (v1 and v2 get no
  reply). SIP is never answered. The budget is 16 KiB/s by default. Sources that are loopback,
  link-local, multicast, broadcast, `0.0.0.0/8` or `240.0.0.0/4`, or use port 0, are never
  answered. DNS and SIP take a strict LDH hostname; QUIC accepts any printable SNI up to 253
  bytes. A hostname with `none` or `stun`, or an invalid one, makes the binary exit before it
  daemonizes, as does a `--probe-reply-rate` above 0 with `none`.

### 9.2 Persisted model and validation (PROPOSAL)

- The params keys are `AWG_BORINGTUN_IMITATE_PROTOCOL` and `AWG_BORINGTUN_IMITATE_DOMAIN`
  (§4.1). They are rendered into the runtime file and validated at load time and again by the
  launcher.
- The probe reply rate stays at BoringTun's default in the first version (**OPEN** whether to
  expose it).

### 9.3 Operations (PROPOSAL)

- **Install time:** `AWG_BORINGTUN_IMITATE_PROTOCOL` and `AWG_BORINGTUN_IMITATE_DOMAIN` from
  the environment (fresh installs only), or an interactive question defaulting to `none`.
- **Change:** `--set-boringtun-imitation <none|dns|quic|sip|stun> [domain]` runs as a
  transaction:
  1. Take the lock and load params.
  2. Require `AWG_BACKEND=boringtun` and validate the new values.
  3. Print the warnings in §9.4.
  4. Back up params and the runtime file, then write the new ones.
  5. Restart the unit if it is active.
  6. Verify the interface, UAPI and listen port.
  7. On failure, restore both files, restart and report.
- **No client changes.** Clients need no new config because S sizes are unchanged; only the
  S-prefix contents change.

### 9.4 Trade-offs the installer must expose

1. **Header protection plus imitation (AWG 3.x).** The header-protection nonce is the first
   12 bytes of the S-prefix. Imitation makes those bytes protocol-shaped (a DNS header varies
   mostly in its transaction ID), so the nonce repeats. An observer who collects two
   datagrams can undo the masking and classify message types again. Confidentiality is not
   affected, because the Noise transport encryption is unchanged. BoringTun warns about this
   rather than refusing it (FACT). The installer should state that under imitation, AWG 3.x
   header protection adds little unmasking resistance. The datagrams present as the imitated
   protocol instead. **At `71d8878`** the effect depends on the protocol: `dns` leaves a
   16-bit nonce, `stun` a 32-bit one, and `quic` and `none` a random one. SIP with any of S1–S4
   at 31 bytes or more is **refused** (`HeaderProtectionNonce::Degenerate`): the request line
   would leave the nonce a few fixed strings. The installer refuses that combination itself
   (§21.3).
2. **Upstream-collision avoidance is off under imitation.** With header protection on and no
   imitation, BoringTun re-frames a transport packet that an upstream receiver would misread
   as a control message. The kernel module (`4569c4c`) and amneziawg-go (`b5928ef`) drop such
   packets. BoringTun's own notes put the per-framing collision probability at up to about 7%
   with the stock installer's H ranges. Under imitation this avoidance is skipped pending a
   per-protocol review (FACT). BoringTun server plus AWG 3.x plus imitation plus kernel or
   go clients may therefore lose a fraction of server-to-client packets. **OPEN:** measure
   this with a live interop test before recommending that combination. Until then the
   installer warns, and recommends imitation with AWG 2.0, or AWG 3.x only with clients
   known to handle it. **Superseded at `71d8878`** (FACT): the per-protocol review landed.
   `imitation_redraw_avoids_upstream_collisions` keeps the avoidance for `none`, `dns`, `quic`
   and `stun`. It excludes only SIP with a request-line prefix, which header protection
   refuses anyway. PR 5 measures kernel-client loss under AWG 3.0 with each imitation
   (§18.6, R5).
3. **Fidelity depends on the S sizes** (FACT, from `fill_dns`, `fill_stun` and `fill_sip` at
   `e4e4dc8`). A complete DNS framing with a root query needs at least 32 bytes of prefix,
   and a domain query needs `12 + len(domain) + 2 + 4 + 15`. STUN needs 20 bytes for a
   complete header. SIP shaping needs at least 31 bytes. QUIC needs only the first byte.
   Below those sizes the prefix degrades to a partial or random shape. The installer
   generates S values from 15 to 150, so some installations will have small S values. The
   installer should warn (not refuse) when `min(S1..S4)` is below the protocol's threshold,
   and should not hard-code these numbers as limits, because they are upstream internals.
4. **Probe responder.** DNS probes get SERVFAIL, STUN probes get Binding Success and QUIC
   probes get Version Negotiation. There is no SIP responder. Loopback sources are never
   answered. The STUN reply is larger than a bare request (about 2.6×), and only the
   aggregate byte budget bounds that reflection (FACT). At `71d8878`, Version Negotiation
   answers only Initials of at least 1200 bytes whose version real servers do not accept;
   QUIC v1 and v2 get no reply (§9.1).
5. **Port choice.** Imitation is more plausible on the protocol's usual port, but the installer
   does not move ports: a port change needs new client configs. Port 53 on a host also conflicts
   with local resolvers such as `systemd-resolved`'s stub. This is documentation only.
6. **Warnings in logs.** BoringTun logs the header-protection-plus-imitation warning only at
   `info` or above, so the installer prints items 1–3 itself.

---

## 10. Relationship with amneziawg-proxy

### 10.1 Current enforcement (FACT)

- The proxy **installer** refuses AWG 3.x
  (`awg_protocol_is_proxy_compatible` l.325, applied at l.358).
- `amneziawg-install.sh` does **not** refuse `--enable-awg3` or `--enable-awg31` while the
  proxy is installed. Only documentation warns against it, and the web panel's migration
  buttons go through the same installer path.
- The proxy's Rust code only documents the AWG 2.0 restriction; it does not detect a
  header-protected configuration at runtime.

"Kernel plus AWG 3.x plus proxy" is therefore disallowed in documentation and at proxy
install time, but not when AWG 3.x is enabled later. **PROPOSAL:** add the missing check to
`setAwgProtocolMode`. This is a kernel-side behaviour change (it refuses a combination that
is already broken), so it is listed separately for maintainer sign-off (PR 8).

### 10.2 Feature comparison

| Aspect | Standalone `amneziawg-proxy` | BoringTun built-in imitation |
|---|---|---|
| Protocols | quic, dns, stun, sip, **auto** | dns, quic, sip, stun (no auto) |
| Where shaping happens | Rewrites the S-prefix of AWG 2.0 packets in flight | Generates the S-prefix natively while building packets |
| AWG versions | 2.0 only; rewriting the prefix breaks 3.x header protection | 2.0, 3.0 and 3.1 (with the caveats in §9.4) |
| Probe responses | QUIC VN, DNS answer (optionally real, forwarded upstream), STUN Binding Success, SIP 100 Trying; optional stateful QUIC handshake continuation | DNS SERVFAIL, STUN Binding Success, QUIC VN; no SIP responder; no DNS forwarding; no QUIC continuation |
| Probe rate limiting | Per client (`--rate-limit`) | Aggregate byte budget |
| Loopback probes | Answered | Never answered |
| Deployment | Separate service; AWG rebound to a backend port | In-process on the same port |
| Domain | `--quic-domain` (SNI for QUIC responses) | `--imitate-domain` (DNS QNAME, SIP URI, QUIC SNI) |

The feature sets are not identical. The installer must not present BoringTun imitation as a
drop-in replacement for proxy deployments that rely on `auto`, real DNS forwarding, SIP
responses or QUIC handshake continuation.

### 10.3 Rule: no proxy in front of BoringTun (PROPOSAL)

- BoringTun already shapes the prefix where the packet is built; a proxy rewriting it again
  is redundant under AWG 2.0 and breaks AWG 3.x header protection.
- The proxy design rebinds AWG to a loopback backend port. BoringTun has no bind-address
  option and always listens on `0.0.0.0` and `[::]` (FACT), so the backend port would stay
  publicly reachable.
- BoringTun never answers loopback probes, and the proxy forwards from loopback, so the two
  responders would interact unpredictably.

### 10.4 Required changes

- **`amneziawg-install.sh`** refuses to install or select BoringTun while the proxy is
  installed. Detection uses the same paths the web panel uses:
  `/etc/systemd/system/amneziawg-proxy.service`, `/usr/local/bin/amneziawg-proxy` and
  `/etc/amneziawg-proxy/proxy.toml`.
- **`amneziawg-proxy/scripts/amneziawg-proxy-install.sh`** adds a guard modelled on
  `awg_protocol_is_proxy_compatible`. `detect_awg_config` (l.336) reads `AWG_BACKEND` the way
  it already reads `AWG_PROTOCOL_VERSION` and refuses anything other than empty or `kernel`,
  pointing to `--set-boringtun-imitation`. This is a script change of roughly ten lines. It
  bumps the proxy component version automatically through `.github/versioning/components.json`.

**Explicit answers:**

- The **first** BoringTun PR (PR 1, §21) leaves the proxy completely untouched: no Rust, no
  scripts, no docs.
- The proxy's **Rust implementation** is never changed by this project.
- The proxy **installer script** gains the guard in the PR that makes BoringTun installable
  (PR 4). Without it, "BoringTun first, proxy later" could not be prevented.
- Existing kernel plus AWG 2.0 plus proxy installations are unaffected. Their params
  normalize to `kernel`, and the proxy's reading of params is unchanged.

### 10.5 Moving a proxied installation to BoringTun (future)

1. Uninstall the proxy with `--restore-awg`, which returns AWG to the public port.
2. Migrate the backend (§20).
3. Set imitation.

Clients keep working throughout because keys, AWG parameters and the endpoint port are
unchanged. The server-to-client camouflage changes from the proxy's to BoringTun's.

---

## 11. Web panel impact

### 11.1 Why the backend stays mostly invisible (FACT, VERIFIED)

- The poller and helper use `awg show all dump`, `awg set … peer … remove` and
  `awg syncconf`. `awg` reaches BoringTun through its socket, and the dump format is produced
  by `awg`, so it is identical for both backends.
- Client configs are rendered with `SERVER_PUB_KEY` from params (`client_manager.rs` l.454).
  The interface key columns in the dump are never used: `parse_dump` stores them, and only
  peer keys are consumed. BoringTun's `(none)` values there are therefore harmless.
- The web unit runs with `ProtectSystem=strict`. Connecting to a Unix socket is not blocked by a
  read-only mount: with `/run` genuinely read-only (`ProtectSystem=strict` alone), `awg` both
  read and changed a BoringTun interface through its socket (VERIFIED, E11). With the web
  unit's full directive set, `awg show all dump` and `awg syncconf` also worked (VERIFIED, E8).
- Protocol migrations started from the web UI run the installer inside the web unit's
  sandbox. Scratch interfaces therefore use transient units (§8.4).

### 11.2 Required changes

- **Leak fix in the privileged helper.** `reconcile_interface` (helper l.575, syncconf l.638)
  drops the `ListenPort = N` line when it equals `awg show <if> listen-port`. For the kernel
  this is equivalent, because a same-port set is a no-op; for BoringTun it prevents the
  socket leak on every web add, remove, enable or disable. It is a root-owned helper change,
  so it needs security review. It lands with the first user-reachable BoringTun PR (PR 4).
- **Lifecycle-script freshness.** Web migrations use the panel's copy
  `/usr/local/bin/amneziawg-install.sh`, written by `amneziawg-web-install.sh`. The installer
  refuses BoringTun operations while that copy lacks backend support (§4.6).

### 11.3 Optional and cosmetic (later)

- Replace "probes kernel support" (`web/mod.rs` l.4026) with datapath-neutral wording.
- Report the backend and the BoringTun release in `system_versions.rs`. Today
  `detect_amneziawg` (l.81) uses `modinfo` and falls back to `awg --version`.
- Expose `AWG_BACKEND` and the imitation keys read-only through the helper's `read-params`
  allowlist.

### 11.4 Not in scope

Changing the backend or imitation from the web panel. If added later, it follows the
`enable-awg3` pattern: a helper subcommand that invokes an installer flag.

---

## 12. Installation and BoringTun binary distribution

### 12.1 Constraints (FACT)

- Targets must not need Rust.
- Upstream publishes no binaries.
- crates.io `boringtun-cli` is Cloudflare's upstream without AmneziaWG support.
- `--version` does not identify the commit.
- The project is BSD-3-Clause, so redistributed binaries must ship the notice.
- The release profile uses LTO with a single codegen unit. A local build took 46 seconds on a
  fast workstation and produced a 1.9 MB dynamically linked binary (VERIFIED). A small VPS
  would take many minutes and need a lot of memory.

### 12.2 Options

| Option | Pros | Cons |
|---|---|---|
| **A. Prebuilt binaries from this repository's CI at a pinned commit** | No toolchain on targets; fast; one audited artefact per architecture; reproducible and attestable | A new release process for a repository that publishes no binaries today (`docs/VERSIONING.md`) |
| **B. Build the pinned commit on the target** | No binary trust needed beyond the source; any architecture | Needs Rust and about 1–2 GB of disk; slow and memory-hungry; network access to crates.io; an extra supply-chain surface (rustup) |
| C. `cargo install --git … --rev <sha> --locked` | Simple | Same drawbacks as B |
| D. Vendor BoringTun as a git submodule | The pin lives in git history | Does not help standalone downloads; still needs A or B |
| E. OCI image as the distribution vehicle | Natural for containers | Not usable by host installs without extraction |
| F. Distribution packages | Native updates | None exist; out of scope |

### 12.3 Recommendation

**Architectural (PROPOSAL):**

1. `amneziawg-install` owns a pin: upstream repository URL, full commit SHA, a release ID and
   one SHA-256 per artefact. The pin is embedded in `amneziawg-install.sh`, because the
   installer is used as a single downloaded file. The integrity of the script then implies
   the integrity of the artefact.
2. **Primary channel (A):** statically linked binaries, built by this repository's CI from
   the pinned commit and published as release assets of this repository. They are verified
   against the embedded SHA-256 before installation.
3. **Secondary channel (B):** opt-in source build of the same commit, from a repository
   checkout only. It reuses `scripts/amneziawg-cargo-build.sh`, verifies `git rev-parse HEAD`
   and uses `--locked`.
4. **Manual channel:** an operator-supplied binary for air-gapped hosts. It is recorded as
   `channel=manual` and accepted only after `--version` and a scratch capability probe pass.
5. Versions are installed side by side and activated atomically, with rollback. Nothing
   upgrades implicitly.

**Implementation details (may change):**

- musl static targets: `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- Built on native `ubuntu-24.04` and `ubuntu-24.04-arm` runners, avoiding cross toolchains
  for `ring`.
- The Rust toolchain pinned by exact version.
- Built inside a digest-pinned container image, with `SOURCE_DATE_EPOCH`,
  `--remap-path-prefix` and stripped symbols.
- A double build that compares hashes, as a reproducibility check.
- `cargo deny check advisories licenses bans` and a generated `THIRD-PARTY-LICENSES`.
- A GitHub build-provenance attestation.
- Release tag `boringtun-0.7.1-ge4e4dc85ec03-b1`. The build counter changes when the
  toolchain or flags change for the same source.
- Assets `boringtun-cli-<release-id>-<arch>-linux-musl.tar.gz` plus `SHA256SUMS`.

**OPEN:** glibc versus musl performance and whether to keep musl. Also which further
architectures to support; armhf, ppc64el, riscv64 and s390x would be source-build only and
untested.

### 12.4 Install-time verification

1. Download over HTTPS only, IPv4-preferred as the installer already does, into a private
   temporary directory on the target filesystem.
2. Check the SHA-256 against the embedded value.
3. Extract with path validation: only the expected file names, no `..`, no links.
4. Require `boringtun-cli --version` to print `boringtun 0.7.1`.
5. Move the files into `<release-id>.tmp`, write `MANIFEST` with the binary's SHA-256 and the
   channel, and rename the directory into place.
6. Switch `current` atomically (a temporary symlink, then `mv -T`) and keep `previous`.

### 12.5 Upgrade and rollback policy (PROPOSAL)

- A pin bump is a reviewed PR. It includes the upstream diff summary and the checksums, and
  must pass the live and interop CI jobs.
- Installing a newer `amneziawg-install.sh` never replaces the running binary on its own.
  `--backend-status` shows the installed release next to the pinned one.
- `--upgrade-boringtun` runs as a transaction under the lock:
  1. Download and verify the new release and install it beside the old one.
  2. Run the capability probe for the current protocol mode and staged validation of the
     current server and client configs, using a scratch instance of the new binary.
  3. Switch `current` and restart the unit.
  4. Verify the unit, the TUN device and the UAPI.
  5. On failure, switch back, restart and report.
- `--rollback-boringtun` switches to `previous` using the same transaction. At most two
  versions are kept.
- Implemented in PR 6 (§21.4), which also adds a build component to the store identity of
  later builds.

### 12.6 Supply-chain considerations

- **Trust roots:** this repository's reviewed pin, GitHub-hosted CI and releases, and TLS.
- **Upstream code:** pinned by full commit SHA, with dependencies locked by `Cargo.lock`
  (`--locked`) and screened by advisory and license checks in CI.
- **Artefacts:** reproducibility check, provenance attestation and embedded checksums. There
  is no `curl | sh` on the default path; rustup is used only for the opt-in source build.
- **Downgrade resistance:** only the embedded hash or an already-installed verified version
  can be activated.
- **Runtime integrity:** the precheck re-hashes the active binary against its manifest on
  every start, which catches corruption or a partial update.

### 12.7 Layout and permissions

See §4.4. Every path is root-owned and not group/other-writable. Helpers and the unit refer to
absolute paths only, with no PATH lookup.

### 12.8 amneziawg-tools acquisition (FACT)

- The PPA's `amneziawg-tools` (commit `ee0f0a9`, AWG 3.1) is published for focal, which the
  installer uses on Debian, and noble, on amd64 and arm64.
- It **recommends** `amneziawg-modules | amneziawg-dkms`, and APT installs recommends by
  default. BoringTun installs must use `apt-get install --no-install-recommends
  amneziawg-tools`. Otherwise DKMS would be pulled in and awg-quick's kernel-first behaviour
  would bypass BoringTun.
- The `amneziawg` package is the DKMS metapackage and must not be installed.
- The tools look for userspace sockets under `/var/run/amneziawg/`, which BoringTun provides
  through its symlink.

---

## 13. Container architecture

### 13.1 Requirements

| Needed | Why | Evidence |
|---|---|---|
| `/dev/net/tun` (`--device /dev/net/tun`) | BoringTun opens it to create the TUN device. | FACT |
| `CAP_NET_ADMIN` in the container's network namespace (`--cap-add NET_ADMIN`) | TUN creation, addresses and MTU, nftables, and fwmark if used. | FACT; datapath VERIFIED in non-initial namespaces |
| Published UDP port (`-p <port>:<port>/udp`) | Client reachability. | — |
| Namespaced sysctls `net.ipv4.ip_forward=1` and, with IPv6, `net.ipv6.conf.all.forwarding=1` (`--sysctl`) | `/proc/sys` is usually read-only in containers, so the installer's `sysctl -p` cannot apply them. | INFERRED |
| Host kernel with TUN and nftables/NAT support, built in or loadable by the host | The container cannot load modules. | INFERRED |
| IPv6 socket family on the host | BoringTun always binds `[::]`. | INFERRED |
| `CAP_NET_BIND_SERVICE` only for ports below 1024 | Included in Docker's default set. | — |

**Not needed:** `amneziawg.ko`, DKMS, kernel headers, a `/lib/modules` mount,
`CAP_SYS_MODULE`, `--privileged` or the host network namespace. BoringTun ran with full
AWG 3.1 support in network namespaces on a host without any AmneziaWG module (VERIFIED). A
Docker run with a minimal capability set is not yet verified; the container PR's test covers
it.

**Rootless.** Creating a TUN device requires `CAP_NET_ADMIN` in the user namespace that owns
the network namespace (INFERRED from the kernel's TUN permission check). A rootless Podman
container may therefore work, but it remains root with `CAP_NET_ADMIN` inside its namespaces.
Rootless operation is **not claimed**.

### 13.2 Process model (PROPOSAL)

- **Entrypoint** under a minimal init such as `tini`:
  1. Validate the mounted state.
  2. Run the same precheck as the unit.
  3. Run `awgBackendQuickUp`, meaning `awg-quick up` with the launcher.
  4. Wait on the BoringTun PID from the PID file.
  5. On SIGTERM, run `awg-quick down` and exit.
- **Crash handling.** If BoringTun dies, the entrypoint exits non-zero and the container's
  restart policy restarts it. The container's network namespace, and its firewall rules,
  disappear with the container, so there is no hook-replay problem.
- **Health check:** `awg show <if> listen-port`.
- **Kernel-first hazard.** If the host has the module loaded or loadable, `awg-quick` inside
  the container would create a kernel link. The entrypoint's precheck detects a loaded module
  through `/sys/module`, and the post-start TUN check catches autoload. Either failure stops
  the container with an explicit message.

### 13.3 Configuration and persistence (PROPOSAL)

- **State volume:** `/etc/amnezia/amneziawg` holds params, the server config and `clients/`.
- **First run:** the entrypoint sources `amneziawg-install.sh` and calls non-interactive
  configuration functions in a "container mode". That mode performs no APT, systemd or
  sysctl writes and generates params, the server config and the runtime file.
- **Management:** `docker exec <c> amneziawg-install.sh --add-client alice`. This needs the
  service-management calls behind functions (§13.5).

### 13.4 The web panel with containers (future)

UAPI sockets are filesystem objects. A web container sharing the `/var/run/wireguard` and
`/var/run/amneziawg` volumes, plus the client directory, could manage a VPN container
without sharing its network namespace. The panel's sudo and helper design is host-oriented,
so this is out of scope.

### 13.5 Decision (PROPOSAL)

The Docker image is a **separate deliverable** after host BoringTun support is stable
(PR 9). The abstraction prepares for it from day one:

- Datapath primitives contain no systemd calls.
- Renderers are pure.
- Binary acquisition is decoupled, so the image uses the same pinned artefact and checksum.
- Precheck and launcher are reusable outside systemd.
- The container PR puts the roughly 15 direct `systemctl … awg-quick@` calls behind
  `awgService*` functions. Examples are at l.3514–3516, 4933, 4936, 6454, 6925, 7006, 7012
  and 7044.

---

## 14. Virtualization and LXC behaviour

| Environment (`systemd-detect-virt`) | kernel backend | boringtun backend |
|---|---|---|
| none / KVM / VMware / Xen / other VMs | allowed (unchanged) | allowed after preflight |
| `lxc`, `lxc-libvirt` | **rejected**, same message as today | allowed only if the preflight passes and systemd is PID 1 |
| `systemd-nspawn` | allowed today (not checked; module loading fails later) | allowed only if the preflight passes |
| `docker`, `podman`, other OCI containers | allowed today (not checked) | host-installer mode refused and pointed to the container deliverable, because there is usually no systemd and the filesystem is ephemeral |
| `openvz` | rejected (unchanged) | rejected: legacy and untested |
| `wsl` | allowed today (not checked) | allowed; test environments only |

**BoringTun preflight (PROPOSAL):**

- `/dev/net/tun` is a character device 10:200 that can be opened read-write.
- A scratch BoringTun interface can be created and its link configured, which proves
  `CAP_NET_ADMIN` and TUN together.
- `/proc/sys/net/ipv6` exists.
- `nft list tables`, or `iptables -L`, works in this network namespace.
- Forwarding sysctls are writable or already enabled.
- systemd is PID 1 for host mode.
- The kernel module is neither loaded nor autoloadable.

On LXC, a failure prints the standard device passthrough hints:
`lxc.cgroup2.devices.allow: c 10:200 rwm` and
`lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file`.

To keep the first PR byte-identical, the kernel LXC message only gains a hint about
`AWG_BACKEND=boringtun` in the virtualization PR (PR 7).

---

## 15. Installation, upgrade and uninstall flows

### 15.1 Fresh kernel install

Unchanged. The only new effect is the extra params keys.

### 15.2 Fresh BoringTun install (PROPOSAL)

1. `initialCheck`: root check, then the backend-aware virtualization check (the backend is
   requested through the environment), then the OS check.
2. Questions. A backend prompt defaults to `kernel` and is shown only when `AWG_BACKEND` is
   unset, followed by an optional imitation question. `AUTO_INSTALL` uses the environment.
3. Refuse if the proxy is installed or the web panel's lifecycle-script copy is stale
   (§4.6, §10.4).
4. APT with IPv4 preference. Ubuntu configures the PPA as today; Debian sets up the keyring
   and source as today, without `deb-src`. Then
   `apt-get install --no-install-recommends amneziawg-tools` and
   `apt-get install nftables iptables qrencode`.
5. Install the pinned BoringTun (§12.4), then write the helpers.
6. Run the preflight (§14), including a scratch AWG 2.0 probe.
7. Write params (`AWG_BACKEND='boringtun'` plus imitation keys), the server config
   (same format) and the runtime file. Configure firewall hooks and sysctls as today.
8. Write the BoringTun drop-in, `daemon-reload` and `enable`, then start and verify.
9. Create the initial client as today.
10. On a failure before step 7, stop with no VPN state written, as when APT fails today. On a
    start failure, leave the unit enabled but stopped, as the kernel path does, and print
    BoringTun hints.

### 15.3 Upgrading the installer script

A new script version never changes the backend, the binary or the protocol. Management
operations only verify and repair missing artefacts. Refreshing outdated helper templates
happens only through an explicit command such as `--upgrade-boringtun` or a future
`--repair-backend`.

### 15.4 Upgrading BoringTun itself

See §12.5.

### 15.5 Tools, OS and kernel upgrades

- **`amneziawg-tools` via APT:** the running daemon is unaffected. The new `awg-quick` takes
  effect at the next start. A CI job renders the drop-in against the packaged unit to catch
  unit changes (§23, risk R12).
- **Kernel upgrades:** nothing to rebuild for BoringTun. The kernel path is unchanged, with
  DKMS repair.

### 15.6 Uninstall (PROPOSAL)

- **Shared steps:** stop and disable the unit, remove the drop-in (and its directory if
  empty), `daemon-reload`, remove the forwarding sysctl file and the AWG directory, and
  remove the PPA as today.
- **Kernel:** today's steps, unchanged.
- **BoringTun:**
  - Remove the runtime file, helpers, binary store, `/run/amneziawg-install` and the
    installer's load-override file.
  - Remove this interface's socket paths only if no daemon serves them.
  - Remove `amneziawg-tools`, but never DKMS packages this backend did not install.
  - Verify that no BoringTun process for the interface remains.

---

## 16. Failure handling and rollback

| Failure | Detection | Behaviour |
|---|---|---|
| Artefact download fails or checksum mismatches | curl status, `sha256sum` | Abort before any VPN state is written; nothing activated. |
| Binary does not run (wrong architecture or libc) | `--version`, scratch probe | Abort before activation; the manual channel is refused. |
| Precheck fails (module present, IPv6 absent, no TUN) | `ExecStartPre` | The unit does not start; the message states the exact remedy. |
| `awg-quick` took the kernel path | Missing PID file, poststart TUN check | Start times out or fails; `poststop` runs `awg-quick down` on the kernel link. |
| Launcher readiness timeout | Launcher | Child killed, own sockets removed, `awg-quick` deletes the link. |
| Daemon crash at runtime | Main PID exit | Supervised restart; `poststop` replays PostDown so firewall rules are not duplicated. |
| Restart loop from a config error | Start limit | The unit gives up after 5 starts in 120 seconds; `--backend-status` explains. |
| Protocol migration fails (probe, validation, apply, restart) | Existing transaction | Unchanged: files restored and previous runtime restarted. For BoringTun, validation ran on scratch BoringTun first. |
| Imitation change fails | Restart or verification | Params and runtime file restored, unit restarted. |
| BoringTun upgrade fails | Verification after the switch | `current` restored, unit restarted. |
| Installer interrupted during a probe | Subshell traps | Scratch daemon, unit, link and sockets cleaned; later sweep under the lock. |
| Uninstall partially fails | Per-step status | Reports `UNINSTALL_FAILED` as today and lists what remains. |
| Descriptor exhaustion | Mitigated by the `ListenPort` filter | A CI regression test asserts stable descriptor counts over 100 add/remove cycles. |

---

## 17. Security considerations

- **Privileges.** BoringTun runs as root: its own privilege drop depends on `getlogin()` and
  fails under systemd (VERIFIED). This is equivalent to the kernel module's trust level but
  is a larger userspace attack surface.
  - Future hardening (**OPEN**): the launcher could start BoringTun as a dedicated user with
    ambient `CAP_NET_ADMIN` (and `CAP_NET_BIND_SERVICE` for low ports) via `setpriv`, with
    pre-created socket directories. That needs its own testing.
  - Sandboxing `awg-quick@` with systemd directives would also constrain the PostUp hooks
    (nftables, firewalld over D-Bus), so it is not proposed initially.
- **Executable ownership and integrity.**
  - The store and helpers are root-owned and not group/other-writable along the whole path.
  - They are referenced by absolute path with no PATH lookup.
  - Real paths are checked to stay inside the store.
  - The SHA-256 is compared against the manifest at every start.
- **Environment injection.** `env -i` plus explicit flags (§7.6). The runtime file is
  validated with strict allowlists. The params `unset` list covers the new keys.
- **UAPI exposure.** The socket accepts full reconfiguration, and `get=1` returns the
  header-protection key (FACT). It must remain root-only, as BoringTun creates it (VERIFIED
  0750). It must not be opened to the web panel's user; the panel keeps going through its
  helper. BoringTun never returns the private key (FACT).
- **Temporary interfaces.**
  - Unique `awgp`/`awgv` names under the lifecycle lock.
  - A precondition that the name is unused, because a bind would hijack a live socket.
  - Tracked PIDs and units only; never `pkill -f`.
  - Traps and a sweep.
- **Stale sockets.** Removed only after `awg show <if>` fails. Deleting a live daemon's socket
  terminates it within about a second (FACT).
- **Process lifecycle.** Supervised with restart limits, and `KillMode=control-group` removes
  leftovers.
- **Crash recovery.** PostDown replay keeps firewall state consistent.
- **Failed service startup.** Fail-closed checks; no silent datapath switch.
- **Rollback during protocol migration.** Unchanged transaction semantics; validation on the
  real backend.
- **Simultaneous management.** All backend mutations take the lifecycle lock: imitation
  changes, upgrades and scratch interfaces. Automatic systemd restarts happen outside the
  lock, but every transaction stops the unit before replacing files.
- **Probe responder.** It sends unauthenticated replies only when imitation is on, bounded
  by an aggregate budget. The STUN reply is a small amplifier bounded only by that budget
  (FACT). Loopback sources are excluded.
- **Package and source integrity.** See §12.6. APT signature verification stays as today.

---

## 18. Testing strategy

### 18.1 Regression (every PR)

- `tests/test-functions.sh`, `tests/test-awg3.sh`, `tests/test-install-mock.sh`,
  `tests/test-ubuntu-ppa.sh`, the proxy tests and `tests/test-ubuntu-resolute-live.sh` must
  pass unchanged.
- Golden tests prove that the kernel drop-in text and the kernel probe and validation
  commands are identical, using the existing command-logging mocks.

### 18.2 Mocked unit tests (new `tests/test-backend.sh`, sourcing the installer)

- **Backend selection and persistence.**
  - `''` normalizes to kernel; `kernel` and `boringtun` are accepted; invalid values fail
    closed.
  - An exported `AWG_BACKEND` is ignored for existing installs.
  - `serializeParams` round-trips the new keys.
- **Invalid combinations.** Kernel with imitation. A domain with `stun` or `none`. Host rules
  table-driven against BoringTun's rules (leading and trailing hyphen, a 64-character label,
  more than 253 characters, underscore, trailing dot). BoringTun with the proxy installed.
  AWG 3.x with the proxy (PR 8).
- **Package selection.** `--no-install-recommends amneziawg-tools` for BoringTun, and no
  headers, DKMS, `amneziawg` or `deb-src` (APT mocks log their arguments).
- **systemd generation.** The BoringTun drop-in matches a golden file; `daemon-reload`,
  `enable` and `start` ordering.
- **Launcher.**
  - Rejects invalid interface names.
  - Rejects a runtime file with the wrong owner or mode, a symlink, or an unknown key.
  - Passes no environment through: a mock `boringtun-cli` records its argv and environment.
  - Readiness timeout and early exit; PID file content.
- **Precheck and poststart.**
  - Module loaded (the `/sys/module` path is overridable for tests) or autoloadable
    (`modprobe` mock).
  - No TUN; no IPv6; checksum mismatch.
  - A non-TUN link.
- **Poststop replay.** Marker semantics. Parser parity with `awg-quick` for case, comments,
  sections, `%i` and order. No replay after a clean stop.
- **Sync filter.** `ListenPort` is omitted only when it equals the live port.
- **Scratch lifecycle.** Call sequence (transient unit versus direct launch), cleanup on error
  and signal, refusal of existing names, sweep.
- **Imitation.** The change transaction and its rollback on restart failure; warnings under
  AWG 3.x; the S-size fidelity advisory.
- **Uninstall.** BoringTun artefacts removed, and DKMS packages untouched.
- **Virtualization matrix** (`systemd-detect-virt` mock).

`tests/test-install-mock.sh` gains a BoringTun `AUTO_INSTALL` phase (mocked apt, curl,
`sha256sum`, `systemctl` and `boringtun-cli`). `tests/test-proxy-scripts.sh` gains the
backend guard.

### 18.3 Live userspace integration (new CI job; GitHub-hosted Ubuntu VMs with systemd)

1. Install the PR-2 artefact, or build the pinned commit. Install PPA `amneziawg-tools` with
   `--no-install-recommends`. Assert that no AmneziaWG module is present.
2. `AWG_BACKEND=boringtun AUTO_INSTALL=y ./amneziawg-install.sh`.
3. Assert: the unit is active with a main PID; the link is a TUN; `awg show` and
   `awg show all dump` work; `awg setconf` and `awg syncconf` work through client add and
   remove via `--add-client` and `--remove-client`.
4. Data transfer from a client in a network namespace (BoringTun client and amneziawg-go
   client): ping and a checksummed TCP transfer.
5. `systemctl restart`, then `systemctl stop` and `start`. Unit restart after kill -9, with
   the nftables rule count unchanged after the crash.
6. Descriptor count stable over 100 add/remove cycles.
7. `--enable-awg3`, `--enable-awg31` and `--disable-awg3`, each followed by a data transfer
   and a check that no scratch leftovers remain.
8. *(PR 5, not PR 4)* `--set-boringtun-imitation dns …`. The probe responder answers a
   non-loopback DNS probe; the wire prefix is DNS-shaped. PR 4 exposes no imitation, so its
   live test runs AWG 2.0, 3.0 and 3.1 with imitation off.
9. Uninstall, then assert that no process, socket, drop-in, helper or store remains.

**Reboot semantics:** an optional nightly job boots a cloud image in QEMU/KVM on the runner,
installs, reboots and asserts that the unit comes back.

### 18.4 Protocol versions

AWG 2.0 (default), 3.0 and 3.1 each get the probe, staged validation and a datapath
transfer. 3.1 runs with RandomTrailers on and with DisableCookies both on and off.

### 18.5 Architectures

x86_64 on `ubuntu-24.04` (and 22.04). aarch64 on `ubuntu-24.04-arm`. Other architectures are
source-build only and untested.

### 18.6 Kernel coexistence (ubuntu-26.04 runner, where the DKMS module builds today)

- With the module loaded, the precheck refuses to start with the documented remedy.
- With the load-override file present, the precheck passes and BoringTun runs. The test
  asserts that `ip link add … type amneziawg` no longer loads the module, for both the
  `blacklist` and the `install … /bin/false` forms, which settles the open choice in §7.11.
- Scratch probes stay on BoringTun even with the module loaded.
- Interop: a BoringTun server run directly in a namespace against a kernel client in
  another namespace, for AWG 2.0, 3.0 and 3.1. The "with imitation" runs, and with them the
  measurement asked for in §9.4, belong to PR 5.

### 18.7 Container (PR 9)

Docker on a runner with no AmneziaWG module (assert `/sys/module/amneziawg` is absent). Run
with `--cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun --sysctl …`, a published UDP
port and `--security-opt no-new-privileges`, with no `/lib/modules` mount. A client in a host
namespace connects and transfers data. Container restart and state persistence are checked.

### 18.8 Upstream harnesses

Run BoringTun's `scripts/awg-go-interop.sh`, `scripts/awg-interop-poc.sh` and
`scripts/awg31-interop.sh` at the pinned commit against the artefact, as a smoke test in
PR 2. Running them changes nothing upstream.

---

## 19. Backward compatibility

| Guarantee | How it is ensured |
|---|---|
| Existing installations behave exactly as before | Missing `AWG_BACKEND` normalizes to kernel; kernel implementations are today's code. Tested by unchanged regression suites and golden tests. |
| No automatic kernel-to-BoringTun migration, and no fallback on DKMS failure | The kernel repair path is unchanged. `ExecStartPre=modprobe` still blocks awg-quick's userspace fallback. BoringTun is only ever installed on request. |
| The environment cannot change an existing installation | New keys are added to the `unset` list; environment values apply to fresh installs only. |
| Kernel `AUTO_INSTALL` unchanged | No new prompts; the interactive backend prompt defaults to kernel. |
| Standalone proxy installations unaffected | Proxy reads only the protocol; the new guard accepts `kernel` or empty. |
| Web panel unaffected on kernel | The helper filter is a same-port no-op. |
| Installer upgrades are inert | No backend, binary or protocol change without an explicit command. |
| Messages and uninstall unchanged for kernel | Kernel branches reuse existing code. |

The only visible change for kernel installations is the new params lines. Proposed
kernel-side behaviour changes, such as enforcing "no AWG 3.x with the proxy", are separate
and flagged (PR 8).

---

## 20. Future backend migration

Not part of the first implementation. The architecture keeps it straightforward.

**Kernel to BoringTun:**

1. **Preconditions under the lock.** No proxy. The web lifecycle script is current. BoringTun
   is installed and verified. The preflight passes. The plan to make the module
   non-loadable (unload plus load override, or package removal) is confirmed.
2. **Stage without downtime.** Render the BoringTun drop-in, runtime file and params with
   `AWG_BACKEND=boringtun` into the transaction directory. Validate using a scratch BoringTun
   instance: capability probe for the current protocol and staged validation of server and
   client configs. This can run while the kernel interface serves traffic, because scratch
   BoringTun never uses `ip link add … type amneziawg`.
3. **Apply (short downtime).**
   1. Stop `awg-quick@`; `awg-quick down` runs PostDown.
   2. `modprobe -r amneziawg`, aborting if the module is in use elsewhere.
   3. Write the load override if the module remains on disk.
   4. Swap the drop-in and params, then `daemon-reload`.
   5. Start and verify.
4. **Roll back on failure.**
   1. Stop the unit and restore the old drop-in and params.
   2. Remove the load override and `daemon-reload`.
   3. `modprobe amneziawg`, start and verify.
5. **Cleanup** is a later, explicit step: remove DKMS, headers and modules-load. Deferring it
   keeps rollback possible.

**What changes:** the service drop-in, the runtime datapath, the params backend key and the
module state. **What does not change:** configs, keys, AWG parameters, ports, firewall hooks
and clients. The migration is client-transparent.

**BoringTun to kernel** runs the reverse. Headers, DKMS and module loading must succeed
before any downtime, validation uses a kernel scratch interface, and the load override is
removed before the kernel scratch interface is created.

This works because backend artefacts are pure renderings of params (§3.1). Any backend's
artefacts can be staged, validated and swapped.

---

## 21. Implementation phases and PR breakdown

| PR | Scope | User-visible | Depends on |
|---|---|---|---|
| **1. Backend seam (kernel only)** | See "Proposed first PR scope" below. | No | — |
| **2. Pinned BoringTun artefacts (CI only)** | A workflow builds the pinned commit for x86_64 and aarch64 (musl) on native runners, checks reproducibility, runs `cargo deny`, generates licenses and publishes `SHA256SUMS` and a provenance attestation. A smoke job runs the upstream interop harnesses and a descriptor-leak regression check against the artefact. The pin is recorded where the installer will read it. | No | — (parallel with 1) |
| **3. BoringTun runtime layer** | `awg-backend-ctl` and launcher, generated from installer functions; the drop-in renderer; scratch interfaces (transient units); `ensureAwgBackendReady`, `awgSyncInterfaceConfig` filter and `awgBackendQuickUp` for BoringTun; probe and validation messages; supervision and crash-safe teardown. Mocked tests, plus a live CI job that provisions a host manually. | No (reachable only through an undocumented test hook) | 1, 2 |
| **4. BoringTun host install and uninstall (experimental)** | `AWG_BACKEND=boringtun` for fresh Debian and Ubuntu installs (VM or bare metal); packages without recommends; binary acquisition and verification; uninstall; proxy and web-lifecycle guards; the web helper `ListenPort` filter; the proxy installer backend guard; the live CI jobs (§18.3–18.6 without their imitation steps); README section marked experimental. No imitation. Implemented as recorded in §21.2. | Yes | 3 |
| **5. Built-in imitation** | Params keys, validation, install-time selection, `--set-boringtun-imitation` transaction, warnings and advisory, `--backend-status`, menu display. The imitation steps of §18.3 (step 8) and §18.6 ("with imitation" interop). Implemented as recorded in §21.3. | Yes | 4 |
| **6. BoringTun binary lifecycle** | `--upgrade-boringtun` and `--rollback-boringtun` transactions. Implemented as recorded in §21.4. | Yes | 4 |
| **7. Virtualization** | Backend-aware `checkVirt` with LXC and nspawn support for BoringTun after preflight; LXC hints; an LXC CI test if feasible (LXD on the runner). | Yes | 4 |
| **8. Web panel and proxy UX, plus kernel-side guard** | Web wording, version display and read-only backend status (helper allowlist); proxy docs; refuse AWG 3.x with the proxy installed (a flagged behaviour change). | Yes | 4 |
| **9. Container deliverable** | Dockerfile and entrypoint, `awgService*` abstraction, container mode, Docker integration test. | Yes | 4, 5 |
| **10. Explicit backend migration** | `--migrate-backend kernel\|boringtun` transaction (§20). | Yes | 4, 6 |

### 21.1 Runtime layer as implemented (PR 3)

PR 3 implements §6 to §8 for BoringTun without making it a backend a user can
select. This section records the implemented contract and every place where it
differs from the proposals above.

**Reachability.** Params validation still accepts only `kernel`, and
`serializeParams` refuses any other value. A fresh install discards an exported
`AWG_BACKEND` and selects the kernel backend, as on `main`, and a persisted
`AWG_BACKEND=boringtun` is rejected as unsupported. The BoringTun branches of
the seam run only after `_awgInternalSelectBoringtunRuntimeForTesting`, an
undocumented function that test code calls after sourcing the installer. The
flag it sets is assigned, never read from the environment, each time the
installer loads. No command-line option, menu entry or params value reaches it,
and PR 4 replaces it with normal backend selection.

**Store.** The runtime consumes the PR 2 archive layout as is:
`/usr/local/lib/amneziawg-install/boringtun/<release>/` holds the unpacked
archive directory `boringtun-cli-<version>-g<commit12>-linux-<arch>-musl`, and
`current` is a relative link to it. Every start verifies:

- every directory from `/` down to the release is root-owned, not a symlink and
  not group- or other-writable, and `current` is a root-owned link to a
  well-formed release name;
- the binary is a root-owned regular file, executable by its owner and not
  writable by anyone else, and its real path stays inside the store;
- `MANIFEST` has exactly the format-1 keys that `scripts/boringtun-artifact.sh`
  writes, once each, for this host's architecture, and its version, commit and
  architecture name the release directory;
- the binary's SHA-256 equals `binary_sha256`.

PR 3 does not compare the release with the pin. The commit may appear only in
`packaging/boringtun/pin.env`, and the store is populated by hand in PR 3's live
test. PR 4, which downloads and installs the artifact, embeds the expected
hashes.

**Helpers.** `awg-boringtun-launch` and `awg-backend-ctl` are generated with
`declare -f` from the installer's own functions, and embed their paths as
read-only settings. They set `PATH`, `LC_ALL=C` and `umask 077` themselves, and
the only value they take from their environment is `INVOCATION_ID`, the start
attempt's identity (below). They are ordinary bash scripts, so the interpreter's
own startup follows normal Bash and systemd semantics; what is scrubbed is the
daemon's environment, which `env -i` reduces to `PATH` and `NO_COLOR`.
Regenerating identical content leaves the files alone. All installer-written
files (helpers, drop-in, runtime file) are replaced atomically and never through
a symlink. Writing the service files always ends with `systemctl
daemon-reload`, also when nothing changed, so a reload that failed once is
retried by the next reconciliation instead of being forgotten.

**Runtime file.** Format 1 has a single key, `FORMAT=1`. The imitation keys of
§4.3 arrive with PR 5 through the same allowlist.

**Drop-in.** Exactly §7.4, written to `awg-quick@<if>.service.d/override.conf`,
the file the kernel drop-in uses. The packaged `awg-quick@.service` in the
Amnezia PPA (`resolute` and `noble`) still has `Type=oneshot`,
`RemainAfterExit=yes` and `ExecStart=/usr/bin/awg-quick up %i`, so the drop-in
contract holds. `precheck` refuses to start if that `ExecStart=` changes or a
local unit file replaces the packaged one.

**Ownership.** Every destructive step acts only on what the runtime can show it
owns. Processes are identified by PID and start time (field 22 of
`/proc/<pid>/stat`), links by ifindex, and socket nodes by device, inode, mode
and change time in nanoseconds (the kernel reuses a freed inode number at
once). A socket node counts as a daemon's only when the daemon provably holds
it (below). Without that evidence a resource is left alone, and a failed `awg`
query is never evidence of anything.

**Attempt identity.** Cleanup authority belongs to one start attempt. For the
service the attempt is systemd's `INVOCATION_ID`: a probe unit
showed it is the same for `ExecStartPre`, `ExecStart` (and so the launcher, which
awg-quick runs), `ExecStartPost`, `ExecStop` and `ExecStopPost` of one
activation, and new for every start, every automatic restart after a crash or
a failed `ExecStartPre`, and every `systemctl restart`. `awgBackendQuickUp`
draws a random token and passes it to every step the same way. Everything an
attempt records is named `/run/amneziawg-install/<if>@<attempt>`, so a hook reads
only the current attempt's state: state that an earlier attempt left behind
(because its `poststop` was killed, or kept it on purpose) can never authorise
the current attempt's cleanup, and it is never deleted by a later attempt
either. A hook without a valid attempt identity refuses to start anything and
touches nothing. `ensureAwgBackendReady` asks systemd for the active unit's
`InvocationID`.

**Attempt state.** `<if>@<attempt>.state` is a root-owned 0600 file, replaced
atomically, parsed against a strict allowlist and never sourced: `ATTEMPT`,
`CONFIG`, `PRE_EXISTING`, `PHASE` (`started`, `prechecked`, `launching`,
`launched`, `launch-failed`), the daemon's `PID` and `PID_START`, `IFINDEX`, the socket nodes
`WG_SOCK` and `AWG_SOCK`, and `DOWN` (`none`, `failed-intact`, `failed`).
Transitions that must hold even when the runtime directory can allocate nothing
new are flags: `precheck` creates `<if>@<attempt>.<flag>-pending` for each, and
the transition only renames it to `<if>@<attempt>.<flag>`:

| Flag | Raised by | Means |
|---|---|---|
| `up` | `poststart` | `awg-quick up` succeeded, so PostUp ran |
| `down` | the guarded down, right before `awg-quick down` | a down of the owned link started; its PostDown may run |
| `done` | after that `awg-quick down` succeeded, or after a PostDown replay finished | the interface's cleanup is complete |
| `replay` | `poststop`, right before the first replayed hook | a PostDown replay started; its hooks may have run |

**precheck.** It opens the attempt (state and flags) before any check can fail;
if it cannot, nothing starts. A link, UAPI socket or `awg` interface of the name
that already exists belongs to someone else: `precheck` records `PRE_EXISTING=1`,
refuses, and the attempt's `poststop` touches none of it. It also refuses when:

- `/sys/module/amneziawg` exists, or `modinfo -n amneziawg` finds the module
  (PR 3 has no load override, §7.11, so any installed module blocks BoringTun);
- `modinfo` or `ss` is missing, so autoloading, or who holds a UAPI socket,
  cannot be established;
- `/dev/net/tun` is not a usable character device, or `/proc/sys/net/ipv6` is
  absent;
- store, helper or runtime-file verification fails;
- the config sets `SaveConfig = true` or an invalid value, read the way
  `awg-quick`'s `read_bool` reads it. The config is the exact file of the
  attempt: `<config dir>/<if>.conf` for the service, the canonical path given to
  `awgBackendQuickUp` otherwise, which `precheck` and `poststart` take as a
  third argument and every later step reads from the state.

**Launcher.** It serves only an attempt in `PHASE=prechecked`, and only while no
link or socket of the name exists. It records its child's PID and start time
before waiting. A UAPI node is recorded only once it is proven to be the
daemon's: the node at `/var/run/wireguard/<if>.sock` must be a UNIX socket
whose inode and device `ss`'s socket diagnostics (`ss -xlHe`, `ino:` and `dev:`)
report for a socket inode that `/proc/<pid>/fd` of the tracked daemon holds, and
the node must not change during the check. BoringTun makes
`/var/run/amneziawg/<if>.sock` a symlink to that socket; a symlink cannot be
tied to a process, so it counts as the daemon's only while it resolves to the
socket node just proven. A node that another process bound at the path, even
one that won the race to it, is never recorded. The nodes are proven again when
the UAPI answers; only then does the launcher write the PID file. On failure it
stops the child through its identity and removes only nodes proven to be that
child's. Only when all of that succeeded, or when it refused before starting
anything, does it record `PHASE=launch-failed`: `awg-quick up` then stops at
its first step, before any PostUp hook, so nothing of the attempt is left and no
PostDown is owed. A proven node it cannot remove, or cannot prove gone, keeps
the earlier phase.

**poststart.** `awg-quick up` returned successfully, so this attempt created the
link (`awg-quick` refuses an existing one) and its PostUp hooks ran. The `up`
flag records that first. If it cannot be raised, or the attempt cannot record
the link awg-quick made (the kernel path), or its state is unusable, `poststop`
could not bring the interface down safely later, so `poststart` does it now
(emergency cleanup, which runs PreDown and PostDown) and fails. Emergency
cleanup never needs the runtime directory to store anything: its private copy
of the config (below) is made whole a second time in `AWG_BT_TMP_DIR` (`/tmp`,
never an inherited `TMPDIR`) when any step in the runtime directory fails, and
it raises the `down` flag only when the `up` flag is raised; a successful
emergency down raises `done`. Then the check shared with
`ensureAwgBackendReady` runs: the recorded TUN link, a live daemon with the
recorded PID and start time that the PID file names and whose `/proc/<pid>/exe`
is the verified binary, a UAPI that answers, and UAPI nodes proven again to be
the recorded ones the daemon holds. When a PostUp hook fails inside
`awg-quick up`, the earlier PostUp hooks stay done and no PostDown runs, exactly
as with `awg-quick` on the kernel module. `poststop` cannot tell that case from
a PostUp whose `up` flag was lost, so it keeps the attempt and names the
PostDown hooks (below).

**Guarded down.** Every `awg-quick down` the runtime runs (`stop`, `poststop`'s
kernel-link cleanup, `poststart`'s emergency cleanup) goes through one path.
Preparing the private config copy can block, so right after it the attempt's
state is read again (still this attempt's, no down started) and the link is
checked again: it must still have the owned ifindex, be of the expected kind
(TUN, kernel, or either) and be listed by `awg`. Only then is the `down` flag
raised and `awg-quick down` run. If the link changed meanwhile, nothing is
touched, the state is kept and the ambiguity is reported. The copy lives in a
fresh 0700 `mktemp -d` directory of root, as a 0600 file named `<if>.conf`, and
is removed by an EXIT trap of the subshell that runs `awg-quick`. Making the
copy is one operation (directory, owner and mode check, write, `chmod`, final
check): if any step fails in the runtime directory, that attempt's own
directory is removed and the whole operation is repeated in `AWG_BT_TMP_DIR`.
The SaveConfig filter checks every write it makes, so an error such as ENOSPC
fails it even when the lines after it, a final `SaveConfig = false` for
example, are left out; a copy that is empty while the config is not is
refused as well.

**stop.** For an attempt with `up` and no `down`, whose link (by ifindex) is
still the owned TUN link, it runs the guarded down and raises `done` on
success, or records `DOWN=failed-intact` (the link survived; awg-quick deletes
the link before the first PostDown hook, so none started) or `DOWN=failed`.
When the instance is already gone, `stop` logs that and succeeds without
`awg-quick down`. As §7.8 and E4 found, systemd runs `ExecStop` only when the
main process exited successfully: after a SIGKILL, or an exit with a failure
status, only `ExecStopPost` runs. The live test checks both cases in the
journal.

**poststop and terminal states.** It runs after every stop, crash and failed
start and reads only the current attempt's state. It removes the state only
because of a positive terminal fact: `PHASE=started`, `PHASE=launch-failed`,
or the `done` flag, which is raised only after an `awg-quick down` or a
PostDown replay that completed. A replay that fails, for example because the
config cannot be read, raises no `done`: the attempt is kept, and since the
replay was recorded as started its hooks are never run again. The absence of an expected flag, `up` in particular, is never one, and
neither is a cleanup step that left an owned resource behind:

| Situation | Action | State |
|---|---|---|
| no state of the current attempt | nothing but the PID file | none |
| `PHASE=started` (precheck refused or failed) | nothing | terminal: removed |
| `PHASE=launch-failed` (the launcher refused, or stopped its child and removed its proven nodes) | nothing more; awg-quick up stopped before any PostUp | terminal: removed |
| no `up` flag otherwise (awg-quick up failed after the launch, or poststart could not record it) | stop the recorded daemon if it runs; PostDown is neither run nor ruled out, and is named | kept |
| `done` flag | nothing more | terminal: removed |
| `replay` flag already raised | name the hooks; never run them again | kept |
| `down` raised, not `done`, `DOWN=failed-intact` and no link of the name | replay PostDown once | terminal after the replay |
| `down` raised, otherwise | name the hooks; never run them again | kept |
| `up`, no down, no link of the name | replay PostDown once | terminal after the replay |
| `up`, no down, the owned kernel link | guarded down | terminal after `done`, kept otherwise |
| `up`, no down, the owned TUN link still there | leave it | kept |
| `up`, no down, another link has the name, or the link was never recorded | leave it; PostDown, which may address the name, is not replayed | kept |
| the recorded daemon does not stop | report | kept |
| the exact recorded node of the dead daemon cannot be removed, or cannot be proven gone (UNKNOWN: its identity cannot be read and its absence cannot be proven) | report incomplete cleanup; the node stays | kept as the proof of ownership; a later `poststop` or uninstall with the same record removes the node and, with `done` raised, finishes without a hook |

A replay raises `replay` before its first hook; if that fails, no hook runs and
the state is kept. Replayed hooks are parsed like `awg-quick`'s `parse_options`
and each runs as `bash -e -o pipefail -c` with `LC_ALL=C`, `%i` substituted and
`INTERFACE` exported; a failing hook is logged and the rest still run.
`awg-quick`'s own shell variables other than `INTERFACE` are not available to
them. Socket nodes are removed only if they are the recorded, proven nodes of a
daemon that is gone; a node that is already gone, was replaced or was never
proven is left alone without error. A kept state is left for diagnosis and for
the operator; the runtime never retries hooks from it on its own.

Every deletion of attempt state or scratch records rests on one of four facts:
(A) nothing owned was ever created, (B) every owned resource was cleaned up,
(C) what remains is proven foreign, (D) the records are superseded by another
durable record.

| Deletion | Where | Justified by |
|---|---|---|
| `<if>@<attempt>.*` with `PHASE=started` | `poststop` | A (awg-quick up never ran); C for a pre-existing link or socket |
| `<if>@<attempt>.*` with `PHASE=launch-failed` | `poststop` | A (refused) or B (child stopped, proven nodes removed); no PostUp ran |
| `<if>@<attempt>.*` with `done` | `poststop` | B (the owned link went with a completed down or replay; daemon stopped and proven nodes removed, or the state is kept) |
| scratch records, full reclaim | `_awgBtScratchReclaim` | B (no live registered client, recorded link gone, unit inactive, daemon stopped, recorded nodes gone); C for anything unrecorded |
| scratch records without owner or guard record | `_awgBtScratchReclaim` | D (the owner and guard records are removed only by a completed reclaim) and B (no live client, the child stopped) |

**PostDown semantics.** The runtime runs each PostDown hook at most once per
attempt: once by `awg-quick down`, or once by the replay when no down reached
PostDown and the replay could be recorded first. It cannot guarantee exactly
once for arbitrary shell commands across every crash boundary: after a partial
`awg-quick down`, after a replay or down is killed part way, or when the
runtime cannot record the replay, the remaining hooks are reported and left to
the operator rather than risked twice.

**SaveConfig.** Every `awg-quick down` the runtime runs uses the private copy of
the current config without its `[Interface]` SaveConfig lines, found the way
`parse_options` finds them. The copy keeps the interface's file name, so
`awg-quick` derives the same interface and runs the same hooks. BoringTun's UAPI
never returns the private key, so a save would otherwise write a keyless
configuration over the real one; a test runs `awg-quick`'s real `cmd_down` and
`save_config` against a keyless `showconf` to show both outcomes. An operator
who runs `awg-quick down` or `awg-quick save` by hand on a BoringTun interface
with `SaveConfig = true` still loses the key; the runtime cannot prevent that.

**Sync filter.** As §6.4. It fails without calling `awg syncconf` when
`awg-quick strip` fails, when `[Interface]` has more than one `ListenPort` or an
invalid one, or when the live port cannot be read. Upstream #65, in the pinned
`71d88784ad29`, makes listen-port rebinding transactional, so an unfiltered
sync no longer leaks sockets there; the live test checks that. The filter
stays: it costs nothing and keeps a sync from rebinding the port at all.

**Staged validation.** Correction to §20 and §8.4, found by the live test: the
kernel module binds `ListenPort` only when a link is brought up, so a kernel
scratch link can take the running server's staged config. BoringTun binds the
port as soon as it is set, even on a link that is down, so the same config
collides with the running server. For BoringTun only, `validateStagedAwgConfigs`
checks `ListenPort` itself and leaves it out of what it applies: at most one
`ListenPort` line, read the way `awg` reads it (comments dropped, whitespace
ignored, any case), with a decimal value from 1 to 65535 and no leading zero.
That is stricter than `awg`, which also takes 0 and service names, and matches
the ports the installer writes. It checks the syntax only, not whether the port
is free. The kernel path is unchanged. The live test also confirmed §8.6:
BoringTun rejects configurations the kernel accepts, for example header
protection with `S3` below 12 bytes, or a `RejectAfterTime` shorter than
`RekeyAfterTime` plus `RekeyTimeout`.

**Scratch interfaces.** Deviation from §8.4: cleanup is done by a guardian
process, not by traps. In a bash subshell, `trap -p` reports the parent's
handlers although they are not active there, so a scratch primitive called from
the protocol code, which runs in subshells, cannot chain traps safely. Each
creation is one attempt with a random 128-bit token and records in
`/run/amneziawg-install/scratch`: `<token>.owner`, written once by the creating
shell (the owner) before anything starts; `<token>.guard`, written only by the
guardian; and, without systemd, `<token>.child`, written by the daemon's own
process. The guardian ignores HUP, INT and TERM, holds no inherited descriptor
and is the only process that starts the instance:

1. It records its own PID and start time (`PHASE=starting`) before it starts
   anything, so no instance exists without a recorded guardian.
2. It starts the daemon only while the owner lives, has not asked it to stop
   and has not reclaimed the attempt. Under systemd that is a transient unit
   named `amneziawg-scratch-<name>-<token>` with `RuntimeMaxSec=900`. The
   guardian forks the `systemd-run` client, which records its own PID and start
   time in `<token>.client`, checks that no reclaim has begun, that its
   attempt's owner record still exists, and that the guardian still lives,
   and only then execs `systemd-run`: no process that can submit the unit is ever unrecorded,
   and the guardian never infers the client from `$!`. The guardian goes on
   only once that record exists, and waits for the client even if the owner
   dies meanwhile, so a unit created late is still torn down; a unit whose
   `systemd-run` answer was lost is recognised by its token. The unit's command
   is BoringTun's behind a gate: it runs only while `<token>.owner` exists and
   `<token>.reclaim` does not, so a unit that systemd creates after a reclaim
   began, or after the records are gone, exits before BoringTun. Without systemd the
   guardian forks a child that writes its own PID and start time to
   `<token>.child`, checks that no reclaim has begun, that its attempt's owner
   record still exists, and that the guardian still lives, and only then execs
   BoringTun under `setpriv --pdeathsig KILL`, with the guardian's ignored
   signals reset. The guardian goes on only once that record exists. A daemon
   therefore never runs without a durable record, whenever the guardian dies;
   the parent-death signal, which has the classic window before `prctl`, is only
   a second line.
3. It records the socket nodes it proves the daemon holds and the TUN link's
   ifindex, then `PHASE=created`.
4. When the owner is gone (exit, signal, SIGKILL or a zombie), has written a
   stop request, or has reclaimed the attempt, it tears the instance down
   through the records and removes them last.

The owner's destroy writes the stop request and waits for the guardian to
finish before it reaps it. A guardian that is gone, or hangs for 30 seconds, is
replaced by a reclaim from the records in the owner. A reclaim first writes
`<token>.reclaim`, before it reads any record; it closes the unit's gate. A
child or client records itself first and reads that mark afterwards, so either
the reclaim sees its record or it sees the mark and starts nothing, even when
a reclaim runs while the guardian is still alive (the owner's reclaim after a
guardian that did not die within 3 seconds of `SIGKILL`). A finished reclaim
removes the owner record first and the mark last, and a token's owner record
is written once and never again, so a registrant that reads the mark and then
the owner record finds one of them telling it to stop: a child that registers
after the reclaim read the records starts nothing, even while its guardian
still lives (waiting for it) and after the mark itself is gone. A
registered `systemd-run` client that is still the same process (PID and start
time) may yet create the unit, so the reclaim waits for it for up to 35 seconds
and, while it lives, keeps every record and stops nothing by name; the client
is never signalled. Then the reclaim takes the daemon
from the guardian's record or the child's own, proves and records socket nodes
of a daemon that still runs, deletes the link only if it has the recorded
ifindex and is a TUN device, stops the unit by its token name and the daemon by
its identity, removes only recorded nodes of a dead daemon, and keeps the
records while anything of the attempt is left. Scratch names are limited to
`[a-zA-Z0-9_-]`, because they become unit names, and a name is refused when its
link, either UAPI socket or an `awg show interfaces` entry exists.

**Stale sweep (§8.4).** Every scratch creation and every
`ensureAwgBackendReady` sweeps `/run/amneziawg-install/scratch`. It reclaims an
attempt only when its owner and its guardian are both proven gone by PID and
start time, which covers an owner killed together with its guardian, a guardian
killed before its owner exited, a direct daemon that outlived both, a unit that
`systemd-run` created after both died, and a teardown interrupted part way. It
never matches resources by name, leaves attempts with unreadable records alone,
and does not rely on the lifecycle lock: callers that hold the lock sweep under
it, and two concurrent sweeps only repeat idempotent steps.

**Signals.** The runtime signals a process only through a check that it is
still the process that started at the recorded time, never PID 1 or itself,
and treats a zombie as gone. Bash reaps an exited background child at once, so
even a child's PID stops naming it when it exits; a child whose start time
cannot be read is not signalled at all. A process's own identity is taken from
`BASHPID` outside any command substitution, which runs in a process of its own.
Bash cannot signal through a pidfd, so a PID reused in the instant between a
check and the `kill` after it remains possible.

**ensureAwgBackendReady.** Mode 1 writes the service files, starts
`awg-quick@<if>` when it is inactive, and then requires the active unit's
current activation (its `InvocationID`) to run the instance it launched (the
check shared with `poststart`), with systemd's `MainPID` equal to the recorded
daemon. A unit that is already active on the kernel module, or on anything
else, fails closed with an error; PR 3 neither restarts nor migrates it.

**awgBackendQuickUp.** It resolves the given config to its canonical path, draws
an attempt token and runs the generated `precheck` for that file, `awg-quick up`
with the launcher, then `poststart`, all with that token. On a failed `precheck`
or `awg-quick up` it runs `poststop`; on a failed `poststart`, `stop` and
`poststop`.

**Tests.** `tests/test-boringtun-runtime.sh` covers the runtime with mocks and a
compiled stand-in daemon: `/proc/<pid>/exe` really is the verified store binary,
and the daemon process itself holds its UAPI socket, as BoringTun does. Mock
hold points and failure points (`mktemp`, `mv`, `rm`, `chmod`, `systemd-run`,
`systemctl stop`, `awg-quick down`) make the races deterministic; a competing
process can hold the UAPI path. With `AWG_QUICK_REFERENCE` the suite also
compares the parsers with `awg-quick`'s and runs `awg-quick`'s real SaveConfig
path. `tests/mutate-boringtun-runtime.sh` breaks one rule at a time and
requires that suite to fail; it is run by hand, not in CI, and it names the
changes it leaves out because they cannot change behaviour. The live test
(`.github/workflows/boringtun-runtime.yml`) builds and packages the pinned binary
with `scripts/boringtun-artifact.sh`, installs `amneziawg-tools` without
recommends, so no kernel module is present, and runs
`tests/test-boringtun-runtime-live.sh` against real systemd and BoringTun.

**Service lifecycle.** Every row belongs to one attempt, the activation's
`INVOCATION_ID`.

| Event | Ownership proof | Destructive action | PostDown | State | Later recovery |
|---|---|---|---|---|---|
| Clean stop | TUN link by ifindex, daemon by PID and start time, nodes by fd and diagnostics | guarded `awg-quick down` | by `awg-quick down`, once | terminal (`done`) | none needed |
| SIGKILL or failing exit of the daemon | as above | none (systemd ends the cgroup; ExecStop does not run) | replayed once (`replay` first) | terminal after the replay | none needed |
| Daemon exits 0, `ip link del` | as above | none (ExecStop finds it gone) | replayed once | terminal after the replay | none needed |
| Stale state of an earlier attempt | none for this attempt | none | none | this attempt's own state only | the earlier state stays for diagnosis |
| precheck refuses a pre-existing link or socket | none (`PRE_EXISTING=1`) | none | none | terminal | none needed |
| precheck fails before recording | none | none | none | none | none needed |
| Kernel path wins after a successful precheck | kernel link by ifindex | guarded `awg-quick down` in `poststop` | by `awg-quick down`, once | terminal (`done`) | none needed |
| Link replaced while the down copy is prepared | recheck fails | none | not replayed while the new link has the name | kept | operator |
| Partial `awg-quick down` (a PostDown hook fails) | owned link at the down | the down, once | partly, by `awg-quick down`; rest named | kept | operator |
| `awg-quick down` fails before deleting the link | owned link at the down | the down, once | replayed once after the cgroup kill | terminal after the replay | none needed |
| `replay` cannot be recorded | owned attempt | none | no hook runs | kept | a later `poststop` of the same attempt may replay once |
| Replay interrupted after some hooks | owned attempt | none | never run again; named | kept | operator |
| Replay fails before its hooks (the config cannot be read) | owned attempt | none | not run; never run again automatically | kept; no `done`; incomplete cleanup reported | operator |
| Replay done, state cannot be removed | owned attempt | none | never run again | kept | none needed |
| Foreign socket at the UAPI path | fd and diagnostics proof fails | none; the node is never recorded | not applicable (the start fails) | terminal (`started` when precheck sees the node, `launch-failed` when it appears later) | the name stays refused until the operator removes the node |
| Launcher fails before readiness | child by PID and start time, nodes by proof | child stopped, its proven nodes removed | none (no PostUp ran) | terminal (`launch-failed`); kept if a node cannot be removed or proven gone | none needed |
| A PostUp hook fails inside `awg-quick up` | owned daemon | awg-quick's own link delete; `poststop` stops the daemon if it still runs | none, as with awg-quick; named as owed | kept (no `up`) | operator |
| `up` cannot be recorded in poststart | owned link at poststart | emergency guarded down (copy in `/tmp` if needed) | by `awg-quick down`, once | terminal (`done`) | none needed |
| Link cannot be recorded, `/tmp` usable | link captured at poststart | emergency guarded down from `/tmp` | once | terminal (`done`) | none needed |
| Runtime directory read-only: neither `up` nor `done` can be recorded | link captured at poststart | emergency guarded down from `/tmp` | by `awg-quick down`, once | kept (no terminal fact recorded) | operator; no hook runs again |
| Runtime-directory copy made but its write or `chmod` fails | link captured at poststart | the whole copy made again in `/tmp`; emergency guarded down | once | terminal (`done`) | none needed |
| Link cannot be recorded, no copy possible anywhere | link captured at poststart | none | owed; named | kept (`up`, no `down`) | operator |
| `up` cannot be recorded, no copy possible, storage restored before `poststop` | link captured at poststart | none | owed; named ("PostUp may have run") | kept (no `up` is not terminal) | operator |
| Exact recorded socket of the dead daemon cannot be unlinked | node identity, daemon gone | `rm` fails | replayed once (`done`) | kept; incomplete cleanup reported | a later `poststop` removes the node and finishes, with no hook |

No row removes a link, socket or unit that the attempt does not own, and no row
runs a PostDown hook twice.

**Scratch failures.**

| Event | Outcome |
|---|---|
| Guardian cannot start or record itself | Nothing was started; the owner reclaims the records and fails. |
| Guardian killed before the direct child registered | The child registers, finds the guardian gone and never becomes BoringTun; the owner or a sweep removes the records. |
| Guardian killed after the child registered, before readiness | The daemon's own record lets the owner (or a sweep) stop it by identity, with or without the parent-death signal. |
| Guardian and owner killed, direct daemon alive | The next sweep stops it by its recorded identity and removes its proven nodes. |
| Owner killed while `systemd-run` is pending | The guardian waits for `systemd-run`, sees the owner gone and stops the late unit. |
| Guardian and owner killed while `systemd-run` is pending | The next sweep waits for the registered client and stops the late unit. |
| A reclaim and a registering child or client race | The reclaim marks, then reads, and removes the owner record before the mark; the registrant records itself, then reads the mark and then the owner record. Either the reclaim sees the registrant and keeps everything, or the registrant finds the mark or a missing owner record and starts nothing, whether or not its guardian lives. |
| Client registered, not yet in `systemd-run`, or blocked inside it | While it lives every sweep marks the attempt as being reclaimed, keeps all records and never signals it; a single inactive answer about the unit is never trusted. |
| Owner and guardian killed while the registered client lives | As above; the unit it submits later starts behind the closed gate and exits before BoringTun; the sweep after the client exits stops the unit by name and removes the records. |
| Unit created, `systemd-run` answer lost, or failure reported but the unit appeared | The client has exited; the reclaim stops the unit by its token name and checks it is inactive. |
| Client exited, unit exists | Stopped by its token name; the records go only once it is inactive. |
| Client exited, no unit | The stop by name finds nothing; the records are removed. |
| Client record names a reused PID | The start time differs, so the client counts as exited; the other process is never signalled or waited for. |
| A unit that systemd creates after the records are gone | Its gate finds no owner record; it exits at once and is collected. |
| `systemd-run` answer lost | The unit is found by its token; the attempt proceeds and is torn down normally. |
| `systemd-run` fails after a concurrent creator took the name | No unit or link but the attempt's own is touched. |
| Owner exits, is signalled, is SIGKILLed or becomes a zombie | The guardian tears the instance down. |
| Destroy interrupted after its stop request | The guardian completes the teardown. |
| Teardown interrupted (guardian killed inside it) | The records remain with `PHASE=teardown`; the next sweep finishes. |
| Foreign socket at the scratch UAPI path | Never recorded; the instance fails and the node is left alone. |
| Foreign link, socket or unit of a scratch-like name | Never touched: nothing refers to it by token. |

**Residual assumptions.**

- Between verification and `exec` only root can change the binary, because
  every path component is root-owned and not writable by anyone else. Bash
  cannot open and execute the verified file descriptor itself.
- A module that appears after `precheck` (for example, installed in between) is
  caught by `poststart`'s TUN check and cleaned up as an owned kernel link, not
  prevented.
- A PID reused between an identity check and the `kill` after it would be
  signalled (no pidfd in bash).
- `awg-quick down` itself deletes the link by name: a replacement in the
  instant between the guarded down's last recheck and awg-quick's own
  `ip link delete` cannot be excluded.
- A socket node removed and recreated within the same nanosecond of change time
  would pass for the recorded one; the symlink of the AmneziaWG path is
  attributed by what it resolves to, not by a descriptor.
- A transient scratch unit whose guardian was killed can run until
  `RuntimeMaxSec` if its owner never destroys it and no later sweep runs.
- A `systemd-run` client that stays blocked keeps its attempt's records, and
  each sweep waits up to 35 seconds for it. A request the client already sent
  can still be processed by systemd after the client died and the records were
  removed; that unit exists briefly, runs only the gate and is collected.
- A kept attempt state stays until an operator removes it or the host reboots
  (`/run` is a tmpfs); the runtime never retries hooks from it on its own. This
  now includes every `awg-quick up` that failed after the launch, because a
  missing `up` flag cannot prove that no PostUp ran.
- Root can race any of these checks deliberately; the runtime defends against
  accidents and ordinary failures, not against root.

---

### 21.2 Host install as implemented (PR 4)

PR 4 makes BoringTun a backend a fresh Debian or Ubuntu install can choose. This
section records what it implements and where it differs from the proposals above.

**Selection and persistence.** `normalizeAwgBackend` accepts `kernel` and
`boringtun`; empty means `kernel`, and every other value fails closed. The
installer keeps a copy of the caller's `AWG_BACKEND` from the moment it loads
(`_AWG_BACKEND_REQUESTED`) and resets the live variable to `kernel`, as before.
Only a fresh install reads that copy (`selectFreshInstallBackend`); existing
installations re-derive the backend from params alone, so an exported value
never switches one, in either direction. `serializeParams` persists
`AWG_BACKEND='boringtun'`. PR 3's internal activation flag and
`_awgInternalSelectBoringtunRuntimeForTesting` are gone: the seam dispatches on
the validated `AWG_BACKEND` only. There is no interactive backend prompt, so the
interactive kernel install asks exactly the questions it asked before; an
operator selects BoringTun with `AWG_BACKEND=boringtun`, interactively or with
`AUTO_INSTALL`.

**Kernel path.** `installAmneziaWG` hands a BoringTun install to
`installBoringtunHost` before its first question. The kernel flow runs the same
commands in the same order; three blocks it shares with BoringTun moved
unchanged into functions (`prepareUbuntuAmneziaPpaForInstall`,
`configureDebianAmneziaAptSource`, `writeAwgServerInstallState`), and the Debian
`deb-src` PPA line is written only when the kernel flow asks for it. The kernel
uninstall removes exactly the packages it removed before.

**Release.** The installer embeds the release tag, base URL, version, source
repository and commit, and per architecture the asset name, archive SHA-256 and
binary SHA-256 (`AWG_BT_RELEASE_*`) of an already published release.
`tests/test-boringtun-host.sh` checks that they are internally consistent, and a
CI job (`tests/test-boringtun-public-release.sh`) downloads the real assets
anonymously and checks them against these constants alone. They are not tied to
`packaging/boringtun/pin.env` or `release.env`, which may already prepare or
publish a newer release that the installer adopts only in a later change (see
"Three contracts" in [BORINGTUN_ARTIFACTS.md](BORINGTUN_ARTIFACTS.md)). The
transaction, in order:

1. `uname -m` maps to x86_64 (`x86_64`, `amd64`) or aarch64 (`aarch64`,
   `arm64`); anything else is refused before any change.
2. `curl --proto =https --proto-redir =https` fetches
   `<base URL>/<asset>` into a private directory, inside the installer's APT
   IPv4 window.
3. The archive's SHA-256 must equal the embedded value before anything else
   reads it.
4. `tar -tzf` must list exactly the release directory and its four files, in
   packaging order, and `tar -tv` must show a directory and four regular files.
   An exact list rules out absolute paths, `..`, other top-level names,
   duplicates and extra members; the type column rules out links, devices and
   FIFOs.
5. The archive is extracted with `--no-same-owner --no-same-permissions`.
6. `MANIFEST` is read as data: exactly the format-1 keys, and format, name,
   version, source repository and commit, target, architecture, OS, libc,
   linkage, binary name and `binary_sha256` must match the embedded contract.
7. The binary's SHA-256 must equal the embedded value. Nothing runs in the
   download directory, which may be on a `noexec` `/tmp`.
8. The files are copied into a root-owned `<store>/.<release>.tmp.XXXXXX`, which
   is verified as a candidate and renamed to `<store>/<release>`.
9. The runtime's own release checks (`_awgBtVerifyRelease`, the part of
   `_awgBtVerifyStore` after reading `current`) must pass for that release, and
   only then is `current` pointed at it, by renaming a new relative link over
   it. Verify, then commit: every failure leaves `current` as it was, or absent;
   there is no switch followed by a rollback.

A release directory in the store, the staged one or one an interrupted install
left under its final name, goes through one verification boundary,
`_awgBtVerifyCandidate`, before anything in it runs: every directory from the
trust anchor down and the release directory are root-owned and not writable by
others; it holds exactly the four files, each a root-owned regular file with a
single link that only root can write (the binary executable), so no symlink or
hard link stands in for a member; the embedded contract (`MANIFEST` read as
data, the binary's SHA-256) holds; and the binary is still the same trusted node
(device, inode, mode and nanosecond ctime) that was hashed. Only then does
`--version` run, and it must print `boringtun 0.7.1`. Between that last check
and the exec only root could replace the binary. An exec through the hashed
file descriptor (`/proc/self/fd`) was considered and not used: with no path
component writable by anyone but root it would close no window a non-root user
can reach.

The published archive already has the store layout and the runtime's `MANIFEST`
format, so nothing is converted: the store holds the release's own `MANIFEST`,
`LICENSE` and `THIRD-PARTY-LICENSES`. There is no `previous` link and no
channel field: upgrade, rollback and other channels are PR 6. A store whose
`current` already selects the verified embedded release is reused without a
download; one that selects anything else is refused, never replaced. The
provenance attestation is not checked on the host; the release notes give
operators the exact `gh attestation verify` command.

**Packages.** Ubuntu runs the same PPA preparation as the kernel flow, then
`apt-get install -y --no-install-recommends amneziawg-tools` and
`apt-get install -y iptables nftables qrencode`. Debian adds the PPA source and
signing key as the kernel flow does but without any `deb-src` entry, installs
`curl` if missing, then the same two installs. No headers, DKMS, `amneziawg` or
`amneziawg-dkms`.

**Order of a fresh install** (`installBoringtunHost`):

1. Host checks before any question or change: Debian or Ubuntu, a release for
   the architecture, systemd, no standalone proxy, a current web lifecycle
   script, `/dev/net/tun` and IPv6, and the kernel-module decision.
2. The usual questions (`installQuestions`).
3. Packages, then the release, inside the APT IPv4 window.
4. The load override, when the operator accepted it.
5. The helpers.
6. The preflight: module, platform, store, helpers and base-unit checks, then
   a scratch instance (the runtime layer's own) that must be a TUN device,
   answer its UAPI and accept `awg setconf` of the chosen AWG 2.0 parameters,
   and whose teardown must leave no link, socket or record.
7. Params, server config, firewall hooks and sysctls
   (`writeAwgServerInstallState`).
8. The runtime file (`FORMAT=1`, no imitation) and the drop-in, then
   `daemon-reload`.
9. `enable`, `start`, and `_awgBtCheckServedByBoringtun`: a unit that is active
   but not served by the verified daemon is stopped again.
10. The initial client.

A failure before step 7 leaves no VPN state. A start failure leaves the unit
enabled but stopped, as the kernel install does, with BoringTun diagnostics and
no kernel fallback.

**Kernel module.** The coexistence test (`tests/test-boringtun-kernel-coexistence.sh`
on the Ubuntu 26.04 runner, where the DKMS module builds) settled §7.11. Without
an override, `ip link add … type amneziawg` autoloads the module. On that runner,
a `blacklist amneziawg` line stopped the autoload (`ip link add` failed, the module
stayed unloaded) but not an explicit `modprobe amneziawg`, which loaded it.
`install amneziawg /bin/false` stopped both. The test requires the install form
to block both, and PR 4 lands only that form, because it also stops an explicit
`modprobe`, for example from a leftover kernel drop-in or `modules-load.d`
entry. The installer's file is `/etc/modprobe.d/amneziawg-install-boringtun.conf`.
The runtime precheck accepts an installed module only while that file is in
force (`_awgBtKernelModuleBlocked`): the exact rendered content, a trusted
root-owned file, and a `modprobe -n -v` dry run for both `amneziawg` and
`rtnl-link-amneziawg` that ends in the install command
(`_awgBtModprobeActionBlocked`). The dry run first lists an `insmod` for each
dependency that is not loaded yet (on that runner `udp_tunnel`, `ip6_udp_tunnel`
and `libcurve25519`), each line with a trailing space, so its output is parsed
as data and never evaluated: the dry run must succeed, the last non-blank action
must be exactly `install /bin/false`, and every earlier one must `insmod` a
dependency by absolute path that is not the AmneziaWG module itself. Anything
else, including an empty output, another install command or an action after
`install /bin/false`, counts as no override, so another modprobe configuration
that outranks the file counts as none. A loaded module is always refused and
never unloaded. An installed module is blocked only with consent: an
interactive prompt that defaults to no, or `AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y`
with `AUTO_INSTALL`. Uninstall removes the file only if its content is still the
installer's.

**Guards.** The installer refuses BoringTun while any of
`/etc/systemd/system/amneziawg-proxy.service`, `/usr/local/bin/amneziawg-proxy`
or `/etc/amneziawg-proxy/proxy.toml` exists; the proxy's uninstaller keeps
`proxy.toml` unless `--purge-config` is given, and a leftover one counts. The
proxy installer reads params as data, never sourcing them
(`parse_params_file`): every line that is not blank or a comment must be an
assignment in a form the installer writes, `KEY='value'` (a single quote in the
value as `'"'"'`) or, from installers before 7c2e7dd, `KEY=value` with a plain
value; a duplicate key or any other line (spaces around `=`, command words,
substitutions, several statements, a malformed quote) fails. It refuses any
backend but empty or `kernel`, and an exported `AWG_BACKEND` never stands in
for a missing one. Only a params file that does not exist lets its legacy
`.conf` discovery stand in; one that exists but fails its checks (a symlink,
another owner, a mode other than 600 or 400, an unreadable file, a line the
parser refuses) leaves the backend unknown, and the proxy installer refuses.
Web
lifecycle freshness (§4.6) is an exact line,
`AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST="boringtun-host-v1"`, that the web
panel's copy of the installer (its configured `AWG_INSTALL_SCRIPT`, by default
`/usr/local/bin/amneziawg-install.sh`) must contain; the copy is read as data
and never overwritten. Later installer versions keep the line.

**Deliberate restarts.** The PR 3 drop-in limits starts to five in 120 seconds
(`StartLimitBurst`, `StartLimitIntervalSec`) so that a crashing daemon cannot
restart forever. The live test showed that the limit also counts restarts that
management operations make on purpose: after a restart, a stop and start, a
recovered crash and an AWG 3.0 migration, the AWG 3.1 migration's restart hit
`start-limit-hit`, and so did its rollback. Management operations therefore call
`awgBackendPrepareServiceStart` before they start or restart the unit
(`ensureAwgQuickRunning` and the protocol transaction's restart and rollback). For
BoringTun it runs `systemctl reset-failed awg-quick@<if>.service`, which resets
the unit's start counter; automatic `Restart=on-failure` restarts stay limited.
For the kernel it does nothing, so the kernel path runs exactly the commands it
ran before.

**Web helper.** `reconcile_interface` in the privileged helper leaves out the
`[Interface]` `ListenPort` line only when there is exactly one, it is a valid
port and it equals `awg show <if> listen-port`; otherwise the stripped config is
synced unchanged. The pinned BoringTun includes upstream #65, so this is
consistency and defense in depth, not a leak fix, and a same-port set is a no-op
for the kernel module.

**Uninstall.** The BoringTun uninstall is a transaction whose commit is the
removal of the configuration:

1. The backend comes from params.
2. `stop` and `disable` run the crash-safe teardown; a failed `disable` stops
   the uninstall before anything is removed (a failed `stop` shows as a daemon
   that still runs, or as a unit not proven inactive at the end).
3. No BoringTun daemon of the interface may still run.
4. The teardown must be terminal (`boringtunTeardownFinished`): every start
   attempt the runtime directory still records is loaded with the runtime's own
   parser (`_awgBtStateLoad`) and must carry one of the terminal facts on which
   poststop removes an attempt (`_awgBtAttemptTerminal`: it never got past the
   precheck or the launcher, or its `done` flag is raised). poststop keeps an
   attempt exactly when its cleanup is unfinished, for example a PostDown replay
   that may have run in part; such an attempt, or one whose state cannot be
   read, stops the uninstall before anything is removed, names the PostDown
   hooks to check and keeps every record, so that the operator can finish the
   cleanup by hand and rerun the uninstall.
5. The drop-in and the sysctl file go as before, then `daemon-reload`; a
   drop-in or sysctl file that stays, or a failed `daemon-reload`, fails the
   uninstall with the configuration kept. The kernel install's
   `/etc/modules-load.d/amneziawg.conf` is never a BoringTun file and is left
   alone.
6. `uninstallBoringtunRuntime` removes only what is provably this
   installation's. A UAPI node goes only when a terminal attempt recorded it
   (device, inode, mode and ctime), the daemon that created it is gone, and the
   socket diagnostics prove it idle (for the AmneziaWG path, a symlink, the
   socket it resolves to, which must be in one of the UAPI directories).
   `_awgBtSocketListenedOn` has three outcomes, and only ABSENT allows a
   removal: LIVE when a valid `ss -xlHe` row names the node's path or its inode
   and device; ABSENT when `ss` succeeded, every row it printed is valid and
   none names the node; UNKNOWN otherwise: `ss` missing or failing, or any row,
   related to the node or not, that is not exactly the shape iproute2 5.9 to
   6.19 print for these flags on the supported releases,
   `<u_str|u_dgr|u_seq> <LISTEN|UNCONN> <recv-q> <send-q> <local> <inode> * <port> <->[ ino:<n> dev:<major>/<minor>][ peers:[ <inode>]...]`,
   with `<local>` an absolute path that comes with `ino` and `dev`, or an
   `@abstract` name or `*` without them. Rows are matched as data and anchored
   on their tail, since a path may hold spaces. A node that stays (live,
   unknown, or not removable) is reported and fails the uninstall, and the
   attempt that recorded it keeps its record: the record is the proof of
   ownership that the next uninstall needs, and it goes only after every node
   it proves is gone. What is at a recorded path is ABSENT (proven by a
   successful listing of its directory, `_awgBtPathAbsent`, since `[[ -e ]]` is
   false on any error too), DIFFERENT (its identity was read and differs: a
   replacement, left alone, and the record's obligation is resolved), MATCH
   (read and equal: the node goes only on proof that it is idle) or UNKNOWN (its
   identity cannot be read): an UNKNOWN node stays, and so does the record; a
   failed identity query is never taken for a different node. An unrecorded
   node is kept and fails the uninstall. A
   generated helper goes only when it is byte for byte what
   this installer generates; a helper that differs (edited, someone else's, or
   written by another installer version) is left in place and reported, which is
   not a failure, but a generated helper that cannot be removed is. Then the
   store and the load override (only if unchanged).
7. Packages: `amneziawg-tools` only; kernel module packages found on a
   BoringTun host were installed by someone else. They are removed by
   `removeBoringtunAptPackages`, which reads the whole package database once
   (`dpkg-query -W -f='${Package}\t${db:Status-Abbrev}\n'`, the same format on
   dpkg 1.20 to 1.23): the read must succeed, every row must be a package name
   and a status abbreviation, and dpkg itself must be listed as installed,
   since dpkg-query reads a missing database as an empty one without an error.
   Only then does a package that is not listed as installed count as absent. A
   failed or malformed read, or a failed removal, fails the uninstall. The
   kernel uninstall keeps its own package removal.
8. The Amnezia repository entries: the PPA entries, and managed source and
   keyring files, each of which must be gone afterwards. The APT index refresh
   after them is not mandatory.
9. Only when every step succeeded and the unit is positively not running is
   `/etc/amnezia/amneziawg` removed. `boringtunServiceInactive` needs a
   successful `systemctl show -p ActiveState --value` whose answer is
   `inactive` or `failed`; systemd answers that also once the unit file is
   gone. A failed query or any other answer fails the uninstall. `systemctl
   is-active` is not used for this: its exit status for an inactive unit
   differs between systemd versions (3 on systemd 252, 4 on 255 for a removed
   unit), and a failed query exits 1. Until the commit, params stay, so the
   next run of the installer is a management run that offers the uninstall
   again.

What is preserved on purpose, and reported, without failing the uninstall: a
helper that is not byte for byte this installer's, a load override that was
changed, other files in the drop-in directory, and state of other instances in
the runtime directory. The kernel uninstall keeps its order and its commands.

**Tests.** `tests/test-boringtun-host.sh` (unit: contract consistency, the
transaction against a fixture archive and hostile variants, guards, packages,
preflight, install order and failure injection, uninstall);
`tests/test-boringtun-install-mock.sh` (the five-distro Docker matrix: a mocked
fresh install and uninstall with real files and APT sources);
`tests/test-boringtun-host-live.sh` (x86_64 and native aarch64 runners, and a
Debian 12 systemd container: the real installer and public release, datapath
under AWG 2.0, 3.0, 3.1 and 2.0 again, client management, restart, stop and
start, SIGKILL recovery, descriptor stability, uninstall and a leftover audit);
`tests/test-boringtun-kernel-coexistence.sh` (above); and a job that downloads
the public release anonymously. The live test runs under a scan of its own
output: it installs without an initial client, adds its test client with the
output kept private, and fails if any recorded private or preshared key, any
config or any QR code row appears in what it printed. Its firewall check
(`tests/helpers/boringtun-live-firewall.sh`, unit-tested with mocked queries by
`tests/test-boringtun-live-firewall.sh`) compares the interface's own rules
(its nft table, or the iptables rules that name it) after restart, stop and
start, and SIGKILL recovery, and a failed query is never a result: the
baseline needs a successful query that finds the rules, and a stopped unit
needs a successful `nft list tables` (or `iptables-save`) that proves them
absent.
`tests/test-boringtun-host-root-safety.sh` runs the unit suite as root in a
container with sentinel files at the real paths and requires that nothing
outside its test root changes; outside a disposable host the suite refuses
root. The mutation runners (`tests/mutate-boringtun-host.sh`,
`tests/mutate-boringtun-runtime.sh`) share `tests/helpers/mutation-engine.sh`,
which counts a mutant as caught only after a passing baseline, a mutated file
that still parses (a syntax error is INVALID, never caught), the suite's own
final summary in the format the runner declares for it, counting a failed
assertion, and at least one assertion-failure line; text that merely contains
"failed" counts for nothing (`tests/test-mutation-engine.sh`).
`tests/equivalence/run-kernel-equivalence.sh <base>` compares the kernel path
with a base revision.

### 21.3 Built-in imitation as implemented (PR 5)

PR 5 lets a BoringTun installation choose, change and inspect BoringTun's own
protocol imitation. It adds no BoringTun source change, binary or pin change.
The release stays `boringtun-cli-0.7.1-g71d88784ad29-b1`. This section records
what it implements and where it differs from §9.

**Persisted model.** A BoringTun installation's params carry
`AWG_BORINGTUN_IMITATE_PROTOCOL` (`none`, `dns`, `quic`, `sip` or `stun`) and
`AWG_BORINGTUN_IMITATE_DOMAIN` (empty, or a hostname for `dns`, `quic` or
`sip`). `serializeParams` writes them only for BoringTun, so kernel params keep
exactly their earlier keys. The environment boundary is the backend's:
- `validateParamsFile` unsets both names before sourcing params.
- A key that is absent means `none`, which is what PR 4 params mean.
- A present key must be valid.
- Kernel params that carry anything other than `none` and no hostname are
  damaged.
- Only a fresh install reads the caller's values, from copies taken when the
  installer loads (`selectFreshInstallImitation`).
- A kernel install that asks for an imitation fails before any change.

The hostname rule is the binary's strict LDH rule (`is_valid_imitation_host`),
applied by the installer to all three protocols. That is narrower than the
binary for QUIC, which accepts any printable SNI. The characters are spelled out,
so no locale widens the rule.

**Runtime file and command line.** `<if>.boringtun` stays `FORMAT=1`. It gains
two optional allowlisted keys, `IMITATE_PROTOCOL` and `IMITATE_DOMAIN`, rendered
only when the imitation is not `none`. A file without them, such as PR 4's, means
`none`, and `none` renders PR 4's file byte for byte. The launcher's parser
refuses:
- `IMITATE_PROTOCOL=none`;
- an unknown protocol;
- a repeated key;
- a hostname without a protocol, an empty one, one with `stun`, or an invalid
  one.

`_awgBtDaemonArgv` always names the protocol and appends the interface last:
`… --verbosity error --imitate-protocol <p> [--imitate-domain <d>] <if>`.
`--probe-reply-rate` is never passed, so the binary's default applies (16 KiB/s
with a protocol, off with `none`). The daemon still gets an `env -i`
environment of `PATH` and `NO_COLOR`, so no `WG_*` variable reaches it. Scratch
instances run the persisted imitation, so staged validation (§8.4) checks what
the service will run, including the SIP refusal.

**Fresh install.**
- `AUTO_INSTALL` takes the environment's values, or `none`, and never asks.
- An interactive BoringTun install asks "Protocol imitation: 1) none (default)
  2) dns 3) quic 4) sip 5) stun", and for `dns`, `quic` and `sip` an optional
  hostname.
- The kernel install asks nothing new.
- The warnings below are printed before the final confirmation.

**Warnings (§9.4).** `printBoringtunImitationWarnings` covers:
- that shaping is server-side only, and client configs do not change;
- the probe replies of the chosen protocol, the budget and the refused sources;
- that the port never changes;
- under AWG 3.x, the header-protection nonce each protocol leaves;
- an advisory, never a refusal, for S1–S4 below the pinned fillers' sizes:
  `dns` 32 (or the hostname's length + 33), `stun` 20, `sip` 31, `quic` 1.

`checkBoringtunImitationProtocolCompat` refuses `sip` under AWG 3.0 or 3.1 while
any S size is 31 or more. It applies both when `sip` is chosen and when
`--enable-awg3` or `--enable-awg31` runs under `sip`. It runs before anything
changes. With the installer's S range of 15–150, that is almost every
installation. A protocol change keeps the imitation and prints the AWG 3.x
warning first. From the menu, enabling an imitation under AWG 3.x asks
`[y/N]`.

**`--set-boringtun-imitation <protocol> [hostname]`** is a transaction in a
subshell:
1. It validates the arguments, takes the lifecycle lock and reloads params
   (`loadParams 0 1`).
2. It requires BoringTun. Identical values are a no-op.
3. It applies the SIP check, then reads `ActiveState`:
   - `active`: apply and restart;
   - `inactive` or `failed`: persist without starting;
   - anything else: abort before any change.
4. It regenerates the helpers (`_awgBtEnsureReady 0`) while the runtime file is
   still the old one, so a PR 4 launcher never meets the new keys. For an active
   unit it proves the running instance (`_awgBtCheckServedByBoringtun`).
5. In a private `.awg-imitation.*` directory it backs up params and the runtime
   file byte for byte, and records their modes (params may be 0400).
6. It renders both new files there and checks them:
   - `serializeParams` must report success; it fails on any write failure,
     including one part-way through or in the imitation append, and still
     restores the umask;
   - the runtime file through the launcher's own parser;
   - params as a complete canonical file: exactly the keys `serializeParams`
     writes for BoringTun (`AWG_PARAMS_KEYS` and `AWG_PARAMS_BORINGTUN_KEYS`,
     which a test keeps equal to its output), each once and in order;
   - params read back in isolation (`readStagedParamsInIsolation`): every
     canonical variable is unset first, so nothing in the installer's shell
     can fill in a missing line, and every key must be set. Then
     `validateParamsFile`, which validates the backend, the imitation and the
     AWG protocol state, must accept the file as the params of a private
     directory;
   - the state read back must be the current state with only the imitation
     changed: a digest of every other key's value is compared, never printed;
   - the server config on a scratch instance that runs the new imitation.

   Every check runs before anything is applied, so a failed one changes no live
   file and needs no rollback.
7. It replaces the runtime file, then params, atomically, keeping their modes.
8. For an active unit it runs `awgBackendPrepareServiceStart`, restarts, and
   verifies:
   - the unit is active;
   - MainPID is the recorded, verified daemon;
   - the TUN link and UAPI answer;
   - the listen port is the persisted one;
   - no amneziawg module is loaded;
   - the daemon's command line carries the new imitation.
9. Any failure, or HUP, INT or TERM once files change, restores both files
   exactly. If the unit was active, it is restarted on the previous imitation
   and verified. If the files cannot be restored, the unit is not restarted.
   Every failing step is reported, and on an incomplete rollback the recovery
   files are kept.

Client configs never change.

**`--backend-status`** prints `key=value` lines and changes nothing: params
whose mode is not 600 or 400 are refused, never repaired. Keys:
- every backend: `backend=`, `awg_protocol=`, `service_state=`;
- BoringTun: `imitation_protocol=`, `imitation_domain=`,
  `imitation_domain_mode=configured|random|none`, `installed_release=`,
  `pinned_release=`, `daemon_state=running|stopped|unverified`, `daemon_pid=`;
- BoringTun, beyond §9: `daemon_imitation_protocol=` and
  `daemon_imitation_domain=`, read from the running daemon's command line. A PR 4
  daemon, started without the flag, reads as `none`.
- kernel: `module_state=loaded|not-loaded`.

It prints no key. It exits 0 for a valid installation, and 1 for params that
cannot be used or a BoringTun store that does not verify
(`installed_release=invalid`).

**Menu.** A BoringTun host's menu shows a line with the backend and the
imitation, and has 8 options: the kernel menu's options with their numbers
(6 still uninstalls), **7) Change BoringTun protocol imitation**, and 8) Exit.
The kernel menu keeps its 7 options unchanged.

**Tests.**
- `tests/test-boringtun-imitation.sh` covers validators, the params boundary,
  fresh-install selection, the runtime file and command line, warnings and
  advisory, the SIP refusal, the transaction's states, failure injection,
  rollback and signal paths, the PR 4 → PR 5 upgrade order, `--backend-status`,
  and the menus. It also runs a real partial write: the kernel stops the params
  write after 25 lines (RLIMIT_FSIZE through `prlimit`). The test checks that
  this makes `serializeParams` and the transaction fail before anything is
  applied, and checks the isolated read-back of staged files that lack a key
  the shell still has. `tests/mutate-boringtun-imitation.sh` has 48 mutants,
  each caught by a named assertion.
- `tests/test-boringtun-runtime.sh` covers the launcher's refusals of bad
  runtime files, and the exact command lines of launcher and scratch instances
  with and without imitation.
- The install-mock matrix covers a kernel `AUTO_INSTALL` with an imitation,
  refused before any change. On the installed host it runs the real
  transaction, active and inactive, plus `--backend-status` and a fresh
  `AUTO_INSTALL` with `sip`.
- The live test (§18.3) cycles `dns` → `quic` → `sip` → `stun` → `none`. It
  records the prefixes of the server's datagrams on the client's side, where
  `dns`, `quic` and `stun` must shape every one and `sip` must carry request
  lines. It sends DNS, STUN, QUIC (reserved and v1) and SIP probes from the
  client's network and from loopback. It also adds and removes a client under
  imitation and moves to AWG 3.0 and back. The x86_64 job installs with the last
  installer before imitation (`9f5a1af`) and manages the host with this one.
- The coexistence job (§18.6) measures an AmneziaWG kernel client's echo loss
  under AWG 3.0 with `none`, `dns`, `quic` and `stun`.
- amneziawg-go is not measured: it would need a pinned, verified third-party
  build in CI. It is left for later.

### 21.4 Binary lifecycle as implemented (PR 6)

PR 6 lets an installed BoringTun host move its binary to the release this installer pins,
and back. It publishes nothing, changes neither the pin nor any hash, and the release stays
`boringtun-cli-0.7.1-g71d88784ad29-b1`. The kernel path is unchanged.

**Release identity and builds.** Published asset names, and with them each archive's
top-level directory, carry no build number. PR 4 named the store directory after that archive
directory, `boringtun-cli-<version>-g<commit12>-linux-<arch>-musl`. So a rebuild of the same
source commit (`-b2`, with a different toolchain or flags and different bytes) would have
collided with build 1. MANIFEST format 1 has no build field either.

PR 6 makes the store identity the installer's (`_awgBtReleaseStoreId`):
- Build 1 keeps exactly the PR 4 name.
- Every later build adds `-b<build>`:
  `boringtun-cli-<version>-g<commit12>-b<build>-linux-<arch>-musl`.
- `-b1` is never written, and `-b0` and leading zeros are invalid (`_awgBtReleaseIdValid`).

Consequences:
- **Existing hosts are untouched:** every PR 4/PR 5 store already names the current pin
  correctly, and no store is renamed or migrated.
- **Builds coexist:** builds 1 and 2 of one commit sit side by side.
- **The archive is unchanged:** a build ≥ 2 is unpacked from its archive directory and stored
  under its build name.

The installer embeds `AWG_BT_RELEASE_BUILD` (the embedded release's build number, its
tag's `-b<build>`). The runtime checks (`_awgBtVerifyRelease`, in the helpers) bind a
directory's version, commit and architecture to its MANIFEST. Format 1 cannot bind the build,
which is stated rather than pretended: the build in a name is the one the installer gave
when it stored a release whose binary had the embedded SHA-256. The store is root's alone,
and a rollback only ever follows `previous`, which only the installer writes.

**Store.** At most two *managed* releases: `current` and `previous`, each a root-owned
relative link to a release directory. A PR 4/PR 5 store has only `current`, which is valid.
The store can hold more release directories than that: one a prune could not remove, one an
interrupted transaction left, or one put there by hand. Those are unmanaged.
- Links are written atomically: a new link renamed over the old (`_awgBtSetStoreLink`).
- A link is read only if it is a root-owned symlink whose target is a single valid release
  name (`_awgBtReadStoreLink`).
- Other release directories are *unmanaged*. They are reported by both commands and counted
  by the status, but never used or removed automatically.

**Commands.** `--upgrade-boringtun` and `--rollback-boringtun` take no argument; an extra one
is a usage error.
- **Upgrade:** moves `current` to the release this installer pins, and only that one. There is
  no "latest", channel or API lookup.
  - When `current` already is the pin, the links are consistent and the helpers already are
    this installer's, it is a true no-op: no download, no link rewrite, no helper rewrite, no
    restart.
  - When `current` already is the pin but the installed helpers are stale (for example those
    of an earlier installer version, which refuse a `-b<build>` pin), only the helpers are
    rewritten and the command says so. There is no download and no link rewrite. An
    `inactive` or `failed` service stays stopped, and a healthy active one is not restarted.
  - If `previous` also names `current` (a switch interrupted between its two renames), it
    removes only that duplicate `previous` link and reports it. Every release directory stays
    as it is. The release that used to be `previous` cannot be known: it stays unmanaged and
    is never guessed or adopted as rollback history.
  - If removing that link fails, the command fails instead of reporting a healthy no-op.
  - An active service that runs another binary (an interrupted switch) is restarted onto
    `current` and verified, never reported as a clean no-op.
- **Rollback:** moves `current` to the release `previous` names, and to no other. It fails
  without changing anything when `previous` is absent or names `current`.
- **No implicit switch:** nothing else changes `current`. Client management, protocol changes,
  imitation changes, the runtime layer and the menu only verify the selected release. A test
  pins the call sites.
- **Helpers:** both commands regenerate the generated helpers (`awg-boringtun-launch`,
  `awg-backend-ctl`) through `_awgBtInstallHelpers` before `current` can change or the service
  restarts. Helpers of earlier installer versions refuse `-b<build>` release names, so a switch
  to a later build would otherwise leave `current` naming a release the installed helpers
  reject at the next start. An upgrade whose pin already is `current` regenerates them too,
  first of all, whatever the service's state, so that the next start of a stopped service runs
  the release `current` selects. If they cannot be written, the command fails before any link
  or service change, a duplicate `previous` included.
  - Helpers are derived files and accept the legacy build 1 names as well. So when an
    activation fails they are not put back: the restored release starts through them.
  - Params, configs and the runtime file are never rewritten for this.

**Transaction** (`boringtunBinaryLifecycle`, a subshell):
1. It takes the lifecycle lock and reads params without migrations. BoringTun only: a kernel
   installation fails before any download or change.
2. `current` must verify, and `previous`, if present, must be a valid link. The unit's
   `ActiveState` decides what happens:
   - `active` is switched and restarted;
   - `inactive` and `failed` are switched and left stopped;
   - anything else, or a state that cannot be read, aborts first.
3. The target:
   - **Upgrade:** the pin is downloaded and verified by PR 4's hardened path
     (`_awgBtEnsurePinnedRelease`, shared with the fresh install) and stored beside `current`.
     A pinned directory already in the store is reused only after it verifies against the
     embedded contract.
   - **Rollback:** the target is `previous`, verified as a store release
     (`_awgBtVerifyCandidate` with a release id):
     - trust of every directory;
     - exactly the four single-link root-owned members;
     - the MANIFEST read as data and bound to the name;
     - the binary's SHA-256 against its MANIFEST;
     - the embedded source repository;
     - the binary unchanged since it was hashed;
     - only then `--version`, against the MANIFEST version.
4. **Validation before switching** (`_awgBtValidateReleaseCandidate`):
   - The target binary runs on scratch instances, selected through `_AWG_BT_CANDIDATE_RELEASE`.
     That variable is set only by this function and reset when the installer loads, so the
     environment cannot set it; the scratch verifies the release itself.
   - It runs the persisted imitation, and the AWG 3.0 or 3.1 capability probe with the
     persisted key.
   - It runs the staged validation of the server config and of every active client config
     (private copies).
   - Params, the server config, the runtime file and every active client config must hash as
     before; they are never rewritten. A snapshot is complete or it fails:
     - if the client set cannot be read, or any of those files cannot be hashed, the
       snapshot fails;
     - before the switch, a failed snapshot stops the command before anything changes;
     - after the switch, it is a failure and the links are restored.
   - A rollback target that rejects today's settings (for example a protocol mode enabled
     after the upgrade) is refused before `current` changes.
5. `previous` := `current`, then `current` := target.
6. An active unit gets `awgBackendPrepareServiceStart`, a restart and
   `_awgBtVerifyLifecycleActivation`:
   - unit active;
   - MainPID the recorded instance, executing the binary `current` now selects;
   - TUN link, UAPI and listen port;
   - no kernel module;
   - the persisted imitation on its command line;
   - the interface carries the server config's peers.
7. On success the old `previous`, if no link names it, is removed only if it is a real
   directory directly in the trusted store. Failure to remove it is a warning.
8. **Failure recovery.** A failure, or HUP/INT/TERM, after step 5 began does the following:
   - Restores both links exactly, including a `previous` that did not exist.
   - Restarts and verifies the original release, but only if this attempt restarted the unit.
   - Removes a release this attempt downloaded.
   - Reports each failing step on its own: activation, link restoration, recovery restart,
     recovery verification. When links cannot be restored, the unit is not restarted and the
     operator gets the exact link targets.
   - Removes the private copies of the client configs on these paths. A signal that arrives
     after the traps are removed but before that removal can leave the private 0700 work
     directory behind (a known follow-up).
   - A failure before step 5 only removes what the attempt created.

**Crash model.** Writing `previous` before `current` means `current` never names a release
that has not passed step 4. After a hard interruption (SIGKILL, power loss):
- **Between the two renames:** `previous` and `current` name the same release.
  - The status marks that `previous` invalid and fails, and a rollback refuses.
  - An upgrade to a different pin proceeds and writes the links afresh.
  - An upgrade to the pin `current` already names drops only the duplicate `previous`.
  - The old `previous` (an upgrade) or the rollback target (a rollback) is left as an
    unmanaged release. That lost rollback history is not recovered: no command guesses it
    from the unmanaged directories.
- **After `current` but before the restart:** the store is consistent (`current` the verified
  target, `previous` the old release). The running daemon still executes the old binary,
  which `--backend-status` shows as `daemon_state=unverified` and
  `daemon_release=<old>`. The next `--upgrade-boringtun` to that pin restarts onto it instead
  of reporting a no-op.

No journal file is needed.

**Status.** `--backend-status` keeps every PR 5 key and appends:
- `previous_release` (a release, `none` or `invalid`);
- `rollback_available` and `upgrade_available` (`yes`/`no`);
- `daemon_release`: the store release the main process executes, from its executable path;
  `none` when stopped, `unknown` otherwise;
- `unmanaged_releases` (a count).

A damaged `current` or `previous` (including `previous` naming `current`) makes it exit 1.
It stays read-only: no repair, download, restart or helper write.

`rollback_available=yes` means that `previous` names another release that passes the
runtime's store check. It does not promise a rollback succeeds. The rollback itself also
checks the release's exact members and single links, runs the binary's `--version`, and
validates it against today's configuration; it can still refuse. Aligning the status with
the stricter structural check is a known follow-up.

**Tests.**
- `tests/test-boringtun-lifecycle.sh` uses TEST FIXTURE releases served by a mocked curl. It
  covers:
  - identity, and the b1/b2 coexistence and switching;
  - PR 4/PR 5 stores, fresh installs and the no-op;
  - service states, gates and candidate validation at AWG 2.0/3.0/3.1 with
    none/dns/quic/stun;
  - rejection by the target binary;
  - activation, link and recovery failures, signals and retention;
  - damaged links and releases, the interrupted switch and the status;
  - the call sites and the candidate's scratch selection;
  - the helpers that the PR 6 base installer (`78b780b`) renders itself: a stopped and an
    active b1 → b2 switch, which must leave helpers that accept b2; a helper update that
    fails; and a failed activation that restarts b1 through the updated helpers. CI fetches
    that installer by its SHA as `AWG_TEST_BASE_INSTALLER`;
  - the same helpers with `current` already the pinned b2: `inactive` and `failed` (helpers
    reconciled, no start, no download, no link change, and a next start that runs through
    them), a healthy active daemon (no restart), an active daemon on another binary (one
    reconciliation, then one restart), a helper update that fails in either stopped state,
    helpers that already are this installer's (a true no-op), and the duplicate `previous`
    left by a killed rollback together with stale helpers;
  - a rollback really killed (SIGKILL) between its two link renames, and the upgrade that
    repairs the duplicate `previous`;
  - snapshots that cannot be completed, each before and after the switch: params, the server
    config, the runtime file, a client config, the client set, and a `sha256sum` failure.
- `tests/mutate-boringtun-lifecycle.sh` holds its mutants, including the helper update, the
  duplicate repair, the helper update when the pin already is `current`, every snapshot input,
  both failure checks and both comparisons.
- The host live test makes a TEST FIXTURE older release current (the verified binary under the
  synthetic commit `feedface…`) and removes the pin from the store. It then upgrades
  (downloading the real release), rolls back, upgrades again without a download, and runs a
  no-op. Each step checks the datapath (ping and a 4 MiB checksummed TCP transfer), the
  daemon's release, the imitation and unchanged configuration hashes.
- The coexistence job runs the same upgrade before its kernel-client interop.
- The x86_64 host job (`AWG_LIVE_BASE_INSTALLER`) then installs the helpers the PR 6 base
  installer renders. It rolls back to a TEST FIXTURE build 2 of the pinned commit (a `-b2`
  name those helpers refuse) through systemd's real restart, and upgrades back, with the
  datapath checked each time.

## 22. Current functions and files that will need modification

### `amneziawg-install.sh` (line numbers at `67fd5ce`)

| Function or location | Change | PR |
|---|---|---|
| Constants block (l.6–37) | Backend constants; BoringTun pin, store and helper paths | 1, 2/4 |
| `serializeParams` (l.2460) | Write `AWG_BACKEND`; imitation keys | 1, 5 |
| `validateParamsFile` (l.5888; `unset` l.5972) | Unset new keys; call backend validation | 1, 5 |
| New `normalizeAwgBackend`, `validatePersistedAwgBackendState` | Backend model | 1 (kernel), 4, 5 |
| `initialCheck` (l.2909), `checkVirt` (l.2749) | Backend-aware policy; identical for kernel in PR 1 | 1, 7 |
| `installQuestions` (l.4092) | Backend and imitation selection | 4, 5 |
| `installAmneziaWG` (l.4599) | Split into backend steps: packages (l.4610–4789), boot (l.4793–4838), drop-in (l.4912–4923), start (l.4933–4960), hints (l.4938–4957, l.4972–4999) | 1 (seam), 4 |
| `ensureAmneziawgKernelModule` (l.3538) | Unchanged; becomes the kernel implementation of `ensureAwgBackendReady` | 1 |
| `ensureAwgQuickRunning` (l.3513) | Reused by the BoringTun implementation | 3 |
| `newClient` (l.5002; l.5003, l.5315) | Readiness and sync through the seam | 1 |
| `revokeClient` (l.5344; l.5387–5388) | Same | 1 |
| `regenerateClients` (l.5391; l.5757–5758) | Same | 1 |
| `persistMigration` (l.6223; l.6459) | Sync through the seam | 1 |
| `probeAwgProtocolCapability` (l.1731; l.1786, l.1803–1817) | Scratch primitive; backend messages | 1, 3 |
| `validateStagedAwgConfigs` (l.6810; l.6818) | Scratch primitive | 1, 3 |
| `applyAwgProtocolTransaction` (l.6900; `restartManualAwgInterface` l.6909; l.7046) | `awgBackendQuickUp` | 1, 3 |
| `setAwgProtocolMode` (l.7069; l.7109, 7158, 7181) | Readiness through the seam; proxy guard | 1, 8 |
| `nonInteractiveAddClient` (l.7435; l.7595–7596) | Readiness and sync through the seam | 1 |
| `nonInteractiveRemoveClient` (l.7612; l.7651–7652) | Same | 1 |
| `uninstallAmneziaWG` (l.5785; l.5811, 5823, 5847) | Backend cleanup | 1 (seam), 4 |
| `manageMenu` (l.7304) | Show backend and imitation | 5 |
| Main dispatch (l.7688 onwards) | `--backend-status`, `--set-boringtun-imitation`, `--upgrade-boringtun`, `--rollback-boringtun`, `--migrate-backend` | 5, 6, 10 |
| Direct `systemctl … awg-quick@` calls | `awgService*` wrappers | 9 |

### Other files

| File | Change | PR |
|---|---|---|
| `amneziawg-web/scripts/amneziawg-web-privileged`: `reconcile_interface` (l.575, syncconf l.638) | Equality-based `ListenPort` filter | 4 |
| same file: `emit_safe_params` (l.378) | Allowlist the backend and imitation keys (read-only) | 8 |
| `amneziawg-web/src/system_versions.rs`, `detect_amneziawg` (l.81) | Backend and BoringTun version | 8 |
| `amneziawg-web/src/web/mod.rs` (l.4026) | Neutral wording | 8 |
| `amneziawg-web/docs/INSTALL.md` (Docker limitations) | Container notes | 9 |
| `amneziawg-proxy/scripts/amneziawg-proxy-install.sh`: `awg_protocol_is_proxy_compatible` (l.325), `detect_awg_config` (l.336) | Backend guard | 4 |
| `amneziawg-proxy/doc/USAGE.md`, `README.md` | Documentation | 4, 8 |
| `amneziawg-proxy/src/**` | **No change** | — |
| `tests/test-backend.sh` (new), `tests/test-install-mock.sh`, `tests/test-awg3.sh`, `tests/test-functions.sh`, `tests/test-proxy-scripts.sh` | Tests | 1, 3, 4, 5 |
| `tests/test-boringtun-live.sh` (new), `tests/test-boringtun-container.sh` (new) | Live and container tests | 3/4, 9 |
| `.github/workflows/test.yml`, `.github/workflows/lint.yml` | New jobs and files | 1, 3, 4 |
| `.github/workflows/boringtun-artifacts.yml` (new) | Artefact pipeline | 2 |
| `docs/VERSIONING.md` | Describe BoringTun artefact releases | 2 |
| `README.md` | BoringTun backend section (experimental), containers | 4, 9 |

---

## 23. Open questions and risks

| # | Item | Type | Proposed next step |
|---|---|---|---|
| R1 | BoringTun leaks listen sockets on every `set=1` carrying `listen_port`. | Upstream defect (VERIFIED) | Mitigated by the `ListenPort` filter. Report upstream as an observation only; this project requests no change. |
| R2 | Hosts booted with `ipv6.disable=1` cannot run BoringTun. | INFERRED limitation | The preflight refuses with a clear message; verify on a VM in PR 4. |
| R3 | Kernel module on BoringTun hosts, especially containers whose host can autoload it. | Design risk | Precheck, poststart check and PID contract, fail-closed (§7.11); test in PR 4. |
| R4 | The daemon runs as root. | Security | Accept initially; evaluate `setpriv` with ambient capabilities later. |
| R5 | AWG 3.x plus imitation: header-protection masking is weakened, and upstream-collision avoidance is off, so kernel and go clients may drop packets. | Operational; PARTLY SUPERSEDED at `71d8878` | The nonce weakening stands (`dns` 16-bit, `stun` 32-bit, `quic` random), and the installer warns. The collision avoidance now applies to `none`, `dns`, `quic` and `stun`, and SIP with a request-line prefix is refused under header protection (§9.4, §21.3). Kernel-client loss is measured by the coexistence job (§21.3); amneziawg-go is not measured in PR 5. |
| R6 | Throughput and CPU compared with the kernel module. | OPEN | Benchmark on VMs (x86_64 and aarch64). |
| R7 | Maturity and security-audit status of the fork; who owns pin bumps and how fast security fixes ship. | Governance | Maintainers decide an owner and a response-time target. |
| R8 | Publishing binaries from this repository is a new release process. | Governance | Decide in PR 2; alternatively publish from the WireSock organisation. |
| R9 | musl versus glibc, and architectures beyond x86_64 and aarch64. | OPEN | Decide in PR 2 after benchmarks. |
| R10 | Older installer copies (for example a stale web-panel lifecycle script) would run kernel repair logic on BoringTun hosts. | Compatibility | Guard (§4.6); consider a params format version. |
| R11 | The installer does not block enabling AWG 3.x while the proxy is installed. | Pre-existing gap | Fix in PR 8 with maintainer sign-off. |
| R12 | The BoringTun drop-in overrides `Type=`, `ExecStop=` and `ExecReload=` of the packaged unit; a future packaged unit could conflict. | Maintenance | CI renders the drop-in against the PPA unit; the precheck verifies the base unit shape. |
| R13 | PostDown replay must match awg-quick's parser exactly. | Correctness | Parity tests against awg-quick's own parsing using fixture configs. |
| R14 | `awg show` shows no interface public key under BoringTun, and `SaveConfig` would erase the private key. | Operational | Document; refuse `SaveConfig` (§7.10). |
| R15 | The web unit's `/run` writability depends on a systemd quirk. | Design risk | Scratch interfaces always use transient units (§8.4). |
| R16 | Probe responder amplification (STUN about 2.6×) is bounded only by an aggregate budget. | Security | Document; consider exposing `WG_PROBE_REPLY_RATE` later. |
| R17 | RPM distributions stay disabled for both backends. | Scope | Revisit when tools packages are verified. |
| R18 | Whether to expose the log level, thread count and probe-reply rate. | OPEN | Not in the first versions. |
| R19 | Firewall rule duplication after an operator deletes a kernel link is pre-existing and not addressed for the kernel. | Pre-existing | Out of scope. |
| R20 | Upstream `awg-quick` could offer a way to force userspace. | Upstream idea | Optional request; the design does not depend on it. |
| R21 | Whether a modprobe `blacklist` line stops the kernel-initiated `rtnl-link-amneziawg` autoload, or whether `install amneziawg /bin/false` is needed. | DECIDED in PR 4 | The coexistence test showed that a blacklist stops the autoload but not an explicit `modprobe`, and the install command stops both; PR 4 uses the install command (§7.11, §21.2). |

---

## Recommended target architecture (concise)

- **One lifecycle model for both backends:** `awg-quick@<if>.service`, the params file as the
  single source of truth, `awg` over netlink or UAPI for live changes, and identical config
  files and firewall hooks.
- **The backend is an explicit, persisted choice** (`AWG_BACKEND`, missing means kernel)
  behind a small Bash backend interface. The kernel implementation is today's code
  unchanged.
- **BoringTun backend:**
  - A pinned, checksum-verified static binary built by this repository's CI.
  - An installer-owned supervised drop-in (`Type=forking`, a PID file written only by the
    launcher, restart limits).
  - A sanitizing launcher that turns validated params into BoringTun flags.
  - Fail-closed prechecks against the kernel module.
  - Crash-safe teardown.
  - A `ListenPort`-filtered sync.
  - Scratch BoringTun instances in transient units for AWG 2.0/3.0/3.1 capability probes and
    staged validation.
- **Built-in imitation** is a BoringTun-only, restart-applied setting with explicit
  security trade-off warnings. The standalone proxy stays a kernel plus AWG 2.0 feature and
  is refused in front of BoringTun.
- **Web panel and proxy remain backend-agnostic**, apart from one helper filter and small
  guards.
- **Containers and LXC** are enabled by the same primitives, delivered after host support.

## Proposed first PR scope

**Title:** "Introduce AWG backend abstraction (kernel only, no behaviour change)"

It is useful on its own, reviewable, and needs nothing from `wiresock-boringtun`.

- **Params model.** Add `AWG_BACKEND` with `normalizeAwgBackend` and
  `validatePersistedAwgBackendState`. Only `kernel` is accepted; empty means kernel; any other
  value, including `boringtun`, fails closed with "not supported by this installer version".
  Add the key to the `validateParamsFile` `unset` list and to `serializeParams`.
- **Seam.** Add the dispatch functions `ensureAwgBackendReady`,
  `awgBackendCreateScratchInterface`, `awgBackendDestroyScratchInterface`,
  `awgSyncInterfaceConfig`, `awgBackendQuickUp`, `awgBackendRenderServiceDropIn`,
  `awgBackendWriteServiceDropIn`, `awgBackendPrepareBoot`, `awgBackendInstallPackages`,
  `awgBackendUninstall` and a backend-aware `checkVirt`. Each kernel branch calls today's
  code verbatim.
- **Call sites.** Route all K11/K12, K14–K17 and K19 call sites through the seam, with no
  change to commands, files or messages.
- **Tests.** All existing suites pass unmodified. Add `tests/test-backend.sh` covering
  normalization, the environment boundary, serialization, rejection of unknown backends, a
  golden kernel drop-in and kernel command-sequence equivalence for probe, validation and
  sync. Wire it into `test.yml`, `lint.yml` and ShellCheck.
- **Docs.** This design document.
- **Excluded:** anything BoringTun-specific, and any change to the proxy or web panel.

---

## Appendix A — Experiment log

All experiments ran on the environment in §0. Test artefacts were removed afterwards.

| # | Experiment | Result |
|---|---|---|
| E1 | `awg-quick up` with `WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun-cli`, run detached without `WG_SUDO` | BoringTun failed to start (privilege drop). |
| E1 | Same with `WG_SUDO=true`; AWG 3.1 server config with hooks | Up; TUN multi-queue (4 queues); both sockets; `awg show` and `showconf` complete except keys; all eight 3.x fields read back; PostUp ran; listens on `0.0.0.0` and `[::]`. |
| E1 | `awg syncconf` add and remove peer | Worked. |
| E1 | `awg-quick down` | Link removed, daemon exited, sockets removed, PostDown ran. |
| E1 | Stale socket and SIGKILL | Stale sockets ignored by `awg show interfaces`; restart over a stale socket worked; link gone after SIGKILL. |
| E1 | Imitation argument validation | Domain with `stun` exits 1; unknown protocol exits 2; `get=1` does not expose imitation. |
| E1 | `net.ipv6.conf.all.disable_ipv6=1` | BoringTun starts and binds both families. |
| E1 | Probe-style scratch interface | All eight fields matched; `[Interface]`-only setconf worked; `ip link delete` made the daemon exit. |
| E2 | `awg-quick@` with an environment drop-in (oneshot) | start, reload and restart worked; daemon stayed in the unit cgroup; daemon-mode log file empty; kill -9 left the unit "active (exited)"; restart recovered; stop clean. A launcher with `--foreground` put logs in the journal (ANSI colours without `NO_COLOR`); the HP plus imitation WARN was visible at `info`. A missing implementation failed the unit. |
| E3 | Network-namespace datapath: BoringTun server with AWG 3.1, header protection, RandomTrailers and DNS imitation, against a plain BoringTun client | Ping OK; 16 MiB TCP transfer with matching SHA-256; server-to-client prefixes DNS-shaped; dump shows `(none)` keys. |
| E3 | Probe responder | Non-loopback DNS probe answered with SERVFAIL; loopback probe (E2) not answered. |
| E3 | `ExecStartPost` failure | `ExecStopPost` ran; `ExecStop` did not. |
| E3 | `Type=forking`, `PIDFile`, `Restart=on-failure` | Reload OK; kill -9 restarted the unit (`NRestarts=1`); PostUp ran twice with no PostDown in between. |
| E4 | Stop hooks per event | Clean stop runs `ExecStop` and `ExecStopPost`; crash runs only `ExecStopPost` (`SERVICE_RESULT=signal`); operator link delete runs `ExecStop` (the prototype's awg-quick down failed; the implementation skips it, §21.1) and `ExecStopPost`, unit inactive and not restarted. |
| E5 | 20 × syncconf during 50 pings per second | 3 of 200 pings lost; listen sockets multiplied; handshake unchanged. |
| E6 | Descriptor count over 50 + 50 syncconfs | +100 fds with `ListenPort`; 0 without; port and peers unchanged. |
| E7 | Launcher never writes the PID file | Unit stays activating until `TimeoutStartSec`, then fails (`timeout`), kills its cgroup, runs `ExecStopPost`, then restarts. |
| E8 | Web-like sandbox (`ProtectSystem=strict`, …) | `awg show all dump` and syncconf worked against BoringTun's socket. `/run` is read-only under `ProtectSystem=strict` alone but read-write when `ProtectControlGroups=yes` is added (systemd 255). A transient unit requested from inside the sandbox started BoringTun. |
| E9 | BoringTun under a systemd transient unit | Default privilege drop fails with `NULL from getlogin`; `WG_SUDO=true` works. |
| E10 | Environment facts | `/usr/bin/ip` exists (Ubuntu 24.04); `tracing-subscriber` 0.3.23 honours `NO_COLOR`; PPA `amneziawg-tools` recommends `amneziawg-dkms`; PPA tools commit is `ee0f0a9` on focal and noble, amd64 and arm64. |
| E11 | `ProtectSystem=strict` alone, where `/run` is read-only and not writable | `awg show <if> listen-port` and `awg set <if> listen-port` both succeeded through BoringTun's UAPI socket, and the change was visible from the host. |

## Appendix B — Observations about BoringTun (informational; no changes requested)

These notes describe the current behaviour of `wiresock-boringtun` at `e4e4dc8` that this
design works around. They are recorded to help a future pin bump remove workarounds. None of
them blocks the design, and this project does not modify BoringTun.

1. A `set=1` carrying `listen_port` re-binds new sockets even when the port is unchanged,
   and the previous sockets stay open (R1).
2. In daemon mode the log writer does not survive the fork.
3. The default privilege drop depends on `getlogin()` and therefore fails under service
   managers.
4. `get=1` omits the private key, so `awg showconf` output cannot be re-applied and
   `SaveConfig` must not be used.
5. Startup requires the IPv6 socket family (inferred).
6. A PID-file or readiness-notification option would remove the need for the launcher's
   readiness polling.
