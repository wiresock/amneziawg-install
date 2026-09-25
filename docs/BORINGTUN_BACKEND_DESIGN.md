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
| `ExecStop=… stop` | Runs `awg-quick down %i` and removes the `.up` marker on success. If the interface is already gone it exits 0 and leaves the marker. |
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
| `systemctl stop` | `ExecStop` runs: `awg-quick down` succeeds and PostDown runs. Then `ExecStopPost` runs with `SERVICE_RESULT=success`. | `stop` clears the `.up` marker; `poststop` has nothing to do. |
| Daemon crash (SIGKILL) | `ExecStop` does **not** run. `ExecStopPost` runs with `SERVICE_RESULT=signal`. The unit restarts after `RestartSec`, and PostUp runs again without a PostDown in between. | `poststop` sees the marker and replays PostDown (§7.9). |
| Operator runs `ip link del <if>` | The daemon exits 0. `ExecStop` runs, but `awg-quick down` fails because the interface is gone. `ExecStopPost` runs. The unit becomes inactive and is not restarted. | `stop` leaves the marker, and `poststop` replays PostDown. |
| `awg-quick` used another datapath, so no PID file was written (simulated with an implementation that does not write it) | The unit stays "activating" until `TimeoutStartSec`, then fails with `timeout`, kills its cgroup and runs `ExecStopPost`. `Restart=` retries. | `poststop` removes a surviving non-TUN link with `awg-quick down`, which runs PostDown. Start limits stop the loop. |
| `ExecStartPost` fails | `ExecStop` is skipped and `ExecStopPost` runs. | Same cleanup. |
| Reload | `ExecReload` works with `Type=forking`. | Filtered sync. |

Without supervision (plain `Type=oneshot`), a BoringTun crash left the unit "active (exited)"
while the interface was gone and `awg syncconf` failed (VERIFIED). That is why supervision is
proposed.

### 7.9 Crash-safe teardown (PROPOSAL)

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

**Which load override (OPEN, decided by the PR 4 coexistence test, §18.6).** A modprobe
`blacklist amneziawg` line makes modprobe ignore the module's aliases. It is not established
that this also stops the kernel's own `rtnl-link-amneziawg` request, which is what
`ip link add … type amneziawg` triggers. `install amneziawg /bin/false` blocks every load that
goes through modprobe, including an explicit `modprobe amneziawg`. It is therefore the safer
choice, but a later migration back to the kernel must remove it first (§20). Note that
`modprobe -n` succeeds for a module with an `install` override, so the precheck must look for
the override file rather than rely on a dry run.
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
   protocol instead.
2. **Upstream-collision avoidance is off under imitation.** With header protection on and no
   imitation, BoringTun re-frames a transport packet that an upstream receiver would misread
   as a control message. The kernel module (`4569c4c`) and amneziawg-go (`b5928ef`) drop such
   packets. BoringTun's own notes put the per-framing collision probability at up to about 7%
   with the stock installer's H ranges. Under imitation this avoidance is skipped pending a
   per-protocol review (FACT). BoringTun server plus AWG 3.x plus imitation plus kernel or
   go clients may therefore lose a fraction of server-to-client packets. **OPEN:** measure
   this with a live interop test before recommending that combination. Until then the
   installer warns, and recommends imitation with AWG 2.0, or AWG 3.x only with clients
   known to handle it.
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
   aggregate byte budget bounds that reflection (FACT).
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
8. `--set-boringtun-imitation dns …`. The probe responder answers a non-loopback DNS probe;
   the wire prefix is DNS-shaped.
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
  another namespace, for AWG 2.0, 3.0 and 3.1, with and without imitation. This yields the
  measurement asked for in §9.4.

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
| **4. BoringTun host install and uninstall (experimental)** | `AWG_BACKEND=boringtun` for fresh Debian and Ubuntu installs (VM or bare metal); packages without recommends; binary acquisition and verification; uninstall; proxy and web-lifecycle guards; the web helper `ListenPort` filter; the proxy installer backend guard; the full live CI job (§18.3–18.6); README section marked experimental. | Yes | 3 |
| **5. Built-in imitation** | Params keys, validation, install-time selection, `--set-boringtun-imitation` transaction, warnings and advisory, `--backend-status`, menu display. | Yes | 4 |
| **6. BoringTun binary lifecycle** | `--upgrade-boringtun` and `--rollback-boringtun` transactions. | Yes | 4 |
| **7. Virtualization** | Backend-aware `checkVirt` with LXC and nspawn support for BoringTun after preflight; LXC hints; an LXC CI test if feasible (LXD on the runner). | Yes | 4 |
| **8. Web panel and proxy UX, plus kernel-side guard** | Web wording, version display and read-only backend status (helper allowlist); proxy docs; refuse AWG 3.x with the proxy installed (a flagged behaviour change). | Yes | 4 |
| **9. Container deliverable** | Dockerfile and entrypoint, `awgService*` abstraction, container mode, Docker integration test. | Yes | 4, 5 |
| **10. Explicit backend migration** | `--migrate-backend kernel\|boringtun` transaction (§20). | Yes | 4, 6 |

---

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
| R5 | AWG 3.x plus imitation: header-protection masking is weakened, and upstream-collision avoidance is off, so kernel and go clients may drop packets. | Operational (FACT; loss rate unmeasured) | Warn; measure in the §18.6 interop job before recommending. |
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
| R21 | Whether a modprobe `blacklist` line stops the kernel-initiated `rtnl-link-amneziawg` autoload, or whether `install amneziawg /bin/false` is needed. | OPEN | Decide in the PR 4 coexistence test (§7.11, §18.6). |

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
| E4 | Stop hooks per event | Clean stop runs `ExecStop` and `ExecStopPost`; crash runs only `ExecStopPost` (`SERVICE_RESULT=signal`); operator link delete runs `ExecStop` (awg-quick down fails) and `ExecStopPost`, unit inactive and not restarted. |
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
