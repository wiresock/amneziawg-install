# AmneziaWG Installer

Set up an [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) obfuscated VPN on any supported Linux server in under 2 minutes — with backward-compatible AWG 2.0 defaults, optional AWG 3.0 support, an optional web panel, and an optional traffic-obfuscation proxy (AmneziaWG 2.0 only).

```
VPN install → (optional) Web panel → (optional) Obfuscation proxy → Manage clients
```

---

## 📖 Background

This project started as a fork of [RomikB/amneziawg-install](https://github.com/RomikB/amneziawg-install). I needed a reliable way to stand up **AmneziaWG 2.0** servers for testing [WireSock Secure Connect](https://www.wiresock.net/), and the upstream script predated the 2.0 release — so I took it and extended it to generate and manage the new 2.0 obfuscation parameters (S3/S4 padding and the H1–H4 header ranges). It now also supports an explicit, capability-checked migration to **AmneziaWG 3.0** while preserving AWG 2.0 as the default for new and existing installations.

Once the installer was solid, it was hard to stop:

1. **`amneziawg-install.sh`** — the original script, extended for AmneziaWG 2.0 (S3/S4, H1–H4, migration from pre-2.0 installs), optional AmneziaWG 3.0 header protection, and optional AmneziaWG 3.1 (`RandomTrailers` / `DisableCookies`).
2. **`amneziawg-web.sh`** — a web panel for managing clients and explicit AWG 2.0 / 3.0 / 3.1 migrations without touching the CLI.
3. **`amneziawg-proxy.sh`** — a UDP obfuscation proxy that takes traffic camouflage to the next level: it wraps AmneziaWG (AWG 2.0 only) so the datagrams on the wire look like a legitimate QUIC, DNS, STUN, or SIP service to Deep Packet Inspection (DPI).

> **⚠️ amneziawg-proxy is compatible only with AmneziaWG 2.0 and is most powerful with WireSock Secure Connect 3.5+.**
> The proxy is compatible **only with AmneziaWG 2.0** (it is **not compatible with AWG 3.0+** because AWG 3.0 uses S1–S4 padding as key material for header encryption). The proxy's full protocol-imitation feature set — coordinated client/server cover traffic, junk-packet shaping, and per-protocol padding — is only fully unleashed when paired with [WireSock Secure Connect](https://www.wiresock.net/) **3.5 or later** on the client side. Standard AmneziaWG clients still connect through the proxy and benefit from the server-side obfuscation, but the bidirectional imitation requires the WireSock client.

---

## 🚀 Quick Start

**VPN only (required):**

```bash
curl -O https://raw.githubusercontent.com/wiresock/amneziawg-install/main/amneziawg-install.sh
chmod +x amneziawg-install.sh
sudo ./amneziawg-install.sh
```

**Add the web panel (optional):**

```bash
curl -O https://raw.githubusercontent.com/wiresock/amneziawg-install/main/amneziawg-web.sh
chmod +x amneziawg-web.sh
sudo ./amneziawg-web.sh install
```

> **Note:** The web panel installer requires `git` to bootstrap the repository when run
> standalone. If `git` is not available, clone the repository manually or use `--binary-src`
> with a pre-built binary.

**Add the obfuscation proxy (optional):**

```bash
curl -O https://raw.githubusercontent.com/wiresock/amneziawg-install/main/amneziawg-proxy.sh
chmod +x amneziawg-proxy.sh
sudo ./amneziawg-proxy.sh
```

> Makes the VPN traffic look like QUIC/DNS/STUN/SIP to DPI. Compatible with
> **AmneziaWG 2.0 only** (not compatible with AWG 3.0+). See
> **[Traffic Obfuscation Proxy](#-traffic-obfuscation-proxy-amneziawg-proxy)**.

✅ **After installation:**
- VPN server is running
- AWG 2.0 remains active by default; [AWG 3.0](#-optional-awg-30-mode) is enabled only by an explicit migration after userspace and kernel capability checks pass (do not enable AWG 3.0 if using `amneziawg-proxy`)
- A client config file is generated at `~/awg0-client-<name>.conf`
- (If installed) Web panel listens on `127.0.0.1:8080` by default — access it on the server at `http://127.0.0.1:8080`, or change `AWG_WEB_LISTEN` / use a reverse proxy for remote access

---

## 🧠 How It Works

- **`amneziawg-install.sh`** — **required.** Installs the VPN server, generates obfuscation parameters, creates client configs, and can transactionally enable AWG 3.0 after capability checks or return the installation to AWG 2.0.
- **`amneziawg-web.sh`** — **optional.** Unified script for:
  - `install` — install the web panel
  - `upgrade` — upgrade the binary
  - `uninstall` — remove the panel
  - `status` — show installation status
- **`amneziawg-proxy.sh`** — **optional.** Installs and manages the UDP obfuscation proxy that fronts AmneziaWG (**AWG 2.0 only**) and makes the traffic look like QUIC, DNS, STUN, or SIP. See **[Traffic Obfuscation Proxy](#-traffic-obfuscation-proxy-amneziawg-proxy)** below.

---

## 🤔 Choose Your Setup

| Goal | What to run |
|------|-------------|
| VPN server only | `amneziawg-install.sh` |
| VPN + web panel | `amneziawg-install.sh` then `amneziawg-web.sh install` |
| VPN + DPI-resistant obfuscation | `amneziawg-install.sh` then `amneziawg-proxy.sh` *(AWG 2.0 only)* |
| Everything | `amneziawg-install.sh`, then `amneziawg-web.sh install`, then `amneziawg-proxy.sh` *(AWG 2.0 only)* |
| Advanced / development | Clone the repo, then run the scripts from the checkout |

---

## 🟢 Minimal Setup — VPN Only (Recommended)

> Most users should start here.

1. Update your system and reboot before installing.
2. Run the commands from **[Quick Start](#-quick-start)**.
3. Answer the prompts. The script installs AmneziaWG, configures the server, and generates a client config file.
4. **Run the script again at any time** to add or remove clients.

---

## 🟡 Advanced Setup — VPN + Web Panel

> ⚠️ Requires VPN to be installed first (`amneziawg-install.sh`).

Use the **[Quick Start](#-quick-start)** commands above, or clone the repository (best for teams or repeated upgrades):

```bash
git clone https://github.com/wiresock/amneziawg-install.git
cd amneziawg-install
sudo ./amneziawg-install.sh
sudo ./amneziawg-web.sh install
```

The installer automatically downloads required files and builds the panel.
Add `--install-rust` if Rust is not already installed on the server.

See [amneziawg-web/docs/INSTALL.md](amneziawg-web/docs/INSTALL.md) for all installer options.

---

## 🎭 Traffic Obfuscation Proxy (amneziawg-proxy)

> ⚠️ Requires VPN to be installed first (`amneziawg-install.sh`).

> [!IMPORTANT]
> **Compatibility: AmneziaWG 2.0 only (incompatible with AWG 3.0+)**
>
> `amneziawg-proxy` is compatible **only with AmneziaWG 2.0** and cannot be used when AWG 3.0 mode is enabled.
>
> In AmneziaWG 2.0, the S1–S4 padding prefix consists of arbitrary random bytes that the proxy safely replaces with cover-protocol filler bytes (QUIC, DNS, STUN, or SIP headers) while preserving the encrypted payload. Starting with AmneziaWG 3.0, the S1–S4 padding values are used as key material for header encryption (`HeaderProtectionKey`). Modifying or rewriting them in flight breaks header decryption on the peer, and the encrypted headers prevent the proxy from classifying packets.
>
> If you plan to use `amneziawg-proxy`, keep your interface in AWG 2.0 mode (the default). Do not enable AWG 3.0 on a proxied interface.

`amneziawg-proxy` is an async UDP proxy (written in Rust) that sits **in front of**
your AmneziaWG server and disguises the traffic so that, to Deep Packet
Inspection (DPI), the port appears to host an ordinary **QUIC, DNS, STUN, or
SIP** service. AmneziaWG's own obfuscation already hides the WireGuard
fingerprint; the proxy adds a second layer that makes the packets *positively
resemble* a known, allowed protocol instead of merely looking random.

> **💡 Best paired with WireSock Secure Connect 3.5+.** The proxy obfuscates
> the **server → client** direction on its own. Bidirectional imitation — where
> the **client → server** direction is camouflaged too — requires
> [WireSock Secure Connect](https://www.wiresock.net/) **3.5 or later**, which
> implements the matching client-side protocol imitation and junk-packet shaping.

### Install

The proxy installer detects the AWG interface, rebinds AmneziaWG to loopback,
builds the binary, and installs a systemd service. One command does it all:

```bash
curl -O https://raw.githubusercontent.com/wiresock/amneziawg-install/main/amneziawg-proxy.sh
chmod +x amneziawg-proxy.sh
sudo ./amneziawg-proxy.sh
```

Run with no arguments and it walks you through guided prompts. Run it again
later and it shows a management menu (status, logs, reconfigure, uninstall).

**Non-interactive examples.** `amneziawg-proxy.sh` forwards any flags to the
installer (cloning the helper scripts on the fly when run standalone), so the
one downloaded file is all you need:

```bash
# QUIC imitation (safest default) — public :51820 → loopback :51821
sudo ./amneziawg-proxy.sh \
  --non-interactive --listen-port 51820 --protocol quic

# DNS imitation that also answers real DNS queries (run on port 53)
sudo ./amneziawg-proxy.sh \
  --non-interactive --listen-port 53 --protocol dns \
  --dns-forward --dns-upstream 1.1.1.1:53

# STUN imitation (port 3478, WebRTC/NAT-permissive networks)
sudo ./amneziawg-proxy.sh \
  --non-interactive --listen-port 3478 --protocol stun
```

Full option reference, configuration keys, and troubleshooting live in
[amneziawg-proxy/doc/USAGE.md](amneziawg-proxy/doc/USAGE.md). Internal design
and packet-level walkthroughs are in
[amneziawg-proxy/doc/ARCHITECTURE.md](amneziawg-proxy/doc/ARCHITECTURE.md).

### How It Works

After install, all client traffic flows through the proxy, which AmneziaWG no
longer exposes directly:

```
                         ┌───────────────────────────────────┐
 VPN client ──── UDP ───►│  0.0.0.0:51820   amneziawg-proxy  │
 (DPI sees QUIC/DNS/     │            │                      │
  STUN/SIP)              │            ▼                      │
                         │  127.0.0.1:51821  awg0 (AmneziaWG)│
                         └───────────────────────────────────┘
```

The proxy does two complementary things:

1. **Probe response.** When a scanner or DPI box sends a protocol probe
   (a QUIC Initial, a DNS query, a STUN Binding Request, a SIP request), the
   proxy replies with a *valid* protocol response — a QUIC Version Negotiation,
   a DNS answer, a STUN Binding Success, a SIP `100 Trying`. The port therefore
   behaves exactly like the service it is pretending to be when actively
   probed.
2. **Padding transformation.** Every outgoing AmneziaWG 2.0 packet already carries a
   random S1–S4 padding prefix. The proxy overwrites that prefix with
   protocol-conformant bytes (a QUIC short header, a DNS/STUN header, SIP header
   text) so the *leading bytes and byte-distribution* of each datagram match the
   imitated protocol — while the encrypted WireGuard payload that follows is
   left untouched. (Note: this relies on AmneziaWG 2.0 protocol semantics where
   headers are plaintext and S1–S4 padding is unkeyed; in AWG 3.0+, S1–S4 padding
   serves as key material for header encryption, so rewriting it breaks compatibility).

| Mode | What DPI sees | Typical port | Good for |
|------|---------------|--------------|----------|
| `quic` | QUIC 1-RTT / Version Negotiation | 443 | QUIC/HTTP-3-heavy networks (safest default) |
| `dns`  | DNS query/response (optionally real) | 53 | DNS-filtered networks |
| `stun` | STUN Binding traffic | 3478 | WebRTC / NAT-traversal-permissive networks |
| `sip`  | SIP signaling | 5060 | VoIP-permissive networks |
| `auto` | Whatever the client probes for | — | Mixed-probe environments |

### Traffic Examples

**STUN mode — an outgoing server packet on the wire.** The padding prefix is
rewritten as a well-formed STUN message; a packet-capture tool dissects it as
STUN and leaves the encrypted AmneziaWG payload as trailing bytes:

```
01 01 00 1c 21 12 a4 42  4f 7a 1c …   ← STUN: Binding Success Response, msg length 0x1c, cookie 0x2112A442
00 20 00 08 00 01 …                    ← XOR-MAPPED-ADDRESS attribute (12 B)
80 22 00 0c …                          ← SOFTWARE attribute (16 B; fills the prefix) → 12 + 16 = 0x1c
… encrypted AmneziaWG payload …        ← opaque ciphertext (trails the message, not parsed)
```

**QUIC mode — a probe and its response.** A DPI box sends a QUIC Initial; the
proxy answers with a valid Version Negotiation packet, swapping the connection
IDs per RFC 9000:

```
→  c3 00000001 04 aabbccdd 00            QUIC Initial probe (DCID=AABBCCDD)
←  c3 00000000 00 04 aabbccdd 00000001   Version Negotiation (SCID echoes the DCID)
```

**DNS mode — a query answered for real.** With `--dns-forward`, a DNS probe is
forwarded to the upstream resolver and the genuine answer is returned, so the
port doubles as a working resolver while still tunneling VPN traffic.

To inspect it yourself, capture on the server's public port and open the capture
in Wireshark — frames decode cleanly as the imitated protocol, with no
"malformed" or WireGuard markers:

```bash
sudo tcpdump -i any -w awg-proxy.pcap udp port 51820
```

### Manage / Uninstall

Re-running `amneziawg-proxy.sh` on an installed host opens a management menu
(status, logs, reconfigure, uninstall) — the simplest path, and it works from
the single downloaded file:

```bash
sudo ./amneziawg-proxy.sh
```

From a repository checkout you can also drive the uninstaller non-interactively
(keeps config/data by default; add `--restore-awg` to rebind AWG to the public
port):

```bash
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh --force
```

---

## ⚙️ After Installation

- **VPN client config** is saved to `~/awg0-client-<name>.conf`. Import it into any AmneziaWG client app.
- **Web panel** listens on `127.0.0.1:8080` by default. Access it on the server at `http://127.0.0.1:8080`, or change `AWG_WEB_LISTEN` / use a reverse proxy for remote access.
- Re-run `sudo ./amneziawg-install.sh` to add or remove VPN clients interactively.
- Check the web panel status at any time:
  ```bash
  ./amneziawg-web.sh status
  ```
  > The `status` command does not require `sudo`.

---

## 🔄 Maintenance

All web panel lifecycle actions use the same script:

**Upgrade the web panel:**

```bash
sudo ./amneziawg-web.sh upgrade
```

**Uninstall the web panel (keeps config and data):**

```bash
sudo ./amneziawg-web.sh uninstall --force
```

**Uninstall and purge all data:**

```bash
sudo ./amneziawg-web.sh uninstall --purge-config --purge-data --force
```

> The script works standalone — it automatically downloads required files when run.

---

## ⚡ Non-Interactive Install

Skip all prompts and use sensible defaults:

```bash
sudo AUTO_INSTALL=y ./amneziawg-install.sh
```

Override specific defaults with environment variables:

| Variable | Default |
|----------|---------|
| `SERVER_PUB_IP` | Auto-detected |
| `SERVER_PUB_NIC` | Auto-detected |
| `SERVER_AWG_NIC` | `awg0` |
| `SERVER_AWG_IPV4` | `10.66.66.1` |
| `SERVER_AWG_IPV6` | `fd42:42:42::1` |
| `ENABLE_IPV6` | `y` if the host has IPv6, otherwise `n` |
| `SERVER_PORT` | Random (49152–65535) |
| `CLIENT_DNS_1` | `1.1.1.1` |
| `CLIENT_DNS_2` | `1.0.0.1` |
| `ALLOWED_IPS` | `0.0.0.0/0, ::/0` (IPv4 only when `ENABLE_IPV6=n`) |
| `CREATE_INITIAL_CLIENT` | `yes` in `AUTO_INSTALL`; prompted interactively |

Set `ENABLE_IPV6=n` for an IPv4-only deployment: the server interface, firewall
rules, and all generated client configs omit IPv6 (no IPv6 address, no `::/0`
route), which avoids route-setup errors on hosts where IPv6 is disabled.

Example:

```bash
sudo AUTO_INSTALL=y SERVER_PORT=51820 CLIENT_DNS_1=8.8.8.8 ./amneziawg-install.sh

# IPv4-only server
sudo AUTO_INSTALL=y ENABLE_IPV6=n ./amneziawg-install.sh
```

---

## 🤖 Non-Interactive Client Management

The install script also supports non-interactive flags for automation and scripting:

```bash
# Add a new client
sudo ./amneziawg-install.sh --add-client alice

# Remove a client
sudo ./amneziawg-install.sh --remove-client alice

# List all clients
sudo ./amneziawg-install.sh --list-clients
```

---

## 🔐 Optional AWG 3.0 / 3.1 Mode

> [!WARNING]
> **Incompatible with amneziawg-proxy:**
> Do **not** enable AWG 3.0 or AWG 3.1 if you are using `amneziawg-proxy`. Because AmneziaWG 3.0+ incorporates the S1–S4 padding values as key material for header protection, the proxy's padding transformations corrupt header decryption and break packet classification.
>
> If you require `amneziawg-proxy`, keep your interface in AWG 2.0 mode (the default). If an interface was already migrated to AWG 3.0 or 3.1, revert it to AWG 2.0 using `sudo ./amneziawg-install.sh --disable-awg3` (or via the web panel under **AWG protocol**) before setting up or running the proxy.

Fresh installs and parameter files created by earlier releases use AWG 2.0 by
default. Installing or upgrading this project never changes an existing
interface's protocol mode. Existing AWG 3.0 installations stay on 3.0 until
you explicitly enable AWG 3.1.

```bash
# Missing protocol state is reported as 2
sudo ./amneziawg-install.sh --protocol-status

# Probe userspace + running kernel support, then migrate the server and clients
sudo ./amneziawg-install.sh --enable-awg3

# Enable AWG 3.1 (AWG 3.0 plus RandomTrailers; DisableCookies stays off)
sudo ./amneziawg-install.sh --enable-awg31

# Atomically remove AWG 3.x-only fields and return every config to AWG 2.0
sudo ./amneziawg-install.sh --disable-awg3
```

AWG 3.0 header protection is interface-wide and cannot communicate with AWG
2.0 clients on the same interface. AWG 3.1 is AWG 3.0 plus `RandomTrailers`
(must match on every peer) and optional `DisableCookies` (server-sent Cookie
Reply / anti-DoS; default `off`). Enabling a mode creates or keeps one shared
header key, validates all generated configs, and updates the server plus every
recoverable client config as one transaction. If capability validation, file
replacement, service restart, or the process itself fails, the previous state
is restored. Redistribute every client config after a migration. The web panel
exposes the same confirmed operations under **AWG protocol**.

When `RandomTrailers` is on, upstream recommends identical `S1`–`S4` values to
reduce packet-type misdetection. The installer warns if they differ and does
not rewrite existing S-values.

**What this installer implements**

| Mode | Fields |
| --- | --- |
| AWG 2.0 | `Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4` |
| AWG 3.0 | AWG 2.0 plus `HeaderProtectionKey`, optional `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout` |
| AWG 3.1 | AWG 3.0 plus `RandomTrailers` and `DisableCookies` |

Clients and the server must run AWG 3.1-capable implementations (`amneziawg-tools`
plus the running kernel module, or an equivalent 3.1 userspace stack). The
installer does not trust package version strings; it probes by applying the
fields to a temporary interface and reading them back. `I1`–`I5` (CPS) are
intentionally not generated, persisted, or migrated. Upstream also defines
optional `MaxHandshakeAttempts`; this installer does not manage that field
(same as the existing AWG 3.0 mode). Externally added `I1`–`I5` or
`MaxHandshakeAttempts` lines are left in place during protocol rewrites.

---

## 🧪 Experimental: BoringTun Userspace Backend

> [!WARNING]
> **Experimental.** The kernel module stays the default and the recommended
> backend. BoringTun is chosen only by an explicit `AWG_BACKEND=boringtun` on a
> **fresh** install, and existing installations are never moved to it.

Instead of the AmneziaWG kernel module (built with DKMS), a server can run
[WireSock BoringTun](https://github.com/Wiresock-Foundation/wiresock-boringtun),
a userspace AmneziaWG implementation that serves the interface through a TUN
device. Nothing is compiled on the server: no Rust toolchain, no DKMS and no
kernel headers.

```bash
# Fresh install with the BoringTun backend
sudo AWG_BACKEND=boringtun AUTO_INSTALL=y ./amneziawg-install.sh

# Interactive install with the BoringTun backend
sudo AWG_BACKEND=boringtun ./amneziawg-install.sh
```

**Where it runs:** Debian 11+ and Ubuntu 22.04+ hosts (virtual machines or bare
metal) with systemd, on x86_64 or aarch64, with `/dev/net/tun` and the IPv6
socket family available. Containers and LXC are not supported. Other
architectures are refused before anything is changed.

**What it installs:**

- `amneziawg-tools` from the Amnezia PPA with `--no-install-recommends`, so the
  kernel module package (`amneziawg-dkms`) is not pulled in, plus `nftables`,
  `iptables` and `qrencode`. No `amneziawg`, DKMS, headers or `deb-src` sources.
- `boringtun-cli` from this repository's immutable public release
  [`boringtun-cli-0.7.1-g71d88784ad29-b1`](https://github.com/wiresock/amneziawg-install/releases/tag/boringtun-cli-0.7.1-g71d88784ad29-b1),
  built from WireSock BoringTun `71d88784ad29dc95871c105e26cc62f6acdd565b`. The
  installer downloads the archive for its architecture from that exact URL and
  checks it against SHA-256 values embedded in the script before extracting
  anything; then it checks the archive's layout, its `MANIFEST`, the binary's
  SHA-256 and `boringtun-cli --version`. No "latest" lookup and no GitHub API.
  The release notes describe how to verify its build provenance yourself.
- The binary into `/usr/local/lib/amneziawg-install/boringtun/`, and two
  generated helpers into `/usr/local/libexec/amneziawg-install/` that supervise
  the daemon inside the usual `awg-quick@<interface>` service.

Before any VPN configuration is written, a preflight starts a temporary
BoringTun instance with the chosen AWG 2.0 parameters and removes it again. If
the download, a check or the preflight fails, nothing is configured. If the
service does not start, the installer stops with BoringTun diagnostics; it
never falls back to the kernel module.

**Managing it:** everything else works as usual: clients, `--enable-awg3`,
`--enable-awg31`, `--disable-awg3` and uninstall. Use `systemctl` or this
script to start and stop the interface: a plain `awg-quick up awg0` does not
start BoringTun. A newer installer version never replaces an installed
BoringTun binary on its own: only `--upgrade-boringtun` does (see below). Exporting
`AWG_BACKEND` has no effect on an existing installation, whichever backend it
uses.

**Kernel module on the host:** if the AmneziaWG kernel module is loaded, the
install refuses and never unloads it. If the module is only installed (for
example `amneziawg-dkms` from an earlier kernel install), `awg-quick` would load
it instead of starting BoringTun, so the install asks before blocking it with
`/etc/modprobe.d/amneziawg-install-boringtun.conf`
(`install amneziawg /bin/false`); with `AUTO_INSTALL`, set
`AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y` to agree. Uninstalling removes that file.
Kernel module packages that the BoringTun install did not install are never
removed, and neither is `/etc/modules-load.d/amneziawg.conf`.

**Uninstall:** it removes only what it can prove is this installation's: a
UAPI socket that a process may still serve, or a helper script changed after
the install, is left in place and reported. If a step fails, or the service's
teardown did not finish (for example PostDown hooks that may have run only in
part), the configuration in `/etc/amnezia/amneziawg` is kept, so running the
installer again offers the uninstall again once the cause is fixed.

**Not with the standalone proxy:** BoringTun cannot run behind
`amneziawg-proxy`, because it always listens on every address. The install
refuses while the proxy (or its `proxy.toml`) is present, and the proxy
installer refuses a BoringTun host. Keep the kernel backend for proxy setups.

**Web panel:** a BoringTun host needs a web panel whose copy of this script
(`/usr/local/bin/amneziawg-install.sh`) is at least this version; the install
refuses while an older copy is installed.

### Upgrading and rolling back the BoringTun binary

```bash
# Move to the BoringTun release this installer version pins
sudo ./amneziawg-install.sh --upgrade-boringtun

# Go back to the release that was current before
sudo ./amneziawg-install.sh --rollback-boringtun
```

**Explicit only.** Running a newer `amneziawg-install.sh` never switches the binary, and
neither does anything else it does: clients, protocol changes, imitation changes and the menu
leave the installed release alone.

**What each command targets.**
- **Upgrade:** only the release pinned in the installer itself, never a "latest" lookup.
  Moving to a newer BoringTun means a newer installer with a reviewed pin. When the pin is
  already installed, the upgrade changes nothing.
- **Rollback:** only the release that was current before the last upgrade or rollback. It
  takes no release argument.

The store keeps at most two releases, `current` and `previous`, so two rollbacks in a row
toggle back and forth.

**What a switch does.**
1. The upgrade downloads and verifies the pinned release exactly as a fresh install does,
   beside the running one.
2. Before anything changes, the target binary is validated on temporary instances against this
   server as it is now:
   - the current AWG protocol mode;
   - the protocol imitation;
   - the server config and every client config.

   A rollback is refused, without changing anything, when the older binary does not accept
   today's settings (for example a protocol mode enabled after the upgrade).
3. `current` and `previous` are switched atomically, and an active service is restarted and
   checked: the right binary, its TUN device, UAPI, listen port, imitation and peers.
4. A stopped or failed service is switched but not started.
5. If the restart or the check fails, both links are restored and the previous binary is
   restarted and checked.

Params, client configs, the imitation and the listen port never change.

**Status.** `--backend-status` adds:
- `previous_release`, `rollback_available` and `upgrade_available`;
- `daemon_release`, the release the running daemon executes, which shows a service that still
  runs an old binary;
- `unmanaged_releases`: release directories neither link names, which are reported but never
  removed automatically.

**Builds.** A later build of the same BoringTun source commit (for example `-b2`) is stored
under its own name, so it can sit beside build 1. Hosts installed before this version keep
their store as it is.

### Built-in protocol imitation (BoringTun only)

A BoringTun server can shape the S1–S4 prefixes of the packets it sends as
`dns`, `quic`, `sip` or `stun`, and answer probes of that service on its listen
port. This uses BoringTun's own imitation; it needs no proxy. The default is
`none`, and the kernel backend has no imitation at all.

```bash
# Choose it on a fresh BoringTun install (an interactive install asks)
sudo AWG_BACKEND=boringtun AWG_BORINGTUN_IMITATE_PROTOCOL=dns \
  AWG_BORINGTUN_IMITATE_DOMAIN=example.com AUTO_INSTALL=y ./amneziawg-install.sh

# Change it later: none, dns, quic, sip or stun, and a hostname for dns, quic or sip
sudo ./amneziawg-install.sh --set-boringtun-imitation quic cdn.example.org
sudo ./amneziawg-install.sh --set-boringtun-imitation none

# Show the backend, the imitation and the running daemon (key=value, no secrets)
sudo ./amneziawg-install.sh --backend-status
```

The management menu of a BoringTun host shows the imitation and offers
**7) Change BoringTun protocol imitation**. The hostname is optional: without
one, BoringTun chooses its own. It must be a plain host name of letters,
digits, hyphens and dots.

A change is one transaction under the same lock as client changes. The new
settings are validated on a temporary BoringTun instance. The running service
is then restarted and checked: the verified daemon, its TUN link, its UAPI, the
same listen port, and the new imitation on its command line. If anything
fails, the previous files are restored exactly and the service is restarted
with the previous imitation. A stopped or failed service is only updated, not
started. Imitation is a server setting: **client configs do not change**, and it
is kept when you switch between AWG 2.0, 3.0 and 3.1.

What to expect:

- **Server side only.** Standard AmneziaWG clients keep sending plain
  AmneziaWG. Only the server's packets are shaped, unless the client imitates
  too (for example WireSock Secure Connect).
- **Probe replies.** DNS queries get `SERVFAIL`. STUN Binding Requests get a
  Binding Success about 2.6× their size, so the reply can be reflected at a
  spoofed source. QUIC Initials of 1200 bytes or more get Version Negotiation,
  but only when they offer a version real servers don't (QUIC v1 and v2 get no
  reply). SIP gets no reply. All replies share a 16 KiB/s budget, and loopback,
  link-local, multicast and broadcast sources are never answered.
- **The port stays the same.** The installer never moves it, because a new port
  needs new client configs. Imitation looks most plausible on the protocol's
  usual port.
- **AWG 3.0 / 3.1.** Header protection takes its nonce from the first 12 bytes
  of each S prefix, and imitation shapes those bytes:
  - `dns` leaves 16 random bits, so header masks repeat within a few hundred
    datagrams.
  - `stun` leaves 32 random bits.
  - `quic` keeps a random nonce.

  Payload encryption is unaffected. BoringTun refuses `sip` with header
  protection while any of S1–S4 is 31 bytes or more, and so does the installer,
  both when you choose `sip` and when you enable AWG 3.x under `sip`. Enabling an
  imitation under AWG 3.x from the menu asks for confirmation.
- **S sizes.** A short S prefix is only partly shaped. The thresholds are:
  - `dns`: 32 bytes, or the hostname's length + 33 for a query that names it;
  - `stun`: 20 bytes;
  - `sip`: 31 bytes;
  - `quic`: 1 byte.

  The installer warns about shorter prefixes but never changes S sizes.

---

## 📦 Requirements

Supported Linux distributions:

- Debian ≥ 11
- Ubuntu ≥ 22.04 (CI-tested on 22.04, 24.04, and 26.04)

### Ubuntu 26.04 PPA compatibility

When the Amnezia PPA does not publish a `resolute` suite, the Ubuntu 26.04
(Resolute) installer uses the PPA's signed Ubuntu 24.04 (`noble`) suite as a
temporary, narrowly scoped fallback:

- The native `resolute` suite is checked first on every install or management
  run. Once it is published, the installer automatically stops using the
  fallback.
- Network failures and unexpected HTTP responses do **not** trigger the
  fallback. Both native PPA metadata endpoints must explicitly report that the
  suite is absent.
- Normal APT signature verification remains enabled. The installer does not
  add `trusted=yes` or allow insecure repositories.
- The fallback is allowed on `amd64`, `arm64`, `armhf`, `ppc64el`, `riscv64`,
  and `s390x`, where the required package indexes are published. It is rejected
  on `i386`, which lacks `amneziawg-tools`.
- Runtime module loading is continuously tested on the GitHub-hosted Ubuntu
  26.04 `amd64` image. Other listed architectures have package-index coverage
  but are not runtime-tested by this repository's CI.

Uninstalling AmneziaWG removes only source entries that exactly match the
Amnezia PPA, including a fallback entry left by an interrupted older install.
Unrelated APT sources in the same file are preserved.

Temporarily disabled:

- Fedora (RPM-based)
- AlmaLinux (RPM-based)
- Rocky Linux (RPM-based)

Reason: verified AmneziaWG 2.0 packages are not currently available for these RPM-based distributions. Please watch this repository's releases and README for support status updates.

Source builds require approximately 2 GiB of free space for `amneziawg-web`
and 1 GiB for `amneziawg-proxy`. Their install and upgrade scripts inspect the
Cargo target filesystem, free inodes, CPU count, and available memory before
building. On constrained hosts they use one Cargo job and, when the source
filesystem is too small, place build artifacts on a suitable disk-backed
filesystem automatically.

To select a specific build filesystem, create a writable directory on an
executable mount and pass it explicitly:

```bash
sudo env AMNEZIAWG_BUILD_ROOT=/path/with/free-space ./amneziawg-web.sh upgrade
sudo env AMNEZIAWG_BUILD_ROOT=/path/with/free-space ./amneziawg-proxy.sh upgrade
```

An explicit `CARGO_TARGET_DIR` is also supported, but is treated as strict: the
operation fails with a diagnostic if that target does not meet the build
requirements.

---

<details>
<summary>⚙️ AmneziaWG 2.0 Parameters</summary>

### Obfuscation Parameters

AmneziaWG 2.0 adds S3/S4 and H1–H4 range parameters for enhanced traffic obfuscation. The installer generates all values automatically.

| Parameter | Range | Constraint |
|-----------|-------|------------|
| Jc | 1–128 | — |
| Jmin | 1–1280 | Jmin ≤ Jmax |
| Jmax | 1–1280 | Jmin ≤ Jmax |
| S1 | 15–150 | S1 + 56 ≠ S2 and S2 + 56 ≠ S1 |
| S2 | 15–150 | S1 + 56 ≠ S2 and S2 + 56 ≠ S1 |
| S3 | 15–150 | S3 + 56 ≠ S4 and S4 + 56 ≠ S3 |
| S4 | 15–150 | S3 + 56 ≠ S4 and S4 + 56 ≠ S3 |
| H1–H4 | 5–2147483647 | Ranges must not overlap |

H parameters accept a range (`min-max`) or a single value.

</details>

<details>
<summary>🔁 Migration from Pre-2.0</summary>

Run the installer on an existing pre-2.0 installation. It detects the need for migration and prompts before proceeding.

**Important:** All existing client configs become incompatible after migration. Regenerate them using option 1 (Add a new user) in the management menu.

Migration steps:
1. Creates `.bak` backup files before making any changes.
2. Generates new S3/S4 values with bidirectional constraint validation.
3. Converts single H values to range format (or regenerates if overlapping).
4. Updates server config and params file atomically.
5. Renames outdated client configs with `.old` suffix.
6. Reloads the running VPN service (if active).

Backups are restored automatically if migration fails.

</details>

<details>
<summary>🔒 Security Notes</summary>

- **Shell injection prevention** — params file values are safely shell-quoted.
- **Atomic writes** — config updates use a temp file + rename to prevent corruption on interruption.
- **Filesystem boundary protection** — client config search uses `-xdev` to stay within the config filesystem.

</details>

---

## Credits

Fork of [RomikB/amneziawg-install](https://github.com/RomikB/amneziawg-install).

## Disclaimer

This is an independent, community-maintained project. It is **not affiliated
with, endorsed by, sponsored by, or otherwise associated with** Amnezia
([amnezia.org](https://amnezia.org/)), the Amnezia VPN application, or the
Amnezia Free VPN service. The project merely builds on the open-source
**AmneziaWG** protocol and tooling. "Amnezia", "AmneziaWG", and any related
names, logos, and trademarks are the property of their respective owners and are
used here only for identification.

Likewise, this installer is provided as-is with no warranty (see License); you
are responsible for how you deploy and use it.

## License

MIT License
