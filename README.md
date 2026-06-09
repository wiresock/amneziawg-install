# AmneziaWG Installer

Set up an [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) obfuscated VPN on any supported Linux server in under 2 minutes — with an optional web panel and an optional traffic-obfuscation proxy.

```
VPN install → (optional) Web panel → (optional) Obfuscation proxy → Manage clients
```

---

## 📖 Background

This project started as a fork of [RomikB/amneziawg-install](https://github.com/RomikB/amneziawg-install). I needed a reliable way to stand up **AmneziaWG 2.0** servers for testing [WireSock Secure Connect](https://www.wiresock.net/), and the upstream script predated the 2.0 release — so I took it and extended it to generate and manage the new 2.0 obfuscation parameters (S3/S4 padding and the H1–H4 header ranges).

Once the installer was solid, it was hard to stop:

1. **`amneziawg-install.sh`** — the original script, extended for AmneziaWG 2.0 (S3/S4, H1–H4, migration from pre-2.0 installs).
2. **`amneziawg-web.sh`** — a web panel for managing clients without touching the CLI.
3. **`amneziawg-proxy.sh`** — a UDP obfuscation proxy that takes traffic camouflage to the next level: it wraps AmneziaWG so the datagrams on the wire look like a legitimate QUIC, DNS, STUN, or SIP service to Deep Packet Inspection (DPI).

> **⚠️ amneziawg-proxy is most powerful with WireSock Secure Connect 3.5+.**
> The proxy's full protocol-imitation feature set — coordinated client/server cover traffic, junk-packet shaping, and per-protocol padding — is only fully unleashed when paired with [WireSock Secure Connect](https://www.wiresock.net/) **3.5 or later** on the client side. Standard AmneziaWG clients still connect through the proxy and benefit from the server-side obfuscation, but the bidirectional imitation requires the WireSock client.

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

> Makes the VPN traffic look like QUIC/DNS/STUN/SIP to DPI. See
> **[Traffic Obfuscation Proxy](#-traffic-obfuscation-proxy-amneziawg-proxy)**.

✅ **After installation:**
- VPN server is running
- A client config file is generated at `~/awg0-client-<name>.conf`
- (If installed) Web panel listens on `127.0.0.1:8080` by default — access it on the server at `http://127.0.0.1:8080`, or change `AWG_WEB_LISTEN` / use a reverse proxy for remote access

---

## 🧠 How It Works

- **`amneziawg-install.sh`** — **required.** Installs the VPN server, generates obfuscation parameters, and creates client configs.
- **`amneziawg-web.sh`** — **optional.** Unified script for:
  - `install` — install the web panel
  - `upgrade` — upgrade the binary
  - `uninstall` — remove the panel
  - `status` — show installation status
- **`amneziawg-proxy.sh`** — **optional.** Installs and manages the UDP obfuscation proxy that fronts AmneziaWG and makes the traffic look like QUIC, DNS, STUN, or SIP. See **[Traffic Obfuscation Proxy](#-traffic-obfuscation-proxy-amneziawg-proxy)** below.

---

## 🤔 Choose Your Setup

| Goal | What to run |
|------|-------------|
| VPN server only | `amneziawg-install.sh` |
| VPN + web panel | `amneziawg-install.sh` then `amneziawg-web.sh install` |
| VPN + DPI-resistant obfuscation | `amneziawg-install.sh` then `amneziawg-proxy.sh` |
| Everything | `amneziawg-install.sh`, then `amneziawg-web.sh install`, then `amneziawg-proxy.sh` |
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
2. **Padding transformation.** Every outgoing AmneziaWG packet already carries a
   random S1–S4 padding prefix. The proxy overwrites that prefix with
   protocol-conformant bytes (a QUIC short header, a DNS/STUN header, SIP header
   text) so the *leading bytes and byte-distribution* of each datagram match the
   imitated protocol — while the encrypted WireGuard payload that follows is
   left untouched.

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
| `SERVER_PORT` | Random (49152–65535) |
| `CLIENT_DNS_1` | `1.1.1.1` |
| `CLIENT_DNS_2` | `1.0.0.1` |
| `ALLOWED_IPS` | `0.0.0.0/0,::/0` |

Example:

```bash
sudo AUTO_INSTALL=y SERVER_PORT=51820 CLIENT_DNS_1=8.8.8.8 ./amneziawg-install.sh
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

## 📦 Requirements

Supported Linux distributions:

- Debian ≥ 11
- Ubuntu ≥ 22.04

Temporarily disabled:

- Fedora (RPM-based)
- AlmaLinux (RPM-based)
- Rocky Linux (RPM-based)

Reason: verified AmneziaWG 2.0 packages are not currently available for these RPM-based distributions. Please watch this repository's releases and README for support status updates.

2 GB of free space required for temporary build files.

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

## License

MIT License
