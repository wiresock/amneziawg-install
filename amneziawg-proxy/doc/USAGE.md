# amneziawg-proxy — Usage Guide

## Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
   - [Automated installer (recommended)](#automated-installer-recommended)
   - [Manual build & install](#manual-build--install)
3. [Configuration](#configuration)
   - [proxy.toml reference](#proxytoml-reference)
   - [AWG config integration](#awg-config-integration)
   - [Protocol modes](#protocol-modes)
   - [Advanced options](#advanced-options)
4. [Running the proxy](#running-the-proxy)
   - [As a systemd service](#as-a-systemd-service)
   - [Directly from the command line](#directly-from-the-command-line)
5. [Logging](#logging)
6. [Uninstallation](#uninstallation)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Linux host with **systemd** (Debian/Ubuntu/CentOS/Fedora/Arch)
- **AmneziaWG** already installed and a working `awg0` interface
- **Rust toolchain ≥ 1.75** (only needed for a source build; the installer
  can install it automatically via `rustup`)

---

## Installation

### Automated installer (recommended)

The installer handles everything: detecting the AWG interface, building the
binary, writing the config, rebinding AWG to loopback, and enabling the
systemd service.

#### Interactive (guided prompts)

```bash
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-install.sh
```

The script will:
1. Detect the AWG interface and its current listen port.
2. Prompt for the public-facing port, protocol to imitate, and optional
   features.
3. Build the proxy binary (or install Rust automatically if `--install-rust`
   is given).
4. Reconfigure AWG to listen on `127.0.0.1:<backend-port>` (loopback only).
5. Write `/etc/amneziawg-proxy/proxy.toml`.
6. Install and start the `amneziawg-proxy` systemd service.

#### Non-interactive (CI / scripted deployment)

```bash
# QUIC imitation, port 51820 public → loopback :51821
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-install.sh \
  --non-interactive \
  --listen-port 51820 \
  --protocol quic

# DNS forwarding mode with a custom upstream resolver
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-install.sh \
  --non-interactive \
  --listen-port 51820 \
  --protocol dns \
  --dns-forward \
  --dns-upstream 1.1.1.1:53

# SIP imitation with stateful QUIC handshake disabled
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-install.sh \
  --non-interactive \
  --listen-port 51820 \
  --protocol sip
```

#### Installer options reference

| Option | Default | Description |
|--------|---------|-------------|
| `--source-dir DIR` | auto-detected | Rust crate directory to build from. |
| `--binary-src PATH` | — | Use a pre-built binary instead of building. Mutually exclusive with `--source-dir`. |
| `--install-rust` | off | Install the Rust toolchain via `rustup` if `cargo` is not found. |
| `--listen-host HOST` | `0.0.0.0` | Public-facing bind address. |
| `--listen-port PORT` | auto from AWG | Public-facing UDP port. |
| `--backend-host HOST` | `127.0.0.1` | Loopback host for the AWG backend. |
| `--backend-port PORT` | `51821` | Port AWG is rebound to after install. |
| `--protocol PROTO` | `quic` | Protocol to imitate: `quic`, `dns`, `sip`, or `auto`. |
| `--session-ttl SECS` | `300` | Idle session timeout in seconds. |
| `--rate-limit N` | `5` | Max probe responses per client per second. |
| `--dns-forward` | off | Enable DNS query forwarding to an upstream resolver. |
| `--dns-upstream ADDR` | `1.1.1.1:53` | Upstream DNS `host:port`. Implies `--dns-forward`. |
| `--quic-handshake` | off | Enable stateful QUIC TLS handshake continuation. |
| `--quic-domain DOMAIN` | `cloudflare.com` | TLS SNI domain for QUIC handshake responses. |
| `--install-dir DIR` | `/usr/local/bin` | Directory for the installed binary. |
| `--config-file FILE` | `/etc/amneziawg-proxy/proxy.toml` | Path for the generated config. |
| `--data-dir DIR` | `/var/lib/amneziawg-proxy` | Service working directory. |
| `--awg-dir DIR` | `/etc/amnezia/amneziawg` | AmneziaWG config directory. |
| `--no-enable` | — | Do not enable the service at boot. |
| `--no-start` | — | Do not start the service immediately after install. |
| `--force` | — | Overwrite existing config without prompting. |
| `--non-interactive` | — | Run without prompts; fail if required values are missing. |

---

### Manual build & install

```bash
# 1. Build release binary
cd amneziawg-proxy
cargo build --release

# 2. Install binary
sudo install -m 755 target/release/amneziawg-proxy /usr/local/bin/

# 3. Create config directory
sudo mkdir -p /etc/amneziawg-proxy

# 4. Write proxy.toml (see Configuration section)
sudo tee /etc/amneziawg-proxy/proxy.toml > /dev/null <<'EOF'
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
imitate_protocol = "quic"
awg_config = "/etc/amnezia/amneziawg/awg0.conf"
EOF

# 5. Rebind AWG to loopback (edit /etc/amnezia/amneziawg/awg0.conf)
#    Change: ListenPort = 51820
#    To:     ListenPort = 51821
#            ListenAddr = 127.0.0.1
# Then reload: sudo wg syncconf awg0 <(sudo wg-quick strip awg0)

# 6. Install systemd service
sudo install -m 644 \
  amneziawg-proxy/packaging/amneziawg-proxy.service \
  /etc/systemd/system/amneziawg-proxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now amneziawg-proxy
```

---

## Configuration

### proxy.toml reference

The proxy reads its configuration from a TOML file. All keys and their
defaults are shown below.

```toml
# ── Required ──────────────────────────────────────────────────────────────────

# Address and port the proxy listens on for incoming VPN/DPI traffic.
listen = "0.0.0.0:51820"

# Address and port of the AmneziaWG backend (must be loopback or a trusted
# interface — not exposed to the internet).
backend = "127.0.0.1:51821"

# ── Protocol imitation ────────────────────────────────────────────────────────

# Which protocol to imitate.
#   "quic"  — High-entropy QUIC 1-RTT padding; responds to QUIC Initial probes
#             with a valid Version Negotiation packet (RFC 9000).
#   "dns"   — DNS response header padding; responds to DNS queries with a valid
#             SERVFAIL reply (RFC 1035).
#   "sip"   — SIP header-style padding; responds to SIP requests with a valid
#             100 Trying reply (RFC 3261).
#   "auto"  — Detect the protocol from each incoming packet; use the detected
#             protocol for that packet. No padding transformation is applied in
#             auto mode because no single protocol can be assumed.
imitate_protocol = "quic"

# ── Session management ────────────────────────────────────────────────────────

# How long (seconds) a client session can remain idle before it is cleaned up.
session_ttl_secs = 300

# How often (seconds) the cleanup task runs to reap expired sessions.
cleanup_interval_secs = 60

# Maximum number of concurrent client sessions.
# Both the session table and the metrics store enforce this limit.
max_sessions = 10000

# ── Rate limiting ─────────────────────────────────────────────────────────────

# Maximum number of probe responses sent to a single client per second.
# Uses a token-bucket algorithm. Packets exceeding the limit are still
# forwarded to the backend but no probe response is sent.
rate_limit_per_sec = 5

# ── I/O tuning ────────────────────────────────────────────────────────────────

# UDP receive buffer size in bytes.
buffer_size = 65535

# ── AWG integration ───────────────────────────────────────────────────────────

# Path to the AmneziaWG interface config file (INI-style).
# When set, the proxy reads S1–S4 and H1–H4 to enable per-type padding
# transformation on outgoing packets. Without this key, packets are forwarded
# verbatim (no padding transform).
awg_config = "/etc/amnezia/amneziawg/awg0.conf"

# ── DNS forwarding (optional) ─────────────────────────────────────────────────

# Forward detected DNS queries to a real upstream resolver before (or instead
# of) generating the SERVFAIL probe response.
# Only valid when imitate_protocol = "dns".
dns_forward_enabled = false

# Upstream DNS resolver to forward queries to when dns_forward_enabled = true.
dns_upstream = "127.0.0.1:53"

# Timeout (milliseconds) waiting for a response from the upstream DNS resolver.
dns_upstream_timeout_ms = 1500

# ── Stateful QUIC handshake (optional) ───────────────────────────────────────

# Enable the stateful QUIC TLS handshake responder (quinn-proto based).
# When enabled, the proxy completes a real QUIC handshake with probing clients
# instead of sending a simple Version Negotiation packet.
# Only valid when imitate_protocol = "quic".
quic_handshake_enabled = false

# TLS SNI domain used to generate the self-signed certificate for the QUIC
# handshake. Should match what a legitimate server at this address would use.
quic_certificate_domain = "localhost"
```

### AWG config integration

The proxy reads a subset of the `[Interface]` section from the AmneziaWG
config file. Only the `[Interface]` section is parsed; `[Peer]` sections and
unknown keys (e.g. `Address`, `PrivateKey`, `DNS`) are silently ignored.

```ini
[Interface]
# Junk packet obfuscation (not used by the proxy, but present in AWG configs)
Jc   = 5
Jmin = 50
Jmax = 1000

# Padding sizes (bytes prepended before the obfuscated header)
S1 = 42    # HandshakeInit prefix
S2 = 88    # HandshakeResponse prefix
S3 = 33    # CookieReply prefix
S4 = 120   # TransportData prefix

# Header ranges (little-endian u32, validated non-overlapping)
H1 = 5-100000004
H2 = 100000005-200000004
H3 = 200000005-300000004
H4 = 300000005-400000004
```

If `awg_config` is not set in `proxy.toml`, no padding transformation is
applied and AWG packets are forwarded unmodified.

### Protocol modes

| Mode | Padding transform | Probe response | Use case |
|------|-------------------|----------------|----------|
| `quic` | High-entropy PRNG bytes (QUIC short-header format) | QUIC Version Negotiation (RFC 9000 §17.2.1) | Ports 443/UDP; QUIC-heavy networks |
| `dns` | DNS response header + zero fill | DNS SERVFAIL (RFC 1035) | Port 53/UDP; DNS-filtered networks |
| `sip` | Cycling SIP header text | SIP 100 Trying (RFC 3261) | Port 5060/UDP; VoIP infrastructure |
| `auto` | None | Matches detected protocol | Mixed-probe environments |

**Choosing a mode:**

- Use `quic` when the public port is 443 or when the network primarily scans
  for QUIC/HTTP3 traffic. This is the safest default as QUIC uses high-entropy
  encrypted payloads that are hard to distinguish from AWG traffic.
- Use `dns` when the VPN must run on port 53 to bypass DNS-based firewalls.
  Pair with `dns_forward_enabled = true` to handle legitimate DNS queries.
- Use `sip` for VoIP-permissive networks or when a SIP service already runs
  on the same host.
- Use `auto` when probe type varies and no single protocol is dominant.
  Note: no padding transformation is applied in auto mode.

### Advanced options

#### DNS query forwarding

When `imitate_protocol = "dns"` and `dns_forward_enabled = true`, the proxy
forwards detected DNS queries to the upstream resolver and returns the real
response to the client. This allows the VPN port to also serve as a functional
DNS resolver:

```toml
imitate_protocol     = "dns"
dns_forward_enabled  = true
dns_upstream         = "1.1.1.1:53"
dns_upstream_timeout_ms = 1500
```

#### Stateful QUIC handshake

When `quic_handshake_enabled = true`, the proxy uses `quinn-proto` as a
full QUIC/TLS state machine to complete a real TLS 1.3 handshake with probing
clients. A self-signed certificate is generated on start-up for
`quic_certificate_domain`. This makes the port indistinguishable from a real
QUIC server to active probers that complete a full handshake:

```toml
imitate_protocol          = "quic"
quic_handshake_enabled    = true
quic_certificate_domain   = "cloudflare.com"
```

> **Note:** The stateful handshake responder caps concurrent connections at
> 2,048 to limit memory usage under adversarial traffic.

---

## Running the proxy

### As a systemd service

```bash
# Start
sudo systemctl start amneziawg-proxy

# Stop
sudo systemctl stop amneziawg-proxy

# Restart (e.g. after editing proxy.toml)
sudo systemctl restart amneziawg-proxy

# Enable at boot
sudo systemctl enable amneziawg-proxy

# Disable at boot
sudo systemctl disable amneziawg-proxy

# Check status
sudo systemctl status amneziawg-proxy
```

### Directly from the command line

```bash
# Run with the default config file (proxy.toml in the current directory)
amneziawg-proxy

# Run with an explicit config file path
amneziawg-proxy /etc/amneziawg-proxy/proxy.toml

# Run with debug logging
RUST_LOG=amneziawg_proxy=debug amneziawg-proxy /etc/amneziawg-proxy/proxy.toml
```

The proxy binds to the configured listen address, starts the session cleanup
task, and then handles packets until it receives `SIGINT` or `SIGTERM`, at
which point it shuts down gracefully.

---

## Logging

Log output is controlled by the `RUST_LOG` environment variable (standard
`tracing-subscriber` env-filter format).

| Level | Output |
|-------|--------|
| `error` | Fatal errors only |
| `warn` | Non-fatal issues (session limit, rate limit, backend errors) |
| `info` | Start/stop, config loaded, session events *(default)* |
| `debug` | Per-packet byte counts, session create/remove |
| `trace` | Very verbose — internal state transitions |

**Examples:**

```bash
# Default (info level)
RUST_LOG=amneziawg_proxy=info

# Debug for the proxy module only
RUST_LOG=amneziawg_proxy=debug

# Debug everything (very verbose)
RUST_LOG=debug

# Warnings and errors only
RUST_LOG=amneziawg_proxy=warn
```

In the systemd unit the log level is set via the `Environment=` directive in
`/etc/systemd/system/amneziawg-proxy.service`:

```ini
Environment=RUST_LOG=amneziawg_proxy=info
```

After changing it, reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart amneziawg-proxy
```

---

## Uninstallation

```bash
# Interactive — preserves config and data by default
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh

# Non-interactive, safe defaults (removes binary and service, keeps config)
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh --force

# Full purge — removes config, data directory, and optionally restores AWG port
sudo ./amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh \
  --purge-config \
  --purge-data \
  --restore-awg \
  --force
```

| Flag | Effect |
|------|--------|
| `--purge-config` | Delete `/etc/amneziawg-proxy/` (proxy.toml and directory). |
| `--purge-data` | Delete the service working directory (`/var/lib/amneziawg-proxy`). |
| `--restore-awg` | Restore AWG listen port from the backup stored in the proxy config. |
| `--force` | Skip confirmation prompts. |

The uninstaller always stops and disables the service and removes the binary
and systemd unit file, regardless of purge flags.

---

## Troubleshooting

### Proxy fails to start: `address already in use`

Another process (or AWG itself) is already listening on the proxy's configured
`listen` port. Check:

```bash
sudo ss -ulnp | grep 51820
```

If AWG is still bound to the public port, ensure its `ListenAddr = 127.0.0.1`
and `ListenPort = 51821` are set in `/etc/amnezia/amneziawg/awg0.conf` and
reload it with `sudo wg syncconf awg0 <(sudo wg-quick strip awg0)`.

### Clients can connect but get no traffic

1. Verify the proxy's `backend` address matches AWG's actual listen address:
   ```bash
   sudo wg show awg0
   ```
2. Check the proxy log for session errors:
   ```bash
   sudo journalctl -u amneziawg-proxy -n 50
   ```
3. Ensure no firewall rule is blocking the loopback path:
   ```bash
   sudo iptables -L -n | grep 51821
   ```

### AWG packets are not being transformed

The padding transform requires the `awg_config` key in `proxy.toml` to point
to a valid AWG config containing S1–S4 and H1–H4 parameters. If the key is
absent or the file is unreadable, the proxy logs a warning and forwards
packets verbatim. Check:

```bash
sudo journalctl -u amneziawg-proxy | grep -i "awg\|config\|padding"
```

### Probe responses are not being sent

If DPI probes are arriving but no response is generated:

1. Check whether the rate limiter is throttling responses — increase
   `rate_limit_per_sec` in `proxy.toml` for testing.
2. Verify `imitate_protocol` matches the probe type (use `"auto"` to detect
   automatically).
3. Raise the log level to `debug` to see per-packet classification output.

### Session limit reached

If the log shows `session limit reached`, increase `max_sessions` in
`proxy.toml`. The default is 10,000; each session uses roughly one UDP socket
and one async task. Also check that the cleanup interval (`cleanup_interval_secs`)
and TTL (`session_ttl_secs`) are not too large, causing idle sessions to
accumulate.

### `permission denied` binding to port 443 or 53

Ports below 1024 require elevated privileges. Either run as root (the default
systemd unit does this) or grant the capability:

```bash
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/amneziawg-proxy
```

Then update the `User=` in the service unit to a non-root user if desired.
