# AmneziaWG Installer

Set up an [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) obfuscated VPN on any supported Linux server in under 2 minutes.

```
VPN install → (optional) Web panel → Manage clients
```

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

---

## 🤔 Choose Your Setup

| Goal | What to run |
|------|-------------|
| VPN server only | `amneziawg-install.sh` |
| VPN + web panel | `amneziawg-install.sh` then `amneziawg-web.sh install` |
| Advanced / development | Clone the repo, then run both scripts from the checkout |

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

- AlmaLinux ≥ 9
- Debian ≥ 11
- Rocky Linux ≥ 9
- Ubuntu ≥ 22.04

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
