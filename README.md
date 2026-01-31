# AmneziaWG installer

**This project is a bash script that aims to setup a [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) VPN on a Linux server, as easily as possible!**

## Requirements

Supported distributions:

- AlmaLinux >= 9
- CentOS >= 9
- Debian >= 11
- Fedora >= 39
- Rocky Linux >= 9
- Ubuntu >= 20.04

2GB of free space is required for temporary files.

## Usage

Before installation it is strictly recommended to upgrade your system to the latest available version and perform the reboot afterwards.

Use curl or wget to download the script:
```bash
curl -O https://raw.githubusercontent.com/wiresock/amneziawg-install/main/amneziawg-install.sh
```
```bash
wget https://raw.githubusercontent.com/wiresock/amneziawg-install/main/amneziawg-install.sh
```

Set permissions:
```bash
chmod +x amneziawg-install.sh
```

And execute:
```bash
./amneziawg-install.sh
```

Answer the questions asked by the script and it will take care of the rest.

It will install AmneziaWG (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.

Run the script again to add or remove clients!

## AmneziaWG 2.0 Features

This installer supports AmneziaWG 2.0 parameters:

- **S3/S4**: Additional obfuscation parameters with bidirectional constraint validation. The protocol requires both `S3 + 56 != S4` AND `S4 + 56 != S3` to avoid the 56-byte WireGuard handshake initiation message size in both directions.
- **H1-H4 Ranges**: Header randomization using non-overlapping ranges for enhanced traffic obfuscation. Each H parameter accepts a range in `min-max` format (e.g., `100-200`) or a single value.

### Parameter Constraints

| Parameter | Range | Constraint |
|-----------|-------|------------|
| Jc | 1-128 | None |
| Jmin | 1-1280 | Jmin <= Jmax |
| Jmax | 1-1280 | Jmin <= Jmax |
| S1 | 15-150 | S1 + 56 != S2 AND S2 + 56 != S1 |
| S2 | 15-150 | S1 + 56 != S2 AND S2 + 56 != S1 |
| S3 | 15-150 | S3 + 56 != S4 AND S4 + 56 != S3 |
| S4 | 15-150 | S3 + 56 != S4 AND S4 + 56 != S3 |
| H1-H4 | 5-2147483647 | Ranges must not overlap |

### Migration from Pre-2.0

When running the script on an existing pre-2.0 installation, it will automatically detect the need for migration and prompt for confirmation before proceeding.

**IMPORTANT:** After migration, all existing client configurations will be incompatible and must be regenerated using option 1 (Add a new user) in the management menu.

The migration process:
1. Creates backup files (`.bak`) before making changes
2. Generates new S3/S4 values satisfying bidirectional constraints
3. Converts single H values to range format or regenerates if overlapping
4. Updates server configuration and params file atomically
5. Renames outdated client configs with `.old` suffix
6. Reloads the running VPN service (if active)

If migration fails, backups are automatically restored.

## Security Features

- **Shell Injection Prevention**: String values in the params file are safely quoted to prevent shell injection when sourced
- **Atomic File Writes**: Configuration updates use temporary files with atomic rename to prevent corruption on interruption
- **Filesystem Boundary Protection**: Client config search uses `-xdev` to prevent crossing filesystem boundaries

## License

MIT License
