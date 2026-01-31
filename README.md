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

- **S3/S4**: Additional obfuscation parameters (with constraint S3 + 56 != S4)
- **H1-H4 Ranges**: Header randomization using non-overlapping ranges for enhanced traffic obfuscation

### Migration from Pre-2.0

When running the script on an existing pre-2.0 installation, it will automatically migrate the configuration to 2.0 format. **Note:** After migration, all existing client configurations must be regenerated.

## License

MIT License
