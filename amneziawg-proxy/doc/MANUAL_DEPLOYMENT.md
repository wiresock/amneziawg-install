# amneziawg-proxy - Manual Deployment Guide

This guide is for deployments that do not fit the automated installer. Use it
when AmneziaWG is managed by another tool, runs in Docker, runs on a different
network namespace, or when you want to own the systemd, firewall, and config
layout yourself.

The proxy is deliberately simple:

- it listens on a public UDP address (`listen`);
- it forwards valid AmneziaWG traffic to a private backend UDP address
  (`backend`);
- it can read the AWG server config (`awg_config`) to apply the same padding
  transformation that AmneziaWG expects;
- it can write a local session status file (`status_file`) for `amneziawg-web`.

The proxy does not need to manage the AWG interface. In a manual deployment,
you only need to make sure the proxy can reach the AWG UDP backend and that
clients connect to the proxy's public UDP port.

## Choose a Topology

### Same host, AWG on loopback

This is the simplest and safest layout.

```text
client -> server public IP:51820/udp -> amneziawg-proxy
amneziawg-proxy -> 127.0.0.1:51821/udp -> AWG interface
```

Configure AWG to listen only on loopback and a backend port:

```ini
[Interface]
ListenAddr = 127.0.0.1
ListenPort = 51821
```

Then configure the proxy:

```toml
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
imitate_protocol = "quic"
awg_config = "/etc/amnezia/amneziawg/awg0.conf"
status_file = "/var/lib/amneziawg-proxy/sessions.json"
status_interval_secs = 5
```

Only the proxy port should be reachable from the internet.

### AWG in Docker, proxy on the host

This layout is useful when an existing container owns the AWG interface.
Publish the container's AWG UDP port to a host loopback-only backend port:

```bash
docker run \
  --name awg \
  --cap-add NET_ADMIN \
  --cap-add SYS_MODULE \
  -p 127.0.0.1:51821:51820/udp \
  your-awg-image
```

Then set:

```toml
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
imitate_protocol = "quic"
```

If the AWG config is available on the host, mount or copy it read-only and set
`awg_config`:

```toml
awg_config = "/etc/amnezia/amneziawg/awg0.conf"
```

If the host cannot read the AWG config, omit `awg_config`. The proxy will still
forward traffic, but it will not load AWG obfuscation parameters, classify AWG
packet types, or apply padding transformation. Use this only if your AWG setup
does not require that transformation or if you have verified clients still
connect correctly.

### Proxy and AWG in Docker

Put both containers on the same Docker network. Because `backend` currently
expects an IP socket address, not a DNS name, use a static container IP or
publish AWG to a loopback port on the Docker host.

Example with static bridge-network IPs:

```yaml
services:
  awg:
    image: your-awg-image
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    networks:
      awg_net:
        ipv4_address: 172.30.0.10
    expose:
      - "51820/udp"

  proxy:
    image: your-amneziawg-proxy-image
    command: ["/usr/local/bin/amneziawg-proxy", "/etc/amneziawg-proxy/proxy.toml"]
    ports:
      - "51820:51820/udp"
    volumes:
      - ./proxy.toml:/etc/amneziawg-proxy/proxy.toml:ro
      - ./sessions:/var/lib/amneziawg-proxy
      # Optional, only if available:
      - ./awg0.conf:/etc/amnezia/amneziawg/awg0.conf:ro
    networks:
      awg_net:
        ipv4_address: 172.30.0.20

networks:
  awg_net:
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

`proxy.toml`:

```toml
listen = "0.0.0.0:51820"
backend = "172.30.0.10:51820"
imitate_protocol = "quic"
awg_config = "/etc/amnezia/amneziawg/awg0.conf"
status_file = "/var/lib/amneziawg-proxy/sessions.json"
status_interval_secs = 5
```

Do not expose the AWG container port directly to the internet in this layout.
Expose only the proxy port.

### AWG on another host or VM

This is supported, but treat the backend path as trusted internal network
traffic:

```text
client -> proxy public IP:51820/udp -> proxy
proxy -> private network IP:51821/udp -> AWG host
```

Example:

```toml
listen = "0.0.0.0:51820"
backend = "10.10.0.5:51821"
imitate_protocol = "quic"
```

Make sure the AWG backend address is reachable only from the proxy host, for
example with a firewall rule on the AWG host.

## Build and Install the Binary

From the repository root:

```bash
cd amneziawg-proxy
cargo build --release
sudo install -m 0755 target/release/amneziawg-proxy /usr/local/bin/amneziawg-proxy
```

Create config and data directories:

```bash
sudo install -d -m 0755 /etc/amneziawg-proxy
sudo install -d -m 0750 /var/lib/amneziawg-proxy
```

If `amneziawg-web` runs on the same host and should read proxy sessions, allow
its service group to traverse the proxy data directory:

```bash
sudo chown root:awg-web /var/lib/amneziawg-proxy
sudo chmod 2750 /var/lib/amneziawg-proxy
```

If `amneziawg-web` is not installed, keep the directory owned by `root:root`.

## Write proxy.toml

Minimal same-host example:

```toml
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
imitate_protocol = "quic"
session_ttl_secs = 300
rate_limit_per_sec = 5
status_file = "/var/lib/amneziawg-proxy/sessions.json"
status_interval_secs = 5
awg_config = "/etc/amnezia/amneziawg/awg0.conf"
```

Important notes:

- `listen` is the public UDP endpoint that client configs should use.
- `backend` is the real AWG UDP listener. Keep it private.
- `backend` must be an IP address and port, for example `127.0.0.1:51821` or
  `172.30.0.10:51820`. Hostnames such as Docker service names are not accepted.
- `awg_config` is optional, but recommended when the proxy must apply AWG
  padding transformation. The file only needs the `[Interface]` obfuscation
  parameters; peer sections are ignored.
- `status_file` defaults to `/var/lib/amneziawg-proxy/sessions.json` when it is
  omitted. Set it explicitly when `amneziawg-web` should read sessions from a
  different path.

Install the config:

```bash
sudo tee /etc/amneziawg-proxy/proxy.toml > /dev/null <<'EOF'
listen = "0.0.0.0:51820"
backend = "127.0.0.1:51821"
imitate_protocol = "quic"
session_ttl_secs = 300
rate_limit_per_sec = 5
status_file = "/var/lib/amneziawg-proxy/sessions.json"
status_interval_secs = 5
awg_config = "/etc/amnezia/amneziawg/awg0.conf"
EOF
sudo chmod 0644 /etc/amneziawg-proxy/proxy.toml
```

## Configure AWG

The public client endpoint should point to the proxy. The AWG backend should
listen on a private address.

For same-host AWG, edit the AWG interface config:

```ini
[Interface]
ListenAddr = 127.0.0.1
ListenPort = 51821
```

Reload the interface using the command appropriate for your deployment. On a
standard host installation, that is usually:

```bash
sudo wg syncconf awg0 <(sudo wg-quick strip awg0)
```

For Docker-based AWG, update the container configuration instead. A common
pattern is to leave AWG listening on `51820/udp` inside the container, but
publish it to the host as `127.0.0.1:51821/udp`.

## Install a systemd Service

Create `/etc/systemd/system/amneziawg-proxy.service`:

```ini
[Unit]
Description=AmneziaWG UDP Proxy
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
LimitNOFILE=16384
UMask=0027
User=root
ExecStart=/usr/local/bin/amneziawg-proxy /etc/amneziawg-proxy/proxy.toml
WorkingDirectory=/var/lib/amneziawg-proxy
Environment=RUST_LOG=amneziawg_proxy=info

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadOnlyPaths=-/etc/amnezia /etc/amneziawg-proxy
ReadWritePaths=/var/lib/amneziawg-proxy

[Install]
WantedBy=multi-user.target
```

If `awg_config` points somewhere else, make sure the service user has normal
filesystem read access to that file. You can also add the config directory to
`ReadOnlyPaths` for hardening; prefix it with `-` when the directory may be
absent on hosts where `awg_config` is omitted.

For public ports below 1024, either keep `User=root` or add
`AmbientCapabilities=CAP_NET_BIND_SERVICE` and run as a dedicated service user
that can read `proxy.toml`, read `awg_config` if configured, and write
`status_file`.

Start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now amneziawg-proxy
sudo systemctl status amneziawg-proxy
```

## Firewall Checklist

- Allow inbound UDP to the proxy public port, for example `51820/udp`.
- Do not expose the AWG backend port to the internet.
- If the backend is on another host, allow the backend UDP port only from the
  proxy host.
- If Docker is used, verify published ports. Prefer
  `127.0.0.1:<backend-port>:<container-awg-port>/udp` for the backend.

Example `ufw` rules for same-host deployment:

```bash
sudo ufw allow 51820/udp
sudo ufw deny 51821/udp
```

## Web Panel Integration

`amneziawg-web` can show active proxy sessions when it can read the status file.
Use the same path in both services:

Proxy `proxy.toml`:

```toml
status_file = "/var/lib/amneziawg-proxy/sessions.json"
status_interval_secs = 5
```

Web environment:

```bash
AWG_PROXY_SESSIONS_FILE=/var/lib/amneziawg-proxy/sessions.json
```

When both services are on the same host, the proxy data directory must be
readable by the web service group:

```bash
sudo chown root:awg-web /var/lib/amneziawg-proxy
sudo chmod 2750 /var/lib/amneziawg-proxy
```

If the proxy runs in Docker, mount the status directory on the host and point
`AWG_PROXY_SESSIONS_FILE` at the mounted `sessions.json`. If the proxy is not
installed or the file is unavailable, the web panel hides the proxy sessions
section and continues to work normally.

## Validation

Check that the proxy starts:

```bash
sudo journalctl -u amneziawg-proxy -n 100 --no-pager
```

Check that it is listening:

```bash
sudo ss -lunp | grep amneziawg-proxy
```

Check that the AWG backend is not publicly exposed:

```bash
sudo ss -lunp | grep -E '51820|51821'
```

After a client connects, check the session status file:

```bash
sudo cat /var/lib/amneziawg-proxy/sessions.json
```

For Docker-hosted AWG, also verify that the proxy can reach the container's UDP
port and that the container is not publishing the backend port on `0.0.0.0`.

## Troubleshooting

### Proxy starts but clients cannot connect

- Confirm client configs point to the proxy public address and port.
- Confirm `backend` points to the real AWG listener.
- Confirm AWG is listening on the backend port.
- Confirm the backend firewall allows traffic from the proxy.
- If `awg_config` is omitted, verify that this deployment works without proxy
  padding transformation.

### Address already in use

AWG and the proxy cannot both bind the same host port. Move AWG to a backend
port or bind it only inside a container/private namespace, then let the proxy
own the public port.

### Docker service name does not work in backend

`backend` must be an IP socket address. Use a static Docker network IP, publish
the AWG container to a host loopback port, or run the proxy in a mode where the
backend has a stable IP address.

### Web panel does not show proxy sessions

- Confirm `status_file` and `AWG_PROXY_SESSIONS_FILE` are the same path.
- Confirm the proxy has written `sessions.json`.
- Confirm the web service user can traverse the status directory and read the
  file.
- Confirm `ReadOnlyPaths` in the web systemd unit includes the status directory
  when `ProtectSystem=strict` is enabled.
