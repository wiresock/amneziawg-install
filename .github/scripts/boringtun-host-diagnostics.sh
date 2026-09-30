#!/bin/bash
# Collect diagnostics of a failed BoringTun host test into a directory. Nothing
# that holds key material is collected: no /etc/amnezia, no client configs,
# and `awg show` hides private and preshared keys by default.
#
# Usage: bash .github/scripts/boringtun-host-diagnostics.sh <output dir>

OUT="${1:?usage: $0 <output dir>}"
SUDO=""
[[ "${EUID}" -eq 0 ]] || SUDO="sudo"
mkdir -p "${OUT}"
collect() { # <file> <command...>
	local FILE="$1"
	shift
	${SUDO} "$@" >"${OUT}/${FILE}" 2>&1 || true
}
collect journal-awg-quick.txt journalctl -u 'awg-quick@*' --no-pager -n 400
collect journal-scratch.txt journalctl -u 'amneziawg-scratch-*' --no-pager -n 200
collect systemctl-status.txt systemctl status 'awg-quick@*' --no-pager --all
collect systemctl-show.txt systemctl show 'awg-quick@awg0.service'
collect ip-link.txt ip -d link show
collect ip-addr.txt ip addr show
collect awg-show.txt awg show
collect sockets.txt ss -xlp
collect packages.txt bash -c "dpkg -l | grep -iE 'amnezia|dkms|linux-headers'"
collect store.txt bash -c 'ls -laR /usr/local/lib/amneziawg-install; cat /usr/local/lib/amneziawg-install/boringtun/current/MANIFEST'
collect helpers.txt ls -la /usr/local/libexec/amneziawg-install
collect runtime-state.txt bash -c 'ls -laR /run/amneziawg-install /var/run/wireguard /var/run/amneziawg'
collect scratch-records.txt bash -c 'for f in /run/amneziawg-install/scratch/*; do echo "== $f"; cat "$f"; done'
collect modules.txt bash -c 'ls /sys/module | grep -i amnezia; modinfo -n amneziawg; ls -la /etc/modprobe.d'
collect dropin.txt bash -c 'cat /etc/systemd/system/awg-quick@*.service.d/override.conf'
${SUDO} chmod -R a+rX "${OUT}" 2>/dev/null || true
