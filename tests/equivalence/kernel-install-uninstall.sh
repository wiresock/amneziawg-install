#!/bin/bash
# Kernel-path equivalence, install and uninstall: inside a disposable container,
# a kernel AUTO_INSTALL and a menu uninstall with command-logging mocks. It
# records every command, the output and every file written below /etc, the
# stores and /root, normalized, to /out/<name>.txt. Run by
# run-kernel-equivalence.sh for a base revision and the working tree on each
# distribution; the transcripts must be identical.
#
# Usage (as root in a container): kernel-install-uninstall.sh <installer> <name>
INSTALLER="$1"
NAME="$2"
LOG=/tmp/equiv.log
: >"${LOG}"
M=/opt/equiv/bin
mkdir -p "${M}"
mock() {
	printf '#!/bin/bash\necho "%s $*" >>%s\n%s\n' "$1" "${LOG}" "$2" >"${M}/$1"
	chmod 0755 "${M}/$1"
}
export PATH="${M}:${PATH}"
mock apt-get 'exit 0'
mock apt 'exit 0'
mock apt-cache '
if [[ "$*" == "show --no-all-versions amneziawg-tools" ]]; then
	printf "Package: amneziawg-tools\nArchitecture: %s\nVersion: 1.0-mock\nFilename: pool/x.deb\n\n" "$(dpkg --print-architecture)"
	exit 0
fi
[[ "$1" == show ]] && exit 1
exit 0'
mock dpkg-query '
if [[ "$1" == -W && "$2" == "-f=\${db:Status-Abbrev}" ]]; then
	case "$3" in amneziawg|amneziawg-tools|amneziawg-dkms) printf "ii "; exit 0 ;; *) exit 1 ;; esac
fi
exec /usr/bin/dpkg-query "$@"'
mock add-apt-repository '
source /etc/os-release
mkdir -p /etc/apt/sources.list.d
printf "Types: deb\nURIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/\nSuites: %s\nComponents: main\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n MOCKKEY\n -----END PGP PUBLIC KEY BLOCK-----\n" "${VERSION_CODENAME}" >"/etc/apt/sources.list.d/amnezia-ubuntu-ppa-${VERSION_CODENAME}.sources"'
mock gpg '
if [[ "$*" == *--show-keys* ]]; then echo "fpr:::::::::75C9DD72C799870E310542E24166F2C257290828:"
elif [[ "$*" == *--dearmor* ]]; then cat >/dev/null; echo KEY; fi
exit 0'
mock curl '
OUT="" URL=""
while (($#)); do case "$1" in -o) OUT="$2"; shift 2 ;; -w) shift 2 ;; -*) shift ;; *) URL="$1"; shift ;; esac; done
case "${URL}" in
	https://ppa.launchpadcontent.net/*) case "${URL}" in */resolute/*) printf 404 ;; *) printf 200 ;; esac ;;
	*) printf -- "-----BEGIN PGP PUBLIC KEY BLOCK-----\nK\n-----END PGP PUBLIC KEY BLOCK-----\n" >"${OUT}" ;;
esac'
mock systemctl '
case "$1" in
	show) exit 1 ;;
	is-active) [[ -f /tmp/active ]] ;;
	start) : >/tmp/active ;;
	stop) rm -f /tmp/active ;;
	*) exit 0 ;;
esac'
# awg reads a syncconf input completely before it logs, so the strip that
# produces it (a process substitution) is always logged first.
cat >"${M}/awg" <<EOF
#!/bin/bash
if [[ "\$1" == syncconf ]]; then
	CONTENT="\$(tr '\n' '|' <"\$3")"
	echo "awg syncconf \$2 <\${CONTENT}>" >>${LOG}
	exit 0
fi
echo "awg \$*" >>${LOG}
case "\$1" in
	genkey) echo "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=" ;;
	pubkey) cat >/dev/null; echo "cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=" ;;
	genpsk) echo "cHNrMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM=" ;;
esac
exit 0
EOF
chmod 0755 "${M}/awg"
mock awg-quick '[[ "$1" == strip ]] && printf "[Interface]\nListenPort = 51820\n"; exit 0'
mock ip '
case "$1$2" in
	-4route) echo "default via 198.51.100.254 dev eth0" ;;
	-6route) echo "default via 2001:db8::ffff dev eth0" ;;
esac
exit 0'
mock modprobe 'exit 0'
mock modinfo 'exit 1'
mock lsmod 'echo "amneziawg 16384 0"'
mock dkms 'exit 0'
mock depmod 'exit 0'
mock sysctl 'exit 0'
mock iptables '[[ "$1" == --version ]] && echo "iptables v1.8.10 (nf_tables)"; exit 0'
mock ip6tables 'exit 0'
mock nft 'exit 0'
mock qrencode 'cat >/dev/null; exit 0'
mock firewall-cmd 'exit 1'
mock shuf '
for A in "$@"; do [[ "$A" == -i* ]] && RANGE="${A#-i}"; done
[[ -n "${RANGE:-}" ]] || RANGE="$2"
echo "${RANGE%%-*}"'
mock uname '[[ "$1" == -r ]] && { echo 6.8.0-equiv; exit 0; }; exec /usr/bin/uname "$@"'
mkdir -p /run/systemd/system /etc/apt/sources.list.d
[[ -f /etc/apt/sources.list || -f /etc/apt/sources.list.d/ubuntu.sources ]] || echo "deb http://deb.debian.org/debian stable main" >/etc/apt/sources.list

snapshot() {
	find /etc/apt /etc/amnezia /etc/systemd/system /etc/modules-load.d /etc/modprobe.d /etc/sysctl.d \
		/usr/local/lib/amneziawg-install /usr/local/libexec/amneziawg-install /root -xdev -type f 2>/dev/null |
		grep -v '/etc/systemd/system/.*\.wants/' | LC_ALL=C sort | while read -r F; do
		printf '%s %s %s\n' "$(stat -c '%a' "$F")" "$(sha256sum <"$F" | cut -c1-16)" "$F"
	done
}

{
	echo "=== install"
	env AUTO_INSTALL=y SERVER_PUB_IP=198.51.100.1 SERVER_PUB_NIC=eth0 ENABLE_IPV6=n bash -c '
		source "$1" || exit 99
		RANDOM=4242
		initialCheck
		installAmneziaWG' _ "${INSTALLER}" 2>&1 </dev/null
	echo "rc=$?"
	echo "--- commands"
	cat "${LOG}"
	echo "--- files"
	snapshot
	: >"${LOG}"
	echo "=== uninstall"
	printf 'y\n' | bash -c 'source "$1" || exit 99; initialCheck; loadParams && uninstallAmneziaWG' _ "${INSTALLER}" 2>&1
	echo "rc=$?"
	echo "--- commands"
	cat "${LOG}"
	echo "--- files"
	snapshot
} | sed -E 's#/tmp/amneziawg-apt-key\.[A-Za-z0-9]+#/tmp/amneziawg-apt-key.X#g; s#amneziawg\.gpg\.tmp\.[A-Za-z0-9]+#amneziawg.gpg.tmp.X#g; s#params\.[A-Za-z0-9]{6}#params.X#g' >"/out/${NAME}.txt"
