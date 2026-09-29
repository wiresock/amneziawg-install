#!/bin/bash
# Integration test: a fresh BoringTun host install (AWG_BACKEND=boringtun
# AUTO_INSTALL=y) and its uninstall, with mocked external commands, on the
# distribution of the container it runs in. It checks what really lands on the
# system: APT sources (no deb-src), the package set (no DKMS, module or
# headers), the verified BoringTun store, helpers, runtime file, drop-in and
# params, and that uninstall removes them without touching kernel-module
# packages. The two steps that need a live BoringTun daemon (the scratch
# preflight and the active-instance check) are stubbed; they run for real in
# the live test, tests/test-boringtun-host-live.sh.
#
# Designed to run inside a disposable Docker container as root:
#   docker run --rm -v "$PWD:/workspace:ro" -w /workspace ubuntu:24.04 bash tests/test-boringtun-install-mock.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "ERROR: This test must be run as root (in a disposable container)"
	exit 1
fi
if [[ ! -f /.dockerenv ]] && ! grep -qE '(/docker|/lxc)' /proc/1/cgroup 2>/dev/null; then
	echo "ERROR: This test must run inside a container. Refusing to modify a real host."
	exit 1
fi

# shellcheck source=/dev/null
source /etc/os-release
echo "=== BoringTun host install (mocked) on ${PRETTY_NAME} ==="
case "${ID}" in
	ubuntu | debian) ;;
	*)
		echo "SKIP: BoringTun host installs are for Debian and Ubuntu"
		exit 0
		;;
esac

PASS=0
FAIL=0
ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}
not_ok() {
	printf '  FAIL: %s\n' "$1"
	FAIL=$((FAIL + 1))
}
check() { # <label> <command...>
	local LABEL="$1"
	shift
	if "$@"; then ok "${LABEL}"; else not_ok "${LABEL}"; fi
}

MOCK=/opt/boringtun-mock
LOG="${MOCK}/log"
rm -rf "${MOCK}"
mkdir -p "${MOCK}/bin" "${MOCK}/serve"
: >"${LOG}"
mock() { # <name> <body>
	printf '#!/bin/bash\n%s\n' "$2" >"${MOCK}/bin/$1"
	chmod 0755 "${MOCK}/bin/$1"
}
export PATH="${MOCK}/bin:${PATH}"

mock apt-get "echo \"apt-get \$*\" >>${LOG}; exit 0"
mock apt "echo \"apt \$*\" >>${LOG}; [[ \"\$1\" == remove && -e ${MOCK}/apt-remove-fails ]] && exit 100; exit 0"
mock apt-cache '
if [[ "$*" == "show --no-all-versions amneziawg-tools" ]]; then
	printf "Package: amneziawg-tools\nArchitecture: %s\nVersion: 1.0-mock\nFilename: pool/main/a/amneziawg/amneziawg-tools_1.0-mock.deb\n\n" "$(dpkg --print-architecture)"
	exit 0
fi
[[ "$1" == show ]] && exit 1
exit 0'
# Installed-package state for uninstall: amneziawg-tools, as the install
# would have left it, and a kernel-module package someone else installed.
mock dpkg-query '
if [[ "$1" == -W && "$2" == "-f=\${db:Status-Abbrev}" ]]; then
	case "$3" in
		amneziawg-tools | amneziawg-dkms) printf "ii "; exit 0 ;;
		*) exit 1 ;;
	esac
fi
exec /usr/bin/dpkg-query "$@"'
mock add-apt-repository '
source /etc/os-release
mkdir -p /etc/apt/sources.list.d
cat >"/etc/apt/sources.list.d/amnezia-ubuntu-ppa-${VERSION_CODENAME}.sources" <<EOF
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: ${VERSION_CODENAME}
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 MOCKKEY
 -----END PGP PUBLIC KEY BLOCK-----
EOF'
mock gpg '
if [[ "$*" == *--show-keys* ]]; then
	echo "fpr:::::::::75C9DD72C799870E310542E24166F2C257290828:"
elif [[ "$*" == *--dearmor* ]]; then
	cat >/dev/null
	echo MOCK_BINARY_KEY_DATA
fi
exit 0'
# curl: PPA metadata probes, the Debian signing key, and the BoringTun release
# asset from the fixture directory.
mock curl "
echo \"curl \$*\" >>${LOG}
OUT='' URL=''
while ((\$#)); do
	case \"\$1\" in
		-o) OUT=\"\$2\"; shift 2 ;;
		-w | --retry | --retry-delay | --connect-timeout | --max-time) shift 2 ;;
		-*) shift ;;
		*) URL=\"\$1\"; shift ;;
	esac
done
case \"\${URL}\" in
	https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/*)
		case \"\${URL}\" in */resolute/*) printf 404 ;; *) printf 200 ;; esac ;;
	https://keyserver.ubuntu.com/*)
		printf -- '-----BEGIN PGP PUBLIC KEY BLOCK-----\nMOCKKEY\n-----END PGP PUBLIC KEY BLOCK-----\n' >\"\${OUT}\" ;;
	https://github.com/wiresock/amneziawg-install/releases/download/*)
		cp -- \"${MOCK}/serve/\${URL##*/}\" \"\${OUT}\" || exit 22 ;;
	*) exit 6 ;;
esac"
mock systemctl "
echo \"systemctl \$*\" >>${LOG}
case \"\$1\" in
	show) exit 1 ;;
	is-active) [[ -f ${MOCK}/active ]] ;;
	start) : >${MOCK}/active ;;
	stop) rm -f ${MOCK}/active ;;
	*) exit 0 ;;
esac"
mock awg '
case "$1" in
	genkey) echo "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=" ;;
	pubkey) cat >/dev/null; echo "cHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=" ;;
	genpsk) echo "cHNrMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnM=" ;;
	show) [[ "${3:-}" == listen-port ]] && echo 51820 ;;
	syncconf) cat >/dev/null ;;
esac
exit 0'
mock awg-quick '[[ "$1" == strip ]] && printf "[Interface]\nListenPort = 51820\n"; exit 0'
mock ip '
case "$1$2" in
	-4route) echo "default via 198.51.100.254 dev eth0" ;;
	-6route) echo "default via 2001:db8::ffff dev eth0" ;;
	-4addr) echo "    inet 198.51.100.1/24 scope global eth0" ;;
esac
exit 0'
mock modinfo "echo \"modinfo \$*\" >>${LOG}; exit 1"
mock modprobe "echo \"modprobe \$*\" >>${LOG}; exit 0"
mock dkms "echo \"dkms \$*\" >>${LOG}; exit 0"
mock depmod "echo \"depmod \$*\" >>${LOG}; exit 0"
mock sysctl 'exit 0'
mock iptables '[[ "$1" == --version ]] && echo "iptables v1.8.10 (nf_tables)"; exit 0'
mock ip6tables 'exit 0'
mock nft 'exit 0'
mock qrencode 'cat >/dev/null; exit 0'
mock firewall-cmd 'exit 1'

# A fixture release: a fake boringtun-cli packed with the release layout. The
# installer's embedded hashes are pointed at it after sourcing.
FIXTURE="${MOCK}/fixture"
source_constants() {
	# shellcheck disable=SC2016
	bash -c 'source "$1" && printf "%s %s %s\n" "${AWG_BT_RELEASE_ASSET_X86_64}" "${AWG_BT_RELEASE_VERSION}" "${AWG_BT_RELEASE_SOURCE_COMMIT}"' _ "${INSTALLER}"
}
read -r ASSET VERSION COMMIT <<<"$(source_constants)"
REL_ID="${ASSET%.tar.gz}"
mkdir -p "${FIXTURE}/${REL_ID}"
printf '#!/bin/sh\n[ "$1" = --version ] && echo "boringtun %s"\nexit 0\n' "${VERSION}" >"${FIXTURE}/${REL_ID}/boringtun-cli"
chmod 0755 "${FIXTURE}/${REL_ID}/boringtun-cli"
echo "BSD-3-Clause fixture" >"${FIXTURE}/${REL_ID}/LICENSE"
echo "fixture notices" >"${FIXTURE}/${REL_ID}/THIRD-PARTY-LICENSES"
BINARY_SHA256="$(sha256sum "${FIXTURE}/${REL_ID}/boringtun-cli" | cut -d' ' -f1)"
{
	echo "artifact_format=1"
	echo "name=boringtun-cli"
	echo "version=${VERSION}"
	echo "source_repository=https://github.com/Wiresock-Foundation/wiresock-boringtun"
	echo "source_commit=${COMMIT}"
	echo "source_date_epoch=1790626003"
	echo "target=x86_64-unknown-linux-musl"
	echo "os=linux"
	echo "arch=x86_64"
	echo "libc=musl"
	echo "linkage=static"
	echo "rust_toolchain=1.98.1"
	echo "rustc=rustc 1.98.1"
	echo "cargo=cargo 1.98.1"
	echo "build_command=cargo build --release --locked -p boringtun-cli"
	echo "build_profile=release,strip=symbols"
	echo "rustflags=--remap-path-prefix=<source>=/boringtun"
	echo "binary=boringtun-cli"
	echo "binary_sha256=${BINARY_SHA256}"
	echo "license=LICENSE (BSD-3-Clause)"
	echo "third_party_licenses=THIRD-PARTY-LICENSES"
} >"${FIXTURE}/${REL_ID}/MANIFEST"
tar --no-recursion --numeric-owner --owner=0 --group=0 -czf "${MOCK}/serve/${ASSET}" -C "${FIXTURE}" \
	"${REL_ID}/" "${REL_ID}/LICENSE" "${REL_ID}/MANIFEST" "${REL_ID}/THIRD-PARTY-LICENSES" "${REL_ID}/boringtun-cli"
ARCHIVE_SHA256="$(sha256sum "${MOCK}/serve/${ASSET}" | cut -d' ' -f1)"

mkdir -p /run/systemd/system /etc/apt/sources.list.d
rm -f /etc/apt/sources.list.d/amneziawg.sources /etc/apt/sources.list.d/amneziawg.sources.list

# run_installer <commands>: source the installer with AWG_BACKEND=boringtun in
# the environment, as an operator would run it, point the embedded release at
# the fixture, stub the two live-daemon steps and evaluate the commands.
run_installer() {
	env AWG_BACKEND=boringtun AUTO_INSTALL=y SERVER_PUB_IP=198.51.100.1 SERVER_PUB_NIC=eth0 SERVER_AWG_NIC=awg0 \
		SERVER_PORT=51820 ENABLE_IPV6=n CREATE_INITIAL_CLIENT=y \
		ARCHIVE_SHA256="${ARCHIVE_SHA256}" BINARY_SHA256="${BINARY_SHA256}" LOG="${LOG}" \
		bash -c '
			source "$1" || exit 99
			shift
			AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64="${ARCHIVE_SHA256}"
			AWG_BT_RELEASE_BINARY_SHA256_X86_64="${BINARY_SHA256}"
			AWG_BT_HOST_ARCH=x86_64
			AWG_BT_TUN_DEVICE=/dev/null
			boringtunHostPreflight() { echo "boringtunHostPreflight" >>"${LOG}"; }
			_awgBtCheckServedByBoringtun() { echo "_awgBtCheckServedByBoringtun $*" >>"${LOG}"; }
			initialCheck
			eval "$1"' _ "${INSTALLER}" "$*"
}

echo "--- fresh install"
run_installer installAmneziaWG >"${MOCK}/install.out" 2>&1
RC=$?
tail -5 "${MOCK}/install.out" | sed 's/^/    | /'
check "the BoringTun AUTO_INSTALL completes" test "${RC}" -eq 0
APT_LOG="$(grep -E '^apt(-get)? ' "${LOG}")"
check "amneziawg-tools is installed without recommends" grep -qx 'apt-get install -y --no-install-recommends amneziawg-tools' <<<"${APT_LOG}"
check "no DKMS, kernel module package or headers are installed" \
	bash -c '! grep -E "install .*(dkms|amneziawg( |$)|amneziawg-dkms|linux-headers)" <<<"$1"' _ "${APT_LOG}"
check "no dkms or depmod runs" bash -c '! grep -qE "^(dkms|depmod) " "$1"' _ "${LOG}"
check "no module is loaded" bash -c '! grep -E "^modprobe " "$1" | grep -qv -- " -n "' _ "${LOG}"
if [[ "${ID}" == debian ]]; then
	check "Debian: the managed PPA source has the deb line" grep -q '^deb \[signed-by=/etc/apt/keyrings/amneziawg.gpg\] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main$' /etc/apt/sources.list.d/amneziawg.sources.list
	check "Debian: and no deb-src entry at all" bash -c '! grep -q "^deb-src" /etc/apt/sources.list.d/amneziawg.sources.list'
	check "Debian: the signing keyring is installed" test -s /etc/apt/keyrings/amneziawg.gpg
else
	check "Ubuntu: no deb-src source copy is generated" test ! -e /etc/apt/sources.list.d/amneziawg.sources -a ! -e /etc/apt/sources.list.d/amneziawg.sources.list
	check "Ubuntu: the Amnezia PPA source is configured" bash -c 'grep -l "ppa.launchpadcontent.net/amnezia/ppa/ubuntu" /etc/apt/sources.list.d/*.sources >/dev/null'
fi
check "the release is downloaded from its exact public URL over HTTPS" \
	grep -q "^curl --proto =https --proto-redir =https .* https://github.com/wiresock/amneziawg-install/releases/download/boringtun-cli-${VERSION}-g${COMMIT:0:12}-b1/${ASSET}\$" "${LOG}"
STORE=/usr/local/lib/amneziawg-install/boringtun
check "the store holds the release and its current link" test "$(readlink "${STORE}/current")" = "${REL_ID}"
check "the store is root-owned and not writable by others" test "$(stat -c '%u %a' "${STORE}" "${STORE}/${REL_ID}" "${STORE}/${REL_ID}/boringtun-cli" | tr '\n' ' ')" = "0 755 0 755 0 755 "
check "the store verifies" run_installer _awgBtVerifyStore
LIBEXEC=/usr/local/libexec/amneziawg-install
check "both helpers are installed root-owned, mode 0755" \
	test "$(stat -c '%u %a' "${LIBEXEC}/awg-boringtun-launch" "${LIBEXEC}/awg-backend-ctl" | tr '\n' ' ')" = "0 755 0 755 "
check "params persist AWG_BACKEND='boringtun'" grep -qx "AWG_BACKEND='boringtun'" /etc/amnezia/amneziawg/params
check "params are root-owned, mode 0600" test "$(stat -c '%u %a' /etc/amnezia/amneziawg/params)" = "0 600"
check "the server config is written" grep -q '^ListenPort = 51820$' /etc/amnezia/amneziawg/awg0.conf
check "the runtime file is written, root-owned, mode 0600" test "$(stat -c '%u %a' /etc/amnezia/amneziawg/awg0.boringtun)" = "0 600"
check "the runtime file enables no imitation" test "$(grep -v '^#' /etc/amnezia/amneziawg/awg0.boringtun)" = "FORMAT=1"
DROPIN=/etc/systemd/system/awg-quick@awg0.service.d/override.conf
check "the BoringTun drop-in is written" grep -qx "ExecStartPre=${LIBEXEC}/awg-backend-ctl precheck %i" "${DROPIN}"
check "the drop-in is exactly the runtime layer's rendering" cmp -s "${DROPIN}" <(run_installer _awgBtRenderServiceDropIn)
check "no kernel drop-in (ExecStartPre=modprobe) is written" bash -c '! grep -q "modprobe" "$1"' _ "${DROPIN}"
check "no modules-load entry is written" test ! -e /etc/modules-load.d/amneziawg.conf
check "no load override is written without an installed module" test ! -e /etc/modprobe.d/amneziawg-install-boringtun.conf
check "the preflight runs before params are written" \
	test "$(grep -n '^boringtunHostPreflight$' "${LOG}" | cut -d: -f1)" -lt "$(grep -n '^systemctl enable awg-quick@awg0$' "${LOG}" | cut -d: -f1)"
check "the unit is enabled and started" grep -qx 'systemctl start awg-quick@awg0' "${LOG}"
check "the active instance is checked" grep -qx '_awgBtCheckServedByBoringtun awg0' "${LOG}"
check "the initial client is created" grep -q '^### Client client$' /etc/amnezia/amneziawg/awg0.conf
check "the forwarding sysctl is written" grep -qx 'net.ipv4.ip_forward = 1' /etc/sysctl.d/awg.conf

echo "--- management keeps BoringTun and does not replace the binary"
BEFORE="$(stat -c '%i %Y' "${STORE}/${REL_ID}/boringtun-cli")"
: >"${LOG}"
env AWG_BACKEND=kernel bash -c 'source "$1" && validateParamsFile >/dev/null && printf "%s" "${AWG_BACKEND}"' _ "${INSTALLER}" >"${MOCK}/backend"
check "an exported AWG_BACKEND=kernel does not switch the installation" test "$(cat "${MOCK}/backend")" = boringtun
run_installer 'loadParams >/dev/null && installBoringtunRelease' >/dev/null 2>&1
check "a second release install reuses the verified release" test "$(stat -c '%i %Y' "${STORE}/${REL_ID}/boringtun-cli")" = "${BEFORE}"
check "without downloading it again" bash -c '! grep -q "^curl .*releases/download" "$1"' _ "${LOG}"

echo "--- uninstall"
: >"${LOG}"
mkdir -p /etc/modprobe.d /etc/modules-load.d
run_installer 'loadParams >/dev/null && _awgBtRenderModprobeOverride >/etc/modprobe.d/amneziawg-install-boringtun.conf'
# An administrator's module boot entry: never the BoringTun install's file.
printf '# the administrator'"'"'s own\namneziawg\n' >/etc/modules-load.d/amneziawg.conf
MODULES_LOAD_SHA="$(sha256sum /etc/modules-load.d/amneziawg.conf)"
# The first attempt's package removal fails: params stay, so the next run of
# the installer is a management run that offers the uninstall again.
: >"${MOCK}/apt-remove-fails"
printf 'y\n' | run_installer 'loadParams && uninstallAmneziaWG' >"${MOCK}/uninstall-failed.out" 2>&1
RC=$?
rm -f "${MOCK}/apt-remove-fails"
tail -3 "${MOCK}/uninstall-failed.out" | sed 's/^/    | /'
check "an uninstall whose package removal fails fails" test "${RC}" -ne 0
check "  and keeps params and the server config" test -e /etc/amnezia/amneziawg/params -a -e /etc/amnezia/amneziawg/awg0.conf
check "  and says so" grep -q "was kept, so the uninstall can be run again" "${MOCK}/uninstall-failed.out"
: >"${LOG}"
printf '6\ny\n' | bash "${INSTALLER}" >"${MOCK}/uninstall.out" 2>&1
RC=$?
tail -3 "${MOCK}/uninstall.out" | sed 's/^/    | /'
check "the next run of the installer is a management run" grep -q "It looks like AmneziaWG is already installed" "${MOCK}/uninstall.out"
check "the uninstall succeeds" test "${RC}" -eq 0
first_line() { # <exact line>: its line number in the log
	grep -nxF -- "$1" "${LOG}" | head -n 1 | cut -d: -f1
}
check "the unit is stopped and disabled before any package is removed" \
	test -n "$(first_line 'systemctl stop awg-quick@awg0')" -a -n "$(first_line 'systemctl disable awg-quick@awg0')" -a \
	"$(first_line 'systemctl stop awg-quick@awg0')" -lt "$(first_line 'apt remove -y amneziawg-tools')" -a \
	"$(first_line 'systemctl disable awg-quick@awg0')" -lt "$(first_line 'apt remove -y amneziawg-tools')"
check "the store is removed" test ! -e "${STORE}" -a ! -e /usr/local/lib/amneziawg-install
check "the helpers are removed" test ! -e "${LIBEXEC}"
check "the drop-in is removed" test ! -e "${DROPIN}" -a ! -d /etc/systemd/system/awg-quick@awg0.service.d
check "the configuration, params and runtime file are removed" test ! -e /etc/amnezia/amneziawg
check "the installer's load override is removed" test ! -e /etc/modprobe.d/amneziawg-install-boringtun.conf
check "only amneziawg-tools is removed" grep -qx 'apt remove -y amneziawg-tools' "${LOG}"
check "the kernel module package someone else installed stays" bash -c '! grep -q "amneziawg-dkms" "$1"' _ "${LOG}"
check "the administrator's /etc/modules-load.d/amneziawg.conf is byte for byte as it was" \
	test "$(sha256sum /etc/modules-load.d/amneziawg.conf 2>/dev/null)" = "${MODULES_LOAD_SHA}"
rm -f /etc/modules-load.d/amneziawg.conf
if [[ "${ID}" == debian ]]; then
	check "Debian: the managed source and keyring are removed" test ! -e /etc/apt/sources.list.d/amneziawg.sources.list -a ! -e /etc/apt/keyrings/amneziawg.gpg
fi

echo
echo "BoringTun install mock (${ID} ${VERSION_ID}): ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
