#!/usr/bin/env bash

# Unit tests for the BoringTun host installation of amneziawg-install.sh: the
# embedded public release and its agreement with the release contract, the
# download-and-verify transaction, the atomic store install, the proxy,
# web-panel and kernel-module guards, package selection, the preflight, the
# order of a fresh install, and the BoringTun part of uninstall. Nothing here
# needs root, the network or systemd: every path is anchored below a test root,
# a fixture archive with a fake boringtun-cli stands in for the release, and
# mocks stand in for curl, apt, systemctl and the other external commands.
#
# Requires python3 (hostile fixture archives) and ss (iproute2).

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"
RELEASE_CONTRACT="${PROJECT_ROOT}/packaging/boringtun/release.env"
PIN_FILE="${PROJECT_ROOT}/packaging/boringtun/pin.env"

# Every path the suite touches is redirected below its private test root, and
# still it refuses root outside a disposable host, before anything is sourced:
# a path that a later change forgets to redirect must never reach /etc.
if [[ "${EUID}" -eq 0 && "${AWG_DISPOSABLE_HOST_TEST:-}" != 1 ]]; then
	echo "ERROR: run the BoringTun host tests as an unprivileged user; as root they run only on a disposable host with AWG_DISPOSABLE_HOST_TEST=1" >&2
	exit 2
fi

for TOOL in python3 ss; do
	if ! command -v "${TOOL}" >/dev/null 2>&1; then
		echo "ERROR: ${TOOL} is required for the BoringTun host tests" >&2
		exit 1
	fi
done

# shellcheck source=../amneziawg-install.sh
source "${INSTALLER}"

T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-host-tests.XXXXXX")"
T="$(CDPATH='' cd -- "${T}" && pwd -P)"
chmod 0755 "${T}"
S="${T}/state"
MOCKBIN="${T}/mockbin"
mkdir -p "${S}" "${MOCKBIN}"

PASS=0
FAIL=0

cleanup() {
	local PID
	for PID in $(cat "${T}/background" 2>/dev/null); do
		kill -KILL "${PID}" 2>/dev/null
	done
	rm -rf -- "${T}"
}
trap cleanup EXIT

ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}

not_ok() {
	printf '  FAIL: %s\n' "$1" >&2
	FAIL=$((FAIL + 1))
}

assert_eq() {
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected:\n%s\n    actual:\n%s\n' "$(sed 's/^/      /' <<<"$1")" "$(sed 's/^/      /' <<<"$2")" >&2
	fi
}

assert_rc() {
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3 (expected rc=$1, got rc=$2; stderr: ${ERR:-})"
	fi
}

assert_contains() {
	if [[ "$2" == *"$1"* ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected to contain: %s\n    actual: %s\n' "$1" "$2" >&2
	fi
}

assert_not_contains() {
	if [[ "$2" != *"$1"* ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected not to contain: %s\n    actual: %s\n' "$1" "$2" >&2
	fi
}

assert_true() {
	local NAME="$1"
	shift
	if "$@"; then ok "${NAME}"; else not_ok "${NAME}"; fi
}

# run <command...>: in a subshell, since installer functions may exit. Sets RC,
# OUT (stdout) and ERR (stderr); stdin is RUN_INPUT when set.
run() {
	if [[ -n "${RUN_INPUT:-}" ]]; then
		("$@") >"${T}/out" 2>"${T}/err" <<<"${RUN_INPUT}"
	else
		("$@") >"${T}/out" 2>"${T}/err" </dev/null
	fi
	RC=$?
	OUT="$(cat "${T}/out")"
	ERR="$(cat "${T}/err")"
}

# A value from a KEY=VALUE contract file, read as data.
contract_value() { # <file> <key>
	sed -n "s/^$2=//p" "$1"
}

echo "=== The embedded release matches the release contract ==="
for PAIR in \
	TAG:BORINGTUN_RELEASE_TAG \
	VERSION:BORINGTUN_RELEASE_VERSION \
	SOURCE_COMMIT:BORINGTUN_RELEASE_SOURCE_COMMIT \
	ASSET_X86_64:BORINGTUN_RELEASE_ASSET_X86_64 \
	ARCHIVE_SHA256_X86_64:BORINGTUN_RELEASE_ARCHIVE_SHA256_X86_64 \
	BINARY_SHA256_X86_64:BORINGTUN_RELEASE_BINARY_SHA256_X86_64 \
	ASSET_AARCH64:BORINGTUN_RELEASE_ASSET_AARCH64 \
	ARCHIVE_SHA256_AARCH64:BORINGTUN_RELEASE_ARCHIVE_SHA256_AARCH64 \
	BINARY_SHA256_AARCH64:BORINGTUN_RELEASE_BINARY_SHA256_AARCH64; do
	EMBEDDED_NAME="AWG_BT_RELEASE_${PAIR%%:*}"
	CONTRACT_VALUE="$(contract_value "${RELEASE_CONTRACT}" "${PAIR#*:}")"
	if [[ -n "${CONTRACT_VALUE}" && "${!EMBEDDED_NAME}" == "${CONTRACT_VALUE}" ]]; then
		ok "${EMBEDDED_NAME} equals ${PAIR#*:} in release.env (${CONTRACT_VALUE})"
	else
		not_ok "${EMBEDDED_NAME} (${!EMBEDDED_NAME}) equals ${PAIR#*:} in release.env (${CONTRACT_VALUE})"
	fi
done
assert_eq "approved" "$(contract_value "${RELEASE_CONTRACT}" BORINGTUN_RELEASE_STATE)" \
	"the embedded release is the approved (published) one"
assert_eq "$(contract_value "${PIN_FILE}" BORINGTUN_REPOSITORY)" "${AWG_BT_RELEASE_SOURCE_REPOSITORY}" \
	"the embedded source repository is the pinned one"
assert_eq "$(contract_value "${PIN_FILE}" BORINGTUN_COMMIT)" "${AWG_BT_RELEASE_SOURCE_COMMIT}" \
	"the embedded source commit is the pinned one"
assert_eq "$(contract_value "${PIN_FILE}" BORINGTUN_VERSION)" "${AWG_BT_RELEASE_VERSION}" \
	"the embedded version is the pinned one"
assert_eq "https://github.com/wiresock/amneziawg-install/releases/download/${AWG_BT_RELEASE_TAG}" "${AWG_BT_RELEASE_BASE_URL}" \
	"downloads come from exactly this repository's release of that tag, over HTTPS"
assert_eq "boringtun-cli-${AWG_BT_RELEASE_VERSION}-g${AWG_BT_RELEASE_SOURCE_COMMIT:0:12}-linux-x86_64-musl.tar.gz" \
	"${AWG_BT_RELEASE_ASSET_X86_64}" "the x86_64 asset name follows from the version and commit"
assert_eq "boringtun-cli-${AWG_BT_RELEASE_VERSION}-g${AWG_BT_RELEASE_SOURCE_COMMIT:0:12}-linux-aarch64-musl.tar.gz" \
	"${AWG_BT_RELEASE_ASSET_AARCH64}" "the aarch64 asset name follows from the version and commit"
assert_eq "0" "$(grep -cE 'releases/latest|api\.github\.com|actions/artifacts' "${INSTALLER}")" \
	"the installer never looks up a latest release, the GitHub API or Actions artifacts"
assert_eq "1" "$(grep -c "^AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST=\"boringtun-host-v1\"$" "${INSTALLER}")" \
	"the installer carries its BoringTun host capability line exactly once"
assert_eq "/etc/systemd/system/amneziawg-proxy.service /usr/local/bin/amneziawg-proxy /etc/amneziawg-proxy/proxy.toml" \
	"${AWG_PROXY_INSTALL_PATHS}" "the proxy is detected by its unit, its binary and its proxy.toml"
assert_eq "/usr/local/bin/amneziawg-install.sh" "${WEB_PANEL_LIFECYCLE_SCRIPT}" \
	"the web panel's default lifecycle-script copy is /usr/local/bin/amneziawg-install.sh"
assert_eq "/etc/modprobe.d/amneziawg-install-boringtun.conf" "${AWG_BT_MODPROBE_OVERRIDE}" \
	"the installer's load override lives in /etc/modprobe.d"

echo "=== Architecture mapping ==="
host_arch_of() {
	(
		AWG_BT_HOST_ARCH="$1"
		_awgBtHostArch
	)
}
assert_eq "x86_64" "$(host_arch_of x86_64)" "x86_64 maps to x86_64"
assert_eq "x86_64" "$(host_arch_of amd64)" "amd64 maps to x86_64"
assert_eq "aarch64" "$(host_arch_of aarch64)" "aarch64 maps to aarch64"
assert_eq "aarch64" "$(host_arch_of arm64)" "arm64 maps to aarch64"
for MACHINE in armv7l armhf i686 riscv64 ppc64le s390x; do
	run host_arch_of "${MACHINE}"
	assert_rc 1 "${RC}" "${MACHINE} has no BoringTun release"
done
run _awgBtSelectRelease x86_64
_awgBtSelectRelease x86_64
assert_eq "${AWG_BT_RELEASE_ASSET_X86_64} ${AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64} ${AWG_BT_RELEASE_BINARY_SHA256_X86_64}" \
	"${_AWG_BT_REL_ASSET} ${_AWG_BT_REL_ARCHIVE_SHA256} ${_AWG_BT_REL_BINARY_SHA256}" "x86_64 selects the x86_64 asset and hashes"
assert_eq "${AWG_BT_RELEASE_ASSET_X86_64%.tar.gz}" "${_AWG_BT_REL_ID}" "the release id is the archive's top-level directory"
_awgBtSelectRelease aarch64
assert_eq "${AWG_BT_RELEASE_ASSET_AARCH64} ${AWG_BT_RELEASE_ARCHIVE_SHA256_AARCH64} ${AWG_BT_RELEASE_BINARY_SHA256_AARCH64}" \
	"${_AWG_BT_REL_ASSET} ${_AWG_BT_REL_ARCHIVE_SHA256} ${_AWG_BT_REL_BINARY_SHA256}" "aarch64 selects the aarch64 asset and hashes"
run _awgBtSelectRelease armv7l
assert_rc 1 "${RC}" "no release is selected for another architecture"

# ── Settings under test: everything below the test root ─────────────────────
# shellcheck disable=SC2034 # read by the sourced installer's functions
{
AWG_BT_TRUST_ANCHOR="${T}"
AWG_BT_TRUSTED_UID="$(id -u)"
AWG_BT_STORE_DIR="${T}/usr/local/lib/amneziawg-install/boringtun"
AWG_BT_LIBEXEC_DIR="${T}/usr/local/libexec/amneziawg-install"
AWG_BT_RUN_DIR="${T}/run/amneziawg-install"
AWG_BT_CONFIG_DIR="${T}/etc/amnezia/amneziawg"
AWG_BT_SYSTEMD_DIR="${T}/etc/systemd/system"
AWG_BT_SYSTEMD_RUNTIME_DIR="${T}/run/systemd/system"
AWG_BT_WG_SOCKET_DIR="${T}/run/wireguard"
AWG_BT_AWG_SOCKET_DIR="${T}/run/amneziawg"
AWG_BT_SYS_DIR="${T}/sys"
AWG_BT_PROC_DIR="/proc"
AWG_BT_TUN_DEVICE="/dev/null"
AWG_BT_PATH="${MOCKBIN}:/usr/local/bin:/usr/bin:/bin"
AWG_BT_HOST_ARCH="x86_64"
AWG_BT_TMP_DIR="${T}/tmp"
AWG_BT_MODPROBE_OVERRIDE="${T}/etc/modprobe.d/amneziawg-install-boringtun.conf"
AWG_PROXY_INSTALL_PATHS="${T}/etc/systemd/system/amneziawg-proxy.service ${T}/usr/local/bin/amneziawg-proxy ${T}/etc/amneziawg-proxy/proxy.toml"
WEB_PANEL_SYSTEMD_UNIT="${T}/etc/systemd/system/amneziawg-web.service"
WEB_PANEL_ENV_FILE="${T}/etc/amneziawg-web/env.conf"
WEB_PANEL_LIFECYCLE_SCRIPT="${T}/usr/local/bin/amneziawg-install.sh"
AMNEZIAWG_DIR="${T}/etc/amnezia/amneziawg"
AWG_SYSTEMD_UNIT_DIR="${T}/etc/systemd/system"
AWG_MODULES_LOAD_FILE="${T}/etc/modules-load.d/amneziawg.conf"
AWG_SYSCTL_FILE="${T}/etc/sysctl.d/awg.conf"
AWG_APT_KEYRING_FILE="${T}/etc/apt/keyrings/amneziawg.gpg"
AMNEZIA_PPA_SOURCES_DIR="${T}/etc/apt/sources.list.d"
APT_FORCE_IPV4_CONF="${T}/etc/apt/apt.conf.d/99amneziawg-force-ipv4"
GAI_CONF="${T}/etc/gai.conf"
TMPDIR="${T}/tmp"
}
mkdir -p "${T}/usr/local/lib" "${T}/usr/local/bin" "${T}/etc" "${T}/run" "${T}/tmp" "${T}/sys/module"
chmod -R go-w "${T}"
PATH="${MOCKBIN}:${PATH}"

# systemctl: everything succeeds and is logged; show fails, so web-panel
# settings are read from the unit file itself.
cat >"${MOCKBIN}/systemctl" <<EOF
#!/bin/bash
echo "systemctl \$*" >>'${S}/log'
[[ "\$1" == show ]] && exit 1
exit 0
EOF
cat >"${MOCKBIN}/modinfo" <<EOF
#!/bin/bash
echo "modinfo \$*" >>'${S}/log'
exit "\$(cat '${S}/modinfo-rc' 2>/dev/null || echo 1)"
EOF
cat >"${MOCKBIN}/modprobe" <<EOF
#!/bin/bash
echo "modprobe \$*" >>'${S}/log'
echo 'install /bin/false '
EOF
# curl serves files from <state>/serve by the URL's last component, and logs
# its arguments. <state>/curl-rc makes it fail.
cat >"${MOCKBIN}/curl" <<EOF
#!/bin/bash
echo "curl \$*" >>'${S}/log'
OUTPUT=""
while ((\$#)); do
	case "\$1" in
		-o) OUTPUT="\$2"; shift 2 ;;
		*) URL="\$1"; shift ;;
	esac
done
[[ -f '${S}/curl-rc' ]] && exit "\$(cat '${S}/curl-rc')"
cp -- "${S}/serve/\${URL##*/}" "\${OUTPUT}" || exit 22
EOF
chmod 0755 "${MOCKBIN}"/*

# ── Fixture release ──────────────────────────────────────────────────────────
# A fake boringtun-cli that prints the release version and records every run,
# packed with the release layout, a MANIFEST and the embedded hashes set to
# the fixture's own.
FIXTURE="${T}/fixture"
FIXTURE_ID="${AWG_BT_RELEASE_ASSET_X86_64%.tar.gz}"
EXEC_LOG="${S}/binary-runs"
make_release_dir() { # <dir> [version printed]
	local DIR="$1" VERSION_TEXT="${2:-boringtun ${AWG_BT_RELEASE_VERSION}}"
	mkdir -p "${DIR}"
	printf '#!/bin/sh\necho "run $0" >>%s\n[ "$1" = --version ] && echo "%s"\nexit 0\n' "${EXEC_LOG}" "${VERSION_TEXT}" >"${DIR}/boringtun-cli"
	chmod 0755 "${DIR}/boringtun-cli"
	printf 'BSD-3-Clause fixture\n' >"${DIR}/LICENSE"
	printf 'fixture notices\n' >"${DIR}/THIRD-PARTY-LICENSES"
}
write_manifest() { # <dir> [key=value overrides...]
	local DIR="$1" KEY
	local -A M=(
		[artifact_format]=1 [name]=boringtun-cli [version]="${AWG_BT_RELEASE_VERSION}"
		[source_repository]="${AWG_BT_RELEASE_SOURCE_REPOSITORY}" [source_commit]="${AWG_BT_RELEASE_SOURCE_COMMIT}"
		[source_date_epoch]=1790626003 [target]=x86_64-unknown-linux-musl [os]=linux [arch]=x86_64 [libc]=musl
		[linkage]=static [rust_toolchain]=1.98.1 [rustc]="rustc 1.98.1" [cargo]="cargo 1.98.1"
		[build_command]="cargo build --release --locked -p boringtun-cli" [build_profile]="release,strip=symbols"
		[rustflags]="--remap-path-prefix=<source>=/boringtun" [binary]=boringtun-cli
		[binary_sha256]="$(sha256sum "${DIR}/boringtun-cli" | cut -d' ' -f1)"
		[license]="LICENSE (BSD-3-Clause)" [third_party_licenses]=THIRD-PARTY-LICENSES
	)
	shift
	for KEY in "$@"; do
		M["${KEY%%=*}"]="${KEY#*=}"
	done
	for KEY in ${AWG_BT_MANIFEST_KEYS}; do
		printf '%s=%s\n' "${KEY}" "${M[${KEY}]}"
	done >"${DIR}/MANIFEST"
}
pack() { # <source root holding FIXTURE_ID/> <archive>
	tar --no-recursion --numeric-owner --owner=0 --group=0 -czf "$2" -C "$1" \
		"${FIXTURE_ID}/" "${FIXTURE_ID}/LICENSE" "${FIXTURE_ID}/MANIFEST" "${FIXTURE_ID}/THIRD-PARTY-LICENSES" "${FIXTURE_ID}/boringtun-cli"
}
make_release_dir "${FIXTURE}/${FIXTURE_ID}"
write_manifest "${FIXTURE}/${FIXTURE_ID}"
mkdir -p "${S}/serve"
pack "${FIXTURE}" "${T}/good.tar.gz"
AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64="$(sha256sum "${T}/good.tar.gz" | cut -d' ' -f1)"
AWG_BT_RELEASE_BINARY_SHA256_X86_64="$(sha256sum "${FIXTURE}/${FIXTURE_ID}/boringtun-cli" | cut -d' ' -f1)"

# hostile <variant> <out>: the good archive with one change, written by
# python's tarfile.
hostile() {
	python3 - "${T}/good.tar.gz" "$2" "$1" "${FIXTURE_ID}" <<'PY'
import io, sys, tarfile
src, out, variant, stem = sys.argv[1:]
tin = tarfile.open(src, "r:gz")
members = [(m, tin.extractfile(m).read() if m.isfile() else None) for m in tin.getmembers()]
tout = tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT)
def add(info, data=None):
    tout.addfile(info, io.BytesIO(data) if data is not None else None)
def clone(m, **kw):
    n = tarfile.TarInfo(m.name)
    for a in ("mode", "uid", "gid", "size", "mtime", "type", "linkname"):
        setattr(n, a, getattr(m, a))
    for k, v in kw.items():
        setattr(n, k, v)
    return n
for m, data in members:
    lic = m.name.endswith("/LICENSE")
    if variant == "absolute" and lic:
        add(clone(m, name="/tmp/escape-absolute"), data); continue
    if variant == "dotdot" and lic:
        add(clone(m, name=stem + "/../escape-dotdot"), data); continue
    if variant == "symlink" and lic:
        add(clone(m, type=tarfile.SYMTYPE, linkname="/etc/passwd", size=0)); continue
    if variant == "hardlink" and lic:
        add(clone(m, type=tarfile.LNKTYPE, linkname=stem + "/boringtun-cli", size=0)); continue
    if variant == "chardev" and lic:
        add(clone(m, type=tarfile.CHRTYPE, size=0)); continue
    if variant == "fifo" and lic:
        add(clone(m, type=tarfile.FIFOTYPE, size=0)); continue
    if variant == "top-level":
        add(clone(m, name=m.name.replace(stem, stem + "-other", 1)), data); continue
    add(clone(m), data)
    if variant == "duplicate" and lic:
        add(clone(m), data)
    if variant == "extra" and lic:
        add(clone(m, name=stem + "/extra"), data)
tout.close()
PY
}

reset_store() {
	rm -rf -- "${T}/usr/local/lib/amneziawg-install" "${S}/serve"/* "${EXEC_LOG}" "${S}/curl-rc" "${T}/tmp"/*
	mkdir -p "${S}/serve"
	: >"${S}/log"
}

# serve <archive>: offer an archive as the x86_64 release asset.
serve() {
	cp -- "$1" "${S}/serve/${AWG_BT_RELEASE_ASSET_X86_64}"
}

store_names() {
	find "${AWG_BT_STORE_DIR}" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | LC_ALL=C sort | tr '\n' ' '
}

echo "=== Download and verification ==="
reset_store
serve "${T}/good.tar.gz"
run installBoringtunRelease
assert_rc 0 "${RC}" "the embedded release is downloaded, verified and installed"
assert_contains "curl --proto =https --proto-redir =https " "$(cat "${S}/log")" "the download is HTTPS only, redirects included"
assert_contains " ${AWG_BT_RELEASE_BASE_URL}/${AWG_BT_RELEASE_ASSET_X86_64}" "$(cat "${S}/log")" "from the exact release URL of the x86_64 asset"
assert_eq "1" "$(grep -c '^curl ' "${S}/log")" "the archive is downloaded once"
assert_eq "${FIXTURE_ID} current " "$(store_names)" "the store holds the release and the current link, nothing else"
assert_eq "${FIXTURE_ID}" "$(readlink "${AWG_BT_STORE_DIR}/current")" "current links to the release"
run _awgBtVerifyStore
assert_rc 0 "${RC}" "the installed store passes the runtime's own verification"
assert_eq "$(readlink -f "${AWG_BT_STORE_DIR}")/${FIXTURE_ID}/boringtun-cli" "${_AWG_BT_VERIFIED_BIN:-$(
	_awgBtVerifyStore
	printf '%s' "${_AWG_BT_VERIFIED_BIN}"
)}" "and names the installed binary"
assert_eq "755 644 644 644 755" "$(stat -c '%a' "${AWG_BT_STORE_DIR}/${FIXTURE_ID}" "${AWG_BT_STORE_DIR}/${FIXTURE_ID}/LICENSE" \
	"${AWG_BT_STORE_DIR}/${FIXTURE_ID}/MANIFEST" "${AWG_BT_STORE_DIR}/${FIXTURE_ID}/THIRD-PARTY-LICENSES" \
	"${AWG_BT_STORE_DIR}/${FIXTURE_ID}/boringtun-cli" | tr '\n' ' ' | sed 's/ $//')" "the release has the store's modes"
assert_true "the archive's MANIFEST is installed as it is" cmp -s "${FIXTURE}/${FIXTURE_ID}/MANIFEST" "${AWG_BT_STORE_DIR}/${FIXTURE_ID}/MANIFEST"
assert_true "the binary ran to report its version" test -s "${EXEC_LOG}"
assert_eq "" "$(grep -v "^run ${AWG_BT_STORE_DIR}/" "${EXEC_LOG}")" \
	"and ran only from the store, never from the download directory (which may be a noexec /tmp)"
assert_eq "0" "$(find "${T}/tmp" -mindepth 1 | wc -l)" "the private download directory is removed"

: >"${S}/log"
run installBoringtunRelease
assert_rc 0 "${RC}" "an install with the verified release already current reuses it"
assert_contains "already installed and verified; it is reused" "${OUT}" "and says so"
assert_eq "0" "$(grep -c '^curl ' "${S}/log")" "nothing is downloaded again"

# failed_download <label> <expected error> [archive]: the transaction fails
# closed, nothing enters the store, and the binary never runs.
failed_download() {
	local LABEL="$1" MESSAGE="$2"
	reset_store
	[[ -n "${3:-}" ]] && serve "$3"
	run installBoringtunRelease
	assert_rc 1 "${RC}" "${LABEL}"
	assert_contains "${MESSAGE}" "${ERR}" "  with: ${MESSAGE}"
	assert_eq "" "$(store_names)" "  and the store stays empty"
	assert_true "  and nothing is left in the download directory" test -z "$(find "${T}/tmp" -mindepth 1 -print -quit)"
}
reset_store
echo 22 >"${S}/curl-rc"
run installBoringtunRelease
assert_rc 1 "${RC}" "a failed download aborts"
assert_contains "could not download the BoringTun release ${AWG_BT_RELEASE_TAG}" "${ERR}" "and names the release"
assert_eq "" "$(store_names)" "and the store stays empty"

printf 'not the release\n' >"${T}/wrong.tar.gz"
failed_download "an archive with another SHA-256 is refused" "does not have the SHA-256 embedded in this installer" "${T}/wrong.tar.gz"
serve "${T}/wrong.tar.gz"
run installBoringtunRelease
assert_true "the binary never runs before the archive hash matches" test ! -e "${EXEC_LOG}"

# Hostile archives whose hash the installer was told to trust: the layout check
# still refuses them before anything is extracted.
GOOD_ARCHIVE_SHA256="${AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64}"
for VARIANT in absolute dotdot symlink hardlink chardev fifo top-level duplicate extra; do
	hostile "${VARIANT}" "${T}/hostile-${VARIANT}.tar.gz"
	AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64="$(sha256sum "${T}/hostile-${VARIANT}.tar.gz" | cut -d' ' -f1)"
	failed_download "an archive with a ${VARIANT} member is refused even when its hash is trusted" \
		"does not have the expected release layout" "${T}/hostile-${VARIANT}.tar.gz"
	assert_true "  and the binary never runs" test ! -e "${EXEC_LOG}"
done
assert_true "no member ever escaped the extraction directory" test ! -e /tmp/escape-absolute -a ! -e "${T}/escape-dotdot" -a ! -e "${T}/tmp/escape-dotdot"

# Well-formed archives with contents that do not match the embedded contract.
bad_release() { # <label> <expected error> <mutation...>
	local LABEL="$1" MESSAGE="$2"
	shift 2
	rm -rf -- "${T}/bad"
	cp -a -- "${FIXTURE}" "${T}/bad"
	"$@"
	pack "${T}/bad" "${T}/bad.tar.gz"
	AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64="$(sha256sum "${T}/bad.tar.gz" | cut -d' ' -f1)"
	failed_download "${LABEL}" "${MESSAGE}" "${T}/bad.tar.gz"
}
bad_release "a MANIFEST that names another source commit is refused" "MANIFEST does not describe" \
	write_manifest "${T}/bad/${FIXTURE_ID}" source_commit=0123456789abcdef0123456789abcdef01234567
bad_release "a MANIFEST of another version is refused" "MANIFEST does not describe" \
	write_manifest "${T}/bad/${FIXTURE_ID}" version=0.7.2
bad_release "a MANIFEST of another architecture is refused" "MANIFEST does not describe" \
	write_manifest "${T}/bad/${FIXTURE_ID}" arch=aarch64 target=aarch64-unknown-linux-musl
bad_release "a MANIFEST of another source repository is refused" "MANIFEST does not describe" \
	write_manifest "${T}/bad/${FIXTURE_ID}" source_repository=https://github.com/cloudflare/boringtun
bad_release "a MANIFEST with an unknown key is refused" "unexpected or repeated key" \
	eval "echo evil=1 >>'${T}/bad/${FIXTURE_ID}/MANIFEST'"
bad_release "a MANIFEST without a key is refused" "has no source_date_epoch" \
	sed -i '/^source_date_epoch=/d' "${T}/bad/${FIXTURE_ID}/MANIFEST"
bad_release "a binary with another SHA-256 is refused" "does not have the SHA-256 embedded" \
	eval "echo 'echo tampered' >>'${T}/bad/${FIXTURE_ID}/boringtun-cli'"
assert_true "  and the binary with the wrong hash never runs" test ! -e "${EXEC_LOG}"
SAVED_BINARY_SHA256="${AWG_BT_RELEASE_BINARY_SHA256_X86_64}"
bad_release "a binary that reports another version is refused" "--version printed 'boringtun 0.7.0'" \
	eval "make_release_dir '${T}/bad/${FIXTURE_ID}' 'boringtun 0.7.0'; write_manifest '${T}/bad/${FIXTURE_ID}'; AWG_BT_RELEASE_BINARY_SHA256_X86_64=\$(sha256sum '${T}/bad/${FIXTURE_ID}/boringtun-cli' | cut -d' ' -f1)"
AWG_BT_RELEASE_BINARY_SHA256_X86_64="${SAVED_BINARY_SHA256}"
AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64="${GOOD_ARCHIVE_SHA256}"

# The store is never replaced: another valid release that is current stays.
reset_store
serve "${T}/good.tar.gz"
run installBoringtunRelease
OTHER_ID="boringtun-cli-0.7.2-g0123456789ab-linux-x86_64-musl"
cp -a -- "${AWG_BT_STORE_DIR}/${FIXTURE_ID}" "${AWG_BT_STORE_DIR}/${OTHER_ID}"
write_manifest "${AWG_BT_STORE_DIR}/${OTHER_ID}" version=0.7.2 source_commit=0123456789abcdef0123456789abcdef01234567
ln -sfn "${OTHER_ID}" "${AWG_BT_STORE_DIR}/current"
run _awgBtVerifyStore
assert_rc 0 "${RC}" "(fixture: another release is current and verifies)"
: >"${S}/log"
run installBoringtunRelease
assert_rc 1 "${RC}" "an installed, valid, different release is never replaced"
assert_contains "never replaces an installed BoringTun binary" "${ERR}" "and the operator is told why"
assert_eq "${OTHER_ID}" "$(readlink "${AWG_BT_STORE_DIR}/current")" "current still selects the installed release"
assert_eq "0" "$(grep -c '^curl ' "${S}/log")" "and nothing is downloaded"

# An install interrupted between the rename and the link completes without a
# second download; a damaged release of that name is refused.
reset_store
serve "${T}/good.tar.gz"
run installBoringtunRelease
rm -f "${AWG_BT_STORE_DIR}/current"
: >"${S}/log"
run installBoringtunRelease
assert_rc 0 "${RC}" "a verified release without its current link is linked, not downloaded again"
assert_eq "0 ${FIXTURE_ID}" "$(grep -c '^curl ' "${S}/log") $(readlink "${AWG_BT_STORE_DIR}/current")" "without a download, to that release"
rm -f "${AWG_BT_STORE_DIR}/current"
echo tampered >>"${AWG_BT_STORE_DIR}/${FIXTURE_ID}/boringtun-cli"
run installBoringtunRelease
assert_rc 1 "${RC}" "a damaged release directory of that name is refused"
assert_true "and not made current" test ! -e "${AWG_BT_STORE_DIR}/current"

# A release directory that is already in the store is a candidate: it must be
# trusted before anything in it runs, and fully verified before current points
# at it. Every failure leaves current as it was.
echo "=== Candidate release in the store: verify, then run, then commit ==="
stage_candidate() { # a verified release in the store, without current
	reset_store
	serve "${T}/good.tar.gz"
	installBoringtunRelease >/dev/null 2>&1
	rm -f "${AWG_BT_STORE_DIR}/current" "${EXEC_LOG}"
	: >"${S}/log"
}
CANDIDATE="${AWG_BT_STORE_DIR}/${FIXTURE_ID}"
candidate_refused() { # <label>
	run installBoringtunRelease
	assert_rc 1 "${RC}" "$1"
	assert_true "  its binary never runs" test ! -e "${EXEC_LOG}"
	assert_true "  and current stays absent" test ! -e "${AWG_BT_STORE_DIR}/current" -a ! -L "${AWG_BT_STORE_DIR}/current"
}
stage_candidate
chmod 0777 "${CANDIDATE}"
candidate_refused "A: a release directory writable by others, current absent, is refused"
assert_contains "not root-owned or is writable by others" "${ERR}" "  as untrusted"
stage_candidate
chmod 0775 "${CANDIDATE}/boringtun-cli"
candidate_refused "a group-writable binary in the release directory is refused"
stage_candidate
chmod 0666 "${CANDIDATE}/MANIFEST"
candidate_refused "a MANIFEST writable by others is refused"
stage_candidate
mv "${CANDIDATE}/LICENSE" "${T}/license.real"
ln -s "${T}/license.real" "${CANDIDATE}/LICENSE"
candidate_refused "a member that is a symlink is refused"
rm -f "${T}/license.real"
stage_candidate
ln "${CANDIDATE}/boringtun-cli" "${T}/hardlink-to-binary"
candidate_refused "a binary with a second hard link is refused"
rm -f "${T}/hardlink-to-binary"
stage_candidate
: >"${CANDIDATE}/extra"
candidate_refused "a release directory with an extra member is refused"
stage_candidate
chmod 0755 "${AWG_BT_STORE_DIR%/*}"
chmod 0777 "${AWG_BT_STORE_DIR}"
candidate_refused "a store directory writable by others is refused before anything runs"
chmod 0755 "${AWG_BT_STORE_DIR}"
# B: another release is current; a candidate that fails leaves it selected.
stage_candidate
cp -a -- "${CANDIDATE}" "${AWG_BT_STORE_DIR}/${OTHER_ID}"
write_manifest "${AWG_BT_STORE_DIR}/${OTHER_ID}" version=0.7.2 source_commit=0123456789abcdef0123456789abcdef01234567
ln -s "${OTHER_ID}" "${AWG_BT_STORE_DIR}/current"
chmod 0777 "${CANDIDATE}"
run installBoringtunRelease
assert_rc 1 "${RC}" "B: with another release current, an untrusted candidate is refused"
assert_eq "${OTHER_ID}" "$(readlink "${AWG_BT_STORE_DIR}/current")" "  and current still selects the other release"
assert_true "  and no binary runs" test ! -e "${EXEC_LOG}"
# C: the binary is replaced right after its digest is taken. The replacement
# never runs: the node is checked again, trust included, just before the exec.
stage_candidate
cat >"${MOCKBIN}/sha256sum" <<EOF
#!/bin/bash
/usr/bin/sha256sum "\$@"
RC=\$?
for F in "\$@"; do
	if [[ "\$F" == "${CANDIDATE}/boringtun-cli" && ! -e "${S}/swapped" ]]; then
		printf '#!/bin/sh\necho "SWAPPED \$0" >>${EXEC_LOG}\necho "boringtun ${AWG_BT_RELEASE_VERSION}"\n' >"\$F.new"
		chmod 0755 "\$F.new"
		mv -f -- "\$F.new" "\$F"
		: >"${S}/swapped"
	fi
done
exit \$RC
EOF
chmod 0755 "${MOCKBIN}/sha256sum"
run installBoringtunRelease
rm -f "${MOCKBIN}/sha256sum"
assert_true "(fixture: the binary was swapped after its digest)" test -e "${S}/swapped"
rm -f "${S}/swapped"
assert_rc 1 "${RC}" "C: a binary replaced between its digest and its run is refused"
assert_contains "changed while it was verified" "${ERR}" "  because it changed"
assert_true "  the replacement never runs" test ! -e "${EXEC_LOG}"
assert_true "  and current stays absent" test ! -e "${AWG_BT_STORE_DIR}/current"
# D: the version check fails.
stage_candidate
make_release_dir "${CANDIDATE}" 'boringtun 0.7.0'
chmod 0755 "${CANDIDATE}/boringtun-cli"
write_manifest "${CANDIDATE}"
SAVED_BINARY_SHA256="${AWG_BT_RELEASE_BINARY_SHA256_X86_64}"
AWG_BT_RELEASE_BINARY_SHA256_X86_64="$(sha256sum "${CANDIDATE}/boringtun-cli" | cut -d' ' -f1)"
run installBoringtunRelease
AWG_BT_RELEASE_BINARY_SHA256_X86_64="${SAVED_BINARY_SHA256}"
assert_rc 1 "${RC}" "D: a candidate whose version check fails is refused"
assert_contains "--version printed 'boringtun 0.7.0'" "${ERR}" "  by its version"
assert_true "  after it ran from the store, trust first" test -s "${EXEC_LOG}"
assert_true "  and current stays absent" test ! -e "${AWG_BT_STORE_DIR}/current"
# E: the runtime's own release verification refuses after the candidate checks.
stage_candidate
run eval '_awgBtVerifyRelease() { echo "final verifier refuses" >&2; return 1; }; installBoringtunRelease'
assert_rc 1 "${RC}" "E: a candidate that the final release verification refuses is refused"
assert_contains "current was not changed" "${ERR}" "  and says current was not changed"
assert_true "  current stays absent" test ! -e "${AWG_BT_STORE_DIR}/current"
reset_store
serve "${T}/good.tar.gz"
run eval '_awgBtVerifyRelease() { return 1; }; installBoringtunRelease'
assert_rc 1 "${RC}" "E: a downloaded release that the final verification refuses is refused"
assert_true "  and current is never created" test ! -e "${AWG_BT_STORE_DIR}/current"
# A failure to switch leaves no link.
stage_candidate
run eval '_awgBtSwitchCurrent() { return 1; }; installBoringtunRelease'
assert_rc 1 "${RC}" "a failed switch of current fails the install"
assert_true "  and leaves current absent" test ! -e "${AWG_BT_STORE_DIR}/current"
# The verified candidate completes.
stage_candidate
run installBoringtunRelease
assert_rc 0 "${RC}" "a trusted, verified candidate is made current"
assert_eq "${FIXTURE_ID}" "$(readlink "${AWG_BT_STORE_DIR}/current")" "  selecting that release"
assert_eq "0" "$(grep -c '^curl ' "${S}/log")" "  without a download"

# A staging failure leaves no half-installed release under its final name.
reset_store
serve "${T}/good.tar.gz"
mkdir -p "${AWG_BT_STORE_DIR}"
eval 'cp() {
	[[ "${*: -1}" == *"/boringtun-cli" && "${*: -1}" == "${AWG_BT_STORE_DIR}"/* ]] && return 1
	command cp "$@"
}'
run installBoringtunRelease
unset -f cp
assert_rc 1 "${RC}" "a copy failure while staging aborts the install"
assert_eq "" "$(store_names)" "and leaves neither a staging directory nor a release in the store"

echo "=== No implicit upgrade ==="
# Only a fresh install acquires a release; management and the runtime layer
# only verify what is installed. A newer installer never replaces the binary.
CALLERS="$(grep -nE '^[[:space:]]*(if ! )?installBoringtunRelease\b|[^_]installBoringtunRelease;|_awgBtFetchRelease "|_awgBtSwitchCurrent\b' "${INSTALLER}" |
	grep -v '^[0-9]*:function ' | wc -l)"
assert_eq "3" "${CALLERS}" "the release is fetched, stored and switched only inside installBoringtunRelease, called only by the fresh install"
assert_contains "installBoringtunRelease" "$(declare -f installBoringtunHost)" "the fresh BoringTun install acquires the release"
for FUNCTION_NAME in _awgBtEnsureReady ensureAwgBackendReady awgBackendCtlMain awgBoringtunLaunchMain nonInteractiveAddClient setAwgProtocolMode; do
	assert_not_contains "installBoringtunRelease" "$(declare -f "${FUNCTION_NAME}")" "${FUNCTION_NAME} never installs a release"
done

echo "=== Store switch is atomic ==="
reset_store
serve "${T}/good.tar.gz"
run installBoringtunRelease
assert_true "current is a symlink" test -L "${AWG_BT_STORE_DIR}/current"
assert_eq "0" "$(find "${AWG_BT_STORE_DIR}" -name '.current.tmp.*' -o -name ".${FIXTURE_ID}.tmp.*" | wc -l)" \
	"no temporary link or staging directory is left behind"

echo "=== Standalone proxy guard ==="
# Every authoritative path counts on its own, a leftover proxy.toml included.
for PROXY_PATH in ${AWG_PROXY_INSTALL_PATHS}; do
	mkdir -p "${PROXY_PATH%/*}"
	: >"${PROXY_PATH}"
	assert_eq "${PROXY_PATH}" "$(boringtunProxyInstallPaths)" "${PROXY_PATH##*/} shows an installed standalone proxy"
	rm -f "${PROXY_PATH}"
done
PROXY_BINARY="$(awk '{print $2}' <<<"${AWG_PROXY_INSTALL_PATHS}")"
ln -s /nonexistent "${PROXY_BINARY}"
assert_eq "${PROXY_BINARY}" "$(boringtunProxyInstallPaths)" "a dangling symlink at a proxy path counts too"
rm -f "${PROXY_BINARY}"
assert_eq "" "$(boringtunProxyInstallPaths)" "without them no proxy is found"

echo "=== Web panel lifecycle-script freshness ==="
MARKER_LINE="AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST=\"${AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST}\""
mkdir -p "${WEB_PANEL_SYSTEMD_UNIT%/*}" "${WEB_PANEL_LIFECYCLE_SCRIPT%/*}" "${T}/opt/amneziawg-web/bin"
rm -f "${WEB_PANEL_SYSTEMD_UNIT}" "${WEB_PANEL_ENV_FILE}"
run webPanelLifecycleScriptSupportsBoringtun
assert_rc 0 "${RC}" "without a web panel there is nothing to check"
printf '[Service]\nExecStart=/usr/local/bin/amneziawg-web\n' >"${WEB_PANEL_SYSTEMD_UNIT}"
run webPanelLifecycleScriptSupportsBoringtun
assert_rc 1 "${RC}" "a web panel whose lifecycle-script copy is missing is refused"
cp -- "${INSTALLER}" "${WEB_PANEL_LIFECYCLE_SCRIPT}"
run webPanelLifecycleScriptSupportsBoringtun
assert_rc 0 "${RC}" "a copy of this installer is accepted"
grep -vxF "${MARKER_LINE}" "${INSTALLER}" >"${WEB_PANEL_LIFECYCLE_SCRIPT}"
run webPanelLifecycleScriptSupportsBoringtun
assert_rc 1 "${RC}" "a copy without the capability line (an older installer) is refused"
{
	grep -vxF "${MARKER_LINE}" "${INSTALLER}"
	echo "# ${MARKER_LINE}"
	echo "X${MARKER_LINE}"
	echo "AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST=\"boringtun-host-v0\""
} >"${WEB_PANEL_LIFECYCLE_SCRIPT}"
run webPanelLifecycleScriptSupportsBoringtun
assert_rc 1 "${RC}" "only the exact capability line counts, not a comment, prefix or other version"
printf '#!/bin/bash\n%s\ntouch %s/sourced\n' "${MARKER_LINE}" "${T}" >"${WEB_PANEL_LIFECYCLE_SCRIPT}"
run webPanelLifecycleScriptSupportsBoringtun
assert_rc 0 "${RC}" "a copy with the capability line is accepted"
assert_true "and the copy is read as data, never run or sourced" test ! -e "${T}/sourced"
# The panel's configured AWG_INSTALL_SCRIPT is the copy that is checked.
CONFIGURED_COPY="${T}/opt/amneziawg-web/bin/amneziawg-install.sh"
printf '[Service]\nEnvironment=AWG_INSTALL_SCRIPT=%s\nExecStart=/usr/local/bin/amneziawg-web\n' "${CONFIGURED_COPY}" >"${WEB_PANEL_SYSTEMD_UNIT}"
assert_eq "${CONFIGURED_COPY}" "$(webPanelLifecycleScriptPath)" "the copy named by the panel's AWG_INSTALL_SCRIPT is the one checked"
run webPanelLifecycleScriptSupportsBoringtun
assert_rc 1 "${RC}" "a fresh default copy does not stand in for a missing configured copy"
cp -- "${INSTALLER}" "${CONFIGURED_COPY}"
run webPanelLifecycleScriptSupportsBoringtun
assert_rc 0 "${RC}" "a current configured copy is accepted"
rm -f "${WEB_PANEL_SYSTEMD_UNIT}" "${WEB_PANEL_LIFECYCLE_SCRIPT}" "${CONFIGURED_COPY}"

echo "=== Kernel module decision ==="
decide() {
	boringtunKernelModuleDecision && echo "override=${_AWG_BT_WRITE_MODPROBE_OVERRIDE}"
}
rm -f "${S}/modinfo-rc"
run decide
assert_eq "0|override=0" "${RC}|${OUT}" "without an installed module nothing is blocked"
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
run decide
assert_rc 1 "${RC}" "a loaded module is refused"
assert_contains "never unloads it" "${ERR}" "and never unloaded"
assert_not_contains "modprobe -r" "$(cat "${S}/log")" "no module is unloaded"
rmdir "${AWG_BT_SYS_DIR}/module/amneziawg"
echo 0 >"${S}/modinfo-rc"
AUTO_INSTALL=y
unset AWG_BORINGTUN_BLOCK_KERNEL_MODULE
run decide
assert_rc 1 "${RC}" "AUTO_INSTALL never blocks an installed module without explicit consent"
assert_contains "AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y" "${ERR}" "and names the consent variable"
AWG_BORINGTUN_BLOCK_KERNEL_MODULE=yes run decide
assert_rc 1 "${RC}" "only the exact value y is consent"
AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y run decide
assert_eq "0|override=1" "${RC}|${OUT}" "AWG_BORINGTUN_BLOCK_KERNEL_MODULE=y with AUTO_INSTALL accepts the block"
AUTO_INSTALL=n
RUN_INPUT="n" run decide
assert_rc 1 "${RC}" "an interactive install that declines the block is refused"
RUN_INPUT="" run decide
assert_rc 1 "${RC}" "the interactive default is not to block"
RUN_INPUT="y" run decide
assert_eq "0|override=1" "${RC}|${OUT}" "an interactive install that accepts the block goes on"
mkdir -p "${AWG_BT_MODPROBE_OVERRIDE%/*}"
_awgBtRenderModprobeOverride >"${AWG_BT_MODPROBE_OVERRIDE}"
chmod 0644 "${AWG_BT_MODPROBE_OVERRIDE}"
run decide
assert_eq "0|override=0" "${RC}|${OUT}" "a module the installer's override already blocks needs no new consent"
rm -f "${AWG_BT_MODPROBE_OVERRIDE}" "${S}/modinfo-rc"
# shellcheck disable=SC2034 # read by boringtunKernelModuleDecision
AUTO_INSTALL=y
run installBoringtunModprobeOverride
assert_rc 0 "${RC}" "the override is written and proven in force"
assert_eq "644 $(_awgBtRenderModprobeOverride)" "$(stat -c '%a' "${AWG_BT_MODPROBE_OVERRIDE}") $(cat "${AWG_BT_MODPROBE_OVERRIDE}")" \
	"as the rendered install command, mode 0644"
printf '#!/bin/bash\necho "insmod /lib/modules/x/amneziawg.ko"\n' >"${MOCKBIN}/modprobe"
run installBoringtunModprobeOverride
assert_rc 1 "${RC}" "an override that modprobe does not apply fails the install"
assert_contains "is not in force" "${ERR}" "and says so"
# The dry run on the Ubuntu 26.04 coexistence job, while the module's
# dependencies were not loaded yet.
printf '#!/bin/bash\nprintf "%%s \\n" %s %s %s "install /bin/false"\n' \
	"'insmod /lib/modules/7.0.0-1012-azure/kernel/net/ipv4/udp_tunnel.ko.zst'" \
	"'insmod /lib/modules/7.0.0-1012-azure/kernel/net/ipv6/ip6_udp_tunnel.ko.zst'" \
	"'insmod /lib/modules/7.0.0-1012-azure/kernel/lib/crypto/libcurve25519.ko.zst'" >"${MOCKBIN}/modprobe"
run installBoringtunModprobeOverride
assert_rc 0 "${RC}" "an override in force behind dependency insmods, as on Ubuntu 26.04, passes"
printf '#!/bin/bash\nprintf "%%s \\n" %s %s\n' \
	"'insmod /lib/modules/7.0.0-1012-azure/kernel/net/ipv4/udp_tunnel.ko.zst'" \
	"'insmod /lib/modules/7.0.0-1012-azure/updates/dkms/amneziawg.ko.zst'" >"${MOCKBIN}/modprobe"
run installBoringtunModprobeOverride
assert_rc 1 "${RC}" "dependency insmods followed by the module's own insmod fail the install"
printf '#!/bin/bash\necho "modprobe $*" >>%s/log\necho "install /bin/false "\n' "${S}" >"${MOCKBIN}/modprobe"
rm -f "${AWG_BT_MODPROBE_OVERRIDE}"

echo "=== Host support checks ==="
support() {
	checkBoringtunHostSupport && echo supported
}
mkdir -p "${AWG_BT_SYSTEMD_RUNTIME_DIR}"
mkdir -p "${T}/proc-ipv6/sys/net/ipv6"
AWG_BT_PROC_DIR="${T}/proc-ipv6"
AWG_BT_TUN_DEVICE="/dev/null"
OS=ubuntu
run support
assert_eq "0|supported" "${RC}|${OUT}" "an Ubuntu x86_64 host with systemd, TUN and IPv6 is supported"
OS=debian
run support
assert_eq "0|supported" "${RC}|${OUT}" "so is Debian"
for OTHER_OS in fedora centos almalinux rocky; do
	OS="${OTHER_OS}"
	run support
	assert_rc 1 "${RC}" "${OTHER_OS} is refused"
done
OS=ubuntu
AWG_BT_HOST_ARCH=armv7l
run support
assert_rc 1 "${RC}" "an unsupported architecture is refused before anything is installed"
assert_contains "only for x86_64 and aarch64" "${ERR}" "and the supported architectures are named"
AWG_BT_HOST_ARCH=aarch64
run support
assert_rc 0 "${RC}" "aarch64 is supported"
# shellcheck disable=SC2034 # read by _awgBtHostArch
AWG_BT_HOST_ARCH=x86_64
mv "${AWG_BT_SYSTEMD_RUNTIME_DIR}" "${AWG_BT_SYSTEMD_RUNTIME_DIR}.off"
run support
assert_rc 1 "${RC}" "a host without systemd is refused"
mv "${AWG_BT_SYSTEMD_RUNTIME_DIR}.off" "${AWG_BT_SYSTEMD_RUNTIME_DIR}"
mkdir -p "${T}/etc/amneziawg-proxy"
: >"${T}/etc/amneziawg-proxy/proxy.toml"
run support
assert_rc 1 "${RC}" "a host with the standalone proxy is refused"
assert_contains "cannot be used behind the standalone proxy" "${ERR}" "with the reason"
assert_contains "Keep the kernel backend, or uninstall the proxy first" "${ERR}" "and both ways forward"
assert_not_contains "set-boringtun-imitation" "${ERR}" "without pointing to a command this version does not have"
assert_true "the proxy is left installed" test -e "${T}/etc/amneziawg-proxy/proxy.toml"
rm -f "${T}/etc/amneziawg-proxy/proxy.toml"
printf '[Service]\nExecStart=/usr/local/bin/amneziawg-web\n' >"${WEB_PANEL_SYSTEMD_UNIT}"
grep -vxF "${MARKER_LINE}" "${INSTALLER}" >"${WEB_PANEL_LIFECYCLE_SCRIPT}"
run support
assert_rc 1 "${RC}" "a host whose web panel runs a stale lifecycle copy is refused"
assert_contains "predates BoringTun host support" "${ERR}" "with the reason"
assert_true "and the web panel's copy is not overwritten" test "$(grep -c "${MARKER_LINE}" "${WEB_PANEL_LIFECYCLE_SCRIPT}")" = 0
rm -f "${WEB_PANEL_SYSTEMD_UNIT}" "${WEB_PANEL_LIFECYCLE_SCRIPT}"
AWG_BT_TUN_DEVICE="${T}/no-tun"
run support
assert_rc 1 "${RC}" "a host without /dev/net/tun is refused"
# shellcheck disable=SC2034 # read by _awgBtCheckPlatform
AWG_BT_TUN_DEVICE="/dev/null"
AWG_BT_PROC_DIR="${T}/proc-no-ipv6"
mkdir -p "${AWG_BT_PROC_DIR}/sys/net"
run support
assert_rc 1 "${RC}" "a host without the IPv6 socket family is refused"
AWG_BT_PROC_DIR="${T}/proc-ipv6"
mkdir -p "${AWG_BT_SYS_DIR}/module/amneziawg"
run support
assert_rc 1 "${RC}" "a host with the kernel module loaded is refused"
rmdir "${AWG_BT_SYS_DIR}/module/amneziawg"

echo "=== Package selection ==="
cat >"${MOCKBIN}/apt-get" <<EOF
#!/bin/bash
echo "apt-get \$*" >>'${S}/apt'
exit 0
EOF
cat >"${MOCKBIN}/apt" <<EOF
#!/bin/bash
echo "apt \$*" >>'${S}/apt'
exit 0
EOF
chmod 0755 "${MOCKBIN}/apt-get" "${MOCKBIN}/apt"
packages() {
	prepareUbuntuAmneziaPpaForInstall() { echo "prepareUbuntuAmneziaPpaForInstall" >>"${S}/apt"; }
	configureDebianAmneziaAptSource() { echo "configureDebianAmneziaAptSource $*" >>"${S}/apt"; }
	installKernelHeaders() { echo "installKernelHeaders $*" >>"${S}/apt"; }
	installBoringtunHostPackages
}
: >"${S}/apt"
OS=ubuntu
run packages
assert_eq "prepareUbuntuAmneziaPpaForInstall
apt-get install -y --no-install-recommends amneziawg-tools
apt-get install -y iptables nftables qrencode" "$(cat "${S}/apt")" \
	"Ubuntu: the shared PPA setup, then amneziawg-tools without recommends, then the firewall and QR tools"
: >"${S}/apt"
# shellcheck disable=SC2034 # read by installBoringtunHostPackages
OS=debian
run packages
assert_eq "configureDebianAmneziaAptSource 0
apt-get update
apt-get install -y --no-install-recommends amneziawg-tools
apt-get install -y qrencode iptables nftables" "$(cat "${S}/apt")" \
	"Debian: the PPA source without deb-src, then amneziawg-tools without recommends, then the other tools"
assert_not_contains "dkms" "$(cat "${S}/apt")" "no DKMS"
assert_not_contains "amneziawg " "$(cat "${S}/apt") " "no amneziawg module metapackage"
assert_not_contains "headers" "$(cat "${S}/apt")" "no kernel headers"
printf '#!/bin/bash\necho "apt-get $*" >>%s/apt\n[[ "$*" == *amneziawg-tools* ]] && exit 100\nexit 0\n' "${S}" >"${MOCKBIN}/apt-get"
: >"${S}/apt"
run packages
assert_rc 1 "${RC}" "a failed amneziawg-tools install aborts"
assert_not_contains "qrencode" "$(cat "${S}/apt")" "before anything else is installed"
printf '#!/bin/bash\necho "apt-get $*" >>%s/apt\nexit 0\n' "${S}" >"${MOCKBIN}/apt-get"
# The Debian source function adds deb-src only for the kernel.
DEBIAN_SOURCE_BODY="$(declare -f configureDebianAmneziaAptSource)"
assert_contains 'if [[ "${INCLUDE_DEB_SRC}" == 1 ]]; then' "${DEBIAN_SOURCE_BODY}" "the Debian deb-src PPA line depends on the caller"
assert_eq "1" "$(declare -f installAmneziaWG | grep -c 'configureDebianAmneziaAptSource 1')" "the kernel install keeps its deb-src line"

echo "=== Preflight ==="
# Everything but the scratch lifecycle is stubbed; that lifecycle is the
# runtime layer's own, tested in tests/test-boringtun-runtime.sh and live.
preflight() {
	_awgBtCheckKernelModule() { echo check-module >>"${S}/pre"; return "${PF_MODULE_RC:-0}"; }
	_awgBtCheckPlatform() { echo check-platform >>"${S}/pre"; }
	_awgBtVerifyStore() { echo verify-store >>"${S}/pre"; }
	_awgBtCheckHelpers() { echo check-helpers >>"${S}/pre"; }
	_awgBtCheckBaseUnit() { echo "check-base-unit $1" >>"${S}/pre"; }
	awgBackendCreateScratchInterface() {
		echo "create $1" >>"${S}/pre"
		[[ "${PF_CREATE_RC:-0}" == 0 ]] || return 1
		_AWG_BT_SCRATCH_TOKENS[$1]="0123456789abcdef0123456789abcdef"
		mkdir -p "${T}/net/$1"
		echo "created $1" >>"${S}/created"
	}
	awgBackendDestroyScratchInterface() {
		echo "destroy $1" >>"${S}/pre"
		[[ "${PF_LEAK:-0}" == 1 ]] || rm -rf "${T}/net/$1"
		return "${PF_DESTROY_RC:-0}"
	}
	_awgBtLinkIsTun() { [[ "${PF_TUN:-1}" == 1 ]]; }
	_awgBtUapiReady() { [[ "${PF_UAPI:-1}" == 1 ]]; }
	_awgBtLinkExists() { [[ -e "${T}/net/$1" ]]; }
	_awgBtListenPort() { echo 43210; }
	awg() {
		echo "awg $*" >>"${S}/pre"
		case "$1" in
			genkey) echo "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=" ;;
			setconf) cp -- "$3" "${S}/preflight.conf"; return "${PF_SETCONF_RC:-0}" ;;
			show) return 0 ;;
		esac
	}
	# shellcheck disable=SC2034 # read by boringtunHostPreflight
	SERVER_AWG_NIC=awg0 SERVER_AWG_JC=4 SERVER_AWG_JMIN=40 SERVER_AWG_JMAX=70
	# shellcheck disable=SC2034 # read by boringtunHostPreflight
	SERVER_AWG_S1=15 SERVER_AWG_S2=25 SERVER_AWG_S3=35 SERVER_AWG_S4=45
	# shellcheck disable=SC2034 # read by boringtunHostPreflight
	SERVER_AWG_H1=100-200 SERVER_AWG_H2=300-400 SERVER_AWG_H3=500-600 SERVER_AWG_H4=700-800
	boringtunHostPreflight
}
: >"${S}/pre"
run preflight
assert_rc 0 "${RC}" "the preflight passes when a scratch BoringTun serves an AWG 2.0 configuration"
PREFLIGHT_IF="$(sed -n 's/^create //p' "${S}/pre")"
assert_eq "check-module
check-platform
verify-store
check-helpers
check-base-unit awg0
awg genkey
create ${PREFLIGHT_IF}
awg setconf ${PREFLIGHT_IF} ${T}/tmp/${PREFLIGHT_IF}.conf
awg show ${PREFLIGHT_IF} dump
destroy ${PREFLIGHT_IF}" "$(sed "s#${T}/tmp/amneziawg-preflight\.[A-Za-z0-9]*/preflight.conf#${T}/tmp/${PREFLIGHT_IF}.conf#" "${S}/pre")" \
	"it checks module, platform, store, helpers and base unit, then runs a scratch instance and tears it down"
assert_eq "[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 25
S3 = 35
S4 = 45
H1 = 100-200
H2 = 300-400
H3 = 500-600
H4 = 700-800" "$(cat "${S}/preflight.conf")" "the scratch instance gets the server's chosen AWG 2.0 parameters, no ListenPort"
assert_eq "0" "$(find "${T}/tmp" -mindepth 1 -name 'amneziawg-preflight.*' | wc -l)" "the preflight's private directory is removed"
preflight_fails() { # <label> <message> <VAR=value...>
	local LABEL="$1" MESSAGE="$2"
	shift 2
	: >"${S}/pre"
	: >"${S}/created"
	local "$@"
	run preflight
	assert_rc 1 "${RC}" "${LABEL}"
	assert_contains "${MESSAGE}" "${ERR}" "  with: ${MESSAGE}"
	if [[ -s "${S}/created" ]]; then
		assert_true "  and the scratch instance is torn down" grep -q '^destroy ' "${S}/pre"
	else
		assert_true "  and nothing is torn down that was never created" test "$(grep -c '^destroy ' "${S}/pre")" = 0
	fi
}
preflight_fails "the preflight fails when the module check fails" "the BoringTun preflight failed" PF_MODULE_RC=1
preflight_fails "the preflight fails when no scratch instance starts" "could not be started" PF_CREATE_RC=1
preflight_fails "the preflight fails when the scratch link is not a TUN device" "is not a TUN device" PF_TUN=0
preflight_fails "the preflight fails when the UAPI does not answer" "UAPI does not answer" PF_UAPI=0
preflight_fails "the preflight fails when awg setconf rejects the configuration" "rejected the AWG 2.0 configuration" PF_SETCONF_RC=1
preflight_fails "the preflight fails when the teardown fails" "not torn down cleanly" PF_DESTROY_RC=1
preflight_fails "the preflight fails when the teardown leaves the link" "left its link, sockets or records behind" PF_LEAK=1
assert_contains "No VPN configuration was written" "${ERR}" "and says that no VPN state was written"

echo "=== Fresh install order and failure semantics ==="
# Every step is stubbed and logged, so the order can be checked and each step
# made to fail. The kernel implementation logs KERNEL if anything reaches it.
install_flow() {
	local STEP
	for STEP in checkBoringtunHostSupport installQuestions enable_apt_ipv4 disable_apt_ipv4 installBoringtunHostPackages \
		installBoringtunRelease installBoringtunModprobeOverride _awgBtInstallHelpers boringtunHostPreflight \
		writeAwgServerInstallState _awgBtInstallServiceFiles _awgBtCheckServedByBoringtun newClient; do
		eval "${STEP}() { echo '${STEP}' \"\$*\" >>'${S}/flow'; [[ \"\${FAIL_STEP:-}\" != '${STEP}' ]]; }"
	done
	for STEP in ensureAmneziawgKernelModule installKernelHeaders sanitizeAwgDkmsConf modprobe dkms depmod; do
		eval "${STEP}() { echo 'KERNEL ${STEP}' \"\$*\" >>'${S}/flow'; }"
	done
	systemctl() {
		echo "systemctl $*" >>"${S}/flow"
		[[ "$1" == start && "${FAIL_START:-0}" == 1 ]] && return 1
		return 0
	}
	shouldCreateInitialClient() { return 0; }
	_AWG_BT_WRITE_MODPROBE_OVERRIDE="${WRITE_OVERRIDE:-0}"
	SERVER_AWG_NIC=awg0
	installBoringtunHost
}
flow() {
	sed 's/ *$//' "${S}/flow"
}
: >"${S}/flow"
run install_flow
assert_rc 0 "${RC}" "a fresh BoringTun install completes"
assert_eq "checkBoringtunHostSupport
installQuestions
enable_apt_ipv4
installBoringtunHostPackages
installBoringtunRelease
disable_apt_ipv4
_awgBtInstallHelpers
boringtunHostPreflight
writeAwgServerInstallState
_awgBtInstallServiceFiles awg0
systemctl enable awg-quick@awg0
systemctl start awg-quick@awg0
_awgBtCheckServedByBoringtun awg0
newClient" "$(flow)" \
	"checks, questions, packages, release, helpers, preflight, then VPN state, service files, enable, start, verify, client"
assert_contains "running on the BoringTun backend (experimental)" "${OUT}" "and reports the BoringTun backend"
assert_not_contains "KERNEL" "$(flow)" "nothing reaches the kernel implementation"
: >"${S}/flow"
WRITE_OVERRIDE=1 run install_flow
assert_eq "disable_apt_ipv4
installBoringtunModprobeOverride
_awgBtInstallHelpers" "$(flow | sed -n '/^disable_apt_ipv4$/,/^_awgBtInstallHelpers$/p')" \
	"an accepted module block is written after the packages and before the helpers and preflight"
for STEP in checkBoringtunHostSupport installBoringtunRelease installBoringtunModprobeOverride _awgBtInstallHelpers boringtunHostPreflight; do
	: >"${S}/flow"
	WRITE_OVERRIDE=1 FAIL_STEP="${STEP}" run install_flow
	assert_rc 1 "${RC}" "a failure of ${STEP} aborts the install"
	assert_not_contains "writeAwgServerInstallState" "$(flow)" "  before any VPN state is written"
	assert_not_contains "systemctl" "$(flow)" "  and before any service is touched"
done
: >"${S}/flow"
FAIL_START=1 run install_flow
assert_rc 1 "${RC}" "a service start failure fails the install"
assert_contains "systemctl enable awg-quick@awg0" "$(flow)" "  leaving the unit enabled, as the kernel install does"
assert_not_contains "newClient" "$(flow)" "  without creating a client"
assert_contains "did not start" "${OUT}" "  with BoringTun diagnostics"
assert_contains "never falls back to the kernel module" "${OUT}" "  that rule out a kernel fallback"
assert_not_contains "KERNEL" "$(flow)" "  and nothing reaches the kernel implementation"
: >"${S}/flow"
FAIL_STEP=_awgBtCheckServedByBoringtun run install_flow
assert_rc 1 "${RC}" "a unit that is active but not served by the verified BoringTun daemon fails the install"
assert_eq "systemctl stop awg-quick@awg0" "$(flow | tail -1)" "  and the unit is stopped again"
assert_not_contains "newClient" "$(flow)" "  without creating a client"

# installAmneziaWG sends only AWG_BACKEND=boringtun to the BoringTun flow.
route() {
	ensureSupportedInstallDistro() { :; }
	installBoringtunHost() { echo boringtun-flow; }
	installQuestions() { echo kernel-flow; exit 0; }
	installAmneziaWG
}
_AWG_BACKEND_REQUESTED=boringtun run route
assert_eq "boringtun-flow" "${OUT}" "a fresh install with AWG_BACKEND=boringtun takes the BoringTun flow"
_AWG_BACKEND_REQUESTED="" run route
assert_eq "kernel-flow" "${OUT}" "a fresh install without AWG_BACKEND takes the kernel flow"
_AWG_BACKEND_REQUESTED=userspace run route
assert_rc 1 "${RC}" "a fresh install with an unknown AWG_BACKEND takes neither flow"
assert_eq "" "${OUT}" "  and installs nothing"

echo "=== Uninstall ==="
AWG_BT_PROC_DIR="/proc"
IF="awgu0"
WG_SOCK="${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
AWG_SOCK="${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"
ATTEMPT=0123456789abcdef0123456789abcdef
DEAD_PID=999999
# install_runtime: a verified store, the generated helpers and the load
# override, as a BoringTun install leaves them.
install_runtime() {
	reset_store
	serve "${T}/good.tar.gz"
	installBoringtunRelease >/dev/null 2>&1
	_awgBtInstallHelpers
	mkdir -p "${AWG_BT_MODPROBE_OVERRIDE%/*}" "${AWG_BT_WG_SOCKET_DIR}" "${AWG_BT_AWG_SOCKET_DIR}"
	_awgBtRenderModprobeOverride >"${AWG_BT_MODPROBE_OVERRIDE}"
}
# record_attempt <phase> [flag...]: a start attempt of IF as poststop leaves
# it, recording the UAPI nodes now at the interface's paths and a daemon that
# is gone.
record_attempt() {
	local PHASE="$1" FLAG
	shift
	(
		_AWG_BT_ATTEMPT="${ATTEMPT}"
		_awgBtPrepareRunDir || exit 1
		_awgBtStateNew "${AWG_BT_CONFIG_DIR}/${IF}.conf" || exit 1
		_AWG_BT_STATE[PHASE]="${PHASE}"
		_AWG_BT_STATE[PID]="${DEAD_PID}"
		_AWG_BT_STATE[PID_START]=1
		_AWG_BT_STATE[WG_SOCK]="$(_awgBtPathId "${WG_SOCK}")"
		_AWG_BT_STATE[AWG_SOCK]="$(_awgBtPathId "${AWG_SOCK}")"
		_awgBtStateSave "${IF}" && _awgBtFlagsArm "${IF}" || exit 1
		for FLAG in "$@"; do
			_awgBtFlagRaise "${IF}" "${FLAG}" || exit 1
		done
	) || not_ok "(fixture: recording attempt ${PHASE} $*)"
}
attempt_files() {
	find "${AWG_BT_RUN_DIR}" -maxdepth 1 -name "${IF}@*" 2>/dev/null | wc -l
}
dead_socket() { # <path>: a UNIX socket node nobody serves
	python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$1"
}
LISTENER_N=0
listening_socket() { # <path>: a UNIX socket another process listens on
	LISTENER_N=$((LISTENER_N + 1))
	python3 -c 'import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); open(sys.argv[2], "w").close(); time.sleep(120)' \
		"$1" "${T}/listening-${LISTENER_N}" &
	echo "$!" >>"${T}/background"
	LAST_LISTENER=$!
	for _ in $(seq 50); do [[ -e "${T}/listening-${LISTENER_N}" ]] && break; sleep 0.1; done
}
stop_listener() {
	kill -KILL "${LAST_LISTENER}" 2>/dev/null
	wait "${LAST_LISTENER}" 2>/dev/null
}
clear_uapi() {
	rm -f "${WG_SOCK}" "${AWG_SOCK}"
	rm -f "${AWG_BT_RUN_DIR}/${IF}@"*
}
runtime_kept() {
	[[ -d "${AWG_BT_STORE_DIR}" && -e "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl" && -e "${AWG_BT_MODPROBE_OVERRIDE}" ]]
}

install_runtime
# A socket another process serves for another interface stays.
listening_socket "${AWG_BT_WG_SOCKET_DIR}/other0.sock"
# A daemon of the interface still runs: nothing is removed.
cp -- "$(command -v bash)" "${AWG_BT_STORE_DIR}/${FIXTURE_ID}/boringtun-cli.running"
"${AWG_BT_STORE_DIR}/${FIXTURE_ID}/boringtun-cli.running" -c 'sleep 120; :' fake "${IF}" &
DAEMON_PID=$!
echo "${DAEMON_PID}" >>"${T}/background"
sleep 0.3
assert_eq "${DAEMON_PID}" "$(boringtunDaemonsOf "${IF}")" "a running BoringTun daemon of the interface is found"
assert_eq "" "$(boringtunDaemonsOf other0)" "and only for its own interface"
run uninstallBoringtunRuntime "${IF}"
assert_rc 1 "${RC}" "the BoringTun uninstall refuses while a daemon of the interface runs"
assert_true "  and removes nothing" runtime_kept
kill -KILL "${DAEMON_PID}"
wait "${DAEMON_PID}" 2>/dev/null
rm -f "${AWG_BT_STORE_DIR}/${FIXTURE_ID}/boringtun-cli.running"

echo "--- S1: unfinished teardown evidence is kept"
# Exactly the review's case: poststop returns 0, and the attempt it keeps
# records a PostDown replay that did not finish (its config is unreadable).
(
	export INVOCATION_ID="${ATTEMPT}"
	_awgBtCurrentAttempt && _awgBtPrepareRunDir &&
		_awgBtStateNew "${T}/missing/${IF}.conf" && _AWG_BT_STATE[PHASE]=launched &&
		_awgBtStateSave "${IF}" && _awgBtFlagsArm "${IF}" && _awgBtFlagRaise "${IF}" up
) || not_ok "(fixture: an up attempt)"
INVOCATION_ID="${ATTEMPT}" run _awgBtCtlPoststop "${IF}"
assert_rc 0 "${RC}" "(fixture: poststop returns 0)"
assert_true "(fixture: poststop keeps the attempt, its replay flag raised and no done flag)" \
	test -e "${AWG_BT_RUN_DIR}/${IF}@${ATTEMPT}.replay" -a ! -e "${AWG_BT_RUN_DIR}/${IF}@${ATTEMPT}.done"
FILES_BEFORE="$(attempt_files)"
run uninstallBoringtunRuntime "${IF}"
assert_rc 1 "${RC}" "an attempt whose PostDown replay did not finish fails the BoringTun uninstall"
assert_contains "did not finish" "${ERR}" "  saying the teardown did not finish"
assert_contains "rerun the uninstall" "${ERR}" "  and how to go on"
assert_eq "${FILES_BEFORE}" "$(attempt_files)" "  every record of the attempt is kept"
assert_true "  and nothing else is removed" runtime_kept
run boringtunTeardownFinished "${IF}"
assert_rc 1 "${RC}" "  boringtunTeardownFinished agrees"
# The operator finished the cleanup by hand; the attempt is now terminal.
mv "${AWG_BT_RUN_DIR}/${IF}@${ATTEMPT}.done-pending" "${AWG_BT_RUN_DIR}/${IF}@${ATTEMPT}.done"
run boringtunTeardownFinished "${IF}"
assert_rc 0 "${RC}" "once the attempt is terminal (done), the teardown counts as finished"
clear_uapi
for PHASE_FLAGS in "launched up" "launched up down" "prechecked"; do
	clear_uapi
	# shellcheck disable=SC2086 # the phase and its flags
	record_attempt ${PHASE_FLAGS}
	run boringtunTeardownFinished "${IF}"
	assert_rc 1 "${RC}" "an attempt '${PHASE_FLAGS}' without the done flag is not finished"
done
clear_uapi
: >"${AWG_BT_RUN_DIR}/${IF}@${ATTEMPT}.state"
run boringtunTeardownFinished "${IF}"
assert_rc 1 "${RC}" "an attempt whose state cannot be read is not proven finished"
clear_uapi
: >"${AWG_BT_RUN_DIR}/${IF}@not-an-attempt.state"
run boringtunTeardownFinished "${IF}"
assert_rc 1 "${RC}" "a record at the interface's name that is no attempt is not proven finished"
clear_uapi
for PHASE_FLAGS in "started" "launch-failed" "launched up done"; do
	clear_uapi
	# shellcheck disable=SC2086 # the phase and its flags
	record_attempt ${PHASE_FLAGS}
	run boringtunTeardownFinished "${IF}"
	assert_rc 0 "${RC}" "an attempt '${PHASE_FLAGS}' is terminal"
done
clear_uapi

echo "--- B2: UAPI nodes are removed only on positive proof"
# E: the dead socket and its alias that a finished attempt recorded go.
dead_socket "${WG_SOCK}"
ln -s "${WG_SOCK}" "${AWG_SOCK}"
record_attempt launched up "done"
run uninstallBoringtunRuntime "${IF}"
assert_rc 0 "${RC}" "E: the BoringTun uninstall succeeds with a finished attempt"
assert_true "  its recorded, dead UAPI socket and alias are removed" test ! -e "${WG_SOCK}" -a ! -L "${AWG_SOCK}"
assert_eq "0" "$(attempt_files)" "  and so is the finished attempt"
assert_true "  the store is removed" test ! -e "${AWG_BT_STORE_DIR}"
assert_true "  both generated helpers are removed" test ! -e "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl" -a ! -e "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
assert_true "  the installer's load override is removed" test ! -e "${AWG_BT_MODPROBE_OVERRIDE}"
assert_true "  the PID file is removed" test ! -e "$(_awgBtPidFile "${IF}")"
assert_true "  a socket another process listens on stays" test -S "${AWG_BT_WG_SOCKET_DIR}/other0.sock"
run uninstallBoringtunRuntime "${IF}"
assert_rc 0 "${RC}" "the BoringTun uninstall can be run again"
# uapi_case <label> <expected socket present> <expected alias present>: run
# the runtime uninstall and check what it left.
uapi_kept() { # <label>
	run uninstallBoringtunRuntime "${IF}"
	assert_rc 1 "${RC}" "$1"
	assert_contains "is not provably an idle UAPI node" "${ERR}" "  reported as a remainder"
}
# A: a process listens on the very socket node the attempt recorded.
install_runtime
listening_socket "${WG_SOCK}"
record_attempt launched up "done"
uapi_kept "A: a recorded socket that a live process listens on is kept"
assert_true "  and the live socket stays" test -S "${WG_SOCK}"
stop_listener
clear_uapi
# B: the AmneziaWG path is an alias of a live socket.
install_runtime
listening_socket "${WG_SOCK}"
ln -s "${WG_SOCK}" "${AWG_SOCK}"
record_attempt launched up "done"
uapi_kept "B: an alias of a live socket is kept while it is listened on"
assert_true "  the alias stays" test -L "${AWG_SOCK}"
assert_true "  and the live socket stays" test -S "${WG_SOCK}"
stop_listener
clear_uapi
# The alias resolves outside the UAPI directories.
install_runtime
mkdir -p "${T}/elsewhere"
dead_socket "${T}/elsewhere/x.sock"
ln -s "${T}/elsewhere/x.sock" "${AWG_SOCK}"
record_attempt launched up "done"
uapi_kept "an alias that resolves outside the UAPI socket directories is kept"
assert_true "  and so is its target" test -S "${T}/elsewhere/x.sock" -a -L "${AWG_SOCK}"
clear_uapi
# C: ss fails. D: ss prints something that is not a UNIX socket list.
for SS_CASE in "C:exit 1" "D:echo 'garbage without a netid'" "D:printf 'u_str LISTEN\\n'"; do
	install_runtime
	dead_socket "${WG_SOCK}"
	record_attempt launched up "done"
	printf '#!/bin/bash\n%s\n' "${SS_CASE#*:}" >"${MOCKBIN}/ss"
	chmod 0755 "${MOCKBIN}/ss"
	PATH="${MOCKBIN}:${PATH}" uapi_kept "${SS_CASE%%:*}: when ss says '${SS_CASE#*:}', the recorded socket is kept"
	assert_true "  it stays" test -S "${WG_SOCK}"
	rm -f "${MOCKBIN}/ss"
	clear_uapi
done
# F: a dead socket that no attempt records.
install_runtime
dead_socket "${WG_SOCK}"
uapi_kept "F: a dead socket without an attempt's record is kept"
assert_true "  it stays" test -S "${WG_SOCK}"
clear_uapi
# A node that replaced the recorded one.
install_runtime
dead_socket "${WG_SOCK}"
record_attempt launched up "done"
rm -f "${WG_SOCK}"
dead_socket "${WG_SOCK}"
uapi_kept "a socket that replaced the recorded node is kept"
clear_uapi
# The recorded daemon (same PID and start time) still lives.
install_runtime
dead_socket "${WG_SOCK}"
(
	_AWG_BT_ATTEMPT="${ATTEMPT}"
	_awgBtPrepareRunDir && _awgBtStateNew "${AWG_BT_CONFIG_DIR}/${IF}.conf" || exit 1
	_AWG_BT_STATE[PHASE]=launched
	_AWG_BT_STATE[PID]="$$"
	_AWG_BT_STATE[PID_START]="$(_awgBtProcessStartTime "$$")"
	_AWG_BT_STATE[WG_SOCK]="$(_awgBtPathId "${WG_SOCK}")"
	_awgBtStateSave "${IF}" && _awgBtFlagsArm "${IF}" && _awgBtFlagRaise "${IF}" up && _awgBtFlagRaise "${IF}" "done"
) || not_ok "(fixture: an attempt of a live daemon)"
uapi_kept "a recorded socket whose recorded daemon still lives is kept"
clear_uapi

echo "--- B2: ss rows are LIVE, ABSENT or UNKNOWN; only ABSENT removes a node"
# A real listener at the recorded node, whose recorded daemon is gone: only the
# liveness proof stands between it and an unlink. The mocked ss prints the
# given rows, and every row must have the shape the supported iproute2 prints.
VALID_ROW="u_str LISTEN 0      4096          /run/unrelated.sock 5504 * 0 <-> ino:7 dev:0/63 peers:"
ss_rows() { # <row>...
	printf '%s\n' "$@" >"${T}/ss-rows"
	printf '#!/bin/bash\ncat %q\n' "${T}/ss-rows" >"${MOCKBIN}/ss"
	chmod 0755 "${MOCKBIN}/ss"
}
live_unknown() { # <label> <row>...
	local LABEL="$1"
	shift
	install_runtime
	listening_socket "${WG_SOCK}"
	record_attempt launched up "done"
	ss_rows "$@"
	PATH="${MOCKBIN}:${PATH}" uapi_kept "${LABEL}"
	assert_true "  the live socket stays" test -S "${WG_SOCK}"
	assert_true "  and so does the attempt's record" test "$(attempt_files)" -gt 0
	stop_listener
	rm -f "${MOCKBIN}/ss"
	clear_uapi
}
live_unknown "D: a malformed row ('u_str invalid invalid invalid /unrelated') keeps a live socket" \
	"u_str invalid invalid invalid /unrelated"
live_unknown "E: a truncated row keeps a live socket" "u_str LISTEN 0      1          ${WG_SOCK} 30113973 * 0"
live_unknown "E: a row cut off after the inode keeps a live socket" "u_str LISTEN 0 1 /run/unrelated.sock 123 * 0 <-> ino:7"
live_unknown "F: an invalid inode field keeps a live socket" "u_str LISTEN 0 1 /run/unrelated.sock 123 * 0 <-> ino:x7 dev:0/63 peers:"
live_unknown "F: an invalid device field keeps a live socket" "u_str LISTEN 0 1 /run/unrelated.sock 123 * 0 <-> ino:7 dev:0:63 peers:"
live_unknown "a row in another state keeps a live socket" "u_str ESTAB 0 0 /run/unrelated.sock 123 * 0 <-> ino:7 dev:0/63 peers:"
live_unknown "a path row without its inode and device keeps a live socket" "u_str LISTEN 0 1 /run/unrelated.sock 123 * 0 <-> peers:"
live_unknown "G: a valid unrelated row next to a malformed one keeps a live socket" \
	"${VALID_ROW}" "u_str invalid invalid invalid /unrelated"
# H: a complete, valid enumeration without the node proves it idle.
install_runtime
dead_socket "${WG_SOCK}"
record_attempt launched up "done"
ss_rows "${VALID_ROW}" "u_dgr UNCONN 0      0           /run/other-dgram.sock 5505 * 0 <-> ino:8 dev:0/63" \
	"u_str LISTEN 0      1              @abstract-name 5506 * 0 <-> peers:" \
	"u_str LISTEN 0      1      /run/with space.sock 5507 * 0 <-> ino:9 dev:0/63 peers: 5508"
PATH="${MOCKBIN}:${PATH}" run uninstallBoringtunRuntime "${IF}"
assert_rc 0 "${RC}" "H: a fully valid listing without the node lets the recorded, dead socket go"
assert_true "  it is removed" test ! -e "${WG_SOCK}"
assert_eq "0" "$(attempt_files)" "  and so is its attempt's record, afterwards"
rm -f "${MOCKBIN}/ss"
clear_uapi

echo "--- N1: an attempt's record stays until the node it proves is gone"
install_runtime
dead_socket "${WG_SOCK}"
record_attempt launched up "done"
printf '#!/bin/bash\nexit 1\n' >"${MOCKBIN}/ss"
chmod 0755 "${MOCKBIN}/ss"
PATH="${MOCKBIN}:${PATH}" run uninstallBoringtunRuntime "${IF}"
rm -f "${MOCKBIN}/ss"
assert_rc 1 "${RC}" "N1: a recorded socket that cannot be inspected fails the BoringTun uninstall"
assert_true "  the socket stays" test -S "${WG_SOCK}"
assert_true "  and the attempt's record stays, as the proof of ownership" test "$(attempt_files)" -gt 0
assert_contains "the attempt's record is kept as the proof of ownership" "${ERR}" "  and the operator is told"
run uninstallBoringtunRuntime "${IF}"
assert_rc 0 "${RC}" "N1: once ss works again, the rerun finishes"
assert_true "  the recorded socket is removed" test ! -e "${WG_SOCK}"
assert_eq "0" "$(attempt_files)" "  and then its record"
clear_uapi

echo "--- B3/S2: generated helpers"
install_runtime
printf '\n' >>"${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"
printf '#!/bin/bash\n# not ours\n' >"${AWG_BT_LIBEXEC_DIR}/awg-custom"
run uninstallBoringtunRuntime "${IF}"
assert_rc 0 "${RC}" "a helper changed after the install does not fail the uninstall"
assert_true "  a helper changed by one byte stays" test -e "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"
assert_contains "awg-backend-ctl is not the file this installer generates" "${OUT}" "  and the operator is told"
assert_true "  the unchanged helper is removed" test ! -e "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
assert_true "  a foreign file in the helper directory stays" test -e "${AWG_BT_LIBEXEC_DIR}/awg-custom"
rm -f "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"
install_runtime
{
	printf '#!/bin/bash\n# awg-boringtun-launch: generated by amneziawg-install from its own functions.\n'
	printf 'echo "an operator'"'"'s launcher that carries the header"\n'
} >"${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
run uninstallBoringtunRuntime "${IF}"
assert_true "a pre-existing file that carries the installer's header line stays" \
	grep -q "carries the header" "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
rm -f "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
install_runtime
ln -sf "${AWG_BT_LIBEXEC_DIR}/awg-custom" "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
run uninstallBoringtunRuntime "${IF}"
assert_true "a symlink at a helper's path stays" test -L "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
rm -f "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
# S2: a generated helper that cannot be removed fails the uninstall.
install_runtime
run eval 'rm() { [[ "${*: -1}" == */awg-backend-ctl ]] && return 1; command rm "$@"; }; uninstallBoringtunRuntime "${IF}"'
assert_rc 1 "${RC}" "S2: a generated helper that cannot be removed fails the BoringTun uninstall"
assert_contains "awg-backend-ctl could not be removed" "${ERR}" "  and names it"
assert_true "  (it is still there)" test -e "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl"
install_runtime
run eval 'rm() { [[ "${*: -1}" == */awg-boringtun-launch ]] && return 1; command rm "$@"; }; uninstallBoringtunRuntime "${IF}"'
assert_rc 1 "${RC}" "S2: and so does the launcher"
run uninstallBoringtunRuntime "${IF}"
assert_rc 0 "${RC}" "the rerun removes them"
assert_true "  both are absent afterwards" test ! -e "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl" -a ! -e "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
rm -f "${AWG_BT_LIBEXEC_DIR}/awg-custom"

echo "--- The load override"
install_runtime
printf 'install amneziawg /bin/false\n# changed\n' >"${AWG_BT_MODPROBE_OVERRIDE}"
run uninstallBoringtunRuntime "${IF}"
assert_rc 0 "${RC}" "a changed load override does not fail the uninstall"
assert_true "  it is left in place" test -e "${AWG_BT_MODPROBE_OVERRIDE}"
assert_contains "was changed after it was installed" "${OUT}" "  and the operator is told"
rm -f "${AWG_BT_MODPROBE_OVERRIDE}"

# uninstallAmneziaWG on a BoringTun host: packages and foreign DKMS, the
# order of its steps and what a failure keeps. PACKAGES_RC and PPA_RC make
# the package or repository step fail, RM_FAILS makes rm fail on that path,
# SYSTEMCTL_FAILS makes that systemctl command fail, and REAL_BT_RUNTIME runs
# the real BoringTun removal.
uninstall_flow() {
	checkOS() { :; }
	systemctl() {
		echo "systemctl $*" >>"${S}/un"
		[[ "$1" == is-active ]] && return 1
		[[ "$1" != "${SYSTEMCTL_FAILS:-}" ]]
	}
	[[ -z "${RM_FAILS:-}" ]] || rm() { [[ "${*: -1}" == "${RM_FAILS}" ]] && return 1; command rm "$@"; }
	removeInstalledAptPackages() {
		echo "remove-packages $*" >>"${S}/un"
		[[ -e "${AMNEZIAWG_DIR}/params" ]] && echo "params present at package removal" >>"${S}/un"
		return "${PACKAGES_RC:-0}"
	}
	removeAmneziaPpaSourceEntries() { return "${PPA_RC:-0}"; }
	enable_apt_ipv4() { :; }
	disable_apt_ipv4() { :; }
	apt-get() { :; }
	apt() { echo "apt $*" >>"${S}/un"; }
	[[ -n "${REAL_BT_RUNTIME:-}" ]] || uninstallBoringtunRuntime() { echo "uninstallBoringtunRuntime $*" >>"${S}/un"; return "${BT_UNINSTALL_RC:-0}"; }
	boringtunDaemonsOf() { cat "${S}/daemons" 2>/dev/null; }
	[[ -n "${REAL_TEARDOWN_CHECK:-}" ]] || boringtunTeardownFinished() { echo "boringtunTeardownFinished $*" >>"${S}/un"; }
	mkdir -p "${AMNEZIAWG_DIR}"
	: >"${AMNEZIAWG_DIR}/params"
	# shellcheck disable=SC2034 # read by uninstallAmneziaWG
	SERVER_AWG_NIC=awg0
	uninstallAmneziaWG
}
for UN_OS in ubuntu debian; do
	: >"${S}/un"
	OS="${UN_OS}" AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
	assert_rc 0 "${RC}" "${UN_OS}: a BoringTun uninstall succeeds"
	assert_contains "remove-packages amneziawg-tools" "$(cat "${S}/un")" "${UN_OS}: a BoringTun uninstall removes amneziawg-tools"
	assert_eq "remove-packages amneziawg-tools" "$(grep '^remove-packages' "${S}/un")" \
		"${UN_OS}: and no module or DKMS package it did not install"
	assert_contains "uninstallBoringtunRuntime awg0" "$(cat "${S}/un")" "${UN_OS}: the BoringTun runtime is removed"
	assert_contains "params present at package removal" "$(cat "${S}/un")" "${UN_OS}: the configuration is still there while packages are removed"
	assert_true "${UN_OS}: and is removed at the end" test ! -e "${AMNEZIAWG_DIR}"
done
: >"${S}/un"
OS=ubuntu AWG_BACKEND=kernel RUN_INPUT=y run uninstall_flow
assert_eq "remove-packages amneziawg amneziawg-tools amneziawg-dkms" "$(grep '^remove-packages' "${S}/un")" \
	"Ubuntu kernel uninstall keeps removing exactly its three packages"
assert_not_contains "uninstallBoringtunRuntime" "$(cat "${S}/un")" "and never runs the BoringTun removal"
assert_not_contains "boringtunTeardownFinished" "$(cat "${S}/un")" "or the BoringTun teardown check"
assert_not_contains "params present at package removal" "$(cat "${S}/un")" "the kernel uninstall keeps removing the configuration before its packages"
: >"${S}/un"
OS=debian AWG_BACKEND=kernel RUN_INPUT=y run uninstall_flow
assert_eq "remove-packages amneziawg amneziawg-tools" "$(grep '^remove-packages' "${S}/un")" \
	"Debian kernel uninstall keeps removing exactly its two packages"
# S3: a failed package or repository step keeps the configuration.
for FAILING in PACKAGES_RC PPA_RC; do
	: >"${S}/un"
	declare "${FAILING}=1"
	OS=ubuntu AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
	unset "${FAILING}"
	assert_rc 1 "${RC}" "S3: a BoringTun uninstall whose ${FAILING%_RC} step fails fails"
	assert_true "  and keeps params, so a rerun uninstalls again" test -e "${AMNEZIAWG_DIR}/params"
	assert_contains "was kept, so the uninstall can be run again" "${OUT}" "  and says so"
done
: >"${S}/un"
PACKAGES_RC=1 OS=ubuntu AWG_BACKEND=kernel RUN_INPUT=y run uninstall_flow
assert_rc 1 "${RC}" "a kernel uninstall whose package step fails still fails"
assert_true "  and, as before, has already removed its configuration" test ! -e "${AMNEZIAWG_DIR}/params"
: >"${S}/un"
OS=ubuntu AWG_BACKEND=boringtun BT_UNINSTALL_RC=1 RUN_INPUT=y run uninstall_flow
assert_rc 1 "${RC}" "a failed BoringTun removal fails the uninstall"
assert_true "  and keeps the configuration, so the uninstall can be rerun" test -e "${AMNEZIAWG_DIR}/params"
assert_not_contains "remove-packages" "$(cat "${S}/un")" "  and removes no package"
echo 4242 >"${S}/daemons"
: >"${S}/un"
OS=ubuntu AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
assert_rc 1 "${RC}" "a BoringTun daemon that survives the stop fails the uninstall"
assert_contains "PID 4242" "${OUT}" "  naming the daemon"
assert_eq "systemctl stop awg-quick@awg0
systemctl disable awg-quick@awg0" "$(cat "${S}/un")" "  before anything is removed"
rm -f "${S}/daemons"
# S1 through the whole uninstall: an unfinished attempt stops it before
# anything is removed.
mkdir -p "${AWG_SYSTEMD_UNIT_DIR}/awg-quick@awg0.service.d" "${AWG_SYSCTL_FILE%/*}"
: >"${AWG_SYSTEMD_UNIT_DIR}/awg-quick@awg0.service.d/override.conf"
: >"${AWG_SYSCTL_FILE}"
IF=awg0
record_attempt launched up replay
: >"${S}/un"
REAL_TEARDOWN_CHECK=1 OS=ubuntu AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
assert_rc 1 "${RC}" "S1: an unfinished BoringTun teardown fails the whole uninstall"
assert_true "  before the drop-in, the sysctl file or params are removed" \
	test -e "${AWG_SYSTEMD_UNIT_DIR}/awg-quick@awg0.service.d/override.conf" -a -e "${AWG_SYSCTL_FILE}" -a -e "${AMNEZIAWG_DIR}/params"
assert_not_contains "uninstallBoringtunRuntime" "$(cat "${S}/un")" "  and before the BoringTun removal"
assert_true "  the attempt's records stay" test -e "${AWG_BT_RUN_DIR}/awg0@${ATTEMPT}.state"
rm -f "${AWG_BT_RUN_DIR}/awg0@"*
IF=awgu0
# N2: every BoringTun removal before the commit is checked. A failure fails
# the uninstall and keeps the configuration; the rerun finishes.
DROPIN_FILE="${AWG_SYSTEMD_UNIT_DIR}/awg-quick@awg0.service.d/override.conf"
n2_retry() { # <label> <file that stays or ""> <VAR=value that makes a step fail>
	local LABEL="$1" FILE="$2" FAULT="$3"
	mkdir -p "${DROPIN_FILE%/*}" "${AWG_SYSCTL_FILE%/*}"
	: >"${DROPIN_FILE}"
	: >"${AWG_SYSCTL_FILE}"
	: >"${S}/un"
	export "${FAULT?}"
	OS=ubuntu AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
	unset "${FAULT%%=*}"
	assert_rc 1 "${RC}" "N2: ${LABEL} fails the BoringTun uninstall"
	[[ -z "${FILE}" ]] || assert_true "  ${FILE##*/} stays" test -e "${FILE}"
	assert_true "  params and config stay" test -e "${AMNEZIAWG_DIR}/params"
	assert_not_contains "uninstalled successfully" "${OUT}" "  and it does not report success"
	OS=ubuntu AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
	assert_rc 0 "${RC}" "N2: after ${LABEL}, the rerun succeeds"
	assert_true "  the drop-in, the sysctl file and the configuration are gone" \
		test ! -e "${DROPIN_FILE}" -a ! -e "${AWG_SYSCTL_FILE}" -a ! -e "${AMNEZIAWG_DIR}"
}
n2_retry "a drop-in that cannot be removed" "${DROPIN_FILE}" "RM_FAILS=${DROPIN_FILE}"
n2_retry "a sysctl file that cannot be removed" "${AWG_SYSCTL_FILE}" "RM_FAILS=${AWG_SYSCTL_FILE}"
n2_retry "a failed systemctl daemon-reload" "" "SYSTEMCTL_FAILS=daemon-reload"
n2_retry "a failed systemctl disable" "${DROPIN_FILE}" "SYSTEMCTL_FAILS=disable"
MANAGED_SOURCE_FILE="${AMNEZIA_PPA_SOURCES_DIR}/amneziawg.sources"
mkdir -p "${AMNEZIA_PPA_SOURCES_DIR}"
printf '# Managed by amneziawg-install\n' >"${MANAGED_SOURCE_FILE}"
n2_retry "a managed APT source that cannot be removed" "${MANAGED_SOURCE_FILE}" "RM_FAILS=${MANAGED_SOURCE_FILE}"
assert_true "  and the rerun removed it" test ! -e "${MANAGED_SOURCE_FILE}"
: >"${S}/un"
mkdir -p "${DROPIN_FILE%/*}" "${AWG_SYSCTL_FILE%/*}"
: >"${DROPIN_FILE}"
: >"${AWG_SYSCTL_FILE}"
RM_FAILS="${DROPIN_FILE}" OS=ubuntu AWG_BACKEND=kernel RUN_INPUT=y run uninstall_flow
assert_true "the kernel uninstall keeps its behaviour on the same failure: configuration removed as before" \
	test ! -e "${AMNEZIAWG_DIR}/params"
rm -f "${DROPIN_FILE}" "${AWG_SYSCTL_FILE}"
# N1 through the whole uninstall: a recorded socket that cannot be inspected
# keeps params and the attempt's record; the rerun, with ss working, finishes.
IF=awg0
WG_SOCK="${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
AWG_SOCK="${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"
install_runtime
dead_socket "${WG_SOCK}"
record_attempt launched up "done"
printf '#!/bin/bash\nexit 1\n' >"${MOCKBIN}/ss"
chmod 0755 "${MOCKBIN}/ss"
REAL_BT_RUNTIME=1 REAL_TEARDOWN_CHECK=1 OS=ubuntu AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
rm -f "${MOCKBIN}/ss"
assert_rc 1 "${RC}" "N1: the whole uninstall fails while a recorded socket cannot be inspected"
assert_true "  params, the socket and the attempt's record stay" \
	test -e "${AMNEZIAWG_DIR}/params" -a -S "${WG_SOCK}" -a "$(attempt_files)" -gt 0
REAL_BT_RUNTIME=1 REAL_TEARDOWN_CHECK=1 OS=ubuntu AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
assert_rc 0 "${RC}" "N1: the rerun of the whole uninstall finishes"
assert_true "  the socket, the record and the configuration are gone" \
	test ! -e "${WG_SOCK}" -a "$(attempt_files)" -eq 0 -a ! -e "${AMNEZIAWG_DIR}"
IF=awgu0
WG_SOCK="${AWG_BT_WG_SOCKET_DIR}/${IF}.sock"
AWG_SOCK="${AWG_BT_AWG_SOCKET_DIR}/${IF}.sock"
# modules-load: the kernel install's boot entry is never a BoringTun file.
mkdir -p "${AWG_MODULES_LOAD_FILE%/*}"
printf '# the administrator'"'"'s own\namneziawg\n' >"${AWG_MODULES_LOAD_FILE}"
MODULES_LOAD_SHA="$(sha256sum "${AWG_MODULES_LOAD_FILE}")"
OS=ubuntu AWG_BACKEND=boringtun RUN_INPUT=y run uninstall_flow
assert_eq "${MODULES_LOAD_SHA}" "$(sha256sum "${AWG_MODULES_LOAD_FILE}" 2>/dev/null)" \
	"a BoringTun uninstall leaves ${AWG_MODULES_LOAD_FILE##*/} byte for byte as it was"
OS=ubuntu AWG_BACKEND=kernel RUN_INPUT=y run uninstall_flow
assert_true "a kernel uninstall still removes it" test ! -e "${AWG_MODULES_LOAD_FILE}"

echo
echo "BoringTun host tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
