#!/bin/bash
# Destructive-to-runner live smoke test for a disposable Ubuntu 26.04 VM.
# This validates signed PPA setup, package resolution, DKMS, module loading,
# userspace tools, and a transient AmneziaWG link. Do not run on a workstation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SMOKE_INTERFACE="awg-ci-smoke"
PPA_KEY_FILE=""
EXPECTED_PPA_FINGERPRINT="75C9DD72C799870E310542E24166F2C257290828"

if [[ "${EUID}" -ne 0 ]]; then
	echo "ERROR: live Resolute smoke test must run as root" >&2
	exit 1
fi

# shellcheck source=../amneziawg-install.sh
source "${PROJECT_ROOT}/amneziawg-install.sh"
# shellcheck source=/etc/os-release
source /etc/os-release

if [[ "${ID}" != "ubuntu" || "${VERSION_ID}" != "26.04" || "${VERSION_CODENAME}" != "resolute" ]]; then
	echo "ERROR: expected Ubuntu 26.04 (resolute), got ${PRETTY_NAME:-unknown}" >&2
	exit 1
fi
if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
	echo "ERROR: this live job currently validates the amd64 package/kernel path" >&2
	exit 1
fi

function cleanup() {
	local SAVED_RC=$?
	trap - EXIT
	ip link delete "${SMOKE_INTERFACE}" 2>/dev/null || true
	modprobe -r amneziawg 2>/dev/null || true
	removeAmneziaPpaSourceEntries "${AMNEZIA_PPA_SOURCES_DIR}" 2>/dev/null || true
	if [[ -n "${PPA_KEY_FILE}" ]]; then
		rm -f "${PPA_KEY_FILE}"
	fi
	_remove_ipv4_overrides 2>/dev/null || true
	exit "${SAVED_RC}"
}
trap cleanup EXIT

echo "=== Resolute VM ==="
cat /etc/os-release
uname -a
if command -v mokutil &>/dev/null; then
	mokutil --sb-state || true
fi

enable_apt_ipv4
apt-get -o APT::Update::Error-Mode=any update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
	curl \
	gnupg \
	python3 \
	software-properties-common \
	"linux-headers-$(uname -r)"

NATIVE_SUITE="$(getUbuntuPpaCodename)"
ARCHITECTURE="$(dpkg --print-architecture)"
configureUbuntuAmneziaPpa "${NATIVE_SUITE}" "${AMNEZIA_PPA_SOURCES_DIR}" "${ARCHITECTURE}"

PPA_KEY_FILE="$(mktemp)"
PPA_SOURCE_METADATA="$(python3 - "${AMNEZIA_PPA_SOURCES_DIR}" "${PPA_KEY_FILE}" <<'PY'
import glob
import os
import re
import shlex
import sys

sources_dir, key_path = sys.argv[1:]
target = "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu"


def parse_deb822(path):
    stanzas = []
    fields = {}
    current = None

    def finish():
        nonlocal fields, current
        if fields:
            stanzas.append(fields)
        fields = {}
        current = None

    with open(path, encoding="utf-8") as source:
        for raw_line in list(source) + ["\n"]:
            line = raw_line.rstrip("\n")
            if not line.strip():
                finish()
                continue
            if line.startswith("#"):
                continue
            if line[:1].isspace():
                if current is None:
                    raise SystemExit(f"malformed continuation in {path}")
                key, index = current
                value = line[1:]
                if value == ".":
                    value = ""
                separator = "\n" if key == "signed-by" else " "
                fields[key][index] += separator + value
                continue
            match = re.fullmatch(r"([A-Za-z0-9-]+):[ \t]*(.*)", line)
            if not match:
                raise SystemExit(f"malformed DEB822 line in {path}: {line}")
            key = match.group(1).lower()
            fields.setdefault(key, []).append(match.group(2))
            current = (key, len(fields[key]) - 1)
    return stanzas


matches = []
for path in glob.glob(os.path.join(sources_dir, "*.sources")):
    for fields in parse_deb822(path):
        uri_values = fields.get("uris", [])
        uris = " ".join(uri_values).split()
        if any(uri.rstrip("/") == target for uri in uris):
            matches.append((path, fields))

legacy_matches = []
for path in glob.glob(os.path.join(sources_dir, "*.list")):
    with open(path, encoding="utf-8") as source:
        for number, raw_line in enumerate(source, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                tokens = shlex.split(line, comments=True)
            except ValueError:
                continue
            if any(token.rstrip("/") == target for token in tokens):
                legacy_matches.append(f"{path}:{number}")

if legacy_matches:
    raise SystemExit(
        "unexpected legacy Amnezia PPA entries: " + ", ".join(legacy_matches)
    )
if len(matches) != 1:
    raise SystemExit(f"expected exactly one Amnezia PPA DEB822 stanza, found {len(matches)}")

path, fields = matches[0]


def one_field(name):
    values = fields.get(name, [])
    if len(values) != 1:
        raise SystemExit(f"target stanza must have exactly one {name} field")
    return values[0].strip()


types = one_field("types").split()
uris = one_field("uris").split()
suites = one_field("suites").split()
components = one_field("components").split()
signed_by = one_field("signed-by").strip()

if "deb" not in types or any(value not in {"deb", "deb-src"} for value in types):
    raise SystemExit(f"unexpected target Types: {types}")
if len(uris) != 1 or uris[0].rstrip("/") != target:
    raise SystemExit(f"unexpected target URIs: {uris}")
if len(suites) != 1 or suites[0] not in {"resolute", "noble"}:
    raise SystemExit(f"unexpected target Suites: {suites}")
if components != ["main"]:
    raise SystemExit(f"unexpected target Components: {components}")
if not (
    signed_by.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    and signed_by.endswith("-----END PGP PUBLIC KEY BLOCK-----")
):
    raise SystemExit("target Signed-By is not a complete inline OpenPGP public key")

for insecure_field in (
    "trusted",
    "allow-insecure",
    "allow-weak",
    "allow-downgrade-to-insecure",
):
    for value in fields.get(insecure_field, []):
        if value.strip().lower() in {"yes", "true", "1", "on", "enable", "with"}:
            raise SystemExit(f"insecure target field: {insecure_field}: {value}")

with open(key_path, "w", encoding="utf-8") as key_file:
    key_file.write(signed_by + "\n")

print(path)
print(" ".join(types))
print(" ".join(uris))
print(" ".join(suites))
print(" ".join(components))
PY
)"
mapfile -t PPA_FIELDS <<< "${PPA_SOURCE_METADATA}"
if [[ "${#PPA_FIELDS[@]}" -ne 5 ]]; then
	echo "ERROR: configured PPA metadata summary is incomplete" >&2
	exit 1
fi
PPA_SOURCE_FILE="${PPA_FIELDS[0]}"
SELECTED_SUITE="${PPA_FIELDS[3]}"
if [[ "${SELECTED_SUITE}" != "${NATIVE_SUITE}" && "${SELECTED_SUITE}" != "noble" ]]; then
	echo "ERROR: unexpected configured suite '${SELECTED_SUITE}'" >&2
	exit 1
fi
if grep -qiE \
	'trusted[[:space:]]*=[[:space:]]*(yes|true|1|on|enable|with)|allow-(insecure|weak|downgrade-to-insecure)[[:space:]]*=[[:space:]]*(yes|true|1|on|enable|with)|^(Trusted|Allow-Insecure|Allow-Weak|Allow-Downgrade-To-Insecure):[[:space:]]*(yes|true|1|on|enable|with)|AllowInsecureRepositories|AllowUnauthenticated' \
	"${PPA_SOURCE_FILE}"; then
	echo "ERROR: insecure APT option found in configured sources" >&2
	exit 1
fi

PPA_FINGERPRINT="$(gpg --batch --show-keys --with-colons "${PPA_KEY_FILE}" |
	awk -F: '$1 == "fpr" { print $10; exit }')"
if [[ "${PPA_FINGERPRINT}" != "${EXPECTED_PPA_FINGERPRINT}" ]]; then
	echo "ERROR: configured PPA signing key fingerprint '${PPA_FINGERPRINT}' does not match expected '${EXPECTED_PPA_FINGERPRINT}'" >&2
	exit 1
fi
echo "=== Configured Amnezia PPA source ==="
printf 'Path: %s\nTypes: %s\nURIs: %s\nSuites: %s\nComponents: %s\nFingerprint: %s\n' \
	"${PPA_SOURCE_FILE}" "${PPA_FIELDS[1]}" "${PPA_FIELDS[2]}" \
	"${SELECTED_SUITE}" "${PPA_FIELDS[4]}" "${PPA_FINGERPRINT}"

# APT performs normal InRelease signature verification here.
apt-get -o APT::Update::Error-Mode=any update
apt-cache policy amneziawg amneziawg-tools amneziawg-dkms
DEBIAN_FRONTEND=noninteractive apt-get install -y \
	amneziawg \
	amneziawg-dkms \
	amneziawg-tools \
	dkms \
	iptables \
	nftables \
	qrencode

echo "=== Installed package versions ==="
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
	amneziawg amneziawg-tools amneziawg-dkms dkms "linux-headers-$(uname -r)"

declare -A EXPECTED_ARCHITECTURES=(
	[amneziawg]="all"
	[amneziawg-dkms]="all"
	[amneziawg-tools]="amd64"
)
for PACKAGE in amneziawg amneziawg-dkms amneziawg-tools; do
	if [[ "$(dpkg-query -W -f='${Status}' "${PACKAGE}")" != "install ok installed" ]]; then
		echo "ERROR: ${PACKAGE} is not fully installed" >&2
		exit 1
	fi
	if [[ "$(dpkg-query -W -f='${Architecture}' "${PACKAGE}")" != "${EXPECTED_ARCHITECTURES[${PACKAGE}]}" ]]; then
		echo "ERROR: ${PACKAGE} has an unexpected architecture" >&2
		exit 1
	fi
	INSTALLED_VERSION="$(dpkg-query -W -f='${Version}' "${PACKAGE}")"
	POLICY="$(apt-cache policy "${PACKAGE}")"
	CANDIDATE_VERSION="$(awk '/Candidate:/ { print $2; exit }' <<< "${POLICY}")"
	if [[ "${CANDIDATE_VERSION}" == "(none)" || "${CANDIDATE_VERSION}" != "${INSTALLED_VERSION}" ]]; then
		echo "ERROR: ${PACKAGE} installed/candidate version mismatch" >&2
		exit 1
	fi
	if ! grep -Fq "${AMNEZIA_PPA_URI} ${SELECTED_SUITE}/main" <<< "${POLICY}"; then
		echo "ERROR: ${PACKAGE} candidate is not attributed to the selected Amnezia PPA suite" >&2
		printf '%s\n' "${POLICY}" >&2
		exit 1
	fi
done

HEADER_PACKAGE="linux-headers-$(uname -r)"
if [[ "$(dpkg-query -W -f='${Status}' "${HEADER_PACKAGE}")" != "install ok installed" ]]; then
	echo "ERROR: running-kernel headers are not fully installed" >&2
	exit 1
fi
apt-get check
disable_apt_ipv4

sanitizeAwgDkmsConf
dkms autoinstall -k "$(uname -r)"
depmod -a

MODULE_PATH="$(find "/lib/modules/$(uname -r)" -name 'amneziawg.ko*' -print -quit)"
if [[ -z "${MODULE_PATH}" ]]; then
	echo "ERROR: DKMS did not install amneziawg.ko for $(uname -r)" >&2
	exit 1
fi
echo "Module path: ${MODULE_PATH}"
DKMS_STATUS="$(dkms status)"
printf '%s\n' "${DKMS_STATUS}"
if ! grep -F 'amneziawg/' <<< "${DKMS_STATUS}" |
	grep -F "$(uname -r)" |
	grep -q ': installed'; then
	echo "ERROR: DKMS does not report amneziawg installed for the running kernel" >&2
	exit 1
fi
modinfo amneziawg
VERMAGIC="$(modinfo -F vermagic amneziawg)"
if [[ "${VERMAGIC}" != "$(uname -r) "* ]]; then
	echo "ERROR: module vermagic '${VERMAGIC}' does not match running kernel '$(uname -r)'" >&2
	exit 1
fi

modprobe amneziawg
if ! lsmod | grep -q '^amneziawg '; then
	echo "ERROR: amneziawg module was not loaded" >&2
	exit 1
fi

echo "=== Userspace and link smoke tests ==="
awg --version
PUBLIC_KEY="$(awg genkey | awg pubkey)"
if [[ "${#PUBLIC_KEY}" -ne 44 ]]; then
	echo "ERROR: awg key pipeline returned an unexpected public key" >&2
	exit 1
fi
ip link add "${SMOKE_INTERFACE}" type amneziawg
ip -details link show "${SMOKE_INTERFACE}"
awg show "${SMOKE_INTERFACE}"
ip link delete "${SMOKE_INTERFACE}"

removeAmneziaPpaSourceEntries "${AMNEZIA_PPA_SOURCES_DIR}"
if amneziaPpaSourceEntriesExist "${AMNEZIA_PPA_SOURCES_DIR}" "${ARCHITECTURE}"; then
	echo "ERROR: Amnezia PPA source still exists after exact cleanup" >&2
	exit 1
else
	SOURCE_EXIST_RC=$?
	if [[ "${SOURCE_EXIST_RC}" -ne 1 ]]; then
		echo "ERROR: PPA source cleanup left ambiguous source state" >&2
		exit 1
	fi
fi
enable_apt_ipv4
apt-get -o APT::Update::Error-Mode=any update
disable_apt_ipv4

echo "Ubuntu 26.04 live AmneziaWG smoke test: OK"
