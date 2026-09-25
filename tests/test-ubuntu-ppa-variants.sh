#!/bin/bash
# Disposable Ubuntu 26.04 reproduction of the APT architecture-variant failure
# with the Amnezia PPA, against the live PPA. With APT::Architecture-Variants
# enabled (Canonical's cloud images enable amd64v3), APT reads an unpinned
# source whose Release file lists amd64v3 only through that index, and the
# PPA's amd64v3 index has no amneziawg-tools. The installer pins its PPA source
# to the native dpkg architecture; this test drives the real configuration and
# refresh paths and checks what APT actually fetches and can install.
#
# It rewrites APT configuration and sources, so it runs only in a disposable
# container or VM that sets AWG_DISPOSABLE_APT_TEST=1, for example:
#   docker run --rm -e AWG_DISPOSABLE_APT_TEST=1 -v "$PWD:/workspace:ro" \
#     -w /workspace ubuntu:26.04 bash tests/test-ubuntu-ppa-variants.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VARIANT_CONF="/etc/apt/apt.conf.d/99-amneziawg-test-variant"
UPDATE_LOG="$(mktemp)"
PASSED=0
FAILED=0

function die() {
	echo "ERROR: $*" >&2
	exit 2
}

if [[ "${AWG_DISPOSABLE_APT_TEST:-}" != "1" ]]; then
	die "this test rewrites APT configuration; run it only in a disposable environment with AWG_DISPOSABLE_APT_TEST=1"
fi
[[ "${EUID}" -eq 0 ]] || die "must run as root"
# shellcheck source=/etc/os-release
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "26.04" ]]; then
	die "expected Ubuntu 26.04, got ${PRETTY_NAME:-unknown}"
fi

function ok() {
	echo "  OK: $1"
	PASSED=$((PASSED + 1))
}

function bad() {
	echo "  FAIL: $1"
	FAILED=$((FAILED + 1))
}

function check() { # <message> <command...>
	local MESSAGE="$1"
	shift
	if "$@"; then ok "${MESSAGE}"; else bad "${MESSAGE}"; fi
}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null || die "apt-get update failed"
apt-get install -y -qq ca-certificates curl gnupg python3 software-properties-common >/dev/null ||
	die "could not install the installer's Ubuntu prerequisites"

# shellcheck source=../amneziawg-install.sh
source "${PROJECT_ROOT}/amneziawg-install.sh"
# shellcheck source=/etc/os-release
source /etc/os-release
ARCH="$(getNativeDpkgArchitecture)" || die "dpkg reports no valid architecture"

function cleanup() {
	removeAmneziaPpaSourceEntries "${AMNEZIA_PPA_SOURCES_DIR}" >/dev/null 2>&1
	rm -f "${VARIANT_CONF}" "${UPDATE_LOG}"
}
trap cleanup EXIT

function set_variant() { # <variant list, "auto", or empty for none>
	if [[ -n "$1" ]]; then
		printf 'APT::Architecture-Variants "%s";\n' "$1" > "${VARIANT_CONF}"
	else
		rm -f "${VARIANT_CONF}"
	fi
}

function ppa_source_file() {
	grep -l 'ppa.launchpadcontent.net/amnezia/ppa/ubuntu' \
		"${AMNEZIA_PPA_SOURCES_DIR}"/*.sources "${AMNEZIA_PPA_SOURCES_DIR}"/*.list 2>/dev/null
}

# Refresh with the PPA's cached lists removed, so the lists directory shows
# exactly which PPA indexes this APT configuration fetches.
function refresh_lists() {
	rm -f /var/lib/apt/lists/ppa.launchpadcontent.net_amnezia_ppa_ubuntu_*
	apt-get -o APT::Update::Error-Mode=any update > "${UPDATE_LOG}" 2>&1
}

function ppa_indexes() {
	find /var/lib/apt/lists -maxdepth 1 -name 'ppa.launchpadcontent.net_amnezia_ppa_ubuntu_dists_*_Packages*' -printf '%f\n' |
		sed -n 's/^ppa\.launchpadcontent\.net_amnezia_ppa_ubuntu_dists_\([a-z0-9-]*\)_main_binary-\([a-z0-9-]*\)_Packages.*$/\1 \2/p' |
		sort -u | paste -sd ',' -
}

function simulate_install() {
	apt-get -s install amneziawg amneziawg-dkms amneziawg-tools > /dev/null 2>&1
}

# expect_pinned_source <label> <suite>: the managed source, what APT fetches for
# it, the installer's candidate preflight, and a simulated install.
function expect_pinned_source() {
	local LABEL="$1"
	local SUITE="$2"
	local FILE
	FILE="$(ppa_source_file)"
	echo "--- ${LABEL}: managed source (inline key omitted)"
	grep -v '^[[:space:]]' "${FILE}"
	check "${LABEL}: source uses the ${SUITE} suite" grep -qx "Suites: ${SUITE}" "${FILE}"
	check "${LABEL}: source has exactly one 'Architectures: ${ARCH}'" \
		test "$(grep -c "^Architectures: ${ARCH}\$" "${FILE}")/$(grep -ciE '^Architectures(-Add|-Remove)?:' "${FILE}")" = "1/1"
	check "${LABEL}: apt-get update succeeds" refresh_lists
	check "${LABEL}: APT fetches only the PPA's plain ${ARCH} index (got '$(ppa_indexes)')" \
		test "$(ppa_indexes)" = "${SUITE} ${ARCH}"
	check "${LABEL}: the installer's amneziawg-tools preflight passes" checkAmneziaPpaToolsCandidate "${SUITE}" "${ARCH}"
	check "${LABEL}: a simulated install of amneziawg, amneziawg-dkms and amneziawg-tools succeeds" simulate_install
}

echo "=== Environment ==="
echo "${PRETTY_NAME}, dpkg architecture ${ARCH}, $(apt-get --version | head -n 1)"
/lib64/ld-linux-x86-64.so.2 --help 2>/dev/null | grep -E 'x86-64-v3' || true

if [[ "${ARCH}" == "amd64" ]]; then
	echo "=== Unpinned source with amd64v3 enabled (observation of the original failure) ==="
	set_variant amd64v3
	removeAmneziaPpaSourceEntries "${AMNEZIA_PPA_SOURCES_DIR}" > /dev/null
	add-apt-repository -y -n ppa:amnezia/ppa > /dev/null 2>&1 || die "add-apt-repository failed"
	refresh_lists || die "apt-get update failed for the unpinned source"
	if checkAmneziaPpaToolsCandidate resolute amd64 2> /dev/null; then
		echo "  OBSERVED: the unpinned source now offers amneziawg-tools (PPA indexes: $(ppa_indexes)); the PPA may have been fixed upstream"
	else
		echo "  OBSERVED: the unpinned source has no amneziawg-tools candidate (PPA indexes: $(ppa_indexes)), as on Ubuntu 26.04 cloud images"
	fi
	removeAmneziaPpaSourceEntries "${AMNEZIA_PPA_SOURCES_DIR}" > /dev/null

	echo "=== Fresh configuration with APT::Architecture-Variants \"amd64v3\" ==="
	check "fresh configureUbuntuAmneziaPpa succeeds" configureUbuntuAmneziaPpa "" "${AMNEZIA_PPA_SOURCES_DIR}"
	expect_pinned_source "amd64v3" resolute

	echo "=== APT::Architecture-Variants \"auto\" ==="
	set_variant auto
	VARIANT_DEBUG="$(apt-get -o Debug::Acquire::Variants=1 update 2>&1)"
	grep -m 1 'Variants enabled' <<< "${VARIANT_DEBUG}" || echo "  (auto enabled no variant on this CPU)"
	expect_pinned_source "auto" resolute
fi

echo "=== No architecture variant configured (control) ==="
set_variant ""
expect_pinned_source "variants off" resolute

# A host installed while the PPA had no resolute suite has an unpinned noble
# entry and amneziawg-tools from noble. The refresh on the next installer run
# moves it to resolute and pins it in the same reconciliation.
echo "=== Existing noble install refreshed to resolute ==="
[[ "${ARCH}" == "amd64" ]] && set_variant amd64v3
removeAmneziaPpaSourceEntries "${AMNEZIA_PPA_SOURCES_DIR}" > /dev/null
add-apt-repository -y -n ppa:amnezia/ppa > /dev/null 2>&1 || die "add-apt-repository failed"
sed -i 's/^Suites: resolute$/Suites: noble/' "$(ppa_source_file)"
refresh_lists || die "apt-get update failed for the noble source"
apt-get install -y -qq --no-install-recommends amneziawg-tools > /dev/null 2>&1 ||
	die "could not install amneziawg-tools from noble to model an existing host"
echo "  existing host: amneziawg-tools $(dpkg-query -W -f='${Version}' amneziawg-tools) from noble"
check "refreshConfiguredUbuntuAmneziaPpa succeeds" refreshConfiguredUbuntuAmneziaPpa
expect_pinned_source "noble to resolute" resolute
check "the refreshed host can upgrade amneziawg-tools to the resolute build" \
	grep -q 'ubuntu26\.04' <<< "$(apt-get -s install amneziawg-tools 2>/dev/null | grep '^Inst amneziawg-tools')"

echo
echo "Ubuntu PPA architecture-variant tests: ${PASSED} passed, ${FAILED} failed"
[[ "${FAILED}" -eq 0 ]]
