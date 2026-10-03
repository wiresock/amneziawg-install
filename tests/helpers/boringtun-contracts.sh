# shellcheck shell=bash
# Checks of this repository's three BoringTun contracts, each on its own terms.
# Sourced by tests/test-boringtun-artifact.sh, tests/test-boringtun-host.sh,
# tests/test-boringtun-release.sh and tests/test-boringtun-public-release.sh.
#
#  1. packaging/boringtun/pin.env, the artifact source pin: the WireSock
#     BoringTun commit the artifact pipeline builds.
#  2. packaging/boringtun/release.env, the release contract: the build of that
#     pin that is being prepared, reviewed or published (candidate or
#     approved). It always matches pin.env, which scripts/boringtun-release.sh
#     enforces.
#  3. The AWG_BT_RELEASE_* constants of amneziawg-install.sh: the published,
#     immutable release this installer downloads and trusts.
#
# A release is built, approved and published before any installer uses it, and
# an installer adopts it only in a later, separate change of its constants. In
# between, the installer still embeds an earlier published release, so 3 may
# differ from 1 and 2, as a candidate or as an approved and published release.
# Nothing here compares 3 with 1 or 2.

BTC_SOURCE_REPOSITORY="https://github.com/Wiresock-Foundation/wiresock-boringtun"
BTC_RELEASE_DOWNLOAD_URL="https://github.com/wiresock/amneziawg-install/releases/download"
BTC_EMBEDDED_NAMES="TAG BASE_URL VERSION SOURCE_REPOSITORY SOURCE_COMMIT BUILD
ASSET_X86_64 ARCHIVE_SHA256_X86_64 BINARY_SHA256_X86_64
ASSET_AARCH64 ARCHIVE_SHA256_AARCH64 BINARY_SHA256_AARCH64"

# AWG_BT_RELEASE_<NAME> of an installer, read as data.
btc_embedded_value() { # <installer> <NAME>
	sed -n "s/^AWG_BT_RELEASE_$2=\"\\(.*\\)\"\$/\\1/p" "$1"
}

# Every way in which the release an installer embeds is not internally
# consistent, one per line; nothing when it is. The tag, the download URL and
# the asset names must all follow from the embedded version, source commit and
# build, and the four hashes must be four different SHA-256 values.
btc_embedded_release_problems() { # <installer>
	local INSTALLER="$1" NAME COUNT STEM ARCH
	local -A E=()
	for NAME in ${BTC_EMBEDDED_NAMES}; do
		COUNT="$(grep -c "^AWG_BT_RELEASE_${NAME}=" "${INSTALLER}")"
		[[ "${COUNT}" == 1 ]] || echo "AWG_BT_RELEASE_${NAME} is assigned ${COUNT} times, not once"
		E[${NAME}]="$(btc_embedded_value "${INSTALLER}" "${NAME}" | head -n 1)"
	done
	[[ "${E[VERSION]}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
		echo "AWG_BT_RELEASE_VERSION '${E[VERSION]}' is not a release version"
	[[ "${E[SOURCE_REPOSITORY]}" == "${BTC_SOURCE_REPOSITORY}" ]] ||
		echo "AWG_BT_RELEASE_SOURCE_REPOSITORY '${E[SOURCE_REPOSITORY]}' is not ${BTC_SOURCE_REPOSITORY}"
	[[ "${E[SOURCE_COMMIT]}" =~ ^[0-9a-f]{40}$ ]] ||
		echo "AWG_BT_RELEASE_SOURCE_COMMIT '${E[SOURCE_COMMIT]}' is not a full commit SHA"
	[[ "${E[BUILD]}" =~ ^[1-9][0-9]{0,8}$ ]] ||
		echo "AWG_BT_RELEASE_BUILD '${E[BUILD]}' is not a positive build number"
	STEM="boringtun-cli-${E[VERSION]}-g${E[SOURCE_COMMIT]:0:12}"
	[[ "${E[TAG]}" == "${STEM}-b${E[BUILD]}" ]] ||
		echo "AWG_BT_RELEASE_TAG '${E[TAG]}' is not ${STEM}-b${E[BUILD]}"
	[[ "${E[BASE_URL]}" == "${BTC_RELEASE_DOWNLOAD_URL}/${E[TAG]}" ]] ||
		echo "AWG_BT_RELEASE_BASE_URL '${E[BASE_URL]}' is not ${BTC_RELEASE_DOWNLOAD_URL}/${E[TAG]}"
	for ARCH in X86_64:x86_64 AARCH64:aarch64; do
		[[ "${E[ASSET_${ARCH%%:*}]}" == "${STEM}-linux-${ARCH#*:}-musl.tar.gz" ]] ||
			echo "AWG_BT_RELEASE_ASSET_${ARCH%%:*} '${E[ASSET_${ARCH%%:*}]}' is not ${STEM}-linux-${ARCH#*:}-musl.tar.gz"
	done
	for NAME in ARCHIVE_SHA256_X86_64 BINARY_SHA256_X86_64 ARCHIVE_SHA256_AARCH64 BINARY_SHA256_AARCH64; do
		[[ "${E[${NAME}]}" =~ ^[0-9a-f]{64}$ ]] ||
			echo "AWG_BT_RELEASE_${NAME} '${E[${NAME}]}' is not a lowercase SHA-256"
	done
	COUNT="$(printf '%s\n' "${E[ARCHIVE_SHA256_X86_64]}" "${E[BINARY_SHA256_X86_64]}" \
		"${E[ARCHIVE_SHA256_AARCH64]}" "${E[BINARY_SHA256_AARCH64]}" | LC_ALL=C sort -u | wc -l)"
	[[ "${COUNT}" == 4 ]] || echo "the four embedded SHA-256 values are not four different values"
}

# Every way in which the artifact pin's commit is not where it belongs, one per
# line; nothing when it is. pin.env defines it and release.env restates it as
# the provenance of the release it describes; no script, workflow or
# configuration repeats it (documentation, *.md, may quote it). The installer
# never needs it: it may hold it only as its AWG_BT_RELEASE_SOURCE_COMMIT, when
# the release it embeds is a build of the same pin.
btc_pin_commit_problems() { # <repository root> <pin commit>
	local ROOT="$1" COMMIT="$2" FILE
	if [[ ! "${COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
		echo "the pin's commit '${COMMIT}' is not a full commit SHA"
		return 0
	fi
	grep -qx "BORINGTUN_COMMIT=${COMMIT}" "${ROOT}/packaging/boringtun/pin.env" ||
		echo "packaging/boringtun/pin.env does not define BORINGTUN_COMMIT=${COMMIT}"
	grep -qx "BORINGTUN_RELEASE_SOURCE_COMMIT=${COMMIT}" "${ROOT}/packaging/boringtun/release.env" ||
		echo "packaging/boringtun/release.env does not restate the pinned commit"
	while IFS= read -r FILE; do
		case "${FILE}" in
			packaging/boringtun/pin.env | packaging/boringtun/release.env) ;;
			amneziawg-install.sh)
				# No -q: an early exit would fail the pipe under pipefail.
				if grep -F -e "${COMMIT}" "${ROOT}/${FILE}" | grep -vx "AWG_BT_RELEASE_SOURCE_COMMIT=\"${COMMIT}\"" >/dev/null; then
					echo "amneziawg-install.sh repeats the pinned commit outside AWG_BT_RELEASE_SOURCE_COMMIT"
				fi
				;;
			*) echo "${FILE} repeats the pinned commit" ;;
		esac
	done < <(cd "${ROOT}" && grep -rlF --exclude-dir=.git --exclude-dir=target --exclude='*.md' -e "${COMMIT}" . |
		sed 's#^\./##' | LC_ALL=C sort)
}
