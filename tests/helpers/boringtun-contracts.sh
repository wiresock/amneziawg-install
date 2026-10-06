# shellcheck shell=bash
# Checks of this repository's three BoringTun contracts, each on its own terms.
# Sourced by tests/test-boringtun-artifact.sh, tests/test-boringtun-host.sh,
# tests/test-boringtun-release.sh, tests/test-boringtun-public-release.sh and
# tests/test-boringtun-host-live.sh.
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
	_btc_embedded_release_problems "$1" with-build
}

# The same checks for an installer version from before AWG_BT_RELEASE_BUILD
# existed, read as data: 9f5a1afb87f7, the earlier installer that the live
# upgrade test installs with, embeds every other name and no build number,
# and its release is build 1. Here AWG_BT_RELEASE_BUILD must not be assigned
# at all, and the tag must end in -b1. Only historical installers are held to
# this; this repository's installer must embed its build
# (btc_embedded_release_problems).
btc_buildless_embedded_release_problems() { # <installer>
	_btc_embedded_release_problems "$1" without-build
}

_btc_embedded_release_problems() { # <installer> <with-build | without-build>
	local INSTALLER="$1" FORMAT="$2" NAME COUNT STEM ARCH
	local -A E=()
	case "${FORMAT}" in
		with-build | without-build) ;;
		*)
			echo "'${FORMAT}' is not an embedded release format"
			return 0
			;;
	esac
	for NAME in ${BTC_EMBEDDED_NAMES}; do
		COUNT="$(grep -c "^AWG_BT_RELEASE_${NAME}=" "${INSTALLER}")"
		if [[ "${NAME}" == BUILD && "${FORMAT}" == without-build ]]; then
			[[ "${COUNT}" == 0 ]] ||
				echo "AWG_BT_RELEASE_BUILD is assigned ${COUNT} times, but an installer without a build number assigns it none"
			E[BUILD]=1
			continue
		fi
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
#
# The check fails closed: when the repository cannot be read completely, it
# prints the scan's diagnostic and returns 1, also when the part it could read
# matched as expected. grep exits 0 with matches, 1 without any and 2 after an
# error, whether or not it matched elsewhere; only 0 and 1 without a
# diagnostic are a complete scan.
btc_pin_commit_problems() { # <repository root> <pin commit>
	local ROOT="$1" COMMIT="$2" FILE LINE LINES RC SCAN ERRORS
	if [[ ! "${COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
		echo "the pin's commit '${COMMIT}' is not a full commit SHA"
		return 0
	fi
	grep -qx "BORINGTUN_COMMIT=${COMMIT}" "${ROOT}/packaging/boringtun/pin.env" ||
		echo "packaging/boringtun/pin.env does not define BORINGTUN_COMMIT=${COMMIT}"
	grep -qx "BORINGTUN_RELEASE_SOURCE_COMMIT=${COMMIT}" "${ROOT}/packaging/boringtun/release.env" ||
		echo "packaging/boringtun/release.env does not restate the pinned commit"
	SCAN="$(mktemp)" || { echo "cannot create a temporary file for the scan of ${ROOT}"; return 1; }
	ERRORS="$(mktemp)" || { rm -f -- "${SCAN}"; echo "cannot create a temporary file for the scan of ${ROOT}"; return 1; }
	# NUL-terminated names, in a file: the scan's own exit status is kept, and
	# no name is split or evaluated.
	(cd -- "${ROOT}" || exit 2; grep -rlZF --exclude-dir=.git --exclude-dir=target --exclude='*.md' -e "${COMMIT}" .) \
		>"${SCAN}" 2>"${ERRORS}"
	RC=$?
	if ((RC > 1)) || [[ -s "${ERRORS}" ]] || ! LC_ALL=C sort -z -o "${SCAN}" -- "${SCAN}" 2>>"${ERRORS}"; then
		echo "the scan of ${ROOT} for the pinned commit did not complete (exit ${RC}): $(tr '\n' ' ' <"${ERRORS}")"
		rm -f -- "${SCAN}" "${ERRORS}"
		return 1
	fi
	while IFS= read -r -d '' FILE; do
		FILE="${FILE#./}"
		case "${FILE}" in
			packaging/boringtun/pin.env | packaging/boringtun/release.env) ;;
			amneziawg-install.sh)
				# Its lines with the commit, read with grep's status kept: a
				# read error must not look like "no other line".
				LINES="$(grep -F -e "${COMMIT}" -- "${ROOT}/${FILE}")"
				RC=$?
				if ((RC > 1)); then
					echo "amneziawg-install.sh could not be read for the pinned commit (exit ${RC})"
					rm -f -- "${SCAN}" "${ERRORS}"
					return 1
				fi
				((RC == 0)) && while IFS= read -r LINE; do
					[[ "${LINE}" == "AWG_BT_RELEASE_SOURCE_COMMIT=\"${COMMIT}\"" ]] && continue
					echo "amneziawg-install.sh repeats the pinned commit outside AWG_BT_RELEASE_SOURCE_COMMIT"
					break
				done <<<"${LINES}"
				;;
			*) echo "${FILE} repeats the pinned commit" ;;
		esac
	done <"${SCAN}"
	rm -f -- "${SCAN}" "${ERRORS}"
}
