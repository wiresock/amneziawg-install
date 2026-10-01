#!/usr/bin/env bash
# shellcheck shell=bash
#
# TEST FIXTURE for the live BoringTun binary-lifecycle tests, sourced by
# tests/test-boringtun-host-live.sh and tests/test-boringtun-kernel-coexistence.sh
# on disposable hosts only.
#
# There is one published BoringTun release. To exercise --upgrade-boringtun and
# --rollback-boringtun against it, these helpers build a second, older-looking
# release in the store from the already verified pinned binary: the same bytes
# under a synthetic source commit (feedface...), so its store name and
# MANIFEST differ while its binary and version are the real ones. It is not a
# published release and nothing claims it is. The installer cannot select it
# by itself: the test makes it current by writing the link directly, as an
# earlier installer would have left an older release, and the real pinned
# release stays the upgrade target, downloaded through the public release path.

BT_FIXTURE_COMMIT="feedfacefeedfacefeedfacefeedfacefeedface"

# bt_fixture_release <store> <pinned release id>: create the TEST FIXTURE
# release next to the pinned one (root-owned, the release's modes, single-link
# files) and print its store name.
bt_fixture_release() {
	local STORE="$1" PINNED="$2" FIXTURE FILE
	FIXTURE="$(sed -E "s/-g[0-9a-f]{12}-/-g${BT_FIXTURE_COMMIT:0:12}-/" <<<"${PINNED}")"
	[[ "${FIXTURE}" != "${PINNED}" && ! -e "${STORE}/${FIXTURE}" ]] || return 1
	mkdir -m 0755 -- "${STORE}/${FIXTURE}" || return 1
	for FILE in LICENSE THIRD-PARTY-LICENSES boringtun-cli; do
		cp -- "${STORE}/${PINNED}/${FILE}" "${STORE}/${FIXTURE}/${FILE}" || return 1
	done
	sed "s/^source_commit=.*/source_commit=${BT_FIXTURE_COMMIT}/" "${STORE}/${PINNED}/MANIFEST" >"${STORE}/${FIXTURE}/MANIFEST" || return 1
	chmod 0644 -- "${STORE}/${FIXTURE}/LICENSE" "${STORE}/${FIXTURE}/THIRD-PARTY-LICENSES" "${STORE}/${FIXTURE}/MANIFEST"
	chmod 0755 -- "${STORE}/${FIXTURE}/boringtun-cli"
	chown -R 0:0 -- "${STORE}/${FIXTURE}"
	printf '%s\n' "${FIXTURE}"
}

# bt_fixture_make_current <store> <fixture id>: point current at the TEST
# FIXTURE atomically and drop previous, as a store an earlier installer left
# would look. Only tests do this; the installer never selects a release it
# did not install through its own lifecycle.
bt_fixture_make_current() {
	ln -s -- "$2" "$1/.current.fixture" && mv -T -f -- "$1/.current.fixture" "$1/current" && rm -f -- "$1/previous"
}

# The release the main process of a unit executes, by store name.
bt_unit_release() { # <unit> <store>
	local PID EXE STORE
	PID="$(systemctl show -p MainPID --value "$1" 2>/dev/null)"
	EXE="$(readlink "/proc/${PID}/exe" 2>/dev/null)" || return 1
	STORE="$(readlink -f "$2")"
	EXE="${EXE#"${STORE}"/}"
	printf '%s\n' "${EXE%/boringtun-cli}"
}

# bt_fixture_build2 <store> <pinned release id>: a TEST FIXTURE build 2 of the
# pinned source commit (the same files and MANIFEST under the -b2 store name
# that a later build of that commit would get), and print its store name. Its
# name is one the helpers of installer versions before PR 6 refuse.
bt_fixture_build2() {
	local STORE="$1" PINNED="$2" FIXTURE FILE
	FIXTURE="$(sed -E 's/(-g[0-9a-f]{12})-linux-/\1-b2-linux-/' <<<"${PINNED}")"
	[[ "${FIXTURE}" != "${PINNED}" && ! -e "${STORE}/${FIXTURE}" ]] || return 1
	mkdir -m 0755 -- "${STORE}/${FIXTURE}" || return 1
	for FILE in LICENSE MANIFEST THIRD-PARTY-LICENSES boringtun-cli; do
		cp -- "${STORE}/${PINNED}/${FILE}" "${STORE}/${FIXTURE}/${FILE}" || return 1
	done
	chmod 0644 -- "${STORE}/${FIXTURE}/LICENSE" "${STORE}/${FIXTURE}/THIRD-PARTY-LICENSES" "${STORE}/${FIXTURE}/MANIFEST"
	chmod 0755 -- "${STORE}/${FIXTURE}/boringtun-cli"
	chown -R 0:0 -- "${STORE}/${FIXTURE}"
	printf '%s\n' "${FIXTURE}"
}

# bt_fixture_make_previous <store> <release id>: point previous at a TEST
# FIXTURE atomically, as a test only.
bt_fixture_make_previous() {
	ln -s -- "$2" "$1/.previous.fixture" && mv -T -f -- "$1/.previous.fixture" "$1/previous"
}
