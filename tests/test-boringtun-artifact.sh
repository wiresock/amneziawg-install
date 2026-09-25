#!/usr/bin/env bash

# Unit tests for scripts/boringtun-artifact.sh. Nothing here compiles Rust:
# a fixture git repository stands in for the BoringTun source, a shell script
# for the binary, and mocks for cargo, rustc, readelf and uname. The real build
# runs in .github/workflows/boringtun-artifacts.yml.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
ARTIFACT_SCRIPT="${PROJECT_ROOT}/scripts/boringtun-artifact.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-artifact-tests.XXXXXX")"
TEST_ROOT="$(CDPATH='' cd -- "${TEST_ROOT}" && pwd -P)"
BIN_DIR="${TEST_ROOT}/bin"
STATE="${TEST_ROOT}/state"
mkdir -p "${BIN_DIR}" "${STATE}" "${TEST_ROOT}/home" "${TEST_ROOT}/cargo-home"

cleanup() {
	rm -rf -- "${TEST_ROOT}"
}
trap cleanup EXIT

PASS=0
FAIL=0

ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}

not_ok() {
	printf '  FAIL: %s\n' "$1" >&2
	FAIL=$((FAIL + 1))
}

assert_eq() {
	local EXPECTED="$1"
	local ACTUAL="$2"
	local NAME="$3"
	if [[ "${ACTUAL}" == "${EXPECTED}" ]]; then
		ok "${NAME}"
	else
		not_ok "${NAME}"
		printf '    expected:\n%s\n    actual:\n%s\n' \
			"$(sed 's/^/      /' <<<"${EXPECTED}")" "$(sed 's/^/      /' <<<"${ACTUAL}")" >&2
	fi
}

# Run the script with the mocks first in PATH, a private HOME and CARGO_HOME,
# and the given pin. Sets RUN_RC, RUN_OUT and RUN_ERR.
PIN_FILE="${TEST_ROOT}/pin.env"
run_script() {
	env PATH="${BIN_DIR}:${PATH}" HOME="${TEST_ROOT}/home" CARGO_HOME="${TEST_ROOT}/cargo-home" \
		RUSTUP_HOME="${TEST_ROOT}/home/.rustup" BORINGTUN_PIN_FILE="${PIN_FILE}" \
		RUSTFLAGS="--caller-rustflags-must-not-leak" CFLAGS="-DCALLER_CFLAGS" \
		bash "${ARTIFACT_SCRIPT}" "$@" >"${TEST_ROOT}/run.out" 2>"${TEST_ROOT}/run.err"
	RUN_RC=$?
	RUN_OUT="$(cat "${TEST_ROOT}/run.out")"
	RUN_ERR="$(cat "${TEST_ROOT}/run.err")"
}

# Pass when the command failed and stderr contains the expected message.
assert_fails_with() {
	local MESSAGE="$1"
	local NAME="$2"
	if (( RUN_RC != 0 )) && [[ "${RUN_ERR}" == *"${MESSAGE}"* ]]; then
		ok "${NAME}"
	else
		not_ok "${NAME} (rc ${RUN_RC}, stderr: ${RUN_ERR})"
	fi
}

assert_succeeds() {
	local NAME="$1"
	if (( RUN_RC == 0 )); then
		ok "${NAME}"
	else
		not_ok "${NAME} (rc ${RUN_RC}, stderr: ${RUN_ERR})"
	fi
}

# ── Mocks ────────────────────────────────────────────────────────────────────
# The script runs Cargo under `env -i`, so the mocks read their settings from
# files in ${STATE} rather than from the environment.
REAL_UNAME="$(command -v uname)"
cat >"${BIN_DIR}/uname" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "-m" ]]; then
	cat "${STATE}/arch" 2>/dev/null || echo x86_64
else
	exec "${REAL_UNAME}" "\$@"
fi
EOF

cat >"${BIN_DIR}/rustc" <<EOF
#!/usr/bin/env bash
printf 'rustc %s (0000000aa 2026-09-01)\n' "\$(cat "${STATE}/toolchain" 2>/dev/null || echo 1.98.1)"
EOF

cat >"${BIN_DIR}/cargo" <<EOF
#!/usr/bin/env bash
STATE="${STATE}"
EOF
cat >>"${BIN_DIR}/cargo" <<'EOF'
printf '%s\n' "$*" >>"${STATE}/cargo.log"
case "${1:-}" in
	--version)
		printf 'cargo %s (0000000bb 2026-08-05)\n' "$(cat "${STATE}/toolchain" 2>/dev/null || echo 1.98.1)"
		;;
	build)
		env | LC_ALL=C sort >"${STATE}/cargo-build.env"
		mode="$(cat "${STATE}/cargo-mode" 2>/dev/null || true)"
		target=""
		while (( $# > 0 )); do
			[[ "$1" == "--target" ]] && target="$2"
			shift
		done
		case "${mode}" in
			fail) exit 101 ;;
			no-binary) exit 0 ;;
			touch-lock) printf '# changed\n' >>Cargo.lock ;;
		esac
		mkdir -p "${CARGO_TARGET_DIR}/${target}/release"
		cp "${STATE}/binary" "${CARGO_TARGET_DIR}/${target}/release/boringtun-cli"
		chmod 0755 "${CARGO_TARGET_DIR}/${target}/release/boringtun-cli"
		;;
	fetch)
		;;
	deny)
		[[ "$(cat "${STATE}/deny-mode" 2>/dev/null)" != "fail" ]]
		;;
	about)
		template="" output=""
		while (( $# > 0 )); do
			case "$1" in
				-o) output="$2"; shift ;;
				*.hbs) template="$1" ;;
			esac
			shift
		done
		if [[ "${template##*/}" == "about-crates.hbs" ]]; then
			cat "${STATE}/crates" >"${output}"
		else
			printf 'THIRD-PARTY LICENSES FOR boringtun-cli\n\nMIT License (1)\n\nUsed by:\n  ring 0.17.14\n' >"${output}"
		fi
		;;
esac
EOF

cat >"${BIN_DIR}/readelf" <<EOF
#!/usr/bin/env bash
STATE="${STATE}"
EOF
cat >>"${BIN_DIR}/readelf" <<'EOF'
case "${1:-}" in
	-hW)
		printf 'ELF Header:\n  Class:                             ELF64\n  Machine:                           %s\n' \
			"$(cat "${STATE}/machine" 2>/dev/null || echo 'Advanced Micro Devices X86-64')"
		;;
	-lW)
		[[ -e "${STATE}/interp" ]] && printf '  INTERP         0x000318 0x0000000000000318\n'
		printf '  LOAD           0x000000 0x0000000000000000\n'
		;;
	-dW)
		[[ -e "${STATE}/needed" ]] && printf ' 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]\n'
		exit 0
		;;
esac
EOF
touch "${BIN_DIR}/cargo-deny" "${BIN_DIR}/cargo-about"
chmod +x "${BIN_DIR}"/*

# A stand-in for boringtun-cli: the version it reports is $1.
write_fake_binary() {
	cat >"$2" <<EOF
#!/bin/sh
case "\$1" in
	--version) echo "boringtun $1" ;;
	--help) printf 'Usage: boringtun-cli [OPTIONS] <INTERFACE_NAME>\n      --tun-fd <TUN_FD>\n      --uapi-fd <UAPI_FD>\n' ;;
esac
EOF
	chmod 0755 "$2"
}
write_fake_binary 0.7.1 "${STATE}/binary"

# ── Fixture BoringTun source ─────────────────────────────────────────────────
SOURCE="${TEST_ROOT}/work/boringtun-src"
mkdir -p "${SOURCE}/boringtun-cli"
printf '[workspace]\nmembers = ["boringtun-cli"]\n' >"${SOURCE}/Cargo.toml"
printf '# fixture lockfile\nversion = 4\n' >"${SOURCE}/Cargo.lock"
printf 'Copyright (c) 2019 Cloudflare, Inc. All rights reserved.\n\nRedistribution and use in source and binary forms, with or without modification, are permitted.\n' \
	>"${SOURCE}/LICENSE.md"
printf '[package]\nname = "boringtun-cli"\nversion = "0.7.1"\n\n[dependencies.boringtun]\nversion = "0.7.1"\n' \
	>"${SOURCE}/boringtun-cli/Cargo.toml"
git -C "${SOURCE}" init -q
git -C "${SOURCE}" add -A
GIT_AUTHOR_DATE="2026-09-24T21:23:28Z" GIT_COMMITTER_DATE="2026-09-24T21:23:28Z" \
	git -C "${SOURCE}" -c user.name=fixture -c user.email=fixture@example.invalid commit -q -m fixture
SOURCE_COMMIT="$(git -C "${SOURCE}" rev-parse HEAD)"
SOURCE_EPOCH="$(git -C "${SOURCE}" show -s --format=%ct HEAD)"
TARGET="x86_64-unknown-linux-musl"
STEM="boringtun-cli-0.7.1-g${SOURCE_COMMIT:0:12}-linux-x86_64-musl"

write_pin() {
	cat >"${PIN_FILE}" <<EOF
# fixture pin
BORINGTUN_REPOSITORY=https://github.com/Wiresock-Foundation/wiresock-boringtun
BORINGTUN_COMMIT=${1:-${SOURCE_COMMIT}}

BORINGTUN_VERSION=${2:-0.7.1}
BORINGTUN_RUST_TOOLCHAIN=1.98.1
BORINGTUN_ARTIFACT_FORMAT=1
EOF
}

echo "=== Pin file ==="

run_script pin
assert_fails_with "pin file is missing" "a missing pin file is rejected"

write_pin
run_script pin
assert_eq "BORINGTUN_REPOSITORY=https://github.com/Wiresock-Foundation/wiresock-boringtun
BORINGTUN_COMMIT=${SOURCE_COMMIT}
BORINGTUN_VERSION=0.7.1
BORINGTUN_RUST_TOOLCHAIN=1.98.1
BORINGTUN_ARTIFACT_FORMAT=1" "${RUN_OUT}" "a valid pin with comments and blank lines is printed as KEY=VALUE"

REPO_PIN_COMMIT="$(env BORINGTUN_PIN_FILE="${PROJECT_ROOT}/packaging/boringtun/pin.env" \
	bash "${ARTIFACT_SCRIPT}" pin 2>/dev/null | sed -n 's/^BORINGTUN_COMMIT=//p')"
if [[ "${REPO_PIN_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
	ok "the repository's own pin file is valid"
else
	not_ok "the repository's own pin file is valid"
fi
# Scripts, workflows and configuration must read the commit from pin.env rather
# than repeat it; documentation may quote it.
assert_eq "packaging/boringtun/pin.env" \
	"$(cd "${PROJECT_ROOT}" && grep -rlF --exclude-dir=.git --exclude-dir=target --exclude='*.md' \
		-e "${REPO_PIN_COMMIT:-unset}" . | sed 's#^\./##')" \
	"the pinned commit is defined only in packaging/boringtun/pin.env"

# Each case: a label, then the complete pin file content.
check_bad_pin() {
	local LABEL="$1" CONTENT="$2" MESSAGE="$3"
	printf '%s\n' "${CONTENT}" >"${PIN_FILE}"
	run_script pin
	assert_fails_with "${MESSAGE}" "${LABEL}"
}
GOOD_REPO="BORINGTUN_REPOSITORY=https://github.com/Wiresock-Foundation/wiresock-boringtun"
GOOD_REST="BORINGTUN_VERSION=0.7.1
BORINGTUN_RUST_TOOLCHAIN=1.98.1
BORINGTUN_ARTIFACT_FORMAT=1"
check_bad_pin "a short commit is rejected" "${GOOD_REPO}
BORINGTUN_COMMIT=e4e4dc85ec03
${GOOD_REST}" "full 40-character"
check_bad_pin "an uppercase commit is rejected" "${GOOD_REPO}
BORINGTUN_COMMIT=E4E4DC85EC039D40BBC92B3667B7FC92966B1B0A
${GOOD_REST}" "full 40-character"
check_bad_pin "a non-hex commit is rejected" "${GOOD_REPO}
BORINGTUN_COMMIT=g4e4dc85ec039d40bbc92b3667b7fc92966b1b0a
${GOOD_REST}" "full 40-character"
check_bad_pin "a branch name is rejected as the commit" "${GOOD_REPO}
BORINGTUN_COMMIT=master
${GOOD_REST}" "full 40-character"
check_bad_pin "a missing key is rejected" "${GOOD_REPO}
${GOOD_REST}" "does not define BORINGTUN_COMMIT"
check_bad_pin "a duplicated key is rejected" "${GOOD_REPO}
BORINGTUN_COMMIT=${SOURCE_COMMIT}
BORINGTUN_COMMIT=${SOURCE_COMMIT}
${GOOD_REST}" "more than once"
check_bad_pin "an unknown key is rejected" "${GOOD_REPO}
BORINGTUN_COMMIT=${SOURCE_COMMIT}
BORINGTUN_BRANCH=master
${GOOD_REST}" "unknown key BORINGTUN_BRANCH"
check_bad_pin "a repository URL with .git is rejected" "BORINGTUN_REPOSITORY=https://github.com/Wiresock-Foundation/wiresock-boringtun.git
BORINGTUN_COMMIT=${SOURCE_COMMIT}
${GOOD_REST}" "without .git"
check_bad_pin "a non-HTTPS repository URL is rejected" "BORINGTUN_REPOSITORY=http://github.com/Wiresock-Foundation/wiresock-boringtun
BORINGTUN_COMMIT=${SOURCE_COMMIT}
${GOOD_REST}" "https://github.com"
check_bad_pin "a floating toolchain is rejected" "${GOOD_REPO}
BORINGTUN_COMMIT=${SOURCE_COMMIT}
BORINGTUN_VERSION=0.7.1
BORINGTUN_RUST_TOOLCHAIN=stable
BORINGTUN_ARTIFACT_FORMAT=1" "exact Rust release"
check_bad_pin "a quoted value is rejected" "${GOOD_REPO}
BORINGTUN_COMMIT='${SOURCE_COMMIT}'
${GOOD_REST}" "plain KEY=VALUE"
check_bad_pin "an exported assignment is rejected" "${GOOD_REPO}
export BORINGTUN_COMMIT=${SOURCE_COMMIT}
${GOOD_REST}" "plain KEY=VALUE"
CRLF_PIN="$(printf '%s\nBORINGTUN_COMMIT=%s\r\n%s\n' "${GOOD_REPO}" "${SOURCE_COMMIT}" "${GOOD_REST}")"
check_bad_pin "a CRLF line ending is rejected" "${CRLF_PIN}" "plain KEY=VALUE"
check_bad_pin "command substitution is rejected and never executed" "${GOOD_REPO}
BORINGTUN_COMMIT=\$(touch ${TEST_ROOT}/pwned)
${GOOD_REST}" "plain KEY=VALUE"
if [[ ! -e "${TEST_ROOT}/pwned" ]]; then
	ok "the pin file is parsed as data, not executed"
else
	not_ok "the pin file is parsed as data, not executed"
fi
ln -sf "${PROJECT_ROOT}/packaging/boringtun/pin.env" "${TEST_ROOT}/pin-link.env"
PIN_FILE="${TEST_ROOT}/pin-link.env"
run_script pin
assert_fails_with "not a regular file" "a symlinked pin file is rejected"
PIN_FILE="${TEST_ROOT}/pin.env"
write_pin

echo "=== Source and toolchain checks ==="

run_script build "${SOURCE}" x86_64-unknown-linux-gnu "${TEST_ROOT}/b-gnu"
assert_fails_with "unsupported target" "a glibc target is rejected"

printf 'aarch64\n' >"${STATE}/arch"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-cross"
assert_fails_with "only native builds are supported" "a cross-architecture build is rejected"
rm -f "${STATE}/arch"

write_pin 0123456789abcdef0123456789abcdef01234567
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-mismatch"
assert_fails_with "does not match the pinned commit" "a checkout of another commit is rejected"
write_pin

run_script build "${TEST_ROOT}/no-such-source" "${TARGET}" "${TEST_ROOT}/b-missing"
assert_fails_with "source directory not found" "a missing source directory is rejected"

printf '\n# local edit\n' >>"${SOURCE}/Cargo.toml"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-dirty"
assert_fails_with "local changes" "a modified tracked file is rejected"
git -C "${SOURCE}" checkout -q -- Cargo.toml

touch "${SOURCE}/untracked.rs"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-untracked"
assert_fails_with "local changes" "an untracked file in the source is rejected"
rm -f "${SOURCE}/untracked.rs"

write_pin "" 0.7.2
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-version"
assert_fails_with "declares version '0.7.1', but the pin expects 0.7.2" "a source version other than the pinned one is rejected"
write_pin

mkdir -p "${TEST_ROOT}/work/.cargo"
printf '[build]\nrustflags = ["-Cdebuginfo=2"]\n' >"${TEST_ROOT}/work/.cargo/config.toml"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-parent-config"
assert_fails_with "ambient Cargo configuration" "Cargo configuration above the source is rejected"
rm -rf "${TEST_ROOT}/work/.cargo"

printf '[build]\njobs = 1\n' >"${TEST_ROOT}/cargo-home/config.toml"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-home-config"
assert_fails_with "ambient Cargo configuration" "Cargo configuration in CARGO_HOME is rejected"
rm -f "${TEST_ROOT}/cargo-home/config.toml"

printf '1.97.0\n' >"${STATE}/toolchain"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-toolchain"
assert_fails_with "rustc 1.98.1 is required" "a toolchain other than the pinned one is rejected"
rm -f "${STATE}/toolchain"

echo "=== Build ==="

BUILD="${TEST_ROOT}/build-1"
: >"${STATE}/cargo.log"
run_script build "${SOURCE}" "${TARGET}" "${BUILD}"
assert_succeeds "a pinned, pristine source builds"
assert_eq "cargo build --release --locked -p boringtun-cli --bin boringtun-cli --target ${TARGET} --config target.${TARGET}.rustflags=[\"--remap-path-prefix=${SOURCE}=/boringtun\", \"--remap-path-prefix=${TEST_ROOT}/cargo-home=/cargo\"]" \
	"$(grep '^build ' "${STATE}/cargo.log" | sed 's/^/cargo /')" \
	"cargo builds only boringtun-cli, --locked, and remaps the source and Cargo home additively"
BUILD_ENV="$(grep -E '^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CFLAGS|CARGO_PROFILE_RELEASE_STRIP|SOURCE_DATE_EPOCH|LC_ALL|TZ|RUSTUP_TOOLCHAIN)=' "${STATE}/cargo-build.env")"
assert_eq "CARGO_PROFILE_RELEASE_STRIP=symbols
LC_ALL=C
RUSTUP_TOOLCHAIN=1.98.1
SOURCE_DATE_EPOCH=${SOURCE_EPOCH}
TZ=UTC" "${BUILD_ENV}" "cargo runs in a scrubbed environment: caller RUSTFLAGS and CFLAGS do not leak in"
assert_eq "755" "$(stat -c '%a' "${BUILD}/boringtun-cli")" "the built binary is mode 0755"
assert_eq "target=${TARGET}
rustc=rustc 1.98.1 (0000000aa 2026-09-01)
cargo=cargo 1.98.1 (0000000bb 2026-08-05)
source_date_epoch=${SOURCE_EPOCH}
build_command=cargo build --release --locked -p boringtun-cli --bin boringtun-cli --target ${TARGET}
binary_sha256=$(sha256sum "${BUILD}/boringtun-cli" | cut -d' ' -f1)" "$(cat "${BUILD}/BUILD-INFO")" \
	"BUILD-INFO records the target, toolchain, commit time, command and binary hash"
assert_eq "" "$(git -C "${SOURCE}" status --porcelain)" "the build leaves the source untouched"

run_script build "${SOURCE}" "${TARGET}" "${BUILD}"
assert_fails_with "must be new or empty" "an existing build directory is not reused"
run_script build "${SOURCE}" "${TARGET}" "${SOURCE}/target-inside"
assert_fails_with "outside the BoringTun source" "a build directory inside the source is rejected"
rm -rf "${SOURCE}/target-inside"

printf 'touch-lock\n' >"${STATE}/cargo-mode"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-lock"
assert_fails_with "changed Cargo.lock" "a build that changes Cargo.lock fails"
git -C "${SOURCE}" checkout -q -- Cargo.lock

printf 'no-binary\n' >"${STATE}/cargo-mode"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-nobin"
assert_fails_with "did not produce" "a build that produces no binary fails"
printf 'fail\n' >"${STATE}/cargo-mode"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-fail"
assert_fails_with "cargo build failed" "a failed cargo build fails"
rm -f "${STATE}/cargo-mode"

write_fake_binary 0.7.0 "${STATE}/binary"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-wrongver"
assert_fails_with "expected 'boringtun 0.7.1'" "a binary reporting another version fails"
write_fake_binary 0.7.1 "${STATE}/binary"

printf '# built in %s\n' "${SOURCE}" >>"${STATE}/binary"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-leak"
assert_fails_with "embeds the local path" "a binary embedding a local build path fails"
write_fake_binary 0.7.1 "${STATE}/binary"

touch "${STATE}/interp"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-interp"
assert_fails_with "requests a program interpreter" "a dynamically linked binary fails"
rm -f "${STATE}/interp"
touch "${STATE}/needed"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-needed"
assert_fails_with "depends on shared libraries" "a binary with shared library dependencies fails"
rm -f "${STATE}/needed"
printf 'AArch64\n' >"${STATE}/machine"
run_script build "${SOURCE}" "${TARGET}" "${TEST_ROOT}/b-machine"
assert_fails_with "is not a 64-bit x86_64 ELF executable" "a binary for another architecture fails"
rm -f "${STATE}/machine"

echo "=== Package ==="

THIRD_PARTY="${TEST_ROOT}/THIRD-PARTY-LICENSES"
printf 'THIRD-PARTY LICENSES FOR boringtun-cli\n\nfixture\n' >"${THIRD_PARTY}"
mkdir -p "${TEST_ROOT}/out-1" "${TEST_ROOT}/out-2"
run_script package "${BUILD}" "${SOURCE}" "${THIRD_PARTY}" "${TEST_ROOT}/out-1"
assert_succeeds "a build packages"
ARCHIVE="${TEST_ROOT}/out-1/${STEM}.tar.gz"
assert_eq "${ARCHIVE}" "${RUN_OUT}" "the archive name carries version, commit, OS, architecture and libc"
assert_eq "drwxr-xr-x 0/0 ${STEM}/
-rw-r--r-- 0/0 ${STEM}/LICENSE
-rw-r--r-- 0/0 ${STEM}/MANIFEST
-rw-r--r-- 0/0 ${STEM}/THIRD-PARTY-LICENSES
-rwxr-xr-x 0/0 ${STEM}/boringtun-cli" \
	"$(LC_ALL=C tar --numeric-owner -tvzf "${ARCHIVE}" | awk '{ print $1, $2, $6 }')" \
	"members are in name order under one directory, with fixed modes and owner 0/0"
assert_eq "${SOURCE_EPOCH}" "$(TZ=UTC LC_ALL=C tar --full-time -tvzf "${ARCHIVE}" | awk '{ print $4 " " $5 }' | sort -u | \
	while read -r d t; do date -u -d "${d} ${t}" +%s; done)" "every member's mtime is the pinned commit time"
assert_eq "00000000" "$(od -An -tx1 -j4 -N4 "${ARCHIVE}" | tr -d ' ')" "the gzip header carries no timestamp"
assert_eq "artifact_format=1
name=boringtun-cli
version=0.7.1
source_repository=https://github.com/Wiresock-Foundation/wiresock-boringtun
source_commit=${SOURCE_COMMIT}
source_date_epoch=${SOURCE_EPOCH}
target=${TARGET}
os=linux
arch=x86_64
libc=musl
linkage=static
rust_toolchain=1.98.1
rustc=rustc 1.98.1 (0000000aa 2026-09-01)
cargo=cargo 1.98.1 (0000000bb 2026-08-05)
build_command=cargo build --release --locked -p boringtun-cli --bin boringtun-cli --target ${TARGET}
build_profile=release,strip=symbols
rustflags=--remap-path-prefix=<source>=/boringtun --remap-path-prefix=<cargo-home>=/cargo
binary=boringtun-cli
binary_sha256=$(sha256sum "${BUILD}/boringtun-cli" | cut -d' ' -f1)
license=LICENSE (BSD-3-Clause)
third_party_licenses=THIRD-PARTY-LICENSES" "$(tar -xzOf "${ARCHIVE}" "${STEM}/MANIFEST")" \
	"MANIFEST records provenance without local paths"
assert_eq "$(cat "${SOURCE}/LICENSE.md")" "$(tar -xzOf "${ARCHIVE}" "${STEM}/LICENSE")" "LICENSE is BoringTun's LICENSE.md"
if ! tar -xzOf "${ARCHIVE}" "${STEM}/MANIFEST" | grep -qF "${TEST_ROOT}"; then
	ok "MANIFEST contains no build-host path"
else
	not_ok "MANIFEST contains no build-host path"
fi

# Packaging again from different file times and a different umask must give
# the same bytes.
touch -d '2001-02-03 04:05:06' "${BUILD}/boringtun-cli" "${THIRD_PARTY}"
(umask 077 && run_script package "${BUILD}" "${SOURCE}" "${THIRD_PARTY}" "${TEST_ROOT}/out-2")
if cmp -s "${ARCHIVE}" "${TEST_ROOT}/out-2/${STEM}.tar.gz"; then
	ok "packaging is deterministic across file times and umask"
else
	not_ok "packaging is deterministic across file times and umask"
fi
assert_eq "" "$(find "${TEST_ROOT}/out-1" "${TEST_ROOT}/out-2" -name '.package.*')" "no staging directory is left behind"

run_script package "${BUILD}" "${SOURCE}" "${THIRD_PARTY}" "${TEST_ROOT}/out-1"
assert_fails_with "refusing to overwrite" "an existing archive is not overwritten"
mkdir -p "${TEST_ROOT}/out-3"
: >"${TEST_ROOT}/empty-third-party"
run_script package "${BUILD}" "${SOURCE}" "${TEST_ROOT}/empty-third-party" "${TEST_ROOT}/out-3"
assert_fails_with "THIRD-PARTY-LICENSES file is missing or empty" "packaging requires third-party license notices"
cp -a "${BUILD}" "${TEST_ROOT}/build-tampered"
printf 'tampered\n' >>"${TEST_ROOT}/build-tampered/boringtun-cli"
run_script package "${TEST_ROOT}/build-tampered" "${SOURCE}" "${THIRD_PARTY}" "${TEST_ROOT}/out-3"
assert_fails_with "differs from the binary recorded in BUILD-INFO" "a binary changed after the build is not packaged"
assert_eq "" "$(ls -A "${TEST_ROOT}/out-3")" "failed packaging leaves nothing behind"

echo "=== Archive verification ==="

run_script verify-archive "${ARCHIVE}" "${TEST_ROOT}/extract-ok"
assert_succeeds "the packaged archive verifies"
assert_eq "${TEST_ROOT}/extract-ok/${STEM}/boringtun-cli" "${RUN_OUT}" "verification prints the extracted binary"

# Rebuild the archive from an edited copy of its tree to create bad inputs.
make_variant() {
	local NAME="$1"
	rm -rf "${TEST_ROOT}/variant" && mkdir -p "${TEST_ROOT}/variant" "${TEST_ROOT}/variants/${NAME}"
	tar -xzf "${ARCHIVE}" -C "${TEST_ROOT}/variant"
	VARIANT_DIR="${TEST_ROOT}/variant/${STEM}"
	VARIANT_ARCHIVE="${TEST_ROOT}/variants/${NAME}/${STEM}.tar.gz"
}
pack_variant() {
	(cd "${TEST_ROOT}/variant" && tar --sort=name --owner=0 --group=0 --numeric-owner "$@" -czf "${VARIANT_ARCHIVE}" -- "${STEM}")
}
check_variant() {
	run_script verify-archive "${VARIANT_ARCHIVE}" "${TEST_ROOT}/extract-$1"
	assert_fails_with "$2" "$3"
}

make_variant extra; printf 'x\n' >"${VARIANT_DIR}/README"; pack_variant
check_variant extra "exactly the expected members" "an archive with an extra member is rejected"
make_variant missing; rm "${VARIANT_DIR}/THIRD-PARTY-LICENSES"; pack_variant
check_variant missing "exactly the expected members" "an archive without third-party notices is rejected"
make_variant symlink; rm "${VARIANT_DIR}/LICENSE"; ln -s /etc/passwd "${VARIANT_DIR}/LICENSE"; pack_variant
check_variant symlink "has type/mode" "an archive with a symlink member is rejected"
make_variant mode; chmod 0777 "${VARIANT_DIR}/boringtun-cli"; pack_variant
check_variant mode "has type/mode" "an archive with a writable binary is rejected"
make_variant owner; pack_variant --owner=1000
check_variant owner "not owned by 0/0" "an archive with non-root owners is rejected"
make_variant traversal; printf 'x\n' >"${TEST_ROOT}/variant/escape"
(cd "${TEST_ROOT}/variant" && tar --owner=0 --group=0 --numeric-owner -P --transform "s,^escape\$,${STEM}/../escape," \
	-czf "${VARIANT_ARCHIVE}" -- "${STEM}" escape)
check_variant traversal "exactly the expected members" "an archive with a path-traversal member is rejected"
if [[ ! -e "${TEST_ROOT}/escape" ]]; then
	ok "a rejected archive is never extracted"
else
	not_ok "a rejected archive is never extracted"
fi
make_variant tampered; printf 'tampered\n' >>"${VARIANT_DIR}/boringtun-cli"; pack_variant
check_variant tampered "does not match binary_sha256" "a binary that does not match MANIFEST is rejected"
make_variant manifest; sed -i "s/^source_commit=.*/source_commit=0123456789abcdef0123456789abcdef01234567/" "${VARIANT_DIR}/MANIFEST"; pack_variant
check_variant manifest "does not describe the pinned artifact" "a MANIFEST for another commit is rejected"
make_variant manifestkey; printf 'extra_key=1\n' >>"${VARIANT_DIR}/MANIFEST"; pack_variant
check_variant manifestkey "unexpected or repeated key" "a MANIFEST with unknown keys is rejected"
make_variant control; printf 'rustc=spoof\033[2Jed\n' >>"${VARIANT_DIR}/MANIFEST"; pack_variant
check_variant control "is not a key=value line" "a MANIFEST line with control characters is rejected"
if [[ "${RUN_ERR}" != *$'\033'* ]]; then
	ok "a rejected MANIFEST line is not echoed to the terminal"
else
	not_ok "a rejected MANIFEST line is not echoed to the terminal"
fi
make_variant license; printf 'not the license\n' >"${VARIANT_DIR}/LICENSE"; pack_variant
check_variant license "not the expected notice" "an archive without the BSD-3-Clause notice is rejected"
cp "${ARCHIVE}" "${TEST_ROOT}/boringtun-cli-0.7.1-g0123456789ab-linux-x86_64-musl.tar.gz"
run_script verify-archive "${TEST_ROOT}/boringtun-cli-0.7.1-g0123456789ab-linux-x86_64-musl.tar.gz" "${TEST_ROOT}/extract-name"
assert_fails_with "not the artifact of the pinned version and commit" "an archive named for another commit is rejected"

echo "=== SHA256SUMS ==="

mkdir -p "${TEST_ROOT}/sums"
cp "${ARCHIVE}" "${TEST_ROOT}/sums/"
cp "${ARCHIVE}" "${TEST_ROOT}/sums/boringtun-cli-0.7.1-g${SOURCE_COMMIT:0:12}-linux-aarch64-musl.tar.gz"
printf 'unrelated\n' >"${TEST_ROOT}/sums/notes.txt"
run_script checksums "${TEST_ROOT}/sums"
assert_succeeds "SHA256SUMS is written"
assert_eq "$(cd "${TEST_ROOT}/sums" && sha256sum -- "boringtun-cli-0.7.1-g${SOURCE_COMMIT:0:12}-linux-aarch64-musl.tar.gz" "${STEM}.tar.gz")" \
	"$(cat "${TEST_ROOT}/sums/SHA256SUMS")" "SHA256SUMS lists exactly the archives, sorted by name, in sha256sum format"
assert_eq "0" "$(cd "${TEST_ROOT}/sums" && sha256sum --quiet -c SHA256SUMS >/dev/null 2>&1; echo $?)" "SHA256SUMS verifies with sha256sum -c"
mkdir -p "${TEST_ROOT}/sums-empty"
run_script checksums "${TEST_ROOT}/sums-empty"
assert_fails_with "no boringtun-cli archives" "SHA256SUMS needs at least one archive"
cp "${ARCHIVE}" "${TEST_ROOT}/sums/boringtun-cli-evil name.tar.gz"
run_script checksums "${TEST_ROOT}/sums"
assert_fails_with "unexpected file name" "an unexpected archive name is rejected"

echo "=== Licenses gate ==="

CRATE_DIR="${TEST_ROOT}/registry/ring-0.17.14"
mkdir -p "${CRATE_DIR}"
printf 'ring 0.17.14 %s/Cargo.toml\n' "${CRATE_DIR}" >"${STATE}/crates"
run_script licenses "${SOURCE}" "${TEST_ROOT}/licenses-ok"
assert_succeeds "the licenses gate passes a clean graph"
assert_eq "THIRD-PARTY LICENSES FOR boringtun-cli" "$(head -n 1 "${TEST_ROOT}/licenses-ok")" "THIRD-PARTY-LICENSES is written"
assert_eq "cargo fetch --locked
cargo deny --locked --manifest-path boringtun-cli/Cargo.toml --config ${PROJECT_ROOT}/packaging/boringtun/deny.toml check advisories bans licenses sources" \
	"$(grep -E '^(fetch|deny) ' "${STATE}/cargo.log" | tail -n 2 | sed 's/^/cargo /')" \
	"cargo-deny gates advisories, bans, licenses and sources with the repository policy"
if grep -q -- '^about generate --frozen --fail ' "${STATE}/cargo.log"; then
	ok "cargo-about runs offline (--frozen) and fails on unattributed licenses"
else
	not_ok "cargo-about runs offline (--frozen) and fails on unattributed licenses"
fi
printf 'fail\n' >"${STATE}/deny-mode"
run_script licenses "${SOURCE}" "${TEST_ROOT}/licenses-deny"
assert_fails_with "failed the cargo-deny policy" "a cargo-deny failure fails the gate"
rm -f "${STATE}/deny-mode"
if [[ ! -e "${TEST_ROOT}/licenses-deny" ]]; then
	ok "a failed gate writes no THIRD-PARTY-LICENSES"
else
	not_ok "a failed gate writes no THIRD-PARTY-LICENSES"
fi
printf 'notice\n' >"${CRATE_DIR}/NOTICE"
run_script licenses "${SOURCE}" "${TEST_ROOT}/licenses-notice"
assert_fails_with "ring 0.17.14 ships NOTICE" "a crate shipping an Apache NOTICE file fails the gate"
rm -f "${CRATE_DIR}/NOTICE"
mv "${BIN_DIR}/cargo-about" "${TEST_ROOT}/cargo-about.hidden"
run_script licenses "${SOURCE}" "${TEST_ROOT}/licenses-tool"
assert_fails_with "cargo-about is required" "the gate requires cargo-about"
mv "${TEST_ROOT}/cargo-about.hidden" "${BIN_DIR}/cargo-about"

echo "=== Device smoke test and usage ==="

if [[ "$(id -u)" -ne 0 ]]; then
	run_script device-smoke "${BUILD}/boringtun-cli"
	assert_fails_with "must run as root" "the device smoke test refuses to run without root"
else
	ok "the device smoke test root check is skipped when the tests run as root"
fi
run_script frobnicate
if (( RUN_RC == 2 )) && [[ "${RUN_ERR}" == *"verify-archive <archive> <extract-dir>"* ]]; then
	ok "an unknown command prints usage and exits 2"
else
	not_ok "an unknown command prints usage and exits 2 (rc ${RUN_RC})"
fi
run_script build "${SOURCE}"
if (( RUN_RC == 2 )); then
	ok "a command with missing arguments prints usage and exits 2"
else
	not_ok "a command with missing arguments prints usage and exits 2 (rc ${RUN_RC})"
fi

printf '\n%d tests, %d failures\n' "$((PASS + FAIL))" "${FAIL}"
(( FAIL == 0 ))
