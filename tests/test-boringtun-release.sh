#!/usr/bin/env bash

# Unit tests for scripts/boringtun-release.sh, the required-notices check of
# scripts/boringtun-artifact.sh and the static shape of the BoringTun Artifacts
# and BoringTun Release workflows. Nothing here talks to GitHub: fixture archives
# stand in for the build (with minimal ELF headers for the binaries), and mocks
# for gh and curl record every call, so a dry run can be shown to change nothing.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
RELEASE_SCRIPT="${PROJECT_ROOT}/scripts/boringtun-release.sh"
ARTIFACT_SCRIPT="${PROJECT_ROOT}/scripts/boringtun-artifact.sh"
RELEASE_WORKFLOW="${PROJECT_ROOT}/.github/workflows/boringtun-release.yml"
ARTIFACTS_WORKFLOW="${PROJECT_ROOT}/.github/workflows/boringtun-artifacts.yml"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-release-tests.XXXXXX")"
TEST_ROOT="$(CDPATH='' cd -- "${TEST_ROOT}" && pwd -P)"
BIN_DIR="${TEST_ROOT}/bin"
MOCK="${TEST_ROOT}/mock"
mkdir -p "${BIN_DIR}" "${MOCK}"

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
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected:\n%s\n    actual:\n%s\n' "$(sed 's/^/      /' <<<"$1")" "$(sed 's/^/      /' <<<"$2")" >&2
	fi
}

assert_true() {
	local NAME="$1"
	shift
	if "$@"; then ok "${NAME}"; else not_ok "${NAME}"; fi
}

REPO="wiresock/amneziawg-install"
PIN_COMMIT="0123456789abcdef0123456789abcdef01234567"
C12="${PIN_COMMIT:0:12}"
ARTIFACTS_COMMIT="89abcdef0123456789abcdef0123456789abcdef"
RUN_ID=4242
PIN_FILE="${TEST_ROOT}/pin.env"
CONTRACT="${TEST_ROOT}/release.env"
cat >"${PIN_FILE}" <<EOF
BORINGTUN_REPOSITORY=https://github.com/Wiresock-Foundation/wiresock-boringtun
BORINGTUN_COMMIT=${PIN_COMMIT}
BORINGTUN_VERSION=0.7.1
BORINGTUN_RUST_TOOLCHAIN=1.98.1
BORINGTUN_ARTIFACT_FORMAT=1
EOF

# Run a script with the mocks first in PATH, the fixture pin and contract, and
# GITHUB_REPOSITORY. Sets RUN_RC, RUN_OUT and RUN_ERR.
run_release() {
	env PATH="${BIN_DIR}:${PATH}" MOCK="${MOCK}" GITHUB_REPOSITORY="${RUN_REPO-${REPO}}" \
		BORINGTUN_PIN_FILE="${PIN_FILE}" BORINGTUN_RELEASE_FILE="${CONTRACT}" \
		bash "${RELEASE_SCRIPT}" "$@" >"${TEST_ROOT}/run.out" 2>"${TEST_ROOT}/run.err"
	RUN_RC=$?
	RUN_OUT="$(cat "${TEST_ROOT}/run.out")"
	RUN_ERR="$(cat "${TEST_ROOT}/run.err")"
}

run_artifact() {
	env BORINGTUN_PIN_FILE="${PIN_FILE}" bash "${ARTIFACT_SCRIPT}" "$@" >"${TEST_ROOT}/run.out" 2>"${TEST_ROOT}/run.err"
	RUN_RC=$?
	RUN_OUT="$(cat "${TEST_ROOT}/run.out")"
	RUN_ERR="$(cat "${TEST_ROOT}/run.err")"
}

assert_fails_with() {
	if (( RUN_RC != 0 )) && [[ "${RUN_ERR}" == *"$1"* ]]; then
		ok "$2"
	else
		not_ok "$2 (rc ${RUN_RC}, stderr: ${RUN_ERR})"
	fi
}

assert_succeeds() {
	if (( RUN_RC == 0 )); then
		ok "$1"
	else
		not_ok "$1 (rc ${RUN_RC}, stderr: ${RUN_ERR})"
	fi
}

# No mutating GitHub call since the call log was last cleared.
no_mutation() {
	! grep -qE -- '--method (POST|PATCH|PUT|DELETE)|(^| )-X ' "${MOCK}/calls" 2>/dev/null
}

# ── Fixtures ─────────────────────────────────────────────────────────────────
# A minimal ELF64 header: enough for readelf to report the class and machine,
# with no program interpreter and no dynamic section.
write_elf() { # <x86_64|aarch64> <file>
	python3 - "$1" "$2" <<'PY'
import struct, sys
machine = {"x86_64": 0x3E, "aarch64": 0xB7}[sys.argv[1]]
header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
header += struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0x400000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
open(sys.argv[2], "wb").write(header + sys.argv[1].encode())
PY
	chmod 0755 "$2"
}

LINE80="$(printf '%80s' '' | tr ' ' '=')"
DASH80="$(printf '%80s' '' | tr ' ' '-')"
# A THIRD-PARTY-LICENSES in the generated format, with the required notices.
write_third_party() { # <file> [variant]
	{
		printf 'THIRD-PARTY LICENSES FOR boringtun-cli\n\nfixture\n\n'
		printf '%s\nBSD 3-Clause "New" or "Revised" License (BSD-3-Clause)\n\nUsed by:\n' "${LINE80}"
		printf '  boringtun 0.7.1 <https://github.com/Wiresock-Foundation/wiresock-boringtun>\n'
		printf '  boringtun-cli 0.7.1 <https://github.com/Wiresock-Foundation/wiresock-boringtun>\n'
		[[ "${2:-}" == placeholder ]] && printf '  curve25519-dalek 4.1.3 <https://example.invalid>\n'
		printf '%s\nCopyright (c) <year> <owner>. \n\nRedistribution and use in source and binary forms...\n\n' "${DASH80}"
		if [[ "${2:-}" != placeholder ]]; then
			printf '%s\nBSD 3-Clause "New" or "Revised" License (BSD-3-Clause)\n\nUsed by:\n' "${LINE80}"
			printf '  %s 4.1.3 <https://github.com/dalek-cryptography/curve25519-dalek>\n' "${3:-curve25519-dalek}"
			printf '%s\n' "${DASH80}"
			[[ "${2:-}" == missing-go ]] || printf 'Copyright (c) 2012 The Go Authors. All rights reserved.\n'
			printf 'Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.\n'
			printf 'Copyright (c) 2016-2021 Henry de Valence. All rights reserved.  \n\nRedistribution...\n\n'
		fi
		printf '%s\nMIT License (MIT)\n\nUsed by:\n  ring 0.17.14 <https://github.com/briansmith/ring>\n%s\n' "${LINE80}" "${DASH80}"
		printf 'Copyright 2015-2025 Brian Smith.\n'
	} >"$1"
}

# Build the archive of one architecture into a directory. A variant changes
# one thing: extra, symlink, traversal, notices, manifest-commit.
make_archive() { # <arch> <out-dir> [variant]
	local ARCH="$1" OUT="$2" VARIANT="${3:-}" STEM STAGE
	STEM="boringtun-cli-0.7.1-g${C12}-linux-${ARCH}-musl"
	STAGE="$(mktemp -d "${TEST_ROOT}/stage.XXXXXX")"
	mkdir -p "${STAGE}/${STEM}" "${OUT}"
	write_elf "${ARCH}" "${STAGE}/${STEM}/boringtun-cli"
	printf 'Copyright (c) 2019 Cloudflare, Inc. All rights reserved.\n\nRedistribution and use in source and binary forms, with or without modification, are permitted.\n' \
		>"${STAGE}/${STEM}/LICENSE"
	if [[ "${VARIANT}" == notices ]]; then
		write_third_party "${STAGE}/${STEM}/THIRD-PARTY-LICENSES" placeholder
	else
		write_third_party "${STAGE}/${STEM}/THIRD-PARTY-LICENSES"
	fi
	local COMMIT="${PIN_COMMIT}"
	[[ "${VARIANT}" == manifest-commit ]] && COMMIT="fedcba9876543210fedcba9876543210fedcba98"
	cat >"${STAGE}/${STEM}/MANIFEST" <<EOF
artifact_format=1
name=boringtun-cli
version=0.7.1
source_repository=https://github.com/Wiresock-Foundation/wiresock-boringtun
source_commit=${COMMIT}
source_date_epoch=1790285008
target=${ARCH}-unknown-linux-musl
os=linux
arch=${ARCH}
libc=musl
linkage=static
rust_toolchain=1.98.1
rustc=rustc 1.98.1 (48a229cea 2026-09-01)
cargo=cargo 1.98.1 (797e8a9bc 2026-08-05)
build_command=cargo build --release --locked -p boringtun-cli --bin boringtun-cli --target ${ARCH}-unknown-linux-musl
build_profile=release,strip=symbols
rustflags=--remap-path-prefix=<source>=/boringtun --remap-path-prefix=<cargo-home>=/cargo
binary=boringtun-cli
binary_sha256=$(sha256sum "${STAGE}/${STEM}/boringtun-cli" | cut -d' ' -f1)
license=LICENSE (BSD-3-Clause)
third_party_licenses=THIRD-PARTY-LICENSES
EOF
	chmod 0644 "${STAGE}/${STEM}/LICENSE" "${STAGE}/${STEM}/THIRD-PARTY-LICENSES" "${STAGE}/${STEM}/MANIFEST"
	case "${VARIANT}" in
		extra) printf 'x\n' >"${STAGE}/${STEM}/README" ;;
		symlink) rm "${STAGE}/${STEM}/LICENSE" && ln -s /etc/passwd "${STAGE}/${STEM}/LICENSE" ;;
	esac
	if [[ "${VARIANT}" == traversal ]]; then
		printf 'x\n' >"${STAGE}/escape"
		(cd "${STAGE}" && tar --owner=0 --group=0 --numeric-owner -P --transform "s,^escape\$,${STEM}/../escape," \
			-czf "${OUT}/${STEM}.tar.gz" -- "${STEM}" escape)
	else
		(cd "${STAGE}" && tar --sort=name --owner=0 --group=0 --numeric-owner -czf "${OUT}/${STEM}.tar.gz" -- "${STEM}")
	fi
	rm -rf -- "${STAGE}"
}

GOOD="${TEST_ROOT}/good"
make_archive x86_64 "${GOOD}"
make_archive aarch64 "${GOOD}"
X_NAME="boringtun-cli-0.7.1-g${C12}-linux-x86_64-musl.tar.gz"
A_NAME="boringtun-cli-0.7.1-g${C12}-linux-aarch64-musl.tar.gz"
write_sums() { # <dir>
	(cd "$1" && sha256sum -- "${A_NAME}" "${X_NAME}" >SHA256SUMS)
}
write_sums "${GOOD}"
sha_of() { sha256sum -- "$1" | cut -d' ' -f1; }
binary_sha_of() { # <archive>
	tar -xzOf "$1" --wildcards '*/boringtun-cli' | sha256sum | cut -d' ' -f1
}

# Write the release contract for the archives in a directory, with overrides
# as KEY=VALUE arguments (an empty value drops the key; KEY+=LINE appends).
write_contract() { # <dir> [KEY=VALUE]...
	local DIR="$1" KV KEY
	shift
	local -A C=(
		[BORINGTUN_RELEASE_FORMAT]=1
		[BORINGTUN_RELEASE_STATE]=candidate
		[BORINGTUN_RELEASE_SOURCE_COMMIT]="${PIN_COMMIT}"
		[BORINGTUN_RELEASE_VERSION]=0.7.1
		[BORINGTUN_RELEASE_ARTIFACT_FORMAT]=1
		[BORINGTUN_RELEASE_BUILD]=2
		[BORINGTUN_RELEASE_TAG]="boringtun-cli-0.7.1-g${C12}-b2"
		[BORINGTUN_RELEASE_ASSET_X86_64]="${X_NAME}"
		[BORINGTUN_RELEASE_ARCHIVE_SHA256_X86_64]="$(sha_of "${DIR}/${X_NAME}")"
		[BORINGTUN_RELEASE_BINARY_SHA256_X86_64]="$(binary_sha_of "${DIR}/${X_NAME}")"
		[BORINGTUN_RELEASE_ASSET_AARCH64]="${A_NAME}"
		[BORINGTUN_RELEASE_ARCHIVE_SHA256_AARCH64]="$(sha_of "${DIR}/${A_NAME}")"
		[BORINGTUN_RELEASE_BINARY_SHA256_AARCH64]="$(binary_sha_of "${DIR}/${A_NAME}")"
	)
	local EXTRA=""
	for KV in "$@"; do
		if [[ "${KV}" == *+=* ]]; then
			EXTRA+="${KV#*+=}"$'\n'
		else
			C[${KV%%=*}]="${KV#*=}"
		fi
	done
	{
		printf '# fixture release contract\n'
		for KEY in BORINGTUN_RELEASE_FORMAT BORINGTUN_RELEASE_STATE BORINGTUN_RELEASE_SOURCE_COMMIT BORINGTUN_RELEASE_VERSION \
			BORINGTUN_RELEASE_ARTIFACT_FORMAT BORINGTUN_RELEASE_BUILD BORINGTUN_RELEASE_TAG BORINGTUN_RELEASE_ASSET_X86_64 \
			BORINGTUN_RELEASE_ARCHIVE_SHA256_X86_64 BORINGTUN_RELEASE_BINARY_SHA256_X86_64 BORINGTUN_RELEASE_ASSET_AARCH64 \
			BORINGTUN_RELEASE_ARCHIVE_SHA256_AARCH64 BORINGTUN_RELEASE_BINARY_SHA256_AARCH64; do
			[[ -n "${C[${KEY}]}" ]] && printf '%s=%s\n' "${KEY}" "${C[${KEY}]}"
		done
		printf '%s' "${EXTRA}"
	} >"${CONTRACT}"
}

# ── Mocks ────────────────────────────────────────────────────────────────────
# gh answers from files in ${MOCK} and records every call in ${MOCK}/calls. It
# behaves like GitHub where it matters: an upload of an existing asset name
# fails, drafts create no tag, and publishing creates the tag.
cat >"${BIN_DIR}/gh" <<'EOF'
#!/usr/bin/env bash
M="${MOCK}"
R="wiresock/amneziawg-install"
printf '%s\n' "$*" >>"${M}/calls"
fail() { printf 'mock gh: %s\n' "$*" >&2; exit 1; }
case "${1:-}" in
	api)
		shift
		method=GET endpoint="" jq_filter="" input="" accept=""
		declare -A field=()
		while (( $# > 0 )); do
			case "$1" in
				--method | -X) method="$2"; shift 2 ;;
				--jq | -q) jq_filter="$2"; shift 2 ;;
				--input) input="$2"; shift 2 ;;
				-H) [[ "$2" == Accept:* ]] && accept="$2"; shift 2 ;;
				--paginate) shift ;;
				-f | -F) field[${2%%=*}]="${2#*=}"; shift 2 ;;
				*) endpoint="$1"; shift ;;
			esac
		done
		out() { if [[ -n "${jq_filter}" ]]; then jq -r "${jq_filter}"; else cat; fi; }
		case "${method} ${endpoint}" in
			"GET repos/${R}/actions/runs/"*)
				[[ -f "${M}/run.json" ]] || fail "HTTP 404"
				out <"${M}/run.json"
				;;
			"GET repos/${R}/compare/"*)
				printf '{"status":"%s"}\n' "$(cat "${M}/compare-status")" | out
				;;
			"GET repos/${R}/git/matching-refs/tags/"*)
				if [[ -f "${M}/tag-after-uploads" && "$(find "${M}/assets" -type f 2>/dev/null | wc -l)" -ge 3 ]]; then
					printf '[{"ref":"refs/tags/%s"}]\n' "$(cat "${M}/tag-after-uploads")" | out
				else
					out <"${M}/tags.json"
				fi
				;;
			"GET repos/${R}/git/ref/tags/"*)
				[[ -f "${M}/published" ]] || fail "HTTP 404"
				printf '{"object":{"type":"commit","sha":"%s"}}\n' "$(cat "${M}/target")" | out
				;;
			"GET repos/${R}/releases?per_page=100")
				if [[ -f "${M}/release.json" ]]; then
					jq -s '.[0] + [.[1]]' "${M}/releases.json" "${M}/release.json" | out
				else
					out <"${M}/releases.json"
				fi
				;;
			"POST repos/${R}/releases")
				[[ "${field[draft]}" == true ]] || fail "not a draft"
				printf '%s\n' "${field[target_commitish]}" >"${M}/target"
				jq -n --arg tag "${field[tag_name]}" --arg name "${field[name]}" \
					'{id: 77, draft: true, tag_name: $tag, name: $name}' >"${M}/release.json"
				mkdir -p "${M}/assets"
				out <"${M}/release.json"
				;;
			"POST https://uploads.github.com/repos/${R}/releases/77/assets?name="*)
				name="${endpoint##*name=}"
				[[ -e "${M}/assets/${name}" ]] && fail "HTTP 422: already_exists"
				cp -- "${input}" "${M}/assets/${name}"
				jq -n --arg n "${name}" --argjson s "$(stat -c %s -- "${input}")" '{name: $n, state: "uploaded", size: $s}' | out
				;;
			"GET repos/${R}/releases/77/assets?per_page=100")
				i=0
				find "${M}/assets" -type f | LC_ALL=C sort | while IFS= read -r f; do
					i=$((i + 1))
					jq -n --argjson id "${i}" --arg n "${f##*/}" '{id: $id, name: $n, state: "uploaded"}'
				done | jq -s . | out
				;;
			"GET repos/${R}/releases/assets/"*)
				[[ "${accept}" == "Accept: application/octet-stream" ]] || fail "asset read without octet-stream"
				f="$(find "${M}/assets" -type f | LC_ALL=C sort | sed -n "${endpoint##*/}p")"
				cat -- "${f}"
				[[ -f "${M}/tamper-readback" ]] && printf 'x'
				exit 0
				;;
			"PATCH repos/${R}/releases/77")
				[[ "${field[draft]}" == false ]] || fail "unexpected patch"
				touch "${M}/published"
				jq '.draft = false' "${M}/release.json" | out
				;;
			*) printf 'mock gh: unexpected api call: %s %s\n' "${method}" "${endpoint}" >&2; exit 99 ;;
		esac
		;;
	run)
		dir=""
		while (( $# > 0 )); do [[ "$1" == --dir ]] && dir="$2"; shift; done
		[[ -f "${M}/download-fail" ]] && fail "download failed"
		mkdir -p -- "${dir}" && cp -a -- "${M}/artifact/." "${dir}/"
		;;
	attestation)
		[[ -f "${M}/attestation-fail" ]] && fail "no matching attestation"
		printf '%s\n' "$*" >>"${M}/attestation-args"
		# Checked against the one attestation in attestation.json the way gh
		# checks it: --cert-identity must equal the certificate's identity,
		# --signer-workflow only anchors its start, the source constraints must
		# match exactly, and the archive must be one of the subjects.
		[[ "${2:-}" == verify ]] || fail "unexpected attestation command"
		file="$3"
		shift 3
		declare -A opt=()
		deny=0
		while (( $# > 0 )); do
			case "$1" in
				--deny-self-hosted-runners) deny=1; shift ;;
				--repo | --cert-identity | --signer-workflow | --source-digest | --source-ref) opt[$1]="$2"; shift 2 ;;
				*) fail "unexpected attestation option $1" ;;
			esac
		done
		att() { jq -r "$1" "${M}/attestation.json"; }
		identity="$(att .identity)"
		[[ "${opt[--repo]:-}" == "$(att .repo)" ]] || fail "no attestation in ${opt[--repo]:-}"
		jq -e --arg d "$(sha256sum -- "${file}" | cut -d' ' -f1)" '.subjects | index($d)' "${M}/attestation.json" >/dev/null ||
			fail "no attestation for ${file##*/}"
		if [[ -n "${opt[--cert-identity]+x}" ]]; then
			[[ "${identity}" == "${opt[--cert-identity]}" ]] || fail "certificate identity ${identity} is not ${opt[--cert-identity]}"
		elif [[ -n "${opt[--signer-workflow]+x}" ]]; then
			[[ "${identity}" == "https://github.com/${opt[--signer-workflow]}"* ]] ||
				fail "certificate identity ${identity} does not start with the signer workflow"
		else
			[[ "${identity}" == "https://github.com/${opt[--repo]}/"* ]] || fail "certificate identity ${identity} is not of the repository"
		fi
		[[ -z "${opt[--source-digest]+x}" || "${opt[--source-digest]}" == "$(att .digest)" ]] || fail "source digest $(att .digest)"
		[[ -z "${opt[--source-ref]+x}" || "${opt[--source-ref]}" == "$(att .ref)" ]] || fail "source ref $(att .ref)"
		(( deny == 0 )) || [[ "$(att .runner)" == github-hosted ]] || fail "built on a self-hosted runner"
		printf 'Verification succeeded! (%s)\n' "${identity}"
		;;
	*) printf 'mock gh: unexpected command: %s\n' "$*" >&2; exit 98 ;;
esac
EOF
cat >"${BIN_DIR}/curl" <<'EOF'
#!/usr/bin/env bash
out="" url=""
while (( $# > 0 )); do
	case "$1" in
		-o) out="$2"; shift 2 ;;
		--retry | --retry-delay) shift 2 ;;
		-*) shift ;;
		*) url="$1"; shift ;;
	esac
done
printf 'curl %s\n' "${url}" >>"${MOCK}/calls"
cp -- "${MOCK}/assets/${url##*/}" "${out}"
[[ -f "${MOCK}/tamper-public" ]] && printf 'x' >>"${out}"
exit 0
EOF
chmod +x "${BIN_DIR}/gh" "${BIN_DIR}/curl"

# A clean GitHub: the run is good, the commit is on the branch, no tag and no
# release, the artifact holds the given directory, and the artifacts workflow
# attested its archives on a GitHub-hosted runner.
reset_mock() { # <artifact-dir> [branch]
	rm -rf -- "${MOCK}" && mkdir -p "${MOCK}/artifact"
	cp -a -- "$1/." "${MOCK}/artifact/"
	jq -n --arg repo "${REPO}" --arg sha "${ARTIFACTS_COMMIT}" --arg branch "${2:-main}" '{
		repository: {full_name: $repo}, head_repository: {full_name: $repo},
		path: ".github/workflows/boringtun-artifacts.yml", status: "completed", conclusion: "success",
		head_sha: $sha, head_branch: $branch, event: "push"}' >"${MOCK}/run.json"
	find "$1" -maxdepth 1 -type f -name '*.tar.gz' -exec sha256sum -- {} + | cut -d' ' -f1 |
		jq -R . | jq -s --arg repo "${REPO}" --arg sha "${ARTIFACTS_COMMIT}" --arg branch "${2:-main}" '{
		identity: "https://github.com/\($repo)/.github/workflows/boringtun-artifacts.yml@refs/heads/\($branch)",
		repo: $repo, digest: $sha, ref: "refs/heads/\($branch)", runner: "github-hosted", subjects: .}' \
		>"${MOCK}/attestation.json"
	printf 'ahead\n' >"${MOCK}/compare-status"
	printf '[]\n' >"${MOCK}/tags.json"
	printf '[]\n' >"${MOCK}/releases.json"
	: >"${MOCK}/calls"
}
edit_run() { # <jq filter>
	jq "$1" "${MOCK}/run.json" >"${MOCK}/run.json.new" && mv "${MOCK}/run.json.new" "${MOCK}/run.json"
}
edit_attestation() { # <jq filter>
	jq "$1" "${MOCK}/attestation.json" >"${MOCK}/attestation.json.new" && mv "${MOCK}/attestation.json.new" "${MOCK}/attestation.json"
}

echo "=== Required notices (scripts/boringtun-artifact.sh) ==="

write_third_party "${TEST_ROOT}/tpl-good"
run_artifact check-notices "${TEST_ROOT}/tpl-good"
assert_succeeds "THIRD-PARTY-LICENSES with every required notice passes"
write_third_party "${TEST_ROOT}/tpl-missing" missing-go
run_artifact check-notices "${TEST_ROOT}/tpl-missing"
assert_fails_with "missing required notice of curve25519-dalek 4.1.3: Copyright (c) 2012 The Go Authors" \
	"a missing curve25519-dalek notice fails"
write_third_party "${TEST_ROOT}/tpl-placeholder" placeholder
run_artifact check-notices "${TEST_ROOT}/tpl-placeholder"
assert_fails_with "only a placeholder notice (no copyright holder) attributes curve25519-dalek 4.1.3" \
	"curve25519-dalek attributed by the bare SPDX template fails"
write_third_party "${TEST_ROOT}/tpl-other-crate" "" x25519-dalek
run_artifact check-notices "${TEST_ROOT}/tpl-other-crate"
assert_fails_with "missing required notice of curve25519-dalek 4.1.3" "the notices must be in curve25519-dalek's own section"
sed 's/^  curve25519-dalek 4.1.3 /  curve25519-dalek 4.1.4 /' "${TEST_ROOT}/tpl-good" >"${TEST_ROOT}/tpl-version"
run_artifact check-notices "${TEST_ROOT}/tpl-version"
assert_fails_with "missing required notice of curve25519-dalek 4.1.3" "a different crate version needs a reviewed required-notices entry"
if [[ "$(grep -c 'Copyright (c) <year> <owner>' "${TEST_ROOT}/tpl-good")" == 1 ]]; then
	ok "(the placeholder is allowed for BoringTun's own crates, whose notice is LICENSE)"
else
	not_ok "(fixture has the workspace placeholder)"
fi
printf 'curve25519-dalek 4.1.3 Copyright (c) 2012 The Go Authors.\n' >"${TEST_ROOT}/notices-bad"
env BORINGTUN_NOTICES_FILE="${TEST_ROOT}/notices-bad" BORINGTUN_PIN_FILE="${PIN_FILE}" \
	bash "${ARTIFACT_SCRIPT}" check-notices "${TEST_ROOT}/tpl-good" >/dev/null 2>"${TEST_ROOT}/run.err"
RUN_RC=$? RUN_ERR="$(cat "${TEST_ROOT}/run.err")"
assert_fails_with "is not '<crate> <version> | Copyright ...'" "a malformed required-notices line fails"
printf '# only comments\n' >"${TEST_ROOT}/notices-empty"
env BORINGTUN_NOTICES_FILE="${TEST_ROOT}/notices-empty" BORINGTUN_PIN_FILE="${PIN_FILE}" \
	bash "${ARTIFACT_SCRIPT}" check-notices "${TEST_ROOT}/tpl-good" >/dev/null 2>"${TEST_ROOT}/run.err"
RUN_RC=$? RUN_ERR="$(cat "${TEST_ROOT}/run.err")"
assert_fails_with "lists no notice" "an empty required-notices list fails"
assert_eq "curve25519-dalek 4.1.3 | Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.
curve25519-dalek 4.1.3 | Copyright (c) 2016-2021 Henry de Valence. All rights reserved.
curve25519-dalek 4.1.3 | Copyright (c) 2012 The Go Authors. All rights reserved." \
	"$(grep -v '^#' "${PROJECT_ROOT}/packaging/boringtun/required-notices")" \
	"the repository requires all three curve25519-dalek notices"
if grep -q '^\[curve25519-dalek.clarify\]$' "${PROJECT_ROOT}/packaging/boringtun/about.toml" && \
	grep -qE '^checksum = "[0-9a-f]{64}"$' "${PROJECT_ROOT}/packaging/boringtun/about.toml"; then
	ok "about.toml clarifies curve25519-dalek with a pinned checksum"
else
	not_ok "about.toml clarifies curve25519-dalek with a pinned checksum"
fi

echo "=== Release contract ==="

write_contract "${GOOD}"
run_release contract
assert_succeeds "a well-formed contract matching the pin parses"
run_release plan
assert_eq "state=candidate
tag=boringtun-cli-0.7.1-g${C12}-b2
title=BoringTun CLI 0.7.1 (WireSock ${C12}), build 2 (experimental)
source=https://github.com/Wiresock-Foundation/wiresock-boringtun@${PIN_COMMIT}
version=0.7.1
build=2
asset=${X_NAME} archive_sha256=$(sha_of "${GOOD}/${X_NAME}") binary_sha256=$(binary_sha_of "${GOOD}/${X_NAME}")
asset=${A_NAME} archive_sha256=$(sha_of "${GOOD}/${A_NAME}") binary_sha256=$(binary_sha_of "${GOOD}/${A_NAME}")
asset=SHA256SUMS sha256=$(sha_of "${GOOD}/SHA256SUMS")" "${RUN_OUT}" \
	"the plan names the exact tag, title, assets and hashes"
run_release notes "${ARTIFACTS_COMMIT}"
assert_succeeds "notes for a full artifacts commit are printed"
if [[ "${RUN_OUT}" == *"$(cat "${GOOD}/SHA256SUMS")"* && "${RUN_OUT}" == *RUSTSEC-2025-0069* && \
	"${RUN_OUT}" == *"not position-independent"* && "${RUN_OUT}" == *"does not yet install BoringTun"* && \
	"${RUN_OUT}" == *"not published or endorsed"* ]]; then
	ok "the notes carry the checksums, the advisory, the aarch64 non-PIE status and the scope"
else
	not_ok "the notes carry the checksums, the advisory, the aarch64 non-PIE status and the scope"
fi

# The provenance command of the notes: every "gh attestation verify" line with
# its continuation lines.
notes_command() { # <notes>
	awk '/gh attestation verify/ { on = 1 } on { print } on && !/\\$/ { on = 0 }' <<<"$1"
}
# The command the notes must give for archives built at <commit> on main.
expected_command() { # <commit>
	printf '%s\n' "gh attestation verify <archive> \\" "  --repo ${REPO} \\" "  --cert-identity \\" \
		"    https://github.com/${REPO}/.github/workflows/boringtun-artifacts.yml@refs/heads/main \\" \
		"  --source-digest $1 \\" "  --source-ref refs/heads/main \\" "  --deny-self-hosted-runners"
}
assert_eq "$(expected_command "${ARTIFACTS_COMMIT}")" "$(notes_command "${RUN_OUT}")" \
	"the notes give one provenance command with the exact repository, identity, artifacts commit, ref and hosted runners"
if [[ "$(grep -c 'gh attestation verify' <<<"${RUN_OUT}")" == 1 && "${RUN_OUT}" != *--signer-workflow* ]] &&
	! grep -qE 'gh attestation verify [^\\]*--repo [^ ]+`?\.?$' <<<"${RUN_OUT}"; then
	ok "  and no weaker command (repository only, or a prefix-matching signer workflow)"
else
	not_ok "  and no weaker command (repository only, or a prefix-matching signer workflow)"
fi
assert_true "  and its source digest is not BoringTun's source commit" \
	test "$(notes_command "${RUN_OUT}" | grep -c -- "${PIN_COMMIT}")" -eq 0
for BAD_COMMIT in "${ARTIFACTS_COMMIT:0:12}" "${ARTIFACTS_COMMIT^^}" "${ARTIFACTS_COMMIT:0:39}g" "${ARTIFACTS_COMMIT}0" ""; do
	run_release notes "${BAD_COMMIT}"
	assert_fails_with "the artifacts commit must be a full 40-character commit SHA" \
		"notes refuse the artifacts commit '${BAD_COMMIT}'"
done
run_release notes
assert_fails_with "notes <commit>" "notes refuse a missing artifacts commit"
run_release notes "${ARTIFACTS_COMMIT}" main
assert_fails_with "notes <commit>" "notes refuse an extra argument"
RUN_REPO="" run_release notes "${ARTIFACTS_COMMIT}"
assert_fails_with "GITHUB_REPOSITORY must be set to owner/repo" "notes refuse to print a command without the repository"

check_contract() { # <message> <label> [overrides]...
	local MESSAGE="$1" LABEL="$2"
	shift 2
	write_contract "${GOOD}" "$@"
	run_release contract
	assert_fails_with "${MESSAGE}" "${LABEL}"
}
check_contract "sets unknown key BORINGTUN_RELEASE_EXTRA" "an unknown key is refused" "X+=BORINGTUN_RELEASE_EXTRA=1"
check_contract "defines BORINGTUN_RELEASE_BUILD more than once" "a repeated key is refused" "X+=BORINGTUN_RELEASE_BUILD=3"
check_contract "does not define BORINGTUN_RELEASE_TAG" "a missing key is refused" "BORINGTUN_RELEASE_TAG="
check_contract "is not a plain KEY=VALUE assignment" "shell syntax is refused" "X+=BORINGTUN_RELEASE_NOTE=\$(id)"
check_contract "BORINGTUN_RELEASE_STATE has an invalid value" "an unknown state is refused" "BORINGTUN_RELEASE_STATE=published"
check_contract "BORINGTUN_RELEASE_ARCHIVE_SHA256_X86_64 has an invalid value" "a malformed hash is refused" \
	"BORINGTUN_RELEASE_ARCHIVE_SHA256_X86_64=abc"
check_contract "but the pin is ${PIN_COMMIT}" "a contract for another source commit is refused" \
	"BORINGTUN_RELEASE_SOURCE_COMMIT=fedcba9876543210fedcba9876543210fedcba98"
check_contract "but the pin is 0.7.1" "a contract for another version is refused" "BORINGTUN_RELEASE_VERSION=0.7.2"
check_contract "tag must be boringtun-cli-0.7.1-g${C12}-b2" "a tag that does not match the build number is refused" \
	"BORINGTUN_RELEASE_TAG=boringtun-cli-0.7.1-g${C12}-b1"
check_contract "asset for aarch64 must be ${A_NAME}" "an asset name not derived from the pin is refused" \
	"BORINGTUN_RELEASE_ASSET_AARCH64=boringtun-cli-0.7.1-g${C12}-linux-x86_64-musl.tar.gz"
check_contract "lists the same hash for both architectures" "the same hash for both architectures is refused" \
	"BORINGTUN_RELEASE_BINARY_SHA256_AARCH64=$(binary_sha_of "${GOOD}/${X_NAME}")"
if grep -qE '^BORINGTUN_RELEASE_STATE=(candidate|approved)$' "${PROJECT_ROOT}/packaging/boringtun/release.env" && \
	env BORINGTUN_PIN_FILE="${PROJECT_ROOT}/packaging/boringtun/pin.env" bash "${RELEASE_SCRIPT}" contract >/dev/null 2>&1; then
	ok "the repository's release contract is valid against the repository's pin"
else
	not_ok "the repository's release contract is valid against the repository's pin"
fi

echo "=== Artifact set ==="

write_contract "${GOOD}"
run_release verify-assets "${GOOD}" "${TEST_ROOT}/verify-good"
assert_succeeds "the artifact set that matches the contract verifies (without running the binaries)"

# Each case: a directory holding a modified set, and the contract to check it with.
bad_set() { # <name>
	BAD="${TEST_ROOT}/sets/$1"
	rm -rf -- "${BAD}" && mkdir -p "${BAD}" && cp -a -- "${GOOD}/." "${BAD}/"
}
check_set() { # <message> <label>
	run_release verify-assets "${BAD}" "${TEST_ROOT}/verify-${RANDOM}${RANDOM}"
	assert_fails_with "$1" "$2"
}
bad_set hash
write_contract "${GOOD}" "BORINGTUN_RELEASE_ARCHIVE_SHA256_X86_64=$(printf '%064d' 1)"
(cd "${BAD}" && printf '%s  %s\n' "$(sha_of "${A_NAME}")" "${A_NAME}" "$(printf '%064d' 1)" "${X_NAME}" >SHA256SUMS)
check_set "${X_NAME} does not have the SHA-256 in the release contract" "a wrong archive hash is refused"
write_contract "${GOOD}" "BORINGTUN_RELEASE_BINARY_SHA256_AARCH64=$(printf '%064d' 2)"
bad_set binary
check_set "the boringtun-cli in ${A_NAME} does not have the SHA-256 in the release contract" "a wrong binary hash is refused"

for VARIANT in extra symlink traversal notices manifest-commit; do
	bad_set "${VARIANT}"
	make_archive x86_64 "${TEST_ROOT}/variant-${VARIANT}" "${VARIANT}"
	cp -- "${TEST_ROOT}/variant-${VARIANT}/${X_NAME}" "${BAD}/${X_NAME}"
	write_sums "${BAD}"
	write_contract "${BAD}" "BORINGTUN_RELEASE_BINARY_SHA256_X86_64=$(binary_sha_of "${GOOD}/${X_NAME}")"
	case "${VARIANT}" in
		extra) check_set "does not contain exactly the expected members" "an unexpected archive member is refused" ;;
		symlink) check_set "has type/mode" "a symlink member is refused" ;;
		traversal) check_set "does not contain exactly the expected members" "a path-traversal member is refused" ;;
		notices) check_set "lacks required copyright notices" "an archive without the curve25519-dalek notices is refused" ;;
		manifest-commit) check_set "MANIFEST does not describe the pinned artifact" "an archive whose MANIFEST names another source commit is refused" ;;
	esac
	# Refused by the archive check itself, not only by a later hash comparison.
	assert_fails_with "${X_NAME} failed archive verification" "  by the archive verification (${VARIANT})"
done
if [[ ! -e "${TEST_ROOT}/escape" && -z "$(find "${TEST_ROOT}" -maxdepth 3 -name escape -path '*verify-*')" ]]; then
	ok "a traversal member is never extracted"
else
	not_ok "a traversal member is never extracted"
fi

write_contract "${GOOD}"
bad_set extra-file; printf 'x\n' >"${BAD}/notes.txt"
check_set "not exactly the two archives and SHA256SUMS" "an extra file in the artifact set is refused"
bad_set no-sums; rm "${BAD}/SHA256SUMS"
check_set "not exactly the two archives and SHA256SUMS" "an artifact set without SHA256SUMS is refused"
bad_set dir-asset; rm "${BAD}/${A_NAME}"; mkdir "${BAD}/${A_NAME}"
check_set "not exactly the two archives and SHA256SUMS" "a directory in place of an asset is refused"
bad_set link-asset; mv "${BAD}/${A_NAME}" "${TEST_ROOT}/elsewhere.tar.gz"; ln -s "${TEST_ROOT}/elsewhere.tar.gz" "${BAD}/${A_NAME}"
check_set "not exactly the two archives and SHA256SUMS" "a symlink in place of an asset is refused"
bad_set dup-sums; printf '%s  %s\n' "$(sha_of "${GOOD}/${X_NAME}")" "${X_NAME}" >>"${BAD}/SHA256SUMS"
check_set "SHA256SUMS is not the one the release contract gives" "a SHA256SUMS with a duplicate entry is refused"

# SHA256SUMS is compared byte for byte, trailing newlines included, before any
# archive is looked at.
sums_differ() { # <label>
	check_set "SHA256SUMS is not the one the release contract gives" "$1"
	if [[ "${RUN_ERR}" != *"failed archive verification"* && "${RUN_ERR}" != *"verified "* ]]; then
		ok "  by the SHA256SUMS comparison, before any archive is checked"
	else
		not_ok "  by the SHA256SUMS comparison, before any archive is checked"
	fi
}
bad_set sums-blank-line; printf '\n' >>"${BAD}/SHA256SUMS"
sums_differ "a SHA256SUMS with an extra blank line at the end is refused"
bad_set sums-no-newline; truncate -s -1 "${BAD}/SHA256SUMS"
assert_true "(fixture: that SHA256SUMS ends without a newline)" test "$(tail -c 1 "${BAD}/SHA256SUMS" | wc -l)" -eq 0
sums_differ "a SHA256SUMS without its final newline is refused"
bad_set sums-crlf; sed -i 's/$/\r/' "${BAD}/SHA256SUMS"
sums_differ "a SHA256SUMS with CRLF line ends is refused"
bad_set sums-exact
printf '%s  %s\n' "$(sha_of "${GOOD}/${A_NAME}")" "${A_NAME}" "$(sha_of "${GOOD}/${X_NAME}")" "${X_NAME}" >"${BAD}/SHA256SUMS"
run_release verify-assets "${BAD}" "${TEST_ROOT}/verify-sums-exact"
assert_succeeds "a SHA256SUMS of exactly the contract's bytes is accepted"

echo "=== Workflow run ==="

reset_mock "${GOOD}"
check_run() { # <jq edit> <message> <label> [commit] [branch]
	reset_mock "${GOOD}"
	edit_run "$1"
	run_release check-run "${MOCK}/run.json" "${4:-${ARTIFACTS_COMMIT}}" "${5:-main}"
	assert_fails_with "$2" "$3"
}
run_release check-run "${MOCK}/run.json" "${ARTIFACTS_COMMIT}" main
assert_succeeds "a successful run of the artifacts workflow for the reviewed commit on main passes"
check_run '.repository.full_name = "someone/fork"' "belongs to someone/fork" "a run of another repository is refused"
check_run '.head_repository.full_name = "someone/fork"' "(head someone/fork)" "a run of a fork's code is refused"
check_run '.path = ".github/workflows/other.yml"' "not of .github/workflows/boringtun-artifacts.yml" "a run of another workflow is refused"
check_run '.conclusion = "failure"' "completed/failure, not completed/success" "a failed run is refused"
check_run '.status = "in_progress" | .conclusion = null' "in_progress/none" "an unfinished run is refused"
check_run '.head_sha = "fedcba9876543210fedcba9876543210fedcba98"' "not the reviewed commit ${ARTIFACTS_COMMIT}" \
	"a run of another commit is refused"
check_run '.head_branch = "feature"' "is on feature, not on main" "a run on another branch is refused"
check_run '.event = "pull_request"' "triggered by pull_request" "a pull-request run is refused"
check_run '.' "full 40-character commit SHA" "an abbreviated commit is refused" "89abcdef"
printf 'not json\n' >"${MOCK}/run.json"
run_release check-run "${MOCK}/run.json" "${ARTIFACTS_COMMIT}" main
assert_fails_with "not the expected JSON" "a malformed run record is refused"

echo "=== Dry run ==="

write_contract "${GOOD}"
reset_mock "${GOOD}"
run_release dry-run "${RUN_ID}" "${ARTIFACTS_COMMIT}" main "${TEST_ROOT}/dry-ok"
assert_succeeds "a dry run of a good candidate passes every check"
if [[ "${RUN_OUT}" == *"tag=boringtun-cli-0.7.1-g${C12}-b2"* && "${RUN_OUT}" == *"artifacts_run=${RUN_ID}"* && \
	"${RUN_OUT}" == *"$(cat "${GOOD}/SHA256SUMS")"* ]]; then
	ok "the dry run prints the would-be tag, run, assets and notes"
else
	not_ok "the dry run prints the would-be tag, run, assets and notes"
fi
assert_true "a dry run makes no change on GitHub" no_mutation
IDENTITY="https://github.com/${REPO}/.github/workflows/boringtun-artifacts.yml@refs/heads/main"
assert_eq "2" "$(grep -c -- "--repo ${REPO} --cert-identity ${IDENTITY} --source-digest ${ARTIFACTS_COMMIT} --source-ref refs/heads/main --deny-self-hosted-runners$" "${MOCK}/attestation-args")" \
	"both archives' provenance is verified against the exact workflow identity, commit and branch"

# The notes a dry run writes, and publication uploads, name the commit the dry
# run verified: not BoringTun's source commit, this checkout's HEAD or any other.
assert_eq "$(expected_command "${ARTIFACTS_COMMIT}")" "$(notes_command "$(cat "${TEST_ROOT}/dry-ok/notes.md")")" \
	"the dry run's notes give the provenance command for the verified artifacts commit"
OTHER_COMMIT="fedcba9876543210fedcba9876543210fedcba98"
reset_mock "${GOOD}"; edit_run ".head_sha = \"${OTHER_COMMIT}\""; edit_attestation ".digest = \"${OTHER_COMMIT}\""
run_release dry-run "${RUN_ID}" "${OTHER_COMMIT}" main "${TEST_ROOT}/dry-other"
assert_succeeds "a dry run of the same archives built at another commit passes"
NOTES="$(cat "${TEST_ROOT}/dry-other/notes.md")"
assert_eq "$(expected_command "${OTHER_COMMIT}")" "$(notes_command "${NOTES}")" \
	"  and its notes name that commit as the source digest"
HEAD_COMMIT="$(git -C "${PROJECT_ROOT}" rev-parse HEAD 2>/dev/null || true)"
if [[ "${NOTES}" != *"${ARTIFACTS_COMMIT}"* && "$(notes_command "${NOTES}")" != *"${PIN_COMMIT}"* && \
	( -z "${HEAD_COMMIT}" || "${NOTES}" != *"${HEAD_COMMIT}"* ) ]]; then
	ok "  and neither the other run's commit, BoringTun's source commit nor this checkout's HEAD"
else
	not_ok "  and neither the other run's commit, BoringTun's source commit nor this checkout's HEAD"
fi

dry_fails() { # <message> <label>
	run_release dry-run "${RUN_ID}" "${ARTIFACTS_COMMIT}" main "${TEST_ROOT}/dry-${RANDOM}${RANDOM}"
	assert_fails_with "$1" "$2"
	assert_true "  and changes nothing" no_mutation
}
reset_mock "${GOOD}"; printf '[{"ref":"refs/tags/boringtun-cli-0.7.1-g%s-b2"}]\n' "${C12}" >"${MOCK}/tags.json"
dry_fails "already exists; a release tag is never reused" "an existing tag is refused"
reset_mock "${GOOD}"; printf '[{"ref":"refs/tags/boringtun-cli-0.7.1-g%s-b20"}]\n' "${C12}" >"${MOCK}/tags.json"
run_release dry-run "${RUN_ID}" "${ARTIFACTS_COMMIT}" main "${TEST_ROOT}/dry-prefix"
assert_succeeds "a tag that only shares the prefix does not block"
reset_mock "${GOOD}"; printf '[{"id":5,"tag_name":"boringtun-cli-0.7.1-g%s-b2","name":"x"}]\n' "${C12}" >"${MOCK}/releases.json"
dry_fails "a release with tag" "an existing release with the tag is refused"
reset_mock "${GOOD}"; printf '[{"id":5,"tag_name":"other","name":"BoringTun CLI 0.7.1 (WireSock %s), build 2 (experimental)"}]\n' "${C12}" >"${MOCK}/releases.json"
dry_fails "a release with tag" "an existing release with the title is refused"
reset_mock "${GOOD}"; edit_run '.conclusion = "failure"'
dry_fails "not completed/success" "a failed artifacts run is refused"
reset_mock "${GOOD}"; edit_run '.head_sha = "fedcba9876543210fedcba9876543210fedcba98"'
dry_fails "not the reviewed commit" "a run whose commit differs from the reviewed one is refused"
reset_mock "${GOOD}"; printf 'diverged\n' >"${MOCK}/compare-status"
dry_fails "is not part of main" "a reviewed commit that is not on main is refused"
reset_mock "${GOOD}"; touch "${MOCK}/attestation-fail"
dry_fails "has no valid build provenance attestation" "an archive without provenance attestation is refused"

# An attestation that differs from the artifacts workflow's in one respect.
attestation_refused() { # <jq edit> <gh's reason> <label>
	reset_mock "${GOOD}"; edit_attestation "$1"
	dry_fails "has no valid build provenance attestation" "$3"
	assert_fails_with "$2" "  for the reason gh gives"
}
LOOKALIKE="https://github.com/${REPO}/.github/workflows/boringtun-artifacts.yml-copy.yml@refs/heads/main"
attestation_refused ".identity = \"${LOOKALIKE}\"" "certificate identity ${LOOKALIKE} is not ${IDENTITY}" \
	"an attestation by a workflow whose identity only starts with the artifacts workflow's is refused"
reset_mock "${GOOD}"; edit_attestation ".identity = \"${LOOKALIKE}\""
if env MOCK="${MOCK}" "${BIN_DIR}/gh" attestation verify "${GOOD}/${X_NAME}" --repo "${REPO}" \
	--signer-workflow "${REPO}/.github/workflows/boringtun-artifacts.yml" >/dev/null 2>&1; then
	ok "  (which --signer-workflow, a prefix match in gh, would accept)"
else
	not_ok "  (which --signer-workflow, a prefix match in gh, would accept)"
fi
attestation_refused ".identity = \"https://github.com/${REPO}/.github/workflows/boringtun-runtime.yml@refs/heads/main\"" \
	"certificate identity" "an attestation by another workflow of this repository is refused"
attestation_refused ".identity |= sub(\"refs/heads/main\$\"; \"refs/heads/feature\")" \
	"certificate identity" "an attestation by the artifacts workflow of another branch is refused"
attestation_refused '.ref = "refs/heads/feature"' "source ref refs/heads/feature" \
	"an attestation of a build from another branch is refused"
attestation_refused '.digest = "fedcba9876543210fedcba9876543210fedcba98"' "source digest fedcba98" \
	"an attestation of a build of another commit is refused"
attestation_refused '.repo = "someone/fork" | .identity |= sub("wiresock/amneziawg-install"; "someone/fork")' \
	"no attestation in ${REPO}" "an attestation of another repository is refused"
attestation_refused '.runner = "self-hosted"' "built on a self-hosted runner" \
	"an attestation from a self-hosted runner is refused"
attestation_refused '.subjects = []' "no attestation for" "an attestation that does not cover the archive is refused"

reset_mock "${GOOD}"; touch "${MOCK}/download-fail"
dry_fails "could not download" "a failed artifact download is refused"
reset_mock "${TEST_ROOT}/sets/hash"
dry_fails "SHA256SUMS is not the one the release contract gives" "a downloaded SHA256SUMS that differs from the contract is refused"
bad_set tampered; printf 'x' >>"${BAD}/${A_NAME}"
reset_mock "${BAD}"
dry_fails "${A_NAME} does not have the SHA-256 in the release contract" "downloaded archive bytes that differ from the contract are refused"

echo "=== Publication ==="

reset_mock "${GOOD}"
run_release publish "${RUN_ID}" "${ARTIFACTS_COMMIT}" "${TEST_ROOT}/pub-candidate"
assert_fails_with "the release contract is a candidate" "a candidate contract is never published"
assert_eq "" "$(cat "${MOCK}/calls")" "  and nothing is called on GitHub"

write_contract "${GOOD}" BORINGTUN_RELEASE_STATE=approved
reset_mock "${GOOD}"
run_release publish "${RUN_ID}" "${ARTIFACTS_COMMIT}" "${TEST_ROOT}/pub-ok"
assert_succeeds "an approved contract is published"
assert_eq "api --method POST repos/${REPO}/releases
api --method POST https://uploads.github.com/repos/${REPO}/releases/77/assets?name=${X_NAME}
api --method POST https://uploads.github.com/repos/${REPO}/releases/77/assets?name=${A_NAME}
api --method POST https://uploads.github.com/repos/${REPO}/releases/77/assets?name=SHA256SUMS
api --method PATCH repos/${REPO}/releases/77" \
	"$(grep -E -- '--method (POST|PATCH|PUT|DELETE)' "${MOCK}/calls" | sed -E 's/ (-f|-F|-H|--input) .*//')" \
	"publication is: draft, three uploads, then one publish; nothing is deleted or replaced"
if grep -q -- '-F draft=true' "${MOCK}/calls" && grep -q -- '-F prerelease=true' "${MOCK}/calls" && \
	grep -q -- "-f target_commitish=${ARTIFACTS_COMMIT}" "${MOCK}/calls"; then
	ok "the release is created as a draft pre-release for the reviewed commit"
else
	not_ok "the release is created as a draft pre-release for the reviewed commit"
fi
if grep -q -- "-F body=@${TEST_ROOT}/pub-ok/notes.md" "${MOCK}/calls" && \
	[[ "$(notes_command "$(cat "${TEST_ROOT}/pub-ok/notes.md")")" == "$(expected_command "${ARTIFACTS_COMMIT}")" ]]; then
	ok "the published notes give the provenance command for the published commit"
else
	not_ok "the published notes give the provenance command for the published commit"
fi
assert_eq "3" "$(grep -c '^api -H Accept: application/octet-stream repos/.*/releases/assets/' "${MOCK}/calls")" \
	"every draft asset is read back before publication"
assert_true "  and the read-back comes before the publish" \
	test "$(grep -n 'releases/assets/' "${MOCK}/calls" | tail -1 | cut -d: -f1)" -lt "$(grep -n -- '--method PATCH' "${MOCK}/calls" | cut -d: -f1)"
assert_eq "3" "$(grep -c "^curl https://github.com/${REPO}/releases/download/boringtun-cli-0.7.1-g${C12}-b2/" "${MOCK}/calls")" \
	"after publication the public URLs are downloaded and compared"

pub_fails() { # <message> <label> [setup]
	reset_mock "${GOOD}"
	eval "${3:-:}"
	run_release publish "${RUN_ID}" "${ARTIFACTS_COMMIT}" "${TEST_ROOT}/pub-${RANDOM}${RANDOM}"
	assert_fails_with "$1" "$2"
	if [[ ! -e "${MOCK}/published" ]] && ! grep -q -- '--method DELETE' "${MOCK}/calls"; then
		ok "  and nothing is published or deleted"
	else
		not_ok "  and nothing is published or deleted"
	fi
}
pub_fails "an asset of that name may already exist; nothing is replaced" "an upload whose name exists fails without replacing it" \
	'mkdir -p "${MOCK}/assets" && printf "other\n" >"${MOCK}/assets/SHA256SUMS"'
pub_fails "does not read back with SHA-256" "a draft asset that reads back differently is not published" \
	'touch "${MOCK}/tamper-readback"'
pub_fails "already exists; a release tag is never reused" "a tag that appears while the draft is prepared blocks publication" \
	'printf "boringtun-cli-0.7.1-g%s-b2\n" "${C12}" >"${MOCK}/tag-after-uploads"'
pub_fails "has no valid build provenance attestation" "publication repeats every dry-run check" \
	'touch "${MOCK}/attestation-fail"'
reset_mock "${GOOD}"; touch "${MOCK}/tamper-public"
run_release publish "${RUN_ID}" "${ARTIFACTS_COMMIT}" "${TEST_ROOT}/pub-public"
assert_fails_with "the public download of ${X_NAME} does not match the verified asset" \
	"a public download URL that serves other bytes fails the publication check"
run_release publish "${RUN_ID}" "${ARTIFACTS_COMMIT}" "${TEST_ROOT}/pub-ok"
assert_fails_with "work directory must be new or empty" "a used work directory is refused"

echo "=== Workflow shape ==="

# The lines of one top-level key of a workflow, up to the next top-level key.
top_block() { # <file> <key>
	awk -v key="$2:" '$0 == key { on = 1; next } on && /^[^ #]/ { exit } on' "$1"
}
# The lines of one job, up to the next job.
job_block() { # <file> <job>
	awk -v job="  $2:" '$0 == job { on = 1; next } on && /^  [^ #]/ { exit } on' "$1"
}
assert_eq "  workflow_dispatch:" "$(top_block "${RELEASE_WORKFLOW}" on | grep -E '^  [a-z_]+:')" \
	"the release workflow runs only when dispatched: no push, tag, release or schedule trigger"
assert_eq "permissions: {}" "$(grep -E '^permissions:' "${RELEASE_WORKFLOW}")" "the release workflow grants nothing by default"
if job_block "${RELEASE_WORKFLOW}" verify | grep -q 'contents: read' && \
	! job_block "${RELEASE_WORKFLOW}" verify | grep -qE 'contents: write|id-token|attestations: write'; then
	ok "the dry-run job can only read"
else
	not_ok "the dry-run job can only read"
fi
assert_eq "1" "$(grep -c 'contents: write' "${RELEASE_WORKFLOW}")" "contents: write appears once, in the publish job"
if job_block "${RELEASE_WORKFLOW}" publish | grep -q 'contents: write' && \
	job_block "${RELEASE_WORKFLOW}" publish | grep -qF "if: inputs.mode == 'publish'" && \
	job_block "${RELEASE_WORKFLOW}" publish | grep -qF 'needs: verify' && \
	job_block "${RELEASE_WORKFLOW}" publish | grep -qF '"$GITHUB_REF" != refs/heads/main'; then
	ok "the publish job runs only for mode=publish, after the dry run, from main"
else
	not_ok "the publish job runs only for mode=publish, after the dry run, from main"
fi
assert_eq "dry-run" "$(awk '/^      mode:/ { on = 1 } on && /default:/ { print $2; exit }' "${RELEASE_WORKFLOW}")" "the default mode is dry-run"
if ! grep -nE -- '--clobber|release (upload|delete|edit)|method DELETE|-X DELETE|force' \
	"${RELEASE_SCRIPT}" "${RELEASE_WORKFLOW}"; then
	ok "no --clobber, no release upload/delete/edit, no DELETE and no force anywhere in the release path"
else
	not_ok "no --clobber, no release upload/delete/edit, no DELETE and no force anywhere in the release path"
fi
if ! grep -n 'verify-test-archive' "${RELEASE_SCRIPT}" "${RELEASE_WORKFLOW}" "${ARTIFACTS_WORKFLOW}" && \
	[[ "$(grep -o 'bta_verify_archive .*' "${RELEASE_SCRIPT}")" == 'bta_verify_archive "${archive}" "${work}/${arch}" 0)" || {' ]]; then
	ok "the release path and the artifacts workflow never skip the notices check"
else
	not_ok "the release path and the artifacts workflow never skip the notices check"
fi
assert_eq "permissions:
  contents: read" "$(grep -A1 -E '^permissions:' "${ARTIFACTS_WORKFLOW}")" "the artifacts workflow is read-only by default"
assert_eq "2" "$(grep -cE 'id-token: write|attestations: write' "${ARTIFACTS_WORKFLOW}")" \
	"the artifacts workflow requests id-token and attestations write once each"
ATTEST="$(job_block "${ARTIFACTS_WORKFLOW}" attest)"
if grep -q 'id-token: write' <<<"${ATTEST}" && grep -q 'attestations: write' <<<"${ATTEST}" && \
	grep -q 'contents: read' <<<"${ATTEST}" && grep -qF "if: github.event_name != 'pull_request'" <<<"${ATTEST}" && \
	grep -q 'uses: actions/attest-build-provenance@v4' <<<"${ATTEST}" && \
	grep -q 'subject-path: dist/boringtun-cli-\*.tar.gz' <<<"${ATTEST}"; then
	ok "only the attest job can attest, it attests the archives, and never for a pull request"
else
	not_ok "only the attest job can attest, it attests the archives, and never for a pull request"
fi
if ! top_block "${ARTIFACTS_WORKFLOW}" on | grep -qE '^  (release|schedule|workflow_run):|tags:'; then
	ok "building artifacts never publishes: no release, tag or schedule trigger"
else
	not_ok "building artifacts never publishes: no release, tag or schedule trigger"
fi

echo "=== Usage ==="

run_release frobnicate
if (( RUN_RC == 2 )) && [[ "${RUN_ERR}" == *"dry-run <run-id> <commit> <branch> <work-dir>"* ]]; then
	ok "an unknown command prints usage and exits 2"
else
	not_ok "an unknown command prints usage and exits 2 (rc ${RUN_RC})"
fi
env -u GITHUB_REPOSITORY PATH="${BIN_DIR}:${PATH}" MOCK="${MOCK}" BORINGTUN_PIN_FILE="${PIN_FILE}" \
	BORINGTUN_RELEASE_FILE="${CONTRACT}" bash "${RELEASE_SCRIPT}" dry-run 1 "${ARTIFACTS_COMMIT}" main "${TEST_ROOT}/dry-norepo" \
	>/dev/null 2>"${TEST_ROOT}/run.err"
RUN_RC=$? RUN_ERR="$(cat "${TEST_ROOT}/run.err")"
assert_fails_with "GITHUB_REPOSITORY must be set" "the repository is never guessed"

printf '\n%d tests, %d failures\n' "$((PASS + FAIL))" "${FAIL}"
(( FAIL == 0 ))
