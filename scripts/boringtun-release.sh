#!/usr/bin/env bash
# Verify and publish a public boringtun-cli artifact release. See
# docs/BORINGTUN_ARTIFACTS.md, "Publishing a release".
#
# The release contract, packaging/boringtun/release.env, names one exact release
# of the pin in packaging/boringtun/pin.env: its tag, build number, asset names
# and the SHA-256 of every archive and of the binary inside it. This script never
# builds anything. It takes the archives that one successful, attested run of the
# BoringTun Artifacts workflow built, checks them against the contract and the
# pin, and only then, for an approved contract, publishes them.
#
# Commands:
#   contract                                  print the validated release contract
#   plan                                      print the tag, title, assets and hashes
#   notes                                     print the release notes
#   check-run <run.json> <commit> <branch>    check workflow run metadata (API JSON)
#   verify-assets <asset-dir> <work-dir>      check a downloaded artifact set
#   dry-run <run-id> <commit> <branch> <work-dir>
#                                             every check, up to the first change on GitHub
#   publish <run-id> <commit> <work-dir>      the dry-run checks for main, then create a
#                                             draft, upload, read back, re-check, publish
#
# dry-run and publish act on GITHUB_REPOSITORY (owner/repo) through the GitHub
# CLI, which reads its token from GH_TOKEN. Nothing is ever deleted, replaced or
# overwritten: an upload whose name exists fails, and a failure after the draft
# was created leaves the draft for inspection.
#
# BORINGTUN_RELEASE_FILE overrides the contract location (used by the tests).

BTR_ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/boringtun-artifact.sh
source "${BTR_ROOT}/scripts/boringtun-artifact.sh"

BTR_CONTRACT_FILE="${BORINGTUN_RELEASE_FILE:-${BTR_ROOT}/packaging/boringtun/release.env}"
BTR_ARTIFACTS_WORKFLOW=".github/workflows/boringtun-artifacts.yml"
BTR_ARTIFACTS_NAME="boringtun-cli-artifacts"
BTR_PUBLISH_BRANCH="main"
BTR_ARCHES="x86_64 aarch64"
BTR_KEYS="BORINGTUN_RELEASE_FORMAT BORINGTUN_RELEASE_STATE BORINGTUN_RELEASE_SOURCE_COMMIT BORINGTUN_RELEASE_VERSION BORINGTUN_RELEASE_ARTIFACT_FORMAT BORINGTUN_RELEASE_BUILD BORINGTUN_RELEASE_TAG BORINGTUN_RELEASE_ASSET_X86_64 BORINGTUN_RELEASE_ARCHIVE_SHA256_X86_64 BORINGTUN_RELEASE_BINARY_SHA256_X86_64 BORINGTUN_RELEASE_ASSET_AARCH64 BORINGTUN_RELEASE_ARCHIVE_SHA256_AARCH64 BORINGTUN_RELEASE_BINARY_SHA256_AARCH64"

declare -gA BTR=()
BTR_TITLE=""
BTR_REPO=""

# The key suffix of an architecture: x86_64 -> X86_64, aarch64 -> AARCH64.
btr_arch_key() {
    printf '%s\n' "${1^^}"
}

# Parse the contract as data and check it against the pin: exactly the known
# keys, once each, every value in its grammar, and every derived value (tag,
# asset names) equal to what the pin and the build number give.
btr_read_contract() {
    local file="${BTR_CONTRACT_FILE}" line key value line_no=0 arch k expected
    local -A seen=()

    BTR=()
    if [[ ! -f "${file}" || -L "${file}" ]]; then
        bta_err "release contract is missing or not a regular file: ${file}"
        return 1
    fi
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line_no=$((line_no + 1))
        [[ "${line}" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        if [[ ! "${line}" =~ ^([A-Z][A-Z0-9_]*)=([^[:space:]\"\'\`\$\;\&\|\<\>\(\)\]+)$ ]]; then
            bta_err "release contract line ${line_no} is not a plain KEY=VALUE assignment"
            return 1
        fi
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        if [[ " ${BTR_KEYS} " != *" ${key} "* ]]; then
            bta_err "release contract line ${line_no} sets unknown key ${key}"
            return 1
        fi
        if [[ -n "${seen[${key}]:-}" ]]; then
            bta_err "release contract defines ${key} more than once"
            return 1
        fi
        seen[${key}]=1
        case "${key}" in
            BORINGTUN_RELEASE_FORMAT) [[ "${value}" == 1 ]] ;;
            BORINGTUN_RELEASE_STATE) [[ "${value}" == candidate || "${value}" == approved ]] ;;
            BORINGTUN_RELEASE_SOURCE_COMMIT) [[ "${value}" =~ ^[0-9a-f]{40}$ ]] ;;
            BORINGTUN_RELEASE_VERSION) [[ "${value}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ;;
            BORINGTUN_RELEASE_ARTIFACT_FORMAT | BORINGTUN_RELEASE_BUILD) [[ "${value}" =~ ^[1-9][0-9]{0,5}$ ]] ;;
            BORINGTUN_RELEASE_TAG) [[ "${value}" =~ ^boringtun-cli-[0-9]+\.[0-9]+\.[0-9]+-g[0-9a-f]{12}-b[1-9][0-9]*$ ]] ;;
            BORINGTUN_RELEASE_ASSET_*) [[ "${value}" =~ ^boringtun-cli-[0-9]+\.[0-9]+\.[0-9]+-g[0-9a-f]{12}-linux-(x86_64|aarch64)-musl\.tar\.gz$ ]] ;;
            BORINGTUN_RELEASE_ARCHIVE_SHA256_* | BORINGTUN_RELEASE_BINARY_SHA256_*) [[ "${value}" =~ ^[0-9a-f]{64}$ ]] ;;
        esac || {
            bta_err "release contract: ${key} has an invalid value"
            return 1
        }
        BTR[${key}]="${value}"
    done <"${file}"
    for key in ${BTR_KEYS}; do
        if [[ -z "${seen[${key}]:-}" ]]; then
            bta_err "release contract does not define ${key}"
            return 1
        fi
    done

    if [[ "${BTR[BORINGTUN_RELEASE_SOURCE_COMMIT]}" != "${BTA_COMMIT}" ]]; then
        bta_err "release contract is for source commit ${BTR[BORINGTUN_RELEASE_SOURCE_COMMIT]}, but the pin is ${BTA_COMMIT}"
        return 1
    fi
    if [[ "${BTR[BORINGTUN_RELEASE_VERSION]}" != "${BTA_VERSION}" ]]; then
        bta_err "release contract is for boringtun-cli ${BTR[BORINGTUN_RELEASE_VERSION]}, but the pin is ${BTA_VERSION}"
        return 1
    fi
    if [[ "${BTR[BORINGTUN_RELEASE_ARTIFACT_FORMAT]}" != "${BTA_ARTIFACT_FORMAT}" ]]; then
        bta_err "release contract is for artifact format ${BTR[BORINGTUN_RELEASE_ARTIFACT_FORMAT]}, but the pin is ${BTA_ARTIFACT_FORMAT}"
        return 1
    fi
    expected="${BTA_PACKAGE}-${BTA_VERSION}-g${BTA_COMMIT:0:12}-b${BTR[BORINGTUN_RELEASE_BUILD]}"
    if [[ "${BTR[BORINGTUN_RELEASE_TAG]}" != "${expected}" ]]; then
        bta_err "release contract tag must be ${expected} for this pin and build"
        return 1
    fi
    for arch in ${BTR_ARCHES}; do
        k="$(btr_arch_key "${arch}")"
        expected="$(bta_archive_stem "${arch}").tar.gz"
        if [[ "${BTR[BORINGTUN_RELEASE_ASSET_${k}]}" != "${expected}" ]]; then
            bta_err "release contract asset for ${arch} must be ${expected}"
            return 1
        fi
    done
    if [[ "${BTR[BORINGTUN_RELEASE_ARCHIVE_SHA256_X86_64]}" == "${BTR[BORINGTUN_RELEASE_ARCHIVE_SHA256_AARCH64]}" || \
        "${BTR[BORINGTUN_RELEASE_BINARY_SHA256_X86_64]}" == "${BTR[BORINGTUN_RELEASE_BINARY_SHA256_AARCH64]}" ]]; then
        bta_err "release contract lists the same hash for both architectures"
        return 1
    fi
    BTR_TITLE="BoringTun CLI ${BTA_VERSION} (WireSock ${BTA_COMMIT:0:12}), build ${BTR[BORINGTUN_RELEASE_BUILD]} (experimental)"
}

btr_print_contract() {
    local key
    for key in ${BTR_KEYS}; do
        printf '%s=%s\n' "${key}" "${BTR[${key}]}"
    done
}

# The exact SHA256SUMS the release carries: both archives, sorted by name.
btr_expected_sums() {
    local arch k
    for arch in ${BTR_ARCHES}; do
        k="$(btr_arch_key "${arch}")"
        printf '%s  %s\n' "${BTR[BORINGTUN_RELEASE_ARCHIVE_SHA256_${k}]}" "${BTR[BORINGTUN_RELEASE_ASSET_${k}]}"
    done | LC_ALL=C sort -k 2
}

btr_sums_sha256() {
    btr_expected_sums | sha256sum | awk '{ print $1 }'
}

btr_print_plan() {
    local arch k
    printf 'state=%s\n' "${BTR[BORINGTUN_RELEASE_STATE]}"
    printf 'tag=%s\n' "${BTR[BORINGTUN_RELEASE_TAG]}"
    printf 'title=%s\n' "${BTR_TITLE}"
    printf 'source=%s@%s\n' "${BTA_REPOSITORY}" "${BTA_COMMIT}"
    printf 'version=%s\n' "${BTA_VERSION}"
    printf 'build=%s\n' "${BTR[BORINGTUN_RELEASE_BUILD]}"
    for arch in ${BTR_ARCHES}; do
        k="$(btr_arch_key "${arch}")"
        printf 'asset=%s archive_sha256=%s binary_sha256=%s\n' "${BTR[BORINGTUN_RELEASE_ASSET_${k}]}" \
            "${BTR[BORINGTUN_RELEASE_ARCHIVE_SHA256_${k}]}" "${BTR[BORINGTUN_RELEASE_BINARY_SHA256_${k}]}"
    done
    printf 'asset=SHA256SUMS sha256=%s\n' "$(btr_sums_sha256)"
}

btr_print_notes() {
    cat <<EOF
Static \`boringtun-cli\` binaries built by this repository from
[WireSock BoringTun](${BTA_REPOSITORY}) commit \`${BTA_COMMIT}\`
(\`boringtun-cli\` ${BTA_VERSION}), build ${BTR[BORINGTUN_RELEASE_BUILD]}, for the experimental userspace
AmneziaWG backend of \`amneziawg-install\`.

These archives are meant for \`amneziawg-install\`, which checks them against
SHA-256 values embedded in the installer. They are not published or endorsed
by the upstream BoringTun or WireSock BoringTun projects. At the time of this
release, \`amneziawg-install\` does not yet install BoringTun.

| Architecture | Target | Linkage |
|---|---|---|
| x86_64 | \`x86_64-unknown-linux-musl\` | static PIE |
| aarch64 | \`aarch64-unknown-linux-musl\` | static, not position-independent: the binary's own code is not address-randomised |

Built reproducibly with Rust ${BTA_RUST_TOOLCHAIN}
(\`cargo build --release --locked -p boringtun-cli\`, symbols stripped) by the
BoringTun Artifacts workflow, which also attests their build provenance. Each
archive holds the binary, BoringTun's BSD-3-Clause \`LICENSE\`,
\`THIRD-PARTY-LICENSES\` for the Rust crates compiled into it, and a
\`MANIFEST\` with the build provenance and the binary's SHA-256.

Tested on native runners of both architectures, with the daemon in the
foreground, against \`amneziawg-go\` (BoringTun's \`awg-go-interop.sh\` and
\`awg31-interop.sh\`). Interop with the AmneziaWG kernel module has not been
tested with these binaries.

Known advisory: RUSTSEC-2025-0069 reports that \`daemonize\` 0.5.0, a
dependency of \`boringtun-cli\`, is unmaintained. It is not a disclosed
vulnerability. The crate runs only when \`boringtun-cli\` daemonizes itself,
and \`amneziawg-install\` runs it exclusively in the foreground.

Verify the archives with \`sha256sum -c SHA256SUMS\` and their provenance with
\`gh attestation verify <archive> --repo ${BTR_REPO:-<owner>/<repo>}\`.

\`\`\`
$(btr_expected_sums)
\`\`\`

Binary SHA-256 (\`binary_sha256\` in each \`MANIFEST\`):

\`\`\`
${BTR[BORINGTUN_RELEASE_BINARY_SHA256_X86_64]}  x86_64 boringtun-cli
${BTR[BORINGTUN_RELEASE_BINARY_SHA256_AARCH64]}  aarch64 boringtun-cli
\`\`\`
EOF
}

btr_need_repo() {
    BTR_REPO="${GITHUB_REPOSITORY:-}"
    if [[ ! "${BTR_REPO}" =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$ ]]; then
        bta_err "GITHUB_REPOSITORY must be set to owner/repo"
        return 1
    fi
    local tool
    for tool in gh jq curl; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            bta_err "${tool} is required"
            return 1
        fi
    done
}

# A new, empty directory for the work of one command.
btr_new_dir() {
    if [[ -e "$1" && ( ! -d "$1" || -L "$1" || -n "$(ls -A -- "$1")" ) ]]; then
        bta_err "work directory must be new or empty: $1"
        return 1
    fi
    mkdir -p -- "$1"
}

# Check the run of the artifacts workflow that built the archives, from the JSON
# of GET /repos/{owner}/{repo}/actions/runs/{id}: this repository's own run of
# that workflow, on a push or a manual dispatch, completed successfully, for
# exactly the reviewed commit on the expected branch.
btr_check_run() {
    local json="$1" commit="$2" branch="$3" fields
    local repo head_repo path status conclusion head_sha head_branch event

    [[ -n "${BTR_REPO}" ]] || btr_need_repo || return 1
    if [[ ! "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
        bta_err "the artifacts commit must be a full 40-character commit SHA"
        return 1
    fi
    if ! fields="$(jq -er '[.repository.full_name, .head_repository.full_name, .path, .status,
            (.conclusion // "none"), .head_sha, .head_branch, .event] | map(tostring) | @tsv' <"${json}" 2>/dev/null)"; then
        bta_err "the workflow run record is not the expected JSON"
        return 1
    fi
    IFS=$'\t' read -r repo head_repo path status conclusion head_sha head_branch event <<<"${fields}"
    if [[ "${repo}" != "${BTR_REPO}" || "${head_repo}" != "${BTR_REPO}" ]]; then
        bta_err "the workflow run belongs to ${repo} (head ${head_repo}), not to ${BTR_REPO}"
        return 1
    fi
    if [[ "${path}" != "${BTR_ARTIFACTS_WORKFLOW}" ]]; then
        bta_err "the workflow run is of ${path}, not of ${BTR_ARTIFACTS_WORKFLOW}"
        return 1
    fi
    if [[ "${status}" != completed || "${conclusion}" != success ]]; then
        bta_err "the workflow run is ${status}/${conclusion}, not completed/success"
        return 1
    fi
    if [[ "${event}" != push && "${event}" != workflow_dispatch ]]; then
        bta_err "the workflow run was triggered by ${event}, not by a push or a manual dispatch"
        return 1
    fi
    if [[ "${head_sha}" != "${commit}" ]]; then
        bta_err "the workflow run built ${head_sha}, not the reviewed commit ${commit}"
        return 1
    fi
    if [[ "${head_branch}" != "${branch}" ]]; then
        bta_err "the workflow run is on ${head_branch}, not on ${branch}"
        return 1
    fi
}

# Check a downloaded artifact set: exactly the two archives and SHA256SUMS, as
# regular files; SHA256SUMS byte for byte as the contract gives it; every
# archive's SHA-256; and every archive's contents, MANIFEST, notices and binary,
# through the artifact script (without running the binaries, which may be of
# another architecture), with the binary's SHA-256 from the contract.
btr_verify_assets() {
    local dir="$1" work="$2" arch k name archive binary listing expected sums

    if [[ ! -d "${dir}" || -L "${dir}" ]]; then
        bta_err "asset directory is missing: ${dir}"
        return 1
    fi
    btr_new_dir "${work}" || return 1
    expected="$(printf '%s f\n' "${BTR[BORINGTUN_RELEASE_ASSET_X86_64]}" "${BTR[BORINGTUN_RELEASE_ASSET_AARCH64]}" SHA256SUMS | LC_ALL=C sort)"
    listing="$(find "${dir}" -mindepth 1 -printf '%P %y\n' | LC_ALL=C sort)"
    if [[ "${listing}" != "${expected}" ]]; then
        bta_err "the artifact set is not exactly the two archives and SHA256SUMS, as regular files"
        return 1
    fi
    # Compared as files: a command substitution would drop trailing newlines.
    sums="${work}/SHA256SUMS.expected"
    btr_expected_sums >"${sums}" || return 1
    if ! cmp -s -- "${dir}/SHA256SUMS" "${sums}"; then
        bta_err "SHA256SUMS is not the one the release contract gives"
        return 1
    fi
    for arch in ${BTR_ARCHES}; do
        k="$(btr_arch_key "${arch}")"
        name="${BTR[BORINGTUN_RELEASE_ASSET_${k}]}"
        archive="${dir}/${name}"
        if [[ "$(bta_sha256 "${archive}")" != "${BTR[BORINGTUN_RELEASE_ARCHIVE_SHA256_${k}]}" ]]; then
            bta_err "${name} does not have the SHA-256 in the release contract"
            return 1
        fi
        binary="$(bta_verify_archive "${archive}" "${work}/${arch}" 0)" || {
            bta_err "${name} failed archive verification"
            return 1
        }
        if [[ "$(bta_sha256 "${binary}")" != "${BTR[BORINGTUN_RELEASE_BINARY_SHA256_${k}]}" ]]; then
            bta_err "the boringtun-cli in ${name} does not have the SHA-256 in the release contract"
            return 1
        fi
        bta_info "verified ${name}"
    done
}

# Refuse a destination that is not free: a tag of that name, or a release with
# that tag or title, other than the draft with id $3 that this run created.
# Drafts are listed only with write access, so the publish job repeats this.
btr_check_destination() {
    local tag="$1" title="$2" own_id="${3:-}" refs releases

    if ! refs="$(gh api "repos/${BTR_REPO}/git/matching-refs/tags/${tag}" --jq '.[].ref')"; then
        bta_err "could not list the tags of ${BTR_REPO}"
        return 1
    fi
    if grep -qxF "refs/tags/${tag}" <<<"${refs}"; then
        bta_err "tag ${tag} already exists; a release tag is never reused or moved"
        return 1
    fi
    if ! releases="$(gh api --paginate "repos/${BTR_REPO}/releases?per_page=100" \
            --jq '.[] | [(.id | tostring), .tag_name, (.name // "")] | @tsv')"; then
        bta_err "could not list the releases of ${BTR_REPO}"
        return 1
    fi
    if awk -F '\t' -v tag="${tag}" -v title="${title}" -v own="${own_id}" \
        '($2 == tag || $3 == title) && $1 != own { found = 1 } END { exit !found }' <<<"${releases}"; then
        bta_err "a release with tag ${tag} or title '${BTR_TITLE}' already exists"
        return 1
    fi
}

# Every check up to the first change on GitHub. Leaves the verified assets in
# <work-dir>/assets and the release notes in <work-dir>/notes.md.
btr_dry_run() {
    local run_id="$1" commit="$2" branch="$3" work="$4" status arch k name

    btr_need_repo || return 1
    if [[ ! "${run_id}" =~ ^[1-9][0-9]{0,19}$ ]]; then
        bta_err "the artifacts run id must be a number"
        return 1
    fi
    if [[ ! "${branch}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]]; then
        bta_err "invalid branch name"
        return 1
    fi
    btr_new_dir "${work}" || return 1

    bta_info "checking run ${run_id} of ${BTR_ARTIFACTS_WORKFLOW} in ${BTR_REPO}"
    if ! gh api "repos/${BTR_REPO}/actions/runs/${run_id}" >"${work}/run.json"; then
        bta_err "could not read workflow run ${run_id}"
        return 1
    fi
    btr_check_run "${work}/run.json" "${commit}" "${branch}" || return 1
    if ! status="$(gh api "repos/${BTR_REPO}/compare/${commit}...${branch}" --jq '.status')" || \
        [[ "${status}" != identical && "${status}" != ahead ]]; then
        bta_err "commit ${commit} is not part of ${branch} (compare status '${status:-unknown}')"
        return 1
    fi

    bta_info "downloading ${BTR_ARTIFACTS_NAME} from run ${run_id}"
    if ! gh run download "${run_id}" --repo "${BTR_REPO}" --name "${BTR_ARTIFACTS_NAME}" --dir "${work}/assets"; then
        bta_err "could not download ${BTR_ARTIFACTS_NAME} from run ${run_id}"
        return 1
    fi
    btr_verify_assets "${work}/assets" "${work}/verify" || return 1

    for arch in ${BTR_ARCHES}; do
        k="$(btr_arch_key "${arch}")"
        name="${BTR[BORINGTUN_RELEASE_ASSET_${k}]}"
        bta_info "verifying the build provenance attestation of ${name}"
        if ! gh attestation verify "${work}/assets/${name}" --repo "${BTR_REPO}" \
            --cert-identity "https://github.com/${BTR_REPO}/${BTR_ARTIFACTS_WORKFLOW}@refs/heads/${branch}" \
            --source-digest "${commit}" --source-ref "refs/heads/${branch}" \
            --deny-self-hosted-runners >"${work}/attestation-${arch}.txt" 2>&1; then
            sed 's/^/    /' "${work}/attestation-${arch}.txt" >&2
            bta_err "${name} has no valid build provenance attestation from ${BTR_ARTIFACTS_WORKFLOW} at ${commit}"
            return 1
        fi
    done

    btr_check_destination "${BTR[BORINGTUN_RELEASE_TAG]}" "${BTR_TITLE}" || return 1
    btr_print_notes >"${work}/notes.md"
    bta_info "all checks passed; nothing was created"
    btr_print_plan
    printf 'artifacts_run=%s\nartifacts_commit=%s\n' "${run_id}" "${commit}"
    printf '\n'
    cat -- "${work}/notes.md"
}

# Upload one file to the draft release. The upload API refuses a name that
# already exists, so nothing is ever replaced.
btr_upload() {
    local id="$1" file="$2" name response size
    name="$(basename -- "${file}")"
    size="$(stat -c %s -- "${file}")"
    if ! response="$(gh api --method POST \
        "https://uploads.github.com/repos/${BTR_REPO}/releases/${id}/assets?name=${name}" \
        -H 'Content-Type: application/octet-stream' --input "${file}")"; then
        bta_err "uploading ${name} failed (an asset of that name may already exist; nothing is replaced)"
        return 1
    fi
    if [[ "$(jq -r '[.name, .state, (.size | tostring)] | @tsv' <<<"${response}")" != "${name}"$'\t'uploaded$'\t'"${size}" ]]; then
        bta_err "GitHub did not record ${name} as uploaded with ${size} bytes"
        return 1
    fi
}

# Read every asset of the release back and compare it with what must be there:
# exactly the three names, each with the expected SHA-256.
btr_read_back() {
    local id="$1" dir="$2" listing expected asset_id name arch k want
    local -A sha=()

    for arch in ${BTR_ARCHES}; do
        k="$(btr_arch_key "${arch}")"
        sha[${BTR[BORINGTUN_RELEASE_ASSET_${k}]}]="${BTR[BORINGTUN_RELEASE_ARCHIVE_SHA256_${k}]}"
    done
    sha[SHA256SUMS]="$(btr_sums_sha256)"
    btr_new_dir "${dir}" || return 1
    if ! listing="$(gh api --paginate "repos/${BTR_REPO}/releases/${id}/assets?per_page=100" \
            --jq '.[] | [(.id | tostring), .name, .state] | @tsv')"; then
        bta_err "could not list the assets of release ${id}"
        return 1
    fi
    expected="$(printf '%s\n' "${!sha[@]}" | LC_ALL=C sort)"
    if [[ "$(awk -F '\t' '{ print $2 }' <<<"${listing}" | LC_ALL=C sort)" != "${expected}" ]] || \
        awk -F '\t' '$3 != "uploaded" { bad = 1 } END { exit !bad }' <<<"${listing}"; then
        bta_err "release ${id} does not hold exactly the three uploaded assets"
        return 1
    fi
    while IFS=$'\t' read -r asset_id name _; do
        want="${sha[${name}]}"
        if ! gh api -H 'Accept: application/octet-stream' "repos/${BTR_REPO}/releases/assets/${asset_id}" >"${dir}/${name}" || \
            [[ "$(bta_sha256 "${dir}/${name}")" != "${want}" ]]; then
            bta_err "asset ${name} of release ${id} does not read back with SHA-256 ${want}"
            return 1
        fi
    done <<<"${listing}"
}

btr_publish() {
    local run_id="$1" commit="$2" work="$3" tag response id draft arch k name ref
    local -a files=()

    if [[ "${BTR[BORINGTUN_RELEASE_STATE]}" != approved ]]; then
        bta_err "the release contract is a candidate: set BORINGTUN_RELEASE_STATE=approved in a reviewed change to publish it"
        return 1
    fi
    btr_dry_run "${run_id}" "${commit}" "${BTR_PUBLISH_BRANCH}" "${work}" >"${work}.dry-run" || return 1
    tag="${BTR[BORINGTUN_RELEASE_TAG]}"
    for arch in ${BTR_ARCHES}; do
        k="$(btr_arch_key "${arch}")"
        files+=("${work}/assets/${BTR[BORINGTUN_RELEASE_ASSET_${k}]}")
    done
    files+=("${work}/assets/SHA256SUMS")

    bta_info "creating draft release ${tag} for ${commit}"
    if ! response="$(gh api --method POST "repos/${BTR_REPO}/releases" \
        -f tag_name="${tag}" -f target_commitish="${commit}" -f name="${BTR_TITLE}" \
        -F body=@"${work}/notes.md" -F draft=true -F prerelease=true -f make_latest=false)"; then
        bta_err "could not create the draft release"
        return 1
    fi
    id="$(jq -r '.id // empty' <<<"${response}")"
    draft="$(jq -r '[.draft, .tag_name] | map(tostring) | @tsv' <<<"${response}")"
    if [[ ! "${id}" =~ ^[0-9]+$ || "${draft}" != true$'\t'"${tag}" ]]; then
        bta_err "GitHub did not create a draft release for ${tag}"
        return 1
    fi
    bta_info "draft release ${id} created; on any failure from here it is left as a draft for inspection"
    for name in "${files[@]}"; do
        btr_upload "${id}" "${name}" || return 1
    done
    btr_read_back "${id}" "${work}/readback" || return 1
    btr_check_destination "${tag}" "${BTR_TITLE}" "${id}" || return 1

    bta_info "publishing release ${id}"
    if ! response="$(gh api --method PATCH "repos/${BTR_REPO}/releases/${id}" -F draft=false)" || \
        [[ "$(jq -r '[.draft, .tag_name] | map(tostring) | @tsv' <<<"${response}")" != false$'\t'"${tag}" ]]; then
        bta_err "could not publish release ${id}"
        return 1
    fi
    if ! ref="$(gh api "repos/${BTR_REPO}/git/ref/tags/${tag}" --jq '[.object.type, .object.sha] | @tsv')" || \
        [[ "${ref}" != commit$'\t'"${commit}" ]]; then
        bta_err "tag ${tag} does not point at ${commit} after publication"
        return 1
    fi
    # What an installer downloads: the public release URLs, without a token.
    btr_new_dir "${work}/public" || return 1
    for name in "${files[@]}"; do
        name="$(basename -- "${name}")"
        if ! curl -fsSL --retry 5 --retry-delay 3 -o "${work}/public/${name}" \
                "https://github.com/${BTR_REPO}/releases/download/${tag}/${name}" || \
            ! cmp -s "${work}/public/${name}" "${work}/assets/${name}"; then
            bta_err "the public download of ${name} does not match the verified asset"
            return 1
        fi
    done
    bta_info "published ${tag}: https://github.com/${BTR_REPO}/releases/tag/${tag}"
    cat -- "${work}.dry-run"
}

btr_usage() {
    sed -n '/^# Commands:/,/^# BORINGTUN_RELEASE_FILE/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

btr_main() {
    local command="${1:-}"

    [[ $# -gt 0 ]] && shift
    bta_read_pin || return 1
    btr_read_contract || return 1
    case "${command}:$#" in
        contract:0) btr_print_contract ;;
        plan:0) btr_print_plan ;;
        notes:0) BTR_REPO="${GITHUB_REPOSITORY:-}" btr_print_notes ;;
        check-run:3) btr_need_repo && btr_check_run "$@" ;;
        verify-assets:2) btr_verify_assets "$@" ;;
        dry-run:4) btr_dry_run "$@" ;;
        publish:3) btr_need_repo && btr_publish "$@" ;;
        *)
            btr_usage
            return 2
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    set -uo pipefail
    umask 022
    btr_main "$@"
    exit $?
fi
