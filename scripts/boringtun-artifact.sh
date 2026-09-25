#!/usr/bin/env bash
# Build, package and verify the pinned WireSock BoringTun `boringtun-cli`
# artifacts. See docs/BORINGTUN_ARTIFACTS.md.
#
# The pin (repository, commit, CLI version, Rust toolchain and artifact format)
# lives in packaging/boringtun/pin.env. This script parses it as data and never
# sources it. Source acquisition is the caller's job: every command that reads
# BoringTun takes an already checked-out tree and refuses one whose HEAD is not
# the pinned commit or that has local changes.
#
# Commands:
#   pin                                         print the validated pin as KEY=VALUE
#   build <source> <target> <build-dir>         build boringtun-cli into a new <build-dir>
#   licenses <source> <output-file>             license/source gate and THIRD-PARTY-LICENSES
#   package <build-dir> <source> <third-party-licenses> <out-dir>
#                                               write a deterministic .tar.gz into <out-dir>
#   verify-archive <archive> <extract-dir>      extract safely and check contents and binary
#   device-smoke <boringtun-cli>                as root: create a TUN device and query its UAPI
#   checksums <dir>                             write <dir>/SHA256SUMS for the archives in <dir>
#
# The script never modifies the BoringTun source, never runs `cargo update`,
# installs nothing and writes only below the directories it is given.
#
# BORINGTUN_PIN_FILE overrides the pin location (used by the tests).

BTA_ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BTA_PIN_FILE="${BORINGTUN_PIN_FILE:-${BTA_ROOT}/packaging/boringtun/pin.env}"
BTA_CONFIG_DIR="${BTA_ROOT}/packaging/boringtun"
BTA_PACKAGE="boringtun-cli"
BTA_SUPPORTED_TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl"
# Recorded verbatim in MANIFEST. The placeholders stand for the local source and
# Cargo home paths that the build remaps, so no runner path reaches the binary.
BTA_BUILD_PROFILE="release,strip=symbols"
BTA_RUSTFLAGS_RECORD="--remap-path-prefix=<source>=/boringtun --remap-path-prefix=<cargo-home>=/cargo"
BTA_MANIFEST_KEYS="artifact_format name version source_repository source_commit source_date_epoch target os arch libc linkage rust_toolchain rustc cargo build_command build_profile rustflags binary binary_sha256 license third_party_licenses"

BTA_REPOSITORY=""
BTA_COMMIT=""
BTA_VERSION=""
BTA_RUST_TOOLCHAIN=""
BTA_ARTIFACT_FORMAT=""

bta_err() {
    printf 'ERROR: %s\n' "$*" >&2
}

bta_info() {
    printf '==> %s\n' "$*" >&2
}

bta_sha256() {
    sha256sum -- "$1" | awk '{ print $1 }'
}

# Parse the pin file as data: comments and blank lines, then exactly one line
# per known key, each value checked against its own grammar.
bta_read_pin() {
    local file="${BTA_PIN_FILE}"
    local line key value line_no=0
    local -A seen=()

    BTA_REPOSITORY="" BTA_COMMIT="" BTA_VERSION="" BTA_RUST_TOOLCHAIN="" BTA_ARTIFACT_FORMAT=""
    if [[ ! -f "${file}" || -L "${file}" ]]; then
        bta_err "pin file is missing or not a regular file: ${file}"
        return 1
    fi
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line_no=$((line_no + 1))
        [[ "${line}" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        if [[ ! "${line}" =~ ^([A-Z][A-Z0-9_]*)=([^[:space:]\"\'\`\$\;\&\|\<\>\(\)\]+)$ ]]; then
            bta_err "pin file line ${line_no} is not a plain KEY=VALUE assignment"
            return 1
        fi
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        if [[ -n "${seen[${key}]:-}" ]]; then
            bta_err "pin file defines ${key} more than once"
            return 1
        fi
        seen[${key}]=1
        case "${key}" in
            BORINGTUN_REPOSITORY)
                [[ "${value}" =~ ^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$ && "${value}" != *.git ]] || {
                    bta_err "BORINGTUN_REPOSITORY must be an https://github.com/<owner>/<repo> URL without .git"
                    return 1
                }
                BTA_REPOSITORY="${value}"
                ;;
            BORINGTUN_COMMIT)
                [[ "${value}" =~ ^[0-9a-f]{40}$ ]] || {
                    bta_err "BORINGTUN_COMMIT must be a full 40-character lowercase commit SHA"
                    return 1
                }
                BTA_COMMIT="${value}"
                ;;
            BORINGTUN_VERSION)
                [[ "${value}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
                    bta_err "BORINGTUN_VERSION must be MAJOR.MINOR.PATCH"
                    return 1
                }
                BTA_VERSION="${value}"
                ;;
            BORINGTUN_RUST_TOOLCHAIN)
                [[ "${value}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
                    bta_err "BORINGTUN_RUST_TOOLCHAIN must be an exact Rust release such as 1.98.1"
                    return 1
                }
                BTA_RUST_TOOLCHAIN="${value}"
                ;;
            BORINGTUN_ARTIFACT_FORMAT)
                [[ "${value}" =~ ^[1-9][0-9]*$ ]] || {
                    bta_err "BORINGTUN_ARTIFACT_FORMAT must be a positive integer"
                    return 1
                }
                BTA_ARTIFACT_FORMAT="${value}"
                ;;
            *)
                bta_err "pin file line ${line_no} sets unknown key ${key}"
                return 1
                ;;
        esac
    done <"${file}"
    for key in BORINGTUN_REPOSITORY BORINGTUN_COMMIT BORINGTUN_VERSION BORINGTUN_RUST_TOOLCHAIN BORINGTUN_ARTIFACT_FORMAT; do
        if [[ -z "${seen[${key}]:-}" ]]; then
            bta_err "pin file does not define ${key}"
            return 1
        fi
    done
}

bta_print_pin() {
    printf 'BORINGTUN_REPOSITORY=%s\n' "${BTA_REPOSITORY}"
    printf 'BORINGTUN_COMMIT=%s\n' "${BTA_COMMIT}"
    printf 'BORINGTUN_VERSION=%s\n' "${BTA_VERSION}"
    printf 'BORINGTUN_RUST_TOOLCHAIN=%s\n' "${BTA_RUST_TOOLCHAIN}"
    printf 'BORINGTUN_ARTIFACT_FORMAT=%s\n' "${BTA_ARTIFACT_FORMAT}"
}

# Print the architecture of a supported target triple.
bta_target_arch() {
    local target="$1" supported
    for supported in ${BTA_SUPPORTED_TARGETS}; do
        if [[ "${target}" == "${supported}" ]]; then
            printf '%s\n' "${target%%-*}"
            return 0
        fi
    done
    bta_err "unsupported target '${target}' (supported: ${BTA_SUPPORTED_TARGETS})"
    return 1
}

bta_archive_stem() {
    local arch="$1"
    printf '%s-%s-g%s-linux-%s-musl\n' "${BTA_PACKAGE}" "${BTA_VERSION}" "${BTA_COMMIT:0:12}" "${arch}"
}

# Refuse a source tree that is not exactly the pinned commit: wrong HEAD, local
# changes (including untracked files that git does not ignore), or a missing
# file the build and the package depend on.
bta_verify_source() {
    local source_dir="$1"
    local head version file

    if [[ ! -d "${source_dir}" ]]; then
        bta_err "BoringTun source directory not found: ${source_dir}"
        return 1
    fi
    if ! head="$(git -C "${source_dir}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)"; then
        bta_err "BoringTun source is not a git checkout: ${source_dir}"
        return 1
    fi
    if [[ "${head}" != "${BTA_COMMIT}" ]]; then
        bta_err "BoringTun source HEAD ${head} does not match the pinned commit ${BTA_COMMIT}"
        return 1
    fi
    if [[ -n "$(git -C "${source_dir}" status --porcelain 2>/dev/null)" ]] || \
        ! git -C "${source_dir}" diff --quiet HEAD -- 2>/dev/null; then
        bta_err "BoringTun source has local changes; build only a pristine checkout of ${BTA_COMMIT}"
        return 1
    fi
    for file in Cargo.toml Cargo.lock LICENSE.md boringtun-cli/Cargo.toml; do
        if ! git -C "${source_dir}" ls-files --error-unmatch -- "${file}" >/dev/null 2>&1; then
            bta_err "BoringTun source does not track ${file} at the pinned commit"
            return 1
        fi
    done
    version="$(awk '
        /^\[/ { in_package = ($0 == "[package]") }
        in_package && /^version[[:space:]]*=/ { gsub(/.*=[[:space:]]*"|".*/, ""); print; exit }
    ' "${source_dir}/boringtun-cli/Cargo.toml")"
    if [[ "${version}" != "${BTA_VERSION}" ]]; then
        bta_err "boringtun-cli/Cargo.toml declares version '${version}', but the pin expects ${BTA_VERSION}"
        return 1
    fi
}

bta_abs_dir() {
    CDPATH='' cd -- "$1" && pwd -P
}

# Cargo reads configuration from the source directory, every parent directory
# and CARGO_HOME. Only configuration tracked in the pinned source may exist: it
# is part of the reviewed build definition. Anything else would change the
# build without appearing in the pin, so it is refused.
bta_check_no_cargo_config() {
    local source_abs="$1" cargo_home="$2" dir candidate

    for candidate in "${source_abs}/.cargo/config" "${source_abs}/.cargo/config.toml"; do
        if [[ -e "${candidate}" ]] && ! git -C "${source_abs}" ls-files --error-unmatch -- \
            "${candidate#"${source_abs}"/}" >/dev/null 2>&1; then
            bta_err "untracked Cargo configuration in the source would change the build: ${candidate}"
            return 1
        fi
    done
    dir="$(dirname -- "${source_abs}")"
    while :; do
        for candidate in "${dir}/.cargo/config" "${dir}/.cargo/config.toml"; do
            if [[ -e "${candidate}" ]]; then
                bta_err "ambient Cargo configuration would change the build: ${candidate}"
                return 1
            fi
        done
        [[ "${dir}" == "/" ]] && break
        dir="$(dirname -- "${dir}")"
    done
    for candidate in "${cargo_home}/config" "${cargo_home}/config.toml"; do
        if [[ -e "${candidate}" ]]; then
            bta_err "ambient Cargo configuration would change the build: ${candidate}"
            return 1
        fi
    done
}

# Run a toolchain command with only the environment the build is defined by, so
# RUSTFLAGS, CC, CFLAGS, CARGO_* or locale settings of the caller cannot leak in.
bta_toolchain_env() {
    env -i \
        PATH="${PATH}" \
        HOME="${HOME}" \
        CARGO_HOME="${BTA_CARGO_HOME}" \
        RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}" \
        RUSTUP_TOOLCHAIN="${BTA_RUST_TOOLCHAIN}" \
        LC_ALL=C \
        TZ=UTC \
        "$@"
}

# Require the exact pinned toolchain and print its version lines.
bta_check_toolchain() {
    local rustc_version cargo_version

    if ! rustc_version="$(bta_toolchain_env rustc --version 2>/dev/null)" || \
        [[ "${rustc_version}" != "rustc ${BTA_RUST_TOOLCHAIN} "* ]]; then
        bta_err "rustc ${BTA_RUST_TOOLCHAIN} is required (found: ${rustc_version:-none}); install it with rustup"
        return 1
    fi
    if ! cargo_version="$(bta_toolchain_env cargo --version 2>/dev/null)" || \
        [[ "${cargo_version}" != "cargo ${BTA_RUST_TOOLCHAIN} "* ]]; then
        bta_err "cargo ${BTA_RUST_TOOLCHAIN} is required (found: ${cargo_version:-none})"
        return 1
    fi
    BTA_RUSTC_VERSION="${rustc_version}"
    BTA_CARGO_VERSION="${cargo_version}"
}

# The ELF machine name readelf prints for each supported architecture.
bta_elf_machine() {
    case "$1" in
        x86_64) printf '%s\n' "Advanced Micro Devices X86-64" ;;
        aarch64) printf '%s\n' "AArch64" ;;
        *) return 1 ;;
    esac
}

# Check that a binary is a static executable for the target's architecture and
# that it is the pinned boringtun-cli with its device (TUN/UAPI) interface.
bta_verify_binary() {
    local binary="$1" target="$2"
    local arch machine header output

    arch="$(bta_target_arch "${target}")" || return 1
    machine="$(bta_elf_machine "${arch}")" || return 1
    if [[ ! -f "${binary}" || -L "${binary}" || ! -x "${binary}" ]]; then
        bta_err "boringtun-cli binary is missing or not an executable regular file: ${binary}"
        return 1
    fi
    if ! header="$(LC_ALL=C readelf -hW -- "${binary}" 2>/dev/null)"; then
        bta_err "${binary} is not an ELF file"
        return 1
    fi
    if ! grep -Eq '^[[:space:]]*Class:[[:space:]]+ELF64$' <<<"${header}" || \
        ! grep -Eq "^[[:space:]]*Machine:[[:space:]]+${machine}\$" <<<"${header}"; then
        bta_err "${binary} is not a 64-bit ${arch} ELF executable"
        return 1
    fi
    if LC_ALL=C readelf -lW -- "${binary}" 2>/dev/null | grep -q 'INTERP'; then
        bta_err "${binary} is dynamically linked: it requests a program interpreter"
        return 1
    fi
    if LC_ALL=C readelf -dW -- "${binary}" 2>/dev/null | grep -q '(NEEDED)'; then
        bta_err "${binary} depends on shared libraries"
        return 1
    fi
    output="$("${binary}" --version 2>&1)" || true
    if [[ "${output}" != "boringtun ${BTA_VERSION}" ]]; then
        bta_err "${binary} --version printed '${output}', expected 'boringtun ${BTA_VERSION}'"
        return 1
    fi
    if ! output="$("${binary}" --help 2>&1)" || [[ "${output}" != *"Usage: boringtun-cli "* ]] || \
        [[ "${output}" != *"--uapi-fd"* || "${output}" != *"--tun-fd"* ]]; then
        bta_err "${binary} --help did not show the boringtun-cli device interface"
        return 1
    fi
}

# Build boringtun-cli for a native target into a new build directory. The
# directory receives the binary, a BUILD-INFO record and Cargo's own target
# directory; nothing is written anywhere else.
bta_build() {
    local source_dir="$1" target="$2" build_dir="$3"
    local arch host_arch source_abs build_abs lock_before epoch binary leak_path remap_config
    local build_command="cargo build --release --locked -p ${BTA_PACKAGE} --bin ${BTA_PACKAGE} --target ${target}"

    arch="$(bta_target_arch "${target}")" || return 1
    host_arch="$(uname -m)"
    if [[ "${host_arch}" != "${arch}" ]]; then
        bta_err "only native builds are supported: target ${target} needs an ${arch} host, this is ${host_arch}"
        return 1
    fi
    bta_verify_source "${source_dir}" || return 1
    source_abs="$(bta_abs_dir "${source_dir}")" || return 1
    BTA_CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
    if [[ "${BTA_CARGO_HOME}" != /* ]]; then
        bta_err "CARGO_HOME must be an absolute path"
        return 1
    fi
    bta_check_no_cargo_config "${source_abs}" "${BTA_CARGO_HOME}" || return 1
    bta_check_toolchain || return 1
    if [[ -e "${build_dir}" && ( ! -d "${build_dir}" || -n "$(ls -A -- "${build_dir}")" ) ]]; then
        bta_err "build directory must be new or empty: ${build_dir}"
        return 1
    fi
    mkdir -p -- "${build_dir}" || return 1
    build_abs="$(bta_abs_dir "${build_dir}")" || return 1
    case "${build_abs}/" in
        "${source_abs}/"*)
            bta_err "build directory must be outside the BoringTun source tree"
            return 1
            ;;
    esac

    # Remap the local source and Cargo home paths out of the binary. Passed with
    # --config so that Cargo joins it to any rustflags the pinned source defines
    # for this target, rather than replacing them as RUSTFLAGS would. The paths
    # are embedded in a TOML string, so quotes, backslashes and control
    # characters are refused.
    for leak_path in "${source_abs}" "${BTA_CARGO_HOME}"; do
        case "${leak_path}" in
            *'"'* | *\\* | *"'"* | *[[:cntrl:]]*)
                bta_err "unsupported character in build path: ${leak_path}"
                return 1
                ;;
        esac
    done
    remap_config="target.${target}.rustflags=[\"--remap-path-prefix=${source_abs}=/boringtun\", \"--remap-path-prefix=${BTA_CARGO_HOME}=/cargo\"]"

    lock_before="$(bta_sha256 "${source_abs}/Cargo.lock")"
    epoch="$(git -C "${source_abs}" show -s --format=%ct HEAD)"
    bta_info "building ${BTA_PACKAGE} ${BTA_VERSION} at ${BTA_COMMIT} for ${target} with ${BTA_RUSTC_VERSION}"
    if ! (cd "${source_abs}" && bta_toolchain_env \
        CARGO_TARGET_DIR="${build_abs}/cargo-target" \
        CARGO_PROFILE_RELEASE_STRIP=symbols \
        SOURCE_DATE_EPOCH="${epoch}" \
        cargo build --release --locked -p "${BTA_PACKAGE}" --bin "${BTA_PACKAGE}" --target "${target}" \
            --config "${remap_config}"); then
        bta_err "cargo build failed"
        return 1
    fi
    if [[ "$(bta_sha256 "${source_abs}/Cargo.lock")" != "${lock_before}" ]]; then
        bta_err "the build changed Cargo.lock"
        return 1
    fi
    bta_verify_source "${source_abs}" || return 1

    binary="${build_abs}/cargo-target/${target}/release/${BTA_PACKAGE}"
    if [[ ! -f "${binary}" || -L "${binary}" ]]; then
        bta_err "cargo did not produce ${binary}"
        return 1
    fi
    install -m 0755 -- "${binary}" "${build_abs}/${BTA_PACKAGE}" || return 1
    for leak_path in "${source_abs}" "${BTA_CARGO_HOME}" "${build_abs}"; do
        if grep -aqF -- "${leak_path}" "${build_abs}/${BTA_PACKAGE}"; then
            bta_err "the binary embeds the local path ${leak_path}; the build would not reproduce elsewhere"
            return 1
        fi
    done
    bta_verify_binary "${build_abs}/${BTA_PACKAGE}" "${target}" || return 1

    {
        printf 'target=%s\n' "${target}"
        printf 'rustc=%s\n' "${BTA_RUSTC_VERSION}"
        printf 'cargo=%s\n' "${BTA_CARGO_VERSION}"
        printf 'source_date_epoch=%s\n' "${epoch}"
        printf 'build_command=%s\n' "${build_command}"
        printf 'binary_sha256=%s\n' "$(bta_sha256 "${build_abs}/${BTA_PACKAGE}")"
    } >"${build_abs}/BUILD-INFO"
    bta_info "built ${build_abs}/${BTA_PACKAGE}"
}

# Gate the dependency graph with cargo-deny (advisories, bans, licenses and
# sources) and generate THIRD-PARTY-LICENSES with cargo-about, offline and
# deterministic for a given pin. Fails when a crate linked into the binary ships
# an Apache-2.0 NOTICE file, whose contents this file does not reproduce yet.
bta_licenses() {
    local source_dir="$1" output="$2"
    local source_abs output_abs lock_before crates line name version manifest notice tool
    local -a crate_lines=()

    bta_verify_source "${source_dir}" || return 1
    source_abs="$(bta_abs_dir "${source_dir}")" || return 1
    BTA_CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
    bta_check_no_cargo_config "${source_abs}" "${BTA_CARGO_HOME}" || return 1
    bta_check_toolchain || return 1
    for tool in cargo-deny cargo-about; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            bta_err "${tool} is required (see docs/BORINGTUN_ARTIFACTS.md for the pinned version)"
            return 1
        fi
    done
    if [[ ! -d "$(dirname -- "${output}")" || -e "${output}" ]]; then
        bta_err "output must be a new file in an existing directory: ${output}"
        return 1
    fi
    output_abs="$(bta_abs_dir "$(dirname -- "${output}")")/$(basename -- "${output}")"
    crates="${output_abs}.crates"
    lock_before="$(bta_sha256 "${source_abs}/Cargo.lock")"

    bta_info "checking the boringtun-cli dependency graph with cargo-deny"
    if ! (cd "${source_abs}" && bta_toolchain_env cargo fetch --locked) || \
        ! (cd "${source_abs}" && bta_toolchain_env cargo deny --locked \
            --manifest-path boringtun-cli/Cargo.toml --config "${BTA_CONFIG_DIR}/deny.toml" \
            check advisories bans licenses sources); then
        bta_err "the dependency graph failed the cargo-deny policy in packaging/boringtun/deny.toml"
        return 1
    fi
    bta_info "generating THIRD-PARTY-LICENSES with cargo-about"
    if ! (cd "${source_abs}" && bta_toolchain_env cargo about generate --frozen --fail \
            --manifest-path boringtun-cli/Cargo.toml -c "${BTA_CONFIG_DIR}/about.toml" \
            "${BTA_CONFIG_DIR}/about.hbs" -o "${output_abs}.tmp") || \
        ! (cd "${source_abs}" && bta_toolchain_env cargo about generate --frozen --fail \
            --manifest-path boringtun-cli/Cargo.toml -c "${BTA_CONFIG_DIR}/about.toml" \
            "${BTA_CONFIG_DIR}/about-crates.hbs" -o "${crates}"); then
        rm -f -- "${output_abs}.tmp" "${crates}"
        bta_err "cargo-about could not attribute every crate to an accepted license"
        return 1
    fi
    mapfile -t crate_lines <"${crates}"
    rm -f -- "${crates}"
    for line in "${crate_lines[@]}"; do
        read -r name version manifest <<<"${line}"
        [[ -n "${name}" ]] || continue
        notice="$(find "$(dirname -- "${manifest}")" -maxdepth 1 -type f -iname 'NOTICE*' -print -quit 2>/dev/null)"
        if [[ -n "${notice}" ]]; then
            rm -f -- "${output_abs}.tmp"
            bta_err "${name} ${version} ships ${notice##*/}; Apache-2.0 requires reproducing it, which THIRD-PARTY-LICENSES does not do yet"
            return 1
        fi
    done
    if [[ "$(bta_sha256 "${source_abs}/Cargo.lock")" != "${lock_before}" ]]; then
        rm -f -- "${output_abs}.tmp"
        bta_err "license generation changed Cargo.lock"
        return 1
    fi
    bta_verify_source "${source_abs}" || return 1
    if ! grep -q '^THIRD-PARTY LICENSES FOR boringtun-cli$' "${output_abs}.tmp" || \
        ! grep -q '^  ring ' "${output_abs}.tmp"; then
        rm -f -- "${output_abs}.tmp"
        bta_err "generated THIRD-PARTY-LICENSES is incomplete"
        return 1
    fi
    mv -- "${output_abs}.tmp" "${output_abs}"
    bta_info "wrote ${output_abs}"
}

# Read a KEY=VALUE file into the associative array named by $2, requiring
# exactly the keys listed in $3, each once.
bta_read_kv() {
    local file="$1" expected="$3" line key line_no=0
    local -n kv_ref="$2"

    kv_ref=()
    if [[ ! -f "${file}" || -L "${file}" ]]; then
        bta_err "missing ${file}"
        return 1
    fi
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line_no=$((line_no + 1))
        # The file may come from an untrusted archive: report where, never what.
        if [[ ! "${line}" =~ ^([a-z0-9_]+)=([^[:cntrl:]]+)$ ]]; then
            bta_err "${file}: line ${line_no} is not a key=value line"
            return 1
        fi
        key="${BASH_REMATCH[1]}"
        if [[ " ${expected} " != *" ${key} "* || -n "${kv_ref[${key}]+set}" ]]; then
            bta_err "${file}: unexpected or repeated key ${key}"
            return 1
        fi
        kv_ref["${key}"]="${BASH_REMATCH[2]}"
    done <"${file}"
    for key in ${expected}; do
        if [[ -z "${kv_ref[${key}]+set}" ]]; then
            bta_err "${file}: missing key ${key}"
            return 1
        fi
    done
}

bta_write_manifest() {
    local -n info_ref="$1"
    local arch="$2"

    printf 'artifact_format=%s\n' "${BTA_ARTIFACT_FORMAT}"
    printf 'name=%s\n' "${BTA_PACKAGE}"
    printf 'version=%s\n' "${BTA_VERSION}"
    printf 'source_repository=%s\n' "${BTA_REPOSITORY}"
    printf 'source_commit=%s\n' "${BTA_COMMIT}"
    printf 'source_date_epoch=%s\n' "${info_ref[source_date_epoch]}"
    printf 'target=%s\n' "${info_ref[target]}"
    printf 'os=linux\n'
    printf 'arch=%s\n' "${arch}"
    printf 'libc=musl\n'
    printf 'linkage=static\n'
    printf 'rust_toolchain=%s\n' "${BTA_RUST_TOOLCHAIN}"
    printf 'rustc=%s\n' "${info_ref[rustc]}"
    printf 'cargo=%s\n' "${info_ref[cargo]}"
    printf 'build_command=%s\n' "${info_ref[build_command]}"
    printf 'build_profile=%s\n' "${BTA_BUILD_PROFILE}"
    printf 'rustflags=%s\n' "${BTA_RUSTFLAGS_RECORD}"
    printf 'binary=%s\n' "${BTA_PACKAGE}"
    printf 'binary_sha256=%s\n' "${info_ref[binary_sha256]}"
    printf 'license=LICENSE (BSD-3-Clause)\n'
    printf 'third_party_licenses=THIRD-PARTY-LICENSES\n'
}

# Create boringtun-cli-<version>-g<commit12>-linux-<arch>-musl.tar.gz from a
# build directory. The archive depends only on its inputs: members in name
# order under one top-level directory, fixed modes, owner 0:0, the commit time
# as mtime and gzip without a name or timestamp. Prints the archive path.
bta_package() {
    local build_dir="$1" source_dir="$2" third_party="$3" out_dir="$4"
    local -A info=()
    local arch stem archive stage rc=0

    bta_verify_source "${source_dir}" || return 1
    bta_read_kv "${build_dir}/BUILD-INFO" info \
        "target rustc cargo source_date_epoch build_command binary_sha256" || return 1
    arch="$(bta_target_arch "${info[target]}")" || return 1
    if [[ "${info[source_date_epoch]}" != "$(git -C "${source_dir}" show -s --format=%ct HEAD)" ]]; then
        bta_err "BUILD-INFO was not produced from the pinned source"
        return 1
    fi
    if [[ ! -f "${build_dir}/${BTA_PACKAGE}" || -L "${build_dir}/${BTA_PACKAGE}" ]] || \
        [[ "$(bta_sha256 "${build_dir}/${BTA_PACKAGE}")" != "${info[binary_sha256]}" ]]; then
        bta_err "${build_dir}/${BTA_PACKAGE} is missing or differs from the binary recorded in BUILD-INFO"
        return 1
    fi
    if [[ ! -s "${source_dir}/LICENSE.md" ]]; then
        bta_err "the BoringTun source has no LICENSE.md"
        return 1
    fi
    if [[ ! -f "${third_party}" || -L "${third_party}" || ! -s "${third_party}" ]]; then
        bta_err "THIRD-PARTY-LICENSES file is missing or empty: ${third_party}"
        return 1
    fi
    if [[ ! -d "${out_dir}" ]]; then
        bta_err "output directory does not exist: ${out_dir}"
        return 1
    fi
    stem="$(bta_archive_stem "${arch}")"
    archive="${out_dir}/${stem}.tar.gz"
    if [[ -e "${archive}" ]]; then
        bta_err "refusing to overwrite ${archive}"
        return 1
    fi

    stage="$(mktemp -d "${out_dir}/.package.XXXXXX")" || return 1
    {
        install -d -m 0755 -- "${stage}/${stem}" &&
            install -m 0755 -- "${build_dir}/${BTA_PACKAGE}" "${stage}/${stem}/${BTA_PACKAGE}" &&
            install -m 0644 -- "${source_dir}/LICENSE.md" "${stage}/${stem}/LICENSE" &&
            install -m 0644 -- "${third_party}" "${stage}/${stem}/THIRD-PARTY-LICENSES" &&
            bta_write_manifest info "${arch}" >"${stage}/${stem}/MANIFEST" &&
            chmod 0644 -- "${stage}/${stem}/MANIFEST" &&
            (cd "${stage}" && LC_ALL=C tar --sort=name --format=ustar --owner=0 --group=0 \
                --numeric-owner --mtime="@${info[source_date_epoch]}" -cf archive.tar -- "${stem}") &&
            gzip -9 -n -c -- "${stage}/archive.tar" >"${stage}/archive.tar.gz" &&
            mv -- "${stage}/archive.tar.gz" "${archive}"
    } || rc=1
    rm -rf -- "${stage}"
    if (( rc != 0 )); then
        bta_err "could not create ${archive}"
        return 1
    fi
    printf '%s\n' "${archive}"
}

# Check an archive against the pin without trusting its contents: the name,
# the exact member list, member types, modes and owners, then extract into a
# new directory and check the manifest, the license files and the binary.
# Prints the path of the extracted binary.
bta_verify_archive() {
    local archive="$1" extract_dir="$2"
    local name stem arch expected listing line mode path binary
    local -A manifest=()

    name="$(basename -- "${archive}")"
    if [[ ! "${name}" =~ ^boringtun-cli-([0-9]+\.[0-9]+\.[0-9]+)-g([0-9a-f]{12})-linux-(x86_64|aarch64)-musl\.tar\.gz$ ]]; then
        bta_err "unexpected artifact name: ${name}"
        return 1
    fi
    arch="${BASH_REMATCH[3]}"
    stem="$(bta_archive_stem "${arch}")"
    if [[ "${name}" != "${stem}.tar.gz" ]]; then
        bta_err "${name} is not the artifact of the pinned version and commit (${stem}.tar.gz)"
        return 1
    fi
    if [[ ! -f "${archive}" || -L "${archive}" ]]; then
        bta_err "archive is missing or not a regular file: ${archive}"
        return 1
    fi
    expected="$(printf '%s\n' "${stem}/" "${stem}/LICENSE" "${stem}/MANIFEST" \
        "${stem}/THIRD-PARTY-LICENSES" "${stem}/${BTA_PACKAGE}")"
    if ! listing="$(LC_ALL=C tar -tzf "${archive}" 2>/dev/null)" || \
        [[ "$(LC_ALL=C sort <<<"${listing}")" != "${expected}" ]]; then
        bta_err "${name} does not contain exactly the expected members"
        return 1
    fi
    while IFS= read -r line; do
        read -r mode _ _ _ _ path <<<"${line}"
        case "${path}" in
            "${stem}/") [[ "${mode}" == "drwxr-xr-x" ]] ;;
            "${stem}/${BTA_PACKAGE}") [[ "${mode}" == "-rwxr-xr-x" ]] ;;
            *) [[ "${mode}" == "-rw-r--r--" ]] ;;
        esac || {
            bta_err "${name}: ${path} has type/mode ${mode}"
            return 1
        }
        [[ "${line}" == *" 0/0 "* ]] || {
            bta_err "${name}: ${path} is not owned by 0/0"
            return 1
        }
    done < <(LC_ALL=C tar --numeric-owner -tvzf "${archive}")

    if [[ -e "${extract_dir}" && ( ! -d "${extract_dir}" || -n "$(ls -A -- "${extract_dir}")" ) ]]; then
        bta_err "extraction directory must be new or empty: ${extract_dir}"
        return 1
    fi
    mkdir -p -- "${extract_dir}" || return 1
    if ! tar -xzf "${archive}" -C "${extract_dir}" --no-same-owner; then
        bta_err "could not extract ${name}"
        return 1
    fi
    binary="${extract_dir}/${stem}/${BTA_PACKAGE}"
    bta_read_kv "${extract_dir}/${stem}/MANIFEST" manifest "${BTA_MANIFEST_KEYS}" || return 1
    if [[ "${manifest[artifact_format]}" != "${BTA_ARTIFACT_FORMAT}" || \
        "${manifest[name]}" != "${BTA_PACKAGE}" || \
        "${manifest[version]}" != "${BTA_VERSION}" || \
        "${manifest[source_repository]}" != "${BTA_REPOSITORY}" || \
        "${manifest[source_commit]}" != "${BTA_COMMIT}" || \
        "${manifest[target]}" != "${arch}-unknown-linux-musl" || \
        "${manifest[arch]}" != "${arch}" || "${manifest[os]}" != "linux" || \
        "${manifest[libc]}" != "musl" || "${manifest[linkage]}" != "static" || \
        "${manifest[rust_toolchain]}" != "${BTA_RUST_TOOLCHAIN}" || \
        "${manifest[binary]}" != "${BTA_PACKAGE}" ]]; then
        bta_err "${name}: MANIFEST does not describe the pinned artifact"
        return 1
    fi
    if [[ "${manifest[binary_sha256]}" != "$(bta_sha256 "${binary}")" ]]; then
        bta_err "${name}: boringtun-cli does not match binary_sha256 in MANIFEST"
        return 1
    fi
    if ! grep -q 'Redistribution and use in source and binary forms' "${extract_dir}/${stem}/LICENSE" || \
        ! grep -q '^THIRD-PARTY LICENSES FOR boringtun-cli$' "${extract_dir}/${stem}/THIRD-PARTY-LICENSES"; then
        bta_err "${name}: LICENSE or THIRD-PARTY-LICENSES is not the expected notice"
        return 1
    fi
    bta_verify_binary "${binary}" "${manifest[target]}" || return 1
    printf '%s\n' "${binary}"
}

# As root: start the binary in the foreground on a fresh TUN device, require the
# device to appear and the UAPI socket to answer `get=1` with errno=0, then stop
# it and require the device to disappear. This exercises the device feature,
# which --version and --help cannot.
bta_device_smoke() {
    local binary="$1"
    local name sock log pid response rc=0 i

    if [[ "$(id -u)" -ne 0 ]]; then
        bta_err "the device smoke test must run as root: it creates a TUN device"
        return 1
    fi
    if [[ ! -c /dev/net/tun ]]; then
        bta_err "/dev/net/tun is not available"
        return 1
    fi
    for i in ip python3; do
        command -v "${i}" >/dev/null 2>&1 || {
            bta_err "${i} is required for the device smoke test"
            return 1
        }
    done
    if [[ ! -f "${binary}" || ! -x "${binary}" ]]; then
        bta_err "not an executable file: ${binary}"
        return 1
    fi
    name="btsmk$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
    sock="/var/run/wireguard/${name}.sock"
    if ip link show dev "${name}" >/dev/null 2>&1 || [[ -e "${sock}" ]]; then
        bta_err "interface or socket ${name} already exists"
        return 1
    fi
    log="$(mktemp)" || return 1
    "${binary}" --foreground --disable-drop-privileges "${name}" >"${log}" 2>&1 &
    pid=$!
    for ((i = 0; i < 50; i++)); do
        [[ -S "${sock}" ]] && ip link show dev "${name}" >/dev/null 2>&1 && break
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.2
    done
    if ! ip -details link show dev "${name}" 2>/dev/null | grep -qw tun; then
        bta_err "boringtun-cli did not create the TUN device ${name}"
        rc=1
    elif ! response="$(python3 - "${sock}" <<'PY'
import socket
import sys

conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
conn.settimeout(5)
conn.connect(sys.argv[1])
conn.sendall(b"get=1\n\n")
data = b""
while not data.endswith(b"\n\n"):
    chunk = conn.recv(4096)
    if not chunk:
        break
    data += chunk
sys.stdout.write(data.decode())
PY
)" || ! grep -qx 'errno=0' <<<"${response}"; then
        bta_err "the UAPI socket did not answer get=1 with errno=0"
        rc=1
    fi
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    for ((i = 0; i < 25; i++)); do
        ip link show dev "${name}" >/dev/null 2>&1 || break
        sleep 0.2
    done
    if ip link show dev "${name}" >/dev/null 2>&1; then
        bta_err "the TUN device ${name} outlived its daemon"
        ip link delete dev "${name}" >/dev/null 2>&1 || true
        rc=1
    fi
    rm -f -- "${sock}"
    if (( rc != 0 )); then
        sed 's/^/    boringtun-cli: /' "${log}" >&2
    else
        bta_info "device smoke test passed: TUN ${name} created, UAPI answered errno=0, device removed on exit"
    fi
    rm -f -- "${log}"
    return "${rc}"
}

# Write SHA256SUMS for every artifact archive in a directory, sorted by name.
bta_checksums() {
    local dir="$1" name
    local -a archives=()

    if [[ ! -d "${dir}" ]]; then
        bta_err "not a directory: ${dir}"
        return 1
    fi
    mapfile -t archives < <(find "${dir}" -maxdepth 1 -type f -name 'boringtun-cli-*.tar.gz' -printf '%f\n' | LC_ALL=C sort)
    if (( ${#archives[@]} == 0 )); then
        bta_err "no boringtun-cli archives in ${dir}"
        return 1
    fi
    for name in "${archives[@]}"; do
        if [[ ! "${name}" =~ ^boringtun-cli-[0-9]+\.[0-9]+\.[0-9]+-g[0-9a-f]{12}-linux-(x86_64|aarch64)-musl\.tar\.gz$ ]]; then
            bta_err "unexpected file name in ${dir}: ${name}"
            return 1
        fi
    done
    (cd "${dir}" && sha256sum -- "${archives[@]}") >"${dir}/SHA256SUMS.tmp" &&
        mv -- "${dir}/SHA256SUMS.tmp" "${dir}/SHA256SUMS" &&
        (cd "${dir}" && sha256sum --quiet -c SHA256SUMS)
}

bta_usage() {
    sed -n '/^# Commands:/,/^# BORINGTUN_PIN_FILE/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

bta_main() {
    local command="${1:-}"

    [[ $# -gt 0 ]] && shift
    bta_read_pin || return 1
    case "${command}:$#" in
        pin:0) bta_print_pin ;;
        build:3) bta_build "$@" ;;
        licenses:2) bta_licenses "$@" ;;
        package:4) bta_package "$@" ;;
        verify-archive:2) bta_verify_archive "$@" ;;
        device-smoke:1) bta_device_smoke "$@" ;;
        checksums:1) bta_checksums "$@" ;;
        *)
            bta_usage
            return 2
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    set -uo pipefail
    umask 022
    bta_main "$@"
    exit $?
fi
