#!/usr/bin/env bash
# Unit tests for the shared low-resource Cargo build helper.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
BUILD_HELPER="${PROJECT_ROOT}/scripts/amneziawg-cargo-build.sh"

TESTS_RUN=0
TESTS_FAILED=0

load_build_helper() {
    # shellcheck source=../scripts/amneziawg-cargo-build.sh
    source "${BUILD_HELPER}"
}

run_test() {
    local name="$1"
    local rc
    shift
    TESTS_RUN=$((TESTS_RUN + 1))
    (set -e; "$@")
    rc=$?
    if [[ "${rc}" -eq 0 ]]; then
        printf '  OK: %s\n' "${name}"
    else
        printf 'FAIL: %s\n' "${name}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

test_constrained_classification() {
    load_build_helper
    awg_build_is_constrained 1 8388608 2097152
    awg_build_is_constrained 4 1048576 2097152
    ! awg_build_is_constrained 4 8388608 2097152
}

test_cgroup_memory_caps_host_estimate() {
    load_build_helper
    _awg_build_proc_available_memory_kb() { printf '16777216\n'; }
    _awg_build_cgroup_available_memory_kb() { printf '1048576\n'; }

    local available_memory
    available_memory="$(_awg_build_available_memory_kb)"
    [[ "${available_memory}" == "1048576" ]]
    awg_build_is_constrained 4 "${available_memory}" 2097152
}

test_zero_proc_memory_is_constrained() {
    load_build_helper
    _awg_build_proc_memory_available_kb() { printf '0\n'; }
    _awg_build_proc_swap_available_kb() { printf '0\n'; }

    local available_memory
    available_memory="$(_awg_build_proc_available_memory_kb)"
    [[ "${available_memory}" == "0" ]]
    awg_build_is_constrained 4 "${available_memory}" 2097152
}

test_cgroup_v2_remaining_memory() {
    load_build_helper
    local cgroup_dir
    _awg_build_proc_memory_available_kb() { printf '16777216\n'; }
    _awg_build_proc_swap_available_kb() { printf '16777216\n'; }
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
    cgroup_dir="${TEST_ROOT}/cgroup"
    mkdir -p "${cgroup_dir}"
    printf '1073741824\n' > "${cgroup_dir}/memory.max"
    printf '268435456\n' > "${cgroup_dir}/memory.current"
    printf '536870912\n' > "${cgroup_dir}/memory.swap.max"
    printf '134217728\n' > "${cgroup_dir}/memory.swap.current"

    [[ "$(_awg_build_cgroup_v2_available_memory_kb "${cgroup_dir}")" == "1179648" ]]

    # A child may report an effectively unlimited numeric value while a parent
    # cgroup imposes the actual cap. The parent headroom must still win.
    printf '9223372036854771712\n' > "${cgroup_dir}/memory.max"
    printf '536870912\n' > "${TEST_ROOT}/memory.max"
    printf '134217728\n' > "${TEST_ROOT}/memory.current"
    printf '268435456\n' > "${TEST_ROOT}/memory.swap.max"
    printf '67108864\n' > "${TEST_ROOT}/memory.swap.current"
    [[ "$(_awg_build_cgroup_v2_available_memory_kb "${cgroup_dir}")" == "589824" ]]

    # Memory and swap are hierarchical but independently limited. A parent can
    # impose the effective memory cap while its child imposes the swap cap.
    printf '4294967296\n' > "${cgroup_dir}/memory.max"
    printf '0\n' > "${cgroup_dir}/memory.current"
    printf '0\n' > "${cgroup_dir}/memory.swap.max"
    printf '0\n' > "${cgroup_dir}/memory.swap.current"
    printf '1073741824\n' > "${TEST_ROOT}/memory.max"
    printf '0\n' > "${TEST_ROOT}/memory.current"
    printf '3221225472\n' > "${TEST_ROOT}/memory.swap.max"
    printf '0\n' > "${TEST_ROOT}/memory.swap.current"
    [[ "$(_awg_build_cgroup_v2_available_memory_kb "${cgroup_dir}")" == "1048576" ]]
}

test_cgroup_v1_combined_mount_and_ancestor_limit() {
    load_build_helper
    local cgroup_file mountinfo_file mount_point mountinfo_mount_point cgroup_dir
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
    cgroup_file="${TEST_ROOT}/cgroup"
    mountinfo_file="${TEST_ROOT}/mountinfo"
    mount_point="${TEST_ROOT}/sys fs/cgroup/cpu,cpuacct,memory"
    mountinfo_mount_point="${mount_point// /\\040}"
    cgroup_dir="${mount_point}/workload/leaf"
    mkdir -p "${cgroup_dir}"

    printf '7:cpu,cpuacct,memory:/tenant/workload/leaf\n' > "${cgroup_file}"
    printf '36 29 0:32 /tenant %s rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,cpu,cpuacct,memory\n' \
        "${mountinfo_mount_point}" > "${mountinfo_file}"

    printf '4294967296\n' > "${cgroup_dir}/memory.limit_in_bytes"
    printf '0\n' > "${cgroup_dir}/memory.usage_in_bytes"
    printf '1073741824\n' > "${mount_point}/workload/memory.limit_in_bytes"
    printf '268435456\n' > "${mount_point}/workload/memory.usage_in_bytes"

    [[ "$(_awg_build_cgroup_v1_dir "${cgroup_file}" "${mountinfo_file}")" == "${cgroup_dir}" ]]
    [[ "$(_awg_build_cgroup_v1_available_memory_kb "${cgroup_dir}")" == "786432" ]]
}

test_candidate_resource_rejections() {
    load_build_helper
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT

    _awg_build_can_execute() { return 1; }
    ! _awg_build_check_candidate "${TEST_ROOT}" 1 1
    [[ "${_AWG_BUILD_LAST_REASON}" == *noexec* ]]

    _awg_build_can_execute() { return 0; }
    _awg_build_available_kb() { printf '512\n'; }
    _awg_build_available_inodes() { printf '10000\n'; }
    ! _awg_build_check_candidate "${TEST_ROOT}" 1024 1
    [[ "${_AWG_BUILD_LAST_REASON}" == *"MiB required"* ]]

    _awg_build_available_kb() { printf '4096\n'; }
    _awg_build_available_inodes() { printf '10\n'; }
    ! _awg_build_check_candidate "${TEST_ROOT}" 1024 100
    [[ "${_AWG_BUILD_LAST_REASON}" == *"inodes free"* ]]
}

test_normal_target_and_cleanup() {
    load_build_helper
    local source_dir expected_target created_tmp
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
    source_dir="${TEST_ROOT}/crate"
    mkdir -p "${source_dir}"
    unset CARGO_TARGET_DIR CARGO_BUILD_TARGET AMNEZIAWG_BUILD_ROOT
    CARGO_BUILD_JOBS=2
    export CARGO_BUILD_JOBS

    awg_prepare_cargo_build "${source_dir}" test-component 1 1 >/dev/null
    expected_target="$(CDPATH='' cd -- "${source_dir}/target" && pwd -P)"
    [[ "${AWG_CARGO_TARGET_DIR}" == "${expected_target}" ]]
    [[ "$(awg_cargo_release_binary test-bin)" == "${expected_target}/release/test-bin" ]]
    created_tmp="${AWG_CARGO_TMPDIR_CREATED}"
    [[ -d "${created_tmp}" ]]
    awg_cleanup_cargo_build
    [[ ! -e "${created_tmp}" ]]
    [[ -d "${expected_target}" ]]
}

test_external_target_fallback_and_cleanup() {
    load_build_helper
    local source_dir build_base owned_root
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
    source_dir="${TEST_ROOT}/small-source"
    build_base="${TEST_ROOT}/large-build-root"
    mkdir -p "${source_dir}" "${build_base}"
    source_dir="$(CDPATH='' cd -- "${source_dir}" && pwd -P)"
    unset CARGO_TARGET_DIR CARGO_BUILD_TARGET AMNEZIAWG_BUILD_ROOT
    TMPDIR="${build_base}"
    CARGO_BUILD_JOBS=2
    export TMPDIR CARGO_BUILD_JOBS

    _awg_build_check_candidate() {
        local candidate canonical
        candidate="$1"
        canonical="$(CDPATH='' cd -- "${candidate}" 2>/dev/null && pwd -P)" || canonical="${candidate}"
        if [[ "${canonical}" == "${source_dir}" || "${canonical}" == "${source_dir}/target" ]]; then
            _AWG_BUILD_LAST_REASON="simulated small filesystem"
            return 1
        fi
        _AWG_BUILD_CHECKED_DIR="${canonical}"
        _AWG_BUILD_CHECKED_FREE_KB=4194304
        _AWG_BUILD_CHECKED_FREE_INODES=100000
        _AWG_BUILD_LAST_REASON=""
        return 0
    }

    awg_prepare_cargo_build "${source_dir}" test-component 2097152 8192 >/dev/null 2>&1
    owned_root="${AWG_CARGO_BUILD_ROOT_CREATED}"
    [[ "${owned_root}" == "${build_base}"/amneziawg-build.* ]]
    [[ "${AWG_CARGO_TARGET_DIR}" == "${owned_root}/target" ]]
    [[ "$(awg_cargo_release_binary test-bin)" == "${owned_root}/target/release/test-bin" ]]
    awg_cleanup_cargo_build
    [[ ! -e "${owned_root}" ]]
    [[ -d "${source_dir}" ]]
}

test_explicit_build_root_wins() {
    load_build_helper
    local source_dir build_base owned_root
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
    source_dir="${TEST_ROOT}/source"
    build_base="${TEST_ROOT}/selected-build-root"
    mkdir -p "${source_dir}" "${build_base}"
    unset CARGO_TARGET_DIR CARGO_BUILD_TARGET TMPDIR
    AMNEZIAWG_BUILD_ROOT="${build_base}"
    CARGO_BUILD_JOBS=2
    export AMNEZIAWG_BUILD_ROOT CARGO_BUILD_JOBS

    awg_prepare_cargo_build "${source_dir}" test-component 1 1 >/dev/null
    owned_root="${AWG_CARGO_BUILD_ROOT_CREATED}"
    [[ "${owned_root}" == "${build_base}"/amneziawg-build.* ]]
    [[ "${AWG_CARGO_TARGET_DIR}" == "${owned_root}/target" ]]
    [[ ! -e "${source_dir}/target" ]]
    awg_cleanup_cargo_build
    [[ ! -e "${owned_root}" ]]
}

test_relative_explicit_target_is_preserved() {
    load_build_helper
    local source_dir expected_target created_tmp
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
    source_dir="${TEST_ROOT}/crate"
    mkdir -p "${source_dir}"
    CARGO_TARGET_DIR="custom-target"
    CARGO_BUILD_JOBS=3
    unset AMNEZIAWG_BUILD_ROOT CARGO_BUILD_TARGET
    export CARGO_TARGET_DIR CARGO_BUILD_JOBS

    awg_prepare_cargo_build "${source_dir}" test-component 1 1 >/dev/null
    expected_target="$(CDPATH='' cd -- "${source_dir}/custom-target" && pwd -P)"
    [[ "${AWG_CARGO_TARGET_DIR}" == "${expected_target}" ]]
    created_tmp="${AWG_CARGO_TMPDIR_CREATED}"
    awg_cleanup_cargo_build
    [[ ! -e "${created_tmp}" ]]
    [[ -d "${expected_target}" ]]
}

test_explicit_target_failure_does_not_fallback() {
    load_build_helper
    local source_dir
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
    source_dir="${TEST_ROOT}/crate"
    mkdir -p "${source_dir}"
    CARGO_TARGET_DIR="bad-target"
    export CARGO_TARGET_DIR
    _awg_build_check_candidate() {
        _AWG_BUILD_LAST_REASON="simulated insufficient space"
        return 1
    }
    ! awg_prepare_cargo_build "${source_dir}" test-component 100 1 >/dev/null 2>&1
    [[ -z "${AWG_CARGO_BUILD_ROOT_CREATED}" ]]
}

test_cross_target_release_path() {
    load_build_helper
    AWG_CARGO_TARGET_DIR="/build/target"
    CARGO_BUILD_TARGET="aarch64-unknown-linux-gnu"
    export CARGO_BUILD_TARGET
    [[ "$(awg_cargo_release_binary app)" == "/build/target/aarch64-unknown-linux-gnu/release/app" ]]

    CARGO_BUILD_TARGET="/targets/custom-device.json"
    [[ "$(awg_cargo_release_binary app)" == "/build/target/custom-device/release/app" ]]

    CARGO_BUILD_TARGET="targets/board.v1.json"
    [[ "$(awg_cargo_release_binary app)" == "/build/target/board.v1/release/app" ]]

    rustc() {
        printf 'rustc 1.93.0\nbinary: rustc\nhost: x86_64-unknown-linux-gnu\n'
    }
    CARGO_BUILD_TARGET="host-tuple"
    [[ "$(awg_cargo_release_binary app)" == "/build/target/x86_64-unknown-linux-gnu/release/app" ]]
}

test_constrained_defaults_and_operator_jobs() {
    load_build_helper
    _awg_build_cpu_count() { printf '1\n'; }
    _awg_build_available_memory_kb() { printf '4194304\n'; }
    rustc() { printf 'host: x86_64-unknown-linux-gnu\n'; }

    unset CARGO_BUILD_JOBS CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    _awg_build_configure_jobs_and_linker
    [[ "${CARGO_BUILD_JOBS}" == "1" ]]
    [[ -z "${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER+x}" ]]
    [[ "${AWG_CARGO_LINKER_POLICY}" == "Cargo configuration/default" ]]

    CARGO_BUILD_JOBS=5
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang
    _awg_build_configure_jobs_and_linker
    [[ "${CARGO_BUILD_JOBS}" == "5" ]]
    [[ "${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER}" == "clang" ]]
}

test_standalone_bootstraps_honor_build_root() {
    local launcher
    for launcher in \
        "${PROJECT_ROOT}/amneziawg-web.sh" \
        "${PROJECT_ROOT}/amneziawg-proxy.sh"; do
        grep -Fq 'bootstrap_roots+=("${AMNEZIAWG_BUILD_ROOT}")' "${launcher}" || return 1
    done
}

test_cleanup_rejects_unowned_names() {
    load_build_helper
    local keep_root keep_tmp
    TEST_ROOT="$(mktemp -d)"
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
    keep_root="${TEST_ROOT}/keep-build"
    keep_tmp="${TEST_ROOT}/keep-tmp"
    mkdir -p "${keep_root}" "${keep_tmp}"
    AWG_CARGO_BUILD_ROOT_CREATED="${keep_root}"
    AWG_CARGO_TMPDIR_CREATED="${keep_tmp}"
    awg_cleanup_cargo_build
    [[ -d "${keep_root}" && -d "${keep_tmp}" ]]
}

test_all_source_build_paths_use_helper() {
    local file
    for file in \
        "${PROJECT_ROOT}/amneziawg-web/scripts/amneziawg-web-install.sh" \
        "${PROJECT_ROOT}/amneziawg-web/scripts/amneziawg-web-upgrade.sh" \
        "${PROJECT_ROOT}/amneziawg-proxy/scripts/amneziawg-proxy-install.sh" \
        "${PROJECT_ROOT}/amneziawg-proxy/scripts/amneziawg-proxy-upgrade.sh"; do
        grep -q 'awg_prepare_cargo_build' "${file}" || return 1
        grep -q 'awg_cargo_release_binary' "${file}" || return 1
    done
}

echo "=== Shared Cargo build helper ==="
run_test "one CPU or low memory is constrained" test_constrained_classification
run_test "cgroup memory limits cap host-wide memory estimates" test_cgroup_memory_caps_host_estimate
run_test "zero proc memory remains a constrained reading" test_zero_proc_memory_is_constrained
run_test "cgroup v2 memory and swap hierarchy is calculated independently" test_cgroup_v2_remaining_memory
run_test "cgroup v1 combined mounts honor mount roots and ancestor limits" test_cgroup_v1_combined_mount_and_ancestor_limit
run_test "noexec, disk-space, and inode shortages are rejected" test_candidate_resource_rejections
run_test "normal crate target is retained and temp files are cleaned" test_normal_target_and_cleanup
run_test "small source filesystem falls back to an owned external target" test_external_target_fallback_and_cleanup
run_test "explicit build root takes precedence over the source filesystem" test_explicit_build_root_wins
run_test "relative explicit Cargo target is resolved and retained" test_relative_explicit_target_is_preserved
run_test "invalid explicit Cargo target fails without fallback" test_explicit_target_failure_does_not_fallback
run_test "triple, custom JSON, and host-tuple target release paths are resolved" test_cross_target_release_path
run_test "constrained defaults preserve Cargo linker configuration and overrides" test_constrained_defaults_and_operator_jobs
run_test "cleanup refuses paths it did not name" test_cleanup_rejects_unowned_names
run_test "all web and proxy source-build paths use the helper" test_all_source_build_paths_use_helper
run_test "standalone web and proxy bootstraps honor the explicit build root" test_standalone_bootstraps_honor_build_root

printf '\n%d tests, %d failures\n' "${TESTS_RUN}" "${TESTS_FAILED}"
[[ "${TESTS_FAILED}" -eq 0 ]]
