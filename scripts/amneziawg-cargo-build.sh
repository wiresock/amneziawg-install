#!/usr/bin/env bash
# Shared resource preparation for amneziawg-web and amneziawg-proxy builds.
#
# This file is sourced by the component install/upgrade scripts. Call
# awg_prepare_cargo_build after the Rust toolchain is available, then use
# awg_cargo_release_binary to locate the resulting binary.

AWG_CARGO_TARGET_DIR=""
AWG_CARGO_TMPDIR_CREATED=""
AWG_CARGO_BUILD_ROOT_CREATED=""
AWG_CARGO_TARGET_FREE_KB=""
AWG_CARGO_TARGET_FREE_INODES=""
AWG_CARGO_JOBS_POLICY="Cargo default"
AWG_CARGO_LINKER_POLICY="Cargo default"

_AWG_BUILD_LAST_REASON=""
_AWG_BUILD_CHECKED_DIR=""
_AWG_BUILD_CHECKED_FREE_KB=""
_AWG_BUILD_CHECKED_FREE_INODES=""

_awg_build_info() {
    if declare -F info >/dev/null 2>&1; then
        info "$*"
    else
        printf '[INFO]  %s\n' "$*"
    fi
}

_awg_build_warn() {
    if declare -F warn >/dev/null 2>&1; then
        warn "$*"
    else
        printf '[WARN]  %s\n' "$*" >&2
    fi
}

_awg_build_is_uint() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

_awg_build_available_kb() {
    LC_ALL=C df -Pk "$1" 2>/dev/null | awk 'NR > 1 { value = $4 } END { if (value ~ /^[0-9]+$/) print value }'
}

_awg_build_available_inodes() {
    LC_ALL=C df -Pi "$1" 2>/dev/null | awk 'NR > 1 { value = $4 } END { if (value ~ /^[0-9]+$/) print value }'
}

_awg_build_can_execute() {
    local root="$1"
    local probe_dir probe_script rc=0

    probe_dir="$(mktemp -d "${root%/}/.amneziawg-exec.XXXXXX" 2>/dev/null)" || return 1
    probe_script="${probe_dir}/probe"
    printf '#!/bin/sh\nexit 0\n' > "${probe_script}" || rc=1
    if [[ "${rc}" -eq 0 ]]; then
        chmod 700 "${probe_script}" 2>/dev/null || rc=1
    fi
    if [[ "${rc}" -eq 0 ]]; then
        "${probe_script}" >/dev/null 2>&1 || rc=1
    fi
    rm -rf -- "${probe_dir}"
    return "${rc}"
}

_awg_build_check_candidate() {
    local candidate="$1"
    local minimum_kb="$2"
    local minimum_inodes="$3"
    local canonical free_kb free_inodes

    _AWG_BUILD_LAST_REASON=""
    _AWG_BUILD_CHECKED_DIR=""
    _AWG_BUILD_CHECKED_FREE_KB=""
    _AWG_BUILD_CHECKED_FREE_INODES=""

    if [[ ! -d "${candidate}" ]]; then
        _AWG_BUILD_LAST_REASON="directory does not exist"
        return 1
    fi

    canonical="$(CDPATH='' cd -- "${candidate}" 2>/dev/null && pwd -P)" || {
        _AWG_BUILD_LAST_REASON="cannot resolve directory"
        return 1
    }

    if [[ ! -w "${canonical}" ]]; then
        _AWG_BUILD_LAST_REASON="directory is not writable"
        return 1
    fi

    if ! _awg_build_can_execute "${canonical}"; then
        _AWG_BUILD_LAST_REASON="filesystem is mounted noexec or cannot execute build artifacts"
        return 1
    fi

    free_kb="$(_awg_build_available_kb "${canonical}")"
    if ! _awg_build_is_uint "${free_kb}"; then
        _AWG_BUILD_LAST_REASON="cannot determine available disk space"
        return 1
    fi
    if (( free_kb < minimum_kb )); then
        _AWG_BUILD_LAST_REASON="only $((free_kb / 1024)) MiB free; $((minimum_kb / 1024)) MiB required"
        return 1
    fi

    free_inodes="$(_awg_build_available_inodes "${canonical}")"
    if [[ -n "${free_inodes}" ]]; then
        if ! _awg_build_is_uint "${free_inodes}"; then
            _AWG_BUILD_LAST_REASON="cannot determine available inodes"
            return 1
        fi
        if (( free_inodes < minimum_inodes )); then
            _AWG_BUILD_LAST_REASON="only ${free_inodes} inodes free; ${minimum_inodes} required"
            return 1
        fi
    fi

    _AWG_BUILD_CHECKED_DIR="${canonical}"
    _AWG_BUILD_CHECKED_FREE_KB="${free_kb}"
    _AWG_BUILD_CHECKED_FREE_INODES="${free_inodes:-unknown}"
    return 0
}

_awg_build_nearest_existing_dir() {
    local path="$1"
    while [[ ! -e "${path}" ]]; do
        local parent
        parent="$(dirname -- "${path}")"
        if [[ "${parent}" == "${path}" ]]; then
            return 1
        fi
        path="${parent}"
    done
    [[ -d "${path}" ]] || return 1
    printf '%s\n' "${path}"
}

_awg_build_resolve_target_override() {
    local source_dir="$1"
    local requested="$2"
    local target_path existing_parent

    if [[ "${requested}" == /* ]]; then
        target_path="${requested}"
    else
        target_path="${source_dir}/${requested}"
    fi

    existing_parent="$(_awg_build_nearest_existing_dir "${target_path}")" || {
        _AWG_BUILD_LAST_REASON="cannot resolve an existing parent for CARGO_TARGET_DIR=${requested}"
        return 1
    }

    if ! _awg_build_check_candidate "${existing_parent}" "${3}" "${4}"; then
        return 1
    fi

    mkdir -p -- "${target_path}" 2>/dev/null || {
        _AWG_BUILD_LAST_REASON="cannot create CARGO_TARGET_DIR=${requested}"
        return 1
    }
    target_path="$(CDPATH='' cd -- "${target_path}" 2>/dev/null && pwd -P)" || {
        _AWG_BUILD_LAST_REASON="cannot resolve CARGO_TARGET_DIR=${requested}"
        return 1
    }

    if ! _awg_build_check_candidate "${target_path}" "${3}" "${4}"; then
        return 1
    fi

    AWG_CARGO_TARGET_DIR="${target_path}"
    AWG_CARGO_TARGET_FREE_KB="${_AWG_BUILD_CHECKED_FREE_KB}"
    AWG_CARGO_TARGET_FREE_INODES="${_AWG_BUILD_CHECKED_FREE_INODES}"
    return 0
}

_awg_build_select_external_root() {
    local minimum_kb="$1"
    local minimum_inodes="$2"
    local -a candidates=()
    local candidate canonical seen="|" diagnostics=""

    if [[ -n "${AMNEZIAWG_BUILD_ROOT:-}" ]]; then
        candidates+=("${AMNEZIAWG_BUILD_ROOT}")
    else
        [[ -n "${TMPDIR:-}" ]] && candidates+=("${TMPDIR}")
        candidates+=("/var/tmp" "/var/cache" "/tmp")
    fi

    for candidate in "${candidates[@]}"; do
        canonical="$(CDPATH='' cd -- "${candidate}" 2>/dev/null && pwd -P)" || canonical="${candidate}"
        if [[ "${seen}" == *"|${canonical}|"* ]]; then
            continue
        fi
        seen+="${canonical}|"

        if _awg_build_check_candidate "${candidate}" "${minimum_kb}" "${minimum_inodes}"; then
            AWG_CARGO_TARGET_FREE_KB="${_AWG_BUILD_CHECKED_FREE_KB}"
            AWG_CARGO_TARGET_FREE_INODES="${_AWG_BUILD_CHECKED_FREE_INODES}"
            AWG_CARGO_BUILD_ROOT_CREATED="$(mktemp -d "${_AWG_BUILD_CHECKED_DIR%/}/amneziawg-build.XXXXXX" 2>/dev/null)" || {
                _AWG_BUILD_LAST_REASON="cannot create a private build directory below ${_AWG_BUILD_CHECKED_DIR}"
                return 1
            }
            mkdir -p -- "${AWG_CARGO_BUILD_ROOT_CREATED}/target"
            AWG_CARGO_TARGET_DIR="${AWG_CARGO_BUILD_ROOT_CREATED}/target"
            return 0
        fi
        diagnostics+="  ${candidate}: ${_AWG_BUILD_LAST_REASON}"$'\n'
    done

    _awg_build_warn "No suitable external Cargo build filesystem was found:"
    while IFS= read -r candidate; do
        [[ -n "${candidate}" ]] && _awg_build_warn "${candidate}"
    done <<< "${diagnostics}"
    if [[ -n "${AMNEZIAWG_BUILD_ROOT:-}" ]]; then
        _awg_build_warn "AMNEZIAWG_BUILD_ROOT was explicitly set; no fallback directories were tried."
    else
        _awg_build_warn "Set AMNEZIAWG_BUILD_ROOT to a writable, executable filesystem with sufficient free space."
    fi
    return 1
}

_awg_build_cpu_count() {
    local count=""
    if command -v nproc >/dev/null 2>&1; then
        count="$(nproc 2>/dev/null || true)"
    elif command -v getconf >/dev/null 2>&1; then
        count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
    fi
    _awg_build_is_uint "${count}" && (( count > 0 )) && printf '%s\n' "${count}"
}

_awg_build_proc_memory_available_kb() {
    [[ -r /proc/meminfo ]] || return 0
    awk '
        $1 == "MemAvailable:" { mem_available = $2; have_mem_available = 1 }
        $1 == "MemFree:"      { mem_free = $2 }
        $1 == "Buffers:"      { buffers = $2 }
        $1 == "Cached:"       { cached = $2 }
        END {
            if (!have_mem_available) mem_available = mem_free + buffers + cached
            print mem_available + 0
        }
    ' /proc/meminfo
}

_awg_build_proc_swap_available_kb() {
    [[ -r /proc/meminfo ]] || return 0
    awk '$1 == "SwapFree:" && $2 ~ /^[0-9]+$/ { print $2; exit }' /proc/meminfo
}

_awg_build_proc_available_memory_kb() {
    local memory_available swap_available
    local have_available=0
    memory_available="$(_awg_build_proc_memory_available_kb)"
    swap_available="$(_awg_build_proc_swap_available_kb)"

    if _awg_build_is_uint "${memory_available}"; then
        have_available=1
    else
        memory_available=0
    fi
    if _awg_build_is_uint "${swap_available}"; then
        have_available=1
    else
        swap_available=0
    fi
    if (( have_available )); then
        printf '%s\n' "$((memory_available + swap_available))"
    fi
}

_awg_build_read_uint_file() {
    local value
    [[ -r "$1" ]] || return 1
    IFS= read -r value < "$1" || return 1
    _awg_build_is_uint "${value}" || return 1
    printf '%s\n' "${value}"
}

_awg_build_is_finite_memory_limit() {
    local value="$1"
    local unlimited_threshold=1152921504606846976
    local index value_digit threshold_digit

    _awg_build_is_uint "${value}" || return 1
    while [[ "${value}" == 0* && "${#value}" -gt 1 ]]; do
        value="${value#0}"
    done
    if (( ${#value} != ${#unlimited_threshold} )); then
        (( ${#value} < ${#unlimited_threshold} ))
        return
    fi
    for ((index = 0; index < ${#value}; index++)); do
        value_digit="${value:index:1}"
        threshold_digit="${unlimited_threshold:index:1}"
        if (( value_digit < threshold_digit )); then
            return 0
        fi
        if (( value_digit > threshold_digit )); then
            return 1
        fi
    done
    return 1
}

_awg_build_cgroup_v2_dir() {
    local relative dir
    [[ -r /sys/fs/cgroup/cgroup.controllers ]] || return 1
    [[ -r /proc/self/cgroup ]] || return 1
    relative="$(awk -F: '$1 == "0" { print $3; exit }' /proc/self/cgroup)"
    [[ -n "${relative}" && "${relative}" == /* ]] || return 1
    dir="/sys/fs/cgroup${relative}"
    if [[ ! -r "${dir}/memory.max" ]] && [[ -r /sys/fs/cgroup/memory.max ]]; then
        dir="/sys/fs/cgroup"
    fi
    [[ -r "${dir}/memory.max" ]] || return 1
    printf '%s\n' "${dir}"
}

_awg_build_mountinfo_path() {
    local path="$1"
    path="${path//\\040/ }"
    path="${path//\\011/$'\t'}"
    path="${path//\\012/$'\n'}"
    path="${path//\\134/\\}"
    printf '%s\n' "${path}"
}

_awg_build_cgroup_v1_memory_mounts() {
    local mountinfo_file="$1"
    [[ -r "${mountinfo_file}" ]] || return 1

    LC_ALL=C awk '
        function has_option(options, wanted, count, item, values) {
            count = split(options, values, ",")
            for (item = 1; item <= count; item++) {
                if (values[item] == wanted) return 1
            }
            return 0
        }
        {
            separator = 0
            for (field = 7; field <= NF; field++) {
                if ($field == "-") {
                    separator = field
                    break
                }
            }
            if (!separator || $(separator + 1) != "cgroup") next
            if (!has_option($(separator + 3), "memory")) next
            print $4 "\t" $5
        }
    ' "${mountinfo_file}"
}

# Optional file arguments allow fixture-based tests of host-specific proc data.
# shellcheck disable=SC2120
_awg_build_cgroup_v1_dir() {
    local cgroup_file="${1:-/proc/self/cgroup}"
    local mountinfo_file="${2:-/proc/self/mountinfo}"
    local relative mount_root mount_point suffix dir base
    [[ -r "${cgroup_file}" ]] || return 1
    relative="$(awk -F: '$2 ~ /(^|,)memory(,|$)/ { print $3; exit }' "${cgroup_file}")"
    [[ -n "${relative}" && "${relative}" == /* ]] || return 1

    while IFS=$'\t' read -r mount_root mount_point; do
        [[ -n "${mount_root}" && -n "${mount_point}" ]] || continue
        mount_root="$(_awg_build_mountinfo_path "${mount_root}")"
        mount_point="$(_awg_build_mountinfo_path "${mount_point}")"

        if [[ "${mount_root}" == "/" ]]; then
            suffix="${relative}"
        elif [[ "${relative}" == "${mount_root}" ]]; then
            suffix=""
        elif [[ "${relative}" == "${mount_root%/}/"* ]]; then
            suffix="${relative#"${mount_root%/}"}"
        else
            continue
        fi

        if [[ -n "${suffix}" ]]; then
            dir="${mount_point%/}${suffix}"
        else
            dir="${mount_point}"
        fi
        if [[ -r "${dir}/memory.limit_in_bytes" ]]; then
            printf '%s\n' "${dir}"
            return 0
        fi
    done < <(_awg_build_cgroup_v1_memory_mounts "${mountinfo_file}")

    # Retain the conventional paths as a compatibility fallback for unusual
    # systems where mountinfo is unavailable or hides the controller mount.
    for base in /sys/fs/cgroup/memory /sys/fs/cgroup; do
        dir="${base}${relative}"
        if [[ -r "${dir}/memory.limit_in_bytes" ]]; then
            printf '%s\n' "${dir}"
            return 0
        fi
    done
    return 1
}

_awg_build_cgroup_v2_available_memory_kb() {
    local dir="$1"
    local memory_max memory_current swap_max swap_current
    local memory_remaining swap_remaining parent
    local memory_best="" swap_best=""
    local proc_memory_kb proc_swap_kb limit_kb
    local effective_memory_kb="" effective_swap_kb=""

    while [[ -r "${dir}/memory.max" ]]; do
        if memory_max="$(_awg_build_read_uint_file "${dir}/memory.max")" &&
                _awg_build_is_finite_memory_limit "${memory_max}" &&
                memory_current="$(_awg_build_read_uint_file "${dir}/memory.current")"; then
            if (( memory_current < memory_max )); then
                memory_remaining=$((memory_max - memory_current))
            else
                memory_remaining=0
            fi
            if [[ -z "${memory_best}" ]] || (( memory_remaining < memory_best )); then
                memory_best="${memory_remaining}"
            fi
        fi

        if swap_max="$(_awg_build_read_uint_file "${dir}/memory.swap.max")" &&
                _awg_build_is_finite_memory_limit "${swap_max}" &&
                swap_current="$(_awg_build_read_uint_file "${dir}/memory.swap.current")"; then
            if (( swap_current < swap_max )); then
                swap_remaining=$((swap_max - swap_current))
            else
                swap_remaining=0
            fi
            if [[ -z "${swap_best}" ]] || (( swap_remaining < swap_best )); then
                swap_best="${swap_remaining}"
            fi
        fi

        parent="${dir%/*}"
        [[ -n "${parent}" && "${parent}" != "${dir}" ]] || break
        dir="${parent}"
    done

    proc_memory_kb="$(_awg_build_proc_memory_available_kb)"
    proc_swap_kb="$(_awg_build_proc_swap_available_kb)"

    if [[ -n "${memory_best}" ]]; then
        limit_kb=$((memory_best / 1024))
        effective_memory_kb="${limit_kb}"
        if _awg_build_is_uint "${proc_memory_kb}" && (( proc_memory_kb < limit_kb )); then
            effective_memory_kb="${proc_memory_kb}"
        fi
    elif _awg_build_is_uint "${proc_memory_kb}"; then
        effective_memory_kb="${proc_memory_kb}"
    fi

    if [[ -n "${swap_best}" ]]; then
        limit_kb=$((swap_best / 1024))
        effective_swap_kb="${limit_kb}"
        if _awg_build_is_uint "${proc_swap_kb}" && (( proc_swap_kb < limit_kb )); then
            effective_swap_kb="${proc_swap_kb}"
        fi
    elif _awg_build_is_uint "${proc_swap_kb}"; then
        effective_swap_kb="${proc_swap_kb}"
    fi

    [[ -n "${effective_memory_kb}" || -n "${effective_swap_kb}" ]] || return 1
    printf '%s\n' "$((${effective_memory_kb:-0} + ${effective_swap_kb:-0}))"
}

_awg_build_cgroup_v1_available_memory_kb() {
    local dir="$1"
    local memory_limit memory_usage memsw_limit memsw_usage
    local remaining candidate best="" parent

    while [[ -r "${dir}/memory.limit_in_bytes" ]]; do
        memory_limit="$(_awg_build_read_uint_file "${dir}/memory.limit_in_bytes")" || return 1
        memory_usage="$(_awg_build_read_uint_file "${dir}/memory.usage_in_bytes")" || return 1

        if memsw_limit="$(_awg_build_read_uint_file "${dir}/memory.memsw.limit_in_bytes")" &&
                _awg_build_is_finite_memory_limit "${memsw_limit}" &&
                memsw_usage="$(_awg_build_read_uint_file "${dir}/memory.memsw.usage_in_bytes")"; then
            if (( memsw_usage < memsw_limit )); then
                candidate=$((memsw_limit - memsw_usage))
            else
                candidate=0
            fi
        elif _awg_build_is_finite_memory_limit "${memory_limit}"; then
            if (( memory_usage < memory_limit )); then
                candidate=$((memory_limit - memory_usage))
            else
                candidate=0
            fi
        else
            candidate=""
        fi

        if [[ -n "${candidate}" ]] && { [[ -z "${best}" ]] || (( candidate < best )); }; then
            best="${candidate}"
        fi

        parent="${dir%/*}"
        [[ -n "${parent}" && "${parent}" != "${dir}" ]] || break
        dir="${parent}"
    done

    [[ -n "${best}" ]] || return 1
    remaining="${best}"
    printf '%s\n' "$((remaining / 1024))"
}

_awg_build_cgroup_available_memory_kb() {
    local dir
    if dir="$(_awg_build_cgroup_v2_dir)"; then
        _awg_build_cgroup_v2_available_memory_kb "${dir}"
        return
    fi
    if dir="$(_awg_build_cgroup_v1_dir)"; then
        _awg_build_cgroup_v1_available_memory_kb "${dir}"
        return
    fi
    return 1
}

_awg_build_available_memory_kb() {
    local proc_available cgroup_available
    proc_available="$(_awg_build_proc_available_memory_kb)"
    cgroup_available="$(_awg_build_cgroup_available_memory_kb 2>/dev/null || true)"

    if _awg_build_is_uint "${proc_available}" && _awg_build_is_uint "${cgroup_available}"; then
        if (( cgroup_available < proc_available )); then
            printf '%s\n' "${cgroup_available}"
        else
            printf '%s\n' "${proc_available}"
        fi
    elif _awg_build_is_uint "${cgroup_available}"; then
        printf '%s\n' "${cgroup_available}"
    elif _awg_build_is_uint "${proc_available}"; then
        printf '%s\n' "${proc_available}"
    fi
}

awg_build_is_constrained() {
    local cpu_count="$1"
    local available_memory_kb="$2"
    local memory_threshold_kb="$3"

    if _awg_build_is_uint "${cpu_count}" && (( cpu_count <= 1 )); then
        return 0
    fi
    if _awg_build_is_uint "${available_memory_kb}" && (( available_memory_kb < memory_threshold_kb )); then
        return 0
    fi
    return 1
}

_awg_build_rustc_host() {
    rustc -vV 2>/dev/null | awk '$1 == "host:" { host = $2 } END { if (host) print host }'
}

_awg_build_configure_jobs_and_linker() {
    local cpu_count available_memory_kb
    local memory_threshold_kb=2097152
    local host normalized linker_var current_linker=""

    cpu_count="$(_awg_build_cpu_count)"
    available_memory_kb="$(_awg_build_available_memory_kb)"

    if awg_build_is_constrained "${cpu_count}" "${available_memory_kb}" "${memory_threshold_kb}"; then
        if [[ -z "${CARGO_BUILD_JOBS:-}" ]]; then
            CARGO_BUILD_JOBS=1
            export CARGO_BUILD_JOBS
            AWG_CARGO_JOBS_POLICY="1 (constrained host: CPUs=${cpu_count:-unknown}, available memory+swap=$(( ${available_memory_kb:-0} / 1024 )) MiB)"
        else
            AWG_CARGO_JOBS_POLICY="${CARGO_BUILD_JOBS} (operator override)"
        fi

    elif [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
        AWG_CARGO_JOBS_POLICY="${CARGO_BUILD_JOBS} (operator override)"
    fi

    host="$(_awg_build_rustc_host)"
    if [[ -n "${host}" ]]; then
        normalized="$(printf '%s' "${host}" | tr '[:lower:]-.' '[:upper:]__')"
        linker_var="CARGO_TARGET_${normalized}_LINKER"
        current_linker="${!linker_var:-}"
        if [[ -n "${current_linker}" ]]; then
            AWG_CARGO_LINKER_POLICY="${current_linker} (operator override)"
        elif [[ "${RUSTFLAGS:-}" == *"linker="* ]]; then
            AWG_CARGO_LINKER_POLICY="RUSTFLAGS override"
        elif [[ "${CARGO_ENCODED_RUSTFLAGS:-}" == *"linker="* ]]; then
            AWG_CARGO_LINKER_POLICY="CARGO_ENCODED_RUSTFLAGS override"
        else
            AWG_CARGO_LINKER_POLICY="Cargo configuration/default"
        fi
    fi
}

awg_prepare_cargo_build() {
    local source_dir="$1"
    local component="$2"
    local minimum_kb="$3"
    local minimum_inodes="${4:-8192}"
    local source_target candidate_root explicit_tmp=""

    if [[ ! -d "${source_dir}" ]]; then
        _awg_build_warn "Cargo source directory does not exist: ${source_dir}"
        return 1
    fi
    source_dir="$(CDPATH='' cd -- "${source_dir}" 2>/dev/null && pwd -P)" || return 1

    if ! _awg_build_is_uint "${minimum_kb}" || (( minimum_kb == 0 )); then
        _awg_build_warn "Invalid minimum build-space requirement: ${minimum_kb} KiB"
        return 1
    fi
    if ! _awg_build_is_uint "${minimum_inodes}" || (( minimum_inodes == 0 )); then
        _awg_build_warn "Invalid minimum build-inode requirement: ${minimum_inodes}"
        return 1
    fi

    AWG_CARGO_TARGET_DIR=""
    AWG_CARGO_TMPDIR_CREATED=""
    AWG_CARGO_BUILD_ROOT_CREATED=""
    AWG_CARGO_TARGET_FREE_KB=""
    AWG_CARGO_TARGET_FREE_INODES=""
    AWG_CARGO_JOBS_POLICY="Cargo default"
    AWG_CARGO_LINKER_POLICY="Cargo default"

    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        if ! _awg_build_resolve_target_override "${source_dir}" "${CARGO_TARGET_DIR}" "${minimum_kb}" "${minimum_inodes}"; then
            _awg_build_warn "Explicit CARGO_TARGET_DIR is unsuitable: ${_AWG_BUILD_LAST_REASON}"
            return 1
        fi
    elif [[ -n "${AMNEZIAWG_BUILD_ROOT:-}" ]]; then
        if ! _awg_build_select_external_root "${minimum_kb}" "${minimum_inodes}"; then
            return 1
        fi
    else
        source_target="${source_dir}/target"
        candidate_root="${source_target}"
        [[ -d "${candidate_root}" ]] || candidate_root="${source_dir}"
        if _awg_build_check_candidate "${candidate_root}" "${minimum_kb}" "${minimum_inodes}"; then
            mkdir -p -- "${source_target}" || return 1
            AWG_CARGO_TARGET_DIR="$(CDPATH='' cd -- "${source_target}" && pwd -P)"
            AWG_CARGO_TARGET_FREE_KB="${_AWG_BUILD_CHECKED_FREE_KB}"
            AWG_CARGO_TARGET_FREE_INODES="${_AWG_BUILD_CHECKED_FREE_INODES}"
        else
            _awg_build_warn "The normal target directory for ${component} is unsuitable: ${_AWG_BUILD_LAST_REASON}"
            if ! _awg_build_select_external_root "${minimum_kb}" "${minimum_inodes}"; then
                return 1
            fi
        fi
    fi

    if [[ -n "${TMPDIR:-}" ]] && _awg_build_check_candidate "${TMPDIR}" "${minimum_kb}" "${minimum_inodes}"; then
        explicit_tmp="${_AWG_BUILD_CHECKED_DIR}"
    elif [[ -n "${TMPDIR:-}" ]]; then
        _awg_build_warn "Ignoring unsuitable TMPDIR=${TMPDIR}: ${_AWG_BUILD_LAST_REASON}"
    fi

    if [[ -n "${explicit_tmp}" ]]; then
        AWG_CARGO_TMPDIR_CREATED="$(mktemp -d "${explicit_tmp%/}/.amneziawg-tmp.XXXXXX" 2>/dev/null)" || return 1
    else
        AWG_CARGO_TMPDIR_CREATED="$(mktemp -d "${AWG_CARGO_TARGET_DIR%/}/.amneziawg-tmp.XXXXXX" 2>/dev/null)" || return 1
    fi

    CARGO_TARGET_DIR="${AWG_CARGO_TARGET_DIR}"
    TMPDIR="${AWG_CARGO_TMPDIR_CREATED}"
    export CARGO_TARGET_DIR TMPDIR

    _awg_build_configure_jobs_and_linker

    _awg_build_info "Build source (${component}): ${source_dir}"
    _awg_build_info "Cargo target: ${AWG_CARGO_TARGET_DIR} ($((AWG_CARGO_TARGET_FREE_KB / 1024)) MiB free, ${AWG_CARGO_TARGET_FREE_INODES} inodes free)"
    _awg_build_info "Compiler temporary directory: ${TMPDIR}"
    _awg_build_info "Cargo jobs: ${AWG_CARGO_JOBS_POLICY}"
    _awg_build_info "Linker: ${AWG_CARGO_LINKER_POLICY}"
    return 0
}

awg_cargo_release_binary() {
    local binary_name="$1"
    local release_dir="${AWG_CARGO_TARGET_DIR}"
    local cargo_target="${CARGO_BUILD_TARGET:-}"
    if [[ -n "${cargo_target}" ]]; then
        if [[ "${cargo_target}" == "host-tuple" ]]; then
            cargo_target="$(_awg_build_rustc_host)"
            if [[ -z "${cargo_target}" ]]; then
                _awg_build_warn "Unable to resolve Cargo's host-tuple target from rustc -vV."
                return 1
            fi
        elif [[ "${cargo_target}" == *.json ]]; then
            cargo_target="$(basename -- "${cargo_target}" .json)"
        fi
        release_dir+="/${cargo_target}"
    fi
    printf '%s/release/%s\n' "${release_dir}" "${binary_name}"
}

awg_cleanup_cargo_build() {
    local tmpdir="${AWG_CARGO_TMPDIR_CREATED:-}"
    local build_root="${AWG_CARGO_BUILD_ROOT_CREATED:-}"

    if [[ -n "${tmpdir}" ]] && [[ "$(basename -- "${tmpdir}")" == .amneziawg-tmp.* ]]; then
        rm -rf -- "${tmpdir}" 2>/dev/null || true
    fi
    if [[ -n "${build_root}" ]] && [[ "$(basename -- "${build_root}")" == amneziawg-build.* ]]; then
        rm -rf -- "${build_root}" 2>/dev/null || true
    fi

    AWG_CARGO_TMPDIR_CREATED=""
    AWG_CARGO_BUILD_ROOT_CREATED=""
}
