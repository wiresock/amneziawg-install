#!/usr/bin/env bash
# amneziawg-proxy-common.sh
# Shared helpers sourced by both amneziawg-proxy-install.sh and
# amneziawg-proxy-uninstall.sh.  Not intended to be executed directly.
#
# https://github.com/wiresock/amneziawg-install

# ── Shared validation helpers ─────────────────────────────────────────────────

# Validate a params file is safe to source: must be a regular file (not a
# symlink), owned by root, and have permissions 600 or 400.
# Returns 0 if safe, 1 with a warning if not.
# Requires warn() to be defined by the sourcing script.
validate_params_file() {
    local f="$1"
    if [[ -L "${f}" ]] || [[ -h "${f}" ]]; then
        warn "Ignoring params file — must not be a symbolic link: ${f}"
        return 1
    fi
    if [[ ! -f "${f}" ]]; then
        return 1
    fi
    local owner perms
    owner="$(stat -c '%u' "${f}" 2>/dev/null || true)"
    perms="$(stat -c '%a' "${f}" 2>/dev/null || true)"
    if [[ -z "${owner}" || -z "${perms}" ]]; then
        warn "Ignoring params file — failed to read file metadata: ${f}"
        return 1
    fi
    if [[ "${owner}" != "0" ]]; then
        warn "Ignoring params file — not owned by root (owner UID: ${owner}): ${f}"
        return 1
    fi
    if [[ "${perms}" != "600" ]] && [[ "${perms}" != "400" ]]; then
        warn "Ignoring params file — insecure permissions (${perms}); expected 600 or 400: ${f}"
        return 1
    fi
    return 0
}
