#!/usr/bin/env bash
# amneziawg-web-uninstall.sh (root-level entrypoint)
#
# This script is the operator-facing entrypoint for the amneziawg-web companion
# uninstaller. It lives next to amneziawg-web-install.sh so the operator lifecycle
# is:
#
#   sudo ./amneziawg-web-install.sh            # install
#   sudo ./amneziawg-web-uninstall.sh          # uninstall (safe defaults)
#   sudo ./amneziawg-web-uninstall.sh \
#        --purge-config --purge-data --force   # full purge
#
# All uninstall logic is in amneziawg-web/scripts/amneziawg-web-uninstall.sh.
# This file is a thin entrypoint that forwards all arguments to that script.
#
# If the repository files are not present locally (e.g. the panel was installed
# via the standalone wrapper), this script will shallow-clone the repository to a
# temporary directory and continue from there.
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

readonly REPO_URL="https://github.com/wiresock/amneziawg-install.git"
readonly REPO_REF="main"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNINSTALLER="${SCRIPT_DIR}/amneziawg-web/scripts/amneziawg-web-uninstall.sh"
BOOTSTRAP_DIR=""

cleanup() {
    if [[ -n "${BOOTSTRAP_DIR}" ]] && [[ -d "${BOOTSTRAP_DIR}" ]]; then
        rm -rf "${BOOTSTRAP_DIR}"
    fi
}

trap cleanup EXIT

bootstrap_repo_if_needed() {
    if [[ -f "${UNINSTALLER}" ]]; then
        return 0
    fi

    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: Uninstall script not found at: ${UNINSTALLER}" >&2
        echo "       Install git and re-run this script, or clone ${REPO_URL} manually." >&2
        exit 1
    fi

    BOOTSTRAP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amneziawg-install.XXXXXX")"

    echo "Uninstall script not found locally. Cloning ${REPO_URL} (${REPO_REF}) into ${BOOTSTRAP_DIR} ..." >&2
    if ! GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "${REPO_REF}" "${REPO_URL}" "${BOOTSTRAP_DIR}" >&2; then
        echo "ERROR: Failed to clone ${REPO_URL}" >&2
        echo "       Clone the repository manually and run ./amneziawg-web-uninstall.sh from there." >&2
        exit 1
    fi

    UNINSTALLER="${BOOTSTRAP_DIR}/amneziawg-web/scripts/amneziawg-web-uninstall.sh"
    if [[ ! -f "${UNINSTALLER}" ]]; then
        echo "ERROR: Uninstall script not found after cloning: ${UNINSTALLER}" >&2
        exit 1
    fi
}

bootstrap_repo_if_needed

exit_code=0
bash "${UNINSTALLER}" "$@" || exit_code=$?
exit "${exit_code}"
