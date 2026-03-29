#!/usr/bin/env bash
# amneziawg-web-upgrade.sh (root-level entrypoint)
#
# This script is the operator-facing entrypoint for the amneziawg-web companion
# upgrade tool. It lives next to amneziawg-web-install.sh so the operator
# lifecycle is:
#
#   sudo ./amneziawg-web-install.sh            # install
#   sudo ./amneziawg-web-upgrade.sh \
#        --binary ./target/release/amneziawg-web  # upgrade
#   sudo ./amneziawg-web-uninstall.sh          # uninstall (safe defaults)
#
# All upgrade logic is in amneziawg-web/scripts/amneziawg-web-upgrade.sh.
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
UPGRADER="${SCRIPT_DIR}/amneziawg-web/scripts/amneziawg-web-upgrade.sh"
BOOTSTRAP_DIR=""

cleanup() {
    if [[ -n "${BOOTSTRAP_DIR}" ]] && [[ -d "${BOOTSTRAP_DIR}" ]]; then
        rm -rf "${BOOTSTRAP_DIR}"
    fi
}

trap cleanup EXIT

bootstrap_repo_if_needed() {
    if [[ -f "${UPGRADER}" ]]; then
        return 0
    fi

    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: Upgrade script not found at: ${UPGRADER}" >&2
        echo "       Install git and re-run this script, or clone ${REPO_URL} manually." >&2
        exit 1
    fi

    BOOTSTRAP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amneziawg-install.XXXXXX")"

    echo "Upgrade script not found locally. Cloning ${REPO_URL} (${REPO_REF}) into ${BOOTSTRAP_DIR} ..." >&2
    if ! GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "${REPO_REF}" "${REPO_URL}" "${BOOTSTRAP_DIR}" >&2; then
        echo "ERROR: Failed to clone ${REPO_URL}" >&2
        echo "       Clone the repository manually and run ./amneziawg-web-upgrade.sh from there." >&2
        exit 1
    fi

    UPGRADER="${BOOTSTRAP_DIR}/amneziawg-web/scripts/amneziawg-web-upgrade.sh"
    if [[ ! -f "${UPGRADER}" ]]; then
        echo "ERROR: Upgrade script not found after cloning: ${UPGRADER}" >&2
        exit 1
    fi
}

bootstrap_repo_if_needed

exit_code=0
bash "${UPGRADER}" "$@" || exit_code=$?
exit "${exit_code}"
