#!/usr/bin/env bash
# amneziawg-web-install.sh (root-level entrypoint)
#
# This script is the operator-facing entrypoint for the amneziawg-web companion
# installer. It lives next to amneziawg-install.sh so the recommended workflow is:
#
#   sudo ./amneziawg-install.sh           # install AmneziaWG
#   sudo ./amneziawg-web-install.sh       # install the web panel
#   # open http://127.0.0.1:8080
#
# All installer logic is in amneziawg-web/scripts/amneziawg-web-install.sh.
# This file is a thin entrypoint that forwards all arguments to that script.
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

readonly REPO_URL="https://github.com/wiresock/amneziawg-install.git"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="${SCRIPT_DIR}/amneziawg-web/scripts/amneziawg-web-install.sh"
BOOTSTRAP_DIR=""

cleanup() {
    if [[ -n "${BOOTSTRAP_DIR}" ]] && [[ -d "${BOOTSTRAP_DIR}" ]]; then
        rm -rf "${BOOTSTRAP_DIR}"
    fi
}

trap cleanup EXIT

bootstrap_repo_if_needed() {
    if [[ -f "${INSTALLER}" ]]; then
        return 0
    fi

    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: Installer script not found at: ${INSTALLER}" >&2
        echo "       Install git and re-run this script, or clone ${REPO_URL} manually." >&2
        exit 1
    fi

    BOOTSTRAP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/amneziawg-install.XXXXXX")"

    echo "Installer files not found locally. Cloning ${REPO_URL} into ${BOOTSTRAP_DIR} ..." >&2
    if ! GIT_TERMINAL_PROMPT=0 git clone --depth 1 "${REPO_URL}" "${BOOTSTRAP_DIR}" >&2; then
        echo "ERROR: Failed to clone ${REPO_URL}" >&2
        echo "       Clone the repository manually and run ./amneziawg-web-install.sh from there." >&2
        exit 1
    fi

    INSTALLER="${BOOTSTRAP_DIR}/amneziawg-web/scripts/amneziawg-web-install.sh"
    if [[ ! -f "${INSTALLER}" ]]; then
        echo "ERROR: Installer script not found after cloning: ${INSTALLER}" >&2
        exit 1
    fi
}

bootstrap_repo_if_needed

bash "${INSTALLER}" "$@"
