#!/usr/bin/env bash
# amneziawg-proxy-install.sh (root-level entrypoint)
#
# This script is the operator-facing entrypoint for the amneziawg-proxy
# installer. It lives next to amneziawg-install.sh so the recommended
# workflow is:
#
#   sudo ./amneziawg-install.sh           # install AmneziaWG
#   sudo ./amneziawg-proxy-install.sh     # install the UDP proxy
#
# All installer logic is in amneziawg-proxy/scripts/amneziawg-proxy-install.sh.
# This file is a thin entrypoint that forwards all arguments to that script.
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="${SCRIPT_DIR}/amneziawg-proxy/scripts/amneziawg-proxy-install.sh"

if [[ ! -f "${INSTALLER}" ]]; then
    echo "ERROR: Installer script not found at: ${INSTALLER}" >&2
    echo "       Make sure you cloned the full repository." >&2
    exit 1
fi

exec bash "${INSTALLER}" "$@"
