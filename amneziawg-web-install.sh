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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="${SCRIPT_DIR}/amneziawg-web/scripts/amneziawg-web-install.sh"

if [[ ! -f "${INSTALLER}" ]]; then
    echo "ERROR: Installer script not found at: ${INSTALLER}" >&2
    echo "       Make sure you cloned the full repository." >&2
    exit 1
fi

exec bash "${INSTALLER}" "$@"
