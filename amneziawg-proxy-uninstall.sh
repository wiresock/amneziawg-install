#!/usr/bin/env bash
# amneziawg-proxy-uninstall.sh (root-level entrypoint)
#
# This script is the operator-facing entrypoint for the amneziawg-proxy
# uninstaller. It lives next to amneziawg-proxy-install.sh so the operator
# lifecycle is:
#
#   sudo ./amneziawg-proxy-install.sh            # install
#   sudo ./amneziawg-proxy-uninstall.sh          # uninstall (safe defaults)
#   sudo ./amneziawg-proxy-uninstall.sh \
#        --purge-config --purge-data --force      # full purge
#
# All uninstall logic is in amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh.
# This file is a thin entrypoint that forwards all arguments to that script.
#
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNINSTALLER="${SCRIPT_DIR}/amneziawg-proxy/scripts/amneziawg-proxy-uninstall.sh"

if [[ ! -f "${UNINSTALLER}" ]]; then
    echo "ERROR: Uninstall script not found at: ${UNINSTALLER}" >&2
    echo "       Make sure you cloned the full repository." >&2
    exit 1
fi

exec bash "${UNINSTALLER}" "$@"
