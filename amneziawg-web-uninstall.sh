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
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNINSTALLER="${SCRIPT_DIR}/amneziawg-web/scripts/amneziawg-web-uninstall.sh"

if [[ ! -f "${UNINSTALLER}" ]]; then
    echo "ERROR: Uninstall script not found at: ${UNINSTALLER}" >&2
    echo "       Make sure you cloned the full repository." >&2
    exit 1
fi

exec bash "${UNINSTALLER}" "$@"
