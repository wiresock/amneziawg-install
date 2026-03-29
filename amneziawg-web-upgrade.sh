#!/usr/bin/env bash
# amneziawg-web-upgrade.sh — legacy wrapper (kept for backward compatibility).
# Prefer: sudo ./amneziawg-web.sh upgrade [OPTIONS]
#
# Delegates to amneziawg-web.sh upgrade.
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/amneziawg-web.sh" ]]; then
    echo "Error: amneziawg-web.sh not found in ${SCRIPT_DIR}." >&2
    echo >&2
    echo "This script is a legacy wrapper around amneziawg-web.sh." >&2
    echo "To use it, either:" >&2
    echo "  * download amneziawg-web.sh into the same directory as this script, or" >&2
    echo "  * clone the full repository:" >&2
    echo "      git clone https://github.com/wiresock/amneziawg-install" >&2
    echo "    and run it from the cloned directory." >&2
    exit 1
fi

exec bash "${SCRIPT_DIR}/amneziawg-web.sh" upgrade "$@"
