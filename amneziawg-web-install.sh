#!/usr/bin/env bash
# amneziawg-web-install.sh — legacy wrapper (kept for backward compatibility).
# Prefer: sudo ./amneziawg-web.sh install [OPTIONS]
#
# Delegates to amneziawg-web.sh install.
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/amneziawg-web.sh" ]]; then
    echo "Error: amneziawg-web.sh not found in ${SCRIPT_DIR}." >&2
    echo "This legacy wrapper expects amneziawg-web.sh to be located alongside it." >&2
    echo "Remediation: download amneziawg-web.sh or clone the repository:" >&2
    echo "  git clone https://github.com/wiresock/amneziawg-install.git" >&2
    exit 1
fi

exec bash "${SCRIPT_DIR}/amneziawg-web.sh" install "$@"
