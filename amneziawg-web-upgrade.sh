#!/usr/bin/env bash
# amneziawg-web-upgrade.sh — legacy wrapper (kept for backward compatibility).
# Prefer: sudo ./amneziawg-web.sh upgrade [OPTIONS]
#
# Delegates to amneziawg-web.sh upgrade.
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/amneziawg-web.sh" upgrade "$@"
