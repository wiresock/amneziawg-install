#!/usr/bin/env bash
# amneziawg-web-uninstall.sh — legacy wrapper (kept for backward compatibility).
# Prefer: sudo ./amneziawg-web.sh uninstall [OPTIONS]
#
# Delegates to amneziawg-web.sh uninstall.
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/amneziawg-web.sh" uninstall "$@"
