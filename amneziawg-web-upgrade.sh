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
# https://github.com/wiresock/amneziawg-install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPGRADER="${SCRIPT_DIR}/amneziawg-web/scripts/amneziawg-web-upgrade.sh"

if [[ ! -f "${UPGRADER}" ]]; then
    echo "ERROR: Upgrade script not found at: ${UPGRADER}" >&2
    echo "       Make sure you cloned the full repository." >&2
    exit 1
fi

exec bash "${UPGRADER}" "$@"
