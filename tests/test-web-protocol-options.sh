#!/usr/bin/env bash
# Test the real panel helper's protocol allowlist without touching an interface.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
# shellcheck disable=SC1090
source <(sed '/^main "\$@"$/d' "$ROOT/amneziawg-web/scripts/amneziawg-web-privileged")
require_root() { :; }
run_protocol_migration() { printf '%s\n' "$@" > "$WORK/dispatched"; }
for operation in enable-awg31 disable-awg3; do
    main "$operation"
    [[ "$(cat "$WORK/dispatched")" == "--$operation" ]]
done
rm "$WORK/dispatched"
for operation in enable-awg3 invalid-protocol; do
    if (main "$operation") > "$WORK/rejected" 2>&1; then
        echo 'FAIL: unsupported panel protocol dispatched'; exit 1
    fi
    [[ ! -e "$WORK/dispatched" ]]
done
echo 'PASS: panel helper permits AWG 2.0 and 3.1 only'
