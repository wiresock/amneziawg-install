#!/usr/bin/env bash
# Reusing installed helpers must work in the web panel's read-only /usr.
# Model an unwritable destination by rejecting temporary-file allocation;
# all real rendering, byte comparison, metadata checks and writes still run.
# Globals configure the sourced installer functions.
# shellcheck disable=SC2034
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
# shellcheck source=../amneziawg-install.sh
source "$ROOT/amneziawg-install.sh"
AWG_BT_TRUST_ANCHOR="$WORK"
AWG_BT_TRUSTED_UID="$(id -u)"
AWG_BT_LIBEXEC_DIR="$WORK/libexec"
BLOCK_WRITES=0
mktemp() {
    if [[ "$BLOCK_WRITES" == 1 && "$*" == "$WORK/libexec/"* ]]; then
        return 1
    fi
    command mktemp "$@"
}

_awgBtInstallHelpers
before="$(stat -c '%i:%a:%u:%s:%Y' "$WORK/libexec/awg-boringtun-launch" "$WORK/libexec/awg-backend-ctl")"
BLOCK_WRITES=1
if ! _awgBtInstallHelpers; then
    echo 'FAIL: identical trusted helpers require a writable installation directory' >&2
    exit 1
fi
[[ "$_AWG_BT_HELPERS_CHANGED" == 0 ]]
[[ "$(stat -c '%i:%a:%u:%s:%Y' "$WORK/libexec/awg-boringtun-launch" "$WORK/libexec/awg-backend-ctl")" == "$before" ]]

# A byte or metadata mismatch must still require a real write, never be
# accepted as an already-installed helper on a read-only filesystem.
printf '\n# changed\n' >> "$WORK/libexec/awg-boringtun-launch"
if _awgBtInstallHelpers; then
    echo 'FAIL: stale helper accepted without replacement' >&2; exit 1
fi
BLOCK_WRITES=0
_awgBtInstallHelpers
[[ "$_AWG_BT_HELPERS_CHANGED" == 1 ]]
chmod 0777 "$WORK/libexec/awg-backend-ctl"
BLOCK_WRITES=1
if _awgBtInstallHelpers; then
    echo 'FAIL: unsafe helper mode accepted without replacement' >&2; exit 1
fi
BLOCK_WRITES=0
_awgBtInstallHelpers
[[ "$_AWG_BT_HELPERS_CHANGED" == 1 ]]
[[ "$(stat -c '%a' "$WORK/libexec/awg-backend-ctl")" == 755 ]]

# The managed-file writer must preserve exact input, including all trailing
# newlines, no trailing newline, and an empty file.
for content in $'one\n\n' 'two' ''; do
    printf '%s' "$content" > "$WORK/expected"
    _awgBtWriteManagedFile "$WORK/libexec/check" 0600 < "$WORK/expected"
    cmp "$WORK/expected" "$WORK/libexec/check"
    BLOCK_WRITES=1
    _awgBtWriteManagedFile "$WORK/libexec/check" 0600 < "$WORK/expected"
    [[ "$_AWG_BT_FILE_CHANGED" == 0 ]]
    BLOCK_WRITES=0
done
ln -s "$WORK/libexec/check" "$WORK/libexec/link"
if _awgBtWriteManagedFile "$WORK/libexec/link" 0600 < "$WORK/expected" 2>/dev/null; then
    echo 'FAIL: symlink accepted as a managed file' >&2; exit 1
fi
echo 'PASS: read-only helper reuse, stale content and unsafe mode rejection, atomic repair, exact bytes, and symlink refusal'
