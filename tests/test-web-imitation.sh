#!/usr/bin/env bash
# Exercise the real privileged boundary with a trusted-installer fixture.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
# shellcheck disable=SC1090
source <(sed '/^main "\$@"$/d' "$ROOT/amneziawg-web/scripts/amneziawg-web-privileged")
installer_supports_boringtun_imitation "$ROOT/amneziawg-install.sh"
require_root() { :; }
resolve_awg_install_script() { printf '%s\n' "$WORK/installer"; }
export TEST_IMITATION_ARGS="$WORK/args"
cat > "$WORK/installer" <<'EOF'
#!/usr/bin/env bash
AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST="boringtun-host-v1"
[[ $# == 3 ]] || exit 91
case "$1" in
    --set-boringtun-imitation|--backend-status)
        printf '%s\n' "$@" > "$TEST_IMITATION_ARGS"
        ;;
    *) exit 90 ;;
esac
echo 'SERVER_PRIV_KEY=must-not-escape'
echo 'SERVER_PRIV_KEY=must-not-escape' >&2
exit "${TEST_IMITATION_EXIT:-0}"
EOF
chmod 700 "$WORK/installer"
for protocol in none dns quic sip stun; do
    output="$(main set-boringtun-imitation "$protocol" '')"
    [[ -z "$output" ]]
    [[ "$(cat "$WORK/args")" == "$(printf '%s\n' --set-boringtun-imitation "$protocol")" ]]
done
output="$(main set-boringtun-imitation quic example.com)"
[[ -z "$output" ]]
[[ "$(cat "$WORK/args")" == $'--set-boringtun-imitation\nquic\nexample.com' ]]
reject() {
    rm -f "$WORK/args"
    if (main set-boringtun-imitation "$@") > "$WORK/rejected" 2>&1; then
        echo 'FAIL: invalid imitation arguments accepted'; exit 1
    fi
    [[ ! -e "$WORK/args" ]]
    ! grep -q must-not-escape "$WORK/rejected"
}
reject
reject quic
reject quic example.com extra
reject invalid ''
reject none example.com
reject stun example.com
for domain in '-bad.test' 'bad-.test' 'bad..test' 'bad.test.' 'https://example.com' 'bad_name' 'bad name' '$bad' $'bad\nname' "$(printf '%064d' 0).test"; do
    reject dns "$domain"
done
export TEST_IMITATION_EXIT=1
if (main set-boringtun-imitation quic example.com) > "$WORK/failed" 2>&1; then
    echo 'FAIL: installer failure accepted'; exit 1
fi
! grep -q must-not-escape "$WORK/failed"
unset TEST_IMITATION_EXIT
cat > "$WORK/installer" <<EOF
#!/usr/bin/env bash
AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST="boringtun-host-v1"
touch "$WORK/legacy-was-executed"
EOF
reject quic example.com
[[ ! -e "$WORK/legacy-was-executed" ]]
echo 'PASS: imitation argv validation, supported modes, suppressed installer output, failure and legacy rejection'
