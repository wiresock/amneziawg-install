#!/usr/bin/env bash
# Exercise the real helper dispatcher while replacing only the trusted-script
# resolver with a temporary fixture. No system files or services are modified.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
# Load function definitions without executing the CLI entry point.
# shellcheck disable=SC1090
source <(sed '/^main "\$@"$/d' "$ROOT/amneziawg-web/scripts/amneziawg-web-privileged")
require_root() { :; }
resolve_awg_install_script() { printf '%s\n' "$WORK/installer"; }
cat > "$WORK/installer" <<'EOF'
#!/usr/bin/env bash
AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST="boringtun-host-v1"
[[ $# == 1 && $1 == --backend-status ]] || exit 90
case "$1" in
    --set-boringtun-imitation|--backend-status)
        ;;
    *) exit 90 ;;
esac
if [[ "${TEST_KERNEL_STATUS:-}" == 1 ]]; then
    printf '%s\n' 'backend=kernel' 'awg_protocol=3.1' 'service_state=active' 'module_state=loaded' 'SERVER_PRIV_KEY=must-not-escape'
    exit 0
fi
printf '%s\n' 'backend=boringtun' 'awg_protocol=2.0' 'service_state=active' 'daemon_state=running' 'daemon_release=boringtun-cli-0.7.1-gae2ab44e9a68-linux-x86_64-musl' 'imitation_protocol=quic' 'imitation_domain=example.com' 'daemon_imitation_protocol=dns' 'daemon_imitation_domain=' 'SERVER_PRIV_KEY=must-not-escape'
exit "${TEST_STATUS_EXIT:-0}"
EOF
chmod 700 "$WORK/installer"
output="$(main backend-status)"
[[ "$output" == $'backend=boringtun\nawg_protocol=2.0\nservice_state=active\ndaemon_state=running\ndaemon_release=boringtun-cli-0.7.1-gae2ab44e9a68-linux-x86_64-musl\nimitation_protocol=quic\nimitation_domain=example.com\ndaemon_imitation_protocol=dns\ndaemon_imitation_domain=' ]]
export TEST_KERNEL_STATUS=1
output="$(main backend-status)"
[[ "$output" == $'backend=kernel\nawg_protocol=3.1\nservice_state=active\nmodule_state=loaded' ]]
unset TEST_KERNEL_STATUS
if (main backend-status extra) > "$WORK/rejected" 2>/dev/null; then
    echo 'FAIL: extra arguments accepted'; exit 1
fi
[[ ! -s "$WORK/rejected" ]]
export TEST_STATUS_EXIT=1
if (main backend-status) > "$WORK/failed" 2>/dev/null; then
    echo 'FAIL: failed inspection accepted'; exit 1
fi
[[ ! -s "$WORK/failed" ]]
unset TEST_STATUS_EXIT
# Legacy installers treat unknown flags as interactive management. The status
# probe must reject them before executing anything, even if executable/trusted.
cat > "$WORK/installer" <<EOF
#!/usr/bin/env bash
AWG_INSTALLER_CAPABILITY_BORINGTUN_HOST="boringtun-host-v1"
touch "$WORK/legacy-was-executed"
EOF
if (main backend-status) > "$WORK/legacy-output" 2>/dev/null; then
    echo 'FAIL: legacy installer accepted'; exit 1
fi
[[ ! -e "$WORK/legacy-was-executed" && ! -s "$WORK/legacy-output" ]]
echo 'PASS: fixed read-only command, filtered output, argument rejection, failure handling, and legacy installer is never executed'
