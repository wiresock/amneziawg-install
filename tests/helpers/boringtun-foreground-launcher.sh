#!/usr/bin/env bash

# CI-only stand-in for boringtun-cli in BoringTun's upstream interop harnesses.
# It is never installed on a target system.
#
# At the pinned commit, scripts/awg-go-interop.sh and scripts/awg31-interop.sh
# start `boringtun-cli --disable-drop-privileges [flags] <iface>` without -f, so
# the daemon forks itself into the background, and then wait for its UAPI
# socket. The planned runtime instead runs `boringtun-cli --foreground` under a
# service manager, and the self-daemonizing path has hung on native aarch64
# (docs/BORINGTUN_ARTIFACTS.md). The workflow passes this file to the harnesses
# as their <boringtun-cli>. It starts the packaged binary, named by the absolute
# path in BORINGTUN_REAL_CLI, with --foreground and the harness's own arguments
# as an asynchronous child, and returns, which keeps the harnesses' contract:
# the launch command returns, then they wait for the socket.
#
# The child keeps the caller's network namespace, session and process group, so
# the harnesses' `ip netns pids | kill` teardown still stops it. In the
# foreground BoringTun logs to stdout and ignores WG_LOG_FILE, which the
# harnesses set and print on failure, so the child's output goes to that file
# when it is set.
#
# Success means only that the child started and did not exit at once. Whether
# the daemon is ready is still the harness's wait for the socket.

set -uo pipefail

die() {
	printf 'boringtun-foreground-launcher: %s\n' "$1" >&2
	exit 1
}

REAL="${BORINGTUN_REAL_CLI:-}"
[[ -n "${REAL}" ]] || die "BORINGTUN_REAL_CLI is not set"
[[ "${REAL}" == /* ]] || die "BORINGTUN_REAL_CLI is not an absolute path: ${REAL}"
[[ -f "${REAL}" && -x "${REAL}" ]] || die "BORINGTUN_REAL_CLI is not an executable file: ${REAL}"
[[ ! "${REAL}" -ef "${BASH_SOURCE[0]}" ]] || die "BORINGTUN_REAL_CLI names this launcher: ${REAL}"
# A copy of this launcher at that path then stops at the first check instead of
# starting itself again.
unset BORINGTUN_REAL_CLI

# --foreground exactly once. Arguments after `--` are positional, not flags.
ARGS=(--foreground)
for ARG in "$@"; do
	case "${ARG}" in
	--) break ;;
	-f | --foreground)
		ARGS=()
		break
		;;
	esac
done
ARGS+=("$@")

if [[ -n "${WG_LOG_FILE:-}" ]]; then
	"${REAL}" "${ARGS[@]}" >"${WG_LOG_FILE}" 2>&1 &
else
	"${REAL}" "${ARGS[@]}" &
fi
PID=$!

# A foreground boringtun-cli does not exit on its own, while one that cannot be
# executed or rejects its arguments exits within milliseconds. Report that here
# rather than as a missing socket. An exited child stays a zombie until waited
# for, so its state is read rather than probed with `kill -0`.
sleep 0.2
STATE="$(cat "/proc/${PID}/stat" 2>/dev/null)"
STATE="${STATE##*) }"
if [[ -z "${STATE}" || "${STATE:0:1}" == Z ]]; then
	wait "${PID}"
	die "${REAL} exited at once with status $?"
fi
exit 0
