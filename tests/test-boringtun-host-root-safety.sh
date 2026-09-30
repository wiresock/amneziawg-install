#!/bin/bash
# Root safety of tests/test-boringtun-host.sh, which exercises the real
# uninstall with every path redirected below its private test root:
#   1. run as root without AWG_DISPOSABLE_HOST_TEST=1, it refuses before any
#      test section and changes nothing;
#   2. run as root with it, on a host whose real paths hold sentinel files
#      (the kernel boot entry, the sysctl file, the drop-in, the APT sources
#      and keyring, the load override), it passes, and no file under /etc,
#      /usr/local, /run, /root or /home changes: only the test root does.
#
# Designed to run inside a disposable Docker container as root, with python3
# and iproute2 (ss) installed:
#   docker run --rm -v "$PWD:/workspace:ro" -w /workspace ubuntu:24.04 \
#     bash -c 'apt-get update && apt-get install -y python3 iproute2 && bash tests/test-boringtun-host-root-safety.sh'

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITE="${SCRIPT_DIR}/test-boringtun-host.sh"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "ERROR: This test must be run as root (in a disposable container)"
	exit 1
fi
if [[ ! -f /.dockerenv ]] && ! grep -qE '(/docker|/lxc)' /proc/1/cgroup 2>/dev/null; then
	echo "ERROR: This test must run inside a container. Refusing to modify a real host."
	exit 1
fi

PASS=0
FAIL=0
ok() {
	echo "  OK: $1"
	PASS=$((PASS + 1))
}
not_ok() {
	echo "  FAIL: $1"
	FAIL=$((FAIL + 1))
}
check() { # <label> <command...>
	local LABEL="$1"
	shift
	if "$@"; then ok "${LABEL}"; else not_ok "${LABEL}"; fi
}

# Every regular file, symlink and socket below the watched trees, with its
# content hash or target: a created, changed or deleted node shows up.
snapshot() {
	find /etc /usr/local /run /root /home -xdev \( -type f -o -type l -o -type s \) -print0 2>/dev/null |
		LC_ALL=C sort -z |
		while IFS= read -r -d '' NODE; do
			if [[ -L "${NODE}" ]]; then
				printf '%s -> %s\n' "${NODE}" "$(readlink -- "${NODE}")"
			elif [[ -f "${NODE}" ]]; then
				printf '%s %s\n' "${NODE}" "$(sha256sum -- "${NODE}" | cut -d' ' -f1)"
			else
				printf '%s socket\n' "${NODE}"
			fi
		done
}

SENTINELS=(/etc/modules-load.d/amneziawg.conf /etc/sysctl.d/awg.conf
	/etc/systemd/system/awg-quick@awg0.service.d/override.conf
	/etc/apt/sources.list.d/amneziawg.sources /etc/apt/sources.list.d/amneziawg.sources.list
	/etc/apt/keyrings/amneziawg.gpg /etc/modprobe.d/amneziawg-install-boringtun.conf
	/etc/apt/apt.conf.d/99amneziawg-force-ipv4)
for FILE in "${SENTINELS[@]}"; do
	mkdir -p "${FILE%/*}"
	printf '# Managed by amneziawg-install\nsentinel for %s\n' "${FILE}" >"${FILE}"
done
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "=== As root without AWG_DISPOSABLE_HOST_TEST=1"
snapshot >"${WORK}/before"
env -u AWG_DISPOSABLE_HOST_TEST bash "${SUITE}" >"${WORK}/refused.log" 2>&1
RC=$?
check "the suite refuses to run" test "${RC}" -ne 0
check "  saying why" grep -q "AWG_DISPOSABLE_HOST_TEST=1" "${WORK}/refused.log"
check "  before any test section" bash -c '! grep -q "^===" "$1"' _ "${WORK}/refused.log"
snapshot >"${WORK}/after-refused"
check "  and changes nothing" cmp -s "${WORK}/before" "${WORK}/after-refused"

echo "=== As root with AWG_DISPOSABLE_HOST_TEST=1, sentinels at the real paths"
AWG_DISPOSABLE_HOST_TEST=1 bash "${SUITE}" >"${WORK}/suite.log" 2>&1
RC=$?
grep -E '^BoringTun host tests:' "${WORK}/suite.log" | sed 's/^/    | /'
check "the suite passes as root" test "${RC}" -eq 0
snapshot >"${WORK}/after"
if cmp -s "${WORK}/before" "${WORK}/after"; then
	ok "no file under /etc, /usr/local, /run, /root or /home changed ($(grep -c . "${WORK}/before") nodes compared)"
else
	not_ok "files outside the test root changed:"
	diff "${WORK}/before" "${WORK}/after" | sed 's/^/    /' | head -n 40
fi
for FILE in "${SENTINELS[@]}"; do
	check "  ${FILE} is intact" grep -q "sentinel for ${FILE}" "${FILE}"
done

echo
echo "BoringTun host tests root safety: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
