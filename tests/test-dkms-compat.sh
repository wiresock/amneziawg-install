#!/bin/bash
# Compile the actual generated compatibility shim against both UDP tunnel APIs.
# No packages, kernel modules, or system paths are changed.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../amneziawg-install.sh
source "${SCRIPT_DIR}/../amneziawg-install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
PASSED=0
FAILED=0
check() {
	local message="$1"; shift
	if "$@"; then
		PASSED=$((PASSED + 1))
	else
		echo "FAIL: ${message}" >&2
		FAILED=$((FAILED + 1))
	fi
}
make_source() {
	mkdir -p "$1/amneziawg-1.0.0/compat"
	cat >"$1/amneziawg-1.0.0/compat/compat.h" <<'EOF'
/* Exact compatibility macros from upstream commit 0bcc6dfaf9. */
#define setup_udp_tunnel_sock(net, sk, sock_cfg) setup_udp_tunnel_sock(net, sk->sk_socket, sock_cfg)
#define udp_tunnel_sock_release(sk) udp_tunnel_sock_release(sk->sk_socket)
EOF
}
make_source "${WORK}/sources"
HEADER="${WORK}/sources/amneziawg-1.0.0/compat/compat.h"
chmod 640 "${HEADER}"
# Before the fix this intentionally compiles the unpatched upstream macros,
# reproducing the incompatible-pointer error from the real Azure kernel build.
if declare -F patchAwgDkmsUdpTunnelCompat >/dev/null; then
	check 'patch reports one changed source' test "$(patchAwgDkmsUdpTunnelCompat "${WORK}/sources")" = 1
	check 'repeat patch is a no-op' test "$(patchAwgDkmsUdpTunnelCompat "${WORK}/sources")" = 0
fi
check 'source mode is preserved' test "$(stat -c %a "${HEADER}")" = 640
cat >"${WORK}/probe.c" <<'EOF'
#include <assert.h>
struct net { int unused; };
struct udp_tunnel_sock_cfg { int unused; };
struct socket;
struct sock { struct socket *sk_socket; };
struct socket { struct sock *sk; };
static void *setup_seen, *release_seen;
#if SETUP_SOCK
void setup_udp_tunnel_sock(struct net *net, struct sock *sk, struct udp_tunnel_sock_cfg *cfg)
#else
void setup_udp_tunnel_sock(struct net *net, struct socket *sk, struct udp_tunnel_sock_cfg *cfg)
#endif
{ (void)net; (void)cfg; setup_seen = sk; }
#if RELEASE_SOCK
void udp_tunnel_sock_release(struct sock *sk)
#else
void udp_tunnel_sock_release(struct socket *sk)
#endif
{ release_seen = sk; }
#include "compat.h"
int main(void) {
    struct sock sk;
    struct socket socket = { &sk };
    sk.sk_socket = &socket;
    /* These are the expressions used by the upstream socket.c callers. */
    setup_udp_tunnel_sock((struct net *)0, socket.sk, (struct udp_tunnel_sock_cfg *)0);
    udp_tunnel_sock_release(socket.sk);
    assert(setup_seen == (SETUP_SOCK ? (void *)&sk : (void *)&socket));
    assert(release_seen == (RELEASE_SOCK ? (void *)&sk : (void *)&socket));
    return 0;
}
EOF
for setup in 0 1; do
	for release in 0 1; do
		if cc -std=gnu11 -Wall -Wextra -Werror -DSETUP_SOCK="${setup}" -DRELEASE_SOCK="${release}" \
			-I "$(dirname "${HEADER}")" "${WORK}/probe.c" -o "${WORK}/probe" >"${WORK}/compile.log" 2>&1; then
			check "correct pointers: setup=${setup}, release=${release}" "${WORK}/probe"
		else
			cat "${WORK}/compile.log" >&2
			check "compile: setup=${setup}, release=${release}" false
		fi
	done
done

if declare -F patchAwgDkmsUdpTunnelCompat >/dev/null; then
	printf '/* An upstream fix must be left alone. */\n' >"${HEADER}"
	cp "${HEADER}" "${WORK}/expected"
	check 'unknown or newer source is not patched' test "$(patchAwgDkmsUdpTunnelCompat "${WORK}/sources")" = 0
	check 'unknown source bytes unchanged' cmp -s "${HEADER}" "${WORK}/expected"
	check 'absent source is harmless' test "$(patchAwgDkmsUdpTunnelCompat "${WORK}/absent")" = 0

	# Redirect only the source directory; the package wrapper and patch are real.
	eval "$(declare -f patchAwgDkmsUdpTunnelCompat | sed '1s/patchAwgDkmsUdpTunnelCompat/patch_fixture_source/')"
	patchAwgDkmsUdpTunnelCompat() { patch_fixture_source "${WORK}/packages"; }
	package_command() {
		printf '%s\n' "$*" >>"${WORK}/calls"
		if [[ ! -f "${WORK}/packages/amneziawg-1.0.0/compat/compat.h" ]]; then
			make_source "${WORK}/packages"
			return "${FIRST_RC}"
		fi
		cc -std=gnu11 -Werror -DSETUP_SOCK=1 -DRELEASE_SOCK=0 \
			-I "${WORK}/packages/amneziawg-1.0.0/compat" "${WORK}/probe.c" -o "${WORK}/package-probe" || return 90
		"${WORK}/package-probe" || return 91
		return "${SECOND_RC}"
	}
	for FIRST_RC in 0 100; do
		for SECOND_RC in 0 37; do
			rm -rf "${WORK}/packages"
			: >"${WORK}/calls"
			rc=0
			installAwgDebianPackages package_command install -y amneziawg >"${WORK}/output" 2>&1 || rc=$?
			if [[ "${FIRST_RC}" == 0 ]]; then expected_rc=0; expected_calls=1
			else expected_rc="${SECOND_RC}"; expected_calls=2; fi
			check 'package status propagated' test "${rc}" = "${expected_rc}"
			check 'retry occurs only after a failed build and applied patch' test "$(wc -l <"${WORK}/calls")" = "${expected_calls}"
			check 'package arguments preserved' test "$(sort -u "${WORK}/calls")" = 'install -y amneziawg'
			check 'source also patched after a successful install for future kernels' test "$(patchAwgDkmsUdpTunnelCompat)" = 0
		done
	done
	: >"${WORK}/calls"
	unrelated_failure() { echo called >>"${WORK}/calls"; return 42; }
	rc=0
	installAwgDebianPackages unrelated_failure || rc=$?
	check 'unrelated package failure preserved' test "${rc}" = 42
	check 'already patched source does not cause repeated retries' test "$(wc -l <"${WORK}/calls")" = 1
	patchAwgDkmsUdpTunnelCompat() { return 73; }
	rc=0
	installAwgDebianPackages true || rc=$?
	check 'patch write failure is propagated' test "${rc}" != 0

	# Exercise the real kernel-install entry and Ubuntu prerequisite setup with
	# an existing half-configured package. Stop at enable_apt_ipv4, before the
	# installer's system-file writes, and run only mocked package operations.
	run_interrupted_install() (
		OS="$1"
		# shellcheck disable=SC2034 # read by the sourced installAmneziaWG
		AWG_BACKEND="$2"
		# Preserve the scenario outside the patch helper's positional arguments.
		local PATCH_RESULT="$3"
		patchAwgDkmsUdpTunnelCompat() {
			echo patch >>"${WORK}/calls"
			[[ "${PATCH_RESULT}" != fail ]] || return 73
			patch_fixture_source "${WORK}/packages"
		}
		ensureSupportedInstallDistro() { :; }
		selectFreshInstallBackend() { :; }
		selectFreshInstallImitation() { :; }
		installQuestions() { :; }
		installBoringtunHost() { echo boringtun >>"${WORK}/calls"; }
		amneziaPpaSourceEntriesExist() { return 1; }
		configureUbuntuAmneziaPpa() { :; }
		checkAmneziaPpaToolsCandidate() { :; }
		apt-get() { :; }
		apt() { package_command "$@"; }
		enable_apt_ipv4() {
			if [[ "${OS}" == ubuntu ]]; then
				prepareUbuntuAmneziaPpaForInstall
			else
				# Debian can also install key-import prerequisites before DKMS.
				apt install -y gnupg || exit 1
			fi
			echo prerequisites-complete >>"${WORK}/calls"
			exit 0
		}
		installAmneziaWG
	)
	FIRST_RC=100 SECOND_RC=0
	for distro in ubuntu debian; do
		make_source "${WORK}/packages"
		: >"${WORK}/calls"
		rc=0
		run_interrupted_install "${distro}" kernel ok >"${WORK}/output" 2>&1 || rc=$?
		check "${distro}: interrupted install recovers" test "${rc}" = 0
		check "${distro}: patch precedes prerequisite packages" test "$(head -n 1 "${WORK}/calls")" = patch
		check "${distro}: prerequisites compile the recovered source" grep -qx prerequisites-complete "${WORK}/calls"
	done
	: >"${WORK}/calls"
	rc=0
	run_interrupted_install ubuntu kernel fail >"${WORK}/output" 2>&1 || rc=$?
	check 'early patch failure stops kernel installation' test "${rc}" != 0
	check 'early patch failure runs no package commands' test "$(cat "${WORK}/calls")" = patch
	: >"${WORK}/calls"
	rc=0
	run_interrupted_install ubuntu "${AWG_BACKEND_BORINGTUN}" fail >"${WORK}/output" 2>&1 || rc=$?
	check 'BoringTun installation remains successful' test "${rc}" = 0
	check 'BoringTun never patches kernel source' test "$(cat "${WORK}/calls")" = boringtun
fi
printf 'DKMS compatibility tests: %s passed, %s failed\n' "${PASSED}" "${FAILED}"
[[ "${FAILED}" == 0 ]]
