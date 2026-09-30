#!/usr/bin/env bash
# Kernel-path equivalence of amneziawg-install.sh: the working tree against a
# base revision, for the kernel backend only.
#   1. management scenarios (kernel-scenarios.sh): every transcript identical;
#   2. install and uninstall (kernel-install-uninstall.sh) in a fresh container
#      per distribution: every transcript identical.
# It prints the SHA-256 of both installers and the counts, and fails unless
# every transcript is identical. Not part of CI: it needs Docker and a base
# revision to compare with. Run it from anywhere inside the repository:
#
#   bash tests/equivalence/run-kernel-equivalence.sh <base revision> [distro...]
#
# The default distributions are ubuntu:22.04 ubuntu:24.04 ubuntu:26.04
# debian:11 debian:12. The install/uninstall part runs as root inside the
# containers only.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
BASE="${1:?usage: $0 <base revision> [distro...]}"
shift
DISTROS=("$@")
((${#DISTROS[@]})) || DISTROS=(ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 debian:11 debian:12)

W="$(mktemp -d "${TMPDIR:-/tmp}/kernel-equivalence.XXXXXX")"
trap 'rm -rf -- "${W}"' EXIT
mkdir -p "${W}/in" "${W}/out"
if ! git -C "${PROJECT_ROOT}" show "${BASE}:amneziawg-install.sh" >"${W}/in/base.sh"; then
	echo "ERROR: ${BASE} has no amneziawg-install.sh" >&2
	exit 2
fi
cp -- "${PROJECT_ROOT}/amneziawg-install.sh" "${W}/in/new.sh"
cp -- "${SCRIPT_DIR}/kernel-install-uninstall.sh" "${W}/in/inner.sh"
chmod -R a+rX "${W}/in"
echo "base: $(git -C "${PROJECT_ROOT}" rev-parse "${BASE}") amneziawg-install.sh $(sha256sum "${W}/in/base.sh" | cut -d' ' -f1)"
echo "new:  working tree amneziawg-install.sh $(sha256sum "${W}/in/new.sh" | cut -d' ' -f1)"
RC=0

echo "=== Management scenarios"
bash "${SCRIPT_DIR}/kernel-scenarios.sh" "${W}/in/base.sh" "${W}/scenarios-base" >/dev/null 2>&1
bash "${SCRIPT_DIR}/kernel-scenarios.sh" "${W}/in/new.sh" "${W}/scenarios-new" >/dev/null 2>&1
TOTAL=0
SAME=0
for FILE in "${W}/scenarios-base"/*.txt; do
	[[ -e "${FILE}" ]] || continue
	TOTAL=$((TOTAL + 1))
	if cmp -s "${FILE}" "${W}/scenarios-new/${FILE##*/}"; then
		SAME=$((SAME + 1))
	else
		echo "DIFFERENT: ${FILE##*/}"
		diff "${FILE}" "${W}/scenarios-new/${FILE##*/}" | head -n 20
	fi
done
if [[ "$(find "${W}/scenarios-new" -name '*.txt' | wc -l)" != "${TOTAL}" ]]; then
	echo "DIFFERENT: the two runs wrote different sets of scenarios"
	RC=1
fi
echo "management scenarios identical: ${SAME}/${TOTAL}"
((TOTAL > 0 && SAME == TOTAL)) || RC=1

echo "=== Install and uninstall"
if ! command -v docker >/dev/null 2>&1; then
	echo "ERROR: docker is required for the install/uninstall part"
	exit 1
fi
TOTAL=0
SAME=0
for DISTRO in "${DISTROS[@]}"; do
	TAG="${DISTRO//[:.\/]/_}"
	for VARIANT in base new; do
		docker run --rm -v "${W}/in:/in:ro" -v "${W}/out:/out" "${DISTRO}" \
			bash /in/inner.sh "/in/${VARIANT}.sh" "${TAG}-${VARIANT}" >/dev/null 2>&1
	done
	TOTAL=$((TOTAL + 1))
	if [[ -s "${W}/out/${TAG}-base.txt" ]] && cmp -s "${W}/out/${TAG}-base.txt" "${W}/out/${TAG}-new.txt"; then
		SAME=$((SAME + 1))
		echo "${DISTRO}: identical ($(grep -c . "${W}/out/${TAG}-new.txt") lines; install $(grep -m1 '^rc=' "${W}/out/${TAG}-new.txt"), uninstall $(grep '^rc=' "${W}/out/${TAG}-new.txt" | tail -n 1))"
	else
		echo "${DISTRO}: DIFFERENT"
		diff "${W}/out/${TAG}-base.txt" "${W}/out/${TAG}-new.txt" 2>&1 | head -n 30
	fi
done
echo "install/uninstall transcripts identical: ${SAME}/${TOTAL}"
((TOTAL > 0 && SAME == TOTAL)) || RC=1
exit "${RC}"
