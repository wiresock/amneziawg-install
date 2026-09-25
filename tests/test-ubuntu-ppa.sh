#!/bin/bash
# Unit and fixture tests for Ubuntu Amnezia PPA suite selection and source
# reconciliation. All APT source files live under a temporary directory.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=../amneziawg-install.sh
source "${PROJECT_ROOT}/amneziawg-install.sh"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT}"' EXIT

function pass() {
	TESTS_RUN=$((TESTS_RUN + 1))
	TESTS_PASSED=$((TESTS_PASSED + 1))
}

function fail() {
	local MESSAGE="$1"
	TESTS_RUN=$((TESTS_RUN + 1))
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "  FAIL: ${MESSAGE}"
}

function assert_eq() {
	local EXPECTED="$1"
	local ACTUAL="$2"
	local MESSAGE="$3"
	if [[ "${EXPECTED}" == "${ACTUAL}" ]]; then
		pass
	else
		fail "${MESSAGE} (expected '${EXPECTED}', got '${ACTUAL}')"
	fi
}

function assert_rc() {
	local EXPECTED="$1"
	local ACTUAL="$2"
	local MESSAGE="$3"
	if [[ "${EXPECTED}" -eq "${ACTUAL}" ]]; then
		pass
	else
		fail "${MESSAGE} (expected rc=${EXPECTED}, got rc=${ACTUAL})"
	fi
}

function assert_file_eq() {
	local EXPECTED="$1"
	local ACTUAL="$2"
	local MESSAGE="$3"
	if cmp -s "${EXPECTED}" "${ACTUAL}"; then
		pass
	else
		fail "${MESSAGE}"
		diff -u "${EXPECTED}" "${ACTUAL}" || true
	fi
}

function assert_contains() {
	local PATTERN="$1"
	local FILE="$2"
	local MESSAGE="$3"
	if grep -Eq "${PATTERN}" "${FILE}"; then
		pass
	else
		fail "${MESSAGE}"
	fi
}

function assert_not_contains() {
	local PATTERN="$1"
	local FILE="$2"
	local MESSAGE="$3"
	if grep -Eq "${PATTERN}" "${FILE}"; then
		fail "${MESSAGE}"
	else
		pass
	fi
}

echo "=== Ubuntu PPA codename and mapping ==="
OUTPUT=$(ID=ubuntu VERSION_CODENAME=resolute UBUNTU_CODENAME="" getUbuntuPpaCodename)
assert_eq "resolute" "${OUTPUT}" "Ubuntu uses VERSION_CODENAME"
OUTPUT=$(ID=linuxmint VERSION_CODENAME=wilma UBUNTU_CODENAME=noble getUbuntuPpaCodename)
assert_eq "noble" "${OUTPUT}" "Linux Mint uses UBUNTU_CODENAME"
assert_eq "noble" "$(getAmneziaPpaFallbackSuite resolute)" "reviewed Resolute fallback is Noble"
getAmneziaPpaFallbackSuite future >/dev/null 2>&1
assert_rc 1 "$?" "unknown future suite has no fallback"
isAmneziaPpaFallbackArchitectureSupported amd64
assert_rc 0 "$?" "amd64 fallback architecture is supported"
isAmneziaPpaFallbackArchitectureSupported i386
assert_rc 1 "$?" "i386 fallback is rejected because tools are absent"

echo "=== PPA availability selection ==="
PROBE_LOG="${TEST_ROOT}/probe.log"
ERROR_LOG="${TEST_ROOT}/probe.err"
: > "${PROBE_LOG}"
(
	function getAmneziaPpaHttpStatus() {
		printf '%s\n' "$1" >> "${PROBE_LOG}"
		printf '%s\n' 200
	}
	probeAmneziaPpaSuite resolute
)
assert_rc 0 "$?" "HTTP 200 InRelease marks a suite available"
assert_eq "1" "$(wc -l < "${PROBE_LOG}" | tr -d ' ')" "available suite does not need a Release probe"

: > "${PROBE_LOG}"
(
	function getAmneziaPpaHttpStatus() {
		printf '%s\n' "$1" >> "${PROBE_LOG}"
		printf '%s\n' 404
	}
	probeAmneziaPpaSuite resolute
)
assert_rc 1 "$?" "two definite metadata 404s mark a suite unavailable"
assert_eq "2" "$(wc -l < "${PROBE_LOG}" | tr -d ' ')" "unavailable suite checks InRelease and Release"

: > "${PROBE_LOG}"
(
	function getAmneziaPpaHttpStatus() {
		printf '%s\n' "$1" >> "${PROBE_LOG}"
		if [[ "$1" == */InRelease ]]; then
			printf '%s\n' 404
		else
			printf '%s\n' 503
		fi
	}
	probeAmneziaPpaSuite resolute
)
assert_rc 2 "$?" "HTTP 5xx after one 404 leaves suite status unknown"

(
	function getAmneziaPpaHttpStatus() {
		printf '%s\n' 302
	}
	probeAmneziaPpaSuite resolute
)
assert_rc 2 "$?" "HTTP redirects leave suite status unknown"

echo "=== PPA HTTP backend redirect handling ==="
REDIRECT_URL="https://example.invalid/redirect"

CURL_STUB_DIR="${TEST_ROOT}/curl-stub"
mkdir -p "${CURL_STUB_DIR}"
cat > "${CURL_STUB_DIR}/curl" <<'SH'
#!/bin/bash
FIRST_ARGUMENT="${1:-}"
FOLLOW_REDIRECT=0
for ARG in "$@"; do
	case "${ARG}" in
		--location | -L | --location-trusted) FOLLOW_REDIRECT=1 ;;
	esac
done
if [[ "${FIRST_ARGUMENT}" == "--disable" && "${FOLLOW_REDIRECT}" -eq 0 ]]; then
	printf '%s\n' 302
else
	printf '%s\n' 200
fi
SH
chmod +x "${CURL_STUB_DIR}/curl"
OUTPUT=$(PATH="${CURL_STUB_DIR}" getAmneziaPpaHttpStatus "${REDIRECT_URL}")
RC=$?
assert_rc 0 "${RC}" "curl backend returns a direct redirect status"
assert_eq "302" "${OUTPUT}" "curl backend disables config first and does not follow redirects"

WGET_STUB_DIR="${TEST_ROOT}/wget-stub"
mkdir -p "${WGET_STUB_DIR}"
ln -s "$(command -v awk)" "${WGET_STUB_DIR}/awk"
cat > "${WGET_STUB_DIR}/wget" <<'SH'
#!/bin/bash
NO_FOLLOW=0
for ARG in "$@"; do
	if [[ "${ARG}" == "--max-redirect=0" ]]; then
		NO_FOLLOW=1
	fi
done
printf '%s\n' "  HTTP/1.1 302 Found" >&2
if [[ "${NO_FOLLOW}" -eq 1 ]]; then
	exit 8
fi
printf '%s\n' "  HTTP/1.1 200 OK" >&2
SH
chmod +x "${WGET_STUB_DIR}/wget"
OUTPUT=$(PATH="${WGET_STUB_DIR}" getAmneziaPpaHttpStatus "${REDIRECT_URL}")
RC=$?
assert_rc 0 "${RC}" "wget backend returns a direct redirect status"
assert_eq "302" "${OUTPUT}" "wget backend does not follow redirects"

PYTHON_STUB_DIR="${TEST_ROOT}/python-stub"
mkdir -p "${PYTHON_STUB_DIR}"
cat > "${PYTHON_STUB_DIR}/python3" <<'SH'
#!/bin/bash
SCRIPT=""
while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
	SCRIPT+="${LINE}"$'\n'
done
if [[ "${SCRIPT}" == *"HTTPRedirectHandler"* \
	&& "${SCRIPT}" == *"redirect_request"* \
	&& "${SCRIPT}" == *"build_opener"* \
	&& "${SCRIPT}" != *"urllib.request.urlopen("* ]]; then
	printf '%s\n' 302
else
	printf '%s\n' 200
fi
SH
chmod +x "${PYTHON_STUB_DIR}/python3"
OUTPUT=$(PATH="${PYTHON_STUB_DIR}" getAmneziaPpaHttpStatus "${REDIRECT_URL}")
RC=$?
assert_rc 0 "${RC}" "Python backend returns a direct redirect status"
assert_eq "302" "${OUTPUT}" "Python backend installs a no-redirect handler"

: > "${PROBE_LOG}"
OUTPUT=$(
	(
		function probeAmneziaPpaSuite() {
			printf '%s\n' "$1" >> "${PROBE_LOG}"
			[[ "$1" == "resolute" ]]
		}
		selectAmneziaPpaSuite resolute amd64
	) 2>"${ERROR_LOG}"
)
RC=$?
assert_rc 0 "${RC}" "native Resolute selection succeeds when metadata exists"
assert_eq "resolute" "${OUTPUT}" "native suite is preferred"
assert_eq "resolute" "$(tr '\n' ' ' < "${PROBE_LOG}" | sed 's/[[:space:]]*$//')" "fallback is not probed when native exists"

: > "${PROBE_LOG}"
OUTPUT=$(
	(
		function probeAmneziaPpaSuite() {
			printf '%s\n' "$1" >> "${PROBE_LOG}"
			[[ "$1" == "noble" ]]
		}
		selectAmneziaPpaSuite resolute amd64
	) 2>"${ERROR_LOG}"
)
RC=$?
assert_rc 0 "${RC}" "Noble selection succeeds after definite Resolute absence"
assert_eq "noble" "${OUTPUT}" "reviewed fallback suite is selected"
assert_eq "resolute noble" "$(tr '\n' ' ' < "${PROBE_LOG}" | sed 's/[[:space:]]*$//')" "native is probed before fallback"
assert_contains 'WARNING:.*noble' "${ERROR_LOG}" "fallback warning names Noble"

: > "${PROBE_LOG}"
(
	function probeAmneziaPpaSuite() {
		printf '%s\n' "$1" >> "${PROBE_LOG}"
		return 2
	}
	selectAmneziaPpaSuite resolute amd64
) > /dev/null 2>"${ERROR_LOG}"
RC=$?
assert_rc 1 "${RC}" "temporary native probe failure is fatal"
assert_eq "resolute" "$(tr '\n' ' ' < "${PROBE_LOG}" | sed 's/[[:space:]]*$//')" "network failure never probes or selects fallback"
assert_contains 'No cross-release fallback was applied' "${ERROR_LOG}" "network failure is explained"

(
	function probeAmneziaPpaSuite() { return 1; }
	selectAmneziaPpaSuite future amd64
) > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "unknown unsupported Ubuntu release is rejected"

(
	function probeAmneziaPpaSuite() { return 1; }
	selectAmneziaPpaSuite resolute i386
) > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "fallback is rejected on an unpublished tools architecture"

echo "=== DEB822 source rewriting ==="
DEB822_DIR="${TEST_ROOT}/deb822"
mkdir -p "${DEB822_DIR}"
cat > "${DEB822_DIR}/combined.sources" <<'EOF'
# Official Ubuntu repository must stay byte-for-byte identical.
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: resolute resolute-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb deb-src
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 keep-this-inline-key-material
 -----END PGP PUBLIC KEY BLOCK-----

# Another unrelated stanza.
Types: deb
URIs: https://packages.example.test/amnezia/ubuntu
Suites: resolute
Components: main
EOF
cat > "${TEST_ROOT}/combined.expected" <<'EOF'
# Official Ubuntu repository must stay byte-for-byte identical.
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: resolute resolute-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb deb-src
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: noble
Components: main
Architectures: amd64
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 keep-this-inline-key-material
 -----END PGP PUBLIC KEY BLOCK-----

# Another unrelated stanza.
Types: deb
URIs: https://packages.example.test/amnezia/ubuntu
Suites: resolute
Components: main
EOF

cat > "${DEB822_DIR}/amneziawg.sources" <<'EOF'
# Managed auxiliary source file whose name contains amnezia.
Types: deb-src
URIs: http://archive.ubuntu.com/ubuntu
Suites: resolute
Components: main
EOF
cp "${DEB822_DIR}/amneziawg.sources" "${TEST_ROOT}/amneziawg.expected"
MODE_BEFORE=$(stat -c '%a' "${DEB822_DIR}/combined.sources")
setAmneziaPpaSuite noble "${DEB822_DIR}" amd64
RC=$?
assert_rc 0 "${RC}" "DEB822 target stanza is rewritten"
assert_file_eq "${TEST_ROOT}/combined.expected" "${DEB822_DIR}/combined.sources" "only the matching DEB822 stanza changes: selected suite and native architecture"
assert_file_eq "${TEST_ROOT}/amneziawg.expected" "${DEB822_DIR}/amneziawg.sources" "filename containing amnezia does not cause unrelated rewrite"
assert_eq "${MODE_BEFORE}" "$(stat -c '%a' "${DEB822_DIR}/combined.sources")" "DEB822 file mode is preserved"

CHECKSUM_BEFORE=$(cksum "${DEB822_DIR}/combined.sources")
setAmneziaPpaSuite noble "${DEB822_DIR}" amd64
assert_rc 0 "$?" "already-correct Noble DEB822 entry succeeds"
CHECKSUM_AFTER=$(cksum "${DEB822_DIR}/combined.sources")
assert_eq "${CHECKSUM_BEFORE}" "${CHECKSUM_AFTER}" "DEB822 rewrite is idempotent"

RERUN_DIR="${TEST_ROOT}/partial-rerun"
mkdir -p "${RERUN_DIR}"
cat > "${RERUN_DIR}/partial-rerun.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: noble resolute
Components: main
Signed-By: keep-key
EOF
setAmneziaPpaSuite noble "${RERUN_DIR}" amd64
assert_rc 0 "$?" "suite list created by add-apt-repository rerun is repaired"
assert_contains '^Suites: noble$' "${RERUN_DIR}/partial-rerun.sources" "rerun repair removes the broken native suite"

MULTILINE_DIR="${TEST_ROOT}/multiline-suite"
mkdir -p "${MULTILINE_DIR}"
cat > "${MULTILINE_DIR}/multiline.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites:
 resolute
Components: main
EOF
setAmneziaPpaSuite noble "${MULTILINE_DIR}" amd64
assert_rc 0 "$?" "valid multiline DEB822 Suites field is normalized"
assert_contains '^Suites:[[:space:]]*noble$' "${MULTILINE_DIR}/multiline.sources" "multiline suite is replaced with the selected suite"
assert_not_contains '^[[:space:]]+resolute$' "${MULTILINE_DIR}/multiline.sources" "stale suite continuation is removed"

COMMENT_CONTINUATION_DIR="${TEST_ROOT}/comment-continuation"
mkdir -p "${COMMENT_CONTINUATION_DIR}"
cat > "${COMMENT_CONTINUATION_DIR}/comments.sources" <<'EOF'
Types: deb
URIs:
# comment inside the logical URIs field
 https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites:
# comment inside the logical Suites field
 resolute
Components: main
EOF
setAmneziaPpaSuite noble "${COMMENT_CONTINUATION_DIR}" amd64
assert_rc 0 "$?" "DEB822 comments do not terminate a logical multiline field"
assert_contains '^# comment inside the logical URIs field$' "${COMMENT_CONTINUATION_DIR}/comments.sources" "URI field comment is preserved"
assert_contains '^# comment inside the logical Suites field$' "${COMMENT_CONTINUATION_DIR}/comments.sources" "Suites field comment is preserved"
assert_contains '^Suites:[[:space:]]*noble$' "${COMMENT_CONTINUATION_DIR}/comments.sources" "commented multiline Suites field is normalized"

echo "=== Legacy source rewriting ==="
LEGACY_DIR="${TEST_ROOT}/legacy"
mkdir -p "${LEGACY_DIR}"
cat > "${LEGACY_DIR}/mixed.list" <<'EOF'
# resolute in this comment must stay unchanged
deb [arch=amd64 signed-by=/key.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/ resolute main # keep trailing comment
deb https://archive.ubuntu.com/ubuntu resolute main
deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu.evil resolute main
# deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
cat > "${TEST_ROOT}/mixed.expected" <<'EOF'
# resolute in this comment must stay unchanged
deb [arch=amd64 signed-by=/key.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main
deb-src [arch=amd64] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/ noble main # keep trailing comment
deb https://archive.ubuntu.com/ubuntu resolute main
deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu.evil resolute main
# deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${LEGACY_DIR}" amd64
assert_rc 0 "$?" "legacy deb and deb-src entries are rewritten"
assert_file_eq "${TEST_ROOT}/mixed.expected" "${LEGACY_DIR}/mixed.list" "legacy rewrite changes only the exact suite field and native arch option"
CHECKSUM_BEFORE=$(cksum "${LEGACY_DIR}/mixed.list")
setAmneziaPpaSuite noble "${LEGACY_DIR}" amd64
assert_rc 0 "$?" "already-correct legacy entries succeed"
assert_eq "${CHECKSUM_BEFORE}" "$(cksum "${LEGACY_DIR}/mixed.list")" "legacy rewrite is idempotent"

COMMENT_DIR="${TEST_ROOT}/legacy-comment"
mkdir -p "${COMMENT_DIR}"
printf '%s\n' \
	'deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main#comment-without-space' \
	> "${COMMENT_DIR}/comment.list"
setAmneziaPpaSuite noble "${COMMENT_DIR}" amd64
assert_rc 0 "$?" "legacy inline comment does not require preceding whitespace"
assert_contains ' noble main#comment-without-space$' "${COMMENT_DIR}/comment.list" "legacy no-space comment is preserved"

QUOTED_URI_DIR="${TEST_ROOT}/quoted-legacy-uri"
mkdir -p "${QUOTED_URI_DIR}"
cat > "${QUOTED_URI_DIR}/quoted.list" <<'EOF'
deb "https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu" resolute main
EOF
setAmneziaPpaSuite noble "${QUOTED_URI_DIR}" amd64
assert_rc 0 "$?" "APT-valid quoted legacy PPA URI is recognized"
assert_contains '^deb \[arch=amd64\] "https://ppa\.launchpadcontent\.net/amnezia/ppa/ubuntu" noble main$' "${QUOTED_URI_DIR}/quoted.list" "quoted URI is preserved while its suite changes"

ENCODED_URI_DIR="${TEST_ROOT}/encoded-legacy-uri"
mkdir -p "${ENCODED_URI_DIR}"
cat > "${ENCODED_URI_DIR}/encoded.list" <<'EOF'
deb https%3a%2f%2fppa.launchpadcontent.net%2famnezia%2fppa%2fubuntu resolute main
EOF
setAmneziaPpaSuite noble "${ENCODED_URI_DIR}" amd64
assert_rc 0 "$?" "APT percent-encoded exact legacy PPA URI is recognized"
assert_contains '^deb \[arch=amd64\] https%3a%2f%2fppa\.launchpadcontent\.net%2famnezia%2fppa%2fubuntu noble main$' "${ENCODED_URI_DIR}/encoded.list" "encoded URI spelling is preserved while its suite changes"

SINGLE_QUOTED_URI_DIR="${TEST_ROOT}/single-quoted-legacy-uri"
mkdir -p "${SINGLE_QUOTED_URI_DIR}"
cat > "${SINGLE_QUOTED_URI_DIR}/single-quoted.list" <<'EOF'
deb 'https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu' resolute main
EOF
setAmneziaPpaSuite noble "${SINGLE_QUOTED_URI_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "single-quoted legacy URI is not misclassified as APT dequoted"
assert_contains ' resolute main$' "${SINGLE_QUOTED_URI_DIR}/single-quoted.list" "unsupported single-quoted URI remains untouched"

BRACKET_COMMENT_DIR="${TEST_ROOT}/bracket-comment"
mkdir -p "${BRACKET_COMMENT_DIR}"
cat > "${BRACKET_COMMENT_DIR}/bracket-comment.list" <<'EOF'
deb [foo=bar#baz] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${BRACKET_COMMENT_DIR}" amd64
assert_rc 0 "$?" "legacy hash inside an option bracket does not start an APT comment"
assert_contains ' noble main$' "${BRACKET_COMMENT_DIR}/bracket-comment.list" "bracket-contained hash option is preserved"

NO_NEWLINE_DIR="${TEST_ROOT}/no-final-newline"
mkdir -p "${NO_NEWLINE_DIR}"
printf '%s' \
	'deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main' \
	> "${NO_NEWLINE_DIR}/no-newline.list"
setAmneziaPpaSuite noble "${NO_NEWLINE_DIR}" amd64
assert_rc 0 "$?" "source without a final newline is rewritten"
assert_contains ' noble main$' "${NO_NEWLINE_DIR}/no-newline.list" "source without final newline receives the selected suite"
assert_eq "0" "$(tail -c 1 "${NO_NEWLINE_DIR}/no-newline.list" | wc -l | tr -d ' ')" "rewrite preserves absence of a final newline"

echo "=== Native architecture pinning (DEB822) ==="
# With APT architecture variants enabled, an unpinned PPA source whose Release
# file lists amd64v3 is read only through that index, which Launchpad publishes
# without amneziawg-tools. The managed entry is pinned to the dpkg architecture.
ARCH_DIR="${TEST_ROOT}/native-arch"

# write_ppa_deb822 <file> [lines after Components...]
function write_ppa_deb822() {
	local FILE="$1"
	shift
	{
		printf '%s\n' '# Managed Amnezia PPA entry; this comment stays.' 'Types: deb' \
			'URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/' \
			'Suites: resolute' 'Components: main'
		if [[ $# -gt 0 ]]; then
			printf '%s\n' "$@"
		fi
		printf '%s\n' 'Signed-By:' ' -----BEGIN PGP PUBLIC KEY BLOCK-----' \
			' fixture-key-material' ' -----END PGP PUBLIC KEY BLOCK-----'
	} > "${FILE}"
}

for ARCH in amd64 arm64 armhf; do
	rm -rf "${ARCH_DIR}"
	mkdir -p "${ARCH_DIR}"
	write_ppa_deb822 "${ARCH_DIR}/amnezia-ubuntu-ppa-resolute.sources"
	write_ppa_deb822 "${TEST_ROOT}/native-arch.expected" "Architectures: ${ARCH}"
	setAmneziaPpaSuite resolute "${ARCH_DIR}" "${ARCH}"
	assert_rc 0 "$?" "unpinned DEB822 source is reconciled on ${ARCH}"
	assert_file_eq "${TEST_ROOT}/native-arch.expected" "${ARCH_DIR}/amnezia-ubuntu-ppa-resolute.sources" \
		"DEB822 source gains exactly 'Architectures: ${ARCH}' and keeps every other field and comment"
	cp "${ARCH_DIR}/amnezia-ubuntu-ppa-resolute.sources" "${TEST_ROOT}/native-arch.first"
	setAmneziaPpaSuite resolute "${ARCH_DIR}" "${ARCH}"
	assert_rc 0 "$?" "second DEB822 reconciliation succeeds on ${ARCH}"
	assert_file_eq "${TEST_ROOT}/native-arch.first" "${ARCH_DIR}/amnezia-ubuntu-ppa-resolute.sources" \
		"second DEB822 reconciliation on ${ARCH} is byte-identical"
	amneziaPpaSourceEntriesExist "${ARCH_DIR}" "${ARCH}"
	assert_rc 0 "$?" "the matcher accepts the entry its writer pinned to ${ARCH}"
done

rm -rf "${ARCH_DIR}"
mkdir -p "${ARCH_DIR}"
write_ppa_deb822 "${ARCH_DIR}/suite-change.sources"
sed -i 's/^Suites: resolute$/Suites: noble/' "${ARCH_DIR}/suite-change.sources"
write_ppa_deb822 "${TEST_ROOT}/suite-change.expected" "Architectures: amd64"
setAmneziaPpaSuite resolute "${ARCH_DIR}" amd64
assert_rc 0 "$?" "noble entry moved to resolute is reconciled"
assert_file_eq "${TEST_ROOT}/suite-change.expected" "${ARCH_DIR}/suite-change.sources" \
	"a noble to resolute suite change pins the native architecture in the same pass"

EXISTING_NAMES=("amd64 amd64v3" "amd64 i386" "amd64" "amd64v3 amd64")
for EXISTING in "${EXISTING_NAMES[@]}"; do
	rm -rf "${ARCH_DIR}"
	mkdir -p "${ARCH_DIR}"
	write_ppa_deb822 "${ARCH_DIR}/existing.sources" "Architectures: ${EXISTING}"
	setAmneziaPpaSuite resolute "${ARCH_DIR}" amd64
	assert_rc 0 "$?" "existing 'Architectures: ${EXISTING}' is reconciled"
	assert_file_eq "${TEST_ROOT}/suite-change.expected" "${ARCH_DIR}/existing.sources" \
		"'Architectures: ${EXISTING}' converges to exactly 'Architectures: amd64'"
done

rm -rf "${ARCH_DIR}"
mkdir -p "${ARCH_DIR}"
write_ppa_deb822 "${ARCH_DIR}/multiline.sources" "Architectures:" " amd64" " amd64v3"
setAmneziaPpaSuite resolute "${ARCH_DIR}" amd64
assert_rc 0 "$?" "multiline Architectures field is reconciled"
assert_file_eq "${TEST_ROOT}/suite-change.expected" "${ARCH_DIR}/multiline.sources" \
	"multiline Architectures converges to one line and drops stale continuations"

rm -rf "${ARCH_DIR}"
mkdir -p "${ARCH_DIR}"
write_ppa_deb822 "${ARCH_DIR}/lowercase.sources" "architectures: amd64v3 amd64"
write_ppa_deb822 "${TEST_ROOT}/lowercase.expected" "architectures: amd64"
setAmneziaPpaSuite resolute "${ARCH_DIR}" amd64
assert_rc 0 "$?" "lowercase Architectures field name is reconciled"
assert_file_eq "${TEST_ROOT}/lowercase.expected" "${ARCH_DIR}/lowercase.sources" \
	"field name spelling is kept and no second Architectures field is added"

for DIRECTIVE in "Architectures-Add: amd64v3" "Architectures-Remove: i386"; do
	rm -rf "${ARCH_DIR}"
	mkdir -p "${ARCH_DIR}"
	write_ppa_deb822 "${ARCH_DIR}/directive.sources" "Architectures: amd64" "${DIRECTIVE}"
	cp "${ARCH_DIR}/directive.sources" "${TEST_ROOT}/directive.original"
	setAmneziaPpaSuite resolute "${ARCH_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
	assert_rc 1 "$?" "'${DIRECTIVE%%:*}' cannot be normalized safely and is rejected"
	assert_file_eq "${TEST_ROOT}/directive.original" "${ARCH_DIR}/directive.sources" \
		"source with '${DIRECTIVE%%:*}' is left untouched"
	amneziaPpaSourceEntriesExist "${ARCH_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
	assert_rc 2 "$?" "matcher reports the '${DIRECTIVE%%:*}' entry as unusable"
done

rm -rf "${ARCH_DIR}"
mkdir -p "${ARCH_DIR}"
write_ppa_deb822 "${ARCH_DIR}/two-fields.sources" "Architectures: amd64" "Architectures: amd64v3"
setAmneziaPpaSuite resolute "${ARCH_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "two Architectures fields are rejected rather than merged"

for BAD_ARCH in "AMD64" "amd64 amd64v3" "amd64;x" "-amd64"; do
	rm -rf "${ARCH_DIR}"
	mkdir -p "${ARCH_DIR}"
	write_ppa_deb822 "${ARCH_DIR}/bad-arch.sources"
	cp "${ARCH_DIR}/bad-arch.sources" "${TEST_ROOT}/bad-arch.original"
	setAmneziaPpaSuite resolute "${ARCH_DIR}" "${BAD_ARCH}" > /dev/null 2>"${ERROR_LOG}"
	assert_rc 1 "$?" "invalid architecture '${BAD_ARCH}' is refused"
	assert_file_eq "${TEST_ROOT}/bad-arch.original" "${ARCH_DIR}/bad-arch.sources" \
		"invalid architecture '${BAD_ARCH}' is never written to a source"
done

rm -rf "${ARCH_DIR}"
mkdir -p "${ARCH_DIR}"
write_ppa_deb822 "${ARCH_DIR}/pinned.sources" "Architectures: amd64"
cat >> "${ARCH_DIR}/pinned.sources" <<'EOF'

Types: deb
URIs: https://archive.ubuntu.com/ubuntu
Suites: resolute
Components: main
Architectures: amd64 i386
EOF
removeAmneziaPpaSourceEntries "${ARCH_DIR}"
assert_rc 0 "$?" "a pinned DEB822 PPA stanza is removed"
assert_not_contains 'ppa\.launchpadcontent\.net/amnezia' "${ARCH_DIR}/pinned.sources" "pinned PPA stanza is gone after removal"
assert_contains '^Architectures: amd64 i386$' "${ARCH_DIR}/pinned.sources" "an unrelated stanza keeps its architecture list"

echo "=== Native architecture pinning (legacy .list) ==="
PPA_URI_TEXT="https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu"
# legacy_case <arch> <input line> <expected line>
function legacy_case() {
	local ARCH="$1"
	local INPUT="$2"
	local EXPECTED="$3"
	rm -rf "${ARCH_DIR}"
	mkdir -p "${ARCH_DIR}"
	printf '%s\n' '# keep this comment' "${INPUT}" \
		'deb [arch=amd64,i386] https://archive.ubuntu.com/ubuntu resolute main' > "${ARCH_DIR}/amnezia.list"
	printf '%s\n' '# keep this comment' "${EXPECTED}" \
		'deb [arch=amd64,i386] https://archive.ubuntu.com/ubuntu resolute main' > "${TEST_ROOT}/legacy-arch.expected"
	setAmneziaPpaSuite resolute "${ARCH_DIR}" "${ARCH}"
	assert_rc 0 "$?" "legacy entry is reconciled: ${INPUT}"
	assert_file_eq "${TEST_ROOT}/legacy-arch.expected" "${ARCH_DIR}/amnezia.list" \
		"legacy entry becomes '${EXPECTED}' and other lines stay byte-identical"
	setAmneziaPpaSuite resolute "${ARCH_DIR}" "${ARCH}"
	assert_file_eq "${TEST_ROOT}/legacy-arch.expected" "${ARCH_DIR}/amnezia.list" \
		"second legacy reconciliation is byte-identical: ${EXPECTED}"
	amneziaPpaSourceEntriesExist "${ARCH_DIR}" "${ARCH}"
	assert_rc 0 "$?" "the matcher accepts the legacy entry pinned to ${ARCH}"
}
legacy_case amd64 "deb [signed-by=/usr/share/keyrings/amnezia.gpg] ${PPA_URI_TEXT} resolute main" \
	"deb [signed-by=/usr/share/keyrings/amnezia.gpg arch=amd64] ${PPA_URI_TEXT} resolute main"
legacy_case amd64 "deb [arch=amd64,amd64v3 signed-by=/k.gpg] ${PPA_URI_TEXT} resolute main" \
	"deb [arch=amd64 signed-by=/k.gpg] ${PPA_URI_TEXT} resolute main"
legacy_case amd64 "deb [signed-by=/k.gpg arch=i386,amd64] ${PPA_URI_TEXT} noble main" \
	"deb [signed-by=/k.gpg arch=amd64] ${PPA_URI_TEXT} resolute main"
legacy_case amd64 "deb [ signed-by=/k.gpg ] ${PPA_URI_TEXT} resolute main" \
	"deb [ signed-by=/k.gpg arch=amd64 ] ${PPA_URI_TEXT} resolute main"
legacy_case amd64 "deb [] ${PPA_URI_TEXT} resolute main" \
	"deb [arch=amd64] ${PPA_URI_TEXT} resolute main"
legacy_case amd64 "deb [Arch=amd64] ${PPA_URI_TEXT} resolute main # trailing comment" \
	"deb [arch=amd64] ${PPA_URI_TEXT} resolute main # trailing comment"
legacy_case arm64 "deb ${PPA_URI_TEXT} resolute main" \
	"deb [arch=arm64] ${PPA_URI_TEXT} resolute main"
legacy_case armhf "deb [signed-by=/k.gpg] ${PPA_URI_TEXT}/ resolute main" \
	"deb [signed-by=/k.gpg arch=armhf] ${PPA_URI_TEXT}/ resolute main"

for OPTIONS in "arch=amd64 arch=amd64v3" "arch=amd64 arch=amd64,amd64v3" "arch+=amd64v3" "arch-=i386"; do
	rm -rf "${ARCH_DIR}"
	mkdir -p "${ARCH_DIR}"
	printf '%s\n' "deb [${OPTIONS}] ${PPA_URI_TEXT} resolute main" > "${ARCH_DIR}/amnezia.list"
	cp "${ARCH_DIR}/amnezia.list" "${TEST_ROOT}/legacy-options.original"
	setAmneziaPpaSuite resolute "${ARCH_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
	assert_rc 1 "$?" "legacy options '${OPTIONS}' cannot be normalized safely and are rejected"
	assert_file_eq "${TEST_ROOT}/legacy-options.original" "${ARCH_DIR}/amnezia.list" \
		"legacy entry with '${OPTIONS}' is left untouched"
done

rm -rf "${ARCH_DIR}"
mkdir -p "${ARCH_DIR}"
printf '%s\n' "deb [arch=amd64 signed-by=/k.gpg] ${PPA_URI_TEXT} resolute main" \
	'deb [arch=amd64,i386] https://archive.ubuntu.com/ubuntu resolute main' > "${ARCH_DIR}/amnezia.list"
removeAmneziaPpaSourceEntries "${ARCH_DIR}"
assert_rc 0 "$?" "a pinned legacy PPA entry is removed"
assert_not_contains 'ppa\.launchpadcontent\.net/amnezia' "${ARCH_DIR}/amnezia.list" "pinned legacy PPA entry is gone after removal"
assert_contains '^deb \[arch=amd64,i386\] https://archive\.ubuntu\.com/ubuntu resolute main$' "${ARCH_DIR}/amnezia.list" \
	"an unrelated legacy line keeps its architecture option"

echo "=== Malformed and ambiguous source handling ==="
MALFORMED_DIR="${TEST_ROOT}/malformed"
mkdir -p "${MALFORMED_DIR}"
cat > "${MALFORMED_DIR}/mixed-uri.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/ https://archive.ubuntu.com/ubuntu
Suites: resolute
Components: main
EOF
cp "${MALFORMED_DIR}/mixed-uri.sources" "${TEST_ROOT}/mixed-uri.original"
setAmneziaPpaSuite noble "${MALFORMED_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "mixed-URI DEB822 stanza is rejected"
assert_file_eq "${TEST_ROOT}/mixed-uri.original" "${MALFORMED_DIR}/mixed-uri.sources" "rejected mixed-URI stanza is untouched"

rm -f "${MALFORMED_DIR}/mixed-uri.sources"
cat > "${MALFORMED_DIR}/missing-suite.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Components: main
EOF
cp "${MALFORMED_DIR}/missing-suite.sources" "${TEST_ROOT}/missing-suite.original"
setAmneziaPpaSuite noble "${MALFORMED_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "matching DEB822 stanza without Suites is rejected"
assert_file_eq "${TEST_ROOT}/missing-suite.original" "${MALFORMED_DIR}/missing-suite.sources" "malformed stanza remains untouched"

rm -f "${MALFORMED_DIR}/missing-suite.sources"
cat > "${MALFORMED_DIR}/invalid-physical-line.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
this is not a DEB822 field
EOF
cp "${MALFORMED_DIR}/invalid-physical-line.sources" "${TEST_ROOT}/invalid-physical-line.original"
setAmneziaPpaSuite noble "${MALFORMED_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "malformed physical line in target DEB822 stanza is rejected"
assert_file_eq "${TEST_ROOT}/invalid-physical-line.original" "${MALFORMED_DIR}/invalid-physical-line.sources" "malformed physical line causes no rewrite"

rm -f "${MALFORMED_DIR}/invalid-physical-line.sources"
cat > "${MALFORMED_DIR}/comment-only-amnezia.sources" <<'EOF'
# https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute
Types: deb
URIs: https://archive.ubuntu.com/ubuntu
Suites: resolute
Components: main
EOF
cp "${MALFORMED_DIR}/comment-only-amnezia.sources" "${TEST_ROOT}/comment-only.original"
setAmneziaPpaSuite noble "${MALFORMED_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 2 "$?" "target URL in a comment is not a source entry"
assert_file_eq "${TEST_ROOT}/comment-only.original" "${MALFORMED_DIR}/comment-only-amnezia.sources" "comment-only match is untouched"

rm -f "${MALFORMED_DIR}/comment-only-amnezia.sources"
cat > "${MALFORMED_DIR}/unclosed-http-options.list" <<'EOF'
deb [arch=amd64 http://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${MALFORMED_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "unclosed legacy options containing the accepted HTTP PPA URI are rejected"

echo "=== Unusable and insecure source handling ==="
SECURITY_DIR="${TEST_ROOT}/security"
mkdir -p "${SECURITY_DIR}"

cat > "${SECURITY_DIR}/disabled.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
Enabled: no
EOF
cp "${SECURITY_DIR}/disabled.sources" "${TEST_ROOT}/disabled.original"
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "disabled DEB822 binary entry is rejected"
assert_file_eq "${TEST_ROOT}/disabled.original" "${SECURITY_DIR}/disabled.sources" "disabled source remains untouched"

rm -f "${SECURITY_DIR}/disabled.sources"
cat > "${SECURITY_DIR}/source-only.sources" <<'EOF'
Types: deb-src
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "source-only DEB822 entry cannot stand in for a binary repository"

rm -f "${SECURITY_DIR}/source-only.sources"
cat > "${SECURITY_DIR}/trusted.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
Trusted: yes
EOF
cp "${SECURITY_DIR}/trusted.sources" "${TEST_ROOT}/trusted.original"
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "DEB822 Trusted: yes entry is rejected"
assert_file_eq "${TEST_ROOT}/trusted.original" "${SECURITY_DIR}/trusted.sources" "insecure DEB822 entry remains untouched"

rm -f "${SECURITY_DIR}/trusted.sources"
cat > "${SECURITY_DIR}/allow-insecure.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
Allow-Insecure: yes
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "DEB822 Allow-Insecure: yes entry is rejected"

rm -f "${SECURITY_DIR}/allow-insecure.sources"
cat > "${SECURITY_DIR}/wrong-architecture.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
Architectures: arm64
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "DEB822 entry excluding the host architecture is rejected"

rm -f "${SECURITY_DIR}/wrong-architecture.sources"
cat > "${SECURITY_DIR}/missing-components.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "DEB822 entry without main Components is rejected"

rm -f "${SECURITY_DIR}/missing-components.sources"
cat > "${SECURITY_DIR}/invalid-types.sources" <<'EOF'
Types: deb binary
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "DEB822 entry with an unknown Types token is rejected"

rm -f "${SECURITY_DIR}/invalid-types.sources"
cat > "${SECURITY_DIR}/first.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
cp "${SECURITY_DIR}/first.sources" "${SECURITY_DIR}/second.sources"
CHECKSUM_BEFORE="$(cksum "${SECURITY_DIR}/first.sources") $(cksum "${SECURITY_DIR}/second.sources")"
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "duplicate active PPA binary entries are rejected"
CHECKSUM_AFTER="$(cksum "${SECURITY_DIR}/first.sources") $(cksum "${SECURITY_DIR}/second.sources")"
assert_eq "${CHECKSUM_BEFORE}" "${CHECKSUM_AFTER}" "duplicate rejection performs no partial rewrite"
assert_eq "0" "$(find "${SECURITY_DIR}" -name '*.amneziawg.*' | wc -l | tr -d ' ')" "validation failure leaves no staged temp files"

rm -f "${SECURITY_DIR}/first.sources" "${SECURITY_DIR}/second.sources"
cat > "${SECURITY_DIR}/binary.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
cat > "${SECURITY_DIR}/source.sources" <<'EOF'
Types: deb-src
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 0 "$?" "one split binary and one source-package entry are accepted"
assert_eq "2" "$(grep -Rhc '^Suites: noble$' "${SECURITY_DIR}" | awk '{ total += $1 } END { print total }')" "both valid split entries are reconciled"

cat > "${SECURITY_DIR}/duplicate-source.sources" <<'EOF'
Types: deb-src
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "duplicate source-package PPA entries are rejected"
assert_contains '^Suites: resolute$' "${SECURITY_DIR}/duplicate-source.sources" "duplicate source rejection performs no new rewrite"

rm -f "${SECURITY_DIR}/binary.sources" "${SECURITY_DIR}/source.sources" "${SECURITY_DIR}/duplicate-source.sources"
ROLLBACK_DIR="${TEST_ROOT}/multi-file-rollback"
ROLLBACK_BIN="${TEST_ROOT}/rollback-bin"
mkdir -p "${ROLLBACK_DIR}" "${ROLLBACK_BIN}"
cat > "${ROLLBACK_DIR}/binary.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
cat > "${ROLLBACK_DIR}/source.sources" <<'EOF'
Types: deb-src
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
cat > "${ROLLBACK_BIN}/mv" <<'EOF'
#!/bin/bash
if [[ "$1" == "-f" && "$2" == *.amneziawg.* ]]; then
	count=0
	[[ -f "${ROLLBACK_MV_COUNT}" ]] && count="$(cat "${ROLLBACK_MV_COUNT}")"
	count=$((count + 1))
	printf '%s\n' "${count}" > "${ROLLBACK_MV_COUNT}"
	if [[ "${count}" -eq 2 ]]; then
		exit 71
	fi
fi
exec /bin/mv "$@"
EOF
chmod +x "${ROLLBACK_BIN}/mv"
export ROLLBACK_MV_COUNT="${TEST_ROOT}/rollback-mv.count"
CHECKSUM_BEFORE="$(cksum "${ROLLBACK_DIR}/binary.sources") $(cksum "${ROLLBACK_DIR}/source.sources")"
PATH="${ROLLBACK_BIN}:${PATH}" setAmneziaPpaSuite noble "${ROLLBACK_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "later file replacement failure is propagated"
CHECKSUM_AFTER="$(cksum "${ROLLBACK_DIR}/binary.sources") $(cksum "${ROLLBACK_DIR}/source.sources")"
assert_eq "${CHECKSUM_BEFORE}" "${CHECKSUM_AFTER}" "multi-file replacement failure rolls back earlier source files"
assert_eq "0" "$(find "${ROLLBACK_DIR}" -name '*.amneziawg*' | wc -l | tr -d ' ')" "multi-file rollback removes staged and backup files"

cat > "${TEST_ROOT}/symlink-target.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
cp "${TEST_ROOT}/symlink-target.sources" "${TEST_ROOT}/symlink-target.original"
ln -s "${TEST_ROOT}/symlink-target.sources" "${SECURITY_DIR}/linked.sources"
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "matching PPA source symlink is rejected"
assert_file_eq "${TEST_ROOT}/symlink-target.original" "${TEST_ROOT}/symlink-target.sources" "symlink target remains untouched"
assert_eq "0" "$(find "${SECURITY_DIR}" -name '*.amneziawg.*' | wc -l | tr -d ' ')" "symlink rejection leaves no staged temp files"

rm -f "${SECURITY_DIR}/linked.sources"
cat > "${SECURITY_DIR}/trusted.list" <<'EOF'
deb [trusted=on allow-insecure=enable allow-weak=with allow-downgrade-to-insecure=1] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "all APT true aliases for legacy insecure options are rejected"

rm -f "${SECURITY_DIR}/trusted.list"
cat > "${SECURITY_DIR}/quoted-insecure-options.list" <<'EOF'
deb ["trusted=yes" "allow-insecure=yes" "allow-weak=yes" "allow-downgrade-to-insecure=yes"] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "APT-quoted legacy signature-bypass options are rejected"

rm -f "${SECURITY_DIR}/quoted-insecure-options.list"
cat > "${SECURITY_DIR}/escaped-insecure-options.list" <<'EOF'
deb [trus\ted=yes] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "APT-escaped legacy signature-bypass options are rejected"

rm -f "${SECURITY_DIR}/escaped-insecure-options.list"
cat > "${SECURITY_DIR}/encoded-insecure-options.list" <<'EOF'
deb [trus%74ed=yes] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "APT percent-encoded legacy signature-bypass options are rejected"

rm -f "${SECURITY_DIR}/encoded-insecure-options.list"
cat > "${SECURITY_DIR}/valueless-insecure-option.list" <<'EOF'
deb [trusted] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "valueless legacy security option is rejected conservatively"

rm -f "${SECURITY_DIR}/valueless-insecure-option.list"
cat > "${SECURITY_DIR}/explicitly-secure.list" <<'EOF'
deb [trusted=off allow-insecure=disable allow-weak=without allow-downgrade-to-insecure=0] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 0 "$?" "explicit APT false aliases for legacy security options remain usable"
assert_contains ' noble main$' "${SECURITY_DIR}/explicitly-secure.list" "secure legacy option values are preserved"

rm -f "${SECURITY_DIR}/explicitly-secure.list"
cat > "${SECURITY_DIR}/wrong-architecture.list" <<'EOF'
deb [arch=arm64] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "legacy entry excluding the host architecture is rejected"

rm -f "${SECURITY_DIR}/wrong-architecture.list"
cat > "${SECURITY_DIR}/missing-component.list" <<'EOF'
deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute
EOF
setAmneziaPpaSuite noble "${SECURITY_DIR}" amd64 > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "legacy entry without the main component is rejected"

echo "=== Configure, rerun, and failed-add cleanup ==="
STUB_BIN="${TEST_ROOT}/bin"
mkdir -p "${STUB_BIN}"
cat > "${STUB_BIN}/add-apt-repository" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${PPA_STUB_LOG}"
if [[ "${PPA_STUB_MODE}" == "nofile" ]]; then
	exit 0
fi
mkdir -p "${PPA_STUB_SOURCES}"
cat > "${PPA_STUB_SOURCES}/amnezia-ubuntu-ppa-resolute.sources" <<'SOURCE'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 fixture-key-material
 -----END PGP PUBLIC KEY BLOCK-----
SOURCE
if [[ "${PPA_STUB_MODE}" == "fail-after-create" ]]; then
	exit 1
fi
exit 0
EOF
chmod +x "${STUB_BIN}/add-apt-repository"

CONFIG_DIR="${TEST_ROOT}/configure"
mkdir -p "${CONFIG_DIR}"
cat > "${CONFIG_DIR}/ignored ppa.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
EOF
cp "${CONFIG_DIR}/ignored ppa.sources" "${CONFIG_DIR}/ignored~ppa.sources"
export PPA_STUB_SOURCES="${CONFIG_DIR}"
export PPA_STUB_LOG="${TEST_ROOT}/add.log"
export PPA_STUB_MODE="create"
: > "${PPA_STUB_LOG}"
(
	set -euo pipefail
	function selectAmneziaPpaSuite() { printf '%s\n' noble; }
	PATH="${STUB_BIN}:${PATH}" configureUbuntuAmneziaPpa resolute "${CONFIG_DIR}" amd64
	printf '%s\n' "${AMNEZIA_PPA_SOURCE_CREATED}" > "${TEST_ROOT}/created.flag"
)
RC=$?
assert_rc 0 "${RC}" "first configure call is errexit-safe and rewrites the PPA"
assert_eq "1" "$(cat "${TEST_ROOT}/created.flag")" "newly added source is marked as owned by the configure call"
assert_contains '^Suites: noble$' "${CONFIG_DIR}/amnezia-ubuntu-ppa-resolute.sources" "new source uses Noble fallback"
assert_contains '^Suites: resolute$' "${CONFIG_DIR}/ignored ppa.sources" "APT-ignored filename with spaces is not reused or rewritten"
assert_contains '^Suites: resolute$' "${CONFIG_DIR}/ignored~ppa.sources" "APT-ignored filename with tilde is not reused or rewritten"
assert_contains '^-y -n ppa:amnezia/ppa$' "${PPA_STUB_LOG}" "add-apt-repository is called with no-update"
assert_eq "1" "$(wc -l < "${PPA_STUB_LOG}" | tr -d ' ')" "repository add runs once"

(
	function selectAmneziaPpaSuite() { printf '%s\n' noble; }
	PATH="${STUB_BIN}:${PATH}" configureUbuntuAmneziaPpa resolute "${CONFIG_DIR}" amd64
	printf '%s\n' "${AMNEZIA_PPA_SOURCE_CREATED}" > "${TEST_ROOT}/created.flag"
)
assert_rc 0 "$?" "installer rerun reuses existing fallback entry"
assert_eq "0" "$(cat "${TEST_ROOT}/created.flag")" "reused administrator source is not marked as newly owned"
assert_eq "1" "$(wc -l < "${PPA_STUB_LOG}" | tr -d ' ')" "rerun does not call add-apt-repository again"
assert_eq "1" "$(grep -c '^URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/$' "${CONFIG_DIR}/amnezia-ubuntu-ppa-resolute.sources")" "rerun creates no duplicate PPA entry"

(
	function selectAmneziaPpaSuite() { printf '%s\n' resolute; }
	PATH="${STUB_BIN}:${PATH}" configureUbuntuAmneziaPpa resolute "${CONFIG_DIR}" amd64
)
assert_rc 0 "$?" "native suite refresh succeeds when Resolute becomes available"
assert_contains '^Suites: resolute$' "${CONFIG_DIR}/amnezia-ubuntu-ppa-resolute.sources" "native Resolute automatically replaces temporary fallback"

(
	function selectAmneziaPpaSuite() { printf '%s\n' resolute; }
	PATH="${STUB_BIN}:${PATH}" configureUbuntuAmneziaPpa resolute "${CONFIG_DIR}" amd64
	if cleanupNewlyCreatedUbuntuAmneziaPpa "${CONFIG_DIR}"; then
		printf '0\n'
	else
		printf '%s\n' "$?"
	fi
) > "${TEST_ROOT}/preexisting-cleanup.rc"
assert_eq "2" "$(cat "${TEST_ROOT}/preexisting-cleanup.rc")" "update-failure cleanup declines to remove a pre-existing source"
assert_contains '^Suites: resolute$' "${CONFIG_DIR}/amnezia-ubuntu-ppa-resolute.sources" "pre-existing source survives simulated update failure"

OWNED_DIR="${TEST_ROOT}/owned-update-failure"
mkdir -p "${OWNED_DIR}"
export PPA_STUB_SOURCES="${OWNED_DIR}"
export PPA_STUB_MODE="create"
(
	set -euo pipefail
	function selectAmneziaPpaSuite() { printf '%s\n' noble; }
	PATH="${STUB_BIN}:${PATH}" configureUbuntuAmneziaPpa resolute "${OWNED_DIR}" amd64
	[[ "${AMNEZIA_PPA_SOURCE_CREATED}" -eq 1 ]]
	cleanupNewlyCreatedUbuntuAmneziaPpa "${OWNED_DIR}"
	[[ "${AMNEZIA_PPA_SOURCE_CREATED}" -eq 0 ]]
)
assert_rc 0 "$?" "simulated update failure rolls back only the newly created PPA source"
assert_eq "0" "$(find "${OWNED_DIR}" -maxdepth 1 -type f | wc -l | tr -d ' ')" "owned update-failure rollback leaves APT source state clean"

NETWORK_DIR="${TEST_ROOT}/network-failure"
mkdir -p "${NETWORK_DIR}"
: > "${PPA_STUB_LOG}"
(
	function probeAmneziaPpaSuite() { return 2; }
	PATH="${STUB_BIN}:${PATH}" configureUbuntuAmneziaPpa resolute "${NETWORK_DIR}" amd64
) > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "network failure prevents repository configuration"
assert_eq "0" "$(wc -l < "${PPA_STUB_LOG}" | tr -d ' ')" "network failure never invokes add-apt-repository"
assert_eq "0" "$(find "${NETWORK_DIR}" -maxdepth 1 -type f | wc -l | tr -d ' ')" "network failure leaves no source file"

NOFILE_DIR="${TEST_ROOT}/missing-after-add"
mkdir -p "${NOFILE_DIR}"
export PPA_STUB_SOURCES="${NOFILE_DIR}"
export PPA_STUB_MODE="nofile"
: > "${PPA_STUB_LOG}"
(
	function selectAmneziaPpaSuite() { printf '%s\n' noble; }
	PATH="${STUB_BIN}:${PATH}" configureUbuntuAmneziaPpa resolute "${NOFILE_DIR}" amd64
) > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "missing source file after successful add command is fatal"
assert_eq "0" "$(find "${NOFILE_DIR}" -maxdepth 1 -type f | wc -l | tr -d ' ')" "missing-source failure leaves no PPA file"

FAILED_ADD_DIR="${TEST_ROOT}/failed-add"
mkdir -p "${FAILED_ADD_DIR}"
export PPA_STUB_SOURCES="${FAILED_ADD_DIR}"
export PPA_STUB_MODE="fail-after-create"
: > "${PPA_STUB_LOG}"
(
	function selectAmneziaPpaSuite() { printf '%s\n' noble; }
	PATH="${STUB_BIN}:${PATH}" configureUbuntuAmneziaPpa resolute "${FAILED_ADD_DIR}" amd64
) > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "add-apt-repository failure is fatal"
assert_eq "0" "$(find "${FAILED_ADD_DIR}" -maxdepth 1 -type f | wc -l | tr -d ' ')" "failed add cleans the partially created source"

echo "=== Native architecture in configure and refresh ==="
DPKG_STUB_BIN="${TEST_ROOT}/dpkg-bin"
mkdir -p "${DPKG_STUB_BIN}"
cat > "${DPKG_STUB_BIN}/dpkg" <<'EOF'
#!/bin/bash
[[ "$1" == "--print-architecture" ]] || exit 2
[[ "${DPKG_STUB_ARCH}" == "fail" ]] && exit 1
printf '%s\n' "${DPKG_STUB_ARCH}"
EOF
chmod +x "${DPKG_STUB_BIN}/dpkg"

for STUB_ARCH in amd64 arm64 armhf; do
	assert_eq "${STUB_ARCH}" "$(DPKG_STUB_ARCH="${STUB_ARCH}" PATH="${DPKG_STUB_BIN}:${PATH}" getNativeDpkgArchitecture)" \
		"native architecture is what dpkg reports (${STUB_ARCH})"
done
for STUB_ARCH in fail "" "AMD64" "amd64 i386"; do
	DPKG_STUB_ARCH="${STUB_ARCH}" PATH="${DPKG_STUB_BIN}:${PATH}" getNativeDpkgArchitecture > /dev/null
	assert_rc 1 "$?" "an unusable dpkg architecture ('${STUB_ARCH}') is refused"
done

FRESH_DIR="${TEST_ROOT}/fresh-native"
mkdir -p "${FRESH_DIR}"
export PPA_STUB_SOURCES="${FRESH_DIR}"
export PPA_STUB_MODE="create"
: > "${PPA_STUB_LOG}"
(
	set -euo pipefail
	function probeAmneziaPpaSuite() { [[ "$1" == "resolute" ]]; }
	DPKG_STUB_ARCH=arm64 PATH="${STUB_BIN}:${DPKG_STUB_BIN}:${PATH}" \
		configureUbuntuAmneziaPpa resolute "${FRESH_DIR}"
	printf '%s %s\n' "${AMNEZIA_PPA_SELECTED_SUITE}" "${AMNEZIA_PPA_ARCHITECTURE}" > "${TEST_ROOT}/fresh.selected"
)
assert_rc 0 "$?" "fresh configure with the dpkg architecture succeeds"
assert_contains '^Suites: resolute$' "${FRESH_DIR}/amnezia-ubuntu-ppa-resolute.sources" "fresh install keeps the native resolute suite"
assert_eq "1" "$(grep -c '^Architectures:' "${FRESH_DIR}/amnezia-ubuntu-ppa-resolute.sources")" "fresh source has exactly one Architectures field"
assert_contains '^Architectures: arm64$' "${FRESH_DIR}/amnezia-ubuntu-ppa-resolute.sources" "fresh source is pinned to the architecture dpkg reports"
assert_eq "resolute arm64" "$(cat "${TEST_ROOT}/fresh.selected")" "configure records the selected suite and architecture"

BADARCH_DIR="${TEST_ROOT}/bad-dpkg-arch"
mkdir -p "${BADARCH_DIR}"
export PPA_STUB_SOURCES="${BADARCH_DIR}"
: > "${PPA_STUB_LOG}"
(
	function probeAmneziaPpaSuite() { return 0; }
	DPKG_STUB_ARCH="AMD64" PATH="${STUB_BIN}:${DPKG_STUB_BIN}:${PATH}" \
		configureUbuntuAmneziaPpa resolute "${BADARCH_DIR}"
) > /dev/null 2>"${ERROR_LOG}"
assert_rc 1 "$?" "configure refuses an invalid dpkg architecture"
assert_eq "0" "$(wc -l < "${PPA_STUB_LOG}" | tr -d ' ')" "an invalid architecture never reaches add-apt-repository"
assert_eq "0" "$(find "${BADARCH_DIR}" -maxdepth 1 -type f | wc -l | tr -d ' ')" "an invalid architecture leaves no source file"

# An Ubuntu 26.04 host installed while the PPA had no resolute suite carries a
# noble entry without an architecture pin. The refresh on the next installer
# run must move it to resolute and pin it in the same reconciliation.
MIGRATE_DIR="${TEST_ROOT}/noble-migration"
mkdir -p "${MIGRATE_DIR}"
cat > "${MIGRATE_DIR}/amnezia-ubuntu-ppa-resolute.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: noble
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 fixture-key-material
 -----END PGP PUBLIC KEY BLOCK-----
EOF
cat > "${TEST_ROOT}/noble-migration.expected" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
Architectures: amd64
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 fixture-key-material
 -----END PGP PUBLIC KEY BLOCK-----
EOF
function run_refresh() {
	(
		function probeAmneziaPpaSuite() { [[ "$1" == "resolute" ]]; }
		function enable_apt_ipv4() { :; }
		function disable_apt_ipv4() { :; }
		ID=ubuntu VERSION_CODENAME=resolute AMNEZIA_PPA_SOURCES_DIR="${MIGRATE_DIR}" \
			DPKG_STUB_ARCH=amd64 PATH="${STUB_BIN}:${DPKG_STUB_BIN}:${PATH}" refreshConfiguredUbuntuAmneziaPpa
	)
}
run_refresh > /dev/null 2>"${ERROR_LOG}"
assert_rc 0 "$?" "refresh of an existing noble entry succeeds"
assert_file_eq "${TEST_ROOT}/noble-migration.expected" "${MIGRATE_DIR}/amnezia-ubuntu-ppa-resolute.sources" \
	"refresh moves noble to resolute and pins the native architecture in the same source"
run_refresh > /dev/null 2>"${ERROR_LOG}"
assert_file_eq "${TEST_ROOT}/noble-migration.expected" "${MIGRATE_DIR}/amnezia-ubuntu-ppa-resolute.sources" \
	"a second refresh leaves the migrated source byte-identical"

echo "=== amneziawg-tools candidate preflight ==="
CANDIDATE_BIN="${TEST_ROOT}/candidate-bin"
mkdir -p "${CANDIDATE_BIN}"
cat > "${CANDIDATE_BIN}/apt-cache" <<'EOF'
#!/bin/bash
printf '%s|%s\n' "${LC_ALL:-}" "$*" >> "${CANDIDATE_LOG}"
case "${CANDIDATE_MODE}" in
	present)
		printf 'Package: amneziawg-tools\nArchitecture: amd64\nVersion: 1.0\nFilename: pool/main/a/amneziawg/amneziawg-tools_1.0_amd64.deb\n\n'
		;;
	status-only)
		printf 'Package: amneziawg-tools\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n\n'
		;;
	absent) ;;
	error) exit 100 ;;
esac
EOF
chmod +x "${CANDIDATE_BIN}/apt-cache"
export CANDIDATE_LOG="${TEST_ROOT}/candidate.log"
CANDIDATE_ERR="${TEST_ROOT}/candidate.err"

: > "${CANDIDATE_LOG}"
CANDIDATE_MODE=present PATH="${CANDIDATE_BIN}:${PATH}" checkAmneziaPpaToolsCandidate resolute amd64 2>"${CANDIDATE_ERR}"
assert_rc 0 "$?" "a downloadable amneziawg-tools candidate passes the preflight"
assert_eq "C|show --no-all-versions amneziawg-tools" "$(cat "${CANDIDATE_LOG}")" "preflight reads the candidate record with a C locale"
assert_eq "0" "$(wc -c < "${CANDIDATE_ERR}" | tr -d ' ')" "a passing preflight prints nothing"

for MODE in absent status-only error; do
	CANDIDATE_MODE="${MODE}" PATH="${CANDIDATE_BIN}:${PATH}" checkAmneziaPpaToolsCandidate resolute amd64 2>"${CANDIDATE_ERR}"
	assert_rc 1 "$?" "no downloadable candidate (${MODE}) fails the preflight"
	assert_contains "suite 'resolute'" "${CANDIDATE_ERR}" "preflight error (${MODE}) names the Ubuntu suite"
	assert_contains "architecture 'amd64'" "${CANDIDATE_ERR}" "preflight error (${MODE}) names the native architecture"
	assert_contains 'amneziawg-tools' "${CANDIDATE_ERR}" "preflight error (${MODE}) names the package"
	assert_contains 'ppa:amnezia/ppa' "${CANDIDATE_ERR}" "preflight error (${MODE}) names the PPA"
	assert_contains 'not a network failure' "${CANDIDATE_ERR}" "preflight error (${MODE}) rules out a network failure"
	assert_not_contains 'internet connection' "${CANDIDATE_ERR}" "preflight error (${MODE}) does not blame the connection"
done

CANDIDATE_MODE=absent PATH="${CANDIDATE_BIN}:${PATH}" checkAmneziaPpaToolsCandidate noble arm64 2>"${CANDIDATE_ERR}"
assert_rc 1 "$?" "preflight fails on a missing arm64 candidate"
assert_contains "suite 'noble' and architecture 'arm64'" "${CANDIDATE_ERR}" "preflight error reports the suite and architecture it was given"

# The Ubuntu install flow refreshes the lists, then checks the candidate, then
# installs; the Debian and Raspberry Pi branch is untouched by the pinning.
INSTALL_BODY="$(declare -f installAmneziaWG)"
UBUNTU_BRANCH="$(awk '/OS.* == .debian. /{exit} /OS.* == .ubuntu. /{p=1} p' <<< "${INSTALL_BODY}")"
DEBIAN_BRANCH="$(awk '/OS.* == .fedora. /{exit} /OS.* == .debian. /{p=1} p' <<< "${INSTALL_BODY}")"
UPDATE_LINE=$(grep -n 'APT::Update::Error-Mode=any update' <<< "${UBUNTU_BRANCH}" | head -1 | cut -d: -f1)
PREFLIGHT_LINE=$(grep -n 'checkAmneziaPpaToolsCandidate' <<< "${UBUNTU_BRANCH}" | head -1 | cut -d: -f1)
INSTALL_LINE=$(grep -n 'install -y dkms iptables nftables amneziawg amneziawg-tools' <<< "${UBUNTU_BRANCH}" | head -1 | cut -d: -f1)
if [[ -n "${UPDATE_LINE}" && -n "${PREFLIGHT_LINE}" && -n "${INSTALL_LINE}" ]] &&
	((UPDATE_LINE < PREFLIGHT_LINE && PREFLIGHT_LINE < INSTALL_LINE)); then
	pass
else
	fail "Ubuntu install flow runs the candidate preflight after the PPA update and before the install"
fi
if grep -qF 'checkAmneziaPpaToolsCandidate "${AMNEZIA_PPA_SELECTED_SUITE}" "${AMNEZIA_PPA_ARCHITECTURE}"' <<< "${UBUNTU_BRANCH}"; then
	pass
else
	fail "Ubuntu install flow passes the suite and architecture configure selected to the preflight"
fi
if [[ -n "${DEBIAN_BRANCH}" ]] &&
	grep -qF 'ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main' <<< "${DEBIAN_BRANCH}" &&
	! grep -qE 'configureUbuntuAmneziaPpa|setAmneziaPpaSuite|checkAmneziaPpaToolsCandidate|[[[:space:]]arch=' <<< "${DEBIAN_BRANCH}"; then
	pass
else
	fail "Debian branch keeps its focal entries and gains no Ubuntu PPA reconciliation or architecture pin"
fi

echo "=== Installed package removal selection ==="
PACKAGE_STUB_BIN="${TEST_ROOT}/package-bin"
mkdir -p "${PACKAGE_STUB_BIN}"
cat > "${PACKAGE_STUB_BIN}/dpkg-query" <<'EOF'
#!/bin/bash
package="${*: -1}"
case "${package}" in
	amneziawg | amneziawg-tools) printf 'ii \n' ;;
	*) exit 1 ;;
esac
EOF
cat > "${PACKAGE_STUB_BIN}/apt" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" > "${PACKAGE_REMOVE_LOG}"
exit "${PACKAGE_REMOVE_RC}"
EOF
chmod +x "${PACKAGE_STUB_BIN}/dpkg-query" "${PACKAGE_STUB_BIN}/apt"
export PACKAGE_REMOVE_LOG="${TEST_ROOT}/package-remove.log"
export PACKAGE_REMOVE_RC=0
PATH="${PACKAGE_STUB_BIN}:${PATH}" removeInstalledAptPackages \
	amneziawg amneziawg-tools amneziawg-dkms
assert_rc 0 "$?" "package removal skips an unavailable historical package name"
assert_eq "remove -y amneziawg amneziawg-tools" "$(cat "${PACKAGE_REMOVE_LOG}")" "only installed AmneziaWG packages are passed to APT"
export PACKAGE_REMOVE_RC=42
PATH="${PACKAGE_STUB_BIN}:${PATH}" removeInstalledAptPackages \
	amneziawg amneziawg-tools amneziawg-dkms > /dev/null 2>&1
assert_rc 42 "$?" "APT package removal failure is propagated"

echo "=== Uninstall/source cleanup ==="
CLEANUP_DIR="${TEST_ROOT}/cleanup"
mkdir -p "${CLEANUP_DIR}"
cat > "${CLEANUP_DIR}/mixed.sources" <<'EOF'
# preserve this comment
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: noble
Components: main
Signed-By: embedded-key

Types: deb
URIs: https://archive.ubuntu.com/ubuntu
Suites: resolute
Components: main
EOF
cat > "${CLEANUP_DIR}/target-only.list" <<'EOF'
deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main
deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/ noble main
EOF
cat > "${CLEANUP_DIR}/mixed.list" <<'EOF'
# keep me
deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main
deb https://archive.ubuntu.com/ubuntu resolute main
EOF
cat > "${CLEANUP_DIR}/insecure-target-only.sources" <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/
Suites: resolute
Components: main
Trusted: yes
EOF
removeAmneziaPpaSourceEntries "${CLEANUP_DIR}"
assert_rc 0 "$?" "content-based uninstall cleanup succeeds"
assert_not_contains 'ppa\.launchpadcontent\.net/amnezia/ppa/ubuntu' "${CLEANUP_DIR}/mixed.sources" "DEB822 PPA stanza is removed regardless of suite"
assert_contains '^URIs: https://archive\.ubuntu\.com/ubuntu$' "${CLEANUP_DIR}/mixed.sources" "unrelated DEB822 stanza remains"
if [[ ! -e "${CLEANUP_DIR}/target-only.list" ]]; then
	pass
else
	fail "source file containing only target entries should be removed"
fi
assert_contains '^# keep me$' "${CLEANUP_DIR}/mixed.list" "legacy comment remains after cleanup"
assert_contains '^deb https://archive\.ubuntu\.com/ubuntu resolute main$' "${CLEANUP_DIR}/mixed.list" "unrelated legacy source remains after cleanup"
assert_not_contains 'ppa\.launchpadcontent\.net/amnezia/ppa/ubuntu' "${CLEANUP_DIR}/mixed.list" "legacy target entry is removed"
if [[ ! -e "${CLEANUP_DIR}/insecure-target-only.sources" ]]; then
	pass
else
	fail "uninstall should safely remove an exact insecure target stanza"
fi
removeAmneziaPpaSourceEntries "${CLEANUP_DIR}"
assert_rc 0 "$?" "uninstall cleanup is idempotent"

echo "=== IPv4 EXIT trap status preservation ==="
TRAP_DIR="${TEST_ROOT}/trap"
mkdir -p "${TRAP_DIR}/apt"
: > "${TRAP_DIR}/gai.conf"
bash -c '
	source "$1"
	APT_FORCE_IPV4_CONF="$2/apt/force-ipv4"
	GAI_CONF="$2/gai.conf"
	enable_apt_ipv4
	exit 37
' _ "${PROJECT_ROOT}/amneziawg-install.sh" "${TRAP_DIR}" > /dev/null 2>&1
assert_rc 37 "$?" "IPv4 cleanup trap preserves a failing exit status"
if [[ ! -e "${TRAP_DIR}/apt/force-ipv4" ]]; then
	pass
else
	fail "IPv4 cleanup trap should remove its managed APT file"
fi

echo ""
echo "Ubuntu PPA tests: ${TESTS_PASSED}/${TESTS_RUN} passed"
if [[ "${TESTS_FAILED}" -ne 0 ]]; then
	echo "Ubuntu PPA tests: FAILED (${TESTS_FAILED} failures)"
	exit 1
fi
echo "Ubuntu PPA tests: OK"
