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
assert_file_eq "${TEST_ROOT}/combined.expected" "${DEB822_DIR}/combined.sources" "only the matching DEB822 Suites value changes"
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
deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/ noble main # keep trailing comment
deb https://archive.ubuntu.com/ubuntu resolute main
deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu.evil resolute main
# deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu resolute main
EOF
setAmneziaPpaSuite noble "${LEGACY_DIR}" amd64
assert_rc 0 "$?" "legacy deb and deb-src entries are rewritten"
assert_file_eq "${TEST_ROOT}/mixed.expected" "${LEGACY_DIR}/mixed.list" "legacy rewrite changes only the exact suite field"
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
assert_contains '^deb "https://ppa\.launchpadcontent\.net/amnezia/ppa/ubuntu" noble main$' "${QUOTED_URI_DIR}/quoted.list" "quoted URI is preserved while its suite changes"

ENCODED_URI_DIR="${TEST_ROOT}/encoded-legacy-uri"
mkdir -p "${ENCODED_URI_DIR}"
cat > "${ENCODED_URI_DIR}/encoded.list" <<'EOF'
deb https%3a%2f%2fppa.launchpadcontent.net%2famnezia%2fppa%2fubuntu resolute main
EOF
setAmneziaPpaSuite noble "${ENCODED_URI_DIR}" amd64
assert_rc 0 "$?" "APT percent-encoded exact legacy PPA URI is recognized"
assert_contains '^deb https%3a%2f%2fppa\.launchpadcontent\.net%2famnezia%2fppa%2fubuntu noble main$' "${ENCODED_URI_DIR}/encoded.list" "encoded URI spelling is preserved while its suite changes"

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
