#!/usr/bin/env bash
# shellcheck disable=SC2034 # the suite sets globals that the sourced installer reads

# Unit tests for the BoringTun binary lifecycle of amneziawg-install.sh
# (--upgrade-boringtun, --rollback-boringtun): the store identity of release
# builds, the current and previous links, the upgrade and rollback
# transaction with its validation of the target binary before current
# changes, its failure, rollback and signal paths, retention of at most two
# managed releases, the lifecycle fields of --backend-status, and that nothing
# else ever switches the binary.
#
# Every release here is a TEST FIXTURE below the test root: fake binaries in
# the release layout, packed and served by a mocked curl. None is a published
# release. systemctl, the activation check, the capability probes and the
# staged config validation are stubs that record which release they ran
# against; the store, its links, the download and verification of releases,
# pruning and the status run for real.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INSTALLER="${PROJECT_ROOT}/amneziawg-install.sh"

if [[ "${EUID}" -eq 0 && "${AWG_DISPOSABLE_HOST_TEST:-}" != 1 ]]; then
	echo "ERROR: run the BoringTun lifecycle tests as an unprivileged user; as root they run only on a disposable host with AWG_DISPOSABLE_HOST_TEST=1" >&2
	exit 2
fi

# shellcheck source=../amneziawg-install.sh
source "${INSTALLER}"

# The real embedded release, before the fixtures replace it.
REAL_TAG="${AWG_BT_RELEASE_TAG}"
REAL_VERSION="${AWG_BT_RELEASE_VERSION}"
REAL_COMMIT="${AWG_BT_RELEASE_SOURCE_COMMIT}"
REAL_BUILD="${AWG_BT_RELEASE_BUILD}"
REAL_ASSET_X86_64="${AWG_BT_RELEASE_ASSET_X86_64}"
REAL_ASSET_AARCH64="${AWG_BT_RELEASE_ASSET_AARCH64}"

T="$(mktemp -d "${TMPDIR:-/tmp}/boringtun-lifecycle-tests.XXXXXX")"
T="$(CDPATH='' cd -- "${T}" && pwd -P)"
chmod 0755 "${T}"
S="${T}/state"
MOCKBIN="${T}/mockbin"
FIXTURE="${T}/fixture"
mkdir -p "${S}" "${MOCKBIN}" "${FIXTURE}"

PASS=0
FAIL=0
BACKGROUND=()

cleanup() {
	local PID
	for PID in "${BACKGROUND[@]}"; do
		kill -KILL "${PID}" 2>/dev/null
	done
	rm -rf -- "${T}"
}
trap cleanup EXIT

ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}

not_ok() {
	printf '  FAIL: %s\n' "$1" >&2
	FAIL=$((FAIL + 1))
}

assert_eq() {
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected:\n%s\n    actual:\n%s\n' "$(sed 's/^/      /' <<<"$1")" "$(sed 's/^/      /' <<<"$2")" >&2
	fi
}

assert_rc() {
	if [[ "$2" == "$1" ]]; then
		ok "$3"
	else
		not_ok "$3 (expected rc=$1, got rc=$2; stdout: ${OUT:-}; stderr: ${ERR:-})"
	fi
}

assert_contains() {
	if [[ "$2" == *"$1"* ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected to contain: %s\n    actual: %s\n' "$1" "$2" >&2
	fi
}

assert_not_contains() {
	if [[ "$2" != *"$1"* ]]; then
		ok "$3"
	else
		not_ok "$3"
		printf '    expected not to contain: %s\n    actual: %s\n' "$1" "$2" >&2
	fi
}

assert_true() {
	local NAME="$1"
	shift
	if "$@"; then ok "${NAME}"; else not_ok "${NAME}"; fi
}

# run <command...>: in a subshell, since installer functions may exit. Sets RC,
# OUT (stdout) and ERR (stderr).
run() {
	("$@") >"${T}/out" 2>"${T}/err" </dev/null
	RC=$?
	OUT="$(cat "${T}/out")"
	ERR="$(cat "${T}/err")"
}

# ── Settings under test: everything below the test root ─────────────────────
AWG_BT_TRUST_ANCHOR="${T}"
AWG_BT_TRUSTED_UID="$(id -u)"
AWG_BT_STORE_DIR="${T}/usr/local/lib/amneziawg-install/boringtun"
AWG_BT_LIBEXEC_DIR="${T}/usr/local/libexec/amneziawg-install"
AWG_BT_RUN_DIR="${T}/run/amneziawg-install"
AWG_BT_CONFIG_DIR="${T}/etc/amnezia/amneziawg"
AWG_BT_SYSTEMD_DIR="${T}/etc/systemd/system"
AWG_BT_SYSTEMD_RUNTIME_DIR="${T}/run/systemd/system"
AWG_BT_WG_SOCKET_DIR="${T}/run/wireguard"
AWG_BT_AWG_SOCKET_DIR="${T}/run/amneziawg"
AWG_BT_SYS_DIR="${T}/sys"
AWG_BT_PROC_DIR="/proc"
AWG_BT_PATH="${MOCKBIN}:/usr/local/bin:/usr/bin:/bin"
AWG_BT_HOST_ARCH="x86_64"
AWG_BT_TMP_DIR="${T}/tmp"
AMNEZIAWG_DIR="${T}/etc/amnezia/amneziawg"
WEB_PANEL_CONFIG_DIR="${AMNEZIAWG_DIR}/clients"
TMPDIR="${T}/tmp"
STORE="${AWG_BT_STORE_DIR}"
mkdir -p "${AMNEZIAWG_DIR}/clients" "${STORE}" "${T}/tmp" "${T}/run" "${T}/sys/module"
chmod -R go-w "${T}"
PATH="${MOCKBIN}:${PATH}"
EXEC_LOG="${S}/binary-runs"

# systemctl: ActiveState from <state>/active-state (show fails while
# <state>/show-fails exists), MainPID from <state>/main-pid; restart logs the
# release current selects and fails while <state>/restart-rc holds a nonzero
# line (one line per call, the last repeating), and sends TERM to its caller
# once when <state>/restart-term exists.
cat >"${MOCKBIN}/systemctl" <<EOF
#!/bin/bash
echo "systemctl \$*" >>'${S}/log'
case "\$1" in
	show)
		[[ -f '${S}/show-fails' ]] && exit 1
		case "\$*" in
			*ActiveState*) cat '${S}/active-state' 2>/dev/null ;;
			*MainPID*) cat '${S}/main-pid' 2>/dev/null || echo 0 ;;
			*) exit 1 ;;
		esac
		exit 0
		;;
	is-active)
		[[ "\$(cat '${S}/active-state' 2>/dev/null)" == active ]]
		exit
		;;
	restart)
		echo "restart current=\$(readlink '${STORE}/current')" >>'${S}/log'
		if [[ -f '${S}/restart-term' ]]; then
			rm -f '${S}/restart-term'
			kill -TERM "\${PPID}"
		fi
		RC=0
		if [[ -s '${S}/restart-rc' ]]; then
			RC="\$(head -n 1 '${S}/restart-rc')"
			[[ "\$(wc -l <'${S}/restart-rc')" -gt 1 ]] && sed -i 1d '${S}/restart-rc'
		fi
		# A start runs the installed helpers, which verify the store
		# themselves: with <state>/restart-uses-helper, both installed
		# helpers must accept the release current selects.
		if [[ -f '${S}/restart-uses-helper' ]]; then
			for HELPER in '${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl' '${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch'; do
				if VERIFIED="\$(bash -c 'source <(head -n -2 "\$1") >/dev/null 2>&1 || exit 2; _awgBtVerifyStore 2>/dev/null && printf "%s" "\${_AWG_BT_VERIFIED_BIN}"' _ "\${HELPER}")"; then
					echo "helper \${HELPER##*/} verified \$(basename "\$(dirname "\${VERIFIED}")")" >>'${S}/log'
				else
					echo "helper \${HELPER##*/} refused current" >>'${S}/log'
					RC=1
				fi
			done
		fi
		exit "\${RC}"
		;;
esac
exit 0
EOF
# stat: params are reported as root's, as validateParamsFile requires.
cat >"${MOCKBIN}/stat" <<'EOF'
#!/bin/bash
LAST="${!#}"
if [[ "${LAST}" == */params && "$*" == *"-c %u "* ]]; then
	printf '0\n'
	exit 0
fi
exec /usr/bin/stat "$@"
EOF
# awg: the interface's peers come from <state>/peers.
cat >"${MOCKBIN}/awg" <<EOF
#!/bin/bash
echo "awg \$*" >>'${S}/log'
if [[ "\$1" == show && "\$3" == peers ]]; then
	cat '${S}/peers' 2>/dev/null
	exit 0
fi
exit 0
EOF
# curl serves <state>/serve/<tag>/<asset> for .../releases/download/<tag>/<asset>.
cat >"${MOCKBIN}/curl" <<EOF
#!/bin/bash
echo "curl \$*" >>'${S}/curl-log'
OUTPUT=""
while ((\$#)); do
	case "\$1" in
		-o) OUTPUT="\$2"; shift 2 ;;
		--retry | --retry-delay | --connect-timeout | --max-time | --proto | --proto-redir) shift 2 ;;
		-*) shift ;;
		*) URL="\$1"; shift ;;
	esac
done
[[ -f '${S}/curl-rc' ]] && exit "\$(cat '${S}/curl-rc')"
TAG="\${URL%/*}"
TAG="\${TAG##*/}"
cp -- "${FIXTURE}/serve/\${TAG}/\${URL##*/}" "\${OUTPUT}" || exit 22
EOF
# sha256sum: the real one. With <state>/hash-fail holding
# "<path> <n> <missing|status>", the n-th run that hashes <path> fails for
# real: "missing" hashes a path that does not exist in its place (that file's
# hash is absent and the run fails), "status" hashes everything and then fails.
REAL_SHA256SUM="$(PATH=/usr/bin:/bin command -v sha256sum)"
cat >"${MOCKBIN}/sha256sum" <<EOF
#!/bin/bash
if [[ -s '${S}/hash-fail' ]]; then
	read -r FAIL_PATH FAIL_CALL FAIL_MODE <'${S}/hash-fail'
	for ARG in "\$@"; do
		[[ "\${ARG}" == "\${FAIL_PATH}" ]] || continue
		CALL=\$((\$(cat '${S}/hash-calls' 2>/dev/null || echo 0) + 1))
		echo "\${CALL}" >'${S}/hash-calls'
		[[ "\${CALL}" == "\${FAIL_CALL}" ]] || break
		if [[ "\${FAIL_MODE}" == status ]]; then
			'${REAL_SHA256SUM}' "\$@"
			exit 1
		fi
		ARGS=()
		for ARG in "\$@"; do
			[[ "\${ARG}" == "\${FAIL_PATH}" ]] && ARG="\${FAIL_PATH}.injected-missing"
			ARGS+=("\${ARG}")
		done
		exec '${REAL_SHA256SUM}' "\${ARGS[@]}"
	done
fi
exec '${REAL_SHA256SUM}' "\$@"
EOF
chmod 0755 "${MOCKBIN}"/*
hash -r

# ── Function stubs ───────────────────────────────────────────────────────────
acquireClientLifecycleLock() {
	echo "lock" >>"${S}/log"
}
_awgBtCheckServedByBoringtun() {
	echo "served current=$(readlink "${STORE}/current")" >>"${S}/log"
	return "$(cat "${S}/served-rc" 2>/dev/null || echo 0)"
}
# The activation check: logs the release current selects and the imitation
# it was asked for; fails while <state>/verify-rc holds a nonzero line.
verifyBoringtunImitationServed() {
	local RC=0
	echo "verify current=$(readlink "${STORE}/current") imitation=$1|$2" >>"${S}/log"
	[[ -f "${S}/verify-touch" ]] && echo "# changed during the switch" >>"${AMNEZIAWG_DIR}/clients/awg0-client-bob.conf"
	if [[ -s "${S}/verify-rc" ]]; then
		RC="$(head -n 1 "${S}/verify-rc")"
		[[ "$(wc -l <"${S}/verify-rc")" -gt 1 ]] && sed -i 1d "${S}/verify-rc"
	fi
	return "${RC}"
}
# The candidate's validation on scratch instances: logs the candidate, what
# current selects meanwhile, and what it validates; a release listed in
# <state>/reject-probe or <state>/reject-validate refuses.
_probe_stub() { # <label> <key>
	echo "probe$1 candidate=${_AWG_BT_CANDIDATE_RELEASE} current=$(readlink "${STORE}/current") key=$([[ "$2" == "${AWG_HEADER_PROTECTION_KEY:-}" && -n "$2" ]] && echo persisted || echo other)" >>"${S}/log"
	! grep -qxF -- "${_AWG_BT_CANDIDATE_RELEASE}" "${S}/reject-probe" 2>/dev/null
}
probeAwg3Capability() { _probe_stub 3 "${1:-}"; }
probeAwg31Capability() { _probe_stub 31 "${1:-}"; }
validateStagedAwgConfigs() {
	local WORK_DIR="$1" FILE NAMES=""
	shift
	for FILE in "$@"; do
		NAMES+="${FILE##*/} "
	done
	echo "validate candidate=${_AWG_BT_CANDIDATE_RELEASE} current=$(readlink "${STORE}/current") imitation=${AWG_BORINGTUN_IMITATE_PROTOCOL}|${AWG_BORINGTUN_IMITATE_DOMAIN} files=${NAMES% }" >>"${S}/log"
	[[ -f "${S}/validate-term" ]] && { rm -f "${S}/validate-term"; kill -TERM "${BASHPID}"; }
	[[ -f "${S}/validate-touch" ]] && echo "# changed during the validation" >>"${AMNEZIAWG_DIR}/clients/awg0-client-bob.conf"
	! grep -qxF -- "${_AWG_BT_CANDIDATE_RELEASE}" "${S}/reject-validate" 2>/dev/null
}
collectActiveAwgClientConfigs() {
	local -n OUTPUT_REF="$1"
	OUTPUT_REF=("${AMNEZIAWG_DIR}/clients/awg0-client-alice.conf" "${AMNEZIAWG_DIR}/clients/awg0-client-bob.conf")
	[[ ! -f "${S}/collect-fails" ]]
}

# ── Fixture releases (TEST FIXTURES, never published) ───────────────────────
# release <name> <version> <source commit> <build> [version printed]: a fake
# boringtun-cli whose bytes name the fixture, packed as the real release
# layout (the archive's directory carries no build, as the published assets
# do not) and served under its own tag. Records VERSION_, COMMIT_, BUILD_,
# TAG_, ASSET_, ARCHIVE_, STORE_ID_, ARCHIVE_SHA_ and BINARY_SHA_<name>.
declare -A VERSION_ COMMIT_ BUILD_ TAG_ ASSET_ ARCHIVE_ID_ STORE_ID_ ARCHIVE_SHA_ BINARY_SHA_
REPOSITORY="${AWG_BT_RELEASE_SOURCE_REPOSITORY}"
write_manifest() { # <dir> <version> <commit> [key=value...]
	local DIR="$1" KEY
	local -A M=(
		[artifact_format]=1 [name]=boringtun-cli [version]="$2"
		[source_repository]="${REPOSITORY}" [source_commit]="$3"
		[source_date_epoch]=1790626003 [target]=x86_64-unknown-linux-musl [os]=linux [arch]=x86_64 [libc]=musl
		[linkage]=static [rust_toolchain]=1.98.1 [rustc]="rustc 1.98.1" [cargo]="cargo 1.98.1"
		[build_command]="cargo build --release --locked -p boringtun-cli" [build_profile]="release,strip=symbols"
		[rustflags]="--remap-path-prefix=<source>=/boringtun" [binary]=boringtun-cli
		[binary_sha256]="$(sha256sum "${DIR}/boringtun-cli" | cut -d' ' -f1)"
		[license]="LICENSE (BSD-3-Clause)" [third_party_licenses]=THIRD-PARTY-LICENSES
	)
	shift 3
	for KEY in "$@"; do
		M["${KEY%%=*}"]="${KEY#*=}"
	done
	for KEY in ${AWG_BT_MANIFEST_KEYS}; do
		printf '%s=%s\n' "${KEY}" "${M[${KEY}]}"
	done >"${DIR}/MANIFEST"
}
release() {
	local NAME="$1" VERSION="$2" COMMIT="$3" BUILD="$4" PRINTED="${5:-boringtun $2}" DIR ARCHIVE_ID
	ARCHIVE_ID="boringtun-cli-${VERSION}-g${COMMIT:0:12}-linux-x86_64-musl"
	DIR="${FIXTURE}/${NAME}/${ARCHIVE_ID}"
	mkdir -p "${DIR}" "${FIXTURE}/serve/fixture-${NAME}"
	printf '#!/bin/sh\n# TEST FIXTURE %s\necho "run %s $*" >>%s\n[ "$1" = --version ] && echo "%s"\nexit 0\n' \
		"${NAME}" "${NAME}" "${EXEC_LOG}" "${PRINTED}" >"${DIR}/boringtun-cli"
	chmod 0755 "${DIR}/boringtun-cli"
	printf 'BSD-3-Clause fixture\n' >"${DIR}/LICENSE"
	printf 'fixture notices\n' >"${DIR}/THIRD-PARTY-LICENSES"
	write_manifest "${DIR}" "${VERSION}" "${COMMIT}"
	tar --no-recursion --numeric-owner --owner=0 --group=0 -czf "${FIXTURE}/serve/fixture-${NAME}/${ARCHIVE_ID}.tar.gz" -C "${FIXTURE}/${NAME}" \
		"${ARCHIVE_ID}/" "${ARCHIVE_ID}/LICENSE" "${ARCHIVE_ID}/MANIFEST" "${ARCHIVE_ID}/THIRD-PARTY-LICENSES" "${ARCHIVE_ID}/boringtun-cli"
	VERSION_["${NAME}"]="${VERSION}"
	COMMIT_["${NAME}"]="${COMMIT}"
	BUILD_["${NAME}"]="${BUILD}"
	TAG_["${NAME}"]="fixture-${NAME}"
	ASSET_["${NAME}"]="${ARCHIVE_ID}.tar.gz"
	ARCHIVE_ID_["${NAME}"]="${ARCHIVE_ID}"
	STORE_ID_["${NAME}"]="$(_awgBtReleaseStoreId "${VERSION}" "${COMMIT}" "${BUILD}" x86_64)"
	ARCHIVE_SHA_["${NAME}"]="$(sha256sum "${FIXTURE}/serve/fixture-${NAME}/${ARCHIVE_ID}.tar.gz" | cut -d' ' -f1)"
	BINARY_SHA_["${NAME}"]="$(sha256sum "${DIR}/boringtun-cli" | cut -d' ' -f1)"
}
COMMIT_X="1111111111111111111111111111111111111111"
release b1 0.7.1 "${COMMIT_X}" 1
release b2 0.7.1 "${COMMIT_X}" 2
release old 0.7.0 "2222222222222222222222222222222222222222" 1
release new 0.7.2 "3333333333333333333333333333333333333333" 1
release old5 0.6.5 "4444444444444444444444444444444444444444" 1

# pin_to <fixture>: this installer's embedded release becomes the fixture.
pin_to() {
	local NAME="$1"
	AWG_BT_RELEASE_TAG="${TAG_[${NAME}]}"
	AWG_BT_RELEASE_BASE_URL="https://github.com/wiresock/amneziawg-install/releases/download/${TAG_[${NAME}]}"
	AWG_BT_RELEASE_VERSION="${VERSION_[${NAME}]}"
	AWG_BT_RELEASE_SOURCE_COMMIT="${COMMIT_[${NAME}]}"
	AWG_BT_RELEASE_BUILD="${BUILD_[${NAME}]}"
	AWG_BT_RELEASE_ASSET_X86_64="${ASSET_[${NAME}]}"
	AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64="${ARCHIVE_SHA_[${NAME}]}"
	AWG_BT_RELEASE_BINARY_SHA256_X86_64="${BINARY_SHA_[${NAME}]}"
}
# store_release <fixture> [store id]: the fixture as a release an earlier
# lifecycle operation installed in the store.
store_release() {
	local NAME="$1" ID="${2:-${STORE_ID_[$1]}}"
	rm -rf -- "${STORE:?}/${ID}"
	cp -r -- "${FIXTURE}/${NAME}/${ARCHIVE_ID_[${NAME}]}" "${STORE}/${ID}"
	chmod 0755 "${STORE}/${ID}" "${STORE}/${ID}/boringtun-cli"
	chmod 0644 "${STORE}/${ID}/LICENSE" "${STORE}/${ID}/MANIFEST" "${STORE}/${ID}/THIRD-PARTY-LICENSES"
}
links() { # <current fixture|-> [previous fixture|none]
	rm -f -- "${STORE}/current" "${STORE}/previous"
	[[ "$1" == - ]] || ln -s -- "${STORE_ID_[$1]}" "${STORE}/current"
	[[ "${2:-none}" == none ]] || ln -s -- "${STORE_ID_[$2]}" "${STORE}/previous"
}
link_of() { # <current|previous>
	if [[ -L "${STORE}/$1" ]]; then readlink "${STORE}/$1"; else echo none; fi
}
store_names() {
	find "${STORE}" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort | tr '\n' ' '
}
sorted() { # <name>...: as store_names lists them
	printf '%s\n' "$@" | LC_ALL=C sort | tr '\n' ' '
}
# The bytes current runs: which fixture's binary current selects.
current_bytes() {
	sha256sum "${STORE}/current/boringtun-cli" 2>/dev/null | cut -d' ' -f1
}

# ── Fixture installation ─────────────────────────────────────────────────────
MOCK_KEY="bW9ja2tleW1vY2trZXltb2NrZXltb2Nra2V5bW9ja2s="
RUNTIME_FILE="${AMNEZIAWG_DIR}/awg0.boringtun"
# make_install <protocol> [domain] [AWG version]: a BoringTun installation of
# that state with two clients, a clean log and an active unit.
make_install() {
	rm -rf -- "${AMNEZIAWG_DIR}"
	mkdir -p "${AMNEZIAWG_DIR}/clients"
	chmod 0755 "${AMNEZIAWG_DIR}"
	rm -f -- "${S}"/*
	SERVER_PUB_IP="198.51.100.10"
	SERVER_PUB_NIC="eth0"
	SERVER_AWG_NIC="awg0"
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/awg0.conf"
	SERVER_AWG_IPV4="10.66.66.1"
	SERVER_AWG_IPV6="fd42:42:42:0:0:0:0:1"
	SERVER_PORT="51820"
	SERVER_PRIV_KEY="${MOCK_KEY}"
	SERVER_PUB_KEY="c2VydmVycHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo="
	CLIENT_DNS_1="1.1.1.1"
	CLIENT_DNS_2="1.0.0.1"
	ALLOWED_IPS="0.0.0.0/0"
	ENABLE_IPV6="n"
	SERVER_AWG_JC="4"
	SERVER_AWG_JMIN="10"
	SERVER_AWG_JMAX="50"
	SERVER_AWG_S1="20"
	SERVER_AWG_S2="30"
	SERVER_AWG_S3="40"
	SERVER_AWG_S4="50"
	SERVER_AWG_H1="100-200"
	SERVER_AWG_H2="300-400"
	SERVER_AWG_H3="500-600"
	SERVER_AWG_H4="700-800"
	AWG_BACKEND=boringtun
	AWG_BORINGTUN_IMITATE_PROTOCOL="${1:-none}"
	AWG_BORINGTUN_IMITATE_DOMAIN="${2:-}"
	AWG_PROTOCOL_VERSION="${3:-2}"
	clearAwg3Params
	if [[ "${AWG_PROTOCOL_VERSION}" != 2 ]]; then
		AWG_HEADER_PROTECTION_KEY="${MOCK_KEY}"
		AWG_CONTENT_PADDING_ADDITION="${AWG3_DEFAULT_CONTENT_PADDING_ADDITION}"
		AWG_REKEY_AFTER_TIME="${AWG3_DEFAULT_REKEY_AFTER_TIME}"
		AWG_REKEY_TIMEOUT="${AWG3_DEFAULT_REKEY_TIMEOUT}"
		AWG_REJECT_AFTER_TIME="${AWG3_DEFAULT_REJECT_AFTER_TIME}"
		AWG_KEEPALIVE_TIMEOUT="${AWG3_DEFAULT_KEEPALIVE_TIMEOUT}"
		if [[ "${AWG_PROTOCOL_VERSION}" == 3.1 ]]; then
			AWG_RANDOM_TRAILERS="${AWG31_DEFAULT_RANDOM_TRAILERS}"
			AWG_DISABLE_COOKIES="${AWG31_DEFAULT_DISABLE_COOKIES}"
		fi
	fi
	cat >"${SERVER_AWG_CONF}" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIV_KEY}

### Client alice
[Peer]
PublicKey = YWxpY2VwdWJrZXkxMjM0NTY3ODkwYWJjZGVmZ2hpams=
AllowedIPs = 10.66.66.2/32

### Client bob
[Peer]
PublicKey = Ym9icHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG0=
AllowedIPs = 10.66.66.3/32
EOF
	printf '[Interface]\nPrivateKey = %s\nAddress = 10.66.66.%s/32\n' "${MOCK_KEY}" 2 >"${AMNEZIAWG_DIR}/clients/awg0-client-alice.conf"
	printf '[Interface]\nPrivateKey = %s\nAddress = 10.66.66.%s/32\n' "${MOCK_KEY}" 3 >"${AMNEZIAWG_DIR}/clients/awg0-client-bob.conf"
	chmod 600 "${SERVER_AWG_CONF}" "${AMNEZIAWG_DIR}"/clients/*.conf
	serializeParams "${AMNEZIAWG_DIR}/params" || return 1
	chmod 600 "${AMNEZIAWG_DIR}/params"
	_awgBtRenderRuntimeFile >"${RUNTIME_FILE}" || return 1
	chmod 600 "${RUNTIME_FILE}"
	printf '%s\n' YWxpY2VwdWJrZXkxMjM0NTY3ODkwYWJjZGVmZ2hpams= Ym9icHVia2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG0= >"${S}/peers"
	echo active >"${S}/active-state"
	: >"${S}/log"
}
# The hash of every file a binary switch must leave as it is.
config_hashes() {
	sha256sum "${AMNEZIAWG_DIR}/params" "${SERVER_AWG_CONF}" "${RUNTIME_FILE}" "${AMNEZIAWG_DIR}"/clients/*.conf | cut -d' ' -f1 | tr '\n' ' '
}
# The lifecycle state: current, previous, the release directories.
lifecycle_state() {
	printf 'current=%s previous=%s store=[%s]' "$(link_of current)" "$(link_of previous)" "$(store_names)"
}
upgrade() { boringtunBinaryLifecycle upgrade; }
rollback() { boringtunBinaryLifecycle rollback; }
restarts() { grep -c '^restart current=' "${S}/log"; }
# The private work directories the transaction left in TMPDIR.
work_dirs() { find "${T}/tmp" -maxdepth 1 -name 'amneziawg-boringtun-lifecycle.*' | wc -l; }

echo "=== Release identity ==="
# The installer's embedded release, on its own terms: release.env describes the
# release being prepared, which this installer may not have adopted yet.
assert_true "the embedded build number is a positive integer" eval '[[ "${REAL_BUILD}" =~ ^[1-9][0-9]*$ ]]'
assert_eq "b${REAL_BUILD}" "${REAL_TAG##*-g*-}" "the embedded tag ends with that build"
assert_eq "${REAL_ASSET_X86_64%.tar.gz}" "$(_awgBtReleaseStoreId "${REAL_VERSION}" "${REAL_COMMIT}" "${REAL_BUILD}" x86_64)" \
	"the published build 1 keeps the store name PR 4 and PR 5 installs gave it (x86_64)"
assert_eq "${REAL_ASSET_AARCH64%.tar.gz}" "$(_awgBtReleaseStoreId "${REAL_VERSION}" "${REAL_COMMIT}" "${REAL_BUILD}" aarch64)" \
	"  (aarch64)"
assert_eq "boringtun-cli-0.7.1-g111111111111-linux-x86_64-musl" "$(_awgBtReleaseStoreId 0.7.1 "${COMMIT_X}" 1 x86_64)" "build 1 has no build component"
assert_eq "boringtun-cli-0.7.1-g111111111111-b2-linux-x86_64-musl" "$(_awgBtReleaseStoreId 0.7.1 "${COMMIT_X}" 2 x86_64)" "build 2 names its build"
assert_eq "boringtun-cli-0.7.1-g111111111111-b10-linux-aarch64-musl" "$(_awgBtReleaseStoreId 0.7.1 "${COMMIT_X}" 10 aarch64)" "build 10 too"
for BAD in 0 01 x "" -1; do
	run _awgBtReleaseStoreId 0.7.1 "${COMMIT_X}" "${BAD}" x86_64
	assert_rc 1 "${RC}" "build '${BAD}' is refused"
done
for ID in boringtun-cli-0.7.1-g111111111111-linux-x86_64-musl boringtun-cli-0.7.1-g111111111111-b2-linux-x86_64-musl \
	boringtun-cli-10.20.30-gabcdefabcdef-b123-linux-aarch64-musl; do
	assert_true "'${ID}' is a release name" _awgBtReleaseIdValid "${ID}"
done
for ID in boringtun-cli-0.7.1-g111111111111-b1-linux-x86_64-musl boringtun-cli-0.7.1-g111111111111-b0-linux-x86_64-musl \
	boringtun-cli-0.7.1-g111111111111-b01-linux-x86_64-musl boringtun-cli-0.7.1-g111111111111-linux-riscv64-musl \
	../boringtun-cli-0.7.1-g111111111111-linux-x86_64-musl "/x/boringtun-cli-0.7.1-g111111111111-linux-x86_64-musl" \
	boringtun-cli-0.7.1-g111111111111-linux-x86_64-musl/boringtun-cli boringtun-cli-0.7.1-g11111111111-linux-x86_64-musl \
	"boringtun-cli-0.7.1-g111111111111-linux-x86_64-musl " current previous ""; do
	if _awgBtReleaseIdValid "${ID}"; then not_ok "'${ID}' is not a release name"; else ok "'${ID}' is not a release name"; fi
done

echo "=== Build 1 and build 2 of one source commit ==="
assert_eq "${VERSION_[b1]} ${COMMIT_[b1]} ${ARCHIVE_ID_[b1]}" "${VERSION_[b2]} ${COMMIT_[b2]} ${ARCHIVE_ID_[b2]}" \
	"the fixtures share version, source commit and archive directory, as two published builds would"
assert_true "but not their binaries" test "${BINARY_SHA_[b1]}" != "${BINARY_SHA_[b2]}"
assert_true "and not their store directories" test "${STORE_ID_[b1]}" != "${STORE_ID_[b2]}"
store_release b1
store_release b2
assert_eq "$(sorted "${STORE_ID_[b1]}" "${STORE_ID_[b2]}")" "$(store_names)" "both coexist in the store"
for NAME in b1 b2; do
	run _awgBtVerifyRelease "${STORE_ID_[${NAME}]}"
	assert_rc 0 "${RC}" "${NAME} verifies under its own name"
done
cp -r -- "${STORE}/${STORE_ID_[b2]}" "${STORE}/boringtun-cli-0.7.1-g222222222222-b2-linux-x86_64-musl"
run _awgBtVerifyRelease boringtun-cli-0.7.1-g222222222222-b2-linux-x86_64-musl
assert_rc 1 "${RC}" "a build directory whose MANIFEST names another commit does not verify"
rm -rf -- "${STORE}/boringtun-cli-0.7.1-g222222222222-b2-linux-x86_64-musl"

make_install dns example.com
rm -rf -- "${STORE:?}"/*
store_release b1
links b1
pin_to b2
BEFORE_HASHES="$(config_hashes)"
run upgrade
assert_rc 0 "${RC}" "b1 -> b2: the upgrade succeeds"
assert_eq "current=${STORE_ID_[b2]} previous=${STORE_ID_[b1]} store=[$(sorted ${STORE_ID_[b1]} ${STORE_ID_[b2]} previous current)]" \
	"$(lifecycle_state)" "b1 -> b2: current is b2, previous b1, both kept side by side"
assert_eq "${BINARY_SHA_[b2]}" "$(current_bytes)" "b1 -> b2: current runs the b2 bytes"
assert_contains "curl" "$(cat "${S}/curl-log" 2>/dev/null)" "b1 -> b2: b2 was downloaded through the release path"
assert_contains "releases/download/${TAG_[b2]}/${ASSET_[b2]}" "$(cat "${S}/curl-log")" "  from its own tag"
pin_to b1
run rollback
assert_rc 0 "${RC}" "b2 -> b1: the rollback succeeds"
assert_eq "current=${STORE_ID_[b1]} previous=${STORE_ID_[b2]}" "$(lifecycle_state | sed 's/ store=.*//')" "b2 -> b1: current is b1, previous b2"
assert_eq "${BINARY_SHA_[b1]}" "$(current_bytes)" "b2 -> b1: current runs the b1 bytes"
assert_eq "${BEFORE_HASHES}" "$(config_hashes)" "params, configs and the runtime file are unchanged by both"
run printBackendStatus
assert_contains $'installed_release='"${STORE_ID_[b1]}"$'\npinned_release='"${STORE_ID_[b1]}" "${OUT}" "status: installed b1, pinned b1"
assert_contains $'previous_release='"${STORE_ID_[b2]}"$'\nrollback_available=yes\nupgrade_available=no' "${OUT}" "status: previous b2, rollback possible, nothing to upgrade"

echo "=== A store from PR 4 or PR 5: current only ==="
make_install
rm -rf -- "${STORE:?}"/*
store_release b1
links b1
pin_to b1
STATE_BEFORE="$(lifecycle_state)"
INODE_BEFORE="$(stat -c %i "${STORE}/current")"
run upgrade
assert_rc 0 "${RC}" "the pinned release already current: --upgrade-boringtun succeeds"
assert_contains "already current; nothing was changed" "${OUT}" "  as a no-op"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "  the links and the store are as they were"
assert_eq "${INODE_BEFORE}" "$(stat -c %i "${STORE}/current")" "  current was not even rewritten"
assert_eq "0" "$(restarts)" "  no restart"
assert_true "  no download" test ! -s "${S}/curl-log"
assert_not_contains "validate" "$(cat "${S}/log")" "  no candidate validation"
run printBackendStatus
assert_contains $'previous_release=none\nrollback_available=no\nupgrade_available=no' "${OUT}" "status of a PR 4/5 store: no previous, no rollback, no upgrade"
pin_to new
run printBackendStatus
assert_contains "upgrade_available=yes" "${OUT}" "with a newer pin, status offers the upgrade"
run upgrade
assert_rc 0 "${RC}" "a PR 4/5 store upgrades without any manual change"
assert_eq "current=${STORE_ID_[new]} previous=${STORE_ID_[b1]}" "$(lifecycle_state | sed 's/ store=.*//')" "  current is the new pin, previous the legacy build 1"

echo "=== Fresh install ==="
rm -rf -- "${STORE:?}"/*
: >"${S}/curl-log"
pin_to b1
run installBoringtunRelease
assert_rc 0 "${RC}" "a fresh install of build 1"
assert_eq "current=${STORE_ID_[b1]} previous=none store=[$(sorted ${STORE_ID_[b1]} current)]" "$(lifecycle_state)" "  stores it under the legacy name, with no previous"
rm -rf -- "${STORE:?}"/*
pin_to b2
run installBoringtunRelease
assert_rc 0 "${RC}" "a fresh install of build 2"
assert_eq "current=${STORE_ID_[b2]} previous=none store=[$(sorted ${STORE_ID_[b2]} current)]" "$(lifecycle_state)" "  stores it under its build name, although the archive's directory has none"
assert_eq "${BINARY_SHA_[b2]}" "$(current_bytes)" "  with the b2 bytes"

echo "=== No previous release ==="
make_install
rm -rf -- "${STORE:?}"/*
store_release old
links old
pin_to new
STATE_BEFORE="$(lifecycle_state)"
run rollback
assert_rc 1 "${RC}" "a rollback without previous fails"
assert_contains "no BoringTun release to roll back to" "${ERR}" "  and says why"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "  nothing changed"
assert_eq "0" "$(restarts)" "  no restart"
store_release new
links old old
run rollback
assert_rc 1 "${RC}" "a rollback whose previous names current fails"

echo "=== Service states ==="
for STATE in active inactive failed; do
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old
	links old
	pin_to new
	echo "${STATE}" >"${S}/active-state"
	run upgrade
	assert_rc 0 "${RC}" "${STATE}: upgrade"
	assert_eq "${STORE_ID_[new]} ${STORE_ID_[old]}" "$(link_of current) $(link_of previous)" "${STATE}: current and previous switched"
	if [[ "${STATE}" == active ]]; then
		assert_eq "1" "$(restarts)" "active: one deliberate restart"
		assert_contains "restart current=${STORE_ID_[new]}" "$(cat "${S}/log")" "active: after current names the new release"
		assert_contains "verify current=${STORE_ID_[new]} imitation=none|" "$(cat "${S}/log")" "active: and the restarted service is verified on it"
		assert_true "active: the start counter is reset first" grep -q '^systemctl reset-failed awg-quick@awg0.service' "${S}/log"
	else
		assert_eq "0" "$(restarts)" "${STATE}: the service is not started"
		assert_contains "was not started" "${OUT}" "${STATE}: and the operator is told"
	fi
	: >"${S}/log"
	run rollback
	assert_rc 0 "${RC}" "${STATE}: rollback"
	assert_eq "${STORE_ID_[old]} ${STORE_ID_[new]}" "$(link_of current) $(link_of previous)" "${STATE}: rolled back, the upgrade becoming previous"
	if [[ "${STATE}" == active ]]; then
		assert_eq "1" "$(restarts)" "active: rollback restarts once"
	else
		assert_eq "0" "$(restarts)" "${STATE}: rollback does not start it either"
	fi
done
for STATE in activating deactivating reloading refreshing ""; do
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old
	store_release new
	links old new
	pin_to b2
	echo "${STATE}" >"${S}/active-state"
	STATE_BEFORE="$(lifecycle_state)"
	run upgrade
	assert_rc 1 "${RC}" "'${STATE:-unknown}': the upgrade aborts"
	run rollback
	assert_rc 1 "${RC}" "'${STATE:-unknown}': so does the rollback"
	assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "'${STATE:-unknown}':   before any change"
	assert_true "'${STATE:-unknown}':   and before any download" test ! -s "${S}/curl-log"
done
make_install
links old new
touch "${S}/show-fails"
STATE_BEFORE="$(lifecycle_state)"
run rollback
assert_rc 1 "${RC}" "an unreadable unit state aborts"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "  before any change"

echo "=== A kernel installation ==="
make_install
AWG_BACKEND=kernel
AWG_BORINGTUN_IMITATE_PROTOCOL=none
serializeParams "${AMNEZIAWG_DIR}/params"
chmod 600 "${AMNEZIAWG_DIR}/params"
rm -rf -- "${STORE:?}"/*
store_release old
links old
pin_to new
STATE_BEFORE="$(lifecycle_state)"
run upgrade
assert_rc 1 "${RC}" "a kernel installation has no BoringTun binary to upgrade"
assert_contains "applies only to the BoringTun backend" "${ERR}" "  and says so"
assert_true "  before any download" test ! -s "${S}/curl-log"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "  or store change"
assert_eq "0" "$(restarts)" "  or service change"

echo "=== The target is validated before it becomes current ==="
for SETTING in "none||2" "dns|example.com|2" "dns|example.com|3" "dns|example.com|3.1" "stun||2" "quic|cdn.example.org|3"; do
	IFS='|' read -r P D V <<<"${SETTING}"
	make_install "${P}" "${D}" "${V}"
	rm -rf -- "${STORE:?}"/*
	store_release old
	links old
	pin_to new
	BEFORE_HASHES="$(config_hashes)"
	run upgrade
	LOG="$(cat "${S}/log")"
	LABEL="AWG ${V} + ${P}"
	assert_rc 0 "${RC}" "${LABEL}: the upgrade succeeds"
	assert_contains "validate candidate=${STORE_ID_[new]} current=${STORE_ID_[old]} imitation=${P}|${D} files=awg0.conf client-1.conf client-2.conf" "${LOG}" \
		"${LABEL}: the new binary validated the server and both client configs with the persisted imitation while current was still the old release"
	case "${V}" in
		2) assert_not_contains "probe" "${LOG}" "${LABEL}: no AWG 3.x probe" ;;
		3) assert_contains "probe3 candidate=${STORE_ID_[new]} current=${STORE_ID_[old]} key=persisted" "${LOG}" "${LABEL}: the AWG 3.0 probe ran on the new binary with the persisted key" ;;
		3.1) assert_contains "probe31 candidate=${STORE_ID_[new]} current=${STORE_ID_[old]} key=persisted" "${LOG}" "${LABEL}: the AWG 3.1 probe ran on the new binary with the persisted key" ;;
	esac
	assert_eq "${BEFORE_HASHES}" "$(config_hashes)" "${LABEL}: params, configs and the runtime file are byte for byte the same after the upgrade"
	: >"${S}/log"
	run rollback
	assert_rc 0 "${RC}" "${LABEL}: the rollback succeeds"
	assert_contains "validate candidate=${STORE_ID_[old]} current=${STORE_ID_[new]} imitation=${P}|${D}" "$(cat "${S}/log")" \
		"${LABEL}: the old binary is validated against the current settings before it becomes current again"
	assert_eq "${BEFORE_HASHES}" "$(config_hashes)" "${LABEL}: and after the rollback"
done

make_install dns example.com 3
rm -rf -- "${STORE:?}"/*
store_release old
store_release new
links new old
pin_to new
echo "${STORE_ID_[old]}" >"${S}/reject-probe"
STATE_BEFORE="$(lifecycle_state)"
run rollback
assert_rc 1 "${RC}" "a previous binary that rejects the current AWG 3.0 settings is refused"
assert_contains "does not accept this installation's current settings" "${ERR}" "  and says why"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "  before current changed, and the old release is kept"
assert_eq "0" "$(restarts)" "  no restart"
rm -f "${S}/reject-probe"
echo "${STORE_ID_[old]}" >"${S}/reject-validate"
run rollback
assert_rc 1 "${RC}" "a previous binary that rejects the current configs is refused"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "  before current changed"
make_install
rm -rf -- "${STORE:?}"/*
store_release old
links old
pin_to new
echo "${STORE_ID_[new]}" >"${S}/reject-validate"
run upgrade
assert_rc 1 "${RC}" "an upgrade target that rejects the configs is refused"
assert_eq "current=${STORE_ID_[old]} previous=none store=[$(sorted ${STORE_ID_[old]} current)]" "$(lifecycle_state)" \
	"  current unchanged, and the release this attempt downloaded is removed"

echo "=== Activation failures restore both links ==="
activation_case() { # <label> <restart rc lines> <verify rc lines> <expected rc> [kept]
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old5
	store_release old
	links old old5
	pin_to new
	printf '%s\n' $2 >"${S}/restart-rc"
	printf '%s\n' $3 >"${S}/verify-rc"
	BEFORE_HASHES="$(config_hashes)"
	rm -rf -- "${T}"/tmp/amneziawg-boringtun-lifecycle.*
	run upgrade
	assert_rc "$4" "${RC}" "$1: the upgrade fails"
	assert_eq "0" "$(work_dirs)" "$1: no private copy of a client config is left behind"
	if [[ "${5:-}" == kept ]]; then
		assert_eq "current=${STORE_ID_[old]} previous=${STORE_ID_[old5]} store=[$(sorted ${STORE_ID_[new]} ${STORE_ID_[old]} ${STORE_ID_[old5]} current previous)]" "$(lifecycle_state)" \
			"$1: current and previous are exactly as before; the downloaded release is kept for the recovery"
	else
		assert_eq "current=${STORE_ID_[old]} previous=${STORE_ID_[old5]} store=[$(sorted ${STORE_ID_[old]} ${STORE_ID_[old5]} current previous)]" "$(lifecycle_state)" \
			"$1: current and previous are exactly as before, the downloaded release is removed and the old previous kept"
	fi
	assert_eq "${BEFORE_HASHES}" "$(config_hashes)" "$1: configs unchanged"
}
activation_case "restart fails" "1 0" "0" 1
assert_eq "restart current=${STORE_ID_[new]}
restart current=${STORE_ID_[old]}" "$(grep '^restart' "${S}/log")" "restart fails: the original release is restarted"
assert_contains "verify current=${STORE_ID_[old]}" "$(cat "${S}/log")" "  and verified"
assert_contains "runs ${STORE_ID_[old]} again" "${ERR}" "  and that is reported"
activation_case "the new daemon is not verified" "0" "1 0" 1
assert_eq "2" "$(restarts)" "unverified: a second restart, on the original"
make_install
rm -rf -- "${STORE:?}"/*
store_release old
links old
pin_to new
printf '%s\n' "only-one-peer" >"${S}/peers.bad"
cp "${S}/peers.bad" "${S}/peers"
run upgrade
assert_rc 1 "${RC}" "an interface without the server's peers fails the activation"
assert_contains "does not carry the peers" "${ERR}" "  and says so"
assert_eq "${STORE_ID_[old]}" "$(link_of current)" "  current is restored"
activation_case "the recovery restart fails too" "1" "0" 1 kept
assert_contains "did not come up verifiably on ${STORE_ID_[new]}" "${ERR}" "both failures are reported: the activation"
assert_contains "the recovery restart of awg-quick@awg0.service on ${STORE_ID_[old]} failed" "${ERR}" "  and the recovery restart"
activation_case "the recovery verification fails" "1 0" "1" 1 kept
assert_contains "is not verifiably served by ${STORE_ID_[old]}" "${ERR}" "the failed recovery verification is reported"

echo "=== Acquisition failures ==="
acquisition_case() { # <label> <expected error fragment> <command breaking the download...>
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old
	links old
	pin_to new
	"${@:3}"
	STATE_BEFORE="$(lifecycle_state)"
	run upgrade
	assert_rc 1 "${RC}" "$1: the upgrade fails"
	assert_contains "$2" "${ERR}" "$1:   because of it"
	assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "$1:   current, previous and the store are as they were"
	assert_eq "0" "$(restarts)" "$1:   no restart"
	assert_not_contains "validate" "$(cat "${S}/log")" "$1:   and nothing was validated, let alone switched"
}
acquisition_case "a failed download" "could not download" eval 'echo 22 >"${S}/curl-rc"'
acquisition_case "an archive with another SHA-256" "does not have the SHA-256 embedded" eval 'AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64=0000000000000000000000000000000000000000000000000000000000000000'
acquisition_case "an archive whose binary has another SHA-256" "" eval 'AWG_BT_RELEASE_BINARY_SHA256_X86_64=0000000000000000000000000000000000000000000000000000000000000000'
acquisition_case "an archive of another layout" "expected release layout" eval '
	mkdir -p "${T}/relayout/${ARCHIVE_ID_[new]}" && cp -r "${FIXTURE}/new/${ARCHIVE_ID_[new]}/." "${T}/relayout/${ARCHIVE_ID_[new]}/" &&
	echo extra >"${T}/relayout/${ARCHIVE_ID_[new]}/EXTRA" &&
	tar -czf "${FIXTURE}/serve/${TAG_[new]}/${ASSET_[new]}.bad" -C "${T}/relayout" "${ARCHIVE_ID_[new]}" &&
	AWG_BT_RELEASE_ARCHIVE_SHA256_X86_64="$(sha256sum "${FIXTURE}/serve/${TAG_[new]}/${ASSET_[new]}.bad" | cut -d" " -f1)" &&
	cp "${FIXTURE}/serve/${TAG_[new]}/${ASSET_[new]}" "${T}/good-new.tar.gz" &&
	mv "${FIXTURE}/serve/${TAG_[new]}/${ASSET_[new]}.bad" "${FIXTURE}/serve/${TAG_[new]}/${ASSET_[new]}"'
cp "${T}/good-new.tar.gz" "${FIXTURE}/serve/${TAG_[new]}/${ASSET_[new]}"

echo "=== Link writes and their restoration ==="
link_fault() { # <label> <failing call: current|previous> <failing call number> [restart rc]
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old5
	store_release old
	links old old5
	pin_to new
	[[ -z "${4:-}" ]] || echo "$4" >"${S}/restart-rc"
	: >"${S}/link-calls"
	eval "$(declare -f _awgBtSetStoreLink | sed '1s/_awgBtSetStoreLink/realSetStoreLink/')"
	_awgBtSetStoreLink() {
		echo "$1" >>"${S}/link-calls"
		if [[ "$1" == "${FAULT_LINK}" && "$(grep -c . "${S}/link-calls")" == "${FAULT_CALL}" ]]; then
			return 1
		fi
		realSetStoreLink "$@"
	}
	FAULT_LINK="$2" FAULT_CALL="$3" upgrade
}
FAULT() { run link_fault "$@"; }
FAULT "no fault" none 0
assert_rc 0 "${RC}" "the upgrade writes its links"
assert_eq "previous current" "$(tr '
' ' ' <"${S}/link-calls" | sed 's/ $//')" 	"previous is written before current, so current never moves before the rollback target is recorded"
FAULT "previous fails" previous 1
assert_rc 1 "${RC}" "writing previous fails: the upgrade fails"
assert_eq "${STORE_ID_[old]} ${STORE_ID_[old5]}" "$(link_of current) $(link_of previous)" "  the links are as before"
assert_eq "0" "$(restarts)" "writing previous fails: no restart, as none had happened"
FAULT "current fails" current 2
assert_rc 1 "${RC}" "writing current fails: the upgrade fails"
assert_eq "${STORE_ID_[old]} ${STORE_ID_[old5]}" "$(link_of current) $(link_of previous)" "  previous, already written, is restored"
FAULT "restoring current fails" current 3 1
assert_rc 1 "${RC}" "when restoring a link fails after a failed write"
assert_contains "could not restore" "${ERR}" "  it is reported"
assert_contains "the store links are not restored" "${ERR}" "  with what the operator has to do"
assert_eq "1" "$(restarts)" "  and the service is not restarted again on links that are not restored"
FAULT "restoring previous fails" previous 4 1
assert_rc 1 "${RC}" "when restoring previous fails after a failed activation"
assert_contains "could not restore ${STORE}/previous to ${STORE_ID_[old5]}" "${ERR}" "  it is reported"
assert_eq "${STORE_ID_[old]}" "$(link_of current)" "  current is restored"
assert_eq "1" "$(restarts)" "  and the service is left for the operator"

echo "=== Signals ==="
make_install
rm -rf -- "${STORE:?}"/*
store_release old5
store_release old
links old old5
pin_to new
touch "${S}/restart-term"
run upgrade
assert_rc 143 "${RC}" "TERM during the restart ends the upgrade"
assert_eq "current=${STORE_ID_[old]} previous=${STORE_ID_[old5]} store=[$(sorted ${STORE_ID_[old]} ${STORE_ID_[old5]} previous current)]" "$(lifecycle_state)" \
	"  after restoring both links and removing the downloaded release"
assert_eq "restart current=${STORE_ID_[old]}" "$(grep '^restart' "${S}/log" | tail -n 1)" "  and restarting the original release"
assert_contains "interrupted" "${ERR}" "  which is reported"
make_install
rm -rf -- "${STORE:?}"/* "${T}"/tmp/amneziawg-boringtun-lifecycle.*
store_release old
links old
pin_to new
touch "${S}/validate-term"
run upgrade
assert_rc 143 "${RC}" "TERM during the validation ends the upgrade"
assert_eq "current=${STORE_ID_[old]} previous=none store=[$(sorted ${STORE_ID_[old]} current)]" "$(lifecycle_state)" \
	"  before any link changed, with the downloaded release removed"
assert_eq "0" "$(restarts)" "  and no restart"
assert_eq "0" "$(work_dirs)" "  and no private work directory left"

echo "=== Retention: current and previous only ==="
make_install
rm -rf -- "${STORE:?}"/*
store_release old5
store_release old
links old old5
pin_to new
run upgrade
assert_rc 0 "${RC}" "upgrade with an older previous"
assert_eq "current=${STORE_ID_[new]} previous=${STORE_ID_[old]} store=[$(sorted ${STORE_ID_[new]} ${STORE_ID_[old]} previous current)]" "$(lifecycle_state)" \
	"  the old previous is removed once the new state is final"
make_install
rm -rf -- "${STORE:?}"/*
store_release old5
store_release old
links old old5
pin_to new
chmod 0777 "${STORE}/${STORE_ID_[old5]}"
run upgrade
assert_rc 0 "${RC}" "an old previous that cannot be removed safely does not fail a finished upgrade"
assert_contains "could not remove ${STORE}/${STORE_ID_[old5]}" "${ERR}" "  it is reported"
assert_true "  and left in place" test -d "${STORE}/${STORE_ID_[old5]}"
chmod 0755 "${STORE}/${STORE_ID_[old5]}"
rm -rf -- "${STORE:?}/${STORE_ID_[old5]}"
run rollback
run upgrade
assert_eq "current=${STORE_ID_[new]} previous=${STORE_ID_[old]} store=[$(sorted ${STORE_ID_[new]} ${STORE_ID_[old]} previous current)]" "$(lifecycle_state)" \
	"a rollback and an upgrade toggle between the two, removing neither"
assert_contains "already current" "$(upgrade 2>&1)" "  and a repeated upgrade is a no-op"
store_release b2
run upgrade
assert_true "an unmanaged release directory is left alone" test -d "${STORE}/${STORE_ID_[b2]}"
run printBackendStatus
assert_contains "unmanaged_releases=1" "${OUT}" "  and counted by the status"
pin_to b1
run upgrade
assert_contains "neither current nor previous names" "${OUT}" "  and named by the next lifecycle operation"
assert_true "  which still leaves it" test -d "${STORE}/${STORE_ID_[b2]}"
ln -s "${STORE_ID_[new]}" "${STORE}/boringtun-cli-9.9.9-g999999999999-linux-x86_64-musl"
run _awgBtPruneRelease boringtun-cli-9.9.9-g999999999999-linux-x86_64-musl
assert_rc 1 "${RC}" "pruning never removes a symlink named like a release"
assert_true "  (it is still there)" test -L "${STORE}/boringtun-cli-9.9.9-g999999999999-linux-x86_64-musl"
rm -f "${STORE}/boringtun-cli-9.9.9-g999999999999-linux-x86_64-musl"
run _awgBtPruneRelease "$(link_of current)"
assert_rc 1 "${RC}" "pruning never removes the release current names"
run _awgBtPruneRelease "$(link_of previous)"
assert_rc 1 "${RC}" "nor the one previous names"
run _awgBtPruneRelease "../state"
assert_rc 1 "${RC}" "nor anything that is not a release name"

echo "=== Damaged links and releases fail closed ==="
damaged() { # <label> <fragment of the expected error> <command damaging the store...>
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old
	store_release new
	links new old
	pin_to new
	"${@:3}"
	: >"${EXEC_LOG}"
	STATE_BEFORE="$(lifecycle_state)"
	run rollback
	assert_rc 1 "${RC}" "$1: the rollback is refused"
	[[ -z "$2" ]] || assert_contains "$2" "${ERR}" "$1:   because of it"
	assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "$1:   nothing changed"
	assert_eq "0" "$(restarts)" "$1:   no restart"
}
OLD_DIR() { echo "${STORE}/${STORE_ID_[old]}"; }
damaged "previous is a directory" "previous is damaged" eval 'rm -f "${STORE}/previous"; mkdir "${STORE}/previous"'
damaged "previous is an absolute link" "previous is damaged" eval 'ln -sfn "${STORE}/${STORE_ID_[old]}" "${STORE}/previous"'
damaged "previous points through a slash" "previous is damaged" eval 'ln -sfn "./${STORE_ID_[old]}" "${STORE}/previous"'
damaged "previous points through .." "previous is damaged" eval 'ln -sfn "../boringtun/${STORE_ID_[old]}" "${STORE}/previous"'
damaged "previous names something outside the store" "previous is damaged" eval 'ln -sfn "/etc" "${STORE}/previous"'
damaged "a writable store" "" chmod 0777 "${STORE}"
chmod 0755 "${STORE}"
damaged "a writable release directory" "" eval 'chmod 0777 "$(OLD_DIR)"'
damaged "a release that is a symlink" "" eval 'mv "$(OLD_DIR)" "${T}/elsewhere"; ln -s "${T}/elsewhere" "$(OLD_DIR)"'
rm -rf "${T}/elsewhere"
damaged "a binary that is a symlink" "" eval 'mv "$(OLD_DIR)/boringtun-cli" "${T}/bin.real"; ln -s "${T}/bin.real" "$(OLD_DIR)/boringtun-cli"'
damaged "a hard-linked binary" "single-link" eval 'ln "$(OLD_DIR)/boringtun-cli" "${T}/hardlink"'
rm -f "${T}/hardlink" "${T}/bin.real"
damaged "an extra member" "exactly the release's four files" eval 'echo x >"$(OLD_DIR)/EXTRA"; chmod 0644 "$(OLD_DIR)/EXTRA"'
damaged "a missing MANIFEST" "" eval 'rm -f "$(OLD_DIR)/MANIFEST"'
damaged "a repeated MANIFEST key" "repeated key" eval 'echo "arch=x86_64" >>"$(OLD_DIR)/MANIFEST"'
damaged "a malformed MANIFEST line" "malformed line" eval 'echo "not a key value" >>"$(OLD_DIR)/MANIFEST"'
damaged "a MANIFEST for another architecture" "does not describe release" eval 'sed -i "s/^arch=x86_64$/arch=aarch64/" "$(OLD_DIR)/MANIFEST"'
damaged "a MANIFEST for another target" "does not describe release" eval 'sed -i "s/^target=.*/target=x86_64-unknown-linux-gnu/" "$(OLD_DIR)/MANIFEST"'
damaged "a MANIFEST of another source repository" "was not built from" eval 'sed -i "s#^source_repository=.*#source_repository=https://example.com/other#" "$(OLD_DIR)/MANIFEST"'
damaged "a binary that does not match its MANIFEST" "does not match the binary_sha256" eval 'echo "# tampered" >>"$(OLD_DIR)/boringtun-cli"'
assert_eq "" "$(grep "run old" "${EXEC_LOG}" 2>/dev/null)" "  the tampered binary never ran"
damaged "a binary that prints another version" "boringtun-cli --version printed" eval '
	sed -i "s/echo \"boringtun 0.7.0\"/echo \"boringtun 9.9.9\"/" "$(OLD_DIR)/boringtun-cli"
	sed -i "s/^binary_sha256=.*/binary_sha256=$(sha256sum "$(OLD_DIR)/boringtun-cli" | cut -d" " -f1)/" "$(OLD_DIR)/MANIFEST"'
# A binary replaced after its hash was taken never runs.
replaced_after_hash() {
	eval "$(declare -f _awgBtVerifyRelease | sed '1s/_awgBtVerifyRelease/realVerifyRelease/')"
	_awgBtVerifyRelease() {
		realVerifyRelease "$@" || return
		if [[ "$1" == "${STORE_ID_[old]}" ]]; then
			cp "${STORE}/$1/boringtun-cli" "${T}/swap" && mv -f "${T}/swap" "${STORE}/$1/boringtun-cli"
		fi
	}
	rollback
}
make_install
rm -rf -- "${STORE:?}"/*
store_release old
store_release new
links new old
: >"${EXEC_LOG}"
run replaced_after_hash
assert_rc 1 "${RC}" "a binary replaced after it was hashed is refused"
assert_contains "changed while it was verified" "${ERR}" "  as replaced"
assert_eq "" "$(grep "run old" "${EXEC_LOG}" 2>/dev/null)" "  and never runs"
assert_eq "${STORE_ID_[new]} ${STORE_ID_[old]}" "$(link_of current) $(link_of previous)" "  nothing changed"
make_install
rm -rf -- "${STORE:?}"/*
store_release old
links old
chmod 0777 "${STORE}/${STORE_ID_[old]}"
pin_to new
run upgrade
assert_rc 1 "${RC}" "an upgrade from a current that does not verify is refused"
assert_contains "does not verify; nothing was changed" "${ERR}" "  and says so"
assert_true "  before any download" test ! -s "${S}/curl-log"

echo "=== An interrupted switch is detected ==="
make_install
rm -rf -- "${STORE:?}"/*
store_release old
store_release new
links new old
pin_to new
echo 1 >"${S}/served-rc"
run upgrade
assert_rc 0 "${RC}" "current already the pin but the service runs another binary: the upgrade finishes the switch"
assert_contains "is not served by it; restarting it on ${STORE_ID_[new]}" "${OUT}" "  and says so instead of reporting a no-op"
assert_eq "1" "$(restarts)" "  with one restart"
assert_contains "verify current=${STORE_ID_[new]}" "$(cat "${S}/log")" "  that is verified"
assert_eq "${STORE_ID_[new]} ${STORE_ID_[old]}" "$(link_of current) $(link_of previous)" "  the links are left as they were"
echo 1 >"${S}/verify-rc"
run upgrade
assert_rc 1 "${RC}" "  and fails visibly when that restart is not verified"

echo "=== --backend-status ==="
status() { printBackendStatus; }
make_install
rm -rf -- "${STORE:?}"/*
store_release old
store_release new
links new old
pin_to new
echo inactive >"${S}/active-state"
STATE_BEFORE="$(lifecycle_state) $(stat -c '%i %a' "${STORE}" "${STORE}/current" "${STORE}/previous" | tr '\n' ' ')"
run status
assert_rc 0 "${RC}" "status of an upgraded store"
assert_contains $'installed_release='"${STORE_ID_[new]}"$'\npinned_release='"${STORE_ID_[new]}" "${OUT}" "  installed and pinned"
assert_contains $'previous_release='"${STORE_ID_[old]}"$'\nrollback_available=yes\nupgrade_available=no\ndaemon_release=none\nunmanaged_releases=0' "${OUT}" \
	"  previous, rollback available, no upgrade, no daemon, nothing unmanaged"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state) $(stat -c '%i %a' "${STORE}" "${STORE}/current" "${STORE}/previous" | tr '\n' ' ')" "  read only: links, inodes and modes unchanged"
assert_eq "0" "$(restarts)" "  no restart"
assert_true "  no download" test ! -s "${S}/curl-log"
rm -f "${STORE}/previous"
mkdir "${STORE}/previous"
run status
assert_rc 1 "${RC}" "a damaged previous makes the status fail"
assert_contains $'previous_release=invalid\nrollback_available=no' "${OUT}" "  and is reported as invalid"
assert_true "  and is left as it is" test -d "${STORE}/previous" -a ! -L "${STORE}/previous"
rmdir "${STORE}/previous"
ln -s "${STORE_ID_[new]}" "${STORE}/previous"
run status
assert_contains "previous_release=invalid" "${OUT}" "a previous that names current is invalid"
rm -f "${STORE}/previous"
ln -sfn "boringtun-cli-0.0.1-g000000000000-linux-x86_64-musl" "${STORE}/current"
run status
assert_rc 1 "${RC}" "a damaged current makes the status fail"
assert_contains $'installed_release=invalid' "${OUT}" "  reported as invalid"
assert_contains "upgrade_available=no" "${OUT}" "  with no upgrade offered from it"
# The release a running daemon executes, from its executable path: a fixture
# release whose binary is a copy of sleep, so that /proc/<pid>/exe is in the
# store.
make_install
rm -rf -- "${STORE:?}"/*
store_release old
store_release new
SLEEP_DIR="${STORE}/${STORE_ID_[old]}"
cp "$(command -v sleep)" "${SLEEP_DIR}/boringtun-cli"
chmod 0755 "${SLEEP_DIR}/boringtun-cli"
sed -i "s/^binary_sha256=.*/binary_sha256=$(sha256sum "${SLEEP_DIR}/boringtun-cli" | cut -d' ' -f1)/" "${SLEEP_DIR}/MANIFEST"
"${SLEEP_DIR}/boringtun-cli" 60 &
BACKGROUND+=("$!")
echo "$!" >"${S}/main-pid"
echo 1 >"${S}/served-rc"
links new old
run status
assert_contains $'installed_release='"${STORE_ID_[new]}" "${OUT}" "after an interrupted switch, current names the new release"
assert_contains "daemon_state=unverified" "${OUT}" "  the daemon is not the verified current one"
assert_contains "daemon_release=${STORE_ID_[old]}" "${OUT}" "  and is shown to run the old release"

echo "=== Nothing else switches the binary ==="
for FUNCTION_NAME in _awgBtEnsureReady ensureAwgBackendReady awgBackendCtlMain awgBoringtunLaunchMain nonInteractiveAddClient \
	nonInteractiveRemoveClient setAwgProtocolMode applyAwgProtocolTransaction setBoringtunImitation manageMenu manageBoringtunMenu \
	printBackendStatus uninstallAmneziaWG; do
	BODY="$(declare -f "${FUNCTION_NAME}")"
	assert_true "${FUNCTION_NAME} never upgrades, rolls back or relinks the store" \
		bash -c '[[ "$1" != *boringtunBinaryLifecycle* && "$1" != *_awgBtEnsurePinnedRelease* && "$1" != *_awgBtSetStoreLink* && "$1" != *_awgBtSwitchCurrent* && "$1" != *installBoringtunRelease* ]]' _ "${BODY}"
done
# The top-level function around every call that fetches the pinned release,
# writes a lifecycle link or runs the transaction ("main" is the command line).
CALLERS="$(awk '
	/^function [A-Za-z_]+/ { NAME = $2; sub(/\(.*/, "", NAME) }
	/^[})]$/ { NAME = "main" }
	/^[[:space:]]*#/ { next }
	/_awgBtEnsurePinnedRelease "|_awgBtSetStoreLink (current|previous)|boringtunBinaryLifecycle (upgrade|rollback)/ { print (NAME == "" ? "main" : NAME) }
' "${INSTALLER}" | LC_ALL=C sort -u | tr '\n' ' ')"
assert_eq "_awgBtSwitchCurrent boringtunBinaryLifecycle installBoringtunRelease main " "${CALLERS}" \
	"the pinned release is fetched and the links written only by the fresh install, the lifecycle transaction and its command line"
assert_eq "$(grep -c 'boringtunBinaryLifecycle upgrade' "${INSTALLER}") $(grep -c 'boringtunBinaryLifecycle rollback' "${INSTALLER}")" "1 1" \
	"the transaction runs only from --upgrade-boringtun and --rollback-boringtun"

echo "=== Scratch instances of a candidate ==="
scratch_argv() {
	_awgBtDaemonArgv() {
		echo "argv $*" >>"${S}/log"
		return 1
	}
	_AWG_BT_CANDIDATE_RELEASE="${STORE_ID_[old]}"
	_awgBtScratchCreate awgs0
}
make_install
rm -rf -- "${STORE:?}"/*
store_release old
store_release new
links new old
run scratch_argv
assert_contains "argv $(readlink -f "${STORE}/${STORE_ID_[old]}/boringtun-cli") awgs0 none" "$(cat "${S}/log")" \
	"a scratch instance of a candidate runs the candidate's verified binary, not current's"
run env _AWG_BT_CANDIDATE_RELEASE=evil bash -c 'source "$1" >/dev/null 2>&1; printf "[%s]" "${_AWG_BT_CANDIDATE_RELEASE}"' _ "${INSTALLER}"
assert_eq "[]" "${OUT}" "the environment never selects a candidate"

echo "=== Helpers of the previous installer version ==="
# The helpers an installation of the PR 6 base (78b780b) left installed,
# rendered by that installer's own _awgBtRenderHelper with this suite's
# settings: CI passes the base installer in AWG_TEST_BASE_INSTALLER, and a
# checkout with history provides it with git.
BASE_COMMIT=78b780bc8df73b86fa1c2722e7af2bd4e11e2a6a
BASE_INSTALLER="${T}/base-installer.sh"
if [[ -n "${AWG_TEST_BASE_INSTALLER:-}" ]]; then
	cp -- "${AWG_TEST_BASE_INSTALLER}" "${BASE_INSTALLER}"
else
	git -C "${PROJECT_ROOT}" show "${BASE_COMMIT}:amneziawg-install.sh" >"${BASE_INSTALLER}" 2>/dev/null || rm -f "${BASE_INSTALLER}"
fi
assert_true "the installer of the PR 6 base is available for the legacy-helper tests" test -s "${BASE_INSTALLER}"
HELPER_SETTINGS="$(for V in ${_AWG_BT_HELPER_VARIABLES}; do printf '%s=%q\n' "${V}" "${!V}"; done)"
install_base_helpers() {
	local KIND NAME
	mkdir -p "${AWG_BT_LIBEXEC_DIR}"
	chmod 0755 "${AWG_BT_LIBEXEC_DIR}"
	for KIND in launch ctl; do
		NAME=awg-boringtun-launch
		[[ "${KIND}" == launch ]] || NAME=awg-backend-ctl
		env -i PATH="${PATH}" bash -c 'source "$1" >/dev/null 2>&1; eval "$2"; _awgBtRenderHelper "$3"' _ "${BASE_INSTALLER}" "${HELPER_SETTINGS}" "${KIND}" \
			>"${AWG_BT_LIBEXEC_DIR}/${NAME}"
		chmod 0755 "${AWG_BT_LIBEXEC_DIR}/${NAME}"
	done
}
# helper_verifies <helper>: the installed helper's own check of the release
# current selects; prints the release it verified.
helper_verifies() {
	local VERIFIED
	VERIFIED="$(bash -c 'source <(head -n -2 "$1") >/dev/null 2>&1 || exit 2; _awgBtVerifyStore 2>/dev/null && printf "%s" "${_AWG_BT_VERIFIED_BIN}"' _ "$1")" || return 1
	basename "$(dirname "${VERIFIED}")"
}
helpers_are_this_installers() {
	cmp -s "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" <(_awgBtRenderHelper launch) &&
		cmp -s "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl" <(_awgBtRenderHelper ctl)
}
legacy_helper_host() { # <unit state>
	make_install dns example.com 3
	rm -rf -- "${STORE:?}"/*
	store_release b1
	links b1
	pin_to b2
	install_base_helpers
	echo "$1" >"${S}/active-state"
	touch "${S}/restart-uses-helper"
}
legacy_helper_host inactive
assert_eq "${STORE_ID_[b1]}" "$(helper_verifies "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch")" "the base's launcher accepts the legacy build 1"
links b2
run helper_verifies "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch"
assert_rc 1 "${RC}" "but refuses a -b2 release as current: the hazard an unreconciled switch would leave"
links b1
BEFORE_HASHES="$(config_hashes)"
run upgrade
assert_rc 0 "${RC}" "stopped host with the base's helpers: b1 -> b2 succeeds"
assert_true "  the helpers are now this installer's" helpers_are_this_installers
assert_eq "${STORE_ID_[b2]} ${STORE_ID_[b1]}" "$(link_of current) $(link_of previous)" "  current is b2 and previous b1"
assert_eq "0" "$(restarts)" "  the service stays stopped"
assert_eq "${STORE_ID_[b2]}" "$(helper_verifies "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch")" "  the installed launcher accepts the new current, so the next start can run b2"
assert_eq "${STORE_ID_[b2]}" "$(helper_verifies "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl")" "  and so does the installed awg-backend-ctl"
assert_eq "${BEFORE_HASHES}" "$(config_hashes)" "  params, configs and the runtime file are unchanged"
legacy_helper_host active
BEFORE_HASHES="$(config_hashes)"
run upgrade
assert_rc 0 "${RC}" "active host with the base's helpers: b1 -> b2 succeeds"
assert_eq "restart current=${STORE_ID_[b2]}
helper awg-backend-ctl verified ${STORE_ID_[b2]}
helper awg-boringtun-launch verified ${STORE_ID_[b2]}" "$(grep -E '^(restart|helper) ' "${S}/log")" \
	"  the restart ran the reconciled installed helpers, which accept b2"
assert_contains "verify current=${STORE_ID_[b2]} imitation=dns|example.com" "$(cat "${S}/log")" "  and the activation was verified"
assert_eq "${BEFORE_HASHES}" "$(config_hashes)" "  configs unchanged"
: >"${S}/log"
run rollback
assert_rc 0 "${RC}" "  a rollback to b1 runs through the same helpers"
assert_contains "helper awg-boringtun-launch verified ${STORE_ID_[b1]}" "$(cat "${S}/log")" "  which accept the legacy b1 again"
legacy_helper_host active
chmod 0777 "${AWG_BT_LIBEXEC_DIR}"
STATE_BEFORE="$(lifecycle_state)"
run upgrade
chmod 0755 "${AWG_BT_LIBEXEC_DIR}"
assert_rc 1 "${RC}" "a helper that cannot be updated stops the change before anything changes"
assert_contains "could not update the BoringTun helpers" "${ERR}" "helper update fails: it says so"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "helper update fails: current and previous are unchanged"
assert_eq "0" "$(restarts)" "helper update fails: no restart"
assert_true "helper update fails: no download" test ! -s "${S}/curl-log"
legacy_helper_host active
printf '1\n0\n' >"${S}/restart-rc"
run upgrade
assert_rc 1 "${RC}" "a failed activation after the helpers were updated"
assert_eq "${STORE_ID_[b1]} none" "$(link_of current) $(link_of previous)" "  restores current b1 and the absent previous"
assert_contains "helper awg-boringtun-launch verified ${STORE_ID_[b1]}" "$(cat "${S}/log")" "  the recovery restart ran through the updated helpers, which accept b1"
assert_contains "runs ${STORE_ID_[b1]} again" "${ERR}" "  and the original release runs again"
assert_true "  the updated helpers stay: nothing depends on the old ones" helpers_are_this_installers

echo "=== Previous naming current after an interrupted switch ==="
# A rollback killed between its two link renames, for real.
interrupted_rollback() {
	eval "$(declare -f _awgBtSetStoreLink | sed '1s/_awgBtSetStoreLink/realSetStoreLink/')"
	_awgBtSetStoreLink() {
		[[ "$1" == current ]] && kill -KILL "${BASHPID}"
		realSetStoreLink "$@"
	}
	rollback
}
duplicate_host() { # <unit state> [served rc]
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old
	store_release new
	links new old
	pin_to new
	echo "$1" >"${S}/active-state"
	echo "${2:-0}" >"${S}/served-rc"
	run interrupted_rollback
	: >"${S}/log"
	: >"${S}/curl-log"
}
duplicate_host active
assert_eq "137" "${RC}" "(the rollback was killed between previous and current)"
assert_eq "current=${STORE_ID_[new]} previous=${STORE_ID_[new]} store=[$(sorted "${STORE_ID_[new]}" "${STORE_ID_[old]}" current previous)]" \
	"$(lifecycle_state)" "(that leaves previous naming current, and the old release unreferenced)"
run printBackendStatus
assert_rc 1 "${RC}" "(the status reports that state as invalid)"
run upgrade
assert_rc 0 "${RC}" "pinned current, previous naming it, healthy daemon: the upgrade repairs and succeeds"
assert_contains "previous named current" "${OUT}" "  it says what it repaired"
assert_eq "current=${STORE_ID_[new]} previous=none store=[$(sorted "${STORE_ID_[new]}" "${STORE_ID_[old]}" current)]" \
	"$(lifecycle_state)" "  the duplicate previous link is removed, current is unchanged and the old release is kept"
assert_contains "left alone: ${STORE_ID_[old]}" "${OUT}" "  the old release is reported as unmanaged, not adopted"
assert_eq "0" "$(restarts)" "  no restart"
assert_true "  no download" test ! -s "${S}/curl-log"
run printBackendStatus
assert_rc 0 "${RC}" "  the status is valid again"
assert_contains $'previous_release=none\nrollback_available=no' "${OUT}" "  with no rollback target"
assert_contains "unmanaged_releases=1" "${OUT}" "  and one unmanaged release"
duplicate_host active 1
run upgrade
assert_rc 0 "${RC}" "with the daemon still on the old release: the upgrade repairs and restarts onto current"
assert_eq "1" "$(restarts)" "  one restart"
assert_contains "verify current=${STORE_ID_[new]}" "$(cat "${S}/log")" "  that is verified"
assert_eq "current=${STORE_ID_[new]} previous=none store=[$(sorted "${STORE_ID_[new]}" "${STORE_ID_[old]}" current)]" \
	"$(lifecycle_state)" "  current unchanged, previous removed, the old release kept"
duplicate_host inactive
run upgrade
assert_rc 0 "${RC}" "with the service stopped: the upgrade repairs"
assert_eq "0" "$(restarts)" "  and does not start it"
assert_eq "none" "$(link_of previous)" "  the duplicate previous link is removed"
duplicate_host active
chmod 0555 "${STORE}"
run upgrade
chmod 0755 "${STORE}"
assert_rc 1 "${RC}" "a duplicate previous that cannot be removed fails the upgrade"
assert_not_contains "already current" "${OUT}" "  without reporting a healthy no-op"
assert_eq "${STORE_ID_[new]}" "$(link_of previous)" "  the link is still there"
make_install
rm -rf -- "${STORE:?}"/*
store_release old
links old old
pin_to new
run upgrade
assert_rc 0 "${RC}" "previous naming an older current: the upgrade still proceeds"
assert_eq "${STORE_ID_[new]} ${STORE_ID_[old]}" "$(link_of current) $(link_of previous)" "  to current new and previous old"

echo "=== The pin already current, with the previous installer version's helpers ==="
# A host whose current already is the pinned -b2 release while the helpers
# the PR 6 base rendered are still installed: those refuse current, so the
# next start would fail. The explicit upgrade, which changes no release here,
# must still leave helpers that accept what current selects, and must not
# start a stopped service to do so.
pinned_legacy_host() { # <unit state> <previous fixture|none> [served rc]
	make_install dns example.com 3
	rm -rf -- "${STORE:?}"/*
	store_release b2
	[[ "$2" == none ]] || store_release "$2"
	links b2 "$2"
	pin_to b2
	install_base_helpers
	echo "$1" >"${S}/active-state"
	echo "${3:-0}" >"${S}/served-rc"
	touch "${S}/restart-uses-helper"
	: >"${S}/log"
	: >"${S}/curl-log"
}
# The upgrade, logging each regeneration of the helpers.
counted_upgrade() {
	eval "$(declare -f _awgBtInstallHelpers | sed '1s/_awgBtInstallHelpers/realInstallHelpers/')"
	_awgBtInstallHelpers() {
		echo "install-helpers" >>"${S}/log"
		realInstallHelpers
	}
	upgrade
}
# Every systemctl call that would start, stop or restart the unit.
service_changes() { grep -cE '^systemctl (start|restart|stop|reload|reload-or-restart|try-restart|kill)( |$)' "${S}/log"; }
pinned_stopped_case() { # <inactive|failed> <previous fixture|none>
	local LABEL="pinned b2 + $1 + legacy helpers" STATE_BEFORE HASHES_BEFORE
	pinned_legacy_host "$1" "$2"
	assert_eq "" "$(helper_verifies "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch")" "${LABEL}: (the base's launcher refuses current b2 before)"
	STATE_BEFORE="$(lifecycle_state)"
	HASHES_BEFORE="$(config_hashes)"
	run counted_upgrade
	assert_rc 0 "${RC}" "${LABEL}: the upgrade succeeds"
	assert_true "${LABEL}: the helpers are reconciled" helpers_are_this_installers
	assert_eq "1" "$(grep -c '^install-helpers$' "${S}/log")" "${LABEL}:   once"
	assert_eq "${STORE_ID_[b2]}" "$(helper_verifies "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch")" "${LABEL}: the installed launcher accepts current b2"
	assert_eq "${STORE_ID_[b2]}" "$(helper_verifies "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl")" "${LABEL}: the installed awg-backend-ctl, whose precheck runs that check, accepts it"
	assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "${LABEL}: current, previous and the store are unchanged"
	assert_true "${LABEL}: no download" test ! -s "${S}/curl-log"
	assert_eq "0" "$(service_changes)" "${LABEL}: the service is neither started nor restarted"
	assert_eq "${HASHES_BEFORE}" "$(config_hashes)" "${LABEL}: params, configs and the runtime file are unchanged"
	assert_contains "helpers in ${AWG_BT_LIBEXEC_DIR} were updated" "${OUT}" "${LABEL}: it says the helpers were updated"
	assert_contains "was left $1; its next start uses the updated helpers" "${OUT}" "${LABEL}:   and that the service was left $1"
	assert_not_contains "nothing was changed" "${OUT}" "${LABEL}: it does not claim that nothing changed"
	: >"${S}/log"
	systemctl restart awg-quick@awg0.service
	assert_eq "restart current=${STORE_ID_[b2]}
helper awg-backend-ctl verified ${STORE_ID_[b2]}
helper awg-boringtun-launch verified ${STORE_ID_[b2]}" "$(grep -E '^(restart|helper) ' "${S}/log")" \
		"${LABEL}: the next start runs through the installed helpers, which accept b2"
}
pinned_stopped_case inactive b1
pinned_stopped_case failed none

LABEL="pinned b2 + active healthy daemon + legacy helpers"
pinned_legacy_host active b1 0
STATE_BEFORE="$(lifecycle_state)"
run counted_upgrade
assert_rc 0 "${RC}" "${LABEL}: the upgrade succeeds"
assert_true "${LABEL}: the helpers are reconciled" helpers_are_this_installers
assert_contains "served current=${STORE_ID_[b2]}" "$(cat "${S}/log")" "${LABEL}: the daemon is checked"
assert_eq "0" "$(service_changes)" "${LABEL}: no restart merely for the helper update"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "${LABEL}: current and previous are unchanged"
assert_true "${LABEL}: no download" test ! -s "${S}/curl-log"
assert_not_contains "nothing was changed" "${OUT}" "${LABEL}: it does not claim that nothing changed"

LABEL="pinned b2 + active daemon on another binary + legacy helpers"
pinned_legacy_host active b1 1
STATE_BEFORE="$(lifecycle_state)"
run counted_upgrade
assert_rc 0 "${RC}" "${LABEL}: the upgrade restarts onto current"
assert_eq "install-helpers
restart current=${STORE_ID_[b2]}
helper awg-backend-ctl verified ${STORE_ID_[b2]}
helper awg-boringtun-launch verified ${STORE_ID_[b2]}" "$(grep -E '^(install-helpers$|restart |helper )' "${S}/log")" \
	"${LABEL}: the helpers are reconciled once, then one restart runs through them onto b2"
assert_contains "verify current=${STORE_ID_[b2]} imitation=dns|example.com" "$(cat "${S}/log")" "${LABEL}: the activation is verified"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "${LABEL}: no link is rewritten"
assert_true "${LABEL}: no download" test ! -s "${S}/curl-log"

pinned_failure_case() { # <inactive|failed>
	local LABEL="pinned b2 + $1 + helpers that cannot be updated" STATE_BEFORE
	pinned_legacy_host "$1" b1
	chmod 0777 "${AWG_BT_LIBEXEC_DIR}"
	STATE_BEFORE="$(lifecycle_state)"
	run upgrade
	chmod 0755 "${AWG_BT_LIBEXEC_DIR}"
	assert_rc 1 "${RC}" "${LABEL}: the upgrade fails"
	assert_contains "could not update the BoringTun helpers" "${ERR}" "${LABEL}: it says so"
	assert_not_contains "already current" "${OUT}" "${LABEL}: without reporting the pin as current"
	assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "${LABEL}: current and previous are unchanged"
	assert_eq "0" "$(service_changes)" "${LABEL}: the service is neither started nor restarted"
	assert_true "${LABEL}: no download" test ! -s "${S}/curl-log"
}
pinned_failure_case inactive
pinned_failure_case failed

# Helpers that already are this installer's: a true no-op, which rewrites
# nothing.
LABEL="pinned b2 + current helpers"
pinned_legacy_host active b1 0
_awgBtInstallHelpers
HELPER_NODES="$(stat -c '%i %Y' "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl")"
STATE_BEFORE="$(lifecycle_state)"
run upgrade
assert_rc 0 "${RC}" "${LABEL}: the upgrade succeeds"
assert_contains "is already current; nothing was changed." "${OUT}" "${LABEL}: and reports a true no-op"
assert_not_contains "helpers in" "${OUT}" "${LABEL}:   without mentioning the helpers"
assert_eq "${HELPER_NODES}" "$(stat -c '%i %Y' "${AWG_BT_LIBEXEC_DIR}/awg-boringtun-launch" "${AWG_BT_LIBEXEC_DIR}/awg-backend-ctl")" "${LABEL}: the helpers are not rewritten"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "${LABEL}: no link is rewritten"
assert_eq "0" "$(service_changes)" "${LABEL}: no restart"
assert_true "${LABEL}: no download" test ! -s "${S}/curl-log"

# Both at once: a rollback killed between its renames left previous naming
# the pinned b2, the old release unreferenced, and the base's helpers are
# installed; the service is stopped.
duplicate_legacy_host() {
	make_install dns example.com 3
	rm -rf -- "${STORE:?}"/*
	store_release old
	store_release b2
	links b2 old
	pin_to b2
	echo inactive >"${S}/active-state"
	run interrupted_rollback
	install_base_helpers
	touch "${S}/restart-uses-helper"
	: >"${S}/log"
	: >"${S}/curl-log"
}
LABEL="previous naming the pinned b2 + legacy helpers + inactive"
duplicate_legacy_host
assert_eq "current=${STORE_ID_[b2]} previous=${STORE_ID_[b2]} store=[$(sorted "${STORE_ID_[b2]}" "${STORE_ID_[old]}" current previous)]" \
	"$(lifecycle_state)" "${LABEL}: (the interrupted rollback left that state)"
run upgrade
assert_rc 0 "${RC}" "${LABEL}: the upgrade succeeds"
assert_eq "current=${STORE_ID_[b2]} previous=none store=[$(sorted "${STORE_ID_[b2]}" "${STORE_ID_[old]}" current)]" \
	"$(lifecycle_state)" "${LABEL}: current stays b2, previous is removed and the old release is kept"
assert_contains "left alone: ${STORE_ID_[old]}" "${OUT}" "${LABEL}: the old release stays unmanaged, not adopted"
assert_true "${LABEL}: the helpers are reconciled" helpers_are_this_installers
assert_eq "0" "$(service_changes)" "${LABEL}: the service stays inactive"
run printBackendStatus
assert_rc 0 "${RC}" "${LABEL}: the status is valid"
assert_contains $'previous_release=none\nrollback_available=no' "${OUT}" "${LABEL}:   with no rollback target"
duplicate_legacy_host
chmod 0777 "${AWG_BT_LIBEXEC_DIR}"
STATE_BEFORE="$(lifecycle_state)"
run upgrade
chmod 0755 "${AWG_BT_LIBEXEC_DIR}"
assert_rc 1 "${RC}" "${LABEL}, helpers that cannot be updated: the upgrade fails"
assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "${LABEL}, helpers that cannot be updated: the store is left as it was, previous included"
assert_eq "0" "$(service_changes)" "${LABEL}, helpers that cannot be updated: no restart"

echo "=== Incomplete configuration snapshots ==="
snapshot_case() { # <label> <command breaking the snapshot...>
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old5
	store_release old
	links old old5
	pin_to new
	"${@:2}"
	STATE_BEFORE="$(lifecycle_state)"
	run upgrade
	assert_rc 1 "${RC}" "$1: the upgrade fails before anything changes"
	assert_contains "cannot read the configuration of this installation; nothing was changed" "${ERR}" "$1:   because the snapshot is incomplete"
	assert_eq "${STATE_BEFORE}" "$(lifecycle_state)" "$1:   current, previous and the store are unchanged"
	assert_eq "0" "$(restarts)" "$1:   no restart"
	assert_not_contains "validate candidate" "$(cat "${S}/log")" "$1:   and the target was never validated"
	chmod -R u+rw "${AMNEZIAWG_DIR}"
}
snapshot_case "params fail to hash" eval 'echo "${AMNEZIAWG_DIR}/params 1 missing" >"${S}/hash-fail"'
snapshot_case "the server config fails to hash" eval 'echo "${SERVER_AWG_CONF} 1 missing" >"${S}/hash-fail"'
snapshot_case "the runtime file is missing" rm -f "${RUNTIME_FILE}"
snapshot_case "the runtime file is unreadable" chmod 000 "${RUNTIME_FILE}"
snapshot_case "a client config is missing" rm -f "${AMNEZIAWG_DIR}/clients/awg0-client-alice.conf"
snapshot_case "a client config is unreadable" chmod 000 "${AMNEZIAWG_DIR}/clients/awg0-client-bob.conf"
snapshot_case "the client set cannot be read" touch "${S}/collect-fails"
snapshot_case "sha256sum fails after hashing everything" eval 'echo "${AMNEZIAWG_DIR}/params 1 status" >"${S}/hash-fail"'
after_case() { # <label> <expected error> <expected rc> <hash-fail line> [validate-touch|verify-touch]
	make_install
	rm -rf -- "${STORE:?}"/*
	store_release old5
	store_release old
	links old old5
	pin_to new
	[[ -z "$4" ]] || echo "$4" >"${S}/hash-fail"
	[[ -z "${5:-}" ]] || touch "${S}/$5"
	run upgrade
	assert_rc "$3" "${RC}" "$1: the change fails"
	assert_contains "$2" "${ERR}" "$1:   as it should"
	assert_eq "${STORE_ID_[old]} ${STORE_ID_[old5]}" "$(link_of current) $(link_of previous)" "$1:   current and previous are as before"
}
after_case "a hash failure after the validation" "after the validation; nothing was changed" 1 "${AMNEZIAWG_DIR}/params 2 missing"
assert_eq "0" "$(restarts)" "  no restart"
after_case "a hash failure status after the validation" "after the validation; nothing was changed" 1 "${AMNEZIAWG_DIR}/params 2 status"
after_case "a configuration that changes during the validation" "changed during the validation" 1 "" validate-touch
after_case "a hash failure after the switch" "after the switch; restoring" 1 "${AMNEZIAWG_DIR}/params 3 missing"
assert_eq "2" "$(restarts)" "  the original release is restarted"
after_case "a hash failure status after the switch" "after the switch; restoring" 1 "${AMNEZIAWG_DIR}/params 3 status"
after_case "a configuration that changes during the switch" "changed during the switch" 1 "" verify-touch

echo "=== Command line ==="
run bash "${INSTALLER}" --upgrade-boringtun "${STORE_ID_[old]}"
assert_rc 1 "${RC}" "--upgrade-boringtun takes no release argument"
assert_contains "Usage: amneziawg-install.sh --upgrade-boringtun" "${ERR}" "  and prints its usage"
run bash "${INSTALLER}" --rollback-boringtun "${STORE_ID_[old]}"
assert_rc 1 "${RC}" "--rollback-boringtun takes no release argument either"

echo
echo "BoringTun lifecycle tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
