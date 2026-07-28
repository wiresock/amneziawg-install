#!/bin/bash

# AmneziaWG server installer
# https://github.com/wiresock/amneziawg-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"
WEB_PANEL_CONFIG_DIR="${AMNEZIAWG_DIR}/clients"

# Ensure sbin directories are in PATH for depmod, modprobe, sysctl, etc.
# Some minimal or non-login root shells may not include these by default.
# Only adjust PATH when the script is executed directly, not when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	if [ -n "${PATH:-}" ]; then
		export PATH="/sbin:/usr/sbin:${PATH:-}"
	else
		export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	fi
fi

# Work around broken IPv6 on cloud VPS providers.  Some providers resolve
# Launchpad / Ubuntu keyserver / COPR hostnames to both A and AAAA records,
# but outbound IPv6 connectivity is broken, causing apt, dnf,
# add-apt-repository, and COPR API calls to hang.
#
# Two complementary mitigations are applied:
#
#  1. APT ForceIPv4 (Debian/Ubuntu only) — a config file in apt.conf.d/
#     forces all apt-based tools (including add-apt-repository, which uses
#     python-apt internally) to use IPv4.  This file is only written when
#     apt-get or apt is present to avoid creating /etc/apt on RPM distros.
#
#  2. gai.conf IPv4-preference rule (all distros) — an IPv4-preference rule
#     is injected into /etc/gai.conf so that glibc's getaddrinfo (and thus
#     Python's socket.getaddrinfo and libcurl used by dnf) *prefers* IPv4.
#     On Ubuntu 24.04 this also fixes a Python traceback from httplib2
#     used by add-apt-repository, which does NOT honour Acquire::ForceIPv4.
APT_FORCE_IPV4_CONF="/etc/apt/apt.conf.d/99amneziawg-force-ipv4"
APT_FORCE_IPV4_SENTINEL="# Managed by amneziawg-install - safe to remove"
GAI_CONF="/etc/gai.conf"
GAI_CONF_SENTINEL="# Added by amneziawg-install - safe to remove"
GAI_CONF_IPV4_RULE="precedence ::ffff:0:0/96 100"
GAI_CONF_IPV4_RULE_REGEX='^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96[[:space:]]+100([[:space:]]*(#.*)?)?$'
AMNEZIA_PPA_URI="https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu"
AMNEZIA_PPA_SOURCES_DIR="/etc/apt/sources.list.d"
AMNEZIA_PPA_SOURCE_CREATED=0
_APT_IPV4_PREV_TRAP_EXIT=""
_APT_IPV4_PREV_TRAP_INT=""
_APT_IPV4_PREV_TRAP_TERM=""
# Return success when gai.conf has an active (uncommented) IPv4 precedence
# rule for ::ffff:0:0/96 with value 100; commented defaults must not match.
gai_conf_has_active_ipv4_rule() {
	grep -Eq "${GAI_CONF_IPV4_RULE_REGEX}" "${GAI_CONF}" 2>/dev/null
}
enable_apt_ipv4() {
	# Only write the APT ForceIPv4 config on distros that actually use APT,
	# to avoid creating /etc/apt on RPM-based systems.
	if command -v apt-get >/dev/null 2>&1 || command -v apt >/dev/null 2>&1 || [[ -d /etc/apt ]]; then
		mkdir -p /etc/apt/apt.conf.d
		printf '%s\n%s\n' "${APT_FORCE_IPV4_SENTINEL}" 'Acquire::ForceIPv4 "true";' \
			> "${APT_FORCE_IPV4_CONF}"
	fi

	# Prefer IPv4 in the system resolver so all glibc consumers (Python,
	# libcurl/dnf, etc.) connect over IPv4.
	if ! gai_conf_has_active_ipv4_rule; then
		local _gai_existed=0
		[[ -f "${GAI_CONF}" ]] && _gai_existed=1
		printf '\n%s\n%s\n' "${GAI_CONF_SENTINEL}" "${GAI_CONF_IPV4_RULE}" \
			>> "${GAI_CONF}"
		# Only set permissions when we created the file; leave existing
		# ownership/mode untouched so the cleanup path can preserve them.
		if [[ "${_gai_existed}" -eq 0 ]]; then
			chmod 0644 "${GAI_CONF}"
		fi
	fi

	# Save existing trap commands so we can chain them (not just restore).
	# trap -p output is eval-safe by design (bash always emits: trap -- 'body' SIG).
	_APT_IPV4_PREV_TRAP_EXIT="$(trap -p EXIT || true)"
	_APT_IPV4_PREV_TRAP_INT="$(trap -p INT || true)"
	_APT_IPV4_PREV_TRAP_TERM="$(trap -p TERM || true)"
	# Install traps that clean up *and* invoke any prior handler, so
	# pre-existing cleanup logic still runs even if the script exits
	# while IPv4 forcing is active.
	trap '_cleanup_apt_ipv4_and_chain EXIT' EXIT
	trap '_cleanup_apt_ipv4_and_chain INT'  INT
	trap '_cleanup_apt_ipv4_and_chain TERM' TERM
}
# Internal: remove the APT ForceIPv4 config and revert gai.conf changes.
_remove_ipv4_overrides() {
	# Only remove the file if it carries our sentinel.
	if [[ -f "${APT_FORCE_IPV4_CONF}" ]] && grep -qFm1 "${APT_FORCE_IPV4_SENTINEL}" "${APT_FORCE_IPV4_CONF}"; then
		rm -f "${APT_FORCE_IPV4_CONF}"
	fi
	# Remove gai.conf lines we added (if any).  Only act when our sentinel
	# is present so pre-existing admin rules are never touched.  This must
	# be idempotent so interrupted previous runs are also cleaned up.
	if [[ -f "${GAI_CONF}" ]] && grep -qF "${GAI_CONF_SENTINEL}" "${GAI_CONF}"; then
		awk -v sent="${GAI_CONF_SENTINEL}" -v regex="${GAI_CONF_IPV4_RULE_REGEX}" '
			# State machine:
			# 1) skip our sentinel line
			# 2) skip the immediately following active IPv4 rule if present
			# 3) print all other lines unchanged
			$0 == sent { prev_sent=1; next }
			prev_sent == 1 && $0 ~ regex { prev_sent=0; next }
			{ prev_sent=0; print }
		' "${GAI_CONF}" > "${GAI_CONF}.tmp"
		if ! chmod --reference="${GAI_CONF}" "${GAI_CONF}.tmp" || ! chown --reference="${GAI_CONF}" "${GAI_CONF}.tmp"; then
			rm -f "${GAI_CONF}.tmp"
			return 1
		fi
		mv "${GAI_CONF}.tmp" "${GAI_CONF}"
	fi
}
# Internal: remove the config file, restore the previous trap for the
# given signal, then immediately invoke the restored handler so it runs
# during the same exit / signal delivery.
_cleanup_apt_ipv4_and_chain() {
	# Preserve the original exit status so chained handlers see the real value.
	local _saved_status=$?
	local sig="$1"
	_remove_ipv4_overrides
	# Restore + chain: re-install the previous trap (if any), then
	# re-deliver the signal / exit so bash invokes the restored handler.
	# This avoids parsing trap -p output entirely (no sed/eval of bodies).
	local prev_var="_APT_IPV4_PREV_TRAP_${sig}"
	local prev_trap="${!prev_var}"
	if [[ -n "${prev_trap}" ]]; then
		# Re-install the previous trap (e.g. trap -- 'handler' EXIT).
		eval "${prev_trap}"
		# Re-deliver the signal so bash invokes the just-restored handler.
		if [[ "${sig}" == "EXIT" ]]; then
			# For EXIT: exiting re-fires the EXIT trap with the original status.
			exit "${_saved_status}"
		else
			# For INT/TERM: re-raise the signal to invoke the restored handler.
			kill -s "${sig}" "$$" 2>/dev/null || {
				case "${sig}" in
					INT)  exit 130 ;;  # 128 + SIGINT(2)
					TERM) exit 143 ;;  # 128 + SIGTERM(15)
				esac
			}
		fi
	else
		trap - "${sig}"
		if [[ "${sig}" == "EXIT" ]]; then
			# Preserve the original exit status when no prior handler exists.
			exit "${_saved_status}"
		elif [[ "${sig}" == INT || "${sig}" == TERM ]]; then
			# Re-raise the signal so default termination semantics are preserved.
			kill -s "${sig}" "$$" 2>/dev/null || {
				case "${sig}" in
					INT)  exit 130 ;;  # 128 + SIGINT(2)
					TERM) exit 143 ;;  # 128 + SIGTERM(15)
				esac
			}
		fi
	fi
}
disable_apt_ipv4() {
	_remove_ipv4_overrides
	# Restore any previously installed traps.
	if [[ -n "${_APT_IPV4_PREV_TRAP_EXIT}" ]]; then
		eval "${_APT_IPV4_PREV_TRAP_EXIT}"
	else
		trap - EXIT
	fi
	if [[ -n "${_APT_IPV4_PREV_TRAP_INT}" ]]; then
		eval "${_APT_IPV4_PREV_TRAP_INT}"
	else
		trap - INT
	fi
	if [[ -n "${_APT_IPV4_PREV_TRAP_TERM}" ]]; then
		eval "${_APT_IPV4_PREV_TRAP_TERM}"
	else
		trap - TERM
	fi
}

# Return the Ubuntu archive codename that add-apt-repository should use.
# Linux Mint exposes its Ubuntu base in UBUNTU_CODENAME.
function getUbuntuPpaCodename() {
	local CODENAME
	if [[ "${ID:-}" == "linuxmint" ]]; then
		CODENAME="${UBUNTU_CODENAME:-}"
	else
		CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
	fi

	if [[ -z "${CODENAME}" ]] || ! [[ "${CODENAME}" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
		echo -e "${RED}ERROR: Unable to determine a valid Ubuntu codename for the Amnezia PPA.${NC}" >&2
		return 1
	fi

	printf '%s\n' "${CODENAME}"
}

# Reviewed cross-release mappings. Unknown releases must never be mapped
# automatically; every mapping requires package and DKMS compatibility testing.
function getAmneziaPpaFallbackSuite() {
	case "$1" in
		resolute) printf '%s\n' "noble" ;;
		*) return 1 ;;
	esac
}

# Noble currently publishes amneziawg-tools for these architectures. Although
# the Release file advertises i386, the required tools package is absent there.
function isAmneziaPpaFallbackArchitectureSupported() {
	case "$1" in
		amd64 | arm64 | armhf | ppc64el | riscv64 | s390x) return 0 ;;
		*) return 1 ;;
	esac
}

# Print the direct HTTP status for a PPA metadata URL without following
# redirects. A redirect is ambiguous and must remain a 3xx so the caller fails
# closed. Network, TLS, timeout, and tool failures return 2 without inventing a
# status. curl is installed by the normal Ubuntu flow; wget/python3 allow
# recovery from an older partial install before the first apt-get update.
function getAmneziaPpaHttpStatus() {
	local URL="$1"
	local STATUS=""
	local OUTPUT=""

	if command -v curl &>/dev/null; then
		STATUS=$(curl --disable -4 --silent --show-error \
			--connect-timeout 10 --max-time 30 \
			--output /dev/null --write-out '%{http_code}' "${URL}") || return 2
	elif command -v wget &>/dev/null; then
		OUTPUT=$(wget -4 --server-response --spider --max-redirect=0 \
			--timeout=30 --tries=1 "${URL}" 2>&1) || true
		STATUS=$(printf '%s\n' "${OUTPUT}" | awk '
			/^[[:space:]]*HTTP\/[0-9.]+[[:space:]]+[0-9][0-9][0-9]/ { status=$2 }
			END { print status }
		')
	elif command -v python3 &>/dev/null; then
		STATUS=$(python3 - "${URL}" <<'PY'
import sys
import urllib.error
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None

request = urllib.request.Request(sys.argv[1], method="GET")
opener = urllib.request.build_opener(NoRedirect())
try:
    with opener.open(request, timeout=30) as response:
        print(response.status)
except urllib.error.HTTPError as error:
    print(error.code)
except (OSError, urllib.error.URLError):
    raise SystemExit(2)
PY
		) || return 2
	else
		return 2
	fi

	if ! [[ "${STATUS}" =~ ^[0-9]{3}$ ]]; then
		return 2
	fi
	printf '%s\n' "${STATUS}"
}

# Tri-state PPA metadata probe:
#   0: suite is available (signed metadata resource exists)
#   1: suite is definitely unavailable (both resources are 404/410)
#   2: status is unknown (network/server/auth/other failure)
function probeAmneziaPpaSuite() {
	local SUITE="$1"
	local RESOURCE
	local STATUS

	for RESOURCE in InRelease Release; do
		STATUS=$(getAmneziaPpaHttpStatus \
			"${AMNEZIA_PPA_URI}/dists/${SUITE}/${RESOURCE}") || return 2
		case "${STATUS}" in
			200) return 0 ;;
			404 | 410) ;;
			*) return 2 ;;
		esac
	done

	return 1
}

# Select the native suite whenever it exists. A fallback is considered only
# after definite native absence, never after a transient or ambiguous failure.
function selectAmneziaPpaSuite() {
	local NATIVE_SUITE="$1"
	local ARCHITECTURE="$2"
	local FALLBACK_SUITE
	local PROBE_RC

	if probeAmneziaPpaSuite "${NATIVE_SUITE}"; then
		PROBE_RC=0
	else
		PROBE_RC=$?
	fi
	case "${PROBE_RC}" in
		0)
			printf '%s\n' "${NATIVE_SUITE}"
			return 0
			;;
		2)
			echo -e "${RED}ERROR: Could not determine whether the Amnezia PPA supports Ubuntu '${NATIVE_SUITE}'.${NC}" >&2
			echo -e "${ORANGE}A network, TLS, rate-limit, or server error occurred. No cross-release fallback was applied.${NC}" >&2
			return 1
			;;
	esac

	FALLBACK_SUITE=$(getAmneziaPpaFallbackSuite "${NATIVE_SUITE}") || {
		echo -e "${RED}ERROR: The Amnezia PPA does not publish packages for Ubuntu '${NATIVE_SUITE}', and no verified fallback is configured.${NC}" >&2
		return 1
	}

	if ! isAmneziaPpaFallbackArchitectureSupported "${ARCHITECTURE}"; then
		echo -e "${RED}ERROR: The verified ${NATIVE_SUITE} -> ${FALLBACK_SUITE} Amnezia PPA fallback is not available for architecture '${ARCHITECTURE}'.${NC}" >&2
		return 1
	fi

	if probeAmneziaPpaSuite "${FALLBACK_SUITE}"; then
		PROBE_RC=0
	else
		PROBE_RC=$?
	fi
	case "${PROBE_RC}" in
		0)
			echo -e "${ORANGE}WARNING: The Amnezia PPA has no native '${NATIVE_SUITE}' repository. Using signed '${FALLBACK_SUITE}' PPA packages from Ubuntu 24.04 for this reviewed compatibility fallback.${NC}" >&2
			printf '%s\n' "${FALLBACK_SUITE}"
			return 0
			;;
		1)
			echo -e "${RED}ERROR: Neither the native '${NATIVE_SUITE}' suite nor its reviewed '${FALLBACK_SUITE}' fallback is available in the Amnezia PPA.${NC}" >&2
			;;
		2)
			echo -e "${RED}ERROR: The native '${NATIVE_SUITE}' suite is unavailable, but the '${FALLBACK_SUITE}' fallback could not be verified because of a network or server error.${NC}" >&2
			echo -e "${ORANGE}No cross-release fallback was applied.${NC}" >&2
			;;
	esac
	return 1
}

# Transform one legacy .list file. Only active deb/deb-src lines whose URI
# token is exactly the Amnezia PPA are considered. Exit codes: 0 matched,
# 3 no match, 4 malformed matching entry.
function _transformAmneziaPpaLegacyFile() {
	local FILE="$1"
	local MODE="$2"
	local SUITE="${3:-}"
	local ARCHITECTURE="${4:-}"

	awk -v mode="${MODE}" -v replacement="${SUITE}" \
		-v target="${AMNEZIA_PPA_URI}" -v host_arch="${ARCHITECTURE}" '
	function is_target_uri(uri, normalized, http_target) {
		normalized=uri
		sub(/\/+$/, "", normalized)
		http_target=target
		sub(/^https:/, "http:", http_target)
		return normalized == target || normalized == http_target
	}
	function contains_target_literal(value, http_target) {
		http_target=target
		sub(/^https:/, "http:", http_target)
		return index(value, target) > 0 || index(value, http_target) > 0
	}
	function dequote_token(value, first, last) {
		first=substr(value, 1, 1)
		last=substr(value, length(value), 1)
		if (length(value) >= 2 && first == "\"" && last == "\"") {
			return substr(value, 2, length(value) - 2)
		}
		return value
	}
	function has_unsupported_quote(value, first, last) {
		first=substr(value, 1, 1)
		last=substr(value, length(value), 1)
		return (first == "\"" && last != "\"") ||
			first == "\047" || last == "\047"
	}
	function hex_value(character) {
		return index("0123456789abcdef", tolower(character)) - 1
	}
	function percent_decode(value, result, i, character, high, low) {
		result=""
		for (i=1; i<=length(value); i++) {
			character=substr(value, i, 1)
			if (character == "%" && i + 2 <= length(value)) {
				high=hex_value(substr(value, i + 1, 1))
				low=hex_value(substr(value, i + 2, 1))
				if (high >= 0 && low >= 0) {
					result=result sprintf("%c", high * 16 + low)
					i += 2
					continue
				}
			}
			result=result character
		}
		return result
	}
	function apt_comment_position(value, i, character, in_options) {
		in_options=0
		for (i=1; i<=length(value); i++) {
			character=substr(value, i, 1)
			if (character == "[") {
				in_options=1
			} else if (character == "]") {
				in_options=0
			} else if (character == "#" && !in_options) {
				return i
			}
		}
		return 0
	}
	function emit_line(value) {
		if (mode != "count") {
			print value
		}
	}
	function csv_contains(value, wanted, count, values, i) {
		count=split(value, values, ",")
		for (i=1; i<=count; i++) {
			if (values[i] == wanted) {
				for (i=1; i<=count; i++) delete values[i]
				return 1
			}
		}
		for (i=1; i<=count; i++) delete values[i]
		return 0
	}
	function options_are_safe(value, count, options, i, option, option_value, arch_value) {
		# APT applies a quote-word lexer to option tokens. Reject quoted option
		# text instead of attempting a partial reimplementation that could miss
		# a quoted signature-bypass key.
		if (index(value, "\"") > 0 || index(value, "\047") > 0 ||
			index(value, "\\") > 0 || index(value, "%") > 0) {
			return 0
		}
		count=split(value, options, /[[:space:]]+/)
		for (i=1; i<=count; i++) {
			option=tolower(options[i])
			if (option ~ /^(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)$/) {
				for (i=1; i<=count; i++) delete options[i]
				return 0
			}
			if (option ~ /^(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)=/) {
				option_value=substr(option, index(option, "=") + 1)
				if (option_value !~ /^(0|no|false|off|disable|without)$/) {
					for (i=1; i<=count; i++) delete options[i]
					return 0
				}
			}
			if (option ~ /^arch=/) {
				arch_value=substr(option, 6)
				if (host_arch == "" || !csv_contains(arch_value, host_arch)) {
					for (i=1; i<=count; i++) delete options[i]
					return 0
				}
			}
			if (option ~ /^arch[-+]=/) {
				# Avoid guessing how additive/subtractive filters interact with
				# the host architecture in an administrator-authored entry.
				for (i=1; i<=count; i++) delete options[i]
				return 0
			}
		}
		for (i=1; i<=count; i++) delete options[i]
		return 1
	}
	BEGIN {
		found=0
		binary_found=0
		source_found=0
		malformed=0
	}
	{
		line=$0
		comment_position=apt_comment_position(line)
		if (comment_position > 0) {
			length_line=comment_position - 1
		} else {
			length_line=length(line)
		}
		position=1
		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}

		type_start=position
		while (position <= length_line && substr(line, position, 1) !~ /[[:space:]]/) {
			position++
		}
		entry_type=substr(line, type_start, position - type_start)
		if (entry_type != "deb" && entry_type != "deb-src") {
			emit_line(line)
			next
		}

		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}
		options=""
		if (substr(line, position, 1) == "[") {
			close_offset=index(substr(line, position), "]")
			if (close_offset == 0) {
				if (contains_target_literal(substr(line, 1, length_line))) {
					malformed=1
				}
				emit_line(line)
				next
			}
			options=substr(line, position + 1, close_offset - 2)
			position += close_offset
			while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
				position++
			}
		}

		uri_start=position
		while (position <= length_line && substr(line, position, 1) !~ /[[:space:]]/) {
			position++
		}
		raw_uri=substr(line, uri_start, position - uri_start)
		decoded_uri_token=percent_decode(raw_uri)
		uri=dequote_token(decoded_uri_token)
		if (!is_target_uri(uri)) {
			if (has_unsupported_quote(raw_uri) && contains_target_literal(decoded_uri_token)) {
				malformed=1
			}
			emit_line(line)
			next
		}

		found++
		if (mode == "remove") {
			next
		}
		if (!options_are_safe(options)) {
			malformed=1
			emit_line(line)
			next
		}

		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}
		suite_start=position
		while (position <= length_line && substr(line, position, 1) !~ /[[:space:]]/) {
			position++
		}
		if (suite_start > length_line) {
			malformed=1
			emit_line(line)
			next
		}
		suite_end=position - 1
		suite_value=substr(line, suite_start, suite_end - suite_start + 1)
		if (suite_value !~ /^[a-z0-9][a-z0-9-]*$/) {
			malformed=1
			emit_line(line)
			next
		}

		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}
		component_start=position
		while (position <= length_line && substr(line, position, 1) !~ /[[:space:]]/) {
			position++
		}
		component=substr(line, component_start, position - component_start)
		if (component != "main") {
			malformed=1
			emit_line(line)
			next
		}
		while (position <= length_line && substr(line, position, 1) ~ /[[:space:]]/) {
			position++
		}
		if (position <= length_line && substr(line, position, 1) != "#") {
			malformed=1
			emit_line(line)
			next
		}

		if (entry_type == "deb") {
			binary_found++
		} else {
			source_found++
		}

		if (mode == "set" && suite_value != replacement) {
			line=substr(line, 1, suite_start - 1) replacement substr(line, suite_end + 1)
		}
		emit_line(line)
	}
	END {
		if (mode == "count") {
			print found, binary_found, source_found
		}
		if (malformed) {
			exit 4
		}
		if (!found) {
			exit 3
		}
		if (mode != "remove" && !binary_found) {
			exit 5
		}
	}
	' "${FILE}"
}

# Transform one DEB822 .sources file stanza-by-stanza. A matching stanza must
# contain the Amnezia PPA as its sole URI; mixed-URI stanzas are rejected so an
# unrelated repository can never inherit the fallback suite.
function _transformAmneziaPpaDeb822File() {
	local FILE="$1"
	local MODE="$2"
	local SUITE="${3:-}"
	local ARCHITECTURE="${4:-}"

	awk -v mode="${MODE}" -v replacement="${SUITE}" \
		-v target="${AMNEZIA_PPA_URI}" -v host_arch="${ARCHITECTURE}" '
	function trim(value) {
		gsub(/^[[:space:]]+/, "", value)
		gsub(/[[:space:]]+$/, "", value)
		return value
	}
	function is_target_uri(uri, normalized, http_target) {
		normalized=uri
		sub(/\/+$/, "", normalized)
		http_target=target
		sub(/^https:/, "http:", http_target)
		return normalized == target || normalized == http_target
	}
	function token_list_contains(value, wanted, count, tokens, i, result) {
		result=0
		count=split(trim(value), tokens, /[[:space:]]+/)
		for (i=1; i<=count; i++) {
			if (tokens[i] == wanted) {
				result=1
			}
			delete tokens[i]
		}
		return result
	}
	function is_explicit_false(value, normalized) {
		normalized=tolower(trim(value))
		return normalized ~ /^(0|no|false|off|disable|without)$/
	}
	function is_explicit_true(value, normalized) {
		normalized=tolower(trim(value))
		return normalized ~ /^(1|yes|true|on|enable|with)$/
	}
	function clear_stanza( i) {
		for (i=1; i<=line_count; i++) {
			delete lines[i]
			delete suite_continuation_lines[i]
			delete skip_lines[i]
		}
		line_count=0
	}
	function emit_stanza( i) {
		if (mode != "count") {
			for (i=1; i<=line_count; i++) {
				if (!skip_lines[i]) {
					print lines[i]
				}
			}
		}
	}
	function process_stanza( i, line, colon, field, value, current_field,
			uri_value, type_value, suite_value, component_value, enabled_value,
			trusted_value, allow_insecure_value, allow_weak_value,
			allow_downgrade_value, architecture_value,
			uri_fields, type_fields, suite_fields, component_fields,
			enabled_fields, trusted_fields, allow_insecure_fields,
			allow_weak_fields, allow_downgrade_fields, architecture_fields,
			architecture_remove_fields, suite_line, syntax_error,
			uri_count, target_count, type_count, type_has_deb,
			type_has_deb_src, type_valid,
			suite_count, suite_valid, component_count, component_valid,
			start, finish) {
		if (line_count == 0) {
			return
		}

		current_field=""
		uri_value=""
		type_value=""
		suite_value=""
		component_value=""
		enabled_value=""
		trusted_value=""
		allow_insecure_value=""
		allow_weak_value=""
		allow_downgrade_value=""
		architecture_value=""
		uri_fields=0
		type_fields=0
		suite_fields=0
		component_fields=0
		enabled_fields=0
		trusted_fields=0
		allow_insecure_fields=0
		allow_weak_fields=0
		allow_downgrade_fields=0
		architecture_fields=0
		architecture_remove_fields=0
		suite_line=0
		syntax_error=0

		for (i=1; i<=line_count; i++) {
			line=lines[i]
			if (line ~ /^#/) {
				continue
			}
			if (line ~ /^[A-Za-z0-9-]+:/) {
				colon=index(line, ":")
				field=tolower(substr(line, 1, colon - 1))
				value=trim(substr(line, colon + 1))
				current_field=field
				if (field == "uris") {
					uri_fields++
					uri_value=(uri_value == "" ? value : uri_value " " value)
				} else if (field == "types") {
					type_fields++
					type_value=(type_value == "" ? value : type_value " " value)
				} else if (field == "suites") {
					suite_fields++
					suite_line=i
					suite_value=(suite_value == "" ? value : suite_value " " value)
				} else if (field == "components") {
					component_fields++
					component_value=(component_value == "" ? value : component_value " " value)
				} else if (field == "enabled") {
					enabled_fields++
					enabled_value=(enabled_value == "" ? value : enabled_value " " value)
				} else if (field == "trusted") {
					trusted_fields++
					trusted_value=(trusted_value == "" ? value : trusted_value " " value)
				} else if (field == "allow-insecure") {
					allow_insecure_fields++
					allow_insecure_value=(allow_insecure_value == "" ? value : allow_insecure_value " " value)
				} else if (field == "allow-weak") {
					allow_weak_fields++
					allow_weak_value=(allow_weak_value == "" ? value : allow_weak_value " " value)
				} else if (field == "allow-downgrade-to-insecure") {
					allow_downgrade_fields++
					allow_downgrade_value=(allow_downgrade_value == "" ? value : allow_downgrade_value " " value)
				} else if (field == "architectures") {
					architecture_fields++
					architecture_value=(architecture_value == "" ? value : architecture_value " " value)
				} else if (field == "architectures-remove") {
					architecture_remove_fields++
				}
				continue
			}
			if (line ~ /^[[:space:]]+/) {
				value=trim(line)
				if (current_field == "") {
					syntax_error=1
				} else if (current_field == "uris") {
					uri_value=uri_value " " value
				} else if (current_field == "types") {
					type_value=type_value " " value
				} else if (current_field == "suites") {
					suite_value=suite_value " " value
					suite_continuation_lines[i]=1
				} else if (current_field == "components") {
					component_value=component_value " " value
				} else if (current_field == "enabled") {
					enabled_value=enabled_value " " value
				} else if (current_field == "trusted") {
					trusted_value=trusted_value " " value
				} else if (current_field == "allow-insecure") {
					allow_insecure_value=allow_insecure_value " " value
				} else if (current_field == "allow-weak") {
					allow_weak_value=allow_weak_value " " value
				} else if (current_field == "allow-downgrade-to-insecure") {
					allow_downgrade_value=allow_downgrade_value " " value
				} else if (current_field == "architectures") {
					architecture_value=architecture_value " " value
				}
			} else {
				syntax_error=1
				current_field=""
			}
		}

		uri_count=split(trim(uri_value), uri_tokens, /[[:space:]]+/)
		target_count=0
		for (i=1; i<=uri_count; i++) {
			if (is_target_uri(uri_tokens[i])) {
				target_count++
			}
			delete uri_tokens[i]
		}
		if (target_count == 0) {
			emit_stanza()
			clear_stanza()
			return
		}

		found++
		if (uri_fields != 1 || uri_count != 1 || target_count != 1) {
			malformed=1
			emit_stanza()
			clear_stanza()
			return
		}

		if (mode == "remove") {
			# Preserve comments even when removing the repository stanza.
			if (mode != "count") {
				for (i=1; i<=line_count; i++) {
					if (lines[i] ~ /^#/) {
						print lines[i]
					}
				}
			}
			clear_stanza()
			return
		}

		type_count=split(trim(type_value), type_tokens, /[[:space:]]+/)
		type_has_deb=0
		type_has_deb_src=0
		type_valid=(type_count > 0)
		for (i=1; i<=type_count; i++) {
			if (type_tokens[i] == "deb") {
				type_has_deb=1
			} else if (type_tokens[i] == "deb-src") {
				type_has_deb_src=1
			} else {
				type_valid=0
			}
			delete type_tokens[i]
		}

		suite_count=split(trim(suite_value), suite_tokens, /[[:space:]]+/)
		suite_valid=(suite_count > 0)
		for (i=1; i<=suite_count; i++) {
			if (suite_tokens[i] !~ /^[a-z0-9][a-z0-9-]*$/) {
				suite_valid=0
			}
			delete suite_tokens[i]
		}

		component_count=split(trim(component_value), component_tokens, /[[:space:]]+/)
		component_valid=(component_count == 1 && component_tokens[1] == "main")
		for (i=1; i<=component_count; i++) {
			delete component_tokens[i]
		}

		if (syntax_error || type_fields != 1 || !type_valid ||
				suite_fields != 1 || !suite_valid || component_fields != 1 ||
				!component_valid || enabled_fields > 1 ||
				(enabled_fields == 1 && !is_explicit_true(enabled_value)) ||
				trusted_fields > 1 ||
				(trusted_fields == 1 && !is_explicit_false(trusted_value)) ||
				allow_insecure_fields > 1 ||
				(allow_insecure_fields == 1 && !is_explicit_false(allow_insecure_value)) ||
				allow_weak_fields > 1 ||
				(allow_weak_fields == 1 && !is_explicit_false(allow_weak_value)) ||
				allow_downgrade_fields > 1 ||
				(allow_downgrade_fields == 1 && !is_explicit_false(allow_downgrade_value)) ||
				architecture_fields > 1 ||
				(architecture_fields == 1 &&
					(host_arch == "" || !token_list_contains(architecture_value, host_arch))) ||
				architecture_remove_fields > 0) {
			malformed=1
			emit_stanza()
			clear_stanza()
			return
		}

		if (type_has_deb) {
			binary_found++
		}
		if (type_has_deb_src) {
			source_found++
		}

		if (mode == "set" && trim(suite_value) != replacement) {
			line=lines[suite_line]
			start=index(line, ":") + 1
			while (start <= length(line) && substr(line, start, 1) ~ /[[:space:]]/) {
				start++
			}
			finish=length(line) + 1
			while (finish > start && substr(line, finish - 1, 1) ~ /[[:space:]]/) {
				finish--
			}
			lines[suite_line]=substr(line, 1, start - 1) replacement substr(line, finish)
			for (i=1; i<=line_count; i++) {
				if (suite_continuation_lines[i]) {
					skip_lines[i]=1
				}
			}
		}
		emit_stanza()
		clear_stanza()
	}
	BEGIN {
		line_count=0
		found=0
		binary_found=0
		source_found=0
		malformed=0
	}
	{
		if ($0 ~ /^[[:space:]]*$/) {
			process_stanza()
			if (mode != "count") {
				print $0
			}
		} else {
			lines[++line_count]=$0
		}
	}
	END {
		process_stanza()
		if (mode == "count") {
			print found, binary_found, source_found
		}
		if (malformed) {
			exit 4
		}
		if (!found) {
			exit 3
		}
		if (mode != "remove" && !binary_found) {
			exit 5
		}
	}
	' "${FILE}"
}

function _transformAmneziaPpaSourceFile() {
	local FILE="$1"
	local MODE="$2"
	local SUITE="${3:-}"
	local ARCHITECTURE="${4:-}"
	case "${FILE}" in
		*.sources) _transformAmneziaPpaDeb822File "${FILE}" "${MODE}" "${SUITE}" "${ARCHITECTURE}" ;;
		*.list) _transformAmneziaPpaLegacyFile "${FILE}" "${MODE}" "${SUITE}" "${ARCHITECTURE}" ;;
		*) return 3 ;;
	esac
}

function isValidAptSourceFilename() {
	local BASENAME="${1##*/}"
	[[ "${BASENAME}" =~ ^[A-Za-z0-9_.-]+\.(list|sources)$ ]]
}

function _preserveAptSourceFinalNewline() {
	local SOURCE_FILE="$1"
	local TRANSFORMED_FILE="$2"
	local FINAL_BYTE_LINE_COUNT

	[[ -s "${SOURCE_FILE}" && -s "${TRANSFORMED_FILE}" ]] || return 0
	FINAL_BYTE_LINE_COUNT=$(tail -c 1 -- "${SOURCE_FILE}" | wc -l) || return 1
	if [[ "${FINAL_BYTE_LINE_COUNT}" -eq 0 ]]; then
		truncate -s -1 -- "${TRANSFORMED_FILE}"
	fi
}

# Return 0 when exactly one usable binary entry exists, 1 when absent, and 2
# when target content is duplicated, unusable, malformed, or unsafe to rewrite.
function amneziaPpaSourceEntriesExist() {
	local SOURCES_DIR="${1:-${AMNEZIA_PPA_SOURCES_DIR}}"
	local ARCHITECTURE="${2:-}"
	local FILE
	local RC
	local ENTRY_COUNTS
	local FILE_TARGET_COUNT
	local FILE_BINARY_COUNT
	local FILE_SOURCE_COUNT
	local TARGET_COUNT=0
	local BINARY_COUNT=0
	local SOURCE_COUNT=0

	[[ -d "${SOURCES_DIR}" ]] || return 1
	if [[ -z "${ARCHITECTURE}" ]]; then
		ARCHITECTURE=$(dpkg --print-architecture 2>/dev/null) || return 2
	fi

	for FILE in "${SOURCES_DIR}"/*.sources "${SOURCES_DIR}"/*.list; do
		[[ -e "${FILE}" || -L "${FILE}" ]] || continue
		isValidAptSourceFilename "${FILE}" || continue
		if ENTRY_COUNTS=$(_transformAmneziaPpaSourceFile \
			"${FILE}" "count" "" "${ARCHITECTURE}"); then
			RC=0
		else
			RC=$?
		fi
		case "${RC}" in
			0 | 5)
				if [[ -L "${FILE}" ]]; then
					echo -e "${RED}ERROR: Refusing to modify Amnezia PPA source through symlink: ${FILE}${NC}" >&2
					return 2
				fi
				read -r FILE_TARGET_COUNT FILE_BINARY_COUNT FILE_SOURCE_COUNT <<< "${ENTRY_COUNTS}"
				if ! [[ "${FILE_TARGET_COUNT}" =~ ^[0-9]+$ &&
					"${FILE_BINARY_COUNT}" =~ ^[0-9]+$ &&
					"${FILE_SOURCE_COUNT}" =~ ^[0-9]+$ ]]; then
					return 2
				fi
				TARGET_COUNT=$((TARGET_COUNT + FILE_TARGET_COUNT))
				BINARY_COUNT=$((BINARY_COUNT + FILE_BINARY_COUNT))
				SOURCE_COUNT=$((SOURCE_COUNT + FILE_SOURCE_COUNT))
				;;
			3) ;;
			*)
				echo -e "${RED}ERROR: Unusable, insecure, malformed, or ambiguous Amnezia PPA source entry in ${FILE}.${NC}" >&2
				return 2
				;;
		esac
	done

	if [[ "${TARGET_COUNT}" -eq 0 ]]; then
		return 1
	fi
	if [[ "${BINARY_COUNT}" -eq 0 ]]; then
		echo -e "${RED}ERROR: Existing Amnezia PPA source content has no active binary ('deb') entry for architecture '${ARCHITECTURE}'.${NC}" >&2
		return 2
	fi
	if [[ "${BINARY_COUNT}" -gt 1 ]]; then
		echo -e "${RED}ERROR: Multiple active Amnezia PPA binary entries were found. Remove the duplicate entries before continuing.${NC}" >&2
		return 2
	fi
	if [[ "${SOURCE_COUNT}" -gt 1 ]]; then
		echo -e "${RED}ERROR: Multiple active Amnezia PPA source-package entries were found. Remove the duplicate entries before continuing.${NC}" >&2
		return 2
	fi
	return 0
}

# Set the suite of each exact Amnezia PPA entry, replacing each affected file
# atomically. Unrelated files, stanzas, fields, comments, options, and inline
# signing keys are preserved. Return 2 when no target entry exists.
function setAmneziaPpaSuite() {
	local SUITE="$1"
	local SOURCES_DIR="${2:-${AMNEZIA_PPA_SOURCES_DIR}}"
	local ARCHITECTURE="${3:-}"
	local FILE
	local TMP_FILE
	local RC
	local INDEX
	local ROLLBACK_INDEX
	local FAILED_INDEX=-1
	local ROLLBACK_FAILED=0
	local ENTRY_COUNTS
	local FILE_TARGET_COUNT
	local FILE_BINARY_COUNT
	local FILE_SOURCE_COUNT
	local FILE_CHECKSUM
	local BACKUP_FILE
	local TARGET_COUNT=0
	local BINARY_COUNT=0
	local SOURCE_COUNT=0
	local -a TARGET_FILES=()
	local -a TEMP_FILES=()
	local -a SOURCE_CHECKSUMS=()
	local -a BACKUP_FILES=()
	local -a CHANGED_FLAGS=()

	if ! [[ "${SUITE}" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
		echo -e "${RED}ERROR: Invalid Amnezia PPA suite '${SUITE}'.${NC}" >&2
		return 1
	fi
	[[ -d "${SOURCES_DIR}" ]] || return 2
	if [[ -z "${ARCHITECTURE}" ]]; then
		ARCHITECTURE=$(dpkg --print-architecture 2>/dev/null) || return 1
	fi

	# Validate all matching content before creating any staged replacements.
	for FILE in "${SOURCES_DIR}"/*.sources "${SOURCES_DIR}"/*.list; do
		[[ -e "${FILE}" || -L "${FILE}" ]] || continue
		isValidAptSourceFilename "${FILE}" || continue
		if ENTRY_COUNTS=$(_transformAmneziaPpaSourceFile \
			"${FILE}" "count" "" "${ARCHITECTURE}"); then
			RC=0
		else
			RC=$?
		fi
		case "${RC}" in
			0 | 5)
				if [[ -L "${FILE}" ]]; then
					echo -e "${RED}ERROR: Refusing to modify Amnezia PPA source through symlink: ${FILE}${NC}" >&2
					return 1
				fi
				read -r FILE_TARGET_COUNT FILE_BINARY_COUNT FILE_SOURCE_COUNT <<< "${ENTRY_COUNTS}"
				if ! [[ "${FILE_TARGET_COUNT}" =~ ^[0-9]+$ &&
					"${FILE_BINARY_COUNT}" =~ ^[0-9]+$ &&
					"${FILE_SOURCE_COUNT}" =~ ^[0-9]+$ ]]; then
					return 1
				fi
				TARGET_COUNT=$((TARGET_COUNT + FILE_TARGET_COUNT))
				BINARY_COUNT=$((BINARY_COUNT + FILE_BINARY_COUNT))
				SOURCE_COUNT=$((SOURCE_COUNT + FILE_SOURCE_COUNT))
				FILE_CHECKSUM=$(cksum -- "${FILE}") || return 1
				TARGET_FILES+=("${FILE}")
				SOURCE_CHECKSUMS+=("${FILE_CHECKSUM}")
				;;
			3) ;;
			*)
				echo -e "${RED}ERROR: Unusable, insecure, malformed, or ambiguous Amnezia PPA source entry in ${FILE}.${NC}" >&2
				return 1
				;;
		esac
	done

	if [[ "${TARGET_COUNT}" -eq 0 ]]; then
		return 2
	fi
	if [[ "${BINARY_COUNT}" -eq 0 ]]; then
		echo -e "${RED}ERROR: Existing Amnezia PPA source content has no active binary ('deb') entry for architecture '${ARCHITECTURE}'.${NC}" >&2
		return 1
	fi
	if [[ "${BINARY_COUNT}" -gt 1 ]]; then
		echo -e "${RED}ERROR: Multiple active Amnezia PPA binary entries were found. Remove the duplicate entries before continuing.${NC}" >&2
		return 1
	fi
	if [[ "${SOURCE_COUNT}" -gt 1 ]]; then
		echo -e "${RED}ERROR: Multiple active Amnezia PPA source-package entries were found. Remove the duplicate entries before continuing.${NC}" >&2
		return 1
	fi

	for FILE in "${TARGET_FILES[@]}"; do
		if [[ -L "${FILE}" || ! -f "${FILE}" ]]; then
			echo -e "${RED}ERROR: Amnezia PPA source changed while it was being validated: ${FILE}${NC}" >&2
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		fi
		TMP_FILE=$(mktemp "${FILE}.amneziawg.XXXXXX") || {
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		}
		if ! cp --preserve=all -- "${FILE}" "${TMP_FILE}"; then
			rm -f "${TMP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		fi
		if _transformAmneziaPpaSourceFile \
			"${FILE}" "set" "${SUITE}" "${ARCHITECTURE}" > "${TMP_FILE}"; then
			RC=0
		else
			RC=$?
		fi
		case "${RC}" in
			0 | 5)
				if ! _preserveAptSourceFinalNewline "${FILE}" "${TMP_FILE}"; then
					rm -f "${TMP_FILE}"
					for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
					return 1
				fi
				TEMP_FILES+=("${TMP_FILE}")
				;;
			*)
				rm -f "${TMP_FILE}"
				for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
				echo -e "${RED}ERROR: Amnezia PPA source changed while it was being rewritten: ${FILE}${NC}" >&2
				return 1
				;;
		esac
	done

	# Recheck every source after staging so a concurrent administrator edit is
	# never overwritten. Backups let a later per-file rename failure roll back
	# earlier files in the same reconciliation.
	for INDEX in "${!TARGET_FILES[@]}"; do
		if [[ -L "${TARGET_FILES[INDEX]}" || ! -f "${TARGET_FILES[INDEX]}" ]] ||
			[[ "$(cksum -- "${TARGET_FILES[INDEX]}")" != "${SOURCE_CHECKSUMS[INDEX]}" ]]; then
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			echo -e "${RED}ERROR: Amnezia PPA source changed while replacements were being staged: ${TARGET_FILES[INDEX]}${NC}" >&2
			return 1
		fi
		BACKUP_FILE=$(mktemp "${TARGET_FILES[INDEX]}.amneziawg-backup.XXXXXX") || {
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			return 1
		}
		if ! cp --preserve=all -- "${TARGET_FILES[INDEX]}" "${BACKUP_FILE}"; then
			rm -f "${BACKUP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			return 1
		fi
		BACKUP_FILES+=("${BACKUP_FILE}")
		if cmp -s "${TARGET_FILES[INDEX]}" "${TEMP_FILES[INDEX]}"; then
			CHANGED_FLAGS+=("0")
		else
			CHANGED_FLAGS+=("1")
		fi
	done

	for INDEX in "${!TARGET_FILES[@]}"; do
		if [[ -L "${TARGET_FILES[INDEX]}" || ! -f "${TARGET_FILES[INDEX]}" ]] ||
			[[ "$(cksum -- "${TARGET_FILES[INDEX]}")" != "${SOURCE_CHECKSUMS[INDEX]}" ]]; then
			FAILED_INDEX="${INDEX}"
			break
		fi
		if [[ "${CHANGED_FLAGS[INDEX]}" -eq 0 ]]; then
			rm -f "${TEMP_FILES[INDEX]}"
		elif ! mv -f "${TEMP_FILES[INDEX]}" "${TARGET_FILES[INDEX]}"; then
			FAILED_INDEX="${INDEX}"
			break
		fi
	done
	if [[ "${FAILED_INDEX}" -ge 0 ]]; then
		for ((ROLLBACK_INDEX=0; ROLLBACK_INDEX<FAILED_INDEX; ROLLBACK_INDEX++)); do
			if [[ "${CHANGED_FLAGS[ROLLBACK_INDEX]}" -eq 1 ]] &&
				! mv -f "${BACKUP_FILES[ROLLBACK_INDEX]}" "${TARGET_FILES[ROLLBACK_INDEX]}"; then
				ROLLBACK_FAILED=1
			fi
		done
		for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
		for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
		if [[ "${ROLLBACK_FAILED}" -eq 1 ]]; then
			echo -e "${RED}ERROR: Failed to roll back every PPA source after a replacement error. Review ${SOURCES_DIR}.${NC}" >&2
		fi
		return 1
	fi
	for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
	return 0
}

# Remove only exact Amnezia PPA entries, regardless of their suite or filename.
# Empty source files are deleted; files retaining comments or unrelated entries
# remain in place. This is idempotent and is also used for failed-add cleanup.
function removeAmneziaPpaSourceEntries() {
	local SOURCES_DIR="${1:-${AMNEZIA_PPA_SOURCES_DIR}}"
	local FILE
	local TMP_FILE
	local RC
	local INDEX
	local ROLLBACK_INDEX
	local FAILED_INDEX=-1
	local ROLLBACK_FAILED=0
	local FILE_CHECKSUM
	local BACKUP_FILE
	local -a TARGET_FILES=()
	local -a TEMP_FILES=()
	local -a SOURCE_CHECKSUMS=()
	local -a BACKUP_FILES=()

	[[ -d "${SOURCES_DIR}" ]] || return 0

	# Validate every prospective removal before staging any file. In particular,
	# mixed-URI DEB822 stanzas and symlinks are never partially processed.
	for FILE in "${SOURCES_DIR}"/*.sources "${SOURCES_DIR}"/*.list; do
		[[ -e "${FILE}" || -L "${FILE}" ]] || continue
		isValidAptSourceFilename "${FILE}" || continue
		if _transformAmneziaPpaSourceFile "${FILE}" "remove" >/dev/null; then
			RC=0
		else
			RC=$?
		fi
		case "${RC}" in
			0)
				if [[ -L "${FILE}" ]]; then
					echo -e "${RED}ERROR: Refusing to modify Amnezia PPA source through symlink: ${FILE}${NC}" >&2
					return 1
				fi
				FILE_CHECKSUM=$(cksum -- "${FILE}") || return 1
				TARGET_FILES+=("${FILE}")
				SOURCE_CHECKSUMS+=("${FILE_CHECKSUM}")
				;;
			3) ;;
			*)
				echo -e "${RED}ERROR: Malformed or ambiguous Amnezia PPA source entry in ${FILE}.${NC}" >&2
				return 1
				;;
		esac
	done

	for FILE in "${TARGET_FILES[@]}"; do
		if [[ -L "${FILE}" || ! -f "${FILE}" ]]; then
			echo -e "${RED}ERROR: Amnezia PPA source changed while it was being validated: ${FILE}${NC}" >&2
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		fi
		TMP_FILE=$(mktemp "${FILE}.amneziawg.XXXXXX") || {
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		}
		if ! cp --preserve=all -- "${FILE}" "${TMP_FILE}"; then
			rm -f "${TMP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			return 1
		fi
		if _transformAmneziaPpaSourceFile "${FILE}" "remove" > "${TMP_FILE}"; then
			RC=0
		else
			RC=$?
		fi
		if [[ "${RC}" -ne 0 ]] ||
			! _preserveAptSourceFinalNewline "${FILE}" "${TMP_FILE}"; then
			rm -f "${TMP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			echo -e "${RED}ERROR: Amnezia PPA source changed while it was being removed: ${FILE}${NC}" >&2
			return 1
		fi
		TEMP_FILES+=("${TMP_FILE}")
	done

	for INDEX in "${!TARGET_FILES[@]}"; do
		if [[ -L "${TARGET_FILES[INDEX]}" || ! -f "${TARGET_FILES[INDEX]}" ]] ||
			[[ "$(cksum -- "${TARGET_FILES[INDEX]}")" != "${SOURCE_CHECKSUMS[INDEX]}" ]]; then
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			echo -e "${RED}ERROR: Amnezia PPA source changed while removals were being staged: ${TARGET_FILES[INDEX]}${NC}" >&2
			return 1
		fi
		BACKUP_FILE=$(mktemp "${TARGET_FILES[INDEX]}.amneziawg-backup.XXXXXX") || {
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			return 1
		}
		if ! cp --preserve=all -- "${TARGET_FILES[INDEX]}" "${BACKUP_FILE}"; then
			rm -f "${BACKUP_FILE}"
			for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
			for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
			return 1
		fi
		BACKUP_FILES+=("${BACKUP_FILE}")
	done

	for INDEX in "${!TARGET_FILES[@]}"; do
		if [[ -L "${TARGET_FILES[INDEX]}" || ! -f "${TARGET_FILES[INDEX]}" ]] ||
			[[ "$(cksum -- "${TARGET_FILES[INDEX]}")" != "${SOURCE_CHECKSUMS[INDEX]}" ]]; then
			FAILED_INDEX="${INDEX}"
			break
		fi
		if grep -q '[^[:space:]]' "${TEMP_FILES[INDEX]}"; then
			if ! mv -f "${TEMP_FILES[INDEX]}" "${TARGET_FILES[INDEX]}"; then
				FAILED_INDEX="${INDEX}"
				break
			fi
		else
			rm -f "${TEMP_FILES[INDEX]}"
			if ! rm -f -- "${TARGET_FILES[INDEX]}"; then
				FAILED_INDEX="${INDEX}"
				break
			fi
		fi
	done
	if [[ "${FAILED_INDEX}" -ge 0 ]]; then
		for ((ROLLBACK_INDEX=0; ROLLBACK_INDEX<FAILED_INDEX; ROLLBACK_INDEX++)); do
			if ! mv -f "${BACKUP_FILES[ROLLBACK_INDEX]}" "${TARGET_FILES[ROLLBACK_INDEX]}"; then
				ROLLBACK_FAILED=1
			fi
		done
		for TMP_FILE in "${TEMP_FILES[@]}"; do rm -f "${TMP_FILE}"; done
		for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
		if [[ "${ROLLBACK_FAILED}" -eq 1 ]]; then
			echo -e "${RED}ERROR: Failed to roll back every PPA source after a removal error. Review ${SOURCES_DIR}.${NC}" >&2
		fi
		return 1
	fi
	for BACKUP_FILE in "${BACKUP_FILES[@]}"; do rm -f "${BACKUP_FILE}"; done
	return 0
}

# Add or reconcile the PPA without letting add-apt-repository update APT before
# a fallback suite can be selected. Existing valid entries are reused, which
# prevents duplicate stanzas on installer reruns.
function configureUbuntuAmneziaPpa() {
	local NATIVE_SUITE="${1:-}"
	local SOURCES_DIR="${2:-${AMNEZIA_PPA_SOURCES_DIR}}"
	local ARCHITECTURE="${3:-}"
	local EXIST_RC
	local SELECTED_SUITE

	AMNEZIA_PPA_SOURCE_CREATED=0
	if [[ -z "${NATIVE_SUITE}" ]]; then
		NATIVE_SUITE=$(getUbuntuPpaCodename) || return 1
	fi
	if [[ -z "${ARCHITECTURE}" ]]; then
		ARCHITECTURE=$(dpkg --print-architecture 2>/dev/null) || {
			echo -e "${RED}ERROR: Unable to determine the system package architecture.${NC}" >&2
			return 1
		}
	fi
	SELECTED_SUITE=$(selectAmneziaPpaSuite "${NATIVE_SUITE}" "${ARCHITECTURE}") || return 1

	if amneziaPpaSourceEntriesExist "${SOURCES_DIR}" "${ARCHITECTURE}"; then
		EXIST_RC=0
	else
		EXIST_RC=$?
	fi
	case "${EXIST_RC}" in
		0)
			if ! setAmneziaPpaSuite "${SELECTED_SUITE}" "${SOURCES_DIR}" "${ARCHITECTURE}"; then
				echo -e "${RED}ERROR: Failed to reconcile the existing Amnezia PPA source.${NC}" >&2
				return 1
			fi
			;;
		1)
			if ! add-apt-repository -y -n ppa:amnezia/ppa; then
				if ! removeAmneziaPpaSourceEntries "${SOURCES_DIR}"; then
					echo -e "${ORANGE}WARNING: Failed to clean up a partial Amnezia PPA source after add-apt-repository failed.${NC}" >&2
				fi
				echo -e "${RED}ERROR: Failed to add Amnezia PPA.${NC}" >&2
				return 1
			fi
			if ! setAmneziaPpaSuite "${SELECTED_SUITE}" "${SOURCES_DIR}" "${ARCHITECTURE}"; then
				if ! removeAmneziaPpaSourceEntries "${SOURCES_DIR}"; then
					echo -e "${ORANGE}WARNING: Failed to clean up the unusable source created by add-apt-repository.${NC}" >&2
				fi
				echo -e "${RED}ERROR: add-apt-repository did not create a usable Amnezia PPA source entry.${NC}" >&2
				return 1
			fi
			AMNEZIA_PPA_SOURCE_CREATED=1
			;;
		*)
			return 1
			;;
	esac

	return 0
}

# Roll back only a source entry created by the current configure call. A
# pre-existing administrator-owned entry is never removed because another
# repository or a transient network failure made apt-get update fail.
# Return 0 when removed, 1 on cleanup failure, and 2 when no new entry is owned.
function cleanupNewlyCreatedUbuntuAmneziaPpa() {
	local SOURCES_DIR="${1:-${AMNEZIA_PPA_SOURCES_DIR}}"

	[[ "${AMNEZIA_PPA_SOURCE_CREATED}" -eq 1 ]] || return 2
	if ! removeAmneziaPpaSourceEntries "${SOURCES_DIR}"; then
		return 1
	fi
	AMNEZIA_PPA_SOURCE_CREATED=0
	return 0
}

# Best-effort reconciliation for an already-installed server. This rechecks the
# native suite on every rerun so a temporary fallback automatically stops being
# used once Launchpad publishes native metadata. Management remains available
# during network outages.
function refreshConfiguredUbuntuAmneziaPpa() {
	local EXIST_RC
	if amneziaPpaSourceEntriesExist "${AMNEZIA_PPA_SOURCES_DIR}"; then
		EXIST_RC=0
	else
		EXIST_RC=$?
	fi
	case "${EXIST_RC}" in
		0)
			enable_apt_ipv4
			if ! configureUbuntuAmneziaPpa "" "${AMNEZIA_PPA_SOURCES_DIR}"; then
				echo -e "${ORANGE}WARNING: Could not refresh the configured Amnezia PPA suite. Leaving the existing entry unchanged.${NC}" >&2
			fi
			disable_apt_ipv4
			;;
		1) return 0 ;;
		*)
			echo -e "${ORANGE}WARNING: Existing Amnezia PPA source content is malformed; automatic suite refresh was skipped.${NC}" >&2
			;;
	esac
	return 0
}

# For sensitive files (private keys, params, configs), a restrictive umask (077)
# is applied locally around their creation to avoid them being briefly world-readable.
# This avoids affecting subprocesses (apt/dnf, dkms, etc.) that expect the default umask.

# Safely quote a value for inclusion in a sourced params file
# Escapes single quotes and wraps in single quotes to prevent shell injection
function safeQuoteParam() {
	local VALUE="$1"
	# Replace each single quote with '"'"' (end quote, literal quote, start quote)
	local ESCAPED
	ESCAPED="$(printf '%s' "${VALUE}" | sed "s/'/'\"'\"'/g")"
	printf "'%s'\n" "${ESCAPED}"
}

# Optional self-test for safeQuoteParam; run by setting SAFE_QUOTE_PARAM_SELFTEST=1
if [[ "${SAFE_QUOTE_PARAM_SELFTEST:-0}" == "1" ]]; then
	TEST_VALUE="O'Reilly"
	QUOTED="$(safeQuoteParam "${TEST_VALUE}")"
	# Verify the quoted form matches the known-good shell-safe literal; no eval needed
	EXPECTED="'O'\"'\"'Reilly'"
	if [[ "${QUOTED}" != "${EXPECTED}" ]]; then
		echo "ERROR: safeQuoteParam self-test failed: expected '${EXPECTED}', got '${QUOTED}'" >&2
		exit 1
	fi
fi

# Determine whether an IPv4 address is in a private / non-routable range.
# Returns 0 (true) for RFC1918, CGNAT (100.64/10), link-local (169.254/16),
# loopback (127/8) and the unspecified address; returns 1 otherwise.
# Inputs that aren't a dotted-quad IPv4 literal also return 1 (treated as
# "not known to be private") so callers can pass through hostnames or IPv6
# untouched.
function isPrivateIPv4() {
	local ADDR="${1:-}"
	# Must be a dotted-quad of 0-255 octets to evaluate; otherwise not-private.
	if ! [[ "${ADDR}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
		return 1
	fi

	# Force base-10 interpretation: the IPv4 regex above accepts leading
	# zeros (e.g. "08.0.0.1"), which would otherwise trigger bash octal
	# parsing and noisy "value too great for base" errors in (( ... )).
	local A B
	A=$((10#${ADDR%%.*}))
	B="${ADDR#*.}"
	B=$((10#${B%%.*}))

	# 10.0.0.0/8
	if (( A == 10 )); then return 0; fi
	# 127.0.0.0/8 (loopback)
	if (( A == 127 )); then return 0; fi
	# 172.16.0.0/12
	if (( A == 172 )) && (( B >= 16 && B <= 31 )); then return 0; fi
	# 192.168.0.0/16
	if (( A == 192 && B == 168 )); then return 0; fi
	# 100.64.0.0/10 (CGNAT - used by AWS, some ISPs, etc.)
	if (( A == 100 )) && (( B >= 64 && B <= 127 )); then return 0; fi
	# 169.254.0.0/16 (link-local, also AWS instance metadata)
	if (( A == 169 && B == 254 )); then return 0; fi
	# 0.0.0.0/8 — the script treats the entire "this network"/software block
	# (RFC 1122 §3.2.1.3) as non-public, not just the single unspecified
	# address 0.0.0.0, since none of these are routable on the public internet.
	if (( A == 0 )); then return 0; fi

	return 1
}

# Detect the server's public IPv4 address.
#
# Strategy:
#   1. Iterate all global-scope IPv4 addresses from `ip -4 addr` and pick
#      the first one that is not private/CGNAT/link-local. This handles
#      multi-homed hosts where a private interface is enumerated before a
#      public one, and avoids a needless external request when a public
#      IPv4 is already bound locally.
#   2. If no public IPv4 is found locally (empty list, or all addresses
#      are private — e.g. AWS EC2, GCP, LXC/Docker hosts), query an
#      external echo service over IPv4 (`curl -4 ifconfig.me`, with a
#      fallback) to discover the NAT-mapped public address. This is
#      required because cloud providers like AWS assign the public/Elastic
#      IP via 1:1 NAT and it never appears on the host's interfaces.
#   3. If external lookup fails or returns nothing usable, fall back to the
#      first locally-detected address (which may still be private but is
#      better than empty; the user can override interactively or via env).
#
# Privacy / opt-out:
#   Set AWG_SKIP_PUBLIC_IP_LOOKUP=y (or =1/=true) to disable the external
#   IP-echo step entirely. When disabled, the function only returns the
#   locally-detected address (or empty), avoiding any outbound HTTPS request
#   to third-party services. Useful for air-gapped installs or when the
#   operator wants to set SERVER_PUB_IP explicitly.
#
# Prints the detected address on stdout. Always returns 0; callers should
# check whether the output is empty.
function detectPublicIPv4() {
	local LOCAL_IP=""
	local FIRST_LOCAL_IP=""
	local CANDIDATE
	local PUBLIC_IP=""
	local URL

	# Collect all global-scope IPv4 addresses (multi-homed hosts may have
	# both a private and a public interface). Prefer the first public one
	# so we don't make an unnecessary external request — and don't
	# accidentally return the NAT-mapped egress IP when a directly-bound
	# public IPv4 already exists locally.
	while IFS= read -r CANDIDATE; do
		[[ -z "${CANDIDATE}" ]] && continue
		[[ -z "${FIRST_LOCAL_IP}" ]] && FIRST_LOCAL_IP="${CANDIDATE}"
		if ! isPrivateIPv4 "${CANDIDATE}"; then
			LOCAL_IP="${CANDIDATE}"
			break
		fi
	done < <(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p')

	# If we didn't find a public one, keep the first (private) address as a
	# fall-back so the function still returns something usable when the
	# external lookup fails or is opted out.
	if [[ -z "${LOCAL_IP}" ]]; then
		LOCAL_IP="${FIRST_LOCAL_IP}"
	fi

	# Honour an explicit opt-out so the installer never makes an unsolicited
	# request to a third-party IP-echo service. Accept y/yes/1/true (any case).
	local SKIP="${AWG_SKIP_PUBLIC_IP_LOOKUP:-}"
	SKIP="${SKIP,,}"
	if [[ "${SKIP}" == "y" || "${SKIP}" == "yes" || "${SKIP}" == "1" || "${SKIP}" == "true" ]]; then
		printf '%s\n' "${LOCAL_IP}"
		return 0
	fi

	if [[ -z "${LOCAL_IP}" ]] || isPrivateIPv4 "${LOCAL_IP}"; then
		if command -v curl >/dev/null 2>&1; then
			for URL in "https://ifconfig.me" "https://api.ipify.org" "https://ipv4.icanhazip.com"; do
				PUBLIC_IP="$(curl -4 -fsS --max-time 5 "${URL}" 2>/dev/null | tr -d '[:space:]')"
				if [[ "${PUBLIC_IP}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]] \
					&& ! isPrivateIPv4 "${PUBLIC_IP}"; then
					printf '%s\n' "${PUBLIC_IP}"
					return 0
				fi
				PUBLIC_IP=""
			done
		elif command -v wget >/dev/null 2>&1; then
			for URL in "https://ifconfig.me" "https://api.ipify.org" "https://ipv4.icanhazip.com"; do
				PUBLIC_IP="$(wget -4 -qO- --timeout=5 --tries=1 "${URL}" 2>/dev/null | tr -d '[:space:]')"
				if [[ "${PUBLIC_IP}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]] \
					&& ! isPrivateIPv4 "${PUBLIC_IP}"; then
					printf '%s\n' "${PUBLIC_IP}"
					return 0
				fi
				PUBLIC_IP=""
			done
		fi
	fi

	printf '%s\n' "${LOCAL_IP}"
	return 0
}

# Copy a client config file to the web panel config directory so the panel
# can discover and display it.  This is a best-effort operation: if the web
# panel is not installed (directory absent), the copy is silently skipped.
function copyToWebPanelDir() {
	local src_file="$1"
	if [[ -d "${WEB_PANEL_CONFIG_DIR}" && ! -L "${WEB_PANEL_CONFIG_DIR}" && -f "${src_file}" && ! -L "${src_file}" ]]; then
		local dest
		dest="${WEB_PANEL_CONFIG_DIR}/$(basename "${src_file}")"
		# Avoid following or overwriting a pre-existing symlink at the destination.
		if [[ -L "${dest}" ]]; then
			# Best-effort: warn and skip rather than risk clobbering the symlink target.
			echo "Warning: refusing to copy '${src_file}' to '${dest}' because destination is a symlink" >&2
			return 0
		fi
		cp -f "${src_file}" "${WEB_PANEL_CONFIG_DIR}/" 2>/dev/null || true
		# Only adjust ownership and permissions on a regular non-symlink file we just copied.
		if [[ -f "${dest}" && ! -L "${dest}" ]]; then
			# Determine the directory's group; use it if available, otherwise fall back to root.
			local dir_group dest_group
			dir_group="$(stat -c '%G' "${WEB_PANEL_CONFIG_DIR}" 2>/dev/null || true)"
			if [[ -n "${dir_group}" ]]; then
				dest_group="${dir_group}"
			else
				dest_group="root"
			fi
			# Enforce root ownership and the chosen group before tightening permissions.
			chown "root:${dest_group}" "${dest}" 2>/dev/null || true
			chmod 640 "${dest}" 2>/dev/null || true
		fi
	fi
}

# Remove a client config file from the web panel config directory.
function removeFromWebPanelDir() {
	local filename="$1"
	if [[ -d "${WEB_PANEL_CONFIG_DIR}" && ! -L "${WEB_PANEL_CONFIG_DIR}" ]]; then
		rm -f -- "${WEB_PANEL_CONFIG_DIR}/${filename}" 2>/dev/null || true
	fi
}

# Serialize all server parameters to a params file
# Uses safe quoting for string values to prevent shell injection when sourced
# Arguments:
#   $1 - Output file path to write the serialized params to
function serializeParams() {
	local OUTPUT_FILE="$1"
	if [[ -z "${OUTPUT_FILE}" ]]; then
		echo "ERROR: serializeParams() requires an output file path" >&2
		return 1
	fi
	# Apply a restrictive umask only while writing the params file to disk,
	# so that subprocesses (apt/dnf, dkms, etc.) are not affected.
	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077
	cat >"${OUTPUT_FILE}" <<EOF
SERVER_PUB_IP=$(safeQuoteParam "${SERVER_PUB_IP}")
SERVER_PUB_NIC=$(safeQuoteParam "${SERVER_PUB_NIC}")
SERVER_AWG_NIC=$(safeQuoteParam "${SERVER_AWG_NIC}")
SERVER_AWG_IPV4=$(safeQuoteParam "${SERVER_AWG_IPV4}")
SERVER_AWG_IPV6=$(safeQuoteParam "${SERVER_AWG_IPV6}")
SERVER_PORT=$(safeQuoteParam "${SERVER_PORT}")
SERVER_PRIV_KEY=$(safeQuoteParam "${SERVER_PRIV_KEY}")
SERVER_PUB_KEY=$(safeQuoteParam "${SERVER_PUB_KEY}")
CLIENT_DNS_1=$(safeQuoteParam "${CLIENT_DNS_1}")
CLIENT_DNS_2=$(safeQuoteParam "${CLIENT_DNS_2}")
ALLOWED_IPS=$(safeQuoteParam "${ALLOWED_IPS}")
ENABLE_IPV6=$(safeQuoteParam "${ENABLE_IPV6:-}")
SERVER_AWG_JC=$(safeQuoteParam "${SERVER_AWG_JC}")
SERVER_AWG_JMIN=$(safeQuoteParam "${SERVER_AWG_JMIN}")
SERVER_AWG_JMAX=$(safeQuoteParam "${SERVER_AWG_JMAX}")
SERVER_AWG_S1=$(safeQuoteParam "${SERVER_AWG_S1}")
SERVER_AWG_S2=$(safeQuoteParam "${SERVER_AWG_S2}")
SERVER_AWG_S3=$(safeQuoteParam "${SERVER_AWG_S3}")
SERVER_AWG_S4=$(safeQuoteParam "${SERVER_AWG_S4}")
SERVER_AWG_H1=$(safeQuoteParam "${SERVER_AWG_H1}")
SERVER_AWG_H2=$(safeQuoteParam "${SERVER_AWG_H2}")
SERVER_AWG_H3=$(safeQuoteParam "${SERVER_AWG_H3}")
SERVER_AWG_H4=$(safeQuoteParam "${SERVER_AWG_H4}")
EOF
	umask "${OLD_UMASK}"
}

# Validate an IPv6 address string
# Handles full form (8 hextets), compressed form (with ::), and mixed forms
# Returns 0 if valid, 1 if invalid
# Note: Does not support IPv4-mapped addresses (e.g., ::ffff:192.0.2.1)
function isValidIPv6() {
	local ADDR="$1"

	if [[ -z "${ADDR}" ]]; then
		return 1
	fi

	# Must only contain hex digits and colons
	if ! [[ "${ADDR}" =~ ^[a-fA-F0-9:]+$ ]]; then
		return 1
	fi

	# Must not start or end with a single colon (:: at boundaries is OK)
	if [[ "${ADDR}" =~ ^:[^:] ]] || [[ "${ADDR}" =~ [^:]:$ ]]; then
		return 1
	fi

	# Count :: occurrences (at most one allowed)
	local WITHOUT_DC="${ADDR//::}"
	local DC_COUNT=$(( (${#ADDR} - ${#WITHOUT_DC}) / 2 ))

	if (( DC_COUNT > 1 )); then
		return 1
	fi

	local -a PARTS=() LEFT_PARTS=() RIGHT_PARTS=()
	local PART LEFT RIGHT LEFT_COUNT RIGHT_COUNT

	if (( DC_COUNT == 1 )); then
		LEFT="${ADDR%%::*}"
		RIGHT="${ADDR#*::}"
		LEFT_COUNT=0
		RIGHT_COUNT=0

		if [[ -n "${LEFT}" ]]; then
			IFS=':' read -ra LEFT_PARTS <<< "${LEFT}"
			LEFT_COUNT=${#LEFT_PARTS[@]}
			for PART in "${LEFT_PARTS[@]}"; do
				if [[ -z "${PART}" ]] || (( ${#PART} > 4 )); then
					return 1
				fi
			done
		fi

		if [[ -n "${RIGHT}" ]]; then
			IFS=':' read -ra RIGHT_PARTS <<< "${RIGHT}"
			RIGHT_COUNT=${#RIGHT_PARTS[@]}
			for PART in "${RIGHT_PARTS[@]}"; do
				if [[ -z "${PART}" ]] || (( ${#PART} > 4 )); then
					return 1
				fi
			done
		fi

		# With :: present, total groups must be fewer than 8
		if (( LEFT_COUNT + RIGHT_COUNT >= 8 )); then
			return 1
		fi
	else
		# No :: compression - must have exactly 8 colon-separated groups
		IFS=':' read -ra PARTS <<< "${ADDR}"
		if (( ${#PARTS[@]} != 8 )); then
			return 1
		fi
		for PART in "${PARTS[@]}"; do
			if [[ -z "${PART}" ]] || (( ${#PART} > 4 )); then
				return 1
			fi
		done
	fi

	return 0
}

# Expand an IPv6 address to its full 8-group form without :: compression
# Each group is lowercase with leading zeros stripped
# e.g., fd42:42:42::1 -> fd42:42:42:0:0:0:0:1
# Used for semantic comparison and reliable prefix extraction
function normalizeIPv6() {
	local ADDR="$1"
	local -a HEXTETS=() LEFT_PARTS=() RIGHT_PARTS=()
	local LEFT RIGHT FILL_COUNT i RESULT NORMALIZED

	if [[ "${ADDR}" == *"::"* ]]; then
		LEFT="${ADDR%%::*}"
		RIGHT="${ADDR#*::}"

		if [[ -n "${LEFT}" ]]; then
			IFS=':' read -ra LEFT_PARTS <<< "${LEFT}"
		fi
		if [[ -n "${RIGHT}" ]]; then
			IFS=':' read -ra RIGHT_PARTS <<< "${RIGHT}"
		fi

		FILL_COUNT=$((8 - ${#LEFT_PARTS[@]} - ${#RIGHT_PARTS[@]}))

		HEXTETS=("${LEFT_PARTS[@]}")
		for (( i = 0; i < FILL_COUNT; i++ )); do
			HEXTETS+=("0")
		done
		HEXTETS+=("${RIGHT_PARTS[@]}")
	else
		IFS=':' read -ra HEXTETS <<< "${ADDR}"
	fi

	RESULT=""
	for (( i = 0; i < 8; i++ )); do
		if (( i > 0 )); then
			RESULT+=":"
		fi
		printf -v NORMALIZED '%x' "0x${HEXTETS[$i]:-0}"
		RESULT+="${NORMALIZED}"
	done

	echo "${RESULT}"
}

# Compress a fully expanded IPv6 address to its canonical compressed form (RFC 5952)
# Replaces the longest run of consecutive zero groups (>= 2) with ::
# Input should be the output of normalizeIPv6() (8 lowercase groups, no leading zeros)
# e.g., fd42:42:42:0:0:0:0:2 -> fd42:42:42::2
function compressIPv6() {
	local ADDR="$1"
	local -a IPV6_PARTS
	IFS=':' read -ra IPV6_PARTS <<< "${ADDR}"

	# Find the longest consecutive run of '0' groups (leftmost if tied)
	local BEST_START=-1
	local BEST_LEN=0
	local CUR_START=-1
	local CUR_LEN=0
	local i

	for (( i = 0; i < 8; i++ )); do
		if [[ "${IPV6_PARTS[$i]}" == "0" ]]; then
			if (( CUR_START == -1 )); then
				CUR_START=$i
				CUR_LEN=1
			else
				(( CUR_LEN++ ))
			fi
			if (( CUR_LEN > BEST_LEN )); then
				BEST_START=$CUR_START
				BEST_LEN=$CUR_LEN
			fi
		else
			CUR_START=-1
			CUR_LEN=0
		fi
	done

	# Per RFC 5952, only compress runs of 2 or more consecutive zero groups
	if (( BEST_LEN < 2 )); then
		local IFS=':'
		echo "${IPV6_PARTS[*]}"
		return
	fi

	# Build the compressed address
	local IFS=':'
	local LEFT_PARTS=("${IPV6_PARTS[@]:0:$BEST_START}")
	local RIGHT_PARTS=("${IPV6_PARTS[@]:$((BEST_START + BEST_LEN))}")
	local LEFT="${LEFT_PARTS[*]}"
	local RIGHT="${RIGHT_PARTS[*]}"

	echo "${LEFT}::${RIGHT}"
}

# Optional self-tests for compressIPv6. These are only run when the installer
# is executed directly with AMNEZIAWG_RUN_IPV6_TESTS=1 in the environment.
# They are intended to guard against regressions in the RFC 5952 logic.
function __compressIPv6_expect() {
	local EXPECTED="$1"
	local INPUT="$2"
	local ACTUAL

	ACTUAL="$(compressIPv6 "${INPUT}")"
	if [[ "${ACTUAL}" != "${EXPECTED}" ]]; then
		echo "compressIPv6 test failed: input='${INPUT}' expected='${EXPECTED}' got='${ACTUAL}'" >&2
		return 1
	fi

	return 0
}

function run_compressIPv6_tests() {
	local FAIL=0

	# Addresses that should NOT compress (no run of >= 2 zero groups)
	__compressIPv6_expect "2001:db8:0:1:2:3:4:5" "2001:db8:0:1:2:3:4:5" || FAIL=1
	__compressIPv6_expect "2001:db8:0:1:2:3:4:0" "2001:db8:0:1:2:3:4:0" || FAIL=1

	# Simple middle run
	__compressIPv6_expect "2001:db8::1:0:0:1" "2001:db8:0:0:1:0:0:1" || FAIL=1

	# Leading zero run
	__compressIPv6_expect "::1:2:3:4:5" "0:0:0:1:2:3:4:5" || FAIL=1

	# Trailing zero run
	__compressIPv6_expect "2001:db8:1:2:3:4::" "2001:db8:1:2:3:4:0:0" || FAIL=1

	# All zeros
	__compressIPv6_expect "::" "0:0:0:0:0:0:0:0" || FAIL=1

	# Longest run chosen over shorter one
	__compressIPv6_expect "2001::1:0:0:1" "2001:0:0:0:1:0:0:1" || FAIL=1

	# Tie case: leftmost longest run wins
	# Two runs of length 2: positions 1–2 and 4–5
	# Input: 2001:0:0:1:0:0:1:1 -> expected: 2001::1:0:0:1:1
	__compressIPv6_expect "2001::1:0:0:1:1" "2001:0:0:1:0:0:1:1" || FAIL=1

	if (( FAIL != 0 )); then
		echo "compressIPv6 self-tests: FAILED" >&2
		return 1
	fi

	echo "compressIPv6 self-tests: OK"
	return 0
}

# Only run self-tests when this script is executed directly and explicitly requested.
if [[ "${BASH_SOURCE[0]}" == "${0}" && "${AMNEZIAWG_RUN_IPV6_TESTS:-0}" == "1" ]]; then
	if run_compressIPv6_tests; then
		exit 0
	else
		exit 1
	fi
fi

function isRoot() {
	if [[ "${EUID}" -ne 0 ]]; then
		echo "You need to run this script as root" >&2
		exit 1
	fi
}

function checkVirt() {
	if ! command -v systemd-detect-virt &>/dev/null; then
		return
	fi

	if [[ "$(systemd-detect-virt)" == "openvz" ]]; then
		echo "OpenVZ is not supported" >&2
		exit 1
	fi

	if [[ "$(systemd-detect-virt)" == "lxc" ]]; then
		echo "LXC is not supported (yet)." >&2
		echo "WireGuard can technically run in an LXC container," >&2
		echo "but the kernel module has to be installed on the host," >&2
		echo "the container has to be run with some specific parameters" >&2
		echo "and only the tools need to be installed in the container." >&2
		exit 1
	fi
}

function checkOS() {
	if [[ ! -f /etc/os-release ]] || [[ ! -r /etc/os-release ]]; then
		echo "Cannot detect OS: /etc/os-release is missing or not readable" >&2
		exit 1
	fi
	# shellcheck source=/etc/os-release
	source /etc/os-release
	OS="${ID}"
	if [[ -z "${OS}" ]]; then
		echo "Cannot detect OS: /etc/os-release is missing the ID field" >&2
		exit 1
	fi
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Debian version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		# Extract major version to handle point-release formats (e.g., "11.7")
		local DEBIAN_MAJOR
		DEBIAN_MAJOR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${DEBIAN_MAJOR} =~ ^[0-9]+$ ]] || [[ ${DEBIAN_MAJOR} -lt 11 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later" >&2
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Ubuntu version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		local RELEASE_YEAR
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${RELEASE_YEAR} =~ ^[0-9]+$ ]] || [[ ${RELEASE_YEAR} -lt 22 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 22.04 or later" >&2
			exit 1
		fi
	elif [[ ${OS} == "linuxmint" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Linux Mint version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		# Linux Mint 21.x is based on Ubuntu 22.04; require major version >= 21
		local MINT_MAJOR
		MINT_MAJOR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${MINT_MAJOR} =~ ^[0-9]+$ ]] || [[ ${MINT_MAJOR} -lt 21 ]]; then
			echo "Your version of Linux Mint (${VERSION_ID}) is not supported. Please use Linux Mint 21 or later" >&2
			exit 1
		fi
		OS=ubuntu # treat Linux Mint as Ubuntu for package management
	elif [[ ${OS} == "fedora" ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect Fedora version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		# Extract major version to handle potential future format changes
		local FEDORA_MAJOR
		FEDORA_MAJOR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if ! [[ ${FEDORA_MAJOR} =~ ^[0-9]+$ ]] || [[ ${FEDORA_MAJOR} -lt 39 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 39 or later" >&2
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ -z "${VERSION_ID}" ]]; then
			echo "Cannot detect CentOS/AlmaLinux/Rocky version: VERSION_ID is missing from /etc/os-release" >&2
			exit 1
		fi
		if [[ ${VERSION_ID} == 7* ]] || [[ ${VERSION_ID} == 8* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 9 or later" >&2
			exit 1
		fi
	else
		echo "Looks like you aren't running this installer on a supported system (Debian, Ubuntu, Linux Mint, or CentOS)." >&2
		exit 1
	fi
}

function getTemporarilyDisabledRPMFamilyMessage() {
	echo "Fedora, AlmaLinux, and Rocky Linux support is temporarily disabled because verified AmneziaWG 2.0 packages are not currently available for these RPM-based distributions. Please watch this repository's releases and README for support status updates."
}

function ensureSupportedInstallDistro() {
	# Temporary install block for RPM-family rebuild verification status.
	# Keep OS detection intact so existing installs on these distros can still
	# run non-install operations until AWG 2.0 packages are verified.
	if [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		echo "$(getTemporarilyDisabledRPMFamilyMessage)" >&2
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [[ -z "${CLIENT_NAME}" ]]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written.
	# Use getent passwd for reliable lookup (supports LDAP, custom home paths, etc.),
	# but gracefully handle systems where getent is unavailable or misconfigured.
	local PASSWD_HOME=""
	local RESULT_DIR
	local HAVE_GETENT=false
	if command -v getent &>/dev/null; then
		HAVE_GETENT=true
	fi
	if [[ "${HAVE_GETENT}" == true ]]; then
		PASSWD_HOME=$(getent passwd "${CLIENT_NAME}" 2>/dev/null | cut -d: -f6)
	fi
	if [[ -n "${PASSWD_HOME}" ]] && [[ -d "${PASSWD_HOME}" ]]; then
		RESULT_DIR="${PASSWD_HOME}"
	elif [[ -d "/home/${CLIENT_NAME}" ]]; then
		# Fallback to traditional /home path for the client when getent is unavailable or misconfigured
		RESULT_DIR="/home/${CLIENT_NAME}"
	elif [[ "${CLIENT_NAME}" == "root" ]]; then
		# Explicitly handle root client
		RESULT_DIR="/root"
	elif [[ "${SUDO_USER:-}" ]]; then
		# if not a system user, use SUDO_USER
		local SUDO_HOME=""
		if [[ "${HAVE_GETENT}" == true ]]; then
			SUDO_HOME=$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6)
		fi
		if [[ -n "${SUDO_HOME}" ]] && [[ -d "${SUDO_HOME}" ]]; then
			RESULT_DIR="${SUDO_HOME}"
		elif [[ -d "/home/${SUDO_USER}" ]]; then
			# Fallback to traditional /home path when getent is unavailable or misconfigured
			RESULT_DIR="/home/${SUDO_USER}"
		else
			RESULT_DIR="/root"
		fi
	else
		# if not SUDO_USER, use /root
		RESULT_DIR="/root"
	fi

	echo "${RESULT_DIR}"
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

# Strip the deprecated REMAKE_INITRD directive from the amneziawg DKMS config
# (newer DKMS versions print noisy warnings for it).
function sanitizeAwgDkmsConf() {
	local AWG_DKMS_CONF
	for AWG_DKMS_CONF in /var/lib/dkms/amneziawg/*/source/dkms.conf; do
		[[ -f "${AWG_DKMS_CONF}" ]] && sed -i '/^REMAKE_INITRD=/d' "${AWG_DKMS_CONF}"
	done
}

# Install kernel headers for the running kernel so DKMS can compile the module.
# $1 – kernel version string; defaults to the running kernel (uname -r).
# For APT-based systems the caller must have already activated enable_apt_ipv4.
function installKernelHeaders() {
	local KERNEL_VER="${1:-$(uname -r)}"
	if [[ "${OS}" == 'ubuntu' ]]; then
		local HEADER_INSTALLED=0
		local HEADER_CANDIDATES=("linux-headers-${KERNEL_VER}" "raspberrypi-kernel-headers" "linux-headers-generic")
		local HDR_PKG
		for HDR_PKG in "${HEADER_CANDIDATES[@]}"; do
			if apt-get install -y "${HDR_PKG}"; then
				HEADER_INSTALLED=1
				break
			else
				echo -e "${ORANGE}WARNING: Failed to install kernel headers package '${HDR_PKG}'. Trying next candidate...${NC}"
			fi
		done
		if [[ "${HEADER_INSTALLED}" -ne 1 ]]; then
			echo -e "${ORANGE}WARNING: Failed to install any suitable kernel headers package. DKMS module build may fail; continuing, but the amneziawg kernel module might not be available until headers are installed and the module is rebuilt.${NC}"
		fi
	elif [[ "${OS}" == 'debian' ]]; then
		local HEADER_INSTALLED=0
		local HEADER_CANDIDATES=("linux-headers-${KERNEL_VER}" "raspberrypi-kernel-headers")
		local DEB_ARCH
		DEB_ARCH=$(dpkg --print-architecture 2>/dev/null) && HEADER_CANDIDATES+=("linux-headers-${DEB_ARCH}")
		local HDR_PKG
		for HDR_PKG in "${HEADER_CANDIDATES[@]}"; do
			if apt-get install -y "${HDR_PKG}"; then
				HEADER_INSTALLED=1
				break
			else
				echo -e "${ORANGE}WARNING: Failed to install kernel headers package '${HDR_PKG}'. Trying next candidate...${NC}"
			fi
		done
		if [[ "${HEADER_INSTALLED}" -ne 1 ]]; then
			echo -e "${ORANGE}WARNING: Failed to install any suitable kernel headers package. DKMS module build may fail; continuing, but the amneziawg kernel module might not be available until headers are installed and the module is rebuilt.${NC}"
		fi
	elif [[ "${OS}" == 'fedora' ]] || [[ "${OS}" == 'centos' ]] || [[ "${OS}" == 'almalinux' ]] || [[ "${OS}" == 'rocky' ]]; then
		if ! dnf install -y "kernel-devel-${KERNEL_VER}"; then
			echo -e "${ORANGE}WARNING: Failed to install kernel-devel for the running kernel (${KERNEL_VER}). Attempting to install the latest kernel-devel instead.${NC}"
			if ! dnf install -y kernel-devel; then
				echo -e "${ORANGE}WARNING: Failed to install any kernel-devel package. Continuing without kernel headers; DKMS module builds may fail until headers are installed and the system is rebooted.${NC}"
			fi
		fi
	fi
}

# Start awg-quick@${SERVER_AWG_NIC} when the service is inactive.
# Called after any successful module-load path so the interface is available
# for subsequent awg syncconf calls.  Exits with code 1 on failure.
function ensureAwgQuickRunning() {
	if [[ -n "${SERVER_AWG_NIC:-}" ]] && ! systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
		echo -e "${ORANGE}Starting awg-quick@${SERVER_AWG_NIC} (was not running)...${NC}"
		if ! systemctl start "awg-quick@${SERVER_AWG_NIC}"; then
			echo -e "${RED}ERROR: Failed to start awg-quick@${SERVER_AWG_NIC}.${NC}"
			echo -e "${ORANGE}Check service status with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
			exit 1
		fi
		echo -e "${GREEN}awg-quick@${SERVER_AWG_NIC} started successfully.${NC}"
	fi
}

# Ensure the amneziawg kernel module is built and loaded for the running kernel.
#
# After a kernel upgrade the DKMS module may still be built only for the old
# kernel.  This function detects that situation and automatically:
#   1. Installs the matching kernel headers (if missing)
#   2. Runs dkms autoinstall for the current kernel
#   3. Rebuilds the module dependency cache (depmod -a)
#   4. Loads the module with modprobe
#   5. Starts the awg-quick service if it was not already running
#
# If everything is already fine the function returns immediately (idempotent).
# If repair fails, it prints diagnostic information and exits with code 1.
function ensureAmneziawgKernelModule() {
	local KERNEL_VER
	KERNEL_VER="$(uname -r)"

	# Fast-path: if the module is already loaded, ensure the VPN service is also
	# running before returning.
	if lsmod 2>/dev/null | grep -q '^amneziawg '; then
		ensureAwgQuickRunning
		return 0
	fi

	# If the module is already built for this kernel, try loading it before
	# falling back to the full repair path.
	if [ -n "$(find "/lib/modules/${KERNEL_VER}" -name 'amneziawg.ko*' -print -quit 2>/dev/null)" ]; then
		if modprobe amneziawg 2>/dev/null && lsmod 2>/dev/null | grep -q '^amneziawg '; then
			# Module loaded successfully; start the VPN service if it was not running.
			ensureAwgQuickRunning
			return 0
		fi
	fi

	echo -e "${ORANGE}amneziawg kernel module is not built or loaded for kernel ${KERNEL_VER}.${NC}"
	echo -e "${ORANGE}Attempting automatic repair...${NC}"

	# Install missing kernel headers so DKMS can compile the module.
	# installKernelHeaders() tries candidates in order and warns on failure.
	if [[ "${OS}" == 'ubuntu' ]] || [[ "${OS}" == 'debian' ]]; then
		local HEADERS_PKG="linux-headers-${KERNEL_VER}"
		if ! dpkg-query -W -f='${Status}' "${HEADERS_PKG}" 2>/dev/null | grep -q 'install ok installed'; then
			echo -e "${ORANGE}Kernel headers (${HEADERS_PKG}) are not installed. Installing...${NC}"
			enable_apt_ipv4
			installKernelHeaders "${KERNEL_VER}"
			disable_apt_ipv4
		fi
	elif [[ "${OS}" == 'fedora' ]] || [[ "${OS}" == 'centos' ]] || [[ "${OS}" == 'almalinux' ]] || [[ "${OS}" == 'rocky' ]]; then
		local HEADERS_PKG="kernel-devel-${KERNEL_VER}"
		if ! rpm -q "${HEADERS_PKG}" &>/dev/null; then
			echo -e "${ORANGE}Kernel headers (${HEADERS_PKG}) are not installed. Installing...${NC}"
			enable_apt_ipv4
			installKernelHeaders "${KERNEL_VER}"
			disable_apt_ipv4
		fi
	fi

	# Strip the deprecated REMAKE_INITRD directive to silence newer DKMS warnings
	sanitizeAwgDkmsConf

	# Build the module for the current kernel with DKMS.
	# Even if this step reports failure we still attempt modprobe below: the
	# actual success criterion is whether the .ko ends up loadable, and an
	# earlier partial build can sometimes satisfy that.  modprobe is the
	# definitive check and will produce a clear error if the build truly failed.
	if command -v dkms &>/dev/null; then
		echo -e "${ORANGE}Running: dkms autoinstall -k ${KERNEL_VER}${NC}"
		if ! dkms autoinstall -k "${KERNEL_VER}"; then
			echo -e "${ORANGE}WARNING: dkms autoinstall failed for kernel ${KERNEL_VER}.${NC}"
			local DKMS_LOG
			DKMS_LOG=$(find /var/lib/dkms/amneziawg -name 'make.log' -path "*${KERNEL_VER}*" 2>/dev/null | head -n 1)
			if [[ -n "${DKMS_LOG}" ]]; then
				echo -e "${ORANGE}Last 20 lines of DKMS build log (${DKMS_LOG}):${NC}"
				tail -20 "${DKMS_LOG}"
			else
				echo -e "${ORANGE}Build log not found. Check /var/lib/dkms/amneziawg/ for details.${NC}"
			fi
		fi
	else
		echo -e "${ORANGE}WARNING: dkms is not installed. Cannot rebuild the kernel module.${NC}"
	fi

	# Rebuild the module dependency cache (required for DKMS + compressed modules)
	if command -v depmod &>/dev/null; then
		depmod -a
	fi

	# Attempt to load the module
	if ! modprobe amneziawg; then
		echo -e "${RED}ERROR: amneziawg kernel module could not be loaded for kernel ${KERNEL_VER}.${NC}"
		echo -e "${ORANGE}The module is still not available in /lib/modules/${KERNEL_VER}/${NC}"
		if [[ "${OS}" == 'ubuntu' ]] || [[ "${OS}" == 'debian' ]]; then
			echo -e "${ORANGE}Manual recovery:${NC}"
			echo -e "${ORANGE}  1. apt install -y \"linux-headers-${KERNEL_VER}\"${NC}"
			echo -e "${ORANGE}  2. dkms autoinstall -k \"${KERNEL_VER}\" && depmod -a${NC}"
			echo -e "${ORANGE}  3. modprobe amneziawg${NC}"
			echo -e "${ORANGE}  4. systemctl start \"awg-quick@${SERVER_AWG_NIC:-awg0}\"${NC}"
		elif [[ "${OS}" == 'fedora' ]] || [[ "${OS}" == 'centos' ]] || [[ "${OS}" == 'almalinux' ]] || [[ "${OS}" == 'rocky' ]]; then
			echo -e "${ORANGE}Manual recovery:${NC}"
			echo -e "${ORANGE}  1. dnf install -y \"kernel-devel-${KERNEL_VER}\"${NC}"
			echo -e "${ORANGE}  2. dkms autoinstall -k \"${KERNEL_VER}\" && depmod -a${NC}"
			echo -e "${ORANGE}  3. modprobe amneziawg${NC}"
			echo -e "${ORANGE}  4. systemctl start \"awg-quick@${SERVER_AWG_NIC:-awg0}\"${NC}"
		fi
		exit 1
	fi

	echo -e "${GREEN}amneziawg module loaded successfully for kernel ${KERNEL_VER}.${NC}"

	# The module was just loaded — start the VPN service if it was not running.
	# After a kernel upgrade the service fails at boot because ExecStartPre
	# (modprobe amneziawg) returns an error; now that the module is available
	# we restart it so the awg interface exists for subsequent awg syncconf calls.
	ensureAwgQuickRunning
}

function readJminAndJmax() {
	SERVER_AWG_JMIN=0
	SERVER_AWG_JMAX=0
	until [[ ${SERVER_AWG_JMIN} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMIN} >= 1 )) && (( ${SERVER_AWG_JMIN} <= 1280 )); do
		read -rp "Server AmneziaWG Jmin [1-1280]: " -e -i 50 SERVER_AWG_JMIN
	done
	until [[ ${SERVER_AWG_JMAX} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMAX} >= 1 )) && (( ${SERVER_AWG_JMAX} <= 1280 )); do
		read -rp "Server AmneziaWG Jmax [1-1280]: " -e -i 1000 SERVER_AWG_JMAX
	done
}

function generateS1AndS2() {
	RANDOM_AWG_S1=$(shuf -i15-150 -n1)
	RANDOM_AWG_S2=$(shuf -i15-150 -n1)
}

function readS1AndS2() {
	SERVER_AWG_S1=0
	SERVER_AWG_S2=0
	until [[ ${SERVER_AWG_S1} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S1} >= 15 )) && (( ${SERVER_AWG_S1} <= 150 )); do
		read -rp "Server AmneziaWG S1 [15-150]: " -e -i "${RANDOM_AWG_S1}" SERVER_AWG_S1
	done
	until [[ ${SERVER_AWG_S2} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S2} >= 15 )) && (( ${SERVER_AWG_S2} <= 150 )); do
		read -rp "Server AmneziaWG S2 [15-150]: " -e -i "${RANDOM_AWG_S2}" SERVER_AWG_S2
	done
}

function generateS3AndS4() {
	RANDOM_AWG_S3=$(shuf -i15-150 -n1)
	RANDOM_AWG_S4=$(shuf -i15-150 -n1)
}

function readS3AndS4() {
	SERVER_AWG_S3=0
	SERVER_AWG_S4=0
	until [[ ${SERVER_AWG_S3} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S3} >= 15 )) && (( ${SERVER_AWG_S3} <= 150 )); do
		read -rp "Server AmneziaWG S3 [15-150]: " -e -i "${RANDOM_AWG_S3}" SERVER_AWG_S3
	done
	until [[ ${SERVER_AWG_S4} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S4} >= 15 )) && (( ${SERVER_AWG_S4} <= 150 )); do
		read -rp "Server AmneziaWG S4 [15-150]: " -e -i "${RANDOM_AWG_S4}" SERVER_AWG_S4
	done
}

# Parse a range string "min-max" or single value into MIN and MAX variables
# Uses indirect variable assignment via printf -v to set caller's variables by name
#
# NOTE: This function only validates format and that min <= max. It does NOT
# validate bounds - callers must use validateRange() to check domain-specific
# bounds (e.g., [5-2147483647] for H parameters, [15-150] for S parameters).
function parseRange() {
	local INPUT="$1"  # SECURITY: Must quote to prevent shell injection
	local MIN_VAR_NAME="$2"  # Name of variable to store min value (indirect assignment)
	local MAX_VAR_NAME="$3"  # Name of variable to store max value (indirect assignment)
	
	# Validate input is not empty
	if [[ -z "${INPUT}" ]]; then
		return 1
	fi
	
	if [[ ${INPUT} =~ ^([0-9]+)-([0-9]+)$ ]]; then
		# Force base-10 interpretation to avoid octal issues with leading zeros
		# e.g., "010" would be interpreted as 8 (octal) without 10# prefix
		local MIN=$((10#${BASH_REMATCH[1]}))
		local MAX=$((10#${BASH_REMATCH[2]}))
		
		# Validate that min <= max
		if (( MIN > MAX )); then
			return 1
		fi
		
		# Indirect assignment: sets the variable named by $MIN_VAR_NAME to $MIN
		printf -v "$MIN_VAR_NAME" '%s' "${MIN}"
		printf -v "$MAX_VAR_NAME" '%s' "${MAX}"
	elif [[ ${INPUT} =~ ^[0-9]+$ ]]; then
		# Single value: use as both min and max
		# Force base-10 interpretation here as well
		local VAL=$((10#${INPUT}))
		printf -v "$MIN_VAR_NAME" '%s' "${VAL}"
		printf -v "$MAX_VAR_NAME" '%s' "${VAL}"
	else
		return 1
	fi
	return 0
}

# Check if two ranges overlap
# Returns 0 (true) if ranges overlap, 1 (false) if they don't
#
# Note: This uses STRICT non-overlap detection where ranges must be fully separated.
# Ranges that share a boundary point (e.g., [5-100] and [100-200]) ARE considered
# overlapping because the value 100 could be selected from either range.
# For AmneziaWG header randomization, this ensures each H parameter produces
# values from completely distinct ranges, maximizing entropy and preventing
# any single value from appearing in multiple parameters.
#
# To create non-overlapping ranges, ensure: range1_max < range2_min
# Example: [5-99] and [100-200] do NOT overlap (99 < 100)
function rangesOverlap() {
	local MIN1=$1
	local MAX1=$2
	local MIN2=$3
	local MAX2=$4
	
	# Ranges do NOT overlap if: max1 < min2 OR max2 < min1 (strict inequality)
	# This means [5-100] and [100-200] DO overlap (100 is not < 100)
	if (( MAX1 < MIN2 )) || (( MAX2 < MIN1 )); then
		return 1  # No overlap
	fi
	return 0  # Overlap exists
}

# Validate that a range is valid (min <= max) and within bounds
function validateRange() {
	local MIN=$1
	local MAX=$2
	local LOWER_BOUND=$3
	local UPPER_BOUND=$4
	
	if (( MIN > MAX )); then
		return 1
	fi
	if (( MIN < LOWER_BOUND )) || (( MAX > UPPER_BOUND )); then
		return 1
	fi
	return 0
}

# Generate non-overlapping random ranges for H1-H4
function generateH1AndH2AndH3AndH4Ranges() {
	# Size of each H1-H4 range (1e8). Chosen to provide a large randomization space
	# while staying well below the 32-bit signed int max (2,147,483,647) so that
	# four ranges plus minimum 1-unit gaps between them all fit within [MIN_VAL, MAX_VAL]
	local RANGE_SIZE=100000000
	local MIN_VAL=5
	local MAX_VAL=2147483647
	local GAP=1  # Minimum gap between segments to prevent boundary overlap
	
	# Calculate available range, rounding down to a multiple of 4 to ensure even distribution among 4 segments
	local RAW_AVAILABLE=$((MAX_VAL - MIN_VAL - GAP * 3))
	local AVAILABLE_RANGE=$((RAW_AVAILABLE - RAW_AVAILABLE % 4))
	
	# Generate 4 non-overlapping ranges by dividing the available space into 4 segments
	local SEGMENT_SIZE=$((AVAILABLE_RANGE / 4))
	
	# Validate that segment size is larger than range size
	if (( SEGMENT_SIZE <= RANGE_SIZE )); then
		# Fallback to deterministic fixed non-overlapping ranges when the calculated segment
		# size is too small to randomize positions for all four ranges. This ensures each
		# range has size RANGE_SIZE and is separated by at least GAP units.
		#
		# Note: With current constants (RANGE_SIZE=100M, MAX_VAL=2.1B), four ranges plus gaps
		# total ~400M which fits comfortably. This fallback exists for future-proofing if
		# constants are changed to values that reduce available randomization space.
		#
		# IMPORTANT: Constants must satisfy: MIN_VAL + 4*(RANGE_SIZE - 1) + 3*GAP <= MAX_VAL
		# With current values: 5 + 4*99999999 + 3*1 = 400,000,004 <= 2,147,483,647 (OK)
		RANDOM_AWG_H1_MIN=${MIN_VAL}
		RANDOM_AWG_H1_MAX=$((MIN_VAL + RANGE_SIZE - 1))
		RANDOM_AWG_H2_MIN=$((RANDOM_AWG_H1_MAX + GAP))
		RANDOM_AWG_H2_MAX=$((RANDOM_AWG_H2_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H3_MIN=$((RANDOM_AWG_H2_MAX + GAP))
		RANDOM_AWG_H3_MAX=$((RANDOM_AWG_H3_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H4_MIN=$((RANDOM_AWG_H3_MAX + GAP))
		RANDOM_AWG_H4_MAX=$((RANDOM_AWG_H4_MIN + RANGE_SIZE - 1))
		return
	fi
	
	local RANDOM_OFFSET_MAX=$((SEGMENT_SIZE - RANGE_SIZE))
	
	# H1 range (segment 0)
	local H1_START=$((MIN_VAL + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H1_MIN=${H1_START}
	RANDOM_AWG_H1_MAX=$((H1_START + RANGE_SIZE - 1))
	
	# H2 range (segment 1, with gap after H1's segment)
	local H2_START=$((MIN_VAL + SEGMENT_SIZE + GAP + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H2_MIN=${H2_START}
	RANDOM_AWG_H2_MAX=$((H2_START + RANGE_SIZE - 1))
	
	# H3 range (segment 2, with gap after H2's segment)
	local H3_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 2 + $(shuf -i0-${RANDOM_OFFSET_MAX} -n1)))
	RANDOM_AWG_H3_MIN=${H3_START}
	RANDOM_AWG_H3_MAX=$((H3_START + RANGE_SIZE - 1))
	
	# H4 range (segment 3, with gap after H3's segment)
	local H4_SEGMENT_START=$((MIN_VAL + (SEGMENT_SIZE + GAP) * 3))
	
	# Adjust H4 segment start if necessary so that a full RANGE_SIZE fits before MAX_VAL
	# This prevents the edge case where randomization could produce a truncated range
	local H4_SEGMENT_MAX_START=$((MAX_VAL - RANGE_SIZE + 1))
	if (( H4_SEGMENT_START > H4_SEGMENT_MAX_START )); then
		H4_SEGMENT_START=${H4_SEGMENT_MAX_START}
	fi

	# Recalculate RANDOM_OFFSET_MAX for H4 based on potentially adjusted segment
	local H4_RANDOM_OFFSET_MAX=$((MAX_VAL - H4_SEGMENT_START - RANGE_SIZE + 1))
	if (( H4_RANDOM_OFFSET_MAX < 0 )); then
		H4_RANDOM_OFFSET_MAX=0
	fi
	
	local H4_START=$((H4_SEGMENT_START + $(shuf -i0-${H4_RANDOM_OFFSET_MAX} -n1)))
	
	# H4 range is guaranteed to fit within bounds due to pre-adjusted segment start
	local H4_END=$((H4_START + RANGE_SIZE - 1))
	
	RANDOM_AWG_H4_MIN=${H4_START}
	RANDOM_AWG_H4_MAX=${H4_END}
	
	# Final validation: ensure all four ranges are non-overlapping
	# The segment-based generation above should prevent overlaps, but this serves
	# as a safety net for any edge cases (e.g., arithmetic boundary conditions)
	local HAS_OVERLAP=0
	if rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}" "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H2_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}"; then
		HAS_OVERLAP=1
	fi
	if rangesOverlap "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H3_MAX}" "${RANDOM_AWG_H4_MIN}" "${RANDOM_AWG_H4_MAX}"; then
		HAS_OVERLAP=1
	fi
	
	# If overlaps remain, fall back to deterministic non-overlapping layout
	if (( HAS_OVERLAP )); then
		RANDOM_AWG_H1_MIN=${MIN_VAL}
		RANDOM_AWG_H1_MAX=$((RANDOM_AWG_H1_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H2_MIN=$((RANDOM_AWG_H1_MAX + GAP))
		RANDOM_AWG_H2_MAX=$((RANDOM_AWG_H2_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H3_MIN=$((RANDOM_AWG_H2_MAX + GAP))
		RANDOM_AWG_H3_MAX=$((RANDOM_AWG_H3_MIN + RANGE_SIZE - 1))
		RANDOM_AWG_H4_MIN=$((RANDOM_AWG_H3_MAX + GAP))
		RANDOM_AWG_H4_MAX=$((RANDOM_AWG_H4_MIN + RANGE_SIZE - 1))
	fi
}

# Read an H parameter range from user input with validation
# Uses indirect variable assignment to set SERVER_AWG_${H_NAME}_MIN and _MAX
function readHRange() {
	local H_NAME=$1
	local DEFAULT_MIN=$2
	local DEFAULT_MAX=$3
	# Variable names for indirect assignment via printf -v
	local RESULT_VAR_MIN="SERVER_AWG_${H_NAME}_MIN"
	local RESULT_VAR_MAX="SERVER_AWG_${H_NAME}_MAX"
	
	local INPUT=""
	local VALID=0
	
	until [[ ${VALID} == 1 ]]; do
		read -rp "Server AmneziaWG ${H_NAME} [5-2147483647] (format: min-max or single value): " -e -i "${DEFAULT_MIN}-${DEFAULT_MAX}" INPUT
		
		if parseRange "${INPUT}" "TEMP_MIN" "TEMP_MAX"; then
			if validateRange "${TEMP_MIN}" "${TEMP_MAX}" 5 2147483647; then
				# Indirect assignment: sets global variables by name
				printf -v "$RESULT_VAR_MIN" '%s' "${TEMP_MIN}"
				printf -v "$RESULT_VAR_MAX" '%s' "${TEMP_MAX}"
				VALID=1
			else
				echo -e "${ORANGE}Invalid range. Min must be <= Max and both must be between 5 and 2147483647.${NC}"
			fi
		else
			echo -e "${ORANGE}Invalid format. Use 'min-max' for a range or a single number.${NC}"
		fi
	done
}

function readH1AndH2AndH3AndH4Ranges() {
	# Validate that generateH1AndH2AndH3AndH4Ranges was called first
	# These variables must be set before using them as defaults
	if [[ -z "${RANDOM_AWG_H1_MIN}" ]] || [[ -z "${RANDOM_AWG_H1_MAX}" ]] || \
	   [[ -z "${RANDOM_AWG_H2_MIN}" ]] || [[ -z "${RANDOM_AWG_H2_MAX}" ]] || \
	   [[ -z "${RANDOM_AWG_H3_MIN}" ]] || [[ -z "${RANDOM_AWG_H3_MAX}" ]] || \
	   [[ -z "${RANDOM_AWG_H4_MIN}" ]] || [[ -z "${RANDOM_AWG_H4_MAX}" ]]; then
		echo -e "${RED}ERROR: H1-H4 random ranges not initialized. Call generateH1AndH2AndH3AndH4Ranges first.${NC}"
		exit 1
	fi
	
	local H_NAMES=("H1" "H2" "H3" "H4")
	local RANDOM_MINS=("${RANDOM_AWG_H1_MIN}" "${RANDOM_AWG_H2_MIN}" "${RANDOM_AWG_H3_MIN}" "${RANDOM_AWG_H4_MIN}")
	local RANDOM_MAXS=("${RANDOM_AWG_H1_MAX}" "${RANDOM_AWG_H2_MAX}" "${RANDOM_AWG_H3_MAX}" "${RANDOM_AWG_H4_MAX}")
	
	for i in "${!H_NAMES[@]}"; do
		local H_NAME="${H_NAMES[$i]}"
		local VALID=0
		
		until [[ ${VALID} == 1 ]]; do
			readHRange "${H_NAME}" "${RANDOM_MINS[$i]}" "${RANDOM_MAXS[$i]}"
			VALID=1
			
			# Check for overlap with all previously defined ranges (skip for first range)
			if (( i > 0 )); then
				for (( j = 0; j < i; j++ )); do
					local PREV_H="${H_NAMES[$j]}"
					local PREV_MIN_VAR="SERVER_AWG_${PREV_H}_MIN"
					local PREV_MAX_VAR="SERVER_AWG_${PREV_H}_MAX"
					local CURR_MIN_VAR="SERVER_AWG_${H_NAME}_MIN"
					local CURR_MAX_VAR="SERVER_AWG_${H_NAME}_MAX"
					
					if rangesOverlap "${!PREV_MIN_VAR}" "${!PREV_MAX_VAR}" "${!CURR_MIN_VAR}" "${!CURR_MAX_VAR}"; then
						echo -e "${ORANGE}${H_NAME} range overlaps with ${PREV_H}. Please enter a non-overlapping range.${NC}"
						VALID=0
						break
					fi
				done
			fi
		done
	done
	
	# Set the final SERVER_AWG_H* variables (combined min-max format for config files)
	SERVER_AWG_H1="${SERVER_AWG_H1_MIN}-${SERVER_AWG_H1_MAX}"
	SERVER_AWG_H2="${SERVER_AWG_H2_MIN}-${SERVER_AWG_H2_MAX}"
	SERVER_AWG_H3="${SERVER_AWG_H3_MIN}-${SERVER_AWG_H3_MAX}"
	SERVER_AWG_H4="${SERVER_AWG_H4_MIN}-${SERVER_AWG_H4_MAX}"
}

# Helper function to convert a single H value to range format if needed
# Validates that the value is numeric and within bounds [5-2147483647]
#
# Return codes (non-standard to convey conversion status):
#   0 = CONVERTED:    Conversion was needed and successful
#   1 = NO_CHANGE:    No conversion needed (empty or already valid range format)
#   2 = INVALID:      Validation failed (caller should regenerate the value)
function convertHToRangeIfNeeded() {
	local VAR_NAME=$1
	local VALUE=${!VAR_NAME}
	
	# No conversion needed if empty
	if [[ -z "${VALUE}" ]]; then
		return 1  # NO_CHANGE
	fi
	
	if [[ "${VALUE}" =~ ^[0-9]+-[0-9]+$ ]]; then
		# Already in range format - validate the range
		local RANGE_MIN RANGE_MAX
		if parseRange "${VALUE}" "RANGE_MIN" "RANGE_MAX"; then
			if validateRange "${RANGE_MIN}" "${RANGE_MAX}" 5 2147483647; then
				return 1  # NO_CHANGE (valid range format)
			fi
		fi
		return 2  # INVALID (malformed range)
	fi
	
	# Single value - validate it's numeric and within bounds
	if [[ "${VALUE}" =~ ^[0-9]+$ ]]; then
		# Force base-10 interpretation to avoid octal issues
		local NUM_VALUE=$((10#${VALUE}))
		if (( NUM_VALUE >= 5 )) && (( NUM_VALUE <= 2147483647 )); then
			# Valid single value - convert to range format
			printf -v "$VAR_NAME" '%s' "${NUM_VALUE}-${NUM_VALUE}"
			return 0  # CONVERTED
		fi
	fi
	
	return 2  # INVALID (non-numeric or out of bounds)
}

# Returns 0 (true) when the host has a usable IPv6 stack, 1 otherwise. Used to
# choose a sensible default for IPv6 support so IPv6-disabled hosts don't produce
# client configs with IPv6 addresses/routes that fail to apply (issue #51).
function ipv6Available() {
	[[ -e /proc/net/if_inet6 ]] || return 1
	local disabled
	disabled="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)"
	[[ "${disabled}" == "1" ]] && return 1
	disabled="$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null)"
	[[ "${disabled}" == "1" ]] && return 1
	return 0
}

function trimWhitespace() {
	local VALUE="$1"
	VALUE="${VALUE#"${VALUE%%[![:space:]]*}"}"
	VALUE="${VALUE%"${VALUE##*[![:space:]]}"}"
	printf '%s\n' "${VALUE}"
}

# Echo a comma-separated CIDR list with IPv6 entries removed (IPv4 kept). Keeps
# ::/0 and other IPv6 routes out of client AllowedIPs when IPv6 is disabled, so
# clients without an IPv6 address don't fail adding an IPv6 route (issue #51).
function stripIPv6FromList() {
	local OUT="" ENTRY
	local -a PARTS
	IFS=',' read -ra PARTS <<< "$1"
	for ENTRY in "${PARTS[@]}"; do
		ENTRY="${ENTRY//[[:space:]]/}"
		[[ -z "${ENTRY}" ]] && continue
		[[ "${ENTRY}" == *:* ]] && continue
		if [[ -z "${OUT}" ]]; then OUT="${ENTRY}"; else OUT="${OUT},${ENTRY}"; fi
	done
	echo "${OUT}"
}

function prepareClientAllowedIPs() {
	local RAW_ALLOWED_IPS="$1"
	local IPV6_ENABLED="${2:-${ENABLE_IPV6:-y}}"
	local CLIENT_ALLOWED_IPS="${RAW_ALLOWED_IPS}"

	if [[ "${IPV6_ENABLED}" == "n" ]]; then
		CLIENT_ALLOWED_IPS=$(stripIPv6FromList "${RAW_ALLOWED_IPS}")
	fi
	CLIENT_ALLOWED_IPS=$(formatClientAllowedIPs "${CLIENT_ALLOWED_IPS}")
	[[ -n "${CLIENT_ALLOWED_IPS}" ]] || return 1
	printf '%s\n' "${CLIENT_ALLOWED_IPS}"
}

function serverConfigHasIPv6Address() {
	local CONFIG_PATH="$1"
	local IN_INTERFACE=0 LINE TRIMMED KEY VALUE SECTION

	while IFS= read -r LINE || [[ -n "${LINE}" ]]; do
		TRIMMED=$(trimWhitespace "${LINE}")
		[[ -z "${TRIMMED}" || "${TRIMMED}" == \#* || "${TRIMMED}" == \;* ]] && continue
		if [[ "${TRIMMED}" =~ ^\[(.*)\]$ ]]; then
			SECTION="${BASH_REMATCH[1],,}"
			IN_INTERFACE=0
			[[ "${SECTION}" == "interface" ]] && IN_INTERFACE=1
			continue
		fi
		(( IN_INTERFACE )) || continue
		[[ "${TRIMMED}" == *=* ]] || continue
		KEY=$(trimWhitespace "${TRIMMED%%=*}")
		[[ "${KEY,,}" == "address" ]] || continue
		VALUE=$(trimWhitespace "${TRIMMED#*=}")
		VALUE="${VALUE%%#*}"
		VALUE="${VALUE%%;*}"
		VALUE=$(trimWhitespace "${VALUE}")
		[[ "${VALUE}" == *:* ]] && return 0
	done < "${CONFIG_PATH}"

	return 1
}

function installQuestions() {
	# Non-interactive mode: use environment variable overrides or sensible defaults
	# Set AUTO_INSTALL=y to skip all prompts
	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		# Only auto-detect if the operator did not provide an explicit override.
		# An explicit SERVER_PUB_IP (even if private, e.g. for an internal-only
		# deployment) is honoured as-is.
		if [[ -z "${SERVER_PUB_IP:-}" ]]; then
			SERVER_PUB_IP=$(detectPublicIPv4)
			# If auto-detection only yielded a non-routable IPv4 (external
			# lookup disabled or blocked), prefer a global IPv6 over baking
			# a private address into client configs. Keep the private value
			# as a last-resort fallback so the install does not hard-fail
			# on hosts with neither egress to IP-echo services nor a global
			# IPv6 (e.g. AWG_SKIP_PUBLIC_IP_LOOKUP set on an IPv4-only LAN).
			local AUTO_PRIVATE_IPV4=""
			if [[ -n "${SERVER_PUB_IP}" ]] && isPrivateIPv4 "${SERVER_PUB_IP}"; then
				AUTO_PRIVATE_IPV4="${SERVER_PUB_IP}"
				SERVER_PUB_IP=""
			fi
			if [[ -z "${SERVER_PUB_IP}" ]]; then
				SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
			fi
			if [[ -z "${SERVER_PUB_IP}" && -n "${AUTO_PRIVATE_IPV4}" ]]; then
				echo -e "${ORANGE}WARNING: No public IPv4 or global IPv6 detected; falling back to private IPv4 ${AUTO_PRIVATE_IPV4}. Generated client configs will only work from networks that can reach this address. Set SERVER_PUB_IP to override.${NC}"
				SERVER_PUB_IP="${AUTO_PRIVATE_IPV4}"
			fi
		fi
		if [[ -z "${SERVER_PUB_IP}" ]]; then
			echo -e "${RED}ERROR: Could not detect public IP address. Set SERVER_PUB_IP and rerun.${NC}"
			exit 1
		fi

		SERVER_PUB_NIC=${SERVER_PUB_NIC:-$(ip -4 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}' | head -1)}
		if [[ -z "${SERVER_PUB_NIC}" ]]; then
			SERVER_PUB_NIC=$(ip -6 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}' | head -1)
		fi
		if [[ -z "${SERVER_PUB_NIC}" ]]; then
			echo -e "${RED}ERROR: Could not detect public interface. Set SERVER_PUB_NIC and rerun.${NC}"
			exit 1
		fi

		SERVER_AWG_NIC=${SERVER_AWG_NIC:-awg0}
		SERVER_AWG_IPV4=${SERVER_AWG_IPV4:-10.66.66.1}
		SERVER_AWG_IPV6=${SERVER_AWG_IPV6:-fd42:42:42::1}
		SERVER_PORT=${SERVER_PORT:-$(shuf -i49152-65535 -n1)}
		CLIENT_DNS_1=${CLIENT_DNS_1:-1.1.1.1}
		# Use ${var-default} (not ${var:-default}) so an explicitly empty CLIENT_DNS_2
		# is honored (skip second resolver), matching the interactive flow.
		CLIENT_DNS_2=${CLIENT_DNS_2-1.0.0.1}
		# Default IPv6 support from the host's capability unless explicitly set via
		# the ENABLE_IPV6 env var. IPv4-only deployments avoid emitting IPv6
		# addresses/routes that fail to apply on IPv6-disabled systems (issue #51).
		if [[ -z "${ENABLE_IPV6:-}" ]]; then
			if ipv6Available; then ENABLE_IPV6=y; else ENABLE_IPV6=n; fi
		fi
		ENABLE_IPV6="${ENABLE_IPV6,,}"
		if [[ "${ENABLE_IPV6}" != "y" && "${ENABLE_IPV6}" != "n" ]]; then
			echo -e "${RED}ERROR: ENABLE_IPV6 must be 'y' or 'n': ${ENABLE_IPV6}${NC}"
			exit 1
		fi
		if [[ "${ENABLE_IPV6}" == "y" ]]; then
			ALLOWED_IPS=${ALLOWED_IPS:-0.0.0.0/0, ::/0}
		else
			ALLOWED_IPS=${ALLOWED_IPS:-0.0.0.0/0}
		fi
		local RAW_ALLOWED_IPS="${ALLOWED_IPS}"
		if ! ALLOWED_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${ENABLE_IPV6}"); then
			echo -e "${RED}ERROR: ALLOWED_IPS has no usable routes after applying ENABLE_IPV6=${ENABLE_IPV6}: ${RAW_ALLOWED_IPS}${NC}"
			exit 1
		fi

		# Validate all overrides with the same checks used in the interactive flow.
		# These values end up in iptables rules, systemd unit paths, and config files,
		# so unsafe characters (shell metacharacters, path separators, whitespace)
		# could enable command injection or path traversal.
		if ! [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_.-]+$ ]]; then
			echo -e "${RED}ERROR: SERVER_PUB_NIC contains invalid characters: ${SERVER_PUB_NIC}${NC}"
			exit 1
		fi
		if ! [[ ${SERVER_AWG_NIC} =~ ^[a-zA-Z0-9_.-]+$ ]] || [[ ${#SERVER_AWG_NIC} -ge 16 ]]; then
			echo -e "${RED}ERROR: SERVER_AWG_NIC is invalid (must be alphanumeric/._- and < 16 chars): ${SERVER_AWG_NIC}${NC}"
			exit 1
		fi
		if ! [[ ${SERVER_AWG_IPV4} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			echo -e "${RED}ERROR: SERVER_AWG_IPV4 is not a valid IPv4 address: ${SERVER_AWG_IPV4}${NC}"
			exit 1
		fi
		if ! isValidIPv6 "${SERVER_AWG_IPV6}"; then
			echo -e "${RED}ERROR: Invalid IPv6 address specified in SERVER_AWG_IPV6: ${SERVER_AWG_IPV6}.${NC}"
			exit 1
		fi
		if ! [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] || (( SERVER_PORT < 1 )) || (( SERVER_PORT > 65535 )); then
			echo -e "${RED}ERROR: SERVER_PORT must be a number between 1 and 65535: ${SERVER_PORT}${NC}"
			exit 1
		fi
		if ! [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			echo -e "${RED}ERROR: CLIENT_DNS_1 is not a valid IPv4 address: ${CLIENT_DNS_1}${NC}"
			exit 1
		fi
		if [[ -n "${CLIENT_DNS_2}" ]] && ! [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			echo -e "${RED}ERROR: CLIENT_DNS_2 is not a valid IPv4 address: ${CLIENT_DNS_2}${NC}"
			exit 1
		fi

		SERVER_AWG_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")

		SERVER_AWG_JC=$(shuf -i3-10 -n1)
		SERVER_AWG_JMIN=50
		SERVER_AWG_JMAX=1000

		generateS1AndS2
		while (( RANDOM_AWG_S1 + 56 == RANDOM_AWG_S2 )) || (( RANDOM_AWG_S2 + 56 == RANDOM_AWG_S1 )); do
			generateS1AndS2
		done
		SERVER_AWG_S1=${RANDOM_AWG_S1}
		SERVER_AWG_S2=${RANDOM_AWG_S2}

		generateS3AndS4
		while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); do
			generateS3AndS4
		done
		SERVER_AWG_S3=${RANDOM_AWG_S3}
		SERVER_AWG_S4=${RANDOM_AWG_S4}

		generateH1AndH2AndH3AndH4Ranges
		SERVER_AWG_H1="${RANDOM_AWG_H1_MIN}-${RANDOM_AWG_H1_MAX}"
		SERVER_AWG_H2="${RANDOM_AWG_H2_MIN}-${RANDOM_AWG_H2_MAX}"
		SERVER_AWG_H3="${RANDOM_AWG_H3_MIN}-${RANDOM_AWG_H3_MAX}"
		SERVER_AWG_H4="${RANDOM_AWG_H4_MIN}-${RANDOM_AWG_H4_MAX}"

		return
	fi

	# Reset all interactive variables to prevent pre-set environment variables
	# from bypassing prompt validation loops
	SERVER_PUB_IP=""
	SERVER_PUB_NIC=""
	SERVER_AWG_NIC=""
	SERVER_AWG_IPV4=""
	SERVER_AWG_IPV6=""
	SERVER_PORT=""
	CLIENT_DNS_1=""
	CLIENT_DNS_2=""
	ALLOWED_IPS=""
	SERVER_AWG_JC=""
	SERVER_AWG_JMIN=""
	SERVER_AWG_JMAX=""
	SERVER_AWG_S1=""
	SERVER_AWG_S2=""
	SERVER_AWG_S3=""
	SERVER_AWG_S4=""

	echo "AmneziaWG server installer (https://github.com/wiresock/amneziawg-install)"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(detectPublicIPv4)
	if [[ -z "${SERVER_PUB_IP}" ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "Public IPv4 or IPv6 address or domain: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	# Extract the token after 'dev' to handle both 'default via ... dev <if>'
	# and 'default dev <if>' (no gateway) route formats
	SERVER_NIC="$(ip -4 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}' | head -1)"
	if [[ -z "${SERVER_NIC}" ]]; then
		# Fallback to IPv6 default route for IPv6-only servers
		SERVER_NIC="$(ip -6 route ls | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); exit}}' | head -1)"
	fi
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_.-]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_AWG_NIC} =~ ^[a-zA-Z0-9_.-]+$ && ${#SERVER_AWG_NIC} -lt 16 ]]; do
		read -rp "AmneziaWG interface name: " -e -i awg0 SERVER_AWG_NIC
	done

	until [[ ${SERVER_AWG_IPV4} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Server AmneziaWG IPv4: " -e -i 10.66.66.1 SERVER_AWG_IPV4
	done

	# Ask whether to enable IPv6. The default reflects the host's IPv6 capability
	# so IPv6-disabled systems don't generate broken client configs (issue #51).
	if ipv6Available; then ENABLE_IPV6_DEFAULT="y"; else ENABLE_IPV6_DEFAULT="n"; fi
	ENABLE_IPV6=""
	until [[ "${ENABLE_IPV6,,}" =~ ^(y|n)$ ]]; do
		read -rp "Enable IPv6 support (tunnel + NAT)? [y/n]: " -e -i "${ENABLE_IPV6_DEFAULT}" ENABLE_IPV6
	done
	ENABLE_IPV6="${ENABLE_IPV6,,}"

	if [[ "${ENABLE_IPV6}" == "y" ]]; then
		until isValidIPv6 "${SERVER_AWG_IPV6}"; do
			read -rp "Server AmneziaWG IPv6: " -e -i fd42:42:42::1 SERVER_AWG_IPV6
		done
		# Normalize to expanded form for consistent storage and comparison
		SERVER_AWG_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
	else
		# Keep a valid placeholder for params storage and client IP derivation;
		# it is never written to the server or client configs when IPv6 is off.
		SERVER_AWG_IPV6=$(normalizeIPv6 "fd42:42:42::1")
	fi

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [[ "${SERVER_PORT}" -ge 1 ]] && [[ "${SERVER_PORT}" -le 65535 ]]; do
		read -rp "Server AmneziaWG port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Adguard DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	while true; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		# Accept empty input (skip second DNS) or a valid IPv4 address
		if [[ -z "${CLIENT_DNS_2}" ]] || [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
			break
		fi
		echo -e "${ORANGE}Invalid IPv4 address. Enter a valid address or leave empty to skip.${NC}"
	done

	if [[ "${ENABLE_IPV6}" == "y" ]]; then ALLOWED_IPS_DEFAULT='0.0.0.0/0, ::/0'; else ALLOWED_IPS_DEFAULT='0.0.0.0/0'; fi
	while true; do
		echo -e "\nAmneziaWG uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i "${ALLOWED_IPS_DEFAULT}" ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="${ALLOWED_IPS_DEFAULT}"
		fi
		if ALLOWED_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${ENABLE_IPV6}"); then
			break
		fi
		echo -e "${ORANGE}AllowedIPs must contain at least one route usable with ENABLE_IPV6=${ENABLE_IPV6}.${NC}"
	done

	# Jc
	RANDOM_AWG_JC=$(shuf -i3-10 -n1)
	until [[ ${SERVER_AWG_JC} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JC} >= 1 )) && (( ${SERVER_AWG_JC} <= 128 )); do
		read -rp "Server AmneziaWG Jc [1-128]: " -e -i "${RANDOM_AWG_JC}" SERVER_AWG_JC
	done

	# Jmin && Jmax
	# Note: Jmin == Jmax is valid - it results in fixed-size junk packets rather than
	# randomized sizes within a range. The protocol accepts Jmin <= Jmax.
	readJminAndJmax
	until [[ "${SERVER_AWG_JMIN}" -le "${SERVER_AWG_JMAX}" ]]; do
		echo "Jmin must be less than or equal to Jmax"
		readJminAndJmax
	done

	# S1 && S2
	# Note: The constraints S1 + 56 != S2 and S2 + 56 != S1 are required by the AmneziaWG
	# protocol to ensure proper packet obfuscation. The value 56 is the WireGuard handshake
	# initiation message size, and this offset must be avoided in both directions.
	generateS1AndS2
	while (( ${RANDOM_AWG_S1} + 56 == ${RANDOM_AWG_S2} )) || (( ${RANDOM_AWG_S2} + 56 == ${RANDOM_AWG_S1} )); do
		generateS1AndS2
	done
	readS1AndS2
	while (( ${SERVER_AWG_S1} + 56 == ${SERVER_AWG_S2} )) || (( ${SERVER_AWG_S2} + 56 == ${SERVER_AWG_S1} )); do
		echo "AmneziaWG requires S1 + 56 != S2 and S2 + 56 != S1"
		readS1AndS2
	done

	# S3 && S4 (AmneziaWG 2.0)
	# Note: Same constraint as S1/S2 - the 56-byte offset must be avoided in both directions
	echo -e "\n${GREEN}AmneziaWG 2.0 Features:${NC}"
	generateS3AndS4
	while (( ${RANDOM_AWG_S3} + 56 == ${RANDOM_AWG_S4} )) || (( ${RANDOM_AWG_S4} + 56 == ${RANDOM_AWG_S3} )); do
		generateS3AndS4
	done
	readS3AndS4
	while (( ${SERVER_AWG_S3} + 56 == ${SERVER_AWG_S4} )) || (( ${SERVER_AWG_S4} + 56 == ${SERVER_AWG_S3} )); do
		echo "AmneziaWG requires S3 + 56 != S4 and S4 + 56 != S3"
		readS3AndS4
	done

	# H1-H4 Ranged Headers (AmneziaWG 2.0)
	echo -e "\n${GREEN}H1-H4 Ranged Headers (ranges must not overlap):${NC}"
	generateH1AndH2AndH3AndH4Ranges
	readH1AndH2AndH3AndH4Ranges

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your AmneziaWG server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

# Emit the server's PostUp/PostDown firewall rules on stdout.
#
# The backend is chosen in priority order:
#   1. firewalld - when the firewalld service is active.
#   2. nftables  - when the nft binary is available and iptables is either absent
#                  or backed by nf_tables (the default on modern Debian/Ubuntu/
#                  Fedora). Emitting native nft rules avoids the iptables-nft
#                  compatibility layer, which on these systems either inserts the
#                  rules into a backend the kernel does not enforce (so NAT/forward
#                  silently breaks) or aborts awg-quick when the legacy ip6_tables
#                  module is unavailable. See issue #79.
#   3. iptables  - legacy fallback for systems without nft.
#
# Reads the SERVER_* globals populated by installQuestions(). The brace blocks in
# the nft chain definitions are single-quoted so awg-quick's `eval` of each hook
# passes them to nft intact instead of treating { ; } as shell syntax.
function ufwIsActive() {
	local UFW_CONF="${UFW_CONF_PATH:-/etc/ufw/ufw.conf}"
	local UFW_STATUS=""

	if command -v ufw >/dev/null 2>&1; then
		UFW_STATUS="$(ufw status 2>/dev/null || true)"
		if printf '%s\n' "${UFW_STATUS}" | grep -qiE '^Status:[[:space:]]+active'; then
			return 0
		fi
		if printf '%s\n' "${UFW_STATUS}" | grep -qiE '^Status:[[:space:]]+inactive'; then
			return 1
		fi
	fi
	grep -qiE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes' "${UFW_CONF}" 2>/dev/null
}

function writeFirewallRules() {
	if systemctl is-active --quiet firewalld 2>/dev/null; then
		local FIREWALLD_IPV4_ADDRESS FIREWALLD_IPV6_ADDRESS FW_PU_V6="" FW_PD_V6=""
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_AWG_IPV4}" | cut -d"." -f1-3)".0"
		if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
			# Derive /64 network address from the normalized IPv6 (first 4 groups + :0:0:0:0)
			FIREWALLD_IPV6_ADDRESS="$(echo "${SERVER_AWG_IPV6}" | cut -d':' -f1-4):0:0:0:0"
			FW_PU_V6=" && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'"
			FW_PD_V6=" && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'"
		fi
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'${FW_PU_V6}
PostUp = firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv4 filter FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = firewall-cmd --direct --add-rule ipv4 mangle FORWARD 0 -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'${FW_PD_V6}
PostDown = firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv4 filter FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = firewall-cmd --direct --remove-rule ipv4 mangle FORWARD 0 -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
			echo "PostUp = firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv6 filter FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = firewall-cmd --direct --add-rule ipv6 mangle FORWARD 0 -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv6 filter FORWARD 1 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = firewall-cmd --direct --remove-rule ipv6 mangle FORWARD 0 -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		fi
	elif ufwIsActive && command -v iptables >/dev/null 2>&1; then
		# UFW installs default-drop rules in its own filtering path. Native nft
		# accept rules in a separate base chain cannot reliably override those
		# drops, so use iptables-compatible insertion when UFW is active. This
		# inserts before UFW's final drop while keeping NAT scoped to VPN clients.
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -I FORWARD 2 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = iptables -t mangle -A FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -t mangle -D FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		if [[ "${ENABLE_IPV6:-y}" == "y" ]] && command -v ip6tables >/dev/null 2>&1; then
			echo "PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = ip6tables -I FORWARD 2 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -t mangle -A FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -t mangle -D FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		elif [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
			echo -e "${ORANGE}WARNING: ENABLE_IPV6=y but ip6tables is unavailable; UFW IPv6 firewall rules will not be generated.${NC}" >&2
		fi
	elif command -v nft >/dev/null 2>&1 && { ! command -v iptables >/dev/null 2>&1 || iptables --version 2>/dev/null | grep -qi 'nf_tables'; }; then
		# In dual-stack mode a single inet table covers both IPv4 and IPv6; in
		# IPv4-only mode an ip table avoids opening/forwarding IPv6 at all.
		# PostDown drops the whole table atomically, so no per-rule deletion (and
		# no ordering fragility) is required.
		# The MSS-clamp rule is scoped to 'oifname <awg>' so it only touches traffic
		# entering the tunnel (notably the return-path SYN-ACK) and leaves any other
		# forwarding the host does alone. It must precede the accept rules: it carries
		# no verdict so the packet falls through to them, but an accept would otherwise
		# terminate the chain before the clamp runs. 'tcp flags & (syn|rst) == syn'
		# matches SYN and SYN-ACK (the segments carrying the MSS option); the &/(|)
		# tokens are single-quoted so awg-quick's eval passes them to nft intact.
		local NFT_TABLE="awg-${SERVER_AWG_NIC}" NFT_FAMILY="inet"
		[[ "${ENABLE_IPV6:-y}" == "n" ]] && NFT_FAMILY="ip"
		echo "PostUp = nft add table ${NFT_FAMILY} ${NFT_TABLE}
PostUp = nft add chain ${NFT_FAMILY} ${NFT_TABLE} input '{ type filter hook input priority 0 ; policy accept ; }'
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} input udp dport ${SERVER_PORT} accept
PostUp = nft add chain ${NFT_FAMILY} ${NFT_TABLE} forward '{ type filter hook forward priority 0 ; policy accept ; }'
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} forward oifname ${SERVER_AWG_NIC} tcp flags '&' '(syn|rst)' == syn tcp option maxseg size set rt mtu
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} forward iifname ${SERVER_AWG_NIC} accept
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} forward iifname ${SERVER_PUB_NIC} oifname ${SERVER_AWG_NIC} ct state related,established accept
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} forward iifname ${SERVER_PUB_NIC} oifname ${SERVER_AWG_NIC} drop
PostUp = nft add chain ${NFT_FAMILY} ${NFT_TABLE} postrouting '{ type nat hook postrouting priority 100 ; policy accept ; }'
PostUp = nft add rule ${NFT_FAMILY} ${NFT_TABLE} postrouting oifname ${SERVER_PUB_NIC} masquerade
PostDown = nft delete table ${NFT_FAMILY} ${NFT_TABLE}"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -I FORWARD 2 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = iptables -t mangle -A FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -t mangle -D FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		# Emit the ip6tables rules only when IPv6 is enabled and ip6tables is
		# available; otherwise these commands would abort awg-quick.
		if [[ "${ENABLE_IPV6:-y}" == "y" ]] && command -v ip6tables >/dev/null 2>&1; then
			echo "PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = ip6tables -I FORWARD 2 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -t mangle -A FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j DROP
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -t mangle -D FORWARD -o ${SERVER_AWG_NIC} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		elif [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
			echo -e "${ORANGE}WARNING: ENABLE_IPV6=y but ip6tables is unavailable; legacy IPv6 firewall rules will not be generated.${NC}" >&2
		fi
	fi
}

function shouldCreateInitialClient() {
	local CREATE_CLIENT="${CREATE_INITIAL_CLIENT:-}"
	CREATE_CLIENT=$(trimWhitespace "${CREATE_CLIENT}")

	case "${CREATE_CLIENT,,}" in
	y|yes|true|1)
		return 0
		;;
	n|no|false|0)
		return 1
		;;
	esac

	if [[ -n "${CREATE_CLIENT}" ]]; then
		echo -e "${RED}ERROR: CREATE_INITIAL_CLIENT must be y/n, yes/no, true/false, or 1/0: ${CREATE_CLIENT}${NC}"
		if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
			exit 1
		fi
	fi

	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		return 0
	fi

	while true; do
		read -rp "Create an initial client configuration now? [Y/n]: " CREATE_CLIENT
		CREATE_CLIENT=${CREATE_CLIENT:-y}
		case "${CREATE_CLIENT,,}" in
		y|yes)
			return 0
			;;
		n|no)
			return 1
			;;
		*)
			echo -e "${ORANGE}Please answer yes or no.${NC}"
			;;
		esac
	done
}

function formatClientAllowedIPs() {
	local OUT="" ENTRY
	local -a PARTS
	IFS=',' read -ra PARTS <<< "$1"
	for ENTRY in "${PARTS[@]}"; do
		ENTRY="${ENTRY#"${ENTRY%%[![:space:]]*}"}"
		ENTRY="${ENTRY%"${ENTRY##*[![:space:]]}"}"
		[[ -z "${ENTRY}" ]] && continue
		if [[ -z "${OUT}" ]]; then OUT="${ENTRY}"; else OUT="${OUT}, ${ENTRY}"; fi
	done
	printf '%s\n' "${OUT}"
}

function installAmneziaWG() {
	ensureSupportedInstallDistro

	# Run setup questions first
	installQuestions

	# Install AmneziaWG tools and module
	# Force IPv4 preference for all package-manager operations — IPv6 may be
	# resolvable but unreachable on some VPS providers, causing apt, dnf,
	# add-apt-repository, and COPR API calls to hang.
	enable_apt_ipv4
	if [[ ${OS} == 'ubuntu' ]]; then
		if [[ -e /etc/apt/sources.list.d/ubuntu.sources ]]; then
			# Check whether any Types: line lacks deb-src. A single stanza with
			# deb-src shouldn't suppress source entries for other binary-only stanzas.
			if grep -q '^Types:' /etc/apt/sources.list.d/ubuntu.sources && \
			   grep '^Types:' /etc/apt/sources.list.d/ubuntu.sources | grep -qv 'deb-src'; then
				# Tag managed file with sentinel so uninstall can verify ownership
				echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources
				cat /etc/apt/sources.list.d/ubuntu.sources >> /etc/apt/sources.list.d/amneziawg.sources
				# Rewrite every Types field in the DEB822 copy to deb-src.
				# The guard above ensures at least one stanza is binary-only,
				# and transforming all stanzas to deb-src is harmless (apt deduplicates).
				sed -i 's/^Types: .*/Types: deb-src/' /etc/apt/sources.list.d/amneziawg.sources
				chmod 644 /etc/apt/sources.list.d/amneziawg.sources
			elif ! grep -q '^Types:' /etc/apt/sources.list.d/ubuntu.sources; then
				echo -e "${ORANGE}NOTE: /etc/apt/sources.list.d/ubuntu.sources has no Types: lines (unexpected format).${NC}"
				echo -e "${ORANGE}Skipping deb-src source generation. DKMS builds may fail if source repos are unavailable.${NC}"
			fi
		else
			if ! grep -q "^deb-src" /etc/apt/sources.list; then
				# Tag managed file with sentinel so uninstall can verify ownership
				echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources.list
				cat /etc/apt/sources.list >> /etc/apt/sources.list.d/amneziawg.sources.list
				# Anchor to line-start 'deb' followed by whitespace to avoid matching deb-src lines
				sed -i 's/^deb[[:space:]]\+/deb-src /' /etc/apt/sources.list.d/amneziawg.sources.list
				chmod 644 /etc/apt/sources.list.d/amneziawg.sources.list
			fi
		fi
		# Repair a PPA entry left by an older interrupted install before the
		# initial update; otherwise a stale unsupported suite breaks the rerun.
		local EXISTING_PPA_RC
		if amneziaPpaSourceEntriesExist "${AMNEZIA_PPA_SOURCES_DIR}"; then
			EXISTING_PPA_RC=0
		else
			EXISTING_PPA_RC=$?
		fi
		if [[ "${EXISTING_PPA_RC}" -eq 0 ]]; then
			configureUbuntuAmneziaPpa "" "${AMNEZIA_PPA_SOURCES_DIR}" || exit 1
		elif [[ "${EXISTING_PPA_RC}" -ne 1 ]]; then
			exit 1
		fi

		apt-get update || { echo -e "${RED}ERROR: Failed to refresh APT package index.${NC}"; exit 1; }
		apt install -y software-properties-common curl || { echo -e "${RED}ERROR: Failed to install software-properties-common and curl.${NC}"; exit 1; }
		configureUbuntuAmneziaPpa "" "${AMNEZIA_PPA_SOURCES_DIR}" || exit 1
		if ! apt-get -o APT::Update::Error-Mode=any update; then
			local PPA_CLEANUP_RC
			if cleanupNewlyCreatedUbuntuAmneziaPpa "${AMNEZIA_PPA_SOURCES_DIR}"; then
				PPA_CLEANUP_RC=0
			else
				PPA_CLEANUP_RC=$?
			fi
			case "${PPA_CLEANUP_RC}" in
				0)
					echo -e "${RED}ERROR: Failed to update APT package indexes after configuring the Amnezia PPA. The newly created PPA source was removed so future APT operations remain usable.${NC}"
					;;
				1)
					echo -e "${RED}ERROR: Failed to update APT package indexes after configuring the Amnezia PPA, and the newly created source could not be removed safely. Review ${AMNEZIA_PPA_SOURCES_DIR}.${NC}"
					;;
				2)
					echo -e "${RED}ERROR: Failed to update APT package indexes after reconciling the pre-existing Amnezia PPA source. The administrator-owned source was left in place.${NC}"
					;;
			esac
			exit 1
		fi
		# Install kernel headers for the running kernel so DKMS can compile the module.
		installKernelHeaders "$(uname -r)"
		apt install -y dkms iptables nftables amneziawg amneziawg-tools qrencode || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -q "^deb-src" /etc/apt/sources.list; then
			# Tag managed file with sentinel so uninstall can verify ownership
			echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources.list
			cat /etc/apt/sources.list >> /etc/apt/sources.list.d/amneziawg.sources.list
			# Convert deb lines to deb-src, tolerating any whitespace while skipping existing deb-src lines
			sed -i -E '/^[[:space:]]*deb-src[[:space:]]/!s/^[[:space:]]*deb[[:space:]]+/deb-src /' /etc/apt/sources.list.d/amneziawg.sources.list
			chmod 644 /etc/apt/sources.list.d/amneziawg.sources.list
		fi
		# Ensure required tools are available for key download/dearmor on minimal systems
		if ! command -v gpg &>/dev/null; then
			apt-get update
			apt-get install -y gnupg || { echo -e "${RED}ERROR: Failed to install gnupg required for key import.${NC}"; exit 1; }
		fi
		if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
			apt-get update
			apt-get install -y curl || { echo -e "${RED}ERROR: Failed to install curl required for key download.${NC}"; exit 1; }
		fi
		mkdir -p /etc/apt/keyrings
		chmod 755 /etc/apt/keyrings
		# Full 40-character fingerprint of the AmneziaWG APT signing key.
		# Short key IDs (e.g., 0x57290828) are collision-prone; always fetch and
		# verify by full fingerprint to prevent keyserver substitution attacks.
		local AMNEZIAWG_APT_FPR="75C9DD72C799870E310542E24166F2C257290828"
		local KEY_URL="https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${AMNEZIAWG_APT_FPR}"
		local TMP_KEY_ASC
		TMP_KEY_ASC=$(mktemp /tmp/amneziawg-apt-key.XXXXXX) || { echo -e "${RED}ERROR: Failed to create temporary file for APT signing key.${NC}"; exit 1; }
		local KEY_FETCH_OK=0
		# Use -4 to avoid IPv6 timeouts on VPS providers where AAAA records
		# resolve but outbound IPv6 connectivity to keyservers is broken.
		if command -v curl &>/dev/null; then
			curl -4 -fsSL "${KEY_URL}" -o "${TMP_KEY_ASC}" && KEY_FETCH_OK=1
		elif command -v wget &>/dev/null; then
			wget -4 -qO "${TMP_KEY_ASC}" "${KEY_URL}" && KEY_FETCH_OK=1
		fi
		if [[ ${KEY_FETCH_OK} -ne 1 ]] || [[ ! -s "${TMP_KEY_ASC}" ]]; then
			rm -f "${TMP_KEY_ASC}"
			echo -e "${RED}ERROR: Failed to download the AmneziaWG APT signing key.${NC}"
			echo -e "${ORANGE}Verify network connectivity and that curl/wget and gnupg are installed.${NC}"
			exit 1
		fi
		# Verify the downloaded key's fingerprint matches before importing.
		# This prevents importing a substituted key from a compromised keyserver.
		local DOWNLOADED_FPR
		DOWNLOADED_FPR=$(gpg --show-keys --with-colons "${TMP_KEY_ASC}" 2>/dev/null | awk -F: '/^fpr:/ { print $10; exit }')
		if [[ -z "${DOWNLOADED_FPR}" ]]; then
			rm -f "${TMP_KEY_ASC}"
			echo -e "${RED}ERROR: Unable to read fingerprint from downloaded AmneziaWG APT signing key.${NC}"
			exit 1
		fi
		if [[ "${DOWNLOADED_FPR^^}" != "${AMNEZIAWG_APT_FPR^^}" ]]; then
			rm -f "${TMP_KEY_ASC}"
			echo -e "${RED}ERROR: Downloaded key fingerprint (${DOWNLOADED_FPR}) does not match expected (${AMNEZIAWG_APT_FPR}).${NC}"
			echo -e "${ORANGE}The key may have been tampered with. Aborting.${NC}"
			exit 1
		fi
		# Fingerprint verified — import the key into the dedicated keyring
		local TMP_KEYRING
		TMP_KEYRING=$(mktemp /etc/apt/keyrings/amneziawg.gpg.tmp.XXXXXX) || {
			rm -f "${TMP_KEY_ASC}"
			echo -e "${RED}ERROR: Failed to create temporary file for AmneziaWG APT signing keyring.${NC}"
			exit 1
		}
		if ! gpg --dearmor < "${TMP_KEY_ASC}" > "${TMP_KEYRING}" 2>/dev/null; then
			rm -f "${TMP_KEY_ASC}" "${TMP_KEYRING}"
			echo -e "${RED}ERROR: Failed to import the AmneziaWG APT signing key into keyring.${NC}"
			exit 1
		fi
		rm -f "${TMP_KEY_ASC}"
		if [[ ! -s "${TMP_KEYRING}" ]]; then
			rm -f "${TMP_KEYRING}"
			echo -e "${RED}ERROR: AmneziaWG APT keyring file is empty after import.${NC}"
			exit 1
		fi
		chmod 644 "${TMP_KEYRING}"
		mv "${TMP_KEYRING}" /etc/apt/keyrings/amneziawg.gpg
		if [[ ! -s /etc/apt/keyrings/amneziawg.gpg ]]; then
			echo -e "${RED}ERROR: AmneziaWG APT keyring file is empty after import.${NC}"
			exit 1
		fi
		# Ensure the managed file exists with sentinel before appending PPA lines.
		# When /etc/apt/sources.list already has deb-src, the copy block above is
		# skipped and the file doesn't exist yet — without this guard the >> below
		# would create it without the sentinel, causing uninstall to leave it behind.
		if [[ ! -f /etc/apt/sources.list.d/amneziawg.sources.list ]]; then
			echo "# Managed by amneziawg-install" > /etc/apt/sources.list.d/amneziawg.sources.list
			chmod 644 /etc/apt/sources.list.d/amneziawg.sources.list
		fi
		# Append PPA repo lines only if not already present (idempotent on re-run)
		if ! grep -q 'ppa.launchpadcontent.net/amnezia/ppa' /etc/apt/sources.list.d/amneziawg.sources.list; then
			echo "deb [signed-by=/etc/apt/keyrings/amneziawg.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
			echo "deb-src [signed-by=/etc/apt/keyrings/amneziawg.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		fi
		apt-get update || { echo -e "${RED}ERROR: Failed to update package index.${NC}"; exit 1; }
		# Install kernel headers for the running kernel so DKMS can compile the module.
		installKernelHeaders "$(uname -r)"
		apt-get install -y dkms amneziawg amneziawg-tools qrencode iptables nftables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'fedora' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		# Install kernel headers for the running kernel so DKMS can compile the module.
		installKernelHeaders "$(uname -r)"
		dnf install -y dkms amneziawg-dkms amneziawg-tools qrencode iptables nftables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	elif [[ ${OS} == 'centos' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		# Install kernel headers for the running kernel so DKMS can compile the module.
		installKernelHeaders "$(uname -r)"
		dnf install -y dkms amneziawg-dkms amneziawg-tools qrencode iptables nftables || { echo -e "${RED}ERROR: Package installation failed. Check your internet connection and try again.${NC}"; exit 1; }
	fi
	disable_apt_ipv4

	# Strip the deprecated REMAKE_INITRD directive from the amneziawg DKMS config.
	sanitizeAwgDkmsConf

	# Force DKMS to build the module for the running kernel only.
	# Using "dkms autoinstall -k" avoids errors from stale kernel directories in
	# /lib/modules/ whose headers are no longer installed (e.g. after a kernel
	# upgrade without reboot).
	# The package post-install hook may not trigger if headers were installed in the
	# same apt transaction, so an explicit autoinstall guarantees the .ko is present.
	if command -v dkms &>/dev/null; then
		if ! dkms autoinstall -k "$(uname -r)"; then
			echo -e "${ORANGE}WARNING: dkms autoinstall failed for kernel $(uname -r).${NC}"
			echo -e "${ORANGE}The amneziawg kernel module may not be available until headers are installed and the module is rebuilt.${NC}"
		fi
	fi

	# Rebuild module dependency cache (required for DKMS + compressed modules, especially on ARM/Ubuntu)
	if command -v depmod &>/dev/null; then
		if ! depmod -a; then
			echo -e "${ORANGE}WARNING: depmod -a failed. The kernel module may not load correctly.${NC}"
			echo -e "${ORANGE}You may need to reboot after installation.${NC}"
		fi
	else
		echo -e "${ORANGE}WARNING: depmod not found. Skipping module dependency cache rebuild.${NC}"
	fi

	# Verify the module was actually built. If the .ko file is missing even after
	# dkms autoinstall, something went wrong during compilation (likely missing
	# kernel headers).  Print an early, actionable warning so the user doesn't have
	# to wait until modprobe to discover the problem.
	if [ -z "$(find "/lib/modules/$(uname -r)" -name 'amneziawg.ko*' -print -quit 2>/dev/null)" ]; then
		echo -e "${ORANGE}WARNING: amneziawg kernel module was NOT built for kernel $(uname -r).${NC}"
		echo -e "${ORANGE}This usually means kernel headers are missing or the DKMS build failed.${NC}"
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			echo -e "${ORANGE}Try: apt install -y \"linux-headers-$(uname -r)\" && dkms autoinstall && depmod -a${NC}"
		elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			echo -e "${ORANGE}Try: dnf install -y \"kernel-devel-$(uname -r)\" && dkms autoinstall && depmod -a${NC}"
		fi
	fi

	# Ensure AmneziaWG kernel module is loaded at boot (before awg-quick service starts)
	mkdir -p /etc/modules-load.d
	chmod 755 /etc/modules-load.d
	if ! grep -qx "amneziawg" /etc/modules-load.d/amneziawg.conf 2>/dev/null; then
		echo "amneziawg" >> /etc/modules-load.d/amneziawg.conf
	fi
	chmod 644 /etc/modules-load.d/amneziawg.conf

	# Ensure configuration directory exists
	mkdir -p "${AMNEZIAWG_DIR}"
	chmod 700 "${AMNEZIAWG_DIR}"

	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	SERVER_PRIV_KEY=$(awg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)

	# Restrict umask for sensitive file creation (private keys, server config)
	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077

	# Save WireGuard settings atomically: write to temp file then move into place
	PARAMS_TMP_FILE="$(mktemp "${AMNEZIAWG_DIR}/params.XXXXXX")" || { echo -e "${RED}ERROR: Failed to create temporary params file.${NC}"; exit 1; }
	serializeParams "${PARAMS_TMP_FILE}" || { echo -e "${RED}ERROR: Failed to write params file.${NC}"; rm -f "${PARAMS_TMP_FILE}"; exit 1; }
	if ! mv -f "${PARAMS_TMP_FILE}" "${AMNEZIAWG_DIR}/params"; then
		echo -e "${RED}ERROR: Failed to move params file into place.${NC}"
		rm -f "${PARAMS_TMP_FILE}"
		exit 1
	fi
	chmod 600 "${AMNEZIAWG_DIR}/params"

	# Add server interface. Include the IPv6 address only when IPv6 is enabled.
	local SERVER_ADDRESS="${SERVER_AWG_IPV4}/24"
	if [[ "${ENABLE_IPV6}" == "y" ]]; then
		SERVER_ADDRESS="${SERVER_ADDRESS},${SERVER_AWG_IPV6}/64"
	fi
	echo "[Interface]
Address = ${SERVER_ADDRESS}
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}" >"${SERVER_AWG_CONF}"
	chmod 600 "${SERVER_AWG_CONF}"

	# Restore default umask before creating system files and running services
	umask "${OLD_UMASK}"

	writeFirewallRules >>"${SERVER_AWG_CONF}"

	# Enable routing on the server
	mkdir -p /etc/sysctl.d
	chmod 755 /etc/sysctl.d
	echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/awg.conf
	if [[ "${ENABLE_IPV6}" == "y" ]]; then
		echo "net.ipv6.conf.all.forwarding = 1" >>/etc/sysctl.d/awg.conf
	fi
	chmod 644 /etc/sysctl.d/awg.conf

	sysctl -p /etc/sysctl.d/awg.conf

	# Add a systemd drop-in override that:
	#  - Ensures the amneziawg module is loaded before awg-quick starts (ExecStartPre)
	#  - Waits for network-online so the interface is available for routing
	# This survives reboots and kernel upgrades without manual intervention.
	mkdir -p "/etc/systemd/system/awg-quick@${SERVER_AWG_NIC}.service.d"
	chmod 755 "/etc/systemd/system/awg-quick@${SERVER_AWG_NIC}.service.d"
	cat > "/etc/systemd/system/awg-quick@${SERVER_AWG_NIC}.service.d/override.conf" <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=modprobe amneziawg
EOF
	chmod 644 "/etc/systemd/system/awg-quick@${SERVER_AWG_NIC}.service.d/override.conf"
	systemctl daemon-reload

	# Gate the service start on the kernel module actually being loadable.
	# If modprobe fails here, the module wasn't built for this kernel — starting
	# the service would just produce a confusing "Unknown device type" error.
	local MODULE_READY=0

	# Always enable the service so it starts on next boot. Even if modprobe fails
	# now (e.g., missing kernel headers), a reboot after installing headers or
	# running dkms autoinstall will load the module via the ExecStartPre override.
	systemctl enable "awg-quick@${SERVER_AWG_NIC}"

	if modprobe amneziawg; then
		systemctl start "awg-quick@${SERVER_AWG_NIC}"
		MODULE_READY=1
	else
		local HEADERS_HINT="matching kernel headers"
		local INSTALL_HINT="Install matching kernel headers"
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			HEADERS_HINT="linux-headers-$(uname -r)"
			INSTALL_HINT="apt install -y \"linux-headers-$(uname -r)\""
		elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			HEADERS_HINT="kernel-devel-$(uname -r)"
			INSTALL_HINT="dnf install -y \"kernel-devel-$(uname -r)\""
		fi

		echo -e "${RED}ERROR: amneziawg kernel module could not be loaded for kernel $(uname -r).${NC}"
		echo -e "${ORANGE}The service was NOT started but is enabled for next boot.${NC}"
		echo -e "${ORANGE}To fix:${NC}"
		echo -e "${ORANGE}  1. Ensure ${HEADERS_HINT} is installed${NC}"
		echo -e "${ORANGE}     ${INSTALL_HINT}${NC}"
		echo -e "${ORANGE}  2. Run: dkms autoinstall && depmod -a${NC}"
		echo -e "${ORANGE}  3. Run: modprobe amneziawg${NC}"
		echo -e "${ORANGE}  4. Run: systemctl start awg-quick@${SERVER_AWG_NIC}${NC}"
		echo -e "${ORANGE}  Or simply reboot the server.${NC}"
	fi

	if [[ ${MODULE_READY} -eq 1 ]]; then
		if shouldCreateInitialClient; then
			newClient
			echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"
		else
			echo -e "${ORANGE}Skipping initial client generation. You can add users later from this script or the web panel.${NC}"
		fi
	else
		echo -e "${ORANGE}Skipping client generation because the server interface is not active.${NC}"
	fi

	# Check if AmneziaWG is running
	systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
	AWG_RUNNING=$?

	# AmneziaWG might not work if we updated the kernel. Tell the user to reboot
	if [[ ${AWG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: AmneziaWG does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if AmneziaWG is running with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
		if ! lsmod | grep -q amneziawg; then
			local HEADERS_HINT="matching kernel headers"
			local INSTALL_HINT="Install matching kernel headers"
			if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
				HEADERS_HINT="linux-headers-$(uname -r)"
				INSTALL_HINT="apt install -y \"linux-headers-$(uname -r)\""
			elif [[ ${OS} == 'fedora' ]] || [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
				HEADERS_HINT="kernel-devel-$(uname -r)"
				INSTALL_HINT="dnf install -y \"kernel-devel-$(uname -r)\""
			fi

			echo -e "${ORANGE}The amneziawg kernel module is NOT loaded.${NC}"
			echo -e "${ORANGE}This usually means the module was not built for kernel $(uname -r).${NC}"
			echo -e "${ORANGE}Install ${HEADERS_HINT} and rebuild: ${INSTALL_HINT} && dkms autoinstall && depmod -a${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_AWG_NIC}\", please reboot!${NC}"
	else # AmneziaWG is running
		echo -e "\n${GREEN}AmneziaWG is running.${NC}"
		echo -e "${GREEN}You can check the status of AmneziaWG with: systemctl status awg-quick@${SERVER_AWG_NIC}\n\n${NC}"
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	ensureAmneziawgKernelModule
	# Reset variables to ensure clean state for each new client
	local CLIENT_NAME=""
	local CLIENT_EXISTS=""
	local IPV4_EXISTS=""
	local IPV6_EXISTS=""
	local DOT_IP=""
	local DOT_EXISTS=""
	local BASE_IP=""

	# If SERVER_PUB_IP is IPv6, normalize brackets
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		SERVER_PUB_IP="${SERVER_PUB_IP#\[}"
		SERVER_PUB_IP="${SERVER_PUB_IP%\]}"
		SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	BASE_IP=$(echo "$SERVER_AWG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')

	# Precompute normalized server IPv6 and base prefix once, since SERVER_AWG_IPV6 is constant here.
	local NORMALIZED_SERVER_IPV6 BASE_IPV6
	NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
	BASE_IPV6=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)

	local FREE_DOT_IP_FOUND=0
	for DOT_IP in {2..254}; do
		# Check IPv4 address "${BASE_IP}.${DOT_IP}/32" is not already in use
		DOT_EXISTS=$(grep -cF "${BASE_IP}.${DOT_IP}/32" "${SERVER_AWG_CONF}")

		# Derive the would-be IPv6 client address in the same way as in AUTO_INSTALL
		# and ensure the corresponding /128 is also not already present.
		local CLIENT_IPV6_CANDIDATE
		CLIENT_IPV6_CANDIDATE=$(normalizeIPv6 "${BASE_IPV6}::${DOT_IP}")

		# Perform a semantic duplicate check: normalize existing /128 IPv6 addresses
		# before comparing, so compressed vs expanded forms are treated as equal.
		IPV6_EXISTS=0
		while IFS= read -r _existing_ip_cidr; do
			# Strip the /128 suffix to get the raw IPv6 address
			local _existing_ip="${_existing_ip_cidr%/*}"
			local _normalized_existing
			_normalized_existing=$(normalizeIPv6 "${_existing_ip}")
			if [[ "${_normalized_existing}" == "${CLIENT_IPV6_CANDIDATE}" ]]; then
				IPV6_EXISTS=1
				break
			fi
		done < <(grep -oE '([0-9a-fA-F:]+)/128' "${SERVER_AWG_CONF}")

		if [[ ${DOT_EXISTS} == '0' && ${IPV6_EXISTS} == '0' ]]; then
			FREE_DOT_IP_FOUND=1
			break
		fi
	done

	if [[ ${FREE_DOT_IP_FOUND} -eq 0 ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		# Auto mode: use default client name and first available IPs
		CLIENT_NAME="client"
		local CLIENT_NUM=2
		while [[ $(grep -c -xF "### Client ${CLIENT_NAME}" "${SERVER_AWG_CONF}") != 0 ]]; do
			CLIENT_NAME="client${CLIENT_NUM}"
			CLIENT_NUM=$((CLIENT_NUM + 1))
		done

		CLIENT_AWG_IPV4="${BASE_IP}.${DOT_IP}"

		local NORMALIZED_SERVER_IPV6 BASE_IPV6_PREFIX
		NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
		BASE_IPV6_PREFIX=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)
		CLIENT_AWG_IPV6=$(normalizeIPv6 "${BASE_IPV6_PREFIX}::${DOT_IP}")
	else
		echo ""
		echo "Client configuration"
		echo ""
		echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

		until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
			read -rp "Client name: " -e CLIENT_NAME
			CLIENT_EXISTS=$(grep -c -xF "### Client ${CLIENT_NAME}" "${SERVER_AWG_CONF}")

			if [[ ${CLIENT_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
				echo ""
			fi
		done

		until [[ ${IPV4_EXISTS} == '0' ]]; do
			read -rp "Client AmneziaWG IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP

			# Validate host number is between 2 and 254
			if ! [[ ${DOT_IP} =~ ^[0-9]+$ ]] || (( DOT_IP < 2 )) || (( DOT_IP > 254 )); then
				echo ""
				echo -e "${ORANGE}Invalid host number. Must be between 2 and 254.${NC}"
				echo ""
				IPV4_EXISTS='1'
				continue
			fi

			CLIENT_AWG_IPV4="${BASE_IP}.${DOT_IP}"
			IPV4_EXISTS=$(grep -cF "$CLIENT_AWG_IPV4/32" "${SERVER_AWG_CONF}")

			if [[ ${IPV4_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
				echo ""
			fi
		done

		# Prompt for the client's IPv6 only when IPv6 support is enabled (issue #51).
		# When disabled, the safety net below derives a placeholder that is never
		# written to the config.
		if [[ "${ENABLE_IPV6}" == "y" ]]; then
			# Normalize server IPv6 and extract /64 prefix (first 4 groups)
			local NORMALIZED_SERVER_IPV6
			NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
			BASE_IP=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)

			# Reset IPV6_EXISTS so the until-loop below actually prompts the user.
			# The free-IP search loop above already set it to '0' for the first
			# available slot, which would cause the until condition to be immediately
			# true and skip the interactive IPv6 selection entirely.
			IPV6_EXISTS=""

			until [[ ${IPV6_EXISTS} == '0' ]]; do
				read -rp "Client AmneziaWG IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP

				# Validate IPv6 host part is a valid hex segment (1-4 hex characters)
				if ! [[ ${DOT_IP} =~ ^[a-fA-F0-9]{1,4}$ ]]; then
					echo ""
					echo -e "${ORANGE}Invalid IPv6 host part. Must be 1-4 hexadecimal characters.${NC}"
					echo ""
					IPV6_EXISTS='1'
					continue
				fi

				CLIENT_AWG_IPV6=$(normalizeIPv6 "${BASE_IP}::${DOT_IP}")
				# Semantic duplicate check: normalize all existing IPv6 in config for comparison
				IPV6_EXISTS=0
				local EXISTING_IPV6_RAW
				while IFS= read -r EXISTING_IPV6_RAW; do
					if [[ "$(normalizeIPv6 "${EXISTING_IPV6_RAW%/128}")" == "${CLIENT_AWG_IPV6}" ]]; then
						IPV6_EXISTS=1
						break
					fi
				done < <(grep -oE '[a-fA-F0-9:]+/128' "${SERVER_AWG_CONF}")

				if [[ ${IPV6_EXISTS} != 0 ]]; then
					echo ""
					echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
					echo ""
				fi
			done
		fi
	fi

	# Safety net: if CLIENT_AWG_IPV6 was not set (e.g., the interactive IPv6
	# prompt was unexpectedly skipped), derive it from the server's /64 prefix
	# and the selected host number to avoid writing a broken config.
	if [[ -z "${CLIENT_AWG_IPV6}" ]]; then
		CLIENT_AWG_IPV6=$(normalizeIPv6 "${BASE_IPV6}::${DOT_IP}")
	fi

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(awg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
	CLIENT_PRE_SHARED_KEY=$(awg genpsk)

	local HOME_DIR
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Build DNS line: include second resolver only if provided
	local CLIENT_DNS="${CLIENT_DNS_1}"
	if [[ -n "${CLIENT_DNS_2}" ]]; then
		CLIENT_DNS="${CLIENT_DNS_1},${CLIENT_DNS_2}"
	fi

	# Compress IPv6 to canonical RFC 5952 form for client config display
	local CLIENT_AWG_IPV6_DISPLAY
	CLIENT_AWG_IPV6_DISPLAY=$(compressIPv6 "${CLIENT_AWG_IPV6}")

	# Build the client Address and route list, including IPv6 only when enabled
	# (issue #51): an IPv6 address/route on an IPv4-only client fails to apply.
	local CLIENT_ADDRESS="${CLIENT_AWG_IPV4}/32"
	if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
		CLIENT_ADDRESS="${CLIENT_ADDRESS},${CLIENT_AWG_IPV6_DISPLAY}/128"
	fi
	local CLIENT_ALLOWED_IPS
	if ! CLIENT_ALLOWED_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${ENABLE_IPV6:-y}"); then
		echo -e "${RED}ERROR: ALLOWED_IPS has no usable routes after applying ENABLE_IPV6=${ENABLE_IPV6:-y}: ${ALLOWED_IPS}${NC}"
		return 1
	fi

	# Restrict umask for client config file creation (contains private key)
	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_ADDRESS}
DNS = ${CLIENT_DNS}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${CLIENT_ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# Restore default umask
	umask "${OLD_UMASK}"

	local client_conf owner_group sudo_home client_chown_ok client_chown_target client_primary_group sudo_chown_target sudo_primary_group
	client_conf="${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
	if ! chmod 600 "${client_conf}"; then
		echo "Warning: failed to set permissions on ${client_conf}" >&2
	fi

	# Copy config to the web panel directory (best-effort) *before* chowning
	# to a non-root user, so the source file is still root-owned and cannot
	# be swapped via a TOCTOU race in a user-writable directory.
	copyToWebPanelDir "${client_conf}"

	# Ensure the generated client config is readable by the intended non-root user,
	# without unintentionally granting access to the sudo-invoking user.
	# Prefer:
	#   1. CLIENT_NAME, if it is a real system user.
	#   2. The owner of HOME_DIR.
	#   3. SUDO_USER, but only if HOME_DIR is SUDO_USER's home directory.

	# Try to determine the ownership of HOME_DIR, if stat is available.
	if command -v stat >/dev/null 2>&1; then
		owner_group="$(stat -c '%U:%G' "${HOME_DIR}" 2>/dev/null || true)"
	fi

	# 1. If CLIENT_NAME corresponds to an existing user, chown to that user.
	client_chown_ok=1
	if [ -n "${CLIENT_NAME:-}" ] && id -u "${CLIENT_NAME}" >/dev/null 2>&1; then
		client_chown_target="${CLIENT_NAME}"
		if command -v id >/dev/null 2>&1; then
			client_primary_group="$(id -gn "${CLIENT_NAME}" 2>/dev/null || true)"
			if [ -n "${client_primary_group}" ]; then
				client_chown_target="${CLIENT_NAME}:${client_primary_group}"
			fi
		fi
		if chown "${client_chown_target}" "${client_conf}" 2>/dev/null; then
			client_chown_ok=0
		fi
	fi

	# 2. If CLIENT_NAME chown did not succeed and we know the owner of HOME_DIR, match that ownership.
	if [ ${client_chown_ok} -ne 0 ] && [ -n "${owner_group:-}" ]; then
		if chown "${owner_group}" "${client_conf}" 2>/dev/null; then
			client_chown_ok=0
		fi
	fi

	# 3. As a last resort, fall back to SUDO_USER only when HOME_DIR is the sudo user's home.
	if [ ${client_chown_ok} -ne 0 ] && [ -n "${SUDO_USER:-}" ] && id -u "${SUDO_USER}" >/dev/null 2>&1; then
		if command -v getent >/dev/null 2>&1; then
			sudo_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
		fi
		if [ -n "${sudo_home:-}" ] && [ "${sudo_home}" = "${HOME_DIR}" ]; then
			sudo_chown_target="${SUDO_USER}"
			if command -v id >/dev/null 2>&1; then
				sudo_primary_group="$(id -gn "${SUDO_USER}" 2>/dev/null || true)"
				if [ -n "${sudo_primary_group}" ]; then
					sudo_chown_target="${SUDO_USER}:${sudo_primary_group}"
				fi
			fi
			chown "${sudo_chown_target}" "${client_conf}" || true
		fi
	fi

	# Add the client as a peer to the server. Include the IPv6 /128 only when
	# IPv6 is enabled (issue #51).
	local PEER_ALLOWED_IPS="${CLIENT_AWG_IPV4}/32"
	if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
		PEER_ALLOWED_IPS="${PEER_ALLOWED_IPS},${CLIENT_AWG_IPV6}/128"
	fi
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${PEER_ALLOWED_IPS}" >>"${SERVER_AWG_CONF}"

	local sync_err
	sync_err=""
	if ! sync_err="$(awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}") 2>&1)"; then
		echo "ERROR: failed to sync AmneziaWG interface '${SERVER_AWG_NIC}' after adding client '${CLIENT_NAME}'" >&2
		if [[ -n "${sync_err}" ]]; then
			echo "${sync_err}" >&2
		fi
		exit 1
	fi

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
	local CLIENT_NUMBER=""
	until [[ ${CLIENT_NUMBER} =~ ^[0-9]+$ ]] && [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${NUMBER_OF_CLIENTS} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# Validate client name contains only characters safe for sed regex patterns.
	# Names created by this script are always [a-zA-Z0-9_-], but a manually
	# edited config could introduce regex metacharacters (e.g., '.', '*').
	if ! [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
		echo -e "${RED}ERROR: Client name '${CLIENT_NAME}' contains unsafe characters. Please fix the config manually.${NC}"
		exit 1
	fi

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

	# remove generated client file
	local HOME_DIR
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# Remove config from the web panel directory (best-effort)
	removeFromWebPanelDir "${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# restart AmneziaWG to apply changes
	ensureAmneziawgKernelModule
	awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
}

function regenerateClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	# If SERVER_PUB_IP is IPv6, normalize brackets
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		SERVER_PUB_IP="${SERVER_PUB_IP#\[}"
		SERVER_PUB_IP="${SERVER_PUB_IP%\]}"
		SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Regenerating all client configurations with current server parameters..."
	echo ""

	local REGENERATED=0
	local FAILED=0
	local NEWKEYS=0

	# Iterate over each client peer block in the server config
	while IFS= read -r CLIENT_NAME; do
		# Validate client name contains only characters safe for sed regex patterns.
		# Names created by this script are always [a-zA-Z0-9_-], but a manually
		# edited config could introduce regex metacharacters (e.g., '.', '*').
		if ! [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
			echo -e "${RED}  SKIP: '${CLIENT_NAME}' - name contains unsafe characters${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		# Extract peer details from the server config for this client
		# The block starts with "### Client <name>" and ends at the next empty line
		local PEER_BLOCK
		PEER_BLOCK=$(sed -n "/^### Client ${CLIENT_NAME}\$/,/^$/p" "${SERVER_AWG_CONF}")

		local CLIENT_PUB_KEY
		CLIENT_PUB_KEY=$(echo "${PEER_BLOCK}" | grep -m1 -E "^PublicKey = " | sed 's/^PublicKey = //')
		local CLIENT_PRE_SHARED_KEY
		CLIENT_PRE_SHARED_KEY=$(echo "${PEER_BLOCK}" | grep -E "^PresharedKey = " | sed 's/^PresharedKey = //')
		local CLIENT_ALLOWED_IPS
		CLIENT_ALLOWED_IPS=$(echo "${PEER_BLOCK}" | grep -E "^AllowedIPs = " | sed 's/^AllowedIPs = //')

		if [[ -z "${CLIENT_PUB_KEY}" ]] || [[ -z "${CLIENT_PRE_SHARED_KEY}" ]] || [[ -z "${CLIENT_ALLOWED_IPS}" ]]; then
			echo -e "${RED}  SKIP: ${CLIENT_NAME} - could not parse peer block from server config${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		# Parse IPv4 and IPv6 addresses from AllowedIPs (e.g., "10.66.66.2/32,fd42:42:42::2/128").
		# There may be multiple routes; select a single "client address" per family to avoid
		# multi-line values corrupting the generated Address = ... line.
		local CLIENT_AWG_IPV4
		local CLIENT_AWG_IPV4_CANDIDATES
		CLIENT_AWG_IPV4_CANDIDATES=$(echo "${CLIENT_ALLOWED_IPS}" \
			| tr ',' '\n' \
			| sed 's/^[[:space:]]*//' \
			| grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32([[:space:]]*$)' \
			| sed 's|/32[[:space:]]*$||')

		local CLIENT_AWG_IPV6
		local CLIENT_AWG_IPV6_CANDIDATES
		CLIENT_AWG_IPV6_CANDIDATES=$(echo "${CLIENT_ALLOWED_IPS}" \
			| tr ',' '\n' \
			| sed 's/^[[:space:]]*//' \
			| grep -E ':' \
			| grep -E '/128([[:space:]]*$)' \
			| sed 's|/128[[:space:]]*$||')

		if [[ -z "${CLIENT_AWG_IPV4_CANDIDATES}" ]]; then
			echo -e "${RED}  SKIP: ${CLIENT_NAME} - could not parse IPv4 from AllowedIPs${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		# Use the first IPv4/IPv6 candidate as the client address; warn if multiple exist.
		if [[ "$(echo "${CLIENT_AWG_IPV4_CANDIDATES}" | wc -l | tr -d ' ')" -gt 1 ]]; then
			echo -e "${ORANGE}  WARN: ${CLIENT_NAME} - multiple IPv4 entries in AllowedIPs; using first one${NC}"
		fi
		CLIENT_AWG_IPV4=$(echo "${CLIENT_AWG_IPV4_CANDIDATES}" | head -n 1)

		if [[ -n "${CLIENT_AWG_IPV6_CANDIDATES}" ]]; then
			if [[ "$(echo "${CLIENT_AWG_IPV6_CANDIDATES}" | wc -l | tr -d ' ')" -gt 1 ]]; then
				echo -e "${ORANGE}  WARN: ${CLIENT_NAME} - multiple IPv6 entries in AllowedIPs; using first one${NC}"
			fi
			CLIENT_AWG_IPV6=$(echo "${CLIENT_AWG_IPV6_CANDIDATES}" | head -n 1)
		else
			CLIENT_AWG_IPV6=""
		fi

		# Normalize then compress IPv6 for canonical display in regenerated client configs
		if [[ -n "${CLIENT_AWG_IPV6}" ]]; then
			CLIENT_AWG_IPV6=$(compressIPv6 "$(normalizeIPv6 "${CLIENT_AWG_IPV6}")")
		fi

		# Build address string, including IPv6 only when the server still has it enabled.
		local CLIENT_ADDRESS="${CLIENT_AWG_IPV4}/32"
		if [[ "${ENABLE_IPV6:-y}" == "y" && -n "${CLIENT_AWG_IPV6}" ]]; then
			CLIENT_ADDRESS="${CLIENT_ADDRESS},${CLIENT_AWG_IPV6}/128"
		fi

		# Route list: drop IPv6 routes whenever the regenerated client will not have
		# an IPv6 address, so it never tries to add a ::/0 route (issue #51).
		local CLIENT_ROUTE_IPV6_ENABLED="${ENABLE_IPV6:-y}"
		if [[ -z "${CLIENT_AWG_IPV6}" ]]; then
			CLIENT_ROUTE_IPV6_ENABLED=n
		fi
		local CLIENT_ROUTE_IPS
		if ! CLIENT_ROUTE_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${CLIENT_ROUTE_IPV6_ENABLED}"); then
			echo -e "${RED}  FAIL: ${CLIENT_NAME} - ALLOWED_IPS has no usable routes after applying ENABLE_IPV6=${CLIENT_ROUTE_IPV6_ENABLED}${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		# Determine home directory and locate existing client config file
		local HOME_DIR
		HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
		# CLIENT_CONF is the canonical "home-based" path for this client's config.
		local CLIENT_CONF
		# CLIENT_CONF_OUTPUT is the path we will ultimately write the regenerated
		# config to. By default it matches CLIENT_CONF, but if we discover an
		# existing config in another location (one of the candidates below),
		# later code should update CLIENT_CONF_OUTPUT to that path so that the
		# regenerated config overwrites/updates the file we actually used to
		# recover the client's private key.
		local CLIENT_CONF_OUTPUT=""
		if [[ -n "${HOME_DIR}" ]]; then
			CLIENT_CONF="${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
			CLIENT_CONF_OUTPUT="${CLIENT_CONF}"
		else
			# If HOME_DIR could not be determined, leave CLIENT_CONF empty and let
			# later logic choose an appropriate output path based on where an
			# existing config is actually found (if any).
			CLIENT_CONF=""
		fi
		local CLIENT_PRIV_KEY=""

		# Try to recover the client's private key from an existing config file.
		# Search multiple common locations to avoid regenerating keys just because
		# getHomeDirForClient guessed a different home than where the config was created.
		local -a CLIENT_CONF_CANDIDATES=()

		# 1) Config under the resolved HOME_DIR (if any)
		if [[ -n "${CLIENT_CONF}" ]]; then
			CLIENT_CONF_CANDIDATES+=("${CLIENT_CONF}" "${CLIENT_CONF}.old")
		fi

		# 2) Root's home (common when run as root or via sudo)
		if [[ -d "/root" ]]; then
			CLIENT_CONF_CANDIDATES+=("/root/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf" \
									 "/root/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf.old")
		fi

		# 3) All user homes under /home
		for SEARCH_DIR in /home/*; do
			if [[ -d "${SEARCH_DIR}" ]]; then
				CLIENT_CONF_CANDIDATES+=("${SEARCH_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf" \
										 "${SEARCH_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf.old")
			fi
		done

		# Scan candidate config files (including .conf.old, renamed during migration).
		# For each candidate, verify that the private key derives to the public key
		# registered in the server config.  This prevents stale or unrelated configs
		# (e.g. left over from a previous installation in another home directory)
		# from being incorrectly matched by filename alone.
		local MATCHED_CONF=""
		for CANDIDATE in "${CLIENT_CONF_CANDIDATES[@]}"; do
			if [[ -f "${CANDIDATE}" ]]; then
				local CANDIDATE_PRIV_KEY
				CANDIDATE_PRIV_KEY=$(grep -m1 -E "^PrivateKey = " "${CANDIDATE}" | sed 's/^PrivateKey = //')
				if [[ -n "${CANDIDATE_PRIV_KEY}" ]]; then
					local CANDIDATE_PUB_KEY
					CANDIDATE_PUB_KEY=$(echo "${CANDIDATE_PRIV_KEY}" | awg pubkey 2>/dev/null || true)
					if [[ "${CANDIDATE_PUB_KEY}" == "${CLIENT_PUB_KEY}" ]]; then
						CLIENT_PRIV_KEY="${CANDIDATE_PRIV_KEY}"
						MATCHED_CONF="${CANDIDATE}"
						break
					fi
				fi
			fi
		done

		# If we recovered an existing private key, align CLIENT_CONF_OUTPUT
		# with the location where that key/config was found. If the matched
		# config is a ".conf.old", strip the suffix so we regenerate the
		# non-.old config in the same directory.
		if [[ -n "${CLIENT_PRIV_KEY}" && -n "${MATCHED_CONF}" ]]; then
			if [[ "${MATCHED_CONF}" == *.old ]]; then
				CLIENT_CONF_OUTPUT="${MATCHED_CONF%.old}"
			else
				CLIENT_CONF_OUTPUT="${MATCHED_CONF}"
			fi
		fi

		if [[ -z "${CLIENT_PRIV_KEY}" ]]; then
			# No existing private key found - generate a new key pair
			# This means the client will need the new config to reconnect
			echo -e "${ORANGE}  ${CLIENT_NAME}: no existing private key found, generating new key pair${NC}"
			CLIENT_PRIV_KEY=$(awg genkey)
			local NEW_CLIENT_PUB_KEY
			NEW_CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)

			# Update the server config with the new public key
			sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/ s|^PublicKey = .*|PublicKey = ${NEW_CLIENT_PUB_KEY}|" "${SERVER_AWG_CONF}"
			CLIENT_PUB_KEY="${NEW_CLIENT_PUB_KEY}"
			NEWKEYS=$((NEWKEYS + 1))
		fi

		# Build DNS line: include second resolver only if provided
		local CLIENT_DNS="${CLIENT_DNS_1}"
		if [[ -n "${CLIENT_DNS_2}" ]]; then
			CLIENT_DNS="${CLIENT_DNS_1},${CLIENT_DNS_2}"
		fi

		# Write the new client config file with current server parameters
		local OUTPUT_CONF="${CLIENT_CONF_OUTPUT:-$CLIENT_CONF}"
		local TMP_CONF

		# Ensure parent directory for the output config exists
		if ! mkdir -p "$(dirname "${OUTPUT_CONF}")"; then
			echo -e "${RED}  ${CLIENT_NAME}: failed to create directory for client config (${OUTPUT_CONF})${NC}"
			FAILED=$((FAILED + 1))
			continue
		fi

		TMP_CONF="$(mktemp "$(dirname "${OUTPUT_CONF}")/.$(basename "${OUTPUT_CONF}").tmp.XXXXXX")" || {
			echo -e "${RED}  ${CLIENT_NAME}: failed to create temporary file for client config (${OUTPUT_CONF})${NC}"
			FAILED=$((FAILED + 1))
			continue
		}

		if cat <<EOF >"${TMP_CONF}" && chmod 600 "${TMP_CONF}" && mv "${TMP_CONF}" "${OUTPUT_CONF}"; then
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_ADDRESS}
DNS = ${CLIENT_DNS}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${CLIENT_ROUTE_IPS}
EOF

		# Copy regenerated config to the web panel directory (best-effort)
		# *before* chowning to a non-root user, so the source file is still
		# root-owned and cannot be swapped via a TOCTOU race.
		copyToWebPanelDir "${OUTPUT_CONF}"

		# If running as root and the output directory is owned by a non-root user,
		# ensure the regenerated client config is owned by that user so they can
		# actually read it (while keeping permissions at 600).
		if [ "$(id -u)" -eq 0 ]; then
			local OUTPUT_OWNER_GROUP OUTPUT_OWNER
			OUTPUT_OWNER_GROUP="$(stat -c '%U:%G' "$(dirname "${OUTPUT_CONF}")" 2>/dev/null || echo "")"
			OUTPUT_OWNER="${OUTPUT_OWNER_GROUP%%:*}"
			if [ -n "${OUTPUT_OWNER_GROUP}" ] && [ -n "${OUTPUT_OWNER}" ] && [ "${OUTPUT_OWNER}" != "root" ]; then
				chown "${OUTPUT_OWNER_GROUP}" "${OUTPUT_CONF}" 2>/dev/null || :
			fi
		fi

		# Regeneration succeeded; existing client config has been updated.

		# Generate QR code if qrencode is installed
		if command -v qrencode &>/dev/null; then
			echo -e "${GREEN}  ${CLIENT_NAME}: regenerated (QR code below)${NC}"
			qrencode -t ansiutf8 -l L <"${OUTPUT_CONF}"
		else
			echo -e "${GREEN}  ${CLIENT_NAME}: regenerated -> ${OUTPUT_CONF}${NC}"
		fi

		REGENERATED=$((REGENERATED + 1))
	else
		# Cleanup temporary file on failure to avoid leaking sensitive data
		rm -f "${TMP_CONF}"
		echo -e "${RED}  ${CLIENT_NAME}: failed to regenerate client config, existing config left unchanged.${NC}"
		FAILED=$((FAILED + 1))
	fi
	done < <(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3)

	# If any server-side peer keys were updated, sync the running config
	if (( NEWKEYS > 0 )); then
		ensureAmneziawgKernelModule
		awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
	fi

	echo ""
	echo -e "${GREEN}Regeneration complete: ${REGENERATED} succeeded, ${FAILED} failed.${NC}"
	if (( NEWKEYS > 0 )); then
		echo -e "${ORANGE}${NEWKEYS} client(s) had new key pairs generated (old private key was not found).${NC}"
	fi
	echo -e "${ORANGE}Distribute the new .conf files to your clients.${NC}"
}

function removeInstalledAptPackages() {
	local PACKAGE
	local PACKAGE_STATUS
	local -a INSTALLED_PACKAGES=()

	for PACKAGE in "$@"; do
		if PACKAGE_STATUS=$(dpkg-query -W -f='${db:Status-Abbrev}' "${PACKAGE}" 2>/dev/null) &&
			[[ "${PACKAGE_STATUS}" == i* ]]; then
			INSTALLED_PACKAGES+=("${PACKAGE}")
		fi
	done

	[[ "${#INSTALLED_PACKAGES[@]}" -gt 0 ]] || return 0
	apt remove -y "${INSTALLED_PACKAGES[@]}"
}

function uninstallAmneziaWG() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/amnezia/amneziawg directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == [yY] ]]; then
		checkOS
		local UNINSTALL_FAILED=0

		systemctl stop "awg-quick@${SERVER_AWG_NIC}"
		systemctl disable "awg-quick@${SERVER_AWG_NIC}"

		# Remove systemd drop-in override created during install
		DROPIN_DIR="/etc/systemd/system/awg-quick@${SERVER_AWG_NIC:?}.service.d"
		OVERRIDE_FILE="${DROPIN_DIR}/override.conf"
		if [[ -f "${OVERRIDE_FILE}" ]]; then
			rm -f "${OVERRIDE_FILE}"
		fi
		# Remove drop-in directory only if empty to avoid deleting user-managed files
		if [[ -d "${DROPIN_DIR}" ]] && [[ -z "$(ls -A "${DROPIN_DIR}")" ]]; then
			rmdir "${DROPIN_DIR}"
		fi
		systemctl daemon-reload

		# Remove module auto-load entry
		rm -f /etc/modules-load.d/amneziawg.conf

		# Disable routing
		# Only remove our conf file; do NOT force ip_forward=0 at runtime because
		# other services (Docker, libvirt, other VPNs) may depend on forwarding.
		# The setting will revert to the system default on next reboot.
		rm -f /etc/sysctl.d/awg.conf

		# Remove config files
		rm -rf "${AMNEZIAWG_DIR:?}"

		if [[ ${OS} == 'ubuntu' ]]; then
			if ! removeInstalledAptPackages amneziawg amneziawg-tools amneziawg-dkms; then
				echo -e "${RED}ERROR: Failed to remove one or more installed AmneziaWG packages.${NC}"
				UNINSTALL_FAILED=1
			fi
			if ! removeAmneziaPpaSourceEntries "${AMNEZIA_PPA_SOURCES_DIR}"; then
				echo -e "${ORANGE}WARNING: Could not safely remove every Amnezia PPA source entry. Review ${AMNEZIA_PPA_SOURCES_DIR} manually.${NC}"
				UNINSTALL_FAILED=1
			fi
			# Remove both possible auxiliary deb-src files when owned by this
			# installer. Systems upgraded between formats can contain both.
			local MANAGED_SOURCE
			for MANAGED_SOURCE in \
				/etc/apt/sources.list.d/amneziawg.sources \
				/etc/apt/sources.list.d/amneziawg.sources.list; do
				if [[ -f "${MANAGED_SOURCE}" ]] && head -1 "${MANAGED_SOURCE}" | grep -q '# Managed by amneziawg-install'; then
					rm -f "${MANAGED_SOURCE}"
				elif [[ -f "${MANAGED_SOURCE}" ]]; then
					echo -e "${ORANGE}NOTE: ${MANAGED_SOURCE} was not created by this installer (missing sentinel). Leaving it in place.${NC}"
				fi
			done
			enable_apt_ipv4
			apt-get update || echo -e "${ORANGE}WARNING: Failed to refresh APT indexes after removing the Amnezia PPA.${NC}"
			disable_apt_ipv4
		elif [[ ${OS} == 'debian' ]]; then
			if ! removeInstalledAptPackages amneziawg amneziawg-tools; then
				echo -e "${RED}ERROR: Failed to remove one or more installed AmneziaWG packages.${NC}"
				UNINSTALL_FAILED=1
			fi
			# Only remove source file and keyring if the source file has our sentinel on line 1
			if [[ -f /etc/apt/sources.list.d/amneziawg.sources.list ]] && head -1 /etc/apt/sources.list.d/amneziawg.sources.list | grep -q '# Managed by amneziawg-install'; then
				rm -f /etc/apt/sources.list.d/amneziawg.sources.list
				rm -f /etc/apt/keyrings/amneziawg.gpg
			elif [[ -f /etc/apt/sources.list.d/amneziawg.sources.list ]]; then
				echo -e "${ORANGE}NOTE: /etc/apt/sources.list.d/amneziawg.sources.list was not created by this installer (missing sentinel). Leaving it and keyring in place.${NC}"
			elif [[ -f /etc/apt/keyrings/amneziawg.gpg ]]; then
				# Source file is gone (manually deleted) but orphaned keyring remains
				echo -e "${ORANGE}NOTE: Managed source file not found but orphaned keyring detected. Removing keyring.${NC}"
				rm -f /etc/apt/keyrings/amneziawg.gpg
			fi
			apt update
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		fi

		# Check if AmneziaWG is running
		systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
		AWG_RUNNING=$?

		if [[ ${AWG_RUNNING} -eq 0 || ${UNINSTALL_FAILED} -ne 0 ]]; then
			echo "AmneziaWG failed to uninstall properly."
			exit 1
		else
			echo "AmneziaWG uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function validateParamsFile() {
	# Security: verify params file is safe to source (owned by root, not readable/writable by others)
	# This mitigates the risk of arbitrary code execution or private key exposure
	# Reject symlinks explicitly so we don't accidentally source an unexpected file via a link.
	if [[ -L "${AMNEZIAWG_DIR}/params" ]] || [[ -h "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file must not be a symbolic link: ${AMNEZIAWG_DIR}/params${NC}" >&2
		echo -e "${ORANGE}Remove the symlink and create a regular file owned by root with mode 600 or 400.${NC}" >&2
		return 1
	fi
	if [[ ! -f "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file not found or is not a regular file: ${AMNEZIAWG_DIR}/params${NC}" >&2
		echo -e "${ORANGE}The installer cannot continue without a valid params file.${NC}" >&2
		return 1
	fi
	if [[ ! -r "${AMNEZIAWG_DIR}/params" ]]; then
		echo -e "${RED}ERROR: Params file is not readable: ${AMNEZIAWG_DIR}/params${NC}" >&2
		echo -e "${ORANGE}Ensure the file is readable by root and try again.${NC}" >&2
		return 1
	fi
	local PARAMS_OWNER PARAMS_PERMS
	PARAMS_OWNER=$(stat -c '%u' "${AMNEZIAWG_DIR}/params" 2>/dev/null)
	PARAMS_PERMS=$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null)
	if [[ -z "${PARAMS_OWNER}" ]] || [[ -z "${PARAMS_PERMS}" ]]; then
		echo -e "${RED}ERROR: Failed to read file metadata for ${AMNEZIAWG_DIR}/params.${NC}" >&2
		echo -e "${ORANGE}Ensure the file exists and is accessible, then retry.${NC}" >&2
		return 1
	fi
	if [[ "${PARAMS_OWNER}" != "0" ]]; then
		echo -e "${RED}ERROR: ${AMNEZIAWG_DIR}/params is not owned by root (owner UID: ${PARAMS_OWNER}).${NC}" >&2
		echo -e "${ORANGE}This is a security risk. Fix with: chown root:root ${AMNEZIAWG_DIR}/params${NC}" >&2
		return 1
	fi
	# Require mode 600 or 400: the file contains SERVER_PRIV_KEY and must not be
	# readable or writable by group/other. Modes like 644 would leak the private key.
	if [[ "${PARAMS_PERMS}" != "600" ]] && [[ "${PARAMS_PERMS}" != "400" ]]; then
		echo -e "${RED}WARNING: ${AMNEZIAWG_DIR}/params has insecure permissions (${PARAMS_PERMS}).${NC}" >&2
		echo -e "${RED}This file contains the server private key and must not be accessible by non-root users.${NC}" >&2
		# For legacy installs created before strict umask/chmod logic, try to auto-remediate
		# when running as root and the file is owned by root, to avoid locking out management actions.
		if [[ "${EUID}" -eq 0 ]] && [[ "${PARAMS_OWNER}" == "0" ]]; then
			echo -e "${ORANGE}Attempting to fix permissions by setting mode 600 on ${AMNEZIAWG_DIR}/params...${NC}" >&2
			local chmod_err
			if chmod_err=$(chmod 600 "${AMNEZIAWG_DIR}/params" 2>&1); then
				echo -e "${GREEN}Permissions on ${AMNEZIAWG_DIR}/params updated to 600. Continuing.${NC}" >&2
			else
				# chmod failed (e.g. read-only filesystem or immutable file attribute).
				# Re-stat first so the warning shows the actual post-failure mode, not
				# the stale pre-chmod value.  Abort only when group/other WRITE bits
				# remain (privilege-escalation risk); group/other READ-only exposure
				# is warned but allowed so management operations are not blocked.
				local current_mode
				if ! current_mode=$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null); then
					echo -e "${RED}ERROR: Could not re-read permissions on ${AMNEZIAWG_DIR}/params after chmod failure; refusing to source an unverified file as root.${NC}" >&2
					return 1
				fi
				echo -e "${ORANGE}WARNING: Could not fix permissions on ${AMNEZIAWG_DIR}/params (current: ${current_mode}): ${chmod_err}${NC}" >&2
				echo -e "${ORANGE}The filesystem may be read-only or the file may have the immutable attribute set.${NC}" >&2
				echo -e "${ORANGE}Fix when possible: chmod 600 ${AMNEZIAWG_DIR}/params${NC}" >&2
				# Abort if any group/other WRITE bit remains set (mode & 022 != 0).
				# Writable params files are a privilege-escalation risk: a
				# non-root user could inject code that runs as root when the
				# file is sourced.
				if (( (8#${current_mode} & 022) != 0 )); then
					echo -e "${RED}ERROR: ${AMNEZIAWG_DIR}/params is writable by group/other (mode: ${current_mode}). Refusing to source for security reasons.${NC}" >&2
					echo -e "${ORANGE}Fix manually: chmod 600 ${AMNEZIAWG_DIR}/params${NC}" >&2
					return 1
				fi
				# Warn if group/other READ bits remain (mode & 044 != 0).
				# This exposes SERVER_PRIV_KEY but is an information-disclosure
				# risk only; blocking the operation does not un-expose the key,
				# so we warn and continue.
				if (( (8#${current_mode} & 044) != 0 )); then
					echo -e "${ORANGE}WARNING: ${AMNEZIAWG_DIR}/params is readable by group/other (mode: ${current_mode}). The server private key may be exposed to non-root users.${NC}" >&2
				fi
			fi
		else
			echo -e "${ORANGE}Fix with: chmod 600 ${AMNEZIAWG_DIR}/params${NC}" >&2
			return 1
		fi
	fi

	# Params must be authoritative; do not let an exported shell variable fill in
	# keys that older params files legitimately lack.
	unset ENABLE_IPV6
	# shellcheck source=/etc/amnezia/amneziawg/params
	if ! source "${AMNEZIAWG_DIR}/params"; then
		echo -e "${RED}ERROR: Failed to load params from ${AMNEZIAWG_DIR}/params.${NC}" >&2
		echo -e "${ORANGE}The file may be corrupted or contain a syntax error. Fix or regenerate it and rerun the installer.${NC}" >&2
		return 1
	fi
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	# Verify server config file exists before attempting migration
	if [[ ! -f "${SERVER_AWG_CONF}" ]]; then
		echo -e "${RED}ERROR: Server configuration file not found: ${SERVER_AWG_CONF}${NC}" >&2
		echo -e "${ORANGE}The params file exists but the config file is missing.${NC}" >&2
		return 1
	fi

	# Validate any persisted flag, but use the actual server interface Address as
	# the authority for installed-server management. This keeps bash and the web
	# panel aligned when an operator converts a server to IPv4-only by removing
	# the IPv6 address from the live config (issue #51).
	if [[ -n "${ENABLE_IPV6:-}" ]]; then
		ENABLE_IPV6=$(trimWhitespace "${ENABLE_IPV6}")
		ENABLE_IPV6="${ENABLE_IPV6,,}"
		if [[ "${ENABLE_IPV6}" != "y" && "${ENABLE_IPV6}" != "n" ]]; then
			echo -e "${RED}ERROR: ENABLE_IPV6 in params must be 'y' or 'n': ${ENABLE_IPV6}${NC}" >&2
			return 1
		fi
	fi
	if serverConfigHasIPv6Address "${SERVER_AWG_CONF}"; then
		ENABLE_IPV6=y
	else
		ENABLE_IPV6=n
	fi

	# Validate and normalize SERVER_AWG_IPV6 from params file
	# Older installations may have stored non-normalized or oddly formatted IPv6
	if ! isValidIPv6 "${SERVER_AWG_IPV6}"; then
		echo -e "${RED}ERROR: Invalid IPv6 address in params file: ${SERVER_AWG_IPV6}${NC}" >&2
		echo -e "${ORANGE}Fix the SERVER_AWG_IPV6 value in ${AMNEZIAWG_DIR}/params${NC}" >&2
		return 1
	fi
	# Global used by loadParams to detect IPv6 normalization changes;
	# prefixed with _ to denote script-internal cross-function state
	_MIGRATE_ORIG_IPV6="${SERVER_AWG_IPV6}"
	SERVER_AWG_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
}

# Migration for pre-2.0 installations: check for missing or invalid S3/S4 parameters
# Sets SERVER_AWG_S3 and SERVER_AWG_S4 if they are missing or invalid
# Returns 0 if migration was needed, 1 if no change
function migrateS3S4() {
	# If both S3/S4 are present, validate them before skipping migration.
	# This catches invalid values from manual edits or partial writes.
	if [[ -n "${SERVER_AWG_S3}" ]] && [[ -n "${SERVER_AWG_S4}" ]]; then
		if [[ "${SERVER_AWG_S3}" =~ ^[0-9]+$ ]] && [[ "${SERVER_AWG_S4}" =~ ^[0-9]+$ ]] && \
		   (( SERVER_AWG_S3 >= 15 )) && (( SERVER_AWG_S3 <= 150 )) && \
		   (( SERVER_AWG_S4 >= 15 )) && (( SERVER_AWG_S4 <= 150 )) && \
		   (( SERVER_AWG_S3 + 56 != SERVER_AWG_S4 )) && (( SERVER_AWG_S4 + 56 != SERVER_AWG_S3 )); then
			return 1
		fi
		# Values are present but invalid — clear them so the logic below regenerates
		SERVER_AWG_S3=""
		SERVER_AWG_S4=""
	fi

	# Try to read existing S3/S4 from config file before using defaults
	# This handles cases where params file is missing values but config file has them
	local CONF_S3 CONF_S4
	CONF_S3=$(grep -E "^S3 = " "${SERVER_AWG_CONF}" 2>/dev/null | sed 's/^S3 = //')
	CONF_S4=$(grep -E "^S4 = " "${SERVER_AWG_CONF}" 2>/dev/null | sed 's/^S4 = //')

	if [[ -n "${CONF_S3}" ]] && [[ -n "${CONF_S4}" ]]; then
		# Validate that loaded values are numeric, within valid range [15-150],
		# and satisfy the bidirectional constraint S3 + 56 != S4 and S4 + 56 != S3
		if [[ "${CONF_S3}" =~ ^[0-9]+$ ]] && [[ "${CONF_S4}" =~ ^[0-9]+$ ]] && \
		   (( CONF_S3 >= 15 )) && (( CONF_S3 <= 150 )) && \
		   (( CONF_S4 >= 15 )) && (( CONF_S4 <= 150 )) && \
		   (( CONF_S3 + 56 != CONF_S4 )) && (( CONF_S4 + 56 != CONF_S3 )); then
			SERVER_AWG_S3="${CONF_S3}"
			SERVER_AWG_S4="${CONF_S4}"
		else
			# Fallback: regenerate S3/S4 if config values are invalid
			generateS3AndS4
			while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); do
				generateS3AndS4
			done
			SERVER_AWG_S3=${RANDOM_AWG_S3}
			SERVER_AWG_S4=${RANDOM_AWG_S4}
		fi
	else
		# Generate random S3/S4 values within the valid range [15-150]
		# ensuring they satisfy the bidirectional constraint S3 + 56 != S4 and S4 + 56 != S3
		# (56 is the WireGuard handshake initiation message size)
		generateS3AndS4
		while (( RANDOM_AWG_S3 + 56 == RANDOM_AWG_S4 )) || (( RANDOM_AWG_S4 + 56 == RANDOM_AWG_S3 )); do
			generateS3AndS4
		done
		SERVER_AWG_S3=${RANDOM_AWG_S3}
		SERVER_AWG_S4=${RANDOM_AWG_S4}
	fi

	return 0
}

# Migration for pre-2.0 installations: convert/validate H1-H4 range parameters
# Returns 0 if migration was needed, 1 if no change
function migrateH1H4() {
	# Check each H1-H4 independently for conversion
	# Return codes: 0=converted, 1=no change needed, 2=invalid (needs regeneration)
	local H_CONVERTED=0
	local H_INVALID=0
	local H_RC

	convertHToRangeIfNeeded "SERVER_AWG_H1"
	H_RC=$?
	if [[ ${H_RC} -eq 0 ]]; then
		H_CONVERTED=1
	elif [[ ${H_RC} -eq 2 ]]; then
		H_INVALID=1
	fi

	convertHToRangeIfNeeded "SERVER_AWG_H2"
	H_RC=$?
	if [[ ${H_RC} -eq 0 ]]; then
		H_CONVERTED=1
	elif [[ ${H_RC} -eq 2 ]]; then
		H_INVALID=1
	fi

	convertHToRangeIfNeeded "SERVER_AWG_H3"
	H_RC=$?
	if [[ ${H_RC} -eq 0 ]]; then
		H_CONVERTED=1
	elif [[ ${H_RC} -eq 2 ]]; then
		H_INVALID=1
	fi

	convertHToRangeIfNeeded "SERVER_AWG_H4"
	H_RC=$?
	if [[ ${H_RC} -eq 0 ]]; then
		H_CONVERTED=1
	elif [[ ${H_RC} -eq 2 ]]; then
		H_INVALID=1
	fi

	# If any H value is still empty after conversion attempts, force regeneration
	# This handles pre-2.0 installations where H1-H4 were never set
	if [[ -z "${SERVER_AWG_H1}" ]] || [[ -z "${SERVER_AWG_H2}" ]] || \
	   [[ -z "${SERVER_AWG_H3}" ]] || [[ -z "${SERVER_AWG_H4}" ]]; then
		H_INVALID=1
	fi

	# Check for overlapping ranges after conversion (even if all values were valid)
	# This catches cases like H1=100, H2=100 which both convert to "100-100"
	if [[ ${H_INVALID} == 0 ]] && [[ ${H_CONVERTED} == 1 || -n "${SERVER_AWG_H1}" ]]; then
		# Parse all H ranges to check for overlaps
		local H1_MIN H1_MAX H2_MIN H2_MAX H3_MIN H3_MAX H4_MIN H4_MAX
		if parseRange "${SERVER_AWG_H1}" "H1_MIN" "H1_MAX" && \
		   parseRange "${SERVER_AWG_H2}" "H2_MIN" "H2_MAX" && \
		   parseRange "${SERVER_AWG_H3}" "H3_MIN" "H3_MAX" && \
		   parseRange "${SERVER_AWG_H4}" "H4_MIN" "H4_MAX"; then
			# Check all pairwise combinations for overlap
			if rangesOverlap "${H1_MIN}" "${H1_MAX}" "${H2_MIN}" "${H2_MAX}" || \
			   rangesOverlap "${H1_MIN}" "${H1_MAX}" "${H3_MIN}" "${H3_MAX}" || \
			   rangesOverlap "${H1_MIN}" "${H1_MAX}" "${H4_MIN}" "${H4_MAX}" || \
			   rangesOverlap "${H2_MIN}" "${H2_MAX}" "${H3_MIN}" "${H3_MAX}" || \
			   rangesOverlap "${H2_MIN}" "${H2_MAX}" "${H4_MIN}" "${H4_MAX}" || \
			   rangesOverlap "${H3_MIN}" "${H3_MAX}" "${H4_MIN}" "${H4_MAX}"; then
				H_INVALID=1
			fi
		else
			# Failed to parse one or more ranges - regenerate all
			H_INVALID=1
		fi
	fi

	# If any H value failed validation or ranges overlap, regenerate all H1-H4 ranges
	# We regenerate all to ensure non-overlapping ranges
	if [[ ${H_INVALID} == 1 ]]; then
		generateH1AndH2AndH3AndH4Ranges
		SERVER_AWG_H1="${RANDOM_AWG_H1_MIN}-${RANDOM_AWG_H1_MAX}"
		SERVER_AWG_H2="${RANDOM_AWG_H2_MIN}-${RANDOM_AWG_H2_MAX}"
		SERVER_AWG_H3="${RANDOM_AWG_H3_MIN}-${RANDOM_AWG_H3_MAX}"
		SERVER_AWG_H4="${RANDOM_AWG_H4_MIN}-${RANDOM_AWG_H4_MAX}"
		H_CONVERTED=1
	fi

	if [[ ${H_CONVERTED} == 1 ]]; then
		return 0
	fi
	return 1
}

# Restore migration backups and exit on failure
# Must only be called from persistMigration after backups have been created
# Provides detailed error context and allows investigation before exiting
function _migrationRestoreAndExit() {
	local ERROR_MSG=$1
	echo ""
	echo -e "${RED}================================================================================${NC}"
	echo -e "${RED}  MIGRATION FAILED${NC}"
	echo -e "${RED}================================================================================${NC}"
	echo -e "${RED}  Error: ${ERROR_MSG}${NC}"
	echo -e "${RED}================================================================================${NC}"
	echo ""
	echo -e "${GREEN}Restoring configuration from backups...${NC}"

	local RESTORE_FAILED=0
	if ! cp "${SERVER_AWG_CONF}.bak" "${SERVER_AWG_CONF}" 2>/dev/null; then
		echo -e "${RED}  WARNING: Failed to restore ${SERVER_AWG_CONF}${NC}"
		RESTORE_FAILED=1
	else
		echo -e "${GREEN}  Restored: ${SERVER_AWG_CONF}${NC}"
	fi

	if ! cp "${AMNEZIAWG_DIR}/params.bak" "${AMNEZIAWG_DIR}/params" 2>/dev/null; then
		echo -e "${RED}  WARNING: Failed to restore ${AMNEZIAWG_DIR}/params${NC}"
		RESTORE_FAILED=1
	else
		echo -e "${GREEN}  Restored: ${AMNEZIAWG_DIR}/params${NC}"
	fi

	if (( RESTORE_FAILED )); then
		echo ""
		echo -e "${RED}Some backups could not be restored automatically.${NC}"
		echo -e "${ORANGE}Backup files remain at:${NC}"
		echo -e "${ORANGE}  ${SERVER_AWG_CONF}.bak${NC}"
		echo -e "${ORANGE}  ${AMNEZIAWG_DIR}/params.bak${NC}"
	else
		rm -f "${SERVER_AWG_CONF}.bak" "${AMNEZIAWG_DIR}/params.bak"
		echo -e "${GREEN}Backup restoration complete. Original configuration preserved.${NC}"
	fi

	echo ""
	echo -e "${ORANGE}You can investigate the issue and re-run the script to retry migration.${NC}"
	echo -e "${ORANGE}The VPN service should still be operational with the original configuration.${NC}"
	exit 1
}

# Persist migrated values to params and server config files
# Handles backup, atomic writes, config file updates, and client config renaming
# Arguments:
#   $1 - ORIG_IPV6: Original IPv6 before normalization (for Address line update)
#   $2 - IPV6_CHANGED: 1 if IPv6 was normalized, 0 otherwise
function persistMigration() {
	local ORIG_IPV6="$1"
	local IPV6_CHANGED="$2"

	# Show prominent warning BEFORE migration begins
	echo ""
	echo -e "${RED}================================================================================${NC}"
	echo -e "${RED}  IMPORTANT: Migration to AmneziaWG 2.0 format required${NC}"
	echo -e "${RED}================================================================================${NC}"
	echo -e "${RED}  After this migration, existing client configurations will be INCOMPATIBLE.${NC}"
	echo -e "${RED}  You MUST regenerate all client configurations for them to connect.${NC}"
	echo -e "${RED}================================================================================${NC}"
	echo ""

	# Require explicit user confirmation before proceeding with migration
	if [[ "${AUTO_INSTALL,,}" == "y" ]]; then
		echo -e "${GREEN}AUTO_INSTALL: Auto-confirming migration to AmneziaWG 2.0${NC}"
	else
		while true; do
			read -rp "Do you want to proceed with migration to AmneziaWG 2.0? [y/N]: " RESP
			case "${RESP}" in
				[Yy])
					break
					;;
				[Nn]|"")
					echo -e "${ORANGE}Migration cancelled. The script cannot continue without migration.${NC}"
					echo -e "${ORANGE}Your existing configuration remains unchanged.${NC}"
					exit 0
					;;
				*)
					echo "Please answer y or n."
					;;
			esac
		done
	fi

	echo -e "${GREEN}Updating configuration with migrated values...${NC}"

	# Create backups of both files before migration
	# Note: If the script is interrupted, the .bak files will remain for manual recovery
	if ! cp "${SERVER_AWG_CONF}" "${SERVER_AWG_CONF}.bak"; then
		echo -e "${RED}ERROR: Failed to create backup of configuration file.${NC}"
		exit 1
	fi

	# Capture original params file permissions so we can preserve secure read-only (400)
	# vs read-write (600) settings chosen by the admin. If detection fails or an
	# unexpected mode is found, default to 600 to preserve existing behavior.
	local original_params_mode
	if original_params_mode="$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null)"; then
		if [ "${original_params_mode}" != "400" ]; then
			original_params_mode="600"
		fi
	else
		original_params_mode="600"
	fi

	if ! cp "${AMNEZIAWG_DIR}/params" "${AMNEZIAWG_DIR}/params.bak"; then
		echo -e "${RED}ERROR: Failed to create backup of params file.${NC}"
		rm -f "${SERVER_AWG_CONF}.bak"
		exit 1
	fi

	# Write to a temporary file first, then atomically rename to prevent partial writes
	local PARAMS_TMP
	if ! PARAMS_TMP="$(mktemp "${AMNEZIAWG_DIR}/params.tmp.XXXXXX")"; then
		_migrationRestoreAndExit "Failed to create temporary params file."
	fi
	if ! serializeParams "${PARAMS_TMP}"; then
		rm -f "${PARAMS_TMP}"
		_migrationRestoreAndExit "Failed to write temporary params file."
	fi

	# Atomically replace the params file to avoid partial writes on interruption
	if ! mv -f "${PARAMS_TMP}" "${AMNEZIAWG_DIR}/params"; then
		rm -f "${PARAMS_TMP}"
		_migrationRestoreAndExit "Failed to atomically replace params file."
	fi

	# Explicitly enforce secure permissions on the new params file, preserving any
	# intentional read-only (400) setting; otherwise default to 600.
	if ! chmod "${original_params_mode}" "${AMNEZIAWG_DIR}/params"; then
		_migrationRestoreAndExit "Failed to set secure permissions on params file."
	fi

	# Update server configuration file with migrated values
	echo -e "${GREEN}Updating server configuration file...${NC}"

	# Insert or update S3 (try update first, then insert after S2)
	if grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
		if ! sed -i "s|^S3 = .*|S3 = ${SERVER_AWG_S3}|" "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "Failed to update S3 in server configuration file."
		fi
	else
		# Verify S2 exists before attempting insertion
		if ! grep -q "^S2 = " "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "Cannot insert S3: S2 parameter not found in configuration file."
		fi
		if ! sed -i "/^S2 = .*/a S3 = ${SERVER_AWG_S3}" "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "Failed to insert S3 into server configuration file."
		fi
		# Verify insertion succeeded
		if ! grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "S3 insertion appeared to succeed but S3 not found in configuration file."
		fi
	fi

	# Insert or update S4 (try update first, then insert after S3, fallback to after S2)
	# Note: Backups were created at the start of migration, so any failure will restore
	# the original files via _migrationRestoreAndExit(). GNU sed -i is atomic (writes to
	# temp file then renames), so partial modifications within a single sed call are unlikely.
	if grep -q "^S4 = " "${SERVER_AWG_CONF}"; then
		if ! sed -i "s|^S4 = .*|S4 = ${SERVER_AWG_S4}|" "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "Failed to update S4 in server configuration file."
		fi
	else
		local S4_INSERTED=0
		local S4_ANCHOR=""

		# Determine anchor point for insertion (prefer S3, fallback to S2)
		if grep -q "^S3 = " "${SERVER_AWG_CONF}"; then
			S4_ANCHOR="S3"
		elif grep -q "^S2 = " "${SERVER_AWG_CONF}"; then
			S4_ANCHOR="S2"
		else
			_migrationRestoreAndExit "Failed to insert S4: neither S3 nor S2 found in configuration file."
		fi

		# Perform single insertion after determined anchor
		if sed -i "/^${S4_ANCHOR} = .*/a S4 = ${SERVER_AWG_S4}" "${SERVER_AWG_CONF}"; then
			S4_INSERTED=1
		fi

		if [[ ${S4_INSERTED} == 0 ]]; then
			_migrationRestoreAndExit "Failed to insert S4 after ${S4_ANCHOR} in server configuration file."
		fi

		# Verify insertion succeeded
		if ! grep -q "^S4 = " "${SERVER_AWG_CONF}"; then
			_migrationRestoreAndExit "S4 insertion appeared to succeed but S4 not found in configuration file."
		fi
	fi

	# Update H1-H4 values (verify existence first, insert if missing)
	# Process in reverse order (H4, H3, H2, H1) so that when inserting after
	# the same anchor point, the final order is correct (H1, H2, H3, H4)
	for H_PARAM in H4 H3 H2 H1; do
		local H_VAR="SERVER_AWG_${H_PARAM}"
		local H_VALUE="${!H_VAR}"

		if grep -q "^${H_PARAM} = " "${SERVER_AWG_CONF}"; then
			if ! sed -i "s|^${H_PARAM} = .*|${H_PARAM} = ${H_VALUE}|" "${SERVER_AWG_CONF}"; then
				_migrationRestoreAndExit "Failed to update ${H_PARAM} in server configuration file."
			fi
		else
			# Parameter doesn't exist, insert after S4 (or S3, S2 as fallback)
			local INSERTED=0
			for AFTER_PARAM in S4 S3 S2; do
				if grep -q "^${AFTER_PARAM} = " "${SERVER_AWG_CONF}"; then
					if sed -i "/^${AFTER_PARAM} = .*/a ${H_PARAM} = ${H_VALUE}" "${SERVER_AWG_CONF}"; then
						INSERTED=1
						break
					fi
				fi
			done
			if [[ ${INSERTED} == 0 ]]; then
				_migrationRestoreAndExit "Failed to insert ${H_PARAM} into server configuration file."
			fi
		fi
	done

	# Normalize the Address line IPv6 if it changed (cosmetic, covered by backup)
	# Scoped to ^Address to avoid touching PostUp/PostDown firewalld rules
	if [[ ${IPV6_CHANGED} == 1 ]]; then
		if sed -i "/^Address = /s|${ORIG_IPV6}/64|${SERVER_AWG_IPV6}/64|" "${SERVER_AWG_CONF}" 2>/dev/null; then
			echo -e "${GREEN}Normalized Address IPv6: ${ORIG_IPV6} -> ${SERVER_AWG_IPV6}${NC}"
		fi
	fi

	# Migration successful, remove backups
	rm -f "${SERVER_AWG_CONF}.bak" "${AMNEZIAWG_DIR}/params.bak"

	# Rename existing client config files that don't have the new parameters
	# This prevents confusion when users try to use old configs after migration
	# Only rename configs that are actually outdated (missing S3/S4 parameters)
	#
	# Iterates over clients listed in the server config and uses getHomeDirForClient
	# to locate each config file. If the expected path does not exist (e.g., because
	# the installer is being re-run under a different context than when configs were
	# created), fall back to a bounded search under /home and /root.
	echo -e "${GREEN}Marking old client configurations as outdated...${NC}"
	local CLIENT_CONFIGS_RENAMED=0
	while IFS= read -r MIGRATE_CLIENT_NAME; do
		if ! [[ ${MIGRATE_CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
			continue
		fi
		local MIGRATE_HOME_DIR
		MIGRATE_HOME_DIR=$(getHomeDirForClient "${MIGRATE_CLIENT_NAME}")
		local MIGRATE_CLIENT_CONF_BASE="${SERVER_AWG_NIC}-client-${MIGRATE_CLIENT_NAME}.conf"
		local MIGRATE_CLIENT_CONF="${MIGRATE_HOME_DIR}/${MIGRATE_CLIENT_CONF_BASE}"

		# If the config is not found at the expected home directory, search common
		# locations (/home and /root) for a matching filename. This helps when the
		# installer is re-run under a different user/root context.
		if [[ ! -f "${MIGRATE_CLIENT_CONF}" ]]; then
			local FOUND_MIGRATE_CONF
			FOUND_MIGRATE_CONF=$(find /home /root -xdev -maxdepth 5 -type f -name "${MIGRATE_CLIENT_CONF_BASE}" 2>/dev/null | head -n 1)
			if [[ -n "${FOUND_MIGRATE_CONF}" ]]; then
				MIGRATE_CLIENT_CONF="${FOUND_MIGRATE_CONF}"
			fi
		fi

		if [[ -f "${MIGRATE_CLIENT_CONF}" ]]; then
			# Only rename if the config doesn't already have S3 parameter
			# (indicating it's a pre-2.0 config that needs regeneration)
			if ! grep -q "^S3 = " "${MIGRATE_CLIENT_CONF}"; then
				if mv "${MIGRATE_CLIENT_CONF}" "${MIGRATE_CLIENT_CONF}.old"; then
					echo -e "${ORANGE}  Renamed: ${MIGRATE_CLIENT_CONF} -> ${MIGRATE_CLIENT_CONF}.old${NC}"
					CLIENT_CONFIGS_RENAMED=$((CLIENT_CONFIGS_RENAMED + 1))
				else
					echo -e "${RED}  WARNING: Failed to rename ${MIGRATE_CLIENT_CONF}${NC}"
				fi
			fi
		fi
	done < <(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3)

	if (( CLIENT_CONFIGS_RENAMED > 0 )); then
		echo -e "${ORANGE}  ${CLIENT_CONFIGS_RENAMED} client config(s) renamed with .old suffix${NC}"
	fi

	# Reload AmneziaWG configuration
	if systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
		echo -e "${GREEN}Reloading AmneziaWG configuration...${NC}"

		# Validate configuration before reloading to prevent VPN disconnection
		if awg-quick strip "${SERVER_AWG_NIC}" >/dev/null 2>&1; then
			awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
		else
			echo -e "${ORANGE}WARNING: Configuration validation failed. Skipping live reload.${NC}"
			echo -e "${ORANGE}The configuration file has been updated successfully, but the running${NC}"
			echo -e "${ORANGE}VPN service could not be reloaded and is still using the previous settings.${NC}"
			echo -e "${ORANGE}To apply the new configuration, manually restart the service:${NC}"
			echo -e "${ORANGE}  systemctl restart awg-quick@${SERVER_AWG_NIC}${NC}"
		fi
	fi

	echo -e "${GREEN}Migration completed successfully.${NC}"
	echo ""
	if (( CLIENT_CONFIGS_RENAMED > 0 )); then
		echo -e "${ORANGE}NOTE: ${CLIENT_CONFIGS_RENAMED} old client config(s) were renamed with .old suffix.${NC}"
		echo -e "${ORANGE}You can delete them after regenerating new configs, or keep them for reference.${NC}"
	fi
	echo -e "${ORANGE}REMINDER: All existing client configurations must be regenerated.${NC}"
	echo -e "${ORANGE}Use option 4 (Regenerate all client configs) to update them automatically.${NC}"
	echo ""
}

# Quiet params rewrite when only IPv6 normalization changed (no protocol migration)
# This keeps the params file in canonical form without alarming the user
# Arguments:
#   $1 - ORIG_IPV6: Original IPv6 before normalization
function quietIPv6Rewrite() {
	local ORIG_IPV6="$1"

	local PARAMS_TMP
	PARAMS_TMP="$(mktemp "${AMNEZIAWG_DIR}/params.tmp.XXXXXX")" || {
		echo -e "${ORANGE}WARNING: Unable to create temporary file for IPv6 normalization. Non-critical.${NC}"
		return 1
	}

	# Preserve existing params file mode (e.g., 400 vs 600) across the rewrite.
	local PARAMS_MODE="600"
	if [ -e "${AMNEZIAWG_DIR}/params" ]; then
		PARAMS_MODE="$(stat -c '%a' "${AMNEZIAWG_DIR}/params" 2>/dev/null || echo "600")"
	fi

	if serializeParams "${PARAMS_TMP}" && 
	   mv -f "${PARAMS_TMP}" "${AMNEZIAWG_DIR}/params"; then
		chmod "${PARAMS_MODE}" "${AMNEZIAWG_DIR}/params"
	else
		rm -f "${PARAMS_TMP}"
		echo -e "${ORANGE}WARNING: Failed to rewrite params with normalized IPv6. Non-critical.${NC}"
	fi

	# Also normalize the Address line in the server config for full consistency.
	# Scoped to ^Address to avoid touching PostUp/PostDown firewalld rules,
	# which must keep the original form so removal matches on shutdown.
	if sed -i "/^Address = /s|${ORIG_IPV6}/64|${SERVER_AWG_IPV6}/64|" "${SERVER_AWG_CONF}" 2>/dev/null; then
		echo -e "${GREEN}Normalized Address IPv6: ${ORIG_IPV6} -> ${SERVER_AWG_IPV6}${NC}"
	fi
}

function loadParams() {
	if ! validateParamsFile; then
		echo -e "${RED}Failed to validate params file. Aborting parameter loading.${NC}" >&2
		exit 1
	fi

	local NEEDS_UPDATE=0
	# Track IPv6 normalization separately from protocol migration;
	# a cosmetic rewrite should not trigger the migration warning
	local IPV6_CHANGED=0
	if [[ "${_MIGRATE_ORIG_IPV6}" != "${SERVER_AWG_IPV6}" ]]; then
		IPV6_CHANGED=1
	fi

	if migrateS3S4; then
		NEEDS_UPDATE=1
	fi

	if migrateH1H4; then
		NEEDS_UPDATE=1
	fi

	# Persist migrated values to params file and update server config
	if [[ ${NEEDS_UPDATE} == 1 ]]; then
		persistMigration "${_MIGRATE_ORIG_IPV6}" "${IPV6_CHANGED}"
	fi

	if [[ ${NEEDS_UPDATE} == 0 ]] && [[ ${IPV6_CHANGED} == 1 ]]; then
		quietIPv6Rewrite "${_MIGRATE_ORIG_IPV6}"
	fi
}

function manageMenu() {
	local MENU_OPTION=""
	echo "AmneziaWG server installer (https://github.com/wiresock/amneziawg-install)"
	echo ""
	echo "It looks like AmneziaWG is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Regenerate all client configs (using current server parameters)"
	echo "   5) Uninstall AmneziaWG"
	echo "   6) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		regenerateClients
		;;
	5)
		uninstallAmneziaWG
		;;
	6)
		exit 0
		;;
	esac
}

# ── Non-interactive client management ─────────────────────────────────────────
#
# These functions support the --add-client and --remove-client flags,
# enabling fully non-interactive client lifecycle management from the
# amneziawg-web panel or other automation tooling.
#
# Contract:
#   --add-client NAME     → validates name, creates client config, exits 0 on success
#   --remove-client NAME  → validates name, removes client config, exits 0 on success
#   --list-clients        → lists all client names (one per line), exits 0
#
# On error, prints a message to stderr and exits with a non-zero code.

function nonInteractiveAddClient() {
	local CLIENT_NAME="$1"

	# Validate the name format (same rules as interactive mode)
	if [[ -z "${CLIENT_NAME}" ]]; then
		echo "ERROR: client name must not be empty" >&2
		exit 1
	fi
	if ! [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
		echo "ERROR: client name must be alphanumeric (plus underscores/dashes)" >&2
		exit 1
	fi
	if [[ ${#CLIENT_NAME} -gt 15 ]]; then
		echo "ERROR: client name must be at most 15 characters" >&2
		exit 1
	fi

	# Ensure params are loaded and config path is set
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	# Check for duplicate name
	if [[ $(grep -c -xF "### Client ${CLIENT_NAME}" "${SERVER_AWG_CONF}") != 0 ]]; then
		echo "ERROR: a client named '${CLIENT_NAME}' already exists" >&2
		exit 1
	fi

	# Auto-assign the first available IP pair (same logic as AUTO_INSTALL)
	local BASE_IP DOT_IP DOT_EXISTS IPV6_EXISTS CLIENT_AWG_IPV4 CLIENT_AWG_IPV6
	BASE_IP="${SERVER_AWG_IPV4%.*}"

	local NORMALIZED_SERVER_IPV6 BASE_IPV6
	NORMALIZED_SERVER_IPV6=$(normalizeIPv6 "${SERVER_AWG_IPV6}")
	BASE_IPV6=$(echo "${NORMALIZED_SERVER_IPV6}" | cut -d':' -f1-4)

	local FREE_FOUND=0
	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -cF "${BASE_IP}.${DOT_IP}/32" "${SERVER_AWG_CONF}")
		local CLIENT_IPV6_CANDIDATE
		CLIENT_IPV6_CANDIDATE=$(normalizeIPv6 "${BASE_IPV6}::${DOT_IP}")
		IPV6_EXISTS=0
		while IFS= read -r _existing_ip_cidr; do
			local _existing_ip="${_existing_ip_cidr%/*}"
			local _normalized_existing
			_normalized_existing=$(normalizeIPv6 "${_existing_ip}")
			if [[ "${_normalized_existing}" == "${CLIENT_IPV6_CANDIDATE}" ]]; then
				IPV6_EXISTS=1
				break
			fi
		done < <(grep -oE '([0-9a-fA-F:]+)/128' "${SERVER_AWG_CONF}")
		if [[ ${DOT_EXISTS} == '0' && ${IPV6_EXISTS} == '0' ]]; then
			FREE_FOUND=1
			break
		fi
	done

	if [[ ${FREE_FOUND} -eq 0 ]]; then
		echo "ERROR: no free IP addresses available (max 253 clients)" >&2
		exit 1
	fi

	CLIENT_AWG_IPV4="${BASE_IP}.${DOT_IP}"
	CLIENT_AWG_IPV6=$(normalizeIPv6 "${BASE_IPV6}::${DOT_IP}")

	# Generate key pair
	local CLIENT_PRIV_KEY CLIENT_PUB_KEY CLIENT_PRE_SHARED_KEY
	CLIENT_PRIV_KEY=$(awg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
	CLIENT_PRE_SHARED_KEY=$(awg genpsk)

	# Non-interactive mode writes client configs to a dedicated directory under
	# AMNEZIAWG_DIR with restrictive root-only permissions. This avoids writing
	# into home directories and keeps access scoped to privileged callers.
	local HOME_DIR="${AMNEZIAWG_DIR}/clients"
	mkdir -p "${HOME_DIR}"
	chmod 700 "${HOME_DIR}"

	local CLIENT_DNS="${CLIENT_DNS_1}"
	if [[ -n "${CLIENT_DNS_2}" ]]; then
		CLIENT_DNS="${CLIENT_DNS_1},${CLIENT_DNS_2}"
	fi

	local CLIENT_AWG_IPV6_DISPLAY
	CLIENT_AWG_IPV6_DISPLAY=$(compressIPv6 "${CLIENT_AWG_IPV6}")

	# Include IPv6 in the client Address/route list only when enabled (issue #51).
	local CLIENT_ADDRESS="${CLIENT_AWG_IPV4}/32"
	if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
		CLIENT_ADDRESS="${CLIENT_ADDRESS},${CLIENT_AWG_IPV6_DISPLAY}/128"
	fi
	local CLIENT_ALLOWED_IPS
	if ! CLIENT_ALLOWED_IPS=$(prepareClientAllowedIPs "${ALLOWED_IPS}" "${ENABLE_IPV6:-y}"); then
		echo -e "${RED}ERROR: ALLOWED_IPS has no usable routes after applying ENABLE_IPV6=${ENABLE_IPV6:-y}: ${ALLOWED_IPS}${NC}"
		return 1
	fi

	# If SERVER_PUB_IP is IPv6, normalize brackets
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		SERVER_PUB_IP="${SERVER_PUB_IP#\[}"
		SERVER_PUB_IP="${SERVER_PUB_IP%\]}"
		SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
	local ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	local OLD_UMASK
	OLD_UMASK="$(umask)"
	umask 077

	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_ADDRESS}
DNS = ${CLIENT_DNS}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${CLIENT_ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	umask "${OLD_UMASK}"

	local client_conf
	client_conf="${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
	chmod 600 "${client_conf}" 2>/dev/null || true

	# Copy the config to the web panel directory (or adjust permissions in
	# place when the file is already there) so the web panel service user can
	# read it.
	copyToWebPanelDir "${client_conf}"

	# Add peer to server config. Include the IPv6 /128 only when IPv6 is enabled.
	local PEER_ALLOWED_IPS="${CLIENT_AWG_IPV4}/32"
	if [[ "${ENABLE_IPV6:-y}" == "y" ]]; then
		PEER_ALLOWED_IPS="${PEER_ALLOWED_IPS},${CLIENT_AWG_IPV6}/128"
	fi
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${PEER_ALLOWED_IPS}" >>"${SERVER_AWG_CONF}"

	# Preserve stdout for the generated client config path expected by callers.
	# Route any informational/repair output from helper setup to stderr.
	ensureAmneziawgKernelModule 1>&2
	if ! awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}") 2>/tmp/amneziawg-syncconf.err; then
		local sync_err
		sync_err="$(cat /tmp/amneziawg-syncconf.err 2>/dev/null || true)"
		rm -f /tmp/amneziawg-syncconf.err
		echo "ERROR: failed to sync AmneziaWG interface '${SERVER_AWG_NIC}' after adding client '${CLIENT_NAME}'" >&2
		if [[ -n "${sync_err}" ]]; then
			echo "${sync_err}" >&2
		fi
		exit 1
	fi
	rm -f /tmp/amneziawg-syncconf.err

	# Print the config path to stdout for the caller
	echo "${client_conf}"
}

function nonInteractiveRemoveClient() {
	local CLIENT_NAME="$1"

	if [[ -z "${CLIENT_NAME}" ]]; then
		echo "ERROR: client name must not be empty" >&2
		exit 1
	fi
	if ! [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ ]]; then
		echo "ERROR: client name contains unsafe characters" >&2
		exit 1
	fi
	if [[ ${#CLIENT_NAME} -gt 15 ]]; then
		echo "ERROR: client name must be at most 15 characters" >&2
		exit 1
	fi

	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	# Check the client exists
	if [[ $(grep -c -xF "### Client ${CLIENT_NAME}" "${SERVER_AWG_CONF}") == 0 ]]; then
		echo "ERROR: no client named '${CLIENT_NAME}' found" >&2
		exit 1
	fi

	# Remove [Peer] block
	# Note: CLIENT_NAME is validated to [a-zA-Z0-9_-]+ so it cannot contain
	# sed metacharacters — safe to interpolate directly.
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

	# Remove client config file (non-interactive configs are stored under
	# ${AMNEZIAWG_DIR}/clients to keep them in a traversable directory).
	local CLIENT_DIR="${AMNEZIAWG_DIR}/clients"
	rm -f "${CLIENT_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
	removeFromWebPanelDir "${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	local sync_err
	sync_err=""
	ensureAmneziawgKernelModule >&2
	if ! sync_err="$(awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}") 2>&1)"; then
		echo "ERROR: failed to sync AmneziaWG interface '${SERVER_AWG_NIC}' after removing client '${CLIENT_NAME}'" >&2
		if [[ -n "${sync_err}" ]]; then
			echo "${sync_err}" >&2
		fi
		exit 1
	fi

	echo "OK"
}

function nonInteractiveListClients() {
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 || true
}

# Only run main logic when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	# ── Non-interactive flags ─────────────────────────────────────────────
	#
	# These flags allow automation tooling (e.g. amneziawg-web) to invoke
	# client lifecycle operations without interactive prompts.
	#
	# Usage:
	#   amneziawg-install.sh --add-client <NAME>
	#   amneziawg-install.sh --remove-client <NAME>
	#   amneziawg-install.sh --list-clients
	#
	# Requires AmneziaWG to be already installed (params file must exist).
	case "${1:-}" in
		--add-client)
			if [[ -z "${2:-}" ]]; then
				echo "ERROR: --add-client requires a client name argument" >&2
				exit 1
			fi
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			loadParams
			nonInteractiveAddClient "$2"
			exit $?
			;;
		--remove-client)
			if [[ -z "${2:-}" ]]; then
				echo "ERROR: --remove-client requires a client name argument" >&2
				exit 1
			fi
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			loadParams
			nonInteractiveRemoveClient "$2"
			exit $?
			;;
		--list-clients)
			initialCheck
			if [[ ! -e "${AMNEZIAWG_DIR}/params" ]]; then
				echo "ERROR: AmneziaWG is not installed (params file missing)" >&2
				exit 1
			fi
			loadParams
			nonInteractiveListClients
			exit $?
			;;
	esac

	# ── Default interactive flow ──────────────────────────────────────────
	# Check for root, virt, OS...
	initialCheck

	# Check if AmneziaWG is already installed and load params
	if [[ -e "${AMNEZIAWG_DIR}/params" ]]; then
		if [[ "${OS}" == "ubuntu" ]]; then
			refreshConfiguredUbuntuAmneziaPpa
		fi
		loadParams
		manageMenu
	else
		installAmneziaWG
	fi
fi
