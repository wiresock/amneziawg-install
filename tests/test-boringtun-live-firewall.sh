#!/usr/bin/env bash
# Unit tests of tests/helpers/boringtun-live-firewall.sh, the live test's
# firewall inspection: with nft and iptables-save mocked, a failed query is
# never taken as a result. A baseline, a comparison or an absence proof fails
# when a query fails, even after partial output, and passes only on
# successful queries.

set -uo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=helpers/boringtun-live-firewall.sh
source "${SCRIPT_DIR}/helpers/boringtun-live-firewall.sh"

T="$(mktemp -d "${TMPDIR:-/tmp}/live-firewall-tests.XXXXXX")"
trap 'rm -rf -- "${T}"' EXIT
PASS=0
FAIL=0
ok() {
	printf '  OK: %s\n' "$1"
	PASS=$((PASS + 1))
}
not_ok() {
	printf '  FAIL: %s\n' "$1"
	FAIL=$((FAIL + 1))
}
passes() { # <label> <command...>
	local LABEL="$1"
	shift
	if "$@"; then ok "${LABEL}"; else not_ok "${LABEL}"; fi
}
fails() { # <label> <command...>
	local LABEL="$1"
	shift
	if "$@"; then not_ok "${LABEL}"; else ok "${LABEL}"; fi
}

TABLE_RULES=$'table ip awg-awg0 {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tudp dport 51820 accept\n\t}\n}'
# nft, driven by NFT_TABLES (what `nft list tables` prints), NFT_TABLE (what
# `nft list table` prints) and NFT_TABLES_RC / NFT_TABLE_RC.
nft() {
	case "$1 $2" in
		"list tables") printf '%s\n' "${NFT_TABLES}"; return "${NFT_TABLES_RC:-0}" ;;
		"list table") printf '%s\n' "${NFT_TABLE}"; return "${NFT_TABLE_RC:-0}" ;;
	esac
	return 99
}
iptables-save() {
	printf '%s\n' "${MOCK_SAVED}"
	return "${MOCK_SAVED_RC:-0}"
}
NFT_CONF="${T}/nft.conf"
printf 'PostUp = nft add table ip awg-awg0\nPostDown = nft delete table ip awg-awg0\n' >"${NFT_CONF}"
IPT_CONF="${T}/ipt.conf"
printf 'PostUp = iptables -I INPUT -p udp --dport 51820 -j ACCEPT\n' >"${IPT_CONF}"
NFT=("${NFT_CONF}" awg0 51820 eth0)
IPT=("${IPT_CONF}" awg0 51820 eth0)
reset_mocks() {
	NFT_TABLES=$'table inet filter\ntable ip awg-awg0'
	NFT_TABLE="${TABLE_RULES}"
	NFT_TABLES_RC=0
	NFT_TABLE_RC=0
	MOCK_SAVED=$'*filter\n-A INPUT -p udp -m udp --dport 51820 -j ACCEPT\n-A FORWARD -i awg0 -j ACCEPT\n-A INPUT -i lo -j ACCEPT\nCOMMIT'
	MOCK_SAVED_RC=0
}

echo "=== nftables: the interface's own table"
reset_mocks
BASELINE=""
passes "a successful query of a present table is a baseline" fw_baseline BASELINE "${NFT[@]}"
[[ "${BASELINE}" == "${TABLE_RULES}" ]] && ok "  holding the table's rules" || not_ok "  holding the table's rules"
passes "the same rules after a restart compare equal" fw_unchanged "${BASELINE}" "${NFT[@]}"
NFT_TABLE="${TABLE_RULES}"$'\n\t\tudp dport 51820 accept'
fails "a duplicated rule after a restart is a difference" fw_unchanged "${BASELINE}" "${NFT[@]}"
reset_mocks
NFT_TABLES=$'table inet filter'
passes "a successful listing without the table proves it absent" fw_absent "${NFT[@]}"
reset_mocks
fails "a listing that still has the table is no absence" fw_absent "${NFT[@]}"

echo "=== Failed nft queries are never a result"
reset_mocks
NFT_TABLE=$'table ip awg-awg0 {\n\tchain input {'
NFT_TABLE_RC=42
BASELINE=""
fails "baseline: nft list table exits 42 after partial output" fw_baseline BASELINE "${NFT[@]}"
[[ -z "${BASELINE}" ]] && ok "  and sets no baseline" || not_ok "  and sets no baseline"
reset_mocks
NFT_TABLES_RC=42
fails "baseline: nft list tables exits 42" fw_baseline BASELINE "${NFT[@]}"
reset_mocks
NFT_TABLES=""
NFT_TABLES_RC=42
fails "stopped: nft list tables exits 42 with no output, which is no proof of absence" fw_absent "${NFT[@]}"
reset_mocks
NFT_TABLE_RC=42
fails "stopped: nft list table exits 42" fw_absent "${NFT[@]}"
reset_mocks
fw_baseline BASELINE "${NFT[@]}"
NFT_TABLE_RC=42
fails "restart: nft list table exits 42 with the same output" fw_unchanged "${BASELINE}" "${NFT[@]}"
reset_mocks
NFT_TABLES_RC=42
fails "restart: nft list tables exits 42" fw_unchanged "${BASELINE}" "${NFT[@]}"
fails "a server config that cannot be read fails" fw_owned_rules "${T}/missing.conf" awg0 51820 eth0

echo "=== iptables: the rules that name the interface"
reset_mocks
passes "a successful iptables-save with the rules is a baseline" fw_baseline BASELINE "${IPT[@]}"
[[ "$(grep -c . <<<"${BASELINE}")" == 2 ]] && ok "  holding only the interface's two rules" || not_ok "  holding only the interface's two rules"
passes "the same rules compare equal" fw_unchanged "${BASELINE}" "${IPT[@]}"
MOCK_SAVED+=$'\n-A FORWARD -i awg0 -j ACCEPT'
fails "a duplicated rule is a difference" fw_unchanged "${BASELINE}" "${IPT[@]}"
MOCK_SAVED=$'*filter\n-A INPUT -i lo -j ACCEPT\nCOMMIT'
passes "a successful iptables-save without them proves them absent" fw_absent "${IPT[@]}"
reset_mocks
MOCK_SAVED=$'*filter\n-A INPUT -p udp -m udp --dport 51820 -j ACCEPT'
MOCK_SAVED_RC=42
fails "baseline: iptables-save exits 42 after partial output" fw_baseline BASELINE "${IPT[@]}"
MOCK_SAVED=""
fails "stopped: iptables-save exits 42 with no output" fw_absent "${IPT[@]}"
reset_mocks
fw_baseline BASELINE "${IPT[@]}"
MOCK_SAVED_RC=42
fails "restart: iptables-save exits 42 with the same output" fw_unchanged "${BASELINE}" "${IPT[@]}"

echo
echo "BoringTun live firewall tests: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
