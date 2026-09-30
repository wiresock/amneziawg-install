#!/usr/bin/env bash
# Firewall inspection for tests/test-boringtun-host-live.sh, sourced by it and
# tested by tests/test-boringtun-live-firewall.sh. It reads the rules that an
# interface's PostUp hooks added, and a failed query is never a result: every
# function fails when the firewall could not be read, whatever it printed.

# fw_owned_rules <server config> <interface> <port> <public interface>
# Prints the interface's own rules as the firewall lists them, and succeeds
# only when every query succeeded; an empty output is then proof that none are
# present. With the installer's nftables hooks these are the interface's own
# table: `nft list tables` must succeed, and when it lists the table,
# `nft list table` must succeed too. Otherwise they are the iptables rules
# that name the interface, its port or the masquerade on the public
# interface, from an `iptables-save` that must succeed.
fw_owned_rules() {
	local CONF="$1" IF="$2" PORT="$3" PUBLIC="$4" DECLARED FAMILY="" TABLE="" TABLES RULES SAVED
	DECLARED="$(sed -n 's/^PostUp = nft add table \(ip\|inet\) \(awg-[A-Za-z0-9_.-]*\)$/\1 \2/p' "${CONF}")" || return 1
	read -r FAMILY TABLE <<<"${DECLARED%%$'\n'*}"
	if [[ -n "${TABLE}" ]]; then
		TABLES="$(nft list tables)" || return 1
		grep -qxF "table ${FAMILY} ${TABLE}" <<<"${TABLES}" || return 0
		RULES="$(nft list table "${FAMILY}" "${TABLE}")" || return 1
		printf '%s\n' "${RULES}"
		return 0
	fi
	SAVED="$(iptables-save)" || return 1
	grep -E -- "(-[io] ${IF}( |$)|--dport ${PORT}( |$)|-o ${PUBLIC} -j MASQUERADE)" <<<"${SAVED}" | LC_ALL=C sort
	return 0
}

# fw_baseline <variable> <config> <interface> <port> <public interface>
# Sets the variable to the interface's rules; succeeds only when the query
# succeeded and the rules are present.
fw_baseline() {
	local OUT
	OUT="$(fw_owned_rules "${@:2}")" || return 1
	[[ -n "${OUT}" ]] || return 1
	printf -v "$1" '%s' "${OUT}"
}

# fw_unchanged <baseline> <config> <interface> <port> <public interface>
# Succeeds only when the query succeeded and the rules equal the baseline, so
# a duplicated or missing rule fails.
fw_unchanged() {
	local OUT
	OUT="$(fw_owned_rules "${@:2}")" || return 1
	[[ -n "$1" && "${OUT}" == "$1" ]]
}

# fw_absent <config> <interface> <port> <public interface>
# Succeeds only when the query succeeded and proved the rules absent.
fw_absent() {
	local OUT
	OUT="$(fw_owned_rules "$@")" || return 1
	[[ -z "${OUT}" ]]
}
