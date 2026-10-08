#!/bin/bash
# shellcheck disable=SC2034 # the arrays are read by the sourcing test
# Live evidence for BoringTun's imitation mode auto, sourced by
# tests/test-boringtun-host-live.sh once the installer runs the server with
# --set-boringtun-imitation auto: several authenticated clients with different
# imitation settings share the one server port, two or three of them behind
# each client address on ports of their own. Every client is a copy of the
# verified binary (CLIENT_BIN) configured with its own installer-generated
# config; the server is the installed, verified daemon.
#
# Clients, with the server address their config is pointed at:
#   acdns, acquic, acsipinj   in NS  (CLIENT_ADDR, ports 41001, 41002, 41006)
#   acsip, acstun, acnone     in NS2 (BT_AUTO_CLIENT_ADDR2, ports 41003-41005)
# acdns, acquic, acsip and acstun run --imitate-protocol dns, quic, sip and
# stun, so their own pre-handshake imitation datagrams are what the server
# can learn from, those of them that are eligible hints under the layout.
# acnone runs none and sends no such datagram. acsipinj runs none too, but
# before it starts, its port sends one SIP request line
# (`boringtun-imitation-wire.py send sip`, 27 bytes), the hint a SIP client's
# imitation leaves before its handshake, which no layout makes AmneziaWG
# traffic. Under AWG 3.0 with an S prefix of 31 bytes or more the policy
# refuses the sip it selects; BoringTun as a client refuses SIP with header
# protection there itself, which is why the hint is planted. The installed
# daemon logs at error level only, so the header-protection refusal itself is
# shown by tests/test-boringtun-auto-hint-live.sh, which reads BoringTun's
# warning.
#
# The planted hint is evidence only if it is one. bt_auto_plant shows that it
# fits no AmneziaWG packet kind (it is shorter than the smallest, so the
# server hands it to probe classification, the only door that records a
# hint; a longer SIP datagram is an AmneziaWG transport whenever its bytes at
# S4 fall in H4, and then it is never a hint), that it was sent, that exactly
# it reached the server's interface from the client's address and port before
# the client existed, and, after the traffic, that the peer's authenticated
# handshake came within the 30 s a hint lives.
#
# Each client's stream is recorded on its side, from the server's address
# and port to that client's port only (capture-to), before the client starts
# and until its traffic has passed. What the server selected for each peer is
# derived from what reached the server (bt_auto_judge_stage, below), never
# from what it sent, and each stream is held to that: a learned dns, quic or
# stun shapes every datagram but that protocol's probe replies, a learned sip
# follows the per-kind SIP rule (bt_wire_assert_sip), and an unresolved peer
# gets no dns, stun or sip shape. Whether a real client's own imitation
# datagrams are eligible hints depends on the random layout, so no real
# client is assumed to be learned here; tests/test-boringtun-auto-hint-live.sh
# shows each protocol learned under a fixed layout. BoringTun does not report
# what it learned, and neither does the installer.
#
# Requires from the caller: INSTALLER, IF, PORT, HOST_ADDR, NS, CLIENT_ADDR,
# VETH_CLIENT, SERVER_TUNNEL_ADDR, WORK, CLIENT_BIN, WIRE, check, ok, bad,
# wait_for, main_pid, record_config_secrets, params_s, params_layout and
# tests/helpers/boringtun-wire-checks.sh; and bt_auto_record_start before the
# command that starts the daemon serving bt_auto_mixed_clients or
# bt_auto_header_protection.

BT_AUTO_NS2="awgcli2"
BT_AUTO_VETH_HOST2="awgvh1"
BT_AUTO_VETH_CLIENT2="awgvc1"
BT_AUTO_HOST_ADDR2="198.51.100.1"
BT_AUTO_CLIENT_ADDR2="198.51.100.2"
BT_AUTO_CLIENTS="acdns acquic acsip acstun acnone acsipinj"
# A name for the host's own network namespace, so that a capture can run on a
# host-side link (bt_wire_capture_start enters a named namespace).
BT_AUTO_HOST_NS="awgautohost"
BT_AUTO_HOST_NS_MADE=0
# How long a planted hint lives in the pinned BoringTun (HINT_LIFETIME).
BT_AUTO_HINT_LIFETIME=30
declare -gA BT_AUTO_NS=() BT_AUTO_VETH=() BT_AUTO_HOST_VETH=() BT_AUTO_SERVER=() BT_AUTO_ADDR=() BT_AUTO_PORT=() BT_AUTO_METRIC=()
declare -gA BT_AUTO_IMITATE=() BT_AUTO_INJECT=() BT_AUTO_CONF=() BT_AUTO_TUNNEL=() BT_AUTO_PID=() BT_AUTO_PLANTED=()

bt_auto_define() { # <name> <ns 1|2> <port> <metric> <imitate> [inject]
	if [[ "$2" == 1 ]]; then
		BT_AUTO_NS[$1]="${NS}"
		BT_AUTO_VETH[$1]="${VETH_CLIENT}"
		BT_AUTO_HOST_VETH[$1]="${VETH_HOST}"
		BT_AUTO_SERVER[$1]="${HOST_ADDR}"
		BT_AUTO_ADDR[$1]="${CLIENT_ADDR}"
	else
		BT_AUTO_NS[$1]="${BT_AUTO_NS2}"
		BT_AUTO_VETH[$1]="${BT_AUTO_VETH_CLIENT2}"
		BT_AUTO_HOST_VETH[$1]="${BT_AUTO_VETH_HOST2}"
		BT_AUTO_SERVER[$1]="${BT_AUTO_HOST_ADDR2}"
		BT_AUTO_ADDR[$1]="${BT_AUTO_CLIENT_ADDR2}"
	fi
	BT_AUTO_PORT[$1]="$3"
	BT_AUTO_METRIC[$1]="$4"
	BT_AUTO_IMITATE[$1]="$5"
	BT_AUTO_INJECT[$1]="${6:-}"
}

# The second client network, joined to the host by a veth pair of its own.
bt_auto_network() {
	ip netns add "${BT_AUTO_NS2}" &&
		ip link add "${BT_AUTO_VETH_HOST2}" type veth peer name "${BT_AUTO_VETH_CLIENT2}" &&
		ip link set "${BT_AUTO_VETH_CLIENT2}" netns "${BT_AUTO_NS2}" &&
		ip addr add "${BT_AUTO_HOST_ADDR2}/24" dev "${BT_AUTO_VETH_HOST2}" &&
		ip link set "${BT_AUTO_VETH_HOST2}" up &&
		ip -n "${BT_AUTO_NS2}" addr add "${BT_AUTO_CLIENT_ADDR2}/24" dev "${BT_AUTO_VETH_CLIENT2}" &&
		ip -n "${BT_AUTO_NS2}" link set "${BT_AUTO_VETH_CLIENT2}" up &&
		ip -n "${BT_AUTO_NS2}" link set lo up
}

bt_auto_stop() { # <name>
	local NAME="$1"
	if [[ -n "${BT_AUTO_PID[${NAME}]:-}" ]]; then
		kill "${BT_AUTO_PID[${NAME}]}" 2>/dev/null
		wait "${BT_AUTO_PID[${NAME}]}" 2>/dev/null
		BT_AUTO_PID[${NAME}]=""
	fi
	rm -f "/var/run/wireguard/${NAME}.sock" "/var/run/amneziawg/${NAME}.sock"
}

bt_auto_cleanup() {
	local NAME
	for NAME in ${BT_AUTO_CLIENTS}; do
		bt_auto_stop "${NAME}"
	done
	ip netns delete "${BT_AUTO_NS2}" 2>/dev/null
	ip link delete "${BT_AUTO_VETH_HOST2}" 2>/dev/null
	# Only the name this run gave the host's namespace; the namespace stays.
	if ((BT_AUTO_HOST_NS_MADE)); then
		ip netns delete "${BT_AUTO_HOST_NS}" 2>/dev/null
		BT_AUTO_HOST_NS_MADE=0
	fi
	return 0
}

# Plant a client's hint before the client starts, and prove each step: the
# datagram fits no AmneziaWG packet kind under this server's layout (and is
# shorter than any, so no S size, H range or key makes it one), the send
# succeeded, and exactly that datagram reached the server's interface from
# the client's address and port, recorded on the host side before the client
# exists. BT_AUTO_PLANTED records when it was sent, for
# bt_auto_hint_in_lifetime.
bt_auto_plant() { # <label> <name>
	local LABEL="$1" NAME="$2" KIND="${BT_AUTO_INJECT[$2]}" CANDIDATES SENT RC ARRIVED="${WORK}/auto-$2.hint" WANT
	BT_AUTO_PLANTED[${NAME}]=""
	CANDIDATES="$(python3 "${WIRE}" candidates send "${KIND}" "$(params_layout)" 2>&1)"
	check "${LABEL}: ${NAME}'s ${KIND} hint fits no AmneziaWG packet kind under this server's layout, and is shorter than any (${CANDIDATES})" \
		bash -c '[[ "$1" =~ ^([0-9]+)\ none$ ]] && ((BASH_REMATCH[1] < 32))' _ "${CANDIDATES}"
	if ! BT_WIRE_CAPTURE_TO_PORT="${PORT}" bt_wire_capture_start "${BT_AUTO_HOST_NS}" "${BT_AUTO_HOST_VETH[${NAME}]}" \
		"${BT_AUTO_ADDR[${NAME}]}" "${BT_AUTO_PORT[${NAME}]}" 60 "${ARRIVED}"; then
		bad "${LABEL}: the server-side capture of ${NAME}'s port ${BT_AUTO_PORT[${NAME}]} started"
		return 1
	fi
	BT_AUTO_PLANTED[${NAME}]="$(bt_auto_uptime)"
	SENT="$(ip netns exec "${BT_AUTO_NS[${NAME}]}" python3 "${WIRE}" send "${KIND}" "${BT_AUTO_SERVER[${NAME}]}" "${PORT}" "${BT_AUTO_PORT[${NAME}]}" 2>&1)"
	RC=$?
	check "${LABEL}: the hint was sent from ${BT_AUTO_ADDR[${NAME}]}:${BT_AUTO_PORT[${NAME}]} to ${BT_AUTO_SERVER[${NAME}]}:${PORT} (${SENT})" \
		bash -c '[[ "$1" == 0 && "$2" =~ ^sent\ [0-9]+$ ]]' _ "${RC}" "${SENT}"
	wait_for 5 test -s "${ARRIVED}"
	if ! bt_wire_capture_finish "${ARRIVED}" stop 10; then
		bad "${LABEL}: the server-side capture of ${NAME}'s port ran until its authorized stop"
		return 1
	fi
	WANT="$(python3 -c 'import importlib.util, sys
spec = importlib.util.spec_from_file_location("wire", sys.argv[1]); w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
print(w.HINTS[sys.argv[2]][:w.PREFIX_KEPT].hex())' "${WIRE}" "${KIND}")"
	check "${LABEL}: exactly that datagram reached the server's interface from ${BT_AUTO_ADDR[${NAME}]}:${BT_AUTO_PORT[${NAME}]}, before ${NAME} started" \
		test "$(cat "${ARRIVED}")" = "${WANT}"
}

# Boot time in centiseconds (CLOCK_BOOTTIME, as /proc/uptime gives it): one
# monotonic clock for the hint and the tunnel. BoringTun's own handshake
# timestamps follow the wall clock, which a container host may step.
bt_auto_uptime() {
	local UP
	read -r UP _ </proc/uptime
	printf '%s\n' "$((10#${UP%.*} * 100 + 10#${UP#*.}))"
}

# The peer's first authenticated handshake came after its hint, because the
# client did not exist before the hint reached the server, and before its
# first ping through the tunnel succeeded at UP. Within the hint's lifetime
# from the hint to that ping, the hint was there when the server selected the
# peer's imitation.
bt_auto_hint_in_lifetime() { # <label> <name> <tunnel up, boot centiseconds>
	check "$1: ${2}'s tunnel was up $(((${3:-0} - ${BT_AUTO_PLANTED[$2]:-0}) / 100)) s after its hint, within the ${BT_AUTO_HINT_LIFETIME} s a hint lives, so its handshake was too" \
		bash -c '[[ "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ ]] && (($2 >= $1 && $2 - $1 < $3 * 100))' _ \
		"${BT_AUTO_PLANTED[$2]:-}" "${3:-}" "${BT_AUTO_HINT_LIFETIME}"
}

# Start a client with the installer-generated config as it is now, its listen
# port fixed and its endpoint the server address of its network.
bt_auto_start() { # <name>
	local NAME="$1" NSX="${BT_AUTO_NS[$1]}"
	bt_auto_stop "${NAME}"
	ip netns exec "${NSX}" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "${CLIENT_BIN}" --foreground --disable-drop-privileges \
		--verbosity error --imitate-protocol "${BT_AUTO_IMITATE[${NAME}]}" "${NAME}" >"${WORK}/${NAME}.log" 2>&1 &
	BT_AUTO_PID[${NAME}]=$!
	if ! wait_for 10 test -S "/var/run/wireguard/${NAME}.sock"; then
		sed 's/^/    client | /' "${WORK}/${NAME}.log"
		return 1
	fi
	install -m 0600 "${BT_AUTO_CONF[${NAME}]}" "${WORK}/${NAME}.conf" &&
		sed -i "s/^Endpoint = .*:${PORT}\$/Endpoint = ${BT_AUTO_SERVER[${NAME}]}:${PORT}/" "${WORK}/${NAME}.conf" &&
		grep -qx "Endpoint = ${BT_AUTO_SERVER[${NAME}]}:${PORT}" "${WORK}/${NAME}.conf" &&
		awg-quick strip "${WORK}/${NAME}.conf" >"${WORK}/${NAME}.setconf" &&
		sed -i "/^\[Interface\]\$/a ListenPort = ${BT_AUTO_PORT[${NAME}]}" "${WORK}/${NAME}.setconf" &&
		awg setconf "${NAME}" "${WORK}/${NAME}.setconf" &&
		ip -n "${NSX}" addr add "${BT_AUTO_TUNNEL[${NAME}]}/32" dev "${NAME}" &&
		ip -n "${NSX}" link set "${NAME}" up &&
		ip -n "${NSX}" route add "${SERVER_TUNNEL_ADDR}/32" dev "${NAME}" metric "${BT_AUTO_METRIC[${NAME}]}" &&
		test "$(awg show "${NAME}" listen-port 2>/dev/null)" = "${BT_AUTO_PORT[${NAME}]}"
}

bt_auto_ping() { # <name> [count]
	ip netns exec "${BT_AUTO_NS[$1]}" ping -I "$1" -c "${2:-1}" -i 0.2 -W 2 "${SERVER_TUNNEL_ADDR}" >/dev/null 2>&1
}

# What the server must have selected for a peer is never read from what it
# sent. For each stage, a record runs on the host from before the daemon that
# serves the stage started until the stage's last observation ended: every
# datagram that reaches the host from either client address to the server
# port, whole, with its kernel arrival time (the helper's record). At the
# stage's end the helper's auto-expect derives, for each observation of a
# client, what the server selected for that peer from that record and the
# client side's evidence of acceptance (when each of its processes started
# and first pinged through the tunnel), by the pinned BoringTun's own rules
# replayed over every history that evidence allows: which of the client's
# datagrams fit an AmneziaWG packet kind under the server's layout (never a
# hint), which protocol each other one is detected as, the listener's and a
# connected socket's hints and their 30 s, which initiations were accepted,
# and the header-protection policy. Each capture is then held to that
# expectation (bt_wire_auto_verdict, or the per-kind SIP rule for a learned
# sip); a record that cannot decide fails the observation, and so does one
# not complete through it.
BT_AUTO_STAGE=""
BT_AUTO_RECORD=""
BT_AUTO_RECORD_READY=""
BT_AUTO_EPOCH=""
BT_AUTO_EPOCH_PID=""
BT_AUTO_SEQ=0
BT_AUTO_PENDING=()
# The client side's evidence of acceptance, per client and stage: when each of
# its processes started (BT_AUTO_BORN) and "<started>:<first ping>" for every
# observation (BT_AUTO_EST), so that some initiation it sent between them was
# accepted and answered by then.
declare -gA BT_AUTO_BORN=() BT_AUTO_EST=()

# Header protection is on (AWG 3.0 and 3.1) and its key, from params; the key
# goes only to a file of mode 0600 that auto-expect reads.
bt_auto_protected() {
	[[ "$(sed -n "s/^AWG_PROTOCOL_VERSION='\\(.*\\)'\$/\\1/p" /etc/amnezia/amneziawg/params)" =~ ^3 ]]
}
bt_auto_hp_key() {
	sed -n "s/^AWG_HEADER_PROTECTION_KEY='\\([A-Za-z0-9+\\/]*=\\)'\$/\\1/p" /etc/amnezia/amneziawg/params
}
bt_auto_trailers() {
	if bt_auto_protected && [[ "$(sed -n "s/^AWG_RANDOM_TRAILERS='\\(.*\\)'\$/\\1/p" /etc/amnezia/amneziawg/params)" == on ]]; then
		echo on
	else
		echo off
	fi
}
# A process's start, in centiseconds of CLOCK_BOOTTIME (field 22 of its
# stat, in clock ticks, rounded down): when a daemon's peer state was empty.
bt_auto_process_start() { # <pid>
	python3 -c 'import os, sys
fields = open("/proc/%d/stat" % int(sys.argv[1])).read().rsplit(")", 1)[1].split()
print(int(fields[19]) * 100 // os.sysconf("SC_CLK_TCK"))' "$1" 2>/dev/null
}

# Start the stage's record, before anything that restarts the daemon.
bt_auto_record_start() { # <stage>
	BT_AUTO_STAGE="$1"
	BT_AUTO_RECORD="${WORK}/auto-${1// /-}.record"
	BT_AUTO_RECORD_READY=""
	BT_AUTO_EPOCH=""
	BT_AUTO_EPOCH_PID=""
	BT_AUTO_PENDING=()
	BT_AUTO_BORN=()
	BT_AUTO_EST=()
	if BT_WIRE_CAPTURE_RECORD=1 BT_WIRE_CAPTURE_TO_PORT="${PORT}" bt_wire_capture_start - any \
		"${CLIENT_ADDR},${BT_AUTO_CLIENT_ADDR2}" any 3600 "${BT_AUTO_RECORD}" &&
		BT_AUTO_RECORD_READY="${BT_WIRE_CAPTURE_READY_CLOCK}" && bt_wire_capture_park auto-record; then
		ok "auto, $1: a record of what reaches the server from ${CLIENT_ADDR} and ${BT_AUTO_CLIENT_ADDR2} runs from before its daemon starts"
	else
		bad "auto, $1: a record of what reaches the server from ${CLIENT_ADDR} and ${BT_AUTO_CLIENT_ADDR2} runs from before its daemon starts"
		BT_AUTO_RECORD=""
	fi
}

# The daemon that serves the stage's clients, and its start: the record must
# have been ready by then, and the stage must end on that same daemon.
bt_auto_epoch() {
	BT_AUTO_EPOCH_PID="$(main_pid)"
	BT_AUTO_EPOCH="$(bt_auto_process_start "${BT_AUTO_EPOCH_PID}")"
	check "auto, ${BT_AUTO_STAGE}: the daemon serving its clients (PID ${BT_AUTO_EPOCH_PID}) started at ${BT_AUTO_EPOCH:-?}, after the record was ready at ${BT_AUTO_RECORD_READY:-?} (centiseconds since boot)" \
		bash -c '[[ "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ ]] && (($2 <= $1))' _ "${BT_AUTO_EPOCH}" "${BT_AUTO_RECORD_READY}"
}

# Record the server's datagrams to one client while that client starts (or
# runs) and moves traffic; it is judged at the end of the stage
# (bt_auto_judge_stage). START is 1 to start the client inside the capture,
# so that its imitation datagrams, handshake and responses are recorded, 0
# for a client that is already up. A client whose peer can learn sip is
# recorded per packet kind, unless header protection masks the tags.
bt_auto_observe() { # <label> <name> <start 1|0>
	local LABEL="$1" NAME="$2" START="$3" CAPTURE FORMAT=prefixes BEGIN END UP
	local -a LAYOUT=()
	BT_AUTO_SEQ=$((BT_AUTO_SEQ + 1))
	CAPTURE="${WORK}/auto-${BT_AUTO_SEQ}-${NAME}.capture"
	if [[ "${BT_AUTO_IMITATE[${NAME}]}" == sip || "${BT_AUTO_INJECT[${NAME}]}" == sip ]] && ! bt_auto_protected; then
		FORMAT=kinds
		LAYOUT=("$(params_layout)" "$(bt_auto_public_key "${NAME}")")
	fi
	if ((START)) && [[ -n "${BT_AUTO_INJECT[${NAME}]}" ]]; then
		bt_auto_stop "${NAME}"
		if ! bt_auto_plant "${LABEL}" "${NAME}"; then
			return
		fi
	fi
	if ! BT_WIRE_CAPTURE_TO_PORT="${BT_AUTO_PORT[${NAME}]}" bt_wire_capture_start "${BT_AUTO_NS[${NAME}]}" "${BT_AUTO_VETH[${NAME}]}" \
		"${BT_AUTO_SERVER[${NAME}]}" "${PORT}" 300 "${CAPTURE}" "${LAYOUT[@]}"; then
		bad "${LABEL}: the capture of the server's datagrams to ${NAME}'s port ${BT_AUTO_PORT[${NAME}]} started"
		return
	fi
	BEGIN="${BT_WIRE_CAPTURE_READY_CLOCK}"
	((START)) && BT_AUTO_BORN[${NAME}]="$(bt_auto_uptime)"
	if ((START)) && ! bt_auto_start "${NAME}"; then
		bad "${LABEL}: ${NAME} starts with its installer-generated config (imitation ${BT_AUTO_IMITATE[${NAME}]}${BT_AUTO_INJECT[${NAME}]:+, a planted ${BT_AUTO_INJECT[${NAME}]} hint})"
	fi
	UP=""
	if wait_for 20 bt_auto_ping "${NAME}" && UP="$(bt_auto_uptime)" && bt_auto_ping "${NAME}" 20; then
		ok "${LABEL}: ${NAME} (${BT_AUTO_ADDR[${NAME}]}:${BT_AUTO_PORT[${NAME}]}) reaches ${SERVER_TUNNEL_ADDR} through its tunnel (21 pings)"
	else
		bad "${LABEL}: ${NAME} (${BT_AUTO_ADDR[${NAME}]}:${BT_AUTO_PORT[${NAME}]}) reaches ${SERVER_TUNNEL_ADDR} through its tunnel"
		sed 's/^/    client | /' "${WORK}/${NAME}.log"
	fi
	if ((START)) && [[ -n "${BT_AUTO_INJECT[${NAME}]}" ]]; then
		bt_auto_hint_in_lifetime "${LABEL}" "${NAME}" "${UP}"
	fi
	if bt_wire_capture_finish "${CAPTURE}" stop 10; then
		ok "${LABEL}: the capture of ${NAME}'s stream ran from before its traffic until its authorized stop ($(wc -l <"${CAPTURE}") records)"
	else
		bad "${LABEL}: the capture of ${NAME}'s stream ran from before its traffic until its authorized stop"
		return
	fi
	bt_wire_now
	END="${BT_WIRE_NOW}"
	if [[ -n "${UP}" && -n "${BT_AUTO_BORN[${NAME}]:-}" ]]; then
		BT_AUTO_EST[${NAME}]+="${BT_AUTO_EST[${NAME}]:+,}${BT_AUTO_BORN[${NAME}]}:${UP}"
	fi
	BT_AUTO_PENDING+=("${LABEL}|${NAME}|${CAPTURE}|${FORMAT}|${BEGIN}|${END}|${START}")
}

# End the stage's record and judge each observation against what the record
# decides. A capture whose peer learned is also held to random, and one whose
# peer stayed unresolved to the protocols a prefix capture shows: each must
# fail, so the verdict tells the two apart on these very captures.
bt_auto_judge_stage() {
	local ENTRY LABEL NAME CAPTURE FORMAT BEGIN END START ORACLE EXPECT HP_FILE=- SERVER_KEY SIZES OTHER
	local LEARNED="" UNRESOLVED=""
	echo "--- auto, ${BT_AUTO_STAGE}: what the server selected, from what reached it"
	if [[ -z "${BT_AUTO_RECORD}" || -z "${BT_AUTO_EPOCH}" ]]; then
		bad "auto, ${BT_AUTO_STAGE}: the stage has a record and a daemon start, so that its observations can be judged"
		bt_wire_capture_resume auto-record >/dev/null 2>&1 && bt_wire_capture_finish "${BT_AUTO_RECORD}" stop 10 >/dev/null 2>&1
		BT_AUTO_PENDING=()
		return
	fi
	check "auto, ${BT_AUTO_STAGE}: the same daemon (PID ${BT_AUTO_EPOCH_PID}) served the whole stage" test "$(main_pid)" = "${BT_AUTO_EPOCH_PID}"
	if bt_wire_capture_resume auto-record && bt_wire_capture_finish "${BT_AUTO_RECORD}" stop 10; then
		ok "auto, ${BT_AUTO_STAGE}: the record ran until its authorized stop, after the stage's last observation ($(wc -l <"${BT_AUTO_RECORD}") datagrams)"
	else
		bad "auto, ${BT_AUTO_STAGE}: the record ran until its authorized stop, after the stage's last observation"
		BT_AUTO_PENDING=()
		return
	fi
	# The installer's record of the server's public key: BoringTun's UAPI
	# reports none. A wrong key would leave every record undecided.
	SERVER_KEY="$(sed -n "s/^SERVER_PUB_KEY='\\([A-Za-z0-9+\\/]*=\\)'\$/\\1/p" /etc/amnezia/amneziawg/params)"
	SIZES="$(params_s S1),$(params_s S2),$(params_s S3),$(params_s S4)"
	if bt_auto_protected; then
		HP_FILE="${WORK}/auto-hp.key"
		(umask 077 && bt_auto_hp_key >"${HP_FILE}")
	fi
	for ENTRY in "${BT_AUTO_PENDING[@]}"; do
		IFS='|' read -r LABEL NAME CAPTURE FORMAT BEGIN END START <<<"${ENTRY}"
		ORACLE="$(python3 "${WIRE}" auto-expect "${BT_AUTO_RECORD}" "${BT_AUTO_ADDR[${NAME}]}" "${BT_AUTO_PORT[${NAME}]}" \
			"$(params_layout)" "${SERVER_KEY}" "${HP_FILE}" "$(bt_auto_trailers)" "${BT_AUTO_EPOCH}" "${BEGIN}" "${END}" \
			"${BT_AUTO_EST[${NAME}]:--}" - 2>&1)"
		sed "s/^/    ${NAME} record | /" <<<"${ORACLE}"
		if [[ ! "${ORACLE##*$'\n'}" =~ ^expect\ (dns|quic|sip|stun|random)$ ]]; then
			bad "${LABEL}: what reached the server from ${NAME} decides what it selected (${ORACLE##*$'\n'})"
			continue
		fi
		EXPECT="${BASH_REMATCH[1]}"
		ok "${LABEL}: what reached the server from ${NAME} decides what it selected: ${EXPECT}"
		if [[ "${EXPECT}" == sip && "${FORMAT}" == kinds ]]; then
			bt_wire_assert_sip "${LABEL}: ${NAME}" "${CAPTURE}" "${SIZES}" \
				init:optional "response:$( ((START)) && echo required || echo optional)" cookie:optional transport:required &&
				echo "    (${LABEL}: $(bt_wire_pooled_shaped) server datagrams to ${NAME} carry a SIP request line)"
		elif bt_wire_auto_verdict "${EXPECT}" "${CAPTURE}" "${FORMAT}" "${SIZES}"; then
			ok "${LABEL}: the server's datagrams to ${NAME} are ${EXPECT}, as the record decided (${BT_WIRE_REASON})"
		else
			bad "${LABEL}: the server's datagrams to ${NAME} are ${EXPECT}, as the record decided (${BT_WIRE_REASON})"
			continue
		fi
		if [[ "${EXPECT}" == random ]]; then
			UNRESOLVED+=" ${NAME}"
			[[ "${FORMAT}" == prefixes ]] || continue
			for OTHER in dns quic stun; do
				if bt_wire_auto_verdict "${OTHER}" "${CAPTURE}" prefixes; then
					bad "${LABEL}: cross-control, ${NAME}'s capture also passes as ${OTHER} (${BT_WIRE_REASON})"
				else
					ok "${LABEL}: cross-control, ${NAME}'s capture fails as ${OTHER} (${BT_WIRE_REASON})"
				fi
			done
		else
			LEARNED+=" ${NAME}:${EXPECT}"
			# A random capture has no dns, stun or sip shape; QUIC's short
			# header, and sip under an S4 of 30 or less, look like random
			# padding, so those captures cannot be told from it that way.
			if [[ "${EXPECT}" == quic ]] || { [[ "${EXPECT}" == sip ]] && (($(params_s S4) < 31)); }; then
				echo "    (${LABEL}: no random cross-control for ${NAME}: a learned ${EXPECT} looks random to it here)"
			elif bt_wire_auto_verdict random "${CAPTURE}" "${FORMAT}" "${SIZES}"; then
				bad "${LABEL}: cross-control, ${NAME}'s capture also passes as random (${BT_WIRE_REASON})"
			else
				ok "${LABEL}: cross-control, ${NAME}'s capture fails as random (${BT_WIRE_REASON})"
			fi
		fi
	done
	[[ "${HP_FILE}" == - ]] || rm -f -- "${HP_FILE}"
	echo "    (auto, ${BT_AUTO_STAGE}: learned, per the record:${LEARNED:- none}; unresolved:${UNRESOLVED:- none})"
	echo "    (a real client left unresolved here sent no eligible datagram under this layout; test-boringtun-auto-hint-live.sh shows each protocol learned under a fixed layout)"
	BT_AUTO_PENDING=()
}

bt_auto_public_key() { # <name>
	sed -n 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' "${BT_AUTO_CONF[$1]}" | head -n 1 | awg pubkey
}

# Each client's endpoint, as the server sees it.
bt_auto_server_endpoint() { # <name>
	local KEY
	KEY="$(bt_auto_public_key "$1")" || return 1
	awg show "${IF}" endpoints 2>/dev/null | awk -v key="${KEY}" '$1 == key { print $2 }'
}

# Add the clients through the installer, and the second network.
bt_auto_setup() {
	local NAME CONF
	bt_auto_define acdns 1 41001 11 dns
	bt_auto_define acquic 1 41002 12 quic
	bt_auto_define acsipinj 1 41006 13 none sip
	bt_auto_define acsip 2 41003 11 sip
	bt_auto_define acstun 2 41004 12 stun
	bt_auto_define acnone 2 41005 13 none
	check "a second client network ${BT_AUTO_NS2} (${BT_AUTO_CLIENT_ADDR2}) is set up" bt_auto_network
	ip -n "${BT_AUTO_NS2}" route add default via "${BT_AUTO_HOST_ADDR2}" 2>/dev/null
	if ip netns list 2>/dev/null | grep -qE "^${BT_AUTO_HOST_NS}( |$)"; then
		bad "the namespace name ${BT_AUTO_HOST_NS} is free (it exists, is not this run's and is left alone)"
	elif ip netns attach "${BT_AUTO_HOST_NS}" "$$"; then
		BT_AUTO_HOST_NS_MADE=1
		ok "the host's own network namespace is named ${BT_AUTO_HOST_NS} for host-side captures"
	else
		bad "the host's own network namespace is named ${BT_AUTO_HOST_NS} for host-side captures"
	fi
	for NAME in ${BT_AUTO_CLIENTS}; do
		bash "${INSTALLER}" --add-client "${NAME}" >"${WORK}/${NAME}-add.private" 2>&1 </dev/null
		check "--add-client ${NAME} (its output, config and QR code stay private)" test "$?" -eq 0
		CONF="$(find /etc/amnezia/amneziawg/clients /root /home -maxdepth 2 -name "${IF}-client-${NAME}.conf" 2>/dev/null | head -n 1)"
		BT_AUTO_CONF[${NAME}]="${CONF}"
		if [[ -n "${CONF}" ]]; then
			record_config_secrets "${CONF}"
			BT_AUTO_TUNNEL[${NAME}]="$(sed -n 's/^Address = \([0-9.]*\)\/32.*/\1/p' "${CONF}" | head -n 1)"
		fi
		check "  the installer wrote ${NAME}'s config, with a tunnel address" test -n "${CONF}" -a -n "${BT_AUTO_TUNNEL[${NAME}]:-}"
	done
}

bt_auto_teardown() {
	local NAME
	bt_auto_cleanup
	for NAME in ${BT_AUTO_CLIENTS}; do
		bash "${INSTALLER}" --remove-client "${NAME}" >/dev/null 2>&1 </dev/null
		check "--remove-client ${NAME}" test "$?" -eq 0
	done
}

# The whole AWG 2.0 scenario: every client started inside its own capture,
# one after the other, so that each handshake is recorded; then all together
# again, transport only. The caller started the stage's record before the
# daemon that serves it.
bt_auto_mixed_clients() {
	local NAME ENDPOINT PIDS=() FAILED_PINGS=0 PID
	echo "--- auto: six clients with different imitation settings share one server port"
	echo "    (under this server's layout, the 247-byte SIP probe would fit: $(python3 "${WIRE}" candidates probe sip "$(params_layout)" 2>&1); the 27-byte hint fits: $(python3 "${WIRE}" candidates send sip "$(params_layout)" 2>&1))"
	bt_auto_epoch
	for NAME in ${BT_AUTO_CLIENTS}; do
		bt_auto_observe "auto, AWG 2.0" "${NAME}" 1
	done
	echo "--- auto: all six at once"
	for NAME in ${BT_AUTO_CLIENTS}; do
		bt_auto_ping "${NAME}" 10 &
		PIDS+=("$!")
	done
	for PID in "${PIDS[@]}"; do
		wait "${PID}" || FAILED_PINGS=$((FAILED_PINGS + 1))
	done
	check "auto: all six clients reach the server at the same time (10 pings each, ${FAILED_PINGS} clients failed)" test "${FAILED_PINGS}" -eq 0
	for NAME in ${BT_AUTO_CLIENTS}; do
		ENDPOINT="$(bt_auto_server_endpoint "${NAME}")"
		check "auto: the server sees ${NAME} at ${BT_AUTO_ADDR[${NAME}]}:${BT_AUTO_PORT[${NAME}]} (${ENDPOINT:-none})" \
			test "${ENDPOINT}" = "${BT_AUTO_ADDR[${NAME}]}:${BT_AUTO_PORT[${NAME}]}"
	done
	check "auto: three clients share ${CLIENT_ADDR} and three ${BT_AUTO_CLIENT_ADDR2}, each on its own port" \
		test "$(for NAME in ${BT_AUTO_CLIENTS}; do bt_auto_server_endpoint "${NAME}"; done | sort -u | cut -d: -f1 | uniq -c | awk '{print $1}' | tr '\n' ' ')" = "3 3 "
	for NAME in ${BT_AUTO_CLIENTS}; do
		bt_auto_observe "auto, all connected" "${NAME}" 0
	done
	bt_auto_judge_stage
}

# Under AWG 3.0 the clients reconnect with their regenerated configs, to the
# daemon the protocol change restarted (the caller started the stage's record
# before that). The record decides each peer under header protection: the
# tags are read through the mask, and a learned sip is refused while an S
# prefix is 31 bytes or more. acsipinj's hint is planted and proven as under
# AWG 2.0, where this server learned it from the same datagram when the record
# said so. That an unresolved acsipinj is BoringTun's header-protection
# refusal, and not a hint that never counted, is not visible here (the
# installed daemon logs errors only): the evidence is the record, the proven
# hint, and the refusal warning that tests/test-boringtun-auto-hint-live.sh
# reads from the same binary. BoringTun clients cannot run sip with header
# protection at those sizes, so acsip does not take part.
bt_auto_header_protection() {
	local NAME LARGEST=0 SIZE
	for NAME in S1 S2 S3 S4; do
		SIZE="$(params_s "${NAME}")"
		((SIZE > LARGEST)) && LARGEST="${SIZE}"
	done
	echo "--- auto under AWG 3.0 (largest S prefix ${LARGEST})"
	for NAME in ${BT_AUTO_CLIENTS}; do
		bt_auto_stop "${NAME}"
	done
	bt_auto_epoch
	for NAME in acdns acquic acstun acnone; do
		bt_auto_observe "auto, AWG 3.0" "${NAME}" 1
	done
	if ((LARGEST >= 31)); then
		bt_auto_observe "auto, AWG 3.0, a proven SIP hint with an S prefix of ${LARGEST} bytes" acsipinj 1
	else
		echo "    (every S prefix is 30 bytes or less: a learned sip stays random there anyway)"
	fi
	bt_auto_judge_stage
}
