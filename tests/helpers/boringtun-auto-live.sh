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
# learns from. acnone runs none and sends no such datagram: its peer stays
# unresolved. acsipinj runs none too, but before it starts, its port sends one
# SIP request line (`boringtun-imitation-wire.py send sip`, 27 bytes), the
# hint a SIP client's imitation leaves before its handshake: the server must
# then shape SIP for that peer under AWG 2.0. Under AWG 3.0 with an S prefix
# of 31 bytes or more the same hint must leave the peer random; BoringTun as
# a client refuses SIP with header protection there itself, which is why the
# hint is planted. The installed daemon logs at error level only, so the
# header-protection refusal itself is shown by
# tests/test-boringtun-auto-hint-live.sh, which reads BoringTun's warning.
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
# and until its traffic has passed. What the checks hold the recorded
# datagrams to:
#   dns, quic, stun: every datagram either has that imitation's S prefix shape
#     or is that protocol's probe reply to the client's own imitation
#     datagrams (classify-auto), and at least 10 are shaped;
#   sip, sipinj (AWG 2.0): the per-kind SIP rule of every packet kind, as
#     for fixed sip (bt_wire_assert_sip);
#   none, and sipinj under AWG 3.0: at least 10 datagrams, none with a dns,
#     stun or sip shape.
# What BoringTun learned for each peer is read from the wire only: it does
# not report it, and neither does the installer.
#
# Requires from the caller: INSTALLER, IF, PORT, HOST_ADDR, NS, CLIENT_ADDR,
# VETH_CLIENT, SERVER_TUNNEL_ADDR, WORK, CLIENT_BIN, WIRE, check, ok, bad,
# wait_for, record_config_secrets, params_s, params_layout and
# tests/helpers/boringtun-wire-checks.sh.

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

# Record the server's datagrams to one client while that client starts (or
# runs) and moves traffic, then check them against what its imitation makes
# the server learn. EXPECT is dns, quic, stun, sip (per-kind rule) or random
# (no dns, stun or sip shape). START is 1 to start the client inside the
# capture, so that its imitation datagrams, handshake and responses are
# recorded, 0 for a client that is already up.
bt_auto_observe() { # <label> <name> <expect> <start 1|0>
	local LABEL="$1" NAME="$2" EXPECT="$3" START="$4" CAPTURE="${WORK}/auto-$2.capture" COUNTS TOTAL SHAPED REPLIES OTHER UP
	local -a LAYOUT=()
	[[ "${EXPECT}" != sip ]] || LAYOUT=("$(params_layout)" "$(bt_auto_public_key "${NAME}")")
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
	if [[ "${EXPECT}" == sip ]]; then
		bt_wire_assert_sip "${LABEL}: ${NAME}" "${CAPTURE}" "$(params_s S1),$(params_s S2),$(params_s S3),$(params_s S4)" \
			init:optional "response:$( ((START)) && echo required || echo optional)" cookie:optional transport:required &&
			echo "    (${LABEL}: $(bt_wire_pooled_shaped) server datagrams to ${NAME} carry a SIP request line)"
		return
	fi
	if ! COUNTS="$(python3 "${WIRE}" classify-auto "$([[ "${EXPECT}" == random ]] && echo none || echo "${EXPECT}")" "${CAPTURE}")" ||
		[[ ! "${COUNTS}" =~ ^(0|[1-9][0-9]*)\ (0|[1-9][0-9]*)\ (0|[1-9][0-9]*)\ (0|[1-9][0-9]*)$ ]]; then
		bad "${LABEL}: ${NAME}'s capture has a valid classification ('${COUNTS:-}')"
		return
	fi
	read -r TOTAL SHAPED REPLIES OTHER <<<"${COUNTS}"
	echo "    (${LABEL}: to ${NAME}, ${TOTAL} server datagrams: ${SHAPED} shaped, ${REPLIES} probe replies, ${OTHER} other)"
	if [[ "${EXPECT}" == random ]]; then
		check "${LABEL}: the server sent ${NAME} datagrams (${TOTAL})" test "${TOTAL}" -ge 10
		check "${LABEL}: none of them has a dns, stun or sip shape: its peer is unresolved, with random S padding" test "${SHAPED}" -eq 0
	else
		check "${LABEL}: at least 10 datagrams to ${NAME} have the ${EXPECT}-shaped S prefix (${SHAPED})" test "${SHAPED}" -ge 10
		check "${LABEL}: every datagram to ${NAME} is ${EXPECT}-shaped or a ${EXPECT} probe reply to its own imitation (${OTHER} other)" test "${OTHER}" -eq 0
	fi
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
# again, transport only.
bt_auto_mixed_clients() {
	local NAME EXPECT ENDPOINT PIDS=() FAILED_PINGS=0 PID
	echo "--- auto: six clients with different imitation settings share one server port"
	echo "    (under this server's layout, the 247-byte SIP probe would fit: $(python3 "${WIRE}" candidates probe sip "$(params_layout)" 2>&1); the 27-byte hint fits: $(python3 "${WIRE}" candidates send sip "$(params_layout)" 2>&1))"
	for NAME in ${BT_AUTO_CLIENTS}; do
		EXPECT="${BT_AUTO_IMITATE[${NAME}]}"
		[[ "${EXPECT}" != none ]] || EXPECT=random
		[[ -z "${BT_AUTO_INJECT[${NAME}]}" ]] || EXPECT="${BT_AUTO_INJECT[${NAME}]}"
		bt_auto_observe "auto, AWG 2.0" "${NAME}" "${EXPECT}" 1
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
	for NAME in acdns acquic acstun acsip acnone; do
		EXPECT="${BT_AUTO_IMITATE[${NAME}]}"
		[[ "${EXPECT}" != none ]] || EXPECT=random
		bt_auto_observe "auto, all connected" "${NAME}" "${EXPECT}" 0
	done
}

# Under AWG 3.0 the clients reconnect with their regenerated configs. A
# learned dns is shaped as before. acsipinj's hint is planted and proven as
# under AWG 2.0, where this server learned it from the same datagram; with an
# S prefix of 31 bytes or more its peer must keep random padding. That this is
# BoringTun's header-protection refusal, and not a hint that never counted, is
# not visible here (the installed daemon logs errors only): the evidence is
# the proven hint, the AWG 2.0 control above, and the refusal warning that
# tests/test-boringtun-auto-hint-live.sh reads from the same binary.
# BoringTun clients cannot run sip with header protection at those sizes, so
# acsip does not take part.
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
	bt_auto_observe "auto, AWG 3.0" acdns dns 1
	bt_auto_observe "auto, AWG 3.0" acnone random 1
	if ((LARGEST >= 31)); then
		bt_auto_observe "auto, AWG 3.0, a proven SIP hint with an S prefix of ${LARGEST} bytes" acsipinj random 1
	else
		echo "    (every S prefix is 30 bytes or less: a learned sip stays random there anyway)"
	fi
	for NAME in acquic acstun; do
		bt_auto_start "${NAME}" && wait_for 20 bt_auto_ping "${NAME}"
		check "auto, AWG 3.0: ${NAME} reaches the server" bt_auto_ping "${NAME}" 5
	done
}
