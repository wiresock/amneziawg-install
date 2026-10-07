# shellcheck shell=bash
# The process contracts and result checks that the live imitation wire tests
# share: tests/test-boringtun-host-live.sh (the installer-managed server, its
# S sizes random) and tests/test-boringtun-sip-wire-live.sh (two peers with
# fixed S sizes). Both run the capture and replay children of
# tests/helpers/boringtun-imitation-wire.py through these functions and judge
# its per-kind result here, so the two cannot drift apart.
#
# The caller provides ok, bad and check (its own counters) and WIRE, the
# helper's path.
#
# Children are owned by identity, not by number. Bash reaps background
# children on its own and the kernel may give a reaped child's PID to another
# process, so a PID alone names nothing. Each child started here records its
# own PID, start time and parent, and waits; the parent tracks that handle in
# BT_WIRE_CHILDREN and only then lets the child run its command
# (bt_wire_spawn, bt_wire_child). An interruption at any point therefore
# finds the child either tracked or not yet running anything, and a child
# whose registration fails or is abandoned never runs its command. A signal
# goes only through a pidfd opened before the identity is checked (the
# helper's "owned"), and a child is waited for only when no other child of
# this shell can hold its PID (bt_wire_collect). bt_wire_cleanup ends and
# collects the tracked children, and touches no other process.
#
# A child's success is its exit status 0 together with its complete, exact
# transcript; neither alone is enough, and output it left behind never stands
# in for either. A capture that passes these checks has produced an internally
# consistent record of what its packet socket delivered over the required
# interval; that is not proof that every datagram on the wire was received.

BT_WIRE_CHILDREN=()
BT_WIRE_DIR=""
BT_WIRE_KINDS="init response cookie transport"
BT_WIRE_SUMMARIES="unknown ambiguous unresolved malformed"

# ── Owned children ───────────────────────────────────────────────────────────
# The current time in centiseconds since boot, in BT_WIRE_NOW, read without
# starting a process.
bt_wire_now() {
	local UPTIME REST
	read -r UPTIME REST </proc/uptime
	UPTIME="${UPTIME/./}"
	BT_WIRE_NOW=$((10#${UPTIME}))
}
# "PID START PPID" of the shell process that runs this, from its own
# /proc/self/stat (START is field 22, the start time in clock ticks), read by
# that shell itself.
bt_wire_self_identity() {
	local LINE REST FIELDS=()
	read -r LINE </proc/self/stat || return 1
	REST="${LINE##*) }"
	read -r -a FIELDS <<<"${REST}"
	printf '%s %s %s\n' "${BASHPID}" "${FIELDS[19]}" "${FIELDS[1]}"
}
# The background child itself: record the identity in ID, wait until the
# parent has tracked it (ID.go), then become the command (exec keeps the PID
# and the start time). A shell function -- the unit tests' stand-ins for
# external commands -- is called instead, and does its own exec. Until the
# go it runs nothing, and it gives up with status 125, its command never
# started, once the parent withdraws (ID.no, or ID removed: a refused
# registration, or cleanup), once the parent is gone (it was reparented),
# or after 60 s.
bt_wire_child() { # <identity file> <command...>
	local ID="$1" PARENT LINE I FIELDS=()
	shift
	bt_wire_self_identity >"${ID}.new" && mv -f -- "${ID}.new" "${ID}" || exit 125
	read -r _ _ PARENT <"${ID}" || exit 125
	for ((I = 0; I < 6000; I++)); do
		[[ -e "${ID}" && ! -e "${ID}.no" ]] || exit 125
		[[ -e "${ID}.go" ]] && break
		read -r LINE </proc/self/stat || exit 125
		read -r -a FIELDS <<<"${LINE##*) }"
		[[ "${FIELDS[1]}" == "${PARENT}" ]] || exit 125
		sleep 0.01
	done
	[[ -e "${ID}" && -e "${ID}.go" && ! -e "${ID}.no" ]] || exit 125
	if declare -F -- "$1" >/dev/null; then
		"$@"
		exit
	fi
	exec "$@"
}
bt_wire_track() { # <handle>
	BT_WIRE_CHILDREN+=("$1")
}
bt_wire_untrack() { # <handle>
	local HANDLE KEEP=()
	for HANDLE in "${BT_WIRE_CHILDREN[@]}"; do
		[[ "${HANDLE}" == "$1" ]] || KEEP+=("${HANDLE}")
	done
	BT_WIRE_CHILDREN=("${KEEP[@]}")
}
# Start COMMAND as an owned background child, its handle "PID START PARENT"
# in the variable VAR and in BT_WIRE_CHILDREN. Its stdout goes to OUT, its
# stderr to ERR ("-": to OUT as well). The child is tracked before it is let
# run its command; if it does not record its identity within 10 s, or not
# its own, it is withdrawn without running anything and this returns 1.
bt_wire_spawn() { # <var> <out> <err|-> <command...>
	local -n BT_WIRE_HANDLE_REF="$1"
	local OUT="$2" ERR="$3" ID PID LINE I
	shift 3
	BT_WIRE_HANDLE_REF=""
	if [[ -z "${BT_WIRE_DIR}" || ! -d "${BT_WIRE_DIR}" ]]; then
		BT_WIRE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bt-wire.XXXXXX")" || return 1
	fi
	ID="$(mktemp "${BT_WIRE_DIR}/child.XXXXXX")" || return 1
	if [[ "${ERR}" == - ]]; then
		bt_wire_child "${ID}" "$@" >"${OUT}" 2>&1 </dev/null &
	else
		bt_wire_child "${ID}" "$@" >"${OUT}" 2>"${ERR}" </dev/null &
	fi
	PID=$!
	LINE=""
	for ((I = 0; I < 500; I++)); do
		read -r LINE 2>/dev/null <"${ID}" && [[ -n "${LINE}" ]] && break
		sleep 0.02
	done
	if [[ ! "${LINE}" =~ ^${PID}\ [0-9]+\ ${BASHPID}$ ]]; then
		: >"${ID}.no"
		echo "    child ${PID} did not record its identity ('${LINE}'); it was withdrawn before running anything"
		return 1
	fi
	# Tracked first, released second: interrupted between the two, cleanup
	# ends the waiting child; before the first, the child runs nothing.
	bt_wire_track "${LINE}"
	# shellcheck disable=SC2034 # a nameref: this sets the caller's variable
	BT_WIRE_HANDLE_REF="${LINE}"
	if ! : >"${ID}.go"; then
		echo "    child ${PID} could not be released"
		bt_wire_stop "${LINE}" 5
		# shellcheck disable=SC2034 # a nameref: this sets the caller's variable
		BT_WIRE_HANDLE_REF=""
		return 1
	fi
}
# What has become of an owned child, in BT_WIRE_PROC: "running", "zombie"
# (exited, not yet collected by this shell), "gone" (no process has its PID:
# this shell already reaped it) or "replaced" (another process has its PID;
# its parent in BT_WIRE_PROC_PPID). Reads /proc only and starts no process,
# so that nothing between this and a wait can take the PID.
bt_wire_state() { # <handle>
	local PID START PARENT LINE REST FIELDS=()
	read -r PID START PARENT <<<"$1"
	BT_WIRE_PROC_PPID=""
	if ! read -r LINE 2>/dev/null <"/proc/${PID}/stat"; then
		BT_WIRE_PROC=gone
		return 0
	fi
	REST="${LINE##*) }"
	read -r -a FIELDS <<<"${REST}"
	BT_WIRE_PROC_PPID="${FIELDS[1]}"
	if [[ "${FIELDS[19]}" != "${START}" ]]; then
		BT_WIRE_PROC=replaced
	elif [[ "${FIELDS[0]}" == [ZX] ]]; then
		BT_WIRE_PROC=zombie
	else
		BT_WIRE_PROC=running
	fi
}
# Signal an owned child through a pidfd, after its identity is confirmed;
# returns 1, sending nothing, if it no longer runs.
bt_wire_signal() { # <handle> <TERM|KILL>
	local PID START PARENT
	read -r PID START PARENT <<<"$1"
	python3 "${WIRE}" owned "${PID}" "${START}" "$2" >/dev/null 2>&1
}
# Wait until an owned child no longer runs, at most SECONDS; 1 if it still does.
bt_wire_await() { # <handle> <seconds>
	local I
	for ((I = 0; I < $2 * 10; I++)); do
		bt_wire_state "$1"
		[[ "${BT_WIRE_PROC}" != running ]] && return 0
		sleep 0.1
	done
	bt_wire_state "$1"
	[[ "${BT_WIRE_PROC}" != running ]]
}
# The exit status of an owned child that no longer runs, in BT_WIRE_STATUS,
# and the handle untracked. A zombie child is waited for: it still holds its
# PID. One this shell already reaped has its status cached by the shell. A
# PID now held by another child of this shell is never waited for, because
# that would wait for the other child: the status is then "unknown", as it is
# from any shell other than the child's parent, which cannot wait for it.
# Returns 1 (BT_WIRE_STATUS=running) for a child that still runs.
bt_wire_collect() { # <handle>
	local PID START PARENT
	read -r PID START PARENT <<<"$1"
	bt_wire_state "$1"
	if [[ "${BT_WIRE_PROC}" != running && "${BASHPID}" != "${PARENT}" ]]; then
		BT_WIRE_STATUS=unknown
		bt_wire_untrack "$1"
		return 0
	fi
	case "${BT_WIRE_PROC}" in
		running)
			BT_WIRE_STATUS=running
			return 1
			;;
		zombie)
			wait "${PID}"
			BT_WIRE_STATUS=$?
			;;
		replaced)
			if [[ "${BT_WIRE_PROC_PPID}" == "${PARENT}" ]]; then
				BT_WIRE_STATUS=unknown
			else
				wait "${PID}" 2>/dev/null
				BT_WIRE_STATUS=$?
			fi
			;;
		*)
			wait "${PID}" 2>/dev/null
			BT_WIRE_STATUS=$?
			;;
	esac
	bt_wire_untrack "$1"
}
# End an owned child: SIGTERM, up to SECONDS, SIGKILL, up to 5 s; then
# collect it. BT_WIRE_STATUS as bt_wire_collect leaves it.
bt_wire_stop() { # <handle> <seconds>
	bt_wire_signal "$1" TERM || true
	if ! bt_wire_await "$1" "$2"; then
		bt_wire_signal "$1" KILL || true
		bt_wire_await "$1" 5 || true
	fi
	bt_wire_collect "$1" || true
}
# End and collect every tracked child: SIGTERM to all, then up to 5 s each
# before SIGKILL. Removes this shell's identity records.
bt_wire_cleanup() {
	local HANDLE
	for HANDLE in "${BT_WIRE_CHILDREN[@]}"; do
		bt_wire_signal "${HANDLE}" TERM || true
	done
	for HANDLE in "${BT_WIRE_CHILDREN[@]}"; do
		bt_wire_stop "${HANDLE}" 5
	done
	BT_WIRE_CHILDREN=()
	[[ -n "${BT_WIRE_DIR}" ]] && rm -rf -- "${BT_WIRE_DIR}"
	BT_WIRE_DIR=""
}
# Wait up to SECONDS for an owned child's first line in FILE, into
# BT_WIRE_FIRST_LINE: 0 if it matches PATTERN (an anchored regular
# expression; BASH_REMATCH holds its groups), 1 if it does not, if the child
# stops running first, or at the limit.
bt_wire_wait_first_line() { # <handle> <file> <pattern> <seconds>
	local I LINE
	BT_WIRE_FIRST_LINE=""
	for ((I = 0; I <= $4 * 10; I++)); do
		if read -r LINE 2>/dev/null <"$2" && [[ -n "${LINE}" ]]; then
			BT_WIRE_FIRST_LINE="${LINE}"
			[[ "${LINE}" =~ $3 ]]
			return
		fi
		bt_wire_state "$1"
		[[ "${BT_WIRE_PROC}" == running ]] || return 1
		sleep 0.1
	done
	return 1
}
bt_wire_show() { # <label> <file>
	[[ -e "$2" ]] && sed "s/^/    $1 | /" "$2"
	return 0
}

# ── Capture ──────────────────────────────────────────────────────────────────
# The capture's timing contract. Its ready line carries its ready clock and
# its "complete" line its end clock: CLOCK_BOOTTIME in centiseconds, which is
# this shell's /proc/uptime. The capture reads the ready clock once its
# socket is bound and completes only once its interval has passed since that
# reading. The interval it observed is therefore end clock minus ready clock:
# how long it took to become ready, and how long this shell took to notice
# that it ended, are outside it. This shell bounds both readings by its own:
# the ready clock lies between its clock just before the start and just after
# it saw the ready line, the end clock between the ready clock and its clock
# once it saw the capture end. The readings are the capture's own; the check
# holds a capture that ends early to the time it reports, whatever the
# delays around it, but it cannot catch a capture that reports times it did
# not live through.
#
# Start the capture in NETNS and wait up to 10 s for its "ready <pid> <start
# time> <ready clock>", which must name this very child, its clock within
# this shell's readings. Sets BT_WIRE_CAPTURE (its handle),
# BT_WIRE_CAPTURE_FILE, BT_WIRE_CAPTURE_SECONDS, BT_WIRE_CAPTURE_READY (its
# ready line) and BT_WIRE_CAPTURE_READY_CLOCK. On failure the child is ended
# and collected. A layout comes with the receiving peer's public key, under
# which the helper checks MAC1 consistency when a complete datagram fits
# more than one packet kind (its Evidence: MAC1 consistency and
# receiver-index correlation, not authentication). With BT_WIRE_CAPTURE_TO_PORT
# set, the capture records only the datagrams to that destination port
# (capture-to): the stream to one of several clients behind one address.
bt_wire_capture_start() { # <netns> <interface> <source> <port> <seconds> <file> [layout receiver-key]
	local NETNS="$1" FILE="$6" PID START PARENT BEFORE READY
	local -a COMMAND=(capture)
	[[ -z "${BT_WIRE_CAPTURE_TO_PORT:-}" ]] || COMMAND=(capture-to "${BT_WIRE_CAPTURE_TO_PORT}")
	shift
	BT_WIRE_CAPTURE=""
	BT_WIRE_CAPTURE_FILE="${FILE}"
	BT_WIRE_CAPTURE_SECONDS="$4"
	BT_WIRE_CAPTURE_READY=""
	BT_WIRE_CAPTURE_READY_CLOCK=""
	if [[ ! "${BT_WIRE_CAPTURE_SECONDS}" =~ ^[1-9][0-9]{0,4}$ ]]; then
		echo "    the capture interval '$4' is not a number of seconds"
		return 1
	fi
	rm -f -- "${FILE}" "${FILE}.state" "${FILE}.stop" "${FILE}.stop.new" "${FILE}.stderr"
	bt_wire_now
	BEFORE="${BT_WIRE_NOW}"
	bt_wire_spawn BT_WIRE_CAPTURE /dev/null "${FILE}.stderr" ip netns exec "${NETNS}" python3 "${WIRE}" "${COMMAND[@]}" "$@" || return 1
	read -r PID START PARENT <<<"${BT_WIRE_CAPTURE}"
	if bt_wire_wait_first_line "${BT_WIRE_CAPTURE}" "${FILE}.state" "^ready ${PID} ${START} (0|[1-9][0-9]{0,17})$" 10; then
		READY="${BASH_REMATCH[1]}"
		bt_wire_now
		if ((BEFORE <= READY && READY <= BT_WIRE_NOW)); then
			BT_WIRE_CAPTURE_READY="${BT_WIRE_FIRST_LINE}"
			BT_WIRE_CAPTURE_READY_CLOCK="${READY}"
			return 0
		fi
		echo "    the capture's ready clock ${READY} is not between ${BEFORE} and ${BT_WIRE_NOW}, this shell's clock before its start and after its ready line"
	fi
	bt_wire_stop "${BT_WIRE_CAPTURE}" 5
	echo "    the capture did not become ready as child ${PID} (status ${BT_WIRE_STATUS})"
	bt_wire_show state "${FILE}.state"
	bt_wire_show capture "${FILE}.stderr"
	BT_WIRE_CAPTURE=""
	return 1
}
# End the capture started last, and check its whole life:
#  - stop: it must still be running, its transcript exactly its own ready
#    line; then a fresh token in FILE.stop authorizes the stop, and SIGTERM
#    goes to that very child. It must end with exactly its ready line and
#    "stopped <records> <token>".
#  - complete: it must still be running (it outlived what it was to observe)
#    and end with exactly its ready line and "complete <records> <end
#    clock>", the end clock at least BT_WIRE_CAPTURE_SECONDS after its ready
#    clock and no later than this shell's clock once it saw the capture end
#    (the timing contract above).
# Either way it must exit 0 within SECONDS, and <records> must be the number
# of records in FILE. Prints the reason and returns 1 otherwise.
bt_wire_capture_finish() { # <file> <stop|complete> <seconds>
	local FILE="$1" MODE="$2" LIMIT="$3" PID START PARENT TOKEN="" RECORDS ENDED READY END="" SPAN WANT_END TRANSCRIPT=()
	read -r PID START PARENT <<<"${BT_WIRE_CAPTURE}"
	if [[ -z "${PID}" || "${FILE}" != "${BT_WIRE_CAPTURE_FILE}" || ! "${MODE}" =~ ^(stop|complete)$ ]]; then
		echo "    no capture of ${FILE} was started to ${MODE}"
		return 1
	fi
	bt_wire_state "${BT_WIRE_CAPTURE}"
	if [[ "${BT_WIRE_PROC}" != running ]]; then
		bt_wire_collect "${BT_WIRE_CAPTURE}" || true
		if [[ "${MODE}" == stop ]]; then
			echo "    the capture ended before its controlled stop (status ${BT_WIRE_STATUS})"
		else
			echo "    the capture ended before what it was to observe did (status ${BT_WIRE_STATUS})"
		fi
		bt_wire_show state "${FILE}.state"
		BT_WIRE_CAPTURE=""
		return 1
	fi
	if [[ "${MODE}" == stop ]]; then
		mapfile -t TRANSCRIPT <"${FILE}.state"
		if [[ "${#TRANSCRIPT[@]}" -ne 1 || "${TRANSCRIPT[0]}" != "${BT_WIRE_CAPTURE_READY}" ]]; then
			echo "    before its stop, the capture's transcript is not exactly its own ready line"
			bt_wire_show state "${FILE}.state"
			bt_wire_stop "${BT_WIRE_CAPTURE}" 5
			BT_WIRE_CAPTURE=""
			return 1
		fi
		TOKEN="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
		if [[ ! "${TOKEN}" =~ ^[0-9a-f]{32}$ ]] || ! printf '%s\n' "${TOKEN}" >"${FILE}.stop.new" ||
			! mv -f -- "${FILE}.stop.new" "${FILE}.stop"; then
			echo "    the stop could not be authorized"
			bt_wire_stop "${BT_WIRE_CAPTURE}" 5
			BT_WIRE_CAPTURE=""
			return 1
		fi
		if ! bt_wire_signal "${BT_WIRE_CAPTURE}" TERM; then
			bt_wire_collect "${BT_WIRE_CAPTURE}" || true
			echo "    the capture was no longer running when its stop was authorized (status ${BT_WIRE_STATUS})"
			bt_wire_show state "${FILE}.state"
			BT_WIRE_CAPTURE=""
			return 1
		fi
	fi
	if ! bt_wire_await "${BT_WIRE_CAPTURE}" "${LIMIT}"; then
		echo "    the capture did not end within ${LIMIT} s"
		bt_wire_stop "${BT_WIRE_CAPTURE}" 5
		BT_WIRE_CAPTURE=""
		return 1
	fi
	bt_wire_now
	ENDED="${BT_WIRE_NOW}"
	bt_wire_collect "${BT_WIRE_CAPTURE}" || true
	BT_WIRE_CAPTURE=""
	READY="${BT_WIRE_CAPTURE_READY_CLOCK}"
	RECORDS="$(wc -l <"${FILE}" 2>/dev/null)" || RECORDS=x
	mapfile -t TRANSCRIPT <"${FILE}.state"
	if [[ "${MODE}" == stop ]]; then
		WANT_END="stopped ${RECORDS} ${TOKEN}"
	elif [[ "${TRANSCRIPT[1]:-}" =~ ^complete\ ${RECORDS}\ (0|[1-9][0-9]{0,17})$ ]]; then
		WANT_END="${TRANSCRIPT[1]}"
		END="${BASH_REMATCH[1]}"
	else
		WANT_END="complete ${RECORDS} <end clock>"
	fi
	if [[ "${BT_WIRE_STATUS}" != 0 ]]; then
		echo "    the capture exited with status ${BT_WIRE_STATUS}, not 0"
	elif [[ "${#TRANSCRIPT[@]}" -ne 2 || "${TRANSCRIPT[0]}" != "${BT_WIRE_CAPTURE_READY}" || "${TRANSCRIPT[1]}" != "${WANT_END}" ]]; then
		echo "    the capture's transcript is not exactly '${BT_WIRE_CAPTURE_READY}', '${WANT_END}'"
	elif [[ "${MODE}" == complete ]] && ((END < READY || END > ENDED)); then
		echo "    the capture's end clock ${END} is not between its ready clock ${READY} and ${ENDED}, this shell's clock once it saw the capture end"
	elif [[ "${MODE}" == complete ]] && ((END - READY < BT_WIRE_CAPTURE_SECONDS * 100)); then
		printf -v SPAN '%d.%02d' $(((END - READY) / 100)) $(((END - READY) % 100))
		echo "    the capture was ready at ${READY} and completed at ${END} (centiseconds since boot): ${SPAN} s, short of its ${BT_WIRE_CAPTURE_SECONDS} s interval"
	else
		return 0
	fi
	bt_wire_show state "${FILE}.state"
	bt_wire_show capture "${FILE}.stderr"
	return 1
}

# ── Replay ───────────────────────────────────────────────────────────────────
# Start the replay in NETNS, its output in OUT, and wait up to 10 s for its
# "ready <pid> <start time>", which must name this very child. Sets
# BT_WIRE_REPLAY (its handle).
bt_wire_replay_start() { # <netns> <out> <replay arguments...>
	local NETNS="$1" OUT="$2" PID START PARENT
	shift 2
	BT_WIRE_REPLAY=""
	rm -f -- "${OUT}"
	bt_wire_spawn BT_WIRE_REPLAY "${OUT}" - ip netns exec "${NETNS}" python3 "${WIRE}" replay "$@" || return 1
	read -r PID START PARENT <<<"${BT_WIRE_REPLAY}"
	if bt_wire_wait_first_line "${BT_WIRE_REPLAY}" "${OUT}" "^ready ${PID} ${START}$" 10; then
		return 0
	fi
	bt_wire_stop "${BT_WIRE_REPLAY}" 5
	bt_wire_show replay "${OUT}"
	BT_WIRE_REPLAY=""
	return 1
}
# The replay must exit 0 within SECONDS, its whole output exactly its ready
# line and "replayed <count>".
bt_wire_replay_finish() { # <out> <count> <seconds>
	local PID START PARENT LINES=()
	read -r PID START PARENT <<<"${BT_WIRE_REPLAY}"
	if [[ -z "${PID}" ]]; then
		echo "    no replay was started"
		return 1
	fi
	if ! bt_wire_await "${BT_WIRE_REPLAY}" "$3"; then
		echo "    the replay did not end within $3 s"
		bt_wire_stop "${BT_WIRE_REPLAY}" 5
		BT_WIRE_REPLAY=""
		return 1
	fi
	bt_wire_collect "${BT_WIRE_REPLAY}" || true
	BT_WIRE_REPLAY=""
	mapfile -t LINES <"$1"
	if [[ "${BT_WIRE_STATUS}" == 0 && "${#LINES[@]}" -eq 2 && "${LINES[0]}" == "ready ${PID} ${START}" && "${LINES[1]}" == "replayed $2" ]]; then
		return 0
	fi
	echo "    replay: status ${BT_WIRE_STATUS}; expected status 0 and exactly 'ready ${PID} ${START}', 'replayed $2'"
	bt_wire_show replay "$1"
	return 1
}

# ── The per-kind SIP result ──────────────────────────────────────────────────
# Validate the complete output of `kinds sip` for sizes S1-S4 and keep it in
# BT_WIRE_SEEN, BT_WIRE_SHAPED, BT_WIRE_EXPECTED, BT_WIRE_VERDICT (by kind) and
# BT_WIRE_SUMMARY (by summary). Exactly eight rows in order: the four kinds
# with five fields each, then the four summaries with two. Counts are
# decimal, shaped never exceeds seen, the expectation is what S gives the
# kind, and the verdict is the one the counts give. Anything else -- missing,
# extra, repeated, reordered, empty, truncated or garbled output -- is
# refused with a reason in BT_WIRE_REASON.
bt_wire_validate_kinds() { # <output> <S1,S2,S3,S4>
	local OUTPUT="$1" SIZES=() ROWS=() KIND INDEX=0 NAME SEEN SHAPED EXPECTED VERDICT EXTRA WANT_EXPECTED WANT_VERDICT COUNT WANT_ROWS=8
	BT_WIRE_REASON=""
	declare -gA BT_WIRE_SEEN=() BT_WIRE_SHAPED=() BT_WIRE_EXPECTED=() BT_WIRE_VERDICT=() BT_WIRE_SUMMARY=()
	IFS=, read -r -a SIZES <<<"$2"
	if [[ "${#SIZES[@]}" -ne 4 ]]; then
		BT_WIRE_REASON="sizes '$2' are not S1,S2,S3,S4"
		return 1
	fi
	for KIND in 0 1 2 3; do
		if [[ ! "${SIZES[KIND]}" =~ ^(0|[1-9][0-9]{0,4})$ ]]; then
			BT_WIRE_REASON="S$((KIND + 1)) '${SIZES[KIND]}' is not a size"
			return 1
		fi
	done
	mapfile -t ROWS <<<"${OUTPUT}"
	if [[ "${#ROWS[@]}" -ne "${WANT_ROWS}" ]]; then
		BT_WIRE_REASON="${#ROWS[@]} result rows, not ${WANT_ROWS}"
		return 1
	fi
	for KIND in ${BT_WIRE_KINDS}; do
		read -r NAME SEEN SHAPED EXPECTED VERDICT EXTRA <<<"${ROWS[INDEX]}"
		if [[ "${NAME}" != "${KIND}" || -n "${EXTRA}" || -z "${VERDICT}" ]]; then
			BT_WIRE_REASON="row $((INDEX + 1)) '${ROWS[INDEX]}' is not a ${KIND} row"
			return 1
		fi
		if [[ ! "${SEEN}" =~ ^(0|[1-9][0-9]{0,8})$ || ! "${SHAPED}" =~ ^(0|[1-9][0-9]{0,8})$ ]] || ((SHAPED > SEEN)); then
			BT_WIRE_REASON="row '${ROWS[INDEX]}' has invalid counts"
			return 1
		fi
		WANT_EXPECTED=random
		((SIZES[INDEX] >= 31)) && WANT_EXPECTED=shaped
		if ((SEEN == 0)); then
			WANT_VERDICT=unobserved
		elif [[ "${WANT_EXPECTED}" == shaped ]]; then
			WANT_VERDICT=FAIL
			((SHAPED == SEEN)) && WANT_VERDICT=ok
		else
			WANT_VERDICT=FAIL
			((SHAPED == 0)) && WANT_VERDICT=ok
		fi
		if [[ "${EXPECTED}" != "${WANT_EXPECTED}" || "${VERDICT}" != "${WANT_VERDICT}" ]]; then
			BT_WIRE_REASON="row '${ROWS[INDEX]}' is inconsistent: S$((INDEX + 1))=${SIZES[INDEX]} gives '${WANT_EXPECTED} ${WANT_VERDICT}'"
			return 1
		fi
		BT_WIRE_SEEN[${KIND}]="${SEEN}"
		BT_WIRE_SHAPED[${KIND}]="${SHAPED}"
		BT_WIRE_EXPECTED[${KIND}]="${EXPECTED}"
		BT_WIRE_VERDICT[${KIND}]="${VERDICT}"
		INDEX=$((INDEX + 1))
	done
	for KIND in ${BT_WIRE_SUMMARIES}; do
		read -r NAME COUNT EXTRA <<<"${ROWS[INDEX]}"
		if [[ "${NAME}" != "${KIND}" || -n "${EXTRA}" || ! "${COUNT}" =~ ^(0|[1-9][0-9]{0,8})$ ]]; then
			BT_WIRE_REASON="row $((INDEX + 1)) '${ROWS[INDEX]}' is not a ${KIND} row"
			return 1
		fi
		BT_WIRE_SUMMARY[${KIND}]="${COUNT}"
		INDEX=$((INDEX + 1))
	done
}
# Run `kinds sip` on CAPTURE and validate its whole output. The helper's
# status and its output are both required; its stderr is shown on failure.
bt_wire_kinds() { # <capture> <S1,S2,S3,S4>
	local OUTPUT
	if ! OUTPUT="$(python3 "${WIRE}" kinds sip "$1" "$2" 2>"$1.kinds-stderr")"; then
		BT_WIRE_REASON="the helper failed: $(tr '\n' ' ' <"$1.kinds-stderr")"
		return 1
	fi
	bt_wire_validate_kinds "${OUTPUT}" "$2"
}
# The SIP verdicts for every recorded relevant observation of one capture, as
# assertions. Each of init, response, cookie and transport gets exactly one
# rule: "required" (seen, and its rule held), "optional" (its rule held if
# seen, its absence stated if not) or "absent" (none seen). A rule may name
# the shaping the scenario expects (kind:required:shaped), which must be what
# that kind's S gives. No recorded datagram may be unknown, ambiguous,
# unresolved or malformed. A result that does not validate is one failed
# assertion.
bt_wire_assert_sip() { # <label> <capture> <S1,S2,S3,S4> <kind:rule[:shaped|random]>...
	local LABEL="$1" CAPTURE="$2" SIZE_LIST="$3" SPEC KIND RULE RULES=() INDEX S SUMMARY WANT
	shift 3
	declare -A RULES_BY_KIND=() WANT_BY_KIND=()
	for SPEC in "$@"; do
		IFS=: read -r KIND RULE WANT <<<"${SPEC}"
		RULES_BY_KIND[${KIND}]="${RULE}"
		WANT_BY_KIND[${KIND}]="${WANT}"
		RULES+=("${SPEC}")
	done
	for KIND in ${BT_WIRE_KINDS}; do
		if [[ ! "${RULES_BY_KIND[${KIND}]:-}" =~ ^(required|optional|absent)$ ||
			! "${WANT_BY_KIND[${KIND}]:-}" =~ ^(|shaped|random)$ ]] || ((${#RULES[@]} != 4)); then
			bad "${LABEL}: the check names one rule for each packet kind ($*)"
			return 1
		fi
	done
	if ! bt_wire_kinds "${CAPTURE}" "${SIZE_LIST}"; then
		bad "${LABEL}: the capture has a complete, valid per-kind result (${BT_WIRE_REASON})"
		return 1
	fi
	INDEX=0
	for KIND in ${BT_WIRE_KINDS}; do
		INDEX=$((INDEX + 1))
		S="$(cut -d, -f"${INDEX}" <<<"${SIZE_LIST}")"
		RULE="${RULES_BY_KIND[${KIND}]}"
		WANT="${WANT_BY_KIND[${KIND}]}"
		[[ -z "${WANT}" ]] || check "${LABEL}: S${INDEX}=${S} makes ${KIND}s ${WANT}" test "${BT_WIRE_EXPECTED[${KIND}]}" = "${WANT}"
		case "${RULE}" in
			required)
				check "${LABEL}: ${KIND} datagrams were recorded (${BT_WIRE_SEEN[${KIND}]})" test "${BT_WIRE_SEEN[${KIND}]}" -ge 1
				check "${LABEL}: recorded ${KIND}s are ${BT_WIRE_EXPECTED[${KIND}]} for S${INDEX}=${S} (${BT_WIRE_SHAPED[${KIND}]}/${BT_WIRE_SEEN[${KIND}]} carry a SIP request line)" \
					test "${BT_WIRE_VERDICT[${KIND}]}" = ok
				;;
			optional)
				if [[ "${BT_WIRE_VERDICT[${KIND}]}" == unobserved ]]; then
					echo "    (${LABEL}: no ${KIND} datagram was recorded; S${INDEX}=${S} would make them ${BT_WIRE_EXPECTED[${KIND}]})"
				else
					check "${LABEL}: recorded ${KIND}s are ${BT_WIRE_EXPECTED[${KIND}]} for S${INDEX}=${S} (${BT_WIRE_SHAPED[${KIND}]}/${BT_WIRE_SEEN[${KIND}]} carry a SIP request line)" \
						test "${BT_WIRE_VERDICT[${KIND}]}" = ok
				fi
				;;
			absent)
				check "${LABEL}: no ${KIND} datagram was recorded (${BT_WIRE_SEEN[${KIND}]})" test "${BT_WIRE_VERDICT[${KIND}]}" = unobserved
				;;
		esac
	done
	for SUMMARY in ${BT_WIRE_SUMMARIES}; do
		check "${LABEL}: no recorded server datagram is ${SUMMARY} (${BT_WIRE_SUMMARY[${SUMMARY}]})" test "${BT_WIRE_SUMMARY[${SUMMARY}]}" -eq 0
	done
}
# How many datagrams of the last validated result carry a request line, over
# all packet kinds: what the pooled check this replaces looked at.
bt_wire_pooled_shaped() {
	local KIND TOTAL=0
	for KIND in ${BT_WIRE_KINDS}; do
		TOTAL=$((TOTAL + BT_WIRE_SHAPED[${KIND}]))
	done
	echo "${TOTAL}"
}
