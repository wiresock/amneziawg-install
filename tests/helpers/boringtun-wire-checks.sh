# shellcheck shell=bash
# The process contracts and result checks that the live imitation wire tests
# share: tests/test-boringtun-host-live.sh (the installer-managed server, its
# S sizes random) and tests/test-boringtun-sip-wire-live.sh (two peers with
# fixed S sizes). Both run the capture and replay children of
# tests/helpers/boringtun-imitation-wire.py through these functions and judge
# its per-kind result here, so the two cannot drift apart.
#
# The caller provides ok, bad and check (its own counters) and WIRE, the
# helper's path. Children started here are recorded in BT_WIRE_CHILDREN;
# bt_wire_cleanup terminates and reaps those still running, and nothing else.
#
# A child's success is its exit status 0 together with its completion
# marker; neither alone is enough, and output it left behind never stands in
# for either.

BT_WIRE_CHILDREN=()
BT_WIRE_KINDS="init response cookie transport"
BT_WIRE_SUMMARIES="unknown ambiguous malformed"

bt_wire_track() { # <pid>
	BT_WIRE_CHILDREN+=("$1")
}
bt_wire_untrack() { # <pid>
	local PID KEEP=()
	for PID in "${BT_WIRE_CHILDREN[@]}"; do
		[[ "${PID}" == "$1" ]] || KEEP+=("${PID}")
	done
	BT_WIRE_CHILDREN=("${KEEP[@]}")
}
# Whether a child of this shell has exited (a zombie until reaped) or is gone.
bt_wire_exited() { # <pid>
	local STATE
	STATE="$(sed -n 's/^.*) \([A-Za-z]\) .*/\1/p' "/proc/$1/stat" 2>/dev/null)"
	[[ -z "${STATE}" || "${STATE}" == Z ]]
}
# Reap an owned child within SECONDS, its status in BT_WIRE_STATUS. A child
# still running at the limit is killed and reaped, BT_WIRE_STATUS=timeout,
# and the function returns 1. Its PID cannot be reused before it is reaped,
# so the kill reaches only that child.
bt_wire_reap() { # <pid> <seconds>
	local PID="$1" I
	for ((I = 0; I < $2 * 10; I++)); do
		bt_wire_exited "${PID}" && break
		sleep 0.1
	done
	if ! bt_wire_exited "${PID}"; then
		kill -KILL "${PID}" 2>/dev/null
		wait "${PID}" 2>/dev/null
		bt_wire_untrack "${PID}"
		BT_WIRE_STATUS=timeout
		return 1
	fi
	wait "${PID}"
	BT_WIRE_STATUS=$?
	bt_wire_untrack "${PID}"
	return 0
}
# Terminate and reap every child still tracked: SIGTERM, up to 5 s, SIGKILL.
bt_wire_cleanup() {
	local PID
	for PID in "${BT_WIRE_CHILDREN[@]}"; do
		bt_wire_exited "${PID}" || kill -TERM "${PID}" 2>/dev/null
	done
	for PID in "${BT_WIRE_CHILDREN[@]}"; do
		bt_wire_reap "${PID}" 5 || true
	done
	BT_WIRE_CHILDREN=()
}
# Wait up to SECONDS for FILE to hold a line matching the extended regex.
bt_wire_wait_line() { # <file> <regex> <seconds>
	local I
	for ((I = 0; I < $3 * 10; I++)); do
		grep -qxE -- "$2" "$1" 2>/dev/null && return 0
		sleep 0.1
	done
	return 1
}

# ── Capture ──────────────────────────────────────────────────────────────────
# Start the capture in NETNS and wait up to 10 s for it to listen. Sets
# BT_WIRE_CAPTURE_PID. On failure the child is reaped and its stderr shown.
bt_wire_capture_start() { # <netns> <interface> <source> <port> <seconds> <file> [layout]
	local NETNS="$1" FILE="$6"
	shift
	rm -f -- "${FILE}" "${FILE}.state" "${FILE}.stderr"
	ip netns exec "${NETNS}" python3 "${WIRE}" capture "$@" 2>"${FILE}.stderr" &
	BT_WIRE_CAPTURE_PID=$!
	bt_wire_track "${BT_WIRE_CAPTURE_PID}"
	if bt_wire_wait_line "${FILE}.state" ready 10; then
		return 0
	fi
	kill -TERM "${BT_WIRE_CAPTURE_PID}" 2>/dev/null
	bt_wire_reap "${BT_WIRE_CAPTURE_PID}" 5 || true
	echo "    capture did not become ready (status ${BT_WIRE_STATUS:-?})"
	sed 's/^/    capture | /' "${FILE}.stderr" 2>/dev/null
	return 1
}
# End the capture: "stop" sends the controlled-stop SIGTERM, "complete" lets
# it run to its deadline. Either way it must exit 0 within SECONDS and end its
# state with "stopped <n>" (for stop) or "complete <n>" (for complete), where
# n is the number of records in FILE. A capture that ended before a stop was
# asked for did not cover the whole interval and fails.
bt_wire_capture_finish() { # <file> <stop|complete> <seconds>
	local FILE="$1" MODE="$2" WANT LAST RECORDS
	[[ "${MODE}" == stop ]] && kill -TERM "${BT_WIRE_CAPTURE_PID}" 2>/dev/null
	if ! bt_wire_reap "${BT_WIRE_CAPTURE_PID}" "$3"; then
		echo "    capture did not end within $3 s"
		return 1
	fi
	WANT=complete
	[[ "${MODE}" == stop ]] && WANT=stopped
	LAST="$(tail -n 1 "${FILE}.state" 2>/dev/null)"
	RECORDS="$(wc -l <"${FILE}" 2>/dev/null)" || RECORDS=x
	if [[ "${BT_WIRE_STATUS}" != 0 || ! "${LAST}" =~ ^${WANT}\ (0|[1-9][0-9]*)$ || "${LAST#* }" != "${RECORDS}" ]]; then
		echo "    capture: status ${BT_WIRE_STATUS}, final state '${LAST}', ${RECORDS} records; expected status 0 and '${WANT} ${RECORDS}'"
		sed 's/^/    capture | /' "${FILE}.stderr" 2>/dev/null
		return 1
	fi
}

# ── Replay ───────────────────────────────────────────────────────────────────
# Start the replay in NETNS, its output in OUT, and wait up to 10 s for it to
# listen. Sets BT_WIRE_REPLAY_PID.
bt_wire_replay_start() { # <netns> <out> <replay arguments...>
	local NETNS="$1" OUT="$2"
	shift 2
	rm -f -- "${OUT}"
	ip netns exec "${NETNS}" python3 "${WIRE}" replay "$@" >"${OUT}" 2>&1 &
	BT_WIRE_REPLAY_PID=$!
	bt_wire_track "${BT_WIRE_REPLAY_PID}"
	if bt_wire_wait_line "${OUT}" ready 10; then
		return 0
	fi
	kill -TERM "${BT_WIRE_REPLAY_PID}" 2>/dev/null
	bt_wire_reap "${BT_WIRE_REPLAY_PID}" 5 || true
	sed 's/^/    replay | /' "${OUT}" 2>/dev/null
	return 1
}
# The replay must exit 0 within SECONDS with exactly "ready" and
# "replayed <count>" as its output.
bt_wire_replay_finish() { # <out> <count> <seconds>
	if ! bt_wire_reap "${BT_WIRE_REPLAY_PID}" "$3"; then
		echo "    replay did not end within $3 s"
		return 1
	fi
	if [[ "${BT_WIRE_STATUS}" != 0 || "$(cat "$1" 2>/dev/null)" != "ready"$'\n'"replayed $2" ]]; then
		echo "    replay: status ${BT_WIRE_STATUS}; expected status 0 and output 'ready', 'replayed $2'"
		sed 's/^/    replay | /' "$1" 2>/dev/null
		return 1
	fi
}

# ── The per-kind SIP result ──────────────────────────────────────────────────
# Validate the complete output of `kinds sip` for sizes S1-S4 and keep it in
# BT_WIRE_SEEN, BT_WIRE_SHAPED, BT_WIRE_EXPECTED, BT_WIRE_VERDICT (by kind) and
# BT_WIRE_SUMMARY (by summary). Exactly seven rows in order: the four kinds
# with five fields each, then the three summaries with two. Counts are
# decimal, shaped never exceeds seen, the expectation is what S gives the
# kind, and the verdict is the one the counts give. Anything else -- missing,
# extra, repeated, reordered, empty, truncated or garbled output -- is
# refused with a reason in BT_WIRE_REASON.
bt_wire_validate_kinds() { # <output> <S1,S2,S3,S4>
	local OUTPUT="$1" SIZES=() ROWS=() KIND INDEX=0 NAME SEEN SHAPED EXPECTED VERDICT EXTRA WANT_EXPECTED WANT_VERDICT COUNT
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
	if [[ "${#ROWS[@]}" -ne 7 ]]; then
		BT_WIRE_REASON="${#ROWS[@]} result rows, not 7"
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
# The SIP verdicts for one capture, as assertions. Each of init, response,
# cookie and transport gets exactly one rule: "required" (seen, and its rule
# held), "optional" (its rule held if seen, its absence stated if not) or
# "absent" (none seen). A rule may name the shaping the scenario expects
# (kind:required:shaped), which must be what that kind's S gives. Every
# capture must also have no unknown, ambiguous or malformed datagram. A result
# that does not validate is one failed assertion.
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
				check "${LABEL}: ${KIND} datagrams were seen (${BT_WIRE_SEEN[${KIND}]})" test "${BT_WIRE_SEEN[${KIND}]}" -ge 1
				check "${LABEL}: ${KIND}s are ${BT_WIRE_EXPECTED[${KIND}]} for S${INDEX}=${S} (${BT_WIRE_SHAPED[${KIND}]}/${BT_WIRE_SEEN[${KIND}]} carry a SIP request line)" \
					test "${BT_WIRE_VERDICT[${KIND}]}" = ok
				;;
			optional)
				if [[ "${BT_WIRE_VERDICT[${KIND}]}" == unobserved ]]; then
					echo "    (${LABEL}: no ${KIND} datagram was seen; S${INDEX}=${S} would make them ${BT_WIRE_EXPECTED[${KIND}]})"
				else
					check "${LABEL}: ${KIND}s are ${BT_WIRE_EXPECTED[${KIND}]} for S${INDEX}=${S} (${BT_WIRE_SHAPED[${KIND}]}/${BT_WIRE_SEEN[${KIND}]} carry a SIP request line)" \
						test "${BT_WIRE_VERDICT[${KIND}]}" = ok
				fi
				;;
			absent)
				check "${LABEL}: no ${KIND} datagram was sent (${BT_WIRE_SEEN[${KIND}]} seen)" test "${BT_WIRE_VERDICT[${KIND}]}" = unobserved
				;;
		esac
	done
	for SUMMARY in ${BT_WIRE_SUMMARIES}; do
		check "${LABEL}: no server datagram is ${SUMMARY} (${BT_WIRE_SUMMARY[${SUMMARY}]})" test "${BT_WIRE_SUMMARY[${SUMMARY}]}" -eq 0
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
