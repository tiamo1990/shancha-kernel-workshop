#!/system/bin/sh
# run_ksu.sh - device side launcher for the own127 KernelSU route.
# Owned by work/vivo/ksu_load/load_ksu.ps1; assumes /data/local/tmp/own127
# and /data/local/tmp/kernelsu_patched.ko are already pushed and non-empty.
set -u
D=/data/local/tmp
BIN=$D/own127
KO=$D/kernelsu_patched.ko
LOG=$D/cve-2026-98260.log

[ -x "$BIN" ] || { echo "RUNFAIL missing $BIN"; exit 1; }
[ -s "$KO" ]  || { echo "RUNFAIL missing $KO"; exit 1; }

# NUL-filled pushes happen when a file is written <1s before a reboot.
case "$(dd if="$BIN" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')" in
	7f454c46) : ;;
	*) echo "RUNFAIL $BIN is not an ELF (NUL push?)"; exit 1 ;;
esac

cd "$D" || exit 1
rm -rf "$D/chan"
mkdir -p "$D/chan"
chmod 777 "$D/chan"
rm -f "$D/ksu_slide.txt" "$D/own127.log" "$D/ksu2.out"

echo "=== RUN127 START $(date +%H:%M:%S) uptime=$(cut -d' ' -f1 /proc/uptime) ===" >> "$LOG"
setsid "$BIN" fake nofix > "$D/own127.log" 2>&1 < /dev/null &
echo "RUN127 pid=$!"
