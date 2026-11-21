#!/system/bin/sh
# chk_ksu.sh - device side verification for the own127 KernelSU route.
D=/data/local/tmp
LOG=$D/cve-2026-98260.log

echo "=== uptime ==="
cut -d' ' -f1 /proc/uptime
echo "=== kernelsu in /proc/modules ==="
grep -i kernelsu /proc/modules || echo "(absent)"
echo "=== gate127 markers ==="
grep -a -E "\[gate127\]|\[al\] init_module|\[al\] BLOCKED|\[kw\] \.cs|\[kw\] perm|\[kw\] g\(7\)|\[plant\].*zeroed|\[kr\] selftest|\[mod\] FOUND|\[mem\] MOD_DATA|MOD_DATA read failed" "$LOG" | tail -25
echo "=== last 4 log lines ==="
tail -4 "$LOG"
echo "=== kmsg (needs root; may fail) ==="
dmesg 2>/dev/null | grep -a -i -E "kernelsu|hks-dfd" | tail -8
echo "CHKDONE"
