# load_ksu.ps1 - one-click: own127 exploit -> hooks_defend bypass -> KernelSU LKM.
# Shows the device log LIVE while the exploit runs (1 s delta pump), with
# 5 s marker polling and a boot-once-retry policy.
#
# Usage:
#   .\load_ksu.ps1                 # full flow (reboot + run + live log)
#   .\load_ksu.ps1 -NoReboot       # run on the current boot
#   .\load_ksu.ps1 -NoReboot -SkipRun   # only show status / live log of an ongoing run
# Params: -Tmo seconds (default 90), -Retry 0|1 (default 1), -Manager <pkg>

[CmdletBinding()]
param(
    [switch]$NoReboot,
    [switch]$SkipRun,
    [int]$Tmo = 90,
    [int]$Retry = 1,
    [string]$Manager = "me.weishu.kernelsu",
    [string]$Adb = "C:\platform-tools\adb.exe"
)

$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$D = "/data/local/tmp"
$LOG = "$D/cve-2026-98260.log"
$BIN = "$root\own127"
$KO = "$root\ksu\kernelsu_patched.ko"
$RUN = "$here\run_ksu.sh"
$CHK = "$here\chk_ksu.sh"
$stamp = { param($m) "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m }

function Say([string]$m) { Write-Host (& $stamp $m) -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host (& $stamp $m) -ForegroundColor Green }
function Warn([string]$m) { Write-Host (& $stamp $m) -ForegroundColor Yellow }
function Bad([string]$m) { Write-Host (& $stamp $m) -ForegroundColor Red }

function Invoke-Adb([string[]]$argv, [switch]$Quiet) {
    $out = & $Adb @argv 2>&1 | Out-String
    if (-not $Quiet) { $out.TrimEnd() | Write-Host }
    return $out
}
function Get-Uptime {
    $u = (& $Adb shell "cut -d' ' -f1 /proc/uptime" 2>$null | Out-String).Trim()
    if ($u -match '^\d+(\.\d+)?$') { return [double]$u }
    return -1
}
function Get-LogSize {
    $s = (& $Adb shell "wc -c < $LOG" 2>$null | Out-String).Trim()
    if ($s -match '^\d+$') { return [int64]$s }
    return -1
}
function Wait-Boot([int]$timeoutSec = 90) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $b = (& $Adb shell "getprop sys.boot_completed" 2>$null | Out-String).Trim()
        if ($b -eq "1") { return $true }
        Start-Sleep -Milliseconds 800
    }
    return $false
}
function Push-Checked([string]$src, [string]$dst) {
    if (-not (Test-Path $src)) { Bad "missing $src"; return $false }
    & $Adb push $src $dst 2>&1 | Out-Null
    & $Adb shell "sync" 2>&1 | Out-Null
    $local = (Get-Item $src).Length
    $remote = (& $Adb shell "wc -c < $dst" 2>$null | Out-String).Trim()
    if ($remote -notmatch '^\d+$' -or [int64]$remote -ne $local) {
        Bad "push size mismatch for $dst (local=$local remote=$remote)"; return $false
    }
    Ok "pushed $(Split-Path -Leaf $src) ($local B)"
    return $true
}

# ---------------------------------------------------------------- preflight
Say "preflight"
if (-not (Test-Path $Adb)) { Bad "adb not found: $Adb"; exit 1 }
$dev = (& $Adb devices 2>&1 | Out-String)
if ($dev -notmatch "\tdevice") { Bad "no device attached"; exit 1 }
$tracing = (& $Adb shell "ls -d /sys/kernel/tracing 2>/dev/null" 2>$null | Out-String).Trim()
if (-not $tracing) { Bad "tracefs missing - cannot run"; exit 1 }
Say ("kernel " + (& $Adb shell "uname -r" 2>$null | Out-String).Trim())
Say ("selinux " + (& $Adb shell "getenforce" 2>$null | Out-String).Trim() + ", uptime " + (Get-Uptime) + "s")

if (-not (Push-Checked $BIN "$D/own127")) { exit 1 }
if (-not (Push-Checked $KO "$D/kernelsu_patched.ko")) { exit 1 }
if (-not (Push-Checked $RUN "$D/run_ksu.sh")) { exit 1 }
if (-not (Push-Checked $CHK "$D/chk_ksu.sh")) { exit 1 }
& $Adb shell "chmod 755 $D/own127 $D/run_ksu.sh $D/chk_ksu.sh" 2>&1 | Out-Null

# ---------------------------------------------------------------- boot
if (-not $NoReboot) {
    Say "rebooting for a clean boot"
    & $Adb shell "sync; reboot" 2>&1 | Out-Null
    Start-Sleep -Seconds 6
    & $Adb wait-for-device 2>&1 | Out-Null
    if (-not (Wait-Boot 120)) { Bad "boot_completed never fired"; exit 1 }
    Say ("boot_completed, uptime=" + (Get-Uptime) + "s - waiting 2s (exploit window)")
    Start-Sleep -Seconds 2
} elseif ((Get-Uptime) -gt 40) {
    Warn "not a fresh boot (uptime >40s) - the chain may still work, the kernel route is timing-independent"
}

# ---------------------------------------------------------------- run + live log
$base = Get-LogSize
if ($base -lt 0) { $base = 0 }
if (-not $SkipRun) {
    Say "starting own127 (fake nofix)"
    & $Adb shell "sh $D/run_ksu.sh" 2>&1 | ForEach-Object { Write-Host $_ }
    $base = Get-LogSize
    if ($base -lt 0) { $base = 0 }
}

$success = $false; $dead = $false; $lastUp = (Get-Uptime)
$deadline = (Get-Date).AddSeconds($Tmo)
$off = $base
Say "live log (delta pump 1s, cap ${Tmo}s) ------------------------------"
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
    $up = Get-Uptime
    if ($up -lt 0) { Write-Host "[reboot] device went away" -ForegroundColor Yellow; $dead = $true; break }
    if ($lastUp -gt 5 -and $up -lt $lastUp - 5) {
        Warn "[reboot] uptime fell $([int]$lastUp)s -> $([int]$up)s (device rebooted)"
        $dead = $true; break
    }
    $lastUp = $up
    $size = Get-LogSize
    if ($size -gt $off) {
        $chunk = (& $Adb shell "tail -c +$($off + 1) $LOG" 2>$null | Out-String)
        if ($chunk) {
            $off = $size
            foreach ($line in ($chunk -split "`n")) {
                if ($line.Trim()) { Write-Host "  $line" }
            }
            if ($chunk -match '\[gate127\] SUCCESS|\[al\] init_module rc=0') { $success = $true; break }
            if ($chunk -match 'kread unreliable|kernel-write route FAILED') {
                Warn "kread unreliable this boot - treating as retryable"; $dead = $true; break
            }
            if ($chunk -match '\[gate127\] done ok=0|RUNFAIL|\[fake\] pre0 ok=0|child wake write failed') {
                Warn "chain stopped before success"; break
            }
        }
    }
    Write-Host ("  ... uptime {0}s" -f [int]$up) -ForegroundColor DarkGray
}
Write-Host "------------------------------------------------------------"

# ---------------------------------------------------------------- verify
$mods = (& $Adb shell "grep -i kernelsu /proc/modules" 2>$null | Out-String).Trim()
if ($mods) {
    Ok "KernelSU LOADED:"
    Write-Host "  $mods" -ForegroundColor Green
    $success = $true
}

& $Adb shell "sh $D/chk_ksu.sh" 2>&1 | ForEach-Object { Write-Host $_ }

if ($success) {
    Ok "launching $Manager so you can look at the screen"
    & $Adb shell "monkey -p $Manager -c android.intent.category.LAUNCHER 1" 2>&1 | Out-Null

# ---- final Chinese prompt: keep the window open -------------------------
Write-Host ""
if ($success) {
    Write-Host "成功：KernelSU 已加载，管理器应显示「工作中 [越狱模式]」。" -ForegroundColor Green
    Write-Host "注意：重启后 root 与模块都会消失，需要重新运行本程序。" -ForegroundColor Yellow
} else {
    Write-Host "失败：本轮未加载成功，详情见上方日志与 /data/local/tmp/cve-2026-98260.log" -ForegroundColor Red
    Write-Host "建议：重启手机后再运行一次；若反复失败，把上面的 gate 日志发给开发者。" -ForegroundColor Yellow
}
if (-not $env:KSULOAD_NOPAUSE) {
    Write-Host "按任意键退出..." -ForegroundColor Cyan
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { $null = Read-Host }
}

    exit 0
}

if ($dead -and $Retry -gt 0) {
    Warn "device rebooted before success - retrying once"
    & $Adb wait-for-device 2>&1 | Out-Null
    if (Wait-Boot 120) {
        Start-Sleep -Seconds 2
        & $PSCommandPath -NoReboot -Retry 0 -Tmo $Tmo -Manager $Manager -Adb $Adb
        exit $LASTEXITCODE
    }
}
Bad "kernel-write route did not reach init_module rc=0 this boot"

# ---- final Chinese prompt: keep the window open -------------------------
Write-Host ""
if ($success) {
    Write-Host "成功：KernelSU 已加载，管理器应显示「工作中 [越狱模式]」。" -ForegroundColor Green
    Write-Host "注意：重启后 root 与模块都会消失，需要重新运行本程序。" -ForegroundColor Yellow
} else {
    Write-Host "失败：本轮未加载成功，详情见上方日志与 /data/local/tmp/cve-2026-98260.log" -ForegroundColor Red
    Write-Host "建议：重启手机后再运行一次；若反复失败，把上面的 gate 日志发给开发者。" -ForegroundColor Yellow
}
if (-not $env:KSULOAD_NOPAUSE) {
    Write-Host "按任意键退出..." -ForegroundColor Cyan
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { $null = Read-Host }
}

exit 1
