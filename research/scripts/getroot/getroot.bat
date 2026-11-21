@echo off
rem ===========================================================================
rem  getroot.bat - one-click CVE-2026-98260 temporary root (NO KernelSU)
rem                vivo X200s / 6.6.127-android15
rem
rem  Pushes own121 + getroot.sh to /data/local/tmp and drives them.
rem
rem  This version: the device script timestamps every step, streams the
rem  exploit/shell output live into this window, polls every GR_POLL seconds
rem  (default 5) and stops early on the [rootsh] marker, gate markers, error
rem  markers or a device reboot (total cap GR_TMO, default 90 s).  A pre-run
rem  environment check aborts with a clear message if the phone is not ready.
rem
rem  usage:  getroot.bat                  push + start + root console
rem          getroot.bat check            pre-run environment check
rem          getroot.bat start            escalate + start the root channel
rem          getroot.bat cmd "id"         run one command as root
rem          getroot.bat shell            interactive root shell (tty)
rem          getroot.bat status           channel state + last log lines
rem          getroot.bat stop             end the root shell
rem          getroot.bat menu             numeric menu
rem
rem  env:    ANDROID_SERIAL=xxxx         pick a device
rem          ADB=C:\path\adb.exe          override adb
rem          GR_TMO=90                    startup wait cap in seconds
rem          GR_POLL=5                    startup poll interval in seconds
rem ===========================================================================
setlocal EnableExtensions
set "HERE=%~dp0"
set "BIN=%HERE%own121"
if not exist "%BIN%" set "BIN=%HERE%..\own121"
set "DEV=/data/local/tmp"
set "ACTION=%~1"
set "ARG2=%~2"
if not defined GR_TMO set "GR_TMO=90"
if not defined GR_POLL set "GR_POLL=5"

if not defined ADB call :find_adb
if not defined ADB goto :no_adb

if /i "%ACTION%"=="check"  goto :a_check
if /i "%ACTION%"=="start"  goto :a_start
if /i "%ACTION%"=="cmd"    goto :a_cmd
if /i "%ACTION%"=="shell"  goto :a_shell
if /i "%ACTION%"=="status" goto :a_status
if /i "%ACTION%"=="stop"   goto :a_stop
if /i "%ACTION%"=="menu"   goto :menu
if "%ACTION%"=="" goto :oneshot
goto :usage

rem --------------------------------------------------------------------------
:find_adb
set "ADB=C:\platform-tools\adb.exe"
if exist "%ADB%" exit /b 0
for /f "delims=" %%I in ('where adb 2^>nul') do (
    set "ADB=%%I"
    exit /b 0
)
set "ADB="
exit /b 1

:log
set "TS=%TIME:~0,8%"
set "TS=%TS: =0%"
echo [%TS%] [getroot] %*
exit /b 0

:logerr
set "TS=%TIME:~0,8%"
set "TS=%TS: =0%"
echo [%TS%] [getroot][ERR] %*
exit /b 0

:device_ok
call "%ADB%" devices 2>nul | findstr /r "device$" >nul
if errorlevel 1 exit /b 1
exit /b 0

:boot_ok
set "BOOT="
for /f "delims=" %%B in ('call "%ADB%" shell getprop sys.boot_completed 2^>nul') do set "BOOT=%%B"
if not "%BOOT%"=="1" exit /b 1
exit /b 0

:push
call :device_ok
if errorlevel 1 (
    call :logerr no device - check "adb devices" or set ANDROID_SERIAL
    exit /b 1
)
call :boot_ok
if errorlevel 1 (
    call :logerr device boot is not finished - wait for sys.boot_completed=1
    exit /b 1
)
if not exist "%BIN%" (
    call :logerr missing "%BIN%"
    exit /b 1
)
if not exist "%HERE%getroot.sh" (
    call :logerr missing "%HERE%getroot.sh"
    exit /b 1
)
call :log pushing own121 to %DEV%/own121
call "%ADB%" push "%BIN%" "%DEV%/own121" >nul 2>&1
if errorlevel 1 (
    call :logerr adb push failed for "%BIN%"
    exit /b 1
)
call :log pushing getroot.sh to %DEV%/getroot.sh
call "%ADB%" push "%HERE%getroot.sh" "%DEV%/getroot.sh" >nul 2>&1
if errorlevel 1 (
    call :logerr adb push failed for getroot.sh
    exit /b 1
)
call "%ADB%" shell chmod 755 %DEV%/own121 %DEV%/getroot.sh >nul 2>&1
call :log files ready
exit /b 0

:run_remote_cmd
rem %1 = command text. Written to a temp file and pushed, so quoting is safe.
set "GR_CMD=%~1"
if not defined GR_CMD exit /b 1
set "GR_TMP=%TEMP%\gr_cmd_%RANDOM%%RANDOM%.txt"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[IO.File]::WriteAllText($env:GR_TMP, $env:GR_CMD, (New-Object Text.UTF8Encoding($false)))" >nul 2>&1
if not exist "%GR_TMP%" (
    call :logerr cannot write "%GR_TMP%"
    exit /b 1
)
call "%ADB%" push "%GR_TMP%" "%DEV%/.gr_cmd" >nul 2>&1
set "GR_PUSH_RC=%ERRORLEVEL%"
del /q "%GR_TMP%" >nul 2>&1
if not "%GR_PUSH_RC%"=="0" (
    call :logerr adb push failed for the command file
    call "%ADB%" shell rm -f %DEV%/.gr_cmd >nul 2>&1
    exit /b 1
)
call "%ADB%" shell "TMO=%GR_TMO% sh %DEV%/getroot.sh cmdfile %DEV%/.gr_cmd"
set "GR_RC=%ERRORLEVEL%"
call "%ADB%" shell rm -f %DEV%/.gr_cmd >nul 2>&1
exit /b %GR_RC%

:check
call "%ADB%" shell "sh %DEV%/getroot.sh check"
exit /b %ERRORLEVEL%

:verify_channel
rem Called after start: make sure the root shell is actually running, not just
rem that adb returned 0 (a device reboot in the middle can look like success).
set "GR_ST=%TEMP%\gr_status_%RANDOM%%RANDOM%.txt"
call "%ADB%" shell "sh %DEV%/getroot.sh status" >"%GR_ST%" 2>&1
findstr /c:"channel: RUNNING" "%GR_ST%" >nul
if errorlevel 1 (
    type "%GR_ST%"
    del /q "%GR_ST%" >nul 2>&1
    call :logerr the device script returned success but the channel is NOT running
    call :logerr if the phone rebooted during start, wait for boot and run start again
    exit /b 1
)
del /q "%GR_ST%" >nul 2>&1
call :log verified - the root channel is RUNNING on the device
exit /b 0

rem --------------------------------------------------------------------------
:a_check
call :push
if errorlevel 1 goto :fail
call :log device-side pre-run environment check
call "%ADB%" shell "sh %DEV%/getroot.sh check"
if errorlevel 1 (
    call :logerr environment check failed - fix the [FAIL] items above
    goto :fail
)
goto :done

:a_start
call :push
if errorlevel 1 goto :fail
call :log starting exploit - poll %GR_POLL%s, cap %GR_TMO%s, live output follows
call "%ADB%" shell "TMO=%GR_TMO% POLL=%GR_POLL% sh %DEV%/getroot.sh start"
if errorlevel 1 (
    call :logerr start failed
    call :logerr if adb said device offline/closed the phone rebooted - wait, then run check
    goto :fail
)
call :verify_channel
if errorlevel 1 goto :fail
goto :done

:a_status
call "%ADB%" shell "sh %DEV%/getroot.sh status"
goto :done

:a_stop
call "%ADB%" shell "sh %DEV%/getroot.sh stop"
goto :done

:a_shell
call :push
if errorlevel 1 goto :fail
call :log handing the console to the interactive root shell - exit or Ctrl-D to leave
call "%ADB%" shell -t "sh %DEV%/getroot.sh shell"
goto :done

:a_cmd
if not defined ARG2 (
    set "ARG2="
    set /p "ARG2=Command to run as root> "
)
if not defined ARG2 goto :usage
call :push
if errorlevel 1 goto :fail
call :log running command as root - live output follows
call :run_remote_cmd "%ARG2%"
set "GR_CMD_RC=%ERRORLEVEL%"
if not "%GR_CMD_RC%"=="0" (
    call :log command exited rc=%GR_CMD_RC%
    if not defined NO_PAUSE pause
    exit /b %GR_CMD_RC%
)
goto :done

rem --------------------------------------------------------------------------
:oneshot
echo.
call :log getroot - CVE-2026-98260 temporary root - no KernelSU
call :log one root session per boot - reboot to clean up
call :push
if errorlevel 1 goto :fail
call "%ADB%" shell "TMO=%GR_TMO% POLL=%GR_POLL% sh %DEV%/getroot.sh start"
if errorlevel 1 goto :fail
call :verify_channel
if errorlevel 1 goto :fail
echo.
call :log root console ready - type a command, or one of the ! commands
call :log !shell = interactive root shell, !status, !check, !stop, exit
echo.
:loop
set "LINE="
set /p "LINE=root> "
if defined LINE goto :have_line
rem blank line: reprompt; repeated empty reads mean EOF (closed stdin)
set /a "EMPTY+=1" >nul 2>&1
if not defined EMPTY set "EMPTY=1"
if %EMPTY% GEQ 20 goto :done
goto :loop
:have_line
set "EMPTY=0"
if /i "%LINE%"=="exit" goto :done
if /i "%LINE%"=="quit" goto :done
if /i "%LINE%"=="!shell" (
    call "%ADB%" shell -t "sh %DEV%/getroot.sh shell"
    goto :loop
)
if /i "%LINE%"=="!status" (
    call "%ADB%" shell "sh %DEV%/getroot.sh status"
    goto :loop
)
if /i "%LINE%"=="!check" (
    call "%ADB%" shell "sh %DEV%/getroot.sh check"
    goto :loop
)
if /i "%LINE%"=="!stop" (
    call "%ADB%" shell "sh %DEV%/getroot.sh stop"
    goto :done
)
call :run_remote_cmd "%LINE%"
goto :loop

rem --------------------------------------------------------------------------
:menu
echo.
echo   getroot - CVE-2026-98260 temporary root - no KernelSU
echo   -----------------------------------------------------
echo    1. check     pre-run environment check
echo    2. start     escalate + start the root command channel
echo    3. cmd       run one command as root
echo    4. shell     interactive root shell
echo    5. status    channel state
echo    6. stop      end the root shell - reboot to clean up
echo    0. exit
echo.
set "M="
set /p "M=Select> "
if not defined M goto :done
set "M=%M: =%"
if "%M%"=="0" goto :done
if "%M%"=="1" goto :m_check
if "%M%"=="2" goto :m_start
if "%M%"=="3" goto :m_cmd
if "%M%"=="4" goto :m_shell
if "%M%"=="5" goto :m_status
if "%M%"=="6" goto :m_stop
goto :menu

:m_check
call :push
if errorlevel 1 goto :fail
call "%ADB%" shell "sh %DEV%/getroot.sh check"
goto :menu

:m_start
call :push
if errorlevel 1 goto :fail
call "%ADB%" shell "TMO=%GR_TMO% POLL=%GR_POLL% sh %DEV%/getroot.sh start"
goto :menu

:m_cmd
set "MC="
set /p "MC=Command to run as root> "
if not defined MC goto :menu
call :run_remote_cmd "%MC%"
goto :menu

:m_shell
call "%ADB%" shell -t "sh %DEV%/getroot.sh shell"
goto :menu

:m_status
call "%ADB%" shell "sh %DEV%/getroot.sh status"
goto :menu

:m_stop
call "%ADB%" shell "sh %DEV%/getroot.sh stop"
goto :menu

rem --------------------------------------------------------------------------
:usage
echo.
echo  usage: getroot.bat [check^|start^|cmd "..."^|shell^|status^|stop^|menu]
echo         getroot.bat            push + start + root console
echo.
echo  env:   ANDROID_SERIAL=xxx   pick a device
echo         ADB=...              override adb path
echo         GR_TMO=90            startup wait cap in seconds
echo         GR_POLL=5            startup poll interval in seconds
echo.
goto :done

:no_adb
call :logerr adb.exe not found - install platform-tools to C:\platform-tools
echo               or set ADB=C:\path\to\adb.exe
goto :fail

:fail
call :logerr failed
if "%ACTION%"=="" if not defined NO_PAUSE pause
exit /b 1

:done
echo.
call :log done
if "%ACTION%"=="" if not defined NO_PAUSE pause
exit /b 0
