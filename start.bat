@echo off
rem Switch the console to UTF-8 so non-ASCII output renders correctly in legacy code-page terminals.
chcp 65001 >nul 2>&1
rem ARTEX supervising start script (Windows)
rem
rem Usage:
rem   start.bat                  run in the foreground (Ctrl-C to stop)
rem   start.bat -addr :9000      extra arguments are passed through to artex unchanged
rem
rem It does one thing: run artex.exe, and when the process exits decide from the exit code whether to relaunch it.
rem
rem   0      user stopped normally   -> leave the loop
rem   75     program asked to restart -> rerun immediately ("One-click update" or "Rollback" was clicked in the UI)
rem   other  crash                    -> rerun after a backoff (1->2->4... up to 60 seconds)
rem
rem Download, SHA256 verification and the swap all happen inside artex at startup
rem (the selfupdate package), not here. The script stays simple; see the notes at the top of start.sh.

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BIN=artex.exe"
if not exist "%BIN%" (
	echo [artex] Executable not found: %BIN% 1>&2
	exit /b 1
)

set "RESTART_CODE=75"
set "MAX_DELAY=60"
set /a delay=1

:loop
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	echo [artex] Exited normally
	exit /b 0
)

if "!code!"=="%RESTART_CODE%" (
	rem Update/rollback is staged: after the rerun artex completes the swap at startup.
	echo [artex] Restart requested ^(applying new version^)...
	set /a delay=1
	goto loop
)

echo [artex] Unexpected exit ^(code=!code!^); restarting in !delay!s 1>&2
rem timeout fails in a redirected console, so ping is the fallback (a delay of N seconds needs N+1 pings).
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
