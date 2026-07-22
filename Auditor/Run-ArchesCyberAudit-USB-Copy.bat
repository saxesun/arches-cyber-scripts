@echo off
setlocal EnableExtensions

echo ERROR: This legacy audit launcher is disabled for Phase 1 because its historical export bundle is not covered by the Phase 1 privacy allowlist.
echo Use the repository-level Run-ArchesCyber.bat launcher instead.
exit /b 3

:: Arches Cyber Audit Launcher
:: Place this BAT in the same folder as the PS1, or put the PS1 in a resources folder.

set "LAUNCHER_DIR=%~dp0"
set "SCRIPT=%LAUNCHER_DIR%..\Scripts\Client-PC-Audit.ps1"
set "SCRIPT_ARGS=-InteractiveDiagnostics"

if not exist "%SCRIPT%" (
    set "SCRIPT=%LAUNCHER_DIR%resources\Client-PC-Audit.ps1"
)

if not exist "%SCRIPT%" (
    set "SCRIPT=%LAUNCHER_DIR%Client-PC-Audit.ps1"
)

if not exist "%SCRIPT%" (
    set "SCRIPT=%LAUNCHER_DIR%Client-PC-Audit-ArchesCyberAudit-USB-Copy.ps1"
    set "SCRIPT_ARGS="
)

if not exist "%SCRIPT%" (
    echo ERROR: Could not find the Arches Cyber audit PowerShell script.
    echo Keep the repository folders together, or put Client-PC-Audit.ps1
    echo next to this BAT or inside a resources folder.
    pause
    exit /b 1
)

:: Relaunch as Administrator if needed.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator permissions...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo Running Arches Cyber Audit...
echo Script: %SCRIPT%
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %SCRIPT_ARGS%

set "EXITCODE=%ERRORLEVEL%"
echo.
echo Audit script finished with exit code %EXITCODE%.
echo Reports are saved on the client Desktop under ArchesCyberAudit and copied to CollectedReports when possible.
pause
exit /b %EXITCODE%
