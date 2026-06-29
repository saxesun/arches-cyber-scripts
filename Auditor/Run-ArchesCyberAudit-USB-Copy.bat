@echo off
setlocal EnableExtensions

:: Arches Cyber Audit Launcher
:: Place this BAT in the same folder as the PS1, or put the PS1 in a resources folder.

set "LAUNCHER_DIR=%~dp0"
set "SCRIPT=%LAUNCHER_DIR%Client-PC-Audit-Diagnostics-Report.ps1"

if not exist "%SCRIPT%" (
    set "SCRIPT=%LAUNCHER_DIR%resources\Client-PC-Audit-Diagnostics-Report.ps1"
)

if not exist "%SCRIPT%" (
    echo ERROR: Could not find Client-PC-Audit-Diagnostics-Report.ps1
    echo Put the PS1 next to this BAT or inside a resources folder.
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

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"

set "EXITCODE=%ERRORLEVEL%"
echo.
echo Audit script finished with exit code %EXITCODE%.
echo Reports are saved on the client Desktop under ArchesCyberAudit and copied to CollectedReports when possible.
pause
exit /b %EXITCODE%
