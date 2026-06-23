@echo off
title Arches Cyber Audit Launcher

:: Self-elevate to Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo Running Arches Cyber Audit...
echo Output will be saved under:
echo %USERPROFILE%\Desktop\ArchesCyberAudit
echo.
echo A copy will also be saved next to this BAT under:
echo %~dp0CollectedReports
echo.

if exist "%~dp0resources\Client-PC-Audit-ArchesCyberAudit-USB-Copy.ps1" (
    set "SCRIPT=%~dp0resources\Client-PC-Audit-ArchesCyberAudit-USB-Copy.ps1"
) else if exist "%~dp0Client-PC-Audit-ArchesCyberAudit-USB-Copy.ps1" (
    set "SCRIPT=%~dp0Client-PC-Audit-ArchesCyberAudit-USB-Copy.ps1"
) else if exist "%~dp0resources\Client-PC-Audit-ArchesCyberAudit.ps1" (
    set "SCRIPT=%~dp0resources\Client-PC-Audit-ArchesCyberAudit.ps1"
) else if exist "%~dp0Client-PC-Audit-ArchesCyberAudit.ps1" (
    set "SCRIPT=%~dp0Client-PC-Audit-ArchesCyberAudit.ps1"
) else if exist "%~dp0resources\Client-PC-Audit-OfficeFree.ps1" (
    set "SCRIPT=%~dp0resources\Client-PC-Audit-OfficeFree.ps1"
) else if exist "%~dp0Client-PC-Audit-OfficeFree.ps1" (
    set "SCRIPT=%~dp0Client-PC-Audit-OfficeFree.ps1"
) else if exist "%~dp0resources\Client-PC-Audit.ps1" (
    set "SCRIPT=%~dp0resources\Client-PC-Audit.ps1"
) else if exist "%~dp0Client-PC-Audit.ps1" (
    set "SCRIPT=%~dp0Client-PC-Audit.ps1"
) else (
    echo ERROR: Could not find the PowerShell audit script.
    echo.
    echo Put this BAT in the same folder as the script, or use this layout:
    echo   ArchesCyberAudit\Run-ArchesCyberAudit.bat
    echo   ArchesCyberAudit\resources\Client-PC-Audit-ArchesCyberAudit.ps1
    echo.
    pause
    exit /b 1
)

echo Using script:
echo %SCRIPT%
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"

echo.
echo Audit finished.
echo Open the report folder here:
echo %USERPROFILE%\Desktop\ArchesCyberAudit
echo.
echo USB/launcher copy should be here:
echo %~dp0CollectedReports
echo.
pause
