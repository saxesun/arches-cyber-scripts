@echo off
setlocal EnableExtensions
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator permissions...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

if not exist "%~dp0Scripts\Start-ArchesCyber.ps1" (
    echo ERROR: Scripts\Start-ArchesCyber.ps1 was not found.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Start-ArchesCyber.ps1"
set "EXITCODE=%ERRORLEVEL%"
echo.
echo Arches Cyber finished with exit code %EXITCODE%.
if exist "%~dp0Scripts\Start-ArchesGuidedFixes.ps1" (
    echo.
    choice /C YN /N /M "Open Guided Fixes? [Y/N] "
    if errorlevel 2 goto finish
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Start-ArchesGuidedFixes.ps1"
)
:finish
pause
exit /b %EXITCODE%
