@echo off
title Client PC Auditor

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: Change to the folder where this BAT file is located
cd /d "%~dp0"

echo Running Audit...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0resources\AuditorCore.ps1"

echo.
echo Audit finished.
pause