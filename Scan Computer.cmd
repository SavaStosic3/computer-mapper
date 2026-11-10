@echo off
rem Double-click to scan now and open the change report.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scan-Computer.ps1" %*
if errorlevel 1 pause
