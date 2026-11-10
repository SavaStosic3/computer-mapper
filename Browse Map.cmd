@echo off
rem Double-click to explore the map in your browser. Close this window to stop the viewer.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Browse-Map.ps1" %*
if errorlevel 1 pause
