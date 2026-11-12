@echo off
cd /d "%~dp0"
taskkill /f /im turbd.exe >nul 2>nul
echo [OK] Turbd service stopped.
timeout /t 2 >nul
