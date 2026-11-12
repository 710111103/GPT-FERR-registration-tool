@echo off
setlocal
cd /d "%~dp0"
title Turb GPT Register (Go)

echo ========================================================
echo   Turb GPT Register (Go Version)
echo   WebUI URL: http://127.0.0.1:5000
echo   Default Auth Code: 123456
echo ========================================================
echo.

set code=123456
if "%1"=="--silent" goto build_and_run
set /p user_code=Enter Auth Code (Press ENTER for default 123456):
if not "%user_code%"=="" set code=%user_code%
echo.
echo Using Auth Code: [%code%]
echo.

:build_and_run
echo [1/3] Stopping previous instances...
taskkill /f /im turbd.exe >nul 2>nul

echo [2/3] Building latest Go binary...
set GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct
go build -o turbd.exe .\cmd\turbd
if errorlevel 1 (
  echo.
  echo [BUILD FAILED] Checking if existing turbd.exe can be used...
  if exist "turbd.exe" (
    echo [INFO] Existing turbd.exe found, starting existing binary...
  ) else (
    echo [ERROR] No turbd.exe available.
    pause
    exit /b 1
  )
) else (
  echo [OK] Build succeeded!
)
echo.

echo [3/3] Starting server and opening browser...
echo Keep this window open while using WebUI. Press Ctrl+C to stop.
echo.

start "" "http://127.0.0.1:5000"
turbd.exe --open-browser --auth-code %code%
set EXIT_CODE=%ERRORLEVEL%
if "%EXIT_CODE%"=="42" (
  echo.
  echo [RELOAD] Restart requested, rebuilding and restarting...
  timeout /t 1 /nobreak >nul
  goto build_and_run
)

echo.
echo Server has stopped.
pause
