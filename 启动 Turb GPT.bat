@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Python virtual environment not found.
  echo Run setup first:
  echo py -3 -m venv .venv
  echo .venv\Scripts\python.exe -m pip install -r requirements.txt
  pause
  exit /b 1
)
start "Turb GPT WebUI" http://127.0.0.1:5000
.venv\Scripts\python.exe web.py
pause
