@echo off
setlocal

cd /d "%~dp0\.."

echo [1/4] Creating virtual environment...
py -m venv .venv
if errorlevel 1 goto :fail

echo [2/4] Upgrading pip...
call .venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto :fail

echo [3/4] Installing backend requirements...
call .venv\Scripts\python.exe -m pip install -r python_backend\requirements.txt
if errorlevel 1 goto :fail

echo [4/4] Installing frontend dependencies...
call npm install
if errorlevel 1 goto :fail

echo.
echo Setup complete.
echo Use scripts\run-backend.cmd in one terminal and npm run dev in another.
exit /b 0

:fail
echo.
echo Setup failed. See errors above.
exit /b 1
