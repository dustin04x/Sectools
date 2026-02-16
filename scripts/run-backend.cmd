@echo off
setlocal

cd /d "%~dp0\..\python_backend"

set PYTHONPATH=..\Lib\site-packages;.
call ..\.venv\Scripts\python.exe main.py
