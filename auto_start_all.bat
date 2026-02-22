@echo off
setlocal enabledelayedexpansion

REM ==========================
REM  SQLMAP SKYNET v1.2.0
REM  Auto Start: UI + MCPFast
REM ==========================

REM 1) Create venv if missing
if not exist ".\.venv\Scripts\python.exe" (
  echo [*] Creating virtual environment: .venv
  py -3.12 -m venv .venv
  if errorlevel 1 (
    echo [!] Failed to create venv. Install Python 3.12+ and try again.
    pause
    exit /b 1
  )
)

REM 2) Activate venv
call .\.venv\Scripts\activate.bat

REM 3) Install deps from requirements.txt 
if not exist ".\.venv\.deps_installed" (
  echo [*] Installing dependencies from requirements.txt ...
  python -m pip install -U pip
  pip install -r requirements.txt
  if errorlevel 1 (
    echo [!] Failed to install requirements.txt
    pause
    exit /b 1
  )
  type nul > ".\.venv\.deps_installed"
)

REM 4) Start SKYNET Dashboard
start "SKYNET-DASHBOARD" cmd /k python main.py --host 127.0.0.1 --port 1337 --debug

REM 5) Start MCP Server (HTTP)
start "SKYNET-MCP" cmd /k fastmcp run .\mcp\server.py:mcp --transport http --host 127.0.0.1 --port 8055

echo.
echo Started:
echo - Dashboard: http://127.0.0.1:1337
echo - MCP:       http://127.0.0.1:8055/mcp
echo.
pause
