@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo   CRISP 2.2 - Cyber Risk Intelligence ^& Security Posture Platform
echo   Local Windows Development Launcher
echo =====================================================================
echo.

:: 1. Verify Node.js
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo Please install Node.js 20 or later from https://nodejs.org/
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node -v') do set NODE_VER=%%i
echo [*] Detected Node.js: %NODE_VER%

:: 2. Check Python
where python >nul 2>nul
if %errorlevel% equ 0 (
    for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PY_VER=%%i
    echo [*] Detected Python: !PY_VER!
    set PYTHON_BIN=python
) else (
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        for /f "tokens=*" %%i in ('py --version 2^>^&1') do set PY_VER=%%i
        echo [*] Detected Python Launcher: !PY_VER!
        set PYTHON_BIN=py
    ) else (
        echo [!] Python not detected. Core client-side SQLite dashboards will function,
        echo     but background Python analytics require Python 3.10+ from https://python.org
    )
)

:: 3. Check and Install Node Dependencies
if not exist "node_modules\" (
    echo [*] Installing Node.js dependencies (first-time setup)...
    call npm install
    if %errorlevel% neq 0 (
        echo [ERROR] Dependency installation failed.
        pause
        exit /b 1
    )
)

:: 4. Ensure .env exists
if not exist ".env" (
    if exist ".env.example" (
        echo [*] Creating .env from .env.example template...
        copy ".env.example" ".env" >nul
    )
)

:: 5. Verify WASM binary presence in public folder
if not exist "public\sql-wasm.wasm" (
    if exist "node_modules\sql.js\dist\sql-wasm.wasm" (
        echo [*] Copying WebAssembly binary to public folder...
        copy "node_modules\sql.js\dist\sql-wasm.wasm" "public\sql-wasm.wasm" >nul
        copy "node_modules\sql.js\dist\sql-wasm-browser.wasm" "public\sql-wasm-browser.wasm" >nul
    )
)

:: 6. Initialize SQLite Database Schema if missing
if defined PYTHON_BIN (
    if not exist "data\crisp.db" (
        echo [*] Initializing SQLite database tables...
        call !PYTHON_BIN! scripts\migrate.py
    )
)

echo.
echo =====================================================================
echo   Starting CRISP Full-Stack Server on http://localhost:3000
echo   Press Ctrl+C in this window to stop the server.
echo =====================================================================
echo.

call npm run dev

pause
