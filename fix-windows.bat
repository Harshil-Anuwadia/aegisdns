@echo off
setlocal
title AegisDNS Windows Preflight Repair
cd /d "%~dp0"

:: Port and service changes require Administrator privileges.
net session >nul 2>&1
if not "%errorLevel%"=="0" (
    echo [INFO] Requesting Administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs"
    exit /b
)

echo ==============================================================================
echo AegisDNS Windows Preflight Repair
echo ==============================================================================
echo.

echo [1/4] Checking Docker Desktop...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERR] Docker Desktop is not installed.
    echo Install it from https://docs.docker.com/desktop/install/windows-install/
    pause
    exit /b 1
)

docker info >nul 2>&1
if errorlevel 1 (
    echo [INFO] Starting Docker Desktop...
    if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
        start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    ) else (
        echo [ERR] Docker Desktop is installed in an unexpected location. Start it manually.
        pause
        exit /b 1
    )
    echo Wait until Docker Desktop reports that its engine is ready, then run install.bat.
) else (
    echo [OK] Docker engine is running.
)

echo.
echo [2/4] Releasing DNS port 53 from Internet Connection Sharing, if active...
sc query SharedAccess | findstr /I "RUNNING" >nul
if not errorlevel 1 (
    net stop SharedAccess >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Internet Connection Sharing could not be stopped.
    ) else (
        echo [OK] Internet Connection Sharing stopped for this session.
    )
) else (
    echo [OK] Internet Connection Sharing is not running.
)

echo.
echo [3/4] Preserving VPN and adapter settings...
echo [OK] Tailscale, adapter DNS, Docker daemon.json, and WSL distributions were left unchanged.

echo.
echo [4/4] Flushing the Windows DNS cache...
ipconfig /flushdns >nul 2>&1
if errorlevel 1 (
    echo [WARN] DNS cache flush failed.
) else (
    echo [OK] DNS cache flushed.
)

echo.
echo ==============================================================================
echo Preflight repair complete. Run install.bat from this directory.
echo ==============================================================================
pause
