@echo off
setlocal

echo ==============================================================================
echo AegisDNS Automated Windows Setup
echo ==============================================================================
echo.

:: Check for Docker
docker --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERR] Docker Desktop is not installed or not running.
    echo Please install Docker Desktop from: https://docs.docker.com/desktop/install/windows-install/
    echo Once installed and running, try again.
    pause
    exit /b 1
)
echo [OK] Docker is installed.

:: Check for Docker Compose
docker compose version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERR] Docker Compose is missing.
    echo Please update Docker Desktop to the latest version.
    pause
    exit /b 1
)
echo [OK] Docker Compose is available.

echo.
echo [INFO] Building and starting AegisDNS container...
docker compose up -d --build

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERR] Failed to start Docker container. 
    echo If you see a "port 53 is already in use" error, you must stop the Windows "Internet Connection Sharing (ICS)" service.
    pause
    exit /b 1
)

echo.
echo ==============================================================================
echo [OK] AegisDNS successfully installed and running!
echo.
echo Required Next Steps for Tailscale Users:
echo   1. Log into your Tailscale Admin Console
echo   2. Go to the 'DNS' tab.
echo   3. Click 'Add Nameserver' -^> 'Custom' and enter the Tailscale IP of this machine.
echo   4. Turn ON 'Override local DNS'.
echo   5. Ensure 'Secure DNS' / DoH is disabled in Chrome/Brave/Firefox settings.
echo.
echo Access the Web Dashboard:
echo   Open http://localhost:5380 in your browser.
echo ==============================================================================
pause
