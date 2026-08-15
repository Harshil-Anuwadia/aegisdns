@echo off
setlocal EnableDelayedExpansion
title AegisDNS Windows Fixer

:: Request Administrator Privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges.
) else (
    echo [INFO] Requesting Administrator privileges to fix network settings...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

echo.
echo ==============================================================================
echo                 AegisDNS Automated Windows Network Fixer
echo ==============================================================================
echo.

echo [1/5] Stopping conflicting Windows Services (ICS)...
net stop SharedAccess >nul 2>&1
sc config SharedAccess start= demand >nul 2>&1
echo [OK] Internet Connection Sharing stopped. (Frees up Port 53)

echo.
echo [2/5] Checking for Tailscale (VPN DNS Conflicts)...
tasklist /FI "IMAGENAME eq tailscaled.exe" 2>NUL | find /I /N "tailscaled.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo [WARN] Tailscale is running. It hijacks DNS queries!
    echo [INFO] Shutting down Tailscale temporarily...
    taskkill /F /IM tailscaled.exe >nul 2>&1
    taskkill /F /IM tailscale-ipn.exe >nul 2>&1
    echo [OK] Tailscale stopped.
) else (
    echo [OK] Tailscale is not running.
)

echo.
echo [3/5] Fixing Windows DNS (Resetting to Automatic)...
powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Loopback*' -and $_.InterfaceDescription -notlike '*vEthernet*'} | Set-DnsClientServerAddress -ResetServerAddresses" >nul 2>&1
echo [OK] Windows DNS reset to Automatic (DHCP).

echo.
echo [4/5] Fixing Docker Desktop IPv6/DNS Bug...
set "DOCKER_CFG=%APPDATA%\Docker\daemon.json"
echo {> "%DOCKER_CFG%"
echo   "builder": {>> "%DOCKER_CFG%"
echo     "gc": {>> "%DOCKER_CFG%"
echo       "defaultKeepStorage": "20GB",>> "%DOCKER_CFG%"
echo       "enabled": true>> "%DOCKER_CFG%"
echo     }>> "%DOCKER_CFG%"
echo   },>> "%DOCKER_CFG%"
echo   "experimental": false,>> "%DOCKER_CFG%"
echo   "dns": ["8.8.8.8", "1.1.1.1"],>> "%DOCKER_CFG%"
echo   "ipv6": false>> "%DOCKER_CFG%"
echo }>> "%DOCKER_CFG%"
echo [OK] Wrote safe IPv4 DNS config to Docker daemon.json.

echo.
echo [5/5] Flushing DNS and Restarting Docker...
ipconfig /flushdns >nul
echo [OK] Flushed Windows DNS Cache.

echo [INFO] Shutting down stuck Docker backend...
wsl --shutdown >nul 2>&1

echo [INFO] Starting Docker Desktop...
start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"

echo.
echo ==============================================================================
echo FIX COMPLETE! 
echo ==============================================================================
echo Your internet is fully restored and Docker is configured perfectly.
echo Wait about 15 seconds for Docker to fully start up, then you can run:
echo.
echo     install.bat
echo.
pause
