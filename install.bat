@echo off
setlocal
cd /d "%~dp0"
if errorlevel 1 (
    echo [ERR] Could not open the AegisDNS installation directory.
    exit /b 1
)

echo ==============================================================================
echo AegisDNS Automated Windows Setup
echo ==============================================================================
echo.

:: Check for Docker CLI
docker --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERR] Docker Desktop is not installed or not running.
    echo Please install Docker Desktop from: https://docs.docker.com/desktop/install/windows-install/
    echo Once installed and running, try again.
    pause
    exit /b 1
)
echo [OK] Docker is installed.

:: Check that Docker Desktop's daemon is ready
docker info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERR] Docker Desktop is installed but its engine is not running.
    echo Start Docker Desktop, wait until it reports that the engine is ready, and retry.
    pause
    exit /b 1
)
echo [OK] Docker engine is running.

:: Check for Docker Compose
docker compose version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERR] Docker Compose is missing.
    echo Please update Docker Desktop to the latest version.
    pause
    exit /b 1
)
echo [OK] Docker Compose is available.

for %%F in (docker-compose.yml Dockerfile Dockerfile.openroot Cargo.lock openroot.json) do (
    if not exist "%%F" (
        echo [ERR] Required project file is missing: %%F
        pause
        exit /b 1
    )
)
if not exist "blocklists\" mkdir "blocklists"

echo.
:: Create or validate config.json and add the current machine address.
echo [INFO] Checking network configuration...
powershell -NoProfile -Command "$ErrorActionPreference='Stop'; $ip=$null; if(Get-Command tailscale -ErrorAction SilentlyContinue){$ip=(& tailscale ip -4 2>$null | Select-Object -First 1)}; if ([string]::IsNullOrWhiteSpace($ip)) { $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -ExpandProperty IPAddress -First 1) }; if ([string]::IsNullOrWhiteSpace($ip)) { $ip='127.0.0.1' }; $ip=$ip.Trim(); if (Test-Path config.json) { $cfg=Get-Content config.json -Raw | ConvertFrom-Json; if ($null -eq $cfg.host_ips -or $cfg.host_ips -is [string]) { throw 'host_ips must be an array' }; $ips=@($cfg.host_ips); if ($ips -notcontains $ip) { $cfg.host_ips=@($ips)+$ip } } else { $cfg=[ordered]@{host_ips=@('127.0.0.1',$ip) | Select-Object -Unique} }; $json=$cfg | ConvertTo-Json -Depth 20; [IO.File]::WriteAllText((Join-Path (Get-Location) 'config.json'),$json+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false))); $envPath=Join-Path (Get-Location) '.env'; $lines=if(Test-Path $envPath){@(Get-Content $envPath | Where-Object {$_ -notmatch '^AEGIS_HOST_IP='})}else{@()}; @($lines)+('AEGIS_HOST_IP='+$ip) | Set-Content $envPath -Encoding ascii"
if errorlevel 1 (
    echo [ERR] Could not create or update config.json and .env.
    pause
    exit /b 1
)

docker compose config --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [ERR] docker-compose.yml or config.json is invalid. Review the message above.
    pause
    exit /b 1
)

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

echo [INFO] Waiting for the AegisDNS daemon to become ready...
set "READY=0"
for /L %%I in (1,1,30) do (
    curl.exe -s -o NUL -w "%%{http_code}" --connect-timeout 1 --max-time 2 http://127.0.0.1:5380/api/stats 2^>nul | findstr /X "401" >nul
    if not errorlevel 1 (
        set "READY=1"
        goto :ready
    )
    timeout /t 1 /nobreak >nul
)

:ready
if "%READY%"=="0" (
    echo [ERR] The container did not become ready. Recent logs:
    docker compose logs --tail=30 aegisdns
    pause
    exit /b 1
)
echo [OK] AegisDNS daemon is running.

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
echo   Username: admin
echo   Password: run this command:
echo     docker exec aegisdns cat /var/lib/aegisdns/admin-password
echo ==============================================================================
pause
