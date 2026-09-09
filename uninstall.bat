@echo off
setlocal
where py >nul 2>&1
if not errorlevel 1 (
    py -3 -X utf8 "%~dp0scripts\setup.py" uninstall %*
    exit /b
)
where python >nul 2>&1
if not errorlevel 1 (
    python -X utf8 "%~dp0scripts\setup.py" uninstall %*
    exit /b
)
echo AegisDNS setup requires Python 3.10 or newer.
echo Install Python from https://www.python.org/downloads/windows/ and enable its launcher.
echo Then reopen this terminal and run uninstall.bat again.
exit /b 1
