@echo off
color 0A
echo ========================================================
echo   Threat Monitor AI - Hackathon Setup Installer
echo ========================================================
echo.

:: 1. Auto-detect Python
echo [*] Checking for Python in the system path...
SET PYTHON_EXE=
python --version >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    SET PYTHON_EXE=python
    GOTO :found
)

py --version >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    SET PYTHON_EXE=py
    GOTO :found
)

color 0C
echo [ERROR] Python was not found on your system!
echo Please download and install Python from https://www.python.org/downloads/
echo Make sure to check the box "Add Python to PATH" during installation.
pause
exit /b

:found
echo [OK] Python is found: %PYTHON_EXE%
%PYTHON_EXE% --version
echo.

:: 2. Upgrade pip
echo [*] Upgrading pip to the latest version...
%PYTHON_EXE% -m pip install --upgrade pip >nul 2>&1
echo [OK] pip upgraded.
echo.

:: 3. Install Requirements
echo [*] Installing required Python libraries...
%PYTHON_EXE% -m pip install scapy bleak mac-vendor-lookup flask flask-cors plyer python-nmap psutil pillow pystray

echo.
echo ========================================================
echo   PYTHON SETUP COMPLETE!
echo ========================================================
echo.
color 0E
echo ⚠️ IMPORTANT SYSTEM REQUIREMENTS ⚠️
echo For this app to actually scan the network, you MUST have these installed:
echo 1. Nmap - Download at: https://nmap.org/download.html
echo 2. Npcap - Download at: https://npcap.com/ (IMPORTANT: Check the box "Install Npcap in WinPcap API-compatible Mode" during installation!)
echo.
echo To start your server later, you must run this script from an ADMINISTRATOR terminal:
echo %PYTHON_EXE% app_launcher.py
echo ========================================================
pause