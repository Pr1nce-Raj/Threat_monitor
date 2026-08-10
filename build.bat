@echo off
echo Building Threat Monitor...
pyinstaller --noconfirm --onefile --windowed ^
  --name "ThreatMonitor" ^
  --icon "icon.ico" ^
  --add-data "templates;templates" ^
  --add-data "icon.ico;." ^
  --hidden-import "flask" ^
  --hidden-import "flask_cors" ^
  --hidden-import "pystray" ^
  --hidden-import "plyer.platforms.win.notification" ^
  --hidden-import "scapy.all" ^
  --hidden-import "bleak" ^
  --hidden-import "nmap" ^
  --noconsole ^
  --uac-admin ^
  app_launcher.py
echo.
echo Done! Your .exe is in the dist/ folder.
pause
