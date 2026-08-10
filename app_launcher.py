import subprocess
import sys
import os

# ── Patch subprocess BEFORE any other import so netsh/nmap never show a window ──
if sys.platform == "win32":
    _original_init = subprocess.Popen.__init__
    def _patched_init(self, *args, **kwargs):
        kwargs.setdefault('creationflags', 0x08000000)  # CREATE_NO_WINDOW
        _original_init(self, *args, **kwargs)
    subprocess.Popen.__init__ = _patched_init

import threading
import webbrowser
import time
import logging

# Check administrative privileges
def is_admin():
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return os.getuid() == 0 if hasattr(os, 'getuid') else True

if not is_admin():
    print("\n" + "=" * 60)
    print(" [!] WARNING: NOT RUNNING AS ADMINISTRATOR")
    print(" Threat Monitor requires Administrator privileges to perform raw")
    print(" Wi-Fi packet sniffing (Scapy) and active port scanning (Nmap).")
    print(" Please restart this terminal/script as Administrator.")
    print("=" * 60 + "\n")

# Try importing scanner dependencies first, catching errors gracefully
try:
    from scanner import app, scan_loop, monitor_bandwidth, get_local_ip
except Exception as e:
    print(f"\n[!] Critical Error: Failed to import scanner modules: {e}")
    print("Please make sure all dependencies are installed (run setup.bat).")
    input("\nPress Enter to exit...")
    sys.exit(1)

SERVER_URL = "http://localhost:5000"

def start_flask():
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    import flask.cli
    flask.cli.show_server_banner = lambda *args, **kwargs: None

    local_ip = get_local_ip()
    print(f"\n * Running on http://127.0.0.1:5000")
    print(f" * Running on http://{local_ip}:5000  (share this with your phone)\n")

    try:
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except Exception as e:
        print(f"[!] Flask server failed to start: {e}")
        os._exit(1)

def main():
    # Start background threads for scanning and bandwidth monitoring
    threading.Thread(target=scan_loop,         daemon=True).start()
    threading.Thread(target=monitor_bandwidth, daemon=True).start()

    # Browser opening thread
    def auto_open():
        time.sleep(3)
        webbrowser.open(SERVER_URL)
    threading.Thread(target=auto_open, daemon=True).start()

    # Try to initialize the system tray icon
    use_tray = True
    try:
        from PIL import Image, ImageDraw
        import pystray

        def create_icon_image():
            img  = Image.new("RGB", (64, 64), color=(13, 15, 20))
            draw = ImageDraw.Draw(img)
            draw.ellipse([16, 16, 48, 48], fill=(34, 201, 122))
            return img

        def open_dashboard(icon, item):
            webbrowser.open(SERVER_URL)

        def quit_app(icon, item):
            icon.stop()
            os._exit(0)

    except ImportError:
        use_tray = False
        print("[!] pystray or Pillow (PIL) is not installed. System tray icon disabled.")

    if use_tray:
        # Start Flask in a background daemon thread since tray icon blocks the main thread
        threading.Thread(target=start_flask, daemon=True).start()
        
        try:
            icon_image = create_icon_image()
            tray_icon  = pystray.Icon(
                name="ThreatMonitor",
                icon=icon_image,
                title="Threat Monitor",
                menu=pystray.Menu(
                    pystray.MenuItem("📡 Open Dashboard", open_dashboard, default=True),
                    pystray.MenuItem("❌ Quit",            quit_app),
                )
            )
            tray_icon.run()
        except Exception as e:
            print(f"[!] System tray icon failed to run: {e}")
            print("[*] Falling back to running Flask on the main thread.")
            start_flask()
    else:
        # Console fallback: run Flask on the main thread (blocking)
        start_flask()

if __name__ == "__main__":
    main()