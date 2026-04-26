import subprocess
import sys
import os

# ── Patch subprocess BEFORE any other import so netsh/nmap never show a window ──
if sys.platform == "win32":
    _original_popen = subprocess.Popen
    def _silent_popen(*args, **kwargs):
        kwargs.setdefault('creationflags', 0x08000000)  # CREATE_NO_WINDOW
        return _original_popen(*args, **kwargs)
    subprocess.Popen = _silent_popen

import threading
import webbrowser
import time
import logging
from PIL import Image, ImageDraw
import pystray
from scanner import app, scan_loop, monitor_bandwidth, get_local_ip

SERVER_URL = "http://localhost:5000"


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


def start_flask():
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    import flask.cli
    flask.cli.show_server_banner = lambda *args, **kwargs: None

    local_ip = get_local_ip()
    print(f"\n * Running on http://127.0.0.1:5000")
    print(f" * Running on http://{local_ip}:5000  (share this with your phone)\n")

    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


def main():
    threading.Thread(target=scan_loop,         daemon=True).start()
    threading.Thread(target=monitor_bandwidth, daemon=True).start()
    threading.Thread(target=start_flask,       daemon=True).start()

    def auto_open():
        time.sleep(3)
        webbrowser.open(SERVER_URL)
    threading.Thread(target=auto_open, daemon=True).start()

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


if __name__ == "__main__":
    main()