import json
import os
import sys
import time
import asyncio
import nmap
import socket
import threading
import psutil
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


# ── Scapy cache permission fix (must be before scapy import) ──
_scapy_cache = os.path.join(os.path.expanduser("~"), ".cache", "scapy")
os.makedirs(_scapy_cache, exist_ok=True)
_pickle = os.path.join(_scapy_cache, "services.pickle")
if os.path.exists(_pickle):
    try:
        os.remove(_pickle)
    except PermissionError:
        pass


from scapy.all import ARP, Ether, srp
from bleak import BleakScanner
from mac_vendor_lookup import MacLookup
from flask import Flask, jsonify, render_template, send_from_directory, request
from flask_cors import CORS
from plyer import notification


# ─────────────────────────────────────────
# INIT
# ─────────────────────────────────────────
vendor_lookup = MacLookup()
try:
    vendor_lookup.update_vendors()
except:
    pass


GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


DB_FILE         = "known_devices.json"
LOG_FILE        = "activity_log.txt"
BT_FILE         = "bt_devices.json"
HISTORY_FILE    = "scan_history.json"   # ── NEW
SCAN_INTERVAL   = 60
HISTORY_MAX     = 1440                  # keep last 24 hrs of per-minute snapshots


_latest_wifi = []
_latest_bt   = []
_scan_meta   = {"last_scan": None, "network": "detecting..."}
_state_lock  = threading.Lock()
_db_lock     = threading.Lock()
_net_stats   = {"upload_speed": "0 KB/s", "download_speed": "0 KB/s"}


BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
CORS(app)

logging.getLogger("werkzeug").setLevel(logging.WARNING)


# ─────────────────────────────────────────
# LOGGING & ALERTS
# ─────────────────────────────────────────
def log_activity(message):
    with open(LOG_FILE, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")


def send_alert(title, message):
    def _notify():
        try:
            notification.notify(
                title=title,
                message=message,
                app_name='Threat Monitor',
                timeout=10
            )
        except Exception:
            pass
    threading.Thread(target=_notify, daemon=True).start()


def read_logs(n=100):
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()[-n:]
    result = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            ts  = line[1:20]
            msg = line[22:]
        except:
            ts, msg = "", line
        severity = "ok"
        if any(x in msg for x in ["ALERT", "NEW DEVICE", "SUSPICIOUS BT"]):
            severity = "alert"
        elif any(x in msg for x in ["SUSPICIOUS", "Spoofing"]):
            severity = "warn"
        result.append({"time": ts, "msg": msg, "type": severity})
    return result


# ─────────────────────────────────────────
# SCAN HISTORY  ── NEW
# ─────────────────────────────────────────
def load_scan_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except:
        return []


def append_scan_history(devices):
    """Called after every scan cycle. Appends one snapshot, caps at HISTORY_MAX."""
    now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total   = len(devices)
    trusted = sum(1 for d in devices if d.get("status") in ("trusted", "self"))
    unknown = sum(1 for d in devices if d.get("status") == "unknown")
    suspicious = sum(1 for d in devices if d.get("status") == "suspicious")

    history = load_scan_history()
    history.append({
        "time":       now,
        "total":      total,
        "trusted":    trusted,
        "unknown":    unknown,
        "suspicious": suspicious,
    })
    # Keep only last HISTORY_MAX entries
    history = history[-HISTORY_MAX:]
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f)


# ─────────────────────────────────────────
# DEVICE DATABASE
# ─────────────────────────────────────────
def _load_db_unlocked():
    """Call only when _db_lock is already held."""
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r") as f:
            content = f.read().strip()
            return json.loads(content) if content else {}
    except json.JSONDecodeError:
        print(f"{YELLOW}[!] {DB_FILE} is corrupted. Resetting...{RESET}")
        try:
            os.remove(DB_FILE)
        except FileNotFoundError:
            pass
        return {}


def load_known_devices():
    with _db_lock:
        return _load_db_unlocked()


def save_device(mac, ip, hostname, vendor, ports, os_guess):
    with _db_lock:
        known  = _load_db_unlocked()
        is_new = False
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if mac not in known:
            known[mac] = {
            "ip": ip, "hostname": hostname, "vendor": vendor,
            "status": "unknown", "os": os_guess, "ports": ports,
            "history": [ip], "first_seen": now, "last_seen": now,
            "nickname": "",
            }
            is_new = True
            send_alert("⚠️ New Device Detected", f"{vendor} ({mac}) at {ip}")
        else:
            entry = known[mac]
            if entry["ip"] != ip:
                log_activity(f"SUSPICIOUS: MAC Spoofing? {mac} moved to {ip}")
                send_alert("🚨 Security Alert", f"MAC Spoofing? {mac} moved to {ip}")
                entry["history"] = entry.get("history", []) + [ip]
                if entry["status"] not in ("trusted", "blocked"):
                    entry["status"] = "suspicious"

            protected = entry.get("status") in ("trusted", "blocked")
            entry.update({"ip": ip, "hostname": hostname, "vendor": vendor,
                          "ports": ports, "os": os_guess, "last_seen": now})
            if protected:
                entry["status"] = known[mac]["status"]

        with open(DB_FILE, "w") as f:
            json.dump(known, f, indent=4)
        return is_new


def mark_trusted(mac):
    with _db_lock:
        known = _load_db_unlocked()
        if mac not in known:
            return False
        known[mac]["status"] = "trusted"
        with open(DB_FILE, "w") as f:
            json.dump(known, f, indent=4)
    unblock_ip_on_windows(mac)
    return True


def mark_blocked(mac):
    with _db_lock:
        known = _load_db_unlocked()
        if mac not in known:
            return False
        known[mac]["status"] = "blocked"
        ip = known[mac].get("ip")
        with open(DB_FILE, "w") as f:
            json.dump(known, f, indent=4)
    if ip:
        block_ip_on_windows(ip, mac)
    return True


# ─────────────────────────────────────────
# FIREWALL
# ─────────────────────────────────────────
def block_ip_on_windows(ip, mac):
    rule_name = f"BLOCKED_{mac.replace(':', '-')}"
    try:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes"
        ], check=True, capture_output=True)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}_OUT", "dir=out", "action=block",
            f"remoteip={ip}", "enable=yes"
        ], check=True, capture_output=True)
        log_activity(f"FIREWALL: Blocked IP {ip} (MAC: {mac})")
        return True
    except subprocess.CalledProcessError as e:
        log_activity(f"FIREWALL ERROR: Could not block {ip} — {e}")
        return False


def unblock_ip_on_windows(mac):
    rule_name = f"BLOCKED_{mac.replace(':', '-')}"
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}"], capture_output=True)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}_OUT"], capture_output=True)
        log_activity(f"FIREWALL: Unblocked MAC {mac}")
    except:
        pass


# ─────────────────────────────────────────
# NETWORK AUDIT
# ─────────────────────────────────────────
DANGEROUS_PORTS = {
    23: "Telnet", 1337: "Hacking Tool", 4444: "Metasploit",
    3389: "RDP", 5900: "VNC", 8080: "Alt HTTP"
}


def check_suspicious_ports(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O -sV --top-ports 20')
        results = {"ports": [], "os": "Unknown"}
        if ip in nm.all_hosts():
            if nm[ip].get("osmatch"):
                results["os"] = nm[ip]["osmatch"][0]["name"]
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    if nm[ip][proto][port]["state"] == "open":
                        results["ports"].append(port)
                        if port in DANGEROUS_PORTS:
                            log_activity(f"ALERT: {ip} port {port} open ({DANGEROUS_PORTS[port]})")
        return results
    except:
        return {"ports": [], "os": "Unknown"}


# ─────────────────────────────────────────
# BLUETOOTH SCAN
# ─────────────────────────────────────────
async def _bt_scan():
    print(f"\n{CYAN}[*] Scanning Bluetooth...{RESET}")
    try:
        discovered = await BleakScanner.discover(timeout=5.0)
        found = []
        for d in discovered:
            name          = d.name if d.name else "Unknown/Hidden"
            is_suspicious = not d.name
            if is_suspicious:
                log_activity(f"SUSPICIOUS BT: Hidden device at {d.address}")
            found.append({
                "address":    d.address,
                "name":       name,
                "signal":     getattr(d, "rssi", "N/A"),
                "suspicious": is_suspicious
            })
        return found
    except Exception as e:
        print(f"{RED}[!] BT Error: {e}{RESET}")
        return []


def scan_bluetooth():
    return asyncio.run(_bt_scan())


# ─────────────────────────────────────────
# WIFI SCAN & BANDWIDTH
# ─────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"


def get_ip_range(local_ip):
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def scan_wifi(ip_range, local_ip):
    print(f"\n{CYAN}[*] Scanning Wi-Fi: {ip_range}...{RESET}")
    result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range),
                 timeout=3, verbose=False)[0]

    devices_to_audit = []
    known = load_known_devices()

    for _, received in result:
        ip, mac = received.psrc, received.hwsrc
        try:    hostname = socket.gethostbyaddr(ip)[0]
        except: hostname = "Unnamed Device"
        try:    vendor = vendor_lookup.lookup(mac)
        except: vendor = "Unknown Manufacturer"
        devices_to_audit.append({"ip": ip, "mac": mac,
                                  "hostname": hostname, "vendor": vendor})

    def audit_task(dev):
        ip, mac = dev['ip'], dev['mac']
        if ip == local_ip:
            return {**dev, "status": "self", "ports": [],
                    "os": "This machine", "last_seen": "Now"}

        prev_entry  = known.get(mac)
        prev_status = prev_entry["status"] if prev_entry else None

        if prev_status is None or prev_status == "suspicious":
            audit    = check_suspicious_ports(ip)
            ports    = audit["ports"]
            os_guess = audit["os"]
        else:
            ports    = prev_entry.get("ports", [])
            os_guess = prev_entry.get("os", "Unknown")

        is_new = save_device(mac, ip, dev['hostname'], dev['vendor'], ports, os_guess)
        status = load_known_devices().get(mac, {}).get("status", "unknown")
        return {**dev, "status": status, "ports": ports, "os": os_guess,
                "is_new": is_new,
                "last_seen": datetime.now().strftime("%H:%M:%S")}

    with ThreadPoolExecutor(max_workers=10) as executor:
        return list(executor.map(audit_task, devices_to_audit))


def monitor_bandwidth():
    global _net_stats
    old_value = psutil.net_io_counters()
    while True:
        time.sleep(1)
        new_value = psutil.net_io_counters()
        upload   = new_value.bytes_sent - old_value.bytes_sent
        download = new_value.bytes_recv - old_value.bytes_recv
        with _state_lock:
            _net_stats["upload_speed"]   = f"{upload   / 1024:.1f} KB/s"
            _net_stats["download_speed"] = f"{download / 1024:.1f} KB/s"
        if upload > 5 * 1024 * 1024:
            send_alert("🚀 High Upload Detected",
                       f"Network uploading at {upload / 1024 / 1024:.1f} MB/s")
        old_value = new_value


# ─────────────────────────────────────────
# MAIN SCAN LOOP
# ─────────────────────────────────────────
def scan_loop():
    global _latest_wifi, _latest_bt, _scan_meta
    while True:
        l_ip = get_local_ip()
        ip_r = get_ip_range(l_ip)
        w_devs, b_devs = scan_wifi(ip_r, l_ip), scan_bluetooth()
        with _state_lock:
            _latest_wifi = w_devs
            _latest_bt   = b_devs
            _scan_meta   = {
                "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "network":   ip_r
            }
        append_scan_history(w_devs)   # ── NEW: snapshot after every scan
        log_activity(f"Full scan completed. Local IP: {l_ip}. Devices found: {len(w_devs)}")
        print(f"\n[*] Cycle complete. Next scan in {SCAN_INTERVAL}s...")
        time.sleep(SCAN_INTERVAL)


# ─────────────────────────────────────────
# FLASK ROUTES
# ─────────────────────────────────────────
@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        BASE_DIR,
        "icon.ico",
        mimetype="image/vnd.microsoft.icon"
    )


@app.route("/api/status")
def api_status():
    with _state_lock:
        total   = len(_latest_wifi)
        unknown = sum(1 for d in _latest_wifi if d.get("status") in ("unknown", "suspicious"))
        ports   = sum(len(d.get("ports", [])) for d in _latest_wifi)
        bt      = len(_latest_bt)
        return jsonify({
            **_scan_meta,
            "total":      total,
            "unknown":    unknown,
            "open_ports": ports,
            "bt_nearby":  bt,
            "bandwidth":  _net_stats,
        })


@app.route("/api/devices")
def api_devices():
    with _state_lock:
        data = list(_latest_wifi)
    known = load_known_devices()
    for device in data:
        mac = device.get("mac")
        if mac and mac in known:
            device["status"]     = known[mac].get("status", device.get("status"))
            device["first_seen"] = known[mac].get("first_seen")
            device["history"]    = known[mac].get("history", [device.get("ip")])
    return jsonify(data)


@app.route("/api/bluetooth")
def api_bluetooth():
    with _state_lock:
        return jsonify(list(_latest_bt))


@app.route("/api/logs")
def api_logs():
    return jsonify(read_logs(100))


@app.route("/api/known")
def api_known():
    return jsonify(load_known_devices())


# ── NEW: history endpoint ──
@app.route("/api/history")
def api_history():
    return jsonify(load_scan_history())


@app.route("/api/trust/<mac>", methods=["POST"])
def api_trust(mac):
    mac = mac.replace("-", ":")
    ok  = mark_trusted(mac)
    if ok:
        log_activity(f"User marked {mac} as TRUSTED")
    return jsonify({"ok": ok})


@app.route("/api/block/<mac>", methods=["POST"])
def api_block(mac):
    mac = mac.replace("-", ":")
    ok  = mark_blocked(mac)
    if ok:
        log_activity(f"User marked {mac} as BLOCKED")
    return jsonify({"ok": ok})

@app.route("/api/nickname/<mac>", methods=["POST"])
def api_nickname(mac):
    mac = mac.replace("-", ":")
    data = request.get_json(silent=True) or {}
    nickname = str(data.get("nickname", "")).strip()[:40]  # max 40 chars
    with _db_lock:
        known = _load_db_unlocked()
        if mac not in known:
            return jsonify({"ok": False, "error": "Device not found"}), 404
        known[mac]["nickname"] = nickname
        with open(DB_FILE, "w") as f:
            json.dump(known, f, indent=4)
    log_activity(f"User set nickname for {mac}: '{nickname}'")
    return jsonify({"ok": True, "nickname": nickname})

@app.route("/api/scan/now", methods=["POST"])
def api_scan_now():
    def do_scan():
        global _latest_wifi, _latest_bt, _scan_meta
        l_ip = get_local_ip()
        ip_r = get_ip_range(l_ip)
        w_devs, b_devs = scan_wifi(ip_r, l_ip), scan_bluetooth()
        with _state_lock:
            _latest_wifi = w_devs
            _latest_bt   = b_devs
            _scan_meta   = {
                "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "network":   ip_r
            }
        append_scan_history(w_devs)   # ── NEW
        log_activity(f"Manual scan triggered. Devices found: {len(w_devs)}")
    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"ok": True, "msg": "Scan started"})


if __name__ == "__main__":
    import logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    import flask.cli
    flask.cli.show_server_banner = lambda *args, **kwargs: None
    
    local_ip = get_local_ip()
    print(f"\n * Running on http://127.0.0.1:5000")
    print(f" * Running on http://{local_ip}:5000  (share this with your phone)")
    print(" * Enter ctrl+C to exit.\n")
    threading.Thread(target=scan_loop,         daemon=True).start()
    threading.Thread(target=monitor_bandwidth, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
