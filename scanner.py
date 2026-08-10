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
import re
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


from scapy.all import ARP, Ether, srp, srp1, IP, UDP, DNS, DNSQR, DNSRR, Raw, sendp, sniff, conf, ICMP
from scapy.layers.dhcp import DHCP
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
    vendor_lookup.load_vendors()
except:
    pass

def _async_update_vendors():
    try:
        vendor_lookup.update_vendors()
    except:
        pass
threading.Thread(target=_async_update_vendors, daemon=True).start()



GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


DB_FILE         = "known_devices.json"
BT_DB_FILE      = "known_bluetooth_devices.json"
LOG_FILE        = "activity_log.txt"
BT_LOG_FILE     = "bluetooth_activity_log.txt"
BT_FILE         = "bt_devices.json"
HISTORY_FILE    = "scan_history.json"   # ── NEW
SCAN_INTERVAL   = 60
HISTORY_MAX     = 1440                  # keep last 24 hrs of per-minute snapshots


_latest_wifi  = []
_latest_bt    = []
_scan_meta    = {"last_scan": None, "network": "detecting..."}
_state_lock   = threading.Lock()
_db_lock      = threading.Lock()
_bt_db_lock   = threading.Lock()
_scan_lock    = threading.Lock()
_history_lock = threading.Lock()
_is_scanning  = False
_scan_error   = None
_net_stats    = {"upload_speed": "0 KB/s", "download_speed": "0 KB/s"}


BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
CORS(app)

logging.getLogger("werkzeug").setLevel(logging.WARNING)


# ─────────────────────────────────────────
# LOGGING & ALERTS
# ─────────────────────────────────────────
def log_activity(message, log_type="wifi"):
    filename = BT_LOG_FILE if log_type == "bluetooth" else LOG_FILE
    with open(filename, "a") as f:
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


def read_logs(n=100, log_type="wifi"):
    filename = BT_LOG_FILE if log_type == "bluetooth" else LOG_FILE
    if not os.path.exists(filename):
        return []
    with open(filename, "r") as f:
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
    with _history_lock:
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

    with _history_lock:
        history = []
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r") as f:
                    history = json.load(f)
            except:
                pass
        history.append({
            "time":       now,
            "total":      total,
            "trusted":    trusted,
            "unknown":    unknown,
            "suspicious": suspicious,
        })
        # Keep only last HISTORY_MAX entries
        history = history[-HISTORY_MAX:]
        try:
            with open(HISTORY_FILE, "w") as f:
                json.dump(history, f)
        except Exception as e:
            log_activity(f"HISTORY FILE ERROR: Could not write scan history — {e}")


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


def load_known_bluetooth_devices():
    with _bt_db_lock:
        if not os.path.exists(BT_DB_FILE):
            return {}
        try:
            with open(BT_DB_FILE, "r") as f:
                content = f.read().strip()
                return json.loads(content) if content else {}
        except Exception:
            return {}


def save_bluetooth_device(address, name, signal, is_suspicious):
    with _bt_db_lock:
        db = {}
        if os.path.exists(BT_DB_FILE):
            try:
                with open(BT_DB_FILE, "r") as f:
                    content = f.read().strip()
                    db = json.loads(content) if content else {}
            except Exception:
                db = {}
        
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_new = False
        
        if address not in db:
            is_new = True
            db[address] = {
                "address": address,
                "name": name if name else "Unknown/Hidden",
                "nickname": "",
                "status": "suspicious" if is_suspicious else "trusted",
                "first_seen": now_str,
                "last_seen": now_str,
                "signal": signal,
                "history": [signal] if signal != "N/A" else []
            }
            log_activity(f"NEW BT DEVICE: Discovered {name if name else 'Unknown/Hidden'} ({address})", log_type="bluetooth")
        else:
            dev = db[address]
            if (dev.get("name") == "Unknown/Hidden" or not dev.get("name")) and name and name != "Unknown/Hidden":
                dev["name"] = name
            
            dev["last_seen"] = now_str
            dev["signal"] = signal
            if signal != "N/A":
                if "history" not in dev:
                    dev["history"] = []
                dev["history"].append(signal)
                dev["history"] = dev["history"][-20:]
        
        try:
            with open(BT_DB_FILE, "w") as f:
                json.dump(db, f, indent=4)
        except Exception as e:
            print(f"Failed to write to Bluetooth database: {e}")
        
        return is_new


def save_device(mac, ip, hostname, vendor, ports, os_guess, friendly_name="", device_type="Generic Device"):
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
            "friendly_name": friendly_name,
            "device_type": device_type,
            }
            is_new = True
            send_alert("⚠️ New Device Detected", f"{vendor} ({mac}) at {ip}")
            resolved_info = f" Name={friendly_name}, Type={device_type}" if friendly_name else ""
            log_activity(f"NEW DEVICE: Discovered {vendor} ({mac}) at {ip}{resolved_info}")
        else:
            entry = known[mac]
            if entry["ip"] != ip:
                log_activity(f"INFO: Device {mac} changed IP from {entry['ip']} to {ip}")
                entry["history"] = entry.get("history", []) + [ip]
                # Re-apply firewall block if IP changed for blocked device
                if entry.get("status") == "blocked":
                    unblock_ip_on_windows(mac)
                    block_ip_on_windows(ip, mac)

            updated_fields = []
            if friendly_name and entry.get("friendly_name") != friendly_name:
                entry["friendly_name"] = friendly_name
                updated_fields.append(f"Name={friendly_name}")
            if device_type and device_type != "Generic Device" and entry.get("device_type", "Generic Device") != device_type:
                entry["device_type"] = device_type
                updated_fields.append(f"Type={device_type}")
            
            if updated_fields:
                log_activity(f"ACTIVE DISCOVERY: Resolved details for {ip} ({mac}): {', '.join(updated_fields)}")

            protected = entry.get("status") in ("trusted", "blocked")
            # Preserve hostname and vendor if new results are generic placeholders
            new_hostname = hostname if hostname != "Unnamed Device" else entry.get("hostname", "Unnamed Device")
            new_vendor = vendor if vendor != "Unknown Manufacturer" else entry.get("vendor", "Unknown Manufacturer")

            entry.update({"ip": ip, "hostname": new_hostname, "vendor": new_vendor,
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
        return block_ip_on_windows(ip, mac)
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
# ACTIVE & PASSIVE NETWORK FINGERPRINTING
# ─────────────────────────────────────────
_sniffer_started = False

def get_scapy_iface(local_ip):
    try:
        for iface in conf.ifaces.values():
            if getattr(iface, "ip", None) == local_ip:
                return iface
    except Exception:
        pass
    return None

def clean_mdns_name(name):
    if not name:
        return None
    if name.endswith('.'):
        name = name[:-1]
    if name.lower().endswith('.local'):
        name = name[:-6]
    if '_tcp' in name or '_udp' in name:
        parts = name.split('.')
        filtered = [p for p in parts if not p.startswith('_')]
        if filtered:
            name = '.'.join(filtered)
        else:
            return None
    if 'in-addr.arpa' in name:
        return None
    return name

def classify_device_type_from_name(name):
    name_lower = name.lower()
    if "iphone" in name_lower:
        return "Smartphone (iPhone)"
    elif "ipad" in name_lower:
        return "Tablet (iPad)"
    elif "android" in name_lower:
        return "Smartphone (Android)"
    elif "macbook" in name_lower or "mac-mini" in name_lower or "imac" in name_lower:
        return "Computer (Mac)"
    elif "desktop" in name_lower or "laptop" in name_lower or "workstation" in name_lower:
        return "Computer (Windows/Linux)"
    elif "tv" in name_lower or "television" in name_lower or "roku" in name_lower or "firestick" in name_lower or "chromecast" in name_lower or "webos" in name_lower:
        return "Smart TV / Media Player"
    elif "printer" in name_lower or "laserjet" in name_lower or "officejet" in name_lower or "epson" in name_lower:
        return "Printer"
    elif "sonos" in name_lower or "nest" in name_lower or "echo" in name_lower or "speaker" in name_lower or "alexa" in name_lower or "googlecast" in name_lower:
        return "Smart Speaker / Cast"
    elif "camera" in name_lower or "doorbell" in name_lower or "ring" in name_lower or "cctv" in name_lower:
        return "IP Camera / Security"
    elif "router" in name_lower or "gateway" in name_lower or "ap" in name_lower or "switch" in name_lower:
        return "Network Device"
    return "Generic Device"

def update_device_passive(mac, ip, friendly_name, device_type):
    if not mac or not ip:
        return
    mac = mac.lower().replace('-', ':')
    with _db_lock:
        known = _load_db_unlocked()
        updated = False
        if mac in known:
            entry = known[mac]
            if friendly_name and not entry.get("friendly_name"):
                entry["friendly_name"] = friendly_name
                updated = True
            if device_type and device_type != "Generic Device" and entry.get("device_type", "Generic Device") == "Generic Device":
                entry["device_type"] = device_type
                updated = True
            if entry.get("ip") != ip:
                entry["ip"] = ip
                updated = True
            if updated:
                entry["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            is_private_mac = False
            if len(mac) >= 2:
                second_char = mac[1].lower()
                if second_char in ['2', '3', '6', '7', 'a', 'b', 'e', 'f']:
                    is_private_mac = True

            vendor = "Private MAC (Randomized)" if is_private_mac else "Unknown Manufacturer"
            final_type = "Smartphone / Tablet (Privacy)" if is_private_mac else (device_type or "Generic Device")

            known[mac] = {
                "ip": ip, "hostname": "Unnamed Device", "vendor": vendor,
                "status": "unknown", "os": "Unknown", "ports": [],
                "history": [ip], "first_seen": now, "last_seen": now,
                "nickname": "",
                "friendly_name": friendly_name,
                "device_type": final_type,
            }
            updated = True
            
        if updated:
            with open(DB_FILE, "w") as f:
                json.dump(known, f, indent=4)
            log_activity(f"PASSIVE DISCOVERY: Resolved details for {ip} ({mac}): Name={friendly_name}, Type={device_type}")

_scapy_l2_lock = threading.Lock()

def query_device_details_l2(ip, mac, iface):
    with _scapy_l2_lock:
        hostname = None
        parts = ip.split('.')
        reverse_ip = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
        
        # log query start
        print(f"L2 QUERY: Querying mDNS reverse IP for {ip} ({mac})", flush=True)
        
        for suffix in ["", ".local"]:
            qname = reverse_ip + suffix
            try:
                pkt = (
                    Ether(dst=mac) /
                    IP(dst=ip) /
                    UDP(sport=5353, dport=5353) /
                    DNS(rd=1, qd=DNSQR(qname=qname, qtype="PTR"))
                )
                ans = srp1(pkt, iface=iface, timeout=1.5, verbose=False)
                if ans:
                    if ans.haslayer(ICMP):
                        print(f"L2 QUERY DEBUG: {ip} returned ICMP error for mDNS", flush=True)
                        continue
                    if ans.haslayer(UDP) and ans[UDP].sport == 5353:
                        data = bytes(ans[UDP].payload)
                        import re
                        strings = re.findall(rb'[a-zA-Z0-9\-\. ]{4,100}', data)
                        candidates = []
                        for s in strings:
                            s_str = s.decode('ascii', errors='ignore').strip()
                            # Ignore infrastructure names like in-addr and arpa
                            if (s_str.startswith('_') or 
                                'in-addr' in s_str.lower() or 
                                'arpa' in s_str.lower() or 
                                s_str.lower() in ('local', 'services', 'dns-sd', 'udp', 'tcp', 'ptr', 'in', 'device-info')):
                                continue
                            if '.' in s_str:
                                s_str = s_str.split('.')[0]
                            if len(s_str) >= 4 and s_str not in candidates:
                                candidates.append(s_str)
                        if candidates:
                            hostname = candidates[0]
                            print(f"L2 QUERY: Resolved mDNS hostname '{hostname}' for {ip}", flush=True)
                            break
            except Exception as e:
                print(f"L2 QUERY ERROR: Exception querying mDNS for {ip}: {e}", flush=True)
                
        if hostname:
            return {
                "friendly_name": hostname,
                "device_type": classify_device_type_from_name(hostname)
            }
            
        # Try NetBIOS
        print(f"L2 QUERY: Querying NetBIOS status for {ip} ({mac})", flush=True)
        try:
            payload = (
                b'\xab\x12\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
            )
            pkt = (
                Ether(dst=mac) /
                IP(dst=ip) /
                UDP(sport=137, dport=137) /
                Raw(load=payload)
            )
            ans = srp1(pkt, iface=iface, timeout=1.5, verbose=False)
            if ans:
                if ans.haslayer(ICMP):
                    print(f"L2 QUERY DEBUG: {ip} returned ICMP error for NetBIOS", flush=True)
                    return None
                if ans.haslayer(UDP) and ans[UDP].sport == 137:
                    if ans.haslayer(Raw):
                        data = ans[Raw].load
                        if len(data) > 57:
                            num_names = data[56]
                            offset = 57
                            for _ in range(num_names):
                                if len(data) >= offset + 18:
                                    name_bytes = data[offset:offset+15]
                                    name_type = data[offset+15]
                                    if name_type == 0x00:
                                        name = name_bytes.decode('ascii', errors='ignore').strip()
                                        print(f"L2 QUERY: Resolved NetBIOS name '{name}' for {ip}", flush=True)
                                        return {
                                            "friendly_name": name,
                                            "device_type": "Windows/Linux PC"
                                        }
                                    offset += 18
            else:
                print(f"L2 QUERY DEBUG: NetBIOS query for {ip} timed out", flush=True)
        except Exception as e:
            print(f"L2 QUERY ERROR: Exception querying NetBIOS for {ip}: {e}", flush=True)
            
        return None

def send_active_multicast_queries_l2(iface):
    try:
        mdns_pkt = (
            Ether(dst="01:00:5e:00:00:fb") /
            IP(dst="224.0.0.251") /
            UDP(sport=5353, dport=5353) /
            DNS(rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR"))
        )
        sendp(mdns_pkt, iface=iface, verbose=False)
        
        m_search = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )
        upnp_pkt = (
            Ether(dst="01:00:5e:7f:ff:fa") /
            IP(dst="239.255.255.250") /
            UDP(sport=1900, dport=1900) /
            Raw(load=m_search.encode('utf-8'))
        )
        sendp(upnp_pkt, iface=iface, verbose=False)
    except Exception:
        pass

def passive_sniff_callback(pkt):
    try:
        if not pkt.haslayer(IP):
            return
            
        src_ip = pkt[IP].src
        local_ip = get_local_ip()
        if src_ip == local_ip:
            return
            
        mac = pkt.src if hasattr(pkt, 'src') else None
        if not mac:
            return
            
        friendly_name = ""
        device_type = "Generic Device"
        
        # 1. DHCP option parsing
        if pkt.haslayer(DHCP):
            opts = pkt[DHCP].options
            hostname = None
            for opt in opts:
                if isinstance(opt, tuple) and opt[0] == 'hostname':
                    hostname = opt[1].decode('utf-8', errors='ignore')
                    break
            if hostname:
                friendly_name = hostname
                device_type = classify_device_type_from_name(hostname)
                update_device_passive(mac, src_ip, friendly_name, device_type)
                
        # 2. mDNS parsing
        elif pkt.haslayer(UDP) and (pkt[UDP].sport == 5353 or pkt[UDP].dport == 5353):
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                names = []
                if dns.qdcount > 0:
                    for i in range(dns.qdcount):
                        q = dns.qd[i]
                        qname = q.qname.decode('utf-8', errors='ignore') if isinstance(q.qname, bytes) else str(q.qname)
                        names.append(qname)
                for rrcount, rr_list in [('ancount', dns.an), ('nscount', dns.ns), ('arcount', dns.ar)]:
                    if getattr(dns, rrcount) > 0 and rr_list:
                        curr = rr_list
                        while curr:
                            rname = curr.rrname.decode('utf-8', errors='ignore') if isinstance(curr.rrname, bytes) else str(curr.rrname)
                            names.append(rname)
                            if curr.type == 12: # PTR
                                rdata = curr.rdata.decode('utf-8', errors='ignore') if isinstance(curr.rdata, bytes) else str(curr.rdata)
                                names.append(rdata)
                            try:
                                curr = curr.payload
                            except:
                                break
                                
                extracted_name = None
                is_cast = False
                for name in names:
                    if '_googlecast' in name or '_chromecast' in name:
                        is_cast = True
                    clean = clean_mdns_name(name)
                    if clean and len(clean) >= 4 and not clean.startswith('_'):
                        extracted_name = clean
                        break
                        
                if extracted_name:
                    friendly_name = extracted_name
                    if is_cast:
                        device_type = "Smart TV / Media Player"
                    else:
                        device_type = classify_device_type_from_name(extracted_name)
                    update_device_passive(mac, src_ip, friendly_name, device_type)
                    
        # 3. LLMNR / NetBIOS parsing
        elif pkt.haslayer(UDP) and (pkt[UDP].dport in (5355, 137) or pkt[UDP].sport in (5355, 137)):
            data = bytes(pkt[UDP].payload)
            import re
            strings = re.findall(rb'[a-zA-Z0-9\- ]{5,15}', data)
            candidates = []
            for s in strings:
                s_str = s.decode('ascii', errors='ignore').strip()
                if len(s_str) >= 5 and s_str.isalnum() and not s_str.startswith('CKAAAA'):
                    candidates.append(s_str)
            if candidates:
                friendly_name = candidates[0]
                device_type = classify_device_type_from_name(friendly_name)
                update_device_passive(mac, src_ip, friendly_name, device_type)
                
        # 4. UPnP SSDP parsing
        elif pkt.haslayer(UDP) and (pkt[UDP].sport == 1900 or pkt[UDP].dport == 1900):
            if pkt.haslayer(Raw):
                data = pkt[Raw].load.decode('utf-8', errors='ignore')
                location = None
                for line in re.split(r'\r?\n', data):
                    if line.lower().startswith('location:'):
                        location = line.split(':', 1)[1].strip()
                        break
                if location:
                    def fetch_xml():
                        try:
                            import urllib.request
                            import re
                            req = urllib.request.Request(location, headers={'User-Agent': 'Mozilla/5.0'})
                            with urllib.request.urlopen(req, timeout=2.0) as f:
                                xml_content = f.read().decode('utf-8', errors='ignore')
                            friendly = re.search(r'<friendlyName>(.*?)</friendlyName>', xml_content)
                            manufacturer = re.search(r'<manufacturer>(.*?)</manufacturer>', xml_content)
                            model = re.search(r'<modelName>(.*?)</modelName>', xml_content)
                            
                            f_name = None
                            if friendly:
                                f_name = friendly.group(1).strip()
                            elif manufacturer and model:
                                f_name = f"{manufacturer.group(1).strip()} {model.group(1).strip()}"
                                
                            if f_name:
                                d_type = "Generic Device"
                                combined = f_name.lower()
                                if any(x in combined for x in ("tv", "television", "bravia", "viera", "lg display", "webos")):
                                    d_type = "Smart TV"
                                elif any(x in combined for x in ("xbox", "playstation", "nintendo", "console")):
                                    d_type = "Game Console"
                                elif any(x in combined for x in ("router", "gateway", "access point", "modem", "firewall", "ubiquiti")):
                                    d_type = "Network Device"
                                elif any(x in combined for x in ("camera", "doorbell", "synology", "nas", "storage", "qnap")):
                                    d_type = "IP Camera / NAS"
                                elif any(x in combined for x in ("printer", "laserjet", "officejet", "epson")):
                                    d_type = "Printer"
                                elif any(x in combined for x in ("speaker", "sonos", "alexa", "echo", "nest", "cast", "receiver", "spotify")):
                                    d_type = "Smart Speaker / Cast"
                                update_device_passive(mac, src_ip, f_name, d_type)
                        except Exception:
                            pass
                    threading.Thread(target=fetch_xml, daemon=True).start()
    except Exception:
        pass

def run_passive_sniffer():
    local_ip = get_local_ip()
    iface = get_scapy_iface(local_ip)
    if iface:
        log_activity(f"PASSIVE DISCOVERY: Starting passive sniffer on interface {iface.name} ({iface.ip})")
        try:
            sniff(iface=iface, filter="udp and (port 67 or port 68 or port 5353 or port 137 or port 5355 or port 1900)",
                  prn=passive_sniff_callback, store=0)
        except Exception as e:
            log_activity(f"PASSIVE DISCOVERY ERROR: Sniffer exception: {e}")
            try:
                sniff(filter="udp and (port 67 or port 68 or port 5353 or port 137 or port 5355 or port 1900)",
                      prn=passive_sniff_callback, store=0)
            except Exception as e2:
                log_activity(f"PASSIVE DISCOVERY ERROR: Sniffer global fallback exception: {e2}")

def query_dnssd_l2(ip, mac, iface):
    services = ["_googlecast._tcp.local", "_airplay._tcp.local", "_services._dns-sd._udp.local"]
    for service in services:
        try:
            pkt = (
                Ether(dst=mac) /
                IP(dst=ip) /
                UDP(sport=5353, dport=5353) /
                DNS(rd=1, qd=DNSQR(qname=service, qtype="PTR"))
            )
            ans = srp1(pkt, iface=iface, timeout=1.0, verbose=False)
            if ans and ans.haslayer(UDP) and ans[UDP].sport == 5353:
                data = bytes(ans[UDP].payload)
                import re
                strings = re.findall(rb'[a-zA-Z0-9\-\. _]{4,100}', data)
                candidates = []
                for s in strings:
                    s_str = s.decode('ascii', errors='ignore').strip()
                    if (s_str.startswith('_') or 
                        'in-addr' in s_str.lower() or 
                        'arpa' in s_str.lower() or 
                        s_str.lower() in ('local', 'services', 'dns-sd', 'udp', 'tcp', 'ptr', 'in')):
                        continue
                    if '.' in s_str:
                        s_str = s_str.split('.')[0]
                    if len(s_str) >= 4 and s_str not in candidates:
                        candidates.append(s_str)
                if candidates:
                    return candidates[0]
        except Exception as e:
            print(f"L2 DNS-SD QUERY ERROR: Exception querying DNS-SD for {ip}: {e}", flush=True)
    return None

def query_http_metadata(ip):
    import ssl
    import urllib.request
    import re
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    headers = {'User-Agent': 'Mozilla/5.0'}
    for port in [80, 8080, 443]:
        proto = "https" if port == 443 else "http"
        url = f"{proto}://{ip}:{port}/"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=1.0, context=ctx) as response:
                html = response.read(4096)
                server = response.getheader('Server', '')
                www_auth = response.getheader('WWW-Authenticate', '')
                
                html_str = html.decode('utf-8', errors='ignore')
                title_match = re.search(r'<title>(.*?)</title>', html_str, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else ""
                
                if title or server or www_auth:
                    return {
                        "title": title,
                        "server": server,
                        "www_auth": www_auth,
                        "port": port
                    }
        except Exception:
            pass
    return None

def parse_http_metadata(meta):
    if not meta:
        return None
    title = meta.get("title", "")
    server = meta.get("server", "")
    www_auth = meta.get("www_auth", "")
    combined = f"{title} {server} {www_auth}".lower()
    
    friendly_name = title if title else ""
    device_type = "Generic Device"
    
    if "pi-hole" in combined:
        friendly_name = "Pi-hole Server"
        device_type = "Network Device"
    elif "mikrotik" in combined:
        friendly_name = "RouterOS Router"
        device_type = "Network Device"
    elif "dd-wrt" in combined:
        friendly_name = "DD-WRT Router"
        device_type = "Network Device"
    elif "openwrt" in combined:
        friendly_name = "OpenWrt Router"
        device_type = "Network Device"
    elif "synology" in combined:
        friendly_name = "Synology NAS"
        device_type = "Storage (NAS)"
    elif "qnap" in combined:
        friendly_name = "QNAP NAS"
        device_type = "Storage (NAS)"
    elif "printer" in combined or "laserjet" in combined or "officejet" in combined or "canon" in combined or "epson" in combined:
        device_type = "Printer"
    elif "camera" in combined or "hikvision" in combined or "dahua" in combined:
        device_type = "IP Camera / Security"
    elif "home assistant" in combined:
        friendly_name = "Home Assistant"
        device_type = "Smart Home Hub"
        
    return {
        "friendly_name": friendly_name,
        "device_type": device_type
    }

def classify_device_type_from_vendor_and_ports(vendor, ports):
    vendor_lower = vendor.lower()
    
    if "private mac" in vendor_lower or "randomized" in vendor_lower:
        return "Smartphone / Tablet (Privacy)"
        
    if any(p in ports for p in [9100, 515, 631]):
        return "Printer"
    if any(p in ports for p in [8008, 8009]):
        return "Smart TV / Media Player"
    if any(p in ports for p in [554, 8554]):
        return "IP Camera / Security"
    if any(p in ports for p in [5000, 5001]):
        return "Storage (NAS)"
        
    if "apple" in vendor_lower:
        return "Apple Device"
    elif "samsung" in vendor_lower:
        if 8001 in ports:
            return "Smart TV"
        return "Samsung Device"
    elif "google" in vendor_lower or "chromecast" in vendor_lower:
        return "Smart TV / Media Player"
    elif "xiaomi" in vendor_lower:
        return "Xiaomi Device"
    elif "lg electronics" in vendor_lower:
        return "Smart TV (webOS)"
    elif "sony" in vendor_lower:
        if any(p in ports for p in [987, 9295, 9304]):
            return "Gaming Console (PlayStation)"
        return "Sony Device"
    elif "nintendo" in vendor_lower:
        return "Gaming Console (Nintendo)"
    elif "microsoft" in vendor_lower:
        return "Computer (Windows)"
    elif "synology" in vendor_lower or "qnap" in vendor_lower:
        return "Storage (NAS)"
    elif "cisco" in vendor_lower or "tp-link" in vendor_lower or "netgear" in vendor_lower or "ubiquiti" in vendor_lower or "linksys" in vendor_lower or "d-link" in vendor_lower or "asus" in vendor_lower:
        return "Network Device"
    elif "huawei" in vendor_lower or "oneplus" in vendor_lower or "oppo" in vendor_lower or "vivo" in vendor_lower:
        return "Smartphone"
    elif "espressif" in vendor_lower:
        return "Smart Home / IoT Device"
    elif "raspberry pi" in vendor_lower:
        return "Computer (Raspberry Pi)"
    elif "hp" in vendor_lower or "hewlett-packard" in vendor_lower or "canon" in vendor_lower or "epson" in vendor_lower or "brother" in vendor_lower or "lexmark" in vendor_lower:
        return "Printer"
        
    return "Generic Device"

def discover_device_details_integrated(ip, mac, local_ip):
    iface = get_scapy_iface(local_ip)
    
    # 1. Scapy L2 mDNS PTR & NetBIOS (Fastest L2)
    if iface:
        details = query_device_details_l2(ip, mac, iface)
        if details:
            return details
            
    # 2. DNS-SD Active Unicast Probe over L2
    if iface:
        dnssd_name = query_dnssd_l2(ip, mac, iface)
        if dnssd_name:
            return {
                "friendly_name": dnssd_name,
                "device_type": classify_device_type_from_name(dnssd_name)
            }
            
    # 3. HTTP title / server header scraping
    http_meta = query_http_metadata(ip)
    if http_meta:
        details = parse_http_metadata(http_meta)
        if details and details.get("friendly_name"):
            return details
            
    # 4. Fallback to discover_device_details (UPnP, socket mDNS, socket NetBIOS)
    return discover_device_details(ip)

# ─────────────────────────────────────────
# NETWORK DEVICE FINGERPRINTING HELPERS (FALLBACKS)
# ─────────────────────────────────────────
def query_netbios_name(ip):
    payload = (
        b'\xab\x12\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57:
            num_names = data[56]
            offset = 57
            for _ in range(num_names):
                if len(data) >= offset + 18:
                    name_bytes = data[offset:offset+15]
                    name_type = data[offset+15]
                    if name_type == 0x00:
                        return name_bytes.decode('ascii', errors='ignore').strip()
                    offset += 18
    except Exception:
        pass
    return None


def query_mdns_name(ip):
    payload = (
        b'\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01'
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(payload, (ip, 5353))
        data, _ = sock.recvfrom(2048)
        sock.close()
        import re
        strings = re.findall(rb'[a-zA-Z0-9\-\. ]{4,100}', data)
        candidates = []
        for s in strings:
            s_str = s.decode('ascii', errors='ignore').strip()
            if s_str.startswith('_') or s_str.lower() in ('local', 'services', 'dns-sd', 'udp', 'tcp', 'ptr', 'in'):
                continue
            if '.' in s_str:
                s_str = s_str.split('.')[0]
            if len(s_str) >= 4 and s_str not in candidates:
                candidates.append(s_str)
        if candidates:
            return candidates[0]
    except Exception:
        pass
    return None


def query_upnp_info(ip):
    m_search = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.8)
        sock.sendto(m_search.encode('utf-8'), (ip, 1900))
        data, _ = sock.recvfrom(2048)
        sock.close()
        response = data.decode('utf-8', errors='ignore')
        location = None
        for line in response.split('\r\n'):
            if line.lower().startswith('location:'):
                location = line.split(':', 1)[1].strip()
                break
        if location:
            import urllib.request
            req = urllib.request.Request(location, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=1.5) as f:
                xml_content = f.read().decode('utf-8', errors='ignore')
            import re
            friendly_name = re.search(r'<friendlyName>(.*?)</friendlyName>', xml_content)
            manufacturer = re.search(r'<manufacturer>(.*?)</manufacturer>', xml_content)
            model = re.search(r'<modelName>(.*?)</modelName>', xml_content)
            info = {}
            if friendly_name: info['friendly_name'] = friendly_name.group(1).strip()
            if manufacturer: info['manufacturer'] = manufacturer.group(1).strip()
            if model: info['model'] = model.group(1).strip()
            return info
    except Exception:
        pass
    return None


def discover_device_details(ip):
    upnp = query_upnp_info(ip)
    if upnp:
        friendly = upnp.get('friendly_name')
        man = upnp.get('manufacturer', '')
        model = upnp.get('model', '')
        combined = f"{friendly} {man} {model}".lower()
        dev_type = "Generic Device"
        if any(x in combined for x in ("tv", "television", "bravia", "viera", "lg display", "webos")):
            dev_type = "Smart TV"
        elif any(x in combined for x in ("xbox", "playstation", "nintendo", "console")):
            dev_type = "Game Console"
        elif any(x in combined for x in ("router", "gateway", "access point", "modem", "firewall", "ubiquiti")):
            dev_type = "Network Device"
        elif any(x in combined for x in ("camera", "doorbell", "synology", "nas", "storage", "qnap")):
            dev_type = "IP Camera / NAS"
        elif any(x in combined for x in ("printer", "laserjet", "officejet", "epson")):
            dev_type = "Printer"
        elif any(x in combined for x in ("speaker", "sonos", "alexa", "echo", "nest", "cast", "receiver", "spotify")):
            dev_type = "Smart Speaker / Cast"
        return {
            "friendly_name": friendly or f"{man} {model}".strip(),
            "device_type": dev_type
        }
    mdns = query_mdns_name(ip)
    if mdns:
        combined = mdns.lower()
        dev_type = "Generic Device"
        if "iphone" in combined:
            dev_type = "Smartphone (iPhone)"
        elif "ipad" in combined:
            dev_type = "Tablet (iPad)"
        elif "android" in combined:
            dev_type = "Smartphone (Android)"
        elif "apple" in combined or "macbook" in combined or "mac" in combined:
            dev_type = "Computer (Mac)"
        elif "tv" in combined:
            dev_type = "Smart TV / Media Player"
        elif any(x in combined for x in ("cast", "speaker", "sonos", "echo", "home", "nest")):
            dev_type = "Smart Speaker / Cast"
        elif "printer" in combined:
            dev_type = "Printer"
        return {
            "friendly_name": mdns,
            "device_type": dev_type
        }
    netbios = query_netbios_name(ip)
    if netbios:
        return {
            "friendly_name": netbios,
            "device_type": "Windows/Linux PC"
        }
    return None


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
                log_activity(f"SUSPICIOUS BT: Hidden device at {d.address}", log_type="bluetooth")
            found.append({
                "address":    d.address,
                "name":       name,
                "signal":     getattr(d, "rssi", "N/A"),
                "suspicious": is_suspicious
            })
        return found
    except Exception as e:
        print(f"{RED}[!] BT Error: {e}{RESET}")
        log_activity(f"BLUETOOTH SCAN ERROR: {e}", log_type="bluetooth")
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
    
    # Broadcast L2 multicast discovery queries in a background thread to prompt device responses
    iface = get_scapy_iface(local_ip)
    if iface:
        threading.Thread(target=send_active_multicast_queries_l2, args=(iface,), daemon=True).start()

    result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range),
                 timeout=3, verbose=False)[0]

    devices_to_audit = []
    for _, received in result:
        ip, mac = received.psrc, received.hwsrc
        devices_to_audit.append({"ip": ip, "mac": mac})

    known = load_known_devices()

    def audit_task(dev):
        ip, mac = dev['ip'], dev['mac']
        
        # Resolve hostname and vendor lookup concurrently in threads
        try:    hostname = socket.gethostbyaddr(ip)[0]
        except: hostname = "Unnamed Device"
        # Check if MAC is private/randomized
        is_private_mac = False
        if len(mac) >= 2:
            second_char = mac[1].lower()
            if second_char in ['2', '3', '6', '7', 'a', 'b', 'e', 'f']:
                is_private_mac = True

        try:
            if is_private_mac:
                vendor = "Private MAC (Randomized)"
            else:
                loop = asyncio.new_event_loop()
                vendor = loop.run_until_complete(vendor_lookup.async_lookup.lookup(mac))
                loop.close()
        except:
            vendor = "Unknown Manufacturer"

        dev_info = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor
        }

        if ip == local_ip:
            # For local machine, set type to Computer
            friendly_name = hostname
            device_type = "Local PC"
            save_device(mac, ip, hostname, vendor, [], "This machine", friendly_name, device_type)
            db_dev = load_known_devices().get(mac, {})
            return {**dev_info, "status": "self", "ports": [],
                    "os": "This machine", "friendly_name": friendly_name,
                    "device_type": device_type, "last_seen": "Now"}

        prev_entry  = known.get(mac)
        prev_status = prev_entry["status"] if prev_entry else None

        if prev_status is None or prev_status == "suspicious":
            audit    = check_suspicious_ports(ip)
            ports    = audit["ports"]
            os_guess = audit["os"]
        else:
            ports    = prev_entry.get("ports", [])
            os_guess = prev_entry.get("os", "Unknown")

        # Active protocol fingerprinting for friendly name and device type
        if (not prev_entry or 
            not prev_entry.get("friendly_name") or 
            prev_entry.get("device_type", "Generic Device") == "Generic Device"):
            details = discover_device_details_integrated(ip, mac, local_ip) or {}
            friendly_name = details.get("friendly_name", "")
            device_type = details.get("device_type", "Generic Device")
            
            # Fallback to OUI & Port Classification if active queries returned generic details
            if device_type == "Generic Device":
                device_type = classify_device_type_from_vendor_and_ports(vendor, ports)
        else:
            friendly_name = prev_entry.get("friendly_name", "")
            device_type = prev_entry.get("device_type", "Generic Device")
            if device_type == "Generic Device":
                device_type = classify_device_type_from_vendor_and_ports(vendor, ports)

        is_new = save_device(mac, ip, hostname, vendor, ports, os_guess, friendly_name, device_type)
        status = load_known_devices().get(mac, {}).get("status", "unknown")
        db_dev = load_known_devices().get(mac, {})
        return {**dev_info, "status": status, "ports": ports, "os": os_guess,
                "is_new": is_new,
                "friendly_name": db_dev.get("friendly_name", friendly_name),
                "device_type": db_dev.get("device_type", device_type),
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
    global _latest_wifi, _latest_bt, _scan_meta, _is_scanning, _scan_error
    global _sniffer_started
    if not _sniffer_started:
        _sniffer_started = True
        threading.Thread(target=run_passive_sniffer, daemon=True).start()
    while True:
        with _scan_lock:
            with _state_lock:
                _is_scanning = True
                _scan_error = None
            try:
                l_ip = get_local_ip()
                ip_r = get_ip_range(l_ip)
                w_devs = scan_wifi(ip_r, l_ip)
                b_devs = scan_bluetooth()
                with _state_lock:
                    _latest_wifi = w_devs
                    _latest_bt   = b_devs
                    _scan_meta   = {
                        "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "network":   ip_r
                    }
                append_scan_history(w_devs)
                for bt_dev in b_devs:
                    save_bluetooth_device(
                        bt_dev["address"],
                        bt_dev["name"],
                        bt_dev["signal"],
                        bt_dev["suspicious"]
                    )
                log_activity(f"Full scan completed. Local IP: {l_ip}. Devices found: {len(w_devs)}")
                log_activity(f"Bluetooth scan completed. Devices found: {len(b_devs)}", log_type="bluetooth")
            except RuntimeError as re:
                err_msg = str(re)
                if "winpcap" in err_msg.lower() or "libpcap" in err_msg.lower():
                    _scan_error = "Npcap/WinPcap driver is not installed or not running. Please install Npcap with WinPcap compatibility mode."
                else:
                    _scan_error = f"Scanner error: {err_msg}"
                log_activity(f"SCAN ERROR: {_scan_error}")
                print(f"{RED}[!] {_scan_error}{RESET}")
            except Exception as e:
                _scan_error = f"Scanner error: {e}"
                log_activity(f"SCAN ERROR: {_scan_error}")
                print(f"{RED}[!] {_scan_error}{RESET}")
            finally:
                with _state_lock:
                    _is_scanning = False
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
            "is_scanning": _is_scanning,
            "error":      _scan_error
        })


@app.route("/api/devices")
def api_devices():
    with _state_lock:
        # Shallow copy of dictionary list to avoid cross-thread modifications
        data = [dict(device) for device in _latest_wifi]
    known = load_known_devices()
    for device in data:
        mac = device.get("mac")
        if mac and mac in known:
            device["status"]        = known[mac].get("status", device.get("status"))
            device["first_seen"]    = known[mac].get("first_seen")
            device["history"]       = known[mac].get("history", [device.get("ip")])
            device["nickname"]      = known[mac].get("nickname", "")
            device["friendly_name"] = known[mac].get("friendly_name", "")
            device["device_type"]   = known[mac].get("device_type", "Generic Device")
            # Merge hostname and vendor from known database if they are better than active scan placeholders
            db_hostname = known[mac].get("hostname")
            if db_hostname and db_hostname != "Unnamed Device":
                device["hostname"] = db_hostname
            db_vendor = known[mac].get("vendor")
            if db_vendor and db_vendor != "Unknown Manufacturer":
                device["vendor"] = db_vendor
    return jsonify(data)


@app.route("/api/bluetooth")
def api_bluetooth():
    with _state_lock:
        data = [dict(device) for device in _latest_bt]
    known = load_known_bluetooth_devices()
    for device in data:
        addr = device.get("address")
        if addr and addr in known:
            device["nickname"]   = known[addr].get("nickname", "")
            device["status"]     = known[addr].get("status", device.get("status", "trusted"))
            device["first_seen"] = known[addr].get("first_seen")
            device["last_seen"]  = known[addr].get("last_seen")
            db_name = known[addr].get("name")
            if db_name and db_name != "Unknown/Hidden":
                device["name"] = db_name
    return jsonify(data)


@app.route("/api/bluetooth/known")
def api_known_bluetooth():
    return jsonify(load_known_bluetooth_devices())


@app.route("/api/bluetooth/nickname/<mac>", methods=["POST"])
def api_bluetooth_nickname(mac):
    mac = mac.replace("-", ":")
    data = request.get_json() or {}
    nick = data.get("nickname", "").strip()
    
    with _bt_db_lock:
        db = {}
        if os.path.exists(BT_DB_FILE):
            try:
                with open(BT_DB_FILE, "r") as f:
                    content = f.read().strip()
                    db = json.loads(content) if content else {}
            except:
                pass
        if mac not in db:
            db[mac] = {
                "address": mac,
                "name": "Unknown/Hidden",
                "nickname": nick,
                "status": "trusted",
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "signal": "N/A",
                "history": []
            }
        else:
            db[mac]["nickname"] = nick
            
        with open(BT_DB_FILE, "w") as f:
            json.dump(db, f, indent=4)
        log_activity(f"User set nickname '{nick}' for BT device {mac}", log_type="bluetooth")
        return jsonify({"ok": True})


@app.route("/api/bluetooth/trust/<mac>", methods=["POST"])
def api_bluetooth_trust(mac):
    mac = mac.replace("-", ":")
    with _bt_db_lock:
        db = {}
        if os.path.exists(BT_DB_FILE):
            try:
                with open(BT_DB_FILE, "r") as f:
                    content = f.read().strip()
                    db = json.loads(content) if content else {}
            except:
                pass
        if mac not in db:
            db[mac] = {
                "address": mac,
                "name": "Unknown/Hidden",
                "nickname": "",
                "status": "trusted",
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "signal": "N/A",
                "history": []
            }
        else:
            db[mac]["status"] = "trusted"
            
        with open(BT_DB_FILE, "w") as f:
            json.dump(db, f, indent=4)
        log_activity(f"User marked Bluetooth device {mac} as TRUSTED", log_type="bluetooth")
        return jsonify({"ok": True})


@app.route("/api/bluetooth/block/<mac>", methods=["POST"])
def api_bluetooth_block(mac):
    mac = mac.replace("-", ":")
    with _bt_db_lock:
        db = {}
        if os.path.exists(BT_DB_FILE):
            try:
                with open(BT_DB_FILE, "r") as f:
                    content = f.read().strip()
                    db = json.loads(content) if content else {}
            except:
                pass
        if mac in db:
            db[mac]["status"] = "blocked"
            with open(BT_DB_FILE, "w") as f:
                json.dump(db, f, indent=4)
            log_activity(f"User marked Bluetooth device {mac} as BLOCKED", log_type="bluetooth")
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "Device not found"}), 404


@app.route("/api/logs")
def api_logs():
    log_type = request.args.get("type", "wifi")
    return jsonify(read_logs(100, log_type))


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
        return jsonify({"ok": True})
    else:
        return jsonify({"ok": False, "error": "Firewall command failed. Please verify you are running as Administrator."}), 500

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
    if _scan_lock.locked():
        return jsonify({"ok": False, "error": "Scan already in progress"}), 409

    def do_scan():
        global _latest_wifi, _latest_bt, _scan_meta, _is_scanning, _scan_error
        with _scan_lock:
            with _state_lock:
                _is_scanning = True
                _scan_error = None
            try:
                l_ip = get_local_ip()
                ip_r = get_ip_range(l_ip)
                w_devs = scan_wifi(ip_r, l_ip)
                b_devs = scan_bluetooth()
                with _state_lock:
                    _latest_wifi = w_devs
                    _latest_bt   = b_devs
                    _scan_meta   = {
                        "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "network":   ip_r
                    }
                append_scan_history(w_devs)
                for bt_dev in b_devs:
                    save_bluetooth_device(
                        bt_dev["address"],
                        bt_dev["name"],
                        bt_dev["signal"],
                        bt_dev["suspicious"]
                    )
                log_activity(f"Manual scan triggered. Devices found: {len(w_devs)}")
                log_activity(f"Manual Bluetooth scan triggered. Devices found: {len(b_devs)}", log_type="bluetooth")
            except RuntimeError as re:
                err_msg = str(re)
                if "winpcap" in err_msg.lower() or "libpcap" in err_msg.lower():
                    _scan_error = "Npcap/WinPcap driver is not installed or not running. Please install Npcap with WinPcap compatibility mode."
                else:
                    _scan_error = f"Scanner error: {err_msg}"
                log_activity(f"SCAN ERROR: {_scan_error}")
            except Exception as e:
                _scan_error = f"Scanner error: {e}"
                log_activity(f"SCAN ERROR: {_scan_error}")
            finally:
                with _state_lock:
                    _is_scanning = False
    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"ok": True, "msg": "Scan started"})


if __name__ == "__main__":
    # logging already imported at top level
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
