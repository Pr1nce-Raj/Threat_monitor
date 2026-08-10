# Threat Monitor 🛡️

> Agent-assisted, concurrent Wi-Fi subnet and Bluetooth spectrum cybersecurity dashboard.

## What It Does

- 📡 **Deep Network Sniffing (Wi-Fi):** Advanced layer-2 packet sniffing on your local subnet using Scapy and Nmap.
- 📶 **Active Bluetooth Sweeping:** Concurrent background scans across the Bluetooth spectrum via Bleak to detect hidden devices and track RSSI.
- 📱 **Premium User Interface:** Highly polished, responsive Vanilla JS/CSS frontend with isolated Wi-Fi and Bluetooth databases.
- 📊 **Real-time Activity:** Live event logging, activity feeds, and historical signal strength tracking (sigBars).
- 🎨 **Dynamic Theming:** High-contrast Light Mode and sleek Dark Mode with micro-animations.
- ⚠️ **Intelligent Tooltips:** Instantly identifies dangerous open ports (e.g., Telnet, RDP).
- 💾 **Device Management:** Assign custom nicknames, mark devices as trusted, or flag them as blocked/suspicious permanently in local JSON databases.

## Tech Stack

| Layer | Technology |
|---|---|
| Wi-Fi Packet Sniffing | Scapy, Nmap, mDNS, NetBIOS |
| Bluetooth Scanning | Bleak |
| Backend API | Flask (Python) |
| Frontend | HTML5, Vanilla JS, CSS3 |
| Database | Local JSON |
| OS Notifications | Plyer (Windows Balloon-tips) |

## Requirements

- Python 3.8+
- Administrator/root privileges (required for raw packet sniffing and Nmap)
- Wi-Fi adapter (for network scanning)
- Bluetooth adapter (for BLE sweeping)

## Setup (First Time Only)

1. Clone the repo:
```bash
git clone https://github.com/Pr1nce-Raj/Threat_monitor.git
cd Threat_monitor
```

2. Run the setup script to install dependencies:
```bash
setup.bat
```
*That’s it. Setup only needs to be done once.*

## Running the System

### Start the Monitor (Admin Required)

Double-click `app_launcher.py` (ensure you run it as an Administrator)

- Starts the background scanning daemon for Wi-Fi and Bluetooth.
- Launches the local web server.
- Navigate to `http://localhost:5000` in your browser to view the dashboard.

## Future Roadmap 🔮

As this project continues to evolve, the following features are planned:

| Feature | Description |
|---|---|
| **Background Daemonization** | Packaging the application to run as a silent Windows Service or Linux `systemd` daemon that starts automatically on boot. |
| **Authentication** | Secure login portal (JWT/Basic Auth) to protect the dashboard when exposed to a local network (e.g., on a Raspberry Pi). |
| **Webhooks & Alerts** | Integration with Discord webhooks or Telegram bots for immediate push notifications when suspicious devices are detected. |
| **Notification Queueing** | Enhancing the `plyer` logic to support queuing, preventing dropped balloon-tips during rapid discovery bursts. |
