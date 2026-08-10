# Network Threat Monitor

Network Threat Monitor is a highly robust, agent-assisted cybersecurity dashboard for your local network. It continuously monitors your Wi-Fi subnet and nearby Bluetooth spectrum to identify, track, and alert you of unknown or suspicious devices.

## 🚀 Current Progress & Features

- **Deep Network Sniffing (Wi-Fi):** Leverages `Scapy`, `Nmap`, `mDNS`, and `NetBIOS` for advanced layer-2 packet sniffing and active port scanning on your local subnet.
- **Active Bluetooth Sweeping:** Utilizes `Bleak` to run concurrent background scans across the Bluetooth spectrum, detecting hidden devices and mapping signal strengths (RSSI).
- **Premium User Interface:** A highly polished, responsive Vanilla JS/CSS frontend featuring:
  - Isolated database views for both Wi-Fi and Bluetooth.
  - Real-time event logging and activity feeds.
  - Historical signal strength tracking (sigBars).
  - High-contrast Light Mode and sleek Dark Mode with micro-animations.
  - Intelligent tooltips for identifying dangerous open ports (e.g., Telnet, RDP).
- **Device Management:** Assign custom nicknames, mark devices as trusted, or flag them as blocked/suspicious permanently in local JSON databases.

## 🛠️ Getting Started

### Prerequisites
- Python 3.8+
- Administrator/root privileges (required for raw packet sniffing and Nmap).

### Installation
1. Clone this repository.
2. Run `setup.bat` to install all necessary Python dependencies (like `scapy`, `python-nmap`, `bleak`, `flask`).
3. Run `app_launcher.py` as an Administrator to start the background scanning daemon and the local web server.
4. Navigate to `http://localhost:5000` in your browser.

## 🔮 Future Roadmap & Planned Additions

As this project continues to evolve, the following features are planned for future development:
- **Background Daemonization:** Packaging the application to run as a silent Windows Service or Linux `systemd` daemon that starts automatically on boot.
- **Authentication:** Implementing a secure login portal (JWT/Basic Auth) to protect the dashboard when exposed to a local network (e.g., running on a Raspberry Pi).
- **Webhooks & External Alerts:** Integration with Discord webhooks or Telegram bots to send immediate push notifications when a new or suspicious device is detected on the network.
- **Notification Queueing:** Enhancing the Windows desktop notification (`plyer`) logic to support queuing, preventing dropped balloon-tips during rapid discovery bursts.
