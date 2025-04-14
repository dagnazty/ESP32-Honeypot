#ESP32 Honeypot with Web UI, SPIFFS Persistence and Webhook Alerts

This project is a standalone Telnet honeypot for the ESP32 platform. It emulates a realistic Linux shell environment to attract and analyze unauthorized access attempts. It features a full web-based configuration UI, persistent storage using SPIFFS, and webhook-based alerting that can be integrated with Discord, Telegram, Signal, WhatsApp, or SIEM platforms.

---

## ✅ Features

- Interactive Telnet honeypot server on port 23
- Realistic Linux shell simulation with multiple commands supported (pwd, whoami, cat, ls, cd, apt, etc.)
- Automatic logging of all client inputs with timestamp and IP address
- Webhooks for real-time alerts (Discord, Telegram, Signal, WhatsApp, SIEM, etc.)
- Web-based configuration panel (SSID, password, webhook)
- SPIFFS-based file system for persistent config and logs
- Offline mode with Wi-Fi Access Point for initial setup
- Fake file system structure with secrets to lure attackers
- Modular code, compatible with any ESP32 board (no M5Stack dependency)

---

## 📷 Screenshots

- Honeypot terminal: emulated Ubuntu 20.04 shell
- Web UI: sleek form to configure Wi-Fi and webhook
- Logs & config viewer directly from browser

---

## ⚙️ Installation

1. Flash this firmware on any ESP32 using Arduino IDE or PlatformIO
2. On first boot, ESP32 will create a Wi-Fi access point:
   - SSID: HoneypotConfig
   - Password: HoneyPotConfig123
3. Connect and open `http://192.168.4.1` to configure
4. After saving the configuration, the ESP32 will reboot and connect to your Wi-Fi
5. Telnet honeypot starts on port 23, listening for attackers
6. All captured inputs will be logged and optionally sent to your webhook

---

## 📁 SPIFFS Structure

/config.json       → Contains Wi-Fi and webhook settings  
/honeypot_logs.txt → Stores captured login attempts and commands  
/index.html        → Web-based configuration UI  

All files are automatically created at first boot if missing.

---

## 📡 Webhook Format

Example payload (JSON, sent as POST):

{
  "content": "📡 Honeypot\n🔍 IP: 192.168.1.5\n💻 Command: `cat /etc/passwd`"
}

You can route this to:

- Discord (via Webhook URL)
- Telegram (via Bot API Gateway)
- Signal (via relay server or bridge)
- WhatsApp (via Business API)
- SIEMs or custom log collectors

---

## 🧠 Emulated Commands

Basic commands:
- pwd, whoami, uptime, hostname, uname -a, id, lscpu, df -h, free -h, env, set, history

Filesystem:
- ls, ls -l, cd, cat, mkdir, rm, rmdir, touch, chmod, chown

Networking:
- ifconfig, ip addr, ping, netstat -an, curl, wget

Services:
- service <name> start/stop/status
- systemctl status/start/stop

Package manager:
- apt-get update, apt-get install

Privilege escalation:
- sudo (with denial)

Fake files like `/etc/passwd`, `secrets.txt`, `mysql_credentials.txt`, etc. are included to bait the attacker.

---

## 📦 Dependencies

- ESPAsyncWebServer
- ArduinoJson
- SPIFFS (built-in)
- WiFi (built-in)

Make sure to install the required libraries via Library Manager or PlatformIO.

---

## 🛡️ Usage Notes

This honeypot is designed for educational and defensive cybersecurity purposes. Do not expose to the internet without proper upstream firewalling or network segmentation. It is not intended to replace full honeynet frameworks like Cowrie, but serves as a lightweight ESP32-based trap.

---

## 📄 License

MIT License - Use freely with attribution.

---

## 💡 Author

Developed by 7h30th3r0n3 | Ethical Hacker & IoT Security Researcher
