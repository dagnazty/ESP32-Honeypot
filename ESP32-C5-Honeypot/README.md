# ESP32-C5 Honeypot with Web UI, SPIFFS Persistence and Webhook Alerts

This project is a standalone Telnet honeypot for the ESP32-C5 platform. It emulates a realistic Linux shell environment to attract and analyze unauthorized access attempts. It features a full web-based configuration UI, persistent storage using SPIFFS, and webhook-based alerting that can be integrated with Discord, Telegram, Signal, WhatsApp, or SIEM platforms.

Alerts on Discord :   
<img alt="WebUi" src="./WebHookDiscord.jpg" width="33%" height="33%"/>
</div>

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
- Built using the ESP-IDF framework for ESP32-C5

---
## 🧩 Compatible Devices

- **ESP32-C5** development boards

---
## ⚙️ Installation

### Prerequisites

- ESP-IDF v5.4 or newer
- ESP32-C5 development board
- USB cable for flashing

### Building and Flashing

1. Clone this repository
2. Navigate to the project directory
3. Build and flash the project:

```
idf.py --preview set-target esp32c5
idf.py build
idf.py -p (PORT) flash
```

### First-time Configuration

1. On first boot, ESP32-C5 will create a Wi-Fi access point:
   - SSID: HoneypotConfig
   - Password: HoneyPotConfig123
2. Connect and open `http://192.168.4.1` to configure
3. After saving the configuration, the ESP32-C5 will reboot and connect to your Wi-Fi
4. Telnet honeypot starts on port 23, listening for attackers
5. All captured inputs will be logged and optionally sent to your webhook

---

## 📁 SPIFFS Structure

- `/spiffs/config.json` - Contains Wi-Fi and webhook settings
- `/spiffs/honeypot_logs.txt` - Stores captured login attempts and commands
- `/spiffs/index.html` - Web-based configuration UI

All files are automatically created at first boot if missing.

---

## 📡 Webhook Format

Example payload (JSON, sent as POST):

```json
{
  "content": "📡 Honeypot\n🔍 IP: 192.168.1.5\n💻 Command: `cat /etc/passwd`"
}
```

### Webhook Options:

**Raspberry Pi Relay**:
   - Set up a Python Flask server on a Raspberry Pi that accepts HTTP requests from the ESP32
   - The relay server forwards the alerts to Discord or other platforms using HTTPS
   - This avoids SSL/TLS limitations on the ESP32
   - Example webhook URL format: `http://your-raspberry-pi-ip:8080/webhook`

Note: Due to ESP32 SSL/TLS limitations, services that enforce HTTPS (like Discord) require using the Raspberry Pi relay method.

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

This project is built using the ESP-IDF framework and depends on:
- ESP-IDF v5.4+
- SPIFFS filesystem
- ESP HTTP Client
- ESP WiFi components

---

## 🛡️ Usage Notes

This honeypot is designed for educational and defensive cybersecurity purposes. Do not expose to the internet without proper upstream firewalling or network segmentation. It is not intended to replace full honeynet frameworks like Cowrie, but serves as a lightweight ESP32-based trap.

---

## 📄 License

MIT License - Use freely with attribution.

---

## 💡 Author and Acknowledgements

Based on the original ESP32 Honeypot project by 7h30th3r0n3, ported to ESP-IDF framework and optimized for ESP32-C5.
