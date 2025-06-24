# Advanced Net Scanner 🔍🖥️

A powerful and modern network scanning tool built with Python and Tkinter. Supports IP scanning, port detection, hostname resolution, MAC vendor lookup, GeoIP location, and OS fingerprinting (via Nmap). Includes a sleek customizable GUI with filtering, export, themes, and more.

---

## ✨ Features

- 🔍 **IP/Subnet/Range Scanning** (e.g. `192.168.1.1`, `192.168.1.0/24`, or `192.168.1.1-192.168.1.100`)
- 🔓 **Port Scanning** using Nmap (Top 20 or Full Port Scan)
- 🖥️ **OS Detection** (admin/root only)
- 🌐 **GeoIP Lookup** using `ipinfo.io`
- 🧠 **MAC Address & Vendor Detection** using ARP and IEEE OUI data
- 🧾 **Export Results** to TXT or CSV
- 🎨 **Themes & UI Customization** (Dark, Light, Blue)
- 🔠 Font size control for accessibility
- 🧪 Real-time **search filter** for scan results
- 📶 **Live progress bar** with threading for speed


---

## 🧰 Requirements

- Python 3.7+
- [Nmap](https://nmap.org/) (must be installed and in PATH)

### Python Libraries

Install dependencies via pip:

```bash
pip install -r requirements.txt
