# 🔍 Network & Port Scanner Tool

A powerful and user-friendly Python-based network and port scanner tool. This script allows you to:

- Scan individual IPs or ranges for availability (ping check)
- Detect open ports using `nmap`
- Resolve hostnames and display basic info
- Export scan results (with enhancements planned)

---

## ⚙️ Features

- ✅ Live device detection on a given network  
- ⚡ Fast scanning with multithreading  
- 🌐 Port scanning via `nmap`  
- 🖥️ Hostname resolution  
- 📤 Export capabilities (planned)  
- 🧠 Device fingerprinting and MAC vendor lookup (planned)  

---

## 🧩 Requirements

Make sure you have Python 3.7+ installed.

Install the required packages:

```bash
pip install -r requirements.txt
```

**Also Required:**

- [`nmap`](https://nmap.org/download.html) – Install and ensure it is available in your system PATH.

---

## 🚀 Usage

Run the scanner:

```bash
python scanner.py
```

You will be prompted to enter:

- A single IP or IP range (e.g., `192.168.1.1-100`)
- Whether to scan for open ports

Results will be displayed directly in the terminal.

---

## 🧪 Sample Output

```
IP: 192.168.1.5
Hostname: device.local
Status: Alive
Open Ports: [22, 80, 443]
```

---

## 🛠️ Planned Features

- [ ] Export scan results to CSV/TXT  
- [ ] Subnet (CIDR) scanning like `192.168.1.0/24`  
- [ ] GUI mode with dark/light theme  
- [ ] Geo-IP lookup for external IPs  
- [ ] Full port scanning toggle  
- [ ] MAC address vendor resolution  
- [ ] Tray icon version for Windows/macOS  
- [ ] SQLite history log of scans  
- [ ] Device fingerprinting (`nmap -O -sV`)  

---

## ❓ Troubleshooting

- **Nmap not found?**  
  Download and install it from [https://nmap.org/download.html](https://nmap.org/download.html), and ensure it’s accessible via terminal/command prompt.

- **Permission Denied or Access Denied?**  
  Try running the script with elevated privileges (e.g., `sudo` on Linux/macOS).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 📬 Contributions

Pull requests and suggestions are welcome!  
For major changes, please open an issue first to discuss what you would like to change.

---
