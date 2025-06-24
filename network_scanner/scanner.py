import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox, filedialog
import threading, socket, ipaddress, subprocess, platform, nmap, requests, os, ctypes
from concurrent.futures import ThreadPoolExecutor

# ------------------------- CONFIG -------------------------
ping_cmd = ["ping", "-n", "1"] if platform.system() == "Windows" else ["ping", "-c", "1"]
executor = ThreadPoolExecutor(max_workers=50)

# Themes
THEMES = {
    "dark": {"bg": "#0f0f0f", "fg": "#00ff9f", "entry_bg": "#1c1c1c", "text_bg": "#1a1a1a"},
    "light": {"bg": "#ffffff", "fg": "#000000", "entry_bg": "#e0e0e0", "text_bg": "#f5f5f5"},
    "blue": {"bg": "#001f3f", "fg": "#7FDBFF", "entry_bg": "#003f5f", "text_bg": "#002f4f"},
}
current_theme = "dark"
font_size = 12

# Load IEEE OUI list
OUI_FILE = "oui.txt"
if not os.path.exists(OUI_FILE):
    try:
        with open(OUI_FILE, "w") as f:
            f.write(requests.get("http://standards-oui.ieee.org/oui/oui.txt", timeout=10).text)
    except Exception:
        pass

mac_map = {}
with open(OUI_FILE, "r", errors="ignore") as f:
    for line in f:
        if "(base 16)" in line:
            p, v = line.split("(base 16)")
            mac_map[p.strip().replace("-", ":")] = v.strip()

# ------------------------- UTILS -------------------------
def is_root():
    try:
        return os.geteuid() == 0
    except:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def get_geo(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3).json()
        return f"{r.get('city', '')}, {r.get('region', '')}, {r.get('country', '')}"
    except:
        return "Unknown Location"

def get_mac_vendor(ip):
    try:
        subprocess.run(ping_cmd + [ip], stdout=subprocess.DEVNULL)
        p = subprocess.check_output(["arp", "-n", ip], universal_newlines=True)
        for line in p.splitlines():
            cols = line.split()
            if ip in cols:
                mac = cols[2].upper()
                vendor = mac_map.get(mac[:8], "Unknown Vendor")
                return mac, vendor
    except:
        pass
    return None, "Unknown"

# ------------------------- SCANNING -------------------------
def scan_ports(ip, output):
    try:
        scanner = nmap.PortScanner()
    except:
        output.insert(tk.END, "❌ Install nmap first.\n")
        return

    args = "-T4 -sV"
    args += " -p-" if full_ports_var.get() else " --top-ports 20"
    if is_root():
        args += " -O"

    try:
        scanner.scan(ip, arguments=args)
        if ip in scanner.all_hosts():
            for proto in scanner[ip].all_protocols():
                for port in sorted(scanner[ip][proto]):
                    st = scanner[ip][proto][port]["state"]
                    svc = scanner[ip][proto][port].get("name", "")
                    output.insert(tk.END, f"   🔓 {port}/{proto} {svc} is {st}\n")
            if is_root() and 'osmatch' in scanner[ip]:
                osg = scanner[ip]['osmatch'][0]['name']
                output.insert(tk.END, f"   🖥️ OS Guess: {osg}\n")
            elif not is_root():
                output.insert(tk.END, "   ⚠️ OS detection skipped (requires admin)\n")
    except Exception as e:
        output.insert(tk.END, f"   ❌ Nmap error: {e}\n")

def scan_host(ip, output):
    ip_str = str(ip)
    if subprocess.run(ping_cmd + [ip_str], stdout=subprocess.DEVNULL).returncode == 0:
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except:
            hostname = "Unknown"
        loc = get_geo(ip_str)
        mac, vendor = get_mac_vendor(ip_str)
        output.insert(tk.END, f"[✔] {ip_str} {hostname} {loc} MAC:{mac or 'N/A'} Vendor:{vendor}\n")
        scan_ports(ip_str, output)
    else:
        output.insert(tk.END, f"[✘] {ip_str} unreachable\n")

def scan_range(ips, output, bar):
    output.delete("1.0", tk.END)
    total = len(ips)
    count = [0]

    def task(ip):
        def upd():
            scan_host(ip, output)
            count[0] += 1
            bar["value"] = int(count[0] / total * 100)
            apply_filter()
        app.after(0, upd)
    for ip in ips:
        executor.submit(task, ip)

# ------------------------- UI LOGIC -------------------------
def on_scan():
    txt = entry_ip.get().strip()
    output_area.delete("1.0", tk.END)
    progress["value"] = 0
    try:
        if "/" in txt:
            hosts = ipaddress.ip_network(txt, strict=False).hosts()
        elif "-" in txt:
            s, e = txt.split("-")
            hosts = [ipaddress.IPv4Address(i) for i in range(int(ipaddress.IPv4Address(s)), int(ipaddress.IPv4Address(e)) + 1)]
        else:
            hosts = [ipaddress.IPv4Address(txt)]
        threading.Thread(target=scan_range, args=(list(hosts), output_area, progress)).start()
    except Exception as e:
        messagebox.showerror("Error", f"Bad input: {e}")

def apply_theme():
    th = THEMES[current_theme]
    app.config(bg=th["bg"])
    for w in all_widgets:
        if isinstance(w, (tk.Entry, tk.Label, tk.Text, tk.Checkbutton, tk.Frame)):
            try:
                w.configure(bg=th.get("entry_bg"), fg=th["fg"])
            except:
                pass
        elif isinstance(w, scrolledtext.ScrolledText):
            try:
                w.configure(bg=th.get("text_bg"), fg=th["fg"])
            except:
                pass



def change_theme(event=None):
    global current_theme
    current_theme = theme_var.get()
    apply_theme()

def change_font(sz):
    global font_size
    font_size = sz
    output_area.config(font=("Consolas", font_size))
    entry_ip.config(font=("Consolas", font_size))

def apply_filter(*args):
    txt = filter_var.get().lower()
    lines = output_area.get("1.0", tk.END).splitlines()
    output_area.delete("1.0", tk.END)
    for l in lines:
        if txt in l.lower():
            output_area.insert(tk.END, l + "\n")

def export_results():
    txt = output_area.get("1.0", tk.END).strip()
    if not txt:
        messagebox.showwarning("Empty", "No results to export.")
        return
    f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("CSV", "*.csv")])
    if f:
        with open(f, "w") as file:
            file.write(txt)

# ------------------------- APP UI -------------------------
app = tk.Tk()
app.title("Advanced Net Scanner")
app.geometry("950x650")

font_main = ("Consolas", font_size)
all_widgets = []

top = tk.Frame(app)
top.pack(pady=10)

tk.Label(top, text="IP/Subnet/Range:", font=font_main).pack(side=tk.LEFT)
entry_ip = tk.Entry(top, font=font_main, width=30)
entry_ip.pack(side=tk.LEFT, padx=5)
all_widgets.append(entry_ip)

ttk.Button(top, text="Scan", command=on_scan).pack(side=tk.LEFT, padx=5)
ttk.Button(top, text="Export", command=export_results).pack(side=tk.LEFT, padx=5)

full_ports_var = tk.BooleanVar()
tk.Checkbutton(top, text="Full Port Scan", variable=full_ports_var).pack(side=tk.LEFT, padx=5)

theme_var = tk.StringVar(value=current_theme)
tk.OptionMenu(top, theme_var, *THEMES.keys(), command=change_theme).pack(side=tk.LEFT, padx=5)

tk.Label(top, text="Font size:", font=font_main).pack(side=tk.LEFT, padx=5)
font_slider = tk.Scale(top, from_=8, to=20, orient=tk.HORIZONTAL, command=lambda v: change_font(int(v)))
font_slider.set(font_size)
font_slider.pack(side=tk.LEFT, padx=5)

f2 = tk.Frame(app)
f2.pack(pady=5)
tk.Label(f2, text="Filter:", font=font_main).pack(side=tk.LEFT)

filter_var = tk.StringVar()
filter_var.trace_add("write", apply_filter)
filter_entry = tk.Entry(f2, textvariable=filter_var, font=font_main, width=40)
filter_entry.pack(side=tk.LEFT)
all_widgets.append(filter_entry)

progress = ttk.Progressbar(app, orient=tk.HORIZONTAL, length=800, mode='determinate')
progress.pack(pady=5)

output_area = scrolledtext.ScrolledText(app, font=font_main, wrap=tk.WORD, width=110, height=30)
output_area.pack(padx=10, pady=10)

all_widgets.extend([output_area, progress])
apply_theme()
app.mainloop()
