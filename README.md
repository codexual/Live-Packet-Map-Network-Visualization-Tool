# 🌍 Live Packet Map - Network Visualization Tool

Visualize your network traffic in real-time with an interactive global map!

This Python-based tool captures live network packets, geolocates IP addresses, and displays them on an interactive map with animated connections.  
Perfect for network monitoring, cybersecurity analysis, or just exploring where your internet traffic goes.

---

## 🚀 Features
- ✔ **Real-time packet capture** (TCP / UDP / ICMP)
- ✔ **Geolocation mapping** (MaxMind GeoLite2 + IPAPI fallback)
- ✔ **Interactive Web UI** with animated connections
- ✔ **Hacker-style visualization** (dark theme, glowing effects)
- ✔ **Connection logging** with protocol filtering

---

## 🛠 Installation (Windows)

### 1️⃣ Prerequisites
- **[Python 3.9+](https://www.python.org/downloads/)**
- **[Npcap 1.83+](https://nmap.org/npcap/)**
  - Required for packet capture (check *"WinPcap compatibility mode"* during install)
- **[Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) C++ For Development Only**
  - Required for compiling Python dependencies

---

### 2️⃣ Clone & Setup
```bash
git clone https://github.com/codexual/Live-Packet-Map-Network-Visualization-Tool.git
cd live-packet-map
```

---

### 3️⃣ Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

### 4️⃣ Run the Tool (As Admin!)
```bash
python app.py
```
*(Or use `run.bat` on Windows for a styled console.)*

➡ **Access the Web UI:** [http://localhost:8000](http://localhost:8000)

---

## 🔧 How It Works

**Backend (`app.py`):**
- Uses `scapy` to sniff packets
- Resolves IPs to locations via **MaxMind GeoLite2**
- Sends data to the frontend via **WebSocket**

**Frontend (`app.js`):**
- Renders an interactive **Leaflet.js** map
- Displays animated connections & logs
- Filters LAN/multicast traffic

---

## 📜 Usage
1. Run the script as **Administrator** (for packet capture permissions).
2. Open the web interface to see live traffic.
3. Hover over markers for IP details.
4. Log panel shows recent packets.

---

## ⚠ Troubleshooting
- **"No packets detected"** → Run as Admin & check Npcap install.
- **GeoIP fails** → Ensure `data/GeoLite2-City.mmdb` exists (auto-downloads on first run).
- **Python errors** → Install VS Build Tools and retry `pip install`.

---

## 📜 License
MIT License — Free for personal & educational use.

---

## 🎯 Perfect For:
- Network administrators  
- Cybersecurity students  
- Privacy-conscious users  
- Anyone who loves data visualization!

---

⭐ **Star this repo if you find it useful!**
