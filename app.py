import asyncio
import json
import os
import platform
import socket
import sys
import threading
from datetime import datetime
from aiohttp import web
import scapy.all as scapy
import websockets
import requests
import geoip2.database
from collections import defaultdict
import tarfile

DEBUG = True

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_DIR, "data")
GEOIP_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")

MAXMIND_ACCOUNT_ID = "MAXMIND ID HERE"
MAXMIND_LICENSE_KEY = "YOUR APP API KEY HERE"
MAXMIND_DOWNLOAD_URL = (
    f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City"
    f"&license_key={MAXMIND_LICENSE_KEY}&suffix=tar.gz"
)

def ensure_geoip_db():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if not os.path.isfile(GEOIP_DB_PATH):
        print("[*] GeoLite2-City.mmdb not found. Downloading from MaxMind...")
        tgz_path = os.path.join(DATA_DIR, "GeoLite2-City.tar.gz")
        try:
            with requests.get(MAXMIND_DOWNLOAD_URL, stream=True, timeout=15) as r:
                r.raise_for_status()
                with open(tgz_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            # Extract mmdb file
            with tarfile.open(tgz_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("GeoLite2-City.mmdb"):
                        member.name = os.path.basename(member.name)
                        tar.extract(member, DATA_DIR)
                        os.rename(os.path.join(DATA_DIR, member.name), GEOIP_DB_PATH)
            os.remove(tgz_path)
            print("[+] GeoLite2-City.mmdb downloaded and extracted.")
        except Exception as e:
            print(f"[!] Error downloading GeoLite2-City.mmdb: {e}")

ensure_geoip_db()

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    print("[+] Loaded local GeoIP database")
except Exception as e:
    print(f"[!] Error loading GeoIP database: {e}")
    geo_reader = None

connected_clients = set()
queue = asyncio.Queue()
geo_cache = {}
active_connections = defaultdict(dict)
connection_counter = 1
connection_lock = threading.Lock()
hostname_cache = {}

def log_debug(message):
    if DEBUG:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[DEBUG {timestamp}] {message}")

def get_external_ip():
    try:
        services = [
            "https://api.ipify.org?format=json",
            "https://ipinfo.io/json",
            "https://ifconfig.me/all.json"
        ]
        for service in services:
            try:
                r = requests.get(service, timeout=3)
                if r.status_code == 200:
                    data = r.json()
                    ip = data.get('ip') or data.get('ip_addr')
                    if ip:
                        log_debug(f"External IP detected: {ip}")
                        return ip
            except Exception:
                continue
        return None
    except Exception as e:
        log_debug(f"IP detection error: {e}")
        return None

def is_local_or_special_ip(ip):
    return (
        ip.startswith('10.') or
        ip.startswith('192.168.') or
        ip.startswith('172.16.') or
        ip.startswith('127.') or
        ip.startswith('224.') or
        ip.startswith('239.') or
        ip == '255.255.255.255'
    )

def resolve_hostname(ip):
    if ip in hostname_cache:
        return hostname_cache[ip]
    if is_local_or_special_ip(ip):
        hostname_cache[ip] = "LAN/Multicast"
        return "LAN/Multicast"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        hostname_cache[ip] = hostname
        return hostname
    except Exception:
        hostname_cache[ip] = "N/A"
        return "N/A"

def geolocate_ip(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    if is_local_or_special_ip(ip):
        geo_cache[ip] = {
            "country": "LAN/Multicast",
            "isp": "Local Network",
            "lat": None,
            "lon": None,
            "hostname": resolve_hostname(ip)
        }
        return geo_cache[ip]
    if geo_reader:
        try:
            response = geo_reader.city(ip)
            lat = response.location.latitude or None
            lon = response.location.longitude or None
            country = response.country.name or "N/A"
            isp = getattr(response.traits, 'isp', None) or getattr(response.traits, 'autonomous_system_organization', None) or getattr(response.traits, 'organization', None) or "N/A"
            geo_cache[ip] = {
                "country": country,
                "isp": isp,
                "lat": lat,
                "lon": lon,
                "hostname": resolve_hostname(ip)
            }
            log_debug(f"GeoDB: {ip} -> {country} ({isp}) [Host: {geo_cache[ip]['hostname']}]")
            return geo_cache[ip]
        except Exception as e:
            log_debug(f"GeoDB error for {ip}: {e}")
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=1.5)
        data = r.json()
        geo_cache[ip] = {
            "country": data.get("country_name", "N/A"),
            "isp": data.get("org", "N/A"),
            "lat": data.get("latitude", None),
            "lon": data.get("longitude", None),
            "hostname": resolve_hostname(ip)
        }
        log_debug(f"IPAPI: {ip} -> {geo_cache[ip]['country']} ({geo_cache[ip]['isp']}) [Host: {geo_cache[ip]['hostname']}]")
        return geo_cache[ip]
    except Exception as e:
        log_debug(f"IPAPI error for {ip}: {e}")
        geo_cache[ip] = {
            "country": "N/A",
            "isp": "N/A",
            "lat": None,
            "lon": None,
            "hostname": resolve_hostname(ip)
        }
        return geo_cache[ip]

def packet_to_dict(pkt):
    if scapy.IP not in pkt:
        return None
    src_ip = pkt[scapy.IP].src
    dst_ip = pkt[scapy.IP].dst
    proto_num = pkt[scapy.IP].proto
    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"Proto-{proto_num}")
    size = len(pkt)
    timestamp = datetime.now().isoformat()
    connection_id = None
    with connection_lock:
        for conn_id, conn_data in active_connections.items():
            if (conn_data["src_ip"] == src_ip and 
                conn_data["dst_ip"] == dst_ip and 
                conn_data["proto"] == proto_name):
                connection_id = conn_id
                break
        if not connection_id:
            global connection_counter
            connection_id = connection_counter
            connection_counter += 1
            active_connections[connection_id] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": proto_name,
                "start_time": timestamp,
                "last_seen": timestamp,
                "packet_count": 1
            }
        else:
            active_connections[connection_id]["last_seen"] = timestamp
            active_connections[connection_id]["packet_count"] += 1
    geo = geolocate_ip(dst_ip)
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto_name,
        "size": size,
        "geo": geo,
        "timestamp": timestamp,
        "connection_id": connection_id,
        "is_new": connection_id == connection_counter - 1
    }

async def websocket_handler(websocket):
    connected_clients.add(websocket)
    log_debug("New client connected")
    try:
        while True:
            await asyncio.sleep(1)
    except websockets.exceptions.ConnectionClosed:
        log_debug("Client disconnected")
    finally:
        connected_clients.remove(websocket)

async def broadcaster():
    log_debug("Broadcaster started")
    while True:
        msg = await queue.get()
        dead_clients = set()
        for ws in connected_clients:
            try:
                await ws.send(json.dumps(msg))
            except Exception:
                dead_clients.add(ws)
        for ws in dead_clients:
            connected_clients.remove(ws)
        queue.task_done()

async def cleanup_connections():
    log_debug("Connection cleaner started")
    while True:
        await asyncio.sleep(30)
        now = datetime.now()
        expired = []
        with connection_lock:
            for conn_id, conn_data in active_connections.items():
                last_seen = datetime.fromisoformat(conn_data["last_seen"])
                if (now - last_seen).total_seconds() > 60:
                    expired.append(conn_id)
            for conn_id in expired:
                del active_connections[conn_id]
                log_debug(f"Connection {conn_id} expired")

async def index(request):
    return web.FileResponse(os.path.join(PROJECT_DIR, 'static/index.html'))

async def js(request):
    return web.FileResponse(os.path.join(PROJECT_DIR, 'static/app.js'))

async def css(request):
    return web.FileResponse(os.path.join(PROJECT_DIR, 'static/style.css'))

async def connections(request):
    with connection_lock:
        # Return all current connections as a list for log/map replay
        return web.json_response(list(active_connections.values()))

async def geoip(request):
    ip = request.query.get('ip')
    if not ip:
        return web.json_response({"error": "No IP provided"})
    geo = geolocate_ip(ip)
    return web.json_response(geo)

async def run_backend():
    log_debug("Starting packet capture")
    loop = asyncio.get_running_loop()
    def _process_packet(pkt):
        try:
            msg = packet_to_dict(pkt)
            if msg:
                asyncio.run_coroutine_threadsafe(queue.put(msg), loop)
        except Exception as e:
            log_debug(f"Packet processing error: {e}")
    def _start_sniff():
        scapy.sniff(
            filter="ip and (tcp or udp or icmp)", 
            prn=_process_packet, 
            store=0
        )
    loop.run_in_executor(None, _start_sniff)

async def main():
    print("\n==== Live Packet Map Backend ====")
    print(f"Project Directory: {PROJECT_DIR}")
    print(f"GeoIP Database: {'Found' if os.path.exists(GEOIP_DB_PATH) else 'Not found'}")
    ext_ip = get_external_ip()
    if ext_ip:
        print(f"External IP: {ext_ip}")
    else:
        print("External IP: Detection failed")
    app = web.Application()
    app.router.add_get('/', index)
    app.router.add_get('/app.js', js)
    app.router.add_get('/style.css', css)
    app.router.add_get('/connections', connections)
    app.router.add_get('/geoip', geoip)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8000)
    await site.start()
    print("HTTP server: http://0.0.0.0:8000")
    ws_server = await websockets.serve(websocket_handler, "0.0.0.0", 8765)
    print("WebSocket server: ws://0.0.0.0:8765")
    asyncio.create_task(run_backend())
    asyncio.create_task(broadcaster())
    asyncio.create_task(cleanup_connections())
    print("\n==== SYSTEM ACTIVE - CTRL+C TO TERMINATE ====\n")
    try:
        await ws_server.wait_closed()
    except KeyboardInterrupt:
        log_debug("Keyboard interrupt received.")
    finally:
        print("\nTerminating...")

if __name__ == "__main__":
    if platform.system() == "Windows":
        print("Run as Administrator for packet capture capabilities")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTerminating...")
    except Exception as e:
        print(f"Critical error: {e}")
        sys.exit(1)
