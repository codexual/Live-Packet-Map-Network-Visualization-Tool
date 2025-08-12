// Use dark tiles
const map = L.map('map').setView([30, 0], 2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  maxZoom: 19,
  attribution: 'Leaflet | Map data © OpenStreetMap contributors'
}).addTo(map);

const logPanel = document.getElementById('log-panel');
const markers = {};
const connectionLines = {};
let lastOpenPopup = null;
let myIp = null;

// Utility: check for valid geo location (not LAN/multicast/N/A)
function isGeoValid(geo) {
  if (!geo) return false;
  if (geo.lat === null || geo.lon === null) return false;
  if (geo.country === "LAN/Multicast" || geo.country === "N/A") return false;
  return true;
}

// Get your external IP and geo location for marker
fetch('https://api.ipify.org?format=json')
  .then(r => r.json())
  .then(data => {
    myIp = data.ip;
    fetch('/geoip?ip=' + myIp)
      .then(r => r.json())
      .then(geo => {
        if (isGeoValid(geo)) {
          addMarker(myIp, geo.lat, geo.lon, {
            proto: "YOU",
            geo,
            src_ip: myIp,
            dst_ip: myIp,
            size: "",
          }, true /* isMe */);
        } else {
          map.setView([30, 0], 2);
        }
      })
      .catch(() => map.setView([30, 0], 2));
  })
  .catch(() => map.setView([30, 0], 2));

// Connect to backend WebSocket
const socket = new WebSocket('ws://' + location.hostname + ':8765');

// Only log/draw public packets (not LAN/Multicast/N/A)
socket.addEventListener('message', (event) => {
  try {
    const msg = JSON.parse(event.data);

    if (!msg.geo || msg.geo.country === "LAN/Multicast" || msg.geo.country === "N/A")
      return;

    showLogPopup(msg);

    if (isGeoValid(msg.geo)) {
      addMarker(msg.dst_ip, msg.geo.lat, msg.geo.lon, msg);
      if (myIp && msg.is_new) {
        drawConnectionLine(myIp, msg.dst_ip, msg.proto);
      }
    }
  } catch (e) {
    showLogPopup({
      proto: "ERR",
      src_ip: "",
      dst_ip: "",
      geo: { country: "", hostname: "" },
      size: "",
      timestamp: new Date().toISOString(),
      error: e
    });
  }
});

// Hacker style animated log notification popup
function showLogPopup(msg) {
  const time = new Date(msg.timestamp).toLocaleTimeString();
  const proto = (msg.proto || '').toLowerCase();
  const entry = document.createElement('div');
  entry.className = `log-entry ${proto === 'tcp' ? 'tcp' : proto === 'udp' ? 'udp' : proto === 'icmp' ? 'icmp' : proto === 'you' ? 'you' : ''}`;
  entry.innerHTML = `
    <span class="proto">${msg.proto || ''}</span>
    <span class="ip">${msg.src_ip} → ${msg.dst_ip}</span><br>
    <span class="country">${msg.geo?.country || ''}</span>
    <span class="hostname">${msg.geo?.hostname || ''}</span><br>
    <span class="size">${msg.size || ''}B</span>
    <span style="float:right;font-size:13px;color:#0ff;">${time}</span>
  `;
  logPanel.prepend(entry);

  // Fade out and remove after 8 seconds
  setTimeout(() => {
    entry.classList.add("fadeout");
    setTimeout(() => entry.remove(), 1200);
  }, 8000);

  // Limit number of popups in panel
  if (logPanel.childNodes.length > 20) {
    for (let i = 20; i < logPanel.childNodes.length; i++) {
      logPanel.childNodes[i].remove();
    }
  }
}

// Map marker logic
function addMarker(ip, lat, lon, msg, isMe = false) {
  if (!markers[ip]) {
    let marker;
    if (isMe) {
      marker = L.marker([lat, lon], {
        icon: L.divIcon({
          html: '<div style="background:#111;border:2px solid #0ff;color:#0ff;border-radius:50%;width:32px;height:32px;display:flex;align-items:center;justify-content:center;font-weight:bold;text-shadow:0 0 8px #0ff;">YOU</div>',
          className: 'marker-self',
          iconSize: [32, 32]
        })
      });
    } else {
      marker = L.marker([lat, lon]);
    }
    marker.addTo(map);
    marker.bindPopup(
      `<b>IP:</b> ${ip}<br>
       <b>Proto:</b> ${msg.proto || ''}<br>
       <b>Country:</b> ${msg.geo.country || ''}<br>
       <b>ISP:</b> ${msg.geo.isp || ''}<br>
       <b>Hostname:</b> ${msg.geo.hostname || ''}<br>
       <b>Size:</b> ${msg.size || ''} bytes`,
      { autoClose: false, closeOnClick: false }
    );
    marker.on('click', () => {
      if (lastOpenPopup && lastOpenPopup !== marker.getPopup()) lastOpenPopup._close();
      marker.openPopup();
      lastOpenPopup = marker.getPopup();
    });
    markers[ip] = marker;
    if (isMe) map.setView([lat, lon], 5);
  }
}

// Draw hacker style neon line from you to endpoint, expires after 10s
function drawConnectionLine(srcIp, dstIp, proto) {
  if (!(markers[srcIp] && markers[dstIp])) return;
  const src = markers[srcIp].getLatLng();
  const dst = markers[dstIp].getLatLng();
  const color = proto === 'TCP' ? '#00ff80' : (proto === 'UDP' ? '#ffe000' : '#ff0055');
  const line = L.polyline([src, dst], {
    color,
    weight: 4,
    opacity: 0.93,
    dashArray: "8,6"
  }).addTo(map);

  // Neon glow effect (CSS filter)
  line.getElement().style.filter = "drop-shadow(0 0 9px " + color + ")";

  // Use a unique key per connection (src-dst-timestamp)
  const key = `${srcIp}-${dstIp}-${Date.now()}`;
  connectionLines[key] = line;

  setTimeout(() => {
    if (connectionLines[key]) {
      map.removeLayer(connectionLines[key]);
      delete connectionLines[key];
    }
  }, 10000);
}
