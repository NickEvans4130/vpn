// --- Tab navigation ---
const navItems = document.querySelectorAll(".nav-item");
const tabs = document.querySelectorAll(".tab");

navItems.forEach((item) => {
  item.addEventListener("click", () => {
    navItems.forEach((i) => i.classList.remove("active"));
    tabs.forEach((t) => t.classList.remove("active"));
    item.classList.add("active");
    document.getElementById(`tab-${item.dataset.tab}`).classList.add("active");
  });
});

// --- Peers (static demo data until the daemon's peer store is wired up) ---
const peers = [
  {
    name: "homelab-exit",
    endpoint: "203.0.113.7:51820",
    x25519: "8f3a…c21e",
    mlkem: "a917…40b2",
  },
];

function renderPeers() {
  const list = document.getElementById("peer-list");
  list.innerHTML = "";
  peers.forEach((p) => {
    const el = document.createElement("div");
    el.className = "peer-card";
    el.innerHTML = `
      <div>
        <div class="peer-name">${p.name}</div>
        <div class="peer-endpoint">${p.endpoint}</div>
      </div>
      <div class="peer-keys">
        <div><span class="key-label">x25519</span> ${p.x25519}</div>
        <div><span class="key-label">ml-kem-768</span> ${p.mlkem}</div>
      </div>
    `;
    list.appendChild(el);
  });
}
renderPeers();

document.getElementById("add-peer-btn").addEventListener("click", () => {
  // Peer provisioning (with QR codes for the static public keys) lands
  // once the daemon exposes a peer-management API; this is a stub so the
  // dashboard's shape is already in place for that wiring.
  alert("Peer provisioning isn't wired up yet -- coming with the peer-management API.");
});

// --- Throughput graph ---
const throughputHistory = new Array(60).fill(0);

function drawGraph() {
  const svg = document.getElementById("throughput-graph");
  const w = 600, h = 140;
  const max = Math.max(1, ...throughputHistory);
  const step = w / (throughputHistory.length - 1);
  const points = throughputHistory
    .map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * (h - 10) - 4).toFixed(1)}`)
    .join(" ");

  svg.innerHTML = `
    <polyline points="${points}" fill="none" stroke="#8b7fff" stroke-width="2" />
    <polyline points="0,${h} ${points} ${w},${h}" fill="#8b7fff14" stroke="none" />
  `;
}

// --- Live stats via WebSocket ---
const connPill = document.getElementById("conn-pill");
const connLabel = document.getElementById("conn-label");

function fmtBytes(bytesPerSec) {
  if (bytesPerSec > 1024 * 1024) return `${(bytesPerSec / 1024 / 1024).toFixed(1)} MB/s`;
  if (bytesPerSec > 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${bytesPerSec.toFixed(0)} B/s`;
}

function fmtUptime(secs) {
  const h = String(Math.floor(secs / 3600)).padStart(2, "0");
  const m = String(Math.floor((secs % 3600) / 60)).padStart(2, "0");
  const s = String(Math.floor(secs % 60)).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

let lastEpoch = null;

function applyStats(stats) {
  connPill.classList.toggle("online", stats.connected);
  connLabel.textContent = stats.connected ? "connected" : "disconnected";

  document.getElementById("stat-connection").textContent = stats.connected ? "Connected" : "Disconnected";
  document.getElementById("stat-peer").textContent = stats.peer_name || "no peer";
  document.getElementById("stat-uptime").textContent = fmtUptime(stats.uptime_secs);
  document.getElementById("stat-epoch").textContent = stats.ratchet_epoch;
  document.getElementById("stat-throughput").textContent = fmtBytes(stats.tx_bytes_per_sec + stats.rx_bytes_per_sec);

  document.getElementById("sec-last-rekey").textContent =
    stats.secs_since_rekey < 60 ? `${Math.floor(stats.secs_since_rekey)}s ago` : `${Math.floor(stats.secs_since_rekey / 60)}m ago`;
  document.getElementById("sec-packets-since").textContent = stats.packets_since_rekey.toLocaleString();
  const pct = Math.min(100, (stats.packets_since_rekey / stats.rekey_packet_threshold) * 100);
  document.getElementById("sec-packets-progress").style.width = `${pct}%`;

  setBadge("sec-obfuscation", stats.obfuscation_enabled);
  setBadge("sec-padding", stats.padding_enabled);
  setBadge("sec-cover-traffic", stats.cover_traffic_enabled);

  if (lastEpoch !== null && stats.ratchet_epoch > lastEpoch) {
    const el = document.getElementById("stat-epoch");
    el.animate(
      [{ textShadow: "0 0 0px #8b7fff" }, { textShadow: "0 0 18px #8b7fff" }, { textShadow: "0 0 0px #8b7fff" }],
      { duration: 700, easing: "ease-out" }
    );
  }
  lastEpoch = stats.ratchet_epoch;

  throughputHistory.shift();
  throughputHistory.push(stats.tx_bytes_per_sec + stats.rx_bytes_per_sec);
  drawGraph();
}

function setBadge(id, active) {
  const el = document.getElementById(id);
  el.textContent = active ? "active" : "off";
  el.className = `badge ${active ? "badge-ok" : "badge-off"}`;
}

function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/stats`);

  ws.onmessage = (event) => {
    try {
      applyStats(JSON.parse(event.data));
    } catch (e) {
      console.error("bad stats payload", e);
    }
  };

  ws.onclose = () => {
    connPill.classList.remove("online");
    connLabel.textContent = "reconnecting…";
    setTimeout(connectWebSocket, 1500);
  };

  ws.onerror = () => ws.close();
}
connectWebSocket();
drawGraph();
