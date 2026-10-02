/**
 * dashboard/app.js: Frontend logic for AI-Powered NIDS Live Execution Environment
 * Handles WebSocket telemetry stream, REST fallbacks, live flow table updates,
 * Canvas 2D Doughnut chart visualization, and real-time alert toast notifications.
 */

// Configuration
const API_BASE_URL = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws/flows";

// State
let isStreamPaused = false;
let socket = null;
let reconnectTimer = null;
const MAX_TABLE_ROWS = 50;

const flowCounts = {
  Benign: 0,
  DoS_DDoS: 0,
  PortScan: 0,
  BruteForce: 0,
};
let totalFlowsCount = 0;
let totalAlertsCount = 0;

// Color mapping per specification
const LABEL_COLORS = {
  Benign: "#10b981",
  DoS_DDoS: "#ef4444",
  PortScan: "#f59e0b",
  BruteForce: "#8b5cf6",
};

// DOM Elements
const flowTableBody = document.getElementById("flow-table-body");
const wsBadge = document.getElementById("ws-badge");
const wsStatusChip = document.getElementById("ws-status-chip");
const topologyStatusText = document.getElementById("topology-status-text");
const toastContainer = document.getElementById("toast-container");
const vaultFeed = document.getElementById("vault-feed");
const vaultCount = document.getElementById("vault-count");
const vaultPlaceholder = document.getElementById("vault-empty-placeholder");

// Stat elements
const statTotalFlows = document.getElementById("stat-total-flows");
const statBenignCount = document.getElementById("stat-benign-count");
const statBenignPct = document.getElementById("stat-benign-pct");
const statThreatCount = document.getElementById("stat-threat-count");
const statThreatPct = document.getElementById("stat-threat-pct");
const statAlertCount = document.getElementById("stat-alert-count");

// Legend elements
const legendBenignVal = document.getElementById("legend-benign-val");
const legendDosVal = document.getElementById("legend-dos-val");
const legendPortscanVal = document.getElementById("legend-portscan-val");
const legendBruteforceVal = document.getElementById("legend-bruteforce-val");
const chartCenterVal = document.getElementById("chart-center-val");

// Buttons
const btnPauseStream = document.getElementById("btn-pause-stream");
const streamBtnText = document.getElementById("stream-btn-text");
const btnTestConnection = document.getElementById("btn-test-connection");
const btnClearAlerts = document.getElementById("btn-clear-alerts");

/**
 * Initialize application
 */
document.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
  initDoughnutChart();
  fetchInitialStats();
  fetchRecentFlows();
  connectWebSocket();
});

/**
 * Event Listeners
 */
function setupEventListeners() {
  btnPauseStream.addEventListener("click", toggleStreamPause);
  btnTestConnection.addEventListener("click", testApiConnection);
  btnClearAlerts.addEventListener("click", clearAlertsLog);
}

function toggleStreamPause() {
  isStreamPaused = !isStreamPaused;
  if (isStreamPaused) {
    streamBtnText.textContent = "Resume Stream";
    btnPauseStream.classList.replace("btn-primary", "btn-secondary");
    setWsStatusBadge(false, "PAUSED");
  } else {
    streamBtnText.textContent = "Pause Stream";
    btnPauseStream.classList.replace("btn-secondary", "btn-primary");
    setWsStatusBadge(true, "LIVE");
  }
}

async function testApiConnection() {
  topologyStatusText.textContent = "Checking API health...";
  try {
    const res = await fetch(`${API_BASE_URL}/health`);
    if (res.ok) {
      const data = await res.json();
      topologyStatusText.textContent = `Online (Model: ${data.model_loaded ? 'Loaded' : 'None'})`;
      topologyStatusText.style.color = "var(--color-green-dark)";
    } else {
      topologyStatusText.textContent = `HTTP ${res.status} Error`;
      topologyStatusText.style.color = "var(--color-red-dark)";
    }
  } catch (err) {
    topologyStatusText.textContent = "Offline / Connection Failed";
    topologyStatusText.style.color = "var(--color-red-dark)";
  }
}

function clearAlertsLog() {
  vaultFeed.innerHTML = "";
  vaultFeed.appendChild(vaultPlaceholder);
  vaultPlaceholder.style.display = "block";
  totalAlertsCount = 0;
  vaultCount.textContent = "0";
  statAlertCount.textContent = "0";
}

/**
 * Set WebSocket status indicator badges
 */
function setWsStatusBadge(connected, label = null) {
  if (connected) {
    wsBadge.textContent = label || "LIVE";
    wsBadge.className = "badge badge-live";
    wsStatusChip.textContent = "/ws/flows (Connected)";
    wsStatusChip.style.color = "var(--color-green-dark)";
  } else {
    wsBadge.textContent = label || "STANDBY";
    wsBadge.className = "badge badge-standby";
    wsStatusChip.textContent = "/ws/flows (Standby)";
    wsStatusChip.style.color = "var(--text-muted)";
  }
}

/**
 * WebSocket Connection & Event Handler
 */
function connectWebSocket() {
  if (socket) {
    try { socket.close(); } catch (_) {}
  }

  setWsStatusBadge(false, "CONNECTING");

  try {
    socket = new WebSocket(WS_URL);

    socket.onopen = () => {
      setWsStatusBadge(true, "LIVE");
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    socket.onmessage = (event) => {
      if (isStreamPaused) return;

      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "flow" && payload.data) {
          handleIncomingFlow(payload.data);
        } else if (payload.type === "alert" && payload.data) {
          handleIncomingAlert(payload.data);
        }
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };

    socket.onclose = () => {
      setWsStatusBadge(false, "STANDBY");
      scheduleReconnect();
    };

    socket.onerror = () => {
      setWsStatusBadge(false, "ERROR");
    };
  } catch (err) {
    setWsStatusBadge(false, "OFFLINE");
    scheduleReconnect();
  }
}

function scheduleReconnect() {
  if (!reconnectTimer) {
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectWebSocket();
    }, 3000);
  }
}

/**
 * REST API Initial Hydration
 */
async function fetchRecentFlows() {
  try {
    const res = await fetch(`${API_BASE_URL}/flows?limit=25`);
    if (res.ok) {
      const data = await res.json();
      if (data.flows && data.flows.length > 0) {
        // Clear empty state
        const emptyRow = flowTableBody.querySelector(".empty-state-row");
        if (emptyRow) emptyRow.remove();

        // Populate table in chronological order
        const sorted = [...data.flows].reverse();
        sorted.forEach(flow => addFlowRow(flow, false));
      }
    }
  } catch (e) {
    console.log("REST /flows unavailable, will rely on live WebSocket.", e);
  }
}

async function fetchInitialStats() {
  try {
    const res = await fetch(`${API_BASE_URL}/stats?minutes=60`);
    if (res.ok) {
      const data = await res.json();
      if (data.counts_by_label) {
        Object.entries(data.counts_by_label).forEach(([label, count]) => {
          if (flowCounts.hasOwnProperty(label)) {
            flowCounts[label] = count;
          }
        });
        updateStatsAndChart();
      }
    }
  } catch (e) {
    console.log("REST /stats initial fetch skipped:", e);
  }
}

/**
 * Handle incoming flow event
 */
function handleIncomingFlow(flow) {
  // Update state counts
  const label = flow.label || "Benign";
  if (flowCounts.hasOwnProperty(label)) {
    flowCounts[label]++;
  } else {
    flowCounts[label] = 1;
  }
  totalFlowsCount++;

  addFlowRow(flow, true);
  updateStatsAndChart();
}

/**
 * Append row to live flow table
 */
function addFlowRow(flow, isLive = true) {
  const emptyRow = flowTableBody.querySelector(".empty-state-row");
  if (emptyRow) emptyRow.remove();

  const tr = document.createElement("tr");

  // Format timestamp (HH:mm:ss.sss)
  const timeStr = formatTimestamp(flow.timestamp);

  // Status pill style class
  const label = flow.label || "Benign";
  const pillClass = getStatusPillClass(label);

  // Confidence & bar
  const confidence = typeof flow.confidence === "number" ? flow.confidence : 1.0;
  const confPctStr = (confidence * 100).toFixed(1) + "%";
  const barFillClass = label === "Benign" ? "fill-benign" : "fill-attack";

  // Top feature chip
  let topFeatureHtml = '<span class="text-neutral">—</span>';
  if (flow.top_features && flow.top_features.length > 0) {
    const topFeat = flow.top_features[0];
    const featName = topFeat.feature || "feature";
    topFeatureHtml = `<span class="top-feature-chip">${escapeHtml(featName)}</span>`;
  }

  tr.innerHTML = `
    <td class="cell-mono">${timeStr}</td>
    <td class="cell-ip">${escapeHtml(flow.src_ip || "—")}</td>
    <td class="cell-mono">${escapeHtml(flow.dst_ip || "—")}:${flow.dst_port || 80}</td>
    <td><span class="status-pill ${pillClass}">${escapeHtml(label)}</span></td>
    <td>
      <div class="confidence-bar-wrapper">
        <div class="confidence-bar-bg">
          <div class="confidence-bar-fill ${barFillClass}" style="width: ${Math.min(confidence * 100, 100)}%;"></div>
        </div>
        <span class="confidence-pct">${confPctStr}</span>
      </div>
    </td>
    <td>${topFeatureHtml}</td>
  `;

  // Prepend new row
  flowTableBody.insertBefore(tr, flowTableBody.firstChild);

  // Maintain max table limit
  while (flowTableBody.children.length > MAX_TABLE_ROWS) {
    flowTableBody.removeChild(flowTableBody.lastChild);
  }
}

/**
 * Handle incoming threat alert
 */
function handleIncomingAlert(alert) {
  totalAlertsCount++;
  vaultCount.textContent = totalAlertsCount;
  statAlertCount.textContent = totalAlertsCount;

  // Show Toast
  showAlertToast(alert);

  // Add to Execution Vault Log
  addAlertToVault(alert);
}

function showAlertToast(alert) {
  const toast = document.createElement("div");
  toast.className = "alert-toast";

  const timeStr = formatTimestamp(alert.timestamp);
  const confidencePct = typeof alert.confidence === "number" ? (alert.confidence * 100).toFixed(1) + "%" : "85%+";

  toast.innerHTML = `
    <div class="toast-icon">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line>
        <line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
    </div>
    <div class="toast-content">
      <div class="toast-header">
        <span class="toast-title">Security Alert</span>
        <span class="toast-time">${timeStr}</span>
      </div>
      <div class="toast-body">
        Threat detected: <strong>${escapeHtml(alert.label)}</strong> from <strong>${escapeHtml(alert.src_ip)}</strong> (Confidence: ${confidencePct})
      </div>
    </div>
  `;

  toastContainer.appendChild(toast);

  // Auto remove toast after 5s
  setTimeout(() => {
    toast.style.transition = "opacity 0.3s ease, transform 0.3s ease";
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

function addAlertToVault(alert) {
  if (vaultPlaceholder) {
    vaultPlaceholder.style.display = "none";
  }

  const entry = document.createElement("div");
  entry.className = "vault-entry";

  const timeStr = formatTimestamp(alert.timestamp);
  const confidencePct = typeof alert.confidence === "number" ? (alert.confidence * 100).toFixed(1) + "%" : "85%+";

  entry.innerHTML = `
    <div class="vault-entry-info">
      <span class="vault-time">${timeStr}</span>
      <span class="vault-ip">${escapeHtml(alert.src_ip)} &rarr; ${escapeHtml(alert.dst_ip)}:${alert.dst_port}</span>
      <span class="vault-badge">${escapeHtml(alert.label)}</span>
    </div>
    <div class="cell-mono text-red" style="font-weight: 600;">${confidencePct} Confidence</div>
  `;

  vaultFeed.insertBefore(entry, vaultFeed.firstChild);

  // Cap vault entries at 30
  while (vaultFeed.children.length > 30) {
    vaultFeed.removeChild(vaultFeed.lastChild);
  }
}

/**
 * Update UI Overview Stats & Doughnut Chart
 */
function updateStatsAndChart() {
  const benign = flowCounts.Benign || 0;
  const dos = flowCounts.DoS_DDoS || 0;
  const portscan = flowCounts.PortScan || 0;
  const bruteforce = flowCounts.BruteForce || 0;

  const threats = dos + portscan + bruteforce;
  const total = benign + threats;

  statTotalFlows.textContent = total.toLocaleString();
  statBenignCount.textContent = benign.toLocaleString();
  statThreatCount.textContent = threats.toLocaleString();

  const benignPct = total > 0 ? ((benign / total) * 100).toFixed(1) : "0.0";
  const threatPct = total > 0 ? ((threats / total) * 100).toFixed(1) : "0.0";

  statBenignPct.textContent = `${benignPct}% of total`;
  statThreatPct.textContent = `${threatPct}% attack rate`;

  // Legend counts
  legendBenignVal.textContent = benign.toLocaleString();
  legendDosVal.textContent = dos.toLocaleString();
  legendPortscanVal.textContent = portscan.toLocaleString();
  legendBruteforceVal.textContent = bruteforce.toLocaleString();
  chartCenterVal.textContent = total.toLocaleString();

  renderDoughnutChart();
}

/**
 * High-DPI Canvas 2D Doughnut Chart
 */
let chartCanvas, chartCtx;

function initDoughnutChart() {
  chartCanvas = document.getElementById("trafficDoughnutChart");
  if (!chartCanvas) return;

  // Scale for high DPI displays
  const dpr = window.devicePixelRatio || 1;
  const rect = chartCanvas.getBoundingClientRect();
  chartCanvas.width = (rect.width || 200) * dpr;
  chartCanvas.height = (rect.height || 200) * dpr;

  chartCtx = chartCanvas.getContext("2d");
  chartCtx.scale(dpr, dpr);

  renderDoughnutChart();
}

function renderDoughnutChart() {
  if (!chartCtx || !chartCanvas) return;

  const dpr = window.devicePixelRatio || 1;
  const width = chartCanvas.width / dpr;
  const height = chartCanvas.height / dpr;
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(centerX, centerY) - 8;
  const cutoutRadius = radius * 0.72;

  chartCtx.clearRect(0, 0, width, height);

  const data = [
    { label: "Benign", value: flowCounts.Benign || 0, color: LABEL_COLORS.Benign },
    { label: "DoS_DDoS", value: flowCounts.DoS_DDoS || 0, color: LABEL_COLORS.DoS_DDoS },
    { label: "PortScan", value: flowCounts.PortScan || 0, color: LABEL_COLORS.PortScan },
    { label: "BruteForce", value: flowCounts.BruteForce || 0, color: LABEL_COLORS.BruteForce },
  ];

  const total = data.reduce((acc, cur) => acc + cur.value, 0);

  if (total === 0) {
    // Empty state ring
    chartCtx.beginPath();
    chartCtx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
    chartCtx.arc(centerX, centerY, cutoutRadius, 2 * Math.PI, 0, true);
    chartCtx.fillStyle = "#e2e8f0";
    chartCtx.fill();
    return;
  }

  let startAngle = -Math.PI / 2;

  data.forEach((segment) => {
    if (segment.value <= 0) return;

    const sliceAngle = (segment.value / total) * (2 * Math.PI);
    const endAngle = startAngle + sliceAngle;

    chartCtx.beginPath();
    chartCtx.arc(centerX, centerY, radius, startAngle, endAngle);
    chartCtx.arc(centerX, centerY, cutoutRadius, endAngle, startAngle, true);
    chartCtx.closePath();
    chartCtx.fillStyle = segment.color;
    chartCtx.fill();

    startAngle = endAngle;
  });
}

/**
 * Utility Helpers
 */
function getStatusPillClass(label) {
  switch (label) {
    case "Benign": return "status-benign";
    case "DoS_DDoS": return "status-dos";
    case "PortScan": return "status-portscan";
    case "BruteForce": return "status-bruteforce";
    default: return "status-benign";
  }
}

function formatTimestamp(isoString) {
  if (!isoString) {
    const now = new Date();
    return now.toTimeString().split(" ")[0] + "." + String(now.getMilliseconds()).padStart(3, "0");
  }
  try {
    const d = new Date(isoString);
    const time = d.toTimeString().split(" ")[0];
    const ms = String(d.getMilliseconds()).padStart(3, "0");
    return `${time}.${ms}`;
  } catch (_) {
    return String(isoString).substring(11, 23);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
