/**
 * CanaryMesh Frontend Controller
 */

let currentSelectedType = "ci_ephemeral";
let cachedTokens = [];
let cachedAlerts = [];
let alertSocket = null;
let alertSocketReconnectTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  loadStats();
  loadTokens();
  loadAlerts();
  connectLiveAlerts();

  // Refresh metrics and recover updates if the live connection is unavailable.
  setInterval(() => {
    loadStats();
    loadAlerts(true);
  }, 5000);
});

function adminFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  const key = sessionStorage.getItem("canaryAdminApiKey");
  if (key) headers.set("Authorization", `Bearer ${key}`);
  return fetch(url, { ...options, headers });
}

function configureAdminKey() {
  const existing = sessionStorage.getItem("canaryAdminApiKey") || "";
  const entered = prompt("Enter the CanaryMesh admin API key. Leave blank to clear it.", existing);
  if (entered === null) return;
  if (entered.trim()) sessionStorage.setItem("canaryAdminApiKey", entered.trim());
  else sessionStorage.removeItem("canaryAdminApiKey");
  loadStats();
  loadTokens();
  loadAlerts();
  connectLiveAlerts();
}

function connectLiveAlerts() {
  const key = sessionStorage.getItem("canaryAdminApiKey");
  if (alertSocketReconnectTimer) clearTimeout(alertSocketReconnectTimer);
  alertSocketReconnectTimer = null;
  if (alertSocket) alertSocket.close();
  alertSocket = null;
  if (!key) return;

  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(
    `${scheme}//${window.location.host}/api/v1/ws/alerts`,
    ["canarymesh", `canarymesh-auth.${key}`],
  );
  alertSocket = socket;
  socket.onmessage = () => {
    loadAlerts(true);
    loadStats();
  };
  socket.onclose = () => {
    if (alertSocket === socket && sessionStorage.getItem("canaryAdminApiKey")) {
      alertSocketReconnectTimer = setTimeout(connectLiveAlerts, 5000);
    }
  };
}

// --- Tab Switching ---
function switchTab(tabName) {
  document.querySelectorAll(".nav-tab").forEach(tab => tab.classList.remove("active"));
  document.querySelectorAll(".view-panel").forEach(panel => panel.classList.remove("active"));

  const targetTab = document.getElementById(`tab-btn-${tabName}`);
  const targetPanel = document.getElementById(`view-${tabName}`);

  if (targetTab) targetTab.classList.add("active");
  if (targetPanel) targetPanel.classList.add("active");

  if (tabName === "fleet") loadTokens();
  if (tabName === "alerts") loadAlerts();
  if (tabName === "simulator") populateSimulatorTokenSelect();
}

// --- Load Stats ---
async function loadStats() {
  try {
    const res = await adminFetch("/api/v1/stats");
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById("stat-active-tokens").innerText = data.active_tokens || 0;
    document.getElementById("stat-total-alerts").innerText = data.total_alerts || 0;
    document.getElementById("stat-tripped-subtext").innerText = `${data.tripped_tokens || 0} tokens touched`;

    const ciCount = (data.token_type_distribution && data.token_type_distribution["ci_ephemeral"]) || 0;
    document.getElementById("stat-ci-tokens").innerText = ciCount;

    // Update nav alert badge
    const alertBadge = document.getElementById("nav-alert-badge");
    if (data.total_alerts > 0) {
      alertBadge.style.display = "inline-block";
      alertBadge.innerText = data.total_alerts;
    } else {
      alertBadge.style.display = "none";
    }
  } catch (err) {
    console.error("Error loading stats:", err);
  }
}

// --- Load Honeytokens ---
async function loadTokens() {
  const tbody = document.getElementById("tokens-table-body");
  try {
    const res = await adminFetch("/api/v1/tokens");
    if (!res.ok) throw new Error("Failed to fetch tokens");
    const tokens = await res.json();
    cachedTokens = tokens;

    if (!tokens || tokens.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 3rem;">
            No honeytokens deployed yet. Click <strong>'+ Deploy Honeytoken'</strong> above to arm your first trap.
          </td>
        </tr>`;
      return;
    }

    tbody.innerHTML = tokens.map(t => {
      const typeBadge = getTypeBadge(t.token_type);
      const statusBadge = t.trigger_count > 0
        ? `<span class="badge badge-tripped">🚨 TRIPPED (${t.trigger_count})</span>`
        : (t.is_active ? `<span class="badge badge-active">● ARMED</span>` : `<span class="badge badge-revoked">REVOKED</span>`);

      const expiresStr = t.expires_at ? formatTimeRemaining(t.expires_at) : `<span style="color: var(--text-muted);">Never</span>`;

      return `
        <tr>
          <td>${typeBadge}</td>
          <td>
            <strong>${escapeHtml(t.label)}</strong>
            <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${t.id}</div>
          </td>
          <td><span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(t.environment)}</span></td>
          <td><span class="mono-token">${escapeHtml(t.display_token)}</span></td>
          <td style="font-size: 0.82rem;">${expiresStr}</td>
          <td>${statusBadge}</td>
          <td style="font-weight: 700; font-family: var(--font-mono);">${t.trigger_count}</td>
          <td>
            <div style="display: flex; gap: 6px;">
              <button class="btn-secondary" style="padding: 4px 8px; font-size: 0.75rem;" onclick="testToken('${t.id}')">Trip Test</button>
              ${t.is_active ? `<button class="btn-danger" onclick="revokeToken('${t.id}')">Revoke</button>` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join("");

    populateSimulatorTokenSelect();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--accent-crimson);">Failed to load tokens: ${err.message}</td></tr>`;
  }
}

// --- Load Alerts ---
async function loadAlerts(silent = false) {
  const tbody = document.getElementById("alerts-table-body");
  try {
    const res = await adminFetch("/api/v1/events?limit=50");
    if (!res.ok) {
      if (res.status === 401 || res.status === 503) {
        throw new Error("Configure CANARY_ADMIN_API_KEY, then enter it with the Admin Key button.");
      }
      throw new Error(`Failed to fetch events (HTTP ${res.status})`);
    }
    const alerts = await res.json();
    cachedAlerts = alerts;

    if (!alerts || alerts.length === 0) {
      if (!silent) {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 3rem;">
              No intrusion alerts recorded yet. Deception mesh active and listening.
            </td>
          </tr>`;
      }
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const geo = a.details || {};
      const locStr = `${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}`;
      const toolStr = a.user_agent || "Unknown Tool";
      const label = a.token_label || a.token_type;
      const route = `${a.action || "EVENT"} ${a.path || "-"}`;
      const eventTokenId = a.token_id || a.event_id || a.id;

      return `
        <tr>
          <td><span class="badge badge-tripped">${escapeHtml(a.severity || "CRITICAL")}</span></td>
          <td>
            <strong>${escapeHtml(label)}</strong>
            <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(eventTokenId)}</div>
          </td>
          <td>
            <div style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-cyan);">${escapeHtml(a.source_ip)}</div>
            <div style="font-size: 0.75rem; color: var(--text-secondary);">${escapeHtml(locStr)}</div>
          </td>
          <td>
            <div style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.8rem;" title="${escapeHtml(toolStr)}">
              ${escapeHtml(toolStr)}
            </div>
          </td>
          <td>
            <span style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(route)}</span>
          </td>
          <td><span class="mono-token">${a.decoy_response_code || "-"}</span></td>
          <td style="font-size: 0.78rem; color: var(--text-secondary); font-family: var(--font-mono);">${formatDateTime(a.timestamp)}</td>
          <td>
            <button class="btn-secondary" style="padding: 4px 8px; font-size: 0.75rem;" onclick="openForensicsModal('${a.id}')">Inspect</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    if (!silent) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--accent-crimson);">Failed to load alerts: ${err.message}</td></tr>`;
    }
  }
}

// --- Deploy Honeytoken Modal Logic ---
function openDeployModal() {
  document.getElementById("deploy-modal").classList.add("active");
}

function closeDeployModal() {
  document.getElementById("deploy-modal").classList.remove("active");
}

function selectTokenType(type) {
  currentSelectedType = type;
  document.querySelectorAll(".type-option").forEach(el => {
    el.classList.toggle("selected", el.getAttribute("data-type") === type);
  });

  const labelInput = document.getElementById("token-label-input");
  if (type === "aws_iam") labelInput.value = "aws-s3-backup-deployer";
  else if (type === "github_pat") labelInput.value = "github-ci-packages-token";
  else if (type === "openai_key") labelInput.value = "openai-agent-eval-key";
  else if (type === "stripe_secret") labelInput.value = "stripe-checkout-api-key";
  else if (type === "database_url") labelInput.value = "postgres-analytics-replica";
  else labelInput.value = "ci-pipeline-runner-key";
}

async function submitCreateToken() {
  const btn = document.getElementById("btn-submit-token");
  btn.disabled = true;
  btn.innerText = "Arming Token...";

  const label = document.getElementById("token-label-input").value.trim() || "unlabeled-honeytoken";
  const environment = document.getElementById("token-env-input").value.trim() || "production";
  const ttl = parseInt(document.getElementById("token-ttl-select").value, 10);
  const webhook = document.getElementById("token-webhook-input").value.trim() || null;

  try {
    const res = await adminFetch("/api/v1/tokens", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token_type: currentSelectedType,
        label: label,
        environment: environment,
        ttl_minutes: ttl > 0 ? ttl : null,
        webhook_url: webhook,
      }),
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || "Failed to create token");
    }

    const tokenData = await res.json();
    closeDeployModal();
    openRevealModal(tokenData);
    loadTokens();
    loadStats();
  } catch (err) {
    alert("Error creating honeytoken: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerText = "Generate & Arm Token";
  }
}

// --- Reveal Modal Logic ---
function openRevealModal(data) {
  document.getElementById("revealed-raw-token").innerText = data.raw_token;
  document.getElementById("revealed-trap-url").innerText = data.trap_url;
  document.getElementById("revealed-instructions").innerText = data.instructions;

  const secGroup = document.getElementById("revealed-secret-group");
  if (data.secret_component) {
    secGroup.style.display = "block";
    document.getElementById("revealed-secret-comp").innerText = data.secret_component;
  } else {
    secGroup.style.display = "none";
  }

  document.getElementById("reveal-modal").classList.add("active");
}

function closeRevealModal() {
  document.getElementById("reveal-modal").classList.remove("active");
}

// --- Forensics Modal ---
function openForensicsModal(alertId) {
  const alert = cachedAlerts.find(a => a.id === alertId);
  if (!alert) return;

  const geo = alert.details || {};
  const eventDetails = JSON.stringify(alert.details || {}, null, 2);
  const label = alert.token_label || alert.token_type;
  const route = `${alert.action || "EVENT"} ${alert.path || "-"}`;

  const body = document.getElementById("forensics-modal-body");
  body.innerHTML = `
    <div class="forensic-grid">
      <div class="forensic-item">
        <div class="forensic-item-label">Honeytoken Label</div>
        <div class="forensic-item-val" style="color: var(--accent-cyan); font-weight:700;">${escapeHtml(label)}</div>
      </div>
      <div class="forensic-item">
        <div class="forensic-item-label">Severity Level</div>
        <div class="forensic-item-val"><span class="badge badge-tripped">${escapeHtml(alert.severity || "CRITICAL")}</span></div>
      </div>
      <div class="forensic-item">
        <div class="forensic-item-label">Adversary Source IP</div>
        <div class="forensic-item-val">${escapeHtml(alert.source_ip)}</div>
      </div>
      <div class="forensic-item">
        <div class="forensic-item-label">Geographic Origin</div>
        <div class="forensic-item-val">${escapeHtml(geo.city || 'N/A')}, ${escapeHtml(geo.country || 'N/A')} (${escapeHtml(geo.isp || 'N/A')})</div>
      </div>
      <div class="forensic-item">
        <div class="forensic-item-label">HTTP Route & Method</div>
        <div class="forensic-item-val">${escapeHtml(route)}</div>
      </div>
      <div class="forensic-item">
        <div class="forensic-item-label">Decoy Response Code</div>
        <div class="forensic-item-val">${alert.decoy_response_code || "N/A"}</div>
      </div>
    </div>

    <div class="form-group" style="margin-top: 1rem;">
      <label class="form-label">Event Details</label>
      <div class="code-block"><pre>${escapeHtml(eventDetails)}</pre></div>
    </div>
  `;

  document.getElementById("forensics-modal").classList.add("active");
}

function closeForensicsModal() {
  document.getElementById("forensics-modal").classList.remove("active");
}

// --- Ephemeral CI Seeder Tab ---
async function generateCISeed() {
  const repo = document.getElementById("ci-repo-input").value.trim() || "org/repo";
  const workflow = document.getElementById("ci-workflow-input").value.trim() || "build";
  const ttl = parseInt(document.getElementById("ci-ttl-input").value, 10) || 60;

  const btn = document.getElementById("btn-generate-ci-seed");
  btn.disabled = true;
  btn.innerText = "Seeding...";

  try {
    const res = await adminFetch("/api/v1/seed/ci", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repository: repo,
        workflow: workflow,
        ttl_minutes: ttl,
      }),
    });

    if (!res.ok) throw new Error("Failed to seed CI key");
    const data = await res.json();

    const output = document.getElementById("ci-seed-output");
    output.innerHTML = `
<button class="code-copy-btn" onclick="copySnippet('ci-seed-export-code')">Copy Export</button>
<pre id="ci-seed-export-code"># Ephemeral Honeytoken Generated
# Token ID: ${data.token_id}
# Expires At: ${data.expires_at}

${data.ci_export_snippet}

echo "[CanaryMesh] Honeytoken armed for run. Any exfiltration alarms immediately!"</pre>`;
    
    loadTokens();
    loadStats();
  } catch (err) {
    alert("Error seeding CI token: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerText = "⚡ Seed Ephemeral CI Key";
  }
}

// --- Attack Simulator ---
function populateSimulatorTokenSelect() {
  const select = document.getElementById("sim-token-select");
  if (!select) return;

  const activeTokens = cachedTokens.filter(t => t.is_active);
  if (activeTokens.length === 0) {
    select.innerHTML = `<option value="">No active tokens available. Deploy one first.</option>`;
    return;
  }

  select.innerHTML = activeTokens.map(t => `
    <option value="${t.id}">${escapeHtml(t.label)} (${t.token_type}) — ${t.display_token}</option>
  `).join("");
}

async function runAttackSimulation() {
  const tokenId = document.getElementById("sim-token-select").value;
  if (!tokenId) {
    alert("Please select a honeytoken to test.");
    return;
  }

  const tool = document.getElementById("sim-tool-select").value;
  const ip = document.getElementById("sim-ip-input").value.trim();
  const payload = document.getElementById("sim-payload-input").value.trim();

  const btn = document.getElementById("btn-fire-simulation");
  btn.disabled = true;
  btn.innerText = "Simulating Intrusion...";

  try {
    const res = await adminFetch("/api/v1/alerts/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token_id: tokenId,
        simulated_tool: tool,
        simulated_ip: ip,
        payload: payload,
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Simulation failed");
    }

    const data = await res.json();

    const resultBox = document.getElementById("simulation-results-container");
    const jsonOutput = document.getElementById("simulation-json-output");
    resultBox.style.display = "block";
    jsonOutput.innerText = JSON.stringify(data, null, 2);

    loadAlerts();
    loadStats();
    loadTokens();
  } catch (err) {
    alert("Simulation error: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerText = "🎯 Simulate Adversary Breach Now";
  }
}

async function testToken(tokenId) {
  try {
    const res = await adminFetch("/api/v1/alerts/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token_id: tokenId }),
    });
    if (res.ok) {
      switchTab("alerts");
      loadAlerts();
      loadStats();
      loadTokens();
    }
  } catch (err) {
    alert("Failed to test token: " + err.message);
  }
}

async function revokeToken(tokenId) {
  if (!confirm(`Are you sure you want to revoke honeytoken ${tokenId}?`)) return;
  try {
    const res = await adminFetch(`/api/v1/tokens/${tokenId}`, { method: "DELETE" });
    if (res.ok) {
      loadTokens();
      loadStats();
    }
  } catch (err) {
    alert("Failed to revoke: " + err.message);
  }
}

// --- Utilities ---
function getTypeBadge(type) {
  if (type === "aws_iam") return `<span class="badge badge-aws">AWS IAM</span>`;
  if (type === "github_pat") return `<span class="badge badge-github">GitHub PAT</span>`;
  if (type === "openai_key") return `<span class="badge badge-openai">OpenAI</span>`;
  if (type === "stripe_secret") return `<span class="badge badge-stripe">Stripe</span>`;
  if (type === "database_url") return `<span class="badge badge-db">Database</span>`;
  return `<span class="badge badge-ci">CI Ephemeral</span>`;
}

function formatTimeRemaining(expiresAtIso) {
  const expires = new Date(expiresAtIso).getTime();
  const now = new Date().getTime();
  const diffMs = expires - now;

  if (diffMs <= 0) return `<span style="color: var(--accent-crimson);">Expired</span>`;

  const mins = Math.floor(diffMs / 60000);
  if (mins < 60) return `<span style="color: var(--accent-cyan); font-family: var(--font-mono);">${mins}m remaining</span>`;
  const hours = Math.floor(mins / 60);
  return `<span style="color: var(--accent-cyan); font-family: var(--font-mono);">${hours}h ${mins % 60}m remaining</span>`;
}

function formatDateTime(isoString) {
  if (!isoString) return "-";
  return new Date(isoString).toISOString().replace("T", " ").substring(0, 19);
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

function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    alert("Copied to clipboard!");
  });
}

function copySnippet(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    alert("Copied code snippet to clipboard!");
  });
}
