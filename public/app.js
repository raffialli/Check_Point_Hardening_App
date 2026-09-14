let sessionId = "";
let hardeningScan = null;
const openCheckGroups = new Set();
const openCheckItems = new Set();
const openMoraDomains = new Set();
const openHierarchyNodes = new Set(["management", "policy", "gateways"]);
let resultsView = "hierarchy";
const KONAMI_SEQUENCE = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"];
let konamiPosition = 0;
let moraModeEnabled = false;

const loginPanel = document.querySelector("#loginPanel");
const workspace = document.querySelector("#workspace");
const loginForm = document.querySelector("#loginForm");
const moraModeBanner = document.querySelector("#moraModeBanner");
const managementTypeInput = document.querySelector("#managementType");
const hostInput = document.querySelector("#host");
const customerNameInput = document.querySelector("#customerName");
const usernameField = document.querySelector("#usernameField");
const usernameInput = document.querySelector("#username");
const smart1CloudInput = document.querySelector("#smart1Cloud");
const mdsScanInput = document.querySelector("#mdsScan");
const domainField = document.querySelector("#domainField");
const managementObjectField = document.querySelector("#managementObjectField");
const domainInput = document.querySelector("#domain");
const managementObjectNameInput = document.querySelector("#managementObjectName");
const passwordField = document.querySelector("#passwordField");
const apiKeyField = document.querySelector("#apiKeyField");
const passwordInput = document.querySelector("#password");
const apiKeyInput = document.querySelector("#apiKey");
const scanButton = document.querySelector("#scanButton");
const exportPdfButton = document.querySelector("#exportPdfButton");
const exportInfrastructurePdfButton = document.querySelector("#exportInfrastructurePdfButton");
const logoutButton = document.querySelector("#logoutButton");
const checksList = document.querySelector("#checksList");
const hierarchyViewButton = document.querySelector("#hierarchyViewButton");
const categoryViewButton = document.querySelector("#categoryViewButton");
const scanStatus = document.querySelector("#scanStatus");
const guideSummary = document.querySelector("#guideSummary");
const summaryGrid = document.querySelector("#summaryGrid");
const commandPanel = document.querySelector("#commandPanel");
const commandResults = document.querySelector("#commandResults");
const downloadDebugLogButton = document.querySelector("#downloadDebugLogButton");
const connectionLabel = document.querySelector("#connectionLabel");
const loginStatus = document.querySelector("#loginStatus");
const backendStatus = document.querySelector("#backendStatus");
const loginDiagnostics = document.querySelector("#loginDiagnostics");
const log = document.querySelector("#log");
const popupOverlay = document.querySelector("#popupOverlay");
const popupDialog = document.querySelector(".popup-dialog");
const popupTitle = document.querySelector("#popupTitle");
const popupMessage = document.querySelector("#popupMessage");
const popupCloseButton = document.querySelector("#popupCloseButton");
const popupCloseIcon = document.querySelector("#popupCloseIcon");
const reauthOverlay = document.querySelector("#reauthOverlay");
const reauthForm = document.querySelector("#reauthForm");
const reauthHostInput = document.querySelector("#reauthHost");
const reauthPortInput = document.querySelector("#reauthPort");
const reauthSmart1CloudInput = document.querySelector("#reauthSmart1Cloud");
const reauthUsernameField = document.querySelector("#reauthUsernameField");
const reauthUsernameInput = document.querySelector("#reauthUsername");
const reauthPasswordField = document.querySelector("#reauthPasswordField");
const reauthPasswordInput = document.querySelector("#reauthPassword");
const reauthApiKeyField = document.querySelector("#reauthApiKeyField");
const reauthApiKeyInput = document.querySelector("#reauthApiKey");
const reauthMdsScanInput = document.querySelector("#reauthMdsScan");
const reauthDomainField = document.querySelector("#reauthDomainField");
const reauthDomainInput = document.querySelector("#reauthDomain");
const reauthManagementObjectField = document.querySelector("#reauthManagementObjectField");
const reauthManagementObjectNameInput = document.querySelector("#reauthManagementObjectName");
const reauthIgnoreTlsInput = document.querySelector("#reauthIgnoreTls");
const reauthLargeEnvironmentModeInput = document.querySelector("#reauthLargeEnvironmentMode");
const reauthStatus = document.querySelector("#reauthStatus");
const reauthCancelButton = document.querySelector("#reauthCancelButton");
let printRestoreOpenGroups = null;
let printRestoreOpenItems = null;
let reauthPromise = null;
let reauthResolve = null;
let reauthReject = null;
let scanProgressTimer = null;

function setBusy(isBusy) {
  document.querySelectorAll("button").forEach((button) => {
    if (!button.closest("#reauthOverlay")) {
      button.disabled = isBusy;
    }
  });
}

function setScanInProgress(isScanning) {
  scanButton.classList.toggle("is-scanning", isScanning);
  scanButton.innerHTML = isScanning
    ? '<span class="spinner" aria-hidden="true"></span><span>Scanning...</span>'
    : "Scan Hardening Posture";
  scanButton.setAttribute("aria-busy", String(isScanning));
  if (isScanning) {
    scanStatus.className = "global-status scan-progress";
    scanStatus.innerHTML = `
      <div class="scan-progress-head">
        <span class="spinner" aria-hidden="true"></span>
        <strong>Scanning hardening posture...</strong>
      </div>
      <div class="scan-stepper">
        <div class="scan-step current">
          <span class="scan-step-dot"></span>
          <div>
            <strong>Starting scan</strong>
            <span>Waiting for command progress...</span>
          </div>
        </div>
      </div>
      `;
    commandPanel.classList.remove("hidden");
    commandResults.innerHTML = `
      <div class="command-row command-row-pending">
        <span class="badge unknown">Running</span>
        <code>/api/scan</code>
        <span>Command details will appear here when the scan completes.</span>
      </div>
    `;
  }
}

function renderScanProgress(progress = {}) {
  if (!scanButton.classList.contains("is-scanning")) {
    return;
  }
  const steps = Array.isArray(progress.steps) ? progress.steps.slice(-9) : [];
  const currentStep = progress.currentStep || "Scanning hardening posture";
  const percent = Number(progress.percent || 0);
  const domainProgress = Number(progress.totalDomains || 0)
    ? `Domain ${progress.currentDomainIndex || 0} of ${progress.totalDomains}${progress.currentDomain ? `: ${progress.currentDomain}` : ""}`
    : "";
  const stepMarkup = steps.length
    ? steps.map((step) => `
      <div class="scan-step ${step.status === "ok" ? "done" : "failed"}">
        <span class="scan-step-dot"></span>
        <div>
          <strong>${escapeHtml(step.command || "Command")}</strong>
          <span>${escapeHtml(step.status === "ok" ? `${step.durationMs || 0} ms` : (step.error || step.phase || "Failed"))}</span>
        </div>
      </div>
    `).join("")
    : "";
  scanStatus.className = `global-status scan-progress ${progress.failed ? "error-state" : ""}`.trim();
  scanStatus.innerHTML = `
    <div class="scan-progress-head">
      ${progress.failed ? "" : '<span class="spinner" aria-hidden="true"></span>'}
      <strong>${escapeHtml(progress.failed ? "Scan failed" : progress.complete ? "Scan complete" : domainProgress ? (moraModeEnabled ? "Scanning Mor-a Mode domains..." : "Scanning all MDS domains...") : "Scanning hardening posture...")}</strong>
      <span>${escapeHtml(`${domainProgress ? `${domainProgress} - ` : ""}${progress.completedSteps || 0} command${Number(progress.completedSteps || 0) === 1 ? "" : "s"} completed`)}</span>
    </div>
    <div class="scan-progress-meter" aria-label="Scan progress">
      <span style="width: ${Math.max(3, Math.min(100, percent))}%"></span>
    </div>
    <div class="scan-stepper">
      ${stepMarkup}
      ${progress.complete || progress.failed ? "" : `
        <div class="scan-step current">
          <span class="scan-step-dot"></span>
          <div>
            <strong>${escapeHtml(currentStep)}</strong>
            <span>Running or waiting for next command...</span>
          </div>
        </div>
      `}
    </div>
  `;
}

function stopScanProgressPolling() {
  if (scanProgressTimer) {
    clearInterval(scanProgressTimer);
    scanProgressTimer = null;
  }
}

function startScanProgressPolling() {
  stopScanProgressPolling();
  const poll = async () => {
    try {
      const result = await api("/api/scan-progress", { sessionId });
      renderScanProgress(result.progress || {});
      if (result.progress?.complete || result.progress?.failed) {
        stopScanProgressPolling();
      }
    } catch {
      // Keep the in-flight scan UI alive; the main scan request will surface errors.
    }
  };
  scanProgressTimer = setInterval(poll, 750);
  poll();
}

function addNotice(message, type = "") {
  const notice = document.createElement("div");
  notice.className = `notice ${type}`.trim();
  notice.textContent = message;
  log.prepend(notice);
}

function showPopup(title, message) {
  popupDialog.classList.remove("wide");
  popupTitle.textContent = title;
  popupMessage.textContent = message;
  popupOverlay.classList.remove("hidden");
  popupCloseButton.focus();
}

function showHtmlPopup(title, html) {
  popupDialog.classList.add("wide");
  popupTitle.textContent = title;
  popupMessage.innerHTML = html;
  popupOverlay.classList.remove("hidden");
  popupCloseButton.focus();
}

function hidePopup() {
  popupOverlay.classList.add("hidden");
}

function setLoginStatus(message, state = "disconnected") {
  loginStatus.textContent = message;
  loginStatus.className = `status-card ${state}`;
}

function setBackendStatus(message, state = "disconnected") {
  backendStatus.textContent = message;
  backendStatus.className = `status-card ${state}`;
}

function setDiagnostics(details = {}) {
  const rows = Object.entries(details).filter(([, value]) => value !== undefined && value !== null && value !== "");
  if (!rows.length) {
    loginDiagnostics.classList.add("hidden");
    loginDiagnostics.innerHTML = "";
    return;
  }
  loginDiagnostics.innerHTML = rows.map(([key, value]) => `
    <dt>${escapeHtml(key)}</dt>
    <dd>${escapeHtml(String(value))}</dd>
  `).join("");
  loginDiagnostics.classList.remove("hidden");
}

function gaiaCommandProgressHtml(message) {
  return `
    <div class="gaia-command-progress" role="status" aria-live="polite">
      <div class="gaia-command-progress-head">
        <strong class="gaia-command-progress-message">${escapeHtml(message)}</strong>
        <span class="gaia-command-elapsed">0s elapsed</span>
      </div>
      <div class="gaia-command-progress-track" aria-hidden="true">
        <span class="gaia-command-progress-bar"></span>
      </div>
      <div class="gaia-command-current">Waiting for command details...</div>
      <div class="gaia-command-steps"></div>
      <p>This can take a few minutes. The app is still working; please keep this window open.</p>
    </div>
  `;
}

function startGaiaCommandProgress(container, message, operationId) {
  const progress = container.querySelector(".gaia-command-progress");
  progress.classList.remove("hidden");
  progress.querySelector(".gaia-command-progress-message").textContent = message;
  const elapsed = progress.querySelector(".gaia-command-elapsed");
  const startedAt = Date.now();
  const updateElapsed = () => {
    const seconds = Math.floor((Date.now() - startedAt) / 1000);
    elapsed.textContent = `${seconds}s elapsed`;
  };
  updateElapsed();
  const timer = window.setInterval(updateElapsed, 1000);
  let polling = false;
  const poll = async () => {
    if (polling) return;
    polling = true;
    try {
      const result = await api("/api/remediation-progress", { sessionId, operationId });
      const state = result.progress || {};
      progress.querySelector(".gaia-command-current").textContent = state.currentTarget
        ? `${state.currentTarget}: ${state.currentCommand || "Running Gaia command"}`
        : (state.currentCommand || "Waiting for Gaia command to start");
      progress.querySelector(".gaia-command-steps").innerHTML = (state.steps || []).slice(-6).map((step) => `
        <div class="gaia-command-step ${step.status === "failed" ? "failed" : step.status === "ok" ? "done" : "waiting"}">
          <strong>${escapeHtml(step.target || "Gaia target")}</strong>
          <code>${escapeHtml(step.command || "Command")}</code>
          ${step.details ? `<span>${escapeHtml(step.details)}</span>` : ""}
        </div>
      `).join("");
    } catch {
      // The action itself owns final error reporting.
    } finally {
      polling = false;
    }
  };
  poll();
  const poller = window.setInterval(poll, 1500);
  return () => {
    window.clearInterval(timer);
    window.clearInterval(poller);
  };
}

function updateAuthMode() {
  const form = new FormData(loginForm);
  const authMode = form.get("authMode") || "password";
  const useApiKey = authMode === "api-key";
  usernameField.classList.toggle("hidden", useApiKey);
  passwordField.classList.toggle("hidden", useApiKey);
  apiKeyField.classList.toggle("hidden", !useApiKey);
  usernameInput.required = !useApiKey;
  passwordInput.required = !useApiKey;
  apiKeyInput.required = useApiKey;
  if (useApiKey) {
    usernameInput.value = "";
    passwordInput.value = "";
  } else {
    apiKeyInput.value = "";
  }
}

function enableMoraMode() {
  moraModeEnabled = true;
  managementTypeInput.value = "mds-all";
  mdsScanInput.checked = true;
  smart1CloudInput.checked = false;
  domainInput.value = "";
  moraModeBanner.classList.remove("hidden");
  document.body.classList.add("mora-mode");
  updateManagementType();
  showHtmlPopup("Welcome to Mor-a Mode", `
    <div class="popup-guide">
      <p>Mor-a Mode is ready for MDS. Log in without selecting a domain and the app will discover active domains, scan them sequentially, and prepare one PDF report per domain.</p>
      <p>This mode is scan-and-report only. Cross-domain remediation controls are intentionally hidden.</p>
    </div>
  `);
}

function allDomainScanSelected() {
  return managementTypeInput.value === "mds-all";
}

function updateManagementType() {
  const managementType = managementTypeInput.value || "sms";
  const isAllDomainMds = managementType === "mds-all";
  const isMds = managementType === "mds" || isAllDomainMds;
  const isSmart1Cloud = managementType === "smart1-cloud";
  mdsScanInput.checked = isMds;
  smart1CloudInput.checked = isSmart1Cloud;
  hostInput.placeholder = isSmart1Cloud
    ? "tenant.example.maas.checkpoint.com/context/web_api"
    : "Hostname or IP Address";
  domainField.classList.toggle("hidden", !isMds || isAllDomainMds);
  managementObjectField.classList.toggle("hidden", !isMds);
  domainInput.required = isMds && !isAllDomainMds;
  managementObjectNameInput.required = isMds;
  moraModeBanner.classList.toggle("hidden", !isAllDomainMds);
  if (isAllDomainMds) {
    moraModeBanner.querySelector("strong").textContent = moraModeEnabled ? "Welcome to Mor-a Mode" : "All Domain Scan Without Remediation";
    moraModeBanner.querySelector("span").textContent = moraModeEnabled
      ? "MDS discovery will scan every active domain sequentially. The Domain field is not required."
      : "Every active MDS domain will be scanned sequentially. The Domain field is not required, and remediation controls are disabled.";
  }
  if (!isMds) {
    domainInput.value = "";
    managementObjectNameInput.value = "";
  }
}

function updateMdsMode() {
  managementTypeInput.value = mdsScanInput.checked
    ? (allDomainScanSelected() ? "mds-all" : "mds")
    : (smart1CloudInput.checked ? "smart1-cloud" : "sms");
  updateManagementType();
}

function updateSmart1CloudMode() {
  managementTypeInput.value = smart1CloudInput.checked ? "smart1-cloud" : (mdsScanInput.checked ? "mds" : "sms");
  updateManagementType();
}

function updateReauthMode() {
  const form = new FormData(reauthForm);
  const authMode = form.get("authMode") || "password";
  const useApiKey = authMode === "api-key";
  reauthUsernameField.classList.toggle("hidden", useApiKey);
  reauthPasswordField.classList.toggle("hidden", useApiKey);
  reauthApiKeyField.classList.toggle("hidden", !useApiKey);
  reauthUsernameInput.required = !useApiKey;
  reauthPasswordInput.required = !useApiKey;
  reauthApiKeyInput.required = useApiKey;
  if (useApiKey) {
    reauthUsernameInput.value = "";
    reauthPasswordInput.value = "";
  } else {
    reauthApiKeyInput.value = "";
  }
}

function updateReauthMdsMode() {
  const enabled = reauthMdsScanInput.checked;
  const allDomains = allDomainScanSelected();
  reauthDomainField.classList.toggle("hidden", !enabled || allDomains);
  reauthManagementObjectField.classList.toggle("hidden", !enabled);
  reauthDomainInput.required = enabled && !allDomains;
  reauthManagementObjectNameInput.required = enabled;
  if (!enabled) {
    reauthDomainInput.value = "";
    reauthManagementObjectNameInput.value = "";
  }
}

function updateReauthSmart1CloudMode() {
  const enabled = reauthSmart1CloudInput.checked;
  reauthHostInput.placeholder = enabled
    ? "tenant.maas.checkpoint.com/context/web_api"
    : "";
}

function renderDetails(details = {}, options = {}) {
  return Object.entries(details)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([key, value]) => {
      const tone = key === "Details" ? options.detailTone : (key === "Evidence" ? options.evidenceTone : "");
      const classes = tone === "critical" ? "critical-detail" : (tone === "success" ? "positive-detail" : "");
      let content = escapeHtml(String(value));
      if (key === "Details" && options.detailLink?.url) {
        const label = escapeHtml(options.detailLink.label || options.detailLink.url);
        const url = escapeHtml(options.detailLink.url);
        content = content.replace(label, `<a href="${url}" target="_blank" rel="noreferrer">${label}</a>`);
      }
      if (key === "Recommendation" && options.recommendationWarning) {
        const warnings = Array.isArray(options.recommendationWarning)
          ? options.recommendationWarning
          : [options.recommendationWarning];
        content += warnings
          .filter(Boolean)
          .map((warning) => `<div class="critical-detail detail-warning">${escapeHtml(warning)}</div>`)
          .join("");
      }
      if (key === "Details" && options.detailWarning) {
        content += `<div class="critical-detail detail-warning">${escapeHtml(options.detailWarning)}</div>`;
      }
      return `<dt>${escapeHtml(key)}</dt><dd class="${classes}">${content}</dd>`;
    })
    .join("");
}

function renderDetailRows(rows = []) {
  if (!Array.isArray(rows) || !rows.length) {
    return "";
  }
  return rows.map((row) => {
    const classes = row.tone === "critical" ? "critical-detail" : "";
    let content = escapeHtml(String(row.text || ""));
    for (const boldText of row.bold || []) {
      const label = escapeHtml(boldText);
      content = content.replaceAll(label, `<strong>${label}</strong>`);
    }
    for (const link of row.links || []) {
      const label = escapeHtml(link.label || link.url || "");
      const url = escapeHtml(link.url || "");
      if (label && url) {
        content = content.replaceAll(label, `<a href="${url}" target="_blank" rel="noreferrer">${label}</a>`);
      }
    }
    if (Array.isArray(row.bullets) && row.bullets.length) {
      content += `<ul class="detail-bullets">${row.bullets.map((bullet) => `<li>${escapeHtml(bullet)}</li>`).join("")}</ul>`;
    }
    return `<dt>${escapeHtml(row.label || "Details")}</dt><dd class="${classes}">${content}</dd>`;
  }).join("");
}

function renderSpecialConsiderations(special = null) {
  if (!special?.text) {
    return "";
  }
  let content = escapeHtml(String(special.text));
  if (special.linkLabel && special.image) {
    const label = escapeHtml(special.linkLabel);
    content = content.replace(label, `
      <button
        class="inline-link special-considerations-link"
        type="button"
        data-image="${escapeHtml(special.image)}"
      >${label}</button>
    `);
  }
  return `<dt>Special Considerations</dt><dd>${content}</dd>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeDownloadFilenamePart(value) {
  return String(value || "")
    .normalize("NFKD")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 100);
}

async function api(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });
  const contentType = response.headers.get("content-type") || "";
  let data;
  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    const text = await response.text();
    const preview = text.replace(/\s+/g, " ").trim().slice(0, 300) || "empty response";
    const error = new Error(
      `Backend returned ${contentType || "non-JSON"} for ${path} (HTTP ${response.status}). ` +
      `This usually means the Node backend is not serving the API route, or a proxy/static server returned HTML. ` +
      `Response preview: ${preview}`
    );
    error.details = { path, status: response.status, contentType, preview };
    throw error;
  }
  if (!response.ok || data.error) {
    const error = new Error(data.error || "Request failed.");
    error.requestId = data.requestId;
    error.details = data;
    if (path !== "/api/login" && isSessionExpiredError(error)) {
      await promptForReauthentication(error);
      return api(path, { ...payload, sessionId });
    }
    throw error;
  }
  return data;
}

function isSessionExpiredError(error) {
  const message = `${error.message || ""} ${error.details?.phase || ""}`.toLowerCase();
  const statusCode = Number(error.details?.statusCode || 0);
  return (
    error.details?.sessionExpired === true ||
    message.includes("session not found") ||
    message.includes("wrong session id") ||
    message.includes("session id") && message.includes("expired") ||
    message.includes("log in again") ||
    message.includes("login again") ||
    message.includes("session expired") ||
    message.includes("session may be expired") ||
    message.includes("invalid session") ||
    message.includes("sid") ||
    statusCode === 401 ||
    statusCode === 403
  );
}

function copyLoginFieldsToReauth() {
  const form = new FormData(loginForm);
  reauthHostInput.value = form.get("host") || "";
  reauthPortInput.value = form.get("port") || "";
  reauthSmart1CloudInput.checked = form.get("smart1Cloud") === "on";
  reauthMdsScanInput.checked = form.get("mdsScan") === "on";
  reauthDomainInput.value = form.get("domain") || "";
  reauthManagementObjectNameInput.value = form.get("managementObjectName") || "";
  reauthIgnoreTlsInput.checked = form.get("ignoreTls") === "on";
  reauthLargeEnvironmentModeInput.checked = form.get("largeEnvironmentMode") === "on";
  const authMode = form.get("authMode") || "password";
  reauthForm.querySelectorAll('input[name="authMode"]').forEach((input) => {
    input.checked = input.value === authMode;
  });
  reauthUsernameInput.value = authMode === "password" ? (form.get("username") || "") : "";
  reauthPasswordInput.value = "";
  reauthApiKeyInput.value = "";
  updateReauthMode();
  updateReauthSmart1CloudMode();
  updateReauthMdsMode();
}

function promptForReauthentication(error) {
  if (reauthPromise) {
    return reauthPromise;
  }
  copyLoginFieldsToReauth();
  const target = connectionLabel.textContent.replace(/^Connected to\s+/i, "").replace(/\.$/, "") || (reauthHostInput.value ? reauthHostInput.value : "the Check Point Management Server");
  const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
  document.querySelector("#reauthMessage").textContent = `Your previous session to ${target} has expired. Please re-enter login credentials.`;
  reauthStatus.textContent = `Reconnect to continue the action you were trying.${requestSuffix}`;
  reauthStatus.className = "status-card error";
  reauthOverlay.classList.remove("hidden");
  reauthHostInput.focus();
  reauthPromise = new Promise((resolve, reject) => {
    reauthResolve = resolve;
    reauthReject = reject;
  }).finally(() => {
    reauthPromise = null;
    reauthResolve = null;
    reauthReject = null;
  });
  return reauthPromise;
}

function closeReauth() {
  reauthOverlay.classList.add("hidden");
  reauthStatus.textContent = "Waiting for login.";
  reauthStatus.className = "status-card disconnected";
}

async function checkBackend() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Health check failed.");
    }
    setBackendStatus(`Local backend reachable at ${data.listenUrl}.`, "connected");
    setDiagnostics({
      "Backend request ID": data.requestId,
      "Backend time": data.serverTime
    });
  } catch (error) {
    setBackendStatus(`Local backend is not reachable: ${error.message}`, "error");
    setDiagnostics({
      "Backend status": "Not reachable",
      "Page URL": window.location.href
    });
  }
}

function statusLabel(status) {
  const labels = {
    pass: "Pass",
    reviewed: "Reviewed",
    "remediation-required": "Remediation Recommended",
    "remediation-recommended": "Remediation Recommended",
    "remediation-review-recommended": "Review Recommended",
    "needs-review": "Review Recommended",
    manual: "Manual",
    informational: "Informational",
    unknown: "Unknown"
  };
  return labels[status] || status;
}

function severityLabel(severity) {
  const labels = {
    high: "High",
    medium: "Medium",
    low: "Low"
  };
  return labels[severity] || severity || "Medium";
}

function renderSummary(summary = {}) {
  const remediationNeeded = Number(summary["remediation-required"] || 0) + Number(summary["remediation-recommended"] || 0);
  const reviewRecommended = Number(summary["needs-review"] || 0) + Number(summary["remediation-review-recommended"] || 0);
  const items = [
    ["remediation-required", "Remediation Needed", remediationNeeded],
    ["needs-review", "Review Recommended", reviewRecommended],
    ["reviewed", "Reviewed"],
    ["manual", "Manual"]
  ];
  summaryGrid.innerHTML = items.map(([key, label, value]) => `
    <div class="summary-card ${key}">
      <span class="summary-value">${value ?? Number(summary[key] || 0)}</span>
      <span class="summary-label">${label}</span>
    </div>
  `).join("");
}

function groupChecks(checks = []) {
  const groups = new Map();
  for (const check of checks) {
    if (!groups.has(check.category)) {
      groups.set(check.category, []);
    }
    groups.get(check.category).push(check);
  }
  return [...groups.entries()];
}

function infrastructureCategoryOrder(check = {}) {
  const category = check.category || "";
  if (category === "Administrator Identity and Access Control") return 10;
  if (category === "Review Implied Rules") return 20;
  if (category === "Decreasing Security Gateway Exposure with Policy") return 10;
  if (category === "Updates, Health, and Ongoing Protection") return 20;
  return 50;
}

function orderInfrastructureChecks(checks = []) {
  return checks.map((check, index) => ({ check, index })).sort((a, b) => (
    infrastructureCategoryOrder(a.check) - infrastructureCategoryOrder(b.check) || a.index - b.index
  )).map(({ check }) => check);
}

function countStatuses(checks = []) {
  return checks.reduce((counts, check) => {
    counts[check.status] = (counts[check.status] || 0) + 1;
    return counts;
  }, {});
}

function replaceCheckInScan(check) {
  if (!hardeningScan || !check?.id) {
    return;
  }
  const index = (hardeningScan.checks || []).findIndex((existing) => existing.id === check.id);
  if (index >= 0) {
    hardeningScan.checks[index] = check;
  } else {
    hardeningScan.checks = [...(hardeningScan.checks || []), check];
  }
  hardeningScan.summary = countStatuses(hardeningScan.checks || []);
}

async function refreshChecks(checkIds = []) {
  const uniqueCheckIds = [...new Set(checkIds.filter(Boolean))];
  if (!uniqueCheckIds.length) {
    return;
  }
  for (const checkId of uniqueCheckIds) {
    const result = await api("/api/check", { sessionId, checkId });
    replaceCheckInScan(result.check);
    hardeningScan.summary = result.summary || hardeningScan.summary;
    hardeningScan.commandResults = {
      ...(hardeningScan.commandResults || {}),
      ...(result.commandResults || {})
    };
  }
}

function relatedRefreshCheckIds(checkId) {
  if (checkId === "admin.accounts" || checkId === "admin.api-key-authentication") {
    return ["admin.accounts", "admin.api-key-authentication", "admin.mfa-idp"];
  }
  if (checkId === "mgmt.trusted-clients") {
    return ["mgmt.trusted-clients", "mgmt.api-access"];
  }
  if (checkId === "updates.cpdiag" || checkId === "updates.dynamic-updates" || checkId === "policy.implied-rules") {
    return [checkId];
  }
  return [checkId];
}

function renderGroupBadges(checks = []) {
  const counts = countStatuses(checks);
  const remediationRecommendedCount = Number(counts["remediation-required"] || 0) + Number(counts["remediation-recommended"] || 0);
  const reviewRecommendedCount = Number(counts["needs-review"] || 0) + Number(counts["remediation-review-recommended"] || 0);
  return [
    ["remediation-recommended", "Remediation Recommended", remediationRecommendedCount],
    ["needs-review", "Review Recommended", reviewRecommendedCount],
    ["reviewed", "Reviewed"],
    ["unknown", "Unknown"],
    ["manual", "Manual"],
    ["informational", "Informational"],
    ["pass", "Pass"]
  ]
    .filter(([key, , value]) => value ?? counts[key])
    .map(([key, label, value]) => `<span class="badge ${key}">${key === "informational" ? label : `${value ?? counts[key]} ${label}`}</span>`)
    .join("");
}

function renderRemediation(check) {
  if (hardeningScan?.moraMode || !check.remediation?.action) {
    return "";
  }
  if (
    check.id === "mgmt.api-access"
    || check.remediation.action === "set-admin-expiration-four-months"
    || check.remediation.action === "cve-disable-legacy-clients"
    || check.remediation.action === "cve-set-site-to-site-ikev2-only"
  ) {
    return "";
  }
  return `
    <div class="remediation-actions">
      <button
        class="danger remediation-button"
        type="button"
        data-action="${escapeHtml(check.remediation.action)}"
        data-check-id="${escapeHtml(check.id)}"
      >${escapeHtml(check.remediation.label || "Remediate now")}</button>
    </div>
  `;
}

function renderReviewSummary(check) {
  return "";
}

function renderChangeSummary(check) {
  return "";
}

function renderReviewAction(check) {
  return "";
}

function renderCheckActions(check) {
  if (hardeningScan?.moraMode) {
    return "";
  }
  const actions = [];
  if (check.id === "mgmt.trusted-clients") {
    actions.push(`
      <button
        class="primary add-trusted-client-button trusted-client-action-button"
        type="button"
        data-check-id="${escapeHtml(check.id)}"
      >Add Trusted Client</button>
    `);
    if (check.remediation?.action === "remove-any-trusted-client") {
      actions.push(`
        <button
          class="danger remediation-button trusted-client-action-button"
          type="button"
          data-action="${escapeHtml(check.remediation.action)}"
          data-check-id="${escapeHtml(check.id)}"
          data-lockout-risk="${check.remediation.lockoutRisk ? "true" : "false"}"
        >${escapeHtml(check.remediation.label || "Remove ANY Trusted Client")}</button>
      `);
    }
  }
  if (check.evidenceTable?.selectable && check.id === "mgmt.trusted-clients" && check.status !== "remediation-required") {
    actions.push(`
      <button
        class="danger delete-selected-button"
        type="button"
        data-check-id="${escapeHtml(check.id)}"
      >Delete Checked Clients</button>
    `);
  }
  if (check.evidenceTable?.selectable && check.id === "admin.accounts") {
    actions.push(`
      <button
        class="danger delete-selected-button"
        type="button"
        data-check-id="${escapeHtml(check.id)}"
      >Delete Checked Administrators</button>
    `);
  }
  if (check.evidenceTable?.selectable && check.id === "admin.accounts" && check.remediation?.action === "set-admin-expiration-four-months") {
    actions.push(`
      <button
        class="danger remediation-button"
        type="button"
        data-action="${escapeHtml(check.remediation.action)}"
        data-check-id="${escapeHtml(check.id)}"
      >${escapeHtml(check.remediation.label || "Remediate now")}</button>
    `);
  }
  if (check.evidenceTable?.selectable && check.id === "admin.api-key-authentication") {
    actions.push(`
      <button
        class="danger delete-selected-button"
        type="button"
        data-check-id="${escapeHtml(check.id)}"
      >Delete Checked API Administrator</button>
    `);
  }
  if (check.evidenceTable?.selectable && check.id === "admin.api-key-authentication" && check.remediation?.action === "set-admin-expiration-four-months") {
    actions.push(`
      <button
        class="danger remediation-button"
        type="button"
        data-action="${escapeHtml(check.remediation.action)}"
        data-check-id="${escapeHtml(check.id)}"
      >${escapeHtml(check.remediation.label || "Remediate now")}</button>
    `);
  }
  if (check.evidenceTable?.selectable && (check.id === "cve.legacy-clients" || check.id === "cve.site-to-site-communities") && check.remediation?.action) {
    actions.push(`
      <button
        class="danger remediation-button"
        type="button"
        data-action="${escapeHtml(check.remediation.action)}"
        data-check-id="${escapeHtml(check.id)}"
      >${escapeHtml(check.remediation.label || "Remediate now")}</button>
    `);
  }
  if (check.id === "mgmt.api-access" && check.remediation?.action) {
    actions.push(`
      <button
        class="danger remediation-button"
        type="button"
        data-action="${escapeHtml(check.remediation.action)}"
        data-check-id="${escapeHtml(check.id)}"
      >${escapeHtml(check.remediation.label || "Remediate now")}</button>
    `);
  }
  if (check.id === "gaia.system-logging-management" && check.evidenceTable?.selectable) {
    actions.push(`
      <button
        class="danger remediation-button"
        type="button"
        data-action="enable-syslog-forwarding"
        data-check-id="${escapeHtml(check.id)}"
      >Enable Syslog Forwarding for Checked Gateways</button>
    `);
  }
  if (check.id === "gaia.allowed-host-access" && check.evidenceTables?.some((table) => table.targetSelection?.value)) {
    actions.push(`
      <button
        class="primary add-gaia-allowed-client-button gaia-allowed-client-action-button"
        type="button"
        data-check-id="${escapeHtml(check.id)}"
      >Add Allowed Client</button>
    `);
    if (check.evidenceTables.some((table) => table.targetSelection?.hasAnyAllowedClient)) {
      actions.push(`
        <button
          class="danger delete-gaia-anyhost-button gaia-allowed-client-action-button"
          type="button"
          data-check-id="${escapeHtml(check.id)}"
        >Delete AnyHost</button>
      `);
    }
  }
  if (check.id === "admin.mfa-idp") {
    actions.push(`
      <button
        class="danger setup-idp-button"
        type="button"
      >How to Setup IdP/External IdP</button>
    `);
  }
  const reviewAction = renderReviewAction(check);
  if (reviewAction) {
    actions.push(reviewAction);
  }
  if (!actions.length) {
    return "";
  }
  return `<div class="check-actions">${actions.join("")}</div>`;
}

function renderEvidenceTable(table, checkId = "") {
  if (!table?.columns?.length || !table?.rows?.length) {
    return "";
  }
  const selectable = Boolean(table.selectable) && !hardeningScan?.moraMode;
  const columns = selectable ? ["Select", ...table.columns] : table.columns;
  const tableClass = table.compact ? "evidence-table evidence-table--compact" : "evidence-table";
  const targetSelection = table.targetSelection?.value && !hardeningScan?.moraMode ? `
    <label class="evidence-target-selection">
      <input
        class="evidence-target-checkbox"
        type="checkbox"
        aria-label="Select ${escapeHtml(table.targetSelection.label || table.targetSelection.value)}"
        data-check-id="${escapeHtml(checkId)}"
        data-target-name="${escapeHtml(table.targetSelection.value)}"
        data-has-any="${table.targetSelection.hasAnyAllowedClient ? "true" : "false"}"
        data-only-any="${table.targetSelection.onlyAnyAllowedClient ? "true" : "false"}"
      >
      <span>Select device</span>
    </label>
  ` : "";
  return `
    <div class="evidence-table-wrap">
      <div class="evidence-title"><span>${escapeHtml(table.title || "Evidence")}</span>${targetSelection}</div>
      <table class="${tableClass}">
        <thead>
          <tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr>
        </thead>
        <tbody>
          ${table.rows.map((row) => `
            <tr>
              ${columns.map((column) => renderEvidenceCell(row, column, checkId)).join("")}
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderEvidenceTables(tables = [], checkId = "") {
  if (!Array.isArray(tables) || !tables.length) {
    return "";
  }
  const hasTargetSelection = !hardeningScan?.moraMode && tables.some((table) => table.targetSelection?.value);
  const selectAll = checkId === "gaia.allowed-host-access" && hasTargetSelection ? `
    <label class="evidence-target-select-all">
      <input
        class="evidence-target-select-all-checkbox"
        type="checkbox"
        data-check-id="${escapeHtml(checkId)}"
      >
      <span>Select All Devices</span>
    </label>
  ` : "";
  return `${selectAll}${tables.map((table) => renderEvidenceTable(table, checkId)).join("")}`;
}

function isCriticalSnmpUsmLine(lines, index) {
  const line = String(lines[index] || "");
  const previous = String(lines[index - 1] || "");
  const token = (value) => String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const authInline = line.match(/^Authentication Type:\s*(.+)$/i);
  if (authInline?.[1]) return token(authInline[1]) !== "sha512";
  if (/^Authentication Type:\s*$/i.test(previous)) return token(line) !== "sha512";
  const privacyInline = line.match(/^Privacy Type:\s*(.+)$/i);
  if (privacyInline?.[1]) return token(privacyInline[1]) !== "aes256";
  if (/^Privacy Type:\s*$/i.test(previous)) return token(line) !== "aes256";
  return false;
}

function renderEvidenceCell(row, column, checkId = "") {
  if (column === "Select") {
    const selectable = row._select;
    if (!selectable?.value) {
      return "<td></td>";
    }
    return `
      <td class="select-cell">
        <input
          class="evidence-row-checkbox"
          type="checkbox"
          aria-label="Select ${escapeHtml(selectable.label || "trusted client")}"
          data-check-id="${escapeHtml(checkId)}"
          data-uid="${escapeHtml(selectable.value)}"
          data-name="${escapeHtml(selectable.label || selectable.value)}"
        >
      </td>
    `;
  }
  const rawValue = row[column];
  const linkValue = rawValue && typeof rawValue === "object" ? rawValue._link || rawValue.link : null;
  if (linkValue?.url) {
    return `
      <td>
        <a
          class="danger evidence-link-button"
          href="${escapeHtml(linkValue.url)}"
          target="_blank"
          rel="noreferrer"
        >${escapeHtml(linkValue.label || "Open documentation")}</a>
      </td>
    `;
  }
  if (Array.isArray(rawValue?.keyValue) && rawValue.keyValue.length) {
    return `
      <td>
        <dl class="evidence-key-value">
          ${rawValue.keyValue.map((item) => `
            <div><dt>${escapeHtml(item.key)}:</dt><dd>${escapeHtml(item.value)}</dd></div>
          `).join("")}
        </dl>
      </td>
    `;
  }
  if (rawValue && typeof rawValue === "object" && (rawValue._tone || rawValue.tone)) {
    const tone = rawValue._tone || rawValue.tone;
    const toneClass = tone === "critical" ? "critical-detail" : (tone === "success" ? "positive-detail" : "");
    if (rawValue.multiline) {
      const criticalLines = new Set((rawValue.criticalLines || []).map(String));
      const sourceLines = String(rawValue.label || rawValue.value || "").split(/\r?\n/);
      const lines = sourceLines
        .map((line, index) => criticalLines.has(line) || (column === "SNMP USM User Details" && isCriticalSnmpUsmLine(sourceLines, index))
          ? `<span class="critical-detail">${escapeHtml(line)}</span>`
          : escapeHtml(line))
        .join("<br>");
      return `<td class="${toneClass}">${lines}</td>`;
    }
    return `<td class="${toneClass}">${escapeHtml(rawValue.label || rawValue.value || "")}</td>`;
  }
  if (rawValue && typeof rawValue === "object" && rawValue.multiline) {
    const criticalLines = new Set((rawValue.criticalLines || []).map(String));
    const sourceLines = String(rawValue.value || "").split(/\r?\n/);
    const lines = sourceLines
      .map((line, index) => criticalLines.has(line) || (column === "SNMP USM User Details" && isCriticalSnmpUsmLine(sourceLines, index))
        ? `<span class="critical-detail">${escapeHtml(line)}</span>`
        : escapeHtml(line))
      .join("<br>");
    return `<td>${lines}</td>`;
  }
  const value = escapeHtml(rawValue && typeof rawValue === "object" ? "" : rawValue || "");
  const remediation = hardeningScan?.moraMode ? null : row._remediation;
  const remediationColumn = row._remediationColumn || (column === "Description" ? "Description" : "State");
  if (column !== remediationColumn || !remediation?.action) {
    return `<td>${value}</td>`;
  }
  return `
    <td>
      <div class="evidence-state-action">
        <span>${value}</span>
        <button
          class="danger remediation-button remediation-inline-button"
          type="button"
          data-action="${escapeHtml(remediation.action)}"
          data-check-id="${escapeHtml(checkId)}"
          ${remediation.targetName ? `data-target-name="${escapeHtml(remediation.targetName)}"` : ""}
        >${escapeHtml(remediation.label || "Remediate now")}</button>
      </div>
    </td>
  `;
}

function renderAuditLog(entries = []) {
  if (!entries.length) {
    return "<div class=\"empty\">No audit events have been recorded yet.</div>";
  }
  return `
    <div class="audit-log-wrap">
      <table class="audit-log-table">
        <colgroup>
          <col class="audit-date-col">
          <col class="audit-admin-col">
          <col class="audit-action-col">
          <col class="audit-status-col">
          <col class="audit-command-col">
          <col class="audit-target-col">
          <col class="audit-details-col">
        </colgroup>
        <thead>
          <tr>
            <th>Date / Time</th>
            <th>Admin</th>
            <th>Action</th>
            <th>Status</th>
            <th>Command</th>
            <th>Target</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          ${entries.map((entry) => `
            <tr>
              <td>${escapeHtml(entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "")}</td>
              <td>${escapeHtml(entry.user || "Unknown")}</td>
              <td>${escapeHtml(entry.action || "")}</td>
              <td><span class="badge audit-${escapeHtml(entry.status || "success")}">${escapeHtml(entry.status || "success")}</span></td>
              <td>${escapeHtml(entry.command || "")}</td>
              <td>${escapeHtml(entry.target || "")}</td>
              <td>${escapeHtml(entry.details || "")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function commandBodySummary(body) {
  if (!body || typeof body !== "object" || !Object.keys(body).length) {
    return "";
  }
  return JSON.stringify(body, null, 2);
}

function renderCommandTrace(commandLog = [], commandResults = {}) {
  if (Array.isArray(commandLog) && commandLog.length) {
    return commandLog.map((entry, index) => {
      const ok = entry.status === "ok";
      const body = commandBodySummary(entry.body);
      const detailRows = [
        entry.target ? ["Target", entry.target] : null,
        entry.phase ? ["Phase", entry.phase] : null,
        entry.statusCode ? ["HTTP", entry.statusCode] : null,
        entry.durationMs !== undefined ? ["Duration", `${entry.durationMs} ms`] : null,
        entry.error ? ["Error", entry.error] : null
      ].filter(Boolean);
      return `
        <details class="command-trace-row">
          <summary>
            <span class="badge ${ok ? "pass" : "unknown"}">${ok ? "OK" : "Failed"}</span>
            <code>${escapeHtml(entry.command || `command-${index + 1}`)}</code>
            <span>${escapeHtml(entry.error || entry.target || "")}</span>
          </summary>
          <div class="command-trace-body">
            ${detailRows.length ? `
              <dl>
                ${detailRows.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("")}
              </dl>
            ` : ""}
            ${body ? `<pre>${escapeHtml(body)}</pre>` : ""}
          </div>
        </details>
      `;
    }).join("");
  }

  return Object.entries(commandResults).map(([command, result]) => {
    const ok = result === "ok";
    const details = ok ? {} : (result || {});
    const detailRows = [
      details.phase ? ["Phase", details.phase] : null,
      details.statusCode ? ["HTTP", details.statusCode] : null,
      details.target ? ["Target", details.target] : null,
      details.error ? ["Error", details.error] : ["Error", "Command failed"]
    ].filter(Boolean);
    return `
      <details class="command-trace-row">
        <summary>
          <span class="badge ${ok ? "pass" : "unknown"}">${ok ? "OK" : "Unavailable"}</span>
          <code>${escapeHtml(command)}</code>
          ${ok ? "<span></span>" : `<span>${escapeHtml(details.error || "Command failed")}</span>`}
        </summary>
        ${ok ? "" : `
          <div class="command-trace-body">
            <dl>${detailRows.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("")}</dl>
          </div>
        `}
      </details>
    `;
  }).join("");
}

function downloadDebugLog() {
  if (!hardeningScan) {
    addNotice("Run a scan before downloading a debug log.", "error");
    return;
  }
  const payload = {
    generatedAt: new Date().toISOString(),
    scannedAt: hardeningScan.scannedAt,
    user: hardeningScan.user || undefined,
    baseUrl: hardeningScan.baseUrl || undefined,
    summary: hardeningScan.summary || {},
    commandLog: hardeningScan.commandLog || [],
    commandResults: hardeningScan.commandResults || {}
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  link.href = url;
  link.download = `check-point-debug-log-${timestamp}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  addNotice("Debug log downloaded.", "success");
}

function renderCheckCardMarkup(check) {
  return `
    <details class="check-card" data-check-id="${escapeHtml(check.id)}" ${openCheckItems.has(check.id) ? "open" : ""}>
      <summary class="check-card-summary">
        <div class="check-card-head">
          <div class="check-card-title-wrap">
            <h4>${escapeHtml(check.title)}</h4>
            ${renderReviewSummary(check)}
            ${renderChangeSummary(check)}
          </div>
          ${check.hideBadges ? "" : `
            <div class="badge-stack">
              <span class="badge ${escapeHtml(check.status)}">${escapeHtml(statusLabel(check.status))}</span>
              <span class="badge severity-${escapeHtml(check.severity || "medium")}">${escapeHtml(severityLabel(check.severity))}</span>
            </div>
          `}
        </div>
      </summary>
      <div class="check-card-body">
        ${check.hierarchyReference ? `<p class="shared-finding-note"><strong>Related finding.</strong> This setting affects this gateway, but its authoritative evidence and any available action live under ${escapeHtml(check.hierarchyReferenceLocation || "Categories")}.</p>` : ""}
        <dl class="check-details">${renderDetails({
          "Recommendation": check.recommendation,
          ...(check.evidenceTable || check.evidenceTables ? {} : { "Evidence": check.evidence }),
          "Details": check.details
        }, { evidenceTone: check.evidenceTone, detailTone: check.detailTone, detailLink: check.detailsLink, detailWarning: check.detailsWarning, recommendationWarning: check.recommendationWarning })}
        ${renderDetailRows(check.detailRows)}
        ${renderSpecialConsiderations(check.specialConsiderations)}
        ${renderDetails({ "Guide section": check.source })}</dl>
        ${renderEvidenceTable(check.evidenceTable, check.id)}
        ${renderEvidenceTables(check.evidenceTables, check.id)}
        ${renderRemediation(check)}
        ${renderCheckActions(check)}
      </div>
    </details>
  `;
}

function renderCheckGroupsMarkup(checks = []) {
  return groupChecks(checks).map(([category, categoryChecks]) => `
    <details class="check-group" data-category="${escapeHtml(category)}" ${openCheckGroups.has(category) ? "open" : ""}>
      <summary class="check-group-summary">
        <span class="check-group-title">${escapeHtml(category)}</span>
        ${category === "Advanced Hardening" ? "" : `<span class="check-group-meta">${categoryChecks.length} check${categoryChecks.length === 1 ? "" : "s"}</span>`}
        <span class="check-group-badges">${renderGroupBadges(categoryChecks)}</span>
      </summary>
      <div class="check-cards">
        ${categoryChecks.map(renderCheckCardMarkup).join("")}
      </div>
    </details>
  `).join("");
}

function checkOwnerScope(check = {}) {
  const id = String(check.id || "");
  if (id === "updates.dynamic-updates" || id === "updates.cpdiag") {
    return "management";
  }
  if (id.startsWith("policy.") || id === "cve.site-to-site-communities" || id === "advanced.explicit-rules") {
    return "policy";
  }
  if (
    id.startsWith("gaia.")
    || id.startsWith("updates.")
    || id.startsWith("security-feature-usage.")
    || id === "cve.legacy-clients"
  ) {
    return id === "gaia.management-external-syslog" ? "management" : "gateway";
  }
  return "management";
}

const gatewayNameColumns = [
  "Gateway", "Name of Gateway", "Gateway Name", "Firewall Name", "Object Name", "Target", "Name"
];

function displayCellValue(value) {
  if (value === undefined || value === null) return "";
  if (typeof value === "object") return String(value.value ?? value.label ?? "");
  return String(value);
}

function canonicalGatewayName(value) {
  let name = displayCellValue(value).trim();
  const labelPrefix = /^(?:management\s+(?:server\s+)?name|management|gateway\s+name|gateway|firewall\s+name|firewall|target\s+name|target|object\s+name|object)\s*(?::|-)\s*/i;
  while (labelPrefix.test(name)) name = name.replace(labelPrefix, "").trim();
  return name;
}

function gatewayIdentityKey(value) {
  return canonicalGatewayName(value).replace(/\s+/g, " ").toLocaleLowerCase();
}

function targetNameFromRow(row = {}) {
  for (const column of gatewayNameColumns) {
    const value = canonicalGatewayName(row[column]);
    if (value && value !== "N/A" && value !== "Not returned") return value;
  }
  return "";
}

function gatewayTargetsForCheck(check = {}) {
  const names = new Map();
  const remember = (value) => {
    const name = canonicalGatewayName(value);
    const key = gatewayIdentityKey(name);
    if (key && !names.has(key)) names.set(key, name);
  };
  for (const row of check.evidenceTable?.rows || []) {
    const name = targetNameFromRow(row);
    if (name) remember(name);
  }
  for (const table of check.evidenceTables || []) {
    const rowNames = (table.rows || []).map(targetNameFromRow).filter(Boolean);
    rowNames.forEach(remember);
    if (!rowNames.length && table.title) remember(table.title);
  }
  return [...names.values()].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

function rowMatchesTarget(row, targetName) {
  return gatewayIdentityKey(targetNameFromRow(row)) === gatewayIdentityKey(targetName);
}

function readOnlyEvidenceRow(row = {}) {
  const { _select, _remediation, _remediationColumn, ...visible } = row;
  return visible;
}

function textMentionsGateway(value, targetName) {
  const targetKey = gatewayIdentityKey(targetName);
  if (!targetKey) return false;
  const normalizedText = String(value || "")
    .replace(/^(?:management\s+(?:server\s+)?name|management|gateway\s+name|gateway|firewall\s+name|firewall|target\s+name|target|object\s+name|object)\s*(?::|-)\s*/i, "")
    .replace(/\s+/g, " ")
    .toLocaleLowerCase();
  return normalizedText.includes(targetKey);
}

function detailRowsForGateway(detailRows = [], targetName) {
  return detailRows.filter((row) => (
    textMentionsGateway(row.text, targetName)
    || (row.bold || []).some((value) => textMentionsGateway(value, targetName))
  ));
}

function evidenceRowsForGateway(check, targetName) {
  return [
    ...(check.evidenceTable?.rows || []).filter((row) => rowMatchesTarget(row, targetName)),
    ...(check.evidenceTables || []).flatMap((table) => {
      const tableIsTarget = gatewayIdentityKey(table.title || "") === gatewayIdentityKey(targetName);
      return tableIsTarget ? (table.rows || []) : (table.rows || []).filter((row) => rowMatchesTarget(row, targetName));
    })
  ];
}

function rowPlainText(row = {}) {
  return Object.entries(row)
    .filter(([key]) => !key.startsWith("_"))
    .map(([, value]) => displayCellValue(value))
    .join(" ")
    .replace(/\s+/g, " ")
    .toLocaleLowerCase();
}

function sharedCheckHasFindingForGateway(check, targetName) {
  const targetDetails = detailRowsForGateway(check.detailRows || [], targetName);
  if (targetDetails.some((row) => row.tone === "critical" || (row.bold || []).length)) return true;
  const rows = evidenceRowsForGateway(check, targetName);
  if (rows.some((row) => row._select || row._remediation || Object.values(row).some((value) => value?.tone === "critical"))) return true;
  if (check.id === "policy.stealth-rule") {
    return rows.some((row) => /\bmissing\b|no exact match|does not have/.test(rowPlainText(row)));
  }
  if (check.id === "gaia.allowed-host-access") {
    return rows.some((row) => /\banyhost\b|\bany host\b|\btype any\b|\bany ip\b/.test(rowPlainText(row)));
  }
  if (check.id === "updates.jumbo-hotfix") {
    return rows.some((row) => String(row["Available Recommended Update"] || "").toLocaleLowerCase() === "yes");
  }
  return ["remediation-required", "remediation-recommended"].includes(check.status) && rows.length > 0;
}

function isGatewayFinding(check) {
  return !["pass", "informational", "reviewed"].includes(check.status);
}

function hasTargetScopedGatewayAction(check) {
  return ["gaia.allowed-host-access", "gaia.system-logging-management", "cve.legacy-clients"].includes(check.id);
}

function checkForGateway(check, targetName, affectedTargetCount, { forceReference = false, referenceLocation = "Shared gateway controls" } = {}) {
  const targetScoped = forceReference || affectedTargetCount > 1;
  const readOnlyReference = forceReference || (affectedTargetCount > 1 && !hasTargetScopedGatewayAction(check));
  const evidenceTable = check.evidenceTable?.rows?.some((row) => rowMatchesTarget(row, targetName))
    ? {
      ...check.evidenceTable,
      selectable: readOnlyReference ? false : check.evidenceTable.selectable,
      rows: check.evidenceTable.rows
        .filter((row) => rowMatchesTarget(row, targetName))
        .map((row) => readOnlyReference ? readOnlyEvidenceRow(row) : row)
    }
    : null;
  const evidenceTables = (check.evidenceTables || []).filter((table) => (
    gatewayIdentityKey(table.title || "") === gatewayIdentityKey(targetName)
    || (table.rows || []).some((row) => rowMatchesTarget(row, targetName))
  )).map((table) => {
    const matchingRows = (table.rows || []).filter((row) => rowMatchesTarget(row, targetName));
    const tableIsTarget = gatewayIdentityKey(table.title || "") === gatewayIdentityKey(targetName);
    const rows = (matchingRows.length && !tableIsTarget ? matchingRows : (table.rows || []))
      .map((row) => readOnlyReference ? readOnlyEvidenceRow(row) : row);
    return { ...table, selectable: readOnlyReference ? false : table.selectable, rows };
  });
  const targetDetailRows = targetScoped ? detailRowsForGateway(check.detailRows || [], targetName) : check.detailRows;
  return {
    ...check,
    hierarchyReference: readOnlyReference,
    hierarchyReferenceLocation: readOnlyReference ? referenceLocation : "",
    evidence: targetScoped
      ? `Showing only evidence and findings associated with ${canonicalGatewayName(targetName)}.`
      : check.evidence,
    evidenceTable,
    evidenceTables: evidenceTables.length ? evidenceTables : null,
    detailRows: targetDetailRows?.length ? targetDetailRows : null,
    recommendationWarning: targetScoped ? "" : check.recommendationWarning,
    detailsWarning: targetScoped ? "" : check.detailsWarning,
    remediation: readOnlyReference ? null : check.remediation,
    review: readOnlyReference ? null : check.review
  };
}

function hierarchySummary(checks) {
  const counts = countStatuses(checks);
  const action = Number(counts["remediation-required"] || 0) + Number(counts["remediation-recommended"] || 0);
  const review = Number(counts["needs-review"] || 0) + Number(counts["remediation-review-recommended"] || 0);
  return `<span class="hierarchy-count">${checks.length} checks</span>${action ? `<span class="badge remediation-required">${action} action</span>` : ""}${review ? `<span class="badge needs-review">${review} review</span>` : ""}`;
}

function renderHierarchyNode({ key, title, description, checks, content = "", open = false, kind = "" }) {
  return `
    <details class="hierarchy-node ${escapeHtml(kind)}" data-hierarchy-key="${escapeHtml(key)}" ${openHierarchyNodes.has(key) || open ? "open" : ""}>
      <summary class="hierarchy-summary">
        <span class="hierarchy-icon" aria-hidden="true"></span>
        <span class="hierarchy-heading"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small></span>
        <span class="hierarchy-meta">${hierarchySummary(checks)}</span>
      </summary>
      <div class="hierarchy-content">${content || renderCheckGroupsMarkup(checks)}</div>
    </details>
  `;
}

function isManagementObjectCheck(check = {}) {
  return check.category === "Management Plane Protection" || check.id === "gaia.management-external-syslog";
}

function managementObjectDisplayName(checks = []) {
  if (hardeningScan?.managementObjectName) return hardeningScan.managementObjectName;
  for (const check of checks) {
    for (const row of check.evidenceTable?.rows || []) {
      const name = displayCellValue(row["Management Server Name"] || row["Management Name"] || row["Management Object"] || "").trim();
      if (name && name !== "N/A" && name !== "Not returned") return name;
    }
    for (const table of check.evidenceTables || []) {
      const name = canonicalGatewayName(table.title || "");
      if (/^management/i.test(String(table.title || "")) && name) return name;
    }
  }
  return hardeningScan?.reportDomainName || "Management server";
}

function infrastructureGatewayTargets(checks = [], managementObjectName = "") {
  const targets = new Map();
  const remember = (value) => {
    const name = canonicalGatewayName(value);
    const key = gatewayIdentityKey(name);
    if (key && key !== gatewayIdentityKey(managementObjectName) && !targets.has(key)) targets.set(key, name);
  };
  (hardeningScan?.gatewayTargets || []).forEach(remember);
  checks.forEach((check) => gatewayTargetsForCheck(check).forEach(remember));
  return [...targets.values()].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

function infrastructureGatewayLabel(targetName) {
  const name = canonicalGatewayName(targetName);
  const key = gatewayIdentityKey(name);
  const clusterKeys = new Set((hardeningScan?.clusterTargets || []).map(gatewayIdentityKey).filter(Boolean));
  if (clusterKeys.has(key)) return `${name} (Cluster Object)`;
  const membership = (hardeningScan?.clusterMemberships || []).find((item) => gatewayIdentityKey(item.memberName) === key);
  return membership?.clusterName ? `${name} (cluster member of: ${canonicalGatewayName(membership.clusterName)})` : name;
}

function renderInfrastructureHierarchy(checks = [], contextKey = "environment") {
  const managementOwnedChecks = checks.filter((check) => checkOwnerScope(check) === "management");
  const policyChecks = checks.filter((check) => checkOwnerScope(check) === "policy");
  const gatewayChecks = checks.filter((check) => checkOwnerScope(check) === "gateway");
  const managementObjectChecks = managementOwnedChecks.filter(isManagementObjectCheck);
  const managementObjectName = managementObjectDisplayName([...managementObjectChecks, ...gatewayChecks]);
  const managementObjectKey = gatewayIdentityKey(managementObjectName);
  const logicalClusterKeys = new Set((hardeningScan?.clusterTargets || []).map(gatewayIdentityKey).filter(Boolean));
  const knownGatewayTargets = infrastructureGatewayTargets(gatewayChecks, managementObjectName);
  const managementChecks = [
    ...managementOwnedChecks.filter((check) => !isManagementObjectCheck(check)),
    ...policyChecks.filter((check) => !["policy.stealth-rule", "policy.gateway-object-status"].includes(check.id))
      .map((check) => check.id === "policy.implied-rules" ? { ...check, category: "Review Implied Rules" } : check)
  ];
  const orderedManagementChecks = orderInfrastructureChecks(managementChecks);
  const gatewayObjectStatusChecks = policyChecks
    .filter((check) => check.id === "policy.gateway-object-status")
    .map((check) => ({ ...check, category: "Gateway Object SIC Status" }));
  const gatewayImpactPolicyChecks = policyChecks.filter((check) => check.id === "policy.stealth-rule");
  const byTarget = new Map();
  for (const check of gatewayChecks) {
    const checkTargets = gatewayTargetsForCheck(check);
    const targets = checkTargets.length ? checkTargets : knownGatewayTargets;
    if (!targets.length) continue;
    for (const target of targets) {
      const targetKey = gatewayIdentityKey(target);
      // Logical cluster objects only own policy-level stealth-rule findings.
      // Appliance checks belong to standalone gateways or physical members.
      if (logicalClusterKeys.has(targetKey)) continue;
      if (managementObjectKey && targetKey === managementObjectKey) {
        managementObjectChecks.push(checkForGateway(check, target, targets.length, { referenceLocation: "Categories" }));
        continue;
      }
      if (!byTarget.has(targetKey)) byTarget.set(targetKey, { name: canonicalGatewayName(target), checks: [] });
      byTarget.get(targetKey).checks.push(checkForGateway(check, target, targets.length, { referenceLocation: "Categories" }));
    }
  }
  for (const check of gatewayImpactPolicyChecks) {
    const targets = gatewayTargetsForCheck(check);
    for (const target of targets) {
      if (!sharedCheckHasFindingForGateway(check, target)) continue;
      const targetKey = gatewayIdentityKey(target);
      if (!byTarget.has(targetKey)) byTarget.set(targetKey, { name: canonicalGatewayName(target), checks: [] });
      byTarget.get(targetKey).checks.push(checkForGateway(check, target, targets.length, { forceReference: true, referenceLocation: "Policy packages" }));
    }
  }
  const targetNodes = [...byTarget.values()]
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }))
    .map(({ name: target, checks: targetChecks }, index) => renderHierarchyNode({
    key: `${contextKey}:gateway:${target}`,
    title: infrastructureGatewayLabel(target),
    description: "All checks and target-specific evidence for this gateway or cluster",
    checks: orderInfrastructureChecks(targetChecks),
    open: index === 0,
    kind: "gateway-node"
  })).join("");
  const gatewayStatusContent = gatewayObjectStatusChecks.length ? renderCheckGroupsMarkup(gatewayObjectStatusChecks) : "";
  const gatewayContent = `${gatewayStatusContent}${targetNodes || `<p class="hierarchy-empty">No gateway-owned checks were returned.</p>`}`;
  const managementObjectNode = managementObjectChecks.length ? renderHierarchyNode({
    key: `${contextKey}:management-object:${managementObjectName}`,
    title: managementObjectName,
    description: "Management Plane Protection and management-server Gaia OS hardening",
    checks: managementObjectChecks,
    open: true,
    kind: "management-object-node"
  }) : "";
  const managementContent = `${renderCheckGroupsMarkup(orderedManagementChecks)}${managementObjectNode}`;
  return `
    <div class="infrastructure-tree">
      ${renderHierarchyNode({ key: `${contextKey}:management`, title: "Policy and Management", description: "Administrators, authentication, global settings, policy controls, and the management server", checks: [...orderedManagementChecks, ...managementObjectChecks], content: managementContent, open: true, kind: "management-node" })}
      ${renderHierarchyNode({ key: `${contextKey}:gateways`, title: "Gateways and clusters", description: "All gateway checks plus policy findings affecting individual gateways, members, or clusters", checks: [...gatewayObjectStatusChecks, ...gatewayChecks, ...gatewayImpactPolicyChecks], content: gatewayContent, open: true, kind: "gateways-node" })}
    </div>
  `;
}

function updateResultViewButtons() {
  const hierarchyActive = resultsView === "hierarchy";
  hierarchyViewButton.classList.toggle("active", hierarchyActive);
  categoryViewButton.classList.toggle("active", !hierarchyActive);
  hierarchyViewButton.setAttribute("aria-pressed", String(hierarchyActive));
  categoryViewButton.setAttribute("aria-pressed", String(!hierarchyActive));
}

function renderChecks() {
  if (!hardeningScan) {
    scanStatus.className = "global-status empty-state";
    scanStatus.textContent = "Run a scan to see hardening checks.";
    checksList.innerHTML = "";
    commandPanel.classList.add("hidden");
    downloadDebugLogButton.disabled = true;
    exportPdfButton.disabled = true;
    exportInfrastructurePdfButton.disabled = true;
    renderSummary({});
    return;
  }
  exportPdfButton.disabled = false;
  exportInfrastructurePdfButton.disabled = false;
  downloadDebugLogButton.disabled = false;

  const moraDomains = hardeningScan.moraMode && Array.isArray(hardeningScan.domains) ? hardeningScan.domains : [];
  const checks = moraDomains.length
    ? moraDomains.flatMap((domain) => domain.scan?.checks || [])
    : (hardeningScan.checks || []);
  const scanned = hardeningScan.scannedAt ? new Date(hardeningScan.scannedAt).toLocaleString() : "";
  const lastScan = hardeningScan.history?.lastScan;
  const lastScanText = lastScan?.scannedAt
    ? `${new Date(lastScan.scannedAt).toLocaleString()} by ${lastScan.user || "Unknown"}`
    : "No previous scan recorded";
  const guide = hardeningScan.guide || {};
  guideSummary.innerHTML = `
    ${escapeHtml(guide.title || "Check Point Gateway and Management Hardening Administration Guide")}
    ${guide.date ? `<span>Published ${escapeHtml(guide.date)}</span>` : ""}
  `;
  scanStatus.className = "global-status";
  scanStatus.innerHTML = `
    <dl>${renderDetails({
      "Checks": checks.length,
      ...(hardeningScan.moraMode ? {
        "Domains scanned": moraDomains.filter((domain) => domain.scan).length,
        "Domains failed": moraDomains.filter((domain) => !domain.scan).length
      } : {}),
      "Remediation recommended": Number(hardeningScan.summary?.["remediation-required"] || 0) + Number(hardeningScan.summary?.["remediation-recommended"] || 0),
      "Review recommended": Number(hardeningScan.summary?.["needs-review"] || 0) + Number(hardeningScan.summary?.["remediation-review-recommended"] || 0),
      "Manual validation": hardeningScan.summary?.manual || 0,
      "Unknown": hardeningScan.summary?.unknown || 0,
      "Passed": hardeningScan.summary?.pass || 0,
      "Scanned": scanned,
      ...(hardeningScan.moraMode ? {} : { "Last Scan": lastScanText })
    })}</dl>
  `;
  renderSummary(hardeningScan.summary || {});

  checksList.innerHTML = hardeningScan.moraMode
    ? moraDomains.map((domain, index) => `
      <details class="mora-domain-group" data-domain-name="${escapeHtml(domain.name)}" ${openMoraDomains.has(domain.name) || index === 0 ? "open" : ""}>
        <summary class="mora-domain-summary">
          ${escapeHtml(domain.name)}
          <span>${domain.scan ? `${domain.scan.checks?.length || 0} checks` : "Scan failed"}</span>
        </summary>
        <div class="mora-domain-content">
          ${domain.scan ? (resultsView === "hierarchy" ? renderInfrastructureHierarchy(domain.scan.checks || [], `domain:${domain.uid || domain.name}`) : renderCheckGroupsMarkup(domain.scan.checks || [])) : `<p class="mora-domain-error">${escapeHtml(domain.error || "This domain could not be scanned.")}</p>`}
        </div>
      </details>
    `).join("")
    : (resultsView === "hierarchy" ? renderInfrastructureHierarchy(checks) : renderCheckGroupsMarkup(checks));

  updateResultViewButtons();

  const results = hardeningScan.commandResults || {};
  const commandLog = hardeningScan.commandLog || [];
  commandResults.innerHTML = renderCommandTrace(commandLog, results);
  commandPanel.classList.toggle("hidden", !commandLog.length && !Object.keys(results).length);
  const apiCollectionDetails = commandPanel.querySelector(".api-collection-details");
  if (apiCollectionDetails) {
    apiCollectionDetails.open = false;
  }

  document.querySelectorAll(".remediation-button").forEach((button) => {
    button.addEventListener("click", handleRemediationClick);
  });
  document.querySelectorAll(".delete-selected-button").forEach((button) => {
    button.addEventListener("click", handleDeleteSelectedObjects);
  });
  document.querySelectorAll(".setup-idp-button").forEach((button) => {
    button.addEventListener("click", handleSetupIdpClick);
  });
  document.querySelectorAll(".add-trusted-client-button").forEach((button) => {
    button.addEventListener("click", handleAddTrustedClientClick);
  });
  document.querySelectorAll(".add-gaia-allowed-client-button").forEach((button) => {
    button.addEventListener("click", handleAddGaiaAllowedClientClick);
  });
  document.querySelectorAll(".delete-gaia-anyhost-button").forEach((button) => {
    button.addEventListener("click", handleDeleteGaiaAnyHostClick);
  });
  document.querySelectorAll(".evidence-target-select-all-checkbox").forEach((checkbox) => {
    checkbox.addEventListener("change", handleEvidenceTargetSelectAll);
  });
  document.querySelectorAll(".evidence-target-checkbox").forEach((checkbox) => {
    checkbox.addEventListener("change", updateEvidenceTargetSelectAll);
  });
  document.querySelectorAll(".special-considerations-link").forEach((button) => {
    button.addEventListener("click", () => {
      const image = button.dataset.image;
      if (!image) return;
      showHtmlPopup("Implied Rules Special Considerations", `
        <div class="popup-image-wrap">
          <img src="${escapeHtml(image)}" alt="Implied Rules Special Considerations">
        </div>
      `);
    });
  });
  document.querySelectorAll(".check-group").forEach((group) => {
    group.addEventListener("toggle", () => {
      const category = group.dataset.category;
      if (!category) return;
      if (group.open) {
        openCheckGroups.add(category);
      } else {
        openCheckGroups.delete(category);
      }
    });
  });
  document.querySelectorAll(".mora-domain-group").forEach((group) => {
    group.addEventListener("toggle", () => {
      const name = group.dataset.domainName;
      if (!name) return;
      if (group.open) {
        openMoraDomains.add(name);
      } else {
        openMoraDomains.delete(name);
      }
    });
  });
  document.querySelectorAll(".hierarchy-node").forEach((node) => {
    node.addEventListener("toggle", () => {
      const key = node.dataset.hierarchyKey;
      if (!key) return;
      if (node.open) openHierarchyNodes.add(key);
      else openHierarchyNodes.delete(key);
    });
  });
  document.querySelectorAll(".check-card").forEach((card) => {
    card.addEventListener("toggle", () => {
      const checkId = card.dataset.checkId;
      if (!checkId) return;
      if (card.open) {
        openCheckItems.add(checkId);
      } else {
        openCheckItems.delete(checkId);
      }
    });
  });
}

hierarchyViewButton.addEventListener("click", () => {
  resultsView = "hierarchy";
  renderChecks();
});

categoryViewButton.addEventListener("click", () => {
  resultsView = "categories";
  renderChecks();
});

function handleEvidenceTargetSelectAll(event) {
  const checkId = event.currentTarget.dataset.checkId;
  if (!checkId) return;
  document
    .querySelectorAll(`.evidence-target-checkbox[data-check-id="${CSS.escape(checkId)}"]`)
    .forEach((checkbox) => {
      checkbox.checked = event.currentTarget.checked;
    });
  updateEvidenceTargetSelectAll({ currentTarget: event.currentTarget });
}

function updateEvidenceTargetSelectAll(event) {
  const checkId = event.currentTarget.dataset.checkId;
  if (!checkId) return;
  const checkboxes = [...document.querySelectorAll(`.evidence-target-checkbox[data-check-id="${CSS.escape(checkId)}"]`)];
  const selectAll = document.querySelector(`.evidence-target-select-all-checkbox[data-check-id="${CSS.escape(checkId)}"]`);
  if (!selectAll || !checkboxes.length) return;
  const checkedCount = checkboxes.filter((checkbox) => checkbox.checked).length;
  selectAll.checked = checkedCount === checkboxes.length;
  selectAll.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;
}

function prepareChecksPrint() {
  if (!hardeningScan) {
    addNotice("Run a scan before exporting a PDF report.", "error");
    return false;
  }
  printRestoreOpenGroups = new Set(openCheckGroups);
  printRestoreOpenItems = new Set(openCheckItems);
  document.body.classList.add("print-checks-only");
  document.querySelectorAll(".check-group").forEach((group) => {
    const category = group.dataset.category;
    if (category) {
      openCheckGroups.add(category);
    }
    group.open = true;
  });
  document.querySelectorAll(".check-card").forEach((card) => {
    const checkId = card.dataset.checkId;
    if (checkId) {
      openCheckItems.add(checkId);
    }
    card.open = true;
  });
  return true;
}

function restoreChecksPrint() {
  document.body.classList.remove("print-checks-only");
  if (!printRestoreOpenGroups || !printRestoreOpenItems) {
    return;
  }
  openCheckGroups.clear();
  printRestoreOpenGroups.forEach((category) => openCheckGroups.add(category));
  openCheckItems.clear();
  printRestoreOpenItems.forEach((checkId) => openCheckItems.add(checkId));
  document.querySelectorAll(".check-group").forEach((group) => {
    const category = group.dataset.category;
    group.open = category ? openCheckGroups.has(category) : group.open;
  });
  document.querySelectorAll(".check-card").forEach((card) => {
    const checkId = card.dataset.checkId;
    card.open = checkId ? openCheckItems.has(checkId) : card.open;
  });
  printRestoreOpenGroups = null;
  printRestoreOpenItems = null;
}

async function exportHardeningChecksPdf(reportLayout = "category", exportButton = exportPdfButton) {
  if (!hardeningScan) {
    addNotice("Run a scan before exporting a PDF report.", "error");
    return;
  }
  exportPdfButton.disabled = true;
  exportInfrastructurePdfButton.disabled = true;
  const originalText = exportButton.textContent;
  exportButton.textContent = "Building PDF...";
  try {
    const response = await fetch("/api/export-pdf", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sessionId, reportLayout })
    });
    if (!response.ok) {
      let message = "PDF export failed.";
      try {
        const data = await response.json();
        message = data.error || message;
      } catch {
        message = await response.text() || message;
      }
      throw new Error(message);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const customerPart = safeDownloadFilenamePart(hardeningScan.customerName);
    const customerPrefix = customerPart ? `${customerPart}-` : "";
    const domainPart = safeDownloadFilenamePart(hardeningScan.reportDomainName);
    link.download = hardeningScan.moraMode
      ? `${customerPrefix}all-domain-${reportLayout}-hardening-reports.zip`
      : (domainPart
        ? `${customerPrefix}${domainPart}-${reportLayout}-hardening-report.pdf`
        : `${customerPrefix}check-point-best-practices-${reportLayout}-hardening-report.pdf`);
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    addNotice(hardeningScan.moraMode
      ? `Separate domain ${reportLayout} PDF reports exported in one ZIP file.`
      : `${reportLayout === "infrastructure" ? "Infrastructure" : "Category"} PDF report exported with cover and intro.`, "success");
  } catch (error) {
    addNotice(`PDF export failed: ${error.message}`, "error");
  } finally {
    exportButton.textContent = originalText;
    exportPdfButton.disabled = false;
    exportInfrastructurePdfButton.disabled = false;
  }
}

function handleSetupIdpClick() {
  showHtmlPopup("How to Setup IdP/External IdP", `
    <div class="popup-guide">
      <h3>Step 1: Define the IdP in SmartConsole</h3>
      <ol>
        <li>Open and log in to SmartConsole.</li>
        <li>Navigate to Manage &amp; Settings &gt; Permissions &amp; Administrators &gt; Administrators.</li>
        <li>Click New &gt; Administrator &gt; SAML Authentication Login.</li>
        <li>Enter the user/administrator name that is defined in your external IdP.</li>
        <li>Note the Identifier (Entity ID) and Reply URL (ACS) generated in the window, as you will need to input these into your IdP.</li>
        <li>Assign a Permission Profile to dictate what the administrator is authorized to do. [<a href="https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_SecurityManagement_AdminGuide/Topics-SECMG/Configuring_RADIUS_Server_Authentication_for_Administrators.htm" target="_blank" rel="noreferrer">1</a>, <a href="https://community.cyberark.com/s/article/How-to-configure-CyberArk-MFA-for-Check-Point-Mobile-Access-Portal-via-SAML" target="_blank" rel="noreferrer">2</a>, <a href="https://support.checkpoint.com/results/sk/sk40697" target="_blank" rel="noreferrer">3</a>, <a href="https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_SecurityManagement_AdminGuide/Content/Topics-SECMG/Managing_Administrator_Accounts.htm" target="_blank" rel="noreferrer">4</a>]</li>
      </ol>
      <h3>Step 2: Configure the External IdP</h3>
      <ol>
        <li>Log into your IdP's admin portal, such as <a href="https://help.okta.com/en-us/content/topics/integrations/check-point-radius-intg-conf-gateway.htm" target="_blank" rel="noreferrer">Okta Admin Console</a> or Microsoft Entra ID.</li>
        <li>Create a new SAML 2.0 Application / Enterprise Application.</li>
        <li>Paste the Identifier (Entity ID) and Reply URL you copied from SmartConsole into the respective fields in your IdP.</li>
        <li>Download the IdP's metadata XML file or copy the login URL and certificate. [<a href="https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_RemoteAccessVPN_AdminGuide/Topics-VPNRG/SAML-Support-for-Remote-Access-VPN.htm" target="_blank" rel="noreferrer">1</a>, <a href="https://docs.omnissa.com/bundle/Connect/page/ConnectorBasedIdentityProvider.html" target="_blank" rel="noreferrer">2</a>, <a href="https://community.cyberark.com/s/article/How-to-configure-CyberArk-MFA-for-Check-Point-Mobile-Access-Portal-via-SAML" target="_blank" rel="noreferrer">3</a>, <a href="https://sc1.checkpoint.com/documents/SMB_R81.10.X/AdminGuides_Centrally_Managed/EN/Content/Topics/Configuring-SAML-Identity-Provider-Centrally-Managed.htm" target="_blank" rel="noreferrer">4</a>]</li>
      </ol>
      <h3>Step 3: Complete the Setup in SmartConsole</h3>
      <ol>
        <li>Return to your administrator setup in SmartConsole.</li>
        <li>Import the metadata file from your IdP or manually input the Identifier, Login URL, and Certificate.</li>
        <li>Click OK and publish the changes. Administrators will now be redirected to your external identity provider for login verification. [<a href="https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_SecurityManagement_AdminGuide/Topics-SECMG/Configuring_RADIUS_Server_Authentication_for_Administrators.htm" target="_blank" rel="noreferrer">1</a>, <a href="https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_RemoteAccessVPN_AdminGuide/Topics-VPNRG/SAML-Support-for-Remote-Access-VPN.htm" target="_blank" rel="noreferrer">2</a>, <a href="https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_SecurityManagement_AdminGuide/Content/Topics-SECMG/Managing_Administrator_Accounts.htm" target="_blank" rel="noreferrer">3</a>]</li>
      </ol>
    </div>
  `);
}

function trustedClientFieldRows(type) {
  if (type === "host") {
    return `<label>IPv4 Address<input name="ipv4Address" required placeholder="192.0.2.10" inputmode="decimal"></label>`;
  }
  if (type === "range") {
    return `
      <label>First IP Address<input name="ipv4AddressFirst" required placeholder="192.0.2.10" inputmode="decimal"></label>
      <label>Last IP Address<input name="ipv4AddressLast" required placeholder="192.0.2.20" inputmode="decimal"></label>
    `;
  }
  return `
    <label>Network/CIDR Address<input name="ipv4Address" required placeholder="192.0.2.0/24" inputmode="decimal"></label>
    <label>Subnet Mask<input name="subnetMask" required placeholder="255.255.255.0" inputmode="decimal"></label>
  `;
}

function validIpv4(value) {
  const parts = String(value || "").trim().split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function ipv4Value(value) {
  return String(value).split(".").reduce((total, part) => (total * 256) + Number(part), 0);
}

function validateTrustedClientForm(form, values) {
  const inputs = [...form.querySelectorAll("input")];
  inputs.forEach((input) => input.setCustomValidity(""));
  if (values.objectType === "host" && !validIpv4(values.ipv4Address)) {
    form.elements.ipv4Address.setCustomValidity("Enter a valid IPv4 address.");
  }
  if (values.objectType === "range") {
    if (!validIpv4(values.ipv4AddressFirst)) form.elements.ipv4AddressFirst.setCustomValidity("Enter a valid first IPv4 address.");
    if (!validIpv4(values.ipv4AddressLast)) form.elements.ipv4AddressLast.setCustomValidity("Enter a valid last IPv4 address.");
    if (validIpv4(values.ipv4AddressFirst) && validIpv4(values.ipv4AddressLast) && ipv4Value(values.ipv4AddressFirst) > ipv4Value(values.ipv4AddressLast)) {
      form.elements.ipv4AddressLast.setCustomValidity("The last IP address must be greater than or equal to the first IP address.");
    }
  }
  if (values.objectType === "network") {
    const [address, prefix, ...extra] = String(values.ipv4Address || "").trim().split("/");
    if (!validIpv4(address) || extra.length || (prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) > 32))) {
      form.elements.ipv4Address.setCustomValidity("Enter a valid IPv4 network or CIDR address.");
    }
    if (!validIpv4(values.subnetMask)) {
      form.elements.subnetMask.setCustomValidity("Enter a subnet mask in full dotted-decimal format.");
    } else {
      const maskBits = values.subnetMask.split(".").map((part) => Number(part).toString(2).padStart(8, "0")).join("");
      if (maskBits.includes("01")) form.elements.subnetMask.setCustomValidity("Enter a valid contiguous subnet mask.");
    }
  }
  return form.reportValidity();
}

function handleAddTrustedClientClick() {
  showHtmlPopup("Add Trusted Client", `
    <form id="addTrustedClientForm" class="trusted-client-form">
      <label>Object Type
        <select name="objectType" required>
          <option value="host">Host Object</option>
          <option value="range">IP Range</option>
          <option value="network">Network Object</option>
        </select>
      </label>
      <label>Object Name<input name="name" required autocomplete="off" placeholder="Trusted Admin Host"></label>
      <div id="trustedClientTypeFields" class="trusted-client-type-fields">${trustedClientFieldRows("host")}</div>
      <div class="trusted-client-form-actions">
        <button class="primary" type="submit">Add and Publish Trusted Client</button>
      </div>
    </form>
  `);
  popupCloseButton.classList.add("hidden");
  const form = document.querySelector("#addTrustedClientForm");
  const typeSelect = form.elements.objectType;
  const typeFields = form.querySelector("#trustedClientTypeFields");
  typeSelect.addEventListener("change", () => {
    typeFields.innerHTML = trustedClientFieldRows(typeSelect.value);
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(form).entries());
    if (!validateTrustedClientForm(form, values)) return;
    const submitButton = form.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    try {
      const result = await api("/api/remediate/add-trusted-client", {
        sessionId,
        checkId: "mgmt.trusted-clients",
        ...values
      });
      hidePopup();
      addNotice(`${result.added} added to trusted clients and published. Refreshing affected checks...`, "success");
      await refreshChecks(relatedRefreshCheckIds("mgmt.trusted-clients"));
      renderChecks();
    } catch (error) {
      const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
      showPopup("Trusted Client Creation Failed", `${error.message}.${requestSuffix}`);
    } finally {
      submitButton.disabled = false;
    }
  });
  form.elements.name.focus();
}

function gaiaAllowedClientFieldRows(type) {
  if (type === "host") {
    return `<label>IPv4 Address<input name="ipv4Address" required placeholder="192.0.2.10" inputmode="decimal"></label>`;
  }
  return `
    <label>Network Address<input name="ipv4Address" required placeholder="198.51.100.0" inputmode="decimal"></label>
    <label>Mask Length<input name="maskLength" required type="number" min="0" max="32" step="1" placeholder="24"></label>
  `;
}

function handleAddGaiaAllowedClientClick() {
  const selectedTargets = [...document.querySelectorAll('.evidence-target-checkbox[data-check-id="gaia.allowed-host-access"]:checked')]
    .map((checkbox) => checkbox.dataset.targetName)
    .filter(Boolean);
  if (!selectedTargets.length) {
    showPopup("Select Gaia Devices", "Select one or more gateway or management objects before adding an allowed client.");
    return;
  }
  showHtmlPopup("Add Gaia Allowed Client", `
    <form id="addGaiaAllowedClientForm" class="trusted-client-form">
      <div class="gaia-selected-targets"><strong>Selected devices:</strong> ${selectedTargets.map(escapeHtml).join(", ")}</div>
      <label>Allowed Client Type
        <select name="objectType" required>
          <option value="host">Host</option>
          <option value="network">Network</option>
        </select>
      </label>
      <div id="gaiaAllowedClientTypeFields" class="trusted-client-type-fields">${gaiaAllowedClientFieldRows("host")}</div>
      <div class="hidden">${gaiaCommandProgressHtml("Sending Gaia command to the selected devices...")}</div>
      <div class="trusted-client-form-actions">
        <button class="primary" type="submit">Add Allowed Client to Selected Devices</button>
      </div>
    </form>
  `);
  popupCloseButton.classList.add("hidden");
  const form = document.querySelector("#addGaiaAllowedClientForm");
  const typeSelect = form.elements.objectType;
  const typeFields = form.querySelector("#gaiaAllowedClientTypeFields");
  typeSelect.addEventListener("change", () => {
    typeFields.innerHTML = gaiaAllowedClientFieldRows(typeSelect.value);
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(form).entries());
    const addressInput = form.elements.ipv4Address;
    addressInput.setCustomValidity(validIpv4(values.ipv4Address) ? "" : "Enter a valid IPv4 address.");
    if (values.objectType === "network") {
      const maskLength = Number(values.maskLength);
      form.elements.maskLength.setCustomValidity(Number.isInteger(maskLength) && maskLength >= 0 && maskLength <= 32
        ? ""
        : "Mask length must be a whole number from 0 through 32.");
    }
    if (!form.reportValidity()) return;
    const submitButton = form.querySelector('button[type="submit"]');
    form.querySelector(".gaia-command-progress").parentElement.classList.remove("hidden");
    [...form.elements].forEach((control) => { control.disabled = true; });
    popupCloseIcon.classList.add("hidden");
    const operationId = globalThis.crypto?.randomUUID?.() || `gaia-${Date.now()}`;
    const stopProgress = startGaiaCommandProgress(
      form,
      `Adding the allowed client on ${selectedTargets.length} selected device${selectedTargets.length === 1 ? "" : "s"}...`,
      operationId
    );
    try {
      const result = await api("/api/remediate/add-gaia-allowed-client", {
        sessionId,
        checkId: "gaia.allowed-host-access",
        operationId,
        targetNames: selectedTargets,
        ...values
      });
      hidePopup();
      const resultMessage = `Allowed client added on ${result.changedCount} device${result.changedCount === 1 ? "" : "s"}${result.failedCount ? `; ${result.failedCount} failed` : ""}.`;
      addNotice(`${resultMessage} Refreshing Gaia Allowed Host Access...`, result.failedCount ? "error" : "success");
      if (result.failedCount) {
        showPopup("Some Gaia Devices Failed", `${resultMessage} ${result.failed.map((item) => `${item.targetName}: ${item.error}`).join(" ")}`);
      }
      await refreshChecks(["gaia.allowed-host-access"]);
      renderChecks();
    } catch (error) {
      const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
      showPopup("Gaia Allowed Client Creation Failed", `${error.message}.${requestSuffix}`);
    } finally {
      stopProgress();
      popupCloseIcon.classList.remove("hidden");
      submitButton.disabled = false;
    }
  });
  form.elements.ipv4Address.focus();
}

async function handleDeleteGaiaAnyHostClick() {
  const selected = [...document.querySelectorAll('.evidence-target-checkbox[data-check-id="gaia.allowed-host-access"]:checked')];
  const targetNames = selected.map((checkbox) => checkbox.dataset.targetName).filter(Boolean);
  if (!targetNames.length) {
    showPopup("Select Gaia Devices", "Select one or more gateway or management objects before deleting AnyHost.");
    return;
  }
  const onlyAnyNames = selected
    .filter((checkbox) => checkbox.dataset.onlyAny === "true")
    .map((checkbox) => checkbox.dataset.targetName);
  if (onlyAnyNames.length) {
    showPopup(
      "Add Another Allowed Client First",
      `AnyHost is the only allowed client on ${onlyAnyNames.join(", ")}. You can't delete it until you add another allowed client so you do not lock yourself out.`
    );
    return;
  }
  const withoutAnyNames = selected
    .filter((checkbox) => checkbox.dataset.hasAny !== "true")
    .map((checkbox) => checkbox.dataset.targetName);
  if (withoutAnyNames.length) {
    showPopup("AnyHost Not Found", `AnyHost was not returned by the latest scan for: ${withoutAnyNames.join(", ")}.`);
    return;
  }
  const confirmed = window.confirm(`Delete AnyHost from ${targetNames.length} selected Gaia device${targetNames.length === 1 ? "" : "s"}?\n\n${targetNames.join(", ")}`);
  if (!confirmed) return;

  setBusy(true);
  const operationId = globalThis.crypto?.randomUUID?.() || `gaia-${Date.now()}`;
  showHtmlPopup("Deleting Gaia AnyHost", gaiaCommandProgressHtml(`Deleting AnyHost on ${targetNames.length} selected device${targetNames.length === 1 ? "" : "s"}...`));
  popupCloseButton.classList.add("hidden");
  popupCloseIcon.classList.add("hidden");
  const stopProgress = startGaiaCommandProgress(popupMessage, `Deleting AnyHost on ${targetNames.length} selected device${targetNames.length === 1 ? "" : "s"}...`, operationId);
  try {
    const result = await api("/api/remediate/delete-gaia-anyhost", {
      sessionId,
      checkId: "gaia.allowed-host-access",
      operationId,
      targetNames
    });
    const resultMessage = `AnyHost deleted on ${result.changedCount} device${result.changedCount === 1 ? "" : "s"}${result.failedCount ? `; ${result.failedCount} failed` : ""}.`;
    hidePopup();
    addNotice(`${resultMessage} Refreshing Gaia Allowed Host Access...`, result.failedCount ? "error" : "success");
    if (result.failedCount) {
      showPopup("Some Gaia Devices Failed", `${resultMessage} ${result.failed.map((item) => `${item.targetName}: ${item.error}`).join(" ")}`);
    }
    await refreshChecks(["gaia.allowed-host-access"]);
    renderChecks();
  } catch (error) {
    const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
    showPopup("AnyHost Deletion Failed", `${error.message}.${requestSuffix}`);
  } finally {
    stopProgress();
    popupCloseIcon.classList.remove("hidden");
    setBusy(false);
  }
}

async function handleDeleteSelectedObjects(event) {
  const button = event.currentTarget;
  const checkId = button.dataset.checkId;
  const selected = [...document.querySelectorAll(`.evidence-row-checkbox[data-check-id="${CSS.escape(checkId)}"]:checked`)];
  const uids = selected.map((checkbox) => checkbox.dataset.uid).filter(Boolean);
  const names = selected.map((checkbox) => checkbox.dataset.name).filter(Boolean);
  const configs = {
    "mgmt.trusted-clients": {
      singular: "trusted client",
      plural: "trusted clients",
      path: "/api/remediate/delete-trusted-clients",
      popupTitle: "Trusted Client Deletion Failed"
    },
    "admin.accounts": {
      singular: "administrator",
      plural: "administrators",
      path: "/api/remediate/delete-administrators",
      popupTitle: "Administrator Deletion Failed"
    },
    "admin.api-key-authentication": {
      singular: "API administrator",
      plural: "API administrators",
      path: "/api/remediate/delete-administrators",
      popupTitle: "API Administrator Deletion Failed"
    }
  };
  const config = configs[checkId];
  if (!config) {
    addNotice("This check does not support deleting checked objects.", "error");
    return;
  }
  if (!uids.length) {
    addNotice(`Select one or more ${config.plural} to delete.`, "error");
    return;
  }

  const itemLabel = uids.length === 1 ? config.singular : config.plural;
  const confirmed = window.confirm(`Delete ${uids.length} ${itemLabel} now?\n\n${names.join(", ")}`);
  if (!confirmed) return;

  setBusy(true);
  try {
    const result = await api(config.path, { sessionId, checkId, uids });
    const deletedLabel = result.deletedCount === 1 ? config.singular : config.plural;
    addNotice(`${result.deletedCount} ${deletedLabel} deleted${result.published ? " and published" : ""}. Refreshing affected checks...`, "success");
    await refreshChecks(relatedRefreshCheckIds(checkId));
    renderChecks();
  } catch (error) {
    const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
    const message = `${config.singular[0].toUpperCase()}${config.singular.slice(1)} deletion failed: ${error.message}.${requestSuffix}`;
    addNotice(message, "error");
    showPopup(config.popupTitle, message);
  } finally {
    setBusy(false);
  }
}

async function handleReviewClick(event) {
  const button = event.currentTarget;
  const checkId = button.dataset.checkId;
  const checkStatus = button.dataset.checkStatus;
  let confirmationMessage = "Mark this check as reviewed and approved by the current logged-in user?";
  if (checkId === "admin.password-idle-lockout" && checkStatus === "remediation-required") {
    confirmationMessage = "This section is currently marked Remediation Recommended. By marking it reviewed, you are accepting settings that Check Point does not recommend. Continue?";
  }
  if (checkId === "mgmt.api-access" && checkStatus === "remediation-required") {
    confirmationMessage = "This section is currently marked Remediation Recommended because Management API access is allowed from ANY IP address. By marking it reviewed, you are accepting a setting that Check Point does not recommend. Continue?";
  }
  if (checkId === "admin.mfa-idp" && checkStatus === "remediation-recommended") {
    confirmationMessage = "This section is currently marked Remediation Recommended because one or more administrator authentication settings still use a local password method. By marking it reviewed, you are accepting settings that do not follow Check Point's recommendation to use MFA or an external Identity Provider for administrative access. Continue?";
  }
  if (checkId === "policy.implied-rules" && checkStatus === "remediation-required") {
    confirmationMessage = "This section is currently marked Remediation Recommended because implied rules are not being logged. By marking it reviewed, you are accepting a security visibility gap that Check Point does not recommend. Continue?";
  }
  if (checkId === "policy.stealth-rule" && checkStatus === "remediation-required") {
    confirmationMessage = "This section is currently marked Remediation Recommended because one or more gateways do not have an exact stealth rule match. By marking it reviewed, you are accepting gateway exposure that Check Point does not recommend. Continue?";
  }
  if (checkId === "mgmt.protected-segment" && checkStatus === "remediation-review-recommended") {
    confirmationMessage = "This section is currently marked Review Recommended because the Management Server does not appear directly behind one of the gateways it manages. By marking it reviewed, you are accepting a management-plane design that may not provide the recommended Security Gateway protection. Continue?";
  }
  if (checkId === "mgmt.admin-source-ip" && checkStatus === "remediation-review-recommended") {
    confirmationMessage = "This section is currently marked Review Recommended because access rules, groups, networks, or address ranges may allow administrative access to the Management Server. By marking it reviewed, you are accepting the listed administrative source exposure paths as reviewed and approved. Continue?";
  }
  if (checkId === "gaia.allowed-host-access" && checkStatus === "remediation-recommended") {
    confirmationMessage = "This section is currently marked Remediation Recommended because Gaia allowed-host access permits connections from ANY IP address. By marking it reviewed, you are accepting Gaia OS management access exposure that should be limited to trusted administrative sources. Continue?";
  }
  if (checkId === "updates.cpdiag" && checkStatus === "remediation-recommended") {
    confirmationMessage = "This section is currently marked Remediation Recommended because diagnostics and telemetry sharing is disabled. By marking it reviewed, you are accepting a setting that may prevent Check Point from proactively identifying and alerting on known exposure risks. Continue?";
  }
  if (checkId === "updates.dynamic-updates" && checkStatus === "remediation-recommended") {
    confirmationMessage = "This section is currently marked Remediation Recommended because one or more dynamic update settings are disabled. By marking it reviewed, you are accepting settings that may delay security protections, IPS updates, and interim vulnerability mitigations. Continue?";
  }
  if (checkId === "cve.ike-global-property" && checkStatus === "remediation-recommended") {
    confirmationMessage = "This section is currently marked Remediation Recommended because Remote Access VPN may still allow deprecated IKEv1 key exchange. By marking it reviewed, you are accepting the listed CVE-2026-50751 exposure state as reviewed and approved. Continue?";
  }
  if (checkId === "cve.legacy-clients" && checkStatus === "remediation-recommended") {
    confirmationMessage = "This section is currently marked Remediation Recommended because legacy VPN clients are still supported on one or more gateways. By marking it reviewed, you are accepting the listed CVE-2026-50751 exposure state as reviewed and approved. Continue?";
  }
  if (checkId === "cve.site-to-site-communities" && checkStatus === "remediation-recommended") {
    confirmationMessage = "This section is currently marked Remediation Recommended because one or more site-to-site VPN communities match the IKEv1 certificate-based CVE-2026-50752 exposure criteria. By marking it reviewed, you are accepting the listed exposure as reviewed and approved. Continue?";
  }
  const confirmed = window.confirm(confirmationMessage);
  if (!confirmed) return;

  setBusy(true);
  try {
    const result = await api("/api/review", { sessionId, checkId });
    addNotice(`Check reviewed by ${result.review.reviewedBy}. Refreshing this check...`, "success");
    await refreshChecks([checkId]);
    renderChecks();
  } catch (error) {
    const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
    const message = `Review update failed: ${error.message}.${requestSuffix}`;
    addNotice(message, "error");
    showPopup("Review Update Failed", message);
  } finally {
    setBusy(false);
  }
}

async function handleRemediationClick(event) {
  const button = event.currentTarget;
  const action = button.dataset.action;
  const actions = {
    "remove-any-trusted-client": {
      confirm: "Remove the trusted client entry that allows any IP address now?",
      path: "/api/remediate/remove-any-trusted-client",
      success: (result) => `${result.removed} removed from trusted clients${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "set-default-expiration-quarterly": {
      confirm: "Set the default administrator expiration period to 4 months now?",
      path: "/api/remediate/default-expiration-quarterly",
      success: (result) => `${result.changed} set to ${result.expirationPeriod} ${result.expirationPeriodTimeUnits}${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "set-admin-expiration-four-months": {
      confirm: "Set checked administrator accounts with no expiration date to expire 4 months from today?",
      path: "/api/remediate/admin-expiration-four-months",
      requiresSelection: true,
      success: (result) => `${result.changedCount} administrator expiration date${result.changedCount === 1 ? "" : "s"} set to ${result.expirationDate}${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "set-minimum-password-length": {
      confirm: "Set the minimum administrator password length to 10 characters now?",
      path: "/api/remediate/minimum-password-length",
      success: (result) => `${result.changed} set to ${result.minPasswordLength} characters${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "set-smartconsole-idle-timeout": {
      confirm: "Enable SmartConsole idle timeout and set it to 10 minutes now?",
      path: "/api/remediate/smartconsole-idle-timeout",
      success: (result) => `${result.changed} enabled and set to ${result.timeoutDuration} minutes${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "set-api-clients-gui-clients": {
      confirm: "Set Management API access to all IP addresses that can be used for GUI clients now?",
      path: "/api/remediate/api-clients-gui-clients",
      success: (result) => `${result.changed} set to ${result.acceptedApiCallsFrom}${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "enable-log-implied-rules": {
      confirm: "Enable logging for implied rules now?",
      path: "/api/remediate/enable-log-implied-rules",
      success: (result) => `${result.changed} enabled${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "enable-diagnostics-telemetry": {
      confirm: "Enable Check Point diagnostics and telemetry sharing now?",
      path: "/api/remediate/enable-diagnostics-telemetry",
      success: (result) => `${result.changed} enabled${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "enable-dynamic-updates": {
      confirm: "Enable dynamic updates and AutoUpdater consent now?",
      path: "/api/remediate/enable-dynamic-updates",
      success: (result) => `${result.changed} enabled${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "enable-syslog-forwarding": {
      confirm: "Enable Gaia OS syslog forwarding to the Management Server for the checked gateways now?",
      path: "/api/remediate/enable-syslog-forwarding",
      requiresSelection: true,
      selectionError: "Select one or more gateways to remediate.",
      success: (result) => `Syslog forwarding enabled on ${result.changedCount} gateway${result.changedCount === 1 ? "" : "s"}${result.failedCount ? `; ${result.failedCount} failed` : ""}. Refreshing affected checks...`
    },
    "cve-set-global-ikev2-only": {
      confirm: "Set the Remote Access VPN global IKE encryption method to IKEv2 only now?",
      path: "/api/remediate/cve-global-ikev2-only",
      success: (result) => `Global IKE encryption method set to ${result.desiredMethod}${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "cve-disable-legacy-clients": {
      confirm: "Disable legacy VPN client support for the checked gateways now?",
      path: "/api/remediate/cve-disable-legacy-clients",
      requiresSelection: true,
      selectionError: "Select one or more gateways to remediate.",
      success: (result) => `${result.changedCount} gateway${result.changedCount === 1 ? "" : "s"} updated${result.published ? " and published" : ""}. Refreshing affected checks...`
    },
    "cve-set-site-to-site-ikev2-only": {
      confirm: "Set checked VPN communities to IKEv2 only now? If a Star community includes externally managed gateways, make the matching change on the externally managed side before policy install.",
      path: "/api/remediate/cve-site-to-site-ikev2-only",
      requiresSelection: true,
      selectionError: "Select one or more VPN communities to remediate.",
      success: (result) => `${result.changedCount} VPN communit${result.changedCount === 1 ? "y" : "ies"} updated${result.published ? " and published" : ""}. Refreshing affected checks...`
    }
  };
  const remediation = actions[action];
  if (!remediation) {
    addNotice(`Unknown remediation action: ${action}`, "error");
    return;
  }
  if (action === "remove-any-trusted-client" && button.dataset.lockoutRisk === "true") {
    showPopup(
      "Trusted Client Required",
      "ANY is currently the only trusted client. Add a new trusted client before deleting ANY so you do not lock yourself out of SmartConsole."
    );
    return;
  }
  const checkId = button.dataset.checkId || "";
  let uids = [];
  if (remediation.requiresSelection) {
    const selected = [...document.querySelectorAll(`.evidence-row-checkbox[data-check-id="${CSS.escape(checkId)}"]:checked`)];
    uids = selected.map((checkbox) => checkbox.dataset.uid).filter(Boolean);
    if (!uids.length) {
      addNotice(remediation.selectionError || "Select one or more objects to update.", "error");
      return;
    }
  }

  const confirmed = window.confirm(remediation.confirm);
  if (!confirmed) return;

  setBusy(true);
  try {
    const targetName = button.dataset.targetName || "";
    const targetNames = action === "enable-syslog-forwarding" ? uids : [];
    const result = await api(remediation.path, { sessionId, checkId, uids, targetName, targetNames });
    addNotice(remediation.success(result), "success");
    await refreshChecks(relatedRefreshCheckIds(checkId));
    renderChecks();
  } catch (error) {
    const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
    const message = `Remediation failed: ${error.message}.${requestSuffix}`;
    addNotice(message, "error");
    showPopup("Remediation Failed", message);
  } finally {
    setBusy(false);
  }
}

popupCloseButton.addEventListener("click", hidePopup);
popupCloseIcon.addEventListener("click", hidePopup);
popupOverlay.addEventListener("click", (event) => {
  if (event.target === popupOverlay) {
    hidePopup();
  }
});
document.addEventListener("keydown", (event) => {
  const key = event.key.length === 1 ? event.key.toLowerCase() : event.key;
  if (key === KONAMI_SEQUENCE[konamiPosition]) {
    konamiPosition += 1;
    if (konamiPosition === KONAMI_SEQUENCE.length) {
      konamiPosition = 0;
      enableMoraMode();
    }
  } else {
    konamiPosition = key === KONAMI_SEQUENCE[0] ? 1 : 0;
  }
  if (event.key === "Escape" && !popupOverlay.classList.contains("hidden")) {
    hidePopup();
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true);
  setLoginStatus("Contacting local webapp backend...", "connecting");
  setDiagnostics({ "Browser action": "Login button clicked" });
  try {
    const form = new FormData(loginForm);
    const authMode = form.get("authMode") || "password";
    const mdsScan = form.get("mdsScan") === "on";
    const moraMode = allDomainScanSelected() && mdsScan;
    const result = await api("/api/login", {
      host: form.get("host"),
      customerName: form.get("customerName"),
      port: form.get("port"),
      username: form.get("username"),
      authMode,
      password: form.get("password"),
      apiKey: form.get("apiKey"),
      smart1Cloud: form.get("smart1Cloud") === "on",
      mdsScan,
      moraMode,
      domain: mdsScan && !moraMode ? form.get("domain") : "",
      managementObjectName: mdsScan ? form.get("managementObjectName") : "",
      ignoreTls: form.get("ignoreTls") === "on",
      largeEnvironmentMode: form.get("largeEnvironmentMode") === "on"
    });
    sessionId = result.sessionId;
    const allDomainLabel = moraModeEnabled ? "Mor-a Mode" : "MDS All Domain Scan";
    const modeLabel = result.moraMode ? ` in ${allDomainLabel} (${result.domains?.filter((domain) => domain.available).length || 0} active domains ready)` : "";
    connectionLabel.textContent = `Connected to ${result.baseUrl} as ${result.user}${modeLabel}`;
    setLoginStatus(`Connected to ${result.baseUrl} as ${result.user}${modeLabel}.`, "connected");
    setDiagnostics({
      "Request ID": result.requestId,
      "Check Point target": result.baseUrl,
      "Result": "Authenticated"
    });
    loginPanel.classList.add("hidden");
    workspace.classList.remove("hidden");
    addNotice(result.moraMode
      ? (moraModeEnabled ? "Welcome to Mor-a Mode. Run a scan to process active domains sequentially." : "All-domain login succeeded. Run a scan to process active domains sequentially without remediation.")
      : "Login succeeded. Run a hardening scan when ready.", "success");
  } catch (error) {
    sessionId = "";
    connectionLabel.textContent = "Not connected";
    const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
    setLoginStatus(`Login failed: ${error.message}.${requestSuffix}`, "error");
    setDiagnostics({
      "Request ID": error.details?.requestId,
      "Browser action": "Login button clicked",
      "Backend route": "/api/login",
      "Check Point command": error.details?.command,
      "Failure phase": error.details?.phase,
      "Check Point target": error.details?.target,
      "HTTP status": error.details?.statusCode,
      "Error": error.message
    });
  } finally {
    setBusy(false);
  }
});

loginForm.querySelectorAll('input[name="authMode"]').forEach((input) => {
  input.addEventListener("change", updateAuthMode);
});
managementTypeInput.addEventListener("change", updateManagementType);
updateAuthMode();
updateManagementType();

reauthForm.querySelectorAll('input[name="authMode"]').forEach((input) => {
  input.addEventListener("change", updateReauthMode);
});
reauthMdsScanInput.addEventListener("change", updateReauthMdsMode);
reauthSmart1CloudInput.addEventListener("change", updateReauthSmart1CloudMode);
updateReauthMode();
updateReauthMdsMode();
updateReauthSmart1CloudMode();

reauthCancelButton.addEventListener("click", () => {
  const error = new Error("Reauthentication canceled.");
  closeReauth();
  if (reauthReject) {
    reauthReject(error);
  }
});

reauthForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  reauthStatus.textContent = "Reconnecting to Check Point...";
  reauthStatus.className = "status-card connecting";
  try {
    const form = new FormData(reauthForm);
    const authMode = form.get("authMode") || "password";
    const mdsScan = form.get("mdsScan") === "on";
    const moraMode = allDomainScanSelected() && mdsScan;
    const result = await api("/api/login", {
      host: form.get("host"),
      customerName: customerNameInput.value,
      port: form.get("port"),
      username: form.get("username"),
      authMode,
      password: form.get("password"),
      apiKey: form.get("apiKey"),
      smart1Cloud: form.get("smart1Cloud") === "on",
      mdsScan,
      moraMode,
      domain: mdsScan && !moraMode ? form.get("domain") : "",
      managementObjectName: mdsScan ? form.get("managementObjectName") : "",
      ignoreTls: form.get("ignoreTls") === "on",
      largeEnvironmentMode: form.get("largeEnvironmentMode") === "on"
    });
    sessionId = result.sessionId;
    document.querySelector("#host").value = form.get("host") || "";
    document.querySelector("#port").value = form.get("port") || "";
    smart1CloudInput.checked = form.get("smart1Cloud") === "on";
    mdsScanInput.checked = mdsScan;
    managementTypeInput.value = mdsScan
      ? (moraMode ? "mds-all" : "mds")
      : (smart1CloudInput.checked ? "smart1-cloud" : "sms");
    document.querySelector("#domain").value = mdsScan ? (form.get("domain") || "") : "";
    document.querySelector("#managementObjectName").value = mdsScan ? (form.get("managementObjectName") || "") : "";
    document.querySelector("#ignoreTls").checked = form.get("ignoreTls") === "on";
    document.querySelector("#largeEnvironmentMode").checked = form.get("largeEnvironmentMode") === "on";
    loginForm.querySelectorAll('input[name="authMode"]').forEach((input) => {
      input.checked = input.value === authMode;
    });
    usernameInput.value = authMode === "password" ? (form.get("username") || "") : "";
    passwordInput.value = "";
    apiKeyInput.value = "";
    updateAuthMode();
    updateManagementType();
    connectionLabel.textContent = `Connected to ${result.baseUrl} as ${result.user}`;
    setLoginStatus(`Connected to ${result.baseUrl} as ${result.user}.`, "connected");
    setDiagnostics({
      "Request ID": result.requestId,
      "Check Point target": result.baseUrl,
      "Result": "Reauthenticated"
    });
    addNotice("Session reestablished. Continuing previous action...", "success");
    closeReauth();
    if (reauthResolve) {
      reauthResolve(result);
    }
  } catch (error) {
    const requestSuffix = error.requestId ? ` Request ID: ${error.requestId}.` : "";
    reauthStatus.textContent = `Reconnect failed: ${error.message}.${requestSuffix}`;
    reauthStatus.className = "status-card error";
  }
});

scanButton.addEventListener("click", async () => {
  setBusy(true);
  setScanInProgress(true);
  startScanProgressPolling();
  try {
    addNotice("Scanning hardening posture...");
    hardeningScan = await api("/api/scan", { sessionId });
    stopScanProgressPolling();
    renderChecks();
    addNotice(`Hardening scan completed at ${new Date(hardeningScan.scannedAt).toLocaleString()}.`, "success");
  } catch (error) {
    stopScanProgressPolling();
    addNotice(error.message, "error");
    scanStatus.className = "global-status error-state";
    scanStatus.textContent = `Scan failed: ${error.message}`;
  } finally {
    setScanInProgress(false);
    setBusy(false);
  }
});

exportPdfButton.addEventListener("click", () => exportHardeningChecksPdf("category", exportPdfButton));
exportInfrastructurePdfButton.addEventListener("click", () => exportHardeningChecksPdf("infrastructure", exportInfrastructurePdfButton));
downloadDebugLogButton.addEventListener("click", downloadDebugLog);
window.addEventListener("afterprint", restoreChecksPrint);

logoutButton.addEventListener("click", async () => {
  setBusy(true);
  try {
    await api("/api/logout", { sessionId });
  } catch (error) {
    addNotice(error.message, "error");
  } finally {
    sessionId = "";
    hardeningScan = null;
    scanButton.textContent = "Scan Hardening Posture";
    openCheckGroups.clear();
    openMoraDomains.clear();
    connectionLabel.textContent = "Not connected";
    setLoginStatus("Not connected.", "disconnected");
    renderChecks();
    workspace.classList.add("hidden");
    loginPanel.classList.remove("hidden");
    setBusy(false);
  }
});

checkBackend();
renderChecks();
