const versionNode = document.querySelector("#appVersion");
const banner = document.querySelector("#appUpdateBanner");
const button = document.querySelector("#appUpdateButton");
const tip = document.querySelector("#localhostOnlyTip");
const statusNode = document.querySelector("#appUpdateStatus");

let bootId = "";
let busy = false;

function setStatus(message, state = "") {
  statusNode.textContent = message || "";
  statusNode.className = state ? `app-update-status ${state}` : "app-update-status";
}

function showVersion(info) {
  if (!info) return;
  versionNode.textContent = info.label ? `Version ${info.label}` : `Version ${info.version || "unknown"}`;
  if (info.bootId) bootId = info.bootId;
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function loadVersion() {
  const response = await fetch("/api/app/version", { cache: "no-store" });
  const data = await readJson(response);
  if (!response.ok) throw new Error(data.error || "Version check failed.");
  showVersion(data);
  return data;
}

function renderStatus(payload) {
  const update = payload.update || {};
  const gate = payload.gate || {};
  if (tip) tip.textContent = gate.detail || tip.textContent;
  if (payload.version) showVersion({ ...payload.version, bootId: payload.bootId || bootId });
  banner.textContent = update.updateAvailable ? update.message : "";
  banner.classList.toggle("hidden", !update.updateAvailable);
  button.disabled = busy || !payload.canApply;
  button.title = payload.canApply ? "Fast-forward origin/main, install dependencies if needed, and restart." : (payload.applyBlockReason || "");
  if (!busy) {
    const upToDate = gate.allowed && !update.updateAvailable && !update.error;
    const state = update.error ? "error" : (upToDate ? "ok" : "");
    setStatus(payload.canApply ? "Ready to update from this localhost session." : (payload.applyBlockReason || update.message || ""), state);
  }
}

async function loadUpdateStatus() {
  setStatus("Checking origin/main…");
  const response = await fetch("/api/app/update-status", { cache: "no-store" });
  const data = await readJson(response);
  if (!response.ok) throw new Error(data.error || "Update check failed.");
  renderStatus(data);
  return data;
}

async function waitForRestart(previousBootId) {
  const started = Date.now();
  while (Date.now() - started < 30000) {
    try {
      const response = await fetch("/api/app/version", { cache: "no-store" });
      if (response.ok) {
        const data = await readJson(response);
        if (data.bootId && data.bootId !== previousBootId) {
          window.location.reload();
          return;
        }
      }
    } catch {
      // The process is between shutdown and the replacement listen.
    }
    await delay(400);
  }
  throw new Error("The server did not come back. Start it again with npm start.");
}

async function applyUpdate() {
  if (busy || button.disabled) return;
  busy = true;
  button.disabled = true;
  setStatus("Updating… the server will restart and this page will reload.");
  const previousBootId = bootId;
  try {
    const response = await fetch("/api/app/update", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}"
    });
    const data = await readJson(response);
    if (!response.ok) throw new Error(data.error || "Update failed.");
    setStatus(data.message || "Restarting the local server…");
    await waitForRestart(data.bootId || previousBootId);
  } catch (error) {
    busy = false;
    setStatus(error.message, "error");
    try {
      await loadUpdateStatus();
    } catch {
      button.disabled = true;
    }
  }
}

async function init() {
  try {
    await loadVersion();
  } catch (error) {
    versionNode.textContent = "Version unavailable";
    setStatus(error.message, "error");
  }
  try {
    await loadUpdateStatus();
  } catch (error) {
    button.disabled = true;
    setStatus(error.message, "error");
  }
}

button?.addEventListener("click", () => {
  void applyUpdate();
});

void init();
