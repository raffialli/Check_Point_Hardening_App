import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import JSZip from "jszip";
import { collectPages, scopedCommandKey, collectionOutcome } from "./lib/collection.js";
import { pollScriptTasks } from "./lib/task-polling.js";
import { operationContext, beginOperation, finishOperation, assertNotCancelled, trackRequest } from "./lib/operations.js";
import { checkOwnerScope, withFindingIdentity } from "./public/finding-model.js";
const STANDARD_API_CONCURRENCY = positiveIntegerEnv("API_CONCURRENCY", 10);

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const PUBLIC_DIR = join(process.cwd(), "public");
const REPORT_BASE_PDF = process.env.REPORT_BASE_PDF || join(PUBLIC_DIR, "assets", "Hardening Report Base.pdf");
const REPORT_GENERATOR = join(process.cwd(), "scripts", "generate_report_pdf.mjs");
const REPORT_NODE = process.env.REPORT_NODE || process.execPath;
const PAGE_LIMIT = 500;
const RUN_SCRIPT_CONCURRENCY = positiveIntegerEnv("RUN_SCRIPT_CONCURRENCY", 8);
const LARGE_ENV_RUN_SCRIPT_CONCURRENCY = positiveIntegerEnv("LARGE_ENV_RUN_SCRIPT_CONCURRENCY", 3);
const LARGE_ENV_API_CONCURRENCY = positiveIntegerEnv("LARGE_ENV_API_CONCURRENCY", 10);
const LARGE_ENV_TASK_POLL_INTERVAL_MS = positiveIntegerEnv("LARGE_ENV_TASK_POLL_INTERVAL_MS", 1250);
const TASK_POLL_TIMEOUT_MS = positiveIntegerEnv("TASK_POLL_TIMEOUT_MS", 180_000);
const TASK_POLL_INTERVAL_MS = positiveIntegerEnv("TASK_POLL_INTERVAL_MS", 1000);
const TASK_POLL_MAX_INTERVAL_MS = positiveIntegerEnv("TASK_POLL_MAX_INTERVAL_MS", 4000);
const CP_API_TIMEOUT_MS = positiveIntegerEnv("CP_API_TIMEOUT_MS", 45_000);
const CP_SIC_TEST_TIMEOUT_MS = positiveIntegerEnv("CP_SIC_TEST_TIMEOUT_MS", 120_000);
const SIC_TEST_CONCURRENCY = positiveIntegerEnv("SIC_TEST_CONCURRENCY", 8);
const LARGE_ENV_SIC_TEST_CONCURRENCY = positiveIntegerEnv("LARGE_ENV_SIC_TEST_CONCURRENCY", 4);
const CP_LOG_API_TIMEOUT_MS = positiveIntegerEnv("CP_LOG_API_TIMEOUT_MS", 120_000);
const CP_VPN_API_TIMEOUT_MS = positiveIntegerEnv("CP_VPN_API_TIMEOUT_MS", 120_000);
const VPN_COMMUNITY_PAGE_LIMIT = positiveIntegerEnv("VPN_COMMUNITY_PAGE_LIMIT", 50);
const SHOW_LOGS_CONCURRENCY = positiveIntegerEnv("SHOW_LOGS_CONCURRENCY", 1);
const CP_API_LOGGING = /^(1|true|yes)$/i.test(process.env.CP_API_LOGGING || "");
const HARDENING_GUIDE_URL = "https://sc1.checkpoint.com/documents/Check_Point_Gateway_and_Management_Hardening/CP_Check_Point_Gateway_and_Management_Hardening.pdf";
const CVE_IKE_DESIRED_METHOD = "ike_v2_only";
const CVE_LEGACY_CLIENT_DISABLED = "true";
const GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE = "Management was unable to access to Gateway. Please check connectivity and scan again";
const sessions = new Map();
const appHistory = {
  reviews: new Map()
};

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8"
};

function positiveIntegerEnv(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function createLimiter(limit) {
  let active = 0;
  const queue = [];

  function runNext() {
    if (active >= limit || !queue.length) return;
    const item = queue.shift();
    active += 1;
    Promise.resolve()
      .then(item.fn)
      .then(item.resolve, item.reject)
      .finally(() => {
        active -= 1;
        runNext();
      });
  }

  return (fn) => new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject });
    runNext();
  });
}

const runScriptQueue = createLimiter(RUN_SCRIPT_CONCURRENCY);
const largeEnvRunScriptQueue = createLimiter(LARGE_ENV_RUN_SCRIPT_CONCURRENCY);
const showLogsQueue = createLimiter(SHOW_LOGS_CONCURRENCY);
const SCAN_CACHEABLE_COMMANDS = new Set([
  "show-access-rule",
  "show-access-rulebase",
  "show-generic-object",
  "show-logs",
  "show-nat-rulebase",
  "show-software-packages-per-targets",
  "where-used"
]);

function log(message, details = {}) {
  const parts = Object.entries(details)
    .filter(([, value]) => value !== undefined && value !== "")
    .map(([key, value]) => `${key}=${value}`);
  console.log(`[${new Date().toISOString()}] ${message}${parts.length ? ` ${parts.join(" ")}` : ""}`);
}

function compactAuditDetails(details) {
  if (!details) {
    return "";
  }
  if (typeof details === "string") {
    return details;
  }
  const text = JSON.stringify(details);
  return text.length > 800 ? `${text.slice(0, 797)}...` : text;
}

function compactLookupErrors(errors = []) {
  const items = (Array.isArray(errors) ? errors : []).map((item) => {
    const rawError = item?.error || item;
    const message = rawError?.message || rawError?.error || rawError?.code || String(rawError || "");
    return {
      gateway: item?.gateway || "",
      target: item?.target || "",
      group: item?.group || "",
      layer: item?.layer || "",
      ruleNumber: item?.ruleNumber || "",
      rulebase: item?.rulebase || "",
      object: item?.object || "",
      error: message
    };
  }).filter((item) => Object.values(item).some(Boolean));
  return {
    error: `${items.length} lookup error${items.length === 1 ? "" : "s"}`,
    errors: items
  };
}

function auditUser(session) {
  return session?.user || "Unknown";
}

function addAuditEntry({ session, action, status = "success", command = "", target = "", details = "" }) {
  return null;
}

function recordCheckChange(session, checkId, message) {
  return null;
}

function auditEntries() {
  return [];
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body)
  });
  res.end(body);
}

function runProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd || process.cwd(),
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      reject(new Error(`${command} exited with code ${code}: ${stderr || stdout || "No output"}`));
    });
  });
}

async function generateHardeningReportPdfFromScan(scan, reportLayout = "category") {
  if (!scan?.checks?.length) {
    throw enrichError(new Error("Run a scan before exporting a PDF report."), {
      phase: "report-scan"
    });
  }
  if (!existsSync(REPORT_GENERATOR)) {
    throw enrichError(new Error("Report generator script was not found."), {
      phase: "report-generator"
    });
  }
  const workingDir = await mkdtemp(join(tmpdir(), "cpbps-report-"));
  const scanPath = join(workingDir, "scan.json");
  const outputPath = join(workingDir, "hardening-report.pdf");
  try {
    await writeFile(scanPath, JSON.stringify({ ...scan, reportLayout: reportLayout === "infrastructure" ? "infrastructure" : "category" }), "utf8");
    await runProcess(REPORT_NODE, [
      REPORT_GENERATOR,
      "--scan-json",
      scanPath,
      "--base-pdf",
      REPORT_BASE_PDF,
      "--output",
      outputPath
    ]);
    return {
      file: await readFile(outputPath),
      cleanup: () => rm(workingDir, { recursive: true, force: true })
    };
  } catch (error) {
    await rm(workingDir, { recursive: true, force: true });
    throw enrichError(error, {
      phase: "report-generation",
      command: `${REPORT_NODE} ${REPORT_GENERATOR}`
    });
  }
}

async function generateHardeningReportPdf(session, reportLayout = "category") {
  return generateHardeningReportPdfFromScan(session.lastHardeningScan, reportLayout);
}

function safeReportFilename(value) {
  return String(value || "domain")
    .normalize("NFKD")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 100) || "domain";
}

function customerReportPrefix(value) {
  return String(value || "").trim() ? `${safeReportFilename(value)}-` : "";
}

function singleReportFilename(scan = {}, reportLayout = "category") {
  const customerPrefix = customerReportPrefix(scan.customerName);
  const domainName = String(scan.reportDomainName || "").trim();
  const layoutSuffix = reportLayout === "infrastructure" ? "infrastructure" : "category";
  return domainName
    ? `${customerPrefix}${safeReportFilename(domainName)}-${layoutSuffix}-hardening-report.pdf`
    : `${customerPrefix}check-point-best-practices-${layoutSuffix}-hardening-report.pdf`;
}

async function generateMoraDomainReportsZip(session, reportLayout = "category") {
  const scan = session.lastHardeningScan;
  const domains = Array.isArray(scan?.domains) ? scan.domains.filter((domain) => domain.scan?.checks?.length) : [];
  if (!scan?.moraMode || !domains.length) {
    throw enrichError(new Error("Run a successful all-domain MDS scan before exporting domain reports."), {
      phase: "report-scan"
    });
  }
  const zip = new JSZip();
  const customerPrefix = customerReportPrefix(scan.customerName);
  for (const domain of domains) {
    const report = await generateHardeningReportPdfFromScan({
      ...domain.scan,
      reportDomainName: domain.name
    }, reportLayout);
    try {
      zip.file(singleReportFilename({ ...domain.scan, customerName: scan.customerName, reportDomainName: domain.name }, reportLayout), report.file);
    } finally {
      await report.cleanup();
    }
  }
  return zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE", compressionOptions: { level: 6 } });
}

function enrichError(error, details) {
  Object.assign(error, details);
  return error;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error("Request body is too large."));
      }
    });
    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        const preview = body.replace(/\s+/g, " ").trim().slice(0, 300);
        reject(enrichError(new Error("Request body must be valid JSON."), {
          phase: "request-body-parse",
          contentType: req.headers["content-type"] || "",
          bodyPreview: preview || "empty response body"
        }));
      }
    });
    req.on("error", reject);
  });
}

function normalizeApiBasePath(pathname, smart1Cloud = false) {
  let path = String(pathname || "").trim();
  if (!path || path === "/") {
    return smart1Cloud ? "/web_api" : "";
  }
  path = path.replace(/\/+/g, "/").replace(/\/$/, "");
  path = path.replace(/\/web-api$/i, "/web_api");
  if (smart1Cloud && !/\/web_api$/i.test(path)) {
    path = `${path}/web_api`;
  }
  return path;
}

function normalizeBaseUrl(host, port, options = {}) {
  const trimmed = String(host || "").trim();
  if (!trimmed) {
    throw new Error("Management server host is required.");
  }
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const url = new URL(withProtocol);
  if (port) {
    url.port = String(port);
  }
  url.pathname = normalizeApiBasePath(url.pathname, options.smart1Cloud);
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

function cpApiUrl(session, command) {
  const url = new URL(session.baseUrl);
  const basePath = normalizeApiBasePath(url.pathname, session.smart1Cloud);
  url.pathname = `${basePath || "/web_api"}/${command}`.replace(/\/+/g, "/");
  url.search = "";
  url.hash = "";
  return url;
}

function sanitizeCommandPayload(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeCommandPayload(item));
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const sanitized = {};
  for (const [key, item] of Object.entries(value)) {
    if (["password", "api-key", "sid"].includes(String(key).toLowerCase())) {
      sanitized[key] = "[redacted]";
    } else {
      sanitized[key] = sanitizeCommandPayload(item);
    }
  }
  return sanitized;
}

function recordScanCommand(session, entry) {
  if (!Array.isArray(session?.scanCommandLog)) {
    return;
  }
  const commandEntry = {
    timestamp: new Date().toISOString(),
    ...entry
  };
  session.scanCommandLog.push(commandEntry);
  if (session.scanProgress) {
    session.scanProgress.steps.push({
      timestamp: commandEntry.timestamp,
      command: commandEntry.command,
      status: commandEntry.status,
      target: commandEntry.target,
      phase: commandEntry.phase,
      statusCode: commandEntry.statusCode,
      durationMs: commandEntry.durationMs,
      error: commandEntry.error
    });
    session.scanProgress.completedSteps = session.scanProgress.steps.length;
    session.scanProgress.currentStep = commandEntry.command;
    session.scanProgress.percent = Math.min(95, Math.max(8, Math.round(session.scanProgress.completedSteps * 3.5)));
  }
  const mora = session?.moraProgress;
  if (mora?.parent?.scanProgress) {
    const childPercent = Number(session.scanProgress?.percent || 0);
    const overallPercent = Math.min(99, Math.round(((mora.index + childPercent / 100) / mora.total) * 100));
    mora.parent.scanProgress.steps.push({
      timestamp: commandEntry.timestamp,
      command: `${mora.domainName}: ${commandEntry.command}`,
      status: commandEntry.status,
      target: commandEntry.target,
      phase: commandEntry.phase,
      statusCode: commandEntry.statusCode,
      durationMs: commandEntry.durationMs,
      error: commandEntry.error
    });
    if (mora.parent.scanProgress.steps.length > 30) {
      mora.parent.scanProgress.steps.splice(0, mora.parent.scanProgress.steps.length - 30);
    }
    mora.parent.scanProgress.completedSteps += 1;
    mora.parent.scanProgress.currentStep = `Domain ${mora.index + 1} of ${mora.total}: ${mora.domainName} - ${commandEntry.command}`;
    mora.parent.scanProgress.currentDomain = mora.domainName;
    mora.parent.scanProgress.currentDomainIndex = mora.index + 1;
    mora.parent.scanProgress.totalDomains = mora.total;
    mora.parent.scanProgress.percent = overallPercent;
  }
}

function cpRequest(session, command, body = {}) {
  const operation = operationContext.getStore()?.operation;
  return trackRequest(operation, () => {
    const execute = () => { assertNotCancelled(operation); return cpRequestUnqueued(session, command, body); };
    if (command === "show-logs") return showLogsQueue(execute);
    if (session?.scanApiQueue && command !== "login") return session.scanApiQueue(execute);
    return execute();
  });
}

function cpRequestUnqueued(session, command, body = {}) {
  return new Promise((resolve, reject) => {
    const url = cpApiUrl(session, command);
    const transport = url.protocol === "http:" ? httpRequest : httpsRequest;
    const payload = JSON.stringify(body);
    const startedAt = Date.now();
    const target = `${url.origin}${url.pathname}`;
    const headers = {
      "content-type": "application/json",
      "accept": "application/json",
      "content-length": Buffer.byteLength(payload)
    };
    if (session.sid) {
      headers["X-chkp-sid"] = session.sid;
    }

    const requestOptions = { method: "POST", headers };
    if (url.protocol === "https:") {
      requestOptions.rejectUnauthorized = session.rejectUnauthorized;
    }

    if (CP_API_LOGGING) {
      log("Check Point API request starting", {
        command,
        target
      });
    }

    const req = transport(url, requestOptions, (apiRes) => {
      let raw = "";
      apiRes.setEncoding("utf8");
      apiRes.on("data", (chunk) => {
        raw += chunk;
      });
      apiRes.on("end", () => {
        let parsed = {};
        if (raw) {
          try {
            parsed = JSON.parse(raw);
          } catch {
            const parsedError = enrichError(new Error(`Check Point returned non-JSON response from ${command}.`), {
              command,
              phase: "response-parse",
              target,
              statusCode: apiRes.statusCode
            });
            recordScanCommand(session, {
              command,
              target,
              body: sanitizeCommandPayload(body),
              status: "failed",
              phase: parsedError.phase,
              statusCode: parsedError.statusCode,
              durationMs: Date.now() - startedAt,
              error: parsedError.message,
              responsePreview: raw.slice(0, 1000)
            });
            reject(parsedError);
            return;
          }
        }
        if (apiRes.statusCode < 200 || apiRes.statusCode >= 300) {
          const message = parsed.message || parsed.errors?.[0]?.message || `${command} failed with HTTP ${apiRes.statusCode}.`;
          if (CP_API_LOGGING) {
            log("Check Point API request failed", { command, status: apiRes.statusCode });
          }
          const apiError = enrichError(new Error(message), {
            command,
            phase: "api-response",
            target,
            statusCode: apiRes.statusCode,
            response: parsed
          });
          recordScanCommand(session, {
            command,
            target,
            body: sanitizeCommandPayload(body),
            status: "failed",
            phase: apiError.phase,
            statusCode: apiError.statusCode,
            durationMs: Date.now() - startedAt,
            error: apiError.message,
            response: parsed
          });
          reject(apiError);
          return;
        }
        if (CP_API_LOGGING) {
          log("Check Point API request completed", { command, status: apiRes.statusCode });
        }
        recordScanCommand(session, {
          command,
          target,
          body: sanitizeCommandPayload(body),
          status: "ok",
          statusCode: apiRes.statusCode,
          durationMs: Date.now() - startedAt
        });
        resolve(parsed);
      });
    });

    const timeoutMs = command === "test-sic-status"
      ? CP_SIC_TEST_TIMEOUT_MS
      : command === "show-logs"
      ? CP_LOG_API_TIMEOUT_MS
      : (command === "show-vpn-communities-star" || command === "show-vpn-communities-meshed"
          ? CP_VPN_API_TIMEOUT_MS
          : CP_API_TIMEOUT_MS);
    req.setTimeout(timeoutMs, () => req.destroy(enrichError(new Error(`${command} timed out.`), {
      command,
      phase: "timeout",
      target: `${url.origin}${url.pathname}`
    })));
    req.on("error", (error) => {
      const socketError = enrichError(error, {
        command,
        phase: error.phase || "socket",
        target
      });
      recordScanCommand(session, {
        command,
        target,
        body: sanitizeCommandPayload(body),
        status: "failed",
        phase: socketError.phase,
        statusCode: socketError.statusCode,
        durationMs: Date.now() - startedAt,
        error: socketError.message
      });
      reject(socketError);
    });
    req.write(payload);
    req.end();
  });
}

function moraDomainIsActive(domain = {}) {
  if (domain.active === false) return false;
  if (domain.active === true) return true;
  const servers = Array.isArray(domain.servers) ? domain.servers : [];
  if (!servers.length) return true;
  return servers.some((server) => (
    server?.active === true ||
    normalizeToken(server?.status || server?.state || server?.role || "").includes("active")
  ));
}

async function discoverMoraDomains(session) {
  const objects = [];
  let offset = 0;
  while (true) {
    const page = await cpRequest(session, "show-domains", {
      offset,
      limit: PAGE_LIMIT,
      "details-level": "full"
    });
    const pageObjects = Array.isArray(page.objects) ? page.objects : [];
    objects.push(...pageObjects);
    offset += pageObjects.length;
    const total = Number(page.total || page["total-objects"] || objects.length);
    if (!pageObjects.length || pageObjects.length < PAGE_LIMIT || offset >= total) break;
  }
  return objects
    .filter((domain) => domain?.name && domain?.uid && moraDomainIsActive(domain))
    .map((domain) => ({
      name: String(domain.name),
      uid: String(domain.uid),
      servers: Array.isArray(domain.servers) ? domain.servers : []
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function login(payload) {
  const smart1Cloud = payload.smart1Cloud === true || payload.smart1Cloud === "true" || payload.smart1Cloud === "on";
  const baseUrl = normalizeBaseUrl(payload.host, payload.port, { smart1Cloud });
  const moraMode = payload.moraMode === true || payload.moraMode === "true" || payload.moraMode === "on";
  const mdsMode = moraMode || payload.mdsScan === true || payload.mdsScan === "true" || payload.mdsScan === "on" || Boolean(String(payload.managementObjectName || "").trim());
  if (moraMode && smart1Cloud) {
    throw new Error("All-domain scanning requires a Multi-Domain Server and cannot be used with Smart-1 Cloud.");
  }
  log("Login request received", {
    target: `${cpApiUrl({ baseUrl, smart1Cloud }, "login").origin}${cpApiUrl({ baseUrl, smart1Cloud }, "login").pathname}`,
    user: payload.username || "",
    domain: payload.domain || "",
    smart1Cloud,
    mdsMode,
    moraMode,
    managementObjectName: payload.managementObjectName || ""
  });
  const session = {
    baseUrl,
    rejectUnauthorized: !payload.ignoreTls,
    largeEnvironmentMode: payload.largeEnvironmentMode === true || payload.largeEnvironmentMode === "true" || payload.largeEnvironmentMode === "on",
    smart1Cloud,
    mdsMode,
    moraMode,
    domain: moraMode ? "" : String(payload.domain || "").trim(),
    managementObjectName: String(payload.managementObjectName || "").trim(),
    customerName: String(payload.customerName || "").replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, 160)
  };
  const authMode = payload.authMode === "api-key" ? "api-key" : "password";
  const loginBody = {};
  if (authMode === "api-key") {
    loginBody["api-key"] = String(payload.apiKey || "");
    if (!loginBody["api-key"]) {
      throw new Error("API key is required.");
    }
  } else {
    loginBody.user = String(payload.username || "");
    if (!loginBody.user) {
      throw new Error("Username is required.");
    }
    loginBody.password = String(payload.password || "");
    if (!loginBody.password) {
      throw new Error("Password is required.");
    }
  }
  if (payload.domain && !moraMode) {
    loginBody.domain = String(payload.domain);
  }
  const loginResult = await cpRequest(session, "login", loginBody);
  if (!loginResult.sid) {
    throw new Error(loginResult.message || "Login did not return a Check Point session ID.");
  }
  let mdsSid = "";
  let globalDomainSid = "";
  let globalDomainLoginError = null;
  if (mdsMode) {
    if (!payload.domain) {
      mdsSid = loginResult.sid;
    } else {
      const mdsLoginBody = {};
      if (authMode === "api-key") {
        mdsLoginBody["api-key"] = loginBody["api-key"];
      } else {
        mdsLoginBody.user = loginBody.user;
        mdsLoginBody.password = loginBody.password;
      }
      const mdsLogin = await cpRequest(session, "login", mdsLoginBody);
      mdsSid = mdsLogin.sid || "";
      if (!mdsSid) {
        throw new Error(mdsLogin.message || "MDS/global login did not return a Check Point session ID.");
      }
    }
    try {
      const globalLoginBody = {
        domain: "Global"
      };
      if (authMode === "api-key") {
        globalLoginBody["api-key"] = loginBody["api-key"];
      } else {
        globalLoginBody.user = loginBody.user;
        globalLoginBody.password = loginBody.password;
      }
      const globalLogin = await cpRequest(session, "login", globalLoginBody);
      globalDomainSid = globalLogin.sid || "";
      if (!globalDomainSid) {
        globalDomainLoginError = { error: globalLogin.message || "Global domain login did not return a session ID." };
      }
    } catch (error) {
      globalDomainLoginError = commandError(error);
    }
  }
  let systemDataSid = "";
  let systemDataLoginError = null;
  try {
    const systemDataLoginBody = {
      domain: "System Data"
    };
    if (authMode === "api-key") {
      systemDataLoginBody["api-key"] = loginBody["api-key"];
    } else {
      systemDataLoginBody.user = loginBody.user;
      systemDataLoginBody.password = loginBody.password;
    }
    const systemDataLogin = await cpRequest(session, "login", systemDataLoginBody);
    systemDataSid = systemDataLogin.sid || "";
    if (!systemDataSid) {
      systemDataLoginError = { error: systemDataLogin.message || "System Data login did not return a session ID." };
    }
  } catch (error) {
    systemDataLoginError = commandError(error);
  }
  let moraDomains = [];
  if (moraMode) {
    const inventorySession = { ...session, sid: mdsSid || loginResult.sid };
    const discoveredDomains = await discoverMoraDomains(inventorySession);
    if (!discoveredDomains.length) {
      throw new Error("The all-domain scan did not find any active MDS domains available to this administrator.");
    }
    for (const domain of discoveredDomains) {
      try {
        const domainLoginBody = { domain: domain.name };
        if (authMode === "api-key") {
          domainLoginBody["api-key"] = loginBody["api-key"];
        } else {
          domainLoginBody.user = loginBody.user;
          domainLoginBody.password = loginBody.password;
        }
        const domainLogin = await cpRequest(session, "login", domainLoginBody);
        moraDomains.push({ ...domain, sid: domainLogin.sid || "", loginError: domainLogin.sid ? null : { error: domainLogin.message || "Domain login did not return a session ID." } });
      } catch (error) {
        moraDomains.push({ ...domain, sid: "", loginError: commandError(error) });
      }
    }
  }
  const loginUser = loginBody.user || "API Key";
  const id = randomUUID();
  const rootSession = {
    id,
    ...session,
    sid: loginResult.sid,
    mdsSid,
    globalDomainSid,
    globalDomainLoginError,
    systemDataSid,
    systemDataLoginError,
    user: loginUser,
    largeEnvironmentMode: session.largeEnvironmentMode,
    smart1Cloud: session.smart1Cloud,
    mdsMode: session.mdsMode,
    moraMode,
    customerName: session.customerName,
    managementObjectName: session.managementObjectName,
    createdAt: Date.now(),
    lastHardeningScan: null
  };
  rootSession.moraDomains = moraDomains.map((domain, index) => ({
    name: domain.name,
    uid: domain.uid,
    servers: domain.servers,
    loginError: domain.loginError,
    session: domain.sid ? {
      ...rootSession,
      id: `${id}:domain:${index}`,
      sid: domain.sid,
      domain: domain.name,
      moraMode: true,
      moraRootSession: rootSession,
      moraDomains: undefined,
      lastHardeningScan: null
    } : null
  }));
  sessions.set(id, rootSession);
  return {
    sessionId: id,
    user: loginUser,
    baseUrl,
    largeEnvironmentMode: session.largeEnvironmentMode,
    smart1Cloud: session.smart1Cloud,
    mdsMode: session.mdsMode,
    moraMode,
    domains: rootSession.moraDomains.map((domain) => ({ name: domain.name, uid: domain.uid, available: Boolean(domain.session) })),
    managementObjectName: session.managementObjectName
  };
}

function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) {
    throw new Error("Session not found. Log in again.");
  }
  return session;
}

function commandError(error) {
  return {
    command: error.command,
    error: error.message,
    phase: error.phase,
    target: error.target,
    statusCode: error.statusCode,
    response: error.response
  };
}

function isExpiredSessionError(error) {
  const message = String(error?.message || "").toLowerCase();
  const statusCode = Number(error?.statusCode || 0);
  return (
    message.includes("wrong session id") ||
    message.includes("session not found") ||
    message.includes("log in again") ||
    message.includes("session may be expired") ||
    message.includes("session expired") ||
    message.includes("invalid session") ||
    (message.includes("session id") && message.includes("expired")) ||
    statusCode === 401 ||
    statusCode === 403
  );
}

async function tryCommand(session, command, body = {}) {
  assertNotCancelled(operationContext.getStore()?.operation);
  if (command === "show-access-rulebase" && body.offset === undefined) {
    return { command, ...await collectPages(
      page => tryCommand(session, command, { ...body, ...page }),
      { key: "rulebase", limit: PAGE_LIMIT }
    ) };
  }
  const cache = session.scanCommandCache;
  const cacheable = cache && SCAN_CACHEABLE_COMMANDS.has(command);
  const cacheKey = cacheable ? scopedCommandKey(session, command, body, stableJson) : "";
  if (cacheable && cache.has(cacheKey)) {
    return cache.get(cacheKey);
  }
  const lookup = (async () => {
    try {
      return { ok: true, command, data: await cpRequest(session, command, body) };
    } catch (error) {
      if (isExpiredSessionError(error) || error.code === "SCAN_CANCELLED") {
        throw error;
      }
      return { ok: false, command, error: commandError(error) };
    }
  })();
  if (cacheable) {
    cache.set(cacheKey, lookup);
  }
  return lookup;
}

async function listObjects(session, command, body = {}) {
  const result = await tryListObjects(session, command, body);
  if (!result.ok) throw Object.assign(new Error(result.error?.error || "Object collection incomplete."), result.error);
  return result.objects;
}

async function tryListObjects(session, command, body = {}) {
  const result = await collectPages(
    page => tryCommand(session, command, { "details-level": "full", ...body, ...page }),
    { limit: PAGE_LIMIT }
  );
  return { ...result, command, objects: result.data.objects || [] };
}

async function tryListSystemDataObjects(session, command, body = {}) {
  if (!session.systemDataSid) {
    return {
      ok: false,
      command,
      error: {
        command: "login",
        error: session.systemDataLoginError?.error || "System Data login is not available.",
        phase: session.systemDataLoginError?.phase || "system-data-login",
        target: session.systemDataLoginError?.target,
        statusCode: session.systemDataLoginError?.statusCode,
        response: session.systemDataLoginError?.response
      },
      objects: []
    };
  }

  return tryListObjects({
    baseUrl: session.baseUrl,
    rejectUnauthorized: session.rejectUnauthorized,
    sid: session.systemDataSid
  }, command, body);
}

async function trySystemDataCommand(session, command, body = {}) {
  if (!session.systemDataSid) {
    return {
      ok: false,
      command,
      error: {
        command: "login",
        error: session.systemDataLoginError?.error || "System Data login is not available.",
        phase: session.systemDataLoginError?.phase || "system-data-login",
        target: session.systemDataLoginError?.target,
        statusCode: session.systemDataLoginError?.statusCode,
        response: session.systemDataLoginError?.response
      }
    };
  }

  return tryCommand({
    baseUrl: session.baseUrl,
    rejectUnauthorized: session.rejectUnauthorized,
    sid: session.systemDataSid
  }, command, body);
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => value !== undefined && value !== null && String(value).trim() !== "").map(String))];
}

function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function normalizeToken(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function flattenValues(value, path = "", matches = []) {
  if (matches.length >= 1000) return matches;
  if (Array.isArray(value)) {
    value.forEach((item, index) => flattenValues(item, `${path}[${index}]`, matches));
    return matches;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      flattenValues(child, path ? `${path}.${key}` : key, matches);
      if (matches.length >= 1000) break;
    }
    return matches;
  }
  matches.push({ path, value });
  return matches;
}

function matchingEvidence(value, predicate, limit = 12) {
  return flattenValues(value)
    .filter(({ path, value: itemValue }) => predicate(path, itemValue))
    .slice(0, limit)
    .map(({ path, value }) => ({ path, value: value === "" ? "(empty)" : String(value) }));
}

function evidenceText(items) {
  if (!items.length) return "";
  return items.map((item) => `${item.path}: ${item.value}`).join(" | ");
}

function displaySettingValue(value) {
  if (value === undefined || value === null) {
    return "Not returned";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function enabledDisabledValue(value) {
  if (value === true || normalizeToken(value) === "true") {
    return "Enabled";
  }
  if (value === false || normalizeToken(value) === "false") {
    return "Disabled";
  }
  return displaySettingValue(value);
}

function isPositionSetting(key) {
  return /(^|-)position$/i.test(String(key || ""));
}

function positionForSetting(settings, key) {
  const candidates = [
    `${key}-position`,
    `${key}-rule-position`,
    `${key.replace(/-rule$/i, "")}-position`
  ];
  for (const candidate of candidates) {
    if (Object.hasOwn(settings, candidate)) {
      return displaySettingValue(settings[candidate]);
    }
  }
  return "";
}

function impliedRuleDescription(key) {
  const token = normalizeToken(key);
  const hasAll = (...parts) => parts.every((part) => token.includes(part));
  if (hasAll("outgoing", "connectra")) {
    return "Legacy rule permitting traffic from older Connectra SSL VPN appliances.";
  }
  if (hasAll("outgoing", "checkpoint") || hasAll("outgoing", "online") || hasAll("outgoing", "services")) {
    return "Allows direct outbound access to ThreatCloud, URL Filtering, and updates.";
  }
  if (hasAll("outgoing", "gateway") || hasAll("outgoing", "gw") || hasAll("outgoing", "originating") || hasAll("outgoing", "firewall")) {
    return "Allows the firewall itself to initiate traffic (NTP, DNS, routing).";
  }
  if (hasAll("dynamic", "address") || hasAll("dynamic", "addr") || hasAll("address", "module") || hasAll("addr", "module") || token.includes("dynaddr") || token.includes("daip")) {
    return "Allows DAIP gateways to connect to the internet/management to update IPs.";
  }
  const descriptions = [
    [["acceptcontrolconnections"], "Permits Management Server to Gateway communications (CPD, policy, logs)."],
    [["acceptremoteaccesscontrolconnections"], "Allows VPN tunnel establishment, authentication, and IKE/IPsec traffic."],
    [["acceptsmartupdateconnections"], "Permits license, contract, and software upgrade management."],
    [["acceptips1managementconnections", "acceptipsmanagementconnections"], "Allows communication and log shipping for dedicated IPS-1 sensors."],
    [["acceptoutgoingpacketsoriginatingfromgateway", "acceptoutgoingpacketsfromgateway"], "Allows the firewall itself to initiate traffic (NTP, DNS, routing)."],
    [["acceptoutgoingpacketsoriginatingfromconnectragateway", "acceptoutgoingpacketsfromconnectragateway"], "Legacy rule permitting traffic from older Connectra SSL VPN appliances."],
    [["acceptoutgoingpacketstocheckpointonlineservices"], "Allows direct outbound access to ThreatCloud, URL Filtering, and updates."],
    [["acceptrip"], "Permits RIP routing protocol updates (UDP 520)."],
    [["acceptdomainnameoverudpqueries", "acceptdomainnameoverudp"], "Permits standard DNS lookups (UDP 53) through the firewall."],
    [["acceptdomainnameovertcpzonetransfer", "acceptdomainnameovertcp"], "Permits DNS zone transfers and large queries (TCP 53)."],
    [["accepticmprequests"], "Permits diagnostic traffic like ping and traceroute."],
    [["acceptwebandsshconnections", "acceptwebsshconnections"], "Allows local web GUI and CLI administration for SMB/Spark appliances."],
    [["acceptincomingtraffictodhcpanddns", "acceptdhcpanddns"], "Allows local clients to use the SMB gateway as a DHCP or DNS server."],
    [["acceptdynamicaddressmodules", "acceptdaipmodules"], "Allows DAIP gateways to connect to the internet/management to update IPs."],
    [["acceptvrrppackets", "acceptvsxipsovrrp"], "Permits VRRP clustering heartbeats to maintain high-availability states."],
    [["acceptidentityawarenesscontrolconnections"], "Allows sharing of user/machine identity data (AD Query, Agents)."],
    [["logimpliedrules"], "Logs traffic accepted by implied rules for auditability and troubleshooting."]
  ];
  const match = descriptions.find(([tokens]) => tokens.some((candidate) => token.includes(candidate)));
  return match ? match[1] : "";
}

function makeCheck({ id, category, title, recommendation, recommendationWarning = "", status, severity = "medium", evidence = "", evidenceTone = "", evidenceTable = null, evidenceTables = null, details = "", detailsLink = null, detailsWarning = "", detailRows = null, specialConsiderations = null, source = "", commands = [], remediation = null, detailTone = "", review = null, hideBadges = false }) {
  return {
    id,
    category,
    title,
    recommendation,
    recommendationWarning,
    status,
    severity,
    evidence,
    evidenceTone,
    evidenceTable,
    evidenceTables,
    details,
    detailsLink,
    detailsWarning,
    detailRows,
    specialConsiderations,
    source,
    commands,
    remediation,
    detailTone,
    review,
    hideBadges,
    ownership: { scope: checkOwnerScope({ id }) },
    evaluationStatus: status,
    collection: { status: "not-reported", errors: [] }
  };
}

function formatDateTime(value) {
  const isoValue = typeof value === "string" ? value : value?.["iso-8601"];
  if (!isoValue) return "Never";
  const normalized = String(isoValue).replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return String(isoValue);
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short"
  }).format(date);
}

function onOff(value) {
  if (value === true) return "On";
  if (value === false) return "Off";
  return value === undefined || value === null ? "" : String(value);
}

function settingRow(setting, value, state = "") {
  return {
    "Setting": setting,
    "Value": value === undefined || value === null || value === "" ? "Not returned" : String(value),
    "State": state
  };
}

function getByNormalizedKey(source, ...keys) {
  if (!source || typeof source !== "object") return undefined;
  const normalizedTargets = new Set(keys.map(normalizeToken));
  const match = Object.entries(source).find(([key]) => normalizedTargets.has(normalizeToken(key)));
  return match ? match[1] : undefined;
}

function defaultExpirationState(data) {
  const expirationType = normalizeToken(data["expiration-type"]);
  if (expirationType === "never") {
    return "Check Point recommends setting expiration at minimum quarterly (4 months).";
  }
  if (expirationType === "expirationdate") {
    return formatDateTime(getByNormalizedKey(data, "expiration-date", "expiration date"));
  }
  if (expirationType === "expirationperiod") {
    return [
      getByNormalizedKey(data, "expiration-period", "expiration period"),
      getByNormalizedKey(data, "expiration-period-time-units", "expiration period time units", "expiration-period-time-unit")
    ].filter((value) => value !== undefined && value !== null && value !== "").join(" ");
  }
  return "";
}

function trustedClientIpData(client) {
  const type = String(client.type || client.TYPE || "").toLowerCase();
  if (type === "ipv4 address") {
    return client["ipv4-address"] || "";
  }
  if (type === "ipv4 netmask") {
    return [client["ipv4-address"], client["subnet-mask4"]].filter(Boolean).join(" / ");
  }
  if (type === "ipv4 address range") {
    return [client["ipv4-address-first"], client["ipv4-address-last"]].filter(Boolean).join(" - ");
  }
  if (type === "wild cards (ip only)") {
    return client["wild-card"] || "";
  }
  if (type === "any") {
    return "Any IP address";
  }
  return "";
}

function trustedClientRows(clients = [], selectable = false) {
  return clients.map((client) => ({
    ...(selectable ? {
      "_select": client.uid ? {
        value: client.uid,
        label: client.name || client.NAME || client.uid
      } : null
    } : {}),
    "Name": client.name || client.NAME || "",
    "Type": client.type || client.TYPE || "",
    "IP Data": trustedClientIpData(client)
  }));
}

function evaluateTrustedClients(result, session) {
  const source = "Hardening guide: Limit SmartConsole Trusted Client Access settings";
  if (!result.ok) {
    return makeCheck({
      id: "mgmt.trusted-clients",
      category: "Administrator Identity and Access Control",
      title: "Restrict SmartConsole Trusted Clients",
      recommendation: "Limit SmartConsole trusted client access to the necessary IP addresses, subnets, and ranges.",
      status: "unknown",
      evidence: "Trusted client data could not be retrieved from System Data.",
      details: result.error?.error || "",
      source,
      commands: [result.command]
    });
  }

  const clients = result.objects || [];
  const names = uniqueStrings(clients.map((client) => client.name || client.NAME));
  const output = clients
    .map((client) => `${client.name || client.NAME || "(unnamed)"} (${client.type || client.TYPE || "unknown"})`)
    .join(", ");
  const rows = trustedClientRows(clients, true);
  const anyClients = clients.filter((client) => String(client.type || client.TYPE || "").toLowerCase() === "any");
  const anyClientNames = uniqueStrings(anyClients.map((client) => client.name || client.NAME));
  const allowsAny = anyClientNames.length > 0;
  const anyIsOnlyTrustedClient = allowsAny
    && clients.every((client) => String(client.type || client.TYPE || "").toLowerCase() === "any");
  const noOutput = !names.length;
  const reviewHistory = appHistory.reviews.get("mgmt.trusted-clients") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  return makeCheck({
    id: "mgmt.trusted-clients",
    category: "Administrator Identity and Access Control",
    title: "Restrict SmartConsole Trusted Clients",
    recommendation: "Limit SmartConsole trusted client access to the necessary IP addresses, subnets, and ranges.",
    status: noOutput ? "unknown" : (allowsAny ? "remediation-required" : (reviewedThisLogin ? "reviewed" : "needs-review")),
    severity: allowsAny ? "high" : "medium",
    evidence: noOutput ? "No trusted client names were returned." : `Trusted clients: ${output}`,
    evidenceTable: rows.length ? {
      selectable: true,
      selectionName: "trusted-client",
      columns: ["Name", "Type", "IP Data"],
      rows
    } : null,
    details: allowsAny
      ? `Your management server allows access from ANY IP address through trusted client ${anyClientNames.join(", ")}. This is a major security concern and should immediately be limited to restricted IPs.`
      : "Trusted client names were returned from System Data. Review each name to confirm access is limited to approved administrative sources.",
    detailTone: allowsAny ? "critical" : "",
    source,
    commands: [`${result.command}: name,type`],
    remediation: allowsAny ? {
      action: "remove-any-trusted-client",
      label: `Remove ${anyClientNames.join(", ")} now`,
      command: "delete-trusted-client",
      target: anyClientNames[0],
      lockoutRisk: anyIsOnlyTrustedClient
    } : null,
    review: !allowsAny && !noOutput ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateManagementApiAccess(apiSettings, trustedClients, session) {
  const source = "Hardening guide: Management API Access";
  const reviewHistory = appHistory.reviews.get("mgmt.api-access") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  if (!apiSettings.ok) {
    return makeCheck({
      id: "mgmt.api-access",
      category: "Administrator Identity and Access Control",
      title: "Management API Access",
      recommendation: "Check Point Recommends limiting access to \"All IP addresses that can be used for GUI clients\".",
      status: "unknown",
      evidence: "API settings could not be retrieved from System Data.",
      details: apiSettings.error?.error || "",
      source,
      commands: [apiSettings.command]
    });
  }

  const acceptedFrom = apiSettings.data?.["accepted-api-calls-from"] || "Not returned";
  const acceptedToken = normalizeToken(acceptedFrom);
  const allowsAny = acceptedToken === "allipaddresses";
  const usesGuiClients = acceptedToken === "allipaddressesthatcanbeusedforguiclients";
  const rows = usesGuiClients && trustedClients.ok
    ? trustedClientRows(trustedClients.objects || [])
    : [{
      "Setting": "accepted-api-calls-from",
      "Value": acceptedFrom
    }];

  return makeCheck({
    id: "mgmt.api-access",
    category: "Administrator Identity and Access Control",
    title: "Management API Access",
    recommendation: "Check Point Recommends limiting access to \"All IP addresses that can be used for GUI clients\".",
    status: allowsAny ? "remediation-required" : (reviewedThisLogin ? "reviewed" : "needs-review"),
    severity: allowsAny ? "high" : "medium",
    evidence: `accepted-api-calls-from: ${acceptedFrom}`,
    evidenceTable: rows.length ? {
      columns: usesGuiClients && trustedClients.ok ? ["Name", "Type", "IP Data"] : ["Setting", "Value"],
      rows
    } : null,
    details: allowsAny
      ? "You are currently allowing API access from ANY IP address. Check Point recommends immediately setting this to match the GUI clients list or Manager Only."
      : (usesGuiClients
        ? "Trusted client names were returned from System Data. Review each name to confirm access is limited to approved administrative sources."
        : "Review the accepted API access setting against your administrative access policy."),
    detailTone: allowsAny ? "critical" : "",
    source,
    commands: [
      "show-api-settings: accepted-api-calls-from",
      ...(usesGuiClients ? ["show-trusted-clients: name,type"] : [])
    ],
    remediation: allowsAny ? {
      action: "set-api-clients-gui-clients",
      label: "Set API Clients to match GUI Clients",
      command: "set-api-settings",
      target: "all ip addresses that can be used for gui clients"
    } : null,
    review: {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    }
  });
}

async function administratorLastLogin(session, username) {
  const cacheKey = normalizeToken(username);
  if (!session.adminLastLoginCache) {
    session.adminLastLoginCache = new Map();
  }
  if (cacheKey && session.adminLastLoginCache.has(cacheKey)) {
    return session.adminLastLoginCache.get(cacheKey);
  }
  const lookup = (async () => {
    const filter = `administrator:${username} AND SmartConsole AND "Log In"`;
    const logResult = await tryCommand(session, "show-logs", {
      "new-query": {
        type: "audit",
        "time-frame": "last-30-days",
        "max-logs-per-request": 1,
        filter
      }
    });
    if (!logResult.ok) {
      return {
        ok: true,
        value: "Audit log lookup unavailable",
        error: logResult.error
      };
    }
    const logTime = logResult.data?.logs?.[0]?.time;
    const logClientIp = logResult.data?.logs?.[0]?.client_ip || logResult.data?.logs?.[0]?.machine || "";
    return {
      ok: true,
      value: logTime ? formatDateTime(logTime) : "No audit log in last 30 days",
      ip: logTime ? (logClientIp || "Not returned") : "N/A"
    };
  })();
  if (cacheKey) {
    session.adminLastLoginCache.set(cacheKey, lookup);
  }
  return lookup;
}

function adminReviewRecommendationWarnings(noRecentLoginNames = [], neverExpirationNames = []) {
  return [
    noRecentLoginNames.length
      ? `The following admins ${noRecentLoginNames.join(", ")} have not logged in in the last 30 days and we recommend deleting the administrator account.`
      : "",
    neverExpirationNames.length
      ? `The following admins ${neverExpirationNames.join(", ")} have no expiration date set. Check Point Recommends administrator accounts expire every 4 months minimum and are reviewed and renewed.`
      : ""
  ].filter(Boolean);
}

function adminExpirationIsNever(admin) {
  return formatDateTime(admin?.["expiration-date"] || admin?.expirationDate) === "Never";
}

function dateFourMonthsFromNow() {
  const date = new Date();
  date.setMonth(date.getMonth() + 4);
  return date.toISOString().slice(0, 10);
}

async function evaluateAdministratorApiKeyAuthentication(result, session) {
  const source = "Hardening guide: Management API Access";
  const reviewHistory = appHistory.reviews.get("admin.api-key-authentication") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const recommendation = "Scope API credentials / tokens to the minimum required roles and APIs. Limit API keys for a duration of two months and do not store these in clear-text file repositories.";
  const details = "Broad API permissions can allow unintended configuration changes if the token is exposed.";
  if (!result.ok) {
    return makeCheck({
      id: "admin.api-key-authentication",
      category: "Administrator Identity and Access Control",
      title: "Administrator Account With API Key Authentication",
      recommendation,
      status: "unknown",
      evidence: "Administrator account data could not be retrieved.",
      details: result.error?.error || "",
      source,
      commands: [result.command]
    });
  }

  const apiKeyAdmins = (result.objects || []).filter((admin) => {
    const method = admin["authentication-method"] || admin.authenticationMethod || "";
    return normalizeToken(method) === "apikey";
  });
  let lastLoginLookupFailed = false;
  const noRecentLoginNames = [];
  const neverExpirationNames = [];
  const rows = await Promise.all(apiKeyAdmins.map(async (admin) => {
    const username = admin.name || admin.NAME || "";
    const lastLogin = username ? await administratorLastLogin(session, username) : { ok: true, value: "Not returned", ip: "Not returned" };
    if (!lastLogin.ok) {
      lastLoginLookupFailed = true;
    }
    const expirationDate = formatDateTime(admin["expiration-date"] || admin.expirationDate);
    if (lastLogin.value === "No audit log in last 30 days") {
      noRecentLoginNames.push(username);
    }
    if (adminExpirationIsNever(admin)) {
      neverExpirationNames.push(username);
    }
    return {
      "_select": admin.uid ? {
        value: admin.uid,
        label: username || admin.uid
      } : null,
      "Username": username,
      "Permission Profile": admin["permissions-profile"]?.name || admin.permissionsProfile?.name || "",
      "Authentication-Method": admin["authentication-method"] || admin.authenticationMethod || "",
      "Expiration Date": expirationDate,
      "Last Login": lastLogin.value,
      "Last Login IP": lastLogin.ip || "Not returned"
    };
  }));
  const recommendationWarnings = adminReviewRecommendationWarnings(noRecentLoginNames, neverExpirationNames);
  const remediationRecommended = recommendationWarnings.length > 0;

  return makeCheck({
    id: "admin.api-key-authentication",
    category: "Administrator Identity and Access Control",
    title: "Administrator Account With API Key Authentication",
    recommendation,
    recommendationWarning: recommendationWarnings,
    status: reviewedThisLogin ? "reviewed" : (remediationRecommended ? "remediation-recommended" : "needs-review"),
    severity: remediationRecommended ? "high" : "medium",
    evidence: rows.length
      ? `${rows.length} administrator account${rows.length === 1 ? "" : "s"} using API key authentication returned.`
      : "No administrator accounts using API key authentication were returned.",
    evidenceTable: rows.length ? {
      selectable: true,
      selectionName: "administrator",
      columns: ["Username", "Permission Profile", "Authentication-Method", "Expiration Date", "Last Login", "Last Login IP"],
      rows
    } : null,
    details: lastLoginLookupFailed ? `${details} One or more last login audit log lookups failed.` : details,
    source,
    commands: [
      `${result.command}: name,permissions-profile,authentication-method,expiration-date`,
      ...(rows.length ? ["show-logs: new-query.type audit,new-query.time-frame last-30-days,new-query.filter administrator:ADMIN_USERNAME AND SmartConsole AND \"Log In\": time,client_ip"] : [])
    ],
    remediation: neverExpirationNames.length ? {
      action: "set-admin-expiration-four-months",
      label: "Set 4 Month Expiration for Administrator",
      command: "set-administrator",
      target: neverExpirationNames.join(", ")
    } : null,
    review: {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    }
  });
}

async function evaluateAdministrators(result, session) {
  const source = "Hardening guide: Review administrator accounts, password policy, and idle timeout";
  if (!result.ok) {
    return [
      makeCheck({
        id: "admin.accounts",
        category: "Administrator Identity and Access Control",
        title: "Review Administrator Accounts",
        recommendation: "Review administrator accounts quarterly, remove unused accounts, and avoid shared administrator accounts.",
        status: "unknown",
        evidence: "Administrator account data could not be retrieved.",
        details: result.error?.error || "",
        source,
        commands: [result.command]
      })
    ];
  }

  const admins = result.objects || [];
  const names = uniqueStrings(admins.map((admin) => admin.name || admin.NAME));
  const likelyShared = names.filter((name) => /shared|operator|support|test|temp/i.test(name));
  const reviewHistory = appHistory.reviews.get("admin.accounts") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  let lastLoginLookupFailed = false;
  const noRecentLoginNames = [];
  const neverExpirationNames = [];
  const rows = await Promise.all(admins.map(async (admin) => {
    const name = admin.name || admin.NAME || "";
    const lastLogin = name ? await administratorLastLogin(session, name) : { ok: true, value: "Not returned", ip: "Not returned" };
    if (!lastLogin.ok) {
      lastLoginLookupFailed = true;
    }
    const expirationDate = formatDateTime(admin["expiration-date"] || admin.expirationDate);
    if (lastLogin.value === "No audit log in last 30 days") {
      noRecentLoginNames.push(name);
    }
    if (adminExpirationIsNever(admin)) {
      neverExpirationNames.push(name);
    }
    return {
      "_select": admin.uid ? {
        value: admin.uid,
        label: admin.name || admin.NAME || admin.uid
      } : null,
      "Name": name,
      "Permission Profile Name": admin["permissions-profile"]?.name || admin.permissionsProfile?.name || "",
      "Authentication-Method": admin["authentication-method"] || admin.authenticationMethod || "",
      "expiration-date": expirationDate,
      "Last Login": lastLogin.value,
      "Last Login IP": lastLogin.ip || "Not returned"
    };
  }));
  const recommendationWarnings = adminReviewRecommendationWarnings(noRecentLoginNames, neverExpirationNames);
  const remediationRecommended = recommendationWarnings.length > 0;

  return [
    makeCheck({
      id: "admin.accounts",
      category: "Administrator Identity and Access Control",
      title: "Review Administrator Accounts",
      recommendation: "Remove or disable unused administrator accounts and avoid shared accounts.",
      recommendationWarning: recommendationWarnings,
      status: names.length ? (reviewedThisLogin ? "reviewed" : (remediationRecommended ? "remediation-recommended" : "needs-review")) : "unknown",
      severity: remediationRecommended ? "high" : "medium",
      evidence: names.length
        ? `${names.length} administrator account${names.length === 1 ? "" : "s"} returned.`
        : "No administrator names were returned.",
      evidenceTable: rows.length ? {
        selectable: true,
        selectionName: "administrator",
        columns: ["Name", "Permission Profile Name", "Authentication-Method", "expiration-date", "Last Login", "Last Login IP"],
        rows
      } : null,
      details: likelyShared.length
        ? `Names that may need review: ${likelyShared.join(", ")}${lastLoginLookupFailed ? " One or more last login audit log lookups failed." : ""}`
        : `Review each returned name for ownership, current use, and whether it represents a shared account.${lastLoginLookupFailed ? " One or more last login audit log lookups failed." : ""}`,
      source,
      commands: [
        `${result.command}: name,permissions-profile,authentication-method,expiration-date`,
        ...(rows.length ? ["show-logs: new-query.type audit,new-query.time-frame last-30-days,new-query.filter administrator:ADMIN_USERNAME AND SmartConsole AND \"Log In\": time,client_ip"] : [])
      ],
      remediation: neverExpirationNames.length ? {
        action: "set-admin-expiration-four-months",
        label: "Set 4 Month Expiration for Administrator",
        command: "set-administrator",
        target: neverExpirationNames.join(", ")
      } : null,
      review: names.length ? {
        action: "mark-reviewed",
        label: "Mark as Reviewed",
        reviewedAt: reviewHistory?.reviewedAt || "",
        reviewedBy: reviewHistory?.reviewedBy || "",
        reviewedThisLogin
      } : null
    })
  ];
}

function isPasswordAuthenticationMethod(value) {
  const method = String(value || "").toLowerCase();
  return method === "check point password" || method === "os password" || method === "password";
}

function unsupportedApiCommandMessage(result, command) {
  const error = result?.error || {};
  const unsupported = error.statusCode === 404
    && (error.response?.code === "generic_err_command_not_found" || /requested api command.*not found/i.test(String(error.error || "")));
  return unsupported ? `API command ${command} is supported in R82.10 and up.` : "";
}

const MANUAL_HARDENING_GUIDE_STATE = "Please manually verify using the hardening guide.";

function evaluateMfaIdentityProvider(defaultSettings, administrators, session) {
  const source = "Hardening guide: MFA and Identity Provider Integration";
  const rows = [];
  let defaultAuthenticationMethod = "";
  let failed = false;
  const defaultSettingsManual = unsupportedApiCommandMessage(defaultSettings, "show-default-administrator-settings");
  const reviewHistory = appHistory.reviews.get("admin.mfa-idp") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;

  if (defaultSettings.ok) {
    defaultAuthenticationMethod = defaultSettings.data?.["authentication-method"] || "";
    rows.push({
      "Scope": "Default administrator settings",
      "Name": "Default",
      "Authentication-Method": defaultAuthenticationMethod || "Not returned"
    });
  } else {
    failed = !defaultSettingsManual;
    rows.push({
      "Scope": "Default administrator settings",
      "Name": "Default",
      "Authentication-Method": defaultSettingsManual || defaultSettings.error?.error || "Command failed"
    });
  }

  if (administrators.ok) {
    const weakAdmins = (administrators.objects || []).filter((admin) => {
      const method = admin["authentication-method"] || admin.authenticationMethod || "";
      return isPasswordAuthenticationMethod(method);
    });
    rows.push(...weakAdmins.map((admin) => ({
      "Scope": "Administrator account",
      "Name": admin.name || admin.NAME || "",
      "Authentication-Method": admin["authentication-method"] || admin.authenticationMethod || ""
    })));
  } else {
    failed = true;
    rows.push({
      "Scope": "Administrator accounts",
      "Name": "Unavailable",
      "Authentication-Method": administrators.error?.error || "Command failed"
    });
  }

  const defaultIsWeak = isPasswordAuthenticationMethod(defaultAuthenticationMethod);
  const weakAdminCount = rows.filter((row) => row["Scope"] === "Administrator account").length;
  const remediationRecommended = defaultIsWeak || weakAdminCount > 0;

  return makeCheck({
    id: "admin.mfa-idp",
    category: "Administrator Identity and Access Control",
    title: "MFA And Identity Provider Integration",
    recommendation: "Check Point recommends setting up MFA for all environments, you can configure an external identity provider (IdP) for both SmartConsole/SmartDashboard administrator authentication and end-user Identity Awareness / Remote Access VPN. Check Point supports popular IdPs like Okta, Ping Identity, and Microsoft Entra ID (Azure AD) via the SAML protocol.",
    status: failed ? "unknown" : (defaultSettingsManual ? "manual" : (reviewedThisLogin ? "reviewed" : (remediationRecommended ? "remediation-recommended" : "needs-review"))),
    severity: remediationRecommended ? "high" : "medium",
    evidence: failed
      ? "One or more identity evidence commands failed."
      : (defaultSettingsManual
        ? MANUAL_HARDENING_GUIDE_STATE
        : `${weakAdminCount} administrator account${weakAdminCount === 1 ? "" : "s"} returned with check point password or os password authentication.`),
    evidenceTable: rows.length ? {
      columns: ["Scope", "Name", "Authentication-Method"],
      rows
    } : null,
    details: "MFA reduces the risk of credential compromise and enables centralized identity lifecycle management.",
    source,
    commands: [
      "show-default-administrator-settings: authentication-method",
      "show-administrators: name,authentication-method"
    ],
    review: !failed && !defaultSettingsManual ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateAdminPolicySettings(defaultSettings, idleTimeout, loginRestrictions, passwordRequirements, session) {
  const source = "Hardening guide: Review administrator accounts, password policy, and idle timeout";
  const rows = [];
  const failed = [defaultSettings, idleTimeout, loginRestrictions, passwordRequirements].filter((result) => !result.ok);
  const manualMessages = new Map([
    [defaultSettings, unsupportedApiCommandMessage(defaultSettings, "show-default-administrator-settings")],
    [idleTimeout, unsupportedApiCommandMessage(idleTimeout, "show-smart-console-idle-timeout")],
    [loginRestrictions, unsupportedApiCommandMessage(loginRestrictions, "show-login-restrictions")],
    [passwordRequirements, unsupportedApiCommandMessage(passwordRequirements, "show-cp-password-requirements")]
  ]);
  const manualResults = failed.filter((result) => manualMessages.get(result));
  const unexpectedFailures = failed.filter((result) => !manualMessages.get(result));
  let needsRemediation = false;
  let needsReview = false;
  const reviewHistory = appHistory.reviews.get("admin.password-idle-lockout") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;

  if (defaultSettings.ok) {
    const data = defaultSettings.data || {};
    const authenticationMethod = data["authentication-method"];
    const checkPointPassword = String(authenticationMethod || "").toLowerCase() === "check point password";
    if (checkPointPassword) needsReview = true;
    rows.push(settingRow(
      "Default authentication-method",
      authenticationMethod,
      checkPointPassword ? "Check Point recommends setting up an authentication method that supports MFA or an external Identity Provider." : ""
    ));
    const expirationType = data["expiration-type"];
    const expirationNever = String(expirationType || "").toLowerCase() === "never";
    if (expirationNever) needsRemediation = true;
    const expirationRow = settingRow(
      "Default expiration-type",
      expirationType,
      defaultExpirationState(data)
    );
    if (expirationNever) {
      expirationRow._remediation = {
        action: "set-default-expiration-quarterly",
        label: "Remediate with Check Point Recommended Config"
      };
    }
    rows.push(expirationRow);
    const notify = data["notify-expiration-to-admin"];
    rows.push(settingRow("Notify expiration to admin", onOff(notify)));
    if (notify === true) {
      rows.push(settingRow("Days to indicate expiration in admin view", data["days-to-indicate-expiration-in-admin-view"]));
      rows.push(settingRow("Days to notify expiration to admin", data["days-to-notify-expiration-to-admin"]));
    }
  } else {
    const manual = manualMessages.get(defaultSettings);
    rows.push(settingRow("Default administrator settings", manual || defaultSettings.error?.error || "Command failed", manual ? MANUAL_HARDENING_GUIDE_STATE : "Unknown"));
  }

  if (idleTimeout.ok) {
    const data = idleTimeout.data || {};
    const enabled = data.enabled;
    if (enabled === false) needsRemediation = true;
    const idleTimeoutRow = settingRow(
      "SmartConsole idle timeout",
      onOff(enabled),
      enabled === false ? "Check Point recommends setting idle timeout to a minimum of 10 minutes." : ""
    );
    if (enabled === false) {
      idleTimeoutRow._remediation = {
        action: "set-smartconsole-idle-timeout",
        label: "Remediate with Check Point Recommended Config"
      };
    }
    rows.push(idleTimeoutRow);
    if (enabled === true) {
      rows.push(settingRow("SmartConsole idle timeout duration", data["timeout-duration"]));
    }
  } else {
    const manual = manualMessages.get(idleTimeout);
    rows.push(settingRow("SmartConsole idle timeout", manual || idleTimeout.error?.error || "Command failed", manual ? MANUAL_HARDENING_GUIDE_STATE : "Unknown"));
  }

  if (loginRestrictions.ok) {
    const data = loginRestrictions.data || {};
    const lockoutAdmin = data["lockout-admin-account"];
    const unlockAdmin = data["unlock-admin-account"];
    if (lockoutAdmin === false || unlockAdmin === false) needsRemediation = true;
    rows.push(settingRow("Lockout admin account", onOff(lockoutAdmin), lockoutAdmin === false ? "Needs remediation" : ""));
    if (lockoutAdmin === true) {
      rows.push(settingRow("Failed authentication attempts", data["failed-authentication-attempts"]));
      rows.push(settingRow("Unlock admin account", onOff(unlockAdmin), unlockAdmin === false ? "Needs remediation" : ""));
      if (unlockAdmin === true) {
        rows.push(settingRow("Lockout duration", `${data["lockout-duration"] ?? "Not returned"} minutes`));
      }
    }
    rows.push(settingRow("Display access denied message", onOff(data["display-access-denied-message"])));
  } else {
    const manual = manualMessages.get(loginRestrictions);
    rows.push(settingRow("Login restrictions", manual || loginRestrictions.error?.error || "Command failed", manual ? MANUAL_HARDENING_GUIDE_STATE : "Unknown"));
  }

  if (passwordRequirements.ok) {
    const data = passwordRequirements.data || {};
    const minPasswordLength = Number(data["min-password-length"]);
    if (Number.isFinite(minPasswordLength) && minPasswordLength < 10) needsRemediation = true;
    const passwordLengthRow = settingRow(
      "Minimum password length",
      data["min-password-length"],
      Number.isFinite(minPasswordLength) && minPasswordLength < 10 ? "Check Point recommends a minimum password length of 10 characters." : ""
    );
    if (Number.isFinite(minPasswordLength) && minPasswordLength < 10) {
      passwordLengthRow._remediation = {
        action: "set-minimum-password-length",
        label: "Remediate with Check Point Recommended Config"
      };
    }
    rows.push(passwordLengthRow);
  } else {
    const manual = manualMessages.get(passwordRequirements);
    rows.push(settingRow("CP password requirements", manual || passwordRequirements.error?.error || "Command failed", manual ? MANUAL_HARDENING_GUIDE_STATE : "Unknown"));
  }

  const status = unexpectedFailures.length ? "unknown" : (manualResults.length ? "manual" : (reviewedThisLogin ? "reviewed" : (needsRemediation ? "remediation-required" : "needs-review")));
  return makeCheck({
    id: "admin.password-idle-lockout",
    category: "Administrator Identity and Access Control",
    title: "Set Admin Password, Idle Timeout, Expiration, And Lockout Policy",
    recommendation: "Use password length of at least 10 characters, disconnect SmartConsole after 10 minutes idle, expire admin access, and enable lockout.",
    status,
    severity: needsRemediation ? "high" : "medium",
    evidence: unexpectedFailures.length
      ? `${unexpectedFailures.length} administrator policy command${unexpectedFailures.length === 1 ? "" : "s"} failed.`
      : (manualResults.length
        ? MANUAL_HARDENING_GUIDE_STATE
        : "Administrator password, idle timeout, expiration, and lockout settings returned."),
    evidenceTable: rows.length ? {
      columns: ["Setting", "Value", "State"],
      rows
    } : null,
    details: needsRemediation
      ? "One or more administrator access control settings are disabled and need remediation."
      : "Review the returned settings against your administrative security policy.",
    source,
    commands: [
      "show-default-administrator-settings",
      "show-smart-console-idle-timeout",
      "show-login-restrictions",
      "show-cp-password-requirements"
    ],
    review: !failed.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateGlobalProperties(result, session) {
  const checks = [];
  const source = "Hardening guide: Limit and Log Implied Rules; Dynamic Updates; Diagnostics and Telemetry";
  if (!result.ok) {
    return [
      makeCheck({
        id: "policy.implied-rules",
        category: "Decreasing Security Gateway Exposure with Policy",
        title: "Review Implied Rules And Enable Logging",
        recommendation: "Review implied rules settings, only enable those that are necessary and ensure that logging for implied rules remain enabled. Implied Rules allow essential Check Point internal communication, connectivity for essential features (e.g. VPN & Remotes Access). Reducing these to the minimum will reduce the potential attack surface and logging them improves auditability and troubleshooting without breaking functionality.",
        status: "unknown",
        evidence: "Global properties could not be retrieved.",
        details: result.error?.error || "",
        source,
        commands: [result.command]
      })
    ];
  }

  const properties = result.data || {};
  const reviewHistory = appHistory.reviews.get("policy.implied-rules") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const cpdiagReviewHistory = appHistory.reviews.get("updates.cpdiag") || null;
  const cpdiagReviewedThisLogin = cpdiagReviewHistory?.sessionId === session.id;
  const firewallProperties = properties.firewall && typeof properties.firewall === "object" && !Array.isArray(properties.firewall)
    ? properties.firewall
    : {};
  const logImpliedRules = firewallProperties["log-implied-rules"];
  const logImpliedRulesDisabled = logImpliedRules === false || normalizeToken(logImpliedRules) === "false";
  const firewallRows = Object.entries(firewallProperties)
    .filter(([key]) => !isPositionSetting(key) && key !== "security-server")
    .map(([key, value]) => {
    const isDisabled = value === false || normalizeToken(value) === "false";
    const row = {
      "Setting": key,
      "Enabled/Disabled": enabledDisabledValue(value),
      "Position": isDisabled ? "" : positionForSetting(firewallProperties, key),
      "Description": key === "log-implied-rules" && logImpliedRulesDisabled
        ? "Check Point recommends that implied rules are always logged. This should be enabled."
        : impliedRuleDescription(key)
    };
    if (key === "log-implied-rules" && logImpliedRulesDisabled) {
      row._remediation = {
        action: "enable-log-implied-rules",
        label: "Enable implied rule logging"
      };
    }
    return row;
  });
  const dataAccessControl = properties["data-access-control"] && typeof properties["data-access-control"] === "object" && !Array.isArray(properties["data-access-control"])
    ? properties["data-access-control"]
    : {};
  const dynamicUpdateSettings = [
    ["auto-download-important-data", "Auto-download important data"],
    ["auto-download-sw-updates-and-new-features", "Auto-download software updates and new features"]
  ];
  const dynamicUpdateRows = dynamicUpdateSettings
    .filter(([key]) => dataAccessControl[key] !== undefined)
    .map(([key, label]) => {
      const value = dataAccessControl[key];
      const enabled = value === true || normalizeToken(value) === "true";
      const row = {
        "Setting": label,
        "Value": enabledDisabledValue(value)
      };
      if (!enabled) {
        row._remediation = {
          action: "enable-dynamic-updates",
          label: "Enable Dynamic Updates"
        };
        row._remediationColumn = "Value";
      }
      return row;
    });
  const dynamicUpdatesReturned = dynamicUpdateRows.length > 0;
  const dynamicUpdatesNeedRemediation = dynamicUpdateRows.some((row) => row.Value === "Disabled");
  const dynamicReviewHistory = appHistory.reviews.get("updates.dynamic-updates") || null;
  const dynamicReviewedThisLogin = dynamicReviewHistory?.sessionId === session.id;
  const sendAnonymousInfo = dataAccessControl["send-anonymous-info"];
  const sendAnonymousInfoReturned = sendAnonymousInfo !== undefined;
  const sendAnonymousInfoEnabled = sendAnonymousInfo === true || normalizeToken(sendAnonymousInfo) === "true";
  const cpdiagRows = sendAnonymousInfoReturned ? [(() => {
    const row = {
      "Setting": "Send anonymous diagnostics information",
      "Value": enabledDisabledValue(sendAnonymousInfo)
    };
    if (!sendAnonymousInfoEnabled) {
      row._remediation = {
        action: "enable-diagnostics-telemetry",
        label: "Enable Diagnostics and Telemetry"
      };
      row._remediationColumn = "Value";
    }
    return row;
  })()] : [];

  checks.push(makeCheck({
    id: "policy.implied-rules",
    category: "Decreasing Security Gateway Exposure with Policy",
    title: "Review Implied Rules And Enable Logging",
    recommendation: "Review implied rules settings, only enable those that are necessary and ensure that logging for implied rules remain enabled. Implied Rules allow essential Check Point internal communication, connectivity for essential features (e.g. VPN & Remotes Access). Reducing these to the minimum will reduce the potential attack surface and logging them improves auditability and troubleshooting without breaking functionality.",
    status: reviewedThisLogin ? "reviewed" : (logImpliedRulesDisabled ? "remediation-required" : (firewallRows.length ? "needs-review" : "unknown")),
    severity: logImpliedRulesDisabled ? "high" : "medium",
    evidence: firewallRows.length ? "Firewall global properties were returned." : "No firewall global properties were found in the returned global properties.",
    evidenceTable: firewallRows.length ? {
      columns: ["Setting", "Enabled/Disabled", "Position", "Description"],
      rows: firewallRows
    } : null,
    details: "Disabling implied rules without correct explicit rules can cause policy install failures and loss of management / log connectivity. See SK179346 for more details.",
    detailsLink: {
      label: "SK179346",
      url: "https://support.checkpoint.com/results/sk/sk179346"
    },
    specialConsiderations: {
      text: "If none of the Check Point Security Gateways use dynamic IP addresses, or have remote access enabled, Implied Rules should be set up as referenced on page 9 of the hardening guide HERE. Make sure to follow the SK above in details to setup any needed explicit rules.",
      linkLabel: "HERE",
      image: "/assets/implied-rules-special-considerations.png"
    },
    recommendationWarning: logImpliedRulesDisabled
      ? "Implied rules are currently not being logged. This creates a security visibility gap. Use the remediation button below to enable implied rule logging."
      : "",
    source,
    commands: [result.command],
    review: firewallRows.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  }));

  checks.push(makeCheck({
    id: "updates.dynamic-updates",
    category: "Updates, Health, and Ongoing Protection",
    title: "Enable Dynamic Updates / AutoUpdater Consent",
    recommendation: "This utility enables dynamic security updates including IPS updates and security fixes. Dynamic updates keep protections current without requiring disruptive upgrades or reboots.",
    status: dynamicUpdatesReturned ? (dynamicReviewedThisLogin ? "reviewed" : (dynamicUpdatesNeedRemediation ? "remediation-recommended" : "needs-review")) : "unknown",
    severity: dynamicUpdatesNeedRemediation ? "high" : "medium",
    evidence: dynamicUpdatesReturned
      ? "Data Access Control AutoUpdater settings were returned."
      : "Data Access Control AutoUpdater settings were not returned from global properties.",
    evidenceTable: dynamicUpdateRows.length ? {
      columns: ["Setting", "Value"],
      rows: dynamicUpdateRows
    } : null,
    details: "Check Point uses this mechanism to mitigate vulnerability as interim preventative measure that helped protect many customers before they were even aware.",
    source,
    commands: [`${result.command}: data-access-control.auto-download-important-data,data-access-control.auto-download-sw-updates-and-new-features`],
    remediation: null,
    review: dynamicUpdatesReturned ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: dynamicReviewHistory?.reviewedAt || "",
      reviewedBy: dynamicReviewHistory?.reviewedBy || "",
      reviewedThisLogin: dynamicReviewedThisLogin
    } : null
  }));

  checks.push(makeCheck({
    id: "updates.cpdiag",
    category: "Updates, Health, and Ongoing Protection",
    title: "Enable Diagnostics And Telemetry / cpdiag",
    recommendation: "Enable your Check Point Management Servers and Security Gateways to share essential non-PII, diagnostics data with Check Point cloud.",
    status: sendAnonymousInfoReturned ? (cpdiagReviewedThisLogin ? "reviewed" : (sendAnonymousInfoEnabled ? "needs-review" : "remediation-recommended")) : "unknown",
    severity: sendAnonymousInfoReturned && !sendAnonymousInfoEnabled ? "high" : "medium",
    evidence: sendAnonymousInfoReturned
      ? `data-access-control.send-anonymous-info is ${enabledDisabledValue(sendAnonymousInfo)}.`
      : "data-access-control.send-anonymous-info was not returned from global properties.",
    evidenceTable: cpdiagRows.length ? {
      columns: ["Setting", "Value"],
      rows: cpdiagRows
    } : null,
    details: "Check Point Diagnostics collects usage information and status telemetry of the product operation. This helps improve supportability and enable proactive identification of issues (without replacing your logging strategy). This is essential for Check Point to identify and proactively alert if your products are exposed to a known vulnerability. The collection and transmission of the data is not CPU-intensive and is shared every 24 hours.",
    source,
    commands: [`${result.command}: data-access-control.send-anonymous-info`],
    remediation: null,
    review: sendAnonymousInfoReturned ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: cpdiagReviewHistory?.reviewedAt || "",
      reviewedBy: cpdiagReviewHistory?.reviewedBy || "",
      reviewedThisLogin: cpdiagReviewedThisLogin
    } : null
  }));

  return checks;
}

function gatewayInstalledVersion(gateway) {
  const directKeys = ["version", "os-version", "software-version", "product-version", "installed-version"];
  for (const key of directKeys) {
    if (gateway?.[key]) return String(gateway[key]);
  }
  const recursive = valuesForNormalizedKey(gateway, ...directKeys)
    .flatMap(uidValues)
    .find(Boolean);
  return recursive ? String(recursive) : "Not returned";
}

function packageListText(packages = []) {
  if (!Array.isArray(packages) || !packages.length) return "";
  return packages
    .map((pkg) => pkg["package-id"] || pkg.packageId || pkg.version || pkg.name)
    .filter(Boolean)
    .join(", ");
}

function installedJumboVersion(packages = []) {
  if (!Array.isArray(packages)) return "";
  const versions = packages.flatMap((pkg) => {
    if (normalizeToken(pkg?.category) !== "jumbo") return [];
    const packageId = String(pkg?.["package-id"] || pkg?.packageId || pkg?.name || "");
    const match = packageId.match(/(R\d+(?:[._]\d+)*)_jumbo.*?_T(\d+)(?:_|\.|$)/i);
    if (!match) return [];
    return [`${match[1].replaceAll("_", ".")} Take ${match[2]}`];
  });
  return uniqueStrings(versions).join(", ");
}

function packageCategoryLabel(value) {
  const normalized = normalizeToken(value);
  if (normalized === "jumbo") return "Jumbo";
  if (normalized === "major") return "Major";
  return value ? `${String(value).charAt(0).toUpperCase()}${String(value).slice(1)}` : "N/A";
}

function gatewayServerType(object = {}) {
  return normalizeToken(object.type || object.TYPE || object["object-type"] || object.objectType || "");
}

function isSimpleGatewayObject(object = {}) {
  return gatewayServerType(object) === "simplegateway";
}

function isClusterGatewayObject(object = {}) {
  const type = gatewayServerType(object);
  return type === "cpmigatewaycluster" || type === "simplecluster" || type === "clusterxl";
}

function isClusterMemberObject(object = {}) {
  const type = gatewayServerType(object);
  return type === "clustermember" || type === "cpmiclustermember" || (type.includes("cluster") && type.includes("member"));
}

function isManagementServerObject(object = {}) {
  const type = gatewayServerType(object);
  return type === "checkpointhost" || type.includes("management");
}

function gatewayServerInventory(gatewaysAndServersResult, fallbackGatewaysResult = null) {
  const sourceResult = gatewaysAndServersResult?.ok ? gatewaysAndServersResult : fallbackGatewaysResult;
  const objects = sourceResult?.ok ? (sourceResult.objects || []) : [];
  const namedObjects = objects.filter((object) => object?.name || object?.NAME || object?.uid);
  const byName = new Map(namedObjects.map((object) => [normalizeToken(object.name || object.NAME || object.uid), object]));
  const simpleGateways = namedObjects.filter(isSimpleGatewayObject);
  const clusters = namedObjects.filter(isClusterGatewayObject);
  const clusterByMemberName = new Map();
  clusters.forEach((cluster) => {
    const blades = cluster["network-security-blades"] || cluster.networkSecurityBlades;
    const memberNames = [
      ...(cluster["cluster-member-names"] || cluster.clusterMemberNames || []),
      ...(cluster["cluster-members"] || cluster.clusterMembers || []).map((member) => member?.name || member?.NAME || member)
    ].filter(Boolean);
    memberNames.forEach((memberName) => {
      clusterByMemberName.set(normalizeToken(memberName), blades);
    });
  });
  const clusterMembers = namedObjects.filter(isClusterMemberObject).map((member) => {
    const ownBlades = member["network-security-blades"] || member.networkSecurityBlades;
    const inheritedBlades = clusterByMemberName.get(normalizeToken(member.name || member.NAME || ""));
    return ownBlades || inheritedBlades
      ? { ...member, _effectiveNetworkSecurityBlades: ownBlades || inheritedBlades }
      : member;
  });
  const effectiveMemberByName = new Map(clusterMembers.map((member) => [normalizeToken(member.name || member.NAME || member.uid), member]));
  const managementServers = namedObjects.filter(isManagementServerObject);
  const policyTargets = [...simpleGateways, ...clusters];
  const managedGateways = [...simpleGateways, ...clusters, ...clusterMembers];
  const runScriptTargets = [
    ...simpleGateways,
    ...clusterMembers,
    ...clusters.flatMap((cluster) => (cluster["cluster-member-names"] || cluster.clusterMemberNames || [])
      .map((name) => effectiveMemberByName.get(normalizeToken(name)) || byName.get(normalizeToken(name)))
      .filter(Boolean))
  ];
  const topologyObjects = namedObjects.filter((object) => {
    if (isManagementServerObject(object)) return false;
    const payload = gatewayTopologyPayload(object);
    return payload.length || isSimpleGatewayObject(object) || isClusterGatewayObject(object) || isClusterMemberObject(object);
  });
  function dedupe(list) {
    const seen = new Set();
    return list.filter((object) => {
      const key = object.uid || normalizeToken(object.name || object.NAME || "");
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  return {
    ok: Boolean(sourceResult?.ok),
    error: sourceResult?.error,
    command: gatewaysAndServersResult?.ok ? "show-gateways-and-servers" : fallbackGatewaysResult?.command || "show-gateways-and-servers",
    objects: namedObjects,
    simpleGateways,
    clusters,
    clusterMembers,
    managementServers,
    policyTargets: dedupe(policyTargets),
    managedGateways: dedupe(managedGateways),
    runScriptTargets: dedupe(runScriptTargets),
    topologyObjects: dedupe(topologyObjects)
  };
}

function gatewayObjectIpAddress(gateway = {}) {
  return gateway["ipv4-address"] || gateway.ipv4Address || gateway["ip-address"] || gateway.ipAddress
    || firstIpv4(allIpv4Values(gateway).join(" ")) || "Not returned";
}

async function collectGatewaySicStatusEvidence(session, gatewayInventory) {
  // Management server objects are intentionally excluded: SIC status is only
  // relevant here for gateways and cluster members that will be scanned.
  const targets = [...(gatewayInventory.simpleGateways || []), ...(gatewayInventory.clusterMembers || [])];
  const seen = new Set();
  const uniqueTargets = targets.filter((gateway) => {
    if (isClusterGatewayObject(gateway)) return false;
    const key = gateway.uid || normalizeToken(gateway.name || gateway.NAME || "");
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const statusLabels = new Map([
    ["uninitialized", "Uninitialized"],
    ["initialized", "Initialized"],
    ["communicating", "Communicating"],
    ["notcommunicating", "Not Communicating"],
    ["unknown", "Unknown"],
    ["failed", "Failed"],
    ["waitingforfirstconnection", "Waiting For First Connection"]
  ]);
  const sicTestQueue = createLimiter(session?.largeEnvironmentMode ? LARGE_ENV_SIC_TEST_CONCURRENCY : SIC_TEST_CONCURRENCY);
  const results = await Promise.all(uniqueTargets.map((gateway) => sicTestQueue(async () => {
    const name = gateway.name || gateway.NAME || gateway.uid || "";
    const test = await tryCommand(session, "test-sic-status", { name });
    const rawStatus = test.ok ? (test.data?.["sic-status"] ?? test.data?.sicStatus ?? "unknown") : "test-failed";
    const statusToken = normalizeToken(rawStatus);
    const communicating = statusToken === "communicating";
    const status = communicating
      ? "Communicating"
      : (test.ok ? (statusLabels.get(statusToken) || `Unknown (${String(rawStatus || "not returned")})`) : "SIC Test Failed");
    return {
      gateway,
      name,
      status,
      communicating,
      message: test.ok ? String(test.data?.["sic-message"] || "") : String(test.error?.error || "test-sic-status failed"),
      sicName: test.ok ? String(test.data?.["sic-name"] || "") : "",
      error: test.ok ? null : test.error
    };
  })));

  const nonCommunicating = results.filter((result) => !result.communicating);
  const blockedKeys = new Set(nonCommunicating.flatMap(({ gateway }) => [
    gateway.uid,
    normalizeToken(gateway.name || gateway.NAME || "")
  ]).filter(Boolean));
  return {
    ok: nonCommunicating.length === 0,
    command: "test-sic-status",
    rows: nonCommunicating.map(({ gateway, name, status, message, sicName }) => ({
      "Object Name": name,
      "Object IP-Address": gatewayObjectIpAddress(gateway),
      "SIC Status": status,
      "SIC Message": message || "Not returned",
      "SIC Name": sicName || "Not returned"
    })),
    blockedKeys,
    results
  };
}

function filterGatewayInventoryBySic(gatewayInventory, sicEvidence) {
  const blocked = sicEvidence?.blockedKeys || new Set();
  const isBlocked = (gateway) => blocked.has(gateway?.uid) || blocked.has(normalizeToken(gateway?.name || gateway?.NAME || ""));
  const clusterIsBlocked = (cluster) => {
    const memberNames = cluster?.["cluster-member-names"] || cluster?.clusterMemberNames || [];
    return memberNames.length > 0 && memberNames.every((name) => blocked.has(normalizeToken(name)));
  };
  return {
    ...gatewayInventory,
    simpleGateways: gatewayInventory.simpleGateways.filter((gateway) => !isBlocked(gateway)),
    clusters: gatewayInventory.clusters.filter((cluster) => !clusterIsBlocked(cluster)),
    clusterMembers: gatewayInventory.clusterMembers.filter((gateway) => !isBlocked(gateway)),
    policyTargets: gatewayInventory.policyTargets.filter((gateway) => !isBlocked(gateway) && !clusterIsBlocked(gateway)),
    managedGateways: gatewayInventory.managedGateways.filter((gateway) => !isBlocked(gateway) && !clusterIsBlocked(gateway)),
    runScriptTargets: gatewayInventory.runScriptTargets.filter((gateway) => !isBlocked(gateway)),
    topologyObjects: gatewayInventory.topologyObjects.filter((gateway) => !isBlocked(gateway) && !clusterIsBlocked(gateway))
  };
}

async function collectJumboHotfixEvidence(session, gatewaysResult) {
  if (!gatewaysResult.ok) {
    return {
      ok: false,
      command: "show-software-packages-per-targets",
      error: gatewaysResult.error,
      rows: [{
        "Name of Gateway": "Gateway Returns No Data",
        "Currently Installed Version": "Gateway Returns No Data",
        "Available Recommended Update": "Gateway Returns No Data",
        "Category": "Gateway Returns No Data",
        "Recommended Upgrade Package": "Gateway Returns No Data"
      }]
    };
  }

  const gateways = gatewaysResult.objects || [];
  if (!gateways.length) {
    return {
      ok: false,
      command: "show-software-packages-per-targets",
      rows: [{
        "Name of Gateway": "Gateway Returns No Data",
        "Currently Installed Version": "Gateway Returns No Data",
        "Available Recommended Update": "Gateway Returns No Data",
        "Category": "Gateway Returns No Data",
        "Recommended Upgrade Package": "Gateway Returns No Data"
      }]
    };
  }

  const errors = [];
  const gatewayNames = gateways.map((gateway) => gateway.name || gateway.NAME || gateway.uid || "").filter(Boolean);
  const batchResult = await tryCommand(session, "show-software-packages-per-targets", {
    display: { installed: "any", recommended: "any" },
    targets: gatewayNames
  });
  const returnedTargets = batchResult.ok && Array.isArray(batchResult.data?.targets) ? [...batchResult.data.targets] : [];
  const returnedKeys = new Set(returnedTargets.flatMap((target) => [target.uid, normalizeToken(target.name || "")]).filter(Boolean));
  const missingGateways = gateways.filter((gateway) => (
    !returnedKeys.has(gateway.uid) && !returnedKeys.has(normalizeToken(gateway.name || gateway.NAME || gateway.uid || ""))
  ));
  if (missingGateways.length) {
    const fallbackResults = await Promise.all(missingGateways.map(async (gateway) => {
      const gatewayName = gateway.name || gateway.NAME || gateway.uid || "";
      const fallback = await tryCommand(session, "show-software-packages-per-targets", {
        display: { installed: "any", recommended: "any" },
        targets: [gatewayName]
      });
      const target = fallback.ok && Array.isArray(fallback.data?.targets) ? fallback.data.targets[0] : null;
      if (!target) errors.push({ gateway: gatewayName, error: fallback.error || batchResult.error || { error: "No software package data returned." } });
      return target;
    }));
    returnedTargets.push(...fallbackResults.filter(Boolean));
  }
  const rows = gateways.map((gateway) => {
    const gatewayName = gateway.name || gateway.NAME || gateway.uid || "";
    const target = returnedTargets.find((item) => (
      normalizeToken(item.name || item.uid) === normalizeToken(gatewayName) ||
      (gateway.uid && item.uid === gateway.uid)
    ));
    const packages = target?.packages;
    if (!target || !packages) {
      return {
        "Name of Gateway": gatewayName || "Gateway Returns No Data",
        "Currently Installed Version": gatewayInstalledVersion(gateway),
        "Available Recommended Update": "Gateway Returns No Data",
        "Category": "Gateway Returns No Data",
        "Recommended Upgrade Package": "Gateway Returns No Data"
      };
    }
    // Request installed packages explicitly and translate Check Point's Jumbo
    // bundle filename into a readable release and take. Fall back to the
    // gateway/member version when no installed Jumbo package is returned.
    const installedJumbo = installedJumboVersion(packages.installed);
    const objectVersion = gatewayInstalledVersion(gateway);
    const installed = installedJumbo || (objectVersion !== "Not returned" ? objectVersion : packageListText(packages.installed));
    const recommendedPackage = Array.isArray(packages.available)
      ? packages.available.find((pkg) => pkg.recommended === true || normalizeToken(pkg.recommended) === "true")
      : null;
    return {
      "Name of Gateway": target.name || gatewayName,
      "Currently Installed Version": installed || "Not returned",
      "Available Recommended Update": recommendedPackage ? "Yes" : "Not",
      "Category": recommendedPackage ? packageCategoryLabel(recommendedPackage.category) : "N/A",
      "Recommended Upgrade Package": recommendedPackage?.["package-id"] || recommendedPackage?.packageId || "N/A"
    };
  });

  return {
    ok: errors.length === 0,
    command: "show-software-packages-per-targets",
    rows,
    errors
  };
}

function licenseFeatureFromSku(value) {
  const normalized = String(value || "").replace(/\s+/g, "").toUpperCase();
  return normalized.replace(/-\d[A-Z0-9-]*$/i, "");
}

const PERPETUAL_LICENSE_FEATURES = new Set(["FW", "VPN", "IA"]);
const LICENSE_FEATURE_NAMES = new Map([
  ["FW", "Firewall"],
  ["VPN", "VPN"],
  ["IA", "Identity Awareness"],
  ["SDWAN", "SD-WAN"],
  ["URLF", "URL Filtering"],
  ["AV", "Anti-Virus"],
  ["ZP", "Zero Phishing"],
  ["APCL", "Application Control"],
  ["TE", "Threat Emulation"],
  ["TEX", "Threat Extraction"],
  ["ASPM", "Anti-Spam"],
  ["ADNS", "Advanced DNS Security"],
  ["ABOT", "Anti-Bot"],
  ["CTNT", "Content Awareness"],
  ["IPS", "IPS"]
]);
const LICENSE_FEATURE_BLADE_KEYS = new Map([
  ["FW", "firewall"],
  ["VPN", "site-to-site-vpn"],
  ["IA", "identity-awareness"],
  ["SDWAN", "sd-wan"],
  ["URLF", "url-filtering"],
  ["AV", "anti-virus"],
  ["ZP", "zero-phishing"],
  ["APCL", "application-control"],
  ["TE", "threat-emulation"],
  ["TEX", "threat-extraction"],
  ["ASPM", "anti-spam"],
  ["ADNS", "advanced-dns-security"],
  ["ABOT", "anti-bot"],
  ["CTNT", "content-awareness"],
  ["IPS", "ips"]
]);
const LICENSE_FEATURE_CODES = [...LICENSE_FEATURE_NAMES.keys()].sort((a, b) => b.length - a.length);

function licenseFeatureCodeFromSku(value) {
  const normalized = licenseFeatureFromSku(value);
  const parts = normalized.split("-").filter(Boolean);
  return LICENSE_FEATURE_CODES.find((code) => parts.includes(code)) || "";
}

function licenseFeatureDisplayName(feature) {
  const normalized = String(feature || "").toUpperCase();
  return LICENSE_FEATURE_NAMES.get(normalized) || normalized;
}

function licenseFeatureEnabledState(feature, gateway = {}) {
  const code = String(feature || "").toUpperCase();
  if (code === "ADNS") {
    return "Please Confirm Config Manually in Assigned Threat Profile";
  }
  const bladeKey = LICENSE_FEATURE_BLADE_KEYS.get(code);
  if (!bladeKey) return { value: "Unable to determine", tone: "unknown" };
  const blades = gateway._effectiveNetworkSecurityBlades || gateway["network-security-blades"] || gateway.networkSecurityBlades;
  if (!blades || typeof blades !== "object") return { value: "Not returned", tone: "unknown" };
  return blades[bladeKey] === true
    ? { value: "Enabled", tone: "success" }
    : { value: "Disabled", tone: "critical" };
}

function parseLicenseStatusFeatures(output) {
  const cleaned = cleanGaiaCliOutput(output);
  const features = new Map();
  const lines = cleaned
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const headerIndex = lines.findIndex((line) => (
    /\bHost\b/i.test(line) &&
    /\bExpiration\b/i.test(line) &&
    /\bSignature\b/i.test(line) &&
    /\bFeatures\b/i.test(line)
  ));
  if (headerIndex >= 0) {
    const dataLines = [];
    for (const line of lines.slice(headerIndex + 1)) {
      if (/^Contract Coverage:/i.test(line)) break;
      if (/^(=+|\+-+|#\s+ID\b)/i.test(line)) continue;
      dataLines.push(line);
    }
    const tokens = dataLines.join(" ").replace(/\s+/g, " ").trim().split(/\s+/).filter(Boolean);
    if (tokens.length >= 4) {
      const expiration = tokens[1] || "Not returned";
      tokens.slice(3)
        .map(licenseFeatureCodeFromSku)
        .filter((feature) => PERPETUAL_LICENSE_FEATURES.has(feature))
        .forEach((feature) => features.set(feature, expiration));
    }
  }

  const compact = cleaned.replace(/\r?\n/g, " ").replace(/\s+/g, " ");
  const contractRegex = /(?:^|\s)\d+\s*\|\s*[A-Z0-9]+\s*\|\s*(never|\d{1,2}[A-Za-z]{3}\s*\d{4})\s*\|\s*([A-Z][A-Z0-9\s-]*?)(?=\s*(?:\+-+|=+\+|\d+\s*\||\|?\s*Covers:|$))/gi;
  let match;
  while ((match = contractRegex.exec(compact)) !== null) {
    const expiration = match[1].replace(/\s+/g, "");
    const feature = licenseFeatureCodeFromSku(match[2]);
    if (feature) {
      features.set(feature, expiration);
    }
  }
  return [...features.entries()].map(([feature, expiration]) => ({
    "License Feature": licenseFeatureDisplayName(feature),
    "Expiration Date": expiration || "Not returned",
    "_licenseCode": feature
  }));
}

async function collectSecurityFeatureUsageEvidence(session, gatewaysResult) {
  if (!gatewaysResult.ok) {
    return {
      ok: false,
      command: "run-script/show-license-status",
      error: gatewaysResult.error,
      rows: [{
        "Object Name": "Gateway Returns No Data",
        "License Feature": "Gateway Returns No Data",
        "Expiration Date": "Gateway Returns No Data",
        "Enabled/Disabled": "Gateway Returns No Data"
      }],
      evidenceTables: [{
        title: "Gateway Name: Gateway Returns No Data",
        compact: true,
        columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
        rows: [{
          "License Feature": "Gateway Returns No Data",
          "Expiration Date": "Gateway Returns No Data",
          "Enabled/Disabled": "Gateway Returns No Data"
        }]
      }]
    };
  }

  const gateways = gatewaysResult.objects || [];
  if (!gateways.length) {
    return {
      ok: false,
      command: "run-script/show-license-status",
      rows: [{
        "Object Name": "Gateway Returns No Data",
        "License Feature": "Gateway Returns No Data",
        "Expiration Date": "Gateway Returns No Data",
        "Enabled/Disabled": "Gateway Returns No Data"
      }],
      evidenceTables: [{
        title: "Gateway Name: Gateway Returns No Data",
        compact: true,
        columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
        rows: [{
          "License Feature": "Gateway Returns No Data",
          "Expiration Date": "Gateway Returns No Data",
          "Enabled/Disabled": "Gateway Returns No Data"
        }]
      }]
    };
  }

  const errors = [];
  const tableResults = await Promise.all(gateways.map(async (gateway) => {
    const gatewayName = gateway.name || gateway.NAME || gateway.uid || "";
    const tableTitle = `Gateway Name: ${gatewayName || "Gateway Returns No Data"}`;
    if (!gatewayName) {
      const rows = [{
        "Object Name": "Gateway Returns No Data",
        "License Feature": "Gateway Returns No Data",
        "Expiration Date": "Gateway Returns No Data",
        "Enabled/Disabled": "Gateway Returns No Data"
      }];
      return {
        rows,
        table: {
          title: tableTitle,
          compact: true,
          columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
          rows: rows.map(({ "License Feature": feature, "Expiration Date": expiration, "Enabled/Disabled": state }) => ({
            "License Feature": feature,
            "Expiration Date": expiration,
            "Enabled/Disabled": state
          }))
        }
      };
    }
    const result = await runScriptWithTaskDetails(session, {
      "script-name": "show license",
      targets: [gatewayName],
      script: "clish -c 'show license status'"
    });
    if (!result.ok) {
      errors.push({ target: gatewayName, error: result.error });
      const rows = [{
        "Object Name": gatewayName,
        "License Feature": "Lookup failed",
        "Expiration Date": runScriptDisplayError(result),
        "Enabled/Disabled": "Not returned"
      }];
      return {
        rows,
        table: {
          title: tableTitle,
          compact: true,
          columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
          rows: rows.map(({ "License Feature": feature, "Expiration Date": expiration, "Enabled/Disabled": state }) => ({
            "License Feature": feature,
            "Expiration Date": expiration,
            "Enabled/Disabled": state
          }))
        }
      };
    }
    const output = runScriptOutputText(result);
    const parsedRows = parseLicenseStatusFeatures(output);
    if (!parsedRows.length) {
      errors.push({ target: gatewayName, error: { error: "No license features parsed from show license status output." } });
      const rows = [{
        "Object Name": gatewayName,
        "License Feature": "No license features returned",
        "Expiration Date": gaiaOutputUnavailable(output) ? GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE : "Not returned",
        "Enabled/Disabled": "Not returned"
      }];
      return {
        rows,
        table: {
          title: tableTitle,
          compact: true,
          columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
          rows: rows.map(({ "License Feature": feature, "Expiration Date": expiration, "Enabled/Disabled": state }) => ({
            "License Feature": feature,
            "Expiration Date": expiration,
            "Enabled/Disabled": state
          }))
        }
      };
    }
    const rows = parsedRows.map((row) => ({
      "Object Name": gatewayName,
      ...row,
      "Enabled/Disabled": licenseFeatureEnabledState(row._licenseCode, gateway)
    }));
    return {
      rows,
      table: {
        title: tableTitle,
        compact: true,
        columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
        rows: rows
          .map(({ "License Feature": feature, "Expiration Date": expiration, "Enabled/Disabled": state }) => ({
            "License Feature": feature,
            "Expiration Date": expiration,
            "Enabled/Disabled": state
          }))
          .sort((a, b) => String(a["License Feature"] || "").localeCompare(String(b["License Feature"] || "")))
      }
    };
  }));
  const rows = tableResults.flatMap((result) => result.rows || []).sort((a, b) => (
    String(a["Object Name"] || "").localeCompare(String(b["Object Name"] || "")) ||
    String(a["License Feature"] || "").localeCompare(String(b["License Feature"] || ""))
  ));
  const evidenceTables = tableResults
    .map((result) => result.table)
    .filter(Boolean)
    .sort((a, b) => String(a.title || "").localeCompare(String(b.title || "")));

  return {
    ok: errors.length === 0,
    command: "run-script/show-license-status",
    rows,
    evidenceTables,
    errors
  };
}

async function collectSizingStatisticsEvidence(session, gatewaysResult) {
  if (!gatewaysResult.ok) {
    return {
      ok: false,
      command: "run-script/cpstat-os-memory-cpu",
      error: gatewaysResult.error,
      rows: []
    };
  }

  const gateways = gatewaysResult.objects || [];
  if (!gateways.length) {
    return {
      ok: false,
      command: "run-script/cpstat-os-memory-cpu",
      error: { error: "No eligible gateway devices were returned." },
      rows: []
    };
  }

  const errors = [];
  const rows = await Promise.all(gateways.map(async (gateway) => {
    const gatewayName = gateway.name || gateway.NAME || gateway.uid || "";
    if (!gatewayName) {
      errors.push({ target: "Unknown gateway", error: { error: "Gateway name was not returned." } });
      return {
        "Gateway": "Gateway Returns No Data",
        "Memory Statistics": { value: "Gateway Returns No Data", multiline: true },
        "CPU Statistics": { value: "Gateway Returns No Data", multiline: true }
      };
    }

    const result = await runScriptWithTaskDetails(mdsRunScriptSession(session, gateway), {
      "script-name": "collect sizing statistics",
      targets: [gatewayName],
      script: [
        "printf '\\n__CPBPS_CPSTAT_MEMORY__\\n'",
        "cpstat os -f memory",
        "printf '\\n__CPBPS_CPSTAT_CPU__\\n'",
        "cpstat os -f cpu"
      ].join("\n")
    });

    if (!result.ok) {
      const message = runScriptDisplayError(result);
      errors.push({ target: gatewayName, error: result.error });
      return {
        "Gateway": gatewayName,
        "Memory Statistics": { value: message, multiline: true },
        "CPU Statistics": { value: message, multiline: true }
      };
    }

    const output = runScriptOutputText(result);
    const parts = splitGaiaCombinedOutput(output);
    const memory = parts.section("CPSTAT_MEMORY");
    const cpu = parts.section("CPSTAT_CPU");
    if (!memory || !cpu) {
      errors.push({ target: gatewayName, error: { error: "One or more cpstat sizing sections returned no data." } });
    }
    return {
      "Gateway": gatewayName,
      "Memory Statistics": { value: memory ? formatCpstatMemoryForDisplay(memory) : "No memory statistics returned", multiline: true },
      "CPU Statistics": { value: cpu || "No CPU statistics returned", multiline: true }
    };
  }));

  rows.sort((a, b) => String(a.Gateway || "").localeCompare(String(b.Gateway || "")));
  return {
    ok: errors.length === 0,
    command: "run-script/cpstat-os-memory-cpu",
    rows,
    errors
  };
}

function formatCpstatMemoryForDisplay(output) {
  const bytesPerGb = 1024 ** 3;
  return String(output || "").split(/\r?\n/).map((line) => {
    const match = line.match(/^(.*)\(Bytes\):\s*([\d,]+)\s*$/i);
    if (!match) return line;
    const bytes = Number(match[2].replaceAll(",", ""));
    if (!Number.isFinite(bytes)) return line;
    return `${match[1]}(GB): ${(bytes / bytesPerGb).toFixed(2)}`;
  }).join("\n");
}

function cleanGaiaCliOutput(output) {
  return String(output || "")
    .split(/\r?\n/)
    .map((line) => line.replace(/(?:\S+\s+)?Config lock is owned by .*?lock database override.*?acquire the lock\.?/gi, "").trim())
    .filter((line) => {
      const token = normalizeToken(line);
      return !token.includes("lockdatabaseoverride") && !token.includes("configlockisowned");
    })
    .join("\n");
}

function gaiaAllowedClientRowsFromOutput(output) {
  const cleaned = cleanGaiaCliOutput(output).trim();
  if (gaiaOutputUnavailable(cleaned)) {
    return [{
      "Type": "Lookup failed",
      "IP Data": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE
    }];
  }
  if (!cleaned) {
    return [{
      "Type": "No allowed clients returned",
      "IP Data": "No output returned"
    }];
  }

  const lines = cleaned.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const rows = [];
  const addAllowedClientRow = (rawType, rawAddress, rawMask = "") => {
    const typeToken = normalizeToken(rawType);
    const address = String(rawAddress || "").trim();
    const mask = String(rawMask || "").trim();
    const isAny = normalizeToken(address) === "any";
    let displayType = rawType;
    let ipData = address;
    if (isAny) {
      displayType = "any";
      ipData = "Any IP address";
    } else if (typeToken === "host") {
      displayType = "ipv4 address";
    } else if (typeToken === "network") {
      displayType = "ipv4 netmask";
      ipData = mask ? `${address} / ${mask}` : address;
    } else if (typeToken === "range") {
      displayType = "ipv4 address range";
    }
    rows.push({
      "Type": isAny ? { value: displayType, tone: "critical" } : displayType,
      "IP Data": isAny ? { value: ipData, tone: "critical" } : ipData
    });
  };

  for (const line of lines) {
    if (/^type\s+address\s+mask\s+length$/i.test(line.replace(/\s+/g, " "))) continue;
    if (/^(?:[\w.-]+[>#])?\s*show\s+allowed-client\b/i.test(line)) continue;
    const parts = line.split(/\s{2,}/).filter(Boolean);
    if (parts.length >= 2 && /^(host|network|range)$/i.test(parts[0])) {
      addAllowedClientRow(parts[0], parts[1], parts[2] || "");
      continue;
    }
    const loose = line.match(/^(Host|Network|Range)\s+(.+?)(?:\s+(\d{1,2}))?$/i);
    if (loose) {
      addAllowedClientRow(loose[1], loose[2], loose[3] || "");
    }
  }

  const uniqueRows = [];
  const seen = new Set();
  for (const row of rows) {
    const key = stableJson({
      type: evidenceCellText(row.Type),
      ip: evidenceCellText(row["IP Data"])
    });
    if (seen.has(key)) continue;
    seen.add(key);
    uniqueRows.push(row);
  }

  return uniqueRows.length ? uniqueRows : [{
    "Type": "Raw Output",
    "IP Data": { value: cleaned, multiline: true }
  }];
}

function gaiaAllowedClientRowsAllowAny(rows = []) {
  return rows.some((row) => {
    const text = normalizeToken(`${evidenceCellText(row.Type)} ${evidenceCellText(row["IP Data"])}`);
    return text.includes("anyhost") || text.includes("anyipaddress") || text === "anyanyipaddress" || text.includes("0.0.0.0/0");
  });
}

function parseGaiaShowUsers(output) {
  const lines = cleanGaiaCliOutput(output)
    .split(/\r?\n/)
    .map((line) => line.replace(/\s+$/g, ""))
    .filter(Boolean);
  const headerIndex = lines.findIndex((line) => /\bUser\b/.test(line) && /\bUid\b/.test(line) && /\bPrivileges\b/.test(line));
  if (headerIndex === -1) {
    return [];
  }
  const header = lines[headerIndex];
  const labels = [
    "User",
    "Uid",
    "Gid",
    "Home Dir.",
    "Shell",
    "Real Name",
    "Privileges",
    "Is user locked out",
    "Two-Factor Authentication"
  ];
  function isHeaderLine(line) {
    return /\bUser\b/.test(line) && /\bUid\b/.test(line) && (/\bPrivileges\b/.test(line) || /\bShell\b/.test(line));
  }
  function normalizeRow(values) {
    return labels.reduce((row, label, index) => {
      row[label] = values[index] || "";
      return row;
    }, {});
  }
  const starts = labels
    .map((label) => ({ label, index: header.indexOf(label) }))
    .filter((item) => item.index >= 0)
    .sort((a, b) => a.index - b.index);
  if (starts.length < 4) {
    return [];
  }
  return lines.slice(headerIndex + 1)
    .filter((line) => line.trim() && !/^-+$/.test(line.trim()) && !isHeaderLine(line))
    .map((line) => {
      const spacedColumns = line.trim().split(/\s{2,}/);
      if (spacedColumns.length >= labels.length) {
        return normalizeRow(spacedColumns);
      }
      const row = {};
      for (let index = 0; index < starts.length; index += 1) {
        const current = starts[index];
        const next = starts[index + 1];
        row[current.label] = line.slice(current.index, next ? next.index : undefined).trim();
      }
      return normalizeRow(labels.map((label) => row[label] || ""));
    })
    .filter((row) => row.User && normalizeToken(row.User) !== "user");
}

function parseGaiaLoginSearchOutput(output, username, connectionType) {
  const cleaned = cleanGaiaCliOutput(output);
  const userToken = String(username || "").trim();
  const typePattern = connectionType === "ssh" ? "SSH connection" : "Web UI connection";
  const candidates = cleaned.split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && line.includes(`${typePattern} by ${userToken}`) && /was a success/i.test(line));

  const parsed = candidates.map((line) => {
    const clientIp = line.match(/\bclient IP\s+([0-9a-fA-F:.]+)/i)?.[1] || "Unknown IP";
    const explicitDate = line.match(/\bat\s+(\d{1,2}:\d{2})\s+(\d{1,2}-[A-Za-z]{3}-\d{4})\b/);
    const syslogDate = line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\b/);
    const displayDate = explicitDate ? `${explicitDate[2]} ${explicitDate[1]}` : (syslogDate ? syslogDate[1] : "Unknown date");
    const sortable = Date.parse(displayDate.replace(/(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{1,2}:\d{2})/, "$2 $1 $3 $4"));
    return {
      display: `${displayDate} / ${clientIp}`,
      sortable: Number.isNaN(sortable) ? 0 : sortable
    };
  });

  parsed.sort((a, b) => b.sortable - a.sortable);
  return parsed[0]?.display || "No successful login found";
}

const GAIA_RECOMMENDED_SHELL = "/etc/cli.sh";
const GAIA_DIRECT_EXPERT_SHELL = "/bin/bash";

function gaiaShellText(row) {
  return evidenceCellText(row?.Shell).trim();
}

function gaiaPrivilegesText(row) {
  return evidenceCellText(row?.Privileges).trim();
}

function gaiaUserText(row) {
  return evidenceCellText(row?.User).trim();
}

function gaiaTwoFactorText(row) {
  return evidenceCellText(row?.["Two-Factor Authentication"]).trim();
}

function gaiaUserHasDirectExpertShell(row) {
  return normalizeToken(gaiaShellText(row)) === normalizeToken(GAIA_DIRECT_EXPERT_SHELL);
}

function gaiaUserHasExpertPrivilege(row) {
  return normalizeToken(gaiaPrivilegesText(row)).includes("accesstoexpertfeatures");
}

function gaiaUserUsesRecommendedShell(row) {
  return normalizeToken(gaiaShellText(row)) === normalizeToken(GAIA_RECOMMENDED_SHELL);
}

function gaiaDisplayUserRows(rows = [], loginLookups = {}) {
  return rows.map((row) => {
    const shell = gaiaShellText(row);
    const directExpertShell = gaiaUserHasDirectExpertShell(row);
    const usesRecommendedShell = gaiaUserUsesRecommendedShell(row);
    const username = gaiaUserText(row);
    const displayRow = {
      ...row,
      "Recommended Shell": shell && !usesRecommendedShell ? GAIA_RECOMMENDED_SHELL : "",
      "Locked Out": row["Is user locked out"] || "",
      "2FA": row["Two-Factor Authentication"] || "",
      "Last WebUI Login": loginLookups.webui?.[username] || "No successful login found",
      "Last SSH Login": loginLookups.ssh?.[username] || "No successful login found"
    };
    if (directExpertShell) {
      displayRow.Shell = { value: shell, tone: "critical" };
      displayRow.Privileges = { value: "User has direct Expert Shell", tone: "critical" };
    }
    return displayRow;
  });
}

function gaiaRunScriptTargets(session, gatewaysResult, gatewaysAndServersResult) {
  const errors = [];
  const targets = [];
  if (gatewaysResult.ok) {
    (gatewaysResult.objects || [])
      .filter((gateway) => gateway?.name || gateway?.uid)
      .forEach((gateway) => {
        const gatewayName = gateway.name || gateway.NAME || gateway.uid;
        targets.push({
          name: gatewayName,
          uid: gateway.uid || "",
          title: `Gateway Name: ${gatewayName}`,
          gateway
        });
      });
  } else {
    errors.push({ target: "gateway-inventory", error: gatewaysResult.error });
  }

  const management = resolveManagementRunScriptTarget(session, gatewaysAndServersResult);
  const managementName = management.name || (management.smart1Cloud ? "" : (managementLoginHost(session) || session.baseUrl));
  if (managementName) {
    const duplicate = targets.find((target) => (
      (management.object?.uid && target.uid === management.object.uid) ||
      normalizeToken(target.name) === normalizeToken(managementName)
    ));
    if (duplicate) {
      duplicate.title = `Management Name: ${managementName}`;
      duplicate.useMdsSession = Boolean(management.configured);
    } else {
      targets.unshift({
        name: managementName,
        uid: management.object?.uid || "",
        title: `Management Name: ${managementName}`,
        useMdsSession: Boolean(management.configured)
      });
    }
  }

  return {
    targets,
    errors,
    error: gatewaysResult.error || gatewaysAndServersResult?.error || { error: "No Gaia OS targets were returned." }
  };
}

async function collectGaiaAdministratorSettingsEvidence(session, gatewaysResult, gatewaysAndServersResult) {
  const columns = ["User", "Shell", "Recommended Shell", "Real Name", "Privileges", "Locked Out", "2FA", "Last WebUI Login", "Last SSH Login"];
  const { targets, errors, error } = gaiaRunScriptTargets(session, gatewaysResult, gatewaysAndServersResult);
  if (!targets.length) {
    return {
      ok: false,
      command: "run-script/show-users",
      error,
      evidenceTables: []
    };
  }
  const evidenceTables = await Promise.all(targets.map(async (target) => {
    const script = [
      "printf '\\n__CPBPS_SHOW_USERS__\\n'",
      "show_users_output=\"$(clish -c \"show users\")\"",
      "printf '%s\\n' \"$show_users_output\"",
      "printf '%s\\n' \"$show_users_output\" | awk 'BEGIN{seen=0} /^[[:space:]]*User[[:space:]]+Uid[[:space:]]+Gid/{seen=1; next} seen && NF {print $1}' | while read gaia_user; do",
      "  [ -n \"$gaia_user\" ] || continue",
      "  printf '\\n__CPBPS_WEBUI_LOGIN__ %s\\n' \"$gaia_user\"",
      "  clish -c \"show syslog logs search \\\"Web UI connection by $gaia_user\\\"\"",
      "  printf '\\n__CPBPS_SSH_LOGIN__ %s\\n' \"$gaia_user\"",
      "  clish -c \"show syslog logs search \\\"SSH connection by $gaia_user\\\"\"",
      "done"
    ].join("\n");
    const result = await runScriptWithTaskDetails(mdsRunScriptSession(session, target), {
      "script-name": "check admin",
      targets: [target.name],
      script
    });
    if (!result.ok) {
      errors.push({ target: target.name, error: result.error });
      return {
        title: target.title,
        columns,
        rows: [{
          "User": "Lookup failed",
          "Uid": "",
          "Gid": "",
          "Home Dir.": "",
          "Shell": "",
          "Recommended Shell": "",
          "Real Name": "",
          "Privileges": runScriptDisplayError(result),
          "Is user locked out": "",
          "Two-Factor Authentication": ""
        }]
      };
    }
    const output = runScriptOutputText(result);
    const parts = splitGaiaCombinedOutput(output);
    const rows = parseGaiaShowUsers(parts.section("SHOW_USERS"));
    const loginLookups = gaiaLoginLookupsFromParts(parts);
    return {
      title: target.title,
      columns,
      rows: rows.length ? gaiaDisplayUserRows(rows, loginLookups) : [gaiaNoUsersRow(gaiaOutputUnavailable(output) ? GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE : undefined)]
    };
  }));
  return {
    ok: errors.length === 0,
    command: "run-script/show-users",
    evidenceTables,
    errors
  };
}

function parseGaiaPasswordControls(output) {
  const text = cleanGaiaCliOutput(output);
  const findValue = (label) => {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = text.match(new RegExp(`^\\s*${escaped}\\s+(.+?)\\s*$`, "mi"));
    return match ? match[1].trim() : "Not returned";
  };
  const enabledDisabled = (value) => {
    const token = normalizeToken(value);
    if (token === "on" || token === "yes" || token === "true" || token === "enabled") return "Enabled";
    if (token === "off" || token === "no" || token === "false" || token === "disabled") return "Disabled";
    return value || "Not returned";
  };
  const twoFactorMatch = text.match(/Configuration Two-Factor Authentication\s*\n\s*(.+?)\s*(?:\n\s*\n|$)/i);
  return {
    "Minimum Password Length": findValue("Minimum Password Length"),
    "Disallow Palindromes": enabledDisabled(findValue("Password Palindrome Check")),
    "Password Complexity": findValue("Password Complexity"),
    "Check for Password Reuse": enabledDisabled(findValue("Password History Checking")),
    "Password History Length": findValue("Password History Length"),
    "Password Expiration Lifetime": findValue("Password Expiration Lifetime"),
    "Password Expiration Lockout Days": findValue("Password Expiration Lockout Days"),
    "Deny Access to Unused Accounts": enabledDisabled(findValue("Deny Access to Unused Accounts")),
    "Days Nonuse Before Lockout": findValue("Days Nonuse Before Lockout"),
    "Deny Access After Failed Attempts": enabledDisabled(findValue("Deny Access After Failed Attempts")),
    "Block admin on fail attempt (except on console)": enabledDisabled(findValue("Block admin on fail attempt (except on console)")),
    "Maximum Failed Attempts": findValue("Maximum Failed Attempts"),
    "Unlock User After Seconds": findValue("Unlock User After Seconds"),
    "Password hashing algorithm": findValue("Password hashing algorithm"),
    "Configuration Two-Factor Authentication": twoFactorMatch ? twoFactorMatch[1].trim() : "Not returned"
  };
}

function firstNumber(value) {
  const match = String(value || "").match(/-?\d+/);
  return match ? Number(match[0]) : null;
}

function isNeverOrNotReturned(value) {
  const token = normalizeToken(value);
  return token === "never" || token === "not returned" || token === "";
}

function isDisabledValue(value) {
  const token = normalizeToken(value);
  return token === "disabled" || token === "off" || token === "no" || token === "false" || token.includes("not required");
}

function gaiaPasswordRecommendation(setting, value) {
  const recommendations = {
    "Minimum Password Length": "10",
    "Disallow Palindromes": "Enabled",
    "Password Complexity": "4",
    "Check for Password Reuse": "Enabled",
    "Password History Length": "30",
    "Password Expiration Lifetime": "90 days",
    "Password Expiration Lockout Days": "1 day",
    "Deny Access to Unused Accounts": "Enabled",
    "Days Nonuse Before Lockout": "30",
    "Deny Access After Failed Attempts": "Enabled",
    "Block admin on fail attempt (except on console)": "Enabled",
    "Maximum Failed Attempts": "5",
    "Unlock User After Seconds": "7200",
    "Password hashing algorithm": "SHA512",
    "Configuration Two-Factor Authentication": "Enabled"
  };
  const recommended = recommendations[setting] || "";
  const numericValue = firstNumber(value);
  const lowerThan = (threshold) => numericValue !== null && numericValue < threshold;
  const higherThan = (threshold) => numericValue !== null && numericValue > threshold;
  const token = normalizeToken(value);
  let critical = false;

  if (setting === "Minimum Password Length") critical = lowerThan(10);
  if (setting === "Disallow Palindromes") critical = isDisabledValue(value);
  if (setting === "Password Complexity") critical = lowerThan(4);
  if (setting === "Check for Password Reuse") critical = isDisabledValue(value);
  if (setting === "Password History Length") critical = higherThan(30);
  if (setting === "Password Expiration Lifetime") critical = isNeverOrNotReturned(value) || lowerThan(90);
  if (setting === "Password Expiration Lockout Days") critical = isNeverOrNotReturned(value) || higherThan(1);
  if (setting === "Deny Access to Unused Accounts") critical = isDisabledValue(value);
  if (setting === "Days Nonuse Before Lockout") critical = higherThan(30);
  if (setting === "Deny Access After Failed Attempts") critical = isDisabledValue(value);
  if (setting === "Block admin on fail attempt (except on console)") critical = isDisabledValue(value);
  if (setting === "Maximum Failed Attempts") critical = higherThan(5);
  if (setting === "Unlock User After Seconds") critical = lowerThan(7200);
  if (setting === "Password hashing algorithm") critical = token === "sha256";
  if (setting === "Configuration Two-Factor Authentication") critical = isDisabledValue(value);

  return critical ? { value: recommended, tone: "critical" } : recommended;
}

function gaiaInlineOutput(output) {
  const values = cleanGaiaCliOutput(output)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  return uniqueStrings(values).join(" | ") || "Not returned";
}

function gaiaSnmpStatusValue(output) {
  const text = cleanGaiaCliOutput(output).trim();
  const token = normalizeToken(text);
  if (token.includes("enabled")) return "Enabled";
  if (token.includes("disabled")) return "Disabled";
  return gaiaInlineOutput(text);
}

function gaiaSnmpInterfacesOutput(output) {
  const text = cleanGaiaCliOutput(output)
    .replace(/Enabled\s+SNMP\s+Agent\s+Interfaces\s+are/gi, "")
    .replace(/\bare\s*,?/gi, "");
  const interfaces = uniqueStrings(text
    .split(/[\r\n|,]+/)
    .map((item) => item.trim())
    .filter((item) => item && !/^-+$/.test(item))
    .filter((item) => !normalizeToken(item).includes("enabledsnmpagentinterfaces")));
  return interfaces.join(" | ") || "Not returned";
}

function gaiaSnmpUsmUsernames(output) {
  const lines = cleanGaiaCliOutput(output)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const names = lines.flatMap((line) => {
    const match = line.match(/^Usm\s+User\s+(.+)$/i);
    const name = match?.[1]?.trim() || "";
    return name && !/\s/.test(name) ? [name] : [];
  });
  return uniqueStrings(names);
}

function gaiaSnmpUsmUserDetail(output, username) {
  const text = cleanGaiaCliOutput(output);
  const findValue = (label) => {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = text.match(new RegExp(`(?:^|[,;]\\s*)${escaped}:?\\s+([^,;\\n]+)`, "mi"));
    return match ? match[1].trim() : "Not returned";
  };
  const usernameValue = findValue("Username");
  const lines = [
    `Username: ${usernameValue === "Not returned" ? username : usernameValue}`,
    `Permissions: ${findValue("Permissions")}`,
    `Security Level: ${findValue("Security Level")}`,
    `Authentication Type: ${findValue("Authentication Type")}`,
    `Privacy Type: ${findValue("Privacy Type")}`
  ];
  const criticalLines = lines.filter((line) => {
    const auth = line.match(/^Authentication Type:\s*(.+)$/i);
    if (auth) return normalizeToken(auth[1]) !== "sha512";
    const privacy = line.match(/^Privacy Type:\s*(.+)$/i);
    if (privacy) return normalizeToken(privacy[1]) !== "aes256";
    return false;
  });
  return {
    value: lines.join("\n"),
    criticalLines
  };
}

function evidenceCellText(value) {
  if (value && typeof value === "object") {
    return String(value.value || value.label || "");
  }
  return String(value || "");
}

function gaiaSnmpRecommendation(row) {
  if (normalizeToken(row["SNMP Status"]) !== "enabled") return "";
  const warnings = [];
  if (normalizeToken(evidenceCellText(row["SNMP Agent Version"])) !== "v3only") {
    warnings.push("SNMP Version should be set to v3-Only.");
  }
  if (normalizeToken(evidenceCellText(row["SNMP Interfaces"])) === "any") {
    warnings.push("SNMP interfaces should be limited to internal interfaces. It is currently set to ANY interface.");
  }
  const usmDetails = evidenceCellText(row["SNMP USM User Details"]);
  const authMatches = [...usmDetails.matchAll(/Authentication Type:\s*([^\n]+)/gi)].map((match) => match[1].trim());
  const privacyMatches = [...usmDetails.matchAll(/Privacy Type:\s*([^\n]+)/gi)].map((match) => match[1].trim());
  if (authMatches.some((value) => normalizeToken(value) !== "sha512")) {
    warnings.push("SNMPv3 USM authentication should use SHA512.");
  }
  if (privacyMatches.some((value) => normalizeToken(value) !== "aes256")) {
    warnings.push("SNMPv3 USM privacy encryption should use AES256.");
  }
  return warnings.length ? { value: uniqueStrings(warnings).join("\n"), tone: "critical", multiline: true } : "";
}

function escapeClishDoubleQuotedValue(value) {
  return String(value || "").replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

async function collectGaiaSnmpHardeningEvidence(session, gatewaysResult, gatewaysAndServersResult) {
  const columns = ["SNMP Status", "SNMP Agent Version", "SNMP Interfaces", "SNMP USM User Details", "Check Point Recommended"];
  const { targets, errors, error } = gaiaRunScriptTargets(session, gatewaysResult, gatewaysAndServersResult);
  if (!targets.length) {
    return {
      ok: false,
      command: "run-script/show-snmp",
      error,
      evidenceTables: []
    };
  }

  async function runSnmpCommand(target, command) {
    const result = await runScriptWithTaskDetails(mdsRunScriptSession(session, target), {
      "script-name": "pull SNMP Config",
      targets: [target.name],
      script: `clish -c "${command}"`
    });
    if (!result.ok) {
      errors.push({ target: target.name, command, error: result.error });
      return { ok: false, value: runScriptDisplayError(result) };
    }
    return {
      ok: true,
      value: runScriptOutputText(result)
    };
  }

  const evidenceTables = await Promise.all(targets.map(async (target) => {
    const statusResult = await runSnmpCommand(target, "show snmp agent");
    if (!statusResult.ok) {
      return {
        title: target.title,
        columns,
        rows: [{
          "SNMP Status": "Lookup failed",
          "SNMP Agent Version": "N/A",
          "SNMP Interfaces": "N/A",
          "SNMP USM User Details": statusResult.value || GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE,
          "Check Point Recommended": ""
        }]
      };
    }

    const status = gaiaSnmpStatusValue(statusResult.value);
    if (normalizeToken(status) === "disabled") {
      return {
        title: target.title,
        columns,
        rows: [{
          "SNMP Status": "Disabled",
          "SNMP Agent Version": "N/A",
          "SNMP Interfaces": "N/A",
          "SNMP USM User Details": "N/A",
          "Check Point Recommended": ""
        }]
      };
    }

    const [versionResult, interfacesResult, usmUsersResult] = await Promise.all([
      runSnmpCommand(target, "show snmp agent-version"),
      runSnmpCommand(target, "show snmp interfaces"),
      runSnmpCommand(target, "show snmp usm users")
    ]);
    let usmUserDetails = "No SNMP USM users returned";
    if (!usmUsersResult.ok) {
      usmUserDetails = "Lookup failed";
    } else {
      const usernames = gaiaSnmpUsmUsernames(usmUsersResult.value);
      if (usernames.length) {
        const detailResults = await Promise.all(usernames.map(async (username) => {
          const detailResult = await runSnmpCommand(target, `show snmp usm user ${escapeClishDoubleQuotedValue(username)}`);
          return detailResult.ok
            ? gaiaSnmpUsmUserDetail(detailResult.value, username)
            : { value: `Username: ${username}\nLookup failed`, criticalLines: [`Username: ${username}`, "Lookup failed"] };
        }));
        usmUserDetails = {
          value: detailResults.map((detail) => detail.value).join("\n\n"),
          multiline: true,
          criticalLines: detailResults.flatMap((detail) => detail.criticalLines || [])
        };
      }
    }
    return {
      title: target.title,
      columns,
      rows: [(() => {
        const snmpInterfaces = interfacesResult.ok ? gaiaSnmpInterfacesOutput(interfacesResult.value) : "Lookup failed";
        const row = {
        "SNMP Status": status || "Not returned",
        "SNMP Agent Version": versionResult.ok ? gaiaInlineOutput(versionResult.value) : "Lookup failed",
        "SNMP Interfaces": normalizeToken(snmpInterfaces) === "any" ? { value: snmpInterfaces, tone: "critical" } : snmpInterfaces,
        "SNMP USM User Details": usmUserDetails
        };
        row["Check Point Recommended"] = gaiaSnmpRecommendation(row);
        return row;
      })()]
    };
  }));

  return {
    ok: errors.length === 0,
    command: "run-script/show-snmp",
    evidenceTables,
    errors
  };
}

async function collectGaiaPasswordPolicyEvidence(session, gatewaysResult, gatewaysAndServersResult) {
  const columns = ["Setting", "Value", "Check Point Recommended"];
  const { targets, errors, error } = gaiaRunScriptTargets(session, gatewaysResult, gatewaysAndServersResult);
  if (!targets.length) {
    return {
      ok: false,
      command: "run-script/show-password-controls",
      error,
      evidenceTables: []
    };
  }
  const evidenceTables = await Promise.all(targets.map(async (target) => {
    const result = await runScriptWithTaskDetails(mdsRunScriptSession(session, target), {
      "script-name": "check pass",
      targets: [target.name],
      script: "clish -c \"show password-controls all\""
    });
    if (!result.ok) {
      errors.push({ target: target.name, error: result.error });
      return {
        title: target.title,
        columns,
        rows: [{
          "Setting": "Lookup failed",
          "Value": runScriptDisplayError(result),
          "Check Point Recommended": ""
        }]
      };
    }
    const output = runScriptOutputText(result);
    if (gaiaOutputUnavailable(output)) {
      return {
        title: target.title,
        columns,
        rows: [{
          "Setting": "Lookup failed",
          "Value": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE,
          "Check Point Recommended": ""
        }]
      };
    }
    const parsed = parseGaiaPasswordControls(output);
    return {
      title: target.title,
      columns,
      rows: Object.entries(parsed).map(([setting, value]) => ({
        "Setting": setting,
        "Value": value,
        "Check Point Recommended": gaiaPasswordRecommendation(setting, value)
      }))
    };
  }));
  return {
    ok: errors.length === 0,
    command: "run-script/show-password-controls",
    evidenceTables,
    errors
  };
}

function gaiaSyslogForwardingValue(output) {
  if (gaiaOutputUnavailable(output)) return GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE;
  const text = cleanGaiaCliOutput(output);
  const token = normalizeToken(text);
  if (token.includes("enabled")) return "Yes";
  if (token.includes("disabled")) return "No";
  return "Not returned";
}

function gaiaManagementSyslogForwardingValue(output) {
  if (isRunScriptGatewayAccessFailure(output)) return GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE;
  const text = cleanGaiaCliOutput(output).trim();
  const token = normalizeToken(text);
  if (token.includes("no database items for log remote addresses")) {
    return "No Forwarding Server Configured";
  }
  const addresses = uniqueStrings(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []);
  if (addresses.length) {
    return `Syslog is Forwarding to ${addresses.join(", ")}`;
  }
  return "No Forwarding Server Configured";
}

function gaiaExternalSyslogDetails(output) {
  if (gaiaOutputUnavailable(output)) {
    return {
      forwarding: "Lookup failed",
      configuration: GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE,
      configurationTable: null
    };
  }
  const configuration = cleanGaiaCliOutput(output).trim();
  const token = normalizeToken(configuration);
  if (!configuration || token.includes("nodatabaseitemsforlogremoteaddresses")) {
    return {
      forwarding: "No",
      configuration: "No Forwarding Server Configured",
      configurationTable: null
    };
  }
  const configurationFields = [
    "Remote Address",
    "Levels",
    "Port",
    "Protocol",
    "Queuing Method Mechanism",
    "TLS Encryption",
    "Authentication Mode"
  ];
  const lines = configuration.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const headerIndex = lines.findIndex((line) => /^Remote\s+Addr\s+Levels\s+Port\s+Protocol/i.test(line));
  const rows = (headerIndex >= 0 ? lines.slice(headerIndex + 1) : lines)
    .map((line) => line.split(/\s+/))
    .filter((parts) => {
      if (parts.length < 6 || />$/.test(parts[0])) return false;
      const first = normalizeToken(parts[0]);
      const second = normalizeToken(parts[1]);
      return !(first === "remote" && (second === "addr" || second === "address"));
    })
    .map((parts) => ({
      "Remote Address": parts[0] || "",
      "Levels": parts[1] || "",
      "Port": parts[2] || "",
      "Protocol": parts[3] || "",
      "Queuing Method Mechanism": parts[4] || "",
      "TLS Encryption": parts[5] || "",
      "Authentication Mode": parts.slice(6).join(" ") || "-"
    }));
  const configurationRows = rows.flatMap((row) => configurationFields.map((field) => ({
    "Column Title": field,
    "Information": row[field]
  })));
  return {
    forwarding: "Yes",
    configuration,
    configurationTable: configurationRows.length ? {
      columns: ["Column Title", "Information"],
      rows: configurationRows
    } : null
  };
}

async function collectGaiaSystemLoggingEvidence(session, gatewaysResult, gatewaysAndServersResult) {
  const { targets: allTargets, errors, error } = gaiaRunScriptTargets(session, gatewaysResult, gatewaysAndServersResult);
  const targets = allTargets.filter((target) => !String(target.title || "").startsWith("Management Name:"));
  if (!targets.length) {
    return {
      ok: false,
      command: "run-script/show-syslog-cplogs/show-syslog-log-remote-addresses",
      error: error || { error: "No Security Gateway Gaia OS targets were returned." },
      rows: []
    };
  }
  const script = [
    "printf '\\n__CPBPS_SYSLOG_CPLOGS__\\n'",
    "clish -c \"show syslog cplogs\"",
    "printf '\\n__CPBPS_SYSLOG_REMOTE_ADDRESSES__\\n'",
    "clish -c \"show syslog log-remote-addresses\""
  ].join("\n");
  const rows = await Promise.all(targets.map(async (target) => {
    const result = await runScriptWithTaskDetails(mdsRunScriptSession(session, target), {
      "script-name": "check syslog forwarding",
      targets: [target.name],
      script
    });
    if (!result.ok) {
      errors.push({ target: target.name, error: result.error });
      const message = runScriptDisplayError(result);
      return {
        "Name": target.name,
        "Syslog Forwarding To Manager": message,
        "Gateway Forwarding To External Server": "Lookup failed",
        "External Syslog Configuration": message,
        "External Syslog Configuration Table": null
      };
    }
    const parts = splitGaiaCombinedOutput(runScriptOutputText(result));
    const external = gaiaExternalSyslogDetails(parts.section("SYSLOG_REMOTE_ADDRESSES"));
    return {
      "Name": target.name,
      "Syslog Forwarding To Manager": gaiaSyslogForwardingValue(parts.section("SYSLOG_CPLOGS")),
      "Gateway Forwarding To External Server": external.forwarding,
      "External Syslog Configuration": external.configuration,
      "External Syslog Configuration Table": external.configurationTable
    };
  }));
  return {
    ok: errors.length === 0,
    command: "run-script/show-syslog-cplogs/show-syslog-log-remote-addresses",
    rows,
    errors
  };
}

async function collectGaiaManagementExternalSyslogEvidence(session, gatewaysAndServersResult) {
  const management = resolveManagementRunScriptTarget(session, gatewaysAndServersResult);
  if (management.smart1Cloud && !management.name) {
    return {
      ok: true,
      command: "run-script/show-syslog-log-remote-addresses",
      skipped: true,
      rows: [{
        "Name": "Smart-1 Cloud",
        "Syslog Forwarding": "Smart-1 Cloud hosted management; Gaia external syslog lookup is not available from the tenant API context."
      }],
      errors: []
    };
  }
  const managementName = management.name || managementLoginHost(session) || session.baseUrl;
  const errors = [];
  if (!managementName) {
    return {
      ok: false,
      command: "run-script/show-syslog-log-remote-addresses",
      error: { error: "Management server object could not be resolved." },
      rows: []
    };
  }

  const result = await runScriptWithTaskDetails(mdsRunScriptSession(session, management), {
    "script-name": "check management syslog forwarding",
    targets: [managementName],
    script: "clish -c \"show syslog log-remote-addresses\""
  });
  if (!result.ok) {
    errors.push({ target: managementName, error: result.error });
    return {
      ok: false,
      command: "run-script/show-syslog-log-remote-addresses",
      rows: [{
        "Name": managementName,
        "Syslog Forwarding": runScriptDisplayError(result)
      }],
      errors
    };
  }

  return {
    ok: true,
    command: "run-script/show-syslog-log-remote-addresses",
    rows: [{
      "Name": managementName,
      "Syslog Forwarding": gaiaManagementSyslogForwardingValue(runScriptOutputText(result))
    }],
    errors
  };
}

function gaiaCombinedCollectionScript() {
  return [
    "printf '\\n__CPBPS_ALLOWED_CLIENTS__\\n'",
    "clish -c \"show allowed-client all\"",
    "printf '\\n__CPBPS_SHOW_USERS__\\n'",
    "show_users_output=\"$(clish -c \"show users\")\"",
    "printf '%s\\n' \"$show_users_output\"",
    "printf '%s\\n' \"$show_users_output\" | awk 'BEGIN{seen=0} /^[[:space:]]*User[[:space:]]+Uid[[:space:]]+Gid/{seen=1; next} seen && NF {print $1}' | while read gaia_user; do",
    "  [ -n \"$gaia_user\" ] || continue",
    "  printf '\\n__CPBPS_WEBUI_LOGIN__ %s\\n' \"$gaia_user\"",
    "  clish -c \"show syslog logs search \\\"Web UI connection by $gaia_user\\\"\"",
    "  printf '\\n__CPBPS_SSH_LOGIN__ %s\\n' \"$gaia_user\"",
    "  clish -c \"show syslog logs search \\\"SSH connection by $gaia_user\\\"\"",
    "done",
    "printf '\\n__CPBPS_PASSWORD_CONTROLS__\\n'",
    "clish -c \"show password-controls all\"",
    "printf '\\n__CPBPS_SYSLOG_CPLOGS__\\n'",
    "clish -c \"show syslog cplogs\"",
    "printf '\\n__CPBPS_SYSLOG_REMOTE_ADDRESSES__\\n'",
    "clish -c \"show syslog log-remote-addresses\"",
    "printf '\\n__CPBPS_SNMP_AGENT__\\n'",
    "clish -c \"show snmp agent\"",
    "printf '\\n__CPBPS_SNMP_AGENT_VERSION__\\n'",
    "clish -c \"show snmp agent-version\"",
    "printf '\\n__CPBPS_SNMP_INTERFACES__\\n'",
    "clish -c \"show snmp interfaces\"",
    "printf '\\n__CPBPS_SNMP_USM_USERS__\\n'",
    "snmp_users=\"$(clish -c \"show snmp usm users\")\"",
    "printf '%s\\n' \"$snmp_users\"",
    "printf '%s\\n' \"$snmp_users\" | awk '/^Usm User /{print $3}' | while read snmp_user; do",
    "  [ -n \"$snmp_user\" ] || continue",
    "  printf '\\n__CPBPS_SNMP_USM_USER__ %s\\n' \"$snmp_user\"",
    "  clish -c \"show snmp usm user $snmp_user\"",
    "done",
    "printf '\n__CPBPS_LICENSE_STATUS__\n'",
    "clish -c 'show license status'",
    "printf '\n__CPBPS_CPSTAT_MEMORY__\n'",
    "cpstat os -f memory",
    "printf '\n__CPBPS_CPSTAT_CPU__\n'",
    "cpstat os -f cpu"
  ].join("\n");
}

function splitGaiaCombinedOutput(output) {
  const sections = new Map();
  const usmUserSections = [];
  const webuiLoginSections = [];
  const sshLoginSections = [];
  let current = null;
  let currentUser = "";
  for (const line of cleanGaiaCliOutput(output).split(/\r?\n/)) {
    const marker = line.match(/^__CPBPS_([A-Z0-9_]+)__\s*(.*)$/);
    if (marker) {
      current = marker[1];
      currentUser = marker[2]?.trim() || "";
      if (current === "SNMP_USM_USER") {
        usmUserSections.push({ username: currentUser, lines: [] });
      } else if (current === "WEBUI_LOGIN") {
        webuiLoginSections.push({ username: currentUser, lines: [] });
      } else if (current === "SSH_LOGIN") {
        sshLoginSections.push({ username: currentUser, lines: [] });
      } else if (!sections.has(current)) {
        sections.set(current, []);
      }
      continue;
    }
    if (!current) continue;
    if (current === "SNMP_USM_USER") {
      usmUserSections[usmUserSections.length - 1]?.lines.push(line);
    } else if (current === "WEBUI_LOGIN") {
      webuiLoginSections[webuiLoginSections.length - 1]?.lines.push(line);
    } else if (current === "SSH_LOGIN") {
      sshLoginSections[sshLoginSections.length - 1]?.lines.push(line);
    } else {
      sections.get(current)?.push(line);
    }
  }
  return {
    section: (name) => (sections.get(name) || []).join("\n").trim(),
    usmUserSections,
    webuiLoginSections,
    sshLoginSections
  };
}

function gaiaLoginLookupsFromParts(parts) {
  const webui = {};
  const ssh = {};
  for (const section of parts.webuiLoginSections || []) {
    if (!section.username) continue;
    webui[section.username] = parseGaiaLoginSearchOutput(section.lines.join("\n"), section.username, "webui");
  }
  for (const section of parts.sshLoginSections || []) {
    if (!section.username) continue;
    ssh[section.username] = parseGaiaLoginSearchOutput(section.lines.join("\n"), section.username, "ssh");
  }
  return { webui, ssh };
}

function gaiaNoUsersRow(message = GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE) {
  return {
    "User": "No users returned",
    "Uid": "",
    "Gid": "",
    "Home Dir.": "",
    "Shell": "",
    "Recommended Shell": "",
    "Real Name": "",
    "Privileges": message,
    "Is user locked out": "",
    "Two-Factor Authentication": "",
    "Locked Out": "",
    "2FA": "",
    "Last WebUI Login": "",
    "Last SSH Login": ""
  };
}

function gaiaLookupFailedUsersRow(message = GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE) {
  return {
    "User": "Lookup failed",
    "Uid": "",
    "Gid": "",
    "Home Dir.": "",
    "Shell": "",
    "Recommended Shell": "",
    "Real Name": "",
    "Privileges": message,
    "Is user locked out": "",
    "Two-Factor Authentication": "",
    "Locked Out": "",
    "2FA": "",
    "Last WebUI Login": "",
    "Last SSH Login": ""
  };
}

function gaiaPasswordRowsFromOutput(output) {
  const parsed = parseGaiaPasswordControls(output);
  return Object.entries(parsed).map(([setting, value]) => ({
    "Setting": setting,
    "Value": value,
    "Check Point Recommended": gaiaPasswordRecommendation(setting, value)
  }));
}

function gaiaSnmpRowFromCombinedSections(parts) {
  const status = gaiaSnmpStatusValue(parts.section("SNMP_AGENT"));
  if (normalizeToken(status) === "disabled") {
    return {
      "SNMP Status": "Disabled",
      "SNMP Agent Version": "N/A",
      "SNMP Interfaces": "N/A",
      "SNMP USM User Details": "N/A",
      "Check Point Recommended": ""
    };
  }

  let usmUserDetails = "No SNMP USM users returned";
  const usernames = gaiaSnmpUsmUsernames(parts.section("SNMP_USM_USERS"));
  if (usernames.length) {
    const detailResults = usernames.map((username) => {
      const detailSection = parts.usmUserSections.find((section) => section.username === username);
      return detailSection
        ? gaiaSnmpUsmUserDetail(detailSection.lines.join("\n"), username)
        : { value: `Username: ${username}\nLookup failed`, criticalLines: [`Username: ${username}`, "Lookup failed"] };
    });
    usmUserDetails = {
      value: detailResults.map((detail) => detail.value).join("\n\n"),
      multiline: true,
      criticalLines: detailResults.flatMap((detail) => detail.criticalLines || [])
    };
  }

  const snmpInterfaces = gaiaSnmpInterfacesOutput(parts.section("SNMP_INTERFACES"));
  const row = {
    "SNMP Status": status || "Not returned",
    "SNMP Agent Version": gaiaInlineOutput(parts.section("SNMP_AGENT_VERSION")),
    "SNMP Interfaces": normalizeToken(snmpInterfaces) === "any" ? { value: snmpInterfaces, tone: "critical" } : snmpInterfaces,
    "SNMP USM User Details": usmUserDetails
  };
  row["Check Point Recommended"] = gaiaSnmpRecommendation(row);
  return row;
}

async function collectGaiaFullScanEvidence(session, gatewaysResult, gatewaysAndServersResult) {
  const allowedClientColumns = ["Type", "IP Data"];
  const adminColumns = ["User", "Shell", "Recommended Shell", "Real Name", "Privileges", "Locked Out", "2FA", "Last WebUI Login", "Last SSH Login"];
  const passwordColumns = ["Setting", "Value", "Check Point Recommended"];
  const snmpColumns = ["SNMP Status", "SNMP Agent Version", "SNMP Interfaces", "SNMP USM User Details", "Check Point Recommended"];
  const { targets, errors, error } = gaiaRunScriptTargets(session, gatewaysResult, gatewaysAndServersResult);
  if (!targets.length) {
    const empty = {
      ok: false,
      error,
      errors,
      evidenceTables: []
    };
    return {
      allowedHostAccess: { ...empty, command: "run-script/show-allowed-client" },
      administratorSettings: { ...empty, command: "run-script/show-users" },
      passwordPolicy: { ...empty, command: "run-script/show-password-controls" },
      snmpMonitoring: { ...empty, command: "run-script/show-snmp" },
      systemLogging: { ok: false, command: "run-script/show-syslog-cplogs", error, rows: [], errors },
      securityFeatureUsage: { ok: false, command: "run-script/show-license-status", error, rows: [], evidenceTables: [], errors },
      sizingStatistics: { ok: false, command: "run-script/cpstat-os-memory-cpu", error, rows: [], errors },
      managementExternalSyslog: { ok: false, command: "run-script/show-syslog-log-remote-addresses", error, rows: [], errors }
    };
  }

  const allowedClientTables = [];
  const adminTables = [];
  const passwordTables = [];
  const snmpTables = [];
  const syslogRows = [];
  const licenseTableResults = [];
  const sizingRows = [];
  const managementSyslogRows = [];
  const licenseErrors = [];
  const sizingErrors = [];
  const managementSyslogErrors = [];
  const script = gaiaCombinedCollectionScript();

  await Promise.all(targets.map(async (target) => {
    const result = await runScriptWithTaskDetails(mdsRunScriptSession(session, target), {
      "script-name": "collect Gaia hardening evidence",
      targets: [target.name],
      script
    });
    if (!result.ok) {
      errors.push({ target: target.name, error: result.error });
      if (!String(target.title || "").startsWith("Management Name:")) {
        licenseErrors.push({ target: target.name, error: result.error });
        sizingErrors.push({ target: target.name, error: result.error });
      } else {
        managementSyslogErrors.push({ target: target.name, error: result.error });
      }
      const message = runScriptDisplayError(result);
      allowedClientTables.push({ title: target.title, columns: allowedClientColumns, rows: [{ "Type": "Lookup failed", "IP Data": message }] });
      adminTables.push({ title: target.title, columns: adminColumns, rows: [gaiaLookupFailedUsersRow(message)] });
      passwordTables.push({ title: target.title, columns: passwordColumns, rows: [{ "Setting": "Lookup failed", "Value": message, "Check Point Recommended": "" }] });
      snmpTables.push({ title: target.title, columns: snmpColumns, rows: [{ "SNMP Status": "Lookup failed", "SNMP Agent Version": "N/A", "SNMP Interfaces": "N/A", "SNMP USM User Details": message, "Check Point Recommended": "" }] });
      if (!String(target.title || "").startsWith("Management Name:")) {
        syslogRows.push({
          "Name": target.name,
          "Syslog Forwarding To Manager": message,
          "Gateway Forwarding To External Server": "Lookup failed",
          "External Syslog Configuration": message,
          "External Syslog Configuration Table": null
        });
        const licenseRows = [{
          "Object Name": target.name,
          "License Feature": "Lookup failed",
          "Expiration Date": message,
          "Enabled/Disabled": "Not returned"
        }];
        licenseTableResults.push({ rows: licenseRows, table: {
          title: `Gateway Name: ${target.name}`,
          compact: true,
          columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
          rows: licenseRows.map((row) => ({
            "License Feature": row["License Feature"],
            "Expiration Date": row["Expiration Date"],
            "Enabled/Disabled": row["Enabled/Disabled"]
          }))
        } });
        sizingRows.push({
          "Gateway": target.name,
          "Memory Statistics": { value: message, multiline: true },
          "CPU Statistics": { value: message, multiline: true }
        });
      } else {
        managementSyslogRows.push({ "Name": target.name, "Syslog Forwarding": message });
      }
      return;
    }

    const output = runScriptOutputText(result);
    if (gaiaOutputUnavailable(output)) {
      errors.push({ target: target.name, error: { error: GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE } });
      if (!String(target.title || "").startsWith("Management Name:")) {
        licenseErrors.push({ target: target.name, error: { error: GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE } });
        sizingErrors.push({ target: target.name, error: { error: GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE } });
      } else {
        managementSyslogErrors.push({ target: target.name, error: { error: GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE } });
      }
      allowedClientTables.push({ title: target.title, columns: allowedClientColumns, rows: [{ "Type": "Lookup failed", "IP Data": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE }] });
      adminTables.push({ title: target.title, columns: adminColumns, rows: [gaiaLookupFailedUsersRow()] });
      passwordTables.push({ title: target.title, columns: passwordColumns, rows: [{ "Setting": "Lookup failed", "Value": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE, "Check Point Recommended": "" }] });
      snmpTables.push({ title: target.title, columns: snmpColumns, rows: [{ "SNMP Status": "Lookup failed", "SNMP Agent Version": "N/A", "SNMP Interfaces": "N/A", "SNMP USM User Details": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE, "Check Point Recommended": "" }] });
      if (!String(target.title || "").startsWith("Management Name:")) {
        syslogRows.push({
          "Name": target.name,
          "Syslog Forwarding To Manager": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE,
          "Gateway Forwarding To External Server": "Lookup failed",
          "External Syslog Configuration": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE,
          "External Syslog Configuration Table": null
        });
        const licenseRows = [{
          "Object Name": target.name,
          "License Feature": "Lookup failed",
          "Expiration Date": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE,
          "Enabled/Disabled": "Not returned"
        }];
        licenseTableResults.push({ rows: licenseRows, table: {
          title: `Gateway Name: ${target.name}`,
          compact: true,
          columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
          rows: licenseRows.map((row) => ({
            "License Feature": row["License Feature"],
            "Expiration Date": row["Expiration Date"],
            "Enabled/Disabled": row["Enabled/Disabled"]
          }))
        } });
        sizingRows.push({
          "Gateway": target.name,
          "Memory Statistics": { value: GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE, multiline: true },
          "CPU Statistics": { value: GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE, multiline: true }
        });
      } else {
        managementSyslogRows.push({ "Name": target.name, "Syslog Forwarding": GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE });
      }
      return;
    }
    const parts = splitGaiaCombinedOutput(output);
    allowedClientTables.push({
      title: target.title,
      columns: allowedClientColumns,
      rows: gaiaAllowedClientRowsFromOutput(parts.section("ALLOWED_CLIENTS"))
    });
    const userRows = parseGaiaShowUsers(parts.section("SHOW_USERS"));
    const loginLookups = gaiaLoginLookupsFromParts(parts);
    adminTables.push({
      title: target.title,
      columns: adminColumns,
      rows: userRows.length ? gaiaDisplayUserRows(userRows, loginLookups) : [gaiaNoUsersRow()]
    });
    passwordTables.push({
      title: target.title,
      columns: passwordColumns,
      rows: gaiaPasswordRowsFromOutput(parts.section("PASSWORD_CONTROLS"))
    });
    snmpTables.push({
      title: target.title,
      columns: snmpColumns,
      rows: [gaiaSnmpRowFromCombinedSections(parts)]
    });
    if (!String(target.title || "").startsWith("Management Name:")) {
      const external = gaiaExternalSyslogDetails(parts.section("SYSLOG_REMOTE_ADDRESSES"));
      syslogRows.push({
        "Name": target.name,
        "Syslog Forwarding To Manager": gaiaSyslogForwardingValue(parts.section("SYSLOG_CPLOGS")),
        "Gateway Forwarding To External Server": external.forwarding,
        "External Syslog Configuration": external.configuration,
        "External Syslog Configuration Table": external.configurationTable
      });
      const parsedLicenseRows = parseLicenseStatusFeatures(parts.section("LICENSE_STATUS"));
      const licenseRows = parsedLicenseRows.length
        ? parsedLicenseRows.map((row) => ({
          "Object Name": target.name,
          ...row,
          "Enabled/Disabled": licenseFeatureEnabledState(row._licenseCode, target.gateway || {})
        }))
        : [{
          "Object Name": target.name,
          "License Feature": "No license features returned",
          "Expiration Date": "Not returned",
          "Enabled/Disabled": "Not returned"
        }];
      if (!parsedLicenseRows.length) {
        licenseErrors.push({ target: target.name, error: { error: "No license features parsed from show license status output." } });
      }
      licenseTableResults.push({ rows: licenseRows, table: {
        title: `Gateway Name: ${target.name}`,
        compact: true,
        columns: ["License Feature", "Expiration Date", "Enabled/Disabled"],
        rows: licenseRows.map((row) => ({
          "License Feature": row["License Feature"],
          "Expiration Date": row["Expiration Date"],
          "Enabled/Disabled": row["Enabled/Disabled"]
        })).sort((a, b) => String(a["License Feature"] || "").localeCompare(String(b["License Feature"] || "")))
      } });
      const memory = parts.section("CPSTAT_MEMORY");
      const cpu = parts.section("CPSTAT_CPU");
      if (!memory || !cpu) {
        sizingErrors.push({ target: target.name, error: { error: "One or more cpstat sizing sections returned no data." } });
      }
      sizingRows.push({
        "Gateway": target.name,
        "Memory Statistics": { value: memory ? formatCpstatMemoryForDisplay(memory) : "No memory statistics returned", multiline: true },
        "CPU Statistics": { value: cpu || "No CPU statistics returned", multiline: true }
      });
    } else {
      managementSyslogRows.push({
        "Name": target.name,
        "Syslog Forwarding": gaiaManagementSyslogForwardingValue(parts.section("SYSLOG_REMOTE_ADDRESSES"))
      });
    }
  }));

  const byTitle = (a, b) => String(a.title || "").localeCompare(String(b.title || ""));
  allowedClientTables.sort(byTitle);
  adminTables.sort(byTitle);
  passwordTables.sort(byTitle);
  snmpTables.sort(byTitle);
  syslogRows.sort((a, b) => String(a.Name || "").localeCompare(String(b.Name || "")));
  const licenseRows = licenseTableResults.flatMap((result) => result.rows || []).sort((a, b) => (
    String(a["Object Name"] || "").localeCompare(String(b["Object Name"] || "")) ||
    String(a["License Feature"] || "").localeCompare(String(b["License Feature"] || ""))
  ));
  const licenseTables = licenseTableResults.map((result) => result.table).filter(Boolean).sort(byTitle);
  sizingRows.sort((a, b) => String(a.Gateway || "").localeCompare(String(b.Gateway || "")));

  return {
    allowedHostAccess: {
      ok: errors.length === 0,
      error: errors.length ? compactLookupErrors(errors) : undefined,
      command: "run-script/show-allowed-client",
      evidenceTables: allowedClientTables,
      errors
    },
    administratorSettings: {
      ok: errors.length === 0,
      error: errors.length ? compactLookupErrors(errors) : undefined,
      command: "run-script/show-users",
      evidenceTables: adminTables,
      errors
    },
    passwordPolicy: {
      ok: errors.length === 0,
      error: errors.length ? compactLookupErrors(errors) : undefined,
      command: "run-script/show-password-controls",
      evidenceTables: passwordTables,
      errors
    },
    snmpMonitoring: {
      ok: errors.length === 0,
      error: errors.length ? compactLookupErrors(errors) : undefined,
      command: "run-script/show-snmp",
      evidenceTables: snmpTables,
      errors
    },
    systemLogging: {
      ok: errors.length === 0,
      error: errors.length ? compactLookupErrors(errors) : undefined,
      command: "run-script/show-syslog-cplogs/show-syslog-log-remote-addresses",
      rows: syslogRows,
      errors
    },
    securityFeatureUsage: {
      ok: licenseErrors.length === 0,
      error: licenseErrors.length ? compactLookupErrors(licenseErrors) : undefined,
      command: "run-script/show-license-status",
      rows: licenseRows,
      evidenceTables: licenseTables,
      errors: licenseErrors
    },
    sizingStatistics: {
      ok: sizingErrors.length === 0,
      error: sizingErrors.length ? compactLookupErrors(sizingErrors) : undefined,
      command: "run-script/cpstat-os-memory-cpu",
      rows: sizingRows,
      errors: sizingErrors
    },
    managementExternalSyslog: {
      ok: managementSyslogErrors.length === 0,
      error: managementSyslogErrors.length ? compactLookupErrors(managementSyslogErrors) : undefined,
      command: "run-script/show-syslog-log-remote-addresses",
      rows: managementSyslogRows,
      errors: managementSyslogErrors
    }
  };
}

function evaluateJumboHotfixAccumulator(result, session) {
  const reviewHistory = appHistory.reviews.get("updates.jumbo-hotfix") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const recommendedCount = (result.rows || []).filter((row) => row["Available Recommended Update"] === "Yes").length;
  const noDataCount = (result.rows || []).filter((row) => Object.values(row).some((value) => value === "Gateway Returns No Data")).length;
  const allRowsNoData = Boolean(result.rows?.length) && noDataCount === result.rows.length;
  return makeCheck({
    id: "updates.jumbo-hotfix",
    category: "Updates, Health, and Ongoing Protection",
    title: "Upgrade To Latest Recommended Jumbo Hotfix Accumulator",
    recommendation: "Check Point periodically releases Jumbo Hotfix Accumulators (JHFs) for each supported version. These releases consolidate stability fixes, reliability improvements, performance enhancements, and security related corrections into a tested and supported package. Running the recommended Jumbo Hotfix Accumulator is a foundational hardening step and should be treated as a baseline requirement for production Security Gateways and Management Servers.",
    status: allRowsNoData ? "unknown" : (reviewedThisLogin ? "reviewed" : (recommendedCount ? "remediation-recommended" : "needs-review")),
    severity: recommendedCount ? "high" : "medium",
    evidence: result.rows?.length
      ? `${result.rows.length} gateway${result.rows.length === 1 ? "" : "s"} checked for recommended Jumbo Hotfix Accumulator availability. ${recommendedCount} recommended update${recommendedCount === 1 ? "" : "s"} found.`
      : "No gateway software package evidence was returned.",
    evidenceTable: result.rows?.length ? {
      columns: ["Name of Gateway", "Currently Installed Version", "Available Recommended Update", "Category", "Recommended Upgrade Package"],
      rows: result.rows
    } : null,
    details: "Delaying adoption of recommended Jumbo Hotfix Accumulators increases operational risk, reduces platform resilience, and limits the effectiveness of other hardening controls described in this document. Recommended Jumbo Hotfix Accumulator Takes include important security and stability fixes that reduce exposure to known issues.",
    detailRows: [{
      label: "Details",
      text: "Check Point recommends operating at or above the recommended major version + jumbo hot fix as noted in SK95746.",
      bold: ["Check Point recommends operating at or above the recommended major version + jumbo hot fix as noted in SK95746."],
      links: [{ label: "SK95746", url: "https://support.checkpoint.com/results/sk/sk95746" }]
    }],
    source: "Hardening guide: Updates, Health, and Ongoing Protection",
    commands: ["show-gateways-and-servers: name,version", "show-software-packages-per-targets: display.installed any, display.recommended any, targets.1 Gateway_Object_NAME"],
    review: !allRowsNoData && result.rows?.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateSecurityFeatureUsage(result, session) {
  const reviewHistory = appHistory.reviews.get("security-feature-usage.licensed-blades") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedRows = (result.rows || []).filter((row) => normalizeToken(row["License Feature"]).includes("lookupfailed"));
  const noDataRows = (result.rows || []).filter((row) => Object.values(row).some((value) => value === "Gateway Returns No Data"));
  const allRowsNoData = Boolean(result.rows?.length) && noDataRows.length === result.rows.length;
  return makeCheck({
    id: "security-feature-usage.licensed-blades",
    category: "Security Feature Usage",
    title: "Licensed Blades vs Active Blades",
    recommendation: "Review licensed security blades and contract expiration dates for each managed gateway. Confirm licensed capabilities match the blades currently enabled in policy and on the gateway.",
    status: allRowsNoData || failedRows.length ? "unknown" : (reviewedThisLogin ? "reviewed" : "needs-review"),
    severity: "medium",
    evidence: result.rows?.length
      ? `${result.rows.length} licensed feature row${result.rows.length === 1 ? "" : "s"} returned across managed gateways.`
      : "No license feature evidence was returned.",
    evidenceTables: result.evidenceTables?.length ? result.evidenceTables : null,
    details: "The license output shows which blade/license features are present and whether those features are perpetual or tied to a contract expiration. Review these against the active blades in the environment.",
    source: "Hardening review: Security Feature Usage",
    commands: ["run-script: clish -c \"show license status\""],
    review: !allRowsNoData && result.rows?.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateSizingStatistics(result) {
  return makeCheck({
    id: "security-feature-usage.sizing-statistics",
    category: "Security Feature Usage",
    title: "Sizing Statistics",
    recommendation: "Review the current CPU and memory statistics for each gateway as a point-in-time sizing indicator. Compare these readings with sustained utilization, traffic growth, enabled blades, and the applicable Check Point sizing guidance before making capacity decisions.",
    status: result.rows?.length && result.ok ? "informational" : "unknown",
    severity: "info",
    evidence: result.rows?.length
      ? `Current CPU and memory statistics were requested from ${result.rows.length} gateway${result.rows.length === 1 ? "" : "s"}.`
      : "No gateway sizing statistics were returned.",
    evidenceTable: result.rows?.length ? {
      columns: ["Gateway", "Memory Statistics", "CPU Statistics"],
      rows: result.rows
    } : null,
    details: "These cpstat readings are a live snapshot and are intended to support engineering review. Memory byte values are displayed in GB using 1 GB = 1,073,741,824 bytes. These readings should not be treated as a substitute for trend data or sustained performance monitoring.",
    source: "Engineering review: Security Feature Usage - Sizing Statistics",
    commands: ["run-script: cpstat os -f memory", "run-script: cpstat os -f cpu"]
  });
}

function objectDisplayName(value) {
  if (value === undefined || value === null) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map(objectDisplayName).filter(Boolean).join(", ");
  }
  if (typeof value === "object") {
    return value.name || value.uid || value.type || JSON.stringify(value);
  }
  return String(value);
}

function objectNames(value) {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) {
    return value.flatMap(objectNames);
  }
  if (typeof value === "object") {
    return [value.name, value.uid, value.type].filter(Boolean).map(String);
  }
  return [String(value)];
}

function isAnyObject(value) {
  return objectNames(value).some((name) => normalizeToken(name) === "any");
}

function fieldContainsGateway(value, gateway) {
  return fieldContainsObjectRef(value, gateway);
}

function objectRefTokens(refs = []) {
  return refs
    .flatMap((ref) => [ref?.name, ref?.NAME, ref?.uid, ref?.UID])
    .filter(Boolean)
    .map(normalizeToken);
}

function fieldContainsObjectRef(value, refs) {
  const tokens = objectRefTokens(Array.isArray(refs) ? refs : [refs]);
  if (!tokens.length) return false;
  return objectNames(value).some((name) => tokens.includes(normalizeToken(name)));
}

function ruleField(rule, ...keys) {
  for (const key of keys) {
    const value = getByNormalizedKey(rule, key);
    if (value !== undefined) return value;
  }
  return undefined;
}

function accessRuleNumber(rule, fallback = "") {
  return rule["rule-number"] ?? rule.ruleNumber ?? rule.position ?? fallback ?? "";
}

function compositeAccessRuleNumber(parentRuleNumber, childRuleNumber) {
  const parent = String(parentRuleNumber ?? "").trim();
  const child = String(childRuleNumber ?? "").trim();
  return parent && child ? `${parent}.${child}` : child || parent;
}

function accessRuleParentRuleNumber(ruleNumber) {
  const value = String(ruleNumber ?? "").trim();
  if (!value.includes(".")) return "";
  const parts = value.split(".").map((part) => part.trim()).filter(Boolean);
  return parts.length > 1 ? parts[0] : "";
}

function accessRuleLogStatus(rule) {
  const track = ruleField(rule, "track", "log", "logging") ?? "";
  if (track === true) return "Enabled";
  if (track === false) return "Disabled";
  if (typeof track === "object" && track) {
    if (track.type && typeof track.type === "object") {
      return track.type.name || track.type.NAME || track.type.uid || objectDisplayName(track.type);
    }
    return track.name || track.NAME || track.type || track["accounting"] || objectDisplayName(track);
  }
  return objectDisplayName(track);
}

function accessRuleLayerName(rule, fallback = "") {
  const layer = rule.layer || rule["access-layer"] || rule["layer-name"];
  if (typeof layer === "object" && layer) {
    return layer.name || layer.uid || fallback;
  }
  return layer || fallback;
}

function accessRuleLayerUid(rule, fallback = "") {
  const layer = rule.layer || rule["access-layer"];
  if (typeof layer === "object" && layer) {
    return layer.uid || fallback;
  }
  return fallback;
}

function policyPackageLabel(layerName, layerUid, packageLookup) {
  const packageInfo = packageLookup.get(layerUid) || packageLookup.get(normalizeToken(layerName));
  const packageName = packageInfo?.packageName || "";
  const accessPolicyName = packageInfo?.layerName || layerName || layerUid || "Unknown";
  return packageName
    ? `Policy Package: ${packageName} Access Policy: ${accessPolicyName}`
    : `Access-Policy: ${layerName || layerUid || "Unknown"}`;
}

function accessLayerParentInfo(layer = {}) {
  const parentLayer = layer["parent-layer"] || layer.parentLayer || layer.parent || "";
  if (!parentLayer) {
    return { parentLayerUid: "", parentLayerName: "" };
  }
  if (typeof parentLayer === "object") {
    const parentType = normalizeToken(parentLayer.type || parentLayer["domain-type"] || "");
    const looksLikeAccessLayer = parentType.includes("accesslayer") || parentType.includes("access-layer");
    const parentLayerUid = looksLikeAccessLayer ? String(parentLayer.uid || "") : "";
    const parentLayerName = looksLikeAccessLayer ? String(parentLayer.name || parentLayer.NAME || "") : "";
    return { parentLayerUid, parentLayerName };
  }
  return { parentLayerUid: String(parentLayer || ""), parentLayerName: "" };
}

function buildAccessLayerPackageLookup(packagesResult) {
  const lookup = new Map();
  if (!packagesResult?.ok) {
    return lookup;
  }
  function remember(layer, packageName) {
    if (!layer || !packageName) return;
    if (typeof layer === "string") {
      lookup.set(layer, { packageName, layerName: "" });
      lookup.set(normalizeToken(layer), { packageName, layerName: "" });
      return;
    }
    if (typeof layer !== "object") return;
    const layerUid = layer.uid || "";
    const layerName = layer.name || layer.NAME || "";
    const { parentLayerUid, parentLayerName } = accessLayerParentInfo(layer);
    const info = { packageName, layerName, parentLayerUid, parentLayerName };
    if (layerUid) lookup.set(layerUid, info);
    if (layerName) lookup.set(normalizeToken(layerName), info);
  }
  function rememberNestedAccessLayers(value, packageName, path = []) {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        const childPath = [...path, String(index)];
        if (normalizeToken(path.at(-1)).includes("accesslayer")) {
          remember(item, packageName);
        }
        rememberNestedAccessLayers(item, packageName, childPath);
      });
      return;
    }
    if (value.type && normalizeToken(value.type).includes("accesslayer")) {
      remember(value, packageName);
      return;
    }
    for (const [key, child] of Object.entries(value)) {
      rememberNestedAccessLayers(child, packageName, [...path, key]);
    }
  }
  for (const policyPackage of packagesResult.objects || []) {
    const packageName = policyPackage.name || policyPackage.NAME || policyPackage.uid || "";
    const layers = [
      ...(Array.isArray(policyPackage["access-layers"]) ? policyPackage["access-layers"] : []),
      ...(Array.isArray(policyPackage.accessLayers) ? policyPackage.accessLayers : []),
      ...(Array.isArray(policyPackage.layers) ? policyPackage.layers : [])
    ];
    for (const layer of layers) {
      remember(layer, packageName);
    }
    rememberNestedAccessLayers(policyPackage, packageName);
  }
  return lookup;
}

function accessLayersFromPackages(packagesResult, options = {}) {
  const layers = [];
  const seen = new Set();
  if (!packagesResult?.ok) {
    return layers;
  }
  function remember(layer, packageName) {
    if (!layer || !packageName) return;
    if (typeof layer === "string") {
      const key = `string:${layer}`;
      if (seen.has(key)) return;
      seen.add(key);
      layers.push({ uid: layer, name: layer, packageName, parentLayerUid: "", parentLayerName: "" });
      return;
    }
    if (typeof layer !== "object") return;
    const uid = String(layer.uid || "");
    const name = String(layer.name || layer.NAME || uid || "");
    if (!uid && !name) return;
    const { parentLayerUid, parentLayerName } = accessLayerParentInfo(layer);
    const key = options.preservePackageOccurrences
      ? `${normalizeToken(packageName)}:${uid || normalizeToken(name)}`
      : (uid || `${packageName}:${normalizeToken(name)}`);
    if (seen.has(key)) return;
    seen.add(key);
    layers.push({ uid, name, packageName, parentLayerUid, parentLayerName });
  }
  function walk(value, packageName, path = []) {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (normalizeToken(path.at(-1)).includes("accesslayer")) {
          remember(item, packageName);
        }
        walk(item, packageName, [...path, String(index)]);
      });
      return;
    }
    if (value.type && normalizeToken(value.type).includes("accesslayer")) {
      remember(value, packageName);
      return;
    }
    for (const [key, child] of Object.entries(value)) {
      walk(child, packageName, [...path, key]);
    }
  }
  for (const policyPackage of packagesResult.objects || []) {
    const packageName = policyPackage.name || policyPackage.NAME || policyPackage.uid || "";
    const packageLayers = [
      ...(Array.isArray(policyPackage["access-layers"]) ? policyPackage["access-layers"] : []),
      ...(Array.isArray(policyPackage.accessLayers) ? policyPackage.accessLayers : []),
      ...(Array.isArray(policyPackage.layers) ? policyPackage.layers : [])
    ];
    for (const layer of packageLayers) {
      remember(layer, packageName);
    }
    walk(policyPackage, packageName);
  }
  return layers;
}

function flattenAccessRulebaseRules(rulebase = []) {
  const rules = [];
  function walk(items) {
    for (const item of Array.isArray(items) ? items : []) {
      if (!item || typeof item !== "object") continue;
      if (normalizeToken(item.type) === "accessrule") {
        rules.push(item);
        continue;
      }
      if (Array.isArray(item.rulebase)) {
        walk(item.rulebase);
      }
    }
  }
  walk(rulebase);
  return rules;
}

function accessRuleDisabledCell(rule) {
  const enabled = rule?.enabled ?? rule?.Enabled;
  if (enabled === false || normalizeToken(enabled) === "false") {
    return { value: "Disabled", tone: "critical" };
  }
  return "";
}

function accessRuleSummary(rule, gateway, layerName, layerUid = "", packageLookup = new Map(), ruleNumber = "", options = {}) {
  const source = ruleField(rule, "source", "sources") ?? "";
  const destination = ruleField(rule, "destination", "destinations") ?? "";
  const service = ruleField(rule, "service", "services") ?? "";
  const action = ruleField(rule, "action") ?? "";
  const actionName = objectDisplayName(action);
  const destinationRefs = options.destinationRefs?.length ? options.destinationRefs : [gateway];
  const logStatus = accessRuleLogStatus(rule);
  const stealthMatch = isAnyObject(source)
    && fieldContainsObjectRef(destination, destinationRefs)
    && isAnyObject(service)
    && normalizeToken(actionName) === "drop";
  const resolvedLayerName = accessRuleLayerName(rule, layerName) || "Unknown";
  const resolvedLayerUid = accessRuleLayerUid(rule, layerUid);
  return {
    policyName: policyPackageLabel(resolvedLayerName, resolvedLayerUid, packageLookup),
    layerName: resolvedLayerName,
    row: {
      "Gateway": gateway.name || gateway.uid || "",
      "Rule #": options.displayRuleNumber || accessRuleNumber(rule, ruleNumber),
      "Disabled": accessRuleDisabledCell(rule),
      "Rule Name": rule.name || "",
      "Source": objectDisplayName(source),
      "Destination": objectDisplayName(destination),
      "Service": objectDisplayName(service),
      "Action": actionName,
      "Log": logStatus,
      "Stealth Rule": stealthMatch ? "Yes" : "No"
    },
    stealthMatch
  };
}

function accessRuleEvidenceRow(rule, objectName, ruleNumber = "", options = {}) {
  const source = ruleField(rule, "source", "sources") ?? "";
  const destination = ruleField(rule, "destination", "destinations") ?? "";
  const service = ruleField(rule, "service", "services") ?? "";
  const action = ruleField(rule, "action") ?? "";
  return {
    ...(options.includeGateway === false ? {} : { "Gateway": objectName || "" }),
    "Rule #": accessRuleNumber(rule, ruleNumber),
    "Disabled": accessRuleDisabledCell(rule),
    "Rule Name": rule.name || "",
    "Source": objectDisplayName(source),
    "Destination": objectDisplayName(destination),
    "Services": objectDisplayName(service),
    "Action": objectDisplayName(action),
    "Log": accessRuleLogStatus(rule)
  };
}

function accessRuleLookupLayer(candidate) {
  return candidate?.layerUid || candidate?.layerName || "";
}

function accessRuleLookupRuleNumber(ruleNumber) {
  const value = String(ruleNumber ?? "").trim();
  if (!value.includes(".")) return value;
  const parts = value.split(".").map((part) => part.trim()).filter(Boolean);
  return parts[parts.length - 1] || value;
}

function objectDictionaryMap(data) {
  const map = new Map();
  for (const object of data?.["objects-dictionary"] || data?.objectsDictionary || []) {
    if (object?.uid) {
      map.set(String(object.uid), object);
    }
  }
  return map;
}

function dictionaryGroupsContainingRefs(dictionary, refs = []) {
  const refTokens = new Set(objectRefTokens(refs));
  if (!refTokens.size) return [];
  const groups = [];
  const seen = new Set();
  for (const object of dictionary?.values?.() || []) {
    const type = normalizeToken(object?.type || object?.["object-type"] || object?.objectType || "");
    if (!["group", "networkgroup", "groupwithexclusion"].includes(type)) continue;
    const objectText = normalizeToken(JSON.stringify(object));
    if (![...refTokens].some((token) => token && objectText.includes(token))) continue;
    const name = object.name || object.uid || "";
    if (!name) continue;
    const key = object.uid || normalizeToken(name);
    if (seen.has(key)) continue;
    seen.add(key);
    groups.push({ name: String(name), uid: String(object.uid || "") });
  }
  return groups;
}

function dereferenceRuleValue(value, dictionary) {
  if (Array.isArray(value)) {
    return value.map((item) => dereferenceRuleValue(item, dictionary));
  }
  if (typeof value === "string" && dictionary.has(value)) {
    return dictionary.get(value);
  }
  return value;
}

function accessRuleWithDictionary(rule, dictionary) {
  if (!dictionary?.size) return rule;
  const resolved = { ...rule };
  for (const key of ["source", "sources", "destination", "destinations", "service", "services", "action"]) {
    if (resolved[key] !== undefined) {
      resolved[key] = dereferenceRuleValue(resolved[key], dictionary);
    }
  }
  if (resolved.track && typeof resolved.track === "object" && resolved.track.type) {
    resolved.track = {
      ...resolved.track,
      type: dereferenceRuleValue(resolved.track.type, dictionary)
    };
  }
  return resolved;
}

async function fetchAccessRuleSummary(session, gateway, candidate, packageLookup, ruleNumber, options = {}) {
  const accessRule = await tryCommand(session, "show-access-rule", {
    "rule-number": accessRuleLookupRuleNumber(ruleNumber),
    layer: accessRuleLookupLayer(candidate),
    "details-level": "full"
  });
  if (!accessRule.ok) {
    return { ok: false, error: accessRule.error };
  }
  return {
    ok: true,
    summary: accessRuleSummary(accessRule.data || {}, gateway, candidate.layerName, candidate.layerUid, packageLookup, ruleNumber, {
      ...options,
      displayRuleNumber: options.displayRuleNumber || String(ruleNumber ?? "")
    })
  };
}

async function fetchAccessRuleEvidence(session, objectName, candidate, packageLookup, ruleNumber) {
  const accessRule = await tryCommand(session, "show-access-rule", {
    "rule-number": accessRuleLookupRuleNumber(ruleNumber),
    layer: accessRuleLookupLayer(candidate),
    "details-level": "full"
  });
  if (!accessRule.ok) {
    return { ok: false, error: accessRule.error };
  }
  const rule = accessRule.data || {};
  const resolvedLayerName = accessRuleLayerName(rule, candidate.layerName) || "Unknown";
  const resolvedLayerUid = accessRuleLayerUid(rule, candidate.layerUid);
  return {
    ok: true,
    policyName: policyPackageLabel(resolvedLayerName, resolvedLayerUid, packageLookup),
    row: accessRuleEvidenceRow(rule, objectName, ruleNumber, { includeGateway: false })
  };
}

function whereUsedDestinationCandidates(data, objectRef) {
  const candidates = [];
  const seen = new Set();
  const objectTokens = objectRefTokens([objectRef]);
  function pushCandidate(node, path) {
    if (!node || typeof node !== "object" || Array.isArray(node)) return;
    if (whereUsedNodeIsHttpsInspection(node, path)) return;
    const layerValue = node.layer || node["access-layer"] || node["access-layer-name"] || node["layer-name"];
    const layerName = typeof layerValue === "object" && layerValue ? layerValue.name || layerValue.uid : layerValue;
    const layerUid = typeof layerValue === "object" && layerValue ? layerValue.uid || "" : "";
    const position = node.position ?? node["rule-number"] ?? node.ruleNumber ?? node.number;
    const pathText = normalizeToken(path.join("."));
    const fieldText = normalizeToken([
      node.field,
      node.column,
      node["used-as"],
      node["used-in"],
      node["field-name"],
      node.context
    ].filter(Boolean).join(" "));
    const jsonText = normalizeToken(JSON.stringify(node));
    const destinationContext = pathText.includes("destination") || fieldText.includes("destination") || jsonText.includes("destination");
    const objectContext = fieldContainsObjectRef(node.destination || node.destinations || node.object || node["used-object"], objectRef)
      || objectTokens.some((token) => token && jsonText.includes(token));
    if (layerName && position !== undefined && position !== null && destinationContext && objectContext) {
      const key = `${layerUid || normalizeToken(layerName)}:${position}`;
      if (!seen.has(key)) {
        seen.add(key);
        candidates.push({
          layerName: String(layerName),
          layerUid: String(layerUid),
          ruleNumber: position,
          policyName: String(layerName)
        });
      }
    }
  }
  function walk(node, path = []) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, [...path, String(index)]));
      return;
    }
    pushCandidate(node, path);
    for (const [key, value] of Object.entries(node)) {
      walk(value, [...path, key]);
    }
  }
  walk(data);
  return candidates;
}

function whereUsedNodeIsHttpsInspection(node, path = []) {
  const context = normalizeToken([
    ...path,
    node?.type,
    node?.["object-type"],
    node?.objectType,
    node?.["rule-type"],
    node?.context
  ].filter(Boolean).join(" "));
  return context.includes("httpsrule")
    || context.includes("httpsinspection")
    || context.includes("tlsrule")
    || context.includes("sslinspection");
}

function whereUsedAccessRuleCandidates(data, objectRef) {
  const candidates = [];
  const seen = new Set();
  function pushCandidate(node, path) {
    if (!node || typeof node !== "object" || Array.isArray(node)) return;
    if (whereUsedNodeIsHttpsInspection(node, path)) return;
    const layerValue = node.layer || node["access-layer"] || node["access-layer-name"] || node["layer-name"];
    const layerName = typeof layerValue === "object" && layerValue ? layerValue.name || layerValue.uid : layerValue;
    const layerUid = typeof layerValue === "object" && layerValue ? layerValue.uid || "" : "";
    const position = node.position ?? node["rule-number"] ?? node.ruleNumber ?? node.number;
    const jsonText = normalizeToken(JSON.stringify(node));
    const accessRuleContext = jsonText.includes("accessrule") || jsonText.includes("rulebase") || layerName;
    if (layerName && position !== undefined && position !== null && accessRuleContext) {
      const key = `${layerUid || normalizeToken(layerName)}:${position}`;
      if (!seen.has(key)) {
        seen.add(key);
        candidates.push({
          layerName: String(layerName),
          layerUid: String(layerUid),
          ruleNumber: position
        });
      }
    }
  }
  function walk(node, path = []) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, [...path, String(index)]));
      return;
    }
    pushCandidate(node, path);
    for (const [key, value] of Object.entries(node)) {
      walk(value, [...path, key]);
    }
  }
  walk(data);
  return candidates;
}

function whereUsedGroupReferences(data, originalRef = {}) {
  const groups = [];
  const seen = new Set();
  const originalTokens = [originalRef.name, originalRef.uid].filter(Boolean).map(normalizeToken);
  function addGroup(node) {
    if (!node || typeof node !== "object" || Array.isArray(node)) return;
    const type = normalizeToken(node.type || node["object-type"] || node.objectType || "");
    const name = node.name || node.NAME || "";
    const uid = node.uid || node.UID || "";
    if (!name && !uid) return;
    if (!["group", "networkgroup", "groupwithexclusion"].includes(type)) return;
    if (type.includes("accessrule") || type.includes("accesslayer") || type.includes("package")) return;
    if (originalTokens.includes(normalizeToken(name)) || originalTokens.includes(normalizeToken(uid))) return;
    const key = uid || normalizeToken(name);
    if (seen.has(key)) return;
    seen.add(key);
    groups.push({ name: String(name || uid), uid: String(uid || "") });
  }
  function walk(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    addGroup(node);
    for (const value of Object.values(node)) {
      walk(value);
    }
  }
  walk(data);
  return groups;
}

function flattenNatRules(rulebase = []) {
  const rules = [];
  function walk(nodes) {
    for (const node of Array.isArray(nodes) ? nodes : []) {
      if (!node || typeof node !== "object") continue;
      const type = normalizeToken(node.type || "");
      if (Array.isArray(node.rulebase)) {
        walk(node.rulebase);
      }
      if (type === "natrule" || node["translated-destination"] !== undefined || node.translatedDestination !== undefined) {
        rules.push(node);
      }
    }
  }
  walk(rulebase);
  return rules;
}

function hyphenKeyToCamel(key) {
  return String(key || "").replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

function natRuleField(rule, ...keys) {
  for (const key of keys) {
    if (rule?.[key] !== undefined) return rule[key];
    const camelKey = hyphenKeyToCamel(key);
    if (rule?.[camelKey] !== undefined) return rule[camelKey];
  }
  return null;
}

function natObjectRefs(value) {
  const refs = [];
  const seen = new Set();
  function addRef(node) {
    if (!node || typeof node !== "object" || Array.isArray(node)) return;
    const name = node.name || node.NAME || "";
    const uid = node.uid || node.UID || "";
    const type = node.type || node.TYPE || "";
    if (!name && !uid) return;
    const key = uid || normalizeToken(name);
    if (seen.has(key)) return;
    seen.add(key);
    refs.push({ name: String(name || uid), uid: String(uid || ""), type: String(type || "") });
  }
  function walk(node) {
    if (!node) return;
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (typeof node !== "object") return;
    addRef(node);
    for (const child of Object.values(node)) {
      walk(child);
    }
  }
  walk(value);
  return refs;
}

function natOriginalDestinationObjectRefs(value) {
  return natObjectRefs(value).filter((ref) => {
    const type = normalizeToken(ref.type);
    const name = normalizeToken(ref.name);
    return name && name !== "any" && type !== "any" && !type.includes("service") && !type.includes("rule");
  });
}

function natValueMatchesManagement(value, target) {
  const targetTokens = [target?.name, target?.ref?.name, target?.ref?.uid, target?.ip]
    .filter(Boolean)
    .map(normalizeToken);
  const valueNames = objectNames(value).map(normalizeToken);
  const valueIps = allIpv4Values(value).map(normalizeToken);
  return valueNames.some((name) => targetTokens.includes(name))
    || valueIps.some((ip) => targetTokens.includes(ip))
    || targetTokens.includes(normalizeToken(objectDisplayName(value)));
}

function natRuleEvidenceRow(rule, packageName, matchedTarget) {
  return {
    "Package": packageName,
    "Rule #": accessRuleNumber(rule),
    "Disabled": accessRuleDisabledCell(rule),
    "Original Source": objectDisplayName(natRuleField(rule, "original-source", "source")),
    "Original Destination": objectDisplayName(natRuleField(rule, "original-destination", "destination")),
    "Original Service": objectDisplayName(natRuleField(rule, "original-service", "service")),
    "Translated Source": objectDisplayName(natRuleField(rule, "translated-source")),
    "Translated Destination": objectDisplayName(natRuleField(rule, "translated-destination")),
    "Translated Service": objectDisplayName(natRuleField(rule, "translated-service")),
    "Matched Management": matchedTarget?.name || matchedTarget?.ip || ""
  };
}

function natPackageNames(packagesResult) {
  if (!packagesResult?.ok) return [];
  return uniqueStrings((packagesResult.objects || []).map((object) => object.name || object.NAME).filter(Boolean));
}

function managementAutomaticNatRows(managementTargets) {
  return managementTargets.flatMap((target) => {
    const settings = target.object?.["nat-settings"] || target.object?.natSettings || null;
    if (!settings || typeof settings !== "object") return [];
    const autoRule = settings["auto-rule"] ?? settings.autoRule;
    const method = settings.method || settings["translation-method"] || settings.translationMethod || "";
    const translatedAddress = settings["ipv4-address"] || settings.ipv4Address || settings["translated-address"] || settings.translatedAddress || "";
    if (autoRule !== true && !method && !translatedAddress) return [];
    return [{
      "Management Object": target.name || target.ip || "",
      "Automatic NAT": autoRule === false ? "Disabled" : "Enabled",
      "Method": objectDisplayName(method) || "Not returned",
      "Translated Address": objectDisplayName(translatedAddress) || "Not returned",
      "Install On": objectDisplayName(settings["install-on"] || settings.installOn) || "Not returned"
    }];
  });
}

function getNestedValue(object, path) {
  return String(path || "").split(".").reduce((current, part) => current?.[part], object);
}

function cveCollectValues(value, predicate, path = "", matches = []) {
  if (matches.length >= 48) return matches;
  if (Array.isArray(value)) {
    value.forEach((item, index) => cveCollectValues(item, predicate, `${path}[${index}]`, matches));
    return matches;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      cveCollectValues(child, predicate, path ? `${path}.${key}` : key, matches);
      if (matches.length >= 48) break;
    }
    return matches;
  }
  if (predicate(path, value)) {
    matches.push({ path, value });
  }
  return matches;
}

function cveCollectObjects(value, predicate, path = "", matches = []) {
  if (matches.length >= 48) return matches;
  if (Array.isArray(value)) {
    value.forEach((item, index) => cveCollectObjects(item, predicate, `${path}[${index}]`, matches));
    return matches;
  }
  if (value && typeof value === "object") {
    if (predicate(path, value)) {
      matches.push({ path, value });
    }
    for (const [key, child] of Object.entries(value)) {
      cveCollectObjects(child, predicate, path ? `${path}.${key}` : key, matches);
      if (matches.length >= 48) break;
    }
  }
  return matches;
}

function cveEvidenceSummary(items, limit = 6) {
  return uniqueStrings(items.map((item) => item.value)).slice(0, limit).join(", ");
}

function cveGatewayParticipants(community) {
  const names = cveCollectValues(community, (path, value) => {
    const normalizedPath = normalizeToken(path);
    if (!normalizedPath.includes("gateway") || !normalizedPath.includes("name")) return false;
    if (typeof value !== "string") return false;
    if (!value || value.length > 180) return false;
    if (["domain", "simple-gateway", "CpmiCertificate"].includes(value)) return false;
    return true;
  });
  return uniqueStrings(names.map((item) => item.value)).slice(0, 12);
}

function cveNamedObjects(objects) {
  return Array.isArray(objects) ? uniqueStrings(objects.map((object) => object?.name)).slice(0, 12) : [];
}

function cveNamedObjectList(objects, emptyLabel = "No gateways returned.") {
  const names = cveNamedObjects(objects);
  return names.length ? names.join(", ") : emptyLabel;
}

function cveManagementLabelForGateway(gateway) {
  const normalizedType = normalizeToken(gateway?.type);
  if (normalizedType.includes("interoperable") || normalizedType.includes("externallymanaged") || normalizedType.includes("externalgateway")) {
    return "externally managed";
  }
  return "locally managed";
}

function cveGatewayLabels(objects) {
  return Array.isArray(objects)
    ? uniqueStrings(objects.filter((object) => object?.name).map((object) => `${object.name} (${cveManagementLabelForGateway(object)})`)).slice(0, 12)
    : [];
}

function cveStarParticipantSummary(centerGateways, satelliteGateways) {
  return {
    value: [
      `center-gateways: ${cveNamedObjectList(centerGateways, "No center gateways returned.")}`,
      `satellite-gateways: ${cveNamedObjectList(satelliteGateways, "No satellite gateways returned.")}`
    ].join("\n"),
    multiline: true
  };
}

function cveCertificateNames(community) {
  const names = cveCollectValues(community, (path, value) => {
    const normalizedPath = normalizeToken(path);
    if (!normalizedPath.includes("certificate") || !normalizedPath.includes("name")) return false;
    return typeof value === "string" && value.length <= 180;
  });
  return uniqueStrings(names.map((item) => item.value)).slice(0, 12);
}

function cveAuthSummaryForGateway(gateway) {
  const sharedSecretEvidence = cveCollectValues(gateway, (path, value) => {
    const normalizedPath = normalizeToken(path);
    const normalizedValue = normalizeToken(value);
    return normalizedPath.includes("sharedsecret")
      || normalizedValue.includes("sharedsecret")
      || normalizedPath.includes("usesharedsecret")
      || normalizedPath.includes("predefinedsecret")
      || normalizedPath.includes("preshared");
  });
  if (sharedSecretEvidence.length) return "Shared secret";
  const certificateEvidence = cveCollectValues(gateway, (path, value) => {
    const normalizedPath = normalizeToken(path);
    const normalizedValue = normalizeToken(value);
    return normalizedValue.includes("certificate")
      || (normalizedPath.includes("auth") && normalizedValue.includes("cert"))
      || (normalizedPath.includes("certificate") && String(value ?? "") !== "");
  });
  return certificateEvidence.length ? "Certificate" : "Not shown by API";
}

function cveSharedSecretExternalGateways(community) {
  if (community["use-shared-secret"] !== true || !Array.isArray(community["shared-secrets"])) {
    return [];
  }
  return community["shared-secrets"]
    .map((entry) => entry?.["external-gateway"])
    .filter((gateway) => gateway?.name)
    .map((gateway) => ({
      name: String(gateway.name),
      type: gateway.type || "external gateway",
      authentication: "Shared secret"
    }));
}

function cveExternalGateways(community) {
  const byName = new Map();
  for (const gateway of cveSharedSecretExternalGateways(community)) {
    byName.set(gateway.name, gateway);
  }
  const gatewayObjects = cveCollectObjects(community, (_path, value) => {
    const normalizedType = normalizeToken(value.type);
    if (!value.name || !value.uid || !value.type || normalizedType === "domain") return false;
    return normalizedType.includes("externallymanaged") || normalizedType.includes("externalgateway") || normalizedType.includes("interoperable");
  });
  for (const gateway of gatewayObjects) {
    const name = String(gateway.value.name);
    if (!byName.has(name)) {
      byName.set(name, {
        name,
        type: gateway.value.type || "external gateway",
        authentication: cveAuthSummaryForGateway(gateway.value)
      });
    }
  }
  return [...byName.values()];
}

function cveExternalGatewaySummary(externalGateways) {
  return externalGateways.length
    ? externalGateways.map((gateway) => `${gateway.name} (${gateway.authentication})`).join(", ")
    : "No externally managed gateways found.";
}

function evaluateCveSiteToSiteCommunity(community, type) {
  const ikeV1Evidence = cveCollectValues(community, (path, value) => {
    const combined = `${normalizeToken(path)} ${normalizeToken(value)}`;
    return combined.includes("ikev1") || combined.includes("ikeversion1");
  });
  const certificateEvidence = cveCollectValues(community, (path, value) => {
    const normalizedPath = normalizeToken(path);
    const normalizedValue = normalizeToken(value);
    return normalizedValue.includes("certificate")
      || (normalizedPath.includes("auth") && normalizedValue.includes("cert"))
      || (normalizedPath.includes("certificate") && String(value ?? "") !== "");
  });
  const externalGateways = type === "star" ? cveExternalGateways(community) : [];
  const usesIkeV1 = ikeV1Evidence.length > 0;
  const usesCertificateAuth = certificateEvidence.length > 0;
  const matchesCriteria = usesIkeV1 && usesCertificateAuth;
  const participantNames = type === "meshed" ? cveGatewayParticipants(community) : [];
  const centerGatewayNames = cveGatewayLabels(community["center-gateways"]);
  const satelliteGatewayNames = cveGatewayLabels(community["satellite-gateways"]);
  const meshedGatewayNames = cveNamedObjects(community.gateways);
  const certificateNames = cveCertificateNames(community);
  return {
    uid: community.uid || "",
    name: community.name || "(unnamed community)",
    type,
    usesIkeV1,
    usesCertificateAuth,
    includesExternalGateways: type === "star" && externalGateways.length > 0,
    externalGateways,
    matchesCriteria,
    summary: {
      participants: type === "meshed"
        ? (meshedGatewayNames.length ? meshedGatewayNames.join(", ") : "No gateways returned.")
        : cveStarParticipantSummary(community["center-gateways"], community["satellite-gateways"]),
      centerGateways: centerGatewayNames.length ? centerGatewayNames.join(", ") : "No center gateways returned.",
      satelliteGateways: satelliteGatewayNames.length ? satelliteGatewayNames.join(", ") : "No satellite gateways returned.",
      ike: ikeV1Evidence.length ? cveEvidenceSummary(ikeV1Evidence) : "No IKEv1 setting returned.",
      certificates: certificateNames.length
        ? certificateNames.join(", ")
        : (usesCertificateAuth ? cveEvidenceSummary(certificateEvidence) : "No certificate evidence returned."),
      externalGateways: type === "meshed" ? "Not applicable for Mesh communities." : cveExternalGatewaySummary(externalGateways)
    }
  };
}

async function collectCveVpnCommunities(session, command, type) {
  const communities = [];
  let offset = 0;
  let total = 0;
  do {
    const page = await cpRequest(session, command, {
      limit: VPN_COMMUNITY_PAGE_LIMIT,
      offset,
      "details-level": "full"
    });
    const objects = page.objects || [];
    communities.push(...objects.map((community) => evaluateCveSiteToSiteCommunity(community, type)));
    total = Number(page.total || communities.length);
    offset += VPN_COMMUNITY_PAGE_LIMIT;
  } while (offset < total);
  return communities;
}

async function collectCveIkeEvidence(session, globalPropertiesResult, gatewaysResult) {
  const errors = [];
  const globalPath = "remote-access.vpn-authentication-and-encryption.encryption-method";
  const globalCurrentMethod = globalPropertiesResult.ok ? getNestedValue(globalPropertiesResult.data, globalPath) : null;
  if (!globalPropertiesResult.ok) {
    errors.push(globalPropertiesResult.error);
  }

  const legacyRows = [];
  if (gatewaysResult.ok) {
    await Promise.all((gatewaysResult.objects || []).map(async (gateway) => {
      const object = await tryCommand(session, "show-generic-object", { uid: gateway.uid });
      if (!object.ok) {
        errors.push({ gateway: gateway.name || gateway.uid, error: object.error });
        legacyRows.push({
          uid: gateway.uid,
          name: gateway.name || gateway.uid || "",
          ipAddress: gateway["ipv4-address"] || gateway.ipv4Address || "",
          vpnRealmUid: "",
          currentDisabled: "Lookup failed",
          needsChange: false,
          status: "Lookup failed"
        });
        return;
      }
      const vpnRealm = (object.data?.realmsForBlades || []).find((realm) => realm.ownedName === "vpn");
      const currentDisabled = vpnRealm?.disabled;
      const needsChange = Boolean(vpnRealm) && String(currentDisabled) !== CVE_LEGACY_CLIENT_DISABLED;
      legacyRows.push({
        uid: gateway.uid,
        name: gateway.name || gateway.uid || "",
        ipAddress: gateway["ipv4-address"] || gateway.ipv4Address || "",
        vpnRealmUid: vpnRealm?.objId || vpnRealm?.uid || "",
        currentDisabled: currentDisabled ?? null,
        needsChange,
        status: vpnRealm ? (needsChange ? "Legacy clients supported" : "Legacy clients disabled") : "No VPN realm"
      });
    }));
  } else {
    errors.push(gatewaysResult.error);
  }
  legacyRows.sort((a, b) => a.name.localeCompare(b.name));

  const communities = [];
  for (const entry of [
    { command: "show-vpn-communities-star", type: "star" },
    { command: "show-vpn-communities-meshed", type: "meshed" }
  ]) {
    try {
      communities.push(...await collectCveVpnCommunities(session, entry.command, entry.type));
    } catch (error) {
      errors.push({
        command: entry.command,
        type: entry.type,
        error: error.message,
        phase: error.phase,
        target: error.target,
        statusCode: error.statusCode,
        response: error.response
      });
    }
  }

  const result = {
    ok: errors.length === 0,
    errors,
    global: {
      path: globalPath,
      currentMethod: globalCurrentMethod ?? null,
      desiredMethod: CVE_IKE_DESIRED_METHOD,
      needsChange: Boolean(globalCurrentMethod) && globalCurrentMethod !== CVE_IKE_DESIRED_METHOD,
      status: globalCurrentMethod
        ? (globalCurrentMethod === CVE_IKE_DESIRED_METHOD ? "IKEv2 only" : "IKEv1 allowed")
        : "Not returned"
    },
    legacyRows,
    communities,
    communityMatches: communities.filter((community) => community.matchesCriteria)
  };
  session.lastCveIkeScan = result;
  return result;
}

async function collectGatewayStealthRuleEvidence(session, gatewaysResult, packagesResult) {
  if (!gatewaysResult.ok) {
    return {
      ok: false,
      command: "where-used/show-access-rule",
      error: gatewaysResult.error,
      gateways: [],
      rowsByPolicy: new Map(),
      missingGateways: []
    };
  }

  const gateways = (gatewaysResult.objects || [])
    .filter((gateway) => gateway?.name || gateway?.uid)
    .map((gateway) => ({ name: gateway.name || "", uid: gateway.uid || "" }));
  const rowsByPolicy = new Map();
  const packageLookup = buildAccessLayerPackageLookup(packagesResult);
  const gatewayMatches = new Map(gateways.map((gateway) => [gateway.uid || gateway.name, false]));
  const addedRows = new Set();
  const errors = [];
  function addPolicyRow(policyName, row) {
    const key = `${policyName}:${row.Gateway}:${row["Rule #"]}:${row["Stealth Rule"]}`;
    if (addedRows.has(key)) return;
    addedRows.add(key);
    if (!rowsByPolicy.has(policyName)) {
      rowsByPolicy.set(policyName, []);
    }
    rowsByPolicy.get(policyName).push(row);
  }
  async function addGlobalParentRows(gateway, candidate, destinationRefs) {
    const layerInfo = packageLookup.get(candidate.layerUid) || packageLookup.get(normalizeToken(candidate.layerName));
    const parentLayerUid = layerInfo?.parentLayerUid || "";
    if (!parentLayerUid) {
      return;
    }
    const globalRulebase = await tryCommand(globalDomainSession(session), "show-access-rulebase", {
      name: parentLayerUid,
      "details-level": "full"
    });
    if (!globalRulebase.ok) {
      errors.push({
        gateway: gateway.name || gateway.uid,
        layer: parentLayerUid,
        rulebase: "global-parent",
        error: globalRulebase.error
      });
      return;
    }
    const dictionary = objectDictionaryMap(globalRulebase.data);
    const parentLayerName = globalRulebase.data?.name || layerInfo.parentLayerName || parentLayerUid;
    const policyName = policyPackageLabel(candidate.layerName, candidate.layerUid, packageLookup);
    for (const rule of globalRulebase.data?.rulebase || []) {
      if (normalizeToken(rule?.name) === "placeholderfordomainrules" || normalizeToken(rule?.type) === "placeholder") {
        break;
      }
      if (normalizeToken(rule?.type) !== "accessrule") {
        continue;
      }
      const resolvedRule = accessRuleWithDictionary(rule, dictionary);
      addPolicyRow(policyName, {
        ...accessRuleSummary(resolvedRule, gateway, parentLayerName, parentLayerUid, packageLookup, accessRuleNumber(resolvedRule)).row,
        "Stealth Rule": "GLOBAL RULES"
      });
    }
  }
  async function collectFromAccessRulebases() {
    const fallbackErrors = [];
    let inspectedRulebases = 0;
    let foundStealthRows = 0;
    const layers = accessLayersFromPackages(packagesResult);
    for (const layer of layers) {
      const layerLookupName = layer.uid || layer.name;
      if (!layerLookupName) continue;
      const rulebase = await tryCommand(session, "show-access-rulebase", {
        name: layerLookupName,
        "details-level": "full"
      });
      if (!rulebase.ok) {
        fallbackErrors.push({ layer: layerLookupName, rulebase: "direct-access-rulebase", error: rulebase.error });
        if (!rulebase.data?.rulebase?.length) continue;
      }
      inspectedRulebases += 1;
      const dictionary = objectDictionaryMap(rulebase.data);
      const layerName = rulebase.data?.name || layer.name || layerLookupName;
      const layerUid = rulebase.data?.uid || layer.uid || "";
      const rules = flattenAccessRulebaseRules(rulebase.data?.rulebase || [])
        .map((rule) => accessRuleWithDictionary(rule, dictionary));
      for (const gateway of gateways) {
        const gatewayKey = gateway.uid || gateway.name;
        const destinationRefs = [gateway, ...dictionaryGroupsContainingRefs(dictionary, [gateway])];
        for (let index = 0; index < rules.length; index += 1) {
          const rule = rules[index];
          const ruleNumber = accessRuleNumber(rule, String(index + 1));
          const summary = accessRuleSummary(rule, gateway, layerName, layerUid, packageLookup, ruleNumber, {
            destinationRefs,
            displayRuleNumber: String(ruleNumber)
          });
          if (!summary.stealthMatch) {
            continue;
          }
          foundStealthRows += 1;
          gatewayMatches.set(gatewayKey, true);
          await addGlobalParentRows(gateway, {
            layerName,
            layerUid,
            ruleNumber
          }, destinationRefs);
          for (const aboveRule of rules.slice(0, index)) {
            const aboveRuleNumber = accessRuleNumber(aboveRule);
            const aboveSummary = accessRuleSummary(aboveRule, gateway, layerName, layerUid, packageLookup, aboveRuleNumber, {
              destinationRefs,
              displayRuleNumber: String(aboveRuleNumber)
            });
            addPolicyRow(aboveSummary.policyName, {
              ...aboveSummary.row,
              "Stealth Rule": "ABOVE STEALTH"
            });
          }
          addPolicyRow(summary.policyName, summary.row);
        }
      }
    }
    return { inspectedRulebases, foundStealthRows, fallbackErrors };
  }

  // Download each access layer once and evaluate gateway references locally.
  // This preserves the evidence while avoiding per-gateway where-used expansion.
  const useRulebaseFirst = true;
  if (useRulebaseFirst) {
    const directRulebase = await collectFromAccessRulebases();
    errors.push(...directRulebase.fallbackErrors);
    return {
      ok: errors.length === 0,
      command: "show-access-rulebase",
      gateways,
      rowsByPolicy,
      missingGateways: gateways.filter((gateway) => !gatewayMatches.get(gateway.uid || gateway.name)),
      errors
    };
  }

  await Promise.all(gateways.map(async (gateway) => {
    const gatewayKey = gateway.uid || gateway.name;
    const whereUsed = await tryCommand(session, "where-used", {
      name: gateway.name || gateway.uid,
      "details-level": "full"
    });
    if (!whereUsed.ok) {
      errors.push({ gateway: gateway.name || gateway.uid, error: whereUsed.error });
      return;
    }
    const groups = whereUsedGroupReferences(whereUsed.data, gateway);
    const destinationRefs = [gateway, ...groups];
    const candidates = whereUsedDestinationCandidates(whereUsed.data, gateway);
    await Promise.all(groups.map(async (group) => {
      const groupLookupName = group.name || group.uid;
      if (!groupLookupName) return;
      const groupWhereUsed = await tryCommand(session, "where-used", {
        name: groupLookupName,
        "details-level": "full"
      });
      if (!groupWhereUsed.ok) {
        errors.push({ gateway: gateway.name || gateway.uid, group: groupLookupName, error: groupWhereUsed.error });
        return;
      }
      candidates.push(...whereUsedDestinationCandidates(groupWhereUsed.data, group));
    }));
    if (!candidates.length) return;

    await Promise.all(candidates.map(async (candidate) => {
      const ruleResult = await fetchAccessRuleSummary(session, gateway, candidate, packageLookup, candidate.ruleNumber, {
        destinationRefs,
        displayRuleNumber: String(candidate.ruleNumber ?? "")
      });
      if (!ruleResult.ok) {
        errors.push({
          gateway: gateway.name || gateway.uid,
          layer: candidate.layerName,
          ruleNumber: candidate.ruleNumber,
          error: ruleResult.error
        });
        return;
      }
      const summary = ruleResult.summary;
      if (summary.stealthMatch) {
        gatewayMatches.set(gatewayKey, true);
        await addGlobalParentRows(gateway, candidate, destinationRefs);
        const stealthRuleNumber = Number(accessRuleLookupRuleNumber(candidate.ruleNumber));
        if (Number.isInteger(stealthRuleNumber) && stealthRuleNumber > 1) {
          const aboveRuleNumbers = Array.from({ length: stealthRuleNumber - 1 }, (_, index) => index + 1);
          await Promise.all(aboveRuleNumbers.map(async (aboveRuleNumber) => {
            const aboveResult = await fetchAccessRuleSummary(session, gateway, candidate, packageLookup, aboveRuleNumber, {
              destinationRefs,
              displayRuleNumber: candidate.ruleNumber && String(candidate.ruleNumber).includes(".")
                ? compositeAccessRuleNumber(accessRuleParentRuleNumber(candidate.ruleNumber), aboveRuleNumber)
                : String(aboveRuleNumber)
            });
            if (!aboveResult.ok) {
              errors.push({
                gateway: gateway.name || gateway.uid,
                layer: candidate.layerName,
                ruleNumber: aboveRuleNumber,
                error: aboveResult.error
              });
              return;
            }
            addPolicyRow(aboveResult.summary.policyName, {
              ...aboveResult.summary.row,
              "Stealth Rule": "ABOVE STEALTH"
            });
          }));
        }
        addPolicyRow(summary.policyName, summary.row);
      }
    }));
  }));

  if (!rowsByPolicy.size && errors.length) {
    const whereUsedErrors = [...errors];
    errors.length = 0;
    const fallback = await collectFromAccessRulebases();
    if (!fallback.inspectedRulebases) {
      errors.push(...whereUsedErrors, ...fallback.fallbackErrors);
    }
  }

  return {
    ok: errors.length === 0,
    command: "where-used/show-access-rule",
    gateways,
    rowsByPolicy,
    missingGateways: gateways.filter((gateway) => !gatewayMatches.get(gateway.uid || gateway.name)),
    errors
  };
}

async function collectAdministrativeSourceIpEvidence(session, gatewaysAndServersResult, packagesResult, networksResult, addressRangesResult) {
  const loginManagement = resolveManagementObject(session, gatewaysAndServersResult);
  const loginIp = managementLoginHost(session) || firstIpv4(allIpv4Values(loginManagement.object).join(" "));
  const domainIdentity = String(session.domain || "").trim();
  const globalSession = session.mdsMode ? globalDomainSession(session) : null;
  const mdsSession = session.mdsMode && session.mdsSid ? { ...session, sid: session.mdsSid } : session;
  const loadMdsGlobalInventory = () => Promise.all([
    tryListObjects(mdsSession, "show-mdss", { "details-level": "full" }),
    tryListObjects(globalSession, "show-packages", { "details-level": "full" }),
    tryListObjects(globalSession, "show-networks", { "details-level": "full" }),
    tryListObjects(globalSession, "show-address-ranges", { "details-level": "full" }),
    tryListObjects(globalSession, "show-hosts", { "details-level": "full" }),
    tryListObjects(mdsSession, "show-global-assignments", { "details-level": "full" })
  ]);
  let mdsGlobalInventory = [null, null, null, null, null, null];
  if (session.mdsMode) {
    const cacheOwner = session.moraRootSession;
    const scanToken = session.moraProgress?.parent?.scanProgress?.startedAt || "";
    if (cacheOwner && scanToken) {
      if (cacheOwner.moraAdminSourceGlobalInventory?.scanToken !== scanToken) cacheOwner.moraAdminSourceGlobalInventory = { scanToken, promise: loadMdsGlobalInventory() };
      mdsGlobalInventory = await cacheOwner.moraAdminSourceGlobalInventory.promise;
    } else {
      mdsGlobalInventory = await loadMdsGlobalInventory();
    }
  }
  const [globalMdsServers, globalPackages, globalNetworks, globalAddressRanges, globalHosts, globalAssignments] = mdsGlobalInventory;
  const managementTargets = [];
  const rememberedTargetIps = new Set();
  function addManagementTarget(target, role) {
    const ip = target.ip || firstIpv4(allIpv4Values(target.object).join(" ")) || firstIpv4(target.name);
    const key = `${normalizeToken(role)}:${ip || normalizeToken(target.name)}`;
    if (!target.name || rememberedTargetIps.has(key)) return;
    rememberedTargetIps.add(key);
    managementTargets.push({
      ...target,
      ip,
      role,
      ref: {
        name: target.name,
        uid: target.object?.uid || ""
      }
    });
  }
  if (session.mdsMode) {
    const mdsIdentity = String(session.managementObjectName || "").trim() || loginIp;
    addManagementTarget(resolveManagementObjectByIdentity(globalMdsServers, mdsIdentity, mdsIdentity), "MDS management host");
  } else {
    addManagementTarget({
      ...loginManagement,
      ip: loginIp
    }, "Management host");
  }
  if (session.mdsMode && domainIdentity) {
    const localManagement = resolveManagementObjectByIdentity(gatewaysAndServersResult, domainIdentity, domainIdentity);
    addManagementTarget(localManagement.matched ? localManagement : resolveDomainManagementFromMdss(globalMdsServers, domainIdentity), "Domain management host");
  }
  const domainTarget = managementTargets.find((target) => target.role === "Domain management host");
  const domainIdentityTokens = new Set([domainIdentity, domainTarget?.name, domainTarget?.domain, domainTarget?.ip].filter(Boolean).map(normalizeToken));
  const matchingGlobalAssignments = (globalAssignments?.objects || []).filter((assignment) => {
    const dependentDomain = assignment?.["dependent-domain"] || assignment?.dependentDomain || {};
    return [dependentDomain.name, dependentDomain.uid, ...allIpv4Values(dependentDomain)].some((candidate) => domainIdentityTokens.has(normalizeToken(candidate)));
  });
  const assignedGlobalPolicyNames = uniqueStrings(matchingGlobalAssignments.map((assignment) => objectDisplayName(assignment?.["global-access-policy"] || assignment?.globalAccessPolicy)).filter(Boolean));
  const assignedGlobalPolicyTokens = new Set(assignedGlobalPolicyNames.map(normalizeToken));
  const assignedGlobalPackages = globalPackages?.ok ? { ...globalPackages, objects: (globalPackages.objects || []).filter((policyPackage) => assignedGlobalPolicyTokens.has(normalizeToken(policyPackage?.name || policyPackage?.NAME || policyPackage?.uid))) } : globalPackages;
  const managementName = managementTargets.map((target) => target.name).filter(Boolean).join(", ") || loginManagement.name || managementLoginHost(session) || session.baseUrl;
  const rowsByPolicy = new Map();
  const packageLookup = buildAccessLayerPackageLookup(packagesResult);
  const addedRows = new Set();
  const objectsByKey = new Map();
  const errors = [];
  const globalPolicyObjectRefs = [];
  const globalObjectWhereUsed = new Map();
  const automaticNatRows = [];
  const translatedDestinationNatRows = [];
  const manualNatOriginalDestinations = new Map();
  if (session.mdsMode && !globalAssignments?.ok) errors.push({ scope: "MDS global assignment discovery", command: "show-global-assignments", error: globalAssignments?.error });
  else if (session.mdsMode && !matchingGlobalAssignments.length) errors.push({ scope: "MDS global assignment discovery", command: "show-global-assignments", error: { error: `No Global assignment was found for domain ${domainIdentity || domainTarget?.name || "Unknown"}.` } });
  else if (session.mdsMode && assignedGlobalPolicyNames.length && assignedGlobalPackages?.ok && !assignedGlobalPackages.objects.length) errors.push({ scope: "Global domain", command: "show-packages", error: { error: `Assigned Global access policy ${assignedGlobalPolicyNames.join(", ")} was not returned by show-packages.` } });
  function addPolicyRow(policyName, row) {
    const key = `${policyName}:${row["Rule #"]}:${row.Source}:${row.Destination}:${row.Services}`;
    if (addedRows.has(key)) return;
    addedRows.add(key);
    if (!rowsByPolicy.has(policyName)) {
      rowsByPolicy.set(policyName, []);
    }
    rowsByPolicy.get(policyName).push(row);
  }
  function rememberObject(objectRef, objectType, details) {
    const name = objectRef?.name || objectRef?.uid || "";
    if (!name) return;
    const key = objectRef.uid || `${normalizeToken(objectType)}:${normalizeToken(name)}:${normalizeToken(details)}`;
    if (objectsByKey.has(key)) return;
    objectsByKey.set(key, {
      "Object Name": name,
      "Object Type": objectType,
      "Details": details
    });
  }
  function rememberGlobalPolicyRef(ref, type, details) {
    const key = ref?.uid || normalizeToken(ref?.name);
    if (!key || globalPolicyObjectRefs.some((entry) => (entry.uid || normalizeToken(entry.name)) === key)) return;
    globalPolicyObjectRefs.push({ name: ref.name || ref.uid || "", uid: ref.uid || "" });
    rememberObject(ref, type, details);
  }

  async function collectGlobalPolicyObjects() {
    if (!session.mdsMode) return;
    for (const [command, result] of [["show-networks", globalNetworks], ["show-address-ranges", globalAddressRanges], ["show-hosts", globalHosts]]) {
      if (!result?.ok) errors.push({ scope: "Global domain object discovery", command, error: result?.error });
    }
    for (const target of managementTargets) {
      if (!target.ip) continue;
      for (const host of (globalHosts?.objects || []).filter((object) => allIpv4Values(object).includes(target.ip))) {
        rememberGlobalPolicyRef(host, "Global Host", `Global host object matching ${target.role} IP ${target.ip}`);
      }
      for (const network of matchingNetworkObjectsForIp(globalNetworks, target.ip)) {
        rememberGlobalPolicyRef(network, "Global Network", `Global object containing ${target.role} IP ${target.ip} (${network.cidr.cidr})`);
      }
      for (const range of matchingAddressRangeObjectsForIp(globalAddressRanges, target.ip)) {
        const first = range.range?.["ipv4-address-first"] || range.range?.ipv4AddressFirst || range.range?.from || range.range?.start || "";
        const last = range.range?.["ipv4-address-last"] || range.range?.ipv4AddressLast || range.range?.to || range.range?.end || "";
        rememberGlobalPolicyRef(range, "Global Address Range", `Global object containing ${target.role} IP ${target.ip} (${[first, last].filter(Boolean).join(" - ")})`);
      }
    }
    const queue = [...globalPolicyObjectRefs];
    const inspected = new Set();
    while (queue.length && inspected.size < 100) {
      const ref = queue.shift();
      const lookupName = ref.name || ref.uid;
      const key = ref.uid || normalizeToken(lookupName);
      if (!lookupName || inspected.has(key)) continue;
      inspected.add(key);
      const usage = await tryCommand(globalSession, "where-used", { name: lookupName, "details-level": "full" });
      if (!usage.ok) {
        errors.push({ scope: "Global domain object expansion", object: lookupName, error: usage.error });
        continue;
      }
      globalObjectWhereUsed.set(key, usage);
      for (const group of whereUsedGroupReferences(usage.data, ref)) {
        const before = globalPolicyObjectRefs.length;
        rememberGlobalPolicyRef(group, "Global Group", `Global group containing ${lookupName}`);
        if (globalPolicyObjectRefs.length > before) queue.push(group);
      }
    }
  }
  async function addGlobalParentRows(candidate) {
    const layerInfo = packageLookup.get(candidate.layerUid) || packageLookup.get(normalizeToken(candidate.layerName));
    const parentLayerUid = layerInfo?.parentLayerUid || "";
    if (!parentLayerUid) return;
    const globalRulebase = await tryCommand(globalDomainSession(session), "show-access-rulebase", {
      name: parentLayerUid,
      "details-level": "full"
    });
    if (!globalRulebase.ok) {
      errors.push({ layer: parentLayerUid, rulebase: "global-parent", error: globalRulebase.error });
      return;
    }
    const dictionary = objectDictionaryMap(globalRulebase.data);
    const parentLayerName = globalRulebase.data?.name || layerInfo.parentLayerName || parentLayerUid;
    const policyName = policyPackageLabel(candidate.layerName, candidate.layerUid, packageLookup);
    for (const rule of globalRulebase.data?.rulebase || []) {
      if (normalizeToken(rule?.name) === "placeholderfordomainrules" || normalizeToken(rule?.type) === "placeholder") break;
      if (normalizeToken(rule?.type) !== "accessrule") continue;
      const resolvedRule = accessRuleWithDictionary(rule, dictionary);
      addPolicyRow(policyName, {
        ...accessRuleEvidenceRow(resolvedRule, "", accessRuleNumber(resolvedRule), { includeGateway: false }),
        "Rule Name": resolvedRule.name || "GLOBAL RULES"
      });
    }
  }

  function fieldContainsManagementIdentity(value, target) {
    const refTokens = new Set(objectRefTokens([target.ref]));
    function containsNestedRef(node) {
      if (node === undefined || node === null) return false;
      if (typeof node === "string" || typeof node === "number") return refTokens.has(normalizeToken(node));
      if (Array.isArray(node)) return node.some(containsNestedRef);
      if (typeof node === "object") {
        if ([node.name, node.uid, node.NAME, node.UID].filter(Boolean).some((candidate) => refTokens.has(normalizeToken(candidate)))) return true;
        const referenceKeys = new Set(["object", "objects", "value", "values", "member", "members", "reference", "references", "destination", "destinations"]);
        return Object.entries(node).some(([key, child]) => referenceKeys.has(normalizeToken(key)) && containsNestedRef(child));
      }
      return false;
    }
    if (fieldContainsObjectRef(value, target.ref) || containsNestedRef(value)) return true;
    const targetIp = target.ip || firstIpv4(allIpv4Values(target.object).join(" "));
    if (!targetIp) return false;
    function containsDirectIp(node) {
      if (node === undefined || node === null) return false;
      if (typeof node === "string" || typeof node === "number") return firstIpv4(node) === targetIp;
      if (Array.isArray(node)) return node.some(containsDirectIp);
      if (typeof node !== "object") return false;
      const addressKeys = new Set(["ipv4address", "ipaddress"]);
      const referenceKeys = new Set(["object", "objects", "value", "values", "member", "members", "reference", "references", "destination", "destinations"]);
      return Object.entries(node).some(([key, child]) => addressKeys.has(normalizeToken(key)) ? firstIpv4(child) === targetIp : (referenceKeys.has(normalizeToken(key)) && containsDirectIp(child)));
    }
    return containsDirectIp(value);
  }

  async function collectDirectGlobalRules() {
    if (!session.mdsMode) return;
    if (!globalMdsServers?.ok) {
      errors.push({ scope: "Global domain", command: "show-mdss", error: globalMdsServers?.error });
      return;
    }
    if (!assignedGlobalPackages?.ok) {
      errors.push({ scope: "Global domain", command: "show-packages", error: assignedGlobalPackages?.error });
      return;
    }
    const targets = [...managementTargets.filter((target) => target.role === "MDS management host" || target.role === "Domain management host"), ...globalPolicyObjectRefs.map((ref) => ({ name: ref.name, ref }))];
    for (const layer of accessLayersFromPackages(assignedGlobalPackages, { preservePackageOccurrences: true })) {
      const layerLookupName = layer.uid || layer.name;
      if (!layerLookupName) continue;
      let offset = 0;
      for (let page = 0; page < 100; page += 1) {
        const rulebase = await tryCommand(globalSession, "show-access-rulebase", { name: layerLookupName, "details-level": "full", limit: 500, offset });
        if (!rulebase.ok) {
          errors.push({ scope: "Global domain", layer: layerLookupName, offset, error: rulebase.error });
          break;
        }
        const dictionary = objectDictionaryMap(rulebase.data);
        const layerName = rulebase.data?.name || layer.name || layerLookupName;
        const policyName = `Global Policy: ${layer.packageName || "Unnamed package"} / ${layerName}`;
        for (const rule of flattenAccessRulebaseRules(rulebase.data?.rulebase || [])) {
          const resolvedRule = accessRuleWithDictionary(rule, dictionary);
          const destination = ruleField(resolvedRule, "destination", "destinations");
          const matchedTargets = targets.filter((target) => fieldContainsManagementIdentity(destination, target));
          if (!matchedTargets.length) continue;
          addPolicyRow(policyName, {
            ...accessRuleEvidenceRow(resolvedRule, "", accessRuleNumber(resolvedRule), { includeGateway: false }),
            "Rule Name": resolvedRule.name || `Direct reference to ${matchedTargets.map((target) => target.name).join(", ")}`
          });
        }
        const total = Number(rulebase.data?.total || 0);
        const to = Number(rulebase.data?.to || 0);
        if (!total || to >= total || !(rulebase.data?.rulebase || []).length) break;
        const nextOffset = to > offset ? to : offset + 500;
        if (nextOffset <= offset) break;
        offset = nextOffset;
      }
    }
  }

  async function collectAssignedGlobalWhereUsedRules() {
    if (!session.mdsMode || !assignedGlobalPackages?.ok) return;
    const assignedLayers = accessLayersFromPackages(assignedGlobalPackages, { preservePackageOccurrences: true });
    const allowedLayerTokens = new Set(assignedLayers.flatMap((layer) => [layer.uid, layer.name].filter(Boolean).map(normalizeToken)));
    const assignedPackageLookup = buildAccessLayerPackageLookup(assignedGlobalPackages);
    for (const ref of globalPolicyObjectRefs) {
      const lookupName = ref.name || ref.uid;
      const key = ref.uid || normalizeToken(lookupName);
      if (!lookupName) continue;
      const usage = globalObjectWhereUsed.get(key) || await tryCommand(globalSession, "where-used", { name: lookupName, "details-level": "full" });
      if (!usage.ok) {
        errors.push({ scope: "Assigned Global policy", object: lookupName, error: usage.error });
        continue;
      }
      for (const candidate of whereUsedAccessRuleCandidates(usage.data, ref)) {
        const candidateTokens = [candidate.layerUid, candidate.layerName].filter(Boolean).map(normalizeToken);
        if (!candidateTokens.some((token) => allowedLayerTokens.has(token))) continue;
        const assignedLayer = assignedLayers.find((layer) => [layer.uid, layer.name].filter(Boolean).map(normalizeToken).some((token) => candidateTokens.includes(token)));
        const ruleResult = await fetchAccessRuleEvidence(globalSession, lookupName, candidate, assignedPackageLookup, candidate.ruleNumber);
        if (!ruleResult.ok) {
          errors.push({ scope: "Assigned Global policy", object: lookupName, layer: candidate.layerName || candidate.layerUid, ruleNumber: candidate.ruleNumber, error: ruleResult.error });
          continue;
        }
        addPolicyRow(`Global Policy: ${assignedLayer?.packageName || "Assigned"} / ${assignedLayer?.name || candidate.layerName || candidate.layerUid || "Access Policy"}`, ruleResult.row);
      }
    }
  }

  async function collectDirectLocalRules() {
    if (!session.mdsMode || !packagesResult?.ok) return;
    const targets = [...managementTargets.filter((target) => target.role === "MDS management host" || target.role === "Domain management host"), ...globalPolicyObjectRefs.map((ref) => ({ name: ref.name, ref }))];
    for (const layer of accessLayersFromPackages(packagesResult)) {
      const layerLookupName = layer.uid || layer.name;
      if (!layerLookupName) continue;
      let offset = 0;
      for (let page = 0; page < 100; page += 1) {
        const rulebase = await tryCommand(session, "show-access-rulebase", { name: layerLookupName, "details-level": "full", limit: 500, offset });
        if (!rulebase.ok) {
          errors.push({ scope: "Local domain", layer: layerLookupName, offset, error: rulebase.error });
          break;
        }
        const dictionary = objectDictionaryMap(rulebase.data);
        const layerName = rulebase.data?.name || layer.name || layerLookupName;
        const policyName = policyPackageLabel(layerName, rulebase.data?.uid || layer.uid || "", packageLookup);
        for (const rule of flattenAccessRulebaseRules(rulebase.data?.rulebase || [])) {
          const resolvedRule = accessRuleWithDictionary(rule, dictionary);
          const destination = ruleField(resolvedRule, "destination", "destinations");
          const matchedTargets = targets.filter((target) => fieldContainsManagementIdentity(destination, target));
          if (!matchedTargets.length) continue;
          addPolicyRow(policyName, {
            ...accessRuleEvidenceRow(resolvedRule, "", accessRuleNumber(resolvedRule), { includeGateway: false }),
            "Rule Name": resolvedRule.name || `Direct reference to ${matchedTargets.map((target) => target.name).join(", ")}`
          });
        }
        const total = Number(rulebase.data?.total || 0);
        const to = Number(rulebase.data?.to || 0);
        if (!total || to >= total || !(rulebase.data?.rulebase || []).length) break;
        const nextOffset = to > offset ? to : offset + 500;
        if (nextOffset <= offset) break;
        offset = nextOffset;
      }
    }
  }

  if (!gatewaysAndServersResult.ok) {
    return {
      ok: false,
      command: "show-gateways-and-servers/where-used/show-access-rule",
      managementName,
      rowsByPolicy,
      objectRows: [],
      errors: [gatewaysAndServersResult.error].filter(Boolean)
    };
  }

  async function addRulesFromWhereUsed(whereUsedResult, lookupName) {
    const candidates = whereUsedAccessRuleCandidates(whereUsedResult.data, { name: lookupName });
    await Promise.all(candidates.map(async (candidate) => {
      // MDS scans enumerate every Global-domain policy directly below. Avoid
      // adding unrelated rules merely because they precede a domain placeholder.
      if (!session.mdsMode) await addGlobalParentRows(candidate);
      const ruleResult = await fetchAccessRuleEvidence(session, managementName, candidate, packageLookup, candidate.ruleNumber);
      if (!ruleResult.ok) {
        errors.push({
          object: lookupName,
          layer: candidate.layerName,
          ruleNumber: candidate.ruleNumber,
          error: ruleResult.error
        });
        return;
      }
      addPolicyRow(ruleResult.policyName, ruleResult.row);
    }));
  }

  const processedObjects = new Set();
  async function processObjectUsage(objectRef, existingWhereUsed = null) {
    const lookupName = objectRef.name || objectRef.uid;
    const objectKey = objectRef.uid || normalizeToken(lookupName);
    if (!lookupName || processedObjects.has(objectKey)) return;
    processedObjects.add(objectKey);
    const usage = existingWhereUsed || await tryCommand(session, "where-used", {
      name: lookupName,
      "details-level": "full"
    });
    if (!usage.ok) {
      errors.push({ object: lookupName, error: usage.error });
      return;
    }
    await addRulesFromWhereUsed(usage, lookupName);
    const queuedGroups = whereUsedGroupReferences(usage.data, objectRef);
    const processedGroups = new Set();
    while (queuedGroups.length && processedGroups.size < 25) {
      const group = queuedGroups.shift();
      const groupLookupName = group.name || group.uid;
      const groupKey = group.uid || normalizeToken(groupLookupName);
      if (!groupLookupName || processedGroups.has(groupKey)) continue;
      processedGroups.add(groupKey);
      rememberObject(group, "Group", `Group containing ${lookupName}`);
      await processObjectUsage(group);
    }
  }

  for (const target of managementTargets) {
    const targetName = target.name;
    const targetIp = target.ip;
    if (target.role === "MDS management host") {
      rememberObject(target.ref, target.matched ? "MDS Server (Global Domain)" : "MDS Server Hostname", target.matched
        ? `MDS object${targetIp ? ` (${targetIp})` : ""}; checked against the Global access policy assigned to this domain and this domain's local policies.`
        : `No Global-domain MDS object matching ${targetName} was returned.`);
      continue;
    }
    if (target.matched && targetName) {
      const whereUsed = await tryCommand(session, "where-used", {
        name: targetName,
        "details-level": "full"
      });
      if (whereUsed.ok) {
        rememberObject(target.ref, "Management Server", `${target.role} object${targetIp ? ` (${targetIp})` : ""}`);
        await processObjectUsage(target.ref, whereUsed);
      } else {
        errors.push(whereUsed.error);
      }
    } else if (targetName) {
      rememberObject(
        target.ref,
        target.role === "Domain management host" ? "Domain Management API Host" : "Management API Host",
        `No management object matching ${targetIp || targetName} was returned in the selected domain; checking matching network and address range objects.`
      );
    }
    for (const network of matchingNetworkObjectsForIp(networksResult, targetIp)) {
      rememberObject(network, "Network", `${target.role} IP ${targetIp} falls within ${network.cidr.cidr}`);
      await processObjectUsage(network);
    }
    for (const range of matchingAddressRangeObjectsForIp(addressRangesResult, targetIp)) {
      const first = range.range?.["ipv4-address-first"] || range.range?.ipv4AddressFirst || range.range?.from || range.range?.start || "";
      const last = range.range?.["ipv4-address-last"] || range.range?.ipv4AddressLast || range.range?.to || range.range?.end || "";
      rememberObject(range, "Address Range", `${target.role} IP ${targetIp} falls within ${[first, last].filter(Boolean).join(" - ")}`);
      await processObjectUsage(range);
    }
  }

  await collectGlobalPolicyObjects();
  await Promise.all([collectDirectLocalRules(), collectDirectGlobalRules()]);
  await collectAssignedGlobalWhereUsedRules();

  for (const target of managementTargets) {
    const natSettings = target.object?.["nat-settings"] || target.object?.natSettings;
    const autoRule = natSettings?.["auto-rule"] ?? natSettings?.autoRule;
    const method = natSettings?.method || "";
    if ((autoRule === true || normalizeToken(autoRule) === "true") && normalizeToken(method) === "static") {
      automaticNatRows.push({
        "Management Object": target.name,
        "NAT Type": "Automatic Static NAT",
        "Auto Rule": "Enabled",
        "Method": method,
        "Translated IPv4 Address": natSettings?.["ipv4-address"] || natSettings?.ipv4Address || "Not returned",
        "Install On": objectDisplayName(natSettings?.["install-on"] || natSettings?.installOn) || "Not returned"
      });
    }
  }

  function flattenLocalNatRules(rulebase = []) {
    const rules = [];
    const walk = (items) => {
      for (const item of Array.isArray(items) ? items : []) {
        if (!item || typeof item !== "object") continue;
        const type = normalizeToken(item.type);
        if (type === "natrule" || ruleField(item, "translated-destination", "translatedDestination") !== undefined) {
          rules.push(item);
        }
        if (Array.isArray(item.rulebase)) walk(item.rulebase);
      }
    };
    walk(rulebase);
    return rules;
  }

  if (managementTargets.some((target) => target.matched) && packagesResult?.ok) {
    const packageNames = uniqueStrings((packagesResult.objects || [])
      .map((policyPackage) => policyPackage?.name || policyPackage?.NAME)
      .filter(Boolean));
    await Promise.all(packageNames.map(async (packageName) => {
      const managementRefs = managementTargets.filter((target) => target.matched).map((target) => target.ref);
      let offset = 0;
      for (let page = 0; page < 100; page += 1) {
        const natRulebase = await tryCommand(session, "show-nat-rulebase", {
          package: packageName,
          "details-level": "full",
          limit: 500,
          offset
        });
        if (!natRulebase.ok) {
          errors.push({ package: packageName, rulebase: "nat", offset, error: natRulebase.error });
          break;
        }
        const dictionary = objectDictionaryMap(natRulebase.data);
        for (const rule of flattenLocalNatRules(natRulebase.data?.rulebase || [])) {
          const translatedDestinationRaw = ruleField(rule, "translated-destination", "translatedDestination");
          const translatedDestination = dereferenceRuleValue(translatedDestinationRaw, dictionary);
          if (!fieldContainsObjectRef(translatedDestination, managementRefs)) continue;
          const originalSource = dereferenceRuleValue(ruleField(rule, "original-source", "originalSource"), dictionary);
          const originalDestination = dereferenceRuleValue(ruleField(rule, "original-destination", "originalDestination"), dictionary);
          const originalService = dereferenceRuleValue(ruleField(rule, "original-service", "originalService"), dictionary);
          const translatedSource = dereferenceRuleValue(ruleField(rule, "translated-source", "translatedSource"), dictionary);
          const translatedService = dereferenceRuleValue(ruleField(rule, "translated-service", "translatedService"), dictionary);
          translatedDestinationNatRows.push({
            "Policy Package": packageName,
            "Rule #": accessRuleNumber(rule),
            "Disabled": accessRuleDisabledCell(rule),
            "Rule Name": rule.name || "",
            "Original Source": objectDisplayName(originalSource),
            "Original Destination": objectDisplayName(originalDestination),
            "Original Service": objectDisplayName(originalService),
            "Translated Source": objectDisplayName(translatedSource),
            "Translated Destination": objectDisplayName(translatedDestination),
            "Translated Service": objectDisplayName(translatedService),
            "Install On": objectDisplayName(ruleField(rule, "install-on", "installOn"))
          });
          const automaticRule = /^automatic rule:/i.test(String(rule.name || ""))
            || rule.automatic === true
            || rule["auto-generated"] === true;
          if (!automaticRule) {
            for (const originalDestinationRef of (Array.isArray(originalDestination) ? originalDestination : [originalDestination])) {
              const refName = originalDestinationRef?.name || originalDestinationRef?.uid || (typeof originalDestinationRef === "string" ? originalDestinationRef : "");
              const refToken = normalizeToken(refName);
              if (!refName || ["any", "original"].includes(refToken) || fieldContainsObjectRef(originalDestinationRef, managementRefs)) continue;
              const refKey = originalDestinationRef?.uid || refToken;
              if (!manualNatOriginalDestinations.has(refKey)) {
                manualNatOriginalDestinations.set(refKey, {
                  ref: typeof originalDestinationRef === "object" ? originalDestinationRef : { name: refName },
                  packageName,
                  ruleNumber: accessRuleNumber(rule)
                });
              }
            }
          }
        }
        const total = Number(natRulebase.data?.total || 0);
        const to = Number(natRulebase.data?.to || 0);
        if (!total || to >= total || !(natRulebase.data?.rulebase || []).length) break;
        const nextOffset = to > offset ? to : offset + 500;
        if (nextOffset <= offset) break;
        offset = nextOffset;
      }
    }));
  }

  for (const { ref, packageName, ruleNumber } of manualNatOriginalDestinations.values()) {
    rememberObject(
      ref,
      "Manual NAT Original Destination",
      `Original Destination in NAT rule ${ruleNumber || "(unnumbered)"} from policy package ${packageName}; this rule translates traffic to the Management Server.`
    );
    await processObjectUsage(ref);
  }

  return {
    ok: errors.length === 0,
    command: "where-used/show-access-rule/show-nat-rulebase",
    managementName,
    rowsByPolicy,
    objectRows: [...objectsByKey.values()],
    automaticNatRows,
    translatedDestinationNatRows,
    manualNatOriginalDestinationCount: manualNatOriginalDestinations.size,
    errors
  };
}

function firstIpv4(value) {
  const match = String(value || "").match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  return match ? match[0] : "";
}

function firstIpv4Cidr(value) {
  const match = String(value || "").match(/\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b/);
  return match ? match[0] : "";
}

function ipv4ToInt(ip) {
  const parts = String(ip || "").split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return parts.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
}

function intToIpv4(value) {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255
  ].join(".");
}

function maskLengthToInt(maskLength) {
  const length = Number(maskLength);
  if (!Number.isInteger(length) || length < 0 || length > 32) return null;
  return length === 0 ? 0 : (0xffffffff << (32 - length)) >>> 0;
}

function netmaskToPrefixLength(netmask) {
  const mask = ipv4ToInt(netmask);
  if (mask === null) return null;
  let prefix = 0;
  let seenZero = false;
  for (let bit = 31; bit >= 0; bit -= 1) {
    const isSet = Boolean(mask & (1 << bit));
    if (isSet && seenZero) return null;
    if (isSet) {
      prefix += 1;
    } else {
      seenZero = true;
    }
  }
  return prefix;
}

function cidrInfo(cidr) {
  const match = String(cidr || "").match(/\b((?:\d{1,3}\.){3}\d{1,3})\/(\d{1,2})\b/);
  if (!match) return null;
  const ipInt = ipv4ToInt(match[1]);
  const maskInt = maskLengthToInt(match[2]);
  if (ipInt === null || maskInt === null) return null;
  const prefixLength = Number(match[2]);
  const networkInt = (ipInt & maskInt) >>> 0;
  return {
    ip: match[1],
    prefixLength,
    network: intToIpv4(networkInt),
    cidr: `${intToIpv4(networkInt)}/${prefixLength}`
  };
}

function networkObjectCidrInfo(object) {
  const ip = object?.["ipv4-address"] || object?.ipv4Address || object?.["subnet4"] || object?.subnet4;
  const prefixLength = object?.["mask-length4"] ?? object?.maskLength4 ?? object?.["ipv4-mask-length"] ?? object?.ipv4MaskLength;
  const netmask = object?.["subnet-mask4"] || object?.subnetMask4 || object?.["ipv4-network-mask"] || object?.ipv4NetworkMask;
  if (!ip) return null;
  if (prefixLength !== undefined && prefixLength !== null && prefixLength !== "") {
    return cidrInfo(`${ip}/${prefixLength}`);
  }
  const derivedPrefixLength = netmaskToPrefixLength(netmask);
  if (derivedPrefixLength !== null) {
    return cidrInfo(`${ip}/${derivedPrefixLength}`);
  }
  return null;
}

function networkContainsIp(networkInfo, ip) {
  const ipInt = ipv4ToInt(ip);
  const maskInt = maskLengthToInt(networkInfo?.prefixLength);
  const networkInt = ipv4ToInt(networkInfo?.network);
  if (ipInt === null || maskInt === null || networkInt === null) return false;
  return ((ipInt & maskInt) >>> 0) === networkInt;
}

function matchingNetworkObjectsForIp(networksResult, ip) {
  if (!networksResult?.ok || !ip) return [];
  return (networksResult.objects || [])
    .map((network) => ({
      name: network.name || network.NAME || network.uid || "",
      uid: network.uid || "",
      cidr: networkObjectCidrInfo(network)
    }))
    .filter((network) => network.name && network.cidr && network.cidr.prefixLength > 0 && networkContainsIp(network.cidr, ip));
}

function addressRangeContainsIp(range, ip) {
  const ipInt = ipv4ToInt(ip);
  const firstInt = ipv4ToInt(range?.["ipv4-address-first"] || range?.ipv4AddressFirst || range?.from || range?.start);
  const lastInt = ipv4ToInt(range?.["ipv4-address-last"] || range?.ipv4AddressLast || range?.to || range?.end);
  if (ipInt === null || firstInt === null || lastInt === null) return false;
  return ipInt >= firstInt && ipInt <= lastInt;
}

function matchingAddressRangeObjectsForIp(addressRangesResult, ip) {
  if (!addressRangesResult?.ok || !ip) return [];
  return (addressRangesResult.objects || [])
    .map((range) => ({
      name: range.name || range.NAME || range.uid || "",
      uid: range.uid || "",
      range
    }))
    .filter((range) => {
      const first = range.range?.["ipv4-address-first"] || range.range?.ipv4AddressFirst || range.range?.from || range.range?.start;
      const last = range.range?.["ipv4-address-last"] || range.range?.ipv4AddressLast || range.range?.to || range.range?.end;
      return range.name && !(first === "0.0.0.0" && last === "255.255.255.255") && addressRangeContainsIp(range.range, ip);
    });
}

function allIpv4Values(value) {
  const addresses = [];
  function walk(node) {
    if (node === undefined || node === null) return;
    if (typeof node === "string" || typeof node === "number") {
      const matches = String(node).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
      addresses.push(...matches);
      return;
    }
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (typeof node === "object") {
      Object.values(node).forEach(walk);
    }
  }
  walk(value);
  return uniqueStrings(addresses);
}

function statusDescriptionText(result) {
  if (!result?.ok) return "";
  const taskDetailValues = (result.data?.tasks || [])
    .flatMap((task) => task?.["task-details"] || task?.taskDetails || [])
    .map((detail) => detail?.statusDescription || detail?.["status-description"])
    .filter((value) => value !== undefined && value !== null && value !== "")
    .map(String);
  if (taskDetailValues.length) {
    return taskDetailValues.join("\n");
  }
  const recursiveValues = valuesForNormalizedKey(result.data, "statusDescription", "status-description")
    .flatMap(uidValues);
  if (recursiveValues.length) {
    return recursiveValues.join("\n");
  }
  const responseMessages = (result.data?.tasks || [])
    .flatMap((task) => task?.["task-details"] || task?.taskDetails || [])
    .map((detail) => detail?.responseMessage || detail?.["response-message"])
    .filter(Boolean);
  return responseMessages.map((message) => {
    try {
      return Buffer.from(String(message), "base64").toString("utf8").trim();
    } catch {
      return "";
    }
  }).filter(Boolean).join("\n");
}

function responseMessageText(result) {
  if (!result?.ok) return "";
  const responseMessages = (result.data?.tasks || [])
    .flatMap((task) => task?.["task-details"] || task?.taskDetails || [])
    .map((detail) => detail?.responseMessage || detail?.["response-message"])
    .filter(Boolean);
  return responseMessages.map((message) => {
    try {
      return Buffer.from(String(message), "base64").toString("utf8").trim();
    } catch {
      return "";
    }
  }).filter(Boolean).join("\n");
}

function isRunScriptGatewayAccessFailure(value) {
  const text = typeof value === "string"
    ? value
    : [
        value?.error?.error,
        value?.error?.message,
        value?.error?.phase,
        value?.error?.response?.message,
        value?.error?.response?.errors,
        value?.phase,
        value?.message,
        statusDescriptionText(value),
        responseMessageText(value)
      ].filter(Boolean).join(" ");
  const token = normalizeToken(text);
  return (
    token.includes("timeout") ||
    token.includes("timedout") ||
    token.includes("unabletoaccess") ||
    token.includes("cannotaccess") ||
    token.includes("cantaccess") ||
    token.includes("notaccessible") ||
    token.includes("notresponding") ||
    token.includes("unreachable") ||
    token.includes("failedtoconnect") ||
    token.includes("connectionrefused") ||
    token.includes("sic") && token.includes("failed") ||
    token.includes("target") && token.includes("notfound")
  );
}

function runScriptDisplayError(result, fallback = "run-script failed") {
  return isRunScriptGatewayAccessFailure(result)
    ? GATEWAY_RUN_SCRIPT_ACCESS_MESSAGE
    : (result?.error?.error || fallback);
}

function runScriptOutputText(result) {
  return [statusDescriptionText(result), responseMessageText(result)].filter(Boolean).join("\n");
}

function gaiaOutputUnavailable(output) {
  const cleaned = cleanGaiaCliOutput(output).trim();
  return !cleaned || isRunScriptGatewayAccessFailure(output);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function taskIdsFromResult(result) {
  return uniqueStrings((result?.data?.tasks || [])
    .map((task) => task?.["task-id"] || task?.taskId || task?.uid)
    .filter(Boolean));
}

async function runScriptWithTaskDetails(session, body) {
  const queue = session?.largeEnvironmentMode ? largeEnvRunScriptQueue : runScriptQueue;
  return queue(() => runScriptWithTaskDetailsUnqueued(session, body));
}

async function runScriptWithTaskDetailsUnqueued(session, body) {
  const runResult = await tryCommand(session, "run-script", body);
  if (!runResult.ok) {
    return runResult;
  }

  const taskIds = taskIdsFromResult(runResult);
  if (!taskIds.length) {
    return runResult;
  }

  const baseInterval = session?.largeEnvironmentMode ? LARGE_ENV_TASK_POLL_INTERVAL_MS : TASK_POLL_INTERVAL_MS;
  return pollScriptTasks({initial: runResult, taskIds, targets: body.targets || [],
    timeoutMs: TASK_POLL_TIMEOUT_MS, intervalMs: baseInterval, maxIntervalMs: TASK_POLL_MAX_INTERVAL_MS,
    sleep, checkCancelled: () => assertNotCancelled(operationContext.getStore()?.operation),
    request: taskId => tryCommand(session, "show-task", {"task-id": taskId, "details-level": "full"})
  });
}

function mdsRunScriptSession(session, target) {
  if (!(target?.useMdsSession || target?.configured) || !session?.mdsSid) {
    return session;
  }
  return {
    ...session,
    sid: session.mdsSid
  };
}

function globalDomainSession(session) {
  if (!session?.globalDomainSid) {
    return session?.mdsSid ? { ...session, sid: session.mdsSid } : session;
  }
  return {
    ...session,
    sid: session.globalDomainSid,
    scanCommandCache: session.moraRootSession?.moraGlobalCommandCache || session.moraGlobalCommandCache || session.scanCommandCache
  };
}

function managementLoginHost(session) {
  try {
    return new URL(session.baseUrl).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return "";
  }
}

function resolveManagementObject(session, gatewaysAndServersResult) {
  const loginHost = managementLoginHost(session);
  if (!gatewaysAndServersResult?.ok) {
    return {
      name: loginHost || session.baseUrl,
      matched: false,
      error: gatewaysAndServersResult?.error
    };
  }
  const objects = gatewaysAndServersResult.objects || [];
  const loginToken = normalizeToken(loginHost);
  const match = objects.find((object) => {
    const names = uniqueStrings([object.name, object.NAME, object.uid]);
    const ips = allIpv4Values(object);
    return names.some((name) => normalizeToken(name) === loginToken) || ips.includes(loginHost);
  });
  return {
    name: match?.name || match?.NAME || loginHost || session.baseUrl,
    matched: Boolean(match),
    object: match || null
  };
}

function resolveManagementObjectByIp(gatewaysAndServersResult, ip, fallbackName = "") {
  if (!ip || !gatewaysAndServersResult?.ok) {
    return {
      name: fallbackName || ip || "",
      matched: false,
      object: null,
      ip
    };
  }
  const objects = gatewaysAndServersResult.objects || [];
  const match = objects.find((object) => allIpv4Values(object).includes(ip));
  return {
    name: match?.name || match?.NAME || fallbackName || ip,
    matched: Boolean(match),
    object: match || null,
    ip
  };
}

function resolveManagementObjectByIdentity(gatewaysAndServersResult, identity, fallbackName = "") {
  const value = String(identity || "").trim();
  const ip = firstIpv4(value);
  if (ip) return resolveManagementObjectByIp(gatewaysAndServersResult, ip, fallbackName || value);
  if (!value || !gatewaysAndServersResult?.ok) return { name: fallbackName || value, matched: false, object: null, ip: "" };
  const token = normalizeToken(value);
  const match = (gatewaysAndServersResult.objects || []).find((object) => (
    [object?.name, object?.NAME, object?.uid, object?.UID].filter(Boolean)
      .some((candidate) => normalizeToken(candidate) === token)
  ));
  return {
    name: match?.name || match?.NAME || fallbackName || value,
    matched: Boolean(match),
    object: match || null,
    ip: firstIpv4(allIpv4Values(match).join(" "))
  };
}

function resolveDomainManagementFromMdss(mdssResult, identity) {
  const value = String(identity || "").trim();
  const token = normalizeToken(value);
  const ip = firstIpv4(value);
  if (!value || !mdssResult?.ok) return { name: value, matched: false, object: null, ip };
  for (const mds of mdssResult.objects || []) {
    for (const domain of Array.isArray(mds?.domains) ? mds.domains : []) {
      const servers = Array.isArray(domain?.servers) ? domain.servers : [];
      const domainMatches = [domain?.name, domain?.uid].filter(Boolean).some((candidate) => normalizeToken(candidate) === token);
      const serverMatch = servers.find((server) => (
        [server?.name, server?.uid].filter(Boolean).some((candidate) => normalizeToken(candidate) === token)
        || (ip && allIpv4Values(server).includes(ip))
      ));
      if (!domainMatches && !serverMatch) continue;
      const server = serverMatch || servers.find((candidate) => candidate?.active === true) || servers[0];
      if (!server) break;
      return { name: server.name || domain.name || value, matched: true, object: server, ip: firstIpv4(allIpv4Values(server).join(" ")), domain: domain.name || "", mds: mds.name || "" };
    }
  }
  return { name: value, matched: false, object: null, ip };
}

function resolveManagementRunScriptTarget(session, gatewaysAndServersResult) {
  const configuredName = String(session?.managementObjectName || "").trim();
  if (configuredName) {
    return {
      name: configuredName,
      matched: true,
      configured: true,
      object: null
    };
  }
  if (session?.smart1Cloud) {
    return {
      name: "",
      matched: false,
      smart1Cloud: true,
      object: null,
      error: { error: "Smart-1 Cloud management is hosted by Check Point; Gaia run-script checks against the management server object are not applicable unless an explicit object name is provided." }
    };
  }
  return resolveManagementObject(session, gatewaysAndServersResult);
}

function gatewayTopologyPayload(gateway) {
  return [
    gateway?.interfaces,
    gateway?.["network-interfaces"],
    gateway?.["topology-settings"],
    gateway?.topology
  ].filter((value) => value !== undefined && value !== null);
}

function gatewayContainsExactTopologyIp(gateway, ip) {
  if (!ip) return false;
  return allIpv4Values(gatewayTopologyPayload(gateway)).includes(ip);
}

function topologySubnetEntries(gateway) {
  const topology = gatewayTopologyPayload(gateway);
  const entries = [];
  function addEntry(ip, prefixLength, interfaceName = "") {
    const ipInt = ipv4ToInt(ip);
    const maskInt = maskLengthToInt(prefixLength);
    if (ipInt === null || maskInt === null) return;
    const networkInt = (ipInt & maskInt) >>> 0;
    entries.push({
      interfaceName,
      ip,
      prefixLength: Number(prefixLength),
      networkInt,
      cidr: `${intToIpv4(networkInt)}/${Number(prefixLength)}`
    });
  }
  function walk(node) {
    if (node === undefined || node === null) return;
    if (typeof node === "string") {
      const cidrMatches = node.match(/\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b/g) || [];
      cidrMatches.map(cidrInfo).filter(Boolean).forEach((info) => addEntry(info.ip, info.prefixLength));
      return;
    }
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    if (typeof node !== "object") return;

    const ip = node["ipv4-address"] || node.ipv4Address || node["ip-address"] || node.ipAddress || node.address;
    const prefixLength = node["ipv4-mask-length"] ?? node.ipv4MaskLength ?? node["mask-length4"] ?? node.maskLength4 ?? node["mask-length"] ?? node.maskLength;
    const netmask = node["ipv4-network-mask"] || node.ipv4NetworkMask || node["subnet-mask4"] || node.subnetMask4 || node["subnet-mask"] || node.subnetMask || node.netmask;
    const interfaceName = node.name || node.NAME || node["interface-name"] || node.interfaceName || "";
    if (ip && prefixLength !== undefined && prefixLength !== null) {
      addEntry(String(ip), prefixLength, String(interfaceName));
    } else if (ip && netmask) {
      const derivedPrefixLength = netmaskToPrefixLength(netmask);
      if (derivedPrefixLength !== null) {
        addEntry(String(ip), derivedPrefixLength, String(interfaceName));
      }
    }

    Object.values(node).forEach(walk);
  }
  walk(topology);
  const seen = new Set();
  return entries.filter((entry) => {
    const key = `${entry.interfaceName}/${entry.ip}/${entry.prefixLength}/${entry.cidr}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function gatewaySharedManagementSubnet(gateway, managementCidr) {
  const management = cidrInfo(managementCidr);
  if (!management) return null;
  const managementIpInt = ipv4ToInt(management.ip);
  if (managementIpInt === null) return null;
  return topologySubnetEntries(gateway)
    .find((entry) => {
      const maskInt = maskLengthToInt(entry.prefixLength);
      return maskInt !== null && ((managementIpInt & maskInt) >>> 0) === entry.networkInt;
    }) || null;
}

function sharedManagementSubnetMessage(managementName, managementIpMask, gateways) {
  const sharedSubnetGateways = (gateways || [])
    .map((gateway) => ({
      name: gateway.name || gateway.NAME || gateway.uid,
      subnet: gatewaySharedManagementSubnet(gateway, managementIpMask)
    }))
    .filter((entry) => entry.name && entry.subnet);
  if (!sharedSubnetGateways.length) {
    return "";
  }
  return `Management does not appear directly behind a gateway managed by ${managementName} but it does appear to be on the same private subnet shared by ${sharedSubnetGateways.map((entry) => `${entry.name}:${entry.subnet.interfaceName || "Interface"}:${entry.subnet.ip}`).join(", ")}`;
}

async function collectManagementFirewallEvidence(session, gatewaysAndServersResult, gatewaysResult) {
  const management = resolveManagementRunScriptTarget(session, gatewaysAndServersResult);
  if (management.smart1Cloud && !management.name) {
    const managementName = "Smart-1 Cloud";
    return {
      ok: true,
      command: "run-script/show-gateways-and-servers",
      managementName,
      skipped: true,
      rows: [{
        "Management Server Name": managementName,
        "Management Server IP/Mask": "Smart-1 Cloud hosted management",
        "Management Default Gateway": "Not applicable",
        "Management Server Behind Gateway": "Smart-1 Cloud management is hosted by Check Point; Gaia route lookup is not available from the tenant API context."
      }],
      errors: []
    };
  }
  const managementName = management.name || managementLoginHost(session) || session.baseUrl;
  const managementRunSession = mdsRunScriptSession(session, management);
  const routeScript = await runScriptWithTaskDetails(managementRunSession, {
    targets: [managementName],
    "script-name": "collect management network evidence",
    script: [
      "printf '\\n__CPBPS_MANAGEMENT_INTERFACES__\\n'",
      "ip -o -4 addr show scope global | cut -d' ' -f7",
      "printf '\\n__CPBPS_MANAGEMENT_DEFAULT_ROUTE__\\n'",
      "netstat -rn | awk '$1 == \"0.0.0.0\" {print $2}'"
    ].join("\n")
  });
  const routeParts = splitGaiaCombinedOutput(runScriptOutputText(routeScript));
  const interfaceStatus = routeScript.ok ? routeParts.section("MANAGEMENT_INTERFACES") : statusDescriptionText(routeScript);
  const defaultRouteStatus = routeScript.ok ? routeParts.section("MANAGEMENT_DEFAULT_ROUTE") : statusDescriptionText(routeScript);
  const managementIpMask = firstIpv4Cidr(interfaceStatus) || interfaceStatus || "Not returned";
  const defaultGatewayIp = firstIpv4(defaultRouteStatus) || "Not returned";
  let behindGateway = "";
  if (gatewaysResult.ok && defaultGatewayIp !== "Not returned") {
    const matchingGateways = (gatewaysResult.objects || [])
      .filter((gateway) => gatewayContainsExactTopologyIp(gateway, defaultGatewayIp))
      .map((gateway) => gateway.name || gateway.NAME || gateway.uid)
      .filter(Boolean);
    if (matchingGateways.length) {
      behindGateway = uniqueStrings(matchingGateways).join(", ");
    } else {
      behindGateway = sharedManagementSubnetMessage(managementName, managementIpMask, gatewaysResult.objects)
        || `Management does not appear behind a gateway managed by ${managementName}`;
    }
  } else {
    behindGateway = gatewaysResult.ok
      ? (sharedManagementSubnetMessage(managementName, managementIpMask, gatewaysResult.objects)
        || `Management does not appear behind a gateway managed by ${managementName}`)
      : "Gateway topology could not be retrieved.";
  }
  return {
    ok: routeScript.ok && gatewaysResult.ok,
    command: "run-script/show-gateways-and-servers",
    managementName,
    interfaceScript: routeScript,
    defaultRouteScript: routeScript,
    rows: [{
      "Management Server Name": managementName,
      "Management Server IP/Mask": managementIpMask,
      "Management Default Gateway": defaultGatewayIp,
      "Management Server Behind Gateway": behindGateway
    }],
    errors: [
      routeScript.ok ? null : routeScript.error,
      gatewaysResult.ok ? null : gatewaysResult.error,
      gatewaysAndServersResult.ok ? null : gatewaysAndServersResult.error
    ].filter(Boolean)
  };
}

function evaluateGatewayStealthRules(result, session) {
  const source = "Hardening guide: Security Gateway Stealth Rule";
  const reviewHistory = appHistory.reviews.get("policy.stealth-rule") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  if (!result.ok && !result.gateways?.length) {
    return makeCheck({
      id: "policy.stealth-rule",
      category: "Decreasing Security Gateway Exposure with Policy",
      title: "Implement Security Gateway Stealth Rule",
      recommendation: "Configure a Stealth Rule to drop traffic that is directed to the Security Gateway itself, except for explicitly required management and control traffic. Security Gateways are frequently scanned. A Stealth Rule reduces the Security Gateway's exposure and limits which hosts can reach Security Gateway services.",
      status: "unknown",
      severity: "high",
      evidence: "Security Gateway stealth rule evidence could not be collected.",
      details: result.error?.error || "Gateway inventory or policy lookup failed.",
      source,
      commands: ["show-gateways-and-servers", result.command]
    });
  }

  const evidenceTables = [...(result.rowsByPolicy || new Map()).entries()].map(([policyName, rows]) => ({
    title: policyName,
    columns: ["Gateway", "Rule #", "Disabled", "Rule Name", "Source", "Destination", "Service", "Action", "Log", "Stealth Rule"],
    rows: [...rows].sort((a, b) => Number(a["Rule #"] || 0) - Number(b["Rule #"] || 0))
  }));
  const hasPolicyEvidence = evidenceTables.length > 0;
  const missingNames = (result.missingGateways || []).map((gateway) => gateway.name || gateway.uid).filter(Boolean);
  if (missingNames.length) {
    evidenceTables.push({
      title: result.ok ? "Missing Stealth Rules" : "Stealth Rules Not Verified",
      columns: ["Gateway", "Finding"],
      rows: missingNames.map((name) => ({
        "Gateway": name,
        "Finding": result.ok ? `${name} does not have a stealth rule. Please remediate this.`
          : `${name}: no matching rule in the collected evidence. Policy collection was incomplete; verify manually.`
      }))
    });
  }
  const hasGatewayInventory = (result.gateways || []).length > 0;
  const allMatched = hasGatewayInventory && missingNames.length === 0;
  const failedLookups = result.errors?.length || 0;
  const lookupFailureWarning = failedLookups
    ? `${failedLookups} policy lookup${failedLookups === 1 ? "" : "s"} could not be fully collected. Review the visible policy evidence and debug log for the failed lookup.`
    : "";
  const stealthRuleDetails = "Review any rules above the Stealth Rule. Allow only required traffic that is directed to the Security Gateway. Drop all other traffic directed to the Security Gateway. Logging should be Enabled during rollout, then tuned to reduce noise.";
  const recommendationWarnings = [
    !allMatched && hasGatewayInventory ? `No matching stealth rule was found for: ${missingNames.join(", ")}.` : "",
    lookupFailureWarning
  ].filter(Boolean);
  const status = !hasGatewayInventory || (failedLookups && !allMatched)
    ? "unknown"
    : (reviewedThisLogin ? "reviewed" : (allMatched ? "needs-review" : "remediation-required"));

  return makeCheck({
    id: "policy.stealth-rule",
    category: "Decreasing Security Gateway Exposure with Policy",
    title: "Implement Security Gateway Stealth Rule",
    recommendation: "Configure a Stealth Rule to drop traffic that is directed to the Security Gateway itself, except for explicitly required management and control traffic. Security Gateways are frequently scanned. A Stealth Rule reduces the Security Gateway's exposure and limits which hosts can reach Security Gateway services.",
    status,
    severity: allMatched ? "medium" : "high",
    evidence: hasGatewayInventory
      ? `${result.gateways.length} gateway${result.gateways.length === 1 ? "" : "s"} checked for destination rules.`
      : "No gateway or cluster policy targets were returned.",
    evidenceTables: evidenceTables.length ? evidenceTables : null,
    details: !hasGatewayInventory
      ? "No simple gateway objects were returned to evaluate."
      : stealthRuleDetails,
    recommendationWarning: recommendationWarnings,
    source,
    commands: ["show-gateways-and-servers: gateway and cluster policy targets", "show-packages: access-layers", "where-used: destination usage", "show-access-rule: source,destination,service,action"],
    review: hasGatewayInventory && hasPolicyEvidence ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateGatewayObjectStatus(result) {
  const rows = result.rows || [];
  return makeCheck({
    id: "policy.gateway-object-status",
    category: "Decreasing Security Gateway Exposure with Policy",
    title: "Gateway Object SIC Status",
    recommendation: "Delete gateway objects that no longer have SIC established after confirming they are no longer required. Stale gateway objects may represent old infrastructure and can leave unnecessary IP access exposed in policy or management configuration.",
    status: rows.length ? "remediation-recommended" : (result.results?.length ? "pass" : "unknown"),
    severity: rows.length ? "high" : "info",
    evidence: rows.length
      ? `${rows.length} managed gateway or cluster member object${rows.length === 1 ? " is" : "s are"} not communicating through SIC and were excluded from gateway-level scanning.`
      : (result.results?.length
        ? `All ${result.results.length} managed gateway and cluster member object${result.results.length === 1 ? " is" : "s are"} communicating through SIC.`
        : "No managed gateway or cluster member objects were available for SIC validation."),
    evidenceTone: !rows.length && result.results?.length ? "success" : "",
    evidenceTable: rows.length ? {
      columns: ["Object Name", "Object IP-Address", "SIC Status", "SIC Message", "SIC Name"],
      rows
    } : null,
    details: rows.length
      ? "Only objects whose live test-sic-status result is not Communicating are shown. These objects were skipped by subsequent gateway-level checks to avoid unnecessary scan time. Validate that an object is obsolete before deleting it."
      : "Only gateway and cluster member objects that do not return a Communicating SIC state appear in this subsection.",
    source: "Hardening review: active Gateway Object SIC Status",
    commands: [result.command || "test-sic-status: name <gateway object>"]
  });
}

function evaluateManagementFirewallProtection(result, session) {
  const source = "Hardening guide: Protect the Management Server Behind a Firewall";
  const behindValue = result.rows?.[0]?.["Management Server Behind Gateway"] || "";
  const appearsBehindGateway = Boolean(behindValue && !behindValue.startsWith("Management does not appear") && !behindValue.startsWith("Gateway topology"));
  const reviewHistory = appHistory.reviews.get("mgmt.protected-segment") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const designWarning = result.ok && !appearsBehindGateway
    ? `${result.managementName || "The Management Server"} does not appear directly behind one of the gateways it has access to manage. Please review your management plane design and make sure your Management server is protected by a Security Gateway.`
    : "";
  return makeCheck({
    id: "mgmt.protected-segment",
    category: "Management Plane Protection",
    title: "Protect Management Server Behind A Firewall",
    recommendation: "Deploy the Security Management Server behind a firewall or protected network segment and restrict inbound access to required administrative sources only.",
    status: result.ok ? (reviewedThisLogin ? "reviewed" : (appearsBehindGateway ? "needs-review" : "remediation-review-recommended")) : "unknown",
    severity: appearsBehindGateway ? "medium" : "high",
    evidence: result.ok
      ? "Management routing evidence and managed gateway topology were evaluated."
      : `${result.errors?.length || 0} management firewall evidence collection command${(result.errors?.length || 0) === 1 ? "" : "s"} failed.`,
    evidenceTable: result.rows?.length ? {
      columns: ["Management Server Name", "Management Server IP/Mask", "Management Default Gateway", "Management Server Behind Gateway"],
      rows: result.rows
    } : null,
    details: "The Management Server controls policy installation, trust relationships (SIC), and administrator access. Segmentation reduces exposure and blast radius.",
    detailRows: designWarning ? [{
      label: "Remediation Review Recommendation",
      text: designWarning,
      bold: [designWarning],
      tone: "critical"
    }] : null,
    source,
    commands: [
      "show-gateways-and-servers: resolve management object name",
      "run-script: ip -o -4 addr show scope global | cut -d' ' -f7",
      "run-script: netstat -rn | awk '$1 == \"0.0.0.0\" {print $2}'",
      "show-gateways-and-servers: topology"
    ],
    review: result.ok ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateAdministrativeSourceIpAddresses(result, session) {
  const source = "Hardening guide: Restrict Administrative Source IP Addresses";
  const reviewHistory = appHistory.reviews.get("mgmt.admin-source-ip") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedLookups = result.errors?.length || 0;
  const evidenceTables = [...(result.rowsByPolicy || new Map()).entries()].map(([policyName, rows]) => ({
    title: policyName,
    columns: ["Rule #", "Disabled", "Rule Name", "Source", "Destination", "Services", "Action", "Log"],
    rows: [...rows].sort((a, b) => Number(a["Rule #"] || 0) - Number(b["Rule #"] || 0))
  }));
  const accessRuleCount = [...(result.rowsByPolicy || new Map()).values()].reduce((total, rows) => total + rows.length, 0);
  const automaticNatCount = result.automaticNatRows?.length || 0;
  const translatedDestinationNatCount = result.translatedDestinationNatRows?.length || 0;
  const natFindingCount = automaticNatCount + translatedDestinationNatCount;
  const manualNatOriginalDestinationCount = result.manualNatOriginalDestinationCount || 0;
  if (result.objectRows?.length) {
    evidenceTables.unshift({
      title: "Object Table",
      columns: ["Object Name", "Object Type", "Details"],
      rows: result.objectRows
    });
  }
  if (automaticNatCount) {
    evidenceTables.push({
      title: "Management Object Automatic NAT",
      columns: ["Management Object", "NAT Type", "Auto Rule", "Method", "Translated IPv4 Address", "Install On"],
      rows: result.automaticNatRows
    });
  }
  if (translatedDestinationNatCount) {
    evidenceTables.push({
      title: "NAT Rules Translating To The Management Server",
      columns: ["Policy Package", "Rule #", "Disabled", "Rule Name", "Original Source", "Original Destination", "Original Service", "Translated Source", "Translated Destination", "Translated Service"],
      rows: result.translatedDestinationNatRows
    });
  }
  return makeCheck({
    id: "mgmt.admin-source-ip",
    category: "Management Plane Protection",
    title: "Restrict Administrative Source IP Addresses",
    recommendation: "Restrict SmartConsole, WebUI, SSH, and API access to internal admin networks or jump hosts.",
    status: result.ok ? (reviewedThisLogin ? "reviewed" : "remediation-review-recommended") : "unknown",
    severity: "high",
    evidence: result.ok
      ? `${accessRuleCount} access rule${accessRuleCount === 1 ? "" : "s"} reference the Management Server or its manual NAT Original Destination objects. ${natFindingCount} management NAT configuration${natFindingCount === 1 ? "" : "s"} found.`
      : `${failedLookups} administrative source IP evidence collection command${failedLookups === 1 ? "" : "s"} failed.`,
    evidenceTables: evidenceTables.length ? evidenceTables : null,
    details: result.ok
      ? (natFindingCount
        ? `The Management Server is being NATed through automatic object NAT, a NAT policy rule with the Management Server in Translated Destination, or both.${manualNatOriginalDestinationCount ? ` ${manualNatOriginalDestinationCount} manual NAT Original Destination object${manualNatOriginalDestinationCount === 1 ? " was" : "s were"} checked with where-used for related access rules.` : ""} Review the translated address and every access rule that can reach it; confirm administrative access is limited to approved source networks or jump hosts.`
        : "No Management Server NAT configuration was found. Review rules that directly reference the Management Server object and confirm administrative access is limited to approved source networks or jump hosts.")
      : "Management Server rule usage could not be fully collected.",
    detailsWarning: natFindingCount
      ? `${result.managementName} is being NATed. Include the translated address in the administrative exposure review and restrict access to approved source IP addresses.`
      : "",
    source,
    commands: ["show-mdss (MDS root session): resolve the physical MDS object and domain management servers", "show-global-assignments: resolve the Global access policy assigned to the scanned domain", "show-gateways-and-servers: resolve the domain management object and inspect nat-settings", "show-networks: networks containing management IP", "show-address-ranges: address ranges containing management IP", "where-used: management object, manual NAT Original Destination objects, matching network/address range objects, and related groups", "show-packages: local policies and the assigned Global access policy", "show-access-rulebase: direct MDS and domain-management references in applicable policies", "show-access-rule: source,destination,service,action,track", "show-nat-rulebase: translated-destination usage of the Management Server object"],
    review: result.ok ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateGaiaAllowedHostAccess(result, session) {
  const source = "Hardening guide: Gaia OS allowed host access";
  const reviewHistory = appHistory.reviews.get("gaia.allowed-host-access") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedLookups = result.errors?.length || 0;
  const evidenceTables = (result.evidenceTables || []).map((table) => {
    const targetName = String(table.title || "").replace(/^(Gateway|Management) Name:\s*/i, "").trim();
    const hasAnyAllowedClient = gaiaAllowedClientRowsAllowAny(table.rows || []);
    return {
      ...table,
      targetSelection: targetName ? {
        value: targetName,
        label: table.title || targetName,
        management: /^Management Name:/i.test(String(table.title || "")),
        hasAnyAllowedClient,
        onlyAnyAllowedClient: hasAnyAllowedClient && (table.rows || []).length === 1
      } : null
    };
  });
  const anyDeviceNames = uniqueStrings(evidenceTables
    .filter((table) => gaiaAllowedClientRowsAllowAny(table.rows || []))
    .map((table) => String(table.title || "")
      .replace(/^(Gateway|Management) Name:\s*/i, "")
      .trim())
    .filter(Boolean));
  const hasAnyAccess = anyDeviceNames.length > 0;
  const detailRows = [];
  if (failedLookups) {
    detailRows.push({
      label: "Details",
      text: `${failedLookups} Gaia allowed-host access lookup${failedLookups === 1 ? "" : "s"} failed.`
    });
  }
  if (hasAnyAccess) {
    for (const deviceName of anyDeviceNames) {
      const text = `${deviceName} allows access from ANY IP address through trusted client AnyHost. This is a major security concern and should immediately be limited to restricted IPs.`;
      detailRows.push({
        label: "Details",
        text,
        bold: [text],
        tone: "critical"
      });
    }
  } else if (!failedLookups) {
    detailRows.push({
      label: "Details",
      text: "Review each Gaia allowed-client entry and confirm Gaia access is limited to approved administrative sources."
    });
  }

  return makeCheck({
    id: "gaia.allowed-host-access",
    category: "Gaia OS Hardening",
    title: "Gaia Allowed Host Access",
    recommendation: "Limit access to GAIA trusted client access to the necessary IP addresses, subnets, and ranges.",
    status: result.ok ? (reviewedThisLogin ? "reviewed" : (hasAnyAccess ? "remediation-recommended" : "needs-review")) : "unknown",
    severity: hasAnyAccess ? "high" : "medium",
    evidence: evidenceTables.length
      ? `${evidenceTables.length} Gaia OS target${evidenceTables.length === 1 ? "" : "s"} returned allowed-host access evidence.`
      : "No Gaia allowed-host access evidence was returned.",
    evidenceTables: evidenceTables.length ? evidenceTables : null,
    details: "",
    detailRows,
    source,
    commands: ["run-script: clish -c \"show allowed-client all\""],
    review: evidenceTables.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin,
      warning: hasAnyAccess
        ? "You are accepting Gaia allowed-host access settings that allow access from ANY IP address. Confirm this exposure is approved before continuing."
        : ""
    } : null
  });
}

function evaluateGaiaAdministratorSettings(result, session) {
  const source = "Hardening guide: Gaia OS administrator settings";
  const reviewHistory = appHistory.reviews.get("gaia.admin-settings") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedLookups = result.errors?.length || 0;
  const tableCount = result.evidenceTables?.length || 0;
  const userRows = (result.evidenceTables || [])
    .flatMap((table) => table.rows || [])
    .filter((row) => {
      const user = normalizeToken(row.User);
      return user && user !== "user" && user !== "lookupfailed" && user !== "nousersreturned";
    });
  const privilegedUserRows = userRows.filter((row) => gaiaUserHasDirectExpertShell(row) || normalizeToken(gaiaPrivilegesText(row)) !== "none");
  const nonClishUsers = uniqueStrings(privilegedUserRows
    .filter((row) => gaiaShellText(row) && !gaiaUserUsesRecommendedShell(row))
    .map((row) => gaiaUserText(row)));
  const disabledTwoFactorUsers = uniqueStrings(privilegedUserRows
    .filter((row) => normalizeToken(gaiaTwoFactorText(row)) === "disabled")
    .map((row) => gaiaUserText(row)));
  const findingRows = [{
    label: "Findings",
    text: failedLookups
      ? `${failedLookups} gateway lookup${failedLookups === 1 ? "" : "s"} failed while collecting Gaia OS administrator settings.`
      : "Review each user has appropriate shell access and 2FA is being used."
  }];
  if (nonClishUsers.length) {
    const text = `${nonClishUsers.join(", ")} ${nonClishUsers.length === 1 ? "is" : "are"} not using the recommended shell /etc/cli.sh. Please review.`;
    findingRows.push({
      label: "Findings",
      text,
      bold: [text],
      tone: "critical"
    });
  }
  if (disabledTwoFactorUsers.length) {
    const text = `Currently ${disabledTwoFactorUsers.join(", ")} ${disabledTwoFactorUsers.length === 1 ? "does" : "do"} not have 2FA enabled. Please review access.`;
    findingRows.push({
      label: "Findings",
      text,
      bold: [text],
      tone: "critical"
    });
  }
  return makeCheck({
    id: "gaia.admin-settings",
    category: "Gaia OS Hardening",
    title: "GAIA OS Administrator Settings",
    recommendation: "Review all users with access to the Gaia OS and ensure all users are authorized, use strong passwords, configure the access role to allow the minimal access required per user role, ensure the shell is set to Gaia Clish and force users to use MFA for access.",
    status: result.ok ? (reviewedThisLogin ? "reviewed" : "needs-review") : "unknown",
    severity: "medium",
    evidence: tableCount
      ? `${tableCount} gateway${tableCount === 1 ? "" : "s"} returned Gaia OS administrator user evidence.`
      : "No Gaia OS administrator user evidence was returned.",
    evidenceTables: result.evidenceTables?.length ? result.evidenceTables : null,
    details: "",
    detailRows: findingRows,
    source,
    commands: [
      "run-script: clish -c \"show users\"",
      "run-script: clish -c \"show syslog logs search 'Web UI connection by USERNAME'\"",
      "run-script: clish -c \"show syslog logs search 'SSH connection by USERNAME'\""
    ],
    review: tableCount ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateGaiaExpertModeAccess(result, session) {
  const source = "Hardening guide: Restrict Expert Mode Access";
  const reviewHistory = appHistory.reviews.get("gaia.expert-mode-access") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedLookups = result.errors?.length || 0;
  const evidenceTables = (result.evidenceTables || []).map((table) => {
    const expertRows = (table.rows || []).filter((row) => gaiaUserHasExpertPrivilege(row) || gaiaUserHasDirectExpertShell(row));
    return {
      title: table.title,
      columns: ["Username", "Access to Expert"],
      rows: expertRows.length
        ? expertRows.map((row) => ({
          "Username": gaiaUserText(row) || "Unknown",
          "Access to Expert": gaiaUserHasDirectExpertShell(row)
            ? { value: "Yes - Direct Expert Shell", tone: "critical" }
            : "Yes"
        }))
        : [{
          "Username": "No users with Expert access",
          "Access to Expert": "No"
        }]
    };
  });
  const expertUserCount = evidenceTables
    .flatMap((table) => table.rows || [])
    .filter((row) => evidenceCellText(row["Access to Expert"]).startsWith("Yes"))
    .length;
  return makeCheck({
    id: "gaia.expert-mode-access",
    category: "Gaia OS Hardening",
    title: "Restrict Expert Mode Access",
    recommendation: "Restrict the Expert mode access to a limited, authorized set of administrators. Use integration with Check Point Playblocks to alert every time the Expert mode is activated (this Playblocks automation does not require a subscription to Playblocks).",
    status: result.ok ? (reviewedThisLogin ? "reviewed" : "needs-review") : "unknown",
    severity: "high",
    evidence: result.ok
      ? `${expertUserCount} Gaia OS user${expertUserCount === 1 ? "" : "s"} with Expert mode access were identified.`
      : `${failedLookups} target lookup${failedLookups === 1 ? "" : "s"} failed while collecting Gaia OS Expert mode access.`,
    evidenceTables: evidenceTables.length ? evidenceTables : null,
    details: "The Expert mode provides full OS access as root user and should be tightly controlled.",
    detailRows: [{
      label: "Details",
      text: "Check Point recommends creating a new Admin Role for R/W but limit Expert Mode, Expert Authentication Method, Expert Password, and Expert Password Hash to None or Read Only.",
      bold: ["Check Point recommends creating a new Admin Role for R/W but limit Expert Mode, Expert Authentication Method, Expert Password, and Expert Password Hash to None or Read Only."],
      tone: "critical"
    }],
    source,
    commands: [
      "run-script: clish -c \"show users\"",
      "run-script: clish -c \"show syslog logs search 'Web UI connection by USERNAME'\"",
      "run-script: clish -c \"show syslog logs search 'SSH connection by USERNAME'\""
    ],
    review: evidenceTables.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateGaiaPasswordPolicyHardening(result, session) {
  const source = "Hardening guide: Gaia OS password policy hardening";
  const reviewHistory = appHistory.reviews.get("gaia.password-policy-hardening") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedLookups = result.errors?.length || 0;
  const tableCount = result.evidenceTables?.length || 0;
  return makeCheck({
    id: "gaia.password-policy-hardening",
    category: "Gaia OS Hardening",
    title: "Password Policy Hardening (Complexity, Age, Reuse)",
    recommendation: "Enforce password complexity, multi-factor authentication (R82 or higher), password history (reuse prevention), password aging, auto lock out of admins with multiple authentication failures or with long inactivity periods.",
    status: result.ok ? (reviewedThisLogin ? "reviewed" : "needs-review") : "unknown",
    severity: "high",
    evidence: tableCount
      ? `${tableCount} Gaia OS target${tableCount === 1 ? "" : "s"} returned password control evidence.`
      : "No Gaia OS password policy evidence was returned.",
    evidenceTables: result.evidenceTables?.length ? result.evidenceTables : null,
    details: failedLookups
      ? `${failedLookups} target lookup${failedLookups === 1 ? "" : "s"} failed while collecting Gaia OS password policy settings.`
      : "Strong password policy reduces brute force and credential reuse risk. Automatically disabling dormant administrator accounts significantly reduces the attack surface by preventing access from accounts associated with former employees.",
    source,
    commands: ["run-script: clish -c \"show password-controls all\""],
    review: tableCount ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateGaiaSnmpMonitoringHardening(result, session) {
  const source = "Hardening guide: Gaia OS SNMP monitoring hardening";
  const reviewHistory = appHistory.reviews.get("gaia.snmp-monitoring-hardening") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedLookups = result.errors?.length || 0;
  const tableCount = result.evidenceTables?.length || 0;
  const rows = (result.evidenceTables || []).flatMap((table) => table.rows || []);
  const enabledRows = rows.filter((row) => normalizeToken(row["SNMP Status"]) === "enabled");
  const recommendationRows = rows.filter((row) => row["Check Point Recommended"]);
  const evidenceTables = (result.evidenceTables || []).map((table) => ({
    ...table,
    rows: (table.rows || []).map((row) => {
      if (normalizeToken(row["SNMP Status"]) !== "enabled") return row;
      const versionText = String(row["SNMP Agent Version"] || "").toLowerCase();
      const weakVersion = /\b(?:snmp)?v?1\b/.test(versionText) || /\b(?:snmp)?v?2c?\b/.test(versionText);
      return weakVersion
        ? {
          ...row,
          "SNMP Agent Version": { value: row["SNMP Agent Version"], tone: "critical" }
        }
        : row;
    })
  }));
  return makeCheck({
    id: "gaia.snmp-monitoring-hardening",
    category: "Gaia OS Hardening",
    title: "SNMP Monitoring Hardening",
    recommendation: "Disable SNMP if not needed. If SNMP is required, use SNMPv3 with SHA512 authentication and AES256 encryption (do not use SNMPv1 or SNMPv2). Run the SNMP agent only on internal interfaces and only allow specific IPs to send requests to these interfaces. For monitoring of Check Point Security Gateways and Management Server, a read-only permission is sufficient.",
    status: result.ok ? (reviewedThisLogin ? "reviewed" : (recommendationRows.length ? "remediation-recommended" : "needs-review")) : "unknown",
    severity: enabledRows.length ? "high" : "medium",
    evidence: tableCount
      ? `${tableCount} Gaia OS target${tableCount === 1 ? "" : "s"} returned SNMP monitoring evidence. ${enabledRows.length} target${enabledRows.length === 1 ? "" : "s"} have SNMP enabled.`
      : "No Gaia OS SNMP monitoring evidence was returned.",
    evidenceTables: evidenceTables.length ? evidenceTables : null,
    details: failedLookups
      ? `${failedLookups} SNMP lookup${failedLookups === 1 ? "" : "s"} failed while collecting Gaia OS SNMP monitoring settings.`
      : "SNMP can expose operational details. Secure configuration reduces information disclosure risk.",
    source,
    commands: [
      "run-script: clish -c \"show snmp agent\"",
      "run-script: clish -c \"show snmp agent-version\"",
      "run-script: clish -c \"show snmp interfaces\"",
      "run-script: clish -c \"show snmp usm users\"",
      "run-script: clish -c \"show snmp usm user USERNAME\""
    ],
    review: tableCount ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin,
      warning: recommendationRows.length
        ? "You are accepting SNMP monitoring settings that do not match Check Point recommendations. Confirm SNMP exposure, version, interfaces, and USM cryptographic settings are approved."
        : ""
    } : null
  });
}

function evaluateGaiaSystemLoggingToManagement(result, session) {
  const source = "Hardening guide: Gaia OS system logging";
  const reviewHistory = appHistory.reviews.get("gaia.system-logging-management") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedLookups = result.errors?.length || 0;
  const disabledCount = (result.rows || []).filter((row) => row["Syslog Forwarding To Manager"] === "No").length;
  const rows = (result.rows || []).map((row) => {
    const displayedRow = {
      ...row,
      _select: row["Syslog Forwarding To Manager"] === "No" ? {
        value: row.Name,
        label: row.Name
      } : null,
      "External Syslog Configuration": row["External Syslog Configuration Table"]
        ? {
          keyValue: row["External Syslog Configuration Table"].rows.map((item) => ({
            key: item["Column Title"],
            value: item["Information"]
          }))
        }
        : {
          value: row["External Syslog Configuration"] || "Not returned",
          multiline: true
        }
    };
    return displayedRow;
  });
  return makeCheck({
    id: "gaia.system-logging-management",
    category: "Gaia OS Hardening",
    title: "Enable Security Gateway System Logging To The Management Server",
    recommendation: "Configure each Security Gateway to forward its Gaia OS system logs (syslog) to the Management Server and avoid relying solely on local log files on the Security Gateway.",
    status: result.ok ? (reviewedThisLogin ? "reviewed" : (disabledCount ? "remediation-recommended" : "needs-review")) : "unknown",
    severity: disabledCount ? "high" : "medium",
    evidence: result.rows?.length
      ? `${result.rows.length} Gaia OS target${result.rows.length === 1 ? "" : "s"} checked for syslog forwarding. ${disabledCount} target${disabledCount === 1 ? "" : "s"} returned disabled.`
      : "No Gaia OS syslog forwarding evidence was returned.",
    evidenceTable: rows.length ? {
      selectable: true,
      selectionName: "gateway",
      columns: ["Name", "Syslog Forwarding To Manager", "Gateway Forwarding To External Server", "External Syslog Configuration"],
      rows
    } : null,
    details: failedLookups
      ? `${failedLookups} target lookup${failedLookups === 1 ? "" : "s"} failed while collecting Gaia OS syslog forwarding settings.`
      : "Local syslog retention on the Security Gateway should be treated as a temporary buffer only, not as the primary source of system level visibility, for these reasons:",
    detailRows: failedLookups ? null : [{
      label: "Details",
      text: "",
      bullets: [
        "Centralized operational visibility: Forwarding syslog to the Management Server allows administrators to review the Security Gateway's Gaia OS events alongside management plane activity.",
        "Improved troubleshooting: Many platform issues (for example routing daemon events, authentication failures, or service restarts) are visible only in system logs.",
        "Ability to audit: Central retention of system logs supports forensic analysis and operational audits.",
        "Resilience: Security Gateway local logs may be lost during reboot, disk issues, or hardware failure; central collection reduces this risk."
      ]
    }],
    source,
    commands: [
      "run-script: clish -c \"show syslog cplogs\"",
      "run-script: clish -c \"show syslog log-remote-addresses\""
    ],
    review: result.rows?.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function evaluateGaiaManagementExternalSyslog(result, session) {
  const source = "Hardening guide: Gaia OS system logging";
  const reviewHistory = appHistory.reviews.get("gaia.management-external-syslog") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  const failedLookups = result.errors?.length || 0;
  const missingForwarding = (result.rows || []).some((row) => (
    row["Syslog Forwarding"] === "No database items for log remote addresses" ||
    row["Syslog Forwarding"] === "No Forwarding Server Configured" ||
    row["Syslog Forwarding"] === "Lookup failed"
  ));
  const missingForwardingNames = uniqueStrings((result.rows || [])
    .filter((row) => (
      row["Syslog Forwarding"] === "No database items for log remote addresses" ||
      row["Syslog Forwarding"] === "No Forwarding Server Configured" ||
      row["Syslog Forwarding"] === "Lookup failed"
    ))
    .map((row) => row.Name || "Management Server"));
  const forwardingWarning = missingForwardingNames.length
    ? `Please setup forwarding for ${missingForwardingNames.join(", ")} in GAIA by going to System Management > System Logging > Configuring System Logging in Gaia Portal > Configuring the Remote System Logging.`
    : "";
  return makeCheck({
    id: "gaia.management-external-syslog",
    category: "Gaia OS Hardening",
    title: "Enable Management Server System Logging To An External Server",
    recommendation: "Configure the Management Server to forward its Gaia OS system logs (syslog) to an external centralized log server, in addition to retaining a local copy for short term operational troubleshooting.",
    recommendationWarning: forwardingWarning,
    status: result.ok ? (reviewedThisLogin ? "reviewed" : (missingForwarding ? "remediation-recommended" : "needs-review")) : "unknown",
    severity: missingForwarding ? "high" : "medium",
    evidence: result.rows?.length
      ? `${result.rows.length} Management Server Gaia OS syslog forwarding check returned evidence.`
      : "No Management Server syslog forwarding evidence was returned.",
    evidenceTable: result.rows?.length ? {
      columns: ["Name", "Syslog Forwarding"],
      rows: result.rows
    } : null,
    details: failedLookups
      ? `${failedLookups} Management Server lookup${failedLookups === 1 ? "" : "s"} failed while collecting Gaia OS external syslog forwarding settings.`
      : "System logs generated by the Management Server should not be retained only locally. Centralized retention supports investigations, regulatory audits, and compliance evidence requirements.",
    source,
    commands: ["run-script: clish -c \"show syslog log-remote-addresses\""],
    review: result.rows?.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin,
      warning: missingForwarding
        ? "You are accepting Management Server system logging settings where external syslog forwarding is not configured. Check Point recommends forwarding Gaia OS system logs to an external centralized log server."
        : ""
    } : null
  });
}

function evaluateGateways(result) {
  const source = "Hardening guide: Gaia OS Hardening, SNMP, dynamic routing, syslog, and LOM restrictions";
  if (!result.ok) {
    return [
      makeCheck({
        id: "gaia.gateway-inventory",
        category: "Gaia OS Hardening",
        title: "Inventory Gateways For Gaia Hardening Review",
        recommendation: "Review each Security Gateway for Gaia OS password policy, SNMP, dynamic routing, syslog, Expert mode, and LOM exposure.",
        status: "unknown",
        evidence: "Gateway inventory could not be retrieved.",
        details: result.error?.error || "",
        source,
        commands: [result.command]
      })
    ];
  }

  const gateways = result.objects || [];
  const names = gateways.map((gateway) => gateway.name || gateway.uid).filter(Boolean).slice(0, 20);
  return [
    makeCheck({
      id: "gaia.gateway-inventory",
      category: "Gaia OS Hardening",
      title: "Inventory Gateways For Gaia Hardening Review",
      recommendation: "Review all Gaia OS users, roles, password policy, SNMP, dynamic routing, Expert mode, syslog, and LOM access.",
      status: gateways.length ? "manual" : "needs-review",
      evidence: gateways.length ? `${gateways.length} gateway, cluster, or member object${gateways.length === 1 ? "" : "s"} found: ${names.join(", ")}${gateways.length > names.length ? ", ..." : ""}` : "No gateway, cluster, or member objects were returned.",
      details: "Most Gaia OS controls require Gaia Portal, Gaia API, SSH/Clish, or an explicit gateway-side collection method.",
      source,
      commands: [result.command]
    }),
    makeCheck({
      id: "gaia.snmp",
      category: "Gaia OS Hardening",
      title: "Harden SNMP Monitoring",
      recommendation: "Disable SNMP if unused. If required, use SNMPv3-only with SHA512 authentication, AES256 privacy, internal interfaces, and specific source IPs.",
      status: "manual",
      evidence: "Management API gateway inventory does not reliably expose Gaia SNMP agent settings.",
      details: "Validate in Gaia Portal > System Management > SNMP.",
      source,
      commands: [result.command]
    }),
    makeCheck({
      id: "gaia.syslog-gateway",
      category: "Gaia OS Hardening",
      title: "Forward Security Gateway System Logs To Management",
      recommendation: "Configure each gateway to send Gaia OS syslog messages to the Management Server / Log Server.",
      status: "manual",
      evidence: "Management API gateway inventory does not reliably expose Gaia system logging settings.",
      details: "Validate in Gaia Portal > System Management > System Logging.",
      source,
      commands: [result.command]
    })
  ];
}

function propertyValue(properties = [], propertyName) {
  const normalizedName = normalizeToken(propertyName);
  const match = Array.isArray(properties)
    ? properties.find((property) => normalizeToken(property?.name) === normalizedName)
    : null;
  return match?.value ?? "";
}

function cloudUserAppId(cloudProvider, authenticationMethod, properties = []) {
  if (cloudProvider === "aws") {
    if (authenticationMethod === "user-authentication") {
      return `Access Key ID: ${propertyValue(properties, "access-key-id") || "Not returned"}`;
    }
    return "N/A";
  }
  if (cloudProvider === "azure") {
    if (authenticationMethod === "service-principal-authentication") {
      return [
        `Application ID: ${propertyValue(properties, "application-id") || "Not returned"}`,
        `Directory ID: ${propertyValue(properties, "directory-id") || "Not returned"}`
      ].join("; ");
    }
    if (authenticationMethod === "user-authentication") {
      return `Entra ID Username: ${propertyValue(properties, "username") || "Not returned"}`;
    }
    return "N/A";
  }
  return "N/A";
}

function cloudProviderRecommendedPermissions(cloudProvider) {
  const links = {
    aws: {
      label: "AWS Recommended Role is ReadOnlyAccess",
      url: "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html"
    },
    azure: {
      label: "Azure Recommends Minimum Reader Role",
      url: "https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal"
    },
    gcp: {
      label: "GCP Recommends the Reader or Viewer Role",
      url: "https://docs.cloud.google.com/iam/docs/roles-overview"
    }
  };
  const link = links[cloudProvider];
  return link ? { _link: link } : "N/A";
}

function evaluateCloudControllerIntegrations(result, session) {
  const source = "Hardening guide: Limiting Third-Party Integration Credentials";
  const recommendation = "Use cloud native roles / service accounts with read-only permissions for discovery. Add write permissions only if automation use cases require them. Cloud credentials can expose large parts of your infrastructure and metadata. Read only roles reduce impact of credential compromise. Examples (minimum privilege approach): AWS: IAM role limited to Describe* APIs only (for discovery), Azure: Service Principal / Managed Identity with Reader role, GCP: Service Account with Viewer role.";
  const details = "You will need to work with your Cloud Admin to review permissions. More info can be found here in the CloudGuard Controller Admin Guide.";
  const detailsLink = {
    label: "CloudGuard Controller Admin Guide",
    url: "https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_CloudGuard_Controller_AdminGuide/Content/Topics-CGRDG/Supported-Data-Centers.htm?tocpath=Supported%20Data%20Centers%7C_____0"
  };
  const reviewHistory = appHistory.reviews.get("integrations.cloud-controllers") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  if (!result.ok) {
    return makeCheck({
      id: "integrations.cloud-controllers",
      category: "Limiting Third-Party Integration Credentials",
      title: "Cloud Controller Integrations (AWS, Azure, GCP)",
      recommendation,
      status: "unknown",
      evidence: "Cloud controller integrations could not be retrieved.",
      details: result.error?.error || "",
      detailsLink,
      source,
      commands: [result.command]
    });
  }

  const supportedTypes = new Set(["aws", "azure", "gcp"]);
  const cloudObjects = (result.objects || []).filter((object) => supportedTypes.has(String(object["data-center-type"] || "").toLowerCase()));
  const rows = cloudObjects.map((object) => {
    const cloudProvider = String(object["data-center-type"] || "").toLowerCase();
    const authenticationMethod = propertyValue(object.properties, "authentication-method") || "Not returned";
    let cloudRegion = "N/A";
    if (cloudProvider === "aws") {
      cloudRegion = propertyValue(object.properties, "region") || "Not returned";
    }
    if (cloudProvider === "azure") {
      cloudRegion = propertyValue(object.properties, "environment") || "Not returned";
    }
    return {
      "Name of Object": object.name || object.NAME || object.uid || "",
      "Cloud Provider": cloudProvider.toUpperCase(),
      "Authentication Method": authenticationMethod,
      "User/App ID": cloudUserAppId(cloudProvider, authenticationMethod, object.properties),
      "Cloud Region/Environment": cloudRegion,
      "Provider Recommended Permissions": cloudProviderRecommendedPermissions(cloudProvider)
    };
  });

  return makeCheck({
    id: "integrations.cloud-controllers",
    category: "Limiting Third-Party Integration Credentials",
    title: "Cloud Controller Integrations (AWS, Azure, GCP)",
    recommendation,
    status: reviewedThisLogin ? "reviewed" : (rows.length ? "needs-review" : "manual"),
    evidence: rows.length
      ? `${rows.length} AWS, Azure, or GCP cloud controller integration${rows.length === 1 ? "" : "s"} returned.`
      : "No AWS, Azure, or GCP cloud controller integrations were returned.",
    evidenceTable: rows.length ? {
      columns: ["Name of Object", "Cloud Provider", "Authentication Method", "User/App ID", "Cloud Region/Environment", "Provider Recommended Permissions"],
      rows
    } : null,
    details,
    detailsLink,
    source,
    commands: [`${result.command}: name,data-center-type,properties`],
    review: {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    }
  });
}

function booleanState(value) {
  if (value === true || normalizeToken(value) === "true") return "Enabled";
  if (value === false || normalizeToken(value) === "false") return "Disabled";
  return "Not returned";
}

function uidValues(value) {
  if (value === undefined || value === null || value === "") return [];
  if (Array.isArray(value)) return value.flatMap(uidValues);
  if (typeof value === "object") return [value.uid, value.value, value.name].filter(Boolean).map(String);
  return [String(value)];
}

function genericObjectPayload(data) {
  if (!data || typeof data !== "object") return {};
  return data.object && typeof data.object === "object" ? data.object : data;
}

function valuesForNormalizedKey(source, ...keys) {
  const targets = new Set(keys.map(normalizeToken));
  const values = [];
  function walk(value) {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) {
      value.forEach(walk);
      return;
    }
    for (const [key, child] of Object.entries(value)) {
      if (targets.has(normalizeToken(key))) {
        values.push(child);
      }
      walk(child);
    }
  }
  walk(source);
  return values;
}

function activeDirectoryUidsFromGatewayObject(data) {
  const payload = genericObjectPayload(data);
  return uniqueStrings(valuesForNormalizedKey(payload, "activeDirectories", "active-directories")
    .flatMap(uidValues));
}

function authorizedClientUidsFromGateway(data) {
  const settings = data?.["identity-awareness-settings"] || {};
  const explicitAuthorizedClients = settings["authorized-clients"] ?? settings.authorizedClients ?? data?.["authorized-clients"] ?? data?.authorizedClients;
  const values = explicitAuthorizedClients !== undefined
    ? [explicitAuthorizedClients]
    : valuesForNormalizedKey(data, "authorizedClients", "authorized-clients");
  return uniqueStrings(values
    .flatMap((value) => {
      if (Array.isArray(value)) {
        return value.flatMap((item) => uidValues(item?.client ?? item));
      }
      if (value && typeof value === "object") {
        return uidValues(value.client ?? value);
      }
      return uidValues(value);
    }));
}

function ldapUsernamesFromActiveDirectoryObject(data) {
  const payload = genericObjectPayload(data);
  const ldapServerUsernames = Array.isArray(payload.ldapServers)
    ? payload.ldapServers.map((server) => server?.username).filter(Boolean)
    : [];
  if (ldapServerUsernames.length) {
    return uniqueStrings(ldapServerUsernames);
  }
  return uniqueStrings(valuesForNormalizedKey(payload, "username").flatMap(uidValues));
}

async function collectActiveDirectoryIntegrationEvidence(session, gatewaysResult) {
  if (!gatewaysResult.ok) {
    return {
      ok: false,
      command: "show-generic-object",
      error: gatewaysResult.error,
      rows: []
    };
  }

  const gateways = gatewaysResult.objects || [];
  const rows = [];
  const errors = [];
  await Promise.all(gateways.map(async (gateway) => {
    const identityAwarenessEnabled = gateway["identity-awareness"] === true || normalizeToken(gateway["identity-awareness"]) === "true";
    const adQueryValue = gateway["identity-awareness-settings"]?.["ad-query"] ?? gateway["ad-query"];
    const adQueryEnabled = identityAwarenessEnabled && (adQueryValue === true || normalizeToken(adQueryValue) === "true");
    const identityCollectorValue = gateway["identity-awareness-settings"]?.["identity-collector"] ?? gateway["identity-collector"];
    const identityCollectorEnabled = identityAwarenessEnabled && (identityCollectorValue === true || normalizeToken(identityCollectorValue) === "true");
    let ldapServerObject = "N/A";
    let ldapDomain = "N/A";
    let ldapUsername = "N/A";
    let identityCollectorHostObject = "N/A";
    let gatewayObject = null;

    if (adQueryEnabled && gateway.uid) {
      gatewayObject = await tryCommand(session, "show-generic-object", {
        uid: gateway.uid,
        "details-level": "full"
      });
      if (!gatewayObject.ok) {
        errors.push({ gateway: gateway.name || gateway.uid, error: gatewayObject.error });
      }
    }

    if (adQueryEnabled) {
      if (!gatewayObject?.ok) {
        ldapServerObject = "Lookup failed";
        ldapDomain = "Lookup failed";
        ldapUsername = "Lookup failed";
      } else {
        const activeDirectoryUids = activeDirectoryUidsFromGatewayObject(gatewayObject.data);
        if (!activeDirectoryUids.length) {
          ldapServerObject = "Not returned";
          ldapDomain = "Not returned";
          ldapUsername = "Not returned";
        } else {
          const activeDirectoryEvidence = await Promise.all(activeDirectoryUids.map(async (uid) => {
            const activeDirectoryObject = await tryCommand(session, "show-generic-object", {
              uid,
              "details-level": "full"
            });
            if (!activeDirectoryObject.ok) {
              errors.push({ gateway: gateway.name || gateway.uid, activeDirectoryUid: uid, error: activeDirectoryObject.error });
              return {
                name: `Lookup failed (${uid})`,
                domain: "Lookup failed",
                username: "Lookup failed"
              };
            }
            const activeDirectoryPayload = genericObjectPayload(activeDirectoryObject.data);
            const usernames = ldapUsernamesFromActiveDirectoryObject(activeDirectoryObject.data);
            return {
              name: activeDirectoryPayload.name || activeDirectoryPayload.NAME || uid,
              domain: activeDirectoryPayload.domainName || activeDirectoryPayload["domain-name"] || "Not returned",
              username: usernames.join(", ") || "Not returned"
            };
          }));
          ldapServerObject = activeDirectoryEvidence.map((item) => item.name).filter(Boolean).join(", ") || "Not returned";
          ldapDomain = activeDirectoryEvidence.map((item) => item.domain).filter(Boolean).join(", ") || "Not returned";
          ldapUsername = activeDirectoryEvidence.map((item) => item.username).filter(Boolean).join(", ") || "Not returned";
        }
      }
    }

    if (identityCollectorEnabled) {
      const authorizedClientUids = authorizedClientUidsFromGateway(gateway);
      if (!authorizedClientUids.length) {
        identityCollectorHostObject = "Not returned";
      } else {
        const authorizedClientNames = await Promise.all(authorizedClientUids.map(async (uid) => {
          const authorizedClientObject = await tryCommand(session, "show-generic-object", {
            uid,
            "details-level": "full"
          });
          if (!authorizedClientObject.ok) {
            errors.push({ gateway: gateway.name || gateway.uid, authorizedClientUid: uid, error: authorizedClientObject.error });
            return `Lookup failed (${uid})`;
          }
          const authorizedClientPayload = genericObjectPayload(authorizedClientObject.data);
          return authorizedClientPayload.name || authorizedClientPayload.NAME || uid;
        }));
        identityCollectorHostObject = authorizedClientNames.filter(Boolean).join(", ") || "Not returned";
      }
    }

    rows.push({
      "Firewall Name": gateway.name || gateway.uid || "",
      "AD-Query Enabled/Disabled": adQueryEnabled ? "Enabled" : "Disabled",
      "AD-Query LDAP Server Object": ldapServerObject,
      "AD-Query Domain": ldapDomain,
      "AD-Query LDAP Username": ldapUsername,
      "Identity Collector Enabled/Disabled": identityCollectorEnabled ? "Enabled" : "Disabled",
      "Identity Collector Host Object": identityCollectorHostObject
    });
  }));

  rows.sort((a, b) => a["Firewall Name"].localeCompare(b["Firewall Name"]));
  return {
    ok: errors.length === 0,
    command: "show-generic-object",
    rows,
    errors
  };
}

function evaluateActiveDirectoryIntegrationAccounts(result, session) {
  const source = "Hardening guide: Limiting Third-Party Integration Credentials";
  const recommendation = "Use a dedicated directory service account for AD / LDAP integrations with read-only permissions for user / group lookup and authentication. Do not use Domain Admin or highly privileged accounts. Directory integrations typically do not require write permissions. Read only accounts reduce lateral movement risk.";
  const detailRows = [
    {
      label: "AD-Query Setup Details",
      text: "Verify with your AD admin Identity Awareness AD Query is setup without Active Directory Administrator privileges follow the instructions in SK93938.",
      links: [{ label: "SK93938", url: "https://support.checkpoint.com/results/sk/sk93938" }]
    },
    {
      label: "Identity Collector Setup Details",
      text: "If using Identity Collector please verify the user configuration on the collector host listed below. Work with your AD administrator to confirm you are following best practices by only needing access to the Event Log Readers group as outlined in the Identity Awareness Setup Guide.",
      bold: ["Event Log Readers"],
      links: [{ label: "Identity Awareness Setup Guide", url: "https://sc1.checkpoint.com/documents/Identity_Awareness_Clients_Admin_Guide/Content/Topics-IA-Clients-AG/Identity-Collector-with-Active-Directory.htm" }]
    }
  ];
  const reviewHistory = appHistory.reviews.get("integrations.active-directory") || null;
  const reviewedThisLogin = reviewHistory?.sessionId === session.id;
  if (!result.ok && !result.rows.length) {
    return makeCheck({
      id: "integrations.active-directory",
      category: "Limiting Third-Party Integration Credentials",
      title: "Active Directory (AD) Integration Accounts",
      recommendation,
      status: "unknown",
      evidence: "Active Directory integration evidence could not be collected.",
      details: result.error?.error || "Gateway inventory could not be retrieved.",
      source,
      commands: ["show-gateways-and-servers", result.command]
    });
  }

  const enabledCount = result.rows.filter((row) => row["AD-Query Enabled/Disabled"] === "Enabled").length;
  const collectorEnabledCount = result.rows.filter((row) => row["Identity Collector Enabled/Disabled"] === "Enabled").length;
  const failedLookups = result.errors?.length || 0;
  return makeCheck({
    id: "integrations.active-directory",
    category: "Limiting Third-Party Integration Credentials",
    title: "Active Directory (AD) Integration Accounts",
    recommendation,
    status: failedLookups ? "unknown" : (reviewedThisLogin ? "reviewed" : (result.rows.length ? "needs-review" : "manual")),
    evidence: result.rows.length
      ? `${result.rows.length} gateway${result.rows.length === 1 ? "" : "s"} checked for AD Query and Identity Collector configuration. ${enabledCount} gateway${enabledCount === 1 ? "" : "s"} have AD Query enabled. ${collectorEnabledCount} gateway${collectorEnabledCount === 1 ? "" : "s"} have Identity Collector enabled.`
      : "No gateway or cluster objects were returned.",
    evidenceTable: result.rows.length ? {
      columns: ["Firewall Name", "AD-Query Enabled/Disabled", "AD-Query LDAP Server Object", "AD-Query Domain", "AD-Query LDAP Username", "Identity Collector Enabled/Disabled", "Identity Collector Host Object"],
      rows: result.rows
    } : null,
    details: failedLookups
      ? `${failedLookups} related object lookup${failedLookups === 1 ? "" : "s"} failed.`
      : "",
    detailRows: failedLookups ? null : detailRows,
    source,
    commands: ["show-simple-gateways/show-simple-clusters: identity-awareness,ad-query,identity-collector", "show-generic-object: activeDirectories,authorized-clients"],
    review: result.rows.length ? {
      action: "mark-reviewed",
      label: "Mark as Reviewed",
      reviewedAt: reviewHistory?.reviewedAt || "",
      reviewedBy: reviewHistory?.reviewedBy || "",
      reviewedThisLogin
    } : null
  });
}

function cveIkeReview(checkId, session, warning = "") {
  const reviewHistory = appHistory.reviews.get(checkId) || null;
  return {
    action: "mark-reviewed",
    label: "Mark as Reviewed",
    reviewedAt: reviewHistory?.reviewedAt || "",
    reviewedBy: reviewHistory?.reviewedBy || "",
    reviewedThisLogin: reviewHistory?.sessionId === session.id,
    warning
  };
}

function evaluateCveGlobalIkeProperty(result, session) {
  const checkId = "cve.ike-global-property";
  const review = cveIkeReview(checkId, session, "You are accepting Remote Access VPN settings that may still allow deprecated IKEv1 key exchange. Confirm this is understood and approved.");
  const reviewedThisLogin = review.reviewedThisLogin;
  const row = {
    "Setting": result.global.path,
    "Current Value": result.global.currentMethod || "Not returned",
    "Recommended Value": CVE_IKE_DESIRED_METHOD,
    "State": result.global.needsChange ? "IKEv1 allowed" : result.global.status
  };
  if (result.global.needsChange) {
    row._remediation = {
      action: "cve-set-global-ikev2-only",
      label: "Set Global IKE To IKEv2 Only"
    };
    row._remediationColumn = "State";
  }
  return makeCheck({
    id: checkId,
    category: "IKE Hardening",
    title: "IKE Version Global Property",
    recommendation: "Set the Remote Access VPN authentication and encryption global property to IKEv2 only. IKEv1 is deprecated and no longer industry best practice.",
    status: result.global.currentMethod
      ? (reviewedThisLogin ? "reviewed" : (result.global.needsChange ? "remediation-recommended" : "needs-review"))
      : "unknown",
    severity: result.global.needsChange ? "high" : "medium",
    evidence: result.global.currentMethod
      ? `Remote Access VPN encryption-method is ${result.global.currentMethod}.`
      : "Remote Access VPN encryption-method was not returned.",
    evidenceTable: {
      columns: ["Setting", "Current Value", "Recommended Value", "State"],
      rows: [row]
    },
    details: "This check was ported from the CVE-Web-Check tool. Review SK166415 and validate older VPN client impact before forcing IKEv2 only.",
    detailsLink: {
      label: "SK166415",
      url: "https://support.checkpoint.com/results/sk/sk166415"
    },
    source: "CVE-Web-Check: CVE-2026-50751 IKE Version Global Property",
    commands: ["show-global-properties: remote-access.vpn-authentication-and-encryption.encryption-method", "set-global-properties: remote-access.vpn-authentication-and-encryption.encryption-method"],
    review
  });
}

function evaluateCveLegacyClients(result, session) {
  const checkId = "cve.legacy-clients";
  const review = cveIkeReview(checkId, session, "You are accepting VPN legacy client support. Confirm legacy client requirements and compensating controls are approved.");
  const reviewedThisLogin = review.reviewedThisLogin;
  const rows = result.legacyRows.map((gateway) => {
    const row = {
      "_select": gateway.needsChange && gateway.vpnRealmUid ? {
        value: gateway.uid,
        label: gateway.name
      } : null,
      "Gateway": gateway.name,
      "IP Address": gateway.ipAddress,
      "VPN Realm UID": gateway.vpnRealmUid || "N/A",
      "Legacy Clients": gateway.status,
      "Current Disabled Value": displaySettingValue(gateway.currentDisabled)
    };
    if (gateway.needsChange) {
      row["Legacy Clients"] = { value: gateway.status, tone: "critical" };
    }
    return row;
  });
  const needsChangeCount = result.legacyRows.filter((gateway) => gateway.needsChange).length;
  return makeCheck({
    id: checkId,
    category: "IKE Hardening",
    title: "Legacy VPN Client Check",
    recommendation: "Disable legacy VPN clients unless there is a documented business requirement. Allowing legacy clients can preserve support for IKEv1, which is no longer an industry best practice.",
    status: reviewedThisLogin ? "reviewed" : (needsChangeCount ? "remediation-recommended" : (rows.length ? "needs-review" : "unknown")),
    severity: needsChangeCount ? "high" : "medium",
    evidence: rows.length
      ? `${rows.length} gateway${rows.length === 1 ? "" : "s"} checked for VPN legacy client support. ${needsChangeCount} gateway${needsChangeCount === 1 ? "" : "s"} need remediation.`
      : "No gateway VPN realm evidence was returned.",
    evidenceTable: rows.length ? {
      selectable: needsChangeCount > 0,
      selectionName: "gateway",
      columns: ["Gateway", "IP Address", "VPN Realm UID", "Legacy Clients", "Current Disabled Value"],
      rows
    } : null,
    details: "The remediation sets the VPN realm owned-object disabled value to true for the selected gateways.",
    source: "CVE-Web-Check: CVE-2026-50751 Legacy Client's Allowed Check",
    commands: ["show-simple-gateways: gateway inventory", "show-generic-object: realmsForBlades ownedName=vpn disabled", "set-generic-object: realmsForBlades.set owned-object.disabled=true"],
    remediation: needsChangeCount ? {
      action: "cve-disable-legacy-clients",
      label: "Disable Legacy Clients For Checked Gateways",
      command: "set-generic-object"
    } : null,
    review
  });
}

function evaluateCveSiteToSiteCommunities(result, session) {
  const checkId = "cve.site-to-site-communities";
  const review = cveIkeReview(checkId, session, "You are accepting site-to-site VPN communities that may use IKEv1 with certificate authentication. Confirm the risk and migration plan are approved.");
  const reviewedThisLogin = review.reviewedThisLogin;
  const rows = result.communities.map((community) => {
    const row = {
      "_select": community.matchesCriteria && community.uid ? {
        value: community.uid,
        label: community.name
      } : null,
      "Community": community.name,
      "Type": community.type === "star" ? "Star" : "Mesh",
      "Participants": community.summary.participants,
      "IKEv1": community.usesIkeV1 ? "Yes" : "No",
      "Certificate Auth": community.usesCertificateAuth ? "Yes" : "No",
      "External Gateways": community.summary.externalGateways,
      "State": community.matchesCriteria ? "Exposure found" : "No combined exposure"
    };
    if (community.matchesCriteria) {
      row.State = { value: "Exposure found", tone: "critical" };
    }
    return row;
  });
  const matches = result.communityMatches.length;
  return makeCheck({
    id: checkId,
    category: "IKE Hardening",
    title: "Site-To-Site VPN Communities IKE Version",
    recommendation: "Review site-to-site VPN communities that use deprecated IKEv1 with certificate-based authentication and migrate them to IKEv2 only.",
    status: reviewedThisLogin ? "reviewed" : (matches ? "remediation-recommended" : (rows.length ? "needs-review" : "unknown")),
    severity: matches ? "high" : "medium",
    evidence: rows.length
      ? `${rows.length} site-to-site VPN communit${rows.length === 1 ? "y" : "ies"} checked. ${matches} matched the IKEv1 certificate-based exposure criteria.`
      : "No site-to-site VPN communities were returned.",
    evidenceTable: rows.length ? {
      selectable: matches > 0,
      selectionName: "community",
      columns: ["Community", "Type", "Participants", "IKEv1", "Certificate Auth", "External Gateways", "State"],
      rows
    } : null,
    details: "If a selected Star community includes externally managed gateways, make the matching IKEv2-only change on the externally managed gateway side before installing policy.",
    source: "CVE-Web-Check: CVE-2026-50752 Site-to-Site VPN Communities",
    commands: ["show-vpn-communities-star: details-level full", "show-vpn-communities-meshed: details-level full", "set-vpn-community-star/set-vpn-community-meshed: encryption-method"],
    remediation: matches ? {
      action: "cve-set-site-to-site-ikev2-only",
      label: "Set Checked Communities To IKEv2 Only",
      command: "set-vpn-community-star/set-vpn-community-meshed"
    } : null,
    review
  });
}

function evaluateCveIkeChecks(result, session) {
  return [
    evaluateCveGlobalIkeProperty(result, session),
    evaluateCveLegacyClients(result, session),
    evaluateCveSiteToSiteCommunities(result, session)
  ];
}

function manualHardeningChecks() {
  return [
    makeCheck({
      id: "integrations.identity-provider-api",
      category: "Limiting Third-Party Integration Credentials",
      title: "Identity Provider And API Integrations",
      recommendation: "Use dedicated least-privilege credentials for IdP, automation, orchestration, and API integrations.",
      status: "manual",
      evidence: "External IdP and API token permissions usually require review in the external platform and credential vault.",
      details: "Maintain an inventory of API tokens, SAML/OIDC application credentials, automation accounts, and integration owners. Remove unused credentials and rotate active secrets.",
      source: "Hardening guide: Limiting Third-Party Integration Credentials"
    }),
    makeCheck({
      id: "gaia.lom",
      category: "Gaia OS Hardening",
      title: "Restrict LOM / Out-Of-Band Management",
      recommendation: "Ensure that the LOM interface is not directly exposed to the Internet, connected only to a dedicated secured management network, and accessible only from explicitly authorized source IP addresses.",
      status: "informational",
      severity: "high",
      evidence: "",
      details: "Many Check Point Appliances include a Lights Out Management (LOM) or out of band management interface that provides direct, low level access to the system, including remote console, power control, and hardware monitoring capabilities. This interface operates independently of the Gaia OS and security policy, and therefore must be treated as highly privileged infrastructure access.",
      detailRows: [
        {
          label: "Recommendation",
          text: "Access to the LOM interface must be tightly restricted and monitored.",
          bullets: [
            "Not directly exposed to the Internet.",
            "Connected only to a dedicated, secured management network.",
            "Accessible only from explicitly authorized source IP addresses."
          ]
        },
        {
          label: "Why",
          text: "LOM provides direct hardware level control, bypassing operating system and security policy enforcement.",
          bullets: [
            "Unauthorized access to LOM can allow full system control, including reboot and console access.",
            "Unauthorized access to LOM can allow modification of boot behavior.",
            "Unauthorized access to LOM can allow access to sensitive system information.",
            "As attackers increasingly target management and control planes, out of band interfaces represent a high impact entry point if not properly isolated.",
            "Improper exposure, for example direct Internet connectivity, significantly increases the risk of unauthorized access."
          ]
        }
      ],
      source: "Hardening guide: Restrict Access to Lights Out Management"
    }),
    makeCheck({
      id: "advanced.explicit-rules",
      category: "Advanced Hardening",
      title: "Use Explicit Rules Instead Of Implied Rules (Only In High-Security Environments)",
      recommendation: "Replace implied rules with explicit Access Control rules only in high security environments, following the Check Point guidance exactly. Explicit rules increase visibility and auditability, but incorrect rules can break policy installation and management/log connectivity.",
      status: "informational",
      evidence: "",
      details: "Follow SK179346 to implement.",
      detailsLink: {
        label: "SK179346",
        url: "https://support.checkpoint.com/results/sk/sk179346"
      },
      source: "Hardening guide: Explicit Rules Instead of Implied Rules",
      hideBadges: true
    })
  ];
}

function summarizeChecks(checks) {
  return checks.reduce((summary, check) => {
    summary[check.status] = (summary[check.status] || 0) + 1;
    return summary;
  }, {});
}

function moveCategoryBefore(checks, category, beforeCategory) {
  const moved = checks.filter((check) => check.category === category);
  if (!moved.length) return checks;
  const remaining = checks.filter((check) => check.category !== category);
  const beforeIndex = remaining.findIndex((check) => check.category === beforeCategory);
  if (beforeIndex === -1) {
    return [...remaining, ...moved];
  }
  return [
    ...remaining.slice(0, beforeIndex),
    ...moved,
    ...remaining.slice(beforeIndex)
  ];
}

async function scanHardening(session) {
  const scannedAt = new Date().toISOString();
  session.adminLastLoginCache = new Map();
  session.scanCommandCache = new Map();
  session.scanCommandLog = [];
  session.scanApiQueue = createLimiter(session.largeEnvironmentMode ? LARGE_ENV_API_CONCURRENCY : STANDARD_API_CONCURRENCY);
  session.scanProgress = {
    active: true,
    failed: false,
    complete: false,
    percent: 3,
    completedSteps: 0,
    currentStep: "Starting hardening scan",
    startedAt: scannedAt,
    completedAt: "",
    steps: []
  };
  const currentScan = {
    scannedAt,
    user: session.user || "Unknown",
    baseUrl: session.baseUrl,
    customerName: session.customerName || "",
    reportDomainName: session.mdsMode && session.domain ? session.domain : ""
  };
  const skipManagementPlaneProtection = Boolean(session.smart1Cloud);
  const skipSmart1OnlyChecks = Boolean(session.smart1Cloud);
  const [
    trustedClients,
    apiSettings,
    administrators,
    defaultAdministratorSettings,
    smartConsoleIdleTimeout,
    loginRestrictions,
    cpPasswordRequirements,
    globalProperties,
    packages,
    dataCenterServers,
    gatewaysAndServers,
    networks,
    addressRanges
  ] = await Promise.all([
    skipSmart1OnlyChecks
      ? Promise.resolve({ ok: true, objects: [], skipped: true })
      : tryListSystemDataObjects(session, "show-trusted-clients", { "details-level": "full" }),
    skipSmart1OnlyChecks
      ? Promise.resolve({ ok: true, data: {}, skipped: true })
      : trySystemDataCommand(session, "show-api-settings"),
    tryListSystemDataObjects(session, "show-administrators", { "details-level": "full" }),
    trySystemDataCommand(session, "show-default-administrator-settings"),
    trySystemDataCommand(session, "show-smart-console-idle-timeout"),
    trySystemDataCommand(session, "show-login-restrictions"),
    trySystemDataCommand(session, "show-cp-password-requirements"),
    tryCommand(session, "show-global-properties", { "details-level": "full" }),
    tryListObjects(session, "show-packages", { "details-level": "full" }),
    tryListObjects(session, "show-data-center-servers", { "details-level": "full" }),
    tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" }),
    tryListObjects(session, "show-networks", { "details-level": "full" }),
    tryListObjects(session, "show-address-ranges", { "details-level": "full" })
  ]);
  let gateways = { ok: true, objects: [], skipped: true };
  let clusters = { ok: true, objects: [], skipped: true };
  if (!gatewaysAndServers.ok) {
    [gateways, clusters] = await Promise.all([
      tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
      tryListObjects(session, "show-simple-clusters", { "details-level": "full" })
    ]);
  }
  const fallbackGatewayInventory = gatewaysAndServers.ok ? null : {
    ok: gateways.ok || clusters.ok,
    command: "show-simple-gateways/show-simple-clusters",
    objects: [...(gateways.objects || []), ...(clusters.objects || [])],
    error: gateways.error || clusters.error
  };
  const discoveredGatewayInventory = gatewayServerInventory(gatewaysAndServers, fallbackGatewayInventory);
  session.scanProgress.currentStep = "Testing active gateway SIC communication";
  const gatewaySicStatus = await collectGatewaySicStatusEvidence(session, discoveredGatewayInventory);
  const gatewayInventory = filterGatewayInventoryBySic(discoveredGatewayInventory, gatewaySicStatus);
  const adGatewayObjects = {
    ok: gatewayInventory.ok,
    objects: [
      ...gatewayInventory.simpleGateways,
      ...gatewayInventory.clusters
    ],
    error: gatewayInventory.error
  };
  const jumboHotfixTargets = {
    ok: gatewayInventory.ok,
    // Software packages are installed on physical gateways. A logical cluster
    // object does not have its own package inventory, so expand clusters to
    // their members and keep standalone gateways as direct targets.
    objects: gatewayInventory.runScriptTargets,
    error: gatewayInventory.error
  };
  const eligibleSimpleGateways = { ok: gatewayInventory.ok, objects: gatewayInventory.simpleGateways, error: gatewayInventory.error };
  const gaiaTargets = { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error };
  const policyTargets = { ok: gatewayInventory.ok, objects: gatewayInventory.policyTargets, error: gatewayInventory.error };
  const topologyTargets = { ok: gatewayInventory.ok, objects: gatewayInventory.topologyObjects, error: gatewayInventory.error };
  const [
    gatewayStealthRules,
    managementFirewallProtection,
    administrativeSourceIpAddresses,
    activeDirectoryIntegrations,
    jumboHotfixEvidence,
    cveIkeEvidence,
    gaiaFullScanEvidence,
    administratorApiKeyAuthentication,
    administratorAccountChecks
  ] = await Promise.all([
    collectGatewayStealthRuleEvidence(session, policyTargets, packages),
    skipManagementPlaneProtection ? Promise.resolve(null) : collectManagementFirewallEvidence(session, gatewaysAndServers, topologyTargets),
    skipManagementPlaneProtection ? Promise.resolve(null) : collectAdministrativeSourceIpEvidence(session, gatewaysAndServers, packages, networks, addressRanges),
    collectActiveDirectoryIntegrationEvidence(session, adGatewayObjects),
    collectJumboHotfixEvidence(session, jumboHotfixTargets),
    collectCveIkeEvidence(session, globalProperties, eligibleSimpleGateways),
    collectGaiaFullScanEvidence(session, gaiaTargets, gatewaysAndServers),
    skipSmart1OnlyChecks ? Promise.resolve(null) : evaluateAdministratorApiKeyAuthentication(administrators, session),
    evaluateAdministrators(administrators, session)
  ]);
  const gaiaAllowedHostAccess = gaiaFullScanEvidence.allowedHostAccess;
  const gaiaAdministratorSettings = gaiaFullScanEvidence.administratorSettings;
  const gaiaPasswordPolicy = gaiaFullScanEvidence.passwordPolicy;
  const gaiaSnmpMonitoring = gaiaFullScanEvidence.snmpMonitoring;
  const gaiaSystemLogging = gaiaFullScanEvidence.systemLogging;
  const gaiaManagementExternalSyslog = session.smart1Cloud
    ? await collectGaiaManagementExternalSyslogEvidence(session, gatewaysAndServers)
    : gaiaFullScanEvidence.managementExternalSyslog;
  const securityFeatureUsage = gaiaFullScanEvidence.securityFeatureUsage;
  const sizingStatistics = gaiaFullScanEvidence.sizingStatistics;

  let checks = [
    ...(skipManagementPlaneProtection ? [] : [
      evaluateManagementFirewallProtection(managementFirewallProtection, session),
      evaluateAdministrativeSourceIpAddresses(administrativeSourceIpAddresses, session)
    ]),
    ...(skipSmart1OnlyChecks ? [] : [
      evaluateTrustedClients(trustedClients, session),
      evaluateManagementApiAccess(apiSettings, trustedClients, session),
      administratorApiKeyAuthentication
    ]),
    ...administratorAccountChecks,
    evaluateAdminPolicySettings(defaultAdministratorSettings, smartConsoleIdleTimeout, loginRestrictions, cpPasswordRequirements, session),
    evaluateMfaIdentityProvider(defaultAdministratorSettings, administrators, session),
    ...evaluateGlobalProperties(globalProperties, session),
    evaluateJumboHotfixAccumulator(jumboHotfixEvidence, session),
    evaluateGatewayStealthRules(gatewayStealthRules, session),
    ...(gatewaySicStatus ? [evaluateGatewayObjectStatus(gatewaySicStatus)] : []),
    evaluateActiveDirectoryIntegrationAccounts(activeDirectoryIntegrations, session),
    evaluateCloudControllerIntegrations(dataCenterServers, session),
    evaluateGaiaAllowedHostAccess(gaiaAllowedHostAccess, session),
    evaluateGaiaAdministratorSettings(gaiaAdministratorSettings, session),
    evaluateGaiaExpertModeAccess(gaiaAdministratorSettings, session),
    evaluateGaiaPasswordPolicyHardening(gaiaPasswordPolicy, session),
    evaluateGaiaSnmpMonitoringHardening(gaiaSnmpMonitoring, session),
    evaluateGaiaSystemLoggingToManagement(gaiaSystemLogging, session),
    evaluateGaiaManagementExternalSyslog(gaiaManagementExternalSyslog, session),
    evaluateSecurityFeatureUsage(securityFeatureUsage, session),
    evaluateSizingStatistics(sizingStatistics),
    ...evaluateCveIkeChecks(cveIkeEvidence, session),
    ...manualHardeningChecks()
  ];
  checks = moveCategoryBefore(checks, "Limiting Third-Party Integration Credentials", "Updates, Health, and Ongoing Protection");

  const adminPolicyResults = [defaultAdministratorSettings, smartConsoleIdleTimeout, loginRestrictions, cpPasswordRequirements];
  const adminPolicyCollection = { ok: adminPolicyResults.every(result => result.ok),
    errors: adminPolicyResults.filter(result => !result.ok).map(result => result.error),
    rows: adminPolicyResults.filter(result => result.ok).map(result => result.data) };
  const collected = {
    "admin.accounts": administrators,
    "admin.api-key-authentication": administrators,
    "admin.password-idle-lockout": adminPolicyCollection,
    "admin.mfa-idp": defaultAdministratorSettings,
    "mgmt.protected-segment": managementFirewallProtection,
    "mgmt.admin-source-ip": administrativeSourceIpAddresses,
    "mgmt.trusted-clients": trustedClients,
    "mgmt.api-access": apiSettings,
    "policy.implied-rules": globalProperties,
    "updates.dynamic-updates": globalProperties,
    "updates.cpdiag": globalProperties,
    "updates.jumbo-hotfix": jumboHotfixEvidence,
    "policy.stealth-rule": gatewayStealthRules,
    "integrations.active-directory": activeDirectoryIntegrations,
    "integrations.cloud-controllers": dataCenterServers,
    "gaia.allowed-host-access": gaiaAllowedHostAccess,
    "gaia.admin-settings": gaiaAdministratorSettings,
    "gaia.expert-mode-access": gaiaAdministratorSettings,
    "gaia.password-policy-hardening": gaiaPasswordPolicy,
    "gaia.snmp-monitoring-hardening": gaiaSnmpMonitoring,
    "gaia.system-logging-management": gaiaSystemLogging,
    "gaia.management-external-syslog": gaiaManagementExternalSyslog,
    "security-feature-usage.licensed-blades": securityFeatureUsage,
    "security-feature-usage.sizing-statistics": sizingStatistics
  };
  const findingContext = { domain: session.domain || "", inventory: gatewaysAndServers.objects || [] };
  checks = checks.map(check => {
    const collector = collected[check.id] || (check.id.startsWith("cve.") ? cveIkeEvidence : null);
    return withFindingIdentity({ ...check, collection: collector ? collectionOutcome(collector)
      : { status: check.status === "manual" ? "not-assessed" : "not-reported", errors: [] } }, findingContext);
  });

  const result = {
    scannedAt,
    user: currentScan.user,
    baseUrl: currentScan.baseUrl,
    customerName: currentScan.customerName,
    reportDomainName: currentScan.reportDomainName,
    managementObjectName: session.managementObjectName || "",
    gatewayTargets: gatewayInventory.runScriptTargets.map((gateway) => gateway.name || gateway.uid).filter(Boolean),
    clusterTargets: gatewayInventory.clusters.map((cluster) => cluster.name || cluster.uid).filter(Boolean),
    targetInventory: findingContext.inventory.map(object => ({ uid: object.uid, name: object.name, type: object.type })),
    clusterMemberships: gatewayInventory.clusters.flatMap((cluster) => {
      const clusterName = cluster.name || cluster.NAME || cluster.uid || "";
      const members = [
        ...(cluster["cluster-member-names"] || cluster.clusterMemberNames || []),
        ...(cluster["cluster-members"] || cluster.clusterMembers || []).map((member) => member?.name || member?.NAME || member)
      ].filter(Boolean);
      return members.map((memberName) => ({ memberName, clusterName }));
    }),
    guide: {
      title: "Check Point Gateway and Management Hardening Administration Guide",
      date: "01 June 2026",
      url: HARDENING_GUIDE_URL
    },
    scanMode: session.largeEnvironmentMode ? "large-environment" : "standard",
    summary: summarizeChecks(checks),
    checks,
    commandLog: session.scanCommandLog || [],
    commandResults: {
      ...(skipSmart1OnlyChecks ? {
        "show-trusted-clients": "skipped for Smart-1 Cloud",
        "show-api-settings": "skipped for Smart-1 Cloud",
        "admin.api-key-authentication": "skipped for Smart-1 Cloud"
      } : {
        "show-trusted-clients": trustedClients.ok ? "ok" : trustedClients.error,
        "show-api-settings": apiSettings.ok ? "ok" : apiSettings.error
      }),
      "show-administrators": administrators.ok ? "ok" : administrators.error,
      "show-default-administrator-settings": defaultAdministratorSettings.ok ? "ok" : defaultAdministratorSettings.error,
      "show-smart-console-idle-timeout": smartConsoleIdleTimeout.ok ? "ok" : smartConsoleIdleTimeout.error,
      "show-login-restrictions": loginRestrictions.ok ? "ok" : loginRestrictions.error,
      "show-cp-password-requirements": cpPasswordRequirements.ok ? "ok" : cpPasswordRequirements.error,
      "show-global-properties": globalProperties.ok ? "ok" : globalProperties.error,
      ...(gateways.skipped ? {} : { "show-simple-gateways": gateways.ok ? "ok" : gateways.error }),
      ...(clusters.skipped ? {} : { "show-simple-clusters": clusters.ok ? "ok" : clusters.error }),
      "show-packages": packages.ok ? "ok" : packages.error,
      "show-data-center-servers": dataCenterServers.ok ? "ok" : dataCenterServers.error,
      "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
      "show-networks": networks.ok ? "ok" : networks.error,
      "show-address-ranges": addressRanges.ok ? "ok" : addressRanges.error,
      "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
      ...(gatewaySicStatus ? {
        "test-sic-status": gatewaySicStatus.ok ? "ok" : { error: `${gatewaySicStatus.rows?.length || 0} gateway object${(gatewaySicStatus.rows?.length || 0) === 1 ? " is" : "s are"} not communicating` }
      } : {}),
      ...(skipManagementPlaneProtection ? {} : {
        "run-script/management-firewall": managementFirewallProtection.ok ? "ok" : { error: `${managementFirewallProtection.errors?.length || 0} lookup error${(managementFirewallProtection.errors?.length || 0) === 1 ? "" : "s"}` }
      }),
      "run-script/gaia-allowed-host-access": gaiaAllowedHostAccess.ok ? "ok" : (gaiaAllowedHostAccess.error || { error: `${gaiaAllowedHostAccess.errors?.length || 0} lookup error${(gaiaAllowedHostAccess.errors?.length || 0) === 1 ? "" : "s"}` }),
      "run-script/gaia-admin-settings": gaiaAdministratorSettings.ok ? "ok" : (gaiaAdministratorSettings.error || { error: `${gaiaAdministratorSettings.errors?.length || 0} lookup error${(gaiaAdministratorSettings.errors?.length || 0) === 1 ? "" : "s"}` }),
      "run-script/gaia-password-policy": gaiaPasswordPolicy.ok ? "ok" : (gaiaPasswordPolicy.error || { error: `${gaiaPasswordPolicy.errors?.length || 0} lookup error${(gaiaPasswordPolicy.errors?.length || 0) === 1 ? "" : "s"}` }),
      "run-script/gaia-snmp-monitoring": gaiaSnmpMonitoring.ok ? "ok" : (gaiaSnmpMonitoring.error || { error: `${gaiaSnmpMonitoring.errors?.length || 0} lookup error${(gaiaSnmpMonitoring.errors?.length || 0) === 1 ? "" : "s"}` }),
      "run-script/gaia-system-logging": gaiaSystemLogging.ok ? "ok" : (gaiaSystemLogging.error || { error: `${gaiaSystemLogging.errors?.length || 0} lookup error${(gaiaSystemLogging.errors?.length || 0) === 1 ? "" : "s"}` }),
      "run-script/gaia-management-external-syslog": gaiaManagementExternalSyslog.ok ? "ok" : (gaiaManagementExternalSyslog.error || { error: `${gaiaManagementExternalSyslog.errors?.length || 0} lookup error${(gaiaManagementExternalSyslog.errors?.length || 0) === 1 ? "" : "s"}` }),
      "run-script/security-feature-usage": securityFeatureUsage.ok ? "ok" : (securityFeatureUsage.error || { error: `${securityFeatureUsage.errors?.length || 0} lookup error${(securityFeatureUsage.errors?.length || 0) === 1 ? "" : "s"}` }),
      "run-script/sizing-statistics": sizingStatistics.ok ? "ok" : (sizingStatistics.error || { error: `${sizingStatistics.errors?.length || 0} lookup error${(sizingStatistics.errors?.length || 0) === 1 ? "" : "s"}` }),
      ...(skipManagementPlaneProtection ? {} : {
        "where-used/show-access-rule/admin-source-ip": administrativeSourceIpAddresses.ok ? "ok" : (administrativeSourceIpAddresses.error || { error: `${administrativeSourceIpAddresses.errors?.length || 0} lookup error${(administrativeSourceIpAddresses.errors?.length || 0) === 1 ? "" : "s"}` }),
        "show-nat-rulebase/admin-source-ip": administrativeSourceIpAddresses.ok ? "ok" : (administrativeSourceIpAddresses.error || { error: `${administrativeSourceIpAddresses.errors?.length || 0} lookup error${(administrativeSourceIpAddresses.errors?.length || 0) === 1 ? "" : "s"}` })
      }),
      "show-software-packages-per-targets": jumboHotfixEvidence.ok ? "ok" : (jumboHotfixEvidence.error || { error: `${jumboHotfixEvidence.errors?.length || 0} lookup error${(jumboHotfixEvidence.errors?.length || 0) === 1 ? "" : "s"}` }),
      "show-generic-object/ad-query": activeDirectoryIntegrations.ok ? "ok" : (activeDirectoryIntegrations.error || { error: `${activeDirectoryIntegrations.errors?.length || 0} lookup error${(activeDirectoryIntegrations.errors?.length || 0) === 1 ? "" : "s"}` }),
      "cve-ike": cveIkeEvidence.ok ? "ok" : { error: `${cveIkeEvidence.errors?.length || 0} lookup error${(cveIkeEvidence.errors?.length || 0) === 1 ? "" : "s"}` },
      "where-used/show-access-rule": gatewayStealthRules.ok ? "ok" : (gatewayStealthRules.error || compactLookupErrors(gatewayStealthRules.errors))
    }
  };
  assertNotCancelled(operationContext.getStore()?.operation);
  session.lastHardeningScan = result;
  addAuditEntry({
    session,
    action: "Scan Hardening Posture",
    command: [
      ...(skipSmart1OnlyChecks ? [] : ["show-trusted-clients", "show-api-settings"]),
      "show-administrators",
      "show-default-administrator-settings",
      "show-smart-console-idle-timeout",
      "show-login-restrictions",
      "show-cp-password-requirements",
      "show-global-properties",
      "show-simple-gateways",
      "show-simple-clusters",
      "show-packages",
      "show-data-center-servers",
      "show-gateways-and-servers",
      "show-networks",
      "show-address-ranges",
      ...(skipManagementPlaneProtection ? [] : ["show-nat-rulebase"]),
      "run-script",
      "run-script: show password-controls all",
      "run-script: show syslog logs search Web UI connection by USERNAME",
      "run-script: show syslog logs search SSH connection by USERNAME",
      "run-script: show snmp agent",
      "run-script: show snmp agent-version",
      "run-script: show snmp interfaces",
      "run-script: show snmp usm users",
      "run-script: show snmp usm user",
      "run-script: show syslog cplogs",
      "run-script: show syslog log-remote-addresses",
      "run-script: show license status",
      "run-script: cpstat os -f memory",
      "run-script: cpstat os -f cpu",
      "show-software-packages-per-targets",
      "show-generic-object",
      "where-used",
      "show-access-rule",
      "show-vpn-communities-star",
      "show-vpn-communities-meshed"
    ].join(", "),
    details: `Scanned ${checks.length} checks.`
  });
  session.scanCommandCache = null;
  session.scanApiQueue = null;
  session.scanProgress = {
    ...(session.scanProgress || {}),
    active: false,
    complete: true,
    failed: false,
    percent: 100,
    currentStep: "Scan complete",
    completedAt: new Date().toISOString()
  };
  return result;
}

function mergeScanSummaries(domainResults = []) {
  return domainResults.reduce((summary, domain) => {
    for (const [status, count] of Object.entries(domain.scan?.summary || {})) {
      summary[status] = Number(summary[status] || 0) + Number(count || 0);
    }
    return summary;
  }, {});
}

async function scanMoraHardening(session) {
  const domains = Array.isArray(session.moraDomains) ? session.moraDomains : [];
  if (!domains.length) {
    throw new Error("The all-domain scan has no discovered domains. Log in again and retry.");
  }
  const startedAt = new Date().toISOString();
  session.moraGlobalCommandCache = new Map();
  session.moraAdminSourceGlobalInventory = null;
  session.scanProgress = {
    active: true,
    failed: false,
    complete: false,
    percent: 1,
    completedSteps: 0,
    currentStep: `Preparing sequential scan of ${domains.length} domains`,
    currentDomain: "",
    currentDomainIndex: 0,
    totalDomains: domains.length,
    startedAt,
    completedAt: "",
    steps: []
  };
  const domainResults = [];
  for (let index = 0; index < domains.length; index += 1) {
    assertNotCancelled(operationContext.getStore()?.operation);
    const domain = domains[index];
    session.scanProgress.currentDomain = domain.name;
    session.scanProgress.currentDomainIndex = index + 1;
    session.scanProgress.currentStep = `Domain ${index + 1} of ${domains.length}: ${domain.name}`;
    session.scanProgress.percent = Math.max(1, Math.round((index / domains.length) * 100));
    if (!domain.session || domain.loginError) {
      domainResults.push({
        name: domain.name,
        uid: domain.uid,
        error: domain.loginError?.error || "Domain login was unavailable.",
        scan: null
      });
      continue;
    }
    domain.session.moraProgress = {
      parent: session,
      index,
      total: domains.length,
      domainName: domain.name
    };
    try {
      const scan = await scanHardening(domain.session);
      domainResults.push({ name: domain.name, uid: domain.uid, error: "", scan });
    } catch (error) {
      if (error.code === "SCAN_CANCELLED") throw error;
      domainResults.push({ name: domain.name, uid: domain.uid, error: error.message || "Domain scan failed.", scan: null });
    } finally {
      domain.session.moraProgress = null;
      domain.session.scanCommandCache = null;
      domain.session.scanApiQueue = null;
    }
    session.scanProgress.percent = Math.round(((index + 1) / domains.length) * 100);
  }
  const successful = domainResults.filter((domain) => domain.scan);
  assertNotCancelled(operationContext.getStore()?.operation);
  const failed = domainResults.filter((domain) => !domain.scan);
  const result = {
    moraMode: true,
    scannedAt: new Date().toISOString(),
    user: session.user || "Unknown",
    baseUrl: session.baseUrl,
    customerName: session.customerName || "",
    guide: successful[0]?.scan?.guide || {
      title: "Check Point Gateway and Management Hardening Administration Guide",
      date: "01 June 2026",
      url: HARDENING_GUIDE_URL
    },
    scanMode: session.largeEnvironmentMode ? "mora-large-environment" : "mora-sequential",
    summary: mergeScanSummaries(domainResults),
    domains: domainResults,
    checks: [],
    commandLog: successful.flatMap((domain) => (domain.scan.commandLog || []).map((entry) => ({ ...entry, domain: domain.name }))),
    commandResults: Object.fromEntries(successful.flatMap((domain) => Object.entries(domain.scan.commandResults || {}).map(([command, value]) => [`${domain.name}: ${command}`, value])))
  };
  session.lastHardeningScan = result;
  session.scanProgress = {
    ...session.scanProgress,
    active: false,
    complete: true,
    failed: successful.length === 0,
    percent: 100,
    currentStep: failed.length
      ? `Completed ${successful.length} domain scan${successful.length === 1 ? "" : "s"}; ${failed.length} domain${failed.length === 1 ? "" : "s"} failed`
      : `Completed all ${successful.length} domain scans`,
    completedAt: new Date().toISOString()
  };
  session.moraGlobalCommandCache = null;
  session.moraAdminSourceGlobalInventory = null;
  return result;
}

async function evaluateSingleHardeningCheck(session, checkId) {
  switch (checkId) {
    case "mgmt.trusted-clients": {
      if (session.smart1Cloud) {
        return {
          check: null,
          commandResults: { "show-trusted-clients": "skipped for Smart-1 Cloud" }
        };
      }
      const trustedClients = await tryListSystemDataObjects(session, "show-trusted-clients", { "details-level": "full" });
      return {
        check: evaluateTrustedClients(trustedClients, session),
        commandResults: { "show-trusted-clients": trustedClients.ok ? "ok" : trustedClients.error }
      };
    }
    case "mgmt.api-access": {
      if (session.smart1Cloud) {
        return {
          check: null,
          commandResults: {
            "show-api-settings": "skipped for Smart-1 Cloud",
            "show-trusted-clients": "skipped for Smart-1 Cloud"
          }
        };
      }
      const [apiSettings, trustedClients] = await Promise.all([
        trySystemDataCommand(session, "show-api-settings"),
        tryListSystemDataObjects(session, "show-trusted-clients", { "details-level": "full" })
      ]);
      return {
        check: evaluateManagementApiAccess(apiSettings, trustedClients, session),
        commandResults: {
          "show-api-settings": apiSettings.ok ? "ok" : apiSettings.error,
          "show-trusted-clients": trustedClients.ok ? "ok" : trustedClients.error
        }
      };
    }
    case "admin.api-key-authentication": {
      if (session.smart1Cloud) {
        return {
          check: null,
          commandResults: { "admin.api-key-authentication": "skipped for Smart-1 Cloud" }
        };
      }
      const administrators = await tryListSystemDataObjects(session, "show-administrators", { "details-level": "full" });
      return {
        check: await evaluateAdministratorApiKeyAuthentication(administrators, session),
        commandResults: { "show-administrators": administrators.ok ? "ok" : administrators.error }
      };
    }
    case "admin.accounts": {
      const administrators = await tryListSystemDataObjects(session, "show-administrators", { "details-level": "full" });
      const checks = await evaluateAdministrators(administrators, session);
      return {
        check: checks.find((check) => check.id === checkId),
        commandResults: { "show-administrators": administrators.ok ? "ok" : administrators.error }
      };
    }
    case "admin.password-idle-lockout": {
      const [defaultAdministratorSettings, smartConsoleIdleTimeout, loginRestrictions, cpPasswordRequirements] = await Promise.all([
        trySystemDataCommand(session, "show-default-administrator-settings"),
        trySystemDataCommand(session, "show-smart-console-idle-timeout"),
        trySystemDataCommand(session, "show-login-restrictions"),
        trySystemDataCommand(session, "show-cp-password-requirements")
      ]);
      return {
        check: evaluateAdminPolicySettings(defaultAdministratorSettings, smartConsoleIdleTimeout, loginRestrictions, cpPasswordRequirements, session),
        commandResults: {
          "show-default-administrator-settings": defaultAdministratorSettings.ok ? "ok" : defaultAdministratorSettings.error,
          "show-smart-console-idle-timeout": smartConsoleIdleTimeout.ok ? "ok" : smartConsoleIdleTimeout.error,
          "show-login-restrictions": loginRestrictions.ok ? "ok" : loginRestrictions.error,
          "show-cp-password-requirements": cpPasswordRequirements.ok ? "ok" : cpPasswordRequirements.error
        }
      };
    }
    case "admin.mfa-idp": {
      const [defaultAdministratorSettings, administrators] = await Promise.all([
        trySystemDataCommand(session, "show-default-administrator-settings"),
        tryListSystemDataObjects(session, "show-administrators", { "details-level": "full" })
      ]);
      return {
        check: evaluateMfaIdentityProvider(defaultAdministratorSettings, administrators, session),
        commandResults: {
          "show-default-administrator-settings": defaultAdministratorSettings.ok ? "ok" : defaultAdministratorSettings.error,
          "show-administrators": administrators.ok ? "ok" : administrators.error
        }
      };
    }
    case "policy.implied-rules":
    case "updates.dynamic-updates":
    case "updates.cpdiag": {
      const globalProperties = await tryCommand(session, "show-global-properties", { "details-level": "full" });
      const checks = evaluateGlobalProperties(globalProperties, session);
      return {
        check: checks.find((check) => check.id === checkId),
        commandResults: { "show-global-properties": globalProperties.ok ? "ok" : globalProperties.error }
      };
    }
    case "cve.ike-global-property":
    case "cve.legacy-clients":
    case "cve.site-to-site-communities": {
      const [globalProperties, gateways] = await Promise.all([
        tryCommand(session, "show-global-properties", { "details-level": "full" }),
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" })
      ]);
      const cveIkeEvidence = await collectCveIkeEvidence(session, globalProperties, gateways);
      const checks = evaluateCveIkeChecks(cveIkeEvidence, session);
      return {
        check: checks.find((check) => check.id === checkId),
        commandResults: {
          "show-global-properties": globalProperties.ok ? "ok" : globalProperties.error,
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "cve-ike": cveIkeEvidence.ok ? "ok" : { error: `${cveIkeEvidence.errors?.length || 0} lookup error${(cveIkeEvidence.errors?.length || 0) === 1 ? "" : "s"}` }
        }
      };
    }
    case "policy.stealth-rule": {
      const [gateways, gatewaysAndServers, packages] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" }),
        tryListObjects(session, "show-packages", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gatewayStealthRules = await collectGatewayStealthRuleEvidence(session, { ok: gatewayInventory.ok, objects: gatewayInventory.policyTargets, error: gatewayInventory.error }, packages);
      return {
        check: evaluateGatewayStealthRules(gatewayStealthRules, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "show-packages": packages.ok ? "ok" : packages.error,
          "where-used/show-access-rule": gatewayStealthRules.ok ? "ok" : (gatewayStealthRules.error || compactLookupErrors(gatewayStealthRules.errors))
        }
      };
    }
    case "mgmt.protected-segment": {
      if (session.smart1Cloud) {
        return {
          check: null,
          commandResults: { "mgmt.protected-segment": "skipped for Smart-1 Cloud" }
        };
      }
      const [gatewaysAndServers, gateways] = await Promise.all([
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" }),
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const managementFirewallProtection = await collectManagementFirewallEvidence(session, gatewaysAndServers, { ok: gatewayInventory.ok, objects: gatewayInventory.topologyObjects, error: gatewayInventory.error });
      return {
        check: evaluateManagementFirewallProtection(managementFirewallProtection, session),
        commandResults: {
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/management-firewall": managementFirewallProtection.ok ? "ok" : { error: `${managementFirewallProtection.errors?.length || 0} lookup error${(managementFirewallProtection.errors?.length || 0) === 1 ? "" : "s"}` }
        }
      };
    }
    case "mgmt.admin-source-ip": {
      if (session.smart1Cloud) {
        return {
          check: null,
          commandResults: { "mgmt.admin-source-ip": "skipped for Smart-1 Cloud" }
        };
      }
      const [gatewaysAndServers, packages, networks, addressRanges] = await Promise.all([
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" }),
        tryListObjects(session, "show-packages", { "details-level": "full" }),
        tryListObjects(session, "show-networks", { "details-level": "full" }),
        tryListObjects(session, "show-address-ranges", { "details-level": "full" })
      ]);
      const administrativeSourceIpAddresses = await collectAdministrativeSourceIpEvidence(session, gatewaysAndServers, packages, networks, addressRanges);
      return {
        check: evaluateAdministrativeSourceIpAddresses(administrativeSourceIpAddresses, session),
        commandResults: {
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "show-packages": packages.ok ? "ok" : packages.error,
          "show-networks": networks.ok ? "ok" : networks.error,
          "show-address-ranges": addressRanges.ok ? "ok" : addressRanges.error,
          "where-used/show-access-rule/admin-source-ip": administrativeSourceIpAddresses.ok ? "ok" : (administrativeSourceIpAddresses.error || { error: `${administrativeSourceIpAddresses.errors?.length || 0} lookup error${(administrativeSourceIpAddresses.errors?.length || 0) === 1 ? "" : "s"}` }),
          "show-nat-rulebase/admin-source-ip": administrativeSourceIpAddresses.ok ? "ok" : (administrativeSourceIpAddresses.error || { error: `${administrativeSourceIpAddresses.errors?.length || 0} lookup error${(administrativeSourceIpAddresses.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "integrations.cloud-controllers": {
      const dataCenterServers = await tryListObjects(session, "show-data-center-servers", { "details-level": "full" });
      return {
        check: evaluateCloudControllerIntegrations(dataCenterServers, session),
        commandResults: { "show-data-center-servers": dataCenterServers.ok ? "ok" : dataCenterServers.error }
      };
    }
    case "integrations.active-directory": {
      const [gateways, clusters, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-simple-clusters", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const adGatewayObjects = {
        ok: gateways.ok || clusters.ok,
        objects: [
          ...(gateways.ok ? gateways.objects || [] : []),
          ...(clusters.ok ? clusters.objects || [] : [])
        ],
        error: gateways.error || clusters.error
      };
      const activeDirectoryIntegrations = await collectActiveDirectoryIntegrationEvidence(session, adGatewayObjects);
      return {
        check: evaluateActiveDirectoryIntegrationAccounts(activeDirectoryIntegrations, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-simple-clusters": clusters.ok ? "ok" : clusters.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "show-generic-object/ad-query": activeDirectoryIntegrations.ok ? "ok" : (activeDirectoryIntegrations.error || { error: `${activeDirectoryIntegrations.errors?.length || 0} lookup error${(activeDirectoryIntegrations.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "updates.jumbo-hotfix": {
      const [gateways, clusters, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-simple-clusters", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const jumboHotfixTargets = {
        ok: gatewayInventory.ok,
        // Match the full scan: query standalone gateways and physical cluster
        // members, never the logical cluster object.
        objects: gatewayInventory.runScriptTargets,
        error: gatewayInventory.error
      };
      const jumboHotfixEvidence = await collectJumboHotfixEvidence(session, jumboHotfixTargets);
      return {
        check: evaluateJumboHotfixAccumulator(jumboHotfixEvidence, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-simple-clusters": clusters.ok ? "ok" : clusters.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "show-software-packages-per-targets": jumboHotfixEvidence.ok ? "ok" : (jumboHotfixEvidence.error || { error: `${jumboHotfixEvidence.errors?.length || 0} lookup error${(jumboHotfixEvidence.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "gaia.allowed-host-access": {
      const [gateways, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gaiaFullScanEvidence = await collectGaiaFullScanEvidence(session, { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error }, gatewaysAndServers);
      const gaiaAllowedHostAccess = gaiaFullScanEvidence.allowedHostAccess;
      return {
        check: evaluateGaiaAllowedHostAccess(gaiaAllowedHostAccess, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/gaia-allowed-host-access": gaiaAllowedHostAccess.ok ? "ok" : (gaiaAllowedHostAccess.error || { error: `${gaiaAllowedHostAccess.errors?.length || 0} lookup error${(gaiaAllowedHostAccess.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "gaia.admin-settings": {
      const [gateways, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gaiaAdministratorSettings = await collectGaiaAdministratorSettingsEvidence(session, { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error }, gatewaysAndServers);
      return {
        check: evaluateGaiaAdministratorSettings(gaiaAdministratorSettings, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/gaia-admin-settings": gaiaAdministratorSettings.ok ? "ok" : (gaiaAdministratorSettings.error || { error: `${gaiaAdministratorSettings.errors?.length || 0} lookup error${(gaiaAdministratorSettings.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "gaia.expert-mode-access": {
      const [gateways, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gaiaAdministratorSettings = await collectGaiaAdministratorSettingsEvidence(session, { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error }, gatewaysAndServers);
      return {
        check: evaluateGaiaExpertModeAccess(gaiaAdministratorSettings, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/gaia-admin-settings": gaiaAdministratorSettings.ok ? "ok" : (gaiaAdministratorSettings.error || { error: `${gaiaAdministratorSettings.errors?.length || 0} lookup error${(gaiaAdministratorSettings.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "gaia.password-policy-hardening": {
      const [gateways, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gaiaPasswordPolicy = await collectGaiaPasswordPolicyEvidence(session, { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error }, gatewaysAndServers);
      return {
        check: evaluateGaiaPasswordPolicyHardening(gaiaPasswordPolicy, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/gaia-password-policy": gaiaPasswordPolicy.ok ? "ok" : (gaiaPasswordPolicy.error || { error: `${gaiaPasswordPolicy.errors?.length || 0} lookup error${(gaiaPasswordPolicy.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "gaia.snmp-monitoring-hardening": {
      const [gateways, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gaiaSnmpMonitoring = await collectGaiaSnmpHardeningEvidence(session, { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error }, gatewaysAndServers);
      return {
        check: evaluateGaiaSnmpMonitoringHardening(gaiaSnmpMonitoring, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/gaia-snmp-monitoring": gaiaSnmpMonitoring.ok ? "ok" : (gaiaSnmpMonitoring.error || { error: `${gaiaSnmpMonitoring.errors?.length || 0} lookup error${(gaiaSnmpMonitoring.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "gaia.system-logging-management": {
      const [gateways, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gaiaSystemLogging = await collectGaiaSystemLoggingEvidence(session, { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error }, gatewaysAndServers);
      return {
        check: evaluateGaiaSystemLoggingToManagement(gaiaSystemLogging, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/gaia-system-logging": gaiaSystemLogging.ok ? "ok" : (gaiaSystemLogging.error || { error: `${gaiaSystemLogging.errors?.length || 0} lookup error${(gaiaSystemLogging.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "gaia.management-external-syslog": {
      const gatewaysAndServers = await tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" });
      const gaiaManagementExternalSyslog = await collectGaiaManagementExternalSyslogEvidence(session, gatewaysAndServers);
      return {
        check: evaluateGaiaManagementExternalSyslog(gaiaManagementExternalSyslog, session),
        commandResults: {
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "run-script/gaia-management-external-syslog": gaiaManagementExternalSyslog.ok ? "ok" : (gaiaManagementExternalSyslog.error || { error: `${gaiaManagementExternalSyslog.errors?.length || 0} lookup error${(gaiaManagementExternalSyslog.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "security-feature-usage.licensed-blades": {
      const [gateways, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gaiaTargets = { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error };
      const securityFeatureUsage = await collectSecurityFeatureUsageEvidence(session, gaiaTargets);
      return {
        check: evaluateSecurityFeatureUsage(securityFeatureUsage, session),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/security-feature-usage": securityFeatureUsage.ok ? "ok" : (securityFeatureUsage.error || { error: `${securityFeatureUsage.errors?.length || 0} lookup error${(securityFeatureUsage.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    case "security-feature-usage.sizing-statistics": {
      const [gateways, gatewaysAndServers] = await Promise.all([
        tryListObjects(session, "show-simple-gateways", { "details-level": "full" }),
        tryListObjects(session, "show-gateways-and-servers", { "details-level": "full" })
      ]);
      const gatewayInventory = gatewayServerInventory(gatewaysAndServers, gateways);
      const gaiaTargets = { ok: gatewayInventory.ok, objects: gatewayInventory.runScriptTargets, error: gatewayInventory.error };
      const sizingStatistics = await collectSizingStatisticsEvidence(session, gaiaTargets);
      return {
        check: evaluateSizingStatistics(sizingStatistics),
        commandResults: {
          "show-simple-gateways": gateways.ok ? "ok" : gateways.error,
          "show-gateways-and-servers": gatewaysAndServers.ok ? "ok" : gatewaysAndServers.error,
          "gateway-inventory": gatewayInventory.ok ? "ok" : gatewayInventory.error,
          "run-script/sizing-statistics": sizingStatistics.ok ? "ok" : (sizingStatistics.error || { error: `${sizingStatistics.errors?.length || 0} lookup error${(sizingStatistics.errors?.length || 0) === 1 ? "" : "s"}` })
        }
      };
    }
    default:
      throw enrichError(new Error("This check does not support targeted refresh yet."), {
        phase: "check-refresh-target",
        target: checkId
      });
  }
}

async function refreshHardeningCheck(session, checkId) {
  if (!checkId) {
    throw enrichError(new Error("No check ID was provided."), {
      phase: "check-refresh-target"
    });
  }
  const { check: evaluated, commandResults = {} } = await evaluateSingleHardeningCheck(session, checkId);
  const errors = Object.values(commandResults).filter(value => value && typeof value === "object");
  const check = evaluated ? withFindingIdentity({ ...evaluated,
    collection: collectionOutcome({ ok: !errors.length, errors, rows: evaluated.evidenceTable?.rows,
      evidenceTables: evaluated.evidenceTables }) }, {
    domain: session.domain || "", inventory: session.lastHardeningScan?.targetInventory || []
  }) : null;
  if (!check) {
    if (session.lastHardeningScan?.checks?.length) {
      session.lastHardeningScan.checks = session.lastHardeningScan.checks.filter((existing) => existing.id !== checkId);
      session.lastHardeningScan.summary = summarizeChecks(session.lastHardeningScan.checks);
      session.lastHardeningScan.commandResults = {
        ...(session.lastHardeningScan.commandResults || {}),
        ...commandResults
      };
    }
    return {
      ok: true,
      check: null,
      summary: session.lastHardeningScan?.summary || summarizeChecks([]),
      commandResults
    };
  }
  if (session.lastHardeningScan?.checks?.length) {
    const index = session.lastHardeningScan.checks.findIndex((existing) => existing.id === check.id);
    if (index >= 0) {
      session.lastHardeningScan.checks[index] = check;
    } else {
      session.lastHardeningScan.checks.push(check);
      session.lastHardeningScan.checks = moveCategoryBefore(session.lastHardeningScan.checks, "Limiting Third-Party Integration Credentials", "Updates, Health, and Ongoing Protection");
    }
    session.lastHardeningScan.summary = summarizeChecks(session.lastHardeningScan.checks);
    session.lastHardeningScan.commandResults = {
      ...(session.lastHardeningScan.commandResults || {}),
      ...commandResults
    };
  }
  addAuditEntry({
    session,
    action: "Refresh Hardening Check",
    command: Object.keys(commandResults).join(", ") || "targeted-check-refresh",
    target: check.id,
    details: `Refreshed ${check.title}.`
  });
  return {
    ok: true,
    check,
    summary: session.lastHardeningScan?.summary || summarizeChecks([check]),
    commandResults
  };
}

function getSystemDataSession(session) {
  if (!session.systemDataSid) {
    throw enrichError(new Error(session.systemDataLoginError?.error || "System Data login is not available."), {
      command: "login",
      phase: session.systemDataLoginError?.phase || "system-data-login",
      target: session.systemDataLoginError?.target,
      statusCode: session.systemDataLoginError?.statusCode,
      response: session.systemDataLoginError?.response
    });
  }
  return {
    baseUrl: session.baseUrl,
    rejectUnauthorized: session.rejectUnauthorized,
    sid: session.systemDataSid
  };
}

async function removeAnyTrustedClient(session) {
  const systemDataSession = getSystemDataSession(session);
  const trustedClients = await listObjects(systemDataSession, "show-trusted-clients", { "details-level": "full" });
  const anyClient = trustedClients.find((client) => String(client.type || "").toLowerCase() === "any");
  if (!anyClient?.uid && !anyClient?.name) {
    throw enrichError(new Error("No trusted client with type 'any' was found."), {
      command: "show-trusted-clients",
      phase: "remediation-target-lookup"
    });
  }

  const remainingRestrictedClients = trustedClients.filter(
    (client) => String(client.type || client.TYPE || "").toLowerCase() !== "any"
  );
  if (!remainingRestrictedClients.length) {
    throw enrichError(new Error("ANY is currently the only trusted client. Add a new trusted client before deleting ANY so you do not lock yourself out of SmartConsole."), {
      command: "show-trusted-clients",
      phase: "lockout-protection"
    });
  }

  const deleteTarget = anyClient.uid ? { uid: anyClient.uid } : { name: anyClient.name };
  const deleteResult = await cpRequest(systemDataSession, "delete-trusted-client", deleteTarget);
  let publishResult = null;
  try {
    publishResult = await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`${anyClient.name} was deleted in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      deleteResult,
      discardResult
    });
  }
  return {
    ok: true,
    command: "delete-trusted-client",
    removed: anyClient.name,
    removedUid: anyClient.uid || "",
    removedType: anyClient.type,
    deleteTarget,
    deleteResult,
    publishResult,
    published: true
  };
}

function validIpv4Cidr(value) {
  const [address, prefix, ...extra] = String(value || "").trim().split("/");
  if (extra.length || isIP(address) !== 4) return false;
  if (prefix === undefined) return true;
  return /^\d+$/.test(prefix) && Number(prefix) >= 0 && Number(prefix) <= 32;
}

function validIpv4SubnetMask(value) {
  if (isIP(String(value || "").trim()) !== 4) return false;
  const bits = String(value).trim().split(".")
    .map((octet) => Number(octet).toString(2).padStart(8, "0"))
    .join("");
  return !bits.includes("01");
}

function ipv4Number(value) {
  return String(value).split(".").reduce((total, octet) => (total * 256) + Number(octet), 0);
}

async function addTrustedClient(session, payload = {}) {
  const systemDataSession = getSystemDataSession(session);
  const name = String(payload.name || "").trim();
  const objectType = String(payload.objectType || "").trim();
  if (!name) {
    throw enrichError(new Error("Enter an object name for the trusted client."), { phase: "trusted-client-validation" });
  }

  let commandPayload;
  if (objectType === "host") {
    const address = String(payload.ipv4Address || "").trim();
    if (isIP(address) !== 4) {
      throw enrichError(new Error("Enter a valid IPv4 address for the Host object."), { phase: "trusted-client-validation" });
    }
    commandPayload = { name, type: "ipv4 address", "ipv4-address": address };
  } else if (objectType === "range") {
    const first = String(payload.ipv4AddressFirst || "").trim();
    const last = String(payload.ipv4AddressLast || "").trim();
    if (isIP(first) !== 4 || isIP(last) !== 4) {
      throw enrichError(new Error("Enter valid first and last IPv4 addresses for the range."), { phase: "trusted-client-validation" });
    }
    if (ipv4Number(first) > ipv4Number(last)) {
      throw enrichError(new Error("The first IP address must be lower than or equal to the last IP address."), { phase: "trusted-client-validation" });
    }
    commandPayload = { name, type: "ipv4 address range", "ipv4-address-first": first, "ipv4-address-last": last };
  } else if (objectType === "network") {
    const address = String(payload.ipv4Address || "").trim();
    const subnetMask = String(payload.subnetMask || "").trim();
    if (!validIpv4Cidr(address)) {
      throw enrichError(new Error("Enter a valid IPv4 network or CIDR address."), { phase: "trusted-client-validation" });
    }
    if (!validIpv4SubnetMask(subnetMask)) {
      throw enrichError(new Error("Enter a valid contiguous subnet mask in dotted-decimal format."), { phase: "trusted-client-validation" });
    }
    commandPayload = { name, type: "ipv4 netmask", "ipv4-address": address, "subnet-mask": subnetMask };
  } else {
    throw enrichError(new Error("Select Host Object, IP Range, or Network Object."), { phase: "trusted-client-validation" });
  }

  const addResult = await cpRequest(systemDataSession, "add-trusted-client", commandPayload);
  try {
    await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = { error: discardError.message, command: discardError.command, phase: discardError.phase };
    }
    throw enrichError(new Error(`${name} was added in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      response: error.response,
      addResult,
      discardResult
    });
  }
  return { added: name, objectType, published: true, commandPayload };
}

async function deleteTrustedClients(session, uids = []) {
  const requestedUids = uniqueStrings(Array.isArray(uids) ? uids : []);
  if (!requestedUids.length) {
    throw enrichError(new Error("No trusted clients were selected for deletion."), {
      command: "delete-trusted-client",
      phase: "input-validation"
    });
  }

  const systemDataSession = getSystemDataSession(session);
  const trustedClients = await listObjects(systemDataSession, "show-trusted-clients", { "details-level": "full" });
  const trustedClientMap = new Map(trustedClients.filter((client) => client.uid).map((client) => [client.uid, client]));
  const missingUids = requestedUids.filter((uid) => !trustedClientMap.has(uid));
  if (missingUids.length) {
    throw enrichError(new Error(`Selected trusted client object was not found: ${missingUids.join(", ")}`), {
      command: "show-trusted-clients",
      phase: "remediation-target-lookup"
    });
  }

  const selectedClients = requestedUids.map((uid) => trustedClientMap.get(uid));
  const deletingAny = selectedClients.some(
    (client) => String(client?.type || client?.TYPE || "").toLowerCase() === "any"
  );
  const selectedUidSet = new Set(requestedUids);
  const remainingRestrictedClients = trustedClients.filter((client) => (
    !selectedUidSet.has(client.uid)
      && String(client.type || client.TYPE || "").toLowerCase() !== "any"
  ));
  if (deletingAny && !remainingRestrictedClients.length) {
    throw enrichError(new Error("Deleting the selected clients would remove ANY without leaving a restricted trusted client. Add or retain at least one trusted client before deleting ANY so you do not lock yourself out of SmartConsole."), {
      command: "show-trusted-clients",
      phase: "lockout-protection"
    });
  }

  const deleted = [];
  try {
    for (const uid of requestedUids) {
      const client = trustedClientMap.get(uid);
      const deleteResult = await cpRequest(systemDataSession, "delete-trusted-client", { uid });
      deleted.push({
        uid,
        name: client.name || client.NAME || uid,
        type: client.type || client.TYPE || "",
        deleteResult
      });
    }
  } catch (error) {
    let discardResult = null;
    if (deleted.length) {
      try {
        discardResult = await cpRequest(systemDataSession, "discard", {});
      } catch (discardError) {
        discardResult = {
          error: discardError.message,
          command: discardError.command,
          phase: discardError.phase,
          statusCode: discardError.statusCode,
          response: discardError.response
        };
      }
    }
    throw enrichError(new Error(`Trusted client deletion failed: ${error.message}`), {
      command: error.command,
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      deleted,
      discardResult
    });
  }

  let publishResult = null;
  try {
    publishResult = await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`Trusted clients were deleted in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      deleted,
      discardResult
    });
  }

  return {
    ok: true,
    command: "delete-trusted-client",
    deleted: deleted.map(({ uid, name, type }) => ({ uid, name, type })),
    deletedCount: deleted.length,
    publishResult,
    published: true
  };
}

async function deleteAdministrators(session, uids = []) {
  const requestedUids = uniqueStrings(Array.isArray(uids) ? uids : []);
  if (!requestedUids.length) {
    throw enrichError(new Error("No administrators were selected for deletion."), {
      command: "delete-administrator",
      phase: "input-validation"
    });
  }

  const systemDataSession = getSystemDataSession(session);
  const administrators = await listObjects(systemDataSession, "show-administrators", { "details-level": "full" });
  const administratorMap = new Map(administrators.filter((admin) => admin.uid).map((admin) => [admin.uid, admin]));
  const missingUids = requestedUids.filter((uid) => !administratorMap.has(uid));
  if (missingUids.length) {
    throw enrichError(new Error(`Selected administrator object was not found: ${missingUids.join(", ")}`), {
      command: "show-administrators",
      phase: "remediation-target-lookup"
    });
  }

  const deleted = [];
  try {
    for (const uid of requestedUids) {
      const admin = administratorMap.get(uid);
      const deleteResult = await cpRequest(systemDataSession, "delete-administrator", { uid });
      deleted.push({
        uid,
        name: admin.name || admin.NAME || uid,
        deleteResult
      });
    }
  } catch (error) {
    let discardResult = null;
    if (deleted.length) {
      try {
        discardResult = await cpRequest(systemDataSession, "discard", {});
      } catch (discardError) {
        discardResult = {
          error: discardError.message,
          command: discardError.command,
          phase: discardError.phase,
          statusCode: discardError.statusCode,
          response: discardError.response
        };
      }
    }
    throw enrichError(new Error(`Administrator deletion failed: ${error.message}`), {
      command: error.command,
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      deleted,
      discardResult
    });
  }

  let publishResult = null;
  try {
    publishResult = await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`Administrators were deleted in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      deleted,
      discardResult
    });
  }

  return {
    ok: true,
    command: "delete-administrator",
    deleted: deleted.map(({ uid, name }) => ({ uid, name })),
    deletedCount: deleted.length,
    publishResult,
    published: true
  };
}

async function setAdministratorExpirationFourMonths(session, checkId = "", uids = []) {
  const requestedUids = uniqueStrings(Array.isArray(uids) ? uids : []);
  if (!requestedUids.length) {
    throw enrichError(new Error("No administrators were selected for expiration update."), {
      command: "set-administrator",
      phase: "input-validation"
    });
  }
  const systemDataSession = getSystemDataSession(session);
  const administrators = await listObjects(systemDataSession, "show-administrators", { "details-level": "full" });
  const administratorMap = new Map(administrators.filter((admin) => admin.uid).map((admin) => [admin.uid, admin]));
  const missingUids = requestedUids.filter((uid) => !administratorMap.has(uid));
  if (missingUids.length) {
    throw enrichError(new Error(`Selected administrator object was not found: ${missingUids.join(", ")}`), {
      command: "show-administrators",
      phase: "remediation-target-lookup"
    });
  }
  const apiKeyOnly = checkId === "admin.api-key-authentication";
  const targets = requestedUids.map((uid) => administratorMap.get(uid)).filter((admin) => {
    if (!adminExpirationIsNever(admin)) return false;
    if (!apiKeyOnly) return true;
    const method = admin["authentication-method"] || admin.authenticationMethod || "";
    return normalizeToken(method) === "apikey";
  });
  if (!targets.length) {
    throw enrichError(new Error("No checked administrator accounts with expiration set to Never were found."), {
      command: "show-administrators",
      phase: "remediation-target-lookup"
    });
  }

  const expirationDate = dateFourMonthsFromNow();
  const changed = [];
  try {
    for (const admin of targets) {
      const name = admin.name || admin.NAME || "";
      if (!name) {
        throw enrichError(new Error("Administrator name was not returned for one selected target."), {
          command: "show-administrators",
          phase: "remediation-target-lookup"
        });
      }
      const setResult = await cpRequest(systemDataSession, "set-administrator", {
        name,
        "expiration-date": expirationDate
      });
      changed.push({
        uid: admin.uid || "",
        name,
        expirationDate,
        setResult
      });
    }
  } catch (error) {
    let discardResult = null;
    if (changed.length) {
      try {
        discardResult = await cpRequest(systemDataSession, "discard", {});
      } catch (discardError) {
        discardResult = {
          error: discardError.message,
          command: discardError.command,
          phase: discardError.phase,
          statusCode: discardError.statusCode,
          response: discardError.response
        };
      }
    }
    throw enrichError(new Error(`Administrator expiration update failed: ${error.message}`), {
      command: error.command,
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      changed,
      discardResult
    });
  }

  let publishResult = null;
  try {
    publishResult = await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`Administrator expiration was changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      changed,
      discardResult
    });
  }

  return {
    ok: true,
    command: "set-administrator",
    changed: changed.map(({ uid, name, expirationDate }) => ({ uid, name, expirationDate })),
    changedCount: changed.length,
    expirationDate,
    publishResult,
    published: true
  };
}

async function setDefaultAdminExpirationQuarterly(session) {
  const systemDataSession = getSystemDataSession(session);
  const body = {
    "expiration-type": "expiration period",
    "expiration-period": 4,
    "expiration-period-time-units": "months"
  };
  const setResult = await cpRequest(systemDataSession, "set-default-administrator-settings", body);
  let publishResult = null;
  try {
    publishResult = await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`Default administrator expiration was changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      setResult,
      discardResult
    });
  }
  return {
    ok: true,
    command: "set-default-administrator-settings",
    changed: "Default administrator expiration",
    expirationType: body["expiration-type"],
    expirationPeriod: body["expiration-period"],
    expirationPeriodTimeUnits: body["expiration-period-time-units"],
    setResult,
    publishResult,
    published: true
  };
}

async function setMinimumPasswordLength(session) {
  const systemDataSession = getSystemDataSession(session);
  const body = {
    "min-password-length": 10
  };
  const setResult = await cpRequest(systemDataSession, "set-cp-password-requirements", body);
  let publishResult = null;
  try {
    publishResult = await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`Minimum password length was changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      setResult,
      discardResult
    });
  }
  return {
    ok: true,
    command: "set-cp-password-requirements",
    changed: "Minimum password length",
    minPasswordLength: body["min-password-length"],
    setResult,
    publishResult,
    published: true
  };
}

async function setSmartConsoleIdleTimeout(session) {
  const systemDataSession = getSystemDataSession(session);
  const body = {
    enabled: true,
    "timeout-duration": 10
  };
  const setResult = await cpRequest(systemDataSession, "set-smart-console-idle-timeout", body);
  let publishResult = null;
  try {
    publishResult = await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`SmartConsole idle timeout was changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      setResult,
      discardResult
    });
  }
  return {
    ok: true,
    command: "set-smart-console-idle-timeout",
    changed: "SmartConsole idle timeout",
    enabled: body.enabled,
    timeoutDuration: body["timeout-duration"],
    setResult,
    publishResult,
    published: true
  };
}

async function setApiClientsToGuiClients(session) {
  const systemDataSession = getSystemDataSession(session);
  const body = {
    "accepted-api-calls-from": "all ip addresses that can be used for gui clients"
  };
  const setResult = await cpRequest(systemDataSession, "set-api-settings", body);
  let publishResult = null;
  try {
    publishResult = await cpRequest(systemDataSession, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(systemDataSession, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`API access settings were changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      setResult,
      discardResult
    });
  }
  return {
    ok: true,
    command: "set-api-settings",
    changed: "Management API access",
    acceptedApiCallsFrom: body["accepted-api-calls-from"],
    setResult,
    publishResult,
    published: true
  };
}

async function enableLogImpliedRules(session) {
  const body = {
    firewall: {
      "log-implied-rules": true
    }
  };
  const setResult = await cpRequest(session, "set-global-properties", body);
  let publishResult = null;
  try {
    publishResult = await cpRequest(session, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(session, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`Implied rule logging was changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      setResult,
      discardResult
    });
  }
  return {
    ok: true,
    command: "set-global-properties",
    changed: "Implied rule logging",
    logImpliedRules: true,
    setResult,
    publishResult,
    published: true
  };
}

async function enableDiagnosticsTelemetry(session) {
  const body = {
    "data-access-control": {
      "send-anonymous-info": true
    }
  };
  const setResult = await cpRequest(session, "set-global-properties", body);
  let publishResult = null;
  try {
    publishResult = await cpRequest(session, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(session, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`Diagnostics and telemetry setting was changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      setResult,
      discardResult
    });
  }
  return {
    ok: true,
    command: "set-global-properties",
    changed: "Diagnostics and telemetry",
    sendAnonymousInfo: true,
    setResult,
    publishResult,
    published: true
  };
}

async function enableDynamicUpdates(session) {
  const body = {
    "data-access-control": {
      "auto-download-important-data": true,
      "auto-download-sw-updates-and-new-features": true
    }
  };
  const setResult = await cpRequest(session, "set-global-properties", body);
  let publishResult = null;
  try {
    publishResult = await cpRequest(session, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(session, "discard", {});
    } catch (discardError) {
      discardResult = {
        error: discardError.message,
        command: discardError.command,
        phase: discardError.phase,
        statusCode: discardError.statusCode,
        response: discardError.response
      };
    }
    throw enrichError(new Error(`Dynamic update settings were changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      setResult,
      discardResult
    });
  }
  return {
    ok: true,
    command: "set-global-properties",
    changed: "Dynamic updates",
    autoDownloadImportantData: true,
    autoDownloadSoftwareUpdatesAndNewFeatures: true,
    setResult,
    publishResult,
    published: true
  };
}

async function publishOrDiscardOnFailure(session, setResult, label) {
  try {
    return await cpRequest(session, "publish", {});
  } catch (error) {
    let discardResult = null;
    try {
      discardResult = await cpRequest(session, "discard", {});
    } catch (discardError) {
      discardResult = commandError(discardError);
    }
    throw enrichError(new Error(`${label} was changed in the session, but publish failed: ${error.message}`), {
      command: "publish",
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      setResult,
      discardResult
    });
  }
}

async function remediateCveGlobalIkeV2Only(session) {
  const attempts = [
    {
      name: "structured-json",
      body: {
        "remote-access": {
          "vpn-authentication-and-encryption": {
            "encryption-method": CVE_IKE_DESIRED_METHOD
          }
        }
      }
    },
    {
      name: "dotted-string",
      body: {
        "remote-access.vpn-authentication-and-encryption.encryption-method": CVE_IKE_DESIRED_METHOD
      }
    }
  ];
  const failed = [];
  for (const attempt of attempts) {
    try {
      const setResult = await cpRequest(session, "set-global-properties", attempt.body);
      const publishResult = await publishOrDiscardOnFailure(session, setResult, "Global IKE encryption method");
      return {
        ok: true,
        command: "set-global-properties",
        changed: "Global IKE encryption method",
        desiredMethod: CVE_IKE_DESIRED_METHOD,
        appliedForm: attempt.name,
        setResult,
        publishResult,
        published: true
      };
    } catch (error) {
      failed.push({
        form: attempt.name,
        error: error.message,
        phase: error.phase,
        statusCode: error.statusCode,
        response: error.response
      });
    }
  }
  const last = failed.at(-1) || {};
  throw enrichError(new Error(last.error || "All global IKE remediation attempts failed."), {
    command: "set-global-properties",
    phase: last.phase || "all-attempts-failed",
    attempts: failed
  });
}

function cveLegacyGatewayChangeAttempts(gateway) {
  return [
    {
      name: "structured-json-boolean",
      body: {
        uid: gateway.uid,
        realmsForBlades: {
          set: [{
            uid: gateway.vpnRealmUid,
            "owned-object": {
              disabled: true
            }
          }]
        }
      }
    },
    {
      name: "dotted-string",
      body: {
        uid: gateway.uid,
        "realmsForBlades.set.1.uid": gateway.vpnRealmUid,
        "realmsForBlades.set.1.owned-object.disabled": CVE_LEGACY_CLIENT_DISABLED
      }
    },
    {
      name: "dotted-boolean",
      body: {
        uid: gateway.uid,
        "realmsForBlades.set.1.uid": gateway.vpnRealmUid,
        "realmsForBlades.set.1.owned-object.disabled": true
      }
    }
  ];
}

async function applyCveLegacyGatewayChange(session, gateway) {
  const failed = [];
  for (const attempt of cveLegacyGatewayChangeAttempts(gateway)) {
    try {
      await cpRequest(session, "set-generic-object", attempt.body);
      return { attempt: attempt.name };
    } catch (error) {
      failed.push({
        form: attempt.name,
        error: error.message,
        phase: error.phase,
        statusCode: error.statusCode,
        response: error.response
      });
    }
  }
  const last = failed.at(-1) || {};
  throw enrichError(new Error(last.error || "All legacy client remediation attempts failed."), {
    command: "set-generic-object",
    phase: last.phase || "all-attempts-failed",
    attempts: failed
  });
}

async function remediateCveLegacyClients(session, gatewayUids = []) {
  if (!session.lastCveIkeScan) {
    throw new Error("Run a scan before applying CVE legacy client remediation.");
  }
  const selected = new Set(gatewayUids || []);
  const targets = (session.lastCveIkeScan.legacyRows || []).filter((gateway) => selected.has(gateway.uid) && gateway.needsChange && gateway.vpnRealmUid);
  const changed = [];
  const failed = [];
  for (const gateway of targets) {
    try {
      const result = await applyCveLegacyGatewayChange(session, gateway);
      changed.push({ ...gateway, appliedForm: result.attempt });
    } catch (error) {
      failed.push({
        ...gateway,
        error: error.message,
        command: error.command,
        phase: error.phase,
        statusCode: error.statusCode,
        response: error.response,
        attempts: error.attempts
      });
    }
  }
  if (changed.length && !failed.length) {
    const publishResult = await publishOrDiscardOnFailure(session, { changed }, "Legacy client VPN realm setting");
    return {
      ok: true,
      command: "set-generic-object",
      changed,
      changedCount: changed.length,
      failed,
      skipped: gatewayUids.length - targets.length,
      publishResult,
      published: true
    };
  }
  return {
    ok: failed.length === 0,
    command: "set-generic-object",
    changed,
    changedCount: changed.length,
    failed,
    skipped: gatewayUids.length - targets.length,
    published: false
  };
}

function cveSiteToSiteCommunityCommand(type) {
  return type === "meshed" ? "set-vpn-community-meshed" : "set-vpn-community-star";
}

function cveSiteToSiteCommunityChangeAttempts(community) {
  const identifiers = community.uid
    ? [{ label: "uid", body: { uid: community.uid } }]
    : [{ label: "name", body: { name: community.name } }];
  if (community.uid && community.name) {
    identifiers.push({ label: "name", body: { name: community.name } });
  }
  const values = [
    { label: "ike_v2_only", value: CVE_IKE_DESIRED_METHOD },
    { label: "ikev2_only", value: "ikev2_only" },
    { label: "ikev2 only", value: "ikev2 only" }
  ];
  return identifiers.flatMap((identifier) => values.map((value) => ({
    name: `${identifier.label}-${value.label}`,
    body: {
      ...identifier.body,
      "encryption-method": value.value
    }
  })));
}

async function applyCveSiteToSiteCommunityChange(session, community) {
  const command = cveSiteToSiteCommunityCommand(community.type);
  const failed = [];
  for (const attempt of cveSiteToSiteCommunityChangeAttempts(community)) {
    try {
      await cpRequest(session, command, attempt.body);
      return { command, attempt: attempt.name };
    } catch (error) {
      failed.push({
        form: attempt.name,
        error: error.message,
        phase: error.phase,
        statusCode: error.statusCode,
        response: error.response
      });
    }
  }
  const last = failed.at(-1) || {};
  throw enrichError(new Error(last.error || "All site-to-site community remediation attempts failed."), {
    command,
    phase: last.phase || "all-attempts-failed",
    attempts: failed
  });
}

async function remediateCveSiteToSiteCommunities(session, communityUids = []) {
  if (!session.lastCveIkeScan) {
    throw new Error("Run a scan before applying CVE site-to-site community remediation.");
  }
  const selected = new Set(communityUids || []);
  const targets = (session.lastCveIkeScan.communities || []).filter((community) => selected.has(community.uid) && community.matchesCriteria);
  const changed = [];
  const failed = [];
  for (const community of targets) {
    try {
      const result = await applyCveSiteToSiteCommunityChange(session, community);
      changed.push({ ...community, command: result.command, appliedForm: result.attempt });
    } catch (error) {
      failed.push({
        ...community,
        error: error.message,
        command: error.command,
        phase: error.phase,
        statusCode: error.statusCode,
        response: error.response,
        attempts: error.attempts
      });
    }
  }
  if (changed.length && !failed.length) {
    const publishResult = await publishOrDiscardOnFailure(session, { changed }, "Site-to-site VPN community IKE setting");
    return {
      ok: true,
      command: "set-vpn-community-star/set-vpn-community-meshed",
      changed,
      changedCount: changed.length,
      failed,
      skipped: communityUids.length - targets.length,
      publishResult,
      published: true
    };
  }
  return {
    ok: failed.length === 0,
    command: "set-vpn-community-star/set-vpn-community-meshed",
    changed,
    changedCount: changed.length,
    failed,
    skipped: communityUids.length - targets.length,
    published: false
  };
}

function gaiaOutputIncludesConfigLock(result) {
  const output = [statusDescriptionText(result), responseMessageText(result)].filter(Boolean).join("\n");
  const token = normalizeToken(output);
  return token.includes("lockdatabaseoverride") || token.includes("configlockisowned");
}

function beginGaiaRemediationProgress(session, operationId, label, totalTargets) {
  session.gaiaRemediationProgress = {
    operationId,
    label,
    active: true,
    complete: false,
    failed: false,
    totalTargets,
    completedTargets: 0,
    currentTarget: "",
    currentCommand: "Preparing Gaia command",
    startedAt: new Date().toISOString(),
    steps: []
  };
}

function updateGaiaRemediationProgress(session, update = {}) {
  if (!session.gaiaRemediationProgress) return;
  Object.assign(session.gaiaRemediationProgress, update);
}

function recordGaiaRemediationStep(session, target, command, status, details = "") {
  if (!session.gaiaRemediationProgress) return;
  session.gaiaRemediationProgress.steps.push({
    timestamp: new Date().toISOString(),
    target,
    command,
    status,
    details
  });
  if (session.gaiaRemediationProgress.steps.length > 20) {
    session.gaiaRemediationProgress.steps.splice(0, session.gaiaRemediationProgress.steps.length - 20);
  }
}

async function runGaiaConfigCommandWithLockOverride(session, target, scriptName, command) {
  const targetSession = mdsRunScriptSession(session, target);
  const runCommand = async () => {
    updateGaiaRemediationProgress(session, { currentTarget: target.name, currentCommand: `clish -c "${command}"` });
    const result = await runScriptWithTaskDetails(targetSession, {
      "script-name": scriptName,
      targets: [target.name],
      script: `clish -c "${command}"`
    });
    recordGaiaRemediationStep(session, target.name, `clish -c "${command}"`, result.ok && !gaiaOutputIncludesConfigLock(result) ? "ok" : "waiting", gaiaOutputIncludesConfigLock(result) ? "Gaia configuration lock detected" : "");
    return result;
  };
  const acquireLockOverride = async () => {
    const lockCommand = "clish -c \"lock database override\"";
    updateGaiaRemediationProgress(session, { currentTarget: target.name, currentCommand: lockCommand });
    const result = await runScriptWithTaskDetails(targetSession, {
      "script-name": "lock database override",
      targets: [target.name],
      script: lockCommand
    });
    recordGaiaRemediationStep(session, target.name, lockCommand, result.ok ? "ok" : "failed", result.ok ? "Lock override task completed" : (result.error?.error || "Lock override failed"));
    return result;
  };
  let commandResult = await runCommand();
  let lockOverrideResult = null;
  let retried = false;
  if (gaiaOutputIncludesConfigLock(commandResult)) {
    lockOverrideResult = await acquireLockOverride();
    if (!lockOverrideResult.ok) {
      throw enrichError(new Error(`Could not acquire the Gaia configuration lock on ${target.name}.`), {
        command: "run-script: lock database override",
        phase: "gaia-config-lock",
        target: target.name,
        response: lockOverrideResult.error || lockOverrideResult.data
      });
    }
    retried = true;
    const settleDelays = [1500, 2500, 4000];
    for (let attempt = 0; attempt < settleDelays.length; attempt += 1) {
      const delayMs = settleDelays[attempt];
      updateGaiaRemediationProgress(session, {
        currentTarget: target.name,
        currentCommand: `Waiting ${delayMs} ms for Gaia configuration lock to settle before retry ${attempt + 1}`
      });
      await sleep(delayMs);
      commandResult = await runCommand();
      if (!gaiaOutputIncludesConfigLock(commandResult)) break;
      if (attempt < settleDelays.length - 1) {
        lockOverrideResult = await acquireLockOverride();
        if (!lockOverrideResult.ok) break;
      }
    }
  }
  if (!commandResult.ok) {
    throw enrichError(new Error(commandResult.error?.error || `Gaia configuration command failed on ${target.name}.`), {
      command: `run-script: ${command}`,
      phase: "remediation-command",
      target: target.name,
      response: commandResult.error || commandResult.data
    });
  }
  if (gaiaOutputIncludesConfigLock(commandResult)) {
    throw enrichError(new Error(`The Gaia configuration lock is still owned by another session on ${target.name}.`), {
      command: `run-script: ${command}`,
      phase: "gaia-config-lock",
      target: target.name,
      response: commandResult.data
    });
  }
  return { targetName: target.name, command, commandResult, lockOverrideResult, retried };
}

async function addGaiaAllowedClientForTargets(session, payload = {}) {
  const requestedNames = uniqueStrings(Array.isArray(payload.targetNames) ? payload.targetNames : []);
  if (!requestedNames.length) {
    throw enrichError(new Error("Select one or more Gaia gateway or management targets."), {
      command: "run-script",
      phase: "input-validation"
    });
  }
  const check = session.lastHardeningScan?.checks?.find((item) => item.id === "gaia.allowed-host-access");
  const eligibleTargets = new Map((check?.evidenceTables || []).map((table) => {
    const name = String(table.title || "").replace(/^(Gateway|Management) Name:\s*/i, "").trim();
    return [name, {
      name,
      useMdsSession: /^Management Name:/i.test(String(table.title || "")) && Boolean(session.mdsSid)
    }];
  }).filter(([name]) => name));
  const invalidNames = requestedNames.filter((name) => !eligibleTargets.has(name));
  if (invalidNames.length) {
    throw enrichError(new Error(`Selected Gaia target was not returned by the latest scan: ${invalidNames.join(", ")}`), {
      command: "run-script",
      phase: "remediation-target-validation",
      target: invalidNames.join(", ")
    });
  }

  const objectType = String(payload.objectType || "");
  let command;
  if (objectType === "host") {
    const address = String(payload.ipv4Address || "").trim();
    if (isIP(address) !== 4) {
      throw enrichError(new Error("Enter a valid IPv4 address for the allowed host."), { phase: "input-validation" });
    }
    command = `add allowed-client host ipv4-address ${address}`;
  } else if (objectType === "network") {
    const address = String(payload.ipv4Address || "").trim();
    const maskLength = Number(payload.maskLength);
    if (isIP(address) !== 4) {
      throw enrichError(new Error("Enter a valid IPv4 network address."), { phase: "input-validation" });
    }
    if (!Number.isInteger(maskLength) || maskLength < 0 || maskLength > 32) {
      throw enrichError(new Error("Mask length must be a whole number from 0 through 32."), { phase: "input-validation" });
    }
    command = `add allowed-client network ipv4-address ${address} mask-length ${maskLength}`;
  } else {
    throw enrichError(new Error("Select Host or Network."), { phase: "input-validation" });
  }

  beginGaiaRemediationProgress(session, String(payload.operationId || ""), "Add Gaia allowed client", requestedNames.length);
  const changed = [];
  const failed = [];
  for (const name of requestedNames) {
    try {
      changed.push(await runGaiaConfigCommandWithLockOverride(session, eligibleTargets.get(name), "add Gaia allowed client", command));
    } catch (error) {
      failed.push({ targetName: name, error: error.message, command: error.command, phase: error.phase });
    }
    updateGaiaRemediationProgress(session, { completedTargets: changed.length + failed.length });
  }
  updateGaiaRemediationProgress(session, {
    active: false,
    complete: true,
    failed: failed.length > 0,
    currentCommand: failed.length ? "Gaia command completed with failures" : "Gaia command complete",
    completedAt: new Date().toISOString()
  });
  return {
    ok: failed.length === 0,
    command,
    targetNames: requestedNames,
    changed,
    changedCount: changed.length,
    failed,
    failedCount: failed.length
  };
}

async function deleteGaiaAnyHostForTargets(session, payload = {}) {
  const requestedNames = uniqueStrings(Array.isArray(payload.targetNames) ? payload.targetNames : []);
  if (!requestedNames.length) {
    throw enrichError(new Error("Select one or more Gaia gateway or management targets."), {
      command: "run-script",
      phase: "input-validation"
    });
  }
  const check = session.lastHardeningScan?.checks?.find((item) => item.id === "gaia.allowed-host-access");
  const eligibleTargets = new Map((check?.evidenceTables || []).map((table) => {
    const name = String(table.title || "").replace(/^(Gateway|Management) Name:\s*/i, "").trim();
    return [name, {
      name,
      useMdsSession: /^Management Name:/i.test(String(table.title || "")) && Boolean(session.mdsSid),
      hasAnyAllowedClient: Boolean(table.targetSelection?.hasAnyAllowedClient),
      onlyAnyAllowedClient: Boolean(table.targetSelection?.onlyAnyAllowedClient)
    }];
  }).filter(([name]) => name));
  const invalidNames = requestedNames.filter((name) => !eligibleTargets.has(name));
  if (invalidNames.length) {
    throw enrichError(new Error(`Selected Gaia target was not returned by the latest scan: ${invalidNames.join(", ")}`), {
      command: "run-script: delete allowed-client host any-host",
      phase: "remediation-target-validation",
      target: invalidNames.join(", ")
    });
  }
  const onlyAnyNames = requestedNames.filter((name) => eligibleTargets.get(name).onlyAnyAllowedClient);
  if (onlyAnyNames.length) {
    throw enrichError(new Error(`AnyHost is the only allowed client on ${onlyAnyNames.join(", ")}. You cannot delete it until you add another allowed client so you do not lock yourself out.`), {
      command: "run-script: delete allowed-client host any-host",
      phase: "lockout-protection",
      target: onlyAnyNames.join(", ")
    });
  }
  const withoutAnyNames = requestedNames.filter((name) => !eligibleTargets.get(name).hasAnyAllowedClient);
  if (withoutAnyNames.length) {
    throw enrichError(new Error(`AnyHost was not returned by the latest scan for: ${withoutAnyNames.join(", ")}.`), {
      command: "run-script: delete allowed-client host any-host",
      phase: "remediation-target-validation",
      target: withoutAnyNames.join(", ")
    });
  }

  const command = "delete allowed-client host any-host";
  beginGaiaRemediationProgress(session, String(payload.operationId || ""), "Delete Gaia AnyHost", requestedNames.length);
  const changed = [];
  const failed = [];
  for (const name of requestedNames) {
    try {
      changed.push(await runGaiaConfigCommandWithLockOverride(session, eligibleTargets.get(name), "delete Gaia AnyHost allowed client", command));
    } catch (error) {
      failed.push({ targetName: name, error: error.message, command: error.command, phase: error.phase });
    }
    updateGaiaRemediationProgress(session, { completedTargets: changed.length + failed.length });
  }
  updateGaiaRemediationProgress(session, {
    active: false,
    complete: true,
    failed: failed.length > 0,
    currentCommand: failed.length ? "Gaia command completed with failures" : "Gaia command complete",
    completedAt: new Date().toISOString()
  });
  return {
    ok: failed.length === 0,
    command,
    targetNames: requestedNames,
    changed,
    changedCount: changed.length,
    failed,
    failedCount: failed.length
  };
}

async function enableGatewaySyslogForwarding(session, targetName) {
  const name = String(targetName || "").trim();
  if (!name) {
    throw enrichError(new Error("No Security Gateway target was provided."), {
      command: "run-script",
      phase: "input-validation"
    });
  }
  const runSet = () => runScriptWithTaskDetails(session, {
    "script-name": "set syslog forwarding",
    targets: [name],
    script: "clish -c \"set syslog cplogs on\""
  });
  let setResult = await runSet();
  let lockOverrideResult = null;
  let retried = false;
  if (setResult.ok && gaiaOutputIncludesConfigLock(setResult)) {
    lockOverrideResult = await runScriptWithTaskDetails(session, {
      "script-name": "lock database override",
      targets: [name],
      script: "clish -c \"lock database override\""
    });
    if (!lockOverrideResult.ok) {
      throw enrichError(new Error(`Could not acquire Gaia configuration lock on ${name}: ${lockOverrideResult.error?.error || "lock database override failed"}`), {
        command: "run-script: lock database override",
        phase: "gaia-config-lock",
        target: name,
        response: lockOverrideResult.error || lockOverrideResult.data
      });
    }
    setResult = await runSet();
    retried = true;
  }
  if (!setResult.ok) {
    throw enrichError(new Error(setResult.error?.error || `Failed to enable syslog forwarding on ${name}.`), {
      command: "run-script: set syslog cplogs on",
      phase: "remediation-command",
      target: name,
      response: setResult.error || setResult.data
    });
  }
  if (gaiaOutputIncludesConfigLock(setResult)) {
    throw enrichError(new Error(`Gaia configuration lock is still owned by another session on ${name}.`), {
      command: "run-script: set syslog cplogs on",
      phase: "gaia-config-lock",
      target: name,
      response: setResult.data
    });
  }
  return {
    ok: true,
    command: "run-script: set syslog cplogs on",
    targetName: name,
    setResult,
    lockOverrideResult,
    retried,
    published: false
  };
}

async function enableGatewaySyslogForwardingForTargets(session, payload = {}) {
  const targetNames = uniqueStrings([
    ...(Array.isArray(payload.targetNames) ? payload.targetNames : []),
    payload.targetName
  ].filter(Boolean));
  if (!targetNames.length) {
    throw enrichError(new Error("No Security Gateway target was provided."), {
      command: "run-script",
      phase: "input-validation"
    });
  }
  const changed = [];
  const failed = [];
  for (const targetName of targetNames) {
    try {
      changed.push(await enableGatewaySyslogForwarding(session, targetName));
    } catch (error) {
      failed.push({ targetName, error: error.message || String(error) });
    }
  }
  return { ok: failed.length === 0, targetNames, changed, changedCount: changed.length, failed, failedCount: failed.length };
}

async function logout(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) {
    return;
  }
  try {
    const sessionIds = uniqueStrings([
      session.sid,
      session.systemDataSid,
      session.mdsSid,
      session.globalDomainSid,
      ...(session.moraDomains || []).map((domain) => domain.session?.sid)
    ]);
    const logoutTargets = sessionIds.map((sid) => ({
        baseUrl: session.baseUrl,
        rejectUnauthorized: session.rejectUnauthorized,
        sid
      }));
    for (const target of logoutTargets) {
      try {
        await cpRequest(target, "logout", {});
      } catch (error) {
        log("Logout request failed", {
          target: target.sid === session.systemDataSid ? "System Data" : "session",
          error: error.message
        });
      }
    }
  } finally {
    sessions.delete(sessionId);
  }
}

function changeTargetList(items = [], fallback = "the selected objects") {
  const names = (Array.isArray(items) ? items : [])
    .map((item) => item?.name || item?.NAME || item?.targetName || item?.uid || "")
    .filter(Boolean);
  return names.length ? names.join(", ") : fallback;
}

function auditedRouteInfo(route) {
  const routes = {
    "/api/scan": {
      action: "Scan Hardening Posture",
      command: "hardening-scan"
    },
    "/api/export-pdf": {
      action: "Exported PDF Report",
      command: "generate-report-pdf"
    },
    "/api/remediate/remove-any-trusted-client": {
      action: "Remediation Executed",
      command: "delete-trusted-client, publish"
    },
    "/api/remediate/remove-anyhost": {
      action: "Remediation Executed",
      command: "delete-trusted-client, publish"
    },
    "/api/remediate/delete-trusted-clients": {
      action: "Remediation Executed",
      command: "delete-trusted-client, publish"
    },
    "/api/remediate/add-trusted-client": {
      action: "Remediation Executed",
      command: "add-trusted-client, publish"
    },
    "/api/remediate/add-gaia-allowed-client": {
      action: "Remediation Executed",
      command: "run-script: add allowed-client"
    },
    "/api/remediate/delete-gaia-anyhost": {
      action: "Remediation Executed",
      command: "run-script: delete allowed-client host any-host"
    },
    "/api/remediate/delete-administrators": {
      action: "Remediation Executed",
      command: "delete-administrator, publish"
    },
    "/api/remediate/admin-expiration-four-months": {
      action: "Remediation Executed",
      command: "set-administrator, publish"
    },
    "/api/remediate/default-expiration-quarterly": {
      action: "Remediation Executed",
      command: "set-default-administrator-settings, publish"
    },
    "/api/remediate/minimum-password-length": {
      action: "Remediation Executed",
      command: "set-cp-password-requirements, publish"
    },
    "/api/remediate/smartconsole-idle-timeout": {
      action: "Remediation Executed",
      command: "set-smart-console-idle-timeout, publish"
    },
    "/api/remediate/api-clients-gui-clients": {
      action: "Remediation Executed",
      command: "set-api-settings, publish"
    },
    "/api/remediate/enable-log-implied-rules": {
      action: "Remediation Executed",
      command: "set-global-properties, publish"
    },
    "/api/remediate/enable-diagnostics-telemetry": {
      action: "Remediation Executed",
      command: "set-global-properties, publish"
    },
    "/api/remediate/enable-dynamic-updates": {
      action: "Remediation Executed",
      command: "set-global-properties, publish"
    },
    "/api/remediate/enable-syslog-forwarding": {
      action: "Remediation Executed",
      command: "run-script: set syslog cplogs on"
    },
    "/api/remediate/cve-global-ikev2-only": {
      action: "Remediation Executed",
      command: "set-global-properties, publish"
    },
    "/api/remediate/cve-disable-legacy-clients": {
      action: "Remediation Executed",
      command: "set-generic-object, publish"
    },
    "/api/remediate/cve-site-to-site-ikev2-only": {
      action: "Remediation Executed",
      command: "set-vpn-community-star/set-vpn-community-meshed, publish"
    }
  };
  return routes[route] || null;
}

async function handleApi(req, res) {
  return operationContext.run({ operation: null }, () => handleApiRequest(req, res));
}

async function handleApiRequest(req, res) {
  const requestId = randomUUID().slice(0, 8);
  let payload = {};
  let operationSession = null;
  let operation = null;
  try {
    if (req.url === "/api/health" && req.method === "GET") {
      log("Local API request", { requestId, route: "/api/health" });
      sendJson(res, 200, {
        requestId,
        ok: true,
        serverTime: new Date().toISOString(),
        listenUrl: `http://${HOST}:${PORT}`
      });
      return;
    }
    payload = await readBody(req);
    if (req.url === "/api/cancel-scan" && req.method === "POST") {
      const session = getSession(payload.sessionId);
      if (session.activeOperation?.kind === "scan") {
        session.activeOperation.cancelled = true;
        if (session.scanProgress) session.scanProgress.currentStep = "Cancelling: waiting for active requests to finish";
      }
      sendJson(res, 200, { requestId, ok: true });
      return;
    }
    const isOperation = req.method === "POST" && (
      ["/api/scan", "/api/check", "/api/logout"].includes(req.url) || req.url.startsWith("/api/remediate/")
    );
    if (isOperation) {
      operationSession = getSession(payload.sessionId);
      operation = beginOperation(operationSession, req.url === "/api/scan" ? "scan" : req.url === "/api/check" ? "check" : "change");
      operationContext.getStore().operation = operation;
      if (operation.kind === "check") {
        operationSession.scanCommandCache = new Map();
        operationSession.scanApiQueue = createLimiter(operationSession.largeEnvironmentMode ? LARGE_ENV_API_CONCURRENCY : STANDARD_API_CONCURRENCY);
      }
    }
    if (req.url === "/api/login" && req.method === "POST") {
      log("Local API request", { requestId, route: "/api/login" });
      sendJson(res, 200, { requestId, ...(await login(payload)) });
      return;
    }
    if (req.url === "/api/scan-progress" && req.method === "POST") {
      const session = getSession(payload.sessionId);
      sendJson(res, 200, {
        requestId,
        ok: true,
        progress: session.scanProgress || {
          active: false,
          complete: false,
          failed: false,
          percent: 0,
          completedSteps: 0,
          currentStep: "No scan running",
          steps: []
        }
      });
      return;
    }
    if (req.url === "/api/remediation-progress" && req.method === "POST") {
      const session = getSession(payload.sessionId);
      const progress = session.gaiaRemediationProgress;
      sendJson(res, 200, {
        requestId,
        ok: true,
        progress: progress && (!payload.operationId || progress.operationId === payload.operationId)
          ? progress
          : {
            active: false,
            complete: false,
            failed: false,
            currentCommand: "Waiting for Gaia command to start",
            steps: []
          }
      });
      return;
    }
    if (req.url === "/api/scan" && req.method === "POST") {
      log("Local API request", { requestId, route: "/api/scan" });
      const session = getSession(payload.sessionId);
      try {
        const result = session.moraMode ? await scanMoraHardening(session) : await scanHardening(session);
        assertNotCancelled(operation);
        sendJson(res, 200, { requestId, ...result });
      } catch (error) {
        if (session.scanProgress) {
          session.scanProgress = {
            ...session.scanProgress,
            active: false,
            complete: false,
            failed: error.code !== "SCAN_CANCELLED",
            cancelled: error.code === "SCAN_CANCELLED",
            percent: Math.max(session.scanProgress.percent || 0, 8),
            currentStep: error.message || "Scan failed",
            completedAt: new Date().toISOString()
          };
        }
        session.scanCommandCache = null;
        session.scanApiQueue = null;
        throw error;
      }
      return;
    }
    if (req.url === "/api/check" && req.method === "POST") {
      log("Local API request", { requestId, route: "/api/check", checkId: payload.checkId });
      const session = getSession(payload.sessionId);
      sendJson(res, 200, { requestId, ...(await refreshHardeningCheck(session, payload.checkId)) });
      return;
    }
    if ((req.url === "/api/remediate/remove-any-trusted-client" || req.url === "/api/remediate/remove-anyhost") && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await removeAnyTrustedClient(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "delete-trusted-client, publish",
        target: result.removed,
        details: `Removed trusted client ${result.removed}.`
      });
      recordCheckChange(session, payload.checkId || "mgmt.trusted-clients", `Last Change: ${auditUser(session)} removed trusted client ${result.removed}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/delete-trusted-clients" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await deleteTrustedClients(session, payload.uids);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "delete-trusted-client, publish",
        target: result.deleted.map((client) => client.name).join(", "),
        details: `Deleted ${result.deletedCount} trusted client${result.deletedCount === 1 ? "" : "s"}.`
      });
      recordCheckChange(session, payload.checkId || "mgmt.trusted-clients", `Last Change: ${auditUser(session)} deleted trusted client${result.deletedCount === 1 ? "" : "s"} ${changeTargetList(result.deleted, "from trusted clients")}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/add-trusted-client" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await addTrustedClient(session, payload);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "add-trusted-client, publish",
        target: result.added,
        details: `Added trusted client ${result.added} (${result.objectType}).`
      });
      recordCheckChange(session, payload.checkId || "mgmt.trusted-clients", `Last Change: ${auditUser(session)} added trusted client ${result.added}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/add-gaia-allowed-client" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await addGaiaAllowedClientForTargets(session, payload);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        status: result.failedCount ? "failed" : "success",
        command: result.changed.some((item) => item.retried)
          ? `run-script: lock database override, ${result.command}`
          : `run-script: ${result.command}`,
        target: result.targetNames.join(", "),
        details: `Added a Gaia allowed client on ${result.changedCount} selected target${result.changedCount === 1 ? "" : "s"}. ${result.failedCount} failed.`
      });
      recordCheckChange(session, payload.checkId || "gaia.allowed-host-access", `Last Change: ${auditUser(session)} added a Gaia allowed client on ${result.changedCount} selected target${result.changedCount === 1 ? "" : "s"}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/delete-gaia-anyhost" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await deleteGaiaAnyHostForTargets(session, payload);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        status: result.failedCount ? "failed" : "success",
        command: result.changed.some((item) => item.retried)
          ? "run-script: lock database override, delete allowed-client host any-host"
          : "run-script: delete allowed-client host any-host",
        target: result.targetNames.join(", "),
        details: `Deleted Gaia AnyHost on ${result.changedCount} selected target${result.changedCount === 1 ? "" : "s"}. ${result.failedCount} failed.`
      });
      recordCheckChange(session, payload.checkId || "gaia.allowed-host-access", `Last Change: ${auditUser(session)} deleted Gaia AnyHost on ${result.changedCount} selected target${result.changedCount === 1 ? "" : "s"}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/delete-administrators" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await deleteAdministrators(session, payload.uids);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "delete-administrator, publish",
        target: result.deleted.map((admin) => admin.name).join(", "),
        details: `Deleted ${result.deletedCount} administrator${result.deletedCount === 1 ? "" : "s"}.`
      });
      recordCheckChange(session, payload.checkId || "admin.accounts", `Last Change: ${auditUser(session)} deleted administrator account${result.deletedCount === 1 ? "" : "s"} ${changeTargetList(result.deleted, "from this section")}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/admin-expiration-four-months" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await setAdministratorExpirationFourMonths(session, payload.checkId, payload.uids);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-administrator, publish",
        target: result.changed.map((admin) => admin.name).join(", "),
        details: `Set ${result.changedCount} administrator expiration date${result.changedCount === 1 ? "" : "s"} to ${result.expirationDate}.`
      });
      recordCheckChange(session, payload.checkId || "admin.accounts", `Last Change: ${auditUser(session)} set a 4 month expiration date (${result.expirationDate}) for administrator account${result.changedCount === 1 ? "" : "s"} ${changeTargetList(result.changed, "selected in this section")}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/default-expiration-quarterly" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await setDefaultAdminExpirationQuarterly(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-default-administrator-settings, publish",
        target: "Default administrator expiration",
        details: `Set expiration to ${result.expirationPeriod} ${result.expirationPeriodTimeUnits}.`
      });
      recordCheckChange(session, payload.checkId || "admin.password-idle-lockout", `Last Change: ${auditUser(session)} set default administrator expiration to ${result.expirationPeriod} ${result.expirationPeriodTimeUnits}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/minimum-password-length" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await setMinimumPasswordLength(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-cp-password-requirements, publish",
        target: "Minimum password length",
        details: `Set minimum password length to ${result.minPasswordLength} characters.`
      });
      recordCheckChange(session, payload.checkId || "admin.password-idle-lockout", `Last Change: ${auditUser(session)} set minimum administrator password length to ${result.minPasswordLength} characters.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/smartconsole-idle-timeout" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await setSmartConsoleIdleTimeout(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-smart-console-idle-timeout, publish",
        target: "SmartConsole idle timeout",
        details: `Enabled timeout and set it to ${result.timeoutDuration} minutes.`
      });
      recordCheckChange(session, payload.checkId || "admin.password-idle-lockout", `Last Change: ${auditUser(session)} enabled SmartConsole idle timeout and set it to ${result.timeoutDuration} minutes.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/api-clients-gui-clients" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await setApiClientsToGuiClients(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-api-settings, publish",
        target: "Management API access",
        details: `Set accepted-api-calls-from to ${result.acceptedApiCallsFrom}.`
      });
      recordCheckChange(session, payload.checkId || "mgmt.api-access", `Last Change: ${auditUser(session)} set Management API access to ${result.acceptedApiCallsFrom}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/enable-log-implied-rules" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await enableLogImpliedRules(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-global-properties, publish",
        target: "firewall.log-implied-rules",
        details: "Set firewall log-implied-rules to true."
      });
      recordCheckChange(session, payload.checkId || "policy.implied-rules", `Last Change: ${auditUser(session)} enabled logging for implied rules.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/enable-diagnostics-telemetry" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await enableDiagnosticsTelemetry(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-global-properties, publish",
        target: "data-access-control.send-anonymous-info",
        details: "Set data-access-control send-anonymous-info to true."
      });
      recordCheckChange(session, payload.checkId || "updates.cpdiag", `Last Change: ${auditUser(session)} enabled diagnostics and telemetry sharing.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/enable-dynamic-updates" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await enableDynamicUpdates(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-global-properties, publish",
        target: "data-access-control.auto-download-important-data, data-access-control.auto-download-sw-updates-and-new-features",
        details: "Set Data Access Control AutoUpdater settings to true."
      });
      recordCheckChange(session, payload.checkId || "updates.dynamic-updates", `Last Change: ${auditUser(session)} enabled dynamic updates and AutoUpdater consent.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/enable-syslog-forwarding" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await enableGatewaySyslogForwardingForTargets(session, payload);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: result.changed.some((item) => item.retried)
          ? "run-script: lock database override, run-script: set syslog cplogs on"
          : "run-script: set syslog cplogs on",
        target: result.targetNames.join(", "),
        details: `Enabled Gaia OS syslog forwarding to Management Server on ${result.changedCount} selected target${result.changedCount === 1 ? "" : "s"}. ${result.failedCount} failed.`
      });
      recordCheckChange(session, payload.checkId || "gaia.system-logging-management", `Last Change: ${auditUser(session)} enabled Gaia OS syslog forwarding to the Management Server on ${result.changedCount} selected target${result.changedCount === 1 ? "" : "s"}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/cve-global-ikev2-only" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await remediateCveGlobalIkeV2Only(session);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-global-properties, publish",
        target: "remote-access.vpn-authentication-and-encryption.encryption-method",
        details: `Set global IKE encryption method to ${result.desiredMethod}.`
      });
      recordCheckChange(session, payload.checkId || "cve.ike-global-property", `Last Change: ${auditUser(session)} set the global Remote Access VPN IKE encryption method to ${result.desiredMethod}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/cve-disable-legacy-clients" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await remediateCveLegacyClients(session, payload.uids);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-generic-object, publish",
        target: result.changed.map((gateway) => gateway.name).join(", "),
        details: `Disabled legacy VPN clients on ${result.changedCount} gateway${result.changedCount === 1 ? "" : "s"}.`
      });
      recordCheckChange(session, payload.checkId || "cve.legacy-clients", `Last Change: ${auditUser(session)} disabled legacy VPN client support on ${changeTargetList(result.changed, "selected gateways")}.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/remediate/cve-site-to-site-ikev2-only" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const result = await remediateCveSiteToSiteCommunities(session, payload.uids);
      addAuditEntry({
        session,
        action: "Remediation Executed",
        command: "set-vpn-community-star/set-vpn-community-meshed, publish",
        target: result.changed.map((community) => community.name).join(", "),
        details: `Set ${result.changedCount} VPN communit${result.changedCount === 1 ? "y" : "ies"} to IKEv2 only.`
      });
      recordCheckChange(session, payload.checkId || "cve.site-to-site-communities", `Last Change: ${auditUser(session)} set VPN communit${result.changedCount === 1 ? "y" : "ies"} ${changeTargetList(result.changed, "selected communities")} to IKEv2 only.`);
      sendJson(res, 200, { requestId, ...result });
      return;
    }
    if (req.url === "/api/export-pdf" && req.method === "POST") {
      log("Local API request", { requestId, route: req.url });
      const session = getSession(payload.sessionId);
      const reportLayout = payload.reportLayout === "infrastructure" ? "infrastructure" : "category";
      const customerPrefix = customerReportPrefix(session.customerName);
      if (session.moraMode) {
        const archive = await generateMoraDomainReportsZip(session, reportLayout);
        res.writeHead(200, {
          "content-type": "application/zip",
          "content-disposition": `attachment; filename="${customerPrefix}all-domain-${reportLayout}-hardening-reports.zip"`,
          "content-length": archive.length
        });
        res.end(archive);
        return;
      }
      const result = await generateHardeningReportPdf(session, reportLayout);
      addAuditEntry({
        session,
        action: "Exported PDF Report",
        command: "generate-report-pdf",
        target: "Hardening Checks",
        details: `Generated ${reportLayout} hardening report with cover and intro PDF.`
      });
      res.writeHead(200, {
        "content-type": "application/pdf",
        "content-disposition": `attachment; filename="${singleReportFilename(session.lastHardeningScan, reportLayout)}"`,
        "content-length": result.file.length
      });
      res.end(result.file, () => {
        void result.cleanup();
      });
      return;
    }
    if (req.url === "/api/logout" && req.method === "POST") {
      log("Local API request", { requestId, route: "/api/logout" });
      await logout(payload.sessionId);
      sendJson(res, 200, { requestId, ok: true });
      return;
    }
    sendJson(res, 404, { requestId, error: "API route not found." });
  } catch (error) {
    const routeInfo = auditedRouteInfo(req.url);
    const session = sessions.get(payload?.sessionId);
    if (routeInfo && session) {
      addAuditEntry({
        session,
        action: routeInfo.action,
        status: "failed",
        command: error.command || routeInfo.command,
        target: payload?.checkId || "",
        details: error.message
      });
    }
    log("Local API request failed", {
      requestId,
      route: req.url,
      error: error.message,
      phase: error.phase,
      contentType: error.contentType,
      bodyPreview: error.bodyPreview
    });
    sendJson(res, error.httpStatus || 400, {
      requestId,
      error: error.message,
      sessionExpired: isExpiredSessionError(error),
      cancelled: error.code === "SCAN_CANCELLED",
      command: error.command,
      phase: error.phase,
      target: error.target,
      statusCode: error.statusCode,
      response: error.response,
      contentType: error.contentType,
      bodyPreview: error.bodyPreview
    });
  } finally {
    if (operation) {
      await finishOperation(operationSession, operation);
      operationSession.scanCommandCache = null;
      operationSession.scanApiQueue = null;
      operationSession.moraGlobalCommandCache = null;
      operationSession.moraAdminSourceGlobalInventory = null;
    }
  }
}

async function serveStatic(req, res) {
  const requestedPath = new URL(req.url, "http://localhost").pathname;
  const relativePath = requestedPath === "/" ? "index.html" : requestedPath.slice(1);
  const filePath = normalize(join(PUBLIC_DIR, relativePath));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  try {
    const file = await readFile(filePath);
    res.writeHead(200, {
      "content-type": contentTypes[extname(filePath)] || "application/octet-stream",
      "cache-control": "no-cache"
    });
    res.end(file);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
}

function handleRequest(req, res) {
  if (req.url.startsWith("/api/")) {
    void handleApi(req, res);
    return;
  }
  void serveStatic(req, res);
}

// Optional explicit interfaces share this process and its session state.
const listenHosts = [...new Set([HOST, ...(process.env.ADDITIONAL_HOSTS || "").split(",")]
  .map((host) => host.trim()).filter(Boolean))];
for (const host of listenHosts) {
  const server = createServer(handleRequest);
  server.listen(PORT, host, () => {
    log("Check Point Hardening App - Open Public Edition listening", { url: `http://${host}:${PORT}` });
  });
}
