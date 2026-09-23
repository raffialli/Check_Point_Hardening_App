import { existsSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { runCommand, runGit, cleanCommandError } from "./command-run.js";
import { readVersionInfo } from "./version-info.js";
import { LOCALHOST_ONLY_DETAIL } from "./localhost-gate.js";
import { DEPENDENCY_FILES, assertSafeGitName, isAncestor, isDirty, readBranch, readHead, remoteTrackingRef } from "./git-repo.js";

function updateError(message, httpStatus = 409) {
  return Object.assign(new Error(message), { httpStatus });
}

function defaultNodeModulesExists(root) {
  return existsSync(join(root, "node_modules"));
}

export async function defaultRunNpm(root) {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  return runCommand(npm, ["install"], { cwd: root, timeoutMs: 180000 });
}

// History-changing apply for the git source only.
// The localhost gate is consulted here and is not reimplemented.
export async function applyGitUpdate({
  root = process.cwd(),
  remote = "origin",
  branch = "main",
  gate,
  hasActiveSessions = () => false,
  run = runGit,
  runNpm = defaultRunNpm,
  nodeModulesExists = defaultNodeModulesExists
} = {}) {
  const safeRemote = assertSafeGitName(remote, "remote");
  const safeBranch = assertSafeGitName(branch, "branch");
  if (!gate?.allowed) {
    throw updateError(gate?.detail || LOCALHOST_ONLY_DETAIL, 403);
  }
  if (hasActiveSessions()) {
    throw updateError("Log out before updating. A restart clears in-memory sessions and any scan still running.", 409);
  }

  let localBranch;
  try {
    localBranch = await readBranch(run, root);
  } catch (error) {
    throw updateError(`This folder is not a git checkout, so it cannot be updated in place. ${cleanCommandError(error)}`, 409);
  }
  if (localBranch !== safeBranch) {
    throw updateError(`One-click update only fast-forwards ${safeBranch}. This checkout is on ${localBranch}. No files were changed.`, 409);
  }
  if (await isDirty(run, root)) {
    throw updateError("Working tree has local changes. Commit or stash them before updating. No files were changed.", 409);
  }

  const before = await readVersionInfo({ root, run });
  const ref = remoteTrackingRef(safeRemote, safeBranch);
  try {
    await run(
      ["fetch", safeRemote, `+refs/heads/${safeBranch}:refs/remotes/${safeRemote}/${safeBranch}`],
      { cwd: root, timeoutMs: 20000 }
    );
  } catch (error) {
    throw updateError(`Could not fetch ${ref}. No files were changed. ${cleanCommandError(error)}`, 502);
  }

  const localSha = before.fullSha || await readHead(run, root);
  const remoteSha = (await run(["rev-parse", ref], { cwd: root })).stdout.trim();
  if (!remoteSha || localSha === remoteSha) {
    throw updateError(`Already up to date with ${ref}. Nothing was pulled.`, 409);
  }
  if (!(await isAncestor(run, root, localSha, remoteSha))) {
    throw updateError("Update is not a fast-forward of the current checkout. Refusing to merge, rebase, or reset. No files were changed.", 409);
  }

  try {
    await run(["pull", "--ff-only", safeRemote, safeBranch], { cwd: root, timeoutMs: 20000 });
  } catch (error) {
    throw updateError(`Fast-forward pull failed. ${cleanCommandError(error)}`, 409);
  }

  const afterSha = await readHead(run, root);
  if (afterSha === localSha) {
    throw updateError("Pull finished without moving HEAD. Restart was not attempted.", 500);
  }

  const names = (await run(["diff", "--name-only", localSha, afterSha], { cwd: root })).stdout
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const dependencyChange = names.some((name) => DEPENDENCY_FILES.has(name));
  const missingModules = !(await nodeModulesExists(root));
  let installedDependencies = false;
  if (dependencyChange || missingModules) {
    try {
      await runNpm(root);
      installedDependencies = true;
    } catch (error) {
      throw updateError(
        `Pulled ${afterSha.slice(0, 7)} but npm install failed, so the server was not restarted. ${cleanCommandError(error)}`,
        500
      );
    }
  }

  const after = await readVersionInfo({ root, run });
  return {
    ok: true,
    previous: before,
    version: after.version,
    sha: after.sha,
    fullSha: after.fullSha,
    label: after.label,
    installedDependencies,
    message: `Updated to ${after.label}. Restarting the local server.`
  };
}

export function canApplyUpdate({ update, gate, hasActiveSessions = false } = {}) {
  if (!gate?.allowed) return { ok: false, reason: gate?.detail || LOCALHOST_ONLY_DETAIL };
  if (hasActiveSessions) return { ok: false, reason: "Log out before updating. A restart clears in-memory sessions and any scan still running." };
  if (update?.error) return { ok: false, reason: update.message || "Update check failed." };
  if (!update?.updateAvailable) return { ok: false, reason: update?.message || "No update is available." };
  if (update.dirty) return { ok: false, reason: "Working tree has local changes. Commit or stash them before updating." };
  if (!update.fastForward) return { ok: false, reason: update.message || "This update is not a fast-forward." };
  return { ok: true, reason: "" };
}

function probeHost(host) {
  if (!host || host === "0.0.0.0" || host === "::") return "127.0.0.1";
  return host;
}

// Detached helper waits until the current process releases the port, then starts server.js again.
export function scheduleProcessRestart({
  execPath = process.execPath,
  script,
  cwd,
  port,
  host,
  spawnImpl = spawn,
  env = process.env
} = {}) {
  const helper = `
import { spawn } from "node:child_process";
import net from "node:net";

const port = ${JSON.stringify(Number(port))};
const probeHost = ${JSON.stringify(probeHost(host))};
const cwd = ${JSON.stringify(cwd)};
const script = ${JSON.stringify(script)};
const execPath = ${JSON.stringify(execPath)};

function listening() {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host: probeHost });
    const done = (value) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(500);
    socket.on("connect", () => done(true));
    socket.on("timeout", () => done(true));
    socket.on("error", () => done(false));
  });
}

let free = false;
for (let attempt = 0; attempt < 75 && !free; attempt += 1) {
  free = !(await listening());
  if (!free) await new Promise((resolve) => setTimeout(resolve, 200));
}
if (!free) process.exit(1);
const child = spawn(execPath, [script], {
  cwd,
  env: process.env,
  detached: true,
  stdio: "ignore"
});
child.unref();
`;
  const child = spawnImpl(execPath, ["--input-type=module", "-e", helper], {
    cwd,
    env,
    detached: true,
    stdio: "ignore"
  });
  child.unref?.();
  return child;
}
