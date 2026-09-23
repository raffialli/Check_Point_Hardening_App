import { spawn } from "node:child_process";

export function scrubSecrets(text) {
  return String(text || "")
    .replace(/https?:\/\/(?:[^/\s@]+)@/gi, (match) => (match.toLowerCase().startsWith("http://") ? "http://" : "https://"))
    .replace(/x-access-token:[^\s@]+/gi, "x-access-token:[redacted]");
}

export function cleanCommandError(error) {
  const text = scrubSecrets(error?.stderr || error?.message || error);
  return text.replace(/\s+/g, " ").trim().slice(0, 500);
}

// Spawn without a shell. Callers pass argv arrays only.
export function runCommand(command, args, { cwd, env, allowFailure = false, timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", ...env },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      finish(reject, Object.assign(new Error(`${command} timed out after ${timeoutMs}ms.`), {
        code: null,
        stdout,
        stderr: scrubSecrets(stderr),
        timedOut: true
      }));
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (stdout.length > 1_000_000) stdout = stdout.slice(-1_000_000);
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      if (stderr.length > 200_000) stderr = stderr.slice(-200_000);
    });
    child.on("error", (error) => {
      const message = error?.code === "ENOENT"
        ? `${command} was not found on PATH.`
        : error.message;
      finish(reject, Object.assign(new Error(message), { code: error.code, stdout, stderr: scrubSecrets(stderr), cause: error }));
    });
    child.on("close", (code) => {
      const result = { code, stdout, stderr: scrubSecrets(stderr) };
      if (code === 0 || allowFailure) {
        finish(resolve, result);
        return;
      }
      finish(reject, Object.assign(
        new Error(scrubSecrets(stderr.trim() || stdout.trim() || `${command} ${args.join(" ")} failed (${code})`)),
        result
      ));
    });
  });
}

export function runGit(args, options) {
  return runCommand("git", args, options);
}
