import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scrubSecrets } from "../lib/command-run.js";
import { runGit } from "../lib/command-run.js";
import { assessLocalhostGate, LOCALHOST_ONLY_DETAIL } from "../lib/localhost-gate.js";
import { readVersionInfo } from "../lib/version-info.js";
import { checkForUpdate, resolveUpdateSource } from "../lib/update-check.js";
import { applyGitUpdate, canApplyUpdate, scheduleProcessRestart } from "../lib/apply-update.js";
import { assertSafeGitName } from "../lib/git-repo.js";

const gitEnv = {
  GIT_AUTHOR_NAME: "Release Test",
  GIT_AUTHOR_EMAIL: "release@example.com",
  GIT_COMMITTER_NAME: "Release Test",
  GIT_COMMITTER_EMAIL: "release@example.com"
};
const allowedGate = { allowed: true, detail: LOCALHOST_ONLY_DETAIL };

function git(cwd, args) {
  return runGit(args, { cwd, env: gitEnv, timeoutMs: 20000 });
}

async function head(cwd) {
  return (await git(cwd, ["rev-parse", "HEAD"])).stdout.trim();
}

async function makePair(version = "1.0.0") {
  const dir = await mkdtemp(join(tmpdir(), "cph-update-"));
  const origin = join(dir, "origin");
  const local = join(dir, "local");
  await mkdir(origin);
  await git(origin, ["init", "-b", "main"]);
  await writeFile(join(origin, "package.json"), `${JSON.stringify({ version })}\n`);
  await writeFile(join(origin, "README.md"), "v1\n");
  await git(origin, ["add", "package.json", "README.md"]);
  await git(origin, ["commit", "-m", "v1"]);
  await git(dir, ["clone", origin, "local"]);
  return {
    dir,
    origin,
    local,
    cleanup: () => rm(dir, { recursive: true, force: true })
  };
}

async function commit(cwd, message, files) {
  for (const [name, contents] of Object.entries(files)) {
    await writeFile(join(cwd, name), contents);
  }
  await git(cwd, ["add", ...Object.keys(files)]);
  await git(cwd, ["commit", "-m", message]);
}

test("localhost gate allows loopback clients and blocks everyone else", () => {
  assert.equal(assessLocalhostGate({ hostHeader: "127.0.0.1:3000", remoteAddress: "127.0.0.1" }).allowed, true);
  assert.equal(assessLocalhostGate({ hostHeader: "localhost:3000", remoteAddress: "::1" }).allowed, true);
  assert.equal(assessLocalhostGate({ hostHeader: "[::1]:3000", remoteAddress: "::ffff:127.0.0.1" }).allowed, true);
  assert.equal(assessLocalhostGate({ hostHeader: "127.0.0.2:3000", remoteAddress: "127.0.0.1" }).allowed, true);
  const remote = assessLocalhostGate({ hostHeader: "localhost", remoteAddress: "192.168.1.20" });
  assert.equal(remote.allowed, false);
  assert.equal(remote.detail, LOCALHOST_ONLY_DETAIL);
  assert.equal(assessLocalhostGate({ hostHeader: "mgmt.example.com", remoteAddress: "127.0.0.1" }).allowed, false);
  assert.equal(assessLocalhostGate({ hostHeader: "127.0.0.1:3000", remoteAddress: "::ffff:10.1.1.5" }).allowed, false);
  assert.equal(assessLocalhostGate({ hostHeader: "", remoteAddress: "127.0.0.1" }).allowed, false);
  assert.equal(assessLocalhostGate({ hostHeader: "127.0.0.1", remoteAddress: "" }).allowed, false);
});

test("version label uses package.json and a short sha", async () => {
  const pair = await makePair("2.0.0");
  try {
    const info = await readVersionInfo({ root: pair.local });
    const full = await head(pair.local);
    assert.equal(info.version, "2.0.0");
    assert.equal(info.fullSha, full);
    assert.equal(info.sha, full.slice(0, 7));
    assert.equal(info.label, `2.0.0 (${info.sha})`);
  } finally {
    await pair.cleanup();
  }
});

test("update check reports behind, equal, and a failed fetch without throwing", async () => {
  const pair = await makePair();
  try {
    const same = await checkForUpdate({ root: pair.local });
    assert.equal(same.updateAvailable, false);
    assert.match(same.message, /Up to date/);
    await commit(pair.origin, "v2", { "README.md": "v2\n", "package.json": '{"version":"1.1.0"}\n' });
    const behind = await checkForUpdate({ root: pair.local });
    assert.equal(behind.updateAvailable, true);
    assert.equal(behind.fastForward, true);
    assert.equal(behind.remote.version, "1.1.0");
    assert.match(behind.message, /Update available/);
    const eligibility = canApplyUpdate({ update: behind, gate: allowedGate });
    assert.equal(eligibility.ok, true);
  } finally {
    await pair.cleanup();
  }

  const root = await mkdtemp(join(tmpdir(), "cph-version-"));
  try {
    await writeFile(join(root, "package.json"), '{"version":"9.9.9"}\n');
    const calls = [];
    const run = async (args) => {
      calls.push(args[0]);
      if (args[0] === "rev-parse" && args[1] === "HEAD") return { code: 0, stdout: "abc1234abc1234abc1234abc1234abc1234abc\n", stderr: "" };
      if (args[0] === "rev-parse") return { code: 0, stdout: "main\n", stderr: "" };
      if (args[0] === "status") return { code: 0, stdout: "", stderr: "" };
      throw Object.assign(new Error("fatal: https://x-access-token:secret@github.com/example/repo.git not found"), { stderr: "https://user:secret@github.com/example/repo.git" });
    };
    const failed = await checkForUpdate({ root, run, source: resolveUpdateSource() });
    assert.equal(failed.updateAvailable, false);
    assert.equal(failed.local.version, "9.9.9");
    assert.match(failed.message, /Could not reach origin\/main/);
    assert.equal(JSON.stringify(failed).includes("secret"), false);
    assert.equal(calls.filter((name) => name === "pull").length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("apply refuses a closed gate, active sessions, a dirty tree, and a non-fast-forward", async () => {
  const untouched = async () => {
    throw new Error("git should not run");
  };
  await assert.rejects(
    () => applyGitUpdate({ gate: { allowed: false, detail: LOCALHOST_ONLY_DETAIL }, run: untouched }),
    (error) => error.httpStatus === 403 && error.message === LOCALHOST_ONLY_DETAIL
  );
  await assert.rejects(
    () => applyGitUpdate({ gate: allowedGate, hasActiveSessions: () => true, run: untouched }),
    /Log out before updating/
  );

  const dirty = await makePair();
  try {
    const before = await head(dirty.local);
    await writeFile(join(dirty.local, "notes.txt"), "local edit\n");
    await assert.rejects(
      () => applyGitUpdate({ root: dirty.local, gate: allowedGate, nodeModulesExists: () => true, runNpm: async () => { throw new Error("npm should not run"); } }),
      /local changes/
    );
    assert.equal(await head(dirty.local), before);
  } finally {
    await dirty.cleanup();
  }

  const diverged = await makePair();
  try {
    await commit(diverged.local, "local", { "README.md": "local\n" });
    await commit(diverged.origin, "remote", { "README.md": "remote\n" });
    const before = await head(diverged.local);
    await assert.rejects(
      () => applyGitUpdate({ root: diverged.local, gate: allowedGate, nodeModulesExists: () => true, runNpm: async () => { throw new Error("npm should not run"); } }),
      /not a fast-forward/
    );
    assert.equal(await head(diverged.local), before);
    const status = await git(diverged.local, ["status", "--porcelain"]);
    assert.equal(status.stdout.trim(), "");
  } finally {
    await diverged.cleanup();
  }
});

test("fast-forward pull installs dependencies only when needed and refuses another branch", async () => {
  const updated = await makePair();
  try {
    await commit(updated.origin, "v1.2.0", { "package.json": '{"version":"1.2.0"}\n' });
    const npmCalls = [];
    const result = await applyGitUpdate({
      root: updated.local,
      gate: allowedGate,
      nodeModulesExists: () => true,
      runNpm: async () => { npmCalls.push("install"); }
    });
    assert.deepEqual(npmCalls, ["install"]);
    assert.equal(result.installedDependencies, true);
    assert.equal(result.version, "1.2.0");
    assert.match(result.message, /Restarting/);
    const pkg = JSON.parse(await readFile(join(updated.local, "package.json"), "utf8"));
    assert.equal(pkg.version, "1.2.0");
    const pulls = await git(updated.local, ["log", "-1", "--format=%s"]);
    assert.match(pulls.stdout, /v1\.2\.0/);
  } finally {
    await updated.cleanup();
  }

  const docsOnly = await makePair();
  try {
    await commit(docsOnly.origin, "docs", { "README.md": "v2\n" });
    let npmCalls = 0;
    const skipped = await applyGitUpdate({
      root: docsOnly.local,
      gate: allowedGate,
      nodeModulesExists: () => true,
      runNpm: async () => { npmCalls += 1; }
    });
    assert.equal(npmCalls, 0);
    assert.equal(skipped.installedDependencies, false);
    npmCalls = 0;
    await commit(docsOnly.origin, "docs again", { "README.md": "v3\n" });
    await applyGitUpdate({
      root: docsOnly.local,
      gate: allowedGate,
      nodeModulesExists: () => false,
      runNpm: async () => { npmCalls += 1; }
    });
    assert.equal(npmCalls, 1);
  } finally {
    await docsOnly.cleanup();
  }

  const other = await makePair();
  try {
    await git(other.local, ["checkout", "-b", "feature"]);
    await commit(other.origin, "main move", { "README.md": "moved\n" });
    const before = await head(other.local);
    await assert.rejects(
      () => applyGitUpdate({ root: other.local, gate: allowedGate, nodeModulesExists: () => true, runNpm: async () => { throw new Error("npm should not run"); } }),
      /only fast-forwards main/
    );
    assert.equal(await head(other.local), before);
  } finally {
    await other.cleanup();
  }
});

test("restart helper starts a replacement process when the port is free", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cph-restart-"));
  const marker = join(dir, "started.txt");
  const script = join(dir, "child.mjs");
  await writeFile(script, `import { writeFile } from "node:fs/promises";\nawait writeFile(${JSON.stringify(marker)}, "ok\\n");\n`);
  try {
    scheduleProcessRestart({ script, cwd: dir, port: 39991, host: "127.0.0.1" });
    let seen = "";
    for (let attempt = 0; attempt < 40 && !seen; attempt += 1) {
      try {
        seen = await readFile(marker, "utf8");
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    assert.equal(seen, "ok\n");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("restart helper is detached and does not run during a refused update", () => {
  let unref = 0;
  const child = scheduleProcessRestart({
    script: "/tmp/server.js",
    cwd: "/tmp/app",
    port: 3000,
    host: "127.0.0.1",
    spawnImpl: (command, args, options) => {
      assert.equal(command, process.execPath);
      assert.equal(args[0], "--input-type=module");
      assert.match(args[2], /\/tmp\/server\.js/);
      assert.match(args[2], /3000/);
      assert.equal(options.detached, true);
      assert.equal(options.stdio, "ignore");
      return { unref() { unref += 1; } };
    }
  });
  assert.equal(unref, 1);
  assert.equal(typeof child.unref, "function");
  assert.throws(() => assertSafeGitName("origin;rm", "remote"), /Unsupported git remote/);
  assert.equal(scrubSecrets("fetch https://x-access-token:secret@github.com/a/b").includes("secret"), false);
});

test("unknown update sources fail before any apply path exists", () => {
  assert.throws(() => resolveUpdateSource({ sourceId: "release-api" }), /not available/);
  const blocked = canApplyUpdate({
    update: { updateAvailable: true, fastForward: true, dirty: false, message: "Update available." },
    gate: { allowed: false, detail: LOCALHOST_ONLY_DETAIL }
  });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.reason, LOCALHOST_ONLY_DETAIL);
});
