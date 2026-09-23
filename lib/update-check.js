import { readVersionInfo } from "./version-info.js";
import { cleanCommandError, runGit } from "./command-run.js";
import { assertSafeGitName, isAncestor, isDirty, readBranch, readHead, remoteTrackingRef } from "./git-repo.js";

// An update source reports whether a newer revision exists.
// Git is the only built-in source. A later release API can implement
// `{ id, check({ root, run }) }` and be passed to checkForUpdate.
export function createGitUpdateSource({ remote = "origin", branch = "main" } = {}) {
  const safeRemote = assertSafeGitName(remote, "remote");
  const safeBranch = assertSafeGitName(branch, "branch");
  return {
    id: "git",
    remote: safeRemote,
    branch: safeBranch,
    async check({ root, run = runGit }) {
      return checkGitUpdate({ root, run, remote: safeRemote, branch: safeBranch });
    }
  };
}

export function resolveUpdateSource({ remote = "origin", branch = "main", sourceId = "git" } = {}) {
  if (sourceId === "git") return createGitUpdateSource({ remote, branch });
  throw Object.assign(
    new Error(`Update source "${sourceId}" is not available. Only the git source is implemented.`),
    { httpStatus: 501 }
  );
}

export async function checkForUpdate({ root = process.cwd(), run, source } = {}) {
  const checker = source || createGitUpdateSource();
  return checker.check({ root, run });
}

async function checkGitUpdate({ root, run, remote, branch }) {
  const localVersion = await readVersionInfo({ root, run });
  const ref = remoteTrackingRef(remote, branch);
  let localBranch = null;
  let dirty = false;
  try {
    localBranch = await readBranch(run, root);
    dirty = await isDirty(run, root);
  } catch (error) {
    return report({
      remote,
      branch,
      ref,
      local: { ...localVersion, branch: localBranch },
      dirty,
      message: `This folder is not a git checkout, so updates cannot be detected. ${cleanCommandError(error)}`,
      error: cleanCommandError(error)
    });
  }

  try {
    await run(
      ["fetch", remote, `+refs/heads/${branch}:refs/remotes/${remote}/${branch}`],
      { cwd: root, timeoutMs: 12000 }
    );
  } catch (error) {
    return report({
      remote,
      branch,
      ref,
      local: { ...localVersion, branch: localBranch },
      dirty,
      message: `Could not reach ${ref}. ${cleanCommandError(error)}`,
      error: cleanCommandError(error)
    });
  }

  let remoteSha;
  try {
    remoteSha = (await run(["rev-parse", ref], { cwd: root })).stdout.trim();
  } catch (error) {
    return report({
      remote,
      branch,
      ref,
      local: { ...localVersion, branch: localBranch },
      dirty,
      message: `${ref} is not available after fetch. ${cleanCommandError(error)}`,
      error: cleanCommandError(error)
    });
  }

  const localSha = localVersion.fullSha || await readHead(run, root);
  let remoteVersion = null;
  try {
    const shown = await run(["show", `${ref}:package.json`], { cwd: root });
    remoteVersion = String(JSON.parse(shown.stdout).version || "") || null;
  } catch {
    remoteVersion = null;
  }
  const remoteShort = remoteSha.slice(0, 7);
  const remoteInfo = {
    version: remoteVersion,
    sha: remoteShort,
    fullSha: remoteSha,
    ref,
    label: remoteVersion ? `${remoteVersion} (${remoteShort})` : remoteShort
  };
  const equal = localSha === remoteSha;
  const behind = !equal && await isAncestor(run, root, localSha, remoteSha);
  const ahead = !equal && !behind && await isAncestor(run, root, remoteSha, localSha);
  const onBranch = localBranch === branch;
  const fastForward = behind && onBranch;
  let message;
  if (equal) message = `Up to date with ${ref}.`;
  else if (behind && !onBranch) message = `${localVersion.label} is behind ${ref} at ${remoteInfo.label}, but this checkout is on ${localBranch}. One-click update only fast-forwards ${branch}.`;
  else if (behind && dirty) message = `Update available: ${localVersion.label} → ${remoteInfo.label}. Local changes must be committed or stashed first.`;
  else if (behind) message = `Update available: ${localVersion.label} → ${remoteInfo.label}.`;
  else if (ahead) message = `${localVersion.label} is ahead of ${ref}. One-click update will not rewind it.`;
  else message = `${localVersion.label} and ${ref} (${remoteInfo.label}) have diverged. One-click update will not merge or reset.`;

  return report({
    remote,
    branch,
    ref,
    local: { ...localVersion, branch: localBranch },
    remoteInfo,
    dirty,
    updateAvailable: behind,
    fastForward,
    message
  });
}

function report({ branch, ref, local, remoteInfo = null, dirty = false, updateAvailable = false, fastForward = false, message, error = null }) {
  return {
    source: "git",
    branch,
    ref,
    updateAvailable,
    fastForward,
    dirty,
    local,
    remote: remoteInfo,
    message,
    error,
    checkedAt: new Date().toISOString()
  };
}
