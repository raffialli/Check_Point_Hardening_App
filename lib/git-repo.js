// Shared git facts for the update check and the apply step.
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._/-]*$/;

export const DEPENDENCY_FILES = new Set(["package.json", "package-lock.json", "npm-shrinkwrap.json"]);

export function assertSafeGitName(value, label) {
  const name = String(value || "");
  const pattern = label === "remote" ? /^[A-Za-z0-9][A-Za-z0-9._-]*$/ : SAFE_NAME;
  if (!pattern.test(name) || name.includes("..") || name.endsWith("/") || name.endsWith(".") || name.includes("//") || name.includes("@")) {
    throw Object.assign(new Error(`Unsupported git ${label}.`), { httpStatus: 400 });
  }
  return name;
}

export async function readHead(run, root) {
  return (await run(["rev-parse", "HEAD"], { cwd: root })).stdout.trim();
}

export async function readBranch(run, root) {
  return (await run(["rev-parse", "--abbrev-ref", "HEAD"], { cwd: root })).stdout.trim();
}

export async function isDirty(run, root) {
  return Boolean((await run(["status", "--porcelain"], { cwd: root })).stdout.trim());
}

export async function isAncestor(run, root, ancestor, descendant) {
  const result = await run(["merge-base", "--is-ancestor", ancestor, descendant], { cwd: root, allowFailure: true });
  return result.code === 0;
}

export function remoteTrackingRef(remote, branch) {
  return `${assertSafeGitName(remote, "remote")}/${assertSafeGitName(branch, "branch")}`;
}
