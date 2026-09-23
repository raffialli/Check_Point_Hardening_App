import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { runGit } from "./command-run.js";

async function readPackageVersion(root) {
  const raw = await readFile(join(root, "package.json"), "utf8");
  const version = JSON.parse(raw).version;
  if (!version) throw new Error("package.json has no version.");
  return String(version);
}

// Local package version plus the short git SHA. Git is optional so a
// packaged copy can still show the version from package.json.
export async function readVersionInfo({ root = process.cwd(), run = runGit, readPackage = readPackageVersion } = {}) {
  let version = "unknown";
  try {
    version = await readPackage(root);
  } catch {
    version = "unknown";
  }
  let fullSha = null;
  try {
    fullSha = (await run(["rev-parse", "HEAD"], { cwd: root })).stdout.trim() || null;
  } catch {
    fullSha = null;
  }
  const sha = fullSha ? fullSha.slice(0, 7) : null;
  return {
    version,
    sha,
    fullSha,
    label: sha ? `${version} (${sha})` : version
  };
}
