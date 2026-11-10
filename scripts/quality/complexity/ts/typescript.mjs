// Loads the dashboard's pinned TypeScript parser and verifies it against
// web/dashboard/package-lock.json. The analyzer must never run with an
// unpinned or drifting parser version.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The analyzer normally lives inside the product repository; test copies in
// temp directories point back at the real checkout via this variable.
const DEFAULT_REPO_ROOT = fileURLToPath(new URL("../../../..", import.meta.url));

export function analyzerRepoRoot() {
  return process.env.TS_COMPLEXITY_REPO_ROOT || DEFAULT_REPO_ROOT;
}

export function loadTypescript() {
  const repoRoot = analyzerRepoRoot();
  const lockPath = join(repoRoot, "web/dashboard", "package-lock.json");
  let lockVersion;
  try {
    const lock = JSON.parse(readFileSync(lockPath, "utf8"));
    lockVersion = lock.packages?.["node_modules/typescript"]?.version;
  } catch (error) {
    throw new Error(`cannot read ${lockPath}: ${error.message}`);
  }
  if (!lockVersion) {
    throw new Error(`${lockPath} pins no node_modules/typescript version`);
  }
  const require = createRequire(import.meta.url);
  let ts;
  let installedVersion;
  try {
    const pkgDir = join(repoRoot, "web/dashboard/node_modules/typescript");
    ts = require(join(pkgDir, "lib", "typescript.js"));
    installedVersion = require(join(pkgDir, "package.json")).version;
  } catch (error) {
    throw new Error(
      `typescript not installed under web/dashboard/node_modules (${error.message}); ` +
      "run npm ci --prefix web/dashboard",
    );
  }
  if (installedVersion !== lockVersion) {
    throw new Error(
      `typescript version drift: installed ${installedVersion}, package-lock pins ${lockVersion}`,
    );
  }
  return {
    ts,
    parser: {
      name: "typescript",
      version: installedVersion,
      lockfile_version: lockVersion,
      pin_matches: true,
      lockfile: "web/dashboard/package-lock.json",
    },
  };
}
