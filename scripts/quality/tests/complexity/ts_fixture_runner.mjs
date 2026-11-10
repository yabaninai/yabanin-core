// Fixture runner for the TS/JS complexity differential analyzer.
//
// Builds a throwaway git repository from ts_fixtures/ (base and head
// states), runs scripts/quality/complexity/ts/analyze.mjs against it and
// asserts exit codes plus report contents for the six required control
// classes. Each control is then re-checked against a deliberately mutated
// copy of the analyzer (single exact-string replacement, target uniqueness
// asserted) so every control is proven to fail on its intended assertion.
// Also checks byte-determinism of two consecutive runs and minimal
// --receipt recording. Exit 0 only if all controls pass on the real
// analyzer and fail on their mutants.
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ANALYZER_DIR = join(HERE, "..", "..", "complexity", "ts");
const FIXTURES = join(HERE, "ts_fixtures");
const PRODUCT_ROOT = fileURLToPath(new URL("../../../..", import.meta.url));
const BLOCKING_LINE = "web/dashboard/src/pages/MegaList.tsx: MegaList (cognitive complexity 16 > 15)";

function runGit(repo, ...args) {
  execFileSync("git", ["-C", repo, ...args], { stdio: ["ignore", "pipe", "pipe"] });
}

function buildFixtureRepo(target) {
  cpSync(join(FIXTURES, "base"), target, { recursive: true });
  runGit(target, "init", "-q");
  runGit(target, "config", "user.email", "fixtures@local.test");
  runGit(target, "config", "user.name", "fixture runner");
  runGit(target, "config", "commit.gpgsign", "false");
  runGit(target, "add", "-A");
  runGit(target, "commit", "-qm", "fixture base");
  cpSync(join(FIXTURES, "head"), target, { recursive: true });
  runGit(target, "add", "-A");
  runGit(target, "commit", "-qm", "fixture head");
  return execFileSync("git", ["-C", target, "rev-parse", "HEAD~1"]).toString("utf8").trim();
}

function runAnalyzer(analyzerDir, repo, baseSha, extraArgs = []) {
  const result = spawnSync(
    "node",
    [join(analyzerDir, "analyze.mjs"), "--repo", repo, "--base", baseSha, ...extraArgs],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env: { ...process.env, TS_COMPLEXITY_REPO_ROOT: PRODUCT_ROOT } },
  );
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

function findEntry(report, name, file) {
  return report.changed_functions.find((entry) => entry.name === name && (!file || entry.file === file)) || null;
}

const CONTROLS = [
  {
    id: "C1", label: "changed body complexity 8 passes as ok",
    check: (report) => {
      const entry = findEntry(report, "changedStraightforward");
      return Boolean(entry && entry.status === "changed" && entry.old_complexity === 8
        && entry.new_complexity === 8 && entry.classification === "ok");
    },
  },
  {
    id: "C2", label: "arrow component >15 fails run naming the function",
    check: (report, run) => {
      const entry = findEntry(report, "MegaList");
      return Boolean(run.code === 1 && report.failures.length === 1
        && report.failures[0] === BLOCKING_LINE && entry && entry.new_complexity === 16
        && entry.classification === "block" && entry.kind === "arrow" && entry.role === "component");
    },
  },
  {
    id: "C3", label: "identical-body rename/move recognized, not re-flagged",
    check: (report) => {
      const renamed = findEntry(report, "renamedBody");
      const ported = findEntry(report, "portedAway");
      return Boolean(renamed && renamed.status === "moved" && renamed.moved_from
        && renamed.moved_from.name === "legacyBody" && renamed.delta === 0
        && ported && ported.status === "moved" && ported.moved_from
        && ported.moved_from.file === "web/dashboard/src/lib/helpers.ts"
        && report.failures.every((line) => line.includes("MegaList")));
    },
  },
  {
    id: "C4", label: "deleted function produces no report entry, only a count",
    check: (report) => {
      const leaked = report.changed_functions.some((entry) => entry.name.includes("deletedHelper"));
      return Boolean(report.summary.deleted === 1 && !leaked);
    },
  },
  {
    id: "C5", label: "untouched legacy 25 is debt summary only, never a failure",
    check: (report) => {
      const debt = report.untouched_debt;
      const top = debt.top[0];
      return Boolean(debt.functions_total === 1 && debt.block === 1 && top
        && top.name === "legacyDeep" && top.complexity === 25
        && report.failures.every((line) => line.includes("MegaList")));
    },
  },
  {
    id: "C6", label: "nested closure measured as its own body",
    check: (report) => {
      const closure = findEntry(report, "withNestedClosure::scale");
      const outer = findEntry(report, "withNestedClosure");
      return Boolean(closure && closure.status === "added" && closure.kind === "arrow"
        && closure.new_complexity === 4 && outer && outer.status === "changed"
        && outer.old_complexity === 2 && outer.new_complexity === 0);
    },
  },
];

const MUTATIONS = [
  { id: "M1a", file: "analyze.mjs", find: "const OK_LIMIT = 10;", replace: "const OK_LIMIT = 5;", control: "C1" },
  { id: "M1b", file: "analyze.mjs", find: "const BLOCK_LIMIT = 15;", replace: "const BLOCK_LIMIT = 1e9;", control: "C2" },
  { id: "M3", file: "analyze.mjs", find: "const movedFrom = bodyPool.get(record.fingerprint)?.shift() || null;", replace: "const movedFrom = null;", control: "C3" },
  { id: "M4", file: "analyze.mjs", find: "deleted: deletedCount,", replace: "deleted: 0,", control: "C4" },
  { id: "M5", file: "analyze.mjs", find: "untouchedDebt.push({ file, name: record.name, complexity: record.complexity, kind: record.kind });", replace: ";", control: "C5" },
  { id: "M6", file: "collect.mjs", find: "ts.forEachChild(node, (child) => visit(child, childScope));", replace: "if (!kind) ts.forEachChild(node, (child) => visit(child, childScope));", control: "C6" },
];

function applyMutation(sourceDir, targetDir, mutation) {
  const path = join(targetDir, mutation.file);
  const source = readFileSync(join(sourceDir, mutation.file), "utf8");
  const occurrences = source.split(mutation.find).length - 1;
  if (occurrences !== 1) {
    return `mutation target appears ${occurrences}x (expected 1): ${mutation.find}`;
  }
  writeFileSync(path, source.replace(mutation.find, mutation.replace));
  return null;
}

function evaluateControl(control, report, run) {
  try {
    return { ok: control.check(report, run), error: null };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function record(rows, id, label, ok) {
  const verdict = ok ? "PASS" : "FAIL";
  rows.push([id, label, verdict]);
  return ok ? 0 : 1;
}

function evaluateControls(rows, report, first) {
  let failures = 0;
  for (const control of CONTROLS) {
    const outcome = evaluateControl(control, report, first);
    failures += record(rows, control.id, control.label, outcome.ok);
  }
  return failures;
}

function isDeterministic(first, second) {
  return second.stdout === first.stdout && second.code === first.code;
}

function receiptRecorded(receiptReport, receiptRun, plainReport) {
  const borderline = findEntry(receiptReport, "borderlineDetailed");
  const plain = findEntry(plainReport, "borderlineDetailed");
  return receiptReport.receipt === "QG-C02-02-placeholder"
    && receiptRun.code === 1
    && Boolean(borderline && borderline.classification === "review")
    && borderline.review === "receipt-recorded"
    && Boolean(plain && plain.review === "required");
}

function runMutation(mutation, repo, baseSha, work) {
  const control = CONTROLS.find((entry) => entry.id === mutation.control);
  const mutantDir = join(work, `mutant-${mutation.id}`);
  cpSync(ANALYZER_DIR, mutantDir, { recursive: true });
  const guardError = applyMutation(ANALYZER_DIR, mutantDir, mutation);
  if (guardError) {
    return { label: `guard: ${guardError}`, detected: false, failed: true };
  }
  const mutantRun = runAnalyzer(mutantDir, repo, baseSha);
  // Only a completed run counts: a crashed mutant (exit 2) must not
  // masquerade as an intended-assertion failure.
  if (mutantRun.code !== 0 && mutantRun.code !== 1) {
    return { label: `mutant crashed (exit ${mutantRun.code}), not a valid detection`, detected: false, failed: true };
  }
  const outcome = evaluateControl(control, JSON.parse(mutantRun.stdout), mutantRun);
  return { label: `mutant must break ${mutation.control} (exit ${mutantRun.code})`, detected: !outcome.ok, failed: false };
}

function emit(rows, failures) {
  process.stderr.write(`ts fixture runner | analyzer ${ANALYZER_DIR}\n`);
  for (const [id, label, verdict] of rows) {
    process.stderr.write(`${id.padEnd(4)} ${label}: ${verdict}\n`);
  }
  process.stderr.write(`ts fixture runner: ${rows.length - failures}/${rows.length} checks passed\n`);
}

function main() {
  const work = mkdtempSync(join(tmpdir(), "ts-complexity-fixtures-"));
  const repo = join(work, "repo");
  let failures = 0;
  const rows = [];
  try {
    const baseSha = buildFixtureRepo(repo);
    const first = runAnalyzer(ANALYZER_DIR, repo, baseSha);
    const report = JSON.parse(first.stdout);
    const second = runAnalyzer(ANALYZER_DIR, repo, baseSha);
    const receiptRun = runAnalyzer(ANALYZER_DIR, repo, baseSha, ["--receipt", "QG-C02-02-placeholder"]);
    const receiptReport = JSON.parse(receiptRun.stdout);

    failures += evaluateControls(rows, report, first);
    failures += record(rows, "C7", "two consecutive runs are byte-identical", isDeterministic(first, second));
    failures += record(rows, "C8", "--receipt recorded and reflected on review-band entries",
      receiptRecorded(receiptReport, receiptRun, report));

    for (const mutation of MUTATIONS) {
      const outcome = runMutation(mutation, repo, baseSha, work);
      rows.push([mutation.id, outcome.label, outcome.detected ? "DETECTED" : "MISSED"]);
      if (!outcome.detected) failures += 1;
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  emit(rows, failures);
  process.exit(failures > 0 ? 1 : 0);
}

main();
