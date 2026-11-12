// Fixture runner for the TS/JS complexity differential analyzer.
//
// Builds throwaway git repositories from ts_fixtures/ (base and head
// states) and runs scripts/quality/complexity/ts/analyze.mjs against them:
//
//   * the main fixture repo pins changed-function controls C1-C13 (metric
//     paths, body-hash stability under reformat-only edits, rename/move
//     recognition, untouched debt, byte-determinism);
//   * the receipt fixture repo pins review-band receipt enforcement: C8
//     (a valid stronger-model receipt clears the 11-15 band) and R1-R15
//     (every invalid-receipt class is rejected with its precise error —
//     including the schema/2 negatives legacy schema/1, stale body hash,
//     wrong gate-config digest and malformed binding — and a missing
//     receipt blocks with NEEDS REVIEW);
//   * the rename fixture repo pins duplicate and rename handling: C14
//     (a byte-identical copy of a surviving original is measured and
//     blocks), C15 (the --debt-out ledger lists untouched and moved debt
//     untruncated), C16 (function-expression/default-export renames stay
//     moves) and C17 (an unreadable changed file exits 2 naming the file);
//   * the wiring repos (W1-W14) drive the live _quality-ts-complexity
//     recipe extracted from the product Makefile through make, with a
//     committed analyzer copy and the parser pin kept on the real
//     checkout via TS_COMPLEXITY_REPO_ROOT.
//
// Receipts are minted with real body hashes taken from the scenarios' own
// gate reports and the analyzer's gateConfigDigest(), mirroring the Go
// suite's report_body_sha256 helper.
//
// Each guarded control is re-checked against a deliberately mutated copy of
// the analyzer (single exact-string replacement, target uniqueness
// asserted) so every guarded control is proven to fail on its intended
// assertion. Exit 0 only if all 58 rows pass (46 analyzer and wiring
// controls, 12 detected mutants).
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ANALYZER_DIR = join(HERE, "..", "..", "complexity", "ts");
const FIXTURES = join(HERE, "ts_fixtures");
const PRODUCT_ROOT = fileURLToPath(new URL("../../../..", import.meta.url));
const BLOCKING_LINE = "web/dashboard/src/pages/MegaList.tsx: MegaList (cognitive complexity 16 > 15)";
const DUPLICATE_LINE = "web/dashboard/src/lib/dup.ts: heavyCopy (cognitive complexity 16 > 15)";
const BAND_FILE = "web/dashboard/src/lib/band.ts";
const BAND_BINDING = `${BAND_FILE}:borderlineTwelve`;
const MODEL_ORDER = ["--model-order", "impl-lite,impl-strong"];
const RECEIPT_SCHEMA = "ts-complexity-review-receipt/2";
const LEGACY_RECEIPT_SCHEMA = "ts-complexity-review-receipt/1";
const HEX64_ZERO = "0".repeat(64);

// Importing the analyzer runs no analysis (analyze.mjs guards direct
// invocation), so the runner mints receipts with the gate's own digest.
const { gateConfigDigest } = await import(pathToFileURL(join(ANALYZER_DIR, "analyze.mjs")).href);

// Review-band body hash minted from the receipt scenario's own report so
// schema/2 receipts bind the exact measured body.
let bandBodySha256 = "";

function bodyShaOf(report, file, name) {
  return report.changed_functions.find((entry) => entry.file === file && entry.name === name)?.body_sha256 ?? "";
}

function runGit(repo, ...args) {
  try {
    execFileSync("git", ["-C", repo, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    throw new Error(`git -C ${repo} ${args.join(" ")} failed: ${error.stderr?.toString() ?? error.message}`);
  }
}

function initRepo(target) {
  runGit(target, "init", "-q");
  runGit(target, "config", "user.email", "fixtures@local.test");
  runGit(target, "config", "user.name", "fixture runner");
  runGit(target, "config", "commit.gpgsign", "false");
}

function buildFixtureRepo(target, scenario) {
  const root = join(FIXTURES, scenario);
  cpSync(join(root, "base"), target, { recursive: true });
  initRepo(target);
  commitAll(target, "fixture base");
  cpSync(join(root, "head"), target, { recursive: true });
  commitAll(target, "fixture head");
  const sha = (ref) => execFileSync("git", ["-C", target, "rev-parse", ref]).toString("utf8").trim();
  return { repo: target, base: sha("HEAD~1"), head: sha("HEAD") };
}

function commitAll(repo, message) {
  runGit(repo, "add", "-A");
  runGit(repo, "commit", "-qm", message);
}

function runAnalyzer(analyzerDir, scenario, extraArgs = []) {
  const result = spawnSync(
    "node",
    [join(analyzerDir, "analyze.mjs"), "--repo", scenario.repo, "--base", scenario.base, ...extraArgs],
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
      // Debt is legacyDeep (block) plus the body-hash-stable reformat
      // body from C13, which is measured at head but never "changed".
      return Boolean(debt.functions_total === 2 && debt.block === 1 && top
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
  {
    id: "C9", label: "switch counts each case clause and nests inside clauses",
    check: (report) => {
      // 4 case clauses at switch nesting (4 x 2) + if inside a clause (2).
      const entry = findEntry(report, "routePlan");
      return Boolean(entry && entry.status === "added" && entry.kind === "function"
        && entry.new_complexity === 10 && entry.classification === "ok");
    },
  },
  {
    id: "C10", label: "catch clause counted and nested body scored deeper",
    check: (report) => {
      // if in try (+1) + catch clause (+1) + if at catch nesting (+2).
      const entry = findEntry(report, "guardedParse");
      return Boolean(entry && entry.status === "added" && entry.new_complexity === 4
        && entry.classification === "ok");
    },
  },
  {
    id: "C11", label: "class getter/setter/method bodies measured separately",
    check: (report) => {
      const getter = findEntry(report, "ScoreKeeper::value");
      const setter = findEntry(report, "ScoreKeeper::value#2");
      const method = findEntry(report, "ScoreKeeper::bump");
      return Boolean(getter && getter.kind === "getter" && getter.status === "added"
        && getter.new_complexity === 1
        && setter && setter.kind === "setter" && setter.status === "added"
        && setter.new_complexity === 3
        && method && method.kind === "method" && method.status === "added"
        && method.new_complexity === 3);
    },
  },
  {
    id: "C12", label: "async function and async arrow bodies measured",
    check: (report) => {
      const fn = findEntry(report, "fetchScore");
      const arrow = findEntry(report, "asyncLabel");
      return Boolean(fn && fn.kind === "function" && fn.status === "added"
        && fn.new_complexity === 4
        && arrow && arrow.kind === "arrow" && arrow.status === "added"
        && arrow.new_complexity === 3);
    },
  },
  {
    id: "C13", label: "reformat-only body keeps body hash, no changed entry",
    check: (report) => {
      // reformat.ts must be in the diff (7 changed in-scope files across the
      // fixture set) yet stableReformat yields no changed_functions entry —
      // it is only measured as untouched debt, at its base complexity.
      const changed = findEntry(report, "stableReformat");
      const debt = report.untouched_debt.top.find((entry) => entry.name === "stableReformat");
      return Boolean(changed === null && debt && debt.complexity === 2
        && report.run.files_changed_in_scope === 7
        && report.failures.every((line) => line.includes("MegaList")));
    },
  },
];

// A rejected receipt must exit 1, mark itself invalid, count its errors and
// name the exact failed check.
function receiptRejected(report, run, fragment) {
  return Boolean(run.code === 1
    && report.receipt && report.receipt.valid === false
    && report.summary.receipt_errors >= 1
    && report.receipt.errors.some((error) => error.includes(fragment)));
}

const RECEIPT_CASES = [
  { id: "R1", label: "receipt bound to another source commit is rejected", fragment: "does not match analyzed head", fields: { source_commit: "USE_BASE" } },
  { id: "R2", label: "receipt bound to another base commit is rejected", fragment: "does not match analyzed base", fields: { base_commit: "USE_HEAD" } },
  { id: "R3", label: "reviewer equal to implementer is rejected", fragment: "equals implementer_model", fields: { reviewer_model: "impl-lite" } },
  { id: "R4", label: "weaker reviewer than implementer is rejected", fragment: "is not stronger than implementer_model", fields: { implementer_model: "impl-strong", reviewer_model: "impl-lite" } },
  { id: "R5", label: "stale receipt (older than 30 days) is rejected", fragment: "is stale (older than 30 days)", fields: { reviewed_at: "2020-01-01T00:00:00Z" } },
  { id: "R6", label: "receipt not binding the review-band function is rejected", fragment: "does not bind review-band function", fields: { bindings: [{ function: "web/dashboard/src/lib/quiet.ts:quietHelper", body_sha256: "1".repeat(64) }] } },
  { id: "R7", label: "reject verdict does not approve the change", fragment: "does not approve the reviewed change", fields: { verdict: "reject" } },
  { id: "R8", label: "unknown verdict value is rejected", fragment: "is not one of: approve, reject, require_refactoring", fields: { verdict: "maybe" } },
  { id: "R9", label: "malformed receipt JSON is rejected", fragment: "cannot be parsed as JSON", raw: "{" },
  { id: "R10", label: "missing receipt file is rejected", fragment: "receipt file cannot be read", path: "does-not-exist.json" },
  { id: "R12", label: "legacy schema/1 receipt is rejected", fragment: "is not supported (expected ts-complexity-review-receipt/2)", raw: (scenario) => JSON.stringify({
    schema: LEGACY_RECEIPT_SCHEMA,
    source_commit: scenario.head,
    base_commit: scenario.base,
    implementer_model: "impl-lite",
    reviewer_model: "impl-strong",
    verdict: "approve",
    reviewed_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    functions: [BAND_BINDING],
  }) },
  { id: "R13", label: "stale body hash binding is rejected", fragment: "does not match the current function body", fields: { bindings: [{ function: BAND_BINDING, body_sha256: HEX64_ZERO }] } },
  { id: "R14", label: "wrong gate-config digest is rejected", fragment: "does not match the active gate configuration", fields: { gate_config_sha256: HEX64_ZERO } },
  { id: "R15", label: "malformed binding object is rejected", fragment: "must have exactly function and body_sha256", fields: { bindings: [{ function: BAND_BINDING }] } },
];

function receiptControls(receiptScenario) {
  const controls = [
    {
      id: "C8", label: "valid stronger-model receipt clears the review band",
      check: (report, run) => {
        const entry = findEntry(report, "borderlineTwelve");
        return Boolean(run.code === 0 && report.receipt && report.receipt.valid === true
          && report.summary.review === 1 && report.summary.review_unreceipted === 0
          && report.summary.receipt_errors === 0
          && entry && entry.classification === "review" && entry.review === "receipt-recorded");
      },
    },
  ];
  for (const receiptCase of RECEIPT_CASES) {
    controls.push({
      id: receiptCase.id,
      label: receiptCase.label,
      check: (report, run) => receiptRejected(report, run, receiptCase.fragment),
    });
  }
  controls.push({
    id: "R11", label: "review band without receipt blocks with NEEDS REVIEW",
    check: (report, run) => Boolean(run.code === 1 && report.receipt === null
      && report.failures.length === 0 && report.summary.review_unreceipted === 1
      && findEntry(report, "borderlineTwelve")?.review === "required"
      && run.stderr.includes(`NEEDS REVIEW RECEIPT ${BAND_FILE}: borderlineTwelve (cognitive complexity 12 in 11-15)`)),
  });
  return controls;
}

function renameControls(ledger) {
  return [
    {
      id: "C14", label: "duplicate copy of a surviving original blocks as added",
      check: (report, run) => {
        const copy = findEntry(report, "heavyCopy");
        return Boolean(run.code === 1 && report.failures.length === 1
          && report.failures[0] === DUPLICATE_LINE
          && copy && copy.status === "added" && copy.classification === "block"
          && copy.new_complexity === 16
          && copy.duplicate_of && copy.duplicate_of.name === "heavyOriginal"
          && copy.duplicate_of.file === "web/dashboard/src/lib/dup.ts"
          && findEntry(report, "heavyOriginal") === null
          && report.changed_functions.every((entry) => entry.name !== "legacyHeavyRenamed" || entry.classification !== "block"));
      },
    },
    {
      id: "C15", label: "--debt-out ledger lists untouched and moved debt untruncated",
      check: () => {
        const gt15 = ledger.functions_gt15;
        return Boolean(ledger.schema === "ts-complexity-debt/1"
          && ledger.summary.untouched_functions === 1
          && ledger.summary.untouched_gt15 === 1 && ledger.summary.untouched_11_to_15 === 0
          && ledger.summary.moved_gt15 === 1 && ledger.summary.moved_11_to_15 === 0
          && ledger.summary.functions_gt15 === 2 && ledger.summary.functions_11_to_15 === 0
          && gt15.length === 2
          && gt15[0].file === "web/dashboard/src/lib/dup.ts" && gt15[0].function === "heavyOriginal"
          && gt15[0].kind === "untouched" && gt15[0].complexity === 16 && gt15[0].function_kind === "function"
          && gt15[1].file === "web/dashboard/src/lib/legacy2.ts" && gt15[1].function === "legacyHeavyRenamed"
          && gt15[1].kind === "moved" && gt15[1].complexity === 25 && gt15[1].function_kind === "function"
          && ledger.functions_11_to_15.length === 0);
      },
    },
    {
      id: "C16", label: "function-expression and default-export renames stay moves",
      check: (report) => {
        const expr = findEntry(report, "exprTargetMoved");
        const def = findEntry(report, "renamedDefault");
        return Boolean(expr && expr.status === "moved" && expr.kind === "function-expression"
          && expr.moved_from && expr.moved_from.name === "exprTarget"
          && expr.moved_from.file === "web/dashboard/src/lib/exprs.ts" && expr.delta === 0
          && def && def.status === "moved" && def.kind === "arrow"
          && def.moved_from && def.moved_from.name === "defaultTarget"
          && def.moved_from.file === "web/dashboard/src/lib/exprs.ts"
          && report.summary.added === 1 && report.summary.moved === 3);
      },
    },
    {
      id: "C17", label: "unreadable changed file exits 2 naming the file",
      check: () => eaccessSurfaces(),
    },
  ];
}

const BASE_MUTATIONS = [
  { id: "M1a", file: "analyze.mjs", find: "const OK_LIMIT = 10;", replace: "const OK_LIMIT = 5;", control: "C1" },
  { id: "M1b", file: "analyze.mjs", find: "const BLOCK_LIMIT = 15;", replace: "const BLOCK_LIMIT = 1e9;", control: "C2" },
  { id: "M3", file: "analyze.mjs", find: "const movedFrom = bodyPool.get(record.body_sha256)?.shift() || null;", replace: "const movedFrom = null;", control: "C3" },
  { id: "M4", file: "analyze.mjs", find: "deleted: deletedCount,", replace: "deleted: 0,", control: "C4" },
  { id: "M5", file: "analyze.mjs", find: "untouchedDebt.push({ file, name: record.name, complexity: record.complexity, kind: record.kind });", replace: ";", control: "C5" },
  { id: "M6", file: "collect.mjs", find: "ts.forEachChild(node, (child) => visit(child, childScope));", replace: "if (!kind) ts.forEachChild(node, (child) => visit(child, childScope));", control: "C6" },
  {
    id: "M-switch", file: "metric.mjs",
    find: "if (ts.isCaseClause(clause)) increment();",
    replace: ";",
    control: "C9",
  },
  {
    id: "M-catch", file: "metric.mjs",
    find: "[ts.isCatchClause, (n) => {\n      increment();\n      inNested(n.variableDeclaration);",
    replace: "[ts.isCatchClause, (n) => {\n      inNested(n.variableDeclaration);",
    control: "C10",
  },
  {
    id: "M-class", file: "collect.mjs",
    find: "if (kind && node.body) {",
    replace: "if (kind && node.body && !ts.isClassLike(node.parent)) {",
    control: "C11",
  },
  {
    id: "M-async", file: "collect.mjs",
    find: "functions.push({",
    replace: "if (node.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword)) return own;\n    functions.push({",
    control: "C12",
  },
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

function isDeterministic(first, second) {
  return second.stdout === first.stdout && second.code === first.code;
}

function parseReport(run, label) {
  // A tool error (exit 2) leaves no report to assert on; surface the
  // analyzer's own diagnostic instead of crashing on JSON.parse("").
  if (run.code !== 0 && run.code !== 1) {
    throw new Error(`${label}: analyzer exited ${run.code} without a report\n${run.stderr}`.trim());
  }
  if (!run.stdout.trim()) {
    throw new Error(`${label}: analyzer exited ${run.code} with empty stdout\n${run.stderr}`.trim());
  }
  try {
    return JSON.parse(run.stdout);
  } catch (error) {
    throw new Error(`${label}: analyzer stdout is not valid JSON (${error.message})`);
  }
}

function runMutation(mutation, scenarios, work) {
  const control = ALL_CONTROLS.get(mutation.control);
  const scenario = scenarios[mutation.repo ?? "main"];
  const mutantDir = join(work, `mutant-${mutation.id}`);
  cpSync(ANALYZER_DIR, mutantDir, { recursive: true });
  const guardError = applyMutation(ANALYZER_DIR, mutantDir, mutation);
  if (guardError) {
    return { label: `guard: ${guardError}`, detected: false, failed: true };
  }
  const mutantRun = runAnalyzer(mutantDir, scenario, mutation.args ?? []);
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

// C17: an unreadable changed file is a tool error, not a silent skip. The
// fixture repo is disposable; permissions are always restored.
let MAIN_SCENARIO = null;
function eaccessSurfaces() {
  const target = join(MAIN_SCENARIO.repo, "web/dashboard/src/pages/MegaList.tsx");
  chmodSync(target, 0o000);
  let run;
  try {
    run = runAnalyzer(ANALYZER_DIR, MAIN_SCENARIO);
  } finally {
    chmodSync(target, 0o644);
  }
  return Boolean(run.code === 2
    && run.stderr.includes("cannot read web/dashboard/src/pages/MegaList.tsx")
    && run.stderr.includes("EACCES"));
}

function writeReceipt(receiptDir, name, scenario, overrides = {}) {
  const path = join(receiptDir, name);
  const raw = typeof overrides.raw === "function" ? overrides.raw(scenario) : overrides.raw;
  if (raw !== undefined) {
    writeFileSync(path, raw);
    return path;
  }
  const fields = Object.fromEntries(
    Object.entries(overrides.fields ?? {}).map(([key, value]) => [
      key,
      value === "USE_BASE" ? scenario.base : value === "USE_HEAD" ? scenario.head : value,
    ]),
  );
  const document = {
    schema: RECEIPT_SCHEMA,
    source_commit: scenario.head,
    base_commit: scenario.base,
    implementer_model: "impl-lite",
    reviewer_model: "impl-strong",
    verdict: "approve",
    reviewed_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    gate_config_sha256: gateConfigDigest(),
    bindings: [{ function: BAND_BINDING, body_sha256: bandBodySha256 }],
    ...fields,
  };
  writeFileSync(path, `${JSON.stringify(document, null, 2)}\n`);
  return path;
}

// QG-C02-03 gate wiring: the live _quality-ts-complexity recipe is pulled
// from the product Makefile and driven through make in fixture repos that
// carry a committed copy of the analyzer package (committed at base so the
// copy never enters the measured diff). TS_COMPLEXITY_REPO_ROOT keeps the
// pinned parser on the real checkout while the analyzed tree stays the
// fixture repo.

function extractGateRecipe() {
  const lines = readFileSync(join(PRODUCT_ROOT, "Makefile"), "utf8").split("\n");
  const start = lines.findIndex((line) => line === "_quality-ts-complexity:");
  if (start === -1) return "";
  const block = [];
  for (let index = start; index < lines.length && lines[index] !== ""; index += 1) block.push(lines[index]);
  return `${block.join("\n")}\n`;
}

const GATE_RECIPE = extractGateRecipe();

function buildGateRepo(work, name, baseScenario, headScenario, copies, writes) {
  const repo = join(work, `${name}-repo`);
  cpSync(join(FIXTURES, baseScenario, "base"), repo, { recursive: true });
  mkdirSync(join(repo, "scripts/quality/complexity"), { recursive: true });
  cpSync(ANALYZER_DIR, join(repo, "scripts/quality/complexity", "ts"), { recursive: true });
  writeFileSync(join(repo, "gate.mk"), GATE_RECIPE);
  initRepo(repo);
  commitAll(repo, "gate base");
  if (headScenario !== null) cpSync(join(FIXTURES, headScenario, "head"), repo, { recursive: true });
  for (const [source, destination] of copies) cpSync(source, join(repo, destination));
  for (const [path, text] of writes) writeFileSync(join(repo, path), text);
  commitAll(repo, "gate head");
  const sha = (ref) => execFileSync("git", ["-C", repo, "rev-parse", ref]).toString("utf8").trim();
  return { repo, base: sha("HEAD~1"), head: sha("HEAD") };
}

function runGate(scenario, receiptPath) {
  const env = { ...process.env, QUALITY_BASE: scenario.base, TS_COMPLEXITY_REPO_ROOT: PRODUCT_ROOT };
  if (receiptPath) env.TS_COMPLEXITY_RECEIPT = receiptPath;
  const result = spawnSync(
    "make", ["-C", scenario.repo, "-f", "gate.mk", "_quality-ts-complexity"],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env },
  );
  const out = `${result.stdout ?? ""}${result.stderr ?? ""}${result.error ? result.error.message : ""}`;
  return { code: result.status, out };
}

function runWiringScenario(rows, work) {
  let failures = 0;
  const gateCase = (id, label, run, wantZero, fragments, forbidden = []) => {
    let ok = wantZero ? run.code === 0 : run.code !== 0;
    for (const fragment of fragments) if (!run.out.includes(fragment)) ok = false;
    for (const fragment of forbidden) if (run.out.includes(fragment)) ok = false;
    failures += record(rows, id, label, ok);
  };

  const recipeOk = GATE_RECIPE.includes("analyze.mjs") && GATE_RECIPE.includes("--base");
  failures += record(rows, "W1", "gate recipe extracted from product Makefile", recipeOk);
  if (!recipeOk) {
    failures += record(rows, "W2-W14", "wiring controls skipped (no recipe)", false);
    return failures;
  }

  const quiet = join(FIXTURES, "receipt", "base", "web/dashboard/src/lib/quiet.ts");
  const blockRepo = buildGateRepo(work, "gateblock", "", "", [], []);
  const bandRepo = buildGateRepo(work, "gateband", "receipt", "receipt", [], []);
  const debtRepo = buildGateRepo(work, "gatedebt", "", null, [[quiet, "web/dashboard/src/lib/quiet.ts"]], []);
  const docsRepo = buildGateRepo(work, "gatedocs", "receipt", null, [], [["NOTE.md", "documentation-only change\n"]]);

  // Receipts for the wiring repos bind the exact bodies those repos
  // measure; hashes are minted from each repo's own scan.
  const blockScan = parseReport(runAnalyzer(ANALYZER_DIR, blockRepo), "gate block scan");
  const bandScan = parseReport(runAnalyzer(ANALYZER_DIR, bandRepo), "gate band scan");
  const megaBody = bodyShaOf(blockScan, "web/dashboard/src/pages/MegaList.tsx", "MegaList");
  const detailedBody = bodyShaOf(blockScan, "web/dashboard/src/App.tsx", "borderlineDetailed");
  const gateBandBody = bodyShaOf(bandScan, BAND_FILE, "borderlineTwelve");
  if (!megaBody || !detailedBody || !gateBandBody) {
    throw new Error("gate-wiring scans are missing a body hash needed for receipt minting");
  }

  const receiptDir = join(work, "gate-receipts");
  mkdirSync(receiptDir, { recursive: true });
  const sameModel = writeReceipt(receiptDir, "gate-same-model.json", blockRepo, {
    fields: {
      reviewer_model: "impl-lite",
      bindings: [
        { function: "web/dashboard/src/pages/MegaList.tsx:MegaList", body_sha256: megaBody },
        { function: "web/dashboard/src/App.tsx:borderlineDetailed", body_sha256: detailedBody },
      ],
    },
  });
  const tampered = writeReceipt(receiptDir, "gate-tampered.json", bandRepo, {
    fields: { source_commit: "USE_BASE", bindings: [{ function: BAND_BINDING, body_sha256: gateBandBody }] },
  });
  const valid = writeReceipt(receiptDir, "gate-valid.json", bandRepo, {
    fields: { bindings: [{ function: BAND_BINDING, body_sha256: gateBandBody }] },
  });

  gateCase("W2", "over-15 change through make blocks without receipt", runGate(blockRepo), false,
    [`BLOCK ${BLOCKING_LINE}`]);
  gateCase("W3", "same-model receipt over >15 change still blocks", runGate(blockRepo, sameModel), false,
    [`BLOCK ${BLOCKING_LINE}`, "equals implementer_model"]);
  gateCase("W4", "review band without receipt fails through make", runGate(bandRepo), false,
    [`NEEDS REVIEW RECEIPT ${BAND_FILE}: borderlineTwelve (cognitive complexity 12 in 11-15)`]);
  gateCase("W5", "receipt bound to another commit is rejected", runGate(bandRepo, tampered), false,
    ["does not match analyzed head"]);
  gateCase("W6", "valid receipt passes via TS_COMPLEXITY_RECEIPT", runGate(bandRepo, valid), true,
    ["review band 11-15: 1"], ["BLOCK ", "NEEDS REVIEW", "RECEIPT INVALID"]);
  gateCase("W7", "untouched debt passes with changed ok body", runGate(debtRepo), true,
    ["untouched debt: 1 functions above 10 (0 review, 1 block)", "changed functions: 1 (1 added, 0 changed, 0 moved)"]);
  gateCase("W8", "docs-only diff measures zero bodies", runGate(docsRepo), true,
    ["changed functions: 0 (0 added, 0 changed, 0 moved)"]);
  return failures;
}

const ROUTING_CHECKS = String.raw`
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "scripts/quality"))
spec = importlib.util.spec_from_file_location("quality", Path(sys.argv[1]) / "scripts/quality/quality.py")
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)
checks = [
    ("ts-diff-selects-gate", "ts-complexity" in quality.classify(["web/dashboard/src/lib/format.ts"])),
    ("dashboard-gate-kept", "dashboard" in quality.classify(["web/dashboard/src/lib/format.ts"])),
    ("manifests-exclude-gate",
     "ts-complexity" not in quality.classify(["web/dashboard/package.json", "web/dashboard/package-lock.json"])),
    ("out-of-scope-trees-exclude-gate",
     "ts-complexity" not in quality.classify(["web/site/src/app.js", "e2e/home.spec.ts"])),
    ("full-profile-contains-gate", "ts-complexity" in quality.expand(["full"])),
    ("docs-diff-excludes-gate", "ts-complexity" not in quality.classify(["README.md"])),
]
for name, ok in checks:
    print(("PASS" if ok else "FAIL") + " " + name)
sys.exit(0 if all(ok for _, ok in checks) else 1)
`;

function runRoutingScenario(rows) {
  const result = spawnSync("python3", ["-c", ROUTING_CHECKS, PRODUCT_ROOT], { encoding: "utf8" });
  const lines = `${result.stdout ?? ""}`.trim().split("\n").filter((line) => line);
  let failures = 0;
  let index = 9;
  if (!lines.length) {
    return record(rows, "W9-W14", `routing checks produced no output (${result.stderr ?? result.error?.message})`, false);
  }
  for (const line of lines) {
    const ok = line.startsWith("PASS ");
    failures += record(rows, `W${index}`, `routing ${line.slice(5) || "unknown"}`, ok);
    index += 1;
  }
  return failures;
}

function main() {
  const work = mkdtempSync(join(tmpdir(), "ts-complexity-fixtures-"));
  let failures = 0;
  const rows = [];
  let fatal = null;
  const scenarios = {};
  try {
    scenarios.main = buildFixtureRepo(join(work, "main-repo"), "");
    scenarios.rename = buildFixtureRepo(join(work, "rename-repo"), "rename");
    scenarios.receipt = buildFixtureRepo(join(work, "receipt-repo"), "receipt");
    MAIN_SCENARIO = scenarios.main;

    const first = runAnalyzer(ANALYZER_DIR, scenarios.main);
    const report = parseReport(first, "analyzer run");
    const second = runAnalyzer(ANALYZER_DIR, scenarios.main);
    for (const control of CONTROLS) {
      const outcome = evaluateControl(control, report, first);
      failures += record(rows, control.id, control.label, outcome.ok);
    }
    failures += record(rows, "C7", "two consecutive runs are byte-identical", isDeterministic(first, second));

    // Mint the review-band body hash from the receipt scenario's own
    // report before any receipt is written, so every receipt binds the
    // exact body the analyzer measures.
    const plainRun = runAnalyzer(ANALYZER_DIR, scenarios.receipt);
    const plainReport = parseReport(plainRun, "no-receipt run");
    bandBodySha256 = bodyShaOf(plainReport, BAND_FILE, "borderlineTwelve");
    if (!bandBodySha256) {
      throw new Error("receipt scenario report carries no body hash for the review-band function");
    }

    const receiptDir = join(work, "receipts");
    mkdirSync(receiptDir, { recursive: true });
    const validPath = writeReceipt(receiptDir, "valid.json", scenarios.receipt, {});
    const receiptPaths = new Map();
    for (const receiptCase of RECEIPT_CASES) {
      receiptPaths.set(receiptCase.id, receiptCase.path
        ? join(receiptDir, receiptCase.path)
        : writeReceipt(receiptDir, `${receiptCase.id.toLowerCase()}.json`, scenarios.receipt, receiptCase));
    }

    const receiptControlsForRun = receiptControls(scenarios.receipt);
    const validRun = runAnalyzer(ANALYZER_DIR, scenarios.receipt, ["--receipt", validPath, ...MODEL_ORDER]);
    const validOutcome = evaluateControl(receiptControlsForRun[0], parseReport(validRun, "valid receipt run"), validRun);
    failures += record(rows, "C8", receiptControlsForRun[0].label, validOutcome.ok);

    const r11 = receiptControlsForRun[receiptControlsForRun.length - 1];
    const plainOutcome = evaluateControl(r11, plainReport, plainRun);
    failures += record(rows, "R11", r11.label, plainOutcome.ok);

    for (let index = 0; index < RECEIPT_CASES.length; index += 1) {
      const receiptCase = RECEIPT_CASES[index];
      const control = receiptControlsForRun[index + 1];
      const run = runAnalyzer(ANALYZER_DIR, scenarios.receipt, ["--receipt", receiptPaths.get(receiptCase.id), ...MODEL_ORDER]);
      const outcome = evaluateControl(control, parseReport(run, `${receiptCase.id} run`), run);
      failures += record(rows, control.id, control.label, outcome.ok);
    }

    const renameRun = runAnalyzer(ANALYZER_DIR, scenarios.rename);
    const renameReport = parseReport(renameRun, "rename run");
    const debtPath = join(work, "rename-debt.json");
    runAnalyzer(ANALYZER_DIR, scenarios.rename, ["--debt-out", debtPath]);
    const ledger = JSON.parse(readFileSync(debtPath, "utf8"));
    for (const control of renameControls(ledger)) {
      const outcome = evaluateControl(control, renameReport, renameRun);
      failures += record(rows, control.id, control.label, outcome.ok);
    }

    failures += runWiringScenario(rows, work);
    failures += runRoutingScenario(rows);

    const mutations = [
      ...BASE_MUTATIONS,
      {
        id: "M-receipt", file: "analyze.mjs",
        find: "const valid = errors.length === 0;",
        replace: "const valid = true;",
        control: "R1", repo: "receipt",
        args: ["--receipt", receiptPaths.get("R1"), ...MODEL_ORDER],
      },
      {
        id: "M-dup", file: "analyze.mjs",
        find: 'status: "added", moved_from: null, duplicate_of: duplicateOf,',
        replace: 'status: duplicateOf ? "moved" : "added", moved_from: duplicateOf, duplicate_of: null,',
        control: "C14", repo: "rename",
      },
    ];
    for (const mutation of mutations) {
      const outcome = runMutation(mutation, scenarios, work);
      rows.push([mutation.id, outcome.label, outcome.detected ? "DETECTED" : "MISSED"]);
      if (!outcome.detected) failures += 1;
    }
  } catch (error) {
    fatal = error;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  if (fatal) {
    process.stderr.write(`ts fixture runner: ${fatal.message}\n`);
    process.exit(1);
  }
  emit(rows, failures);
  process.exit(failures > 0 ? 1 : 0);
}

const ALL_CONTROLS = new Map();
for (const control of [...CONTROLS, ...receiptControls(null), ...renameControls(null)]) {
  ALL_CONTROLS.set(control.id, control);
}

main();
