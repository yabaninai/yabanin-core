// Differential TypeScript/JavaScript function-body complexity analyzer.
//
// Given a base revision and the current working tree, measures every
// added/changed/moved function body under the configured scopes and reports
// untouched legacy debt separately, including debt carried by renamed or
// relocated bodies (a rename never resets debt). Review-band bodies (11-15)
// require a valid stronger-model review receipt (see README.md for the
// receipt schema shared with the Go gate). Metric rules, report schema and
// known limits are documented in README.md next to this file.
//
// Exit codes: 0 = no blocking finding; 1 = a changed body exceeds
// BLOCK_LIMIT, the review band lacks a valid receipt, or a provided receipt
// is invalid (each named on stderr); 2 = tool error (bad base, missing
// merge base, parser failure, TypeScript pin drift, unreadable source).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadTypescript } from "./typescript.mjs";
import { isMeasuredFile, parseAndCollect } from "./collect.mjs";
import { classifyComplexity } from "./metric.mjs";

const ANALYZER = {
  name: "ts-complexity-diff",
  version: "1.1.0",
  metric: "cognitive-complexity/sonar-style",
  rules: "scripts/quality/complexity/ts/README.md#metric-rules",
};
const OK_LIMIT = 10;
const REVIEW_LIMIT = 15;
const BLOCK_LIMIT = 15;
const DEFAULT_SCOPE = "web/dashboard/";
const DEBT_SCHEMA = "ts-complexity-debt/1";
const RECEIPT_SCHEMA = "ts-complexity-review-receipt/1";
const RECEIPT_VERDICTS = ["approve", "reject", "require_refactoring"];
// 30 days mirrors the maximum bounded-exception expiry in
// standards/maintainability.md; 24h tolerates reviewer/client clock skew.
const RECEIPT_MAX_AGE_DAYS = 30;
const RECEIPT_FUTURE_TOLERANCE_MS = 24 * 60 * 60 * 1000;
const VALUE_FLAGS = {
  "--repo": "repo",
  "--base": "base",
  "--receipt": "receipt",
  "--json-out": "jsonOut",
  "--debt-out": "debtOut",
  "--model-order": "modelOrder",
};

class UsageError extends Error {}

function gitText(repo, ...args) {
  return execFileSync("git", ["-C", repo, ...args], { maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }).toString("utf8");
}

function gitNull(repo, ...args) {
  return execFileSync("git", ["-C", repo, ...args], { maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
}

function zList(raw) {
  return raw.toString("utf8").split("\0").filter((entry) => entry.length > 0);
}

function parseArgs(argv) {
  const options = { scopes: [], repo: null, base: null, receipt: null, jsonOut: null, debtOut: null, modelOrder: null, quiet: false };
  const next = (index) => {
    const value = argv[index + 1];
    if (value === undefined) throw new UsageError(`missing value for ${argv[index]}`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--scope") options.scopes.push(next(index++));
    else if (arg === "--quiet") options.quiet = true;
    else if (VALUE_FLAGS[arg]) options[VALUE_FLAGS[arg]] = next(index++);
    else throw new UsageError(`unknown argument: ${arg}`);
  }
  return options;
}

function resolveRevision(repo, base) {
  const head = gitText(repo, "rev-parse", "HEAD").trim();
  if (!base) return { head, revision: head, baseRef: null, baseCommit: null };
  let baseCommit;
  try {
    baseCommit = gitText(repo, "rev-parse", "--verify", "--end-of-options", `${base}^{commit}`).trim();
  } catch (error) {
    const detail = error.stderr ? error.stderr.toString("utf8").trim() : error.message;
    throw new Error(`cannot resolve base ref ${base}: ${detail}`);
  }
  const mergeBase = gitText(repo, "merge-base", baseCommit, head).trim();
  if (!mergeBase) throw new Error(`no merge base between ${baseCommit} and HEAD`);
  return { head, revision: mergeBase, baseRef: base, baseCommit };
}

function inScope(path, scopes) {
  return isMeasuredFile(path) && scopes.some((prefix) => path.startsWith(prefix));
}

function listScopeFiles(repo, scopes) {
  const tracked = zList(gitNull(repo, "ls-files", "-z"));
  const untracked = zList(gitNull(repo, "ls-files", "--others", "--exclude-standard", "-z"));
  return [...new Set([...tracked, ...untracked])].filter((path) => inScope(path, scopes)).sort();
}

function listChangedFiles(repo, revision, scopes) {
  const diffed = zList(gitNull(repo, "diff", "--name-only", "--no-renames", "-z", revision, "--"));
  const untracked = zList(gitNull(repo, "ls-files", "--others", "--exclude-standard", "-z"));
  return [...new Set([...diffed, ...untracked])].filter((path) => inScope(path, scopes)).sort();
}

function blobAt(repo, revision, path) {
  try {
    return gitText(repo, "cat-file", "blob", `${revision}:${path}`);
  } catch {
    return null; // path did not exist at the base revision
  }
}

function groupBy(records, keyOf) {
  const groups = new Map();
  for (const record of records) {
    const key = keyOf(record);
    const list = groups.get(key) || [];
    list.push(record);
    groups.set(key, list);
  }
  return groups;
}

function entryBase(file, record) {
  return {
    file,
    name: record.name,
    kind: record.kind,
    role: record.role,
    line: record.line,
    fingerprint: record.fingerprint,
  };
}

function classifyEntry(entry, reviewState) {
  const classification = classifyComplexity(entry.new_complexity, { okMax: OK_LIMIT, reviewMax: REVIEW_LIMIT });
  const review = classification === "review" ? reviewState : null;
  return { ...entry, classification, review };
}

// --- Stronger-model review receipts (schema ts-complexity-review-receipt/1)
//
// A receipt is a JSON file binding one independent review to the exact
// analyzed commits, the review-band functions and both model identities.
// Every failed check produces its own precise error; one invalid receipt
// blocks the run exactly like an unreceipted review-band body.

function readReceiptDocument(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (error) {
    return { document: null, errors: [`receipt file cannot be read: ${error.message}`] };
  }
  try {
    const document = JSON.parse(raw);
    if (!document || typeof document !== "object" || Array.isArray(document)) {
      return { document: null, errors: ["receipt file must contain a JSON object"] };
    }
    return { document, errors: [] };
  } catch (error) {
    return { document: null, errors: [`receipt file cannot be parsed as JSON: ${error.message}`] };
  }
}

function receiptFieldErrors(document) {
  const stringKeys = ["schema", "source_commit", "base_commit", "implementer_model", "reviewer_model", "verdict", "reviewed_at"];
  const errors = [];
  for (const key of stringKeys) {
    const value = document[key];
    if (typeof value !== "string" || value.trim() === "") errors.push(`receipt is missing ${key}`);
  }
  if (!Array.isArray(document.functions) || document.functions.length === 0) {
    errors.push("receipt is missing functions");
  }
  if (typeof document.schema === "string" && document.schema !== RECEIPT_SCHEMA) {
    errors.push(`receipt schema '${document.schema}' is not supported (expected ${RECEIPT_SCHEMA})`);
  }
  return errors;
}

function receiptCommitErrors(document, run) {
  const errors = [];
  if (typeof document.source_commit === "string" && document.source_commit !== run.head) {
    errors.push(`receipt source_commit ${document.source_commit} does not match analyzed head ${run.head}`);
  }
  if (typeof document.base_commit === "string" && document.base_commit !== run.mergeBase) {
    errors.push(`receipt base_commit ${document.base_commit} does not match analyzed base ${run.mergeBase}`);
  }
  return errors;
}

function receiptModelErrors(document, modelOrder) {
  const implementer = document.implementer_model;
  const reviewer = document.reviewer_model;
  if (implementer === reviewer) {
    return [`receipt reviewer_model '${reviewer}' equals implementer_model; an independent stronger reviewer is required`];
  }
  if (!modelOrder) return [];
  const errors = [];
  const implementerRank = modelOrder.indexOf(implementer);
  const reviewerRank = modelOrder.indexOf(reviewer);
  if (implementerRank === -1) errors.push(`receipt implementer_model '${implementer}' is not in the configured model strength ordering`);
  if (reviewerRank === -1) errors.push(`receipt reviewer_model '${reviewer}' is not in the configured model strength ordering`);
  if (implementerRank !== -1 && reviewerRank !== -1 && reviewerRank <= implementerRank) {
    errors.push(`receipt reviewer_model '${reviewer}' is not stronger than implementer_model '${implementer}' per --model-order`);
  }
  return errors;
}

function receiptVerdictErrors(document) {
  const verdict = document.verdict;
  if (!RECEIPT_VERDICTS.includes(verdict)) {
    return [`receipt verdict '${verdict}' is not one of: ${RECEIPT_VERDICTS.join(", ")}`];
  }
  if (verdict !== "approve") return [`receipt verdict '${verdict}' does not approve the reviewed change`];
  return [];
}

function receiptFreshnessErrors(document, nowMs) {
  const raw = document.reviewed_at;
  const reviewedAt = typeof raw === "string" ? Date.parse(raw) : NaN;
  if (Number.isNaN(reviewedAt)) return [`receipt reviewed_at '${raw}' is not an ISO-8601 timestamp`];
  if (reviewedAt - nowMs > RECEIPT_FUTURE_TOLERANCE_MS) return [`receipt reviewed_at ${raw} is in the future`];
  const maxAgeMs = RECEIPT_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
  if (nowMs - reviewedAt > maxAgeMs) return [`receipt reviewed_at ${raw} is stale (older than ${RECEIPT_MAX_AGE_DAYS} days)`];
  return [];
}

function receiptBindingErrors(document, band) {
  const listed = document.functions;
  if (!Array.isArray(listed) || listed.some((item) => typeof item !== "string" || item.trim() === "")) {
    return ["receipt functions must be a list of non-empty 'file:name' strings"];
  }
  const bound = new Set(listed);
  return band
    .filter((entry) => !bound.has(`${entry.file}:${entry.name}`))
    .map((entry) => `receipt does not bind review-band function ${entry.file}: ${entry.name} (expected "${entry.file}:${entry.name}")`);
}

function validateReceipt(path, run, band, modelOrder, nowMs) {
  const { document, errors } = readReceiptDocument(path);
  if (document) {
    errors.push(...receiptFieldErrors(document));
    errors.push(...receiptCommitErrors(document, run));
    errors.push(...receiptModelErrors(document, modelOrder));
    errors.push(...receiptVerdictErrors(document));
    errors.push(...receiptFreshnessErrors(document, nowMs));
    errors.push(...receiptBindingErrors(document, band));
  }
  const valid = errors.length === 0;
  return {
    path,
    valid,
    errors,
    schema: document?.schema ?? null,
    source_commit: document?.source_commit ?? null,
    base_commit: document?.base_commit ?? null,
    implementer_model: document?.implementer_model ?? null,
    reviewer_model: document?.reviewer_model ?? null,
    verdict: document?.verdict ?? null,
    reviewed_at: document?.reviewed_at ?? null,
    functions: Array.isArray(document?.functions) ? document.functions : null,
  };
}

function parseModelOrder(raw) {
  if (!raw) return null;
  const names = raw.split(",").map((name) => name.trim()).filter((name) => name.length > 0);
  return names.length > 0 ? names : null;
}

// Pass 1 — survivors: a base body that still exists at head under its own
// qualified name is unchanged and can never back a rename or move. Pairing
// survivors before anything else is order-independent: a duplicate copy
// appearing earlier in the file cannot steal the original's identity.
function claimSurvivors(side) {
  const newByFingerprint = groupBy(side.newRecs, (record) => record.fingerprint);
  for (const old of side.oldRecs) {
    const twin = (newByFingerprint.get(old.fingerprint) || []).find((record) => !record.claimed && record.name === old.name);
    if (twin) {
      twin.claimed = true;
      old.taken = true;
    }
  }
}

// Pass 2 — in-file renames: identical bodies under different names. Each
// vanished original backs at most one rename; later copies fall through to
// duplicate handling.
function claimRenames(side, emit) {
  const vanished = groupBy(
    side.oldRecs.filter((old) => !old.taken),
    (old) => old.fingerprint,
  );
  for (const record of side.newRecs) {
    if (record.claimed) continue;
    const candidates = vanished.get(record.fingerprint);
    if (!candidates || candidates.length === 0) continue;
    const twin = candidates.shift();
    twin.taken = true;
    record.claimed = true;
    emit.renamed(side.file, twin, record);
  }
}

// Pass 3 — changed bodies: same own name and kind, different content.
function claimChanged(side, emit) {
  for (const record of side.newRecs) {
    if (record.claimed) continue;
    const twin = side.oldRecs.find((old) => !old.taken && old.ownName === record.ownName && old.kind === record.kind);
    if (twin) {
      twin.taken = true;
      record.claimed = true;
      emit.changed(side.file, twin, record);
    }
  }
}

function matchSide(side, emit) {
  claimSurvivors(side);
  claimRenames(side, emit);
  claimChanged(side, emit);
  return side.newRecs.filter((record) => !record.claimed);
}

// Pending bodies are cross-file moves, duplicates or additions. A pending
// body whose identical base twin vanished from its own file is a move. If
// no vanished twin remains but the fingerprint exists at base, the body
// duplicates a function whose original still exists (or was already claimed
// by one move) and is measured as added code — identical copies must not
// escape measurement.
function resolvePending(pending, bodyPool, baseTwins, emit) {
  for (const { file, record } of pending) {
    const movedFrom = bodyPool.get(record.fingerprint)?.shift() || null;
    const base = entryBase(file, record);
    if (movedFrom) {
      emit.entry({ ...base, status: "moved", moved_from: { file: movedFrom.file, name: movedFrom.name }, duplicate_of: null, old_complexity: movedFrom.complexity, new_complexity: record.complexity, delta: 0 });
      continue;
    }
    const duplicateOf = baseTwins.get(record.fingerprint) || null;
    emit.entry({ ...base, status: "added", moved_from: null, duplicate_of: duplicateOf, old_complexity: null, new_complexity: record.complexity, delta: null });
  }
}

function buildDebt(headRecords, changedKeys) {
  const untouchedDebt = [];
  for (const [file, records] of headRecords) {
    for (const record of records) {
      if (!changedKeys.has(`${file}\0${record.name}`)) {
        untouchedDebt.push({ file, name: record.name, complexity: record.complexity, kind: record.kind });
      }
    }
  }
  return untouchedDebt;
}

function debtSummary(untouchedDebt) {
  const counts = { functions_total: untouchedDebt.length, ok: 0, review: 0, block: 0 };
  for (const record of untouchedDebt) {
    counts[classifyComplexity(record.complexity, { okMax: OK_LIMIT, reviewMax: REVIEW_LIMIT })] += 1;
  }
  const top = [...untouchedDebt]
    .sort((a, b) => b.complexity - a.complexity || a.name.localeCompare(b.name) || a.file.localeCompare(b.file))
    .slice(0, 10);
  return { ...counts, top };
}

function digestHead(repo, scopeFiles) {
  const digest = createHash("sha256");
  for (const path of scopeFiles) {
    try {
      digest.update(`${path}\0${createHash("sha256").update(readFileSync(join(repo, path))).digest("hex")}\n`);
    } catch (error) {
      // Only a file absent from the working tree is skipped; any other read
      // failure (permissions, I/O) is a tool error and must surface (exit 2).
      if (error.code !== "ENOENT") throw new Error(`cannot read ${path}: ${error.message}`);
    }
  }
  return `sha256:${digest.digest("hex")}`;
}

function digestBase(repo, revision, scopes) {
  const raw = gitText(repo, "ls-tree", "-r", "-z", "--format=%(objectname) %(path)", revision);
  const digest = createHash("sha256");
  for (const entry of zList(raw)) {
    const separator = entry.indexOf(" ");
    const path = entry.slice(separator + 1);
    if (!inScope(path, scopes)) continue;
    digest.update(`${path}\0${entry.slice(0, separator)}\n`);
  }
  return `sha256:${digest.digest("hex")}`;
}

function humanSummaryLines(report) {
  const run = report.run;
  const lines = [
    `${ANALYZER.name} ${ANALYZER.version} | parser typescript ${report.parser.version} (lockfile ${report.parser.lockfile_version})`,
    `base ${run.merge_base} -> head ${run.head_commit} | scope ${run.scope.join(", ")} | files ${run.files_in_scope} (${run.files_changed_in_scope} changed)`,
    `changed functions: ${report.changed_functions.length} (${report.summary.added} added, ${report.summary.changed} changed, ${report.summary.moved} moved) | deleted ${report.summary.deleted}`,
    `review band ${OK_LIMIT + 1}-${REVIEW_LIMIT}: ${report.summary.review} | blocking >${BLOCK_LIMIT}: ${report.summary.blocking}`,
    `untouched debt: ${report.untouched_debt.review + report.untouched_debt.block} functions above ${OK_LIMIT} (${report.untouched_debt.review} review, ${report.untouched_debt.block} block)`,
  ];
  for (const failure of report.failures) {
    lines.push(`BLOCK ${failure}`);
  }
  if (report.receipt) {
    for (const error of report.receipt.errors) lines.push(`RECEIPT INVALID ${error}`);
  }
  for (const entry of report.changed_functions) {
    if (entry.review === "required") lines.push(`NEEDS REVIEW RECEIPT ${entry.file}: ${entry.name} (cognitive complexity ${entry.new_complexity} in ${OK_LIMIT + 1}-${REVIEW_LIMIT})`);
  }
  return lines;
}

class ParseFailure extends Error {}

function worktreeText(repo, file) {
  try {
    return readFileSync(join(repo, file), "utf8");
  } catch (error) {
    // Only a file absent from the working tree reads as deleted; any other
    // read failure (permissions, I/O) is a tool error and must surface.
    if (error.code === "ENOENT") return null;
    throw new Error(`cannot read ${file}: ${error.message}`);
  }
}

function recordsFor(ts, file, text) {
  if (text === null) return [];
  const parsed = parseAndCollect(ts, file, text);
  if (parsed.error) throw new ParseFailure(parsed.error);
  return parsed.functions;
}

function sideFor(ts, repo, revision, file) {
  return {
    file,
    oldRecs: recordsFor(ts, file, blobAt(repo, revision, file)),
    newRecs: recordsFor(ts, file, worktreeText(repo, file)),
  };
}

function parseSides(ts, repo, revision, changedFiles) {
  const sides = [];
  const errors = [];
  for (const file of changedFiles) {
    try {
      sides.push(sideFor(ts, repo, revision, file));
    } catch (error) {
      if (error instanceof ParseFailure) errors.push(error.message);
      else throw error;
    }
  }
  if (errors.length > 0) {
    throw new Error(`parser failure:\n  ${errors.join("\n  ")}`);
  }
  return sides;
}

function computeEntries(sides) {
  const entries = [];
  const pending = [];
  let vanished = 0;
  const emit = {
    renamed: (file, old, record) => {
      const base = entryBase(file, record);
      entries.push({ ...base, status: "moved", moved_from: { file, name: old.name }, duplicate_of: null, old_complexity: old.complexity, new_complexity: record.complexity, delta: 0 });
    },
    changed: (file, old, record) => {
      const base = entryBase(file, record);
      entries.push({ ...base, status: "changed", moved_from: null, duplicate_of: null, old_complexity: old.complexity, new_complexity: record.complexity, delta: record.complexity - old.complexity });
    },
    entry: (entry) => entries.push(entry),
  };

  const bodyPool = new Map();
  const baseTwins = new Map();
  for (const side of sides) {
    const stillUnmatched = matchSide(side, emit);
    for (const record of stillUnmatched) pending.push({ file: side.file, record });
    for (const old of side.oldRecs) {
      if (!baseTwins.has(old.fingerprint)) {
        baseTwins.set(old.fingerprint, { file: side.file, name: old.name });
      }
      if (old.taken) continue;
      const queue = bodyPool.get(old.fingerprint) || [];
      queue.push({ file: side.file, name: old.name, complexity: old.complexity });
      bodyPool.set(old.fingerprint, queue);
      vanished += 1;
    }
  }
  resolvePending(pending, bodyPool, baseTwins, emit);
  const crossFileMoves = entries.filter((entry) => entry.status === "moved" && entry.moved_from.file !== entry.file).length;
  return { entries, deletedCount: vanished - crossFileMoves };
}

function collectHeadRecords(ts, repo, scopeFiles, sides) {
  const headRecords = new Map();
  for (const file of scopeFiles) {
    const side = sides.find((candidate) => candidate.file === file);
    if (side) {
      headRecords.set(file, side.newRecs);
      continue;
    }
    let text;
    try {
      text = readFileSync(join(repo, file), "utf8");
    } catch (error) {
      // Only a file absent from the working tree has no head measurement;
      // any other read failure is a tool error and must surface (exit 2).
      if (error.code === "ENOENT") continue;
      throw new Error(`cannot read ${file}: ${error.message}`);
    }
    const parsed = parseAndCollect(ts, file, text);
    if (parsed.error) throw new Error(`parser failure: ${parsed.error}`);
    headRecords.set(file, parsed.functions);
  }
  return headRecords;
}

// The debt ledger lists every function above OK_LIMIT that this change did
// not touch, plus debt carried by renamed or relocated bodies. Entries are
// never truncated; the ledger records debt, it does not block anything.
function debtLedgerRows(untouchedDebt, changedFunctions) {
  const untouched = untouchedDebt
    .filter((record) => record.complexity > OK_LIMIT)
    .map((record) => ({ file: record.file, function: record.name, complexity: record.complexity, kind: "untouched", function_kind: record.kind }));
  const moved = changedFunctions
    .filter((entry) => entry.status === "moved" && entry.new_complexity > OK_LIMIT)
    .map((entry) => ({ file: entry.file, function: entry.name, complexity: entry.new_complexity, kind: "moved", function_kind: entry.kind }));
  return [...untouched, ...moved].sort((a, b) => a.file.localeCompare(b.file) || a.function.localeCompare(b.function));
}

function buildDebtLedger(report, untouchedDebt, changedFunctions) {
  const rows = debtLedgerRows(untouchedDebt, changedFunctions);
  const byKind = (kind) => rows.filter((row) => row.kind === kind);
  const gt15 = rows.filter((row) => row.complexity > REVIEW_LIMIT);
  const band = rows.filter((row) => row.complexity > OK_LIMIT && row.complexity <= REVIEW_LIMIT);
  return {
    schema: DEBT_SCHEMA,
    policy: { ok_max: OK_LIMIT, review_max: REVIEW_LIMIT, block_over: BLOCK_LIMIT },
    analyzer: { ...ANALYZER },
    parser: report.parser,
    run: {
      repository_root: report.run.repository_root,
      scope: report.run.scope,
      merge_base: report.run.merge_base,
      head_commit: report.run.head_commit,
      generated_at: new Date().toISOString(),
    },
    summary: {
      untouched_functions: untouchedDebt.length,
      untouched_gt15: byKind("untouched").filter((row) => row.complexity > REVIEW_LIMIT).length,
      untouched_11_to_15: byKind("untouched").filter((row) => row.complexity <= REVIEW_LIMIT).length,
      moved_gt15: byKind("moved").filter((row) => row.complexity > REVIEW_LIMIT).length,
      moved_11_to_15: byKind("moved").filter((row) => row.complexity <= REVIEW_LIMIT).length,
      functions_gt15: gt15.length,
      functions_11_to_15: band.length,
    },
    functions_gt15: gt15,
    functions_11_to_15: band,
  };
}

function analyze(ts, parser, options) {
  const repo = gitText(analyzerRepoRootSafe(options), "rev-parse", "--show-toplevel").trim();
  const scopes = options.scopes.length > 0 ? options.scopes : [DEFAULT_SCOPE];
  const rev = resolveRevision(repo, options.base);
  const scopeFiles = listScopeFiles(repo, scopes);
  const changedFiles = listChangedFiles(repo, rev.revision, scopes);
  const sides = parseSides(ts, repo, rev.revision, changedFiles);

  const { entries, deletedCount } = computeEntries(sides);
  const staged = entries
    .map((entry) => (entry.status === "moved" ? { ...entry, classification: "moved", review: null } : classifyEntry(entry, null)))
    .sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name));
  const band = staged.filter((entry) => entry.classification === "review");
  const receipt = options.receipt
    ? validateReceipt(options.receipt, { head: rev.head, mergeBase: rev.revision }, band, parseModelOrder(options.modelOrder), Date.now())
    : null;
  const reviewState = receipt === null ? "required" : receipt.valid ? "receipt-recorded" : "receipt-invalid";
  const changedFunctions = staged.map((entry) => (entry.classification === "review" ? { ...entry, review: reviewState } : entry));
  const changedKeys = new Set(changedFunctions.map((entry) => `${entry.file}\0${entry.name}`));

  const headRecords = collectHeadRecords(ts, repo, scopeFiles, sides);
  const untouchedDebt = buildDebt(headRecords, changedKeys);
  const failures = changedFunctions
    .filter((entry) => entry.classification === "block")
    .map((entry) => `${entry.file}: ${entry.name} (cognitive complexity ${entry.new_complexity} > ${BLOCK_LIMIT})`);
  const countBy = (predicate) => changedFunctions.filter(predicate).length;

  const report = {
    schema: "ts-complexity-diff/2",
    analyzer: { ...ANALYZER, limits: { ok_max: OK_LIMIT, review_max: REVIEW_LIMIT, block_over: BLOCK_LIMIT } },
    parser,
    run: {
      repository_root: repo,
      scope: scopes,
      base_ref: rev.baseRef,
      base_commit: rev.baseCommit,
      merge_base: rev.revision,
      head_commit: rev.head,
      files_in_scope: scopeFiles.length,
      files_changed_in_scope: changedFiles.length,
      source_digest: digestHead(repo, scopeFiles),
      base_source_digest: digestBase(repo, rev.revision, scopes),
    },
    receipt,
    changed_functions: changedFunctions,
    summary: {
      added: countBy((entry) => entry.status === "added"),
      changed: countBy((entry) => entry.status === "changed"),
      moved: countBy((entry) => entry.status === "moved"),
      deleted: deletedCount,
      review: band.length,
      blocking: failures.length,
      review_unreceipted: receipt === null ? band.length : 0,
      receipt_errors: receipt === null ? 0 : receipt.errors.length,
    },
    untouched_debt: debtSummary(untouchedDebt),
    failures,
  };
  return { report, ledger: buildDebtLedger(report, untouchedDebt, changedFunctions) };
}

function analyzerRepoRootSafe(options) {
  // The analyzed repository defaults to the checkout holding this script
  // (throwaway fixture repos embed a copy); TS_COMPLEXITY_REPO_ROOT steers
  // only the pinned parser in typescript.mjs, never the analyzed tree.
  return options.repo || fileURLToPath(new URL("../../../..", import.meta.url));
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const { ts, parser } = loadTypescript();
  const { report, ledger } = analyze(ts, parser, options);
  const json = `${JSON.stringify(report, null, 2)}\n`;
  process.stdout.write(json);
  if (options.jsonOut) writeFileSync(options.jsonOut, json);
  if (options.debtOut) writeFileSync(options.debtOut, `${JSON.stringify(ledger, null, 2)}\n`);
  if (!options.quiet) {
    for (const line of humanSummaryLines(report)) process.stderr.write(`${line}\n`);
  }
  const blocked = report.failures.length + report.summary.review_unreceipted + report.summary.receipt_errors;
  process.exit(blocked > 0 ? 1 : 0);
}

try {
  main();
} catch (error) {
  process.stderr.write(`ts-complexity-diff error: ${error.message}\n`);
  process.exit(2);
}
