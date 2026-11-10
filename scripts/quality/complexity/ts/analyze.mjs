// Differential TypeScript/JavaScript function-body complexity analyzer.
//
// Given a base revision and the current working tree, measures every
// added/changed/moved function body under the configured scopes and reports
// untouched legacy debt separately. Metric rules, report schema and known
// limits are documented in README.md next to this file.
//
// Exit codes: 0 = no blocking complexity; 1 = at least one changed body
// exceeds BLOCK_LIMIT (offenders named on stderr); 2 = tool error (bad base,
// missing merge base, parser failure, TypeScript pin drift).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { analyzerRepoRoot, loadTypescript } from "./typescript.mjs";
import { isMeasuredFile, parseAndCollect } from "./collect.mjs";
import { classifyComplexity } from "./metric.mjs";

const ANALYZER = {
  name: "ts-complexity-diff",
  version: "1.0.0",
  metric: "cognitive-complexity/sonar-style",
  rules: "scripts/quality/complexity/ts/README.md#metric-rules",
};
const OK_LIMIT = 10;
const REVIEW_LIMIT = 15;
const BLOCK_LIMIT = 15;
const DEFAULT_SCOPE = "web/dashboard/";
const VALUE_FLAGS = { "--repo": "repo", "--base": "base", "--receipt": "receipt", "--json-out": "jsonOut" };

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
  const options = { scopes: [], repo: null, base: null, receipt: null, jsonOut: null, quiet: false };
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

function classifyEntry(entry, receiptPresent) {
  const classification = classifyComplexity(entry.new_complexity, { okMax: OK_LIMIT, reviewMax: REVIEW_LIMIT });
  const review = classification === "review" ? (receiptPresent ? "receipt-recorded" : "required") : null;
  return { ...entry, classification, review };
}

function matchSide(side, emit) {
  const oldByFingerprint = groupBy(side.oldRecs, (record) => record.fingerprint);
  const unmatched = [];
  for (const record of side.newRecs) {
    const twins = oldByFingerprint.get(record.fingerprint);
    if (twins && twins.length > 0) {
      emit.identical(side, twins.shift(), record);
    } else {
      unmatched.push(record);
    }
  }
  const stillUnmatched = [];
  for (const record of unmatched) {
    const twin = side.oldRecs.find(
      (old) => !old.taken && old.ownName === record.ownName && old.kind === record.kind,
    );
    if (twin) {
      twin.taken = true;
      emit.changed(side.file, twin, record);
    } else {
      stillUnmatched.push(record);
    }
  }
  return stillUnmatched;
}

function resolvePending(pending, bodyPool, emit) {
  for (const { file, record } of pending) {
    const movedFrom = bodyPool.get(record.fingerprint)?.shift() || null;
    const base = entryBase(file, record);
    if (movedFrom) {
      emit.entry({ ...base, status: "moved", moved_from: movedFrom, old_complexity: movedFrom.record.complexity, new_complexity: record.complexity, delta: 0 });
    } else {
      emit.entry({ ...base, status: "added", moved_from: null, old_complexity: null, new_complexity: record.complexity, delta: null });
    }
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
    } catch {
      // deleted-from-worktree files are absent from the head digest by design
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
  return lines;
}

class ParseFailure extends Error {}

function worktreeText(repo, file) {
  try {
    return readFileSync(join(repo, file), "utf8");
  } catch {
    return null; // deleted in the working tree
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
    identical: (side, old, record) => {
      // Identical body: unchanged (same name) or renamed/moved in this file;
      // neither is re-measured as new or changed code.
      if (old.name !== record.name) {
        const base = entryBase(side.file, record);
        entries.push({ ...base, status: "moved", moved_from: { file: side.file, name: old.name }, old_complexity: old.complexity, new_complexity: record.complexity, delta: 0 });
      }
      old.taken = true;
    },
    changed: (file, old, record) => {
      const base = entryBase(file, record);
      entries.push({ ...base, status: "changed", moved_from: null, old_complexity: old.complexity, new_complexity: record.complexity, delta: record.complexity - old.complexity });
    },
    entry: (entry) => entries.push(entry),
  };

  const bodyPool = new Map();
  for (const side of sides) {
    const stillUnmatched = matchSide(side, emit);
    for (const record of stillUnmatched) pending.push({ file: side.file, record });
    for (const old of side.oldRecs) {
      if (old.taken) continue;
      const queue = bodyPool.get(old.fingerprint) || [];
      queue.push({ file: side.file, record: old });
      bodyPool.set(old.fingerprint, queue);
      vanished += 1;
    }
  }
  resolvePending(pending, bodyPool, emit);
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
    try {
      const parsed = parseAndCollect(ts, file, readFileSync(join(repo, file), "utf8"));
      if (parsed.error) throw new Error(`parser failure: ${parsed.error}`);
      headRecords.set(file, parsed.functions);
    } catch (error) {
      if (error.message.startsWith("parser failure")) throw error;
      // absent from the working tree: nothing to measure at head
    }
  }
  return headRecords;
}

function analyze(ts, parser, options) {
  const repo = gitText(analyzerRepoRootSafe(options), "rev-parse", "--show-toplevel").trim();
  const scopes = options.scopes.length > 0 ? options.scopes : [DEFAULT_SCOPE];
  const rev = resolveRevision(repo, options.base);
  const scopeFiles = listScopeFiles(repo, scopes);
  const changedFiles = listChangedFiles(repo, rev.revision, scopes);
  const sides = parseSides(ts, repo, rev.revision, changedFiles);

  const { entries, deletedCount } = computeEntries(sides);
  const receiptPresent = options.receipt !== null && options.receipt !== undefined;
  const changedFunctions = entries
    .map((entry) => (entry.status === "moved" ? { ...entry, classification: "moved", review: null } : classifyEntry(entry, receiptPresent)))
    .sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name));
  const changedKeys = new Set(changedFunctions.map((entry) => `${entry.file}\0${entry.name}`));

  const headRecords = collectHeadRecords(ts, repo, scopeFiles, sides);
  const untouchedDebt = buildDebt(headRecords, changedKeys);
  const failures = changedFunctions
    .filter((entry) => entry.classification === "block")
    .map((entry) => `${entry.file}: ${entry.name} (cognitive complexity ${entry.new_complexity} > ${BLOCK_LIMIT})`);
  const countBy = (predicate) => changedFunctions.filter(predicate).length;

  return {
    schema: "ts-complexity-diff/1",
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
    receipt: options.receipt ?? null,
    changed_functions: changedFunctions,
    summary: {
      added: countBy((entry) => entry.status === "added"),
      changed: countBy((entry) => entry.status === "changed"),
      moved: countBy((entry) => entry.status === "moved"),
      deleted: deletedCount,
      review: countBy((entry) => entry.classification === "review"),
      blocking: failures.length,
    },
    untouched_debt: debtSummary(untouchedDebt),
    failures,
  };
}

function analyzerRepoRootSafe(options) {
  return options.repo || analyzerRepoRoot();
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const { ts, parser } = loadTypescript();
  const report = analyze(ts, parser, options);
  const json = `${JSON.stringify(report, null, 2)}\n`;
  process.stdout.write(json);
  if (options.jsonOut) writeFileSync(options.jsonOut, json);
  if (!options.quiet) {
    for (const line of humanSummaryLines(report)) process.stderr.write(`${line}\n`);
  }
  process.exit(report.failures.length > 0 ? 1 : 0);
}

try {
  main();
} catch (error) {
  process.stderr.write(`ts-complexity-diff error: ${error.message}\n`);
  process.exit(2);
}
