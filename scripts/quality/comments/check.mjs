#!/usr/bin/env node
// Comment-lane safety checker: proves a .ts/.tsx edit changed no executable
// token and no ASI-relevant line boundary, and routes semantic directive
// comments (triple-slash refs, @ts-* pragmas, eslint-* directives,
// license/attribution blocks) to manual review instead of a silent pass.
//
// Usage:
//   node check.mjs <old-file> <new-file>
//   node check.mjs --against <git-rev> <path> [...]   (old side read from git)
//   node check.mjs ... --json                         (machine-readable)
//
// Exit codes: 0 all PASS · 1 ≥1 FAIL (token/line-boundary/syntax) ·
// 2 no FAIL but ≥1 FLAG (directive change needs manual review).
// Pair mode compares exactly two files; --against mode compares each path's
// current disk content with the same path in <git-rev>.
//
// Not wired into product gates; see self-test.mjs for negative controls.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(scriptDir, '../../..')

// The checker must not add its own dependency tree; it reuses the TypeScript
// compiler the dashboard already pins. web/site files ride the same install.
function loadTypeScript() {
  const require = createRequire(import.meta.url)
  const candidates = [
    { paths: [resolve(repoRoot, 'web/dashboard')], origin: 'web/dashboard devDependencies' },
    { paths: [resolve(repoRoot, 'web/site')], origin: 'web/site devDependencies' },
  ]
  for (const candidate of candidates) {
    try {
      const resolved = require.resolve('typescript', candidate)
      return { ts: require(resolved), origin: candidate.origin, resolved }
    } catch {
      // keep trying
    }
  }
  const ts = require('typescript')
  return { ts, origin: 'ambient NODE_PATH', resolved: 'typescript' }
}

const { ts, origin: tsOrigin, resolved: tsResolved } = loadTypeScript()

function scriptKindFor(fileName) {
  if (/\.tsx$/i.test(fileName)) return ts.ScriptKind.TSX
  if (/\.(ts|mts|cts)$/i.test(fileName)) return ts.ScriptKind.TS
  return null
}

function parse(fileName, text) {
  const kind = scriptKindFor(fileName)
  if (kind === null) {
    return { error: `unsupported extension (want .ts/.tsx): ${fileName}` }
  }
  const sourceFile = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, kind)
  // parseDiagnostics is compiler-internal but stable; absence just skips the guard.
  const diagnostics = sourceFile.parseDiagnostics || []
  if (diagnostics.length > 0) {
    const first = ts.flattenDiagnosticMessageText(diagnostics[0].messageText, ' ')
    return { error: `syntax error: ${first}` }
  }
  return { sourceFile }
}

// Collect leaf tokens in document order. The parser (not a raw scanner pass)
// assigns JSX text, regex literals and template spans correctly, so trivia
// never leaks into the executable stream.
function collectTokens(sourceFile) {
  const fullText = sourceFile.getFullText()
  const tokens = []
  const visit = (node) => {
    if (node.getChildCount(sourceFile) === 0) {
      tokens.push({ kind: node.kind, text: node.getText(sourceFile), start: node.getStart(sourceFile), end: node.end })
    } else {
      node.getChildren(sourceFile).forEach(visit)
    }
  }
  sourceFile.getChildren(sourceFile).forEach(visit)
  tokens.sort((a, b) => a.start - b.start)
  let previousEnd = null
  return tokens.map((token, index) => {
    // Leading line breaks before the first token cannot affect ASI, so
    // deleting a leading comment line must not fail on token #0.
    const trivia = index === 0 ? '' : fullText.slice(previousEnd, token.start)
    previousEnd = token.end
    return {
      kindName: ts.SyntaxKind[token.kind],
      text: token.text,
      lineBreakBefore: /\r|\n/.test(trivia),
      line: sourceFile.getLineAndCharacterOfPosition(token.start).line + 1,
    }
  })
}

// All comments the parser treated as trivia, gathered from node boundaries so
// JSX text or string contents can never be misread as a comment.
function collectComments(sourceFile) {
  const fullText = sourceFile.getFullText()
  const seen = new Set()
  const ranges = []
  const addRanges = (found) => {
    for (const range of found) {
      const key = `${range.pos}:${range.end}`
      if (!seen.has(key)) {
        seen.add(key)
        ranges.push({ ...range, text: fullText.slice(range.pos, range.end), line: sourceFile.getLineAndCharacterOfPosition(range.pos).line + 1 })
      }
    }
  }
  const visit = (node) => {
    addRanges(ts.getLeadingCommentRanges(fullText, node.getFullStart()) || [])
    addRanges(ts.getTrailingCommentRanges(fullText, node.end) || [])
    node.getChildren(sourceFile).forEach(visit)
  }
  visit(sourceFile)
  return ranges
}

// One normalized key per directive comment so reformatting alone does not
// trigger a flag, while any add/remove/reword of the directive text does.
function normalizeComment(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*\*+\/?/, '').trim())
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim()
}

const LICENSE_PATTERN =
  /(spdx-license-identifier|copyright|©|\(c\)\s*(19|20)\d{2}|all rights reserved|licensed under|(apache|mit|bsd|gpl|mpl)[ -]license)/i

function classifyDirective(text) {
  const trimmed = text.trim()
  // Exactly three slashes opens a directive; four or more is a plain comment.
  if (/^\/\/\/(?!\/)/.test(trimmed)) return 'triple-slash'
  if (/@ts-[a-z][a-z-]*/i.test(trimmed)) return 'ts-pragma'
  if (/\beslint-(disable|enable|configure)/i.test(trimmed)) return 'eslint-directive'
  if (LICENSE_PATTERN.test(normalizeComment(trimmed))) return 'license'
  return null
}

function collectDirectives(sourceFile) {
  const directives = []
  for (const comment of collectComments(sourceFile)) {
    const type = classifyDirective(comment.text)
    if (type !== null) {
      directives.push({ type, key: `${type} ${normalizeComment(comment.text)}`, line: comment.line + 1, preview: normalizeComment(comment.text).slice(0, 90) })
    }
  }
  return directives
}

function diffMultiset(oldItems, newItems) {
  const counts = new Map()
  for (const item of oldItems) {
    const held = counts.get(item.key)
    if (held) held.count += 1
    else counts.set(item.key, { count: 1, item })
  }
  const changes = []
  for (const item of newItems) {
    const held = counts.get(item.key)
    if (!held || held.count === 0) changes.push({ change: 'added', ...item })
    else held.count -= 1
  }
  for (const [key, held] of counts) {
    for (let i = 0; i < held.count; i += 1) {
      changes.push({ change: 'removed', ...held.item })
    }
  }
  return changes
}

// PASS requires identical (kind, text, lineBreakBefore) streams. Line NUMBERS
// may shift (deleting a comment line is fine); line-break PRESENCE between
// adjacent tokens may not, because ASI depends on it.
function comparePair(label, oldFileName, oldText, newFileName, newText) {
  const details = []
  const oldParsed = parse(oldFileName, oldText)
  if (oldParsed.error) return { label, result: 'FAIL', details: [`old side: ${oldParsed.error}`] }
  const newParsed = parse(newFileName, newText)
  if (newParsed.error) return { label, result: 'FAIL', details: [`new side: ${newParsed.error}`] }

  const oldTokens = collectTokens(oldParsed.sourceFile)
  const newTokens = collectTokens(newParsed.sourceFile)
  const limit = Math.min(oldTokens.length, newTokens.length)
  for (let i = 0; i < limit; i += 1) {
    const a = oldTokens[i]
    const b = newTokens[i]
    if (a.kindName !== b.kindName || a.text !== b.text) {
      return {
        label,
        result: 'FAIL',
        details: [
          `token #${i} changed: old ${a.kindName} ${JSON.stringify(a.text)} (line ${a.line}) vs new ${b.kindName} ${JSON.stringify(b.text)} (line ${b.line})`,
        ],
      }
    }
    if (a.lineBreakBefore !== b.lineBreakBefore) {
      return {
        label,
        result: 'FAIL',
        details: [
          `line boundary before token #${i} ${JSON.stringify(b.text)} changed (old line ${a.line}: ${a.lineBreakBefore}, new line ${b.line}: ${b.lineBreakBefore}) — ASI hazard`,
        ],
      }
    }
  }
  if (oldTokens.length !== newTokens.length) {
    const longer = oldTokens.length > newTokens.length ? oldTokens : newTokens
    const which = oldTokens.length > newTokens.length ? 'old' : 'new'
    const extra = longer[limit]
    return {
      label,
      result: 'FAIL',
      details: [`token count changed: old ${oldTokens.length} vs new ${newTokens.length}; first extra ${which} token ${extra.kindName} ${JSON.stringify(extra.text)} (line ${extra.line})`],
    }
  }

  if ((oldText.startsWith('#!') ? 1 : 0) !== (newText.startsWith('#!') ? 1 : 0)) {
    details.push('shebang line added or removed')
  }
  const directiveChanges = diffMultiset(collectDirectives(oldParsed.sourceFile), collectDirectives(newParsed.sourceFile))
  for (const change of directiveChanges) {
    details.push(`${change.change} ${change.type} directive (line ${change.line ?? '?'}): ${change.preview}`)
  }
  if (details.length > 0) return { label, result: 'FLAG', details }
  return { label, result: 'PASS', details: [] }
}

function gitShow(rev, pathRelativeToRoot) {
  return execFileSync('git', ['show', `${rev}:${pathRelativeToRoot}`], { cwd: repoRoot, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
}

function repoRelative(path) {
  const absolute = isAbsolute(path) ? path : resolve(process.cwd(), path)
  const rel = relative(repoRoot, absolute)
  if (rel.startsWith('..')) throw new Error(`path outside repository: ${path}`)
  return rel
}

function parseArgs(argv) {
  const args = { files: [], against: null, json: false }
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--against') {
      args.against = argv[i + 1]
      i += 1
    } else if (argv[i] === '--json') {
      args.json = true
    } else {
      args.files.push(argv[i])
    }
  }
  return args
}

function buildResults(args) {
  const results = []
  if (args.against !== null) {
    for (const file of args.files) {
      const rel = repoRelative(file)
      let oldText
      try {
        oldText = gitShow(args.against, rel)
      } catch {
        results.push({ label: rel, result: 'FAIL', details: ['file not present in --against revision'] })
        continue
      }
      let newText
      try {
        newText = readFileSync(resolve(repoRoot, rel), 'utf8')
      } catch {
        results.push({ label: rel, result: 'FAIL', details: ['file missing on disk'] })
        continue
      }
      results.push(comparePair(rel, rel, oldText, rel, newText))
    }
  } else {
    if (args.files.length !== 2) {
      throw new Error('pair mode needs exactly <old-file> <new-file>')
    }
    const [oldFile, newFile] = args.files
    results.push(comparePair(`${oldFile} -> ${newFile}`, oldFile, readFileSync(oldFile, 'utf8'), newFile, readFileSync(newFile, 'utf8')))
  }
  return results
}

function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.files.length === 0) {
    console.error('usage: check.mjs <old> <new> | check.mjs --against <rev> <path>... [--json]')
    process.exit(1)
  }
  let results
  try {
    results = buildResults(args)
  } catch (error) {
    console.error(`check.mjs: ${error.message}`)
    process.exit(1)
  }
  const summary = { PASS: 0, FAIL: 0, FLAG: 0 }
  for (const result of results) {
    summary[result.result] += 1
    if (!args.json) {
      const lines = [`${result.result}  ${result.label}`]
      for (const detail of result.details) lines.push(`      ${detail}`)
      console.log(lines.join('\n'))
    }
  }
  if (args.json) {
    console.log(JSON.stringify({ summary, results, typescript: { origin: tsOrigin, resolved: tsResolved } }, null, 2))
  } else {
    console.log(`summary: ${summary.PASS} pass, ${summary.FLAG} flag, ${summary.FAIL} fail (typescript via ${tsOrigin})`)
  }
  process.exit(summary.FAIL > 0 ? 1 : summary.FLAG > 0 ? 2 : 0)
}

main()
