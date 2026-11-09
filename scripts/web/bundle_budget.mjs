#!/usr/bin/env node
// IMP-52: dashboard bundle size budget.
// Budget is fixed at recording time (work record docs/plans/work-records/IMP-52.md):
//   BEFORE: entry (script tag in dist/index.html) = 342,767 B raw.
//   BUDGET: entry raw <= 220,000 B (−36%, vendor-react + vendor-i18n extracted).
//   LazyCharts boundary: no chunk in the entry's static import closure may
//   contain the `recharts` marker — charts must stay out of the startup graph.
// Exit 0 = within budget; exit 1 = violation (wired into `npm run build`).
import { readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = fileURLToPath(new URL('.', import.meta.url))
const distDir = resolve(scriptDir, '../../web/dashboard/dist')
const args = process.argv.slice(2)
const flagIdx = args.indexOf('--entry-budget')
const budgetOverride = flagIdx !== -1 ? Number(args[flagIdx + 1]) : undefined
const ENTRY_BUDGET_BYTES = 220_000
const entryBudget = Number.isFinite(budgetOverride) && budgetOverride > 0 ? budgetOverride : ENTRY_BUDGET_BYTES
const RECHARTS_MARKER = 'recharts'

const errors = []
const warnings = []

function fail(msg) {
  errors.push(msg)
}

if (!readExists(join(distDir, 'index.html'))) {
  console.error(`bundle_budget: ${distDir} not found — run "npm run build" first`)
  process.exit(1)
}

function readExists(p) {
  try {
    readFileSync(p)
    return true
  } catch {
    return false
  }
}

const indexHtml = readFileSync(join(distDir, 'index.html'), 'utf8')
const entryMatch = indexHtml.match(/<script[^>]+src="(\/assets\/[^"]+\.js)"/)
if (!entryMatch) {
  console.error('bundle_budget: no entry script found in dist/index.html')
  process.exit(1)
}
const entryFile = entryMatch[1].replace(/^\//, '')
const entryName = entryFile.split('/').pop()
const entryPath = join(distDir, entryFile)
const entryBytes = readFileSync(entryPath).length
const assetsDir = join(distDir, 'assets')
const jsFiles = readdirSync(assetsDir).filter(f => f.endsWith('.js'))
const sizes = new Map(jsFiles.map(f => [f, readFileSync(join(assetsDir, f)).length]))

// Static import closure of the entry: Vite emits all imports at the top of a
// chunk as `import"./name.js"` or `import"./name.js"`. Dynamic imports
// (`import("./x.js")`) are NOT followed — those are lazy boundaries.
function staticImports(file, seen = new Set()) {
  if (seen.has(file)) return seen
  seen.add(file)
  const src = readFileSync(join(assetsDir, file), 'utf8')
  // Static imports in minified output: `import"./x.js"` and `import{a as b}from"./x.js"`
  // (no space before `from`). Dynamic boundaries are parenthesized: `import("./x.js")`.
  const re = /(?:^|;)\s*import\s*"(\.\/[^"]+\.js)"|\bfrom\s*"(\.\/[^"]+\.js)"/g
  for (const m of src.matchAll(re)) {
    const dep = (m[1] ?? m[2]).replace(/^\.\//, '')
    if (sizes.has(dep)) staticImports(dep, seen)
  }
  return seen
}

const closure = staticImports(entryName)
const rechartsInClosure = [...closure].filter(f => {
  const src = readFileSync(join(assetsDir, f), 'utf8')
  return src.includes(RECHARTS_MARKER)
})

console.log('bundle_budget: dashboard dist report')
console.log(`  entry: ${entryName} = ${entryBytes} B raw (budget ${entryBudget} B, before 342,767 B)`)
const top = [...sizes.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)
for (const [f, b] of top) console.log(`  chunk ${f.padEnd(34)} ${String(b).padStart(9)} B`)
console.log(`  entry static import closure: ${closure.size} chunk(s)`)
console.log(`  recharts marker in startup closure: ${rechartsInClosure.length ? rechartsInClosure.join(', ') : 'none'}`)

if (entryBytes > entryBudget) {
  fail(`entry ${entryFile} is ${entryBytes} B > budget ${entryBudget} B`)
}
if (rechartsInClosure.length > 0) {
  fail(`recharts reached the startup graph via: ${rechartsInClosure.join(', ')} (LazyCharts boundary broken)`)
}
for (const w of warnings) console.warn(`  warn: ${w}`)
if (errors.length > 0) {
  for (const e of errors) console.error(`bundle_budget: FAIL ${e}`)
  process.exit(1)
}
console.log('bundle_budget: OK')
