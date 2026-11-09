// NEXT-20: run the CLIENT match-expression evaluator (the same module the
// RulesPage preview uses) against the shared corpus and diff it with the
// backend-pinned expectations. Divergence = exit 1, never a warning.
import { execFileSync } from 'node:child_process'
import { readFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const root = new URL('../..', import.meta.url).pathname
const corpus = JSON.parse(readFileSync(join(root, 'contracts/rules-corpus.json'), 'utf8'))

// Compile the pure TS module with the dashboard's own esbuild (dev dep);
// bin/esbuild is a native binary — execute it directly.
const dir = mkdtempSync(join(tmpdir(), 'rules-parity-'))
execFileSync(join(root, 'web/dashboard/node_modules/.bin/esbuild'), [
  join(root, 'web/dashboard/src/lib/matchExpr.ts'),
  '--format=cjs', '--outfile=' + join(dir, 'matchExpr.cjs'),
], { stdio: 'inherit' })
const { evaluateMatchExpr } = require(join(dir, 'matchExpr.cjs'))

let fail = 0
for (const tc of corpus.cases) {
  const got = evaluateMatchExpr(tc.expr, corpus.context)
  const gotBool = got === null ? false : got // parity: null ↔ backend false
  if (gotBool !== tc.expected) {
    console.log(`  ✗ ${tc.id}: expr ${JSON.stringify(tc.expr)} → ${got}, corpus says ${tc.expected}`)
    fail++
  }
}
console.log(`rules grammar parity (client): ${corpus.cases.length - fail}/${corpus.cases.length} cases match`)
process.exit(fail ? 1 : 0)
