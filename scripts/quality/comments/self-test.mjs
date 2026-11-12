#!/usr/bin/env node
// Self-test for check.mjs. Runs the real CLI against every fixture pair and
// asserts the exact result, exit code and a diagnostic substring, so the
// negative controls prove the intended failure mode rather than any failure.
//
// Usage: node scripts/quality/comments/self-test.mjs   (exit 0 = all as expected)
import { spawnSync } from 'node:child_process'
import { readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(scriptDir, 'fixtures')

// expectedResult -> process exit code (mirrors check.mjs contract)
const EXIT_FOR = { PASS: 0, FAIL: 1, FLAG: 2 }

// name is the prefix of each fixture directory; `contains` pins the reason
// (string or list — every element must appear in the checker output).
const EXPECTATIONS = [
  { name: 'pass-comment-churn', result: 'PASS', contains: 'summary: 1 pass, 0 flag, 0 fail' },
  { name: 'pass-tsx-comment-churn', result: 'PASS', contains: 'summary: 1 pass, 0 flag, 0 fail' },
  { name: 'pass-jsdoc-reword', result: 'PASS', contains: 'summary: 1 pass, 0 flag, 0 fail' },
  { name: 'fail-token-edit', result: 'FAIL', contains: ['token #', '"active"', '"enabled"'] },
  { name: 'fail-asi-hazard', result: 'FAIL', contains: 'ASI hazard' },
  { name: 'flag-ts-ignore-removed', result: 'FLAG', contains: 'removed ts-pragma directive' },
  { name: 'flag-eslint-directive-added', result: 'FLAG', contains: 'added eslint-directive' },
  { name: 'flag-license-changed', result: 'FLAG', contains: 'removed license' },
  { name: 'flag-triple-slash-added', result: 'FLAG', contains: 'added triple-slash' },
]

function pairFor(caseName) {
  const caseDir = join(fixturesDir, caseName)
  const files = readdirSync(caseDir)
  const oldFile = files.find((f) => f.startsWith('old.'))
  const newFile = files.find((f) => f.startsWith('new.'))
  if (!oldFile || !newFile) throw new Error(`fixture ${caseName} must contain old.* and new.*`)
  return [join(caseDir, oldFile), join(caseDir, newFile)]
}

function runCheck(args) {
  const run = spawnSync(process.execPath, [join(scriptDir, 'check.mjs'), ...args], { encoding: 'utf8' })
  return { status: run.status, stdout: run.stdout, stderr: run.stderr }
}

const cases = [...EXPECTATIONS]
// Control: comparing a file with itself must pass cleanly.
cases.push({
  name: 'identical-file-control',
  result: 'PASS',
  contains: 'summary: 1 pass, 0 flag, 0 fail',
  args: pairFor('pass-comment-churn').slice(0, 1).flatMap((old) => [old, old]),
})

let failures = 0
for (const expectation of cases) {
  const args = expectation.args ?? pairFor(expectation.name)
  const run = runCheck(args)
  const problems = []
  if (run.status !== EXIT_FOR[expectation.result]) {
    problems.push(`exit ${run.status}, want ${EXIT_FOR[expectation.result]}`)
  }
  const output = `${run.stdout}\n${run.stderr}`
  const needles = Array.isArray(expectation.contains) ? expectation.contains : [expectation.contains]
  for (const needle of needles) {
    if (!output.includes(needle)) problems.push(`output missing ${JSON.stringify(needle)}`)
  }
  if (expectation.result === 'FLAG' || expectation.result === 'FAIL') {
    // The negative-control guarantee: a directive change or token change must
    // never be reported as a clean pass.
    if (run.status === 0) problems.push('silently passed')
  }
  const verdict = problems.length === 0 ? 'ok' : `BAD (${problems.join('; ')})`
  console.log(`${verdict.padEnd(12)} ${expectation.name}: expect ${expectation.result}`)
  if (problems.length > 0) {
    failures += 1
    console.log(run.stdout.trim())
    if (run.stderr.trim()) console.log(run.stderr.trim())
  }
}

console.log(failures === 0 ? 'self-test: all cases as expected' : `self-test: ${failures} case(s) off`)
process.exit(failures === 0 ? 0 : 1)
