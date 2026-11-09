// IMP-09 — live smoke crawl of every navigation screen against a REAL stand.
//
// Generalization of artifacts/ux-audit-2026-10-02/crawl.cjs: the same page
// set and checks as the stub-mode gate (e2e/astra/imp09-smoke.spec.ts), but
// against a running deployment. Read-only browsing — the only write is the
// login POST. Not part of any gate: a manual acceptance utility.
//
// Usage:
//   node scripts/e2e/live-smoke.cjs --base http://127.0.0.1:13000 \
//        [--pages overview,keys,...] [--viewports 1440,1024,390] \
//        [--env ~/.yabanin-opencode-stand/env] [--out <dir>] [--no-shots] [--no-fail]
//
// Credentials come from the environment (YABANIN_ADMIN_EMAIL /
// YABANIN_ADMIN_PASSWORD), optionally loaded from --env. Defaults to the
// canonical navigation set from web/dashboard/src/App.tsx NAV_SECTIONS.
//
// Per page × viewport the crawl records and judges:
//   - console errors (console.error / uncaught pageerror),
//   - 4xx/5xx responses from /api/** (unexpected on a healthy stand),
//   - i18n missing-key marker "[missing:",
//   - Go zero-time date "Jan 1, 1",
//   - the page's own heading (h1 inside main),
//   - horizontal overflow: documentElement.scrollWidth <= innerWidth + 1.
//
// Output: <out>/report.json + one screenshot per page × viewport. Exit code
// 1 when any finding is recorded (unless --no-fail).

'use strict'

const fs = require('fs')
const path = require('path')

let playwright
try {
  playwright = require('playwright')
} catch {
  console.error('live-smoke: playwright is not installed — run `npm ci` at the repo root first')
  process.exit(2)
}

// Canonical navigation pages — mirrors App.tsx NAV_SECTIONS (keep in sync).
// R101-02: synced with the stub-mode crawl after the 26→30 gap fix (+ the
// guardrails summary, D-R101-1) — the same five ids e2e/astra/
// imp09-smoke.spec.ts DASH_PAGES gained.
const CANONICAL_PAGES = [
  'overview', 'cost', 'credits',
  'requests-explorer', 'analytics', 'dashboards', 'tasks', 'tool-calls', 'lineage', 'compare',
  'cache', 'classifier', 'feedback',
  'keys', 'budgets', 'exports', 'model-access', 'members',
  'guardrails', 'models', 'rules', 'routing-map', 'tool-policy', 'policy-decisions', 'prompts', 'label-policy',
  'orgs', 'audit-log', 'admin-users', 'org-settings', 'mcp-credentials',
]

const DEFAULT_VIEWPORTS = '1440,1024,390'
const SETTLE_MS = Number(process.env.SMOKE_SETTLE_MS || 1200)
const NETWORK_IDLE_MS = 20_000

function parseArgs(argv) {
  const args = {
    base: process.env.BASE || 'http://127.0.0.1:13000',
    pages: CANONICAL_PAGES,
    viewports: DEFAULT_VIEWPORTS,
    envFile: null,
    out: null,
    shots: true,
    fail: true,
  }
  const rest = argv.slice(2)
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]
    const next = () => rest[++i]
    if (a === '--base') args.base = next().replace(/\/$/, '')
    else if (a === '--pages') args.pages = next().split(',').map(s => s.trim()).filter(Boolean)
    else if (a === '--viewports') args.viewports = next()
    else if (a === '--env') args.envFile = next()
    else if (a === '--out') args.out = next()
    else if (a === '--no-shots') args.shots = false
    else if (a === '--no-fail') args.fail = false
    else if (a === '-h' || a === '--help') args.help = true
    else {
      console.error(`live-smoke: unknown argument ${a}`)
      process.exit(2)
    }
  }
  if (args.help) {
    console.log('see the header comment of scripts/e2e/live-smoke.cjs')
    process.exit(0)
  }
  const unknown = args.pages.filter(p => !CANONICAL_PAGES.includes(p))
  if (unknown.length > 0) {
    console.error(`live-smoke: unknown page id(s): ${unknown.join(', ')}`)
    process.exit(2)
  }
  if (!args.out) {
    const run = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    args.out = path.join('artifacts', 'imp', 'smoke', run)
  }
  return args
}

function loadEnvFile(file) {
  const env = {}
  let raw
  try {
    raw = fs.readFileSync(file, 'utf8')
  } catch {
    console.error(`live-smoke: cannot read env file ${file}`)
    process.exit(2)
  }
  for (const line of raw.split('\n')) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/)
    if (m) env[m[1]] = m[2]
  }
  return env
}

async function login(page, base, creds) {
  await page.goto(`${base}/auth/login`, { waitUntil: 'networkidle' })
  await page.fill('input[name=email]', creds.email)
  await page.fill('input[name=password]', creds.password)
  await Promise.all([
    page.waitForURL(u => !String(u).includes('/auth/login'), { timeout: 15_000 }).catch(() => {}),
    page.click('button[type=submit]'),
  ])
  if (page.url().includes('/auth/login')) {
    throw new Error(`login failed — still on ${page.url()}`)
  }
}

async function crawlViewport(browser, { base, pages, width, height, shots, out, creds }) {
  // One context per viewport: the login session cookie lives (and stays)
  // inside the same context that crawls the pages.
  const context = await browser.newContext({ viewport: { width, height } })
  const report = {}
  try {
    const loginPage = await context.newPage()
    await login(loginPage, base, creds)
    await loginPage.close()

    for (const id of pages) {
      const entry = {
        viewport: { width, height },
        h1: '',
        consoleErrors: [],
        apiFailures: [],
        missingKeys: false,
        zeroDate: false,
        docWidth: null,
        overflow: null,
        ms: null,
        shot: null,
      }
      report[id] = entry
      const t0 = Date.now()
      try {
        // A fresh page per route keeps console/response listeners per-page
        // clean (same isolation as the stub spec's per-test page).
        const page = await context.newPage()
        page.on('console', msg => {
          if (msg.type() === 'error') entry.consoleErrors.push(msg.text().slice(0, 300))
        })
        page.on('pageerror', err => entry.consoleErrors.push(`pageerror: ${String(err).slice(0, 300)}`))
        page.on('response', res => {
          const u = new URL(res.url())
          if (u.pathname.startsWith('/api/') && res.status() >= 400) {
            entry.apiFailures.push(`${res.status()} ${res.request().method()} ${u.pathname}`)
          }
        })

        await page.goto(`${base}/#${id}`, { waitUntil: 'domcontentloaded' })
        await page.waitForLoadState('networkidle', { timeout: NETWORK_IDLE_MS }).catch(() => {})
        await page.waitForTimeout(SETTLE_MS)

        entry.h1 = await page.locator('main h1').first().innerText().catch(() => '')
        const body = await page.locator('body').innerText().catch(() => '')
        entry.missingKeys = body.includes('[missing:')
        entry.zeroDate = body.includes('Jan 1, 1')
        entry.docWidth = await page.evaluate(() => document.documentElement.scrollWidth)
        entry.overflow = entry.docWidth > width + 1

        if (shots) {
          const shot = path.join(out, `p-${id}-${width}.png`)
          await page.screenshot({ path: shot }).catch(() => {})
          entry.shot = path.basename(shot)
        }
        await page.close().catch(() => {})
      } catch (err) {
        entry.consoleErrors.push(`crawl-error: ${String(err).slice(0, 300)}`)
      }
      entry.ms = Date.now() - t0
    }
  } finally {
    await context.close()
  }
  return report
}

function judge(viewports) {
  const findings = []
  for (const [width, pages] of Object.entries(viewports)) {
    for (const [id, entry] of Object.entries(pages)) {
      const label = `${id}@${width}`
      if (!entry.h1) findings.push(`${label}: no page heading (h1)`)
      for (const e of entry.consoleErrors) findings.push(`${label}: console error: ${e}`)
      for (const f of entry.apiFailures) findings.push(`${label}: /api failure: ${f}`)
      if (entry.missingKeys) findings.push(`${label}: "[missing:" rendered`)
      if (entry.zeroDate) findings.push(`${label}: zero-time date "Jan 1, 1" rendered`)
      if (entry.overflow) findings.push(`${label}: horizontal overflow (${entry.docWidth}px > ${entry.viewport.width + 1}px)`)
    }
  }
  return findings
}

async function main() {
  const args = parseArgs(process.argv)
  fs.mkdirSync(args.out, { recursive: true })

  const env = args.envFile ? loadEnvFile(args.envFile) : {}
  const creds = {
    email: process.env.YABANIN_ADMIN_EMAIL || env.YABANIN_ADMIN_EMAIL,
    password: process.env.YABANIN_ADMIN_PASSWORD || env.YABANIN_ADMIN_PASSWORD,
  }
  if (!creds.email || !creds.password) {
    console.error('live-smoke: set YABANIN_ADMIN_EMAIL / YABANIN_ADMIN_PASSWORD (env or --env)')
    process.exit(2)
  }

  const browser = await playwright.chromium.launch()
  const report = {
    base: args.base,
    startedAt: new Date().toISOString(),
    pages: args.pages,
    viewports: {},
    findings: [],
  }

  try {
    // Login once per viewport: sessions are cookie-scoped per context, and
    // the crawl context is created inside crawlViewport.
    for (const vp of args.viewports.split(',').map(s => Number(s.trim())).filter(Boolean)) {
      const height = vp >= 1024 ? 900 : 844
      report.viewports[String(vp)] = await crawlViewport(browser, {
        base: args.base,
        pages: args.pages,
        width: vp,
        height,
        shots: args.shots,
        out: args.out,
        creds,
      })
      console.log(`[live-smoke] viewport ${vp}: ${args.pages.length} pages crawled`)
    }
  } finally {
    await browser.close()
  }

  report.findings = judge(report.viewports)
  report.finishedAt = new Date().toISOString()
  const reportPath = path.join(args.out, 'report.json')
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2))

  console.log(`[live-smoke] ${args.pages.length * Object.keys(report.viewports).length} crawls, ` +
    `${report.findings.length} finding(s)`)
  for (const f of report.findings.slice(0, 40)) console.log(`  - ${f}`)
  if (report.findings.length > 40) console.log(`  … ${report.findings.length - 40} more in ${reportPath}`)
  console.log(`[live-smoke] report: ${reportPath}`)

  if (report.findings.length > 0 && args.fail) process.exit(1)
}

main().catch(e => {
  console.error(e)
  process.exit(1)
})
