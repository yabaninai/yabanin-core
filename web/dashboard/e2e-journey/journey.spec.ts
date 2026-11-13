// CV-02 request-journey browser acceptance — REAL end-to-end suite.
//
// Drives the REAL dashboard artifact (web/dashboard/dist, served by the Go
// stand at the same origin as the REAL admin API) over a REAL, fully
// migrated disposable Postgres seeded by the stand with two tenants and
// five request rows. Expectations come from the FIXTURE written by the Go
// stand — the raw request_logs column values read back by direct SQL
// (independent store oracle) — plus the documented rendering contract
// restated below in local formatters. Nothing imports the product's own
// view model to compute its own expected answer.
//
// Coverage (each scenario is a named acceptance contract):
//   AC-RT     stored facts round-trip: DB oracle == API payload == page
//   AC-BLK    pre-upstream termination renders NO attempt facts (≠ zero)
//   AC-UNK    unknown counters render "not recorded" (≠ 0/1)
//   AC-ZERO   recorded zeros render as real zeros (≠ "not recorded")
//   AC-STALE  tenant switch clears the previous tenant's facts
//   AC-IDOR   unauthorized deep link to another tenant is refused, no leak
//   AC-KB     keyboard-only navigation reaches the journey view
//   AC-NARROW 390px viewport keeps the journey usable
//   AC-PERF   deep-link and row-click render timings (documented method)
//
// Run through the Go stand (see playwright.journey.config.ts header).
import { expect, test, type Page } from '@playwright/test'
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

// ---------------------------------------------------------------------------
// Fixture (written by the Go stand; raw SQL read-back = store oracle)
// ---------------------------------------------------------------------------

interface DecisionDoc {
  source: string
  from?: string
  to?: string
  class?: string
  confidence?: number
  threshold?: number
  reason?: string
  rule?: { id?: string; version?: string }
}

interface Oracle {
  method: string
  model_requested: string
  model_used: string
  status_code: number
  duration_ms: number
  tokens_in: number
  tokens_out: number
  attempt_count: number | null
  retry_count: number | null
  first_token_ms: number | null
  routing_decision: string | null
  classifier_class: string | null
  classifier_confidence: number | null
  classifier_source: string | null
  cache_hit_type: string | null
  upstream_url: string | null
  error: string | null
  answer_status: string | null
}

interface FixtureRow { org: 'a' | 'b'; request_id: string; oracle: Oracle }

interface Fixture {
  run_id: string
  session_cookie: string
  orgs: { a: { id: string; name: string }; b: { id: string; name: string } }
  users: { a_only: { cookie: string }; both: { cookie: string } }
  rows: { served: FixtureRow; blocked: FixtureRow; legacy: FixtureRow; zero: FixtureRow; tenantb: FixtureRow }
}

const BASE_URL = process.env.CV02_BASE_URL
const fixturePath = process.env.CV02_FIXTURE
if (!BASE_URL || !fixturePath) throw new Error('CV02_BASE_URL/CV02_FIXTURE not set — run under the Go stand')
const fixture: Fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
const artifacts = process.env.CV02_ARTIFACTS ?? '.'

// Cross-tenant marker strings that must NEVER render for the wrong tenant.
const TENANT_B_MARKERS = [
  fixture.rows.tenantb.oracle.model_used,
  ...(fixture.rows.tenantb.oracle.error ? [fixture.rows.tenantb.oracle.error] : []),
  ...(fixture.rows.tenantb.oracle.answer_content ? [fixture.rows.tenantb.oracle.answer_content] : []),
]

// ---------------------------------------------------------------------------
// Rendering contract, restated here independently of the product code
// (expected visible text derived from the oracle values + en.json copy)
// ---------------------------------------------------------------------------

const COPY = {
  journeyHeading: 'Recorded journey',
  unknown: 'not recorded',
  blockedTitle: 'No upstream attempt',
  blockedDetail: (status: number) =>
    `Terminated before reaching a model — nothing was sent upstream (status ${status}).`,
  decisionNotRecorded: 'No routing decision recorded (legacy row)',
  upstreamUrlNotRecorded: 'upstream URL not recorded (no originals access, or none captured)',
  cacheNone: 'no cache hit',
  noErrorDetail: 'no error detail recorded',
  answerAbsent: 'served answer not recorded (legacy row)',
  answerComplete: 'Complete',
  perAttemptNote: 'Per-attempt timing and outcomes are not recorded — only per-request totals.',
  requestUnknownTitle: 'Request not found in the log',
}

/** Contract: null counter ⇒ "not recorded"; a real number renders verbatim. */
function counterText(v: number | null): string {
  return v === null ? COPY.unknown : String(v)
}

/** Contract: attempts · retries · TTFT compact line (served branch only). */
function countersLine(o: Oracle): string {
  return `Fallback attempts: ${counterText(o.attempt_count)} · Intra-model retries: ${counterText(o.retry_count)} · Time to first token, ms: ${counterText(o.first_token_ms)}`
}

/** Contract: "⚠ source: from → to (class @conf/threshold reason)" for a
 * cross-route move; "passthrough: model" for an unchanged route. */
function decisionMeta(d: DecisionDoc): string[] {
  const meta: string[] = []
  if (d.class) meta.push(d.class)
  if (typeof d.confidence === 'number') {
    meta.push(`@${d.confidence.toFixed(2)}${typeof d.threshold === 'number' ? `/${d.threshold}` : ''}`)
  }
  if (d.reason) meta.push(d.reason)
  return meta
}

function decisionText(raw: string): string {
  const d = JSON.parse(raw) as DecisionDoc
  const parts: string[] = []
  if (d.source === 'passthrough') parts.push(`passthrough: ${d.from ?? ''}`)
  else if (d.from && d.to && d.from !== d.to) parts.push(`⚠ ${d.source}: ${d.from} → ${d.to}`)
  else parts.push(`${d.source}: ${d.to || d.from} kept`)
  const meta = decisionMeta(d)
  if (meta.length > 0) parts.push(`(${meta.join(' ')})`)
  return parts.join(' ')
}

/** Contract: "rule <first 8 chars> · v<version>" chip (CORE-TRACE-04). */
function ruleChipText(raw: string): string {
  const d = JSON.parse(raw) as DecisionDoc
  if (!d.rule?.id) return ''
  const short = d.rule.id.length > 8 ? d.rule.id.slice(0, 8) : d.rule.id
  const version = d.rule.version ? ` · v${d.rule.version}` : ''
  return `rule ${short}${version}`
}

// ---------------------------------------------------------------------------
// Page helpers
// ---------------------------------------------------------------------------

/** Opens a fresh logged-in page in a NEW browser context (stand-minted
 * session cookie) derived from the test's browser. */
async function pageAsFrom(
  page: Page,
  who: 'a_only' | 'both',
  viewport?: { width: number; height: number },
): Promise<Page> {
  const ctx = await page.context().browser()!.newContext({
    baseURL: BASE_URL,
    locale: 'en-US',
    ...(viewport ? { viewport } : {}),
  })
  await ctx.addCookies([{
    name: fixture.session_cookie,
    value: fixture.users[who].cookie,
    url: BASE_URL,
    httpOnly: true,
    sameSite: 'Lax',
  }])
  const p = await ctx.newPage()
  // Best-effort 4xx/5xx log — the stand's artifacts keep the exact request
  // that failed, which is the first question any red run asks.
  p.on('response', res => {
    if (res.status() >= 400) {
      try {
        appendFileSync(join(artifacts, 'http-errors.log'),
          `${new Date().toISOString()} ${res.status()} ${res.request().method()} ${res.url()}\n`)
      } catch { /* diagnostics only */ }
    }
  })
  return p
}

/** Opens a deep link into the inspector drawer for one seeded row. */
async function openJourney(p: Page, row: FixtureRow): Promise<void> {
  const orgId = fixture.orgs[row.org].id
  await p.goto(`/#requests-explorer?org=${orgId}&inspect=request:${row.request_id}`)
  await expect(p.getByRole('heading', { name: COPY.journeyHeading, exact: true })).toBeVisible({ timeout: 20_000 })
}

// Journey stages are data-testid targets; the classifier chip is a span
// inside the decision li, so match the attribute, not a tag.
const stage = (p: Page, id: string) => p.locator(`[data-testid="journey-${id}"]`)

/** Stage 2: routing decision + classifier chip. */
async function expectDecisionStage(p: Page, o: Oracle): Promise<void> {
  if (o.routing_decision !== null) {
    await expect(stage(p, 'decision')).toContainText(decisionText(o.routing_decision))
    const chip = ruleChipText(o.routing_decision)
    if (chip) await expect(stage(p, 'decision')).toContainText(chip)
  } else {
    await expect(stage(p, 'decision')).toContainText(COPY.decisionNotRecorded)
  }
  if (o.classifier_class) {
    const conf = o.classifier_confidence === null ? '' : ` @${o.classifier_confidence.toFixed(2)}`
    const src = o.classifier_source ? ` (${o.classifier_source})` : ''
    await expect(stage(p, 'classifier')).toContainText(`Classifier: ${o.classifier_class}${conf}${src}`)
  } else {
    await expect(stage(p, 'classifier')).toHaveCount(0)
  }
}

/** Stage 3: upstream serving, with the policy-gated upstream URL taken from
 * the REAL API payload so UI == API == DB holds under whatever the ACL exposes. */
async function expectUpstreamStage(p: Page, o: Oracle, detail: Record<string, unknown>): Promise<void> {
  await expect(stage(p, 'upstream')).toContainText(o.model_used)
  await expect(stage(p, 'upstream')).toContainText(`${o.status_code} · ${o.duration_ms} ms`)
  await expect(stage(p, 'upstream')).toContainText(countersLine(o))
  const apiUpstream = detail.upstream_url
  if (typeof apiUpstream === 'string' && apiUpstream) {
    await expect(stage(p, 'upstream')).toContainText(apiUpstream)
  } else {
    await expect(stage(p, 'upstream')).toContainText(COPY.upstreamUrlNotRecorded)
  }
}

/** Stage 4: outcome — status, error (policy-gated via the API payload),
 * cache hit, tokens and the answer-view presence. */
async function expectResponseStage(p: Page, o: Oracle, detail: Record<string, unknown>): Promise<void> {
  await expect(stage(p, 'response')).toContainText(String(o.status_code))
  const apiError = detail.error
  if (typeof apiError === 'string' && apiError) {
    await expect(stage(p, 'response')).toContainText(apiError)
  } else if (o.status_code >= 400) {
    await expect(stage(p, 'response')).toContainText(COPY.noErrorDetail)
  }
  const apiCache = detail.cache_hit_type
  await expect(stage(p, 'response')).toContainText(
    typeof apiCache === 'string' && apiCache ? `Cache hit: ${apiCache}` : `Cache hit: ${COPY.cacheNone}`,
  )
  await expect(stage(p, 'response')).toContainText(`${o.tokens_in} → ${o.tokens_out}`)
  await expect(stage(p, 'response')).toContainText(
    o.answer_status === 'complete' ? COPY.answerComplete : COPY.answerAbsent,
  )
  await expect(p.getByText(COPY.perAttemptNote)).toBeVisible()
}

/** Asserts the whole journey matches the oracle for a SERVED row, taking the
 * policy-gated fields (error text, upstream URL, cache type) from the REAL
 * API payload so UI == API == DB holds under whatever the ACL exposes. */
async function expectServedJourney(p: Page, row: FixtureRow, detail: Record<string, unknown>): Promise<void> {
  const o = row.oracle
  await expect(stage(p, 'request')).toContainText(o.method)
  await expect(stage(p, 'request')).toContainText(o.model_requested)
  await expectDecisionStage(p, o)
  await expectUpstreamStage(p, o, detail)
  await expectResponseStage(p, o, detail)
}

/** Screenshots into the stand-provided artifacts dir and attaches them. */
async function shot(p: Page, name: string): Promise<void> {
  const path = join(artifacts, `${name}.png`)
  mkdirSync(artifacts, { recursive: true })
  await p.screenshot({ path })
  await test.info().attach(name, { path })
}

/** Fetches the org-scoped detail with the SAME cookie jar as the page. */
async function apiDetail(p: Page, row: FixtureRow): Promise<{ status: number; body: Record<string, unknown> }> {
  const orgId = fixture.orgs[row.org].id
  const res = await p.context().request.get(`/api/organizations/${orgId}/requests/${row.request_id}`)
  let body: Record<string, unknown> = {}
  try { body = (await res.json()) as Record<string, unknown> } catch { /* non-JSON denial body */ }
  return { status: res.status(), body }
}

// ---------------------------------------------------------------------------
// AC-RT — stored values round-trip through the REAL artifact
// ---------------------------------------------------------------------------

test('AC-RT stored journey facts round-trip: DB oracle == API payload == rendered page', async ({ page }) => {
  const p = await pageAsFrom(page, 'a_only')
  const row = fixture.rows.served
  const { status, body } = await apiDetail(p, row)
  expect(status, 'org-admin detail fetch must succeed').toBe(200)
  // API == store oracle, field by field (independent of any UI rendering).
  const o = row.oracle
  expect(body.model_used).toBe(o.model_used)
  expect(body.status_code).toBe(o.status_code)
  expect(body.duration_ms).toBe(o.duration_ms)
  expect(body.attempt_count).toBe(o.attempt_count)
  expect(body.retry_count).toBe(o.retry_count)
  expect(body.first_token_ms).toBe(o.first_token_ms)
  expect(body.routing_decision).toBe(o.routing_decision)
  expect(body.classifier_class).toBe(o.classifier_class)
  expect(body.classifier_confidence).toBe(o.classifier_confidence)
  expect(body.classifier_source).toBe(o.classifier_source)
  // FIX-20 envelope exposure: the org-admin payload grant carries the parsed
  // model_response view — status and the exact client-facing content.
  expect(body.response_view?.status).toBe('complete')
  expect(body.response_view?.model).toBe(o.model_used)
  if (o.answer_content) expect(body.response_view?.content).toBe(o.answer_content)
  expect(body.tokens_in).toBe(o.tokens_in)
  expect(body.tokens_out).toBe(o.tokens_out)
  // Page == the same oracle (deep link into the inspector drawer).
  await openJourney(p, row)
  await expectServedJourney(p, row, body)
  await shot(p, 'ac-rt-served')
  await p.close()
})

// ---------------------------------------------------------------------------
// AC-BLK — a pre-upstream termination is visibly distinct from a zero-valued
// row: NO attempt facts render at all (NULL counters, not 0)
// ---------------------------------------------------------------------------

test('AC-BLK blocked termination renders no attempt facts, never zeros', async ({ page }) => {
  const p = await pageAsFrom(page, 'a_only')
  const row = fixture.rows.blocked
  const o = row.oracle
  expect(o.model_used, 'stand contract: model_used === "" marks the blocked row').toBe('')
  expect(o.attempt_count).toBeNull()
  expect(o.retry_count).toBeNull()
  expect(o.first_token_ms).toBeNull()
  const { body } = await apiDetail(p, row)
  // The blocked row is OWNED by this console user: the own-row payload grant
  // carries the recorded error text through the real API and UI.
  expect(body.error).toBe(o.error)
  await openJourney(p, row)
  await expect(p.getByTestId('journey-blocked')).toContainText(COPY.blockedTitle)
  await expect(p.getByTestId('journey-blocked')).toContainText(COPY.blockedDetail(o.status_code))
  // The negative: NO attempt-shaped facts anywhere in the upstream stage.
  await expect(stage(p, 'upstream')).not.toContainText('Fallback attempts')
  await expect(stage(p, 'upstream')).not.toContainText('Intra-model retries')
  await expect(stage(p, 'upstream')).not.toContainText('Time to first token')
  await expect(stage(p, 'upstream')).not.toContainText('0 ms')
  // The outcome stage still reports the real status + recorded error.
  await expect(stage(p, 'response')).toContainText(String(o.status_code))
  if (typeof body.error === 'string' && body.error) {
    await expect(stage(p, 'response')).toContainText(body.error)
  }
  await shot(p, 'ac-blk-blocked')
  await p.close()
})

// ---------------------------------------------------------------------------
// AC-UNK — NULL counters on a SERVED row are "not recorded", not 0/1
// ---------------------------------------------------------------------------

test('AC-UNK unknown counters render as not-recorded, never as 0 or 1', async ({ page }) => {
  const p = await pageAsFrom(page, 'a_only')
  const row = fixture.rows.legacy
  const o = row.oracle
  expect(o.attempt_count).toBeNull()
  await openJourney(p, row)
  await expect(stage(p, 'upstream')).toContainText(countersLine(o))
  await expect(stage(p, 'upstream')).not.toContainText('Fallback attempts: 0')
  await expect(stage(p, 'upstream')).not.toContainText('Fallback attempts: 1')
  await expect(stage(p, 'decision')).toContainText(COPY.decisionNotRecorded)
  await expect(stage(p, 'response')).toContainText(COPY.answerAbsent)
  await shot(p, 'ac-unk-legacy')
  await p.close()
})

// ---------------------------------------------------------------------------
// AC-ZERO — recorded zeros are real zeros (the positive twin of AC-UNK)
// ---------------------------------------------------------------------------

test('AC-ZERO recorded zero counters render as explicit zeros', async ({ page }) => {
  const p = await pageAsFrom(page, 'a_only')
  const row = fixture.rows.zero
  const o = row.oracle
  expect(o.retry_count, 'stand contract: zero row records retry_count = 0').toBe(0)
  await openJourney(p, row)
  await expect(stage(p, 'upstream')).toContainText(countersLine(o))
  await expect(stage(p, 'upstream')).toContainText('Intra-model retries: 0')
  await expect(stage(p, 'upstream')).not.toContainText(`Intra-model retries: ${COPY.unknown}`)
  // Failing status with an empty error string states the absence.
  await expect(stage(p, 'response')).toContainText(String(o.status_code))
  await expect(stage(p, 'response')).toContainText(COPY.noErrorDetail)
  await shot(p, 'ac-zero-retry')
  await p.close()
})

// ---------------------------------------------------------------------------
// AC-STALE — switching tenant clears the previous tenant's facts
// ---------------------------------------------------------------------------

test('AC-STALE tenant switch clears the previous tenant journey from the drawer', async ({ page }) => {
  const p = await pageAsFrom(page, 'both')
  const served = fixture.rows.served
  const tenantb = fixture.rows.tenantb
  const orgB = fixture.orgs.b.id
  // Tenant A journey is open and showing A facts.
  await openJourney(p, served)
  await expect(stage(p, 'upstream')).toContainText(served.oracle.model_used)
  await shot(p, 'ac-stale-before-switch')
  // The drawer is modal (backdrop traps pointer events): close it first,
  // like a real user, then switch the org scope to tenant B through the
  // real shell org switcher (combobox button + listbox).
  await p.keyboard.press('Escape')
  await expect(p.getByRole('heading', { name: COPY.journeyHeading, exact: true })).toHaveCount(0)
  await p.getByRole('button', { name: /org switcher/i }).click()
  await p.locator(`#org-switcher-option-${orgB}`).click()
  // B's list loads (its own row appears — no request-id column exists, so
  // key on B's unique model)…
  await expect(p.locator('table')).toContainText(tenantb.oracle.model_used, { timeout: 20_000 })
  // …and A's journey deep-linked under B's scope must be refused. A hash-only
  // goto is a same-document navigation (the app reads inspect at mount), so
  // reload once — exactly what a user opening a shared deep link gets.
  await p.goto(`/#requests-explorer?org=${orgB}&inspect=request:${served.request_id}`)
  await p.reload()
  await expect(p.getByText(COPY.requestUnknownTitle, { exact: false })).toBeVisible({ timeout: 20_000 })
  await expect(p.getByRole('heading', { name: COPY.journeyHeading, exact: true })).toHaveCount(0)
  await expect(p.locator('body')).not.toContainText(`Fallback attempts: ${served.oracle.attempt_count}`)
  await expect(p.locator('body')).not.toContainText(`${served.oracle.duration_ms} ms`)
  for (const marker of TENANT_B_MARKERS) {
    await expect(p.locator('body')).not.toContainText(marker)
  }
  await shot(p, 'ac-stale-after-switch')
  await p.close()
})

// ---------------------------------------------------------------------------
// AC-IDOR — a deep link into another tenant's journey is refused and leaks
// nothing (403/404 at the API, notice in the UI, no marker strings in DOM)
// ---------------------------------------------------------------------------

test('AC-IDOR unauthorized deep link to a foreign tenant is refused without leaks', async ({ page }) => {
  const p = await pageAsFrom(page, 'a_only')
  const tenantb = fixture.rows.tenantb
  const orgB = fixture.orgs.b.id
  // API negative probes with the same credential: list and detail under B.
  const listRes = await p.context().request.get(`/api/organizations/${orgB}/requests`)
  expect(listRes.status(), 'foreign list must be denied with 4xx').toBeGreaterThanOrEqual(400)
  const detailRes = await p.context().request.get(`/api/organizations/${orgB}/requests/${tenantb.request_id}`)
  expect(detailRes.status(), 'foreign detail must be denied with 4xx').toBeGreaterThanOrEqual(400)
  // UI deep link straight into B's row: refused honestly, zero B facts.
  await p.goto(`/#requests-explorer?org=${orgB}&inspect=request:${tenantb.request_id}`)
  await expect(p.getByText(COPY.requestUnknownTitle, { exact: false })).toBeVisible({ timeout: 20_000 })
  const bodyText = await p.locator('body').innerText()
  for (const marker of TENANT_B_MARKERS) {
    expect(bodyText, `cross-tenant marker must not render: ${marker}`).not.toContain(marker)
  }
  await shot(p, 'ac-idor-refused')
  await p.close()
})

// ---------------------------------------------------------------------------
// AC-KB — keyboard-only navigation reaches the journey view
// ---------------------------------------------------------------------------

test('AC-KB keyboard-only navigation reaches the journey view (Tab + Enter)', async ({ page }) => {
  const p = await pageAsFrom(page, 'a_only')
  const orgA = fixture.orgs.a.id
  await p.goto(`/#requests-explorer?org=${orgA}`)
  await expect(p.locator('table')).toContainText(fixture.rows.served.oracle.model_used, { timeout: 20_000 })
  // Tab until THIS row's actions toggle («⋯», labeled «Actions: <id>»)
  // carries focus; Enter opens its menu.
  const servedToggleLabel = `Actions: ${fixture.rows.served.request_id}`
  let focusedToggle = false
  for (let i = 0; i < 120 && !focusedToggle; i++) {
    await p.keyboard.press('Tab')
    focusedToggle = await p.evaluate(label => {
      const el = document.activeElement as HTMLElement | null
      return el?.getAttribute('aria-label') === label
    }, servedToggleLabel)
  }
  expect(focusedToggle, 'a row actions toggle must receive focus by keyboard alone').toBe(true)
  await p.keyboard.press('Enter') // opens the menu
  // DOM order puts the first menuitem («Inspect») next in the tab sequence.
  await p.keyboard.press('Tab')
  await p.keyboard.press('Enter') // activates «Inspect»
  await expect(p.getByRole('heading', { name: COPY.journeyHeading, exact: true })).toBeVisible({ timeout: 20_000 })
  await expect(stage(p, 'upstream')).toContainText(fixture.rows.served.oracle.model_used)
  await shot(p, 'ac-kb-journey')
  await p.close()
})

// ---------------------------------------------------------------------------
// AC-NARROW — 390px viewport keeps the journey readable
// ---------------------------------------------------------------------------

test.describe('AC-NARROW 390px viewport', () => {
  const NARROW = { width: 390, height: 844 }

  test('journey stages stay visible without the blocked node on a served row', async ({ page }) => {
    const p = await pageAsFrom(page, 'a_only', NARROW)
    await openJourney(p, fixture.rows.served)
    for (const id of ['request', 'decision', 'upstream', 'response']) {
      await expect(stage(p, id)).toBeVisible()
    }
    await expect(p.getByTestId('journey-blocked')).toHaveCount(0)
    await shot(p, 'ac-narrow-served')
    await p.close()
  })

  test('blocked row states its termination at 390px too', async ({ page }) => {
    const p = await pageAsFrom(page, 'a_only', NARROW)
    await openJourney(p, fixture.rows.blocked)
    await expect(p.getByTestId('journey-blocked')).toContainText(COPY.blockedTitle)
    await shot(p, 'ac-narrow-blocked')
    await p.close()
  })
})

// ---------------------------------------------------------------------------
// AC-PERF — render cost of the journey view (documented, informational):
// goto() at 'commit' then wait for the journey heading; and the row-click
// path from the loaded list. Headless chromium on the stand host; numbers
// are recorded in artifacts/journey-timings.json — a coarse 15s ceiling
// guards against catastrophic regressions, not a lab benchmark.
// ---------------------------------------------------------------------------

test('AC-PERF journey render timings (deep link and row click)', async ({ page }) => {
  test.setTimeout(240_000) // six fresh browser boots live in one test
  const timings: Array<{ case: string; iteration: number; ms: number }> = []
  const served = fixture.rows.served
  const orgA = fixture.orgs.a.id

  for (let i = 1; i <= 3; i++) {
    const p = await pageAsFrom(page, 'a_only')
    const t0 = Date.now()
    await p.goto(`/#requests-explorer?org=${orgA}&inspect=request:${served.request_id}`, { waitUntil: 'commit' })
    await p.getByRole('heading', { name: COPY.journeyHeading, exact: true }).waitFor()
    const ms = Date.now() - t0
    timings.push({ case: 'deep-link-commit-to-journey', iteration: i, ms })
    expect(ms, 'deep-link render must stay well under 15s').toBeLessThan(15_000)
    await p.close()
  }

  for (let i = 1; i <= 3; i++) {
    const p = await pageAsFrom(page, 'a_only')
    await p.goto(`/#requests-explorer?org=${orgA}`)
    // The request-id has no column; this row is the only one on the model.
    const rowLoc = p.locator('tbody tr').filter({ hasText: served.oracle.model_used })
    await rowLoc.first().waitFor({ timeout: 20_000 })
    const t0 = Date.now()
    await rowLoc.first().click()
    await p.getByRole('heading', { name: COPY.journeyHeading, exact: true }).waitFor()
    const ms = Date.now() - t0
    timings.push({ case: 'row-click-to-journey', iteration: i, ms })
    expect(ms, 'row-click render must stay well under 15s').toBeLessThan(15_000)
    await p.close()
  }

  const path = join(artifacts, 'journey-timings.json')
  mkdirSync(artifacts, { recursive: true })
  writeFileSync(path, JSON.stringify({
    run_id: fixture.run_id,
    method: 'Date.now() delta: goto(waitUntil:commit)→journey heading visible; and table row click→heading visible; headless chromium',
    timings,
  }, null, 2))
  await test.info().attach('journey-timings', { path })
})
