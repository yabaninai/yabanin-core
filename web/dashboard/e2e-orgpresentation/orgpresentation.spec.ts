// CV-03 org-presentation browser acceptance — the three frozen cases.
//
// Runs ONLY under the Go stand (cv03_org_presentation_browser_int_test.go)
// against the REAL built artifact + REAL admin API + migrated Postgres.
// The stand seeds three named orgs with DISTINCT, independently pinned
// wallets (amount AND updated-at stamp) so a wrong-row read can never
// pass by rendering a different org's numbers through a different
// formatter.
//
// Ledger denomination: credit balances are USD-denominated ledger rows.
// An org's currency/timezone are DISPLAY preferences only — a non-USD
// preference labels the same USD ledger amount (e.g. "45.67 USD") and
// renders the stamp in the org's zone; there is NO FX conversion, so the
// expected strings are the same cents, differently labeled/located.
//
//   AC-OP-MEMBER  operator member: own-org wallet renders the member's
//                 JPY/Tokyo presentation, ZERO root-only directory calls
//   AC-OP-SHARE   root: the page-2 target's org GET is parked mid-flight;
//                 unmounting/remounting and re-entering the target must
//                 SHARE that one GET, then render CHF/Zurich after
//                 release — the c466995 control re-issues the GET and
//                 fails here
//   AC-OP-READER  reader: analytics (analytics.read) renders own
//                 EUR/Berlin money, ZERO directory calls, wallet stays 403
//
// All expected strings are re-derived INDEPENDENTLY in this file (Intl,
// from fixture oracle values) — product formatting code is never imported,
// so a broken formatter cannot validate itself.
import { expect, test, type Browser, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'

const BASE_URL = process.env.CV03_BASE_URL
const FIXTURE = process.env.CV03_FIXTURE

interface OrgOracle {
  id: string
  name: string
  currency: string
  timezone: string
  balance_cents: number
  updated_at: string
}

interface Fixture {
  run_id: string
  session_cookie: string
  users: { root: { cookie: string }; member: { cookie: string }; reader: { cookie: string } }
  target: OrgOracle
  member: OrgOracle
  reader: OrgOracle
  analytics: { from: string; to: string; metrics: string; expected_cost: number }
  control: { barrier_arm: string; barrier_release: string; barrier_state: string }
}

if (!BASE_URL || !FIXTURE) throw new Error('CV03_BASE_URL/CV03_FIXTURE must be set by the Go stand')
const fx: Fixture = JSON.parse(readFileSync(FIXTURE, 'utf8'))

// Independent expected-string derivation (mirror of the product contract,
// not an import of it).
const usdMoney = (v: number, currency: string): string =>
  currency === 'USD'
    ? new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(v)
    : `${new Intl.NumberFormat('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(v)} USD`
const dateTimeIn = (iso: string, tz: string): string =>
  new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: tz }).format(new Date(iso))

const userContext = async (browser: Browser, cookie: string) => {
  const ctx = await browser.newContext({ baseURL: BASE_URL, locale: 'en-US' })
  await ctx.addCookies([
    { name: fx.session_cookie, value: cookie, url: BASE_URL, httpOnly: true, sameSite: 'Lax' },
  ])
  return ctx
}

// Exact-path tally of the root-only directory listing; detail GETs and any
// tolerated root-only probe must NOT count.
const tallyDirectory = (page: Page): string[] => {
  const calls: string[] = []
  page.on('request', (r) => {
    if (new URL(r.url()).pathname === '/api/organizations') calls.push(r.url())
  })
  return calls
}

const barrierState = async (page: Page) => {
  const res = await page.request.get(BASE_URL + fx.control.barrier_state)
  return (await res.json()) as { armed: boolean; parked: number; flushed: number; cancelled: number; timed_out: number }
}

test.beforeEach(() => {
  expect(fx.run_id, 'fixture run id').toBeTruthy()
})

test('AC-OP-MEMBER member wallet renders own JPY/Tokyo presentation with zero directory calls', async ({ browser }) => {
  const ctx = await userContext(browser, fx.users.member.cookie)
  const page = await ctx.newPage()
  const dirCalls = tallyDirectory(page)

  await page.goto('/#credits')
  // autoSelect commits the member's single own org (from /api/me, not the
  // root-only directory); the USD ledger amount renders labeled by the
  // member's JPY preference, the stamp in Tokyo time.
  const strip = page.getByLabel('Credits & Billing')
  await expect(strip).toContainText(usdMoney(fx.member.balance_cents / 100, fx.member.currency))
  await expect(strip).toContainText(dateTimeIn(fx.member.updated_at, fx.member.timezone))

  expect(dirCalls, 'member session must not call the root-only directory').toHaveLength(0)
  await ctx.close()
})

test('AC-OP-SHARE remount shares the parked org GET and then renders CHF/Zurich', async ({ browser }) => {
  const ctx = await userContext(browser, fx.users.root.cookie)
  const page = await ctx.newPage()
  await page.goto('/#credits')

  // Browser-side tallies, live from before the first selection through
  // the FINAL render: the server barrier only counts GETs that arrive
  // while armed, so an org GET re-issued AFTER release would escape its
  // parked counter — this tally does not miss it. The wallet counter is
  // the observable commit signal: the remounted page re-commits the
  // target by firing its (never parked) wallet GET.
  const targetOrgGETs: string[] = []
  let targetWalletGETs = 0
  const orgPath = `/api/organizations/${fx.target.id}`
  const walletPath = `/api/orgs/${fx.target.id}/credits/balance`
  page.on('request', (r) => {
    const p = new URL(r.url()).pathname
    if (p === orgPath) targetOrgGETs.push(r.url())
    if (p === walletPath) targetWalletGETs++
  })

  // Arm, then commit the page-2 target by hand (fill commits the full id
  // in one change — the exact parked GET).
  expect((await page.request.post(BASE_URL + fx.control.barrier_arm)).status()).toBe(204)
  await page.getByLabel('Org ID').selectOption({ label: 'Enter ID manually…' })
  await page.getByLabel('org uuid').fill(fx.target.id)

  // The target's org GET is parked; the unparked wallet LANDS meanwhile
  // (observable) and renders through the PENDING presentation's USD/UTC
  // defaults — the interim state the parity fix must not freeze.
  await expect.poll(async () => (await barrierState(page)).parked).toBe(1)
  await expect.poll(() => targetWalletGETs, { timeout: 10_000 }).toBeGreaterThan(0)
  await expect(page.getByLabel('Credits & Billing')).toContainText(usdMoney(fx.target.balance_cents / 100, 'USD'))

  // Unmount (overview is root-readable), remount: autoSelect picks a
  // page-1 filler (the target is beyond page 1), then re-enter the target.
  const walletsBeforeRecommit = targetWalletGETs
  await page.goto('/#overview')
  await page.goto('/#credits')
  await page.getByLabel('Org ID').selectOption({ label: 'Enter ID manually…' })
  await page.getByLabel('org uuid').fill(fx.target.id)

  // Observable proof the re-commit fully happened: a NEW target wallet
  // GET lands and the balance is visible (still through the pending
  // presentation, still the USD-ledger default). Only NOW is the barrier
  // read meaningful — by this point an honestly re-issued org GET would
  // already be parked, and a shared one never fired a second request.
  await expect.poll(() => targetWalletGETs, { timeout: 10_000 }).toBeGreaterThan(walletsBeforeRecommit)
  await expect(page.getByLabel('Credits & Billing')).toContainText(usdMoney(fx.target.balance_cents / 100, 'USD'))
  const st = await barrierState(page)
  expect(st.parked, 'the remounted view must share the one in-flight org GET').toBe(1)
  expect(st.cancelled, 'the parked GET must never be cancelled by the remount').toBe(0)

  // Release: the single genuine org response is served through.
  expect((await page.request.post(BASE_URL + fx.control.barrier_release)).status()).toBe(204)
  await expect.poll(async () => (await barrierState(page)).flushed).toBe(1)
  const done = await barrierState(page)
  expect(done.cancelled).toBe(0)
  expect(done.timed_out).toBe(0)

  // The remounted view awaited that shared response: the USD ledger
  // amount labeled by the CHF preference and the pinned stamp rendered
  // in Zurich — not the USD/UTC defaults. The whole-session tally closes
  // the post-release window the barrier cannot see.
  const strip = page.getByLabel('Credits & Billing')
  await expect(strip).toContainText(usdMoney(fx.target.balance_cents / 100, fx.target.currency))
  await expect(strip).toContainText(dateTimeIn(fx.target.updated_at, fx.target.timezone))
  expect(targetOrgGETs, 'exactly one target org GET across the whole session, including after release').toHaveLength(1)
  await ctx.close()
})

test('AC-OP-READER analytics renders own EUR presentation with wallet still denied', async ({ browser }) => {
  const ctx = await userContext(browser, fx.users.reader.cookie)
  const page = await ctx.newPage()
  const dirCalls = tallyDirectory(page)

  const q = `m=${fx.analytics.metrics}&from=${encodeURIComponent(fx.analytics.from)}&to=${encodeURIComponent(fx.analytics.to)}`
  await page.goto(`/#analytics?${q}`)
  // GlobalScopeBar autoSelects the reader's single own org; the query
  // runs org-scoped and the USD-denominated totals render labeled by the
  // reader's EUR preference.
  const strip = page.getByLabel('Analytics explorer')
  await expect(strip).toContainText(usdMoney(fx.analytics.expected_cost, fx.reader.currency))

  expect(dirCalls, 'reader session must not call the root-only directory').toHaveLength(0)
  const wallet = await page.request.get(`${BASE_URL}/api/orgs/${fx.reader.id}/credits/balance`)
  expect(wallet.status(), 'reader must keep the budgets.manage denial').toBe(403)
  await ctx.close()
})
