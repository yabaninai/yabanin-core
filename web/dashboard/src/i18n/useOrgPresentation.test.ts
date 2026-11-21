import assert from 'node:assert/strict'
import { describe, it, beforeEach } from 'node:test'
import { resetMeCache, requestMe, type Me } from '../hooks/usePermissions.ts'
import {
  beginDirectory,
  beginOrgDetail,
  directoryExtra,
  directorySnapshot,
  identityKey,
  mayResolveDetail,
  memberOrgs,
  resetDirectory,
  resolveOrgPresentation,
  wantDirectory,
} from './useOrgPresentation.ts'
import type { Organization } from '../api/orgs.ts'

// Tenant UI/API parity contract for the org-presentation pool:
//   * a reader resolves presentation (and OrgSelect options) from /api/me
//     alone — zero root-only directory requests, even while /api/me is
//     still pending (no doomed 403 on a fresh stand);
//   * the fail-open /api/me-unavailable case keeps the legacy directory
//     behavior;
//   * the directory cache is identity-scoped and generation-guarded: a
//     late completion after a reload/identity switch is discarded, and a
//     different identity never reuses the previous listing;
//   * the reload sequence (resetMeCache + resetDirectory + fresh /api/me)
//     updates a mounted member's pool (new memberships appear);
//   * presentation is authoritative store data with USD/UTC defaults for
//     unset values and foreign orgs; root resolves page-2+ orgs through the
//     supported single-org GET instead of defaulting, and a member never
//     fires that root-only route.

type FetchCall = { url: string; resolve: (body: unknown) => void; reject: (err: unknown) => void }

let calls: FetchCall[] = []

function stubFetch(): void {
  // @ts-expect-error — a minimal fetch stub is enough for the contract.
  globalThis.fetch = (url: string) => new Promise((res, rej) => {
    calls.push({
      url,
      resolve: (body: unknown) => {
        res(new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      },
      reject: (err: unknown) => rej(err),
    })
  })
}

function dirCalls(): number {
  return calls.filter(c => c.url.includes('/organizations')).length
}

const memberMe: Me = {
  id: 'm1',
  name: 'Reader',
  email: 'reader@example.test',
  is_root: false,
  organizations: [
    { id: 'org-a', name: 'Org A', role: 'reader', permissions: ['analytics.read'], slug: 'acme', currency: 'EUR', timezone: 'Europe/Berlin' },
  ],
}

describe('useOrgPresentation org pool (tenant parity)', () => {
  beforeEach(() => {
    resetMeCache()
    resetDirectory()
    calls = []
    stubFetch()
  })

  it('delayed /api/me reader: zero directory fetches, presentation from /api/me alone', async () => {
    const pending = requestMe()
    assert.equal(calls.length, 1)
    // While /api/me is pending the identity is unknown: never fetch.
    assert.equal(wantDirectory(true, null), false)
    calls[0]!.resolve(memberMe)
    const me = await pending
    // A member may never list the directory either.
    assert.equal(wantDirectory(false, me), false)
    assert.equal(dirCalls(), 0, 'reader fired a root-only directory request')

    const orgs = memberOrgs(me!)
    assert.equal(resolveOrgPresentation(orgs, 'org-a').currency, 'EUR')
    assert.equal(resolveOrgPresentation(orgs, 'org-a').timezone, 'Europe/Berlin')
    assert.equal(resolveOrgPresentation(orgs, 'acme').currency, 'EUR', 'slug lookup')
  })

  it('foreign org id resolves to defaults — member never sees foreign presentation', async () => {
    const orgs = memberOrgs(memberMe)
    assert.deepEqual(resolveOrgPresentation(orgs, 'org-foreign'), { currency: 'USD', timezone: 'UTC' })
    assert.deepEqual(resolveOrgPresentation(orgs, ''), { currency: 'USD', timezone: 'UTC' })
  })

  it('authoritative values with USD/UTC defaults for unset/invalid fields', () => {
    const orgs: Organization[] = [
      { id: 'o1', name: 'One', slug: 'one' }, // nothing set
      { id: 'o2', name: 'Two', slug: 'two', currency: 'sgd', timezone: 'Asia/Singapore' },
      { id: 'o3', name: 'Three', slug: 'three', currency: 'XX', timezone: '' }, // invalid shapes
    ]
    assert.deepEqual(resolveOrgPresentation(orgs, 'o1'), { currency: 'USD', timezone: 'UTC' })
    assert.deepEqual(resolveOrgPresentation(orgs, 'o2'), { currency: 'SGD', timezone: 'Asia/Singapore' })
    assert.deepEqual(resolveOrgPresentation(orgs, 'o3'), { currency: 'USD', timezone: 'UTC' })
  })

  it('fail-open: unavailable /api/me keeps the legacy directory behavior', async () => {
    const pending = requestMe()
    calls[0]!.reject(new TypeError('me unavailable'))
    const me = await pending
    assert.equal(me, null)
    assert.equal(wantDirectory(false, null), true)
    // Drive the same call the hook makes for the fail-open case.
    const listing = beginDirectory(null)
    assert.equal(dirCalls(), 1)
    calls[1]!.resolve({ data: [{ id: 'org-a', name: 'Org A', currency: 'GBP' }] })
    const rows = await listing
    assert.equal(resolveOrgPresentation(rows, 'org-a').currency, 'GBP')
    assert.deepEqual(directorySnapshot(), { identity: identityKey(null), rows })
  })

  it('late stale root completion after identity switch is discarded, never committed', async () => {
    const rootA: Me = { id: 'root-a', name: 'A', is_root: true }
    const first = beginDirectory(rootA)
    assert.equal(dirCalls(), 1)
    // Identity switch (logout): the state is retired while the flight is pending.
    resetDirectory()
    calls[0]!.resolve({ data: [{ id: 'old-root-org', name: 'Stale' }] })
    await first
    assert.equal(directorySnapshot().rows, null, 'stale completion committed the previous identity\'s rows')

    // The next identity refetches instead of reusing the retired listing.
    const rootB: Me = { id: 'root-b', name: 'B', is_root: true }
    const second = beginDirectory(rootB)
    assert.equal(dirCalls(), 2, 'a different identity reused the old directory')
    calls[1]!.resolve({ data: [{ id: 'org-b', name: 'B Org' }] })
    await second
    assert.equal(directorySnapshot().identity, 'root-b')
  })

  it('member reload sequence refreshes the pool: new memberships appear on the same mount', async () => {
    const before = requestMe()
    calls[0]!.resolve(memberMe)
    await before
    assert.equal(memberOrgs((await before)!).length, 1)

    // reload(): reset both caches, then the next /api/me carries org-b too.
    resetMeCache()
    resetDirectory()
    const after = requestMe()
    assert.equal(calls.length, 2, 'reload refires /api/me for the mounted pool')
    calls[1]!.resolve({
      ...memberMe,
      organizations: [
        ...memberMe.organizations!,
        { id: 'org-b', name: 'Org B', role: 'reader', permissions: [], slug: 'bee', currency: 'JPY', timezone: 'Asia/Tokyo' },
      ],
    })
    const me2 = await after
    const orgs = memberOrgs(me2!)
    assert.equal(orgs.length, 2)
    assert.deepEqual(resolveOrgPresentation(orgs, 'org-b'), { currency: 'JPY', timezone: 'Asia/Tokyo' })
  })

  it('root resolves a page-2+ org through the supported single-org GET, not defaults', async () => {
    const root: Me = { id: 'root-a', name: 'A', is_root: true }
    assert.equal(wantDirectory(false, root), true)
    const listing = beginDirectory(root)
    calls[0]!.resolve({ data: [{ id: 'org-page1', name: 'Page One', currency: 'GBP' }] })
    const rows = await listing
    assert.equal(resolveOrgPresentation(rows, 'org-page1').currency, 'GBP')

    // org-page9 sits beyond page 1: the root-only fallback resolves the
    // actual record before defaults apply.
    assert.equal(mayResolveDetail(false, root), true)
    const detail = beginOrgDetail(root, 'org-page9')
    assert.equal(calls.length, 2)
    assert.match(calls[1]!.url, /\/organizations\/org-page9$/)
    calls[1]!.resolve({ id: 'org-page9', name: 'Page Nine', slug: 'nine', currency: 'CHF', timezone: 'Europe/Zurich' })
    const org = await detail
    assert.equal(org?.currency, 'CHF')
    assert.equal(directoryExtra('org-page9')?.timezone, 'Europe/Zurich')
    assert.deepEqual(resolveOrgPresentation([...rows, org!], 'org-page9'), { currency: 'CHF', timezone: 'Europe/Zurich' })
    // Committed singles are deduplicated: resolving again does not refetch.
    await beginOrgDetail(root, 'org-page9')
    assert.equal(calls.length, 2)

    // A member may never fire the root-only detail route.
    assert.equal(mayResolveDetail(false, memberMe), false)
  })

  it('detail fallback: failures retry later, retired commits are discarded', async () => {
    const root: Me = { id: 'root-a', name: 'A', is_root: true }
    beginDirectory(root) // listing stays pending; irrelevant here
    const failed = beginOrgDetail(root, 'org-x')
    calls[1]!.reject(new TypeError('boom'))
    assert.equal(await failed, null)
    assert.equal(directoryExtra('org-x'), null)
    // Pending marker cleared → a later attempt refires instead of no-opping.
    const retried = beginOrgDetail(root, 'org-x')
    assert.equal(calls.length, 3)
    calls[2]!.resolve({ id: 'org-x', name: 'X', slug: 'x', currency: 'SEK', timezone: 'Europe/Stockholm' })
    assert.equal((await retried)?.currency, 'SEK')

    // A reset retires the flight: its late completion is neither committed
    // nor adopted by the awaiting caller.
    const stale = beginOrgDetail(root, 'org-y')
    resetDirectory()
    calls[3]!.resolve({ id: 'org-y', name: 'Y', slug: 'y', currency: 'NOK', timezone: 'Europe/Oslo' })
    assert.equal(await stale, null)
    assert.equal(directoryExtra('org-y'), null, 'retired detail commit leaked into the fresh state')
  })
})
