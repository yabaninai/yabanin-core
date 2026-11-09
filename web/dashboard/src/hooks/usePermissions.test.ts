import assert from 'node:assert/strict'
import { describe, it, beforeEach } from 'node:test'
import { requestMe, resetMeCache } from './usePermissions.ts'

// callers share a single flight, and resetMeCache invalidates everything
// (the post-logout hygiene the UserMenu relies on).
// navigation remounts must not loop a request the endpoint already failed).
// The latch is session state too: resetMeCache clears it, so the next login
// re-probes /api/me instead of inheriting the previous session's failure
// (an identity stuck unknown would stay silently fail-open).

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

describe('usePermissions /api/me cache (IMP-31)', () => {
  beforeEach(() => {
    resetMeCache()
    calls = []
    stubFetch()
  })

  it('one request per session: the second call is served from the cache', async () => {
    const first = requestMe()
    assert.equal(calls.length, 1)
    calls[0]!.resolve({ id: 'a1', name: 'Root', is_root: true, email: 'r@example.test' })
    const me = await first
    assert.equal(me?.id, 'a1')

    const second = await requestMe()
    assert.equal(calls.length, 1, 'no second fetch for a cached identity')
    assert.equal(second?.id, 'a1')
  })

  it('concurrent callers share a single in-flight request', async () => {
    const a = requestMe()
    const b = requestMe()
    assert.equal(calls.length, 1, 'deduplicated to one fetch')
    calls[0]!.resolve({ id: 'a2', name: 'Member', is_root: false, organizations: [] })
    const [ma, mb] = await Promise.all([a, b])
    assert.equal(ma?.id, 'a2')
    assert.equal(mb?.id, 'a2')
  })

  it('a failed answer latches unavailable — later callers do not refire this session', async () => {
    const pending = requestMe()
    calls[0]!.reject(new TypeError('network down'))
    const failed = await pending
    assert.equal(failed, null, 'failure resolves to null (endpoint unavailable)')

    const next = await requestMe()
    assert.equal(calls.length, 1, 'the latch prevents a refire on remount (IMP-10b)')
    assert.equal(next, null, 'latched unavailability keeps the fail-open identity')
  })

  it('resetMeCache forces a fresh request after logout — including a latched failure', async () => {
    const pending = requestMe()
    calls[0]!.reject(new TypeError('network down'))
    await pending
    await requestMe()
    assert.equal(calls.length, 1, 'latched: no refire before logout')

    resetMeCache()
    const second = requestMe()
    assert.equal(calls.length, 2, 'reset invalidates the latch and the cache — next login re-probes')
    calls[1]!.resolve({ id: 'a5', name: 'Next Session', is_root: false })
    assert.equal((await second)?.id, 'a5')
  })
})
