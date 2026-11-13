import { test, mock, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { getEventListeners } from 'node:events'
import { ApiError, DEFAULT_READ_TIMEOUT_MS, loginNextUrl, onUnauthorized, readJSON, resetCsrf, sendMutation } from './transport.ts'

// Transport acceptance: the transport owns the full HTTP lifecycle — a documented
// default read timeout that is really armed (even without options), a caller
// abort that stays connected through body parsing, CSRF dedup where one
// cancelled caller never cancels the token for everyone, and cleanup that
// leaves no listeners/timers behind. Mutations are never resent after a
// network timeout (outcome unknown); the only resend is the documented single
// replay after a CSRF 403 "forbidden".

interface StubResponse {
  status: number
  ok: boolean
  statusText?: string
  json?: () => Promise<unknown>
  text?: () => Promise<string>
}

type Call = { url: string; init: RequestInit }
type Handler = (call: Call) => Promise<StubResponse>

const realFetch = globalThis.fetch
const calls: Call[] = []

function jsonResponse(status: number, body: unknown, statusText = ''): StubResponse {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText,
    json: async () => body,
    text: async () => JSON.stringify(body),
  }
}

function installFetch(handler: Handler): void {
  calls.length = 0
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const call = { url: String(url), init: init ?? {} }
    calls.push(call)
    return handler(call) as unknown as Promise<Response>
  }) as typeof fetch
}

afterEach(() => {
  globalThis.fetch = realFetch
  resetCsrf()
})

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (e: unknown) => void } {
  let resolve!: (value: T) => void
  let reject!: (e: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res as (value: T) => void
    reject = rej
  })
  return { promise, resolve, reject }
}

function abortListenerCount(signal: AbortSignal | undefined): number {
  return signal ? getEventListeners(signal, 'abort').length : 0
}

// A response whose JSON body stays unread until `release` settles; it rejects
// with the scope signal's reason, like a real interrupted body read.
function hangingJsonResponse(signal: AbortSignal | undefined, release: Promise<void>): StubResponse {
  return {
    status: 200,
    ok: true,
    json: () => new Promise<never>((_, reject) => {
      release.then(() => reject(new SyntaxError('unexpected end of JSON input')))
      signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
    }),
  }
}

const csrfRoute = '/auth/csrf'

function csrfOk(token: string): StubResponse {
  return jsonResponse(200, { csrf_token: token })
}

const mutationCalls = (): Call[] => calls.filter(c => c.url !== csrfRoute)

async function primeCsrfToken(token = 't0'): Promise<void> {
  installFetch(async call => (call.url === csrfRoute ? csrfOk(token) : jsonResponse(200, {})))
  await sendMutation('/warmup', { method: 'POST' })
  calls.length = 0
}

const isTimeoutError = (err: unknown): boolean => err instanceof DOMException && err.name === 'TimeoutError'

test('read: GET without opts carries a signal armed at the documented default timeout', async () => {
  mock.timers.enable({ apis: ['setTimeout'] })
  try {
    let seen: AbortSignal | undefined
    installFetch(async call => {
      seen = call.init.signal
      return new Promise<never>((_, reject) => {
        seen?.addEventListener('abort', () => reject(seen?.reason), { once: true })
      })
    })
    const pending = readJSON('/organizations')
    assert.ok(seen, 'fetch must receive a signal even with no options')
    mock.timers.tick(DEFAULT_READ_TIMEOUT_MS - 1)
    const state = await Promise.race([
      pending.then(() => 'settled' as const, () => 'settled' as const),
      Promise.resolve().then(() => 'pending' as const),
    ])
    assert.equal(state, 'pending', 'nothing may abort before the documented deadline')
    mock.timers.tick(1)
    await assert.rejects(pending, isTimeoutError)
  } finally {
    mock.timers.reset()
  }
})

test('read: explicit timeoutMs wins over the default; timeoutMs 0 disables the timer', async () => {
  mock.timers.enable({ apis: ['setTimeout'] })
  try {
    installFetch(async call => new Promise<never>((_, reject) => {
      call.init.signal?.addEventListener('abort', () => reject(call.init.signal?.reason), { once: true })
    }))
    // Explicit 10s: aborted by its own deadline (not the 30s default).
    const explicit = readJSON('/x', { timeoutMs: 10_000 })
    mock.timers.tick(10_000)
    await assert.rejects(explicit, isTimeoutError)

    // `0` disables the read timeout entirely (disabled policy): ticking far
    // past the default stays silent, and only the body release settles it.
    const release = deferred<void>()
    installFetch(async call => hangingJsonResponse(call.init.signal, release.promise))
    const disabled = readJSON('/x', { timeoutMs: 0 })
    mock.timers.tick(DEFAULT_READ_TIMEOUT_MS * 10)
    release.resolve()
    await assert.rejects(disabled, SyntaxError)
  } finally {
    mock.timers.reset()
  }
})

test('read: an already-aborted caller signal rejects without a round trip', async () => {
  const controller = new AbortController()
  controller.abort()
  installFetch(async call => {
    assert.ok(call.init.signal?.aborted, 'fetch must see the aborted state up front')
    return new Promise<never>((_, reject) => reject(call.init.signal?.reason))
  })
  await assert.rejects(readJSON('/x', { signal: controller.signal }), (err: unknown) => err === controller.signal.reason)
})

test('read: caller abort during the JSON body read cancels the operation and cleans up', async () => {
  const controller = new AbortController()
  const release = deferred<void>()
  installFetch(async call => hangingJsonResponse(call.init.signal, release.promise))
  const pending = readJSON('/x', { signal: controller.signal })
  setTimeout(() => controller.abort(), 5)
  await assert.rejects(pending, (err: unknown) => err === controller.signal.reason)
  release.resolve()
  await new Promise(resolve => setTimeout(resolve, 5))
  assert.equal(abortListenerCount(controller.signal), 0, 'no caller listener may leak after cleanup')
})

test('read: caller abort during the error-body read cancels and cleans up', async () => {
  const controller = new AbortController()
  installFetch(async call => ({
    status: 502,
    ok: false,
    statusText: 'Bad Gateway',
    text: () => new Promise<never>((_, reject) => {
      call.init.signal?.addEventListener('abort', () => reject(call.init.signal?.reason), { once: true })
    }),
  }))
  const pending = readJSON('/x', { signal: controller.signal })
  setTimeout(() => controller.abort(), 5)
  await assert.rejects(pending, (err: unknown) => err === controller.signal.reason)
  assert.equal(abortListenerCount(controller.signal), 0)
})

test('read: status handling — 401 resets CSRF and reports unauthorized; server error codes parse; non-JSON keeps the status line', async () => {
  await primeCsrfToken('stale')
  installFetch(async () => jsonResponse(401, {}, 'Unauthorized'))
  const err401 = await readJSON('/x').catch((e: unknown) => e)
  assert.ok(err401 instanceof ApiError)
  assert.equal((err401 as ApiError).status, 401)
  assert.match((err401 as ApiError).message, /Unauthorized \(401\)/)

  installFetch(async () => jsonResponse(403, { error: 'permission_denied' }))
  const err403 = await readJSON('/x').catch((e: unknown) => e)
  assert.ok(err403 instanceof ApiError)
  assert.equal((err403 as ApiError).code, 'permission_denied')
  assert.match((err403 as ApiError).message, /API error 403: permission_denied/)

  installFetch(async () => ({ status: 429, ok: false, statusText: 'Too Many Requests', text: async () => 'slow down' }))
  const err429 = await readJSON('/x').catch((e: unknown) => e)
  assert.ok(err429 instanceof ApiError)
  assert.equal((err429 as ApiError).status, 429)
  assert.equal((err429 as ApiError).code, undefined)
  assert.equal((err429 as ApiError).body, 'slow down')
})

test('read: malformed/non-JSON success bodies propagate the parse failure (historical parity)', async () => {
  installFetch(async () => ({
    status: 200,
    ok: true,
    json: async () => { throw new SyntaxError('Unexpected token < in JSON') },
  }))
  await assert.rejects(readJSON('/x'), SyntaxError)
})

test('read: cleanup leaves no caller listeners after success (and no live timer)', async () => {
  mock.timers.enable({ apis: ['setTimeout'] })
  try {
    const controller = new AbortController()
    installFetch(async () => jsonResponse(200, { ok: 1 }))
    const result = await readJSON('/x', { signal: controller.signal, timeoutMs: DEFAULT_READ_TIMEOUT_MS }) as { ok: number }
    assert.equal(result.ok, 1)
    assert.equal(abortListenerCount(controller.signal), 0, 'dispose must drop the caller listener')
    // A disposed scope's timer is cleared: ticking past the deadline is
    // silent (a stray abort would surface as an unhandled rejection).
    mock.timers.tick(DEFAULT_READ_TIMEOUT_MS * 2)
  } finally {
    mock.timers.reset()
  }
})

test('mutation: caller abort during the response body read keeps the merged signal connected (audit synthetic #2)', async () => {
  const controller = new AbortController()
  let bodySignal: AbortSignal | undefined
  installFetch(async call => {
    if (call.url === csrfRoute) return csrfOk('tok')
    bodySignal = call.init.signal
    return {
      status: 200,
      ok: true,
      json: async () => {
        controller.abort()
        return {}
      },
    }
  })
  const outcome = await sendMutation('/api/things', { method: 'POST' }, { signal: controller.signal })
  assert.ok(outcome.ok, `mutation should complete: ${outcome.ok ? '' : outcome.error.message}`)
  assert.ok(bodySignal?.aborted, 'caller abort during json() must be visible on the fetch signal')
})

test('mutation: headers merge cannot override the CSRF header and credentials stay include', async () => {
  await primeCsrfToken('real-token')
  installFetch(async call => {
    assert.equal(call.init.credentials, 'include')
    const headers = new Headers(call.init.headers)
    assert.equal(headers.get('X-CSRF-Token'), 'real-token')
    assert.equal(headers.get('X-Audit-Reason'), 'because')
    return jsonResponse(200, { done: true })
  })
  const outcome = await sendMutation('/api/things', { method: 'POST' }, { headers: { 'X-Audit-Reason': 'because', 'X-CSRF-Token': 'evil' } })
  assert.ok(outcome.ok)
})

test('mutation: a network timeout is NOT resent — the outcome stays unknown, exactly one fetch', async () => {
  await primeCsrfToken()
  installFetch(async call => new Promise<never>((_, reject) => {
    call.init.signal?.addEventListener('abort', () => reject(call.init.signal?.reason), { once: true })
  }))
  await assert.rejects(
    sendMutation('/api/things', { method: 'POST' }, { timeoutMs: 20 }),
    isTimeoutError,
  )
  assert.equal(mutationCalls().length, 1, 'an accepted-or-not mutation must never be retried')
})

test('mutation: CSRF 403 "forbidden" replays exactly once with a fresh token (old contract)', async () => {
  const tokens = ['t1', 't2']
  const mutationTokens: string[] = []
  installFetch(async call => {
    if (call.url === csrfRoute) return csrfOk(tokens.shift() ?? 'tx')
    mutationTokens.push(new Headers(call.init.headers).get('X-CSRF-Token') ?? '')
    if (mutationTokens.length === 1) return { status: 403, ok: false, statusText: 'Forbidden', text: async () => 'forbidden' }
    return jsonResponse(200, { ok: 1 })
  })
  const outcome = await sendMutation('/api/things', { method: 'POST' })
  assert.ok(outcome.ok)
  assert.deepEqual(mutationTokens, ['t1', 't2'], 'the replay must carry the refreshed token')

  // A second "forbidden" is reported as-is — no second replay.
  installFetch(async call => {
    if (call.url === csrfRoute) return csrfOk('t3')
    return { status: 403, ok: false, statusText: 'Forbidden', text: async () => 'forbidden' }
  })
  const rejected = await sendMutation('/api/things', { method: 'POST' })
  assert.equal(rejected.ok, false)
  assert.equal(rejected.ok ? 0 : rejected.status, 403)
  assert.equal(mutationCalls().length, 2)
})

test('mutation: a 403 that is not a CSRF rejection is never replayed', async () => {
  await primeCsrfToken()
  installFetch(async () => jsonResponse(403, { error: 'denied' }))
  const outcome = await sendMutation('/api/things', { method: 'POST' })
  assert.equal(outcome.ok, false)
  assert.equal(outcome.ok ? 0 : outcome.error.code, 'denied')
  assert.equal(mutationCalls().length, 1)
})

test('mutation: first-attempt 401 throws unauthorized and drops the cached token; post-replay 401 is a plain error', async () => {
  await primeCsrfToken('cached')
  installFetch(async () => jsonResponse(401, {}, 'Unauthorized'))
  const err = await sendMutation('/api/things', { method: 'POST' }).catch((e: unknown) => e)
  assert.ok(err instanceof ApiError)
  assert.match((err as ApiError).message, /Unauthorized \(401\)/)

  // The cached token was dropped by the 401: the next mutation reloads it.
  // First mutation call → CSRF 403 (replay with a reloaded token), replay →
  // 401: the final response is reported as a plain error.
  let csrfLoads = 0
  let mutationCount = 0
  installFetch(async call => {
    if (call.url === csrfRoute) {
      csrfLoads++
      return csrfOk('fresh')
    }
    mutationCount++
    if (mutationCount === 1) return { status: 403, ok: false, statusText: 'Forbidden', text: async () => 'forbidden' }
    return jsonResponse(401, {}, 'Unauthorized')
  })
  const outcome = await sendMutation('/api/things', { method: 'POST' })
  // The CSRF-forbidden reset before the replay reloads the token (the
  // historical contract), so the shared load runs twice here.
  assert.equal(csrfLoads, 2)
  assert.equal(outcome.ok, false)
  // Post-replay 401 is reported as a plain ApiError of the final response,
  // exactly like the historical contract (not as the unauthorized() reset).
  assert.equal(outcome.ok ? 0 : outcome.status, 401)
  assert.equal(mutationCount, 2)
})

test('mutation: 204 returns no body; malformed success JSON still propagates', async () => {
  await primeCsrfToken()
  installFetch(async () => ({ status: 204, ok: true, statusText: 'No Content', json: async () => { throw new Error('204 must not be parsed') } }))
  const outcome = await sendMutation('/api/things', { method: 'DELETE' })
  assert.ok(outcome.ok)
  assert.equal(outcome.body, undefined)

  installFetch(async () => ({
    status: 200,
    ok: true,
    json: async () => { throw new SyntaxError('malformed') },
  }))
  await assert.rejects(sendMutation('/api/things', { method: 'POST' }), SyntaxError)
})

test('CSRF dedup: one cancelled caller does not cancel the token for the others', async () => {
  const gate = deferred<StubResponse>()
  let csrfLoads = 0
  installFetch(async call => {
    if (call.url === csrfRoute) {
      csrfLoads++
      return gate.promise
    }
    return jsonResponse(200, { ok: 1 })
  })

  const cancelled = new AbortController()
  const a = sendMutation('/api/things', { method: 'POST' }, { signal: cancelled.signal })
  const b = sendMutation('/api/other', { method: 'POST' })
  await new Promise(resolve => setTimeout(resolve, 5))
  cancelled.abort()
  await assert.rejects(a, (err: unknown) => err === cancelled.signal.reason)
  assert.equal(csrfLoads, 1, 'both callers share one in-flight token load')

  gate.resolve(csrfOk('shared'))
  assert.ok((await b).ok, 'the other caller still gets the token')
  assert.equal(csrfLoads, 1)
  assert.equal(mutationCalls().length, 1, 'only the surviving caller reaches the mutation')
})

test('CSRF dedup: a failed shared load is not cached — the next caller retries the load', async () => {
  let loads = 0
  installFetch(async call => {
    if (call.url === csrfRoute) {
      loads++
      return loads === 1 ? jsonResponse(500, {}, 'Internal Server Error') : csrfOk('t-ok')
    }
    return jsonResponse(200, { ok: 1 })
  })
  const first = await sendMutation('/api/things', { method: 'POST' }).catch((e: unknown) => e)
  assert.ok(first instanceof ApiError)
  const second = await sendMutation('/api/things', { method: 'POST' })
  assert.ok(second.ok)
  assert.equal(loads, 2)
})

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

test('401 hook: a read 401 notifies exactly once; unsubscribe stops the notifications', async () => {
  let fired = 0
  const unsubscribe = onUnauthorized(() => {
    fired++
  })
  try {
    installFetch(async () => jsonResponse(401, {}, 'Unauthorized'))
    await assert.rejects(readJSON('/x'), (err: unknown) => err instanceof ApiError && err.status === 401)
    assert.equal(fired, 1, 'the first 401 of a request notifies the listener once')

    await assert.rejects(readJSON('/y'), (err: unknown) => err instanceof ApiError && err.status === 401)
    assert.equal(fired, 2, 'a later 401 still notifies — the gate stays up, the signal is idempotent')

    unsubscribe()
    await assert.rejects(readJSON('/z'), (err: unknown) => err instanceof ApiError && err.status === 401)
    assert.equal(fired, 2, 'after unsubscribe the listener is detached')
  } finally {
    unsubscribe()
  }
})

test('401 hook: non-401 failures never notify', async () => {
  let fired = 0
  const unsubscribe = onUnauthorized(() => {
    fired++
  })
  try {
    installFetch(async () => jsonResponse(500, { error: 'boom' }))
    await assert.rejects(readJSON('/x'), (err: unknown) => err instanceof ApiError && err.status === 500)
    installFetch(async () => jsonResponse(403, { error: 'permission_denied' }))
    await assert.rejects(readJSON('/y'), (err: unknown) => err instanceof ApiError && err.status === 403)
    assert.equal(fired, 0)
  } finally {
    unsubscribe()
  }
})

test('401 hook: mutation first-attempt 401, CSRF-load 401 and post-replay 401 all notify', async () => {
  let fired = 0
  const unsubscribe = onUnauthorized(() => {
    fired++
  })
  try {
    // First mutation attempt answers 401 — the unauthorized() path.
    await primeCsrfToken('cached')
    installFetch(async () => jsonResponse(401, {}, 'Unauthorized'))
    await assert.rejects(sendMutation('/api/things', { method: 'POST' }))
    assert.equal(fired, 1)

    // The CSRF token load itself answers 401 — the same shared path.
    installFetch(async call => (call.url === csrfRoute ? jsonResponse(401, {}, 'Unauthorized') : jsonResponse(200, {})))
    await assert.rejects(sendMutation('/api/things', { method: 'POST' }))
    assert.equal(fired, 2)

    // CSRF 403 replay whose final answer is 401 — the toApiError path.
    let mutationCount = 0
    installFetch(async call => {
      if (call.url === csrfRoute) return csrfOk('fresh')
      mutationCount++
      if (mutationCount === 1) return { status: 403, ok: false, statusText: 'Forbidden', text: async () => 'forbidden' }
      return { status: 401, ok: false, statusText: 'Unauthorized', text: async () => '' }
    })
    const outcome = await sendMutation('/api/things', { method: 'POST' })
    assert.equal(outcome.ok, false)
    assert.equal(fired, 3, 'no real 401 response may go unseen')
  } finally {
    unsubscribe()
  }
})

test('loginNextUrl: deep link keeps path, query and hash; value is encoded once', () => {
  assert.equal(
    loginNextUrl({ pathname: '/', search: '', hash: '#keys?org=acme' }),
    '/auth/login?next=%2F%23keys%3Forg%3Dacme',
  )
  assert.equal(
    loginNextUrl({ pathname: '/', search: '?x=1', hash: '#overview' }),
    '/auth/login?next=%2F%3Fx%3D1%23overview',
  )
})

test('loginNextUrl: scheme-relative and non-relative targets fall back to "/" (server contract)', () => {
  // A deep link whose hash contains "//" is same-origin and stays intact —
  // only a leading "//" or "/\" of the whole next value is rejected.
  assert.equal(
    loginNextUrl({ pathname: '/#//evil.com', search: '', hash: '' }),
    '/auth/login?next=%2F%23%2F%2Fevil.com',
  )
  assert.equal(
    loginNextUrl({ pathname: '//evil.com', search: '', hash: '' }),
    '/auth/login?next=%2F',
  )
  assert.equal(
    loginNextUrl({ pathname: '/\\evil.com', search: '', hash: '' }),
    '/auth/login?next=%2F',
  )
  assert.equal(
    loginNextUrl({ pathname: 'https://evil.com', search: '', hash: '' }),
    '/auth/login?next=%2F',
  )
  // The deep-link variant decodes back to the full location (single encode).
  assert.equal(decodeURIComponent(loginNextUrl({ pathname: '/', search: '', hash: '#keys?org=a&x=1' }).split('next=')[1]!), '/#keys?org=a&x=1')
})
