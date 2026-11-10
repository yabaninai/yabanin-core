import { afterEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { fetchCreditTransactions, fetchLowBalanceOrgs } from './credits.ts'

const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })

function response(body: unknown) {
  globalThis.fetch = async () => new Response(JSON.stringify(body), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  })
}

test('a fresh database with null low-balance IDs renders an empty list', async () => {
  response({ threshold_cents: -500, count: 0, org_ids: null })
  const result = await fetchLowBalanceOrgs()
  assert.deepEqual(result.org_ids, [])
  assert.equal(result.org_ids.includes('seed-org'), false)
})

test('a new organization with no transactions has an iterable list', async () => {
  response({ org_id: 'new-org', limit: 50, count: 0, txns: null })
  assert.deepEqual((await fetchCreditTransactions('new-org')).txns, [])
})

test('nonempty low-balance IDs survive normalization', async () => {
  response({ threshold_cents: -500, count: 1, org_ids: ['low-org'] })
  assert.deepEqual((await fetchLowBalanceOrgs()).org_ids, ['low-org'])
})

test('missing or malformed lists do not become healthy empty results', async () => {
  for (const org_ids of [undefined, 'bad', [42], null]) {
    response({ threshold_cents: -500, count: 1, org_ids })
    await assert.rejects(fetchLowBalanceOrgs(), /Invalid low-balance/)
  }
  response({ org_id: 'org', count: 1, txns: null })
  await assert.rejects(fetchCreditTransactions('org'), /Invalid credit transaction/)
})
