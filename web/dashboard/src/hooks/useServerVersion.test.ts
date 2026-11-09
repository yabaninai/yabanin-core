import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EXPECTED_API_LEVEL,
  versionBanner,
  type ServerVersionState,
} from './useServerVersion.ts'

// api_level BELOW the dashboard's expectation raises the banner, a level at
// or above it does not, and a 404 (endpoint predates the handshake) does.
// Everything that leaves the level unknown must stay banner-free — unknown is
// not "older".

const SERVER = (api_level: number) => ({
  version: '1.9.0',
  commit: 'abc1234',
  api_level,
  migration: 21,
})

test('api_level below the expected level raises the banner (with the server identity)', () => {
  assert.deepEqual(versionBanner({ kind: 'older', server: SERVER(EXPECTED_API_LEVEL - 1) }), {
    server: SERVER(EXPECTED_API_LEVEL - 1),
  })
  assert.deepEqual(versionBanner({ kind: 'older', server: SERVER(0) }), { server: SERVER(0) })
})

test('api_level at or above the expected level raises no banner', () => {
  assert.equal(versionBanner({ kind: 'compatible', server: SERVER(EXPECTED_API_LEVEL) }), null)
  assert.equal(versionBanner({ kind: 'compatible', server: SERVER(EXPECTED_API_LEVEL + 1) }), null)
})

test('a 404 answer raises the banner (without a server identity)', () => {
  assert.deepEqual(versionBanner({ kind: 'unavailable' }), {})
})

test('loading and unknown answers raise no banner', () => {
  const unknowns: ServerVersionState[] = [
    { kind: 'loading' },
    { kind: 'unknown' }, // network/5xx/401/malformed — level genuinely unknown
  ]
  for (const state of unknowns) {
    assert.equal(versionBanner(state), null, `state ${state.kind} must stay banner-free`)
  }
})

test('the expected level matches the IMP-10a server contract (currently 1)', () => {
  assert.equal(EXPECTED_API_LEVEL, 1)
})
