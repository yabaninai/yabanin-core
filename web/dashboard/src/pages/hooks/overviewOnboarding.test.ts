import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ONBOARDING_MEMORY_KEY, parseOnboardingMemory,
} from './overviewOnboarding.ts'

test('parseOnboardingMemory: only the two known boolean flags survive', () => {
  assert.deepEqual(parseOnboardingMemory(null), {})
  assert.deepEqual(parseOnboardingMemory('not json'), {})
  assert.deepEqual(parseOnboardingMemory('{"dismissed":true,"doneDismissed":true}'), {
    dismissed: true,
    doneDismissed: true,
  })
  // A tampered/foreign payload never flips a flag on.
  assert.deepEqual(parseOnboardingMemory('{"dismissed":"yes","evil":true}'), {})
  assert.deepEqual(parseOnboardingMemory('{"dismissed":false}'), {})
})

test('the storage key is namespaced like the other platform stores', () => {
  assert.equal(ONBOARDING_MEMORY_KEY, 'yabanin.onboarding.v1')
})
