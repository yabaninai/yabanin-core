import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { validateKeyLabels } from './labels.ts'

describe('validateKeyLabels', () => {
  it('normalizes a key and percent-decodes a value', () => {
    const r = validateKeyLabels({ ' Team ': 'payments%2Fbilling' })
    assert.deepEqual(r.problems, [])
    assert.deepEqual(r.labels, { team: 'payments/billing' })
  })

  it('rejects grammar, reserved prefix, length, and secrets', () => {
    const secret = 'sk-' + 'A'.repeat(40)
    const r = validateKeyLabels({
      'yabanin.internal': '1',
      '1bad': 'x',
      note: 'x'.repeat(129),
      token: secret,
      team: 'payments',
    })
    const byKey = Object.fromEntries(r.problems.map(p => [p.key, p.reason]))
    assert.equal(byKey['yabanin.internal'], 'reserved')
    assert.equal(byKey['1bad'], 'invalid_key')
    assert.equal(byKey.note, 'value_too_long')
    assert.equal(byKey.token, 'secret_like')
    assert.deepEqual(r.labels, { team: 'payments' })
    assert.equal(JSON.stringify(r.problems).includes(secret), false)
  })

  it('rejects the 21st label', () => {
    const many: Record<string, string> = {}
    for (let i = 0; i < 21; i++) many[`k${String(i).padStart(2, '0')}`] = 'ok'
    const r = validateKeyLabels(many)
    assert.equal(Object.keys(r.labels).length, 20)
    assert.equal(r.problems.some(p => p.reason === 'too_many'), true)
  })
})
