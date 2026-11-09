// AUX-17: node:test coverage for the inspect deep-link parse/serialize pair
// (same contract as tableUrl.test.ts — the encode/decode a reload uses).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readInspectParam, relatedListHref, writeInspectParam } from './inspectUrl.ts'

test('readInspectParam: present, absent, blank and unparsable values', () => {
  assert.equal(readInspectParam('inspect=org-9'), 'org-9')
  assert.equal(readInspectParam('org=acme&inspect=key-1&locale=ja'), 'key-1')
  assert.equal(readInspectParam(''), null)
  assert.equal(readInspectParam('org=acme'), null)
  assert.equal(readInspectParam('inspect='), null)
  assert.equal(readInspectParam('inspect=%20'), null)
  // A URLSearchParams instance works the same as a raw string.
  assert.equal(readInspectParam(new URLSearchParams('inspect=a:b')), 'a:b')
})

test('writeInspectParam: set, replace and remove keep other params intact', () => {
  const set = new URLSearchParams('org=acme')
  writeInspectParam(set, 'org-9')
  assert.equal(set.get('inspect'), 'org-9')
  assert.equal(set.get('org'), 'acme')

  writeInspectParam(set, 'key-2')
  assert.equal(set.get('inspect'), 'key-2')

  writeInspectParam(set, null)
  assert.equal(set.has('inspect'), false)
  assert.equal(set.get('org'), 'acme')

  // Blank ids never encode.
  const blank = new URLSearchParams()
  writeInspectParam(blank, '   ')
  assert.equal(blank.has('inspect'), false)
  // Values are trimmed.
  writeInspectParam(blank, '  org-1  ')
  assert.equal(blank.get('inspect'), 'org-1')
})

test('relatedListHref: strips inspect, keeps scope params, applies extras', () => {
  assert.equal(relatedListHref('keys', 'inspect=org-9'), '#keys')
  assert.equal(
    relatedListHref('requests-explorer', 'org=acme&locale=ja&inspect=key-1'),
    '#requests-explorer?org=acme&locale=ja',
  )
  assert.equal(
    relatedListHref('requests-explorer', 'inspect=org-9', { org: 'org-fixture' }),
    '#requests-explorer?org=org-fixture',
  )
  // Blank extras never encode as `org=`.
  assert.equal(relatedListHref('requests-explorer', '', { org: '' }), '#requests-explorer')
  assert.equal(
    relatedListHref('rules', 'org=acme&inspect=a', { model: 'gpt-4' }),
    '#rules?org=acme&model=gpt-4',
  )
})
