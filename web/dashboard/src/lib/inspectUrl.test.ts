// AUX-17: node:test coverage for the inspect deep-link parse/serialize pair
// (same contract as tableUrl.test.ts — the encode/decode a reload uses).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readInspectParam, readInspectRowKeys, relatedListHref, writeInspectParam } from './inspectUrl.ts'

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

test('readInspectRowKeys: raw selector values, never collapsed', () => {
  // One selector: the normal deep link after a row click.
  assert.deepEqual(readInspectRowKeys('inspect=request%3Areq-1&row_key=9007199254740993'), ['9007199254740993'])
  // Absent param is null (legacy link: no selector, no guessing).
  assert.equal(readInspectRowKeys('inspect=request%3Areq-1'), null)
  assert.equal(readInspectRowKeys(''), null)
  // Blank-present is ['']: presence is intent — the server's strict 400
  // must decide, not a silent fallback.
  assert.deepEqual(readInspectRowKeys('row_key='), [''])
  // A duplicated selector surfaces as TWO values. Collapsing to the first
  // sibling (URLSearchParams.get) would silently inspect a row the URL
  // never named.
  assert.deepEqual(readInspectRowKeys('row_key=1&row_key=2'), ['1', '2'])
  assert.deepEqual(readInspectRowKeys('row_key=1&row_key=1'), ['1', '1'])
  // A URLSearchParams instance works the same as a raw string.
  assert.deepEqual(readInspectRowKeys(new URLSearchParams('inspect=request%3Areq-1&row_key=7')), ['7'])
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
  // The row selector belongs to this correlation only: it must not leak
  // into a related list page and retarget a future inspector there.
  assert.equal(
    relatedListHref('requests-explorer', 'org=acme&inspect=request%3Areq-1&row_key=7'),
    '#requests-explorer?org=acme',
  )
})
