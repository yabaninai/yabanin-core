// semantics MUST mirror adminstore.RenderTemplate (pkg/adminstore/
// promptstudio.go): one left-to-right pass, verbatim insertion, no rescan,
// malformed tokens verbatim, missing vars/partials fail closed.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  extractTemplateVars, extractPartialRefs, renderTemplateClient,
  buildChatCurl, shellSingleQuote, templatePreview, parseParamsObject,
} from './promptRender.ts'

test('extractTemplateVars finds unique vars in first-appearance order', () => {
  assert.deepEqual(
    extractTemplateVars('Hello {{ name }}, {{name}} and {{other_name}}!'),
    ['name', 'other_name'],
  )
})

test('extractTemplateVars skips partial refs and the reserved namespace', () => {
  assert.deepEqual(
    extractTemplateVars('{{partials.tone}} and {{partials.bad token}} and {{partials.}} and {{real}}'),
    ['real'],
  )
})

test('extractTemplateVars leaves malformed tokens out', () => {
  assert.deepEqual(extractTemplateVars('{{a b}} {{ }} {x} {{ok}}'), ['ok'])
})

test('extractPartialRefs finds unique partial names', () => {
  assert.deepEqual(
    extractPartialRefs('{{partials.tone}} {{ tone }} {{partials.other}} {{var}}'),
    ['tone', 'other'],
  )
})

test('renderTemplateClient substitutes vars and partial bodies verbatim, one pass', () => {
  const res = renderTemplateClient(
    'Say {{word}} then {{partials.rule}} and {{word}} again',
    { word: 'hi' },
    { rule: 'use {{word}} literally' },
  )
  assert.deepEqual(res, { ok: true, text: 'Say hi then use {{word}} literally and hi again' })
})

test('renderTemplateClient fails closed on a missing variable', () => {
  const res = renderTemplateClient('Hi {{missing}}', {}, {})
  assert.equal(res.ok, false)
  if (!res.ok) assert.match(res.error, /missing/)
})

test('renderTemplateClient fails closed on a missing partial', () => {
  const res = renderTemplateClient('Rule: {{partials.absent}}', {}, {})
  assert.equal(res.ok, false)
  if (!res.ok) assert.match(res.error, /absent/)
})

test('renderTemplateClient accepts an empty partial body (present, empty string)', () => {
  const res = renderTemplateClient('A{{partials.noop}}B', {}, { noop: '' })
  assert.deepEqual(res, { ok: true, text: 'AB' })
})

test('renderTemplateClient keeps malformed tokens verbatim', () => {
  assert.deepEqual(
    renderTemplateClient('{{a b}} {{partials.}} {x}', {}, {}),
    { ok: true, text: '{{a b}} {{partials.}} {x}' },
  )
})

test('renderTemplateClient replaces a token with a present-but-empty var value', () => {
  assert.deepEqual(
    renderTemplateClient('{{v}}', { v: '' }, {}),
    { ok: true, text: '' },
  )
})

test('shellSingleQuote survives embedded single quotes', () => {
  assert.equal(shellSingleQuote("it's"), `'it'\\''s'`)
})

test('buildChatCurl targets /v1/chat/completions with the rendered system message', () => {
  const curl = buildChatCurl({
    baseUrl: 'https://gw.example.test/',
    model: 'glm-5.3-flash',
    system: 'You are judging {{x}}'.replace('{{x}}', 'data'),
    user: ' Judge this ',
  })
  assert.match(curl, /curl -sS 'https:\/\/gw\.example\.test\/v1\/chat\/completions'/)
  assert.match(curl, /'Authorization: Bearer '\$ROUTER_API_KEY/)
  const payload = /-d ('.*')$/.exec(curl)?.[1] ?? ''
  const parsed = JSON.parse(payload.replaceAll(`'\\''`, `'`).slice(1, -1)) as {
    model: string
    messages: Array<{ role: string; content: string }>
  }
  assert.equal(parsed.model, 'glm-5.3-flash')
  assert.deepEqual(parsed.messages, [
    { role: 'system', content: 'You are judging data' },
    { role: 'user', content: ' Judge this ' },
  ])
})

test('buildChatCurl omits the user message when absent', () => {
  const curl = buildChatCurl({ baseUrl: 'http://127.0.0.1:8080', model: 'm', system: 's' })
  assert.equal((curl.match(/"role"/g) ?? []).length, 1)
})

test('templatePreview flattens whitespace and caps the length', () => {
  assert.equal(templatePreview('a\n\n  b'), 'a b')
  assert.equal(templatePreview('x'.repeat(200), 10).length, 10)
  assert.match(templatePreview('y'.repeat(200), 10), /…$/)
})

test('parseParamsObject accepts empty text, JSON objects; rejects arrays/scalars/invalid', () => {
  assert.deepEqual(parseParamsObject(''), { ok: true, value: undefined })
  assert.deepEqual(parseParamsObject('  '), { ok: true, value: undefined })
  assert.deepEqual(parseParamsObject('{"model":"m"}'), { ok: true, value: { model: 'm' } })
  assert.deepEqual(parseParamsObject('{}'), { ok: true, value: {} })
  assert.equal(parseParamsObject('[1]').ok, false)
  assert.equal(parseParamsObject('"x"').ok, false)
  assert.equal(parseParamsObject('null').ok, false)
  assert.equal(parseParamsObject('{bad').ok, false)
})
