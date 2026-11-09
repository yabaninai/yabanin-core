import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  activateRequestBody, activePackDir, durableVersionLabel, filterGuardPackJournal,
  guardPackErrorView, packRows, parseIdentityPart, simulateRequestBody, statusView,
} from './guardPacksModel.ts'

// N02-P08 (T02/T06): the executable half of the GuardPacksPage decisions.
// The .tsx cannot render under the node strip-types harness, so the model
// owns every decision the page makes — this file pins them:
//
//   1. the exact wire payloads (the browser spec asserts these on the network);
//   2. identity parsing mirrors the gateway's strings.Cut semantics (FIRST
//      '@'), so the "Active" row mark can never disagree with what the
//      runtime actually loads;
//   3. error mapping is fail-closed: a 409 carries the server's LIVE durable
//      state, a store failure is never rendered as "nothing happened";
//   4. the journal filter is client-side by documented necessity (the audit
//      endpoint has no resource filter) and labeled first-page upstream;
//   5. status normalization renders unknown as unknown — never a zero date,
//      never a fabricated loadable=true.

describe('guard packs wire payloads', () => {
  it('simulate body carries pack_id/version/sample verbatim', () => {
    assert.deepEqual(simulateRequestBody('alpha', '1', 'hello'), { pack_id: 'alpha', version: '1', sample: 'hello' })
  })
  it('activate body carries pack_id/version verbatim (no invented fields)', () => {
    assert.deepEqual(activateRequestBody('alpha', '2.0'), { pack_id: 'alpha', version: '2.0' })
    const body = activateRequestBody('alpha', '1') as Record<string, unknown>
    assert.deepEqual(Object.keys(body).sort(), ['pack_id', 'version'])
  })
})

describe('durable identity parsing (gateway Cut semantics)', () => {
  it('splits at the FIRST @ (versions may contain @)', () => {
    assert.deepEqual(parseIdentityPart('alpha@1'), { packId: 'alpha', version: '1' })
    assert.deepEqual(parseIdentityPart('alpha@1@rc'), { packId: 'alpha', version: '1@rc' })
  })
  it('malformed parts are null, never guessed', () => {
    for (const bad of ['', '@', 'alpha@', '@1']) {
      assert.equal(parseIdentityPart(bad), null, `parseIdentityPart(${JSON.stringify(bad)})`)
    }
  })
  it('activePackDir: built-in chain and multi-pack identities name no single row', () => {
    assert.equal(activePackDir(''), null)
    assert.equal(activePackDir('core'), null)
    assert.equal(activePackDir('alpha@1'), 'alpha')
    assert.equal(activePackDir('a@1,b@2'), null)
    assert.equal(activePackDir('not-an-identity'), null)
  })
  it('durableVersionLabel names the built-in chain instead of a blank', () => {
    assert.equal(durableVersionLabel(''), 'core')
    assert.equal(durableVersionLabel('  '), 'core')
    assert.equal(durableVersionLabel('alpha@1'), 'alpha@1')
  })
})

describe('honest ApiError mapping', () => {
  // Mirrors transport.toApiError: the JSON body's `error` field becomes the
  // message text, exactly what the real ApiError carries.
  const apiErr = (status: number, body: string): unknown => {
    let message = `API error ${status}`
    try {
      const parsed = JSON.parse(body) as { error?: string }
      if (parsed?.error) message = `API error ${status}: ${parsed.error}`
    } catch { /* non-JSON body */ }
    return { status, body, message }
  }

  it('404 keeps the server text (unknown pack/version is not softened)', () => {
    const view = guardPackErrorView(apiErr(404, '{"error":"guard pack version not found: alpha@9"}'))
    assert.equal(view.kind, 'notFound')
    assert.match(view.serverMessage, /guard pack version not found/)
    assert.equal(view.conflict, undefined)
  })
  it('409 conflict envelope surfaces the LIVE durable state', () => {
    const view = guardPackErrorView(apiErr(409, '{"error":"conflict","current":{"active_version":"beta@2","previous_version":"core"}}'))
    assert.equal(view.kind, 'conflictState')
    assert.deepEqual(view.conflict, { active_version: 'beta@2', previous_version: 'core' })
  })
  it('409 without the envelope (verification failure) stays a plain conflict', () => {
    const view = guardPackErrorView(apiErr(409, '{"error":"guard pack failed verification: sha256 mismatch"}'))
    assert.equal(view.kind, 'conflict')
    assert.match(view.serverMessage, /sha256 mismatch/)
  })
  it('500/503 map to store failure / unwired, others to http', () => {
    assert.equal(guardPackErrorView(apiErr(500, '{}')).kind, 'storeFailure')
    assert.equal(guardPackErrorView(apiErr(503, '{}')).kind, 'unwired')
    assert.equal(guardPackErrorView(apiErr(400, '{}')).kind, 'http')
  })
  it('a non-ApiError still renders (honest text, never a silent success)', () => {
    const view = guardPackErrorView(new Error('network down'))
    assert.equal(view.kind, 'http')
    assert.match(view.serverMessage, /network down/)
  })
})

describe('audit journal client-side filter', () => {
  it('keeps only guard_pack entries, in order', () => {
    const entries = [
      { id: '1', action: 'update', resource: 'team_budget' },
      { id: '2', action: 'activate', resource: 'guard_pack', details: 'pack=alpha,version=1' },
      { id: '3', action: 'rollback', resource: 'guard_pack' },
      { id: '4', action: 'create', resource: 'api_key' },
    ]
    const kept = filterGuardPackJournal(entries as never[])
    assert.deepEqual(kept.map(e => e.id), ['2', '3'])
  })
})

describe('status normalization (no zero dates, no fabricated health)', () => {
  it('full body maps field-for-field', () => {
    const view = statusView({
      active_version: 'alpha@1', previous_version: 'core',
      updated_by: 'root@x.test', updated_at: '2026-10-24T00:00:00Z',
      staged_version: 'beta@3',
      runtime: { active_pack_loadable: true, check: 'load check text' },
    })
    assert.deepEqual(view, {
      activeVersion: 'alpha@1', previousVersion: 'core',
      updatedBy: 'root@x.test', updatedAt: '2026-10-24T00:00:00Z',
      stagedVersion: 'beta@3',
      activePackLoadable: true, loadError: null, check: 'load check text',
    })
  })
  it('a missing updated_at is unknown (null), never a zero date', () => {
    assert.equal(statusView({ active_version: 'core', staged_version: '', runtime: { active_pack_loadable: true } }).updatedAt, null)
  })
  it('a degraded body is the honest unknown state (loadable=false)', () => {
    const view = statusView(null)
    assert.equal(view.activePackLoadable, false)
    assert.equal(view.activeVersion, 'core')
    assert.equal(view.updatedBy, null)
    const partial = statusView({ active_version: 'alpha@1' })
    assert.equal(partial.activePackLoadable, false)
    assert.equal(partial.loadError, null)
  })
})

describe('pack row normalization (degraded list body never crashes the table)', () => {
  it('non-array → empty list', () => {
    assert.deepEqual(packRows(undefined), [])
    assert.deepEqual(packRows({}), [])
  })
  it('rows without a dir are dropped; rows with a dir keep their fields', () => {
    const rows = packRows([
      { dir: 'alpha', pack_id: 'alpha', pack_version: '1' },
      { pack_id: 'no-dir' },
      { dir: 'ghost', error: 'manifest.json not found' },
    ])
    assert.deepEqual(rows.map(r => r.dir), ['alpha', 'ghost'])
    assert.equal(rows[1]?.error, 'manifest.json not found')
  })
})
