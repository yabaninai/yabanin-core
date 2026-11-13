// ONLY the server's accepted fields (unknown fields 400 via
// DisallowUnknownFields), the versioned activate rides active_version, and
// a validation rejection surfaces its server message verbatim (the editor
// shows exactly what validatePolicyYAML answered).

import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

import { getPolicy, getPolicyDrift, isPolicyConflictError, listPolicies, policyConflictCurrent, policyValidationErrorText, updatePolicy, validatePolicyDoc } from './policyPipelines.ts'
import { ApiError, resetCsrf } from './transport.ts'

interface Call { url: string; init: RequestInit }
type Handler = (call: Call) => { status: number; body: unknown }

const realFetch = globalThis.fetch
const calls: Call[] = []

function installFetch(handler: Handler): void {
  calls.length = 0
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const call = { url: String(url), init: init ?? {} }
    calls.push(call)
    const res = handler(call)
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      statusText: '',
      headers: new Headers({ 'Content-Type': 'application/json' }),
      json: async () => res.body,
      text: async () => JSON.stringify(res.body),
    } as unknown as Response
  }) as typeof fetch
}

function csrfAware(handler: Handler): Handler {
  return call => (call.url === '/auth/csrf'
    ? { status: 200, body: { csrf_token: 'tok-policy' } }
    : handler(call))
}

afterEach(() => {
  globalThis.fetch = realFetch
  resetCsrf()
})

test('listPolicies unwraps {data, count}', async () => {
  installFetch(csrfAware(() => ({
    status: 200,
    body: { data: [{ id: 'pp_1', org_id: 'o', name: 'deny-net', enabled: true, current_version: 2, created_at: '', updated_at: '' }], count: 1 },
  })))
  const rows = await listPolicies('org 1')
  assert.equal(rows.length, 1)
  assert.equal(rows[0].name, 'deny-net')
  assert.equal(calls[0].url, '/api/organizations/org%201/policies')
})

test('getPolicy returns the detail (versions newest first per the server)', async () => {
  installFetch(csrfAware(() => ({
    status: 200,
    body: { policy: { id: 'pp_1' }, versions: [{ version: 2 }, { version: 1 }], attachments: [] },
  })))
  const d = await getPolicy('o', 'pp_1')
  assert.equal(d.versions[0].version, 2)
  assert.equal(calls[0].url, '/api/organizations/o/policies/pp_1')
})

test('updatePolicy carries exactly the changed fields (nothing else)', async () => {
  installFetch(csrfAware(() => ({ status: 200, body: { policy: { id: 'pp_1' } } })))
  const policyCalls = () => calls.filter(c => c.url.includes('/policies/pp_1'))

  await updatePolicy('o', 'pp_1', { active_version: 3 })
  assert.equal(policyCalls()[0].init.method, 'PUT')
  assert.deepEqual(JSON.parse(String(policyCalls()[0].init.body)), { active_version: 3 },
    'activate = PUT with the version field only')

  await updatePolicy('o', 'pp_1', { yaml: 'kind: Policy\n' })
  assert.deepEqual(JSON.parse(String(policyCalls()[1].init.body)), { yaml: 'kind: Policy\n' },
    'a draft save = PUT with the yaml field only')

  await updatePolicy('o', 'pp_1', { enabled: false })
  assert.deepEqual(JSON.parse(String(policyCalls()[2].init.body)), { enabled: false })

  await updatePolicy('o', 'pp_1', {})
  assert.deepEqual(JSON.parse(String(policyCalls()[3].init.body)), {},
    'an empty patch is sent as-is — the server 400s "nothing to update" honestly')
})

test('a validation rejection surfaces the server message verbatim', async () => {
  installFetch(csrfAware(() => ({ status: 400, body: { error: 'policy yaml must declare kind: Policy' } })))
  await assert.rejects(() => updatePolicy('o', 'pp_1', { yaml: 'nope' }))
  assert.equal(policyValidationErrorText(new Error('x')), '', 'non-ApiError is not a validation rejection')

  let caught: unknown
  try { await updatePolicy('o', 'pp_1', { yaml: 'nope' }) } catch (err) { caught = err }
  assert.equal(policyValidationErrorText(caught), 'policy yaml must declare kind: Policy')
})

test('updatePolicy carries the concurrency token exactly when supplied', async () => {
  installFetch(csrfAware(() => ({ status: 200, body: { policy: { id: 'pp_1' } } })))
  const policyCalls = () => calls.filter(c => c.url.includes('/policies/pp_1'))

  await updatePolicy('o', 'pp_1', { yaml: 'kind: Policy\n', version: 2 })
  assert.deepEqual(JSON.parse(String(policyCalls()[0].init.body)), { yaml: 'kind: Policy\n', version: 2 },
    'the loaded current_version rides the body')

  await updatePolicy('o', 'pp_1', { active_version: 3, version: 0 })
  assert.deepEqual(JSON.parse(String(policyCalls()[1].init.body)), { active_version: 3, version: 0 },
    'version 0 (never activated) is a REAL token — it must be sent, not dropped')

  await updatePolicy('o', 'pp_1', { enabled: true })
  assert.deepEqual(JSON.parse(String(policyCalls()[2].init.body)), { enabled: true },
    'absent token = the legacy unconditional PUT')
})

test('a 409 is recognized as the stale-version conflict and unwraps the live current_version', async () => {
  installFetch(csrfAware(() => ({
    status: 409,
    body: { error: 'version conflict: the policy changed since you loaded it', current: { policy: { id: 'pp_1', current_version: 7 } } },
  })))
  let caught: unknown
  try { await updatePolicy('o', 'pp_1', { active_version: 3, version: 2 }) } catch (err) { caught = err }
  assert.equal(isPolicyConflictError(caught), true, 'the 409 is the conflict')
  assert.equal(policyConflictCurrent(caught), 7, 'the live current_version unwraps for the rebase offer')
})

test('conflict helpers stay strict about what is NOT a conflict', async () => {
  installFetch(csrfAware(() => ({ status: 400, body: { error: 'policy yaml must declare kind: Policy' } })))
  let validation: unknown
  try { await updatePolicy('o', 'pp_1', { yaml: 'nope' }) } catch (err) { validation = err }
  assert.equal(isPolicyConflictError(validation), false, 'a 400 is not a conflict')
  assert.equal(policyConflictCurrent(validation), null)

  const malformed = new ApiError(409, 'conflict', 'conflict', 'not-json{')
  assert.equal(policyConflictCurrent(malformed), null, 'a malformed 409 body degrades to null, never a guess')

  assert.equal(policyConflictCurrent(new Error('x')), null, 'non-ApiError is never a conflict')
})

// --- validate endpoint, drift report, git_sha ban

test('validatePolicyDoc posts the draft to /policies/validate and echoes the identity', async () => {
  installFetch(csrfAware(() => ({ status: 200, body: { valid: true, name: 'pii-guard', mode: 'shadow' } })))
  const ok = await validatePolicyDoc('o', 'kind: Policy\n')
  const call = calls[calls.length - 1]
  assert.ok(call.url.includes('/policies/validate'), 'the arbiter endpoint is hit')
  assert.equal(call.init.method, 'POST')
  assert.deepEqual(JSON.parse(String(call.init.body)), { yaml: 'kind: Policy\n' })
  assert.deepEqual(ok, { valid: true, name: 'pii-guard', mode: 'shadow' })
})

test('validatePolicyDoc rejects with the server text — no local YAML opinion', async () => {
  installFetch(csrfAware(() => ({ status: 400, body: { error: 'policy yaml: unknown field "bogus_field"' } })))
  let caught: unknown
  try { await validatePolicyDoc('o', 'bogus_field: true') } catch (err) { caught = err }
  assert.equal(policyValidationErrorText(caught), 'policy yaml: unknown field "bogus_field"',
    'the verbatim server message is the one the editor will show')
})

test('getPolicyDrift fetches the drift report and returns it whole', async () => {
  installFetch(csrfAware(() => ({
    status: 200,
    body: {
      org_id: 'o', count: 2, drift_count: 1,
      data: [
        { policy_id: 'pp_1', name: 'pii-guard', status: 'drift', enabled: true, current_version: 2, latest_version: 3, latest_git_sha: '', latest_created_by: 'admin@x', latest_edited_at: 'now' },
        { policy_id: 'pp_2', name: 'tox-guard', status: 'managed', enabled: true, current_version: 4, latest_version: 4, latest_git_sha: 'abc', latest_created_by: 'reconcile', latest_edited_at: 'then' },
      ],
    },
  })))
  const report = await getPolicyDrift('o')
  assert.ok(calls[calls.length - 1].url.includes('/policies/drift'), 'the drift endpoint is hit')
  assert.equal(report.drift_count, 1)
  assert.equal(report.data[0].status, 'drift')
  assert.equal(report.data[1].status, 'managed')
})

test('the update patch carries no git_sha (owner decision 2026-11-04, G3)', async () => {
  // Source-level pin: the UI must not even offer the field — the API 400s
  // any caller-supplied git_sha (authorship is reconcile-managed).
  const { readFileSync } = await import('node:fs')
  const { dirname, join } = await import('node:path')
  const { fileURLToPath } = await import('node:url')
  const here = dirname(fileURLToPath(import.meta.url))
  const src = readFileSync(join(here, 'policyPipelines.ts'), 'utf8')
  assert.ok(!src.includes('git_sha?'), 'PolicyUpdatePatch must not carry git_sha')
  assert.ok(!src.includes('body.git_sha'), 'updatePolicy must not forward git_sha')
})
