// listQuery(page, pageSize, sort, dir) must sign EVERY range with an explicit
// page_size — today it omits it, so the server slices at its own default (50)
// while page labels assume the page's PAGE_SIZE (25 on Orgs/Models): the
// "1–25 of N" line describes rows the server never sent. Page counts come
// only from the response's pagination (total_pages/total), never from a
// local counter.
//
// applied, client.ts neither exports listQuery nor loads under
// node --experimental-strip-types (extensionless relative imports); a static
// import would crash the whole file instead of failing these assertions one
// api/http.ts — update the path then.
import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'

// Post-patch signatures (client.ts is frozen until the HOT-PATCH lands).
type ListQuery = (page: number, pageSize: number, sort?: string, dir?: 'asc' | 'desc') => string
interface ListOpts {
  signal?: AbortSignal
  sort?: string
  dir?: 'asc' | 'desc'
  pageSize?: number
}

async function clientModule(): Promise<Record<string, unknown>> {
  try {
    return await import('../api/client.ts') as unknown as Record<string, unknown>
  } catch (e) {
    assert.fail(
      `client.ts must import under node --test (got: ${String(e)}). ` +
      'HOT-PATCH IMP-05 part 1 (export listQuery + .ts import extensions) is not applied yet.',
    )
  }
}

async function listQueryFn(): Promise<ListQuery> {
  const mod = await clientModule()
  assert.equal(
    typeof mod.listQuery,
    'function',
    'client.ts must export listQuery — HOT-PATCH IMP-05 part 1 is not applied yet ' +
    '(the query builder is the pagination contract, D-05).',
  )
  return mod.listQuery as ListQuery
}

// ---- listQuery itself: the signed range --------------------------------

test('listQuery signs every range with page_size (D-05)', async () => {
  const listQuery = await listQueryFn()
  const q = new URLSearchParams(listQuery(2, 25))
  assert.equal(q.get('page'), '2')
  assert.equal(q.get('page_size'), '25')
})

test('listQuery carries sort/dir when given and omits them otherwise', async () => {
  const listQuery = await listQueryFn()
  const sorted = new URLSearchParams(listQuery(3, 25, 'name', 'desc'))
  assert.equal(sorted.get('page'), '3')
  assert.equal(sorted.get('page_size'), '25')
  assert.equal(sorted.get('sort'), 'name')
  assert.equal(sorted.get('dir'), 'desc')

  const plain = new URLSearchParams(listQuery(1, 50))
  assert.equal(plain.get('sort'), null)
  assert.equal(plain.get('dir'), null)
})

test('listQuery defaults: page=1 with the server page size (50)', async () => {
  const listQuery = await listQueryFn()
  const q = new URLSearchParams(listQuery(1, 50))
  assert.equal(q.get('page'), '1')
  assert.equal(q.get('page_size'), '50')
  assert.equal(q.get('sort'), null)
  assert.equal(q.get('dir'), null)
})

// ---- wrapper level: every list endpoint routes through listQuery --------

const realFetch = globalThis.fetch
let lastUrl = ''

function stubListBody(body: unknown) {
  lastUrl = ''
  globalThis.fetch = (async (url: RequestInfo | URL): Promise<Response> => {
    lastUrl = String(url)
    return { ok: true, status: 200, json: async () => body } as unknown as Response
  }) as typeof fetch
}

afterEach(() => {
  globalThis.fetch = realFetch
})

const EMPTY_PAGE = { data: [], pagination: { page: 1, page_size: 50, total: 0, total_pages: 0 } }

async function listFn(mod: Record<string, unknown>, name: string): Promise<(page?: number, opts?: ListOpts) => Promise<unknown>> {
  assert.equal(
    typeof mod[name],
    'function',
    `client.ts must export ${name} — HOT-PATCH IMP-05 part 2 (call sites) is not applied yet.`,
  )
  return mod[name] as (page?: number, opts?: ListOpts) => Promise<unknown>
}

test('listOrganizations sends page_size and keeps the AUX-03 sort/dir', async () => {
  const mod = await clientModule()
  const listOrganizations = await listFn(mod, 'listOrganizations')
  stubListBody(EMPTY_PAGE)
  await listOrganizations(2, { pageSize: 25, sort: 'name', dir: 'asc' })
  const url = new URL(lastUrl, 'http://localhost')
  assert.equal(url.pathname, '/api/organizations')
  assert.equal(url.searchParams.get('page'), '2')
  assert.equal(url.searchParams.get('page_size'), '25')
  assert.equal(url.searchParams.get('sort'), 'name')
  assert.equal(url.searchParams.get('dir'), 'asc')
})

test('listOrganizations falls back to the server page size (50)', async () => {
  const mod = await clientModule()
  const listOrganizations = await listFn(mod, 'listOrganizations')
  stubListBody(EMPTY_PAGE)
  await listOrganizations(1)
  const url = new URL(lastUrl, 'http://localhost')
  assert.equal(url.searchParams.get('page'), '1')
  assert.equal(url.searchParams.get('page_size'), '50')
})

test('listAPIKeys routes its pageSize through listQuery (no ad-hoc suffix)', async () => {
  const mod = await clientModule()
  const listAPIKeys = await listFn(mod, 'listAPIKeys')
  stubListBody(EMPTY_PAGE)
  await listAPIKeys('org-1', 2, { pageSize: 25 })
  const url = new URL(lastUrl, 'http://localhost')
  assert.equal(url.pathname, '/api/api-keys')
  assert.equal(url.searchParams.get('org_id'), 'org-1')
  assert.equal(url.searchParams.get('page'), '2')
  assert.equal(url.searchParams.get('page_size'), '25')
})

test('listAuditLogs and listAdminUsers send page_size too', async () => {
  const mod = await clientModule()
  const listAuditLogs = await listFn(mod, 'listAuditLogs')
  const listAdminUsers = await listFn(mod, 'listAdminUsers')

  stubListBody({ audit_logs: [], total: 0, page: 3, page_size: 25 })
  await listAuditLogs(3, { pageSize: 25 })
  const auditUrl = new URL(lastUrl, 'http://localhost')
  assert.equal(auditUrl.pathname, '/api/audit-logs')
  assert.equal(auditUrl.searchParams.get('page'), '3')
  assert.equal(auditUrl.searchParams.get('page_size'), '25')

  stubListBody(EMPTY_PAGE)
  await listAdminUsers(1, { pageSize: 50 })
  const adminsUrl = new URL(lastUrl, 'http://localhost')
  assert.equal(adminsUrl.pathname, '/api/admin-users')
  assert.equal(adminsUrl.searchParams.get('page'), '1')
  assert.equal(adminsUrl.searchParams.get('page_size'), '50')
})
