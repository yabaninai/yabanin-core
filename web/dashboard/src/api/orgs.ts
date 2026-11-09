
import { fetchJSON, postJSON, listQuery, DEFAULT_PAGE_SIZE, type Paginated, type ListSortParams, type RequestOptions } from './http.ts'

export interface Organization {
  id: string
  name: string
  slug: string
  created_at?: string
  // I18N-11: per-org presentation settings. Currency is an ISO-4217 code
  // (default "USD"); timezone is an IANA name (default "UTC") used for
  // billing-day bucketing and localized date/currency rendering.
  currency?: string
  timezone?: string
  issue_url_template?: string
}

export async function listOrganizations(page = 1, opts?: RequestOptions & ListSortParams & { pageSize?: number }): Promise<Paginated<Organization>> {
  return fetchJSON(`/organizations?${listQuery(page, opts?.pageSize ?? DEFAULT_PAGE_SIZE, opts?.sort, opts?.dir)}`, opts)
}

export async function getOrganization(id: string, opts?: RequestOptions): Promise<Organization> {
  return fetchJSON(`/organizations/${encodeURIComponent(id)}`, opts)
}

export async function createOrganization(name: string, slug: string, opts?: RequestOptions): Promise<Organization> {
  return postJSON('/organizations', { name, slug }, 'POST', opts)
}

/** UI-VF-1: PUT /api/organizations/{id} — full update of editable fields. */
export async function updateOrganization(
  id: string,
  values: { name: string; slug: string; currency: string; timezone: string; issue_url_template?: string },
  opts?: RequestOptions,
): Promise<void> {
  await postJSON(`/organizations/${encodeURIComponent(id)}`, values, 'PUT', opts)
}

/** UI-VF-1: DELETE /api/organizations/{id}. */
export async function deleteOrganization(id: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/organizations/${encodeURIComponent(id)}`, {}, 'DELETE', opts)
}
