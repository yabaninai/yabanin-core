// unchanged).

import { fetchJSON, postJSON, listQuery, DEFAULT_PAGE_SIZE, type Paginated, type ListSortParams, type RequestOptions } from './http.ts'

export interface AdminUser {
  id: string
  email: string
  display_name: string
  is_root: boolean
  active: boolean
  created_at?: string
  updated_at?: string
}

// Admin users support the server sort allowlist (id, email,
// display_name, is_root, active, created_at).
export async function listAdminUsers(page = 1, opts?: RequestOptions & ListSortParams & { pageSize?: number }): Promise<Paginated<AdminUser>> {
  return fetchJSON(`/admin-users?${listQuery(page, opts?.pageSize ?? DEFAULT_PAGE_SIZE, opts?.sort, opts?.dir)}`, opts)
}

export async function createAdminUser(body: { email: string; password: string; name: string; is_root: boolean }, opts?: RequestOptions): Promise<AdminUser> {
  return postJSON<AdminUser>('/admin-users', body, 'POST', opts)
}

export async function updateAdminUser(id: string, body: { name?: string; is_root?: boolean }, opts?: RequestOptions): Promise<void> {
  await postJSON(`/admin-users/${encodeURIComponent(id)}`, body, 'PUT', opts)
}

export async function deleteAdminUser(id: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/admin-users/${encodeURIComponent(id)}`, {}, 'DELETE', opts)
}
