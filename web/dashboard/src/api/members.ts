// Wrappers over EXISTING endpoints only (no new server contracts): whitelists
// and model aliases are root-only routes today; members/developers are
// org-scoped under members.manage.

import { fetchJSON, postJSON, type Paginated, type RequestOptions } from './http.ts'

export interface Team {
  id: string
  org_id: string
  name: string
  slug: string
  parent_team?: string | null
  created_at?: string
  updated_at?: string
}

export interface WhitelistEntry {
  id: number
  target_id: string
  model_name: string
  allowed: boolean
  created_at?: string
}

export type OrgRole = 'org-admin' | 'operator' | 'reader' | 'security_auditor' | 'partner'

// Mirrors adminstore.AllOrgRoles (roles.go) — the server validates this exact
// set and 400s anything else.
export const ORG_ROLES: OrgRole[] = ['org-admin', 'operator', 'reader', 'security_auditor', 'partner']

export interface OrgMembership {
  id: string
  user_id: string
  org_id: string
  role: OrgRole
  created_at?: string
  updated_at?: string
}

export interface DeveloperUser {
  id: string
  email: string
  display_name: string
  org_id: string
  team_id: string
  active: boolean
}

// W-INV: one pending member invitation (mirrors adminstore.MemberInvite —
// the wire format never carries token material; the one-time token exists
// only in the create/resend response's invite_path).
export interface MemberInvite {
  id: string
  org_id: string
  email: string
  role: OrgRole
  expires_at: string
  accepted_at?: string | null
  created_by: string
  invited_user_id?: string
  created_at?: string
  updated_at?: string
}

// Shape of the create/resend responses: invite_path is the one-time
// acceptance path ("/invite/<token>") — the only moment the raw token is
// visible anywhere.
export interface MemberInviteLink {
  invite: MemberInvite
  invite_path: string
  expires_at: string
}

function pageQuery(page: number, pageSize?: number): string {
  const q = new URLSearchParams({ page: String(page) })
  if (pageSize) q.set('page_size', String(pageSize))
  return q.toString()
}

// Teams are root-only (GET /api/teams?org_id=…). The access summary requests
// one large page (server cap 100) and sorts client-side; the count line
// honestly reports fetched vs total when the org has more.
export async function listTeams(orgId: string, page = 1, pageSize = 100, opts?: RequestOptions): Promise<Paginated<Team>> {
  return fetchJSON(`/teams?org_id=${encodeURIComponent(orgId)}&${pageQuery(page, pageSize)}`, opts)
}

export async function listKeyWhitelist(apiKeyID: string, page = 1, pageSize = 100, opts?: RequestOptions): Promise<Paginated<WhitelistEntry>> {
  return fetchJSON(`/whitelist/api-keys/${encodeURIComponent(apiKeyID)}?${pageQuery(page, pageSize)}`, opts)
}

export async function addKeyWhitelist(apiKeyID: string, modelName: string, allowed: boolean, opts?: RequestOptions): Promise<WhitelistEntry> {
  return postJSON<WhitelistEntry>(`/whitelist/api-keys/${encodeURIComponent(apiKeyID)}`, { model_name: modelName, allowed }, 'POST', opts)
}

export async function removeKeyWhitelist(apiKeyID: string, modelName: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/whitelist/api-keys/${encodeURIComponent(apiKeyID)}/${encodeURIComponent(modelName)}`, {}, 'DELETE', opts)
}

export async function listTeamWhitelist(teamID: string, page = 1, pageSize = 100, opts?: RequestOptions): Promise<Paginated<WhitelistEntry>> {
  return fetchJSON(`/whitelist/teams/${encodeURIComponent(teamID)}?${pageQuery(page, pageSize)}`, opts)
}

export async function addTeamWhitelist(teamID: string, modelName: string, allowed: boolean, opts?: RequestOptions): Promise<WhitelistEntry> {
  return postJSON<WhitelistEntry>(`/whitelist/teams/${encodeURIComponent(teamID)}`, { model_name: modelName, allowed }, 'POST', opts)
}

export async function removeTeamWhitelist(teamID: string, modelName: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/whitelist/teams/${encodeURIComponent(teamID)}/${encodeURIComponent(modelName)}`, {}, 'DELETE', opts)
}

export async function listOrgMembers(orgId: string, opts?: RequestOptions): Promise<OrgMembership[]> {
  const resp = await fetchJSON<{ data?: OrgMembership[] | null }>(`/organizations/${encodeURIComponent(orgId)}/members`, opts)
  return resp.data ?? []
}

export async function createOrgMember(orgId: string, userID: string, role: OrgRole, opts?: RequestOptions): Promise<OrgMembership> {
  return postJSON<OrgMembership>(`/organizations/${encodeURIComponent(orgId)}/members`, { user_id: userID, role }, 'POST', opts)
}

export async function updateOrgMember(orgId: string, userID: string, role: OrgRole, opts?: RequestOptions): Promise<OrgMembership> {
  return postJSON<OrgMembership>(`/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userID)}`, { role }, 'PUT', opts)
}

export async function deleteOrgMember(orgId: string, userID: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(userID)}`, {}, 'DELETE', opts)
}

// Developers only exist on portal-enabled deployments: the routes answer 404
// otherwise, which callers surface as an honest error state.
export async function listDevelopers(orgId: string, opts?: RequestOptions): Promise<DeveloperUser[]> {
  const resp = await fetchJSON<{ data?: DeveloperUser[] | null }>(`/organizations/${encodeURIComponent(orgId)}/developers`, opts)
  return resp.data ?? []
}

export async function createDeveloper(orgId: string, body: { email: string; display_name?: string; team_id?: string }, opts?: RequestOptions): Promise<DeveloperUser> {
  return postJSON<DeveloperUser>(`/organizations/${encodeURIComponent(orgId)}/developers`, body, 'POST', opts)
}

export async function setDeveloperActive(orgId: string, userID: string, active: boolean, opts?: RequestOptions): Promise<void> {
  await postJSON(`/organizations/${encodeURIComponent(orgId)}/developers/${encodeURIComponent(userID)}`, { active }, 'PUT', opts)
}

export async function deleteDeveloper(orgId: string, userID: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/organizations/${encodeURIComponent(orgId)}/developers/${encodeURIComponent(userID)}`, {}, 'DELETE', opts)
}

// --- Member invitations (W-INV, org:members.manage) ---

export async function listMemberInvites(orgId: string, opts?: RequestOptions): Promise<MemberInvite[]> {
  const resp = await fetchJSON<{ data?: MemberInvite[] | null; count?: number }>(
    `/organizations/${encodeURIComponent(orgId)}/members/invites`, opts)
  return resp.data ?? []
}

export async function inviteMember(orgId: string, email: string, role: OrgRole, opts?: RequestOptions): Promise<MemberInviteLink> {
  return postJSON<MemberInviteLink>(`/organizations/${encodeURIComponent(orgId)}/members/invite`, { email, role }, 'POST', opts)
}

export async function resendMemberInvite(orgId: string, inviteID: string, opts?: RequestOptions): Promise<MemberInviteLink> {
  return postJSON<MemberInviteLink>(`/organizations/${encodeURIComponent(orgId)}/members/invites/${encodeURIComponent(inviteID)}/resend`, {}, 'POST', opts)
}

export async function revokeMemberInvite(orgId: string, inviteID: string, opts?: RequestOptions): Promise<void> {
  await postJSON(`/organizations/${encodeURIComponent(orgId)}/members/invites/${encodeURIComponent(inviteID)}/revoke`, {}, 'POST', opts)
}
