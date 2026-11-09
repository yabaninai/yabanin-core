// Cross-tab org continuity (user finding 2026-09-15): the org scope is part
// of the URL per UI-contract #1, but each tab starts from its own URL — the
// operator had to copy-paste the org id between screens. The last committed
// org is remembered here (best-effort localStorage) and used ONLY as a
// fallback when the arriving URL carries no org; an explicit ?org= in the
// link always wins, so shareable deep links keep their exact meaning.
const KEY = 'yabanin.orgScope.v1'

export function readLastOrg(): string {
  try {
    return localStorage.getItem(KEY) ?? ''
  } catch {
    return ''
  }
}

export function rememberOrg(orgId: string): void {
  try {
    if (orgId) localStorage.setItem(KEY, orgId)
    else localStorage.removeItem(KEY)
  } catch {
    // Private mode / tests — continuity is best-effort.
  }
}
