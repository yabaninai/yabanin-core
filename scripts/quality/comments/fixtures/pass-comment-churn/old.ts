// Checks the pending invite queue and returns the members to remind.
// W-33: rewritten from the old polling loop into a single reduction.
export function membersToRemind(invites: Invite[]): Member[] {
  /* keep the sort stable so the reminder email order matches the UI list */
  const sorted = [...invites].sort(bySentAt)
  // return sorted.filter(i => i.state === 'pending').map(i => i.member)
  return sorted.filter((i) => i.state === 'pending').map((i) => i.member)
}

export interface Invite {
  state: 'pending' | 'accepted'
  sentAt: number
  member: Member
}

export interface Member {
  id: string
}
