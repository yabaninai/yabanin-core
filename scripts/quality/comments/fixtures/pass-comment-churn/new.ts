export function membersToRemind(invites: Invite[]): Member[] {
  // Stable sort keeps reminder email order aligned with the UI list.
  const sorted = [...invites].sort(bySentAt)
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
