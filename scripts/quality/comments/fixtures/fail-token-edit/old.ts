// Picks the first active session for the header chip.
export function firstActive(sessions: Session[]): Session | undefined {
  return sessions.find((s) => s.active)
}

export interface Session {
  id: string
  active: boolean
}
