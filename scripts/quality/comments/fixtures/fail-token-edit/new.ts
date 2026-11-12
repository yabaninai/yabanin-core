export function firstActive(sessions: Session[]): Session | undefined {
  return sessions.find((s) => s.enabled)
}

export interface Session {
  id: string
  active: boolean
}
