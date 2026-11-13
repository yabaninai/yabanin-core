export function firstActive(users: User[]): User | undefined {
  return users.find((u) => u.active)
}

export interface User {
  id: string
  active: boolean
}
