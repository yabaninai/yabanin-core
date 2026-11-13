// The newline after `return` is load-bearing (ASI): this version returns
// undefined, which is why the token stream must record line boundaries.
export function firstActive(users: User[]): User | undefined {
  return // the list is newest-first; IMP-7 settled on undefined-for-empty
    users.find((u) => u.active)
}

export interface User {
  id: string
  active: boolean
}
