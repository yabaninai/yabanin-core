// TP-06: async results belong to the org scope that started them. Every
// in-flight operation captures the (org, epoch) it was launched under; a
// completion may only be applied while that scope is still current. The
// epoch is page-local and bumps exactly once per org switch, so a delayed
// create/rotate/list from org A can never mutate org B's state or surface
// A's one-time key under B's scope.
export interface AsyncScope {
  org: string
  epoch: number
}

export function isCurrentScope(seen: AsyncScope, current: AsyncScope): boolean {
  return seen.org === current.org && seen.epoch === current.epoch
}
