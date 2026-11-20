import type { GlobalScopeState } from '../lib/globalScope'

export function requestExplorerWindow(scope: Pick<GlobalScopeState, 'period' | 'from' | 'to'>, now = new Date()): { from: string; to: string } {
  if (scope.period === 'custom') return { from: scope.from, to: scope.to }
  const span = Date.parse(scope.to) - Date.parse(scope.from)
  return { from: new Date(now.getTime() - span).toISOString(), to: now.toISOString() }
}
