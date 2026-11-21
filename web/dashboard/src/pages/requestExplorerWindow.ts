import type { GlobalScopeState } from '../lib/globalScope'

export type RequestWindow = { from: string; to: string }

export function requestExplorerWindow(scope: Pick<GlobalScopeState, 'period' | 'from' | 'to'>, now = new Date()): RequestWindow {
  if (scope.period === 'custom') return { from: scope.from, to: scope.to }
  const span = Date.parse(scope.to) - Date.parse(scope.from)
  return { from: new Date(now.getTime() - span).toISOString(), to: now.toISOString() }
}

export function resolveRequestFilters(
  scope: Pick<GlobalScopeState, 'org' | 'period' | 'from' | 'to'>,
  query: string,
  onWindow: (window: RequestWindow) => void,
  now = new Date(),
): { orgId: string; from: string; to: string; query?: string } {
  const window = requestExplorerWindow(scope, now)
  onWindow(window)
  return { orgId: scope.org.trim(), from: window.from, to: window.to, query: query || undefined }
}
