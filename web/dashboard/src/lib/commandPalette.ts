// AUX-21 (command palette): pure helpers — matching and grouping of the
// palette commands, plus the hash builders for its navigation actions. Kept
// out of the component so node:test can cover them without a DOM, mirroring
// lib/inspectUrl.ts. The palette is navigation-only on purpose: it never
// mutates anything, it only moves the operator (pages) or lands on a page
// with a prefilled filter (the errors-only view of the request explorer).

export interface CommandOption {
  /** Stable command id (page id, or a palette-… action id). */
  id: string
  /** Display label (already translated by the caller). */
  label: string
  /** Group/section label (already translated by the caller). */
  section: string
  /** Extra non-displayed match tokens (e.g. the raw page id). */
  keywords?: string[]
  /**
   * Prebuilt in-app hash for navigation actions (relatedListHref output).
   * Absent for plain page commands — the shell goto() applies.
   */
  href?: string
}

/** Case-insensitive substring match over label, section and keywords. */
export function filterCommands(query: string, commands: CommandOption[]): CommandOption[] {
  const q = query.trim().toLowerCase()
  if (q === '') return commands
  return commands.filter(
    c =>
      c.label.toLowerCase().includes(q) ||
      c.section.toLowerCase().includes(q) ||
      (c.keywords ?? []).some(k => k.toLowerCase().includes(q)),
  )
}

/** Group a flat command list by section, preserving first-seen order. */
export function groupCommands(commands: CommandOption[]): Array<{ section: string; items: CommandOption[] }> {
  const order: string[] = []
  const bySection = new Map<string, CommandOption[]>()
  for (const command of commands) {
    let items = bySection.get(command.section)
    if (!items) {
      items = []
      bySection.set(command.section, items)
      order.push(command.section)
    }
    items.push(command)
  }
  return order.map(section => ({ section, items: bySection.get(section)! }))
}

/** The committed YQL of the errors-only explorer view (queryLang registry). */
export const ERRORS_ONLY_YQL = 'status >= 400'

/**
 * Hash for a palette navigation action: the current hash query (org scope,
 * locale — the GlobalScope continuity contract) with the extra params set,
 * the stale inspect param dropped. A blank extra never encodes as `key=`.
 */
export function actionHref(target: string, extra: Record<string, string> = {}): string {
  const params = new URLSearchParams(
    typeof window === 'undefined'
      ? ''
      : (window.location.hash.split('?')[1] ?? ''),
  )
  params.delete('inspect')
  for (const [key, value] of Object.entries(extra)) {
    if (value.trim() !== '') params.set(key, value.trim())
  }
  const qs = params.toString()
  return `#${target}${qs ? `?${qs}` : ''}`
}
