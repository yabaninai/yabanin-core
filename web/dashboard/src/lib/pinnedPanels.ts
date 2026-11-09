// AUX-07 — "pin any board panel to Overview". A pin is the panel identity
// (`<boardId>/<panelId>`) in a per-browser localStorage list; on Overview the
// pinned panels re-render for the Overview applied scope (org · GlobalScope
// window), never a snapshot of numbers. Persistence rules mirror
// lib/tablePrefs.ts (AUX-22): one key, untrusted JSON re-validated on read,
// best-effort writes. The saved-views/useTablePrefs contracts do not fit a
// pin (a pin has no query snapshot and no columns), so this is a third,
// deliberately smaller registry.
//
// The valid-id check happens at the lib boundary via the BOARDS registry, so
// a hand-edited localStorage entry can never resolve to a panel that does
// not exist.

import { BOARDS } from './boards.ts'

const KEY = 'yabanin.pinnedPanels.v1'
const MAX_PINS = 12

/** Every panel id that exists on some board, e.g. `budgets/top-agents`. */
export function validPanelIds(): Set<string> {
  const out = new Set<string>()
  for (const [boardId, board] of Object.entries(BOARDS)) {
    for (const panel of board.panels) out.add(`${boardId}/${panel.id}`)
  }
  return out
}

/** Validates an untrusted parsed-JSON value into a clean pin list. */
export function parsePinnedPanels(raw: unknown, valid: Set<string>): string[] {
  if (!Array.isArray(raw)) return []
  const out: string[] = []
  for (const entry of raw) {
    if (typeof entry !== 'string') continue
    const id = entry.trim()
    if (!id || id.length > 80 || !valid.has(id)) continue
    if (!out.includes(id)) out.push(id)
    if (out.length >= MAX_PINS) break
  }
  return out
}

export function listPinnedPanels(): string[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return []
    return parsePinnedPanels(JSON.parse(raw), validPanelIds())
  } catch {
    return []
  }
}

function writePins(pins: string[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(pins.slice(0, MAX_PINS)))
  } catch {
    // Private mode / tests — persistence is best-effort.
  }
}

export function pinPanel(id: string): void {
  if (!validPanelIds().has(id)) return
  const pins = listPinnedPanels()
  if (pins.includes(id) || pins.length >= MAX_PINS) return
  writePins([...pins, id])
}

export function unpinPanel(id: string): void {
  writePins(listPinnedPanels().filter(p => p !== id))
}
