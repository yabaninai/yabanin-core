import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { fetchLabelKeys, getOrganization } from '../../api/client'
import { BoardPanelCard } from './BoardPanelCard'
import { useOrgPresentation } from '../../i18n/useOrgPresentation'
import { uiLocale } from '../../i18n/format'
import { explorerHash, resolveBoard, type ResolvedPanel } from '../../lib/boards'
import { drillPanelPoint, loadPanels, type PanelPayload } from '../../lib/boardPanels'
import { listPinnedPanels, unpinPanel } from '../../lib/pinnedPanels'

// AUX-07 — the Overview side of "pin any panel". Pinned panels re-render for
// the Overview APPLIED scope (the org the page loaded + the GlobalScope
// window), with their own loads: one generation guard + one AbortController
// (asyncScope — no parallel loads, no stale landing). The board global
// filter does not exist here (Overview has no filter bar), so panels resolve
// with an empty board filter — resolveBoard still hides dimensions the org
// does not have. An empty pin list renders nothing (no reserved space).

interface PinnedPanelsProps {
  org: string
  from: string
  to: string
  tz: string
}

interface PinnedPanel {
  /** The stored pin id, `boardId/panelId`. */
  pin: string
  panel: ResolvedPanel
}

export function PinnedPanels({ org, from, to, tz }: PinnedPanelsProps) {
  const { t } = useTranslation()
  const [pins, setPins] = useState<string[]>(() => listPinnedPanels())
  const [keys, setKeys] = useState<string[]>([])
  const [template, setTemplate] = useState('')
  const [data, setData] = useState<Map<string, PanelPayload>>(new Map())
  const { currency } = useOrgPresentation(org || undefined)
  const metricFmt = useMemo(() => ({ locale: uiLocale(), currency }), [currency])
  // AVR-01: the caption must describe the window the shown data was fetched
  // with — captured when a load lands, not the live props.
  const [applied, setApplied] = useState<{ from: string; to: string; tz: string } | null>(null)

  const remove = (pin: string) => {
    unpinPanel(pin)
    setPins(cur => cur.filter(p => p !== pin))
  }

  // Label keys + issue template: the same context Dashboards resolves its
  // panels with, so a pinned panel keeps its shape on Overview.
  useEffect(() => {
    if (!org) { setKeys([]); setTemplate(''); return }
    const ctrl = new AbortController()
    fetchLabelKeys(org, from, to, { signal: ctrl.signal }).then(rows => setKeys(rows.map(r => r.key))).catch(() => setKeys([]))
    getOrganization(org, { signal: ctrl.signal }).then(o => setTemplate(o.issue_url_template ?? '')).catch(() => setTemplate(''))
    return () => ctrl.abort()
  }, [org, from, to])

  // Resolve every pin to its panel definition. A pin whose board/panel no
  // longer exists is dropped at the lib boundary already.
  const panels = useMemo<PinnedPanel[]>(() => {
    const out: PinnedPanel[] = []
    for (const pin of pins) {
      const sep = pin.indexOf('/')
      if (sep <= 0) continue
      const boardId = pin.slice(0, sep)
      const panelId = pin.slice(sep + 1)
      const board = resolveBoard(boardId, keys, { team: '', repo: '', issue: '' })
      const panel = board.find(p => p.id === panelId)
      if (panel && !panel.hidden) out.push({ pin, panel })
    }
    return out
  }, [pins, keys])

  const gen = useRef(0)
  const ctrl = useRef<AbortController | null>(null)

  const run = useCallback(async () => {
    if (panels.length === 0) { setData(new Map()); setApplied(null); return }
    const g = ++gen.current
    ctrl.current?.abort()
    const ac = new AbortController()
    ctrl.current = ac
    const result = await loadPanels(org, from, to, tz, panels.map(p => p.panel), ac.signal)
    if (gen.current !== g || ac.signal.aborted) return
    setData(result)
    setApplied({ from, to, tz })
  }, [org, from, to, tz, panels])

  useEffect(() => {
    void run()
    return () => ctrl.current?.abort()
  }, [run])

  if (panels.length === 0) return null

  const win = applied ?? { from, to, tz }
  return (
    <section className="flex flex-col gap-4" aria-label={t('dashboards.pinned')}>
      <h2 className="text-lg font-semibold text-[color:var(--astra-ink)]">{t('dashboards.pinned')}</h2>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {panels.map(({ pin, panel }) => (
          <BoardPanelCard
            key={pin}
            panel={panel}
            result={data.get(panel.id)}
            applied={applied ? { ...win, filter: panel.query.filter } : undefined}
            explorerHref={explorerHash(org, win.from, win.to, panel, { tz })}
            metricFmt={metricFmt}
            issueTemplate={template}
            pinned
            onTogglePin={() => remove(pin)}
            onPointClick={drillPanelPoint(panel, data.get(panel.id), org, win)}
          />
        ))}
      </div>
    </section>
  )
}
