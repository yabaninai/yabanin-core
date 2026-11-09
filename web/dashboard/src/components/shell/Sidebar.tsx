import { useId, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronDown, Lock, Search } from 'lucide-react'
import { filterCommands } from '../../lib/commandPalette'

// surfaces that show it: the calm paper sidebar on lg+ (this file's <nav>)
// and the below-lg disclosure panel in the Topbar (via SidebarNav). The
// sections arrive access-filtered (AUX-13) from App, so the sidebar, the
// disclosure and the ⌘K palette always agree on what is reachable.
//
// Item styling (Astra v2): active = selection ground + on-selection ink +
// a short 2px marker + aria-current; the marker column is reserved on
// inactive items (transparent border) so nothing shifts on selection.

export interface NavItemView {
  id: string
  labelKey: string
  icon: ReactNode
  /** D-UI-2 locked entry (Enterprise section): a focusable anchor to the
      EE app, rendered grey with a lock — never hidden, never a dead button. */
  href?: string
  locked?: boolean
}

export interface NavSectionView {
  labelKey: string
  items: NavItemView[]
}

export function SidebarNav({ sections, page, onNavigate, heading }: {
  sections: NavSectionView[]
  page: string
  onNavigate: (id: string) => void
  heading: boolean
}) {
  const { t } = useTranslation()
  const id = useId()
  const [query, setQuery] = useState('')
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set())
  const matches = new Set(filterCommands(query, sections.flatMap(section =>
    section.items.map(item => ({ id: item.id, label: t(item.labelKey), section: t(section.labelKey), keywords: [item.id] })),
  )).map(item => item.id))
  const filtered = sections.map(section => ({ ...section, items: section.items.filter(item => matches.has(item.id)) }))
  const searching = query.trim() !== ''
  return (
    <>
      <label className="mb-3 flex min-h-[44px] items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3">
        <Search size={16} className="shrink-0 text-[color:var(--astra-text-muted)]" aria-hidden="true" />
        <span className="sr-only">{t('app.filterNavigation')}</span>
        <input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder={t('app.filterNavigation')} className="min-h-[44px] min-w-0 w-full border-0 bg-transparent text-sm" />
      </label>
      {matches.size === 0 && <p role="status" className="px-3 py-2 text-sm text-[color:var(--astra-text-muted)]">{t('app.navigationNoMatches')}</p>}
      {filtered.map(section => {
        if (section.items.length === 0) return null
        const expanded = !heading || searching || !collapsed.has(section.labelKey)
        const itemsId = `${id}-${section.labelKey}`
        return (
          <div key={section.labelKey} role="group" aria-label={t(section.labelKey)} className={heading ? 'mb-3' : ''}>
            {heading && (
              <button
                type="button"
                aria-label={t('app.navigationSection', { section: t(section.labelKey) })}
                aria-expanded={expanded}
                aria-controls={itemsId}
                disabled={searching}
                onClick={() => {
                  if (searching) return
                  setCollapsed(previous => {
                    const next = new Set(previous)
                    if (next.has(section.labelKey)) next.delete(section.labelKey)
                    else next.add(section.labelKey)
                    return next
                  })
                }}
                className="flex min-h-[44px] w-full items-center justify-between gap-2 rounded-[length:var(--astra-radius-control)] px-3 text-start text-[11px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)]"
              >
                <span>{t(section.labelKey)}</span>
                <ChevronDown size={14} className={`shrink-0 ${expanded ? '' : '-rotate-90 rtl:rotate-90'}`} aria-hidden="true" />
              </button>
            )}
            <div id={itemsId} hidden={!expanded} className={expanded ? 'flex flex-col items-stretch gap-0.5' : ''}>
              {section.items.map(item => item.locked && item.href ? (
                // D-UI-2 (owner decision 2026-11-06): a locked Enterprise
                // entry is ALWAYS visible and never a dead button — it stays
                // a focusable anchor (Enter navigates to the EE app), grey
                // via the muted ink token with a lock marker and an
                // explanatory tooltip (design standard §9 Disabled: readable
                // label + reason, not just opacity).
                <a
                  key={item.id}
                  href={item.href}
                  aria-disabled="true"
                  title={t('app.navEeLocked')}
                  className="flex min-h-[44px] items-center gap-2 rounded-[length:var(--astra-radius-control)] border-s-2 border-s-transparent px-3 text-sm text-[color:var(--astra-text-muted)] no-underline transition-colors hover:bg-[color:var(--astra-surface-muted)] justify-start"
                >
                  <span aria-hidden="true" className="shrink-0">{item.icon}</span>
                  <span>{t(item.labelKey)}</span>
                  <Lock size={14} className="ms-auto shrink-0" aria-hidden="true" />
                </a>
              ) : (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => { setQuery(''); onNavigate(item.id) }}
                  aria-current={page === item.id ? 'page' : undefined}
                  className={`flex min-h-[44px] items-center gap-2 rounded-[length:var(--astra-radius-control)] border-s-2 px-3 text-sm transition-colors ${
                    page === item.id
                      ? 'border-s-[color:var(--astra-accent)] bg-[color:var(--astra-selection)] font-semibold text-[color:var(--astra-on-selection)]'
                      : 'border-s-transparent text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]'
                  } justify-start`}
                >
                  {item.icon}
                  {t(item.labelKey)}
                </button>
              ))}
            </div>
          </div>
        )
      })}
    </>
  )
}

export function Sidebar({ sections, page, onNavigate }: {
  sections: NavSectionView[]
  page: string
  onNavigate: (id: string) => void
}) {
  const { t } = useTranslation()
  return (
    <nav
      aria-label={t('app.adminNavigation')}
      className="sticky top-16 hidden h-[calc(100vh-4rem)] w-56 shrink-0 flex-col overflow-y-auto border-e border-[color:var(--astra-rule)] px-2 py-3 lg:flex"
    >
      <SidebarNav sections={sections} page={page} onNavigate={onNavigate} heading />
    </nav>
  )
}
