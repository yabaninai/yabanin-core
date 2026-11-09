import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Building2, Check, ChevronsUpDown, Search } from 'lucide-react'
import type { ScopeOrgOption, ShellScopeController } from '../../hooks/useGlobalScope'

// shared GlobalScope store (hooks/useShellScope). A searchable listbox over
// org NAMES (never raw UUIDs first): root also gets "All organizations" and
// the root directory listing; a member sees exactly their /api/me orgs.
//   * The trigger shows the resolved org NAME; a current org beyond the loaded
//     directory page surfaces verbatim as "ID: <value>" (OrgSelect precedent)
//     instead of silently dropping it.
//   * Keyboard: the panel opens into the search field; ArrowDown/ArrowUp move
//     the active option, Enter commits, Escape closes and returns focus to the
//     trigger; Tab or a pointer-down outside closes without committing.
//   * RTL: logical properties only (ms/me/ps/pe, start/end) — the panel mirrors
//     under `dir="rtl"`.
//   * A deep link's ?org= is committed by the store before this control opens;
//     the switcher only renders and replaces the applied value.

const ALL = '__all_orgs__'

export function OrgSwitcher({ scope }: { scope: ShellScopeController }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const rootRef = useRef<HTMLDivElement | null>(null)
  const triggerRef = useRef<HTMLButtonElement | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const activeRef = useRef<HTMLButtonElement | null>(null)

  const options = useMemo<ScopeOrgOption[]>(() => {
    const base = scope.canAllOrgs ? [{ id: '', name: t('orgSwitcher.allOrgs') }, ...scope.options] : scope.options
    if (scope.org && !base.some(o => o.id === scope.org)) {
      return [...base, { id: scope.org, name: t('orgSelect.unknownOption', { id: scope.org }) }]
    }
    return base
  }, [scope.canAllOrgs, scope.options, scope.org, t])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return options
    return options.filter(o => o.name.toLowerCase().includes(q) || o.id.toLowerCase().includes(q))
  }, [options, query])

  useEffect(() => {
    setActive(0)
  }, [query])

  const close = (returnFocus: boolean) => {
    setOpen(false)
    setQuery('')
    if (returnFocus) triggerRef.current?.focus()
  }

  const pick = (option: ScopeOrgOption) => {
    scope.setOrg(option.id)
    close(true)
  }

  useEffect(() => {
    if (!open) return
    inputRef.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        close(true)
      }
    }
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) close(false)
    }
    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('pointerdown', onPointerDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('pointerdown', onPointerDown)
    }
  }, [open])

  useEffect(() => {
    activeRef.current?.scrollIntoView({ block: 'nearest' })
  }, [active, filtered.length])

  const label = !scope.org
    ? t('orgSwitcher.allOrgs')
    : (scope.orgName || t('orgSelect.unknownOption', { id: scope.org }))
  const activeId = filtered[active] ? `org-switcher-option-${filtered[active].id || ALL}` : undefined

  return (
    <div ref={rootRef} className="relative">
      {/* The trigger's accessible name deliberately avoids the word
          "organization" (orgSwitcher.open): page-level org selects are
          labeled t('scope.organization'), and specs address them with
          getByLabel — the shell control must never join that match. */}
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t('orgSwitcher.open')}
        onClick={() => (open ? close(true) : setOpen(true))}
        className="inline-flex min-h-[44px] max-w-[18rem] items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 text-sm text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]"
      >
        <Building2 size={16} aria-hidden="true" className="shrink-0 text-[color:var(--astra-text-muted)]" />
        <span className="min-w-0 truncate font-medium">{label}</span>
        <ChevronsUpDown size={14} aria-hidden="true" className="shrink-0 text-[color:var(--astra-text-muted)]" />
      </button>

      {open && (
        <div className="absolute start-0 z-30 mt-2 w-72 rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] p-2 shadow-lg">
          <div className="relative">
            <Search size={14} aria-hidden="true" className="pointer-events-none absolute inset-y-0 my-auto ms-2.5 text-[color:var(--astra-text-muted)]" />
            <input
              ref={inputRef}
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'ArrowDown') {
                  e.preventDefault()
                  setActive(a => Math.min(a + 1, filtered.length - 1))
                } else if (e.key === 'ArrowUp') {
                  e.preventDefault()
                  setActive(a => Math.max(a - 1, 0))
                } else if (e.key === 'Enter') {
                  e.preventDefault()
                  const option = filtered[active]
                  if (option) pick(option)
                }
              }}
              role="combobox"
              aria-expanded
              aria-controls="org-switcher-listbox"
              aria-activedescendant={activeId}
              aria-label={t('orgSwitcher.search')}
              placeholder={t('orgSwitcher.search')}
              className="control w-full ps-8"
            />
          </div>
          <div role="listbox" id="org-switcher-listbox" aria-label={t('orgSwitcher.open')} className="mt-1 max-h-64 overflow-y-auto">
            {scope.orgsLoading && (
              <p role="status" className="px-2 py-1.5 text-sm text-[color:var(--astra-text-muted)]">{t('orgSelect.loading')}</p>
            )}
            {!scope.orgsLoading && filtered.length === 0 && (
              <p className="px-2 py-1.5 text-sm text-[color:var(--astra-text-muted)]">{t('orgSwitcher.noMatches')}</p>
            )}
            {filtered.map((option, i) => {
              const selected = option.id === scope.org
              return (
                <button
                  key={option.id || ALL}
                  ref={i === active ? activeRef : undefined}
                  type="button"
                  role="option"
                  id={`org-switcher-option-${option.id || ALL}`}
                  aria-selected={selected}
                  onClick={() => pick(option)}
                  className={`flex min-h-[40px] w-full items-center gap-2 rounded-[length:var(--astra-radius-control)] px-2 text-start text-sm ${
                    i === active
                      ? 'bg-[color:var(--astra-selection)] text-[color:var(--astra-on-selection)]'
                      : 'text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]'
                  }`}
                >
                  <span className="min-w-0 flex-1 truncate">{option.name}</span>
                  {selected && <Check size={14} aria-hidden="true" className="shrink-0" />}
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
