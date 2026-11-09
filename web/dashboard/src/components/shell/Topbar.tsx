import { useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react'
import { useTranslation } from 'react-i18next'
import { Check, ChevronDown, Menu, Search, X } from 'lucide-react'
import { OrgSwitcher } from './OrgSwitcher'
import { UserMenu } from './UserMenu'
import { PERIOD_PRESETS, type PeriodPreset } from '../../lib/analyticsQuery'
import type { ShellScopeController } from '../../hooks/useGlobalScope'

//   brand · OrgSwitcher · period preset · version-banner slot · ⌘K · user
//   menu · (below lg) the navigation disclosure toggle.
//
// The org + period controls drive the shared GlobalScope store, so a choice
// here follows the operator onto every scoped screen without re-selection.
// Below lg the same controls move into the disclosure panel above the
// navigation sections — the global scope stays reachable at every width.
//
// the layout must not shift when the banner lands.

export interface TopbarProps {
  scope: ShellScopeController
  navId: string
  navOpen: boolean
  onToggleNav: () => void
  navToggleRef: RefObject<HTMLButtonElement>
  /** The (access-filtered) navigation for the below-lg disclosure panel. */
  navSlot: ReactNode
  paletteOpen: boolean
  onTogglePalette: () => void
  paletteButtonRef: RefObject<HTMLButtonElement>
  onSignedOut: () => void
}

export function Topbar({
  scope, navId, navOpen, onToggleNav, navToggleRef, navSlot,
  paletteOpen, onTogglePalette, paletteButtonRef, onSignedOut,
}: TopbarProps) {
  const { t } = useTranslation()
  const scopeControls = (
    <div className="flex min-w-0 flex-wrap items-center gap-2">
      <OrgSwitcher scope={scope} />
      <PeriodPresetSelect scope={scope} />
    </div>
  )
  return (
    <header className="sticky top-0 z-20 border-b border-[color:var(--astra-rule)] bg-[color:var(--astra-paper)]">
      <div className="flex h-16 items-center justify-between gap-x-6 px-4 md:px-6">
        <div className="flex min-w-0 items-center gap-3">
          {/* Brand */}
          <span
            aria-hidden="true"
            className="grid h-8 w-7 shrink-0 place-items-center border border-[color:var(--astra-ink)] bg-[color:var(--astra-surface)] text-lg font-semibold leading-none text-[color:var(--astra-ink)]"
            style={{ transform: 'rotate(-7deg)' }}
          >
            Y
          </span>
          <span className="text-xl font-semibold tracking-tight text-[color:var(--astra-ink)]">{t('app.brand')}</span>
          {/* Global scope on one wide topbar band (lg+); below lg it lives in
              the disclosure panel. The testids keep the two copies apart for
              the harness — the hidden copy stays out of the way. */}
          <div data-testid="topbar-scope" className="hidden min-w-0 ps-4 lg:block">{scopeControls}</div>
        </div>

        <div className="flex items-center gap-2">
          {/* version-banner slot — deliberately empty; the layout must not shift when the banner lands. */}
          <div data-testid="version-banner-slot" className="min-w-0" />

          <button
            ref={paletteButtonRef}
            type="button"
            aria-haspopup="dialog"
            aria-expanded={paletteOpen}
            onClick={onTogglePalette}
            className="inline-flex min-h-[44px] items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-2 text-sm text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] sm:px-3"
          >
            <Search size={16} aria-hidden="true" />
            <span className="sr-only">{t('palette.open')}</span>
            {/* The shortcut hint reads on wide topbars only: at 360px with
                enlarged root text (the AVR-10 stress) the topbar must keep
                the document within its bound, so below sm the button is the
                icon alone (the sr-only label stays). */}
            <kbd aria-hidden="true" className="hidden rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] bg-[color:var(--astra-surface-muted)] px-1 text-xs text-[color:var(--astra-text-muted)] sm:inline">
              {/Mac|iPhone|iPad/.test(navigator.platform) ? t('palette.kbdMac') : t('palette.kbdOther')}
            </kbd>
          </button>

          <UserMenu scope={scope} onSignedOut={onSignedOut} />

          <button
            ref={navToggleRef}
            type="button"
            aria-expanded={navOpen}
            aria-controls={navId}
            onClick={onToggleNav}
            className="inline-flex min-h-[44px] min-w-[44px] items-center justify-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] lg:hidden"
          >
            {navOpen ? <X size={20} aria-hidden="true" /> : <Menu size={20} aria-hidden="true" />}
            <span className="sr-only">{navOpen ? t('app.closeNavigation') : t('app.openNavigation')}</span>
          </button>
        </div>
      </div>

      {/* Mobile disclosure panel: display:none when closed (hidden from AT
          too); state is conveyed by aria-expanded on the toggle. The global
          scope controls ride above the navigation sections. */}
      <nav
        id={navId}
        aria-label={t('app.adminNavigation')}
        className={`border-t border-[color:var(--astra-rule)] bg-[color:var(--astra-paper)] px-4 pb-3 pt-1 lg:hidden ${navOpen ? 'block' : 'hidden'}`}
      >
        <div data-testid="disclosure-scope" className="pb-2 pt-1">{scopeControls}</div>
        {navSlot}
      </nav>
    </header>
  )
}

// "Custom range…" entry. A pinned custom window (deep link ?from=&to=) shows
// as the selected "Custom" state; the popover commits exact borders through
// the same store (setRange), so every scoped screen follows.
//
// The control is a button + listbox menu, NOT a native <select>: page-level
// period selects are located by their options (`locator('select', { has:
// option … })` in the harness) — a second select carrying the same option
// labels would break those scans (the aux04 strict-violation class). A
// closed menu renders nothing, so idle-shell tests never see its options.

const PERIOD_CUSTOM = '__custom_range__'

export function PeriodPresetSelect({ scope }: { scope: ShellScopeController }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const [customOpen, setCustomOpen] = useState(false)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const rootRef = useRef<HTMLDivElement | null>(null)
  const triggerRef = useRef<HTMLButtonElement | null>(null)
  const listboxRef = useRef<HTMLDivElement | null>(null)
  const activeRef = useRef<HTMLButtonElement | null>(null)

  const pinned = scope.period === 'custom'

  const items = useMemo<Array<{ id: string; label: string }>>(() => {
    const list: Array<{ id: string; label: string }> = PERIOD_PRESETS.map(p => ({ id: p, label: t(`analytics.preset.${p}`) }))
    if (pinned) list.push({ id: 'custom', label: t('analytics.preset.custom') })
    list.push({ id: PERIOD_CUSTOM, label: t('period.customRange') })
    return list
  }, [pinned, t])

  const close = (returnFocus: boolean) => {
    setOpen(false)
    if (returnFocus) triggerRef.current?.focus()
  }

  useEffect(() => {
    if (!open && !customOpen) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        setCustomOpen(false)
        close(true)
      }
    }
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setCustomOpen(false)
        close(false)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('pointerdown', onPointerDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('pointerdown', onPointerDown)
    }
  }, [open, customOpen])

  useEffect(() => {
    setActive(0)
  }, [open])

  useEffect(() => {
    if (open) listboxRef.current?.focus()
  }, [open])

  useEffect(() => {
    activeRef.current?.scrollIntoView({ block: 'nearest' })
  }, [active, open])

  const openCustom = () => {
    setFrom(scope.from.slice(0, 10))
    setTo(scope.to.slice(0, 10))
    setOpen(false)
    setCustomOpen(true)
  }

  const pick = (id: string) => {
    if (id === PERIOD_CUSTOM) {
      openCustom()
      return
    }
    if (id === 'custom') {
      // A pinned range is a state, not a choice — the item only displays it.
      close(true)
      return
    }
    scope.setPeriod(id as Exclude<PeriodPreset, 'custom'>)
    close(true)
  }

  const currentLabel = pinned ? t('analytics.preset.custom') : t(`analytics.preset.${scope.period}`)
  const activeId = items[active] ? `period-preset-option-${items[active].id}` : undefined

  return (
    <div ref={rootRef} className="relative flex items-center gap-2">
      {/* The accessible name deliberately avoids the word "period"
          (period.select): page-level period selects are labeled
          t('scope.period'), and specs address them with getByLabel. */}
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t('period.select')}
        onClick={() => setOpen(o => !o)}
        className="inline-flex min-h-[44px] items-center gap-2 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 text-sm text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]"
      >
        <span className="hidden text-[color:var(--astra-text-muted)] xl:inline">{t('scope.period')}</span>
        <span className="min-w-0 truncate font-medium">{currentLabel}</span>
        <ChevronDown size={14} aria-hidden="true" className="shrink-0 text-[color:var(--astra-text-muted)]" />
      </button>

      {open && (
        <div
          ref={listboxRef}
          role="listbox"
          tabIndex={-1}
          aria-label={t('period.select')}
          aria-activedescendant={activeId}
          onKeyDown={e => {
            if (e.key === 'ArrowDown') {
              e.preventDefault()
              setActive(a => Math.min(a + 1, items.length - 1))
            } else if (e.key === 'ArrowUp') {
              e.preventDefault()
              setActive(a => Math.max(a - 1, 0))
            } else if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              const item = items[active]
              if (item) pick(item.id)
            }
          }}
          className="absolute start-0 z-30 mt-2 flex w-52 flex-col rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] p-1 shadow-lg outline-none"
        >
          {items.map((item, i) => {
            const selected = item.id === scope.period
            return (
              <button
                key={item.id}
                ref={i === active ? activeRef : undefined}
                type="button"
                role="option"
                id={`period-preset-option-${item.id}`}
                aria-selected={selected}
                onMouseMove={() => setActive(i)}
                onClick={() => pick(item.id)}
                tabIndex={-1}
                className={`flex min-h-[40px] items-center gap-2 rounded-[length:var(--astra-radius-control)] px-2 text-start text-sm ${
                  i === active
                    ? 'bg-[color:var(--astra-selection)] text-[color:var(--astra-on-selection)]'
                    : 'text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]'
                }`}
              >
                <span className="min-w-0 flex-1 truncate">{item.label}</span>
                {selected && <Check size={14} aria-hidden="true" className="shrink-0" />}
              </button>
            )
          })}
        </div>
      )}

      {customOpen && (
        <div
          role="group"
          aria-label={t('period.customRange')}
          className="absolute end-0 z-30 mt-2 flex w-64 flex-col gap-2 rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] p-3 shadow-lg"
        >
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('analytics.from')}</span>
            <input type="date" value={from} onChange={e => setFrom(e.target.value)} aria-label={t('analytics.from')} className="control" />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('analytics.to')}</span>
            <input type="date" value={to} onChange={e => setTo(e.target.value)} aria-label={t('analytics.to')} className="control" />
          </label>
          <div className="flex gap-2">
            <button type="button" className="btn-primary flex-1" disabled={!from || !to || from > to} onClick={() => {
              if (!from || !to || from > to) return
              scope.setRange(`${from}T00:00:00Z`, `${to}T00:00:00Z`)
              setCustomOpen(false)
            }}>
              {t('period.apply')}
            </button>
            <button type="button" className="btn-secondary flex-1" onClick={() => setCustomOpen(false)}>
              {t('period.cancel')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
