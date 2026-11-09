import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'
import { filterCommands, groupCommands, type CommandOption } from '../../lib/commandPalette'

// AUX-21: the ⌘K / Ctrl+K command palette — a search field over the visible
// navigation (the AUX-13 access-filtered NAV_SECTIONS) plus a few navigation
// actions. Navigation-only on purpose: nothing here mutates — a selection
// either moves to a page or lands on one with a prefilled filter; mutating
// flows stay behind their dialogs (AUX-12).
//
// Keyboard contract (aux12/aux17 pattern): the field takes focus on open,
// Tab/Shift+Tab cycle inside the dialog, Escape closes it and focus returns
// to the opener — or, for a keyboard-opened palette (no opener element), to
// the first focusable in the admin content region. Arrow keys move the
// active option, Enter runs it, and the ARIA combobox/listbox roles wire the
// field to the list (aria-activedescendant, aria-selected).
//
// The layer is a fixed inset-0 flex container with a panel capped at
// min(36rem, 100%) — no horizontal document growth at 360px (the AUX-21
// overflow gate, same approach as .astra-drawer in index.css).

export interface CommandPaletteProps {
  commands: CommandOption[]
  /** Runs a command; the palette closes itself first. */
  onRun: (id: string) => void
  onClose: () => void
}

// Focusable elements inside the panel — the same selector the ActionDialog /
// EntityDrawer traps use.
const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function CommandPalette({ commands, onRun, onClose }: CommandPaletteProps) {
  const { t } = useTranslation()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const panelRef = useRef<HTMLDivElement | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const openerRef = useRef<HTMLElement | null>(null)

  const filtered = useMemo(() => filterCommands(query, commands), [query, commands])
  const groups = useMemo(() => groupCommands(filtered), [filtered])
  const activeIndex = Math.min(active, Math.max(filtered.length - 1, 0))
  const activeId = filtered[activeIndex] ? `command-palette-option-${filtered[activeIndex].id}` : undefined

  useEffect(() => {
    setActive(0)
  }, [query])

  useEffect(() => {
    openerRef.current = document.activeElement as HTMLElement | null
    inputRef.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key !== 'Tab' || !panelRef.current) return
      const focusable = Array.from(panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE))
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      // Restore to the opener when it is still connected (a keyboard-opened
      // palette has none) — otherwise to the page content, never to <body>
      // (the aux12/aux17 pattern).
      const opener = openerRef.current
      if (opener instanceof HTMLElement && opener.isConnected && opener !== document.body) {
        opener.focus()
        return
      }
      document.getElementById('admin-content')
        ?.querySelector<HTMLElement>(FOCUSABLE)
        ?.focus()
    }
  }, [onClose])

  const choose = (index: number) => {
    const command = filtered[index]
    if (!command) return
    onClose()
    onRun(command.id)
  }

  const onInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (filtered.length === 0) {
      if (event.key === 'Enter') event.preventDefault()
      return
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActive((activeIndex + 1) % filtered.length)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActive((activeIndex - 1 + filtered.length) % filtered.length)
    } else if (event.key === 'Enter') {
      event.preventDefault()
      choose(activeIndex)
    }
  }

  let optionIndex = -1

  return (
    <div className="astra-palette-layer">
      <div aria-hidden="true" className="astra-palette-backdrop" />
      <div ref={panelRef} role="dialog" aria-modal="true" aria-label={t('palette.title')} className="astra-palette">
        <div className="flex items-center gap-2 border-b border-[color:var(--astra-rule)] px-3">
          <Search size={16} aria-hidden="true" className="shrink-0 text-[color:var(--astra-text-muted)]" />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-controls="command-palette-listbox"
            aria-activedescendant={activeId}
            aria-autocomplete="list"
            aria-label={t('palette.searchLabel')}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={onInputKeyDown}
            placeholder={t('palette.placeholder')}
            className="astra-palette-input"
          />
          <button type="button" onClick={onClose} aria-label={t('common.close')} className="btn-secondary shrink-0">✕</button>
        </div>

        {filtered.length === 0 ? (
          <p role="status" className="px-3 py-6 text-sm text-[color:var(--astra-text-muted)]">{t('palette.noMatches')}</p>
        ) : (
          <ul id="command-palette-listbox" role="listbox" aria-label={t('palette.commands')} className="astra-palette-list">
            {groups.map(group => (
              <Fragment key={group.section}>
                <li role="presentation" className="astra-palette-section">{group.section}</li>
                {group.items.map(command => {
                  optionIndex += 1
                  const index = optionIndex
                  return (
                    <li
                      key={command.id}
                      id={`command-palette-option-${command.id}`}
                      role="option"
                      aria-selected={index === activeIndex}
                      className={`astra-palette-option${index === activeIndex ? ' is-active' : ''}`}
                      onMouseMove={() => setActive(index)}
                      onClick={() => choose(index)}
                    >
                      <span className="truncate">{command.label}</span>
                    </li>
                  )
                })}
              </Fragment>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
