import { useState, type KeyboardEvent } from 'react'

// chips + a free-text input with a datalist of registry model names. The field
// itself stays presentation-only — existence/enabled validation and its texts
// come from the page via tagState/tagTitle, so the same component serves both
// lists and the save-blocker stays in one place (the page's submit check).

export interface TagFieldProps {
  id: string
  label: string
  hint?: string
  placeholder?: string
  value: string[]
  onChange: (next: string[]) => void
  /** datalist options (registry model names). */
  suggestions?: string[]
  datalistId: string
  /** Per-tag state: 'ok' renders neutral; 'disabled'/'unknown' flag the chip. */
  tagState?: (name: string) => 'ok' | 'disabled' | 'unknown'
  /** Native title per tag (why it is flagged); defaults to the name. */
  tagTitle?: (name: string) => string | undefined
  /** Accessible remove label; receives the tag name. */
  removeLabel: (name: string) => string
  disabled?: boolean
}

export function TagField({
  id, label, hint, placeholder, value, onChange, suggestions = [], datalistId,
  tagState, tagTitle, removeLabel, disabled = false,
}: TagFieldProps) {
  const [draft, setDraft] = useState('')

  const add = (raw: string) => {
    const name = raw.trim()
    setDraft('')
    if (!name || value.includes(name)) return
    onChange([...value, name])
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    // Enter must add a tag, not submit the surrounding FormDrawer form;
    // comma commits too (paste-with-commas splits on the blur/change path —
    // the input is single-line by design, the API layer also accepts newlines).
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      e.stopPropagation()
      add(draft)
      return
    }
    if (e.key === 'Backspace' && draft === '' && value.length > 0) {
      onChange(value.slice(0, -1))
    }
  }

  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-[color:var(--astra-text-muted)]" htmlFor={id}>
        {label}
      </label>
      <div className="flex w-full flex-wrap items-center gap-1.5 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-2 py-1.5">
        {value.map(name => {
          const state = tagState?.(name) ?? 'ok'
          return (
            <span
              key={name}
              title={tagTitle?.(name) ?? name}
              className="inline-flex max-w-full items-center gap-1 rounded-[length:var(--astra-radius-control)] border py-0.5 pe-1 ps-1.5 text-xs"
              style={{
                fontFamily: 'var(--astra-font-code)',
                borderColor: state === 'unknown'
                  ? 'var(--astra-danger)'
                  : state === 'disabled' ? 'var(--astra-warning)' : 'var(--astra-rule)',
                color: state === 'unknown'
                  ? 'var(--astra-danger)'
                  : state === 'disabled' ? 'var(--astra-warning)' : 'var(--astra-ink)',
              }}
            >
              {state !== 'ok' && <span aria-hidden="true">▲ </span>}
              <span className="min-w-0 truncate">{name}</span>
              <button
                type="button"
                onClick={() => onChange(value.filter(v => v !== name))}
                disabled={disabled}
                aria-label={removeLabel(name)}
                className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-[length:var(--astra-radius-control)] text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)] hover:text-[color:var(--astra-ink)]"
              >
                <span aria-hidden="true">✕</span>
              </button>
            </span>
          )
        })}
        <input
          id={id}
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={onKeyDown}
          onBlur={() => add(draft)}
          list={datalistId}
          placeholder={placeholder}
          disabled={disabled}
          autoComplete="off"
          className="min-w-[10rem] flex-1 bg-transparent py-0.5 text-sm text-[color:var(--astra-ink)] outline-none"
          style={{ fontFamily: 'var(--astra-font-code)' }}
        />
        <datalist id={datalistId}>
          {suggestions.map(s => <option key={s} value={s} />)}
        </datalist>
      </div>
      {hint && <p className="mt-1 text-[11px] text-[color:var(--astra-text-muted)]">{hint}</p>}
    </div>
  )
}
