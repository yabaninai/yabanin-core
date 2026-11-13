import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  appendClause, clauseToString, flattenAnd, nodeToString, opsForField, orderToString,
  parseYQL, rebuildFromLeaves, removeLeaf, serializeYQL,
  type YqlClause, type YqlFieldMeta, type YqlOp,
} from '../../lib/queryLang'

// The shared filter bar behind the request explorer, the analytics
// explorer and the dashboards boards. One component owns the draft/applied
// contract every screen must honour:
//   - the draft is what the input shows; `applied` is what onApply received;
//   - parse-ok drafts commit automatically after debounceMs (300-400ms);
//     debounceMs = 0 commits on every keystroke (the explorer adds its own
//     400ms fetch debounce on top);
//   - Enter and blur commit immediately;
//   - an invalid draft is NEVER applied — the inline role=alert (with a <mark>
//     on the offending character) says why and the last applied value keeps
//     driving the data;
//   - chips (top-level AND-ed clauses) are removable, the add-filter builder
//     and simple per-field inputs rewrite the draft and commit immediately.
// The component is a controlled view over `applied`: parents keep the state
// and stay responsible for URL sync and refetching. The field registry is a
// prop, so a screen can narrow or extend it (live label.<key> fields come
// from GET /api/analytics/label-keys; dashboards pass their board fields).
//
// quick fields are inputs over the same YQL draft (every keystroke rewrites
// the canonical `field = value` leaves), boolean toggles compile their fixed
// clause in and out, and the YQL input stays visible above the collapsible
// builder + cheatsheet. Quick fields, toggles, chips and the query text are
// four views of ONE committed string — never parallel filter states.

export type FilterBarMode = 'yql' | 'simple' | 'hybrid'

export interface FilterBarBooleanSpec {
  /** Toggle identity (React key); typically the clause's field name. */
  name: string
  /** Human label next to the checkbox. */
  label: string
  /** The exact clause present in the YQL when the toggle is ON. */
  clause: YqlClause
}

export interface FilterBarHandle {
  /** AND one clause into the current draft and commit it immediately. */
  appendClause: (clause: YqlClause) => void
}

interface FilterBarProps {
  id: string
  /** Accessible name of the bar (and of the YQL input in yql mode). */
  label: string
  /** Field registry offered by the builder / cheatsheet / simple inputs. */
  fields: YqlFieldMeta[]
  /** The committed value; changing it from outside re-syncs the draft. */
  applied: string
  onApply: (next: string) => void
  mode?: FilterBarMode
  debounceMs?: number
  hint?: string
  /** Extra value suggestions per field (datalist). */
  valueHints?: (field: string) => string[]
  /** Display names for simple-mode field inputs (default: the field name). */
  fieldLabels?: Record<string, string>
  /** hybrid mode: the quick per-field inputs (compiled into the YQL). */
  quickFields?: YqlFieldMeta[]
  /** hybrid mode: boolean quick toggles compiled into the YQL. */
  booleanFields?: FilterBarBooleanSpec[]
}

/** Read back the `field = value` pairs a simple-mode bar has applied. */
export function simpleValues(query: string, fields: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const name of fields) out[name] = ''
  const parsed = parseYQL(query)
  if (!parsed.ok) return out
  for (const leaf of flattenAnd(parsed.root).leaves) {
    if (leaf.op === '=' && out[leaf.field] !== undefined) out[leaf.field] = leaf.values[0] ?? ''
  }
  return out
}

export const FilterBar = forwardRef<FilterBarHandle, FilterBarProps>(function FilterBar(
  { id, label, fields, applied, onApply, mode = 'yql', debounceMs = 350, hint, valueHints, fieldLabels, quickFields, booleanFields },
  ref,
) {
  const { t } = useTranslation()
  const simple = mode === 'simple'
  const hybrid = mode === 'hybrid'

  const [draft, setDraft] = useState(applied)
  const draftRef = useRef(draft)
  useEffect(() => { draftRef.current = draft }, [draft])
  const parse = useMemo(() => parseYQL(draft), [draft])
  // Marks the last value this bar sent (or received from outside). The sync
  // effect below only resets the draft when `applied` moved PAST that mark —
  // otherwise in-progress typing would be clobbered by parent re-renders.
  const sentRef = useRef(applied.trim())

  const applyRef = useRef(onApply)
  useEffect(() => { applyRef.current = onApply })

  useEffect(() => {
    const next = applied.trim()
    if (next === sentRef.current) return
    sentRef.current = next
    setDraft(next)
  }, [applied])

  const applyText = (text: string) => {
    const next = text.trim()
    if (next === sentRef.current) return
    sentRef.current = next
    applyRef.current(next)
  }

  // Auto-apply parse-ok drafts after the debounce. An invalid draft never
  // schedules a commit; retyping valid text restarts the timer.
  useEffect(() => {
    if (!parse.ok) return
    const next = draft.trim()
    if (next === sentRef.current) return
    const fire = () => {
      sentRef.current = next
      applyRef.current(next)
    }
    if (debounceMs <= 0) {
      fire()
      return
    }
    const timer = setTimeout(fire, debounceMs)
    return () => clearTimeout(timer)
  }, [draft, parse, debounceMs])

  const commitNow = () => {
    if (!parse.ok) return
    applyText(draft)
  }

  useImperativeHandle(ref, () => ({
    appendClause: (clause: YqlClause) => {
      const parsed = parseYQL(draftRef.current)
      const next = appendClause(draftRef.current, clause, parsed.ok ? parsed.order : null)
      setDraft(next)
      applyText(next)
    },
  }), [])

  // Chips: top-level AND-ed clauses are individually removable; anything
  // else (or / not / groups) collapses into one grouped chip.
  const chips = useMemo(() => flattenAnd(parse.ok ? parse.root : null), [parse])

  const removeChip = (index: number) => {
    const next = removeLeaf(draftRef.current, index)
    setDraft(next)
    applyText(next)
  }

  // Add-filter builder state (field -> operator -> value -> AND into the text).
  const [afField, setAfField] = useState(fields[0]?.name ?? '')
  const [afOp, setAfOp] = useState<YqlOp>('=')
  const [afValue, setAfValue] = useState('')
  const [afError, setAfError] = useState('')
  const afMeta = useMemo(() => fields.find(f => f.name === afField), [fields, afField])
  const afOps = useMemo(() => (afMeta ? opsForField(afMeta) : []), [afMeta])

  const changeAfField = (f: string) => {
    setAfField(f)
    const meta = fields.find(x => x.name === f)
    setAfOp(meta ? opsForField(meta)[0] : '=')
    setAfValue('')
    setAfError('')
  }

  const addFilterClause = () => {
    const meta = fields.find(x => x.name === afField)
    if (!meta) return
    setAfError('')
    // Adding onto a broken draft would silently discard it (appendClause
    // starts from the last valid root) — refuse and point at the input.
    if (draft.trim() !== '' && !parse.ok) {
      setAfError(t('explorer.queryFixFirst'))
      return
    }
    let clause: YqlClause
    if (afOp === 'empty' || afOp === 'not empty') {
      clause = { kind: 'clause', field: meta.name, op: afOp, values: [] }
    } else {
      const v = afValue.trim()
      if (!v) { setAfError(t('explorer.queryValueRequired')); return }
      clause = { kind: 'clause', field: meta.name, op: afOp, values: [v] }
    }
    const next = appendClause(draft, clause, parse.ok ? parse.order : null)
    const check = parseYQL(next)
    if (!check.ok) { setAfError(check.error); return }
    setDraft(next)
    setAfValue('')
    applyText(next)
  }

  // Simple mode: one input per allowed field; each keystroke rewrites the
  // draft as a canonical `field = value` AND-chain and the debounce applies it.
  const simpleValueOf = (field: string): string => {
    if (!parse.ok) return ''
    const hit = flattenAnd(parse.root).leaves.find(l => l.field === field && l.op === '=')
    return hit?.values[0] ?? ''
  }
  const setSimpleValue = (field: string, raw: string) => {
    const parsed = parseYQL(draftRef.current)
    if (!parsed.ok) return
    const { leaves, rest } = flattenAnd(parsed.root)
    const v = raw.trim()
    const others = leaves.filter(l => l.field !== field)
    const nextLeaves = v
      ? [...others, { kind: 'clause' as const, field, op: '=' as const, values: [v] }]
      : others
    setDraft(serializeYQL(rebuildFromLeaves(nextLeaves, rest), parsed.order))
  }

  // hybrid mode: a boolean toggle swaps its fixed clause in and out of the
  // AND-chain. The checked state is the clause's exact serialized form — a
  // hand-edited `status >= 500` does NOT light the `status >= 400` toggle.
  const booleanOn = (spec: FilterBarBooleanSpec): boolean => {
    if (!parse.ok) return false
    const want = clauseToString(spec.clause)
    return flattenAnd(parse.root).leaves.some(l => clauseToString(l) === want)
  }
  const setBooleanValue = (spec: FilterBarBooleanSpec, on: boolean) => {
    const parsed = parseYQL(draftRef.current)
    if (!parsed.ok) return
    const { leaves, rest } = flattenAnd(parsed.root)
    const want = clauseToString(spec.clause)
    const others = leaves.filter(l => clauseToString(l) !== want)
    const nextLeaves = on ? [...others, spec.clause] : others
    setDraft(serializeYQL(rebuildFromLeaves(nextLeaves, rest), parsed.order))
  }

  const hints = (field: string): string[] => {
    const seen = new Set<string>()
    for (const v of valueHints?.(field) ?? []) {
      if (v) seen.add(v)
    }
    return [...seen]
  }

  // The add-filter builder and the YQL cheatsheet. In yql mode both render
  // inline (historical layout); in hybrid mode they collapse into one
  // disclosure under the always-visible query input.
  const builderBlock = (
    <div className="flex flex-wrap items-end gap-2">
      <label className="flex flex-col gap-1 text-sm">
        <span className="text-[color:var(--astra-text-muted)]">{t('explorer.addFilterField')}</span>
        <select value={afField} onChange={e => changeAfField(e.target.value)} className="control w-44">
          {fields.map(f => <option key={f.name} value={f.name}>{f.name}</option>)}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm">
        <span className="text-[color:var(--astra-text-muted)]">{t('explorer.addFilterOp')}</span>
        <select value={afOp} onChange={e => setAfOp(e.target.value as YqlOp)} className="control w-40">
          {afOps.map(op => <option key={op} value={op}>{op}</option>)}
        </select>
      </label>
      {afOp !== 'empty' && afOp !== 'not empty' && (
        afMeta?.kind === 'cache' ? (
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('explorer.addFilterValue')}</span>
            <select value={afValue} onChange={e => setAfValue(e.target.value)} className="control w-40">
              <option value="exact">exact</option>
              <option value="semantic">semantic</option>
              <option value="miss">miss</option>
            </select>
          </label>
        ) : (
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('explorer.addFilterValue')}</span>
            <input
              value={afValue}
              onChange={e => setAfValue(e.target.value)}
              list={`${id}-value-hints`}
              placeholder={afMeta?.kind === 'time' ? t('explorer.queryTimeHint') : afMeta?.kind === 'number' ? t('explorer.queryNumberHint') : t('explorer.queryTextHint')}
              spellCheck={false}
              className="control w-44"
            />
            <datalist id={`${id}-value-hints`}>
              {hints(afField).map(v => <option key={v} value={v} />)}
            </datalist>
          </label>
        )
      )}
      <button type="button" onClick={addFilterClause} className="btn-secondary min-h-[44px]">
        {t('explorer.addFilterAdd')}
      </button>
    </div>
  )

  const cheatBlock = (
    <div className="flex flex-col gap-2 text-xs text-[color:var(--astra-text-muted)]">
      <p className="flex flex-wrap items-center gap-1">
        <span className="font-medium text-[color:var(--astra-ink)]">{t('explorer.cheatFields')}</span>
        <span style={{ fontFamily: 'var(--astra-font-code)' }}>{fields.map(f => f.name).join(', ')}</span>
      </p>
      <p>{t('explorer.cheatOps')}</p>
      <ul className="flex flex-col gap-1">
        {['explorer.cheatExample1', 'explorer.cheatExample2', 'explorer.cheatExample3', 'explorer.cheatExample4', 'explorer.cheatExample5'].map(k => (
          <li key={k} style={{ fontFamily: 'var(--astra-font-code)' }}>{t(k)}</li>
        ))}
      </ul>
    </div>
  )

  return (
    // In yql and hybrid modes the section stays unlabeled: the input inside
    // carries the accessible name, and a same-named region would make
    // getByLabel(name)/role lookups ambiguous for assistive queries.
  // hybrid tightens the card padding: the explorer's vertical budget
  // belongs to the rows.
    <section className={`card flex flex-col gap-2 ${hybrid ? '!px-4 !py-2' : ''}`} aria-label={simple ? label : undefined}>
      {simple && (
        <div className="flex flex-wrap items-end gap-3">
          {fields.map(f => (
            <label key={f.name} className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{fieldLabels?.[f.name] ?? f.name}</span>
              <input
                value={simpleValueOf(f.name)}
                onChange={e => setSimpleValue(f.name, e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); commitNow() } }}
                list={`${id}-hints-${f.name}`}
                spellCheck={false}
                className="control w-44"
              />
              <datalist id={`${id}-hints-${f.name}`}>
                {hints(f.name).map(v => <option key={v} value={v} />)}
              </datalist>
            </label>
          ))}
        </div>
      )}
      {hybrid && (
        // next to the always-visible YQL input; every control above is a
        // view of the same committed query.
        <div className="flex flex-wrap items-end gap-3">
          {(quickFields ?? []).map(f => (
            <label key={f.name} className="flex flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{fieldLabels?.[f.name] ?? f.name}</span>
              <input
                value={simpleValueOf(f.name)}
                onChange={e => setSimpleValue(f.name, e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); commitNow() } }}
                list={`${id}-hints-${f.name}`}
                spellCheck={false}
                className="control w-44"
              />
              <datalist id={`${id}-hints-${f.name}`}>
                {hints(f.name).map(v => <option key={v} value={v} />)}
              </datalist>
            </label>
          ))}
          {(booleanFields ?? []).map(bf => (
            <label key={bf.name} className="flex min-h-[44px] items-center gap-2 pb-2 text-sm text-[color:var(--astra-ink)]">
              <input
                type="checkbox"
                checked={booleanOn(bf)}
                onChange={e => setBooleanValue(bf, e.target.checked)}
              />
              {bf.label}
            </label>
          ))}
          <div className="flex min-w-[240px] flex-1 items-end gap-2">
            <label htmlFor={`${id}-input`} className="flex min-w-0 flex-1 flex-col gap-1 text-sm">
              <span className="text-[color:var(--astra-text-muted)]">{label}</span>
              <input
                id={`${id}-input`}
                value={draft}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); commitNow() } }}
                onBlur={commitNow}
                placeholder={t('explorer.queryPlaceholder')}
                spellCheck={false}
                aria-invalid={(!parse.ok && draft.trim() !== '') || undefined}
                aria-describedby={(!parse.ok && draft.trim() !== '') || hint ? (parse.ok ? `${id}-hint` : `${id}-error`) : undefined}
                className="control min-w-[160px]"
                style={{ fontFamily: 'var(--astra-font-code)' }}
              />
            </label>
            <button
              type="button"
              onClick={() => { setDraft(''); applyText('') }}
              disabled={!draft}
              className="btn-secondary"
            >
              {t('explorer.queryClear')}
            </button>
          </div>
        </div>
      )}
      {!hybrid && !simple && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor={`${id}-input`} className="text-sm text-[color:var(--astra-text-muted)]">
              {label}
            </label>
            <input
              id={`${id}-input`}
              value={draft}
              onChange={e => setDraft(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); commitNow() } }}
              onBlur={commitNow}
              placeholder={t('explorer.queryPlaceholder')}
              spellCheck={false}
              aria-invalid={(!parse.ok && draft.trim() !== '') || undefined}
              aria-describedby={(!parse.ok && draft.trim() !== '') || hint ? (parse.ok ? `${id}-hint` : `${id}-error`) : undefined}
              className="control min-w-[240px] flex-1"
              style={{ fontFamily: 'var(--astra-font-code)' }}
            />
            <button
              type="button"
              onClick={() => { setDraft(''); applyText('') }}
              disabled={!draft}
              className="btn-secondary"
            >
              {t('explorer.queryClear')}
            </button>
          </div>
          {!parse.ok && draft.trim() !== '' && (
            <p id={`${id}-error`} role="alert" className="text-sm text-[color:var(--astra-danger)]">
              {t('explorer.queryInvalid', { error: parse.error })}
              <span className="mt-1 block" style={{ fontFamily: 'var(--astra-font-code)' }}>
                {draft.slice(0, parse.pos)}
                <mark>{draft[parse.pos] ?? ''}</mark>
                {draft.slice(parse.pos + 1)}
              </span>
            </p>
          )}
        </>
      )}
      {hybrid && !parse.ok && draft.trim() !== '' && (
        <p id={`${id}-error`} role="alert" className="text-sm text-[color:var(--astra-danger)]">
          {t('explorer.queryInvalid', { error: parse.error })}
          <span className="mt-1 block" style={{ fontFamily: 'var(--astra-font-code)' }}>
            {draft.slice(0, parse.pos)}
            <mark>{draft[parse.pos] ?? ''}</mark>
            {draft.slice(parse.pos + 1)}
          </span>
        </p>
      )}

      {(chips.leaves.length > 0 || chips.rest || (parse.ok && parse.order)) && (
        <ul className="flex flex-wrap gap-2" aria-label={t('explorer.queryApplied')}>
          {chips.leaves.map((cl, i) => (
            <li
              key={`${i}-${cl.field}-${cl.op}`}
              className="inline-flex items-center gap-1 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface-muted)] px-2 py-1 text-xs"
            >
              <span style={{ fontFamily: 'var(--astra-font-code)' }}>{clauseToString(cl)}</span>
              {/* 44px touch target floor on the remove hit area. */}
              <button
                type="button"
                onClick={() => removeChip(i)}
                aria-label={t('explorer.queryRemoveChip', { filter: clauseToString(cl) })}
                className="inline-flex min-h-[44px] items-center px-1 text-[color:var(--astra-text-muted)] hover:text-[color:var(--astra-ink)]"
              >
                ×
              </button>
            </li>
          ))}
          {chips.rest && (
            <li
              className="inline-flex items-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface-muted)] px-2 py-1 text-xs"
              title={t('explorer.queryGroupHint')}
            >
              <span style={{ fontFamily: 'var(--astra-font-code)' }}>{nodeToString(chips.rest)}</span>
            </li>
          )}
          {parse.ok && parse.order && (
            <li
              className="inline-flex items-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface-muted)] px-2 py-1 text-xs"
              title={t('explorer.queryGroupHint')}
            >
              <span style={{ fontFamily: 'var(--astra-font-code)' }}>{orderToString(parse.order)}</span>
            </li>
          )}
        </ul>
      )}

      {!simple && !hybrid && builderBlock}
      {afError && <p role="alert" className="text-sm text-[color:var(--astra-danger)]">{afError}</p>}

      {hint && (
        <p id={`${id}-hint`} className="text-xs text-[color:var(--astra-text-muted)]">{hint}</p>
      )}

      {!simple && !hybrid && (
        <details className="text-sm">
          <summary className="cursor-pointer text-[color:var(--astra-ink)]">{t('explorer.cheatTitle')}</summary>
          <div className="mt-2 pl-4">{cheatBlock}</div>
        </details>
      )}

      {hybrid && (
        <details className="text-sm">
          <summary className="cursor-pointer text-[color:var(--astra-ink)]">{t('explorer.cheatTitle')}</summary>
          <div className="mt-2 flex flex-col gap-3 pl-4">
            {builderBlock}
            {afError && <p role="alert" className="text-sm text-[color:var(--astra-danger)]">{afError}</p>}
            {cheatBlock}
          </div>
        </details>
      )}
    </section>
  )
})
