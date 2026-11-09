import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useOrgs } from '../i18n/useOrgPresentation'
import { readLastOrg } from '../lib/orgScope'

// UI-VF-1: OrgSelect — astra primitive replacing free-text org-id inputs.
//
// Before: every screen asked the user to copy an org UUID by hand (from the
// Orgs page) into a text field. OrgSelect turns that into a dropdown fed by
// the shared org-list cache (one request per session, see useOrgPresentation),
// with two safety valves so nothing that was possible before is lost:
//   * deep links / remembered ids that are not in the loaded list (e.g. an org
//     beyond page 1) render as an explicit "ID: <value>" option instead of a
//     blank select;
//   * `allowManual` adds an "Enter ID manually…" option that flips the control
//     into a text input, for orgs the picker cannot list.
//
// The control is UNCONTROLLED-free: it renders exactly `value` and reports
// changes upward; callers keep ownership of the committed scope.

const MANUAL = '__manual__'

export interface OrgSelectProps {
  /** Current org id ('' = "all organizations" when allowAll). */
  value: string
  onChange: (orgId: string) => void
  /** Optional conditional commit for a delayed automatic fallback. User
   *  changes always use onChange; local forms keep the existing default. */
  onAutoSelect?: (orgId: string) => void
  /** Render the empty "all organizations" option (scope bars want it; forms don't). */
  allowAll?: boolean
  /** Label for the empty option; defaults to t('scope.allGlobal'). */
  allLabel?: string
  /** Offer the "Enter ID manually…" escape hatch (default true). */
  allowManual?: boolean
  disabled?: boolean
  /** Width utility classes; matches the ScopeBar org input by default. */
  className?: string
  /** aria-label override for the manual text input. */
  manualAriaLabel?: string
  /** Org-required screens: when mounted empty, auto-commit a selection once
   *  the list loads — the last-used org if it is in the list, else the first
   *  org. No-op when the value is already set (deep link / last-org memory). */
  autoSelect?: boolean
}

export function OrgSelect({
  value,
  onChange,
  onAutoSelect,
  allowAll = false,
  allLabel,
  allowManual = true,
  disabled = false,
  className = 'sm:w-56',
  manualAriaLabel,
  autoSelect = false,
}: OrgSelectProps) {
  const { t } = useTranslation()
  const { orgs } = useOrgs()
  const [manual, setManual] = useState(false)
  const inputRef = useRef<HTMLInputElement | null>(null)
  // autoSelect fires at most once per mount (a ref, not state: firing must
  // not re-render; the guard survives value/orgs updates either way).
  const autoFilled = useRef(false)

  useEffect(() => {
    if (manual) inputRef.current?.focus()
  }, [manual])

  useEffect(() => {
    if (!autoSelect || autoFilled.current) return
    if (value) { autoFilled.current = true; return }
    if (!orgs || orgs.length === 0) return
    const last = readLastOrg()
    const pick = last && orgs.some(o => o.id === last || o.slug === last) ? last : orgs[0].id
    autoFilled.current = true
    ;(onAutoSelect ?? onChange)(pick)
  }, [autoSelect, value, orgs, onChange, onAutoSelect])

  const known = useMemo(() => {
    if (!orgs) return null
    const map = new Map<string, string>()
    for (const o of orgs) map.set(o.id, o.name)
    return map
  }, [orgs])

  const valueKnown = !value || (known ? known.has(value) : false)
  const loading = known === null

  // Manual mode: a plain text input committed on blur/Enter — same contract
  // the old free-text org field had, so ScopeBar keeps its keyboard flows.
  if (manual) {
    return (
      <span className="inline-flex min-w-0 flex-1 items-center gap-1">
        <input
          ref={inputRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onBlur={() => { if (value !== MANUAL) onChange(value.trim()) }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') (e.target as HTMLInputElement).blur()
            if (e.key === 'Escape') setManual(false)
          }}
          placeholder="00000000-0000-0000-0000-000000000000"
          aria-label={manualAriaLabel ?? t('orgSelect.manualLabel')}
          disabled={disabled}
          className={`control min-w-0 flex-1 font-[family-name:var(--astra-font-code)] ${className}`}
        />
        <button
          type="button"
          onClick={() => setManual(false)}
          disabled={disabled}
          className="btn-secondary shrink-0"
        >
          {t('orgSelect.backToList')}
        </button>
      </span>
    )
  }

  return (
    <select
      value={valueKnown ? value : (value ? '__unknown__' : value)}
      onChange={(e) => {
        const v = e.target.value
        if (v === MANUAL) {
          setManual(true)
          onChange('')
          return
        }
        onChange(v === '__unknown__' ? value : v)
      }}
      disabled={disabled}
      className={`control ${className}`}
    >
      {allowAll && <option value="">{allLabel ?? t('scope.allGlobal')}</option>}
      {loading && <option value="">{t('orgSelect.loading')}</option>}
      {known?.size === 0 && !loading && (
        <option value="">{t('orgSelect.empty')}</option>
      )}
      {/* Value came from a deep link / last-org memory and is not in the
          loaded page — surface it verbatim instead of silently dropping it. */}
      {!loading && value && !valueKnown && (
        <option value="__unknown__">{t('orgSelect.unknownOption', { id: value })}</option>
      )}
      {[...(known?.entries() ?? [])].map(([id, name]) => (
        <option key={id} value={id}>{name}</option>
      ))}
      {allowManual && !loading && (
        <option value={MANUAL}>{t('orgSelect.manualOption')}</option>
      )}
    </select>
  )
}

/** UI-VF-1: companion "reload org list" affordance for empty/failed loads. */
export function OrgSelectReload({ onClick, disabled }: { onClick: () => void; disabled?: boolean }) {
  const { t } = useTranslation()
  return (
    <button type="button" onClick={onClick} disabled={disabled} className="btn-secondary">
      {t('orgSelect.reload')}
    </button>
  )
}
