import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { readLastOrg, rememberOrg } from '../lib/orgScope'
import { OrgSelect } from './OrgSelect'

// Astra primitive: ScopeBar (standards/design.md "Components and contracts").
// Organization, environment, period, timezone + explicit Apply; editable and
// applied values are separated (drafts vs the committed scope, plus an
// applied-scope summary line).
//
// U03 base: selects organization and provider, mirrors them into the URL
// (?org=<id>&provider=<name>) so a scoped view is shareable and survives a
// reload. UX-03 (v19.4): drafts AUTO-COMMIT after a 300ms debounce (blur and
// Enter still commit immediately) — no separate Load/Apply press is needed;
// screens refetch off the committed scope. When `onApply` is provided, drafts
// commit only via the Apply button (explicit applied-scope semantics).

export interface Scope {
  orgId: string
  provider: string
}

export interface ScopePeriod {
  value: string
  options: { value: string; label: string }[]
}

/** Controllable scope fields (AUX-04: honest filters — every visible control
 * must change the request; a field the server ignores is not rendered). */
export type ScopeField = 'org' | 'provider' | 'period' | 'tz'

export interface ScopeBarProps extends Scope {
  onChange: (scope: Scope) => void
  loading?: boolean
  /** Second editable dimension (e.g. prod/staging). */
  environment?: string
  onEnvironmentChange?: (environment: string) => void
  /** Select-style period (all time / last 24h / …). */
  period?: ScopePeriod
  onPeriodChange?: (period: string) => void
  /** Timezone label (e.g. "UTC"); free text so orgs with non-UTC work too. */
  timezone?: string
  onTimezoneChange?: (timezone: string) => void
  /** Which fields to render (AUX-04). A hidden field is inert: it is dropped
   * from the mirrored URL and emitted as "" so the screen can never send it.
   * Default (prop omitted): org + provider, plus period/tz when wired. */
  fields?: ScopeField[]
  /** When set, drafts apply only via this button (explicit Apply semantics). */
  onApply?: () => void
  /** Summary of what is currently applied, e.g. "org acme · UTC". */
  appliedSummary?: string
}

// The scope query rides in the HASH fragment (e.g. #overview?org=acme) because
// the app is hash-routed: window.location.search is empty for hash routes.
// This mirrors how the i18n locale is read (src/i18n/index.ts). The plain
// search string is also checked so non-hash URLs keep working.
function hashQuery(): string {
  const hash = window.location.hash
  return hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : ''
}

// Exported for screens that auto-load on mount: initializing the scope from
// the URL synchronously (useState initializer) avoids a wasted global request
// before the ScopeBar's mount-effect adoption lands (UX-03).
export function readScopeFromURL(): Scope {
  try {
    const p = new URLSearchParams(hashQuery())
    const s = new URLSearchParams(window.location.search)
    return {
      orgId: p.get('org') ?? s.get('org') ?? '',
      provider: p.get('provider') ?? s.get('provider') ?? '',
    }
  } catch {
    return { orgId: '', provider: '' }
  }
}

function writeScopeToURL(scope: Scope) {
  try {
    const url = new URL(window.location.href)
    const base = url.hash.split('?')[0]
    const q = new URLSearchParams(hashQuery())
    if (scope.orgId) q.set('org', scope.orgId); else q.delete('org')
    if (scope.provider) q.set('provider', scope.provider); else q.delete('provider')
    const qs = q.toString()
    url.hash = qs ? `${base}?${qs}` : base
    window.history.replaceState(null, '', url.toString())
  } catch {
    // Non-browser environment (tests) — URL sync is best-effort.
  }
}

const labelCls = 'flex min-w-0 max-w-full flex-col gap-1 text-sm'
// AVR-10 (F09 text-enlarge): labels wrap/break so they can't push the form
// wider than the viewport when the root font is enlarged.
const labelSpanCls = 'overflow-wrap-anywhere text-[color:var(--astra-text-muted)]'
// AVR-07 (F09): min-height 44px — the project control height token
// (--astra-height-control) as the touch target floor. shared .control class
// (index.css) carries the porcelain chrome.
const inputCls = 'control'

export function ScopeBar({
  orgId,
  provider,
  onChange,
  loading = false,
  environment,
  onEnvironmentChange,
  period,
  onPeriodChange,
  timezone,
  onTimezoneChange,
  fields,
  onApply,
  appliedSummary,
}: ScopeBarProps) {
  const { t } = useTranslation()
  // AUX-04: a field left out of `fields` is not rendered AND is inert — the
  // URL mirror drops its param and scope emissions carry "" for it. Showing a
  // control the server ignores would be a decorative filter.
  const showProvider = fields ? fields.includes('provider') : true
  const showPeriod = fields ? fields.includes('period') : true
  const showTz = fields ? fields.includes('tz') : true
  // Local draft state so a partial type doesn't fire a refetch on every key.
  const [draftOrg, setDraftOrg] = useState(orgId)
  const [draftProvider, setDraftProvider] = useState(showProvider ? provider : '')
  const [draftEnvironment, setDraftEnvironment] = useState(environment ?? '')
  const [draftTimezone, setDraftTimezone] = useState(timezone ?? '')

  // Adopt the scope from the URL on mount, then tell the screen to load it.
  // Cross-tab continuity: when the arriving URL has no org, fall back to the
  // last committed org (deep links with an explicit ?org= always win).
  useEffect(() => {
    const fromURL = readScopeFromURL()
    if (!fromURL.orgId) fromURL.orgId = readLastOrg()
    if (!showProvider) fromURL.provider = ''
    setDraftOrg(fromURL.orgId)
    setDraftProvider(fromURL.provider)
    if (fromURL.orgId !== orgId || fromURL.provider !== provider) {
      onChange(fromURL)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Keep drafts in sync when the scope changes from outside (e.g. a reset).
  useEffect(() => { setDraftOrg(orgId) }, [orgId])
  useEffect(() => { setDraftProvider(showProvider ? provider : '') }, [provider, showProvider])
  useEffect(() => { setDraftEnvironment(environment ?? '') }, [environment])
  useEffect(() => { setDraftTimezone(timezone ?? '') }, [timezone])

  // UX-03: auto-commit the drafts after a short debounce so the screen
  // refetches as the user finishes editing — without firing on every keystroke
  // (the original reason drafts existed). onApply screens keep explicit Apply
  // semantics and are excluded. Same-value commits are filtered so the debounce
  // is a no-op when the drafts already match the committed scope.
  useEffect(() => {
    if (onApply) return
    const next = { orgId: draftOrg.trim(), provider: showProvider ? draftProvider.trim() : '' }
    if (next.orgId === orgId && next.provider === provider) return
    const timer = setTimeout(() => onChange(next), 300)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftOrg, draftProvider])

  // Mirror the committed scope into the URL and remember the org so other
  // tabs can adopt it when their own URL carries none. Hidden fields are not
  // advertised as filters (AUX-04): their params are stripped.
  useEffect(() => {
    writeScopeToURL({ orgId, provider: showProvider ? provider : '' })
    rememberOrg(orgId)
  }, [orgId, provider, showProvider])

  const apply = () => {
    onChange({ orgId: draftOrg.trim(), provider: showProvider ? draftProvider.trim() : '' })
    if (onEnvironmentChange) onEnvironmentChange(draftEnvironment.trim())
    if (onTimezoneChange) onTimezoneChange(draftTimezone.trim())
    if (onApply) onApply()
  }

  const hasScope = Boolean(orgId || provider)

  // Commit-on-blur only when there is no explicit Apply button; with onApply,
  // blur must not silently apply (editable ≠ applied).
  const commit = onApply ? () => {} : apply

  // AVR-10 (F09 text-enlarge): min-w-0 on the card and its flex children so
  // the form fields can shrink and wrap instead of pushing the document wider
  // when the root font is enlarged (fixed w-64/w-44 inputs overflow at 200%).
  return (
    <div className="card flex min-w-0 flex-wrap items-end gap-3">
      <label className={`${labelCls} min-w-0 max-w-full`}>
        <span className={labelSpanCls}>{t('scope.organization')}</span>
        {/* UI-VF-1: org picker fed by the shared org-list cache replaces the
            free-text UUID input; "" still means "all (global)" and manual UUID
            entry stays available as an escape hatch. */}
        <OrgSelect
          value={draftOrg}
          onChange={setDraftOrg}
          allowAll
          disabled={loading}
        />
      </label>
      {showProvider && (
        <label className={`${labelCls} min-w-0 max-w-full`}>
          <span className={labelSpanCls}>{t('scope.provider')}</span>
          <input
            value={draftProvider}
            onChange={e => setDraftProvider(e.target.value)}
            onBlur={commit}
            onKeyDown={e => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }}
            placeholder={t('scope.allProviders')}
            disabled={loading}
            className={`${inputCls} sm:w-40`}
          />
        </label>
      )}
      {onEnvironmentChange && (
        <label className={` min-w-0 max-w-full`}>
          <span className={labelSpanCls}>{t('scope.environment')}</span>
          <input
            value={draftEnvironment}
            onChange={e => setDraftEnvironment(e.target.value)}
            onBlur={commit}
            onKeyDown={e => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }}
            placeholder={t('scope.production')}
            disabled={loading}
            className={`${inputCls} sm:w-36`}
          />
        </label>
      )}
      {showPeriod && onPeriodChange && period && (
        <label className={` min-w-0 max-w-full`}>
          <span className={labelSpanCls}>{t('scope.period')}</span>
          <select
            value={period.value}
            onChange={e => { onPeriodChange(e.target.value); if (onApply) onApply() }}
            disabled={loading}
            className={`${inputCls} sm:w-44`}
          >
            {period.options.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </label>
      )}
      {showTz && onTimezoneChange && (
        <label className={` min-w-0 max-w-full`}>
          <span className={labelSpanCls}>{t('scope.timezone')}</span>
          <input
            value={draftTimezone}
            onChange={e => setDraftTimezone(e.target.value)}
            onBlur={commit}
            onKeyDown={e => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }}
            placeholder={t('scope.utc')}
            disabled={loading}
            className={`${inputCls} sm:w-28`}
          />
        </label>
      )}
      {onApply && (
        <button
          type="button"
          onClick={apply}
          disabled={loading}
          className="btn-primary"
        >
          {t('common.apply')}
        </button>
      )}
      {hasScope && !onApply && (
        <button
          type="button"
          onClick={() => { setDraftOrg(''); setDraftProvider(''); onChange({ orgId: '', provider: '' }) }}
          disabled={loading}
          className="btn-secondary"
        >
          {t('common.resetScope')}
        </button>
      )}
      {appliedSummary && (
        <p
          className="w-full text-[color:var(--astra-text-muted)]"
          style={{ font: '11px/1.4 var(--astra-font-code)', letterSpacing: '0.12em', textTransform: 'uppercase' }}
        >
          {t('scope.appliedPrefix')} {appliedSummary}
        </p>
      )}
    </div>
  )
}
