import { useEffect, useRef, ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { EvidenceLabel, EvidenceTier, SignatureStatus } from './EvidenceLabel'
import { CopyIdButton } from './CopyIdButton'
import { StateNotice } from './StateNotice'
import { FOCUSABLE, useFocusTrap } from './useFocusTrap'

// Astra primitive: RequestInspector (standards/design.md "Components and
// contracts"). ID, actual model, region claim, timing, cost provenance,
// evidence, raw JSON in <details>. Every field comes from the real API —
// what the API does not record is shown as "Not recorded", never invented.
//
// Surfaces:
//   * inline (default) — a static panel on the page;
//   * dialog — the centered modal (LineagePage);
//   * drawer — the right-side inspector panel over a dimmed backdrop
//     via ?inspect=request:<id>). The shell is the shared .astra-drawer
//     surface; the keyboard contract (opener capture, Tab cycle, Escape,
//     focus restore) lives in the shared useFocusTrap hook — one copy for
//     every modal surface.
//
// `links` the related pages (Lineage) under the field list; both come from
// the page and stay optional — the inspector itself invents nothing.

export interface InspectorField {
  label: string
  value: ReactNode
  mono?: boolean
}

export interface RequestInspectorProps {
  /** True when the record exists (vs "nothing selected"). */
  record: {
    id?: string
    model?: string
    regionClaim?: string
    timing?: string
    evidence?: { tier: EvidenceTier; explanation: ReactNode }
    signature?: { status: SignatureStatus; detail?: ReactNode }
    raw?: unknown
  } | null
  onClose?: () => void
  /** Renders as an accessible modal dialog instead of an inline panel. */
  dialog?: boolean
  variant?: 'inline' | 'dialog' | 'drawer'
  /** Extra real-API fields, appended after the standard ones. */
  fields?: InspectorField[]
  /** Cost provenance line; when absent the inspector says it is not recorded. */
  costProvenance?: ReactNode
  /** Verify action (signature), if the screen offers it. */
  verify?: {
    status: SignatureStatus
    onVerify?: () => void
    verifying?: boolean
  }
  loading?: boolean
  /** the route/attempt trail block, shown after the field list. */
  routeTimeline?: ReactNode
  /** Related-page links (scope preserved), shown last. */
  links?: Array<{ label: string; href: string }>
}

// The modal shell (dialog + drawer). Mounted only when a modal surface is
// requested, so the focus-trap effect exists exactly when the panel does.
function InspectorModalSurface({
  surface, onClose, children,
}: {
  surface: 'dialog' | 'drawer'
  onClose?: () => void
  children: ReactNode
}) {
  const { t } = useTranslation()
  const panelRef = useRef<HTMLDivElement | null>(null)
  useFocusTrap(panelRef, onClose ?? (() => {}))

  // Containment backstop: mobile browsers are emulated with mobile tabbing
  // semantics — a[href] is not a Tab stop there, so a native Tab past the
  // raw-record <summary> falls through to <body> and breaks the aria-modal
  // promise. After every Tab (post default-action check) a fall-through to
  // the document root is corrected back into the panel. Other surfaces
  // (palette, drawers) own their focus; only the body fall-through triggers
  // the pull-back.
  useEffect(() => {
    const panel = panelRef.current
    if (!panel) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      window.setTimeout(() => {
        if (panel.querySelector(':focus')) return
        const active = document.activeElement
        if (active === document.body || active === document.documentElement) {
          const first = panel.querySelector<HTMLElement>(FOCUSABLE)
          ;(first ?? panel).focus()
        }
      }, 0)
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
  }, [])

  const heading = (
    <div className="flex items-start justify-between gap-3">
      <h3 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('inspector.requestDetails')}</h3>
      {onClose && (
        <button type="button" onClick={onClose} className="btn-secondary">
          {t('common.close')}
        </button>
      )}
    </div>
  )

  if (surface === 'drawer') {
    return (
      <div className="astra-drawer-layer">
        <div aria-hidden="true" className="astra-drawer-backdrop" />
        <div
          ref={panelRef}
          role="dialog"
          aria-modal="true"
          aria-label={t('inspector.dialogLabel')}
          className="astra-drawer"
        >
          {heading}
          {children}
        </div>
      </div>
    )
  }

  return (
    // Overlay uses the ink token at 40% (the porcelain backdrop), an
    // explicit element instead of a Tailwind palette utility.
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
      <div aria-hidden="true" className="fixed inset-0" style={{ background: 'var(--astra-ink)', opacity: 0.4 }} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('inspector.dialogLabel')}
        tabIndex={-1}
        className="astra-panel relative w-full max-w-2xl border-[color:var(--astra-rule-strong)] p-5"
      >
        {heading}
        {children}
      </div>
    </div>
  )
}

export function RequestInspector({ record, onClose, dialog, variant, fields = [], costProvenance, verify, loading, routeTimeline, links = [] }: RequestInspectorProps) {
  const { t } = useTranslation()
  const surface: 'inline' | 'dialog' | 'drawer' = variant ?? (dialog ? 'dialog' : 'inline')
  const modal = surface !== 'inline'

  if (surface === 'drawer') {
    // The explorer mounts the drawer for an inspect id; while the detail and
    // lineage fetches run the panel shows the honest loading state, and a
    // failed/unknown id degrades to the drawer's not-found notice.
    return (
      <InspectorModalSurface surface="drawer" onClose={onClose}>
        {loading ? (
          <p className="text-sm text-[color:var(--astra-text-muted)]">{t('inspector.loadingRecord')}</p>
        ) : !record ? (
          <StateNotice state="empty" message={t('drawer.notFound')} />
        ) : (
          <InspectorBody
            record={record}
            fields={fields}
            costProvenance={costProvenance}
            verify={verify}
            routeTimeline={routeTimeline}
            links={links}
          />
        )}
      </InspectorModalSurface>
    )
  }

  if (loading) {
    return (
      <aside className="astra-panel border-[color:var(--astra-rule-strong)] px-4 py-5 text-sm text-[color:var(--astra-text-muted)]">
        {t('inspector.loadingRecord')}
      </aside>
    )
  }

  if (!record) {
    return (
      <aside className="flex flex-col gap-1 border border-dashed border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-4 py-5 text-sm text-[color:var(--astra-text-muted)]">
        {t('inspector.noRequestSelected')}
      </aside>
    )
  }

  const body = (
    <InspectorBody
      record={record}
      fields={fields}
      costProvenance={costProvenance}
      verify={verify}
      routeTimeline={routeTimeline}
      links={links}
    />
  )

  if (modal) {
    return (
      <InspectorModalSurface surface="dialog" onClose={onClose}>
        {body}
      </InspectorModalSurface>
    )
  }

  return <aside className="astra-panel border-[color:var(--astra-rule-strong)] p-5">{body}</aside>
}

// The record body shared by every surface: the field list, the optional
// route/attempt trail, evidence, verify, raw JSON and related links.
function InspectorBody({
  record, fields, costProvenance, verify, routeTimeline, links,
}: {
  record: NonNullable<RequestInspectorProps['record']>
  fields: InspectorField[]
  costProvenance?: ReactNode
  verify?: RequestInspectorProps['verify']
  routeTimeline?: ReactNode
  links: Array<{ label: string; href: string }>
}) {
  const { t } = useTranslation()
  const dl: [string, ReactNode, boolean?][] = [
    [t('inspector.requestId'), record.id ? <span className="flex flex-wrap items-center gap-2"><span className="break-all">{record.id}</span><CopyIdButton value={record.id} label="request" /></span> : t('common.unavailable'), true],
    [t('inspector.modelActual'), record.model ?? t('common.notRecorded')],
    [t('inspector.regionClaim'), record.regionClaim ?? t('common.notRecorded')],
    [t('inspector.recordedAtUtc'), record.timing ?? t('common.notRecorded')],
    [t('inspector.costProvenance'), costProvenance ?? t('inspector.costNotRecorded')],
    ...fields.map(f => [f.label, f.value, f.mono] as [string, ReactNode, boolean?]),
  ]

  return (
    <div className="flex flex-col gap-4">
      <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
        {dl.map(([label, value, mono]) => (
          <div key={label} className="min-w-0">
            <dt
              className="text-[color:var(--astra-text-muted)]"
              style={{ font: 'var(--astra-font-label)/1.4 var(--astra-font-ui)', letterSpacing: '0.04em', textTransform: 'uppercase' }}
            >
              {label}
            </dt>
            <dd
              className="mt-0.5 break-all text-sm text-[color:var(--astra-ink)]"
              style={mono ? { fontFamily: 'var(--astra-font-code)' } : undefined}
            >
              {value}
            </dd>
          </div>
        ))}
      </dl>
      {routeTimeline}
      {record.evidence && (
        <EvidenceLabel tier={record.evidence.tier} explanation={record.evidence.explanation} signature={record.signature} />
      )}
      {verify && (
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <button
            type="button"
            onClick={verify.onVerify}
            disabled={!verify.onVerify || verify.verifying}
            className="btn-secondary"
          >
            {verify.verifying ? t('inspector.verifying') : t('inspector.verifySignature')}
          </button>
          {verify.status !== 'unverified' && (
            <span className={verify.status === 'valid' ? 'text-[color:var(--astra-success)]' : 'text-[color:var(--astra-danger)]'}>
              {verify.status === 'valid'
                ? t('inspector.signatureValidDetail')
                : t('inspector.verificationFailedDetail')}
            </span>
          )}
        </div>
      )}
      {record.raw !== undefined && (
        <details>
          <summary className="cursor-pointer text-sm font-medium text-[color:var(--astra-ink)]">{t('inspector.rawRecordJson')}</summary>
          <pre className="mt-2 max-h-72 overflow-auto border border-[color:var(--astra-rule)] bg-[color:var(--astra-surface-muted)] p-3 text-xs leading-relaxed" style={{ fontFamily: 'var(--astra-font-code)' }}>
            {JSON.stringify(record.raw, null, 2)}
          </pre>
        </details>
      )}
      {links.length > 0 && (
        <nav aria-label={t('drawer.links')} className="flex flex-col gap-1 border-t border-[color:var(--astra-rule)] pt-3">
          {links.map(link => (
            <a key={link.href + link.label} href={link.href} className="inline-flex min-h-[36px] items-center text-sm font-medium text-[color:var(--astra-ink)] underline decoration-[color:var(--astra-rule-strong)] underline-offset-4 hover:bg-[color:var(--astra-surface-muted)]">
              {link.label}
            </a>
          ))}
        </nav>
      )}
    </div>
  )
}
