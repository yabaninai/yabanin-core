import { useRef, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { CopyIdButton } from './CopyIdButton'
import { StateNotice } from './StateNotice'
import { useFocusTrap } from './useFocusTrap'

// EntityDrawer — the side inspector card for an entity (API key,
// model, rule, organization). A right-side panel over a dimmed backdrop,
// opened from an entity-name click and from the `?inspect=<id>` deep link.
// Read-only on purpose: it surfaces identifiers (full-value copy, as in the
// DataTable), the typed fields already carried by the list row (or an
// existing detail GET — no new endpoints), recent related activity when the
// page already holds that data, and links to the related list pages. The
// mutating actions stay in the rows (ActionDialog contract); permission
// gates are untouched.
//
// The keyboard contract (opener capture, Tab cycle, Escape, focus restore)
// comes from the shared useFocusTrap hook that backs the drawer.
// Full-screen width on phones (the layout must not break at 360px — see
// .astra-drawer in index.css).
export interface EntityDrawerId {
  label: string
  value: string
}

export interface EntityDrawerField {
  label: string
  value: ReactNode
  mono?: boolean
}

export interface EntityDrawerLink {
  label: string
  href: string
}

export interface EntityDrawerProps {
  /** Entity-type label above the title (e.g. the list page's title). */
  kind: string
  /** Entity display name; doubles as the dialog's accessible name. */
  title: string
  onClose: () => void
  /** Identifiers with a full-value copy button (IDs, model names). */
  ids?: EntityDrawerId[]
  /** Typed key fields from the row / detail data; absent → not shown. */
  fields?: EntityDrawerField[]
  /** Recent related actions, only when the page already holds that data. */
  activity?: ReactNode
  /** Links to the related list pages (preserve scope, drop ?inspect). */
  links?: EntityDrawerLink[]
  /** The inspect id is not among the loaded rows (honest not-found state). */
  missing?: boolean
  children?: ReactNode
}

// The keyboard contract (opener capture, Tab cycle, Escape, focus restore)
// the drawer shell.

export function EntityDrawer({
  kind, title, onClose, ids = [], fields = [], activity, links = [], missing = false, children,
}: EntityDrawerProps) {
  const { t } = useTranslation()
  const panelRef = useRef<HTMLDivElement | null>(null)
  useFocusTrap(panelRef, onClose)

  return (
    <div className="astra-drawer-layer">
      <div aria-hidden="true" className="astra-drawer-backdrop" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="astra-drawer"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-[11px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{kind}</p>
            <h2 className="mt-0.5 break-all text-lg font-semibold text-[color:var(--astra-ink)]">{title}</h2>
          </div>
          <button type="button" onClick={onClose} aria-label={t('common.close')} className="btn-secondary shrink-0">✕</button>
        </div>

        {missing ? (
          <StateNotice state="empty" message={t('drawer.notFound')} />
        ) : (
          <>
            {ids.length > 0 && (
              <section aria-label={t('drawer.ids')} className="flex flex-col gap-2">
                <h3 className="text-xs font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('drawer.ids')}</h3>
                {ids.map(id => (
                  <div key={id.label} className="flex flex-wrap items-center justify-between gap-2">
                    <span className="min-w-0 break-all text-sm" style={{ fontFamily: 'var(--astra-font-code)' }}>{id.value}</span>
                    <CopyIdButton value={id.value} label={id.label} />
                  </div>
                ))}
              </section>
            )}

            {fields.length > 0 && (
              <section aria-label={t('drawer.fields')}>
                <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('drawer.fields')}</h3>
                <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
                  {fields.map(f => (
                    <div key={f.label} className="min-w-0">
                      <dt
                        className="text-[color:var(--astra-text-muted)]"
                        style={{ font: 'var(--astra-font-label)/1.4 var(--astra-font-ui)', letterSpacing: '0.04em', textTransform: 'uppercase' }}
                      >
                        {f.label}
                      </dt>
                      <dd
                        className="mt-0.5 break-all text-sm text-[color:var(--astra-ink)]"
                        style={f.mono ? { fontFamily: 'var(--astra-font-code)' } : undefined}
                      >
                        {f.value}
                      </dd>
                    </div>
                  ))}
                </dl>
              </section>
            )}

            {activity}

            {links.length > 0 && (
              <nav aria-label={t('drawer.links')} className="flex flex-col gap-1 border-t border-[color:var(--astra-rule)] pt-3">
                <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('drawer.links')}</h3>
                {links.map(link => (
                  <a key={link.href + link.label} href={link.href} className="inline-flex min-h-[36px] items-center text-sm font-medium text-[color:var(--astra-ink)] underline decoration-[color:var(--astra-rule-strong)] underline-offset-4 hover:bg-[color:var(--astra-surface-muted)]">
                    {link.label}
                  </a>
                ))}
              </nav>
            )}

            {children}
          </>
        )}
      </div>
    </div>
  )
}
