import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useFocusTrap } from './useFocusTrap'

// item 3). A form in the right-side panel (the .astra-drawer shell shared
// with EntityDrawer) instead of a permanent creation form above the list.
//
// Contract:
//   * Escape closes (and focus returns to the opener) — via the shared
//     useFocusTrap; Escape is ignored while a submit is in flight so an
//     impatient keypress cannot drop a half-sent request silently;
//   * the submit button goes through the useAction submit semantics:
//     busy disables the controls, success closes the drawer, a failure
//     renders inline (role=alert) and keeps the drawer open with the
//     fields intact. Descriptor-risk flows (type-the-name, reason,
//     undo toast) keep using ActionDialog — a create form never opens a
//     second modal on top of the drawer;
//   * `open` is controlled: nothing renders while closed, and the trap
//     only ever arms for an open panel (the panel mounts fresh per open).

export interface FormDrawerProps {
  /** Controlled visibility; the drawer renders nothing while closed. */
  open: boolean
  /** Entity-type eyebrow above the title (e.g. «Организация»). */
  kind?: string
  /** Drawer title; doubles as the dialog's accessible name. */
  title: string
  /** Submit button label; defaults to the common «Save». */
  submitLabel?: string
  onClose: () => void
  /**
   * Reads the current field values from the page state and performs the
   * mutation. Resolve = close; reject = inline error, drawer stays open.
   */
  onSubmit: () => Promise<void>
  children: ReactNode
}

export function FormDrawer(props: FormDrawerProps) {
  if (!props.open) return null
  return <FormDrawerPanel {...props} />
}

function FormDrawerPanel({
  kind, title, submitLabel, onClose, onSubmit, children,
}: FormDrawerProps) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const panelRef = useRef<HTMLDivElement | null>(null)
  // The trap arms once per mount with a stable escape closure; while busy
  // the escape must not close, so the closure reads a ref and the guard
  // lives here rather than in the generic hook.
  const onCloseRef = useRef(onClose)
  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])
  const escape = useCallback(() => {
    if (!busy) onCloseRef.current()
  }, [busy])
  useFocusTrap(panelRef, escape)

  const submit = async () => {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      await onSubmit()
      onCloseRef.current()
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

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
            {kind && (
              <p className="text-[11px] font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{kind}</p>
            )}
            <h2 className="mt-0.5 break-all text-lg font-semibold text-[color:var(--astra-ink)]">{title}</h2>
          </div>
          <button
            type="button"
            onClick={() => onCloseRef.current()}
            aria-label={t('common.close')}
            disabled={busy}
            className="btn-secondary shrink-0"
          >
            ✕
          </button>
        </div>

        <form
          className="flex min-h-0 flex-1 flex-col gap-4"
          onSubmit={e => {
            e.preventDefault()
            void submit()
          }}
        >
          <div className="flex min-h-0 flex-1 flex-col gap-4">{children}</div>
          {error && (
            <p role="alert" className="text-sm" style={{ color: 'var(--astra-danger)' }}>
              {t('actions.errorLabel')}: {error}
            </p>
          )}
          <div className="flex justify-end gap-2 border-t border-[color:var(--astra-rule)] pt-3">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => onCloseRef.current()}
              disabled={busy}
            >
              {t('common.cancel')}
            </button>
            <button type="submit" className="btn-primary" disabled={busy}>
              {submitLabel ?? t('common.save')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
