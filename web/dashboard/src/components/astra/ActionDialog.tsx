// AUX-12: shared action-contract surface (useAction + ActionDialog + toast).
//
// Replaces the browser confirm()/prompt() dialogs with a keyboard-accessible
// surface driven by an ActionDescriptor. Risk routing:
//   low + reversible + undo provided -> execute immediately, toast with a
//     10s Undo affordance (inverse call), no modal.
//   medium -> modal with was -> becomes and consequences.
//   high / irreversible -> modal with consequences and a type-the-entity-name
//     confirmation.
// AUX-14b: dialogs can collect an operator reason (opts.reason) and hand it
// to execute — callers send it as the X-Audit-Reason header, which the audit
// journal stores and shows. The toast-undo path has no dialog, so it sends
// no reason (the journal still records the inverse call itself).
// This file must stay free of any org/root authorization logic.
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useFocusTrap } from './useFocusTrap'

export type ActionRisk = 'low' | 'medium' | 'high'

export interface ActionDescriptor {
  id: string
  risk: ActionRisk
  permission?: string
  reversible: boolean
  impact?: ReactNode
}

export interface ActionRunOptions {
  entity?: string
  was?: ReactNode
  becomes?: ReactNode
  input?: { label: string; initial: string }
  /** AUX-14b: collect an operator reason and pass it to execute. */
  reason?: { required?: boolean }
  confirmLabel: string
  impact?: ReactNode
  execute: (args: { value: string; reason: string }) => Promise<void>
  undo?: () => Promise<void>
  onDone?: () => void
  onError?: (message: string) => void
}

/** Reasons are capped in step with the server (auditReasonMaxRunes = 512). */
const REASON_MAX = 512

/** AUX-14b: map a collected reason onto request options (X-Audit-Reason). */
export function auditReasonOpts(reason: string): { headers?: Record<string, string> } {
  const trimmed = reason.trim()
  return trimmed ? { headers: { 'X-Audit-Reason': trimmed } } : {}
}

const UNDO_MS = 10_000

function messageOf(err: unknown): string {
  if (err instanceof Error && err.message) return err.message
  return String(err)
}

interface PendingAction {
  opts: ActionRunOptions
  impact?: ReactNode
  nameRequired: boolean
}

interface ToastState {
  undo: () => Promise<void>
  onDone?: () => void
  onError?: (message: string) => void
}

export function ActionDialog({
  pending,
  entity,
  inputValue,
  reasonValue,
  busy,
  error,
  onValueChange,
  onReasonChange,
  onConfirm,
  onCancel,
}: {
  pending: PendingAction
  entity?: string
  inputValue: string
  reasonValue: string
  busy: boolean
  error: string
  onValueChange: (value: string) => void
  onReasonChange: (value: string) => void
  onConfirm: () => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const panelRef = useRef<HTMLDivElement | null>(null)
  const { opts, impact, nameRequired } = pending
  const valueFilled = !opts.input || inputValue.trim().length > 0
  const nameFilled = !nameRequired || inputValue.trim() === (entity ?? '').trim()
  const reasonFilled = !opts.reason?.required || reasonValue.trim().length > 0
  const canConfirm = !busy && valueFilled && nameFilled && reasonFilled

  // trap Tab inside the panel, close on Escape and restore focus on unmount.
  // Runs once per dialog; onCancel is stable (setPending) so the closure
  // stays valid.
  useFocusTrap(panelRef, onCancel)

  return (
    <div className="astra-overlay">
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={t('actions.dialogLabel')}
        className="card astra-dialog"
      >
        <h2 className="text-lg font-medium">{opts.confirmLabel}</h2>
        {impact && <p className="mt-3 text-sm">{impact}</p>}
        {opts.was != null && (
          <p className="mt-3 text-sm">
            <span style={{ color: 'var(--astra-text-muted)' }}>{t('actions.was')}: </span>
            <span className="break-all">{opts.was}</span>
            <span className="mx-2" style={{ color: 'var(--astra-text-muted)' }}>→</span>
            <span style={{ color: 'var(--astra-text-muted)' }}>{t('actions.becomes')}: </span>
            <span className="break-all">{opts.becomes ?? (opts.input ? inputValue : '—')}</span>
          </p>
        )}
        {opts.input && (
          <div className="mt-3">
            <label className="mb-1 block text-sm" style={{ color: 'var(--astra-text-muted)' }} htmlFor="action-dialog-input">
              {opts.input.label}
            </label>
            <input
              id="action-dialog-input"
              className="control w-full"
              value={inputValue}
              onChange={(event) => onValueChange(event.target.value)}
            />
          </div>
        )}
        {nameRequired && (
          <div className="mt-3">
            <label className="mb-1 block text-sm" style={{ color: 'var(--astra-text-muted)' }} htmlFor="action-dialog-name">
              {t('actions.confirmNameLabel', { name: entity ?? '' })}
            </label>
            <input
              id="action-dialog-name"
              className="control w-full"
              value={inputValue}
              onChange={(event) => onValueChange(event.target.value)}
              autoComplete="off"
            />
          </div>
        )}
        {opts.reason && (
          <div className="mt-3">
            <label className="mb-1 block text-sm" style={{ color: 'var(--astra-text-muted)' }} htmlFor="action-dialog-reason">
              {opts.reason.required ? t('actions.reasonRequiredLabel') : t('actions.reasonLabel')}
            </label>
            <input
              id="action-dialog-reason"
              className="control w-full"
              value={reasonValue}
              maxLength={REASON_MAX}
              onChange={event => onReasonChange(event.target.value)}
              autoComplete="off"
            />
          </div>
        )}
        {error && (
          <p role="alert" className="mt-3 text-sm" style={{ color: 'var(--astra-danger)' }}>
            {t('actions.errorLabel')}: {error}
          </p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={onCancel} disabled={busy}>
            {t('common.cancel')}
          </button>
          <button type="button" className="btn-primary" onClick={onConfirm} disabled={!canConfirm}>
            {opts.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

export function ActionToast({
  onUndo,
  onDismiss,
}: {
  onUndo: () => void
  onDismiss: () => void
}) {
  const { t } = useTranslation()
  return (
    <div role="status" className="astra-toast">
      <span>{t('actions.done')}</span>
      <button type="button" className="btn-secondary" onClick={onUndo}>
        {t('actions.undo')}
      </button>
      <button type="button" aria-label={t('actions.dismiss')} onClick={onDismiss}>
        ✕
      </button>
    </div>
  )
}

export function useAction(descriptor: ActionDescriptor) {
  const [pending, setPending] = useState<PendingAction | null>(null)
  const [busy, setBusy] = useState(false)
  const [dialogError, setDialogError] = useState('')
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const [toast, setToast] = useState<ToastState | null>(null)
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(
    () => () => {
      if (toastTimer.current) clearTimeout(toastTimer.current)
    },
    [],
  )

  const clearToast = useCallback(() => {
    if (toastTimer.current) {
      clearTimeout(toastTimer.current)
      toastTimer.current = null
    }
    setToast(null)
  }, [])

  const run = useCallback(
    (opts: ActionRunOptions) => {
      clearToast()
      setReason('')
      if (descriptor.risk === 'low' && descriptor.reversible && opts.undo) {
        setBusy(true)
        opts
          .execute({ value: '', reason: '' })
          .then(() => {
            opts.onDone?.()
            setBusy(false)
            setToast({ undo: opts.undo!, onDone: opts.onDone, onError: opts.onError })
            toastTimer.current = setTimeout(() => setToast(null), UNDO_MS)
          })
          .catch((err) => {
            setBusy(false)
            opts.onError?.(messageOf(err))
          })
        return
      }
      setDialogError('')
      setValue(opts.input?.initial ?? '')
      setPending({
        opts,
        impact: opts.impact ?? descriptor.impact,
        nameRequired: descriptor.risk === 'high' && !!opts.entity,
      })
    },
    [clearToast, descriptor],
  )

  const cancel = useCallback(() => setPending(null), [])

  const confirm = useCallback(async () => {
    if (!pending || busy) return
    const { opts, nameRequired } = pending
    if (nameRequired && value.trim() !== (opts.entity ?? '').trim()) return
    if (opts.reason?.required && !reason.trim()) return
    setBusy(true)
    setDialogError('')
    try {
      await opts.execute({ value: value.trim(), reason: reason.trim() })
      setPending(null)
      opts.onDone?.()
    } catch (err) {
      setDialogError(messageOf(err))
    } finally {
      setBusy(false)
    }
  }, [busy, pending, value, reason])

  const undoToast = useCallback(async () => {
    if (!toast) return
    clearToast()
    try {
      await toast.undo()
      toast.onDone?.()
    } catch (err) {
      toast.onError?.(messageOf(err))
    }
  }, [clearToast, toast])

  const ui = (
    <>
      {pending && (
        <ActionDialog
          pending={pending}
          entity={pending.opts.entity}
          inputValue={value}
          reasonValue={reason}
          busy={busy}
          error={dialogError}
          onValueChange={setValue}
          onReasonChange={setReason}
          onConfirm={() => void confirm()}
          onCancel={cancel}
        />
      )}
      {toast && <ActionToast onUndo={() => void undoToast()} onDismiss={clearToast} />}
    </>
  )

  return { run, ui, busy, dialogOpen: pending !== null }
}
