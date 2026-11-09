import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { StateNotice } from '../../components/astra/StateNotice'

// agent-key create/rotate flows. TP-06 clipboard contract: success is
// confirmed only after the writeText await resolves, a rejected clipboard
// keeps the only copy of the secret on screen (retry or dismiss), and the
// explicit dismiss is the ONLY remover. 'copied'/'error' feedback resets to
// idle after 2s; the secret itself never auto-clears.

type CopyState = 'idle' | 'copied' | 'error'

export function OneTimeSecretBanner({
  title, message, secret, onDismiss,
}: {
  title: string
  message: string
  secret: string
  onDismiss: () => void
}) {
  const { t } = useTranslation()
  const [copyState, setCopyState] = useState<CopyState>('idle')
  useEffect(() => {
    setCopyState('idle')
  }, [secret])
  useEffect(() => {
    if (copyState === 'idle') return
    const timer = setTimeout(() => setCopyState('idle'), 2000)
    return () => clearTimeout(timer)
  }, [copyState])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret)
      setCopyState('copied')
    } catch {
      setCopyState('error')
    }
  }

  return (
    <StateNotice
      state="warning"
      title={title}
      message={message}
      details={
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <code
            className="flex-1 break-all rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] bg-[color:var(--astra-surface)] p-2 text-xs"
            style={{ fontFamily: 'var(--astra-font-code)' }}
          >
            {secret}
          </code>
          <button
            onClick={() => void copy()}
            disabled={copyState === 'copied'}
            className="inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 text-xs font-medium text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)] disabled:opacity-50"
          >
            {t('common.copy')}
          </button>
          <span role="status" aria-live="polite" className="w-20 text-xs">
            {copyState === 'copied' && <span className="text-[color:var(--astra-success)]">{t('common.copied')} ✓</span>}
            {copyState === 'error' && <span className="text-[color:var(--astra-danger)]">{t('common.copyFailed')}</span>}
          </span>
          <button
            onClick={onDismiss}
            className="inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] px-2 text-xs text-[color:var(--astra-text-muted)] hover:text-[color:var(--astra-ink)]"
          >
            {t('common.dismiss')}
          </button>
        </div>
      }
    />
  )
}
