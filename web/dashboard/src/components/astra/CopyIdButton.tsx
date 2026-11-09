import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

// Astra primitive: CopyIdButton. Copies a record ID fully (IDs may wrap in
// tables, but copy must take the whole value — standards/design.md). Shows a
// transient "Copied" confirmation (not hover-only), falls back to a hidden
// textarea when the clipboard API is unavailable (non-secure contexts).

export function CopyIdButton({ value, label }: { value: string; label?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout>>()

  useEffect(() => () => clearTimeout(timer.current), [])

  const copy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value)
      } else {
        const ta = document.createElement('textarea')
        ta.value = value
        ta.style.position = 'fixed'
        ta.style.opacity = '0'
        document.body.appendChild(ta)
        ta.select()
        document.execCommand('copy')
        document.body.removeChild(ta)
      }
      setCopied(true)
      clearTimeout(timer.current)
      timer.current = setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard denied — the ID stays visible for manual selection.
    }
  }

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={copied ? t('common.copied') : t('common.copyAria', { label: label ?? 'ID', value })}
      className="inline-flex min-h-[44px] items-center gap-1 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-2 text-xs text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)] hover:text-[color:var(--astra-ink)]"
    >
      <span aria-hidden="true">{copied ? '✓' : '⧉'}</span>
      <span role="status">{copied ? t('common.copied') : t('common.copy')}</span>
    </button>
  )
}
