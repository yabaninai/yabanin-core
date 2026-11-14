import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

// Identifiers render verbatim, never uppercased or truncated in copy.
// The table-sized sibling of CopyIdButton: same clipboard
// semantics (full value, transient visible "Copied" confirmation, hidden-
// textarea fallback for non-secure contexts) at chip height so it fits a
// dense row or a drawer field line.

export function IdChip({ value, label }: { value: string; label?: string }) {
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
    <span
      className="inline-flex max-w-full items-center gap-1 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] py-0.5 pe-1 ps-1.5"
      style={{ fontFamily: 'var(--astra-font-code)', fontVariantNumeric: 'tabular-nums' }}
    >
      <span className="min-w-0 truncate text-xs" title={value}>{value}</span>
      <button
        type="button"
        onClick={copy}
        aria-label={copied ? t('common.copied') : t('common.copyAria', { label: label ?? 'ID', value })}
        className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-[length:var(--astra-radius-control)] text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)] hover:text-[color:var(--astra-ink)]"
      >
        <span aria-hidden="true">{copied ? '✓' : '⧉'}</span>
        <span role="status" className="sr-only">{copied ? t('common.copied') : t('common.copy')}</span>
      </button>
    </span>
  )
}
