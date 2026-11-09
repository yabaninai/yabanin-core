import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

// Astra copy block: the config text stays visible for manual selection; the
// copy action mirrors CopyIdButton (clipboard API + textarea fallback,
// transient role=status confirmation, 44px target). Extracted from
// guided agent setup show the same "copy this verbatim" affordance.

export function CopyBlock({ id, text, copyLabel }: { id: string; text: string; copyLabel: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout>>()
  useEffect(() => () => clearTimeout(timer.current), [])

  const copy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text)
      } else {
        const ta = document.createElement('textarea')
        ta.value = text
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
      // Clipboard denied — the block stays visible for manual selection.
    }
  }

  return (
    <div className="astra-panel flex flex-col gap-2 p-3" data-testid={`copy-block-${id}`}>
      <pre
        aria-label={copyLabel}
        tabIndex={0}
        className="overflow-x-auto text-xs leading-relaxed text-[color:var(--astra-ink)]"
        style={{ fontFamily: 'var(--astra-font-code)', margin: 0 }}
      >
        {text}
      </pre>
      <div>
        <button
          type="button"
          onClick={() => void copy()}
          aria-label={copyLabel}
          className="inline-flex min-h-[44px] items-center gap-1 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-3 text-xs text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)] hover:text-[color:var(--astra-ink)]"
          data-testid={`copy-${id}`}
        >
          <span aria-hidden="true">{copied ? '✓' : '⧉'}</span>
          <span role="status">{copied ? t('common.copied') : t('common.copy')}</span>
        </button>
      </div>
    </div>
  )
}
