import { ReactNode, useId, useState } from 'react'
import { useTranslation } from 'react-i18next'

// where a report's numbers come from. The collapsed control names the source
// («ⓘ Источники») with the SHORT pinned ref (7 chars) and snapshot date; the
// full raw provenance (git URL, sha256, …) lives inside the disclosure so it
// can never widen the document. Everything wraps with overflow-wrap:anywhere
// — provenance strings are the unbreakable-token case that drove the 1517px
// Overview overflow.

export interface ProvenanceNoteProps {
  /** Short pinned ref shown collapsed (e.g. a 7-char commit). */
  shortRef?: string
  /** Snapshot date shown collapsed (YYYY-MM-DD). */
  date?: string
  /** Full provenance label, rendered mono inside the disclosure. */
  raw?: ReactNode
  /** Extra evidence lines revealed with the raw label (e.g. unpriced models). */
  children?: ReactNode
  /** Visible control label; defaults to t('provenance.sources'). */
  label?: string
}

export function ProvenanceNote({ shortRef, date, raw, children, label }: ProvenanceNoteProps) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const panelId = useId()
  const summary = [shortRef, date].filter(Boolean).join(' · ')
  return (
    <div className="astra-panel px-4 py-3">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen(o => !o)}
        className="inline-flex max-w-full flex-wrap items-center gap-2 text-sm text-[color:var(--astra-info)] hover:underline focus-visible:underline"
      >
        <span aria-hidden="true">ⓘ</span>
        <span className="font-medium">{label ?? t('provenance.sources')}</span>
        {summary && (
          <span
            className="text-[color:var(--astra-text-muted)]"
            style={{ fontFamily: 'var(--astra-font-code)', fontVariantNumeric: 'tabular-nums' }}
          >
            {summary}
          </span>
        )}
      </button>
      {open && (
        <div
          id={panelId}
          className="overflow-wrap-anywhere mt-2 border-s-2 border-[color:var(--astra-info)] bg-[color:var(--astra-info-surface)] px-3 py-2 text-sm text-[color:var(--astra-ink)]"
        >
          {raw != null && (
            <p className="overflow-wrap-anywhere min-w-0" style={{ fontFamily: 'var(--astra-font-code)', fontSize: 'var(--astra-font-small)' }}>
              {raw}
            </p>
          )}
          {children}
        </div>
      )}
    </div>
  )
}
