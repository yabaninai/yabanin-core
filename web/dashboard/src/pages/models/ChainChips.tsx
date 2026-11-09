import { useTranslation } from 'react-i18next'
import { chainTargetStatus, chainChipShell } from './helpers'

// list. With `onInspect` a chip is a button that opens the target's
// inspector; targets missing from the registry (danger) or disabled (warning)
// are flagged so a broken chain is visible at a glance — the same truth the
// form validates and the server enforces.
//
// disabled target says the operator switch routes nothing here, an unknown
// target carries the manual-register hint. Neither ever reads as working.

export function ChainChips({
  targets, known, onInspect, inspectTitle,
}: {
  targets: string[]
  known: ReadonlyMap<string, boolean>
  /** When given, chips render as buttons that open the target inspector. */
  onInspect?: (name: string) => void
  /** Native title for a chip; receives the name (flagged names get ▲). */
  inspectTitle?: (name: string) => string
}) {
  const { t } = useTranslation()
  if (targets.length === 0) return null
  return (
    <span className="flex flex-wrap items-center gap-1">
      {targets.map(name => {
        const status = chainTargetStatus(name, known)
        const flagged = status !== 'ok'
        const color = status === 'unknown'
          ? 'var(--astra-danger)'
          : status === 'disabled' ? 'var(--astra-warning)' : 'var(--astra-ink)'
        const reason = status === 'disabled'
          ? t('models.chipDisabledTitle', { name })
          : status === 'unknown'
            ? t('models.chipUnknownTitle', { name })
            : null
        const title = reason ?? (inspectTitle ? inspectTitle(name) : name)
        const content = (
          <>
            {flagged && <span aria-hidden="true">▲ </span>}
            <span className="min-w-0 truncate">{name}</span>
          </>
        )
        return onInspect ? (
          <button
            key={name}
            type="button"
            onClick={() => onInspect(name)}
            title={title}
            className={`${chainChipShell} hover:bg-[color:var(--astra-surface-muted)]`}
            style={{ fontFamily: 'var(--astra-font-code)', color }}
          >
            {content}
          </button>
        ) : (
          <span key={name} title={title} className={chainChipShell} style={{ fontFamily: 'var(--astra-font-code)', color }}>
            {content}
          </span>
        )
      })}
    </span>
  )
}
