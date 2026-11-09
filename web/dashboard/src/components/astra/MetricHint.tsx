import { useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'

// Keep glossary text readable even when its trigger is near a viewport edge
// or inside a scrolling panel. The portal avoids ancestor clipping; placement
// uses the client viewport rather than mobile's overflow-expanded innerWidth.
const GLYPH = '?'

export function MetricHint({ label, description }: { label?: string; description: ReactNode }) {
  const { t } = useTranslation()
  const id = useId()
  const triggerRef = useRef<HTMLButtonElement>(null)
  const tooltipRef = useRef<HTMLSpanElement>(null)
  const [hovered, setHovered] = useState(false)
  const [focused, setFocused] = useState(false)
  const open = hovered || focused

  useLayoutEffect(() => {
    if (!open) return
    const trigger = triggerRef.current
    const tooltip = tooltipRef.current
    if (!trigger || !tooltip) return
    const position = () => {
      const viewport = document.documentElement
      const margin = 8
      tooltip.style.maxWidth = `min(15rem, ${Math.max(0, viewport.clientWidth - margin * 2)}px)`
      const anchor = trigger.getBoundingClientRect()
      const box = tooltip.getBoundingClientRect()
      const direction = getComputedStyle(trigger).direction
      const alignedLeft = direction === 'rtl' ? anchor.left : anchor.right - box.width
      tooltip.style.direction = direction
      tooltip.style.left = `${Math.max(margin, Math.min(alignedLeft, viewport.clientWidth - box.width - margin))}px`
      const below = anchor.bottom + 4
      const top = below + box.height <= viewport.clientHeight - margin ? below : anchor.top - box.height - 4
      tooltip.style.top = `${Math.max(margin, Math.min(top, viewport.clientHeight - box.height - margin))}px`
    }
    position()
    const observer = new ResizeObserver(position)
    observer.observe(trigger)
    observer.observe(tooltip)
    observer.observe(document.documentElement)
    window.addEventListener('resize', position)
    window.addEventListener('scroll', position, true)
    return () => {
      observer.disconnect()
      window.removeEventListener('resize', position)
      window.removeEventListener('scroll', position, true)
    }
  }, [open, description])

  return (
    <span className="inline-flex" onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
      <button
        ref={triggerRef}
        type="button"
        aria-label={label ? t('common.metricHintAria', { name: label }) : t('common.metricHint')}
        aria-describedby={id}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-[color:var(--astra-rule-strong)] text-xs leading-none text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)] hover:text-[color:var(--astra-ink)]"
      >
        <span aria-hidden="true">{GLYPH}</span>
      </button>
      {typeof document !== 'undefined' && createPortal(
        <span
          ref={tooltipRef}
          role="tooltip"
          id={id}
          hidden={!open}
          className="pointer-events-none fixed left-0 top-0 z-20 w-max max-w-60 overflow-wrap-anywhere rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-2 py-1 text-start text-xs font-normal normal-case tracking-normal text-[color:var(--astra-ink)]"
        >
          {description}
        </span>,
        document.body,
      )}
    </span>
  )
}
