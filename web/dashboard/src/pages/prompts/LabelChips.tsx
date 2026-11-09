import type { PromptLabelName } from '../../api/prompts'

// draft/active/canary/custom). Shared by the library list and the detail
// header; empty renders an honest em dash, not a fake chip.
export function LabelChips({ labels }: { labels: PromptLabelName[] }) {
  if (labels.length === 0) {
    return <span className="text-[color:var(--astra-text-muted)]">—</span>
  }
  return (
    <span className="flex flex-wrap gap-1">
      {labels.map(label => (
        <span
          key={label}
          className="inline-flex items-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface-muted)] px-1.5 py-0.5 font-mono text-xs text-[color:var(--astra-ink)]"
        >
          {label}
        </span>
      ))}
    </span>
  )
}
