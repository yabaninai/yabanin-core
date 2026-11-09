import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { listAPIKeys, listModels, listOrganizations } from '../api/client'
import {
  readOnboardingMemory, writeOnboardingMemory,
} from '../pages/hooks/overviewOnboarding'

// UI-contract #11: onboarding — org → model → key → first request → logs.
// A checklist whose steps reflect LIVE state from the read-only API; each
// pending step deep-links to the page that completes it. Honest semantics
// (TP-07):
// - the key step counts ACTIVE keys in the APPLIED org (the scope this
//   screen is showing — a revoked key or another org's keys must not
//   complete it). With no org applied (global scope) the first org stands
//   in: keys belong to an org, and the org step guarantees one exists
//   before keys are possible.
// - the model step requires an ENABLED model; the request step reads the
//   savings report already loaded by the page, so it reflects the same
//   window the screen shows.
// - unknown/loading/error never count as done: "all done" requires every
//   step to be confirmed true, and a scope switch resets the signals so no
//   previous org's results linger.
//
// dismissed checklist stays dismissed. Once every step is confirmed the card
// collapses to a small done-chip («Setup complete ✓»); closing the chip is
// remembered too.

export type OnboardingStep = {
  id: 'org' | 'model' | 'key' | 'request'
  done: boolean | null // null = not yet determined (still checking)
  /** Route id rendered as an in-app hash link (`#${page}`). */
  page: string
}

export function OnboardingCard({ orgId, requestCount }: { orgId: string; requestCount: number | null }) {
  const { t } = useTranslation()
  const [orgs, setOrgs] = useState<boolean | null>(null)
  const [models, setModels] = useState<boolean | null>(null)
  const [keys, setKeys] = useState<boolean | null>(null)
  const [memory, setMemory] = useState(readOnboardingMemory)

  useEffect(() => {
    let cancelled = false
    // TP-07: a scope switch resets the signals — the checklist must never
    // show the previous org's key result while the new org loads, and an
    // unknown step must never read as done.
    setOrgs(null)
    setModels(null)
    setKeys(null)
    void (async () => {
      let firstOrg: string | undefined
      try {
        const o = await listOrganizations(1)
        if (cancelled) return
        setOrgs((o.pagination?.total ?? o.data?.length ?? 0) > 0)
        firstOrg = o.data?.[0]?.id
      } catch {
        if (!cancelled) setOrgs(null)
      }
      try {
        const m = await listModels(1)
        if (!cancelled) setModels((m.data ?? []).some(x => x.enabled))
      } catch {
        if (!cancelled) setModels(null)
      }
      try {
        const target = orgId || firstOrg
        if (target) {
          const k = await listAPIKeys(target, 1)
          if (!cancelled) setKeys((k.data ?? []).some(x => x.active))
        } else if (!cancelled) {
          setKeys(false) // no org exists → no keys possible
        }
      } catch {
        if (!cancelled) setKeys(null)
      }
    })()
    return () => { cancelled = true }
  }, [orgId])

  const steps: OnboardingStep[] = [
    { id: 'org', done: orgs, page: 'orgs' },
    { id: 'model', done: models, page: 'models' },
    { id: 'key', done: keys, page: 'keys' },
    // TP-07: `#explorer` is not a registered route — the requests explorer is.
    { id: 'request', done: requestCount === null ? null : requestCount > 0, page: 'requests-explorer' },
  ]
  // Unknown (null) steps are part of the denominator: partial data must not
  // produce "all done".
  const allDone = steps.every(s => s.done === true)

  const dismiss = (flag: 'dismissed' | 'doneDismissed') => {
    const next = { ...memory, [flag]: true }
    setMemory(next)
    writeOnboardingMemory(next)
  }

  if (allDone) {
    // The collapsed done-chip: one calm line, no steps, no links.
    if (memory.doneDismissed) return null
    return (
      <div
        data-testid="onboarding-done-chip"
        role="status"
        aria-label={t('onboarding.doneChip')}
        className="astra-panel flex w-fit max-w-full items-center gap-2 px-3 py-1.5 text-sm text-[color:var(--astra-ink)]"
      >
        <span aria-hidden="true" style={{ color: 'var(--astra-success)' }}>✓</span>
        {t('onboarding.doneChip')}
        <button
          type="button"
          onClick={() => dismiss('doneDismissed')}
          aria-label={t('common.close')}
          className="rounded-[length:var(--astra-radius-control)] px-1.5 text-xs text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)]"
        >
          ✕
        </button>
      </div>
    )
  }

  if (memory.dismissed) return null
  return (
    <section
      aria-label={t('onboarding.title')}
      className="card space-y-3"
      style={{ borderColor: 'var(--astra-rule-strong)' }}
    >
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-base font-semibold text-[color:var(--astra-ink)]">{t('onboarding.title')}</h2>
        <button
          type="button"
          onClick={() => dismiss('dismissed')}
          aria-label={t('common.close')}
          className="rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 py-1 text-xs text-[color:var(--astra-text-muted)] hover:bg-[color:var(--astra-surface-muted)]"
        >
          ✕
        </button>
      </div>
      <ol className="space-y-2">
        {steps.map((s, i) => (
          <li key={s.id} className="flex items-center gap-3 text-sm">
            <span
              aria-hidden="true"
              className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-xs font-semibold"
              style={{
                borderColor: s.done === true ? 'var(--astra-success)' : 'var(--astra-rule-strong)',
                color: s.done === true ? 'var(--astra-success)' : 'var(--astra-text-muted)',
              }}
            >
              {s.done === true ? '✓' : i + 1}
            </span>
            <span className={s.done === true ? 'text-[color:var(--astra-text-muted)]' : 'text-[color:var(--astra-ink)]'}>
              {t(`onboarding.step_${s.id}`)}
            </span>
            {s.done !== true && (
              <a
                href={`#${s.page}`}
                className="ms-auto text-xs font-medium underline decoration-dotted underline-offset-4 hover:text-[color:var(--astra-action)]"
              >
                {t('onboarding.go')}
              </a>
            )}
          </li>
        ))}
      </ol>
      <p className="text-xs text-[color:var(--astra-text-muted)]">{t('onboarding.hint')}</p>
    </section>
  )
}
