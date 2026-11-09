import { useTranslation } from 'react-i18next'
import { GitBranch, PackageSearch, ShieldAlert, Tags, type LucideIcon } from 'lucide-react'
import { usePermissions } from '../hooks/usePermissions'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import {
  guardrailsCardOpenable, guardrailsLockReasonKey, guardrailsLockReasonParams,
  type GuardrailsAccess,
} from './guardrailsModel'

// summary screen that links the existing policy screens — not a rename, not
// a nav group. The screens stay where they are; this page only composes
// read-only link cards to them and names who can open each one.
//
// Honesty contract:
// - No data fetching, no counts, no status badges: the page would either
//   have to duplicate the target screens' gates per-endpoint or show stale
//   fabricated numbers, so it reads nothing at all (0 API calls; pinned by
//   GuardrailsPage.test.ts).
// - Every card mirrors the target screen's NAV_SECTIONS gate (App.tsx) and
//   is pinned against it by the unit test. Cards the caller cannot open use
//   hint — the reason names the missing right, the hint says where to get it.
// - The screen itself is nav-gated at the floor of its links' gates
//   (label-policy's analytics.read): whoever sees the summary can open at
//   least one card; a viewer who can open none never sees the nav entry.
//   A deep link still renders (the server stays the arbiter behind every
//   link) and shows the honest "nothing openable" state below.
//
// documented fail-open when it failed, root bypass) lives in
// guardrailsModel.ts so the ordering is executable under the node harness
// (guardrailsModel.test.ts pins latency/failure/deep-link-403); this page
// only feeds it the usePermissions slice and renders the verdict.

interface Surface {
  id: string
  icon: LucideIcon
  /** The target screen's nav labelKey — the card title is the nav label. */
  titleKey: string
  descKey: string
  /** The server-side gate the target screen's data sits behind (App.tsx). */
  access: { rootOnly?: boolean; anyOrg?: string[] }
}

// Routing Rules, Label Policy. Order follows the nav table's policy section.
const SURFACES: Surface[] = [
  {
    id: 'tool-policy',
    icon: ShieldAlert,
    titleKey: 'app.navToolPolicy',
    descKey: 'guardrails.toolPolicyDesc',
    access: { rootOnly: true },
  },
  {
    id: 'rules',
    icon: GitBranch,
    titleKey: 'app.navRoutingRules',
    descKey: 'guardrails.rulesDesc',
    access: { rootOnly: true },
  },
  {
    id: 'label-policy',
    icon: Tags,
    titleKey: 'app.navLabelPolicy',
    descKey: 'guardrails.labelPolicyDesc',
    access: { anyOrg: ['analytics.read'] },
  },
  // N02-P08: the detector-pack lifecycle screen (root-only guard mount).
  {
    id: 'guard-packs',
    icon: PackageSearch,
    titleKey: 'app.navGuardPacks',
    descKey: 'guardrails.packsDesc',
    access: { rootOnly: true },
  },
]

export function GuardrailsPage() {
  const { t } = useTranslation()
  const perms = usePermissions()

  // The gate decision is delegated to the pinned model (guardrailsModel.test
  // exercises the exact ordering): locked cards persist while /api/me is in
  // flight (no flicker-to-open), a failed /api/me degrades to the documented
  // fail-open, and the server stays the arbiter behind every link.
  const permsView = {
    loading: perms.loading,
    hasIdentity: perms.me !== null,
    isRoot: perms.isRoot,
    canAnyOrg: perms.canAnyOrg,
  }
  const openable = (access: GuardrailsAccess): boolean =>
    guardrailsCardOpenable(access, permsView)

  const openCount = SURFACES.filter(s => openable(s.access)).length

  return (
    <div className="space-y-6">
      <PageHeader title={t('guardrails.title')} purpose={t('guardrails.purpose')} />

      <p className="max-w-3xl text-sm text-[color:var(--astra-text-muted)]">{t('guardrails.intro')}</p>

      <section aria-labelledby="guardrails-surfaces" className="space-y-3">
        <h2 id="guardrails-surfaces" className="text-base font-semibold text-[color:var(--astra-ink)]">
          {t('guardrails.surfacesTitle')}
        </h2>
        {openCount === 0 && (
          <StateNotice state="empty" message={t('guardrails.noneVisible')} />
        )}
        <div className="grid min-w-0 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {SURFACES.map(s => {
            const Icon = s.icon
            if (openable(s.access)) {
              return (
                <a
                  key={s.id}
                  href={`#${s.id}`}
                  data-testid={`guardrails-link-${s.id}`}
                  className="astra-panel flex min-w-0 flex-col gap-2 px-4 py-4 no-underline transition-colors hover:border-[color:var(--astra-rule-strong)]"
                >
                  <span className="flex items-center gap-2 text-base font-semibold text-[color:var(--astra-ink)]">
                    <Icon size={16} aria-hidden="true" />
                    {t(s.titleKey)}
                  </span>
                  <span className="text-sm text-[color:var(--astra-text-muted)]">{t(s.descKey)}</span>
                  <span className="mt-auto pt-1 text-sm font-medium text-[color:var(--astra-ink)]">
                    {t('guardrails.openScreen')} →
                  </span>
                </a>
              )
            }
            // link, never a bare disable without the why).
            return (
              <div
                key={s.id}
                data-testid={`guardrails-locked-${s.id}`}
                className="astra-panel flex min-w-0 flex-col gap-2 px-4 py-4"
              >
                <span className="flex items-center gap-2 text-base font-semibold text-[color:var(--astra-text-muted)]">
                  <Icon size={16} aria-hidden="true" />
                  {t(s.titleKey)}
                </span>
                <span className="text-sm text-[color:var(--astra-text-muted)]">{t(s.descKey)}</span>
                <span className="text-sm font-medium text-[color:var(--astra-ink)]">
                  {t(guardrailsLockReasonKey(s.access), guardrailsLockReasonParams(s.access))}
                </span>
                <span className="text-sm text-[color:var(--astra-text-muted)]">{t('guardrails.lockedHint')}</span>
              </div>
            )
          })}
        </div>
      </section>
    </div>
  )
}
