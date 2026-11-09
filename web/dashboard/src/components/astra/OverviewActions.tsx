import { ArrowUpRight, FileSearch, KeyRound, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { usePermissions } from '../../hooks/usePermissions'
import { actionHref, ERRORS_ONLY_YQL } from '../../lib/commandPalette'

/** Short paths to existing workflows, scoped to the selected organization. */
export function OverviewActions({ org, from, to }: { org: string; from: string; to: string }) {
  const { t } = useTranslation()
  const perms = usePermissions(org || undefined)
  const actions = [
    {
      visible: perms.can('requests.read'),
      href: actionHref('requests-explorer', { org, from, to, query: ERRORS_ONLY_YQL }),
      label: t('overview.actionErrors'),
      hint: t('overview.actionErrorsHint'),
      icon: <FileSearch size={18} aria-hidden="true" />,
    },
    {
      visible: perms.can('policies.manage'),
      href: actionHref('policy-decisions', { org }),
      label: t('overview.actionDecisions'),
      hint: t('overview.actionDecisionsHint'),
      icon: <ShieldCheck size={18} aria-hidden="true" />,
    },
    {
      visible: perms.can('keys.manage') || perms.can('agent_keys.manage'),
      href: actionHref('keys', { org }),
      label: t('overview.actionAccess'),
      hint: t('overview.actionAccessHint'),
      icon: <KeyRound size={18} aria-hidden="true" />,
    },
  ].filter(action => action.visible)

  if (perms.loading || (org && actions.length === 0)) return null
  return (
    <section aria-label={t('overview.quickActions')} className="astra-panel min-w-0 p-4">
      <h2 className="text-base font-semibold">{t('overview.quickActions')}</h2>
      {!org ? (
        <p className="mt-2 text-sm text-[color:var(--astra-text-muted)]">{t('overview.actionsNeedOrg')}</p>
      ) : (
        <div className="mt-2 divide-y divide-[color:var(--astra-rule)]">
          {actions.map(action => (
            <a key={action.href} href={action.href} className="flex min-h-[44px] items-start gap-3 rounded-[length:var(--astra-radius-control)] px-2 py-3 text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]">
              <span className="mt-0.5 shrink-0 text-[color:var(--astra-accent)]">{action.icon}</span>
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium">{action.label}</span>
                <span className="mt-1 block text-xs text-[color:var(--astra-text-muted)]">{action.hint}</span>
              </span>
              <ArrowUpRight size={16} className="mt-0.5 shrink-0 rtl:-scale-x-100" aria-hidden="true" />
            </a>
          ))}
        </div>
      )}
    </section>
  )
}
