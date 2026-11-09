import { useTranslation } from 'react-i18next'
import { useOrgs } from '../../i18n/useOrgPresentation'

// «страница v2» item 1: the operator sees the organization, not a UUID).
// Backed by the shared org-list cache (UI-VF-1), so a screen full of rows
// costs one request. Until the list loads — or when the id is unknown — the
// raw id shows in its place (honest fallback, never an invented name).

export function OrgName({ orgId }: { orgId?: string | null }) {
  const { t } = useTranslation()
  const { orgs } = useOrgs()
  if (!orgId) return <span title={t('common.unknown')}>{t('common.unknown')}</span>
  const org = orgs?.find(o => o.id === orgId || o.slug === orgId)
  if (org) {
    return (
      <span className="min-w-0" title={orgId}>
        <span className="block truncate">{org.name}</span>
      </span>
    )
  }
  return (
    <span
      className="min-w-0 truncate"
      title={orgId}
      style={{ fontFamily: 'var(--astra-font-code)', fontVariantNumeric: 'tabular-nums' }}
    >
      {orgId}
    </span>
  )
}
