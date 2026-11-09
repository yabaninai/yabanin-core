import { useTranslation } from 'react-i18next'
import {
  EXPECTED_API_LEVEL,
  useServerVersion,
  versionBanner,
} from '../../hooks/useServerVersion'

// (the decision comes from useServerVersion/versionBanner). It renders only
// for the two card triggers: the server's api_level is below this build's
// expectation, or /api/version answered 404 (the server predates the
// handshake) — in both cases part of the newer dashboard's screens may not
// work against the older admin API.
//
// Warning semantics never ride on color alone: the △ glyph and the text
// label carry the state (StateNotice convention). The band is not
// dismissible — it states a build-level incompatibility that stays true for
// the whole session (the handshake answer is cached; a reload refetches).

export function VersionBanner() {
  const { t } = useTranslation()
  const banner = versionBanner(useServerVersion())
  if (!banner) return null
  return (
    <div
      role="status"
      data-testid="version-banner"
      className="border-b px-4 py-2 md:px-6"
      style={{ borderColor: 'var(--astra-warning)', backgroundColor: 'var(--astra-warning-surface)' }}
    >
      <p className="flex items-start gap-2 text-sm font-medium text-[color:var(--astra-ink)]">
        <span aria-hidden="true" className="shrink-0" style={{ color: 'var(--astra-warning)' }}>
          △
        </span>
        <span>{t('versionBanner.title')}</span>
      </p>
      <p
        className="ps-6 text-sm text-[color:var(--astra-text-muted)]"
        style={{ overflowWrap: 'anywhere' }}
      >
        {banner.server
          ? t('versionBanner.details', {
              version: banner.server.version,
              commit: banner.server.commit,
              serverLevel: banner.server.api_level,
              expectedLevel: EXPECTED_API_LEVEL,
            })
          : t('versionBanner.unavailable')}
      </p>
    </div>
  )
}
