import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/transport'
import { getRatesCatalog, type RatesCatalog, type RefModelEntry } from '../api/currencies'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { IdChip } from '../components/astra/IdChip'
import { usePermissions } from '../hooks/usePermissions'
import { useTableUrlState } from '../hooks/useTableUrlState'
import { formatDateTime, formatNumber } from '../i18n/format'
import { RatesPromotionSection } from './RatesPromotionSection'

// Currencies UI slice 2 (brief 2026-11-02 §6.1): read-only view of the
// committed reference rates catalog — the pricing every gateway request is
// priced with. Session-scoped: ANY authenticated admin session may read it
// (no org gate, no store dependency — handler reads the sealed snapshot), so
// the page has no org picker and no permission gating; the server arbitrates.
//
// The citation (version + digest + provenance + notices) is the audit anchor:
// the digest renders copyable (IdChip copies the full value).
//
// Slice 5 adds the root-only promotion workflow (diff → mandatory reason →
// promote) BELOW the catalog. The catalog view itself stays read-only; the
// mutation surface is confined to RatesPromotionSection, mounted only for
// root sessions (fail-open when /me cannot answer — the server arbitrates).

export function RatesPage() {
  const { t } = useTranslation()
  const perms = usePermissions()
  const [catalog, setCatalog] = useState<RatesCatalog | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(true)
  const { page, setPage, sort, setSort } = useTableUrlState('rates-models', {})

  const load = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    try {
      const cat = await getRatesCatalog({ signal })
      setCatalog(cat)
      setError(null)
    } catch (e) {
      if (signal?.aborted || (e as { name?: string })?.name === 'AbortError') return
      setCatalog(null)
      setError(e instanceof ApiError ? e : null)
    } finally {
      if (!signal?.aborted) setLoading(false)
    }
  }, [])

  useEffect(() => {
    const ctrl = new AbortController()
    void load(ctrl.signal)
    return () => { ctrl.abort() }
  }, [load])

  const columns: DataTableColumn<RefModelEntry>[] = [
    {
      key: 'provider',
      header: t('rates.colProvider'),
      type: 'text',
      render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.provider}</span>,
    },
    {
      key: 'model',
      header: t('rates.colModel'),
      type: 'text',
      render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.model}</span>,
    },
    {
      key: 'aliases',
      header: t('rates.colAliases'),
      type: 'text',
      getSortValue: r => (r.aliases ?? []).join(','),
      render: r => r.aliases?.length
        ? <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.aliases.join(', ')}</span>
        : <span className="text-[color:var(--astra-text-muted)]">—</span>,
    },
    {
      key: 'region',
      header: t('rates.colRegion'),
      type: 'text',
      render: r => r.region || <span className="text-[color:var(--astra-text-muted)]">—</span>,
    },
    {
      key: 'tier',
      header: t('rates.colTier'),
      type: 'text',
      render: r => r.tier || <span className="text-[color:var(--astra-text-muted)]">—</span>,
    },
    {
      key: 'currency',
      header: t('rates.colCurrency'),
      type: 'text',
      render: r => <span className="whitespace-nowrap">{r.currency}</span>,
    },
    {
      key: 'rates',
      header: t('rates.colRates'),
      type: 'number',
      align: 'right',
      getSortValue: r => r.rates?.length ?? 0,
      render: r => <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatNumber(r.rates?.length ?? 0)}</span>,
    },
    {
      key: 'effective',
      header: t('rates.colEffective'),
      type: 'text',
      getSortValue: r => r.effective_from ?? '',
      render: r => (
        <span className="whitespace-nowrap text-xs" style={{ fontVariantNumeric: 'tabular-nums' }}>
          {r.effective_from || '…'} → {r.effective_to || '…'}
        </span>
      ),
    },
    {
      key: 'verified',
      header: t('rates.colVerified'),
      type: 'text',
      getSortValue: r => r.verified_at ?? '',
      render: r => r.verified_at
        ? <span className="whitespace-nowrap" style={{ fontVariantNumeric: 'tabular-nums' }}>{r.verified_at}</span>
        : <span className="text-[color:var(--astra-text-muted)]">—</span>,
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader title={t('rates.title')} purpose={t('rates.purpose')} />

      {loading && !catalog && <StateNotice state="loading" />}

      {!loading && !catalog && !error && (
        <StateNotice state="empty" message={t('rates.notAvailable')} />
      )}

      {/* 501 = the deployment predates the currencies program — that is a
          different answer from "failed to load", and it must not render a
          fake empty catalog. */}
      {error?.status === 501 && (
        <StateNotice state="empty" message={t('rates.notAvailable')} />
      )}

      {error && error.status !== 501 && (
        error.status === 401 || error.status === 403 ? (
          <StateNotice
            state="error"
            title={t('states.failedToLoad')}
            message={t('rates.sessionRequired')}
            action={{ label: t('common.retry'), onClick: () => void load() }}
          />
        ) : (
          <StateNotice
            state="error"
            title={t('states.failedToLoad')}
            message={error.message || t('rates.loadFailed')}
            action={{ label: t('common.retry'), onClick: () => void load() }}
          />
        )
      )}

      {catalog && (
        <>
          {catalog.ref.notices?.length > 0 && (
            <StateNotice
              state="warning"
              title={t('rates.notices')}
              message={catalog.ref.notices.join(' · ')}
            />
          )}

          <section aria-labelledby="rates-citation-title" className="astra-panel flex flex-col gap-3 p-4">
            <h2 id="rates-citation-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">
              {t('rates.citation')}
            </h2>
            <div className="grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
              <p>
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.version')}: </span>
                <span className="font-medium" style={{ fontFamily: 'var(--astra-font-code)' }}>{catalog.ref.version}</span>
              </p>
              <p>
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.generated')}: </span>
                <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatDateTime(catalog.ref.generated_at, undefined)}</span>
              </p>
              <p className="flex flex-wrap items-center gap-2">
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.digest')}: </span>
                <IdChip value={catalog.ref.digest} label={t('rates.copyDigest')} />
              </p>
              <p className="flex flex-wrap items-center gap-2">
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.packDigest')}: </span>
                <IdChip value={catalog.ref.pack_digest} label={t('rates.copyDigest')} />
              </p>
              <p>
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.reviewSla')}: </span>
                <span style={{ fontVariantNumeric: 'tabular-nums' }}>
                  {catalog.ref.review_sla_days > 0
                    ? t('rates.slaDays', { days: formatNumber(catalog.ref.review_sla_days) })
                    : '—'}
                </span>
              </p>
              <p className="min-w-0">
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.provenance')}: </span>
                <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{catalog.ref.provenance || '—'}</span>
              </p>
              <p>
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.schema')}: </span>
                <span style={{ fontVariantNumeric: 'tabular-nums' }}>{formatNumber(catalog.catalog.schema_version)}</span>
              </p>
              <p className="min-w-0">
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.source')}: </span>
                <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{catalog.catalog.source || '—'}</span>
              </p>
              <p>
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.reviewer')}: </span>
                {catalog.catalog.reviewer || <span className="text-[color:var(--astra-text-muted)]">—</span>}
              </p>
              <p className="flex flex-wrap items-center gap-2">
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.supersedes')}: </span>
                {catalog.catalog.supersedes
                  ? <IdChip value={catalog.catalog.supersedes} label={t('rates.copyDigest')} />
                  : <span className="text-[color:var(--astra-text-muted)]">—</span>}
              </p>
              <p>
                <span className="text-[color:var(--astra-text-muted)]">{t('rates.models')}: </span>
                <span className="font-medium" style={{ fontVariantNumeric: 'tabular-nums' }}>
                  {t('rates.modelsCount', { count: formatNumber(catalog.catalog.models.length) })}
                </span>
              </p>
            </div>
          </section>

          <section aria-labelledby="rates-entries-title" className="flex flex-col gap-3">
            <h2 id="rates-entries-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">
              {t('rates.entriesTitle')}
            </h2>
            <p className="text-sm text-[color:var(--astra-text-muted)]">{t('rates.entriesNote')}</p>
            <DataTable
              columns={columns}
              rows={catalog.catalog.models}
              getRowId={r => `${r.provider}/${r.model}${r.region ? `@${r.region}` : ''}${r.tier ? `+${r.tier}` : ''}${r.context_band ? `~${r.context_band}` : ''}`}
              loading={false}
              empty={t('rates.emptyModels')}
              page={page}
              pageSize={25}
              onPageChange={setPage}
              sort={sort}
              onSortChange={setSort}
              sortMode="client"
              caption={t('rates.caption')}
            />
          </section>

          {/* Root-only promotion workflow (slice 5). Fail-open when /me
              cannot answer (me === null after load): the controls render and
              the server arbitrates — same doctrine as the BudgetsPage gates.
              A known non-root session never sees the controls at all. */}
          {!perms.loading && (perms.isRoot || perms.me === null) && (
            <RatesPromotionSection onPromoted={() => void load()} />
          )}
        </>
      )}
    </div>
  )
}
