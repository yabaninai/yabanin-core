import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { fetchCreditBalance, fetchCreditTransactions, type CreditBalance, type CreditTransaction } from '../api/client'
import { getCreditsLedger, type CreditsLedgerView } from '../api/currencies'
import { ApiError } from '../api/transport'
import { LedgerPanel } from './credits/LedgerPanel'
import { OrgSelect } from '../components/OrgSelect'
import { PageHeader } from '../components/astra/PageHeader'
import { MetricStrip } from '../components/astra/MetricStrip'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { formatMoney, formatDateTime } from '../i18n/format'
import { useOrgPresentation } from '../i18n/useOrgPresentation'


export function CreditsPage() {
  const { t } = useTranslation()
  const [orgId, setOrgId] = useState('')
  const { currency, timezone } = useOrgPresentation(orgId.trim() || undefined)
  const [balance, setBalance] = useState<CreditBalance | null>(null)
  const [txns, setTxns] = useState<CreditTransaction[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  // Currencies slice 4: the ledger audit view rides the same applied-org
  // generation as the wallet. A ledger failure must NOT break the wallet
  // surface (and vice versa): it settles into its own notice.
  const [ledger, setLedger] = useState<CreditsLedgerView | null>(null)
  const [ledgerNotDeployed, setLedgerNotDeployed] = useState(false)
  const [ledgerError, setLedgerError] = useState('')

  // UX-03: auto-load — the org input commits after a 300ms debounce (Enter
  // still loads immediately); no Load button, Retry stays on the error notice.
  // Stale-fetch safety (U07): a newer org's load aborts the previous
  // in-flight one, so a slow response for org A cannot clobber org B.
  //
  // UI-01 (audit addendum): the displayed balance/transactions belong to
  // exactly one applied org. Every load carries a generation; only the
  // newest generation may write state (an aborted org-A load can neither
  // settle its loading flag nor surface A's rows after org B took over),
  // and switching or clearing the org drops the previous org's data BEFORE
  // the new fetch — A's wallet must not survive a delayed, failed, or empty
  // load of org B. A same-org reload keeps the old data labeled by its load.
  const loadAbort = useRef<AbortController | null>(null)
  const loadGen = useRef(0)
  const dataOrg = useRef('') // org the displayed balance/txns belong to ('' = none)
  const handleLoad = useCallback(async () => {
    const org = orgId.trim()
    if (!org) {
      // org cleared: settle back to the not-loaded state, never keep the
      // previous org's wallet on screen
      loadGen.current++
      loadAbort.current?.abort()
      setBalance(null)
      setTxns([])
      setError('')
      setLoading(false)
      setLedger(null)
      setLedgerNotDeployed(false)
      setLedgerError('')
      dataOrg.current = ''
      return
    }
    const gen = ++loadGen.current
    if (dataOrg.current !== org) {
      // switching orgs: the previous org's data is not a preview of the
      // new one — drop it up front, before the fetch resolves or fails
      setBalance(null)
      setTxns([])
      setLedger(null)
      setLedgerNotDeployed(false)
      setLedgerError('')
      dataOrg.current = ''
    }
    loadAbort.current?.abort()
    const ctrl = new AbortController()
    loadAbort.current = ctrl
    setLoading(true)
    setError('')
    setLedgerNotDeployed(false)
    setLedgerError('')
    // The ledger is a separate surface with its own honesty contract: it
    // cannot fail the wallet load, and its own failures are its own states.
    void getCreditsLedger(org, 50, { signal: ctrl.signal })
      .then(view => {
        if (gen !== loadGen.current) return
        setLedger(view)
      })
      .catch((e: unknown) => {
        if (gen !== loadGen.current) return
        if (e instanceof DOMException && e.name === 'AbortError') return
        setLedger(null)
        if (e instanceof ApiError && e.status === 501) setLedgerNotDeployed(true)
        else setLedgerError(e instanceof Error ? e.message : String(e))
      })
    try {
      const [bal, txnResp] = await Promise.all([
        fetchCreditBalance(org, { signal: ctrl.signal }),
        fetchCreditTransactions(org, 50, { signal: ctrl.signal }),
      ])
      if (gen !== loadGen.current) return // superseded: a newer org owns the screen
      setBalance(bal)
      setTxns(txnResp.txns)
      dataOrg.current = org
    } catch (e: unknown) {
      if (gen !== loadGen.current) return // superseded failure stays silent
      if (!(e instanceof DOMException && e.name === 'AbortError')) {
        setError(e instanceof Error ? e.message : String(e))
      }
    } finally {
      // only the newest load may settle the loading flag: an aborted org-A
      // completion must not flip loading off while org B is still in flight
      if (gen === loadGen.current) setLoading(false)
    }
  }, [orgId])

  useEffect(() => {
    if (!orgId.trim()) return
    const timer = setTimeout(() => { void handleLoad() }, 300)
    return () => { clearTimeout(timer); loadAbort.current?.abort() }
  }, [handleLoad, orgId])

  const balanceDollars = balance ? balance.balance_cents / 100 : 0
  const isLow = balance && balance.balance_cents < 500
  const isCritical = balance && balance.balance_cents <= -100

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('credits.title')}
        purpose={t('credits.purpose')}
      />

      {/* Org scope — UI-VF-1: OrgSelect picker instead of a hand-copied UUID;
          autoSelect pre-commits the last-used or first org so the balance
          loads on arrival. The debounced effect still drives the fetches. */}
      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1 text-sm">
          <span className="text-[color:var(--astra-text-muted)]">{t('credits.orgId')}</span>
          <OrgSelect
            value={orgId}
            onChange={setOrgId}
            autoSelect
            className="sm:w-72"
            manualAriaLabel={t('credits.orgUuid')}
          />
        </label>
      </div>

      {error && <StateNotice state="error" message={error} action={{ label: t('common.retry'), onClick: () => void handleLoad() }} />}

      {loading && !error && <StateNotice state="loading" />}

      {/* Balance */}
      {balance && (
        <div className="flex flex-col gap-3">
            <MetricStrip
              aria-label={t('credits.title')}
              metrics={[
                {
                  label: t('credits.availableBalance'),
                  value: formatMoney(balanceDollars, currency),
                  unit: 'USD',
                  source: t('credits.sourceCentsUpdated', {
                    cents: balance.balance_cents,
                    updated: formatDateTime(balance.updated_at, timezone),
                  }),
                  state: isCritical ? 'error' : isLow ? 'warning' : 'ok',
                },
              ]}
            />
            {isCritical && (
              <StateNotice state="error" title={t('credits.overdraft')} message={t('credits.overdraftMessage')} />
            )}
            {isLow && !isCritical && (
              <StateNotice state="warning" title={t('credits.lowBalance')} message={t('credits.lowBalanceMessage')} />
            )}

          {/* Top up CTA */}
          <div className="card text-sm">
            <p className="text-[color:var(--astra-ink)]">
              {t('credits.topUpIntro')}
            </p>
            <ul className="mt-1 text-xs text-[color:var(--astra-text-muted)] list-disc list-inside space-y-0.5">
              <li>{t('credits.topUpAmount')}</li>
              <li>{t('credits.topUpReference')}</li>
            </ul>
          </div>
        </div>
      )}

      {/* Transaction history — UI-01: an empty history renders as an explicit
          empty state only after the load settled for this org (zero rows is a
          real answer, not a missing table) */}
      {txns.length > 0 && (
        <CreditTransactions txns={txns} currency={currency} timezone={timezone} />
      )}
      {balance && !loading && !error && txns.length === 0 && (
        <StateNotice state="empty" message={t('credits.noTransactions')} />
      )}

      {ledgerNotDeployed && !loading && (
        <StateNotice state="empty" message={t('credits.ledger.notDeployed')} />
      )}
      {ledgerError && !loading && (
        <StateNotice
          state="error"
          title={t('credits.ledger.loadFailedTitle')}
          message={ledgerError}
          action={{ label: t('common.retry'), onClick: () => void handleLoad() }}
        />
      )}
      {ledger && <LedgerPanel ledger={ledger} currency={currency} timezone={timezone} />}

      {!balance && !loading && !error && (
        <StateNotice state="not-loaded" message={t('credits.notLoaded')} />
      )}
    </div>
  )
}

// AUX-03: the transaction history runs on DataTable v2 (client mode) —
// time sorts chronologically, amounts by cent value; newest first by default.
function CreditTransactions({ txns, currency, timezone }: { txns: CreditTransaction[]; currency: string; timezone: string | undefined }) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const columns: DataTableColumn<CreditTransaction>[] = [
    {
      key: 'created_at',
      header: t('credits.time'),
      type: 'date',
      render: txn => (
        <span className="whitespace-nowrap text-[color:var(--astra-text-muted)]" style={{ fontVariantNumeric: 'tabular-nums' }}>
          {formatDateTime(txn.created_at, timezone)}
        </span>
      ),
    },
    {
      key: 'type',
      header: t('credits.type'),
      type: 'text',
      getSortValue: txn => txn.type,
      render: txn => (
        <span className="inline-flex items-center rounded-[length:var(--astra-radius-control)] border px-2 py-0.5 text-xs font-medium"
          style={
            txn.type === 'topup'
              ? { borderColor: 'var(--astra-success)', color: 'var(--astra-success)', background: 'var(--astra-success-surface)' }
              : { borderColor: 'var(--astra-info)', color: 'var(--astra-info)', background: 'var(--astra-info-surface)' }
          }
        >
          {txn.type === 'topup' ? t('credits.topUp') : t('credits.usage')}
        </span>
      ),
    },
    {
      key: 'model',
      header: t('credits.model'),
      type: 'text',
      sortable: false,
      getSortValue: txn => ((txn.metadata as Record<string, unknown>)?.model as string | undefined) ?? null,
      render: txn => (
        <span className="text-[color:var(--astra-text-muted)]">
          {(txn.metadata as Record<string, unknown>)?.model as string || '—'}
        </span>
      ),
    },
    {
      key: 'amount_cents',
      header: t('credits.amount'),
      type: 'money',
      unit: 'USD',
      align: 'right',
      render: txn => (
        <span className="font-medium" style={{ color: txn.amount_cents >= 0 ? 'var(--astra-success)' : 'var(--astra-danger)', fontVariantNumeric: 'tabular-nums' }}>
          {txn.amount_cents >= 0 ? '+' : ''}{formatMoney(txn.amount_cents / 100, currency)}
        </span>
      ),
    },
    {
      key: 'balance_after',
      header: t('credits.balanceAfter'),
      type: 'money',
      unit: 'USD',
      align: 'right',
      render: txn => (
        <span className="text-[color:var(--astra-text-muted)]" style={{ fontVariantNumeric: 'tabular-nums' }}>
          {formatMoney(txn.balance_after / 100, currency)}
        </span>
      ),
    },
  ]
  return (
    <div className="astra-panel overflow-hidden py-4">
      <h2 className="px-6 pb-2 text-lg font-semibold text-[color:var(--astra-ink)]">{t('credits.recentTransactions')}</h2>
      <div className="px-6">
        <DataTable
          columns={columns}
          rows={txns}
          getRowId={txn => String(txn.id)}
          page={page}
          pageSize={50}
          onPageChange={setPage}
          defaultSort={{ key: 'created_at', dir: 'desc' }}
          caption={t('credits.recentTransactions')}
        />
      </div>
    </div>
  )
}
