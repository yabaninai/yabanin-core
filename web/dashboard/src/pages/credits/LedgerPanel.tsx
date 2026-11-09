import { useTranslation } from 'react-i18next'

import type { CreditsLedgerView } from '../../api/currencies'
import { MetricStrip } from '../../components/astra/MetricStrip'
import { StateNotice } from '../../components/astra/StateNotice'
import { formatMoney, formatNumber, formatDateTime } from '../../i18n/format'

// Currencies UI slice 4 (brief 2026-11-02 §6.3): the ledger audit view —
// GET /api/credits/ledger. This panel is the RECONCILIATION surface: the
// running wallet above answers "what can this org spend"; this answers
// "do the books add up". It is read-only; top-ups and usage rows come from
// the gateway, not from here.
//
// Honesty rules:
//  - ledger_consistent is the SERVER's verdict, rendered verbatim as a
//    state: false is an error notice (wallet ≠ ledger sum — a real defect,
//    never softened), null/absent is "not reported" (muted), never ok;
//  - transaction_count is the server's full count; the table above shows
//    the newest `limit` rows — the panel says both, never one pretending
//    to be the other;
//  - starter_grant renders claimed/unclaimed with the configured amount —
//    an unclaimed grant is not free money on screen;
//  - credits_scale renders verbatim (the unit story for every cents number).

export function LedgerPanel({ ledger, currency, timezone }: {
  ledger: CreditsLedgerView
  currency: string | undefined
  timezone: string | undefined
}) {
  const { t } = useTranslation()
  const consistent = ledger.ledger_consistent
  const grant = ledger.starter_grant

  return (
    <section aria-labelledby="credits-ledger-title" className="flex flex-col gap-3">
      <h2 id="credits-ledger-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">
        {t('credits.ledger.title')}
      </h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('credits.ledger.purpose')}</p>

      {consistent === false && (
        <StateNotice
          state="error"
          title={t('credits.ledger.inconsistentTitle')}
          message={t('credits.ledger.inconsistentMessage', {
            wallet: formatMoney((ledger.wallet?.balance_cents ?? 0) / 100, currency),
            sum: formatMoney(ledger.ledger_sum_cents / 100, currency),
          })}
        />
      )}

      <MetricStrip
        aria-label={t('credits.ledger.title')}
        metrics={[
          {
            label: t('credits.ledger.sum'),
            value: formatMoney(ledger.ledger_sum_cents / 100, currency),
            unit: 'USD',
            source: t('credits.ledger.sumSource', { cents: formatNumber(ledger.ledger_sum_cents) }),
            state: consistent === false ? 'error' : 'ok',
          },
          {
            label: t('credits.ledger.transactions'),
            value: formatNumber(ledger.transaction_count),
            source: ledger.transactions.length < ledger.transaction_count
              ? t('credits.ledger.rowsShown', { shown: formatNumber(ledger.transactions.length) })
              : undefined,
            state: 'ok',
          },
          {
            label: t('credits.ledger.verdict'),
            value: consistent === true
              ? t('credits.ledger.consistent')
              : consistent === false
                ? t('credits.ledger.inconsistent')
                : t('credits.ledger.notReported'),
            state: consistent === true ? 'ok' : consistent === false ? 'error' : 'unknown',
          },
        ]}
      />

      <div className="astra-panel flex flex-col gap-2 p-4 text-sm">
        {ledger.wallet && (
          <p data-testid="ledger-wallet">
            <span className="text-[color:var(--astra-text-muted)]">{t('credits.ledger.wallet')}: </span>
            <span style={{ fontVariantNumeric: 'tabular-nums' }}>
              {formatMoney(ledger.wallet.balance_cents / 100, currency)}
            </span>
            <span className="text-[color:var(--astra-text-muted)]">
              {' '}{t('credits.ledger.updated', { at: formatDateTime(ledger.wallet.updated_at, timezone) })}
            </span>
          </p>
        )}
        {grant && (
          <p data-testid="ledger-grant">
            <span className="text-[color:var(--astra-text-muted)]">{t('credits.ledger.starterGrant')}: </span>
            {grant.claimed
              ? t('credits.ledger.grantClaimed', { amount: formatMoney(grant.claimed_cents / 100, currency) })
              : t('credits.ledger.grantUnclaimed', { amount: formatMoney(grant.configured_cents / 100, currency) })}
          </p>
        )}
        {/* credits_scale: verbatim server caption — the cents→money story. */}
        <p className="text-xs text-[color:var(--astra-text-muted)]" data-testid="ledger-credits-scale">
          {ledger.credits_scale}
        </p>
      </div>
    </section>
  )
}
