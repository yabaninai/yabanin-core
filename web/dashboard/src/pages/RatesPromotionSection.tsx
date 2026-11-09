import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/transport'
import {
  diffRatesPack, parseRatesRefusal, promoteRatesPack,
  type RatesDiffReport, type RatesPromotion, type RatesRefusalEnvelope,
} from '../api/currencies'
import { IdChip } from '../components/astra/IdChip'
import { StateNotice } from '../components/astra/StateNotice'
import { formatNumber } from '../i18n/format'

// Currencies UI slice 5 (brief 2026-11-02 §6.3): the root-only rates
// promotion workflow — POST /api/rates/diff then POST /api/rates/promote.
// The page stays session-scoped for the catalog; ONLY this section is
// root-gated, mirroring the server (a non-root session never sees the
// controls — absent, not disabled — so no no-op buttons).
//
// Confirmation model: promote is a SECOND explicit step. The operator must
// first diff the pack (the report is rendered before anything is sent to
// promote), then type a MANDATORY reason, then press Promote. Buttons are
// disabled with reasons (empty pack, oversized pack, missing reason,
// server refusal, in-flight request) — never hidden no-ops.
//
// Honesty rules (brief §4):
//  - a 422 refusal is DATA: the refusal reason and the full report render;
//    Promote stays disabled after a refusal (the server will refuse again —
//    a retry button that re-sends a known-refused pack would be a fake
//    action);
//  - the request-body ceiling is enforced client-side as a guard AND
//    stated up front ("in this build" — it is a build property, not a pack
//    property; a middleware 403 is never blamed on pack content). Rates
//    routes carry a 16 MiB per-prefix ceiling (the sealed official pack is
//    ~2.6 MB); every other admin route keeps the global 1 MiB;
//  - the swap is durable: the promotion is recorded in the database, so
//    restarts keep it and every process serves it (each within its pricing
//    cache refresh window) — stated next to every applied result;
//  - 400 renders the operator-facing server text (bad pack / chain break /
//    unserveable / missing reason); 401/403 on diff/promote for a root
//    session means the session changed or the body limit — distinct copy.

/** The per-prefix middleware body ceiling for /api/rates/ routes
    (16 MiB, this build — room for the ~2.6 MB sealed official pack). */
export const RATES_PACK_BODY_LIMIT_BYTES = 16_777_216

type Phase = 'input' | 'review' | 'result'

export function RatesPromotionSection({ onPromoted }: { onPromoted: () => void }) {
  const { t } = useTranslation()
  const [phase, setPhase] = useState<Phase>('input')
  const [pack, setPack] = useState('')
  const [diffReason, setDiffReason] = useState('')
  const [promoteReason, setPromoteReason] = useState('')
  const [report, setReport] = useState<RatesDiffReport | null>(null)
  const [refusal, setRefusal] = useState<RatesRefusalEnvelope | null>(null)
  const [promo, setPromo] = useState<RatesPromotion | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [busy, setBusy] = useState<'diff' | 'promote' | null>(null)
  const fileRef = useRef<HTMLInputElement | null>(null)

  const packBytes = pack ? new TextEncoder().encode(pack).length : 0 // the middleware counts bytes, not chars
  const packTooLarge = packBytes > RATES_PACK_BODY_LIMIT_BYTES
  const canDiff = pack.trim().length > 0 && !packTooLarge && busy === null
  const canPromote = phase === 'review'
    && report !== null
    && !(refusal?.refused ?? false)
    && promoteReason.trim().length > 0
    && busy === null

  const runDiff = async () => {
    if (!canDiff) return
    setBusy('diff')
    setError(null)
    setRefusal(null)
    try {
      const r = await diffRatesPack(pack, diffReason.trim() || undefined)
      setReport(r)
      setPhase('review')
    } catch (e) {
      const env = parseRatesRefusal(e)
      if (env) {
        setRefusal(env)
        setReport(env.report)
        setPhase('review')
      } else {
        setError(e instanceof ApiError ? e : null)
      }
    } finally {
      setBusy(null)
    }
  }

  const runPromote = async () => {
    if (!canPromote) return
    setBusy('promote')
    setError(null)
    try {
      const p = await promoteRatesPack(pack, promoteReason.trim())
      setPromo(p)
      setPhase('result')
      onPromoted() // the committed catalog above is stale now — reload it
    } catch (e) {
      const env = parseRatesRefusal(e)
      if (env) {
        setRefusal(env)
        setReport(env.report)
      } else {
        setError(e instanceof ApiError ? e : null)
      }
    } finally {
      setBusy(null)
    }
  }

  const loadFile = async (file: File | undefined) => {
    if (!file) return
    setError(null)
    try {
      setPack(await file.text())
    } catch {
      setError(new ApiError(0, t('rates.promotion.fileReadFailed')))
    } finally {
      if (fileRef.current) fileRef.current.value = '' // same file can be re-picked
    }
  }

  const startOver = () => {
    setPhase('input')
    setReport(null)
    setRefusal(null)
    setPromo(null)
    setPromoteReason('')
    setError(null)
  }

  const renderError = () => {
    if (!error) return null
    const message = error.status === 401 || (error.status === 403 && !packTooLarge)
      ? t('rates.promotion.rootRequired')
      : error.status === 403 && packTooLarge
        ? t('rates.promotion.tooLarge')
        : error.status === 400
          ? error.message || t('rates.promotion.badRequest')
          : error.message || t('rates.promotion.loadFailed')
    return (
      <StateNotice
        state="error"
        title={t('states.failedToLoad')}
        message={message}
      />
    )
  }

  return (
    <section aria-labelledby="rates-promotion-title" className="astra-panel flex flex-col gap-3 p-4" data-testid="rates-promotion-section">
      <h2 id="rates-promotion-title" className="text-lg font-semibold text-[color:var(--astra-ink)]">
        {t('rates.promotion.title')}
      </h2>
      <p className="text-sm text-[color:var(--astra-text-muted)]">{t('rates.promotion.purpose')}</p>
      {/* Build property, stated up front — never blamed on a pack later. */}
      <p className="text-xs text-[color:var(--astra-text-muted)]">{t('rates.promotion.bodyLimit')}</p>

      {renderError()}

      {phase === 'input' && (
        <div className="flex flex-col gap-3" data-testid="rates-promotion-input">
          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-[color:var(--astra-ink)]">{t('rates.promotion.packLabel')}</span>
            <textarea
              className="input min-h-32 font-mono text-xs"
              style={{ fontFamily: 'var(--astra-font-code)' }}
              value={pack}
              onChange={(e) => setPack(e.target.value)}
              placeholder={t('rates.promotion.packPlaceholder')}
              aria-label={t('rates.promotion.packLabel')}
              spellCheck={false}
            />
          </label>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <label className="btn-secondary cursor-pointer">
              {t('rates.promotion.loadFile')}
              <input
                ref={fileRef}
                type="file"
                accept="application/json,.json"
                className="sr-only"
                onChange={(e) => void loadFile(e.target.files?.[0])}
              />
            </label>
            {packBytes > 0 && (
              <span className="text-xs text-[color:var(--astra-text-muted)]" style={{ fontVariantNumeric: 'tabular-nums' }}>
                {t('rates.promotion.packBytes', { count: formatNumber(packBytes) })}
              </span>
            )}
          </div>
          {packTooLarge && (
            <StateNotice state="error" message={t('rates.promotion.tooLarge')} />
          )}
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('rates.promotion.diffReasonLabel')}</span>
            <input
              type="text"
              className="input"
              value={diffReason}
              onChange={(e) => setDiffReason(e.target.value)}
              aria-label={t('rates.promotion.diffReasonLabel')}
            />
          </label>
          <div>
            <button type="button" className="btn-primary" disabled={!canDiff} onClick={() => void runDiff()}>
              {busy === 'diff' ? t('rates.promotion.diffBusy') : t('rates.promotion.diffButton')}
            </button>
            {pack.trim().length === 0 && (
              <p className="mt-1 text-xs text-[color:var(--astra-text-muted)]">{t('rates.promotion.needPack')}</p>
            )}
          </div>
        </div>
      )}

      {phase === 'review' && report && (
        <div className="flex flex-col gap-3" data-testid="rates-promotion-review">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('rates.promotion.from')} </span>
            <span style={{ fontFamily: 'var(--astra-font-code)' }}>{report.from.version}</span>
            <IdChip value={report.from.digest} />
            <span aria-hidden="true">→</span>
            <span className="text-[color:var(--astra-text-muted)]">{t('rates.promotion.to')} </span>
            <span style={{ fontFamily: 'var(--astra-font-code)' }}>{report.to.version}</span>
            <IdChip value={report.to.digest} />
          </div>

          <p className="text-sm" style={{ fontVariantNumeric: 'tabular-nums' }}>
            {t('rates.promotion.diffCounts', {
              added: formatNumber(report.added),
              removed: formatNumber(report.removed),
              changed: formatNumber(report.changed),
            })}
          </p>

          {report.review_needed && (
            <StateNotice state="warning" message={t('rates.promotion.reviewNeeded')} />
          )}

          {/* A refusal is data: the reason and the report both render; the
              promote button below stays disabled (retrying a refused pack
              is a fake action). */}
          {refusal?.refused && (
            <StateNotice
              state="error"
              title={t('rates.promotion.refusalTitle')}
              message={refusal.refusal_reason}
            />
          )}

          {report.flags.length > 0 && (
            <div className="text-xs text-[color:var(--astra-text-muted)]" data-testid="rates-promotion-flags">
              <p className="font-medium">{t('rates.promotion.flags')}</p>
              <ul className="list-disc ps-4">
                {report.flags.map((f, i) => (
                  <li key={`${f.kind}-${f.entry}-${i}`} style={{ fontFamily: 'var(--astra-font-code)' }}>
                    {f.kind}: {f.entry}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {report.rendered && (
            <details className="text-xs">
              <summary className="cursor-pointer text-[color:var(--astra-text-muted)]">{t('rates.promotion.renderTitle')}</summary>
              <pre className="mt-1 max-h-64 overflow-auto border border-[color:var(--astra-rule)] bg-[color:var(--astra-surface-muted)] p-2 text-xs" style={{ fontFamily: 'var(--astra-font-code)' }}>
                {report.rendered}
              </pre>
            </details>
          )}

          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium text-[color:var(--astra-ink)]">{t('rates.promotion.promoteReasonLabel')}</span>
            <input
              type="text"
              className="input"
              value={promoteReason}
              onChange={(e) => setPromoteReason(e.target.value)}
              aria-label={t('rates.promotion.promoteReasonLabel')}
              data-testid="rates-promotion-reason"
            />
          </label>
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" className="btn-primary" disabled={!canPromote} onClick={() => void runPromote()}>
              {busy === 'promote' ? t('rates.promotion.promoteBusy') : t('rates.promotion.promoteButton')}
            </button>
            <button type="button" className="btn-secondary" disabled={busy !== null} onClick={startOver}>
              {t('rates.promotion.backToEdit')}
            </button>
            {promoteReason.trim().length === 0 && (
              <p className="text-xs text-[color:var(--astra-text-muted)]">{t('rates.promotion.promoteReasonRequired')}</p>
            )}
            {refusal?.refused && promoteReason.trim().length > 0 && (
              <p className="text-xs text-[color:var(--astra-text-muted)]">{t('rates.promotion.refusedNoRetry')}</p>
            )}
          </div>
        </div>
      )}

      {phase === 'result' && promo && (
        <div className="flex flex-col gap-3" data-testid="rates-promotion-result">
          {promo.applied ? (
            <StateNotice state="partial" title={t('rates.promotion.appliedTitle')} message={t('rates.promotion.applied')} details={t('rates.promotion.restartNote')} />
          ) : (
            <StateNotice state="warning" title={t('rates.promotion.notAppliedTitle')} message={t('rates.promotion.notApplied')} />
          )}
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="text-[color:var(--astra-text-muted)]">{t('rates.promotion.before')} </span>
            <span style={{ fontFamily: 'var(--astra-font-code)' }}>{promo.before.version}</span>
            <IdChip value={promo.before.digest} />
            <span aria-hidden="true">→</span>
            <span className="text-[color:var(--astra-text-muted)]">{t('rates.promotion.after')} </span>
            <span style={{ fontFamily: 'var(--astra-font-code)' }}>{promo.after.version}</span>
            <IdChip value={promo.after.digest} />
          </div>
          {promo.diff && (
            <p className="text-sm" style={{ fontVariantNumeric: 'tabular-nums' }}>
              {t('rates.promotion.diffCounts', {
                added: formatNumber(promo.diff.added),
                removed: formatNumber(promo.diff.removed),
                changed: formatNumber(promo.diff.changed),
              })}
            </p>
          )}
          <div>
            <button type="button" className="btn-secondary" onClick={startOver}>
              {t('rates.promotion.startOver')}
            </button>
          </div>
        </div>
      )}
    </section>
  )
}
