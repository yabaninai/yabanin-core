import { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

// Astra primitive: EvidenceLabel (standards/design.md "Components and contracts").
// Evidence tier + explanation. The four lineage evidence tiers are NOT a
// ranked green/yellow/red ladder — they are different kinds of claims, all
// rendered in the evidence (info) color. Signature status is a separate,
// orthogonal fact and is displayed independently.

export type EvidenceTier =
  | 'provider_attested'
  | 'endpoint_pinned'
  | 'header_observed'
  | 'provider_declared'
  | 'raw'
  | 'rollup'
  | 'sample'
  | (string & {})

export type SignatureStatus = 'valid' | 'invalid' | 'unverified'

export interface EvidenceLabelProps {
  tier: EvidenceTier
  /** Why this tier applies to this record. Required — a bare label is not evidence. */
  explanation: ReactNode
  signature?: {
    status: SignatureStatus
    /** Key id or check detail, e.g. "org:<uuid>:v3". */
    detail?: ReactNode
  }
}

// The tiers translate to i18next keys; an unrecognized tier falls back to the
// raw value (it is data, not UI copy).
const tierKeys: Record<string, string> = {
  provider_attested: 'evidence.tierProviderAttested',
  endpoint_pinned: 'evidence.tierEndpointPinned',
  header_observed: 'evidence.tierHeaderObserved',
  provider_declared: 'evidence.tierProviderDeclared',
  // AUX-15: pace-based projections (budget forecasts) are estimates, not
  // measurements — they are computed client-side from observed series.
  estimate: 'evidence.tierEstimate',
  // AUX-23: data-source tiers for analytics results — the same primitive
  // states whether numbers are raw, pre-aggregated (rollup) or a truncated
  // sample, uniformly across the screens that show them.
  raw: 'evidence.tierRaw',
  rollup: 'evidence.tierRollup',
  sample: 'evidence.tierSample',
}

const signatureKeys: Record<SignatureStatus, string> = {
  valid: 'evidence.signatureValid',
  invalid: 'evidence.signatureInvalid',
  unverified: 'evidence.signatureNotVerified',
}

export function EvidenceLabel({ tier, explanation, signature }: EvidenceLabelProps) {
  const { t } = useTranslation()
  const tierLabel = tierKeys[tier] ? t(tierKeys[tier]) : tier
  return (
    <div className="flex flex-col gap-2">
      <div className="border-s-2 border-[color:var(--astra-info)] bg-[color:var(--astra-info-surface)] px-3 py-2">
        <span
          className="font-medium text-[color:var(--astra-info)]"
          style={{ font: 'var(--astra-font-label)/1.4 var(--astra-font-ui)', letterSpacing: '0.06em', textTransform: 'uppercase' }}
        >
          {t('evidence.prefix', { tier: tierLabel })}
        </span>
        <p className="overflow-wrap-anywhere mt-1 text-sm text-[color:var(--astra-ink)]">{explanation}</p>
      </div>
      {signature && (
        <p className="flex items-center gap-2 text-sm">
          <span
            aria-hidden="true"
            style={{
              color:
                signature.status === 'valid'
                  ? 'var(--astra-success)'
                  : signature.status === 'invalid'
                    ? 'var(--astra-danger)'
                    : 'var(--astra-text-muted)',
            }}
          >
            {signature.status === 'valid' ? '●' : signature.status === 'invalid' ? '✕' : '○'}
          </span>
          <span
            className={
              signature.status === 'valid'
                ? 'text-[color:var(--astra-success)]'
                : signature.status === 'invalid'
                  ? 'text-[color:var(--astra-danger)]'
                  : 'text-[color:var(--astra-text-muted)]'
            }
          >
            {t(signatureKeys[signature.status])}
          </span>
          {signature.detail && (
            <span className="overflow-wrap-anywhere min-w-0 text-[color:var(--astra-text-muted)]" style={{ fontFamily: 'var(--astra-font-code)' }}>
              {signature.detail}
            </span>
          )}
        </p>
      )}
    </div>
  )
}
