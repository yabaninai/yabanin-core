
import { readJSON, sendMutation, type RequestOptions } from './transport.ts'

export interface CreditBalance {
  org_id: string
  balance_cents: number
  balance_usd: number
  updated_at: string
}

export interface CreditTransaction {
  id: number
  org_id: string
  amount_cents: number
  balance_after: number
  type: 'topup' | 'usage'
  request_id?: string
  invoice_ref?: string
  metadata?: Record<string, unknown>
  created_at: string
}

export interface CreditTransactionsResponse {
  org_id: string
  limit: number
  count: number
  txns: CreditTransaction[]
}

export interface LowBalanceOrgsResponse {
  threshold_cents: number
  count: number
  org_ids: string[]
}

export async function fetchCreditBalance(orgId: string, opts?: RequestOptions): Promise<CreditBalance> {
  return readJSON<CreditBalance>(`/api/orgs/${encodeURIComponent(orgId)}/credits/balance`, opts)
}

export async function fetchCreditTransactions(orgId: string, limit = 50, opts?: RequestOptions): Promise<CreditTransactionsResponse> {
  const qs = new URLSearchParams({ limit: String(limit) })
  return readJSON<CreditTransactionsResponse>(`/api/orgs/${encodeURIComponent(orgId)}/credits/transactions?${qs}`, opts)
}

export async function fetchLowBalanceOrgs(threshold = -500, limit = 100, opts?: RequestOptions): Promise<LowBalanceOrgsResponse> {
  const qs = new URLSearchParams({ threshold: String(threshold), limit: String(limit) })
  return readJSON<LowBalanceOrgsResponse>(`/api/credits/low-balance?${qs}`, opts)
}

export async function requestTopUp(orgId: string, amountCents: number, invoiceRef: string, opts?: RequestOptions): Promise<void> {
  const outcome = await sendMutation(`/api/orgs/${encodeURIComponent(orgId)}/credits/topup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount_cents: amountCents, invoice_ref: invoiceRef }),
  }, opts)
  if (!outcome.ok) throw outcome.error
}
