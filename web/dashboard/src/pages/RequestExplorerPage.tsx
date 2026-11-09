import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useHashParam } from '../hooks/useHashParam'
import { useInspectParam } from '../hooks/useInspectParam'
import {
  fetchLabelKeys, getLineage, getRequestDetail, isRequestListStats, listRequests, listPolicyDecisions, requestStats, fetchSavingsReport,
  type LineageAttestation, type PolicyDecision, type RequestDetail, type RequestListStats, type RequestRow,
} from '../api/client'
import { currentHashQuery, relatedListHref } from '../lib/inspectUrl'
import {
  appendClause, parseYQL, serializeYQL, YQL_FIELDS, type YqlFieldMeta,
} from '../lib/queryLang'
import type { SortState } from '../lib/tableSort'
import { formatMoneyCell } from '../lib/columnFormat'
import { tablePrefsKey } from '../lib/tablePrefs'
import { PageHeader } from '../components/astra/PageHeader'
import { StateNotice } from '../components/astra/StateNotice'
import { DataTable, type DataTableColumn } from '../components/astra/DataTable'
import { BulkActions, BULK_SELECTION_LIMIT } from '../components/astra/BulkActions'
import { RowActions } from '../components/astra/RowActions'
import { TableSettingsMenu } from '../components/astra/TableSettingsMenu'
import { downloadCSV, toCSV } from '../components/astra/csv'
import { RequestInspector } from '../components/astra/RequestInspector'
import { MetricStrip, type Metric, type MetricState } from '../components/astra/MetricStrip'
import { FilterBar, type FilterBarHandle } from '../components/astra/FilterBar'
import { GlobalScopeBar } from '../components/GlobalScopeBar'
import { Pagination } from '../components/Pagination'
import { useGlobalScope } from '../lib/globalScope'
import { useAutoRefresh, useAutoRefreshInterval, useDocumentHidden } from '../lib/freshness'
import { FreshnessControl } from '../components/astra/FreshnessControl'
import { useTablePrefs } from '../hooks/useTablePrefs'

//   - GET /api/organizations/{id}/requests — one YQL filter system (quick
//     fields and the errors-only toggle compile into the committed query),
//     honest pagination (server total);
//   - the inspector is the right-side drawer, deep-linkable via
//     ?inspect=request:<id>; a row click opens it;
//   - GET /api/analytics/savings — model value hints for the quick filter.
// Privacy mode masks error text and hides raw JSON.

const PRIVACY_KEY = 'explorer-privacy-mode'
// v2 button budget: one «⋯» RowActions toggle per row — the page size keeps
// the whole page (rows + chrome) within the ≤40 button acceptance.
const PAGE_SIZE = 25
const TABLE_ID = 'requests-explorer'

// v2 checklist item 5/8: compact rows and a short default column set — the
// identity/error/tool columns move to the table settings menu.
const DEFAULT_HIDDEN_COLUMNS = ['request_id', 'tool_calls', 'error']

// AUX-01: the explorer sorts SERVER-side — a header click rewrites the
// `order by` clause of the committed YQL query (the single sort source of
// truth, already URL-persisted via the `query` param) and the refetch applies
// it. Columns without an orderable YQL counterpart (composite/label columns)
// are not sortable. Sorting never reorders rows locally: rows arrive in the
// server order for the requested page.
const SORT_YQL_FIELD: Record<string, string> = {
  request_id: 'request',
  created_at: 'created',
  model_used: 'model',
  status_code: 'status',
  cost_usd: 'cost',
  ttft: 'ttft',
  task_id: 'task',
  error: 'error',
}
const SORT_COLUMN_KEY: Record<string, string> = Object.fromEntries(
  Object.entries(SORT_YQL_FIELD).map(([column, field]) => [field, column]),
)

function toRFC3339(local: string): string {
  // datetime-local -> RFC3339 (UTC assumed; the inputs are labeled UTC).
  return local ? `${local}:00Z` : ''
}

/** ISO Z timestamp -> datetime-local value (UTC inputs, minute precision). */
function toLocalInput(iso: string): string {
  return iso ? iso.slice(0, 16) : ''
}

const EXPLORER_EVIDENCE_KEYS: Record<string, string> = {
  endpoint_pinned: 'explorer.evidenceEndpointPinned',
  header_observed: 'explorer.evidenceHeaderObserved',
  provider_attested: 'explorer.evidenceProviderAttested',
  provider_declared: 'explorer.evidenceProviderDeclared',
}

// PO-04: request-log detail fields for the inspector. The stored response
// snapshot (redacted/truncated by PH.1) is shown as raw JSON; the request
// body is NOT stored and is stated as such, never invented. Privacy mode hides
// the raw snapshot and the error text.

// Compact human-readable form of the routing_decision JSON. Language-neutral
// on purpose (technical tokens only): "tier_router: a → b (medium @0.60)"
// or "passthrough: a". A cross-route move (from ≠ to) gets a ⚠ prefix so the
// cost/route implication is impossible to miss.
// CORE-TRACE-04: when the decision carries the matched routing rule's
// identity ref, a mono chip appends the short rule id + content version;
// the tooltip holds the full id. Two same-name rules stay distinguishable in
// request history, and rows logged before that rule's edit keep showing the
// ORIGINAL version (the ref was frozen into the stored payload at match
// time). Absent ref → unchanged rendering (never a fabricated identity).
function renderRoutingDecision(raw: string): React.ReactNode {
  let d: { source?: string; from?: string; to?: string; class?: string; confidence?: number; threshold?: number; reason?: string; rule?: { id?: string; version?: string } } | null = null
  try { d = JSON.parse(raw) } catch { /* fall through to raw */ }
  if (!d || !d.source) return raw
  const parts: string[] = []
  const from = d.from ?? ''
  const to = d.to ?? ''
  if (d.source === 'passthrough') parts.push(`passthrough: ${from}`)
  else if (from && to && from !== to) parts.push(`⚠ ${d.source}: ${from} → ${to}`)
  else parts.push(`${d.source}: ${to || from} kept`)
  const meta: string[] = []
  if (d.class) meta.push(d.class)
  if (typeof d.confidence === 'number') {
    const thr = typeof d.threshold === 'number' ? `/${d.threshold}` : ''
    meta.push(`@${d.confidence.toFixed(2)}${thr}`)
  }
  if (d.reason) meta.push(d.reason)
  if (meta.length) parts.push(`(${meta.join(' ')})`)
  const text = parts.join(' ')
  const ruleID = typeof d.rule?.id === 'string' ? d.rule.id : ''
  if (!ruleID) return text
  const short = ruleID.length > 8 ? ruleID.slice(0, 8) : ruleID
  const version = typeof d.rule?.version === 'string' && d.rule.version ? ` · v${d.rule.version}` : ''
  return (
    <span>
      {text}{' '}
      <span
        title={`rule ${ruleID}${version}`}
        className="rounded border border-[color:var(--astra-rule-strong)] px-1 text-xs text-[color:var(--astra-text-muted)]"
        style={{ fontFamily: 'var(--astra-font-code)' }}
      >
        rule {short}{version}
      </span>
    </span>
  )
}

// fields the request-log API already carries (routing_decision,
// attempt_count, retry_count, first_token_ms, cache_hit_type, duration). A
// per-attempt list (model/provider/status/duration per try — Portkey-style
// AttemptOutcome) is NOT recorded by the API; until it is, this block shows
// the recorded facts and never invents intermediate attempts.
function routeTimelineNode(
  t: (k: string) => string,
  d: RequestDetail,
): React.ReactNode {
  let routed: React.ReactNode
  if (d.routing_decision) routed = renderRoutingDecision(d.routing_decision)
  const requested = d.model_requested || undefined
  const servedLatency = typeof d.duration_ms === 'number' ? ` · ${d.duration_ms} ms` : ''
  const facts: string[] = []
  if (d.attempt_count != null && d.attempt_count > 0) facts.push(`${t('explorer.detailAttempts')}: ${d.attempt_count}`)
  if (d.retry_count != null && d.retry_count > 0) facts.push(`${t('explorer.detailRetries')}: ${d.retry_count}`)
  if (d.first_token_ms != null) facts.push(`${t('explorer.detailTtft')}: ${d.first_token_ms}`)
  if (d.cache_hit_type) facts.push(`${t('explorer.detailCache')}: ${d.cache_hit_type}`)
  return (
    <section aria-label={t('explorer.detailRouting')} className="flex flex-col gap-2">
      <h4 className="text-xs font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('explorer.detailRouting')}</h4>
      <ol className="flex flex-col gap-1 text-sm">
        {requested && (
          <li className="flex flex-wrap items-center gap-2">
            <span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-[color:var(--astra-rule-strong)] text-xs text-[color:var(--astra-text-muted)]">1</span>
            <span className="text-[color:var(--astra-text-muted)]">{t('explorer.model')}:</span>
            <span style={{ fontFamily: 'var(--astra-font-code)' }}>{requested}</span>
          </li>
        )}
        {routed !== undefined && (
          <li className="flex flex-wrap items-center gap-2">
            <span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-[color:var(--astra-rule-strong)] text-xs text-[color:var(--astra-text-muted)]">2</span>
            <span className="text-[color:var(--astra-text-muted)]">{t('explorer.detailRouting')}:</span>
            <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{routed}</span>
          </li>
        )}
        <li className="flex flex-wrap items-center gap-2">
          <span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-[color:var(--astra-rule-strong)] text-xs text-[color:var(--astra-text-muted)]">3</span>
          <span className="text-[color:var(--astra-text-muted)]">{t('inspector.modelActual')}:</span>
          <span style={{ fontFamily: 'var(--astra-font-code)' }}>{d.model_used}</span>
          <span style={{ fontFamily: 'var(--astra-font-code)' }}>{d.status_code}{servedLatency}</span>
        </li>
      </ol>
      {facts.length > 0 && (
        <p className="text-xs text-[color:var(--astra-text-muted)]">{facts.join(' · ')}</p>
      )}
    </section>
  )
}

// Cost provenance from the recorded row (was a hardcoded "not recorded"
// placeholder): usage-based cost with token counts, or the honest
// zero-per-token note for local/subscription routes.
function costProvenanceNode(
  t: (k: string, opts?: Record<string, unknown>) => string,
  d: RequestDetail | null,
): React.ReactNode {
  if (!d) return undefined
  if (!d.cost_in_usd) {
    return <span className="text-[color:var(--astra-text-muted)]">{t('explorer.costZeroRoute')}</span>
  }
  return <span>{t('explorer.costDetail', {
    cost: `$${formatCostUsd(d.cost_in_usd)}`,
    tin: d.tokens_in ?? 0,
    tout: d.tokens_out ?? 0,
  })}</span>
}

function sortedLabelEntries(labels: Record<string, string> | undefined): Array<[string, string]> {
  if (!labels) return []
  return Object.entries(labels).sort(([a], [b]) => a.localeCompare(b))
}

function labelValueNode(key: string, value: string): React.ReactNode {
  if (key === 'ci.pipeline_url' && value.startsWith('https://')) {
    return (
      <a href={value} className="break-all underline" rel="noreferrer">
        {value}
      </a>
    )
  }
  return value
}

function buildDetailFields(
  t: (k: string) => string,
  d: RequestDetail | null,
  privacy: boolean,
  onAddLabel?: (key: string, value: string) => void,
): Array<{ label: string; value: React.ReactNode; mono?: boolean }> {
  if (!d) return []
  const fields: Array<{ label: string; value: React.ReactNode; mono?: boolean }> = []
  const add = (label: string, value: string, mono = true) => {
    if (value) fields.push({ label: t(label), value, mono })
  }
  // The recorded error is a first-class on-call fact; privacy mode masks it
  // (it can carry response/provider detail), like every row surface.
  if (d.error) {
    fields.push({
      label: t('explorer.headerError'),
      value: privacy
        ? <span className="text-[color:var(--astra-text-muted)]">•••</span>
        : <span className="break-all">{d.error}</span>,
      mono: false,
    })
  }
  if (d.prompt_hash) add('explorer.detailPromptHash', d.prompt_hash)
  if (d.tier_used) add('explorer.detailTier', d.tier_used, false)
  if (d.classifier_class) add('explorer.detailClassifier', d.classifier_class, false)
  // The route/attempt facts (routing decision, cache, TTFT, attempts,
  // retries) render in the dedicated trail block above — see routeTimeline.
  if (d.task_id) add('explorer.detailTask', d.task_id)
  if (d.agent_id) add('explorer.detailAgent', d.agent_id)
  const labelEntries = sortedLabelEntries(d.labels)
  if (labelEntries.length > 0) {
    fields.push({
      label: t('explorer.labels'),
      mono: false,
      value: (
        <span className="flex flex-col gap-1">
          {labelEntries.map(([key, value]) => (
            <span key={key} className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => onAddLabel?.(key, value)}
                className="inline-flex min-h-[44px] items-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 text-start text-xs text-[color:var(--astra-ink)] hover:bg-[color:var(--astra-surface-muted)]"
              >
                <span style={{ fontFamily: 'var(--astra-font-code)' }}>{key}={value}</span>
              </button>
              {key === 'ci.pipeline_url' && value.startsWith('https://') ? labelValueNode(key, value) : null}
            </span>
          ))}
        </span>
      ),
    })
  }
  // The tool/function calls the model requested in this response. Sources,
  // by authority:
  //   - d.tool_call_invocations — per-occurrence calls with reassembled
  //     arguments, recorded by loggerd from the PRE-truncation sample
  //     (0014 table). The full truth where it exists;
  //   - d.response_view.tool_calls — the FIX-20 processed-response
  //     envelope's calls, merged by index from the actual served response
  //     (survives when no original sample was retained);
  //   - d.tool_calls — recorded distinct names (older table, same
  //     pre-truncation guarantee, no arguments); the stored sample enriches
  //     them with ids/arguments when it survived the 4000-char cap;
  //   - the stored sample alone — the only source for legacy rows.
  // Privacy mode masks the whole section (names and arguments are response
  // content). A truncated sample with nothing recorded shows the honest
  // "cut off" note instead of silent absence.
  const invocations = privacy ? [] : (d.tool_call_invocations ?? [])
  const envelopeCalls: ExtractedToolCall[] = privacy
    ? []
    : (d.response_view?.tool_calls ?? []).map(tc => ({
        id: tc.id,
        name: tc.name ?? '',
        arguments: tc.arguments ?? '',
      }))
  const recordedNames = privacy ? [] : (d.tool_calls ?? []).map(tc => tc.tool_name).filter(Boolean)
  const parsedCalls = privacy ? [] : extractToolCalls(d.upstream_response)
  const sampleTruncated = !privacy && typeof d.upstream_response === 'string' && d.upstream_response.includes('[truncated]')
  const toolCalls: ExtractedToolCall[] = invocations.length > 0
    ? invocations.map(inv => ({
        id: inv.call_id ?? undefined,
        name: inv.tool_name,
        arguments: inv.arguments ?? '',
      }))
    : envelopeCalls.length > 0
    ? envelopeCalls
    : recordedNames.length > 0
    ? recordedNames.map(name => {
        // Arguments may be absent (truncated sample) — rendered as '—'
        // below, never fabricated. Same-name calls merge their argument
        // blobs (the table stores distinct names only).
        const withArgs = parsedCalls.filter(p => p.name === name)
        return {
          id: withArgs.find(p => p.id)?.id,
          name,
          arguments: withArgs.map(p => p.arguments).filter(Boolean).join('\n'),
        }
      })
    : parsedCalls
  if (toolCalls.length > 0) {
    fields.push({
      label: t('explorer.detailToolCalls'),
      mono: false,
      value: (
        <ol className="flex flex-col gap-2">
          {toolCalls.map((tc, i) => (
            <li key={tc.id ?? i} className="flex flex-col gap-1">
              <span className="break-all text-xs font-medium text-[color:var(--astra-ink)]">
                {i + 1}. <span style={{ fontFamily: 'var(--astra-font-code)' }}>{tc.name || t('common.unknown')}</span>
                {tc.id ? <span className="text-[color:var(--astra-text-muted)]"> · {tc.id}</span> : null}
              </span>
              <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-[length:var(--astra-radius-control)] bg-[color:var(--astra-surface-muted)] p-2 text-xs">{tc.arguments || '—'}</pre>
            </li>
          ))}
        </ol>
      ),
    })
  } else if (sampleTruncated) {
    // Nothing parsed and nothing recorded, but the sample admits it was cut:
    // absence of evidence is NOT evidence of absence — say so.
    fields.push({
      label: t('explorer.detailToolCalls'),
      mono: false,
      value: <span className="text-[color:var(--astra-text-muted)]">{t('explorer.detailToolCallsTruncated')}</span>,
    })
  }
  // FIX-20: the model answer — the processed, client-facing response the
  // gateway actually served (post policy/routing), with an explicit
  // completeness status. Reason tokens are shown as-is: technical tokens,
  // language-neutral like the routing decision above. Content and reasoning
  // are response content — privacy mode masks them, the status stays
  // (it is metadata).
  const rv = d.response_view
  if (rv) {
    const statusText = rv.status === 'partial'
      ? `${t('explorer.detailAnswerPartial')}${rv.reason ? ` · ${rv.reason}` : ''}`
      : t('explorer.detailAnswerComplete')
    fields.push({
      label: t('explorer.detailAnswer'),
      mono: false,
      value: (
        <div className="flex flex-col gap-2">
          <span className="text-xs text-[color:var(--astra-text-muted)]">
            {statusText}
            {rv.truncated ? ` · ${t('explorer.detailAnswerTruncated')}` : ''}
          </span>
          {privacy
            ? <span className="text-[color:var(--astra-text-muted)]">•••</span>
            : (
              <>
                {rv.content
                  ? <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-[length:var(--astra-radius-control)] bg-[color:var(--astra-surface-muted)] p-3 text-xs">{rv.content}</pre>
                  : null}
                {rv.reasoning_content
                  ? <details>
                      <summary className="cursor-pointer text-xs text-[color:var(--astra-text-muted)]">{t('explorer.detailAnswerReasoning')}</summary>
                      <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-[length:var(--astra-radius-control)] bg-[color:var(--astra-surface-muted)] p-3 text-xs">{rv.reasoning_content}</pre>
                    </details>
                  : null}
              </>
            )}
        </div>
      ),
    })
  }
  // The stored response snapshot — the "raw" the user asked for. In privacy
  // mode the snapshot is masked (it is response content).
  fields.push({
    label: t('explorer.detailResponse'),
    mono: true,
    value: privacy
      ? <span className="text-[color:var(--astra-text-muted)]">•••</span>
      : d.response && d.response !== null && d.response !== 'null'
        ? <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-[length:var(--astra-radius-control)] bg-[color:var(--astra-surface-muted)] p-3 text-xs">{
            // PH.1 stores long snapshots truncated; such rows arrive as JSON
            // strings (not objects) — render them as text, never as "null".
            typeof d.response === 'string' ? d.response : JSON.stringify(d.response, null, 2)
          }</pre>
        : <span className="text-[color:var(--astra-text-muted)]">{t('explorer.detailNoResponse')}</span>,
  })
  fields.push({
    label: t('explorer.detailBodyNote'),
    value: t('explorer.detailBodyNoteText'),
    mono: false,
  })
  // What ACTUALLY went to the model (post model-override / effort injection)
  // and what the model answered. When the sent model differs from the
  // client's, the block is prefixed with a visible marker — the routing
  // trail above explains why (user finding 2026-09-15).
  if (d.upstream_request && d.upstream_request !== 'null') {
    const sentText = typeof d.upstream_request === 'string' ? d.upstream_request : JSON.stringify(d.upstream_request, null, 2)
    const changedModel = extractJSONModel(d.response) !== extractJSONModel(d.upstream_request)
    fields.push({
      label: changedModel ? t('explorer.detailSentChanged') : t('explorer.detailSent'),
      mono: true,
      value: <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-[length:var(--astra-radius-control)] bg-[color:var(--astra-surface-muted)] p-3 text-xs">{(changedModel ? '⚠ ' : '') + sentText}</pre>,
    })
  }
  if (d.upstream_response && d.upstream_response !== 'null') {
    const respText = typeof d.upstream_response === 'string' ? d.upstream_response : JSON.stringify(d.upstream_response, null, 2)
    fields.push({
      label: t('explorer.detailModelResponse'),
      mono: true,
      value: <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-[length:var(--astra-radius-control)] bg-[color:var(--astra-surface-muted)] p-3 text-xs">{respText}</pre>,
    })
  }
  return fields
}

// Best-effort "model" field extraction from a stored JSON payload string —
// used only to flag in-flight model changes in the inspector labels.
function extractJSONModel(raw: unknown): string | undefined {
  if (typeof raw !== 'string') {
    if (raw && typeof raw === 'object' && 'model' in (raw as Record<string, unknown>)) {
      return String((raw as Record<string, unknown>).model)
    }
    return undefined
  }
  try {
    const v = JSON.parse(raw)
    return v && typeof v === 'object' && 'model' in v ? String(v.model) : undefined
  } catch {
    return undefined
  }
}

// The tool/function calls the model requested in this response. Sources:
//   - a non-streaming completion snapshot: choices[].message.tool_calls;
//   - a streamed SSE sample: tool_calls arrive as delta fragments split across
//     chunks — they are aggregated by index (name from the first fragment,
//     arguments concatenated) exactly like OpenAI clients reassemble them.
// A bounded/truncated sample may yield partial arguments; they are shown as
// stored, never fabricated.
interface ExtractedToolCall { id?: string; name: string; arguments: string }

function collectCompletionToolCalls(doc: unknown, out: Map<number, ExtractedToolCall>): void {
  if (!doc || typeof doc !== 'object') return
  const choices = (doc as Record<string, unknown>).choices
  if (!Array.isArray(choices)) return
  for (const ch of choices) {
    if (!ch || typeof ch !== 'object') continue
    const msg = (ch as Record<string, unknown>).message
    const tcs = msg && typeof msg === 'object' ? (msg as Record<string, unknown>).tool_calls : undefined
    if (!Array.isArray(tcs)) continue
    tcs.forEach((tc, i) => {
      if (!tc || typeof tc !== 'object') return
      const r = tc as Record<string, unknown>
      const fn = r.function && typeof r.function === 'object' ? r.function as Record<string, unknown> : {}
      const idx = typeof r.index === 'number' ? r.index : i
      const prev = out.get(idx) ?? { name: '', arguments: '' }
      out.set(idx, {
        id: typeof r.id === 'string' && r.id ? r.id : prev.id,
        name: typeof fn.name === 'string' && fn.name ? fn.name : prev.name,
        arguments: prev.arguments + (typeof fn.arguments === 'string' ? fn.arguments : ''),
      })
    })
  }
}

function collectStreamDeltaToolCalls(line: string, out: Map<number, ExtractedToolCall>): void {
  try {
    const doc = JSON.parse(line)
    if (!doc || typeof doc !== 'object') return
    const choices = (doc as Record<string, unknown>).choices
    if (!Array.isArray(choices)) return
    for (const ch of choices) {
      if (!ch || typeof ch !== 'object') continue
      const delta = (ch as Record<string, unknown>).delta
      const tcs = delta && typeof delta === 'object' ? (delta as Record<string, unknown>).tool_calls : undefined
      if (!Array.isArray(tcs)) continue
      tcs.forEach((tc, i) => {
        if (!tc || typeof tc !== 'object') return
        const r = tc as Record<string, unknown>
        const fn = r.function && typeof r.function === 'object' ? r.function as Record<string, unknown> : {}
        const idx = typeof r.index === 'number' ? r.index : i
        const prev = out.get(idx) ?? { name: '', arguments: '' }
        out.set(idx, {
          id: typeof r.id === 'string' && r.id ? r.id : prev.id,
          name: typeof fn.name === 'string' && fn.name ? fn.name : prev.name,
          arguments: prev.arguments + (typeof fn.arguments === 'string' ? fn.arguments : ''),
        })
      })
    }
  } catch { /* not a JSON frame — skip */ }
}

function extractToolCalls(raw: unknown): ExtractedToolCall[] {
  const out = new Map<number, ExtractedToolCall>()
  if (raw && typeof raw === 'object') {
    collectCompletionToolCalls(raw, out)
    return [...out.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v).filter(tc => tc.name || tc.arguments)
  }
  if (typeof raw !== 'string' || !raw) return []
  try {
    collectCompletionToolCalls(JSON.parse(raw), out)
  } catch {
    // Not a single JSON document — a streamed SSE sample: aggregate frames.
    for (const line of raw.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed.startsWith('data: ')) continue
      const payload = trimmed.slice('data: '.length)
      if (payload === '[DONE]') continue
      collectStreamDeltaToolCalls(payload, out)
    }
  }
  return [...out.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v).filter(tc => tc.name || tc.arguments)
}

// Per-request costs live in the 1e-5 range: widen precision when the
// 4-decimal view would round a nonzero cost to 0.0000 (reads as "free").
function formatCostUsd(v: number): string {
  return Math.abs(v) >= 0.00005 ? v.toFixed(4) : v.toFixed(6)
}

/** Full-value clipboard copy (the CopyIdButton fallback path). */
async function copyText(value: string): Promise<void> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
      return
    }
  } catch { /* fall through to the hidden-textarea path */ }
  try {
    const ta = document.createElement('textarea')
    ta.value = value
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  } catch { /* denied — the ID stays visible for manual selection */ }
}

export function RequestExplorerPage() {
  const { t, i18n } = useTranslation()
  // AUX-08: the org scope is the shared GlobalScope (hash ?org=, remembered
  // across screens) — picked once, it follows the operator; the shared bar
  // below renders its controls. UI-contract #1 still holds: a filtered view
  // is a shareable link and survives reload/back-forward.
  const gs = useGlobalScope()
  const org = gs.org.trim()
  // links (?model= / ?task= from Models/Tasks screens) are folded into it as
  // clauses once at mount and their params are then dropped from the hash,
  // so a reload can never resurrect a removed chip.
  const [urlModel, setUrlModel] = useHashParam('model')
  const [urlTask, setUrlTask] = useHashParam('task')
  const [urlQuery, setUrlQuery] = useHashParam('query')
  const [yqlCommitted, setYqlCommitted] = useState(() => {
    let q = urlQuery
    if (urlModel.trim()) q = appendClause(q, { kind: 'clause', field: 'model', op: '=', values: [urlModel.trim()] }, null)
    if (urlTask.trim()) q = appendClause(q, { kind: 'clause', field: 'task', op: '=', values: [urlTask.trim()] }, null)
    return q
  })
  const seededLegacyParams = urlModel.trim() !== '' || urlTask.trim() !== ''
  useEffect(() => {
    if (!seededLegacyParams) return
    setUrlModel('')
    setUrlTask('')
    // One-time legacy-param cleanup after the mount-time fold-in.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const filterBarRef = useRef<FilterBarHandle>(null)
  const yqlParse = useMemo(() => parseYQL(yqlCommitted), [yqlCommitted])

  // The header sort indicator mirrors the order-by clause of the committed
  // query; orderings without a table column (e.g. latency) show as the YQL
  // chip only. Rewriting the committed value re-syncs the FilterBar draft
  // (controlled `applied`) and the URL hash.
  const serverSort: SortState | null = yqlParse.ok && yqlParse.order && SORT_COLUMN_KEY[yqlParse.order.field]
    ? { key: SORT_COLUMN_KEY[yqlParse.order.field], dir: yqlParse.order.desc ? 'desc' : 'asc' }
    : null
  const applyHeaderSort = (next: SortState | null) => {
    // An invalid committed query cannot be rewritten reliably — the bar's
    // inline parse error explains; fix the query first.
    if (!yqlParse.ok) return
    if (next && !SORT_YQL_FIELD[next.key]) return
    const order = next ? { field: SORT_YQL_FIELD[next.key], desc: next.dir === 'desc' } : null
    const query = serializeYQL(yqlParse.root, order)
    setYqlCommitted(query)
    setUrlQuery(query)
  }
  // AUX-08: the applied window is the GlobalScope period — ONE range field
  // (the preset select in the shared bar). The datetime-local inputs appear
  // only for a hand-pinned custom range and mirror the shared scope.
  const [fromLocal, setFromLocal] = useState(() => toLocalInput(gs.from))
  const [toLocal, setToLocal] = useState(() => toLocalInput(gs.to))
  useEffect(() => {
    setFromLocal(toLocalInput(gs.from))
    setToLocal(toLocalInput(gs.to))
  }, [gs.from, gs.to])
  const commitWindow = (from: string, to: string) => {
    setFromLocal(from)
    setToLocal(to)
    if (from && to) gs.setRange(toRFC3339(from), toRFC3339(to))
  }
  const [privacy, setPrivacy] = useState<boolean>(() => {
    try { return localStorage.getItem(PRIVACY_KEY) === '1' } catch { return false }
  })

  const [rows, setRows] = useState<RequestRow[]>([])
  // AUX-20: bulk selection for the export / add-to-filter actions. Requests
  // are ephemeral (scope + page window), so the selection survives page
  // changes but is dropped whenever the applied scope changes (the debounce
  // effect below) — a stale id must never export or filter silently.
  const [selectedRequestIds, setSelectedRequestIds] = useState<string[]>([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  const [page, setPage] = useState(1)
  const [requestedPage, setRequestedPage] = useState(1)
  // Aggregate block over the SAME applied filters as the table below. The
  // stats fetch is best-effort: a failure degrades the strip to "Failed to
  // load" and never blocks or fakes the list.
  const [stats, setStats] = useState<RequestListStats | null>(null)
  const [statsFailed, setStatsFailed] = useState(false)

  const [loading, setLoading] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [loadError, setLoadError] = useState('')
  // AUX-23: freshness — clock label of the last successful load and the
  // honest stale marker when a REFRESH failed (the shown rows stay).
  const [asOf, setAsOf] = useState<number | null>(null)
  const [refreshStale, setRefreshStale] = useState(false)
  const [autoRefreshMs, setAutoRefreshMs] = useAutoRefreshInterval()
  const tabHidden = useDocumentHidden()
  const [topModels, setTopModels] = useState<Array<{ model: string; actual_cost_usd: number }>>([])
  const [labelKeys, setLabelKeys] = useState<string[]>([])
  const [inspectParam, setInspectParam] = useInspectParam()
  const inspectId = inspectParam.startsWith('request:') ? inspectParam.slice('request:'.length) : inspectParam
  const [inspectRecord, setInspectRecord] = useState<LineageAttestation | null>(null)
  const [inspectDetail, setInspectDetail] = useState<RequestDetail | null>(null)
  const [inspectorLoading, setInspectorLoading] = useState(false)
  // CORE-TRACE-03: the policy decisions attached to the inspected request —
  // a separate record from the request log (the log answers "what happened",
  // the decision log answers "what the policy made of it"). Tri-state so the
  // drawer never renders a bare nothing while the fetch is in flight or
  // broken; keyed to [inspectId, org] with a cancelled guard like the other
  // drawer fetches, so a stale response can never land in a reopened drawer.
  const [inspectDecisions, setInspectDecisions] = useState<PolicyDecision[] | null>(null)
  const [inspectDecisionsState, setInspectDecisionsState] = useState<'idle' | 'loading' | 'ready' | 'failed'>('idle')
  const gen = useRef(0)
  // AUX-22: per-table column visibility + density (compact is the v2
  // default; seeded once for operators without stored prefs).
  const tablePrefs = useTablePrefs(TABLE_ID)
  useEffect(() => {
    try {
      if (localStorage.getItem(tablePrefsKey(TABLE_ID)) !== null) return
    } catch { return }
    tablePrefs.setDensity('compact')
    tablePrefs.setHiddenColumnIds([...DEFAULT_HIDDEN_COLUMNS])
    // One-time first-visit seeding; stored prefs always win afterwards.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    try { localStorage.setItem(PRIVACY_KEY, privacy ? '1' : '0') } catch { /* non-browser */ }
  }, [privacy])

  // Commit parse-ok drafts (chip removals and builder adds land here too —
  // they rewrite the text). The URL param tracks the committed value, not
  // keystrokes; invalid drafts are held back by the FilterBar and never
  // reach this handler.
  const applyQuery = (next: string) => {
    setYqlCommitted(next)
    setUrlQuery(next)
  }

  // AUX-05: the field registry is a prop — the base YQL registry plus the
  // org's live label keys (GET /api/analytics/label-keys), so the builder can
  // add label.<key> clauses without typing raw syntax.
  const filterFields = useMemo<YqlFieldMeta[]>(() => [
    ...YQL_FIELDS,
    ...labelKeys.map(key => ({ name: `label.${key}`, kind: 'text' as const, nullable: true, orderable: false, aliases: [] })),
  ], [labelKeys])

  // The shared filter params: the list and its aggregate strip must describe
  // exactly the same applied scope (they are fetched together, generation-
  // guarded by `gen`). The quick fields and the errors-only toggle live
  // inside the committed query — there are no parallel filter params.
  const buildFilterParams = () => ({
    orgId: org,
    from: toRFC3339(fromLocal) || undefined, to: toRFC3339(toLocal) || undefined,
    query: yqlCommitted || undefined,
  })

  const load = async (p = 1) => {
    if (!org) return
    const g = ++gen.current
    setLoading(true)
    setLoaded(false)
    setLoadError('')
    setRefreshStale(false)
    setRows([]); setTotal(0); setTotalPages(1); setPage(1); setRequestedPage(p)
    setStats(null); setStatsFailed(false)
    const filterParams = buildFilterParams()
    try {
      const [resp, statsRes] = await Promise.allSettled([
        listRequests({ ...filterParams, page: p, pageSize: PAGE_SIZE }),
        requestStats(filterParams),
      ])
      if (gen.current !== g) return
      if (resp.status === 'fulfilled') {
        setRows(resp.value.data ?? [])
        setTotal(resp.value.pagination?.total ?? resp.value.data?.length ?? 0)
        setTotalPages(resp.value.pagination?.total_pages ?? 1)
        setPage(resp.value.pagination?.page ?? p)
        setAsOf(Date.now())
      } else {
        setLoadError(resp.reason instanceof Error ? resp.reason.message : String(resp.reason))
      }
      // A stats payload that does not parse (empty body, shape drift) is
      // treated exactly like a transport failure: the strip shows the honest
      // "failed to load" state and never crashes on undefined fields.
      if (statsRes.status === 'fulfilled' && isRequestListStats(statsRes.value)) setStats(statsRes.value)
      else setStatsFailed(true)
    } finally {
      if (gen.current === g) { setLoading(false); setLoaded(true) }
    }
  }

  // AUX-23 refresh (manual ⟳ / auto tick): the SAME applied filters and page,
  // nothing cleared or reset — sorting lives in the committed query, the open
  // inspector (drawer) is untouched, rows are replaced in place on success.
  // A failed refresh keeps the shown rows and sets the honest stale marker
  // (asyncScope: the generation guard discards a superseded completion, and
  // the hook skips ticks while a load is in flight — no parallel requests).
  const refresh = async () => {
    if (!org) return
    const g = ++gen.current
    setLoading(true)
    const p = page || 1
    const filterParams = buildFilterParams()
    try {
      const [resp, statsRes] = await Promise.allSettled([
        listRequests({ ...filterParams, page: p, pageSize: PAGE_SIZE }),
        requestStats(filterParams),
      ])
      if (gen.current !== g) return
      if (resp.status === 'fulfilled') {
        setRows(resp.value.data ?? [])
        setTotal(resp.value.pagination?.total ?? resp.value.data?.length ?? 0)
        setTotalPages(resp.value.pagination?.total_pages ?? 1)
        setPage(resp.value.pagination?.page ?? p)
        setAsOf(Date.now())
        setRefreshStale(false)
        // AUX-23: a SUCCESSFUL refresh is also the recovery path after a
        // failed initial load — the list renders again, the error notice
        // goes, and auto-refresh becomes active with the fresh data.
        setLoadError('')
        setLoaded(true)
      } else {
        setRefreshStale(true)
      }
      if (statsRes.status === 'fulfilled' && isRequestListStats(statsRes.value)) {
        setStats(statsRes.value)
        // An honest recovery: the earlier "failed to load" placeholder goes
        // once the refresh actually brings the numbers back.
        setStatsFailed(false)
      }
      else setStatsFailed(true)
    } finally {
      if (gen.current === g) setLoading(false)
    }
  }

  // Model value hints for the quick field and the query builder (best-effort
  // side fetch; failures just leave the datalist empty).
  useEffect(() => {
    if (!org) return
    fetchSavingsReport({ org_id: org, days: 30 })
      .then(rep => setTopModels((rep.top_models_by_cost ?? []).slice(0, 8)))
      .catch(() => setTopModels([]))
  }, [org])

  // Label keys for the FilterBar field registry (best-effort; a failure just
  // leaves the builder without label.<key> options).
  useEffect(() => {
    if (!org) { setLabelKeys([]); return }
    const ctrl = new AbortController()
    fetchLabelKeys(org, toRFC3339(fromLocal), toRFC3339(toLocal), { signal: ctrl.signal })
      .then(rows => setLabelKeys(rows.map(r => r.key)))
      .catch(() => setLabelKeys([]))
    return () => ctrl.abort()
  }, [org, fromLocal, toLocal])

  // Value suggestions from existing endpoints: models come from the savings
  // report already fetched for the hints.
  const queryValueHints = (field: string): string[] => {
    if (field === 'model' || field === 'model_requested') return topModels.map(m => m.model)
    return []
  }

  // Page change refetch.
  useEffect(() => {
    if (!loaded || requestedPage === 1) return
    void load(requestedPage)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestedPage])

  // UX-03: auto-search — any filter edit (org, window, YQL query) refetches
  // page 1 after a 400ms debounce. Requires an org (the endpoint is
  // org-scoped); pagination is not part of the debounce (its own effect).
  // The YQL dependency is the COMMITTED value: invalid drafts are held back
  // by the FilterBar and never reach this fetch. The window is the
  // GlobalScope period: picking a preset anywhere moves it.
  useEffect(() => {
    if (!org) return
    setSelectedRequestIds([])
    const timer = setTimeout(() => { void load(1) }, 400)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [org, fromLocal, toLocal, yqlCommitted])

  // AUX-23: auto-refresh — the operator's interval (localStorage); paused
  // while the tab is hidden OR the request inspector (drawer) is open; ticks
  // landing on an in-flight load are skipped inside the hook.
  useAutoRefresh({
    intervalMs: autoRefreshMs,
    paused: tabHidden || inspectId !== '',
    active: loaded,
    loading,
    onRefresh: () => { void refresh() },
  })

  // The drawer's data: lineage (signature/region evidence) and the
  // request-log detail (stored response snapshot + prompt_hash) are
  // independent; fetch both and let either resolve. The effect (not a click
  // handler) is what makes the ?inspect=request:<id> deep link work.
  useEffect(() => {
    if (!inspectId) return
    let cancelled = false
    setInspectRecord(null)
    setInspectDetail(null)
    setInspectorLoading(true)
    const lineage = getLineage(inspectId)
      .then(rec => ({ ok: true as const, rec }))
      .catch(() => ({ ok: false as const, rec: null }))
    const detail = org
      ? getRequestDetail(org, inspectId)
        .then(rec => ({ ok: true as const, rec }))
        .catch(() => ({ ok: false as const, rec: null }))
      : Promise.resolve({ ok: false as const, rec: null })
    void Promise.all([lineage, detail]).then(([l, d]) => {
      if (cancelled) return
      setInspectRecord(l.ok ? { ...(l.rec as LineageAttestation), request_id: inspectId } : null)
      setInspectDetail(d.ok ? (d.rec as RequestDetail) : null)
      setInspectorLoading(false)
    })
    return () => { cancelled = true }
  }, [inspectId, org])

  // CORE-TRACE-03: fetch the decision-log rows for this request. First page
  // only — the drawer shows the freshest evaluations plus a link into the
  // full log; it must not re-implement the log's pagination. The callback
  // form lets the section's retry affordance re-run the same scoped fetch.
  // The guard is a GENERATION ref, not a closure
  // flag — the retry button invokes this callback outside the effect, so
  // its closure was never registered for cleanup and a late retry response
  // could land after an org switch, a close/reopen or a newer fetch and
  // set rows/state from the previous scope. Every invocation takes a fresh
  // token and both settle branches compare it, so a superseded response —
  // effect- or retry-originated — is a no-op; the idle branch (close /
  // empty scope) bumps the token too, invalidating anything in flight.
  const genInspectDecisions = useRef(0)
  const loadInspectDecisions = useCallback(() => {
    if (!inspectId || !org) { ++genInspectDecisions.current; setInspectDecisions(null); setInspectDecisionsState('idle'); return }
    const g = ++genInspectDecisions.current
    setInspectDecisions(null)
    setInspectDecisionsState('loading')
    listPolicyDecisions(org, 1, { requestId: inspectId })
      .then(res => { if (genInspectDecisions.current === g) { setInspectDecisions(res.rows); setInspectDecisionsState('ready') } })
      .catch(() => { if (genInspectDecisions.current === g) setInspectDecisionsState('failed') })
  }, [inspectId, org])

  useEffect(() => loadInspectDecisions(), [loadInspectDecisions])

  const openInspector = (requestId: string) => {
    if (!requestId) return
    setInspectParam(`request:${requestId}`)
  }
  const closeInspector = () => {
    setInspectParam(null)
    setInspectRecord(null)
    setInspectDetail(null)
    setInspectDecisions(null)
    setInspectDecisionsState('idle')
  }

  // AUX-05: chips, the add-filter builder, the YQL input with the error
  // highlight and the cheatsheet now live in the shared FilterBar. The page
  // keeps only the committed value, URL sync and refetching.
  const addLabelClause = (key: string, value: string) => {
    filterBarRef.current?.appendClause(
      { kind: 'clause', field: `label.${key}`, op: '=', values: [value] },
    )
  }

  // AUX-20: the requests API is read-only, so the honest bulk actions are
  // the client-side ones — a CSV export of the selected rows and an
  // `request in (…)` filter clause through the shared FilterBar. Privacy
  // mode masks error text in the UI, so the export masks it too.
  const exportSelectedRequestsCsv = (selected: RequestRow[]) => {
    downloadCSV(
      'requests.csv',
      toCSV(
        [t('explorer.headerRequestId'), t('explorer.headerAtUtc'), t('explorer.headerModel'), t('explorer.headerStatus'), t('explorer.headerCostUsd'), t('explorer.headerTokens'), t('explorer.headerTask'), t('explorer.headerError')],
        selected.map(r => [
          r.request_id,
          r.created_at,
          r.model_used,
          r.status_code,
          r.cost_usd,
          `${r.tokens_in}/${r.tokens_out}`,
          r.task_id || '',
          privacy ? '' : (r.error || ''),
        ]),
      ),
    )
  }
  const addSelectedToFilter = (selected: RequestRow[]) => {
    const ids = selected.map(r => r.request_id).filter(Boolean)
    if (ids.length === 0) return
    filterBarRef.current?.appendClause({ kind: 'clause', field: 'request', op: 'in', values: ids })
  }

  // drawer; Copy / Inspect / Lineage / label filters live in the «⋯» menu.
  // The toggle keeps its 36px target but is pulled over the cell padding
  // (-my-2) so it does not inflate the compact row height (v2 item 8).
  const rowActions = (r: RequestRow) => (
    // The menu's clicks must not also trigger the row's open-drawer click.
    <span className="-my-2 inline-flex items-center" onClick={e => e.stopPropagation()}>
      <RowActions
        label={`${t('common.actions')}: ${r.request_id}`}
        items={[
          { id: 'inspect', label: t('common.inspector'), onSelect: () => openInspector(r.request_id) },
          { id: 'lineage', label: t('explorer.viewLineage'), onSelect: () => { window.location.hash = `#lineage?req=${encodeURIComponent(r.request_id)}` } },
          { id: 'copy', label: t('common.copy'), onSelect: () => { void copyText(r.request_id) } },
          ...sortedLabelEntries(r.labels).slice(0, 3).map(([key, value]) => ({
            id: `label-${key}`,
            label: `label.${key} = ${value}`,
            onSelect: () => addLabelClause(key, value),
          })),
        ]}
      />
    </span>
  )

  const columns: DataTableColumn<RequestRow>[] = [
    { key: 'created_at', header: t('explorer.headerAtUtc'), format: 'date', render: r => <span style={{ fontFamily: 'var(--astra-font-code)' }}>{r.created_at.slice(0, 19).replace('T', ' ')}</span> },
    { key: 'model_used', header: t('explorer.headerModel'), type: 'text' },
    { key: 'status_code', header: t('explorer.headerStatus'), align: 'right', mono: true, type: 'number' },
    {
      key: 'cost_usd', header: t('explorer.headerCostUsd'), align: 'right', mono: true, type: 'money', unit: 'USD',
      // Zero cost is "no per-token charge on this route", not "$0.00" —
      // honest em dash; the exact value rides the title hint (v2 money rule).
      render: r => {
        if (!(r.cost_usd > 0)) return '—'
        const cell = formatMoneyCell(r.cost_usd, { locale: i18n.language, currency: 'USD' })
        return cell.title != null ? <span title={cell.title}>{cell.text}</span> : cell.text
      },
    },
    {
      // Composite "in/out" display over two server fields — no single order
      // expression, so the header is not a sort control (AUX-02 tooltip).
      key: 'tokens', header: t('explorer.headerTokens'), align: 'right', mono: true, sortable: false,
      render: r => `${r.tokens_in}/${r.tokens_out}`,
    },
    {
      // Observability parity (Bifrost attempt trail). Absent = unknown
      // (legacy row or non-streaming) — rendered as an em dash, never 0,
      // and sorted as missing (last), never as -1/0.
      key: 'ttft', header: t('explorer.headerTtft'), align: 'right', mono: true, type: 'number', unit: 'ms',
      getSortValue: r => r.first_token_ms ?? null,
      render: r => r.first_token_ms != null ? String(r.first_token_ms) : '—',
    },
    { key: 'task_id', header: t('explorer.headerTask'), type: 'text', render: r => r.task_id || '—' },
    {
      // Labels are not orderable server-side (YQL: "cannot order by label").
      // Scanning-only here: filtering by a label lives in the row menu and
      // the drawer (v2 item 4: one interaction per row).
      key: 'labels', header: t('explorer.labels'), sortable: false,
      render: r => {
        const entries = sortedLabelEntries(r.labels)
        if (entries.length === 0) return '—'
        const shown = entries.slice(0, 3)
        const rest = entries.length - shown.length
        return (
          <span className="flex flex-wrap items-center gap-1">
            {shown.map(([key, value]) => (
              <span
                key={key}
                className="inline-flex max-w-full items-center rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] px-2 py-0.5 text-xs text-[color:var(--astra-ink)]"
              >
                <span className="break-all" style={{ fontFamily: 'var(--astra-font-code)' }}>{key}={value}</span>
              </span>
            ))}
            {rest > 0 ? <span className="text-xs text-[color:var(--astra-text-muted)]">{t('explorer.labelMore', { count: rest })}</span> : null}
          </span>
        )
      },
    },
    {
      // fields the list API already carries: a cache hit, a fallback (more
      // than one attempt), intra-model retries. Absent facts are an em
      // dash — never a fake "clean".
      key: 'decision', header: t('explorer.detailRouting'), sortable: false,
      headerHint: t('explorer.detailRouting'),
      render: r => {
        const parts: React.ReactNode[] = []
        if (r.cache_hit_type && r.cache_hit_type !== 'miss') {
          parts.push(<span key="cache" title={t('explorer.detailCache')}>{r.cache_hit_type}</span>)
        }
        if (r.attempt_count != null && r.attempt_count > 1) {
          parts.push(<span key="attempts" title={t('explorer.detailAttempts')}>×{r.attempt_count}</span>)
        }
        if (r.retry_count != null && r.retry_count > 0) {
          parts.push(<span key="retries" title={t('explorer.detailRetries')}>↻{r.retry_count}</span>)
        }
        if (parts.length === 0) return '—'
        return <span className="flex flex-wrap items-center justify-end gap-2">{parts}</span>
      },
    },
    {
      // Tool/function calls of THIS request (list surface): distinct
      // recorded names, straight from the org-scoped tool_calls table.
      // The drawer keeps the deep view (ids, arguments, sample parse).
      // Privacy mode masks names — they are response content. The tool
      // field is not orderable server-side.
      key: 'tool_calls', header: t('explorer.headerToolCalls'), sortable: false,
      render: r => privacy
        ? <span className="text-[color:var(--astra-text-muted)]">•••</span>
        : r.tool_calls?.length
          ? <span className="break-all text-xs" style={{ fontFamily: 'var(--astra-font-code)' }}>{r.tool_calls.join(', ')}</span>
          : '—',
    },
    {
      key: 'error', header: t('explorer.headerError'), type: 'text',
      render: r => privacy
        ? <span className="text-[color:var(--astra-text-muted)]">•••</span>
        : <span className="break-all text-xs">{r.error || '—'}</span>,
    },
    {
      key: 'request_id', header: t('explorer.headerRequestId'), mono: true, type: 'text',
      render: r => <span className="break-all">{r.request_id || '—'}</span>,
    },
  ]

  // Aggregate strip over the applied scope. Three honest states: loading
  // (calm ellipsis), failed (explicit "failed to load", table unaffected),
  // measured values. Unknown/zero-latency rows are excluded server-side, so
  // the latency numbers never include fake zeros.
  const statsMetrics: Metric[] = (() => {
    const allLabels = ['statRequests', 'statSuccessRate', 'statAvgLatency', 'statP95Latency']
    if (statsFailed) {
      return allLabels.map(label => ({
        label: t(`explorer.${label}`),
        value: t('states.failedToLoad'),
        state: 'unknown' as MetricState,
      }))
    }
    if (!stats) {
      return allLabels.map(label => ({
        label: t(`explorer.${label}`),
        value: '',
        state: 'loading' as MetricState,
      }))
    }
    return [
      { label: t('explorer.statRequests'), value: stats.total_requests.toLocaleString(), source: t('explorer.statsSource'), state: 'ok' as MetricState },
      { label: t('explorer.statSuccessRate'), value: `${(stats.success_rate * 100).toFixed(1)}%`, unit: t('explorer.statSuccessOfTotal'), state: 'ok' as MetricState },
      { label: t('explorer.statAvgLatency'), value: Math.round(stats.average_latency_ms).toLocaleString(), unit: 'ms', state: 'ok' as MetricState },
      { label: t('explorer.statP95Latency'), value: Math.round(stats.p95_latency_ms).toLocaleString(), unit: 'ms', state: 'ok' as MetricState },
    ]
  })()

  // CORE-TRACE-03: the drawer's decision-log section. Rendered inside the
  // inspector body (routeTimeline slot) so it shows for EVERY inspected
  // request — including requests whose request-log row is gone, where this
  // section plus the unknown-request diagnosis is the only evidence the
  // operator gets. Enforce and shadow render differently on purpose: an
  // enforce row names the applied action, a shadow row names what WOULD
  // have happened and never reads as an applied verdict.
  const decisionsLink = relatedListHref('policy-decisions', currentHashQuery(), { org, request: inspectId })
  const inspectorDecisionsNode: React.ReactNode = (
    <section aria-label={t('explorer.policyDecisionsHeading')} className="flex flex-col gap-2" data-testid="inspector-policy-decisions">
      <h4 className="text-xs font-medium uppercase tracking-wide text-[color:var(--astra-text-muted)]">{t('explorer.policyDecisionsHeading')}</h4>
      {inspectDecisionsState === 'loading' && (
        <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="inspector-decisions-loading">{t('states.loading')}</p>
      )}
      {inspectDecisionsState === 'failed' && (
        <div className="flex flex-wrap items-center gap-2" data-testid="inspector-decisions-failed">
          <p className="text-sm text-[color:var(--astra-warning)]">{t('explorer.decisionsLoadFailed')}</p>
          <button type="button" onClick={loadInspectDecisions}
            className="text-sm text-[color:var(--astra-accent)] underline underline-offset-2">
            {t('common.retry')}
          </button>
        </div>
      )}
      {inspectDecisionsState === 'ready' && (inspectDecisions !== null && inspectDecisions.length > 0 ? (
        <>
          <ul className="flex flex-col gap-2 text-sm">
            {inspectDecisions.slice(0, 5).map(d => (
              <li key={d.id}
                className="flex flex-col gap-1 rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule)] px-3 py-2"
                data-testid="inspector-decision-row">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[color:var(--astra-ink)]" style={{ fontFamily: 'var(--astra-font-code)' }}>
                    {d.policy_id}{d.policy_version > 0 ? ` @v${d.policy_version}` : ''}
                  </span>
                  <span className="rounded-full border border-[color:var(--astra-rule-strong)] px-2 text-xs uppercase tracking-wide text-[color:var(--astra-text-muted)]">{d.mode}</span>
                  <span className="text-xs text-[color:var(--astra-text-muted)]">{d.created_at}</span>
                </div>
                <p className="text-[color:var(--astra-ink)]" data-testid="inspector-decision-verdict">
                  {d.mode === 'enforce'
                    ? t('explorer.decisionActual', { verdict: d.verdict })
                    : t('explorer.decisionShadow', { verdict: d.verdict })}
                </p>
                {!d.findings_valid && (
                  <p className="text-xs text-[color:var(--astra-warning)]">{t('explorer.decisionsFindingsInvalid')}</p>
                )}
                {d.findings.length > 0 && (
                  <ul className="flex flex-col gap-0.5 text-xs text-[color:var(--astra-text-muted)]">
                    {d.findings.map((f, i) => (
                      <li key={`${d.id}-${i}`}>{f.step ? `${f.step}: ${f.category}` : f.category}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
          {inspectDecisions.length > 5 && (
            <p className="text-xs text-[color:var(--astra-text-muted)]">{t('explorer.decisionsMore')}</p>
          )}
          <a className="w-fit text-sm text-[color:var(--astra-accent)] underline underline-offset-2"
            href={decisionsLink} data-testid="inspector-decisions-open-log">
            {t('explorer.decisionsOpenLog')}
          </a>
        </>
      ) : (
        <p className="text-sm text-[color:var(--astra-text-muted)]" data-testid="inspector-decisions-empty">{t('explorer.decisionsEmpty')}</p>
      ))}
    </section>
  )

  return (
    // (v2 item 8 — ≥15 rows at 1440×900). One compact band carries the
    // applied scope AND the table settings; the aggregate strip sits under
    // the table so the rows start as high as possible.
    <div className="flex flex-col gap-3">
      <PageHeader
        title={t('explorer.title')}
        freshness={
          <FreshnessControl
            asOf={asOf}
            stale={refreshStale}
            loading={loading}
            // The requests endpoint is org-scoped: without an org there is
            // nothing to refresh.
            disabled={!org}
            onRefresh={() => { void refresh() }}
            intervalMs={autoRefreshMs}
            onIntervalChange={setAutoRefreshMs}
          />
        }
      />
      {privacy && (
        <StateNotice state="partial" title={t('explorer.privacyOnTitle')}
          message={t('explorer.privacyOnMessage')} />
      )}

      {/* The applied scope: org · period from the shared GlobalScope (AUX-08).
          ONE range field — the preset; the two borders appear only for a
          hand-pinned custom range. The privacy toggle carries its hint as a
          native tooltip (what masking covers) plus the banner above. */}
      <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2 rounded-[length:var(--astra-radius-panel)] border border-[color:var(--astra-rule)] bg-[color:var(--astra-surface)] px-4 py-1.5">
        <div className="flex flex-wrap items-end gap-x-4 gap-y-2">
          <GlobalScopeBar fields={['org', 'period']} orgLabel={t('explorer.organizationId')} />
          {gs.period === 'custom' && (
            <>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('explorer.fromUtc')}</span>
                <input type="datetime-local" value={fromLocal} onChange={e => commitWindow(e.target.value, toLocal)}
                  className="min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-2" />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-[color:var(--astra-text-muted)]">{t('explorer.toUtc')}</span>
                <input type="datetime-local" value={toLocal} onChange={e => commitWindow(fromLocal, e.target.value)}
                  className="min-h-[44px] rounded-[length:var(--astra-radius-control)] border border-[color:var(--astra-rule-strong)] bg-[color:var(--astra-surface)] px-3 py-2" />
              </label>
            </>
          )}
          <label title={t('explorer.privacyOnMessage')} className="flex min-h-[44px] items-center gap-2 pb-2 text-sm text-[color:var(--astra-ink)]">
            <input type="checkbox" checked={privacy} onChange={e => setPrivacy(e.target.checked)} />
            {privacy ? t('explorer.privacyOn') : t('explorer.privacyOff')}
          </label>
        </div>
        <TableSettingsMenu
          columns={columns.map(c => ({ key: c.key, header: c.header }))}
          hiddenColumnIds={tablePrefs.hiddenColumnIds}
          onHiddenChange={tablePrefs.setHiddenColumnIds}
          density={tablePrefs.density}
          onDensityChange={tablePrefs.setDensity}
          onReset={tablePrefs.reset}
        />
      </div>

      {/* the ONE filter system — quick fields and the errors-only
          toggle compile into the same committed YQL as the query input and
          the chips (FilterBar hybrid mode). Refetches only parse-ok commits;
          debounceMs=0 keeps commit-on-keystroke, the fetch debounce stays
          below. */}
      <FilterBar
        ref={filterBarRef}
        id="explorer-yql"
        label={t('explorer.queryLabel')}
        mode="hybrid"
        fields={filterFields}
        quickFields={[
          { name: 'model', kind: 'text', nullable: false, orderable: true, aliases: [] },
          { name: 'task', kind: 'text', nullable: true, orderable: true, aliases: [] },
        ]}
        booleanFields={[{
          name: 'errors-only',
          label: t('explorer.errorsOnly'),
          clause: { kind: 'clause', field: 'status', op: '>=', values: ['400'] },
        }]}
        fieldLabels={{ model: t('explorer.model'), task: t('explorer.taskFilter') }}
        applied={yqlCommitted}
        onApply={applyQuery}
        debounceMs={0}
        valueHints={queryValueHints}
      />

      {loadError && <StateNotice state="error" message={loadError} action={{ label: t('common.retry'), onClick: () => void load(1) }} />}
      {!loaded && !loading && (
        <StateNotice state="not-loaded"
          message={t('explorer.notLoaded')} />
      )}

      {loaded && (
        <section aria-label={t('explorer.requestsHeading')} className="flex flex-col gap-2">
          <BulkActions
            rows={rows}
            getRowId={r => r.request_id || `${r.created_at}-${r.status_code}`}
            getRowLabel={r => r.request_id || r.created_at}
            selectedIds={selectedRequestIds}
            onSelectionChange={setSelectedRequestIds}
            limit={BULK_SELECTION_LIMIT}
            actions={[
              { id: 'requests.bulk.export', label: t('common.exportCsv'), instant: exportSelectedRequestsCsv },
              { id: 'requests.bulk.filter', label: t('bulk.addToFilter'), instant: addSelectedToFilter },
            ]}
          />
          <DataTable
            columns={columns}
            rows={rows}
            getRowId={r => r.request_id || `${r.created_at}-${r.status_code}`}
            selection={{
              selectedRowIds: selectedRequestIds,
              onSelectionChange: setSelectedRequestIds,
              limit: BULK_SELECTION_LIMIT,
              rowLabel: r => r.request_id || r.created_at,
            }}
            page={page}
            pageSize={PAGE_SIZE}
            onPageChange={setRequestedPage}
            pagination="external"
            sortMode="server"
            sort={serverSort}
            onSortChange={applyHeaderSort}
            serverTotal={total}
            scopeNote={t('explorer.scopeNotePage', { page, totalPages })}
            caption={t('explorer.captionRequests')}
            empty={t('explorer.emptyRequests')}
            emptyAction={{ label: t('explorer.clearModelFilter'), onClick: () => applyQuery('') }}
            density={tablePrefs.density}
            hiddenColumnIds={tablePrefs.hiddenColumnIds}
            onRowClick={r => openInspector(r.request_id)}
            selectedId={inspectId || undefined}
            renderActions={rowActions}
          />
          <Pagination page={page} pageSize={PAGE_SIZE} total={total} totalPages={totalPages} loading={loading} onChange={setRequestedPage} />
          {/* Applied-scope metrics under the table: same filters as the
              list (AUX-20 of the strip contract), kept off the rows'
              vertical budget (v2 item 8). */}
          <MetricStrip aria-label={t('explorer.statsHeading')} metrics={statsMetrics} />
        </section>
      )}

      {inspectId !== '' && (
        <RequestInspector
          variant="drawer"
          loading={inspectorLoading}
          record={!inspectorLoading && inspectId ? {
            id: inspectId,
            model: typeof inspectRecord?.model_used === 'string'
              ? inspectRecord.model_used
              : inspectDetail?.model_used || undefined,
            regionClaim: typeof inspectRecord?.inference_region === 'string'
              ? inspectRecord.inference_region
              : inspectDetail?.home_region || undefined,
            // Timing falls back to the request_logs timestamp: lineage rows
            // exist only for post-enablement traffic, but every logged request
            // has a created_at (user finding 2026-09-15: "Not recorded").
            timing: typeof inspectRecord?.timestamp === 'string' && inspectRecord.timestamp
              ? inspectRecord.timestamp
              : (inspectDetail?.created_at || undefined),
              evidence: inspectRecord ? {
              tier: typeof inspectRecord.region_evidence === 'string' && inspectRecord.region_evidence ? inspectRecord.region_evidence : 'provider_declared',
              explanation: EXPLORER_EVIDENCE_KEYS[typeof inspectRecord.region_evidence === 'string' ? inspectRecord.region_evidence : '']
                ? t(EXPLORER_EVIDENCE_KEYS[typeof inspectRecord.region_evidence === 'string' ? inspectRecord.region_evidence : ''])
                : t('explorer.noLineageRecord'),
            } : undefined,
          // The raw block previously showed ONLY the lineage record; for
          // requests without one it disappeared entirely ("raw record
          // null"). Fall back to the full request-log detail — the snapshot
          // fields already render above, this is the complete record.
          raw: privacy ? undefined : (inspectRecord ?? inspectDetail ?? undefined),
          } : null}
          fields={buildDetailFields(t, inspectDetail, privacy, (key, value) => addLabelClause(key, value))}
          costProvenance={costProvenanceNode(t, inspectDetail)}
          routeTimeline={(
            // CORE-TRACE-03: the timeline slot carries three layers so the
            // drawer stays informative even when the request-log row is
            // gone: the explicit unknown-request diagnosis (never a bare
            // empty shell), the policy decisions for this request, and —
            // only when the detail row exists — the routing timeline.
            <>
              {!inspectorLoading && !inspectDetail && (
                <StateNotice state="warning" title={t('explorer.detailRequestUnknownTitle')}
                  message={t('explorer.detailRequestUnknown')} />
              )}
              {inspectorDecisionsNode}
              {inspectDetail ? routeTimelineNode(t, inspectDetail) : null}
            </>
          )}
          links={[
            { label: t('explorer.viewLineage'), href: `#lineage?req=${encodeURIComponent(inspectId)}` },
            { label: t('explorer.decisionsOpenLog'), href: decisionsLink },
          ]}
          onClose={closeInspector}
        />
      )}
    </div>
  )
}
