//
// The "top consumers" panel replaces the old «Top models by counterfactual
// cost» chart: the FinOps question is «who spends», not «which model». The
// data comes from the EXISTING analytics query engine (no new endpoints):
//   GET /api/analytics/query?group_by=team   — spend per team (a team groups
//           an org's API keys, so this is the keys' spend);
//   GET /api/analytics/query?group_by=agent  — spend per agent key.
// The server resolves display names for both dimensions (display_names), so
// the table shows names, never raw UUIDs. Tool calls (a2a / mcp) are NOT
// consumers or models — the gateway logs them as model_used «a2a:<target>» /
// «mcp:<server>:<tool>» (pkg/cli/a2a_audit.go, mcp_audit.go), so the savings
// payload's top-model rows are split: tool rows go to their own panel
// (toolBucketRows), everything else is regular model traffic this page no
// longer itemizes.
//
// Honesty rules carried from the platform standards:
//   * a metric cell that did not arrive stays null — unknown is never
//     folded into 0 (unknown ≠ 0);
//   * muted buckets («(none)», …) are kept as rows — spend without a key or
//     agent attribution is part of the answer to «who spends» — but flagged
//     unattributed and never drillable (a filter on «(none)» would query a
//     literal value that does not exist);
//   * only agent rows are drillable: the request explorer's YQL has an
//     `agent` field, no `team` field (pkg/adminstore/yql.go) — a team row
//     honestly has no per-row drill link.

import type { AnalyticsResult } from '../../lib/analyticsQuery.ts'

export type ConsumerKind = 'team' | 'agent'

export interface ConsumerRow {
  kind: ConsumerKind
  /** Raw dimension value (UUID, or a muted bucket label). */
  id: string
  /**
   * Server-resolved display name; '' when the row is a muted bucket (the
   * renderer substitutes the localized «Unattributed» label).
   */
  name: string
  costUsd: number | null
  requests: number | null
  /** True when a row drill link may exist (agent rows with a real id). */
  drillable: boolean
}

/** One merged, display-ready consumers board. */
export interface ConsumersBoard {
  rows: ConsumerRow[]
  /** Sources (of 2) that failed — the honest partial-data marker. */
  failures: number
}

/** Server `top` per dimension; the merged list is capped to the same top. */
export const CONSUMER_TOP = 10

/** Bucket labels that mean "no value", never a real entity. */
export const MUTED_CONSUMER_VALUES = new Set(['(none)', '(other)', '(untagged)'])

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

/**
 * Rows of one analytics result grouped by a single consumer dimension
 * (granularity 'none': every row is [dim, cost_usd, requests]).
 */
export function consumerRows(result: AnalyticsResult | null | undefined, kind: ConsumerKind): ConsumerRow[] {
  if (!result || !Array.isArray(result.rows) || !Array.isArray(result.columns)) return []
  const cols = result.columns
  const dimIdx = cols.findIndex(c => c.type !== 'time' && c.type !== 'number')
  if (dimIdx < 0) return []
  const idxByName = new Map<string, number>()
  cols.forEach((c, i) => { if (c.type === 'number') idxByName.set(c.name, i) })
  const costIdx = idxByName.get('cost_usd') ?? -1
  const reqIdx = idxByName.get('requests') ?? -1
  const dimName = String(cols[dimIdx]!.name)
  const names = result.display_names?.[dimName] ?? {}

  const rows: ConsumerRow[] = []
  for (const row of result.rows) {
    const id = String(row[dimIdx] ?? '')
    if (id === '') continue
    const muted = MUTED_CONSUMER_VALUES.has(id)
    rows.push({
      kind,
      id,
      name: muted ? '' : (names[id] ?? id),
      costUsd: costIdx >= 0 ? num(row[costIdx]) : null,
      requests: reqIdx >= 0 ? num(row[reqIdx]) : null,
      drillable: kind === 'agent' && !muted,
    })
  }
  return rows
}

/**
 * Merge the team and agent boards into one display list: spend-descending
 * (unknown spend last), capped to CONSUMER_TOP. `failures` counts the sources
 * that failed — one failed source keeps the other half visible with an
 * honest partial marker, both failed is an error state (the hook throws).
 */
export function mergeConsumers(
  team: AnalyticsResult | null,
  agent: AnalyticsResult | null,
  failures: number,
): ConsumersBoard {
  const rows = [...consumerRows(team, 'team'), ...consumerRows(agent, 'agent')]
    .sort((a, b) => (b.costUsd ?? -Infinity) - (a.costUsd ?? -Infinity))
    .slice(0, CONSUMER_TOP)
  return { rows, failures }
}

export type ToolBucketKind = 'a2a' | 'mcp'

export interface ToolBucketRow {
  /** Raw request_logs.model_used of the tool call («a2a:billing-agent»). */
  tool: string
  kind: ToolBucketKind
  requests: number | null
  costUsd: number | null
}

/** Model rows that are actually tool traffic, split out per bucket. */
export function toolBucketRows(
  topModels: ReadonlyArray<{ model: string; requests: number; actual_cost_usd: number }> | undefined,
): ToolBucketRow[] {
  const out: ToolBucketRow[] = []
  for (const m of topModels ?? []) {
    const kind: ToolBucketKind | null =
      m.model === 'a2a' || m.model.startsWith('a2a:')
        ? 'a2a'
        : m.model === 'mcp' || m.model.startsWith('mcp:')
          ? 'mcp'
          : null
    if (!kind) continue
    out.push({
      tool: m.model,
      kind,
      requests: num(m.requests),
      costUsd: num(m.actual_cost_usd),
    })
  }
  return out.sort((a, b) => (b.costUsd ?? -Infinity) - (a.costUsd ?? -Infinity))
}
