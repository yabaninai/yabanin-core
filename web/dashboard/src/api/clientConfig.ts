// Every guided-client config block comes from the SERVER — GET
// /api/client-config/{agent} renders through pkg/clientconfig
// (services/admin/handlers/client_config_handlers.go), the
// single source of truth for every client format. This module is a thin
// typed client plus the browser-local test-connection helpers.
//
// Contracts:
//   - the API key itself is never embedded: the server renderers emit an env
//     NAME (env_key / ANTHROPIC_AUTH_TOKEN source / {env:…}) and a key VALUE
//     never enters the request either (only the env NAME rides key_env);
//   - the console still invents no gateway URL: base_url is the
//     operator-entered origin, required, and validated server-side;
//   - labels ride the canonical X-Yabanin-Labels grammar server-side;
//     entries outside it drop and come back in dropped_labels (rendered,
//     never silently ignored).

import { fetchJSON, type RequestOptions } from './http.ts'

// The FULL six-agent set: every client the
// API renders (services/admin/handlers/client_config_handlers.go
// clientConfigAgents) and the CLI guides (`yb client-config --client …`) is
// guided here too — the handler test and the clientConfig contract test pin
// the three sets to the same list.
export const GUIDED_AGENTS = ['claude-code', 'codex', 'opencode', 'continue', 'cline', 'aider'] as const
export type GuidedAgent = (typeof GUIDED_AGENTS)[number]

export function isGuidedAgent(v: string): v is GuidedAgent {
  return (GUIDED_AGENTS as readonly string[]).includes(v)
}

export interface ClientConfigParams {
  /** Gateway origin as the operator enters it (scheme + host[, port]); the
      server-side renderers normalize the /v1 suffix. */
  baseURL: string
  /** Env var the client reads the gateway key from (default YABANIN_API_KEY). */
  keyEnv?: string
  /** Optional default model id. */
  model?: string
  /** Optional scope labels rendered into the config (X-Yabanin-Labels). */
  labels?: Record<string, string>
}

/** One label dropped by the server's grammar check (key + why). */
export interface DroppedLabel {
  key: string
  reason: string
}

/** GET /api/client-config/{agent} payload — the render + its metadata. */
export interface ClientConfigResult {
  agent: GuidedAgent
  /** 'shell' | 'toml' | 'json' — how the config block is meant to be read. */
  format: string
  /** Where the block goes, verbatim from the server (docs/clients parity). */
  path: string
  /** The exact text to copy — byte-identical to pkg/clientconfig output. */
  config: string
  /** The effective env var name (defaults resolved server-side). */
  key_env: string
  /** Labels outside the canonical grammar: dropped, with a reason each. */
  dropped_labels?: DroppedLabel[]
}

/** encodeLabelsQuery renders the labels param in the canonical k=v,k=v form
 * (sorted keys; values percent-encoded per query semantics — the server
 * decodes and re-validates through pkg/labels). */
export function encodeLabelsQuery(labels: Record<string, string>): string {
  const entries = Object.entries(labels).filter(([, v]) => v !== undefined && v !== null)
  if (entries.length === 0) return ''
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return entries.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join(',')
}

/** Fetch the server-side render for one agent (unknown agents 404; invalid
 * params 400 — both surface as ApiError to the caller). */
export async function getClientConfig(
  agent: GuidedAgent, params: ClientConfigParams, opts?: RequestOptions,
): Promise<ClientConfigResult> {
  const q = new URLSearchParams({ base_url: params.baseURL })
  if (params.keyEnv?.trim()) q.set('key_env', params.keyEnv.trim())
  if (params.model?.trim()) q.set('model', params.model.trim())
  const labels = params.labels ? encodeLabelsQuery(params.labels) : ''
  if (labels) q.set('labels', labels)
  return fetchJSON<ClientConfigResult>(`/client-config/${encodeURIComponent(agent)}?${q}`, opts)
}

/** The full copy block for one agent: the server-rendered config under its
 * path comment, plus the env-var reminder the docs carry (the key lives in
 * the environment, never in the config file). */
export function agentCopyBlock(result: ClientConfigResult): string {
  const head = `# ${result.path}\n`
  const envNote = result.agent === 'codex'
    ? `\n# environment (not the config file)\nexport ${result.key_env}='yb_…'\n`
    : ''
  return `${head}${result.config}${envNote}`
}

/** The gateway-side check style per agent (docs/clients/*.md «Check»):
 * Claude Code authenticates with x-api-key + anthropic-version, every other
 * guided client with a Bearer authorization header. */
export function agentTestAuth(agent: GuidedAgent): { header: 'x-api-key' | 'authorization'; extra?: Record<string, string> } {
  switch (agent) {
    case 'claude-code': return { header: 'x-api-key', extra: { 'anthropic-version': '2023-06-01' } }
    case 'codex': return { header: 'authorization' }
    case 'opencode': return { header: 'authorization' }
    case 'continue': return { header: 'authorization' }
    case 'cline': return { header: 'authorization' }
    case 'aider': return { header: 'authorization' }
  }
}

/** Mirror of clientconfig.withV1 for the browser-side /v1/models test URL. */
export function withV1(base: string): string {
  const trimmed = base.trim().replace(/\/+$/, '')
  return trimmed.endsWith('/v1') ? trimmed : `${trimmed}/v1`
}

/** The /v1/models URL the test-connection action calls. */
export function agentTestURL(baseURL: string): string {
  return `${withV1(baseURL)}/models`
}
