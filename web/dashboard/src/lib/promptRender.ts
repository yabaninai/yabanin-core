//
// The token grammar and render semantics MIRROR the server's
// adminstore.RenderTemplate (pkg/adminstore/promptstudio.go) exactly:
//   {{ partials.NAME }}  → partial lookup
//   {{ NAME }}           → variable lookup
// NAME is [A-Za-z0-9_.-]+; whitespace inside the braces is allowed; tokens
// that match no grammar (e.g. "{{a b}}", "{{partials.}}") stay verbatim.
// Rendering is ONE left-to-right pass — substituted text is never rescanned,
// so partial cycles are impossible by construction and a body may safely
// contain literal "{{…}}". Missing variables/partials are ERRORS (fail-closed,
// like the server): a half-rendered prompt must never look like a preview.
//
// This module is preview-only. It NEVER calls a model; the gateway render on
// the request path stays the single source of truth for production.

export const TEMPLATE_TOKEN_RE = /\{\{\s*(?:partials\.([A-Za-z0-9_.-]+)|([A-Za-z0-9_.-]+))\s*\}\}/g

/** The reserved partial-reference namespace inside templates. */
export const PARTIALS_TOKEN_PREFIX = 'partials.'

export interface TemplateRenderOk { ok: true; text: string }
export interface TemplateRenderError { ok: false; error: string }
export type TemplateRenderResult = TemplateRenderOk | TemplateRenderError

/** Variable names in first-appearance order (duplicates collapsed; the reserved "partials." namespace excluded — those tokens stay verbatim). */
export function extractTemplateVars(template: string): string[] {
  const names: string[] = []
  const seen = new Set<string>()
  for (const m of template.matchAll(TEMPLATE_TOKEN_RE)) {
    const name = m[2] ?? ''
    if (!name || name.startsWith(PARTIALS_TOKEN_PREFIX) || seen.has(name)) continue
    seen.add(name)
    names.push(name)
  }
  return names
}

/** Referenced partial names in first-appearance order (duplicates collapsed). */
export function extractPartialRefs(template: string): string[] {
  const names: string[] = []
  const seen = new Set<string>()
  for (const m of template.matchAll(TEMPLATE_TOKEN_RE)) {
    const name = m[1] ?? ''
    if (!name || seen.has(name)) continue
    seen.add(name)
    names.push(name)
  }
  return names
}

/** One-pass render identical in semantics to adminstore.RenderTemplate. */
export function renderTemplateClient(
  template: string,
  vars: Record<string, string>,
  partials: Record<string, string>,
): TemplateRenderResult {
  let error = ''
  const out = template.replace(TEMPLATE_TOKEN_RE, (_whole, partialName?: string, varName?: string) => {
    if (partialName !== undefined) {
      if (Object.prototype.hasOwnProperty.call(partials, partialName)) return partials[partialName]!
      error ||= `partial "${partialName}" not found`
      return _whole
    }
    const name = varName ?? ''
    if (name.startsWith(PARTIALS_TOKEN_PREFIX)) return _whole // malformed partial token stays verbatim
    if (Object.prototype.hasOwnProperty.call(vars, name)) return vars[name]!
    error ||= `variable "${name}" is not set`
    return _whole
  })
  if (error) return { ok: false, error }
  return { ok: true, text: out }
}

/** Single-quote shell escaping ('→'\''"), for the generated curl body. */
export function shellSingleQuote(value: string): string {
  return `'${value.split("'").join(`'\\''`)}'`
}

export interface ChatCurlInput {
  /** Gateway origin, e.g. https://gateway.example.test (no path). */
  baseUrl: string
  model: string
  /** The RENDERED template — becomes the system message. */
  system: string
  /** Optional final user message of the sample request. */
  user?: string
}

/**
 * Builds a ready-to-run curl for POST {baseUrl}/v1/chat/completions whose
 * system message is the rendered template. The API key is a shell variable
 * (never a value the UI owns): the operator exports it before running.
 */
export function buildChatCurl(input: ChatCurlInput): string {
  const base = input.baseUrl.trim().replace(/\/+$/, '')
  const messages: Array<{ role: string; content: string }> = [{ role: 'system', content: input.system }]
  if (input.user && input.user.length > 0) messages.push({ role: 'user', content: input.user })
  const payload = JSON.stringify({ model: input.model, messages })
  // Plain concatenation: the line-continuation backslashes stay literal
  // (template literals ending in an escape confuse the node type-stripper).
  return [
    'curl -sS ' + shellSingleQuote(`${base}/v1/chat/completions`) + ' \\',
    "  -H 'Content-Type: application/json' \\",
    "  -H 'Authorization: Bearer '$ROUTER_API_KEY \\",
    '  -d ' + shellSingleQuote(payload),
  ].join('\n')
}

/** First line + ellipsis preview of a multi-line template (list/detail tables). */
export function templatePreview(template: string, max = 96): string {
  const flat = template.replace(/\s+/g, ' ').trim()
  if (flat.length <= max) return flat
  return `${flat.slice(0, max - 1)}…`
}

/**
 * Parses the optional params JSON object of the editor forms: empty text =
 * absent (the server stores '{}'); otherwise it must be a JSON object
 * (the contract of validatePromptParamsBody). Arrays/scalars/invalid → !ok.
 */
export function parseParamsObject(text: string): { ok: true; value?: Record<string, unknown> } | { ok: false } {
  const trimmed = text.trim()
  if (trimmed === '') return { ok: true, value: undefined }
  try {
    const parsed = JSON.parse(trimmed) as unknown
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false }
    return { ok: true, value: parsed as Record<string, unknown> }
  } catch {
    return { ok: false }
  }
}
