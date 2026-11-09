// Mirror of the API-key label checks in services/admin/handlers/api_key_labels.go
// (A2 §1). The Go handler is the authority: if these disagree, fix this file.

export interface LabelProblem {
  key: string
  reason: string
}

export const MAX_KEY_LABELS = 20
const MAX_KEY_LEN = 63
const MAX_VALUE_LEN = 128
const KEY_RE = /^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$/
const SECRET_RE = /\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b/

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length
}

function normalizeValue(raw: string): { value: string; reason: string } {
  let decoded = raw
  if (raw.includes('%')) {
    try {
      decoded = decodeURIComponent(raw)
    } catch {
      return { value: '', reason: 'invalid_value' }
    }
  }
  decoded = decoded.trim()
  if (!decoded) return { value: '', reason: 'invalid_value' }
  if (byteLength(decoded) > MAX_VALUE_LEN) return { value: '', reason: 'value_too_long' }
  for (const ch of decoded) {
    const code = ch.codePointAt(0) ?? 0
    if (code <= 0x1f || code === 0x7f) return { value: '', reason: 'invalid_value' }
  }
  return { value: decoded, reason: '' }
}

export function validateKeyLabels(input: Record<string, string>): { labels: Record<string, string>; problems: LabelProblem[] } {
  const out: Record<string, string> = {}
  const problems: LabelProblem[] = []
  let accepted = 0
  for (const rawKey of Object.keys(input).sort()) {
    const key = rawKey.trim().toLowerCase()
    if (!key || key.length > MAX_KEY_LEN || key.includes('%') || !KEY_RE.test(key)) {
      problems.push({ key: rawKey, reason: 'invalid_key' })
      continue
    }
    if (key.startsWith('yabanin.')) {
      problems.push({ key, reason: 'reserved' })
      continue
    }
    if (Object.prototype.hasOwnProperty.call(out, key)) {
      problems.push({ key, reason: 'invalid_key' })
      continue
    }
    if (accepted >= MAX_KEY_LABELS) {
      problems.push({ key, reason: 'too_many' })
      continue
    }
    const checked = normalizeValue(input[rawKey] ?? '')
    if (checked.reason) {
      problems.push({ key, reason: checked.reason })
      continue
    }
    if (SECRET_RE.test(checked.value)) {
      problems.push({ key, reason: 'secret_like' })
      continue
    }
    out[key] = checked.value
    accepted++
  }
  return { labels: out, problems }
}
