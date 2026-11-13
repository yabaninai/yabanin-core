// Pseudo-localization is QA-only and must never cost the production
// entry anything: the stretched bundle is derived from `en` on demand (when a
// QA request selects ?locale=pseudo), not built eagerly at module load.
//
// The stretch contract is unchanged: deterministic middle padding
// (stable across runs — the pseudo gate compares rendered text between
// locales), wrapping every string in «…». Pseudo text must NEVER ship to a
// real locale — it only exercises layout under longer strings.

const PSEUDO_FACTOR = 1.4

// Deterministic stretch: pad the middle of the string so the result is
// stable across runs (the gate compares rendered text between locales).
function stretch(s: string): string {
  if (!s) return s
  const pad = Math.max(0, Math.round(s.length * (PSEUDO_FACTOR - 1)))
  const half = Math.ceil(pad / 2)
  const filler = 'á'.repeat(half) + 'é'.repeat(pad - half)
  return s.slice(0, Math.ceil(s.length / 2)) + filler + s.slice(Math.ceil(s.length / 2))
}

// Structurally identical to `en` (same keys, stretched strings); typed as an
// open record so the per-section union inference does not fight the cast.
export function buildPseudo(en: Record<string, unknown>): Record<string, Record<string, string>> {
  const pseudo: Record<string, Record<string, string>> = {}
  for (const section of Object.keys(en)) {
    const values = en[section] as unknown as Record<string, string>
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(values)) {
      out[k] = typeof v === 'string' ? `«${stretch(v)}»` : v
    }
    pseudo[section] = out
  }
  return pseudo
}
