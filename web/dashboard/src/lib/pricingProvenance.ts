// provenance label — "<source> <date> sha256:<hex>" (pkg/adminstore/
// cost_analytics.go builds it from the file pricer's provenance), where the
// source is either a pinned upstream URL like
// "github.com/BerriAI/litellm@61a73c5…/model_prices_and_context_window.json"
// or, since CORE-REF-04, the served reference catalog's version identifier
// "yabanin-catalog@<version>". Interpolated verbatim into a KPI card line a
// label carries ~170-character unbreakable tokens and widens the document
// past the viewport. Surfaces show a SHORT collapsed ref + snapshot date and
// reveal the full label on demand (ProvenanceNote); parsePricingProvenance
// does the split. Tolerant by contract: any piece may be absent, `raw`
// always carries the verbatim backend label.
//
// Catalog labels additionally expose the structured citation (catalog
// version + sealed-digest prefix); collapsedProvenanceRef renders the
// collapsed node as `catalog:<version> digest:<hex-prefix>` for them.

export interface CatalogProvenance {
  /** Sealed catalog version from the `yabanin-catalog@<version>` source. */
  version: string
  /** First ≤7 hex chars of the sealed catalog digest. */
  digestPrefix: string
}

export interface PricingProvenance {
  /** The raw backend label, verbatim — the disclosure shows it in full. */
  raw: string
  /** The snapshot source: the label minus the date and sha256 tokens. */
  source: string
  /** Snapshot date (YYYY-MM-DD) when the label carries one. */
  date?: string
  /** sha256 fingerprint token ("sha256:<hex>") when present. */
  sha256?: string
  /** Short pinned ref (≤7 chars): the commit after '@', else the sha256 prefix. */
  ref?: string
  /** Structured catalog citation when the source names a yabanin catalog. */
  catalog?: CatalogProvenance
}

const SHA_RE = /sha256:[0-9a-fA-F]+/
const DATE_RE = /\b\d{4}-\d{2}-\d{2}\b/
const CATALOG_RE = /^yabanin-catalog@(\S+)$/
const SEALED_DIGEST_LEN = 64
const SHORT_REF_LEN = 7

export function parsePricingProvenance(raw: string): PricingProvenance {
  const text = raw.trim()
  const sha = text.match(SHA_RE)?.[0]
  const date = text.match(DATE_RE)?.[0]
  let source = text
  if (sha) source = source.replace(sha, '')
  if (date) source = source.replace(date, '')
  source = source.replace(/\s+/g, ' ').trim()
  let ref: string | undefined
  const commit = source.match(/@([^/\s]+)/)?.[1]
  if (commit) ref = commit.slice(0, SHORT_REF_LEN)
  else if (sha) ref = sha.slice('sha256:'.length, 'sha256:'.length + SHORT_REF_LEN)
  let catalog: CatalogProvenance | undefined
  const cat = source.match(CATALOG_RE)?.[1]
  const digestHex = sha?.slice('sha256:'.length)
  if (cat && digestHex && digestHex.length === SEALED_DIGEST_LEN) {
    catalog = { version: cat, digestPrefix: digestHex.slice(0, SHORT_REF_LEN) }
  }
  return { raw: text, source, date, sha256: sha, ref, catalog }
}

/**
 * The collapsed provenance node: `catalog:<version> digest:<hex-prefix>` for
 * catalog labels (CORE-REF-04), else the plain short ref; undefined when
 * there is nothing pinned to show.
 */
export function collapsedProvenanceRef(p: PricingProvenance): string | undefined {
  if (p.catalog) return `catalog:${p.catalog.version} digest:${p.catalog.digestPrefix}`
  return p.ref
}

/**
 * The catalog node from structured backend metadata
 * (PricingMetadata.pricing_catalog, pkg/adminstore/savings.go) — preferred
 * over label parsing when the payload carries it.
 */
export function catalogNodeRef(catalog: { version: string; digest: string }): string {
  return `catalog:${catalog.version} digest:${catalog.digest.slice(0, SHORT_REF_LEN)}`
}
