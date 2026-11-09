// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// RouteVersion is the cache route-identity namespace (RT-05). It follows the
// affinity store's "v2" precedent: bumping the constant moves every new entry
// into a fresh key/value namespace, so entries written before the bump (or by
// a route layout this build does not understand) are never read again — a
// safe, silent miss and refill. Legacy keys are neither read nor deleted by
// this code: they expire through their existing TTL. FLUSHDB and cross-key
// cleanup stay out of the request path.
//
// v3 (CACHE-02, hashing guard): normalization stopped collapsing number
// literals through float64 (2^53+1 no longer rewrites to 2^53; 1e3 stays 1e3).
// An entry sealed under v2 normalization can no longer be reproduced by v3
// lookups of a sibling literal — but the reverse reach existed: a v2 entry
// written for literal L was keyed by the collapsed bytes of L, and a v3
// lookup of that collapsed spelling produced exactly those bytes. The bump
// makes every pre-v3 entry unreachable in one step across the exact hash,
// the pg exact version column, the semantic version filter and the sealed
// provenance version — one constant instead of per-layer migrations.
const RouteVersion = "v3"

// RouteIdentity is the unified lookup/store contract for cache entries
// (RT-05): the org that owns the entry, the canonical route model that
// generated (and may consume) the response, the route namespace version, and
// the canonical generation-affecting parameters the gateway injected for the
// winning candidate (e.g. reasoning effort). Lookup and Write must use the
// same identity for the same logical cache slot; an entry whose recorded
// provenance does not match the lookup identity is a miss, never a hit under
// an old route.
type RouteIdentity struct {
	// OrgID is the tenant that owns the entry. Never empty on the request path.
	OrgID string
	// Model is the canonical route model — the model that actually generated
	// the response and the model the current route resolved to.
	Model string
	// Version is the route namespace; empty means RouteVersion.
	Version string
	// GenParams is the canonical string of generation-affecting parameters
	// ("" when the route injects none). Responses generated under a
	// different parameter set are not interchangeable.
	GenParams string
	// Upstream is the endpoint-revision component (audit H1): a one-way
	// fingerprint (UpstreamFingerprint) of the provider + effective base URL
	// the response was generated against. Entries whose identity agrees on
	// model/org/params but were produced by a different upstream endpoint
	// (provider re-point, base-URL rotation, provider swap under one model
	// name) are not interchangeable. Strict equality including the empty
	// string (SpaceMatch precedent): pinned lookups never match entries
	// without the component and vice versa — pre-H1 entries degrade to
	// self-healing misses; two component-blind sides ("" == "", test stubs
	// and doubles) remain compatible.
	Upstream string
}

// Resolved returns the identity with the route namespace defaulted.
func (ri RouteIdentity) Resolved() RouteIdentity {
	if ri.Version == "" {
		ri.Version = RouteVersion
	}
	return ri
}

// Provenance records how a cache entry was produced. It is stored with the
// entry and verified on every hit so the served response can always be
// attributed to the model that actually generated it, under the route and
// policies current at lookup time. Entries without a verifiable provenance
// (legacy raw payloads, foreign formats) are treated as misses.
type Provenance struct {
	OrgID     string `json:"org"`
	ModelUsed string `json:"model_used"`
	Version   string `json:"route"`
	GenParams string `json:"gen,omitempty"`
	// EmbedVer identifies the embedding space (embedder model + query
	// prefix, see embeddings.SpaceVersioner) the entry's stored vector was
	// produced in. Empty means a legacy entry written before embedding-space
	// versioning (N03-P04-T02) or an entry written by a version-blind
	// embedder. Compared on the semantic path only: exact layers are
	// prompt-hash keyed and never compare vectors.
	EmbedVer string `json:"embed_ver,omitempty"`
	// ThresholdVer identifies the similarity-admission rule (threshold,
	// metric, ef) in force when the entry was written. Serving an entry
	// under a different admission regime than the one that produced it
	// would make hit-rate and confusion measurements incomparable across
	// the change; a strict-equality check degrades such entries to
	// self-healing misses instead. Semantic path only, same as EmbedVer.
	ThresholdVer string `json:"threshold_ver,omitempty"`
	// DecisiveVer identifies the decisive-content detector version whose
	// one-way fingerprint this entry carries (N03-P04-T05; "dc1"). Empty on
	// entries written before the guard or by writers that do not stamp;
	// such entries are never compatible with a versioning lookup
	// (Provenance.DecisiveMatch) and degrade to self-healing misses.
	// Semantic path only, same as EmbedVer.
	DecisiveVer string `json:"decisive_ver,omitempty"`
	// DecisiveFP is a one-way (sha256-based) fingerprint of the prompt's
	// decisive content — dates, numbers, entities, access markers — computed
	// by the writer over the normalized prompt. Stored as a hash: the cache
	// never stores prompt text, and this field must not become a way to
	// reconstruct it. Semantic path only, same as EmbedVer.
	DecisiveFP string `json:"decisive_fp,omitempty"`
	// Upstream is the endpoint-revision fingerprint stamped at write time
	// (audit H1; see RouteIdentity.Upstream). Empty on entries written
	// before the guard or by component-blind writers (test doubles); a
	// pinned lookup degrades such entries to misses (Matches).
	Upstream string `json:"up,omitempty"`
}

// cacheEnvelope is the on-disk (Redis value / pgvector response column)
// wrapper that carries the provenance next to the cached completion
// document.
type cacheEnvelope struct {
	Route string          `json:"route"`
	Prov  Provenance      `json:"prov"`
	Data  json.RawMessage `json:"data"`
}

// SealEntry wraps a cached completion document with its route provenance.
// The sealed bytes are the value stored in Redis (and the pgvector response
// column); an entry that cannot carry a provenance must not be stored at all.
func SealEntry(data []byte, ri RouteIdentity) ([]byte, error) {
	return SealEntryVersioned(data, ri, "", "")
}

// SealEntryVersioned seals a cached completion document with its route
// provenance plus the embedding-space and threshold-admission versions
// current at write time (N03-P04-T02). The cache looks up entries only when
// both versions match its current configuration (SpaceMatch); entries
// sealed by this function's legacy twin carry empty versions and stay
// compatible only with version-blind lookups. No decisive-content stamp is
// recorded — use SealEntryVersionedContent when the writer can compute one;
// entries sealed here degrade to misses under the T05 admission guard.
func SealEntryVersioned(data []byte, ri RouteIdentity, embedVer, thresholdVer string) ([]byte, error) {
	return SealEntryVersionedContent(data, ri, embedVer, thresholdVer, "", "")
}

// SealEntryVersionedContent seals a cached completion document with its
// route provenance, the embedding-space and threshold-admission versions
// (N03-P04-T02) and the decisive-content stamp (N03-P04-T05) current at
// write time. decisiveVer/decisiveFP are the output of DecisiveContentStamp
// over the same normalized prompt the entry is keyed by; the lookup-side
// guard recomputes that stamp from the lookup prompt and serves the entry
// only when both halves match. The decisive stamp is a one-way fingerprint:
// no prompt text is stored.
func SealEntryVersionedContent(data []byte, ri RouteIdentity, embedVer, thresholdVer, decisiveVer, decisiveFP string) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("seal cache entry: empty response")
	}
	ri = ri.Resolved()
	sealed, err := json.Marshal(cacheEnvelope{
		Route: ri.Version,
		Prov: Provenance{
			OrgID:        ri.OrgID,
			ModelUsed:    ri.Model,
			Version:      ri.Version,
			GenParams:    ri.GenParams,
			Upstream:     ri.Upstream,
			EmbedVer:     embedVer,
			ThresholdVer: thresholdVer,
			DecisiveVer:  decisiveVer,
			DecisiveFP:   decisiveFP,
		},
		Data: data,
	})
	if err != nil {
		return nil, fmt.Errorf("seal cache entry: %w", err)
	}
	return sealed, nil
}

// OpenEntry unwraps sealed cache bytes. ok=false reports bytes that are not a
// verifiable sealed entry — legacy raw payloads, foreign formats, truncated
// documents. Callers must treat them as a cache miss: an entry without a
// trustworthy provenance must never be served.
func OpenEntry(raw []byte) (prov Provenance, data json.RawMessage, ok bool) {
	var env cacheEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Provenance{}, nil, false
	}
	if env.Route == "" || env.Prov.ModelUsed == "" || env.Prov.OrgID == "" || len(env.Data) == 0 {
		return Provenance{}, nil, false
	}
	return env.Prov, env.Data, true
}

// Matches reports whether a sealed entry's provenance is compatible with the
// route identity performing the lookup. Every field must agree: a mismatch
// means the entry was produced by a different route (model, generation
// parameters, upstream endpoint) or namespace and must not be served. The
// Upstream comparison is strict equality including the empty string: a
// pinned lookup (endpoint-revision guard, H1) is never compatible with an
// entry that carries no fingerprint (pre-guard or component-blind writer) —
// such entries degrade to self-healing misses — and two component-blind
// sides ("" == "") remain compatible, preserving test-doubles behavior
// (SpaceMatch precedent).
func (p Provenance) Matches(ri RouteIdentity) bool {
	ri = ri.Resolved()
	return p.Version == ri.Version &&
		p.OrgID == ri.OrgID &&
		p.ModelUsed == ri.Model &&
		p.GenParams == ri.GenParams &&
		p.Upstream == ri.Upstream
}

// SpaceMatch reports whether a sealed entry's embedding-space and
// threshold-admission versions are compatible with the versions current at
// lookup time (N03-P04-T02). The comparison is strict equality, including
// the empty string: a versioning lookup is never compatible with an entry
// whose space is unknown (legacy or version-blind writer) — such entries
// degrade to safe, self-healing misses and are re-stamped on refill. Two
// version-blind sides ("" == "") remain compatible, which preserves the
// existing behavior of test stubs and embedders that cannot identify their
// space. Exact-cache layers must not consult this check: they are
// prompt-hash keyed and never compare vectors.
func (p Provenance) SpaceMatch(embedVer, thresholdVer string) bool {
	return p.EmbedVer == embedVer && p.ThresholdVer == thresholdVer
}

// UpstreamFingerprint derives the endpoint-revision component of the cache
// route identity (audit H1): a one-way (sha256-based) fingerprint of the
// provider name and effective base URL a response is generated against.
// Stamped on write and compared on lookup, so a re-pointed or rotated
// endpoint (provider re-point, base-URL change, provider swap under one
// model name) degrades warm entries to self-healing misses instead of
// serving answers from the old endpoint. Hash, not raw URL: the cache never
// stores endpoint configuration and this component must not become a way to
// read it. The upstream API key is deliberately excluded — rotating a key
// does not change the answers an endpoint produces, so key rotation must not
// invalidate warm entries. Stable output: the same (provider, url) pair
// always maps to the same fingerprint within a build.
func UpstreamFingerprint(provider, baseURL string) string {
	h := sha256.Sum256([]byte(provider + "\n" + baseURL))
	return "u1:" + hex.EncodeToString(h[:16])
}
