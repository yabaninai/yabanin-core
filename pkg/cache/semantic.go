// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	pgxpool "github.com/jackc/pgx/v5/pgxpool"
)

// ErrMiss reports that no semantically similar entry was found.
var ErrMiss = errors.New("cache miss")

const (
	// DefaultSimilarityThreshold is the default cosine similarity threshold for semantic search.
	DefaultSimilarityThreshold = 0.95

	// DefaultEFSearch is the default HNSW ef_search runtime parameter.
	DefaultEFSearch = 100
)

// SemanticCache wraps pgvector ANN search with embedding and threshold filtering.
type SemanticCache struct {
	pool      *pgxpool.Pool
	threshold float32 // cosine similarity (1.0 = exact match)
	efSearch  int
	// admissionVer is the stable stamp of the similarity-admission rule
	// THIS instance applies, computed once by NewSemanticCache from the
	// resolved (threshold, efSearch) pair; see AdmissionVersion.
	admissionVer string
}

// NewSemanticCache creates a new semantic cache backed by the given pgx pool.
func NewSemanticCache(pool *pgxpool.Pool, threshold float32, efSearch int) *SemanticCache {
	if threshold == 0 {
		threshold = DefaultSimilarityThreshold
	}
	if efSearch == 0 {
		efSearch = DefaultEFSearch
	}
	return &SemanticCache{
		pool:         pool,
		threshold:    threshold,
		efSearch:     efSearch,
		admissionVer: semanticAdmissionVersion(threshold, efSearch),
	}
}

// semanticAdmissionVersion formats the stable admission-rule stamp for a
// resolved (threshold, ef) pair. One format for every stamp: the package
// default and per-instance versions must stay byte-comparable for SpaceMatch.
func semanticAdmissionVersion(threshold float32, efSearch int) string {
	return fmt.Sprintf("sem1:%.4f:cosine:%d", threshold, efSearch)
}

// SemanticAdmissionVersion returns the stable identifier of the
// similarity-admission rule (cosine threshold + HNSW ef) applied by the
// package-default semantic configuration (N03-P04-T02: versioned
// thresholds). The writer stamps it into every entry's provenance and the
// semantic lookup only serves entries whose stamped rule equals the current
// one — so a threshold change starts a new, cleanly attributable entry
// epoch instead of mixing admission regimes inside one index. Bump the
// prefix (sem1 → sem2) if the rule's MEANING ever changes in a way the
// parameters alone do not express.
//
// This is the stamp of the PACKAGE DEFAULTS (0.95 / 100). A semantic cache
// built with explicit non-default parameters must stamp its own rule via
// (*SemanticCache).AdmissionVersion — a mismatched stamp would misattribute
// entries across admission regimes.
func SemanticAdmissionVersion() string {
	return semanticAdmissionVersion(DefaultSimilarityThreshold, DefaultEFSearch)
}

// AdmissionVersion returns the stable identifier of the similarity-admission
// rule THIS instance applies (constructor-computed from its resolved
// threshold and ef_search). For the production defaults — NewSemanticCache
// called with zero values — it is byte-identical to
// SemanticAdmissionVersion(), so entries stamped before per-instance rules
// existed stay compatible (SpaceMatch). A non-default rule yields a
// different stamp, so cross-rule semantic lookups degrade to self-healing
// misses instead of serving entries admitted under another regime.
func (s *SemanticCache) AdmissionVersion() string {
	if s == nil {
		return SemanticAdmissionVersion()
	}
	if s.admissionVer == "" {
		// Zero-value construction (bypassing NewSemanticCache): stamp the
		// rule its fields actually express, never pretend the defaults.
		return semanticAdmissionVersion(s.threshold, s.efSearch)
	}
	return s.admissionVer
}

// LookupResult holds the result of a semantic cache lookup.
type LookupResult struct {
	Entry      *Entry
	Similarity float32 // actual cosine similarity (0..1)
}

// Lookup performs an ANN search for the most similar cached entry.
// modelVer filters by version (use "" to match all versions).
// Returns ErrMiss if no entry is within the similarity threshold.
func (s *SemanticCache) Lookup(ctx context.Context, orgID, modelTier, modelVer string, queryVec []float32) (*LookupResult, error) {
	if len(queryVec) == 0 {
		return nil, ErrMiss
	}

	queryVecSQL, err := vectorToSQL(queryVec)
	if err != nil {
		return nil, fmt.Errorf("convert embedding: %w", err)
	}

	// Build the query with optional model_version filter.
	var whereClauses []string
	var args []interface{}
	argIndex := 1

	whereClauses = append(whereClauses, fmt.Sprintf("org_id = $%d", argIndex))
	args = append(args, orgID)
	argIndex++

	whereClauses = append(whereClauses, fmt.Sprintf("model_tier = $%d", argIndex))
	args = append(args, modelTier)
	argIndex++

	if modelVer != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("model_version = $%d", argIndex))
		args = append(args, modelVer)
		argIndex++
	}

	whereClauses = append(whereClauses, "expires_at > now()")

	query := fmt.Sprintf(`
		SELECT id, org_id, model_tier, prompt_hash, embedding::text, response, sse_chunks,
		       tokens_in, tokens_out, hit_count, model_version, created_at, expires_at,
		       (embedding <=> ($%d)::vector) AS cosine_distance
		FROM cache_entries
		WHERE %s
		ORDER BY cosine_distance ASC
		LIMIT 1
	`, argIndex, joinStrings(whereClauses, " AND "))

	// Append the embedding vector as the last argument.
	args = append(args, queryVecSQL)

	// AF-15: hnsw.ef_search must be in force on the exact connection that
	// runs the ANN search. SET cannot take bind parameters and SET LOCAL is
	// discarded outside a transaction block, so the parameter-safe
	// set_config(..., is_local => true) executes inside this transaction: it
	// applies to this connection and is reverted on commit/rollback, never
	// leaking to the next pool borrower.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("semantic lookup begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit; reverts is_local settings

	if _, err := tx.Exec(ctx, "SELECT set_config('hnsw.ef_search', $1, true)", strconv.Itoa(s.efSearch)); err != nil {
		return nil, fmt.Errorf("apply hnsw.ef_search: %w", err)
	}

	var id, orgIDOut, modelTierOut, promptHash, modelVerOut, embeddingText string
	var response, sseChunks []byte
	var tokensIn, tokensOut, hitCount int
	var createdAt, expiresAt time.Time
	var cosineDistance float64

	err = tx.QueryRow(ctx, query, args...).Scan(
		&id, &orgIDOut, &modelTierOut, &promptHash, &embeddingText,
		&response, &sseChunks, &tokensIn, &tokensOut, &hitCount,
		&modelVerOut, &createdAt, &expiresAt, &cosineDistance,
	)
	if err == pgx.ErrNoRows {
		return nil, ErrMiss
	}
	if err != nil {
		return nil, fmt.Errorf("semantic lookup query: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("semantic lookup commit: %w", err)
	}

	// pgvector `<=>` is cosine DISTANCE (1 - cosine similarity, range 0..2);
	// the bare-operator ORDER BY keeps the HNSW index usable. Convert once,
	// here: 0 distance → similarity 1.0 (identical), 1.0 → 0, 2.0 → -1.
	similarity := cosineDistanceToSimilarity(cosineDistance)
	if similarity < s.threshold {
		return nil, ErrMiss
	}

	entry := &Entry{
		ID:         id,
		OrgID:      orgIDOut,
		ModelTier:  modelTierOut,
		PromptHash: promptHash,
		Response:   response,
		TokensIn:   tokensIn,
		TokensOut:  tokensOut,
		HitCount:   hitCount,
		ModelVer:   modelVerOut,
		CreatedAt:  createdAt,
		ExpiresAt:  expiresAt,
	}

	if len(sseChunks) > 0 {
		entry.SSEChunks = sseChunks
	}

	if embeddingText != "" {
		entry.Embedding, _ = vectorFromSQL(embeddingText) // non-fatal parse error
	}

	go s.incrementHits(ctx, id)

	return &LookupResult{Entry: entry, Similarity: similarity}, nil
}

// cosineDistanceToSimilarity converts a pgvector cosine distance (1 - cosine
// similarity, range 0..2) into cosine similarity (range -1..1). Double
// inverting this value previously served dissimilar prompts as cache hits
// while rejecting near-exact ones.
func cosineDistanceToSimilarity(d float64) float32 {
	return float32(1.0 - d)
}

func (s *SemanticCache) incrementHits(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx, "UPDATE cache_entries SET hit_count = hit_count + 1 WHERE id = $1", id)
}

// joinStrings joins a slice of strings with the given separator.
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += sep + p
	}
	return result
}
