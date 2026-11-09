// Package cache provides pg-backed semantic cache storage with vector embedding support.
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	pgxpool "github.com/jackc/pgx/v5/pgxpool"
)

// Entry represents a single cached LLM response with its embedding.
type Entry struct {
	ID         string          `json:"id"`
	OrgID      string          `json:"org_id"`
	ModelTier  string          `json:"model_tier"`
	PromptHash string          `json:"prompt_hash"`
	Embedding  []float32       `json:"-"` // stored as pgvector, not serialized
	Response   json.RawMessage `json:"response"`
	SSEChunks  json.RawMessage `json:"sse_chunks,omitempty"`
	TokensIn   int             `json:"tokens_in"`
	TokensOut  int             `json:"tokens_out"`
	HitCount   int             `json:"hit_count"`
	ModelVer   string          `json:"model_version"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
}

// Store is a pgx-based interface for semantic cache entries.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new cache store backed by the given pgx pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Put inserts or updates a cache entry. Returns the entry ID.
func (s *Store) Put(ctx context.Context, e *Entry) (string, error) {
	embeddingSQL, err := vectorToSQL(e.Embedding)
	if err != nil {
		return "", fmt.Errorf("convert embedding to pgvector: %w", err)
	}

	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO cache_entries (org_id, model_tier, prompt_hash, embedding, response, sse_chunks,
		                           tokens_in, tokens_out, hit_count, model_version, created_at, expires_at)
		VALUES ($1, $2, $3, $4::vector, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (org_id, model_tier, prompt_hash, model_version)
		DO UPDATE SET embedding = EXCLUDED.embedding,
		              response = EXCLUDED.response,
		              sse_chunks = EXCLUDED.sse_chunks,
		              tokens_in = EXCLUDED.tokens_in,
		              tokens_out = EXCLUDED.tokens_out,
		              expires_at = EXCLUDED.expires_at
		RETURNING id
	`,
		e.OrgID, e.ModelTier, e.PromptHash, embeddingSQL,
		e.Response, e.SSEChunks,
		e.TokensIn, e.TokensOut, e.HitCount, e.ModelVer,
		e.CreatedAt, e.ExpiresAt,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("put cache entry: %w", err)
	}
	return id, nil
}

// GetExact looks up a cache entry by org_id, model_tier and prompt_hash.
// Returns (nil, nil) on miss.
func (s *Store) GetExact(ctx context.Context, orgID, modelTier, promptHash, modelVer string) (*Entry, error) {
	e, err := s.scanOne(ctx, `
		SELECT id, org_id, model_tier, prompt_hash, embedding::text, response, sse_chunks,
		       tokens_in, tokens_out, hit_count, model_version, created_at, expires_at
		FROM cache_entries
		WHERE org_id = $1 AND model_tier = $2 AND prompt_hash = $3 AND model_version = $4
		  AND expires_at > now()
	`, orgID, modelTier, promptHash, modelVer)
	if err != nil {
		return nil, fmt.Errorf("get exact cache: %w", err)
	}

	if e != nil {
		go s.incrementHits(ctx, e.ID)
	}

	return e, nil
}

// GetSemantic finds the most similar cache entry by embedding cosine distance.
// Returns (nil, nil) if no entry is within threshold or no entries exist.
func (s *Store) GetSemantic(ctx context.Context, orgID, modelTier string, embedding []float32, threshold float64) (*Entry, error) {
	if len(embedding) == 0 {
		return nil, nil //nolint:nilnil // documented: empty embedding is a miss, not an error
	}

	embeddingSQL, err := vectorToSQL(embedding)
	if err != nil {
		return nil, fmt.Errorf("convert embedding to pgvector: %w", err)
	}

	e, err := s.scanOne(ctx, `
		SELECT id, org_id, model_tier, prompt_hash, embedding::text, response, sse_chunks,
		       tokens_in, tokens_out, hit_count, model_version, created_at, expires_at
		FROM cache_entries
		WHERE org_id = $1 AND model_tier = $2 AND expires_at > now()
		ORDER BY embedding <=> ($3)::vector
		LIMIT 1
	`, orgID, modelTier, embeddingSQL)
	if err != nil {
		return nil, fmt.Errorf("get semantic cache: %w", err)
	}

	if e != nil {
		dist := SquaredL2Distance(e.Embedding, embedding)
		if dist > threshold {
			return nil, nil //nolint:nilnil // documented: below-threshold is a miss, not an error
		}
		go s.incrementHits(ctx, e.ID)
	}

	return e, nil
}

// IncrementHits atomically increments the hit_count for a cache entry.
func (s *Store) IncrementHits(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "UPDATE cache_entries SET hit_count = hit_count + 1 WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("increment hits: %w", err)
	}
	return nil
}

// Delete removes a cache entry by ID.
func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM cache_entries WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete cache entry: %w", err)
	}
	return nil
}

// PurgeExpired removes all entries past their expires_at. Returns count deleted.
func (s *Store) PurgeExpired(ctx context.Context) (int, error) {
	result, err := s.pool.Exec(ctx, "DELETE FROM cache_entries WHERE expires_at <= now()")
	if err != nil {
		return 0, fmt.Errorf("purge expired: %w", err)
	}
	return int(result.RowsAffected()), nil
}

// PurgeExpiredWithLock removes expired entries using pg_try_advisory_xact_lock
// for safe multi-replica cleanup. Returns (deleted_count, lock_acquired).
const cachePurgeLockID = 42 // consistent across all replicas

// PurgeExpiredWithLock is exported so the cleaner can use it directly.
func (s *Store) PurgeExpiredWithLock(ctx context.Context) (int, bool, error) {
	// Start a transaction: advisory lock auto-releases on commit/rollback.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("purge with lock begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit; releases the advisory lock on error paths

	var gotLock bool
	err = tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", cachePurgeLockID).Scan(&gotLock)
	if err != nil {
		return 0, false, fmt.Errorf("purge with lock acquire: %w", err)
	}

	if !gotLock {
		// Another replica holds the lock — skip this cycle.
		return 0, false, nil
	}

	result, err := tx.Exec(ctx, "DELETE FROM cache_entries WHERE expires_at <= now()")
	if err != nil {
		return 0, false, fmt.Errorf("purge with lock delete: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, false, fmt.Errorf("purge with lock commit: %w", err)
	}

	return int(result.RowsAffected()), true, nil
}

// scanOne executes a query that returns at most one cache entry and deserializes it.
func (s *Store) scanOne(ctx context.Context, sql string, args ...interface{}) (*Entry, error) {
	var id, orgID, modelTier, promptHash, modelVer string
	var embeddingText string
	var response, sseChunks []byte
	var tokensIn, tokensOut, hitCount int
	var createdAt, expiresAt time.Time

	err := s.pool.QueryRow(ctx, sql, args...).Scan(
		&id, &orgID, &modelTier, &promptHash, &embeddingText,
		&response, &sseChunks, &tokensIn, &tokensOut, &hitCount,
		&modelVer, &createdAt, &expiresAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil //nolint:nilnil // documented: no row is a cache miss, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("scan cache entry: %w", err)
	}

	e := &Entry{
		ID:         id,
		OrgID:      orgID,
		ModelTier:  modelTier,
		PromptHash: promptHash,
		Response:   response,
		TokensIn:   tokensIn,
		TokensOut:  tokensOut,
		HitCount:   hitCount,
		ModelVer:   modelVer,
		CreatedAt:  createdAt,
		ExpiresAt:  expiresAt,
	}

	if len(sseChunks) > 0 {
		e.SSEChunks = sseChunks
	}

	if embeddingText != "" {
		e.Embedding, err = vectorFromSQL(embeddingText)
		if err != nil {
			return nil, fmt.Errorf("parse embedding from pgvector text: %w", err)
		}
	}

	return e, nil
}

func (s *Store) incrementHits(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx, "UPDATE cache_entries SET hit_count = hit_count + 1 WHERE id = $1", id)
}

// ---------------------------------------------------------------------------
// pgvector helpers: convert between Go []float32 and PostgreSQL vector text.
// ---------------------------------------------------------------------------

func vectorToSQL(v []float32) (string, error) {
	if len(v) == 0 {
		return "", fmt.Errorf("embedding must have at least one dimension")
	}
	b := make([]byte, 0, len(v)*10)
	b = append(b, '[')
	for i, f := range v {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendFloat32(b, f)
	}
	b = append(b, ']')
	return string(b), nil
}

func vectorFromSQL(s string) ([]float32, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return nil, fmt.Errorf("invalid pgvector text: %q", s)
	}
	s = s[1 : len(s)-1]
	parts := strings.Split(s, ",")
	v := make([]float32, 0, len(parts))
	for _, p := range parts {
		f, err := parseFloat32(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("parse vector element %q: %w", p, err)
		}
		v = append(v, f)
	}
	return v, nil
}

// SquaredL2Distance computes the squared L2 distance between two embeddings:
// Σ(aᵢ-bᵢ)², no sqrt. It is monotonic with the pgvector `<=>` cosine distance
// for unit vectors (L2² = 2 - 2·cos_sim), which is what pgvector-indexed
// embeddings are. Exported so the offline audit simulator (pkg/costsim) can
// reuse the production distance metric — one implementation, not a copy.
// Convert to similarity with sim = 1 - d/2 (see pkg/costsim/simcache.go).
func SquaredL2Distance(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 1e9
	}
	var sumSq float64
	for i := range a {
		d := float64(a[i] - b[i])
		sumSq += d * d
	}
	return sumSq
}

func appendFloat32(b []byte, f float32) []byte {
	if f == 0 {
		return append(b, '0')
	}
	s := fmt.Sprintf("%.6g", f)
	return append(b, s...)
}

func parseFloat32(s string) (float32, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	if err != nil {
		return 0, err
	}
	return float32(f), nil
}
