package adminstore

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/kms"
)

// ErrNotFound is the canonical "entity does not exist" sentinel.
// Store adapters return it (wrapping pgx.ErrNoRows); admin handlers map
// it to HTTP 404 via errors.Is.
var ErrNotFound = errors.New("not found")

// IsNotFound reports whether err is (or wraps) ErrNotFound or pgx.ErrNoRows.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows)
}

// AdminUser represents an admin panel user.
type AdminUser struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	IsRoot      bool      `json:"is_root"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Organization represents an organization.
type Organization struct {
	ID                         string    `json:"id"`
	Name                       string    `json:"name"`
	Slug                       string    `json:"slug"`
	CreatedAt                  time.Time `json:"created_at"`
	CacheMode                  string    `json:"cache_mode"`
	CacheEnabled               bool      `json:"cache_enabled"`
	RoutingMode                string    `json:"routing_mode"`
	RoutingThresholdConfidence float64   `json:"routing_threshold_confidence"`
	// Currency is the ISO-4217 code used to present costs for this org
	// (default "USD"). Timezone is an IANA name used for billing-day
	// bucketing and date labels (default "UTC"). See pkg/i18n for the
	// helpers that consume these (I18N-11).
	Currency string `json:"currency"`
	Timezone string `json:"timezone"`
	// IssueURLTemplate is an https URL containing {issue}. Empty means unset.
	IssueURLTemplate string `json:"issue_url_template,omitempty"`
	// GraceFloorCents is the per-org grace floor (ADR-0001 §8; NEXT-18f).
	// nil = platform default. Listed for root org tables; the authoritative
	// read/write path is the org budget settings API (org_credits row).
	GraceFloorCents *int64 `json:"grace_floor_cents,omitempty"`
}

// Team represents a team within an organization.
type Team struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	Name       string    `json:"name"`
	Slug       string    `json:"slug"`
	ParentTeam *string   `json:"parent_team,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// APIKey represents an API key.
//
// W-SECADM: KeyHash is internal-only (`json:"-"`) — the sha256 material never
// that answer HTTP requests report HasHash instead.
type APIKey struct {
	ID              string            `json:"id"`
	KeyHash         string            `json:"-"`
	HasHash         bool              `json:"has_hash"`
	OrgID           *string           `json:"org_id,omitempty"`
	TeamID          *string           `json:"team_id,omitempty"`
	Name            string            `json:"name"`
	Active          bool              `json:"active"`
	CreatedAt       time.Time         `json:"created_at"`
	Labels          map[string]string `json:"labels"`
	LabelsLocked    bool              `json:"labels_locked"`
	CanMintSessions bool              `json:"can_mint_sessions"`
	CanReadUsage    bool              `json:"can_read_usage"`
	// never used); ExpiresAt NULL = the key never expires.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	// keys get a SHORTER Retry-After on a 429, so they poll sooner and win
	// freed window capacity first. This is ordering in the reject policy —
	// not a preemptive scheduler, and there is no admission queue.
	Priority int `json:"priority"`
}

// ModelRegistry represents a model entry.
//
// serializes upstream key material. Callers that answer HTTP requests report
// HasUpstreamKey instead.
type ModelRegistry struct {
	ID                string    `json:"id"`
	ModelName         string    `json:"model_name"`
	DisplayName       string    `json:"display_name"`
	Tier              string    `json:"tier"`
	UpstreamURL       *string   `json:"upstream_url,omitempty"`
	UpstreamAPIKey    *string   `json:"-"`
	HasUpstreamKey    bool      `json:"has_key"`
	Provider          string    `json:"provider"`
	FallbackModel     *string   `json:"fallback_model,omitempty"`
	FailoverModels    []string  `json:"failover_models"`
	TierPool          []string  `json:"tier_pool"`
	UpstreamTimeoutMs *int      `json:"upstream_timeout_ms,omitempty"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
}

// CreateModelParams holds all configurable fields for CreateModel. Optional
// fields use pointer types so empty/zero values can be distinguished from
// "leave default". The Store layer is responsible for encrypting
// UpstreamAPIKey when an encryptor is configured.
type CreateModelParams struct {
	ModelName         string
	DisplayName       string
	Tier              string
	UpstreamURL       *string
	UpstreamAPIKey    *string
	Provider          string // empty → DB default 'openai-compat'
	FallbackModel     *string
	FailoverModels    []string
	TierPool          []string
	UpstreamTimeoutMs *int
}

// UpdateModelParams holds all configurable fields for UpdateModel. Any field
// that is nil / left at its zero value will be skipped (partial update). The
// Store layer encrypts UpstreamAPIKey when an encryptor is configured.
type UpdateModelParams struct {
	ModelName         string
	DisplayName       *string
	Tier              *string
	UpstreamURL       *string
	UpstreamAPIKey    *string // plaintext — encrypted by the store if enc configured
	ClearUpstreamKey  bool
	Provider          *string // nil → leave unchanged
	FallbackModel     *string
	FailoverModels    []string // nil → leave unchanged; empty [] → set to {}
	TierPool          []string // nil → leave unchanged
	UpstreamTimeoutMs *int
	Enabled           *bool
}

// RoutingRule represents a routing rule.
type RoutingRule struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	MatchExpr   string    `json:"match_expr"`
	TargetModel string    `json:"target_model"`
	Priority    int       `json:"priority"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// WhitelistEntry represents a model whitelist entry for keys or teams.
type WhitelistEntry struct {
	ID        int64     `json:"id"`
	TargetID  string    `json:"target_id"`
	ModelName string    `json:"model_name"`
	Allowed   bool      `json:"allowed"`
	CreatedAt time.Time `json:"created_at"`
}

// RequestLogStats holds aggregated request statistics.
type RequestLogStats struct {
	TotalRequests  int64   `json:"total_requests"`
	TotalTokensIn  int64   `json:"total_tokens_in"`
	TotalTokensOut int64   `json:"total_tokens_out"`
	AvgDurationMs  float64 `json:"avg_duration_ms"`
	ErrorCount     int64   `json:"error_count"`
	SuccessRate    float64 `json:"success_rate"`
}

// AdminUserWithHash extends AdminUser to include password_hash for auth.
type AdminUserWithHash struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	DisplayName  string    `json:"display_name"`
	IsRoot       bool      `json:"is_root"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TopModelCount is a named type for model usage analytics.
type TopModelCount struct {
	ModelName string `json:"model_name"`
	Count     int64  `json:"count"`
}

// TopOrgCount is a named type for org usage analytics.
type TopOrgCount struct {
	OrgID    string `json:"org_id"`
	Slug     string `json:"slug"`
	Count    int64  `json:"count"`
	TokensIn int64  `json:"tokens_in"`
}

// TimeSeriesPoint represents a single point in a time series.
type TimeSeriesPoint struct {
	Time  string `json:"time"`
	Value int64  `json:"value"`
}

// ErrorBreakdownEntry represents an error category with count.
type ErrorBreakdownEntry struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// LatencyPercentile holds a latency percentile value.
type LatencyPercentile struct {
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

// RecentErrorLog represents a recent failed request for debugging.
type RecentErrorLog struct {
	ID         int64     `json:"id"`
	RequestID  string    `json:"request_id"`
	OrgID      string    `json:"org_id"`
	ModelUsed  string    `json:"model_used"`
	StatusCode int       `json:"status_code"`
	DurationMs int       `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// pgxdb is the interface for database operations in adminstore.
// It abstracts *pgxpool.Pool to enable unit testing without a real database.
type pgxdb interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	// BeginAuditTx starts the transactional append the audit writer uses
	// (ENT-03). A *pgx.Tx satisfies auditTx.
	BeginAuditTx(ctx context.Context) (auditTx, error)
}

// auditTx is the minimal transactional surface the audit writer needs
// (ENT-03). *pgx.Tx satisfies it; the test double is small.
type auditTx interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// pgxRowsAdapter wraps pgxpool.Pool to implement pgxdb.
type pgxRowsAdapter struct {
	*pgxpool.Pool
}

func (a *pgxRowsAdapter) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return a.Pool.Query(ctx, sql, args...)
}

func (a *pgxRowsAdapter) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return a.Pool.QueryRow(ctx, sql, args...)
}

func (a *pgxRowsAdapter) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return a.Pool.Exec(ctx, sql, args...)
}

func (a *pgxRowsAdapter) BeginAuditTx(ctx context.Context) (auditTx, error) {
	return a.Begin(ctx)
}

// Store provides CRUD operations for admin panel data.
type Store struct {
	requestPayloadGrantMu    sync.Mutex
	requestPayloadGrantCache map[[32]byte]requestPayloadGrantCacheEntry
	pool                     *pgxpool.Pool // direct pool reference for raw DB access (e.g. sovereign handlers)
	db                       pgxdb
	log                      *slog.Logger
	enc                      *encryption.Encryptor
	// credKMS, when non-nil, receives NEW org credential writes as versioned
	// envelopes (N01-P04 successor; see orgcredentials.go for the seam
	// contract). Legacy enc: rows keep decrypting through enc (dual-trust
	// read); nil keeps the legacy single-key behavior byte-identical.
	credKMS kms.Provider
	// policyVersions bumps the OP-0b→OP-8 policy version key after every
	// policy mutation (nil = skip; the gateway TTL bounds staleness).
	policyVersions PolicyVersionBumper
	// (canarystore:ver:<orgID>) after every canary rollout mutation
	// (nil = skip; the gateway rollout-cache TTL bounds staleness).
	canaryVersions CanaryVersionBumper
}

// New creates a new admin store.
func New(pool *pgxpool.Pool, l *slog.Logger, enc *encryption.Encryptor) *Store {
	var db pgxdb
	if pool != nil {
		db = &pgxRowsAdapter{pool}
	}
	return &Store{pool: pool, db: db, log: l, enc: enc}
}

// newForTest creates a store with a given db interface (testing only).
func newForTest(db pgxdb, l *slog.Logger, enc *encryption.Encryptor) *Store {
	return &Store{db: db, log: l, enc: enc}
}

// AdoptCredentialKMS opts the org credential seam into versioned envelopes:
// new writes are sealed under the keyset's current version, legacy enc: rows
// keep decrypting (dual-trust read), and credential writes lazily re-seal
// old-format rows (the drain step of the rotation runbook — no data
// migration and no traffic stop required). A nil provider is a no-op, so the
// legacy single-key default stays byte-identical.
//
// Call this once during startup wiring, before the store serves traffic; the
// field is read by request paths without synchronization. Key material is
// rotated on the provider itself (VersionedKMS.Rotate) — never by calling
// this again with a second ring, which would strand envelopes written under
// the first one. That startup-only contract is enforced structurally: a
// second adoption is refused (the first keyset stays bound) with a loud
// warning, so a mid-traffic re-wire can neither strand envelopes under a
// replaced ring nor race the unsynchronized request-path reads.
func (s *Store) AdoptCredentialKMS(v kms.Provider) {
	if v == nil {
		return
	}
	if s.credKMS != nil {
		if s.log != nil {
			s.log.Warn("credential keyset re-adoption refused: AdoptCredentialKMS is startup-only and the first keyset stays bound; rotate key material on the provider (VersionedKMS.Rotate), never by re-adoption")
		}
		return
	}
	s.credKMS = v
}

// Log returns the underlying logger.
func (s *Store) Log() *slog.Logger {
	return s.log
}

// DB returns the underlying *pgxpool.Pool for raw queries.
// Used by admin handlers that need direct table access (e.g. sovereign models).
func (s *Store) DB() *pgxpool.Pool {
	return s.pool
}

// scanner is satisfied by both pgx.Row and pgx.Rows, letting scanModel serve
// single-row and multi-row SELECTs identically.
type scanner interface {
	Scan(dest ...any) error
}

// Helper to join SQL conditions.
func joinConditions(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	result := conditions[0]
	for _, c := range conditions[1:] {
		result += " AND " + c
	}
	return result
}

// Helper to join SET clauses for UPDATE queries.
func joinSetClauses(clauses []string) string {
	if len(clauses) == 0 {
		return ""
	}
	result := clauses[0]
	for _, c := range clauses[1:] {
		result += ", " + c
	}
	return result
}

func appendSQLAnd(query string, conditions []string) string {
	if len(conditions) == 0 {
		return query
	}
	return query + " AND " + joinConditions(conditions)
}

// ---------------------------------------------------------------------------
// P4.9: Per-org cache settings — reads/writes organizations.cache_mode.
// ---------------------------------------------------------------------------

// OrgCacheSettings holds the per-organization cache configuration.
type OrgCacheSettings struct {
	CacheEnabled bool   `json:"cache_enabled"`
	CacheMode    string `json:"cache_mode"` // "off" | "exact" | "semantic"
}

// RoutingMode constants for per-organization classifier routing configuration.
const (
	RoutingModeAuto           = "auto"            // default — uses threshold_confidence cutoff
	RoutingModeAggressiveCost = "aggressive_cost" // low threshold (0.4) — route aggressively
	RoutingModeAlwaysPremium  = "always_premium"  // skip classifier, always use premium model
	RoutingModeAlwaysCheap    = "always_cheap"    // skip classifier, always use cheapest model
	RoutingModeClassifierOnly = "classifier_only" // high threshold (0.9) — route only on high confidence
)

// OrgRoutingSettings holds the per-organization routing configuration.
type OrgRoutingSettings struct {
	RoutingMode                string  `json:"routing_mode"`
	RoutingThresholdConfidence float64 `json:"routing_threshold_confidence"` // cutoff for classifier decision
}

// stringPtr returns a pointer to the given string.
func stringPtr(s string) *string {
	return &s
}

// A/B experiment methods — stubbed for P4.14; full implementation uses pkg/cache.ExperimentStore.
// These are delegated to cache.NewExperimentStore(pool) in gateway initialization.
