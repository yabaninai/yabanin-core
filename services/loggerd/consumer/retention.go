package consumer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ---------------------------------------------------------------------------
// NEXT-21: retention worker — per-team hot-storage windows (migration 0026)
// with a bounded cold-storage export BEFORE any hot-storage delete.
//
// Contract:
//   - export-before-delete: a batch is deleted only after its archive
//     (JSONL + sha256 manifest) was successfully written; a failed export
//     leaves hot rows untouched;
//   - redaction: exports null out raw content payloads (responses, upstream
//     captures, cache payloads, error text) when the policy redacts; hashes,
//     metadata and the lineage hash chain (record_hash/prev_hash) always go
//     verbatim, so archives verify without breaking append-only semantics;
//   - lineage is ARCHIVE-ONLY: request_lineage is append-only (PB1.2
//     tamper-evidence trigger blocks UPDATE/DELETE), so expired rows are
//     copied to deterministic per-UTC-day cold buckets and stay in hot
//     storage — the ledger remains the authority, hashes are never rewritten;
//   - bounded: batch and batches-per-tick caps mirror the AF-16 retention
//     bounds; '' destination or an unsupported scheme (s3://) SKIPS the
//     family — retention never deletes without a destination.
// ---------------------------------------------------------------------------

// ErrUnsupportedColdDestination marks a stored destination the worker cannot
// write to (reserved s3:// scheme until a native S3 writer lands).
var ErrUnsupportedColdDestination = errors.New("cold destination scheme not supported")

// ErrNoColdDestination marks the empty policy destination: the caller must
// skip cleanup (retention never deletes without a successful export).
var ErrNoColdDestination = errors.New("no cold destination configured")

// ColdStorage is the destination seam for cold-storage archives. NEXT-21
// ships the file implementation; object stores are expected behind mounts or
// a future implementation of this interface (no new dependencies).
type ColdStorage interface {
	Write(ctx context.Context, key string, data []byte) error
}

// FSStore writes archives under an absolute local directory root.
type FSStore struct {
	root string
}

// NewFSStore validates the root. Directories are created lazily on the
// first Write so resolving a policy destination never touches the filesystem.
func NewFSStore(root string) (*FSStore, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("cold storage root must be an absolute path: %q", root)
	}
	return &FSStore{root: filepath.Clean(root)}, nil
}

// Write stores one archive object. The key is anchored before joining, so a
// crafted key cannot traverse above the root.
func (s *FSStore) Write(_ context.Context, key string, data []byte) error {
	clean := filepath.Clean(string(filepath.Separator) + key)
	full := filepath.Join(s.root, clean)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return fmt.Errorf("create archive directory: %w", err)
	}
	return os.WriteFile(full, data, 0o600)
}

// coldStorageFromURI resolves a policy destination URI. The empty
// destination resolves to ErrNoColdDestination: the caller must then skip
// cleanup (the export-before-delete contract).
func coldStorageFromURI(dest string) (ColdStorage, error) {
	if dest == "" {
		return nil, ErrNoColdDestination
	}
	u, err := url.Parse(dest)
	if err != nil {
		return nil, fmt.Errorf("parse cold destination %q: %w", dest, err)
	}
	switch u.Scheme {
	case "file":
		if u.Host != "" {
			return nil, fmt.Errorf("cold destination %q: file URIs must not name a host", dest)
		}
		if !filepath.IsAbs(u.Path) {
			return nil, fmt.Errorf("cold destination %q: file path must be absolute", dest)
		}
		return NewFSStore(u.Path)
	case "s3":
		return nil, fmt.Errorf("%w: %q (s3 writer is a NEXT-21 follow-up; use a file:// mount)", ErrUnsupportedColdDestination, dest)
	default:
		return nil, fmt.Errorf("invalid cold destination scheme %q in %q", u.Scheme, dest)
	}
}

// RetentionPolicySource feeds the worker. Production adapter wraps
// *adminstore.Store; tests use fakes.
type RetentionPolicySource interface {
	ListEnabledTeamRetentionAssignments(ctx context.Context) ([]adminstore.TeamRetentionAssignment, error)
	EffectiveOrgRetention(ctx context.Context, orgID string) (*adminstore.OrgRetention, error)
}

// StorePolicySource adapts *adminstore.Store to RetentionPolicySource.
type StorePolicySource struct {
	Store *adminstore.Store
}

// ListEnabledTeamRetentionAssignments delegates to the store.
func (s StorePolicySource) ListEnabledTeamRetentionAssignments(ctx context.Context) ([]adminstore.TeamRetentionAssignment, error) {
	return s.Store.ListEnabledTeamRetentionAssignments(ctx)
}

// EffectiveOrgRetention delegates to the store.
func (s StorePolicySource) EffectiveOrgRetention(ctx context.Context, orgID string) (*adminstore.OrgRetention, error) {
	return s.Store.EffectiveOrgRetention(ctx, orgID)
}

// RetentionDB is the database surface of the retention worker.
type RetentionDB interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
}

// RetentionConfig bounds the worker loop. Zero fields fall back to
// DefaultRetentionConfig values.
type RetentionConfig struct {
	// Interval is the poll tick between retention passes.
	Interval time.Duration
	// CleanupEvery is the minimum spacing between actually destructive
	// passes (cadence gate, mirrors the AF-16 cleanup cadence).
	CleanupEvery time.Duration
	// BatchSize is the export/delete batch bound per statement.
	BatchSize int
	// BatchesPerTick bounds how much one pass drains per table family.
	BatchesPerTick int
}

// DefaultRetentionConfig returns production-safe defaults: hourly passes,
// 500-row batches, at most 40 batches per family per pass — the same
// worst-case drain bound as the AF-16 settled retention.
func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{
		Interval:       time.Hour,
		CleanupEvery:   time.Hour,
		BatchSize:      500,
		BatchesPerTick: 40,
	}
}

func (c RetentionConfig) withDefaults() RetentionConfig {
	d := DefaultRetentionConfig()
	if c.Interval <= 0 {
		c.Interval = d.Interval
	}
	if c.CleanupEvery <= 0 {
		c.CleanupEvery = d.CleanupEvery
	}
	if c.BatchSize <= 0 {
		c.BatchSize = d.BatchSize
	}
	if c.BatchesPerTick <= 0 {
		c.BatchesPerTick = d.BatchesPerTick
	}
	return c
}

const (
	// retentionRequestLogsSelect reads one oldest-first batch of a team's
	// expired request_logs rows. Content columns (response, upstream_request,
	// upstream_response, error) are exported only when the policy allows;
	// they are never required for the delete decision.
	retentionRequestLogsSelect = `SELECT id, request_id, team_id::text, model_requested, model_used,
			status_code, duration_ms, tokens_in, tokens_out, cost_in_usd, counterfactual_cost_usd,
			cache_hit_type, classifier_class, classifier_confidence, tier_used, routing_decision,
			prompt_hash, created_at,
			response, upstream_request, upstream_response, error
		FROM request_logs
		WHERE team_id = $1 AND created_at < now() - make_interval(days => $2)
		ORDER BY created_at, id
		LIMIT $3`

	// retentionRequestLogsDelete removes EXACTLY the exported ids. There is
	// deliberately no time-based DELETE for request_logs in this worker: the
	// global purge in services/run/loggerd.go (YABANIN_LOG_RETENTION_DAYS)
	// stays the only unconditioned path.
	retentionRequestLogsDelete = `DELETE FROM request_logs WHERE id = ANY($1)`

	// retentionCacheSelect reads one oldest-first batch of an org's expired
	// cache entries. The response payload goes only when the policy allows;
	// the embedding vector never leaves hot storage.
	retentionCacheSelect = `SELECT id::text, org_id::text, model_tier, prompt_hash,
			tokens_in, tokens_out, hit_count, model_version, created_at, expires_at, response
		FROM cache_entries
		WHERE org_id = $1 AND created_at < now() - make_interval(days => $2)
		ORDER BY created_at, id
		LIMIT $3`

	retentionCacheDelete = `DELETE FROM cache_entries WHERE id = ANY($1)`

	// retentionLineageSelect reads one oldest-first batch of an org's
	// expired lineage rows VERBATIM (hash-chain columns untouched — the
	// export must verify against the ledger). request_lineage is APPEND-ONLY
	// (PB1.2 tamper-evidence trigger blocks UPDATE/DELETE, 0001_init): the
	// retention worker therefore ARCHIVES expired lineage rows but never
	// deletes them — hot rows stay, satisfying the hash chain by construction.
	retentionLineageSelect = `SELECT id, request_id, ts, model_used, inference_region,
			model_origin_country, log_storage_region, provider_entity_jurisdiction,
			attestation_hash, attestation_key_id, model_sovereignty_tier, model_vendor_hq,
			region_evidence, record_hash, prev_hash, raw_attestation
		FROM request_lineage
		WHERE org_id = $1 AND ts < now() - make_interval(days => $2)
		ORDER BY ts, id
		LIMIT $3`
)

// requestLogExport is one archived request_logs row. Content payloads are
// null when the policy redacts; hashes and metadata always go.
type requestLogExport struct {
	ID                    int64           `json:"id"`
	RequestID             *string         `json:"request_id"`
	TeamID                *string         `json:"team_id"`
	ModelRequested        string          `json:"model_requested"`
	ModelUsed             string          `json:"model_used"`
	StatusCode            int32           `json:"status_code"`
	DurationMs            int32           `json:"duration_ms"`
	TokensIn              int32           `json:"tokens_in"`
	TokensOut             int32           `json:"tokens_out"`
	CostInUSD             *float64        `json:"cost_in_usd"`
	CounterfactualCostUSD *float64        `json:"counterfactual_cost_usd"`
	CacheHitType          *string         `json:"cache_hit_type"`
	ClassifierClass       *string         `json:"classifier_class"`
	ClassifierConfidence  *float32        `json:"classifier_confidence"`
	TierUsed              *string         `json:"tier_used"`
	RoutingDecision       *string         `json:"routing_decision"`
	PromptHash            *string         `json:"prompt_hash"`
	CreatedAt             time.Time       `json:"created_at"`
	Response              json.RawMessage `json:"response"`
	UpstreamRequest       json.RawMessage `json:"upstream_request"`
	UpstreamResponse      json.RawMessage `json:"upstream_response"`
	Error                 *string         `json:"error"`
}

// cacheEntryExport is one archived cache_entries row. The response payload
// is null when the policy redacts; the embedding vector is never exported.
type cacheEntryExport struct {
	ID           string          `json:"id"`
	OrgID        string          `json:"org_id"`
	ModelTier    string          `json:"model_tier"`
	PromptHash   string          `json:"prompt_hash"`
	TokensIn     int32           `json:"tokens_in"`
	TokensOut    int32           `json:"tokens_out"`
	HitCount     int32           `json:"hit_count"`
	ModelVersion string          `json:"model_version"`
	CreatedAt    time.Time       `json:"created_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
	Response     json.RawMessage `json:"response"`
}

// lineageExport is one archived request_lineage row, verbatim: attestation
// and hash-chain fields are copied untouched so an archive verifies against
// the append-only ledger.
type lineageExport struct {
	ID                         int64           `json:"id"`
	RequestID                  string          `json:"request_id"`
	TS                         time.Time       `json:"ts"`
	ModelUsed                  string          `json:"model_used"`
	InferenceRegion            string          `json:"inference_region"`
	ModelOriginCountry         string          `json:"model_origin_country"`
	LogStorageRegion           string          `json:"log_storage_region"`
	ProviderEntityJurisdiction string          `json:"provider_entity_jurisdiction"`
	AttestationHash            string          `json:"attestation_hash"`
	AttestationKeyID           *string         `json:"attestation_key_id"`
	ModelSovereigntyTier       *string         `json:"model_sovereignty_tier"`
	ModelVendorHQ              *string         `json:"model_vendor_hq"`
	RegionEvidence             string          `json:"region_evidence"`
	RecordHash                 string          `json:"record_hash"`
	PrevHash                   *string         `json:"prev_hash"`
	RawAttestation             json.RawMessage `json:"raw_attestation"`
}

// exportManifest is the sidecar of every archive: enough to verify integrity
// (sha256 over the exact JSONL bytes) and to audit what was removed.
type exportManifest struct {
	Table      string    `json:"table"`
	Scope      string    `json:"scope"`
	Rows       int       `json:"rows"`
	Sha256     string    `json:"sha256"`
	Redacted   bool      `json:"redacted"`
	CutoffDays int       `json:"cutoff_days"`
	ExportedAt time.Time `json:"exported_at"`
}

// RetentionStats summarizes one worker pass (logged and asserted in tests).
type RetentionStats struct {
	RequestLogsExported  int
	CacheEntriesExported int
	LineageExported      int
	SkippedNoDestination int
	SkippedUnsupported   int
}

// RetentionWorker exports expired records to cold storage and only then
// deletes them from hot storage. Run owns one goroutine; tick/RunOnce are
// safe for concurrent use in tests but production wiring starts exactly one
// worker per process.
type RetentionWorker struct {
	db       RetentionDB
	policies RetentionPolicySource
	log      *slog.Logger
	cfg      RetentionConfig
	now      func() time.Time

	mu          sync.Mutex
	lastCleanup time.Time
}

// NewRetentionWorker builds the worker with production defaults.
func NewRetentionWorker(db RetentionDB, policies RetentionPolicySource, logger *slog.Logger) *RetentionWorker {
	if logger == nil {
		logger = slog.Default()
	}
	return &RetentionWorker{
		db:       db,
		policies: policies,
		log:      logger,
		cfg:      DefaultRetentionConfig(),
		now:      time.Now,
	}
}

// WithConfig overrides the bounds (tests).
func (w *RetentionWorker) WithConfig(cfg RetentionConfig) *RetentionWorker {
	w.cfg = cfg.withDefaults()
	return w
}

// Run loops until ctx is cancelled, executing cadence-gated retention passes.
func (w *RetentionWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			stats, err := w.tick(ctx)
			if err != nil {
				w.log.Error("retention pass failed", "error", err)
				continue
			}
			if stats.RequestLogsExported+stats.CacheEntriesExported+stats.LineageExported > 0 {
				w.log.Info("retention pass completed",
					"request_logs", stats.RequestLogsExported,
					"cache_entries", stats.CacheEntriesExported,
					"lineage", stats.LineageExported,
					"skipped_no_destination", stats.SkippedNoDestination,
					"skipped_unsupported", stats.SkippedUnsupported)
			}
		}
	}
}

// tick applies the cleanup cadence gate and runs at most one pass.
func (w *RetentionWorker) tick(ctx context.Context) (RetentionStats, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if !w.lastCleanup.IsZero() && now.Sub(w.lastCleanup) < w.cfg.CleanupEvery {
		return RetentionStats{}, nil
	}
	stats, err := w.runOnce(ctx)
	if err != nil {
		return stats, err
	}
	w.lastCleanup = now
	return stats, nil
}

// runOnce executes one full retention pass: team-scoped request_logs per
// enabled policy, org-scoped cache_entries and request_lineage per effective
// org window (strictest enabled team policy wins; see adminstore.OrgRetention).
func (w *RetentionWorker) runOnce(ctx context.Context) (RetentionStats, error) {
	var stats RetentionStats

	assignments, err := w.policies.ListEnabledTeamRetentionAssignments(ctx)
	if err != nil {
		return stats, fmt.Errorf("list retention policies: %w", err)
	}

	orgs := make(map[string]struct{})
	seenTeams := make(map[string]struct{})
	for _, a := range assignments {
		if _, dup := seenTeams[a.TeamID]; dup {
			continue
		}
		seenTeams[a.TeamID] = struct{}{}
		orgs[a.OrgID] = struct{}{}

		if a.RequestLogsDays == nil {
			continue
		}
		store, err := coldStorageFromURI(a.ColdDestination)
		if err != nil {
			if errors.Is(err, ErrNoColdDestination) {
				// No destination: cleanup is forbidden — retention never
				// deletes without a successful export.
				stats.SkippedNoDestination++
				continue
			}
			if errors.Is(err, ErrUnsupportedColdDestination) {
				stats.SkippedUnsupported++
				w.log.Warn("retention: unsupported cold destination, family skipped",
					"table", "request_logs", "team_id", a.TeamID, "destination", a.ColdDestination)
				continue
			}
			return stats, err
		}
		n, err := w.exportAndDeleteRequestLogs(ctx, a, store)
		if err != nil {
			return stats, err
		}
		stats.RequestLogsExported += n
	}

	for orgID := range orgs {
		eff, err := w.policies.EffectiveOrgRetention(ctx, orgID)
		if err != nil {
			if errors.Is(err, adminstore.ErrNoRetention) {
				continue
			}
			return stats, fmt.Errorf("effective org retention %s: %w", orgID, err)
		}
		// W-LOGG: each family checks ITS OWN window pointer. The old
		// `||` condition entered this block for a lineage-only policy and
		// dereferenced the nil CacheEntriesDays below — a guaranteed panic
		// the moment the beta worker gets wired.
		if eff.CacheEntriesDays != nil {
			store, err := coldStorageFromURI(derefString(eff.Destination))
			if err != nil {
				if errors.Is(err, ErrNoColdDestination) {
					stats.SkippedNoDestination++
					continue
				}
				if errors.Is(err, ErrUnsupportedColdDestination) {
					stats.SkippedUnsupported++
					w.log.Warn("retention: unsupported cold destination, families skipped",
						"tables", "cache_entries", "org_id", orgID,
						"destination", derefString(eff.Destination))
					continue
				}
				return stats, err
			}
			n, err := w.exportAndDeleteCacheEntries(ctx, orgID, *eff, store)
			if err != nil {
				return stats, err
			}
			stats.CacheEntriesExported += n
		}
		if eff.LineageDays != nil {
			store, err := coldStorageFromURI(derefString(eff.Destination))
			if err != nil {
				if errors.Is(err, ErrNoColdDestination) {
					stats.SkippedNoDestination++
					continue
				}
				if errors.Is(err, ErrUnsupportedColdDestination) {
					stats.SkippedUnsupported++
					w.log.Warn("retention: unsupported cold destination, families skipped",
						"tables", "request_lineage", "org_id", orgID,
						"destination", derefString(eff.Destination))
					continue
				}
				return stats, err
			}
			n, err := w.exportAndDeleteLineage(ctx, orgID, *eff, store)
			if err != nil {
				return stats, err
			}
			stats.LineageExported += n
		}
	}
	return stats, nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// exportAndDeleteRequestLogs drains bounded oldest-first batches: export the
// batch to an archive, then delete exactly the exported ids.
func (w *RetentionWorker) exportAndDeleteRequestLogs(ctx context.Context, a adminstore.TeamRetentionAssignment, store ColdStorage) (int, error) {
	// W-LOGG guard: the derefs below stay protected even if a future
	// caller skips the window check.
	if a.RequestLogsDays == nil {
		return 0, nil
	}
	total := 0
	redacted := a.RedactContent
	for batch := 0; batch < w.cfg.BatchesPerTick; batch++ {
		rows, ids, err := w.selectRequestLogsBatch(ctx, a.TeamID, *a.RequestLogsDays)
		if err != nil {
			return total, fmt.Errorf("select expired request_logs (team %s): %w", a.TeamID, err)
		}
		if len(ids) == 0 {
			return total, nil
		}
		if redacted {
			for i := range rows {
				rows[i].Response = nil
				rows[i].UpstreamRequest = nil
				rows[i].UpstreamResponse = nil
				rows[i].Error = nil
			}
		}
		err = writeArchive(ctx, store, "request_logs", a.TeamID, *a.RequestLogsDays, redacted, rows)
		if err != nil {
			// The batch stays in hot storage; the next pass re-exports it.
			return total, fmt.Errorf("archive request_logs (team %s): %w", a.TeamID, err)
		}
		if _, err := w.db.Exec(ctx, retentionRequestLogsDelete, ids); err != nil {
			return total, fmt.Errorf("delete exported request_logs (team %s): %w", a.TeamID, err)
		}
		total += len(ids)
		if len(ids) < w.cfg.BatchSize {
			return total, nil
		}
	}
	return total, nil
}

func (w *RetentionWorker) selectRequestLogsBatch(ctx context.Context, teamID string, days int) ([]requestLogExport, []int64, error) {
	tid, err := uuid.Parse(teamID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid team id %q: %w", teamID, err)
	}
	rows, err := w.db.Query(ctx, retentionRequestLogsSelect, tid, days, w.cfg.BatchSize)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var out []requestLogExport
	var ids []int64
	for rows.Next() {
		var r requestLogExport
		if err := rows.Scan(&r.ID, &r.RequestID, &r.TeamID, &r.ModelRequested, &r.ModelUsed,
			&r.StatusCode, &r.DurationMs, &r.TokensIn, &r.TokensOut, &r.CostInUSD,
			&r.CounterfactualCostUSD, &r.CacheHitType, &r.ClassifierClass,
			&r.ClassifierConfidence, &r.TierUsed, &r.RoutingDecision, &r.PromptHash,
			&r.CreatedAt, &r.Response, &r.UpstreamRequest, &r.UpstreamResponse, &r.Error); err != nil {
			return nil, nil, err
		}
		ids = append(ids, r.ID)
		out = append(out, r)
	}
	return out, ids, rows.Err()
}

// exportAndDeleteCacheEntries drains bounded oldest-first batches of the
// org's expired cache entries (effective MIN window).
func (w *RetentionWorker) exportAndDeleteCacheEntries(ctx context.Context, orgID string, eff adminstore.OrgRetention, store ColdStorage) (int, error) {
	// W-LOGG guard: a lineage-only policy must never reach this path (the
	// caller now checks the pointer, but the deref below stays guarded so a
	// future call-site regression cannot panic the worker).
	if eff.CacheEntriesDays == nil {
		return 0, nil
	}
	oid, err := uuid.Parse(orgID)
	if err != nil {
		return 0, fmt.Errorf("invalid org id %q: %w", orgID, err)
	}
	total := 0
	for batch := 0; batch < w.cfg.BatchesPerTick; batch++ {
		rows, err := w.db.Query(ctx, retentionCacheSelect, oid, *eff.CacheEntriesDays, w.cfg.BatchSize)
		if err != nil {
			return total, fmt.Errorf("select expired cache_entries (org %s): %w", orgID, err)
		}
		var exports []cacheEntryExport
		var ids []uuid.UUID
		for rows.Next() {
			var r cacheEntryExport
			if err := rows.Scan(&r.ID, &r.OrgID, &r.ModelTier, &r.PromptHash, &r.TokensIn,
				&r.TokensOut, &r.HitCount, &r.ModelVersion, &r.CreatedAt, &r.ExpiresAt,
				&r.Response); err != nil {
				rows.Close()
				return total, fmt.Errorf("scan cache entry: %w", err)
			}
			id, parseErr := uuid.Parse(r.ID)
			if parseErr != nil {
				rows.Close()
				return total, fmt.Errorf("parse cache entry id %q: %w", r.ID, parseErr)
			}
			ids = append(ids, id)
			exports = append(exports, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return total, fmt.Errorf("iterate cache entries: %w", err)
		}
		rows.Close()
		if len(ids) == 0 {
			return total, nil
		}
		if eff.RedactContent {
			for i := range exports {
				exports[i].Response = nil
			}
		}
		if err := writeArchive(ctx, store, "cache_entries", orgID, *eff.CacheEntriesDays, eff.RedactContent, exports); err != nil {
			return total, fmt.Errorf("archive cache_entries (org %s): %w", orgID, err)
		}
		if _, err := w.db.Exec(ctx, retentionCacheDelete, ids); err != nil {
			return total, fmt.Errorf("delete exported cache_entries (org %s): %w", orgID, err)
		}
		total += len(ids)
		if len(ids) < w.cfg.BatchSize {
			return total, nil
		}
	}
	return total, nil
}

// exportAndDeleteLineage archives bounded oldest-first batches of the org's
// expired lineage rows into deterministic per-UTC-day bucket keys. Lines are
// verbatim (hash chain preserved) and the writes are idempotent: the same
// bucket rewrites the same object. request_lineage is append-only (PB1.2),
// so there is deliberately NO hot-storage delete here — the archive is a
// cold copy, the ledger stays the authority.
func (w *RetentionWorker) exportAndDeleteLineage(ctx context.Context, orgID string, eff adminstore.OrgRetention, store ColdStorage) (int, error) {
	// W-LOGG guard: a cache-only policy must never reach this path — the
	// caller now checks the pointer, this deref stays guarded.
	if eff.LineageDays == nil {
		return 0, nil
	}
	if _, err := uuid.Parse(orgID); err != nil {
		return 0, fmt.Errorf("invalid org id %q: %w", orgID, err)
	}
	total := 0
	buckets := map[string][]lineageExport{}
	var order []string
	seen := map[int64]struct{}{}
	for batch := 0; batch < w.cfg.BatchesPerTick; batch++ {
		// request_lineage.org_id is TEXT (0001): bind the canonical string.
		rows, err := w.db.Query(ctx, retentionLineageSelect, orgID, *eff.LineageDays, w.cfg.BatchSize)
		if err != nil {
			return total, fmt.Errorf("select expired request_lineage (org %s): %w", orgID, err)
		}
		count := 0
		for rows.Next() {
			var r lineageExport
			if err := rows.Scan(&r.ID, &r.RequestID, &r.TS, &r.ModelUsed, &r.InferenceRegion,
				&r.ModelOriginCountry, &r.LogStorageRegion, &r.ProviderEntityJurisdiction,
				&r.AttestationHash, &r.AttestationKeyID, &r.ModelSovereigntyTier,
				&r.ModelVendorHQ, &r.RegionEvidence, &r.RecordHash, &r.PrevHash,
				&r.RawAttestation); err != nil {
				rows.Close()
				return total, fmt.Errorf("scan lineage row: %w", err)
			}
			// No delete follows the export: without it every batch re-reads
			// the same oldest rows, so the pass dedupes by id and stops at
			// the first batch that yields nothing new.
			if _, dup := seen[r.ID]; dup {
				continue
			}
			seen[r.ID] = struct{}{}
			bucket := r.TS.UTC().Format("20060102")
			if _, isNew := buckets[bucket]; !isNew {
				order = append(order, bucket)
			}
			buckets[bucket] = append(buckets[bucket], r)
			count++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return total, fmt.Errorf("iterate lineage rows: %w", err)
		}
		rows.Close()
		if count == 0 || count < w.cfg.BatchSize {
			break
		}
	}
	if len(buckets) == 0 {
		return 0, nil
	}
	// Redaction NEVER touches lineage rows: the attestation/hash-chain
	// columns are the append-only contract (NEXT-21 scope item 3).
	for _, bucket := range order {
		key := fmt.Sprintf("request_lineage/%s/%s.jsonl", orgID, bucket)
		if err := writeArchiveTo(ctx, store, key, *eff.LineageDays, false, buckets[bucket]); err != nil {
			return total, fmt.Errorf("archive request_lineage (org %s): %w", orgID, err)
		}
		total += len(buckets[bucket])
	}
	return total, nil
}

// writeArchive writes one JSONL archive plus its sha256 manifest under a
// unique timestamped key, so concurrent passes never overwrite each other's
// archives.
func writeArchive[T any](ctx context.Context, store ColdStorage, table, scopeID string, days int, redacted bool, rows []T) error {
	key := fmt.Sprintf("%s/%s/%s.jsonl",
		table, scopeID, time.Now().UTC().Format("20060102T150405.000000000"))
	return writeArchiveTo(ctx, store, key, days, redacted, rows)
}

// writeArchiveTo writes one JSONL archive plus its sha256 manifest under an
// explicit key (deterministic for lineage day buckets).
func writeArchiveTo[T any](ctx context.Context, store ColdStorage, key string, days int, redacted bool, rows []T) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range rows {
		if err := enc.Encode(rows[i]); err != nil {
			return fmt.Errorf("encode %s row: %w", key, err)
		}
	}
	sum := sha256.Sum256(buf.Bytes())
	if err := store.Write(ctx, key, buf.Bytes()); err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}
	manifest, err := json.Marshal(exportManifest{
		Table:      strings.SplitN(key, "/", 2)[0],
		Scope:      strings.SplitN(key, "/", 3)[1],
		Rows:       len(rows),
		Sha256:     hex.EncodeToString(sum[:]),
		Redacted:   redacted,
		CutoffDays: days,
		ExportedAt: time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("encode %s manifest: %w", key, err)
	}
	if err := store.Write(ctx, key+".manifest.json", manifest); err != nil {
		return fmt.Errorf("write %s manifest: %w", key, err)
	}
	return nil
}
