package adminstore

// (policystore.go): immutable version rows, one atomic activation
// transaction, org isolation through the app.current_org GUC (FORCE RLS on
// canary_rollout*, migration 0003), and version-key cache invalidation after
// every successful mutation (the PolicyVersionBumper contract under the
// canarystore:ver: namespace). The gateway-side resolver
// (pkg/router/canary.go) consumes LoadCanarySnapshot only.
//
// Rollback semantics (D3): the manual rollback is UpdateCanaryRollout with
// enabled=false — one atomic UPDATE plus the version-key bump; version
// history is untouched and re-enabling restores the active version
// immediately. The automatic rollback is deliberately NOT implemented; the
// evidence function below (CanaryRolloutEvidence) is the auto-Recommendation
// hook — numbers for a human decision, never an action.

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Canary rollout version labels (canary_rollout_versions.label).
const (
	CanaryLabelDraft  = "draft"
	CanaryLabelActive = "active"
)

// CanaryArmCanary / CanaryArmBase are the arm vocabulary of the decision
// payload and metrics (mirrors the ratified D2 split).
const (
	CanaryArmCanary = "canary"
	CanaryArmBase   = "base"
)

// CanaryRollout is one org-scoped named model rollout (migration 0003).
type CanaryRollout struct {
	ID string `json:"id"`
	// OrgID is immutable: rollouts never move between orgs.
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
	// Enabled is the attach/rollback flag: false = deactivated (manual
	// rollback, D3 — all traffic to base), true = the active version splits
	// traffic. The per-version content changes are versions, never in-place
	// edits.
	Enabled bool `json:"enabled"`
	// CurrentVersion is the version the rollout resolves to (0 = none yet).
	CurrentVersion int       `json:"current_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// CanaryRolloutVersion is one immutable (base_model, canary_model, percent)
// version of a rollout. Percent is a whole number 1..99 (D2).
type CanaryRolloutVersion struct {
	ID          string    `json:"id"`
	RolloutID   string    `json:"rollout_id"`
	OrgID       string    `json:"org_id"`
	Version     int       `json:"version"`
	BaseModel   string    `json:"base_model"`
	CanaryModel string    `json:"canary_model"`
	Percent     int       `json:"percent"`
	Label       string    `json:"label"` // draft | active
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// CanaryRolloutSnapshot is one complete, org-scoped view of the rollouts and
// their active versions. LoadCanarySnapshot returns either the complete value
// or an error.
type CanaryRolloutSnapshot struct {
	Rollouts []CanaryRollout
	Versions map[string]CanaryRolloutVersion
}

// CanaryRolloutStore is the persistence contract for versioned canary
// rollouts (the admin API surface; the gateway needs only the snapshot).
// Every operation runs under the org-isolation GUC (FORCE RLS on
// canary_rollout*), so a rollout of another org is ErrNotFound.
type CanaryRolloutStore interface {
	// CreateCanaryRollout creates the rollout and its FIRST version (label
	// draft). current_version stays 0 until SetActiveCanaryRolloutVersion.
	CreateCanaryRollout(ctx context.Context, orgID, name, baseModel, canaryModel string, percent int, createdBy string) (CanaryRollout, CanaryRolloutVersion, error)
	GetCanaryRollout(ctx context.Context, orgID, rolloutID string) (CanaryRollout, error)
	ListCanaryRollouts(ctx context.Context, orgID string) ([]CanaryRollout, error)
	// UpdateCanaryRollout flips the enabled flag only. enabled=false is the
	// manual rollback (D3): atomic, immediate, history-preserving.
	UpdateCanaryRollout(ctx context.Context, orgID, rolloutID string, enabled bool) (CanaryRollout, error)
	// CreateCanaryRolloutVersion appends the next draft version (max+1).
	CreateCanaryRolloutVersion(ctx context.Context, orgID, rolloutID, baseModel, canaryModel string, percent int, createdBy string) (CanaryRolloutVersion, error)
	ListCanaryRolloutVersions(ctx context.Context, orgID, rolloutID string) ([]CanaryRolloutVersion, error)
	GetCanaryRolloutVersion(ctx context.Context, orgID, rolloutID string, version int) (CanaryRolloutVersion, error)
	// SetActiveCanaryRolloutVersion points current_version at version, flips
	// its label to active and demotes the previously active label to draft —
	SetActiveCanaryRolloutVersion(ctx context.Context, orgID, rolloutID string, version int) (CanaryRollout, error)
	// DeleteCanaryRollout removes the rollout; versions cascade.
	DeleteCanaryRollout(ctx context.Context, orgID, rolloutID string) error
}

// *Store implements the canary rollout contract for the admin API.
var _ CanaryRolloutStore = (*Store)(nil)

const canaryRolloutTable = `canary_rollouts`
const canaryRolloutVersionTable = `canary_rollout_versions`

// canaryRolloutColumns is the canonical SELECT list for rollout reads.
const canaryRolloutColumns = `id::text, org_id::text, name, enabled, COALESCE(current_version, 0), created_at, updated_at`

// canaryRolloutVersionColumns is the canonical SELECT list for version reads.
const canaryRolloutVersionColumns = `id::text, rollout_id::text, org_id::text, version, base_model, canary_model, percent, label, COALESCE(created_by, ''), created_at`

// CanaryVersionKeyPrefix is the Redis key namespace for the cache
// invalidation contract — the PolicyVersionKeyPrefix mechanics under a
// separate namespace so policy bumps never drop canary caches and vice
// versa. KEY "canarystore:ver:<orgID>", VALUE decimal int64 (recommended
// time.Now().UnixNano()), TTL 7 days refreshed on every Set, missing key =
// version 0. The gateway canary resolver reads the key to drop its per-org
// rollout cache; with an unreachable Redis it degrades to its own hard TTL.
const CanaryVersionKeyPrefix = "canarystore:ver:"

// CanaryVersionTTL bounds the Redis retention of one org's canary version
// key (PolicyVersionTTL parity).
const CanaryVersionTTL = 7 * 24 * time.Hour

// CanaryVersionBumper is the gateway cache-invalidation hook (the
// PolicyVersionBumper contract under the canary namespace): after every
// successful rollout mutation the store bumps the org's version so every
// gateway drops its cached rollout snapshot immediately. A failed bump never
// fails the mutation — the gateway TTL bounds the staleness.
type CanaryVersionBumper interface {
	SetCanaryVersion(ctx context.Context, orgID string, version int64) error
}

// CanaryVersionRedis is the Redis surface the canary version cache needs
// (PolicyVersionRedis parity).
type CanaryVersionRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd
}

// redisCanaryVersions is the production CanaryVersionBumper (and reader for
// the gateway wiring). Values are decimal int64 nanos.
type redisCanaryVersions struct {
	rdb CanaryVersionRedis
	log *slog.Logger
}

// NewCanaryVersionCache builds the Redis-backed canary version store. Wired
// in services/run over the shared Redis: the admin store bumps, the gateway
// resolver reads the same keys.
func NewCanaryVersionCache(rdb CanaryVersionRedis, l *slog.Logger) *redisCanaryVersions {
	return &redisCanaryVersions{rdb: rdb, log: l}
}

func (s *redisCanaryVersions) key(orgID string) string {
	return CanaryVersionKeyPrefix + orgID
}

// GetCanaryVersion reads the org's current canary version. A missing key is
// version 0, not an error.
func (s *redisCanaryVersions) GetCanaryVersion(ctx context.Context, orgID string) (int64, error) {
	v, err := s.rdb.Get(ctx, s.key(orgID)).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read canary version: %w", err)
	}
	version, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse canary version %q: %w", v, err)
	}
	return version, nil
}

// SetCanaryVersion records a new canary version for the org.
func (s *redisCanaryVersions) SetCanaryVersion(ctx context.Context, orgID string, version int64) error {
	if err := s.rdb.Set(ctx, s.key(orgID), strconv.FormatInt(version, 10), CanaryVersionTTL).Err(); err != nil {
		return fmt.Errorf("write canary version: %w", err)
	}
	return nil
}

// SetCanaryVersionBumper wires the version-key invalidation (nil = skip; the
// gateway TTL bounds staleness).
func (s *Store) SetCanaryVersionBumper(b CanaryVersionBumper) {
	s.canaryVersions = b
}

// bumpCanaryVersion invalidates the gateway's rollout cache after a
// successful mutation. Fail-soft (bumpPolicyVersion parity).
func (s *Store) bumpCanaryVersion(ctx context.Context, orgID string) {
	if s.canaryVersions == nil {
		return
	}
	if err := s.canaryVersions.SetCanaryVersion(ctx, orgID, time.Now().UnixNano()); err != nil && s.log != nil {
		s.log.Warn("canary version bump failed; gateway rollout cache expires via TTL",
			"org_id", orgID, "error", err.Error())
	}
}

// validateCanaryContent applies the shared bounds: whole percent 1..99 (D2 —
// 0 and 100 are the "canary gets all/no traffic" degenerate states the packet
// rejects), non-empty distinct model names.
func validateCanaryContent(baseModel, canaryModel string, percent int) error {
	if baseModel == "" || len(baseModel) > 256 {
		return fmt.Errorf("base model must be 1 to 256 characters")
	}
	if canaryModel == "" || len(canaryModel) > 256 {
		return fmt.Errorf("canary model must be 1 to 256 characters")
	}
	if baseModel == canaryModel {
		return fmt.Errorf("base and canary models must differ")
	}
	if percent < 1 || percent > 99 {
		return fmt.Errorf("canary percent must be a whole number between 1 and 99")
	}
	return nil
}

// CreateCanaryRollout creates the rollout and its first version (v1, draft)
// in one transaction. current_version stays 0 (and Enabled false) until
// SetActiveCanaryRolloutVersion — a fresh rollout never receives traffic.
func (s *Store) CreateCanaryRollout(ctx context.Context, orgID, name, baseModel, canaryModel string, percent int, createdBy string) (CanaryRollout, CanaryRolloutVersion, error) {
	if orgID == "" {
		return CanaryRollout{}, CanaryRolloutVersion{}, fmt.Errorf("org id is required")
	}
	if err := validatePolicyName(name); err != nil {
		return CanaryRollout{}, CanaryRolloutVersion{}, err
	}
	if err := validateCanaryContent(baseModel, canaryModel, percent); err != nil {
		return CanaryRollout{}, CanaryRolloutVersion{}, err
	}

	var r CanaryRollout
	var v CanaryRolloutVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO `+canaryRolloutTable+` (org_id, name) VALUES ($1::uuid, $2)
			 RETURNING `+canaryRolloutColumns,
			orgID, name,
		).Scan(scanCanaryRolloutDests(&r)...); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("rollout name %q already exists in this org: %w", name, err)
			}
			return fmt.Errorf("create canary rollout: %w", err)
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO `+canaryRolloutVersionTable+` (rollout_id, org_id, version, base_model, canary_model, percent, label, created_by)
			 VALUES ($1::uuid, $2::uuid, 1, $3, $4, $5, $6, $7)
			 RETURNING `+canaryRolloutVersionColumns,
			r.ID, orgID, baseModel, canaryModel, percent, CanaryLabelDraft, createdBy,
		).Scan(scanCanaryRolloutVersionDests(&v)...); err != nil {
			return fmt.Errorf("create canary rollout version: %w", err)
		}
		return nil
	})
	if err != nil {
		return CanaryRollout{}, CanaryRolloutVersion{}, err
	}
	s.bumpCanaryVersion(ctx, orgID)
	return r, v, nil
}

// GetCanaryRollout returns the rollout row; a foreign/missing id is
// ErrNotFound (org-isolation GUC + explicit org predicate).
func (s *Store) GetCanaryRollout(ctx context.Context, orgID, rolloutID string) (CanaryRollout, error) {
	var r CanaryRollout
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		out, err := getCanaryRolloutTx(ctx, tx, orgID, rolloutID)
		if err != nil {
			return err
		}
		r = out
		return nil
	})
	if err != nil {
		return CanaryRollout{}, err
	}
	return r, nil
}

// ListCanaryRollouts returns all rollouts of one org, oldest first.
func (s *Store) ListCanaryRollouts(ctx context.Context, orgID string) ([]CanaryRollout, error) {
	var out []CanaryRollout
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+canaryRolloutColumns+` FROM `+canaryRolloutTable+
				` WHERE org_id = $1::uuid ORDER BY created_at ASC, id ASC`,
			orgID,
		)
		if err != nil {
			return fmt.Errorf("list canary rollouts: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r CanaryRollout
			if err := rows.Scan(scanCanaryRolloutDests(&r)...); err != nil {
				return fmt.Errorf("scan canary rollout: %w", err)
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateCanaryRollout flips the enabled flag. enabled=false is the manual
// rollback (D3): one atomic UPDATE; version history stays; re-enabling
// restores the previously active version.
func (s *Store) UpdateCanaryRollout(ctx context.Context, orgID, rolloutID string, enabled bool) (CanaryRollout, error) {
	var r CanaryRollout
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`UPDATE `+canaryRolloutTable+` SET enabled = $3
			 WHERE id = $1::uuid AND org_id = $2::uuid
			 RETURNING `+canaryRolloutColumns,
			rolloutID, orgID, enabled,
		).Scan(scanCanaryRolloutDests(&r)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("update canary rollout: %w", err)
		}
		return nil
	})
	if err != nil {
		return CanaryRollout{}, err
	}
	s.bumpCanaryVersion(ctx, orgID)
	return r, nil
}

// CreateCanaryRolloutVersion appends the next draft version (max+1,
// enforced by ux_canary_rollout_versions_rollout_version). A concurrent
// append that loses the race surfaces as a unique violation to retry.
func (s *Store) CreateCanaryRolloutVersion(ctx context.Context, orgID, rolloutID, baseModel, canaryModel string, percent int, createdBy string) (CanaryRolloutVersion, error) {
	if err := validateCanaryContent(baseModel, canaryModel, percent); err != nil {
		return CanaryRolloutVersion{}, err
	}
	var v CanaryRolloutVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getCanaryRolloutTx(ctx, tx, orgID, rolloutID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx,
			`INSERT INTO `+canaryRolloutVersionTable+` (rollout_id, org_id, version, base_model, canary_model, percent, label, created_by)
			 SELECT $1::uuid, $2::uuid, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6, $7
			 FROM `+canaryRolloutVersionTable+` WHERE rollout_id = $1::uuid
			 RETURNING `+canaryRolloutVersionColumns,
			rolloutID, orgID, baseModel, canaryModel, percent, CanaryLabelDraft, createdBy,
		).Scan(scanCanaryRolloutVersionDests(&v)...)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("concurrent canary rollout update, retry: %w", err)
			}
			return fmt.Errorf("create canary rollout version: %w", err)
		}
		return nil
	})
	if err != nil {
		return CanaryRolloutVersion{}, err
	}
	s.bumpCanaryVersion(ctx, orgID)
	return v, nil
}

// ListCanaryRolloutVersions returns the rollout's versions, newest first.
func (s *Store) ListCanaryRolloutVersions(ctx context.Context, orgID, rolloutID string) ([]CanaryRolloutVersion, error) {
	var out []CanaryRolloutVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getCanaryRolloutTx(ctx, tx, orgID, rolloutID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT `+canaryRolloutVersionColumns+` FROM `+canaryRolloutVersionTable+
				` WHERE rollout_id = $1::uuid AND org_id = $2::uuid ORDER BY version DESC`,
			rolloutID, orgID,
		)
		if err != nil {
			return fmt.Errorf("list canary rollout versions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v CanaryRolloutVersion
			if err := rows.Scan(scanCanaryRolloutVersionDests(&v)...); err != nil {
				return fmt.Errorf("scan canary rollout version: %w", err)
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetCanaryRolloutVersion returns one version of the rollout.
func (s *Store) GetCanaryRolloutVersion(ctx context.Context, orgID, rolloutID string, version int) (CanaryRolloutVersion, error) {
	var v CanaryRolloutVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getCanaryRolloutTx(ctx, tx, orgID, rolloutID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx,
			`SELECT `+canaryRolloutVersionColumns+` FROM `+canaryRolloutVersionTable+
				` WHERE rollout_id = $1::uuid AND org_id = $2::uuid AND version = $3`,
			rolloutID, orgID, version,
		).Scan(scanCanaryRolloutVersionDests(&v)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("get canary rollout version: %w", err)
		}
		return nil
	})
	if err != nil {
		return CanaryRolloutVersion{}, err
	}
	return v, nil
}

// SetActiveCanaryRolloutVersion points current_version at version in one
// previously active label demotes to draft, the target's label becomes
// active, the rollout row carries the new current_version, and the version
// key bumps so every gateway drops its cached snapshot. Gateway instances
// observe the switch at the same logical state — no mixed percent window.
func (s *Store) SetActiveCanaryRolloutVersion(ctx context.Context, orgID, rolloutID string, version int) (CanaryRollout, error) {
	var r CanaryRollout
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getCanaryRolloutTx(ctx, tx, orgID, rolloutID); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM `+canaryRolloutVersionTable+
				` WHERE rollout_id = $1::uuid AND org_id = $2::uuid AND version = $3)`,
			rolloutID, orgID, version,
		).Scan(&exists); err != nil {
			return fmt.Errorf("check canary rollout version: %w", err)
		}
		if !exists {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx,
			`UPDATE `+canaryRolloutVersionTable+` SET label = $4
			 WHERE rollout_id = $1::uuid AND org_id = $2::uuid AND label = $3`,
			rolloutID, orgID, CanaryLabelActive, CanaryLabelDraft,
		); err != nil {
			return fmt.Errorf("demote active canary rollout version: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE `+canaryRolloutVersionTable+` SET label = $4
			 WHERE rollout_id = $1::uuid AND org_id = $2::uuid AND version = $3`,
			rolloutID, orgID, version, CanaryLabelActive,
		); err != nil {
			return fmt.Errorf("activate canary rollout version: %w", err)
		}
		err := tx.QueryRow(ctx,
			`UPDATE `+canaryRolloutTable+` SET current_version = $3
			 WHERE id = $1::uuid AND org_id = $2::uuid
			 RETURNING `+canaryRolloutColumns,
			rolloutID, orgID, version,
		).Scan(scanCanaryRolloutDests(&r)...)
		if err != nil {
			return fmt.Errorf("set active canary rollout version: %w", err)
		}
		return nil
	})
	if err != nil {
		return CanaryRollout{}, err
	}
	s.bumpCanaryVersion(ctx, orgID)
	return r, nil
}

// DeleteCanaryRollout removes the rollout; versions cascade (FK ON DELETE
// CASCADE). Deleting a missing/foreign rollout is ErrNotFound.
func (s *Store) DeleteCanaryRollout(ctx context.Context, orgID, rolloutID string) error {
	var deleted int64
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM `+canaryRolloutTable+` WHERE id = $1::uuid AND org_id = $2::uuid`,
			rolloutID, orgID,
		)
		if err != nil {
			return fmt.Errorf("delete canary rollout: %w", err)
		}
		deleted = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrNotFound
	}
	s.bumpCanaryVersion(ctx, orgID)
	return nil
}

// LoadCanarySnapshot reads the org's enabled rollouts and their active
// versions from one repeatable-read transaction (LoadPolicySnapshot parity):
// activation cannot mix rollout and version rows from different database
// snapshots, so a gateway resolving mid-activation sees either the old or
// the new percent — never a mixture.
func (s *Store) LoadCanarySnapshot(ctx context.Context, orgID string) (CanaryRolloutSnapshot, error) {
	if s.db == nil {
		return CanaryRolloutSnapshot{}, fmt.Errorf("database not available")
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return CanaryRolloutSnapshot{}, fmt.Errorf("begin canary snapshot tx: %w", err)
	}
	rollback := func() { _ = tx.Rollback(ctx) }
	if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"); err != nil {
		rollback()
		return CanaryRolloutSnapshot{}, fmt.Errorf("set canary snapshot isolation: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
		rollback()
		return CanaryRolloutSnapshot{}, fmt.Errorf("set canary snapshot org: %w", err)
	}

	snapshot := CanaryRolloutSnapshot{
		Rollouts: make([]CanaryRollout, 0),
		Versions: make(map[string]CanaryRolloutVersion),
	}
	rollouts, err := tx.Query(ctx,
		`SELECT `+canaryRolloutColumns+` FROM `+canaryRolloutTable+
			` WHERE org_id = $1::uuid ORDER BY created_at ASC, id ASC`,
		orgID,
	)
	if err != nil {
		rollback()
		return CanaryRolloutSnapshot{}, fmt.Errorf("snapshot list canary rollouts: %w", err)
	}
	for rollouts.Next() {
		var r CanaryRollout
		if err := rollouts.Scan(scanCanaryRolloutDests(&r)...); err != nil {
			rollouts.Close()
			rollback()
			return CanaryRolloutSnapshot{}, fmt.Errorf("snapshot scan canary rollout: %w", err)
		}
		snapshot.Rollouts = append(snapshot.Rollouts, r)
	}
	if err := rollouts.Err(); err != nil {
		rollouts.Close()
		rollback()
		return CanaryRolloutSnapshot{}, fmt.Errorf("snapshot iterate canary rollouts: %w", err)
	}
	rollouts.Close()

	versions, err := tx.Query(ctx,
		`SELECT crv.id::text, crv.rollout_id::text, crv.org_id::text, crv.version, crv.base_model, crv.canary_model, crv.percent, crv.label, COALESCE(crv.created_by, ''), crv.created_at
		 FROM `+canaryRolloutVersionTable+` crv
		 JOIN `+canaryRolloutTable+` cr ON cr.id = crv.rollout_id AND cr.org_id = crv.org_id AND cr.current_version = crv.version
		 WHERE cr.org_id = $1::uuid AND cr.enabled AND cr.current_version > 0
		 ORDER BY cr.created_at ASC, cr.id ASC`, orgID,
	)
	if err != nil {
		rollback()
		return CanaryRolloutSnapshot{}, fmt.Errorf("snapshot list active canary versions: %w", err)
	}
	for versions.Next() {
		var v CanaryRolloutVersion
		if err := versions.Scan(scanCanaryRolloutVersionDests(&v)...); err != nil {
			versions.Close()
			rollback()
			return CanaryRolloutSnapshot{}, fmt.Errorf("snapshot scan active canary version: %w", err)
		}
		snapshot.Versions[v.RolloutID] = v
	}
	if err := versions.Err(); err != nil {
		versions.Close()
		rollback()
		return CanaryRolloutSnapshot{}, fmt.Errorf("snapshot iterate active canary versions: %w", err)
	}
	versions.Close()

	if err := tx.Commit(ctx); err != nil {
		return CanaryRolloutSnapshot{}, fmt.Errorf("commit canary snapshot tx: %w", err)
	}
	return snapshot, nil
}

// CanaryEvidence is the measured rollout health the auto-Recommendation hook
// surfaces (D3: evidence only — the owner decides, the system never rolls
// back by itself).
type CanaryEvidence struct {
	RolloutID    string `json:"rollout_id"`
	WindowHours  int    `json:"window_hours"`
	CanaryTotal  int64  `json:"canary_total"`
	CanaryErrors int64  `json:"canary_errors"`
	BaseTotal    int64  `json:"base_total"`
	BaseErrors   int64  `json:"base_errors"`
	// Recommendation is the computed advice: "rollback-recommended" when the
	// canary arm's error share exceeds the base arm's by the threshold,
	// "hold" otherwise. It is DATA for a human, never an action.
	Recommendation string `json:"recommendation"`
}

// canaryRecommendThreshold is the error-share delta (canary minus base) that
// flips the recommendation to rollback-recommended. Deliberately
// conservative and visible in the payload; tuning is an owner decision.
const canaryRecommendThreshold = 0.05

// CanaryRolloutEvidence is the recommendation hook (D3): it measures the
// rollout's actual traffic split and per-arm failure counts from request_logs
// (routing_decision carries rollout_id/arm) and returns a recommendation.
// Evidence function only — no caller
// may act on it automatically.
func (s *Store) CanaryRolloutEvidence(ctx context.Context, orgID, rolloutID string, window time.Duration) (CanaryEvidence, error) {
	if window <= 0 {
		return CanaryEvidence{}, fmt.Errorf("evidence window must be positive")
	}
	r, err := s.GetCanaryRollout(ctx, orgID, rolloutID)
	if err != nil {
		return CanaryEvidence{}, err
	}
	ev := CanaryEvidence{RolloutID: r.ID, WindowHours: int(window.Hours())}
	if ev.WindowHours < 1 {
		ev.WindowHours = 1
	}
	err = s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		rows, err := tx.Query(ctx,
			`SELECT COALESCE(routing_decision::jsonb->>'arm',''), COUNT(*),
			        COUNT(*) FILTER (WHERE status_code >= 500)
			 FROM request_logs
			 WHERE org_id = $1::uuid AND created_at > now() - $2::interval
			   AND routing_decision IS NOT NULL
			   AND routing_decision::jsonb->>'rollout_id' = $3
			 GROUP BY 1`,
			orgID, fmt.Sprintf("%d hours", ev.WindowHours), rolloutID,
		)
		if err != nil {
			return fmt.Errorf("canary evidence query: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var arm string
			var total, errs int64
			if err := rows.Scan(&arm, &total, &errs); err != nil {
				return fmt.Errorf("scan canary evidence: %w", err)
			}
			switch arm {
			case CanaryArmCanary:
				ev.CanaryTotal, ev.CanaryErrors = total, errs
			case CanaryArmBase:
				ev.BaseTotal, ev.BaseErrors = total, errs
			}
		}
		return rows.Err()
	})
	if err != nil {
		return CanaryEvidence{}, err
	}
	ev.Recommendation = canaryRecommendation(ev.CanaryTotal, ev.CanaryErrors, ev.BaseTotal, ev.BaseErrors)
	return ev, nil
}

// canaryRecommendation computes the D3 advice from the measured arm counts:
// "rollback-recommended" when both arms carry traffic and the canary arm's
// error share exceeds the base arm's by canaryRecommendThreshold, "hold"
// otherwise (insufficient data never recommends). Pure — evidence only; no
// caller may act on it automatically.
func canaryRecommendation(canaryTotal, canaryErrors, baseTotal, baseErrors int64) string {
	if canaryTotal <= 0 || baseTotal <= 0 {
		return "hold"
	}
	canaryShare := float64(canaryErrors) / float64(canaryTotal)
	baseShare := float64(baseErrors) / float64(baseTotal)
	if canaryShare-baseShare >= canaryRecommendThreshold {
		return "rollback-recommended"
	}
	return "hold"
}

// getCanaryRolloutTx is the in-tx existence+visibility probe (getPolicyTx
// parity): under the pinned GUC a foreign rollout is invisible, so a missing
// row is ErrNotFound — the cross-org 404 semantics.
func getCanaryRolloutTx(ctx context.Context, tx auditTx, orgID, rolloutID string) (CanaryRollout, error) {
	var r CanaryRollout
	err := tx.QueryRow(ctx,
		`SELECT `+canaryRolloutColumns+` FROM `+canaryRolloutTable+
			` WHERE id = $1::uuid AND org_id = $2::uuid`,
		rolloutID, orgID,
	).Scan(scanCanaryRolloutDests(&r)...)
	if err != nil {
		if IsNotFound(err) {
			return CanaryRollout{}, ErrNotFound
		}
		return CanaryRollout{}, fmt.Errorf("get canary rollout: %w", err)
	}
	return r, nil
}

func scanCanaryRolloutDests(r *CanaryRollout) []any {
	return []any{
		&r.ID, &r.OrgID, &r.Name, &r.Enabled, &r.CurrentVersion, &r.CreatedAt, &r.UpdatedAt,
	}
}

func scanCanaryRolloutVersionDests(v *CanaryRolloutVersion) []any {
	return []any{
		&v.ID, &v.RolloutID, &v.OrgID, &v.Version, &v.BaseModel, &v.CanaryModel, &v.Percent, &v.Label, &v.CreatedBy, &v.CreatedAt,
	}
}
