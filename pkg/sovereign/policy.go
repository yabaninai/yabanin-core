// Package sovereign classifies models by data-residency posture and enforces
// per-org routing policy that constrains which jurisdictions may serve a
// given tenant. It is the policy layer on top of PB4.1 schema metadata.
package sovereign

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Policy is the per-org sovereignty routing constraint, enforced before
// model selection in the tier router (PB4.5).
type Policy struct {
	RequiredTier      Tier
	ExcludedCountries []string
	BuyerJurisdiction string
	CNAllowed         bool
	// Egress binds a country profile per egress kind (N09-P05-T02). A nil
	// map means no per-kind rules; org-wide ExcludedCountries still apply
	// to every kind via CheckEgress. Serialized into the PolicyStore Redis
	// cache; entries written before this field existed decode with
	// Egress=nil, so the rollout and rollback are both transparent.
	Egress map[EgressKind]EgressProfile `json:"egress,omitempty"`
}

// DefaultPolicy allows every model (no constraints). Used when an org has no
// row in org_sovereignty_policy. Sovereign buyers override this via the
// admin API; the CN-off default still holds because CNGuard (PB4.8) runs
// independently of Policy.
func DefaultPolicy() Policy {
	return Policy{RequiredTier: TierForeign}
}

// Allows reports whether a model satisfies the policy. Defined in
// provider.go, where it delegates to AllowsExplain — the same boolean with
// a structured exclusion reason (N09-P05-T04).

// PolicyStore loads a Policy from Postgres with a Redis cache (60s TTL).
// Cache misses fall back to DefaultPolicy; cache writes are best-effort.
type PolicyStore struct {
	rdb *redis.Client
	pg  PgQueryer
	ttl time.Duration
}

// PgQueryer is the minimal Postgres surface the store needs. *sql.DB and
// pgxpool.Pool both satisfy it via a thin adapter; defined here to avoid a
// hard import of database/sql or pgx in this package.
type PgQueryer interface {
	QueryRow(ctx context.Context, q string, args ...any) PgRow
}

type PgRow interface {
	Scan(dest ...any) error
}

func NewPolicyStore(rdb *redis.Client, pg PgQueryer) *PolicyStore {
	return &PolicyStore{rdb: rdb, pg: pg, ttl: 60 * time.Second}
}

func (s *PolicyStore) Get(ctx context.Context, orgID string) Policy {
	if s == nil || s.rdb == nil || orgID == "" {
		return DefaultPolicy()
	}
	key := "sovp:" + orgID
	if v, err := s.rdb.Get(ctx, key).Bytes(); err == nil && len(v) > 0 {
		var p Policy
		if json.Unmarshal(v, &p) == nil {
			return p
		}
	}
	p := s.loadFromDB(ctx, orgID)
	if raw, err := json.Marshal(p); err == nil {
		_ = s.rdb.Set(ctx, key, raw, s.ttl).Err()
	}
	return p
}

func (s *PolicyStore) loadFromDB(ctx context.Context, orgID string) Policy {
	if s == nil || s.pg == nil {
		return DefaultPolicy()
	}
	var (
		reqTier   string
		excl      []string
		buyerJur  string
		cnAllowed bool
	)
	err := s.pg.QueryRow(ctx,
		`SELECT required_tier, excluded_countries, buyer_jurisdiction, cn_allowed
		 FROM org_sovereignty_policy WHERE org_id = $1`, orgID,
	).Scan(&reqTier, &excl, &buyerJur, &cnAllowed)
	if err != nil {
		return DefaultPolicy()
	}
	return Policy{
		RequiredTier:      Tier(reqTier),
		ExcludedCountries: excl,
		BuyerJurisdiction: buyerJur,
		CNAllowed:         cnAllowed,
	}
}

// Invalidate drops the cached policy so the next Get re-reads from Postgres.
// Called by the admin handler after a policy update.
func (s *PolicyStore) Invalidate(ctx context.Context, orgID string) {
	if s == nil || s.rdb == nil {
		return
	}
	_ = s.rdb.Del(ctx, "sovp:"+orgID).Err()
}

// ErrNoSovereignModel is returned by the tier router when policy filtering
// empties the candidate pool. Carries diagnostic context for logging/alerts.
type ErrNoSovereignModel struct {
	OrgID          string
	RequiredTier   Tier
	Excluded       []string
	PoolSizeBefore int
}

func (e ErrNoSovereignModel) Error() string {
	return fmt.Sprintf("no model satisfies sovereignty policy for org %s (required_tier=%s, excluded=%v)",
		e.OrgID, e.RequiredTier, e.Excluded)
}
