package cache

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
)

// DBPolicyLoader loads per-org cache policy from the organizations table.
type DBPolicyLoader struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// NewDBPolicyLoader creates a loader that reads cache_enabled / cache_mode from DB.
func NewDBPolicyLoader(pool *pgxpool.Pool, log *slog.Logger) *DBPolicyLoader {
	return &DBPolicyLoader{pool: pool, log: log}
}

// LoadOrgPolicy implements OrgPolicyLoader — reads organizations.cache_enabled and cache_mode.
func (l *DBPolicyLoader) LoadOrgPolicy(ctx context.Context, orgID string) (*OrgPolicy, error) {
	if l.pool == nil {
		l.log.Warn("db policy loader: pool is nil, returning default enabled")
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}

	var cacheEnabled bool
	var cacheMode string
	err := l.pool.QueryRow(ctx,
		`SELECT cache_enabled, COALESCE(cache_mode, 'semantic') FROM organizations WHERE id = $1`,
		orgID,
	).Scan(&cacheEnabled, &cacheMode)
	if err != nil {
		return nil, fmt.Errorf("load org cache policy: %w", err)
	}

	return cachePolicyFor(cacheEnabled, cacheMode, l.log), nil
}

// cachePolicyFor maps the organizations row (cache_enabled, cache_mode) onto
// the cache policy. The admin API's valid modes (cache_handlers): off |
// contract, not a default case — an org that said NO must get a fully
// disabled cache (lookup AND write), never the semantic default.
func cachePolicyFor(cacheEnabled bool, cacheMode string, log *slog.Logger) *OrgPolicy {
	policy := &OrgPolicy{
		CacheMetrics: true,
		TTL:          24 * time.Hour,
	}

	if !cacheEnabled {
		policy.Mode = PrivacyDisabled
		return policy
	}

	switch strings.ToLower(cacheMode) {
	case "off":
		policy.Mode = PrivacyDisabled
	case "exact":
		policy.Mode = PrivacyEnabled
		policy.Semantic = false
	case "semantic", "":
		policy.Mode = PrivacyEnabled
		policy.Semantic = true
	default:
		log.Warn("unknown cache_mode, defaulting to semantic", "mode", cacheMode)
		policy.Mode = PrivacyEnabled
		policy.Semantic = true
	}

	return policy
}

// Wrap returns a closure that calls LoadOrgPolicy on the receiver,
// adapting *DBPolicyLoader to the OrgPolicyLoader function type.
func (l *DBPolicyLoader) Wrap() OrgPolicyLoader {
	return l.LoadOrgPolicy
}
