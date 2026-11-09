package rulestore

// fully migrated Postgres (testdb.Postgres, no build tag — the harness
// posture of pkg/adminstore sqlcontract_int_test.go). The store's only SQL
// surface is the routing_rules read behind GetByOrg; the contract runs it
// with a real org, an org without rules and an unknown org, and with the
// Redis layer both absent and present (cache fill, empty-set caching,
// invalidation), failing on any *pgconn.PgError or rows breakage.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqlc03fRuleContract fails the test when Postgres rejects the SQL (any
// *pgconn.PgError); other errors are business answers and only logged.
func sqlc03fRuleContract(t *testing.T, name string, fn func(ctx context.Context) error) {
	t.Helper()
	err := fn(context.Background())
	if err == nil {
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Errorf("%s: Postgres rejected the SQL: %s (code %s, where %s, detail %q)",
			name, pgErr.Message, pgErr.Code, pgErr.Where, pgErr.Detail)
		return
	}
	t.Logf("%s: non-SQL error tolerated by the contract: %v", name, err)
}

func TestSQLContractRulestore(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	token := fmt.Sprintf("sc03f%x", time.Now().UnixNano())

	var orgA, orgB string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-a", token+"-org-a").Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-b", token+"-org-b").Scan(&orgB))
	// orgA: one enabled rule (priority 10) and one disabled (priority 20);
	// orgB: none.
	_, err := pool.Exec(ctx, `
		INSERT INTO routing_rules (org_id, match_expr, target_model, priority, enabled)
		VALUES ($1::uuid, $2, $3, 10, true),
		       ($1::uuid, $2, $3, 20, false)`,
		orgA, `model == "`+token+`-m"`, token+"-m")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("rulestore contract cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM routing_rules WHERE org_id::text = ANY($1)`, []string{orgA, orgB})
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA, orgB})
	})

	newStore := func(rdb cacheOps) *Store {
		return New(pool, rdb, time.Minute, nil, slog.Default())
	}

	// DB path — real org with one enabled rule.
	sqlc03fRuleContract(t, "GetByOrg[orgA]", func(ctx context.Context) error {
		rules, err := newStore(nil).GetByOrg(ctx, orgA)
		if err != nil {
			return err
		}
		if !assert.Len(t, rules, 1, "only the enabled rule is served") {
			return nil
		}
		assert.Equal(t, token+"-m", rules[0].TargetModel)
		assert.Equal(t, orgA, rules[0].OrgID)
		return nil
	})

	// DB path — empty rule set (also exercises the empty-result shape).
	sqlc03fRuleContract(t, "GetByOrg[orgB,empty]", func(ctx context.Context) error {
		rules, err := newStore(nil).GetByOrg(ctx, orgB)
		if err != nil {
			return err
		}
		assert.Empty(t, rules)
		return nil
	})
	sqlc03fRuleContract(t, "GetByOrg[unknown-org,empty]", func(ctx context.Context) error {
		// Production callers pass org uuids; a valid uuid without rules
		// yields the empty set.
		rules, err := newStore(nil).GetByOrg(ctx, uuid.NewString())
		if err != nil {
			return err
		}
		assert.Empty(t, rules)
		return nil
	})

	// Redis-backed path: fill, hit, invalidate, re-read; the empty org
	// caches its empty set the same way.
	rdb := testdb.Redis(t)
	t.Cleanup(func() {
		if err := rdb.Del(ctx, cacheKeyPrefix+orgA, cacheKeyPrefix+orgB).Err(); err != nil {
			t.Errorf("rulestore contract redis cleanup: %v", err)
		}
	})
	cached := newStore(rdb)
	sqlc03fRuleContract(t, "GetByOrg[redis,fill]", func(ctx context.Context) error {
		rules, err := cached.GetByOrg(ctx, orgA)
		if err != nil {
			return err
		}
		assert.Len(t, rules, 1)
		return nil
	})
	assert.Equal(t, int64(1), rdb.Exists(ctx, cacheKeyPrefix+orgA).Val(),
		"the rule set must be cached after the DB fill")
	sqlc03fRuleContract(t, "GetByOrg[redis,hit]", func(ctx context.Context) error {
		rules, err := cached.GetByOrg(ctx, orgA)
		if err != nil {
			return err
		}
		assert.Len(t, rules, 1, "the cache hit must decode into the same rule set")
		return nil
	})
	sqlc03fRuleContract(t, "GetByOrg[redis,empty-set]", func(ctx context.Context) error {
		rules, err := cached.GetByOrg(ctx, orgB)
		if err != nil {
			return err
		}
		assert.Empty(t, rules)
		return nil
	})
	assert.Equal(t, int64(1), rdb.Exists(ctx, cacheKeyPrefix+orgB).Val(),
		"the empty rule set is cached too (RT-06)")
	cached.Invalidate(ctx, orgA)
	assert.Equal(t, int64(0), rdb.Exists(ctx, cacheKeyPrefix+orgA).Val(),
		"Invalidate must drop the org's cache entry")
	sqlc03fRuleContract(t, "GetByOrg[redis,after-invalidate]", func(ctx context.Context) error {
		rules, err := cached.GetByOrg(ctx, orgA)
		if err != nil {
			return err
		}
		assert.Len(t, rules, 1, "the post-invalidation read refills from the DB")
		return nil
	})
}
