package a2aagg

// SQL contract for the A2A agent registry on the disposable,
// fully migrated Postgres (testdb.Postgres, no build tag — the harness
// posture of pkg/adminstore sqlcontract_int_test.go). Every exported store
// method runs the production SQL with present/disabled/missing combinations
// and every partial-update placeholder shape, failing on any
// *pgconn.PgError (rejected columns/types/placeholders). Business errors
// (ErrNotFound, duplicate names) are asserted where they pin semantics.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sqlc03fA2AContract fails the test when Postgres rejects the SQL (any
// *pgconn.PgError); other errors are business answers and only logged.
func sqlc03fA2AContract(t *testing.T, name string, fn func(ctx context.Context) error) {
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

func sqlc03fA2ASeed(t *testing.T, pool *pgxpool.Pool) (orgA, orgB, token string) {
	t.Helper()
	ctx := context.Background()
	token = fmt.Sprintf("sc03f%x", time.Now().UnixNano())
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-a", token+"-org-a").Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-b", token+"-org-b").Scan(&orgB))
	_, err := pool.Exec(ctx, `
		INSERT INTO a2a_agents (org_id, name, display_name, url, enabled)
		VALUES ($1::uuid, $2, 'Contract A2A A', 'https://a2a.example.com/a', true),
		       ($1::uuid, $3, 'Contract A2A B', 'https://a2a.example.com/b', false)`,
		orgA, token+"-alpha", token+"-beta")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("a2aagg contract cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM a2a_agents WHERE org_id::text = ANY($1)`, []string{orgA, orgB})
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA, orgB})
	})
	return orgA, orgB, token
}

func TestSQLContractA2AAgg(t *testing.T) {
	pool := testdb.Postgres(t)
	orgA, orgB, token := sqlc03fA2ASeed(t, pool)
	ctx := context.Background()
	store := NewStore(pool)
	missing := token + "-missing"

	sqlc03fA2AContract(t, "Create[gamma]", func(ctx context.Context) error {
		agent, err := store.Create(ctx, CreateParams{
			OrgID: orgA, Name: token + "-gamma", URL: "https://a2a.example.com/g", Enabled: true})
		if err != nil {
			return err
		}
		assert.Equal(t, token+"-gamma", agent.Name)
		return nil
	})
	_, err := store.Create(ctx, CreateParams{OrgID: orgA, Name: token + "-gamma", URL: "https://a2a.example.com"})
	require.ErrorContains(t, err, "already exists", "Create[duplicate] is a typed conflict")

	sqlc03fA2AContract(t, "GetEnabled[alpha]", func(ctx context.Context) error {
		agent, err := store.GetEnabled(ctx, orgA, token+"-alpha")
		if err != nil {
			return err
		}
		assert.True(t, agent.Enabled)
		return nil
	})
	_, err = store.GetEnabled(ctx, orgA, token+"-beta")
	require.ErrorIs(t, err, ErrNotFound, "GetEnabled[disabled] must read as missing")
	_, err = store.GetEnabled(ctx, orgA, missing)
	require.ErrorIs(t, err, ErrNotFound, "GetEnabled[missing]")

	sqlc03fA2AContract(t, "Get[alpha]", func(ctx context.Context) error {
		_, err := store.Get(ctx, orgA, token+"-alpha")
		return err
	})
	sqlc03fA2AContract(t, "Get[beta,disabled]", func(ctx context.Context) error {
		agent, err := store.Get(ctx, orgA, token+"-beta")
		if err != nil {
			return err
		}
		assert.False(t, agent.Enabled)
		return nil
	})
	_, err = store.Get(ctx, orgA, missing)
	require.ErrorIs(t, err, ErrNotFound, "Get[missing]")

	sqlc03fA2AContract(t, "List[orgA]", func(ctx context.Context) error {
		agents, err := store.List(ctx, orgA)
		if err != nil {
			return err
		}
		assert.GreaterOrEqual(t, len(agents), 3, "alpha, beta and the created gamma")
		return nil
	})
	sqlc03fA2AContract(t, "List[orgB,empty]", func(ctx context.Context) error {
		agents, err := store.List(ctx, orgB)
		if err != nil {
			return err
		}
		assert.Empty(t, agents)
		return nil
	})

	// Update — every partial combination re-shapes the placeholder list.
	newURL := "https://a2a.example.com/g2"
	enabled := false
	display := "Gamma A2A"
	for _, tc := range []struct {
		name string
		p    UpdateParams
	}{
		{"url", UpdateParams{URL: &newURL}},
		{"enabled", UpdateParams{Enabled: &enabled}},
		{"display-name", UpdateParams{DisplayName: &display}},
		{"all", UpdateParams{DisplayName: &display, URL: &newURL, Enabled: &enabled}},
	} {
		sqlc03fA2AContract(t, "Update[gamma,"+tc.name+"]", func(ctx context.Context) error {
			agent, err := store.Update(ctx, orgA, token+"-gamma", tc.p)
			if err != nil {
				return err
			}
			assert.Equal(t, token+"-gamma", agent.Name)
			return nil
		})
	}
	_, err = store.Update(ctx, orgA, missing, UpdateParams{})
	require.ErrorIs(t, err, ErrNotFound, "Update[missing]")

	sqlc03fA2AContract(t, "Delete[gamma]", func(ctx context.Context) error {
		return store.Delete(ctx, orgA, token+"-gamma")
	})
	err = store.Delete(ctx, orgA, token+"-gamma")
	require.ErrorIs(t, err, ErrNotFound, "Delete[already removed]")
}
