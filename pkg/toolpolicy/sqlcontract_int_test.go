package toolpolicy

// disposable, fully migrated Postgres (testdb.Postgres, no build tag — the
// harness posture of pkg/adminstore sqlcontract_int_test.go). Every exported
// store method runs the production SQL with enabled/disabled/missing
// combinations and every partial-update placeholder shape, failing on any
// *pgconn.PgError (rejected columns/types/placeholders). Business errors
// (ErrNotFound, duplicate names) are asserted where they pin semantics.

import (
	"context"
	"encoding/json"
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

// sqlc03fToolContract fails the test when Postgres rejects the SQL (any
// *pgconn.PgError); other errors are business answers and only logged.
func sqlc03fToolContract(t *testing.T, name string, fn func(ctx context.Context) error) {
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

func sqlc03fToolSeed(t *testing.T, pool *pgxpool.Pool) (orgA, orgB, token string) {
	t.Helper()
	ctx := context.Background()
	token = fmt.Sprintf("sc03f%x", time.Now().UnixNano())
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-a", token+"-org-a").Scan(&orgA))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text`,
		token+"-org-b", token+"-org-b").Scan(&orgB))
	// allow the exact tool for every subject; deny the wildcard for one
	// agent; one disabled allow row (excluded from ListEnabled).
	_, err := pool.Exec(ctx, `
		INSERT INTO tool_policies (org_id, name, subject, tool, action, priority, enabled)
		VALUES ($1::uuid, $2, '*', 'web_search', 'allow', 100, true),
		       ($1::uuid, $3, $4, 'web_*', 'deny', 50, true),
		       ($1::uuid, $5, '*', 'shell', 'allow', 100, false)`,
		orgA, token+"-allow-exact", token+"-deny-wildcard", "11111111-1111-1111-1111-111111111111", token+"-disabled")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("toolpolicy contract cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM tool_policies WHERE org_id::text = ANY($1)`, []string{orgA, orgB})
		cleanup(`DELETE FROM organizations WHERE id::text = ANY($1)`, []string{orgA, orgB})
	})
	return orgA, orgB, token
}

func TestSQLContractToolpolicy(t *testing.T) {
	pool := testdb.Postgres(t)
	orgA, orgB, token := sqlc03fToolSeed(t, pool)
	ctx := context.Background()
	store := NewStore(pool)
	missing := token + "-missing"

	sqlc03fToolContract(t, "Create[gamma]", func(ctx context.Context) error {
		pol, err := store.Create(ctx, CreateParams{
			OrgID: orgA, Name: token + "-gamma", Subject: "*", Tool: "mcp:github:*",
			Action: "deny", Priority: 10, Enabled: true})
		if err != nil {
			return err
		}
		assert.Equal(t, "deny", pol.Action)
		return nil
	})
	_, err := store.Create(ctx, CreateParams{OrgID: orgA, Name: token + "-gamma", Subject: "*", Tool: "*", Action: "allow"})
	require.ErrorContains(t, err, "already exists", "Create[duplicate] is a typed conflict")

	sqlc03fToolContract(t, "ListEnabled[orgA]", func(ctx context.Context) error {
		pols, err := store.ListEnabled(ctx, orgA)
		if err != nil {
			return err
		}
		assert.Len(t, pols, 3, "engine loader sees enabled rows only (disabled one excluded, gamma included)")
		return nil
	})
	sqlc03fToolContract(t, "ListEnabled[orgB,empty]", func(ctx context.Context) error {
		pols, err := store.ListEnabled(ctx, orgB)
		if err != nil {
			return err
		}
		assert.Empty(t, pols)
		return nil
	})

	sqlc03fToolContract(t, "List[orgA]", func(ctx context.Context) error {
		pols, err := store.List(ctx, orgA)
		if err != nil {
			return err
		}
		assert.GreaterOrEqual(t, len(pols), 4, "all rows regardless of enabled state")
		return nil
	})
	sqlc03fToolContract(t, "List[orgB,empty]", func(ctx context.Context) error {
		pols, err := store.List(ctx, orgB)
		if err != nil {
			return err
		}
		assert.Empty(t, pols)
		return nil
	})

	sqlc03fToolContract(t, "Get[allow-exact]", func(ctx context.Context) error {
		pol, err := store.Get(ctx, orgA, token+"-allow-exact")
		if err != nil {
			return err
		}
		assert.Equal(t, "web_search", pol.Tool)
		return nil
	})
	_, err = store.Get(ctx, orgA, missing)
	require.ErrorIs(t, err, ErrNotFound, "Get[missing]")

	// Update — every partial combination re-shapes the placeholder list.
	subject := "22222222-2222-2222-2222-222222222222"
	tool := "fetch"
	action := "allow"
	priority := 7
	enabled := false
	for _, tc := range []struct {
		name string
		p    UpdateParams
	}{
		{"subject", UpdateParams{Subject: &subject}},
		{"tool", UpdateParams{Tool: &tool}},
		{"action", UpdateParams{Action: &action}},
		{"priority", UpdateParams{Priority: &priority}},
		{"enabled", UpdateParams{Enabled: &enabled}},
		{"all", UpdateParams{Subject: &subject, Tool: &tool, Action: &action, Priority: &priority, Enabled: &enabled}},
	} {
		sqlc03fToolContract(t, "Update[gamma,"+tc.name+"]", func(ctx context.Context) error {
			pol, err := store.Update(ctx, orgA, token+"-gamma", tc.p)
			if err != nil {
				return err
			}
			assert.Equal(t, token+"-gamma", pol.Name)
			return nil
		})
	}
	_, err = store.Update(ctx, orgA, missing, UpdateParams{})
	require.ErrorIs(t, err, ErrNotFound, "Update[missing]")

	sqlc03fToolContract(t, "Delete[gamma]", func(ctx context.Context) error {
		return store.Delete(ctx, orgA, token+"-gamma")
	})
	err = store.Delete(ctx, orgA, token+"-gamma")
	require.ErrorIs(t, err, ErrNotFound, "Delete[already removed]")

	// OP-6: the server + rules columns round-trip. The rules document is
	// the exact wire shape the engine compiles on load.
	const guardRules = `{"args":{"max_bytes":4096,"deny_regex":["sk-[A-Za-z0-9_-]{16,}"]},"result":{"mode":"mask","secrets":true},"fail":"closed"}`
	var gammaRules string
	sqlc03fToolContract(t, "Create[guarded]", func(ctx context.Context) error {
		pol, err := store.Create(ctx, CreateParams{
			OrgID: orgA, Name: token + "-guarded", Subject: "*", Server: "github",
			Tool: "*", Action: "allow", Rules: json.RawMessage(guardRules),
			Priority: 10, Enabled: true})
		if err != nil {
			return err
		}
		assert.Equal(t, "github", pol.Server, "server column round-trips")
		assert.JSONEq(t, guardRules, string(pol.Rules), "rules round-trip")
		return nil
	})
	sqlc03fToolContract(t, "ListEnabled[guarded,server+rules]", func(ctx context.Context) error {
		pols, err := store.ListEnabled(ctx, orgA)
		if err != nil {
			return err
		}
		for _, p := range pols {
			if p.Name == token+"-guarded" {
				gammaRules = p.Server
				assert.Equal(t, "github", p.Server)
				assert.JSONEq(t, guardRules, string(p.Rules))
			}
		}
		assert.Equal(t, "github", gammaRules, "the engine loader carries server+rules")
		return nil
	})
	// OP-6 org isolation: orgB's loader sees none of orgA's guarded rows.
	sqlc03fToolContract(t, "ListEnabled[orgB,isolation]", func(ctx context.Context) error {
		pols, err := store.ListEnabled(ctx, orgB)
		if err != nil {
			return err
		}
		for _, p := range pols {
			assert.NotEqual(t, token+"-guarded", p.Name, "orgA guard rules must be invisible to orgB")
		}
		return nil
	})
	newRules := json.RawMessage(`{"args":{"max_bytes":64}}`)
	sqlc03fToolContract(t, "Update[guarded,rules]", func(ctx context.Context) error {
		pol, err := store.Update(ctx, orgA, token+"-guarded", UpdateParams{Rules: &newRules})
		if err != nil {
			return err
		}
		assert.JSONEq(t, string(newRules), string(pol.Rules), "rules patch applies")
		return nil
	})
	// rules = NULL (clearing the guard) round-trips as nil.
	sqlc03fToolContract(t, "Update[guarded,clear-rules]", func(ctx context.Context) error {
		empty := json.RawMessage{}
		pol, err := store.Update(ctx, orgA, token+"-guarded", UpdateParams{Rules: &empty})
		if err != nil {
			return err
		}
		assert.Nil(t, pol.Rules, "an empty patch value clears the rules (NULL)")
		return nil
	})
}
