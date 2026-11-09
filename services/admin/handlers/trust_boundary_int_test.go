//go:build integration

package handlers_test

// NEXT-15-F2 (FIXED): /v1/feedback requires a Bearer org/agent API key and
// derives the org SERVER-SIDE from the resolved key. The client X-Org-Id
// header is ignored — an anonymous caller can no longer attach feedback
// (classifier training signal) to an arbitrary org.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
	"github.com/stretchr/testify/require"
)

func TestNEXT15_FeedbackBearerOrgAttribution(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()

	// Org + team + api_key for the authenticated caller.
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('next15-fb', 'next15-fb') RETURNING id::text`).Scan(&orgID))
	_, err := pool.Exec(ctx,
		`INSERT INTO organizations_teams (org_id, name, slug) VALUES ($1, 'fb', 'fb')`, orgID)
	require.NoError(t, err)
	hash := sha256.Sum256([]byte("next15-feedback-key"))
	_, err = pool.Exec(ctx,
		`INSERT INTO api_keys (key_hash, org_id, name, active, team_id)
		 SELECT $1, $2, 'fb-key', true, id FROM organizations_teams WHERE org_id = $2`,
		fmt.Sprintf("%x", hash), orgID)
	require.NoError(t, err)

	h := handlers.New(&stubStore{}, "test-session-secret", "localhost", nil)
	h.SetFeedbackCollector(feedback.NewCollector(pool, slog.Default()), auth.NewResolver(pool, nil, 0, nil))
	router := h.SetupRouter()

	doPost := func(authz, orgHeader string) int {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/feedback",
			strings.NewReader(`{"action":"thumbs_up","override_class":"easy"}`))
		req.Header.Set("Content-Type", "application/json")
		if authz != "" {
			req.Header.Set("Authorization", "Bearer "+authz)
		}
		if orgHeader != "" {
			req.Header.Set("X-Org-Id", orgHeader)
		}
		req.Header.Set("X-Request-Id", fmt.Sprintf("next15-req-%d", time.Now().UnixNano()))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	t.Run("anonymous caller is 401 (F2 fixed)", func(t *testing.T) {
		if code := doPost("", "99999999-9999-4999-8999-999999999999"); code != http.StatusUnauthorized {
			t.Errorf("anon feedback = %d, want 401", code)
		}
	})

	t.Run("invalid key is 401", func(t *testing.T) {
		if code := doPost("wrong-key", ""); code != http.StatusUnauthorized {
			t.Errorf("bad-key feedback = %d, want 401", code)
		}
	})

	t.Run("valid key accepted; client X-Org-Id is ignored (server-side attribution)", func(t *testing.T) {
		if code := doPost("next15-feedback-key", "99999999-9999-4999-8999-999999999999"); code != http.StatusAccepted {
			t.Errorf("key feedback with forged org header = %d, want 202 (org derived from the key)", code)
		}
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM classifier_feedback WHERE org_id = $1`, orgID).Scan(&n))
		if n != 1 {
			t.Errorf("feedback rows for the KEY org = %d, want 1 (forged header must not attribute)", n)
		}
		var forged int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM classifier_feedback WHERE org_id = '99999999-9999-4999-8999-999999999999'`).Scan(&forged))
		if forged != 0 {
			t.Errorf("feedback rows for the forged org = %d, want 0", forged)
		}
	})
}
