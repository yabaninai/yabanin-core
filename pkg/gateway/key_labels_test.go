package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
)

type keyLabelRow struct {
	orgID    string
	apiKeyID string
	labels   map[string]string
	locked   bool
	mint     bool
	usage    bool
}

func (m *keyLabelRow) Scan(dest ...interface{}) error {
	strIdx := 0
	boolIdx := 0
	for _, d := range dest {
		switch v := d.(type) {
		case *string:
			switch strIdx {
			case 0:
				*v = m.apiKeyID
			case 1:
				*v = m.orgID
			default:
				*v = ""
			}
			strIdx++
		case *[]byte:
			raw, err := json.Marshal(m.labels)
			if err != nil {
				return err
			}
			*v = raw
		case *bool:
			switch boolIdx {
			case 0:
				*v = m.locked
			case 1:
				*v = m.mint
			case 2:
				*v = m.usage
			}
			boolIdx++
		case **time.Time:
			*v = nil
		}
	}
	return nil
}

func TestKeyLabels_HeaderOverrideAndLock(t *testing.T) {
	row := &keyLabelRow{
		orgID: "org-1", apiKeyID: "key-1",
		labels: map[string]string{"team": "payments"},
		mint:   true,
	}
	pool := &mockDBForGateway{queryRowFn: func(ctx context.Context, query string, args ...interface{}) pgx.Row {
		return row
	}}
	rdb := &mockRedisForGateway{getFn: func(ctx context.Context, key string) *redis.StringCmd {
		cmd := redis.NewStringCmd(ctx)
		cmd.SetErr(redis.Nil)
		return cmd
	}}
	resolver := auth.NewResolver(pool, rdb, 300, nil)
	gw := &gateway{}

	serve := func(header string) (team string, mint bool, dropped string, code int) {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer yb_labelkey")
		if header != "" {
			req.Header.Set("X-Yabanin-Labels", header)
		}
		rec := httptest.NewRecorder()
		NewAuthMiddleware(config.Gateway{AuthMode: "header"}, resolver).ServeHTTP(
			gw.labelsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				team = labelsFrom(r.Context())["team"]
				if p, ok := principalFrom(r.Context()); ok {
					mint = p.CanMintSessions
				}
				w.WriteHeader(http.StatusNoContent)
			})),
		).ServeHTTP(rec, req)
		return team, mint, rec.Header().Get("X-Yabanin-Labels-Dropped"), rec.Code
	}

	team, mint, _, code := serve("")
	if code != http.StatusNoContent || team != "payments" || !mint {
		t.Fatalf("key labels: code=%d team=%q mint=%v", code, team, mint)
	}

	team, _, _, code = serve("team=other")
	if code != http.StatusNoContent || team != "other" {
		t.Fatalf("unlocked override: code=%d team=%q", code, team)
	}

	row.locked = true
	team, _, dropped, code := serve("team=other")
	if code != http.StatusNoContent || team != "payments" || !strings.Contains(dropped, "locked") {
		t.Fatalf("locked: code=%d team=%q dropped=%q", code, team, dropped)
	}
}
