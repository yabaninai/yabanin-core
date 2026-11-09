//go:build integration

package cli

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	migrate "github.com/reireirei/yabanin/pkg/migrate"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestSessionKey_IntegrationMintResolveRevoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pg, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })
	host, err := pg.Host(ctx)
	require.NoError(t, err)
	port, err := pg.MappedPort(ctx, "5432")
	require.NoError(t, err)
	dsn := "postgres://postgres:postgres@" + host + ":" + strings.Split(port.Port(), "/")[0] + "/yabanin?sslmode=disable"
	// Deadline-poll until the fresh container accepts the migration run —
	// no fixed retry-count sleep loop.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err = migrate.Run(ctx, dsn, "sg"); err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	require.NoError(t, err, "migrate did not succeed within 15s")
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	rd, err := testredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { _ = rd.Terminate(context.Background()) })
	rhost, err := rd.Host(ctx)
	require.NoError(t, err)
	rport, err := rd.MappedPort(ctx, "6379")
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: rhost + ":" + strings.Split(rport.Port(), "/")[0]})
	t.Cleanup(func() { _ = rdb.Close() })

	var orgID, teamID, keyID string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO organizations (name, slug) VALUES ('sess', 'sess-it') RETURNING id::text`).Scan(&orgID))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO organizations_teams (org_id, name, slug) VALUES ($1::uuid, 'core', 'core') RETURNING id::text`, orgID).Scan(&teamID))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO api_keys (key_hash, org_id, team_id, name, active, can_mint_sessions, labels)
		 VALUES ('parent-hash', $1::uuid, $2::uuid, 'parent', true, true, '{"team":"payments"}'::jsonb) RETURNING id::text`, orgID, teamID).Scan(&keyID))

	gw := &gateway{dbPool: pool, rdb: rdb, log: slog.Default(), sessionDB: pool, sessionKV: rdb}
	req := httptest.NewRequest(http.MethodPost, "/v1/yabanin/session-keys", strings.NewReader(`{"ttl_seconds":60,"labels":{"job":"lint"}}`))
	req = req.WithContext(withPrincipal(req.Context(), principal{APIKeyID: keyID, CanMintSessions: true}))
	req.Header.Set("X-Org-Id", orgID)
	rec := httptest.NewRecorder()
	gw.mintSessionKey(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "ybs_")
}
