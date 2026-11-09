//go:build integration

package lineage

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	migrate "github.com/reireirei/yabanin/pkg/migrate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// The Docker-gated half of L02/H1: on a REAL Postgres the outbox relay must
// be durable across a consumer "restart" (a new Outbox instance picks up the
// pending rows), idempotent on request_id, and the resulting per-org chain
// must verify with VerifyChain.

func startLineageDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err, "docker/testcontainers required")
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	parts := strings.Split(port.Port(), "/")
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s:%s/yabanin?sslmode=disable", host, parts[0])

	waitPool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(waitPool.Close)
	waitForLineageDBReady(t, ctx, waitPool)
	_, err = migrate.Run(ctx, connStr, "sg")
	require.NoError(t, err)
	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool, connStr
}

func attestation(reqID, orgID string) Attestation {
	return Attestation{
		RequestID: reqID, OrgID: orgID, ModelUsed: "gpt-4o-mini",
		InferenceRegion: "US", ModelOrigin: "US", LogStorageRegion: "SG",
		ProviderEntity: "US",
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// waitForLineageDBReady polls the pool until Postgres accepts connections or
// the deadline expires — container healthcheck by deadline, not a fixed
// retry-count sleep loop.
func waitForLineageDBReady(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var err error
	for {
		if err = pool.Ping(ctx); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("test postgres did not become reachable within 15s: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestIntegration_OutboxDurableAcrossRestart(t *testing.T) {
	pool, _ := startLineageDB(t)
	ctx := context.Background()
	orgID := "11111111-1111-4111-8111-111111111111"

	// "Gateway process 1": enqueues two rows but the relay NEVER runs
	// (simulated hard kill between commit and relay).
	ob1 := NewOutbox(pool, slog.Default())
	require.NoError(t, ob1.Enqueue(ctx, attestation("req-r1", orgID), "sig-1", "k1"))
	require.NoError(t, ob1.Enqueue(ctx, attestation("req-r2", orgID), "sig-2", "k1"))

	// "Gateway process 2" (restart): a fresh outbox relays pending rows.
	ob2 := NewOutbox(pool, slog.Default())
	n, err := ob2.RelayPass(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, 2, "both committed rows must relay after restart")

	// Idempotency: relaying again inserts nothing new.
	var rows int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM request_lineage").Scan(&rows))
	n2, err := ob2.RelayPass(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n2, "second pass must find nothing pending")
	var rows2 int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM request_lineage").Scan(&rows2))
	assert.Equal(t, rows, rows2, "duplicate relay pass must not insert (idempotent on request_id)")

	// The chain verifies (H1) and covers every relayed row.
	ledger := NewLedgerStore(pool)
	status, err := ledger.VerifyChain(ctx, orgID)
	require.NoError(t, err)
	assert.True(t, status.Intact, "chain must be intact after relay; broken_at=%v", status.BrokenAt)
	assert.Equal(t, rows, status.Chained)
}

func TestIntegration_VerifyChainDetectsTampering(t *testing.T) {
	pool, _ := startLineageDB(t)
	ctx := context.Background()
	orgID := "22222222-2222-4222-8222-222222222222"

	ob := NewOutbox(pool, slog.Default())
	require.NoError(t, ob.Enqueue(ctx, attestation("req-t1", orgID), "sig-1", "k1"))
	require.NoError(t, ob.Enqueue(ctx, attestation("req-t2", orgID), "sig-2", "k1"))
	_, err := ob.RelayPass(ctx)
	require.NoError(t, err)

	ledger := NewLedgerStore(pool)
	status, err := ledger.VerifyChain(ctx, orgID)
	require.NoError(t, err)
	require.True(t, status.Intact)

	// Direct UPDATE is blocked by the append-only triggers; simulate tampering
	// by disabling the guards, mutating a row, and restoring them —
	// verification must catch the rewritten row.
	for _, trg := range []string{"trg_lineage_no_update", "trg_lineage_no_delete"} {
		_, err = pool.Exec(ctx, "ALTER TABLE request_lineage DISABLE TRIGGER "+trg)
		require.NoError(t, err)
	}
	_, err = pool.Exec(ctx, "UPDATE request_lineage SET model_used='tampered' WHERE request_id='req-t1'")
	require.NoError(t, err)
	for _, trg := range []string{"trg_lineage_no_update", "trg_lineage_no_delete"} {
		_, err = pool.Exec(ctx, "ALTER TABLE request_lineage ENABLE TRIGGER "+trg)
		require.NoError(t, err)
	}

	status2, err := ledger.VerifyChain(ctx, orgID)
	require.NoError(t, err)
	assert.False(t, status2.Intact, "tampered row must break the chain")
}
