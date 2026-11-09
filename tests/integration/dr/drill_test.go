//go:build integration

// Package dr holds the executable disaster-recovery drill (ENT-05): back up a
// migrated database with pg_dump, wipe it, restore, and prove data integrity
// (audit hash-chain + row counts) while measuring restore time for RTO.
package dr

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // register the pgx database/sql driver
	"github.com/reireirei/yabanin/pkg/auditlog"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestDR_BackupWipeRestoreVerify(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("drill"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	host, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	port, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)
	uri := fmt.Sprintf("postgres://postgres:postgres@%s:%s/drill?sslmode=disable", host, port.Port())

	cid := pgContainer.GetContainerID()
	execIn := func(args ...string) string {
		out, err := execCommand("docker", append([]string{"exec", "-i", cid}, args...)...)
		require.NoError(t, err, "%v", args)
		return out
	}

	// Wait out the image's init window: the entrypoint restarts the server
	// between first-boot setup and the real start, and connections are
	// refused during that gap even after Run() reports readiness once.
	require.Eventually(t, func() bool {
		out, err := execCommand("docker", "exec", cid,
			"pg_isready", "-h", "localhost", "-U", "postgres", "-d", "drill")
		return err == nil && strings.Contains(out, "accepting connections")
	}, 30*time.Second, 500*time.Millisecond, "postgres never became ready inside the container")

	// Migrate to the production schema (same files a real deployment runs).
	// Globbed, not hardcoded: the migration set is squashed periodically and
	// the drill must exercise whatever the repo actually ships.
	repoRoot, err := filepath.Abs("../../..")
	require.NoError(t, err)
	migFiles, err := filepath.Glob(filepath.Join(repoRoot, "migrations", "*.up.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, migFiles, "no up-migrations discovered")
	for _, local := range migFiles {
		out, err := execCommand("docker", "cp", local, cid+":/tmp/mig.sql")
		require.NoError(t, err, out)
		out, err = execCommand("docker", "exec", "-i", cid, "psql", "-h", "localhost", "-U", "postgres", "-d", "drill",
			"-v", "ON_ERROR_STOP=1", "-q", "-f", "/tmp/mig.sql")
		require.NoError(t, err, "apply %s: %s", filepath.Base(local), out)
	}

	pool, err := sql.Open("pgx", uri)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	// Seed audit rows through the production writer so the restored chain is
	// verifiable with the production verifier.
	aw := auditlog.NewWriter(pool)
	require.NoError(t, aw.BackfillChain(ctx))
	require.NoError(t, aw.Append(ctx, "drill.action", "dr-resource", `{"k":"v"}`, "admin-1", "Drill Admin", "127.0.0.1"))
	require.NoError(t, aw.Append(ctx, "drill.action2", "dr-resource2", `{"k2":"v2"}`, "admin-1", "Drill Admin", "127.0.0.1"))

	var auditRowsBefore int
	require.NoError(t, pool.QueryRowContext(ctx, "SELECT count(*) FROM admin_audit_logs").Scan(&auditRowsBefore))
	require.GreaterOrEqual(t, auditRowsBefore, 2)

	// --- Backup (RPO artifact) ---
	backupStart := time.Now()
	dump, err := execCommand("docker", "exec", cid, "sh", "-c",
		"pg_dump 'postgres://postgres:postgres@localhost:5432/drill?sslmode=disable' --format=custom")
	require.NoError(t, err)
	backupDur := time.Since(backupStart)
	require.NotEmpty(t, dump, "pg_dump produced no output")
	t.Logf("RPO evidence: backup taken at %s (%d bytes, %s)",
		time.Now().UTC().Format(time.RFC3339), len(dump), backupDur.Round(time.Millisecond))

	// --- Simulate disaster ---
	wipeStart := time.Now()
	execIn("psql", "-h", "localhost", "-U", "postgres", "-d", "drill", "-c", "DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
	t.Logf("disaster simulated (schema dropped) in %s", time.Since(wipeStart).Round(time.Millisecond))

	// --- Restore (RTO measurement) ---
	restoreStart := time.Now()
	writeDump := func() (string, error) {
		cmd := exec.Command("docker", "exec", "-i", cid, "sh", "-c", "cat > /tmp/drill.dump")
		cmd.Stdin = bytes.NewReader([]byte(dump))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := writeDump()
	require.NoError(t, err, "write dump: %s", out)
	out, err = execCommand("docker", "exec", cid,
		"pg_restore", "-d", "postgres://postgres:postgres@localhost:5432/drill?sslmode=disable",
		"--no-owner", "--exit-on-error", "/tmp/drill.dump")
	require.NoError(t, err, "pg_restore: %s", out)
	restoreDur := time.Since(restoreStart)

	// --- Verify integrity with production tooling ---
	restored, err := sql.Open("pgx", uri)
	require.NoError(t, err)
	t.Cleanup(func() { _ = restored.Close() })

	var tables int
	require.NoError(t, restored.QueryRowContext(ctx,
		"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").Scan(&tables))
	require.GreaterOrEqual(t, tables, 50, "expected the full migrated schema")

	var auditRows int
	require.NoError(t, restored.QueryRowContext(ctx, "SELECT count(*) FROM admin_audit_logs").Scan(&auditRows))
	require.Equal(t, auditRowsBefore, auditRows, "audit rows must survive the restore")

	broken, err := auditlog.NewVerifier(restored).Verify(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(0), broken, "audit hash-chain must be intact after restore")

	t.Logf("RTO evidence: restore+verify completed in %s (dump %d bytes)",
		restoreDur.Round(time.Millisecond), len(dump))
}

// execCommand runs a command and returns its combined output.
func execCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}
