//go:build integration

package accounting

import (
	"context"
	"database/sql"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// The same client request ID must restore as two independently paid calls.
func TestAccountingPaidBackupRestore(t *testing.T) {
	s := startStand(t)
	s.seedSecondOrg(t)
	rid := s.reqPrefix + "paid-restore"
	orgs := []string{s.oracleDB.orgID, s.orgB.orgID}
	keys := []string{s.apiKey, s.orgB.apiKey}
	for i, org := range orgs {
		status, body, err := s.chatFull(t, rid, 45*time.Second, chatOptions{
			apiKey: keys[i], stream: i == 1, content: org + rid,
		})
		require.NoError(t, err)
		require.Equal(t, httpOK, status, body)
	}
	require.Equal(t, fixtureTotals{2, 2, 2}, paidRestoreCounts(s, rid))
	before := make(map[string]string)
	var ids []string
	for _, org := range orgs {
		requireEventually(t, time.Minute, 100*time.Millisecond, func() bool {
			return s.oracleCount(t, `SELECT count(*) FROM settlement_jobs
				WHERE org_id=$1 AND request_id=$2 AND charge_kind='resale_deduction' AND status='settled'`, org, rid) == 1
		}, "paid restore control must settle before backup")
		ids = append(ids, s.requireUUIDKeyedCharge(t, rid, org, "before backup"))
		before[org] = paidRestoreDigest(t, s.oracleDB.db, org, rid)
	}
	require.NotEqual(t, ids[0], ids[1])
	dump := paidBackup(t, s)
	s.controlRequest(t, "after-paid-backup")
	restored, app := restorePaidDatabase(t, s, dump)
	requireRestoreRegionScope(t, app, rid)
	for _, org := range orgs {
		require.Equal(t, before[org], paidRestoreDigest(t, restored, org, rid))
	}
	var late int
	require.NoError(t, restored.QueryRowContext(t.Context(),
		"SELECT count(*) FROM request_logs WHERE request_id=$1", s.reqPrefix+"ctl-after-paid-backup").Scan(&late))
	require.Zero(t, late, "a post-backup request must be absent in the restored cluster")
	require.Equal(t, fixtureTotals{2, 2, 2}, paidRestoreCounts(s, rid))
}

func paidRestoreCounts(s *stand, rid string) fixtureTotals {
	a, d, r := s.fixture.Counts(rid)
	return fixtureTotals{a, d, r}
}

// Join by tenant and minted ID; a missing or duplicate row changes cardinality.
// Hash complete rows, including wallet remainder, without logging payloads.
func paidRestoreDigest(t *testing.T, db *sql.DB, org, rid string) string {
	t.Helper()
	const query = `SELECT count(*), min(encode(sha256(convert_to(
		jsonb_build_array(to_jsonb(a),to_jsonb(f),to_jsonb(l),to_jsonb(s),to_jsonb(c),to_jsonb(w))::text,
		'UTF8')), 'hex'))
		FROM request_admissions a
		JOIN request_terminal_facts f USING(invocation_id,org_id,client_request_id)
		JOIN request_logs l ON l.invocation_id=a.invocation_id AND l.org_id::text=a.org_id AND l.request_id=a.client_request_id
		JOIN settlement_jobs s ON s.invocation_id=a.invocation_id AND s.org_id=a.org_id AND s.request_id=a.client_request_id
		JOIN credit_transactions c ON c.invocation_id=a.invocation_id AND c.org_id=a.org_id AND c.request_id=a.client_request_id
		JOIN org_credits w ON w.org_id=a.org_id
		WHERE a.org_id=$1 AND a.client_request_id=$2 AND a.state='reconciled'
		AND f.event->>'tokens_in'='7' AND f.event->>'tokens_out'='3'
		AND l.tokens_in=7 AND l.tokens_out=3 AND l.status_code=200
		AND s.charge_kind='resale_deduction' AND s.status='settled' AND s.amount_micro_usd=$3
		AND c.type='usage' AND c.amount_micro_usd=-s.amount_micro_usd`
	var count int
	var digest sql.NullString
	require.NoError(t, db.QueryRowContext(t.Context(), query, org, rid, fixtureMicroUSDCost).Scan(&count, &digest))
	require.Equal(t, 1, count, "expected one complete paid chain for %s", org)
	require.True(t, digest.Valid)
	return digest.String
}

func paidRestoreCommand(t *testing.T, pg *testpostgres.PostgresContainer, args ...string) string {
	t.Helper()
	code, reader, err := pg.Exec(t.Context(), args)
	require.NoError(t, err)
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Zero(t, code, "%s", data)
	return string(data)
}

func paidBackup(t *testing.T, s *stand) string {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "dr", "backup.sh")
	require.NoError(t, s.pg.CopyFileToContainer(t.Context(), script, "/tmp/backup.sh", 0700))
	paidRestoreCommand(t, s.pg, "bash", "/tmp/backup.sh", "postgresql:///yabanin?user=yabanin", "/tmp/paid-backup")
	paidRestoreCommand(t, s.pg, "sh", "-ec", "sha256sum -c /tmp/paid-backup/*.sha256 && cp /tmp/paid-backup/*.dump /tmp/paid.dump")
	src, err := s.pg.CopyFileFromContainer(t.Context(), "/tmp/paid.dump")
	require.NoError(t, err)
	defer src.Close()
	path := filepath.Join(t.TempDir(), "paid.dump")
	file, err := os.OpenFile(path, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, copyErr := io.Copy(file, src)
	closeErr := file.Close()
	require.NoError(t, copyErr)
	require.NoError(t, closeErr)
	return path
}

func restorePaidDatabase(t *testing.T, s *stand, dump string) (*sql.DB, *sql.DB) {
	t.Helper()
	// v0.45.0 Run only starts and inspects; it does not wait. The source
	// container survives because binaries build before first use, but this
	// DR target runs bootstrap over the local socket right away and can hit
	// the temporary-init postmaster. Wait for the double readiness log and
	// the listening port first.
	target, err := testpostgres.Run(t.Context(), pgImage, testpostgres.WithDatabase(pgDatabase),
		testpostgres.WithUsername(pgOwnerUser), testpostgres.WithPassword(pgOwnerPass),
		testpostgres.BasicWaitStrategies())
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		require.NoError(t, target.Terminate(ctx))
	})
	require.NotEqual(t, s.pg.GetContainerID(), target.GetContainerID())
	const uri = "postgresql:///yabanin?user=yabanin"
	// Cluster roles are provisioned separately from the database archive.
	require.NoError(t, target.CopyFileToContainer(t.Context(), filepath.Join(repoRoot(t), "deploy/quickstart/bootstrap-app-role.sql"), "/tmp/bootstrap.sql", 0600))
	paidRestoreCommand(t, target, "psql", "-X", "-v", "ON_ERROR_STOP=1", uri, "-f", "/tmp/bootstrap.sql")
	require.NoError(t, target.CopyFileToContainer(t.Context(), dump, "/tmp/paid.dump", 0600))
	require.NoError(t, target.CopyFileToContainer(t.Context(), filepath.Join(repoRoot(t), "scripts/dr/restore.sh"), "/tmp/restore.sh", 0700))
	paidRestoreCommand(t, target, "bash", "/tmp/restore.sh", uri, "/tmp/paid.dump")
	// The operator command must refuse to overwrite a populated target.
	code, output, err := target.Exec(t.Context(), []string{"bash", "/tmp/restore.sh", uri, "/tmp/paid.dump"})
	require.NoError(t, err)
	msg, err := io.ReadAll(output)
	require.NoError(t, err)
	require.Equal(t, 1, code)
	require.Contains(t, string(msg), "refusing to restore")
	dsn, err := target.ConnectionString(t.Context(), "sslmode=disable")
	require.NoError(t, err)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	appURI, err := url.Parse(dsn)
	require.NoError(t, err)
	appURI.User = url.UserPassword(pgAppUser, pgAppPass)
	app, err := sql.Open("pgx", appURI.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = app.Close() })
	return db, app
}

func requireRestoreRegionScope(t *testing.T, app *sql.DB, rid string) {
	t.Helper()
	tx, err := app.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	defer tx.Rollback()
	var role string
	require.NoError(t, tx.QueryRowContext(t.Context(), "SELECT current_user").Scan(&role))
	require.Equal(t, pgAppUser, role)
	for _, scope := range []struct {
		region string
		want   int
	}{{"test", 2}, {"different-test-region", 0}} {
		_, err = tx.ExecContext(t.Context(), "SELECT set_config('app.region',$1,true)", scope.region)
		require.NoError(t, err)
		var count int
		require.NoError(t, tx.QueryRowContext(t.Context(), "SELECT count(*) FROM request_logs WHERE request_id=$1", rid).Scan(&count))
		require.Equal(t, scope.want, count, "restored app reads in region %s", scope.region)
	}
}
