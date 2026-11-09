//go:build integration

package migrate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func disposableServerCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "migration-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// This server accepts both TLS and plaintext. The DDL event trigger observes
// the actual migration session, so a secure preliminary Ping cannot mask a
// plaintext second connection (the original regression).
func TestMigrationSessionTLSProvenanceAndPublicSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dsn, owner, container := spinBaselineStand(t, ctx)
	cert, key := disposableServerCertificate(t)
	require.NoError(t, container.CopyToContainer(ctx, cert, "/tmp/migration.crt", 0644))
	require.NoError(t, container.CopyToContainer(ctx, key, "/tmp/migration.key", 0600))
	code, _, err := container.Exec(ctx, []string{"sh", "-c", "chown postgres:postgres /tmp/migration.key"})
	require.NoError(t, err)
	require.Zero(t, code)
	for _, command := range []string{"ALTER SYSTEM SET ssl_cert_file = '/tmp/migration.crt'", "ALTER SYSTEM SET ssl_key_file = '/tmp/migration.key'", "ALTER SYSTEM SET ssl = on", "SELECT pg_reload_conf()"} {
		_, err := owner.Exec(ctx, command)
		require.NoError(t, err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(ca, cert, 0600))
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	// The disposable certificate deliberately has IP SANs only.
	u.Host = net.JoinHostPort("127.0.0.1", u.Port())
	q := u.Query()
	q.Set("sslmode", "verify-full")
	q.Set("sslrootcert", ca)
	q.Set("pool_max_conns", "1")
	q.Set("application_name", "migration-tls-proof")
	q.Set("options", "-c search_path=alternate -c role=migration_restricted")
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	_, err = owner.Exec(ctx, `CREATE SCHEMA alternate;
 CREATE ROLE migration_restricted;
 CREATE SCHEMA migration_evidence;
 CREATE TABLE migration_evidence.events (ssl boolean, region text, app text, login_role boolean, schema_name text);
 CREATE FUNCTION migration_evidence.observe() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN
 INSERT INTO migration_evidence.events SELECT ssl, current_setting('app.region', true), current_setting('application_name'), current_user = session_user, current_schema() FROM pg_stat_ssl WHERE pid = pg_backend_pid();
 END $$;
 CREATE EVENT TRIGGER migration_transport_evidence ON ddl_command_end EXECUTE FUNCTION migration_evidence.observe();`)
	require.NoError(t, err)
	// Prove the witness can detect plaintext, rather than testing only Ping.
	_, err = owner.Exec(ctx, "CREATE TABLE migration_evidence.plaintext_probe (id int)")
	require.NoError(t, err)
	var plaintext int
	require.NoError(t, owner.QueryRow(ctx, "SELECT COUNT(*) FROM migration_evidence.events WHERE NOT ssl").Scan(&plaintext))
	require.Positive(t, plaintext)
	_, err = owner.Exec(ctx, "DROP TABLE migration_evidence.plaintext_probe; TRUNCATE migration_evidence.events")
	require.NoError(t, err)
	// Retry the server reload on this goroutine with a finite context. The
	// probe cannot outlive the test or race fixture cleanup on timeout.
	probeContext, stopProbe := context.WithTimeout(ctx, 5*time.Second)
	defer stopProbe()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var probeErr error
	for {
		probe, err := Connect(probeContext, u.String(), "eu")
		require.NoError(t, err)
		probeErr = probe.Ping(probeContext)
		probe.Close()
		if probeErr == nil || probeContext.Err() != nil {
			break
		}
		select {
		case <-ticker.C:
		case <-probeContext.Done():
		}
	}
	require.NoError(t, probeErr, "TLS server reload/connect")
	result, err := Run(ctx, u.String(), "eu")
	require.NoError(t, err)
	require.EqualValues(t, 27, result.Version)
	_, err = Run(ctx, u.String(), "eu")
	require.NoError(t, err, "maxconns=1 no-change must release before metadata")
	_, err = Down(ctx, u.String(), "eu", 28)
	require.NoError(t, err, "maxconns=1 no-op must query pinned connection")
	_, err = Down(ctx, u.String(), "eu", 26)
	require.NoError(t, err)
	// Extension installation temporarily appends pg_temp to search_path; the
	// effective creation schema must still be public for every DDL event.
	var count, invalid int
	require.NoError(t, owner.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE ssl IS DISTINCT FROM true OR region IS DISTINCT FROM 'eu' OR app IS DISTINCT FROM 'migration-tls-proof' OR login_role IS DISTINCT FROM true OR schema_name IS DISTINCT FROM 'public') FROM migration_evidence.events`).Scan(&count, &invalid))
	require.Positive(t, count)
	if invalid != 0 {
		var states string
		require.NoError(t, owner.QueryRow(ctx, "SELECT COALESCE(json_agg(s)::text, '[]') FROM (SELECT ssl, region, app, login_role, schema_name, COUNT(*) FROM migration_evidence.events GROUP BY ssl, region, app, login_role, schema_name) s").Scan(&states))
		t.Logf("observed migration DDL session states: %s", states)
	}
	require.Zero(t, invalid, "every migration DDL must retain TLS and controlled session state")
	var alternate bool
	require.NoError(t, owner.QueryRow(ctx, "SELECT to_regclass('alternate.schema_migrations') IS NOT NULL").Scan(&alternate))
	require.False(t, alternate)
	var extensionSchema string
	require.NoError(t, owner.QueryRow(ctx, "SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='vector'").Scan(&extensionSchema))
	require.Equal(t, "public", extensionSchema)
	// Host verification and CA failures must fail before touching the ledger.
	badHost := *u
	badHost.Host = net.JoinHostPort("localhost", u.Port())
	_, err = Run(ctx, badHost.String(), "eu")
	require.ErrorContains(t, err, "certificate")
	wrongCA, _ := disposableServerCertificate(t)
	wrongPath := filepath.Join(t.TempDir(), "wrong-ca.pem")
	require.NoError(t, os.WriteFile(wrongPath, wrongCA, 0600))
	wrong := u.Query()
	wrong.Set("sslrootcert", wrongPath)
	badCA := *u
	badCA.RawQuery = strings.ReplaceAll(wrong.Encode(), "+", "%20")
	_, err = Run(ctx, badCA.String(), "eu")
	require.ErrorContains(t, err, "certificate")
	// Full down also releases the single acquisition before reading empty metadata.
	result, err = Down(ctx, u.String(), "eu", 0)
	require.NoError(t, err)
	require.Zero(t, result.Version)
}

func TestMigrationRequiredTLSRefusesPlaintext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dsn, owner, _ := spinBaselineStand(t, ctx)
	_, err := Run(ctx, strings.Replace(dsn, "sslmode=disable", "sslmode=require", 1), "eu")
	require.Error(t, err)
	var exists bool
	require.NoError(t, owner.QueryRow(ctx, "SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&exists))
	require.False(t, exists)
}

func tinyMigrationSource(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "0001_probe.up.sql"), []byte("CREATE TABLE public.session_probe (id int);"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "0001_probe.down.sql"), []byte("DROP TABLE public.session_probe;"), 0600))
	return "file://" + dir
}

func requirePoolReleased(t *testing.T, parent context.Context, pool *pgxpool.Pool) {
	t.Helper()
	require.Eventually(t, func() bool { return pool.Stat().AcquiredConns() == 0 }, time.Second, time.Millisecond)
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	require.NoError(t, pool.Ping(ctx), "failed session must not strand or poison pool acquisition")
}

func TestMigrationSessionFailureAndCancellationCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn, owner, _ := spinBaselineStand(t, ctx)
	pool, err := Connect(ctx, dsn+"&pool_max_conns=1", "eu")
	require.NoError(t, err)
	defer pool.Close()
	source := tinyMigrationSource(t)
	// A source failure occurs after driver acquisition and ledger construction.
	_, err = openMigrationSession(ctx, pool, "unknown-source://invalid")
	require.Error(t, err)
	requirePoolReleased(t, ctx, pool)
	lockID, err := database.GenerateAdvisoryLockId("/yabanin", "public", "schema_migrations")
	require.NoError(t, err)
	locker, err := owner.Acquire(ctx)
	require.NoError(t, err)
	defer locker.Release()
	lock := func() { _, err := locker.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); require.NoError(t, err) }
	unlock := func() { _, err := locker.Exec(ctx, "SELECT pg_advisory_unlock($1)", lockID); require.NoError(t, err) }
	t.Run("constructor cancellation", func(t *testing.T) {
		lock()
		defer unlock()
		deadline, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		defer stop()
		started := time.Now()
		_, err := openMigrationSession(deadline, pool, source)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Less(t, time.Since(started), 3*time.Second)
		requirePoolReleased(t, ctx, pool)
	})
	for _, timeout := range []bool{false, true} {
		name := "operation cancellation"
		if timeout {
			name = "lock timeout"
		}
		t.Run(name, func(t *testing.T) {
			operation, stop := context.WithCancel(ctx)
			defer stop()
			session, err := openMigrationSession(operation, pool, source)
			require.NoError(t, err)
			lock()
			defer unlock()
			if timeout {
				session.m.LockTimeout = 50 * time.Millisecond
			} else {
				time.AfterFunc(50*time.Millisecond, stop)
			}
			started := time.Now()
			err = session.m.Up()
			if timeout {
				require.ErrorIs(t, err, migrate.ErrLockTimeout)
			}
			err = session.close(err)
			if !timeout {
				require.ErrorIs(t, err, context.Canceled)
			}
			require.Error(t, err)
			require.Less(t, time.Since(started), 3*time.Second)
			requirePoolReleased(t, ctx, pool)
		})
	}
	t.Run("SQL cancellation", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "0001_probe.up.sql"), []byte("SELECT pg_sleep(10); CREATE TABLE public.never_created (id int);"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "0001_probe.down.sql"), []byte("DROP TABLE public.never_created;"), 0600))
		operation, stop := context.WithCancel(ctx)
		defer stop()
		session, err := openMigrationSession(operation, pool, "file://"+dir)
		require.NoError(t, err)
		time.AfterFunc(100*time.Millisecond, stop)
		started := time.Now()
		err = session.close(session.m.Up())
		require.ErrorIs(t, err, context.Canceled)
		require.Less(t, time.Since(started), 3*time.Second)
		requirePoolReleased(t, ctx, pool)
		var exists bool
		require.NoError(t, owner.QueryRow(ctx, "SELECT to_regclass('public.never_created') IS NOT NULL").Scan(&exists))
		require.False(t, exists)
	})
	t.Run("cancel versus release", func(t *testing.T) {
		for range 20 {
			operation, stop := context.WithCancel(ctx)
			session, err := openMigrationSession(operation, pool, source)
			require.NoError(t, err)
			done := make(chan struct{})
			go func() { stop(); close(done) }()
			err = session.close(nil)
			require.True(t, err == nil || errors.Is(err, context.Canceled))
			<-done
			requirePoolReleased(t, ctx, pool)
		}
	})
}
