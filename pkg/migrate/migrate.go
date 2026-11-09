// Package migrate is the region-aware migration runner shared by the unified
// binary (in-process dispatch) and the standalone yabanin-migrate tool. It uses
// golang-migrate with embedded migrations and sets the app.region GUC on every
// connection before executing, so RLS policies are applied per-region.
package migrate

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Result is the outcome of a migration run, for logging/reporting.
type Result struct {
	Applied  int // number of migrations now recorded in schema_migrations
	Version  int64
	Duration time.Duration
	Region   string
}

// refuseAuthorityLessURI rejects postgres:// URIs whose authority is empty
// (e.g. "postgres://svc@/tmp/db"): pgx fills the host from a filesystem-probed
// machine-default socket directory while the URI path silently becomes the
// database name — the effective target would differ per machine, so the input
// class is refused before any connection attempt. Keyword DSNs never carry a
// URL scheme, so the scheme check keeps them out of this refusal.
func refuseAuthorityLessURI(uri string) error {
	if u, err := url.Parse(uri); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") && u.Host == "" {
		return fmt.Errorf(
			"URI has no host authority: pgx would silently use a machine-probed default socket directory: use a TCP host:port URI")
	}
	return nil
}

// Connect creates a pgx pool that sets app.region on every new connection.
// It uses pgxpool.ParseConfig (not pgx.ParseConfig + manual struct) so the pool
// config carries the createdByParseConfig guard NewWithConfig requires.
// Authority-less postgres:// URIs are refused before any connection attempt.
func Connect(ctx context.Context, pgURI, region string) (*pgxpool.Pool, error) {
	return connect(ctx, pgURI, region, false)
}

func connect(ctx context.Context, pgURI, region string, tcpOnly bool) (*pgxpool.Pool, error) {
	if err := refuseAuthorityLessURI(pgURI); err != nil {
		return nil, fmt.Errorf("parse pg_uri: %w", err)
	}
	pc, err := pgxpool.ParseConfig(pgURI)
	if err != nil {
		return nil, fmt.Errorf("parse pg_uri: %w", err)
	}
	if tcpOnly {
		if err := requireTCP(pc); err != nil {
			return nil, err
		}
	}
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		// Migration path runs under controlled elevation: pin the session to
		// the login role so a role injected through the DSN (e.g. PG
		// "options=-c role=yabanin_app") can never execute DDL/DML that the
		// RLS-bound application role must not. SET ROLE NONE is the exact
		// inverse of the app pools' SET ROLE (regionrouter.ConfigurePool).
		if _, err := conn.Exec(ctx, "SET ROLE NONE"); err != nil {
			return fmt.Errorf("reset session role for migration: %w", err)
		}
		if _, err := conn.Exec(ctx, "SELECT set_config('app.region', $1, false)", region); err != nil {
			return fmt.Errorf("set app.region GUC: %w", err)
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	return pool, nil
}

// Run applies all embedded migrations using the configured pgx connection.
// Migrations always use the public schema, login role, and supplied region.
func Run(ctx context.Context, pgURI, region string) (Result, error) {
	return runDirection(ctx, pgURI, region, nil)
}

// Down reverts to target (0 = all the way down). A current version at or
// below a positive target is a no-op; it never upgrades to that target.
func Down(ctx context.Context, pgURI, region string, target int) (Result, error) {
	return runDirection(ctx, pgURI, region, &target)
}

func runDirection(ctx context.Context, pgURI, region string, target *int) (Result, error) {
	pool, err := connect(ctx, pgURI, region, true)
	if err != nil {
		return Result{}, err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return Result{}, fmt.Errorf("database ping failed: %w", err)
	}
	tmpDir, err := extractMigrationsToTemp()
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: cleanup migrations temp dir: %v\n", err)
		}
	}()
	session, err := openMigrationSession(ctx, pool, "file://"+tmpDir)
	if err != nil {
		return Result{}, fmt.Errorf("create migrator: %w", err)
	}
	start := time.Now()
	switch {
	case target == nil:
		err = session.m.Up()
	case *target <= 0:
		err = session.m.Down()
	default:
		// Use the pinned connection: querying the pool here deadlocks when its
		// sole connection is held by the migration driver.
		var current int64
		err = session.conn.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM public.schema_migrations").Scan(&current)
		if err == nil && current > int64(*target) {
			err = session.m.Migrate(uint(*target))
		}
	}
	duration := time.Since(start)
	if errors.Is(err, migrate.ErrNoChange) {
		err = nil
	}
	// Release the driver acquisition before metadata reads, also for maxconns=1.
	if err = session.close(err); err != nil {
		return Result{}, fmt.Errorf("migrations failed: %w", err)
	}
	res := Result{Region: region, Duration: duration}
	err = pool.QueryRow(ctx, "SELECT COUNT(*), COALESCE(MAX(version), 0) FROM public.schema_migrations").Scan(&res.Applied, &res.Version)
	if err != nil {
		return Result{}, fmt.Errorf("read migration result: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return res, nil
}

// requireTCP retains the migration command's explicit socket refusal without
// reconstructing the DSN or altering the parsed TLS/fallback configuration.
func requireTCP(config *pgxpool.Config) error {
	hosts := []string{config.ConnConfig.Host}
	for _, fallback := range config.ConnConfig.Fallbacks {
		hosts = append(hosts, fallback.Host)
	}
	for _, host := range hosts {
		if strings.HasPrefix(host, "/") {
			return fmt.Errorf("parse pg_uri: unix-socket directory host %q not supported by migrations: use a TCP host:port URI", host)
		}
	}
	return nil
}

type migrationSession struct {
	ctx       context.Context
	db        *sql.DB
	conn      *sql.Conn
	m         *migrate.Migrate
	transport net.Conn
	stop      func() bool
	stopped   chan struct{}
}

func openMigrationSession(ctx context.Context, pool *pgxpool.Pool, sourceURL string) (*migrationSession, error) {
	if err := requireTCP(pool.Config()); err != nil {
		return nil, err
	}
	s := &migrationSession{ctx: ctx, db: stdlib.OpenDBFromPool(pool)}
	var err error
	s.conn, err = s.db.Conn(ctx)
	if err != nil {
		return nil, s.close(err)
	}
	err = s.conn.Raw(func(raw any) error {
		conn, ok := raw.(*stdlib.Conn)
		if !ok {
			return fmt.Errorf("unexpected migration SQL driver %T", raw)
		}
		s.transport = conn.Conn().PgConn().Conn()
		return nil
	})
	if err != nil {
		return nil, s.close(err)
	}
	// The postgres driver's lock and migration queries use Background. Close
	// only the concurrency-safe transport on cancellation, not pgx.Conn itself.
	// Register before WithConnection: its constructor also takes an advisory lock.
	s.stopped = make(chan struct{})
	s.stop = context.AfterFunc(ctx, func() {
		defer close(s.stopped)
		_ = s.transport.Close()
	})
	if _, err = s.conn.ExecContext(ctx, "SET search_path TO public"); err != nil {
		return nil, s.close(err)
	}
	driver, err := postgres.WithConnection(ctx, s.conn, &postgres.Config{
		// Preserve the previous postgres URL driver's leading-slash lock identity
		// so old and new migration runners serialize on the same advisory lock.
		DatabaseName: "/" + pool.Config().ConnConfig.Database,
		SchemaName:   "public",
	})
	if err != nil {
		return nil, s.close(err)
	}
	s.m, err = migrate.NewWithDatabaseInstance(sourceURL, "postgres", driver)
	if err != nil {
		return nil, s.close(err)
	}
	return s, nil
}

// close must run before pool.Close. On errors a lock query may still be
// running after golang-migrate's lock timeout; sever its transport first so
// sql.Conn.Close cannot wait forever. Stop/join the cancellation callback
// before releasing the acquisition so it cannot kill a subsequently reused
// pool session. Each migrationSession has exactly one owner and one close.
func (s *migrationSession) close(operationErr error) error {
	operationErr = errors.Join(operationErr, s.ctx.Err())
	if operationErr != nil && s.transport != nil {
		_ = s.transport.Close()
	}
	if s.stop != nil && !s.stop() {
		<-s.stopped
	}
	// Cancellation can race the stop call; never report that run as success.
	operationErr = errors.Join(operationErr, s.ctx.Err())
	// A raw transport close does not itself mark pgx.Conn closed. After all
	// in-flight SQL has unblocked, invalidate it under database/sql's lock so
	// pgxpool cannot hand a silently closed socket to the next borrower.
	if operationErr != nil && s.transport != nil {
		_ = s.transport.Close()
		_ = s.conn.Raw(func(raw any) error {
			return raw.(*stdlib.Conn).Conn().Close(context.Background())
		})
	}
	var closeErr error
	if s.m != nil {
		srcErr, dbErr := s.m.Close()
		closeErr = errors.Join(srcErr, dbErr)
	} else if s.conn != nil {
		closeErr = s.conn.Close()
	}
	return errors.Join(operationErr, closeErr, s.db.Close())
}

// extractMigrationsToTemp extracts embedded .sql migrations to a temporary directory.
func extractMigrationsToTemp() (string, error) {
	tmpDir, err := os.MkdirTemp("", "yabanin-migrations-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	err = fs.WalkDir(migrationsFS, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		// path is "migrations/<file>"; place it flat in tmpDir so the golang-migrate
		// file:// source sees a single directory of .sql files.
		data, err := migrationsFS.ReadFile(path)
		if err != nil {
			return err
		}
		// 0600: read only by the migrator in this same process/user.
		return os.WriteFile(filepath.Join(tmpDir, d.Name()), data, 0600)
	})
	if err != nil {
		// Best-effort cleanup; the walk error is what the caller reports.
		if rmErr := os.RemoveAll(tmpDir); rmErr != nil {
			fmt.Fprintf(os.Stderr, "warning: cleanup migrations temp dir: %v\n", rmErr)
		}
		return "", fmt.Errorf("walk migrations: %w", err)
	}
	return tmpDir, nil
}
