package testdb

// A05 (audit §A05): destructive credit-table suites used to CREATE and DROP
// product tables (credit_transactions/org_credits) in the SHARED disposable
// stand's public schema; any later suite reusing that stand in the same test
// binary then failed with SQLSTATE 42P01 (undefined_table) — the audited
// pairing was a credit teardown followed by the N06-P06 joint reporting
// scenario. The ownership-root fix is a primitive, not a sleep/retry/skip:
// a suite that owns destructive DDL gets a FIXTURE-OWNED Postgres schema on
// the same disposable stand, with every pooled connection's search_path
// pinned to that schema ONLY. Unqualified DDL/DML can then never reach the
// shared public schema: CREATE lands in the fixture, DROP hits only the
// fixture, and teardown (DROP SCHEMA ... CASCADE) restores the stand by
// construction. Suites that must observe the product-like migrated schema
// (e.g. the reporting scenario) keep using Postgres/PostgresRegion
// unchanged.

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// fixtureLabelSanitizer strips every character Postgres identifiers may not
// carry unquoted, after lowercasing. The result is embedded between fixed
// prefixes/suffixes and always quoted with pgx.Identifier anyway, so this is
// defense in depth against hostile-ish labels, not the only guard.
var fixtureLabelSanitizer = regexp.MustCompile(`[^a-z0-9_]+`)

const (
	// fixtureLabelMaxLen keeps the whole schema name well under Postgres's
	// 63-byte NAMEDATALEN so names are never silently truncated (truncation
	// could collide two fixtures into one schema).
	fixtureLabelMaxLen = 24
	// fixtureSchemaPrefix namespaces every fixture schema so the
	// guaranteed-teardown guarantee is checkable (regression scans
	// pg_namespace for residue).
	fixtureSchemaPrefix = "fx_"
)

// fixtureSchemaLabel sanitizes a suite label into an identifier-safe chunk:
// lowercase, [a-z0-9_] only, bounded length, never empty.
func fixtureSchemaLabel(label string) string {
	sanitized := fixtureLabelSanitizer.ReplaceAllString(strings.ToLower(label), "_")
	if len(sanitized) > fixtureLabelMaxLen {
		sanitized = sanitized[:fixtureLabelMaxLen]
	}
	if sanitized == "" {
		sanitized = "fixture"
	}
	return sanitized
}

// fixtureSchemaName builds the unique fixture schema identifier from a suite
// label and a randomness suffix. Pure so it is unit-testable; the Docker
// path passes randomHex(8).
func fixtureSchemaName(label, suffix string) string {
	return fixtureSchemaPrefix + fixtureSchemaLabel(label) + "_" + suffix
}

// randomHex returns n crypto-random bytes as hex (2n chars). crypto/rand
// never fails on supported platforms; the time-based fallback keeps fixture
// naming total even where it would.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		return fmt.Sprintf("%0*x", 2*n, time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// PostgresOwnedSchema returns a pool bound to the SAME disposable, fully
// migrated Postgres stand as Postgres, but isolated in a fixture-owned
// schema: the schema is created fresh (unique per call), every pooled
// connection's search_path is pinned to it — and to nothing else — and
// tb.Cleanup drops the whole schema (CASCADE) after closing the pool.
//
// Ownership contract (A05):
//
//   - CREATE/DROP/INSERT/UPDATE with unqualified names resolve ONLY inside
//     the fixture schema; a missing table is a loud 42P01 inside the
//     fixture, never a silent fall-through into the shared public schema
//     (that is why public is deliberately NOT on the search_path).
//   - Destructive DDL in the owning suite therefore cannot destroy the
//     shared stand's product-like schema for later suites.
//   - Teardown is guaranteed restore: DROP SCHEMA ... CASCADE removes every
//     object the fixture created even if the suite failed mid-way. A drop
//     failure on a LIVE stand fails the test (residue would leak across
//     suites); if the shared stand itself died first, the fixture died with
//     its container and there is nothing left to restore (FIX-12 semantics).
//
// Skips under -short like every disposable stand. Concurrency-safe: unique
// schema per call, no shared mutable state beyond the stand's own locks.
func PostgresOwnedSchema(tb testing.TB, label string) *pgxpool.Pool {
	tb.Helper()
	shared, uri, err := ensurePostgres(tb)
	require.NoError(tb, err)

	schema := fixtureSchemaName(label, randomHex(8))
	quoted := pgx.Identifier{schema}.Sanitize()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	_, err = shared.Exec(ctx, "CREATE SCHEMA "+quoted)
	cancel()
	require.NoError(tb, err, "create fixture-owned schema %s", schema)

	// pgxpool.ParseConfig (not pgx.ParseConfig + manual wrap) so the config
	// carries the flag pgxpool.NewWithConfig requires in pgx v5.10 — the
	// same pattern PostgresRegion/PostgresApp use for their pools.
	pc, err := pgxpool.ParseConfig(uri)
	if err != nil {
		dropFixtureSchema(tb, shared, quoted, schema)
		require.NoError(tb, err, "parse fixture pool config for schema %s", schema)
	}
	// Startup-parameter search_path: applies to every connection of this
	// pool from the handshake on, with no per-connection SET and no window
	// in which a borrowed connection could run against the public schema.
	// Only the fixture schema is on the path (pg_catalog and the temp
	// schema stay implicit per Postgres rules).
	pc.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		dropFixtureSchema(tb, shared, quoted, schema)
		require.NoError(tb, err, "open fixture-owned pool for schema %s", schema)
	}

	tb.Cleanup(func() {
		pool.Close()
		dropFixtureSchema(tb, shared, quoted, schema)
	})
	return pool
}

// dropFixtureSchema is the guaranteed-restore half of PostgresOwnedSchema:
// best-effort DROP SCHEMA ... CASCADE with a bounded deadline, upgraded to a
// test failure only when the shared stand is still alive (real residue) and
// downgraded to a log when the stand itself died first (the fixture schema
// died with its container; FIX-12 owns stand liveness).
func dropFixtureSchema(tb testing.TB, shared *pgxpool.Pool, quoted, schema string) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := shared.Exec(ctx, "DROP SCHEMA IF EXISTS "+quoted+" CASCADE")
	if err == nil {
		return
	}
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if pingErr := shared.Ping(pingCtx); pingErr != nil {
		tb.Logf("testdb: fixture schema %s teardown skipped — shared stand is down, fixture died with its container (drop: %v, ping: %v)",
			schema, err, pingErr)
		return
	}
	tb.Errorf("testdb: fixture schema %s teardown failed, shared stand left with residue: %v", schema, err)
}
