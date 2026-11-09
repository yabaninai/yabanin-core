package handlers

import (
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// QG2-B3 (owner decision 2026-09-13: Docker required for tests): the shared
// dev-Postgres DSN and the PID-named schema isolation are replaced by the
// package-wide disposable, fully migrated stand from pkg/testdb. Tests
// serialize on the mutex because they share the stand and recreate tables.
var creditsIntegrationMu sync.Mutex

func setupTestDBForCredits(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// testdb.Postgres skips under -short before the lock is taken; the
	// cleanup releases the lock even when the test exits via Skip/FailNow.
	pool := testdb.Postgres(t)
	creditsIntegrationMu.Lock()
	t.Cleanup(creditsIntegrationMu.Unlock)
	return pool
}

// releaseCreditsIntegration is kept for existing call sites; the lock is
// released by the t.Cleanup registered in setupTestDBForCredits.
func releaseCreditsIntegration(_ *pgxpool.Pool) {}
