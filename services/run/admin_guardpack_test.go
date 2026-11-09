package run

// Dockerless contract for the admin guard-pack wiring helper
// (admin_guardpack.go): the routes stay unwired (nil → the handlers' 503
// posture) when there is no usable coordination point — no DB pool, or a
// durable record that cannot be read. The positive path (healthy pool →
// hydrated lifecycle over the durable CAS) is covered end-to-end by
// services/admin/handlers TestGuardPacks_GatewayReplicaAdoptsAPIActivation
// on testdb.Postgres.

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/guardhooks"
)

func TestGuardPackHandlersForAdmin_NilPoolStaysUnwired(t *testing.T) {
	if got := guardPackHandlersForAdmin(context.Background(), nil, slog.Default(), guardhooks.ModeDeny, t.TempDir(), config.GuardPackVerifyConfig{}); got != nil {
		t.Fatal("without a DB pool the admin guard-pack surface must stay unwired (503 posture)")
	}
}

func TestGuardPackHandlersForAdmin_UnreadableRecordStaysUnwired(t *testing.T) {
	// A lazily-created pool against a refused port: the durable state read
	// fails, so the helper must return nil (routes answer 503) instead of
	// mounting a surface with doomed CAS preconditions.
	pool, err := pgxpool.New(context.Background(), "postgres://yabanin:yabanin@127.0.0.1:1/yabanin")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if got := guardPackHandlersForAdmin(context.Background(), pool, slog.Default(), guardhooks.ModeDeny, t.TempDir(), config.GuardPackVerifyConfig{}); got != nil {
		t.Fatal("an unreadable durable record must keep the admin guard-pack surface unwired")
	}
}

func TestGuardPackHandlersForAdmin_BrokenVerifierStaysUnwired(t *testing.T) {
	// A configured-but-unreadable verifier key directory is the fail-loud
	// three-state branch: the surface is not mounted half-verified — every
	// signed decode would fail closed behind it, so the routes answer 503
	// with the loud startup log instead.
	pool, err := pgxpool.New(context.Background(), "postgres://yabanin:yabanin@127.0.0.1:1/yabanin")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	broken := config.GuardPackVerifyConfig{KeysDir: filepath.Join(t.TempDir(), "missing-keys")}
	if got := guardPackHandlersForAdmin(context.Background(), pool, slog.Default(), guardhooks.ModeDeny, t.TempDir(), broken); got != nil {
		t.Fatal("a broken verifier configuration must keep the admin guard-pack surface unwired (fail loud)")
	}
}

// guard: the helper is total — never panics on a nil logger and always
// returns nil (not a half-built handler) when the coordination point is
// missing.
func TestGuardPackHandlersForAdmin_NilLoggerSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("helper must be nil-logger safe: %v", r)
		}
	}()
	if got := guardPackHandlersForAdmin(context.Background(), nil, nil, guardhooks.ModeDeny, "", config.GuardPackVerifyConfig{}); got != nil {
		t.Fatal("nil pool must yield nil handlers")
	}
}
