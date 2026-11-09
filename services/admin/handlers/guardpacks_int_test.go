package handlers_test

// Real-Postgres integration for the guard-pack lifecycle API (testdb
// posture): the durable CAS (pkg/policystore.GuardPolicyCAS, migration 0013)
// behind the real PackLifecycle, driven end-to-end through SetupRouter.
//
// Locked scenarios:
//   - activate via the API ⇒ the SAME lifecycle enforces the new detectors
//     on the next evaluation — no restart (N02-P02 required result);
//   - a second store client (the second-replica posture) sees the winner's
//     activation through the durable row and loses its own stale CAS with
//     exactly-one-winner semantics;
//   - rollback through the API restores the prior enforcement through the
//     identical durable CAS.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	cli "github.com/reireirei/yabanin/pkg/gateway"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/services/admin/handlers"
	"github.com/stretchr/testify/require"
)

func TestGuardPacks_DurableCASIntegration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, `DELETE FROM guard_pack_state WHERE id = 1`)
		if err != nil {
			t.Errorf("cleanup guard_pack_state: %v", err)
		}
	})

	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "alpha", "1", gpDetect)

	// Replica A: the admin surface's lifecycle, bound to the durable CAS.
	casA := policystore.NewGuardPolicyCAS(pool)
	lifecycleA := guardhooks.NewPackLifecycle("core", guardhooks.ModeDeny, casA)
	h := handlers.New(&stubStore{}, gpSecret, "localhost", nil)
	h.SetGuardPackHandlers(handlers.NewGuardPackHandlers(packRoot, lifecycleA, casA, nil))
	routerA := h.SetupRouter()
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)

	// Activate through the HTTP API.
	w := guardPackRequest(t, routerA, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"alpha","version":"1"}`)
	require.Equal(t, http.StatusOK, w.Code, "activate via API: %s", w.Body.String())
	require.Contains(t, w.Body.String(), `"active_version":"alpha@1"`)

	// WITHOUT RESTART: the same lifecycle now enforces the pack detector.
	_, _, err := lifecycleA.ActiveHook().Apply("GPBLOCK_SECRET_TOKEN")
	require.ErrorIs(t, err, guardhooks.ErrDenied,
		"the API-activated pack must enforce on the next evaluation without a restart")

	// Replica B: an independent store client sees the activation via the
	// durable row, and its own stale CAS loses (exactly one winner).
	casB := policystore.NewGuardPolicyCAS(pool)
	state, err := casB.ActiveGuardPackState(ctx)
	require.NoError(t, err)
	require.Equal(t, "alpha@1", state.ActiveVersion, "the second replica must observe the activation via the store")
	require.Equal(t, "core", state.PreviousVersion)
	require.ErrorIs(t, casB.CompareAndSwap(ctx, "core", "beta@1"), policystore.ErrGuardPackConflict,
		"a replica acting on a stale local version must lose the durable CAS")

	// Rollback through the API restores the prior version via the same CAS.
	w = guardPackRequest(t, routerA, http.MethodPost, gpRollbackPath, rootCookie, "")
	require.Equal(t, http.StatusOK, w.Code, "rollback via API: %s", w.Body.String())
	require.Contains(t, w.Body.String(), `"active_version":"core"`)

	// Enforcement is back to the built-in chain on the same lifecycle.
	_, _, err = lifecycleA.ActiveHook().Apply("GPBLOCK_SECRET_TOKEN")
	require.NoError(t, err, "rollback must restore the prior (built-in) enforcement")

	// The durable row records the inverse transition.
	state, err = casA.ActiveGuardPackState(ctx)
	require.NoError(t, err)
	require.Equal(t, "core", state.ActiveVersion)
	require.Equal(t, "alpha@1", state.PreviousVersion)

	// Unknown pack stays a fail-closed 404 with the real store wired.
	w = guardPackRequest(t, routerA, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"missing","version":"1"}`)
	require.Equal(t, http.StatusNotFound, w.Code)
}

// packSourcesForTest materialises the env-source list the gateway startup
// wiring would build for the given pack IDs.
func packSourcesForTest(t *testing.T, root string, ids ...string) []guardhooks.PackSource {
	t.Helper()
	var out []guardhooks.PackSource
	for _, id := range ids {
		manifest, err := os.ReadFile(filepath.Join(root, id, "manifest.json")) // #nosec G304 -- both components are test-controlled fixture paths, never user input.
		require.NoError(t, err)
		out = append(out, guardhooks.PackSource{Root: filepath.Join(root, id), Manifest: manifest})
	}
	return out
}

// TestGuardPacks_GatewayReplicaAdoptsAPIActivation drives the production
// wiring end-to-end on real Postgres: replica A is the
// admin HTTP surface built exactly like services/run wires it (hydrated
// lifecycle + durable CAS via cli.HydrateGuardPackLifecycle behind
// SetupRouter); replicas B are gateway startups built through the shared
// cli.ReconcileGuardPackLifecycle constructor. The durable guard_pack_state
// row is the only coordination point between them.
func TestGuardPacks_GatewayReplicaAdoptsAPIActivation(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, `DELETE FROM guard_pack_state WHERE id = 1`)
		if err != nil {
			t.Errorf("cleanup guard_pack_state: %v", err)
		}
	})

	packRoot := t.TempDir()
	writeGuardPackFixture(t, packRoot, "golden", "1", "GOLDEN_E2E_[A-Z]+")
	writeGuardPackFixture(t, packRoot, "alpha", "2", "ALPHA_E2E_[A-Z]+")
	logger := slog.New(slog.DiscardHandler)

	gatewayStartup := func(packID string) *guardhooks.PackLifecycle {
		lifecycle, err := cli.ReconcileGuardPackLifecycle(ctx, pool, logger, guardhooks.ModeDeny, packRoot, packSourcesForTest(t, packRoot, packID), nil)
		require.NoError(t, err)
		require.NotNil(t, lifecycle, "a loadable env pack must never degrade to built-in hooks in this scenario")
		return lifecycle
	}
	denied := func(lifecycle *guardhooks.PackLifecycle, needle string) bool {
		_, _, err := lifecycle.ActiveHook().Apply(needle)
		return errors.Is(err, guardhooks.ErrDenied)
	}

	// Gateway replica B1 boots with env pack golden: no durable record → the
	// row is bootstrapped (core → golden@1) and golden is enforced.
	b1 := gatewayStartup("golden")
	require.True(t, denied(b1, "GOLDEN_E2E_X"), "B1 must enforce its env pack after the bootstrap")

	// Replica A: the admin server (hydrated lifecycle, durable CAS, real
	// router) — hydrated AFTER the bootstrap, the production ordering (the
	// gateway startup precedes operator API use, so the rebase sees the live
	// row).
	dwA, err := cli.HydrateGuardPackLifecycle(ctx, pool, logger, guardhooks.ModeDeny, packRoot, nil)
	require.NoError(t, err)
	h := handlers.New(&stubStore{}, gpSecret, "localhost", nil)
	h.SetGuardPackHandlers(handlers.NewGuardPackHandlers(packRoot, dwA.Lifecycle, dwA.Policy, nil))
	routerA := h.SetupRouter()
	rootCookie := makeSessionCookie(t, "root@x.test", true, gpSecret)

	// Replica A activates alpha@2 through the HTTP API.
	w := guardPackRequest(t, routerA, http.MethodPost, gpActivatePath, rootCookie, `{"pack_id":"alpha","version":"2"}`)
	require.Equal(t, http.StatusOK, w.Code, "activate via API: %s", w.Body.String())
	require.Contains(t, w.Body.String(), `"active_version":"alpha@2"`)

	// Replica B2 restarts with the ALIGNED env pack: it adopts A's API
	// activation through the durable CAS — alpha enforced, golden gone.
	b2 := gatewayStartup("alpha")
	require.True(t, denied(b2, "ALPHA_E2E_X"), "replica B must adopt the API-activated pack via the durable CAS")
	require.False(t, denied(b2, "GOLDEN_E2E_X"), "replica B must not keep enforcing the superseded version")

	// Rollback through the HTTP API restores golden@1.
	w = guardPackRequest(t, routerA, http.MethodPost, gpRollbackPath, rootCookie, "")
	require.Equal(t, http.StatusOK, w.Code, "rollback via API: %s", w.Body.String())
	require.Contains(t, w.Body.String(), `"active_version":"golden@1"`)

	// Replica B3 (env still golden) adopts the rollback: golden enforced,
	// alpha gone — no replica-local state involved.
	b3 := gatewayStartup("golden")
	require.True(t, denied(b3, "GOLDEN_E2E_X"), "replica B must adopt the durable rollback")
	require.False(t, denied(b3, "ALPHA_E2E_X"), "the rolled-back pack must not survive on a restarted replica")
}
