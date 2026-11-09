package cli

// Live-replica acceptance for runtime guard-pack adoption (FIX-03, audit
// CA-02) on real Postgres (testdb posture, guard_pack_state migration 0013).
//
// Unlike guardpack_durable_int_test.go — which proves adoption by STARTING
// new replicas with aligned env — this test starts the admin surface and TWO
// gateway replicas ONCE and never restarts them and never rewrites their env
// (both replicas boot with env pack "golden" and keep it for the whole test).
// The rule changes are proven through the replicas' real request path
// (applyEgressGuards) while the durable row moves underneath:
//
//  1. activate A→B through the admin-handler activation shape
//     (Stage + Activate over the hydrated lifecycle — the exact body the
//     /api/guard-packs/activate route executes) ⇒ BOTH running replicas
//     flip their enforced regex within the convergence bound;
//  2. an activation whose pack is NOT loadable on the replicas (it only
//     exists in the admin's own pack root — the "sync has not arrived yet"
//     posture) ⇒ replicas keep the last known-good version enforcing while
//     the probes fail;
//  3. the pack arrives on the replicas' root ⇒ they converge without any
//     further API action;
//  4. rollback through the admin route shape ⇒ both replicas flip back.
//
// The store-down failure posture (C3/C4 with an unreadable coordination
// point) is pinned deterministically against the scripted store in
// guardpack_watch_test.go — a real pooled Postgres cannot be taken down
// mid-test without renting the whole stand.

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestGuardPackLiveReplicasAdoptActivation_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM guard_pack_state WHERE id = 1`); err != nil {
			t.Errorf("cleanup guard_pack_state: %v", err)
		}
	})
	logger := slog.New(slog.DiscardHandler)
	cas := policystore.NewGuardPolicyCAS(pool)

	// Two pack roots, one production topology: the admin surface stages
	// activations from ITS operator-configured root; the gateway replicas
	// materialize adoptions from THEIR root. golden@1 and alpha@2 exist in
	// both; beta@3 only on the admin side until step 3 "syncs" it.
	replicasRoot := t.TempDir()
	adminRoot := t.TempDir()
	for _, root := range []string{replicasRoot, adminRoot} {
		writeVersionedPack(t, root, "golden", "1", "LIVE_GOLDEN_[A-Z]+")
		writeVersionedPack(t, root, "alpha", "2", "LIVE_ALPHA_[A-Z]+")
	}
	writeVersionedPack(t, adminRoot, "beta", "3", "LIVE_BETA_[A-Z]+")

	// The replicas' env is fixed for the whole test: pack "golden", never
	// rewritten. Runtime adoption — not env — drives every rule change.
	t.Setenv("YABANIN_GUARD_PACK_DIR", replicasRoot)
	t.Setenv("YABANIN_GUARD_ACTIVE_PACKS", "golden")
	t.Setenv("YABANIN_GUARD_PACK_MODE", "")
	startReplica := func() *gateway {
		t.Helper()
		w := &gatewayWiring{cfg: config.Gateway{GatewayCompliance: config.GatewayCompliance{GuardMode: "deny"}}, l: logger, pool: pool}
		gw := &gateway{gatewayCore: gatewayCore{log: logger}}
		if err := loadGuardHooks(ctx, w, gw); err != nil {
			t.Fatalf("replica startup: %v", err)
		}
		if gw.guardLifecycle == nil || gw.guardWatch == nil {
			t.Fatal("live replica must boot with a lifecycle and the runtime watcher (durable store configured)")
		}
		return gw
	}

	// Start the admin surface and TWO gateway replicas ONCE. Nothing below
	// restarts them or touches their env.
	r1 := startReplica() // bootstraps the durable row core → golden@1
	r2 := startReplica() // twin: idempotent adopt of golden@1
	adminLC, err := hydrateGuardPackLifecycle(ctx, cas, logger, guardhooks.ModeDeny, adminRoot, nil)
	if err != nil {
		t.Fatalf("admin hydration: %v", err)
	}
	awaitGuardAdoption(t, r1, r1.guardWatch, "LIVE_GOLDEN_VALUE", "LIVE_ALPHA_VALUE", "golden@1", 10*time.Second)
	awaitGuardAdoption(t, r2, r2.guardWatch, "LIVE_GOLDEN_VALUE", "LIVE_ALPHA_VALUE", "golden@1", 10*time.Second)

	// activateGuardPack mirrors the /api/guard-packs/activate route body:
	// resolve <packDir>/<id>/manifest.json, Stage (verify + compile), then
	// publish through the durable CAS.
	activateGuardPack := func(t *testing.T, packID, version string) {
		t.Helper()
		manifest, readErr := os.ReadFile(adminRoot + "/" + packID + "/manifest.json") // #nosec G304 -- test-controlled fixture path.
		if readErr != nil {
			t.Fatalf("read admin pack %s: %v", packID, readErr)
		}
		if _, err := adminLC.Stage(adminRoot+"/"+packID, manifest); err != nil {
			t.Fatalf("stage %s@%s: %v", packID, version, err)
		}
		if err := adminLC.Activate(ctx); err != nil {
			t.Fatalf("activate %s@%s: %v", packID, version, err)
		}
	}

	// 1. API activation A→B: both RUNNING replicas must enforce the new
	//    regex without a restart and without an env rewrite.
	activateGuardPack(t, "alpha", "2")
	state, err := cas.ActiveGuardPackState(ctx)
	if err != nil || state.ActiveVersion != "alpha@2" || state.PreviousVersion != "golden@1" {
		t.Fatalf("durable row after activation = %+v, %v", state, err)
	}
	awaitGuardAdoption(t, r1, r1.guardWatch, "LIVE_ALPHA_VALUE", "LIVE_GOLDEN_VALUE", "alpha@2", 10*time.Second)
	awaitGuardAdoption(t, r2, r2.guardWatch, "LIVE_ALPHA_VALUE", "LIVE_GOLDEN_VALUE", "alpha@2", 10*time.Second)

	// 2. An activation the replicas cannot load (beta@3 exists only on the
	//    admin root): probes fail, last known-good keeps enforcing on BOTH
	//    replicas for longer than the full convergence bound.
	activateGuardPack(t, "beta", "3")
	state, err = cas.ActiveGuardPackState(ctx)
	if err != nil || state.ActiveVersion != "beta@3" {
		t.Fatalf("durable row after the unavailable activation = %+v, %v", state, err)
	}
	time.Sleep(6*time.Second + guardPackWatchInterval) // > 2×interval + jitter: at least one failed probe per replica
	for name, r := range map[string]*gateway{"r1": r1, "r2": r2} {
		if applied := r.guardWatch.appliedVersion(); applied != "alpha@2" {
			t.Fatalf("%s adopted an unloadable pack, applied %q", name, applied)
		}
		if _, err := r.applyEgressGuards([]byte("LIVE_ALPHA_VALUE")); !isGuardDenied(err) {
			t.Fatalf("%s dropped the last known-good enforcement: %v", name, err)
		}
		if _, err := r.applyEgressGuards([]byte("LIVE_GOLDEN_VALUE")); isGuardDenied(err) {
			t.Fatalf("%s enforces a version it could not load", name)
		}
	}

	// 3. The pack reaches the replicas' root (sync/volume attach): they
	//    converge on their own — no further API action, no restart.
	writeVersionedPack(t, replicasRoot, "beta", "3", "LIVE_BETA_[A-Z]+")
	awaitGuardAdoption(t, r1, r1.guardWatch, "LIVE_BETA_VALUE", "LIVE_ALPHA_VALUE", "beta@3", 10*time.Second)
	awaitGuardAdoption(t, r2, r2.guardWatch, "LIVE_BETA_VALUE", "LIVE_ALPHA_VALUE", "beta@3", 10*time.Second)

	// 4. Rollback through the admin route shape: both replicas flip back.
	if err := adminLC.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	state, err = cas.ActiveGuardPackState(ctx)
	if err != nil || state.ActiveVersion != "alpha@2" || state.PreviousVersion != "beta@3" {
		t.Fatalf("durable row after rollback = %+v, %v", state, err)
	}
	awaitGuardAdoption(t, r1, r1.guardWatch, "LIVE_ALPHA_VALUE", "LIVE_BETA_VALUE", "alpha@2", 10*time.Second)
	awaitGuardAdoption(t, r2, r2.guardWatch, "LIVE_ALPHA_VALUE", "LIVE_BETA_VALUE", "alpha@2", 10*time.Second)
}
