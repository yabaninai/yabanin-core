package cli

// Dockerless tests for runtime guard-pack adoption (FIX-03, audit CA-02):
// the per-request hook snapshot (no torn state, same-process transitions
// visible) and the durable-version watcher (adopt / last-known-good /
// converge) driven by the scripted coordination surface. The real-Postgres
// live-replica acceptance lives in guardpack_live_int_test.go.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
)

// guardHookGateway builds a gateway the way the wiring does for watcher-less
// construction (the audit scenario shape).
func guardHookGateway(t *testing.T, lc *guardhooks.PackLifecycle, log *slog.Logger) *gateway {
	t.Helper()
	return &gateway{gatewayCore: gatewayCore{log: log}, guardLifecycle: lc, guardHooks: lc.ActiveHook()}
}

// setGuardStoreState moves the scripted durable row (the store mutex guards
// CAS/read races in the watcher probes).
func setGuardStoreState(s *scriptedGuardStore, state policystore.GuardPackState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// awaitGuardAdoption polls the replica's request-path guard until the wanted
// rule flip is observed (denied needle, passed other) AND the watcher's
// applied version reached wantApplied, or fails the test at the deadline
// (the convergence contract bound).
func awaitGuardAdoption(t *testing.T, gw *gateway, w *guardPackWatcher, deniedBody, passedBody, wantApplied string, deadline time.Duration) {
	t.Helper()
	limit := time.Now().Add(deadline)
	for time.Now().Before(limit) {
		_, errDenied := gw.applyEgressGuards([]byte(deniedBody))
		_, errPassed := gw.applyEgressGuards([]byte(passedBody))
		if isGuardDenied(errDenied) && !isGuardDenied(errPassed) && w.appliedVersion() == wantApplied {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("replica did not adopt %q within %v (denied %q err, passed %q, applied %q)",
		wantApplied, deadline, deniedBody, passedBody, w.appliedVersion())
}

// startTestWatcher runs a watcher with a tiny interval against ctx (cancelled
// by the test's own defer).
func startTestWatcher(t *testing.T, ctx context.Context, store GuardPackPolicyStore, root string, initial *guardhooks.Hook) *guardPackWatcher {
	t.Helper()
	var logs bytes.Buffer
	w := newGuardPackWatcher(store, slog.New(slog.NewTextHandler(&logs, nil)), guardhooks.ModeDeny, root, initial, nil)
	w.interval = 2 * time.Millisecond
	go w.Run(ctx)
	return w
}

// TestAuditGatewaySeesLifecycleActivation reproduces audit CA-02 exactly: the
// gateway captured the startup hook, so after a lifecycle activation the
// gateway forwarded newly forbidden payloads. With per-request resolution the
// same-process Activate (and the rollback) must be enforced on the next
// request — no re-capture, no restart.
func TestAuditGatewaySeesLifecycleActivation(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "old", "1", "AUDIT_OLD_[A-Z]+")
	writeVersionedPack(t, root, "next", "2", "AUDIT_NEXT_[A-Z]+")
	store := &scriptedGuardStore{}
	p, err := reconcileForTest(t, store, root, "old")
	if err != nil {
		t.Fatal(err)
	}
	gw := guardHookGateway(t, p, testLogger())
	if _, err = p.StageSources(testPackSources(t, root, "next")); err != nil {
		t.Fatal(err)
	}
	if err = p.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = p.ActiveHook().Apply("AUDIT_NEXT_VALUE"); !isGuardDenied(err) {
		t.Fatal("fixture activation did not succeed")
	}
	if _, err = gw.applyEgressGuards([]byte("AUDIT_NEXT_VALUE")); !isGuardDenied(err) {
		t.Fatalf("lifecycle activated next pack, gateway forwarded newly forbidden payload: %v", err)
	}
	// The inverse transition is equally visible: a rollback restores the
	// previous enforcement on the next request.
	if err = p.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = gw.applyEgressGuards([]byte("AUDIT_NEXT_VALUE")); isGuardDenied(err) {
		t.Fatalf("rollback not enforced on the request path: %v", err)
	}
	if _, err = gw.applyEgressGuards([]byte("AUDIT_OLD_VALUE")); !isGuardDenied(err) {
		t.Fatalf("rollback must restore the previous detector: %v", err)
	}
}

// TestMCPParamGuardSeesLifecycleActivation verifies the mcpParamGuard path
// resolves the same live hook: an MCP tool-call param denied after the
// activation without any re-capture.
func TestMCPParamGuardSeesLifecycleActivation(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "mcp", "1", "MCP_AUDIT_[A-Z]+")
	store := &scriptedGuardStore{}
	lc, err := reconcileForTest(t, store, root, "mcp")
	if err != nil {
		t.Fatal(err)
	}
	gw := guardHookGateway(t, lc, testLogger())
	g := &mcpParamGuard{gw: gw}

	writeVersionedPack(t, root, "mcpnext", "2", "MCP_NEXT_[A-Z]+")
	if _, err := lc.StageSources(testPackSources(t, root, "mcpnext")); err != nil {
		t.Fatal(err)
	}
	if err := lc.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, deny, _ := g.Scan(context.Background(), []byte("MCP_NEXT_VALUE"))
	if deny == "" {
		t.Fatal("mcpParamGuard kept the startup hook after the activation")
	}
}

// TestGuardPackWatcherAdoptsDurableVersionChanges drives the C2/C4 contract
// on the scripted store: activation golden@1 → alpha@2 and the rollback back
// are enforced by the live gateway within the contract bound, the applied
// version tracks the row, and adoption never writes the durable row.
func TestGuardPackWatcherAdoptsDurableVersionChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "WATCH_GOLDEN_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "WATCH_ALPHA_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "core"}}
	lc, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	gw.guardWatch = startTestWatcher(t, ctx, store, root, lc.ActiveHook())

	// The first probe adopts the row's current version even though it matches
	// the startup hook (self-healing baseline), then the API-shaped flip.
	awaitGuardAdoption(t, gw, gw.guardWatch, "WATCH_GOLDEN_VALUE", "WATCH_ALPHA_VALUE", "golden@1", 2*time.Second)

	// Admin API activation: the row moves; the replica flips WITHOUT a
	// restart and without touching its env packs.
	setGuardStoreState(store, policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"})
	awaitGuardAdoption(t, gw, gw.guardWatch, "WATCH_ALPHA_VALUE", "WATCH_GOLDEN_VALUE", "alpha@2", 2*time.Second)

	// Rollback: the row moves back; the replica follows.
	setGuardStoreState(store, policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "alpha@2"})
	awaitGuardAdoption(t, gw, gw.guardWatch, "WATCH_GOLDEN_VALUE", "WATCH_ALPHA_VALUE", "golden@1", 2*time.Second)

	// Adoption is read-only: the replica never CASes the durable row.
	if calls := store.casCalls(); len(calls) != 0 {
		t.Fatalf("runtime adoption must not write the durable row, got CAS calls %v", calls)
	}
}

// TestGuardPackWatcherAdoptsDurableCore pins the rollback-to-built-ins
// adoption: a replica enforcing a pack flips to the built-in chain when the
// durable row returns to core.
func TestGuardPackWatcherAdoptsDurableCore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "CORE_BACK_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "core"}}
	lc, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	gw.guardWatch = startTestWatcher(t, ctx, store, root, lc.ActiveHook())
	awaitGuardAdoption(t, gw, gw.guardWatch, "CORE_BACK_VALUE", "NOT_A_PATTERN_VALUE", "golden@1", 2*time.Second)

	// The durable row returns to core: the replica must enforce the built-in
	// chain — the pack pattern passes again and applied tracks "core".
	setGuardStoreState(store, policystore.GuardPackState{ActiveVersion: "core", PreviousVersion: "golden@1"})
	limit := time.Now().Add(2 * time.Second)
	for time.Now().Before(limit) {
		_, errPack := gw.applyEgressGuards([]byte("CORE_BACK_VALUE"))
		if !isGuardDenied(errPack) && gw.guardWatch.appliedVersion() == "core" {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if applied := gw.guardWatch.appliedVersion(); applied != "core" {
		t.Fatalf("durable core rollback not adopted within the bound, applied %q", applied)
	}
	if _, err := gw.applyEgressGuards([]byte("CORE_BACK_VALUE")); isGuardDenied(err) {
		t.Fatalf("the rolled-back pack must not enforce after core adoption: %v", err)
	}
}

// TestGuardPackWatcherStoreDownKeepsLastKnownGood pins C3/C4: while the store
// is unreadable the replica keeps enforcing the last known-good version,
// surfaces the failure, and converges on the first successful probe after
// recovery — a lost notification cannot strand the replica.
func TestGuardPackWatcherStoreDownKeepsLastKnownGood(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "LKG_GOLDEN_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "LKG_ALPHA_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "core"}}
	lc, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	w := newGuardPackWatcher(store, testLogger(), guardhooks.ModeDeny, root, lc.ActiveHook(), nil)
	w.interval = 2 * time.Millisecond
	go w.Run(ctx)
	gw.guardWatch = w

	awaitGuardAdoption(t, gw, w, "LKG_GOLDEN_VALUE", "LKG_ALPHA_VALUE", "golden@1", 2*time.Second)

	// Store down + the row moving underneath: the probe fails, the replica
	// keeps enforcing golden (LKG).
	store.mu.Lock()
	store.readErr = errors.New("store unavailable")
	store.state = policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"}
	store.mu.Unlock()
	time.Sleep(20 * time.Millisecond) // several probes must fail
	if applied := w.appliedVersion(); applied != "golden@1" {
		t.Fatalf("failed probes must keep the last known-good version, applied %q", applied)
	}
	if _, err := gw.applyEgressGuards([]byte("LKG_GOLDEN_VALUE")); !isGuardDenied(err) {
		t.Fatalf("store outage must not drop the last known-good enforcement: %v", err)
	}
	if _, err := gw.applyEgressGuards([]byte("LKG_ALPHA_VALUE")); isGuardDenied(err) {
		t.Fatal("the unavailable version must not be enforced from a failed probe")
	}

	// Recovery: the first successful probe converges to the missed version.
	store.mu.Lock()
	store.readErr = nil
	store.mu.Unlock()
	awaitGuardAdoption(t, gw, w, "LKG_ALPHA_VALUE", "LKG_GOLDEN_VALUE", "alpha@2", 2*time.Second)
	if applied := w.appliedVersion(); applied != "alpha@2" {
		t.Fatalf("replica did not converge after store recovery, applied %q", applied)
	}
}

// TestGuardPackWatcherUnreadablePackKeepsLastKnownGood pins the pack-side
// failure posture: a durable activation whose pack is not loadable on the
// replica fails the materialization, keeps the previous chain enforcing, and
// adopts as soon as the pack becomes readable.
func TestGuardPackWatcherUnreadablePackKeepsLastKnownGood(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "PACK_GOLDEN_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "core"}}
	lc, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	gw.guardWatch = startTestWatcher(t, ctx, store, root, lc.ActiveHook())
	awaitGuardAdoption(t, gw, gw.guardWatch, "PACK_GOLDEN_VALUE", "PACK_ALPHA_VALUE", "golden@1", 2*time.Second)

	// The admin activates ghost@9; the replica cannot resolve it on disk.
	setGuardStoreState(store, policystore.GuardPackState{ActiveVersion: "ghost@9", PreviousVersion: "golden@1"})
	time.Sleep(20 * time.Millisecond)
	if applied := gw.guardWatch.appliedVersion(); applied != "golden@1" {
		t.Fatalf("unloadable pack must not be adopted, applied %q", applied)
	}
	if _, err := gw.applyEgressGuards([]byte("PACK_GOLDEN_VALUE")); !isGuardDenied(err) {
		t.Fatalf("unloadable activation must keep the last known-good enforcing: %v", err)
	}

	// The pack appears on disk (sync tooling / volume attach): converge.
	writeVersionedPack(t, root, "ghost", "9", "PACK_GHOST_[A-Z]+")
	awaitGuardAdoption(t, gw, gw.guardWatch, "PACK_GHOST_VALUE", "PACK_GOLDEN_VALUE", "ghost@9", 2*time.Second)
}

// TestGuardPackWatcherConcurrentRequestsSeeWholeVersions proves the snapshot
// invariant under a live adoption race: each request resolves the hook ONCE
// via guardHook (the exact per-request resolution applyEgressGuards uses),
// and one resolved hook can never exhibit two versions' behaviors at once —
// a torn merge (both detector sets) would deny both bodies, a missing hook
// neither. Deny mode makes the enforced detector set directly observable.
func TestGuardPackWatcherConcurrentRequestsSeeWholeVersions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "TORN_GOLDEN_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "TORN_ALPHA_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "core"}}
	initial, err := guardhooks.LoadPackHook(guardhooks.ModeDeny, testPackSources(t, root, "golden"))
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	w := newGuardPackWatcher(store, testLogger(), guardhooks.ModeDeny, root, initial, nil)
	w.interval = time.Millisecond
	go w.Run(ctx)
	gw.guardWatch = w

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// One request = one hook resolution; both probes run against
				// that single resolved value, so any mixture is a real tear.
				h := gw.guardHook()
				if h == nil {
					t.Error("request resolved a nil hook")
					return
				}
				_, _, errGolden := h.Apply("TORN_GOLDEN_VALUE")
				_, _, errAlpha := h.Apply("TORN_ALPHA_VALUE")
				switch {
				case isGuardDenied(errGolden) && !isGuardDenied(errAlpha):
					// golden@1 enforced — valid.
				case isGuardDenied(errAlpha) && !isGuardDenied(errGolden):
					// alpha@2 enforced — valid.
				default:
					t.Errorf("torn guard state: golden err=%v alpha err=%v", errGolden, errAlpha)
					return
				}
				// The full request entry stays healthy under the swap race.
				if _, err := gw.applyEgressGuards([]byte("TORN_GOLDEN_VALUE TORN_ALPHA_VALUE")); err != nil && !isGuardDenied(err) {
					t.Errorf("request-path failure under adoption race: %v", err)
					return
				}
			}
		}()
	}
	setGuardStoreState(store, policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if out, err := gw.applyEgressGuards([]byte("TORN_ALPHA_VALUE")); isGuardDenied(err) {
			_ = out
			if w.appliedVersion() == "alpha@2" {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if applied := w.appliedVersion(); applied != "alpha@2" {
		t.Fatalf("adoption under concurrent requests = %q, want alpha@2", applied)
	}
}

// TestGuardPackWatcherWiredOnlyWithoutPool pins the wiring gate half that
// needs no external service: a no-pool deployment never starts the runtime
// watcher (bit-for-bit legacy posture). The wired-with-durable-store half is
// proven against real Postgres in guardpack_live_int_test.go — the startup
// reconciliation refuses an unreachable store, so a lazy pool cannot stand in.
func TestGuardPackWatcherWiredOnlyWithoutPool(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "WIRE_GOLDEN_[A-Z]+")
	t.Setenv("YABANIN_GUARD_PACK_DIR", root)
	t.Setenv("YABANIN_GUARD_ACTIVE_PACKS", "golden")
	t.Setenv("YABANIN_GUARD_PACK_MODE", "")

	w := &gatewayWiring{cfg: config.Gateway{GatewayCompliance: config.GatewayCompliance{GuardMode: "deny"}}, l: testLogger()}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	if err := loadGuardHooks(context.Background(), w, gw); err != nil {
		t.Fatal(err)
	}
	if gw.guardWatch != nil {
		t.Fatal("no-pool deployment must not start the runtime watcher")
	}
	if _, err := gw.applyEgressGuards([]byte("WIRE_GOLDEN_VALUE")); !isGuardDenied(err) {
		t.Fatalf("watcher-less replica must enforce through the lifecycle: %v", err)
	}
	if h := gw.guardHook(); h == nil || h != gw.guardLifecycle.ActiveHook() {
		t.Fatal("the request path must resolve the lifecycle live when no watcher is wired")
	}
}
