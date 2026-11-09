package cli

// Dockerless contract tests for the durable guard-pack reconciliation
// (guardpack_durable.go): scripted coordination surfaces drive the
// bootstrap / idempotent-adopt / env-reassertion / lost-race-adoption
// decisions, the resolver identity contract, and the admin hydration core.
// The real-SQL behavior of the durable CAS is pinned in pkg/policystore and
// the cross-process adoption scenario in services/admin/handlers
// (guardpacks_int_test.go).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
)

// scriptedGuardStore is the in-memory GuardPackPolicyStore with failure and
// race-injection seams.
type scriptedGuardStore struct {
	mu      sync.Mutex
	state   policystore.GuardPackState
	casLog  []string
	casErr  error // injected before the CAS decision (lost-race posture)
	readErr error
}

func (s *scriptedGuardStore) CompareAndSwap(_ context.Context, from, to string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.casLog = append(s.casLog, from+"->"+to)
	if s.casErr != nil {
		return s.casErr
	}
	if s.state.ActiveVersion == "" {
		s.state = policystore.GuardPackState{ActiveVersion: to, PreviousVersion: from}
		return nil
	}
	if s.state.ActiveVersion != from {
		return policystore.ErrGuardPackConflict
	}
	s.state = policystore.GuardPackState{ActiveVersion: to, PreviousVersion: from}
	return nil
}

func (s *scriptedGuardStore) ActiveGuardPackState(context.Context) (policystore.GuardPackState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return policystore.GuardPackState{}, s.readErr
	}
	return s.state, nil
}

func (s *scriptedGuardStore) casCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.casLog...)
}

// writeVersionedPack materialises one valid unsigned local pack (the
// guard_test.go writer pins version "1"; the durable identity contract needs
// arbitrary versions).
func writeVersionedPack(t *testing.T, root, id, version, pattern string) {
	t.Helper()
	packDir := filepath.Join(root, id)
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"detectors": []map[string]string{{
		"rule_id": id + "-r0", "rule_version": "1", "category": "secret", "pattern": pattern,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "detector.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	manifest, err := json.Marshal(guardhooks.PackManifest{
		SchemaVersion: guardhooks.GuardPackManifestVersion,
		PackID:        id,
		PackVersion:   version,
		RuntimeAPI:    guardhooks.RuntimeVersion,
		Files:         []guardhooks.PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testPackSources(t *testing.T, root string, ids ...string) []guardhooks.PackSource {
	t.Helper()
	var out []guardhooks.PackSource
	for _, id := range ids {
		manifest, err := os.ReadFile(filepath.Join(root, id, "manifest.json")) // #nosec G304 -- both components are test-controlled fixture paths, never user input.
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, guardhooks.PackSource{Root: filepath.Join(root, id), Manifest: manifest})
	}
	return out
}

func reconcileForTest(t *testing.T, store GuardPackPolicyStore, root string, ids ...string) (*guardhooks.PackLifecycle, error) {
	t.Helper()
	return reconcileGuardPackLifecycle(context.Background(), store, testLogger(), guardhooks.ModeDeny, root, testPackSources(t, root, ids...), nil)
}

// TestReconcileGuardPackLifecycle_NoDBKeepsLocalFallback pins the no-pool
// posture through the shared core: the local no-op store reads as "no
// durable record", the CAS answers nil, and the env pack activates locally —
// bit-for-bit the pre-durable gateway behavior.
func TestReconcileGuardPackLifecycle_NoDBKeepsLocalFallback(t *testing.T) {
	root := t.TempDir()
	writeStartupGuardPack(t, root, "golden", "GOLDEN_LOCAL_[A-Z]+", 1)
	lifecycle, err := reconcileForTest(t, localGuardPolicyStore{}, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle == nil {
		t.Fatal("no-pool reconciliation must activate locally")
	}
	if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_LOCAL_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("local fallback did not enforce the env pack: %v", err)
	}
}

func TestReconcileGuardPackLifecycle_DurableBootstrap(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "GOLDEN_BOOT_[A-Z]+")
	store := &scriptedGuardStore{}
	lifecycle, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	if got := store.casCalls(); len(got) != 1 || got[0] != "core->golden@1" {
		t.Fatalf("bootstrap CAS calls = %v, want [core->golden@1]", got)
	}
	if store.state.ActiveVersion != "golden@1" || store.state.PreviousVersion != "core" {
		t.Fatalf("durable state after bootstrap = %+v", store.state)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_BOOT_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("bootstrapped pack not enforced: %v", err)
	}
}

// TestReconcileGuardPackLifecycle_IdenticalRestartAdoptsWithoutCAS pins the
// idempotent adopt: a restart (or twin replica) re-staging the durable
// active version must NOT run the CAS — the durable adapter refuses
// from == to, so a naive switch would fail every such startup.
func TestReconcileGuardPackLifecycle_IdenticalRestartAdoptsWithoutCAS(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "GOLDEN_ADOPT_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "core"}}
	lifecycle, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	if calls := store.casCalls(); len(calls) != 0 {
		t.Fatalf("identical restart ran the CAS: %v", calls)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_ADOPT_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("adopted pack not enforced: %v", err)
	}
	// The adopt re-anchored previous from the durable record: a rollback now
	// CASes exactly the transition the durable row expects.
	if err := lifecycle.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback after adopt: %v", err)
	}
	if got := store.casCalls(); len(got) != 1 || got[0] != "golden@1->core" {
		t.Fatalf("rollback CAS calls = %v, want [golden@1->core]", got)
	}
}

// TestReconcileGuardPackLifecycle_EnvReassertsThroughCAS pins the documented
// posture: a gateway restart whose env packs differ from the durable record
// re-asserts the env configuration THROUGH the CAS (env-based startup
// activation keeps working; the transition is recorded durably).
func TestReconcileGuardPackLifecycle_EnvReassertsThroughCAS(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "GOLDEN_RE_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"}}
	lifecycle, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	if got := store.casCalls(); len(got) != 1 || got[0] != "alpha@2->golden@1" {
		t.Fatalf("re-assertion CAS calls = %v, want [alpha@2->golden@1]", got)
	}
	if store.state.ActiveVersion != "golden@1" || store.state.PreviousVersion != "alpha@2" {
		t.Fatalf("durable state after re-assertion = %+v", store.state)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_RE_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("re-asserted pack not enforced: %v", err)
	}
}

// TestReconcileGuardPackLifecycle_LostRaceAdoptsDurableWinner pins the
// two-replica race contract: the loser of the durable CAS reads the winner's
// version and adopts it (its chain enforces the winner's detectors).
func TestReconcileGuardPackLifecycle_LostRaceAdoptsDurableWinner(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "GOLDEN_LOSE_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "ALPHA_WIN_[A-Z]+")
	// The durable row already names the winner (an API activation or a twin
	// replica moved it between our read and our CAS) and every CAS attempt
	// loses (the winner is not our rebased current).
	store := &scriptedGuardStore{
		state:  policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"},
		casErr: policystore.ErrGuardPackConflict,
	}
	lifecycle, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle == nil {
		t.Fatal("a loadable durable winner must be adopted, not dropped")
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_WIN_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("replica did not adopt the durable winner's detectors: %v", err)
	}
}

func TestReconcileGuardPackLifecycle_LostRaceUnloadableWinnerKeepsBuiltinHooks(t *testing.T) {
	root := t.TempDir()
	writeStartupGuardPack(t, root, "golden", "GOLDEN_UNL_[A-Z]+", 1)
	for name, state := range map[string]policystore.GuardPackState{
		"winner missing on disk": {ActiveVersion: "missing@9", PreviousVersion: "core"},
		"winner is built-in":     {ActiveVersion: "core", PreviousVersion: "golden@1"},
	} {
		t.Run(name, func(t *testing.T) {
			store := &scriptedGuardStore{state: state, casErr: policystore.ErrGuardPackConflict}
			lifecycle, err := reconcileForTest(t, store, root, "golden")
			if err != nil {
				t.Fatal(err)
			}
			// The degraded lifecycle stays rebased on the durable truth while
			// its hook chain is the built-in one: the env pack passes.
			if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_UNL_VALUE"); err != nil {
				t.Fatalf("degraded reconcile must serve the built-in hook chain: %v", err)
			}
		})
	}
}

func TestReconcileGuardPackLifecycle_StateReadFailureRefusesStartup(t *testing.T) {
	root := t.TempDir()
	writeStartupGuardPack(t, root, "golden", "GOLDEN_RD_[A-Z]+", 1)
	store := &scriptedGuardStore{readErr: errors.New("store unavailable")}
	if _, err := reconcileForTest(t, store, root, "golden"); err == nil {
		t.Fatal("an unreadable durable record must refuse the startup, not serve uncoordinated")
	}
}

func TestResolveDurableGuardPackSources(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "G_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "A_[A-Z]+")

	if sources, err := resolveDurableGuardPackSources(root, "core", nil); err != nil || sources != nil {
		t.Fatalf("core must resolve to no sources, got %v, %v", sources, err)
	}
	sources, err := resolveDurableGuardPackSources(root, "golden@1", nil)
	if err != nil || len(sources) != 1 {
		t.Fatalf("single identity resolve: %v, %v", sources, err)
	}
	sources, err = resolveDurableGuardPackSources(root, "alpha@2,golden@1", nil)
	if err != nil || len(sources) != 2 {
		t.Fatalf("joined identity resolve: %v, %v", sources, err)
	}
	for name, identity := range map[string]string{
		"empty":            "",
		"no version":       "golden",
		"traversal":        "../escape@1",
		"missing manifest": "ghost@1",
		"version mismatch": "golden@999",
	} {
		if _, err := resolveDurableGuardPackSources(root, identity, nil); err == nil {
			t.Fatalf("%s: identity %q must fail resolution", name, identity)
		}
	}
}

func TestGuardPackPolicyForSelectsCoordinationPoint(t *testing.T) {
	if _, ok := guardPackPolicyFor(nil).(localGuardPolicyStore); !ok {
		t.Fatal("nil pool must select the local no-op store (R009 no-DB posture)")
	}
	// A lazily-created pool (no connection attempted) selects the durable CAS.
	pool, err := pgxpool.New(context.Background(), "postgres://yabanin:yabanin@127.0.0.1:1/yabanin")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, ok := guardPackPolicyFor(pool).(*policystore.GuardPolicyCAS); !ok {
		t.Fatal("a DB pool must select the durable CAS")
	}
}

func TestHydrateGuardPackLifecycleCore(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "GOLDEN_HYD_[A-Z]+")

	t.Run("hydrates the durable active pack for an immediate rollback", func(t *testing.T) {
		store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "core"}}
		lifecycle, err := hydrateGuardPackLifecycle(ctx, store, testLogger(), guardhooks.ModeDeny, root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_HYD_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
			t.Fatalf("hydrated lifecycle does not enforce the durable active pack: %v", err)
		}
		// The hydration payoff: rollback right after a restart CASes the
		// transition the durable row expects.
		if err := lifecycle.Rollback(ctx); err != nil {
			t.Fatalf("rollback right after hydration: %v", err)
		}
		if got := store.casCalls(); len(got) != 1 || got[0] != "golden@1->core" {
			t.Fatalf("post-hydration rollback CAS calls = %v", got)
		}
	})
	t.Run("no durable record keeps the built-in identity", func(t *testing.T) {
		lifecycle, err := hydrateGuardPackLifecycle(ctx, &scriptedGuardStore{}, testLogger(), guardhooks.ModeDeny, root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_HYD_VALUE"); err != nil {
			t.Fatalf("no-record hydration must leave the built-in chain active: %v", err)
		}
		if err := lifecycle.Rollback(ctx); err == nil || err.Error() != "guard pack rollback: no active pack" {
			t.Fatalf("rollback without an active pack must be refused, got %v", err)
		}
	})
	t.Run("unloadable active pack keeps activate working", func(t *testing.T) {
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "missing@9", PreviousVersion: "core"}}
		lifecycle, err := hydrateGuardPackLifecycle(ctx, store, logger, guardhooks.ModeDeny, root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if lifecycle.StagedVersion() != "" {
			t.Fatal("hydration of an unloadable pack must not stage anything")
		}
		if !bytes.Contains(logs.Bytes(), []byte("not usable")) {
			t.Fatalf("hydration failure not warned: %q", logs.String())
		}
	})
	t.Run("unreadable record is an error", func(t *testing.T) {
		if _, err := hydrateGuardPackLifecycle(ctx, &scriptedGuardStore{readErr: errors.New("down")}, testLogger(), guardhooks.ModeDeny, root, nil); err == nil {
			t.Fatal("an unreadable durable record must be reported so the routes stay unwired")
		}
	})
}
