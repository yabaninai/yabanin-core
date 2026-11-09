package cli

// N02-P08 T04/T08 behavioral pins:
//
//   - T08 interruption: a durable CAS that won while the activating process
//     died mid-materialization converges on the next admin hydration /
//     gateway restart WITHOUT a second CAS write (no double-activation side
//     effects); an interrupted watcher probe (cancelled context) keeps the
//     last known-good hook enforcing, counts the failure, and converges when
//     the interruption clears.
//   - T04 false-positive feedback: repeated findings surface on the
//     audit/log surface (and metrics), and NEVER mutate policy state — no
//     durable CAS write, no re-stage, no auto activation, in shadow and in
//     enforce mode.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/policystore"
)

// TestGuardPackActivationInterruptedMidMaterializationConverges pins the
// interrupted-activation contract: the durable CAS is the single activation
// point, so a process that dies after the CAS (before exposing the hook)
// leaves exactly one durable transition behind, and every surviving process
// converges by ADOPTING the row — never by re-running the CAS.
func TestGuardPackActivationInterruptedMidMaterializationConverges(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "INT_GOLDEN_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "INT_ALPHA_[A-Z]+")

	// The activation's CAS won (row = alpha@2) but the activating process
	// died before exposing the hook anywhere.
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"}}

	t.Run("admin hydration adopts without a second CAS", func(t *testing.T) {
		lifecycle, err := hydrateGuardPackLifecycle(ctx, store, testLogger(), guardhooks.ModeDeny, root, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := lifecycle.ActiveHook().Apply("INT_ALPHA_VALUE"); !isGuardDenied(err) {
			t.Fatalf("hydration must converge to the interrupted activation's detectors: %v", err)
		}
		if calls := store.casCalls(); len(calls) != 0 {
			t.Fatalf("hydration must adopt the won CAS, never re-activate: %v", calls)
		}
		// The operator's next transition CASes exactly what the row expects.
		if err := lifecycle.Rollback(ctx); err != nil {
			t.Fatalf("rollback after converged hydration: %v", err)
		}
		if calls := store.casCalls(); len(calls) != 1 || calls[0] != "alpha@2->golden@1" {
			t.Fatalf("post-convergence rollback CAS calls = %v, want [alpha@2->golden@1]", calls)
		}
		if _, _, err := lifecycle.ActiveHook().Apply("INT_GOLDEN_VALUE"); !isGuardDenied(err) {
			t.Fatalf("rollback must restore the real previous detectors: %v", err)
		}
	})

	t.Run("gateway restart re-asserts env once then adopts idempotently", func(t *testing.T) {
		// Row is back on golden@1 (the rollback above); a gateway restart with
		// env packs = alpha re-asserts the env configuration through exactly
		// one CAS, and a twin restart of the same env adopts with zero more.
		if calls := store.casCalls(); len(calls) != 1 {
			t.Fatalf("precondition: %v", calls)
		}
		first, err := reconcileForTest(t, store, root, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if calls := store.casCalls(); len(calls) != 2 || calls[1] != "golden@1->alpha@2" {
			t.Fatalf("env re-assertion CAS calls = %v, want [..., golden@1->alpha@2]", calls)
		}
		if _, _, err := first.ActiveHook().Apply("INT_ALPHA_VALUE"); !isGuardDenied(err) {
			t.Fatalf("re-asserted env pack not enforced: %v", err)
		}
		twin, err := reconcileForTest(t, store, root, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if calls := store.casCalls(); len(calls) != 2 {
			t.Fatalf("identical twin restart must adopt without a CAS, calls = %v", calls)
		}
		if _, _, err := twin.ActiveHook().Apply("INT_ALPHA_VALUE"); !isGuardDenied(err) {
			t.Fatalf("twin adopt lost enforcement: %v", err)
		}
	})
}

// TestGuardPackWatcherProbeInterruptedKeepsLastKnownGood pins C3/C4 for the
// interrupted-probe case: a probe whose store read fails with a cancelled
// context keeps the last known-good hook enforcing, increments the watch
// failure counter, never writes the durable row, and converges on the first
// healthy probe after the interruption clears.
func TestGuardPackWatcherProbeInterruptedKeepsLastKnownGood(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "INT_PROBE_GOLDEN_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "INT_PROBE_ALPHA_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "golden@1", PreviousVersion: "core"}}
	lc, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{gatewayCore: gatewayCore{log: testLogger()}}
	w := startTestWatcher(t, ctx, store, root, lc.ActiveHook())
	gw.guardWatch = w
	awaitGuardAdoption(t, gw, w, "INT_PROBE_GOLDEN_VALUE", "INT_PROBE_ALPHA_VALUE", "golden@1", 2*time.Second)

	failuresBefore := testutil.ToFloat64(metrics.GuardPackWatchFailuresTotal)

	// The row moves while every probe is interrupted (cancelled context —
	// e.g. a per-probe deadline or shutdown race): no adoption, LKG holds.
	store.mu.Lock()
	store.readErr = context.Canceled
	store.state = policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"}
	store.mu.Unlock()
	time.Sleep(30 * time.Millisecond) // several interrupted probes
	if delta := testutil.ToFloat64(metrics.GuardPackWatchFailuresTotal) - failuresBefore; delta < 1 {
		t.Fatalf("interrupted probes must surface in the watch failure counter, delta = %v", delta)
	}
	if applied := w.appliedVersion(); applied != "golden@1" {
		t.Fatalf("interrupted probes must keep the last known-good version, applied %q", applied)
	}
	if _, err := gw.applyEgressGuards([]byte("INT_PROBE_GOLDEN_VALUE")); !isGuardDenied(err) {
		t.Fatalf("interrupted probes must not drop the LKG enforcement: %v", err)
	}
	if _, err := gw.applyEgressGuards([]byte("INT_PROBE_ALPHA_VALUE")); isGuardDenied(err) {
		t.Fatal("the un-adopted version must not enforce from an interrupted probe")
	}

	// The interruption clears: the next healthy probe converges to the row.
	store.mu.Lock()
	store.readErr = nil
	store.mu.Unlock()
	awaitGuardAdoption(t, gw, w, "INT_PROBE_ALPHA_VALUE", "INT_PROBE_GOLDEN_VALUE", "alpha@2", 2*time.Second)
	if calls := store.casCalls(); len(calls) != 0 {
		t.Fatalf("runtime adoption must never write the durable row (no double activation), got %v", calls)
	}
}

// TestGuardPackFindingsNeverMutatePolicyState pins the T04 false-positive
// feedback boundary: findings reach the audit/log surface (plus metrics and
// the request outcome) and nothing else. No finding, however frequent, may
// stage, activate, roll back, or CAS policy state — policy changes are
// operator actions only.
func TestGuardPackFindingsNeverMutatePolicyState(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "fp", "1", "FP_FEEDBACK_[A-Z]+")
	store := &scriptedGuardStore{}
	lc, err := reconcileForTest(t, store, root, "fp") // the ONE legitimate CAS: core->fp@1
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	gw := &gateway{
		gatewayCore:    gatewayCore{log: slog.New(slog.NewTextHandler(&logs, nil))},
		guardLifecycle: lc,
		guardHooks:     lc.ActiveHook(),
	}
	body := []byte("false positive probe FP_FEEDBACK_VALUE")

	// Shadow posture: every finding audits and forwards; policy state frozen.
	gw.policyRuntime = &PolicyRuntime{mode: PolicyModeShadow}
	for i := 0; i < 25; i++ {
		out, err := gw.applyEgressGuards(body)
		if err != nil || string(out) != string(body) {
			t.Fatalf("shadow finding must forward unchanged: %q, %v", out, err)
		}
	}
	if !strings.Contains(logs.String(), "guard detection (shadow)") {
		t.Fatalf("findings must reach the audit log surface: %q", logs.String())
	}

	// Enforce posture: the deny surfaces to the caller — and STILL no policy
	// mutation, no staged candidate, no activation side effect.
	gw.policyRuntime = nil
	if _, err := gw.applyEgressGuards(body); !isGuardDenied(err) {
		t.Fatalf("enforce mode must deny the finding: %v", err)
	}
	if calls := store.casCalls(); len(calls) != 1 || calls[0] != "core->fp@1" {
		t.Fatalf("findings must never write the durable CAS, calls = %v", calls)
	}
	if staged := lc.StagedVersion(); staged != "" {
		t.Fatalf("findings must never stage a candidate, staged %q", staged)
	}
	if state, err := store.ActiveGuardPackState(context.Background()); err != nil || state.ActiveVersion != "fp@1" || state.PreviousVersion != "core" {
		t.Fatalf("durable state moved on findings: %+v, %v", state, err)
	}
	if _, _, err := lc.ActiveHook().Apply("FP_FEEDBACK_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("the operator-activated chain must be the only enforcement change: %v", err)
	}
}
