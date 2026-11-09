package trcli

// gateway's policy version key (policystore:ver:<orgID>, the OP-0b → OP-8
// contract) for every org it converged — so a running gateway reloads its
// compiled pipelines immediately instead of waiting out its probe TTL.
// Covered here over a recording bumper: apply bumps per affected org with a
// fresh UnixNano value, in-sync orgs and dry-runs never bump, a failed apply
// never bumps, and a failed/unreachable bump is a WARNING (the gateway's TTL
// fallback bounds staleness), never a reconcile failure. The Redis half —
// exact key/value/TTL over the real store — is policies_bump_int_test.go.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// recordingBumper records SetPolicyVersion calls (orgID → values, in order).
type recordingBumper struct {
	calls    []bumpCall
	failWith error
	onCall   func(context.Context, string, int64) error
}

type bumpCall struct {
	orgID   string
	version int64
}

func (b *recordingBumper) SetPolicyVersion(ctx context.Context, orgID string, version int64) error {
	b.calls = append(b.calls, bumpCall{orgID: orgID, version: version})
	if b.onCall != nil {
		return b.onCall(ctx, orgID, version)
	}
	if b.failWith != nil {
		return b.failWith
	}
	return nil
}

func (b *recordingBumper) count(orgID string) int {
	n := 0
	for _, c := range b.calls {
		if c.orgID == orgID {
			n++
		}
	}
	return n
}

// TestPoliciesReconcile_BumpVersionKey_OnApply: apply bumps once per
// affected org with a fresh UnixNano; an in-sync re-run does not bump.
func TestPoliciesReconcile_BumpVersionKey_OnApply(t *testing.T) {
	store := newFakePolicyStore("acme", "beta")
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	writeDecl(t, dir, "beta", "pii-guard.yaml", declPIIGuard)

	bumper := &recordingBumper{}
	run := func(mutate func(*policiesReconcileOptions)) string {
		t.Helper()
		opts := reconcileOpts(dir, mutate)
		opts.VersionBumper = bumper
		var sb strings.Builder
		if err := runPoliciesReconcile(context.Background(), store, opts, &sb); err != nil {
			t.Fatalf("runPoliciesReconcile: %v\n%s", err, sb.String())
		}
		return sb.String()
	}

	fresh := time.Now().Add(-time.Minute).UnixNano()
	out := run(func(o *policiesReconcileOptions) { o.Apply = true })

	if len(bumper.calls) != 2 {
		t.Fatalf("apply must bump both converged orgs, got %+v", bumper.calls)
	}
	for _, c := range bumper.calls {
		if c.version <= fresh {
			t.Fatalf("bump value must be a fresh UnixNano, got %d", c.version)
		}
	}
	if bumper.count("org-1") != 1 || bumper.count("org-2") != 1 {
		t.Fatalf("exactly one bump per org expected: %+v", bumper.calls)
	}
	for _, want := range []string{
		adminstore.PolicyVersionKeyPrefix + "org-1",
		adminstore.PolicyVersionKeyPrefix + "org-2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output must confirm the %s bump:\n%s", want, out)
		}
	}

	// Second apply: everything in sync — no mutations, no bumps.
	bumper.calls = nil
	out = run(func(o *policiesReconcileOptions) { o.Apply = true })
	if len(bumper.calls) != 0 {
		t.Fatalf("an in-sync apply must not invalidate the gateway cache: %+v", bumper.calls)
	}
	if strings.Contains(out, "cache:") {
		t.Fatalf("no cache line expected for an in-sync org:\n%s", out)
	}
}

// TestPoliciesReconcile_BumpVersionKey_DryRunAndFailures: dry-runs never
// bump (they write nothing), a failed apply never bumps its org, and a
// failed bump only warns — the run still succeeds.
func TestPoliciesReconcile_BumpVersionKey_DryRunAndFailures(t *testing.T) {
	t.Run("dry-run never bumps even with a pending diff", func(t *testing.T) {
		store := newFakePolicyStore("acme")
		dir := t.TempDir()
		writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
		bumper := &recordingBumper{}
		opts := reconcileOpts(dir, nil) // no Apply
		opts.VersionBumper = bumper
		var sb strings.Builder
		if err := runPoliciesReconcile(context.Background(), store, opts, &sb); err != nil {
			t.Fatalf("dry-run: %v", err)
		}
		if len(bumper.calls) != 0 {
			t.Fatalf("dry-run must not touch the gateway cache: %+v", bumper.calls)
		}
	})

	t.Run("a failed apply never bumps its org", func(t *testing.T) {
		store := newFakePolicyStore("acme")
		dir := t.TempDir()
		// Seed the converged v1, then declare drifted content (declPIIGuardV2's
		// body) → the plan is update+activate and the apply dies in the
		// version append: the org is not converged, so its gateway cache
		// must not be invalidated.
		if _, _, err := store.CreatePolicy(context.Background(), "org-1", "pii-guard", declPIIPolicy, "sha", "seed"); err != nil {
			t.Fatalf("seed policy: %v", err)
		}
		writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuardV2)
		bumper := &recordingBumper{}
		opts := reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true })
		opts.VersionBumper = bumper
		store.failVersionCreate = errors.New("boom")
		var sb strings.Builder
		if err := runPoliciesReconcile(context.Background(), store, opts, &sb); err == nil {
			t.Fatalf("the injected apply failure must fail the run")
		}
		if len(bumper.calls) != 0 {
			t.Fatalf("a failed apply must not bump: %+v", bumper.calls)
		}
	})
	t.Run("a failed bump is a warning, not a reconcile failure", func(t *testing.T) {
		store := newFakePolicyStore("acme")
		dir := t.TempDir()
		writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
		bumper := &recordingBumper{failWith: fmt.Errorf("dial redis: connection refused")}
		opts := reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true })
		opts.VersionBumper = bumper
		var sb strings.Builder
		if err := runPoliciesReconcile(context.Background(), store, opts, &sb); err != nil {
			t.Fatalf("a Redis outage must not fail the reconcile (gateway TTL fallback): %v", err)
		}
		out := sb.String()
		if !strings.Contains(out, "WARNING") || !strings.Contains(out, "TTL fallback") {
			t.Fatalf("the outage must warn with the TTL hint:\n%s", out)
		}
	})
}

func TestPoliciesReconcile_BumpWaitsForParentCancellationAfterApply(t *testing.T) {
	store := newFakePolicyStore("acme")
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	started := make(chan context.Context, 1)
	bumper := &recordingBumper{onCall: func(ctx context.Context, _ string, _ int64) error {
		started <- ctx
		<-ctx.Done()
		return ctx.Err()
	}}
	opts := reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true })
	opts.VersionBumper = bumper
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out strings.Builder
	done := make(chan error, 1)
	go func() { done <- runPoliciesReconcile(ctx, store, opts, &out) }()

	var bumpCtx context.Context
	select {
	case bumpCtx = <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile did not reach the version bump after applying policy changes")
	}
	if len(store.pols) != 1 || len(store.vers) != 1 {
		t.Fatalf("version bump began before successful apply: policies=%d versions=%d", len(store.pols), len(store.vers))
	}
	if _, ok := bumpCtx.Deadline(); !ok {
		t.Fatal("version bump context has no bounded deadline")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("parent cancellation during warning-only bump failed reconcile: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("version bump did not return after parent cancellation")
	}
	if bumper.count("org-1") != 1 {
		t.Fatalf("expected one canceled bump attempt, got %+v", bumper.calls)
	}
	if !strings.Contains(out.String(), "WARNING") || !strings.Contains(out.String(), "TTL fallback") {
		t.Fatalf("canceled bump should be reported as a warning with TTL fallback:\n%s", out.String())
	}
}

func TestPoliciesReconcile_BumpUsesActualFiveSecondDeadline(t *testing.T) {
	store := newFakePolicyStore("acme")
	dir := t.TempDir()
	writeDecl(t, dir, "acme", "pii-guard.yaml", declPIIGuard)
	started := make(chan time.Time, 1)
	bumper := &recordingBumper{onCall: func(ctx context.Context, _ string, _ int64) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("bump context missing deadline")
		}
		started <- deadline
		<-ctx.Done()
		return ctx.Err()
	}}
	opts := reconcileOpts(dir, func(o *policiesReconcileOptions) { o.Apply = true })
	opts.VersionBumper = bumper
	var out strings.Builder
	done := make(chan error, 1)
	begin := time.Now()
	go func() { done <- runPoliciesReconcile(context.Background(), store, opts, &out) }()

	var deadline time.Time
	select {
	case deadline = <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile did not reach the version bump after applying policy changes")
	}
	remaining := time.Until(deadline)
	if remaining < 4*time.Second || remaining > 6*time.Second {
		t.Fatalf("version bump deadline is %v from observation, want the production five-second bound", remaining)
	}
	if len(store.pols) != 1 || len(store.vers) != 1 {
		t.Fatalf("version bump began before successful apply: policies=%d versions=%d", len(store.pols), len(store.vers))
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("deadline expiry during warning-only bump failed reconcile: %v", err)
		}
	case <-time.After(time.Until(deadline) + time.Second):
		t.Fatal("bump did not return by its context deadline")
	}
	if time.Since(begin) < 4*time.Second {
		t.Fatalf("bump returned before the actual five-second timeout: %v", time.Since(begin))
	}
	if bumper.count("org-1") != 1 {
		t.Fatalf("expected one timed-out bump attempt, got %+v", bumper.calls)
	}
	if !strings.Contains(out.String(), "WARNING") || !strings.Contains(out.String(), "TTL fallback") {
		t.Fatalf("deadline failure should be warning-only with TTL fallback:\n%s", out.String())
	}
}

// TestPoliciesRedisAddrDefault: the --redis-addr flag default resolves from
// $YABANIN_REDIS_ADDR (the deployment env contract) and falls back to
// localhost:6379.
func TestPoliciesRedisAddrDefault(t *testing.T) {
	t.Setenv("YABANIN_REDIS_ADDR", "redis.example:6380")
	if got := policiesRedisAddrDefault(); got != "redis.example:6380" {
		t.Fatalf("env override: got %q", got)
	}
	t.Setenv("YABANIN_REDIS_ADDR", "")
	if got := policiesRedisAddrDefault(); got != policiesDefaultRedisAddr {
		t.Fatalf("fallback: got %q, want %q", got, policiesDefaultRedisAddr)
	}
}
