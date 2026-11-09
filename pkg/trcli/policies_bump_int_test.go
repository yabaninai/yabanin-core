package trcli

// the REAL Redis (disposable testcontainers stand, repo convention — no
// miniredis). Proves the OP-0b contract end to end: `reconcile --apply`
// leaves `policystore:ver:<orgID>` as a fresh decimal UnixNano (the gateway
// probe then reloads the compiled pipelines without a restart), a dry-run
// with a pending diff leaves the key untouched, and a converging apply
// CHANGES the value (the gateway probe compares versions, not existence).
// Skips in -short mode and without Docker.

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// TestPoliciesReconcile_BumpVersionKey_Redis_Integration.
func TestPoliciesReconcile_BumpVersionKey_Redis_Integration(t *testing.T) {
	store, slug := newReconcileIntStore(t)
	rdb := testdb.Redis(t)
	ctx := context.Background()
	orgID := orgIDBySlug(t, store, slug)
	key := adminstore.PolicyVersionKeyPrefix + orgID
	dir := t.TempDir()

	bumper := adminstore.PolicyVersionBumper(
		adminstore.NewPolicyVersionCache(rdb, slog.New(slog.DiscardHandler)))

	// reconcile runs the core with the given mutations and fails on errors.
	reconcile := func(t *testing.T, mutate func(*policiesReconcileOptions)) string {
		t.Helper()
		opts := reconcileOpts(dir, func(o *policiesReconcileOptions) {
			o.Org = slug
			if mutate != nil {
				mutate(o)
			}
		})
		var sb strings.Builder
		if err := runPoliciesReconcile(ctx, store, opts, &sb); err != nil {
			t.Fatalf("reconcile: %v\n%s", err, sb.String())
		}
		return sb.String()
	}
	readVersion := func(t *testing.T) int64 {
		t.Helper()
		raw, err := rdb.Get(ctx, key).Result()
		if err != nil {
			t.Fatalf("read %s after apply: %v", key, err)
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			t.Fatalf("the contract value is a decimal int64, got %q: %v", raw, err)
		}
		return v
	}

	writeIntDecl(t, dir, slug, declPIIGuard)

	// Dry-run with a pending diff: nothing written, key absent.
	out := reconcile(t, nil)
	if _, err := rdb.Get(ctx, key).Result(); err == nil {
		t.Fatalf("dry-run must not create %s:\n%s", key, out)
	}

	// Apply: the key exists with a fresh UnixNano and the contract TTL.
	fresh := time.Now().Add(-time.Minute).UnixNano()
	out = reconcile(t, func(o *policiesReconcileOptions) { o.Apply = true; o.VersionBumper = bumper })
	if !strings.Contains(out, "bumped") {
		t.Fatalf("apply must confirm the cache bump:\n%s", out)
	}
	v1 := readVersion(t)
	if v1 <= fresh {
		t.Fatalf("bump value must be a fresh UnixNano, got %d", v1)
	}
	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil {
		t.Fatalf("ttl: %v", err)
	}
	if ttl <= 6*24*time.Hour {
		t.Fatalf("the bump must carry the ~7d contract TTL, got %v", ttl)
	}

	// In-sync re-apply: no mutations → the value stays as-is.
	reconcile(t, func(o *policiesReconcileOptions) { o.Apply = true; o.VersionBumper = bumper })
	if v2 := readVersion(t); v2 != v1 {
		t.Fatalf("an in-sync apply must not invalidate the gateway cache: %d → %d", v1, v2)
	}

	// Drift (a UI edit past git) → the next converging apply must CHANGE
	// the value: the gateway probe compares versions, not existence.
	polList, err := store.ListPolicies(ctx, orgID)
	if err != nil || len(polList) != 1 {
		t.Fatalf("list policies: %v (%d)", err, len(polList))
	}
	if _, err := store.CreatePolicyVersion(ctx, orgID, polList[0].ID, declPIIGuardV2, "", "admin@ui"); err != nil {
		t.Fatalf("seed ui edit: %v", err)
	}
	writeIntDecl(t, dir, slug, declPIIGuardV2)
	reconcile(t, func(o *policiesReconcileOptions) { o.Apply = true; o.VersionBumper = bumper })
	if v3 := readVersion(t); v3 <= v1 {
		t.Fatalf("a converging apply must change the version key: %d → %d", v1, v3)
	}
}
