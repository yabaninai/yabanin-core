package regionrouter

// N09-P01-T09 [compatibility] — old/new configuration walk for
// pkg/regionrouter.
//
// The walk drives the real Router (and its downstream FailoverEvaluator
// consumer) over the cache wire format and the store contract so migration
// and rollback parity is proven by behaviour:
//
//	legacy cache bytes   pre-seeded "0sg"/"1eu" rows (the historical
//	                     encode output — unchanged) served with zero DB reads
//	new write → reader   SetAssignment emits the same wire bytes a
//	                     rolled-back old build reads
//	documented tolerance len>=2 garbage cache values become region names —
//	                     pinned together with the loud downstream surface
//	                     ("no healthy peer for home region zz")
//	unsupported store    read-only store rejects SetAssignment loudly
//
// Existing coverage intentionally not duplicated: decode's len<2 matrix and
// encode/decode round-trips (router_test.go), the failover policy battery
// (failover_policy_test.go), cache write-failure metrics.

import (
	"context"
	"strings"
	"testing"
)

// t09ReadOnlyStore satisfies orgStore only — the read-only replica shape
// (no UpsertRegion method), so SetAssignment must refuse it explicitly.
type t09ReadOnlyStore struct{ calls int }

func (s *t09ReadOnlyStore) LookupRegion(context.Context, string) (string, bool, error) {
	s.calls++
	return "", false, errOrgNotFound
}

// TestN09P1T09_Compat_LegacyCacheBytesServedWithoutStore pins rollback
// compatibility: cache rows written by the historical build decode through
// the current Resolve unchanged, and a cached org never touches the store —
// a rolled-back deployment keeps serving from the same Redis.
func TestN09P1T09_Compat_LegacyCacheBytesServedWithoutStore(t *testing.T) {
	kv := newMemKV()
	// Exact legacy encode output: flag byte + region, nothing else.
	kv.data["org_region:org-a"] = "0sg"
	kv.data["org_region:org-b"] = "1eu"

	// Store rows deliberately disagree with the cache to prove the cache wins.
	store := &fakeStore{rows: map[string]Assignment{
		"org-a": {HomeRegion: "in", ResidencyPinned: false},
	}}
	r := New(store, kv)
	ctx := context.Background()

	if got := r.Resolve(ctx, "org-a"); got != (Assignment{HomeRegion: "sg", ResidencyPinned: false}) {
		t.Fatalf("legacy unpinned row: got %+v, want {sg false}", got)
	}
	if got := r.Resolve(ctx, "org-b"); got != (Assignment{HomeRegion: "eu", ResidencyPinned: true}) {
		t.Fatalf("legacy pinned row: got %+v, want {eu true}", got)
	}
	if store.calls != 0 {
		t.Fatalf("cached orgs hit the store %d times, want 0", store.calls)
	}
}

// TestN09P1T09_Compat_NewWriteRoundTripsToOldReaderShape pins the forward
// direction: an assignment written by the current code lands in the cache as
// the exact legacy byte shape, and a fresh Router with an empty store (the
// rolled-back old build's view) resolves it from those bytes alone.
func TestN09P1T09_Compat_NewWriteRoundTripsToOldReaderShape(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{}, writable: true}
	kv := newMemKV()
	r := New(store, kv)
	ctx := context.Background()

	if err := r.SetAssignment(ctx, "org-c", "in", true); err != nil {
		t.Fatalf("SetAssignment: %v", err)
	}
	if _, ok := kv.data["org_region:org-c"]; ok {
		t.Fatal("SetAssignment must invalidate the cache, not leave a stale row")
	}

	// The next Resolve reads the store and writes the cache back as the
	// exact legacy byte shape — today's writer emits what every historical
	// reader decoded.
	if got := r.Resolve(ctx, "org-c"); got != (Assignment{HomeRegion: "in", ResidencyPinned: true}) {
		t.Fatalf("store-backed resolve: got %+v, want {in true}", got)
	}
	if cached := kv.data["org_region:org-c"]; cached != "1in" {
		t.Fatalf("wire format changed: cache holds %q, want legacy shape \"1in\"", cached)
	}

	// The old reader: same cache bytes, and it adds no further store reads.
	oldReader := New(&fakeStore{rows: map[string]Assignment{}}, kv)
	if got := oldReader.Resolve(ctx, "org-c"); got != (Assignment{HomeRegion: "in", ResidencyPinned: true}) {
		t.Fatalf("old reader over new bytes: got %+v, want {in true}", got)
	}
	if store.calls != 1 { // the single store-backed resolve above
		t.Fatalf("store lookups: got %d, want 1", store.calls)
	}
}

// TestN09P1T09_Compat_TwoCharGarbageRegionNamesStayBounded documents the
// accepted decode tolerance end to end: a len>=2 garbage cache value is not
// rejected — it becomes a region name — and the real downstream consumer
// (FailoverEvaluator) then fails loudly and actionably instead of silently
// misrouting. Pinned so a future strictness change is a conscious decision.
func TestN09P1T09_Compat_TwoCharGarbageRegionNamesStayBounded(t *testing.T) {
	kv := newMemKV()
	kv.data["org_region:org-z"] = "0zz" // flag byte + garbage region name

	r := New(&fakeStore{rows: map[string]Assignment{}}, kv)
	got := r.Resolve(context.Background(), "org-z")
	if got != (Assignment{HomeRegion: "zz", ResidencyPinned: false}) {
		t.Fatalf("garbage cache value: got %+v, want the documented {zz false} tolerance", got)
	}

	// Downstream, the unknown region name never silently serves: with no
	// healthy peer anywhere the evaluator answers with the named-region 503.
	checker := NewHealthChecker([]PeerURL{})
	fe := NewFailoverEvaluator(r, checker, regions3(), "sg", nil)
	err := fe.Decide(context.Background(), "org-z")
	if err == nil {
		t.Fatal("garbage home region must not resolve to a serving decision")
	}
	if !strings.Contains(err.Error(), "no healthy peer for home region zz") {
		t.Fatalf("downstream error must name the unsupported region, got: %v", err)
	}
}

// TestN09P1T09_Compat_ReadOnlyStoreAssignmentRejectedLoudly pins the
// unsupported store shape: a store without the writer surface (the read-only
// replica wiring) must produce the explicit read-only error — never a silent
// success and never a panic — and must not write the cache.
func TestN09P1T09_Compat_ReadOnlyStoreAssignmentRejectedLoudly(t *testing.T) {
	store := &t09ReadOnlyStore{}
	kv := newMemKV()
	r := New(store, kv)

	err := r.SetAssignment(context.Background(), "org-ro", "eu", true)
	if err == nil {
		t.Fatal("read-only store must reject SetAssignment")
	}
	if got := err.Error(); got != "regionrouter: store is read-only" {
		t.Fatalf("read-only error text changed: %q", got)
	}
	if _, ok := kv.data["org_region:org-ro"]; ok {
		t.Fatal("rejected assignment leaked into the cache")
	}
	if store.calls != 0 {
		t.Fatalf("rejected write hit the store %d times, want 0", store.calls)
	}
}
