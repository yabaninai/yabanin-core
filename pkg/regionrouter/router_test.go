package regionrouter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// fakeStore is an in-memory orgStore for unit tests.
type fakeStore struct {
	rows     map[string]Assignment
	writable bool
	calls    int
}

func (f *fakeStore) LookupRegion(_ context.Context, orgID string) (string, bool, error) {
	f.calls++
	a, ok := f.rows[orgID]
	if !ok {
		return "", false, errOrgNotFound
	}
	return a.HomeRegion, a.ResidencyPinned, nil
}

func (f *fakeStore) UpsertRegion(_ context.Context, orgID, region string, pinned bool) error {
	if !f.writable {
		return errors.New("read-only")
	}
	f.rows[orgID] = Assignment{HomeRegion: region, ResidencyPinned: pinned}
	return nil
}

// memKV is an in-memory kvStore.
type memKV struct {
	data map[string]string
}

func newMemKV() *memKV { return &memKV{data: map[string]string{}} }

func (m *memKV) Get(_ context.Context, key string) (string, error) {
	v, ok := m.data[key]
	if !ok {
		return "", errCacheMiss
	}
	return v, nil
}
func (m *memKV) Set(_ context.Context, key, value string, _ time.Duration) error {
	m.data[key] = value
	return nil
}
func (m *memKV) Del(_ context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func TestRouter_PinnedOrg_ReturnsHomeRegion(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-1": {HomeRegion: "in", ResidencyPinned: true},
	}}
	r := New(store, newMemKV())
	got := r.Resolve(context.Background(), "org-1")
	if got.HomeRegion != "in" {
		t.Errorf("expected in, got %s", got.HomeRegion)
	}
	if !got.ResidencyPinned {
		t.Error("expected pinned=true")
	}
}

func TestRouter_UnknownOrg_DefaultSG(t *testing.T) {
	r := New(&fakeStore{rows: map[string]Assignment{}}, newMemKV())
	got := r.Resolve(context.Background(), "nope")
	if got.HomeRegion != DefaultRegion {
		t.Errorf("expected default %s, got %s", DefaultRegion, got.HomeRegion)
	}
	if got.ResidencyPinned {
		t.Error("expected pinned=false for unknown org")
	}
}

func TestRouter_EmptyOrgID_DefaultFast(t *testing.T) {
	store := &fakeStore{}
	r := New(store, newMemKV())
	got := r.Resolve(context.Background(), "")
	if got.HomeRegion != DefaultRegion {
		t.Errorf("expected %s, got %s", DefaultRegion, got.HomeRegion)
	}
	if store.calls != 0 {
		t.Errorf("expected zero DB calls for empty org, got %d", store.calls)
	}
}

func TestRouter_CacheHit_FastPath(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-2": {HomeRegion: "eu", ResidencyPinned: false},
	}}
	r := New(store, newMemKV())
	ctx := context.Background()
	_ = r.Resolve(ctx, "org-2") // populate cache
	if store.calls != 1 {
		t.Fatalf("expected 1 DB call on miss, got %d", store.calls)
	}
	_ = r.Resolve(ctx, "org-2") // cache hit
	_ = r.Resolve(ctx, "org-2")
	if store.calls != 1 {
		t.Errorf("expected still 1 DB call (cached), got %d", store.calls)
	}
}

func TestRouter_Invalidate_ClearsCache(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-3": {HomeRegion: "sg", ResidencyPinned: true},
	}}
	r := New(store, newMemKV())
	ctx := context.Background()
	_ = r.Resolve(ctx, "org-3")
	r.Invalidate(ctx, "org-3")
	_ = r.Resolve(ctx, "org-3")
	if store.calls != 2 {
		t.Errorf("expected 2 DB calls after invalidate, got %d", store.calls)
	}
}

func TestRouter_SetAssignment_UpdatesAndInvalidates(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{}, writable: true}
	r := New(store, newMemKV())
	if err := r.SetAssignment(context.Background(), "org-9", "eu", true); err != nil {
		t.Fatalf("SetAssignment: %v", err)
	}
	got := r.Resolve(context.Background(), "org-9")
	if got.HomeRegion != "eu" || !got.ResidencyPinned {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	cases := []Assignment{
		{HomeRegion: "sg", ResidencyPinned: true},
		{HomeRegion: "in", ResidencyPinned: false},
		{HomeRegion: "eu", ResidencyPinned: true},
	}
	def := Assignment{HomeRegion: "sg", ResidencyPinned: false}
	for _, c := range cases {
		got := decode(encode(c.HomeRegion, c.ResidencyPinned), def)
		if got != c {
			t.Errorf("round-trip mismatch: %+v vs %+v", got, c)
		}
	}
}

func TestDecode_Malformed_ReturnsDefault(t *testing.T) {
	def := Assignment{HomeRegion: "sg", ResidencyPinned: false}
	for _, bad := range []string{"", "x", "9"} {
		got := decode(bad, def)
		if got != def {
			t.Errorf("expected default for %q, got %+v", bad, got)
		}
	}
}

// paths: silent cache write-back and invalidation losses).
type errKV struct {
	setErr error
	delErr error
}

func (e *errKV) Get(_ context.Context, _ string) (string, error) {
	return "", errCacheMiss
}
func (e *errKV) Set(_ context.Context, _, _ string, _ time.Duration) error {
	return e.setErr
}
func (e *errKV) Del(_ context.Context, _ string) error { return e.delErr }

func TestRouter_Invalidate_Error_CountsMetric(t *testing.T) {
	kv := &errKV{delErr: errors.New("redis down")}
	r := New(&fakeStore{}, kv)
	ctx := context.Background()

	before := testutil.ToFloat64(metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("del"))
	r.Invalidate(ctx, "org-x")
	after := testutil.ToFloat64(metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("del"))

	if after != before+1 {
		t.Errorf("expected del-failure counter to increment from %v to %v, got %v", before, before+1, after)
	}
}

func TestRouter_Resolve_SetError_CountsMetric(t *testing.T) {
	kv := &errKV{setErr: errors.New("redis down")}
	store := &fakeStore{rows: map[string]Assignment{
		"org-y": {HomeRegion: "eu", ResidencyPinned: true},
	}}
	r := New(store, kv)
	ctx := context.Background()

	before := testutil.ToFloat64(metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("set"))
	got := r.Resolve(ctx, "org-y")
	after := testutil.ToFloat64(metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("set"))

	if got.HomeRegion != "eu" || !got.ResidencyPinned {
		t.Errorf("failed cache write must not change the resolution result, got %+v", got)
	}
	if after != before+1 {
		t.Errorf("expected set-failure counter to increment from %v to %v, got %v", before, before+1, after)
	}
}

func TestRouter_Resolve_NegativeCacheSetError_CountsMetric(t *testing.T) {
	kv := &errKV{setErr: errors.New("redis down")}
	r := New(&fakeStore{rows: map[string]Assignment{}}, kv)
	ctx := context.Background()

	before := testutil.ToFloat64(metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("set"))
	got := r.Resolve(ctx, "unknown-org")
	after := testutil.ToFloat64(metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("set"))

	if got.HomeRegion != DefaultRegion {
		t.Errorf("expected fail-open default for unknown org, got %+v", got)
	}
	if after != before+1 {
		t.Errorf("expected negative-cache set-failure counter to increment from %v to %v, got %v", before, before+1, after)
	}
}

func TestRouter_WithLogger_NilIgnored(t *testing.T) {
	r := New(&fakeStore{}, newMemKV())
	defaultLog := r.log
	r.WithLogger(nil)
	if r.log != defaultLog {
		t.Error("WithLogger(nil) must keep the existing logger")
	}
}
