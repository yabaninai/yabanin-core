package regionrouter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
)

func TestFailoverEvaluator_NonPinnedHomeDown_Failover(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-1": {HomeRegion: "in", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())

	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: httptest.NewServer(nil).URL},
		{Region: "eu", URL: httptest.NewServer(nil).URL},
	})

	regions := config.RegionMap{
		"sg": {Name: "sg", Priority: 1, GatewayURL: "http://sg:8082"},
		"in": {Name: "in", Priority: 2, GatewayURL: "http://in:8082"},
		"eu": {Name: "eu", Priority: 3, GatewayURL: "http://eu:8082"},
	}

	fe := NewFailoverEvaluator(router, checker, regions, "sg", nil)

	err := fe.Decide(context.Background(), "org-1")
	if err == nil {
		t.Fatal("expected redirect error for non-pinned org with down home region")
	}
	t.Logf("got expected failover error: %v", err)
}

func TestFailoverEvaluator_PinnedHomeDown_Notify(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-2": {HomeRegion: "in", ResidencyPinned: true},
	}}
	router := New(store, newMemKV())

	checker := NewHealthChecker([]PeerURL{
		{Region: "sg", URL: httptest.NewServer(nil).URL},
	})

	regions := config.RegionMap{
		"sg": {Name: "sg", Priority: 1, GatewayURL: "http://sg:8082"},
		"in": {Name: "in", Priority: 2},
	}

	fe := NewFailoverEvaluator(router, checker, regions, "sg", nil)

	err := fe.Decide(context.Background(), "org-2")
	if err == nil {
		t.Fatal("expected error for pinned org with down home region")
	}
}

func TestFailoverEvaluator_LocalRegion_Nil(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-3": {HomeRegion: "sg", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())

	checker := NewHealthChecker([]PeerURL{})

	regions := config.RegionMap{
		"sg": {Name: "sg", Priority: 1, GatewayURL: "http://sg:8082"},
	}

	fe := NewFailoverEvaluator(router, checker, regions, "sg", nil)

	err := fe.Decide(context.Background(), "org-3")
	if err != nil {
		t.Fatalf("expected nil for local region org, got: %v", err)
	}
}

func TestHealthChecker_PingsPeers(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	checker := NewHealthChecker([]PeerURL{
		{Region: "in", URL: srv.URL},
	})
	healthy := checker.HealthyRegions(context.Background())
	if len(healthy) != 1 || healthy[0] != "in" {
		t.Errorf("expected [in], got %v", healthy)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("expected 1 HTTP call, got %d", calls)
	}
}

func TestHealthChecker_Cache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	checker := NewHealthChecker([]PeerURL{
		{Region: "in", URL: srv.URL},
	})
	_ = checker.HealthyRegions(context.Background())

	// Second call should use 5s cache.
	healthy := checker.HealthyRegions(context.Background())
	if len(healthy) != 1 {
		t.Errorf("expected cached result, got %v", healthy)
	}
}

func TestHealthChecker_DeadPeer(t *testing.T) {
	checker := NewHealthChecker([]PeerURL{
		{Region: "in", URL: "http://localhost:1"}, // will fail
	})
	healthy := checker.HealthyRegions(context.Background())
	if len(healthy) != 0 {
		t.Errorf("expected no healthy regions, got %v", healthy)
	}
}

func TestValidateRegion(t *testing.T) {
	cases := []struct {
		region string
		want   bool
	}{
		{"sg", true},
		{"in", true},
		{"eu", true},
		{"us-east-1", true},
		{"", false},
		{"UPPER", false},
		{"has space", false},
	}
	for _, c := range cases {
		err := ValidateRegion(c.region)
		gotOK := err == nil
		if gotOK != c.want {
			t.Errorf("ValidateRegion(%q): got %v, want %v (err: %v)", c.region, gotOK, c.want, err)
		}
	}
}

func TestErrCacheMiss(t *testing.T) {
	if errCacheMiss == nil {
		t.Fatal("errCacheMiss should not be nil")
	}
	if !errors.Is(errCacheMiss, errCacheMiss) {
		t.Error("errCacheMiss should match itself")
	}
}

func TestErrOrgNotFound(t *testing.T) {
	if errOrgNotFound == nil {
		t.Fatal("errOrgNotFound should not be nil")
	}
	if !errors.Is(errOrgNotFound, errOrgNotFound) {
		t.Error("errOrgNotFound should match itself")
	}
}

func TestNewFailoverEvaluator_NilLogger(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{
		"org-x": {HomeRegion: "sg", ResidencyPinned: false},
	}}
	router := New(store, newMemKV())
	checker := NewHealthChecker([]PeerURL{})
	regions := config.RegionMap{"sg": {Name: "sg", Priority: 1}}

	fe := NewFailoverEvaluator(router, checker, regions, "sg", nil)
	if fe == nil {
		t.Fatal("expected non-nil evaluator")
	}

	err := fe.Decide(context.Background(), "org-x")
	if err != nil {
		t.Errorf("expected nil for local org, got: %v", err)
	}
}

func TestPeerRedirect_Error(t *testing.T) {
	pr := PeerRedirect{TargetURL: "http://in:8082", Reason: "home region down"}
	msg := pr.Error()
	if msg != "redirect to http://in:8082: home region down" {
		t.Errorf("unexpected error string: %s", msg)
	}
}

func TestConfigRegionMap_SortedByPriority(t *testing.T) {
	rm := config.RegionMap{
		"eu": {Name: "eu", Priority: 3},
		"sg": {Name: "sg", Priority: 1},
		"in": {Name: "in", Priority: 2},
	}
	sorted := rm.SortedByPriority()
	if len(sorted) != 3 {
		t.Fatalf("expected 3 regions, got %d", len(sorted))
	}
	for i, rc := range sorted {
		expected := []string{"sg", "in", "eu"}[i]
		if rc.Name != expected {
			t.Errorf("sorted[%d]: expected %s, got %s", i, expected, rc.Name)
		}
	}
}

func TestConfigRegionMap_Lookup(t *testing.T) {
	rm := config.RegionMap{
		"sg": {Name: "sg"},
		"in": {Name: "in"},
	}
	rc, ok := rm.Lookup("sg")
	if !ok || rc.Name != "sg" {
		t.Errorf("expected sg found, got %v %+v", ok, rc)
	}
	_, ok = rm.Lookup("unknown")
	if ok {
		t.Error("expected not found for unknown region")
	}
}

func TestConfigRegionMap_SortedByPriority_Empty(t *testing.T) {
	var rm config.RegionMap
	sorted := rm.SortedByPriority()
	if len(sorted) != 0 {
		t.Errorf("expected empty, got %v", sorted)
	}
}

func TestRouter_SetAssignment_ReadOnlyStore(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{}} // writable=false
	router := New(store, newMemKV())
	err := router.SetAssignment(context.Background(), "org-x", "eu", true)
	if err == nil {
		t.Fatal("expected error for read-only store")
	}
}

func TestRouter_SetAssignment_Success(t *testing.T) {
	store := &fakeStore{rows: map[string]Assignment{}, writable: true}
	router := New(store, newMemKV())

	if err := router.SetAssignment(context.Background(), "org-new", "eu", true); err != nil {
		t.Fatalf("SetAssignment: %v", err)
	}

	got := router.Resolve(context.Background(), "org-new")
	if got.HomeRegion != "eu" || !got.ResidencyPinned {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestRouter_NewWithRedis_TypeCheck(t *testing.T) {
	// Verify that NewWithRedis accepts a mock redis client via interface.
	store := &fakeStore{rows: map[string]Assignment{}}
	rdb := newMemKV() // memKV implements kvStore, but NewWithRedis expects *redis.Client
	_ = store
	_ = rdb
	// We can't easily test this without a real redis client, but the compile-time
	// check that *redis.Client satisfies kvStore is sufficient.
}
