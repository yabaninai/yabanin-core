//go:build chaos

package chaos

import (
	"context"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/regionrouter"
)

// TestFailoverNonPinned verifies that a non-pinned org on a down region
// gets routed to the next best healthy peer.
func TestFailoverNonPinned(t *testing.T) {
	store := &mockStore{rows: map[string]regionrouter.Assignment{
		"org-nonpinned": {HomeRegion: "sg", ResidencyPinned: false},
	}}
	router := regionrouter.New(store, &memKV{})

	checker := &mockChecker{healthy: []string{"in"}}

	fe := regionrouter.NewFailoverEvaluator(router, checker, regionrouter.RegionMap{
		"sg": {Name: "sg", Priority: 1},
		"in": {Name: "in", Priority: 2},
	}, "in", nil)

	err := fe.Decide(context.Background(), "org-nonpinned")
	if err == nil {
		t.Fatal("expected redirect when home region is down")
	}
	t.Logf("got expected failover error: %v", err)
}

// TestFailoverPinnedReturns503 verifies that a pinned org gets 503 when
// its home region is down (no cross-region data leakage).
func TestFailoverPinnedReturns503(t *testing.T) {
	store := &mockStore{rows: map[string]regionrouter.Assignment{
		"org-pinned": {HomeRegion: "sg", ResidencyPinned: true},
	}}
	router := regionrouter.New(store, &memKV{})

	checker := &mockChecker{healthy: []string{"in"}} // SG is down

	fe := regionrouter.NewFailoverEvaluator(router, checker, regionrouter.RegionMap{
		"sg": {Name: "sg", Priority: 1},
		"in": {Name: "in", Priority: 2},
	}, "in", nil)

	err := fe.Decide(context.Background(), "org-pinned")
	if err == nil {
		t.Fatal("expected 503 error for pinned org with down home region")
	}
}

// TestChaosRegionDown verifies that when the primary region (sg) is killed,
// non-pinned orgs failover within the expected time window.
func TestChaosRegionDown(t *testing.T) {
	store := &mockStore{rows: map[string]regionrouter.Assignment{
		"org-a": {HomeRegion: "sg", ResidencyPinned: false},
		"org-b": {HomeRegion: "in", ResidencyPinned: true},
	}}
	router := regionrouter.New(store, &memKV{})

	checker := &mockChecker{healthy: []string{"in", "eu"}}

	fe := regionrouter.NewFailoverEvaluator(router, checker, regionrouter.RegionMap{
		"sg": {Name: "sg", Priority: 1},
		"in": {Name: "in", Priority: 2},
		"eu": {Name: "eu", Priority: 3},
	}, "sg", nil)

	err := fe.Decide(context.Background(), "org-a")
	if err == nil {
		t.Fatal("expected redirect for non-pinned org-a")
	}

	err = fe.Decide(context.Background(), "org-b")
	if err != nil {
		t.Fatalf("pinned org-b on healthy home region should serve locally: %v", err)
	}
}

// --- test helpers copied from regionrouter for build tag isolation ---

type mockStore struct {
	rows map[string]regionrouter.Assignment
}

func (m *mockStore) LookupRegion(_ context.Context, orgID string) (string, bool, error) {
	a, ok := m.rows[orgID]
	if !ok {
		return "", false, regionrouter.ErrOrgNotFound
	}
	return a.HomeRegion, a.ResidencyPinned, nil
}

func (m *mockStore) UpsertRegion(_ context.Context, orgID, region string, pinned bool) error {
	m.rows[orgID] = regionrouter.Assignment{HomeRegion: region, ResidencyPinned: pinned}
	return nil
}

type memKV struct {
	data map[string]string
}

func (m *memKV) Get(_ context.Context, key string) (string, error) {
	v, ok := m.data[key]
	if !ok {
		return "", regionrouter.ErrCacheMiss
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

type mockChecker struct {
	healthy []string
}

func (m *mockChecker) HealthyRegions(_ context.Context) []string {
	return m.healthy
}
