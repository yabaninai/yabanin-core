package circuit

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTenantKey_Composition(t *testing.T) {
	cases := []struct {
		name     string
		org      string
		workload string
	}{
		{"plain", "org1", "wl1"},
		{"concatenation collision pair a", "a", "bc"},
		{"concatenation collision pair b", "ab", "c"},
		{"empty org", "", "wl"},
		{"empty workload", "org", ""},
		{"both empty", "", ""},
	}
	seen := make(map[string]string)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := TenantKey(tc.org, tc.workload)
			if again := TenantKey(tc.org, tc.workload); again != key {
				t.Fatalf("tenant key must be stable: %q then %q", key, again)
			}
			if prev, clash := seen[key]; clash {
				t.Fatalf("tenant key collision: (%q,%q) and (%q,%q) both %q",
					prev, "", tc.org, tc.workload, key)
			}
			seen[key] = tc.org
		})
	}
	// The pair every naive concatenation merges must stay distinct.
	if TenantKey("a", "bc") == TenantKey("ab", "c") {
		t.Fatal(`("a","bc") and ("ab","c") must not share a key`)
	}
}

// Acceptance (tenant dimension): a noisy tenant's failure storm opens only
// its own breaker for the endpoint — every other tenant keeps using it.
func TestTenantMap_NoisyTenantTripsAlone(t *testing.T) {
	tm := NewTenantMap(Config{
		Enabled:          true,
		FailureThreshold: 3,
		SuccessThreshold: 2,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	}, 0, nil)
	ep := "https://api.test/v1"

	for i := 0; i < 3; i++ {
		if err := tm.Allow("noisy", ep); err != nil {
			t.Fatalf("noisy attempt %d must be allowed, got %v", i, err)
		}
		tm.RecordFailure("noisy", ep)
	}

	if st := tm.State("noisy", ep); st != StateOpen {
		t.Fatalf("noisy tenant breaker must be open, got %s", st)
	}
	if err := tm.Allow("noisy", ep); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("noisy tenant must be rejected, got %v", err)
	}
	// Other tenants are untouched by the storm.
	if err := tm.Allow("other", ep); err != nil {
		t.Fatalf("other tenant must still be served, got %v", err)
	}
	if st := tm.State("other", ep); st != StateClosed {
		t.Fatalf("other tenant breaker must stay closed, got %s", st)
	}
	if ra := tm.RetryAfter("noisy", ep); ra <= 0 {
		t.Fatalf("open breaker must carry a retry hint, got %v", ra)
	}
	if ra := tm.RetryAfter("other", ep); ra != 0 {
		t.Fatalf("closed breaker must not carry a retry hint, got %v", ra)
	}
}

// Negative: an exhausted probe budget is per tenant — one tenant's half-open
// probing cannot consume or block another tenant's slot.
func TestTenantMap_ProbeBudgetNotShared(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      40 * time.Millisecond,
		Window:           time.Minute,
	}
	tm := NewTenantMap(cfg, 0, nil)
	ep := "https://api.test/v1"

	if err := tm.Allow("noisy", ep); err != nil {
		t.Fatalf("noisy must be allowed, got %v", err)
	}
	tm.RecordFailure("noisy", ep) // → Open

	time.Sleep(2 * cfg.OpenTimeout)

	// Noisy consumes its single half-open probe slot.
	if err := tm.Allow("noisy", ep); err != nil {
		t.Fatalf("half-open probe must be admitted, got %v", err)
	}
	if err := tm.Allow("noisy", ep); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("probe budget must be exhausted, got %v", err)
	}

	// Other traffic is independent, and its success cannot touch the
	// noisy tenant's in-flight probe.
	if err := tm.Allow("other", ep); err != nil {
		t.Fatalf("other tenant must be served while noisy probes, got %v", err)
	}
	tm.RecordSuccess("other", ep)
	if got := tm.Breaker("noisy", ep).Metrics().HalfOpenInFlight; got != 1 {
		t.Fatalf("noisy probe slot must be unaffected by other tenants, got %d in flight", got)
	}

	// The probe outcome closes only the noisy tenant's breaker.
	tm.RecordSuccess("noisy", ep)
	if st := tm.State("noisy", ep); st != StateClosed {
		t.Fatalf("noisy must recover to closed, got %s", st)
	}
	if st := tm.State("other", ep); st != StateClosed {
		t.Fatalf("other must be untouched, got %s", st)
	}
}

func TestTenantMap_EndpointNormalizationSharesOneBreaker(t *testing.T) {
	tm := NewTenantMap(Config{Enabled: true, FailureThreshold: 1, OpenTimeout: time.Minute, Window: time.Minute}, 0, nil)

	if err := tm.Allow("tenant-a", "https://API.test:443/v1"); err != nil {
		t.Fatalf("first form must be allowed, got %v", err)
	}
	tm.RecordFailure("tenant-a", "https://api.test:443/other/path?x=1")

	if got := tm.Len(); got != 1 {
		t.Fatalf("normalized forms must share one breaker, got %d entries", got)
	}
	if st := tm.State("tenant-a", "HTTPS://API.test:443"); st != StateOpen {
		t.Fatalf("raw variant must observe the same breaker, got %s", st)
	}

	// A different tenant on the same endpoint is a distinct breaker.
	tm.RecordFailure("tenant-b", "https://api.test:443")
	if got := tm.Len(); got != 2 {
		t.Fatalf("second tenant must get its own breaker, got %d entries", got)
	}
	if st := tm.State("tenant-b", "https://api.test:443"); st != StateOpen {
		t.Fatalf("second tenant breaker must be open, got %s", st)
	}
	if st := tm.State("tenant-a", "https://api.test:443"); st != StateOpen {
		t.Fatalf("first tenant breaker must stay open, got %s", st)
	}
}

func TestTenantMap_LRUEvictsLeastRecentlyUsed(t *testing.T) {
	tm := NewTenantMap(Config{
		Enabled:          true,
		FailureThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	}, 2, nil)
	ep := "https://api.test/v1"

	if err := tm.Allow("tenant-a", ep); err != nil {
		t.Fatalf("tenant-a allowed, got %v", err)
	}
	tm.RecordFailure("tenant-a", ep) // tenant-a → Open
	_ = tm.Breaker("tenant-b", ep)   // tenant-b now more recent

	_ = tm.Breaker("tenant-c", ep) // over the bound → evicts tenant-a (LRU)
	if got := tm.Len(); got != 2 {
		t.Fatalf("map must stay bounded at 2, got %d", got)
	}

	// Evicted tenant lost its open state: a fresh breaker starts closed.
	if st := tm.State("tenant-a", ep); st != StateClosed {
		t.Fatalf("re-created breaker must start closed, got %s", st)
	}
	if err := tm.Allow("tenant-a", ep); err != nil {
		t.Fatalf("re-created breaker must admit, got %v", err)
	}
}

func TestTenantMap_UnattributedSharesOneBucket(t *testing.T) {
	tm := NewTenantMap(Config{
		Enabled:          true,
		FailureThreshold: 2,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	}, 0, nil)
	ep := "https://api.test/v1"

	for i := 0; i < 2; i++ {
		if err := tm.Allow("", ep); err != nil {
			t.Fatalf("unattributed attempt %d must be allowed, got %v", i, err)
		}
		tm.RecordFailure("", ep)
	}
	if st := tm.State("", ep); st != StateOpen {
		t.Fatalf("unattributed bucket must be open, got %s", st)
	}
	if err := tm.Allow("attributed", ep); err != nil {
		t.Fatalf("attributed tenant must be unaffected, got %v", err)
	}
}

func TestTenantMap_OpenAndRecoverLogWithTenant(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      20 * time.Millisecond,
		Window:           time.Minute,
	}
	tm := NewTenantMap(cfg, 0, lg)
	ep := "https://api.test/v1"

	if err := tm.Allow("tenant-a", ep); err != nil {
		t.Fatalf("allowed, got %v", err)
	}
	tm.RecordFailure("tenant-a", ep)

	if !strings.Contains(buf.String(), "circuit breaker open") ||
		!strings.Contains(buf.String(), "tenant-a") ||
		!strings.Contains(buf.String(), "https://api.test") {
		t.Fatalf("open log must carry tenant and endpoint, got: %s", buf.String())
	}

	time.Sleep(2 * cfg.OpenTimeout)
	if err := tm.Allow("tenant-a", ep); err != nil {
		t.Fatalf("recovery probe must be admitted, got %v", err)
	}
	tm.RecordSuccess("tenant-a", ep)

	if !strings.Contains(buf.String(), "circuit breaker recovered") {
		t.Fatalf("recovery must be logged, got: %s", buf.String())
	}
}

// Jitter configured on the shared config must reach every per-tenant
// breaker: refusal hints for one tenant are spread, never identical, and
// never earlier than the exact remaining refusal time.
func TestTenantMap_RetryAfterJitterReachesTenantBreakers(t *testing.T) {
	restore := withRetryAfterRandom(t, func() float64 { return 0.5 })
	defer restore()

	tm := NewTenantMap(Config{
		Enabled:          true,
		FailureThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
		RetryAfterJitter: 0.5,
	}, 0, nil)
	ep := "https://api.test/v1"

	tm.RecordFailure("tenant-a", ep) // → Open
	tm.RecordFailure("tenant-b", ep) // → Open

	// draw()==0.5 with fraction 0.5 widens the remaining refusal time by
	// exactly 25%. The remaining time decays between the trip and the read,
	// so the assertion pins a 2s window under the 75s target: exact hints
	// (~60s) and double-jitter (~90s) both fall far outside.
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		ra := tm.RetryAfter(tenant, ep)
		want := time.Minute + time.Minute/4
		if ra > want || ra < want-2*time.Second {
			t.Fatalf("%s: jittered hint must be %v minus decay (≤2s), got %v", tenant, want, ra)
		}
	}
}

func TestTenantMap_ConcurrentMixedUsage(t *testing.T) {
	tm := NewTenantMap(Config{
		Enabled:          true,
		FailureThreshold: 5,
		SuccessThreshold: 1,
		OpenTimeout:      10 * time.Millisecond,
		Window:           time.Minute,
	}, 0, nil)
	endpoints := []string{"https://a.test", "https://b.test"}
	tenants := []string{"t0", "t1", "t2", "t3"}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			tenant := tenants[g%len(tenants)]
			ep := endpoints[(g/len(tenants))%len(endpoints)]
			for i := 0; i < 100; i++ {
				if err := tm.Allow(tenant, ep); err != nil {
					continue
				}
				if i%3 == 0 {
					tm.RecordFailure(tenant, ep)
				} else {
					tm.RecordSuccess(tenant, ep)
				}
				_ = tm.State(tenant, ep)
				_ = tm.RetryAfter(tenant, ep)
			}
		}(g)
	}
	wg.Wait()

	// Bounded map, every tenant/endpoint pair materialized.
	if got := tm.Len(); got != len(tenants)*len(endpoints) {
		t.Fatalf("expected %d tracked breakers, got %d", len(tenants)*len(endpoints), got)
	}
	for _, tenant := range tenants {
		for _, ep := range endpoints {
			if got := tm.Breaker(tenant, ep).Metrics().HalfOpenInFlight; got < 0 {
				t.Fatalf("probe counter must never go negative, got %d", got)
			}
		}
	}
}
