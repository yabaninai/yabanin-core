package circuit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// --- EndpointKey normalization (OP-2 callout parity, minus the path) ---

func TestEndpointKey_Normalization(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://api.openai.com/v1/chat/completions", "https://api.openai.com"},
		{"http://Api.Example.ORG:8080/a/b?token=x", "http://api.example.org:8080"},
		{"  https://host.example/path  ", "https://host.example"},
		{"https://host.example#frag", "https://host.example"},
		{"https://u:p@host.example/path", "https://host.example"},
		{"not a url", "not a url"},
		{"http://127.0.0.1:9090", "http://127.0.0.1:9090"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := EndpointKey(tc.raw); got != tc.want {
			t.Errorf("EndpointKey(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestEndpointKey_PathAndQueryDoNotSplitEndpoints(t *testing.T) {
	a := EndpointKey("https://api.example.com/v1/chat/completions")
	b := EndpointKey("https://api.example.com/v1/embeddings")
	if a != b {
		t.Fatalf("routes of one endpoint must share a breaker: %q vs %q", a, b)
	}
}

// --- Per-endpoint isolation (the W-VER defect) ---

func TestCircuitMap_FlapOneEndpointLeavesOthersWorking(t *testing.T) {
	m := NewMap(Config{
		Enabled:          true,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	}, 0, nil)
	epA := EndpointKey("http://127.0.0.1:1/v1")
	epB := EndpointKey("http://127.0.0.1:2/v1")

	// Flap endpoint A past its threshold.
	for i := 0; i < 2; i++ {
		if err := m.Allow(epA); err != nil {
			t.Fatalf("A attempt %d must be allowed, got %v", i, err)
		}
		m.RecordFailure(epA)
	}
	if m.State(epA) != StateOpen {
		t.Fatalf("endpoint A must be open after flapping, got %s", m.State(epA))
	}
	if err := m.Allow(epA); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("endpoint A must reject, got %v", err)
	}
	// Endpoint B is untouched.
	if err := m.Allow(epB); err != nil {
		t.Fatalf("endpoint B must still be served, got %v", err)
	}
	m.RecordSuccess(epB)
	if m.State(epB) != StateClosed {
		t.Fatalf("endpoint B must stay closed, got %s", m.State(epB))
	}
}

// --- Recovery: half-open probe per endpoint ---

func TestCircuitMap_HalfOpenProbeRecoversEndpoint(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      40 * time.Millisecond,
		Window:           time.Minute,
	}
	m := NewMap(cfg, 0, nil)
	epA := EndpointKey("http://a.test")
	epB := EndpointKey("http://b.test")

	if err := m.Allow(epA); err != nil {
		t.Fatalf("A must be allowed, got %v", err)
	}
	m.RecordFailure(epA) // → Open
	if err := m.Allow(epA); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("A must reject while open, got %v", err)
	}

	time.Sleep(2 * cfg.OpenTimeout)

	// Probe succeeds → closed. B was never open in the first place.
	if err := m.Allow(epA); err != nil {
		t.Fatalf("half-open probe must be admitted, got %v", err)
	}
	m.RecordSuccess(epA)
	if m.State(epA) != StateClosed {
		t.Fatalf("A must recover to closed, got %s", m.State(epA))
	}
	if m.State(epB) != StateClosed {
		t.Fatalf("B must be untouched, got %s", m.State(epB))
	}

	// Failed probe → re-open with the slot released (floor-0 release).
	if err := m.Allow(epA); err != nil {
		t.Fatalf("A must be allowed again, got %v", err)
	}
	m.RecordFailure(epA)
	if err := m.Allow(epA); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("failed probe must re-open A, got %v", err)
	}
	if got := m.Breaker(epA).Metrics().HalfOpenInFlight; got != 0 {
		t.Fatalf("failed probe must release its slot, got %d in flight", got)
	}
}

// --- LRU bound ---

func TestCircuitMap_LRUEvictsLeastRecentlyUsed(t *testing.T) {
	m := NewMap(Config{
		Enabled:          true,
		FailureThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	}, 2, nil)
	epA := EndpointKey("http://a.test")
	epB := EndpointKey("http://b.test")
	epC := EndpointKey("http://c.test")

	if err := m.Allow(epA); err != nil {
		t.Fatalf("A allowed, got %v", err)
	}
	m.RecordFailure(epA) // A → Open
	_ = m.Breaker(epB)   // B is now more recent than A

	_ = m.Breaker(epC) // over the bound → evicts A (LRU)
	if got := m.Len(); got != 2 {
		t.Fatalf("map must stay bounded at 2, got %d", got)
	}

	// Evicted A lost its open state: a fresh breaker starts closed.
	if m.State(epA) != StateClosed {
		t.Fatalf("re-created endpoint must start closed, got %s", m.State(epA))
	}
	if err := m.Allow(epA); err != nil {
		t.Fatalf("re-created endpoint must admit, got %v", err)
	}
}

// --- Global kill-switch key ---

func TestCircuitMap_GlobalKeySharesOneBreaker(t *testing.T) {
	m := NewMap(Config{
		Enabled:          true,
		FailureThreshold: 2,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	}, 0, nil)

	for i := 0; i < 2; i++ {
		if err := m.Allow(GlobalBreakerKey); err != nil {
			t.Fatalf("global attempt %d must be allowed, got %v", i, err)
		}
		m.RecordFailure(GlobalBreakerKey)
	}
	if err := m.Allow(GlobalBreakerKey); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("global breaker must reject after threshold, got %v", err)
	}
	if m.Len() != 1 {
		t.Fatalf("global scope must use exactly one entry, got %d", m.Len())
	}
	if got := testutil.ToFloat64(metrics.CircuitFailures.WithLabelValues(GlobalBreakerKey)); got < 1 {
		t.Fatalf("global trips must be counted under the empty label, got %v", got)
	}
}

// --- Observability: open/recover logs carry the endpoint key ---

type captureHandler struct {
	mu      sync.Mutex
	records []string
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Message+"|"+attrsString(r))
	return nil
}

func (h *captureHandler) withAttrs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.records))
	copy(out, h.records)
	return out
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func attrsString(r slog.Record) string {
	var b strings.Builder
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(a.Key + "=" + a.Value.String() + ";")
		return true
	})
	return b.String()
}

func TestCircuitMap_OpenAndRecoverLogsWithEndpoint(t *testing.T) {
	h := &captureHandler{}
	log := slog.New(h)
	m := NewMap(Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      30 * time.Millisecond,
		Window:           time.Minute,
	}, 0, log)
	ep := EndpointKey("http://ep.test")

	if err := m.Allow(ep); err != nil {
		t.Fatalf("must be allowed, got %v", err)
	}
	m.RecordFailure(ep) // → Open, logged

	time.Sleep(2 * 30 * time.Millisecond)
	if err := m.Allow(ep); err != nil {
		t.Fatalf("probe must be admitted, got %v", err)
	}
	m.RecordSuccess(ep) // → Closed, logged

	joined := strings.Join(h.withAttrs(), "\n")
	if !strings.Contains(joined, "circuit breaker open|endpoint="+ep) {
		t.Fatalf("open log must carry the endpoint, got: %s", joined)
	}
	if !strings.Contains(joined, "circuit breaker recovered|endpoint="+ep) {
		t.Fatalf("recover log must carry the endpoint, got: %s", joined)
	}
}

func TestBreaker_RejectsMetricCountsRejections(t *testing.T) {
	name := "rejects-metric"
	b := NewBreaker(Config{
		Name:             name,
		Enabled:          true,
		FailureThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	})
	before := testutil.ToFloat64(metrics.CircuitRejects.WithLabelValues(name))

	b.RecordFailure() // → Open
	if err := b.Allow(); err == nil {
		t.Fatal("open breaker must reject")
	}
	after := testutil.ToFloat64(metrics.CircuitRejects.WithLabelValues(name))
	if after != before+1 {
		t.Fatalf("rejection must increment CircuitRejects, delta %v", after-before)
	}

	// Disabled breakers never count: nil-map-safe gateways rely on this.
	off := NewBreaker(Config{Name: "disabled", Enabled: false})
	if err := off.Allow(); err != nil {
		t.Fatalf("disabled breaker must allow, got %v", err)
	}
	if got := testutil.ToFloat64(metrics.CircuitRejects.WithLabelValues("disabled")); got != 0 {
		t.Fatalf("disabled breaker must not count rejections, got %v", got)
	}
}

// --- Concurrency: W-CIR regression against the PER-ENDPOINT map ---
//
// TestCircuitMap_ConcurrentPerEndpointMixed hammers Allow/RecordSuccess/
// RecordFailure across two endpoint keys concurrently (run under -race) and
// asserts the probe-slot accounting stays bounded per breaker: leaked slots
// used to wedge breakers open.

func TestCircuitMap_ConcurrentPerEndpointMixed(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		FailureThreshold: 2,
		SuccessThreshold: 2,
		OpenTimeout:      time.Millisecond,
		Window:           time.Minute,
	}
	m := NewMap(cfg, 0, nil)
	endpoints := []string{
		EndpointKey("http://ep-one.test"),
		EndpointKey("http://ep-two.test"),
	}

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ep := endpoints[(g+i)%len(endpoints)]
				if err := m.Allow(ep); err != nil {
					continue
				}
				if (g+i)%3 == 0 {
					m.RecordFailure(ep)
				} else {
					m.RecordSuccess(ep)
				}
			}
		}(g)
	}
	wg.Wait()

	for _, ep := range endpoints {
		if got := m.Breaker(ep).Metrics().HalfOpenInFlight; got < 0 || int(got) > cfg.SuccessThreshold {
			t.Fatalf("half-open in-flight for %s must stay within [0, %d], got %d", ep, cfg.SuccessThreshold, got)
		}
		switch s := m.State(ep); s {
		case StateClosed, StateOpen, StateHalfOpen:
		default:
			t.Fatalf("impossible state for %s after mixed traffic: %s", ep, s)
		}
	}
	if got := m.Len(); got > DefaultMaxEndpoints {
		t.Fatalf("map must respect its bound, got %d", got)
	}
}

// TestCircuitMap_ConcurrentEvictionAndRecreate slams creation of many keys
// past the LRU bound while other goroutines keep using the surviving keys —
// the map must never hand out a half-constructed breaker or panic.
func TestCircuitMap_ConcurrentEvictionAndRecreate(t *testing.T) {
	m := NewMap(Config{
		Enabled:          true,
		FailureThreshold: 1,
		OpenTimeout:      time.Minute,
		Window:           time.Minute,
	}, 4, nil)

	hot := EndpointKey("http://hot.test")
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				ep := fmt.Sprintf("http://churn-%d-%d.test", g, i)
				if err := m.Allow(EndpointKey(ep)); err == nil {
					m.RecordSuccess(EndpointKey(ep))
				}
				if err := m.Allow(hot); err == nil {
					m.RecordSuccess(hot)
				}
			}
		}(g)
	}
	wg.Wait()

	if got := m.Len(); got > 4 {
		t.Fatalf("bound must hold under churn, got %d", got)
	}
	// The hot endpoint survived every eviction window and stays usable.
	if err := m.Allow(hot); err != nil {
		t.Fatalf("hot endpoint must remain usable, got %v", err)
	}
}
