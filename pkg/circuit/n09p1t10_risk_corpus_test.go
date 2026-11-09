package circuit

// N09-P01-T10 [risk] — resource-bound verification for pkg/circuit.
// Test-only card: zero production changes.
//
//	resources — an identity storm (thousands of distinct endpoint keys,
//	URL-variant duplicates of the same endpoint, malformed keys) can never
//	grow the breaker map past its configured bound; the hot endpoint's
//	open state survives the storm via LRU recency; variant spellings of one
//	endpoint share one breaker; concurrent storms stay bounded and
//	deadlock-free.

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestN09P1T10_Risk_IdentityStormStaysBounded: 5000 distinct endpoint keys
// against a 64-entry map. The bound holds, and the hot endpoint — touched on
// every iteration, so it stays most-recently-used — keeps its tripped state
// while cold entries are evicted around it.
func TestN09P1T10_Risk_IdentityStormStaysBounded(t *testing.T) {
	t.Parallel()

	m := NewMap(Config{Enabled: true, Name: "storm"}, 64, nil)
	const hot = "https://hot.example"

	// Trip the hot breaker first (default threshold 10).
	for i := 0; i < 10; i++ {
		m.RecordFailure(hot)
	}
	require.Equal(t, StateOpen, m.State(hot))

	for i := 0; i < 5000; i++ {
		key := fmt.Sprintf("https://host-%04d.example", i)
		m.RecordFailure(key)
		require.Error(t, m.Allow(hot), "the open hot breaker refuses while the storm runs")
	}

	assert.LessOrEqual(t, m.Len(), 64, "the map bound is hard")
	assert.Equal(t, StateOpen, m.State(hot),
		"the hot endpoint's tripped state survives the storm via LRU recency")
}

// TestN09P1T10_Risk_URLVariantsCollapseToOneBreaker: case, path, query,
// fragment, userinfo and whitespace variants of the same endpoint map to one
// breaker — adversarial spelling cannot multiply breakers for one upstream,
// and failures recorded through any variant trip the shared breaker.
func TestN09P1T10_Risk_URLVariantsCollapseToOneBreaker(t *testing.T) {
	t.Parallel()

	variants := []string{
		"https://api.example.com/v1/chat",
		"HTTPS://API.EXAMPLE.COM/v1/chat?trace=1",
		" https://api.example.com/other/path#frag ",
		"https://user:secret@api.example.com",
	}

	key := EndpointKey(variants[0])
	for _, v := range variants[1:] {
		assert.Equal(t, key, EndpointKey(v), "variant %q must collapse to the same breaker identity", v)
	}

	// Documented caller contract: normalization happens at the call
	// boundary (map_test.go pins the same pattern). With it, all variants
	// share one breaker and the combined failures trip it.
	m := NewMap(Config{Enabled: true, Name: "variants", FailureThreshold: 3}, 0, nil)
	for _, v := range variants {
		m.RecordFailure(EndpointKey(v))
	}
	assert.Equal(t, 1, m.Len(), "all variants share one breaker under the documented contract")
	assert.Equal(t, StateOpen, m.State(EndpointKey(variants[1])))
	require.Error(t, m.Allow(EndpointKey(variants[3])), "the shared refusal applies to every variant")

	// Risk guard: a caller that skips normalization gets per-spelling
	// breakers (the map never rewrites keys), but the cardinality bound
	// still protects it — spelling storms cannot grow the map unbounded.
	raw := NewMap(Config{Enabled: true, Name: "raw", FailureThreshold: 3}, 2, nil)
	for i := 0; i < 50; i++ {
		raw.RecordFailure(fmt.Sprintf("https://api.example.com/v%d", i)) // path is part of the raw key
	}
	assert.LessOrEqual(t, raw.Len(), 2)
}

// TestN09P1T10_Risk_MalformedKeysDegradeWithoutSilentSharing: unparseable
// inputs degrade to the lowercased trimmed literal — they never panic, never
// collapse into the well-formed endpoint namespace, and equal malformed
// spellings share (documented), while case-different spellings collapse.
func TestN09P1T10_Risk_MalformedKeysDegradeWithoutSilentSharing(t *testing.T) {
	t.Parallel()

	malformed := []string{"", "   ", "not a url", "http://", "://x", "/relative", "HTTPS://"}
	for _, raw := range malformed {
		assert.NotPanics(t, func() { _ = EndpointKey(raw) })

		// Degraded keys stay out of the well-formed endpoint namespace:
		// they never equal a parsed scheme://host identity.
		if k := EndpointKey(raw); k != "" {
			assert.NotEqual(t, "https://api.example.com", k,
				"degraded key %q must not share a well-formed endpoint identity", raw)
		}
	}

	// Documented degradation rules, pinned:
	assert.Empty(t, EndpointKey(""))
	assert.Equal(t, "not a url", EndpointKey("Not A URL"))
	assert.Equal(t, "http://", EndpointKey("HTTP://"))
	assert.Equal(t, "://x", EndpointKey(" ://x "))

	// No silent sharing with the well-formed namespace.
	assert.NotEqual(t, EndpointKey("http://"), EndpointKey("https://api.example.com"))
}

// TestN09P1T10_Risk_ConcurrentStormBoundedAndDeadlockFree: 64 goroutines
// hammering distinct keys with Allow/RecordFailure/RecordSuccess finish, and
// the map stays within its bound.
func TestN09P1T10_Risk_ConcurrentStormBoundedAndDeadlockFree(t *testing.T) {
	t.Parallel()

	m := NewMap(Config{Enabled: true, Name: "concurrent-storm"}, 128, nil)

	const workers, keysPerWorker = 64, 80
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < keysPerWorker; i++ {
				key := fmt.Sprintf("https://w%02d-%03d.example", w, i)
				if err := m.Allow(key); err != nil {
					continue // open: skip the work, still touch the map
				}
				if i%2 == 0 {
					m.RecordSuccess(key)
				} else {
					m.RecordFailure(key)
				}
				_ = m.State(key)
			}
		}(w)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-timeoutAfterSeconds(10):
		t.Fatal("concurrent storm deadlocked")
	}

	assert.LessOrEqual(t, m.Len(), 128)
}

// timeoutAfterSeconds is a tiny helper so the test reads linearly.
func timeoutAfterSeconds(n int) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		time.Sleep(time.Duration(n) * time.Second)
		close(ch)
	}()
	return ch
}

// The host-key shape, pinned once more explicitly: case collapses, the
// default port does NOT collapse (the port is part of the documented host
// identity — a distinct port is a distinct endpoint).
func TestN09P1T10_Risk_HostKeyShapeStable(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "https://hot.example", EndpointKey("https://HOT.example/anything"))
	assert.Equal(t, "https://hot.example:8443", EndpointKey("https://hot.example:8443/x"))
	assert.NotEqual(t,
		EndpointKey("https://hot.example"),
		EndpointKey("https://hot.example:8443"),
		"a distinct port is a distinct endpoint identity")
	assert.True(t, strings.HasPrefix(EndpointKey("https://hot.example/anything"), "https://"))
}
