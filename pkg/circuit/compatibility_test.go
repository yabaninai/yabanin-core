// N09-P02-T09 compatibility matrix, aspect pkg/circuit: the packet's
// circuit surfaces (T02 TenantMap, T03 RetryAfter+jitter, T04
// RecordCanceled) passed against the REAL supported consumer disciplines —
// pkg/pipeline/callout (direct Breaker, singleflight winner records the
// outcome) and pkg/gateway (Map with ScopePerEndpoint fallback hops and the
// ScopeGlobal kill switch) — under their OLD configurations, plus the
// explicit-refusal and clamp rows the older corpora do not own.
//
// Where T07 pinned primitive decision boundaries and T08 the interruption
// and recovery narratives, this corpus pins what an UNCHANGED consumer can
// observe across the packet branch: the old disciplines still compile and
// behave identically (no new API call is required), refusals stay
// errors.Is-matchable through the consumers' %w wrapping, the dual-scope
// gateway semantics are intact, a disabled config stays inert even with new
// fields set, and unsupported/clamped configuration falls back explicitly
// instead of misbehaving. Every case is deterministic: short real timers
// with bounded outcome polls, no goroutine timing dependencies.
package circuit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// calloutDiscipline models pkg/pipeline/callout's exact terminal discipline
// (callout.go:111-133, transport.go:127): Allow gates the call, the winner
// path records RecordFailure for ANY post error — including a canceled
// context — and RecordSuccess for a 2xx, and refusals are wrapped with %w so
// callers can errors.Is-match ErrCircuitOpen (callout.go:115).
type calloutDiscipline struct {
	br *Breaker
}

func (c calloutDiscipline) call(postErr error) error {
	if err := c.br.Allow(); err != nil {
		return fmt.Errorf("callout detector.internal: %w", err)
	}
	if postErr != nil {
		c.br.RecordFailure()
		return postErr
	}
	c.br.RecordSuccess()
	return nil
}

// oldBreakerConfig is a pre-packet configuration: thresholds and a window
// only. No RetryAfterJitter, no RecordCanceled wiring — exactly what an
// unchanged consumer constructs.
func oldBreakerConfig(threshold int, openTimeout time.Duration) Config {
	return Config{
		Enabled:          true,
		Name:             "detector.internal",
		FailureThreshold: threshold,
		SuccessThreshold: 1,
		OpenTimeout:      openTimeout,
		Window:           time.Minute,
	}
}

// TestCompat_CalloutShapeOldConfigLifecycle walks the callout discipline
// through a full trip-recover cycle under the old configuration: healthy
// flow serves, threshold failures open the breaker, refusals stay
// errors.Is-matchable through the %w wrap WITHOUT consulting any T03 API
// (the old discipline never calls RetryAfter), and after the open window a
// genuine success closes the breaker again. The packet must not have
// changed any observable step of this cycle.
func TestCompat_CalloutShapeOldConfigLifecycle(t *testing.T) {
	c := calloutDiscipline{br: NewBreaker(oldBreakerConfig(2, 40*time.Millisecond))}

	// Healthy flow: served, breaker closed, counters clean.
	require.NoError(t, c.call(nil))
	m := c.br.Metrics()
	assert.Equal(t, StateClosed, m.State)
	assert.Zero(t, m.FailureCount)

	// Degrade: two post errors trip the breaker exactly at the threshold.
	require.NoError(t, c.br.Allow(), "pre-trip attempts must be admitted")
	c.br.RecordFailure()
	require.NoError(t, c.br.Allow())
	c.br.RecordFailure()
	assert.Equal(t, StateOpen, c.br.State(), "old config must trip at the configured threshold")

	// Refusal: wrapped with %w (callout.go:115), errors.Is-matchable, and
	// the old flow needs no Retry-After advice to classify it.
	err := c.call(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCircuitOpen,
		"callout depends on matching ErrCircuitOpen through its own wrap")
	require.NotErrorIs(t, err, context.Canceled)

	// The T03 advice exists for NEW consumers without changing the old
	// contract: positive, bounded by the configured window, and unused by
	// the old discipline above.
	if hint := c.br.RetryAfter(); hint <= 0 || hint > 40*time.Millisecond {
		t.Fatalf("RetryAfter on the old config must be a positive hint within the window, got %v", hint)
	}

	// Recover: once the window elapses, the old discipline's plain
	// Allow+RecordSuccess probe closes the breaker again — no new API
	// involved. Poll Allow itself: the flip happens inside it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := c.br.Allow(); err == nil {
			c.br.RecordSuccess()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("open window never elapsed for the recovery probe")
		}
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, StateClosed, c.br.State(), "one genuine success with threshold 1 must close")
	require.NoError(t, c.call(nil), "serving must resume normally after recovery")
}

// TestCompat_CalloutShapeCanceledRequestsStillFeedBreaker pins the
// PRE-EXISTING old-consumer discipline this packet deliberately did not
// change: callout records RecordFailure for any post error, a canceled
// context included, so an impatient-client cancel storm can trip the
// endpoint breaker (documented hazard, T04 record; the fix is the wave-2
// wiring card adopting the terminal-path discipline, not a behavior change
// smuggled into the library). The pin proves the packet branch preserved
// old-consumer behavior exactly — the contrast (RecordCanceled carries no
// health signal) is owned by cancel_test.go and the joint scenario.
func TestCompat_CalloutShapeCanceledRequestsStillFeedBreaker(t *testing.T) {
	c := calloutDiscipline{br: NewBreaker(oldBreakerConfig(2, time.Hour))}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := fmt.Errorf("callout detector.internal: post: %w", ctx.Err())

	require.Error(t, c.call(canceled))
	require.Error(t, c.call(canceled))
	m := c.br.Metrics()
	assert.Equal(t, StateOpen, m.State,
		"old discipline: cancellations are indistinguishable failures")
	assert.Equal(t, 2, m.FailureCount)

	// Downstream effect the hazard describes: the next real request is
	// refused pre-upstream while the breaker is open.
	require.ErrorIs(t, c.call(nil), ErrCircuitOpen)
}

// TestCompat_GatewayShapePerEndpointFallbackHops models pkg/gateway's
// per-endpoint scope (upstream.go:451-476, the W-VER default): the scope is
// the consumer's choice of keys — each fallback hop gates itself on its own
// normalized endpoint breaker, and a hop whose breaker is open is a
// retryable failure — the chain advances to the next candidate instead of
// failing the request. The packet must not have changed this isolation or
// the fall-through.
func TestCompat_GatewayShapePerEndpointFallbackHops(t *testing.T) {
	m := NewMap(Config{
		Enabled:          true,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      time.Hour, // no recovery inside this scenario
		Window:           time.Minute,
	}, 0, nil)

	flapping := EndpointKey("https://flapping.test/v1")
	healthy := EndpointKey("https://healthy.test/v1")

	// The flapping endpoint degrades open; the healthy one is untouched.
	require.NoError(t, m.Allow(flapping))
	m.RecordFailure(flapping)
	assert.Equal(t, StateOpen, m.State(flapping))
	assert.Equal(t, StateClosed, m.State(healthy))

	// A request whose first candidate is open falls through to the next
	// candidate and is served: refusals stay errors.Is-matchable through
	// the gateway's %w wrap (upstream.go:461).
	hopErr := fmt.Errorf("circuit breaker open for endpoint %s: %w", flapping, m.Allow(flapping))
	require.ErrorIs(t, hopErr, ErrCircuitOpen)
	require.NoError(t, m.Allow(healthy), "the chain must reach the healthy candidate")
	m.RecordSuccess(healthy)
	assert.Equal(t, StateClosed, m.State(healthy))
	assert.Equal(t, StateOpen, m.State(flapping))
}

// TestCompat_GatewayShapeGlobalKillSwitch models pkg/gateway's ScopeGlobal
// compatibility mode (upstream.go:426-449): the gateway wires every hop
// onto the single shared GlobalBreakerKey, gates the request entry before
// any candidate is tried, records the final outcome on that one breaker,
// and embeds the State() string in its refusal message. The packet must not
// have changed this mode.
func TestCompat_GatewayShapeGlobalKillSwitch(t *testing.T) {
	m := NewMap(Config{
		Enabled:          true,
		FailureThreshold: 2,
		SuccessThreshold: 1,
		OpenTimeout:      40 * time.Millisecond,
		Window:           time.Minute,
	}, 0, nil)

	entry := func() error {
		if err := m.Allow(GlobalBreakerKey); err != nil {
			return fmt.Errorf("circuit breaker is %s", m.State(GlobalBreakerKey))
		}
		return nil
	}

	// Entries gate on the single breaker; two failing requests trip it for
	// every endpoint at once.
	require.NoError(t, entry())
	m.RecordFailure(GlobalBreakerKey)
	require.NoError(t, entry())
	m.RecordFailure(GlobalBreakerKey)

	err := entry()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open",
		"the gateway embeds the State() string in its refusal message")
	assert.Equal(t, StateOpen, m.State(GlobalBreakerKey))

	// Recovery through the same single key.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := entry(); err == nil {
			m.RecordSuccess(GlobalBreakerKey)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("kill-switch window never elapsed")
		}
		time.Sleep(time.Millisecond)
	}
	assert.Equal(t, StateClosed, m.State(GlobalBreakerKey))
	require.NoError(t, entry(), "traffic must resume through the kill switch")
}

// TestCompat_DisabledConfigStaysInertWithNewFields pins the forward
// compatibility of a disabled deployment: a config with Enabled=false must
// stay fully inert even when the packet's new fields are set on it — no
// shedding, no hint, no cancellation bookkeeping. An operator who merely
// upgrades must observe zero behavior change.
func TestCompat_DisabledConfigStaysInertWithNewFields(t *testing.T) {
	b := NewBreaker(Config{
		Enabled:          false,
		Name:             "disabled",
		FailureThreshold: 1,
		OpenTimeout:      time.Hour,
		Window:           time.Minute,
		RetryAfterJitter: 0.9, // new T03 field: must have no effect while disabled
	})

	require.NoError(t, b.Allow(), "a disabled breaker must admit unconditionally")
	b.RecordFailure()
	b.RecordFailure()
	require.NoError(t, b.Allow())
	b.RecordCanceled() // new T04 API: must be a no-op while disabled
	assert.Equal(t, StateClosed, b.State())
	assert.Zero(t, b.RetryAfter(), "a disabled breaker must never advertise a hint")
	m := b.Metrics()
	assert.Zero(t, m.FailureCount, "disabled means no health bookkeeping")
	assert.Zero(t, m.HalfOpenInFlight)

	// The same inertness through the map forwarders (gateway passes its
	// config through NewMap verbatim).
	mp := NewMap(Config{Enabled: false, RetryAfterJitter: 0.9}, 0, nil)
	key := EndpointKey("https://any.test/v1")
	require.NoError(t, mp.Allow(key))
	mp.RecordCanceled(key)
	assert.Zero(t, mp.RetryAfter(key), "disabled map must never advertise a hint")
}

// TestCompat_TenantTableClampFallback pins the explicit clamp contract for
// unsupported table bounds: NewTenantMap with maxTenants <= 0 falls back to
// DefaultMaxTenants instead of building an unbounded or zero-capacity map —
// a misconfigured bound must degrade to the documented default, never to a
// silent misbehavior.
func TestCompat_TenantTableClampFallback(t *testing.T) {
	cfg := Config{Enabled: true, FailureThreshold: 3, OpenTimeout: time.Minute, Window: time.Minute}
	for _, tc := range []struct {
		name       string
		maxTenants int
	}{
		{"zero", 0},
		{"negative", -7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tm := NewTenantMap(cfg, tc.maxTenants, nil)
			assert.Equal(t, DefaultMaxTenants, tm.lru.max,
				"an unsupported bound must fall back to DefaultMaxTenants")
			// The fallback map is fully functional.
			require.NoError(t, tm.Allow("org", "https://x.test/v1"))
			tm.RecordSuccess("org", "https://x.test/v1")
			assert.Equal(t, StateClosed, tm.Breaker("org", "https://x.test/v1").State())
		})
	}
}
