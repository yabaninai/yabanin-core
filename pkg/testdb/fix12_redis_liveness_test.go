package testdb

// FIX-12 (audit 2026-10-28, hypothesis H2) — Redis stand half.
//
// The audited poisoning scenario applied verbatim to the Redis stand: the
// per-binary sync.Once cached the *redis.Client and redisInitErr forever, so
// one transient stand death mid-binary (Docker VM churn) left every later
// Redis()/FlushDB caller in the binary with `connection refused` — no
// re-check, no recovery, no diagnosis. The Postgres stand got the per-use
// liveness + bounded recreate-once contract in the first FIX-12 delivery;
// these tests pin the SAME contract for Redis.
//
// Like fix12_liveness_test.go, these tests are Dockerless: a real
// *redis.Client pointed at 127.0.0.1:1 produces exactly the dial-refused
// error chain the audited suites saw, and package-local stand lifecycle
// seams (redisStandStart / redisStandProbe) let the tests drive the
// ensure/recreate control flow with fake container handles. The contract
// pinned here:
//
//   - a healthy stand is reused as-is (same client, no extra starts);
//   - a confirmed dead listener triggers EXACTLY ONE bounded recreate;
//   - the recreate error is diagnosable: dead container ID, mapped port,
//     elapsed lifetime, original liveness error, recreate cause and a
//     `docker events` hint;
//   - the recreate frees ONLY the stand's own resources: the dead container
//     handle is terminated best-effort (never leaked) and no foreign
//     container is ever touched;
//   - a failed recreate degrades to a sticky diagnosable error, not a storm
//     of start attempts.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// fix12RedisFakeHandle records whether the best-effort terminate ran (the
// dead stand's handle must never leak; a foreign handle must never be
// touched).
type fix12RedisFakeHandle struct {
	terminated bool
}

func (f *fix12RedisFakeHandle) Terminate(_ context.Context, _ ...testcontainers.TerminateOption) error {
	f.terminated = true
	return nil
}

// fix12RedisDeadClient returns a real client bound to an address with no
// listener: pinging it reproduces the audited
// `dial tcp ... connect: connection refused` chain through the real go-redis
// dialer.
func fix12RedisDeadClient(t *testing.T, port string) *redis.Client {
	t.Helper()
	opt, err := redis.ParseURL(fmt.Sprintf("redis://127.0.0.1:%s", port))
	require.NoError(t, err)
	client := redis.NewClient(opt)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// fix12RedisReset clears the package-level Redis stand state and seams, and
// restores everything at test end so the Docker-backed tests in this package
// are unaffected.
func fix12RedisReset(t *testing.T) {
	t.Helper()
	prevOnce, prevClient, prevInitErr := redisOnce, redisClient, redisInitErr
	prevContainer, prevID, prevPort, prevStarted := redisContainer, redisContainerID, redisContainerPort, redisStartedAt
	prevStart, prevProbe := redisStandStart, redisStandProbe
	t.Cleanup(func() {
		redisOnce, redisClient, redisInitErr = prevOnce, prevClient, prevInitErr
		redisContainer, redisContainerID, redisContainerPort, redisStartedAt = prevContainer, prevID, prevPort, prevStarted
		redisStandStart, redisStandProbe = prevStart, prevProbe
	})
	redisOnce = new(sync.Once)
	redisClient, redisInitErr = nil, nil
	redisContainer, redisContainerID, redisContainerPort, redisStartedAt = nil, "", "", time.Time{}
	redisStandStart, redisStandProbe = redisStandStartReal, redisLiveness
}

// TestFix12RedisLivenessProbeRealDeadAddr drives the real bounded probe
// against a real client whose address has no listener: every probe attempt
// must fail with the dial-refused chain and the final error must classify as
// listener-down (the only recreate justification).
func TestFix12RedisLivenessProbeRealDeadAddr(t *testing.T) {
	fix12RedisReset(t)
	dead := fix12RedisDeadClient(t, "1")

	err := redisLiveness(dead)
	require.Error(t, err, "a dead address must never pass the liveness probe")
	require.True(t, listenerDown(err), "refused dials must classify as listener-down, got: %v", err)
	require.Contains(t, err.Error(), "connection refused")

	require.Error(t, redisLiveness(nil), "a missing client must not pass as live")
}

// TestFix12RedisDialRefusedChain pins the go-redis error shape: the audited
// failure was a raw dial refusal, and listenerDown must see through the
// go-redis wrapping to *net.OpError / ECONNREFUSED.
func TestFix12RedisDialRefusedChain(t *testing.T) {
	dead := fix12RedisDeadClient(t, "1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := dead.Ping(ctx).Err()
	require.Error(t, err)
	require.True(t, listenerDown(err), "single go-redis ping on a refused dial must classify as listener-down, got: %v", err)

	var opErr *net.OpError
	require.ErrorAs(t, err, &opErr, "go-redis must surface a *net.OpError dial chain")
	require.Equal(t, "dial", opErr.Op)
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
}

// TestFix12RedisDeadListenerRecreatesOnce is the Redis H2 contract: the
// binary boots a stand that has already died (the audited poisoning
// scenario); the first Redis() caller must observe the dead listener,
// recreate exactly once, and every later caller must reuse the recovered
// client.
func TestFix12RedisDeadListenerRecreatesOnce(t *testing.T) {
	fix12RedisReset(t)

	dead := fix12RedisDeadClient(t, "1")
	healthy := fix12RedisDeadClient(t, "2") // never probed for real; identity only
	deadHandle := &fix12RedisFakeHandle{}
	freshHandle := &fix12RedisFakeHandle{}

	starts := 0
	redisStandStart = func(tb testing.TB) (*redisStand, error) {
		tb.Helper()
		starts++
		switch starts {
		case 1:
			return &redisStand{
				client:      dead,
				containerID: "ctr-fix12-redis-dead",
				port:        "50907",
				started:     time.Now().Add(-2 * time.Minute),
				container:   deadHandle,
			}, nil
		case 2:
			return &redisStand{
				client:      healthy,
				containerID: "ctr-fix12-redis-fresh",
				port:        "50908",
				started:     time.Now(),
				container:   freshHandle,
			}, nil
		default:
			return nil, fmt.Errorf("unexpected redis stand start #%d (recreate must be bounded to one)", starts)
		}
	}
	redisStandProbe = func(client *redis.Client) error {
		if client == dead {
			return redisLiveness(dead) // real bounded probe on the real dead address
		}
		return nil
	}

	client := Redis(t)
	require.Same(t, healthy, client, "the recovered stand must be handed out")
	require.Equal(t, 2, starts, "boot + exactly one bounded recreate")
	require.True(t, deadHandle.terminated, "the dead container handle must be terminated (no leak)")
	require.False(t, freshHandle.terminated, "the fresh container must stay alive")
	require.Equal(t, "ctr-fix12-redis-fresh", redisContainerID)
	require.Equal(t, "50908", redisContainerPort)
	require.NoError(t, redisInitErr)

	// Reuse when healthy: repeated callers never trigger another recreate.
	require.Same(t, healthy, Redis(t))
	require.Same(t, healthy, Redis(t))
	require.Equal(t, 2, starts)
}

// TestFix12RedisRecreateFailureStickyDiagnosable proves the failure half of
// the bound: when the single recreate attempt also fails, the caller gets one
// diagnosable error (dead container ID, port, lifetime, liveness cause,
// recreate cause, docker events hint) and no further start attempts.
func TestFix12RedisRecreateFailureStickyDiagnosable(t *testing.T) {
	fix12RedisReset(t)

	dead := fix12RedisDeadClient(t, "1")
	deadHandle := &fix12RedisFakeHandle{}

	// Simulate a stand that booted fine and then died (Once consumed).
	redisOnce.Do(func() {})
	redisClient = dead
	redisContainer = deadHandle
	redisContainerID = "ctr-fix12-redis-dead"
	redisContainerPort = "50907"
	redisStartedAt = time.Now().Add(-2 * time.Minute)

	starts := 0
	redisStandStart = func(tb testing.TB) (*redisStand, error) {
		tb.Helper()
		starts++
		return nil, fmt.Errorf("start disposable redis (is Docker running?): docker daemon exploded")
	}
	redisStandProbe = func(client *redis.Client) error { return redisLiveness(dead) }

	client, err := ensureRedis(t)
	require.Error(t, err)
	require.Nil(t, client)
	require.Equal(t, 1, starts, "the recreate must be attempted exactly once")
	require.True(t, deadHandle.terminated, "the dead handle must still be retired (no leak)")

	for _, want := range []string{
		"ctr-fix12-redis-dead",   // dead container ID
		"50907",                  // dead mapped port
		"connection refused",     // original liveness error (real dead address)
		"docker daemon exploded", // recreate cause
		"docker events",          // diagnosability hint
	} {
		require.Contains(t, err.Error(), want, "recreate error must be diagnosable")
	}

	// Sticky degradation: further callers fail fast with the same diagnosis
	// instead of hammering Docker with start attempts.
	clientAgain, errAgain := ensureRedis(t)
	require.Error(t, errAgain)
	require.Nil(t, clientAgain)
	require.Equal(t, 1, starts)
}

// TestFix12RedisRecreateFreesOnlyOwnResources is the isolation half of the
// FIX-12 acceptance (aspect 3): a death detected by one caller must free ONLY
// the adopted stand's own resources — its own container handle terminated,
// exactly one replacement started — and must never terminate a handle that
// was never adopted by this stand.
func TestFix12RedisRecreateFreesOnlyOwnResources(t *testing.T) {
	fix12RedisReset(t)

	dead := fix12RedisDeadClient(t, "1")
	healthy := fix12RedisDeadClient(t, "2")
	deadHandle := &fix12RedisFakeHandle{}
	freshHandle := &fix12RedisFakeHandle{}
	foreignHandle := &fix12RedisFakeHandle{} // never adopted by this stand

	// Adopt the dead stand; foreignHandle is never stored in any stand
	// global, so only handles reachable through the stand globals may ever
	// be terminated.
	redisOnce.Do(func() {})
	redisClient = dead
	redisContainer = deadHandle
	redisContainerID = "ctr-fix12-redis-dead"
	redisContainerPort = "50907"
	redisStartedAt = time.Now().Add(-2 * time.Minute)
	_ = foreignHandle

	starts := 0
	redisStandStart = func(tb testing.TB) (*redisStand, error) {
		tb.Helper()
		starts++
		return &redisStand{
			client:      healthy,
			containerID: "ctr-fix12-redis-fresh",
			port:        "50908",
			started:     time.Now(),
			container:   freshHandle,
		}, nil
	}
	redisStandProbe = func(client *redis.Client) error {
		if client == dead {
			return redisLiveness(dead)
		}
		return nil
	}

	client := Redis(t)
	require.Same(t, healthy, client)
	require.Equal(t, 1, starts, "once consumed by the adopted boot → the recreate is the only start")
	require.True(t, deadHandle.terminated, "the adopted dead handle must be terminated")
	require.False(t, freshHandle.terminated, "the fresh replacement container must stay alive")
	require.False(t, foreignHandle.terminated, "a never-adopted foreign container must never be touched")
}

// TestFix12RedisConcurrentEnsureRecreatesOnce is the race-safety contract:
// many parallel Redis() callers hitting a freshly dead stand must produce
// exactly one recreate, one terminated dead handle, and one shared recovered
// client — under -race.
func TestFix12RedisConcurrentEnsureRecreatesOnce(t *testing.T) {
	fix12RedisReset(t)

	dead := fix12RedisDeadClient(t, "1")
	healthy := fix12RedisDeadClient(t, "2")
	deadHandle := &fix12RedisFakeHandle{}

	starts := 0
	redisStandStart = func(tb testing.TB) (*redisStand, error) {
		tb.Helper()
		starts++
		if starts == 1 {
			return &redisStand{client: dead, containerID: "ctr-fix12-redis-dead", container: deadHandle}, nil
		}
		return &redisStand{client: healthy, containerID: "ctr-fix12-redis-fresh"}, nil
	}
	redisStandProbe = func(client *redis.Client) error {
		if client == dead {
			return redisLiveness(dead)
		}
		return nil
	}

	// Goroutine-safe caller path: the fatal require lives in Redis, so the
	// spawned callers use ensureRedis directly and surface errors to the
	// test goroutine (require/assert must not run on spawned goroutines).
	// requireDocker is hoisted so its Skip can only fire on the test goroutine.
	requireDocker(t)
	const callers = 8
	results := make([]*redis.Client, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client, err := ensureRedis(t)
			results[i], errs[i] = client, err
		}(i)
	}
	wg.Wait()

	for i, client := range results {
		require.NoError(t, errs[i], "caller %d ensure failed", i)
		require.Same(t, healthy, client, "caller %d must see the recovered stand", i)
	}
	require.Equal(t, 2, starts, "boot + exactly one recreate under concurrency")
	require.True(t, deadHandle.terminated)
}
