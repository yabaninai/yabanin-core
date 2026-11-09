package consumer

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// ENT-04 (HA multi-replica): loggerd leader election.
//
// Leader is a Redis-backed leader election (distributed lock) so N loggerd
// replicas elect a single active node. The holder renews the lock on a
// heartbeat; if the holder dies the lock TTL expires and a follower acquires it
// (automatic failover). Renewal and release are fenced by the holder's replica
// id via an atomic Lua compare-and-set, so a slow or partitioned replica can
// never extend or delete another replica's lock (no split-brain double-write).
//
// The consumer group + msg:seen dedup remain as a safety net, but with a single
// elected leader the normal path has exactly one active consumer.

// LeaderRedis is the minimal Redis surface for leader election:
//   - SetNX: acquire the lock (SET key id NX PX ttl).
//   - Eval: atomic compare-and-renew / compare-and-release (Lua) for fencing.
type LeaderRedis interface {
	SetNX(ctx context.Context, key string, value any, expiration time.Duration) *redis.BoolCmd
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

// NewLeaderRedis wraps a *redis.Client for leader election.
func NewLeaderRedis(rdb *redis.Client) LeaderRedis { return &leaderRedisWrapper{rdb} }

type leaderRedisWrapper struct{ *redis.Client }

// renewScript extends the lock TTL only if we still own it. Returns 1 on
// success, 0 otherwise.
const renewScript = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0
`

// releaseScript deletes the lock only if we still own it. Returns 1 on success,
// 0 otherwise.
const releaseScript = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
`

// Leader holds one replica's claim on the leader lock.
type Leader struct {
	rdb LeaderRedis
	key string
	id  string
	ttl time.Duration
	log *slog.Logger

	mu   sync.Mutex
	held bool
}

// NewLeader builds a Leader. ttl is the lock TTL (the failover window); id is
// this replica's unique fencing id (a random one is generated when empty).
func NewLeader(rdb LeaderRedis, key, id string, ttl time.Duration, log *slog.Logger) *Leader {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if id == "" {
		id = randomLeaderID()
	}
	if log == nil {
		log = slog.Default()
	}
	return &Leader{rdb: rdb, key: key, id: id, ttl: ttl, log: log}
}

func randomLeaderID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("leader-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// TryAcquire attempts to become the leader. Returns true when this replica now
// holds the lock (a fresh or expired lock), false when another replica holds it.
func (l *Leader) TryAcquire(ctx context.Context) (bool, error) {
	ok, err := l.rdb.SetNX(ctx, l.key, l.id, l.ttl).Result()
	if err != nil {
		return false, fmt.Errorf("leader acquire: %w", err)
	}
	l.setHeld(ok)
	if ok {
		l.log.Info("acquired leader lock", "key", l.key, "id", l.id, "ttl", l.ttl.String())
	}
	return ok, nil
}

// Renew extends the lock TTL. Returns (true, nil) when this replica still holds
// the lock, (false, nil) when it lost it (expired / taken over), or (_, err) on
// a transient Redis failure (the prior held state is returned for the bool).
func (l *Leader) Renew(ctx context.Context) (bool, error) {
	res, err := l.rdb.Eval(ctx, renewScript, []string{l.key}, l.id, l.ttl.Milliseconds()).Result()
	if err != nil {
		return l.IsHeld(), fmt.Errorf("leader renew: %w", err)
	}
	still := evalInt(res) == 1
	l.setHeld(still)
	return still, nil
}

// Release relinquishes the lock (only effective when we own it — fenced). Safe
// to call even when not the leader.
func (l *Leader) Release(ctx context.Context) error {
	_, err := l.rdb.Eval(ctx, releaseScript, []string{l.key}, l.id).Result()
	l.setHeld(false)
	if err != nil {
		return fmt.Errorf("leader release: %w", err)
	}
	l.log.Info("released leader lock", "key", l.key, "id", l.id)
	return nil
}

// IsHeld reports whether this replica currently holds the lock (local state).
func (l *Leader) IsHeld() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held
}

func (l *Leader) setHeld(v bool) {
	l.mu.Lock()
	l.held = v
	l.mu.Unlock()
}

// Lead runs fn for as long as this replica is the leader. It acquires the lock,
// runs fn in a child context, and renews the lock on a heartbeat (ttl/3). On
// leadership loss (a clean "not owner" renew), an unexpected fn exit, or ctx
// completion it cancels fn's context and waits for fn to return. If ctx is not
// done it loops to re-acquire (taking over or standing by). It returns when
// ctx is done. fn is expected to block until its context is cancelled (e.g. the
// stream consumer's Start).
func (l *Leader) Lead(ctx context.Context, fn func(ctx context.Context) error) error {
	interval := l.ttl / 3
	if interval <= 0 {
		interval = time.Second
	}
	for {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // best-effort re-election loop; ctx governs exit
		}
		ok, err := l.TryAcquire(ctx)
		if err != nil {
			// Transient Redis failure: retry until ctx is done; returning
			// nil here is the documented Lead() contract (best-effort loop).
			l.log.Warn("leader acquire error, retrying", "error", err.Error())
			if !sleepCtx(ctx, interval) {
				return nil
			}
			continue
		}
		if !ok {
			// Another replica leads; stand by and retry.
			if !sleepCtx(ctx, interval) {
				return nil
			}
			continue
		}

		l.log.Info("promoted to leader, starting workload")
		leaderCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := fn(leaderCtx); err != nil {
				// A workload failure used to be discarded. Count and
				// log it so repeated crashes are visible before re-election.
				metrics.LeaderFnFailedTotal.Inc()
				l.log.Error("leader workload failed", "error", err.Error())
			}
		}()

		lost := false
		ticker := time.NewTicker(interval)
		for !lost {
			select {
			case <-ctx.Done():
				lost = true
			case <-done:
				l.log.Warn("leader workload exited; re-electing")
				lost = true
			case <-ticker.C:
				still, rerr := l.Renew(ctx)
				if rerr != nil {
					// Transient: keep leadership and retry next tick.
					l.log.Warn("leader renew error (keeping leadership)", "error", rerr.Error())
					continue
				}
				if !still {
					l.log.Warn("lost leadership")
					lost = true
				}
			}
		}
		ticker.Stop()
		cancel()
		<-done // wait for the workload (consumer) to stop before re-election

		if ctx.Err() != nil {
			// Shutdown: release cleanly (fenced no-op if already lost).
			if rerr := l.Release(context.Background()); rerr != nil { //nolint:contextcheck // request ctx already cancelled at shutdown; Release needs a live ctx
				l.log.Warn("leader release on shutdown failed", "error", rerr.Error())
			}
			return nil
		}
		// Leadership lost (or workload died): loop to re-acquire / stand by.
	}
}

// evalInt coerces a Lua EVAL result to an int64 count (0/1).
func evalInt(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		var i int64
		_, _ = fmt.Sscanf(n, "%d", &i)
		return i
	default:
		return 0
	}
}

// sleepCtx sleeps for d, returning false if ctx is done first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
