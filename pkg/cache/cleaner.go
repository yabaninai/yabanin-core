// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Cleaner runs periodic TTL expiration cleanup across both cache backends.
type Cleaner struct {
	cache    *CacheService
	interval time.Duration
	log      *slog.Logger
	cancel   context.CancelFunc
	mu       sync.Mutex
}

// NewCleaner creates a new TTL cleaner that runs every interval.
func NewCleaner(cache *CacheService, interval time.Duration, log *slog.Logger) *Cleaner {
	if interval == 0 {
		interval = 5 * time.Minute // plan: 5 min for timely TTL enforcement
	}
	return &Cleaner{
		cache:    cache,
		interval: interval,
		log:      log,
	}
}

// Start begins periodic cleanup. Returns a context that is cancelled when Stop() is called.
func (c *Cleaner) Start(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()

	go func() {
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.runCleanup(ctx)
			}
		}
	}()

	return ctx
}

// Stop terminates the cleanup goroutine.
func (c *Cleaner) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
}

func (c *Cleaner) runCleanup(ctx context.Context) {
	if c.cache == nil {
		return
	}

	RecordJanitorRun()

	redisCount, pgDeleted, gotLock, err := c.cache.PurgeAllWithLock(ctx)
	if err != nil {
		c.log.Error("cache cleanup failed", "error", err)
		RecordJanitorError()
		return
	}

	totalDeleted := redisCount + pgDeleted
	RecordJanitorDeleted(totalDeleted)
	c.log.Debug("cache cleanup completed", "redis_expired", redisCount, "pg_expired", pgDeleted, "total_deleted", totalDeleted, "lock_acquired", gotLock)
}

// PurgeNow runs a single cleanup immediately (for testing/admin).
func (c *Cleaner) PurgeNow(ctx context.Context) (int, int, error) {
	return c.cache.PurgeExpired(ctx)
}
