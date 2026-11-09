package cli

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
)

// sessionRedis is the Redis slice used by session mint limits and spend caps.
// A nil client skips the cap and logs a warning (same soft failure as TokenBudget).
type sessionRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Incr(ctx context.Context, key string) *redis.IntCmd
	IncrBy(ctx context.Context, key string, value int64) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

func (gw *gateway) sessionRedisClient() sessionRedis {
	if gw.sessionKV != nil {
		return gw.sessionKV
	}
	if gw.rdb == nil {
		return nil
	}
	return gw.rdb
}

// checkSessionBudget rejects a request that has already reached the session
// token or cost cap. Redis being down is a soft miss: the request proceeds
// and a warning is logged. The cap is not an authorization check.
func (gw *gateway) checkSessionBudget(w http.ResponseWriter, r *http.Request) bool {
	p, ok := principalFrom(r.Context())
	if !ok || p.SessionKeyID == "" || (p.SessionMaxTokens == nil && p.SessionMaxCostUSD == nil) {
		return true
	}
	kv := gw.sessionRedisClient()
	if kv == nil {
		gw.log.Warn("session budget skipped; redis unavailable", "session_key_id", p.SessionKeyID)
		return true
	}
	if p.SessionMaxTokens != nil {
		n, err := kv.Get(r.Context(), sessionTokenKey(p.SessionKeyID)).Int64()
		if err != nil && err != redis.Nil {
			gw.log.Warn("session budget read failed; redis unavailable", "error", err, "session_key_id", p.SessionKeyID)
			return true
		}
		if err == nil && n >= *p.SessionMaxTokens {
			writeSessionBudgetExceeded(w, r)
			return false
		}
	}
	if p.SessionMaxCostUSD != nil {
		n, err := kv.Get(r.Context(), sessionCostKey(p.SessionKeyID)).Int64()
		if err != nil && err != redis.Nil {
			gw.log.Warn("session budget read failed; redis unavailable", "error", err, "session_key_id", p.SessionKeyID)
			return true
		}
		if err == nil && float64(n) >= *p.SessionMaxCostUSD*1_000_000 {
			writeSessionBudgetExceeded(w, r)
			return false
		}
	}
	return true
}

func writeSessionBudgetExceeded(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("x-should-retry", "false")
	apierrors.Write(w, http.StatusTooManyRequests, "session_budget_exceeded",
		"session key budget exceeded")
	_ = r
}

// recordSessionSpend adds tokens and microdollars after a response. Unknown
// price adds 0 and sets X-Yabanin-Budget-Warning. Redis down is a soft miss.
func (gw *gateway) recordSessionSpend(ctx context.Context, w http.ResponseWriter, tokens int64, costUSD float64, priced bool) {
	p, ok := principalFrom(ctx)
	if !ok || p.SessionKeyID == "" || (p.SessionMaxTokens == nil && p.SessionMaxCostUSD == nil) {
		return
	}
	if !priced {
		noteBudgetWarning(w, "unpriced_requests")
		costUSD = 0
	}
	kv := gw.sessionRedisClient()
	if kv == nil {
		gw.log.Warn("session budget record skipped; redis unavailable", "session_key_id", p.SessionKeyID)
		return
	}
	ttl := time.Hour
	if !p.SessionExpiresAt.IsZero() {
		ttl = time.Until(p.SessionExpiresAt) + time.Hour
		if ttl < time.Hour {
			ttl = time.Hour
		}
	}
	if p.SessionMaxTokens != nil && tokens > 0 {
		if err := kv.IncrBy(ctx, sessionTokenKey(p.SessionKeyID), tokens).Err(); err != nil {
			gw.log.Warn("session token record failed", "error", err, "session_key_id", p.SessionKeyID)
		} else {
			_ = kv.Expire(ctx, sessionTokenKey(p.SessionKeyID), ttl).Err()
		}
	}
	if p.SessionMaxCostUSD != nil {
		micros := int64(costUSD * 1_000_000)
		if err := kv.IncrBy(ctx, sessionCostKey(p.SessionKeyID), micros).Err(); err != nil {
			gw.log.Warn("session cost record failed", "error", err, "session_key_id", p.SessionKeyID)
		} else {
			_ = kv.Expire(ctx, sessionCostKey(p.SessionKeyID), ttl).Err()
		}
	}
}

func eventKeyID(ctx context.Context) string {
	p, ok := principalFrom(ctx)
	if !ok {
		return ""
	}
	return p.APIKeyID
}

func eventSessionID(ctx context.Context) string {
	p, ok := principalFrom(ctx)
	if !ok {
		return ""
	}
	return p.SessionKeyID
}

func sessionTokenKey(id string) string { return "yb:skey:" + id + ":tok" }
func sessionCostKey(id string) string  { return "yb:skey:" + id + ":ucost" }

func noteBudgetWarning(w http.ResponseWriter, value string) {
	if w == nil {
		return
	}
	cur := w.Header().Get("X-Yabanin-Budget-Warning")
	if cur == "" {
		w.Header().Set("X-Yabanin-Budget-Warning", value)
		return
	}
	if strings.Contains(cur, value) {
		return
	}
	w.Header().Set("X-Yabanin-Budget-Warning", cur+"; "+value)
}
