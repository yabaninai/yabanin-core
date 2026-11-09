package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
)

// ---------------------------------------------------------------------------
// the gateway data plane behind YABANIN_KEY_RATE_LIMITS (default OFF — with
// the flag unset gw.rateLimits stays nil and the middleware is not mounted,
// so behavior is byte-for-byte identical to before).
//
// Design:
//   - Limits come from adminstore (migration 0027, admin CRUD) — every
//     enabled row matching the request's key/team/org is enforced against its
//     own Redis window; the strictest remaining value binds and labels the
//     headers.
//   - Redis holds the window state (sliding window per dimension, one Lua
//     EVAL per request), so every replica pointed at the same Redis enforces
//     one shared limit. Time comes from the Redis server (TIME) so skewed
//     replica clocks agree.
//   - TPM reserves the INPUT estimate (body bytes/4, the same estimator the
//     completions endpoint uses for its fallback usage) before the upstream
//     call and is corrected to the actual usage after the response
//     (reconcileRateLimitTokens), so a stream counts by fact, not estimate.
//   - A denied request records nothing: with concurrent requests racing on
//     the limit, exactly the first N admissions pass.
//   - Redis (or limits-source) unavailability fails OPEN per OD-07: the
//     request proceeds, the fallback counter increments and a WARN is
//     throttled to one per warnEvery. Metrics never carry raw key
//     identifiers in labels (only the dimension "rpm"/"tpm").
// ---------------------------------------------------------------------------

// rateLimitsWindow is the fixed sliding-window span for both dimensions:
// RPM and TPM are per-minute limits.
const rateLimitsWindow = time.Minute

// keyRateLimitsFlagEnabled reports whether the card's feature flag is set.
// at wiring time and defaults to off.
func keyRateLimitsFlagEnabled() bool {
	return config.KeyRateLimitsEnabled()
}

// keyRateLimitFallbackTotal counts enforcement decisions taken without Redis
// or without limits data (OD-07 fail-open path). A rising value means the
// shared limit was not enforced: until the dependency returns, requests are
// admitted without accounting.
var keyRateLimitFallbackTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gateway_key_ratelimit_fallback_total",
	Help: "Key rate-limit decisions taken without Redis or limits data (fail-open, IMP-80).",
})

// keyRateLimitDeniedTotal counts client-visible 429s by the binding
// dimension ("rpm"/"tpm"). Labels never contain key, team or org ids.
var keyRateLimitDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateway_key_ratelimit_denied_total",
	Help: "Requests denied by key rate limits, by binding dimension (no identifiers in labels).",
}, []string{"dimension"})

// rateLimitScripter is the subset of the Redis client the limiter needs.
// *redis.Client satisfies it; unit tests substitute a fake.
type rateLimitScripter interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

// rateLimitsSource provides the per-scope limits for an identity triple.
// *adminstore.Store implements it; unit tests substitute a stub.
type rateLimitsSource interface {
	EffectiveKeyRateLimits(ctx context.Context, apiKeyID, teamID, orgID string) ([]adminstore.KeyRateScopeLimits, error)
}

// rateLimitScopeRef is one identity dimension to enforce for a request with
// adds the split input/output token windows (itpm/otpm): input is reserved
// from the request estimate, output is credited post-fact by the reconcile.
type rateLimitScopeRef struct {
	scope string
	id    string
	rpm   int64
	tpm   int64
	itpm  int64
	otpm  int64
}

func (r rateLimitScopeRef) rpmZSet() string  { return "gwrl:rpm:" + r.scope + ":" + r.id }
func (r rateLimitScopeRef) tpmZSet() string  { return "gwrl:tpm:" + r.scope + ":" + r.id }
func (r rateLimitScopeRef) tpmHash() string  { return "gwrl:tpmw:" + r.scope + ":" + r.id }
func (r rateLimitScopeRef) itpmZSet() string { return "gwrl:itpm:" + r.scope + ":" + r.id }
func (r rateLimitScopeRef) itpmHash() string { return "gwrl:itpmw:" + r.scope + ":" + r.id }
func (r rateLimitScopeRef) otpmZSet() string { return "gwrl:otpm:" + r.scope + ":" + r.id }
func (r rateLimitScopeRef) otpmHash() string { return "gwrl:otpmw:" + r.scope + ":" + r.id }

// tokenWindows renders the zset+hash pair of every token window this scope
// can carry, in the reconcile script's KEYS order (tpm, itpm, otpm). Windows
// whose dimension is off are never populated, so the reconcile's ZSCORE guard
// skips them.
func (r rateLimitScopeRef) tokenWindows() []string {
	return []string{r.tpmZSet(), r.tpmHash(), r.itpmZSet(), r.itpmHash(), r.otpmZSet(), r.otpmHash()}
}

// rateLimitsCacheEntry is a resolved identity triple with its fetch time.
type rateLimitsCacheEntry struct {
	limits  []adminstore.KeyRateScopeLimits
	expires time.Time
}

// keyRateLimiter enforces the per-key/team/org RPM+TPM windows. The limits
// resolver is cached for a short TTL (admin changes propagate within that
// bound); Redis holds the window state. W-CAPS adds the org-caps enforcer
// (caps field, nil when YABANIN_ORG_CAPS is off): its windows ride the same
// atomic admit script and the same reconcile reservation as the admin-set
// scopes, but fail CLOSED in enforce mode.
type keyRateLimiter struct {
	rdb    rateLimitScripter
	source rateLimitsSource
	log    *slog.Logger

	// caps is the org-level beta-caps layer (nil = off). It is built from
	// the same Redis handle and adminstore source as the key-level limiter.
	caps *orgCapsEnforcer

	// callTimeout bounds each Redis round-trip so a slow (not only down)
	// Redis cannot stall inference requests.
	callTimeout time.Duration
	// warnEvery throttles the fail-open WARN (no log spam).
	warnEvery time.Duration
	lastWarn  atomic.Int64
	// memberSeq makes window members unique per process; combined with the
	// nanosecond timestamp, cross-process collisions are negligible.
	memberSeq atomic.Uint64

	// mu guards the limits cache; entries expire after cacheTTL and a
	// refill sweeps expired triples, so the map holds at most one window's
	// worth of live identities.
	mu       sync.Mutex
	cache    map[string]rateLimitsCacheEntry
	cacheTTL time.Duration
	// lazily built — the limiter works without a priority source).
	priorities map[string]priorityCacheEntry
}

// newKeyRateLimiter wires the limiter. A nil logger falls back to
// slog.Default().
func newKeyRateLimiter(rdb rateLimitScripter, source rateLimitsSource, logger *slog.Logger) *keyRateLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	return &keyRateLimiter{
		rdb:         rdb,
		source:      source,
		log:         logger,
		callTimeout: 500 * time.Millisecond,
		warnEvery:   30 * time.Second,
		cache:       map[string]rateLimitsCacheEntry{},
		cacheTTL:    5 * time.Second,
	}
}

// window and admits the request only when all of them have capacity; a denied
// request records nothing, so exactly N concurrent requests pass an N limit.
// A window is touched only when its limit > 0 (an off dimension never has
// members to clean).
//
//	KEYS    — per scope i (0-based): [rpm zset, tpm zset, tpm weights hash,
//	          itpm zset, itpm weights hash, otpm zset, otpm weights hash]
//	ARGV[1] — number of scopes
//	ARGV[2] — window in milliseconds
//	ARGV[3] — unique member for this request
//	ARGV[4] — input-token estimate for this request
//	ARGV[5+4i]..ARGV[8+4i] — scope i's rpm / tpm / itpm / otpm limit
//
// TPM/ITPM reserve the input estimate before the upstream call; OTPM cannot
// know its output upfront, so it admits against the ACCUMULATED output of
// completed requests and records the member with weight 0 for the reconcile
// to credit the actual completion tokens (post-fact accounting — one
// in-flight request can overshoot its own window; documented semantic).
//
// Returns {allowed, rpmRemaining, rpmLimit, rpmResetMs, tpmRemaining,
// tpmLimit, tpmResetMs, retryMs, dimension} where the remaining/reset values
// describe the strictest window (the binding limit; -1 remaining / 0 limit
// when a dimension has no limits at all) and dimension names the binding
// dimension on a denial (” when allowed).
var admitScript = `
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local n = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local member = ARGV[3]
local est = tonumber(ARGV[4])

local minRpmRem, minRpmLimit, minRpmReset = nil, nil, nil
local minTpmRem, minTpmLimit, minTpmReset = nil, nil, nil
local denyDimension, denyRetryMs = nil, 0

for i = 1, n do
	local rpmLimit = tonumber(ARGV[5 + 4 * (i - 1)])
	local tpmLimit = tonumber(ARGV[6 + 4 * (i - 1)])
	local itpmLimit = tonumber(ARGV[7 + 4 * (i - 1)])
	local otpmLimit = tonumber(ARGV[8 + 4 * (i - 1)])
	local base = 7 * (i - 1)
	local rpmZ, tpmZ, tpmH = KEYS[base + 1], KEYS[base + 2], KEYS[base + 3]
	local itpmZ, itpmH, otpmZ, otpmH = KEYS[base + 4], KEYS[base + 5], KEYS[base + 6], KEYS[base + 7]

	local rpmReset = 0
	if rpmLimit > 0 then
		redis.call('ZREMRANGEBYSCORE', rpmZ, '-inf', now - window)
		local oldest = redis.call('ZRANGE', rpmZ, 0, 0, 'WITHSCORES')
		if #oldest > 1 then
			rpmReset = math.max(0, tonumber(oldest[2]) + window - now)
		end
		local count = redis.call('ZCARD', rpmZ)
		local rem = rpmLimit - count - 1
		if rem < 0 and denyDimension == nil then
			denyDimension = 'rpm'
			denyRetryMs = rpmReset
		end
		if minRpmRem == nil or rem < minRpmRem then
			minRpmRem, minRpmLimit, minRpmReset = rem, rpmLimit, rpmReset
		end
	end

	-- token windows share the same expire-and-weight shape; otpm checks the
	-- accumulated output only (the in-flight request's output is unknown).
	local tokenReset = {}
	local tokenLimits = {tpmLimit, itpmLimit, otpmLimit}
	local tokenZ = {tpmZ, itpmZ, otpmZ}
	local tokenH = {tpmH, itpmH, otpmH}
	local tokenNames = {'tpm', 'itpm', 'otpm'}
	for d = 1, 3 do
		local reset = 0
		if tokenLimits[d] > 0 then
			local expired = redis.call('ZRANGEBYSCORE', tokenZ[d], '-inf', now - window)
			for _, m in ipairs(expired) do
				redis.call('ZREM', tokenZ[d], m)
				redis.call('HDEL', tokenH[d], m)
			end
			local oldest = redis.call('ZRANGE', tokenZ[d], 0, 0, 'WITHSCORES')
			if #oldest > 1 then
				reset = math.max(0, tonumber(oldest[2]) + window - now)
			end
		end
		tokenReset[d] = reset
	end

	if tpmLimit > 0 then
		local sum = 0
		local weights = redis.call('HVALS', tpmH)
		for _, w in ipairs(weights) do
			sum = sum + tonumber(w)
		end
		local rem = tpmLimit - (sum + est)
		if rem < 0 and denyDimension == nil then
			denyDimension = 'tpm'
			denyRetryMs = tokenReset[1]
		end
		if minTpmRem == nil or rem < minTpmRem then
			minTpmRem, minTpmLimit, minTpmReset = rem, tpmLimit, tokenReset[1]
		end
	end

	if itpmLimit > 0 then
		local sum = 0
		local weights = redis.call('HVALS', itpmH)
		for _, w in ipairs(weights) do
			sum = sum + tonumber(w)
		end
		local rem = itpmLimit - (sum + est)
		if rem < 0 and denyDimension == nil then
			denyDimension = 'itpm'
			denyRetryMs = tokenReset[2]
		end
	end

	if otpmLimit > 0 then
		local sum = 0
		local weights = redis.call('HVALS', otpmH)
		for _, w in ipairs(weights) do
			sum = sum + tonumber(w)
		end
		local rem = otpmLimit - sum
		if rem < 0 and denyDimension == nil then
			denyDimension = 'otpm'
			denyRetryMs = tokenReset[3]
		end
	end
end

if denyDimension ~= nil then
	return {0,
		minRpmRem or -1, minRpmLimit or 0, minRpmReset or 0,
		minTpmRem or -1, minTpmLimit or 0, minTpmReset or 0,
		denyRetryMs, denyDimension}
end

for i = 1, n do
	local rpmLimit = tonumber(ARGV[5 + 4 * (i - 1)])
	local tpmLimit = tonumber(ARGV[6 + 4 * (i - 1)])
	local itpmLimit = tonumber(ARGV[7 + 4 * (i - 1)])
	local otpmLimit = tonumber(ARGV[8 + 4 * (i - 1)])
	local base = 7 * (i - 1)
	if rpmLimit > 0 then
		redis.call('ZADD', KEYS[base + 1], now, member)
		redis.call('PEXPIRE', KEYS[base + 1], window)
	end
	if tpmLimit > 0 and est > 0 then
		redis.call('ZADD', KEYS[base + 2], now, member)
		redis.call('HSET', KEYS[base + 3], member, est)
		redis.call('PEXPIRE', KEYS[base + 2], window)
		redis.call('PEXPIRE', KEYS[base + 3], window)
	end
	if itpmLimit > 0 and est > 0 then
		redis.call('ZADD', KEYS[base + 4], now, member)
		redis.call('HSET', KEYS[base + 5], member, est)
		redis.call('PEXPIRE', KEYS[base + 4], window)
		redis.call('PEXPIRE', KEYS[base + 5], window)
	end
	if otpmLimit > 0 then
		-- weight 0: the output is credited by the reconcile after the
		-- response (the member must exist for the correction to find).
		redis.call('ZADD', KEYS[base + 6], now, member)
		redis.call('HSET', KEYS[base + 7], member, 0)
		redis.call('PEXPIRE', KEYS[base + 6], window)
		redis.call('PEXPIRE', KEYS[base + 7], window)
	end
end

return {1,
	minRpmRem or -1, minRpmLimit or 0, minRpmReset or 0,
	minTpmRem or -1, minTpmLimit or 0, minTpmReset or 0,
	0, ''}
`

// reconcileScript replaces a request's reserved input estimate with the
// prompt/completion split — the aggregate TPM window holds the total, the
// ITPM window the prompt tokens, and the OTPM window (reserved with weight 0)
// the completion tokens. Scope windows whose entry already slid out are left
// alone — re-adding a weight for an expired window would leak an orphan hash
// field its cleanup can never see.
//
//	KEYS    — per scope i (0-based): [tpm zset, tpm hash, itpm zset, itpm
//	          hash, otpm zset, otpm hash] (off dimensions are empty → skipped)
//	ARGV[1] — unique member of the request being corrected
//	ARGV[2] — actual total tokens (prompt + completion)
//	ARGV[3] — actual prompt tokens
//	ARGV[4] — actual completion tokens
//	ARGV[5] — number of scopes
var reconcileScript = `
local member = ARGV[1]
local total = tonumber(ARGV[2])
local prompt = tonumber(ARGV[3])
local completion = tonumber(ARGV[4])
local n = tonumber(ARGV[5])
for i = 1, n do
	local b = 6 * (i - 1)
	if redis.call('ZSCORE', KEYS[b + 1], member) then
		redis.call('HSET', KEYS[b + 2], member, total)
	end
	if redis.call('ZSCORE', KEYS[b + 3], member) then
		redis.call('HSET', KEYS[b + 4], member, prompt)
	end
	if redis.call('ZSCORE', KEYS[b + 5], member) then
		redis.call('HSET', KEYS[b + 6], member, completion)
	end
end
return 1
`

// shadowCapsScript is the SHADOW-mode counterpart of the caps windows (
// it also fixes the W-CAPS gap where caps rpm/tpm windows denied for real in
// shadow mode). It runs over the caps scopes ONLY — key-level limits stay
// enforce-always on the main admit — measures what WOULD have been denied,
// and records every request so the shadow windows accumulate the org's real
// traffic (the deny answer would keep the window pinned at the limit and
// blind the shadow report to the actual request pattern).
//
//	KEYS/ARGV — same layout as admitScript. Returns the would-deny dimension
//	('' = none); every limit>0 window still records the member.
var shadowCapsScript = `
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local n = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local member = ARGV[3]
local est = tonumber(ARGV[4])

local denyDimension = ''

for i = 1, n do
	local rpmLimit = tonumber(ARGV[5 + 4 * (i - 1)])
	local tpmLimit = tonumber(ARGV[6 + 4 * (i - 1)])
	local itpmLimit = tonumber(ARGV[7 + 4 * (i - 1)])
	local otpmLimit = tonumber(ARGV[8 + 4 * (i - 1)])
	local base = 7 * (i - 1)
	local rpmZ, tpmZ, tpmH = KEYS[base + 1], KEYS[base + 2], KEYS[base + 3]
	local itpmZ, itpmH, otpmZ, otpmH = KEYS[base + 4], KEYS[base + 5], KEYS[base + 6], KEYS[base + 7]

	if rpmLimit > 0 then
		redis.call('ZREMRANGEBYSCORE', rpmZ, '-inf', now - window)
		local count = redis.call('ZCARD', rpmZ)
		if count + 1 > rpmLimit and denyDimension == '' then
			denyDimension = 'rpm'
		end
		redis.call('ZADD', rpmZ, now, member)
		redis.call('PEXPIRE', rpmZ, window)
	end

	local tokenLimits = {tpmLimit, itpmLimit, otpmLimit}
	local tokenZ = {tpmZ, itpmZ, otpmZ}
	local tokenH = {tpmH, itpmH, otpmH}
	local tokenNames = {'tpm', 'itpm', 'otpm'}
	for d = 1, 3 do
		if tokenLimits[d] > 0 then
			local expired = redis.call('ZRANGEBYSCORE', tokenZ[d], '-inf', now - window)
			for _, m in ipairs(expired) do
				redis.call('ZREM', tokenZ[d], m)
				redis.call('HDEL', tokenH[d], m)
			end
			local sum = 0
			local weights = redis.call('HVALS', tokenH[d])
			for _, w in ipairs(weights) do
				sum = sum + tonumber(w)
			end
			-- otpm measures ACCUMULATED output only: the in-flight request's
			-- output is unknown, so its estimate never enters the check.
			local check = sum
			if d < 3 then
				check = sum + est
			end
			if check > tokenLimits[d] and denyDimension == '' then
				denyDimension = tokenNames[d]
			end
			if d == 3 then
				-- otpm reserves 0: the output is unknown pre-flight and is
				-- credited by the reconcile after the response.
				redis.call('ZADD', tokenZ[d], now, member)
				redis.call('HSET', tokenH[d], member, 0)
			elseif est > 0 then
				redis.call('ZADD', tokenZ[d], now, member)
				redis.call('HSET', tokenH[d], member, est)
			end
			redis.call('PEXPIRE', tokenZ[d], window)
			redis.call('PEXPIRE', tokenH[d], window)
		end
	end
end

return denyDimension
`

// limitsFor resolves the applicable per-scope limits for an identity triple,
// behind a short TTL cache. Resolution errors fail open (the request is
// admitted without accounting, the fallback metric counts) — the limiter
// never turns a configuration-data outage into a data-plane outage.
func (rl *keyRateLimiter) limitsFor(ctx context.Context, apiKeyID, teamID, orgID string) []adminstore.KeyRateScopeLimits {
	cacheKey := apiKeyID + "\x00" + teamID + "\x00" + orgID
	now := time.Now()

	rl.mu.Lock()
	entry, ok := rl.cache[cacheKey]
	rl.mu.Unlock()
	if ok && now.Before(entry.expires) {
		return entry.limits
	}

	limits, err := rl.source.EffectiveKeyRateLimits(ctx, apiKeyID, teamID, orgID)
	if err != nil {
		rl.failOpen(err)
		limits = nil
	}

	rl.mu.Lock()
	for k, e := range rl.cache {
		if !now.Before(e.expires) {
			delete(rl.cache, k)
		}
	}
	rl.cache[cacheKey] = rateLimitsCacheEntry{limits: limits, expires: now.Add(rl.cacheTTL)}
	rl.mu.Unlock()
	return limits
}

// planScopes turns the resolved limits into the ordered scope refs (key,
// team, org — first-presented wins on the hypothetical duplicate) plus the
// per-dimension on flags (a dimension is on when ANY scope sets it). Admin
func planScopes(limits []adminstore.KeyRateScopeLimits, keyID, teamID, orgID string) (scopes []rateLimitScopeRef, rpmOn, tpmOn, itpmOn, otpmOn bool) {
	byScope := make(map[string]adminstore.KeyRateScopeLimits, len(limits))
	for _, l := range limits {
		if _, dup := byScope[l.Scope]; !dup {
			byScope[l.Scope] = l
		}
	}
	for _, ref := range []struct {
		scope, id string
	}{
		{adminstore.RateLimitScopeKey, keyID},
		{adminstore.RateLimitScopeTeam, teamID},
		{adminstore.RateLimitScopeOrg, orgID},
	} {
		if ref.id == "" {
			continue
		}
		l, ok := byScope[ref.scope]
		if !ok {
			continue
		}
		s := rateLimitScopeRef{scope: ref.scope, id: ref.id}
		if l.RPM != nil && *l.RPM > 0 {
			s.rpm = *l.RPM
			rpmOn = true
		}
		if l.TPM != nil && *l.TPM > 0 {
			s.tpm = *l.TPM
			tpmOn = true
		}
		scopes = append(scopes, s)
	}
	return scopes, rpmOn, tpmOn, itpmOn, otpmOn
}

// admitDecision carries the strictest-window state for the response headers
// and the reconcile reservation.
type admitDecision struct {
	allowed   bool
	member    string
	rpmRem    int64 // remaining requests after admission; -1 when no rpm limits
	rpmLimit  int64
	rpmReset  time.Duration
	tpmRem    int64 // remaining tokens after admission; -1 when no tpm limits
	tpmLimit  int64
	tpmReset  time.Duration
	retryMs   int64
	dimension string
}

// middleware admits or denies one inference request by its key/team/org
// limits, writes the OpenAI-style rate-limit headers, and — when a token
// window applies — attaches the usage reconciler for the post-response
// correction.
//
// W-CAPS ordering: the org-caps budget is answered first (402 budget_
// exceeded), then one atomic window check covers key-level → org-level (the
// first scope that denies names the dimension), and any caps dependency
// failure fails CLOSED in enforce mode (503) while the legacy key-limit
// path keeps its OD-07 fail-open.
//
//   - the caps scope carries the split ITPM/OTPM windows and a per-key TPM
//     cap scope ("orgcapskey:<key>") when the org set one;
//   - SHADOW mode never denies on caps windows: the caps scopes run through
//     shadowCapsScript (measure + account), only key-level scopes ride the
//     enforcing admit (fixes the W-CAPS gap where caps windows denied for
//     real in shadow mode);
//   - on a 429 the Retry-After hint scales with the API key's fair-share
//     priority: higher-priority keys poll sooner and win freed capacity
//     first (reject-policy ordering — NOT a preemptive scheduler; there is
//     no admission queue and a full window still denies the request).
func (rl *keyRateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyID := r.Header.Get("X-API-Key-Id")
		teamID := r.Header.Get("X-Team-Id")
		orgID := r.Header.Get("X-Org-Id")
		if keyID == "" && teamID == "" && orgID == "" {
			// No data-plane identity (static-key auth modes): nothing to
			// key the windows on — the per-IP limiter stays responsible.
			next.ServeHTTP(w, r)
			return
		}

		// W-CAPS: resolve the org's effective caps and answer the hard
		// monthly budget before the windows (an over-budget org hears 402,
		// not a rate-limit retry that could never succeed).
		var capsScopes []rateLimitScopeRef
		if rl.caps != nil && orgID != "" {
			caps, deny := rl.caps.precheck(w, r, orgID)
			if deny {
				return
			}
			if caps != nil {
				// nil caps = a shadow-mode pass-through after a dependency
				// failure: no windows were resolved, nothing to observe.
				capsScopes = append(capsScopes, capsScopeRef(caps, orgID))
				if keyID != "" {
					if keyRef := keyCapsScopeRef(caps, keyID); keyRef.tpm > 0 {
						capsScopes = append(capsScopes, keyRef)
					}
				}
			}
		}

		limits := rl.limitsFor(r.Context(), keyID, teamID, orgID)
		scopes, rpmOn, tpmOn, itpmOn, otpmOn := planScopes(limits, keyID, teamID, orgID)
		var capsRPMOn, capsTokenOn bool
		for _, cs := range capsScopes {
			if cs.rpm > 0 {
				capsRPMOn = true
			}
			if cs.tpm > 0 || cs.itpm > 0 || cs.otpm > 0 {
				capsTokenOn = true
			}
		}
		if !rpmOn && !tpmOn && !itpmOn && !otpmOn && !capsRPMOn && !capsTokenOn {
			next.ServeHTTP(w, r)
			return
		}

		// Token windows reserve the input estimate before the request: the
		// body is buffered once here and re-armed for the handler unchanged.
		// OTPM alone also needs the (possibly zero) estimate — its windows
		// are credited post-fact.
		anyToken := tpmOn || itpmOn || otpmOn || capsTokenOn
		var est int64
		if anyToken {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
					"request body too large or malformed")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			est = estimateRequestTokens(len(body))
		}

		// Enforce mode: caps scopes ride the same atomic admit as the
		// key-level scopes. Shadow mode: the admit covers the key-level
		// scopes only — the caps windows are measured (and accounted) by
		// the shadow script below and NEVER deny.
		enforceCaps := rl.caps == nil || rl.caps.enforce()
		admitScopes := scopes
		if len(capsScopes) > 0 && enforceCaps {
			admitScopes = append(append([]rateLimitScopeRef{}, scopes...), capsScopes...)
		}

		res, admitErr := rl.admitErr(r.Context(), admitScopes, est)
		if admitErr != nil {
			// W-CAPS: with org caps enforcing, a limiter dependency failure
			// must fail CLOSED — an unavailable window cannot admit an
			// unbounded request. Without caps (or in shadow) the OD-07
			// fail-open stands, counted as a would-deny.
			if rl.caps != nil {
				if rl.caps.enforce() {
					orgCapsDeniedTotal.WithLabelValues(orgCapsKindDependency).Inc()
					writeUnavailable(w, rl.caps.callTimeout)
					return
				}
				orgCapsWouldDenyTotal.WithLabelValues(orgCapsKindDependency).Inc()
			}
			rl.failOpen(admitErr)
			res = admitDecision{allowed: true, rpmRem: -1, tpmRem: -1}
		}

		// Shadow-mode caps windows measure what WOULD have been
		// denied and keep accounting the org's real traffic; the request
		// passes either way. Skipped when the admit failed open (member ""):
		// with the window state unavailable there is nothing to account on.
		reconcileScopes := admitScopes
		if len(capsScopes) > 0 && !enforceCaps && res.member != "" {
			for _, kind := range rl.caps.shadowObserve(r.Context(), capsScopes, est, res.member) {
				orgCapsWouldDenyTotal.WithLabelValues(kind).Inc()
			}
			reconcileScopes = append(append([]rateLimitScopeRef{}, admitScopes...), capsScopes...)
		}

		setRateLimitHeaders(w, res)
		if !res.allowed {
			keyRateLimitDeniedTotal.WithLabelValues(res.dimension).Inc()
			retryAfter := fairShareRetryAfterSeconds(res.retryMs, rl.priorityFor(r.Context(), keyID))
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
			apierrors.WriteWithCode(w, http.StatusTooManyRequests,
				apierrors.ErrorCodeRateLimitExceeded,
				"Rate limit reached: "+rateLimitDimensionText(res.dimension)+
					", retry in "+strconv.FormatInt(retryAfter, 10)+"s",
				"rate_limit_exceeded")
			return
		}

		if anyToken {
			r = r.WithContext(withTokenReconcile(r.Context(), &tokenReservation{
				rl:       rl,
				scopes:   reconcileScopes,
				member:   res.member,
				estimate: est,
				active:   est > 0 || capsOTPMOn(capsScopes),
			}))
		}
		next.ServeHTTP(w, r)
	})
}

// capsOTPMOn reports whether any caps scope carries the OTPM window — those
// members are recorded with weight 0 and need the reconcile even when the
// input estimate was zero.
func capsOTPMOn(scopes []rateLimitScopeRef) bool {
	for _, s := range scopes {
		if s.otpm > 0 {
			return true
		}
	}
	return false
}

// admit runs the atomic window check+record for all scopes in one EVAL.
// Redis errors fail open (OD-07): the request proceeds, the fallback metric
// counts and the WARN is throttled. The caps-aware middleware uses admitErr
// to decide fail-closed instead.
func (rl *keyRateLimiter) admit(ctx context.Context, scopes []rateLimitScopeRef, est int64) admitDecision {
	dec, err := rl.admitErr(ctx, scopes, est)
	if err != nil {
		rl.failOpen(err)
		return admitDecision{allowed: true, rpmRem: -1, tpmRem: -1}
	}
	return dec
}

// admitErr is admit without the fail-open decision: a Redis (or result-shape)
// error is returned to the caller, which owns the open/closed policy.
func (rl *keyRateLimiter) admitErr(ctx context.Context, scopes []rateLimitScopeRef, est int64) (admitDecision, error) {
	dec := admitDecision{allowed: true, rpmRem: -1, tpmRem: -1, member: rl.member()}
	if len(scopes) == 0 {
		return dec, nil
	}

	var keys []string
	args := make([]interface{}, 0, 5+4*len(scopes))
	args = append(args, len(scopes), rateLimitsWindow.Milliseconds(), dec.member, est)
	for _, s := range scopes {
		keys = append(keys, s.rpmZSet(), s.tpmZSet(), s.tpmHash(), s.itpmZSet(), s.itpmHash(), s.otpmZSet(), s.otpmHash())
		args = append(args, s.rpm, s.tpm, s.itpm, s.otpm)
	}

	res, err := rl.eval(ctx, admitScript, keys, args)
	if err != nil {
		return dec, err
	}
	vals, ok := res.([]interface{})
	if !ok || len(vals) < 9 {
		return dec, fmt.Errorf("admit script: unexpected result shape %T", res)
	}
	num := func(i int) int64 { v, _ := vals[i].(int64); return v }
	dec.allowed = num(0) == 1
	dec.rpmRem, dec.rpmLimit, dec.rpmReset = num(1), num(2), time.Duration(num(3))*time.Millisecond
	dec.tpmRem, dec.tpmLimit, dec.tpmReset = num(4), num(5), time.Duration(num(6))*time.Millisecond
	dec.retryMs = num(7)
	dimension, _ := vals[8].(string)
	dec.dimension = dimension
	return dec, nil
}

// eval executes one script under the limiter's call timeout. The context is
// deliberately detached (context.WithoutCancel): the window record/correction
// is accounting that must survive a client disconnect mid-response, so
// request cancellation never drops it. Values are still inherited.
func (rl *keyRateLimiter) eval(ctx context.Context, script string, keys []string, args []interface{}) (interface{}, error) {
	ec, cancel := context.WithTimeout(context.WithoutCancel(ctx), rl.callTimeout)
	defer cancel()
	return rl.rdb.Eval(ec, script, keys, args...).Result()
}

// failOpen records one fallback decision and throttles the WARN.
func (rl *keyRateLimiter) failOpen(err error) {
	keyRateLimitFallbackTotal.Inc()
	now := time.Now().UnixNano()
	last := rl.lastWarn.Load()
	if last != 0 && now-last < rl.warnEvery.Nanoseconds() {
		return
	}
	if rl.lastWarn.CompareAndSwap(last, now) {
		rl.log.Warn("key rate limiter: dependency unavailable, failing open", "error", err)
	}
}

// member builds the per-process-unique window member id.
func (rl *keyRateLimiter) member() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10) + "-" +
		strconv.FormatUint(rl.memberSeq.Add(1), 10)
}

// ---------------------------------------------------------------------------
// REJECT policy only — on a 429 the Retry-After hint scales so higher-
// priority keys poll sooner and win freed window capacity first. This is
// documented fairness, NOT a preemptive scheduler: there is no admission
// ordering, no queue, and no preemption — a full window denies every request
// regardless of priority; only the retry cadence differs.
//
// Semantics: Retry-After_seconds = ceil(retryMs * (10 - priority) / 5 / 1000).
// The default priority 5 leaves the hint EXACTLY as before (factor 1.0);
// priority 9 retries at ~0.2×, priority 0 backs off at ~2×. Resolution
// errors fail open to the default — fairness is best-effort and never
// changes an admission decision by itself.
// ---------------------------------------------------------------------------

// keyPrioritySource resolves one API key's fair-share priority.
// *adminstore.Store implements it; tests substitute a stub.
type keyPrioritySource interface {
	APIKeyPriority(ctx context.Context, keyID string) (int, error)
}

// priorityCacheEntry is one resolved key priority and its fetch time.
type priorityCacheEntry struct {
	priority int
	expires  time.Time
}

// priorityFor resolves the key's priority behind a short TTL cache. Any
// error (unknown key, DB down) yields the default — the limiter never
// denies or delays a request because the priority lookup failed.
func (rl *keyRateLimiter) priorityFor(ctx context.Context, keyID string) int {
	if keyID == "" {
		return adminstore.DefaultAPIKeyPriority
	}
	now := time.Now()
	rl.mu.Lock()
	if rl.priorities != nil {
		if e, ok := rl.priorities[keyID]; ok && now.Before(e.expires) {
			rl.mu.Unlock()
			return e.priority
		}
	}
	rl.mu.Unlock()

	priority := adminstore.DefaultAPIKeyPriority
	if src, ok := rl.source.(keyPrioritySource); ok {
		if p, err := src.APIKeyPriority(ctx, keyID); err == nil {
			priority = p
		}
	}

	rl.mu.Lock()
	if rl.priorities == nil {
		rl.priorities = map[string]priorityCacheEntry{}
	}
	for k, e := range rl.priorities {
		if !now.Before(e.expires) {
			delete(rl.priorities, k)
		}
	}
	rl.priorities[keyID] = priorityCacheEntry{priority: priority, expires: now.Add(rl.cacheTTL)}
	rl.mu.Unlock()
	return priority
}

// fairShareRetryAfterSeconds scales a denial's Retry-After hint by the key's
// priority and renders it in whole seconds (minimum 1).
func fairShareRetryAfterSeconds(retryMs int64, priority int) int64 {
	if retryMs < 0 {
		retryMs = 0
	}
	factor := int64(10 - priority) // priority 0..9 → 10..1 (fifths of 2.0)
	if factor < 1 {
		factor = 1
	}
	// (retryMs * factor) / 5 with rounding; retryMs ≤ 60_000 so the product
	// cannot overflow.
	scaled := (retryMs*factor + 2) / 5
	secs := (scaled + 999) / 1000
	if secs < 1 {
		secs = 1
	}
	return secs
}

// ---------------------------------------------------------------------------
// W-CAPS: org-level beta caps (YABANIN_ORG_CAPS = shadow|enforce). Every org
// gets the beta defaults — 60 RPM / 200k TPM / $50 monthly budget — unless it
// overrides them through the admin caps endpoint (org_caps table). The RPM/
// TPM windows reuse the atomic admit/reconcile scripts above (scope
// "orgcaps", so they never collide with admin-configured org rows); the
// budget is an integer-cent comparison of the cached month-to-date spend.
//
// Enforce mode fails CLOSED: an unreachable caps source (DB) or an unusable
// Redis denies with 503 — unlike the key-limit layer's OD-07 fail-open —
// because a beta cap that silently disappears is worse than a short outage.
// Shadow mode only counts what WOULD have been denied.
// ---------------------------------------------------------------------------

// orgCapsKind* are the denial metric labels (never carry org identifiers).
const (
	orgCapsKindRPM        = "rpm"
	orgCapsKindTPM        = "tpm"
	orgCapsKindITPM       = "itpm"
	orgCapsKindOTPM       = "otpm"
	orgCapsKindBudget     = "budget"
	orgCapsKindDependency = "dependency"
)

// orgCapsDeniedTotal counts enforce-mode denials by kind (429 rpm/tpm,
// 402 budget, 503 dependency fail-closed).
var orgCapsDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateway_org_caps_denied_total",
	Help: "Org caps enforce-mode denials, by kind (no identifiers in labels).",
}, []string{"kind"})

// orgCapsWouldDenyTotal counts shadow-mode would-deny decisions by kind.
var orgCapsWouldDenyTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateway_org_caps_would_deny_total",
	Help: "Org caps shadow-mode would-deny decisions, by kind (no identifiers in labels).",
}, []string{"kind"})

// Beta defaults mirrored from adminstore (single source of truth there);
// referenced directly to keep the gateway free of duplicated constants.

// orgCapsSource resolves the effective caps, the month-to-date spend and the
// webhook target for one org. *adminstore.Store implements it; tests stub it.
type orgCapsSource interface {
	EffectiveOrgCaps(ctx context.Context, orgID string) (*adminstore.EffectiveOrgCaps, error)
	OrgMonthSpendCents(ctx context.Context, orgID string) (int64, error)
	OrgAlertTarget(ctx context.Context, orgID string) (adminstore.OrgAlertTarget, error)
}

// capsCacheEntry is a resolved caps block (with its webhook target) and the
// fetch time — admin caps changes propagate within the TTL.
type capsCacheEntry struct {
	caps    *adminstore.EffectiveOrgCaps
	target  adminstore.OrgAlertTarget
	expires time.Time
}

// spendCacheEntry caches one org's month-to-date spend (short TTL: the
// settle loop feeds request_logs continuously, so a few seconds of staleness
// bounds the budget overrun at the in-flight request rate, not at zero).
type spendCacheEntry struct {
	cents   int64
	expires time.Time
}

// orgCapsEnforcer carries the caps policy for the gateway data plane.
type orgCapsEnforcer struct {
	rdb      rateLimitScripter
	source   orgCapsSource
	mode     string // config.OrgCapsShadow | config.OrgCapsEnforce
	log      *slog.Logger
	notifier *adminstore.BudgetWebhookNotifier

	// callTimeout bounds each dependency round-trip (Redis and the caps
	// resolve path reuse the limiter's budget).
	callTimeout time.Duration
	// warnEvery throttles dependency WARNs (no log spam).
	warnEvery      time.Duration
	lastWarn       atomic.Int64
	notifyMu       sync.Mutex
	notifyAt       map[string]time.Time
	notifyCooldown time.Duration

	mu         sync.Mutex
	capsCache  map[string]capsCacheEntry
	capsTTL    time.Duration
	spendCache map[string]spendCacheEntry
	spendTTL   time.Duration
}

// newOrgCapsEnforcer wires the caps layer over the shared Redis handle and
// adminstore source. mode is a non-off config.OrgCaps* value.
func newOrgCapsEnforcer(rdb rateLimitScripter, source orgCapsSource, mode string, logger *slog.Logger) *orgCapsEnforcer {
	if logger == nil {
		logger = slog.Default()
	}
	return &orgCapsEnforcer{
		rdb:            rdb,
		source:         source,
		mode:           mode,
		log:            logger,
		notifier:       adminstore.NewBudgetWebhookNotifier(logger),
		callTimeout:    500 * time.Millisecond,
		warnEvery:      30 * time.Second,
		notifyAt:       map[string]time.Time{},
		notifyCooldown: time.Hour,
		capsCache:      map[string]capsCacheEntry{},
		capsTTL:        5 * time.Second,
		spendCache:     map[string]spendCacheEntry{},
		spendTTL:       3 * time.Second,
	}
}

func (c *orgCapsEnforcer) enforce() bool { return c.mode == config.OrgCapsEnforce }

// eval executes one caps script under the caps call timeout, detached from
// request cancellation (same accounting-survives-disconnect contract as the
// limiter's eval).
func (c *orgCapsEnforcer) eval(ctx context.Context, script string, keys []string, args []interface{}) (interface{}, error) {
	ec, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.callTimeout)
	defer cancel()
	return c.rdb.Eval(ec, script, keys, args...).Result()
}

// scopeRef renders the caps as one admit-script scope (distinct "orgcaps"
// OTPM windows ride the same scope (0 = off — the org did not opt in).
func capsScopeRef(caps *adminstore.EffectiveOrgCaps, orgID string) rateLimitScopeRef {
	return rateLimitScopeRef{
		scope: "orgcaps", id: orgID,
		rpm: caps.RPM, tpm: caps.TPM, itpm: caps.InputTPM, otpm: caps.OutputTPM,
	}
}

// (namespace "orgcapskey", one window per API key of the org; 0 = off — no
// per-key cap configured).
func keyCapsScopeRef(caps *adminstore.EffectiveOrgCaps, keyID string) rateLimitScopeRef {
	return rateLimitScopeRef{scope: "orgcapskey", id: keyID, tpm: caps.KeyTPM}
}

// cached fetch helpers -------------------------------------------------------

func (c *orgCapsEnforcer) fetchCaps(ctx context.Context, orgID string) (capsCacheEntry, error) {
	c.mu.Lock()
	if e, ok := c.capsCache[orgID]; ok && time.Now().Before(e.expires) {
		c.mu.Unlock()
		return e, nil
	}
	c.mu.Unlock()

	ectx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.callTimeout)
	defer cancel()
	caps, err := c.source.EffectiveOrgCaps(ectx, orgID)
	if err != nil {
		return capsCacheEntry{}, err
	}
	var target adminstore.OrgAlertTarget
	tctx, tcancel := context.WithTimeout(context.WithoutCancel(ctx), c.callTimeout)
	target, _ = c.source.OrgAlertTarget(tctx, orgID) // webhook is best-effort
	tcancel()

	entry := capsCacheEntry{caps: caps, target: target, expires: time.Now().Add(c.capsTTL)}
	c.mu.Lock()
	c.capsCache[orgID] = entry
	c.mu.Unlock()
	return entry, nil
}

func (c *orgCapsEnforcer) fetchSpend(ctx context.Context, orgID string) (int64, error) {
	c.mu.Lock()
	if e, ok := c.spendCache[orgID]; ok && time.Now().Before(e.expires) {
		c.mu.Unlock()
		return e.cents, nil
	}
	c.mu.Unlock()

	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.callTimeout)
	defer cancel()
	cents, err := c.source.OrgMonthSpendCents(sctx, orgID)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.spendCache[orgID] = spendCacheEntry{cents: cents, expires: time.Now().Add(c.spendTTL)}
	c.mu.Unlock()
	return cents, nil
}

// warn throttles dependency WARNs.
func (c *orgCapsEnforcer) warn(err error) {
	now := time.Now().UnixNano()
	last := c.lastWarn.Load()
	if last != 0 && now-last < c.warnEvery.Nanoseconds() {
		return
	}
	if c.lastWarn.CompareAndSwap(last, now) {
		c.log.Warn("org caps: dependency unavailable", "mode", c.mode, "error", err)
	}
}

// metric counts one denial (enforce) or would-deny (shadow).
func (c *orgCapsEnforcer) metric(kind string) {
	if c.enforce() {
		orgCapsDeniedTotal.WithLabelValues(kind).Inc()
	} else {
		orgCapsWouldDenyTotal.WithLabelValues(kind).Inc()
	}
}

// precheck resolves the org caps and answers the hard monthly budget.
// It returns the effective caps block to enforce windows from (nil when the
// caps layer should stay out of this request's way) and deny=true when the
// response has already been written:
//
//	budget exceeded (enforce)   → 402 budget_exceeded + owner webhook
//	caps/spend source down      → 503 fail-closed (enforce) / pass (shadow)
//
// A caps block is ALWAYS returned on success — caps windows are on by
// construction (beta defaults ≥ 1), and a 0/absent dimension would have been
func (c *orgCapsEnforcer) precheck(w http.ResponseWriter, r *http.Request, orgID string) (*adminstore.EffectiveOrgCaps, bool) {
	entry, err := c.fetchCaps(r.Context(), orgID)
	if err != nil {
		c.warn(fmt.Errorf("resolve caps: %w", err))
		c.metric(orgCapsKindDependency)
		if !c.enforce() {
			return nil, false
		}
		writeUnavailable(w, c.callTimeout)
		return nil, true
	}

	spend, err := c.fetchSpend(r.Context(), orgID)
	if err != nil {
		c.warn(fmt.Errorf("month spend: %w", err))
		c.metric(orgCapsKindDependency)
		if !c.enforce() {
			return nil, false
		}
		writeUnavailable(w, c.callTimeout)
		return nil, true
	}

	if spend >= entry.caps.MonthlyBudgetCents {
		c.metric(orgCapsKindBudget)
		if !c.enforce() {
			return nil, false
		}
		c.notifyBudgetAsync(r, orgID, entry, spend)
		apierrors.Write(w, http.StatusPaymentRequired, "budget_exceeded",
			"organization monthly budget limit reached — top up or raise the caps to continue")
		return nil, true
	}
	return entry.caps, false
}

// shadowObserve runs the SHADOW-mode caps windows: it measures what would
// have been denied (the returned kinds, one per first binding dimension) and
// records the request so the shadow windows accumulate real traffic. A Redis
// failure degrades to a dependency would-deny count and an empty result —
// shadow never fails a request.
func (c *orgCapsEnforcer) shadowObserve(ctx context.Context, scopes []rateLimitScopeRef, est int64, member string) []string {
	var keys []string
	args := make([]interface{}, 0, 5+4*len(scopes))
	args = append(args, len(scopes), rateLimitsWindow.Milliseconds(), member, est)
	for _, s := range scopes {
		keys = append(keys, s.rpmZSet(), s.tpmZSet(), s.tpmHash(), s.itpmZSet(), s.itpmHash(), s.otpmZSet(), s.otpmHash())
		args = append(args, s.rpm, s.tpm, s.itpm, s.otpm)
	}
	res, err := c.eval(ctx, shadowCapsScript, keys, args)
	if err != nil {
		c.warn(fmt.Errorf("shadow caps windows: %w", err))
		return []string{orgCapsKindDependency}
	}
	dim, ok := res.(string)
	if !ok || dim == "" {
		return nil
	}
	return []string{dim}
}

// notifyBudgetAsync fires the budget_exceeded webhook to the org's configured
// spend-alert target (reused, not duplicated) at most once per cooldown, off
// the request path.
func (c *orgCapsEnforcer) notifyBudgetAsync(r *http.Request, orgID string, entry capsCacheEntry, spend int64) {
	c.notifyMu.Lock()
	if time.Since(c.notifyAt[orgID]) < c.notifyCooldown {
		c.notifyMu.Unlock()
		return
	}
	c.notifyAt[orgID] = time.Now()
	c.notifyMu.Unlock()

	ctx := context.WithoutCancel(r.Context())
	go func() {
		bctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := c.notifier.BudgetExceeded(bctx, orgID, entry.target,
			entry.caps.MonthlyBudgetCents, spend); err != nil {
			c.log.Warn("budget_exceeded webhook failed", "org", orgID, "error", err)
		}
	}()
}

// writeUnavailable answers the fail-closed 503 (shared shape for the caps
// resolve and the Redis-eval failure paths).
func writeUnavailable(w http.ResponseWriter, timeout time.Duration) {
	retryAfter := (timeout.Milliseconds() + 999) / 1000
	if retryAfter < 1 {
		retryAfter = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
	apierrors.Write(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
		"org caps enforcement temporarily unavailable")
}

// tokenReservation is the per-request reconcile handle attached to the
// request context: the middleware's input-token reservation, corrected to
// the actual usage by the endpoint finish paths.
type tokenReservation struct {
	rl     *keyRateLimiter
	scopes []rateLimitScopeRef
	member string
	// estimate is the input-token reserve charged before the upstream call.
	estimate int64
	// active is false when nothing was reserved — there is nothing to
	// correct then. It stays true for a zero estimate only when an OTPM
	// window recorded the member (weight 0) awaiting the output credit.
	active bool
}

type tokenReconcileCtxKey struct{}

func withTokenReconcile(ctx context.Context, tr *tokenReservation) context.Context {
	return context.WithValue(ctx, tokenReconcileCtxKey{}, tr)
}

// reconcileRateLimitUsage corrects the request's token reservations to the
// actual usage: the aggregate TPM window holds prompt+completion, the ITPM
// window the prompt tokens (swapping the input estimate for the fact), and
// the OTPM window the completion tokens (crediting the weight-0 placeholder).
// Safe to call on any context: without a reservation (feature off, RPM-only
// limits, no identity) it is a no-op, and Redis errors degrade to keeping the
// estimate (fail-open). The estimator contract: the ITPM reserve is
// bytes/4 — the same shape estimateRequestTokens uses and the completions
// endpoint's fallback usage — corrected to the tokenizer-exact prompt count
// as soon as real usage arrives.
func reconcileRateLimitUsage(ctx context.Context, promptTokens, completionTokens int64) {
	if promptTokens < 0 || completionTokens < 0 {
		return
	}
	tr, _ := ctx.Value(tokenReconcileCtxKey{}).(*tokenReservation)
	if tr == nil || !tr.active {
		return
	}
	total := promptTokens + completionTokens
	if total == tr.estimate && promptTokens == tr.estimate && completionTokens == 0 {
		return // nothing would change — skip the Redis round-trip
	}
	var keys []string
	for _, s := range tr.scopes {
		keys = append(keys, s.tokenWindows()...)
	}
	if _, err := tr.rl.eval(ctx, reconcileScript, keys,
		[]interface{}{tr.member, total, promptTokens, completionTokens, len(tr.scopes)}); err != nil {
		tr.rl.failOpen(err)
	}
}

// estimateRequestTokens is the pre-request input-token estimate: ~4 bytes
// per token, the same shape the completions endpoint uses for its fallback
// usage. It only seeds the token-window reservations — the post-response
// correction to the actual usage is the source of truth.
func estimateRequestTokens(bodyLen int) int64 {
	return int64((bodyLen + 3) / 4)
}

// rateLimitDimensionText renders the binding dimension for the 429 message.
func rateLimitDimensionText(dimension string) string {
	switch dimension {
	case "tpm":
		return "tokens per minute (TPM) limit exceeded"
	case "itpm":
		return "input tokens per minute (ITPM) limit exceeded"
	case "otpm":
		return "output tokens per minute (OTPM) limit exceeded"
	default:
		return "requests per minute (RPM) limit exceeded"
	}
}

// setRateLimitHeaders writes the OpenAI-style rate-limit headers for the
// strictest (binding) window. Headers for a dimension are only set when a
// limit exists for it; the values mirror the admit decision exactly.
func setRateLimitHeaders(w http.ResponseWriter, d admitDecision) {
	h := w.Header()
	if d.rpmLimit > 0 {
		h.Set("x-ratelimit-limit-requests", strconv.FormatInt(d.rpmLimit, 10))
		h.Set("x-ratelimit-remaining-requests", strconv.FormatInt(max64(d.rpmRem, 0), 10))
		h.Set("x-ratelimit-reset-requests", formatResetSeconds(d.rpmReset))
	}
	if d.tpmLimit > 0 {
		h.Set("x-ratelimit-limit-tokens", strconv.FormatInt(d.tpmLimit, 10))
		h.Set("x-ratelimit-remaining-tokens", strconv.FormatInt(max64(d.tpmRem, 0), 10))
		h.Set("x-ratelimit-reset-tokens", formatResetSeconds(d.tpmReset))
	}
}

// formatResetSeconds renders a reset delay the way OpenAI does ("1s",
// "6m0s"), rounded up to whole seconds.
func formatResetSeconds(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return (time.Duration(math.Ceil(d.Seconds())) * time.Second).String()
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
