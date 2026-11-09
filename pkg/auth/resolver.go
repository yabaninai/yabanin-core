package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// ErrKeyExpired reports that a key resolved to an active row whose expires_at
// "key_expired" so clients can branch on expiry instead of treating it as an
// unknown-key failure. Like the other resolve failures it is NOT cached.
var ErrKeyExpired = errors.New("api key expired")

// DBPool is the minimal database interface for org resolution.
type DBPool interface {
	QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row
}

// RedisClient is the minimal redis interface for org resolution caching.
type RedisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd
}

// CacheSigner provides HMAC signing/verification for cache values to prevent poisoning.
type CacheSigner struct {
	key []byte
}

// NewCacheSigner creates a CacheSigner from a hex-encoded secret.
func NewCacheSigner(secret string) (*CacheSigner, error) {
	if secret == "" {
		return nil, fmt.Errorf("cache signer: empty secret")
	}
	key, err := hex.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("cache signer: invalid hex secret: %w", err)
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("cache signer: secret must be at least 128 bits (32 hex chars)")
	}
	return &CacheSigner{key: key}, nil
}

// Sign returns a signed version of value in the form "value:hex(hmac(value))".
func (s *CacheSigner) Sign(key, value string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(key + ":" + value))
	return value + ":" + hex.EncodeToString(mac.Sum(nil))
}

// Verify extracts and checks the HMAC suffix. Returns (value, true) on success, ("", false) on failure.
func (s *CacheSigner) Verify(key, signed string) (string, bool) {
	colon := strings.LastIndex(signed, ":")
	if colon < 0 {
		return "", false
	}
	value := signed[:colon]
	sig := signed[colon+1:]
	expected := s.Sign(key, value)
	expectedSig := expected[len(value)+1:]
	if len(sig) != len(expectedSig) {
		return "", false
	}
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", false
	}
	return value, true
}

// Resolver resolves an API key to an org_id using DB lookup with Redis caching.
type Resolver struct {
	pool     DBPool
	rdb      RedisClient
	cacheTTL int64 // seconds
	signer   *CacheSigner
	// now is the clock seam for deterministic expiry tests (AUTH-03/04);
	// production code always sees time.Now via NewResolver.
	now func() time.Time
}

// NewResolver creates a new org resolver. Pass signer as nil to skip HMAC verification.
func NewResolver(pool DBPool, rdb RedisClient, cacheTTL int64, signer *CacheSigner) *Resolver {
	return &Resolver{
		pool:     pool,
		rdb:      rdb,
		cacheTTL: cacheTTL,
		signer:   signer,
		now:      time.Now,
	}
}

// WithNow overrides the resolver clock and returns r. Production callers
// never use it; expiry tests drive time deterministically ("key expires
// between two authenticated requests") without sleeping.
func (r *Resolver) WithNow(fn func() time.Time) *Resolver {
	if fn != nil {
		r.now = fn
	}
	return r
}

// ResolveResult contains the resolved identity for an API key. For agent
// principals (G1), AgentID is set and APIKeyID is empty; for regular api_keys,
// AgentID is empty and APIKeyID is set.
type ResolveResult struct {
	OrgID    string
	APIKeyID string
	TeamID   string
	AgentID  string
	// UserID is set for a personal developer key. Empty for org and agent keys.
	UserID          string
	Labels          map[string]string
	LabelsLocked    bool
	CanMintSessions bool
	CanReadUsage    bool
	// Session fields are set only for a ybs_ key. APIKeyID is the parent key
	// so whitelist and key limits follow the parent. Session labels are not
	// copied into Labels; the gateway merges them as a second source.
	SessionKeyID        string
	SessionLabels       map[string]string
	SessionLabelsLocked bool
	SessionMaxTokens    *int64
	SessionMaxCostUSD   *float64
	SessionExpiresAt    time.Time
	// KeyExpiresAt is the effective parent-key expiry as an identity
	// property (AUTH-03/04): for a session key it is the parent api_key's
	// expires_at, for a regular/agent key its own. Zero means no expiry.
	// Callers must treat a past KeyExpiresAt exactly like an inactive key
	// even when the resolve cache still serves the entry.
	KeyExpiresAt time.Time
}

// resolveCacheV2 is the JSON body after the v2: prefix.
type resolveCacheV2 struct {
	Org    string            `json:"org"`
	Key    string            `json:"key"`
	Team   string            `json:"team"`
	Agent  string            `json:"agent"`
	User   string            `json:"user"`
	Labels map[string]string `json:"labels"`
	Locked bool              `json:"locked"`
	Mint   bool              `json:"mint"`
	Usage  bool              `json:"usage"`
	// Session identity. Empty on a parent-key cache entry.
	Session  string            `json:"session,omitempty"`
	SLabels  map[string]string `json:"slabels,omitempty"`
	SLocked  bool              `json:"slocked,omitempty"`
	SMaxTok  *int64            `json:"smax_tok,omitempty"`
	SMaxCost *float64          `json:"smax_cost,omitempty"`
	SExp     int64             `json:"sexp,omitempty"`
	// KExp is the effective parent-key expiry (AUTH-04): the warm cache
	// rechecks it as an identity property instead of trusting the Redis TTL.
	KExp int64 `json:"kexp,omitempty"`
}

// parseResolveCache reads a resolver cache value. A v2: prefix is JSON.
// Anything else is the older pipe format (3, 4, or 5 fields). Broken JSON
// is a cache miss, not an auth failure. AT-14 should extend this function
// rather than add a second parser.
func parseResolveCache(decoded string) (*ResolveResult, bool) {
	if strings.HasPrefix(decoded, "v2:") {
		var doc resolveCacheV2
		if err := json.Unmarshal([]byte(strings.TrimPrefix(decoded, "v2:")), &doc); err != nil {
			return nil, false
		}
		labels := doc.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		slabels := doc.SLabels
		if slabels == nil {
			slabels = map[string]string{}
		}
		res := &ResolveResult{
			OrgID: doc.Org, APIKeyID: doc.Key, TeamID: doc.Team, AgentID: doc.Agent, UserID: doc.User,
			Labels: labels, LabelsLocked: doc.Locked, CanMintSessions: doc.Mint, CanReadUsage: doc.Usage,
			SessionKeyID: doc.Session, SessionLabels: slabels, SessionLabelsLocked: doc.SLocked,
			SessionMaxTokens: doc.SMaxTok, SessionMaxCostUSD: doc.SMaxCost,
		}
		if doc.SExp != 0 {
			res.SessionExpiresAt = time.Unix(doc.SExp, 0).UTC()
		}
		if doc.KExp != 0 {
			res.KeyExpiresAt = time.Unix(doc.KExp, 0).UTC()
		}
		return res, true
	}
	parts := strings.Split(decoded, "|")
	if len(parts) < 3 {
		return nil, false
	}
	res := &ResolveResult{OrgID: parts[0], APIKeyID: parts[1], TeamID: parts[2], Labels: map[string]string{}}
	if len(parts) >= 4 {
		res.AgentID = parts[3]
	}
	if len(parts) >= 5 {
		res.UserID = parts[4]
	}
	return res, true
}

func formatResolveCache(res *ResolveResult) string {
	labels := res.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	var sexp int64
	if !res.SessionExpiresAt.IsZero() {
		sexp = res.SessionExpiresAt.UTC().Unix()
	}
	var kexp int64
	if !res.KeyExpiresAt.IsZero() {
		kexp = res.KeyExpiresAt.UTC().Unix()
	}
	slabels := res.SessionLabels
	if slabels == nil {
		slabels = map[string]string{}
	}
	raw, err := json.Marshal(resolveCacheV2{
		Org: res.OrgID, Key: res.APIKeyID, Team: res.TeamID, Agent: res.AgentID, User: res.UserID,
		Labels: labels, Locked: res.LabelsLocked, Mint: res.CanMintSessions, Usage: res.CanReadUsage,
		Session: res.SessionKeyID, SLabels: slabels, SLocked: res.SessionLabelsLocked,
		SMaxTok: res.SessionMaxTokens, SMaxCost: res.SessionMaxCostUSD, SExp: sexp, KExp: kexp,
	})
	if err != nil {
		return "v2:{}"
	}
	return "v2:" + string(raw)
}

// Resolve returns org_id, api_key_id, and team_id for a plaintext API key.
func (r *Resolver) Resolve(ctx context.Context, key string) (*ResolveResult, error) {
	if strings.TrimSpace(key) == "" {
		return nil, nil //nolint:nilnil // documented: empty key means "not an API key", not an error
	}

	hash := sha256.Sum256([]byte(key))
	keyHash := fmt.Sprintf("%x", hash)

	cacheKey := fmt.Sprintf("org:resolve:%s", keyHash)

	if r.rdb != nil {
		val := r.rdb.Get(ctx, cacheKey)
		cached, err := val.Result()
		if err == nil {
			decoded := cached
			if r.signer != nil {
				v, ok := r.signer.Verify(cacheKey, cached)
				if !ok {
					decoded = ""
				} else {
					decoded = v
				}
			}
			// 4 fields: org|apikey|team|agent (empty for the unused side).
			// A legacy 3-field value is accepted (agent stays empty).
			if decoded != "" {
				if res, ok := parseResolveCache(decoded); ok {
					// AUTH-04: expiry is an identity property, not just the
					// Redis TTL. A cached entry whose key (parent key for a
					// session) or session has since expired is treated as a
					// miss and falls through to the authoritative DB path —
					// which reports key_expired / not-found as appropriate.
					now := r.now()
					expired := (!res.KeyExpiresAt.IsZero() && now.After(res.KeyExpiresAt)) ||
						(!res.SessionExpiresAt.IsZero() && now.After(res.SessionExpiresAt))
					if !expired {
						return res, nil
					}
				}
			}
		}
	}

	var orgID, apiKeyID, teamID, userID string
	if r.pool != nil && IsSessionKey(key) {
		res, err := r.resolveSession(ctx, keyHash, cacheKey)
		if err != nil || res != nil {
			return res, err
		}
	}
	if r.pool != nil {
		// 1) Regular api_keys first (backcompat). expires_at NULL means the
		// key does not expire. A past expires_at is inactive and is not cached,
		// so a TTL cannot outlive the key.
		var keyExpires *time.Time
		var keyLabelsRaw []byte
		var labelsLocked, canMint, canUsage bool
		err := r.pool.QueryRow(ctx,
			`SELECT id::text, org_id::text, COALESCE(team_id::text, ''), COALESCE(user_id::text, ''), expires_at,
			        COALESCE(labels, '{}'::jsonb), labels_locked, can_mint_sessions, can_read_usage
			 FROM api_keys WHERE key_hash = $1 AND active = true`,
			keyHash,
		).Scan(&apiKeyID, &orgID, &teamID, &userID, &keyExpires, &keyLabelsRaw, &labelsLocked, &canMint, &canUsage)
		if err == nil && orgID != "" {
			if keyExpires != nil && r.now().After(*keyExpires) {
				// as 401 code "key_expired", not a generic unknown-key 401.
				return nil, ErrKeyExpired
			}
			keyLabels := map[string]string{}
			if len(keyLabelsRaw) > 0 {
				if uerr := json.Unmarshal(keyLabelsRaw, &keyLabels); uerr != nil || keyLabels == nil {
					keyLabels = map[string]string{}
				}
			}
			res := &ResolveResult{
				OrgID: orgID, APIKeyID: apiKeyID, TeamID: teamID, UserID: userID,
				Labels: keyLabels, LabelsLocked: labelsLocked, CanMintSessions: canMint, CanReadUsage: canUsage,
			}
			if keyExpires != nil {
				// AUTH-04: carry the expiry so the cache entry is TTL-bounded
				// by it and the warm path can recheck it.
				res.KeyExpiresAt = keyExpires.UTC()
			}
			r.cacheResolve(ctx, cacheKey, res)
			return res, nil
		}

		// 2) Agent-principal keys (G1). ADL-03: a delegated (child) key carries
		// a delegation TTL (expires_at) — the resolver rejects it once past that
		// instant, exactly like a revoked key. A root key (expires_at NULL) has
		// no TTL and is unaffected. The resolver cache TTL (S02) bounds how long
		// an expired key keeps resolving.
		//
		// hasExpiry/expiresAt: we scan expires_at into a *time.Time (a pointer
		// target) so pgx can distinguish NULL (hasExpiry=false, root key) from a
		// value (hasExpiry=true, child key). Scanning into **time.Time is
		// unsupported by pgx and would silently leave the TTL unset.
		var agentID string
		var expiresAt *time.Time
		err = r.pool.QueryRow(ctx,
			"SELECT id::text, org_id::text, expires_at FROM agent_keys WHERE key_hash = $1 AND active = true",
			keyHash,
		).Scan(&agentID, &orgID, &expiresAt)
		if err == nil && orgID != "" {
			// TTL check: a child key past its delegation TTL is rejected. We
			// deliberately do NOT cache the "expired" outcome — caching would
			// extend the expiry beyond expires_at (the S02 bound applies to the
			// happy path only); re-querying on each miss keeps the TTL honest.
			if expiresAt != nil && r.now().After(*expiresAt) {
				return nil, fmt.Errorf("agent key not found or inactive")
			}
			res := &ResolveResult{OrgID: orgID, AgentID: agentID, Labels: map[string]string{}}
			if expiresAt != nil {
				// AUTH-04: a delegated key's TTL rides on the result the same
				// way, so its cache entry cannot outlive the delegation.
				res.KeyExpiresAt = expiresAt.UTC()
			}
			r.cacheResolve(ctx, cacheKey, res)
			return res, nil
		}
	}

	return nil, fmt.Errorf("api key not found or inactive")
}
func (r *Resolver) resolveSession(ctx context.Context, keyHash, cacheKey string) (*ResolveResult, error) {
	var sessionID, orgID, parentID, teamID, userID string
	var sessionRaw, parentRaw []byte
	var sessionLocked, parentLocked bool
	var maxTokens *int64
	var maxCostText *string
	var expires time.Time
	// parentKeyExpires scans the parent api_key's expires_at (AUTH-03).
	var parentKeyExpires *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT s.id::text, s.org_id::text, s.parent_api_key_id::text,
		        COALESCE(s.labels, '{}'::jsonb), s.labels_locked,
		        s.max_tokens, s.max_cost_usd::text, s.expires_at,
		        COALESCE(k.team_id::text, ''), COALESCE(k.labels, '{}'::jsonb), k.labels_locked,
		        COALESCE(k.user_id::text, ''), k.expires_at
		   FROM session_keys s
		   JOIN api_keys k ON k.id = s.parent_api_key_id
		  WHERE s.key_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
		    AND k.active = true
		    AND (k.expires_at IS NULL OR k.expires_at > now())`,
		keyHash,
	).Scan(&sessionID, &orgID, &parentID, &sessionRaw, &sessionLocked, &maxTokens, &maxCostText, &expires,
		&teamID, &parentRaw, &parentLocked, &userID, &parentKeyExpires)
	if err != nil || orgID == "" {
		return nil, fmt.Errorf("api key not found or inactive")
	}
	parentLabels := decodeLabelMap(parentRaw)
	sessionLabels := decodeLabelMap(sessionRaw)
	var maxCost *float64
	if maxCostText != nil && *maxCostText != "" {
		if f, perr := strconv.ParseFloat(*maxCostText, 64); perr == nil {
			maxCost = &f
		}
	}
	res := &ResolveResult{
		OrgID: orgID, APIKeyID: parentID, TeamID: teamID, UserID: userID,
		Labels: parentLabels, LabelsLocked: parentLocked,
		CanMintSessions: false, CanReadUsage: false,
		SessionKeyID: sessionID, SessionLabels: sessionLabels, SessionLabelsLocked: sessionLocked,
		SessionMaxTokens: maxTokens, SessionMaxCostUSD: maxCost, SessionExpiresAt: expires.UTC(),
	}
	if parentKeyExpires != nil {
		// AUTH-03: the session lives no longer than its parent key. The SQL
		// above already denies a session whose parent has expired; the
		// carried value keeps minting and cache TTLs honest afterwards.
		res.KeyExpiresAt = parentKeyExpires.UTC()
	}
	r.cacheResolve(ctx, cacheKey, res)
	return res, nil
}

func decodeLabelMap(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return map[string]string{}
	}
	return out
}

// cacheResolve stores a hit. A key is cached only until IT expires (its own
// expires_at for regular and delegated keys, the parent key's for a session
// — AUTH-03/04), until its session expires, and never longer than the
// resolver TTL. A key that is already expired is not cached.
func (r *Resolver) cacheResolve(ctx context.Context, cacheKey string, res *ResolveResult) {
	if r.rdb == nil || res == nil {
		return
	}
	now := r.now()
	ttl := r.cacheTTL
	bound := func(exp time.Time) {
		if exp.IsZero() {
			return
		}
		remain := int64(exp.Sub(now).Seconds())
		if remain <= 0 {
			ttl = 0
			return
		}
		if ttl <= 0 || remain < ttl {
			ttl = remain
		}
	}
	bound(res.KeyExpiresAt)
	bound(res.SessionExpiresAt)
	if ttl <= 0 {
		return
	}
	cacheVal := formatResolveCache(res)
	if r.signer != nil {
		cacheVal = r.signer.Sign(cacheKey, cacheVal)
	}
	r.rdb.Set(ctx, cacheKey, cacheVal, time.Duration(ttl)*time.Second)
}
