package cli

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/labels"
)

const (
	labelPolicyMemTTL   = 30 * time.Second
	labelPolicyRedisTTL = 60 * time.Second
	labelPolicyWarnGap  = time.Minute
)

// labelKV is the Redis slice of the org policy cache.
type labelKV interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
}

// labelDB loads the stored policy JSON. found is false when the org has no row.
type labelDB interface {
	Load(ctx context.Context, orgID string) (raw []byte, found bool, err error)
}

type labelMemEntry struct {
	compiled *labels.Compiled
	until    time.Time
}

// orgLabelPolicies is memory (30s) then Redis (60s) then the database.
// Any database error returns the default policy and logs at most once a minute per org.
type orgLabelPolicies struct {
	mu   sync.Mutex
	mem  map[string]labelMemEntry
	warn map[string]time.Time
	now  func() time.Time
	kv   labelKV
	db   labelDB
	log  *slog.Logger
}

func (p *orgLabelPolicies) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *orgLabelPolicies) get(ctx context.Context, orgID string) *labels.Compiled {
	if orgID == "" {
		return defaultLabelPolicy
	}
	now := p.clock()
	p.mu.Lock()
	if e, ok := p.mem[orgID]; ok && now.Before(e.until) {
		compiled := e.compiled
		p.mu.Unlock()
		return compiled
	}
	p.mu.Unlock()

	key := "yb:labelpolicy:" + orgID
	if p.kv != nil {
		raw, err := p.kv.Get(ctx, key)
		if err == nil && raw != "" {
			if compiled, cerr := compilePolicyJSON([]byte(raw)); cerr == nil {
				p.remember(orgID, compiled, now.Add(labelPolicyMemTTL))
				return compiled
			}
		}
	}
	if p.db == nil {
		return defaultLabelPolicy
	}
	raw, found, err := p.db.Load(ctx, orgID)
	if err != nil {
		p.warnOnce(orgID, now, err)
		p.remember(orgID, defaultLabelPolicy, now.Add(labelPolicyMemTTL))
		return defaultLabelPolicy
	}
	if !found {
		p.remember(orgID, defaultLabelPolicy, now.Add(labelPolicyMemTTL))
		return defaultLabelPolicy
	}
	compiled, err := compilePolicyJSON(raw)
	if err != nil {
		p.warnOnce(orgID, now, err)
		return defaultLabelPolicy
	}
	if p.kv != nil {
		_ = p.kv.Set(ctx, key, string(raw), labelPolicyRedisTTL)
	}
	p.remember(orgID, compiled, now.Add(labelPolicyMemTTL))
	return compiled
}

func (p *orgLabelPolicies) remember(orgID string, compiled *labels.Compiled, until time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mem == nil {
		p.mem = map[string]labelMemEntry{}
	}
	p.mem[orgID] = labelMemEntry{compiled: compiled, until: until}
}

func (p *orgLabelPolicies) warnOnce(orgID string, now time.Time, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.warn == nil {
		p.warn = map[string]time.Time{}
	}
	if last, ok := p.warn[orgID]; ok && now.Sub(last) < labelPolicyWarnGap {
		return
	}
	p.warn[orgID] = now
	if p.log != nil {
		p.log.Warn("label policy unavailable; using default", "org_id", orgID, "error", err.Error())
	}
}

func compilePolicyJSON(raw []byte) (*labels.Compiled, error) {
	var policy labels.Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, err
	}
	return policy.Compile()
}

type redisLabelKV struct{ c *redis.Client }

func (r redisLabelKV) Get(ctx context.Context, key string) (string, error) {
	val, err := r.c.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", errLabelMiss
	}
	return val, err
}

func (r redisLabelKV) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return r.c.Set(ctx, key, value, ttl).Err()
}

var errLabelMiss = errors.New("label policy cache miss")

type poolLabelDB struct{ pool *pgxpool.Pool }

func (p poolLabelDB) Load(ctx context.Context, orgID string) ([]byte, bool, error) {
	if p.pool == nil {
		return nil, false, nil
	}
	var raw []byte
	err := p.pool.QueryRow(ctx, `SELECT policy FROM label_policies WHERE org_id = $1`, orgID).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return raw, true, nil
}

func (gw *gateway) orgLabelPolicies() *orgLabelPolicies {
	gw.labelPolicyOnce.Do(func() {
		p := &orgLabelPolicies{log: gw.log, mem: map[string]labelMemEntry{}, warn: map[string]time.Time{}}
		if gw.rdb != nil {
			p.kv = redisLabelKV{c: gw.rdb}
		}
		p.db = poolLabelDB{pool: gw.dbPool}
		gw.labelsOrg = p
	})
	return gw.labelsOrg
}
