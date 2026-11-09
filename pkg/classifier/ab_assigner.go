package classifier

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// ABAssigner handles A/B test variant assignment for classifier routing.
type ABAssigner struct {
	mu       sync.RWMutex
	cache    map[string]string // orgID -> variant
	cacheTTL int               // seconds
}

// NewABAssigner creates a new ABAssigner with the given cache TTL in seconds.
func NewABAssigner(cacheTTLSeconds int) *ABAssigner {
	if cacheTTLSeconds <= 0 {
		cacheTTLSeconds = 3600 // 1 hour default
	}
	return &ABAssigner{
		cache:    make(map[string]string),
		cacheTTL: cacheTTLSeconds,
	}
}

// Assign returns the A/B variant for an org. Uses deterministic bucketing based on SHA-256 of orgID+experimentName.
func (ab *ABAssigner) Assign(orgID, experimentName string, trafficPct int) string {
	if trafficPct == 0 {
		return "control" // full control
	}

	key := fmt.Sprintf("%s:%s", orgID, experimentName)
	h := sha256.Sum256([]byte(key))
	bucket := int(h[0]) % 100

	if bucket < trafficPct {
		return "treatment" // in the test group
	}
	return "control"
}

// GetVariant returns cached assignment or computes new one.
func (ab *ABAssigner) GetVariant(orgID, experimentName string, trafficPct int) string {
	ab.mu.RLock()
	variant, ok := ab.cache[orgID]
	ab.mu.RUnlock()

	if ok {
		return variant // sticky assignment
	}

	variant = ab.Assign(orgID, experimentName, trafficPct)

	ab.mu.Lock()
	ab.cache[orgID] = variant
	ab.mu.Unlock()

	return variant
}
