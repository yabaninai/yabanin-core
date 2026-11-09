package cli

import (
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// cacheUpstreamFP derives the endpoint-revision component of the cache route
// identity (audit H1) for a candidate: a one-way fingerprint of the provider
// and the effective base URL this request would be answered by (upstreamURL).
// Every cache lookup and write must derive the component through this helper
// (serveChatCache lookup, the chat and stream write paths), so a re-pointed
// endpoint degrades warm entries to self-healing misses symmetrically on
// both sides. The fingerprint is one-way: no endpoint configuration is
// stored in the cache.
func (gw *gateway) cacheUpstreamFP(mi resolver.ModelInfo) string {
	return cache.UpstreamFingerprint(mi.Provider, gw.upstreamURL(mi))
}
