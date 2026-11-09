package cache

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit H1: the endpoint-revision component of the route identity. A cache
// entry produced by upstream endpoint A must never be served to a lookup
// that resolves the same model to upstream endpoint B (provider re-point,
// base-URL rotation, provider swap under one model name) — the component is
// stamped on write (seal) and compared on lookup (Matches), and it is a
// one-way fingerprint: the cache never stores endpoint configuration.
//
// These pins reference the H1 API surface directly, so on a baseline without
// the fix this file does not compile (STREAM-01 typed-pin precedent); the
// behavioral end-to-end pin lives in pkg/gateway (h1_upstream_repoint_test).

func TestH1_UpstreamFingerprint_StableDistinctOneWay(t *testing.T) {
	a1 := UpstreamFingerprint("openai", "https://api.example.com/v1")
	a2 := UpstreamFingerprint("openai", "https://api.example.com/v1")
	bURL := UpstreamFingerprint("openai", "https://api.other.example.com/v1")
	bProv := UpstreamFingerprint("anthropic", "https://api.example.com/v1")

	require.NotEmpty(t, a1)
	assert.Equal(t, a1, a2, "the same (provider, url) pair must fingerprint identically")
	assert.NotEqual(t, a1, bURL, "a different base URL is a different endpoint revision")
	assert.NotEqual(t, a1, bProv, "a different provider is a different endpoint revision")

	assert.NotContains(t, a1, "api.example.com", "one-way: no raw URL may be recoverable from the component")
	assert.NotContains(t, a1, "openai", "one-way: no raw provider string in the component")
	assert.True(t, strings.HasPrefix(a1, "u1:"), "versioned prefix so the derivation itself can rotate")
}

func TestH1_Matches_UpstreamComponentIsLoadBearing(t *testing.T) {
	fpA := UpstreamFingerprint("openai", "https://a.example.com/v1")
	fpB := UpstreamFingerprint("openai", "https://b.example.com/v1")

	ri := RouteIdentity{OrgID: "org-1", Model: "m", Upstream: fpA}
	base := Provenance{OrgID: "org-1", ModelUsed: "m", Version: RouteVersion}

	assert.False(t, base.Matches(ri),
		"component-blind provenance vs a pinned lookup: miss (pre-guard entries degrade)")
	assert.True(t, func() bool { p := base; p.Upstream = fpA; return p.Matches(ri) }(),
		"matching fingerprints agree")
	assert.False(t, func() bool { p := base; p.Upstream = fpB; return p.Matches(ri) }(),
		"a different endpoint fingerprint must never match")
	assert.False(t, func() bool { p := base; p.Upstream = fpA; ri2 := ri; ri2.Upstream = fpB; return p.Matches(ri2) }(),
		"pinned provenance vs a lookup re-pointed elsewhere must never match")

	// SpaceMatch precedent: strict equality including the empty string, in
	// BOTH directions — a pinned lookup is never compatible with an entry
	// that carries no fingerprint (pre-guard entries degrade to self-healing
	// misses), and two component-blind sides stay compatible so test doubles
	// and unpinned internal identities keep working.
	pinned := RouteIdentity{OrgID: "org-1", Model: "m", Upstream: fpA}
	blind := RouteIdentity{OrgID: "org-1", Model: "m"}
	assert.False(t, base.Matches(pinned), "component-blind entry vs pinned lookup: miss")
	assert.False(t, func() bool { p := base; p.Upstream = fpA; return p.Matches(blind) }(),
		"pinned entry vs component-blind lookup: miss (fail-closed both directions)")
	assert.True(t, base.Matches(blind), "two component-blind sides stay compatible")

	// The other components must stay load-bearing alongside the new one.
	assert.False(t, func() bool { p := base; p.ModelUsed = "other"; return p.Matches(ri) }())
	assert.False(t, func() bool { p := base; p.OrgID = "org-2"; return p.Matches(ri) }())
}

func TestH1_SealOpen_UpstreamRoundTrip(t *testing.T) {
	fp := UpstreamFingerprint("openai", "https://a.example.com/v1")
	ri := RouteIdentity{OrgID: "org-1", Model: "m", Upstream: fp}

	sealed, err := SealEntry([]byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`), ri)
	require.NoError(t, err)

	prov, data, ok := OpenEntry(sealed)
	require.True(t, ok)
	require.NotEmpty(t, data)
	assert.Equal(t, fp, prov.Upstream, "the seal must carry the endpoint fingerprint")
	assert.Equal(t, "org-1", prov.OrgID)
	assert.Equal(t, "m", prov.ModelUsed)
}
