package cache

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RT-05: an entry may only be served when its stored provenance matches the
// route identity performing the lookup. These tests pin the envelope format
// and the match contract without Redis: the handler-level regressions
// (pkg/gateway rt05 tests) and the container roundtrips cover the wiring.

func TestSealOpenEntry_RoundTrip(t *testing.T) {
	ri := RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}
	sealed, err := SealEntry([]byte(`{"id":"c1"}`), ri)
	require.NoError(t, err)

	prov, data, ok := OpenEntry(sealed)
	require.True(t, ok, "sealed entry must open")
	assert.Equal(t, "org-1", prov.OrgID)
	assert.Equal(t, "m-1", prov.ModelUsed)
	assert.Equal(t, RouteVersion, prov.Version)
	assert.Equal(t, "high", prov.GenParams)
	assert.JSONEq(t, `{"id":"c1"}`, string(data))
	assert.True(t, prov.Matches(ri), "the producing identity must match its own entry")
}

func TestOpenEntry_LegacyRawPayload_IsNotVerifiable(t *testing.T) {
	// A pre-RT-05 entry is a raw completion document: no envelope, no
	// provenance. It must open as false — a miss, never a hit.
	prov, data, ok := OpenEntry([]byte(`{"id":"legacy","choices":[]}`))
	assert.False(t, ok)
	assert.Empty(t, prov.ModelUsed)
	assert.Nil(t, data)
}

func TestOpenEntry_TruncatedAndForeignFormats_Miss(t *testing.T) {
	for name, raw := range map[string][]byte{
		"truncated":  []byte(`{"route":"v2","prov":{`),
		"empty":      {},
		"json-array": []byte(`[1,2,3]`),
		"no-data":    []byte(`{"route":"v2","prov":{"org":"o","model_used":"m"}}`),
		"no-model":   []byte(`{"route":"v2","prov":{"org":"o"},"data":{"x":1}}`),
		"no-org":     []byte(`{"route":"v2","prov":{"model_used":"m"},"data":{"x":1}}`),
		"no-route":   []byte(`{"prov":{"org":"o","model_used":"m"},"data":{"x":1}}`),
	} {
		_, _, ok := OpenEntry(raw)
		assert.False(t, ok, "%s must not open as a verifiable entry", name)
	}
}

func TestProvenance_Matches_IdentityDimensions(t *testing.T) {
	base := RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}
	sealed, err := SealEntry([]byte(`{"id":"c1"}`), base)
	require.NoError(t, err)
	prov, _, ok := OpenEntry(sealed)
	require.True(t, ok)

	assert.True(t, prov.Matches(base))
	assert.False(t, prov.Matches(RouteIdentity{OrgID: "org-2", Model: "m-1", GenParams: "high"}),
		"a foreign org's entry must not match")
	assert.False(t, prov.Matches(RouteIdentity{OrgID: "org-1", Model: "m-2", GenParams: "high"}),
		"an entry of another route model must not match")
	assert.False(t, prov.Matches(RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "low"}),
		"an entry generated under other generation parameters must not match")
	assert.False(t, prov.Matches(RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high", Version: "v2"}),
		"an entry of another route namespace (here: the pre-CACHE-02 v2 namespace) must not match")
}

func TestSealEntry_EmptyResponse_Refused(t *testing.T) {
	_, err := SealEntry(nil, RouteIdentity{OrgID: "org-1", Model: "m"})
	assert.Error(t, err, "an entry without a response must not be storable")
}

func TestRouteIdentity_Resolved_DefaultVersion(t *testing.T) {
	ri := RouteIdentity{OrgID: "org-1", Model: "m"}.Resolved()
	assert.Equal(t, RouteVersion, ri.Version)
	assert.Equal(t, "v3", ri.Version) // CACHE-02 namespace bump pin (see normalize_numbers_test.go)
}

func TestEnvelope_BytesAreStableJSON(t *testing.T) {
	sealed, err := SealEntry([]byte(`{"a":1}`), RouteIdentity{OrgID: "o", Model: "m"})
	require.NoError(t, err)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(sealed, &raw))
	assert.Contains(t, raw, "route")
	assert.Contains(t, raw, "prov")
	assert.Contains(t, raw, "data")
}
