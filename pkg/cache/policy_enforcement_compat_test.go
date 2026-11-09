package cache

// Enforcement compatibility corpus for the policy-regime seam of the cache
// service. The seam's contract: with the binding armed, a cache operation is
// served or stored only when the tenant policy regime governing it resolves
// into a fingerprint that can join the route identity unambiguously. Every
// other operation is refused explicitly — no cache read, no write on any
// layer or writer queue, and the refusal is counted in
// CacheEnforcementOffSkippedTotal so silenced traffic stays distinguishable
// from organic misses.
//
// Refused operations:
//   - enforcement off or unverifiable (armed resolver answers "") — pinned
//     by the enforcement-off tests in policy_regime_test.go;
//   - an org-less identity (nothing names the tenant regime that would
//     govern the replay) — pinned here at the unit and service level;
//   - a fingerprint breaking the composition contract (empty after the
//     check above, or carrying the unit separator the composition joins on)
//     — pinned here, including the alias it prevents.
//
// The negative scenarios: a crafted fingerprint must never serve or store
// under an aliased identity (and must not clobber the warm entry), and a
// foreign org's sealed entry planted at the victim's exact key must not
// serve even when both orgs resolve the same regime fingerprint — the org
// provenance seal is the second, independent gate.

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidRegimeFingerprint_Contract(t *testing.T) {
	cases := []struct {
		name string
		fp   string
		want bool
	}{
		{"empty is the enforcement-off answer", "", false},
		{"plain regime token", "r1", true},
		{"hex digest shape (the production form)", "1f2e3d4c5b6a7f80", true},
		{"tag-shaped text without the separator", "polreg:r1", true},
		{"lone separator", "\x1f", false},
		{"fingerprint embedding another regime's composed identity", "r2\x1fpolreg:r1", false},
		{"fingerprint opening with the composition separator", "\x1fpolreg:r1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, validRegimeFingerprint(tc.fp))
		})
	}
}

func TestRegimeResolve_RefusalMatrix(t *testing.T) {
	ctx := context.Background()
	ri := RouteIdentity{OrgID: "org-1", Model: "m-1", GenParams: "high"}
	orgless := RouteIdentity{Model: "m-1", GenParams: "high"}

	cases := []struct {
		name       string
		armed      bool
		fp         string // resolver answer when armed
		ri         RouteIdentity
		wantGated  bool
		wantCalls  int
		wantParams string
	}{
		{
			name: "disarmed keeps the plain identity for a tenant operation",
			ri:   ri, wantGated: false, wantCalls: 0, wantParams: "high",
		},
		{
			name: "disarmed keeps the plain identity for an org-less operation",
			ri:   orgless, wantGated: false, wantCalls: 0, wantParams: "high",
		},
		{
			name:  "armed with a valid fingerprint composes once",
			armed: true, fp: "r1", ri: ri, wantGated: false, wantCalls: 1,
			wantParams: "high\x1fpolreg:r1",
		},
		{
			name:  "armed with the enforcement-off answer refuses",
			armed: true, fp: "", ri: ri, wantGated: true, wantCalls: 1,
			wantParams: "high",
		},
		{
			name:  "armed org-less refuses without consulting the resolver",
			armed: true, fp: "r1", ri: orgless, wantGated: true, wantCalls: 0,
			wantParams: "high",
		},
		{
			name:  "armed with a separator-carrying fingerprint refuses",
			armed: true, fp: "r2\x1fpolreg:r1", ri: ri, wantGated: true, wantCalls: 1,
			wantParams: "high",
		},
		{
			name:  "armed with a separator-prefixed fingerprint refuses",
			armed: true, fp: "\x1fpolreg:r1", ri: ri, wantGated: true, wantCalls: 1,
			wantParams: "high",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := &CacheService{}
			calls := 0
			if tc.armed {
				cs.SetPolicyRegimeResolver(func(context.Context, string) string {
					calls++
					return tc.fp
				})
			}

			before := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
			got, gated := cs.regimeResolve(ctx, tc.ri)
			after := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)

			assert.Equal(t, tc.wantGated, gated)
			assert.Equal(t, tc.wantCalls, calls, "resolver consultation count")
			assert.Equal(t, tc.wantParams, got.GenParams,
				"a refused operation must come back uncomposed, a served one composed once")
			wantSkips := 0
			if tc.wantGated {
				wantSkips = 1
			}
			assert.InDelta(t, before+float64(wantSkips), after, 0,
				"every refusal ticks the skip counter exactly once, a served operation none")
		})
	}
}

func TestComposeRegimeGenParams_InjectiveForValidFingerprints(t *testing.T) {
	// Over the contract-respecting inputs the composition must be injective:
	// two distinct (parameters, fingerprint) pairs never compose to the same
	// identity string, so a stored entry can only be served by a lookup that
	// resolved the very same regime.
	params := []string{"", "low", "high", "high\x1fpolreg:r1"}
	fps := []string{"r1", "r2", "r10", "polreg:r1"}
	seen := make(map[string]string)
	for _, p := range params {
		for _, f := range fps {
			require.True(t, validRegimeFingerprint(f), "grid fingerprints must satisfy the contract: %q", f)
			composed := composeRegimeGenParams(p, f)
			owner, collision := seen[composed]
			require.False(t, collision, "(%q, %q) collides with %s", p, f, owner)
			seen[composed] = "(" + p + "," + f + ")"
		}
	}

	// What the validation buys: a fingerprint crafted to embed another
	// regime's composed parameters would alias the identity of a different
	// (parameters, fingerprint) pair. The gate refuses such a fingerprint,
	// so the alias is unreachable through the boundary.
	assert.Equal(t,
		composeRegimeGenParams("high\x1fpolreg:r2", "r1"),
		composeRegimeGenParams("high", "r2\x1fpolreg:r1"),
		"without validation these distinct pairs would share one identity")
	assert.False(t, validRegimeFingerprint("r2\x1fpolreg:r1"))
}

// TestService_RegimeRefusal_Orgless_NoReadNoWriteNoQueue pins the org-less
// refusal on a live Redis: with the binding armed, a cache operation that
// carries no org is refused before any layer is touched, while the same
// operation with an org is governed normally — the refusal is surgical, not
// a global silencing. A poison entry planted at the org-less key must stay
// untouched: unread, and never overwritten by the refused write.
func TestService_RegimeRefusal_Orgless_NoReadNoWriteNoQueue(t *testing.T) {
	rdb := redisContainer(t)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	cs := newRoutedTestService(rdb)
	cs.SetPolicyRegimeResolver(func(_ context.Context, org string) string {
		if org == "" {
			return "unreachable" // the gate must refuse before consulting the resolver
		}
		return "r1"
	})
	ctx := context.Background()

	model := "m-1"
	body := []byte(`{"messages":[{"role":"user","content":"orgless"}]}`)
	resp := []byte(`{"id":"poison","choices":[{"message":{"content":"forbidden?"}}]}`)
	hash := ComputePromptHash(normalizeForCache(body))
	key0 := MakeKey("", model, hash)

	// A poisoned entry sits at exactly the key an ungated org-less lookup
	// would read and an ungated org-less write would overwrite.
	plainRI := RouteIdentity{Model: model}.Resolved()
	sealed, err := SealEntry(resp, plainRI)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(ctx, key0, sealed, time.Hour).Err())

	// Lookup: refused — no read, no serve, one skip counted.
	before := counter.snapshot()
	skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	hit, err := cs.LookupWithResult(ctx, RouteIdentity{Model: model}, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "an org-less lookup must be refused, not served")
	after := counter.snapshot()
	assert.Zero(t, after["get"]-before["get"], "the refusal must not read the cache")
	assert.InDelta(t, skips+1, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0)

	// Write: refused — no store, no writer-queue touch, one skip counted.
	q0, d0, w0 := cs.WriterStats()
	before = counter.snapshot()
	skips = testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	require.NoError(t, cs.Write(ctx, RouteIdentity{Model: model}, body, resp, 1, 1))
	after = counter.snapshot()
	assert.Zero(t, after["set"]-before["set"], "the refusal must not store on the exact layer")
	q1, d1, w1 := cs.WriterStats()
	assert.Equal(t, q0, q1, "the refusal must not queue a pgvector job")
	assert.Equal(t, d0, d1)
	assert.Equal(t, w0, w1)
	assert.InDelta(t, skips+1, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0)

	// The poison entry is untouched: the refusal neither served nor
	// overwrote it.
	raw, err := rdb.Get(ctx, key0).Bytes()
	require.NoError(t, err)
	assert.Equal(t, sealed, raw, "the refused operations must leave the key byte-identical")

	// Contrast: the same operations WITH an org are governed and do reach
	// the layers — read on lookup, store plus queue-drop on write (the test
	// writer is born stopped).
	ri := RouteIdentity{OrgID: "org-1", Model: model}
	before = counter.snapshot()
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "no warm entry for the org yet")
	assert.Positive(t, counter.snapshot()["get"]-before["get"],
		"a governed lookup does read the cache")

	require.NoError(t, cs.Write(ctx, ri, body, resp, 1, 1))
	q2, d2, w2 := cs.WriterStats()
	assert.Equal(t, q0, q2)
	assert.Equal(t, d0+1, d2, "the governed write reaches the writer queue (dropped by the stopped test writer)")
	assert.Equal(t, w0, w2)
	raw, err = rdb.Get(ctx, MakeKey("org-1", model, hash)).Bytes()
	require.NoError(t, err)
	assert.NotEqual(t, sealed, raw, "the governed write stores its own sealed entry")
}

// TestService_AmbiguousFingerprint_Window_NoServeNoStore pins the refusal of
// a contract-breaking fingerprint on a live Redis. While the resolver
// answers a fingerprint carrying the composition separator, the cache must
// neither serve nor store — even against a planted entry sealed under the
// very identity the ambiguous fingerprint would compose — and must leave the
// warm entry byte-identical. Back under a valid fingerprint, the service
// recovers through its own write path.
func TestService_AmbiguousFingerprint_Window_NoServeNoStore(t *testing.T) {
	rdb := redisContainer(t)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	cs := newRoutedTestService(rdb)
	fp := "r1"
	cs.SetPolicyRegimeResolver(func(context.Context, string) string { return fp })
	ctx := context.Background()

	org, model := "org-amb", "m-1"
	body := []byte(`{"messages":[{"role":"user","content":"ambiguous"}]}`)
	resp1 := []byte(`{"id":"v1","choices":[{"message":{"content":"pre-window"}}]}`)
	hash := ComputePromptHash(normalizeForCache(body))
	key := MakeKey(org, model, hash)
	ri := RouteIdentity{OrgID: org, Model: model, GenParams: "high"}

	// Baseline: a governed write lands and serves warm.
	require.NoError(t, cs.Write(ctx, ri, body, resp1, 1, 1))
	hit, err := cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(resp1), string(hit.Data))
	warm, err := rdb.Get(ctx, key).Bytes()
	require.NoError(t, err)

	// Enter the ambiguous window: the crafted fingerprint composes to the
	// identity a planted entry below is sealed under.
	fp = "r2\x1fpolreg:r1"

	// The window stores nothing: the warm bytes stay untouched, the writer
	// queue is not touched either.
	skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	q0, d0, w0 := cs.WriterStats()
	require.NoError(t, cs.Write(ctx, ri, body, []byte(`{"id":"evil"}`), 1, 1))
	assert.InDelta(t, skips+1, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0)
	q1, d1, w1 := cs.WriterStats()
	assert.Equal(t, q0, q1)
	assert.Equal(t, d0, d1)
	assert.Equal(t, w0, w1)
	raw, err := rdb.Get(ctx, key).Bytes()
	require.NoError(t, err)
	assert.Equal(t, warm, raw, "the refused write must leave the warm entry byte-identical")

	// Plant an entry sealed under the ambiguous identity: without the gate,
	// a lookup under the crafted fingerprint would compose exactly this
	// identity and serve the planted bytes.
	ambRI := RouteIdentity{OrgID: org, Model: model, GenParams: composeRegimeGenParams("high", fp)}.Resolved()
	planted, err := SealEntry([]byte(`{"id":"planted","choices":[{"message":{"content":"aliased"}}]}`), ambRI)
	require.NoError(t, err)
	require.NoError(t, rdb.Set(ctx, key, planted, time.Hour).Err())

	// The lookup is refused before any read: the planted, identity-matching
	// entry must not serve.
	before := counter.snapshot()
	skips = testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "an ambiguous fingerprint must refuse the lookup even against a matching planted entry")
	after := counter.snapshot()
	assert.Zero(t, after["get"]-before["get"], "the refusal must not read the cache")
	assert.InDelta(t, skips+1, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0)

	// Back under a valid fingerprint: the planted entry does not match the
	// r1 identity, and a governed rewrite recovers the warm path.
	fp = "r1"
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "the planted ambiguous identity must not serve under the valid regime either")
	require.NoError(t, cs.Write(ctx, ri, body, resp1, 1, 1))
	hit, err = cs.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(resp1), string(hit.Data), "the service recovers through its own write path")
}

// TestService_CrossOrg_RegimeSealed_PlantRejected binds the two independent
// seals into one negative: a foreign org's sealed entry planted at the
// victim's exact key must not serve even when both orgs resolve the SAME
// regime fingerprint — the org provenance seal rejects the replay, and a
// governed miss must stay distinguishable from a refusal (no skip counted).
func TestService_CrossOrg_RegimeSealed_PlantRejected(t *testing.T) {
	rdb := redisContainer(t)
	counter := &redisCmdCounter{counts: map[string]int{}}
	rdb.AddHook(counter)
	cs := newRoutedTestService(rdb)
	cs.SetPolicyRegimeResolver(func(_ context.Context, _ string) string { return "r1" })
	ctx := context.Background()

	model := "m-1"
	body := []byte(`{"messages":[{"role":"user","content":"cross-org-regime"}]}`)
	respA := []byte(`{"id":"orga","choices":[{"message":{"content":"org-a secret"}}]}`)
	respB := []byte(`{"id":"orgb","choices":[{"message":{"content":"org-b content"}}]}`)
	hash := ComputePromptHash(normalizeForCache(body))

	riA := RouteIdentity{OrgID: "org-a", Model: model}
	require.NoError(t, cs.Write(ctx, riA, body, respA, 1, 1))
	foreign, err := rdb.Get(ctx, MakeKey("org-a", model, hash)).Bytes()
	require.NoError(t, err)

	// Plant org-a's sealed blob at org-b's exact key. The blob carries
	// org-a's provenance seal and the same regime fingerprint org-b
	// resolves — only the org seal can reject it.
	require.NoError(t, rdb.Set(ctx, MakeKey("org-b", model, hash), foreign, time.Hour).Err())

	skips := testutil.ToFloat64(CacheEnforcementOffSkippedTotal)
	hit, err := cs.LookupWithResult(ctx, RouteIdentity{OrgID: "org-b", Model: model}, body)
	require.NoError(t, err)
	assert.Nil(t, hit, "a foreign org's regime-sealed entry must not serve at the victim's key")
	assert.InDelta(t, skips, testutil.ToFloat64(CacheEnforcementOffSkippedTotal), 0,
		"a governed miss is not a refusal — no skip counted")

	// The victim's own governed write lands and serves; the plant is gone.
	require.NoError(t, cs.Write(ctx, RouteIdentity{OrgID: "org-b", Model: model}, body, respB, 1, 1))
	hit, err = cs.LookupWithResult(ctx, RouteIdentity{OrgID: "org-b", Model: model}, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respB), string(hit.Data))
	assert.NotEqual(t, string(respA), string(hit.Data))
}
