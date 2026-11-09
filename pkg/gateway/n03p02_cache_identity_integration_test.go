//go:build integration

package cli

// N03-P02-T03 acceptance on real plumbing: the tenant policy regime binds the
// cache route identity, so a warm entry stored under an earlier policy
// snapshot degrades to a real miss after the policy tightens — on the exact
// layer AND on the semantic (pgvector) layer — while foreign-org entries and
// unchanged-regime entries keep serving. The tighten goes through the REAL
// control plane (adminstore mutations + the real Redis version bumper) and
// the fingerprint through a real PolicyRuntime over that store, with the
// regime resolver armed on the real CacheService exactly like the production
// wiring (wireCacheService → SetPolicyRegimeResolver(gw.policyCacheRegime)).
//
// The identity layer is exercised through the production CacheService entry
// points (LookupWithResult/Write); serve-time re-governance on top of a
// served hit is covered by the existing cache-integration suite. All stands
// here are disposable per-test Docker containers.

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/cache"
)

func TestN03P02_Integration_PolicyRegimeBindsCacheIdentity(t *testing.T) {
	env := r011ITSetup(t, "n03p02-it-marker")
	logger := slog.New(slog.DiscardHandler)
	runtime, err := NewPolicyRuntime(env.store, env.versions, PolicyModeEnforce, nil, logger)
	require.NoError(t, err, "construct the policy runtime over the real store")
	gw := testHookGateway(runtime)
	env.cacheSvc.SetPolicyRegimeResolver(gw.policyCacheRegime)

	ctx := context.Background()
	orgA := r011ITNewOrg(t, env, "n03a", "semantic")
	orgB := r011ITNewOrg(t, env, "n03b", "semantic")

	// The regime fingerprint is stable per org (org-a and org-b start with
	// identical empty snapshots, so equal digests are correct here; the
	// org-scoping assertions bite after the tighten below).
	fpA0 := gw.policyCacheRegime(ctx, orgA.id)
	require.NotEmpty(t, fpA0)
	require.Equal(t, fpA0, gw.policyCacheRegime(ctx, orgA.id))
	fpB0 := gw.policyCacheRegime(ctx, orgB.id)
	require.NotEmpty(t, fpB0)

	// Warm org-a under regime v0 (no policies attached yet), through both
	// backends: the exact layer synchronously, the pgvector semantic layer
	// asynchronously.
	ri := cache.RouteIdentity{OrgID: orgA.id, Model: "n03p02-it-model", GenParams: "high"}
	body := []byte(`{"model":"n03p02-it-model","messages":[{"role":"user","content":"n03p02 prompt"}]}`)
	respV1 := []byte(`{"id":"n03-v1","choices":[{"message":{"role":"assistant","content":"pre-tighten"}}]}`)

	hit, err := env.cacheSvc.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.Nil(t, hit, "cold lookup must miss")

	_, _, writeBaseline := env.cacheSvc.WriterStats()
	require.NoError(t, env.cacheSvc.Write(ctx, ri, body, respV1, 1, 2))
	hit, err = env.cacheSvc.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respV1), string(hit.Data), "same regime serves the warm exact entry")
	r011ITWaitCacheWrite(t, env, writeBaseline)

	// Foreign org: same prompt, own entry — org-a's data never serves.
	riB := cache.RouteIdentity{OrgID: orgB.id, Model: "n03p02-it-model", GenParams: "high"}
	respB := []byte(`{"id":"n03-b","choices":[{"message":{"role":"assistant","content":"org-b own"}}]}`)
	require.NoError(t, env.cacheSvc.Write(ctx, riB, body, respB, 1, 1))
	hitB, err := env.cacheSvc.LookupWithResult(ctx, riB, body)
	require.NoError(t, err)
	require.NotNil(t, hitB)
	assert.JSONEq(t, string(respB), string(hitB.Data), "org-b must be served its own entry only")

	// TIGHTEN org-a through the real control plane: CreatePolicy + publish +
	// attach + enable, with the real Redis version bump asserted inside.
	r011ITAttachDeny(t, env, orgA, "n03p02-it-marker")

	fpA1 := gw.policyCacheRegime(ctx, orgA.id)
	require.NotEqual(t, fpA0, fpA1, "the tighten must move org-a's regime fingerprint")
	require.Equal(t, fpB0, gw.policyCacheRegime(ctx, orgB.id), "org-b's regime must stay untouched")

	// ACCEPTANCE: org-a's warm entry — cached under the earlier policy regime
	// — is no longer a hit on any layer. The exact entry mismatches on
	// provenance, and the semantic candidate (already persisted above)
	// mismatches the same way: the stale entry cannot bypass.
	hit, err = env.cacheSvc.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.Nil(t, hit, "a warm entry stored under the earlier policy regime must degrade to a real miss after the tighten")

	// org-b keeps serving under its unchanged regime — the tighten is
	// org-scoped, not a fleet-wide flush.
	hitB, err = env.cacheSvc.LookupWithResult(ctx, riB, body)
	require.NoError(t, err)
	require.NotNil(t, hitB)
	assert.JSONEq(t, string(respB), string(hitB.Data))

	// Refill under the new regime: the fresh response becomes the warm entry.
	respV2 := []byte(`{"id":"n03-v2","choices":[{"message":{"role":"assistant","content":"post-tighten"}}]}`)
	require.NoError(t, env.cacheSvc.Write(ctx, ri, body, respV2, 1, 2))
	hit, err = env.cacheSvc.LookupWithResult(ctx, ri, body)
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.JSONEq(t, string(respV2), string(hit.Data), "the refilled entry serves under the new regime")
}
