package cli

// failure/boundary tests for the gateway credential source
// a cancelled or failing resolve must fail closed WITHOUT poisoning the
// probe cache (a partial/unknown state never reads as "no credential" or
// "credential"), an interrupted needs_reauth marking must not flip sticky
// state, and malformed stored payloads must produce diagnosable errors that
// carry no key material. (Foreign-tenant denies, rotation races and
// cancel-on-the-real-stack live in mcpcreds_boundary_int_test.go.)

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/mcpagg"
)

// ctxAwareStore honors context cancellation on the resolve/status methods
// the source calls on the request path (the plain double ignores ctx).
type ctxAwareStore struct {
	fakeMCPCredsStore
	resolves atomic.Int64
}

func (f *ctxAwareStore) ResolveMCPUserSecret(ctx context.Context, org, srv, agent string) (string, string, int64, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", "", 0, false, err
	}
	f.resolves.Add(1)
	return f.fakeMCPCredsStore.ResolveMCPUserSecret(ctx, org, srv, agent)
}

func (f *ctxAwareStore) ResolveMCPServerSecret(ctx context.Context, org, srv string) (string, string, int64, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", "", 0, false, err
	}
	return f.fakeMCPCredsStore.ResolveMCPServerSecret(ctx, org, srv)
}

func (f *ctxAwareStore) SetMCPUserCredentialStatus(ctx context.Context, org, srv, agent, status string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.fakeMCPCredsStore.SetMCPUserCredentialStatus(ctx, org, srv, agent, status)
}

// TestMCPCredsSource_CancelledResolve_FailClosedNoCachePoison: a resolve
// killed by cancellation errors out, and the next healthy request still
// resolves the credential — the failure was never cached as a negative.
func TestMCPCredsSource_CancelledResolve_FailClosedNoCachePoison(t *testing.T) {
	store := &ctxAwareStore{fakeMCPCredsStore: fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer user-tok"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
	}}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h, kind, err := src.AuthHeaders(ctx, "org-1", "srv", "ag-1")
	require.Error(t, err, "a cancelled resolve must fail closed")
	require.ErrorIs(t, err, context.Canceled, "the cancellation must stay diagnosable")
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)

	// No poisoned negative: the healthy request resolves immediately.
	h, kind, err = src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer user-tok"}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)

	// No poisoned positive either: the store read stays authoritative.
	h, _, err = src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Positive(t, store.resolves.Load(), "every request must re-resolve the store")
}

// TestMCPCredsSource_TransientResolveError_NeverCachedAsNegative: an
// infrastructure error is not a "no credential" decision — it must not be
// cached as one, or a DB blip would disable credentials for the TTL.
func TestMCPCredsSource_TransientResolveError_NeverCachedAsNegative(t *testing.T) {
	calls := 0
	healthy := `{"Authorization":"Bearer user-tok"}`
	store := &failingOnceStore{fakeMCPCredsStore: &fakeMCPCredsStore{
		userSecret: healthy, userKind: mcpagg.CredKindHeaders, userOK: true,
	}, onResolve: func() error {
		calls++
		if calls == 1 {
			return errors.New("db blip")
		}
		return nil
	}}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Hour})

	_, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.Error(t, err, "a resolve failure must fail closed, not fall back to unauthenticated")
	assert.Equal(t, mcpagg.CredKindNone, kind)

	// The error never became a cached negative: the next call re-probes and
	// serves the credential.
	h, _, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer user-tok"}, h["Authorization"])
}

// failingOnceStore injects one resolve failure into an otherwise healthy
// double.
type failingOnceStore struct {
	*fakeMCPCredsStore
	onResolve func() error
}

func (f *failingOnceStore) ResolveMCPUserSecret(ctx context.Context, org, srv, agent string) (string, string, int64, bool, error) {
	if err := f.onResolve(); err != nil {
		return "", "", 0, false, err
	}
	return f.fakeMCPCredsStore.ResolveMCPUserSecret(ctx, org, srv, agent)
}

// TestMCPCredsSource_CancelledUnauthorizedInterrupt_NoStickyFlip: an
// interrupted needs_reauth marking stays an error and leaves the row's
// status untouched — an interrupted recovery never half-applies.
func TestMCPCredsSource_CancelledUnauthorizedInterrupt_NoStickyFlip(t *testing.T) {
	store := &ctxAwareStore{fakeMCPCredsStore: fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer dead-tok"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
	}}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h, retry, err := src.OnUpstreamUnauthorized(ctx, "org-1", "srv", "ag-1", mcpagg.CredKindHeaders)
	require.Error(t, err, "an interrupted needs_reauth marking must surface, not silently pass")
	require.ErrorIs(t, err, context.Canceled, "the cancellation must stay diagnosable")
	assert.Nil(t, h)
	assert.False(t, retry)
	assert.Empty(t, store.statuses, "an interrupted marking must not flip the sticky status")
}

// TestBuildAuthHeaders_MalformedPayloads_DiagnosableWithoutLeak: malformed
// stored payloads are refused with errors that name the problem but never
// echo the token material.
func TestBuildAuthHeaders_MalformedPayloads_DiagnosableWithoutLeak(t *testing.T) {
	const token = "sk-boundary-token-4f5e6d7c8b9a" //nolint:gosec // G101 false positive: synthetic test literal, not a credential
	tests := []struct {
		name    string
		kind    string
		payload string
	}{
		{"truncated headers json", mcpagg.CredKindHeaders, `{"Authorization":"` + token},
		{"non-object headers", mcpagg.CredKindHeaders, `[` + token + `]`},
		{"empty headers object", mcpagg.CredKindHeaders, `{}`},
		{"truncated oauth json", mcpagg.CredKindOAuth, `{"access_token":"` + token},
		{"oauth without access token", mcpagg.CredKindOAuth, `{"refresh_token":"` + token + `-rt"}`},
		{"unknown kind", "basic", `{"user":"` + token + `"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := buildAuthHeaders(tc.kind, tc.payload)
			require.Error(t, err, "%s must be refused (fail closed)", tc.name)
			assert.Nil(t, h)
			assert.NotContains(t, err.Error(), token,
				"the diagnosable error must not carry the token material")
			assert.NotEmpty(t, err.Error(), "the refusal must stay diagnosable")
		})
	}
}

// TestMCPCredsSource_ZeroValueDecision_NeverReadsAsSuccess pins the store
// polarity at the source boundary: a store reporting ok=false with no error
// is a miss (nil headers, none kind, no error) — never a silent empty
// success carrying partial headers.
func TestMCPCredsSource_ZeroValueDecision_NeverReadsAsSuccess(t *testing.T) {
	store := &fakeMCPCredsStore{userOK: false, srvOK: false}
	src := newMCPCredsSource(mcpCredsSourceConfig{Store: store, TTL: time.Second})

	h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)

	// An oauth payload without an access token is NOT usable: the resolve
	// must miss rather than emit an empty-scheme Authorization header.
	store.userOK = true
	store.userKind = mcpagg.CredKindOAuth
	store.userSecret = `{"refresh_token":"rt-only"}`
	h, kind, err = src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Nil(t, h, "a tokenless oauth payload must not resolve")
	assert.Equal(t, mcpagg.CredKindNone, kind)
}
