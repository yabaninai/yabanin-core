package cli

// N05-P02-T02 (I54) credential-mode matrix for the gateway source: the
// connection configuration's credential_mode selects which credential layer
// may authorize an invoke — service never consults the user layer, delegated
// NEVER silently escalates a user miss to the service credential, auto is
// the legacy chain, and a mode-lookup failure is fail-closed.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/mcpagg"
)

// srvCallsCountingStore counts server-level resolutions so the delegated
// no-fallback pin can prove the service layer is never even consulted.
type srvCallsCountingStore struct {
	fakeMCPCredsStore
	srvCalls int
}

func (f *srvCallsCountingStore) ResolveMCPServerSecret(ctx context.Context, orgID, serverName string) (string, string, int64, bool, error) {
	f.mu.Lock()
	f.srvCalls++
	f.mu.Unlock()
	return f.fakeMCPCredsStore.ResolveMCPServerSecret(ctx, orgID, serverName)
}

func modeSource(store MCPCredsStore) *mcpCredsSource {
	return newMCPCredsSource(mcpCredsSourceConfig{
		Store: store,
		TTL:   time.Second,
		Now:   func() time.Time { return time.Unix(0, 0) },
	})
}

func modeFixture(mode string) *fakeMCPCredsStore {
	store := &fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer user-tok"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
		srvSecret: `{"Authorization":"Bearer srv-tok"}`, srvKind: mcpagg.CredKindHeaders, srvOK: true,
		srvMode: mode,
	}
	modeSource(store)
	return store
}

func TestMCPCredsMode_AutoIsLegacyChain(t *testing.T) {
	store := &fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer user-tok"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
		srvSecret: `{"Authorization":"Bearer srv-tok"}`, srvKind: mcpagg.CredKindHeaders, srvOK: true,
		srvMode: mcpagg.CredModeAuto,
	}
	src := modeSource(store)

	// Per-user wins over server-level.
	h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer user-tok"}, h["Authorization"], "auto: the per-user credential wins")
	assert.Equal(t, mcpagg.CredKindHeaders, kind)

	// The explicit empty mode (unmigrated row) behaves identically.
	emptySrc := modeSource(&fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer user-tok"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
		srvSecret: `{"Authorization":"Bearer srv-tok"}`, srvKind: mcpagg.CredKindHeaders, srvOK: true,
	})
	h2, _, err := emptySrc.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer user-tok"}, h2["Authorization"])
}

func TestMCPCredsMode_ServiceNeverConsultsUserLayer(t *testing.T) {
	counting := &srvCallsCountingStore{}
	store := &counting.fakeMCPCredsStore
	store.userSecret = `{"Authorization":"Bearer user-tok"}`
	store.userKind = mcpagg.CredKindHeaders
	store.userOK = true
	store.srvSecret = `{"Authorization":"Bearer srv-tok"}`
	store.srvKind = mcpagg.CredKindHeaders
	store.srvOK = true
	store.srvMode = mcpagg.CredModeService
	src := modeSource(counting)

	h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, []string{"Bearer srv-tok"}, h["Authorization"], "service mode: only the service credential")
	assert.Equal(t, mcpagg.CredKindHeaders, kind)
	assert.Equal(t, 1, counting.srvCalls)
}

func TestMCPCredsMode_ServiceMissingCredentialIsMiss(t *testing.T) {
	// The service credential is absent (or not applicable) while a user
	// credential exists: still a miss — the user layer is never consulted.
	store := modeFixture(mcpagg.CredModeService)
	store.srvOK = false
	src := modeSource(store)

	h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)
	assert.True(t, store.userOK, "precondition: a usable user credential exists but must be ignored")
}

func TestMCPCredsMode_DelegatedNeverEscalatesToService(t *testing.T) {
	// I54 negative pin: the user credential is unavailable and the service
	// credential EXISTS and is usable — the invoke must still miss. The
	// gateway must not silently fall back to the more privileged layer.
	counting := &srvCallsCountingStore{}
	store := &counting.fakeMCPCredsStore
	store.srvSecret = `{"Authorization":"Bearer srv-tok"}`
	store.srvKind = mcpagg.CredKindHeaders
	store.srvOK = true
	store.srvMode = mcpagg.CredModeDelegated
	src := modeSource(counting)

	h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Nil(t, h, "delegated: a user miss must never fall back to the service credential")
	assert.Equal(t, mcpagg.CredKindNone, kind)
	assert.Equal(t, 0, counting.srvCalls, "the service layer must not even be consulted")
}

func TestMCPCredsMode_DelegatedUserCredServed(t *testing.T) {
	store := modeFixture(mcpagg.CredModeDelegated)
	src := modeSource(store)

	h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer user-tok"}, h["Authorization"])
	assert.Equal(t, mcpagg.CredKindHeaders, kind)
}

func TestMCPCredsMode_OAuthKindApplicabilityPerMode(t *testing.T) {
	// An oauth credential without an access_token is not applicable in any
	// mode — the mode selects the layer, the kind applicability stays.
	for _, mode := range append([]string{""}, mcpagg.CredentialModes...) {
		store := modeFixture(mode)
		src := modeSource(store)
		store.srvKind = mcpagg.CredKindOAuth
		store.srvSecret = `{"refresh_token":"rt"}` // no access_token
		store.userOK = false

		h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
		require.NoError(t, err)
		assert.Nil(t, h, "mode %q: unusable oauth secret must be a miss", mode)
		assert.Equal(t, mcpagg.CredKindNone, kind, "mode %q", mode)
	}
}

func TestMCPCredsMode_LookupFailureFailsClosed(t *testing.T) {
	// A mode-read infrastructure error must not resolve any layer: egressing
	// without knowing the mode could silently escalate (I54).
	store := &fakeMCPCredsStore{
		userSecret: `{"Authorization":"Bearer user-tok"}`, userKind: mcpagg.CredKindHeaders, userOK: true,
		srvSecret: `{"Authorization":"Bearer srv-tok"}`, srvKind: mcpagg.CredKindHeaders, srvOK: true,
		modeErr: errors.New("db down"),
	}
	src := modeSource(store)

	h, kind, err := src.AuthHeaders(context.Background(), "org-1", "srv", "ag-1")
	require.Error(t, err)
	assert.Nil(t, h)
	assert.Equal(t, mcpagg.CredKindNone, kind)
	assert.Contains(t, err.Error(), "credential mode")
}

func TestMCPCredsMode_ServiceModeIgnoresUserRefreshPath(t *testing.T) {
	// OnUpstreamUnauthorized in service mode: the server-level credential is
	// authoritative and (by the frozen MC-1 posture) never self-refreshes;
	// the flow answer is the headers-kind auth-required regardless of any
	// user state.
	store := modeFixture(mcpagg.CredModeService)
	src := modeSource(store)

	headers, retry, err := src.OnUpstreamUnauthorized(context.Background(), "org-1", "srv", "ag-1", mcpagg.CredKindHeaders)
	require.NoError(t, err)
	assert.Nil(t, headers)
	assert.False(t, retry, "server-level creds do not self-refresh (frozen posture)")
	assert.True(t, store.userOK, "precondition: the user layer exists but service mode ignores it")
}
