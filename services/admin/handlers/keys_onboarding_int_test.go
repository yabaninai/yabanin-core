package handlers

// NEXT-01 (F01): the dashboard key-onboarding flow sends name/org_id/key_hash
// WITHOUT team_id, but api_keys.team_id is NOT NULL on the 0001 baseline.
// These tests drive the REAL handler against a disposable, fully migrated
// Postgres — no manual team seeding in helpers — and pin the exact HTTP
// behavior for the missing/foreign-team cases (deterministic 4xx, not a
// raw 500 leaking the SQL error).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newKeysOnboardingH builds the real handler stack on the package-wide
// disposable, fully migrated stand.
func newKeysOnboardingH(t *testing.T) *AdminHandlers {
	t.Helper()
	store := adminstore.New(testdb.Postgres(t), slog.Default(), nil)
	return New(store, "", "", []string{})
}

// seedOnboardingOrg creates a fresh org through the real store (no team).
func seedOnboardingOrg(t *testing.T, h *AdminHandlers) string {
	t.Helper()
	slug := fmt.Sprintf("next01-org-%d", time.Now().UnixNano())
	org, err := h.store.CreateOrganization(context.Background(), "NEXT-01 Org", slug)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.store.DeleteOrganization(context.Background(), org.ID) })
	return org.ID
}

// uniqueKeyHash keeps repeat runs (-count>1, -shuffle) off the shared stand's
// api_keys.key_hash unique index.
func uniqueKeyHash(suffix string) string {
	return fmt.Sprintf("next01-hash-%s-%d", suffix, time.Now().UnixNano())
}

// cleanupKey removes a key created by the test so the shared stand stays
// repeatable.
func cleanupKey(t *testing.T, h *AdminHandlers, body *bytes.Buffer) {
	t.Helper()
	var key adminstore.APIKey
	if err := json.Unmarshal(body.Bytes(), &key); err != nil || key.ID == "" {
		return
	}
	t.Cleanup(func() { _ = h.store.DeleteAPIKey(context.Background(), key.ID) })
}

func postKey(t *testing.T, h *AdminHandlers, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/api-keys", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	h.CreateAPIKey()(rw, req)
	return rw
}

// The UI's exact payload (api/client.ts createAPIKey): no team_id.
// Contract-neutral expectation: a deterministic 4xx, never a 500 with a raw
// SQL error. (Which 4xx the omitted-team case deserves — required-team 400
// vs future default-team resolution — is the recorded owner decision.)
func TestCreateAPIKey_NoTeam_DeterministicClientError(t *testing.T) {
	h := newKeysOnboardingH(t)
	orgID := seedOnboardingOrg(t, h)

	rw := postKey(t, h, map[string]any{
		"name": "ui-key", "org_id": orgID, "key_hash": uniqueKeyHash("noteam"),
	})
	// NEXT-01 owner decision 2026-09-18: default-team fallback — an omitted
	// team_id resolves to the org's default team; the create now succeeds.
	assert.Equal(t, http.StatusCreated, rw.Code, "default-team fallback should create the key; body: %s", rw.Body.String())
	assert.NotContains(t, rw.Body.String(), "SQLSTATE", "raw SQL errors must not leak to the client")
	cleanupKey(t, h, rw.Body)
}

func TestCreateAPIKey_ForeignTeam_RejectedAsClientError(t *testing.T) {
	h := newKeysOnboardingH(t)
	orgA := seedOnboardingOrg(t, h)
	orgB := seedOnboardingOrg(t, h)

	team, err := h.store.CreateTeam(context.Background(), orgB, "B Team", "b-team", nil)
	require.NoError(t, err)

	rw := postKey(t, h, map[string]any{
		"name": "cross-org-key", "org_id": orgA, "key_hash": uniqueKeyHash("foreign"), "team_id": team.ID,
	})
	assert.Equal(t, http.StatusBadRequest, rw.Code, "team of another org must be a 400, body: %s", rw.Body.String())
	assert.NotContains(t, rw.Body.String(), "SQLSTATE", "raw SQL errors must not leak to the client")
}

func TestCreateAPIKey_UnknownTeam_RejectedAsClientError(t *testing.T) {
	h := newKeysOnboardingH(t)
	orgID := seedOnboardingOrg(t, h)

	rw := postKey(t, h, map[string]any{
		"name": "ghost-team-key", "org_id": orgID, "key_hash": "next01-hash-unknown",
		"team_id": "11111111-2222-4333-8444-555555555555",
	})
	assert.Equal(t, http.StatusBadRequest, rw.Code, "unknown team must be a 400, body: %s", rw.Body.String())
}

func TestCreateAPIKey_ValidTeam_CreatesAndResolves(t *testing.T) {
	h := newKeysOnboardingH(t)
	orgID := seedOnboardingOrg(t, h)
	team, err := h.store.CreateTeam(context.Background(), orgID, "Real Team", "real-team", nil)
	require.NoError(t, err)

	rw := postKey(t, h, map[string]any{
		"name": "ok-key", "org_id": orgID, "key_hash": uniqueKeyHash("ok"), "team_id": team.ID,
	})
	require.Equal(t, http.StatusCreated, rw.Code, "body: %s", rw.Body.String())
	cleanupKey(t, h, rw.Body)

	var key adminstore.APIKey
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &key))
	require.NotNil(t, key.TeamID)
	assert.Equal(t, team.ID, *key.TeamID)

	got, err := h.store.GetAPIKeyByID(context.Background(), key.ID)
	require.NoError(t, err)
	assert.True(t, got.Active)
}
