package adminstore

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-SECADM: the sha256 key material of API and agent keys is internal-only
// (`json:"-"`). Every serialized row carries has_hash instead, so HTTP
// clients can tell "a hash is stored" without ever seeing it.

const wsecadmProbeHash = "sha256-wsecadm-probe-deadbeef"

func TestAPIKeyJSON_NeverCarriesKeyHash(t *testing.T) {
	k := &APIKey{
		ID:      "key-1",
		KeyHash: wsecadmProbeHash,
		HasHash: true,
		Name:    "probe",
		Active:  true,
	}
	raw, err := json.Marshal(k)
	require.NoError(t, err)

	assert.NotContains(t, string(raw), wsecadmProbeHash, "key_hash material must never serialize")
	assert.NotContains(t, string(raw), "key_hash", "no key_hash field may appear at all")

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, true, decoded["has_hash"], "has_hash must be present for HTTP callers")
}

func TestAgentKeyJSON_NeverCarriesKeyHash(t *testing.T) {
	k := &AgentKey{
		ID:      "agent-key-1",
		KeyHash: wsecadmProbeHash,
		HasHash: true,
		OrgID:   "org-1",
		Name:    "probe",
		Active:  true,
	}
	raw, err := json.Marshal(k)
	require.NoError(t, err)

	assert.NotContains(t, string(raw), wsecadmProbeHash, "key_hash material must never serialize")
	assert.NotContains(t, string(raw), "key_hash", "no key_hash field may appear at all")

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, true, decoded["has_hash"], "has_hash must be present for HTTP callers")
}

// scanAPIKey derives HasHash from the scanned material.
func TestScanAPIKey_SetsHasHash(t *testing.T) {
	created := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	var k APIKey
	require.NoError(t, scanAPIKey(&mockPGXRow{data: [][]interface{}{{
		"key-1", wsecadmProbeHash, "org-1", "team-1", "opencode", true, created, []byte("{}"), false, false, false, nil, nil,
	}}}, &k))
	assert.True(t, k.HasHash, "a scanned hash must report has_hash=true")
	assert.Equal(t, wsecadmProbeHash, k.KeyHash, "the in-process value stays available to internal callers")
}

// scanAgentKey derives HasHash from the scanned material.
func TestScanAgentKey_SetsHasHash(t *testing.T) {
	created := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	store := newForTest(&mockDB{
		queryFn: func(_ context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
			return &mockPGXRows{data: [][]interface{}{
				{"agent-1", wsecadmProbeHash, "org-1", "bot", true, created, nil, nil, nil, nil},
			}}, nil
		},
	}, newTestLogger(), nil)

	keys, err := store.ListAgentKeys(t.Context(), "org-1")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.True(t, keys[0].HasHash)
	assert.Equal(t, wsecadmProbeHash, keys[0].KeyHash)
	raw, mErr := json.Marshal(keys[0])
	require.NoError(t, mErr)
	assert.NotContains(t, string(raw), wsecadmProbeHash, "the listed row must not serialize the hash")
}
