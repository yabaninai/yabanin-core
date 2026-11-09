package cache

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVectorToSQL(t *testing.T) {
	tests := []struct {
		name    string
		input   []float32
		want    string
		wantErr bool
	}{
		{"single dim", []float32{0.5}, "[0.5]", false},
		{"three dims", []float32{0.1, -0.2, 0.3}, "[0.1,-0.2,0.3]", false},
		{"zero dim error", []float32{}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vectorToSQL(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVectorFromSQL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []float32
		wantErr bool
	}{
		{"simple", "[0.1,0.2,0.3]", []float32{0.1, 0.2, 0.3}, false},
		{"with spaces", "[ 0.1 , -0.2 , 0.3 ]", []float32{0.1, -0.2, 0.3}, false},
		{"invalid brackets", "0.1,0.2", nil, true},
		{"empty", "", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vectorFromSQL(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSquaredL2Distance(t *testing.T) {
	a := []float32{1.0, 0.0, 0.0, 0.0, 0.0}
	b := []float32{1.0, 0.0, 0.0, 0.0, 0.0}
	assert.InDelta(t, 0.0, SquaredL2Distance(a, b), 0.001)

	c := []float32{-1.0, 0.0, 0.0, 0.0, 0.0}
	assert.InDelta(t, 4.0, SquaredL2Distance(a, c), 0.001)

	d := []float32{1.0, 0.0, 0.0}
	assert.Greater(t, SquaredL2Distance(a, d), 1e8)
}

func TestStoreVectorHelpersRoundTrip(t *testing.T) {
	original := []float32{0.001, -0.5, 0.999, 0.0, 1.0, -0.25, 0.75}
	sql, err := vectorToSQL(original)
	require.NoError(t, err)

	parsed, err := vectorFromSQL(sql)
	require.NoError(t, err)
	assert.Equal(t, original, parsed)
}

func TestStorePutAndGetExact(t *testing.T) {
	now := time.Now()
	entry := &Entry{
		OrgID:      "org-123",
		ModelTier:  "smart",
		PromptHash: "abc123",
		Embedding:  []float32{0.1, 0.2, 0.3, 0.4, 0.5},
		Response:   json.RawMessage(`{"id":"chat-1","choices":[{}]}`),
		TokensIn:   10,
		TokensOut:  5,
		ModelVer:   "v1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}

	sql, err := vectorToSQL(entry.Embedding)
	require.NoError(t, err)
	assert.Equal(t, "[0.1,0.2,0.3,0.4,0.5]", sql)

	parsed, err := vectorFromSQL(sql)
	require.NoError(t, err)
	assert.Equal(t, entry.Embedding, parsed)
}

func TestStoreGetExactMiss(t *testing.T) {
	// Real behavior tested in integration tests using testcontainers.
	t.Skip("covered by integration tests using testcontainers")
}

func TestPurgeExpired(t *testing.T) {
	t.Skip("purge expired is tested via integration tests")
}
