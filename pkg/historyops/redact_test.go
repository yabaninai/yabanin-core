package historyops

// Unit coverage for the redact_content runner's pure logic (ENT-HIST-04):
// plan-id encoding, batch chunking, config defaults, and the checkpoint
// defenses that fire before any database access. Database behavior is pinned
// in redact_int_test.go on a real PostgreSQL stand.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlanIDRoundTrip(t *testing.T) {
	for _, family := range SelectableFamilies {
		id := encodePlanID(family, "1729")
		gotFamily, raw, err := decodePlanID(id)
		require.NoError(t, err, id)
		assert.Equal(t, family, gotFamily, id)
		assert.Equal(t, "1729", raw, id)
	}
	// A uuid-shaped id survives too (cache_entries/sessions plans).
	f, raw, err := decodePlanID("cache_entries/6f1e9c76-9f9e-4a1e-b0a2-6f3e1e9b7d01")
	require.NoError(t, err)
	assert.Equal(t, FamilyCacheEntries, f)
	assert.Equal(t, "6f1e9c76-9f9e-4a1e-b0a2-6f3e1e9b7d01", raw)
}

func TestDecodePlanIDRejectsMalformed(t *testing.T) {
	for _, malformed := range []string{
		"1729",                // no family prefix
		"nonsense/1729",       // unknown family
		"request_lineage/12",  // protected family is not selectable
		"policy_decisions/12", // protected family is not selectable
		"/12",                 // empty family name
	} {
		_, _, err := decodePlanID(malformed)
		require.Error(t, err, malformed)
		if errors.Is(err, ErrInvalidRequest) {
			continue // malformed-checkpoint class, as designed
		}
		refusal, ok := RefusalOf(err)
		require.True(t, ok, "%s: expected refusal or ErrInvalidRequest", malformed)
		assert.Equal(t, RefusalProtectedFamily, refusal.Code, malformed)
	}
}

func TestChunkIDs(t *testing.T) {
	assert.Nil(t, chunkIDs(nil, 3), "empty plan yields no batches")

	seven := []string{"1", "2", "3", "4", "5", "6", "7"}
	batches := chunkIDs(seven, 3)
	require.Len(t, batches, 3)
	assert.Equal(t, []string{"1", "2", "3"}, batches[0])
	assert.Equal(t, []string{"4", "5", "6"}, batches[1])
	assert.Equal(t, []string{"7"}, batches[2])

	assert.Len(t, chunkIDs(seven, 7), 1, "exact fit stays one batch")
	assert.Len(t, chunkIDs(seven, 100), 1, "size above len stays one batch")

	// Every id appears exactly once, order preserved.
	var flat []string
	for _, b := range chunkIDs(seven, 2) {
		flat = append(flat, b...)
	}
	assert.Equal(t, seven, flat)
}

func TestRedactRunnerConfigDefaults(t *testing.T) {
	assert.Equal(t, defaultRedactBatchSize, NewRedactRunner(nil, RedactConfig{}).batchSize)
	assert.Equal(t, defaultRedactBatchSize, NewRedactRunner(nil, RedactConfig{BatchSize: -5}).batchSize)
	assert.Equal(t, 42, NewRedactRunner(nil, RedactConfig{BatchSize: 42}).batchSize)
}

// The checkpoint defenses must fire before any database access: a corrupted
// plan id or a plan naming a family outside the selection fails the batch
// without a pool (nil pool would panic if the code path reached BeginTx).
func TestExecuteBatchRejectsCorruptedPlanBeforeDB(t *testing.T) {
	runner := NewRedactRunner(nil, RedactConfig{})
	job := &Job{
		OrgID: testOrg,
		Op:    OpRedactContent,
		Selection: func() Selection {
			sel, err := NewSelection(testOrg, "", closedPeriod(), []Family{FamilyRequestLogs},
				SelectionFilters{}, newFakeClock().Now())
			require.NoError(t, err)
			return sel
		}(),
	}

	_, err := runner.ExecuteBatch(t.Context(), job, 0, []string{"not-a-plan-id"})
	require.ErrorIs(t, err, ErrInvalidRequest, "malformed plan id")

	_, err = runner.ExecuteBatch(t.Context(), job, 0, []string{
		encodePlanID(FamilyCacheEntries, "6f1e9c76-9f9e-4a1e-b0a2-6f3e1e9b7d01"),
	})
	require.ErrorIs(t, err, ErrInvalidRequest, "family outside selection")
}
