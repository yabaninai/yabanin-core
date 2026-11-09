package consumer

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Valid canonical UUIDs used as passthrough fixtures across consumer tests.
const (
	testSessionUUID = "3f2b8a4c-9d1e-4f5a-8b7c-6e5d4c3b2a10"
	testTeamUUID    = "7c1e9a2b-3d4f-4a5b-9c8d-0e1f2a3b4c5d"
	testAgentUUID   = "b2c3d4e5-6f7a-4b8c-9d0e-1f2a3b4c5d6e"
	testOrgUUID     = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
)

// Golden vectors for the deterministic v5 mapping. They pin BOTH the input
// set and nsRequestLogs: editing the namespace or the mapping breaks storage
// compatibility and must be a deliberate migration, not a drive-by change.
const (
	goldenOpenCodeSession = "4dbfc67b-6ed9-5942-a9b6-53770ac48875" // ses_f7c8cea03ffeQF8w3WLp7oRA9w
	goldenStandSession    = "14a6474c-661b-53cc-9c85-7eae61fcc39a" // ses_testNonUuid123
)

func TestUUIDField_EmptyStringBecomesNil(t *testing.T) {
	// Hashing "" would merge ALL session-less traffic into one group.
	assert.Nil(t, uuidField(""))
}

func TestUUIDField_CanonicalUUIDPassthrough(t *testing.T) {
	out := uuidField(testSessionUUID)
	require.IsType(t, "", out)
	assert.Equal(t, testSessionUUID, out.(string))
}

func TestUUIDField_NonCanonicalUUIDNormalizedToCanonical(t *testing.T) {
	canonical := "4dbfc67b-6ed9-5942-a9b6-53770ac48875"
	for _, spelling := range []string{
		"4DBFC67B6ED95942A9B653770AC48875",
		"urn:uuid:4DBFC67B-6ED9-5942-A9B6-53770AC48875",
		"{4dbfc67b-6ed9-5942-a9b6-53770ac48875}",
	} {
		out := uuidField(spelling)
		require.IsType(t, "", out, spelling)
		assert.Equal(t, canonical, out.(string), spelling)
	}
}

func TestUUIDField_NonUUIDHashesDeterministically(t *testing.T) {
	assert.Equal(t, goldenOpenCodeSession, uuidField("ses_f7c8cea03ffeQF8w3WLp7oRA9w"))
	assert.Equal(t, goldenStandSession, uuidField("ses_testNonUuid123"))
}

func TestUUIDField_RepeatCallsStable(t *testing.T) {
	first := uuidField("opencode-session")
	second := uuidField("opencode-session")
	require.IsType(t, "", first)
	assert.Equal(t, first.(string), second.(string))
}

func TestUUIDField_DistinctInputsDistinctOutputs(t *testing.T) {
	assert.NotEqual(t, uuidField("ses_aaa"), uuidField("ses_bbb"))
}

func TestUUIDField_OutputAlwaysParsesAsUUID(t *testing.T) {
	for _, in := range []string{"ses_x", "opencode-session", "team-1", "12345", "  spaced  "} {
		out := uuidField(in)
		require.IsType(t, "", out, in)
		_, err := uuid.Parse(out.(string))
		assert.NoError(t, err, "input %q produced %q", in, out.(string))
	}
}

func TestEventString_NonStringBecomesEmpty(t *testing.T) {
	fields := map[string]interface{}{
		"num":  12345,
		"str":  "ses_x",
		"miss": nil,
	}
	assert.Equal(t, "ses_x", eventString(fields, "str"))
	assert.Empty(t, eventString(fields, "num"))
	assert.Empty(t, eventString(fields, "miss"))
	assert.Empty(t, eventString(fields, "absent"))
}
