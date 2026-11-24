package adminstore

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The list row's row_key crosses the wire as an exact decimal string: JSON
// numbers cannot carry int64 beyond 2^53 (every JS number is a float64 and
// rounds 2^53+1 to 2^53), and an unset key is omitted so legacy rows keep
// their historical bytes.
func TestRequestListRowRowKeyWireFormat(t *testing.T) {
	big := int64(9007199254740993) // 2^53+1: not representable as float64

	out, err := json.Marshal(RequestListRow{RequestID: "req-1", RowKey: big})
	require.NoError(t, err)
	require.Contains(t, string(out), `"row_key":"9007199254740993"`,
		"the beyond-2^53 key must marshal as an exact decimal string")

	var back RequestListRow
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, big, back.RowKey, "the string encoding must unmarshal back to the exact int64")

	zero, err := json.Marshal(RequestListRow{RequestID: "req-1"})
	require.NoError(t, err)
	require.NotContains(t, string(zero), "row_key", "an unset row_key is omitted, not zero")
}
