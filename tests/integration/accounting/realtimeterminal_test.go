//go:build integration

package accounting

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func realtimeBoundarySession(shape string) []string {
	response := func(id, text string, inputTokens, outputTokens int) []string {
		created := fmt.Sprintf(`{"type":"response.created","response":{"id":%q,"status":"in_progress"}}`, id)
		delta := fmt.Sprintf(`{"type":"response.output_text.delta","delta":%q}`, fixtureAssistantContent)
		done := fmt.Sprintf(`{"type":"response.done","response":{"id":%q,"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":%q}]}],"usage":{"input_tokens":%d,"output_tokens":%d}}}`, id, text, inputTokens, outputTokens)
		return []string{"event: response.created\ndata: " + created + "\n\n",
			"event: response.output_text.delta\ndata: " + delta + "\n\n",
			"event: response.done\ndata: " + done + "\n\n"}
	}
	switch shape {
	case "cr":
		wire := response("first", "one", 7, 3)
		for i := range wire {
			wire[i] = strings.ReplaceAll(wire[i], "\n", "\r")
		}
		return wire
	case "large":
		return response("first", strings.Repeat("a", (1<<20)+1), 7, 3)
	case "trailing":
		return append(response("first", "one", 7, 3), "event: rate_limits.updated\ndata: {\"type\":\"rate_limits.updated\",\"rate_limits\":[]}\n\n")
	case "multiple":
		return append(response("first", "one", 2, 1), response("second", "two", 7, 3)...)
	default:
		panic("unknown realtime fixture shape: " + shape)
	}
}

func requestBoundarySession(t *testing.T, s *stand, rid string, wire []string) string {
	t.Helper()
	s.fixture.mu.Lock()
	s.fixture.realtimeFrames[rid] = wire
	s.fixture.mu.Unlock()
	payload := fmt.Sprintf(`{"model":%q,"input":"realtime terminal ordering"}`, s.model)
	status, body, err := httpPostJSONBounded(45*time.Second, s.gatewayURL+"/v1/realtime", s.apiKey, rid, payload, 2<<20)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, []string{"/v1/realtime"}, s.fixture.ArrivalPaths(rid))
	return body
}

func TestAccountingRealtimeTerminalBoundaries(t *testing.T) {
	s := startStand(t)
	shapes := []string{"large", "trailing", "multiple", "cr"}
	var targets []string
	for _, shape := range shapes {
		targets = append(targets, s.reqPrefix+"failure-"+shape)
	}
	s.armPermanentTerminalWriteFailure(t, targets...)
	before := s.fixture.Snapshot()
	for i, shape := range shapes {
		t.Run(shape, func(t *testing.T) {
			wire := realtimeBoundarySession(shape)
			healthy := s.reqPrefix + "healthy-" + shape
			body := requestBoundarySession(t, s, healthy, wire)
			require.Equal(t, sha256.Sum256([]byte(strings.Join(wire, ""))), sha256.Sum256([]byte(body)), "healthy stream bytes or event order changed")
			s.requireNativeSettled(t, "realtime", shape, healthy, "/v1/realtime")
			failed := requestBoundarySession(t, s, targets[i], wire)
			requireDirectTerminalFailure(t, s, "realtime sse", http.StatusOK, failed)
		})
	}
	s.requireGroupDrainedWithin(t, s.redisClient(t), 2*time.Minute)
	for _, rid := range targets {
		require.Len(t, s.oracleAdmissions(t, rid, s.oracleDB.orgID), 1, "%s admission", rid)
		require.Zero(t, s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID), "%s terminal facts", rid)
		require.Zero(t, s.oracleCreditTotals(t, rid, s.oracleDB.orgID).UsageRows, "%s wallet debit", rid)
	}
	want := 2 * len(shapes)
	require.Equal(t, fixtureTotals{arrivals: want, dispatches: want, receipts: want}, s.fixture.Since(before))
	s.fixture.VerifyEvidence()
}

func TestRealtimeBoundaryFixture(t *testing.T) {
	f := startFixture(t, t.TempDir(), "unit-token")
	t.Cleanup(f.stop)
	s := &stand{gatewayURL: f.baseURL(), apiKey: "unit-token", model: "rt-test", fixture: f}
	for _, tc := range []struct {
		shape string
		count int
	}{{"large", 3}, {"trailing", 4}, {"multiple", 6}, {"cr", 3}} {
		wire := realtimeBoundarySession(tc.shape)
		body := requestBoundarySession(t, s, tc.shape, wire)
		require.Equal(t, sha256.Sum256([]byte(strings.Join(wire, ""))), sha256.Sum256([]byte(body)))
		require.Len(t, controlSSEFrames(t, body), tc.count)
		if tc.shape == "large" {
			require.Greater(t, len(wire[2]), 1<<20)
			s.fixture.mu.Lock()
			s.fixture.realtimeFrames["limited"] = wire
			s.fixture.mu.Unlock()
			_, _, err := requestRealtime(t, s, "limited")
			require.ErrorContains(t, err, "reader limit")
		}
	}
}
