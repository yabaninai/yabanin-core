//go:build integration

package accounting

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// splitAccountingFailure separates a single terminal error from the content
// delivered before it. OpenAI streams may close the error with [DONE].
func splitAccountingFailure(frames []sseFrame) ([]sseFrame, bool) {
	if len(frames) > 0 && frames[len(frames)-1] == (sseFrame{Data: "[DONE]"}) {
		frames = frames[:len(frames)-1]
	}
	if len(frames) == 0 {
		return nil, false
	}
	last := frames[len(frames)-1]
	code, ok := decodeErrorCode(last.Data)
	return frames[:len(frames)-1], ok && code == "accounting_commit_failed" && (last.Event == "" || last.Event == "error")
}

func requireDirectTerminalFailure(t *testing.T, s *stand, family string, status int, body string) {
	t.Helper()
	switch family {
	case "completions legacy sse":
		require.Equal(t, http.StatusOK, status)
		frames, ok := splitAccountingFailure(controlSSEFrames(t, body))
		require.True(t, ok, "missing terminal accounting error: %s", clip(body))
		// The fixture combines text and finish_reason in one frame. A relay
		// may hold the whole frame until the accounting transaction completes.
		require.LessOrEqual(t, len(frames), 1)
		if len(frames) == 1 {
			require.Empty(t, frames[0].Event)
			validateCompletionsReply(t, s, frames[0].Data)
		}
	case "realtime sse":
		require.Equal(t, http.StatusOK, status)
		frames, ok := splitAccountingFailure(controlSSEFrames(t, body))
		require.True(t, ok, "missing terminal accounting error: %s", clip(body))
		requireEventSequence(t, family, frames, []string{"response.created", "response.output_text.delta"})
		var delta responsesPayload
		require.NoError(t, json.Unmarshal([]byte(frames[1].Data), &delta))
		require.Equal(t, fixtureAssistantContent, delta.Delta)
	default:
		require.Equal(t, http.StatusInternalServerError, status)
		code, ok := decodeErrorCode(body)
		require.True(t, ok)
		require.Equal(t, "accounting_commit_failed", code)
	}
}

func TestAccountingDirectTerminalFailure(t *testing.T) {
	s := startStand(t)
	selected := map[string]bool{"embeddings": true, "completions legacy": true, "completions legacy sse": true,
		"moderations": true, "rerank": true, "realtime sse": true}
	var families []refusalFamily
	var ids []string
	for _, family := range refusalFamilies() {
		if selected[family.name] {
			families = append(families, family)
			ids = append(ids, familyRequestID(s, "terminal-", family.name))
			delete(selected, family.name)
		}
	}
	require.Empty(t, selected, "a required route is missing from the fixture")
	s.armPermanentTerminalWriteFailure(t, ids...)
	for i, family := range families {
		t.Run(family.name, func(t *testing.T) {
			s.controlFamily(t, family, "before")
			before := s.fixture.Snapshot()
			rid := ids[i]
			status, body, err := family.request(t, s, rid)
			require.NoError(t, err)
			requireDirectTerminalFailure(t, s, family.name, status, body)
			require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}, s.fixture.Since(before))
			require.Equal(t, []string{family.upstream}, s.fixture.ArrivalPaths(rid))
			s.controlFamily(t, family, "after")
		})
	}
	s.requireGroupDrainedWithin(t, s.redisClient(t), 2*time.Minute)
	for _, rid := range ids {
		require.Len(t, s.oracleAdmissions(t, rid, s.oracleDB.orgID), 1, "%s admissions", rid)
		require.Zero(t, s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID), "%s terminal facts", rid)
		require.Zero(t, s.oracleCreditTotals(t, rid, s.oracleDB.orgID).UsageRows, "%s charges", rid)
		a, d, r := s.fixture.Counts(rid)
		require.Equal(t, [3]int{1, 1, 1}, [3]int{a, d, r}, "%s provider contact after drain", rid)
	}
	s.fixture.VerifyEvidence()
}

func TestDirectAccountingErrorFrame(t *testing.T) {
	failure := sseFrame{Data: `{"error":{"code":"accounting_commit_failed"}}`}
	content := sseFrame{Data: `{"choices":[]}`}
	end := sseFrame{Data: "[DONE]"}
	for _, tail := range [][]sseFrame{{failure}, {failure, end}} {
		prefix, ok := splitAccountingFailure(append([]sseFrame{content}, tail...))
		require.True(t, ok)
		require.Equal(t, []sseFrame{content}, prefix)
	}
	for _, frames := range [][]sseFrame{{}, {content, end}, {{Data: `{"error":{"message":"accounting_commit_failed"}}`}}, {failure, content}} {
		_, ok := splitAccountingFailure(frames)
		require.False(t, ok)
	}
}
