package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const reviewPrefix = "data: {\"choices\":[{\"delta\":{\"content\":\"terminator text: data: [DONE]\"}}]}\n\n"

func TestReviewHeldTerminalShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		writes []string
	}{
		{"policy release batch", []string{reviewPrefix + "data: [DONE]\n\n"}},
		{"duplicate upstream terminal", []string{reviewPrefix, "data: [DONE]\n\n", "data: [DONE]\n\n"}},
		{"no-space CRLF", []string{reviewPrefix, "data:[DONE]\r\n\r\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := httptest.NewRecorder()
			writer := newSSETerminalWatch(raw)
			writer.armDoneHold()
			for _, p := range tc.writes {
				_, err := writer.Write([]byte(p))
				require.NoError(t, err)
			}
			before := raw.Body.String()
			require.False(t, hasReviewDoneLine(before), "terminal visible before commit: %q", before)
			writer.releaseDoneHold()
			require.Contains(t, raw.Body.String(), reviewPrefix)
			require.True(t, hasReviewDoneLine(raw.Body.String()), "successful terminal lost")
		})
	}
}

func hasReviewDoneLine(s string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if line == "data: [DONE]" || line == "data:[DONE]" {
			return true
		}
	}
	return false
}

type reviewStreamOrderStore struct {
	fakeInvocationStore
	w      *httptest.ResponseRecorder
	before string
}

func (s *reviewStreamOrderStore) RecordTerminalFacts(ctx context.Context, rec terminalFactsRecord) error {
	s.before = s.w.Body.String()
	return s.fakeInvocationStore.RecordTerminalFacts(ctx, rec)
}

func TestReviewPaidStreamDuplicateOrdering(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		printSSEFixture(t, w, reviewPrefix+"data: [DONE]\n\ndata: [DONE]\n\n")
	}))
	defer up.Close()
	gw := goldenChatGateway(t, up.URL)
	out := httptest.NewRecorder()
	store := &reviewStreamOrderStore{w: out}
	gw.invocations = store
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/v1/chat/completions", strings.NewReader(goldenChatStreamBody))
	goldenIdentity(req)
	gw.chatCompletions(out, req)
	require.Len(t, store.admitted, 1)
	require.Len(t, store.facts, 1)
	require.Contains(t, store.before, "terminator text:")
	require.False(t, hasReviewDoneLine(store.before), "client had already received success by the first durable-write attempt: %q", store.before)
	require.True(t, hasReviewDoneLine(out.Body.String()))
}

func TestReviewPaidStreamEnforcedPrefixOrdering(t *testing.T) {
	policy := strings.Replace(streamDenyFinalYAML("never-matches"), "[stream_final]", "[stream_prefix]", 1)
	policy = strings.Replace(policy, "      words:", "      prefix_tokens: 100000\n      prefix_delay_ms: 30000\n      words:", 1)
	up := newStreamPolicyUpstream(t, 0, streamChunkFrame("c1", "policy content"))
	gw := goldenChatGateway(t, up.srv.URL)
	gw.policyRuntime = streamPolicyGateway(t, PolicyModeEnforce, policy).policyRuntime
	out := httptest.NewRecorder()
	store := &reviewStreamOrderStore{w: out}
	gw.invocations = store
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/v1/chat/completions", strings.NewReader(goldenChatStreamBody))
	goldenIdentity(req)
	req.Header.Set("X-Org-Id", testOrg)
	gw.chatCompletions(out, req)
	require.Len(t, store.facts, 1)
	t.Logf("before facts %q; final %q", store.before, out.Body.String())
	require.NotContains(t, store.before, "data: [DONE]\n\n", "policy released complete success before accounting")
	require.Contains(t, out.Body.String(), "policy content")
	require.Contains(t, out.Body.String(), "data: [DONE]\n\n", "policy path lost a complete SSE terminal")
}
