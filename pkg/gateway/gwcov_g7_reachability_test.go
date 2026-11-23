package cli

// TEST-ONLY coverage recovery (critical-go gate, round G7): closes the last
// count=0 blocks the G1-G6 leaves proved unreachable by test-only means.
// Each production change backing these tests landed with its own proof in
// the same commit; this file adds only the behavioral pins:
//
//	audio_transcriptions.go  138.3,141.1  defensive encode arm through the
//	                                      audioRebuild seam (502, no upstream,
//	                                      no terminal facts)
//	responses_native.go      58.3,59.1    openai default compensating a
//	                                      provider lost between the two
//	                                      registry lookups one native
//	                                      request performs
//	agent_hop_budget.go      hopTermination total three-way settle
//	                                      classification after the dead
//	                                      fallthrough removal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
)

// TestGWCovG7_TranscriptionRebuildFailureArm drives the full transcription
// handler with the rebuild seam forced to fail: the request must settle as
// 502 "failed to encode upstream request" with no upstream traffic and no
// durable terminal facts.
func TestGWCovG7_TranscriptionRebuildFailureArm(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(server.Close)

	gw := g3Gateway(t, g3Model(server.URL))
	store := g3Store(t, gw)

	prev := audioRebuild
	audioRebuild = func([]audioFormPart, string) ([]byte, http.Header, error) {
		return nil, nil, errors.New("g7: forced rebuild failure")
	}
	t.Cleanup(func() { audioRebuild = prev })

	form, contentType := g3Upload(t, "m", "g7.wav", g3WAV(512))
	rec := g3PostTranscription(t, gw, form, contentType)

	require.Equal(t, http.StatusBadGateway, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "failed to encode upstream request")
	require.Zero(t, hits.Load(), "a rebuild failure must never reach upstream")
	require.Empty(t, store.facts, "no terminal facts for an un-encodeable request")
}

// g7FlapResolver models a registry row that changes BETWEEN the two lookups
// one native /v1/responses request performs: wantResponsesNative resolves
// the route first, admission re-resolves moments later (TTL expiry /
// invalidation / concurrent row update in production).
type g7FlapResolver struct {
	calls atomic.Int64
	first resolver.ModelInfo
	next  resolver.ModelInfo
}

func (f *g7FlapResolver) Resolve(ctx context.Context, name string) resolver.ModelInfo {
	info, _ := f.ResolveChecked(ctx, name)
	return info
}

func (f *g7FlapResolver) ResolveChecked(_ context.Context, _ string) (resolver.ModelInfo, error) {
	if f.calls.CompareAndSwap(0, 1) {
		return f.first, nil
	}
	return f.next, nil
}

// TestGWCovG7_ResponsesNativeEmptyProviderDefaultsToOpenAI pins the openai
// default at responses_native.go:57-59: a provider that was listed when the
// route was selected but empty at admission's re-resolution still serves the
// request through the native /v1/responses path.
func TestGWCovG7_ResponsesNativeEmptyProviderDefaultsToOpenAI(t *testing.T) {
	var gotPath atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		gotPath.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"g7":"native-ok"}`))
	}))
	t.Cleanup(up.Close)

	gw := responsesTestGateway(t, up.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = &g7FlapResolver{
		first: resolver.ModelInfo{ModelName: "m", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
		next:  resolver.ModelInfo{ModelName: "m", Provider: "", UpstreamURL: up.URL, Enabled: true},
	}

	rec := postResponses(t, gw, `{"model":"m","input":"hi"}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "/v1/responses", gotPath.Load(),
		"served by the native path, not the /v1/chat/completions translation adapter")
	require.Equal(t, `{"g7":"native-ok"}`, rec.Body.String())
}

// TestGWCovG7_HopTerminationClassification pins the total three-way settle
// classification: an upstream wire failure always wins, a dead parent
// context classifies the hop as client_cancel, a healthy hop inherits the
// parent's completed class.
func TestGWCovG7_HopTerminationClassification(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	t.Cleanup(cancel)

	require.Equal(t, "upstream_error", hopTermination(context.Background(), errors.New("g7: wire failed")),
		"an upstream error always classifies the hop as upstream_error")
	require.Equal(t, "client_cancel", hopTermination(canceled, nil),
		"a dead parent context classifies the hop as client_cancel")
	require.Equal(t, "completed", hopTermination(context.Background(), nil),
		"a healthy hop inherits the parent's completed class")
}
