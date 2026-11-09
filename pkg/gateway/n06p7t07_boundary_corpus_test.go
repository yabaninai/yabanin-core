package cli

// N06-P07-T07 boundary corpus — gateway seam. The packet's reusable EDGE
// cases that the T01–T06 acceptance tests do not pin:
//
//	(A) unit-priced settlement edges at the endpoints: a ZERO upstream
//	    duration is a priced ZERO (not no_usage), sub-µUSD and huge-finite
//	    durations bill the exact float product, invalid image counts bill
//	    one, and speech billing is unicode RUNES not UTF-8 bytes;
//	(B) the judge hop as the sole charger at the exact window boundary
//	    (its settled quote is an exact 6 µUSD — float64-verified);
//	(C) saturation edges: the last-admitted/first-refused boundary pre-wire,
//	    the pre-wire refusal across every JSON endpoint, and the degenerate
//	    maxKeys=1 ledger refusing at the gateway seam while the cap is far
//	    away.
//
// Exact µUSD pins (75, 6, 15, 60, 250000) were verified against float64
// arithmetic; do not "simplify" the literals.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// t07PostSpeech posts a speech request with an explicit workload header
// ("" = no label, untracked).
func t07PostSpeech(t *testing.T, gw *gateway, input, workload string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"tts","input":"` + input + `","voice":"alloy"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/speech", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	if workload != "" {
		req.Header.Set("X-Yabanin-Workload", workload)
	}
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// t07SpeechGateway is the unit-priced tts-1 stand over a byte-identical
// mp3 upstream, with a wire-hit counter.
func t07SpeechGateway(t *testing.T) (*gateway, func() *eventpub.Event, *atomic.Int64) {
	t.Helper()
	mp3 := audioFixtureBytes(t, "hello.mp3")
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(mp3)
	}))
	t.Cleanup(server.Close)

	gw := newAudioGateway(t, audioTestModel(server.URL))
	gw.unitPricer = operatorUnitsForTest(t)
	return gw, unitEventCapture(gw), &hits
}

// TestN06P7T07_TranscriptionDurationEdgesSettlePriced: the duration axis
// settles the EXACT upstream actual at the edges — zero duration is a
// priced ZERO (never "no_usage"), a sub-µUSD actual rounds to a zero µUSD
// charge while keeping the priced status, and a huge finite duration is
// billed as-is (the cap lives in the window, not in a settlement clamp).
func TestN06P7T07_TranscriptionDurationEdgesSettlePriced(t *testing.T) {
	cases := []struct {
		name     string
		duration string
		want     float64
	}{
		{name: "zero duration settles priced zero", duration: "0", want: 0},
		{name: "sub-microsecond duration charges zero µUSD", duration: "0.000001", want: fixtureTranscriptionRate * 1e-06},
		{name: "huge finite duration bills the actual", duration: "1000000", want: fixtureTranscriptionRate * 1e+06},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := stubUnitUpstream(t, `{"id":"tr","text":"hi","duration":`+tc.duration+`}`)
			gw := newAudioGateway(t, audioTranscriptionModel(up.URL))
			gw.unitPricer = operatorUnitsForTest(t)
			read := unitEventCapture(gw)

			wav := audioFixtureBytes(t, "hello.wav")
			body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
			rec := postAudioTranscriptions(t, gw, body, contentType)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			ev := read()
			require.NotNil(t, ev, "no request.completed event")
			require.Equal(t, "priced", ev.CostStatus, "a present duration is a price, even when it is zero")
			require.Equal(t, "none", ev.UsageSource)
			require.Zero(t, ev.TokensIn)
			require.Zero(t, ev.TokensOut)
			require.InDelta(t, tc.want, ev.EstimatedCostUSD, 0)
		})
	}
}

// TestN06P7T07_ImagesBilledOneWhenRequestCountInvalid: n=0 and negative n
// are request-level invalid counts; the endpoint bills exactly one image at
// the per_image rate instead of zero or a negative quote.
func TestN06P7T07_ImagesBilledOneWhenRequestCountInvalid(t *testing.T) {
	tiny := base64.StdEncoding.EncodeToString(testTinyPNG)
	for _, tc := range []struct {
		name string
		n    int
	}{
		{name: "n zero bills one", n: 0},
		{name: "n negative bills one", n: -3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, read := newUnitImagesGateway(t,
				`{"created":1790000000,"data":[{"b64_json":"`+tiny+`"}]}`)
			rec := postImages(t, gw, `{"model":"m","prompt":"one red cube","n":`+strconv.Itoa(tc.n)+`}`)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

			ev := read()
			require.NotNil(t, ev)
			require.InDelta(t, fixtureImageRate, ev.EstimatedCostUSD, 0)
			require.Equal(t, "priced", ev.CostStatus)
		})
	}
}

// TestN06P7T07_SpeechChargesRunesNotBytes: the per_character axis counts
// unicode runes — one ASCII rune is the smallest non-zero quote and a
// 4-rune/8-byte Cyrillic input bills 4× the rate, never 8×.
func TestN06P7T07_SpeechChargesRunesNotBytes(t *testing.T) {
	gw, read, _ := t07SpeechGateway(t)
	entry, ok := gw.unitPrice("openai", "tts-1", pricing.UnitPerCharacter)
	require.True(t, ok, "operator catalog lost tts-1 per_character")

	rec := t07PostSpeech(t, gw, "a", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	ev := read()
	require.NotNil(t, ev)
	require.InDelta(t, entry.Rate, ev.EstimatedCostUSD, 0)
	require.Equal(t, "priced", ev.CostStatus)

	rec = t07PostSpeech(t, gw, "ключ", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	ev = read()
	require.NotNil(t, ev)
	require.InDelta(t, entry.Rate*4, ev.EstimatedCostUSD, 0)
	require.NotEqual(t, entry.Rate*8, ev.EstimatedCostUSD, "billing must not count UTF-8 bytes")
}

// TestN06P7T07_JudgeHopLandsWindowExactlyAtCap: the judge hop is the sole
// charger at the window boundary — judgeHopOKBody settles gpt-4o-mini
// 11/7 → 5.85e-06 USD, an exact 6 µUSD quote — so a 6 µUSD cap admits the
// first hop, lands the window exactly on the cap, and refuses the second
// hop BEFORE the wire without a phantom charge; one µUSD of headroom lets
// the second hop through and lands at twice the quote.
func TestN06P7T07_JudgeHopLandsWindowExactlyAtCap(t *testing.T) {
	const hopCharge = 6 // µUSD, float64-verified

	t.Run("cap exactly one hop", func(t *testing.T) {
		presetWorkloadLedger(t, hopCharge)
		up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
		client, req := newJudgeHopClient(t, up, nil)

		resp, err := client.JudgeChat(workloadHopContextID("req-t07-cap-hit", jointWLKey), req)
		require.NoError(t, err)
		require.JSONEq(t, `{"verdict":"allow"}`, resp.Content)
		require.Equal(t, int64(1), up.hits.Load())
		require.Equal(t, money.MicroUSD(hopCharge), sharedWorkloadLedger().Spent("org-judge", jointWLKey))
		sharedLoopBudget().Release("req-t07-cap-hit")

		_, err = client.JudgeChat(workloadHopContextID("req-t07-cap-deny", jointWLKey), req)
		require.ErrorIs(t, err, budget.ErrWorkloadBudgetExceeded)
		require.Contains(t, err.Error(), "judge workload budget")
		require.Equal(t, int64(1), up.hits.Load(), "refused hop must not reach the upstream")
		require.Equal(t, money.MicroUSD(hopCharge), sharedWorkloadLedger().Spent("org-judge", jointWLKey), "refusal must not charge")
		sharedLoopBudget().Release("req-t07-cap-deny")
	})

	t.Run("one micro of headroom admits the second hop", func(t *testing.T) {
		presetWorkloadLedger(t, hopCharge+1)
		up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
		client, req := newJudgeHopClient(t, up, nil)

		_, err := client.JudgeChat(workloadHopContextID("req-t07-ctl-a", jointWLKey), req)
		require.NoError(t, err)
		sharedLoopBudget().Release("req-t07-ctl-a")

		_, err = client.JudgeChat(workloadHopContextID("req-t07-ctl-b", jointWLKey), req)
		require.NoError(t, err)
		require.Equal(t, int64(2), up.hits.Load())
		require.Equal(t, money.MicroUSD(2*hopCharge), sharedWorkloadLedger().Spent("org-judge", jointWLKey))
		sharedLoopBudget().Release("req-t07-ctl-b")
	})
}

// TestN06P7T07_SaturationExactBoundaryPreWire: interactive settlement does
// not charge the shared in-process ledger (chargeback is durable-side; only
// the judge hop charges in-process), so the boundary is built by charging
// the window directly. One µUSD under the cap the labeled request admits;
// with the window exactly at the cap the next request is the FIRST refusal
// — before the wire — and a neighbor window under the same org is
// untouched.
func TestN06P7T07_SaturationExactBoundaryPreWire(t *testing.T) {
	ledger := presetWorkloadLedger(t, 75)
	gw, _, hits := t07SpeechGateway(t)

	ledger.Charge(jointWLOrg, jointWLKey, 74)
	rec := postJoint(t, gw, gw.audioSpeech, "/v1/audio/speech", "application/json",
		`{"model":"tts","input":"hello","voice":"alloy"}`, jointWLOrg, jointWLKey)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, int64(1), hits.Load())
	require.Equal(t, money.MicroUSD(74), ledger.Spent(jointWLOrg, jointWLKey),
		"interactive settlement does not charge the in-process ledger")

	ledger.Charge(jointWLOrg, jointWLKey, 1) // window exactly at cap
	rec = postJoint(t, gw, gw.audioSpeech, "/v1/audio/speech", "application/json",
		`{"model":"tts","input":"hello","voice":"alloy"}`, jointWLOrg, jointWLKey)
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "workload_budget_exceeded")
	require.Equal(t, int64(1), hits.Load(), "refusal must be pre-wire")

	rec = postJoint(t, gw, gw.audioSpeech, "/v1/audio/speech", "application/json",
		`{"model":"tts","input":"hello","voice":"alloy"}`, jointWLOrg, "media-neighbor")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, int64(2), hits.Load())
}

// TestN06P7T07_SaturationPreWireAcrossJSONEndpoints: with the window
// charged exactly to the cap, the shared org-namespaced ledger refuses
// every other endpoint's labeled request BEFORE the wire — legacy
// completions, embeddings, rerank, moderations — while a neighbor workload
// label rides through on the same endpoint.
func TestN06P7T07_SaturationPreWireAcrossJSONEndpoints(t *testing.T) {
	ledger := presetWorkloadLedger(t, 75)
	ledger.Charge(jointWLOrg, jointWLKey, 75) // window exactly at cap

	matrix, upHits, _ := newAdmissionMatrixGateway(t)

	for _, tc := range []struct {
		name    string
		path    string
		body    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{name: "legacy completions", path: "/v1/completions", body: `{"model":"m","prompt":"hi"}`, handler: matrix.completions},
		{name: "embeddings", path: "/v1/embeddings", body: `{"model":"m","input":"hi"}`, handler: matrix.embeddings},
		{name: "rerank", path: "/v1/rerank", body: `{"model":"m","query":"q","documents":["d"]}`, handler: matrix.rerank},
		{name: "moderations", path: "/v1/moderations", body: `{"model":"m","input":"hi"}`, handler: matrix.moderations},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := postJoint(t, matrix, tc.handler, tc.path, "application/json", tc.body, jointWLOrg, jointWLKey)
			require.Equal(t, http.StatusTooManyRequests, got.Code, got.Body.String())
			require.Contains(t, got.Body.String(), "workload_budget_exceeded")
			require.Zero(t, upHits.Load(), "refusal must be pre-wire")
		})
	}

	// Neighbor window: the same saturated ledger, a different label —
	// the request rides through to the wire.
	got := postJoint(t, matrix, matrix.embeddings, "/v1/embeddings", "application/json",
		`{"model":"m","input":"hi"}`, jointWLOrg, "media-neighbor")
	require.Equal(t, http.StatusOK, got.Code, got.Body.String())
	require.Equal(t, int64(1), upHits.Load())
}

// TestN06P7T07_DegenerateKeyBoundFailsClosedAtGateway: a maxKeys=1 ledger
// wired at the gateway seam refuses the SECOND distinct workload label
// fail-closed — while the cap is far from reached — and the refused label
// charges nothing, while the held window keeps working.
func TestN06P7T07_DegenerateKeyBoundFailsClosedAtGateway(t *testing.T) {
	l := budget.NewWorkloadLedgerBounded(money.MicroUSD(1000000), 0, 1)
	workloadLedgerShared.Store(l)
	t.Cleanup(func() { workloadLedgerShared.Store(nil) })

	gw, _, hits := t07SpeechGateway(t)

	rec := t07PostSpeech(t, gw, "hello", "held")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, int64(1), hits.Load())

	rec = t07PostSpeech(t, gw, "hello", "fresh")
	require.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "workload_budget_exceeded")
	// The refusal names the key-bound branch, not the cap: the message
	// carries the ledger's own "refusing new key" text for THIS key while
	// the cap (1 000 000 µUSD) is far from the 75 µUSD actually spent.
	require.Contains(t, rec.Body.String(), `refusing new key \"fresh\"`)
	require.Equal(t, int64(1), hits.Load(), "key-bound refusal must be pre-wire")
	require.Equal(t, money.MicroUSD(0), l.Spent("", "fresh"), "refused key must stay untracked")

	rec = t07PostSpeech(t, gw, "hello", "held")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, int64(2), hits.Load())
}
