//go:build integration

// N06-P07-T06 joint user scenario (REAL stand: live Postgres + the real §5
// reservation controller in enforce mode). The same narrative as the mock
// twin (n06p7t06_joint_scenario_test.go), but every seam runs over its
// production wiring: unit-priced bounds RESERVE through the estimator's T02
// branch, completions settle actuals with reserve tuples + termination, the
// judge hop reserves through §5 and charges its settled actual into the
// org-namespaced workload window, and a saturated window refuses chat and
// every non-chat endpoint fail-closed BEFORE §5 — the wallet stays funded,
// proving the workload dimension composes on top of the credit gate.
//
// Per-seam live pins (NEXT-18c, agent_hop_budget_int_test.go,
// workload_hop_int_test.go) are not repeated; this is the composition.
package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/testdb"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/money"
)

func TestN06P7T06_JointUnitWorkloadScenario_Live(t *testing.T) {
	pool := testdb.Postgres(t)
	up, hits := jointScenarioUpstream(t)
	org := seedReservationsOrg(t, pool, "enforce", 100_000) // funded $1000 wallet
	gw := streamTestGateway(up.URL)
	gw.retryPolicy.MaxAttempts = 1
	gw.res = stubModelResolver{
		"stub-model": {ModelName: "stub-model", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
		"tts":        {ModelName: "tts-1", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
		"whisper":    {ModelName: "whisper-1", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
		"img":        {ModelName: "gpt-image-1", Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}
	gw.unitPricer = operatorUnitsForTest(t)

	// The REAL §5 controller: token scopes price through the stub table, the
	// unit axes through the same synthetic operator catalog the settle side uses —
	// one catalog feeds both the reserve bound and the billed actuals.
	rates := gatewayRates(pool)
	rates.Base.Units = operatorUnitsForTest(t)
	store := budget.NewReservationStoreWithConfig(pool, nil, budget.ReservationConfig{
		DefaultGraceFloorCents: 0,
	})
	gw.admission = budget.NewAdmission(store, rates, nil,
		"gw-int-"+uuid.NewString()[:8], budget.ModeEnforce, reservationOrgLoader(pool), budget.DefaultAdmissionConfig())

	// The opt-in per-replica workload cap ($100) over the funded wallet: the
	// story saturates the WINDOW, never the wallet.
	const liveWLCap = int64(100_000_000)
	ledger := presetWorkloadLedger(t, liveWLCap)
	agent := newTestAgentWithBudget(t, pool, org, "10000")

	live := &jointEventLog{}
	restore := observeEvent(func(e *eventpub.Event) {
		if e.EventType == "request.completed" {
			live.add(e)
		}
	})
	defer restore()

	// ---- Leg 1: STT reserves per audio second and settles actuals. --------
	wav := audioFixtureBytes(t, "hello.wav")
	form, ctype := buildAudioMultipart(t,
		map[string]string{"model": "whisper", "response_format": "verbose_json"},
		"file", "hello.wav", "audio/wav", wav)
	rec := postJoint(t, gw, gw.audioTranscriptions, "/v1/audio/transcriptions", ctype, string(form), org, jointWLKey)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stt := live.byEndpoint("audio.transcriptions")
	require.NotNil(t, stt, "the transcription leg must settle its completion event")
	require.Equal(t, org, stt.OrgID)
	require.Equal(t, jointWLKey, stt.Labels["workload"])
	whisperRate := jointUnitRate(t, gw, "openai", "whisper-1", pricing.UnitPerAudioSecond)
	require.InDelta(t, whisperRate*8, stt.EstimatedCostUSD, 0, "the billed actual is 8 upstream seconds")
	require.Equal(t, "priced", stt.CostStatus)
	require.NotEmpty(t, stt.Reservations, "the unit-priced leg reserved through the real §5 controller")
	require.Equal(t, string(budget.TerminationCompleted), stt.Termination)

	// ---- Leg 2: imagegen reserves per image (n=2). ------------------------
	rec = postJoint(t, gw, gw.imagesGenerations, "/v1/images/generations",
		"application/json", `{"model":"img","prompt":"a single red cube on a white background","n":2}`, org, jointWLKey)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	imgEv := live.byEndpoint("images.generation")
	require.NotNil(t, imgEv, "the imagegen leg must settle its completion event")
	require.Equal(t, jointWLKey, imgEv.Labels["workload"])
	imgRate := jointUnitRate(t, gw, "openai", "gpt-image-1", pricing.UnitPerImage)
	require.InDelta(t, imgRate*2, imgEv.EstimatedCostUSD, 0)
	require.Equal(t, "priced", imgEv.CostStatus)
	require.NotEmpty(t, imgEv.Reservations)
	require.Equal(t, string(budget.TerminationCompleted), imgEv.Termination)

	// ---- Leg 3: TTS reserves per input character. -------------------------
	rec = postJoint(t, gw, gw.audioSpeech, "/v1/audio/speech",
		"application/json", `{"model":"tts","input":"hello","voice":"alloy"}`, org, jointWLKey)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	ttsEv := live.byEndpoint("audio.speech")
	require.NotNil(t, ttsEv, "the speech leg must settle its completion event")
	require.Equal(t, jointWLKey, ttsEv.Labels["workload"])
	ttsRate := jointUnitRate(t, gw, "openai", "tts-1", pricing.UnitPerCharacter)
	require.InDelta(t, ttsRate*5, ttsEv.EstimatedCostUSD, 0)
	require.Equal(t, "priced", ttsEv.CostStatus)
	require.NotEmpty(t, ttsEv.Reservations)
	require.Equal(t, string(budget.TerminationCompleted), ttsEv.Termination)

	// Interactive legs attribute durably but do not charge the window (the
	// T04 residual); the ledger is still at zero here.
	require.Equal(t, money.MicroUSD(0), ledger.Spent(org, jointWLKey),
		"interactive unit legs label the window without charging it")

	// ---- Leg 4: the internal judge hop reserves AND charges the window. ---
	// The hop wires to its own judge upstream (the established live-hop
	// harness shape): same §5 controller, same workload window.
	hopUp, hopHits := newJudgeHopUpstream(t)
	hopClient := newLiveJudgeClient(t, gw, hopUp)
	hopReq := judgeHopRequest("gpt-4o-mini")
	hopReq.Meta.Org = org
	resp, err := hopClient.JudgeChat(
		withPrincipal(workloadHopContextID("req-joint-hop-live", jointWLKey), principal{AgentID: agent}),
		hopReq)
	require.NoError(t, err)
	require.JSONEq(t, `{"verdict":"allow"}`, resp.Content)

	hopEv := live.byEndpoint(agentHopEndpoint)
	require.NotNil(t, hopEv, "the hop settles its completion event")
	require.Equal(t, org, hopEv.OrgID)
	require.Equal(t, jointWLKey, hopEv.Labels["workload"])
	require.NotEmpty(t, hopEv.Reservations, "the hop reserved through §5 like any other hop")
	require.Equal(t, string(budget.TerminationCompleted), hopEv.Termination)
	hopCharge := ledger.Spent(org, jointWLKey)
	require.Positive(t, hopCharge, "the hop's settled actual charged the shared window")
	require.Equal(t, int64(1), hopHits.Load(), "the allowed hop reaches the judge wire exactly once")
	sharedLoopBudget().Release("req-joint-hop-live")

	// ---- Saturation: the batch backlog burns the window, wallet stays. ----
	ledger.Charge(org, jointWLKey, money.MicroUSD(liveWLCap))

	formDenied, ctypeDenied := buildAudioMultipart(t,
		map[string]string{"model": "whisper", "response_format": "verbose_json"},
		"file", "hello.wav", "audio/wav", wav)
	denied := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		path    string
		body    string
	}{
		{"chat_completions", gw.chatCompletions, "/v1/chat/completions",
			`{"model":"stub-model","messages":[{"role":"user","content":"hi"}]}`},
		{"audio_transcriptions", gw.audioTranscriptions, "/v1/audio/transcriptions", ""},
		{"images_generations", gw.imagesGenerations, "/v1/images/generations",
			`{"model":"img","prompt":"one more","n":1}`},
		{"audio_speech", gw.audioSpeech, "/v1/audio/speech",
			`{"model":"tts","input":"one more","voice":"alloy"}`},
	}
	beforeEvents := live.count()
	beforeHits := hits.Load()
	beforeHopHits := hopHits.Load()
	for _, d := range denied {
		var rec *httptest.ResponseRecorder
		if d.path == "/v1/audio/transcriptions" {
			rec = postJoint(t, gw, d.handler, d.path, ctypeDenied, string(formDenied), org, jointWLKey)
		} else {
			rec = postJoint(t, gw, d.handler, d.path, "application/json", d.body, org, jointWLKey)
		}
		require.Equal(t, http.StatusTooManyRequests, rec.Code, "%s: %s", d.name, rec.Body.String())
		require.Contains(t, rec.Body.String(), "workload_budget_exceeded", d.name)
	}
	require.Equal(t, beforeHits, hits.Load(), "denied legs never reach the wire")
	require.Equal(t, beforeEvents, live.count(), "denied legs settle no completion event")

	// The detector loop is capped by the same window.
	_, err = hopClient.JudgeChat(
		withPrincipal(workloadHopContextID("req-joint-hop-denied-live", jointWLKey), principal{AgentID: agent}),
		hopReq)
	require.ErrorIs(t, err, budget.ErrWorkloadBudgetExceeded)
	require.Equal(t, beforeHopHits, hopHits.Load(), "a capped hop never reaches the wire")
	sharedLoopBudget().Release("req-joint-hop-denied-live")

	// ---- Control: the cap is per window; another workload still runs. -----
	rec = postJoint(t, gw, gw.chatCompletions, "/v1/chat/completions",
		"application/json", `{"model":"stub-model","messages":[{"role":"user","content":"hi"}]}`, org, "media-fleet-2")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String(),
		"a different workload of the same org keeps its own window")
	require.Equal(t, money.MicroUSD(0), ledger.Spent(org, "media-fleet-2"),
		"the control window stays uncharged (interactive attribution only)")
}
