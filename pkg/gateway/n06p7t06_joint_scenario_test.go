package cli

// N06-P07-T06 joint user scenario (MOCK stand): one org runs ONE agent
// workload through a complete multimodal job — a transcription, an image
// batch and a speech synthesis leg (T02 unit-priced admission + settle), an
// internal judge hop (T03) that charges the SAME org-namespaced cap window
// (T04), and then the window saturates and every endpoint — chat and
// non-chat alike — refuses fail-closed BEFORE any upstream traffic.
//
// This is the composition pin: each seam has its own unit/live corpus
// (unit_pricing_test.go, agent_hop_budget_test.go, admission_workload_test.go,
// workload_hop_test.go); nothing here re-proves those pins, it proves the
// seams hold together as one user story. The REAL (live Postgres) twin of
// this scenario lives in n06p7t06_joint_scenario_int_test.go.

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"
	"github.com/reireirei/yabanin/pkg/upstream"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// The whole story runs under one org and one workload key: interactive
// non-chat legs, the chat control leg and the internal judge hop all share
// this org-namespaced cap window.
const (
	jointWLOrg = "agent-org-joint"
	jointWLKey = "media-fleet"
	// jointWLCap is the per-replica daily window in micro-USD ($1.00).
	jointWLCap = int64(1_000_000)
)

// jointScenarioUpstream serves one mock provider answering every endpoint
// family the story touches with realistic bodies: a transcription JSON with
// an 8-second duration, a two-image data array, MPEG bytes for speech and a
// chat completion. hits counts every request that reached the wire.
func jointScenarioUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	img := base64.StdEncoding.EncodeToString(testTinyPNG)
	speech := audioFixtureBytes(t, "hello.mp3")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/v1/audio/transcriptions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"text":"hi","duration":8,"language":"en"}`))
		case "/v1/images/generations":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":1790000000,"data":[` +
				`{"b64_json":"` + img + `"},{"b64_json":"` + img + `"}]}`))
		case "/v1/audio/speech":
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = w.Write(speech)
		default: // /v1/chat/completions
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl","choices":[{"message":{"content":"ok"}}],` +
				`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		}
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

// jointEventLog collects every completion event the stand publishes; the
// mutex keeps -race clean even if a publish ever detaches from the request
// goroutine.
type jointEventLog struct {
	mu  sync.Mutex
	evs []*eventpub.Event
}

func (l *jointEventLog) add(e *eventpub.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, e)
}

func (l *jointEventLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.evs)
}

func (l *jointEventLog) byEndpoint(name string) *eventpub.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.evs {
		if e.Endpoint == name {
			return e
		}
	}
	return nil
}

// jointGateway builds the mock stand: strict auth, one registry carrying all
// four story models (alias -> canonical unit-catalog names), the synthetic operator
// unit catalog and the event log. The workload ledger is swapped by the test.
func jointGateway(t *testing.T, up *httptest.Server) (*gateway, *jointEventLog) {
	t.Helper()
	gw := &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: up.URL},
		log:  slog.New(slog.DiscardHandler),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res: stubModelResolver{
			"chat-m":  {ModelName: "fim", Provider: "openai", UpstreamURL: up.URL, UpstreamAPIKey: "up-key", Enabled: true},
			"tts":     {ModelName: "tts-1", Provider: "openai", UpstreamURL: up.URL, UpstreamAPIKey: "up-key", Enabled: true},
			"whisper": {ModelName: "whisper-1", Provider: "openai", UpstreamURL: up.URL, UpstreamAPIKey: "up-key", Enabled: true},
			"img":     {ModelName: "gpt-image-1", Provider: "openai", UpstreamURL: up.URL, UpstreamAPIKey: "up-key", Enabled: true},
		},
		pool:        upstream.NewPool(upstream.Options{}),
		fallback:    fallbackrouter.NewFallbackExecutor(nil, 3, nil),
		retryPolicy: retry.Policy{MaxAttempts: 1},
	}
	gw.unitPricer = operatorUnitsForTest(t)
	events := &jointEventLog{}
	gw.eventNote = events.add
	return gw, events
}

// postJoint drives one story leg through the real handler with an org and
// workload header preset (the auth-free direct-call pattern the reservation
// live harness uses; auth envelope shapes are the matrix corpus's seam, not
// this one). org and workload select X-Org-Id and X-Yabanin-Workload.
func postJoint(t *testing.T, gw *gateway, handler func(http.ResponseWriter, *http.Request),
	path, contentType, body, org, workload string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Org-Id", org)
	req.Header.Set("X-Yabanin-Workload", workload)
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// jointUnitRate reads a rate out of the stand's synthetic operator unit catalog so the
// cost expectations are derived from the same source the gateway uses.
func jointUnitRate(t *testing.T, gw *gateway, providerName, model, unit string) float64 {
	t.Helper()
	entry, ok := gw.unitPricer.LookupUnit(providerName, model)
	require.True(t, ok, "operator catalog must price %s:%s", providerName, model)
	require.Equal(t, unit, entry.Unit)
	return entry.Rate
}

// TestN06P7T06_JointUnitWorkloadScenario_Mock is the packet's user story on
// the mock stand; see the file comment for the narrative.
func TestN06P7T06_JointUnitWorkloadScenario_Mock(t *testing.T) {
	up, hits := jointScenarioUpstream(t)
	ledger := presetWorkloadLedger(t, jointWLCap)
	gw, events := jointGateway(t, up)

	// ---- Leg 1: the fleet transcribes a briefing tape (STT, per-second). --
	wav := audioFixtureBytes(t, "hello.wav")
	form, ctype := buildAudioMultipart(t,
		map[string]string{"model": "whisper", "response_format": "verbose_json"},
		"file", "hello.wav", "audio/wav", wav)
	rec := postJoint(t, gw, gw.audioTranscriptions, "/v1/audio/transcriptions", ctype, string(form),
		jointWLOrg, jointWLKey)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stt := events.byEndpoint("audio.transcriptions")
	require.NotNil(t, stt, "the transcription leg must settle its completion event")
	require.Equal(t, jointWLOrg, stt.OrgID)
	require.Equal(t, jointWLKey, stt.Labels["workload"], "the settle event carries the workload identity")
	whisperRate := jointUnitRate(t, gw, "openai", "whisper-1", pricing.UnitPerAudioSecond)
	require.InDelta(t, whisperRate*8, stt.EstimatedCostUSD, 0, "billed actuals are 8 upstream seconds at the catalog rate")
	require.Equal(t, "priced", stt.CostStatus)

	// ---- Leg 2: the fleet renders a two-image storyboard (per image). ----
	rec = postJoint(t, gw, gw.imagesGenerations, "/v1/images/generations",
		"application/json", `{"model":"img","prompt":"a single red cube on a white background","n":2}`, jointWLOrg, jointWLKey)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	imgEv := events.byEndpoint("images.generation")
	require.NotNil(t, imgEv, "the imagegen leg must settle its completion event")
	require.Equal(t, jointWLOrg, imgEv.OrgID)
	require.Equal(t, jointWLKey, imgEv.Labels["workload"])
	imgRate := jointUnitRate(t, gw, "openai", "gpt-image-1", pricing.UnitPerImage)
	require.InDelta(t, imgRate*2, imgEv.EstimatedCostUSD, 0, "n=2 bills two images")
	require.Equal(t, "priced", imgEv.CostStatus)

	// ---- Leg 3: the fleet voices its report (TTS, per character). --------
	rec = postJoint(t, gw, gw.audioSpeech, "/v1/audio/speech",
		"application/json", `{"model":"tts","input":"hello","voice":"alloy"}`, jointWLOrg, jointWLKey)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	tts := events.byEndpoint("audio.speech")
	require.NotNil(t, tts, "the speech leg must settle its completion event")
	require.Equal(t, jointWLOrg, tts.OrgID)
	require.Equal(t, jointWLKey, tts.Labels["workload"])
	ttsRate := jointUnitRate(t, gw, "openai", "tts-1", pricing.UnitPerCharacter)
	require.InDelta(t, ttsRate*5, tts.EstimatedCostUSD, 0, `"hello" is 5 billable characters`)
	require.Equal(t, "priced", tts.CostStatus)

	// The three interactive legs attribute durably (labels) but do not
	// charge the cap window — the interactive charge-site is T04's recorded
	// residual; only the internal hop charges (pinned below).
	require.Equal(t, money.MicroUSD(0), ledger.Spent(jointWLOrg, jointWLKey),
		"interactive unit legs label the window without charging it")

	// ---- Leg 4: the agent loop runs an internal judge hop that CHARGES. --
	up2 := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	hopClient, hopReq := newJudgeHopClient(t, up2, nil)
	hopReq.Meta.Org = jointWLOrg

	var hopEv *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { hopEv = e })
	resp, err := hopClient.JudgeChat(workloadHopContextID("req-joint-hop", jointWLKey), hopReq)
	restore()
	require.NoError(t, err)
	require.JSONEq(t, `{"verdict":"allow"}`, resp.Content)
	require.Equal(t, int64(1), up2.hits.Load(), "the hop reached its upstream exactly once")

	require.NotNil(t, hopEv, "the hop settles its completion event")
	require.Equal(t, agentHopEndpoint, hopEv.Endpoint)
	require.Equal(t, jointWLKey, hopEv.Labels["workload"])
	hopCharge := ledger.Spent(jointWLOrg, jointWLKey)
	require.Positive(t, hopCharge, "the hop's settled actual charges the shared window")
	require.Equal(t, money.MicroUSD(0), ledger.Spent(jointWLOrg, "other-fleet"),
		"only the story's own workload window moves")
	sharedLoopBudget().Release("req-joint-hop")

	// ---- Saturation: the batch backlog burns the rest of the window. ------
	ledger.Charge(jointWLOrg, jointWLKey, money.MicroUSD(jointWLCap))

	denied := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		path    string
		body    string
	}{
		{"chat_completions", gw.chatCompletions, "/v1/chat/completions",
			`{"model":"chat-m","messages":[{"role":"user","content":"hi"}]}`},
		{"audio_transcriptions", gw.audioTranscriptions, "/v1/audio/transcriptions", ""},
		{"images_generations", gw.imagesGenerations, "/v1/images/generations",
			`{"model":"img","prompt":"one more","n":1}`},
		{"audio_speech", gw.audioSpeech, "/v1/audio/speech",
			`{"model":"tts","input":"one more","voice":"alloy"}`},
	}
	beforeEvents := events.count()
	beforeHits := hits.Load()
	for _, d := range denied {
		var rec *httptest.ResponseRecorder
		if d.path == "/v1/audio/transcriptions" {
			form, ctype := buildAudioMultipart(t,
				map[string]string{"model": "whisper", "response_format": "verbose_json"},
				"file", "hello.wav", "audio/wav", wav)
			rec = postJoint(t, gw, d.handler, d.path, ctype, string(form), jointWLOrg, jointWLKey)
		} else {
			rec = postJoint(t, gw, d.handler, d.path, "application/json", d.body, jointWLOrg, jointWLKey)
		}
		require.Equal(t, http.StatusTooManyRequests, rec.Code, "%s: %s", d.name, rec.Body.String())
		require.Contains(t, rec.Body.String(), "workload_budget_exceeded", d.name)
	}
	require.Equal(t, beforeHits, hits.Load(), "denied legs never reach the wire")
	require.Equal(t, beforeEvents, events.count(), "denied legs settle no completion event")

	// And the internal hop is capped by the same window (the detector loop
	// cannot outspend its workload).
	_, err = hopClient.JudgeChat(workloadHopContextID("req-joint-hop-denied", jointWLKey), hopReq)
	require.ErrorIs(t, err, budget.ErrWorkloadBudgetExceeded)
	require.Equal(t, int64(1), up2.hits.Load(), "a capped hop never reaches the wire")
	sharedLoopBudget().Release("req-joint-hop-denied")

	// ---- Control: the cap is per window, not per org or per process. -----
	rec = postJoint(t, gw, gw.chatCompletions, "/v1/chat/completions",
		"application/json", `{"model":"chat-m","messages":[{"role":"user","content":"hi"}]}`, jointWLOrg, "media-fleet-2")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String(),
		"a different workload of the same org keeps its own window")
}
