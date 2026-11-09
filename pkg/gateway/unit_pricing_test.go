package cli

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// stubUnitPricer serves a hand-built unit table: entries are keyed
// "provider:model" exactly as LookupUnit receives them.
type stubUnitPricer struct {
	entries map[string]pricing.UnitEntry
}

func (s stubUnitPricer) LookupUnit(providerName, model string) (pricing.UnitEntry, bool) {
	e, ok := s.entries[providerName+":"+model]
	return e, ok
}

// Synthetic operator rates exercise settlement without redistributing a price
// corpus. Model IDs are adapter test identities, not claims about market prices.
const (
	fixtureSpeechRate        = 0.000032
	fixtureTranscriptionRate = 0.000128
	fixtureImageRate         = 0.125
)

func operatorUnitsForTest(t *testing.T) *pricing.UnitFilePricer {
	t.Helper()
	up, err := pricing.NewUnitFilePricer(pricing.UnitFile{
		Source: "authored synthetic gateway settlement fixture", Date: "2026-11-09", Currency: "USD",
		Units: []pricing.UnitEntry{
			{Provider: "openai", Model: "tts-1", Unit: pricing.UnitPerCharacter, Rate: fixtureSpeechRate},
			{Provider: "openai", Model: "whisper-1", Unit: pricing.UnitPerAudioSecond, Rate: fixtureTranscriptionRate},
			{Provider: "openai", Model: "gpt-image-1", Unit: pricing.UnitPerImage, Rate: fixtureImageRate},
		},
	}, "synthetic-gateway-unit-fixture")
	if err != nil {
		t.Fatalf("load synthetic operator units: %v", err)
	}
	return up
}

// stubUnitUpstream starts an upstream answering every request with the given
// JSON body.
func stubUnitUpstream(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

// unitEventCapture registers an eventNote sink on the gateway and returns a
// reader for the published request.completed event (nil before publication).
func unitEventCapture(gw *gateway) func() *eventpub.Event {
	var ev atomic.Value
	ev.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { ev.Store(e) }
	return func() *eventpub.Event { return ev.Load().(*eventpub.Event) }
}

// TestUnitHelpers pins the T02 quantity/estimate helpers: the audio-second
// reservation is the size-derived ceiling at the 8 kbit/s floor, the image
// count defaults missing/invalid n to 1, the duration parser accepts only a
// finite non-negative JSON number, and costStatusUnit lifts a bare no_usage
// to priced exactly once.
func TestUnitHelpers(t *testing.T) {
	t.Run("transcription reservation seconds", func(t *testing.T) {
		cases := []struct {
			bytes int
			want  float64
		}{
			{bytes: 0, want: 0},
			{bytes: 1, want: 1},
			{bytes: 1000, want: 1}, // 8 kbit/s floor
			{bytes: 1001, want: 2}, // ceil(1.001)
			{bytes: 2500, want: 3}, // ceil(2.5)
			{bytes: 100000, want: 100},
		}
		for _, tc := range cases {
			if got := transcriptionReservationSeconds(tc.bytes); got != tc.want {
				t.Fatalf("transcriptionReservationSeconds(%d) = %v, want %v", tc.bytes, got, tc.want)
			}
		}
	})
	t.Run("images request count", func(t *testing.T) {
		two := int64(2)
		neg := int64(-3)
		zero := int64(0)
		cases := []struct {
			name string
			n    *int64
			want float64
		}{
			{name: "nil defaults to 1", n: nil, want: 1},
			{name: "negative clamps to 1", n: &neg, want: 1},
			{name: "zero clamps to 1", n: &zero, want: 1},
			{name: "explicit n", n: &two, want: 2},
		}
		for _, tc := range cases {
			if got := imagesRequestCount(tc.n); got != tc.want {
				t.Fatalf("%s: imagesRequestCount = %v, want %v", tc.name, got, tc.want)
			}
		}
	})
	t.Run("transcription response duration", func(t *testing.T) {
		cases := []struct {
			name   string
			body   string
			want   float64
			wantOK bool
		}{
			{name: "duration", body: `{"text":"hi","duration":7.5}`, want: 7.5, wantOK: true},
			{name: "integer duration", body: `{"duration":3}`, want: 3, wantOK: true},
			{name: "missing duration", body: `{"text":"hi"}`},
			{name: "string duration", body: `{"duration":"7.5"}`},
			{name: "negative duration", body: `{"duration":-1}`},
			{name: "not json", body: "\x00\x01"},
		}
		for _, tc := range cases {
			got, ok := transcriptionResponseDuration([]byte(tc.body))
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("%s: transcriptionResponseDuration = (%v,%v), want (%v,%v)", tc.name, got, ok, tc.want, tc.wantOK)
			}
		}
	})
	t.Run("cost status unit lift", func(t *testing.T) {
		cases := []struct {
			base       string
			unitPriced bool
			want       string
		}{
			{base: "no_usage", unitPriced: true, want: "priced"},
			{base: "no_usage", unitPriced: false, want: "no_usage"},
			{base: "unknown_price", unitPriced: true, want: "unknown_price"},
			{base: "priced", unitPriced: true, want: "priced"},
			{base: "cache_hit", unitPriced: false, want: "cache_hit"},
			{base: "legacy", unitPriced: false, want: "legacy"},
		}
		for _, tc := range cases {
			if got := costStatusUnit(tc.base, tc.unitPriced); got != tc.want {
				t.Fatalf("costStatusUnit(%q,%v) = %q, want %q", tc.base, tc.unitPriced, got, tc.want)
			}
		}
	})
}

// TestAudioSpeech_UnitPricedSettlement: with a synthetic operator catalog wired,
// tts-1 settles at rate × unicode input characters; the event keeps usage
// source "none" and zero tokens (no invented token counts) but the cost
// status lifts to "priced".
func TestAudioSpeech_UnitPricedSettlement(t *testing.T) {
	mp3 := audioFixtureBytes(t, "hello.mp3")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(mp3)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTestModel(server.URL))
	gw.unitPricer = operatorUnitsForTest(t)
	read := unitEventCapture(gw)

	rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hello","voice":"alloy"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(mp3) {
		t.Fatal("audio bytes not byte-identical")
	}
	got := read()
	if got == nil {
		t.Fatal("no request.completed event")
	}
	entry, ok := gw.unitPrice("openai", "tts-1", pricing.UnitPerCharacter)
	if !ok {
		t.Fatal("catalog lost tts-1 per_character")
	}
	if want := entry.Rate * 5; got.EstimatedCostUSD != want { // "hello" = 5 runes
		t.Fatalf("cost %v, want %v", got.EstimatedCostUSD, want)
	}
	if got.UsageSource != "none" || got.TokensIn != 0 || got.TokensOut != 0 {
		t.Fatalf("tokens/source must stay zero-none: %+v", got)
	}
	if got.CostStatus != "priced" {
		t.Fatalf("cost status %q, want priced", got.CostStatus)
	}
}

// TestAudioSpeech_UnitUnpricedStaysNoUsage: an empty unit catalog (or no
// catalog at all) leaves the D2 status quo — cost 0, cost status "no_usage".
func TestAudioSpeech_UnitUnpricedStaysNoUsage(t *testing.T) {
	builtIn, err := pricing.LoadBundledUnits()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		pricer pricing.UnitPricer
	}{
		{name: "catalog without the model", pricer: stubUnitPricer{entries: map[string]pricing.UnitEntry{
			"openai:other-tts": {Provider: "openai", Model: "other-tts", Unit: pricing.UnitPerCharacter, Rate: 0.01},
		}}},
		{name: "no catalog", pricer: nil},
		{name: "built-in default has no shipped unit rates", pricer: builtIn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "audio/mpeg")
				_, _ = w.Write([]byte{0x01, 0x02})
			}))
			defer server.Close()

			gw := newAudioGateway(t, audioTestModel(server.URL))
			gw.unitPricer = tc.pricer
			read := unitEventCapture(gw)

			rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hello","voice":"alloy"}`, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			got := read()
			if got == nil {
				t.Fatal("no request.completed event")
			}
			if got.EstimatedCostUSD != 0 || got.CostStatus != "no_usage" || got.UsageSource != "none" {
				t.Fatalf("event must stay zero-cost no_usage: %+v", got)
			}
		})
	}
}

// TestAudioTranscriptions_UnitPricedDuration: verbose_json responses settle
// at the catalog per-second rate × the upstream duration; usage source stays
// "none" with zero tokens and the cost status lifts to "priced".
func TestAudioTranscriptions_UnitPricedDuration(t *testing.T) {
	server := stubUnitUpstream(t, `{"text":"hi","duration":7.5,"language":"en"}`)
	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	gw.unitPricer = operatorUnitsForTest(t)
	read := unitEventCapture(gw)

	wav := audioFixtureBytes(t, "hello.wav")
	body, ct := buildAudioMultipart(t, map[string]string{
		"model":           "m",
		"response_format": "verbose_json",
	}, "file", "hello.wav", "audio/wav", wav)
	rec := postAudioTranscriptions(t, gw, body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	got := read()
	if got == nil {
		t.Fatal("no request.completed event")
	}
	entry, ok := gw.unitPrice("openai", "whisper-1", pricing.UnitPerAudioSecond)
	if !ok {
		t.Fatal("catalog lost whisper-1 per_second_audio")
	}
	if want := entry.Rate * 7.5; got.EstimatedCostUSD != want {
		t.Fatalf("cost %v, want %v", got.EstimatedCostUSD, want)
	}
	if got.UsageSource != "none" || got.TokensIn != 0 || got.TokensOut != 0 {
		t.Fatalf("tokens/source must stay zero-none: %+v", got)
	}
	if got.CostStatus != "priced" {
		t.Fatalf("cost status %q, want priced", got.CostStatus)
	}
}

// TestAudioTranscriptions_UsageBlockBeatsDuration: when the upstream reports
// a token usage block the unit fallback never fires — the duration present
// in the same response is not billed, the provider source and tokens flow
// through and the status stays honestly unknown.
func TestAudioTranscriptions_UsageBlockBeatsDuration(t *testing.T) {
	server := stubUnitUpstream(t,
		`{"text":"hi","duration":7.5,"usage":{"prompt_tokens":11,"output_tokens":3}}`)
	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	gw.unitPricer = operatorUnitsForTest(t)
	read := unitEventCapture(gw)

	wav := audioFixtureBytes(t, "hello.wav")
	body, ct := buildAudioMultipart(t, map[string]string{
		"model":           "m",
		"response_format": "verbose_json",
	}, "file", "hello.wav", "audio/wav", wav)
	rec := postAudioTranscriptions(t, gw, body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	got := read()
	if got == nil {
		t.Fatal("no request.completed event")
	}
	if got.TokensIn != 11 || got.TokensOut != 3 || got.UsageSource != "provider" {
		t.Fatalf("provider usage must flow through: %+v", got)
	}
	if got.EstimatedCostUSD != 0 || got.CostStatus != "unknown_price" {
		t.Fatalf("unit rate must not fire on provider usage: %+v", got)
	}
}

// TestAudioTranscriptions_NoDurationStaysUnknown: a plain text/JSON response
// without a duration stays on the legacy settlement even with the unit
// catalog wired — the size-derived reservation quantity is never reused for
// billing.
func TestAudioTranscriptions_NoDurationStaysUnknown(t *testing.T) {
	server := stubUnitUpstream(t, `{"text":"hi"}`)
	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	gw.unitPricer = operatorUnitsForTest(t)
	read := unitEventCapture(gw)

	wav := audioFixtureBytes(t, "hello.wav")
	body, ct := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
	rec := postAudioTranscriptions(t, gw, body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	got := read()
	if got == nil {
		t.Fatal("no request.completed event")
	}
	if got.EstimatedCostUSD != 0 || got.CostStatus != "no_usage" {
		t.Fatalf("no-duration response must stay zero-cost no_usage: %+v", got)
	}
}

// newUnitImagesGateway builds an images.generation gateway whose stub
// upstream answers with the given JSON body and whose unit catalog is the
// synthetic operator catalog.
func newUnitImagesGateway(t *testing.T, upstreamBody string) (*gateway, func() *eventpub.Event) {
	t.Helper()
	server := stubUnitUpstream(t, upstreamBody)
	info := resolver.ModelInfo{ModelName: "gpt-image-1", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
	gw := imagesTestGateway(t, info, server.URL)
	gw.unitPricer = operatorUnitsForTest(t)
	return gw, unitEventCapture(gw)
}

// TestImages_UnitPricedSettlement: without a token-priced usage block, a
// model the unit catalog prices per image settles at n × rate; the cost
// status lifts to "priced" even though the upstream reported no usage.
func TestImages_UnitPricedSettlement(t *testing.T) {
	tiny := base64.StdEncoding.EncodeToString(testTinyPNG)
	gw, read := newUnitImagesGateway(t,
		`{"created":1790000000,"data":[{"b64_json":"`+tiny+`"},{"b64_json":"`+tiny+`"}]}`)

	rec := postImages(t, gw, `{"model":"m","prompt":"two red cubes","n":2}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	ev := read()
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.EstimatedCostUSD != 2*fixtureImageRate {
		t.Fatalf("cost %v, want two synthetic image units", ev.EstimatedCostUSD)
	}
	if ev.CostStatus != "priced" {
		t.Fatalf("cost status %q, want priced", ev.CostStatus)
	}
	if ev.UsageSource != "none" || ev.TokensIn != 0 || ev.TokensOut != 0 {
		t.Fatalf("tokens/source must stay zero-none: %+v", ev)
	}
}

// TestImages_UnitPricedDefaultsToOne: a request without n bills exactly one
// image.
func TestImages_UnitPricedDefaultsToOne(t *testing.T) {
	tiny := base64.StdEncoding.EncodeToString(testTinyPNG)
	gw, read := newUnitImagesGateway(t,
		`{"created":1790000000,"data":[{"b64_json":"`+tiny+`"}]}`)

	rec := postImages(t, gw, `{"model":"m","prompt":"one red cube"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	ev := read()
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.EstimatedCostUSD != fixtureImageRate {
		t.Fatalf("cost %v, want one synthetic image unit (n defaults to 1)", ev.EstimatedCostUSD)
	}
	if ev.CostStatus != "priced" {
		t.Fatalf("cost status %q, want priced", ev.CostStatus)
	}
}

// TestImages_UsageBlockStillUnitPricedForUnpricedTokens: gpt-image-1 reports
// token usage the token catalog cannot price — the unit fallback still
// applies; the provider usage flows through as tokens while the cost comes
// from the per-image rate.
func TestImages_UsageBlockStillUnitPricedForUnpricedTokens(t *testing.T) {
	tiny := base64.StdEncoding.EncodeToString(testTinyPNG)
	gw, read := newUnitImagesGateway(t,
		`{"created":1790000000,"data":[{"b64_json":"`+tiny+`"}],"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444}}`)

	rec := postImages(t, gw, `{"model":"m","prompt":"three red cubes","n":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	ev := read()
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.TokensIn != 20 || ev.TokensOut != 1424 || ev.UsageSource != "provider" {
		t.Fatalf("provider usage must flow through: %+v", ev)
	}
	if want := 3 * fixtureImageRate; ev.EstimatedCostUSD != want {
		t.Fatalf("cost %v, want %v", ev.EstimatedCostUSD, want)
	}
	if ev.CostStatus != "priced" {
		t.Fatalf("cost status %q, want priced", ev.CostStatus)
	}
}

// TestImages_UnitUnpricedStaysUnknownPrice: a model missing from the unit
// catalog keeps the D1/D2 status quo — no usage block means cost 0 with
// "no_usage"; a usage block the token catalog cannot price stays cost 0
// with "unknown_price". Neither path invents a cost.
func TestImages_UnitUnpricedStaysUnknownPrice(t *testing.T) {
	tiny := base64.StdEncoding.EncodeToString(testTinyPNG)
	cases := []struct {
		name           string
		upstreamBody   string
		wantCostStatus string
	}{
		{
			name:           "no usage block",
			upstreamBody:   `{"created":1,"data":[{"b64_json":"` + tiny + `"}]}`,
			wantCostStatus: "no_usage",
		},
		{
			name:           "usage block, tokens unpriced",
			upstreamBody:   `{"created":1,"data":[{"b64_json":"` + tiny + `"}],"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444}}`,
			wantCostStatus: "unknown_price",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := stubUnitUpstream(t, tc.upstreamBody)
			info := resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
			gw := imagesTestGateway(t, info, server.URL)
			gw.unitPricer = operatorUnitsForTest(t) // no entry for the -canon name
			read := unitEventCapture(gw)

			rec := postImages(t, gw, `{"model":"m","prompt":"one red cube","n":2}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			ev := read()
			if ev == nil {
				t.Fatal("no request.completed event")
			}
			if ev.EstimatedCostUSD != 0 || ev.CostStatus != tc.wantCostStatus {
				t.Fatalf("unpriced model must stay zero-cost %s: %+v", tc.wantCostStatus, ev)
			}
		})
	}
}

// TestGatewayUnitPriceNilSafe: a nil catalog (hand-built gateways) and a
// model with the wrong unit kind both resolve to unpriced — the fail-closed
// contract of the gateway helper.
func TestGatewayUnitPriceNilSafe(t *testing.T) {
	gw := newAudioGateway(t, audioTestModel("http://unused.invalid"))
	if _, ok := gw.unitPrice("openai", "tts-1", pricing.UnitPerCharacter); ok {
		t.Fatal("nil unitPricer must be unpriced")
	}
	gw.unitPricer = operatorUnitsForTest(t)
	if _, ok := gw.unitPrice("openai", "tts-1", pricing.UnitPerImage); ok {
		t.Fatal("wrong unit kind must be unpriced")
	}
	if _, ok := gw.unitPrice("openai", "whisper-1", pricing.UnitPerAudioSecond); !ok {
		t.Fatal("whisper-1 per_second_audio must price from the operator catalog")
	}
	if _, ok := gw.unitPrice("nonexistent", "m", pricing.UnitPerImage); ok {
		t.Fatal("unknown provider must be unpriced")
	}
}
