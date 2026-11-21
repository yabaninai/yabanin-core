//go:build integration

package accounting

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestAccountingMediaFamiliesBeforeDispatch closes the codec-scope gap
// the ten-family sweep documented for /v1/audio/speech (binary response)
// and /v1/audio/transcriptions (multipart request): the media codecs
// obey the same owner-approved pre-dispatch refusal contract — refuse
// with the documented 503 history_unavailable envelope when the durable
// accounting write path is broken, contact no provider, record no
// accounting, never contact the provider late under the refused id, and
// resume normal service with healthy route-specific controls around
// every fault window.
//
// The healthy controls are codec-honest, not token-shaped copies of the
// chat family:
//
//   - speech relays byte-exact binary audio with the upstream content
//     type and carries trusted 0/0 tokens: the codec has no token usage,
//     and no per-character unit catalog is seeded on this stand (the
//     product ships none by default; only an embedding-side install can
//     set one), so the durable outcome is the explicit unpriced status —
//     usage_source none, cost_status no_usage, zero cost, zero charge.
//     A priced zero would be a fabricated price, not an observation.
//   - transcription relays the known JSON reply byte-identically with
//     the family-distinct provider usage (11/0 — different from chat's
//     7/3 and embeddings' 7/0) billed exactly once under the minted
//     invocation as the signed 22 micro-USD zero-markup debit, and the
//     persisted payload is the metadata-only projection (D3 — audio
//     bytes never reach the event stream).
//
// Codec-specific negative controls run live on the same stand:
// streaming speech requests are refused 400 unsupported_feature with
// zero provider contact; bogus multipart bodies (not multipart, no
// file, multiple files, missing model) are refused 400 pre-admission
// with zero contact and zero accounting; and a 200 transcription reply
// whose usage block is malformed leaves the durable outcome fail-closed
// (no invented tokens, no fabricated price, no charge) while the
// byte-honest relay still succeeds.
//
// Real-stand full-suite execution happens under the heavy lease; the
// fixture detectors and validators backing this case are proven in
// isolation (TestMediaFixtureSelfCheck, TestMediaArtifactValidatorControls).
func TestAccountingMediaFamiliesBeforeDispatch(t *testing.T) {
	s := startStand(t)
	s.seedSecondOrg(t)

	for _, table := range []string{"request_admissions", "request_terminal_facts"} {
		if !s.oracleTableExists(t, table) {
			t.Fatalf("candidate is missing required accounting table %s", table)
		}
	}
	start := s.fixture.Snapshot()
	families := mediaFamilies()
	var targetRids []string
	for _, fam := range families {
		fam := fam
		t.Run(fam.name, func(t *testing.T) {
			s.mediaControl(t, fam, "pre")

			s.armAccountingWriteOutage(t)
			defer s.disarmAccountingWriteOutage(t)

			before := s.fixture.Snapshot()
			rid := familyRequestID(s, "tgt-media-refusal-", fam.name)
			targetRids = append(targetRids, rid)
			rep := fam.request(s, rid)
			if err := mediaRefusalArtifact(fam.name, rep); err != nil {
				t.Fatal(err)
			}
			s.requireZeroContact(t, fam.name, rid, before)
			s.disarmAccountingWriteOutage(t)

			s.mediaControl(t, fam, "post")
		})
	}

	s.requireGroupDrainedWithin(t, s.redisClient(t), 2*time.Minute)
	s.requireNoLateContactOrRetroBilling(t, targetRids)
	want := 2 * len(families) // one healthy control on each side of every fault
	if got := s.fixture.Since(start); got != (fixtureTotals{arrivals: want, dispatches: want, receipts: want}) {
		t.Fatalf("unexpected provider contact across all media refusal windows: got %+v, want %d healthy round trips", got, want)
	}

	s.classifyMediaCodecControls(t)
}

// mediaFamily mirrors refusalFamily for the two media codecs, with the
// durable expectations as per-family facts: token usage, usage source,
// cost status, cost, and the wallet/settlement outcome.
type mediaFamily struct {
	name           string
	upstream       string
	request        func(s *stand, rid string) mediaReply
	validate       func(rep mediaReply) error
	tokensIn       int
	tokensOut      int
	usageSource    string // "provider" | "none"
	costStatus     string // "priced" | "no_usage"
	costUSD        float64
	walletMicro    int64 // expected signed usage-transaction sum
	settlementJobs int   // expected invocation-scoped settlement jobs
}

// mediaFamilies enumerates the two media codec families with named
// request builders and validators (maintainability: bounded bodies, no
// mega-closures).
func mediaFamilies() []mediaFamily {
	return []mediaFamily{
		{
			name:     "audio speech",
			upstream: "/v1/audio/speech",
			request:  requestSpeech,
			validate: healthySpeechArtifact,
			// Trusted 0/0: the codec has no token usage. With no unit
			// catalog installed the durable outcome is the explicit
			// unpriced status, never a priced zero.
			tokensIn: 0, tokensOut: 0,
			usageSource: "none", costStatus: "no_usage", costUSD: 0,
			walletMicro: 0, settlementJobs: 0,
		},
		{
			name:     "audio transcription",
			upstream: "/v1/audio/transcriptions",
			request:  requestTranscription,
			validate: healthyTranscriptionReply,
			// 11 input tokens at the seeded 2.0 per-M rate, zero markup:
			// the signed 22 micro-USD debit, distinct from chat's 32.
			tokensIn: fixtureTranscribePromptTokens, tokensOut: fixtureTranscribeOutputTokens,
			usageSource: "provider", costStatus: "priced", costUSD: 22e-06,
			walletMicro: -fixtureTranscribeMicroUSDCost, settlementJobs: 1,
		},
	}
}

// requestSpeech sends one buffered speech request.
func requestSpeech(s *stand, rid string) mediaReply {
	status, body, contentType, err := httpPostSpeech(45*time.Second, s.gatewayURL+"/v1/audio/speech",
		s.apiKey, rid, s.model, fixtureSpeechInput, fixtureSpeechVoice)
	return mediaReply{status: status, body: body, contentType: contentType, err: err}
}

// requestTranscription sends one healthy multipart transcription request.
func requestTranscription(s *stand, rid string) mediaReply {
	status, body, contentType, err := httpPostMultipart(45*time.Second, s.gatewayURL+"/v1/audio/transcriptions",
		s.apiKey, rid, s.model, nil,
		multipartFile{filename: fixtureTranscribeAudioFile, contentType: fixtureTranscribeAudioContentType, data: fixtureWAVBytes()})
	return mediaReply{status: status, body: []byte(body), contentType: contentType, err: err}
}

// mediaControl proves a media family's healthy round trip: HTTP 200 with
// the codec-specific artifact validated against independently known
// bytes, exactly one whole-ledger arrival/dispatch/receipt on the
// family's OWN upstream path, retained evidence, one durable row with
// the family's token/usage/cost facts on both the log and the terminal
// fact, a confirmed admission under the same invocation, the
// wallet/settlement outcome, tenant-bound rows — and, for the multipart
// codec, the metadata-only payload projection (D3). It is the
// route-specific validity oracle: without it, a family's refusal window
// could be excused as an unusable route rather than the product's
// refusal.
func (s *stand) mediaControl(t *testing.T, fam mediaFamily, phase string) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := familyRequestID(s, "ctl-"+phase+"-", fam.name)
	rep := fam.request(s, rid)
	requireNoMediaArtifactError(t, fam.name, phase, fam.validate(rep))
	s.fixture.VerifyEvidence()
	delta := s.fixture.Since(before)
	if delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		a, d, r := s.fixture.Counts(rid)
		t.Fatalf("harness: %s control %s: whole-ledger delta arrivals/dispatches/receipts = %d/%d/%d, want 1/1/1 (id-matched %d/%d/%d); the provider-contact detector itself must be proven by a passing control before any fault window",
			fam.name, phase, delta.arrivals, delta.dispatches, delta.receipts, a, d, r)
	}
	if paths := s.fixture.ArrivalPaths(rid); len(paths) != 1 || paths[0] != fam.upstream {
		t.Fatalf("harness: %s control %s: arrival path(s) %v, want exactly [%s] — the request was not served by this family's own dispatch path",
			fam.name, phase, paths, fam.upstream)
	}
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 1
	}, "harness: %s control %s never became durable in request_logs", fam.name, phase)
	invocationID := s.requireMediaDurableEvidence(t, fam, phase, rid)
	if fam.upstream == "/v1/audio/transcriptions" {
		s.requireTranscriptionMetadataPayload(t, phase, rid, invocationID, fixtureTranscribeAudioFile)
	}
	s.requireMediaChargeEvidence(t, fam, phase, rid)
	s.requireMediaTenantBound(t, fam, phase, rid)
	t.Logf("harness: %s control %s ok (request id %s)", fam.name, phase, rid)
}

// requireMediaDurableEvidence is requireDurableControlEvidence
// generalized over the media families' durable facts: exactly one
// admission row in a confirmed state carrying an invocation id, exactly
// one linked terminal fact and log under that invocation with the
// family's tokens, and the family's usage_source/cost_status carried
// consistently on both surfaces. Speech's trusted 0/0 with usage_source
// none and cost_status no_usage is asserted here — a priced zero would
// be a fabricated price. Returns the invocation id for caller-side
// charge and payload assertions.
func (s *stand) requireMediaDurableEvidence(t *testing.T, fam mediaFamily, phase, rid string) string {
	t.Helper()
	rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	if len(rows) != 1 {
		t.Fatalf("product: %s control %s: %d admission row(s), want exactly 1 — the healthy dispatch was not durably confirmed", fam.name, phase, len(rows))
	}
	a := rows[0]
	requireAdmissionVocabulary(t, a)
	if a.State != "admitted" && a.State != "reconciled" {
		t.Fatalf("product: %s control %s: admission state %q is not a confirmed outcome — a healthy dispatch must not end voided or unresolved", fam.name, phase, a.State)
	}
	if a.InvocationID == "" {
		t.Fatalf("product: %s control %s: admission row carries no invocation id", fam.name, phase)
	}
	const linked = `SELECT count(*) FROM request_terminal_facts f
		JOIN request_logs l ON l.invocation_id = f.invocation_id AND l.org_id::text = f.org_id
		WHERE f.invocation_id=$1::uuid AND f.org_id=$2 AND f.client_request_id=$3
		AND l.request_id=$3 AND f.event->>'invocation_id'=f.invocation_id::text
		AND f.event->>'org_id'=f.org_id AND f.event->>'request_id'=f.client_request_id
		AND l.tokens_in=$4 AND l.tokens_out=$5
		AND f.event->>'tokens_in'=l.tokens_in::text AND f.event->>'tokens_out'=l.tokens_out::text
		AND l.usage_source=$6 AND l.cost_status=$7
		AND f.event->>'usage_source'=$6 AND f.event->>'cost_status'=$7
		AND abs(l.cost_in_usd - $8::double precision) < 1e-12`
	if n := s.oracleCount(t, linked, a.InvocationID, s.oracleDB.orgID, rid,
		fam.tokensIn, fam.tokensOut, fam.usageSource, fam.costStatus, fam.costUSD); n != 1 {
		t.Fatalf("product: %s control %s: expected one matching terminal fact and log with %d/%d tokens, usage_source %q, cost_status %q and cost %.2e under admission %s, got %d",
			fam.name, phase, fam.tokensIn, fam.tokensOut, fam.usageSource, fam.costStatus, fam.costUSD, a.InvocationID, n)
	}
	return a.InvocationID
}

// requireTranscriptionMetadataPayload asserts D3 for the multipart
// codec: the persisted event payload is the metadata-only projection —
// the file entry with filename, size and content type — and carries no
// raw audio bytes under any retention class.
func (s *stand) requireTranscriptionMetadataPayload(t *testing.T, phase, rid, invocationID, filename string) {
	t.Helper()
	const payload = `SELECT f.event->>'payload' FROM request_terminal_facts f
		WHERE f.invocation_id=$1::uuid AND f.org_id=$2 AND f.client_request_id=$3`
	var body string
	if err := s.oracleDB.db.QueryRow(payload, invocationID, s.oracleDB.orgID, rid).Scan(&body); err != nil {
		t.Fatalf("product: transcription %s: terminal fact carries no payload to inspect: %v", phase, err)
	}
	if !strings.Contains(body, `"file"`) || !strings.Contains(body, filename) {
		t.Fatalf("product: transcription %s: payload %s is not the metadata projection (want the file entry naming %s)", phase, clip(body), filename)
	}
	if bytes.Contains([]byte(body), []byte("RIFF")) || strings.Contains(body, "data:audio") {
		t.Fatalf("product: transcription %s: payload carries raw audio bytes — D3 violation (payload %s)", phase, clip(body))
	}
}

// requireMediaChargeEvidence asserts the wallet/settlement outcome of a
// healthy media control. A priced family bills exactly once under its
// minted invocation as the signed debit with at least one settlement
// job and no legacy-keyed duplicate; an unpriced family charges nothing
// anywhere — the explicit no_usage outcome must never surface as a
// zero-valued charge row or settlement job.
func (s *stand) requireMediaChargeEvidence(t *testing.T, fam mediaFamily, phase, rid string) {
	t.Helper()
	rows := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	if len(rows) != 1 {
		t.Fatalf("product: %s control %s: %d admission row(s), want exactly 1", fam.name, phase, len(rows))
	}
	if fam.walletMicro != 0 {
		s.requirePricedMediaCharge(t, fam, phase, rid, rows[0].InvocationID)
		return
	}
	if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows+c.TopupRows != 0 {
		t.Fatalf("product: %s control %s: %d credit transaction(s) for an unpriced codec (usage_source none, cost_status no_usage) — zero cost must never surface as a charge row (%+v)",
			fam.name, phase, c.UsageRows+c.TopupRows, c)
	}
	if n := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: %s control %s: %d settlement job(s) for an unpriced codec — no settlement may be scheduled for a request that never priced", fam.name, phase, n)
	}
}

// requirePricedMediaCharge asserts the priced-family wallet oracle: one
// signed debit of the family-distinct amount under the minted
// invocation, at least the expected settlement jobs, and no
// legacy correlation-keyed duplicates of either.
func (s *stand) requirePricedMediaCharge(t *testing.T, fam mediaFamily, phase, rid, invocationID string) {
	t.Helper()
	c := s.oracleUsageByInvocation(t, invocationID, s.oracleDB.orgID)
	if c.UsageRows != 1 || c.SumMicroUSD != fam.walletMicro {
		t.Fatalf("product: %s control %s: invocation %s has %d usage rows summing to %d micro-USD, want exactly 1 signed debit of %d (zero-markup resale of the family-distinct usage at the seeded rates)",
			fam.name, phase, invocationID, c.UsageRows, c.SumMicroUSD, fam.walletMicro)
	}
	if c.SumCents > 0 {
		t.Errorf("product: %s control %s: usage transaction for %s carries positive cents %d — a debit must not be positive", phase, fam.name, rid, c.SumCents)
	}
	if legacy := s.oracleCount(t,
		`SELECT count(*) FROM credit_transactions
		 WHERE org_id = $1 AND request_id = $2 AND type = 'usage'
		   AND invocation_id IS DISTINCT FROM $3::uuid`,
		s.oracleDB.orgID, rid, invocationID); legacy != 0 {
		t.Fatalf("product: %s control %s: %d legacy correlation-keyed usage rows for %s beside invocation %s — duplicate charge identity",
			fam.name, phase, legacy, rid, invocationID)
	}
	if jobs := s.oracleCount(t,
		`SELECT count(*) FROM settlement_jobs WHERE invocation_id = $1::uuid AND org_id = $2`,
		invocationID, s.oracleDB.orgID); jobs < fam.settlementJobs {
		t.Fatalf("product: %s control %s: %d settlement jobs under invocation %s, want at least %d",
			fam.name, phase, jobs, invocationID, fam.settlementJobs)
	}
	if legacy := s.oracleCount(t,
		`SELECT count(*) FROM settlement_jobs
		 WHERE org_id = $1 AND request_id = $2
		   AND invocation_id IS DISTINCT FROM $3::uuid`,
		s.oracleDB.orgID, rid, invocationID); legacy != 0 {
		t.Fatalf("product: %s control %s: %d legacy correlation-keyed settlement jobs for %s beside invocation %s — duplicate settlement identity",
			fam.name, phase, legacy, rid, invocationID)
	}
}

// requireMediaTenantBound asserts the second organization has no row of
// any kind for the control request: durable accounting is tenant-bound.
func (s *stand) requireMediaTenantBound(t *testing.T, fam mediaFamily, phase, rid string) {
	t.Helper()
	if n := s.oracleRequestLogCount(t, rid, s.orgB.orgID); n != 0 {
		t.Fatalf("product: %s control %s: %d request_logs row(s) visible to org %s — durable rows must be tenant-bound", fam.name, phase, n, s.orgB.name)
	}
	if c := s.oracleCreditTotals(t, rid, s.orgB.orgID); c.UsageRows+c.TopupRows != 0 {
		t.Fatalf("product: %s control %s: credit transactions visible to org %s (%+v) — charges must be tenant-bound", fam.name, phase, s.orgB.name, c)
	}
	if n := s.oracleAdmissionRowCount(t, rid, s.orgB.orgID); n != 0 {
		t.Fatalf("product: %s control %s: %d admission row(s) visible to org %s — admissions must be tenant-bound", fam.name, phase, n, s.orgB.name)
	}
}

// classifyMediaCodecControls proves, live, the codec-specific
// pre-admission contracts and the fail-closed usage rule on the same
// stand (classification-probe discipline: they are harness/route
// evidence executed on every run).
func (s *stand) classifyMediaCodecControls(t *testing.T) {
	t.Helper()
	t.Run("codec classification", func(t *testing.T) {
		s.classifySpeechStreamingRefused(t)
		s.classifyBogusMultipartRefused(t)
		s.classifyMalformedUsageFailClosed(t)
	})
}

// classifySpeechStreamingRefused proves the buffered-only speech
// contract: stream=true or an SSE Accept header is refused pre-admission
// with 400 unsupported_feature and zero provider contact (mirrors the
// realtime WebSocket transport refusal).
func (s *stand) classifySpeechStreamingRefused(t *testing.T) {
	t.Helper()
	for _, variant := range []struct {
		name   string
		extra  map[string]string
		stream bool
	}{
		{name: "stream flag", stream: true},
		{name: "sse accept", extra: map[string]string{"Accept": "text/event-stream"}},
	} {
		before := s.fixture.Snapshot()
		rid := familyRequestID(s, "cls-media-", "speech "+variant.name)
		payload := fmt.Sprintf(`{"model":%q,"input":%q,"voice":%q,"stream":%t}`,
			s.model, fixtureSpeechInput, fixtureSpeechVoice, variant.stream)
		status, body, _, err := httpPostJSONFull(45*time.Second, s.gatewayURL+"/v1/audio/speech",
			s.apiKey, rid, payload, variant.extra)
		if err != nil || status != 400 {
			t.Fatalf("product: speech %s: status=%d err=%v, want 400 (body %s) — the documented buffered-only refusal is missing",
				variant.name, status, err, clip(body))
		}
		code, ok := decodeErrorCode(body)
		if !ok || code != "unsupported_feature" {
			t.Fatalf("product: speech %s: error.code = %q (ok=%v), want unsupported_feature (body %s)",
				variant.name, code, ok, clip(body))
		}
		if delta := s.fixture.Since(before); delta.arrivals != 0 || delta.dispatches != 0 || delta.receipts != 0 {
			t.Fatalf("product: speech %s contacted the provider (%d/%d/%d), want 0/0/0 — the refusal must precede admission and any upstream work",
				variant.name, delta.arrivals, delta.dispatches, delta.receipts)
		}
		if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
			t.Fatalf("product: speech %s created %d request_logs row(s), want 0 — a codec-refused request records no accounting", variant.name, n)
		}
	}
}

// classifyBogusMultipartRefused proves the multipart pre-admission
// contract: a body that is not multipart, a multipart without a file
// part, with multiple file parts, or without a model field is refused
// 400 before admission with zero provider contact, zero accounting and
// no minted admission.
func (s *stand) classifyBogusMultipartRefused(t *testing.T) {
	t.Helper()
	file := multipartFile{filename: fixtureTranscribeAudioFile, contentType: fixtureTranscribeAudioContentType, data: fixtureWAVBytes()}
	bad := []struct {
		name    string
		request func(rid string) (int, string, error)
	}{
		{"not multipart", func(rid string) (int, string, error) {
			payload := fmt.Sprintf(`{"model":%q,"input":"text body"}`, s.model)
			return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/audio/transcriptions", s.apiKey, rid, payload)
		}},
		{"no file part", func(rid string) (int, string, error) {
			status, body, _, err := httpPostMultipart(45*time.Second, s.gatewayURL+"/v1/audio/transcriptions", s.apiKey, rid, s.model, nil)
			return status, body, err
		}},
		{"multiple file parts", func(rid string) (int, string, error) {
			status, body, _, err := httpPostMultipart(45*time.Second, s.gatewayURL+"/v1/audio/transcriptions", s.apiKey, rid, s.model, nil, file, file)
			return status, body, err
		}},
		{"missing model", func(rid string) (int, string, error) {
			status, body, _, err := httpPostMultipart(45*time.Second, s.gatewayURL+"/v1/audio/transcriptions", s.apiKey, rid, "", nil, file)
			return status, body, err
		}},
	}
	for _, c := range bad {
		before := s.fixture.Snapshot()
		rid := familyRequestID(s, "cls-media-", "transcription "+c.name)
		status, body, err := c.request(rid)
		if err != nil || status != 400 {
			t.Fatalf("product: transcription %s: status=%d err=%v, want 400 pre-admission (body %s) — the malformed upload must be refused before any upstream work",
				c.name, status, err, clip(body))
		}
		if delta := s.fixture.Since(before); delta.arrivals != 0 || delta.dispatches != 0 || delta.receipts != 0 {
			t.Fatalf("product: transcription %s contacted the provider (%d/%d/%d), want 0/0/0 — the refusal must precede admission and any upstream work",
				c.name, delta.arrivals, delta.dispatches, delta.receipts)
		}
		if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
			t.Fatalf("product: transcription %s created %d request_logs row(s), want 0", c.name, n)
		}
		if n := s.oracleAdmissionRowCount(t, rid, s.oracleDB.orgID); n != 0 {
			t.Fatalf("product: transcription %s minted %d admission row(s), want 0 — a codec-refused request never reaches admission", c.name, n)
		}
	}
}

// classifyMalformedUsageFailClosed proves the fail-closed usage rule of
// the multipart codec: a 200 reply whose usage block cannot parse as
// token counts still relays byte-identically, but the durable outcome is
// trusted 0/0 with usage_source none and cost_status no_usage — no
// invented tokens, no fabricated price, no charge, no settlement.
func (s *stand) classifyMalformedUsageFailClosed(t *testing.T) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := familyRequestID(s, "cls-media-", "transcription malformed usage")
	status, body, contentType, err := httpPostMultipart(45*time.Second, s.gatewayURL+"/v1/audio/transcriptions",
		s.apiKey, rid, s.model, nil,
		multipartFile{filename: fixtureTranscribeBadUsageFile, contentType: fixtureTranscribeAudioContentType, data: fixtureWAVBytes()})
	if err != nil || status != httpOK {
		t.Fatalf("product: transcription malformed usage: status=%d err=%v (body %s) — the byte-honest relay of the 200 reply must succeed",
			status, err, clip(body))
	}
	if body != fixtureTranscribeBadUsageReply {
		t.Fatalf("product: transcription malformed usage: relayed body %s is not byte-identical to the known corrupted reply %s",
			clip(body), fixtureTranscribeBadUsageReply)
	}
	if !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("product: transcription malformed usage: relayed content type %q, want application/json", contentType)
	}
	if delta := s.fixture.Since(before); delta.arrivals != 1 || delta.dispatches != 1 || delta.receipts != 1 {
		t.Fatalf("product: transcription malformed usage: delta arrivals/dispatches/receipts = %d/%d/%d, want 1/1/1",
			delta.arrivals, delta.dispatches, delta.receipts)
	}
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleRequestLogCount(t, rid, s.oracleDB.orgID) == 1
	}, "product: transcription malformed usage never became durable in request_logs")
	failClosed := mediaFamily{
		name: "audio transcription (malformed usage)", tokensIn: 0, tokensOut: 0,
		usageSource: "none", costStatus: "no_usage", costUSD: 0,
	}
	invocationID := s.requireMediaDurableEvidence(t, failClosed, "malformed usage", rid)
	s.requireTranscriptionMetadataPayload(t, "malformed usage", rid, invocationID, fixtureTranscribeBadUsageFile)
	if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows+c.TopupRows != 0 {
		t.Fatalf("product: transcription malformed usage: %d credit transaction(s) — uninterpretable usage must never be charged (%+v)",
			c.UsageRows+c.TopupRows, c)
	}
	if n := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: transcription malformed usage: %d settlement job(s) — uninterpretable usage must never be settled", n)
	}
	t.Logf("product: transcription malformed-usage reply classified: fail-closed 0/0, no invented tokens, no fabricated price (request id %s)", rid)
}

// TestAccountingMediaDisconnectedAfterDispatch is the media-codec
// instance of the admitted-request recovery case (recovery_test.go):
// once a speech request is irrevocably dispatched — the fixture has
// accepted and recorded the dispatch and holds the response at its
// barrier — killing only the gateway process and restarting it against
// the same storage must leave exactly one provider contact, a durable
// record that already existed at the barrier, the unresolved state
// positively identified rather than fabricated success, and — because
// the speech codec's outcome on this stand is the explicit unpriced
// trusted 0/0 — exactly zero usage rows and settlement jobs, not merely
// "at most one".
func TestAccountingMediaDisconnectedAfterDispatch(t *testing.T) {
	s := startStand(t)

	// Healthy control first: proves both detectors and the whole stand
	// work, so a missing durable record below is a product gap, not a
	// harness blind spot.
	s.controlRequest(t, "pre-crash")

	speech := mediaFamilies()[0]
	rid := s.reqPrefix + "tgt-media-recovery"
	s.fixture.Hold(rid)

	result := make(chan mediaReply, 1)
	go func() {
		result <- speech.request(s, rid)
	}()

	// Harness validity: the provider must actually accept the dispatch
	// (barrier reached) while the client keeps waiting.
	if !s.fixture.WaitForDispatch(rid, 30*time.Second) {
		t.Fatalf("harness: target speech request never reached the provider dispatch barrier — cannot test recovery of an admitted media request")
	}
	select {
	case r := <-result:
		t.Fatalf("harness: target speech request already finished (status=%d err=%v) before the crash — the case requires an in-flight request", r.status, r.err)
	case <-time.After(500 * time.Millisecond):
		// Still in flight, as required.
	}

	// Product assertion: a durable start record must exist NOW, before
	// the crash — the fact that makes recovery possible at all. Capture
	// the exact server-minted admission UUID so every post-restart
	// identity assertion binds to it (a duplicate mint under the same
	// HTTP invocation cannot hide behind a first-row read).
	ds := s.requireDurableStartAtBarrier(t, rid)

	before := s.fixture.Snapshot()
	s.killGatewaySIGKILL()

	// Release the held response: the dead gateway cannot receive it.
	s.fixture.ReleaseAll()
	select {
	case r := <-result:
		if r.err == nil && r.status == httpOK {
			t.Fatalf("harness: client received a successful completion (%d) although the gateway died mid-flight", r.status)
		}
		t.Logf("harness: client observed the crash as expected (status=%d err=%v)", r.status, r.err)
	case <-time.After(10 * time.Second):
		t.Fatalf("harness: client speech request did not terminate after the gateway was killed")
	}

	s.restartGateway()

	// Independent provider oracle: the whole case (including the
	// restart) must have caused exactly one provider contact and one
	// accepted dispatch. A recovery that re-dispatches bills twice.
	s.fixture.VerifyEvidence()
	if delta := s.fixture.Since(before); delta.arrivals != 0 {
		t.Fatalf("product: media recovery case: %d additional provider contact(s) after the accepted dispatch (restart must not re-dispatch)", delta.arrivals)
	}
	if a, d, r := s.fixture.Counts(rid); a != 1 || d != 1 || r != 0 {
		t.Fatalf("product: media recovery case: provider arrivals/dispatches/receipts for %s = %d/%d/%d, want 1/1/0 (the response was never delivered back)",
			rid, a, d, r)
	}

	// Storage oracle (current b966c29 unresolved contract): discover the
	// crashed media request through exactly one admission bound to the
	// pre-crash captured UUID. The audit log is OPTIONAL — when rows are
	// present they must not fabricate success (validated below); no
	// mandatory request_logs row and no "at most one" admission slack.
	s.requireMediaUnresolvedDurableState(t, ds, rid, "after restart")

	// Speech-specific charge boundary: the codec's unpriced trusted 0/0
	// outcome means a crashed speech request can never legitimately
	// produce a charge — exactly zero usage rows and settlement jobs,
	// a stronger bound than the chat family's "at most one".
	if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows+c.TopupRows != 0 {
		t.Fatalf("product: media recovery case: %d credit transaction(s) for the crashed speech request — an unpriced codec must never charge, not even once (%+v)",
			c.UsageRows+c.TopupRows, c)
	}
	if n := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("product: media recovery case: %d settlement job(s) for the crashed speech request — an unpriced codec must never schedule settlement", n)
	}

	// The stand must still be healthy after recovery.
	s.controlRequest(t, "post-recovery")
	t.Logf("product: media recovery case passed (request id %s)", rid)
}

// requireMediaUnresolvedDurableState asserts, at recovery time, the
// b966c29 unresolved contract for a crashed media request: discovery via
// exactly one tenant-bound admission matching the UUID captured at the
// dispatch barrier (requireDurableStartAtBarrier) — no duplicate mint,
// no success-shaped state; the audit log (request_logs) may be absent,
// and any rows present must not fabricate success; zero fabricated
// terminal facts; zero admissions under a foreign org. Wallet, credit-row
// and settlement zeros are asserted by the caller's codec boundary below.
// The eventual unresolved transition (grace window, exact resolve reason)
// is owned by the sibling unresolved case, not this immediate check.
func (s *stand) requireMediaUnresolvedDurableState(t *testing.T, ds durableStart, rid, phase string) {
	t.Helper()
	if ds.invocationUUID == "" {
		t.Fatalf("%s: media recovery case: no admitted invocation UUID was captured for %s at the dispatch barrier — the admissions-backed start is required to bind post-restart identity", phase, rid)
	}
	adm := s.oracleAdmissions(t, rid, s.oracleDB.orgID)
	if len(adm) != 1 {
		t.Fatalf("%s: media recovery case: %d admission row(s) for %s (%s), want exactly 1 bound to the captured UUID %s",
			phase, len(adm), rid, fmtAdmissions(adm), ds.invocationUUID)
	}
	if adm[0].InvocationID != ds.invocationUUID {
		t.Fatalf("%s: media recovery case: admission UUID changed across the restart: barrier %s, now %s", phase, ds.invocationUUID, adm[0].InvocationID)
	}
	requireAdmissionVocabulary(t, adm[0])
	if adm[0].State == "reconciled" {
		t.Fatalf("%s: media recovery case: admission state for %s is %q — claims completion although the provider response was never delivered back", phase, rid, adm[0].State)
	}
	t.Logf("product: media recovery case: %s: crashed request discoverable via admission %s in state %q", phase, ds.invocationUUID, adm[0].State)

	// Tenant binding: the admission must surface only under this stand's org.
	if foreign := s.oracleAdmissions(t, rid, "org-not-this-tenant"); len(foreign) != 0 {
		t.Fatalf("%s: media recovery case: admission rows for %s leaked under a foreign org: %s", phase, rid, fmtAdmissions(foreign))
	}

	// No fabricated terminal evidence behind the not-completed state.
	if n := s.oracleTerminalFactsCount(t, rid, s.oracleDB.orgID); n != 0 {
		t.Fatalf("%s: media recovery case: %d terminal facts row(s) for %s although the provider response was never delivered back", phase, n, rid)
	}

	// Audit log is optional; present rows must not fabricate success.
	logRows := s.oracleRequestLogRows(t, rid, s.oracleDB.orgID)
	requireNoFabricatedRequestLogRows(t, rid, s.oracleDB.orgID, logRows, phase)
	t.Logf("product: media recovery case: %s: audit log rows=%d (optional; none fabricate success)", phase, len(logRows))
}
