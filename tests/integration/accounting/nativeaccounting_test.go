//go:build integration

package accounting

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/stretchr/testify/require"
)

// D1 dynamic regression for the native Anthropic Messages protocol
// (/v1/messages): the accounting contract proven for chat in this package
// must hold identically when the product serves the provider-native
// protocol instead of a translated one. Everything is driven through the
// real binary's published HTTP surface; the fixture ledger and the owner
// database are the only oracles. Stream-ordering (terminal frame only
// after the durable terminal commit) is proven separately in
// nativestreamterminal_test.go for both native protocols.

// provisionNativeAnthropicModel registers a provider-anthropic model
// routing at this stand's fixture through the same shapes seed uses for
// the chat model: the fixture credential encrypted with the stand's
// retained seed key, operator-known per-million rates and a zero-markup
// resale row, so every durable accounting oracle (billed 7/3-token row at
// the stand rates, wallet debit of exactly 32 micro-USD) applies
// unchanged. The model name is never looked up before this insert, and
// the resolver/pricer caches hold no stale entries for it (misses are
// not cached; the first lookup is served live from the database).
func (s *stand) provisionNativeAnthropicModel(t *testing.T) string {
	t.Helper()
	model := "acc-anth-model-" + s.runID
	enc, err := encryption.New(s.encKey)
	require.NoError(t, err, "harness: build encryptor from the stand's retained seed key")
	ciphertext, err := enc.Encrypt(s.fixtureTok)
	require.NoError(t, err, "harness: encrypt the fixture credential like seed does")
	s.oracleExec(t, "register native anthropic model", `
		INSERT INTO models_registry (
			model_name, display_name, tier, provider, upstream_url, upstream_api_key,
			failover_models, tier_pool, upstream_timeout_ms, enabled
		) VALUES ($1, $2, 'smart', 'anthropic', $3, $4, '{}', '{easy,medium,hard}', 180000, true)
		ON CONFLICT (model_name) DO NOTHING`,
		model, model+" (native fixture)", s.fixture.baseURL(), ciphertext)
	s.oracleExec(t, "install native anthropic model pricing",
		`INSERT INTO models_pricing (provider, model, input_per_m, output_per_m, source)
		 VALUES ('anthropic', $1, $2, $3, 'manual')`,
		model, s.pricingInputPerM, s.pricingOutputPerM)
	s.oracleExec(t, "install zero-markup resale pricing for the native anthropic model",
		`INSERT INTO reseller_pricing (org_id, model_name, markup_pct, active)
		 VALUES ($1, $2, 0, true)`, s.oracleDB.orgID, model)
	return model
}

// nativeMessages sends one Anthropic-native Messages request against the
// provisioned native model in the requested delivery mode.
func (s *stand) nativeMessages(t *testing.T, model, rid string, stream bool, timeout time.Duration) (int, string, error) {
	t.Helper()
	payload := fmt.Sprintf(
		`{"model":%q,"max_tokens":32,"stream":%t,"messages":[{"role":"user","content":"native accounting probe"}]}`,
		model, stream)
	return httpPostJSON(timeout, s.gatewayURL+"/v1/messages", s.apiKey, rid, payload)
}

// --- Anthropic Messages document shapes (client side) ------------------

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicMessageDoc struct {
	ID         string                  `json:"id"`
	Type       string                  `json:"type"`
	Role       string                  `json:"role"`
	Content    []anthropicContentBlock `json:"content"`
	Model      string                  `json:"model"`
	StopReason string                  `json:"stop_reason"`
	Usage      anthropicUsage          `json:"usage"`
}

type anthropicErrorBody struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type anthropicErrorDoc struct {
	Type  string             `json:"type"`
	Error anthropicErrorBody `json:"error"`
}

// validateNativeMessageReply asserts the buffered native reply is the
// fixture's own document: known content and usage survived the native
// protocol without translation.
func validateNativeMessageReply(t *testing.T, s *stand, body string) {
	t.Helper()
	var doc anthropicMessageDoc
	require.NoError(t, json.Unmarshal([]byte(body), &doc),
		"native anthropic buffered: reply is not a JSON message document (body %s)", clip(body))
	require.Equal(t, "message", doc.Type, "native anthropic buffered: document type")
	require.Equal(t, "assistant", doc.Role, "native anthropic buffered: role")
	require.Len(t, doc.Content, 1, "native anthropic buffered: content blocks")
	require.Equal(t, "text", doc.Content[0].Type, "native anthropic buffered: content type")
	require.Equal(t, fixtureAssistantContent, doc.Content[0].Text, "native anthropic buffered: content")
	require.Equal(t, "end_turn", doc.StopReason, "native anthropic buffered: stop reason")
	require.Equal(t, fixturePromptTokens, doc.Usage.InputTokens, "native anthropic buffered: input tokens")
	require.Equal(t, fixtureCompletionTokens, doc.Usage.OutputTokens, "native anthropic buffered: output tokens")
}

// validateNativeMessageStream asserts the relayed native SSE sequence:
// the fixture's six protocol frames, byte-honestly relayed, with the
// prefix usage in message_start, the known content in the text delta and
// the terminal usage in message_delta. No [DONE] sentinel exists in this
// protocol; a clean EOF after message_stop is the expected end.
func validateNativeMessageStream(t *testing.T, s *stand, body string) {
	t.Helper()
	frames := controlSSEFrames(t, body)
	names := make([]string, len(frames))
	for i, fr := range frames {
		names[i] = fr.Event
	}
	require.Equal(t, []string{
		"message_start", "content_block_start", "content_block_delta",
		"content_block_stop", "message_delta", "message_stop",
	}, names, "native anthropic sse: relayed event sequence (body %s)", clip(body))
	requireNoDONESentinel(t, "native anthropic sse", frames)

	var start struct {
		Message anthropicMessageDoc `json:"message"`
	}
	require.NoError(t, json.Unmarshal([]byte(frames[0].Data), &start),
		"native anthropic sse: message_start payload (data %s)", clip(frames[0].Data))
	require.Equal(t, fixturePromptTokens, start.Message.Usage.InputTokens,
		"native anthropic sse: message_start prefix usage")

	var delta struct {
		Delta struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"delta"`
	}
	require.NoError(t, json.Unmarshal([]byte(frames[2].Data), &delta),
		"native anthropic sse: content_block_delta payload (data %s)", clip(frames[2].Data))
	require.Equal(t, "text_delta", delta.Delta.Type, "native anthropic sse: delta type")
	require.Equal(t, fixtureAssistantContent, delta.Delta.Text, "native anthropic sse: delta text")

	var term struct {
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
		Usage anthropicUsage `json:"usage"`
	}
	require.NoError(t, json.Unmarshal([]byte(frames[4].Data), &term),
		"native anthropic sse: message_delta payload (data %s)", clip(frames[4].Data))
	require.Equal(t, "end_turn", term.Delta.StopReason, "native anthropic sse: terminal stop reason")
	require.Equal(t, fixtureCompletionTokens, term.Usage.OutputTokens, "native anthropic sse: terminal usage")
}

// requireNativeMessagesRefusal asserts the pre-dispatch refusal contract
// on the native protocol: HTTP 503 with the Anthropic error envelope
// carrying the history_unavailable gateway code in the message prefix
// (apierrors.Anthropic renders "[code] message") and the 503 vocabulary
// type. A stream:true target gets the same JSON refusal — the request is
// refused before dispatch, so no SSE is ever started.
func requireNativeMessagesRefusal(t *testing.T, status int, body, phase string) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, status, "%s: status (body %s)", phase, clip(body))
	var doc anthropicErrorDoc
	require.NoError(t, json.Unmarshal([]byte(body), &doc), "%s: body is not an Anthropic error document (body %s)", phase, clip(body))
	require.Equal(t, "error", doc.Type, "%s: envelope type", phase)
	require.Equal(t, "overloaded_error", doc.Error.Type, "%s: error type must use the 503 vocabulary", phase)
	require.True(t, strings.HasPrefix(doc.Error.Message, "[history_unavailable]"),
		"%s: error message %q must carry the history_unavailable code prefix", phase, doc.Error.Message)
}

// requireNativeMessagesTerminalFailure asserts the post-dispatch
// terminal-facts failure contract on the buffered native path: exactly
// one truthful terminal — HTTP 500 with the Anthropic error envelope
// carrying the accounting_commit_failed code — instead of a success
// reply whose usage was never made durable.
func requireNativeMessagesTerminalFailure(t *testing.T, status int, body, phase string) {
	t.Helper()
	require.Equal(t, http.StatusInternalServerError, status, "%s: status (body %s)", phase, clip(body))
	var doc anthropicErrorDoc
	require.NoError(t, json.Unmarshal([]byte(body), &doc), "%s: body is not an Anthropic error document (body %s)", phase, clip(body))
	require.Equal(t, "error", doc.Type, "%s: envelope type", phase)
	require.Equal(t, "api_error", doc.Error.Type, "%s: error type must use the 500 vocabulary", phase)
	require.True(t, strings.HasPrefix(doc.Error.Message, "[accounting_commit_failed]"),
		"%s: error message %q must carry the accounting_commit_failed code prefix", phase, doc.Error.Message)
}

// requireNativeMessagesStreamTerminalFailure asserts the same contract
// on the native stream path: the nonterminal content was already
// delivered, then exactly one protocol error event carrying
// accounting_commit_failed, and never a message_stop — a second,
// untruthful terminal — after the failed commit.
func requireNativeMessagesStreamTerminalFailure(t *testing.T, body, phase string) {
	t.Helper()
	frames := controlSSEFrames(t, body)
	requireNoDONESentinel(t, phase, frames)
	errEvents := 0
	sawContent, sawStop := false, false
	for _, fr := range frames {
		switch fr.Event {
		case "content_block_delta":
			sawContent = true
		case "message_stop":
			sawStop = true
		case "error":
			errEvents++
			require.Contains(t, fr.Data, "accounting_commit_failed",
				"%s: stream error event does not carry the accounting_commit_failed code (data %s)", phase, clip(fr.Data))
		}
	}
	require.True(t, sawContent, "%s: stream delivered no content before the accounting failure (body %s)", phase, clip(body))
	require.Equal(t, 1, errEvents, "%s: error event count", phase)
	require.False(t, sawStop, "%s: message_stop was delivered after the failed terminal commit — an untruthful second terminal (body %s)", phase, clip(body))
}

// requireNativeSettled asserts the full durable settlement of one healthy
// native request: the consumer's wallet usage settled, one request_logs
// row, the admission/facts/log evidence chain with the fixture token
// usage, the billed row, the exactly-once UUID-keyed wallet charge with
// its intent, and exactly one provider round trip through the expected
// native dispatch path.
func (s *stand) requireNativeSettled(t *testing.T, family, phase, rid, path string) {
	t.Helper()
	org := s.oracleDB.orgID
	requireEventually(t, 60*time.Second, 500*time.Millisecond, func() bool {
		return s.oracleCreditTotals(t, rid, org).UsageRows == 1
	}, "%s %s: wallet usage never settled", family, phase)
	require.Equal(t, 1, s.oracleRequestLogCount(t, rid, org), "%s %s: request_logs rows", family, phase)
	s.requireDurableControlEvidence(t, family, phase, rid, fixtureCompletionTokens)
	s.requireBilledRow(t, rid, org, phase)
	s.requireWalletChargedExactlyOnce(t, rid, org, phase)
	s.requireWalletIntentPresent(t, rid, org, phase)
	require.NotEmpty(t, s.requireUUIDKeyedCharge(t, rid, org, phase), "%s %s: uuid-keyed charge", family, phase)
	a, d, r := s.fixture.Counts(rid)
	require.EqualValues(t, 1, a, "%s %s: fixture arrivals", family, phase)
	require.EqualValues(t, 1, d, "%s %s: fixture dispatches", family, phase)
	require.EqualValues(t, 1, r, "%s %s: fixture receipts", family, phase)
	paths := s.fixture.ArrivalPaths(rid)
	require.Len(t, paths, 1, "%s %s: arrival paths %v", family, phase, paths)
	require.Equal(t, path, paths[0], "%s %s: request was not served by the native dispatch path", family, phase)
}

// armPermanentTerminalWriteFailure installs a deterministic terminal-facts
// write fault for the listed request ids: every INSERT for those rows
// fails with a plain (non-retryable) error, so the accounting commit can
// never succeed while armed. The transient variant (40001 on first
// attempt, armTransientTerminalWrite) proves recovery; this one proves
// the failure answer itself.
func (s *stand) armPermanentTerminalWriteFailure(t *testing.T, rids ...string) {
	t.Helper()
	s.oracleExec(t, "create native terminal fault selector", `CREATE TABLE acc_native_termfail_target (rid text PRIMARY KEY)`)
	for _, rid := range rids {
		s.oracleExec(t, "arm native terminal fault target", `INSERT INTO acc_native_termfail_target VALUES ($1)`, rid)
	}
	s.oracleExec(t, "arm native terminal fault", `
		CREATE FUNCTION acc_native_termfail() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF EXISTS (SELECT 1 FROM acc_native_termfail_target WHERE rid=NEW.client_request_id) THEN
				RAISE EXCEPTION 'injected permanent terminal write failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER acc_native_termfail BEFORE INSERT ON request_terminal_facts
		FOR EACH ROW EXECUTE FUNCTION acc_native_termfail()`)
	t.Cleanup(func() {
		s.oracleExec(t, "remove native terminal fault", `
			DROP TRIGGER acc_native_termfail ON request_terminal_facts;
			DROP FUNCTION acc_native_termfail();
			DROP TABLE acc_native_termfail_target`)
	})
}

// TestAccountingNativeAnthropicProtocol proves the accounting contract on
// the native Anthropic Messages protocol for both delivery modes:
//
//   - healthy: the fixture's own document/frames reach the client and the
//     full durable settlement (facts, log, admission, wallet) completes
//     through the /v1/messages dispatch path;
//   - refusal: an accounting write outage refuses the request before
//     dispatch (503, history_unavailable code, Anthropic envelope) with
//     zero provider contact and no durable rows, in both modes;
//   - permanent terminal failure: after a real dispatch whose terminal
//     commit can never succeed, the client gets exactly one truthful
//     terminal (500 + accounting_commit_failed buffered; a single
//     protocol error event instead of message_stop on the stream), with
//     no re-dispatch and no phantom charge.
func TestAccountingNativeAnthropicProtocol(t *testing.T) {
	s := startStand(t)
	org := s.oracleDB.orgID
	s.assertWalletConfigured(t, org, "native anthropic pre-control")
	s.controlRequest(t, "native-anth-pre")
	model := s.provisionNativeAnthropicModel(t)

	// Healthy buffered native reply.
	ridJSON := s.reqPrefix + "native-msg-json"
	beforeJSON := s.fixture.Snapshot()
	status, body, err := s.nativeMessages(t, model, ridJSON, false, 45*time.Second)
	require.NoError(t, err, "native anthropic buffered: transport")
	require.Equal(t, http.StatusOK, status, "native anthropic buffered: status (body %s)", clip(body))
	validateNativeMessageReply(t, s, body)
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}, s.fixture.Since(beforeJSON),
		"native anthropic buffered: provider contact")
	s.requireNativeSettled(t, "native anthropic buffered", "healthy", ridJSON, "/v1/messages")

	// Healthy native SSE reply.
	ridSSE := s.reqPrefix + "native-msg-sse"
	beforeSSE := s.fixture.Snapshot()
	status, body, err = s.nativeMessages(t, model, ridSSE, true, 45*time.Second)
	require.NoError(t, err, "native anthropic sse: transport")
	require.Equal(t, http.StatusOK, status, "native anthropic sse: status (body %s)", clip(body))
	validateNativeMessageStream(t, s, body)
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}, s.fixture.Since(beforeSSE),
		"native anthropic sse: provider contact")
	s.requireNativeSettled(t, "native anthropic sse", "healthy", ridSSE, "/v1/messages")

	// Refusal while the durable accounting write is impossible.
	beforeOutage := s.fixture.Snapshot()
	s.armAccountingWriteOutage(t)
	ridRefusal := s.reqPrefix + "native-msg-refusal"
	status, body, err = s.nativeMessages(t, model, ridRefusal, false, 45*time.Second)
	require.NoError(t, err, "native anthropic buffered refusal: transport")
	requireNativeMessagesRefusal(t, status, body, "native anthropic buffered refusal")
	ridRefusalSSE := s.reqPrefix + "native-msg-refusal-sse"
	status, body, err = s.nativeMessages(t, model, ridRefusalSSE, true, 45*time.Second)
	require.NoError(t, err, "native anthropic sse refusal: transport")
	requireNativeMessagesRefusal(t, status, body, "native anthropic sse refusal")
	s.disarmAccountingWriteOutage(t)
	for _, tc := range []struct {
		family string
		rid    string
	}{
		{family: "native anthropic buffered refusal", rid: ridRefusal},
		{family: "native anthropic sse refusal", rid: ridRefusalSSE},
	} {
		s.requireZeroContact(t, tc.family, tc.rid, beforeOutage)
		require.Empty(t, s.oracleAdmissions(t, tc.rid, org), "%s: admission rows", tc.family)
		require.Zero(t, s.oracleRequestLogCount(t, tc.rid, org), "%s: request_logs rows", tc.family)
		require.Zero(t, s.oracleTerminalFactsCount(t, tc.rid, org), "%s: terminal facts", tc.family)
		require.Zero(t, s.oracleCreditTotals(t, tc.rid, org).UsageRows, "%s: wallet usage rows", tc.family)
	}
	s.controlRequest(t, "native-anth-mid")

	// Permanent terminal-facts failure after a real dispatch.
	ridFail := s.reqPrefix + "native-msg-termfail"
	ridFailSSE := s.reqPrefix + "native-msg-termfail-sse"
	s.armPermanentTerminalWriteFailure(t, ridFail, ridFailSSE)
	beforeFail := s.fixture.Snapshot()
	status, body, err = s.nativeMessages(t, model, ridFail, false, 60*time.Second)
	require.NoError(t, err, "native anthropic buffered terminal failure: transport")
	requireNativeMessagesTerminalFailure(t, status, body, "native anthropic buffered terminal failure")
	status, body, err = s.nativeMessages(t, model, ridFailSSE, true, 60*time.Second)
	require.NoError(t, err, "native anthropic sse terminal failure: transport")
	require.Equal(t, http.StatusOK, status, "native anthropic sse terminal failure: stream status (body %s)", clip(body))
	requireNativeMessagesStreamTerminalFailure(t, body, "native anthropic sse terminal failure")
	require.Equal(t, fixtureTotals{arrivals: 2, dispatches: 2, receipts: 2}, s.fixture.Since(beforeFail),
		"native anthropic terminal failure: exactly one dispatch per target, no re-dispatch")
	for _, tc := range []struct {
		family string
		rid    string
	}{
		{family: "native anthropic buffered terminal failure", rid: ridFail},
		{family: "native anthropic sse terminal failure", rid: ridFailSSE},
	} {
		a, d, r := s.fixture.Counts(tc.rid)
		require.EqualValues(t, 1, a, "%s: fixture arrivals", tc.family)
		require.EqualValues(t, 1, d, "%s: fixture dispatches", tc.family)
		require.EqualValues(t, 1, r, "%s: fixture receipts", tc.family)
		require.Len(t, s.oracleAdmissions(t, tc.rid, org), 1, "%s: admission rows", tc.family)
		require.Zero(t, s.oracleTerminalFactsCount(t, tc.rid, org), "%s: the failed terminal write must leave no facts row", tc.family)
		require.Zero(t, s.oracleCreditTotals(t, tc.rid, org).UsageRows, "%s: no charge may settle", tc.family)
	}

	// The consumer must not retro-bill the failed terminals, and the
	// product stays healthy for a control request afterwards.
	s.controlRequest(t, "native-anth-post")
	s.requireGroupDrainedWithin(t, s.redisClient(t), 2*time.Minute)
	for _, tc := range []struct {
		family string
		rid    string
	}{
		{family: "native anthropic buffered terminal failure", rid: ridFail},
		{family: "native anthropic sse terminal failure", rid: ridFailSSE},
	} {
		require.Zero(t, s.oracleTerminalFactsCount(t, tc.rid, org), "%s: late facts row after consumer drain", tc.family)
		require.Zero(t, s.oracleCreditTotals(t, tc.rid, org).UsageRows, "%s: late charge after consumer drain", tc.family)
	}
	require.Equal(t, fixtureTotals{arrivals: 3, dispatches: 3, receipts: 3}, s.fixture.Since(beforeFail),
		"only the two fault targets and the post-control may reach the provider")
	s.fixture.VerifyEvidence()
}

// TestAccountingNativeAnthropicTerminalRetry proves recovery on the
// native protocol: a serialization failure aborting the first
// terminal-facts INSERT after the native dispatch is retried under the
// original invocation without calling the provider again, mirroring
// TestAccountingTransientTerminalWrite for /v1/messages.
func TestAccountingNativeAnthropicTerminalRetry(t *testing.T) {
	s := startStand(t)
	org := s.oracleDB.orgID
	s.assertWalletConfigured(t, org, "native anthropic retry pre-control")
	s.controlRequest(t, "native-anth-retry-pre")
	model := s.provisionNativeAnthropicModel(t)

	rid := s.reqPrefix + "native-msg-retry"
	s.armTransientTerminalWrite(t, rid)
	before := s.fixture.Snapshot()
	status, body, err := s.nativeMessages(t, model, rid, false, 45*time.Second)
	require.NoError(t, err, "native anthropic retry: transport")
	attempts := func() int {
		return s.oracleCount(t, "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM acc_terminal_attempts")
	}
	require.Positive(t, attempts(), "the terminal insert fault never fired")
	delta := s.fixture.Since(before)
	require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1, receipts: 1}, delta,
		"native anthropic retry: provider contact for the target")
	if status == http.StatusOK {
		validateNativeMessageReply(t, s, body)
		require.Equal(t, 1, s.oracleTerminalFactsCount(t, rid, org),
			"native anthropic retry: success returned without durable terminal usage")
	} else {
		require.GreaterOrEqual(t, status, http.StatusInternalServerError, "native anthropic retry: unexpected status %d", status)
		var envelope anthropicErrorDoc
		require.NoError(t, json.Unmarshal([]byte(body), &envelope), "native anthropic retry: failure body (body %s)", clip(body))
		require.NotEmpty(t, envelope.Error.Message, "native anthropic retry: failure message")
	}
	requireEventually(t, 2*time.Minute, 200*time.Millisecond, func() bool {
		return attempts() >= 2 && s.oracleCreditTotals(t, rid, org).UsageRows > 0
	}, "native anthropic retry: terminal usage must survive the failed insert and settle")
	s.requireNativeSettled(t, "native anthropic retry", "recovered", rid, "/v1/messages")
	require.Equal(t, delta, s.fixture.Since(before), "provider contacted again while recovering the native terminal write")
	s.controlRequest(t, "native-anth-retry-post")
	s.requireGroupDrainedWithin(t, s.redisClient(t), 2*time.Minute)
	require.Equal(t, fixtureTotals{arrivals: 2, dispatches: 2, receipts: 2}, s.fixture.Since(before),
		"only the target and the post-control may reach the provider")
	s.fixture.VerifyEvidence()
}
