//go:build integration

package accounting

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// refusalFamily is one client-facing dispatch family: how to issue one
// authenticated request of that family, the upstream protocol path its
// healthy traffic must arrive on (proving WHICH dispatch family served
// it, e.g. native Responses rather than the chat-adapted translation),
// and the independently defined protocol validity check for a healthy
// reply. The fault windows reuse the whole-ledger and storage oracles.
type refusalFamily struct {
	name     string // case-log family name
	request  func(s *stand, rid string) (status int, body string, err error)
	upstream string                                    // fixture arrival path a healthy control must use
	validate func(t *testing.T, s *stand, body string) // protocol contract of the healthy reply
}

// TestAccountingRefusalFamiliesBeforeDispatch extends the independent
// pre-dispatch refusal proof beyond buffered chat: every synchronous
// client-facing dispatch family the stand's provider serves — chat
// (buffered and SSE), embeddings, NATIVE Responses (buffered and SSE;
// the gateway env lists the seeded openai-compat provider as a native
// Responses provider), legacy completions, moderations and rerank —
// must obey the same owner-approved contract when the durable
// request-accounting write path is broken: refuse with the documented
// 503 history_unavailable envelope, contact no provider (whole-ledger
// zero, no first attempt, no retry, no fallback hop), record no
// accounting of any kind, and resume normal service per family with
// healthy route-specific controls before and after each fault window.
//
// Healthy family controls are strong, not formal: HTTP 200, an
// independently validated protocol reply, exactly one whole-ledger
// arrival/dispatch/receipt on the family's OWN upstream path, retained
// evidence, and a durable request_logs row. Wallet-debit economics per
// family are the accounting suite's territory (chat carries the exact
// -32 micro-USD proof); here the shared refusal-relevant fact is the
// durable start, which is family-independent.
//
// Known dispatch-family omissions (identifiable, not silently absent):
//
//   - /v1/realtime: WebSocket family; the stand's client transport is
//     plain HTTP, so refusal-at-upgrade cannot be observed here.
//   - /v1/audio/speech, /v1/audio/transcriptions, /v1/images/generations:
//     binary and multipart upstream bodies; the fixture would need
//     non-JSON codecs before the refusal window could be proven.
//   - /v1/files and /v1/batches: asynchronous job lifecycle (upload then
//     materialize), not one synchronous dispatch whose pre-dispatch
//     refusal this case could assert in a single window.
//   - /v1/messages (+/count_tokens): distinct client protocol, but on
//     this provider it translates to the chat upstream family already
//     covered, so it adds client-surface, not dispatch-family, coverage.
//
// The fault, its verification and its restoration are the original
// refusal case's real-infrastructure trigger set, unchanged. All
// requests below share the stand, one seeded model, one provider and
// one tenant credential set. Real-stand full-suite execution happens
// under the heavy lease; this case keeps the standalone baseline and
// earlier results untouched.
func TestAccountingRefusalFamiliesBeforeDispatch(t *testing.T) {
	s := startStandWithGatewayEnv(t, "YABANIN_RESPONSES_NATIVE_PROVIDERS=openai-compat")

	families := []refusalFamily{
		{
			name: "chat buffered",
			request: func(s *stand, rid string) (int, string, error) {
				return s.chat(t, rid, 45*time.Second)
			},
			upstream: "/v1/chat/completions",
			validate: func(t *testing.T, s *stand, body string) {
				var doc struct {
					Choices []struct {
						Message struct {
							Role    string `json:"role"`
							Content string `json:"content"`
						} `json:"message"`
					} `json:"choices"`
					Usage struct {
						PromptTokens     int `json:"prompt_tokens"`
						CompletionTokens int `json:"completion_tokens"`
					} `json:"usage"`
				}
				if err := json.Unmarshal([]byte(body), &doc); err != nil {
					t.Fatalf("families: chat control body is not chat.completion JSON: %v (body %s)", err, clip(body))
				}
				if len(doc.Choices) != 1 || doc.Choices[0].Message.Content != fixtureAssistantContent || doc.Choices[0].Message.Role != "assistant" {
					t.Fatalf("families: chat control reply malformed (body %s)", clip(body))
				}
				if doc.Usage.PromptTokens != fixturePromptTokens || doc.Usage.CompletionTokens != fixtureCompletionTokens {
					t.Fatalf("families: chat control usage = %d/%d, want %d/%d", doc.Usage.PromptTokens, doc.Usage.CompletionTokens, fixturePromptTokens, fixtureCompletionTokens)
				}
			},
		},
		{
			name: "chat sse",
			request: func(s *stand, rid string) (int, string, error) {
				return s.chatFull(t, rid, 45*time.Second, chatOptions{stream: true})
			},
			upstream: "/v1/chat/completions",
			validate: func(t *testing.T, s *stand, body string) {
				for _, want := range []string{
					`"object":"chat.completion.chunk"`,
					`"content":"` + fixtureAssistantContent + `"`,
					`"finish_reason":"stop"`,
					`"prompt_tokens":` + fmt.Sprint(fixturePromptTokens),
					"data: [DONE]",
				} {
					if !strings.Contains(body, want) {
						t.Fatalf("families: chat sse control missing %q (body %s)", want, clip(body))
					}
				}
			},
		},
		{
			name: "embeddings",
			request: func(s *stand, rid string) (int, string, error) {
				payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance embeddings probe"}`, s.model)
				return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/embeddings", s.apiKey, rid, payload)
			},
			upstream: "/v1/embeddings",
			validate: func(t *testing.T, s *stand, body string) {
				var doc struct {
					Object string `json:"object"`
					Data   []struct {
						Object    string    `json:"object"`
						Embedding []float64 `json:"embedding"`
					} `json:"data"`
					Usage struct {
						PromptTokens int `json:"prompt_tokens"`
					} `json:"usage"`
				}
				if err := json.Unmarshal([]byte(body), &doc); err != nil {
					t.Fatalf("families: embeddings control body is not embeddings JSON: %v (body %s)", err, clip(body))
				}
				if doc.Object != "list" || len(doc.Data) != 2 {
					t.Fatalf("families: embeddings control envelope malformed (body %s)", clip(body))
				}
				for i, d := range doc.Data {
					if d.Object != "embedding" || len(d.Embedding) != fixtureEmbedDims {
						t.Fatalf("families: embeddings control data[%d] malformed (%d dims, want %d)", i, len(d.Embedding), fixtureEmbedDims)
					}
				}
				if doc.Usage.PromptTokens != fixturePromptTokens {
					t.Fatalf("families: embeddings control usage = %d, want %d", doc.Usage.PromptTokens, fixturePromptTokens)
				}
			},
		},
		{
			name: "responses native buffered",
			request: func(s *stand, rid string) (int, string, error) {
				payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance responses probe"}`, s.model)
				return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/responses", s.apiKey, rid, payload)
			},
			upstream: "/v1/responses",
			validate: func(t *testing.T, s *stand, body string) {
				var doc struct {
					Object string `json:"object"`
					Status string `json:"status"`
					Output []struct {
						Type    string `json:"type"`
						Content []struct {
							Type string `json:"type"`
							Text string `json:"text"`
						} `json:"content"`
					} `json:"output"`
					Usage struct {
						InputTokens  int `json:"input_tokens"`
						OutputTokens int `json:"output_tokens"`
					} `json:"usage"`
				}
				if err := json.Unmarshal([]byte(body), &doc); err != nil {
					t.Fatalf("families: responses control body is not a response object: %v (body %s)", err, clip(body))
				}
				if doc.Object != "response" || doc.Status != "completed" || len(doc.Output) != 1 || len(doc.Output[0].Content) != 1 {
					t.Fatalf("families: responses control envelope malformed (body %s)", clip(body))
				}
				if doc.Output[0].Content[0].Type != "output_text" || doc.Output[0].Content[0].Text != fixtureAssistantContent {
					t.Fatalf("families: responses control output text malformed (body %s)", clip(body))
				}
				if doc.Usage.InputTokens != fixturePromptTokens || doc.Usage.OutputTokens != fixtureCompletionTokens {
					t.Fatalf("families: responses control usage = %d/%d, want %d/%d", doc.Usage.InputTokens, doc.Usage.OutputTokens, fixturePromptTokens, fixtureCompletionTokens)
				}
			},
		},
		{
			name: "responses native sse",
			request: func(s *stand, rid string) (int, string, error) {
				payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance responses probe","stream":true}`, s.model)
				return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/responses", s.apiKey, rid, payload)
			},
			upstream: "/v1/responses",
			validate: func(t *testing.T, s *stand, body string) {
				for _, want := range []string{
					"event: response.created",
					"event: response.output_text.delta",
					`"delta":"` + fixtureAssistantContent + `"`,
					"event: response.completed",
					`"input_tokens":` + fmt.Sprint(fixturePromptTokens),
					`"output_tokens":` + fmt.Sprint(fixtureCompletionTokens),
				} {
					if !strings.Contains(body, want) {
						t.Fatalf("families: responses sse control missing %q (body %s)", want, clip(body))
					}
				}
				// The native Responses stream has no [DONE] sentinel: its
				// presence would mean the chat-adapted path answered, not
				// the native family this control claims to prove.
				if strings.Contains(body, "[DONE]") {
					t.Fatalf("families: responses sse control carries a chat-style [DONE] sentinel — the ADAPTED path answered, not native Responses (body %s)", clip(body))
				}
			},
		},
		{
			name: "completions legacy",
			request: func(s *stand, rid string) (int, string, error) {
				payload := fmt.Sprintf(`{"model":%q,"prompt":"accounting acceptance completions probe"}`, s.model)
				return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/completions", s.apiKey, rid, payload)
			},
			upstream: "/v1/completions",
			validate: func(t *testing.T, s *stand, body string) {
				var doc struct {
					Object  string `json:"object"`
					Choices []struct {
						Text string `json:"text"`
					} `json:"choices"`
					Usage struct {
						PromptTokens     int `json:"prompt_tokens"`
						CompletionTokens int `json:"completion_tokens"`
					} `json:"usage"`
				}
				if err := json.Unmarshal([]byte(body), &doc); err != nil {
					t.Fatalf("families: completions control body is not text_completion JSON: %v (body %s)", err, clip(body))
				}
				if doc.Object != "text_completion" || len(doc.Choices) != 1 || doc.Choices[0].Text != fixtureAssistantContent {
					t.Fatalf("families: completions control reply malformed (body %s)", clip(body))
				}
				if doc.Usage.PromptTokens != fixturePromptTokens || doc.Usage.CompletionTokens != fixtureCompletionTokens {
					t.Fatalf("families: completions control usage = %d/%d, want %d/%d", doc.Usage.PromptTokens, doc.Usage.CompletionTokens, fixturePromptTokens, fixtureCompletionTokens)
				}
			},
		},
		{
			name: "moderations",
			request: func(s *stand, rid string) (int, string, error) {
				payload := fmt.Sprintf(`{"model":%q,"input":"accounting acceptance moderations probe"}`, s.model)
				return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/moderations", s.apiKey, rid, payload)
			},
			upstream: "/v1/moderations",
			validate: func(t *testing.T, s *stand, body string) {
				var doc struct {
					Results []struct {
						Flagged bool `json:"flagged"`
					} `json:"results"`
					Usage struct {
						PromptTokens int `json:"prompt_tokens"`
					} `json:"usage"`
				}
				if err := json.Unmarshal([]byte(body), &doc); err != nil {
					t.Fatalf("families: moderations control body is not moderations JSON: %v (body %s)", err, clip(body))
				}
				if len(doc.Results) != 2 {
					t.Fatalf("families: moderations control results = %d, want 2 (body %s)", len(doc.Results), clip(body))
				}
				if doc.Usage.PromptTokens != fixturePromptTokens {
					t.Fatalf("families: moderations control usage = %d, want %d", doc.Usage.PromptTokens, fixturePromptTokens)
				}
			},
		},
		{
			name: "rerank",
			request: func(s *stand, rid string) (int, string, error) {
				payload := fmt.Sprintf(`{"model":%q,"query":"accounting acceptance","documents":["probe one","probe two"]}`, s.model)
				return httpPostJSON(45*time.Second, s.gatewayURL+"/v1/rerank", s.apiKey, rid, payload)
			},
			upstream: "/v1/rerank",
			validate: func(t *testing.T, s *stand, body string) {
				var doc struct {
					Results []struct {
						Index          int     `json:"index"`
						RelevanceScore float64 `json:"relevance_score"`
					} `json:"results"`
					Usage struct {
						PromptTokens int `json:"prompt_tokens"`
					} `json:"usage"`
				}
				if err := json.Unmarshal([]byte(body), &doc); err != nil {
					t.Fatalf("families: rerank control body is not rerank JSON: %v (body %s)", err, clip(body))
				}
				if len(doc.Results) != 2 || doc.Results[0].RelevanceScore <= 0 || doc.Results[0].RelevanceScore > 1 {
					t.Fatalf("families: rerank control results malformed (body %s)", clip(body))
				}
				if doc.Usage.PromptTokens != fixturePromptTokens {
					t.Fatalf("families: rerank control usage = %d, want %d", doc.Usage.PromptTokens, fixturePromptTokens)
				}
			},
		},
	}

	var targetRids []string
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			s.controlFamily(t, fam, "pre")

			s.armAccountingWriteOutage(t)
			defer s.disarmAccountingWriteOutage(t)

			before := s.fixture.Snapshot()
			rid := s.reqPrefix + "tgt-refusal-" + strings.ReplaceAll(strings.ReplaceAll(fam.name, " ", "-"), "/", "-")
			targetRids = append(targetRids, rid)
			status, body, err := fam.request(s, rid)

			switch {
			case err != nil:
				t.Fatalf("product: refusal %s: client transport error %v — the request must be refused with the documented 503 history_unavailable contract, not dropped", fam.name, err)
			case status != 503:
				t.Fatalf("product: refusal %s: client status %d, want 503 (body %s) — the family was denied or served for the wrong reason; the documented history_unavailable refusal is missing", fam.name, status, clip(body))
			}
			code, ok := decodeErrorCode(body)
			if !ok {
				t.Fatalf("product: refusal %s: 503 body is not the documented structured error envelope (body %s)", fam.name, clip(body))
			}
			if code != "history_unavailable" {
				t.Fatalf("product: refusal %s: 503 error.code %q, want history_unavailable (body %s)", fam.name, code, clip(body))
			}

			s.fixture.VerifyEvidence()
			if delta := s.fixture.Since(before); delta.arrivals != 0 || delta.dispatches != 0 || delta.receipts != 0 {
				t.Fatalf("product: refusal %s: whole-ledger provider contact during the outage arrivals/dispatches/receipts = %d/%d/%d, want 0/0/0 — the request must never be dispatched, retried or failed over",
					fam.name, delta.arrivals, delta.dispatches, delta.receipts)
			}
			if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
				t.Fatalf("product: refusal %s: %d request_logs row(s) exist for the refused request", fam.name, n)
			}
			if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows+c.TopupRows != 0 {
				t.Fatalf("product: refusal %s: credit transactions exist for the refused request (%+v)", fam.name, c)
			}
			if n := s.oracleSettlementJobs(t, rid, s.oracleDB.orgID); n != 0 {
				t.Fatalf("product: refusal %s: %d settlement job(s) exist for the refused request", fam.name, n)
			}
			if n := s.oracleAdmissionRowCount(t, rid, s.oracleDB.orgID); n != 0 {
				t.Fatalf("product: refusal %s: %d admission row(s) exist for the refused request", fam.name, n)
			}

			s.disarmAccountingWriteOutage(t)
			s.controlFamily(t, fam, "post")
		})
	}

	// No refused request may retroactively bill on any family.
	for _, rid := range targetRids {
		if n := s.oracleRequestLogCount(t, rid, s.oracleDB.orgID); n != 0 {
			t.Fatalf("product: refusal families: %d request_logs row(s) appeared for refused %s after restoration", n, rid)
		}
		if c := s.oracleCreditTotals(t, rid, s.oracleDB.orgID); c.UsageRows != 0 {
			t.Fatalf("product: refusal families: %d usage transaction(s) appeared for refused %s after restoration", c.UsageRows, rid)
		}
	}
}

// controlFamily proves the family's healthy round trip around a fault
// window: HTTP 200, an independently validated protocol reply, exactly
// one whole-ledger contact on the family's OWN upstream path, retained
// evidence and a durable request_logs row. It is the route-specific
// validity oracle: without it, a family's refusal window could be
// excused as an unusable route rather than the product's refusal.
func (s *stand) controlFamily(t *testing.T, fam refusalFamily, phase string) {
	t.Helper()
	before := s.fixture.Snapshot()
	rid := s.reqPrefix + "ctl-" + phase + "-" + strings.ReplaceAll(strings.ReplaceAll(fam.name, " ", "-"), "/", "-")
	status, body, err := fam.request(s, rid)
	if err != nil || status != httpOK {
		t.Fatalf("harness: %s control %s failed (status=%d err=%v body=%s): the family's route, credentials or fixture protocol is broken; product assertions below would be meaningless",
			fam.name, phase, status, err, clip(body))
	}
	fam.validate(t, s, body)
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
	t.Logf("harness: %s control %s ok (request id %s)", fam.name, phase, rid)
}
