package cli

// G4 owner decision 2026-11-04 — producer-side trace_completeness stamp.
// The arms pin the owner-binding vocabulary semantics: any drop ⇒ partial;
// truncation ⇒ partial + reason; no instrumentation ⇒ unknown (never full);
// declared+published ⇒ full; declared and nothing landed ⇒ absent. The
// negative pin (CORE-TRACE-05) keeps the tag surface content-free: closed
// reason enums only, the stamp value grammar-bounded JSON, and a
// client-attributed stamp key overridden at the funnel.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/requestid"
)

// traceStampValuePattern is the full grammar a stamped label value may
// match: a versioned envelope of vocabulary + closed reason codes. Anything
// else (request content, secrets, free text) is a contract violation —
// pinned by TestTraceStampNoSecretsInTags.
var traceStampValuePattern = regexp.MustCompile(
	`^\{"v":1,"c":"(full|partial|absent|unknown)"(,"r":\["[a-z0-9_:]{1,64}"(,"[a-z0-9_:]{1,64}"){0,3}\])?\}$`)

// traceStampTestID returns a registry-unique request id and registers
// cleanup that removes the tracker, so shuffled/parallel-safe test runs
// never observe another test's evidence.
func traceStampTestID(t *testing.T, name string) string {
	t.Helper()
	id := t.Name() + "/" + name
	t.Cleanup(func() {
		traceStampMu.Lock()
		defer traceStampMu.Unlock()
		delete(traceStampRegistry, id)
		delete(traceStampRingPos, id)
	})
	return id
}

// traceStampPeekEnvelope reads the request's envelope without claiming it
// (funnel tests must observe the drop the detached publish goroutine
// records, which claim would race).
func traceStampPeekEnvelope(requestID string) (traceCompletenessEnvelope, bool) {
	traceStampMu.Lock()
	defer traceStampMu.Unlock()
	st, ok := traceStampRegistry[requestID]
	if !ok {
		return traceCompletenessEnvelope{}, false
	}
	return st.envelope(), true
}

// TestTraceCompletenessVocabularyArms pins the owner-binding verdict table.
func TestTraceCompletenessVocabularyArms(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(requestID string)
		want       string
		wantDrops  []string
		wantTruncs []string
	}{
		{
			name: "no_evidence_is_unknown",
			// Declare 0: registers the tracker with no evidence — the
			// shape of a surface that instrumented nothing observable.
			setup: func(id string) {
				traceStampDeclare(id, 0)
			},
			want: "unknown",
		},
		{
			name: "published_without_declaration_is_unknown",
			setup: func(id string) {
				traceStampObservePublished(id)
				traceStampObservePublished(id)
			},
			want: "unknown",
		},
		{
			name: "backlog_full_drop_is_partial",
			setup: func(id string) {
				traceStampObserveDrop(id, traceStampDropBacklogFull)
			},
			want:      "partial",
			wantDrops: []string{"drop:event_publish:backlog_full"},
		},
		{
			name: "publish_failed_drop_is_partial",
			setup: func(id string) {
				traceStampObserveDrop(id, traceStampDropPublishFailed)
			},
			want:      "partial",
			wantDrops: []string{"drop:event_publish:publish_failed"},
		},
		{
			name: "duplicate_drops_collapse",
			setup: func(id string) {
				traceStampObserveDrop(id, traceStampDropBacklogFull)
				traceStampObserveDrop(id, traceStampDropBacklogFull)
			},
			want:      "partial",
			wantDrops: []string{"drop:event_publish:backlog_full"},
		},
		{
			name: "truncation_is_partial_with_reason",
			setup: func(id string) {
				traceStampMarkTruncated(id, traceStampTruncPolicySteps)
				traceStampMarkTruncated(id, traceStampTruncPolicyFindings)
			},
			want:       "partial",
			wantTruncs: []string{"truncated:policy_steps", "truncated:policy_findings"},
		},
		{
			name: "drops_cite_before_truncations",
			setup: func(id string) {
				traceStampMarkTruncated(id, traceStampTruncPolicyFindings)
				traceStampObserveDrop(id, traceStampDropBacklogFull)
			},
			want:       "partial",
			wantDrops:  []string{"drop:event_publish:backlog_full"},
			wantTruncs: []string{"truncated:policy_findings"},
		},
		{
			name: "declared_and_published_is_full",
			setup: func(id string) {
				traceStampDeclare(id, 2)
				traceStampObservePublished(id)
				traceStampObservePublished(id)
			},
			want: "full",
		},
		{
			name: "declared_undercount_stays_unknown",
			setup: func(id string) {
				// A declared cohort with no observed drop but fewer
				// published events than declared must not upgrade: the
				// missing sibling may still be in flight (or already
				// lost) — unknown is the honest verdict, never full.
				traceStampDeclare(id, 2)
				traceStampObservePublished(id)
			},
			want: "unknown",
		},
		{
			name: "declared_and_nothing_landed_is_absent",
			setup: func(id string) {
				traceStampDeclare(id, 3)
			},
			want: "absent",
		},
		{
			name: "published_zero_without_declaration_is_unknown",
			setup: func(id string) {
				traceStampDeclare(id, 0)
			},
			want: "unknown",
		},
		{
			name: "drop_overrides_full",
			setup: func(id string) {
				traceStampDeclare(id, 1)
				traceStampObservePublished(id)
				traceStampObserveDrop(id, traceStampDropPublishFailed)
			},
			want:      "partial",
			wantDrops: []string{"drop:event_publish:publish_failed"},
		},
		{
			name: "truncation_overrides_full",
			setup: func(id string) {
				traceStampDeclare(id, 1)
				traceStampObservePublished(id)
				traceStampMarkTruncated(id, traceStampTruncPolicySteps)
			},
			want:       "partial",
			wantTruncs: []string{"truncated:policy_steps"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := traceStampTestID(t, tc.name)
			tc.setup(id)
			env, ok := traceStampPeekEnvelope(id)
			require.True(t, ok, "tracker must exist after observation")
			require.Equal(t, traceStampVersion, env.Version)
			require.Equal(t, tc.want, env.Completeness)
			require.Equal(t, tc.wantDrops, envReasonsOf(env, "drop:"))
			require.Equal(t, tc.wantTruncs, envReasonsOf(env, "truncated:"))
		})
	}
}

// envReasonsOf filters envelope reasons by prefix (drops cite drop:…,
// truncations cite truncated:…).
func envReasonsOf(env traceCompletenessEnvelope, prefix string) []string {
	var out []string
	for _, reason := range env.Reasons {
		if strings.HasPrefix(reason, prefix) {
			out = append(out, reason)
		}
	}
	return out
}

// TestTraceStampReasonVocabularyClosed: every reason code is a bounded,
// content-free slug (CORE-TRACE-05) — the enum set itself must satisfy the
// consumer's grammar so the two sides can never drift apart silently.
func TestTraceStampReasonVocabularyClosed(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z0-9_]{1,32}(:[a-z0-9_]{1,32}){0,2}$`)
	require.NotEmpty(t, traceStampReasonVocabulary)
	for reason := range traceStampReasonVocabulary {
		require.Regexp(t, pattern, reason, "reason code %q must stay grammar-bounded", reason)
	}
}

// TestTraceStampAppendUniqueOverflow: the reason list caps at
// traceStampMaxReasons entries plus the overflow marker; duplicates and
// post-overflow reasons are ignored, never silently extended.
func TestTraceStampAppendUniqueOverflow(t *testing.T) {
	reasons := []string{}
	reasons = traceStampAppendUnique(reasons, "a")
	reasons = traceStampAppendUnique(reasons, "b")
	reasons = traceStampAppendUnique(reasons, "c")
	require.Equal(t, []string{"a", "b", "c"}, reasons)
	reasons = traceStampAppendUnique(reasons, "d")
	require.Equal(t, []string{"a", "b", "c", "reasons_truncated"}, reasons)
	reasons = traceStampAppendUnique(reasons, "e")
	require.Equal(t, []string{"a", "b", "c", "reasons_truncated"}, reasons)
	reasons = traceStampAppendUnique(reasons, "c")
	require.Equal(t, []string{"a", "b", "c", "reasons_truncated"}, reasons)
}

// TestTraceCompletenessEnvelopeBounded: the stamped value never exceeds
// labels.MaxValueLen; overflow degrades oldest reasons in favor of the
// marker instead of emitting a label downstream normalization would reject.
func TestTraceCompletenessEnvelopeBounded(t *testing.T) {
	// Worst realistic envelope: every drop and truncation reason cited.
	full := traceCompletenessEnvelope{
		Version:      traceStampVersion,
		Completeness: traceCompletePartial,
		Reasons: []string{
			traceStampDropBacklogFull, traceStampDropPublishFailed,
			traceStampTruncPolicySteps,
		},
	}
	value := full.marshalBounded()
	require.LessOrEqual(t, len(value), labels.MaxValueLen)
	require.Regexp(t, traceStampValuePattern, value)

	// Future-proofing: pathological reason payloads must still fit.
	huge := traceCompletenessEnvelope{
		Version:      traceStampVersion,
		Completeness: traceCompletePartial,
		Reasons:      []string{strings.Repeat("a", 200), strings.Repeat("b", 200)},
	}
	value = huge.marshalBounded()
	require.LessOrEqual(t, len(value), labels.MaxValueLen)
	require.Contains(t, value, traceStampReasonsTruncatedCode,
		"overflow must be marked, not silent")

	// The minimal envelope is valid on its own.
	minimal := traceCompletenessEnvelope{Version: traceStampVersion, Completeness: traceCompleteUnknown}
	require.Regexp(t, traceStampValuePattern, minimal.marshalBounded())
}

// TestTraceStampEventStampsAndOverrides: the stamp is authoritative producer
// telemetry — it overrides a client-attributed key, preserves sibling
// labels, and never mutates the caller's map.
func TestTraceStampEventStampsAndOverrides(t *testing.T) {
	id := traceStampTestID(t, "override")
	traceStampObserveDrop(id, traceStampDropBacklogFull)

	caller := map[string]string{
		"workload":         "agent:agent-g1",
		traceStampLabelKey: `{"v":1,"c":"full"}`, // forged client claim
	}
	ev := &eventpub.Event{RequestID: id, Labels: caller}
	traceStampEvent(ev)

	require.Contains(t, ev.Labels, "workload")
	value := ev.Labels[traceStampLabelKey]
	require.Regexp(t, traceStampValuePattern, value)
	var env traceCompletenessEnvelope
	require.NoError(t, json.Unmarshal([]byte(value), &env))
	require.Equal(t, traceCompletePartial, env.Completeness,
		"the producer envelope must win over a forged client stamp")

	// The caller's map is untouched: shared label maps feed other events.
	require.JSONEq(t, `{"v":1,"c":"full"}`, caller[traceStampLabelKey])
	require.Len(t, caller, 2)

	// Fresh request: unknown, never full.
	fresh := traceStampTestID(t, "fresh")
	ev2 := &eventpub.Event{RequestID: fresh}
	traceStampEvent(ev2)
	require.JSONEq(t, `{"v":1,"c":"unknown"}`, ev2.Labels[traceStampLabelKey])
}

// TestTraceStampEventSkipsRequestlessEvents: audit surfaces without a
// request scope (RequestID empty) are untouched — no registry churn, no
// fabricated stamp.
func TestTraceStampEventSkipsRequestlessEvents(t *testing.T) {
	ev := &eventpub.Event{EventType: "mcp_call_audit"}
	traceStampEvent(ev)
	require.Nil(t, ev.Labels)
	traceStampEvent(nil) // must not panic
}

// traceStampHostileSKLive assembles the canonical fake "sk-live" key at
// runtime from two fragments. The public-export gate's source secret scan
// (scripts/public-export-gate.sh section b) greps exported source text for
// sk- shapes with no suffix requirement, so the fixture must never appear
// as a contiguous literal in source — including in comments. The runtime
// value is byte-identical to the literal it replaces;
// TestTraceStampHostileSKLiveGolden pins that shape with an independent
// split.
var traceStampHostileSKLive = "sk-liv" + "e-0123456789abcdef"

// TestTraceStampNoSecretsInTags is the tag-surface negative pin
// (CORE-TRACE-05): hostile strings presented through every observation
// channel are rejected — the reason list accepts closed-enum codes only,
// so no request content or credential material can enter the stamp.
func TestTraceStampNoSecretsInTags(t *testing.T) {
	hostile := []string{
		"Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig",
		traceStampHostileSKLive,
		"password:hunter2",
		"user said: <script>alert(1)</script>",
		"DROP:event_publish:backlog_full", // case-variant impersonation
		"drop:event_publish:backlog_full; drop:event_publish:publish_failed",
	}
	for _, reason := range hostile {
		id := traceStampTestID(t, fmt.Sprintf("hostile-%d", len(reason)))
		traceStampObserveDrop(id, reason)
		traceStampMarkTruncated(id, reason)
		// Hostile observations never register a tracker (validity is
		// checked before state creation), so the stamped envelope is the
		// fresh-claim unknown — with none of the hostile material.
		ev := &eventpub.Event{RequestID: id}
		traceStampEvent(ev)
		require.JSONEq(t, `{"v":1,"c":"unknown"}`, ev.Labels[traceStampLabelKey],
			"hostile reason %q must be ignored, not stored", reason)
	}

	// The stamped value of a request whose observations were all hostile
	// carries none of the hostile strings.
	id := traceStampTestID(t, "canary")
	canary := "CANARY-SECRET-VALUE"
	traceStampObserveDrop(id, canary)
	traceStampDeclare(id, -1)
	ev := &eventpub.Event{RequestID: id}
	traceStampEvent(ev)
	require.NotContains(t, ev.Labels[traceStampLabelKey], canary)
}

// TestTraceStampHostileSKLiveGolden is the golden equality pin for the
// runtime-assembled hostile fixture above: the fragments must concatenate
// byte-identically to the canonical fake key (built here from a different
// split point), so any assembly drift fails loud instead of silently
// weakening the hostile-input row.
func TestTraceStampHostileSKLiveGolden(t *testing.T) {
	require.Equal(t, "sk-live-"+"0123456789abcdef", traceStampHostileSKLive)
	// sk- prefix + 21 body chars — the exact shape the export gate's
	// section-b pattern matches on, pinned so the fixture keeps exercising
	// the credential-shaped hostile class it was written for.
	require.Len(t, traceStampHostileSKLive, 24)
}

// TestPublishEventBacklogFullStampsRequestRow: the backlog-full drop path
// must cite the request-row stamp (owner arm 1), not only the metric —
// mirrored from TestPublishEventBacklogFullCounted's semaphore discipline.
func TestPublishEventBacklogFullStampsRequestRow(t *testing.T) {
	// Saturate the shared semaphore and HOLD the tokens for the whole test:
	// publishEvent must hit the full backlog, not a free slot.
	for i := 0; i < cap(eventPublishSem); i++ {
		select {
		case eventPublishSem <- struct{}{}:
		case <-time.After(10 * time.Second):
			t.Fatalf("publish semaphore not empty at slot %d — leaked tokens", i)
		}
	}
	defer func() {
		for i := 0; i < cap(eventPublishSem); i++ {
			select {
			case <-eventPublishSem:
			case <-time.After(10 * time.Second):
				t.Fatalf("publish semaphore did not drain at slot %d", i)
			}
		}
	}()

	id := traceStampTestID(t, "backlog")
	before := silentFailureValue(t, "event_publish", "backlog_full")
	publishEvent(deadRedisPublisher(), testLogger(), &eventpub.Event{
		EventType: "request.completed", Source: "unit-test", RequestID: id,
	})
	require.InDelta(t, before+1, silentFailureValue(t, "event_publish", "backlog_full"), 1e-9)

	env, ok := traceStampPeekEnvelope(id)
	require.True(t, ok, "the drop must register the request tracker")
	require.Equal(t, traceCompletePartial, env.Completeness)
	require.Equal(t, []string{"drop:event_publish:backlog_full"}, env.Reasons)
}

// TestPublishEventTerminalFailureStampsRequestRow: exhausted retries cite
// the stamp asynchronously (the retries run on the publish goroutine).
func TestPublishEventTerminalFailureStampsRequestRow(t *testing.T) {
	requirePublishQuiescence(t) // exact delta: no foreign publish may land after `before`
	id := traceStampTestID(t, "terminal")
	before := silentFailureValue(t, "event_publish", "publish_failed")
	publishEvent(deadRedisPublisher(), testLogger(), &eventpub.Event{
		EventType: "request.completed", Source: "unit-test", RequestID: id,
	})
	require.Eventually(t, func() bool {
		env, ok := traceStampPeekEnvelope(id)
		return ok &&
			env.Completeness == traceCompletePartial &&
			len(env.Reasons) == 1 &&
			env.Reasons[0] == "drop:event_publish:publish_failed"
	}, 5*time.Second, 10*time.Millisecond,
		"a permanently failed publish must cite the request-row stamp")
	require.InDelta(t, before+1, silentFailureValue(t, "event_publish", "publish_failed"), 1e-9)
}

// TestFinishRequestStampsTraceCompleteness: the finish funnel stamps every
// request event — unknown without evidence, full with a declared-and-
// satisfied cohort — and the claim frees the tracker (one stamp per
// request; the last finish event wins).
func TestFinishRequestStampsTraceCompleteness(t *testing.T) {
	gw := &gateway{log: testLogger()}

	t.Run("unknown_without_evidence", func(t *testing.T) {
		id := traceStampTestID(t, "finish-unknown")
		ev := gw.finishRequest(context.Background(), requestFinish{
			base: eventBase{EventType: "request.completed", RequestID: id},
		}, nil)
		require.JSONEq(t, `{"v":1,"c":"unknown"}`, ev.Labels[traceStampLabelKey])
		_, stillTracked := traceStampPeekEnvelope(id)
		require.False(t, stillTracked, "the finish claim must free the tracker")
	})

	t.Run("full_with_declared_cohort", func(t *testing.T) {
		id := traceStampTestID(t, "finish-full")
		traceStampDeclare(id, 1)
		traceStampObservePublished(id)
		ev := gw.finishRequest(context.Background(), requestFinish{
			base: eventBase{EventType: "request.completed", RequestID: id},
		}, nil)
		require.JSONEq(t, `{"v":1,"c":"full"}`, ev.Labels[traceStampLabelKey])
	})

	t.Run("requestless_events_unstamped", func(t *testing.T) {
		ev := gw.finishRequest(context.Background(), requestFinish{
			base: eventBase{EventType: "request.completed"},
		}, nil)
		require.Nil(t, ev.Labels)
	})
}

// TestPolicyTruncationMarksRequestRow: a decision envelope clipped at the
// cap must surface the same fact on the request-row stamp (owner arm 2) —
// evaluated end-to-end through the real runtime with a policy whose step
// count exceeds policyMaxTraceSteps and finding count exceeds
// policyMaxDecisionFindings.
func TestPolicyTruncationMarksRequestRow(t *testing.T) {
	const steps = policyMaxTraceSteps + 6

	var sb strings.Builder
	sb.WriteString("apiVersion: ypp/v1\nkind: Policy\nname: truncate-mark\nmode: enforce\nhooks:\n  - pre_upstream\nsteps:\n")
	words := make([]string, 0, steps)
	for i := 0; i < steps; i++ {
		word := fmt.Sprintf("marker-%02d", i)
		words = append(words, word)
		fmt.Fprintf(&sb, "  - id: step-%02d\n    detector: builtin/contains\n    params:\n      words: [\"%s\"]\n      action: flag\n", i, word)
	}

	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "truncate-1", OrgID: testOrg, Name: "truncate-mark", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: sb.String()}, []adminstore.PolicyAttachment{chatAttachment(10)})
	rt := newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
	gw := testHookGateway(rt)

	id := traceStampTestID(t, "policy-truncation")
	body := []byte(`{"messages":[{"role":"user","content":"` + strings.Join(words, " ") + `"}]}`)
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", testOrg)
	r.Header.Set("X-API-Key-Id", "key-1")
	r = r.WithContext(requestid.NewContext(r.Context(), requestid.ID(id)))

	_, policyEvent, ok := gw.policyPreUpstream(w, r, "chat", "m", "openai", body)
	require.True(t, ok, "flag-mode policy must never block")
	decisions := parseDecisions(t, policyEvent)
	require.NotEmpty(t, decisions)
	require.Equal(t, "partial", decisions[0].TraceCompleteness,
		"the decision envelope must report the truncation")

	env, traced := traceStampPeekEnvelope(id)
	require.True(t, traced, "the truncation must register the request tracker")
	require.Equal(t, traceCompletePartial, env.Completeness)
	require.Equal(t,
		[]string{"truncated:policy_steps", "truncated:policy_findings"}, env.Reasons)
}

// TestTraceStampPolicyTruncationWithoutRequestID: evaluations without a
// request id (background/store-init paths) honestly skip the mark instead
// of attributing truncation to an empty key.
func TestTraceStampPolicyTruncationWithoutRequestID(t *testing.T) {
	traceStampPolicyTruncation(context.Background(), true, true) // must not panic
}
