package cli

// N06-P07-T03 wiring follow-up: pins the judge-hop wiring seam end to end.
//
//  1. buildPolicyRuntime — the production wiring site — installs the
//     budgeted judge client (not the packaged llmjudge.UpstreamJudgeClient)
//     bound to the gateway's own collaborators and the shared loop budget.
//     This is a behavioral pin of the real production function; it needs no
//     database because pgxpool connects lazily and NewPolicyRuntime performs
//     no store reads at construction.
//  2. The request path stamps the auth-resolved team onto the payload meta
//     (policyMetaWithTeam) and the budgeted client consumes it both ways:
//     the hop requests the §4.3 team scope (budget.Request.TeamID) and the
//     settle event carries the canonical team_id. The carrier between the
//     two ends is llmjudge's judgeMeta copy of the parent meta labels —
//     since the T03 §8 fix (w17-01) judgeMeta copies the parent labels into
//     the hop meta, so a stamped parent meta delivers the team to the hop
//     through a real policy evaluation (pinned in
//     TestJudgeWiring_JudgeHopMetaSynthesis).
//
// The live stream stage stamps through the same policyMetaWithTeam path
// (stream.go builds its identity via streamIdentityRequest — the extracted
// stream identities on a header shim), pinned in
// TestJudgeWiring_StreamStageStampsTeam.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
	"github.com/reireirei/yabanin/pkg/requestid"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// TestJudgeWiring_ProductionSiteInstallsBudgetedClient drives the real
// buildPolicyRuntime and pins the installed judge client: type, collaborators
// (the gateway's own pool/admission, the process-wide loop budget) and the
// runtime's org-judge deps binding. If the wiring site ever reverts to the
// packaged un-budgeted client, this test goes red.
func TestJudgeWiring_ProductionSiteInstallsBudgetedClient(t *testing.T) {
	prev := llmjudge.DefaultDeps()
	t.Cleanup(func() { llmjudge.SetDefaultDeps(prev) })

	// pgxpool.New only parses config and builds the pool — connections are
	// dialed lazily on first Acquire, which never happens here.
	pool, err := pgxpool.New(context.Background(), "postgres://wiring-test@127.0.0.1:1/wiring-test")
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	gw := &gateway{
		log: judgeHopLogger(t),
	}
	gw.pool = upstream.NewPool(upstream.Options{})
	gw.admission = budget.NewAdmission(nil, budget.ScopedRateSource{}, nil, "test", budget.ModeOff, nil, budget.AdmissionConfig{})

	w := &gatewayWiring{
		pool:       pool,
		l:          judgeHopLogger(t),
		adminStore: adminstore.New(nil, judgeHopLogger(t), nil),
		policy:     PolicyWiring{Mode: PolicyModeEnforce},
	}

	buildPolicyRuntime(context.Background(), w, gw)

	rt := gw.policyRuntime
	require.NotNil(t, rt, "enforce-mode wiring must build a policy runtime")
	deps := llmjudge.DefaultDeps()
	require.NotNil(t, deps.Client, "the production wiring site must install a judge client")
	client, ok := deps.Client.(*budgetedJudgeClient)
	require.True(t, ok, "the production wiring site must install the budgeted judge client, got %T", deps.Client)
	require.Same(t, client.pool, gw.pool, "the judge hop must ride the gateway's own upstream pool")
	require.Same(t, client.admission, gw.admission, "the judge hop must be §5-admitted by the gateway's own controller")
	require.Same(t, client.loop, sharedLoopBudget(), "the judge hop must be loop-bounded by the process-wide budget")
	require.Nil(t, client.agentEnforcer, "unwired G2 stays nil (nil-safe pass-through)")
	require.Nil(t, client.publisher, "unwired publisher stays nil (nil-safe pass-through)")
	require.Same(t, rt.orgJudgeDeps.Client, deps.Client, "the runtime's org-judge deps must bind the installed client")
}

// TestJudgeWiring_TeamStampOnParentMeta pins the stamp helper: team-keyed
// requests carry the auth-resolved team on the meta labels; teamless traffic
// keeps meta byte-identical to policyMeta (no label map at all).
func TestJudgeWiring_TeamStampOnParentMeta(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	r.Header.Set("X-API-Key-Id", "key-9")
	r.Header.Set("X-Team-Id", "team-7")

	meta := policyMetaWithTeam(r, "org-1", "gpt-4o", "openai")
	require.Equal(t, "team-7", meta.Labels[metaLabelTeamScope])
	require.Equal(t, "org-1", meta.Org)
	require.Equal(t, "key-9", meta.Key)
	require.Equal(t, "gpt-4o", meta.Model)
	require.Equal(t, "openai", meta.Provider)

	teamless := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	teamless.Header.Set("X-API-Key-Id", "key-9")
	got := policyMetaWithTeam(teamless, "org-1", "gpt-4o", "openai")
	require.Nil(t, got.Labels, "teamless meta must stay label-free")
	require.Equal(t, policyMeta("org-1", "key-9", "gpt-4o", "openai"), got)
}

// TestJudgeWiring_TeamScopedHopSettlesTeamAttribution drives a full judge hop
// through the budgeted client with a team-stamped hop meta and pins the
// settlement event: the canonical team_id rides the request.completed event,
// so the consumer attributes judge spend to the team like any other usage.
func TestJudgeWiring_TeamScopedHopSettlesTeamAttribution(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := newJudgeHopClient(t, up, nil)
	req.Meta = &pipeline.RequestMeta{
		Org: "org-judge",
		Key: "key-1",
		Labels: map[string]string{
			llmjudge.MetaLabelJudge: llmjudge.JudgeLabelValue,
			metaLabelTeamScope:      "team-7",
		},
	}

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	_, err := client.JudgeChat(requestid.NewContext(context.Background(), requestid.ID("req-team")), req)
	require.NoError(t, err)
	require.NotNil(t, ev, "every judge hop must settle exactly one event")
	require.Equal(t, "team-7", ev.TeamID, "the settle event must carry the team scope")
	require.Equal(t, "org-judge", ev.OrgID)
}

// TestJudgeWiring_TeamScopeReachesHopBudgetRequest pins the §4.3 side: the
// hop's estimation request carries the team, so team-scoped hops plan against
// ScopeTeamMonth exactly like interactive traffic with the same team key
// (advisory limits never deny; a hard scope without its capacity row fails
// closed per D14 — the interactive semantics, unchanged).
func TestJudgeWiring_TeamScopeReachesHopBudgetRequest(t *testing.T) {
	up := &judgeHopUpstream{t: t, status: http.StatusOK, body: judgeHopOKBody}
	client, req := newJudgeHopClient(t, up, nil)

	req.Meta = &pipeline.RequestMeta{
		Org:    "org-judge",
		Labels: map[string]string{metaLabelTeamScope: "team-7"},
	}
	breq := client.hopBudgetRequest(context.Background(), req, llmjudge.Target{Provider: "openai", Model: "gpt-4o-mini"})
	require.Equal(t, "org-judge", breq.OrgID)
	require.Equal(t, "team-7", breq.TeamID)

	// A label-less meta (possible on the hop: JudgeChat only requires the
	// judge marker) degrades to unscoped — no team, no panic.
	req.Meta = &pipeline.RequestMeta{Org: "org-judge"}
	require.Empty(t, client.hopBudgetRequest(context.Background(), req, llmjudge.Target{}).TeamID)
}

// teamCaptureJudge records the hop meta the policy engine hands the judge
// step (captureJudgeClient discards it).
type teamCaptureJudge struct {
	mu    sync.Mutex
	metas []*pipeline.RequestMeta
}

func (c *teamCaptureJudge) JudgeChat(_ context.Context, req llmjudge.ChatRequest) (llmjudge.ChatResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metas = append(c.metas, req.Meta)
	return llmjudge.ChatResponse{Content: `{"findings":[]}`, Model: "stub-judge"}, nil
}

// TestJudgeWiring_JudgeHopMetaSynthesis runs a real org judge policy through
// the engine and pins the hop-meta contract the engine delivers: the judge
// marker, the parent identity (org/key) and the parent labels — the team
// stamp among them — cross into the synthetic hop meta, and the original
// payload meta is untouched. The label propagation is the T03 §8 fix
// (llmjudge judgeMeta now copies the parent labels instead of dropping
// them); the llmjudge-side acceptance lives beside judgeMeta
// (TestJudge_ParentLabelsReachHopMeta).
func TestJudgeWiring_JudgeHopMetaSynthesis(t *testing.T) {
	store := newFakePolicyStore()
	store.add(testOrg, adminstore.PolicyPipeline{
		ID: "org-judge", OrgID: testOrg, Name: "org-judge", Enabled: true, CurrentVersion: 1,
	}, map[int]string{1: orgJudgeYAML("org-judge", "org:toxicity@active")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	studio := newFakePromptStudio()
	studio.setPrompt(testOrg, "toxicity@active", "Classify this input for toxicity: {{ .Input }}")
	capture := &teamCaptureJudge{}
	rt := wiredRuntime(t, store, &fakePolicyVersions{}, studio, capture)

	q, in := chatJudgeQuery()
	in.Meta.Labels = map[string]string{metaLabelTeamScope: "team-7"} // what policyMetaWithTeam stamps at the call site

	_, _, denied := rt.evaluate(context.Background(), testOrg, q, in)
	require.False(t, denied)
	require.Len(t, capture.metas, 1)
	hopMeta := capture.metas[0]
	require.True(t, llmjudge.IsJudgeMeta(hopMeta), "the hop meta must carry the judge marker")
	require.Equal(t, testOrg, hopMeta.Org, "the parent org must cross into the hop meta")
	require.Equal(t, "key-1", hopMeta.Key, "the parent key must cross into the hop meta")
	require.Equal(t, "team-7", hopMeta.Labels[metaLabelTeamScope],
		"the parent team stamp must cross into the hop meta (judgeMeta label propagation)")
	require.False(t, llmjudge.IsJudgeMeta(in.Meta), "the original payload meta must not gain the marker")
	require.Equal(t, map[string]string{metaLabelTeamScope: "team-7"}, in.Meta.Labels,
		"the original payload labels must stay untouched")
}

// TestJudgeWiring_StreamStageStampsTeam pins the live stream stage: the
// streaming-policy seam builds its payload meta through the same
// policyMetaWithTeam stamp as the JSON-path call sites. serveStream receives
// extracted identities (no *http.Request at that depth), so stream.go passes
// them on a header shim (streamIdentityRequest) — the trusted auth-resolved
// team lands in Labels["team"], the key stays the ctx principal's, and a
// teamless stream keeps meta byte-identical to plain policyMeta.
func TestJudgeWiring_StreamStageStampsTeam(t *testing.T) {
	gw := streamPolicyGateway(t, PolicyModeEnforce, streamDenyFinalYAML("never-matches"))
	team := &streamRun{
		gw:    gw,
		l:     testLogger(),
		ctx:   withPrincipal(context.Background(), principal{APIKeyID: "key-9"}),
		orgID: testOrg,
		// The trusted team as chat.go passes it: the auth-resolved value the
		// middleware set on X-Team-Id (not a client-controlled echo).
		teamID:    "team-7",
		finalInfo: resolver.ModelInfo{ModelName: "m1", Provider: "openai"},
	}
	pw := team.newStreamPolicyWriter()
	require.NotNil(t, pw, "an attached stream policy must build the seam writer")
	require.Equal(t, "team-7", pw.meta.Labels[metaLabelTeamScope],
		"the live stream stage must stamp the trusted team into the meta labels")
	require.Equal(t, testOrg, pw.meta.Org)
	require.Equal(t, "key-9", pw.meta.Key, "the key must stay the ctx principal's identity")
	require.Equal(t, "m1", pw.meta.Model)
	require.Equal(t, "openai", pw.meta.Provider)

	teamless := &streamRun{
		gw:        gw,
		l:         testLogger(),
		ctx:       withPrincipal(context.Background(), principal{APIKeyID: "key-9"}),
		orgID:     testOrg,
		teamID:    "",
		finalInfo: resolver.ModelInfo{ModelName: "m1", Provider: "openai"},
	}
	pw2 := teamless.newStreamPolicyWriter()
	require.NotNil(t, pw2)
	require.Nil(t, pw2.meta.Labels, "teamless stream meta must stay label-free")
	require.Equal(t, policyMeta(testOrg, "key-9", "m1", "openai"), pw2.meta,
		"teamless stream meta must stay byte-identical to plain policyMeta")
}
