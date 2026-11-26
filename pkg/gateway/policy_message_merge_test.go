package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyPreUpstreamMessageRedaction(t *testing.T) {
	const body = `{"model":"m", "vendor":9007199254740993,"messages":[{"role":"assistant","content":null,"tool_calls":[]},{"role":"tool","tool_call_id":"abc","content":"badge-123"}]}`
	for _, mode := range []string{"enforce", "shadow"} {
		t.Run(mode, func(t *testing.T) {
			yaml := "apiVersion: ypp/v1\nkind: Policy\nname: mask\nmode: " + mode + "\nhooks: [pre_upstream]\nsteps:\n" + r011RedactStep("badge", "badge-[0-9]+")
			_, rt := r011Runtime(t, &fakePolicyVersions{}, yaml)
			w, req := policyRequest(body)
			req.Header.Set("X-Org-Id", "org-a")
			got, event, ok := testHookGateway(rt).policyPreUpstream(w, req, "chat", "m", "openai", []byte(body))
			require.True(t, ok)
			require.NotEmpty(t, parseDecisions(t, event))
			if mode == "shadow" {
				require.Equal(t, body, string(got))
				return
			}
			require.JSONEq(t, strings.Replace(body, "badge-123", "[REDACTED:badge:1]", 1), string(got))
			require.Contains(t, string(got), `9007199254740993`) // no float64 round trip
		})
	}
}

func TestPolicyMessageMergeRejectsConflictingBody(t *testing.T) {
	const original = `{"messages":[{"role":"user","content":"fixture"}]}`
	before := pipelineMessages([]byte(original))
	after := pipelineMessages([]byte(original))
	after[0].Content = "masked"
	for _, body := range []string{
		`{"messages":[]}`,
		strings.Replace(original, `"fixture"`, `[{"type":"text","text":"fixture"}]`, 1),
		strings.Replace(original, `"user"`, `"tool"`, 1),
		strings.Replace(original, `"messages":`, `"Messages":[],"messages":`, 1),
		strings.Replace(original, `"content":`, `"Content":"fixture","content":`, 1),
	} {
		got, err := mergePolicyMessageContent([]byte(body), before, after)
		require.Error(t, err)
		require.Nil(t, got)
	}
}
