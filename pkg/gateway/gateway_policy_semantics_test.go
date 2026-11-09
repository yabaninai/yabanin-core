package cli

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func TestPolicyGuardrailVerdictKeepsPipelineSemanticsTyped(t *testing.T) {
	tests := []struct {
		action pipeline.Action
		want   GuardrailVerdict
	}{
		{pipeline.ActionAllow, GuardrailAllow},
		{pipeline.ActionDeny, GuardrailDeny},
		{pipeline.ActionMask, GuardrailRedact},
		{pipeline.ActionFlag, GuardrailAuditOnly},
		{pipeline.Action("unknown"), GuardrailDeny},
	}
	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			require.Equal(t, tt.want, policyGuardrailVerdict(tt.action))
		})
	}
}
