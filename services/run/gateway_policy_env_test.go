package run

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	cli "github.com/reireirei/yabanin/pkg/gateway"
)

func TestPolicyColdFailureWiring(t *testing.T) {
	t.Setenv("YABANIN_POLICY_MODE", "enforce")
	t.Setenv("YABANIN_POLICY_CALLOUT_ALLOW_HOSTS", "")
	for _, tc := range []struct {
		name     string
		value    string
		wantMode cli.PolicyColdFailureMode
		warn     bool
	}{
		{name: "unset defaults closed", value: "", wantMode: cli.PolicyColdFailureFailClosed},
		{name: "empty defaults closed", value: "   ", wantMode: cli.PolicyColdFailureFailClosed},
		{name: "explicit closed", value: "fail-closed", wantMode: cli.PolicyColdFailureFailClosed},
		{name: "normalized open", value: "  FAIL-OPEN ", wantMode: cli.PolicyColdFailureFailOpen},
		{name: "unknown defaults closed without echo", value: "sensitive-unknown-sentinel", wantMode: cli.PolicyColdFailureFailClosed, warn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YABANIN_POLICY_COLD_FAILURE_MODE", tc.value)
			var output bytes.Buffer
			wiring, err := policyWiringFromEnv(slog.New(slog.NewTextHandler(&output, nil)))
			if err != nil {
				t.Fatalf("policyWiringFromEnv: %v", err)
			}
			if wiring.Mode != cli.PolicyModeEnforce {
				t.Fatalf("global mode = %q, want enforce", wiring.Mode)
			}
			if wiring.ColdFailureMode != tc.wantMode {
				t.Fatalf("cold mode = %q, want %q", wiring.ColdFailureMode, tc.wantMode)
			}
			logged := output.String()
			if tc.warn && !strings.Contains(logged, "defaulting to fail-closed") {
				t.Fatalf("unknown value warning missing: %q", logged)
			}
			if !tc.warn && logged != "" {
				t.Fatalf("valid value emitted unexpected warning: %q", logged)
			}
			if strings.Contains(logged, tc.value) && tc.value != "" {
				t.Fatalf("operator input was echoed in warning: %q", logged)
			}
		})
	}
}
