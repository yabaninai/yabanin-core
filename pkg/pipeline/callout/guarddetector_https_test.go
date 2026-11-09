package callout

// N02-P08 https posture (n02p4 N2 decision): https is the
// production requirement for a remote guard detector endpoint. The operator
// allow-list and the dial-time reserved-IP guard remain the hard controls, so
// a cleartext non-loopback endpoint still constructs — but it announces
// itself loudly, and the loopback/test-rig convention stays silent.

import (
	"bytes"
	"log/slog"
	"testing"
)

// TestGuardDetectorHTTPSPosture pins the announced posture: non-loopback
// cleartext warns, loopback cleartext (the test-rig convention) and https do
// not. Rejection of non-http/https schemes and unapproved hosts is covered by
// TestGuardDetector_ConstructionValidation.
func TestGuardDetectorHTTPSPosture(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	deps := Deps{AllowHosts: []string{"detector.test", "127.0.0.1", "localhost"}}
	rt, err := New(deps)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}

	for name, tc := range map[string]struct {
		endpoint string
		wantWarn bool
	}{
		"non-loopback cleartext warns": {endpoint: "http://detector.test/v1/detect", wantWarn: true},
		"loopback cleartext silent":    {endpoint: "http://127.0.0.1:9/v1/detect", wantWarn: false},
		"localhost cleartext silent":   {endpoint: "http://localhost:9/v1/detect", wantWarn: false},
		"https silent":                 {endpoint: "https://detector.test/v1/detect", wantWarn: false},
	} {
		t.Run(name, func(t *testing.T) {
			logs.Reset()
			if _, err := rt.NewGuardDetector(GuardDetectorConfig{Identity: guardIdentity, Endpoint: tc.endpoint}); err != nil {
				t.Fatalf("construct %s: %v", tc.endpoint, err)
			}
			warned := bytes.Contains(logs.Bytes(), []byte("cleartext http endpoint"))
			if warned != tc.wantWarn {
				t.Fatalf("warn = %v, want %v (log: %q)", warned, tc.wantWarn, logs.String())
			}
		})
	}
}
