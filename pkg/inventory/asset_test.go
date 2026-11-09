package inventory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var validSeen = func() (time.Time, time.Time) {
	first := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	return first, first.Add(time.Hour)
}

func validAsset() Asset {
	first, last := validSeen()
	return Asset{
		OrgID:      "org-1",
		AssetKey:   "mcp_server:fs",
		Kind:       KindMCPServer,
		Payload:    json.RawMessage(`{"name":"fs","url":"https://mcp.example/fs"}`),
		Source:     SourceMCPRegistry,
		Confidence: ConfidenceHigh,
		FirstSeen:  first,
		LastSeen:   last,
	}
}

func TestAssetValidateAcceptsEveryKind(t *testing.T) {
	first, last := validSeen()
	for _, kind := range AssetKinds {
		a := validAsset()
		a.Kind = kind
		a.AssetKey = string(kind) + ":x"
		a.FirstSeen, a.LastSeen = first, last
		if err := a.Validate(); err != nil {
			t.Fatalf("kind %s: unexpected error: %v", kind, err)
		}
	}
	if len(AssetKinds) != 6 {
		t.Fatalf("AssetKinds: want 6 kinds (agent/service/mcp_server/tool/model/provider), got %d", len(AssetKinds))
	}
}

func TestAssetValidateProvenanceInvariants(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Asset)
		want string
	}{
		{"empty org", func(a *Asset) { a.OrgID = "" }, "org_id is required"},
		{"org whitespace", func(a *Asset) { a.OrgID = "org 1" }, "whitespace"},
		{"org control char", func(a *Asset) { a.OrgID = "org\x001" }, "whitespace"},
		{"org too long", func(a *Asset) { a.OrgID = strings.Repeat("x", 257) }, "length/encoding"},
		{"empty asset key", func(a *Asset) { a.AssetKey = "" }, "asset_key is required"},
		{"unknown kind", func(a *Asset) { a.Kind = AssetKind("vendor") }, "unknown asset kind"},
		{"empty source", func(a *Asset) { a.Source = "" }, "source is required"},
		{"unknown confidence", func(a *Asset) { a.Confidence = "certain" }, "unknown confidence"},
		{"nil payload", func(a *Asset) { a.Payload = nil }, "payload is required"},
		{"invalid json payload", func(a *Asset) { a.Payload = json.RawMessage(`{`) }, "not valid JSON"},
		{"array payload", func(a *Asset) { a.Payload = json.RawMessage(`[1,2]`) }, "JSON object"},
		{"zero first_seen", func(a *Asset) { a.FirstSeen = time.Time{} }, "first_seen is required"},
		{"zero last_seen", func(a *Asset) { a.LastSeen = time.Time{} }, "last_seen is required"},
		{"last before first", func(a *Asset) { a.LastSeen = a.FirstSeen.Add(-time.Second) }, "last_seen"},
	}
	for _, tc := range cases {
		a := validAsset()
		tc.mut(&a)
		err := a.Validate()
		if err == nil {
			t.Fatalf("%s: expected error, got nil", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error %q does not contain %q", tc.name, err.Error(), tc.want)
		}
	}
}

func TestAssetValidateEqualSeenWindowAllowed(t *testing.T) {
	a := validAsset()
	a.LastSeen = a.FirstSeen
	if err := a.Validate(); err != nil {
		t.Fatalf("equal first_seen/last_seen must be allowed (import stamps): %v", err)
	}
}

func TestVocabularies(t *testing.T) {
	for _, k := range []AssetKind{"agent", "service", "mcp_server", "tool", "model", "provider"} {
		if !ValidAssetKind(k) {
			t.Errorf("ValidAssetKind(%q) = false, want true", k)
		}
	}
	for _, k := range []AssetKind{"", "Agent", "mcpserver", "endpoint", "AGENTS.md"} {
		if ValidAssetKind(k) {
			t.Errorf("ValidAssetKind(%q) = true, want false (closed vocabulary)", k)
		}
	}
	for _, c := range []Confidence{ConfidenceHigh, ConfidenceLow} {
		if !ValidConfidence(c) {
			t.Errorf("ValidConfidence(%q) = false, want true", c)
		}
	}
	for _, c := range []Confidence{"", "HIGH", "medium", "certain"} {
		if ValidConfidence(c) {
			t.Errorf("ValidConfidence(%q) = true, want false (closed vocabulary)", c)
		}
	}
	if SourceMCPRegistry != "mcp_registry" {
		t.Fatalf("SourceMCPRegistry = %q, want mcp_registry (source value is contract: DISPATCH W02 source=mcp_registry)", SourceMCPRegistry)
	}
}
