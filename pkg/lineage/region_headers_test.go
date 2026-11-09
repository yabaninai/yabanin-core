package lineage

import (
	"context"
	"net/http"
	"testing"
)

func respWith(headers map[string]string) *http.Response {
	h := make(http.Header)
	for k, v := range headers {
		h.Set(k, v)
	}
	// http.NoBody: header-only fake, nothing to close — satisfies bodyclose.
	return &http.Response{Header: h, Body: http.NoBody}
}

func TestResolveInferenceRegionWithEvidence_ProviderAttested(t *testing.T) {
	rr := &RegionResolver{}
	//nolint:bodyclose // header-only fake response (http.NoBody), no transport resource to close
	region, ev := rr.ResolveInferenceRegionWithEvidence(
		context.Background(), "openai", "https://api.openai.com", "", respWith(map[string]string{"x-yabanin-region": "JP"}))
	if region != "JP" || ev != EvidenceProviderAttested {
		t.Fatalf("got (%q, %s), want (JP, %s)", region, ev, EvidenceProviderAttested)
	}
}

func TestResolveInferenceRegionWithEvidence_HeaderObserved(t *testing.T) {
	rr := &RegionResolver{}
	// NRT is a real colo in cfRayCountry → JP.
	//nolint:bodyclose // header-only fake response (http.NoBody), no transport resource to close
	region, ev := rr.ResolveInferenceRegionWithEvidence(
		context.Background(), "openai", "https://api.openai.com", "", respWith(map[string]string{"cf-ray": "84a1c-NRT"}))
	if region != "JP" || ev != EvidenceHeaderObserved {
		t.Fatalf("got (%q, %s), want (JP, %s)", region, ev, EvidenceHeaderObserved)
	}
}

func TestResolveInferenceRegionWithEvidence_PinnedBeatsHeaders(t *testing.T) {
	rr := &RegionResolver{}
	// Pinned endpoint + disagreeing header: pinned wins, the header is an
	// anomaly to alert on, not a re-resolution.
	//nolint:bodyclose // header-only fake response (http.NoBody), no transport resource to close
	region, ev := rr.ResolveInferenceRegionWithEvidence(
		context.Background(), "openai", "https://eu.example.com", "EU", respWith(map[string]string{"cf-ray": "84a1c-NRT"}))
	if region != "EU" || ev != EvidenceEndpointPinned {
		t.Fatalf("got (%q, %s), want (EU, %s)", region, ev, EvidenceEndpointPinned)
	}
}

func TestResolveInferenceRegionWithEvidence_ProviderDeclaredFallback(t *testing.T) {
	rr := &RegionResolver{}
	region, ev := rr.ResolveInferenceRegionWithEvidence(
		context.Background(), "openai", "https://api.openai.com", "", nil)
	if region == "" {
		t.Fatal("region must never be empty")
	}
	if ev != EvidenceProviderDeclared {
		t.Fatalf("evidence = %s, want %s", ev, EvidenceProviderDeclared)
	}
}
