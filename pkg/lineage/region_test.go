package lineage

import (
	"context"
	"net/http"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
)

func reg() *provider.JurisdictionRegistry { return provider.NewJurisdictionRegistry(nil, 0) }

func TestResolve_CFTimeSin_SG(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("cf-ray", "83a1abc-SIN")
	if got := rr.ResolveInferenceRegion(context.Background(), "openai", "", resp); got != "SG" {
		t.Errorf("cf-ray SIN → %q, want SG", got)
	}
}

func TestResolve_YabaninHeaderPriority(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("x-yabanin-region", "in") // lowercase must be normalised
	resp.Header.Set("cf-ray", "83a1abc-SIN")  // would resolve to SG
	if got := rr.ResolveInferenceRegion(context.Background(), "openai", "", resp); got != "IN" {
		t.Errorf("x-yabanin-region must win, got %q want IN", got)
	}
}

func TestResolve_NoResponse_DefaultRegion(t *testing.T) {
	rr := NewRegionResolver(reg())
	// provider unknown + nil pool → fail-closed US default
	if got := rr.ResolveInferenceRegion(context.Background(), "openai", "", nil); got != "US" {
		t.Errorf("nil resp default → %q, want US", got)
	}
}

func TestResolve_UnknownCFRay_Default(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("cf-ray", "deadbeef-ZZZ") // unknown colo
	if got := rr.ResolveInferenceRegion(context.Background(), "openai", "", resp); got != "US" {
		t.Errorf("unknown cf-ray → %q, want US fallback", got)
	}
}

func TestResolve_ServedBy_NRT_JP(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("x-served-by", "cache-2-NRT")
	if got := rr.ResolveInferenceRegion(context.Background(), "openai", "", resp); got != "JP" {
		t.Errorf("x-served-by NRT → %q, want JP", got)
	}
}

// --- PB1.7: ResolveInferenceRegionWithEvidence ---

func TestResolveEvidence_PinnedRegion_BeatsHeaders(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("cf-ray", "83a1abc-SIN") // would resolve to SG via header
	region, ev := rr.ResolveInferenceRegionWithEvidence(context.Background(), "openai", "", "jp", resp)
	if region != "JP" || ev != EvidenceEndpointPinned {
		t.Errorf("pinned region must win: got (%q,%s), want (JP,endpoint_pinned)", region, ev)
	}
}

func TestResolveEvidence_GlobalPinnedIgnored(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("cf-ray", "83a1abc-SIN")
	region, ev := rr.ResolveInferenceRegionWithEvidence(context.Background(), "openai", "", "GLOBAL", resp)
	if region != "SG" || ev != EvidenceHeaderObserved {
		t.Errorf("GLOBAL pinned region must fall through to headers: got (%q,%s)", region, ev)
	}
}

func TestResolveEvidence_AttestedHeader_HighestTier(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("x-yabanin-region", "JP")
	resp.Header.Set("cf-ray", "83a1abc-SIN")
	region, ev := rr.ResolveInferenceRegionWithEvidence(context.Background(), "openai", "", "SG", resp)
	if region != "JP" || ev != EvidenceProviderAttested {
		t.Errorf("attested header must win over pinned+cf-ray: got (%q,%s)", region, ev)
	}
}

func TestResolveEvidence_HeaderObserved(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("cf-ray", "83a1abc-NRT")
	region, ev := rr.ResolveInferenceRegionWithEvidence(context.Background(), "openai", "", "", resp)
	if region != "JP" || ev != EvidenceHeaderObserved {
		t.Errorf("cf-ray without pinned region: got (%q,%s), want (JP,header_observed)", region, ev)
	}
}

func TestResolveEvidence_ProviderDeclared_Fallback(t *testing.T) {
	rr := NewRegionResolver(reg())
	region, ev := rr.ResolveInferenceRegionWithEvidence(context.Background(), "openai", "", "", nil)
	if region != "US" || ev != EvidenceProviderDeclared {
		t.Errorf("no signals: got (%q,%s), want (US,provider_declared)", region, ev)
	}
}

// TestResolveEvidence_CompatWrapper asserts the deprecated single-return
// wrapper keeps its historical region behavior (tests above pin the old cases).
func TestResolveEvidence_CompatWrapper(t *testing.T) {
	rr := NewRegionResolver(reg())
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("cf-ray", "83a1abc-SIN")
	if got := rr.ResolveInferenceRegion(context.Background(), "openai", "", resp); got != "SG" {
		t.Errorf("compat wrapper region %q, want SG", got)
	}
}
