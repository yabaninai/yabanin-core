// Package lineage implements jurisdictional lineage attestation: per-request
// cryptographically provable claims about WHERE inference ran, WHICH model
// family served it, and WHICH jurisdiction hosts the logs.
package lineage

import (
	"context"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/provider"
)

// RegionResolver maps an upstream request/response to an ISO-3166-1 alpha-2
// inference country. Strategy, in priority order:
//  1. upstream response header "x-yabanin-region" (provider opt-in, trusted)
//  2. response "cf-ray" suffix (Cloudflare colo → IATA → country)
//  3. response "x-served-by" region suffix
//  4. provider Jurisdiction.DefaultInferenceRegion (fallback, never empty)
type RegionResolver struct {
	reg *provider.JurisdictionRegistry
}

// Evidence grades how inference_region was resolved. The attestation carries
// the tier so a reviewer knows how strong the claim is.
type Evidence string

const (
	// EvidenceProviderAttested is the provider opt-in header
	// (x-yabanin-region, trusted).
	EvidenceProviderAttested Evidence = "provider_attested"
	// EvidenceEndpointPinned means the destination endpoint itself encodes
	// the region (self-hosted, or a model registered with an explicit
	// non-GLOBAL region).
	EvidenceEndpointPinned Evidence = "endpoint_pinned"
	// EvidenceHeaderObserved means the serving location was inferred from
	// response headers.
	EvidenceHeaderObserved Evidence = "header_observed"
	// EvidenceProviderDeclared is the vendor default — the provider does not
	// disclose serving regions.
	EvidenceProviderDeclared Evidence = "provider_declared"
)

// NewRegionResolver builds a resolver backed by the given jurisdiction registry.
func NewRegionResolver(reg *provider.JurisdictionRegistry) *RegionResolver {
	return &RegionResolver{reg: reg}
}

// ResolveInferenceRegion inspects the upstream response to determine the
// inference country. providerName is the adapter key ("openai","anthropic"..).
// Never returns "" — falls back to the provider default then "US".
//
// Deprecated: prefer ResolveInferenceRegionWithEvidence, which also reports
// the evidence tier. Kept for compatibility with existing tests.
func (rr *RegionResolver) ResolveInferenceRegion(ctx context.Context, providerName, upstreamURL string, resp *http.Response) string {
	region, _ := rr.ResolveInferenceRegionWithEvidence(ctx, providerName, upstreamURL, "", resp)
	return region
}

// ResolveInferenceRegionWithEvidence returns the region plus the evidence
// tier that produced it. Priority: provider opt-in header > pinned endpoint
// (the explicit destination config beats post-hoc headers; a header
// disagreeing with a pinned endpoint is an anomaly worth alerting on, not a
// resolution) > cf-ray / x-served-by > provider default. Never returns "".
func (rr *RegionResolver) ResolveInferenceRegionWithEvidence(ctx context.Context, providerName, upstreamURL, pinnedRegion string, resp *http.Response) (string, Evidence) {
	if resp != nil {
		if v := strings.TrimSpace(resp.Header.Get("x-yabanin-region")); v != "" {
			return strings.ToUpper(v), EvidenceProviderAttested
		}
	}
	if pinnedRegion = strings.TrimSpace(pinnedRegion); pinnedRegion != "" && !strings.EqualFold(pinnedRegion, "GLOBAL") {
		return strings.ToUpper(pinnedRegion), EvidenceEndpointPinned
	}
	if resp != nil {
		if cf := resp.Header.Get("cf-ray"); cf != "" {
			if c := cfRayToCountry(cf); c != "" {
				return c, EvidenceHeaderObserved
			}
		}
		if sb := resp.Header.Get("x-served-by"); sb != "" {
			if c := servedByToCountry(sb); c != "" {
				return c, EvidenceHeaderObserved
			}
		}
	}
	def := "US"
	if rr != nil && rr.reg != nil {
		j := rr.reg.Get(ctx, providerName)
		if j.DefaultInferenceRegion != "" {
			def = j.DefaultInferenceRegion
		}
	}
	return def, EvidenceProviderDeclared
}

// cfRayToCountry maps a Cloudflare cf-ray ("83a1abc-SIN") colo suffix → country.
// Only colos relevant to sovereign routing are mapped; unknown colos return "".
var cfRayCountry = map[string]string{
	"SIN": "SG", "HKG": "HK", "NRT": "JP", "KIX": "JP",
	"BOM": "IN", "MAA": "IN", "DEL": "IN", "BLR": "IN",
	"DXB": "AE", "FRA": "EU", "AMS": "EU", "LHR": "EU",
	"IAD": "US", "SJC": "US", "ORD": "US",
}

func cfRayToCountry(ray string) string {
	parts := strings.Split(ray, "-")
	if len(parts) < 2 {
		return ""
	}
	if c, ok := cfRayCountry[strings.ToUpper(parts[len(parts)-1])]; ok {
		return c
	}
	return ""
}

// servedByToCountry handles "cache-<i>-<region>" style headers.
func servedByToCountry(s string) string {
	s = strings.ToUpper(s)
	switch {
	case strings.HasSuffix(s, "SIN"), strings.HasSuffix(s, "SG"):
		return "SG"
	case strings.HasSuffix(s, "BOM"), strings.HasSuffix(s, "IN"):
		return "IN"
	case strings.HasSuffix(s, "NRT"), strings.HasSuffix(s, "JP"):
		return "JP"
	case strings.HasSuffix(s, "DXB"), strings.HasSuffix(s, "AE"):
		return "AE"
	case strings.Contains(s, "EU"):
		return "EU"
	default:
		return ""
	}
}
