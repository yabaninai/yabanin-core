package router

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// N09-P05-T05 negative-scenario battery (packet kind=negative), router side.
// The packet acceptance «Denied region не используется даже при outage
// основного маршрута» is pinned here at the EXECUTOR composition level —
// the filter-level fail-close is T04's unit tests; this battery proves the
// gateway wiring (filter → FallbackExecutor) never dials an excluded or
// unreadable candidate during a full outage of the permitted chain, and
// that the typed refusal is never hidden through the wrap boundary.

// TestN09P5T05_DefaultPolicyUnknownMetaNeverDialedDuringOutage: under the
// DEFAULT policy posture (CN-off), a full outage of the only permitted
// candidate must exhaust the chain with the excluded (cn_flagged) and the
// unreadable (meta_unknown) candidates never dialed — an outage cannot
// widen what the default posture routes to, and unknown routing metadata
// may not be dialed speculatively.
func TestN09P5T05_DefaultPolicyUnknownMetaNeverDialedDuringOutage(t *testing.T) {
	// Real HTTP endpoint so dials are observable; it answers 500 — the
	// permitted chain is fully down.
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fail.Close()

	// Registry knows m-cn and m-us-full; m-unknown has no metadata entry.
	lookup := TierMetaLookup(metaModels())
	resolved := []resolver.ModelInfo{
		chainInfo("m-us-full", "openai", "US", fail.URL+"/us"),
		chainInfo("m-cn", "sakana", "GLOBAL", fail.URL+"/cn-denied"),
		chainInfo("m-unknown", "shadow", "?", fail.URL+"/unknown-meta"),
	}

	filtered := FilterChainByPolicy(sovereign.DefaultPolicy(), resolved, lookup)
	if len(filtered.Chain) != 1 || filtered.Chain[0].ModelName != "m-us-full" {
		t.Fatalf("filtered chain = %+v, want only m-us-full (DefaultPolicy is restrictive: CN-off)", filtered.Chain)
	}
	wantReasons := map[string]sovereign.ProviderDenialReason{
		"m-cn":      sovereign.DenialProviderCNFlagged,
		"m-unknown": sovereign.DenialProviderMetaUnknown,
	}
	if len(filtered.Excluded) != 2 {
		t.Fatalf("excluded = %+v, want exactly m-cn and m-unknown", filtered.Excluded)
	}
	for _, x := range filtered.Excluded {
		if wantReasons[x.Denial.ModelName] != x.Denial.Reason {
			t.Errorf("%s reason = %q, want %q", x.Denial.ModelName, x.Denial.Reason, wantReasons[x.Denial.ModelName])
		}
	}

	// Wire the filtered chain into the executor the way the gateway would.
	primary := filtered.Chain[0]
	byName := map[string]resolver.ModelInfo{}
	for _, c := range filtered.Chain {
		byName[c.ModelName] = c
	}
	exec := NewFallbackExecutor(&stubResolver{byName: byName}, 0, nil)

	var dials []string
	_, _, attempts, err := exec.Execute(context.Background(), primary,
		func(_ context.Context, info resolver.ModelInfo) (int, error) {
			dials = append(dials, info.UpstreamURL)
			return http.StatusInternalServerError, fmt.Errorf("upstream down")
		})
	if err == nil {
		t.Fatal("expected chain exhaustion error: the only permitted upstream is down")
	}
	for _, u := range dials {
		if strings.Contains(u, "cn-denied") || strings.Contains(u, "unknown-meta") {
			t.Fatalf("excluded/unreadable endpoint %q was dialed during outage (dials=%v)", u, dials)
		}
	}
	if len(dials) != 1 || !strings.Contains(dials[0], "/us") {
		t.Fatalf("dials = %v, want exactly the permitted /us endpoint", dials)
	}
	if len(attempts) != 1 {
		t.Fatalf("attempts = %d, want 1 (trace keeps only real attempts)", len(attempts))
	}
}

// TestN09P5T05_RefusalSurvivesWrapping_TypedFieldsIntact: when the policy
// excludes EVERY candidate, the typed refusal carries one record per
// candidate, survives a %w wrap boundary with its structured fields intact
// (an error flattened to text on the way out is a hidden error), keeps the
// per-candidate explanations and the non-claim disclosure in its message,
// and never phrases the country binding as a guarantee.
func TestN09P5T05_RefusalSurvivesWrapping_TypedFieldsIntact(t *testing.T) {
	pol := restrictiveExclusionPolicy()
	lookup := TierMetaLookup(metaModels())
	filtered := FilterChainByPolicy(pol, []resolver.ModelInfo{
		chainInfo("m-ru", "ru-model", "RU", "https://ru.example"),
		chainInfo("m-cn", "sakana", "GLOBAL", "https://cn.example"),
	}, lookup)

	err := filtered.Err()
	if err == nil {
		t.Fatal("all-candidates-excluded must produce a refusal")
	}

	// Wrap boundary (gateway/error-middleware shape): type and fields must
	// survive errors.As through %w.
	var typed *ErrNoPermittedProvider
	if !errors.As(fmt.Errorf("serving: %w", err), &typed) {
		t.Fatal("ErrNoPermittedProvider not recoverable through %w wrap (error hidden)")
	}
	if len(typed.Excluded) != 2 {
		t.Fatalf("typed refusal lost exclusion records: %+v", typed.Excluded)
	}
	byModel := map[string]ExcludedCandidate{}
	for _, x := range typed.Excluded {
		byModel[x.Denial.ModelName] = x
	}
	wantReasons := map[string]sovereign.ProviderDenialReason{
		"m-ru": sovereign.DenialProviderCountryExcluded,
		"m-cn": sovereign.DenialProviderCNFlagged,
	}
	for model, want := range wantReasons {
		x, ok := byModel[model]
		if !ok {
			t.Fatalf("model %s missing from typed refusal: %+v", model, typed.Excluded)
		}
		if x.Denial.Reason != want || x.Denial.Provider == "" || x.Region == "" {
			t.Errorf("%s record incomplete: reason=%q provider=%q region=%q",
				model, x.Denial.Reason, x.Denial.Provider, x.Region)
		}
	}

	msg := typed.Error()
	for _, want := range []string{
		"m-ru=ru-model/RU/country_excluded",
		"m-cn=sakana/GLOBAL/cn_flagged",
		sovereign.ResidencyDisclosure,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message must contain %q, got %q", want, msg)
		}
	}
	// Non-claim property (mirrors the sovereign battery's process control):
	// every "guarantee" mention must sit inside the disclosure sentence.
	if got, want := strings.Count(msg, "guarantee"), strings.Count(msg, sovereign.ResidencyDisclosure); got != want {
		t.Errorf("refusal has %d guarantee mentions but %d non-claim sentences: %q", got, want, msg)
	}
}
