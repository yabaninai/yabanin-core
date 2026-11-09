package regionrouter

import (
	"reflect"
	"testing"

	"github.com/reireirei/yabanin/pkg/sovereign"
)

// TestDataClass_ClosedAndCovering: the class set is closed, every class
// maps to valid sovereign kinds only, and the mapping is TOTAL over the
// sovereign egress kinds — no policy dimension is unreachable from routing.
func TestDataClass_ClosedAndCovering(t *testing.T) {
	seen := map[sovereign.EgressKind]bool{}
	for _, c := range DataClasses {
		if !c.Valid() {
			t.Errorf("class %q listed in DataClasses but not Valid()", c)
		}
		kinds := c.Kinds()
		if len(kinds) == 0 {
			t.Errorf("class %q maps to no kinds", c)
		}
		for _, k := range kinds {
			if !k.Valid() {
				t.Errorf("class %q maps to invalid sovereign kind %q", c, k)
			}
			seen[k] = true
			got, ok := DataClassForKind(k)
			if !ok {
				t.Errorf("sovereign kind %q has no routing class", k)
				continue
			}
			if !containsKind(got.Kinds(), k) {
				t.Errorf("DataClassForKind(%q) = %q, whose kinds lack it", k, got)
			}
		}
	}
	for _, k := range sovereign.EgressKinds {
		if !seen[k] {
			t.Errorf("sovereign kind %q is not reachable from any DataClass", k)
		}
	}
	if got, ok := DataClassForKind("nope"); ok {
		t.Errorf("DataClassForKind(bogus) = %q, want !ok", got)
	}
	if (DataClass("bogus")).Valid() {
		t.Error("unknown class must not be Valid")
	}
	if kinds := (DataClass("bogus")).Kinds(); kinds != nil {
		t.Errorf("unknown class kinds = %v, want nil (deny-all)", kinds)
	}
}

func containsKind(list []sovereign.EgressKind, k sovereign.EgressKind) bool {
	for _, v := range list {
		if v == k {
			return true
		}
	}
	return false
}

// TestDataClass_DetectorsIsCompound: the detectors class must enforce BOTH
// the inference and the logs profiles (payload content + findings plane).
func TestDataClass_DetectorsIsCompound(t *testing.T) {
	kinds := ClassDetectors.Kinds()
	want := []sovereign.EgressKind{sovereign.EgressInference, sovereign.EgressLogs}
	if !reflect.DeepEqual(kinds, want) {
		t.Errorf("ClassDetectors.Kinds() = %v, want %v", kinds, want)
	}
}

// TestCheckClass_Table: per-class resolution over per-kind profiles —
// first denial in the class's fixed kind order wins; org-wide rules apply
// to every kind; normalization is case/whitespace-insensitive.
func TestCheckClass_Table(t *testing.T) {
	pol := sovereign.Policy{
		ExcludedCountries: []string{"CN"},
		Egress: map[sovereign.EgressKind]sovereign.EgressProfile{
			sovereign.EgressInference:  {AllowedCountries: []string{"SG"}},
			sovereign.EgressLogs:       {ExcludedCountries: []string{"SG"}},
			sovereign.EgressEmbeddings: {AllowedCountries: []string{"EU"}},
			sovereign.EgressTools:      {AllowedCountries: []string{"SG"}},
			sovereign.EgressExport:     {AllowedCountries: []string{"EU"}},
		},
	}
	cases := []struct {
		name     string
		class    DataClass
		country  string
		wantOK   bool
		wantKind sovereign.EgressKind
		wantRule sovereign.DenialReason
	}{
		{"inference allowlisted sg", ClassInference, "SG", true, "", ""},
		{"inference normalization", ClassInference, " sg ", true, "", ""},
		{"inference allowlist denies eu", ClassInference, "eu", false, sovereign.EgressInference, sovereign.DenialKindNotAllowed},
		{"inference allowlist beats org-wide for cn", ClassInference, "CN", false, sovereign.EgressInference, sovereign.DenialKindNotAllowed},
		{"logs kind-excluded sg", ClassLogs, "SG", false, sovereign.EgressLogs, sovereign.DenialKindExcluded},
		{"logs permits eu", ClassLogs, "EU", true, "", ""},
		{"embeddings allowlist denies sg", ClassEmbeddings, "SG", false, sovereign.EgressEmbeddings, sovereign.DenialKindNotAllowed},
		{"embeddings allowlist denies cn before org-wide", ClassEmbeddings, "cn", false, sovereign.EgressEmbeddings, sovereign.DenialKindNotAllowed},
		{"logs org-wide denies cn", ClassLogs, "cn", false, sovereign.EgressLogs, sovereign.DenialOrgExcluded},
		{"tools allowlist denies eu", ClassTools, "EU", false, sovereign.EgressTools, sovereign.DenialKindNotAllowed},
		{"export permits eu", ClassExport, "EU", true, "", ""},
		// detectors = inference AND logs: the stricter layer wins.
		{"detectors: sg blocked by logs exclusion", ClassDetectors, "SG", false, sovereign.EgressLogs, sovereign.DenialKindExcluded},
		{"detectors: eu blocked by inference allowlist", ClassDetectors, "EU", false, sovereign.EgressInference, sovereign.DenialKindNotAllowed},
		{"detectors: no country satisfies both", ClassDetectors, "CN", false, sovereign.EgressInference, sovereign.DenialKindNotAllowed},
		// fail-closed: empty country never satisfies an allowlist.
		{"empty country vs inference allowlist", ClassInference, "", false, sovereign.EgressInference, sovereign.DenialKindNotAllowed},
		{"empty country vs detectors", ClassDetectors, "  ", false, sovereign.EgressInference, sovereign.DenialKindNotAllowed},
		{"empty country, org-wide only", ClassLogs, "", true, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, kind, rule := CheckClass(pol, tc.class, tc.country)
			if ok != tc.wantOK || kind != tc.wantKind || rule != tc.wantRule {
				t.Errorf("CheckClass(%s, %q) = (%v, %q, %q), want (%v, %q, %q)",
					tc.class, tc.country, ok, kind, rule, tc.wantOK, tc.wantKind, tc.wantRule)
			}
		})
	}
}

// TestCheckClass_DefaultPolicyPermitsAll: an org without constraints keeps
// the fail-open default for every class (no implicit denials).
func TestCheckClass_DefaultPolicyPermitsAll(t *testing.T) {
	def := sovereign.DefaultPolicy()
	for _, c := range DataClasses {
		for _, country := range []string{"SG", "EU", "CN", ""} {
			if ok, kind, rule := CheckClass(def, c, country); !ok {
				t.Errorf("default policy denied class %s country %q (kind=%q rule=%q)", c, country, kind, rule)
			}
		}
	}
}

// TestCheckClass_InvalidClassDenied: an unknown class must never resolve to
// an allow (fail-closed against future category bypasses).
func TestCheckClass_InvalidClassDenied(t *testing.T) {
	ok, kind, rule := CheckClass(sovereign.DefaultPolicy(), DataClass("widgets"), "SG")
	if ok {
		t.Error("invalid class must deny")
	}
	if kind != "" || rule != "" {
		t.Errorf("invalid class denial = (%q, %q), want empty markers", kind, rule)
	}
}
