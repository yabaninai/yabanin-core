package license

import (
	"errors"
	"reflect"
	"testing"
)

// stubEntitlementSource stands in for a future enterprise implementation:
// it is an ordinary struct implemented outside the core default paths and
// wired into a consumer explicitly. It must not be confused with a package
// default — it exists only in tests.
type stubEntitlementSource struct {
	features []string
	err      error
	active   bool
}

func (s stubEntitlementSource) OrgFeatures(orgID string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.features, nil
}

func (s stubEntitlementSource) Active() bool { return s.active }

// compile-time proof that any external struct with the two methods satisfies
// the extension interface.
var _ EntitlementSource = stubEntitlementSource{}

// TestEntitlementSource_InterfaceContract verifies the wiring shape documented
// on EntitlementSource: values flow through the interface unchanged, errors
// propagate (no implicit feature fallback), and orgID reaches the source.
func TestEntitlementSource_InterfaceContract(t *testing.T) {
	var src EntitlementSource = stubEntitlementSource{
		features: []string{"sso", "audit-export"},
		active:   true,
	}

	features, err := src.OrgFeatures("org_1")
	if err != nil {
		t.Fatalf("OrgFeatures returned error: %v", err)
	}
	if !reflect.DeepEqual(features, []string{"sso", "audit-export"}) {
		t.Fatalf("features = %v, want [sso audit-export]", features)
	}
	if !src.Active() {
		t.Fatal("Active() = false, want true from wired source")
	}
}

// TestEntitlementSource_ErrorPropagates_NoDefault verifies the no-business-
// defaults rule: a source error is surfaced, never replaced by a default
// feature set.
func TestEntitlementSource_ErrorPropagates_NoDefault(t *testing.T) {
	wantErr := errors.New("entitlement lookup unavailable")
	var src EntitlementSource = stubEntitlementSource{err: wantErr}

	features, err := src.OrgFeatures("org_1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if features != nil {
		t.Fatalf("features = %v on error, want nil (no defaults)", features)
	}
	if src.Active() {
		t.Fatal("Active() = true without external activation, want false")
	}
}

// TestEntitlementSource_NilMeansNotEnforced verifies the documented nil
// semantics: the zero interface value is the "not in enforcement mode"
// marker, and the consumer-side guard pattern (documented on the interface)
// changes no behavior when no source is wired.
func TestEntitlementSource_NilMeansNotEnforced(t *testing.T) {
	var src EntitlementSource
	if src != nil {
		t.Fatal("zero EntitlementSource = nil, want nil (not enforced)")
	}

	// Consumer-side guard (the documented wiring pattern): a nil source is
	// "not in enforcement mode" — no features, no activity, no defaults.
	features := func(src EntitlementSource, orgID string) []string {
		if src == nil {
			return nil
		}
		f, err := src.OrgFeatures(orgID)
		if err != nil {
			return nil
		}
		return f
	}(src, "org_1")
	if features != nil {
		t.Fatalf("features = %v without wired source, want nil (no defaults)", features)
	}
}
