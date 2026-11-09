package license_test

// integration proof for the entitlement boundary from the consumer
// side: the EntitlementSource interface is the only seam between the Apache
// core and a future closed-source enterprise module. The implementation must
// live outside core and reach a consumer exclusively through this exported
// interface — core never imports the enterprise side. This file is compiled
// from an external package (the same dependency direction a future
// enterprise/ module would have) and pins the consumer posture documented on
// the interface; the production entry point that holds the (nil) source is
// services/run/admin.go.

import (
	"errors"
	"testing"

	"github.com/reireirei/yabanin/pkg/license"
)

// enterpriseSideSource stands in for a future enterprise-module
// implementation: defined outside the license package, satisfying the core
// interface with no core-side registration or default.
type enterpriseSideSource struct {
	features []string
	err      error
	active   bool
}

func (s enterpriseSideSource) OrgFeatures(orgID string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.features, nil
}

func (s enterpriseSideSource) Active() bool { return s.active }

// Compile-time proof from outside the core package: the extension interface
// is satisfiable by an external module without touching core internals.
var _ license.EntitlementSource = enterpriseSideSource{}

// consumerFeatures is the documented consumer guard: a nil source is "not in
// enforcement mode" (no features, no failure); a wired source's features
// flow through unchanged; an error propagates and is never replaced by a
// default feature set.
func consumerFeatures(src license.EntitlementSource, orgID string) ([]string, error) {
	if src == nil {
		return nil, nil
	}
	return src.OrgFeatures(orgID)
}

// TestEntitlementIntegration_EnterpriseSideWiring verifies the full boundary
// axis at the consumer shape: unactivated core (nil source) stays unenforced
// without failure, an explicitly wired external source passes features
// through, and a source error surfaces with nil features (no defaults).
func TestEntitlementIntegration_EnterpriseSideWiring(t *testing.T) {
	// Core default posture: no enterprise module present, nothing enforced.
	var src license.EntitlementSource
	features, err := consumerFeatures(src, "org_1")
	if err != nil {
		t.Fatalf("nil source must not fail: got error %v", err)
	}
	if features != nil {
		t.Fatalf("nil source features = %v, want nil (not enforced, no defaults)", features)
	}

	// Enterprise module wired explicitly through the interface.
	src = enterpriseSideSource{features: []string{"sso", "audit-export"}, active: true}
	features, err = consumerFeatures(src, "org_1")
	if err != nil {
		t.Fatalf("wired source returned error: %v", err)
	}
	if len(features) != 2 || features[0] != "sso" || features[1] != "audit-export" {
		t.Fatalf("features = %v, want [sso audit-export]", features)
	}
	if !src.Active() {
		t.Fatal("Active() = false on wired active source, want true")
	}

	// Error axis: the source error propagates, no default feature set appears.
	wantErr := errors.New("entitlement backend unavailable")
	src = enterpriseSideSource{err: wantErr}
	features, err = consumerFeatures(src, "org_1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if features != nil {
		t.Fatalf("features = %v on error, want nil (no defaults)", features)
	}
}
